//! Clean-room Rust port of liblzma's xz decoder, structurally
//! faithful.
//!
//! Phase 1 of [`internal/PLAN_xz_liblzma_port.md`](../../../internal/PLAN_xz_liblzma_port.md);
//! streaming I/O and chunk-level resume added in Phase F of
//! [`internal/old/PLAN_xz_liblzma_phase_f.md`](../../../internal/old/PLAN_xz_liblzma_phase_f.md).
//! Sibling to [`super::xz_native`]: the existing decoder is the
//! production path; this module is the rewrite that supersedes
//! it once Phase F.6 lands the migration commit.
//!
//! # Why a parallel module
//!
//! [`PLAN_xz_liblzma_deep_dive.md`](../../../internal/old/PLAN_xz_liblzma_deep_dive.md)
//! Phase A documented liblzma's hot-loop register discipline and
//! attributed peel's 1.5× per-byte gap to per-bit memory-store
//! costs that liblzma's compiled output avoids. Phase C of that
//! plan tested whether a struct-shape change ("LocalRc"
//! stack-staging) inside the existing decoder could close the
//! gap; it could not. The diagnosis was that closing the gap
//! requires the same overall function shape liblzma uses — a
//! single dispatch loop where the rc state, dict pointer, and
//! prob-base pointer all stay register-resident across thousands
//! of expansion sites.
//!
//! # `unsafe` posture
//!
//! Liberal — `unsafe` admitted wherever liblzma uses raw pointers,
//! with `// SAFETY:` comments on every block.
//!
//! # Phase F.2 streaming I/O
//!
//! [`Decoder::decode_step`] is now incremental: each call does
//! at most one structural unit of work (read the Stream Header,
//! one Block Header, one LZMA2 chunk, the Index, or the Stream
//! Footer) and returns. The slurp-first regression at low
//! bandwidth (Phase 8 cells 10 Mbps / 100 Mbps in
//! [`PLAN_xz_liblzma_port.md`](../../../internal/PLAN_xz_liblzma_port.md))
//! is gone — read and decode now overlap with the network pull.
//!
//! Multi-Block + multi-Stream support landed in Phase F.3.
//! Per-LZMA2-chunk checkpoint blob support landed in Phase F.4
//! (serializer / `decoder_state_into`) and Phase F.5
//! (deserializer / `Decoder::resume` / [`resume_factory`]).
//! Phase F.6's migration commit retires `xz_native` and
//! reroutes `peel::decode::xz` to this module.

pub mod block;
pub mod check;
pub mod decoder;
pub mod dict;
pub mod error;
pub mod lzma2;
pub mod range_coder;
pub mod raw;
pub mod resume;
pub mod stream;
pub mod xz_error;

#[cfg(test)]
pub(crate) mod test_support;

use std::io::{self, Read, Write};

use self::block::{block_header_real_size, parse_block_header, BlockHeader};
use self::check::BlockCheckHasher;
use self::stream::{
    parse_stream_footer, parse_stream_header, read_multibyte, StreamFlags, STREAM_FOOTER_LEN,
    STREAM_HEADER_LEN,
};
use self::xz_error::XzError;
use crate::decode::{DecodeError, DecodeStatus, StreamingDecoder};
use crate::hash::crc32::Crc32;
use crate::types::ByteOffset;

use self::error::XzPortError;
use self::lzma2::{Lzma2Decoder, Lzma2StepStatus};
use self::resume::XzPortResumeState;

/// Public `xz` streaming decoder built on the liblzma-port
/// inner loop.
///
/// Implements [`StreamingDecoder`] with the same shape as
/// [`super::xz_native::Decoder`] so the bench grid + production
/// registry can swap between them.
///
/// # Per-call work shape (Phase F.2)
///
/// Each [`StreamingDecoder::decode_step`] does at most one
/// structural unit of work:
/// - Stream Header (12 bytes)
/// - Block Header (≤ 1 KiB)
/// - One LZMA2 chunk (≤ 64 KiB compressed)
/// - Block Padding + Block Check (≤ 35 bytes)
/// - Index (variable; bounded by Block count)
/// - Stream Footer (12 bytes)
///
/// The state machine itself loops *across* calls, not within
/// one. Throughput at high bandwidth comes from
/// [`Lzma2Decoder`]'s inner loop (the structural port);
/// throughput at low bandwidth comes from this incremental
/// shape (read and decode overlap with network pull).
///
/// # Round-one limitations
///
/// - **Single-Block streams only.** Multi-Block + multi-Stream
///   support is filed as Phase F.3.
/// - **No checkpoint blob.** [`StreamingDecoder::decoder_state_into`]
///   returns `false`. Phase F.4 implements the inter-chunk
///   blob format; Phase F.5 wires the resume_factory.
/// - **Stream / Block / Check parsers borrowed from
///   [`super::xz_native`].** They're well-tested clean-room
///   ports already; Phase F.6's migration commit decides
///   whether to fold them into `xz_liblzma` or keep them
///   shared in a common module.
pub struct Decoder {
    /// Wrapped source. Held in an `Option` so we can drop it on
    /// terminal error or clean EOF and short-circuit subsequent
    /// calls. Reads happen via `read_into` / `read_exact_into`.
    source: Option<Box<dyn Read + Send>>,
    /// Decoder state machine. See [`State`].
    state: State,
    /// High-water source-byte counter — what
    /// [`StreamingDecoder::bytes_consumed`] returns. Advanced
    /// only after a successful read; partial reads advance only
    /// by what was actually delivered.
    bytes_consumed: u64,
    /// Latest frame boundary (Stream end, or per-LZMA2-chunk
    /// boundary inside a Block). Phase F.4 will refine the
    /// per-chunk boundary semantics; F.2 sets it at end-of-Stream
    /// only.
    last_frame_boundary: Option<ByteOffset>,
    /// Reusable scratch for the current Block Header. Sized to
    /// the spec's 1024-byte cap on first use; held thereafter.
    block_header_buf: Vec<u8>,
    /// Persistent input buffer that holds bytes pulled from
    /// `source` but not yet consumed by the state machine. All
    /// reads ([`read_exact_via`], [`fill_at_least`]) drain
    /// this first before pulling from `source`. Bounded by the
    /// read-chunk size on each pull (64 KiB) so memory stays
    /// flat across long streams.
    pending_input: Vec<u8>,
    /// `(unpadded_size, uncompressed_size)` records observed in
    /// the current Stream. Cleared whenever a fresh Stream
    /// Header is parsed; consumed by Index validation at the
    /// end of each Stream. Round-one (single-Block) only ever
    /// holds zero or one record.
    stream_block_records: Vec<(u64, u64)>,
}

/// Decoder state machine. Mirror of
/// [`super::xz_native::State`]'s shape, simpler because Phase
/// F.2's round-one supports single-Block streams only.
enum State {
    /// Need to pull the 12-byte Stream Header.
    AwaitStreamHeader,
    /// Stream Header parsed; we hold its [`StreamFlags`] across
    /// the Block and into the Footer cross-check.
    BetweenBlocks {
        flags: StreamFlags,
        records_seen: u64,
    },
    /// Inside a Block; decoding LZMA2 chunks.
    InBlock {
        flags: StreamFlags,
        records_seen: u64,
        ctx: Box<BlockCtx>,
    },
    /// Stream's Index Indicator has been consumed; reading the
    /// `Number_of_Records` + per-Block records.
    InIndex {
        flags: StreamFlags,
        records_seen: u64,
    },
    /// Stream finished cleanly. Subsequent steps are no-ops.
    Done,
}

/// Per-Block accounting context. Lives only while
/// [`State::InBlock`] is active; cleared at Block end before
/// returning to [`State::BetweenBlocks`].
struct BlockCtx {
    /// Parsed Block Header.
    header: BlockHeader,
    /// Source-byte offset where the LZMA2 stream began (just
    /// after the Block Header). Used to compute observed
    /// `Compressed_Size` for cross-check.
    lzma2_start_offset: u64,
    /// Decompressed bytes emitted from this Block. Updated
    /// inside [`HashingTeeSink::write`] as bytes flow through.
    decompressed_so_far: u64,
    /// `true` once the LZMA2 EndOfStream chunk has been
    /// consumed. After that we still owe Block Padding +
    /// Check before returning to `BetweenBlocks`.
    lzma2_finished: bool,
    /// LZMA2 chunk dispatcher.
    lzma2: Lzma2Decoder,
    /// Block-Check hasher (CRC32 / CRC64 / SHA-256 / None).
    /// Updated as decoded bytes flow through the tee-sink.
    check_hasher: BlockCheckHasher,
}

impl Decoder {
    /// Construct a [`Decoder`] over `source`. Construction
    /// never reads from the source; the first
    /// [`StreamingDecoder::decode_step`] does the first read.
    ///
    /// # Errors
    ///
    /// Currently never returns `Err`. Signature kept fallible
    /// to match [`super::DecoderFactory`] without an adapter.
    pub fn new(source: Box<dyn Read + Send>) -> Result<Self, DecodeError> {
        Ok(Self {
            source: Some(source),
            state: State::AwaitStreamHeader,
            bytes_consumed: 0,
            last_frame_boundary: None,
            block_header_buf: Vec::new(),
            pending_input: Vec::new(),
            stream_block_records: Vec::new(),
        })
    }

    fn step_inner(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, XzPortError> {
        match &mut self.state {
            State::Done => Ok(DecodeStatus::Eof),

            State::AwaitStreamHeader => {
                let mut buf = [0u8; STREAM_HEADER_LEN];
                read_exact_via(
                    &mut self.source,
                    &mut self.pending_input,
                    &mut self.bytes_consumed,
                    &mut buf,
                )
                .map_err(map_io_to_framing("Stream Header"))?;
                let flags = parse_stream_header(&buf)?;
                self.stream_block_records.clear();
                self.state = State::BetweenBlocks {
                    flags,
                    records_seen: 0,
                };
                Ok(DecodeStatus::MoreData)
            }

            State::BetweenBlocks {
                flags,
                records_seen,
            } => {
                let flags = *flags;
                let records_seen_now = *records_seen;

                // Read the Block_Header_Size byte. 0x00 routes
                // to the Index Indicator path; non-zero is the
                // leading byte of a real Block Header.
                let mut size_buf = [0u8; 1];
                read_exact_via(
                    &mut self.source,
                    &mut self.pending_input,
                    &mut self.bytes_consumed,
                    &mut size_buf,
                )
                .map_err(map_io_to_framing("Block Header size byte"))?;
                let size_byte = size_buf[0];

                if size_byte == 0x00 {
                    // Index Indicator
                    self.state = State::InIndex {
                        flags,
                        records_seen: records_seen_now,
                    };
                    return Ok(DecodeStatus::MoreData);
                }

                let real_size = block_header_real_size(size_byte);
                self.block_header_buf.clear();
                self.block_header_buf.reserve(real_size);
                self.block_header_buf.push(size_byte);
                let already_have = self.block_header_buf.len();
                self.block_header_buf.resize(real_size, 0);
                read_exact_via(
                    &mut self.source,
                    &mut self.pending_input,
                    &mut self.bytes_consumed,
                    &mut self.block_header_buf[already_have..],
                )
                .map_err(map_io_to_framing("Block Header"))?;
                let header = parse_block_header(&self.block_header_buf)?;
                let lzma2 = Lzma2Decoder::new(header.dict_size);
                let check_hasher = BlockCheckHasher::new(flags.check);
                let lzma2_start_offset = self.bytes_consumed;
                let ctx = Box::new(BlockCtx {
                    header,
                    lzma2_start_offset,
                    decompressed_so_far: 0,
                    lzma2_finished: false,
                    lzma2,
                    check_hasher,
                });
                self.state = State::InBlock {
                    flags,
                    records_seen: records_seen_now,
                    ctx,
                };
                Ok(DecodeStatus::MoreData)
            }

            State::InBlock {
                flags,
                records_seen,
                ctx,
            } => {
                let flags = *flags;
                let records_seen_now = *records_seen;

                if !ctx.lzma2_finished {
                    Self::process_one_lzma2_chunk(
                        &mut self.source,
                        &mut self.pending_input,
                        &mut self.bytes_consumed,
                        ctx,
                        sink,
                    )?;
                    // Phase F.4: advance the per-LZMA2-chunk
                    // frame boundary so the coordinator's
                    // checkpoint cadence fires at every chunk
                    // where `decoder_state_into` will succeed.
                    if ctx.lzma2.is_at_chunk_boundary() && !ctx.lzma2_finished {
                        self.last_frame_boundary = Some(ByteOffset::new(self.bytes_consumed));
                    }
                    return Ok(DecodeStatus::MoreData);
                }

                // LZMA2 finished. Validate sizes, consume Block
                // Padding + Check, return to BetweenBlocks.
                let observed_compressed =
                    self.bytes_consumed.saturating_sub(ctx.lzma2_start_offset);
                if let Some(declared) = ctx.header.compressed_size {
                    if declared != observed_compressed {
                        return Err(XzPortError::Framing(format!(
                            "Block Header Compressed_Size = {declared}, observed {observed_compressed}"
                        )));
                    }
                }
                if let Some(declared) = ctx.header.uncompressed_size {
                    if declared != ctx.decompressed_so_far {
                        return Err(XzPortError::Framing(format!(
                            "Block Header Uncompressed_Size = {declared}, observed {}",
                            ctx.decompressed_so_far
                        )));
                    }
                }

                // Block Padding: 0..=3 zero bytes to align to
                // 4-byte boundary.
                let pad_len = (4 - (observed_compressed & 0b11) as usize) & 0b11;
                if pad_len > 0 {
                    let mut pad = [0u8; 3];
                    read_exact_via(
                        &mut self.source,
                        &mut self.pending_input,
                        &mut self.bytes_consumed,
                        &mut pad[..pad_len],
                    )
                    .map_err(map_io_to_framing("Block Padding"))?;
                    for &b in &pad[..pad_len] {
                        if b != 0x00 {
                            return Err(XzPortError::Framing(format!(
                                "non-zero Block Padding byte 0x{b:02X}"
                            )));
                        }
                    }
                }

                let check_size = flags.check.size();
                let mut check_buf = [0u8; 32];
                if check_size > 0 {
                    read_exact_via(
                        &mut self.source,
                        &mut self.pending_input,
                        &mut self.bytes_consumed,
                        &mut check_buf[..check_size],
                    )
                    .map_err(map_io_to_framing("Block Check"))?;
                }
                let hasher =
                    std::mem::replace(&mut ctx.check_hasher, BlockCheckHasher::new(flags.check));
                hasher.verify(&check_buf[..check_size])?;

                let unpadded_size = (ctx.header.header_size_bytes as u64)
                    .saturating_add(observed_compressed)
                    .saturating_add(check_size as u64);
                self.stream_block_records
                    .push((unpadded_size, ctx.decompressed_so_far));

                self.state = State::BetweenBlocks {
                    flags,
                    records_seen: records_seen_now + 1,
                };
                Ok(DecodeStatus::MoreData)
            }

            State::InIndex {
                flags,
                records_seen,
            } => {
                let flags = *flags;
                let records_seen = *records_seen;

                // Index = Indicator (already consumed) +
                // Number_of_Records (varint) + per-Block records
                // (Unpadded_Size + Uncompressed_Size, varints) +
                // 0..=3 zero bytes padding + 4-byte CRC32.
                // Bounded by the Block count and a small
                // constant; pull the whole tail in one shot.
                let mut index_bytes: Vec<u8> = Vec::with_capacity(64);
                index_bytes.push(0x00);

                let num_records = read_varint_via(
                    &mut self.source,
                    &mut self.pending_input,
                    &mut self.bytes_consumed,
                    &mut index_bytes,
                )?;
                if num_records != records_seen {
                    return Err(XzPortError::Framing(format!(
                        "Index record count mismatch: declared {num_records}, observed {records_seen}"
                    )));
                }
                if num_records as usize != self.stream_block_records.len() {
                    return Err(XzPortError::Framing(format!(
                        "Index record vector length mismatch: declared {num_records}, observed {}",
                        self.stream_block_records.len()
                    )));
                }
                for &(observed_unpadded, observed_uncomp) in self.stream_block_records.iter() {
                    let declared_unpadded = read_varint_via(
                        &mut self.source,
                        &mut self.pending_input,
                        &mut self.bytes_consumed,
                        &mut index_bytes,
                    )?;
                    let declared_uncomp = read_varint_via(
                        &mut self.source,
                        &mut self.pending_input,
                        &mut self.bytes_consumed,
                        &mut index_bytes,
                    )?;
                    if declared_unpadded != observed_unpadded {
                        return Err(XzPortError::Framing(format!(
                            "Index Unpadded_Size mismatch: declared {declared_unpadded}, observed {observed_unpadded}"
                        )));
                    }
                    if declared_uncomp != observed_uncomp {
                        return Err(XzPortError::Framing(format!(
                            "Index Uncompressed_Size mismatch: declared {declared_uncomp}, observed {observed_uncomp}"
                        )));
                    }
                }
                // Index Padding to 4-byte alignment.
                let index_so_far = index_bytes.len();
                let index_pad = (4 - (index_so_far & 0b11)) & 0b11;
                if index_pad > 0 {
                    let mut pad = [0u8; 3];
                    read_exact_via(
                        &mut self.source,
                        &mut self.pending_input,
                        &mut self.bytes_consumed,
                        &mut pad[..index_pad],
                    )
                    .map_err(map_io_to_framing("Index Padding"))?;
                    for &b in &pad[..index_pad] {
                        if b != 0x00 {
                            return Err(XzPortError::Framing(format!(
                                "non-zero Index Padding byte 0x{b:02X}"
                            )));
                        }
                        index_bytes.push(0x00);
                    }
                }
                let mut crc_buf = [0u8; 4];
                read_exact_via(
                    &mut self.source,
                    &mut self.pending_input,
                    &mut self.bytes_consumed,
                    &mut crc_buf,
                )
                .map_err(map_io_to_framing("Index CRC32"))?;
                let stored = u32::from_le_bytes(crc_buf);
                let mut crc = Crc32::new();
                crc.update(&index_bytes);
                let computed = crc.finalize();
                if stored != computed {
                    return Err(XzPortError::Framing(format!(
                        "Index CRC32 mismatch: stored 0x{stored:08X}, computed 0x{computed:08X}"
                    )));
                }

                // Stream Footer (12 bytes).
                let mut footer = [0u8; STREAM_FOOTER_LEN];
                read_exact_via(
                    &mut self.source,
                    &mut self.pending_input,
                    &mut self.bytes_consumed,
                    &mut footer,
                )
                .map_err(map_io_to_framing("Stream Footer"))?;
                let (footer_flags, _backward_size) = parse_stream_footer(&footer)?;
                if footer_flags.check != flags.check {
                    return Err(XzPortError::Framing(format!(
                        "Stream Footer Check ID disagrees with Header: header={:?}, footer={:?}",
                        flags.check, footer_flags.check
                    )));
                }

                self.last_frame_boundary = Some(ByteOffset::new(self.bytes_consumed));

                // Phase F.3: detect a follow-on concatenated
                // Stream (`cat a.xz b.xz > c.xz`). xz handles
                // these transparently; output is the
                // concatenation of each Stream's payload. If
                // there are no more bytes, we're done; if the
                // next byte is 0x00, that's Stream Padding —
                // which the xz spec permits in 4-byte
                // multiples but we conservatively reject (as
                // does `xz_native` and the rest of the peel
                // pipeline).
                match peek_byte_via(
                    &mut self.source,
                    &mut self.pending_input,
                    &mut self.bytes_consumed,
                )? {
                    None => {
                        self.source = None;
                        self.state = State::Done;
                        Ok(DecodeStatus::Eof)
                    }
                    Some(0x00) => Err(XzPortError::Framing(
                        "Stream Padding (zero-padded follow-on) not supported".into(),
                    )),
                    Some(byte) => {
                        // The peek consumed one source byte;
                        // re-buffer it so AwaitStreamHeader
                        // sees a full 12-byte header from
                        // its first read.
                        self.pending_input.insert(0, byte);
                        self.bytes_consumed = self.bytes_consumed.saturating_sub(1);
                        self.state = State::AwaitStreamHeader;
                        Ok(DecodeStatus::MoreData)
                    }
                }
            }
        }
    }

    /// Read one LZMA2 chunk's worth of bytes from
    /// `pending_input` (refilled from `source` on demand) and
    /// drive it through `ctx.lzma2.step`, hashing decoded
    /// bytes via `ctx.check_hasher` as they flow through to
    /// `sink`. Returns once the chunk completes or the LZMA2
    /// EndOfStream is consumed.
    ///
    /// `pending_input` is **the unified input buffer** shared
    /// with all other read paths. This call drains its
    /// `..local_pos` prefix after each `step` outcome (so the
    /// buffer never grows unboundedly) and the post-Block
    /// readers (Block Padding, Block Check, Index, Stream
    /// Footer) drain their bytes from this same buffer first
    /// before pulling from `source`.
    fn process_one_lzma2_chunk(
        source: &mut Option<Box<dyn Read + Send>>,
        pending_input: &mut Vec<u8>,
        bytes_consumed: &mut u64,
        ctx: &mut BlockCtx,
        sink: &mut dyn Write,
    ) -> Result<(), XzPortError> {
        let mut tee = HashingTeeSink {
            hasher: &mut ctx.check_hasher,
            sink,
            byte_count: 0,
        };

        // Drive the LZMA2 step machine until one chunk completes
        // (Produced) or we hit EndOfStream. NeedInput pulls more
        // bytes from source into pending_input.
        loop {
            let mut local_pos: usize = 0;
            match ctx.lzma2.step(pending_input, &mut local_pos, &mut tee)? {
                Lzma2StepStatus::EndOfStream => {
                    *bytes_consumed = bytes_consumed.saturating_add(local_pos as u64);
                    pending_input.drain(..local_pos);
                    ctx.decompressed_so_far = ctx
                        .decompressed_so_far
                        .saturating_add(tee.byte_count as u64);
                    ctx.lzma2_finished = true;
                    return Ok(());
                }
                Lzma2StepStatus::Produced => {
                    *bytes_consumed = bytes_consumed.saturating_add(local_pos as u64);
                    pending_input.drain(..local_pos);
                    ctx.decompressed_so_far = ctx
                        .decompressed_so_far
                        .saturating_add(tee.byte_count as u64);
                    return Ok(());
                }
                Lzma2StepStatus::NeedInput => {
                    // Drain any bytes step() consumed before
                    // bailing on underflow (parsing the chunk
                    // header consumes bytes even on the path
                    // that subsequently NeedInputs on the
                    // payload).
                    if local_pos > 0 {
                        *bytes_consumed = bytes_consumed.saturating_add(local_pos as u64);
                        pending_input.drain(..local_pos);
                    }
                    let src = source.as_mut().ok_or_else(|| {
                        XzPortError::Framing("source closed mid-LZMA2-chunk".into())
                    })?;
                    let pulled = read_more_into(src.as_mut(), pending_input)
                        .map_err(map_io_to_framing("LZMA2 chunk"))?;
                    if pulled == 0 {
                        return Err(XzPortError::Framing(
                            "unexpected end of source mid-LZMA2-chunk".into(),
                        ));
                    }
                }
            }
        }
    }
}

impl StreamingDecoder for Decoder {
    fn decode_step(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, DecodeError> {
        if matches!(self.state, State::Done) {
            return Ok(DecodeStatus::Eof);
        }
        match self.step_inner(sink) {
            Ok(status) => Ok(status),
            Err(e) => {
                let consumed = self.bytes_consumed;
                self.source = None;
                self.state = State::Done;
                Err(DecodeError::Read {
                    consumed,
                    source: io::Error::other(format!("xz_liblzma: {e}")),
                })
            }
        }
    }

    fn bytes_consumed(&self) -> ByteOffset {
        ByteOffset::new(self.bytes_consumed)
    }

    fn frame_boundary(&self) -> Option<ByteOffset> {
        self.last_frame_boundary
    }

    fn set_source_start_offset(&mut self, offset: u64) {
        self.bytes_consumed = offset;
    }

    fn decoder_state_size_hint(&self) -> usize {
        // Dominated by the dict bytes (up to 64 MiB at preset
        // 9). Add a generous overhead for the fixed-shape
        // fields (probs ≤ 28 KiB, check state ≤ 105 B for
        // SHA-256, plus ~120 B of varying numerics).
        match &self.state {
            State::InBlock { ctx, .. } => ctx.lzma2.dict().size + 32 * 1024 + 256,
            _ => 0,
        }
    }

    fn decoder_state_into(&self, out: &mut Vec<u8>) -> bool {
        let State::InBlock { flags, ctx, .. } = &self.state else {
            return false;
        };
        // Capture only at clean inter-chunk boundaries; the
        // F.4 blob format doesn't carry per-bit cursor state.
        if !ctx.lzma2.is_at_chunk_boundary() {
            return false;
        }
        if ctx.lzma2_finished {
            return false;
        }
        if ctx.lzma2.needs_dict_reset() {
            // First chunk hasn't run yet — no useful state to
            // capture. The plain factory will replay the same
            // first chunk on resume.
            return false;
        }

        let lzma1 = ctx.lzma2.decoder();
        let dict = ctx.lzma2.dict();

        let mut probs_buf = Vec::with_capacity(self::resume::probs_serialized_len());
        self::resume::write_probs_into(&mut probs_buf, &lzma1.probs);

        let mut check_state = Vec::with_capacity(ctx.check_hasher.serialized_state_len());
        ctx.check_hasher.serialize_state(&mut check_state);

        let snap = XzPortResumeState {
            stream_check: flags.check,
            stream_block_records: self.stream_block_records.clone(),
            block_header_size_bytes: ctx.header.header_size_bytes as u32,
            block_compressed_size_declared: ctx.header.compressed_size,
            block_uncompressed_size_declared: ctx.header.uncompressed_size,
            block_dict_size: ctx.header.dict_size,
            block_lzma2_start_offset: ctx.lzma2_start_offset,
            block_decompressed_so_far: ctx.decompressed_so_far,
            block_seen_first_chunk: !ctx.lzma2.needs_dict_reset(),
            block_lzma2_finished: ctx.lzma2_finished,
            needs_props: ctx.lzma2.needs_props(),
            needs_dict_reset: ctx.lzma2.needs_dict_reset(),
            lc: lzma1.literal_context_bits as u8,
            lp: (lzma1.literal_pos_mask + 1).trailing_zeros() as u8,
            pb: (lzma1.pos_mask + 1).trailing_zeros() as u8,
            lzma_state: lzma1.state as u8,
            rep0: lzma1.rep0,
            rep1: lzma1.rep1,
            rep2: lzma1.rep2,
            rep3: lzma1.rep3,
            dict_capacity: dict.size as u32,
            dict_full: dict.full as u32,
            dict_data: self::resume::dict_recent(dict),
            probs: probs_buf,
            check_state,
        };
        XzPortResumeState::write_into(out, &snap);
        true
    }
}

/// [`crate::decode::DecoderFactory`] adapter for [`Decoder`].
///
/// # Errors
///
/// Forwards any error returned by [`Decoder::new`] (currently
/// none).
pub fn factory(src: Box<dyn Read + Send>) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    Ok(Box::new(Decoder::new(src)?))
}

impl Decoder {
    /// Reconstruct a [`Decoder`] from a Phase F.4 resume blob
    /// + the source byte offset the blob describes.
    ///
    /// `source` is positioned at `start_offset` — the
    /// coordinator has already pre-seeked the underlying byte
    /// stream there. On success the returned [`Decoder`] is
    /// in `State::InBlock` with a fully reconstituted
    /// `Lzma2Decoder`; the next [`StreamingDecoder::decode_step`]
    /// reads the next chunk's control byte from the source.
    ///
    /// # Errors
    ///
    /// Returns the parser's [`resume::ResumeBlobError`]
    /// converted to a typed [`DecodeError::Read`] on bad
    /// magic, unknown version, truncation, or CRC mismatch.
    pub fn resume(
        blob: &[u8],
        source: Box<dyn Read + Send>,
        start_offset: u64,
    ) -> Result<Self, DecodeError> {
        let snap = XzPortResumeState::deserialize(blob).map_err(|e| DecodeError::Read {
            consumed: 0,
            source: io::Error::other(format!("xz_liblzma resume: {e}")),
        })?;

        let lzma1 = self::resume::restore_lzma1_decoder(&snap).map_err(|e| DecodeError::Read {
            consumed: 0,
            source: io::Error::other(format!("xz_liblzma resume: {e}")),
        })?;
        let dict = self::resume::dict_restore(snap.dict_capacity, snap.dict_full, &snap.dict_data);
        let lzma2 = Lzma2Decoder::from_resume(lzma1, dict, snap.needs_props, snap.needs_dict_reset);
        let check_hasher =
            self::resume::restore_check_hasher(&snap).map_err(|e| DecodeError::Read {
                consumed: 0,
                source: io::Error::other(format!("xz_liblzma resume: {e}")),
            })?;

        // Reconstruct a partial BlockHeader from the captured
        // fields. Only the fields the InBlock arm references
        // need to be filled.
        let header = BlockHeader {
            header_size_bytes: snap.block_header_size_bytes as usize,
            compressed_size: snap.block_compressed_size_declared,
            uncompressed_size: snap.block_uncompressed_size_declared,
            dict_size: snap.block_dict_size,
        };
        let ctx = Box::new(BlockCtx {
            header,
            lzma2_start_offset: snap.block_lzma2_start_offset,
            decompressed_so_far: snap.block_decompressed_so_far,
            lzma2_finished: snap.block_lzma2_finished,
            lzma2,
            check_hasher,
        });
        let flags = StreamFlags {
            check: snap.stream_check,
        };
        Ok(Self {
            source: Some(source),
            state: State::InBlock {
                flags,
                records_seen: snap.stream_block_records.len() as u64,
                ctx,
            },
            bytes_consumed: start_offset,
            last_frame_boundary: Some(ByteOffset::new(start_offset)),
            block_header_buf: Vec::new(),
            pending_input: Vec::new(),
            stream_block_records: snap.stream_block_records,
        })
    }
}

/// [`crate::decode::DecoderResumeFactory`] adapter for
/// [`Decoder::resume`]. Argument order matches the trait
/// alias's `(source, blob, start_offset)`.
///
/// # Errors
///
/// Forwards any error returned by [`Decoder::resume`].
pub fn resume_factory(
    source: Box<dyn Read + Send>,
    blob: &[u8],
    start_offset: u64,
) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    Ok(Box::new(Decoder::resume(blob, source, start_offset)?))
}

// ===== I/O helpers =====

/// Read exactly `buf.len()` bytes into `buf`. Drains
/// `pending_input` first; tops up from `source` only if more
/// bytes are needed. All four read paths (Stream Header, Block
/// Header, Block Padding/Check, Index/Footer) share this so
/// over-reads from the LZMA2 chunk loop don't strand bytes.
fn read_exact_via(
    source: &mut Option<Box<dyn Read + Send>>,
    pending_input: &mut Vec<u8>,
    bytes_consumed: &mut u64,
    buf: &mut [u8],
) -> io::Result<()> {
    let mut filled = 0;
    if !pending_input.is_empty() {
        let take = pending_input.len().min(buf.len());
        buf[..take].copy_from_slice(&pending_input[..take]);
        pending_input.drain(..take);
        *bytes_consumed = bytes_consumed.saturating_add(take as u64);
        filled = take;
    }
    if filled == buf.len() {
        return Ok(());
    }
    let src = source.as_mut().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "source closed before read completed",
        )
    })?;
    while filled < buf.len() {
        match src.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "source ended mid-read",
                ))
            }
            Ok(n) => {
                filled += n;
                *bytes_consumed = bytes_consumed.saturating_add(n as u64);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Peek the next source byte (consuming it). Returns
/// `Ok(None)` cleanly if the source has ended without
/// delivering a byte — the multi-Stream "is there a follow-on"
/// detector. Drains `pending_input` first.
fn peek_byte_via(
    source: &mut Option<Box<dyn Read + Send>>,
    pending_input: &mut Vec<u8>,
    bytes_consumed: &mut u64,
) -> Result<Option<u8>, XzPortError> {
    if let Some(&b) = pending_input.first() {
        pending_input.drain(..1);
        *bytes_consumed = bytes_consumed.saturating_add(1);
        return Ok(Some(b));
    }
    let Some(src) = source.as_mut() else {
        return Ok(None);
    };
    let mut buf = [0u8; 1];
    loop {
        match src.read(&mut buf) {
            Ok(0) => return Ok(None),
            Ok(_) => {
                *bytes_consumed = bytes_consumed.saturating_add(1);
                return Ok(Some(buf[0]));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(XzPortError::Framing(format!("peek byte: {e}"))),
        }
    }
}

/// Append at most one read's worth of bytes from `source` to
/// `buf` (without growing the read budget arbitrarily). Returns
/// the number of bytes appended.
///
/// The single-`read` shape lets the caller drive the LZMA2 step
/// machine forward whenever fresh bytes arrive — the chunk-level
/// state machine inside `Lzma2Decoder` decides whether to ask
/// for more.
fn read_more_into(source: &mut (dyn Read + Send), buf: &mut Vec<u8>) -> io::Result<usize> {
    // Top up to 64 KiB at a time — the LZMA2 spec ceiling for
    // one chunk's compressed size, so this read covers the
    // worst-case need in a single syscall.
    const READ_CHUNK: usize = 64 * 1024;
    let original = buf.len();
    buf.resize(original + READ_CHUNK, 0);
    let n = loop {
        match source.read(&mut buf[original..]) {
            Ok(n) => break n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                buf.truncate(original);
                return Err(e);
            }
        }
    };
    buf.truncate(original + n);
    Ok(n)
}

/// Read a Multibyte-encoded VLI via `read_exact_via`, capturing
/// raw bytes into `capture` for later CRC verification.
fn read_varint_via(
    source: &mut Option<Box<dyn Read + Send>>,
    pending_input: &mut Vec<u8>,
    bytes_consumed: &mut u64,
    capture: &mut Vec<u8>,
) -> Result<u64, XzPortError> {
    let mut buf: Vec<u8> = Vec::with_capacity(9);
    loop {
        let mut byte = [0u8; 1];
        read_exact_via(source, pending_input, bytes_consumed, &mut byte)
            .map_err(map_io_to_framing("VLI"))?;
        buf.push(byte[0]);
        capture.push(byte[0]);
        if byte[0] & 0x80 == 0 {
            break;
        }
        if buf.len() >= 9 {
            return Err(XzPortError::Framing("VLI exceeds 9 bytes".into()));
        }
    }
    // Re-use the existing read_multibyte parser on the captured
    // bytes; it returns the decoded value + the byte count.
    let (val, n) =
        read_multibyte(&buf).map_err(|e: XzError| XzPortError::Framing(format!("VLI: {e}")))?;
    debug_assert_eq!(n, buf.len());
    Ok(val)
}

fn map_io_to_framing(label: &'static str) -> impl FnOnce(io::Error) -> XzPortError {
    move |e| XzPortError::Framing(format!("{label}: {e}"))
}

/// Sink wrapper that forwards writes to the user's `sink`
/// while updating the Block-Check `hasher` in lock-step. Lets
/// the streaming Block decoder hash decoded bytes as they flow
/// out, without staging them into a buffer first.
struct HashingTeeSink<'a> {
    hasher: &'a mut BlockCheckHasher,
    sink: &'a mut dyn Write,
    /// Bytes written through this tee. Updated on each `write`
    /// call. The Block-level `decompressed_so_far` adds this on
    /// each chunk completion.
    byte_count: usize,
}

impl Write for HashingTeeSink<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Mirror of `xz_native::Decoder`'s chunk dispatch: hash
        // first, then forward. write_all is what `Lzma2Decoder`
        // uses internally, so an Ok(buf.len()) keeps us
        // contractually in sync.
        self.hasher.update(buf);
        self.sink.write_all(buf)?;
        self.byte_count = self.byte_count.saturating_add(buf.len());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }
}
