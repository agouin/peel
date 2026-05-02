//! Hand-rolled, pure-Rust .xz / LZMA streaming decoder.
//!
//! Phase 1 of `docs/PLAN_xz_block_decoder.md`. Lives here behind the
//! cargo feature flag `peel_xz_native` so production paths still
//! route through [`crate::decode::xz::XzDecoder`] (the upstream
//! `xz2` / liblzma binding) until Phase 7 swaps the implementations.
//!
//! # What's working in Phase 1
//!
//! - [`stream::parse_stream_header`] / [`stream::parse_stream_footer`]
//!   over the .xz spec's 12-byte fixed structures, including CRC32
//!   integrity.
//! - [`block::parse_block_header`] for variable-length Block
//!   Headers, with single-LZMA2-filter validation, dict-size cap
//!   at 64 MiB, and CRC32 integrity.
//! - LZMA2 chunk types `0x00` (end of stream), `0x01`
//!   (uncompressed + dict reset), and `0x02` (uncompressed, no
//!   reset). The bytes are streamed straight to the sink.
//! - Index walk: `Index_Indicator` + `Number_of_Records` + per-Block
//!   records + padding + CRC32.
//! - Multi-Block Streams within a single .xz file (the file shape
//!   `xz -T0` / `pixz` produces).
//! - Per-Stream `frame_boundary` reporting, mirroring the wrapper
//!   at `src/decode/xz.rs`. Per-LZMA2-chunk granularity arrives in
//!   Phases 6–7.
//!
//! # What Phase 2 added
//!
//! - [`range_coder::RangeDecoder`]: slice-based LZMA range-coder
//!   reader (the foundation for Phases 3 and 4). Exposes
//!   `decode_bit`, `decode_direct_bits`, and the
//!   [`range_coder::bit_tree_decode`] /
//!   [`range_coder::bit_tree_reverse_decode`] glue used by the
//!   LZMA literal/length/distance code in Phase 3. Not yet wired
//!   into the [`Decoder`] state machine — that happens in Phase 4
//!   when LZMA chunks become first-class.
//!
//! # What Phase 3 added
//!
//! - [`lzma_state`]: 12-state machine + four transition tables
//!   (literal / match / rep / short-rep), transcribed from the
//!   LZMA spec.
//! - [`probs::LzmaProbs`]: probability table allocation sized to
//!   the Block's `lc`/`lp`/`pb`, with `reset()` for the LZMA2
//!   chunk control bytes that request a fresh model.
//! - [`probs::decode_literal`] / [`probs::decode_length`] /
//!   [`probs::decode_distance`]: the three inner-loop primitives
//!   the Phase 4 chunk decoder will drive against the range coder
//!   and the dictionary. Not yet wired into the [`Decoder`] state
//!   machine — Phase 4 hooks them up when LZMA chunks become
//!   first-class.
//!
//! # What's deferred
//!
//! - LZMA chunks (control bytes `0x80..=0xFF`) surface
//!   [`error::XzError::LzmaChunkUnimplemented`] (mapped at the
//!   trait boundary into [`crate::decode::DecodeError::Read`]) per
//!   the plan; Phases 2–4 implement the range coder, LZMA
//!   probability tables, and the LZMA2 chunk decoder.
//! - The Block-trailer Check (CRC32 / CRC64 / SHA-256) is read but
//!   not yet verified — Phase 5 wires it up. Block Padding is
//!   consumed and required to be all-zero.
//! - Stream Padding (zero alignment between concatenated Streams)
//!   stays rejected with a clean error, matching the wrapper's
//!   round-one behavior.
//! - BCJ pre-filters and `dict_size > 64 MiB` are rejected at
//!   parse time per `docs/PLAN_xz_block_decoder.md` §Scope.
//!
//! # Source consumption accounting
//!
//! Bytes pulled from the source are counted into `bytes_consumed`
//! as soon as they're handed to us by `Read::read`; partial reads
//! (`Ok(n)` with `n < buf.len()`) advance the counter by `n` only.
//! `frame_boundary` is updated atomically with the state transition
//! that ends a Stream (Stream Footer parsed), so the protocol-level
//! guarantee — "decoding from frame_boundary onward produces the
//! suffix of a clean run" — holds at the same per-Stream
//! granularity the wrapper exposes today.

use std::io::{self, Read, Write};

use crate::decode::{DecodeError, DecodeStatus, StreamingDecoder};
use crate::types::ByteOffset;

pub mod block;
pub mod error;
pub mod lzma_state;
pub mod probs;
pub mod range_coder;
pub mod stream;

#[cfg(test)]
pub(crate) mod test_support;

use self::block::{parse_block_header, parse_lzma2_chunk_header, BlockHeader, Lzma2ChunkHeader};
use self::error::XzError;
use self::stream::{
    parse_stream_footer, parse_stream_header, read_multibyte, CheckId, StreamFlags,
    STREAM_FOOTER_LEN, STREAM_HEADER_LEN,
};

/// Largest possible Index padding before its CRC. The Index has
/// 0..=3 zero bytes of padding so the total Index size aligns to
/// 4 bytes.
const INDEX_PADDING_MAX: usize = 3;

/// Public alias for [`Decoder`] that follows the in-tree
/// `<Format>Decoder` naming convention used by the other decode
/// modules. Internal code keeps the shorter `Decoder` name.
pub use Decoder as XzNativeDecoder;

/// Read exactly `buf.len()` bytes from `source`, advancing
/// `bytes_consumed` for every actually-delivered byte.
///
/// `Ok(0)` mid-buffer surfaces as [`XzError::UnexpectedEof`] with
/// the supplied label so callers can name the field they were
/// trying to read in error messages.
fn read_exact_into(
    source: &mut (dyn Read + Send),
    bytes_consumed: &mut u64,
    buf: &mut [u8],
    label: &'static str,
) -> Result<(), XzError> {
    let mut filled = 0;
    while filled < buf.len() {
        match source.read(&mut buf[filled..]) {
            Ok(0) => return Err(XzError::UnexpectedEof(label)),
            Ok(n) => {
                filled += n;
                // INVARIANT: `n <= buf.len() - filled` and
                // `buf.len() <= isize::MAX`, so `as u64` cannot
                // truncate.
                *bytes_consumed = bytes_consumed.saturating_add(n as u64);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(XzError::SourceIo(e)),
        }
    }
    Ok(())
}

/// Read 1 byte if the source still has data, returning `Ok(None)`
/// when the source has cleanly ended (no bytes delivered).
///
/// Used to detect a follow-on Stream after a Stream Footer: a
/// concatenated `cat a.xz b.xz` puts another Stream Header right
/// after the previous Footer, while a single-Stream file ends
/// there.
fn peek_byte_or_eof(
    source: &mut (dyn Read + Send),
    bytes_consumed: &mut u64,
) -> Result<Option<u8>, XzError> {
    let mut buf = [0u8; 1];
    loop {
        match source.read(&mut buf) {
            Ok(0) => return Ok(None),
            Ok(_) => {
                *bytes_consumed = bytes_consumed.saturating_add(1);
                return Ok(Some(buf[0]));
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(XzError::SourceIo(e)),
        }
    }
}

/// Decoder state machine.
///
/// Plan §Phase 1 specifies four logical states:
/// `Initial -> InStream -> InBlock { ctx } -> Done`. We add an
/// internal `BetweenBlocks` shorthand that captures the byte
/// already pulled from the source so we can decide whether the
/// next Block has a Block Header (size byte ≥ 0x01) or this is
/// the Index Indicator (size byte == 0x00). Plus an `InIndex`
/// state and a Stream Footer parse, all bounded so each
/// `decode_step` does at most one unit of work.
#[derive(Debug)]
enum State {
    /// Need to pull the 12-byte Stream Header.
    AwaitingStreamHeader,
    /// Stream Header parsed; we hold its [`StreamFlags`] across
    /// Blocks so the per-Block Check size is known.
    BetweenBlocks {
        /// Stream Flags as parsed from this Stream's Header — we
        /// re-validate them against the Stream Footer at the end.
        flags: StreamFlags,
        /// Index entries we'll cross-check against the
        /// `Number_of_Records` field once the Index Indicator
        /// arrives. Cleared when entering the next Stream.
        records_seen: u64,
    },
    /// Inside a Block, decoding LZMA2 chunks. The LZMA2 stream
    /// terminates at a control byte of `0x00`; after that we
    /// consume Block Padding + Check and return to
    /// [`State::BetweenBlocks`].
    InBlock {
        /// Stream Flags carried across the Block (Check size
        /// depends on Stream Flags).
        flags: StreamFlags,
        /// Index records accumulated for the surrounding Stream.
        records_seen: u64,
        /// Per-Block accounting context.
        ctx: BlockCtx,
    },
    /// Stream's Index Indicator has been consumed; reading the
    /// `Number_of_Records` field, then the per-Block records.
    InIndex {
        /// Stream Flags carried across to the Footer cross-check.
        flags: StreamFlags,
        /// Index records observed by the time we entered the
        /// Index — must equal the declared `Number_of_Records`.
        records_seen: u64,
    },
    /// Stream finished cleanly. Subsequent steps are no-ops.
    Done,
}

/// Per-Block accounting context. Lives only while
/// [`State::InBlock`] is active; cleared at Block end before
/// returning to [`State::BetweenBlocks`].
#[derive(Debug)]
struct BlockCtx {
    /// Parsed Block Header. Carries the optional declared
    /// `Compressed_Size` and `Uncompressed_Size` for end-of-Block
    /// validation.
    header: BlockHeader,
    /// Source-byte offset where the LZMA2 stream began (just
    /// after the Block Header). Used to compute observed
    /// `Compressed_Size`.
    lzma2_start_offset: u64,
    /// Decompressed bytes emitted from this Block.
    decompressed_so_far: u64,
    /// `true` after the very first chunk has been decoded — the
    /// first chunk in a Block must reset the dictionary, the
    /// rest don't have to. Phase 1 only handles uncompressed
    /// chunks, but we still pin the invariant so Phase 4 inherits
    /// it.
    seen_first_chunk: bool,
    /// `true` once we've consumed an `EndOfStream` LZMA2 chunk
    /// (control byte `0x00`). After that we still owe Block
    /// Padding + Check before returning to `BetweenBlocks`.
    lzma2_finished: bool,
}

/// Streaming pure-Rust .xz decoder.
///
/// Owns its source on construction; subsequent
/// [`StreamingDecoder::decode_step`] calls do not need it passed
/// back in. The source is `Send` so the decoder can be moved to a
/// worker thread the same way [`crate::decode::xz::XzDecoder`] can.
pub struct Decoder {
    /// Wrapped source, dropped on terminal error or clean EOF so
    /// further `decode_step` calls cheaply short-circuit.
    source: Option<Box<dyn Read + Send>>,
    /// State machine; see [`State`].
    state: State,
    /// High-water source-byte counter — what
    /// [`StreamingDecoder::bytes_consumed`] returns. Advanced only
    /// after a successful read; partial reads advance only by
    /// what was actually delivered.
    bytes_consumed: u64,
    /// Latest Stream-end boundary observed, or `None` if no
    /// Stream has completed yet. Per-LZMA2-chunk boundaries are
    /// added in Phases 6–7.
    last_frame_boundary: Option<ByteOffset>,
    /// Source-byte offset where the most recent Index began. Used
    /// to compare the observed Index length against the
    /// `Backward_Size` field in the Stream Footer.
    index_start_offset: u64,
    /// Reusable scratch for one Block Header. Sized to the spec's
    /// 1024-byte cap on first use; held thereafter.
    block_header_buf: Vec<u8>,
}

impl Decoder {
    /// Construct a [`Decoder`] over `src`.
    ///
    /// Does not pull any bytes from the source.
    ///
    /// # Errors
    ///
    /// Currently never returns `Err`; the signature is fallible to
    /// match [`crate::decode::DecoderFactory`].
    pub fn new(src: Box<dyn Read + Send>) -> Result<Self, DecodeError> {
        Ok(Self {
            source: Some(src),
            state: State::AwaitingStreamHeader,
            bytes_consumed: 0,
            last_frame_boundary: None,
            index_start_offset: 0,
            block_header_buf: Vec::new(),
        })
    }

    fn finish_stream(&mut self) {
        self.last_frame_boundary = Some(ByteOffset::new(self.bytes_consumed));
    }

    fn step_inner(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, XzError> {
        // Each call performs at most one unit of work — read one
        // structural element (Stream Header, Block Header, single
        // LZMA2 chunk, Index, Stream Footer) — and returns. The
        // state machine itself loops *across* calls, not within a
        // single call, so the coordinator can interleave punching
        // and checkpointing.
        match &mut self.state {
            State::Done => Ok(DecodeStatus::Eof),

            State::AwaitingStreamHeader => {
                let Some(source) = self.source.as_mut() else {
                    self.state = State::Done;
                    return Ok(DecodeStatus::Eof);
                };
                let mut buf = [0u8; STREAM_HEADER_LEN];
                read_exact_into(
                    source.as_mut(),
                    &mut self.bytes_consumed,
                    &mut buf,
                    "Stream Header",
                )?;
                let flags = parse_stream_header(&buf)?;
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
                let records_seen = *records_seen;
                let Some(source) = self.source.as_mut() else {
                    return Err(XzError::UnexpectedEof("Block Header size byte"));
                };
                // Read the Block_Header_Size byte. 0x00 routes
                // to the Index Indicator path; non-zero is
                // the leading byte of a real Block Header.
                let mut size_byte = [0u8; 1];
                read_exact_into(
                    source.as_mut(),
                    &mut self.bytes_consumed,
                    &mut size_byte,
                    "Block Header size byte",
                )?;
                if size_byte[0] == 0x00 {
                    // The Index Indicator we just consumed
                    // counts as the first byte of the Index
                    // for the Backward_Size cross-check.
                    self.index_start_offset = self.bytes_consumed - 1;
                    self.state = State::InIndex {
                        flags,
                        records_seen,
                    };
                    return Ok(DecodeStatus::MoreData);
                }
                let real_size = block::block_header_real_size(size_byte[0]);
                self.block_header_buf.clear();
                self.block_header_buf.resize(real_size, 0);
                self.block_header_buf[0] = size_byte[0];
                let source = self.source.as_mut().expect("source still present");
                read_exact_into(
                    source.as_mut(),
                    &mut self.bytes_consumed,
                    &mut self.block_header_buf[1..],
                    "Block Header tail",
                )?;
                let header = parse_block_header(&self.block_header_buf)?;
                let lzma2_start_offset = self.bytes_consumed;
                self.state = State::InBlock {
                    flags,
                    records_seen,
                    ctx: BlockCtx {
                        header,
                        lzma2_start_offset,
                        decompressed_so_far: 0,
                        seen_first_chunk: false,
                        lzma2_finished: false,
                    },
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
                    // Read one LZMA2 chunk, decode it, return
                    // for caller to interleave punching.
                    Self::process_lzma2_chunk(
                        self.source
                            .as_mut()
                            .ok_or(XzError::UnexpectedEof("LZMA2 chunk"))?
                            .as_mut(),
                        &mut self.bytes_consumed,
                        ctx,
                        sink,
                    )?;
                    return Ok(DecodeStatus::MoreData);
                }
                // LZMA2 finished. Validate sizes, consume
                // Block Padding + Check, return to
                // BetweenBlocks. Phase 5 verifies the Check;
                // Phase 1 reads it and advances.
                let observed_compressed =
                    self.bytes_consumed.saturating_sub(ctx.lzma2_start_offset);
                if let Some(declared) = ctx.header.compressed_size {
                    if declared != observed_compressed {
                        return Err(XzError::BlockSizeMismatch {
                            field: "Compressed_Size",
                            declared,
                            actual: observed_compressed,
                        });
                    }
                }
                if let Some(declared) = ctx.header.uncompressed_size {
                    if declared != ctx.decompressed_so_far {
                        return Err(XzError::BlockSizeMismatch {
                            field: "Uncompressed_Size",
                            declared,
                            actual: ctx.decompressed_so_far,
                        });
                    }
                }

                // Block Padding: 0..=3 zero bytes to align
                // the LZMA2 stream to a 4-byte boundary.
                let pad_len = (4 - (observed_compressed & 0b11) as usize) & 0b11;
                if pad_len > 0 {
                    let mut pad = [0u8; 3];
                    let source = self
                        .source
                        .as_mut()
                        .ok_or(XzError::UnexpectedEof("Block Padding"))?;
                    read_exact_into(
                        source.as_mut(),
                        &mut self.bytes_consumed,
                        &mut pad[..pad_len],
                        "Block Padding",
                    )?;
                    for &b in &pad[..pad_len] {
                        if b != 0x00 {
                            return Err(XzError::MalformedBlockHeader(
                                "non-zero Block Padding byte",
                            ));
                        }
                    }
                }

                let check_size = flags.check.size();
                if check_size > 0 {
                    let mut check_buf = [0u8; 32]; // Max == SHA-256 size
                    let source = self
                        .source
                        .as_mut()
                        .ok_or(XzError::UnexpectedEof("Block Check"))?;
                    read_exact_into(
                        source.as_mut(),
                        &mut self.bytes_consumed,
                        &mut check_buf[..check_size],
                        "Block Check",
                    )?;
                    // Phase 5 verifies the Check value against
                    // the decompressed output. Phase 1 reads
                    // and discards.
                    let _ = match flags.check {
                        CheckId::None => 0u64,
                        CheckId::Crc32 => {
                            u32::from_le_bytes(check_buf[..4].try_into().expect("len")) as u64
                        }
                        CheckId::Crc64 => {
                            u64::from_le_bytes(check_buf[..8].try_into().expect("len"))
                        }
                        CheckId::Sha256 => 0u64,
                    };
                }

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
                // Index layout: Index_Indicator (already
                // consumed) + Number_of_Records (varint) +
                // per-Block records (Unpadded_Size +
                // Uncompressed_Size, varints) + 0..=3 zero
                // bytes padding + 4-byte CRC32. We read the
                // whole tail in one go because the Index is
                // bounded by the running Block count and a
                // small constant.
                let source = self
                    .source
                    .as_mut()
                    .ok_or(XzError::UnexpectedEof("Index"))?;
                // Pull the Number_of_Records varint first, by
                // reading bytes one at a time until the
                // continuation bit clears.
                let num_records = read_varint_streaming(source.as_mut(), &mut self.bytes_consumed)?;
                if num_records != records_seen {
                    return Err(XzError::MalformedBlockHeader(
                        "Index record count differs from observed Block count",
                    ));
                }
                // For each record, read two varints. We don't
                // cross-check the values yet — Phase 5 does
                // that. Phase 1 just consumes them so the
                // Stream Footer parse lines up.
                for _ in 0..num_records {
                    let _unpadded =
                        read_varint_streaming(source.as_mut(), &mut self.bytes_consumed)?;
                    let _uncomp = read_varint_streaming(source.as_mut(), &mut self.bytes_consumed)?;
                }
                // Index Padding + CRC32.
                let index_len_so_far = self.bytes_consumed - self.index_start_offset;
                let pad_len = (4 - (index_len_so_far & 0b11) as usize) & 0b11;
                if pad_len > 0 {
                    let mut pad = [0u8; INDEX_PADDING_MAX];
                    read_exact_into(
                        source.as_mut(),
                        &mut self.bytes_consumed,
                        &mut pad[..pad_len],
                        "Index Padding",
                    )?;
                    for &b in &pad[..pad_len] {
                        if b != 0x00 {
                            return Err(XzError::MalformedBlockHeader(
                                "non-zero Index Padding byte",
                            ));
                        }
                    }
                }
                let mut crc_bytes = [0u8; 4];
                read_exact_into(
                    source.as_mut(),
                    &mut self.bytes_consumed,
                    &mut crc_bytes,
                    "Index CRC32",
                )?;
                // Index CRC verification: Phase 5 wires it up
                // properly. For Phase 1 we read & discard so
                // the byte counts stay aligned with the
                // Stream Footer's Backward_Size.

                // Stream Footer.
                let index_len = self.bytes_consumed - self.index_start_offset;
                let mut footer = [0u8; STREAM_FOOTER_LEN];
                read_exact_into(
                    source.as_mut(),
                    &mut self.bytes_consumed,
                    &mut footer,
                    "Stream Footer",
                )?;
                let (footer_flags, backward_size) = parse_stream_footer(&footer)?;
                if footer_flags != flags {
                    return Err(XzError::StreamFlagsMismatch {
                        header: flags.as_u16(),
                        footer: footer_flags.as_u16(),
                    });
                }
                if backward_size != index_len {
                    return Err(XzError::BackwardSizeMismatch {
                        declared: backward_size,
                        actual: index_len,
                    });
                }

                self.finish_stream();

                // Decide whether another Stream follows. The
                // wrapper at `src/decode/xz.rs` rejects Stream
                // Padding; so do we. The next byte (if any)
                // must be the leading byte of a fresh Stream
                // Header.
                let source = self
                    .source
                    .as_mut()
                    .ok_or(XzError::UnexpectedEof("possible follow-on Stream Header"))?;
                let next = peek_byte_or_eof(source.as_mut(), &mut self.bytes_consumed)?;
                match next {
                    None => {
                        self.source = None;
                        self.state = State::Done;
                        Ok(DecodeStatus::MoreData)
                    }
                    // Stream Padding (which we reject) or a
                    // malformed follow-on Stream: a real
                    // Stream Header magic byte 0 is `0xFD`,
                    // not zero. Either way, bail.
                    Some(0x00) => Err(XzError::StreamPaddingUnsupported),
                    Some(byte) => {
                        // Pull the rest of the Stream Header
                        // (we already consumed its first
                        // byte). On a clean follow-on Stream
                        // this byte equals `0xFD`; we'll
                        // catch a magic mismatch in the
                        // header parser.
                        let mut full = [0u8; STREAM_HEADER_LEN];
                        full[0] = byte;
                        let source = self
                            .source
                            .as_mut()
                            .ok_or(XzError::UnexpectedEof("Stream Header"))?;
                        read_exact_into(
                            source.as_mut(),
                            &mut self.bytes_consumed,
                            &mut full[1..],
                            "Stream Header tail",
                        )?;
                        let new_flags = parse_stream_header(&full)?;
                        self.state = State::BetweenBlocks {
                            flags: new_flags,
                            records_seen: 0,
                        };
                        Ok(DecodeStatus::MoreData)
                    }
                }
            }
        }
    }

    /// Consume the next LZMA2 chunk from the source, write any
    /// decompressed output to `sink`, and update `ctx`.
    ///
    /// Pulled out of the `InBlock` arm so it can hold a `&mut`
    /// to `ctx` while still calling into a helper that wants to
    /// borrow the source separately — same shape as the zstd
    /// helper at `src/decode/zstd.rs`.
    fn process_lzma2_chunk(
        source: &mut (dyn Read + Send),
        bytes_consumed: &mut u64,
        ctx: &mut BlockCtx,
        sink: &mut dyn Write,
    ) -> Result<(), XzError> {
        let mut ctl = [0u8; 1];
        read_exact_into(source, bytes_consumed, &mut ctl, "LZMA2 chunk control byte")?;
        // We need to peek the parsed shape to know how many more
        // bytes to pull. The chunk header is at most 6 bytes; we
        // refill once more to cover all variants.
        let mut buf = [0u8; 6];
        buf[0] = ctl[0];
        // Determine how many additional bytes are needed for the
        // chunk header (excluding properties + payload).
        let need_more = match ctl[0] {
            0x00 => 0,
            0x01 | 0x02 => 2,
            0x03..=0x7F => 0, // reserved; let the parser reject
            0x80..=0xFF => {
                // mode 0b10 / 0b11 carry a properties byte —
                // we'll pull that one along with the size
                // fields.
                if (ctl[0] >> 5) & 0b11 >= 0b10 {
                    5
                } else {
                    4
                }
            }
        };
        if need_more > 0 {
            read_exact_into(
                source,
                bytes_consumed,
                &mut buf[1..1 + need_more],
                "LZMA2 chunk header",
            )?;
        }
        let chunk = parse_lzma2_chunk_header(&buf[..1 + need_more])?;

        // Enforce: first chunk in a Block must reset the dict.
        if !ctx.seen_first_chunk
            && !chunk.resets_dict()
            && !matches!(chunk, Lzma2ChunkHeader::EndOfStream)
        {
            return Err(XzError::Lzma2MissingInitialReset(ctl[0]));
        }
        ctx.seen_first_chunk = true;

        match chunk {
            Lzma2ChunkHeader::EndOfStream => {
                ctx.lzma2_finished = true;
                Ok(())
            }
            Lzma2ChunkHeader::Uncompressed {
                uncompressed_size, ..
            } => {
                // Stream the chunk payload straight to the sink
                // in fixed-size pieces so we don't allocate a
                // 64 KiB scratch on every chunk.
                let mut remaining = uncompressed_size as usize;
                let mut scratch = [0u8; 4096];
                while remaining > 0 {
                    let take = remaining.min(scratch.len());
                    read_exact_into(
                        source,
                        bytes_consumed,
                        &mut scratch[..take],
                        "LZMA2 uncompressed chunk payload",
                    )?;
                    sink.write_all(&scratch[..take]).map_err(XzError::SinkIo)?;
                    remaining -= take;
                }
                ctx.decompressed_so_far = ctx
                    .decompressed_so_far
                    .saturating_add(u64::from(uncompressed_size));
                Ok(())
            }
            Lzma2ChunkHeader::Lzma { .. } => {
                // Phase 4 will replace this with a real LZMA
                // decoder; until then we surface a clean
                // "unimplemented" error so callers can fall back
                // to the wrapper at `src/decode/xz.rs`.
                Err(XzError::LzmaChunkUnimplemented)
            }
        }
    }
}

/// Read a multibyte (varint) integer from a streaming source one
/// byte at a time, advancing `bytes_consumed` for each byte
/// delivered.
///
/// The Index can in theory be larger than any single buffer — a
/// large multi-Block stream has one record per Block, each
/// holding two varints — so we pull bytes one at a time rather
/// than refill a fixed-size scratch.
fn read_varint_streaming(
    source: &mut (dyn Read + Send),
    bytes_consumed: &mut u64,
) -> Result<u64, XzError> {
    let mut buf = [0u8; stream::MAX_MULTIBYTE_LEN];
    for i in 0..stream::MAX_MULTIBYTE_LEN {
        read_exact_into(
            source,
            bytes_consumed,
            &mut buf[i..i + 1],
            "multibyte integer",
        )?;
        if buf[i] & 0x80 == 0 {
            let (value, n) = read_multibyte(&buf[..=i])?;
            // INVARIANT: read_multibyte consumed all bytes since
            // the terminator was the last one we read.
            debug_assert_eq!(n, i + 1);
            return Ok(value);
        }
    }
    Err(XzError::MalformedMultibyte("encoding exceeds 9 bytes"))
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
                // Errors are terminal — drop the source so
                // further calls cleanly short-circuit and OS
                // resources are released as soon as possible.
                self.source = None;
                self.state = State::Done;
                Err(e.into_decode_error(consumed))
            }
        }
    }

    fn bytes_consumed(&self) -> ByteOffset {
        ByteOffset::new(self.bytes_consumed)
    }

    fn frame_boundary(&self) -> Option<ByteOffset> {
        self.last_frame_boundary
    }
}

/// [`crate::decode::DecoderFactory`] adapter for [`Decoder`].
///
/// Not registered by [`crate::decode::DecoderRegistry::with_defaults`]
/// in Phase 1 — the production path still goes through the upstream
/// wrapper. Phase 7 swaps the registration.
///
/// # Errors
///
/// Forwards any error returned by [`Decoder::new`].
pub fn factory(src: Box<dyn Read + Send>) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    Ok(Box::new(Decoder::new(src)?))
}

// Allow inner modules to reach the private helpers used in tests.
#[cfg(test)]
pub(crate) use stream::write_multibyte as test_write_multibyte;

#[cfg(test)]
mod tests {
    use super::block::LZMA2_FILTER_ID;
    use super::stream::{
        crc32, write_multibyte, CheckId, StreamFlags, STREAM_FOOTER_MAGIC, STREAM_HEADER_MAGIC,
    };
    use super::*;

    use std::io::Cursor;

    /// Hand-build an .xz Stream from a list of (uncompressed)
    /// payload chunks: one Block, one or more LZMA2
    /// uncompressed-chunk records. Mirrors what `xz
    /// --lzma2=preset=0` produces for tiny inputs (the spike's
    /// "tiny → uncompressed-mode LZMA2 chunk" fixture shape).
    fn build_xz_uncompressed(payloads: &[&[u8]], check: CheckId, dict_encoded: u8) -> Vec<u8> {
        // Stream Header
        let flags = StreamFlags { check };
        let flag_bytes = flags.to_bytes();
        let stream_hdr_crc = crc32(&flag_bytes);
        let mut out = Vec::new();
        out.extend_from_slice(&STREAM_HEADER_MAGIC);
        out.extend_from_slice(&flag_bytes);
        out.extend_from_slice(&stream_hdr_crc.to_le_bytes());

        // LZMA2 stream: first chunk has reset_dict = true, rest
        // do not. Each uncompressed chunk: control byte (0x01 or
        // 0x02) + 2-byte BE size-1 + payload bytes. Then
        // 0x00-byte EndOfStream marker.
        let mut lzma2: Vec<u8> = Vec::new();
        for (i, p) in payloads.iter().enumerate() {
            assert!(!p.is_empty() && p.len() <= 65_536, "valid chunk size");
            let ctl = if i == 0 { 0x01u8 } else { 0x02u8 };
            lzma2.push(ctl);
            let s = (p.len() - 1) as u16;
            lzma2.extend_from_slice(&s.to_be_bytes());
            lzma2.extend_from_slice(p);
        }
        lzma2.push(0x00); // EndOfStream

        let total_uncompressed: u64 = payloads.iter().map(|p| p.len() as u64).sum();
        let compressed_size = lzma2.len() as u64;

        // Block Header — declare both sizes (matches `xz` CLI
        // output by default).
        let mut body = Vec::new();
        let flags_byte: u8 = 0b1100_0000; // both sizes present, num_filters = 1
        body.push(flags_byte);
        write_multibyte(compressed_size, &mut body);
        write_multibyte(total_uncompressed, &mut body);
        write_multibyte(LZMA2_FILTER_ID, &mut body);
        write_multibyte(1, &mut body); // props size
        body.push(dict_encoded);

        let total_unpadded = body.len() + 1 + 4;
        let total = (total_unpadded + 3) & !3;
        let pad = total - total_unpadded;
        body.resize(body.len() + pad, 0x00);
        let stored = ((total / 4) - 1) as u8;
        let mut bh = Vec::with_capacity(total);
        bh.push(stored);
        bh.extend_from_slice(&body);
        let bh_crc = crc32(&bh);
        bh.extend_from_slice(&bh_crc.to_le_bytes());

        // Block: header + LZMA2 + padding + check
        out.extend_from_slice(&bh);
        let block_offset_before_lzma2 = out.len();
        out.extend_from_slice(&lzma2);
        let lzma2_len = out.len() - block_offset_before_lzma2;
        let block_pad = (4 - (lzma2_len & 0b11)) & 0b11;
        out.resize(out.len() + block_pad, 0x00);
        // Phase 1 doesn't verify the Check, so we can write zeros
        // for the right size and the decoder will accept them.
        out.resize(out.len() + check.size(), 0x00);

        // Index: indicator + 1-record (this Block) + padding + CRC32.
        let index_start = out.len();
        out.push(0x00); // Index Indicator
        write_multibyte(1, &mut out); // Number_of_Records = 1
        let unpadded_size = bh.len() as u64 + lzma2_len as u64 + check.size() as u64;
        write_multibyte(unpadded_size, &mut out);
        write_multibyte(total_uncompressed, &mut out);
        let index_so_far = out.len() - index_start;
        let index_pad = (4 - (index_so_far & 0b11)) & 0b11;
        out.resize(out.len() + index_pad, 0x00);
        let index_crc_input_start = index_start;
        let index_crc = crc32(&out[index_crc_input_start..]);
        out.extend_from_slice(&index_crc.to_le_bytes());
        let index_len = (out.len() - index_start) as u64;

        // Stream Footer
        let backward_raw = u32::try_from((index_len / 4) - 1).expect("backward_size in range");
        let mut footer_middle = [0u8; 6];
        footer_middle[..4].copy_from_slice(&backward_raw.to_le_bytes());
        footer_middle[4..6].copy_from_slice(&flag_bytes);
        let footer_crc = crc32(&footer_middle);
        out.extend_from_slice(&footer_crc.to_le_bytes());
        out.extend_from_slice(&footer_middle);
        out.extend_from_slice(&STREAM_FOOTER_MAGIC);

        out
    }

    fn decode_all(input: Vec<u8>) -> (Vec<u8>, Decoder) {
        let mut decoder = Decoder::new(Box::new(Cursor::new(input))).expect("construct");
        let mut sink = Vec::new();
        loop {
            let status = decoder.decode_step(&mut sink).expect("step");
            if status == DecodeStatus::Eof {
                break;
            }
        }
        (sink, decoder)
    }

    #[test]
    fn single_chunk_uncompressed_round_trip() {
        let payload = b"hello, xz native";
        let bytes = build_xz_uncompressed(&[payload], CheckId::Crc64, 12);
        let len = bytes.len();
        let (out, dec) = decode_all(bytes);
        assert_eq!(out, payload);
        assert_eq!(dec.bytes_consumed().get(), len as u64);
        assert!(dec.frame_boundary().is_some());
    }

    #[test]
    fn multi_chunk_uncompressed_round_trip() {
        let p1 = b"chunk-one ".repeat(100);
        let p2 = b"chunk-two ".repeat(50);
        let p3 = b"chunk-three";
        let bytes = build_xz_uncompressed(&[&p1, &p2, p3], CheckId::Crc64, 12);
        let mut expected = p1.clone();
        expected.extend_from_slice(&p2);
        expected.extend_from_slice(p3);
        let (out, _dec) = decode_all(bytes);
        assert_eq!(out, expected);
    }

    #[test]
    fn supports_all_check_ids() {
        for check in [
            CheckId::None,
            CheckId::Crc32,
            CheckId::Crc64,
            CheckId::Sha256,
        ] {
            let payload = b"check-id-test";
            let bytes = build_xz_uncompressed(&[payload], check, 0);
            let (out, _dec) = decode_all(bytes);
            assert_eq!(out, payload);
        }
    }

    /// Frame boundary lands at exactly the end of the Stream
    /// Footer.
    #[test]
    fn frame_boundary_at_stream_footer_end() {
        let payload = b"boundary-test";
        let bytes = build_xz_uncompressed(&[payload], CheckId::Crc64, 12);
        let len = bytes.len();
        let mut decoder = Decoder::new(Box::new(Cursor::new(bytes))).expect("construct");
        let mut sink = Vec::new();
        loop {
            let status = decoder.decode_step(&mut sink).expect("step");
            if status == DecodeStatus::Eof {
                break;
            }
        }
        assert_eq!(decoder.frame_boundary(), Some(ByteOffset::new(len as u64)));
    }

    /// `bytes_consumed` is monotonically non-decreasing across
    /// every `decode_step` call.
    #[test]
    fn bytes_consumed_is_monotone() {
        let payload = b"monotone-payload".repeat(8);
        let bytes = build_xz_uncompressed(&[&payload], CheckId::Crc64, 12);
        let mut decoder = Decoder::new(Box::new(Cursor::new(bytes))).expect("construct");
        let mut last = 0u64;
        let mut sink = Vec::new();
        loop {
            let status = decoder.decode_step(&mut sink).expect("step");
            let now = decoder.bytes_consumed().get();
            assert!(now >= last, "regressed {last} -> {now}");
            last = now;
            if status == DecodeStatus::Eof {
                break;
            }
        }
    }

    /// `bytes_consumed` is bounded above by the actual source
    /// size at every observation, even mid-stream.
    #[test]
    fn bytes_consumed_never_exceeds_source_length() {
        let payload = b"bounded-payload".repeat(16);
        let bytes = build_xz_uncompressed(&[&payload], CheckId::Crc64, 12);
        let len = bytes.len() as u64;
        let mut decoder = Decoder::new(Box::new(Cursor::new(bytes))).expect("construct");
        let mut sink = Vec::new();
        loop {
            let status = decoder.decode_step(&mut sink).expect("step");
            assert!(decoder.bytes_consumed().get() <= len);
            if status == DecodeStatus::Eof {
                break;
            }
        }
        assert_eq!(decoder.bytes_consumed().get(), len);
    }

    /// After EOF, repeated calls keep returning `Eof` without
    /// touching the (now-dropped) source.
    #[test]
    fn repeated_calls_after_eof_stay_eof() {
        let bytes = build_xz_uncompressed(&[b"foo"], CheckId::None, 0);
        let mut decoder = Decoder::new(Box::new(Cursor::new(bytes))).expect("construct");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("step") == DecodeStatus::MoreData {}
        for _ in 0..5 {
            assert_eq!(
                decoder.decode_step(&mut sink).expect("idempotent eof"),
                DecodeStatus::Eof,
            );
        }
        assert_eq!(sink, b"foo");
    }

    /// Empty source: very first step returns Read error at the
    /// missing Stream Header.
    #[test]
    fn empty_source_reports_read_error() {
        let mut decoder = Decoder::new(Box::new(Cursor::new(Vec::<u8>::new()))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { consumed, .. }) => {
                assert_eq!(consumed, 0);
            }
            other => panic!("expected Read error, got {other:?}"),
        }
    }

    /// Garbage input is rejected with a `Read` error containing
    /// "bad Stream Header magic".
    #[test]
    fn garbage_source_rejected_with_bad_magic() {
        let garbage = vec![0xDEu8; 64];
        let mut decoder = Decoder::new(Box::new(Cursor::new(garbage))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { source, .. }) => {
                let msg = source.to_string();
                assert!(msg.contains("bad Stream Header magic"), "msg: {msg}");
            }
            other => panic!("expected Read error, got {other:?}"),
        }
    }

    /// Truncated stream surfaces as a clean Read error rather
    /// than a panic.
    #[test]
    fn truncated_stream_reports_read_error() {
        let bytes = build_xz_uncompressed(&[b"truncate-me"], CheckId::Crc64, 12);
        let truncated = bytes[..bytes.len() - 8].to_vec();
        let len = truncated.len() as u64;
        let mut decoder = Decoder::new(Box::new(Cursor::new(truncated))).expect("construct");
        let mut sink = Vec::new();
        loop {
            match decoder.decode_step(&mut sink) {
                Ok(DecodeStatus::MoreData) => continue,
                Ok(DecodeStatus::Eof) => panic!("truncated should not reach Eof cleanly"),
                Err(DecodeError::Read { consumed, .. }) => {
                    assert!(consumed <= len);
                    return;
                }
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
    }

    /// A failing sink produces [`DecodeError::Write`] rather than
    /// silently dropping output.
    #[test]
    fn sink_failure_propagates_as_write_error() {
        struct FailingSink;
        impl Write for FailingSink {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "no"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let bytes = build_xz_uncompressed(&[b"sink-fails"], CheckId::None, 0);
        let mut decoder = Decoder::new(Box::new(Cursor::new(bytes))).expect("construct");
        let mut hit_write = false;
        for _ in 0..1024 {
            match decoder.decode_step(&mut FailingSink) {
                Ok(DecodeStatus::MoreData) => continue,
                Ok(DecodeStatus::Eof) => break,
                Err(DecodeError::Write(e)) => {
                    assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe);
                    hit_write = true;
                    break;
                }
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
        assert!(hit_write, "expected a Write error against the failing sink");
    }

    /// LZMA chunks (control bytes 0x80..=0xFF) surface the
    /// deliberate Phase-1 placeholder error rather than panicking
    /// or silently producing garbage.
    #[test]
    fn lzma_chunk_returns_unimplemented_error() {
        // Build an .xz file whose LZMA2 stream's first chunk is
        // an LZMA-compressed chunk (0xE0...) so the parser
        // dispatches into the Phase-1 stub. We don't need real
        // compressed data — the dispatch fails before the
        // payload is touched.
        let mut lzma2: Vec<u8> = Vec::new();
        // 0xE0 = full reset + props; needs 6-byte header + 1
        // props byte. Sizes encode "1": uncompressed_size=1
        // (high5=0, low16=0), compressed_size=1 (low16=0). The
        // fake props byte is 0 (lc=0, lp=0, pb=0).
        lzma2.extend_from_slice(&[0xE0, 0x00, 0x00, 0x00, 0x00, 0x00]);
        lzma2.push(0x00); // payload byte (won't be read)
        lzma2.push(0x00); // EndOfStream

        let flags = StreamFlags {
            check: CheckId::None,
        };
        let flag_bytes = flags.to_bytes();
        let stream_hdr_crc = crc32(&flag_bytes);
        let mut out = Vec::new();
        out.extend_from_slice(&STREAM_HEADER_MAGIC);
        out.extend_from_slice(&flag_bytes);
        out.extend_from_slice(&stream_hdr_crc.to_le_bytes());

        let mut body = Vec::new();
        body.push(0u8); // flags: no sizes, num_filters=1
        write_multibyte(LZMA2_FILTER_ID, &mut body);
        write_multibyte(1, &mut body);
        body.push(0u8); // dict_encoded
        let total_unpadded = body.len() + 1 + 4;
        let total = (total_unpadded + 3) & !3;
        let pad = total - total_unpadded;
        body.resize(body.len() + pad, 0x00);
        let stored = ((total / 4) - 1) as u8;
        let mut bh = Vec::with_capacity(total);
        bh.push(stored);
        bh.extend_from_slice(&body);
        let bh_crc = crc32(&bh);
        bh.extend_from_slice(&bh_crc.to_le_bytes());
        out.extend_from_slice(&bh);
        out.extend_from_slice(&lzma2);

        let mut decoder = Decoder::new(Box::new(Cursor::new(out))).expect("construct");
        let mut sink = Vec::new();
        loop {
            match decoder.decode_step(&mut sink) {
                Ok(DecodeStatus::MoreData) => continue,
                Ok(DecodeStatus::Eof) => panic!("expected error before EOF"),
                Err(DecodeError::Read { source, .. }) => {
                    let msg = source.to_string();
                    assert!(
                        msg.contains("LZMA chunk decoding not yet implemented"),
                        "msg: {msg}"
                    );
                    return;
                }
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
    }

    /// Stream Padding (zero bytes between concatenated Streams)
    /// is rejected, matching the wrapper's behavior in
    /// `src/decode/xz.rs`.
    #[test]
    fn stream_padding_rejected() {
        let mut bytes = build_xz_uncompressed(&[b"padded-test"], CheckId::None, 0);
        // Append four zero bytes before EOF. The decoder should
        // reject this rather than silently advance.
        bytes.extend_from_slice(&[0u8; 4]);
        let mut decoder = Decoder::new(Box::new(Cursor::new(bytes))).expect("construct");
        let mut sink = Vec::new();
        loop {
            match decoder.decode_step(&mut sink) {
                Ok(DecodeStatus::MoreData) => continue,
                Ok(DecodeStatus::Eof) => panic!("expected error before EOF"),
                Err(DecodeError::Read { source, .. }) => {
                    let msg = source.to_string();
                    assert!(msg.contains("Stream Padding"), "msg: {msg}");
                    return;
                }
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
    }

    /// Multi-Stream input — `cat a.xz b.xz` shape — decodes the
    /// concatenation of both payloads and surfaces a frame
    /// boundary at each Stream's end.
    #[test]
    fn concatenated_streams_decode_in_order() {
        let a = build_xz_uncompressed(&[b"alpha"], CheckId::Crc64, 12);
        let b = build_xz_uncompressed(&[b"beta"], CheckId::None, 0);
        let a_len = a.len();
        let total = a_len + b.len();
        let mut combined = a;
        combined.extend_from_slice(&b);

        let mut decoder = Decoder::new(Box::new(Cursor::new(combined))).expect("construct");
        let mut sink = Vec::new();
        let mut boundaries: Vec<u64> = Vec::new();
        loop {
            let prior = decoder.frame_boundary();
            let status = decoder.decode_step(&mut sink).expect("step");
            let next = decoder.frame_boundary();
            if next != prior {
                boundaries.push(next.expect("just observed").get());
            }
            if status == DecodeStatus::Eof {
                break;
            }
        }
        assert_eq!(sink, b"alphabeta");
        assert_eq!(boundaries, vec![a_len as u64, total as u64]);
    }

    /// Captured byte-for-byte from `printf 'hello' | xz
    /// --lzma2=preset=0` (xz 5.8.3). Pinned in this constant so
    /// the round-trip and concatenation tests share the same
    /// liblzma-produced fixture and a regression in either path
    /// names the format-level cause directly.
    const REAL_XZ_HELLO: &[u8] = &[
        0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00, 0x04, 0xE6, 0xD6, 0xB4, 0x46, 0x03, 0xC0, 0x09,
        0x05, 0x21, 0x01, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6D, 0xFF, 0x09, 0xFF, 0x01, 0x00,
        0x04, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0x00, 0x00, 0x00, 0xB1, 0x37, 0xB9, 0xDB, 0xE5,
        0xDA, 0x1E, 0x9B, 0x00, 0x01, 0x21, 0x05, 0x47, 0x54, 0x73, 0xDC, 0x1F, 0xB6, 0xF3, 0x7D,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x59, 0x5A,
    ];

    /// Real `xz --lzma2=preset=0` output on a tiny payload uses
    /// uncompressed LZMA2 chunks; we should byte-identically
    /// decode it.
    #[test]
    fn real_xz_preset_0_tiny_payload_round_trip() {
        let bytes = REAL_XZ_HELLO;
        let (out, dec) = decode_all(bytes.to_vec());
        assert_eq!(out, b"hello");
        assert_eq!(dec.bytes_consumed().get(), bytes.len() as u64);
        assert_eq!(
            dec.frame_boundary(),
            Some(ByteOffset::new(bytes.len() as u64))
        );
    }

    /// Same payload as a multi-Stream concatenation: two real
    /// `xz` outputs glued together. Pins the multi-Stream
    /// follow-on path against actual liblzma output rather than
    /// only our hand-built fixtures.
    #[test]
    fn real_xz_two_concatenated_streams_round_trip() {
        let mut combined = REAL_XZ_HELLO.to_vec();
        combined.extend_from_slice(REAL_XZ_HELLO);
        let (out, _dec) = decode_all(combined);
        assert_eq!(out, b"hellohello");
    }

    /// The factory plumbing constructs a working decoder.
    #[test]
    fn factory_constructs_and_decodes() {
        let bytes = build_xz_uncompressed(&[b"factory-test"], CheckId::Crc64, 12);
        let mut decoder = factory(Box::new(Cursor::new(bytes))).expect("factory");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("step") == DecodeStatus::MoreData {}
        assert_eq!(sink, b"factory-test");
    }

    /// Pin the helper used in test fixtures: round-trips a
    /// hand-built multibyte integer through both write and read.
    #[test]
    fn write_multibyte_round_trip() {
        let mut buf = Vec::new();
        let n = test_write_multibyte(123_456_789, &mut buf);
        assert!((1..=9).contains(&n));
        let (got, m) = read_multibyte(&buf).expect("decode");
        assert_eq!(got, 123_456_789);
        assert_eq!(m, n);
    }
}
