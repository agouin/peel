//! Hand-rolled, pure-Rust Zstandard streaming decoder.
//!
//! Phase 1 of `docs/PLAN_zstd_block_decoder.md`. Lives here behind a
//! cargo feature flag (`peel_zstd_native`) so production paths still
//! route through [`crate::decode::zstd::ZstdDecoder`] (the upstream
//! `zstd` crate binding) until Phase 8 swaps the implementations.
//!
//! # What's working in Phase 1
//!
//! - [`frame::parse_frame_header`] — RFC 8478 §3.1.1.1.1, including
//!   skippable-frame magic classification.
//! - [`block::parse_block_header`] — RFC 8478 §3.1.1.2.
//! - `Raw_Block` and `RLE_Block` decoding — verbatim copy and
//!   single-byte-repeated, respectively.
//! - Skippable frame skipping (consumes magic + 4-byte length +
//!   that many opaque user bytes).
//! - Per-frame `frame_boundary` reporting for the multi-frame
//!   producers we already test against the upstream wrapper.
//!
//! # What's deferred
//!
//! `Compressed_Block` returns
//! [`error::ZstdError::CompressedBlockUnimplemented`] (mapped at the
//! trait boundary into [`crate::decode::DecodeError::Read`]) per the
//! plan; Phases 3-5 implement the literals + sequences stack. Custom
//! dictionaries and `windowLog > 27` are rejected at frame-header
//! parse time.
//!
//! # Source consumption accounting
//!
//! Bytes pulled from the source are counted into `bytes_consumed` as
//! soon as they're handed to us by `Read::read`; partial reads
//! (`Ok(n)` with `n < buf.len()`) advance the counter by `n` only.
//! `frame_boundary` is updated atomically with the state transition
//! that ends a frame (last block decoded or content-checksum
//! verified, whichever applies), so the protocol-level guarantee —
//! "decoding from frame_boundary onward produces the suffix of a
//! clean run" — holds.

use std::io::{self, Read, Write};

use crate::decode::{DecodeError, DecodeStatus, StreamingDecoder};
use crate::types::ByteOffset;

pub mod bitstream;
pub mod block;
pub mod error;
pub mod frame;

use self::block::{parse_block_header, BlockType, BLOCK_HEADER_LEN, BLOCK_MAX_SIZE};
use self::error::ZstdError;
use self::frame::{
    classify_magic, frame_header_tail_len, parse_frame_header, parse_skippable_frame_size,
    FrameHeader, FrameMagic, MAX_FRAME_HEADER_LEN,
};

/// Bytes discarded per `decode_step` while traversing a skippable
/// frame. Matches `crate::decode::lz4::SKIP_CHUNK` so the cadence is
/// consistent with the lz4 path.
///
/// We don't define an `OUTPUT_CHUNK` analogue here because RFC 8478
/// already caps a single block at `min(Window_Size, 128 KiB)` —
/// each block's output is structurally bounded smaller than the
/// 1 MiB chunk every other in-tree decoder uses.
const SKIP_CHUNK: usize = 1 << 16;

/// Streaming pure-Rust zstd decoder.
///
/// Owns its source on construction; subsequent
/// [`StreamingDecoder::decode_step`] calls do not need it passed back
/// in. The source is `Send` so the decoder can be moved to a worker
/// thread the same way [`crate::decode::zstd::ZstdDecoder`] can.
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
    /// Latest frame boundary observed, or `None` if no frame has
    /// completed yet. Updated atomically with the
    /// `EndOfFrame` -> `BetweenFrames` transition.
    last_frame_boundary: Option<ByteOffset>,
    /// Reusable scratch for block payloads. Sized to the RFC's
    /// 128 KiB cap on first use; held thereafter to avoid per-block
    /// allocation in the hot loop.
    payload_buf: Vec<u8>,
    /// Reusable scratch for skippable-frame data so we don't
    /// allocate a fresh buffer on every step.
    skip_buf: Vec<u8>,
}

/// Read exactly `buf.len()` bytes from `source`, advancing
/// `bytes_consumed` for every actually-delivered byte.
///
/// `Ok(0)` mid-buffer surfaces as [`ZstdError::UnexpectedEof`]
/// with the supplied label so callers can name the field they
/// were trying to read in error messages.
fn read_exact_into(
    source: &mut (dyn Read + Send),
    bytes_consumed: &mut u64,
    buf: &mut [u8],
    label: &'static str,
) -> Result<(), ZstdError> {
    let mut filled = 0;
    while filled < buf.len() {
        match source.read(&mut buf[filled..]) {
            Ok(0) => return Err(ZstdError::UnexpectedEof(label)),
            Ok(n) => {
                filled += n;
                // INVARIANT: `n <= buf.len() - filled` and
                // `buf.len() <= isize::MAX`, so `as u64` cannot
                // truncate.
                *bytes_consumed = bytes_consumed.saturating_add(n as u64);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ZstdError::SourceIo(e)),
        }
    }
    Ok(())
}

/// Read 4 bytes for a frame magic, treating clean EOF before any
/// byte arrived as `Ok(None)` (the stream is structurally over).
fn read_magic_or_eof(
    source: &mut (dyn Read + Send),
    bytes_consumed: &mut u64,
) -> Result<Option<u32>, ZstdError> {
    let mut buf = [0u8; 4];
    let mut filled = 0;
    while filled < 4 {
        match source.read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(None);
                }
                return Err(ZstdError::UnexpectedEof("frame magic"));
            }
            Ok(n) => {
                filled += n;
                *bytes_consumed = bytes_consumed.saturating_add(n as u64);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ZstdError::SourceIo(e)),
        }
    }
    Ok(Some(u32::from_le_bytes(buf)))
}

/// Decoder state machine.
///
/// The transitions are driven by what the source has delivered so
/// far. A `decode_step` does at most one unit of work — read one
/// block's payload, traverse one chunk of skippable data, or
/// transition between frames — before returning so the extractor
/// can interleave punching and checkpointing.
#[derive(Debug)]
enum State {
    /// Need to read the next 4-byte magic. EOF at this state is a
    /// clean stream end; EOF mid-magic is a truncation error.
    AwaitingMagic,
    /// Skippable frame in progress; `remaining` bytes of opaque
    /// user data still to discard.
    SkippingUserData {
        /// Bytes left to consume from the skippable frame's payload.
        remaining: u64,
    },
    /// Inside a regular frame, between blocks. Carries the parsed
    /// frame header so we can verify checksum and Frame_Content_Size
    /// at end-of-frame.
    InFrame {
        /// Parsed frame header.
        header: FrameHeader,
        /// Decompressed bytes emitted so far in this frame, used
        /// to cross-check `Frame_Content_Size` at end-of-frame.
        decoded_in_frame: u64,
    },
    /// Just decoded the final block of a frame; if the frame
    /// declared a content checksum, we still owe a 4-byte trailer
    /// read before the frame truly ends.
    AwaitingContentChecksum {
        /// Decompressed bytes produced for this frame (carried for
        /// future XXH64 verification — Phase 6 wires it up; Phase 1
        /// consumes the bytes but does not yet validate them).
        decoded_in_frame: u64,
    },
    /// Stream ended cleanly. Subsequent steps are no-ops.
    Done,
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
            state: State::AwaitingMagic,
            bytes_consumed: 0,
            last_frame_boundary: None,
            payload_buf: Vec::new(),
            skip_buf: Vec::new(),
        })
    }

    // Free helpers below take `&mut Box<dyn Read + Send>` and a
    // `&mut u64` consumed-counter rather than `&mut self`. That
    // shape lets the caller hold a mutable borrow on a per-decoder
    // scratch buffer (`payload_buf`, `skip_buf`) while still
    // calling into the helper, which the borrow checker would
    // otherwise reject.

    /// Decode-step's "we just finished the frame" hook: stamp
    /// `last_frame_boundary` at the current high-water mark and
    /// return to `AwaitingMagic` for the next frame (or stream EOF).
    fn finish_frame(&mut self) {
        self.last_frame_boundary = Some(ByteOffset::new(self.bytes_consumed));
        self.state = State::AwaitingMagic;
    }

    /// Internal: the body of one `decode_step`, returning the
    /// internal error type. The trait-level `decode_step` wraps
    /// this with the [`ZstdError::into_decode_error`] boundary.
    fn step_inner(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, ZstdError> {
        loop {
            match &self.state {
                State::Done => return Ok(DecodeStatus::Eof),

                State::AwaitingMagic => {
                    let Some(source) = self.source.as_mut() else {
                        self.state = State::Done;
                        return Ok(DecodeStatus::Eof);
                    };
                    let magic = read_magic_or_eof(source.as_mut(), &mut self.bytes_consumed)?;
                    match magic {
                        None => {
                            // Clean stream EOF.
                            self.source = None;
                            self.state = State::Done;
                            return Ok(DecodeStatus::Eof);
                        }
                        Some(magic) => match classify_magic(magic) {
                            Some(FrameMagic::Regular) => {
                                // Read the rest of the header. First the
                                // FHD byte to learn the tail length.
                                let mut fhd = [0u8; 1];
                                read_exact_into(
                                    source.as_mut(),
                                    &mut self.bytes_consumed,
                                    &mut fhd,
                                    "Frame_Header_Descriptor",
                                )?;
                                let tail = frame_header_tail_len(fhd[0]);
                                let mut full = [0u8; MAX_FRAME_HEADER_LEN];
                                full[0..4].copy_from_slice(&magic.to_le_bytes());
                                full[4] = fhd[0];
                                read_exact_into(
                                    source.as_mut(),
                                    &mut self.bytes_consumed,
                                    &mut full[5..5 + tail],
                                    "frame header tail",
                                )?;
                                let header = parse_frame_header(&full[..5 + tail])?;
                                self.state = State::InFrame {
                                    header,
                                    decoded_in_frame: 0,
                                };
                                // Loop again so the caller observes
                                // actual decode progress on this step.
                            }
                            Some(FrameMagic::Skippable { .. }) => {
                                let mut size_bytes = [0u8; 4];
                                read_exact_into(
                                    source.as_mut(),
                                    &mut self.bytes_consumed,
                                    &mut size_bytes,
                                    "skippable frame length",
                                )?;
                                let user_size = u32::from_le_bytes(size_bytes) as u64;
                                // `parse_skippable_frame_size` is the
                                // pure-bytes equivalent for callers
                                // who already buffered the magic;
                                // here we read the size separately
                                // because we already consumed the
                                // magic bytes via read_magic_or_eof.
                                let _ = parse_skippable_frame_size;
                                self.state = State::SkippingUserData {
                                    remaining: user_size,
                                };
                                // Loop again to consume some bytes
                                // (or immediately finish if zero).
                            }
                            None => {
                                return Err(ZstdError::BadMagic { magic });
                            }
                        },
                    }
                }

                State::SkippingUserData { remaining } => {
                    if *remaining == 0 {
                        // Skippable frame done — its end is a frame
                        // boundary just like a regular frame's end.
                        self.finish_frame();
                        return Ok(DecodeStatus::MoreData);
                    }
                    let remaining_now = *remaining;
                    let Some(source) = self.source.as_mut() else {
                        return Err(ZstdError::UnexpectedEof("skippable user data"));
                    };
                    let chunk = remaining_now.min(SKIP_CHUNK as u64) as usize;
                    if self.skip_buf.len() < chunk {
                        self.skip_buf.resize(chunk, 0);
                    }
                    read_exact_into(
                        source.as_mut(),
                        &mut self.bytes_consumed,
                        &mut self.skip_buf[..chunk],
                        "skippable user data",
                    )?;
                    if let State::SkippingUserData { remaining } = &mut self.state {
                        *remaining = remaining.saturating_sub(chunk as u64);
                    }
                    return Ok(DecodeStatus::MoreData);
                }

                State::InFrame {
                    header,
                    decoded_in_frame,
                } => {
                    let frame_header = *header;
                    let mut decoded = *decoded_in_frame;
                    let Some(source) = self.source.as_mut() else {
                        return Err(ZstdError::UnexpectedEof("block header"));
                    };
                    let mut bh_bytes = [0u8; BLOCK_HEADER_LEN];
                    read_exact_into(
                        source.as_mut(),
                        &mut self.bytes_consumed,
                        &mut bh_bytes,
                        "block header",
                    )?;
                    let bh = parse_block_header(&bh_bytes)?;

                    // Tighten Block_Maximum_Size against the frame's
                    // Window_Size (RFC 8478 §3.1.1.2 calls out
                    // "smallest of Window_Size and 128 KB"). We rely
                    // on the Phase-1 invariant that windowLog ≤ 27
                    // (enforced at frame-header parse time).
                    let block_cap =
                        u32::try_from(frame_header.window_size.min(u64::from(BLOCK_MAX_SIZE)))
                            .unwrap_or(BLOCK_MAX_SIZE);
                    if bh.block_size > block_cap {
                        return Err(ZstdError::BlockTooLarge {
                            size: bh.block_size,
                            cap: block_cap,
                        });
                    }

                    match bh.block_type {
                        BlockType::Raw => {
                            let n = bh.block_size as usize;
                            if self.payload_buf.len() < n {
                                self.payload_buf.resize(n, 0);
                            }
                            let source = self.source.as_mut().expect("source present");
                            read_exact_into(
                                source.as_mut(),
                                &mut self.bytes_consumed,
                                &mut self.payload_buf[..n],
                                "raw block payload",
                            )?;
                            sink.write_all(&self.payload_buf[..n])
                                .map_err(ZstdError::SourceIo)?;
                            decoded = decoded.saturating_add(n as u64);
                        }
                        BlockType::Rle => {
                            let mut byte_buf = [0u8; 1];
                            let source = self.source.as_mut().expect("source present");
                            read_exact_into(
                                source.as_mut(),
                                &mut self.bytes_consumed,
                                &mut byte_buf,
                                "RLE block payload",
                            )?;
                            let n = bh.block_size as usize;
                            if self.payload_buf.len() < n {
                                self.payload_buf.resize(n, 0);
                            }
                            for slot in &mut self.payload_buf[..n] {
                                *slot = byte_buf[0];
                            }
                            sink.write_all(&self.payload_buf[..n])
                                .map_err(ZstdError::SourceIo)?;
                            decoded = decoded.saturating_add(n as u64);
                        }
                        BlockType::Compressed => {
                            return Err(ZstdError::CompressedBlockUnimplemented);
                        }
                    }

                    if bh.last_block {
                        if frame_header.has_checksum {
                            self.state = State::AwaitingContentChecksum {
                                decoded_in_frame: decoded,
                            };
                        } else {
                            if let Some(fcs) = frame_header.fcs {
                                if fcs != decoded {
                                    return Err(ZstdError::MalformedFrameHeader(
                                        "Frame_Content_Size mismatch (no checksum frame)",
                                    ));
                                }
                            }
                            self.finish_frame();
                        }
                    } else {
                        self.state = State::InFrame {
                            header: frame_header,
                            decoded_in_frame: decoded,
                        };
                    }
                    return Ok(DecodeStatus::MoreData);
                }

                State::AwaitingContentChecksum { decoded_in_frame } => {
                    let decoded = *decoded_in_frame;
                    let Some(source) = self.source.as_mut() else {
                        return Err(ZstdError::UnexpectedEof("frame content checksum"));
                    };
                    let mut buf = [0u8; 4];
                    read_exact_into(
                        source.as_mut(),
                        &mut self.bytes_consumed,
                        &mut buf,
                        "frame content checksum",
                    )?;
                    // Phase 1 reads but does not verify — Phase 6
                    // wires up XXH64. We still advance the frame
                    // boundary so checkpoints stay aligned. The
                    // declared FCS cross-check also moves to Phase 6
                    // (it lives next to the XXH64 verification).
                    let _checksum_low32 = u32::from_le_bytes(buf);
                    let _ = decoded;
                    self.finish_frame();
                    return Ok(DecodeStatus::MoreData);
                }
            }
        }
    }
}

impl StreamingDecoder for Decoder {
    fn decode_step(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, DecodeError> {
        if let State::Done = self.state {
            return Ok(DecodeStatus::Eof);
        }
        match self.step_inner(sink) {
            Ok(status) => Ok(status),
            Err(e) => {
                let consumed = self.bytes_consumed;
                // Errors are terminal — drop the source so further
                // calls cleanly short-circuit and OS resources are
                // released as soon as possible.
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
/// wrapper. Phase 8 swaps the registration.
///
/// # Errors
///
/// Forwards any error returned by [`Decoder::new`].
pub fn factory(src: Box<dyn Read + Send>) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    Ok(Box::new(Decoder::new(src)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    /// Helper: assemble a single-segment, no-checksum frame from a
    /// list of (last_block, block_type, block_size, payload-on-wire)
    /// tuples. The Phase 0 spike (`docs/PLAN_zstd_block_decoder.md`
    /// Appendix A) used the same shape.
    fn build_frame(content_size: u64, has_checksum: bool, blocks: &[Block]) -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&frame::ZSTD_FRAME_MAGIC.to_le_bytes());
        let cc_bit = u8::from(has_checksum);
        // FHD: fcs_flag=3, single_segment=1, cc_flag, dict_id=0.
        frame.push(0b1110_0000 | (cc_bit << 2));
        frame.extend_from_slice(&content_size.to_le_bytes());
        for b in blocks {
            let h = u32::from(b.last) | (b.ty << 1) | (b.size << 3);
            frame.push(h as u8);
            frame.push((h >> 8) as u8);
            frame.push((h >> 16) as u8);
            frame.extend_from_slice(b.payload);
        }
        if has_checksum {
            frame.extend_from_slice(&[0, 0, 0, 0]);
        }
        frame
    }

    struct Block<'a> {
        last: bool,
        ty: u32,
        size: u32,
        payload: &'a [u8],
    }

    fn raw(last: bool, payload: &[u8]) -> Block<'_> {
        Block {
            last,
            ty: 0,
            size: payload.len() as u32,
            payload,
        }
    }

    fn rle<'a>(last: bool, byte: &'a [u8; 1], regen: u32) -> Block<'a> {
        Block {
            last,
            ty: 1,
            size: regen,
            payload: byte,
        }
    }

    fn compressed(last: bool, payload: &[u8]) -> Block<'_> {
        Block {
            last,
            ty: 2,
            size: payload.len() as u32,
            payload,
        }
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

    /// Single Raw_Block frame round-trips and reports a frame
    /// boundary at end-of-stream.
    #[test]
    fn single_raw_block_frame() {
        let payload = b"hello, raw zstd";
        let frame = build_frame(payload.len() as u64, false, &[raw(true, payload)]);
        let total_len = frame.len();
        let (out, dec) = decode_all(frame);
        assert_eq!(out, payload);
        assert_eq!(dec.bytes_consumed().get(), total_len as u64);
        assert_eq!(
            dec.frame_boundary(),
            Some(ByteOffset::new(total_len as u64))
        );
    }

    /// Single RLE_Block frame regenerates the byte the right
    /// number of times.
    #[test]
    fn single_rle_block_frame() {
        let frame = build_frame(1024, false, &[rle(true, b"X", 1024)]);
        let (out, _dec) = decode_all(frame);
        assert_eq!(out.len(), 1024);
        assert!(out.iter().all(|&b| b == b'X'));
    }

    /// Multi-block frame: Raw + RLE + Raw with last_block on the
    /// final block. Mirrors the Phase 0 hand-crafted Vector A.
    #[test]
    fn multi_block_frame_concatenates_in_order() {
        let frame = build_frame(
            16,
            false,
            &[
                raw(false, b"abcd"),
                rle(false, b"X", 4),
                raw(true, b"WXYZ1234"),
            ],
        );
        let (out, _dec) = decode_all(frame);
        assert_eq!(out, b"abcdXXXXWXYZ1234");
    }

    /// Multi-frame stream: two single-segment frames concatenated.
    /// The boundary observed between them lands exactly at the
    /// end of the first compressed frame.
    #[test]
    fn multi_frame_records_intermediate_boundary() {
        let f1 = build_frame(5, false, &[raw(true, b"alpha")]);
        let f2 = build_frame(4, false, &[raw(true, b"beta")]);
        let f1_len = f1.len();
        let total = f1_len + f2.len();
        let mut combined = f1;
        combined.extend_from_slice(&f2);

        let mut decoder = Decoder::new(Box::new(Cursor::new(combined))).expect("construct");
        let mut sink = Vec::new();
        let mut boundaries: Vec<u64> = Vec::new();
        loop {
            let prior = decoder.frame_boundary();
            let status = decoder.decode_step(&mut sink).expect("step");
            let now = decoder.frame_boundary();
            if now != prior {
                boundaries.push(now.expect("just observed").get());
            }
            if status == DecodeStatus::Eof {
                break;
            }
        }
        assert_eq!(sink, b"alphabeta");
        assert_eq!(boundaries, vec![f1_len as u64, total as u64]);
    }

    /// Skippable frames are consumed transparently and produce a
    /// frame boundary at their end.
    #[test]
    fn skippable_frame_is_skipped() {
        let mut stream = Vec::new();
        // Skippable frame, magic 0x184D2A50, 16 bytes of garbage.
        stream.extend_from_slice(&frame::SKIPPABLE_MAGIC_BASE.to_le_bytes());
        stream.extend_from_slice(&16u32.to_le_bytes());
        stream.extend_from_slice(&[0xAB; 16]);
        // Then a real Raw_Block frame.
        stream.extend_from_slice(&build_frame(3, false, &[raw(true, b"end")]));
        let (out, _dec) = decode_all(stream);
        assert_eq!(out, b"end");
    }

    /// Skippable frame at end-of-stream still ends cleanly.
    #[test]
    fn trailing_skippable_frame_ends_cleanly() {
        let mut stream = build_frame(3, false, &[raw(true, b"foo")]);
        stream.extend_from_slice(&frame::SKIPPABLE_MAGIC_BASE.to_le_bytes());
        stream.extend_from_slice(&8u32.to_le_bytes());
        stream.extend_from_slice(&[0u8; 8]);
        let (out, _dec) = decode_all(stream);
        assert_eq!(out, b"foo");
    }

    /// `Compressed_Block` is the deliberate Phase-1 hole — it must
    /// surface a clean error rather than panicking or silently
    /// producing garbage.
    #[test]
    fn compressed_block_returns_unimplemented_error() {
        // We don't need a *real* compressed payload; the parser
        // dispatches on the block type tag before touching the
        // payload bytes. (The `payload_on_wire` pull happens after
        // the type-dispatch error is returned.)
        let frame = build_frame(0, false, &[compressed(true, &[])]);
        let mut decoder = Decoder::new(Box::new(Cursor::new(frame))).expect("construct");
        let mut sink = Vec::new();
        loop {
            match decoder.decode_step(&mut sink) {
                Ok(DecodeStatus::Eof) => panic!("expected error"),
                Ok(DecodeStatus::MoreData) => continue,
                Err(DecodeError::Read { source, .. }) => {
                    let msg = source.to_string();
                    assert!(
                        msg.contains("compressed block decoding not yet implemented"),
                        "unexpected msg: {msg}"
                    );
                    break;
                }
                Err(other) => panic!("unexpected error variant: {other:?}"),
            }
        }
    }

    /// Bytes-consumed never exceeds the source length, including
    /// across frame boundaries.
    #[test]
    fn bytes_consumed_never_exceeds_source_length() {
        let frame = build_frame(
            16,
            false,
            &[
                raw(false, b"abcd"),
                rle(false, b"X", 4),
                raw(true, b"WXYZ1234"),
            ],
        );
        let len = frame.len() as u64;
        let mut decoder = Decoder::new(Box::new(Cursor::new(frame))).expect("construct");
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

    /// `bytes_consumed` is monotonically non-decreasing.
    #[test]
    fn bytes_consumed_is_monotone() {
        let frame = build_frame(
            16,
            false,
            &[
                raw(false, b"abcd"),
                rle(false, b"X", 4),
                raw(true, b"WXYZ1234"),
            ],
        );
        let mut decoder = Decoder::new(Box::new(Cursor::new(frame))).expect("construct");
        let mut sink = Vec::new();
        let mut last = 0u64;
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

    /// After EOF, repeated calls keep returning `Eof` without
    /// touching the (now-dropped) source.
    #[test]
    fn repeated_calls_after_eof_stay_eof() {
        let frame = build_frame(3, false, &[raw(true, b"foo")]);
        let mut decoder = Decoder::new(Box::new(Cursor::new(frame))).expect("construct");
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

    /// Empty source: very first step returns Eof without error.
    #[test]
    fn empty_source_reports_eof_immediately() {
        let mut decoder = Decoder::new(Box::new(Cursor::new(Vec::<u8>::new()))).expect("construct");
        let mut sink = Vec::new();
        assert_eq!(
            decoder.decode_step(&mut sink).expect("step"),
            DecodeStatus::Eof
        );
        assert!(sink.is_empty());
        assert_eq!(decoder.bytes_consumed().get(), 0);
        assert_eq!(decoder.frame_boundary(), None);
    }

    /// Truncated frame (magic only, no header) surfaces as a clean
    /// error rather than a panic.
    #[test]
    fn truncated_after_magic_reports_unexpected_eof() {
        let buf = frame::ZSTD_FRAME_MAGIC.to_le_bytes().to_vec();
        let mut decoder = Decoder::new(Box::new(Cursor::new(buf))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { source, .. }) => {
                assert!(
                    source.to_string().contains("unexpected EOF"),
                    "msg: {source}"
                );
            }
            other => panic!("expected Read error, got {other:?}"),
        }
    }

    /// Garbage prefix surfaces as bad-magic, not panic.
    #[test]
    fn garbage_prefix_reports_bad_magic() {
        let buf = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34];
        let mut decoder = Decoder::new(Box::new(Cursor::new(buf))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { source, .. }) => {
                let msg = source.to_string();
                assert!(msg.contains("bad frame magic"), "msg: {msg}");
            }
            other => panic!("expected Read error, got {other:?}"),
        }
    }

    /// Failing sink propagates as a Read error (Phase 1 maps sink
    /// failures through the source-IO path; the boundary maps it
    /// to `DecodeError::Read`). Phase 6 may move this to
    /// `DecodeError::Write` when the sink path is plumbed
    /// separately, but the contract for callers is stable: they
    /// see *some* terminal `Err`.
    #[test]
    fn sink_failure_propagates_as_error() {
        struct FailingSink;
        impl Write for FailingSink {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "no"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let frame = build_frame(8, false, &[raw(true, b"failsink")]);
        let mut decoder = Decoder::new(Box::new(Cursor::new(frame))).expect("construct");
        match decoder.decode_step(&mut FailingSink) {
            Err(DecodeError::Read { .. }) => {}
            other => panic!("expected Read (sink-mapped), got {other:?}"),
        }
    }

    /// The factory plumbing constructs a working decoder.
    #[test]
    fn factory_constructs_and_decodes() {
        let frame = build_frame(5, false, &[raw(true, b"hello")]);
        let mut decoder = factory(Box::new(Cursor::new(frame))).expect("factory");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("step") == DecodeStatus::MoreData {}
        assert_eq!(sink, b"hello");
    }
}
