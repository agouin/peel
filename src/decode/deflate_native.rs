//! Hand-rolled, pure-Rust DEFLATE streaming decoder.
//!
//! Phases 1–2 of `docs/PLAN_deflate_block_decoder.md` — currently
//! shipped behind the cargo feature flag `peel_deflate_native`. The
//! existing [`crate::decode::gzip`] wrapper around `flate2` remains
//! the production gzip path; this module is built up phase-by-phase
//! and Phase 8 swaps it in as the production gzip / zip-DEFLATE
//! backend.
//!
//! # What's working in Phase 1
//!
//! - The byte-oriented [`Decoder`] state machine
//!   (`Initial → AwaitingStoredHeader → InStoredBlock → Done`)
//!   covering RFC 1951 §3.2.4 stored blocks end-to-end.
//! - Multi-block stored streams: a non-final stored block transitions
//!   back to `AwaitingBlockType` after its payload is consumed; the
//!   loop terminates only when a stored block's `BFINAL` bit was
//!   set.
//! - Clean placeholder errors for fixed-Huffman (`BTYPE=01`) and
//!   dynamic-Huffman (`BTYPE=10`) blocks; reserved (`BTYPE=11`)
//!   surfaces as a structural error. Phase 3 fills in fixed,
//!   Phase 4 fills in dynamic.
//! - Byte-aligned source-cursor accounting:
//!   [`StreamingDecoder::bytes_consumed`] reports exactly the bytes
//!   the decoder has pulled off the source, never speculatively.
//!
//! # What Phase 2 added
//!
//! - [`bitstream::BitReader`]: streaming forward bit reader over a
//!   `Box<dyn Read + Send>` source. RFC 1951 §3.1.1 bit ordering
//!   (LSB-first byte order, LSB-first bit ordering within each
//!   byte). Provides `peek_bits` / `consume_bits` / `read_bits` /
//!   `align_to_byte` / `byte_position`. Pure logic on top of a
//!   small (4 KiB) pull-buffer; cursor accounting honours the
//!   floor convention from `docs/PLAN_deflate_block_decoder.md`
//!   §Risks 2 (the byte the bit cursor is fractionally inside is
//!   *not* freeable). Not yet wired into the [`Decoder`] state
//!   machine — Phase 5 swaps the byte-oriented `read_exact_into`
//!   helper out for the bit reader once Phases 3 and 4 land
//!   fixed and dynamic Huffman bodies that need it.
//!
//! # What Phase 1 / 2 do *not* do
//!
//! - Fixed Huffman block bodies (Phase 3) — the bit reader is
//!   ready; the canonical-Huffman table builder and the literal /
//!   length / distance dispatch land in Phase 3.
//! - Dynamic Huffman blocks with the HLIT / HDIST / HCLEN preamble
//!   (Phase 4).
//! - LZ77 sliding window (Phase 5).
//! - gzip framing — this decoder takes raw deflate input, the same
//!   shape `flate2::read::DeflateDecoder` consumes. The RFC 1952
//!   header / trailer / multi-member chaining wrapper lands in
//!   Phase 6.
//! - Resume / `decoder_state()` blob support (Phase 7).
//! - Registration into [`crate::decode::DecoderRegistry`] (Phase 8).
//!
//! [RFC 1951]: https://www.rfc-editor.org/rfc/rfc1951
//!
//! # Source consumption accounting
//!
//! Bytes pulled from the source are counted into `bytes_consumed` as
//! soon as `Read::read` delivers them; partial reads (`Ok(n)` with
//! `n < buf.len()`) advance the counter by `n` only. Stored blocks
//! are byte-aligned by RFC 1951 §3.2.4 — no fractional-byte cursor
//! exists today; Phase 7's resume-blob layout will introduce a
//! `bit_offset_in_first_byte` field once Phases 3/4 land bit-aligned
//! Huffman blocks.

use std::io::{self, Read, Write};

use crate::decode::{DecodeError, DecodeStatus, StreamingDecoder};
use crate::types::ByteOffset;

pub mod bitstream;
pub mod block;
pub mod error;

use self::block::{
    parse_block_type_byte, parse_stored_lengths, BlockHeader, BlockType, STORED_HEADER_LEN,
};
use self::error::DeflateError;

/// Output buffer size used per [`StreamingDecoder::decode_step`] for
/// stored-block payload streaming. Matches the existing in-tree
/// decoders (`crate::decode::xz`, `crate::decode::lz4`) so the
/// extractor's punch / checkpoint cadence behaves the same way
/// regardless of which decoder is in front of it.
const OUTPUT_CHUNK: usize = 1 << 20;

/// Streaming pure-Rust DEFLATE decoder.
///
/// Owns its source on construction; subsequent
/// [`StreamingDecoder::decode_step`] calls do not need it passed back
/// in. The source is `Send` so the decoder can be moved to a worker
/// thread the same way the other in-tree decoders can.
///
/// Phase 1 ships stored-block support only; fixed and dynamic
/// Huffman blocks return [`DeflateError::FixedHuffmanUnimplemented`]
/// / [`DeflateError::DynamicHuffmanUnimplemented`] respectively, both
/// translated through [`DeflateError::into_decode_error`] at the
/// trait boundary.
pub struct Decoder {
    /// Wrapped source, dropped on terminal error or clean EOF so
    /// further `decode_step` calls cheaply short-circuit and OS
    /// resources are released as soon as possible.
    source: Option<Box<dyn Read + Send>>,
    /// State machine; see [`State`].
    state: State,
    /// High-water source-byte counter — what
    /// [`StreamingDecoder::bytes_consumed`] returns. Advanced only
    /// after a successful read; partial reads advance only by what
    /// was actually delivered.
    bytes_consumed: u64,
    /// Pre-allocated scratch space for stored-block payload streaming.
    /// Reused across steps to avoid per-call allocation.
    output_buf: Vec<u8>,
}

/// Decoder state machine.
///
/// Transitions are driven by what the source has delivered so far. A
/// `decode_step` does at most one unit of work — read the next block
/// header, read the stored-block length pair, or stream up to
/// [`OUTPUT_CHUNK`] bytes of a stored-block payload — before
/// returning so the extractor can interleave punching and
/// checkpointing.
#[derive(Debug)]
enum State {
    /// Need to read the next block-type byte (`BFINAL` + `BTYPE` in
    /// the low 3 bits, with the high 5 bits discarded for stored
    /// blocks per RFC 1951 §3.2.4). Clean source EOF *before* this
    /// state's read is a structural error: a deflate stream must end
    /// with a `BFINAL=1` block.
    AwaitingBlockType,
    /// Just consumed the BTYPE byte for a stored block. Need to read
    /// the 4-byte `(LEN_lo, LEN_hi, NLEN_lo, NLEN_hi)` header.
    AwaitingStoredHeader {
        /// Whether the just-parsed block header had `BFINAL=1`.
        last: bool,
    },
    /// Inside a stored block, streaming the verbatim payload to the
    /// sink. Each step copies up to [`OUTPUT_CHUNK`] bytes.
    InStoredBlock {
        /// Bytes of payload still to copy.
        remaining: u32,
        /// Whether this is the last block in the deflate stream.
        last: bool,
    },
    /// Stream ended cleanly. Subsequent steps are no-ops.
    Done,
}

/// Read exactly `buf.len()` bytes from `source`, advancing
/// `bytes_consumed` for every actually-delivered byte.
///
/// `Ok(0)` mid-buffer surfaces as [`DeflateError::UnexpectedEof`]
/// with the supplied label so callers can name the field they were
/// trying to read in error messages. Mirrors the helper at
/// [`crate::decode::zstd::read_exact_into`].
fn read_exact_into(
    source: &mut (dyn Read + Send),
    bytes_consumed: &mut u64,
    buf: &mut [u8],
    label: &'static str,
) -> Result<(), DeflateError> {
    let mut filled = 0;
    while filled < buf.len() {
        match source.read(&mut buf[filled..]) {
            Ok(0) => return Err(DeflateError::UnexpectedEof(label)),
            Ok(n) => {
                filled += n;
                // INVARIANT: `n <= buf.len() - filled` and
                // `buf.len() <= isize::MAX`, so `as u64` cannot
                // truncate.
                *bytes_consumed = bytes_consumed.saturating_add(n as u64);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(DeflateError::SourceIo(e)),
        }
    }
    Ok(())
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
            state: State::AwaitingBlockType,
            bytes_consumed: 0,
            output_buf: vec![0u8; OUTPUT_CHUNK],
        })
    }

    /// Internal: the body of one `decode_step`, returning the
    /// internal error type. The trait-level `decode_step` wraps this
    /// with the [`DeflateError::into_decode_error`] boundary.
    fn step_inner(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, DeflateError> {
        loop {
            match self.state {
                State::Done => return Ok(DecodeStatus::Eof),

                State::AwaitingBlockType => {
                    let Some(source) = self.source.as_mut() else {
                        // Source already dropped (terminal earlier
                        // call); short-circuit cleanly.
                        self.state = State::Done;
                        return Ok(DecodeStatus::Eof);
                    };
                    let mut byte = [0u8; 1];
                    read_exact_into(
                        source.as_mut(),
                        &mut self.bytes_consumed,
                        &mut byte,
                        "block-type byte",
                    )?;
                    let BlockHeader { last, ty } = parse_block_type_byte(byte[0])?;
                    self.state = match ty {
                        BlockType::Stored => State::AwaitingStoredHeader { last },
                        BlockType::FixedHuffman => {
                            return Err(DeflateError::FixedHuffmanUnimplemented)
                        }
                        BlockType::DynamicHuffman => {
                            return Err(DeflateError::DynamicHuffmanUnimplemented)
                        }
                    };
                    // Loop again so the caller observes actual decode
                    // progress on this step rather than getting one
                    // step per state transition.
                }

                State::AwaitingStoredHeader { last } => {
                    let Some(source) = self.source.as_mut() else {
                        self.state = State::Done;
                        return Ok(DecodeStatus::Eof);
                    };
                    let mut buf = [0u8; STORED_HEADER_LEN];
                    read_exact_into(
                        source.as_mut(),
                        &mut self.bytes_consumed,
                        &mut buf,
                        "stored-block LEN/NLEN",
                    )?;
                    let len = parse_stored_lengths(buf)?;
                    self.state = State::InStoredBlock {
                        remaining: u32::from(len),
                        last,
                    };
                    // Loop again so this step also makes payload
                    // progress (avoids a no-output step that would
                    // confuse the extractor's quiescence accounting).
                }

                State::InStoredBlock { remaining, last } => {
                    if remaining == 0 {
                        if last {
                            // Final block fully consumed. Drop the
                            // source so future calls cheaply
                            // short-circuit.
                            self.source = None;
                            self.state = State::Done;
                            return Ok(DecodeStatus::Eof);
                        } else {
                            self.state = State::AwaitingBlockType;
                            // Don't loop — return so the caller
                            // observes one step of progress per
                            // block boundary.
                            return Ok(DecodeStatus::MoreData);
                        }
                    }

                    let Some(source) = self.source.as_mut() else {
                        // Lost the source mid-payload — propagate as
                        // EOF rather than silently truncating.
                        self.state = State::Done;
                        return Err(DeflateError::UnexpectedEof("stored-block payload"));
                    };

                    // Bound the read so a single step never copies
                    // more than `OUTPUT_CHUNK` bytes.
                    let want = (remaining as usize).min(self.output_buf.len());
                    let buf = &mut self.output_buf[..want];
                    let n = match source.read(buf) {
                        Ok(0) => {
                            // Source EOF mid-payload is a truncation
                            // error, not a clean stream end.
                            return Err(DeflateError::UnexpectedEof("stored-block payload"));
                        }
                        Ok(n) => n,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(DeflateError::SourceIo(e)),
                    };
                    // INVARIANT: `n <= want <= OUTPUT_CHUNK <=
                    // isize::MAX`, so `as u64`/`as u32` cannot
                    // truncate.
                    self.bytes_consumed = self.bytes_consumed.saturating_add(n as u64);
                    sink.write_all(&self.output_buf[..n])
                        .map_err(DeflateError::SinkIo)?;
                    self.state = State::InStoredBlock {
                        remaining: remaining.saturating_sub(n as u32),
                        last,
                    };
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
        // Phase 1 doesn't surface mid-stream restart points yet —
        // Phase 7 lands the per-block boundary + decoder_state blob.
        // The byte-aligned stored-block payload boundary *is* a
        // valid restart point in principle (the gzip wrapper today
        // surfaces per-member boundaries that satisfy the same
        // contract), but exposing it before the per-block
        // checkpoint cadence wiring is in place would invite the
        // coordinator to act on a boundary the rest of the pipeline
        // can't yet take advantage of.
        None
    }
}

/// [`crate::decode::DecoderFactory`] adapter for [`Decoder`].
///
/// Not registered by [`crate::decode::DecoderRegistry::with_defaults`]
/// in Phase 1 — the production gzip path still goes through
/// [`crate::decode::gzip::factory`] / `flate2`. Phase 8 swaps the
/// registration once the decoder is feature-complete.
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

    /// Build a single-block stored deflate stream containing
    /// `payload` verbatim. The output is RFC 1951 §3.2.4 conformant
    /// raw deflate (no gzip / zlib framing).
    fn build_stored_stream(payload: &[u8], last: bool) -> Vec<u8> {
        assert!(
            payload.len() <= u16::MAX as usize,
            "stored-block LEN is u16"
        );
        let mut out = Vec::with_capacity(payload.len() + 5);
        // BTYPE byte: bit 0 = BFINAL, bits 2:1 = 00 (stored), bits
        // 3..=7 = 0 (alignment padding).
        let btype_byte: u8 = if last { 0b0000_0001 } else { 0b0000_0000 };
        out.push(btype_byte);
        let len = payload.len() as u16;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&(!len).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Drive the decoder to EOF and collect its output.
    fn decode_all(stream: Vec<u8>) -> Vec<u8> {
        let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode step") == DecodeStatus::MoreData {}
        sink
    }

    #[test]
    fn single_stored_block_round_trips() {
        let payload = b"hello, deflate stored world".to_vec();
        let stream = build_stored_stream(&payload, true);
        let stream_len = stream.len();
        let decoder_len = stream_len as u64;

        let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode step") == DecodeStatus::MoreData {}

        assert_eq!(sink, payload);
        assert_eq!(decoder.bytes_consumed().get(), decoder_len);
    }

    #[test]
    fn empty_stored_block_round_trips() {
        // Edge case: BFINAL=1, BTYPE=00, LEN=0, NLEN=0xFFFF, no
        // payload. Decoder must surface clean Eof without writing
        // anything to the sink.
        let stream = build_stored_stream(&[], true);
        let out = decode_all(stream);
        assert!(out.is_empty());
    }

    #[test]
    fn multiple_stored_blocks_concatenate_in_order() {
        // Three back-to-back stored blocks, only the last with
        // BFINAL=1.
        let mut stream = Vec::new();
        stream.extend_from_slice(&build_stored_stream(b"alpha-", false));
        stream.extend_from_slice(&build_stored_stream(b"beta-", false));
        stream.extend_from_slice(&build_stored_stream(b"gamma!", true));

        let out = decode_all(stream);
        assert_eq!(out, b"alpha-beta-gamma!");
    }

    #[test]
    fn payload_larger_than_one_step_round_trips() {
        // Exceed OUTPUT_CHUNK to force a multi-step payload copy.
        let payload: Vec<u8> = (0..(OUTPUT_CHUNK + 12345))
            .map(|i| (i % 251) as u8)
            // OUTPUT_CHUNK + 12345 ≤ STORED_MAX_LEN won't hold:
            // OUTPUT_CHUNK = 1 MiB > 65 535 max. Truncate to fit a
            // single stored block.
            .take(u16::MAX as usize)
            .collect();
        let stream = build_stored_stream(&payload, true);
        let out = decode_all(stream);
        assert_eq!(out, payload);
    }

    #[test]
    fn bytes_consumed_is_monotone_across_steps() {
        // A multi-block stream where every step's `bytes_consumed`
        // value never regresses.
        let mut stream = Vec::new();
        for _ in 0..4 {
            stream.extend_from_slice(&build_stored_stream(&[0xABu8; 1024], false));
        }
        stream.extend_from_slice(&build_stored_stream(&[0xCDu8; 1024], true));
        let stream_len = stream.len();

        let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
        let mut sink = Vec::new();
        let mut last = 0u64;
        loop {
            let status = decoder.decode_step(&mut sink).expect("decode step");
            let now = decoder.bytes_consumed().get();
            assert!(now >= last, "bytes_consumed regressed from {last} to {now}");
            assert!(now <= stream_len as u64, "bytes_consumed exceeded source");
            last = now;
            if status == DecodeStatus::Eof {
                break;
            }
        }
        assert_eq!(last, stream_len as u64);
    }

    #[test]
    fn repeated_calls_after_eof_stay_eof() {
        let stream = build_stored_stream(b"steady-state", true);
        let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode") == DecodeStatus::MoreData {}
        for _ in 0..5 {
            assert_eq!(
                decoder.decode_step(&mut sink).expect("idempotent eof"),
                DecodeStatus::Eof
            );
        }
        assert_eq!(sink, b"steady-state");
    }

    #[test]
    fn fixed_huffman_block_surfaces_phase3_placeholder() {
        // BFINAL=1, BTYPE=01 → 0b011 = 0x03.
        let stream = vec![0x03u8];
        let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { source, .. }) => {
                assert!(
                    source.to_string().contains("BTYPE=01"),
                    "expected BTYPE=01 placeholder message, got: {source}"
                );
            }
            other => panic!("expected Read error, got {other:?}"),
        }
    }

    #[test]
    fn dynamic_huffman_block_surfaces_phase4_placeholder() {
        // BFINAL=1, BTYPE=10 → 0b101 = 0x05.
        let stream = vec![0x05u8];
        let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { source, .. }) => {
                assert!(
                    source.to_string().contains("BTYPE=10"),
                    "expected BTYPE=10 placeholder message, got: {source}"
                );
            }
            other => panic!("expected Read error, got {other:?}"),
        }
    }

    #[test]
    fn reserved_btype_surfaces_structural_error() {
        // BFINAL=1, BTYPE=11 → 0b111 = 0x07.
        let stream = vec![0x07u8];
        let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { source, .. }) => {
                assert!(
                    source.to_string().contains("reserved block type"),
                    "expected reserved-block error, got: {source}"
                );
            }
            other => panic!("expected Read error, got {other:?}"),
        }
    }

    #[test]
    fn truncated_block_type_byte_surfaces_unexpected_eof() {
        let stream: Vec<u8> = Vec::new();
        let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { consumed, source }) => {
                assert_eq!(consumed, 0);
                assert!(source.to_string().contains("block-type byte"));
            }
            other => panic!("expected Read error, got {other:?}"),
        }
    }

    #[test]
    fn truncated_stored_header_surfaces_unexpected_eof() {
        // BTYPE byte present but only 2 of the 4 LEN/NLEN bytes.
        let stream = vec![0x01u8, 0x10, 0x00];
        let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { source, .. }) => {
                assert!(source.to_string().contains("LEN/NLEN"));
            }
            other => panic!("expected Read error, got {other:?}"),
        }
    }

    #[test]
    fn truncated_stored_payload_surfaces_unexpected_eof() {
        // BFINAL=1, stored, LEN=8, NLEN=0xFFF7, but only 3 payload
        // bytes follow.
        let mut stream = Vec::new();
        stream.push(0x01u8);
        stream.extend_from_slice(&8u16.to_le_bytes());
        stream.extend_from_slice(&(!8u16).to_le_bytes());
        stream.extend_from_slice(b"abc");
        let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
        let mut sink = Vec::new();
        loop {
            match decoder.decode_step(&mut sink) {
                Ok(DecodeStatus::MoreData) => continue,
                Ok(DecodeStatus::Eof) => panic!("truncated payload should not reach Eof"),
                Err(DecodeError::Read { source, .. }) => {
                    assert!(
                        source.to_string().contains("stored-block payload"),
                        "expected payload-truncation message, got: {source}"
                    );
                    return;
                }
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn corrupt_stored_lengths_surface_typed_error() {
        // BTYPE byte then a deliberately-corrupted LEN/NLEN pair.
        let stream = vec![0x01u8, 0x10, 0x00, 0xAD, 0xDE];
        let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { source, .. }) => {
                assert!(
                    source.to_string().contains("LEN/NLEN mismatch"),
                    "expected LEN/NLEN mismatch, got: {source}"
                );
            }
            other => panic!("expected Read error, got {other:?}"),
        }
    }

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

        let payload = b"sink-fails-on-write".repeat(64);
        let stream = build_stored_stream(&payload, true);
        let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
        match decoder.decode_step(&mut FailingSink) {
            Err(DecodeError::Write(e)) => {
                assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe);
            }
            other => panic!("expected Write error, got {other:?}"),
        }
        // After a terminal error the decoder is poisoned to Done; a
        // follow-up step is a no-op Eof.
        assert_eq!(
            decoder
                .decode_step(&mut FailingSink)
                .expect("eof after error"),
            DecodeStatus::Eof
        );
    }

    #[test]
    fn factory_constructs_and_decodes_a_stored_stream() {
        let payload = b"factory-path-check".repeat(32);
        let stream = build_stored_stream(&payload, true);
        let mut decoder = factory(Box::new(Cursor::new(stream))).expect("factory");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode") == DecodeStatus::MoreData {}
        assert_eq!(sink, payload);
    }

    #[test]
    fn frame_boundary_is_none_in_phase_1() {
        // Phase 1 does not yet surface restart points; Phase 7 lands
        // the resume blob and starts advancing this. Pin the
        // contract so we notice if it accidentally regresses before
        // the rest of the resume plumbing is ready.
        let stream = build_stored_stream(b"x", true);
        let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode") == DecodeStatus::MoreData {}
        assert_eq!(decoder.frame_boundary(), None);
    }
}
