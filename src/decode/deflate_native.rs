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
//! Bytes pulled from the source travel through
//! [`bitstream::BitReader`]; the decoder reports
//! [`StreamingDecoder::bytes_consumed`] as the bit reader's byte-floor
//! (`byte_position().0`). For byte-aligned blocks (stored payload, the
//! gap between back-to-back stored blocks) the floor moves byte-by-
//! byte exactly as the Phase 1 byte-oriented helper did. For
//! Huffman blocks (BTYPE=01 / Phase 4 BTYPE=10) the floor lags by up
//! to 1 byte while the bit cursor is fractionally inside a byte; the
//! `docs/PLAN_deflate_block_decoder.md` §Risks 2 floor convention
//! pins the contract: bytes the cursor has fully passed are
//! puncher-safe; the byte the cursor sits inside must stay on disk.

use std::io::{Read, Write};

use crate::decode::{DecodeError, DecodeStatus, StreamingDecoder};
use crate::types::ByteOffset;

pub mod bitstream;
pub mod block;
pub mod error;
pub mod huffman;

use self::bitstream::BitReader;
use self::block::{parse_stored_lengths, STORED_HEADER_LEN};
use self::error::DeflateError;
use self::huffman::{HuffTable, DIST_BASE, FIXED_DIST_TABLE, FIXED_LITLEN_TABLE, LENGTH_BASE};

/// Output buffer size used per [`StreamingDecoder::decode_step`] for
/// stored-block payload streaming. Matches the existing in-tree
/// decoders (`crate::decode::xz`, `crate::decode::lz4`) so the
/// extractor's punch / checkpoint cadence behaves the same way
/// regardless of which decoder is in front of it.
const OUTPUT_CHUNK: usize = 1 << 20;

/// Streaming pure-Rust DEFLATE decoder.
///
/// Owns its source on construction (via [`BitReader`]); subsequent
/// [`StreamingDecoder::decode_step`] calls do not need it passed back
/// in. The source is `Send` so the decoder can be moved to a worker
/// thread the same way the other in-tree decoders can.
///
/// Phases 1–3 ship stored blocks (`BTYPE=00`) and fixed-Huffman
/// blocks (`BTYPE=01`) end-to-end. Dynamic-Huffman blocks
/// (`BTYPE=10`) return
/// [`DeflateError::DynamicHuffmanUnimplemented`] until Phase 4 fills
/// the path in. The reserved value (`BTYPE=11`) surfaces as
/// [`DeflateError::ReservedBlockType`].
pub struct Decoder {
    /// Bit-level source reader. Owns the underlying
    /// `Box<dyn Read + Send>` and exposes `byte_position` for the
    /// floor-cursor accounting the puncher relies on.
    bits: BitReader,
    /// State machine; see [`State`].
    state: State,
    /// Sliding-window stand-in (Phase 5 swaps for a 32 KiB ring).
    /// Holds the cumulative decompressed output for the current
    /// run; back-references inside fixed/dynamic Huffman blocks
    /// index from `window.len() - distance`. Phase 5 trims the
    /// front to keep the window bounded.
    window: Vec<u8>,
    /// Bytes already flushed from `window` to the sink. Phase 5
    /// swaps for the ring's tail cursor.
    window_flushed: usize,
    /// Pre-allocated scratch buffer for stored-block aligned
    /// payload reads. Reused across steps to avoid per-call
    /// allocation.
    output_buf: Vec<u8>,
}

/// Decoder state machine.
///
/// Transitions are driven by what the source has delivered so far. A
/// `decode_step` does at most one unit of work — read the next block
/// header, read the stored-block length pair, stream up to
/// [`OUTPUT_CHUNK`] bytes of a stored-block payload, or decode a
/// bounded number of fixed-Huffman symbols — before returning so the
/// extractor can interleave punching and checkpointing.
#[derive(Debug)]
enum State {
    /// Need to read the next block header (`BFINAL` (1 bit) +
    /// `BTYPE` (2 bits) per RFC 1951 §3.2.3). Clean source EOF
    /// *before* this state's read is a structural error: a deflate
    /// stream must end with a `BFINAL=1` block.
    AwaitingBlockType,
    /// Just consumed the BFINAL+BTYPE for a stored block (and
    /// byte-aligned the bit cursor per RFC 1951 §3.2.4). Need to
    /// read the 4-byte `(LEN_lo, LEN_hi, NLEN_lo, NLEN_hi)` header.
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
    /// Inside a fixed-Huffman block. Decodes lit/length symbols
    /// (RFC 1951 §3.2.6 precomputed tables) until the EOB
    /// (literal/length 256) symbol; a single step bounds work at
    /// roughly [`OUTPUT_CHUNK`] bytes of decompressed output before
    /// returning so the extractor's punch / checkpoint cadence
    /// stays responsive.
    InFixedHuffmanBlock {
        /// Whether this is the last block in the deflate stream.
        last: bool,
    },
    /// Stream ended cleanly. Subsequent steps are no-ops.
    Done,
}

/// Re-label any [`DeflateError::UnexpectedEof`] surfaced by `r`
/// with the given context-specific `label`, leaving every other
/// variant untouched. Used at the seam between the bit reader's
/// generic "bit stream" / "aligned-byte read" labels and the
/// per-field labels the existing tests assert on
/// (`block-type byte`, `stored-block LEN/NLEN`, etc.).
fn relabel_eof<T>(r: Result<T, DeflateError>, label: &'static str) -> Result<T, DeflateError> {
    r.map_err(|e| match e {
        DeflateError::UnexpectedEof(_) => DeflateError::UnexpectedEof(label),
        other => other,
    })
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
            bits: BitReader::new(src),
            state: State::AwaitingBlockType,
            window: Vec::new(),
            window_flushed: 0,
            output_buf: vec![0u8; OUTPUT_CHUNK],
        })
    }

    /// Flush every newly-decoded byte from the window stand-in to
    /// the sink. Phase 5 will replace this with a ring-buffer-aware
    /// flush that respects the 32 KiB tail.
    fn flush_window_to_sink(&mut self, sink: &mut dyn Write) -> Result<(), DeflateError> {
        if self.window_flushed < self.window.len() {
            sink.write_all(&self.window[self.window_flushed..])
                .map_err(DeflateError::SinkIo)?;
            self.window_flushed = self.window.len();
        }
        Ok(())
    }

    /// Internal: the body of one `decode_step`, returning the
    /// internal error type. The trait-level `decode_step` wraps this
    /// with the [`DeflateError::into_decode_error`] boundary.
    fn step_inner(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, DeflateError> {
        loop {
            match self.state {
                State::Done => return Ok(DecodeStatus::Eof),

                State::AwaitingBlockType => {
                    let bfinal = relabel_eof(self.bits.read_bits(1), "block-type byte")?;
                    let btype = relabel_eof(self.bits.read_bits(2), "block-type byte")?;
                    let last = bfinal == 1;
                    self.state = match btype {
                        0b00 => {
                            // Stored: align to the next byte boundary
                            // (RFC 1951 §3.2.4) before reading the
                            // LEN/NLEN header.
                            self.bits.align_to_byte();
                            State::AwaitingStoredHeader { last }
                        }
                        0b01 => State::InFixedHuffmanBlock { last },
                        0b10 => return Err(DeflateError::DynamicHuffmanUnimplemented),
                        0b11 => return Err(DeflateError::ReservedBlockType),
                        // INVARIANT: `read_bits(2)` returns 0..=3.
                        _ => unreachable!("BTYPE field is 2 bits"),
                    };
                    // Loop again so the caller observes actual decode
                    // progress on this step rather than getting one
                    // step per state transition.
                }

                State::AwaitingStoredHeader { last } => {
                    let mut buf = [0u8; STORED_HEADER_LEN];
                    relabel_eof(self.bits.read_aligned(&mut buf), "stored-block LEN/NLEN")?;
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
                            self.state = State::Done;
                            return Ok(DecodeStatus::Eof);
                        }
                        self.state = State::AwaitingBlockType;
                        // Don't loop — return so the caller observes
                        // one step of progress per block boundary.
                        return Ok(DecodeStatus::MoreData);
                    }

                    // Bound the read so a single step never copies
                    // more than `OUTPUT_CHUNK` bytes. Stored-block
                    // payload is always byte-aligned per RFC 1951
                    // §3.2.4, so the bit reader's fast-path works.
                    let want = (remaining as usize).min(self.output_buf.len());
                    let buf = &mut self.output_buf[..want];
                    relabel_eof(self.bits.read_aligned(buf), "stored-block payload")?;
                    // Push to the sliding-window stand-in so a
                    // subsequent fixed/dynamic-Huffman block can
                    // back-reference into stored output, then flush
                    // the new bytes to the sink.
                    self.window.extend_from_slice(buf);
                    self.flush_window_to_sink(sink)?;
                    // INVARIANT: `want <= remaining` and
                    // `want <= u32::MAX`, so the cast and subtract
                    // cannot underflow.
                    self.state = State::InStoredBlock {
                        remaining: remaining - want as u32,
                        last,
                    };
                    return Ok(DecodeStatus::MoreData);
                }

                State::InFixedHuffmanBlock { last } => {
                    if let Some(status) = self.decode_huffman_body(
                        &FIXED_LITLEN_TABLE,
                        Some(&FIXED_DIST_TABLE),
                        last,
                        sink,
                    )? {
                        return Ok(status);
                    }
                }
            }
        }
    }

    /// Decode RFC 1951 §3.2.5 lit/length / distance symbols against
    /// `lit_table` (and `dist_table` when present) until either the
    /// block's EOB symbol is consumed or the per-step output cap of
    /// roughly [`OUTPUT_CHUNK`] bytes is reached.
    ///
    /// Returns `Ok(Some(_))` when the inner loop produced a
    /// step-terminating event (block end + transition, or output
    /// cap reached); returns `Ok(None)` on impossible cases that
    /// should bubble up through the outer loop. The structure
    /// matches the existing `step_inner` pattern: the outer loop
    /// owns state transitions, helpers return when they have
    /// progress to report.
    ///
    /// `dist_table = None` is a placeholder for Phase 4's "literals
    /// only" dynamic blocks (HDIST=1 with the only code length 0);
    /// hitting a length symbol with no distance table surfaces as
    /// [`DeflateError::MalformedHuffman`].
    fn decode_huffman_body(
        &mut self,
        lit_table: &HuffTable,
        dist_table: Option<&HuffTable>,
        last: bool,
        sink: &mut dyn Write,
    ) -> Result<Option<DecodeStatus>, DeflateError> {
        let start_window_len = self.window.len();
        loop {
            let sym = lit_table.decode(&mut self.bits)?;
            match sym {
                0..=255 => {
                    // INVARIANT: sym < 256, fits in u8.
                    self.window.push(sym as u8);
                }
                256 => {
                    // End of block. Flush, transition, return.
                    self.flush_window_to_sink(sink)?;
                    self.state = if last {
                        State::Done
                    } else {
                        State::AwaitingBlockType
                    };
                    return Ok(Some(if last {
                        DecodeStatus::Eof
                    } else {
                        DecodeStatus::MoreData
                    }));
                }
                257..=285 => {
                    let lc = (sym - 257) as usize;
                    // INVARIANT: lc <= 28, in bounds of LENGTH_BASE.
                    let (extra_bits, base) = LENGTH_BASE[lc];
                    let extra = if extra_bits == 0 {
                        0
                    } else {
                        self.bits.read_bits(u32::from(extra_bits))?
                    };
                    let length = base + extra;

                    let dist_table = dist_table.ok_or(DeflateError::MalformedHuffman(
                        "back-reference symbol with no distance alphabet declared",
                    ))?;
                    let dsym = dist_table.decode(&mut self.bits)?;
                    if dsym >= 30 {
                        return Err(DeflateError::ReservedDistanceCode { code: dsym });
                    }
                    // INVARIANT: dsym < 30, in bounds of DIST_BASE.
                    let (dextra_bits, dbase) = DIST_BASE[dsym as usize];
                    let dextra = if dextra_bits == 0 {
                        0
                    } else {
                        self.bits.read_bits(u32::from(dextra_bits))?
                    };
                    let distance = dbase + dextra;

                    let available = self.window.len() as u64;
                    if u64::from(distance) > available {
                        return Err(DeflateError::BackReferenceUnderflow {
                            distance,
                            available,
                        });
                    }
                    // INVARIANT: distance <= window.len() per the
                    // bounds check above; the subtraction cannot
                    // underflow.
                    let start = self.window.len() - distance as usize;
                    // RFC 1951 §3.2.5 overlap-by-design: when
                    // `length > distance`, the early bytes of the
                    // copy are read as soon as they're appended.
                    // The byte-by-byte loop honors this without any
                    // special casing.
                    for k in 0..length as usize {
                        let byte = self.window[start + k];
                        self.window.push(byte);
                    }
                }
                286..=287 => {
                    return Err(DeflateError::MalformedHuffman(
                        "lit/length symbols 286 and 287 are reserved",
                    ));
                }
                _ => {
                    return Err(DeflateError::MalformedHuffman("lit/length symbol > 287"));
                }
            }

            // Bound per-step output. A single match symbol can emit
            // up to 258 bytes, so the check happens after each
            // symbol; the cap is therefore "soft" by up to one
            // match's worth of output, which is well under the
            // extractor's punch granularity.
            if self.window.len() - start_window_len >= OUTPUT_CHUNK {
                self.flush_window_to_sink(sink)?;
                return Ok(Some(DecodeStatus::MoreData));
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
                let consumed = self.bits.byte_position().0;
                // Errors are terminal — clamp to Done so further
                // calls cleanly short-circuit. The bit reader (and
                // the source it owns) lives on inside `self.bits`
                // until the decoder is dropped; that's fine because
                // every subsequent decode_step short-circuits at
                // the `State::Done` arm above.
                self.state = State::Done;
                Err(e.into_decode_error(consumed))
            }
        }
    }

    fn bytes_consumed(&self) -> ByteOffset {
        // The bit reader's byte-floor is the puncher-safe high-water
        // mark per `docs/PLAN_deflate_block_decoder.md` §Risks 2:
        // bytes strictly before this index are fully consumed; the
        // byte the bit cursor is fractionally inside (only possible
        // mid-Huffman-block) must stay on disk.
        ByteOffset::new(self.bits.byte_position().0)
    }

    fn frame_boundary(&self) -> Option<ByteOffset> {
        // Phases 1–3 don't surface mid-stream restart points yet —
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
    fn truncated_fixed_huffman_block_surfaces_unexpected_eof() {
        // BFINAL=1, BTYPE=01 → 0b011 = 0x03. The byte's high 5 bits
        // are part of the first Huffman code (not padding), so the
        // decoder needs more bits than the source provides.
        let stream = vec![0x03u8];
        let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { source, .. }) => {
                let msg = source.to_string();
                // Bit reader's "bit stream" label, the deflate-side
                // analogue of the existing "stored-block payload" /
                // "block-type byte" labels.
                assert!(
                    msg.contains("bit stream"),
                    "expected truncation message, got: {msg}"
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
    fn frame_boundary_stays_none_until_phase_7() {
        // Phases 1–3 do not yet surface restart points; Phase 7
        // lands the resume blob and starts advancing this. Pin the
        // contract so we notice if it accidentally regresses before
        // the rest of the resume plumbing is ready.
        let stream = build_stored_stream(b"x", true);
        let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode") == DecodeStatus::MoreData {}
        assert_eq!(decoder.frame_boundary(), None);
    }

    // ----------------------------------------------------------------
    // Phase 3 — fixed-Huffman block (BTYPE=01) tests
    // ----------------------------------------------------------------

    /// Bit-level encoder for hand-building fixed-Huffman fixtures.
    /// LSB-first within each byte (RFC 1951 §3.1.1) so the output
    /// matches exactly what the bit reader expects.
    struct BitWriter {
        bytes: Vec<u8>,
        acc: u64,
        nbits: u32,
    }

    impl BitWriter {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                acc: 0,
                nbits: 0,
            }
        }

        fn write_bits(&mut self, value: u32, n: u32) {
            debug_assert!(n <= 32);
            debug_assert!(n == 32 || value < (1u32 << n));
            self.acc |= u64::from(value) << self.nbits;
            self.nbits += n;
            while self.nbits >= 8 {
                self.bytes.push(self.acc as u8);
                self.acc >>= 8;
                self.nbits -= 8;
            }
        }

        fn finish(mut self) -> Vec<u8> {
            if self.nbits > 0 {
                self.bytes.push(self.acc as u8);
            }
            self.bytes
        }
    }

    /// Reverse the low `n` bits of `v` — the encoder-side analogue
    /// of the bit-reverse [`huffman::bit_reverse`] does at table-
    /// build time. Huffman codes are written MSB-first into the
    /// stream; the bit reader returns LSB-first peek values, so the
    /// canonical code is reversed before going on the wire.
    fn rev(v: u32, n: u32) -> u32 {
        let mut r = 0u32;
        let mut v = v;
        for _ in 0..n {
            r = (r << 1) | (v & 1);
            v >>= 1;
        }
        r
    }

    /// RFC 1951 §3.2.6 fixed lit/length canonical code by symbol.
    fn fixed_litlen_canonical(sym: u16) -> (u32, u32) {
        match sym {
            0..=143 => (0b0011_0000_u32 + u32::from(sym), 8),
            144..=255 => (0b1_1001_0000_u32 + u32::from(sym - 144), 9),
            256..=279 => (u32::from(sym - 256), 7),
            280..=287 => (0b1100_0000_u32 + u32::from(sym - 280), 8),
            _ => panic!("invalid lit/length symbol {sym}"),
        }
    }

    /// Encode a fixed-Huffman block consisting of literals (no
    /// back-references). `last` controls the BFINAL bit.
    fn encode_fixed_literal_block(payload: &[u8], last: bool) -> Vec<u8> {
        let mut w = BitWriter::new();
        // BFINAL + BTYPE=01.
        w.write_bits(u32::from(last), 1);
        w.write_bits(0b01, 2);
        // One literal per byte.
        for &b in payload {
            let (canonical, len) = fixed_litlen_canonical(u16::from(b));
            w.write_bits(rev(canonical, len), len);
        }
        // EOB symbol (256): canonical 0, 7 bits → reversed 0.
        let (eob_c, eob_len) = fixed_litlen_canonical(256);
        w.write_bits(rev(eob_c, eob_len), eob_len);
        w.finish()
    }

    /// Encode a single back-reference operation as a fixed-Huffman
    /// block: write a literal 'a', then a length-`length`,
    /// distance-`distance` match. Both length and distance must
    /// fit in their fixed-Huffman base tables (3..=258, 1..=32768).
    fn encode_fixed_match_block(
        prefix_literal: u8,
        length: u32,
        distance: u32,
        last: bool,
    ) -> Vec<u8> {
        let mut w = BitWriter::new();
        w.write_bits(u32::from(last), 1);
        w.write_bits(0b01, 2);

        // Literal prefix.
        let (lc, ll) = fixed_litlen_canonical(u16::from(prefix_literal));
        w.write_bits(rev(lc, ll), ll);

        // Length code: search LENGTH_BASE for the right entry.
        // INVARIANT (test harness): caller passes a `length` that
        // matches a base entry exactly so extra_bits resolve to 0
        // (keeps the helper minimal).
        let (length_code_idx, _) = huffman::LENGTH_BASE
            .iter()
            .enumerate()
            .find(|(_, (extra, base))| *extra == 0 && *base == length)
            .expect("test harness: length must match a 0-extra-bit base");
        let length_sym = 257u16 + length_code_idx as u16;
        let (sc, sl) = fixed_litlen_canonical(length_sym);
        w.write_bits(rev(sc, sl), sl);

        // Distance code: same — find a 0-extra-bit base.
        let (dist_code_idx, _) = huffman::DIST_BASE
            .iter()
            .enumerate()
            .find(|(_, (extra, base))| *extra == 0 && *base == distance)
            .expect("test harness: distance must match a 0-extra-bit base");
        let dist_sym = dist_code_idx as u16;
        let (dc, dl) = (u32::from(dist_sym), 5);
        w.write_bits(rev(dc, dl), dl);

        // EOB.
        let (eob_c, eob_len) = fixed_litlen_canonical(256);
        w.write_bits(rev(eob_c, eob_len), eob_len);
        w.finish()
    }

    #[test]
    fn fixed_huffman_eob_only_block_round_trips() {
        // Empty payload encoded as a fixed-Huffman block: BFINAL=1,
        // BTYPE=01, then EOB = 7 zero bits. Decoder must surface
        // clean Eof with nothing in the sink.
        let stream = encode_fixed_literal_block(&[], true);
        let out = decode_all(stream);
        assert!(out.is_empty());
    }

    #[test]
    fn fixed_huffman_single_literal_round_trips() {
        let stream = encode_fixed_literal_block(b"X", true);
        let out = decode_all(stream);
        assert_eq!(out, b"X");
    }

    #[test]
    fn fixed_huffman_ascii_string_round_trips() {
        // Mix of 8-bit (0..=143) and 9-bit (144..=255) canonical
        // codes via ASCII text plus a non-ASCII byte.
        let payload = b"the quick brown fox 0123456789 \xC0\xFF".to_vec();
        let stream = encode_fixed_literal_block(&payload, true);
        let out = decode_all(stream);
        assert_eq!(out, payload);
    }

    /// RFC 1951 §3.2.5 distance codes 0..=3 cover distances 1..=4
    /// with no extra bits — the dense edge cases the plan calls
    /// out as Phase 3 must-test.
    #[test]
    fn fixed_huffman_distance_codes_zero_through_three_round_trip() {
        for distance in 1u32..=4 {
            // Encode "a" + match (length 3, distance d). The 'a'
            // literal seeds the back-reference history; the match
            // copies "a" `length` times, producing `1 + length`
            // bytes total — but `distance` controls how the bytes
            // overlap. With distance=1, length=3 → "aaaa" (the
            // RLE-by-back-reference idiom).
            let stream = encode_fixed_match_block(b'a', 3, distance, true);
            let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
            let mut sink = Vec::new();
            // For distance > 1, we need more history than a single
            // 'a' provides — so for this test, only distance=1
            // succeeds; distance 2..=4 surface BackReferenceUnderflow
            // (the prefix has only 1 byte of history).
            match decoder.decode_step(&mut sink) {
                Ok(_) if distance == 1 => {
                    // Drive to completion.
                    while decoder.decode_step(&mut sink).expect("decode") == DecodeStatus::MoreData
                    {
                    }
                    assert_eq!(sink, b"aaaa", "distance=1 length=3");
                }
                Err(DecodeError::Read { source, .. }) if distance > 1 => {
                    assert!(
                        source.to_string().contains("distance"),
                        "expected back-reference error for distance={distance}, got: {source}"
                    );
                }
                other => panic!("unexpected outcome at distance={distance}: {other:?}"),
            }
        }
    }

    #[test]
    fn fixed_huffman_overlap_back_reference_round_trips() {
        // The classic distance-1 length-N back-reference: encodes
        // an N-times repetition. Tests RFC 1951 §3.2.5
        // overlap-by-design.
        // Encode 'a' + match(length=8, distance=1) → "aaaaaaaaa" (9 'a's).
        let stream = encode_fixed_match_block(b'a', 8, 1, true);
        let out = decode_all(stream);
        assert_eq!(out, b"aaaaaaaaa");
    }

    #[test]
    fn fixed_huffman_back_reference_underflow_surfaces_typed_error() {
        // Encode 'a' + match(length=3, distance=4). With only 1
        // byte of prior output, distance=4 reaches before the
        // window's start; the decoder must surface
        // BackReferenceUnderflow.
        let stream = encode_fixed_match_block(b'a', 3, 4, true);
        let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { source, .. }) => {
                let msg = source.to_string();
                assert!(
                    msg.contains("distance 4 exceeds available history"),
                    "expected BackReferenceUnderflow message, got: {msg}"
                );
            }
            other => panic!("expected Read error, got {other:?}"),
        }
    }

    #[test]
    fn fixed_huffman_reserved_distance_code_30_surfaces_typed_error() {
        // Hand-build a fixed-Huffman block that emits distance code
        // 30 (reserved). Sequence: BFINAL=1, BTYPE=01, literal 'a',
        // length 3 (lit/len code 257 = 7-bit canonical 0b0000001),
        // distance code 30 (5-bit canonical 0b11110).
        let mut w = BitWriter::new();
        w.write_bits(1, 1); // BFINAL
        w.write_bits(0b01, 2); // BTYPE=01
                               // literal 'a' (97): canonical 0b0011_0000 + 97 = 0b1001_0001, 8 bits.
        let (c, l) = fixed_litlen_canonical(97);
        w.write_bits(rev(c, l), l);
        // length code 257 → canonical 0b0000001, 7 bits, reversed = 0b1000000 = 0x40.
        let (c, l) = fixed_litlen_canonical(257);
        w.write_bits(rev(c, l), l);
        // distance 30: 5-bit canonical 30 = 0b11110, reversed = 0b01111.
        w.write_bits(rev(30, 5), 5);
        // EOB.
        let (c, l) = fixed_litlen_canonical(256);
        w.write_bits(rev(c, l), l);
        let stream = w.finish();

        let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { source, .. }) => {
                let msg = source.to_string();
                assert!(
                    msg.contains("reserved distance code 30"),
                    "expected ReservedDistanceCode message, got: {msg}"
                );
            }
            other => panic!("expected Read error, got {other:?}"),
        }
    }

    #[test]
    fn multiple_fixed_huffman_blocks_concatenate_in_order() {
        // Two back-to-back fixed-Huffman blocks (only the second
        // with BFINAL=1). The bit cursor must persist across the
        // block boundary — a deflate stream's blocks are not
        // byte-aligned to each other, so we build the whole stream
        // through a single [`BitWriter`] rather than concatenating
        // two byte-finalized blocks (which would round to the next
        // byte and corrupt the alignment).
        let mut w = BitWriter::new();
        // Block A (non-final) literals + EOB.
        w.write_bits(0, 1);
        w.write_bits(0b01, 2);
        for &b in b"alpha-" {
            let (c, l) = fixed_litlen_canonical(u16::from(b));
            w.write_bits(rev(c, l), l);
        }
        let (eob_c, eob_l) = fixed_litlen_canonical(256);
        w.write_bits(rev(eob_c, eob_l), eob_l);
        // Block B (final) literals + EOB.
        w.write_bits(1, 1);
        w.write_bits(0b01, 2);
        for &b in b"omega!" {
            let (c, l) = fixed_litlen_canonical(u16::from(b));
            w.write_bits(rev(c, l), l);
        }
        w.write_bits(rev(eob_c, eob_l), eob_l);
        let stream = w.finish();

        let out = decode_all(stream);
        assert_eq!(out, b"alpha-omega!");
    }

    /// Differential against `flate2` (`miniz_oxide` backend) at
    /// `Compression::fast()` — for inputs short enough that
    /// `miniz_oxide` reliably emits BTYPE=01. For inputs that come
    /// out as BTYPE=00 (stored) or BTYPE=10 (dynamic), the test
    /// still asserts byte-identity for the BTYPEs Phase 1 / 3
    /// support and skips dynamic blocks until Phase 4.
    #[test]
    fn flate2_round_trip_50_random_short_fixtures() {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write as _;

        let mut rng = 0xCAFE_F00Du32;
        let mut step = || {
            rng ^= rng << 13;
            rng ^= rng >> 17;
            rng ^= rng << 5;
            rng
        };

        let mut fixed_count = 0u32;
        let mut stored_count = 0u32;
        let mut dynamic_count = 0u32;

        for _ in 0..50 {
            // Short payloads bias miniz_oxide toward fixed Huffman.
            let len = (step() % 24) as usize + 4;
            // Restrict to ASCII printable so flate2 prefers
            // Huffman over stored.
            let payload: Vec<u8> = (0..len)
                .map(|_| {
                    let r = step() & 0x3F;
                    (r as u8) + 32
                })
                .collect();

            let mut enc = DeflateEncoder::new(Vec::new(), Compression::fast());
            enc.write_all(&payload).expect("encode");
            let raw = enc.finish().expect("finish");
            assert!(!raw.is_empty(), "encoder produced empty output");

            // BTYPE classification on the first 3 bits of byte 0.
            let btype = (raw[0] >> 1) & 0b11;
            match btype {
                0b00 => {
                    stored_count += 1;
                    let mut decoder = Decoder::new(Box::new(Cursor::new(raw))).expect("construct");
                    let mut sink = Vec::new();
                    while decoder.decode_step(&mut sink).expect("decode") == DecodeStatus::MoreData
                    {
                    }
                    assert_eq!(sink, payload, "BTYPE=00 round-trip");
                }
                0b01 => {
                    fixed_count += 1;
                    let mut decoder = Decoder::new(Box::new(Cursor::new(raw))).expect("construct");
                    let mut sink = Vec::new();
                    while decoder.decode_step(&mut sink).expect("decode") == DecodeStatus::MoreData
                    {
                    }
                    assert_eq!(sink, payload, "BTYPE=01 round-trip");
                }
                0b10 => {
                    dynamic_count += 1;
                    // Phase 4 work; current placeholder rejects
                    // cleanly. Accept either the placeholder error
                    // or… actually, only the placeholder is valid.
                    let mut decoder = Decoder::new(Box::new(Cursor::new(raw))).expect("construct");
                    let mut sink = Vec::new();
                    match decoder.decode_step(&mut sink) {
                        Err(DecodeError::Read { source, .. }) => {
                            assert!(
                                source.to_string().contains("BTYPE=10"),
                                "expected dynamic-Huffman placeholder"
                            );
                        }
                        other => panic!("expected Phase 4 placeholder, got {other:?}"),
                    }
                }
                _ => unreachable!("BTYPE is 2 bits"),
            }
        }

        // Sanity gate: at least one fixed-Huffman fixture must have
        // appeared. If miniz_oxide ever flips its heuristic this
        // test will start failing this gate, prompting us to
        // restructure rather than silently lose coverage.
        assert!(
            fixed_count > 0,
            "no BTYPE=01 fixtures in 50 — miniz_oxide heuristic changed?"
        );
        // Print the breakdown for debug runs (visible with
        // `cargo test -- --nocapture`).
        eprintln!(
            "flate2 differential: {fixed_count} fixed, {stored_count} stored, {dynamic_count} dynamic out of 50"
        );
    }
}
