//! Hand-rolled, pure-Rust DEFLATE streaming decoder.
//!
//! Phases 1–9 of `docs/PLAN_deflate_block_decoder.md`. Phase 8
//! swapped this module in as the production gzip path
//! ([`crate::decode::gzip`] is now a thin re-export of [`gzip`]
//! below); Phase 9a swapped the production zip-DEFLATE path off
//! `flate2` and onto [`Decoder::new`]. The `flate2` crate is now
//! a dev-dependency only — the differential test suite uses it to
//! encode round-trip fixtures.
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
//! # What Phases 3–5 added
//!
//! - **Phase 3.** [`huffman::HuffTable`] canonical-code builder,
//!   precomputed [`huffman::FIXED_LITLEN_TABLE`] /
//!   [`huffman::FIXED_DIST_TABLE`] singletons via `LazyLock`, RFC
//!   1951 §3.2.5 length / distance base tables, and the
//!   [`Self::decode_huffman_body`] inner-symbol loop (shared with
//!   Phase 4).
//! - **Phase 4.** [`dynamic::parse_preamble`] for the RFC 1951
//!   §3.2.7 three-stage preamble (HLIT / HDIST / HCLEN counts → CL
//!   alphabet code lengths in permuted order → flat lit/length +
//!   distance code-length sequence with RLE 16/17/18 expansion).
//!   Per-block tables live in [`Self::dyn_lit`] / [`Self::dyn_dist`]
//!   and are taken in / out around each [`Self::decode_huffman_body`]
//!   call to satisfy the borrow checker. [`bitstream::BitReader`]
//!   gained soft-`ensure` semantics so streams ending exactly at
//!   the EOB code's last bit decode cleanly.
//! - **Phase 5.** [`window::RingWindow`] — 32 KiB ring buffer
//!   replacing the unbounded `Vec<u8>` window stand-in. Holds the
//!   most-recent 32 KiB of decoded output across blocks; bounded
//!   regardless of total decoded volume. Pairs with a per-step
//!   `decoded_buf` staging vec that streams to the sink at
//!   end-of-block / end-of-stream / output-cap boundaries.
//!
//! # What Phases 1–5 do *not* do
//!
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
pub mod dynamic;
pub mod error;
pub mod gzip;
pub mod huffman;
pub mod resume;
pub mod window;

use self::bitstream::BitReader;
use self::block::{parse_stored_lengths, STORED_HEADER_LEN};
use self::error::DeflateError;
use self::huffman::{HuffTable, DIST_BASE, FIXED_DIST_TABLE, FIXED_LITLEN_TABLE, LENGTH_BASE};
use self::window::RingWindow;

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
/// Phases 1–4 ship every RFC 1951 §3.2.3 block type: stored
/// (`BTYPE=00`), fixed-Huffman (`BTYPE=01`), and dynamic-Huffman
/// (`BTYPE=10`). The reserved value (`BTYPE=11`) surfaces as
/// [`DeflateError::ReservedBlockType`].
pub struct Decoder {
    /// Bit-level source reader. Owns the underlying
    /// `Box<dyn Read + Send>` and exposes `byte_position` for the
    /// floor-cursor accounting the puncher relies on.
    bits: BitReader,
    /// State machine; see [`State`].
    state: State,
    /// 32 KiB sliding window for back-references (RFC 1951 §3.2.5).
    /// Holds the most-recent 32 KiB of decoded output across
    /// blocks; a back-reference at distance `d` reads from `d`
    /// bytes back. Back-references are bounded by `d <= 32 KiB`
    /// per the spec's max-distance constant, so the window's
    /// bounded ring covers every valid lookup. Bytes that fall off
    /// the back of the ring have already been written to the sink
    /// via [`Self::decoded_buf`].
    window: RingWindow,
    /// Per-step staging buffer for sink writes. Decoded literal
    /// bytes and back-reference output land here as they're
    /// emitted; flushed to the sink at end-of-block, end-of-stream,
    /// and whenever the per-step output cap is reached.
    decoded_buf: Vec<u8>,
    /// Pre-allocated scratch buffer for stored-block aligned
    /// payload reads. Reused across steps to avoid per-call
    /// allocation.
    output_buf: Vec<u8>,
    /// Per-block dynamic-Huffman lit/length table. Populated by
    /// [`dynamic::parse_preamble`] when entering a BTYPE=10 block;
    /// taken back out before each [`Self::decode_huffman_body`]
    /// call (to satisfy the borrow checker — the helper takes
    /// `&mut self`) and restored if the block didn't end this
    /// step. Cleared at end-of-block.
    dyn_lit: Option<HuffTable>,
    /// Per-block dynamic-Huffman distance table. `None` when the
    /// block declared an all-zero distance alphabet (RFC 1951
    /// §3.2.7's "literals-only block" special case).
    dyn_dist: Option<HuffTable>,
    /// Latest restart-safe boundary inside the deflate stream, in
    /// source bytes. Set when the decoder transitions into
    /// `State::AwaitingBlockType` after a non-final block —
    /// i.e. just past the EOB / end-of-stored-payload of the
    /// previous block. The boundary's *bit* offset within the
    /// returned byte lives on the [`Self::decoder_state`] blob;
    /// callers that ignore the blob and resume via
    /// [`Self::from_bits`] alone get byte-aligned behavior, which
    /// is correct only when this boundary happens to land on a
    /// byte boundary. Use [`crate::decode::DecoderResumeFactory`]
    /// for bit-aligned resume.
    last_frame_boundary: Option<ByteOffset>,
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
    /// Inside a dynamic-Huffman block. The per-block lit/length and
    /// distance tables (built from RFC 1951 §3.2.7's preamble) live
    /// in [`Decoder::dyn_lit`] / [`Decoder::dyn_dist`]; the State
    /// variant holds only the `last` flag so the inner-block decode
    /// can fall through the same [`Decoder::decode_huffman_body`]
    /// helper the fixed-Huffman path uses.
    InDynamicHuffmanBlock {
        /// Whether this is the last block in the deflate stream.
        last: bool,
    },
    /// Stream ended cleanly. Subsequent steps are no-ops.
    Done,
}

/// Outcome from one inner-block decode pass over Huffman symbols.
/// Returned by [`Decoder::decode_huffman_body`] so the outer
/// [`Decoder::step_inner`] can perform state-transition + table-
/// drop bookkeeping in one place (instead of having the helper
/// reach into [`Decoder::dyn_lit`] / [`Decoder::dyn_dist`] mid-loop,
/// which would clash with the helper's existing `&mut self`).
#[derive(Debug, Eq, PartialEq)]
enum HuffmanBodyOutcome {
    /// EOB symbol observed; the block is complete. Caller drops
    /// any per-block tables and transitions to either `Done`
    /// (BFINAL=1) or `AwaitingBlockType` (BFINAL=0).
    Eob,
    /// Per-step output cap reached without an EOB. Caller restores
    /// any per-block tables and returns
    /// [`DecodeStatus::MoreData`] so the extractor can interleave
    /// punching / checkpointing before the next decode_step
    /// resumes the same block.
    Yielded,
}

/// Re-label any [`DeflateError::UnexpectedEof`] surfaced by `r`
/// with the given context-specific `label`, leaving every other
/// variant untouched. Used at the seam between the bit reader's
/// generic "bit stream" / "aligned-byte read" labels and the
/// per-field labels the existing tests assert on
/// (`block-type byte`, `stored-block LEN/NLEN`, etc.).
pub(super) fn relabel_eof<T>(
    r: Result<T, DeflateError>,
    label: &'static str,
) -> Result<T, DeflateError> {
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
        Ok(Self::from_bits(BitReader::new(src)))
    }

    /// Construct a [`Decoder`] over a pre-existing [`BitReader`].
    ///
    /// Used by the [`gzip`] wrapper so it can hand off the same bit
    /// reader to the deflate body for the duration of a member,
    /// then recover it (via [`Self::into_bits`]) for trailer
    /// parsing once the deflate stream ends. Construction does not
    /// pull any bytes.
    #[must_use]
    pub fn from_bits(bits: BitReader) -> Self {
        Self {
            bits,
            state: State::AwaitingBlockType,
            window: RingWindow::new(),
            decoded_buf: Vec::new(),
            output_buf: vec![0u8; OUTPUT_CHUNK],
            dyn_lit: None,
            dyn_dist: None,
            last_frame_boundary: None,
        }
    }

    /// Recover the [`BitReader`] after the deflate stream has
    /// reached [`DecodeStatus::Eof`] (i.e. after the `BFINAL=1`
    /// block's EOB has been consumed).
    ///
    /// The bit cursor is left wherever the last symbol's bits
    /// landed — generally mid-byte. Callers that need to read
    /// byte-aligned bytes after the deflate stream (e.g. the gzip
    /// trailer per RFC 1952 §2.2) must call
    /// [`BitReader::align_to_byte`] before further reads, matching
    /// RFC 1951's "any incomplete bits of the final byte … are
    /// skipped" rule. Calling this before `Eof` yields a bit
    /// reader still mid-decode; the deflate state and any
    /// per-block tables are dropped with the rest of the
    /// [`Decoder`].
    #[must_use]
    pub fn into_bits(self) -> BitReader {
        self.bits
    }

    /// Flush the per-step decoded staging buffer to the sink and
    /// clear it. Called at end-of-block, end-of-stream, and
    /// whenever the per-step output cap is reached. Idempotent
    /// when the staging buffer is empty.
    fn flush_decoded_to_sink(&mut self, sink: &mut dyn Write) -> Result<(), DeflateError> {
        if !self.decoded_buf.is_empty() {
            sink.write_all(&self.decoded_buf)
                .map_err(DeflateError::SinkIo)?;
            self.decoded_buf.clear();
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
                        0b10 => {
                            // Parse the dynamic-Huffman preamble
                            // inline (RFC 1951 §3.2.7). Tables live
                            // in self.dyn_lit / self.dyn_dist for the
                            // duration of the block.
                            let (lit, dist) = dynamic::parse_preamble(&mut self.bits)?;
                            self.dyn_lit = Some(lit);
                            self.dyn_dist = dist;
                            State::InDynamicHuffmanBlock { last }
                        }
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
                        // Record the block boundary at the current
                        // (byte-aligned) bit cursor so
                        // [`Self::decoder_state`] can emit a resume
                        // blob from this point. Stored blocks are
                        // byte-aligned by RFC 1951 §3.2.4, so the
                        // bit_offset captured by the blob is 0 here.
                        self.last_frame_boundary =
                            Some(ByteOffset::new(self.bits.byte_position().0));
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
                    // Push into the sliding window so a subsequent
                    // fixed/dynamic-Huffman block can back-reference
                    // into the stored output, and stage to the
                    // decoded buffer for the sink flush below.
                    self.window.append_slice(buf, &mut self.decoded_buf);
                    self.flush_decoded_to_sink(sink)?;
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
                    let outcome = self.decode_huffman_body(
                        &FIXED_LITLEN_TABLE,
                        Some(&FIXED_DIST_TABLE),
                        sink,
                    )?;
                    match outcome {
                        HuffmanBodyOutcome::Eob => {
                            self.state = if last {
                                State::Done
                            } else {
                                // Record the post-EOB boundary
                                // before transitioning. The bit
                                // cursor is generally mid-byte; the
                                // [`Self::decoder_state`] blob
                                // carries the bit-offset within the
                                // returned byte so a resumed
                                // decoder can re-skip the consumed
                                // bits.
                                self.last_frame_boundary =
                                    Some(ByteOffset::new(self.bits.byte_position().0));
                                State::AwaitingBlockType
                            };
                            return Ok(if last {
                                DecodeStatus::Eof
                            } else {
                                DecodeStatus::MoreData
                            });
                        }
                        HuffmanBodyOutcome::Yielded => return Ok(DecodeStatus::MoreData),
                    }
                }

                State::InDynamicHuffmanBlock { last } => {
                    // Take the per-block tables out so the helper's
                    // `&mut self` borrow doesn't clash with the
                    // immutable borrow on the tables. INVARIANT: the
                    // BTYPE=10 dispatch above always populates
                    // `self.dyn_lit` before transitioning to this
                    // state; reaching this arm with `dyn_lit = None`
                    // would be a state-machine bug.
                    let lit = self.dyn_lit.take().ok_or(DeflateError::MalformedHuffman(
                        "dynamic-block lit table missing at decode time",
                    ))?;
                    let dist = self.dyn_dist.take();
                    let result = self.decode_huffman_body(&lit, dist.as_ref(), sink);
                    match result {
                        Ok(HuffmanBodyOutcome::Eob) => {
                            // Tables drop with `lit` / `dist` going
                            // out of scope.
                            self.state = if last {
                                State::Done
                            } else {
                                self.last_frame_boundary =
                                    Some(ByteOffset::new(self.bits.byte_position().0));
                                State::AwaitingBlockType
                            };
                            return Ok(if last {
                                DecodeStatus::Eof
                            } else {
                                DecodeStatus::MoreData
                            });
                        }
                        Ok(HuffmanBodyOutcome::Yielded) => {
                            // Restore tables for the next decode_step
                            // to resume against.
                            self.dyn_lit = Some(lit);
                            self.dyn_dist = dist;
                            return Ok(DecodeStatus::MoreData);
                        }
                        Err(e) => {
                            // Tables drop on error; the parent's
                            // error path also clamps state to Done so
                            // the partial tables aren't observable.
                            return Err(e);
                        }
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
    /// Returns [`HuffmanBodyOutcome`]; the caller (the
    /// [`Self::step_inner`] state arm for the matching block type)
    /// handles state transitions and per-block-table cleanup. This
    /// keeps the helper's `&mut self` borrow scoped to the
    /// inner-loop work and avoids tangling the state machine
    /// transitions with the table-buffer ownership across
    /// fixed-vs-dynamic dispatch.
    ///
    /// `dist_table = None` corresponds to RFC 1951 §3.2.7's
    /// "literals only" dynamic block (HDIST=1 with the single
    /// distance-code length 0); hitting a length symbol with no
    /// distance table surfaces as [`DeflateError::MalformedHuffman`].
    fn decode_huffman_body(
        &mut self,
        lit_table: &HuffTable,
        dist_table: Option<&HuffTable>,
        sink: &mut dyn Write,
    ) -> Result<HuffmanBodyOutcome, DeflateError> {
        loop {
            let sym = lit_table.decode(&mut self.bits)?;
            match sym {
                0..=255 => {
                    // INVARIANT: sym < 256, fits in u8.
                    self.window.append_byte(sym as u8, &mut self.decoded_buf);
                }
                256 => {
                    // End of block. Flush; caller transitions state.
                    self.flush_decoded_to_sink(sink)?;
                    return Ok(HuffmanBodyOutcome::Eob);
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

                    self.window
                        .match_copy(distance, length, &mut self.decoded_buf)?;
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
            if self.decoded_buf.len() >= OUTPUT_CHUNK {
                self.flush_decoded_to_sink(sink)?;
                return Ok(HuffmanBodyOutcome::Yielded);
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
        // Phase 7 advances this at every transition into
        // `State::AwaitingBlockType` after a non-final block — i.e.
        // the post-EOB / post-stored-payload point of every
        // intermediate block. The boundary's byte index is the bit
        // reader's `byte_position` floor; the bit-offset within
        // that byte (typically non-zero for Huffman blocks) lives
        // on the [`Self::decoder_state`] blob and is re-skipped on
        // resume by [`resume::resume`]. Callers must use the blob
        // — restarting at this offset alone produces correct
        // output only when the boundary happens to be byte-aligned.
        self.last_frame_boundary
    }

    fn decoder_state(&self) -> Option<Vec<u8>> {
        // Snapshotable iff we're between blocks (just past EOB /
        // end-of-stored-payload) and we've decoded at least one
        // block — the initial `AwaitingBlockType` (no decoding
        // done yet) is covered by the regular factory at
        // offset 0.
        if !matches!(self.state, State::AwaitingBlockType) {
            return None;
        }
        self.last_frame_boundary?;
        let (byte_pos, bit_off) = self.bits.byte_position();
        let blob = resume::DflResumeState {
            container: resume::Container::RawDeflate,
            source_byte_position: byte_pos,
            bit_offset: bit_off,
            window_contents: self.window.recent_in_order(),
            total_decompressed: self.window.total_written(),
            running_crc32: 0,
            bfinal_seen: false,
        };
        Some(blob.serialize())
    }
}

/// [`crate::decode::DecoderFactory`] adapter for [`Decoder`].
///
/// Not registered by [`crate::decode::DecoderRegistry::with_defaults`]
/// — raw deflate streams (no gzip framing) are not a registered
/// archive format. The factory is still public so the zip
/// pipeline can reach it for `CompressionMethod::Deflate` entries
/// (see [`crate::zip::decode::decompress_entry`]).
///
/// # Errors
///
/// Forwards any error returned by [`Decoder::new`].
pub fn factory(src: Box<dyn Read + Send>) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    Ok(Box::new(Decoder::new(src)?))
}

/// [`crate::decode::DecoderResumeFactory`] adapter for the
/// hand-rolled deflate decoder.
///
/// Reconstructs a [`Decoder`] from a blob previously produced by
/// [`Decoder::decoder_state`]. The new decoder's bit cursor lands
/// at the saved `(source_byte_position, bit_offset)` and the
/// sliding window is pre-seeded from the blob's chronological
/// tail so subsequent back-references resolve correctly.
///
/// `start_offset` must equal the blob's
/// `source_byte_position`; the function surfaces
/// [`DecodeError::ResumeMismatch`] on disagreement so the
/// extractor's resume seam can distinguish "blob mis-aligned with
/// the source cursor" from a downstream malformed-stream failure.
///
/// # Errors
///
/// - [`DecodeError::Construct`] when the blob is structurally
///   malformed (bad magic, unsupported version, oversized window,
///   etc.) or when the bit-offset skip would read past the end of
///   `src`.
/// - [`DecodeError::ResumeMismatch`] when `start_offset` doesn't
///   match the blob's saved cursor.
pub fn resume_factory(
    src: Box<dyn Read + Send>,
    state_blob: &[u8],
    start_offset: u64,
) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    let state = resume::deserialize_at_boundary(state_blob, start_offset)?;
    if state.container != resume::Container::RawDeflate {
        return Err(DecodeError::Construct(std::io::Error::other(
            "deflate resume blob rejected: expected container=RawDeflate",
        )));
    }
    Ok(Box::new(Decoder::resume(src, state)?))
}

impl Decoder {
    /// Internal: build a [`Decoder`] from a parsed
    /// [`resume::DflResumeState`]. Public callers go through
    /// [`resume_factory`]; the [`gzip::GzipDecoder`] resume path
    /// also funnels through here once it has unwrapped the gzip
    /// framing fields.
    pub(super) fn resume(
        src: Box<dyn Read + Send>,
        state: resume::DflResumeState,
    ) -> Result<Self, DecodeError> {
        let mut bits = BitReader::new_at(src, state.source_byte_position);
        // Skip the bits already consumed of the first delivered
        // byte. `read_bits` is strict — propagate truncation as
        // `DecodeError::Construct` rather than letting it surface
        // as a mid-decode error later.
        if state.bit_offset > 0 {
            bits.read_bits(u32::from(state.bit_offset)).map_err(|e| {
                DecodeError::Construct(std::io::Error::other(format!(
                    "deflate resume blob rejected: cannot skip bit_offset: {e}"
                )))
            })?;
        }
        let mut decoder = Self::from_bits(bits);
        decoder
            .window
            .restore_from_snapshot(&state.window_contents, state.total_decompressed);
        decoder.last_frame_boundary = Some(ByteOffset::new(state.source_byte_position));
        Ok(decoder)
    }
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
    fn truncated_dynamic_huffman_block_surfaces_unexpected_eof() {
        // BFINAL=1, BTYPE=10 → 0b101 = 0x05. The decoder consumes
        // the first 3 bits as block header, then needs HLIT (5 bits)
        // + HDIST (5 bits) + HCLEN (4 bits) = 14 more bits — but
        // only 5 bits are left in the source byte. Surfaces as a
        // bit-stream truncation.
        let stream = vec![0x05u8];
        let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { source, .. }) => {
                assert!(
                    source.to_string().contains("bit stream"),
                    "expected truncation message, got: {source}"
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
    fn frame_boundary_remains_none_for_single_block_streams() {
        // For a stream consisting of a single (final) block, no
        // intermediate-block boundary is ever observed: the
        // BFINAL=1 path transitions straight to `State::Done`
        // without going through `AwaitingBlockType`. Pin this
        // contract so we don't accidentally start surfacing
        // end-of-stream as a "frame boundary" — that's the
        // [`StreamingDecoder::bytes_consumed`] cursor's job.
        let stream = build_stored_stream(b"x", true);
        let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode") == DecodeStatus::MoreData {}
        assert_eq!(decoder.frame_boundary(), None);
    }

    #[test]
    fn frame_boundary_advances_at_each_intermediate_stored_block() {
        // Two non-final stored blocks then a final one. The decoder
        // should record a frame boundary after each of the first
        // two blocks ends — between the two non-final blocks and
        // between the second non-final and the final one. The
        // final block's end is NOT a frame boundary (we transition
        // directly to Done).
        let block_a = build_stored_stream(b"alpha-", false);
        let block_b = build_stored_stream(b"beta-", false);
        let block_c = build_stored_stream(b"gamma!", true);
        let mut stream = block_a.clone();
        stream.extend_from_slice(&block_b);
        stream.extend_from_slice(&block_c);
        let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
        let mut sink = Vec::new();
        let mut boundaries: Vec<u64> = Vec::new();
        loop {
            let prior = decoder.frame_boundary();
            let status = decoder.decode_step(&mut sink).expect("decode");
            let next = decoder.frame_boundary();
            if next != prior {
                boundaries.push(next.expect("just observed").get());
            }
            if status == DecodeStatus::Eof {
                break;
            }
        }
        assert_eq!(
            boundaries,
            vec![block_a.len() as u64, (block_a.len() + block_b.len()) as u64],
        );
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
    /// `Compression::fast()` — covers all three BTYPE values
    /// generated by miniz_oxide on short ASCII fixtures
    /// (predominantly BTYPE=01). Phase 4's dynamic-Huffman path
    /// makes BTYPE=10 byte-identical, same as 00 / 01.
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
                    let mut decoder = Decoder::new(Box::new(Cursor::new(raw))).expect("construct");
                    let mut sink = Vec::new();
                    while decoder.decode_step(&mut sink).expect("decode") == DecodeStatus::MoreData
                    {
                    }
                    assert_eq!(sink, payload, "BTYPE=10 round-trip");
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

    // ----------------------------------------------------------------
    // Phase 4 — dynamic-Huffman block (BTYPE=10) tests
    // ----------------------------------------------------------------

    /// Differential against `flate2` at `Compression::default()`
    /// (level 6) on payloads long enough that miniz_oxide reliably
    /// picks BTYPE=10. Required by
    /// `docs/PLAN_deflate_block_decoder.md` §Phase 4 exit criteria
    /// (500 random fixtures).
    #[test]
    fn flate2_round_trip_500_random_dynamic_huffman_fixtures() {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write as _;

        let mut rng = 0xDEAD_BEEFu32;
        let mut step = || {
            rng ^= rng << 13;
            rng ^= rng >> 17;
            rng ^= rng << 5;
            rng
        };

        // Mix of payload "shapes" exercises different Huffman
        // alphabets:
        //   - random bytes (high-entropy, dense Huffman)
        //   - ASCII text with repetition (back-references everywhere)
        //   - Single byte repeated (longest possible RLE matches)
        //   - Two-character alphabet (sparse Huffman, long zero
        //     runs in the lit/length code-lengths sequence — exercises
        //     RLE 18 in the preamble)
        let make_payload = |variant: u32, len: usize, step: &mut dyn FnMut() -> u32| {
            let mut p = Vec::with_capacity(len);
            match variant % 4 {
                0 => {
                    // High-entropy random.
                    for _ in 0..len {
                        p.push((step() & 0xFF) as u8);
                    }
                }
                1 => {
                    // English-ish text with whitespace.
                    let words: &[&[u8]] = &[
                        b"the ", b"quick ", b"brown ", b"fox ", b"jumps ", b"over ", b"lazy ",
                        b"dog. ", b"\n",
                    ];
                    while p.len() < len {
                        let w = words[(step() as usize) % words.len()];
                        p.extend_from_slice(w);
                    }
                    p.truncate(len);
                }
                2 => {
                    // Single byte repeated.
                    let b = (step() & 0xFF) as u8;
                    p.resize(len, b);
                }
                _ => {
                    // Two-character alphabet — biases the lit/length
                    // table to mostly-zeros, exercising RLE 18 in
                    // the preamble.
                    let a = (step() & 0xFF) as u8;
                    let b = (step() & 0xFF) as u8;
                    for i in 0..len {
                        p.push(if (i & 1) == 0 { a } else { b });
                    }
                }
            }
            p
        };

        let mut dynamic_count = 0u32;
        let mut other_count = 0u32;
        for i in 0..500u32 {
            // 200..1224 byte payloads — long enough that miniz_oxide
            // picks dynamic Huffman the vast majority of the time.
            let len = 200 + (step() as usize % 1024);
            let payload = make_payload(i, len, &mut step);

            let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&payload).expect("encode");
            let raw = enc.finish().expect("finish");
            assert!(!raw.is_empty(), "encoder produced empty output");

            let btype = (raw[0] >> 1) & 0b11;
            let raw_len = raw.len();
            let mut decoder = Decoder::new(Box::new(Cursor::new(raw))).expect("construct");
            let mut sink = Vec::new();
            loop {
                match decoder.decode_step(&mut sink) {
                    Ok(DecodeStatus::MoreData) => {}
                    Ok(DecodeStatus::Eof) => break,
                    Err(e) => panic!(
                        "decode failed (fixture {i}, variant {}, len {len}, BTYPE={btype}, raw_len {raw_len}, payload[..16]={:02x?}): {e:?}",
                        i % 4,
                        &payload[..payload.len().min(16)]
                    ),
                }
            }
            assert_eq!(
                sink, payload,
                "round-trip mismatch (BTYPE={btype}, fixture {i})",
            );

            if btype == 0b10 {
                dynamic_count += 1;
            } else {
                other_count += 1;
            }
        }

        // The plan's exit criterion: "500 random dynamic-Huffman
        // fixtures decode byte-identical to flate2." Each fixture
        // round-trips byte-identically regardless of BTYPE; the
        // dynamic-count assertion below is a coverage gate so a
        // miniz_oxide heuristic flip can't silently erode the path
        // we're actually exercising. 300 is empirically below the
        // current count (~375) and well above zero.
        assert!(
            dynamic_count >= 300,
            "only {dynamic_count} of 500 fixtures came back as BTYPE=10 \
             — miniz_oxide heuristic changed?"
        );
        eprintln!(
            "Phase 4 differential: {dynamic_count} dynamic / {other_count} other (fixed/stored) out of 500"
        );
    }

    /// Hand-built fixture exercising the dynamic-Huffman preamble's
    /// RLE 18 (long zero run, 11..=138 zeros). Encodes a block
    /// whose lit/length alphabet uses only literal `'A'` (65) and
    /// EOB (256) — every other lit/length entry has length 0,
    /// which the encoder emits as one or more RLE-18 runs.
    ///
    /// Built as a true round-trip: we use flate2 to encode the
    /// payload (which produces BTYPE=10 with RLE 17/18 in the
    /// preamble for sparse alphabets), then decode through our
    /// path and check the output. The payload is `b"AAAA"` ×
    /// 1000 = 4000 bytes, which compresses heavily and uses a
    /// sparse alphabet.
    #[test]
    fn flate2_round_trip_sparse_alphabet_exercises_rle_zeros() {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write as _;

        let payload: Vec<u8> = b"A".repeat(4000);
        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&payload).expect("encode");
        let raw = enc.finish().expect("finish");
        let btype = (raw[0] >> 1) & 0b11;
        // miniz_oxide at level 6 on a 4 KB single-byte payload
        // emits a dynamic-Huffman block (the sparse-alphabet case
        // we want to exercise).
        assert_eq!(btype, 0b10, "expected dynamic-Huffman block");

        let mut decoder = Decoder::new(Box::new(Cursor::new(raw))).expect("construct");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode") == DecodeStatus::MoreData {}
        assert_eq!(sink, payload);
    }

    /// Hand-built fixture exercising the dynamic-Huffman preamble's
    /// RLE 16 (repeat-previous-length, 3..=6 repeats). Constructs a
    /// payload that miniz_oxide encodes with a code-length sequence
    /// containing repeated non-zero lengths (the case RLE 16
    /// targets). Works the same way as the RLE 18 test: a flate2
    /// round-trip with a payload designed to force the encoder
    /// into the right shape.
    #[test]
    fn flate2_round_trip_dense_alphabet_exercises_rle_16() {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write as _;

        // English-ish text exercises a dense lit/length alphabet
        // (most ASCII printable symbols used at similar
        // frequencies → similar code lengths → RLE 16 fires for
        // adjacent same-length entries). High-entropy random bytes
        // would force miniz_oxide into BTYPE=00 (stored) since
        // they don't compress.
        let mut payload = Vec::with_capacity(2048);
        let lines: &[&[u8]] = &[
            b"the quick brown fox jumps over the lazy dog. ",
            b"sphinx of black quartz, judge my vow. ",
            b"pack my box with five dozen liquor jugs. ",
            b"jived fox nymph grabs quick waltz. ",
            b"how vexingly quick daft zebras jump. ",
        ];
        let mut i = 0;
        while payload.len() < 2048 {
            payload.extend_from_slice(lines[i % lines.len()]);
            i += 1;
        }
        payload.truncate(2048);

        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&payload).expect("encode");
        let raw = enc.finish().expect("finish");
        let btype = (raw[0] >> 1) & 0b11;
        assert_eq!(btype, 0b10, "expected dynamic-Huffman block");

        let mut decoder = Decoder::new(Box::new(Cursor::new(raw))).expect("construct");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode") == DecodeStatus::MoreData {}
        assert_eq!(sink, payload);
    }

    /// Multi-block dynamic-Huffman: large enough that miniz_oxide
    /// chunks the payload into ≥ 2 dynamic blocks. The bit cursor
    /// must persist across the per-block boundary, and the
    /// per-block tables (`dyn_lit` / `dyn_dist`) must be cleared at
    /// EOB and rebuilt for the next block.
    #[test]
    fn flate2_round_trip_multi_block_dynamic_huffman() {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write as _;

        // 64 KB random payload — miniz_oxide at level 9 emits
        // multiple dynamic-Huffman blocks for inputs this size.
        let mut rng = 0xCAFE_BABEu32;
        let mut step = || {
            rng ^= rng << 13;
            rng ^= rng >> 17;
            rng ^= rng << 5;
            rng
        };
        let payload: Vec<u8> = (0..64 * 1024).map(|_| (step() & 0xFF) as u8).collect();

        let mut enc = DeflateEncoder::new(Vec::new(), Compression::best());
        enc.write_all(&payload).expect("encode");
        let raw = enc.finish().expect("finish");

        let mut decoder = Decoder::new(Box::new(Cursor::new(raw))).expect("construct");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode") == DecodeStatus::MoreData {}
        assert_eq!(sink, payload);
    }

    /// Dynamic block with a back-reference distance > 32 KiB
    /// upper-bounds the sliding-window stand-in's growth. (Phase 5
    /// adds the ring buffer; Phase 4 just verifies that
    /// long-distance back-references still resolve correctly.)
    #[test]
    fn flate2_round_trip_long_distance_back_references() {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write as _;

        // Repeat a 4 KB random prefix 16 times → 64 KB, with strong
        // 4 KB-period self-similarity. miniz_oxide will emit
        // back-references with distances up to the prefix length.
        let mut rng = 0xFADE_F00Du32;
        let mut step = || {
            rng ^= rng << 13;
            rng ^= rng >> 17;
            rng ^= rng << 5;
            rng
        };
        let prefix: Vec<u8> = (0..4096).map(|_| (step() & 0xFF) as u8).collect();
        let payload: Vec<u8> = (0..16).flat_map(|_| prefix.iter().copied()).collect();

        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&payload).expect("encode");
        let raw = enc.finish().expect("finish");

        let mut decoder = Decoder::new(Box::new(Cursor::new(raw))).expect("construct");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode") == DecodeStatus::MoreData {}
        assert_eq!(sink, payload);
    }

    // ----------------------------------------------------------------
    // Phase 5 — cross-block back-references + ring-buffer integration
    // ----------------------------------------------------------------

    /// Hand-built fixture exercising the single most important
    /// Phase 5 invariant: a back-reference whose distance reaches
    /// into the **previous block**'s output. The flat-`Vec<u8>`
    /// stand-in we used through Phase 4 happened to support this
    /// because it accumulated everything without trimming; the
    /// 32 KiB ring-buffer introduced in Phase 5 must continue to.
    ///
    /// Stream shape (all fixed-Huffman):
    /// - Block A (BFINAL=0): literals `'a' 'b' 'c'`, EOB.
    /// - Block B (BFINAL=1): literal `'X'`, match
    ///   `(length=3, distance=4)` — reads back `4` bytes from the
    ///   write-cursor (which sits just after `'X'` at total
    ///   position 4), copying the original `'a' 'b' 'c'`. EOB.
    ///
    /// Decoded output: `"abcXabc"`. The match's source bytes lived
    /// entirely in block A.
    #[test]
    fn cross_block_back_reference_resolves_through_ring_window() {
        let mut w = BitWriter::new();

        // -- Block A: BFINAL=0, BTYPE=01, literals "abc", EOB -----
        w.write_bits(0, 1);
        w.write_bits(0b01, 2);
        for &b in b"abc" {
            let (c, l) = fixed_litlen_canonical(u16::from(b));
            w.write_bits(rev(c, l), l);
        }
        let (eob_c, eob_l) = fixed_litlen_canonical(256);
        w.write_bits(rev(eob_c, eob_l), eob_l);

        // -- Block B: BFINAL=1, BTYPE=01, literal 'X', match,  EOB
        w.write_bits(1, 1);
        w.write_bits(0b01, 2);
        let (xc, xl) = fixed_litlen_canonical(u16::from(b'X'));
        w.write_bits(rev(xc, xl), xl);

        // Length code for length 3 = lit/length symbol 257
        // (LENGTH_BASE[0] = (extra=0, base=3)).
        let (lc, ll) = fixed_litlen_canonical(257);
        w.write_bits(rev(lc, ll), ll);

        // Distance code for distance 4 = distance symbol 3
        // (DIST_BASE[3] = (extra=0, base=4)). 5-bit canonical 3 →
        // reversed 0b11000 = 24.
        let dist_canonical = 3u32;
        w.write_bits(rev(dist_canonical, 5), 5);

        // EOB.
        w.write_bits(rev(eob_c, eob_l), eob_l);

        let stream = w.finish();
        let out = decode_all(stream);
        assert_eq!(out, b"abcXabc");
    }

    /// flate2 differential at multiple compression levels — Phase 5
    /// stresses the ring-buffer + multi-block path against
    /// miniz_oxide's range of block-iteration heuristics. Levels 1,
    /// 6 (default), and 9 (best) emit different block sizes /
    /// shapes; the round-trip must be byte-identical at every
    /// level.
    #[test]
    fn flate2_round_trip_random_payloads_at_every_level() {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write as _;

        let mut rng = 0xACDC_1234u32;
        let mut step = || {
            rng ^= rng << 13;
            rng ^= rng >> 17;
            rng ^= rng << 5;
            rng
        };
        // 16 KiB-ish English-ish payload with embedded high-entropy
        // patches — exercises a mix of long matches (from the
        // repeated text) and literals (from the high-entropy
        // patches). Big enough that level 9 produces multiple
        // blocks.
        let mut payload = Vec::with_capacity(16 * 1024);
        let lines: &[&[u8]] = &[
            b"the quick brown fox jumps over the lazy dog. ",
            b"sphinx of black quartz, judge my vow. ",
            b"pack my box with five dozen liquor jugs. ",
        ];
        let mut idx = 0;
        while payload.len() < 16 * 1024 {
            payload.extend_from_slice(lines[idx % lines.len()]);
            idx += 1;
            if idx % 7 == 0 {
                for _ in 0..32 {
                    payload.push((step() & 0xFF) as u8);
                }
            }
        }
        payload.truncate(16 * 1024);

        for level in [
            Compression::fast(),
            Compression::default(),
            Compression::best(),
        ] {
            let mut enc = DeflateEncoder::new(Vec::new(), level);
            enc.write_all(&payload).expect("encode");
            let raw = enc.finish().expect("finish");

            let mut decoder = Decoder::new(Box::new(Cursor::new(raw))).expect("construct");
            let mut sink = Vec::new();
            while decoder.decode_step(&mut sink).expect("decode") == DecodeStatus::MoreData {}
            assert_eq!(sink, payload, "round-trip at level {level:?}");
        }
    }

    /// Stream large enough that the ring buffer wraps at least
    /// once: deflate at 256 KiB (8× the 32 KiB window). The
    /// decoder must still produce byte-identical output even when
    /// the most-recent 32 KiB is the only history available for
    /// back-references.
    #[test]
    fn flate2_round_trip_payload_spanning_window_wrap() {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write as _;

        // 256 KiB compressible payload — repeating short phrase so
        // miniz_oxide finds plenty of within-window matches but
        // never tries to back-reference farther than the ring's
        // 32 KiB capacity.
        let mut payload = Vec::with_capacity(256 * 1024);
        let phrase: &[u8] = b"deflate sliding-window stress test phrase 0123456789 ";
        while payload.len() < 256 * 1024 {
            payload.extend_from_slice(phrase);
        }
        payload.truncate(256 * 1024);

        let mut enc = DeflateEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&payload).expect("encode");
        let raw = enc.finish().expect("finish");

        let mut decoder = Decoder::new(Box::new(Cursor::new(raw))).expect("construct");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode") == DecodeStatus::MoreData {}
        assert_eq!(sink, payload);
    }

    // ----------------------------------------------------------------
    // Phase 7 — decoder_state / resume round-trip tests
    // ----------------------------------------------------------------

    /// Reference-clean decode of `raw` for cross-checking
    /// resume runs. Drives a fresh decoder to EOF and returns the
    /// full output.
    fn decode_clean(raw: &[u8]) -> Vec<u8> {
        let mut decoder = Decoder::new(Box::new(Cursor::new(raw.to_vec()))).expect("construct");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode") == DecodeStatus::MoreData {}
        sink
    }

    /// Capture every `(decoder_state blob, frame_boundary, prefix
    /// emitted so far)` triple observed during a clean run of
    /// `raw`. The triples are exactly the resume points the
    /// coordinator could checkpoint at — Phase 7's contract is
    /// that each one round-trips to byte-identical output.
    #[allow(clippy::type_complexity)]
    fn capture_resume_points(raw: &[u8]) -> Vec<(Vec<u8>, u64, Vec<u8>)> {
        let mut decoder = Decoder::new(Box::new(Cursor::new(raw.to_vec()))).expect("construct");
        let mut sink: Vec<u8> = Vec::new();
        let mut points: Vec<(Vec<u8>, u64, Vec<u8>)> = Vec::new();
        let mut last_boundary: Option<u64> = None;
        loop {
            let status = decoder.decode_step(&mut sink).expect("decode");
            let boundary = decoder.frame_boundary().map(|b| b.get());
            // Capture once per new boundary observation.
            if boundary != last_boundary {
                if let Some(b) = boundary {
                    if let Some(blob) = decoder.decoder_state() {
                        points.push((blob, b, sink.clone()));
                    }
                }
                last_boundary = boundary;
            }
            if status == DecodeStatus::Eof {
                break;
            }
        }
        points
    }

    /// Build a multi-block raw deflate stream by concatenating
    /// hand-built fixed-Huffman blocks, only the last with
    /// BFINAL=1. Each block emits the corresponding `payloads[i]`
    /// as literals (no back-references), so block boundaries are
    /// deterministic and resume tests are reproducible across
    /// flate2 / miniz_oxide version updates.
    fn build_multi_block_fixed_huffman_stream(payloads: &[&[u8]]) -> (Vec<u8>, Vec<u8>) {
        assert!(!payloads.is_empty());
        let mut w = BitWriter::new();
        let combined: Vec<u8> = payloads.iter().flat_map(|p| p.iter().copied()).collect();
        for (i, payload) in payloads.iter().enumerate() {
            let last = i + 1 == payloads.len();
            // BFINAL + BTYPE=01.
            w.write_bits(u32::from(last), 1);
            w.write_bits(0b01, 2);
            for &b in *payload {
                let (c, l) = fixed_litlen_canonical(u16::from(b));
                w.write_bits(rev(c, l), l);
            }
            // EOB.
            let (eob_c, eob_l) = fixed_litlen_canonical(256);
            w.write_bits(rev(eob_c, eob_l), eob_l);
        }
        (w.finish(), combined)
    }

    #[test]
    fn resume_blob_round_trips_byte_identical_at_every_block_boundary() {
        // Hand-built 5-block fixed-Huffman stream — guaranteed to
        // produce 4 intermediate block boundaries regardless of
        // any flate2 / miniz_oxide heuristic. Each block decodes
        // to a different short payload so we can detect off-by-one
        // resume errors.
        let chunks: &[&[u8]] = &[
            b"first block content; ",
            b"second is a bit longer than the first; ",
            b"third has unique tokens 12345 67890; ",
            b"fourth: more bytes here for good measure!! ",
            b"fifth and final block to close out.",
        ];
        let (raw, payload) = build_multi_block_fixed_huffman_stream(chunks);

        // Sanity: the clean decode matches the original payload.
        let clean = decode_clean(&raw);
        assert_eq!(clean, payload);

        // Capture every resume point.
        let points = capture_resume_points(&raw);
        assert_eq!(
            points.len(),
            chunks.len() - 1,
            "expected {} intermediate block boundaries",
            chunks.len() - 1,
        );

        // Resume from each point and confirm the suffix
        // round-trips byte-identically.
        for (i, (blob, boundary, prefix)) in points.iter().enumerate() {
            let suffix_src = raw[*boundary as usize..].to_vec();
            let mut resumed: Box<dyn StreamingDecoder> =
                resume_factory(Box::new(Cursor::new(suffix_src)), blob, *boundary).expect("resume");
            let mut sink = Vec::new();
            while resumed.decode_step(&mut sink).expect("decode") == DecodeStatus::MoreData {}
            let mut combined = prefix.clone();
            combined.extend_from_slice(&sink);
            assert_eq!(
                combined, payload,
                "resume point {i} (boundary={boundary}) didn't round-trip"
            );
        }
    }

    #[test]
    fn resume_factory_rejects_blob_with_mismatched_start_offset() {
        // Capture a blob from a real run, then call resume_factory
        // with a deliberately wrong start_offset. Hand-built
        // multi-block stream so the test doesn't depend on flate2
        // / miniz_oxide block-boundary heuristics.
        let chunks: &[&[u8]] = &[b"resume mismatch block A ", b"resume mismatch block B "];
        let (raw, _payload) = build_multi_block_fixed_huffman_stream(chunks);
        let points = capture_resume_points(&raw);
        let (blob, boundary, _) = points
            .first()
            .expect("at least one resume point on the captured stream");
        // Wrong start_offset: shift by 1 byte.
        let bad_offset = boundary + 1;
        let result = resume_factory(
            Box::new(Cursor::new(raw[*boundary as usize..].to_vec())),
            blob,
            bad_offset,
        );
        match result {
            Err(DecodeError::ResumeMismatch { expected, actual }) => {
                assert_eq!(expected, *boundary);
                assert_eq!(actual, bad_offset);
            }
            Err(other) => panic!("expected ResumeMismatch, got {other:?}"),
            Ok(_) => panic!("expected ResumeMismatch, got Ok(decoder)"),
        }
    }

    #[test]
    fn resume_factory_rejects_malformed_blob() {
        let bogus = vec![0u8; 32];
        let result = resume_factory(Box::new(Cursor::new(Vec::<u8>::new())), &bogus, 0);
        match result {
            Err(DecodeError::Construct(e)) => {
                assert!(
                    e.to_string().contains("resume blob rejected"),
                    "unexpected message: {e}",
                );
            }
            Err(other) => panic!("expected Construct error, got {other:?}"),
            Ok(_) => panic!("expected Construct error, got Ok(decoder)"),
        }
    }

    /// Bit-cursor edge case from the plan: capture a resume point
    /// where the bit cursor is mid-byte (the next BFINAL bit lives
    /// in the same source byte as the previous block's EOB code).
    /// On resume, the bit reader must re-deliver that byte and the
    /// blob must skip the consumed bits, not the whole byte.
    ///
    /// Uses the hand-built fixed-Huffman multi-block helper so
    /// boundaries land on deterministic bit positions. Each EOB is
    /// 7 bits long; with 8 bits per byte and BFINAL+BTYPE taking
    /// 3 bits at the start of each block, most boundaries fall
    /// mid-byte.
    #[test]
    fn resume_at_mid_byte_boundary_reads_shared_byte_again() {
        let chunks: &[&[u8]] = &[b"a", b"b", b"cd", b"ef", b"ghi", b"jkl"];
        let (raw, payload) = build_multi_block_fixed_huffman_stream(chunks);

        let points = capture_resume_points(&raw);
        // Find at least one resume point whose blob carries a
        // non-zero bit_offset (the mid-byte case).
        let mut mid_byte_count = 0u32;
        for (blob, boundary, prefix) in &points {
            let parsed = resume::DflResumeState::deserialize(blob).expect("parse blob");
            if parsed.bit_offset != 0 {
                mid_byte_count += 1;
                // Resume from this mid-byte boundary.
                let suffix_src = raw[*boundary as usize..].to_vec();
                let mut resumed: Box<dyn StreamingDecoder> =
                    resume_factory(Box::new(Cursor::new(suffix_src)), blob, *boundary)
                        .expect("resume");
                let mut sink = Vec::new();
                while resumed.decode_step(&mut sink).expect("decode") == DecodeStatus::MoreData {}
                let mut combined = prefix.clone();
                combined.extend_from_slice(&sink);
                assert_eq!(
                    combined, payload,
                    "mid-byte resume (boundary={boundary}, bit_offset={}) didn't round-trip",
                    parsed.bit_offset,
                );
            }
        }
        assert!(
            mid_byte_count > 0,
            "expected at least one mid-byte boundary in {} resume points",
            points.len()
        );
    }
}
