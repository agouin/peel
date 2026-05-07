//! Zstandard ([RFC 8478]) streaming decoder.
//!
//! Hand-rolled, pure-Rust implementation. Phase 8 of
//! `docs/PLAN_zstd_block_decoder.md` swapped this in as the production
//! path; the upstream `zstd` crate is now only a dev-dependency for
//! differential tests.
//!
//! # Coverage
//!
//! - Frame parsing: [`frame::parse_frame_header`] (§3.1.1.1.1),
//!   skippable-frame magic classification, and per-frame
//!   `frame_boundary` reporting for resume.
//! - Block layer: [`block::parse_block_header`] (§3.1.1.2),
//!   `Raw_Block`, `RLE_Block`, and `Compressed_Block` end-to-end.
//! - Compressed_Block pipeline: literals (§3.1.1.3 / §4.2),
//!   sequences (§3.1.1.4 / §4.2.2), and execution against a
//!   sliding window with the three repeat-offset slots
//!   (§3.1.1.5).
//! - Frame-level validation: XXH64 content-checksum verification
//!   (RFC 8478 §3.1.1) over decompressed output, and
//!   `Frame_Content_Size` cross-check at end-of-frame.
//! - Mid-frame resume: [`ZstdDecoder::decoder_state`] /
//!   [`resume::resume`] let the extractor checkpoint and restart at
//!   every block boundary inside a frame; see [`resume`] for the
//!   wire format.
//!
//! # Out of round-one scope
//!
//! Custom dictionaries (`Dictionary_ID != 0`) and `windowLog > 27`
//! frames are rejected at frame-header parse time with a clean
//! `DecodeError::Read` rather than silently producing wrong output.
//!
//! [RFC 8478]: https://datatracker.ietf.org/doc/html/rfc8478
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
use crate::hash::xxh64::Xxh64;
use crate::types::ByteOffset;

pub mod bitstream;
pub mod block;
pub mod error;
pub mod frame;
pub mod fse;
pub mod huffman;
pub mod literals;
pub mod resume;
pub mod sequences;
pub mod window;

pub use resume::{resume, resume_factory};

/// Public alias for [`Decoder`] that follows the in-tree
/// `<Format>Decoder` naming convention used by the other decode
/// modules ([`crate::decode::lz4::Lz4Decoder`],
/// [`crate::decode::xz::XzDecoder`], etc.). Internal code continues
/// to use the shorter `Decoder` name.
pub use Decoder as ZstdDecoder;

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
/// thread the same way the other in-tree decoders can.
pub struct Decoder {
    /// Wrapped source, dropped on terminal error or clean EOF so
    /// further `decode_step` calls cheaply short-circuit.
    pub(crate) source: Option<Box<dyn Read + Send>>,
    /// State machine; see [`State`].
    pub(crate) state: State,
    /// High-water source-byte counter — what
    /// [`StreamingDecoder::bytes_consumed`] returns. Advanced only
    /// after a successful read; partial reads advance only by
    /// what was actually delivered.
    pub(crate) bytes_consumed: u64,
    /// Latest frame boundary observed, or `None` if no frame has
    /// completed yet. Updated atomically with each block-boundary
    /// stop (mid-frame) and end-of-frame transition.
    pub(crate) last_frame_boundary: Option<ByteOffset>,
    /// `true` between two consecutive blocks of the same frame —
    /// the only point at which a [`StreamingDecoder::decoder_state`]
    /// blob is meaningful. Cleared when entering or leaving a frame
    /// and at the top of each block read; set true after a block's
    /// payload has been fully consumed, written to the sink, and
    /// folded into the per-frame state. Mirrors `Lz4Decoder`'s
    /// `between_blocks` flag (`src/decode/lz4.rs`).
    pub(crate) between_blocks: bool,
    /// Reusable scratch for block payloads. Sized to the RFC's
    /// 128 KiB cap on first use; held thereafter to avoid per-block
    /// allocation in the hot loop.
    pub(crate) payload_buf: Vec<u8>,
    /// Reusable scratch for skippable-frame data so we don't
    /// allocate a fresh buffer on every step.
    pub(crate) skip_buf: Vec<u8>,
    /// Reusable scratch for one Compressed_Block's decompressed
    /// output. Sized lazily up to the per-frame
    /// `Block_Maximum_Decompressed_Size` cap and reused across
    /// blocks; we `clear()` it at the top of each block.
    pub(crate) block_out: Vec<u8>,
    /// Per-frame state — only set while decoding inside a
    /// regular frame. The contents reset when entering a new
    /// frame (`AwaitingMagic` → `InFrame`) and clear on
    /// `finish_frame`. See [`FrameDecodeState`].
    pub(crate) frame_state: Option<FrameDecodeState>,
}

/// Per-frame decoding state lifted out of the [`State`] enum so
/// the inner-block fast path can hold a `&mut` to it without
/// matching on the state every step. Initialized when entering
/// `InFrame` from `AwaitingMagic`; cleared on `finish_frame`.
#[derive(Debug)]
pub(crate) struct FrameDecodeState {
    /// Sliding ring buffer for back-references (RFC 8478
    /// §3.1.1.1.4 + §4.1.3). Sized to the frame's `window_size`,
    /// capped at 128 MiB.
    pub(crate) window: window::SlidingWindow,
    /// Three repeat-offset slots (RFC 8478 §3.1.1.5). Reset to
    /// the spec defaults `(1, 4, 8)` per frame.
    pub(crate) repeats: sequences::RepeatOffsets,
    /// Last Huffman tree decoded by a `Compressed_Literals_Block`,
    /// reused by `Treeless_Literals_Block`s in the same frame.
    pub(crate) prev_huffman: Option<huffman::HuffmanTree>,
    /// Last LL/OF/ML FSE tables, reused by sequence-section
    /// `Repeat_Mode` declarations in subsequent blocks.
    pub(crate) prev_seq_tables: sequences::PrevSequenceTables,
    /// Streaming XXH64 (seed = 0) over the *decompressed* bytes
    /// emitted from this frame. The trailing 4-byte checksum is
    /// verified against `xxh64.finalize() as u32` when
    /// `Content_Checksum_Flag` is set; otherwise the hasher is
    /// updated but never observed (its cost is a single
    /// `wrapping_mul` + `xor` per stripe — negligible compared to
    /// the per-byte sequence executor work).
    pub(crate) xxh64: Xxh64,
    /// Source-byte offset of this frame's leading magic. Diagnostic
    /// only — the resume blob carries it through round-trip but no
    /// decode logic depends on the value.
    pub(crate) frame_start_offset: u64,
}

impl FrameDecodeState {
    fn new(window_size: u64, frame_start_offset: u64) -> Result<Self, ZstdError> {
        Ok(Self {
            window: window::SlidingWindow::new(window_size)?,
            repeats: sequences::RepeatOffsets::default(),
            prev_huffman: None,
            prev_seq_tables: sequences::PrevSequenceTables::default(),
            xxh64: Xxh64::new(),
            frame_start_offset,
        })
    }
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
pub(crate) enum State {
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
            between_blocks: false,
            payload_buf: Vec::new(),
            skip_buf: Vec::new(),
            block_out: Vec::new(),
            frame_state: None,
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
        // End-of-frame is reachable via the regular factory at the
        // boundary offset — no decoder_state blob is needed past
        // this point.
        self.between_blocks = false;
        // Per-frame state (window, repeat slots, prior FSE/Huffman
        // tables) is scoped to a single frame: a `Repeat_Mode`
        // sequences-section in a *later* frame must not see the
        // current frame's tables.
        self.frame_state = None;
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
                                // The 4-byte magic was consumed by
                                // `read_magic_or_eof` above; the
                                // frame's first source byte sat at
                                // `bytes_consumed - 4`.
                                let frame_start_offset = self.bytes_consumed.saturating_sub(4);
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
                                // Allocate per-frame state. The
                                // window's capacity comes from
                                // `header.window_size` (already
                                // capped at 128 MiB by the frame
                                // parser). RFC 8478 §3.1.1.1.2
                                // permits a zero `Window_Size` for
                                // single-segment frames whose
                                // `Frame_Content_Size` is also 0
                                // (an empty payload — `zstd`
                                // emits these); clamp to 1 so
                                // `SlidingWindow`'s "non-empty
                                // ring" invariant holds. No
                                // back-references are possible in
                                // such a frame, so the extra byte
                                // is allocated but never touched.
                                let window_capacity = header.window_size.max(1);
                                self.frame_state = Some(FrameDecodeState::new(
                                    window_capacity,
                                    frame_start_offset,
                                )?);
                                self.state = State::InFrame {
                                    header,
                                    decoded_in_frame: 0,
                                };
                                // We're inside a frame now, but
                                // before the first block has been
                                // decoded — not a checkpointable
                                // restart point.
                                self.between_blocks = false;
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
                    // We're about to read the next block's header —
                    // any prior block's "between blocks" anchor is
                    // no longer the truth. Clear before any failure
                    // path can return without resetting it.
                    self.between_blocks = false;
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
                                .map_err(ZstdError::SinkIo)?;
                            // Append to the window so subsequent
                            // Compressed_Blocks in this frame can
                            // back-reference these bytes; also feed
                            // the same bytes into the XXH64 hasher
                            // for the optional content-checksum
                            // trailer.
                            let frame_state = self
                                .frame_state
                                .as_mut()
                                .expect("frame_state present in InFrame");
                            frame_state.window.append(&self.payload_buf[..n]);
                            frame_state.xxh64.update(&self.payload_buf[..n]);
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
                                .map_err(ZstdError::SinkIo)?;
                            let frame_state = self
                                .frame_state
                                .as_mut()
                                .expect("frame_state present in InFrame");
                            frame_state.window.append(&self.payload_buf[..n]);
                            frame_state.xxh64.update(&self.payload_buf[..n]);
                            decoded = decoded.saturating_add(n as u64);
                        }
                        BlockType::Compressed => {
                            // Read the entire compressed block
                            // payload into the scratch buffer.
                            let n = bh.block_size as usize;
                            if self.payload_buf.len() < n {
                                self.payload_buf.resize(n, 0);
                            }
                            let source = self.source.as_mut().expect("source present");
                            read_exact_into(
                                source.as_mut(),
                                &mut self.bytes_consumed,
                                &mut self.payload_buf[..n],
                                "compressed block payload",
                            )?;
                            let payload = &self.payload_buf[..n];
                            let frame_state = self
                                .frame_state
                                .as_mut()
                                .expect("frame_state present in InFrame");

                            // 1. Literals section (RFC 8478 §3.1.1.3).
                            let lh = literals::parse_literals_header(payload)?;
                            let lit_start = usize::from(lh.header_size);
                            let lit_end = lit_start.checked_add(lh.payload_size as usize).ok_or(
                                ZstdError::MalformedFrameHeader(
                                    "literals section spans past block",
                                ),
                            )?;
                            if lit_end > payload.len() {
                                return Err(ZstdError::MalformedFrameHeader(
                                    "literals section spans past block",
                                ));
                            }
                            let literals_buf = literals::decode_literals(
                                &lh,
                                &payload[lit_start..lit_end],
                                &mut frame_state.prev_huffman,
                            )?;

                            // 2. Sequences section (RFC 8478 §3.1.1.4).
                            let seq_section = &payload[lit_end..];
                            let seqs = sequences::decode_sequences(
                                seq_section,
                                &mut frame_state.prev_seq_tables,
                            )?;

                            // 3. Execute: walk sequences, materialize
                            //    bytes into `block_out`, update window
                            //    and repeat slots. The Block_Maximum_
                            //    Decompressed_Size cap (RFC §3.1.1.2:
                            //    min(Window_Size, 128 KiB)) is enforced
                            //    inside `execute` *up front* — checking
                            //    after the fact would be too late, the
                            //    underlying `out.reserve` could already
                            //    have OOMed on a malformed sequences
                            //    section.
                            let decompressed_cap =
                                u64::from(BLOCK_MAX_SIZE).min(frame_header.window_size);
                            self.block_out.clear();
                            sequences::execute(
                                &seqs,
                                &literals_buf,
                                &mut frame_state.window,
                                &mut frame_state.repeats,
                                &mut self.block_out,
                                decompressed_cap,
                            )?;

                            sink.write_all(&self.block_out).map_err(ZstdError::SinkIo)?;
                            // The sequence executor already appended
                            // these bytes to `frame_state.window`;
                            // now also feed them into the XXH64
                            // hasher for the content-checksum trailer.
                            frame_state.xxh64.update(&self.block_out);
                            decoded = decoded.saturating_add(self.block_out.len() as u64);
                        }
                    }

                    if bh.last_block {
                        // Frame_Content_Size cross-check fires
                        // unconditionally — the trailing content
                        // checksum (if present) is a separate
                        // integrity layer over the *bytes* and
                        // doesn't subsume the *count* check.
                        if let Some(fcs) = frame_header.fcs {
                            if fcs != decoded {
                                return Err(ZstdError::FrameContentSizeMismatch {
                                    declared: fcs,
                                    actual: decoded,
                                });
                            }
                        }
                        if frame_header.has_checksum {
                            // The 4-byte trailer is still owed; this
                            // is not a clean restart point. Defer
                            // last_frame_boundary advance until
                            // `finish_frame` runs after the trailer
                            // verifies.
                            self.state = State::AwaitingContentChecksum {
                                decoded_in_frame: decoded,
                            };
                        } else {
                            self.finish_frame();
                        }
                    } else {
                        // Mid-frame block boundary: this is a
                        // restart-eligible point as long as the
                        // resume blob is paired with the offset.
                        // Mirror lz4's discipline (`src/decode/lz4.rs`):
                        // stamp `last_frame_boundary` *after* every
                        // byte of the block has been consumed and
                        // every per-frame side-effect (window,
                        // repeat slots, prior FSE/Huffman tables,
                        // XXH64) has been applied. The
                        // `between_blocks` flag is what gates
                        // [`Self::decoder_state`] returning
                        // `Some(blob)` for this checkpoint.
                        self.last_frame_boundary = Some(ByteOffset::new(self.bytes_consumed));
                        self.between_blocks = true;
                        self.state = State::InFrame {
                            header: frame_header,
                            decoded_in_frame: decoded,
                        };
                    }
                    return Ok(DecodeStatus::MoreData);
                }

                State::AwaitingContentChecksum { decoded_in_frame } => {
                    let _ = decoded_in_frame;
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
                    let expected = u32::from_le_bytes(buf);
                    // The XXH64 hasher lives in `frame_state` and
                    // was fed every decompressed byte. Take it out
                    // (`finalize` consumes), compute the digest,
                    // and compare its low 32 bits to the trailer.
                    let frame_state = self
                        .frame_state
                        .as_mut()
                        .expect("frame_state present in AwaitingContentChecksum");
                    // Take the hasher out (`finalize` consumes by
                    // value); a fresh default is left in place
                    // since the frame is about to end via
                    // `finish_frame` anyway.
                    let hasher = std::mem::take(&mut frame_state.xxh64);
                    let got = (hasher.finalize() & 0xFFFF_FFFF) as u32;
                    if got != expected {
                        return Err(ZstdError::ChecksumMismatch { expected, got });
                    }
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

    fn set_source_start_offset(&mut self, offset: u64) {
        // Idempotent for the resume-factory path: `resume::resume`
        // already seeds `bytes_consumed = start_offset`, so calling
        // here with the same offset is a no-op. The regular factory
        // leaves the counter at zero; this is what aligns it with the
        // global source offset on resume from a frame end (no decoder
        // state blob saved at frame boundaries).
        self.bytes_consumed = offset;
    }

    fn decoder_state_into(&self, out: &mut Vec<u8>) -> bool {
        // The blob is meaningful only when paused at a block
        // boundary inside a regular frame. Between frames the
        // regular factory works (no state needed); mid-block /
        // mid-header / mid-skippable have no clean restart point.
        // The `between_blocks` flag, set just after a block's
        // payload has been consumed and committed, is the gate.
        match resume::capture(self) {
            Some(state) => {
                // The zstd resume blob is small (≤ ~150 B), so
                // building a temporary Vec via the existing
                // `serialize()` and copying it into `out` is
                // immaterial perf-wise. xz_native is the format
                // that justifies a fully direct-write path
                // (`PLAN_checkpoint_blob_dedup.md` Phase 2).
                out.extend_from_slice(&state.serialize());
                true
            }
            None => false,
        }
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

    /// A malformed `Compressed_Block` (zero-byte payload, but a
    /// Compressed type tag) must surface a clean error rather than
    /// panicking. This regressed the Phase-1 placeholder; Phase 5
    /// hooks the real decoder up but garbage-in still produces
    /// `Err`.
    #[test]
    fn malformed_compressed_block_surfaces_clean_error() {
        let frame = build_frame(0, false, &[compressed(true, &[])]);
        let mut decoder = Decoder::new(Box::new(Cursor::new(frame))).expect("construct");
        let mut sink = Vec::new();
        loop {
            match decoder.decode_step(&mut sink) {
                Ok(DecodeStatus::Eof) => panic!("expected error"),
                Ok(DecodeStatus::MoreData) => continue,
                Err(DecodeError::Read { .. }) => break,
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

    /// Failing sink propagates as `DecodeError::Write`, distinct from
    /// source-IO errors. The extractor's
    /// `sink_error_surfaces_as_typed_error` test relies on this so it
    /// can recover the typed `SinkError` captured by its adapter.
    #[test]
    fn sink_failure_propagates_as_write_error() {
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
            Err(DecodeError::Write(e)) => assert_eq!(e.kind(), io::ErrorKind::BrokenPipe),
            other => panic!("expected Write, got {other:?}"),
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

    // ---- Real-frame FSE / Huffman validation -------------------
    //
    // Phase 4a/4b validation: compress a real payload via libzstd,
    // walk the resulting frame through our existing parsers, and
    // exercise the literals decoder against bytes the spike (or
    // hand-built fixtures) couldn't reach. Locks the FSE
    // distribution parser, FseTable::build, and parse_fse_weights
    // against ground truth before sequences.rs lands.
    //
    // The literals section regenerates *N* bytes of literal data
    // that the sequences section will later interleave with
    // back-references — the decoded literals aren't directly a
    // prefix of the decompressed output. So we check structural
    // properties (length matches `regenerated_size`, decode
    // returned Ok), not byte-for-byte equality with libzstd's
    // decompressed output.

    /// Walk a libzstd-produced frame, run our literals decoder on
    /// every Compressed_Block's literals section, and assert the
    /// regenerated_size invariant.
    ///
    /// `at_least_one_fse_huffman` is set if the test encountered
    /// (and successfully decoded) at least one
    /// Compressed_Literals_Block whose tree description used
    /// FSE-coded weights — the path the Phase 4b half-commit
    /// lit up.
    fn validate_literals_in_frame(payload: &[u8], at_least_one_fse_huffman: &mut bool) {
        use self::block::{parse_block_header, BlockType, BLOCK_HEADER_LEN};
        use self::frame::parse_frame_header;
        use self::literals::{decode_literals, parse_literals_header, LiteralsBlockType};

        let compressed = ::zstd::encode_all(payload, 3).expect("encode");
        let fh = parse_frame_header(&compressed).expect("frame header");
        let mut p = fh.header_size;
        let mut prev_huffman = None;
        loop {
            let bh = parse_block_header(&compressed[p..]).expect("block header");
            p += BLOCK_HEADER_LEN;
            if let BlockType::Compressed = bh.block_type {
                let block_payload = &compressed[p..p + bh.block_size as usize];
                let lh = parse_literals_header(block_payload).expect("literals header");
                let lit_payload = &block_payload[usize::from(lh.header_size)
                    ..usize::from(lh.header_size) + lh.payload_size as usize];
                if matches!(lh.block_type, LiteralsBlockType::Compressed) {
                    // Was it FSE-coded? First byte of the
                    // literals payload is the tree-description
                    // header byte.
                    if !lit_payload.is_empty() && lit_payload[0] < 128 {
                        *at_least_one_fse_huffman = true;
                    }
                }
                if matches!(
                    lh.block_type,
                    LiteralsBlockType::Compressed | LiteralsBlockType::Treeless
                ) {
                    let out = decode_literals(&lh, lit_payload, &mut prev_huffman)
                        .expect("decode literals");
                    assert_eq!(
                        out.len(),
                        lh.regenerated_size as usize,
                        "regenerated_size mismatch (lh={lh:?})",
                    );
                }
            }
            p += bh.payload_on_wire() as usize;
            if bh.last_block {
                break;
            }
        }
    }

    /// Synthetic compressible payload with a wide alphabet —
    /// reliably routes through Compressed_Literals_Block at
    /// level 3.
    ///
    /// Pure-random bytes don't help: libzstd correctly notices
    /// they don't compress and routes to Raw_Literals_Block. So
    /// we cycle through all 256 byte values in a structured
    /// pattern that has both repetition (compressible) and a
    /// large alphabet (non-trivial Huffman tree).
    fn wide_alphabet_compressible_payload(len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            // Interleave a structured cycle of bytes 0..256 with
            // a repeating header sequence. The header gives the
            // sequences-section back-references something to
            // match against; the cycle gives the literals section
            // a wide alphabet.
            let block = i / 17;
            let byte = match i % 17 {
                0 => b'<',
                1 => b'r',
                2 => b'>',
                _ => ((block + i) % 256) as u8,
            };
            out.push(byte);
        }
        out
    }

    /// End-to-end: Compressed_Literals_Block whose Huffman tree
    /// description uses FSE-coded weights (RFC §4.2.1.2). At
    /// `zstd -3`, the wide-alphabet fixtures below reliably route
    /// through this path, so this test exercises the entire
    /// distribution-parser → table-builder → 2-state weight-stream
    /// decoder → implicit-weight reconstruction pipeline against
    /// libzstd ground truth.
    #[test]
    fn fse_huffman_weights_decode_against_libzstd_frames() {
        let mut hit_fse = false;
        for len in [8 * 1024, 32 * 1024, 128 * 1024] {
            let payload = wide_alphabet_compressible_payload(len);
            validate_literals_in_frame(&payload, &mut hit_fse);
        }
        assert!(
            hit_fse,
            "fixture inputs did not produce any FSE-coded Huffman weight section",
        );
    }

    /// Text-payload counterpart: locks the literals decoder
    /// against libzstd output for prose-like input. Whether the
    /// encoder picks direct-mode or FSE-mode weights depends on
    /// alphabet width; both paths must succeed.
    #[test]
    fn literals_decode_against_libzstd_text_frames() {
        let payload: Vec<u8> = b"the quick brown fox jumps over the lazy dog. \
            pack my box with five dozen liquor jugs. how vexingly quick \
            daft zebras jump! sphinx of black quartz, judge my vow. "
            .repeat(200);
        let mut hit_fse = false;
        validate_literals_in_frame(&payload, &mut hit_fse);
        let _ = hit_fse;
    }

    // ---- Phase 5 end-to-end differential -----------------------
    //
    // Now that Compressed_Block is wired through decode_step, the
    // streaming decoder should round-trip arbitrary payloads
    // byte-identical to the upstream `zstd` crate. These tests
    // are the Phase 5 exit criterion (per
    // `docs/PLAN_zstd_block_decoder.md`).

    fn round_trip_via_native(payload: &[u8], level: i32) {
        let compressed = ::zstd::encode_all(payload, level).expect("encode");
        let mut decoder = Decoder::new(Box::new(Cursor::new(compressed))).expect("construct");
        let mut sink = Vec::with_capacity(payload.len());
        loop {
            let status = decoder.decode_step(&mut sink).expect("step");
            if status == DecodeStatus::Eof {
                break;
            }
        }
        if sink != payload {
            let n = sink.len().min(64);
            let p = payload.len().min(64);
            panic!(
                "native decode mismatch (level {level}): expected {} bytes, got {}; first bytes expected={:02x?}, got={:02x?}",
                payload.len(),
                sink.len(),
                &payload[..p],
                &sink[..n]
            );
        }
    }

    #[test]
    fn round_trip_text_payload_levels_1_3_9() {
        let payload: Vec<u8> = b"the quick brown fox jumps over the lazy dog. \
            pack my box with five dozen liquor jugs. how vexingly quick \
            daft zebras jump! sphinx of black quartz, judge my vow. "
            .repeat(200);
        for level in [1, 3, 9] {
            round_trip_via_native(&payload, level);
        }
    }

    #[test]
    fn round_trip_wide_alphabet_payload_levels_1_3_9() {
        for size in [4 * 1024, 32 * 1024, 128 * 1024] {
            let payload = wide_alphabet_compressible_payload(size);
            for level in [1, 3, 9] {
                round_trip_via_native(&payload, level);
            }
        }
    }

    #[test]
    fn round_trip_random_short_payloads() {
        // Deterministic LCG so we don't pull in a dev-dep RNG.
        // Keep these short; this catches edge cases like 0-byte
        // and 1-byte payloads, single-block frames, and small
        // sequence sections.
        let mut state: u64 = 0xDEAD_BEEF_CAFE_F00D;
        for trial in 0..16 {
            // Mix in `trial` so each iteration uses a fresh seed.
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1442695040888963407 ^ trial);
            let len = (state as usize) & 0x1FFF; // 0..=8191
            let mut payload = vec![0u8; len];
            for byte in payload.iter_mut() {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1442695040888963407);
                *byte = (state >> 33) as u8;
            }
            round_trip_via_native(&payload, 3);
        }
    }

    #[test]
    fn round_trip_small_repetitive_payload_uses_back_references() {
        // A short repetitive payload that the encoder will emit
        // primarily via back-references — exercises the executor's
        // overlap path and repeat-offset slots.
        let payload = b"abcdefgh".repeat(64); // 512 bytes, period 8
        round_trip_via_native(&payload, 3);
    }

    #[test]
    fn round_trip_multi_block_frame() {
        // Force several Compressed_Blocks in one frame: the
        // largest block decompressed-size is min(window_size, 128
        // KiB), so a > 128 KiB payload produces multiple blocks
        // and exercises cross-block back-references and
        // Repeat_Mode for the FSE tables.
        let payload: Vec<u8> = b"the quick brown fox jumps over the lazy dog. \
            pack my box with five dozen liquor jugs. how vexingly quick \
            daft zebras jump! sphinx of black quartz, judge my vow. "
            .repeat(2000); // ~290 KiB -> at least 3 blocks at default settings
        round_trip_via_native(&payload, 3);
    }

    #[test]
    fn round_trip_multi_frame_concatenation() {
        // Two separate frames concatenated. The decoder should
        // reset per-frame state (window, repeat slots, FSE tables,
        // Huffman tree) on the frame boundary and produce
        // byte-identical output to the upstream `zstd` crate's
        // `decode_all` (which handles multi-frame inputs).
        let payload_a = b"the quick brown fox jumps over the lazy dog".repeat(50);
        let payload_b = b"abcdefgh".repeat(64);
        let mut compressed = ::zstd::encode_all(&payload_a[..], 3).expect("encode a");
        compressed.extend_from_slice(&::zstd::encode_all(&payload_b[..], 3).expect("encode b"));

        let mut decoder = Decoder::new(Box::new(Cursor::new(compressed))).expect("construct");
        let mut sink = Vec::new();
        loop {
            let status = decoder.decode_step(&mut sink).expect("step");
            if status == DecodeStatus::Eof {
                break;
            }
        }
        let mut expected = payload_a.clone();
        expected.extend_from_slice(&payload_b);
        assert_eq!(sink, expected);
    }

    // ---- Phase 6 frame-level validation ------------------------
    //
    // Three integrity surfaces fire at end-of-frame:
    //   * XXH64 content-checksum trailer matches the low 32 bits
    //     of the hash over decompressed output (RFC 8478 §3.1.1).
    //   * Frame_Content_Size (when declared) matches the byte
    //     count we actually decoded.
    //   * `windowLog > 27` and non-zero `Dictionary_ID` are
    //     rejected at frame-header parse time (see frame.rs tests
    //     for the lower-level coverage).
    //
    // These tests construct deliberately broken frames and assert
    // that each surfaces a clean `DecodeError::Read` rather than
    // panicking or, worse, silently producing wrong output.

    /// Build a single-segment, checksum-bearing frame and run our
    /// decoder + libzstd over it; both must agree, and our hasher
    /// must accept the trailer. Goldens the wiring of `Xxh64`
    /// through every block type.
    #[test]
    fn frames_with_real_content_checksum_round_trip() {
        use std::io::Write;
        for size in [0usize, 1, 32, 1024, 16 * 1024, 256 * 1024] {
            let payload: Vec<u8> = (0..size).map(|i| (i * 31 + 7) as u8).collect();
            let mut frame = Vec::new();
            {
                let mut enc = ::zstd::Encoder::new(&mut frame, 3).expect("encoder");
                enc.include_checksum(true).expect("checksum on");
                enc.write_all(&payload).expect("write");
                enc.finish().expect("finish");
            }
            let (out, _dec) = decode_all(frame);
            assert_eq!(out, payload, "size={size}");
        }
    }

    /// A frame whose trailing checksum has been bit-flipped must
    /// surface a clean `ChecksumMismatch` (mapped to
    /// `DecodeError::Read`) rather than silently delivering the
    /// (correct) decompressed bytes. The decoder *also* still emits
    /// the bytes to the sink before failing — that's a deliberate
    /// streaming consequence — but the terminal step is `Err`, so
    /// callers won't accept the output as authoritative.
    #[test]
    fn corrupted_content_checksum_surfaces_error() {
        use std::io::Write;
        let payload = b"frame contents to be hashed";
        let mut frame = Vec::new();
        {
            let mut enc = ::zstd::Encoder::new(&mut frame, 3).expect("encoder");
            enc.include_checksum(true).expect("checksum on");
            enc.write_all(payload).expect("write");
            enc.finish().expect("finish");
        }
        // Flip a bit in the trailer.
        let last = frame.len() - 1;
        frame[last] ^= 0x01;

        let mut decoder = Decoder::new(Box::new(Cursor::new(frame))).expect("construct");
        let mut sink = Vec::new();
        let mut saw_error = false;
        loop {
            match decoder.decode_step(&mut sink) {
                Ok(DecodeStatus::MoreData) => continue,
                Ok(DecodeStatus::Eof) => break,
                Err(DecodeError::Read { source, .. }) => {
                    let msg = source.to_string();
                    assert!(msg.contains("content-checksum"), "msg: {msg}");
                    saw_error = true;
                    break;
                }
                Err(other) => panic!("unexpected error variant: {other:?}"),
            }
        }
        assert!(saw_error, "expected a checksum-mismatch error");
    }

    /// A hand-built single-segment frame that declares
    /// `Frame_Content_Size = 100` but only emits 4 bytes must
    /// surface `FrameContentSizeMismatch`, even with no checksum
    /// involved. Keeps the FCS check independent of XXH64.
    #[test]
    fn declared_fcs_smaller_than_decoded_surfaces_error() {
        let mut frame = build_frame(100, false, &[raw(true, b"abcd")]);
        // build_frame puts content_size=100 in the FHD-tail FCS;
        // the body emits only 4 bytes ("abcd") — mismatch.
        let mut decoder =
            Decoder::new(Box::new(Cursor::new(std::mem::take(&mut frame)))).expect("construct");
        let mut sink = Vec::new();
        loop {
            match decoder.decode_step(&mut sink) {
                Ok(DecodeStatus::MoreData) => continue,
                Ok(DecodeStatus::Eof) => panic!("expected error before EOF"),
                Err(DecodeError::Read { source, .. }) => {
                    let msg = source.to_string();
                    assert!(msg.contains("Frame_Content_Size"), "msg: {msg}");
                    break;
                }
                Err(other) => panic!("unexpected error variant: {other:?}"),
            }
        }
    }

    /// Frame_Content_Size mismatch fires even when the frame
    /// declares a content checksum: the FCS check happens
    /// *before* the checksum trailer is even read. (Bumping the
    /// checksum out of the way makes the test reproducible
    /// against a hand-crafted frame, where computing a real
    /// XXH64 trailer would otherwise be needed.)
    #[test]
    fn declared_fcs_mismatch_takes_precedence_over_checksum() {
        // build_frame with has_checksum=true appends 4 zero bytes
        // as a placeholder trailer — but since the FCS check
        // fires before the trailer is read, we never get to it.
        let frame = build_frame(99, true, &[raw(true, b"abcd")]);
        let mut decoder = Decoder::new(Box::new(Cursor::new(frame))).expect("construct");
        let mut sink = Vec::new();
        loop {
            match decoder.decode_step(&mut sink) {
                Ok(DecodeStatus::MoreData) => continue,
                Ok(DecodeStatus::Eof) => panic!("expected error before EOF"),
                Err(DecodeError::Read { source, .. }) => {
                    assert!(
                        source.to_string().contains("Frame_Content_Size"),
                        "msg: {source}",
                    );
                    break;
                }
                Err(other) => panic!("unexpected error variant: {other:?}"),
            }
        }
    }

    /// `windowLog > 27` (the round-one cap) is rejected at frame
    /// header parse time — before any block is consumed — and
    /// surfaces as `UnsupportedFrameFeature`.
    #[test]
    fn oversized_window_log_rejected_at_frame_parse() {
        // Frame header: !single_segment, fcs_flag=0, dict_id=0.
        // FHD = 0x00. WD: exponent=18 -> windowLog=28 > 27.
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&frame::ZSTD_FRAME_MAGIC.to_le_bytes());
        hdr.push(0x00);
        hdr.push(18 << 3);
        let mut decoder = Decoder::new(Box::new(Cursor::new(hdr))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { source, .. }) => {
                let msg = source.to_string();
                assert!(msg.contains("windowLog > 27"), "msg: {msg}");
            }
            other => panic!("expected unsupported-feature error, got {other:?}"),
        }
    }

    /// Non-zero Dictionary_ID is rejected at frame-header parse time
    /// (custom dictionaries are out of round-one scope).
    #[test]
    fn non_zero_dict_id_rejected_at_frame_parse() {
        // FHD: dict_id_flag=1 (1B DID), single_segment=1, fcs_flag=3.
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&frame::ZSTD_FRAME_MAGIC.to_le_bytes());
        hdr.push(0b1110_0001);
        hdr.push(0x42); // DID=0x42
        hdr.extend_from_slice(&16u64.to_le_bytes());
        let mut decoder = Decoder::new(Box::new(Cursor::new(hdr))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { source, .. }) => {
                let msg = source.to_string();
                assert!(msg.contains("Dictionary_ID"), "msg: {msg}");
            }
            other => panic!("expected unsupported-feature error, got {other:?}"),
        }
    }

    // ---- Phase 7 decoder_state / resume ------------------------
    //
    // The Phase-7 wire format and `resume` constructor are
    // exercised here at the StreamingDecoder boundary: a clean run
    // emits a stream of mid-frame `decoder_state` blobs, each of
    // which must reconstruct a decoder that produces the suffix of
    // the plaintext byte-identically.

    /// Helper: drive the decoder through the bytes after `start`,
    /// resumed from `blob`, and collect the suffix. Any error
    /// surfaces as a panic — the test bodies want a single failure
    /// point per assertion.
    fn drive_resume(combined: &[u8], start: u64, blob: &[u8]) -> Vec<u8> {
        let suffix = combined[start as usize..].to_vec();
        let mut decoder =
            resume::resume(Box::new(Cursor::new(suffix)), blob, start).expect("resume constructs");
        let mut out = Vec::new();
        loop {
            let status = decoder.decode_step(&mut out).expect("resume step");
            if status == DecodeStatus::Eof {
                break;
            }
        }
        out
    }

    /// Decode-state is `None` at every step *before* the first block
    /// has been consumed (and at end-of-frame, where the regular
    /// factory works).
    #[test]
    fn decoder_state_is_none_between_frames_and_pre_block() {
        let payload = b"frame contents".repeat(8); // small enough to fit in a single block
        let frame = ::zstd::encode_all(payload.as_slice(), 3).expect("encode");
        let mut decoder = Decoder::new(Box::new(Cursor::new(frame))).expect("construct");
        let mut sink = Vec::new();
        // First step pulls the frame magic + header — still pre-block.
        let status = decoder.decode_step(&mut sink).expect("step 1");
        assert_eq!(status, DecodeStatus::MoreData);
        assert!(
            decoder.decoder_state().is_none(),
            "pre-block in-frame state must not be checkpointable",
        );
        // Drain to EOF and confirm the post-EOF state is also None.
        loop {
            if decoder.decode_step(&mut sink).expect("drain") == DecodeStatus::Eof {
                break;
            }
        }
        assert!(decoder.decoder_state().is_none(), "post-EOF state is None");
    }

    /// Round-trip a multi-block frame's resume blobs: every mid-frame
    /// boundary is a valid restart point, byte-identical.
    #[test]
    fn decoder_state_blob_resumes_byte_identically_at_every_block() {
        // Generate a payload large enough to force several blocks.
        let payload: Vec<u8> = b"the quick brown fox jumps over the lazy dog. \
            pack my box with five dozen liquor jugs. how vexingly quick \
            daft zebras jump! sphinx of black quartz, judge my vow. "
            .repeat(2000); // ~290 KiB — at level 3 yields multiple blocks
        let combined = ::zstd::encode_all(payload.as_slice(), 3).expect("encode");

        // Walk a clean run, capturing (offset, blob, decoded_so_far)
        // at every step where decoder_state() is Some.
        let mut decoder = Decoder::new(Box::new(Cursor::new(combined.clone()))).expect("construct");
        let mut clean_sink = Vec::new();
        let mut checkpoints: Vec<(u64, Vec<u8>, usize)> = Vec::new();
        loop {
            let status = decoder.decode_step(&mut clean_sink).expect("clean step");
            if let Some(blob) = decoder.decoder_state() {
                let offset = decoder
                    .frame_boundary()
                    .expect("frame_boundary set with state")
                    .get();
                checkpoints.push((offset, blob, clean_sink.len()));
            }
            if status == DecodeStatus::Eof {
                break;
            }
        }
        assert_eq!(clean_sink, payload);
        assert!(
            checkpoints.len() >= 2,
            "expected several mid-frame checkpoints, got {}",
            checkpoints.len(),
        );

        // For each checkpoint: resume from the suffix and the blob,
        // and verify the output equals the plaintext suffix from
        // `decoded_so_far`.
        for (i, (offset, blob, decoded_so_far)) in checkpoints.iter().enumerate() {
            let got = drive_resume(&combined, *offset, blob);
            let expected = &payload[*decoded_so_far..];
            assert_eq!(
                got.as_slice(),
                expected,
                "checkpoint #{i} (offset {offset}, decoded_so_far {decoded_so_far}) \
                 resume produced {} bytes vs expected {}",
                got.len(),
                expected.len(),
            );
        }
    }

    /// Phase-7 exit criterion: the lz4-style restart-point property
    /// holds for the new decoder. Mirrors
    /// `decode::zstd::tests::frame_boundary_property_is_a_valid_restart_point`
    /// but exercises mid-frame boundaries too — every observed
    /// `frame_boundary` paired with its `decoder_state` blob (or
    /// the regular factory if `decoder_state` is `None`) reconstructs
    /// a decoder that produces the plaintext suffix byte-identically.
    #[test]
    fn frame_boundary_property_is_a_valid_restart_point() {
        let mut state: u64 = 0x00C0_FFEE_BEEF;
        for trial in 0..6u64 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1442695040888963407 ^ trial);
            // Vary length to mix single-block and multi-block frames.
            let len = (state as usize) & 0x3FFFF; // up to ~256 KiB
            let mut payload = vec![0u8; len];
            for byte in payload.iter_mut() {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1442695040888963407);
                *byte = (state >> 33) as u8;
            }
            let combined = ::zstd::encode_all(payload.as_slice(), 3).expect("encode");

            let mut decoder =
                Decoder::new(Box::new(Cursor::new(combined.clone()))).expect("construct");
            let mut clean_sink = Vec::new();
            let mut prior_boundary = decoder.frame_boundary();
            let mut boundaries: Vec<(u64, Option<Vec<u8>>, usize)> = Vec::new();
            loop {
                let status = decoder.decode_step(&mut clean_sink).expect("step");
                let now = decoder.frame_boundary();
                if now != prior_boundary {
                    boundaries.push((
                        now.expect("just observed").get(),
                        decoder.decoder_state(),
                        clean_sink.len(),
                    ));
                    prior_boundary = now;
                }
                if status == DecodeStatus::Eof {
                    break;
                }
            }
            assert_eq!(clean_sink, payload, "trial {trial}: clean run mismatch");

            for (i, (offset, blob, decoded_so_far)) in boundaries.iter().enumerate() {
                let suffix_compressed = combined[*offset as usize..].to_vec();
                let expected = &payload[*decoded_so_far..];
                let got: Vec<u8> = match blob {
                    Some(b) => drive_resume(&combined, *offset, b),
                    None => {
                        // End-of-frame boundary: regular factory works.
                        if suffix_compressed.is_empty() {
                            assert_eq!(*decoded_so_far, payload.len());
                            continue;
                        }
                        let mut d = Decoder::new(Box::new(Cursor::new(suffix_compressed)))
                            .expect("restart construct");
                        let mut out = Vec::new();
                        loop {
                            if d.decode_step(&mut out).expect("restart step") == DecodeStatus::Eof {
                                break;
                            }
                        }
                        out
                    }
                };
                assert_eq!(
                    got.as_slice(),
                    expected,
                    "trial {trial} boundary #{i} (offset {offset}, decoded_so_far {decoded_so_far})",
                );
            }
        }
    }

    /// A blob whose bytes are obviously not a Phase-7 envelope is
    /// rejected via [`DecodeError::Construct`] without panic.
    #[test]
    fn resume_rejects_malformed_blob() {
        let combined = ::zstd::encode_all(&b"abcdefg"[..], 3).expect("encode");
        // Bogus blob.
        let r = resume::resume(Box::new(Cursor::new(combined)), &[0u8; 4], 0);
        match r {
            Err(DecodeError::Construct(e)) => {
                assert!(e.to_string().contains("zstd resume"), "msg: {e}");
            }
            Err(other) => panic!("expected Construct error, got {other:?}"),
            Ok(_) => panic!("expected Construct error, got Ok(decoder)"),
        }
    }

    /// A frame with a content checksum: the XXH64 hasher state is
    /// captured by the blob, so resuming continues hashing from the
    /// last block boundary and the trailer still verifies.
    #[test]
    fn resume_preserves_content_checksum_state() {
        use std::io::Write as _;
        let payload: Vec<u8> = b"checksum check ".repeat(20_000);
        let mut frame = Vec::new();
        {
            let mut enc = ::zstd::Encoder::new(&mut frame, 3).expect("encoder");
            enc.include_checksum(true).expect("checksum on");
            enc.write_all(&payload).expect("write");
            enc.finish().expect("finish");
        }

        // Capture the first mid-frame blob.
        let mut decoder = Decoder::new(Box::new(Cursor::new(frame.clone()))).expect("construct");
        let mut sink = Vec::new();
        let (offset, blob, decoded_so_far) = loop {
            let status = decoder.decode_step(&mut sink).expect("step");
            if let Some(blob) = decoder.decoder_state() {
                break (
                    decoder.frame_boundary().expect("boundary").get(),
                    blob,
                    sink.len(),
                );
            }
            if status == DecodeStatus::Eof {
                panic!("expected at least one mid-frame checkpoint");
            }
        };

        // Resume with that blob and verify both: (a) suffix
        // produces the right plaintext, and (b) the checksum
        // trailer at end-of-frame is accepted (no error).
        let got = drive_resume(&frame, offset, &blob);
        assert_eq!(got, payload[decoded_so_far..]);
    }

    /// 500-fixture differential against `::zstd::encode_all` — Phase 6
    /// exit criterion. Each fixture is a deterministic LCG-generated
    /// payload of varied size, encoded at level 3 (the most common
    /// real-world setting), and decoded both by the upstream `zstd`
    /// crate and our hand-rolled path. Outputs must match
    /// byte-identically. Fast (~250 ms in debug) because each
    /// fixture is ≤ 8 KiB.
    #[test]
    fn differential_against_zstd_crate_500_fixtures() {
        let mut state: u64 = 0xC0FF_EE00_DEAD_BEEF;
        for trial in 0..500u64 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1442695040888963407 ^ trial);
            let len = (state as usize) & 0x1FFF; // 0..=8191
            let mut payload = vec![0u8; len];
            for byte in payload.iter_mut() {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1442695040888963407);
                *byte = (state >> 33) as u8;
            }
            let frame = ::zstd::encode_all(payload.as_slice(), 3).expect("encode");
            let (out, _dec) = decode_all(frame);
            if out != payload {
                panic!(
                    "differential mismatch on trial {trial}, len={len}: \
                     expected {} bytes, got {}",
                    payload.len(),
                    out.len(),
                );
            }
        }
    }
}
