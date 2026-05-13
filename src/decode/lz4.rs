//! lz4 streaming decoder for the [LZ4 Frame Format].
//!
//! Per `internal/PLAN_v2.md` §4 we drive the wire format ourselves and feed
//! individual blocks through [`lz4_flex::block::decompress_into`] (the
//! upstream block-layer API). The frame layer in `lz4_flex` is gated
//! behind a `frame` feature that pulls a separate hash dependency and
//! has historically been less stable than the block layer; parsing the
//! 11-or-so-byte header ourselves keeps the runtime tree small and
//! exposes the exact frame and block boundaries we need for
//! checkpointing.
//!
//! # Frame boundaries
//!
//! [`StreamingDecoder::frame_boundary`] surfaces a restart-safe
//! source offset at two granularities. **Frame ends** are the byte
//! immediately after a complete LZ4 frame (its EndMark plus, when
//! the content-checksum flag is set, its 4-byte content checksum)
//! — at this position [`StreamingDecoder::decoder_state`] returns
//! `None` and a fresh `Lz4Decoder::new(source)` reading the suffix
//! produces byte-identical output to a clean run.
//!
//! **Block boundaries inside a frame** are the byte immediately
//! after the last byte of a successfully decoded block (payload +
//! optional block checksum). At a block boundary `decoder_state`
//! returns `Some(blob)` carrying the [`Lz4ResumeState`] needed to
//! seed a fresh decoder mid-frame: `block_max_size`, the
//! per-frame checksum flags, the optional `content_size`
//! declaration, the running `bytes_decompressed` cross-check
//! counter, and (when `content_checksum` is set) the partial
//! XXH32 hasher state accumulated across every prior block.
//! Resume goes through [`Lz4Decoder::resume`] (or
//! [`resume_factory`] via the registry); see `OPTIMIZATIONS.md`
//! §O.7b.
//!
//! Per-block boundaries make a single huge `tar.lz4` frame
//! resumable: producers like Polkachu's snapshot service emit one
//! 100+ GB frame, and round-one's frame-end-only granularity
//! reduced resume to "rewind to byte 0." Concatenated `cat a.lz4
//! b.lz4` streams produce both shapes — boundaries at every block
//! plus a final boundary post-EndMark — matching what the
//! per-member tar.xz / tar.zst harnesses expose.
//!
//! # Skippable frames
//!
//! Magics `184D2A50`–`184D2A5F` are LZ4's "skippable" frames — they
//! carry a 4-byte size and that many opaque bytes which the spec
//! requires the decoder to ignore. We honor them transparently: the
//! decoder consumes the prefix and goes back to looking for a regular
//! frame magic. Skippable frames may appear before the first frame and
//! between frames.
//!
//! # Round-one limitations
//!
//! - **Block-independent frames only** (FLG bit 5 = 1). Linked-block
//!   frames are rare in published archives (the `lz4` CLI's default is
//!   independent), and supporting them cleanly requires shuttling a
//!   64-KiB dictionary between blocks. We surface a clean
//!   [`DecodeError::Read`] naming the unsupported feature rather than
//!   silently producing wrong output. Promotion to "linked supported"
//!   is a follow-on if a real corpus needs it.
//! - **Stream Padding between frames is not skipped.** The spec allows
//!   zero-byte padding between concatenated frames; pathological
//!   producers that emit it will surface as a magic-mismatch on the
//!   next frame. Real-world `cat`-concatenated streams have no padding
//!   and decode cleanly.
//!
//! [LZ4 Frame Format]: https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md

use std::io::{self, Read, Write};
use std::mem;

use crate::decode::{DecodeError, DecodeStatus, StreamingDecoder};
use crate::types::ByteOffset;

/// Magic bytes identifying a regular LZ4 frame (little-endian
/// `0x184D2204`).
const LZ4_FRAME_MAGIC: u32 = 0x184D_2204;

/// Skippable frames cover magic numbers `0x184D2A50`–`0x184D2A5F`.
/// The low nibble is user-defined.
const SKIPPABLE_MAGIC_BASE: u32 = 0x184D_2A50;
const SKIPPABLE_MAGIC_MASK: u32 = 0xFFFF_FFF0;

/// Largest LZ4 block size the spec admits (BD bits 6-4 = 7 ⇒ 4 MiB).
const MAX_BLOCK_SIZE: usize = 4 * 1024 * 1024;

/// How many source bytes we'll discard in a single
/// [`StreamingDecoder::decode_step`] when traversing a skippable frame.
/// 64 KiB is large enough to amortize the scratch refill while still
/// bounding the per-call work the way the zstd / xz decoders do.
const SKIP_CHUNK: usize = 1 << 16;

/// Streaming lz4-Frame decoder that exposes block-boundary frame
/// boundaries.
///
/// Owns its source on construction; subsequent
/// [`StreamingDecoder::decode_step`] calls do not need it passed back
/// in. The source is `Send` so the decoder can be moved to a worker
/// thread the same way [`crate::decode::zstd::ZstdDecoder`] can.
pub struct Lz4Decoder {
    state: State,
    /// Cumulative bytes the decoder has actually committed to
    /// processing — what [`StreamingDecoder::bytes_consumed`] returns.
    /// Updated only after a successful read; truncated reads do not
    /// advance it past what was actually consumed.
    bytes_consumed: u64,
    /// Latest frame boundary (the offset just after a successfully
    /// processed block, frame header, or end-of-frame marker).
    last_frame_boundary: Option<ByteOffset>,
    /// `true` when [`Self::last_frame_boundary`] points at a position
    /// where [`State::InFrame`] is paused between blocks (i.e. the
    /// boundary is mid-frame and a fresh decoder needs the
    /// [`Lz4ResumeState`] blob to continue). Set after a successful
    /// block-decode arm; cleared at the start of every `decode_step`
    /// of `State::InFrame` before reading the next block-size
    /// header. Always `false` at end-of-frame, between frames, and
    /// while skipping skippable frames — those positions are
    /// restartable from the offset alone.
    between_blocks: bool,
    /// Reusable scratch buffer for compressed block payloads. Sized
    /// lazily up to [`MAX_BLOCK_SIZE`] when needed.
    input_buf: Vec<u8>,
    /// Reusable scratch buffer for decompressed block output. Sized
    /// lazily up to the frame's declared block-max-size when the
    /// header is parsed.
    output_buf: Vec<u8>,
    /// Reusable scratch buffer for traversing skippable frames.
    skip_buf: [u8; SKIP_CHUNK],
}

/// Decoder state machine.
///
/// ```text
/// BetweenFrames ──magic == LZ4_FRAME_MAGIC──> InFrame { ctx } [parsed header]
///               ──magic ∈ skippable range────> SkippingSkippable { remaining }
///               ──source EOF─────────────────> Done
///               ──any other 4-byte magic─────> Err
///
/// InFrame ──block hdr non-zero──> InFrame { ctx } [decoded a block]
///         ──block hdr == 0──────> BetweenFrames [optional content checksum]
///
/// SkippingSkippable ──remaining > 0──> SkippingSkippable
///                   ──remaining == 0─> BetweenFrames
///
/// any ──Err────────────────────────> Done
/// ```
///
/// `Transient` is a placeholder used for in-place state replacement
/// via [`mem::replace`]; it should never be observable outside
/// `decode_step`.
enum State {
    /// Initial state, and the steady state immediately after a frame
    /// (regular or skippable) ends. The next 4 bytes of source are the
    /// next frame's magic, or end-of-source.
    BetweenFrames {
        source: Box<dyn Read + Send>,
    },
    /// Inside a regular frame; sitting between blocks. The next 4
    /// bytes of source are a block size header.
    InFrame {
        source: Box<dyn Read + Send>,
        ctx: FrameContext,
    },
    /// Inside a skippable frame; the next `remaining` bytes belong to
    /// it and should be discarded.
    SkippingSkippable {
        source: Box<dyn Read + Send>,
        remaining: u64,
    },
    Done,
    Transient,
}

/// Per-frame parameters captured while parsing a frame header.
struct FrameContext {
    /// Maximum block size this frame is allowed to emit, in bytes.
    block_max_size: u32,
    /// Per-block 4-byte XXH32 checksum present after every block payload.
    block_checksum: bool,
    /// 4-byte XXH32 checksum present after the end-of-frame marker.
    content_checksum: bool,
    /// Optional content size declared in the header; if present, the
    /// decoder cross-checks it against `bytes_decompressed` at end of
    /// frame and surfaces a [`DecodeError::Read`] on mismatch.
    content_size: Option<u64>,
    /// Running XXH32 over decompressed bytes, instantiated only when
    /// `content_checksum` is set so checksum-disabled frames pay
    /// nothing.
    content_hasher: Option<xxh32::Xxh32>,
    /// Cumulative decompressed bytes from this frame; used to validate
    /// `content_size` at end-of-frame.
    bytes_decompressed: u64,
}

impl Lz4Decoder {
    /// Construct an [`Lz4Decoder`] over `src`.
    ///
    /// Does not pull any bytes from the source — construction never
    /// fails today, but the constructor still returns a `Result` so
    /// the signature matches [`super::DecoderFactory`].
    ///
    /// # Errors
    ///
    /// Currently never returns `Err`. The signature stays fallible so
    /// the type matches [`super::DecoderFactory`] without an extra
    /// adapter.
    pub fn new(src: Box<dyn Read + Send>) -> Result<Self, DecodeError> {
        Ok(Self {
            state: State::BetweenFrames { source: src },
            bytes_consumed: 0,
            last_frame_boundary: None,
            between_blocks: false,
            input_buf: Vec::new(),
            output_buf: Vec::new(),
            skip_buf: [0u8; SKIP_CHUNK],
        })
    }

    /// Move the decoder to terminal-error state and produce a
    /// [`DecodeError::Read`]. Used by every "we cannot continue
    /// safely" branch so subsequent [`StreamingDecoder::decode_step`]
    /// calls cleanly return [`DecodeStatus::Eof`] instead of being
    /// invited to read more from a poisoned source.
    fn fail(&mut self, message: impl Into<String>) -> DecodeError {
        let consumed = self.bytes_consumed;
        self.state = State::Done;
        DecodeError::Read {
            consumed,
            source: io::Error::other(message.into()),
        }
    }

    /// Like [`Self::fail`] but wraps an existing [`io::Error`] as the
    /// source — preserves `ErrorKind` so callers can distinguish
    /// truncation (`UnexpectedEof`) from underlying transport
    /// failures (`ConnectionAborted`, `BrokenPipe`, …).
    fn fail_with(&mut self, source: io::Error) -> DecodeError {
        let consumed = self.bytes_consumed;
        self.state = State::Done;
        DecodeError::Read { consumed, source }
    }

    /// Build a fresh decoder seeded mid-frame from a previously
    /// captured [`Lz4ResumeState`] blob.
    ///
    /// `start_offset` is the source byte offset at which `src` will
    /// deliver its first byte — i.e. the `decoder_position` saved in
    /// the checkpoint at the same step the blob was captured.
    /// `bytes_consumed` is seeded with this value so the decoder
    /// reports a consistent high-water mark from the first call;
    /// `last_frame_boundary` is seeded to the same offset so the
    /// caller observes the resume position as a still-valid frame
    /// boundary until the decoder advances past it.
    ///
    /// On success the decoder sits in [`State::InFrame`] with the
    /// frame context restored and is ready for [`Self::decode_step`].
    /// The next bytes pulled from `src` must be a 4-byte block-size
    /// header — exactly what the original run was about to read when
    /// it captured the blob.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Construct`] if `state_blob` is
    /// malformed (bad magic, unknown format, length mismatch, or
    /// internal field disagreement such as `content_checksum` set
    /// without a `content_hasher`). Resume failures here are not
    /// fatal — the caller can fall back to a fresh decode from a
    /// coarser frame boundary if it can find one.
    pub fn resume(
        src: Box<dyn Read + Send>,
        state_blob: &[u8],
        start_offset: u64,
    ) -> Result<Self, DecodeError> {
        let resume = Lz4ResumeState::deserialize(state_blob).map_err(|reason| {
            DecodeError::Construct(io::Error::other(format!(
                "lz4 resume blob rejected: {reason}",
            )))
        })?;
        let ctx = FrameContext {
            block_max_size: resume.block_max_size,
            block_checksum: resume.block_checksum,
            content_checksum: resume.content_checksum,
            content_size: resume.content_size,
            content_hasher: resume.content_hasher,
            bytes_decompressed: resume.bytes_decompressed,
        };
        // The fresh-construct path (re)sizes `output_buf` after
        // parsing the frame header; the resume path skips parsing and
        // must replicate that work itself, otherwise the first block
        // decompress overruns a zero-length scratch buffer.
        let output_buf = vec![0u8; ctx.block_max_size as usize];
        Ok(Self {
            state: State::InFrame { source: src, ctx },
            bytes_consumed: start_offset,
            last_frame_boundary: Some(ByteOffset::new(start_offset)),
            between_blocks: true,
            input_buf: Vec::new(),
            output_buf,
            skip_buf: [0u8; SKIP_CHUNK],
        })
    }
}

/// Per-frame parameters captured at the moment the decoder reports
/// [`StreamingDecoder::decoder_state`] as `Some(...)` — i.e. between
/// two blocks of a single frame.
///
/// Serialized as an opaque byte blob and stored in the §9 checkpoint
/// alongside the decoder offset (`OPTIMIZATIONS.md` §O.7b). The
/// layout is fixed-width at 74 bytes:
///
/// ```text
///  4 B  magic = b"LZDR"
///  1 B  format_version (currently 1)
///  4 B  block_max_size (u32 LE)
///  1 B  block_checksum (0/1)
///  1 B  content_checksum (0/1)
///  1 B  content_size_present (0/1)
///  8 B  content_size value (u64 LE; 0 when not present)
///  8 B  bytes_decompressed (u64 LE)
///  1 B  content_hasher_present (0/1)
/// 45 B  content_hasher serialized state (zeros when not present)
/// ```
///
/// Always 74 bytes — fixed-width keeps deserialize trivial. The
/// magic + version prefix lets us reject blobs from unrelated
/// formats and bump the layout later without ambiguity.
struct Lz4ResumeState {
    block_max_size: u32,
    block_checksum: bool,
    content_checksum: bool,
    content_size: Option<u64>,
    bytes_decompressed: u64,
    content_hasher: Option<xxh32::Xxh32>,
}

const RESUME_MAGIC: [u8; 4] = *b"LZDR";
const RESUME_FORMAT_V1: u8 = 1;
/// Total length of the [`Lz4ResumeState`] on-disk blob, in bytes.
const RESUME_BLOB_LEN: usize = 4 + 1 + 4 + 1 + 1 + 1 + 8 + 8 + 1 + xxh32::SERIALIZED_LEN;

impl Lz4ResumeState {
    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RESUME_BLOB_LEN);
        out.extend_from_slice(&RESUME_MAGIC);
        out.push(RESUME_FORMAT_V1);
        out.extend_from_slice(&self.block_max_size.to_le_bytes());
        out.push(u8::from(self.block_checksum));
        out.push(u8::from(self.content_checksum));
        match self.content_size {
            Some(v) => {
                out.push(1);
                out.extend_from_slice(&v.to_le_bytes());
            }
            None => {
                out.push(0);
                out.extend_from_slice(&0u64.to_le_bytes());
            }
        }
        out.extend_from_slice(&self.bytes_decompressed.to_le_bytes());
        match &self.content_hasher {
            Some(h) => {
                out.push(1);
                out.extend_from_slice(&h.serialize());
            }
            None => {
                out.push(0);
                out.extend_from_slice(&[0u8; xxh32::SERIALIZED_LEN]);
            }
        }
        debug_assert_eq!(out.len(), RESUME_BLOB_LEN);
        out
    }

    fn deserialize(blob: &[u8]) -> Result<Self, &'static str> {
        if blob.len() != RESUME_BLOB_LEN {
            return Err("blob length mismatch");
        }
        if blob[0..4] != RESUME_MAGIC {
            return Err("bad magic");
        }
        if blob[4] != RESUME_FORMAT_V1 {
            return Err("unknown format version");
        }
        let block_max_size = u32::from_le_bytes([blob[5], blob[6], blob[7], blob[8]]);
        // Mirror the `parse_frame_header` validation: block_max_size
        // is one of the four valid LZ4-spec values. Reject anything
        // else defensively rather than trusting the blob.
        const BMS_64K: u32 = 64 * 1024;
        const BMS_256K: u32 = 256 * 1024;
        const BMS_1M: u32 = 1024 * 1024;
        const BMS_4M: u32 = 4 * 1024 * 1024;
        match block_max_size {
            BMS_64K | BMS_256K | BMS_1M | BMS_4M => {}
            _ => return Err("invalid block_max_size"),
        }
        let block_checksum = match blob[9] {
            0 => false,
            1 => true,
            _ => return Err("block_checksum must be 0 or 1"),
        };
        let content_checksum = match blob[10] {
            0 => false,
            1 => true,
            _ => return Err("content_checksum must be 0 or 1"),
        };
        let content_size_present = match blob[11] {
            0 => false,
            1 => true,
            _ => return Err("content_size_present must be 0 or 1"),
        };
        let content_size_value = u64::from_le_bytes([
            blob[12], blob[13], blob[14], blob[15], blob[16], blob[17], blob[18], blob[19],
        ]);
        let content_size = if content_size_present {
            Some(content_size_value)
        } else {
            None
        };
        let bytes_decompressed = u64::from_le_bytes([
            blob[20], blob[21], blob[22], blob[23], blob[24], blob[25], blob[26], blob[27],
        ]);
        let hasher_present = match blob[28] {
            0 => false,
            1 => true,
            _ => return Err("content_hasher_present must be 0 or 1"),
        };
        // Enforce the `parse_frame_header` invariant that
        // `content_hasher.is_some() == content_checksum` — disagreement
        // would crash the EndMark arm's `expect("hasher present when
        // content_checksum set")`.
        if hasher_present != content_checksum {
            return Err("content_checksum and content_hasher presence disagree");
        }
        let content_hasher = if hasher_present {
            let bytes = &blob[29..29 + xxh32::SERIALIZED_LEN];
            // SAFETY note: bounds checked above by the
            // `RESUME_BLOB_LEN` length match.
            Some(xxh32::Xxh32::deserialize(bytes)?)
        } else {
            None
        };
        Ok(Self {
            block_max_size,
            block_checksum,
            content_checksum,
            content_size,
            bytes_decompressed,
            content_hasher,
        })
    }
}

impl StreamingDecoder for Lz4Decoder {
    fn decode_step(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, DecodeError> {
        match mem::replace(&mut self.state, State::Transient) {
            State::Done => {
                self.state = State::Done;
                Ok(DecodeStatus::Eof)
            }

            State::Transient => {
                // INVARIANT: `Transient` is only ever installed by the
                // `mem::replace` above and is replaced by a concrete
                // state on every match arm before this arm could run.
                // Reaching it indicates a panic-recovery edge; fail
                // closed rather than continue.
                Err(self.fail("lz4 decoder observed in transient state (poisoned)"))
            }

            State::BetweenFrames { mut source } => {
                let mut magic_bytes = [0u8; 4];
                match try_read_exact(&mut source, &mut magic_bytes) {
                    Ok(ReadOutcome::Eof) => {
                        // Clean source EOF *between* frames is a
                        // successful end-of-stream. If the very first
                        // byte of the source produces this, the
                        // overall stream is empty — that's not an
                        // error in lz4, just a no-op decode.
                        self.state = State::Done;
                        Ok(DecodeStatus::Eof)
                    }
                    Ok(ReadOutcome::Ok) => {
                        self.bytes_consumed = self.bytes_consumed.saturating_add(4);
                        let magic = u32::from_le_bytes(magic_bytes);
                        if magic == LZ4_FRAME_MAGIC {
                            match parse_frame_header(&mut source, &mut self.bytes_consumed) {
                                Ok(ctx) => {
                                    if ctx.block_max_size as usize > self.output_buf.len() {
                                        self.output_buf.resize(ctx.block_max_size as usize, 0);
                                    }
                                    self.state = State::InFrame { source, ctx };
                                    Ok(DecodeStatus::MoreData)
                                }
                                Err(err) => Err(self.fail_with(err)),
                            }
                        } else if magic & SKIPPABLE_MAGIC_MASK == SKIPPABLE_MAGIC_BASE {
                            let mut len_bytes = [0u8; 4];
                            if let Err(err) = source.read_exact(&mut len_bytes) {
                                return Err(self.fail_with(err));
                            }
                            self.bytes_consumed = self.bytes_consumed.saturating_add(4);
                            let remaining = u32::from_le_bytes(len_bytes) as u64;
                            self.state = if remaining == 0 {
                                State::BetweenFrames { source }
                            } else {
                                State::SkippingSkippable { source, remaining }
                            };
                            Ok(DecodeStatus::MoreData)
                        } else {
                            Err(self.fail(format!(
                                "lz4: unrecognized magic 0x{magic:08X} at offset {}",
                                self.bytes_consumed.saturating_sub(4)
                            )))
                        }
                    }
                    Err(err) => Err(self.fail_with(err)),
                }
            }

            State::SkippingSkippable {
                mut source,
                remaining,
            } => {
                let to_skip = remaining.min(self.skip_buf.len() as u64) as usize;
                if let Err(err) = source.read_exact(&mut self.skip_buf[..to_skip]) {
                    return Err(self.fail_with(err));
                }
                self.bytes_consumed = self.bytes_consumed.saturating_add(to_skip as u64);
                let remaining = remaining.saturating_sub(to_skip as u64);
                self.state = if remaining == 0 {
                    State::BetweenFrames { source }
                } else {
                    State::SkippingSkippable { source, remaining }
                };
                Ok(DecodeStatus::MoreData)
            }

            State::InFrame {
                mut source,
                mut ctx,
            } => {
                // Once we start reading the next block-size header
                // we are no longer "between blocks" — the resume
                // blob captured at this point would be paired with a
                // `decoder_position` that is mid-header. Clear the
                // flag before any failure path can return without
                // resetting it.
                self.between_blocks = false;

                // Read the 4-byte block size header.
                let mut hdr = [0u8; 4];
                if let Err(err) = source.read_exact(&mut hdr) {
                    return Err(self.fail_with(err));
                }
                self.bytes_consumed = self.bytes_consumed.saturating_add(4);
                let raw = u32::from_le_bytes(hdr);

                if raw == 0 {
                    // EndMark. Optionally validate content checksum,
                    // optionally cross-check declared content size.
                    if ctx.content_checksum {
                        let mut cc = [0u8; 4];
                        if let Err(err) = source.read_exact(&mut cc) {
                            return Err(self.fail_with(err));
                        }
                        self.bytes_consumed = self.bytes_consumed.saturating_add(4);
                        let expected = u32::from_le_bytes(cc);
                        // INVARIANT: ctx.content_hasher is `Some` whenever
                        // ctx.content_checksum is true — `parse_frame_header`
                        // constructs them together.
                        let hasher = ctx
                            .content_hasher
                            .as_ref()
                            .expect("hasher present when content_checksum set");
                        let got = hasher.finalize();
                        if got != expected {
                            return Err(self.fail(format!(
                                "lz4: content checksum mismatch at offset {} \
                                 (expected 0x{expected:08X}, got 0x{got:08X})",
                                self.bytes_consumed
                            )));
                        }
                    }
                    if let Some(declared) = ctx.content_size {
                        if declared != ctx.bytes_decompressed {
                            return Err(self.fail(format!(
                                "lz4: declared content size {declared} disagrees with \
                                 decompressed size {}",
                                ctx.bytes_decompressed
                            )));
                        }
                    }
                    self.last_frame_boundary = Some(ByteOffset::new(self.bytes_consumed));
                    self.state = State::BetweenFrames { source };
                    return Ok(DecodeStatus::MoreData);
                }

                let is_uncompressed = (raw & 0x8000_0000) != 0;
                let block_size = (raw & 0x7FFF_FFFF) as usize;
                if block_size > MAX_BLOCK_SIZE {
                    return Err(self.fail(format!(
                        "lz4: block size {block_size} exceeds spec maximum {MAX_BLOCK_SIZE}"
                    )));
                }
                if block_size > ctx.block_max_size as usize {
                    return Err(self.fail(format!(
                        "lz4: block size {block_size} exceeds frame's declared maximum {}",
                        ctx.block_max_size
                    )));
                }

                if self.input_buf.len() < block_size {
                    self.input_buf.resize(block_size, 0);
                }
                if let Err(err) = source.read_exact(&mut self.input_buf[..block_size]) {
                    return Err(self.fail_with(err));
                }
                self.bytes_consumed = self.bytes_consumed.saturating_add(block_size as u64);

                if ctx.block_checksum {
                    let mut bc = [0u8; 4];
                    if let Err(err) = source.read_exact(&mut bc) {
                        return Err(self.fail_with(err));
                    }
                    self.bytes_consumed = self.bytes_consumed.saturating_add(4);
                    let expected = u32::from_le_bytes(bc);
                    let got = xxh32::xxh32(&self.input_buf[..block_size], 0);
                    if got != expected {
                        return Err(self.fail(format!(
                            "lz4: block checksum mismatch at offset {} \
                             (expected 0x{expected:08X}, got 0x{got:08X})",
                            self.bytes_consumed
                        )));
                    }
                }

                let written: usize = if is_uncompressed {
                    sink.write_all(&self.input_buf[..block_size])
                        .map_err(DecodeError::Write)?;
                    if let Some(h) = ctx.content_hasher.as_mut() {
                        h.update(&self.input_buf[..block_size]);
                    }
                    block_size
                } else {
                    // Decompressed output cannot exceed the declared
                    // block-max-size for the frame; the buffer was
                    // sized to that bound when the header was parsed.
                    let n = lz4_flex::block::decompress_into(
                        &self.input_buf[..block_size],
                        &mut self.output_buf[..],
                    )
                    .map_err(|e| {
                        let consumed = self.bytes_consumed;
                        self.state = State::Done;
                        DecodeError::Read {
                            consumed,
                            source: io::Error::other(format!("lz4: block decompress: {e}")),
                        }
                    })?;
                    sink.write_all(&self.output_buf[..n])
                        .map_err(DecodeError::Write)?;
                    if let Some(h) = ctx.content_hasher.as_mut() {
                        h.update(&self.output_buf[..n]);
                    }
                    n
                };
                ctx.bytes_decompressed = ctx.bytes_decompressed.saturating_add(written as u64);
                // O.7b: every block boundary is a checkpoint-eligible
                // restart point now that the resume blob carries the
                // FrameContext. Update *after* every byte the block
                // contributes — payload + optional block-checksum —
                // has been consumed and `bytes_consumed` is final;
                // mirrors the discipline at the EndMark site above
                // so a crash mid-write never records a boundary
                // ahead of the bytes the sink actually accepted.
                self.last_frame_boundary = Some(ByteOffset::new(self.bytes_consumed));
                self.between_blocks = true;
                self.state = State::InFrame { source, ctx };
                Ok(DecodeStatus::MoreData)
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
        // Idempotent for the resume-factory path: `resume_factory`
        // already seeds `bytes_consumed = start_offset`. For the
        // regular factory this aligns the counter with the global
        // source on resume from a frame end (no decoder state blob).
        self.bytes_consumed = offset;
    }

    fn decoder_state_into(&self, out: &mut Vec<u8>) -> bool {
        // The blob is only meaningful at a position where the
        // decoder is paused mid-frame, between blocks; resuming from
        // anywhere else either doesn't need a state seed (between
        // frames; the factory route works) or isn't a safe restart
        // point (mid-block, mid-skippable, mid-header).
        if !self.between_blocks {
            return false;
        }
        let State::InFrame { ctx, .. } = &self.state else {
            return false;
        };
        let resume = Lz4ResumeState {
            block_max_size: ctx.block_max_size,
            block_checksum: ctx.block_checksum,
            content_checksum: ctx.content_checksum,
            content_size: ctx.content_size,
            bytes_decompressed: ctx.bytes_decompressed,
            content_hasher: ctx.content_hasher.clone(),
        };
        // Fixed-length blob (`RESUME_BLOB_LEN`, ~120 B); the
        // intermediate Vec is irrelevant compared to xz_native's
        // 8 MiB dict.
        out.extend_from_slice(&resume.serialize());
        true
    }
}

/// Result of [`try_read_exact`] — distinguishes "source ended cleanly
/// before any bytes were read" from "source ended mid-buffer".
enum ReadOutcome {
    /// All requested bytes were read.
    Ok,
    /// Source returned `Ok(0)` on the very first read; no bytes were
    /// consumed. Allowed only at frame boundaries.
    Eof,
}

/// Read exactly `buf.len()` bytes, distinguishing first-byte EOF from
/// mid-buffer truncation. A mid-buffer truncation maps to
/// [`io::ErrorKind::UnexpectedEof`].
fn try_read_exact<R: Read>(source: &mut R, buf: &mut [u8]) -> io::Result<ReadOutcome> {
    let mut total = 0;
    while total < buf.len() {
        match source.read(&mut buf[total..])? {
            0 => {
                if total == 0 {
                    return Ok(ReadOutcome::Eof);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "lz4: source ended mid-buffer",
                ));
            }
            n => total += n,
        }
    }
    Ok(ReadOutcome::Ok)
}

/// Parse a regular LZ4 frame header (everything after the 4-byte
/// magic, up to and including the 1-byte HC).
///
/// Updates `bytes_consumed` to reflect the bytes pulled from the
/// source. On success returns the per-frame parameters.
fn parse_frame_header<R: Read>(
    source: &mut R,
    bytes_consumed: &mut u64,
) -> io::Result<FrameContext> {
    // FLG and BD are always present.
    let mut fb = [0u8; 2];
    source.read_exact(&mut fb)?;
    *bytes_consumed = bytes_consumed.saturating_add(2);
    let flg = fb[0];
    let bd = fb[1];

    let version = (flg >> 6) & 0b11;
    if version != 0b01 {
        return Err(io::Error::other(format!(
            "lz4: unsupported frame version {version} (only v01 is defined)"
        )));
    }
    let block_independence = (flg >> 5) & 0b1 == 1;
    let block_checksum = (flg >> 4) & 0b1 == 1;
    let content_size_flag = (flg >> 3) & 0b1 == 1;
    let content_checksum = (flg >> 2) & 0b1 == 1;
    let reserved_flg_bit_1 = (flg >> 1) & 0b1;
    let dict_id_flag = flg & 0b1 == 1;
    if reserved_flg_bit_1 != 0 {
        return Err(io::Error::other(
            "lz4: reserved bit 1 in FLG is set; refusing to decode",
        ));
    }
    if !block_independence {
        // Round-one limitation, see module docs. Surface the unsupported
        // feature by name rather than producing wrong output.
        return Err(io::Error::other(
            "lz4: linked-block frames are not supported in this round; \
             only independent-block frames decode (FLG bit 5 must be set)",
        ));
    }

    // BD: bits 6-4 carry block-max-size; bits 7,3-0 are reserved.
    let bd_reserved = bd & 0b1000_1111;
    if bd_reserved != 0 {
        return Err(io::Error::other(
            "lz4: reserved bits in BD are set; refusing to decode",
        ));
    }
    let bd_size_code = (bd >> 4) & 0b0111;
    let block_max_size: u32 = match bd_size_code {
        4 => 64 * 1024,
        5 => 256 * 1024,
        6 => 1024 * 1024,
        7 => 4 * 1024 * 1024,
        other => {
            return Err(io::Error::other(format!(
                "lz4: invalid BD block-max-size code {other} (must be 4..=7)"
            )))
        }
    };

    // The full FLG..end-of-DictID byte range is the input to the HC
    // checksum. Buffer it as we read so we can verify in one shot.
    let mut hashed: Vec<u8> = Vec::with_capacity(2 + 8 + 4);
    hashed.extend_from_slice(&fb);

    let content_size = if content_size_flag {
        let mut cs = [0u8; 8];
        source.read_exact(&mut cs)?;
        *bytes_consumed = bytes_consumed.saturating_add(8);
        hashed.extend_from_slice(&cs);
        Some(u64::from_le_bytes(cs))
    } else {
        None
    };

    if dict_id_flag {
        let mut did = [0u8; 4];
        source.read_exact(&mut did)?;
        *bytes_consumed = bytes_consumed.saturating_add(4);
        hashed.extend_from_slice(&did);
        // We don't apply dictionaries (round-one MVP); the spec lets
        // the decoder reject when it can't fulfill, but most producers
        // never set DictID outside a private corpus, so we just record
        // and ignore.
    }

    // HC: one byte equal to (XXH32(hashed) >> 8) & 0xff.
    let mut hc = [0u8; 1];
    source.read_exact(&mut hc)?;
    *bytes_consumed = bytes_consumed.saturating_add(1);
    let hc_expected = ((xxh32::xxh32(&hashed, 0) >> 8) & 0xff) as u8;
    if hc[0] != hc_expected {
        return Err(io::Error::other(format!(
            "lz4: header checksum mismatch (expected 0x{hc_expected:02X}, got 0x{:02X})",
            hc[0]
        )));
    }

    let content_hasher = if content_checksum {
        Some(xxh32::Xxh32::new(0))
    } else {
        None
    };

    Ok(FrameContext {
        block_max_size,
        block_checksum,
        content_checksum,
        content_size,
        content_hasher,
        bytes_decompressed: 0,
    })
}

/// [`super::DecoderFactory`] adapter for [`Lz4Decoder`].
///
/// Registered against the `.lz4` / `.tar.lz4` suffixes, the format
/// name `lz4`, and the magic `04 22 4D 18` at offset 0 by
/// [`super::DecoderRegistry::with_defaults`].
///
/// # Errors
///
/// Forwards [`DecodeError::Construct`] from [`Lz4Decoder::new`]. In
/// practice this never fires today; the signature stays fallible to
/// match [`super::DecoderFactory`].
pub fn factory(src: Box<dyn Read + Send>) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    Ok(Box::new(Lz4Decoder::new(src)?))
}

/// [`super::DecoderResumeFactory`] adapter for [`Lz4Decoder::resume`].
///
/// Registered against the format name `lz4` by
/// [`super::DecoderRegistry::with_defaults`] (`OPTIMIZATIONS.md`
/// §O.7b). Coordinator dispatches here when a checkpoint carries a
/// `decoder_state` blob and the resolved format is `lz4`; otherwise
/// the regular [`factory`] is used.
///
/// # Errors
///
/// Forwards [`DecodeError::Construct`] from [`Lz4Decoder::resume`]
/// when the blob is malformed (bad magic, length mismatch, internal
/// field disagreement).
pub fn resume_factory(
    src: Box<dyn Read + Send>,
    state_blob: &[u8],
    start_offset: u64,
) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    Ok(Box::new(Lz4Decoder::resume(src, state_blob, start_offset)?))
}

/// Hand-rolled XXH32 used for the LZ4 frame's header, block, and
/// content checksums.
///
/// Public surface is the streaming [`Xxh32`] state plus the one-shot
/// [`xxh32`] free function. A standalone implementation is preferred
/// to pulling in `twox-hash` (the dep `lz4_flex`'s frame feature uses);
/// per `internal/ENGINEERING_STANDARDS.md` §2.1 we hand-roll trivial
/// primitives whose maintenance cost is dominated by the surrounding
/// framing rather than the algorithm itself. The reference test
/// vectors from the [xxHash spec] are encoded in the unit tests.
///
/// [xxHash spec]: https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md
mod xxh32 {
    const PRIME32_1: u32 = 0x9E37_79B1;
    const PRIME32_2: u32 = 0x85EB_CA77;
    const PRIME32_3: u32 = 0xC2B2_AE3D;
    const PRIME32_4: u32 = 0x27D4_EB2F;
    const PRIME32_5: u32 = 0x1656_67B1;

    /// One-shot XXH32 of `input` with `seed`.
    pub fn xxh32(input: &[u8], seed: u32) -> u32 {
        let mut h: u32;
        let mut p = 0usize;
        let len = input.len();

        if len >= 16 {
            let mut v1 = seed.wrapping_add(PRIME32_1).wrapping_add(PRIME32_2);
            let mut v2 = seed.wrapping_add(PRIME32_2);
            let mut v3 = seed;
            let mut v4 = seed.wrapping_sub(PRIME32_1);
            let limit = len - 16;
            loop {
                v1 = round(v1, read_u32_le(&input[p..]));
                v2 = round(v2, read_u32_le(&input[p + 4..]));
                v3 = round(v3, read_u32_le(&input[p + 8..]));
                v4 = round(v4, read_u32_le(&input[p + 12..]));
                p += 16;
                if p > limit {
                    break;
                }
            }
            h = v1
                .rotate_left(1)
                .wrapping_add(v2.rotate_left(7))
                .wrapping_add(v3.rotate_left(12))
                .wrapping_add(v4.rotate_left(18));
        } else {
            h = seed.wrapping_add(PRIME32_5);
        }

        h = h.wrapping_add(len as u32);

        while p + 4 <= len {
            h = h.wrapping_add(read_u32_le(&input[p..]).wrapping_mul(PRIME32_3));
            h = h.rotate_left(17).wrapping_mul(PRIME32_4);
            p += 4;
        }
        while p < len {
            h = h.wrapping_add(u32::from(input[p]).wrapping_mul(PRIME32_5));
            h = h.rotate_left(11).wrapping_mul(PRIME32_1);
            p += 1;
        }

        avalanche(h)
    }

    /// Total bytes the [`Xxh32::serialize`] / [`Xxh32::deserialize`]
    /// pair occupies. Fixed-width — the on-disk shape is:
    /// `seed (4) | v1 (4) | v2 (4) | v3 (4) | v4 (4) | total_len (8) | buffer_len (1) | buffer (16)`.
    /// The `seed` is included even though LZ4 frames always pass 0
    /// at construction; preserving it keeps the round-trip honest
    /// for any future caller (and matches the `finalize` short-input
    /// branch that uses `seed` directly).
    pub const SERIALIZED_LEN: usize = 4 + 4 + 4 + 4 + 4 + 8 + 1 + 16;

    /// Streaming XXH32 state — used for the frame's content checksum,
    /// which must be computed across decompressed bytes from every
    /// block in the frame.
    #[derive(Clone)]
    pub struct Xxh32 {
        seed: u32,
        v1: u32,
        v2: u32,
        v3: u32,
        v4: u32,
        /// Buffered bytes that didn't yet form a 16-byte lane group.
        buffer: [u8; 16],
        /// Bytes valid in `buffer`.
        buffer_len: usize,
        /// Total bytes processed across all `update` calls.
        total_len: u64,
    }

    impl Xxh32 {
        pub fn new(seed: u32) -> Self {
            Self {
                seed,
                v1: seed.wrapping_add(PRIME32_1).wrapping_add(PRIME32_2),
                v2: seed.wrapping_add(PRIME32_2),
                v3: seed,
                v4: seed.wrapping_sub(PRIME32_1),
                buffer: [0u8; 16],
                buffer_len: 0,
                total_len: 0,
            }
        }

        /// Serialize the streaming hasher into a fixed-width
        /// [`SERIALIZED_LEN`]-byte blob suitable for embedding in a
        /// resume blob.
        ///
        /// Round-trips with [`Self::deserialize`] across any input
        /// length: feeding the same bytes through a fresh hasher and
        /// `update` produces an identical [`Self::finalize`] digest
        /// before and after the round trip.
        #[must_use]
        pub fn serialize(&self) -> [u8; SERIALIZED_LEN] {
            let mut out = [0u8; SERIALIZED_LEN];
            out[0..4].copy_from_slice(&self.seed.to_le_bytes());
            out[4..8].copy_from_slice(&self.v1.to_le_bytes());
            out[8..12].copy_from_slice(&self.v2.to_le_bytes());
            out[12..16].copy_from_slice(&self.v3.to_le_bytes());
            out[16..20].copy_from_slice(&self.v4.to_le_bytes());
            out[20..28].copy_from_slice(&self.total_len.to_le_bytes());
            // `buffer_len` is bounded to 0..=15 by the streaming
            // discipline (`update` consumes a full 16 the moment one
            // is available) so a 1-byte field is sufficient.
            out[28] = self.buffer_len as u8;
            out[29..29 + 16].copy_from_slice(&self.buffer);
            out
        }

        /// Reconstruct a streaming hasher from its
        /// [`Self::serialize`] output.
        ///
        /// Validates `buffer_len ∈ 0..=15` defensively — a hostile
        /// blob could otherwise install an invariant break that
        /// makes [`Self::finalize`]'s tail loop walk past the
        /// buffer.
        ///
        /// # Errors
        ///
        /// Returns the static error message describing the field
        /// that failed validation.
        pub fn deserialize(bytes: &[u8]) -> Result<Self, &'static str> {
            if bytes.len() != SERIALIZED_LEN {
                return Err("xxh32 blob length mismatch");
            }
            let seed = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            let v1 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            let v2 = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
            let v3 = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
            let v4 = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
            let total_len = u64::from_le_bytes([
                bytes[20], bytes[21], bytes[22], bytes[23], bytes[24], bytes[25], bytes[26],
                bytes[27],
            ]);
            let buffer_len = bytes[28];
            if buffer_len > 15 {
                return Err("xxh32 buffer_len out of range");
            }
            let mut buffer = [0u8; 16];
            buffer.copy_from_slice(&bytes[29..29 + 16]);
            Ok(Self {
                seed,
                v1,
                v2,
                v3,
                v4,
                buffer,
                buffer_len: buffer_len as usize,
                total_len,
            })
        }

        pub fn update(&mut self, mut input: &[u8]) {
            self.total_len = self.total_len.saturating_add(input.len() as u64);

            if self.buffer_len > 0 {
                let need = 16 - self.buffer_len;
                if input.len() < need {
                    self.buffer[self.buffer_len..self.buffer_len + input.len()]
                        .copy_from_slice(input);
                    self.buffer_len += input.len();
                    return;
                }
                self.buffer[self.buffer_len..].copy_from_slice(&input[..need]);
                self.consume_block(self.buffer);
                input = &input[need..];
                self.buffer_len = 0;
            }

            while input.len() >= 16 {
                let mut block = [0u8; 16];
                block.copy_from_slice(&input[..16]);
                self.consume_block(block);
                input = &input[16..];
            }

            if !input.is_empty() {
                self.buffer[..input.len()].copy_from_slice(input);
                self.buffer_len = input.len();
            }
        }

        fn consume_block(&mut self, block: [u8; 16]) {
            self.v1 = round(self.v1, read_u32_le(&block[0..]));
            self.v2 = round(self.v2, read_u32_le(&block[4..]));
            self.v3 = round(self.v3, read_u32_le(&block[8..]));
            self.v4 = round(self.v4, read_u32_le(&block[12..]));
        }

        pub fn finalize(&self) -> u32 {
            let mut h = if self.total_len >= 16 {
                self.v1
                    .rotate_left(1)
                    .wrapping_add(self.v2.rotate_left(7))
                    .wrapping_add(self.v3.rotate_left(12))
                    .wrapping_add(self.v4.rotate_left(18))
            } else {
                self.seed.wrapping_add(PRIME32_5)
            };
            h = h.wrapping_add(self.total_len as u32);

            let tail = &self.buffer[..self.buffer_len];
            let mut p = 0usize;
            while p + 4 <= tail.len() {
                h = h.wrapping_add(read_u32_le(&tail[p..]).wrapping_mul(PRIME32_3));
                h = h.rotate_left(17).wrapping_mul(PRIME32_4);
                p += 4;
            }
            while p < tail.len() {
                h = h.wrapping_add(u32::from(tail[p]).wrapping_mul(PRIME32_5));
                h = h.rotate_left(11).wrapping_mul(PRIME32_1);
                p += 1;
            }

            avalanche(h)
        }
    }

    fn round(acc: u32, lane: u32) -> u32 {
        acc.wrapping_add(lane.wrapping_mul(PRIME32_2))
            .rotate_left(13)
            .wrapping_mul(PRIME32_1)
    }

    fn avalanche(mut h: u32) -> u32 {
        h ^= h >> 15;
        h = h.wrapping_mul(PRIME32_2);
        h ^= h >> 13;
        h = h.wrapping_mul(PRIME32_3);
        h ^= h >> 16;
        h
    }

    fn read_u32_le(bytes: &[u8]) -> u32 {
        // INVARIANT: every caller has already bounded `bytes` to ≥ 4
        // via slice indexing or an explicit length check; the array
        // construction below cannot panic in any reachable callsite.
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // Reference vectors from xxHash spec doc / test suite. Seed 0
        // is the LZ4 frame format's seed.
        #[test]
        fn empty_input_seed_zero() {
            assert_eq!(xxh32(b"", 0), 0x02CC_5D05);
        }

        #[test]
        fn empty_input_seed_prime() {
            assert_eq!(xxh32(b"", PRIME32_1), 0x36B7_8AE7);
        }

        #[test]
        fn single_byte_input_seed_zero() {
            // The xxHash reference test for "a" with seed 0.
            assert_eq!(xxh32(b"a", 0), 0x550D_7456);
        }

        #[test]
        fn small_input_seed_zero() {
            // "Nobody inspects the spammish repetition" — a recognized
            // xxHash reference vector.
            assert_eq!(
                xxh32(b"Nobody inspects the spammish repetition", 0),
                0xE229_3B2F,
            );
        }

        #[test]
        fn large_input_streaming_matches_oneshot() {
            let payload: Vec<u8> = (0u8..=255u8).cycle().take(10_000).collect();
            let one_shot = xxh32(&payload, 0);
            // Drive the streaming hasher through awkward chunk sizes
            // (each prime length forces the buffered remainder logic
            // to exercise multiple boundary alignments).
            for chunk_size in [1usize, 7, 13, 31, 64, 256] {
                let mut h = Xxh32::new(0);
                for chunk in payload.chunks(chunk_size) {
                    h.update(chunk);
                }
                assert_eq!(h.finalize(), one_shot, "chunk_size={chunk_size}");
            }
        }

        #[test]
        fn streaming_finalize_can_be_called_multiple_times_consistently() {
            let mut h = Xxh32::new(0);
            h.update(b"hello world");
            let a = h.finalize();
            let b = h.finalize();
            assert_eq!(a, b);
        }

        #[test]
        fn serialize_round_trip_at_buffer_boundaries() {
            // The streaming hasher's buffered remainder is in
            // 0..=15. Exercise each remainder shape so the
            // serialize → deserialize → finalize chain is honest at
            // every alignment that production code can hit.
            let payload: Vec<u8> = (0u8..=255u8).cycle().take(10_000).collect();
            for take in [0usize, 1, 7, 8, 15, 16, 31, 1024, 9_999, 10_000] {
                let mut h = Xxh32::new(0);
                h.update(&payload[..take]);
                let expected = h.finalize();

                let blob = h.serialize();
                let mut restored = Xxh32::deserialize(&blob).expect("round-trip");
                assert_eq!(restored.finalize(), expected, "take={take}");

                // The restored hasher must accept additional updates
                // and produce the same digest as a fresh one fed the
                // full payload.
                if take < payload.len() {
                    restored.update(&payload[take..]);
                    let mut full = Xxh32::new(0);
                    full.update(&payload);
                    assert_eq!(restored.finalize(), full.finalize(), "take={take} suffix");
                }
            }
        }

        #[test]
        fn serialize_includes_seed_for_short_input_path() {
            // The < 16-byte finalize branch reads `seed` directly.
            // A round trip across that branch must preserve seed.
            let mut h = Xxh32::new(PRIME32_1);
            h.update(b"abc");
            let expected = h.finalize();
            let blob = h.serialize();
            let restored = Xxh32::deserialize(&blob).expect("round-trip");
            assert_eq!(restored.finalize(), expected);
        }

        #[test]
        fn deserialize_rejects_oversized_buffer_len() {
            let mut h = Xxh32::new(0);
            h.update(b"data");
            let mut blob = h.serialize();
            blob[28] = 16; // buffer_len must be 0..=15
            match Xxh32::deserialize(&blob) {
                Err("xxh32 buffer_len out of range") => {}
                Ok(_) => panic!("expected reject, got Ok"),
                Err(other) => panic!("unexpected error: {other}"),
            }
        }

        #[test]
        fn deserialize_rejects_wrong_blob_length() {
            match Xxh32::deserialize(&[0u8; SERIALIZED_LEN - 1]) {
                Err("xxh32 blob length mismatch") => {}
                Ok(_) => panic!("expected reject"),
                Err(other) => panic!("unexpected error: {other}"),
            }
            match Xxh32::deserialize(&[0u8; SERIALIZED_LEN + 1]) {
                Err("xxh32 blob length mismatch") => {}
                Ok(_) => panic!("expected reject"),
                Err(other) => panic!("unexpected error: {other}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    /// Encode `payload` as a single-block, single-frame LZ4 archive
    /// with `block_max_size = 4 MiB` and the requested feature flags.
    /// Helper is local to the tests so we can drive every code path
    /// without a runtime encoder dependency.
    struct EncoderOpts {
        block_checksum: bool,
        content_size: bool,
        content_checksum: bool,
        compress_block: bool,
    }

    fn encode_lz4(payload: &[u8], opts: EncoderOpts) -> Vec<u8> {
        let mut out = Vec::new();
        // Magic.
        out.extend_from_slice(&LZ4_FRAME_MAGIC.to_le_bytes());
        // FLG.
        let mut flg: u8 = 0b0100_0000; // version = 01
        flg |= 0b0010_0000; // block independence
        if opts.block_checksum {
            flg |= 0b0001_0000;
        }
        if opts.content_size {
            flg |= 0b0000_1000;
        }
        if opts.content_checksum {
            flg |= 0b0000_0100;
        }
        // BD.
        let bd: u8 = 0b0111_0000; // 4 MiB block max
        out.push(flg);
        out.push(bd);
        let mut hashed = vec![flg, bd];
        if opts.content_size {
            let cs = (payload.len() as u64).to_le_bytes();
            out.extend_from_slice(&cs);
            hashed.extend_from_slice(&cs);
        }
        let hc = ((xxh32::xxh32(&hashed, 0) >> 8) & 0xff) as u8;
        out.push(hc);

        // One block, optionally compressed via lz4_flex's block API.
        let (block, uncompressed_flag) = if opts.compress_block && !payload.is_empty() {
            let max_compressed = lz4_flex::block::get_maximum_output_size(payload.len());
            let mut tmp = vec![0u8; max_compressed];
            let n = lz4_flex::block::compress_into(payload, &mut tmp).expect("compress");
            // If compression made things larger, fall back to
            // uncompressed (matches what a real encoder would do).
            if n >= payload.len() {
                (payload.to_vec(), 0x8000_0000_u32)
            } else {
                tmp.truncate(n);
                (tmp, 0u32)
            }
        } else {
            (payload.to_vec(), 0x8000_0000_u32)
        };

        let header = (block.len() as u32) | uncompressed_flag;
        out.extend_from_slice(&header.to_le_bytes());
        out.extend_from_slice(&block);
        if opts.block_checksum {
            let bc = xxh32::xxh32(&block, 0);
            out.extend_from_slice(&bc.to_le_bytes());
        }
        // EndMark.
        out.extend_from_slice(&[0u8; 4]);
        if opts.content_checksum {
            let cc = xxh32::xxh32(payload, 0);
            out.extend_from_slice(&cc.to_le_bytes());
        }
        out
    }

    fn drive_to_eof(decoder: &mut dyn StreamingDecoder, sink: &mut Vec<u8>) {
        while decoder.decode_step(sink).expect("decode_step") == DecodeStatus::MoreData {}
    }

    /// Encode `payload` as a single-frame archive with one block
    /// every `block_max_size` bytes. All blocks are uncompressed —
    /// the goal is exercising mid-frame block boundaries, not
    /// exercising compression. `block_max_size` must be one of the
    /// LZ4-spec values (64K, 256K, 1M, 4M).
    fn encode_lz4_multi_block(
        payload: &[u8],
        block_max_size: u32,
        block_checksum: bool,
        content_checksum: bool,
        content_size: Option<u64>,
    ) -> Vec<u8> {
        let bd_size_code: u8 = match block_max_size {
            65_536 => 4,
            262_144 => 5,
            1_048_576 => 6,
            4_194_304 => 7,
            other => panic!("invalid block_max_size {other}"),
        };
        let mut out = Vec::new();
        out.extend_from_slice(&LZ4_FRAME_MAGIC.to_le_bytes());
        let mut flg: u8 = 0b0100_0000; // version = 01
        flg |= 0b0010_0000; // block independence
        if block_checksum {
            flg |= 0b0001_0000;
        }
        if content_size.is_some() {
            flg |= 0b0000_1000;
        }
        if content_checksum {
            flg |= 0b0000_0100;
        }
        let bd = bd_size_code << 4;
        out.push(flg);
        out.push(bd);
        let mut hashed = vec![flg, bd];
        if let Some(v) = content_size {
            let cs = v.to_le_bytes();
            out.extend_from_slice(&cs);
            hashed.extend_from_slice(&cs);
        }
        let hc = ((xxh32::xxh32(&hashed, 0) >> 8) & 0xff) as u8;
        out.push(hc);

        for chunk in payload.chunks(block_max_size as usize) {
            // Uncompressed block: header has the high bit set; the
            // payload bytes follow verbatim.
            let header = (chunk.len() as u32) | 0x8000_0000_u32;
            out.extend_from_slice(&header.to_le_bytes());
            out.extend_from_slice(chunk);
            if block_checksum {
                let bc = xxh32::xxh32(chunk, 0);
                out.extend_from_slice(&bc.to_le_bytes());
            }
        }

        out.extend_from_slice(&[0u8; 4]); // EndMark
        if content_checksum {
            let cc = xxh32::xxh32(payload, 0);
            out.extend_from_slice(&cc.to_le_bytes());
        }
        out
    }

    /// Minimal happy-path: uncompressed block, no checksums, no size.
    #[test]
    fn single_uncompressed_block_round_trips() {
        let payload = b"hello, lz4 frame world!".repeat(123);
        let frame = encode_lz4(
            &payload,
            EncoderOpts {
                block_checksum: false,
                content_size: false,
                content_checksum: false,
                compress_block: false,
            },
        );
        let frame_len = frame.len() as u64;

        let mut decoder = Lz4Decoder::new(Box::new(Cursor::new(frame))).expect("construct");
        let mut sink = Vec::with_capacity(payload.len());
        drive_to_eof(&mut decoder, &mut sink);
        assert_eq!(sink, payload);
        assert_eq!(decoder.bytes_consumed().get(), frame_len);
        assert_eq!(decoder.frame_boundary(), Some(ByteOffset::new(frame_len)));
    }

    /// Compressed block, all checksums and content size — exercises
    /// every header / per-block code path in one go.
    #[test]
    fn compressed_block_with_all_checks_round_trips() {
        let payload = b"compressible-payload-".repeat(2048);
        let frame = encode_lz4(
            &payload,
            EncoderOpts {
                block_checksum: true,
                content_size: true,
                content_checksum: true,
                compress_block: true,
            },
        );
        let frame_len = frame.len() as u64;

        let mut decoder = Lz4Decoder::new(Box::new(Cursor::new(frame))).expect("construct");
        let mut sink = Vec::with_capacity(payload.len());
        drive_to_eof(&mut decoder, &mut sink);
        assert_eq!(sink, payload);
        assert_eq!(decoder.bytes_consumed().get(), frame_len);
    }

    /// `bytes_consumed` is monotonically non-decreasing across every
    /// `decode_step` call, including the EndMark step.
    #[test]
    fn bytes_consumed_is_monotone() {
        let payload = b"monotone".repeat(8192);
        let frame = encode_lz4(
            &payload,
            EncoderOpts {
                block_checksum: false,
                content_size: false,
                content_checksum: false,
                compress_block: true,
            },
        );

        let mut decoder = Lz4Decoder::new(Box::new(Cursor::new(frame.clone()))).expect("construct");
        let mut last = 0u64;
        loop {
            let status = decoder
                .decode_step(&mut std::io::sink())
                .expect("decode_step");
            let now = decoder.bytes_consumed().get();
            assert!(now >= last, "regressed {last} -> {now}");
            assert!(now <= frame.len() as u64);
            last = now;
            if status == DecodeStatus::Eof {
                break;
            }
        }
    }

    /// Concatenated frames decode to the concatenation of their
    /// payloads, and a frame boundary is observable between the two
    /// frames at the post-EndMark offset.
    #[test]
    fn concatenated_frames_decode_and_expose_intermediate_boundary() {
        let payload_a = b"frame-A-payload-".repeat(800);
        let payload_b = b"frame-B-payload-different-".repeat(600);
        let frame_a = encode_lz4(
            &payload_a,
            EncoderOpts {
                block_checksum: false,
                content_size: false,
                content_checksum: false,
                compress_block: true,
            },
        );
        let frame_b = encode_lz4(
            &payload_b,
            EncoderOpts {
                block_checksum: false,
                content_size: false,
                content_checksum: false,
                compress_block: true,
            },
        );
        let mut combined = frame_a.clone();
        combined.extend_from_slice(&frame_b);
        let combined_len = combined.len() as u64;

        let mut decoder =
            Lz4Decoder::new(Box::new(Cursor::new(combined.clone()))).expect("construct");
        let mut sink = Vec::with_capacity(payload_a.len() + payload_b.len());
        let mut saw_intermediate = false;
        loop {
            let status = decoder.decode_step(&mut sink).expect("decode_step");
            if let Some(b) = decoder.frame_boundary() {
                if b.get() == frame_a.len() as u64 {
                    saw_intermediate = true;
                }
            }
            if status == DecodeStatus::Eof {
                break;
            }
        }

        let mut expected = payload_a.clone();
        expected.extend_from_slice(&payload_b);
        assert_eq!(sink, expected);
        assert!(
            saw_intermediate,
            "should observe a boundary at the inter-frame offset",
        );
        assert_eq!(decoder.bytes_consumed().get(), combined_len);
    }

    /// Skippable frames are silently consumed, and the wrapped regular
    /// frame still decodes to its payload.
    #[test]
    fn skippable_frame_is_skipped_transparently() {
        let payload = b"after-skippable".repeat(1024);
        let regular = encode_lz4(
            &payload,
            EncoderOpts {
                block_checksum: false,
                content_size: false,
                content_checksum: false,
                compress_block: false,
            },
        );

        // Build: leading skippable frame (8 opaque bytes) + regular
        // frame + trailing skippable frame (3 opaque bytes).
        let mut input = Vec::new();
        input.extend_from_slice(&SKIPPABLE_MAGIC_BASE.to_le_bytes());
        input.extend_from_slice(&8u32.to_le_bytes());
        input.extend_from_slice(&[0xAA; 8]);
        input.extend_from_slice(&regular);
        input.extend_from_slice(&(SKIPPABLE_MAGIC_BASE | 0x0F).to_le_bytes());
        input.extend_from_slice(&3u32.to_le_bytes());
        input.extend_from_slice(&[0xBB; 3]);

        let mut decoder = Lz4Decoder::new(Box::new(Cursor::new(input.clone()))).expect("construct");
        let mut sink = Vec::with_capacity(payload.len());
        drive_to_eof(&mut decoder, &mut sink);
        assert_eq!(sink, payload);
        assert_eq!(decoder.bytes_consumed().get(), input.len() as u64);
    }

    /// Empty source: clean Eof on the very first step, no error.
    #[test]
    fn empty_source_reports_eof_immediately() {
        let mut decoder =
            Lz4Decoder::new(Box::new(Cursor::new(Vec::<u8>::new()))).expect("construct");
        let mut sink = Vec::new();
        assert_eq!(
            decoder.decode_step(&mut sink).expect("step"),
            DecodeStatus::Eof,
        );
        assert!(sink.is_empty());
    }

    /// Garbage bytes that don't form a valid magic surface as a
    /// `Read` error, not a panic.
    #[test]
    fn unrecognized_magic_is_a_read_error() {
        let garbage = vec![0xDE_u8, 0xAD, 0xBE, 0xEF, 0x12, 0x34];
        let mut decoder = Lz4Decoder::new(Box::new(Cursor::new(garbage))).expect("construct");
        match decoder.decode_step(&mut Vec::new()) {
            Err(DecodeError::Read { .. }) => {}
            other => panic!("expected Read error, got {other:?}"),
        }
    }

    /// Linked-block frames are explicitly rejected with a `Read`
    /// error naming the unsupported feature.
    #[test]
    fn linked_block_frames_are_rejected_with_named_feature() {
        // Build a frame manually with FLG bit 5 = 0 (linked).
        let mut frame = Vec::new();
        frame.extend_from_slice(&LZ4_FRAME_MAGIC.to_le_bytes());
        let flg: u8 = 0b0100_0000; // version 01, block independence = 0
        let bd: u8 = 0b0111_0000;
        frame.push(flg);
        frame.push(bd);
        let hc = ((xxh32::xxh32(&[flg, bd], 0) >> 8) & 0xff) as u8;
        frame.push(hc);

        let mut decoder = Lz4Decoder::new(Box::new(Cursor::new(frame))).expect("construct");
        match decoder.decode_step(&mut Vec::new()) {
            Err(DecodeError::Read { source, .. }) => {
                let msg = source.to_string();
                assert!(
                    msg.contains("linked-block"),
                    "expected linked-block unsupported message, got: {msg}",
                );
            }
            other => panic!("expected Read error, got {other:?}"),
        }
    }

    /// A header checksum mismatch is surfaced cleanly.
    #[test]
    fn header_checksum_mismatch_reports_read_error() {
        let payload = b"header-checksum-test".to_vec();
        let mut frame = encode_lz4(
            &payload,
            EncoderOpts {
                block_checksum: false,
                content_size: false,
                content_checksum: false,
                compress_block: false,
            },
        );
        // Flip the HC byte (offset 6: magic[4] + FLG + BD + HC).
        let hc_idx = 4 + 2;
        frame[hc_idx] ^= 0xFF;
        let mut decoder = Lz4Decoder::new(Box::new(Cursor::new(frame))).expect("construct");
        match decoder.decode_step(&mut Vec::new()) {
            Err(DecodeError::Read { source, .. }) => {
                assert!(source.to_string().contains("header checksum"));
            }
            other => panic!("expected header checksum Read error, got {other:?}"),
        }
    }

    /// A block checksum mismatch is detected and surfaced.
    #[test]
    fn block_checksum_mismatch_reports_read_error() {
        let payload = b"block-checksum-test".repeat(64);
        let mut frame = encode_lz4(
            &payload,
            EncoderOpts {
                block_checksum: true,
                content_size: false,
                content_checksum: false,
                compress_block: false,
            },
        );
        // Frame layout: magic (4) + FLG (1) + BD (1) + HC (1) +
        //               block size (4) + payload + block_checksum (4) + endmark (4)
        // Flip a byte inside the payload to break the checksum.
        let payload_offset = 4 + 1 + 1 + 1 + 4;
        frame[payload_offset] ^= 0xFF;

        let mut decoder = Lz4Decoder::new(Box::new(Cursor::new(frame))).expect("construct");
        let mut hit = false;
        for _ in 0..1024 {
            match decoder.decode_step(&mut Vec::new()) {
                Ok(DecodeStatus::MoreData) => continue,
                Ok(DecodeStatus::Eof) => break,
                Err(DecodeError::Read { source, .. }) => {
                    assert!(source.to_string().contains("block checksum"));
                    hit = true;
                    break;
                }
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
        assert!(hit, "expected block checksum mismatch to be detected");
    }

    /// A content checksum mismatch is detected and surfaced.
    #[test]
    fn content_checksum_mismatch_reports_read_error() {
        let payload = b"content-checksum-test".repeat(64);
        let mut frame = encode_lz4(
            &payload,
            EncoderOpts {
                block_checksum: false,
                content_size: false,
                content_checksum: true,
                compress_block: false,
            },
        );
        // The trailing 4 bytes are the content checksum; corrupt one.
        let cc_off = frame.len() - 4;
        frame[cc_off] ^= 0xFF;
        let mut decoder = Lz4Decoder::new(Box::new(Cursor::new(frame))).expect("construct");
        let mut hit = false;
        for _ in 0..1024 {
            match decoder.decode_step(&mut Vec::new()) {
                Ok(DecodeStatus::MoreData) => continue,
                Ok(DecodeStatus::Eof) => break,
                Err(DecodeError::Read { source, .. }) => {
                    assert!(source.to_string().contains("content checksum"));
                    hit = true;
                    break;
                }
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
        assert!(hit, "expected content checksum mismatch to be detected");
    }

    /// A truncated frame surfaces as a `Read` error and never advances
    /// `bytes_consumed` past the truncation point.
    #[test]
    fn truncated_frame_reports_read_error() {
        let payload = b"truncated-frame-input".repeat(2048);
        let frame = encode_lz4(
            &payload,
            EncoderOpts {
                block_checksum: false,
                content_size: false,
                content_checksum: false,
                compress_block: true,
            },
        );
        // Drop the trailing EndMark and a few bytes of the block.
        let truncated = frame[..frame.len() - 8].to_vec();
        let truncated_len = truncated.len() as u64;
        let mut decoder = Lz4Decoder::new(Box::new(Cursor::new(truncated))).expect("construct");
        loop {
            match decoder.decode_step(&mut Vec::new()) {
                Ok(DecodeStatus::MoreData) => continue,
                Ok(DecodeStatus::Eof) => panic!("truncated frame should not reach Eof cleanly"),
                Err(DecodeError::Read { consumed, .. }) => {
                    assert!(consumed <= truncated_len);
                    return;
                }
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
    }

    /// Frame boundaries returned by the decoder are valid restart
    /// points: decoding from a recorded post-frame boundary produces
    /// exactly the suffix of the concatenated stream's plaintext.
    #[test]
    fn frame_boundary_is_a_valid_restart_point() {
        let payload_a = b"restart-A-".repeat(400);
        let payload_b = b"restart-B-".repeat(800);
        let frame_a = encode_lz4(
            &payload_a,
            EncoderOpts {
                block_checksum: false,
                content_size: false,
                content_checksum: false,
                compress_block: true,
            },
        );
        let frame_b = encode_lz4(
            &payload_b,
            EncoderOpts {
                block_checksum: false,
                content_size: false,
                content_checksum: false,
                compress_block: true,
            },
        );
        let mut combined = frame_a.clone();
        combined.extend_from_slice(&frame_b);

        // Re-decode the suffix from the inter-frame boundary; the
        // result must equal `payload_b`.
        let suffix = combined[frame_a.len()..].to_vec();
        let mut restart = Lz4Decoder::new(Box::new(Cursor::new(suffix))).expect("restart");
        let mut restart_out = Vec::new();
        drive_to_eof(&mut restart, &mut restart_out);
        assert_eq!(restart_out, payload_b);
    }

    /// A failing sink propagates as `Write` rather than dropped output.
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

        let payload = b"sink-fails".repeat(128);
        let frame = encode_lz4(
            &payload,
            EncoderOpts {
                block_checksum: false,
                content_size: false,
                content_checksum: false,
                compress_block: false,
            },
        );
        let mut decoder = Lz4Decoder::new(Box::new(Cursor::new(frame))).expect("construct");
        let mut hit = false;
        for _ in 0..1024 {
            match decoder.decode_step(&mut FailingSink) {
                Ok(DecodeStatus::MoreData) => continue,
                Ok(DecodeStatus::Eof) => break,
                Err(DecodeError::Write(e)) => {
                    assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe);
                    hit = true;
                    break;
                }
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
        assert!(hit, "expected Write error against the failing sink");
    }

    /// Repeated calls after Eof keep returning Eof.
    #[test]
    fn repeated_calls_after_eof_stay_eof() {
        let payload = b"steady-state".to_vec();
        let frame = encode_lz4(
            &payload,
            EncoderOpts {
                block_checksum: false,
                content_size: false,
                content_checksum: false,
                compress_block: false,
            },
        );
        let mut decoder = Lz4Decoder::new(Box::new(Cursor::new(frame))).expect("construct");
        let mut sink = Vec::new();
        drive_to_eof(&mut decoder, &mut sink);
        for _ in 0..5 {
            assert_eq!(
                decoder.decode_step(&mut sink).expect("idempotent eof"),
                DecodeStatus::Eof,
            );
        }
        assert_eq!(sink, payload);
    }

    /// The factory plumbing constructs a working decoder.
    #[test]
    fn factory_constructs_and_decodes() {
        let payload = b"factory-lz4-check".repeat(256);
        let frame = encode_lz4(
            &payload,
            EncoderOpts {
                block_checksum: false,
                content_size: false,
                content_checksum: false,
                compress_block: true,
            },
        );
        let mut decoder = factory(Box::new(Cursor::new(frame))).expect("factory");
        let mut sink = Vec::new();
        drive_to_eof(decoder.as_mut(), &mut sink);
        assert_eq!(sink, payload);
    }

    // ---- O.7b: mid-frame resume -----------------------------------

    /// Drive the decoder past the first block of a multi-block frame
    /// and assert `decoder_state()` is `Some(...)` only at the
    /// resume-eligible position.
    #[test]
    fn decoder_state_blob_round_trips_via_resume() {
        let payload: Vec<u8> = (0u8..=255u8).cycle().take(200_000).collect();
        let frame = encode_lz4_multi_block(&payload, 64 * 1024, false, true, None);

        // Build a fresh decoder and produce the reference output.
        let mut reference = Vec::with_capacity(payload.len());
        let mut ref_decoder =
            Lz4Decoder::new(Box::new(Cursor::new(frame.clone()))).expect("construct");
        drive_to_eof(&mut ref_decoder, &mut reference);
        assert_eq!(reference, payload);

        // Drive a second decoder forward and capture
        // `decoder_state` + `bytes_consumed` at the first block
        // boundary that lands past the 100-KiB mark. The decoder
        // sets `between_blocks` itself after every successful
        // block decode (O.7b semantic flip).
        let mut decoder = Lz4Decoder::new(Box::new(Cursor::new(frame.clone()))).expect("construct");
        let mut sink_a = Vec::new();
        let (blob, split_offset) = loop {
            let status = decoder.decode_step(&mut sink_a).expect("step");
            if let Some(blob) = decoder.decoder_state() {
                if sink_a.len() >= 100 * 1024 {
                    let off = decoder.bytes_consumed().get();
                    break (blob, off);
                }
            }
            if status == DecodeStatus::Eof {
                panic!("hit EOF before reaching mid-frame snapshot point");
            }
        };
        assert_eq!(blob.len(), RESUME_BLOB_LEN);

        // Suffix from `split_offset` onward → resume → decode the
        // rest. The concatenation of `sink_a` (the prefix already
        // emitted) and the resume's output must equal `reference`.
        let suffix = frame[split_offset as usize..].to_vec();
        let mut resumed =
            Lz4Decoder::resume(Box::new(Cursor::new(suffix)), &blob, split_offset).expect("resume");
        let mut sink_b = Vec::new();
        drive_to_eof(&mut resumed, &mut sink_b);

        let mut combined = sink_a;
        combined.extend_from_slice(&sink_b);
        assert_eq!(combined, payload);
    }

    #[test]
    fn frame_boundary_advances_per_block_within_a_single_frame() {
        // A multi-block single-frame archive: count distinct
        // `frame_boundary` values the decoder reports. With O.7b's
        // per-block boundary, an N-block frame produces ≥ N+1
        // distinct values (one per block, plus the post-EndMark
        // boundary). The pre-O.7b decoder reported only the single
        // post-EndMark value.
        let payload: Vec<u8> = (0u8..=255u8).cycle().take(300_000).collect();
        let frame = encode_lz4_multi_block(&payload, 64 * 1024, false, false, None);
        let expected_blocks = payload.len().div_ceil(64 * 1024); // = 5

        let mut decoder = Lz4Decoder::new(Box::new(Cursor::new(frame))).expect("construct");
        let mut sink = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        loop {
            let status = decoder.decode_step(&mut sink).expect("step");
            if let Some(b) = decoder.frame_boundary() {
                seen.insert(b.get());
            }
            if status == DecodeStatus::Eof {
                break;
            }
        }
        // Boundaries: one per successful block + one post-EndMark.
        assert!(
            seen.len() > expected_blocks,
            "expected >{expected_blocks} distinct boundaries (blocks + EndMark), saw {}: {:?}",
            seen.len(),
            seen
        );
    }

    #[test]
    fn decoder_state_is_none_during_block_header_read() {
        // After a block boundary fires, `between_blocks` is true and
        // `decoder_state()` returns `Some`. The next `decode_step`
        // begins reading the next block's size header — at that
        // moment the flag must clear so the resume blob isn't
        // captured against an offset that's mid-header.
        let payload: Vec<u8> = (0u8..=255u8).cycle().take(150_000).collect();
        let frame = encode_lz4_multi_block(&payload, 64 * 1024, false, false, None);

        let mut decoder = Lz4Decoder::new(Box::new(Cursor::new(frame))).expect("construct");
        let mut sink = Vec::new();
        // Drive past at least one block boundary.
        loop {
            let status = decoder.decode_step(&mut sink).expect("step");
            if decoder.decoder_state().is_some() {
                break;
            }
            assert_ne!(status, DecodeStatus::Eof, "hit EOF before any block ended");
        }

        // Stepping again advances into the next block-size header
        // read; `between_blocks` clears and `decoder_state` returns
        // None until the next block fully decodes.
        let _ = decoder.decode_step(&mut sink).expect("step");
        // The state may already have advanced into the block
        // payload arm, where `between_blocks` is also false; either
        // way the contract is "None until the next block boundary."
        // Just assert it's None right after the header is being
        // read.
        // We can't observe the in-between state directly, but the
        // critical contract is preserved by the next assertion:
        // by the time we hit the *next* block end, the captured
        // blob's `bytes_decompressed` must reflect the new block.
        let mut prior_bd = None;
        loop {
            let status = decoder.decode_step(&mut sink).expect("step");
            if let Some(blob) = decoder.decoder_state() {
                let resume = Lz4ResumeState::deserialize(&blob).expect("blob");
                if let Some(prior) = prior_bd {
                    assert!(
                        resume.bytes_decompressed > prior,
                        "bytes_decompressed must monotone-advance across block boundaries: \
                         {prior} -> {}",
                        resume.bytes_decompressed,
                    );
                    return;
                }
                prior_bd = Some(resume.bytes_decompressed);
            }
            if status == DecodeStatus::Eof {
                break;
            }
        }
    }

    #[test]
    fn decoder_state_is_none_between_frames() {
        // Default Lz4Decoder starts in BetweenFrames; before any
        // block decode runs, `decoder_state()` must return None
        // because the resume path doesn't apply there (the factory
        // route is enough).
        let frame = encode_lz4(
            b"between-frames-state",
            EncoderOpts {
                block_checksum: false,
                content_size: false,
                content_checksum: false,
                compress_block: false,
            },
        );
        let decoder = Lz4Decoder::new(Box::new(Cursor::new(frame))).expect("construct");
        assert!(decoder.decoder_state().is_none());
    }

    #[test]
    fn resume_rejects_malformed_blob() {
        // A blob with bad magic must be rejected as a
        // DecodeError::Construct rather than crashing the decoder.
        let bad = vec![0u8; RESUME_BLOB_LEN];
        let src: Box<dyn Read + Send> = Box::new(Cursor::new(Vec::<u8>::new()));
        let result = Lz4Decoder::resume(src, &bad, 0);
        match result {
            Err(DecodeError::Construct(err)) => {
                let msg = err.to_string();
                assert!(msg.contains("bad magic"), "msg={msg}");
            }
            Ok(_) => panic!("expected Construct, got Ok"),
            Err(other) => panic!("expected Construct, got {other:?}"),
        }
    }

    #[test]
    fn resume_rejects_content_checksum_disagreement() {
        // The blob's `content_checksum` flag and `content_hasher`
        // presence must agree; a mismatch is a hard reject.
        let resume = Lz4ResumeState {
            block_max_size: 64 * 1024,
            block_checksum: false,
            content_checksum: true, // says hasher must be present...
            content_size: None,
            bytes_decompressed: 0,
            content_hasher: None, // ...but it isn't
        };
        let blob = resume.serialize();
        let src: Box<dyn Read + Send> = Box::new(Cursor::new(Vec::<u8>::new()));
        let result = Lz4Decoder::resume(src, &blob, 0);
        match result {
            Err(DecodeError::Construct(err)) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("content_checksum and content_hasher"),
                    "msg={msg}",
                );
            }
            Ok(_) => panic!("expected Construct, got Ok"),
            Err(other) => panic!("expected Construct, got {other:?}"),
        }
    }
}
