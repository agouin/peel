//! lz4 streaming decoder for the [LZ4 Frame Format].
//!
//! Per `docs/PLAN_v2.md` §4 we drive the wire format ourselves and feed
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
//! [`StreamingDecoder::frame_boundary`] surfaces the offset
//! immediately after a complete LZ4 frame (its EndMark plus, when the
//! content-checksum flag is set, its 4-byte content checksum). The
//! coordinator restarts a fresh decoder at the saved boundary on
//! resume, so the only restart-safe positions are those where the
//! decoder is between frames — the frame's per-block parameters
//! (block-max-size, checksum flags, …) live in liblz4-flex-shaped
//! state that today is not serialized into the checkpoint, and a
//! restart from a mid-frame offset would have no way to interpret the
//! next bytes. Per-block (within-frame) checkpoint granularity
//! requires extending the checkpoint format with a serialized
//! [`FrameContext`] and is filed as a follow-on (`O.7b`); see
//! `docs/PLAN_v2.md` §4 round-one notes.
//!
//! Concatenated `cat a.lz4 b.lz4` streams therefore produce one
//! boundary per frame, which is the same shape `decode/xz.rs`
//! produces per Stream and `decode/zstd.rs` produces per zstd frame.
//! A `.tar.lz4` whose producer chose to emit one frame per tar
//! member (the harness pattern in
//! `tests/test_coordinator_crash.rs`) gets a boundary per member,
//! matching the per-member granularity the tar.xz / tar.zst harnesses
//! get.
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

/// Hand-rolled XXH32 used for the LZ4 frame's header, block, and
/// content checksums.
///
/// Public surface is the streaming [`Xxh32`] state plus the one-shot
/// [`xxh32`] free function. A standalone implementation is preferred
/// to pulling in `twox-hash` (the dep `lz4_flex`'s frame feature uses);
/// per `docs/ENGINEERING_STANDARDS.md` §2.1 we hand-roll trivial
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

    /// Streaming XXH32 state — used for the frame's content checksum,
    /// which must be computed across decompressed bytes from every
    /// block in the frame.
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
}
