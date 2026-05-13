//! gzip framing wrapper around the hand-rolled deflate decoder
//! (RFC 1952).
//!
//! The deflate decoder at [`super::Decoder`] understands raw
//! deflate streams (the BTYPE=00/01/10 block types described in
//! RFC 1951). gzip wraps each deflate stream in a
//! [`member`-shaped envelope][rfc1952]:
//!
//! ```text
//!   ID1   ID2   CM    FLG   MTIME(4)   XFL   OS    optional fields  deflate stream  CRC32(4)  ISIZE(4)
//!  0x1F  0x8B   ?     ?     ────────   ?     ?     FEXTRA/FNAME/    (RFC 1951)      (over     (low 32
//!                                                  FCOMMENT/FHCRC                    decompressed   bits of
//!                                                  per FLG bits)                     bytes)         ISIZE)
//! ```
//!
//! Concatenated members are valid gzip — `gunzip -c a.gz b.gz` and
//! the equivalent in any conformant decoder picks each member up in
//! turn. The wrapper here preserves that property: after a clean
//! member trailer it probes for another `ID1 ID2` magic and either
//! starts the next member or transitions to clean EOF.
//!
//! # Architecture
//!
//! [`GzipDecoder`] owns the same [`super::bitstream::BitReader`]
//! across header / deflate-body / trailer phases. While inside the
//! deflate body, the bit reader is temporarily moved into an inner
//! [`super::Decoder`] (via [`super::Decoder::from_bits`]); when the
//! deflate stream cleanly hits EOB on the `BFINAL=1` block the bit
//! reader is recovered (via [`super::Decoder::into_bits`]) so the
//! gzip layer can byte-align it and read the trailer. The outer
//! state machine never holds both at once.
//!
//! # CRC32 + ISIZE accounting
//!
//! Every byte the inner deflate decoder writes to its sink is
//! tee'd into a running [`Crc32`] hasher and an `ISIZE` low-32-bit
//! counter via [`CrcTeeSink`]. At end-of-deflate we compare the
//! hasher's finalised CRC and the wrap-around counter against the
//! 8-byte trailer; mismatches surface as
//! [`DeflateError::GzipCrcMismatch`] or
//! [`DeflateError::GzipIsizeMismatch`].
//!
//! # `frame_boundary` and `bytes_consumed`
//!
//! Member boundaries — the byte cursor immediately past the
//! trailer of a successfully-validated member — are valid restart
//! points: a fresh [`GzipDecoder`] reading from that offset
//! produces the suffix of the original output. The wrapper records
//! the boundary at trailer-validation time and surfaces it via
//! [`StreamingDecoder::frame_boundary`]. `bytes_consumed` reports
//! the bit reader's byte-floor regardless of which phase owns the
//! reader.
//!
//! [rfc1952]: https://www.rfc-editor.org/rfc/rfc1952

use std::io::{self, Read, Write};

use crate::decode::{DecodeError, DecodeStatus, StreamingDecoder};
use crate::types::ByteOffset;
use crate::zip::crc32::Crc32;

use super::bitstream::BitReader;
use super::error::DeflateError;
use super::relabel_eof;

/// FLG bit assignments (RFC 1952 §2.3.1.2).
const FLG_FTEXT: u8 = 0x01;
const FLG_FHCRC: u8 = 0x02;
const FLG_FEXTRA: u8 = 0x04;
const FLG_FNAME: u8 = 0x08;
const FLG_FCOMMENT: u8 = 0x10;
/// Bit mask covering the three reserved FLG bits (5..=7).
const FLG_RESERVED: u8 = 0xE0;

/// Streaming gzip decoder.
///
/// Wraps a [`super::Decoder`] (the hand-rolled deflate body) with
/// the RFC 1952 framing. Owns the source on construction; the
/// trait-level [`StreamingDecoder::decode_step`] drives header
/// parsing → deflate body → trailer validation → member chaining
/// → clean EOF.
pub struct GzipDecoder {
    state: State,
    /// The bit reader that walks the entire gzip stream.
    /// `Some(_)` when the wrapper itself owns it (header / trailer
    /// / between-members / done states); `None` while the inner
    /// deflate decoder owns it (in-deflate-body state).
    bits: Option<BitReader>,
    /// The inner deflate decoder. `Some(_)` while we're inside a
    /// member's deflate stream; `None` otherwise.
    inner: Option<super::Decoder>,
    /// Running CRC32 over the decompressed bytes of the current
    /// member. Reset at the start of each member.
    running_crc: Crc32,
    /// Low 32 bits of the running decompressed-byte counter for
    /// the current member. Reset at the start of each member;
    /// wraps on overflow (RFC 1952 §2.3.1.5: ISIZE is "the size of
    /// the original (uncompressed) input data modulo 2^32").
    running_isize: u32,
    /// Latest member-end boundary, in source bytes. Set when a
    /// member's trailer validates cleanly; carried across decode
    /// steps so [`StreamingDecoder::frame_boundary`] is monotone.
    last_frame_boundary: Option<ByteOffset>,
    /// CRC-32 the most-recently-validated member's trailer recorded.
    /// `None` until the first member's trailer lands. Read via
    /// [`Self::last_member_crc32`]; used by the
    /// [`super::members::scan_first_member`] helper to populate
    /// [`super::members::GzMemberRecord::crc32`] without re-decoding
    /// the bytes. Persists across the inter-member transition until
    /// the next member's trailer lands.
    last_member_crc32: Option<u32>,
    /// ISIZE (low 32 bits of decompressed length, RFC 1952 §2.3.1.5)
    /// the most-recently-validated member's trailer recorded. `None`
    /// until the first member's trailer lands. Lives next to
    /// [`Self::last_member_crc32`] for the same reason.
    last_member_isize: Option<u32>,
    /// Count of members whose trailers have validated cleanly so
    /// far. Read via [`Self::members_scanned`]; the parallel path's
    /// entry condition gates on `≥ 2`. Resets only on a fresh
    /// [`Self::new`] / [`super::members::scan_first_member`] call;
    /// monotonically non-decreasing across decode steps.
    members_scanned: u32,
}

/// Outer state machine for the gzip wrapper.
#[derive(Debug)]
enum State {
    /// At the start of a (sub)stream. Need to read and validate the
    /// gzip member header.
    AwaitingHeader,
    /// Inside a member's deflate body. The inner deflate decoder
    /// owns the bit reader; CRC + ISIZE accumulate in the wrapper.
    InDeflateBody,
    /// Deflate body has cleanly hit Eof. Need to byte-align the
    /// bit reader (RFC 1951 final-block bit-skip rule), then read
    /// and validate the 8-byte trailer.
    AwaitingTrailer,
    /// Member trailer validated. Probe for another member header
    /// (concatenated members are valid gzip per RFC 1952 §2.2);
    /// transition to `AwaitingHeader` if more bytes follow,
    /// else `Done`.
    BetweenMembers,
    /// Stream cleanly ended. Subsequent steps return EOF.
    Done,
}

/// `Write` adapter that tees decompressed bytes from the inner
/// deflate decoder into a running CRC32 hasher and ISIZE counter,
/// then forwards them to the user-supplied sink.
struct CrcTeeSink<'a> {
    inner: &'a mut dyn Write,
    crc: &'a mut Crc32,
    isize_low32: &'a mut u32,
}

impl<'a> Write for CrcTeeSink<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        // INVARIANT: n ≤ buf.len() per the Read contract; the
        // updates only count bytes actually accepted by the sink.
        self.crc.update(&buf[..n]);
        // INVARIANT: n ≤ buf.len() ≤ usize::MAX, so `as u32`
        // truncating is the desired behavior — RFC 1952 §2.3.1.5
        // wraps ISIZE at 2^32.
        *self.isize_low32 = self.isize_low32.wrapping_add(n as u32);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl GzipDecoder {
    /// Construct a [`GzipDecoder`] over `src`. Does not pull any
    /// bytes from the source.
    ///
    /// # Errors
    ///
    /// Currently never returns `Err`; the signature is fallible to
    /// match [`crate::decode::DecoderFactory`].
    pub fn new(src: Box<dyn Read + Send>) -> Result<Self, DecodeError> {
        Ok(Self {
            state: State::AwaitingHeader,
            bits: Some(BitReader::new(src)),
            inner: None,
            running_crc: Crc32::new(),
            running_isize: 0,
            last_frame_boundary: None,
            last_member_crc32: None,
            last_member_isize: None,
            members_scanned: 0,
        })
    }

    /// Number of gzip members whose trailers have validated cleanly
    /// since construction. Phase 2 of [`internal/PLAN_gzip_throughput.md`]:
    /// the parallel-path entry condition gates on
    /// `members_scanned() >= 2`, and the [`super::members`] scanner
    /// helpers loop until this advances.
    #[must_use]
    pub fn members_scanned(&self) -> u32 {
        self.members_scanned
    }

    /// CRC-32 the most-recently-validated member's trailer recorded.
    /// `None` until the first member's trailer lands. Carries the
    /// per-member CRC across the inter-member transition (the
    /// running CRC32 hasher resets on the next member's
    /// `AwaitingHeader → InDeflateBody` transition; this field
    /// persists). Used by [`super::members::scan_first_member`] to
    /// populate [`super::members::GzMemberRecord::crc32`].
    #[must_use]
    pub fn last_member_crc32(&self) -> Option<u32> {
        self.last_member_crc32
    }

    /// ISIZE (RFC 1952 §2.3.1.5: low 32 bits of decompressed length)
    /// the most-recently-validated member's trailer recorded. `None`
    /// until the first member's trailer lands. Sister of
    /// [`Self::last_member_crc32`].
    #[must_use]
    pub fn last_member_isize(&self) -> Option<u32> {
        self.last_member_isize
    }

    /// Mirror of [`StreamingDecoder::decode_step`] that returns the
    /// internal [`DeflateError`] vocabulary instead of round-tripping
    /// through [`DecodeError`]'s flattened `io::Error::other(...)`.
    /// Phase 2 of [`internal/PLAN_gzip_throughput.md`]: the
    /// [`super::members`] scanner needs the typed variants
    /// (`UnexpectedEof` vs `GzipBadMagic` vs `GzipCrcMismatch`) so
    /// the coordinator can discriminate "retry / wrong format / fail
    /// closed" without parsing message strings.
    ///
    /// Same terminal-error contract as [`Self::decode_step`]: any
    /// error clamps the wrapper to `Done` and drops the inner
    /// decoder + bit reader so subsequent calls cleanly short-
    /// circuit.
    pub(super) fn step_typed(
        &mut self,
        sink: &mut dyn Write,
    ) -> Result<DecodeStatus, DeflateError> {
        if matches!(self.state, State::Done) {
            return Ok(DecodeStatus::Eof);
        }
        match self.step_inner(sink) {
            Ok(status) => Ok(status),
            Err(e) => {
                self.state = State::Done;
                self.inner = None;
                self.bits = None;
                Err(e)
            }
        }
    }

    /// Source-byte high-water mark, regardless of which phase owns
    /// the bit reader. Mirrors the convention from
    /// [`super::Decoder::bytes_consumed`].
    fn current_byte_consumed(&self) -> u64 {
        if let Some(bits) = &self.bits {
            bits.byte_position().0
        } else if let Some(inner) = &self.inner {
            inner.bytes_consumed().get()
        } else {
            // Both `None` is a transient-state-machine bug; reach
            // here and we've lost track of cursor. Return 0 so the
            // error path's `consumed` field stays bounded.
            0
        }
    }

    /// Internal: one decode-step body returning the local error
    /// type. The trait-level wrapper translates to [`DecodeError`].
    ///
    /// Each call advances the wrapper by exactly one state-machine
    /// transition (or one inner-deflate `decode_step`). This
    /// per-step granularity is intentional: it ensures the caller
    /// observes [`StreamingDecoder::frame_boundary`] at each
    /// member-end before the wrapper barrels into the next
    /// member's deflate body. A coarser "loop until output / Eof"
    /// granularity would silently merge two member-boundary
    /// updates into one observable jump, losing the per-member
    /// boundary cadence the extractor's checkpoint observer
    /// depends on.
    fn step_inner(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, DeflateError> {
        match self.state {
            State::Done => Ok(DecodeStatus::Eof),

            State::AwaitingHeader => {
                self.parse_member_header()?;
                // Hand the bit reader off to the inner deflate
                // decoder for the duration of this member.
                let bits = self
                    .bits
                    .take()
                    .expect("bits owned in AwaitingHeader state");
                self.inner = Some(super::Decoder::from_bits(bits));
                self.running_crc = Crc32::new();
                self.running_isize = 0;
                self.state = State::InDeflateBody;
                Ok(DecodeStatus::MoreData)
            }

            State::InDeflateBody => {
                let inner = self
                    .inner
                    .as_mut()
                    .expect("inner decoder owned in InDeflateBody state");
                let mut tee = CrcTeeSink {
                    inner: sink,
                    crc: &mut self.running_crc,
                    isize_low32: &mut self.running_isize,
                };
                let status = match inner.decode_step(&mut tee) {
                    Ok(s) => s,
                    Err(DecodeError::Read { source, .. }) => {
                        return Err(DeflateError::SourceIo(source));
                    }
                    Err(DecodeError::Write(source)) => {
                        return Err(DeflateError::SinkIo(source));
                    }
                    Err(DecodeError::Construct(source)) => {
                        return Err(DeflateError::SourceIo(source));
                    }
                    Err(DecodeError::ResumeMismatch { .. }) => {
                        // The inner decoder only surfaces this
                        // when constructed via the resume
                        // factory; we constructed via
                        // `from_bits`, so this is unreachable.
                        return Err(DeflateError::SourceIo(io::Error::other(
                            "deflate inner decoder reported ResumeMismatch unexpectedly",
                        )));
                    }
                };
                match status {
                    DecodeStatus::MoreData => Ok(DecodeStatus::MoreData),
                    DecodeStatus::Eof => {
                        // Deflate stream done. Recover the bit
                        // reader for the trailer phase.
                        let inner = self
                            .inner
                            .take()
                            .expect("inner decoder owned in InDeflateBody state");
                        self.bits = Some(inner.into_bits());
                        self.state = State::AwaitingTrailer;
                        Ok(DecodeStatus::MoreData)
                    }
                }
            }

            State::AwaitingTrailer => {
                let (recorded_crc, recorded_isize) = self.read_and_validate_trailer()?;
                // Member done. Record the boundary at the current
                // byte cursor (now past the trailer) plus the
                // per-member CRC32 / ISIZE so the
                // [`super::members::scan_first_member`] helper can
                // pull them out without re-decoding.
                let bits = self
                    .bits
                    .as_ref()
                    .expect("bits owned in AwaitingTrailer state");
                let boundary = bits.byte_position().0;
                self.last_frame_boundary = Some(ByteOffset::new(boundary));
                self.last_member_crc32 = Some(recorded_crc);
                self.last_member_isize = Some(recorded_isize);
                self.members_scanned = self.members_scanned.saturating_add(1);
                self.state = State::BetweenMembers;
                Ok(DecodeStatus::MoreData)
            }

            State::BetweenMembers => {
                // Probe for the first byte of the next member.
                // Soft-ensure: at clean EOF the bit reader has 0
                // bits buffered.
                let bits = self
                    .bits
                    .as_mut()
                    .expect("bits owned in BetweenMembers state");
                bits.ensure(8)?;
                if bits.bits_buffered() == 0 {
                    // Source is exhausted; clean stream end.
                    self.state = State::Done;
                } else {
                    // More bytes follow. Defer header parsing to
                    // the next call's AwaitingHeader arm — keeps
                    // the per-step granularity uniform and matches
                    // the existing flate2-based wrapper's
                    // step-per-member-transition cadence at
                    // `crate::decode::gzip` line 287-304.
                    self.state = State::AwaitingHeader;
                }
                Ok(DecodeStatus::MoreData)
            }
        }
    }

    /// Parse a single gzip member header off the bit reader.
    /// Assumes the bit cursor is byte-aligned (caller is the
    /// AwaitingHeader / BetweenMembers state, both of which exit
    /// with the cursor at a byte boundary).
    fn parse_member_header(&mut self) -> Result<(), DeflateError> {
        let bits = self
            .bits
            .as_mut()
            .expect("bits owned during header parsing");
        debug_assert_eq!(bits.byte_position().1, 0);

        // Fixed 10-byte header: ID1 ID2 CM FLG MTIME(4) XFL OS.
        let mut fixed = [0u8; 10];
        relabel_eof(bits.read_aligned(&mut fixed), "gzip header")?;
        if fixed[0] != 0x1F || fixed[1] != 0x8B {
            return Err(DeflateError::GzipBadMagic {
                id1: fixed[0],
                id2: fixed[1],
            });
        }
        if fixed[2] != 0x08 {
            return Err(DeflateError::GzipUnsupportedCompressionMethod { cm: fixed[2] });
        }
        let flg = fixed[3];
        if flg & FLG_RESERVED != 0 {
            return Err(DeflateError::GzipReservedFlag { flg });
        }
        // bytes 4..=7: MTIME (skip); byte 8: XFL (skip); byte 9: OS
        // (skip). RFC 1952 only requires MTIME be a valid Unix
        // timestamp or zero; we don't surface or validate them.
        let _ = (FLG_FTEXT, FLG_FHCRC); // FTEXT informational only

        // Optional FEXTRA: 2-byte XLEN little-endian + XLEN bytes.
        if flg & FLG_FEXTRA != 0 {
            let mut xlen_buf = [0u8; 2];
            relabel_eof(bits.read_aligned(&mut xlen_buf), "gzip FEXTRA xlen")?;
            let xlen = u16::from_le_bytes(xlen_buf) as usize;
            if xlen > 0 {
                let mut extra = vec![0u8; xlen];
                relabel_eof(bits.read_aligned(&mut extra), "gzip FEXTRA payload")?;
                let _ = extra;
            }
        }

        // Optional FNAME: NUL-terminated string. Read byte-by-byte
        // until NUL — the bit reader's read_aligned fast-path needs
        // a known length, so the per-byte read_bits(8) is the right
        // primitive here.
        if flg & FLG_FNAME != 0 {
            loop {
                let b = relabel_eof(bits.read_bits(8), "gzip FNAME")? as u8;
                if b == 0 {
                    break;
                }
            }
        }

        // Optional FCOMMENT: NUL-terminated string.
        if flg & FLG_FCOMMENT != 0 {
            loop {
                let b = relabel_eof(bits.read_bits(8), "gzip FCOMMENT")? as u8;
                if b == 0 {
                    break;
                }
            }
        }

        // Optional FHCRC: 2-byte CRC16 of the header. Round-one
        // skips validation (matches the existing flate2-based
        // wrapper's behavior, which also defers to the underlying
        // library and doesn't surface FHCRC mismatches as a typed
        // error). Phase 11 may add validation if real-world
        // archives need it.
        if flg & FLG_FHCRC != 0 {
            let mut hcrc = [0u8; 2];
            relabel_eof(bits.read_aligned(&mut hcrc), "gzip FHCRC")?;
            let _ = hcrc;
        }

        Ok(())
    }

    /// Byte-align the bit cursor (RFC 1951's "any incomplete bits
    /// of the final byte are skipped" rule), then read and
    /// validate the 8-byte trailer (CRC32 + ISIZE) against the
    /// running counters. Returns `(recorded_crc, recorded_isize)`
    /// on success so the caller can stash them on the wrapper for
    /// [`Self::last_member_crc32`] / [`Self::last_member_isize`]
    /// without re-decoding.
    fn read_and_validate_trailer(&mut self) -> Result<(u32, u32), DeflateError> {
        let bits = self
            .bits
            .as_mut()
            .expect("bits owned during trailer parsing");
        bits.align_to_byte();
        let mut trailer = [0u8; 8];
        relabel_eof(bits.read_aligned(&mut trailer), "gzip trailer")?;
        let recorded_crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
        let recorded_isize = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
        let computed_crc = self.running_crc.finalize();
        if computed_crc != recorded_crc {
            return Err(DeflateError::GzipCrcMismatch {
                expected: recorded_crc,
                computed: computed_crc,
            });
        }
        if self.running_isize != recorded_isize {
            return Err(DeflateError::GzipIsizeMismatch {
                expected: recorded_isize,
                computed: self.running_isize,
            });
        }
        Ok((recorded_crc, recorded_isize))
    }
}

impl StreamingDecoder for GzipDecoder {
    fn decode_step(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, DecodeError> {
        if matches!(self.state, State::Done) {
            return Ok(DecodeStatus::Eof);
        }
        match self.step_inner(sink) {
            Ok(status) => Ok(status),
            Err(e) => {
                let consumed = self.current_byte_consumed();
                // Errors are terminal — clamp to Done so further
                // calls cleanly short-circuit. Drop both the
                // potential inner decoder and the bit reader; the
                // source they own goes with them.
                self.state = State::Done;
                self.inner = None;
                self.bits = None;
                Err(e.into_decode_error(consumed))
            }
        }
    }

    fn bytes_consumed(&self) -> ByteOffset {
        ByteOffset::new(self.current_byte_consumed())
    }

    fn frame_boundary(&self) -> Option<ByteOffset> {
        // While the inner deflate decoder owns the bit reader,
        // its per-deflate-block boundary is the latest restart
        // point inside the current member — strictly more recent
        // than the previous member's end (which is what
        // `last_frame_boundary` carries here). Delegate to the
        // inner so the extractor's quiescent-checkpoint loop
        // fires the puncher at every block boundary within a
        // single-member archive (Phase 10 of
        // `internal/PLAN_deflate_block_decoder.md`). The blob this
        // wrapper emits at the same checkpoint
        // ([`Self::decoder_state`]) carries the running CRC32 +
        // ISIZE counter the resume needs.
        if let Some(inner) = &self.inner {
            if let Some(b) = inner.frame_boundary() {
                return Some(b);
            }
        }
        self.last_frame_boundary
    }

    fn set_source_start_offset(&mut self, offset: u64) {
        // Gzip wraps a `BitReader` that reports the source-byte floor;
        // align it the same way the bare deflate decoder does. Only
        // reseat when the BitReader is fresh — the `resume_factory`
        // path hands the cursor to an inner deflate decoder
        // (`self.bits = None`) that has already been seeded and may
        // have consumed bits, and even when the wrapper retains
        // ownership the BitReader can be mid-pull.
        if let Some(bits) = self.bits.as_mut() {
            if bits.is_untouched() {
                bits.set_byte_offset(offset);
            }
        }
        if let Some(inner) = self.inner.as_mut() {
            inner.set_source_start_offset(offset);
        }
    }

    fn decoder_state_into(&self, out: &mut Vec<u8>) -> bool {
        // Gzip blobs only round-trip mid-deflate-body, when the
        // inner decoder is at a deflate-block boundary. Between
        // members the per-member `frame_boundary` is restartable
        // via the regular factory at that offset; mid-header /
        // mid-trailer have no clean restart point. Mirrors
        // `Lz4Decoder::between_blocks` and the zstd analogue.
        if !matches!(self.state, State::InDeflateBody) {
            return false;
        }
        let Some(inner) = self.inner.as_ref() else {
            return false;
        };
        let Some(inner_blob) = inner.decoder_state() else {
            return false;
        };
        // The inner blob's container is RawDeflate; rewrap as Gzip
        // and inject the wrapper's running CRC32 / ISIZE. Round-
        // tripping through deserialise + reserialise is a small
        // cost (≤ 33 KiB) and keeps the gzip layer from having to
        // know the inner blob's wire format.
        let mut state = match super::resume::DflResumeState::deserialize(&inner_blob) {
            Ok(s) => s,
            Err(_) => {
                // Inner blob shape is internal to our crate; a
                // deserialize failure here would be a bug, not a
                // legitimate caller error. Return `false` so the
                // coordinator falls back to the regular factory at
                // the per-member frame_boundary.
                return false;
            }
        };
        state.container = super::resume::Container::Gzip;
        state.running_crc32 = self.running_crc.current();
        state.total_decompressed = u64::from(self.running_isize);
        out.extend_from_slice(&state.serialize());
        true
    }
}

/// [`crate::decode::DecoderFactory`] adapter for [`GzipDecoder`].
///
/// Not registered by [`crate::decode::DecoderRegistry::with_defaults`]
/// in Phase 6 — the production gzip path still goes through
/// [`crate::decode::gzip::factory`] / `flate2`. Phase 8 swaps the
/// registration once Phase 7's resume support has landed.
///
/// # Errors
///
/// Forwards any error returned by [`GzipDecoder::new`].
pub fn factory(src: Box<dyn Read + Send>) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    Ok(Box::new(GzipDecoder::new(src)?))
}

/// [`crate::decode::DecoderResumeFactory`] adapter for
/// [`GzipDecoder`].
///
/// Reconstructs a wrapper sitting at a mid-member deflate-block
/// boundary: the inner deflate decoder's state is restored from
/// the blob's deflate-half (window snapshot + bit cursor), and
/// the gzip framing's running CRC32 + ISIZE counter are restored
/// from the blob's gzip-half so the trailer-validation phase
/// after the resumed deflate stream produces the same outcome a
/// clean run would.
///
/// `start_offset` must equal the blob's
/// `source_byte_position`; mismatch surfaces as
/// [`DecodeError::ResumeMismatch`].
///
/// # Errors
///
/// - [`DecodeError::Construct`] when the blob is malformed or the
///   bit-offset skip would read past the end of `src`.
/// - [`DecodeError::ResumeMismatch`] when `start_offset` doesn't
///   match the blob's saved cursor.
pub fn resume_factory(
    src: Box<dyn Read + Send>,
    state_blob: &[u8],
    start_offset: u64,
) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    let state = super::resume::deserialize_at_boundary(state_blob, start_offset)?;
    if state.container != super::resume::Container::Gzip {
        return Err(DecodeError::Construct(io::Error::other(
            "gzip resume blob rejected: expected container=Gzip",
        )));
    }

    // Restore the running CRC32 + ISIZE counter from the blob's
    // gzip-half. The hasher's seed() method primes the internal
    // state to the captured running value (NOT the finalised
    // CRC), so subsequent updates compound correctly with the
    // original prefix's contribution.
    let mut running_crc = Crc32::new();
    running_crc.seed(state.running_crc32);
    // INVARIANT: bytes_decompressed_in_member is u64 in the blob,
    // u32 here — the trailer's ISIZE is mod 2^32 by spec, so the
    // low-32 truncation is the desired behavior.
    let running_isize = state.total_decompressed as u32;

    // The deflate-half of the blob feeds an inner deflate decoder
    // resumed at the same source byte / bit offset. We rewrap the
    // state so `Decoder::resume` sees a RawDeflate container.
    let deflate_state = super::resume::DflResumeState {
        container: super::resume::Container::RawDeflate,
        ..state
    };
    let inner = super::Decoder::resume(src, deflate_state)?;

    // The wrapper takes the inner decoder back over and re-enters
    // `InDeflateBody`. The bit reader currently lives inside the
    // inner decoder; the wrapper reclaims it after the deflate
    // stream hits Eof, exactly the same path the non-resume run
    // takes.
    let last_frame_boundary = Some(ByteOffset::new(start_offset));
    Ok(Box::new(GzipDecoder {
        state: State::InDeflateBody,
        bits: None,
        inner: Some(inner),
        running_crc,
        running_isize,
        last_frame_boundary,
        // The resume blob captures the prefix of one in-progress
        // member (Phase 7 of `PLAN_deflate_block_decoder.md`); no
        // member's trailer has validated *in this resumed
        // GzipDecoder*, so the per-member fields stay `None` until
        // the resumed member's own trailer lands.
        last_member_crc32: None,
        last_member_isize: None,
        members_scanned: 0,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    use flate2::bufread::GzEncoder;
    use flate2::Compression;

    /// Encode `payload` as a single-member gzip blob using
    /// flate2's default compression level — matches the existing
    /// `crate::decode::gzip::tests::encode_gzip` helper so the
    /// ported tests land on identical bytes.
    fn encode_gzip(payload: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(payload, Compression::default());
        let mut out = Vec::with_capacity(payload.len() / 2 + 32);
        encoder.read_to_end(&mut out).expect("encode");
        out
    }

    /// Drive a decoder to EOF and return the collected output.
    fn decode_all(stream: Vec<u8>) -> Vec<u8> {
        let mut decoder = GzipDecoder::new(Box::new(Cursor::new(stream))).expect("construct");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode_step") == DecodeStatus::MoreData {}
        sink
    }

    #[test]
    fn single_member_round_trip() {
        let payload = b"hello, gzip frame world!".repeat(2048);
        let compressed = encode_gzip(&payload);
        let mut decoder =
            GzipDecoder::new(Box::new(Cursor::new(compressed.clone()))).expect("construct");

        let mut sink = Vec::with_capacity(payload.len());
        while let DecodeStatus::MoreData = decoder.decode_step(&mut sink).expect("decode_step") {}

        assert_eq!(sink, payload);
        assert_eq!(decoder.bytes_consumed().get(), compressed.len() as u64);
        assert_eq!(
            decoder.frame_boundary(),
            Some(ByteOffset::new(compressed.len() as u64))
        );
    }

    /// Phase 0 of `internal/PLAN_gzip_throughput.md`: cross-validate the
    /// hand-rolled streaming wrapper against `flate2`'s
    /// `MultiGzDecoder` on an 8-member fixture (the `pigz`/concat
    /// shape the parallel-member work in later phases targets). This
    /// guards against drift between the streaming-path output and
    /// the differential reference before the parallel path is layered
    /// on; round-one parallel decode reuses this same single-member
    /// inner loop, so any divergence here would corrupt the parallel
    /// path's per-member output too.
    #[test]
    fn multi_member_eight_member_round_trip_matches_flate2() {
        // Eight ~1 KiB members with distinct contents. Sized to keep
        // the test fast on debug builds while still exercising the
        // outer state-machine transitions across all members.
        let mut combined = Vec::new();
        let mut expected = Vec::new();
        for i in 0u8..8 {
            let payload: Vec<u8> = (0..1024)
                .map(|j| (j as u8).wrapping_add(i.wrapping_mul(31)))
                .collect();
            combined.extend_from_slice(&encode_gzip(&payload));
            expected.extend_from_slice(&payload);
        }

        // peel's hand-rolled decoder.
        let peel_out = decode_all(combined.clone());
        assert_eq!(
            peel_out, expected,
            "peel multi-member output differs from concatenated payloads"
        );

        // flate2's MultiGzDecoder reference. Cross-validates the
        // wire-format interpretation; differential corpus expansion
        // (Phase 2 of the plan) will widen this to a 50-fixture sweep.
        let mut flate_out = Vec::new();
        flate2::read::MultiGzDecoder::new(Cursor::new(combined.clone()))
            .read_to_end(&mut flate_out)
            .expect("flate2 multi-member decode");
        assert_eq!(
            peel_out, flate_out,
            "peel multi-member output differs from flate2's MultiGzDecoder"
        );
    }

    /// Phase 2 of `internal/PLAN_gzip_throughput.md`: tighten the
    /// per-member contract. `frame_boundary()` must advance exactly
    /// once per member (no spurious advances within a member's
    /// deflate body — those go through the inner deflate decoder's
    /// per-block boundary, not the gzip wrapper's last-frame field),
    /// and `members_scanned()` must increment in lockstep with each
    /// observed boundary advance. The parallel-path entry condition
    /// gates on `members_scanned() >= 2`, so this contract is
    /// load-bearing for the Phase 3 dispatch decision.
    #[test]
    fn frame_boundary_advances_per_member_in_multi_member_stream() {
        // Six members of distinct sizes so any "boundary observed
        // twice" or "boundary skipped" bug surfaces directly in the
        // expected vector.
        let mut combined = Vec::new();
        let mut expected_offsets = Vec::new();
        let mut cursor = 0u64;
        for i in 0u8..6 {
            let payload: Vec<u8> = (0..(512 * (i as usize + 1)))
                .map(|j| (j as u8).wrapping_add(i.wrapping_mul(13)))
                .collect();
            let blob = encode_gzip(&payload);
            cursor += blob.len() as u64;
            combined.extend_from_slice(&blob);
            expected_offsets.push(cursor);
        }

        let mut decoder =
            GzipDecoder::new(Box::new(Cursor::new(combined.clone()))).expect("construct");
        let mut sink = Vec::new();
        let mut observed_offsets: Vec<u64> = Vec::new();
        let mut observed_counts: Vec<u32> = Vec::new();
        let mut last_boundary = decoder.frame_boundary();
        loop {
            let status = decoder.decode_step(&mut sink).expect("decode_step");
            // We're checking *gzip-wrapper* per-member advances —
            // that means the wrapper's `last_frame_boundary` field,
            // which is only observable as `frame_boundary()` between
            // members (i.e. when the inner deflate decoder is not
            // owning the bit reader). Use `members_scanned()` as the
            // load-bearing per-member counter; sample
            // `frame_boundary()` whenever the count advances.
            let count = decoder.members_scanned();
            let expected_seen = observed_counts.last().copied().unwrap_or(0);
            if count > expected_seen {
                // The wrapper is now in `BetweenMembers` /
                // `Done` state, so `frame_boundary()` returns the
                // wrapper's `last_frame_boundary` rather than
                // delegating to a non-existent inner decoder.
                let boundary = decoder
                    .frame_boundary()
                    .expect("frame_boundary observable after a member's trailer validates");
                observed_offsets.push(boundary.get());
                observed_counts.push(count);
                last_boundary = Some(boundary);
            } else {
                // Within a member: the boundary must not have moved
                // backward (monotone), and must equal the previous
                // observation while we're inside the deflate body.
                if let (Some(prev), Some(curr)) = (last_boundary, decoder.frame_boundary()) {
                    assert!(
                        curr >= prev,
                        "frame_boundary regressed: {prev:?} → {curr:?}",
                    );
                }
            }
            if status == DecodeStatus::Eof {
                break;
            }
        }

        assert_eq!(
            observed_offsets, expected_offsets,
            "per-member boundaries must match the encoded layout exactly",
        );
        assert_eq!(
            observed_counts,
            (1u32..=expected_offsets.len() as u32).collect::<Vec<_>>(),
            "members_scanned must increment in lockstep with each observed boundary",
        );
        assert_eq!(
            decoder.members_scanned(),
            expected_offsets.len() as u32,
            "final members_scanned must equal the number of encoded members",
        );
        assert_eq!(decoder.bytes_consumed().get(), combined.len() as u64);
    }

    #[test]
    fn multi_member_round_trip_records_each_boundary() {
        let payload_a = b"member A payload".repeat(512);
        let payload_b = b"member B payload, longer".repeat(700);
        let member_a = encode_gzip(&payload_a);
        let member_b = encode_gzip(&payload_b);
        let mut combined = member_a.clone();
        combined.extend_from_slice(&member_b);

        let mut decoder =
            GzipDecoder::new(Box::new(Cursor::new(combined.clone()))).expect("construct");

        let mut sink = Vec::new();
        let mut boundaries: Vec<u64> = Vec::new();
        loop {
            let prior = decoder.frame_boundary();
            let status = decoder.decode_step(&mut sink).expect("decode_step");
            let next = decoder.frame_boundary();
            if next != prior {
                boundaries.push(next.expect("just observed").get());
            }
            if status == DecodeStatus::Eof {
                break;
            }
        }

        let mut expected = payload_a.clone();
        expected.extend_from_slice(&payload_b);
        assert_eq!(sink, expected);
        assert_eq!(boundaries.len(), 2, "boundaries={boundaries:?}");
        assert_eq!(boundaries[0], member_a.len() as u64, "member A end");
        assert_eq!(boundaries[1], combined.len() as u64, "member B end");
        assert_eq!(decoder.bytes_consumed().get(), combined.len() as u64);
    }

    #[test]
    fn bytes_consumed_is_monotone() {
        let payload = b"gzip monotone payload".repeat(1024);
        let member = encode_gzip(&payload);
        let mut combined = member.clone();
        combined.extend_from_slice(&member);

        let mut decoder =
            GzipDecoder::new(Box::new(Cursor::new(combined.clone()))).expect("construct");

        let mut last = 0u64;
        loop {
            let status = decoder
                .decode_step(&mut std::io::sink())
                .expect("decode_step");
            let now = decoder.bytes_consumed().get();
            assert!(now >= last, "bytes_consumed regressed from {last} to {now}");
            last = now;
            if status == DecodeStatus::Eof {
                break;
            }
        }

        assert_eq!(last, combined.len() as u64);
    }

    #[test]
    fn bytes_consumed_never_exceeds_source_length() {
        let payload = b"gzip bounded payload".repeat(4096);
        let compressed = encode_gzip(&payload);
        let len = compressed.len() as u64;
        let mut decoder = GzipDecoder::new(Box::new(Cursor::new(compressed))).expect("construct");

        loop {
            let status = decoder
                .decode_step(&mut std::io::sink())
                .expect("decode_step");
            assert!(decoder.bytes_consumed().get() <= len);
            if status == DecodeStatus::Eof {
                break;
            }
        }
    }

    #[test]
    fn repeated_calls_after_eof_stay_eof() {
        let payload = b"gzip steady-state".to_vec();
        let compressed = encode_gzip(&payload);
        let mut decoder = GzipDecoder::new(Box::new(Cursor::new(compressed))).expect("construct");

        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode_step") == DecodeStatus::MoreData {}

        for _ in 0..5 {
            let status = decoder.decode_step(&mut sink).expect("idempotent eof");
            assert_eq!(status, DecodeStatus::Eof);
        }
        assert_eq!(sink, payload);
    }

    #[test]
    fn empty_source_reports_read_error() {
        let mut decoder =
            GzipDecoder::new(Box::new(Cursor::new(Vec::<u8>::new()))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { consumed, .. }) => assert_eq!(consumed, 0),
            other => panic!("expected Read error, got {other:?}"),
        }
    }

    #[test]
    fn garbage_source_reports_read_error() {
        let garbage = vec![0xDE_u8; 4096];
        let mut decoder = GzipDecoder::new(Box::new(Cursor::new(garbage))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { source, .. }) => {
                assert!(
                    source.to_string().contains("bad magic"),
                    "expected bad-magic error, got: {source}"
                );
            }
            other => panic!("expected Read error from garbage, got {other:?}"),
        }
    }

    #[test]
    fn truncated_stream_reports_read_error() {
        let payload = b"gzip truncated payload".repeat(2048);
        let compressed = encode_gzip(&payload);
        let truncated = compressed[..compressed.len() - 16].to_vec();
        let truncated_len = truncated.len() as u64;
        let mut decoder = GzipDecoder::new(Box::new(Cursor::new(truncated))).expect("construct");

        let mut sink = Vec::new();
        loop {
            match decoder.decode_step(&mut sink) {
                Ok(DecodeStatus::MoreData) => continue,
                Ok(DecodeStatus::Eof) => panic!("truncated stream should not reach Eof cleanly"),
                Err(DecodeError::Read { consumed, .. }) => {
                    assert!(consumed <= truncated_len);
                    return;
                }
                Err(other) => panic!("unexpected error: {other:?}"),
            }
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

        let payload = b"gzip failing-sink".repeat(8192);
        let compressed = encode_gzip(&payload);
        let mut decoder = GzipDecoder::new(Box::new(Cursor::new(compressed))).expect("construct");

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

    #[test]
    fn frame_boundary_is_a_valid_restart_point() {
        let payload_a = b"restart-A-".repeat(800);
        let payload_b = b"restart-B-longer-".repeat(1200);
        let member_a = encode_gzip(&payload_a);
        let member_b = encode_gzip(&payload_b);
        let mut combined = member_a.clone();
        combined.extend_from_slice(&member_b);

        let mut decoder =
            GzipDecoder::new(Box::new(Cursor::new(combined.clone()))).expect("construct");
        let mut sink = Vec::new();
        let mut first_boundary: Option<u64> = None;
        loop {
            let prior = decoder.frame_boundary();
            let status = decoder.decode_step(&mut sink).expect("decode_step");
            let next = decoder.frame_boundary();
            if first_boundary.is_none() && next != prior {
                first_boundary = next.map(|b| b.get());
            }
            if status == DecodeStatus::Eof {
                break;
            }
        }
        let boundary = first_boundary.expect("at least one boundary observed");
        assert_eq!(boundary, member_a.len() as u64);

        let suffix = combined[boundary as usize..].to_vec();
        let mut restart = GzipDecoder::new(Box::new(Cursor::new(suffix))).expect("restart");
        let mut restart_out = Vec::new();
        loop {
            let status = restart.decode_step(&mut restart_out).expect("decode_step");
            if status == DecodeStatus::Eof {
                break;
            }
        }
        assert_eq!(restart_out, payload_b);
    }

    #[test]
    fn factory_constructs_and_decodes() {
        let payload = b"gzip factory check".repeat(1024);
        let compressed = encode_gzip(&payload);
        let mut decoder = factory(Box::new(Cursor::new(compressed.clone()))).expect("factory");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode_step") == DecodeStatus::MoreData {}
        assert_eq!(sink, payload);
    }

    #[test]
    fn corrupted_crc32_byte_surfaces_typed_error() {
        let payload = b"gzip CRC32 corruption".to_vec();
        let mut compressed = encode_gzip(&payload);
        // Flip a bit in the trailer's CRC32 (bytes len-8 .. len-4).
        let crc_byte = compressed.len() - 8;
        compressed[crc_byte] ^= 0x01;

        let mut decoder = GzipDecoder::new(Box::new(Cursor::new(compressed))).expect("construct");
        let mut sink = Vec::new();
        loop {
            match decoder.decode_step(&mut sink) {
                Ok(DecodeStatus::MoreData) => continue,
                Ok(DecodeStatus::Eof) => panic!("corrupt CRC must not reach Eof"),
                Err(DecodeError::Read { source, .. }) => {
                    assert!(
                        source.to_string().contains("CRC32 mismatch"),
                        "expected CRC32 mismatch, got: {source}"
                    );
                    return;
                }
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn corrupted_isize_byte_surfaces_typed_error() {
        let payload = b"gzip ISIZE corruption".to_vec();
        let mut compressed = encode_gzip(&payload);
        // Flip a bit in the trailer's ISIZE (bytes len-4 .. len).
        let isize_byte = compressed.len() - 1;
        compressed[isize_byte] ^= 0x80;

        let mut decoder = GzipDecoder::new(Box::new(Cursor::new(compressed))).expect("construct");
        let mut sink = Vec::new();
        loop {
            match decoder.decode_step(&mut sink) {
                Ok(DecodeStatus::MoreData) => continue,
                Ok(DecodeStatus::Eof) => panic!("corrupt ISIZE must not reach Eof"),
                Err(DecodeError::Read { source, .. }) => {
                    assert!(
                        source.to_string().contains("ISIZE mismatch"),
                        "expected ISIZE mismatch, got: {source}"
                    );
                    return;
                }
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
    }

    #[test]
    fn unsupported_compression_method_surfaces_typed_error() {
        // Hand-built gzip header with CM=2 (reserved). Truncated
        // after the header — we only need the header parse to
        // surface the CM error, not a full member.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x1F, 0x8B, 0x02, 0x00, 0, 0, 0, 0, 0x00, 0x03]);
        let mut decoder = GzipDecoder::new(Box::new(Cursor::new(bytes))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { source, .. }) => {
                assert!(
                    source
                        .to_string()
                        .contains("unsupported compression method"),
                    "expected unsupported-CM error, got: {source}"
                );
            }
            other => panic!("expected Read error, got {other:?}"),
        }
    }

    #[test]
    fn reserved_flg_bits_surface_typed_error() {
        // FLG with bit 5 set (a reserved bit per RFC 1952 §2.3.1.2).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x1F, 0x8B, 0x08, 0x20, 0, 0, 0, 0, 0x00, 0x03]);
        let mut decoder = GzipDecoder::new(Box::new(Cursor::new(bytes))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { source, .. }) => {
                assert!(
                    source.to_string().contains("reserved FLG bits"),
                    "expected reserved-FLG error, got: {source}"
                );
            }
            other => panic!("expected Read error, got {other:?}"),
        }
    }

    /// Hand-built header with FNAME / FCOMMENT / FHCRC flags set —
    /// confirms the optional-fields path consumes all variable-
    /// length payloads correctly. Body / trailer come from a
    /// real flate2 encode of a small payload, with the header
    /// prepended manually.
    #[test]
    fn header_with_fname_fcomment_fhcrc_round_trips() {
        let payload = b"opt-fields-payload".to_vec();
        let real = encode_gzip(&payload);
        // Skip the 10-byte fixed header from flate2's output; keep
        // the deflate stream + trailer.
        let body_and_trailer = &real[10..];

        // Build a custom header with FNAME='x' FCOMMENT='y' FHCRC=2 bytes.
        let mut frame = Vec::new();
        frame.extend_from_slice(&[
            0x1F,
            0x8B,
            0x08,
            FLG_FNAME | FLG_FCOMMENT | FLG_FHCRC,
            0,
            0,
            0,
            0,
            0x00,
            0x03,
        ]);
        frame.extend_from_slice(b"x\0");
        frame.extend_from_slice(b"y\0");
        frame.extend_from_slice(&[0x12, 0x34]); // FHCRC bytes (not validated)
        frame.extend_from_slice(body_and_trailer);

        let out = decode_all(frame);
        assert_eq!(out, payload);
    }

    /// FEXTRA payload of arbitrary length is consumed and ignored.
    #[test]
    fn header_with_fextra_round_trips() {
        let payload = b"extra-bytes-payload".to_vec();
        let real = encode_gzip(&payload);
        let body_and_trailer = &real[10..];

        let extra = vec![0xA5u8; 17];
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0x1F, 0x8B, 0x08, FLG_FEXTRA, 0, 0, 0, 0, 0x00, 0x03]);
        frame.extend_from_slice(&(extra.len() as u16).to_le_bytes());
        frame.extend_from_slice(&extra);
        frame.extend_from_slice(body_and_trailer);

        let out = decode_all(frame);
        assert_eq!(out, payload);
    }

    // ----------------------------------------------------------------
    // Phase 7 — gzip wrapper resume tests
    // ----------------------------------------------------------------

    /// Capture every (decoder_state blob, frame_boundary, prefix
    /// emitted so far) triple where the wrapper exposes a resume
    /// point during a clean run. For the gzip wrapper, blobs are
    /// emitted at deflate-block boundaries inside a member; the
    /// per-member `frame_boundary` updates also fire but
    /// `decoder_state` returns None at those (the regular factory
    /// can resume from a member boundary on its own).
    #[allow(clippy::type_complexity)]
    fn capture_gzip_resume_points(raw: &[u8]) -> Vec<(Vec<u8>, u64, Vec<u8>)> {
        let mut decoder = GzipDecoder::new(Box::new(Cursor::new(raw.to_vec()))).expect("construct");
        let mut sink: Vec<u8> = Vec::new();
        let mut points: Vec<(Vec<u8>, u64, Vec<u8>)> = Vec::new();
        loop {
            let status = decoder.decode_step(&mut sink).expect("decode");
            // `decoder_state` only returns Some at deflate-block
            // boundaries inside a member; capture each unique blob.
            if let (Some(blob), Some(b)) = (decoder.decoder_state(), decoder.bytes_consumed())
                .pipe(|(s, b)| (s, Some(b.get())))
            {
                points.push((blob, b, sink.clone()));
            }
            if status == DecodeStatus::Eof {
                break;
            }
        }
        points
    }

    /// Trait bridge for the `.pipe(...)` form above; keeps the
    /// capture loop readable. (Internal to this test module.)
    trait Pipe: Sized {
        fn pipe<R, F: FnOnce(Self) -> R>(self, f: F) -> R {
            f(self)
        }
    }
    impl<T> Pipe for T {}

    /// Construct a gzip stream by concatenating a custom 10-byte
    /// header + a hand-built multi-block deflate body (so the
    /// resume tests are reproducible across flate2 / miniz_oxide
    /// version updates) + an RFC 1952-conformant trailer.
    fn build_multi_block_gzip(chunks: &[&[u8]]) -> (Vec<u8>, Vec<u8>) {
        // Build the deflate body via the parent test module's
        // helper. We re-implement it locally here so the gzip
        // module's tests don't depend on test-only items in the
        // parent.
        struct W {
            bytes: Vec<u8>,
            acc: u64,
            n: u32,
        }
        impl W {
            fn new() -> Self {
                Self {
                    bytes: Vec::new(),
                    acc: 0,
                    n: 0,
                }
            }
            fn put(&mut self, v: u32, n: u32) {
                self.acc |= u64::from(v) << self.n;
                self.n += n;
                while self.n >= 8 {
                    self.bytes.push(self.acc as u8);
                    self.acc >>= 8;
                    self.n -= 8;
                }
            }
            fn finish(mut self) -> Vec<u8> {
                if self.n > 0 {
                    self.bytes.push(self.acc as u8);
                }
                self.bytes
            }
        }
        fn rev(mut v: u32, n: u32) -> u32 {
            let mut r = 0u32;
            for _ in 0..n {
                r = (r << 1) | (v & 1);
                v >>= 1;
            }
            r
        }
        fn fixed_litlen(sym: u16) -> (u32, u32) {
            match sym {
                0..=143 => (0b0011_0000_u32 + u32::from(sym), 8),
                144..=255 => (0b1_1001_0000_u32 + u32::from(sym - 144), 9),
                256..=279 => (u32::from(sym - 256), 7),
                280..=287 => (0b1100_0000_u32 + u32::from(sym - 280), 8),
                _ => panic!("invalid sym"),
            }
        }

        let combined: Vec<u8> = chunks.iter().flat_map(|p| p.iter().copied()).collect();
        let mut w = W::new();
        for (i, payload) in chunks.iter().enumerate() {
            let last = i + 1 == chunks.len();
            w.put(u32::from(last), 1);
            w.put(0b01, 2); // BTYPE=01 fixed Huffman
            for &b in *payload {
                let (c, l) = fixed_litlen(u16::from(b));
                w.put(rev(c, l), l);
            }
            let (eob_c, eob_l) = fixed_litlen(256);
            w.put(rev(eob_c, eob_l), eob_l);
        }
        let deflate_body = w.finish();

        // Wrap in gzip framing: header + deflate body + trailer.
        let mut gz = Vec::with_capacity(10 + deflate_body.len() + 8);
        gz.extend_from_slice(&[0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0x00, 0x03]);
        gz.extend_from_slice(&deflate_body);
        let crc = crate::zip::crc32::ieee(&combined);
        gz.extend_from_slice(&crc.to_le_bytes());
        let isize_low32 = (combined.len() as u32).to_le_bytes();
        gz.extend_from_slice(&isize_low32);
        (gz, combined)
    }

    #[test]
    fn gzip_resume_blob_round_trips_at_each_block_boundary() {
        let chunks: &[&[u8]] = &[b"first ", b"second ", b"third ", b"fourth ", b"fifth."];
        let (raw, payload) = build_multi_block_gzip(chunks);

        // Sanity: clean decode.
        let mut clean = GzipDecoder::new(Box::new(Cursor::new(raw.clone()))).expect("construct");
        let mut sink = Vec::new();
        while clean.decode_step(&mut sink).expect("decode") == DecodeStatus::MoreData {}
        assert_eq!(sink, payload);

        // Capture resume points and confirm each round-trips
        // byte-identically through the gzip resume_factory.
        let points = capture_gzip_resume_points(&raw);
        assert!(
            !points.is_empty(),
            "expected at least one mid-member resume point"
        );

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
                "gzip resume point {i} (boundary={boundary}) didn't round-trip",
            );
        }
    }

    #[test]
    fn gzip_resume_factory_rejects_raw_deflate_blob() {
        // A blob with container=RawDeflate must be rejected by the
        // gzip resume factory — the framing layers don't agree on
        // CRC32 / ISIZE semantics.
        let chunks: &[&[u8]] = &[b"alpha ", b"beta."];
        let (raw, _) = build_multi_block_gzip(chunks);
        // Construct a raw-deflate blob from the embedded deflate
        // body (skip header, drop trailer), pull a resume point
        // out of *that*, and feed it to the gzip resume factory.
        let deflate_body = &raw[10..raw.len() - 8];
        let mut decoder = super::super::Decoder::new(Box::new(Cursor::new(deflate_body.to_vec())))
            .expect("construct");
        let mut sink = Vec::new();
        let mut blob = None;
        let mut boundary = 0u64;
        loop {
            let status = decoder.decode_step(&mut sink).expect("decode");
            if let Some(b) = decoder.decoder_state() {
                blob = Some(b);
                boundary = decoder.bytes_consumed().get();
                break;
            }
            if status == DecodeStatus::Eof {
                break;
            }
        }
        let blob = blob.expect("captured a raw-deflate blob");
        match resume_factory(Box::new(Cursor::new(Vec::<u8>::new())), &blob, boundary) {
            Err(DecodeError::Construct(e)) => {
                assert!(
                    e.to_string().contains("expected container=Gzip"),
                    "unexpected message: {e}",
                );
            }
            Err(other) => panic!("expected Construct error, got {other:?}"),
            Ok(_) => panic!("expected Construct error, got Ok(decoder)"),
        }
    }

    #[test]
    fn gzip_resume_blob_carries_running_crc_and_isize() {
        // Pin the contract that gzip's running CRC + ISIZE land in
        // the blob and round-trip through the resume factory. We
        // verify by parsing the captured blob directly.
        let chunks: &[&[u8]] = &[b"hello ", b"world."];
        let (raw, payload) = build_multi_block_gzip(chunks);
        let points = capture_gzip_resume_points(&raw);
        let (blob, _boundary, _prefix) = points
            .first()
            .expect("at least one mid-member resume point");

        let parsed = super::super::resume::DflResumeState::deserialize(blob).expect("parse");
        assert_eq!(parsed.container, super::super::resume::Container::Gzip);
        // The running CRC at the first block boundary equals the
        // CRC32 of the bytes the first block emitted.
        let first_chunk_crc = crate::zip::crc32::ieee(chunks[0]);
        assert_eq!(parsed.running_crc32, first_chunk_crc);
        // The running ISIZE equals the bytes emitted so far.
        assert_eq!(parsed.total_decompressed, chunks[0].len() as u64);
        // Sanity: the full payload still round-trips through the
        // resume factory at this point.
        let suffix_src = raw[parsed.source_byte_position as usize..].to_vec();
        let mut resumed: Box<dyn StreamingDecoder> = resume_factory(
            Box::new(Cursor::new(suffix_src)),
            blob,
            parsed.source_byte_position,
        )
        .expect("resume");
        let mut sink = Vec::new();
        while resumed.decode_step(&mut sink).expect("decode") == DecodeStatus::MoreData {}
        let mut combined = chunks[0].to_vec();
        combined.extend_from_slice(&sink);
        assert_eq!(combined, payload);
    }
}
