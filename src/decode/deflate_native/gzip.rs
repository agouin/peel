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
        })
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
                self.read_and_validate_trailer()?;
                // Member done. Record the boundary at the current
                // byte cursor (now past the trailer).
                let bits = self
                    .bits
                    .as_ref()
                    .expect("bits owned in AwaitingTrailer state");
                let boundary = bits.byte_position().0;
                self.last_frame_boundary = Some(ByteOffset::new(boundary));
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
    /// running counters.
    fn read_and_validate_trailer(&mut self) -> Result<(), DeflateError> {
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
        Ok(())
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
        self.last_frame_boundary
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
}
