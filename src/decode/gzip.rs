//! Gzip streaming decoder ([RFC 1952]).
//!
//! Wraps [`flate2::bufread::GzDecoder`] in single-member mode and chains
//! a fresh decoder over each subsequent member so the protocol-level
//! [`StreamingDecoder::frame_boundary`] contract can be honored at
//! whole-member granularity. Each gzip member is an independent
//! self-contained unit (10+-byte header, deflate body, 8-byte trailer
//! with CRC32 + ISIZE), so member ends are valid restart points: a
//! resuming decoder pointed at byte N — where N is the cumulative end
//! of the K-th member — produces exactly the suffix of the plaintext
//! that the K+1..M members encode.
//!
//! Per-member granularity is the natural granularity for gzip; per-
//! deflate-block granularity inside a single member is *not* a usable
//! restart point because the deflate body's CRC and ISIZE are computed
//! over the full uncompressed payload of the member, not per block.
//! This matches the position xz takes in [`super::xz`] (round-one
//! per-Stream rather than per-Block).
//!
//! # Source consumption accounting
//!
//! Mirrors the xz path's "input is owned by us, byte counts are
//! counted by us" discipline — but the bookkeeping is done by an
//! adapter rather than by reaching into the underlying library:
//!
//! ```text
//! Box<dyn Read> ──> CountingBufReader ──> GzDecoder ──> sink.write_all
//!                          ^
//!                          |
//!                  consumed counter
//! ```
//!
//! [`CountingBufReader`] is a [`BufRead`] adapter whose `consume(n)`
//! increments a `u64` by `n`. Because [`flate2::bufread::GzDecoder`]
//! drives the underlying reader through `BufRead::fill_buf` /
//! `consume`, that counter is exactly the conservative "bytes the
//! decoder has committed to processing" high-water mark the protocol
//! requires. Bytes that have been pulled into the buffer via
//! `fill_buf` but not yet `consume`'d are *not* counted: punching past
//! them would risk losing data that needs to be re-read on resume from
//! a frame boundary. Same safety contract as the xz path, expressed
//! through the BufRead trait instead of through liblzma's `total_in()`.
//!
//! # Frame boundary detection
//!
//! `GzDecoder` with `multi=false` returns `Ok(0)` from
//! [`Read::read`] at the end of each gzip member after verifying the
//! CRC32 and ISIZE in the trailer. At that point the cumulative
//! `consumed` counter equals the byte offset immediately past the
//! member's trailer; we record it as the latest frame boundary, then
//! consume the inner [`CountingBufReader`] back via
//! [`flate2::bufread::GzDecoder::into_inner`] and probe the source
//! with `BufRead::fill_buf` to decide whether more members follow:
//!
//! - If `fill_buf` returns an empty slice, the source is exhausted
//!   and we transition to [`State::Done`]. The next
//!   [`decode_step`](StreamingDecoder::decode_step) returns
//!   [`DecodeStatus::Eof`].
//! - Otherwise, we wrap the same [`CountingBufReader`] in a fresh
//!   `GzDecoder`. Its `new()` constructor parses the next member's
//!   header eagerly from the same buffered prefix, so any read-ahead
//!   bytes that crossed the boundary in the previous member's final
//!   `fill_buf` are not lost.
//!
//! Trailing junk (bytes after the final member's trailer that do not
//! form a valid gzip header) surfaces on the next decode step as a
//! [`DecodeError::Read`] from `GzDecoder` rather than a clean
//! [`DecodeStatus::Eof`]. Real-world gzip files do not append trailing
//! junk; tools that produce concatenated streams produce concatenated
//! valid members.
//!
//! [RFC 1952]: https://www.rfc-editor.org/rfc/rfc1952

use std::io::{self, BufRead, Read, Write};
use std::mem;

use flate2::bufread::GzDecoder;

use crate::decode::{DecodeError, DecodeStatus, StreamingDecoder};
use crate::types::ByteOffset;

/// Output buffer size used per [`StreamingDecoder::decode_step`].
///
/// Matches [`super::xz`] / [`super::zstd`] so the extractor's
/// punch / checkpoint cadence behaves the same way regardless of which
/// decoder is in front of it.
const OUTPUT_CHUNK: usize = 1 << 20;

/// Input buffer size used by the [`CountingBufReader`].
///
/// 64 KiB is large enough to amortize per-`read` syscall overhead while
/// staying small enough that a single refill does not stall progress
/// on slow connections; the same rationale as the xz path's
/// `INPUT_CHUNK`.
const INPUT_CHUNK: usize = 1 << 16;

/// [`BufRead`] adapter that tracks the cumulative number of bytes
/// `consume`'d off the buffer.
///
/// The counter advances *only* on `consume(n)`, never on `fill_buf` —
/// this is the precise definition of "bytes the consumer has committed
/// to processing" used by [`StreamingDecoder::bytes_consumed`].
struct CountingBufReader {
    /// Owned source. We never hand a reference back; once the wrapper
    /// is constructed all reads are mediated through `fill_buf`.
    source: Box<dyn Read + Send>,
    /// Internal scratch buffer holding bytes pulled from `source` but
    /// not yet returned via `fill_buf`.
    buf: Box<[u8]>,
    /// `buf[pos..filled]` is the slice currently visible to `fill_buf`.
    pos: usize,
    /// Bytes valid in `buf` (`<= buf.len()`).
    filled: usize,
    /// Cumulative bytes `consume`'d. Monotonically non-decreasing.
    consumed: u64,
}

impl CountingBufReader {
    fn new(source: Box<dyn Read + Send>) -> Self {
        Self {
            source,
            buf: vec![0u8; INPUT_CHUNK].into_boxed_slice(),
            pos: 0,
            filled: 0,
            consumed: 0,
        }
    }
}

impl Read for CountingBufReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let avail = self.fill_buf()?;
        let n = avail.len().min(out.len());
        // INVARIANT: `n <= avail.len()` and `avail = &self.buf[pos..filled]`,
        // so the slice arithmetic below cannot panic.
        out[..n].copy_from_slice(&avail[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for CountingBufReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.pos >= self.filled {
            let n = self.source.read(&mut self.buf)?;
            self.filled = n;
            self.pos = 0;
        }
        Ok(&self.buf[self.pos..self.filled])
    }

    fn consume(&mut self, amt: usize) {
        let avail = self.filled.saturating_sub(self.pos);
        let amt = amt.min(avail);
        self.pos = self.pos.saturating_add(amt);
        self.consumed = self.consumed.saturating_add(amt as u64);
    }
}

/// Streaming gzip decoder that exposes per-member boundaries.
///
/// Construction does not pull bytes from the source — the first
/// `fill_buf` happens during the first `decode_step`. The source is
/// `Send` so the decoder can be moved to a worker thread the same way
/// [`super::xz::XzDecoder`] and [`super::zstd::ZstdDecoder`] can.
pub struct GzipDecoder {
    state: State,
    /// Pre-allocated scratch space for the decoded output of each
    /// step. Reused across steps to avoid per-call allocation.
    output_buf: Vec<u8>,
    /// Latest frame boundary observed, or `None` if no member has
    /// completed yet.
    last_frame_boundary: Option<ByteOffset>,
    /// Snapshot of the safe consumed offset, refreshed at the end of
    /// every step. Reading this avoids touching the live decoder
    /// state from `bytes_consumed`, which is `&self`.
    consumed_snapshot: u64,
}

/// Decoder state machine.
///
/// ```text
/// Decoding ──read returns Ok(n)──> Decoding         [emits output]
/// Decoding ──read returns Ok(0), source has more──> Decoding (fresh GzDecoder)
/// Decoding ──read returns Ok(0), source empty─────> Done
/// Decoding ──read returns Err──────────────────────> Done
/// ```
///
/// `Transient` is a placeholder used during in-place state
/// replacement via [`mem::replace`]; it is never observable outside
/// `decode_step`.
enum State {
    /// Boxed because the inner [`GzDecoder`] embeds the deflate state
    /// machine (~200 bytes) and the [`State::Done`] / [`State::Transient`]
    /// variants are zero-sized; carrying that footprint inline blows
    /// the enum's size and trips `clippy::large_enum_variant`.
    Decoding(Box<GzDecoder<CountingBufReader>>),
    Done,
    Transient,
}

impl GzipDecoder {
    /// Construct a [`GzipDecoder`] over `src`.
    ///
    /// Does not pull any bytes from the source. The first member's
    /// header is parsed inside the first call to
    /// [`StreamingDecoder::decode_step`]; the `consumed = 0` contract
    /// on [`DecodeError::Construct`] therefore holds vacuously.
    ///
    /// # Errors
    ///
    /// Currently infallible. The signature returns
    /// [`DecodeError::Construct`] for symmetry with the other
    /// decoders' factories so the registry plumbing can stay
    /// uniform; future configuration parsing (e.g. preserving header
    /// metadata) may legitimately surface construction failures.
    pub fn new(src: Box<dyn Read + Send>) -> Result<Self, DecodeError> {
        let counter = CountingBufReader::new(src);
        Ok(Self {
            state: State::Decoding(Box::new(GzDecoder::new(counter))),
            output_buf: vec![0u8; OUTPUT_CHUNK],
            last_frame_boundary: None,
            consumed_snapshot: 0,
        })
    }
}

impl StreamingDecoder for GzipDecoder {
    fn decode_step(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, DecodeError> {
        match mem::replace(&mut self.state, State::Transient) {
            State::Done => {
                self.state = State::Done;
                Ok(DecodeStatus::Eof)
            }

            State::Transient => {
                // INVARIANT: `Transient` is only ever installed by
                // the `mem::replace` above and is replaced by a
                // concrete state on every match arm before this arm
                // could run. Reaching it would indicate a
                // panic-recovery edge case where the decoder is
                // poisoned; fail closed rather than continue.
                self.state = State::Done;
                Err(DecodeError::Read {
                    consumed: self.consumed_snapshot,
                    source: io::Error::other("gzip decoder observed in transient state (poisoned)"),
                })
            }

            State::Decoding(mut decoder) => {
                let read_result = decoder.read(&mut self.output_buf);
                // Snapshot the counter regardless of which arm we take
                // below. `get_ref()` reaches the live counter without
                // moving ownership.
                self.consumed_snapshot = decoder.get_ref().consumed;

                match read_result {
                    Ok(0) => {
                        // Member boundary: GzDecoder verified the
                        // trailer's CRC32 and ISIZE before returning
                        // 0, so `consumed_snapshot` points exactly
                        // past the end of the trailer and is a valid
                        // restart point.
                        let boundary = self.consumed_snapshot;
                        self.last_frame_boundary = Some(ByteOffset::new(boundary));

                        // Recover the inner counter from the finished
                        // GzDecoder. Any read-ahead bytes the
                        // GzDecoder pulled while parsing the trailer
                        // remain buffered in the counter and will be
                        // visible to the next `fill_buf` call below.
                        // `*decoder` peels the Box so we can move out
                        // of the GzDecoder via `into_inner`.
                        let mut counter = (*decoder).into_inner();

                        let avail = match counter.fill_buf() {
                            Ok(a) => a,
                            Err(err) => {
                                self.state = State::Done;
                                return Err(DecodeError::Read {
                                    consumed: boundary,
                                    source: err,
                                });
                            }
                        };

                        if avail.is_empty() {
                            // Source is exhausted. Transition to Done
                            // but return MoreData this step so the
                            // coordinator gets one final observation
                            // of the new boundary; the next call
                            // returns Eof.
                            self.state = State::Done;
                            return Ok(DecodeStatus::MoreData);
                        }

                        // More bytes follow. They are either the
                        // start of a new member (success) or trailing
                        // junk (failure surfaces from the new
                        // GzDecoder's first read on the next step).
                        // Either way we install the new state now and
                        // let the next decode_step exercise it.
                        self.state = State::Decoding(Box::new(GzDecoder::new(counter)));
                        Ok(DecodeStatus::MoreData)
                    }
                    Ok(n) => {
                        // INVARIANT: `n <= self.output_buf.len()` per
                        // the [`Read::read`] contract.
                        sink.write_all(&self.output_buf[..n])
                            .map_err(DecodeError::Write)?;
                        self.state = State::Decoding(decoder);
                        Ok(DecodeStatus::MoreData)
                    }
                    Err(err) => {
                        // Errors from GzDecoder are terminal: format
                        // violations leave the underlying decoder in
                        // an inconsistent state and re-running it
                        // would risk silent data loss.
                        self.state = State::Done;
                        Err(DecodeError::Read {
                            consumed: self.consumed_snapshot,
                            source: err,
                        })
                    }
                }
            }
        }
    }

    fn bytes_consumed(&self) -> ByteOffset {
        ByteOffset::new(self.consumed_snapshot)
    }

    fn frame_boundary(&self) -> Option<ByteOffset> {
        self.last_frame_boundary
    }
}

/// [`super::DecoderFactory`] adapter for [`GzipDecoder`].
///
/// Registered against the `.gz` / `.tar.gz` suffixes, the format name
/// `gzip`, and the gzip magic `1F 8B` at offset 0 by
/// [`super::DecoderRegistry::with_defaults`].
///
/// # Errors
///
/// Forwards [`DecodeError::Construct`] from [`GzipDecoder::new`].
pub fn factory(src: Box<dyn Read + Send>) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    Ok(Box::new(GzipDecoder::new(src)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    use flate2::bufread::GzEncoder;
    use flate2::Compression;

    /// Encode a payload as a single-member gzip blob using flate2's
    /// default compression level (matches the `gzip` CLI default of 6).
    fn encode_gzip(payload: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(payload, Compression::default());
        let mut out = Vec::with_capacity(payload.len() / 2 + 32);
        encoder.read_to_end(&mut out).expect("encode");
        out
    }

    /// Round-trip a single-member gzip blob through the decoder.
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

    /// Concatenated members decode to the concatenation of their
    /// plaintexts, and every observed boundary lands at a cumulative
    /// end-of-member offset.
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

    /// `bytes_consumed` is monotonically non-decreasing across every
    /// `decode_step` call, including across member boundaries.
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

    /// `bytes_consumed` is bounded above by the actual source size at
    /// every observation, even mid-member.
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

    /// After EOF, repeated calls keep returning `Eof` without
    /// panicking or rewinding state.
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

    /// Empty source: GzDecoder cannot parse the header and surfaces
    /// the failure on the first decode step. We surface it as a clean
    /// [`DecodeError::Read`] without panicking.
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

    /// Garbage input is rejected with a `Read` error.
    #[test]
    fn garbage_source_reports_read_error() {
        let garbage = vec![0xDE_u8; 4096];
        let mut decoder = GzipDecoder::new(Box::new(Cursor::new(garbage))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { .. }) => {}
            other => panic!("expected Read error from garbage, got {other:?}"),
        }
    }

    /// Truncated streams must surface as a clean
    /// [`DecodeError::Read`]; the decoder must not over-report
    /// `bytes_consumed`.
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

    /// Frame boundaries returned by the decoder are valid restart
    /// points: decoding from a recorded boundary produces exactly the
    /// suffix of the stream's plaintext.
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

    /// The factory plumbing constructs a working decoder.
    #[test]
    fn factory_constructs_and_decodes() {
        let payload = b"gzip factory check".repeat(1024);
        let compressed = encode_gzip(&payload);
        let mut decoder = factory(Box::new(Cursor::new(compressed.clone()))).expect("factory");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode_step") == DecodeStatus::MoreData {}
        assert_eq!(sink, payload);
    }
}
