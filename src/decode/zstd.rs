//! Zstandard ([RFC 8878]) streaming decoder.
//!
//! Wraps the upstream [`::zstd::stream::read::Decoder`] in single-frame
//! mode and steps it frame-by-frame so the protocol-level
//! [`StreamingDecoder::frame_boundary`] contract can be honored. The
//! upstream API does not expose frame transitions directly: it
//! transparently concatenates frames in multi-frame mode and yields
//! `Ok(0)` only at end-of-stream. By forcing single-frame mode and
//! re-instantiating the decoder when more bytes remain, this module
//! converts each `Ok(0)` into a frame-boundary observation.
//!
//! # Source consumption accounting
//!
//! The decoder shape is:
//!
//! ```text
//! Box<dyn Read>  ->  CountingReader  ->  BufReader  ->  zstd::Decoder
//!                       (atomic            (zstd's own
//!                        counter)            input buffer)
//! ```
//!
//! Bytes pulled from the source are counted by [`CountingReader`] into a
//! shared [`AtomicU64`]. Bytes still held in the [`BufReader`] but not
//! yet consumed by the zstd state machine are visible via
//! [`std::io::BufReader::buffer`]. The conservative consumed offset is
//! `count - buffered`: every byte before that has been copied into
//! libzstd's internal context and will not be re-read from the source.
//!
//! # Frame boundary detection
//!
//! In single-frame mode, the upstream reader transitions to its
//! `Finished` state once a frame's footer is processed and returns
//! `Ok(0)` from subsequent `read()` calls. At that transition the
//! `BufReader`'s remaining buffer is the start of the *next* frame (or
//! empty at clean stream EOF). The decoder records that exact byte
//! position as the latest frame boundary, then either constructs a new
//! single-frame decoder over the same `BufReader` (preserving any
//! already-read bytes) or transitions to its own terminal `Done` state.
//!
//! [RFC 8878]: https://datatracker.ietf.org/doc/html/rfc8878

use std::io::{BufRead, BufReader, Read, Write};
use std::mem;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::decode::{DecodeError, DecodeStatus, StreamingDecoder};
use crate::types::ByteOffset;

/// Output buffer size used per [`StreamingDecoder::decode_step`].
///
/// Sized to amortize syscall and dispatch overhead while still bounding
/// the work performed per step so the coordinator can interleave
/// punching and checkpointing. Same value as the Python prototype's
/// `_OUTPUT_CHUNK`.
const OUTPUT_CHUNK: usize = 1 << 20;

/// Streaming zstd decoder that exposes per-frame boundaries.
///
/// Take ownership of the source on construction; subsequent
/// [`StreamingDecoder::decode_step`] calls do not need the source
/// passed back in. The source is `Send` so the decoder can be moved to
/// a worker thread.
pub struct ZstdDecoder {
    /// Decoder state machine — see the type's own documentation.
    state: State,
    /// Total bytes pulled from the source so far. Updated by
    /// [`CountingReader`] on every successful `read`.
    source_bytes_read: Arc<AtomicU64>,
    /// Latest frame boundary observed, or `None` if no frame has
    /// completed yet.
    last_frame_boundary: Option<ByteOffset>,
    /// Pre-allocated scratch space for the next decode step. Reused
    /// across steps to avoid per-call allocation.
    output_buf: Vec<u8>,
    /// Snapshot of the safe consumed offset, refreshed at the end of
    /// every step and after construction. Reading this avoids touching
    /// the live decoder state from `bytes_consumed`, which is `&self`.
    consumed_snapshot: u64,
}

/// Decoder state machine.
///
/// The transitions are linear except for `Decoding -> BetweenFrames ->
/// Decoding`, which loops once per frame:
///
/// ```text
/// Decoding(...) ──Ok(n>0)──> Decoding(...)        [emits output]
/// Decoding(...) ──Ok(0)────> BetweenFrames(...)   [records boundary]
/// BetweenFrames ──data────> Decoding(...)         [next frame]
/// BetweenFrames ──EOF─────> Done                  [clean stream end]
/// any           ──Err─────> Done                  [error is terminal]
/// ```
///
/// `Transient` is a placeholder used during in-place state replacement
/// via [`mem::replace`]; it is never observable outside `decode_step`.
enum State {
    Decoding(::zstd::stream::read::Decoder<'static, BufReader<CountingReader>>),
    BetweenFrames(BufReader<CountingReader>),
    Done,
    Transient,
}

/// `Read` adapter that increments a shared counter for every byte it
/// hands out.
///
/// The counter is shared (via `Arc`) with the owning [`ZstdDecoder`] so
/// that `bytes_consumed` can observe progress without having to crack
/// open the live `zstd` decoder.
struct CountingReader {
    inner: Box<dyn Read + Send>,
    count: Arc<AtomicU64>,
}

impl Read for CountingReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        // u64 can address every byte we'd ever care about; an `as`
        // cast is fine because `n <= buf.len() <= isize::MAX`.
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

impl ZstdDecoder {
    /// Construct a [`ZstdDecoder`] over `src`.
    ///
    /// Does not pull any bytes from the source — construction failure
    /// reflects libzstd context allocation only.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Construct`] if libzstd refuses to allocate
    /// a decompression context.
    pub fn new(src: Box<dyn Read + Send>) -> Result<Self, DecodeError> {
        let count = Arc::new(AtomicU64::new(0));
        let counting = CountingReader {
            inner: src,
            count: Arc::clone(&count),
        };
        // BufReader is required by zstd::stream::read::Decoder::with_buffer,
        // and using it directly (instead of letting `Decoder::new` allocate
        // an internal one) lets us preserve buffered bytes across the
        // single-frame restart loop.
        let buf_reader = BufReader::new(counting);
        let decoder = ::zstd::stream::read::Decoder::with_buffer(buf_reader)
            .map_err(DecodeError::Construct)?
            .single_frame();
        Ok(Self {
            state: State::Decoding(decoder),
            source_bytes_read: count,
            last_frame_boundary: None,
            output_buf: vec![0u8; OUTPUT_CHUNK],
            consumed_snapshot: 0,
        })
    }

    /// Returns `(count, buffered)` so callers can compute the safe
    /// consumed offset as `count - buffered`.
    fn read_state(&self) -> (u64, u64) {
        let count = self.source_bytes_read.load(Ordering::Relaxed);
        let buffered = match &self.state {
            State::Decoding(d) => d.get_ref().buffer().len() as u64,
            State::BetweenFrames(b) => b.buffer().len() as u64,
            State::Done | State::Transient => 0,
        };
        (count, buffered)
    }

    fn refresh_consumed_snapshot(&mut self) {
        let (count, buffered) = self.read_state();
        // Invariant: `buffered <= count`. The BufReader can never hold
        // more bytes than have been pulled from the source. Saturating
        // keeps this trivially panic-free even if the invariant is ever
        // violated — we'd just under-report consumption, which is the
        // safe direction for hole punching.
        self.consumed_snapshot = count.saturating_sub(buffered);
    }
}

impl StreamingDecoder for ZstdDecoder {
    fn decode_step(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, DecodeError> {
        // The loop below executes at most twice per call in steady
        // state: once to attempt a read in `Decoding`, and at most once
        // more if that read finished a frame and a follow-up
        // `BetweenFrames` transition needs to either spin up the next
        // frame or report EOF. A pathological zero-byte stream of empty
        // frames could in theory iterate further, but each iteration
        // consumes input so the loop is bounded by the source length.
        loop {
            match mem::replace(&mut self.state, State::Transient) {
                State::Done => {
                    self.state = State::Done;
                    self.refresh_consumed_snapshot();
                    return Ok(DecodeStatus::Eof);
                }

                State::Decoding(mut decoder) => match decoder.read(&mut self.output_buf) {
                    Ok(0) => {
                        // Single-frame mode reached the frame footer.
                        // The BufReader's remaining buffer is whatever
                        // bytes the decoder had pulled past the end of
                        // the just-finished frame, i.e. the start of
                        // the next frame.
                        let buf_reader = decoder.finish();
                        let count = self.source_bytes_read.load(Ordering::Relaxed);
                        let buffered = buf_reader.buffer().len() as u64;
                        // INVARIANT: `buffered <= count` — see
                        // `refresh_consumed_snapshot` for the rationale.
                        let boundary = count.saturating_sub(buffered);
                        self.last_frame_boundary = Some(ByteOffset::new(boundary));
                        self.state = State::BetweenFrames(buf_reader);
                        // Return immediately so the caller can observe
                        // the new frame_boundary and (if it owns a
                        // checkpoint discipline) snapshot a `bytes_out`
                        // that is paired exactly with this source
                        // offset. Falling through to spin up the next
                        // frame in the same call would let bytes_out
                        // race past the boundary, which §10's resume
                        // contract relies on.
                        self.refresh_consumed_snapshot();
                        return Ok(DecodeStatus::MoreData);
                    }
                    Ok(n) => {
                        sink.write_all(&self.output_buf[..n])
                            .map_err(DecodeError::Write)?;
                        self.state = State::Decoding(decoder);
                        self.refresh_consumed_snapshot();
                        return Ok(DecodeStatus::MoreData);
                    }
                    Err(err) => {
                        // Errors are terminal: the decoder context may
                        // be in an inconsistent state and re-running
                        // it would risk silent data loss.
                        let count = self.source_bytes_read.load(Ordering::Relaxed);
                        let buffered = decoder.get_ref().buffer().len() as u64;
                        let consumed = count.saturating_sub(buffered);
                        self.state = State::Done;
                        self.consumed_snapshot = consumed;
                        return Err(DecodeError::Read {
                            consumed,
                            source: err,
                        });
                    }
                },

                State::BetweenFrames(mut buf_reader) => {
                    // Probe the source: if `fill_buf` returns an empty
                    // slice the stream is cleanly exhausted; otherwise
                    // any leading bytes are the start of another frame
                    // and a fresh single-frame decoder takes ownership
                    // of the same `BufReader` (preserving the bytes
                    // already pulled but not yet handed to zstd).
                    let buffer = match buf_reader.fill_buf() {
                        Ok(b) => b,
                        Err(err) => {
                            let count = self.source_bytes_read.load(Ordering::Relaxed);
                            let buffered = buf_reader.buffer().len() as u64;
                            let consumed = count.saturating_sub(buffered);
                            self.state = State::Done;
                            self.consumed_snapshot = consumed;
                            return Err(DecodeError::Read {
                                consumed,
                                source: err,
                            });
                        }
                    };
                    if buffer.is_empty() {
                        self.state = State::Done;
                        self.refresh_consumed_snapshot();
                        return Ok(DecodeStatus::Eof);
                    }
                    match ::zstd::stream::read::Decoder::with_buffer(buf_reader) {
                        Ok(d) => {
                            self.state = State::Decoding(d.single_frame());
                            // Loop again to actually attempt a read in
                            // `Decoding`; we don't return `MoreData`
                            // here because no output has been produced
                            // and the caller's progress contract is
                            // about output-or-status.
                        }
                        Err(err) => {
                            self.state = State::Done;
                            self.refresh_consumed_snapshot();
                            return Err(DecodeError::Construct(err));
                        }
                    }
                }

                State::Transient => {
                    // INVARIANT: `Transient` is only ever installed by
                    // the `mem::replace` above and is replaced by a
                    // concrete state on every match arm before this
                    // arm could run. Reaching it would indicate a
                    // panic-recovery edge case where the decoder is
                    // poisoned; fail closed rather than continue.
                    self.state = State::Done;
                    return Err(DecodeError::Read {
                        consumed: self.consumed_snapshot,
                        source: std::io::Error::other(
                            "zstd decoder observed in transient state (poisoned)",
                        ),
                    });
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

/// [`super::DecoderFactory`] adapter for [`ZstdDecoder`].
///
/// This is the entry point registered by
/// [`super::DecoderRegistry::with_defaults`] for the `.zst` and `.zstd`
/// suffixes.
///
/// # Errors
///
/// Forwards [`DecodeError::Construct`] from [`ZstdDecoder::new`].
pub fn factory(src: Box<dyn Read + Send>) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    Ok(Box::new(ZstdDecoder::new(src)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    /// Round-trip a single zstd frame through the decoder.
    #[test]
    fn single_frame_round_trip() {
        let payload = b"hello, frame world!".repeat(1024);
        let compressed = ::zstd::encode_all(&payload[..], 3).expect("encode");
        let mut decoder =
            ZstdDecoder::new(Box::new(Cursor::new(compressed.clone()))).expect("construct");

        let mut sink = Vec::with_capacity(payload.len());
        while let DecodeStatus::MoreData = decoder.decode_step(&mut sink).expect("decode_step") {}

        assert_eq!(sink, payload);
        assert_eq!(decoder.bytes_consumed().get(), compressed.len() as u64);
        assert!(decoder.frame_boundary().is_some());
    }

    /// Concatenated frames decode to the concatenation of their plain
    /// payloads, and the boundary observed between them lands exactly
    /// at the end of the first compressed frame.
    #[test]
    fn multi_frame_round_trip_records_boundary() {
        let payload_a = b"frame A payload".repeat(512);
        let payload_b = b"frame B payload, longer".repeat(700);
        let frame_a = ::zstd::encode_all(&payload_a[..], 3).expect("encode A");
        let frame_b = ::zstd::encode_all(&payload_b[..], 3).expect("encode B");
        let mut combined = frame_a.clone();
        combined.extend_from_slice(&frame_b);

        let mut decoder =
            ZstdDecoder::new(Box::new(Cursor::new(combined.clone()))).expect("construct");

        // Pump until we observe a boundary, then keep going until EOF.
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

        // We should observe two distinct boundaries: end of frame A
        // and end of the full stream (which is also end of frame B).
        assert_eq!(boundaries.len(), 2, "boundaries={boundaries:?}");
        assert_eq!(boundaries[0], frame_a.len() as u64, "frame A end");
        assert_eq!(boundaries[1], combined.len() as u64, "frame B end");
        assert_eq!(decoder.bytes_consumed().get(), combined.len() as u64);
    }

    /// Regression: when a frame's footer is reached, the decoder must
    /// surface the new boundary *before* spinning up the next frame's
    /// decoder in the same call. Otherwise §10's checkpoint discipline
    /// records a `bytes_out` that includes bytes already produced from
    /// the next frame, breaking byte-identical resume.
    #[test]
    fn frame_boundary_advance_pairs_with_unchanged_output() {
        let payload_a = b"a".repeat(2048);
        let payload_b = b"b".repeat(4096);
        let frame_a = ::zstd::encode_all(&payload_a[..], 1).expect("encode A");
        let frame_b = ::zstd::encode_all(&payload_b[..], 1).expect("encode B");
        let mut combined = frame_a.clone();
        combined.extend_from_slice(&frame_b);

        let mut decoder =
            ZstdDecoder::new(Box::new(Cursor::new(combined.clone()))).expect("construct");

        let mut sink = Vec::new();
        let mut prior_boundary = decoder.frame_boundary();
        loop {
            let bytes_before = sink.len() as u64;
            let status = decoder.decode_step(&mut sink).expect("decode_step");
            let next_boundary = decoder.frame_boundary();
            if next_boundary != prior_boundary {
                let bytes_after = sink.len() as u64;
                assert_eq!(
                    bytes_after, bytes_before,
                    "frame-boundary-advance step must not produce output: \
                     before={bytes_before} after={bytes_after}",
                );
                prior_boundary = next_boundary;
            }
            if status == DecodeStatus::Eof {
                break;
            }
        }

        // Sanity: decoded output is the concatenation of payload A and B.
        let mut expected = payload_a;
        expected.extend_from_slice(&payload_b);
        assert_eq!(sink, expected);
    }

    /// `bytes_consumed` is monotonically non-decreasing across every
    /// `decode_step` call, including across frame boundaries.
    #[test]
    fn bytes_consumed_is_monotone() {
        let payload = b"monotone payload".repeat(2048);
        let frame = ::zstd::encode_all(&payload[..], 3).expect("encode");
        let mut combined = frame.clone();
        combined.extend_from_slice(&frame);

        let mut decoder =
            ZstdDecoder::new(Box::new(Cursor::new(combined.clone()))).expect("construct");

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
    /// every observation, even mid-stream.
    #[test]
    fn bytes_consumed_never_exceeds_source_length() {
        let payload = b"abcdef".repeat(8192);
        let compressed = ::zstd::encode_all(&payload[..], 3).expect("encode");
        let len = compressed.len() as u64;
        let mut decoder = ZstdDecoder::new(Box::new(Cursor::new(compressed))).expect("construct");

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

    /// After EOF, repeated calls keep returning `Eof` without panicking
    /// or rewinding state.
    #[test]
    fn repeated_calls_after_eof_stay_eof() {
        let payload = b"steady-state".to_vec();
        let compressed = ::zstd::encode_all(&payload[..], 3).expect("encode");
        let mut decoder = ZstdDecoder::new(Box::new(Cursor::new(compressed))).expect("construct");

        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode_step") == DecodeStatus::MoreData {}

        for _ in 0..5 {
            let status = decoder.decode_step(&mut sink).expect("idempotent eof");
            assert_eq!(status, DecodeStatus::Eof);
        }
        assert_eq!(sink, payload);
    }

    /// Empty source: zstd treats this as a malformed stream because no
    /// frame magic is present. The decoder must surface the failure as
    /// [`DecodeError::Read`] without panicking.
    #[test]
    fn empty_source_reports_read_error() {
        let mut decoder =
            ZstdDecoder::new(Box::new(Cursor::new(Vec::<u8>::new()))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { consumed, .. }) => assert_eq!(consumed, 0),
            other => panic!("expected Read error, got {other:?}"),
        }
    }

    /// Garbage input is rejected with a `Read` error. zstd 0.13 maps
    /// libzstd's format errors to [`std::io::ErrorKind::Other`] with a
    /// human-readable message; we don't pin a specific kind because
    /// upstream may legitimately tighten this in a future release.
    #[test]
    fn garbage_source_reports_read_error() {
        let garbage = vec![0xDE_u8; 4096];
        let mut decoder = ZstdDecoder::new(Box::new(Cursor::new(garbage))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { .. }) => {}
            other => panic!("expected Read error from garbage, got {other:?}"),
        }
    }

    /// A failing sink produces [`DecodeError::Write`] without
    /// corrupting subsequent state observations.
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

        let payload = b"failing-sink-payload".repeat(8192);
        let compressed = ::zstd::encode_all(&payload[..], 3).expect("encode");
        let mut decoder = ZstdDecoder::new(Box::new(Cursor::new(compressed))).expect("construct");

        match decoder.decode_step(&mut FailingSink) {
            Err(DecodeError::Write(e)) => assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe),
            other => panic!("expected Write error, got {other:?}"),
        }
    }

    /// The factory plumbing — both the explicit `factory` fn and the
    /// path returned via the registry — produces a working decoder.
    #[test]
    fn factory_constructs_and_decodes() {
        let payload = b"factory check".repeat(1024);
        let compressed = ::zstd::encode_all(&payload[..], 3).expect("encode");
        let mut decoder = factory(Box::new(Cursor::new(compressed.clone()))).expect("factory");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode_step") == DecodeStatus::MoreData {}
        assert_eq!(sink, payload);
    }

    /// A property test that frame boundaries returned by the decoder
    /// are valid restart points: decoding from a recorded boundary
    /// produces exactly the suffix of the stream's plaintext.
    ///
    /// Hand-rolled LCG; same approach as `types::tests` to avoid
    /// pulling in a PRNG crate (see ENGINEERING_STANDARDS.md §2).
    #[test]
    fn frame_boundary_property_is_a_valid_restart_point() {
        let mut rng = Lcg::seeded(0x5EED);
        for _ in 0..16 {
            // Build a multi-frame stream from 2..=4 random payloads.
            let frame_count = (rng.next_u32() % 3 + 2) as usize;
            let mut payloads: Vec<Vec<u8>> = Vec::with_capacity(frame_count);
            for _ in 0..frame_count {
                let len = (rng.next_u32() % 4096 + 64) as usize;
                payloads.push(random_bytes(&mut rng, len));
            }
            let mut compressed_per_frame: Vec<Vec<u8>> = Vec::with_capacity(frame_count);
            let mut combined: Vec<u8> = Vec::new();
            for p in &payloads {
                let c = ::zstd::encode_all(&p[..], 1).expect("encode");
                combined.extend_from_slice(&c);
                compressed_per_frame.push(c);
            }

            // Walk the original stream, recording every boundary.
            let mut decoder =
                ZstdDecoder::new(Box::new(Cursor::new(combined.clone()))).expect("construct");
            let mut boundaries: Vec<u64> = Vec::new();
            let mut sink = Vec::new();
            loop {
                let prior = decoder.frame_boundary();
                let status = decoder.decode_step(&mut sink).expect("decode_step");
                let now = decoder.frame_boundary();
                if now != prior {
                    boundaries.push(now.expect("observed").get());
                }
                if status == DecodeStatus::Eof {
                    break;
                }
            }

            // Each boundary must land exactly at a cumulative end-of-frame
            // position and decoding from that offset must reproduce the
            // suffix of the plaintext.
            let mut cumulative_bytes = 0u64;
            let mut cumulative_payload: Vec<u8> = Vec::new();
            for (i, frame) in compressed_per_frame.iter().enumerate() {
                cumulative_bytes += frame.len() as u64;
                cumulative_payload.extend_from_slice(&payloads[i]);
                assert_eq!(
                    boundaries[i], cumulative_bytes,
                    "boundary[{i}] expected {cumulative_bytes}",
                );

                // Restart: feed the decoder only the bytes after the
                // boundary, expect the *suffix* of the plaintext.
                // The terminal boundary lands at end-of-stream and has
                // no remaining frames to decode; an empty source is not
                // a valid zstd stream so we skip the restart there.
                let suffix_compressed = combined[cumulative_bytes as usize..].to_vec();
                if suffix_compressed.is_empty() {
                    assert_eq!(
                        i + 1,
                        compressed_per_frame.len(),
                        "empty suffix only at end"
                    );
                    continue;
                }
                let expected_suffix = {
                    let mut total: Vec<u8> = Vec::new();
                    for p in &payloads {
                        total.extend_from_slice(p);
                    }
                    total[cumulative_payload.len()..].to_vec()
                };
                let mut restart =
                    ZstdDecoder::new(Box::new(Cursor::new(suffix_compressed))).expect("restart");
                let mut restart_out = Vec::new();
                loop {
                    let status = restart.decode_step(&mut restart_out).expect("decode_step");
                    if status == DecodeStatus::Eof {
                        break;
                    }
                }
                assert_eq!(restart_out, expected_suffix, "restart from boundary[{i}]",);
            }
        }
    }

    // ---- LCG ----------------------------------------------------------
    //
    // Same shape as `types::tests::Lcg`. Duplicated rather than promoted
    // to a shared test util because keeping each module's tests
    // self-contained makes them easier to read in isolation; the
    // duplication is tiny.

    struct Lcg(u64);
    impl Lcg {
        const fn seeded(seed: u64) -> Self {
            Self(seed ^ 0x9E37_79B9_7F4A_7C15)
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }
        fn next_u32(&mut self) -> u32 {
            (self.next_u64() >> 32) as u32
        }
    }

    fn random_bytes(rng: &mut Lcg, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let v = rng.next_u64();
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.truncate(len);
        out
    }
}
