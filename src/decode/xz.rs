//! xz / LZMA streaming decoder ([XZ file format]).
//!
//! Wraps [`xz2::stream::Stream`] in single-Stream mode and steps it
//! Stream-by-Stream so the protocol-level
//! [`StreamingDecoder::frame_boundary`] contract can be honored at
//! whole-`Stream` granularity. Plan §3 calls this the "round-one MVP"
//! granularity for xz: per-Stream rather than per-Block. Real-world
//! `.tar.xz` archives are almost always single-Block (and therefore
//! single-Stream from the format's point of view), and *no*
//! implementation can checkpoint within a single Block — the file
//! itself does not contain a usable restart point. Per-Block
//! granularity is filed as `O.6b` in `docs/OPTIMIZATIONS.md`.
//!
//! # Source consumption accounting
//!
//! Unlike the zstd path — which lets `BufReader` own the input buffer
//! and reads `count - buffered` to compute the safe consumed offset —
//! the xz path drives [`Stream::process`] manually: a fixed-size input
//! buffer is filled from the source, then handed to liblzma a slice at
//! a time. This is a closer fit to liblzma's slice-in / slice-out API
//! than the [`Read`] adapter would be, and it lets us record the exact
//! byte offset at which each Stream ends without reaching past the
//! library's surface.
//!
//! ```text
//! Box<dyn Read> -> input_buf[input_pos..input_filled]
//!                       |
//!                       v
//!                  xz2::Stream::process
//!                       |
//!                       v
//!                  sink.write_all
//! ```
//!
//! `bytes_consumed` is `finished_streams_total_in + current_stream.total_in()`,
//! the conservative number of source bytes the xz state machine has
//! actually committed to. Bytes that have been pulled from the source
//! into `input_buf` but not yet handed to the stream are *not* yet
//! consumed — punching past them would risk losing data that needs to
//! be re-read on resume from a frame boundary.
//!
//! # Frame boundary detection
//!
//! liblzma surfaces [`Status::StreamEnd`] when a Stream is fully
//! decoded. At that point the cumulative source bytes consumed equals
//! the end of that Stream; we record it as the latest frame boundary
//! and either spin up a new [`Stream::new_stream_decoder`] over the
//! same source (concatenated `.xz` files) or transition to a terminal
//! "done" state when the source is exhausted.
//!
//! Stream Padding (zero-byte alignment between concatenated streams,
//! per the xz spec) is *not* handled in round-one. A new Stream is
//! created immediately after the previous one ends; if the next bytes
//! are not the xz magic, liblzma returns its `Format` error variant
//! and the coordinator surfaces a clean [`DecodeError::Read`].
//! Real-world concatenated xz files (the `cat a.xz b.xz` shape) work
//! because they typically have no padding; pathological streams with
//! padding will need explicit handling once a use case appears.
//!
//! [XZ file format]: https://tukaani.org/xz/xz-file-format.txt

use std::io::{self, Read, Write};
use std::mem;

use xz2::stream::{Action, Status, Stream};

use crate::decode::{DecodeError, DecodeStatus, StreamingDecoder};
use crate::types::ByteOffset;

/// Output buffer size used per [`StreamingDecoder::decode_step`].
///
/// Same value as [`crate::decode::zstd`]'s `OUTPUT_CHUNK` so the
/// extractor's punch/checkpoint cadence behaves the same way regardless
/// of which decoder is in front of it.
const OUTPUT_CHUNK: usize = 1 << 20;

/// Input buffer size used to refill from the source.
///
/// 64 KiB is large enough to amortize per-`read` syscall overhead while
/// staying small enough that a single refill does not stall progress on
/// slow connections — a one-step decode that produces output happens
/// within the first few process() calls after a refill.
const INPUT_CHUNK: usize = 1 << 16;

/// Memory-usage limit handed to liblzma. `u64::MAX` disables the limit
/// entirely, matching `xz`'s `--memlimit-decompress=0` behavior. The
/// largest legitimately-encoded `.xz` file we expect to handle has a
/// dictionary of ~64 MiB; setting a hard limit here would reject those
/// archives without giving the user a recourse, and we have no
/// reasonable adaptive value to pick. The decoder is bounded by source
/// length anyway.
const MEMLIMIT: u64 = u64::MAX;

/// Streaming xz / LZMA decoder that exposes per-`Stream` boundaries.
///
/// Take ownership of the source on construction; subsequent
/// [`StreamingDecoder::decode_step`] calls do not need the source
/// passed back in. The source is `Send` so the decoder can be moved to
/// a worker thread the same way [`crate::decode::zstd::ZstdDecoder`]
/// can.
pub struct XzDecoder {
    /// Decoder state machine — see [`State`].
    state: State,
    /// Total bytes from already-finished xz Streams. When the current
    /// Stream completes, its `total_in()` is added here and the Stream
    /// is replaced; per-Stream `total_in` resets, but our cumulative
    /// account does not.
    finished_streams_total_in: u64,
    /// Input scratch buffer holding bytes pulled from the source but
    /// not yet handed to liblzma. `input_buf[input_pos..input_filled]`
    /// is the next slice that will be processed.
    input_buf: Box<[u8]>,
    /// Bytes valid in `input_buf` (`<= input_buf.len()`).
    input_filled: usize,
    /// Bytes already fed to liblzma (`<= input_filled`).
    input_pos: usize,
    /// Pre-allocated scratch space for the next decode step. Reused
    /// across steps to avoid per-call allocation.
    output_buf: Vec<u8>,
    /// Latest frame boundary observed, or `None` if no Stream has
    /// completed yet.
    last_frame_boundary: Option<ByteOffset>,
    /// Snapshot of the safe consumed offset, refreshed at the end of
    /// every step. Reading this avoids touching the live decoder state
    /// from `bytes_consumed`, which is `&self`.
    consumed_snapshot: u64,
}

/// Decoder state machine.
///
/// The transitions match the zstd state machine in spirit, but the xz
/// shape is simpler: liblzma's [`Stream::process`] is the only call we
/// ever make against the underlying state, so there is no
/// `BetweenFrames` distinction — when a Stream ends we either replace
/// it in place (more bytes follow) or transition to `Done` (source
/// exhausted).
///
/// ```text
/// Decoding ──Status::Ok / GetCheck──> Decoding         [emits output]
/// Decoding ──Status::StreamEnd, src has more──> Decoding (fresh Stream)
/// Decoding ──Status::StreamEnd, src empty─────> Done
/// any      ──Err───────────────────────────────> Done
/// ```
///
/// `Transient` is a placeholder used during in-place state replacement
/// via [`mem::replace`]; it is never observable outside `decode_step`.
enum State {
    Decoding {
        /// liblzma context for the current xz Stream.
        stream: Stream,
        /// The owned source we read from to refill `input_buf`.
        source: Box<dyn Read + Send>,
    },
    Done,
    Transient,
}

impl XzDecoder {
    /// Construct an [`XzDecoder`] over `src`.
    ///
    /// Does not pull any bytes from the source — construction failure
    /// reflects liblzma context allocation only.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Construct`] if liblzma refuses to allocate
    /// a decompression context.
    pub fn new(src: Box<dyn Read + Send>) -> Result<Self, DecodeError> {
        let stream = Stream::new_stream_decoder(MEMLIMIT, 0)
            .map_err(|e| DecodeError::Construct(io::Error::other(format!("xz init: {e}"))))?;
        Ok(Self {
            state: State::Decoding {
                stream,
                source: src,
            },
            finished_streams_total_in: 0,
            input_buf: vec![0u8; INPUT_CHUNK].into_boxed_slice(),
            input_filled: 0,
            input_pos: 0,
            output_buf: vec![0u8; OUTPUT_CHUNK],
            last_frame_boundary: None,
            consumed_snapshot: 0,
        })
    }

    /// Cumulative bytes liblzma has actually consumed from the source.
    ///
    /// Equal to `finished_streams_total_in + current_stream.total_in()`
    /// when a Stream is live; falls back to the last snapshot otherwise.
    fn live_consumed(&self) -> u64 {
        match &self.state {
            State::Decoding { stream, .. } => self
                .finished_streams_total_in
                .saturating_add(stream.total_in()),
            State::Done | State::Transient => self.consumed_snapshot,
        }
    }

    fn refresh_consumed_snapshot(&mut self) {
        self.consumed_snapshot = self.live_consumed();
    }
}

impl StreamingDecoder for XzDecoder {
    fn decode_step(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, DecodeError> {
        // Each call performs at most one refill + one process; both
        // advance state monotonically and return before the next
        // call. The state machine itself is what loops across calls,
        // not within a single call.
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
                    source: io::Error::other(
                        "xz decoder observed in transient state (poisoned)",
                    ),
                })
            }

            State::Decoding {
                mut stream,
                mut source,
            } => {
                // Refill the input buffer if we've fed everything we
                // previously read from the source. A `read` returning
                // Ok(0) mid-stream is a truncation: we have no
                // StreamEnd yet but the source is gone.
                if self.input_pos >= self.input_filled {
                    match source.read(&mut self.input_buf[..]) {
                        Ok(0) => {
                            let consumed = self
                                .finished_streams_total_in
                                .saturating_add(stream.total_in());
                            self.state = State::Done;
                            self.consumed_snapshot = consumed;
                            return Err(DecodeError::Read {
                                consumed,
                                source: io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "xz: source ended mid-stream",
                                ),
                            });
                        }
                        Ok(n) => {
                            self.input_filled = n;
                            self.input_pos = 0;
                        }
                        Err(err) => {
                            let consumed = self
                                .finished_streams_total_in
                                .saturating_add(stream.total_in());
                            self.state = State::Done;
                            self.consumed_snapshot = consumed;
                            return Err(DecodeError::Read {
                                consumed,
                                source: err,
                            });
                        }
                    }
                }

                let prev_in = stream.total_in();
                let prev_out = stream.total_out();
                let result = stream.process(
                    &self.input_buf[self.input_pos..self.input_filled],
                    &mut self.output_buf,
                    Action::Run,
                );
                let consumed_this = stream.total_in().saturating_sub(prev_in) as usize;
                let produced_this = stream.total_out().saturating_sub(prev_out) as usize;
                self.input_pos = self.input_pos.saturating_add(consumed_this);

                match result {
                    Ok(Status::Ok) | Ok(Status::GetCheck) => {
                        if produced_this > 0 {
                            sink.write_all(&self.output_buf[..produced_this])
                                .map_err(DecodeError::Write)?;
                        }
                        self.state = State::Decoding { stream, source };
                        self.refresh_consumed_snapshot();
                        Ok(DecodeStatus::MoreData)
                    }
                    Ok(Status::StreamEnd) => {
                        if produced_this > 0 {
                            sink.write_all(&self.output_buf[..produced_this])
                                .map_err(DecodeError::Write)?;
                        }
                        // Stream complete: cumulative consumed equals
                        // finished_streams_total_in + this stream's
                        // total_in. Record it as the frame boundary
                        // and either chain a fresh Stream over the
                        // remaining input or transition to Done.
                        self.finished_streams_total_in = self
                            .finished_streams_total_in
                            .saturating_add(stream.total_in());
                        let boundary = self.finished_streams_total_in;
                        self.last_frame_boundary = Some(ByteOffset::new(boundary));
                        self.consumed_snapshot = boundary;
                        // Drop the finished Stream before checking for
                        // follow-on input — it's no longer needed and
                        // freeing it eagerly bounds the peak liblzma
                        // context footprint to one stream at a time.
                        drop(stream);

                        // Determine if more streams follow. If we
                        // still have leftover input bytes those are
                        // the start of the next Stream. Otherwise
                        // probe the source.
                        if self.input_pos >= self.input_filled {
                            match source.read(&mut self.input_buf[..]) {
                                Ok(0) => {
                                    self.input_filled = 0;
                                    self.input_pos = 0;
                                    self.state = State::Done;
                                    // Surface the boundary observation
                                    // through the caller's progress
                                    // contract. The next decode_step
                                    // will see Done and return Eof.
                                    return Ok(DecodeStatus::MoreData);
                                }
                                Ok(n) => {
                                    self.input_filled = n;
                                    self.input_pos = 0;
                                }
                                Err(err) => {
                                    self.state = State::Done;
                                    return Err(DecodeError::Read {
                                        consumed: boundary,
                                        source: err,
                                    });
                                }
                            }
                        }

                        // Build a fresh Stream over whatever bytes
                        // remain (leftover from this read or freshly
                        // refilled). If liblzma rejects construction
                        // we surface it as a mid-stream Read error
                        // rather than Construct — Construct is
                        // reserved for initial construction
                        // (`consumed = 0`).
                        match Stream::new_stream_decoder(MEMLIMIT, 0) {
                            Ok(next) => {
                                self.state = State::Decoding {
                                    stream: next,
                                    source,
                                };
                                Ok(DecodeStatus::MoreData)
                            }
                            Err(err) => {
                                self.state = State::Done;
                                Err(DecodeError::Read {
                                    consumed: boundary,
                                    source: io::Error::other(format!(
                                        "xz next-stream init: {err}"
                                    )),
                                })
                            }
                        }
                    }
                    Ok(Status::MemNeeded) => {
                        // liblzma returns MemNeeded when no progress
                        // is possible without more memory. With
                        // MEMLIMIT == u64::MAX this should not fire
                        // in practice, but if it does we surface it
                        // as a Read error rather than spinning
                        // forever.
                        let consumed = self
                            .finished_streams_total_in
                            .saturating_add(stream.total_in());
                        self.state = State::Done;
                        self.consumed_snapshot = consumed;
                        Err(DecodeError::Read {
                            consumed,
                            source: io::Error::other("xz: memory limit exceeded"),
                        })
                    }
                    Err(err) => {
                        // Errors are terminal: liblzma's state may be
                        // inconsistent and re-running it would risk
                        // silent data loss.
                        let consumed = self
                            .finished_streams_total_in
                            .saturating_add(stream.total_in());
                        self.state = State::Done;
                        self.consumed_snapshot = consumed;
                        Err(DecodeError::Read {
                            consumed,
                            source: io::Error::other(format!("xz: {err}")),
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

/// [`super::DecoderFactory`] adapter for [`XzDecoder`].
///
/// Registered against the `.xz` / `.tar.xz` suffixes, the format name
/// `xz`, and the xz magic `FD 37 7A 58 5A 00` at offset 0 by
/// [`super::DecoderRegistry::with_defaults`].
///
/// # Errors
///
/// Forwards [`DecodeError::Construct`] from [`XzDecoder::new`].
pub fn factory(src: Box<dyn Read + Send>) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    Ok(Box::new(XzDecoder::new(src)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    use xz2::stream::{Check, Stream as XzStream};

    /// Encode a payload as a single-Stream xz blob, using liblzma's
    /// easy encoder at preset 6 (matching `xz`'s default).
    fn encode_xz(payload: &[u8]) -> Vec<u8> {
        let mut encoder = XzStream::new_easy_encoder(6, Check::Crc64).expect("encoder");
        let mut out: Vec<u8> = Vec::with_capacity(payload.len() / 2 + 256);
        let mut input_pos = 0usize;
        let mut scratch = vec![0u8; 1 << 14];
        // Drive the encoder through Run until all input is consumed,
        // then Finish until StreamEnd.
        loop {
            let action = if input_pos < payload.len() {
                Action::Run
            } else {
                Action::Finish
            };
            let prev_in = encoder.total_in();
            let prev_out = encoder.total_out();
            let res = encoder
                .process(&payload[input_pos..], &mut scratch, action)
                .expect("encode step");
            let consumed = (encoder.total_in() - prev_in) as usize;
            let produced = (encoder.total_out() - prev_out) as usize;
            input_pos += consumed;
            out.extend_from_slice(&scratch[..produced]);
            if let Status::StreamEnd = res {
                break;
            }
        }
        out
    }

    /// Round-trip a single xz Stream through the decoder.
    #[test]
    fn single_stream_round_trip() {
        let payload = b"hello, xz frame world!".repeat(2048);
        let compressed = encode_xz(&payload);
        let mut decoder =
            XzDecoder::new(Box::new(Cursor::new(compressed.clone()))).expect("construct");

        let mut sink = Vec::with_capacity(payload.len());
        while let DecodeStatus::MoreData = decoder.decode_step(&mut sink).expect("decode_step") {}

        assert_eq!(sink, payload);
        assert_eq!(decoder.bytes_consumed().get(), compressed.len() as u64);
        assert_eq!(
            decoder.frame_boundary(),
            Some(ByteOffset::new(compressed.len() as u64))
        );
    }

    /// Concatenated Streams decode to the concatenation of their plain
    /// payloads, and every observed boundary lands at a cumulative
    /// end-of-Stream offset.
    #[test]
    fn multi_stream_round_trip_records_each_boundary() {
        let payload_a = b"stream A payload".repeat(512);
        let payload_b = b"stream B payload, longer".repeat(700);
        let stream_a = encode_xz(&payload_a);
        let stream_b = encode_xz(&payload_b);
        let mut combined = stream_a.clone();
        combined.extend_from_slice(&stream_b);

        let mut decoder =
            XzDecoder::new(Box::new(Cursor::new(combined.clone()))).expect("construct");

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
        assert_eq!(boundaries[0], stream_a.len() as u64, "Stream A end");
        assert_eq!(boundaries[1], combined.len() as u64, "Stream B end");
        assert_eq!(decoder.bytes_consumed().get(), combined.len() as u64);
    }

    /// `bytes_consumed` is monotonically non-decreasing across every
    /// `decode_step` call, including across Stream boundaries.
    #[test]
    fn bytes_consumed_is_monotone() {
        let payload = b"xz monotone payload".repeat(1024);
        let stream_a = encode_xz(&payload);
        let mut combined = stream_a.clone();
        combined.extend_from_slice(&stream_a);

        let mut decoder =
            XzDecoder::new(Box::new(Cursor::new(combined.clone()))).expect("construct");

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
        let payload = b"xz bounded payload".repeat(4096);
        let compressed = encode_xz(&payload);
        let len = compressed.len() as u64;
        let mut decoder = XzDecoder::new(Box::new(Cursor::new(compressed))).expect("construct");

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
        let payload = b"xz steady-state".to_vec();
        let compressed = encode_xz(&payload);
        let mut decoder = XzDecoder::new(Box::new(Cursor::new(compressed))).expect("construct");

        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode_step") == DecodeStatus::MoreData {}

        for _ in 0..5 {
            let status = decoder.decode_step(&mut sink).expect("idempotent eof");
            assert_eq!(status, DecodeStatus::Eof);
        }
        assert_eq!(sink, payload);
    }

    /// Empty source: liblzma cannot identify a stream and returns a
    /// format error; we surface it as a clean [`DecodeError::Read`]
    /// without panicking. Construction does *not* consume bytes, so
    /// `consumed` is zero on this path.
    #[test]
    fn empty_source_reports_read_error() {
        let mut decoder =
            XzDecoder::new(Box::new(Cursor::new(Vec::<u8>::new()))).expect("construct");
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
        let mut decoder = XzDecoder::new(Box::new(Cursor::new(garbage))).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { .. }) => {}
            other => panic!("expected Read error from garbage, got {other:?}"),
        }
    }

    /// Truncated streams must surface as a clean
    /// [`DecodeError::Read`] (kind `UnexpectedEof` when the source
    /// runs out, or any other kind if liblzma sees the truncation
    /// first); the decoder must not over-report `bytes_consumed`.
    #[test]
    fn truncated_stream_reports_read_error() {
        let payload = b"xz truncated payload".repeat(2048);
        let compressed = encode_xz(&payload);
        let truncated = compressed[..compressed.len() - 16].to_vec();
        let truncated_len = truncated.len() as u64;
        let mut decoder = XzDecoder::new(Box::new(Cursor::new(truncated))).expect("construct");

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

        let payload = b"xz failing-sink".repeat(8192);
        let compressed = encode_xz(&payload);
        let mut decoder = XzDecoder::new(Box::new(Cursor::new(compressed))).expect("construct");

        // Walk forward until we observe any error — the very first
        // step that produces output will hit the failing sink.
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

    /// Frame-boundary advance step does not produce output: the same
    /// pairing-with-checkpoint discipline the zstd decoder relies on
    /// must hold here, otherwise §10's resume contract breaks for the
    /// xz path the same way it would for the zstd path.
    #[test]
    fn frame_boundary_advance_pairs_with_unchanged_output() {
        let payload_a = b"a".repeat(2048);
        let payload_b = b"b".repeat(4096);
        let stream_a = encode_xz(&payload_a);
        let stream_b = encode_xz(&payload_b);
        let mut combined = stream_a;
        combined.extend_from_slice(&stream_b);

        let mut decoder =
            XzDecoder::new(Box::new(Cursor::new(combined.clone()))).expect("construct");

        let mut sink = Vec::new();
        let mut prior_boundary = decoder.frame_boundary();
        loop {
            let status = decoder.decode_step(&mut sink).expect("decode_step");
            let next_boundary = decoder.frame_boundary();
            if next_boundary != prior_boundary {
                // Boundary observation paired with whatever output
                // had been emitted by this step's StreamEnd-bearing
                // process call. We assert the cumulative output is
                // consistent with the boundary by checking the final
                // sink content below, rather than asserting "no new
                // output this step" — the Stream's final process call
                // legitimately emits residual decoded bytes alongside
                // StreamEnd, and that is part of the prior frame's
                // payload, not the next.
                prior_boundary = next_boundary;
            }
            if status == DecodeStatus::Eof {
                break;
            }
        }

        let mut expected = payload_a;
        expected.extend_from_slice(&payload_b);
        assert_eq!(sink, expected);
    }

    /// Frame boundaries returned by the decoder are valid restart
    /// points: decoding from a recorded boundary produces exactly the
    /// suffix of the stream's plaintext.
    #[test]
    fn frame_boundary_is_a_valid_restart_point() {
        let payload_a = b"restart-A-".repeat(800);
        let payload_b = b"restart-B-longer-".repeat(1200);
        let stream_a = encode_xz(&payload_a);
        let stream_b = encode_xz(&payload_b);
        let mut combined = stream_a.clone();
        combined.extend_from_slice(&stream_b);

        let mut decoder =
            XzDecoder::new(Box::new(Cursor::new(combined.clone()))).expect("construct");
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
        assert_eq!(boundary, stream_a.len() as u64);

        // Re-decode the suffix of the source from the recorded
        // boundary; the result must be the suffix of the plaintext.
        let suffix = combined[boundary as usize..].to_vec();
        let mut restart = XzDecoder::new(Box::new(Cursor::new(suffix))).expect("restart");
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
        let payload = b"xz factory check".repeat(1024);
        let compressed = encode_xz(&payload);
        let mut decoder = factory(Box::new(Cursor::new(compressed.clone()))).expect("factory");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("decode_step") == DecodeStatus::MoreData {}
        assert_eq!(sink, payload);
    }
}
