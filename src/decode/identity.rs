//! Identity ("decompress nothing") streaming decoder.
//!
//! Used for archive formats that have no compression layer wrapping the
//! container — uncompressed `.tar` is the canonical example. The decoder
//! copies bytes verbatim from its source into the sink in bounded
//! [`OUTPUT_CHUNK`]-byte steps so the extractor can interleave punching
//! and checkpointing the same way it does for the zstd decoder.
//!
//! # Frame boundaries
//!
//! An uncompressed stream has no internal restart points the way a
//! multi-frame zstd stream does, but the [`StreamingDecoder::frame_boundary`]
//! contract is also exactly what tar's member-aligned checkpoint
//! discipline needs: any byte position is a valid restart for the
//! decoder (it's just `pread`), and the [`Sink::is_quiescent`] gate
//! guarantees the sink only commits checkpoints between members.
//! Reporting `Some(bytes_consumed)` after every step therefore lets
//! the existing `extractor` loop fire its quiescent-checkpoint cadence
//! without any special-casing for the identity case.

use std::io::{Read, Write};

use crate::decode::{DecodeError, DecodeStatus, StreamingDecoder};
use crate::types::ByteOffset;

/// Output buffer size used per [`StreamingDecoder::decode_step`].
///
/// Same value as [`crate::decode::zstd`]'s `OUTPUT_CHUNK` so the
/// extractor's punch/checkpoint cadence behaves the same way regardless
/// of which decoder is in front of it.
const OUTPUT_CHUNK: usize = 1 << 20;

/// Streaming "do nothing" decoder.
///
/// Owns its source on construction; subsequent
/// [`StreamingDecoder::decode_step`] calls do not need it passed back
/// in. The source is `Send` so the decoder can be moved to a worker
/// thread the same way [`crate::decode::zstd::ZstdDecoder`] can.
pub struct IdentityDecoder {
    /// The wrapped source. `None` once the source has reported clean
    /// EOF; subsequent steps return [`DecodeStatus::Eof`] without
    /// touching the source again.
    source: Option<Box<dyn Read + Send>>,
    /// Total bytes copied from the source so far. Equal to bytes
    /// written into the sink — this decoder is byte-for-byte.
    bytes_copied: u64,
    /// Pre-allocated scratch space for the next decode step.
    output_buf: Vec<u8>,
}

impl IdentityDecoder {
    /// Construct an [`IdentityDecoder`] over `src`.
    ///
    /// Does not pull any bytes from the source — construction never
    /// fails, but the constructor still returns a `Result` so the
    /// signature matches [`super::DecoderFactory`].
    ///
    /// # Errors
    ///
    /// Currently never returns `Err`. The signature is kept fallible
    /// so the type matches [`super::DecoderFactory`] without an extra
    /// adapter.
    pub fn new(src: Box<dyn Read + Send>) -> Result<Self, DecodeError> {
        Ok(Self {
            source: Some(src),
            bytes_copied: 0,
            output_buf: vec![0u8; OUTPUT_CHUNK],
        })
    }
}

impl StreamingDecoder for IdentityDecoder {
    fn decode_step(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, DecodeError> {
        let Some(source) = self.source.as_mut() else {
            return Ok(DecodeStatus::Eof);
        };
        match source.read(&mut self.output_buf) {
            Ok(0) => {
                // Drop the source so future calls cheaply short-circuit
                // and so any file-descriptor resource is released as
                // soon as possible.
                self.source = None;
                Ok(DecodeStatus::Eof)
            }
            Ok(n) => {
                sink.write_all(&self.output_buf[..n])
                    .map_err(DecodeError::Write)?;
                // INVARIANT: `n <= OUTPUT_CHUNK <= isize::MAX`, so the
                // `as u64` cast cannot truncate.
                self.bytes_copied = self.bytes_copied.saturating_add(n as u64);
                Ok(DecodeStatus::MoreData)
            }
            Err(err) => {
                let consumed = self.bytes_copied;
                // A read error is terminal; subsequent steps must not
                // attempt to pull more bytes from a source the OS has
                // already told us is unhappy.
                self.source = None;
                Err(DecodeError::Read {
                    consumed,
                    source: err,
                })
            }
        }
    }

    fn bytes_consumed(&self) -> ByteOffset {
        ByteOffset::new(self.bytes_copied)
    }

    fn frame_boundary(&self) -> Option<ByteOffset> {
        // The whole stream is one big restart-aligned region — every
        // observed offset is a valid resume point. Reporting
        // bytes_copied lets the extractor's quiescent-checkpoint
        // cadence land at the natural sink-side member boundaries
        // instead of stalling waiting for a frame transition that will
        // never arrive.
        Some(ByteOffset::new(self.bytes_copied))
    }
}

/// [`super::DecoderFactory`] adapter for [`IdentityDecoder`].
///
/// Registered against the `.tar` suffix, the format name `tar`, and
/// the `ustar\0` magic at offset 257 by
/// [`super::DecoderRegistry::with_defaults`].
///
/// # Errors
///
/// Forwards [`DecodeError::Construct`] from [`IdentityDecoder::new`].
/// In practice this never fires today; the signature stays fallible
/// to match [`super::DecoderFactory`].
pub fn factory(src: Box<dyn Read + Send>) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    Ok(Box::new(IdentityDecoder::new(src)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    /// A tiny payload round-trips byte-for-byte and reports EOF on the
    /// next step after the source is drained.
    #[test]
    fn small_payload_round_trips() {
        let payload = b"hello, identity!".to_vec();
        let mut decoder =
            IdentityDecoder::new(Box::new(Cursor::new(payload.clone()))).expect("construct");
        let mut sink = Vec::with_capacity(payload.len());
        loop {
            let status = decoder.decode_step(&mut sink).expect("step");
            if status == DecodeStatus::Eof {
                break;
            }
        }
        assert_eq!(sink, payload);
        assert_eq!(decoder.bytes_consumed().get(), payload.len() as u64);
        // Identity decoder reports a frame boundary at the live
        // bytes_copied position.
        assert_eq!(
            decoder.frame_boundary(),
            Some(ByteOffset::new(payload.len() as u64))
        );
    }

    /// `bytes_consumed` and `frame_boundary` advance together and stay
    /// monotone across every step, including across the boundary
    /// between the last data step and the first EOF step.
    #[test]
    fn bytes_and_frame_boundary_are_monotone() {
        let payload = b"monotone-payload".repeat(8192);
        let mut decoder =
            IdentityDecoder::new(Box::new(Cursor::new(payload.clone()))).expect("construct");
        let mut sink = Vec::new();
        let mut last_consumed = 0u64;
        loop {
            let status = decoder.decode_step(&mut sink).expect("step");
            let now = decoder.bytes_consumed().get();
            assert!(now >= last_consumed, "regression {last_consumed} -> {now}");
            assert_eq!(decoder.frame_boundary(), Some(ByteOffset::new(now)));
            last_consumed = now;
            if status == DecodeStatus::Eof {
                break;
            }
        }
        assert_eq!(last_consumed, payload.len() as u64);
    }

    /// Sources larger than [`OUTPUT_CHUNK`] need multiple steps and the
    /// decoder must still copy every byte without dropping a single
    /// one across step boundaries.
    #[test]
    fn payload_larger_than_one_step_round_trips() {
        // OUTPUT_CHUNK + a little, so we need at least two steps.
        let len = OUTPUT_CHUNK + 12345;
        let mut payload = Vec::with_capacity(len);
        for i in 0..len {
            payload.push((i % 251) as u8);
        }
        let mut decoder =
            IdentityDecoder::new(Box::new(Cursor::new(payload.clone()))).expect("construct");
        let mut sink = Vec::with_capacity(len);
        let mut steps = 0u32;
        loop {
            let status = decoder.decode_step(&mut sink).expect("step");
            steps += 1;
            if status == DecodeStatus::Eof {
                break;
            }
            assert!(steps < 1024, "should converge in << 1024 steps");
        }
        assert_eq!(sink, payload);
        assert_eq!(decoder.bytes_consumed().get(), len as u64);
    }

    /// Repeated calls after EOF stay at EOF; the underlying source
    /// dropping does not turn into a panic or an extra read.
    #[test]
    fn repeated_calls_after_eof_stay_eof() {
        let payload = b"steady-eof".to_vec();
        let mut decoder =
            IdentityDecoder::new(Box::new(Cursor::new(payload.clone()))).expect("construct");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("step") == DecodeStatus::MoreData {}
        for _ in 0..5 {
            assert_eq!(
                decoder.decode_step(&mut sink).expect("idempotent eof"),
                DecodeStatus::Eof,
            );
        }
        assert_eq!(sink, payload);
    }

    /// Empty source: the very first step reports EOF and writes
    /// nothing.
    #[test]
    fn empty_source_reports_eof_immediately() {
        let mut decoder =
            IdentityDecoder::new(Box::new(Cursor::new(Vec::<u8>::new()))).expect("construct");
        let mut sink = Vec::new();
        assert_eq!(
            decoder.decode_step(&mut sink).expect("step"),
            DecodeStatus::Eof
        );
        assert!(sink.is_empty());
        assert_eq!(decoder.bytes_consumed().get(), 0);
        // A frame boundary at zero is still reported, matching the
        // monotone-from-construction contract callers depend on.
        assert_eq!(decoder.frame_boundary(), Some(ByteOffset::ZERO));
    }

    /// A failing source surfaces as [`DecodeError::Read`] without
    /// over-reporting `bytes_consumed`. Once the read fails, the
    /// decoder must not pull any further bytes from the source — we
    /// verify that by handing it a source that panics on a second
    /// `read` call.
    #[test]
    fn source_failure_propagates_as_read_error_and_stops() {
        struct OneShotFailingReader {
            calls: u32,
        }
        impl Read for OneShotFailingReader {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                self.calls += 1;
                if self.calls == 1 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "boom",
                    ));
                }
                panic!("decoder pulled from source after a Read error");
            }
        }
        let mut decoder =
            IdentityDecoder::new(Box::new(OneShotFailingReader { calls: 0 })).expect("construct");
        let mut sink = Vec::new();
        match decoder.decode_step(&mut sink) {
            Err(DecodeError::Read { consumed, source }) => {
                assert_eq!(consumed, 0);
                assert_eq!(source.kind(), std::io::ErrorKind::ConnectionAborted);
            }
            other => panic!("expected Read error, got {other:?}"),
        }
        // After the error, subsequent steps cleanly report EOF without
        // touching the (now panicking) source.
        for _ in 0..3 {
            assert_eq!(
                decoder
                    .decode_step(&mut sink)
                    .expect("clean EOF after error"),
                DecodeStatus::Eof,
            );
        }
    }

    /// A failing sink surfaces as [`DecodeError::Write`] and the
    /// decoder reports the bytes it actually copied (which, on the
    /// step that failed, is zero — `write_all` is all-or-nothing from
    /// our caller's point of view).
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

        let payload = b"sink-fails".repeat(8192);
        let mut decoder = IdentityDecoder::new(Box::new(Cursor::new(payload))).expect("construct");
        match decoder.decode_step(&mut FailingSink) {
            Err(DecodeError::Write(e)) => {
                assert_eq!(e.kind(), std::io::ErrorKind::BrokenPipe);
            }
            other => panic!("expected Write error, got {other:?}"),
        }
        // We failed before writing, so bytes_consumed stays at zero.
        assert_eq!(decoder.bytes_consumed().get(), 0);
    }

    /// The factory plumbing constructs a working decoder.
    #[test]
    fn factory_constructs_and_decodes() {
        let payload = b"factory-id-check".repeat(1024);
        let mut decoder = factory(Box::new(Cursor::new(payload.clone()))).expect("factory");
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink).expect("step") == DecodeStatus::MoreData {}
        assert_eq!(sink, payload);
    }
}
