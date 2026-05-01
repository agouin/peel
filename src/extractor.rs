//! Drive a [`StreamingDecoder`] forward, fan its output into a [`Sink`],
//! and release source blocks behind the decoder via a [`PunchHole`].
//!
//! The loop is a Rust port of `pyproto/core.py`'s `PunchingExtractor`,
//! with the §8.1 refinement that punching is gated on a *quiescent
//! checkpoint position* rather than just `bytes_consumed`. The
//! checkpoint advances only when the decoder reports a
//! [`StreamingDecoder::frame_boundary`] *and* the sink reports
//! [`Sink::is_quiescent`] in the same step. Anything we punch is
//! irrecoverable; aligning the punch limit with restart-safe positions
//! means a crash here loses at most one frame of work even before the
//! §9 checkpointing layer is in place.
//!
//! # Stats
//!
//! [`ExtractionStats`] records what the extractor saw: bytes consumed
//! from the source, bytes written to the sink, bytes successfully
//! punched, plus a coarse breakdown of where wall-clock time went
//! (decode vs. write vs. punch). Stats are reset on every
//! [`Extractor::extract`] call and represent that single extraction.
//!
//! # Source ownership
//!
//! The extractor borrows the source's file descriptor for hole punching
//! but does not read from it directly — the decoder, constructed by
//! the caller, owns the read side. The accompanying
//! `examples/extract_demo.rs` opens the source twice (one read handle
//! for the decoder, one read-write handle for punching) and passes the
//! latter's [`BorrowedFd`] to [`Extractor::extract`]. The §10
//! coordinator follows the same shape, plumbing the fd through the
//! [`crate::download::SparseFile`] it already owns.

#![cfg(unix)]

use std::io::Write;
use std::os::fd::BorrowedFd;
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::decode::{DecodeError, DecodeStatus, StreamingDecoder};
use crate::progress::ProgressState;
use crate::punch::{align_down, PunchError, PunchHole};
use crate::sink::{Sink, SinkError};
use crate::types::ByteOffset;

/// Default minimum gap, in bytes, between successive punch syscalls.
///
/// Matches the Python prototype's `_PUNCH_THRESHOLD` (4 MiB). Smaller
/// values reduce the in-flight compressed footprint at the cost of more
/// syscalls; larger values amortize the syscall over more decoded
/// bytes.
pub const DEFAULT_PUNCH_THRESHOLD: u64 = 4 * 1024 * 1024;

/// Errors produced by [`Extractor::extract`].
///
/// The variants distinguish the three responsibilities the extractor
/// fans the work across: the decoder (source byte stream), the sink
/// (output destination), and the puncher (block release on the
/// source). Callers can `match` on the variant to decide what to log
/// vs. retry vs. surface as a hard failure.
#[derive(Debug, Error)]
pub enum ExtractorError {
    /// The decoder rejected the source bytes.
    #[error("decode failed during extraction")]
    Decode(#[source] DecodeError),

    /// The sink rejected a write or its terminal close check.
    #[error("sink failed during extraction")]
    Sink(#[source] SinkError),

    /// The puncher returned an unrecoverable error.
    /// `PunchError::Unsupported` is *not* surfaced as an error — it is
    /// observed once and downgrades the rest of the extraction to a
    /// no-op puncher silently.
    #[error("hole punch failed at offset {offset} length {length}")]
    Punch {
        /// Offset passed to the failing punch.
        offset: u64,
        /// Length passed to the failing punch.
        length: u64,
        /// The underlying puncher error.
        #[source]
        source: PunchError,
    },

    /// Defensive: the decoder reported [`DecodeError::Write`] but the
    /// adapter that wraps the sink did not capture the underlying
    /// [`SinkError`]. By construction this cannot happen; surfacing it
    /// as its own variant keeps the public error surface honest if a
    /// future refactor breaks the invariant.
    #[error("sink reported failure but the typed error was lost (internal invariant)")]
    SinkErrorLost,

    /// The checkpoint observer registered via
    /// [`Extractor::extract_with_callback`] returned an error. The
    /// underlying cause is preserved for the coordinator to surface.
    #[error("checkpoint observer aborted extraction")]
    Observer(#[source] std::io::Error),
}

/// Tunables for [`Extractor::extract`].
#[derive(Debug, Clone, Copy)]
pub struct ExtractorConfig {
    /// Minimum gap, in bytes, between successive punch syscalls. The
    /// extractor accumulates progress and only invokes the puncher
    /// when the unpunched-but-checkpointed prefix is at least this
    /// large.
    pub punch_threshold: u64,
}

impl Default for ExtractorConfig {
    fn default() -> Self {
        Self {
            punch_threshold: DEFAULT_PUNCH_THRESHOLD,
        }
    }
}

/// Snapshot passed to the [`Extractor::extract_with_callback`]
/// observer on every quiescent advance.
///
/// The observer is the §10 coordinator's hook for writing a checkpoint
/// at exactly the right moment: the decoder has just completed a frame
/// **and** the sink reports it is at a member boundary, so the source
/// position recorded here is a restart-safe point for resume.
#[derive(Debug, Clone)]
pub struct CheckpointInfo {
    /// Source byte offset immediately past the most recently completed
    /// frame. Resume seeks the decoder back to this offset.
    pub source_position: u64,
    /// Total bytes consumed from the source by the decoder so far.
    pub bytes_in: u64,
    /// Total bytes the sink has accepted so far.
    pub bytes_out: u64,
    /// Running count of quiescent checkpoints observed in this run,
    /// inclusive of this one. Useful for throttling cadence.
    pub quiescent_index: u64,
    /// Opaque per-decoder state captured at the same step the
    /// boundary advanced, when the decoder needs more than the offset
    /// alone to resume cleanly. See
    /// [`StreamingDecoder::decoder_state`]. `None` for decoders whose
    /// frame boundaries are restartable from the offset alone (the
    /// historical contract; everything but lz4's mid-frame boundaries
    /// today).
    pub decoder_state: Option<Vec<u8>>,
}

/// Wall-clock and byte-volume statistics for one extraction.
///
/// Times overlap inside the decode loop only inasmuch as
/// [`Self::write_time`] is *subtracted out* of [`Self::decode_time`]
/// when the sink write happens inside `decode_step`. The three time
/// fields are therefore disjoint and can be summed for "useful time"
/// without double-counting.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExtractionStats {
    /// Total bytes the decoder reported as consumed from the source
    /// when the loop ended. For a clean extraction this equals the
    /// source's logical length.
    pub bytes_in: u64,
    /// Total bytes the sink accepted via [`Sink::write`].
    pub bytes_out: u64,
    /// Total bytes successfully released via [`PunchHole::punch`].
    /// Zero when the puncher reported [`PunchError::Unsupported`] on
    /// its first call.
    pub bytes_punched: u64,
    /// Number of successful [`PunchHole::punch`] calls.
    pub punch_calls: u64,
    /// True if the puncher reported [`PunchError::Unsupported`] at
    /// least once. After that point, the extractor stops issuing
    /// punches (the source's compressed footprint is held until the
    /// caller deletes the file).
    pub punch_unsupported: bool,
    /// Number of distinct frame-boundary observations. Each transition
    /// of [`StreamingDecoder::frame_boundary`] to a new value
    /// increments this counter once.
    pub frame_boundaries_observed: u64,
    /// Number of times the checkpoint position was advanced. A
    /// checkpoint advance requires both a new frame boundary *and*
    /// [`Sink::is_quiescent`]; these are usually but not always
    /// 1:1 with frame boundaries.
    pub quiescent_checkpoints: u64,
    /// Wall-clock time spent inside [`StreamingDecoder::decode_step`],
    /// minus the time the decoder spent calling the sink.
    pub decode_time: Duration,
    /// Wall-clock time spent inside [`Sink::write`], cumulated across
    /// every call the decoder made into the wrapping adapter.
    pub write_time: Duration,
    /// Wall-clock time spent inside [`PunchHole::punch`].
    pub punch_time: Duration,
}

/// Coordinator that ties decoder, sink, and puncher into one loop.
///
/// `Extractor` is configuration-only; create it once with
/// [`Extractor::with_defaults`] (or [`Extractor::new`] for a custom
/// [`ExtractorConfig`]) and reuse it for as many extractions as the
/// caller has work for. The state for any single extraction lives
/// entirely on the call stack of [`Self::extract`].
///
/// Optionally pairs with a [`ProgressState`] (via
/// [`Self::with_progress`]) so the per-write byte counter feeds the
/// `PLAN_v2.md` §6 progress UI.
#[derive(Debug, Clone)]
pub struct Extractor {
    config: ExtractorConfig,
    progress: Option<Arc<ProgressState>>,
}

impl Extractor {
    /// Create an extractor with the given config.
    #[must_use]
    pub fn new(config: ExtractorConfig) -> Self {
        Self {
            config,
            progress: None,
        }
    }

    /// Create an extractor with [`ExtractorConfig::default`].
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(ExtractorConfig::default())
    }

    /// Attach a [`ProgressState`] to the extractor. Every successful
    /// sink write `fetch_add`s its byte length into
    /// [`ProgressState::add_extracted`]; the renderer thread reads
    /// from there asynchronously.
    #[must_use]
    pub fn with_progress(mut self, progress: Arc<ProgressState>) -> Self {
        self.progress = Some(progress);
        self
    }

    /// Borrow the configured tunables.
    #[must_use]
    pub fn config(&self) -> &ExtractorConfig {
        &self.config
    }

    /// Drive `decoder` to completion, fanning its output into `sink`
    /// and punching the source behind quiescent checkpoints.
    ///
    /// `source_fd` must refer to the same file the decoder is reading
    /// from and must be open with write permission (the punch syscall
    /// requires it). The caller typically opens the source twice — one
    /// read-only handle for the decoder and one read-write handle for
    /// the puncher — and hands the read-write handle's
    /// [`BorrowedFd`] in here.
    ///
    /// # Errors
    ///
    /// Returns the appropriate [`ExtractorError`] variant on failure.
    /// `PunchError::Unsupported` is *not* a hard failure: the first
    /// such observation flips [`ExtractionStats::punch_unsupported`]
    /// and the rest of the extraction proceeds without space
    /// reclamation.
    pub fn extract<S: Sink>(
        &self,
        source_fd: BorrowedFd<'_>,
        decoder: &mut dyn StreamingDecoder,
        sink: S,
        puncher: &dyn PunchHole,
    ) -> Result<ExtractionStats, ExtractorError> {
        self.extract_with_callback(source_fd, decoder, sink, puncher, |_| Ok(()))
    }

    /// Like [`Self::extract`] but invokes `on_checkpoint` whenever the
    /// extractor advances its quiescent-checkpoint position.
    ///
    /// The callback fires *before* the in-loop punch for that
    /// position, so a coordinator using it to write a durable
    /// checkpoint sees the discipline:
    ///
    /// 1. Decoder + sink report a quiescent boundary.
    /// 2. Coordinator writes its checkpoint.
    /// 3. Extractor punches the source up to the boundary.
    ///
    /// If the callback returns `Err`, the extractor stops and surfaces
    /// the failure as [`ExtractorError::Observer`]; no further bytes
    /// are written and no further punches issued.
    ///
    /// # Errors
    ///
    /// Same as [`Self::extract`], plus [`ExtractorError::Observer`] if
    /// `on_checkpoint` returns `Err`.
    pub fn extract_with_callback<S, F>(
        &self,
        source_fd: BorrowedFd<'_>,
        decoder: &mut dyn StreamingDecoder,
        mut sink: S,
        puncher: &dyn PunchHole,
        on_checkpoint: F,
    ) -> Result<ExtractionStats, ExtractorError>
    where
        S: Sink,
        F: FnMut(CheckpointInfo) -> std::io::Result<()>,
    {
        let stats = self.run_loop(source_fd, decoder, &mut sink, puncher, on_checkpoint)?;
        sink.close().map_err(ExtractorError::Sink)?;
        Ok(stats)
    }

    /// Inner loop. Borrowing `&mut sink` here (rather than moving) is
    /// what lets [`Self::extract`] call `sink.close()` once the loop
    /// returns and the borrow is released.
    fn run_loop<S, F>(
        &self,
        source_fd: BorrowedFd<'_>,
        decoder: &mut dyn StreamingDecoder,
        sink: &mut S,
        puncher: &dyn PunchHole,
        mut on_checkpoint: F,
    ) -> Result<ExtractionStats, ExtractorError>
    where
        S: Sink,
        F: FnMut(CheckpointInfo) -> std::io::Result<()>,
    {
        // Align to the puncher's preferred block boundary or 4 KiB,
        // whichever is larger. Misaligned tails are silently retained
        // by the kernel rather than treated as an error; aligning here
        // keeps the punch effective without surprising the caller.
        let block = puncher.block_size_hint().max(4096);

        let mut stats = ExtractionStats::default();
        let mut last_punched: u64 = 0;
        let mut last_quiescent_at: u64 = 0;
        let mut last_observed_boundary: Option<u64> = None;
        let mut punch_disabled = false;

        let mut adapter = SinkAdapter {
            sink,
            bytes_out: 0,
            write_time: Duration::ZERO,
            captured: None,
            progress: self.progress.as_deref(),
        };

        loop {
            // Time the decode_step call as a whole, then subtract out
            // any time the inner sink.write spent — that becomes
            // stats.write_time, and the rest is decode-only time.
            let pre_write = adapter.write_time;
            let t_decode = Instant::now();
            let step = decoder.decode_step(&mut adapter);
            let total = t_decode.elapsed();
            let write_delta = adapter.write_time.saturating_sub(pre_write);
            stats.decode_time = stats
                .decode_time
                .saturating_add(total.saturating_sub(write_delta));
            stats.write_time = stats.write_time.saturating_add(write_delta);

            let status = match step {
                Ok(s) => s,
                Err(DecodeError::Write(_)) => {
                    // The decoder surfaces a write failure as an
                    // io::Error; the adapter captured the typed
                    // SinkError before returning that io::Error.
                    return Err(adapter
                        .captured
                        .take()
                        .map_or(ExtractorError::SinkErrorLost, ExtractorError::Sink));
                }
                Err(other) => return Err(ExtractorError::Decode(other)),
            };

            stats.bytes_in = decoder.bytes_consumed().get();

            // Checkpoint discipline: only fire when the boundary
            // *just* advanced AND the sink is quiescent in the same
            // step. If we instead allowed firing on a later iteration
            // (after the boundary changed), the sink might have
            // already consumed bytes from frame N+1 — pairing an old
            // `source_position` with a newer `bytes_out` and breaking
            // resume's byte-identical guarantee.
            let boundary = decoder.frame_boundary().map(ByteOffset::get);
            let boundary_advanced = boundary != last_observed_boundary && boundary.is_some();
            if boundary_advanced {
                stats.frame_boundaries_observed = stats.frame_boundaries_observed.saturating_add(1);
                last_observed_boundary = boundary;
            }
            if boundary_advanced {
                if let Some(b) = boundary {
                    if adapter.sink.is_quiescent() && b > last_quiescent_at {
                        last_quiescent_at = b;
                        stats.quiescent_checkpoints = stats.quiescent_checkpoints.saturating_add(1);
                        let info = CheckpointInfo {
                            source_position: b,
                            bytes_in: stats.bytes_in,
                            bytes_out: adapter.bytes_out,
                            quiescent_index: stats.quiescent_checkpoints,
                            decoder_state: decoder.decoder_state(),
                        };
                        on_checkpoint(info).map_err(ExtractorError::Observer)?;
                    }
                }
            }

            // Punch behind last_quiescent_at, aligned to filesystem
            // blocks. We never punch past the most recent
            // checkpoint-safe position even though more bytes have
            // technically been consumed; that discipline is what makes
            // a crash here recoverable.
            if !punch_disabled {
                self.maybe_punch(
                    source_fd,
                    puncher,
                    block,
                    last_quiescent_at,
                    &mut last_punched,
                    &mut stats,
                    &mut punch_disabled,
                    /*final_sweep=*/ false,
                )?;
            }

            if status == DecodeStatus::Eof {
                break;
            }
        }

        // Final sweep: release every block up to the last checkpoint,
        // ignoring the punch_threshold so even a small tail gets
        // freed.
        if !punch_disabled {
            self.maybe_punch(
                source_fd,
                puncher,
                block,
                last_quiescent_at,
                &mut last_punched,
                &mut stats,
                &mut punch_disabled,
                /*final_sweep=*/ true,
            )?;
        }

        stats.bytes_in = decoder.bytes_consumed().get();
        stats.bytes_out = adapter.bytes_out;
        Ok(stats)
    }

    /// Issue a punch covering `[last_punched, align_down(quiescent_at))`
    /// when the gap meets the configured threshold (or unconditionally
    /// during the final sweep).
    #[allow(clippy::too_many_arguments)]
    fn maybe_punch(
        &self,
        source_fd: BorrowedFd<'_>,
        puncher: &dyn PunchHole,
        block: u64,
        quiescent_at: u64,
        last_punched: &mut u64,
        stats: &mut ExtractionStats,
        punch_disabled: &mut bool,
        final_sweep: bool,
    ) -> Result<(), ExtractorError> {
        // INVARIANT: `block >= 4096 > 0`, so `align_down` returns Some.
        let aligned = align_down(quiescent_at, block).unwrap_or(0);
        let gap = aligned.saturating_sub(*last_punched);
        let should_punch = if final_sweep {
            gap > 0
        } else {
            gap >= self.config.punch_threshold
        };
        if !should_punch {
            return Ok(());
        }

        let t = Instant::now();
        let result = puncher.punch(source_fd, ByteOffset::new(*last_punched), gap);
        stats.punch_time = stats.punch_time.saturating_add(t.elapsed());

        match result {
            Ok(()) => {
                stats.bytes_punched = stats.bytes_punched.saturating_add(gap);
                stats.punch_calls = stats.punch_calls.saturating_add(1);
                *last_punched = aligned;
                Ok(())
            }
            Err(PunchError::Unsupported { .. }) => {
                stats.punch_unsupported = true;
                *punch_disabled = true;
                Ok(())
            }
            Err(other) => Err(ExtractorError::Punch {
                offset: *last_punched,
                length: gap,
                source: other,
            }),
        }
    }
}

/// `Write` adapter that forwards into a [`Sink`], counts bytes, and
/// times the call so the extractor can split decode time from sink
/// write time. Captures the typed [`SinkError`] on failure so the
/// extractor can recover it after `decode_step` collapses it to an
/// `io::Error`.
struct SinkAdapter<'a, S: Sink> {
    sink: &'a mut S,
    bytes_out: u64,
    write_time: Duration,
    captured: Option<SinkError>,
    progress: Option<&'a ProgressState>,
}

impl<S: Sink> Write for SinkAdapter<'_, S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let t = Instant::now();
        let result = self.sink.write(buf);
        self.write_time = self.write_time.saturating_add(t.elapsed());
        match result {
            Ok(()) => {
                // u64 can address every byte we'll ever care about; an
                // `as` cast is fine because `buf.len() <= isize::MAX`.
                let n = buf.len() as u64;
                self.bytes_out = self.bytes_out.saturating_add(n);
                if let Some(p) = self.progress {
                    p.add_extracted(n);
                }
                Ok(buf.len())
            }
            Err(e) => {
                let kind = match &e {
                    SinkError::Io { source, .. } => source.kind(),
                    _ => std::io::ErrorKind::Other,
                };
                self.captured = Some(e);
                Err(std::io::Error::new(
                    kind,
                    "sink rejected write (typed error captured by adapter)",
                ))
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Cursor, Read};
    use std::os::fd::AsFd;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::decode::zstd::ZstdDecoder;
    use crate::punch::NoopPuncher;
    use crate::sink::RawSink;

    static UNIQ: AtomicU64 = AtomicU64::new(0);

    fn unique_temp(label: &str) -> PathBuf {
        let pid = std::process::id();
        let n = UNIQ.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("peel_extractor_unit_{label}_{pid}_{nanos}_{n}"))
    }

    struct CleanupOnDrop(PathBuf);
    impl Drop for CleanupOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Sink-into-`Vec` for tests. Always quiescent; error on demand.
    /// `fail_at = Some(N)` makes the next write that would push the
    /// total past `N` bytes fail, regardless of the chunk size the
    /// decoder hands us.
    struct VecSink {
        bytes: Vec<u8>,
        fail_at: Option<u64>,
        is_quiescent: bool,
    }

    impl Sink for VecSink {
        fn write(&mut self, buf: &[u8]) -> Result<(), SinkError> {
            if let Some(at) = self.fail_at {
                if self.bytes.len() as u64 + buf.len() as u64 > at {
                    return Err(SinkError::Io {
                        path: PathBuf::from("test-vec-sink"),
                        source: std::io::Error::new(std::io::ErrorKind::BrokenPipe, "boom"),
                    });
                }
            }
            self.bytes.extend_from_slice(buf);
            Ok(())
        }
        fn is_quiescent(&self) -> bool {
            self.is_quiescent
        }
        fn close(self) -> Result<(), SinkError> {
            Ok(())
        }
    }

    /// Hand-rolled LCG for "random enough" bytes — same shape as the
    /// generator in `crate::types::tests` and `crate::decode::zstd::tests`.
    /// Inlined rather than promoted to a shared helper because each
    /// module's tests stay self-contained for readability.
    fn random_bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            out.extend_from_slice(&state.to_le_bytes());
        }
        out.truncate(len);
        out
    }

    /// Sink that toggles quiescence with each byte boundary, used to
    /// drive the quiescent-checkpoint advance count.
    struct ToggleQuiescentSink {
        bytes: Vec<u8>,
        quiescent: bool,
    }
    impl Sink for ToggleQuiescentSink {
        fn write(&mut self, buf: &[u8]) -> Result<(), SinkError> {
            self.bytes.extend_from_slice(buf);
            self.quiescent = !self.quiescent;
            Ok(())
        }
        fn is_quiescent(&self) -> bool {
            self.quiescent
        }
        fn close(self) -> Result<(), SinkError> {
            Ok(())
        }
    }

    /// Build a multi-frame zstd stream over `payloads`.
    fn encode_frames(payloads: &[&[u8]]) -> (Vec<u8>, Vec<usize>) {
        let mut combined = Vec::new();
        let mut ends = Vec::with_capacity(payloads.len());
        for p in payloads {
            let frame = ::zstd::encode_all(*p, 1).expect("encode");
            combined.extend_from_slice(&frame);
            ends.push(combined.len());
        }
        (combined, ends)
    }

    /// Smoke: drive a single-frame zstd stream through a Vec sink and
    /// verify byte-for-byte the output and the recorded stats.
    #[test]
    fn extracts_single_frame_into_vec_sink() {
        let payload = b"single-frame extractor unit test\n".repeat(1024);
        let (compressed, _) = encode_frames(&[&payload]);
        let len = compressed.len() as u64;

        let mut decoder = ZstdDecoder::new(Box::new(Cursor::new(compressed))).expect("ctor");
        let sink = VecSink {
            bytes: Vec::with_capacity(payload.len()),
            fail_at: None,
            is_quiescent: true,
        };

        let stdout = std::io::stdout();
        // The puncher gets a borrowed fd from any open file. We are
        // not actually punching anything here (NoopPuncher) so a
        // non-regular fd like stdout is fine.
        let extractor = Extractor::with_defaults();
        let stats = extractor
            .extract(stdout.as_fd(), &mut decoder, sink, &NoopPuncher::new())
            .expect("extract");

        assert_eq!(stats.bytes_in, len);
        assert_eq!(stats.bytes_out, payload.len() as u64);
        assert_eq!(stats.bytes_punched, 0);
        assert_eq!(stats.punch_calls, 0);
        assert!(stats.frame_boundaries_observed >= 1);
        // Single-frame stream + always-quiescent sink: at least one
        // checkpoint advance, possibly more (e.g. terminal Eof).
        assert!(stats.quiescent_checkpoints >= 1);
    }

    /// Multi-frame source: every frame end is observed, and each one
    /// advances the quiescent checkpoint.
    #[test]
    fn observes_frame_boundaries_and_advances_checkpoints() {
        let frame_a = b"alpha".repeat(2048);
        let frame_b = b"beta-bigger".repeat(4096);
        let frame_c = b"gamma-tiny".to_vec();
        let (compressed, _ends) = encode_frames(&[&frame_a, &frame_b, &frame_c]);
        let len = compressed.len() as u64;

        let mut decoder = ZstdDecoder::new(Box::new(Cursor::new(compressed))).expect("ctor");
        let sink = VecSink {
            bytes: Vec::new(),
            fail_at: None,
            is_quiescent: true,
        };

        let stdout = std::io::stdout();
        let stats = Extractor::with_defaults()
            .extract(stdout.as_fd(), &mut decoder, sink, &NoopPuncher::new())
            .expect("extract");

        assert_eq!(stats.bytes_in, len);
        assert_eq!(
            stats.bytes_out,
            (frame_a.len() + frame_b.len() + frame_c.len()) as u64,
        );
        assert!(
            stats.frame_boundaries_observed >= 3,
            "saw {} frame boundaries",
            stats.frame_boundaries_observed,
        );
        assert!(
            stats.quiescent_checkpoints >= 3,
            "advanced checkpoint {} times",
            stats.quiescent_checkpoints,
        );
    }

    /// A non-quiescent sink suppresses checkpoint advances entirely:
    /// frame boundaries are still observed but the safe punch position
    /// never moves, so [`ExtractionStats::quiescent_checkpoints`]
    /// stays at zero.
    #[test]
    fn non_quiescent_sink_blocks_checkpoint_advance() {
        let payload = b"never-quiescent".repeat(512);
        let (compressed, _) = encode_frames(&[&payload, &payload]);

        let mut decoder = ZstdDecoder::new(Box::new(Cursor::new(compressed))).expect("ctor");
        let sink = VecSink {
            bytes: Vec::new(),
            fail_at: None,
            is_quiescent: false,
        };

        let stats = Extractor::with_defaults()
            .extract(
                std::io::stdout().as_fd(),
                &mut decoder,
                sink,
                &NoopPuncher::new(),
            )
            .expect("extract");

        assert!(stats.frame_boundaries_observed >= 2);
        assert_eq!(stats.quiescent_checkpoints, 0);
        assert_eq!(stats.bytes_punched, 0);
    }

    /// A sink that errors mid-stream surfaces as
    /// [`ExtractorError::Sink`] carrying the original [`SinkError`],
    /// not as a generic decode error.
    #[test]
    fn sink_error_surfaces_as_typed_error() {
        let payload = b"sink-fails-mid".repeat(8192);
        let (compressed, _) = encode_frames(&[&payload]);

        let mut decoder = ZstdDecoder::new(Box::new(Cursor::new(compressed))).expect("ctor");
        let sink = VecSink {
            bytes: Vec::new(),
            fail_at: Some(1024),
            is_quiescent: true,
        };

        let result = Extractor::with_defaults().extract(
            std::io::stdout().as_fd(),
            &mut decoder,
            sink,
            &NoopPuncher::new(),
        );
        match result {
            Err(ExtractorError::Sink(SinkError::Io { source, .. })) => {
                assert_eq!(source.kind(), std::io::ErrorKind::BrokenPipe);
            }
            other => panic!("expected ExtractorError::Sink, got {other:?}"),
        }
    }

    /// Garbage source bytes: the decoder rejects them and we surface
    /// [`ExtractorError::Decode`] verbatim — the puncher must not have
    /// been invoked, and the sink does not see a single byte.
    #[test]
    fn decode_error_surfaces_typed_and_skips_punch() {
        let mut decoder = ZstdDecoder::new(Box::new(Cursor::new(vec![0xCC; 4096]))).expect("ctor");

        // Recording puncher to confirm we never called punch.
        struct CountingPuncher(std::sync::atomic::AtomicUsize);
        impl PunchHole for CountingPuncher {
            fn punch(
                &self,
                _fd: BorrowedFd<'_>,
                _offset: ByteOffset,
                _length: u64,
            ) -> Result<(), PunchError> {
                self.0.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            fn block_size_hint(&self) -> u64 {
                4096
            }
        }
        let puncher = CountingPuncher(std::sync::atomic::AtomicUsize::new(0));
        let sink = VecSink {
            bytes: Vec::new(),
            fail_at: None,
            is_quiescent: true,
        };

        let result = Extractor::with_defaults().extract(
            std::io::stdout().as_fd(),
            &mut decoder,
            sink,
            &puncher,
        );
        match result {
            Err(ExtractorError::Decode(DecodeError::Read { .. })) => {}
            other => panic!("expected Decode::Read, got {other:?}"),
        }
        assert_eq!(puncher.0.load(Ordering::Relaxed), 0);
    }

    /// Toggling-quiescent sink should advance the checkpoint *some* of
    /// the time but not on every frame boundary. Whatever the actual
    /// number, the sink ends up holding the entire decoded payload.
    #[test]
    fn toggle_quiescent_sink_extracts_full_payload() {
        let payload_a = b"toggle".repeat(700);
        let payload_b = b"checkpoint".repeat(900);
        let (compressed, _) = encode_frames(&[&payload_a, &payload_b]);
        let total: Vec<u8> = payload_a.iter().chain(payload_b.iter()).copied().collect();

        let mut decoder = ZstdDecoder::new(Box::new(Cursor::new(compressed))).expect("ctor");
        let sink = ToggleQuiescentSink {
            bytes: Vec::with_capacity(total.len()),
            quiescent: true,
        };

        // Capture the sink contents through a side channel: VecSink's
        // owner is the extractor. For this test we need the bytes
        // back, so we pre-allocate and verify via the stats that the
        // count matches.
        let stats = Extractor::with_defaults()
            .extract(
                std::io::stdout().as_fd(),
                &mut decoder,
                sink,
                &NoopPuncher::new(),
            )
            .expect("extract");

        assert_eq!(stats.bytes_out, total.len() as u64);
    }

    /// Small punch threshold: the in-loop punch fires (against a
    /// real file) and `bytes_punched` reflects the punched range.
    /// We don't assert disk shrinkage here because that depends on
    /// the host filesystem; that lives in the integration tests.
    /// We *do* assert that the puncher saw a non-zero gap.
    #[test]
    fn small_threshold_triggers_in_loop_punches() {
        // Random-looking payloads compress poorly so the per-frame
        // compressed size easily exceeds the 4 KiB block alignment
        // and the punch threshold below.
        let frame_a = random_bytes(0xA1, 64 * 1024);
        let frame_b = random_bytes(0xB2, 64 * 1024);
        let frame_c = random_bytes(0xC3, 64 * 1024);
        let (compressed, _) = encode_frames(&[&frame_a, &frame_b, &frame_c]);
        assert!(
            compressed.len() > 8192,
            "compressed source must straddle the threshold (got {} bytes)",
            compressed.len(),
        );

        let path = unique_temp("threshold");
        let _g = CleanupOnDrop(path.clone());
        std::fs::write(&path, &compressed).expect("write source");
        let punch_handle = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open rw");

        let mut decoder =
            ZstdDecoder::new(Box::new(std::fs::File::open(&path).expect("open ro"))).expect("ctor");

        // Recording puncher reports its own block size and counts
        // calls; it always succeeds (acts like a noop with telemetry).
        struct CountingPuncher(std::sync::atomic::AtomicU64, std::sync::atomic::AtomicU64);
        impl PunchHole for CountingPuncher {
            fn punch(
                &self,
                _fd: BorrowedFd<'_>,
                _offset: ByteOffset,
                length: u64,
            ) -> Result<(), PunchError> {
                self.0.fetch_add(1, Ordering::Relaxed);
                self.1.fetch_add(length, Ordering::Relaxed);
                Ok(())
            }
            fn block_size_hint(&self) -> u64 {
                4096
            }
        }
        let puncher = CountingPuncher(
            std::sync::atomic::AtomicU64::new(0),
            std::sync::atomic::AtomicU64::new(0),
        );

        let sink = VecSink {
            bytes: Vec::new(),
            fail_at: None,
            is_quiescent: true,
        };

        let cfg = ExtractorConfig {
            punch_threshold: 4096, // small enough to fire mid-loop
        };
        let stats = Extractor::new(cfg)
            .extract(punch_handle.as_fd(), &mut decoder, sink, &puncher)
            .expect("extract");

        let calls = puncher.0.load(Ordering::Relaxed);
        let bytes = puncher.1.load(Ordering::Relaxed);
        assert!(
            calls >= 1,
            "expected at least one in-loop punch, got {calls}"
        );
        assert!(bytes > 0);
        assert_eq!(stats.bytes_punched, bytes);
        assert_eq!(stats.punch_calls, calls);
        assert!(!stats.punch_unsupported);
    }

    /// First-call `Unsupported` puncher disables the rest of the
    /// pipeline silently and surfaces it via stats.
    #[test]
    fn unsupported_puncher_disables_punching_silently() {
        struct UnsupportedPuncher;
        impl PunchHole for UnsupportedPuncher {
            fn punch(
                &self,
                _fd: BorrowedFd<'_>,
                _offset: ByteOffset,
                _length: u64,
            ) -> Result<(), PunchError> {
                Err(PunchError::Unsupported { errno: 95 })
            }
            fn block_size_hint(&self) -> u64 {
                4096
            }
        }

        let frame_a = random_bytes(0xDEAD, 32 * 1024);
        let frame_b = random_bytes(0xBEEF, 32 * 1024);
        let (compressed, _) = encode_frames(&[&frame_a, &frame_b]);
        let len = compressed.len() as u64;

        let path = unique_temp("unsupported");
        let _g = CleanupOnDrop(path.clone());
        std::fs::write(&path, &compressed).expect("write source");
        let rw = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open rw");

        let mut decoder =
            ZstdDecoder::new(Box::new(std::fs::File::open(&path).expect("ro"))).expect("ctor");
        let sink = VecSink {
            bytes: Vec::new(),
            fail_at: None,
            is_quiescent: true,
        };

        let cfg = ExtractorConfig {
            punch_threshold: 4096,
        };
        let stats = Extractor::new(cfg)
            .extract(rw.as_fd(), &mut decoder, sink, &UnsupportedPuncher)
            .expect("extract");

        assert!(stats.punch_unsupported);
        assert_eq!(stats.bytes_punched, 0);
        assert_eq!(stats.punch_calls, 0);
        assert_eq!(stats.bytes_in, len);
    }

    /// Hard puncher errors propagate as [`ExtractorError::Punch`].
    #[test]
    fn hard_punch_error_propagates() {
        struct BrokenPuncher;
        impl PunchHole for BrokenPuncher {
            fn punch(
                &self,
                _fd: BorrowedFd<'_>,
                offset: ByteOffset,
                length: u64,
            ) -> Result<(), PunchError> {
                Err(PunchError::Io {
                    offset: offset.get(),
                    length,
                    source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "no"),
                })
            }
            fn block_size_hint(&self) -> u64 {
                4096
            }
        }

        let frame = random_bytes(0xCAFE, 32 * 1024);
        let (compressed, _) = encode_frames(&[&frame, &frame]);

        let path = unique_temp("broken");
        let _g = CleanupOnDrop(path.clone());
        std::fs::write(&path, &compressed).expect("write");
        let rw = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("rw");

        let mut decoder =
            ZstdDecoder::new(Box::new(std::fs::File::open(&path).expect("ro"))).expect("ctor");
        let sink = VecSink {
            bytes: Vec::new(),
            fail_at: None,
            is_quiescent: true,
        };

        let cfg = ExtractorConfig {
            punch_threshold: 4096,
        };
        let result = Extractor::new(cfg).extract(rw.as_fd(), &mut decoder, sink, &BrokenPuncher);
        match result {
            Err(ExtractorError::Punch { source, .. }) => {
                assert!(matches!(source, PunchError::Io { .. }));
            }
            other => panic!("expected ExtractorError::Punch, got {other:?}"),
        }
    }

    /// `RawSink` round-trip: extract a single-frame zstd into a file
    /// and compare contents byte-for-byte to the original payload.
    #[test]
    fn raw_sink_round_trip_via_file() {
        let payload = b"raw-sink-round-trip".repeat(16384);
        let (compressed, _) = encode_frames(&[&payload]);

        let src_path = unique_temp("rawsrc");
        let dst_path = unique_temp("rawdst");
        let _gs = CleanupOnDrop(src_path.clone());
        let _gd = CleanupOnDrop(dst_path.clone());
        std::fs::write(&src_path, &compressed).expect("write src");

        let rw = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&src_path)
            .expect("rw");
        let mut decoder =
            ZstdDecoder::new(Box::new(std::fs::File::open(&src_path).expect("ro"))).expect("ctor");
        let sink = RawSink::create(&dst_path).expect("dst");

        let stats = Extractor::with_defaults()
            .extract(rw.as_fd(), &mut decoder, sink, &NoopPuncher::new())
            .expect("extract");

        assert_eq!(stats.bytes_out, payload.len() as u64);
        let mut got = Vec::new();
        std::fs::File::open(&dst_path)
            .expect("reopen dst")
            .read_to_end(&mut got)
            .expect("read dst");
        assert_eq!(got, payload);
    }
}
