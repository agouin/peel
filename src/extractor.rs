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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::checkpoint::SinkState;
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

/// Default duration past which the §2.2 watchdog warns that a single
/// `decode_step` call took unusually long.
///
/// 30 s matches the renderer's stall threshold
/// ([`crate::progress::DEFAULT_STALL_WARN_INTERVAL`]) and the io_uring
/// backend's in-flight watchdog ([`crate::io_backend`] §2.1) so the
/// three signals compose: a freeze surfaces all of them inside the
/// same wall-clock window and the operator can correlate from log
/// alone. Override via `PEEL_DECODE_STEP_WARN_SECS`.
pub const DEFAULT_DECODE_STEP_WARN: Duration = Duration::from_secs(30);

/// Read `PEEL_DECODE_STEP_WARN_SECS` (positive integer seconds) and
/// fall back to [`DEFAULT_DECODE_STEP_WARN`]. `0` or any malformed
/// value uses the default.
fn decode_step_warn_from_env() -> Duration {
    std::env::var("PEEL_DECODE_STEP_WARN_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|n| *n > 0)
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_DECODE_STEP_WARN)
}

/// §2.2 (`PLAN_decoder_freeze.md`): post-hoc watchdog that fires a
/// single `tracing::warn!` line when one `decode_step` call exceeds
/// `threshold`.
///
/// Post-hoc because we run on the same thread as the call we are
/// timing — we cannot preempt it. The point is to localise the wedge
/// after the fact: if the watchdog fires on the freeze and the
/// io_uring §2.1 watchdog also fires, the wedge is inside a
/// kernel-level op the ring is waiting on. If §2.2 fires but §2.1
/// stays silent, the wedge is somewhere `decode_step` reaches that
/// is not the IO backend (sink-side `write_all`, a CPU spin, etc.).
///
/// Rate-limited via `last_warned_at`: a sustained slow window emits
/// one entry per `threshold`-sized interval, not one per loop tick.
struct DecodeStepWatchdog {
    threshold: Duration,
    last_warned_at: Option<Instant>,
}

impl DecodeStepWatchdog {
    fn from_env() -> Self {
        Self {
            threshold: decode_step_warn_from_env(),
            last_warned_at: None,
        }
    }

    /// `true` iff `elapsed` exceeds the threshold *and* the rate-limit
    /// window has elapsed since the last warning. Mutates
    /// `last_warned_at` to `Some(now)` on a positive return.
    fn should_warn(&mut self, elapsed: Duration, now: Instant) -> bool {
        if elapsed < self.threshold {
            return false;
        }
        if let Some(prev) = self.last_warned_at {
            if now.saturating_duration_since(prev) < self.threshold {
                return false;
            }
        }
        self.last_warned_at = Some(now);
        true
    }
}

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

    /// Minimum source-byte progress between successive
    /// [`Extractor::extract_with_callback`] observer invocations.
    ///
    /// The extractor measures progress against the most recently
    /// persisted boundary and gates the observer call when *both*
    /// this floor *and* [`Self::checkpoint_min_interval`] have not
    /// been cleared. Throttled steps skip both the
    /// [`StreamingDecoder::decoder_state`] call and the
    /// [`CheckpointInfo`] allocation, which is load-bearing for
    /// decoders whose `decoder_state()` serializes a non-trivial
    /// sliding window (xz_native: ~8 MiB per call).
    /// See `docs/PLAN_lazy_decoder_state.md`.
    ///
    /// `0` means "no byte-progress floor" — every quiescent advance
    /// fires the observer. This is the [`Self::default`] so that
    /// library callers using [`Extractor::extract`] /
    /// [`Extractor::with_defaults`] get the historical
    /// "observer-per-advance" behavior. Production callers (the
    /// [`crate::coordinator`]) explicitly set the
    /// [`crate::coordinator::CoordinatorConfig::checkpoint_min_bytes`]
    /// value here.
    ///
    /// The very first persist-eligible advance always fires
    /// regardless of these floors, so a clean cadence config
    /// doesn't strand a run with no checkpoints.
    pub checkpoint_min_bytes: u64,

    /// Minimum wall-clock time between successive observer
    /// invocations. Pairs with [`Self::checkpoint_min_bytes`] —
    /// throttle gates a call only when *both* the byte floor *and*
    /// the time floor have not been cleared.
    ///
    /// `Duration::ZERO` (the [`Self::default`]) means "no
    /// time-based floor". As with `checkpoint_min_bytes`, the very
    /// first persist-eligible advance always fires.
    pub checkpoint_min_interval: Duration,
}

impl Default for ExtractorConfig {
    fn default() -> Self {
        Self {
            punch_threshold: DEFAULT_PUNCH_THRESHOLD,
            checkpoint_min_bytes: 0,
            checkpoint_min_interval: Duration::ZERO,
        }
    }
}

// `CheckpointAck` was removed in `PLAN_lazy_decoder_state.md` Phase 1.
//
// The throttle that the coordinator's observer used to apply (returning
// `CheckpointAck::Throttled` to skip a write) now lives inside the
// extractor's run loop, gated by [`ExtractorConfig::checkpoint_min_bytes`]
// and [`ExtractorConfig::checkpoint_min_interval`]. The observer's only
// signal to the extractor is now its `io::Result<()>` return: `Ok` means
// "persisted; advance hole-punching up to this position", `Err` means
// "abort the extraction with this error".
//
// The punch-bounded-by-last-persisted invariant
// (`tests::throttled_observer_does_not_advance_punch_past_persisted_position`)
// continues to hold: the extractor's throttle skips the observer call and
// does *not* update `last_persisted_quiescent_at`, so a crash between a
// throttled step and the next durable write resumes from the most recent
// observer-acknowledged position.

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
    /// Live sink state captured at the same step. The coordinator
    /// persists this verbatim into the checkpoint; the sink's
    /// resume constructor consumes it to restart from the exact
    /// position the killed run left off.
    pub sink_state: SinkState,
}

/// Wall-clock and byte-volume statistics for one extraction.
///
/// The main extraction times overlap inside the decode loop only
/// inasmuch as [`Self::write_time`] is *subtracted out* of
/// [`Self::decode_time`] when the sink write happens inside
/// `decode_step`. `decode_time`, `write_time`, and `punch_time` are
/// therefore disjoint and can be summed for "useful time" without
/// double-counting. The `source_*` fields are lower-level diagnostics
/// from the coordinator's streaming reader and may overlap
/// `decode_time`.
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
    /// Bytes the streaming source read back from the sparse part
    /// file. Only coordinator-driven runs populate this; direct
    /// extractor use leaves it at zero.
    pub source_sparse_read_bytes: u64,
    /// Wall-clock time spent in sparse-file `read_at` calls on the
    /// streaming source path.
    pub source_sparse_read_time: Duration,
    /// Wall-clock time the streaming source spent waiting for the
    /// needed chunk bitmap bit to become complete.
    pub source_wait_time: Duration,
    /// Number of source-read calls that had to wait for at least one
    /// missing chunk.
    pub source_wait_count: u64,
    /// Number of poll sleeps taken by the streaming source while
    /// waiting for incomplete chunks.
    pub source_poll_sleeps: u64,
    /// Wall-clock time spent inside [`StreamingDecoder::decode_step`],
    /// minus the time the decoder spent calling the sink.
    pub decode_time: Duration,
    /// Wall-clock time spent inside [`Sink::write`], cumulated across
    /// every call the decoder made into the wrapping adapter.
    pub write_time: Duration,
    /// Wall-clock time spent inside [`PunchHole::punch`].
    pub punch_time: Duration,
    /// Wall-clock time spent in `SparseFile::sync_all` from the
    /// checkpoint observer (publication-side fsync of `.peel.part`).
    /// Populated only by coordinator-driven runs;
    /// [`Extractor::extract`] / [`Extractor::extract_with_callback`]
    /// leave this at zero. `PLAN_checkpoint_cadence_throughput.md`
    /// Phase 0.
    pub ckpt_sparse_sync_time: Duration,
    /// Number of `SparseFile::sync_all` calls the observer made.
    pub ckpt_sparse_sync_calls: u64,
    /// Wall-clock time spent constructing the [`crate::checkpoint::Checkpoint`]
    /// — bitmap clone, fingerprints clone, sink-state clone, hash-state
    /// snapshot, decoder-state clone, plus the binary serialize.
    /// Coordinator-only.
    pub ckpt_serialize_time: Duration,
    /// Wall-clock time from `OpenOptions::open(.tmp)` through the
    /// final `write_all` (no fsync). Coordinator-only.
    pub ckpt_tmp_write_time: Duration,
    /// Wall-clock time spent in `File::sync_all` on the `.tmp` file.
    /// Coordinator-only.
    pub ckpt_tmp_fsync_time: Duration,
    /// Wall-clock time spent in `fs::rename(.tmp, ckpt)`.
    /// Coordinator-only.
    pub ckpt_rename_time: Duration,
    /// Wall-clock time spent in `File::sync_all` on the parent
    /// directory. Coordinator-only.
    pub ckpt_dir_fsync_time: Duration,
    /// Number of parent-directory `sync_all` calls the observer
    /// made (one per checkpoint write on platforms that support it).
    pub ckpt_dir_fsync_calls: u64,
    /// Total wall-clock spent inside the checkpoint observer closure
    /// (sum of every observer invocation, success and error). Used
    /// to assert that the per-step counters above add up to the
    /// observed observer time within noise.
    pub ckpt_observer_time: Duration,
    /// Wall-clock time spent in [`StreamingDecoder::decoder_state`]
    /// during persist-eligible advances — i.e. the call that builds
    /// the resume blob immediately before the observer is invoked.
    /// For xz_native this serializes the LZMA dictionary; for other
    /// decoders it's a sliding-window snapshot. Lives outside both
    /// the timed phases and `ckpt_observer_time`, so without this
    /// counter the cost was unattributed in the diagnostic table.
    /// `PLAN_xz_bench_profile.md` Phase 1.
    pub ckpt_decoder_state_time: Duration,
    /// Number of [`StreamingDecoder::decoder_state`] calls. Equals
    /// `quiescent_checkpoints` exactly (one per persist-eligible
    /// advance). `PLAN_xz_bench_profile.md` Phase 1.
    pub ckpt_decoder_state_calls: u64,
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
#[derive(Clone)]
pub struct Extractor {
    config: ExtractorConfig,
    progress: Option<Arc<ProgressState>>,
    /// Optional run-wide kill switch, polled once per `decode_step`
    /// iteration of the inner loop. See [`Self::with_kill_switch`].
    kill_switch: Option<Arc<AtomicBool>>,
    /// Optional dynamic checkpoint byte-floor provider
    /// (`PLAN_checkpoint_cadence_throughput.md` Phase 2). When set,
    /// the cadence throttle calls this on each persist-eligible
    /// advance and uses the returned value as the byte floor instead
    /// of [`ExtractorConfig::checkpoint_min_bytes`]. The provider is
    /// expected to return *at least* the configured floor — the
    /// coordinator wires it up so the configured value is the lower
    /// bound and the rate-aware term is the upper bound.
    checkpoint_floor_provider: Option<Arc<dyn Fn() -> u64 + Send + Sync>>,
}

impl std::fmt::Debug for Extractor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Extractor")
            .field("config", &self.config)
            .field("progress", &self.progress.as_ref().map(|_| "ProgressState"))
            .field(
                "kill_switch",
                &self.kill_switch.as_ref().map(|_| "AtomicBool"),
            )
            .field(
                "checkpoint_floor_provider",
                &self
                    .checkpoint_floor_provider
                    .as_ref()
                    .map(|_| "FloorProvider"),
            )
            .finish()
    }
}

impl Extractor {
    /// Create an extractor with the given config.
    #[must_use]
    pub fn new(config: ExtractorConfig) -> Self {
        Self {
            config,
            progress: None,
            kill_switch: None,
            checkpoint_floor_provider: None,
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

    /// Attach the run-wide kill switch (`PLAN_responsiveness.md`
    /// §2.3). The inner loop polls the flag once per iteration —
    /// before each `decode_step` call — so a CPU-bound decoder that
    /// never reads source bytes (e.g., a zstd block whose literals
    /// fit entirely in the window) still notices a SIGTERM within one
    /// step. Tripping returns
    /// [`ExtractorError::Observer`] carrying the
    /// `peel:kill-switch-tripped` sentinel; the coordinator's
    /// `run_one` matcher recognizes it and surfaces
    /// `CoordinatorError::Aborted`.
    #[must_use]
    pub fn with_kill_switch(mut self, kill: Arc<AtomicBool>) -> Self {
        self.kill_switch = Some(kill);
        self
    }

    /// Attach a dynamic byte-floor provider for the checkpoint
    /// cadence throttle (`PLAN_checkpoint_cadence_throughput.md`
    /// Phase 2).
    ///
    /// On each persist-eligible advance the throttle calls
    /// `provider()` and uses the returned value as the byte floor
    /// instead of [`ExtractorConfig::checkpoint_min_bytes`]. The
    /// coordinator uses this to scale the floor with realized
    /// download throughput: at high rates the realized term raises
    /// the floor so cadence is paced by the OS's ability to durably
    /// publish, not by raw byte progress; at low rates the
    /// configured byte floor still wins.
    ///
    /// The contract: the provider returns *at least* the configured
    /// `checkpoint_min_bytes` value (the coordinator enforces this
    /// via `max(configured, rate * target_interval)`); the throttle
    /// does not double-check. The time floor
    /// ([`ExtractorConfig::checkpoint_min_interval`]) still bounds
    /// resume granularity from above regardless of the dynamic
    /// floor.
    #[must_use]
    pub fn with_checkpoint_floor_provider(
        mut self,
        provider: Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> Self {
        self.checkpoint_floor_provider = Some(provider);
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
    /// extractor advances its quiescent-checkpoint position *and* the
    /// configured cadence floors
    /// ([`ExtractorConfig::checkpoint_min_bytes`] /
    /// [`ExtractorConfig::checkpoint_min_interval`]) have been cleared.
    ///
    /// Throttled steps skip the observer call entirely — including the
    /// [`StreamingDecoder::decoder_state`] invocation that builds the
    /// resume blob. This is load-bearing for decoders whose
    /// `decoder_state()` is non-trivial (xz_native: ~8 MiB per call); see
    /// `docs/PLAN_lazy_decoder_state.md` for the diagnosis.
    ///
    /// On a successful observer return (`Ok(())`) the extractor advances
    /// hole-punching up to the now-persisted position. On `Err`, the
    /// extractor stops and surfaces [`ExtractorError::Observer`]; no
    /// further bytes are written and no further punches issued. The
    /// punch-bounded-by-last-persisted invariant is preserved:
    /// throttled steps do *not* update the persisted-position cursor,
    /// so a crash between a throttled step and the next observer call
    /// resumes from the most recent observer-acknowledged position.
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
        // Highest boundary the observer has reported as durably
        // persisted. Hole-punching is bounded by this — never by
        // `last_quiescent_at` — so a throttled (non-persisted)
        // observer call cannot orphan the bytes the still-current
        // durable checkpoint references. A crash between a
        // throttled write and the next persisted one resumes from
        // `last_persisted_quiescent_at` with all bytes from there
        // onward intact.
        let mut last_persisted_quiescent_at: u64 = 0;
        let mut last_observed_boundary: Option<u64> = None;
        let mut punch_disabled = false;
        // Throttle bookkeeping (Phase 1 of `PLAN_lazy_decoder_state.md`).
        // `None` until the first persist-eligible advance — the very
        // first call always fires regardless of the cadence floors so
        // a clean run produces at least one durable checkpoint even
        // when both floors are wide.
        let mut last_persist_time: Option<Instant> = None;

        let mut adapter = SinkAdapter {
            sink,
            bytes_out: 0,
            write_time: Duration::ZERO,
            captured: None,
            progress: self.progress.as_deref(),
        };

        // §2.2 (PLAN_decoder_freeze.md): post-hoc watchdog. Reads the
        // env once at loop entry; the threshold is fixed for the run.
        let mut step_watchdog = DecodeStepWatchdog::from_env();

        loop {
            // §2.3: poll the kill switch at the top of every loop
            // iteration — independent of the source-read poll, since a
            // CPU-bound decoder may not read source bytes between work
            // units. Tripping surfaces as `Observer` carrying the
            // shared `peel:kill-switch-tripped` sentinel so the
            // coordinator's `run_one` matcher maps it to `Aborted`.
            if let Some(flag) = self.kill_switch.as_ref() {
                if flag.load(Ordering::Acquire) {
                    return Err(ExtractorError::Observer(std::io::Error::other(
                        "peel:kill-switch-tripped",
                    )));
                }
            }
            // Time the decode_step call as a whole, then subtract out
            // any time the inner sink.write spent — that becomes
            // stats.write_time, and the rest is decode-only time.
            let pre_write = adapter.write_time;
            let t_decode = Instant::now();
            // §1.3: span carries the decoder's source cursor so a wedge
            // here (e.g., a decoder spinning without producing) is
            // visible under `RUST_LOG=peel=debug`.
            let bytes_consumed = decoder.bytes_consumed().get();
            // §2.2: capture the sink's bytes_out before the call so the
            // watchdog can report whether the slow step *produced*
            // output or merely *read* source. The two deltas, taken
            // together with `write_delta`, distinguish a
            // sink-blocked step from a source-blocked step.
            let bytes_out_before = adapter.bytes_out;
            // §2.4b: publish the entry timestamp so the renderer-side
            // peer watchdog ([`crate::progress::DecodeStepStallDetector`])
            // can fire even when this thread is parked inside a
            // blocking syscall — the §2.2 post-hoc check below cannot
            // run while the call is still in flight. The
            // `mark_decode_step_exited` pair-call sits right after the
            // return below; on a panic from the decoder, the renderer
            // would briefly continue to see a non-zero `started_ns`,
            // but the surrounding `extract_with_callback` unwinds and
            // tears down the extractor before the next renderer tick.
            if let Some(p) = self.progress.as_deref() {
                p.mark_decode_step_entered();
            }
            let step = {
                let span = tracing::debug_span!(
                    target: "peel::extractor",
                    "decode_step",
                    bytes_consumed,
                    bytes_out = adapter.bytes_out,
                );
                let _enter = span.enter();
                decoder.decode_step(&mut adapter)
            };
            if let Some(p) = self.progress.as_deref() {
                p.mark_decode_step_exited();
            }
            let total = t_decode.elapsed();
            let write_delta = adapter.write_time.saturating_sub(pre_write);
            stats.decode_time = stats
                .decode_time
                .saturating_add(total.saturating_sub(write_delta));
            stats.write_time = stats.write_time.saturating_add(write_delta);

            // §2.2 watchdog firing site. Runs *after* the call returns
            // (post-hoc — we cannot preempt a step we are running on
            // the same thread as). On a true wedge the call never
            // returns; on a slow-but-finite call the warning surfaces
            // exactly which step took the time and what it produced.
            if step_watchdog.should_warn(total, Instant::now()) {
                let after_consumed = decoder.bytes_consumed().get();
                let consumed_delta = after_consumed.saturating_sub(bytes_consumed);
                let bytes_out_delta = adapter.bytes_out.saturating_sub(bytes_out_before);
                tracing::warn!(
                    target: "peel::extractor",
                    elapsed_secs = total.as_secs(),
                    write_time_secs = write_delta.as_secs(),
                    bytes_consumed = after_consumed,
                    consumed_delta,
                    bytes_out = adapter.bytes_out,
                    bytes_out_delta,
                    "decode_step took {}s (consumed +{} src bytes, wrote +{} out bytes, sink time {}s)",
                    total.as_secs(),
                    consumed_delta,
                    bytes_out_delta,
                    write_delta.as_secs(),
                );
            }

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
                        // Throttle gate (Phase 1 of
                        // `PLAN_lazy_decoder_state.md`). The gate
                        // sits *before* both `decoder.decoder_state()`
                        // and the `CheckpointInfo` allocation so a
                        // throttled step pays neither cost. The very
                        // first persist-eligible advance bypasses the
                        // gate (`last_persist_time == None`); after
                        // that, a step is throttled iff *both* the
                        // byte floor and the time floor are
                        // un-cleared.
                        let throttled = if let Some(prev) = last_persist_time {
                            let bytes_progressed = b.saturating_sub(last_persisted_quiescent_at);
                            let time_progressed = prev.elapsed();
                            // Phase 2: sample the dynamic floor when
                            // a provider is attached; otherwise use
                            // the static configured floor. The
                            // provider's contract is to return at
                            // least the configured floor, so the
                            // throttle never relaxes below the
                            // user-set lower bound.
                            let bytes_floor = self
                                .checkpoint_floor_provider
                                .as_ref()
                                .map_or(self.config.checkpoint_min_bytes, |p| p());
                            bytes_progressed < bytes_floor
                                && time_progressed < self.config.checkpoint_min_interval
                        } else {
                            false
                        };
                        if !throttled {
                            stats.quiescent_checkpoints =
                                stats.quiescent_checkpoints.saturating_add(1);
                            // Time `decoder_state()` separately
                            // (`PLAN_xz_bench_profile.md` Phase 1).
                            // For xz_native this builds an 8 MiB LZMA
                            // dict snapshot and lives outside both
                            // the timed phases and the observer
                            // closure; without this counter the cost
                            // showed up as unattributed "overlap".
                            let ds_start = Instant::now();
                            let decoder_state = decoder.decoder_state();
                            stats.ckpt_decoder_state_time = stats
                                .ckpt_decoder_state_time
                                .saturating_add(ds_start.elapsed());
                            stats.ckpt_decoder_state_calls =
                                stats.ckpt_decoder_state_calls.saturating_add(1);
                            let info = CheckpointInfo {
                                source_position: b,
                                bytes_in: stats.bytes_in,
                                bytes_out: adapter.bytes_out,
                                quiescent_index: stats.quiescent_checkpoints,
                                decoder_state,
                                sink_state: adapter.sink.sink_state(),
                            };
                            on_checkpoint(info).map_err(ExtractorError::Observer)?;
                            last_persist_time = Some(Instant::now());
                            last_persisted_quiescent_at = b;
                        }
                    }
                }
            }

            // Punch behind the last *persisted* boundary, aligned to
            // filesystem blocks. Bounding by the persisted (rather
            // than the latest-observed) position is what guarantees
            // that a crash before the next persisted write resumes
            // cleanly: the durable checkpoint's `decoder_position`
            // always points at bytes the punch has not touched.
            if !punch_disabled {
                self.maybe_punch(
                    source_fd,
                    puncher,
                    block,
                    last_persisted_quiescent_at,
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

        // Final sweep: release every block up to the last persisted
        // checkpoint, ignoring the punch_threshold so even a small
        // tail gets freed. The successful EOF path means the
        // extraction is complete and no resume will be attempted, so
        // bounding by `last_persisted_quiescent_at` here is purely
        // defensive — but it preserves the `maybe_punch` contract
        // ("never punch past a position the observer hasn't
        // acknowledged as durable") in one place.
        if !punch_disabled {
            self.maybe_punch(
                source_fd,
                puncher,
                block,
                last_persisted_quiescent_at,
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

        // §1.3: span around the punch syscall — slow filesystems
        // (network mounts, congested NVMe) sometimes show up here.
        let span = tracing::debug_span!(
            target: "peel::punch",
            "maybe_punch",
            offset = *last_punched,
            length = gap,
            final_sweep,
        );
        let _enter = span.enter();
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
        // §1.3: span around the sink write — when extract progress is
        // flat, this span (vs the surrounding decode_step span) shows
        // whether the wedge is in the decoder or the sink.
        let span = tracing::debug_span!(
            target: "peel::sink",
            "sink_write",
            buf_len = buf.len(),
            bytes_out = self.bytes_out,
        );
        let _enter = span.enter();
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
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

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
        fn sink_state(&self) -> crate::checkpoint::SinkState {
            crate::checkpoint::SinkState::Raw {
                bytes_written: self.bytes.len() as u64,
            }
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
        fn sink_state(&self) -> crate::checkpoint::SinkState {
            crate::checkpoint::SinkState::Raw {
                bytes_written: self.bytes.len() as u64,
            }
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

    /// §2.3: a decoder that returns `MoreData` indefinitely without
    /// reading source must still observe the kill switch within a
    /// bounded number of iterations, so a SIGTERM during such a spin
    /// is not a hang.
    #[test]
    fn kill_switch_aborts_cpu_bound_decoder_within_one_iteration() {
        use crate::types::ByteOffset;

        struct SpinningDecoder {
            iterations: std::sync::atomic::AtomicU64,
        }
        impl StreamingDecoder for SpinningDecoder {
            fn decode_step(&mut self, _sink: &mut dyn Write) -> Result<DecodeStatus, DecodeError> {
                self.iterations.fetch_add(1, Ordering::Relaxed);
                Ok(DecodeStatus::MoreData)
            }
            fn bytes_consumed(&self) -> ByteOffset {
                ByteOffset::ZERO
            }
            fn frame_boundary(&self) -> Option<ByteOffset> {
                None
            }
        }

        let kill = Arc::new(AtomicBool::new(false));
        // Pre-trip the kill switch so the very next loop iteration
        // observes it. With the §2.3 poll, the test returns within
        // one decode_step. Without the poll, the spinning decoder
        // would loop forever and the test would time out below.
        kill.store(true, Ordering::Release);

        let mut decoder = SpinningDecoder {
            iterations: std::sync::atomic::AtomicU64::new(0),
        };
        let sink = VecSink {
            bytes: Vec::new(),
            fail_at: None,
            is_quiescent: true,
        };
        let extractor = Extractor::with_defaults().with_kill_switch(Arc::clone(&kill));

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // stdout fd is fine — the NoopPuncher never touches it.
            let result = extractor.extract(
                std::io::stdout().as_fd(),
                &mut decoder,
                sink,
                &NoopPuncher::new(),
            );
            let _ = tx.send((result, decoder.iterations.load(Ordering::Relaxed)));
        });

        let (result, iters) = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("kill switch should abort the spin within 2s");
        match result {
            Err(ExtractorError::Observer(e)) => {
                assert_eq!(e.to_string(), "peel:kill-switch-tripped");
            }
            other => panic!("expected Observer(KILL_SENTINEL), got {other:?}"),
        }
        // The pre-tripped switch lands on the first iteration, before
        // any decode_step runs. Allow a tiny upper bound to avoid
        // false positives if the loop layout changes.
        assert!(
            iters <= 1,
            "expected ≤1 decode_step call before abort, got {iters}",
        );
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
            ..ExtractorConfig::default()
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
            ..ExtractorConfig::default()
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
            ..ExtractorConfig::default()
        };
        let result = Extractor::new(cfg).extract(rw.as_fd(), &mut decoder, sink, &BrokenPuncher);
        match result {
            Err(ExtractorError::Punch { source, .. }) => {
                assert!(matches!(source, PunchError::Io { .. }));
            }
            other => panic!("expected ExtractorError::Punch, got {other:?}"),
        }
    }

    /// Mock [`StreamingDecoder`] that emits a fixed-size payload of
    /// `0xCD` bytes per `decode_step`, surfaces a fresh frame
    /// boundary at each emission, and counts `decoder_state()`
    /// invocations into a shared `Arc<AtomicU32>` so tests can
    /// assert the extractor's throttle gate sits *before* blob
    /// construction (Phase 1 of `PLAN_lazy_decoder_state.md`).
    ///
    /// `decoder_state()` returns a small distinguishable blob so
    /// observer-side assertions can verify that the extractor
    /// *forwards* the captured state when it does fire — i.e. the
    /// laziness applies only to throttled steps, not to the persist
    /// path.
    struct CountingDecoder {
        frame_size: u64,
        remaining_frames: u32,
        bytes_consumed: u64,
        last_boundary: Option<u64>,
        decoder_state_calls: Arc<AtomicU32>,
    }

    impl StreamingDecoder for CountingDecoder {
        fn decode_step(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, DecodeError> {
            if self.remaining_frames == 0 {
                return Ok(DecodeStatus::Eof);
            }
            // Stream one "frame" worth of bytes per call. The
            // payload byte (0xCD) is arbitrary — we never inspect it.
            let payload = vec![0xCDu8; self.frame_size as usize];
            sink.write_all(&payload).map_err(DecodeError::Write)?;
            self.bytes_consumed = self.bytes_consumed.saturating_add(self.frame_size);
            self.last_boundary = Some(self.bytes_consumed);
            self.remaining_frames -= 1;
            Ok(DecodeStatus::MoreData)
        }
        fn bytes_consumed(&self) -> ByteOffset {
            ByteOffset::new(self.bytes_consumed)
        }
        fn frame_boundary(&self) -> Option<ByteOffset> {
            self.last_boundary.map(ByteOffset::new)
        }
        fn decoder_state(&self) -> Option<Vec<u8>> {
            self.decoder_state_calls.fetch_add(1, Ordering::Relaxed);
            // Sentinel byte pattern — distinct enough to be
            // recognisable in observer-side asserts.
            Some(vec![0xABu8; 64])
        }
    }

    /// File-backed punch handle for the mock-decoder tests. The
    /// extractor needs a writable fd for hole-punch syscalls; we
    /// open a small zero-padded scratch file (sized at
    /// `frame_size * frames`) so any in-loop punches hit a real
    /// page rather than failing.
    fn open_scratch_punch_handle(byte_len: u64) -> (PathBuf, std::fs::File) {
        let path = unique_temp("counting-decoder");
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .expect("open scratch");
        f.set_len(byte_len).expect("set_len");
        (path, f)
    }

    /// With the default [`ExtractorConfig`] (no throttle), every
    /// quiescent boundary fires the observer and triggers a
    /// `decoder_state()` call. Establishes the baseline against
    /// which the next test's throttle skip is measured.
    #[test]
    fn no_throttle_calls_decoder_state_on_every_quiescent_advance() {
        const FRAMES: u32 = 4;
        const FRAME_SIZE: u64 = 1024;

        let calls = Arc::new(AtomicU32::new(0));
        let mut decoder = CountingDecoder {
            frame_size: FRAME_SIZE,
            remaining_frames: FRAMES,
            bytes_consumed: 0,
            last_boundary: None,
            decoder_state_calls: Arc::clone(&calls),
        };
        let sink = VecSink {
            bytes: Vec::new(),
            fail_at: None,
            is_quiescent: true,
        };
        let (path, scratch) = open_scratch_punch_handle(FRAME_SIZE * u64::from(FRAMES));
        let _g = CleanupOnDrop(path);

        let observer_calls = std::cell::Cell::new(0u32);
        let observer_saw_blob = std::cell::Cell::new(0u32);

        // Default config: punch enabled, no checkpoint throttle.
        let stats = Extractor::with_defaults()
            .extract_with_callback(
                scratch.as_fd(),
                &mut decoder,
                sink,
                &NoopPuncher::new(),
                |info| {
                    observer_calls.set(observer_calls.get() + 1);
                    if info.decoder_state.is_some() {
                        observer_saw_blob.set(observer_saw_blob.get() + 1);
                    }
                    Ok(())
                },
            )
            .expect("extract");

        // Each frame produces one quiescent advance → one observer
        // call → one `decoder_state()` invocation.
        assert_eq!(observer_calls.get(), FRAMES);
        assert_eq!(observer_saw_blob.get(), FRAMES);
        assert_eq!(calls.load(Ordering::Relaxed), FRAMES);
        // `quiescent_checkpoints` counts only persist-eligible
        // advances now, but with no throttle every advance is
        // persist-eligible.
        assert_eq!(stats.quiescent_checkpoints, u64::from(FRAMES));
        assert_eq!(stats.frame_boundaries_observed, u64::from(FRAMES));
    }

    /// With `checkpoint_min_bytes = u64::MAX` and a long
    /// `checkpoint_min_interval`, only the very first
    /// persist-eligible advance fires (`last_persist_time = None`
    /// bypass). All subsequent quiescent advances are throttled
    /// inside the extractor — proving that
    /// `decoder.decoder_state()` is gated by the throttle, not
    /// invoked unconditionally.
    ///
    /// This is the load-bearing assertion for `PLAN_lazy_decoder_state.md`
    /// Phase 1: an xz_native pipeline run that throttles 99 % of
    /// its quiescent advances now pays the (~8 MiB) blob cost only
    /// on the 1 % that persist.
    #[test]
    fn throttle_gates_decoder_state_invocation() {
        const FRAMES: u32 = 4;
        const FRAME_SIZE: u64 = 1024;

        let calls = Arc::new(AtomicU32::new(0));
        let mut decoder = CountingDecoder {
            frame_size: FRAME_SIZE,
            remaining_frames: FRAMES,
            bytes_consumed: 0,
            last_boundary: None,
            decoder_state_calls: Arc::clone(&calls),
        };
        let sink = VecSink {
            bytes: Vec::new(),
            fail_at: None,
            is_quiescent: true,
        };
        let (path, scratch) = open_scratch_punch_handle(FRAME_SIZE * u64::from(FRAMES));
        let _g = CleanupOnDrop(path);

        let observer_calls = std::cell::Cell::new(0u32);

        let cfg = ExtractorConfig {
            // Floors set so wide that only the first-call bypass
            // can let the observer fire. Subsequent advances are
            // gated by both floors simultaneously and skip the
            // observer + the `decoder_state()` invocation.
            checkpoint_min_bytes: u64::MAX,
            checkpoint_min_interval: Duration::from_secs(60 * 60),
            ..ExtractorConfig::default()
        };
        let stats = Extractor::new(cfg)
            .extract_with_callback(
                scratch.as_fd(),
                &mut decoder,
                sink,
                &NoopPuncher::new(),
                |_info| {
                    observer_calls.set(observer_calls.get() + 1);
                    Ok(())
                },
            )
            .expect("extract");

        assert_eq!(
            observer_calls.get(),
            1,
            "expected exactly the first-call bypass to fire; got {}",
            observer_calls.get(),
        );
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "decoder_state() must be called only on persist-eligible advances; \
             got {} (a regression in the throttle gate would surface here)",
            calls.load(Ordering::Relaxed),
        );
        // Three of the four quiescent advances were throttled
        // inside the extractor; only the first one increments the
        // counter.
        assert_eq!(stats.quiescent_checkpoints, 1);
        // Frame boundaries are still observed even when throttled.
        assert_eq!(stats.frame_boundaries_observed, u64::from(FRAMES));
    }

    /// Regression test for the throttle/punch race that originally
    /// broke mid-frame lz4 resume: when the cadence-throttle skips
    /// observer calls, the extractor must NOT advance hole-punching
    /// past the boundary the previous *persisted* observer call
    /// recorded. If it does, a crash before the next persisted write
    /// leaves the durable checkpoint pointing at zeroed bytes and
    /// resume cannot continue.
    ///
    /// Phase 1 of `PLAN_lazy_decoder_state.md` moved the throttle
    /// from the observer into the extractor; this test exercises
    /// the same invariant under the new shape. We configure
    /// `checkpoint_min_bytes = u64::MAX` and a long
    /// `checkpoint_min_interval` so only the very first
    /// persist-eligible advance fires (`last_persist_time = None`
    /// bypass), and every subsequent quiescent advance is throttled
    /// inside the extractor — exactly the scenario the prior
    /// `CheckpointAck::Throttled`-driven version simulated.
    #[test]
    fn throttled_observer_does_not_advance_punch_past_persisted_position() {
        // Three frames so we get at least three quiescent boundaries
        // through the loop (post-frame-A, post-frame-B, post-frame-C).
        // Random-ish payloads keep them incompressible enough that
        // each compressed frame straddles multiple block alignments.
        let frame_a = random_bytes(0xA1, 16 * 1024);
        let frame_b = random_bytes(0xB2, 16 * 1024);
        let frame_c = random_bytes(0xC3, 16 * 1024);
        let (compressed, _ends) = encode_frames(&[&frame_a, &frame_b, &frame_c]);

        let path = unique_temp("throttle-punch");
        let _g = CleanupOnDrop(path.clone());
        std::fs::write(&path, &compressed).expect("write source");
        let punch_handle = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open rw");
        let mut decoder =
            ZstdDecoder::new(Box::new(std::fs::File::open(&path).expect("ro"))).expect("ctor");

        // Records the offset/length of every `punch` call so the
        // assertion can check none reached past the most recently
        // persisted position.
        struct RecordingPuncher {
            calls: std::sync::Mutex<Vec<(u64, u64)>>,
        }
        impl PunchHole for RecordingPuncher {
            fn punch(
                &self,
                _fd: BorrowedFd<'_>,
                offset: ByteOffset,
                length: u64,
            ) -> Result<(), PunchError> {
                self.calls.lock().unwrap().push((offset.get(), length));
                Ok(())
            }
            fn block_size_hint(&self) -> u64 {
                4096
            }
        }
        let puncher = RecordingPuncher {
            calls: std::sync::Mutex::new(Vec::new()),
        };

        let sink = VecSink {
            bytes: Vec::new(),
            fail_at: None,
            is_quiescent: true,
        };

        // Records the source_position the (one and only) observer
        // call sees — that's the boundary durable on disk after the
        // throttle starts firing. The assertion below cross-checks
        // that no in-loop punch reached past it.
        let persisted = std::cell::Cell::new(None::<u64>);
        let observer_calls = std::cell::Cell::new(0u32);

        let cfg = ExtractorConfig {
            // Small enough to fire mid-loop. Without the
            // throttle-respects-persisted-bound invariant, throttled
            // steps would still advance the punch past the first
            // persisted boundary.
            punch_threshold: 4096,
            // Both floors set so wide that only the
            // `last_persist_time = None` bypass on the very first
            // advance lets the observer fire once. Every advance
            // after that is throttled inside the extractor.
            checkpoint_min_bytes: u64::MAX,
            checkpoint_min_interval: Duration::from_secs(60 * 60),
        };
        let stats = Extractor::new(cfg)
            .extract_with_callback(punch_handle.as_fd(), &mut decoder, sink, &puncher, |info| {
                observer_calls.set(observer_calls.get() + 1);
                persisted.set(Some(info.source_position));
                Ok(())
            })
            .expect("extract");

        assert_eq!(
            observer_calls.get(),
            1,
            "extractor-side throttle should let exactly the first persist-eligible \
             advance fire; got {} calls",
            observer_calls.get(),
        );
        let durable = persisted.get().expect("at least one persisted call");
        let calls = puncher.calls.lock().unwrap().clone();
        assert!(
            !calls.is_empty(),
            "expected at least one in-loop punch with the small threshold",
        );
        for (offset, length) in &calls {
            let end = offset.saturating_add(*length);
            assert!(
                end <= durable,
                "punch [{offset}, {end}) reached past last-persisted position {durable}; \
                 a crash here would leave the durable checkpoint pointing at zeroed bytes",
            );
        }
        // Sanity: the run still completed and produced the right output.
        assert_eq!(
            stats.bytes_out,
            (frame_a.len() + frame_b.len() + frame_c.len()) as u64,
        );
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

    // ---- §2.2 DecodeStepWatchdog --------------------------------------

    /// Healthy steps (under threshold) never trip the watchdog,
    /// regardless of how many we feed it.
    #[test]
    fn decode_step_watchdog_silent_under_threshold() {
        let mut wd = DecodeStepWatchdog {
            threshold: Duration::from_secs(30),
            last_warned_at: None,
        };
        let now = Instant::now();
        for i in 0..10 {
            let elapsed = Duration::from_millis(50);
            assert!(
                !wd.should_warn(elapsed, now + Duration::from_millis(i)),
                "tick {i}: healthy step should not warn"
            );
        }
        assert!(wd.last_warned_at.is_none());
    }

    /// One slow step crosses the threshold; the watchdog fires once
    /// and stamps `last_warned_at`.
    #[test]
    fn decode_step_watchdog_warns_when_threshold_exceeded() {
        let mut wd = DecodeStepWatchdog {
            threshold: Duration::from_secs(30),
            last_warned_at: None,
        };
        let now = Instant::now();
        assert!(wd.should_warn(Duration::from_secs(45), now));
        assert!(wd.last_warned_at.is_some());
    }

    /// Two consecutive slow steps inside the same warn window only
    /// fire once — the rate-limit prevents log spam from a steadily
    /// slow phase.
    #[test]
    fn decode_step_watchdog_rate_limits_within_window() {
        let mut wd = DecodeStepWatchdog {
            threshold: Duration::from_secs(30),
            last_warned_at: None,
        };
        let t0 = Instant::now();
        assert!(wd.should_warn(Duration::from_secs(45), t0));
        // 5 s later, still slow → silent.
        assert!(!wd.should_warn(Duration::from_secs(45), t0 + Duration::from_secs(5)));
        // 35 s later, the rate-limit window has elapsed → fires again.
        assert!(wd.should_warn(Duration::from_secs(45), t0 + Duration::from_secs(35)));
    }

    /// `PEEL_DECODE_STEP_WARN_SECS` overrides the default; an invalid
    /// or zero value falls back. Mirrors the env-override pattern in
    /// `progress::StallDetector::from_env` and the §2.1 watchdog.
    #[test]
    fn decode_step_warn_env_override() {
        let prev = std::env::var("PEEL_DECODE_STEP_WARN_SECS").ok();
        std::env::set_var("PEEL_DECODE_STEP_WARN_SECS", "5");
        assert_eq!(decode_step_warn_from_env(), Duration::from_secs(5));
        std::env::set_var("PEEL_DECODE_STEP_WARN_SECS", "0");
        assert_eq!(decode_step_warn_from_env(), DEFAULT_DECODE_STEP_WARN);
        std::env::set_var("PEEL_DECODE_STEP_WARN_SECS", "garbage");
        assert_eq!(decode_step_warn_from_env(), DEFAULT_DECODE_STEP_WARN);
        std::env::remove_var("PEEL_DECODE_STEP_WARN_SECS");
        assert_eq!(decode_step_warn_from_env(), DEFAULT_DECODE_STEP_WARN);
        match prev {
            Some(v) => std::env::set_var("PEEL_DECODE_STEP_WARN_SECS", v),
            None => std::env::remove_var("PEEL_DECODE_STEP_WARN_SECS"),
        }
    }

    /// Once a slow step has fired, recovery (a series of fast steps)
    /// must clear the rate-limit watermark only by aging out — the
    /// watchdog does not auto-arm. This matches the StallDetector's
    /// behaviour under transient slowness.
    #[test]
    fn decode_step_watchdog_does_not_double_fire_immediately_after_recovery() {
        let mut wd = DecodeStepWatchdog {
            threshold: Duration::from_secs(30),
            last_warned_at: None,
        };
        let t0 = Instant::now();
        assert!(wd.should_warn(Duration::from_secs(60), t0));
        // Healthy step 5 s later — silent (under threshold).
        assert!(!wd.should_warn(Duration::from_millis(10), t0 + Duration::from_secs(5)));
        // Another slow step 10 s after the original — still inside the
        // rate-limit window, still silent.
        assert!(!wd.should_warn(Duration::from_secs(60), t0 + Duration::from_secs(10)));
    }
}
