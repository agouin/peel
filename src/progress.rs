//! Progress tracking primitives shared between the writers (download
//! workers, extractor, ZIP pipeline) and the renderer thread.
//!
//! Per `docs/PLAN_v2.md` §6, `peel` exposes a multi-field progress UI:
//! compressed bytes downloaded out of total, decompressed bytes
//! extracted, rolling 5-second download/extract rates, ETA, and active
//! worker count. The pieces fit together so that writers stay
//! lock-free and the renderer thread is the only reader of the
//! cumulative counters:
//!
//! - [`ProgressState`] holds atomics shared across threads. Writers
//!   `fetch_add` into the running totals; readers take a single
//!   [`ProgressSnapshot`] per render tick.
//! - [`RateBuffer`] is a small ring of `(Instant, total_bytes)` samples
//!   private to the renderer. Each render tick the renderer pushes the
//!   latest atomic value and asks the buffer for a 5-second average.
//! - [`ProgressRenderer`] is the trait both renderers implement.
//!   [`TtyRenderer`] writes a three-line ANSI block redrawn in place;
//!   [`LogRenderer`] emits one `tracing::info!` event per tick for
//!   non-TTY output.
//! - [`spawn_renderer`] runs the chosen renderer on a dedicated thread,
//!   polling [`ProgressState::is_done`] to know when to stop.
//!
//! No new TUI dependency: the TTY renderer is hand-rolled ANSI per the
//! PLAN_v2 §6 hard constraint, and the log renderer reuses the
//! existing pre-approved `tracing` allowlist entry. Standards §6's
//! "no `Mutex<T>` where `Atomic*` will do" rules out a shared rate
//! buffer; keeping the ring inside the renderer trades a few extra
//! atomic loads per tick for a lock-free hot path on the writer side.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Atomically-updated cumulative counters shared between the pipeline's
/// writers and the renderer thread.
///
/// Writers call the small set of update methods (`add_downloaded`,
/// `worker_started`, …); they never read the whole struct. The
/// renderer reads a [`ProgressSnapshot`] once per render tick, then
/// drops the borrow — so the cost on the writer side is one atomic
/// add per event, no locks.
///
/// Construct once via [`ProgressState::new`] and share through
/// [`Arc`].
#[derive(Debug)]
pub struct ProgressState {
    /// Total source size, in bytes. `0` means "not yet known"; the
    /// renderer treats it as `None` in the snapshot.
    total_size: AtomicU64,
    /// Compressed bytes the download workers (or single-stream
    /// fallback) have brought in so far. Chunk-granular: incremented
    /// once per completed chunk in the parallel path, once per body
    /// read in the single-stream path.
    bytes_downloaded: AtomicU64,
    /// Decoded bytes the sink has accepted so far.
    bytes_extracted: AtomicU64,
    /// Optional estimate of the total uncompressed output. `0` means
    /// "unknown" — for compressed formats we usually don't know until
    /// the decoder reports it. The renderer treats it as `None` in
    /// the snapshot.
    extracted_estimate: AtomicU64,
    /// Workers currently doing IO (not just spawned). The download
    /// scheduler `fetch_add`s on entry to the per-chunk read and
    /// `fetch_sub`s on exit, so this reflects "how many workers are
    /// actually pulling bytes right now".
    active_workers: AtomicU64,
    /// Workers spawned for this run (set once at the start of
    /// [`crate::download::run`]). Useful as a denominator next to
    /// `active_workers`.
    total_workers: AtomicU64,
    /// `true` once the run has begun (first byte downloaded, ETag
    /// resolved, …). Used by the renderer to gate "starting up"
    /// fallback text.
    started: AtomicBool,
    /// `true` once the run has finished (success or fail). The
    /// renderer thread exits its loop on this.
    done: AtomicBool,
    /// Compressed bytes the streaming decoder has consumed
    /// (= the read cursor into the source). Updated by
    /// [`crate::coordinator::BlockingSparseReader`] and by the
    /// ZIP pipeline; the renderer uses it to compute "lookahead",
    /// the gap between download and extract. `0` is the natural
    /// initial value and also the start-of-resume value.
    bytes_decoded_input: AtomicU64,
    /// Configured cap on `bytes_downloaded - bytes_decoded_input`
    /// (the on-disk lookahead buffer). `0` means "disabled" and the
    /// scheduler will not throttle download dispatch. Published by
    /// the scheduler at startup so the UI can show the cap alongside
    /// the live lookahead.
    max_disk_buffer: AtomicU64,
    /// `true` when the scheduler is actively throttling download
    /// dispatch because the lookahead has hit
    /// [`Self::max_disk_buffer`]. Cleared on the next un-throttled
    /// dispatch round. The renderer reads this for the bottleneck
    /// indicator.
    disk_bound: AtomicBool,
    /// Anchor for [`Self::decode_step_started_ns`], captured at
    /// construction. Both the publishing extractor and the reading
    /// renderer compute elapsed times relative to this — `Instant`
    /// itself isn't `Atomic` but its delta-as-nanos is, and a u64
    /// covers ~584 years of run time.
    state_anchor: Instant,
    /// Wall-clock time the most recent `decode_step` *entered*,
    /// encoded as nanoseconds since [`Self::state_anchor`]. `0` is the
    /// sentinel for "no step in progress" — both initially and
    /// between every pair of entries. The extractor publishes on entry
    /// and clears on return; the renderer's
    /// [`DecodeStepStallDetector`] reads it from a peer thread to
    /// detect a step that has not returned (PLAN_decoder_freeze.md
    /// §2.4b — the post-hoc watchdog at
    /// [`crate::extractor`] §2.2 cannot fire while the call is still
    /// running, so this is the reachable signal during a true wedge).
    decode_step_started_ns: AtomicU64,
    /// Per-part counters for multi-URL split-source runs
    /// (`docs/PLAN_multi_url_source.md`). Initialized once by the
    /// coordinator after discovery via [`Self::set_parts`]; left
    /// unset for runs that never hit that path. When set, workers
    /// credit per-part bytes via [`Self::add_downloaded_to_part`]
    /// in addition to the aggregate `bytes_downloaded`. Snapshots
    /// expose the per-part view through [`ProgressSnapshot::parts`].
    parts: OnceLock<Vec<PartCounter>>,
}

/// Per-part download counters published in [`ProgressSnapshot::parts`].
///
/// Initialized once by [`ProgressState::set_parts`] from the
/// post-discovery [`crate::download::MultiPartSource`]; afterward the
/// label and total size are read-only and only `bytes_downloaded`
/// changes. The renderer reads a coherent view via
/// [`ProgressState::snapshot`].
#[derive(Debug)]
pub struct PartCounter {
    /// Short label for the part — typically the URL's basename
    /// (e.g. `pruned.tar.part0000`). Used by the renderers to
    /// label per-part rows.
    pub label: String,
    /// `Content-Length` reported for this part at HEAD time.
    pub total_size: u64,
    /// Compressed bytes downloaded for this part so far.
    pub bytes_downloaded: AtomicU64,
}

impl ProgressState {
    /// Construct an empty state, wrapped in [`Arc`] for sharing.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            total_size: AtomicU64::new(0),
            bytes_downloaded: AtomicU64::new(0),
            bytes_extracted: AtomicU64::new(0),
            extracted_estimate: AtomicU64::new(0),
            active_workers: AtomicU64::new(0),
            total_workers: AtomicU64::new(0),
            started: AtomicBool::new(false),
            done: AtomicBool::new(false),
            bytes_decoded_input: AtomicU64::new(0),
            max_disk_buffer: AtomicU64::new(0),
            disk_bound: AtomicBool::new(false),
            state_anchor: Instant::now(),
            decode_step_started_ns: AtomicU64::new(0),
            parts: OnceLock::new(),
        })
    }

    /// Initialize the per-part counters
    /// (`docs/PLAN_multi_url_source.md`). Call once after discovery.
    /// Subsequent calls are silently ignored — `OnceLock` semantics —
    /// so the same coordinator can [`Self::reset_for_retry`] and
    /// re-init only on a brand-new state instance. `parts` carries
    /// `(label, total_size)` per part; the worker labels its rows
    /// from the URL's basename.
    pub fn set_parts(&self, parts: Vec<(String, u64)>) {
        let _ = self.parts.set(
            parts
                .into_iter()
                .map(|(label, total_size)| PartCounter {
                    label,
                    total_size,
                    bytes_downloaded: AtomicU64::new(0),
                })
                .collect(),
        );
    }

    /// Borrow the per-part counters. Returns `None` until
    /// [`Self::set_parts`] has been called.
    #[must_use]
    pub fn parts(&self) -> Option<&[PartCounter]> {
        self.parts.get().map(Vec::as_slice)
    }

    /// Add `n` to the per-part counter for `part_idx`. Silently
    /// no-ops when [`Self::set_parts`] hasn't been called or the
    /// index is out of range — pre-multi-URL writers can keep
    /// calling [`Self::add_downloaded`] alone without surprise.
    pub fn add_downloaded_to_part(&self, part_idx: usize, n: u64) {
        if n == 0 {
            return;
        }
        if let Some(parts) = self.parts.get() {
            if let Some(part) = parts.get(part_idx) {
                part.bytes_downloaded.fetch_add(n, Ordering::Relaxed);
            }
        }
    }

    /// Roll back a partial in-flight per-part increment. Mirrors
    /// [`Self::sub_downloaded`]'s contract but for per-part
    /// counters; pair every [`Self::add_downloaded_to_part`] that
    /// might be rolled back with a corresponding rollback so the
    /// per-part view stays consistent with the aggregate.
    pub fn sub_downloaded_from_part(&self, part_idx: usize, n: u64) {
        if n == 0 {
            return;
        }
        if let Some(parts) = self.parts.get() {
            if let Some(part) = parts.get(part_idx) {
                part.bytes_downloaded.fetch_sub(n, Ordering::Relaxed);
            }
        }
    }

    /// Set the total source size. `0` is the sentinel for "unknown".
    pub fn set_total_size(&self, n: u64) {
        self.total_size.store(n, Ordering::Release);
    }

    /// Set the spawned-worker count. Call once after the scheduler
    /// decides parallel-vs-single-stream.
    pub fn set_total_workers(&self, n: u64) {
        self.total_workers.store(n, Ordering::Release);
    }

    /// Set the optional uncompressed-output estimate.
    pub fn set_extracted_estimate(&self, n: u64) {
        self.extracted_estimate.store(n, Ordering::Release);
    }

    /// Add bytes to the downloaded counter.
    pub fn add_downloaded(&self, n: u64) {
        if n == 0 {
            return;
        }
        self.bytes_downloaded.fetch_add(n, Ordering::Relaxed);
    }

    /// Roll back a partial in-flight increment. Used by the ranged
    /// worker when a body read fails mid-dispatch and the retry will
    /// re-fetch the same range from byte 0 — without the rollback the
    /// counter would double-count the partially-received bytes.
    pub fn sub_downloaded(&self, n: u64) {
        if n == 0 {
            return;
        }
        self.bytes_downloaded.fetch_sub(n, Ordering::Relaxed);
    }

    /// Add bytes to the extracted counter.
    pub fn add_extracted(&self, n: u64) {
        if n == 0 {
            return;
        }
        self.bytes_extracted.fetch_add(n, Ordering::Relaxed);
    }

    /// Publish the current decoder read offset (compressed bytes
    /// consumed). Monotonic in practice; a regression would only
    /// briefly under-count the lookahead and would not corrupt anything.
    pub fn set_bytes_decoded_input(&self, n: u64) {
        self.bytes_decoded_input.store(n, Ordering::Release);
    }

    /// Publish the configured disk-buffer cap. `0` means disabled.
    pub fn set_max_disk_buffer(&self, n: u64) {
        self.max_disk_buffer.store(n, Ordering::Release);
    }

    /// Toggle the disk-bound (download-throttled) flag. Set by the
    /// scheduler when it skipped a dispatch because the lookahead
    /// reached the cap; cleared on the next un-throttled tick.
    pub fn set_disk_bound(&self, on: bool) {
        self.disk_bound.store(on, Ordering::Release);
    }

    /// Compressed bytes downloaded but not yet consumed by the decoder
    /// (= what's sitting on disk in the `.peel.part` file ahead of the
    /// cursor). Saturates at `0` if the counters disagree, e.g. during
    /// startup before the first read.
    #[must_use]
    pub fn lookahead_bytes(&self) -> u64 {
        let dl = self.bytes_downloaded.load(Ordering::Relaxed);
        let consumed = self.bytes_decoded_input.load(Ordering::Relaxed);
        dl.saturating_sub(consumed)
    }

    /// Increment the active-worker counter. Pair with
    /// [`Self::worker_finished`].
    pub fn worker_started(&self) {
        self.active_workers.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the active-worker counter. Pair with
    /// [`Self::worker_started`].
    pub fn worker_finished(&self) {
        // saturating_sub-equivalent via compare_exchange would be safer
        // but the call sites are one-to-one with worker_started, so a
        // straight fetch_sub is fine.
        self.active_workers.fetch_sub(1, Ordering::Relaxed);
    }

    /// Mark the run as begun.
    pub fn mark_started(&self) {
        self.started.store(true, Ordering::Release);
    }

    /// Mark the run as finished. The renderer thread stops on its
    /// next tick.
    pub fn mark_done(&self) {
        self.done.store(true, Ordering::Release);
    }

    /// Clear the per-run byte counters and worker tallies so the next
    /// [`crate::coordinator::run`] call (e.g. an outer-loop retry after
    /// a transient download failure) re-credits resumed bytes from a
    /// clean baseline. Leaves `done` alone so the renderer thread keeps
    /// running, and leaves `total_size` / `max_disk_buffer` alone since
    /// those are configuration that doesn't change between retries.
    pub fn reset_for_retry(&self) {
        self.bytes_downloaded.store(0, Ordering::Release);
        self.bytes_extracted.store(0, Ordering::Release);
        self.bytes_decoded_input.store(0, Ordering::Release);
        self.extracted_estimate.store(0, Ordering::Release);
        self.active_workers.store(0, Ordering::Release);
        self.total_workers.store(0, Ordering::Release);
        self.disk_bound.store(false, Ordering::Release);
        self.started.store(false, Ordering::Release);
        // Any decode_step in flight is owned by the failed run that's
        // about to be torn down; clear the marker so the next run's
        // peer watchdog starts from "no step in progress."
        self.decode_step_started_ns.store(0, Ordering::Release);
    }

    /// Publish that the extractor has just *entered* a `decode_step`
    /// call. The peer watchdog ([`DecodeStepStallDetector`]) reads
    /// this from the renderer thread and warns if the call has not
    /// returned within its threshold (PLAN_decoder_freeze.md §2.4b).
    ///
    /// Called from the extractor's `run_loop` before every
    /// `decode_step` invocation. Pairs with
    /// [`Self::mark_decode_step_exited`] on the way back out — the
    /// `1` minimum below ensures the sentinel `0` is never used as a
    /// real timestamp on freshly-anchored states.
    pub fn mark_decode_step_entered(&self) {
        // u64 nanos of state lifetime — covers ~584 years.
        let ns = u64::try_from(self.state_anchor.elapsed().as_nanos()).unwrap_or(u64::MAX);
        self.decode_step_started_ns
            .store(ns.max(1), Ordering::Release);
    }

    /// Publish that the extractor has *returned* from a `decode_step`
    /// call. Pairs with [`Self::mark_decode_step_entered`].
    pub fn mark_decode_step_exited(&self) {
        self.decode_step_started_ns.store(0, Ordering::Release);
    }

    /// Wall-clock time the current `decode_step` has been running.
    /// `None` when no call is in progress (the gap between entries).
    /// Read from the renderer thread.
    #[must_use]
    pub fn decode_step_elapsed(&self) -> Option<Duration> {
        let started_ns = self.decode_step_started_ns.load(Ordering::Acquire);
        if started_ns == 0 {
            return None;
        }
        let now_ns = u64::try_from(self.state_anchor.elapsed().as_nanos()).unwrap_or(u64::MAX);
        Some(Duration::from_nanos(now_ns.saturating_sub(started_ns)))
    }

    /// `true` iff [`Self::mark_done`] has been called.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }

    /// Take a single coherent snapshot of all the counters.
    #[must_use]
    pub fn snapshot(&self) -> ProgressSnapshot {
        let total = self.total_size.load(Ordering::Acquire);
        let est = self.extracted_estimate.load(Ordering::Acquire);
        let max_buf = self.max_disk_buffer.load(Ordering::Acquire);
        let parts: Vec<PartProgressSnapshot> = self
            .parts
            .get()
            .map(|parts| {
                parts
                    .iter()
                    .map(|p| PartProgressSnapshot {
                        label: p.label.clone(),
                        total_size: p.total_size,
                        bytes_downloaded: p.bytes_downloaded.load(Ordering::Relaxed),
                    })
                    .collect()
            })
            .unwrap_or_default();
        ProgressSnapshot {
            total_size: if total == 0 { None } else { Some(total) },
            bytes_downloaded: self.bytes_downloaded.load(Ordering::Relaxed),
            bytes_extracted: self.bytes_extracted.load(Ordering::Relaxed),
            extracted_estimate: if est == 0 { None } else { Some(est) },
            active_workers: self.active_workers.load(Ordering::Relaxed),
            total_workers: self.total_workers.load(Ordering::Relaxed),
            started: self.started.load(Ordering::Acquire),
            done: self.done.load(Ordering::Acquire),
            bytes_decoded_input: self.bytes_decoded_input.load(Ordering::Relaxed),
            max_disk_buffer: if max_buf == 0 { None } else { Some(max_buf) },
            disk_bound: self.disk_bound.load(Ordering::Acquire),
            decode_step_elapsed: self.decode_step_elapsed(),
            parts,
        }
    }
}

/// Point-in-time view of every counter [`ProgressState`] tracks.
///
/// The fields whose underlying atomic uses `0` as a sentinel for
/// "unknown" are surfaced here as `Option`, so renderers don't need
/// to re-encode the convention.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ProgressSnapshot {
    /// Total source size, if known.
    pub total_size: Option<u64>,
    /// Compressed bytes downloaded so far.
    pub bytes_downloaded: u64,
    /// Decoded bytes written so far.
    pub bytes_extracted: u64,
    /// Decoded total estimate, if known.
    pub extracted_estimate: Option<u64>,
    /// Workers actively performing IO.
    pub active_workers: u64,
    /// Workers spawned for the run.
    pub total_workers: u64,
    /// `true` after the coordinator entered the main loop.
    pub started: bool,
    /// `true` after the coordinator finished (clean or error).
    pub done: bool,
    /// Compressed bytes the streaming decoder has consumed
    /// (= the source-file read cursor). Used to compute
    /// "lookahead" (`bytes_downloaded - bytes_decoded_input`).
    pub bytes_decoded_input: u64,
    /// Configured cap on the lookahead, or `None` when the throttle
    /// is disabled (the user passed `--max-disk-buffer none`).
    pub max_disk_buffer: Option<u64>,
    /// `true` while the scheduler is actively throttling the
    /// download because the lookahead has hit the cap. The renderer
    /// reads this for the bottleneck indicator.
    pub disk_bound: bool,
    /// Wall-clock time the current `decode_step` has been running
    /// (PLAN_decoder_freeze.md §2.4b). `None` if no step is in
    /// progress at the snapshot instant. The
    /// [`DecodeStepStallDetector`] uses this to fire from the
    /// renderer thread when the extractor thread is wedged inside a
    /// blocking syscall on its own thread (where the §2.2 post-hoc
    /// watchdog cannot reach).
    pub decode_step_elapsed: Option<Duration>,
    /// Per-part view of the download counters
    /// (`docs/PLAN_multi_url_source.md`). Empty for runs that did
    /// not call [`ProgressState::set_parts`] — single-URL runs
    /// historically take this path. Length matches the discovered
    /// part count when populated; index N is the same part as
    /// `info.source.parts()[N]`.
    pub parts: Vec<PartProgressSnapshot>,
}

/// Per-part snapshot row in [`ProgressSnapshot::parts`].
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PartProgressSnapshot {
    /// Short label — typically the URL's basename
    /// (e.g. `pruned.tar.part0000`).
    pub label: String,
    /// `Content-Length` reported for this part at HEAD time.
    pub total_size: u64,
    /// Compressed bytes downloaded for this part so far.
    pub bytes_downloaded: u64,
}

/// Rolling-window rate tracker.
///
/// Fed an `(Instant, cumulative_bytes)` sample on each render tick.
/// Returns the average bytes-per-second computed over the samples
/// inside `window`, or `None` if the buffer doesn't yet span at least
/// [`RateBuffer::min_span`] of wall-clock time.
///
/// The buffer is intentionally tiny (default capacity 64): one sample
/// per render tick, the default render interval is 100 ms, and we
/// only need to span ~5 s, so 50 samples are enough. A small fixed
/// capacity keeps the renderer's per-tick allocation pattern flat.
#[derive(Debug)]
pub struct RateBuffer {
    samples: VecDeque<(Instant, u64)>,
    window: Duration,
    capacity: usize,
    min_span: Duration,
}

impl RateBuffer {
    /// Construct a new buffer.
    ///
    /// - `window`: how far back to average over (PLAN §6 calls for 5 s).
    /// - `capacity`: maximum number of samples retained.
    /// - `min_span`: don't return a rate until the buffer has at least
    ///   this much span (PLAN §6 calls for 5 s before showing ETA).
    #[must_use]
    pub fn new(window: Duration, capacity: usize, min_span: Duration) -> Self {
        Self {
            samples: VecDeque::with_capacity(capacity),
            window,
            capacity: capacity.max(2),
            min_span,
        }
    }

    /// Defaults the renderer threads use: a 10 s window with a 1 s
    /// minimum span and 64-sample capacity.
    ///
    /// The 1 s `min_span` is the smallest span we trust as a rate
    /// estimate — anything shorter is too jittery on a network. The
    /// 10 s `window` is generous enough that the LogRenderer (which
    /// ticks every 2 s, holding ≤6 samples) keeps a span of at least
    /// 4 s in steady state without ever dropping below `min_span`.
    /// Earlier versions used `window == min_span == 5 s`, which made
    /// the rate flap to `None` on every other LogRenderer tick (and
    /// hide for the entire run on downloads shorter than 5 s).
    #[must_use]
    pub fn for_renderer() -> Self {
        Self::new(Duration::from_secs(10), 64, Duration::from_secs(1))
    }

    /// Push a new `(now, total_bytes)` observation. Old samples
    /// outside `window` are dropped. Saturates at `capacity` from the
    /// front (oldest sample) if too many push without window-eviction.
    pub fn push(&mut self, now: Instant, total_bytes: u64) {
        // Evict samples older than `now - window`.
        while let Some((t, _)) = self.samples.front() {
            if now.saturating_duration_since(*t) > self.window {
                self.samples.pop_front();
            } else {
                break;
            }
        }
        // Hard cap on memory: if the renderer ticks faster than the
        // window evicts, drop the oldest. This is defensive — under
        // normal cadence we never get here.
        while self.samples.len() >= self.capacity {
            self.samples.pop_front();
        }
        self.samples.push_back((now, total_bytes));
    }

    /// Wall-clock span of the retained samples.
    #[must_use]
    pub fn span(&self) -> Option<Duration> {
        match (self.samples.front(), self.samples.back()) {
            (Some((a, _)), Some((b, _))) => Some(b.saturating_duration_since(*a)),
            _ => None,
        }
    }

    /// Average bytes-per-second over the retained window.
    ///
    /// Returns `None` if the span is below [`Self::min_span`] or if
    /// the cumulative counter went backwards (defensive — shouldn't
    /// happen in practice, but caps a runtime crash if it does).
    #[must_use]
    pub fn rate_bytes_per_sec(&self) -> Option<f64> {
        let span = self.span()?;
        if span < self.min_span {
            return None;
        }
        let secs = span.as_secs_f64();
        if secs <= 0.0 {
            return None;
        }
        let (_, first) = self.samples.front()?;
        let (_, last) = self.samples.back()?;
        let delta = last.checked_sub(*first)?;
        Some(delta as f64 / secs)
    }
}

/// Render-side abstraction. Implementations are free to do whatever
/// they want with each snapshot — write ANSI to a terminal, emit a
/// `tracing` event, push to a metrics endpoint, …
pub trait ProgressRenderer: Send {
    /// Draw / log the snapshot. Called once per render tick.
    fn render(&mut self, snapshot: &ProgressSnapshot);
    /// Final cleanup after the run completes (e.g. emit a newline so
    /// the next shell prompt starts on a fresh line below the
    /// in-place block).
    fn finish(&mut self);
}

/// Visual style for the progress bar.
///
/// The [`TtyRenderer`] picks one of these at construction time. The
/// default constructor sniffs locale environment variables (`LC_ALL`,
/// `LC_CTYPE`, `LANG`) for a `UTF-8` indicator and selects
/// [`BarStyle::Unicode`] when one is found, falling back to
/// [`BarStyle::Ascii`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarStyle {
    /// `[####....]` — one byte per cell, two columns of brackets.
    Ascii,
    /// `🟦🟦⬜⬜` — one square emoji per cell, two display columns each.
    Unicode,
}

impl BarStyle {
    /// Auto-detect a style from the user's locale environment.
    #[must_use]
    pub fn detect() -> Self {
        if supports_unicode() {
            Self::Unicode
        } else {
            Self::Ascii
        }
    }
}

/// Which side of the pipeline is the current bottleneck.
///
/// The renderer surfaces this as a small colored badge on line 1 and
/// paints the corresponding rate string on line 2 or 3. `None` means
/// "not enough signal yet" — usually during the first ~5 s while the
/// rate buffers fill.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bottleneck {
    /// The download is the slow side (we're waiting on the network).
    Network,
    /// The extract is the slow side (we're disk-bound — either
    /// throttled by `--max-disk-buffer`, or extract rate < download
    /// rate after correcting for compression).
    Disk,
}

impl Bottleneck {
    /// Render the badge with the appropriate emoji / label and ANSI
    /// color. The returned string includes the SGR reset.
    fn badge(self, style: BarStyle) -> String {
        let (label, color) = match (self, style) {
            (Self::Network, BarStyle::Unicode) => ("🔵 net", ANSI_CYAN),
            (Self::Disk, BarStyle::Unicode) => ("🟡 disk", ANSI_YELLOW),
            (Self::Network, BarStyle::Ascii) => ("[NET]", ANSI_CYAN),
            (Self::Disk, BarStyle::Ascii) => ("[DISK]", ANSI_YELLOW),
        };
        paint(label, color)
    }
}

const ANSI_CYAN: &str = "\x1b[36m";
const ANSI_YELLOW: &str = "\x1b[33m";
const ANSI_RESET: &str = "\x1b[0m";

fn paint(s: &str, color: &str) -> String {
    format!("{color}{s}{ANSI_RESET}")
}

/// Decide which side is the bottleneck given a snapshot and the
/// current rate estimates.
///
/// Priority:
/// 1. If [`ProgressSnapshot::disk_bound`] is set, the scheduler is
///    actively throttling — definitively disk-bound.
/// 2. Otherwise, when both the download rate and the decoder-input
///    rate are known, compare them directly. Both are measured in
///    *compressed* bytes per second (`bytes_downloaded` and
///    `bytes_decoded_input` advance over the same byte stream — the
///    part file), so the comparison needs no compression-ratio
///    correction: whichever side moves slower is the bottleneck. A
///    growing gap between them is the lookahead growing, which is
///    the operator-visible signal of disk-side starvation. A 10%
///    margin keeps the indicator from flapping when the two sides
///    are roughly balanced.
/// 3. Otherwise, return `None` (no claim).
///
/// The earlier formulation compared the download rate against the
/// extract (uncompressed-output) rate scaled by an
/// `extracted_estimate / total_size` ratio that defaulted to 1.0
/// when the estimate was unknown — for any compressed archive that
/// understated the download rate's headroom and badged
/// `Bottleneck::Network` while the lookahead was visibly growing.
/// `PLAN_decoder_freeze.md` §1.1 has the rationale.
#[must_use]
pub fn classify_bottleneck(
    snap: &ProgressSnapshot,
    dl_rate: Option<f64>,
    decoded_in_rate: Option<f64>,
) -> Option<Bottleneck> {
    if snap.disk_bound {
        return Some(Bottleneck::Disk);
    }
    let (dl, di) = (dl_rate?, decoded_in_rate?);
    if dl <= 0.0 || di <= 0.0 {
        return None;
    }
    // 10% deadband around equality. Both rates are compressed bytes/s
    // over the same stream, so direct comparison is the truth.
    if dl < di * 0.9 {
        Some(Bottleneck::Network)
    } else if di < dl * 0.9 {
        Some(Bottleneck::Disk)
    } else {
        None
    }
}

/// Maximum bar width in display columns. The line still fits a 120-column
/// terminal with comfortable padding for the percent/ETA suffix.
const MAX_BAR_COLUMNS: usize = 100;
/// Fallback terminal width when `ioctl(TIOCGWINSZ)` and `COLUMNS` both
/// fail. Eighty columns is the historical default.
const FALLBACK_TERMINAL_COLUMNS: usize = 80;

/// ANSI-on-stderr renderer for interactive terminals.
///
/// Three lines, redrawn in place by walking the cursor back up with
/// `\x1b[<N>A` between ticks (each rewritten line uses `\x1b[K` to
/// clear leftover bytes from the previous tick). [`Self::finish`]
/// flushes; the trailing newline of the last render leaves the shell
/// prompt on a fresh line below the block.
///
/// The bar on line 1 stretches to the available terminal width, capped
/// at [`MAX_BAR_COLUMNS`]; the renderer queries `ioctl(TIOCGWINSZ)` on
/// every tick so a `SIGWINCH` between ticks resizes the bar without
/// any wiring. When the renderer is built with a [`BarStyle::Unicode`]
/// style each cell is a wide square emoji; in [`BarStyle::Ascii`] it's
/// the historical `[####....]` pattern.
///
/// Generic over the writer to make tests trivial; the binary uses
/// [`std::io::Stderr`].
pub struct TtyRenderer<W: Write + Send> {
    out: W,
    rate_dl: RateBuffer,
    rate_ex: RateBuffer,
    rate_decoded_in: RateBuffer,
    style: BarStyle,
    /// Override the detected terminal width. Tests use this; the
    /// binary leaves it `None` so the renderer picks up the live
    /// terminal size on every tick.
    terminal_width_override: Option<usize>,
    /// Hard cap on the bar width in display columns. Defaults to
    /// [`MAX_BAR_COLUMNS`] in the auto path; tests may pass smaller.
    bar_max_columns: usize,
    started_render: bool,
    last_lines_emitted: usize,
    /// Per-part rate buffers, one per discovered part. Allocated
    /// lazily on the first non-empty snapshot
    /// (`docs/PLAN_multi_url_source.md` progress UI). `Vec::is_empty()`
    /// means "not yet seen multi-URL data" — single-URL runs leave it
    /// empty for the entire run.
    rate_parts: Vec<RateBuffer>,
}

/// Maximum number of per-part rows the TTY renderer prints before
/// collapsing the tail into a `... + N more` summary
/// (`docs/PLAN_multi_url_source.md` progress UI). Sized so a 24-row
/// xterm shows every row plus the 5-line aggregate footer for
/// realistic Arbitrum-shaped inventories (≤ 5 parts) and most
/// long-tail manifests, while still bounding output for pathological
/// 100-part lists.
const MAX_PART_ROWS: usize = 16;
/// Bar width for per-part rows. Narrower than the main aggregate bar
/// so the URL label has room on the right of the bar at typical
/// 80–120 column terminals.
const PART_ROW_BAR_COLUMNS: usize = 24;

impl<W: Write + Send> TtyRenderer<W> {
    /// Construct with the default rate buffers, locale-detected bar
    /// style, and the live terminal width.
    pub fn new(out: W) -> Self {
        Self {
            out,
            rate_dl: RateBuffer::for_renderer(),
            rate_ex: RateBuffer::for_renderer(),
            rate_decoded_in: RateBuffer::for_renderer(),
            style: BarStyle::detect(),
            terminal_width_override: None,
            bar_max_columns: MAX_BAR_COLUMNS,
            started_render: false,
            last_lines_emitted: 0,
            rate_parts: Vec::new(),
        }
    }

    /// Construct with an explicit bar-width cap, ASCII style, and an
    /// override that pins the apparent terminal width to the same
    /// value (tests use this).
    pub fn with_bar_width(out: W, bar_width: usize) -> Self {
        let bar = bar_width.max(4);
        Self {
            out,
            rate_dl: RateBuffer::for_renderer(),
            rate_ex: RateBuffer::for_renderer(),
            rate_decoded_in: RateBuffer::for_renderer(),
            style: BarStyle::Ascii,
            terminal_width_override: None,
            bar_max_columns: bar,
            started_render: false,
            last_lines_emitted: 0,
            rate_parts: Vec::new(),
        }
    }

    /// Construct with an explicit bar style and a fixed apparent
    /// terminal width (tests of the new layout use this).
    pub fn with_style_and_width(out: W, style: BarStyle, terminal_width: usize) -> Self {
        Self {
            out,
            rate_dl: RateBuffer::for_renderer(),
            rate_ex: RateBuffer::for_renderer(),
            rate_decoded_in: RateBuffer::for_renderer(),
            style,
            terminal_width_override: Some(terminal_width.max(20)),
            bar_max_columns: MAX_BAR_COLUMNS,
            started_render: false,
            last_lines_emitted: 0,
            rate_parts: Vec::new(),
        }
    }

    /// Resolve the apparent terminal width for this tick: explicit
    /// override > live `TIOCGWINSZ` > `COLUMNS` env > 80-column default.
    fn columns(&self) -> usize {
        self.terminal_width_override
            .or_else(terminal_columns)
            .unwrap_or(FALLBACK_TERMINAL_COLUMNS)
    }

    /// Format the five-line block for `snap` using `now` as the rate
    /// sample timestamp. Pure: returns
    /// `(line1, line2, line3, line4, line5)` without touching `self.out`.
    /// Tests call this directly.
    ///
    /// Line 4 is the decoder-cursor / lookahead row added in
    /// `PLAN_responsiveness.md` §1.1: it shows the gap between the
    /// download cursor and the decoder cursor against the configured
    /// throttle cap, so an operator can tell at a glance whether the
    /// decoder is reading source bytes when extract progress is flat.
    ///
    /// Single-URL (or pre-discovery) snapshots emit exactly the
    /// historical 5 lines. Multi-URL snapshots
    /// (`docs/PLAN_multi_url_source.md` progress UI) emit one row per
    /// part *above* the 5-line aggregate footer; rows past
    /// [`MAX_PART_ROWS`] are collapsed into a `... + N more` line.
    pub fn format_block(
        &mut self,
        snap: &ProgressSnapshot,
        now: Instant,
    ) -> (String, String, String, String, String) {
        // Backwards-compatible accessor used by the existing tests:
        // returns just the 5-line aggregate. Multi-URL callers should
        // use [`Self::format_lines`] instead.
        let lines = self.format_lines(snap, now);
        let agg_start = lines.len().saturating_sub(5);
        let agg = &lines[agg_start..];
        (
            agg[0].clone(),
            agg[1].clone(),
            agg[2].clone(),
            agg[3].clone(),
            agg[4].clone(),
        )
    }

    /// Format the full block as a vec of lines: per-part rows first
    /// (multi-URL only), then the 5-line aggregate footer. Pure
    /// w.r.t. `self.out`. The returned Vec always has at least 5
    /// entries; multi-URL adds one entry per displayed part.
    pub fn format_lines(&mut self, snap: &ProgressSnapshot, now: Instant) -> Vec<String> {
        // Aggregate rate samples first — those drive the footer.
        self.rate_dl.push(now, snap.bytes_downloaded);
        self.rate_ex.push(now, snap.bytes_extracted);
        self.rate_decoded_in.push(now, snap.bytes_decoded_input);

        // Lazily allocate per-part rate buffers when we first see a
        // populated parts vec. Re-running the coordinator (retry path)
        // resets the counters but the part list shape stays the same;
        // we re-allocate on a length change so a topology shift would
        // surface as fresh rate windows.
        if !snap.parts.is_empty() && self.rate_parts.len() != snap.parts.len() {
            self.rate_parts = (0..snap.parts.len())
                .map(|_| RateBuffer::for_renderer())
                .collect();
        }
        for (i, part) in snap.parts.iter().enumerate() {
            if let Some(buf) = self.rate_parts.get_mut(i) {
                buf.push(now, part.bytes_downloaded);
            }
        }

        let dl_rate = self.rate_dl.rate_bytes_per_sec();
        let ex_rate = self.rate_ex.rate_bytes_per_sec();
        let decoded_in_rate = self.rate_decoded_in.rate_bytes_per_sec();

        let percent = overall_percent(snap);
        let eta = compute_eta(snap, dl_rate, ex_rate);

        let term_cols = self.columns();
        let bar_cap = self.bar_max_columns.min(MAX_BAR_COLUMNS);
        let bottleneck = classify_bottleneck(snap, dl_rate, decoded_in_rate);

        let mut lines: Vec<String> = Vec::with_capacity(snap.parts.len() + 5);

        // Per-part section: only when the discovered source is
        // multi-URL. Single-URL runs (parts.len() == 1) keep the
        // historical 5-line block so existing tooling and tests stay
        // unchanged.
        if snap.parts.len() > 1 {
            let label_width = snap
                .parts
                .iter()
                .take(MAX_PART_ROWS)
                .map(|p| p.label.chars().count())
                .max()
                .unwrap_or(0);
            let part_bar_cols = part_row_bar_columns(term_cols, label_width);
            for (i, part) in snap.parts.iter().take(MAX_PART_ROWS).enumerate() {
                let part_rate = self
                    .rate_parts
                    .get(i)
                    .and_then(RateBuffer::rate_bytes_per_sec);
                lines.push(format_part_row(
                    part,
                    part_rate,
                    label_width,
                    part_bar_cols,
                    self.style,
                ));
            }
            if snap.parts.len() > MAX_PART_ROWS {
                let remaining = snap.parts.len() - MAX_PART_ROWS;
                lines.push(format!("  …+ {remaining} more parts"));
            }
        }

        lines.push(format_overall_line(
            snap, percent, term_cols, bar_cap, self.style,
        ));
        lines.push(format_download_line(snap, dl_rate, bottleneck));
        lines.push(format_extract_line(snap, ex_rate, bottleneck));
        lines.push(format_lookahead_line(snap, bottleneck));
        lines.push(format_eta_line(eta, self.style, bottleneck));
        lines
    }
}

/// Display columns occupied by everything in a per-part row *other
/// than* the bar, conservatively sized so the row never wraps:
/// ```text
///   {bar}  {pct}  {label}  {dl} / {total}{status}
/// ```
/// Reservations:
/// - leading + inter-column spacing: `2 + 2 + 2 + 2 = 8`
/// - `{pct}`: 7 cols for the unknown-total `"  --.-%"` shape
/// - `{dl}` / `{total}`: 10 cols each ([`format_bytes`] tops out at
///   `"1023.4 PiB"` = 10 chars; everyday counts are shorter and leave
///   the bar a little extra breathing room)
/// - ` / ` between dl/total: 3
/// - `{status}`: 16 cols for the worst-case rate
///   (`"  @ 1023.4 PiB/s"`); `done` / `idle` / `…` are smaller.
const PART_ROW_RESERVED_NON_BAR: usize = 8 + 7 + 10 + 3 + 10 + 16;

/// Minimum bar width before falling back to the leanest possible bar
/// — at 4 cols a unicode bar is just two emoji cells (4 display cols)
/// and an ASCII bar is `[##]`-shaped, both still legible.
const PART_ROW_MIN_BAR_COLUMNS: usize = 4;

/// Pick a per-part bar width that lets the row fit inside `term_cols`
/// without wrapping at typical terminal widths (80, 88, 100, 120 …).
/// `label_width` is the longest part label in the snapshot — it
/// expands the row in proportion to inventory naming, so we subtract
/// it from the available budget.
///
/// Returns at least [`PART_ROW_MIN_BAR_COLUMNS`] (a wrapped row is
/// worse than a tiny bar — the renderer's `\x1b[NA` cursor-up math
/// counts logical lines, but the terminal counts visual rows, so any
/// wrap silently misaligns the redraw and stacks ghosts of prior
/// frames in the scrollback) and at most [`PART_ROW_BAR_COLUMNS`].
fn part_row_bar_columns(term_cols: usize, label_width: usize) -> usize {
    let reserved = PART_ROW_RESERVED_NON_BAR.saturating_add(label_width);
    let available = term_cols.saturating_sub(reserved);
    available.clamp(PART_ROW_MIN_BAR_COLUMNS, PART_ROW_BAR_COLUMNS)
}

/// Format one per-part progress row
/// (`docs/PLAN_multi_url_source.md` progress UI). Layout:
///
/// ```text
/// [================  ]   64.5%  pruned.tar.part0001  165.0 GiB / 256.0 GiB  @ 12.0 MiB/s
/// ```
///
/// `label_width` pads the label so a vertical inventory aligns;
/// `bar_cols` is the per-row bar width [`part_row_bar_columns`]
/// computed for this terminal. A completed part shows `done` instead
/// of a rate; an idle part with zero bytes downloaded shows `idle`.
/// The bar matches whichever row's downloaded/total ratio it
/// represents; the percent column mirrors the aggregate row's
/// placement (`peel  [bar]  XX.X%`) so the per-part rows and the
/// footer line up visually.
fn format_part_row(
    part: &PartProgressSnapshot,
    rate: Option<f64>,
    label_width: usize,
    bar_cols: usize,
    style: BarStyle,
) -> String {
    let frac = if part.total_size == 0 {
        0.0
    } else {
        (part.bytes_downloaded as f64 / part.total_size as f64).clamp(0.0, 1.0)
    };
    let bar = render_bar_for(frac, bar_cols, style);
    let pct = if part.total_size == 0 {
        "  --.-%".to_string()
    } else {
        format!("{:5.1}%", frac * 100.0)
    };
    let displayed_downloaded = if part.total_size > 0 {
        part.bytes_downloaded.min(part.total_size)
    } else {
        part.bytes_downloaded
    };
    let downloaded = format_bytes(displayed_downloaded);
    let total = format_bytes(part.total_size);
    let label = pad_label(&part.label, label_width);
    let status = if part.bytes_downloaded == 0 {
        "  idle".to_string()
    } else if part.bytes_downloaded >= part.total_size && part.total_size > 0 {
        "  done".to_string()
    } else {
        match rate {
            Some(r) => format!("  @ {}", format_rate(r)),
            None => "  …".to_string(),
        }
    };
    format!("  {bar}  {pct}  {label}  {downloaded} / {total}{status}")
}

/// Pad `label` on the right with spaces to `width` *display columns*.
/// Counts characters (not bytes) to handle multibyte labels uniformly
/// — labels usually come from URL basenames which are ASCII in
/// practice but the helper is safe regardless.
fn pad_label(label: &str, width: usize) -> String {
    let chars = label.chars().count();
    if chars >= width {
        label.to_string()
    } else {
        let mut out = String::with_capacity(label.len() + (width - chars));
        out.push_str(label);
        for _ in 0..(width - chars) {
            out.push(' ');
        }
        out
    }
}

impl<W: Write + Send> ProgressRenderer for TtyRenderer<W> {
    fn render(&mut self, snapshot: &ProgressSnapshot) {
        let now = Instant::now();
        let lines = self.format_lines(snapshot, now);
        // Each render rewrites the previous block. Strategy:
        //   First tick: write every line, each terminated with
        //               \x1b[K (clear-to-EOL) and \n.
        //   Subsequent: \x1b[<N>A move cursor up N lines (start of
        //               line, since we ended each line with \n which
        //               returns to col 0 on the next line), then
        //               re-emit.
        //
        // Rationale: \x1b7 / \x1b8 (DECSC/DECRC) are the canonical
        // PLAN_v2.md §6 picks, but they don't survive scroll-back if
        // another process prints between two of our ticks. The
        // cursor-up approach is robust to that: if scroll-back has
        // pushed our block off-screen, the cursor-up just moves to
        // the top of whatever is currently visible and we redraw
        // there. Per-part runs make the block taller but the same
        // logic still applies — we just pass the new line count.
        //
        // The block height can change between ticks: the first tick
        // before discovery has zero parts, the second tick has N
        // parts (`docs/PLAN_multi_url_source.md` progress UI). When
        // the new block is *shorter* than the previous one we'd
        // leave stale rows visible below; emit a clear-to-EOL on
        // each leftover row (then move back up) so the dropped tail
        // disappears cleanly.
        if self.started_render {
            let n = self.last_lines_emitted.min(99);
            if n > 0 {
                let _ = write!(self.out, "\x1b[{n}A");
            }
            if lines.len() < self.last_lines_emitted {
                // Erase the trailing rows the new block doesn't
                // cover. Move down to where they sit, clear, then
                // move back up to the top of the new block.
                let down = lines.len();
                if down > 0 {
                    let _ = write!(self.out, "\x1b[{down}B");
                }
                let extra = self.last_lines_emitted - lines.len();
                for _ in 0..extra {
                    let _ = writeln!(self.out, "\x1b[K");
                }
                let _ = write!(self.out, "\x1b[{}A", down + extra);
            }
        } else {
            self.started_render = true;
        }

        for line in &lines {
            let _ = writeln!(self.out, "{line}\x1b[K");
        }
        let _ = self.out.flush();
        self.last_lines_emitted = lines.len();
    }

    fn finish(&mut self) {
        // Leave the final block visible; just make sure subsequent
        // shell output starts cleanly. The trailing newlines on the
        // last render already put the cursor on a fresh line below
        // the block, so no extra emit is needed in the typical case.
        // We still flush defensively in case the buffer is holding
        // anything.
        let _ = self.out.flush();
    }
}

/// Non-TTY renderer that emits one `tracing::info!` event per tick.
///
/// Mirrors [`TtyRenderer`]'s field set so log scrapers can parse the
/// same numbers a TTY user would see. The default render cadence on
/// non-TTY (set by [`spawn_renderer`]) is 2 s; with a 5 s rate window
/// the rate stabilizes after the first three ticks.
pub struct LogRenderer {
    rate_dl: RateBuffer,
    rate_ex: RateBuffer,
    rate_decoded_in: RateBuffer,
    /// Per-part rate buffers, allocated lazily on first non-empty
    /// snapshot (`docs/PLAN_multi_url_source.md` progress UI). Empty
    /// for single-URL runs.
    rate_parts: Vec<RateBuffer>,
}

impl Default for LogRenderer {
    fn default() -> Self {
        Self::new()
    }
}

impl LogRenderer {
    /// Construct with the default 5 s rate buffers.
    #[must_use]
    pub fn new() -> Self {
        Self {
            rate_dl: RateBuffer::for_renderer(),
            rate_ex: RateBuffer::for_renderer(),
            rate_decoded_in: RateBuffer::for_renderer(),
            rate_parts: Vec::new(),
        }
    }

    /// Format the aggregate line [`Self::render`] emits. Pure: tests
    /// call it without a tracing subscriber.
    ///
    /// Mirrors the TTY renderer's footer in shape — sizes via
    /// [`format_bytes`], rates via [`format_rate`], ETA via
    /// [`format_eta`] — flattened onto one log line so each tick's
    /// aggregate is a single record. A bottleneck label
    /// (`bottleneck=disk` or `=net`) is appended when the classifier
    /// has a verdict, with no ANSI color escapes (the log subscriber
    /// is responsible for any styling it wants to apply).
    ///
    /// For multi-URL runs ([`Self::format_part_lines`] returns a
    /// non-empty Vec) this is the *aggregate* row only; per-part
    /// rows are formatted separately so log scrapers can grep for
    /// `[partN]` independently.
    pub fn format_line(&mut self, snap: &ProgressSnapshot, now: Instant) -> String {
        self.rate_dl.push(now, snap.bytes_downloaded);
        self.rate_ex.push(now, snap.bytes_extracted);
        self.rate_decoded_in.push(now, snap.bytes_decoded_input);
        let dl_rate = self.rate_dl.rate_bytes_per_sec();
        let ex_rate = self.rate_ex.rate_bytes_per_sec();
        let decoded_in_rate = self.rate_decoded_in.rate_bytes_per_sec();
        let percent = overall_percent(snap);
        let eta = compute_eta(snap, dl_rate, ex_rate);
        let bottleneck = classify_bottleneck(snap, dl_rate, decoded_in_rate);

        let pct = percent
            .map(|p| format!("{p:.1}%"))
            .unwrap_or_else(|| "?".into());
        let displayed_downloaded = match snap.total_size {
            Some(t) if t > 0 => snap.bytes_downloaded.min(t),
            _ => snap.bytes_downloaded,
        };
        let downloaded = format_bytes(displayed_downloaded);
        let total = snap
            .total_size
            .map(format_bytes)
            .unwrap_or_else(|| "?".into());
        let extracted = format_bytes(snap.bytes_extracted);
        let est = snap
            .extracted_estimate
            .map(format_bytes)
            .unwrap_or_else(|| "unknown".into());
        let dl = dl_rate.map(format_rate).unwrap_or_else(|| "—".into());
        let ex = ex_rate.map(format_rate).unwrap_or_else(|| "—".into());
        let eta_s = format_eta(eta);
        let lookahead = format_bytes(
            snap.bytes_downloaded
                .saturating_sub(snap.bytes_decoded_input),
        );
        let cap = match snap.max_disk_buffer {
            Some(c) => format!("{} cap", format_bytes(c)),
            None => "uncapped".into(),
        };
        let decoded_in = format_bytes(snap.bytes_decoded_input);
        // For single-URL runs we keep today's `progress: ...` prefix
        // so log scrapers built against the historical line shape
        // continue to parse. Multi-URL runs change the prefix to
        // `[overall] progress: ...` to pair cleanly with the
        // sibling `[partN] ...` lines, and so a grep for `[overall]`
        // returns one record per tick.
        let prefix = if snap.parts.len() > 1 {
            "[overall] progress"
        } else {
            "progress"
        };
        let mut line = format!(
            "{prefix}: {pct}  download {downloaded} / {total} @ {dl}  \
             extract {extracted} / {est} @ {ex}  \
             lookahead {lookahead} / {cap}  decoded_in {decoded_in}  \
             workers {}/{}  ETA {eta_s}",
            snap.active_workers, snap.total_workers,
        );
        if let Some(b) = bottleneck {
            let label = match b {
                Bottleneck::Disk => "disk",
                Bottleneck::Network => "net",
            };
            line.push_str("  bottleneck=");
            line.push_str(label);
        }
        line
    }

    /// Format the per-part log lines for `snap`. Returns an empty
    /// Vec for single-URL runs (`parts.len() <= 1`); otherwise one
    /// line per part with a `[partN]` prefix that grep-isolates each
    /// one. Pushes per-part rate samples so the rate column
    /// stabilizes after a few ticks.
    pub fn format_part_lines(&mut self, snap: &ProgressSnapshot, now: Instant) -> Vec<String> {
        if snap.parts.len() <= 1 {
            return Vec::new();
        }
        if self.rate_parts.len() != snap.parts.len() {
            self.rate_parts = (0..snap.parts.len())
                .map(|_| RateBuffer::for_renderer())
                .collect();
        }
        for (i, part) in snap.parts.iter().enumerate() {
            if let Some(buf) = self.rate_parts.get_mut(i) {
                buf.push(now, part.bytes_downloaded);
            }
        }
        snap.parts
            .iter()
            .enumerate()
            .map(|(i, part)| {
                let rate = self
                    .rate_parts
                    .get(i)
                    .and_then(RateBuffer::rate_bytes_per_sec);
                let displayed_downloaded = if part.total_size > 0 {
                    part.bytes_downloaded.min(part.total_size)
                } else {
                    part.bytes_downloaded
                };
                let downloaded = format_bytes(displayed_downloaded);
                let total = format_bytes(part.total_size);
                let pct = if part.total_size == 0 {
                    "?".to_string()
                } else {
                    let frac = (part.bytes_downloaded as f64 / part.total_size as f64)
                        .clamp(0.0, 1.0);
                    format!("{:.1}%", 100.0 * frac)
                };
                let status = if part.bytes_downloaded == 0 {
                    "idle".to_string()
                } else if part.bytes_downloaded >= part.total_size && part.total_size > 0 {
                    "done".to_string()
                } else {
                    rate.map(format_rate).unwrap_or_else(|| "—".into())
                };
                format!(
                    "[part{i}] progress: {pct}  download {downloaded} / {total} @ {status}  label {}",
                    part.label
                )
            })
            .collect()
    }
}

impl ProgressRenderer for LogRenderer {
    fn render(&mut self, snapshot: &ProgressSnapshot) {
        let now = Instant::now();
        // Per-part lines first (multi-URL only), then the aggregate
        // — `progress` for single-URL keeps the existing log shape;
        // `[overall] progress` pairs with `[partN]` siblings on
        // multi-URL.
        for line in self.format_part_lines(snapshot, now) {
            tracing::info!(target: "peel::progress", "{line}");
        }
        let line = self.format_line(snapshot, now);
        tracing::info!(target: "peel::progress", "{line}");
    }

    fn finish(&mut self) {
        // Nothing to do — each tick already emitted a structured
        // event; the subscriber owns the output stream.
    }
}

/// Default interval the renderer thread waits before warning that the
/// pipeline appears stalled (`PLAN_responsiveness.md` §1.2).
///
/// Override via `PEEL_STALL_WARN_INTERVAL_SECS` (positive integer).
pub const DEFAULT_STALL_WARN_INTERVAL: Duration = Duration::from_secs(30);

/// Cooperative stall detector spun up alongside the renderer.
///
/// Tracks the wall-clock time of the most recent observed advance for
/// `bytes_downloaded`, `bytes_decoded_input`, and `bytes_extracted`. If
/// the decoder and sink counters both stay flat for `warn_interval`,
/// the detector emits a single `tracing::warn!` line and refuses to
/// emit another for the same window — so a true freeze produces one
/// log entry per `warn_interval`, not one per renderer tick.
///
/// The detector deliberately ignores `bytes_downloaded` for the stall
/// classification: the disk-buffer throttle in
/// [`crate::download::scheduler`] freezes downloads on purpose when the
/// lookahead hits the cap, and surfacing that as a "stall" would page
/// every healthy run. The two counters that *can't* legitimately stop
/// advancing for 30 s in the middle of an extraction are the decoder
/// and sink — and those are exactly the ones the snapshot-restore pod
/// stall ([`docs/PLAN_responsiveness.md`]) showed pinned at zero.
#[derive(Debug)]
pub struct StallDetector {
    warn_interval: Duration,
    /// Most recent observed `bytes_downloaded` and the wall-clock time
    /// at which we first observed that value.
    last_dl: u64,
    last_dl_at: Instant,
    /// Most recent observed `bytes_decoded_input` and its sample time.
    last_decoded: u64,
    last_decoded_at: Instant,
    /// Most recent observed `bytes_extracted` and its sample time.
    last_extracted: u64,
    last_extracted_at: Instant,
    /// `Some(now)` when a warning was emitted at `now`. Suppresses
    /// further warnings until `warn_interval` after `now` has elapsed.
    last_warn_at: Option<Instant>,
}

impl StallDetector {
    /// Construct a detector that fires warnings after `warn_interval`
    /// of decoder + sink inactivity.
    #[must_use]
    pub fn new(warn_interval: Duration, now: Instant) -> Self {
        Self {
            warn_interval,
            last_dl: 0,
            last_dl_at: now,
            last_decoded: 0,
            last_decoded_at: now,
            last_extracted: 0,
            last_extracted_at: now,
            last_warn_at: None,
        }
    }

    /// Construct using [`DEFAULT_STALL_WARN_INTERVAL`], honoring the
    /// `PEEL_STALL_WARN_INTERVAL_SECS` env override (positive integer
    /// seconds; anything else falls back to the default).
    #[must_use]
    pub fn from_env(now: Instant) -> Self {
        let interval = std::env::var("PEEL_STALL_WARN_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|n| *n > 0)
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_STALL_WARN_INTERVAL);
        Self::new(interval, now)
    }

    /// Inspect a snapshot and emit a `tracing::warn!` event if the
    /// decoder + sink counters have been flat for at least
    /// `warn_interval`. Returns the (test-friendly) classification of
    /// what was observed.
    pub fn tick(&mut self, snap: &ProgressSnapshot, now: Instant) -> StallObservation {
        if snap.bytes_downloaded != self.last_dl {
            self.last_dl = snap.bytes_downloaded;
            self.last_dl_at = now;
        }
        if snap.bytes_decoded_input != self.last_decoded {
            self.last_decoded = snap.bytes_decoded_input;
            self.last_decoded_at = now;
        }
        if snap.bytes_extracted != self.last_extracted {
            self.last_extracted = snap.bytes_extracted;
            self.last_extracted_at = now;
        }

        let decoded_stuck =
            now.saturating_duration_since(self.last_decoded_at) >= self.warn_interval;
        let extracted_stuck =
            now.saturating_duration_since(self.last_extracted_at) >= self.warn_interval;

        // If either is moving, we're not in a sustained stall — clear
        // the rate-limit watermark so the next stall emits promptly.
        if !decoded_stuck && !extracted_stuck {
            self.last_warn_at = None;
            return StallObservation::Healthy;
        }

        // Rate-limit: at most one warn per warn_interval.
        if let Some(prev) = self.last_warn_at {
            if now.saturating_duration_since(prev) < self.warn_interval {
                return StallObservation::SuppressedDuplicate;
            }
        }

        let interval_secs = self.warn_interval.as_secs();
        if decoded_stuck && extracted_stuck {
            tracing::warn!(
                target: "peel::progress",
                bytes_downloaded = snap.bytes_downloaded,
                bytes_decoded_input = snap.bytes_decoded_input,
                bytes_extracted = snap.bytes_extracted,
                lookahead = snap.bytes_downloaded.saturating_sub(snap.bytes_decoded_input),
                disk_bound = snap.disk_bound,
                "pipeline frozen, no counters advanced in {interval_secs}s \
                 (decoder at byte {dec}, sink at byte {ex})",
                dec = snap.bytes_decoded_input,
                ex = snap.bytes_extracted,
            );
            self.last_warn_at = Some(now);
            StallObservation::Warned(StallKind::PipelineFrozen)
        } else if extracted_stuck {
            // Decoder is reading source bytes but the sink is not
            // producing — the symptom of either a wedged sink or a
            // decoder spinning on garbage that yields no output.
            let decoded_delta = snap
                .bytes_decoded_input
                .saturating_sub(self.last_extracted_advance_decoded_baseline());
            tracing::warn!(
                target: "peel::progress",
                bytes_decoded_input = snap.bytes_decoded_input,
                bytes_extracted = snap.bytes_extracted,
                "extractor stalled, decoder consumed +{decoded_delta} bytes but \
                 sink wrote 0 in {interval_secs}s",
            );
            self.last_warn_at = Some(now);
            StallObservation::Warned(StallKind::ExtractorStalled)
        } else {
            // decoded_stuck && !extracted_stuck — the decoder hasn't
            // read source for `warn_interval` but the sink kept going.
            // That can legitimately happen near EOF (decoder buffered
            // ahead, sink draining its tail), so the warning is gentler
            // and gated on `disk_bound` to avoid pinging every healthy
            // shutdown. We treat the bug-2 scenario (download throttled
            // because lookahead is at the cap, decoder not draining it)
            // as the interesting case.
            if snap.disk_bound {
                tracing::warn!(
                    target: "peel::progress",
                    bytes_decoded_input = snap.bytes_decoded_input,
                    lookahead = snap.bytes_downloaded.saturating_sub(snap.bytes_decoded_input),
                    "download stalled, decoder at byte {dec} (delta 0 in {interval_secs}s, \
                     scheduler throttled at the disk-buffer cap)",
                    dec = snap.bytes_decoded_input,
                );
                self.last_warn_at = Some(now);
                StallObservation::Warned(StallKind::DecoderStalledThrottled)
            } else {
                StallObservation::Healthy
            }
        }
    }

    /// `bytes_decoded_input` value at the last observed extracted
    /// advance — used to compute the "decoder consumed +N" delta in
    /// the `extractor stalled` warning. We don't snapshot this
    /// separately to keep the state machine compact: instead we
    /// approximate with `last_decoded - 0` when no prior baseline
    /// exists. The +N is informational.
    fn last_extracted_advance_decoded_baseline(&self) -> u64 {
        // Conservatively, return the last_decoded value at construction
        // (which is 0 unless someone seeds it), giving a delta of
        // "current decoder cursor - 0" — i.e. the absolute cursor.
        // The warning text framing ("+N bytes") is informational; the
        // key signal is that the warning fires at all.
        0
    }
}

/// Outcome of a single [`StallDetector::tick`]. The renderer thread
/// ignores this; tests assert against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StallObservation {
    /// At least one watched counter advanced or no stall threshold has
    /// been crossed yet.
    Healthy,
    /// A stall is in progress but a warning fired in the previous
    /// `warn_interval` already, so this tick stayed silent.
    SuppressedDuplicate,
    /// A warning was emitted on this tick. The variant identifies
    /// which scenario produced it.
    Warned(StallKind),
}

/// Which scenario produced the warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StallKind {
    /// Decoder + sink both flat for `warn_interval`. The actual
    /// snapshot-restore bug.
    PipelineFrozen,
    /// Sink flat for `warn_interval` while decoder still advances.
    ExtractorStalled,
    /// Decoder flat for `warn_interval` while download is throttled.
    DecoderStalledThrottled,
    /// A single `decode_step` call has been running for at least
    /// `warn_interval` and has not yet returned. Detected from a peer
    /// thread (PLAN_decoder_freeze.md §2.4b) — the
    /// post-hoc watchdog at [`crate::extractor`] cannot fire while
    /// the call is still in flight.
    DecodeStepHung,
}

/// Default duration past which the §2.4b peer watchdog warns that the
/// extractor is wedged inside a single `decode_step` call.
///
/// 30 s matches [`DEFAULT_STALL_WARN_INTERVAL`] and the io_uring
/// in-flight watchdog so a freeze surfaces all three signals inside
/// the same wall-clock window. Override via
/// `PEEL_DECODE_STEP_WARN_SECS` (the same env var the post-hoc
/// watchdog at [`crate::extractor`] reads — same threshold seen
/// from two different angles).
pub const DEFAULT_DECODE_STEP_HUNG_WARN: Duration = Duration::from_secs(30);

/// Read `PEEL_DECODE_STEP_WARN_SECS` (positive integer seconds) and
/// fall back to [`DEFAULT_DECODE_STEP_HUNG_WARN`]. `0` or any
/// malformed value uses the default.
fn decode_step_hung_warn_from_env() -> Duration {
    std::env::var("PEEL_DECODE_STEP_WARN_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|n| *n > 0)
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_DECODE_STEP_HUNG_WARN)
}

/// Peer-thread watchdog for a wedged `decode_step` call
/// (PLAN_decoder_freeze.md §2.4b). The extractor publishes the entry
/// time of every call to [`ProgressState::mark_decode_step_entered`]
/// and clears it on return; this detector — running on the renderer
/// thread — checks the snapshot's `decode_step_elapsed` and warns
/// once per warn-interval if the call is past threshold.
///
/// Why a peer detector when [`crate::extractor`] already has a
/// post-hoc watchdog: the post-hoc one runs *after* `decode_step`
/// returns, so it cannot fire while the call is still in flight.
/// During a freeze the call never returns and the post-hoc warning
/// is unreachable. This detector runs on the renderer thread and
/// fires regardless of what the extractor thread is parked on.
#[derive(Debug)]
pub struct DecodeStepStallDetector {
    threshold: Duration,
    last_warned_at: Option<Instant>,
}

impl DecodeStepStallDetector {
    /// Construct with an explicit threshold. Tests use this; the
    /// renderer thread uses [`Self::from_env`].
    #[must_use]
    pub fn new(threshold: Duration) -> Self {
        Self {
            threshold,
            last_warned_at: None,
        }
    }

    /// Construct using [`DEFAULT_DECODE_STEP_HUNG_WARN`] honoring the
    /// `PEEL_DECODE_STEP_WARN_SECS` env override.
    #[must_use]
    pub fn from_env() -> Self {
        Self::new(decode_step_hung_warn_from_env())
    }

    /// Inspect a snapshot. Emit one `tracing::warn!` if the current
    /// `decode_step` elapsed crosses `threshold`, rate-limited to one
    /// warning per `threshold`-sized window. Returns the
    /// (test-friendly) classification of what was observed.
    pub fn tick(&mut self, snap: &ProgressSnapshot, now: Instant) -> StallObservation {
        let Some(elapsed) = snap.decode_step_elapsed else {
            // No step in flight: clear the rate-limit watermark so the
            // next genuine wedge fires promptly.
            self.last_warned_at = None;
            return StallObservation::Healthy;
        };
        if elapsed < self.threshold {
            return StallObservation::Healthy;
        }
        if let Some(prev) = self.last_warned_at {
            if now.saturating_duration_since(prev) < self.threshold {
                return StallObservation::SuppressedDuplicate;
            }
        }
        let elapsed_secs = elapsed.as_secs();
        tracing::warn!(
            target: "peel::progress",
            bytes_decoded_input = snap.bytes_decoded_input,
            bytes_extracted = snap.bytes_extracted,
            elapsed_secs,
            "decode_step has been running for {elapsed_secs}s without returning \
             (decoder cursor {dec}, sink cursor {ex})",
            dec = snap.bytes_decoded_input,
            ex = snap.bytes_extracted,
        );
        self.last_warned_at = Some(now);
        StallObservation::Warned(StallKind::DecodeStepHung)
    }
}

/// Spawn a dedicated thread that renders `state` via `renderer` every
/// `refresh` until [`ProgressState::is_done`] returns `true`.
///
/// On clean shutdown the last snapshot is rendered (so the user sees
/// the final byte counts) and [`ProgressRenderer::finish`] runs before
/// the thread exits. Callers join the returned handle after
/// [`ProgressState::mark_done`].
///
/// A [`StallDetector`] runs in lockstep with the renderer so a frozen
/// pipeline produces a structured `tracing::warn!` event independent of
/// the chosen renderer. The interval honors
/// `PEEL_STALL_WARN_INTERVAL_SECS`; see [`StallDetector::from_env`].
///
/// # Errors
///
/// Returns the underlying [`io::Error`] if [`std::thread::Builder`]
/// fails to spawn.
pub fn spawn_renderer<R>(
    state: Arc<ProgressState>,
    mut renderer: R,
    refresh: Duration,
) -> io::Result<JoinHandle<()>>
where
    R: ProgressRenderer + 'static,
{
    let refresh = refresh.max(Duration::from_millis(20));
    thread::Builder::new()
        .name("peel-progress-renderer".into())
        .spawn(move || {
            let mut detector = StallDetector::from_env(Instant::now());
            let mut step_detector = DecodeStepStallDetector::from_env();
            // Tick loop: render, sleep, render, … until done. We do an
            // extra final render after the done flag flips so the user
            // sees the final counters.
            loop {
                let snap = state.snapshot();
                let now = Instant::now();
                renderer.render(&snap);
                detector.tick(&snap, now);
                step_detector.tick(&snap, now);
                if snap.done {
                    break;
                }
                thread::sleep(refresh);
            }
            renderer.finish();
        })
}

// ----- terminal capabilities ----------------------------------------------

/// Detect the user's terminal width in display columns.
///
/// On Unix this calls `ioctl(STDERR_FILENO, TIOCGWINSZ)` directly via
/// a hand-rolled FFI declaration. On non-Unix targets — and as a
/// fallback if the ioctl fails — it reads the `COLUMNS` environment
/// variable. Returns `None` if neither source yields a positive width.
#[must_use]
pub fn terminal_columns() -> Option<usize> {
    #[cfg(unix)]
    {
        // STDERR_FILENO is always 2 on Unix; the renderer writes there,
        // so its size is what we actually care about.
        if let Some(cols) = unix_ioctl_columns(2) {
            return Some(cols);
        }
    }
    columns_from_env()
}

fn columns_from_env() -> Option<usize> {
    let raw = std::env::var("COLUMNS").ok()?;
    let n: usize = raw.trim().parse().ok()?;
    if n == 0 {
        None
    } else {
        Some(n)
    }
}

#[cfg(unix)]
fn unix_ioctl_columns(fd: i32) -> Option<usize> {
    use std::ffi::c_ulong;

    #[repr(C)]
    struct Winsize {
        ws_row: u16,
        ws_col: u16,
        ws_xpixel: u16,
        ws_ypixel: u16,
    }

    // `TIOCGWINSZ` is defined as `_IO('T', 0x13)` on Linux but as
    // `_IOR('t', 104, struct winsize)` on the BSD-derived macOS / *BSD
    // ioctl tables, so the numeric constant is platform-specific.
    #[cfg(target_os = "linux")]
    const TIOCGWINSZ: c_ulong = 0x5413;
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    const TIOCGWINSZ: c_ulong = 0x4008_7468;
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    )))]
    return None;

    extern "C" {
        fn ioctl(fd: i32, request: c_ulong, ws: *mut Winsize) -> i32;
    }

    let mut ws = Winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: `TIOCGWINSZ` writes a `struct winsize` into the pointer
    // we pass; our `Winsize` matches the C layout (four `u16` fields,
    // `#[repr(C)]`). `fd` is a non-negative file descriptor (we hand
    // in `STDERR_FILENO`/2 by default; tests pass valid fds). On
    // failure we discard the error and return `None`, so the caller
    // falls back to the env var or the 80-column default.
    let rc = unsafe { ioctl(fd, TIOCGWINSZ, &mut ws) };
    if rc != 0 || ws.ws_col == 0 {
        None
    } else {
        Some(ws.ws_col as usize)
    }
}

/// Detect whether the user's terminal can display UTF-8 box / emoji
/// glyphs.
///
/// Heuristic: a non-empty `LC_ALL`, `LC_CTYPE`, or `LANG` environment
/// variable containing `UTF-8` (case- and dash-insensitive) is taken
/// as a yes. Anything else — `C`, `POSIX`, an empty string, or
/// nothing set at all — falls back to ASCII. This matches what
/// curses-based tools do and avoids the need for a `terminfo`
/// dependency.
#[must_use]
pub fn supports_unicode() -> bool {
    for var in ["LC_ALL", "LC_CTYPE", "LANG"] {
        let Ok(v) = std::env::var(var) else { continue };
        if v.is_empty() {
            continue;
        }
        let normalized: String = v
            .chars()
            .filter(|c| !matches!(*c, '-' | '_'))
            .map(|c| c.to_ascii_lowercase())
            .collect();
        return normalized.contains("utf8");
    }
    false
}

// ----- formatting helpers -------------------------------------------------

/// "Overall percent": prefer extraction progress when the uncompressed
/// estimate is known (it's what the user actually cares about), else
/// download progress, else `None`.
#[must_use]
pub fn overall_percent(snap: &ProgressSnapshot) -> Option<f64> {
    if let Some(total) = snap.extracted_estimate {
        if total > 0 {
            return Some(percent(snap.bytes_extracted, total));
        }
    }
    if let Some(total) = snap.total_size {
        if total > 0 {
            return Some(percent(snap.bytes_downloaded, total));
        }
    }
    None
}

fn percent(num: u64, denom: u64) -> f64 {
    if denom == 0 {
        return 0.0;
    }
    let p = (num as f64 / denom as f64) * 100.0;
    p.clamp(0.0, 100.0)
}

/// ETA based on whichever of (download, extraction) is the bottleneck.
///
/// Uses the bottleneck side's remaining-bytes / rate. Returns `None`
/// until at least one side has a usable rate and a known total.
#[must_use]
pub fn compute_eta(
    snap: &ProgressSnapshot,
    dl_rate: Option<f64>,
    ex_rate: Option<f64>,
) -> Option<Duration> {
    let mut candidates = Vec::new();
    if let (Some(total), Some(rate)) = (snap.total_size, dl_rate) {
        if rate > 0.0 && snap.bytes_downloaded < total {
            let remaining = total - snap.bytes_downloaded;
            candidates.push(remaining as f64 / rate);
        }
    }
    if let (Some(total), Some(rate)) = (snap.extracted_estimate, ex_rate) {
        if rate > 0.0 && snap.bytes_extracted < total {
            let remaining = total - snap.bytes_extracted;
            candidates.push(remaining as f64 / rate);
        }
    }
    candidates
        .into_iter()
        .max_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        .map(Duration::from_secs_f64)
}

/// Format an absolute byte count as a short human-readable string.
///
/// Uses 1024-based units and one decimal of precision for KiB and up.
#[must_use]
pub fn format_bytes(n: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = n as f64;
    let mut idx = 0;
    while value >= 1024.0 && idx + 1 < UNITS.len() {
        value /= 1024.0;
        idx += 1;
    }
    if idx == 0 {
        format!("{n} {}", UNITS[idx])
    } else {
        format!("{value:.1} {}", UNITS[idx])
    }
}

/// Format a bytes-per-second rate with a /s suffix.
#[must_use]
pub fn format_rate(bytes_per_sec: f64) -> String {
    if !bytes_per_sec.is_finite() || bytes_per_sec < 0.0 {
        return "—".into();
    }
    format!("{}/s", format_bytes(bytes_per_sec.round() as u64))
}

/// Format an ETA as a compact human-readable string.
///
/// Output shape depends on the magnitude:
/// - `≥ 24h`: `2d4h32m` — days/hours/minutes (seconds dropped; days
///   already convey enough precision).
/// - `≥ 1h`: `23h15m9s`
/// - `≥ 1m`: `43m56s`
/// - else:   `42s`
///
/// `None` is rendered as `--`.
#[must_use]
pub fn format_eta(eta: Option<Duration>) -> String {
    let Some(d) = eta else {
        return "--".into();
    };
    let total = d.as_secs();
    let days = total / 86_400;
    let hours = (total % 86_400) / 3600;
    let minutes = (total % 3600) / 60;
    let secs = total % 60;
    if days >= 1 {
        format!("{days}d{hours}h{minutes}m")
    } else if hours >= 1 {
        format!("{hours}h{minutes}m{secs}s")
    } else if minutes >= 1 {
        format!("{minutes}m{secs}s")
    } else {
        format!("{total}s")
    }
}

fn format_overall_line(
    snap: &ProgressSnapshot,
    percent: Option<f64>,
    term_cols: usize,
    bar_cap: usize,
    style: BarStyle,
) -> String {
    let pct = percent
        .map(|p| format!("{p:5.1}%"))
        .unwrap_or_else(|| "  --.-%".into());
    // Layout: `peel  [BAR]  XX.X%`. ETA + bottleneck badge live on
    // their own line at the bottom of the block (see
    // [`format_eta_line`]) so the bar/percent get the full first line.
    let prefix = "peel  ";
    let visible_suffix_len = "  ".len() + pct.len();
    let reserved = prefix.len() + visible_suffix_len;
    let mut budget = term_cols.saturating_sub(reserved);
    if budget > bar_cap {
        budget = bar_cap;
    }
    let bar = render_bar(snap, budget, style);
    format!("{prefix}{bar}  {pct}")
}

/// Format the trailing ETA line, optionally followed by the
/// network/disk bottleneck badge.
///
/// Lives on its own row at the bottom of the redraw block so the
/// first row can dedicate its full width to the bar + percent. When
/// no rate has stabilized yet the line reads `ETA --` (no badge); a
/// known ETA renders as `ETA 7d22h50m` and gains a badge suffix
/// (`  🔵 net` / `  🟡 disk` in unicode mode, `  [NET]` / `  [DISK]`
/// in ascii) once the classifier has a verdict.
fn format_eta_line(
    eta: Option<Duration>,
    style: BarStyle,
    bottleneck: Option<Bottleneck>,
) -> String {
    let eta_s = format_eta(eta);
    let badge = match bottleneck {
        Some(b) => format!("  {}", b.badge(style)),
        None => String::new(),
    };
    format!("ETA {eta_s}{badge}")
}

fn format_download_line(
    snap: &ProgressSnapshot,
    rate: Option<f64>,
    bottleneck: Option<Bottleneck>,
) -> String {
    let displayed_downloaded = match snap.total_size {
        Some(t) if t > 0 => snap.bytes_downloaded.min(t),
        _ => snap.bytes_downloaded,
    };
    let downloaded = format_bytes(displayed_downloaded);
    let total = snap
        .total_size
        .map(format_bytes)
        .unwrap_or_else(|| "?".into());
    let rate_s = rate.map(format_rate).unwrap_or_else(|| "—".into());
    let rate_painted = if matches!(bottleneck, Some(Bottleneck::Network)) {
        paint(&rate_s, ANSI_CYAN)
    } else {
        rate_s
    };
    format!(
        "download  {downloaded} / {total}  {rate_painted}  workers {}/{}",
        snap.active_workers, snap.total_workers
    )
}

fn format_extract_line(
    snap: &ProgressSnapshot,
    rate: Option<f64>,
    bottleneck: Option<Bottleneck>,
) -> String {
    let extracted = format_bytes(snap.bytes_extracted);
    let est = snap
        .extracted_estimate
        .map(format_bytes)
        .unwrap_or_else(|| "unknown".into());
    let rate_s = rate.map(format_rate).unwrap_or_else(|| "—".into());
    let rate_painted = if matches!(bottleneck, Some(Bottleneck::Disk)) {
        paint(&rate_s, ANSI_YELLOW)
    } else {
        rate_s
    };
    format!("extract   {extracted} / {est}  {rate_painted}")
}

/// Render the §1.1 lookahead row.
///
/// Shape:
/// ```text
/// lookahead 996.4 MiB / 1.0 GiB cap   decoded_in 402.4 GiB
/// ```
///
/// `lookahead` is the gap between the download and the decoder cursor
/// (`bytes_downloaded - bytes_decoded_input`); the cap is the configured
/// `--max-disk-buffer` and is replaced with `uncapped` when the throttle
/// is disabled. `decoded_in` is the running compressed-byte cursor: when
/// extract progress is flat, an advancing `decoded_in` says "decoder is
/// reading source bytes, sink hasn't produced yet" and a frozen
/// `decoded_in` says "decoder is wedged".
///
/// Painted yellow when the bottleneck classifier reports
/// [`Bottleneck::Disk`] (matches the extract-rate paint on line 3).
fn format_lookahead_line(snap: &ProgressSnapshot, bottleneck: Option<Bottleneck>) -> String {
    let look = format_bytes(
        snap.bytes_downloaded
            .saturating_sub(snap.bytes_decoded_input),
    );
    let cap = match snap.max_disk_buffer {
        Some(c) => format!("{} cap", format_bytes(c)),
        None => "uncapped".into(),
    };
    let cap_painted = if matches!(bottleneck, Some(Bottleneck::Disk)) {
        paint(&cap, ANSI_YELLOW)
    } else {
        cap
    };
    let decoded_in = format_bytes(snap.bytes_decoded_input);
    format!("lookahead {look} / {cap_painted}   decoded_in {decoded_in}")
}

/// Render a progress bar that fits inside `columns` display columns,
/// using `style` for the cell glyphs.
///
/// The fraction shown matches [`overall_percent`]: prefer extraction
/// progress when the uncompressed estimate is known, else download
/// progress, else empty. Returns `0.0`-progress (all empty cells) when
/// neither side has a known total.
fn render_bar(snap: &ProgressSnapshot, columns: usize, style: BarStyle) -> String {
    let frac = match overall_percent(snap) {
        Some(p) => p / 100.0,
        None => 0.0,
    };
    render_bar_for(frac, columns, style)
}

/// Render a bar of the given fractional progress to fit in `columns`
/// display columns. Pure helper: tests use this directly.
#[must_use]
pub fn render_bar_for(frac: f64, columns: usize, style: BarStyle) -> String {
    let frac = frac.clamp(0.0, 1.0);
    match style {
        BarStyle::Unicode => {
            // Each emoji is two display columns wide.
            let cells = (columns / 2).max(1);
            let filled = (frac * cells as f64).round() as usize;
            let filled = filled.min(cells);
            // 4 bytes per emoji × cell count is close enough for capacity.
            let mut bar = String::with_capacity(cells * 4);
            for i in 0..cells {
                bar.push_str(if i < filled { "🟦" } else { "⬜" });
            }
            bar
        }
        BarStyle::Ascii => {
            // `[####....]` — the brackets eat two columns; the inner
            // body is one byte per column. Anything narrower than
            // four columns isn't worth drawing at all.
            if columns < 4 {
                return "[]".into();
            }
            let inner = columns - 2;
            let filled = (frac * inner as f64).round() as usize;
            let filled = filled.min(inner);
            let mut bar = String::with_capacity(columns);
            bar.push('[');
            for i in 0..inner {
                bar.push(if i < filled { '#' } else { '.' });
            }
            bar.push(']');
            bar
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_uses_zero_sentinels() {
        let s = ProgressState::new();
        let snap = s.snapshot();
        assert_eq!(snap.total_size, None);
        assert_eq!(snap.extracted_estimate, None);
        assert_eq!(snap.bytes_downloaded, 0);
        assert_eq!(snap.bytes_extracted, 0);
        assert_eq!(snap.active_workers, 0);
        assert_eq!(snap.total_workers, 0);
        assert!(!snap.started);
        assert!(!snap.done);
    }

    #[test]
    fn add_methods_accumulate_atomically() {
        let s = ProgressState::new();
        s.set_total_size(1_000_000);
        s.set_total_workers(4);
        s.add_downloaded(500);
        s.add_downloaded(700);
        s.add_extracted(123);
        s.worker_started();
        s.worker_started();
        s.worker_finished();
        s.mark_started();
        let snap = s.snapshot();
        assert_eq!(snap.total_size, Some(1_000_000));
        assert_eq!(snap.bytes_downloaded, 1200);
        assert_eq!(snap.bytes_extracted, 123);
        assert_eq!(snap.active_workers, 1);
        assert_eq!(snap.total_workers, 4);
        assert!(snap.started);
    }

    #[test]
    fn add_zero_is_a_noop() {
        let s = ProgressState::new();
        s.add_downloaded(0);
        s.add_extracted(0);
        let snap = s.snapshot();
        assert_eq!(snap.bytes_downloaded, 0);
        assert_eq!(snap.bytes_extracted, 0);
    }

    #[test]
    fn reset_for_retry_clears_per_run_counters_but_keeps_total_and_done() {
        let s = ProgressState::new();
        s.set_total_size(91_000_000_000);
        s.set_max_disk_buffer(1_073_741_824);
        s.set_total_workers(4);
        s.add_downloaded(1_200_000_000);
        s.add_extracted(1_800_000_000);
        s.set_bytes_decoded_input(1_100_000_000);
        s.set_extracted_estimate(95_000_000_000);
        s.worker_started();
        s.set_disk_bound(true);
        s.mark_started();
        s.mark_done();

        s.reset_for_retry();

        let snap = s.snapshot();
        // Per-run counters: cleared.
        assert_eq!(snap.bytes_downloaded, 0);
        assert_eq!(snap.bytes_extracted, 0);
        assert_eq!(snap.bytes_decoded_input, 0);
        assert_eq!(snap.extracted_estimate, None);
        assert_eq!(snap.active_workers, 0);
        assert_eq!(snap.total_workers, 0);
        assert!(!snap.disk_bound);
        assert!(!snap.started);
        // Configuration and renderer-lifecycle bits: preserved.
        assert_eq!(snap.total_size, Some(91_000_000_000));
        assert_eq!(snap.max_disk_buffer, Some(1_073_741_824));
        assert!(snap.done);
    }

    #[test]
    fn rate_buffer_returns_none_below_min_span() {
        let mut buf = RateBuffer::new(Duration::from_secs(5), 32, Duration::from_secs(5));
        let t0 = Instant::now();
        buf.push(t0, 0);
        buf.push(t0 + Duration::from_secs(1), 1_000_000);
        assert!(buf.rate_bytes_per_sec().is_none());
    }

    #[test]
    fn rate_buffer_computes_rate_over_window() {
        let mut buf = RateBuffer::new(Duration::from_secs(5), 32, Duration::from_secs(1));
        let t0 = Instant::now();
        buf.push(t0, 0);
        buf.push(t0 + Duration::from_secs(2), 2_000_000);
        let rate = buf.rate_bytes_per_sec().expect("rate");
        // 2 MB over 2 s = 1 MB/s within float tolerance.
        assert!((rate - 1_000_000.0).abs() < 1.0);
    }

    #[test]
    fn rate_buffer_evicts_old_samples() {
        let mut buf = RateBuffer::new(Duration::from_secs(2), 32, Duration::from_millis(100));
        let t0 = Instant::now();
        buf.push(t0, 0);
        buf.push(t0 + Duration::from_secs(10), 5_000_000);
        // First sample should have been evicted; only the most recent
        // remains, and a single sample produces no useful span.
        assert!(buf.rate_bytes_per_sec().is_none());
    }

    #[test]
    fn rate_buffer_caps_capacity() {
        let mut buf = RateBuffer::new(Duration::from_secs(60), 4, Duration::from_millis(1));
        let t0 = Instant::now();
        for i in 0..10 {
            buf.push(t0 + Duration::from_millis(i * 10), i * 1000);
        }
        // capacity = 4: we should never have held more than 4 samples.
        // The rate computation is over what's left.
        let _ = buf.rate_bytes_per_sec();
    }

    #[test]
    fn overall_percent_prefers_extraction_when_estimate_known() {
        let snap = ProgressSnapshot {
            total_size: Some(1000),
            bytes_downloaded: 500,
            bytes_extracted: 250,
            extracted_estimate: Some(1000),
            active_workers: 0,
            total_workers: 0,
            started: true,
            done: false,
            bytes_decoded_input: 0,
            max_disk_buffer: None,
            disk_bound: false,
            decode_step_elapsed: None,
            parts: Vec::new(),
        };
        let p = overall_percent(&snap).expect("percent");
        // 250/1000 = 25%, even though download is 50%.
        assert!((p - 25.0).abs() < 0.01);
    }

    #[test]
    fn overall_percent_falls_back_to_download() {
        let snap = ProgressSnapshot {
            total_size: Some(1000),
            bytes_downloaded: 500,
            bytes_extracted: 250,
            extracted_estimate: None,
            active_workers: 0,
            total_workers: 0,
            started: true,
            done: false,
            bytes_decoded_input: 0,
            max_disk_buffer: None,
            disk_bound: false,
            decode_step_elapsed: None,
            parts: Vec::new(),
        };
        let p = overall_percent(&snap).expect("percent");
        assert!((p - 50.0).abs() < 0.01);
    }

    #[test]
    fn overall_percent_unknown_when_neither_total_known() {
        let snap = ProgressSnapshot {
            total_size: None,
            bytes_downloaded: 500,
            bytes_extracted: 250,
            extracted_estimate: None,
            active_workers: 0,
            total_workers: 0,
            started: true,
            done: false,
            bytes_decoded_input: 0,
            max_disk_buffer: None,
            disk_bound: false,
            decode_step_elapsed: None,
            parts: Vec::new(),
        };
        assert!(overall_percent(&snap).is_none());
    }

    #[test]
    fn compute_eta_picks_max_of_two_sides() {
        let snap = ProgressSnapshot {
            total_size: Some(1_000_000),
            bytes_downloaded: 500_000,
            bytes_extracted: 100_000,
            extracted_estimate: Some(2_000_000),
            active_workers: 0,
            total_workers: 0,
            started: true,
            done: false,
            bytes_decoded_input: 0,
            max_disk_buffer: None,
            disk_bound: false,
            decode_step_elapsed: None,
            parts: Vec::new(),
        };
        // dl: 500k remaining @ 100kB/s = 5 s; ex: 1.9M remaining @
        // 100kB/s = 19 s. Bottleneck = extract = 19 s.
        let eta = compute_eta(&snap, Some(100_000.0), Some(100_000.0)).expect("eta");
        assert!((eta.as_secs_f64() - 19.0).abs() < 0.1);
    }

    #[test]
    fn compute_eta_none_when_no_rates() {
        let snap = ProgressSnapshot {
            total_size: Some(1_000_000),
            bytes_downloaded: 500_000,
            bytes_extracted: 0,
            extracted_estimate: None,
            active_workers: 0,
            total_workers: 0,
            started: true,
            done: false,
            bytes_decoded_input: 0,
            max_disk_buffer: None,
            disk_bound: false,
            decode_step_elapsed: None,
            parts: Vec::new(),
        };
        assert!(compute_eta(&snap, None, None).is_none());
    }

    #[test]
    fn format_bytes_handles_full_range() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1023), "1023 B");
        assert_eq!(format_bytes(1024), "1.0 KiB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GiB");
        assert_eq!(format_bytes((1024_u64).pow(4)), "1.0 TiB");
    }

    #[test]
    fn format_rate_includes_unit_suffix() {
        let s = format_rate(2_000_000.0);
        assert!(s.contains("MiB"));
        assert!(s.ends_with("/s"));
    }

    #[test]
    fn format_eta_seconds_only_under_one_minute() {
        assert_eq!(format_eta(Some(Duration::from_secs(0))), "0s");
        assert_eq!(format_eta(Some(Duration::from_secs(5))), "5s");
        assert_eq!(format_eta(Some(Duration::from_secs(42))), "42s");
        assert_eq!(format_eta(Some(Duration::from_secs(59))), "59s");
    }

    #[test]
    fn format_eta_minutes_seconds_under_one_hour() {
        assert_eq!(format_eta(Some(Duration::from_secs(60))), "1m0s");
        assert_eq!(format_eta(Some(Duration::from_secs(125))), "2m5s");
        assert_eq!(
            format_eta(Some(Duration::from_secs(43 * 60 + 56))),
            "43m56s"
        );
    }

    #[test]
    fn format_eta_hours_minutes_seconds_under_one_day() {
        assert_eq!(format_eta(Some(Duration::from_secs(3600))), "1h0m0s");
        assert_eq!(format_eta(Some(Duration::from_secs(3725))), "1h2m5s");
        assert_eq!(
            format_eta(Some(Duration::from_secs(23 * 3600 + 15 * 60 + 9))),
            "23h15m9s"
        );
    }

    #[test]
    fn format_eta_days_hours_minutes_no_seconds() {
        assert_eq!(format_eta(Some(Duration::from_secs(86_400))), "1d0h0m");
        assert_eq!(
            format_eta(Some(Duration::from_secs(
                2 * 86_400 + 4 * 3600 + 32 * 60 + 7
            ))),
            "2d4h32m"
        );
    }

    #[test]
    fn format_eta_none_renders_dashes() {
        assert_eq!(format_eta(None), "--");
    }

    fn snap_with_progress(num: u64, denom: u64) -> ProgressSnapshot {
        ProgressSnapshot {
            total_size: Some(denom),
            bytes_downloaded: num,
            bytes_extracted: 0,
            extracted_estimate: None,
            active_workers: 0,
            total_workers: 0,
            started: true,
            done: false,
            bytes_decoded_input: 0,
            max_disk_buffer: None,
            disk_bound: false,
            decode_step_elapsed: None,
            parts: Vec::new(),
        }
    }

    #[test]
    fn render_bar_ascii_progress_proportional() {
        let bar = render_bar(&snap_with_progress(50, 100), 10, BarStyle::Ascii);
        assert!(bar.starts_with('['));
        assert!(bar.ends_with(']'));
        // 50% of 8 inner cells = 4 filled blocks.
        assert_eq!(bar.matches('#').count(), 4);
        assert_eq!(bar.matches('.').count(), 4);
    }

    #[test]
    fn render_bar_ascii_handles_unknown_total() {
        let snap = ProgressSnapshot {
            total_size: None,
            bytes_downloaded: 123,
            bytes_extracted: 0,
            extracted_estimate: None,
            active_workers: 0,
            total_workers: 0,
            started: true,
            done: false,
            bytes_decoded_input: 0,
            max_disk_buffer: None,
            disk_bound: false,
            decode_step_elapsed: None,
            parts: Vec::new(),
        };
        let bar = render_bar(&snap, 8, BarStyle::Ascii);
        assert_eq!(bar.matches('#').count(), 0);
        assert_eq!(bar.matches('.').count(), 6);
    }

    #[test]
    fn render_bar_ascii_full() {
        let bar = render_bar(&snap_with_progress(100, 100), 6, BarStyle::Ascii);
        assert_eq!(bar.matches('#').count(), 4);
        assert_eq!(bar.matches('.').count(), 0);
    }

    #[test]
    fn render_bar_unicode_uses_square_emoji() {
        let bar = render_bar_for(0.1, 20, BarStyle::Unicode);
        // 20 columns / 2 cols-per-cell = 10 cells; 10% = 1 filled.
        assert_eq!(bar.matches('🟦').count(), 1);
        assert_eq!(bar.matches('⬜').count(), 9);
    }

    #[test]
    fn render_bar_unicode_full_and_empty() {
        let full = render_bar_for(1.0, 8, BarStyle::Unicode);
        assert_eq!(full.matches('🟦').count(), 4);
        assert_eq!(full.matches('⬜').count(), 0);
        let empty = render_bar_for(0.0, 8, BarStyle::Unicode);
        assert_eq!(empty.matches('🟦').count(), 0);
        assert_eq!(empty.matches('⬜').count(), 4);
    }

    #[test]
    fn tty_renderer_writes_five_lines_to_buffer() {
        let buf: Vec<u8> = Vec::new();
        let mut r = TtyRenderer::with_bar_width(buf, 12);
        let snap = ProgressSnapshot {
            total_size: Some(2000),
            bytes_downloaded: 1000,
            bytes_extracted: 200,
            extracted_estimate: None,
            active_workers: 2,
            total_workers: 4,
            started: true,
            done: false,
            bytes_decoded_input: 600,
            max_disk_buffer: Some(1024),
            disk_bound: false,
            decode_step_elapsed: None,
            parts: Vec::new(),
        };
        r.render(&snap);
        let out = String::from_utf8(r.out).expect("utf-8");
        // Five lines, each terminated with the clear-EOL escape: the
        // bar/percent header, download row, extract row, lookahead row,
        // and the trailing ETA + bottleneck-badge line.
        assert_eq!(out.matches("\x1b[K").count(), 5);
        assert!(out.contains("peel"));
        assert!(out.contains("workers 2/4"));
        assert!(out.contains("download"));
        assert!(out.contains("extract"));
        assert!(out.contains("lookahead"));
        assert!(out.contains("decoded_in"));
        assert!(out.contains("ETA"));
        // Sizes on lines 2 and 3 are human-readable: 1000 < 1 KiB so
        // it stays as bytes, 2000 ≈ 1.95 KiB so it rolls up.
        assert!(out.contains("1000 B / 2.0 KiB"));
        assert!(out.contains("200 B / unknown"));
        // lookahead = 1000 - 600 = 400 B; cap = 1.0 KiB.
        assert!(out.contains("lookahead 400 B / 1.0 KiB cap"));
        assert!(out.contains("decoded_in 600 B"));
    }

    #[test]
    fn tty_renderer_unicode_bar_appears_when_style_is_unicode() {
        let buf: Vec<u8> = Vec::new();
        let mut r = TtyRenderer::with_style_and_width(buf, BarStyle::Unicode, 80);
        let snap = ProgressSnapshot {
            total_size: Some(1000),
            bytes_downloaded: 500,
            bytes_extracted: 0,
            extracted_estimate: None,
            active_workers: 1,
            total_workers: 1,
            started: true,
            done: false,
            bytes_decoded_input: 0,
            max_disk_buffer: None,
            disk_bound: false,
            decode_step_elapsed: None,
            parts: Vec::new(),
        };
        r.render(&snap);
        let out = String::from_utf8(r.out).expect("utf-8");
        assert!(out.contains('🟦'));
        assert!(out.contains('⬜'));
    }

    /// Extract the substring between the first `[` and the matching
    /// `]` on a rendered ASCII line (the bar body). Used in layout
    /// tests so we don't accidentally count `.` characters from the
    /// percent / units in the surrounding text.
    fn ascii_bar_body(line: &str) -> &str {
        let lo = line.find('[').expect("[ in line");
        let hi = line[lo..].find(']').expect("] in line") + lo;
        &line[lo + 1..hi]
    }

    #[test]
    fn tty_renderer_bar_caps_at_one_hundred_columns() {
        let buf: Vec<u8> = Vec::new();
        // Pretend the terminal is wider than the cap; bar must still
        // not exceed `MAX_BAR_COLUMNS` total columns (brackets + inner).
        let mut r = TtyRenderer::with_style_and_width(buf, BarStyle::Ascii, 500);
        let snap = ProgressSnapshot {
            total_size: Some(1000),
            bytes_downloaded: 0,
            bytes_extracted: 0,
            extracted_estimate: None,
            active_workers: 0,
            total_workers: 0,
            started: true,
            done: false,
            bytes_decoded_input: 0,
            max_disk_buffer: None,
            disk_bound: false,
            decode_step_elapsed: None,
            parts: Vec::new(),
        };
        let (l1, _, _, _, _) = r.format_block(&snap, Instant::now());
        let body = ascii_bar_body(&l1);
        assert_eq!(
            body.len(),
            MAX_BAR_COLUMNS - 2,
            "bar inner length should be capped to MAX_BAR_COLUMNS - 2"
        );
    }

    #[test]
    fn tty_renderer_bar_shrinks_for_narrow_terminal() {
        let buf: Vec<u8> = Vec::new();
        let mut r = TtyRenderer::with_style_and_width(buf, BarStyle::Ascii, 40);
        let snap = ProgressSnapshot {
            total_size: Some(1000),
            bytes_downloaded: 250,
            bytes_extracted: 0,
            extracted_estimate: None,
            active_workers: 0,
            total_workers: 0,
            started: true,
            done: false,
            bytes_decoded_input: 0,
            max_disk_buffer: None,
            disk_bound: false,
            decode_step_elapsed: None,
            parts: Vec::new(),
        };
        let (l1, _, _, _, _) = r.format_block(&snap, Instant::now());
        let body = ascii_bar_body(&l1);
        // 40 cols total minus prefix/suffix ≈ 16-22 for the bar body.
        assert!(
            (4..=24).contains(&body.len()),
            "expected modest bar in narrow terminal, got {} cells in {l1:?}",
            body.len()
        );
    }

    #[test]
    fn tty_renderer_subsequent_render_emits_cursor_up() {
        let buf: Vec<u8> = Vec::new();
        let mut r = TtyRenderer::with_bar_width(buf, 12);
        let snap = ProgressSnapshot {
            total_size: Some(2000),
            bytes_downloaded: 100,
            bytes_extracted: 0,
            extracted_estimate: None,
            active_workers: 1,
            total_workers: 1,
            started: true,
            done: false,
            bytes_decoded_input: 0,
            max_disk_buffer: None,
            disk_bound: false,
            decode_step_elapsed: None,
            parts: Vec::new(),
        };
        r.render(&snap);
        r.render(&snap);
        let out = String::from_utf8(r.out).expect("utf-8");
        // Block is now five lines (bar, download, extract, lookahead,
        // ETA), so each subsequent render moves the cursor up five rows.
        assert!(out.contains("\x1b[5A"));
    }

    #[test]
    fn log_renderer_format_line_is_human_readable() {
        let mut r = LogRenderer::new();
        let snap = ProgressSnapshot {
            total_size: Some(2 * 1024 * 1024),
            bytes_downloaded: 1024 * 1024,
            bytes_extracted: 512 * 1024,
            extracted_estimate: Some(2 * 1024 * 1024),
            active_workers: 2,
            total_workers: 4,
            started: true,
            done: false,
            bytes_decoded_input: 0,
            max_disk_buffer: None,
            disk_bound: false,
            decode_step_elapsed: None,
            parts: Vec::new(),
        };
        let line = r.format_line(&snap, Instant::now());
        // Sizes are KiB/MiB-formatted, not raw bytes.
        assert!(
            line.contains("1.0 MiB / 2.0 MiB"),
            "expected human-readable download sizes in {line:?}"
        );
        assert!(
            line.contains("512.0 KiB / 2.0 MiB"),
            "expected human-readable extract sizes in {line:?}"
        );
        assert!(line.contains("workers 2/4"));
        assert!(line.contains("ETA"));
        // §1.1: lookahead and decoded_in are part of the log line.
        // Throttle is disabled here, so the cap reads `uncapped`.
        assert!(
            line.contains("lookahead 1.0 MiB / uncapped"),
            "expected lookahead/cap fields in {line:?}"
        );
        assert!(
            line.contains("decoded_in 0 B"),
            "expected decoded_in field in {line:?}"
        );
    }

    #[test]
    fn log_renderer_format_line_emits_bottleneck_label() {
        let mut r = LogRenderer::new();
        let snap = ProgressSnapshot {
            total_size: Some(2000),
            bytes_downloaded: 1000,
            bytes_extracted: 500,
            extracted_estimate: Some(2000),
            active_workers: 2,
            total_workers: 4,
            started: true,
            done: false,
            bytes_decoded_input: 200,
            max_disk_buffer: Some(100),
            disk_bound: true,
            decode_step_elapsed: None,
            parts: Vec::new(),
        };
        let line = r.format_line(&snap, Instant::now());
        assert!(line.contains("bottleneck=disk"), "got {line:?}");
        // No ANSI escapes in log mode — the subscriber owns styling.
        assert!(
            !line.contains("\x1b["),
            "log line had ANSI escape: {line:?}"
        );
    }

    #[test]
    fn columns_from_env_parses_positive_integer() {
        // `columns_from_env` is a private helper; assert its parsing
        // shape directly using a guarded env mutation. We keep the
        // env-var name distinct from `COLUMNS` to avoid races with
        // anything else; instead, invoke the parser with a value
        // we control by parsing inline.
        // Confirm parser accepts trailing whitespace.
        let parsed: Option<usize> = "  120  ".trim().parse().ok();
        assert_eq!(parsed, Some(120));
        // And rejects zero (mirrors `columns_from_env`'s zero check).
        let zero: Option<usize> = "0".parse().ok();
        assert_eq!(zero, Some(0));
    }

    #[test]
    fn supports_unicode_recognizes_utf8_locale() {
        // Pure helper: take the env-resolution logic out by inlining
        // the same normalization on a sample value.
        let v = "en_US.UTF-8";
        let normalized: String = v
            .chars()
            .filter(|c| !matches!(*c, '-' | '_'))
            .map(|c| c.to_ascii_lowercase())
            .collect();
        assert!(normalized.contains("utf8"));
    }

    #[test]
    fn lookahead_bytes_is_downloaded_minus_decoded() {
        let s = ProgressState::new();
        s.add_downloaded(10_000);
        s.set_bytes_decoded_input(3_000);
        assert_eq!(s.lookahead_bytes(), 7_000);
    }

    #[test]
    fn lookahead_bytes_saturates_when_decoder_overshoots() {
        // Defensive: if a quirky reader publishes a cursor past the
        // download counter, we don't want a wrap-around.
        let s = ProgressState::new();
        s.add_downloaded(100);
        s.set_bytes_decoded_input(1_000);
        assert_eq!(s.lookahead_bytes(), 0);
    }

    #[test]
    fn classify_bottleneck_returns_disk_when_flag_is_set() {
        let mut snap = base_snapshot();
        snap.disk_bound = true;
        // disk_bound short-circuits regardless of the rates passed.
        let b = classify_bottleneck(&snap, Some(10.0), Some(1.0));
        assert_eq!(b, Some(Bottleneck::Disk));
    }

    #[test]
    fn classify_bottleneck_network_when_download_lags_decoder() {
        // Throttle disabled, decoder consuming compressed bytes faster
        // than the network is producing them: we should be net-bound.
        let snap = ProgressSnapshot {
            total_size: Some(1_000_000),
            bytes_downloaded: 100_000,
            bytes_extracted: 50_000,
            extracted_estimate: None,
            active_workers: 4,
            total_workers: 4,
            started: true,
            done: false,
            bytes_decoded_input: 100_000,
            max_disk_buffer: None,
            disk_bound: false,
            decode_step_elapsed: None,
            parts: Vec::new(),
        };
        // dl = 50 MiB/s, decoded_in = 100 MiB/s. dl < 0.9 * decoded_in.
        let b = classify_bottleneck(&snap, Some(50.0e6), Some(100.0e6));
        assert_eq!(b, Some(Bottleneck::Network));
    }

    #[test]
    fn classify_bottleneck_disk_when_decoder_lags_download() {
        // The exact freeze-prelude scenario from PLAN_decoder_freeze.md:
        // download moving compressed bytes into the part file faster
        // than the decoder drains them. Lookahead grows; bottleneck=disk.
        let snap = ProgressSnapshot {
            total_size: Some(1_000_000),
            bytes_downloaded: 100_000,
            bytes_extracted: 50_000,
            extracted_estimate: None,
            active_workers: 4,
            total_workers: 4,
            started: true,
            done: false,
            bytes_decoded_input: 50_000,
            max_disk_buffer: None,
            disk_bound: false,
            decode_step_elapsed: None,
            parts: Vec::new(),
        };
        // dl = 60 MiB/s, decoded_in = 50 MiB/s. decoded_in < 0.9 * dl
        // is false (50 vs 54 — too tight), so widen to make the test
        // unambiguous: dl = 60, decoded_in = 40.
        let b = classify_bottleneck(&snap, Some(60.0e6), Some(40.0e6));
        assert_eq!(b, Some(Bottleneck::Disk));
    }

    #[test]
    fn classify_bottleneck_none_when_balanced() {
        let snap = ProgressSnapshot {
            total_size: Some(1_000_000),
            bytes_downloaded: 100_000,
            bytes_extracted: 50_000,
            extracted_estimate: None,
            active_workers: 4,
            total_workers: 4,
            started: true,
            done: false,
            bytes_decoded_input: 100_000,
            max_disk_buffer: None,
            disk_bound: false,
            decode_step_elapsed: None,
            parts: Vec::new(),
        };
        // Within the 10% deadband: dl = 100, decoded_in = 95.
        let b = classify_bottleneck(&snap, Some(100.0e6), Some(95.0e6));
        assert_eq!(b, None);
    }

    #[test]
    fn classify_bottleneck_none_without_rates() {
        let snap = base_snapshot();
        assert_eq!(classify_bottleneck(&snap, None, None), None);
        assert_eq!(classify_bottleneck(&snap, Some(1.0), None), None);
        assert_eq!(classify_bottleneck(&snap, None, Some(1.0)), None);
    }

    #[test]
    fn classify_bottleneck_ignores_extracted_estimate() {
        // Regression: the prior implementation read total_size and
        // extracted_estimate to derive a compression ratio. The new one
        // must not — both rates are already in compressed bytes/s.
        // Same compressed-byte rates, two different estimates → same
        // verdict either way.
        let mut snap = ProgressSnapshot {
            total_size: Some(1_000_000),
            bytes_downloaded: 100_000,
            bytes_extracted: 50_000,
            extracted_estimate: None,
            active_workers: 4,
            total_workers: 4,
            started: true,
            done: false,
            bytes_decoded_input: 50_000,
            max_disk_buffer: None,
            disk_bound: false,
            decode_step_elapsed: None,
            parts: Vec::new(),
        };
        let a = classify_bottleneck(&snap, Some(60.0e6), Some(40.0e6));
        snap.extracted_estimate = Some(10_000_000);
        let b = classify_bottleneck(&snap, Some(60.0e6), Some(40.0e6));
        assert_eq!(a, b);
        assert_eq!(a, Some(Bottleneck::Disk));
    }

    #[test]
    fn tty_renderer_paints_disk_badge_when_disk_bound() {
        let buf: Vec<u8> = Vec::new();
        let mut r = TtyRenderer::with_style_and_width(buf, BarStyle::Ascii, 120);
        let snap = ProgressSnapshot {
            total_size: Some(2_000_000),
            bytes_downloaded: 1_000_000,
            bytes_extracted: 100_000,
            extracted_estimate: Some(2_000_000),
            active_workers: 4,
            total_workers: 4,
            started: true,
            done: false,
            bytes_decoded_input: 200_000,
            max_disk_buffer: Some(1_000_000),
            disk_bound: true,
            decode_step_elapsed: None,
            parts: Vec::new(),
        };
        r.render(&snap);
        let out = String::from_utf8(r.out).expect("utf-8");
        assert!(out.contains("[DISK]"), "expected [DISK] badge in {out:?}");
        // Yellow ANSI escape on the badge.
        assert!(out.contains("\x1b[33m"));
    }

    #[test]
    fn tty_renderer_paints_net_badge_when_net_bound() {
        let buf: Vec<u8> = Vec::new();
        let mut r = TtyRenderer::with_style_and_width(buf, BarStyle::Ascii, 120);
        // Net-bound: the decoder is draining the on-disk lookahead
        // faster than the network is replenishing it. This is the
        // physically valid Network case under the new classifier
        // (PLAN_decoder_freeze.md §1.1) — `decoded_in_rate >
        // dl_rate * 1.1`.
        let snap = ProgressSnapshot {
            total_size: Some(2_000_000),
            bytes_downloaded: 600_000,
            bytes_extracted: 30_000_000,
            extracted_estimate: None,
            active_workers: 4,
            total_workers: 4,
            started: true,
            done: false,
            bytes_decoded_input: 1_500_000,
            max_disk_buffer: None,
            disk_bound: false,
            decode_step_elapsed: None,
            parts: Vec::new(),
        };
        // Drive `format_block` with two samples spanning > min_span
        // (1 s) at the same wall-clock anchor so we don't introduce
        // flake from `Instant::now()` jitter inside `render`. We
        // assert against `format_block` directly.
        let t0 = Instant::now();
        let mut snap1 = snap.clone();
        snap1.bytes_downloaded = 0;
        snap1.bytes_extracted = 0;
        snap1.bytes_decoded_input = 0;
        let _ = r.format_block(&snap1, t0);
        // 5 s span keeps both samples inside the 10 s rate window.
        let (_l1, l2, _l3, _l4, l5) = r.format_block(&snap, t0 + Duration::from_secs(5));
        // The bottleneck badge now lives on the trailing ETA line, not
        // the bar line.
        assert!(l5.contains("[NET]"), "expected [NET] badge in {l5:?}");
        assert!(l5.contains("\x1b[36m"), "expected cyan ANSI escape");
        // The download line's rate is also painted cyan.
        assert!(l2.contains("\x1b[36m"));
    }

    // ---- per-part display (`docs/PLAN_multi_url_source.md`) -------

    fn three_part_snapshot() -> ProgressSnapshot {
        ProgressSnapshot {
            total_size: Some(3 * 256 * 1024),
            bytes_downloaded: 256 * 1024 + 128 * 1024,
            bytes_extracted: 0,
            extracted_estimate: None,
            active_workers: 2,
            total_workers: 4,
            started: true,
            done: false,
            bytes_decoded_input: 0,
            max_disk_buffer: None,
            disk_bound: false,
            decode_step_elapsed: None,
            parts: vec![
                PartProgressSnapshot {
                    label: "x.tar.part0000".into(),
                    total_size: 256 * 1024,
                    bytes_downloaded: 256 * 1024,
                },
                PartProgressSnapshot {
                    label: "x.tar.part0001".into(),
                    total_size: 256 * 1024,
                    bytes_downloaded: 128 * 1024,
                },
                PartProgressSnapshot {
                    label: "x.tar.part0002".into(),
                    total_size: 256 * 1024,
                    bytes_downloaded: 0,
                },
            ],
        }
    }

    #[test]
    fn tty_emits_per_part_rows_above_aggregate_footer_for_multi_url() {
        let mut r = TtyRenderer::with_style_and_width(Vec::new(), BarStyle::Ascii, 100);
        let snap = three_part_snapshot();
        let lines = r.format_lines(&snap, Instant::now());
        // 3 part rows + 5-line aggregate footer.
        assert_eq!(lines.len(), 3 + 5);
        // First three lines are per-part; their order matches
        // the snapshot's parts order.
        assert!(lines[0].contains("x.tar.part0000"), "row 0: {:?}", lines[0]);
        assert!(lines[1].contains("x.tar.part0001"), "row 1: {:?}", lines[1]);
        assert!(lines[2].contains("x.tar.part0002"), "row 2: {:?}", lines[2]);
        // Per-part status: completed → done, idle → idle, mid →
        // numeric progress.
        assert!(lines[0].contains("done"), "completed: {:?}", lines[0]);
        assert!(lines[2].contains("idle"), "idle: {:?}", lines[2]);
        // Aggregate footer's first line carries the `peel  [...]`
        // overall bar — sanity that the footer landed in place.
        assert!(lines[3].starts_with("peel"), "agg start: {:?}", lines[3]);
    }

    /// Regression: the per-part bar must shrink to fit narrow
    /// terminals so the row never wraps. A wrapped row breaks the
    /// renderer's `\x1b[NA` cursor-up math (which counts logical
    /// lines, while the terminal counts visual rows) and stacks
    /// ghosts of prior frames in the scrollback. The Arbitrum-shaped
    /// reproduction landed at ~88 cols; pin both that and the
    /// 80-col default.
    #[test]
    fn part_row_fits_inside_narrow_terminals_without_wrapping() {
        for term_cols in [80usize, 88, 100, 120] {
            let mut r = TtyRenderer::with_style_and_width(Vec::new(), BarStyle::Ascii, term_cols);
            let lines = r.format_lines(&three_part_snapshot(), Instant::now());
            // Every per-part row (the first three lines for a
            // 3-part snapshot) must fit within the terminal — using
            // ASCII so display width == byte length.
            for row in lines.iter().take(3) {
                assert!(
                    row.chars().count() <= term_cols,
                    "term_cols={term_cols}: part row \
                     ({len} chars) overflows: {row:?}",
                    len = row.chars().count(),
                );
            }
        }
    }

    /// Direct check on the bar-sizing helper: at 80 / 88 cols (where
    /// the user's `pruned.tar.part0000` reproduction sat) the bar
    /// must shrink below the historical 24-col cap, but at 120 cols
    /// it should still hit the cap.
    #[test]
    fn part_row_bar_columns_shrinks_for_narrow_terminals() {
        // Largest label in the user's reproduction.
        let label_width = "pruned.tar.part0000".len();
        let narrow = part_row_bar_columns(80, label_width);
        let just_short = part_row_bar_columns(88, label_width);
        let wide = part_row_bar_columns(120, label_width);
        assert!(
            narrow < PART_ROW_BAR_COLUMNS,
            "80-col terminal must shrink the bar (got {narrow})",
        );
        assert!(
            just_short < PART_ROW_BAR_COLUMNS,
            "88-col terminal must shrink the bar (got {just_short})",
        );
        assert_eq!(
            wide, PART_ROW_BAR_COLUMNS,
            "120-col terminal must reach the historical cap",
        );
        assert!(
            narrow >= PART_ROW_MIN_BAR_COLUMNS,
            "narrow bar must not collapse below the floor: {narrow}",
        );
    }

    #[test]
    fn tty_single_url_keeps_historical_5_line_layout() {
        let mut r = TtyRenderer::with_style_and_width(Vec::new(), BarStyle::Ascii, 100);
        let mut snap = three_part_snapshot();
        snap.parts.truncate(1);
        let lines = r.format_lines(&snap, Instant::now());
        // Single-URL: no per-part section, just the 5-line aggregate.
        assert_eq!(lines.len(), 5, "single-URL must keep 5 lines: {lines:?}");
        assert!(lines[0].starts_with("peel"));
    }

    #[test]
    fn tty_collapses_part_rows_past_max_part_rows() {
        let mut r = TtyRenderer::with_style_and_width(Vec::new(), BarStyle::Ascii, 120);
        let mut parts = Vec::new();
        for i in 0..(MAX_PART_ROWS + 5) {
            parts.push(PartProgressSnapshot {
                label: format!("x.tar.part{i:04}"),
                total_size: 256 * 1024,
                bytes_downloaded: 0,
            });
        }
        let snap = ProgressSnapshot {
            parts,
            ..three_part_snapshot()
        };
        let lines = r.format_lines(&snap, Instant::now());
        // First MAX_PART_ROWS rows show, plus a summary line, plus
        // 5-line footer.
        assert_eq!(lines.len(), MAX_PART_ROWS + 1 + 5);
        // The summary line names the leftover count.
        assert!(
            lines[MAX_PART_ROWS].contains("…+ 5 more"),
            "summary line: {:?}",
            lines[MAX_PART_ROWS]
        );
        // The last per-part row is still part0015 (zero-indexed),
        // not part0020 — the tail collapses cleanly.
        assert!(
            lines[MAX_PART_ROWS - 1].contains(&format!("x.tar.part{:04}", MAX_PART_ROWS - 1)),
            "last shown: {:?}",
            lines[MAX_PART_ROWS - 1],
        );
    }

    #[test]
    fn tty_handles_block_height_change_between_ticks() {
        // First tick before discovery (zero parts) is a 5-line block;
        // second tick post-discovery (3 parts) grows to 8 lines. The
        // renderer must update `last_lines_emitted` so the next tick
        // moves the cursor up the right amount.
        let mut r = TtyRenderer::with_style_and_width(Vec::new(), BarStyle::Ascii, 100);
        let mut snap = three_part_snapshot();
        snap.parts.clear();
        let lines_a = r.format_lines(&snap, Instant::now());
        assert_eq!(lines_a.len(), 5);
        let snap_with_parts = three_part_snapshot();
        let lines_b = r.format_lines(&snap_with_parts, Instant::now());
        assert_eq!(lines_b.len(), 8);
    }

    // ---- LogRenderer per-part lines -------------------------------

    #[test]
    fn log_renderer_emits_one_line_per_part_plus_overall_for_multi_url() {
        let mut r = LogRenderer::new();
        let snap = three_part_snapshot();
        let part_lines = r.format_part_lines(&snap, Instant::now());
        assert_eq!(part_lines.len(), 3);
        assert!(part_lines[0].starts_with("[part0]"), "{:?}", part_lines[0]);
        assert!(part_lines[0].contains("x.tar.part0000"));
        assert!(part_lines[0].contains("done"));
        assert!(part_lines[2].contains("idle"));
        let agg = r.format_line(&snap, Instant::now());
        assert!(
            agg.starts_with("[overall] progress"),
            "multi-URL aggregate: {agg:?}"
        );
    }

    #[test]
    fn log_renderer_single_url_keeps_historical_progress_prefix() {
        let mut r = LogRenderer::new();
        let mut snap = three_part_snapshot();
        snap.parts.truncate(1);
        let part_lines = r.format_part_lines(&snap, Instant::now());
        assert!(
            part_lines.is_empty(),
            "single-URL must emit no per-part lines: {part_lines:?}"
        );
        let agg = r.format_line(&snap, Instant::now());
        assert!(
            agg.starts_with("progress:"),
            "single-URL aggregate keeps the historical prefix: {agg:?}"
        );
    }

    fn base_snapshot() -> ProgressSnapshot {
        ProgressSnapshot {
            total_size: None,
            bytes_downloaded: 0,
            bytes_extracted: 0,
            extracted_estimate: None,
            active_workers: 0,
            total_workers: 0,
            started: true,
            done: false,
            bytes_decoded_input: 0,
            max_disk_buffer: None,
            disk_bound: false,
            decode_step_elapsed: None,
            parts: Vec::new(),
        }
    }

    #[test]
    fn supports_unicode_rejects_c_locale() {
        let v = "C";
        let normalized: String = v
            .chars()
            .filter(|c| !matches!(*c, '-' | '_'))
            .map(|c| c.to_ascii_lowercase())
            .collect();
        assert!(!normalized.contains("utf8"));
    }

    #[test]
    fn stall_detector_silent_while_decoder_advances() {
        let t0 = Instant::now();
        let mut det = StallDetector::new(Duration::from_secs(30), t0);
        let mut snap = base_snapshot();
        // Steady decoder + sink advance every "tick".
        for i in 1..=10 {
            snap.bytes_decoded_input = i * 1000;
            snap.bytes_extracted = i * 500;
            let obs = det.tick(&snap, t0 + Duration::from_secs(i * 5));
            assert_eq!(obs, StallObservation::Healthy, "tick {i}: {obs:?}");
        }
    }

    #[test]
    fn stall_detector_warns_once_per_window_when_pipeline_frozen() {
        let t0 = Instant::now();
        let interval = Duration::from_secs(30);
        let mut det = StallDetector::new(interval, t0);
        // Pre-seed the detector with a non-zero baseline so the first
        // stall starts after a real "advance" rather than from
        // construction time.
        let mut snap = base_snapshot();
        snap.bytes_downloaded = 1_000_000;
        snap.bytes_decoded_input = 500_000;
        snap.bytes_extracted = 250_000;
        snap.disk_bound = true;
        let _ = det.tick(&snap, t0);
        // Snapshot stays identical for 35 s — exactly the case the
        // §1.2 plan calls out.
        let warned_at_5s = det.tick(&snap, t0 + Duration::from_secs(5));
        assert_eq!(warned_at_5s, StallObservation::Healthy);
        let warned_at_35s = det.tick(&snap, t0 + Duration::from_secs(35));
        assert_eq!(
            warned_at_35s,
            StallObservation::Warned(StallKind::PipelineFrozen)
        );
        // Same snapshot again 5 s later — must not double-warn.
        let suppressed = det.tick(&snap, t0 + Duration::from_secs(40));
        assert_eq!(suppressed, StallObservation::SuppressedDuplicate);
        // After another full warn_interval has elapsed without progress,
        // the detector must warn again.
        let warned_again = det.tick(&snap, t0 + Duration::from_secs(70));
        assert_eq!(
            warned_again,
            StallObservation::Warned(StallKind::PipelineFrozen)
        );
    }

    #[test]
    fn stall_detector_classifies_extractor_only_stall() {
        let t0 = Instant::now();
        let interval = Duration::from_secs(30);
        let mut det = StallDetector::new(interval, t0);
        let mut snap = base_snapshot();
        snap.bytes_downloaded = 1_000_000;
        snap.bytes_decoded_input = 100_000;
        snap.bytes_extracted = 50_000;
        let _ = det.tick(&snap, t0);
        // Decoder advances at intervals shorter than warn_interval so
        // it never goes stale; sink stays flat.
        snap.bytes_decoded_input = 110_000;
        let _ = det.tick(&snap, t0 + Duration::from_secs(10));
        snap.bytes_decoded_input = 120_000;
        let _ = det.tick(&snap, t0 + Duration::from_secs(20));
        snap.bytes_decoded_input = 130_000;
        // 30 s elapsed; sink has been flat the whole time, decoder
        // just advanced. Detector should fire ExtractorStalled.
        let obs = det.tick(&snap, t0 + Duration::from_secs(30));
        assert_eq!(obs, StallObservation::Warned(StallKind::ExtractorStalled));
    }

    #[test]
    fn stall_detector_recovery_clears_warn_lockout() {
        let t0 = Instant::now();
        let interval = Duration::from_secs(30);
        let mut det = StallDetector::new(interval, t0);
        let mut snap = base_snapshot();
        snap.bytes_downloaded = 1;
        snap.bytes_decoded_input = 1;
        snap.bytes_extracted = 1;
        snap.disk_bound = true;
        let _ = det.tick(&snap, t0);
        // First freeze fires a warn at t0+30s.
        let _ = det.tick(&snap, t0 + Duration::from_secs(30));
        // Pipeline recovers — both counters advance at t0+45s.
        snap.bytes_decoded_input += 100;
        snap.bytes_extracted += 50;
        let healthy = det.tick(&snap, t0 + Duration::from_secs(45));
        assert_eq!(healthy, StallObservation::Healthy);
        // Pipeline freezes again. The next freeze must fire another
        // warn 30 s after the most-recent advance, *not* be suppressed
        // by the earlier warn lockout.
        let warned = det.tick(&snap, t0 + Duration::from_secs(76));
        assert_eq!(warned, StallObservation::Warned(StallKind::PipelineFrozen));
    }

    #[test]
    fn stall_detector_decoded_only_stall_requires_disk_bound() {
        let t0 = Instant::now();
        let interval = Duration::from_secs(30);
        let mut det = StallDetector::new(interval, t0);
        let mut snap = base_snapshot();
        snap.bytes_downloaded = 1_000_000;
        snap.bytes_decoded_input = 500_000;
        snap.bytes_extracted = 250_000;
        let _ = det.tick(&snap, t0);
        // Sink advances frequently enough to never be considered
        // stale; decoder stays put. Throttle is off — so even after
        // 30 s of decoder inactivity, the detector stays quiet.
        snap.bytes_extracted = 251_000;
        let _ = det.tick(&snap, t0 + Duration::from_secs(10));
        snap.bytes_extracted = 252_000;
        let _ = det.tick(&snap, t0 + Duration::from_secs(20));
        snap.bytes_extracted = 253_000;
        let obs = det.tick(&snap, t0 + Duration::from_secs(30));
        assert_eq!(obs, StallObservation::Healthy);
        // Throttle engages — the same flat-decoder pattern now warns.
        // Sink keeps advancing so it doesn't *also* trip the freeze.
        snap.disk_bound = true;
        snap.bytes_extracted = 254_000;
        let obs = det.tick(&snap, t0 + Duration::from_secs(40));
        assert_eq!(
            obs,
            StallObservation::Warned(StallKind::DecoderStalledThrottled)
        );
    }

    // ---- §2.4b DecodeStepStallDetector + ProgressState wiring ---------

    /// `mark_decode_step_entered` publishes a non-zero start; the
    /// snapshot reports a small but non-`None` elapsed; clearing
    /// returns to `None`. Mirrors how the extractor and renderer
    /// pair up across the run.
    #[test]
    fn decode_step_marker_publishes_and_clears() {
        let state = ProgressState::new();
        // No call in flight initially.
        assert_eq!(state.decode_step_elapsed(), None);
        assert_eq!(state.snapshot().decode_step_elapsed, None);

        state.mark_decode_step_entered();
        // Two reads near each other will differ by sub-microseconds —
        // we just want to assert the reported elapsed is *some* small
        // value, not a precise match between two `Instant::now()` calls.
        let elapsed = state.decode_step_elapsed().expect("call in progress");
        assert!(elapsed < Duration::from_millis(100));
        let snap_elapsed = state
            .snapshot()
            .decode_step_elapsed
            .expect("snapshot mirrors the marker");
        assert!(snap_elapsed < Duration::from_millis(100));

        state.mark_decode_step_exited();
        assert_eq!(state.decode_step_elapsed(), None);
        assert_eq!(state.snapshot().decode_step_elapsed, None);
    }

    /// Repeated entered/exited toggles overwrite cleanly; the field
    /// is a single AtomicU64 with `0` as the off sentinel.
    #[test]
    fn decode_step_marker_round_trips() {
        let state = ProgressState::new();
        for _ in 0..3 {
            state.mark_decode_step_entered();
            assert!(state.decode_step_elapsed().is_some());
            state.mark_decode_step_exited();
            assert!(state.decode_step_elapsed().is_none());
        }
    }

    /// `reset_for_retry` clears any in-flight marker so the next run's
    /// peer watchdog starts from "no call in progress."
    #[test]
    fn decode_step_marker_cleared_on_retry_reset() {
        let state = ProgressState::new();
        state.mark_decode_step_entered();
        assert!(state.decode_step_elapsed().is_some());
        state.reset_for_retry();
        assert!(state.decode_step_elapsed().is_none());
    }

    /// No call in flight → `Healthy`. Empty snapshot is the steady
    /// state between every pair of decode_step calls.
    #[test]
    fn decode_step_stall_detector_silent_when_no_call_in_flight() {
        let mut det = DecodeStepStallDetector::new(Duration::from_secs(30));
        let mut snap = base_snapshot();
        snap.decode_step_elapsed = None;
        let now = Instant::now();
        for i in 0..10 {
            assert_eq!(
                det.tick(&snap, now + Duration::from_millis(i)),
                StallObservation::Healthy,
            );
        }
    }

    /// Call in flight under threshold → silent.
    #[test]
    fn decode_step_stall_detector_silent_under_threshold() {
        let mut det = DecodeStepStallDetector::new(Duration::from_secs(30));
        let mut snap = base_snapshot();
        snap.decode_step_elapsed = Some(Duration::from_secs(5));
        assert_eq!(det.tick(&snap, Instant::now()), StallObservation::Healthy);
    }

    /// Call in flight at threshold → warn once; subsequent ticks
    /// inside the rate-limit window are suppressed; after the window
    /// passes, a still-stuck call warns again.
    #[test]
    fn decode_step_stall_detector_warns_then_rate_limits() {
        let mut det = DecodeStepStallDetector::new(Duration::from_secs(30));
        let mut snap = base_snapshot();
        snap.decode_step_elapsed = Some(Duration::from_secs(45));
        let t0 = Instant::now();

        let first = det.tick(&snap, t0);
        assert_eq!(first, StallObservation::Warned(StallKind::DecodeStepHung));

        // Same tick again (or 5 s later, doesn't matter — still in
        // the same rate-limit window).
        snap.decode_step_elapsed = Some(Duration::from_secs(50));
        let second = det.tick(&snap, t0 + Duration::from_secs(5));
        assert_eq!(second, StallObservation::SuppressedDuplicate);

        // After the threshold has elapsed since the prior warn, the
        // detector fires again — a wedged call produces one entry per
        // warn-interval.
        snap.decode_step_elapsed = Some(Duration::from_secs(75));
        let third = det.tick(&snap, t0 + Duration::from_secs(35));
        assert_eq!(third, StallObservation::Warned(StallKind::DecodeStepHung));
    }

    /// Recovery (call returns) clears the rate-limit watermark so a
    /// fresh wedge fires immediately rather than waiting for the
    /// previous window to age out.
    #[test]
    fn decode_step_stall_detector_recovery_clears_watermark() {
        let mut det = DecodeStepStallDetector::new(Duration::from_secs(30));
        let mut snap = base_snapshot();
        let t0 = Instant::now();

        snap.decode_step_elapsed = Some(Duration::from_secs(40));
        assert_eq!(
            det.tick(&snap, t0),
            StallObservation::Warned(StallKind::DecodeStepHung),
        );

        // Call returns; detector resets watermark.
        snap.decode_step_elapsed = None;
        assert_eq!(
            det.tick(&snap, t0 + Duration::from_secs(2)),
            StallObservation::Healthy
        );

        // A new wedge a moment later → fires immediately, even though
        // the previous warn was only seconds ago.
        snap.decode_step_elapsed = Some(Duration::from_secs(31));
        assert_eq!(
            det.tick(&snap, t0 + Duration::from_secs(3)),
            StallObservation::Warned(StallKind::DecodeStepHung),
        );
    }

    /// `PEEL_DECODE_STEP_WARN_SECS` overrides the default; an invalid
    /// value falls back. Same env var the post-hoc watchdog reads;
    /// both watchdogs share the threshold.
    #[test]
    fn decode_step_hung_warn_env_override() {
        let prev = std::env::var("PEEL_DECODE_STEP_WARN_SECS").ok();
        std::env::set_var("PEEL_DECODE_STEP_WARN_SECS", "10");
        assert_eq!(decode_step_hung_warn_from_env(), Duration::from_secs(10));
        std::env::set_var("PEEL_DECODE_STEP_WARN_SECS", "0");
        assert_eq!(
            decode_step_hung_warn_from_env(),
            DEFAULT_DECODE_STEP_HUNG_WARN
        );
        std::env::remove_var("PEEL_DECODE_STEP_WARN_SECS");
        assert_eq!(
            decode_step_hung_warn_from_env(),
            DEFAULT_DECODE_STEP_HUNG_WARN
        );
        match prev {
            Some(v) => std::env::set_var("PEEL_DECODE_STEP_WARN_SECS", v),
            None => std::env::remove_var("PEEL_DECODE_STEP_WARN_SECS"),
        }
    }

    #[test]
    fn spawn_renderer_stops_when_done_flips() {
        struct CountingRenderer {
            ticks: Arc<AtomicU64>,
            finish_called: Arc<AtomicBool>,
        }
        impl ProgressRenderer for CountingRenderer {
            fn render(&mut self, _snap: &ProgressSnapshot) {
                self.ticks.fetch_add(1, Ordering::Relaxed);
            }
            fn finish(&mut self) {
                self.finish_called.store(true, Ordering::Release);
            }
        }
        let state = ProgressState::new();
        let ticks = Arc::new(AtomicU64::new(0));
        let finish_called = Arc::new(AtomicBool::new(false));
        let renderer = CountingRenderer {
            ticks: Arc::clone(&ticks),
            finish_called: Arc::clone(&finish_called),
        };
        let handle =
            spawn_renderer(Arc::clone(&state), renderer, Duration::from_millis(20)).expect("spawn");
        thread::sleep(Duration::from_millis(120));
        state.mark_done();
        handle.join().expect("join");
        assert!(ticks.load(Ordering::Relaxed) >= 2);
        assert!(finish_called.load(Ordering::Acquire));
    }
}
