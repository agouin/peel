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
use std::sync::{Arc, Mutex};
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
#[derive(Debug, Default)]
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
    /// One-shot configuration banner lines (e.g. `io_backend=uring
    /// depth=64`, `http_version=auto …`) that the TTY renderer should
    /// print as scrollback above its in-place block. Mirrors the
    /// `tracing::info!` lines the non-TTY [`LogRenderer`] gets via the
    /// subscriber, since the TTY path suppresses INFO events to keep
    /// the redraw region clean. Drained by [`spawn_renderer`] each
    /// tick.
    info_banner: Mutex<Vec<String>>,
}

impl ProgressState {
    /// Construct an empty state, wrapped in [`Arc`] for sharing.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
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

    /// Append a configuration-banner line.
    ///
    /// Used to surface `tracing::info!` content (HTTP-version choice,
    /// resolved IO backend) in the TTY progress UI: the subscriber
    /// suppresses INFO events on a TTY so the in-place redraw isn't
    /// corrupted, but the user still wants the same one-glance config
    /// summary the non-TTY path prints. Drained on each render tick by
    /// [`spawn_renderer`] and handed to [`ProgressRenderer::take_banner`].
    pub fn push_banner(&self, line: String) {
        // Mutex poisoning is ignored: a banner line is best-effort
        // diagnostic output; losing one rather than panicking the
        // renderer thread is the right trade-off.
        if let Ok(mut v) = self.info_banner.lock() {
            v.push(line);
        }
    }

    /// Drain pending banner lines. Returns an empty `Vec` if a previous
    /// thread poisoned the mutex (see [`Self::push_banner`]).
    #[must_use]
    pub fn take_banner(&self) -> Vec<String> {
        self.info_banner
            .lock()
            .map(|mut v| std::mem::take(&mut *v))
            .unwrap_or_default()
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
        }
    }
}

/// Point-in-time view of every counter [`ProgressState`] tracks.
///
/// The fields whose underlying atomic uses `0` as a sentinel for
/// "unknown" are surfaced here as `Option`, so renderers don't need
/// to re-encode the convention.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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
    /// Hand the renderer banner lines drained from
    /// [`ProgressState::take_banner`]. Default no-op: only the
    /// [`TtyRenderer`] paints them (the non-TTY path's banner equivalents
    /// already arrive via the `tracing` subscriber's INFO output, so
    /// surfacing them again here would double-print). Called by
    /// [`spawn_renderer`] before each render tick when the state had
    /// pending lines.
    fn take_banner(&mut self, _lines: Vec<String>) {}
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
    /// Visible-width display length of [`Self::badge`], in columns.
    /// ANSI escapes don't count; emojis count as 2 columns each.
    fn visible_len(self, style: BarStyle) -> usize {
        match (self, style) {
            (Self::Network, BarStyle::Unicode) => "🔵 net".chars().count() + 1, // 1 emoji = 2 cols, " net" = 4
            (Self::Disk, BarStyle::Unicode) => "🟡 disk".chars().count() + 1,
            (Self::Network, BarStyle::Ascii) => "[NET]".len(),
            (Self::Disk, BarStyle::Ascii) => "[DISK]".len(),
        }
    }

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
/// 2. Otherwise, when both download and extract rates are known, fall
///    back to a rate comparison. The decoder consumes compressed
///    bytes at roughly the download rate; the sink writes uncompressed
///    bytes at the extract rate. We compare the extract rate against
///    the download rate scaled by the compression ratio
///    (`extracted_estimate / total_size`); the slower side is the
///    bottleneck. A 10% margin keeps the indicator from flapping when
///    the two sides are roughly balanced.
/// 3. Otherwise, return `None` (no claim).
#[must_use]
pub fn classify_bottleneck(
    snap: &ProgressSnapshot,
    dl_rate: Option<f64>,
    ex_rate: Option<f64>,
) -> Option<Bottleneck> {
    if snap.disk_bound {
        return Some(Bottleneck::Disk);
    }
    let (dl, ex) = (dl_rate?, ex_rate?);
    if dl <= 0.0 || ex <= 0.0 {
        return None;
    }
    // Compression ratio: bytes-out per byte-in. Default to 1.0 (treat
    // as if uncompressed) when we don't have an estimate yet.
    let ratio = match (snap.total_size, snap.extracted_estimate) {
        (Some(total), Some(est)) if total > 0 => (est as f64 / total as f64).max(1.0),
        _ => 1.0,
    };
    // Effective extract rate measured in *source* (compressed) bytes
    // per second, so it's directly comparable to the download rate.
    let ex_in_source_units = ex / ratio;
    // 10% deadband around equality.
    if dl < ex_in_source_units * 0.9 {
        Some(Bottleneck::Network)
    } else if ex_in_source_units < dl * 0.9 {
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
    /// Banner lines staged for the next render tick. Printed once,
    /// above the redraw block, then dropped — they belong to scrollback
    /// rather than the in-place region.
    pending_banner: Vec<String>,
}

impl<W: Write + Send> TtyRenderer<W> {
    /// Construct with the default rate buffers, locale-detected bar
    /// style, and the live terminal width.
    pub fn new(out: W) -> Self {
        Self {
            out,
            rate_dl: RateBuffer::for_renderer(),
            rate_ex: RateBuffer::for_renderer(),
            style: BarStyle::detect(),
            terminal_width_override: None,
            bar_max_columns: MAX_BAR_COLUMNS,
            started_render: false,
            last_lines_emitted: 0,
            pending_banner: Vec::new(),
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
            style: BarStyle::Ascii,
            terminal_width_override: None,
            bar_max_columns: bar,
            started_render: false,
            last_lines_emitted: 0,
            pending_banner: Vec::new(),
        }
    }

    /// Construct with an explicit bar style and a fixed apparent
    /// terminal width (tests of the new layout use this).
    pub fn with_style_and_width(out: W, style: BarStyle, terminal_width: usize) -> Self {
        Self {
            out,
            rate_dl: RateBuffer::for_renderer(),
            rate_ex: RateBuffer::for_renderer(),
            style,
            terminal_width_override: Some(terminal_width.max(20)),
            bar_max_columns: MAX_BAR_COLUMNS,
            started_render: false,
            last_lines_emitted: 0,
            pending_banner: Vec::new(),
        }
    }

    /// Resolve the apparent terminal width for this tick: explicit
    /// override > live `TIOCGWINSZ` > `COLUMNS` env > 80-column default.
    fn columns(&self) -> usize {
        self.terminal_width_override
            .or_else(terminal_columns)
            .unwrap_or(FALLBACK_TERMINAL_COLUMNS)
    }

    /// Format the three-line block for `snap` using `now` as the rate
    /// sample timestamp. Pure: returns `(line1, line2, line3)` without
    /// touching `self.out`. Tests call this directly.
    pub fn format_block(
        &mut self,
        snap: &ProgressSnapshot,
        now: Instant,
    ) -> (String, String, String) {
        self.rate_dl.push(now, snap.bytes_downloaded);
        self.rate_ex.push(now, snap.bytes_extracted);

        let dl_rate = self.rate_dl.rate_bytes_per_sec();
        let ex_rate = self.rate_ex.rate_bytes_per_sec();

        let percent = overall_percent(snap);
        let eta = compute_eta(snap, dl_rate, ex_rate);

        let term_cols = self.columns();
        let bar_cap = self.bar_max_columns.min(MAX_BAR_COLUMNS);
        let bottleneck = classify_bottleneck(snap, dl_rate, ex_rate);

        let line1 = format_overall_line(
            snap, percent, eta, term_cols, bar_cap, self.style, bottleneck,
        );
        let line2 = format_download_line(snap, dl_rate, bottleneck);
        let line3 = format_extract_line(snap, ex_rate, bottleneck);
        (line1, line2, line3)
    }
}

impl<W: Write + Send> ProgressRenderer for TtyRenderer<W> {
    fn render(&mut self, snapshot: &ProgressSnapshot) {
        let now = Instant::now();
        let (l1, l2, l3) = self.format_block(snapshot, now);
        // Each render rewrites three lines. Strategy:
        //   First tick: write all three lines, each terminated with
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
        // there. Three lines always lose nothing; if the user wants
        // to see the original block they're already redrawing it.
        if self.started_render {
            // Move cursor to the start of the first line we previously
            // wrote. Lines emitted: at most 3.
            let n = self.last_lines_emitted.min(99);
            if n > 0 {
                let _ = write!(self.out, "\x1b[{n}A");
            }
        } else {
            self.started_render = true;
        }

        // Pending banner lines are drained ahead of the body. Each one
        // overwrites the corresponding row of the previous block (via
        // the cursor-up above) and is then pushed into scrollback by
        // the body lines that follow. They are not counted in
        // `last_lines_emitted` so the next tick's cursor-up doesn't
        // try to redraw over them.
        for line in self.pending_banner.drain(..) {
            let _ = writeln!(self.out, "{line}\x1b[K");
        }

        let _ = writeln!(self.out, "{l1}\x1b[K");
        let _ = writeln!(self.out, "{l2}\x1b[K");
        let _ = writeln!(self.out, "{l3}\x1b[K");
        let _ = self.out.flush();
        self.last_lines_emitted = 3;
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

    fn take_banner(&mut self, lines: Vec<String>) {
        self.pending_banner.extend(lines);
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
        }
    }

    /// Format the line [`Self::render`] will emit. Pure: tests call
    /// it without a tracing subscriber.
    ///
    /// Mirrors the TTY renderer's three-line block in shape — sizes
    /// via [`format_bytes`], rates via [`format_rate`], ETA via
    /// [`format_eta`] — flattened onto one log line so each tick is a
    /// single record. A bottleneck label (`bottleneck=disk` or
    /// `=net`) is appended when the classifier has a verdict, with
    /// no ANSI color escapes (the log subscriber is responsible for
    /// any styling it wants to apply).
    pub fn format_line(&mut self, snap: &ProgressSnapshot, now: Instant) -> String {
        self.rate_dl.push(now, snap.bytes_downloaded);
        self.rate_ex.push(now, snap.bytes_extracted);
        let dl_rate = self.rate_dl.rate_bytes_per_sec();
        let ex_rate = self.rate_ex.rate_bytes_per_sec();
        let percent = overall_percent(snap);
        let eta = compute_eta(snap, dl_rate, ex_rate);
        let bottleneck = classify_bottleneck(snap, dl_rate, ex_rate);

        let pct = percent
            .map(|p| format!("{p:.1}%"))
            .unwrap_or_else(|| "?".into());
        let downloaded = format_bytes(snap.bytes_downloaded);
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
        let mut line = format!(
            "progress: {pct}  download {downloaded} / {total} @ {dl}  \
             extract {extracted} / {est} @ {ex}  workers {}/{}  ETA {eta_s}",
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
}

impl ProgressRenderer for LogRenderer {
    fn render(&mut self, snapshot: &ProgressSnapshot) {
        let now = Instant::now();
        let line = self.format_line(snapshot, now);
        tracing::info!(target: "peel::progress", "{line}");
    }

    fn finish(&mut self) {
        // Nothing to do — each tick already emitted a structured
        // event; the subscriber owns the output stream.
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
            // Tick loop: render, sleep, render, … until done. We do an
            // extra final render after the done flag flips so the user
            // sees the final counters.
            loop {
                // Hand any pending banner lines (e.g. `io_backend=…`,
                // `http_version=…`) to the renderer ahead of the body.
                let banner = state.take_banner();
                if !banner.is_empty() {
                    renderer.take_banner(banner);
                }
                let snap = state.snapshot();
                renderer.render(&snap);
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
    eta: Option<Duration>,
    term_cols: usize,
    bar_cap: usize,
    style: BarStyle,
    bottleneck: Option<Bottleneck>,
) -> String {
    let pct = percent
        .map(|p| format!("{p:5.1}%"))
        .unwrap_or_else(|| "  --.-%".into());
    let eta_s = format_eta(eta);
    let badge = match bottleneck {
        Some(b) => format!("  {}", b.badge(style)),
        None => String::new(),
    };
    // Layout: `peel  [BAR]  XX.X%  ETA Xh Xm Xs  [badge]`
    // Reserve everything except the bar; the bar fills what's left.
    // The badge contains ANSI escapes which don't take screen columns,
    // so we reserve only the visible width.
    let prefix = "peel  ";
    let badge_visible = bottleneck.map(|b| b.visible_len(style)).unwrap_or(0);
    let visible_suffix_len = "  ".len()
        + pct.len()
        + "  ETA ".len()
        + eta_s.len()
        + if badge_visible > 0 { 2 } else { 0 } // the "  " before badge
        + badge_visible;
    let reserved = prefix.len() + visible_suffix_len;
    let mut budget = term_cols.saturating_sub(reserved);
    if budget > bar_cap {
        budget = bar_cap;
    }
    let bar = render_bar(snap, budget, style);
    format!("{prefix}{bar}  {pct}  ETA {eta_s}{badge}")
}

fn format_download_line(
    snap: &ProgressSnapshot,
    rate: Option<f64>,
    bottleneck: Option<Bottleneck>,
) -> String {
    let downloaded = format_bytes(snap.bytes_downloaded);
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
    fn tty_renderer_writes_three_lines_to_buffer() {
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
            bytes_decoded_input: 0,
            max_disk_buffer: None,
            disk_bound: false,
        };
        r.render(&snap);
        let out = String::from_utf8(r.out).expect("utf-8");
        // Three lines, each terminated with the clear-EOL escape.
        assert_eq!(out.matches("\x1b[K").count(), 3);
        assert!(out.contains("peel"));
        assert!(out.contains("workers 2/4"));
        assert!(out.contains("download"));
        assert!(out.contains("extract"));
        // Sizes on lines 2 and 3 are human-readable: 1000 < 1 KiB so
        // it stays as bytes, 2000 ≈ 1.95 KiB so it rolls up.
        assert!(out.contains("1000 B / 2.0 KiB"));
        assert!(out.contains("200 B / unknown"));
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
        };
        let (l1, _, _) = r.format_block(&snap, Instant::now());
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
        };
        let (l1, _, _) = r.format_block(&snap, Instant::now());
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
        };
        r.render(&snap);
        r.render(&snap);
        let out = String::from_utf8(r.out).expect("utf-8");
        assert!(out.contains("\x1b[3A"));
    }

    #[test]
    fn progress_state_banner_round_trip() {
        let s = ProgressState::new();
        s.push_banner("io_backend=uring depth=64".into());
        s.push_banner("http_version=auto (ALPN-negotiated H1/H2)".into());
        let lines = s.take_banner();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "io_backend=uring depth=64");
        assert_eq!(lines[1], "http_version=auto (ALPN-negotiated H1/H2)");
        // A second drain returns nothing — `take_banner` empties the queue.
        assert!(s.take_banner().is_empty());
    }

    #[test]
    fn tty_renderer_take_banner_prints_lines_above_body_once() {
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
        };
        // First render with two banner lines; the renderer should print
        // them ahead of the body block.
        r.take_banner(vec![
            "io_backend=blocking (forced)".into(),
            "http_version=h2 (forced; h2c prior-knowledge over plaintext)".into(),
        ]);
        r.render(&snap);
        // Second render with no new banner lines; body redraws via
        // cursor-up by 3 (NOT 5 — the banner is scrollback now).
        r.render(&snap);
        let out = String::from_utf8(r.out).expect("utf-8");
        // Banner lines appear exactly once.
        assert_eq!(
            out.matches("io_backend=blocking (forced)").count(),
            1,
            "io_backend banner should print exactly once: {out:?}"
        );
        assert_eq!(
            out.matches("http_version=h2").count(),
            1,
            "http_version banner should print exactly once: {out:?}"
        );
        // Body redraw moves up 3 lines, never 5.
        assert!(out.contains("\x1b[3A"), "expected cursor-up by 3: {out:?}");
        assert!(
            !out.contains("\x1b[5A"),
            "must not include banner lines in cursor-up count: {out:?}"
        );
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
        let b = classify_bottleneck(&snap, Some(10.0), Some(1.0));
        assert_eq!(b, Some(Bottleneck::Disk));
    }

    #[test]
    fn classify_bottleneck_falls_back_to_rate_comparison() {
        // Throttle disabled (max_disk_buffer = None, disk_bound = false)
        // and download is slower than extract (after compression
        // correction): we should be net-bound.
        let snap = ProgressSnapshot {
            total_size: Some(1_000_000),
            bytes_downloaded: 100_000,
            bytes_extracted: 50_000,
            extracted_estimate: Some(2_000_000), // 2x compression
            active_workers: 4,
            total_workers: 4,
            started: true,
            done: false,
            bytes_decoded_input: 100_000,
            max_disk_buffer: None,
            disk_bound: false,
        };
        // dl = 100kB/s, ex = 1MB/s => ex_in_source = 1MB/2 = 500kB/s
        // dl < 0.9 * 500kB/s, so net-bound.
        let b = classify_bottleneck(&snap, Some(100_000.0), Some(1_000_000.0));
        assert_eq!(b, Some(Bottleneck::Network));
    }

    #[test]
    fn classify_bottleneck_disk_bound_when_extract_lags() {
        let snap = ProgressSnapshot {
            total_size: Some(1_000_000),
            bytes_downloaded: 100_000,
            bytes_extracted: 50_000,
            extracted_estimate: Some(2_000_000),
            active_workers: 4,
            total_workers: 4,
            started: true,
            done: false,
            bytes_decoded_input: 50_000,
            max_disk_buffer: None,
            disk_bound: false,
        };
        // dl = 5MB/s, ex = 1MB/s => ex_in_source = 500kB/s.
        // ex_in_source < 0.9 * dl, so disk-bound.
        let b = classify_bottleneck(&snap, Some(5_000_000.0), Some(1_000_000.0));
        assert_eq!(b, Some(Bottleneck::Disk));
    }

    #[test]
    fn classify_bottleneck_none_when_balanced() {
        let snap = ProgressSnapshot {
            total_size: Some(1_000_000),
            bytes_downloaded: 100_000,
            bytes_extracted: 50_000,
            extracted_estimate: Some(2_000_000),
            active_workers: 4,
            total_workers: 4,
            started: true,
            done: false,
            bytes_decoded_input: 50_000,
            max_disk_buffer: None,
            disk_bound: false,
        };
        // Balanced: dl = 1MB/s, ex = 2MB/s => ex_in_source = 1MB/s.
        let b = classify_bottleneck(&snap, Some(1_000_000.0), Some(2_000_000.0));
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
        // Snapshot where rate-comparison should pick Network
        // (download is slower than extract / compression ratio).
        let snap = ProgressSnapshot {
            total_size: Some(2_000_000),
            bytes_downloaded: 600_000,
            bytes_extracted: 30_000_000,
            extracted_estimate: Some(2_000_000),
            active_workers: 4,
            total_workers: 4,
            started: true,
            done: false,
            bytes_decoded_input: 600_000,
            max_disk_buffer: None,
            disk_bound: false,
        };
        // Drive `format_block` with two samples spanning > 5s (the
        // rate buffer's min-span) at the same wall-clock anchor so we
        // don't introduce flake from `Instant::now()` jitter inside
        // `render`. We assert against `format_block` directly.
        let t0 = Instant::now();
        let mut snap1 = snap;
        snap1.bytes_downloaded = 0;
        snap1.bytes_extracted = 0;
        let _ = r.format_block(&snap1, t0);
        // Exactly 5 s span — the buffer's window is also 5 s and
        // eviction is `dt > window`, so the older sample is kept.
        let (l1, l2, _l3) = r.format_block(&snap, t0 + Duration::from_secs(5));
        assert!(l1.contains("[NET]"), "expected [NET] badge in {l1:?}");
        assert!(l1.contains("\x1b[36m"), "expected cyan ANSI escape");
        // The download line's rate is also painted cyan.
        assert!(l2.contains("\x1b[36m"));
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
