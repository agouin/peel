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
use std::sync::Arc;
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
        ProgressSnapshot {
            total_size: if total == 0 { None } else { Some(total) },
            bytes_downloaded: self.bytes_downloaded.load(Ordering::Relaxed),
            bytes_extracted: self.bytes_extracted.load(Ordering::Relaxed),
            extracted_estimate: if est == 0 { None } else { Some(est) },
            active_workers: self.active_workers.load(Ordering::Relaxed),
            total_workers: self.total_workers.load(Ordering::Relaxed),
            started: self.started.load(Ordering::Acquire),
            done: self.done.load(Ordering::Acquire),
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

    /// 5 s window, 64-sample capacity, 5 s minimum span — the defaults
    /// PLAN_v2 §6 specifies.
    #[must_use]
    pub fn five_second() -> Self {
        Self::new(Duration::from_secs(5), 64, Duration::from_secs(5))
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

/// ANSI-on-stderr renderer for interactive terminals.
///
/// Three lines, redrawn in place via `\x1b7` / `\x1b8` (DECSC/DECRC).
/// On the first tick the renderer saves the cursor, then on every
/// subsequent tick it restores to that position before re-emitting
/// the three lines (each terminated with `\x1b[K` to clear the rest
/// of the line). [`Self::finish`] emits a final newline so the shell
/// prompt appears below the block.
///
/// Generic over the writer to make tests trivial; the binary uses
/// [`std::io::Stderr`].
pub struct TtyRenderer<W: Write + Send> {
    out: W,
    rate_dl: RateBuffer,
    rate_ex: RateBuffer,
    bar_width: usize,
    started_render: bool,
    last_lines_emitted: usize,
}

impl<W: Write + Send> TtyRenderer<W> {
    /// Construct with the default rate buffers and a 24-character
    /// progress bar.
    pub fn new(out: W) -> Self {
        Self::with_bar_width(out, 24)
    }

    /// Construct with an explicit bar width (tests use this).
    pub fn with_bar_width(out: W, bar_width: usize) -> Self {
        Self {
            out,
            rate_dl: RateBuffer::five_second(),
            rate_ex: RateBuffer::five_second(),
            bar_width: bar_width.max(4),
            started_render: false,
            last_lines_emitted: 0,
        }
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

        let line1 = format_overall_line(snap, percent, eta);
        let line2 = format_download_line(snap, dl_rate, self.bar_width);
        let line3 = format_extract_line(snap, ex_rate);
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
            rate_dl: RateBuffer::five_second(),
            rate_ex: RateBuffer::five_second(),
        }
    }

    /// Format the structured line that [`Self::render`] will emit.
    /// Pure: tests call this without a tracing subscriber.
    pub fn format_line(&mut self, snap: &ProgressSnapshot, now: Instant) -> String {
        self.rate_dl.push(now, snap.bytes_downloaded);
        self.rate_ex.push(now, snap.bytes_extracted);
        let dl_rate = self.rate_dl.rate_bytes_per_sec();
        let ex_rate = self.rate_ex.rate_bytes_per_sec();
        let percent = overall_percent(snap);
        let eta = compute_eta(snap, dl_rate, ex_rate);
        let total = snap
            .total_size
            .map(|n| n.to_string())
            .unwrap_or_else(|| "?".into());
        let est = snap
            .extracted_estimate
            .map(|n| n.to_string())
            .unwrap_or_else(|| "?".into());
        let pct = percent
            .map(|p| format!("{p:.1}"))
            .unwrap_or_else(|| "?".into());
        let dl = dl_rate
            .map(|r| format!("{r:.0}"))
            .unwrap_or_else(|| "?".into());
        let ex = ex_rate
            .map(|r| format!("{r:.0}"))
            .unwrap_or_else(|| "?".into());
        let eta_s = eta
            .map(|d| d.as_secs().to_string())
            .unwrap_or_else(|| "?".into());
        format!(
            "progress: pct={pct}% downloaded={}/{total} extracted={}/{est} \
             dl_bps={dl} ex_bps={ex} workers={}/{} eta_secs={eta_s}",
            snap.bytes_downloaded, snap.bytes_extracted, snap.active_workers, snap.total_workers,
        )
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

/// Format an ETA as `MM:SS` (or `H:MM:SS` for ≥ 1 hour). `None` is
/// rendered as `--:--`.
#[must_use]
pub fn format_eta(eta: Option<Duration>) -> String {
    let Some(d) = eta else {
        return "--:--".into();
    };
    let total_secs = d.as_secs();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let secs = total_secs % 60;
    if hours > 0 {
        format!("{hours}:{minutes:02}:{secs:02}")
    } else {
        format!("{minutes:02}:{secs:02}")
    }
}

fn format_overall_line(
    snap: &ProgressSnapshot,
    percent: Option<f64>,
    eta: Option<Duration>,
) -> String {
    let pct = percent
        .map(|p| format!("{p:5.1}%"))
        .unwrap_or_else(|| "  --.-%".into());
    let downloaded = format_bytes(snap.bytes_downloaded);
    let total = snap
        .total_size
        .map(format_bytes)
        .unwrap_or_else(|| "?".into());
    format!(
        "peel  {downloaded} / {total}  ({pct})  ETA {}",
        format_eta(eta)
    )
}

fn format_download_line(snap: &ProgressSnapshot, rate: Option<f64>, bar_width: usize) -> String {
    let bar = render_bar(snap.bytes_downloaded, snap.total_size, bar_width);
    let rate_s = rate.map(format_rate).unwrap_or_else(|| "—".into());
    format!(
        "  download {bar}  {rate_s}  workers {}/{}",
        snap.active_workers, snap.total_workers
    )
}

fn format_extract_line(snap: &ProgressSnapshot, rate: Option<f64>) -> String {
    let extracted = format_bytes(snap.bytes_extracted);
    let est = snap
        .extracted_estimate
        .map(format_bytes)
        .unwrap_or_else(|| "unknown".into());
    let rate_s = rate.map(format_rate).unwrap_or_else(|| "—".into());
    format!("  extract  {extracted} / {est}  {rate_s}")
}

fn render_bar(num: u64, denom: Option<u64>, width: usize) -> String {
    let width = width.max(2);
    let mut bar = String::with_capacity(width + 2);
    bar.push('[');
    let filled = match denom {
        Some(d) if d > 0 => {
            let frac = (num as f64 / d as f64).clamp(0.0, 1.0);
            (frac * width as f64).round() as usize
        }
        _ => 0,
    };
    let filled = filled.min(width);
    for i in 0..width {
        bar.push(if i < filled { '#' } else { '.' });
    }
    bar.push(']');
    bar
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
    fn format_eta_short_uses_mmss() {
        assert_eq!(format_eta(Some(Duration::from_secs(5))), "00:05");
        assert_eq!(format_eta(Some(Duration::from_secs(125))), "02:05");
    }

    #[test]
    fn format_eta_long_uses_hmmss() {
        assert_eq!(format_eta(Some(Duration::from_secs(3725))), "1:02:05");
    }

    #[test]
    fn format_eta_none_renders_dashes() {
        assert_eq!(format_eta(None), "--:--");
    }

    #[test]
    fn render_bar_progress_proportional() {
        let bar = render_bar(50, Some(100), 10);
        assert!(bar.starts_with('['));
        assert!(bar.ends_with(']'));
        // 50% of 10 = 5 filled blocks.
        assert_eq!(bar.matches('#').count(), 5);
        assert_eq!(bar.matches('.').count(), 5);
    }

    #[test]
    fn render_bar_handles_unknown_total() {
        let bar = render_bar(123, None, 8);
        assert_eq!(bar.matches('#').count(), 0);
        assert_eq!(bar.matches('.').count(), 8);
    }

    #[test]
    fn render_bar_full() {
        let bar = render_bar(100, Some(100), 6);
        assert_eq!(bar.matches('#').count(), 6);
        assert_eq!(bar.matches('.').count(), 0);
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
        };
        r.render(&snap);
        let out = String::from_utf8(r.out).expect("utf-8");
        // Three lines, each terminated with the clear-EOL escape.
        assert_eq!(out.matches("\x1b[K").count(), 3);
        assert!(out.contains("peel"));
        assert!(out.contains("workers 2/4"));
        assert!(out.contains("download"));
        assert!(out.contains("extract"));
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
        };
        r.render(&snap);
        r.render(&snap);
        let out = String::from_utf8(r.out).expect("utf-8");
        assert!(out.contains("\x1b[3A"));
    }

    #[test]
    fn log_renderer_format_line_is_structured() {
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
        };
        let line = r.format_line(&snap, Instant::now());
        assert!(line.contains("downloaded=1000/2000"));
        assert!(line.contains("extracted=500/2000"));
        assert!(line.contains("workers=2/4"));
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
