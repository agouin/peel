//! Adaptive chunk-size policy for the download scheduler
//! (`internal/PLAN_v2.md` §8).
//!
//! The policy observes per-dispatch completion latencies and the
//! retry rate, and decides whether to grow or shrink the **dispatch
//! size** — the number of bytes the scheduler asks a worker to fetch
//! in one ranged GET. Growing is useful when the network is fast and
//! the workers are CPU-light; shrinking is useful when the upstream
//! starts injecting 5xx errors or the per-chunk latency spikes
//! (typically a sign of a saturated link or per-connection
//! throttling).
//!
//! # Mechanism
//!
//! The bitmap's chunk-size — the **planning unit** stored in the
//! checkpoint — is fixed for the lifetime of a run. The policy
//! controls how many consecutive bitmap chunks the scheduler
//! coalesces into a single worker task. So if the bitmap chunk-size
//! is 1 MiB and the policy's current target is 16 MiB, each worker
//! task covers 16 contiguous bitmap chunks (one ranged GET, one
//! `pwrite_at`). When the policy decides to halve, the next dispatch
//! covers 8 chunks; halving again, 4; and so on down to 1 chunk.
//!
//! # Invariants
//!
//! - The current target is always a multiple of the bitmap chunk
//!   size (so it maps to a whole number of chunks).
//! - The current target is in `[bitmap_chunk_size, MAX_DISPATCH_BYTES]`.
//! - Resize decisions are gated by [`HYSTERESIS`] — at most one
//!   resize per 30 s of wall-clock time, regardless of how many
//!   samples have come in.
//!
//! # Resume
//!
//! Per `PLAN_v2.md` §8 step 3, the simpler implementation freezes the
//! bitmap chunk-size at the size present at first checkpoint and
//! does not re-tune across resumes. The bitmap chunk-size lives in
//! the checkpoint (already there since `PLAN.md` §9); the policy
//! itself is *not* persisted — every resume starts fresh at the
//! configured initial dispatch size, with hysteresis observed from
//! the resume's start.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Hard floor on the dispatch size. Per `PLAN_v2.md` §8: 1 MiB.
///
/// The *effective* floor is `max(MIN_DISPATCH_BYTES, bitmap_chunk_size)`
/// because the scheduler can never dispatch less than one whole bitmap
/// chunk — the bitmap is the unit of completion.
pub const MIN_DISPATCH_BYTES: u64 = 1024 * 1024;

/// Hard cap on the dispatch size. Per `PLAN_v2.md` §8: 64 MiB.
pub const MAX_DISPATCH_BYTES: u64 = 64 * 1024 * 1024;

/// Default initial dispatch size when adaptive is enabled. Matches the
/// pre-§8 fixed default so users see no behavior change at start-up.
pub const DEFAULT_INITIAL_DISPATCH_BYTES: u64 = 4 * 1024 * 1024;

/// Hysteresis: the policy waits this long after each resize before
/// considering another. Prevents oscillation when the workload is
/// near a threshold.
pub const HYSTERESIS: Duration = Duration::from_secs(30);

/// Number of recent samples retained for percentile / mean queries.
/// Sized for the demo cadence (typical chunk completes in ~100 ms to
/// a few seconds; 64 samples spans the last ~5–60 s of activity).
pub const SAMPLE_CAPACITY: usize = 64;

/// Threshold under which a sample is "fast." Per `PLAN_v2.md` §8:
/// "all workers consistently complete chunks in < 1 s" is the grow
/// signal.
pub const GROW_LATENCY_THRESHOLD: Duration = Duration::from_secs(1);

/// p95 latency threshold for the shrink signal. Per `PLAN_v2.md` §8.
pub const SHRINK_P95_THRESHOLD: Duration = Duration::from_secs(5);

/// Retry-rate threshold for the shrink signal: more than 10 % of
/// recent dispatches needing a retry.
pub const SHRINK_RETRY_RATIO: f64 = 0.10;

/// Lower bound on samples before any resize decision fires. Below
/// this we have too little data for a meaningful percentile or mean.
const MIN_SAMPLES_FOR_DECISION: usize = 8;

/// One observation submitted to the policy after a worker completes a
/// dispatch.
#[derive(Debug, Clone, Copy)]
pub struct Sample {
    /// Wall-clock instant the sample was recorded.
    pub at: Instant,
    /// How long the worker spent fetching + writing the dispatch.
    pub elapsed: Duration,
    /// True iff the dispatch needed at least one retry. Used to
    /// approximate the upstream's stability.
    pub retried: bool,
}

/// What [`ChunkSizePolicy::evaluate`] decided this tick.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ResizeDecision {
    /// Keep the current dispatch size.
    Hold,
    /// Move the dispatch size up to `new`.
    Grow {
        /// Previous dispatch size in bytes.
        old: u64,
        /// New dispatch size in bytes.
        new: u64,
    },
    /// Move the dispatch size down to `new`.
    Shrink {
        /// Previous dispatch size in bytes.
        old: u64,
        /// New dispatch size in bytes.
        new: u64,
    },
}

/// Adaptive chunk-size policy.
///
/// Threading: the `current_size` field is an atomic — workers read
/// the current target without taking a lock. Sample submission goes
/// through a [`Mutex`]; the lock-side critical section is small (a
/// `VecDeque::push_back` and an old-sample eviction). The scheduler
/// thread is the only [`Self::evaluate`] caller, so contention on
/// the mutex is limited to "writers post samples" vs. "scheduler
/// reads samples for a decision" — both rare relative to the network
/// cadence.
///
/// # Construction
///
/// Use [`ChunkSizePolicy::new`] for the production defaults, or
/// [`ChunkSizePolicy::with_bounds`] when tests need a smaller floor /
/// cap to make the behaviour observable.
#[derive(Debug)]
pub struct ChunkSizePolicy {
    bitmap_chunk_size: u64,
    min_dispatch: u64,
    max_dispatch: u64,
    current_size: AtomicU64,
    inner: Mutex<PolicyInner>,
    hysteresis: Duration,
}

#[derive(Debug)]
struct PolicyInner {
    samples: VecDeque<Sample>,
    last_change: Option<Instant>,
    /// Created at construction; used as the "earliest evaluable"
    /// instant when no resize has happened yet, so the very first
    /// hysteresis check has a stable reference point.
    created_at: Instant,
}

impl ChunkSizePolicy {
    /// Construct a policy with the production defaults.
    ///
    /// `bitmap_chunk_size` is the size of one bitmap chunk in bytes —
    /// the policy never returns a target smaller than this. `initial`
    /// is the starting dispatch size; it is clamped to
    /// `[max(bitmap_chunk_size, MIN_DISPATCH_BYTES), MAX_DISPATCH_BYTES]`
    /// and rounded down to a multiple of `bitmap_chunk_size`.
    ///
    /// # Panics
    ///
    /// Panics if `bitmap_chunk_size == 0`.
    #[must_use]
    pub fn new(bitmap_chunk_size: u64, initial: u64) -> Self {
        Self::with_bounds(
            bitmap_chunk_size,
            initial,
            MIN_DISPATCH_BYTES,
            MAX_DISPATCH_BYTES,
            HYSTERESIS,
        )
    }

    /// Construct a policy with explicit bounds. Tests use this to
    /// observe behaviour at smaller scales than the production
    /// defaults allow.
    ///
    /// # Panics
    ///
    /// Panics if `bitmap_chunk_size == 0` or `min > max`.
    #[must_use]
    pub fn with_bounds(
        bitmap_chunk_size: u64,
        initial: u64,
        min_dispatch: u64,
        max_dispatch: u64,
        hysteresis: Duration,
    ) -> Self {
        assert!(bitmap_chunk_size > 0, "bitmap_chunk_size must be > 0");
        assert!(min_dispatch <= max_dispatch, "min must be <= max");
        let effective_min =
            round_up_to_chunk(min_dispatch.max(bitmap_chunk_size), bitmap_chunk_size);
        let effective_max = round_down_to_chunk(max_dispatch.max(effective_min), bitmap_chunk_size);
        let initial = clamp_and_align(initial, effective_min, effective_max, bitmap_chunk_size);
        Self {
            bitmap_chunk_size,
            min_dispatch: effective_min,
            max_dispatch: effective_max,
            current_size: AtomicU64::new(initial),
            inner: Mutex::new(PolicyInner {
                samples: VecDeque::with_capacity(SAMPLE_CAPACITY),
                last_change: None,
                created_at: Instant::now(),
            }),
            hysteresis,
        }
    }

    /// The bitmap chunk-size the policy was constructed against.
    #[must_use]
    pub fn bitmap_chunk_size(&self) -> u64 {
        self.bitmap_chunk_size
    }

    /// The effective floor in bytes (always `>= bitmap_chunk_size`).
    #[must_use]
    pub fn min_dispatch(&self) -> u64 {
        self.min_dispatch
    }

    /// The effective cap in bytes.
    #[must_use]
    pub fn max_dispatch(&self) -> u64 {
        self.max_dispatch
    }

    /// The current target dispatch size in bytes.
    #[must_use]
    pub fn current(&self) -> u64 {
        self.current_size.load(Ordering::Acquire)
    }

    /// Record a completed dispatch. Cheap: pushes one entry to a
    /// bounded ring buffer.
    pub fn record(&self, sample: Sample) {
        // INVARIANT: a poisoned mutex here only happens if a previous
        // holder panicked, which is bounded to a panic in our own
        // small critical sections; the scheduler treats poisoning as
        // "drop the sample" rather than crashing the whole download.
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        if inner.samples.len() == SAMPLE_CAPACITY {
            inner.samples.pop_front();
        }
        inner.samples.push_back(sample);
    }

    /// Decide whether to resize and apply the change atomically.
    ///
    /// `now` is the wall-clock instant the scheduler is on; the
    /// policy uses it for the hysteresis check. `remaining_chunks`
    /// is the number of bitmap chunks still incomplete;
    /// `workers` is the spawned-worker count. The grow rule
    /// requires `>= 2 × workers chunks remaining` to avoid oversizing
    /// the dispatch unit when only the tail of the file is left.
    pub fn evaluate(&self, now: Instant, remaining_chunks: u64, workers: u32) -> ResizeDecision {
        // INVARIANT: a poisoned mutex here only happens if a previous
        // holder panicked; treat it as "no decision available this
        // tick" rather than crashing.
        let Ok(mut inner) = self.inner.lock() else {
            return ResizeDecision::Hold;
        };

        // Hysteresis: respect the floor regardless of which side a
        // resize is being requested from. The first decision uses
        // `created_at` as the reference so a long start-up doesn't
        // bypass the floor.
        let last = inner.last_change.unwrap_or(inner.created_at);
        if now.saturating_duration_since(last) < self.hysteresis {
            return ResizeDecision::Hold;
        }

        if inner.samples.len() < MIN_SAMPLES_FOR_DECISION {
            return ResizeDecision::Hold;
        }

        // Snapshot the metrics we need; drop the borrow before any
        // atomic mutation so the lock window stays small.
        let mut latencies: Vec<Duration> = inner.samples.iter().map(|s| s.elapsed).collect();
        let retried_count = inner.samples.iter().filter(|s| s.retried).count();
        let total_samples = inner.samples.len();

        let current = self.current_size.load(Ordering::Acquire);

        // Shrink rule:
        //   - p95 latency over the recent window > SHRINK_P95_THRESHOLD, or
        //   - retry rate over the recent window > SHRINK_RETRY_RATIO.
        let p95 = percentile(&mut latencies, 0.95).unwrap_or_default();
        let retry_ratio = retried_count as f64 / total_samples as f64;
        if (p95 > SHRINK_P95_THRESHOLD || retry_ratio > SHRINK_RETRY_RATIO)
            && current > self.min_dispatch
        {
            let new = current
                .checked_div(2)
                .unwrap_or(self.min_dispatch)
                .max(self.min_dispatch);
            let new = round_up_to_chunk(new, self.bitmap_chunk_size).min(self.max_dispatch);
            if new < current {
                self.current_size.store(new, Ordering::Release);
                inner.last_change = Some(now);
                inner.samples.clear();
                return ResizeDecision::Shrink { old: current, new };
            }
        }

        // Grow rule:
        //   - all recent samples completed in < GROW_LATENCY_THRESHOLD, and
        //   - remaining_chunks >= 2 × workers.
        let workers_u64 = u64::from(workers.max(1));
        let all_fast = inner
            .samples
            .iter()
            .all(|s| s.elapsed < GROW_LATENCY_THRESHOLD);
        let plenty_of_work = remaining_chunks >= workers_u64.saturating_mul(2);
        if all_fast && plenty_of_work && current < self.max_dispatch {
            let new = current
                .checked_mul(2)
                .unwrap_or(self.max_dispatch)
                .min(self.max_dispatch);
            let new = round_down_to_chunk(new, self.bitmap_chunk_size).max(self.min_dispatch);
            if new > current {
                self.current_size.store(new, Ordering::Release);
                inner.last_change = Some(now);
                inner.samples.clear();
                return ResizeDecision::Grow { old: current, new };
            }
        }

        ResizeDecision::Hold
    }

    /// Diagnostic accessor: how many samples are currently in the
    /// ring buffer. Tests use this to verify sample bookkeeping.
    #[must_use]
    pub fn sample_count(&self) -> usize {
        match self.inner.lock() {
            Ok(g) => g.samples.len(),
            Err(_) => 0,
        }
    }
}

/// Linear-interpolation percentile over `samples`. Sorts in place.
/// Returns `None` for an empty slice; rounds the percentile rank to a
/// nearest-rank index so a 64-sample buffer at p=0.95 returns the
/// 60th-smallest entry, which is the conservative reading.
fn percentile(samples: &mut [Duration], p: f64) -> Option<Duration> {
    if samples.is_empty() {
        return None;
    }
    samples.sort();
    let n = samples.len();
    let idx = ((p * n as f64).ceil() as usize).clamp(1, n) - 1;
    Some(samples[idx])
}

fn round_up_to_chunk(bytes: u64, chunk: u64) -> u64 {
    if chunk == 0 {
        return bytes;
    }
    let r = bytes % chunk;
    if r == 0 {
        bytes
    } else {
        bytes.saturating_add(chunk - r)
    }
}

fn round_down_to_chunk(bytes: u64, chunk: u64) -> u64 {
    if chunk == 0 {
        return bytes;
    }
    bytes - (bytes % chunk)
}

fn clamp_and_align(value: u64, min: u64, max: u64, chunk: u64) -> u64 {
    let clamped = value.clamp(min, max);
    let aligned = round_down_to_chunk(clamped, chunk).max(min);
    aligned.min(max)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(at: Instant, ms: u64, retried: bool) -> Sample {
        Sample {
            at,
            elapsed: Duration::from_millis(ms),
            retried,
        }
    }

    #[test]
    fn new_clamps_initial_into_range() {
        // Initial below min → starts at min.
        let p =
            ChunkSizePolicy::with_bounds(1024, 512, 2 * 1024, 64 * 1024, Duration::from_millis(10));
        assert_eq!(p.current(), 2 * 1024);

        // Initial above max → starts at max.
        let p = ChunkSizePolicy::with_bounds(
            1024,
            1_000_000,
            2 * 1024,
            64 * 1024,
            Duration::from_millis(10),
        );
        assert_eq!(p.current(), 64 * 1024);
    }

    #[test]
    fn min_floor_respects_bitmap_chunk_size() {
        // bitmap_chunk_size > MIN_DISPATCH_BYTES requested → floor
        // should be the bitmap chunk size, not MIN.
        let p = ChunkSizePolicy::with_bounds(
            8 * 1024,
            8 * 1024,
            1024,
            128 * 1024,
            Duration::from_millis(10),
        );
        assert_eq!(p.min_dispatch(), 8 * 1024);
    }

    #[test]
    fn current_aligned_to_bitmap_chunk_size() {
        let p =
            ChunkSizePolicy::with_bounds(1024, 5_000, 1024, 64 * 1024, Duration::from_millis(10));
        assert_eq!(p.current() % 1024, 0);
    }

    #[test]
    fn record_caps_at_capacity() {
        let p = ChunkSizePolicy::new(1024, 4 * 1024);
        let now = Instant::now();
        for i in 0..(SAMPLE_CAPACITY * 2) {
            p.record(sample(now + Duration::from_millis(i as u64), 100, false));
        }
        assert!(p.sample_count() <= SAMPLE_CAPACITY);
    }

    #[test]
    fn evaluate_holds_below_min_samples() {
        let p =
            ChunkSizePolicy::with_bounds(1024, 4 * 1024, 1024, 64 * 1024, Duration::from_millis(0));
        let now = Instant::now();
        // Only a few samples — not enough to decide.
        for i in 0..3 {
            p.record(sample(now, 100, false));
            let _ = i;
        }
        assert_eq!(
            p.evaluate(now + Duration::from_millis(1), 1000, 4),
            ResizeDecision::Hold
        );
    }

    #[test]
    fn evaluate_grows_when_all_fast_and_plenty_of_work() {
        let p =
            ChunkSizePolicy::with_bounds(1024, 4 * 1024, 1024, 64 * 1024, Duration::from_millis(0));
        let now = Instant::now();
        for _ in 0..MIN_SAMPLES_FOR_DECISION {
            p.record(sample(now, 100, false));
        }
        let decision = p.evaluate(now + Duration::from_millis(1), 1000, 4);
        match decision {
            ResizeDecision::Grow { old, new } => {
                assert_eq!(old, 4 * 1024);
                assert_eq!(new, 8 * 1024);
            }
            other => panic!("expected Grow, got {other:?}"),
        }
        assert_eq!(p.current(), 8 * 1024);
    }

    #[test]
    fn evaluate_does_not_grow_when_remaining_too_small() {
        let p =
            ChunkSizePolicy::with_bounds(1024, 4 * 1024, 1024, 64 * 1024, Duration::from_millis(0));
        let now = Instant::now();
        for _ in 0..MIN_SAMPLES_FOR_DECISION {
            p.record(sample(now, 100, false));
        }
        // workers = 4 → need >= 8 chunks remaining; pass 5.
        assert_eq!(
            p.evaluate(now + Duration::from_millis(1), 5, 4),
            ResizeDecision::Hold
        );
        assert_eq!(p.current(), 4 * 1024);
    }

    #[test]
    fn evaluate_shrinks_on_p95_spike() {
        let p =
            ChunkSizePolicy::with_bounds(1024, 8 * 1024, 1024, 64 * 1024, Duration::from_millis(0));
        let now = Instant::now();
        // Most samples fast, but a few way over the 5 s threshold —
        // p95 must exceed.
        for _ in 0..(MIN_SAMPLES_FOR_DECISION - 2) {
            p.record(sample(now, 100, false));
        }
        for _ in 0..3 {
            p.record(sample(now, 7_000, false));
        }
        let decision = p.evaluate(now + Duration::from_millis(1), 1000, 4);
        match decision {
            ResizeDecision::Shrink { old, new } => {
                assert_eq!(old, 8 * 1024);
                assert_eq!(new, 4 * 1024);
            }
            other => panic!("expected Shrink, got {other:?}"),
        }
        assert_eq!(p.current(), 4 * 1024);
    }

    #[test]
    fn evaluate_shrinks_on_retry_ratio() {
        let p = ChunkSizePolicy::with_bounds(
            1024,
            16 * 1024,
            1024,
            64 * 1024,
            Duration::from_millis(0),
        );
        let now = Instant::now();
        // 8 samples; 2 of them retried = 25 % > 10 %.
        for i in 0..MIN_SAMPLES_FOR_DECISION {
            let retried = i < 2;
            p.record(sample(now, 100, retried));
        }
        match p.evaluate(now + Duration::from_millis(1), 1000, 4) {
            ResizeDecision::Shrink { new, .. } => assert_eq!(new, 8 * 1024),
            other => panic!("expected Shrink, got {other:?}"),
        }
    }

    #[test]
    fn evaluate_does_not_shrink_below_floor() {
        let p = ChunkSizePolicy::with_bounds(1024, 1024, 1024, 64 * 1024, Duration::from_millis(0));
        let now = Instant::now();
        for _ in 0..MIN_SAMPLES_FOR_DECISION {
            p.record(sample(now, 7_000, true));
        }
        assert_eq!(
            p.evaluate(now + Duration::from_millis(1), 1000, 4),
            ResizeDecision::Hold
        );
    }

    #[test]
    fn evaluate_does_not_grow_above_cap() {
        let p =
            ChunkSizePolicy::with_bounds(1024, 4 * 1024, 1024, 4 * 1024, Duration::from_millis(0));
        let now = Instant::now();
        for _ in 0..MIN_SAMPLES_FOR_DECISION {
            p.record(sample(now, 100, false));
        }
        assert_eq!(
            p.evaluate(now + Duration::from_millis(1), 1000, 4),
            ResizeDecision::Hold
        );
    }

    #[test]
    fn hysteresis_blocks_back_to_back_changes() {
        let hyst = Duration::from_millis(100);
        let p = ChunkSizePolicy::with_bounds(1024, 4 * 1024, 1024, 64 * 1024, hyst);
        let now = Instant::now();
        for _ in 0..MIN_SAMPLES_FOR_DECISION {
            p.record(sample(now, 100, false));
        }
        // First evaluation must wait out hysteresis from `created_at`.
        assert_eq!(
            p.evaluate(now + Duration::from_millis(1), 1000, 4),
            ResizeDecision::Hold
        );
        // After hysteresis elapses, growth fires.
        let after = now + hyst + Duration::from_millis(1);
        assert!(matches!(
            p.evaluate(after, 1000, 4),
            ResizeDecision::Grow { .. }
        ));
        // Refill samples; second evaluation is again gated.
        for _ in 0..MIN_SAMPLES_FOR_DECISION {
            p.record(sample(after, 100, false));
        }
        assert_eq!(
            p.evaluate(after + Duration::from_millis(1), 1000, 4),
            ResizeDecision::Hold
        );
    }

    #[test]
    fn growth_clears_old_samples_so_next_decision_uses_fresh_data() {
        let hyst = Duration::from_millis(0);
        let p = ChunkSizePolicy::with_bounds(1024, 4 * 1024, 1024, 64 * 1024, hyst);
        let now = Instant::now();
        for _ in 0..MIN_SAMPLES_FOR_DECISION {
            p.record(sample(now, 100, false));
        }
        let _ = p.evaluate(now + Duration::from_millis(1), 1000, 4);
        // Buffer cleared.
        assert_eq!(p.sample_count(), 0);
    }

    #[test]
    fn percentile_basic() {
        let mut v: Vec<Duration> = (1..=10).map(Duration::from_millis).collect();
        // p95 over 10 entries → ceil(0.95*10)=10 → idx 9 → 10 ms.
        assert_eq!(percentile(&mut v, 0.95).unwrap(), Duration::from_millis(10));
        // p50 over 10 entries → ceil(0.5*10)=5 → idx 4 → 5 ms.
        let mut v: Vec<Duration> = (1..=10).map(Duration::from_millis).collect();
        assert_eq!(percentile(&mut v, 0.5).unwrap(), Duration::from_millis(5));
    }

    #[test]
    fn percentile_empty_is_none() {
        let mut v: Vec<Duration> = Vec::new();
        assert!(percentile(&mut v, 0.5).is_none());
    }

    #[test]
    fn rounding_helpers() {
        assert_eq!(round_up_to_chunk(0, 1024), 0);
        assert_eq!(round_up_to_chunk(1, 1024), 1024);
        assert_eq!(round_up_to_chunk(1024, 1024), 1024);
        assert_eq!(round_up_to_chunk(1025, 1024), 2048);

        assert_eq!(round_down_to_chunk(0, 1024), 0);
        assert_eq!(round_down_to_chunk(1023, 1024), 0);
        assert_eq!(round_down_to_chunk(1024, 1024), 1024);
        assert_eq!(round_down_to_chunk(1025, 1024), 1024);
    }
}
