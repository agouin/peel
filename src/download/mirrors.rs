//! Multi-mirror routing (`PLAN_v2.md` §13).
//!
//! A [`MirrorSet`] holds the **primary** URL plus zero or more
//! `--mirror`-supplied alternates that all serve byte-identical copies
//! of the same source. The download workers pick a live mirror per
//! ranged-GET attempt; failing mirrors are excluded for a backoff
//! window and retried thereafter.
//!
//! # Picking
//!
//! Each mirror carries a small block of atomics — `excluded_until_ns`
//! (an offset from the set's creation timestamp), `in_flight`,
//! `latency_ema_ns`, `successes`, `failures`. [`MirrorSet::pick`]
//! scans the live mirrors and returns the index of the one with the
//! lowest `(in_flight + 1) * max(latency_ema_ns, 1)` score, biasing
//! new dispatches toward fast, idle mirrors. Ties resolve by the
//! mirror's position in the set (primary first).
//!
//! [`MirrorSet::pick_or_wait`] returns immediately when a live mirror
//! exists, otherwise sleeps in short increments until one's exclusion
//! window expires, the `cancel` flag flips, or the supplied deadline
//! passes. The "wait until a mirror recovers" path keeps a transient
//! all-mirrors-failed cluster from torpedoing the whole download.
//!
//! # Recording outcomes
//!
//! - [`MirrorSet::record_success`] decrements `in_flight`, updates the
//!   latency EMA, and bumps `successes`.
//! - [`MirrorSet::record_failure`] decrements `in_flight`, sets the
//!   exclusion window, and bumps `failures`.
//!
//! Both methods are safe to call concurrently from any number of
//! workers; the entire surface is lock-free apart from the
//! short-lived sleep inside `pick_or_wait`.

#![cfg(unix)]

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use super::worker::SourceFingerprint;
use crate::http::Url;

/// Default exclusion window after a mirror failure
/// (`PLAN_v2.md` §13: "that mirror is excluded for 30 s").
pub const DEFAULT_MIRROR_EXCLUDE_FOR: Duration = Duration::from_secs(30);

/// Default cap on how long [`MirrorSet::pick_or_wait`] will block
/// when every mirror is currently excluded. The picker re-checks at
/// short intervals so the call returns promptly once any mirror
/// recovers; the cap keeps a wedged cluster from blocking forever.
pub const DEFAULT_MIRROR_PICK_DEADLINE: Duration = Duration::from_secs(60);

/// Sleep granularity inside [`MirrorSet::pick_or_wait`] while every
/// mirror is excluded.
const PICK_SLEEP_STEP: Duration = Duration::from_millis(50);

/// One mirror in the set: its URL plus the source-identity headers
/// captured at HEAD time.
///
/// Each mirror retains its own [`SourceFingerprint`] because a CDN
/// and an origin server commonly differ in their `ETag` scheme even
/// when the underlying bytes match. The agreement check in
/// [`crate::download::discover_with_mirrors`] decides which mirrors
/// are kept; once they're in a [`MirrorSet`], the worker validates
/// each per-attempt response against the *picked* mirror's fingerprint.
#[derive(Debug, Clone)]
pub struct Mirror {
    /// URL the worker issues ranged GETs against.
    pub url: Url,
    /// `ETag` / `Last-Modified` recorded for *this* mirror at HEAD
    /// time. Verified per response against the same headers.
    pub fingerprint: SourceFingerprint,
}

impl Mirror {
    /// Construct a mirror.
    #[must_use]
    pub fn new(url: Url, fingerprint: SourceFingerprint) -> Self {
        Self { url, fingerprint }
    }
}

/// Per-mirror health counters, all atomic.
///
/// Stored in a parallel `Vec` next to the mirrors so a slot-free
/// `for (mirror, health) in zip(...)` walk works for the picker.
#[derive(Debug, Default)]
struct MirrorHealth {
    /// Mirror is excluded until this many ns after the
    /// [`MirrorSet`]'s `epoch`. `0` means "live".
    excluded_until_ns: AtomicU64,
    /// Outstanding requests currently routed to this mirror. Used as
    /// the picker's load-balancing tiebreaker.
    in_flight: AtomicU32,
    /// Exponential moving average of recent successful response
    /// latencies, in ns. `0` means "no samples yet"; the picker
    /// treats it as 1 ns to keep the comparison meaningful.
    latency_ema_ns: AtomicU64,
    /// Total successful completions.
    successes: AtomicU64,
    /// Total failures.
    failures: AtomicU64,
}

/// EMA smoothing factor — bigger = more responsive to recent samples.
/// We use a 1/8 weight for the new sample, which matches the
/// `tcp_rtt` smoother in BSD-derived stacks closely enough.
const EMA_NUMERATOR: u64 = 1;
const EMA_DENOMINATOR: u64 = 8;

/// A pool of mirrors plus per-mirror health.
///
/// Constructed with at least one mirror (the primary). Workers pick
/// per dispatch via [`Self::pick_or_wait`] and report outcomes via
/// [`Self::record_success`] / [`Self::record_failure`].
#[derive(Debug)]
pub struct MirrorSet {
    mirrors: Vec<Mirror>,
    health: Vec<MirrorHealth>,
    epoch: Instant,
    exclude_for_ns: u64,
}

impl MirrorSet {
    /// Construct a set from one or more mirrors. Panics if `mirrors`
    /// is empty — the call sites guarantee at least the primary is
    /// present, so this is an invariant violation, not a user-facing
    /// error.
    ///
    /// The first mirror is the **primary** and is what fallback paths
    /// (single-stream, format detection, etc.) consult when they need
    /// a single canonical URL.
    #[must_use]
    pub fn new(mirrors: Vec<Mirror>) -> Self {
        Self::with_exclude_for(mirrors, DEFAULT_MIRROR_EXCLUDE_FOR)
    }

    /// Like [`Self::new`] but with a custom exclusion window. Tests
    /// pass a small value (e.g. 100 ms) so a "mirror recovers" path
    /// can fire within the test timeout.
    #[must_use]
    pub fn with_exclude_for(mirrors: Vec<Mirror>, exclude_for: Duration) -> Self {
        // INVARIANT: every public call site (CLI parsing, coordinator
        // bootstrap, tests) guarantees at least the primary URL is
        // present. An empty MirrorSet is unreachable by construction.
        assert!(!mirrors.is_empty(), "MirrorSet requires >= 1 mirror");
        let n = mirrors.len();
        let mut health = Vec::with_capacity(n);
        for _ in 0..n {
            health.push(MirrorHealth::default());
        }
        let exclude_for_ns = u64::try_from(exclude_for.as_nanos()).unwrap_or(u64::MAX);
        Self {
            mirrors,
            health,
            epoch: Instant::now(),
            exclude_for_ns,
        }
    }

    /// Convenience for the common "no `--mirror` flags given" case:
    /// build a one-element set from the primary URL and fingerprint.
    #[must_use]
    pub fn single(url: Url, fingerprint: SourceFingerprint) -> Self {
        Self::new(vec![Mirror::new(url, fingerprint)])
    }

    /// Number of mirrors in the set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.mirrors.len()
    }

    /// Always `false` — the constructor enforces a non-empty set.
    /// Provided to satisfy `clippy::len-without-is-empty`; callers
    /// should not need it.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// True iff the set has more than one mirror.
    #[must_use]
    pub fn has_alternates(&self) -> bool {
        self.mirrors.len() > 1
    }

    /// Borrow the primary mirror (the first one).
    #[must_use]
    pub fn primary(&self) -> &Mirror {
        &self.mirrors[0]
    }

    /// Borrow the mirror at `idx`.
    #[must_use]
    pub fn mirror(&self, idx: usize) -> &Mirror {
        &self.mirrors[idx]
    }

    /// Number of mirrors currently *not* excluded. O(N).
    #[must_use]
    pub fn live_count(&self) -> usize {
        let now_ns = self.now_ns();
        self.health
            .iter()
            .filter(|h| h.excluded_until_ns.load(Ordering::Relaxed) <= now_ns)
            .count()
    }

    /// Record a successful completion against `idx`.
    ///
    /// Decrements `in_flight`, updates the latency EMA, and bumps
    /// `successes`. Treats `idx` out of range as a no-op so callers
    /// don't have to gate on the index.
    pub fn record_success(&self, idx: usize, latency: Duration) {
        let Some(h) = self.health.get(idx) else {
            return;
        };
        h.in_flight.fetch_sub(1, Ordering::Relaxed);
        let sample_ns = u64::try_from(latency.as_nanos()).unwrap_or(u64::MAX);
        let prev = h.latency_ema_ns.load(Ordering::Relaxed);
        let next = if prev == 0 {
            sample_ns
        } else {
            // EMA: new = old * (1 - w) + sample * w, with
            // w = EMA_NUMERATOR / EMA_DENOMINATOR.
            let old_part = prev / EMA_DENOMINATOR * (EMA_DENOMINATOR - EMA_NUMERATOR);
            let new_part = sample_ns / EMA_DENOMINATOR * EMA_NUMERATOR;
            old_part.saturating_add(new_part)
        };
        h.latency_ema_ns.store(next, Ordering::Relaxed);
        h.successes.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failure against `idx`. Excludes the mirror for the
    /// configured backoff window (multi-mirror runs only) and bumps
    /// `failures`.
    ///
    /// In **single-mirror** runs the exclusion window is skipped:
    /// excluding the only mirror would wedge the picker until the
    /// window expires, defeating the worker's existing retry-with-
    /// backoff behaviour. The failure counter still increments so
    /// diagnostics remain meaningful.
    pub fn record_failure(&self, idx: usize) {
        let Some(h) = self.health.get(idx) else {
            return;
        };
        h.in_flight.fetch_sub(1, Ordering::Relaxed);
        if self.mirrors.len() > 1 {
            let now_ns = self.now_ns();
            let until = now_ns.saturating_add(self.exclude_for_ns);
            // The picker only excludes mirrors whose
            // `excluded_until_ns` is in the future; storing the
            // larger of the existing and new value preserves a
            // longer pre-existing window if a racing failure
            // happened to set one.
            let prev = h.excluded_until_ns.load(Ordering::Relaxed);
            if until > prev {
                h.excluded_until_ns.store(until, Ordering::Relaxed);
            }
        }
        h.failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Pick the index of a live mirror, returning `None` if every
    /// mirror is currently excluded.
    ///
    /// This **does not** increment `in_flight`. Callers that intend
    /// to actually use the picked mirror should use
    /// [`Self::pick_or_wait`] which atomically claims an in-flight
    /// slot, or call [`Self::claim`] manually after picking.
    #[must_use]
    pub fn pick(&self) -> Option<usize> {
        let now_ns = self.now_ns();
        let mut best_score: u128 = u128::MAX;
        let mut best_idx: Option<usize> = None;
        for (i, h) in self.health.iter().enumerate() {
            if h.excluded_until_ns.load(Ordering::Relaxed) > now_ns {
                continue;
            }
            let in_flight = u128::from(h.in_flight.load(Ordering::Relaxed));
            let latency = u128::from(h.latency_ema_ns.load(Ordering::Relaxed)).max(1);
            let score = in_flight.saturating_add(1).saturating_mul(latency);
            if score < best_score {
                best_score = score;
                best_idx = Some(i);
            }
        }
        best_idx
    }

    /// Atomically claim an in-flight slot on `idx`. Use after
    /// [`Self::pick`] before issuing a request.
    pub fn claim(&self, idx: usize) {
        if let Some(h) = self.health.get(idx) {
            h.in_flight.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Pick a mirror, waiting up to `deadline` for one to recover if
    /// every mirror is currently excluded. On success, claims an
    /// in-flight slot atomically; the caller must pair the call
    /// with exactly one [`Self::record_success`] or
    /// [`Self::record_failure`].
    ///
    /// Returns `None` when `cancel` flips to `true`, when the
    /// deadline elapses with no mirror recovering, or — degenerately
    /// — when called on an impossibly-empty set (the constructor
    /// rejects that, so `None` here means "all mirrors stayed
    /// excluded").
    pub fn pick_or_wait(&self, max_wait: Duration, cancel: &AtomicBool) -> Option<usize> {
        let deadline = Instant::now()
            .checked_add(max_wait)
            .unwrap_or_else(Instant::now);
        loop {
            if cancel.load(Ordering::Relaxed) {
                return None;
            }
            if let Some(idx) = self.pick() {
                self.claim(idx);
                return Some(idx);
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let remaining = deadline.saturating_duration_since(now);
            thread::sleep(PICK_SLEEP_STEP.min(remaining));
        }
    }

    /// Snapshot per-mirror counters for tests and diagnostics.
    #[must_use]
    pub fn stats(&self) -> Vec<MirrorStats> {
        self.health
            .iter()
            .map(|h| MirrorStats {
                successes: h.successes.load(Ordering::Relaxed),
                failures: h.failures.load(Ordering::Relaxed),
                in_flight: h.in_flight.load(Ordering::Relaxed),
                latency_ema_ns: h.latency_ema_ns.load(Ordering::Relaxed),
            })
            .collect()
    }

    fn now_ns(&self) -> u64 {
        let elapsed = self.epoch.elapsed();
        u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
    }
}

/// Snapshot of one mirror's counters.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct MirrorStats {
    /// Successful completions recorded against this mirror.
    pub successes: u64,
    /// Failures recorded against this mirror.
    pub failures: u64,
    /// In-flight requests right now.
    pub in_flight: u32,
    /// EMA of recent successful latencies, in ns.
    pub latency_ema_ns: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).expect("parse")
    }

    fn mirror(s: &str) -> Mirror {
        Mirror::new(url(s), SourceFingerprint::default())
    }

    #[test]
    #[should_panic(expected = "MirrorSet requires >= 1 mirror")]
    fn empty_set_panics() {
        let _ = MirrorSet::new(Vec::new());
    }

    #[test]
    fn primary_is_first_mirror() {
        let s = MirrorSet::new(vec![mirror("http://a/"), mirror("http://b/")]);
        assert_eq!(s.primary().url.to_string(), "http://a/");
        assert_eq!(s.len(), 2);
        assert!(s.has_alternates());
    }

    #[test]
    fn single_mirror_no_alternates() {
        let s = MirrorSet::single(url("http://a/"), SourceFingerprint::default());
        assert_eq!(s.len(), 1);
        assert!(!s.has_alternates());
    }

    #[test]
    fn pick_returns_a_live_mirror() {
        let s = MirrorSet::new(vec![mirror("http://a/"), mirror("http://b/")]);
        let idx = s.pick().expect("pick");
        assert!(idx < 2);
    }

    #[test]
    fn pick_skips_excluded_mirrors() {
        let s = MirrorSet::with_exclude_for(
            vec![mirror("http://a/"), mirror("http://b/")],
            Duration::from_secs(10),
        );
        s.claim(0);
        s.record_failure(0);
        // Now mirror 0 is excluded; only 1 is live.
        let idx = s.pick().expect("pick");
        assert_eq!(idx, 1);
        assert_eq!(s.live_count(), 1);
    }

    #[test]
    fn pick_returns_none_when_all_excluded() {
        let s = MirrorSet::with_exclude_for(
            vec![mirror("http://a/"), mirror("http://b/")],
            Duration::from_secs(10),
        );
        s.claim(0);
        s.record_failure(0);
        s.claim(1);
        s.record_failure(1);
        assert!(s.pick().is_none());
        assert_eq!(s.live_count(), 0);
    }

    #[test]
    fn pick_or_wait_recovers_after_short_window() {
        // Multi-mirror set so failure exclusions actually fire (in
        // single-mirror mode failures don't exclude).
        let s = MirrorSet::with_exclude_for(
            vec![mirror("http://a/"), mirror("http://b/")],
            Duration::from_millis(80),
        );
        s.claim(0);
        s.record_failure(0);
        s.claim(1);
        s.record_failure(1);
        let cancel = AtomicBool::new(false);
        let started = Instant::now();
        let _idx = s
            .pick_or_wait(Duration::from_secs(2), &cancel)
            .expect("recovers");
        assert!(started.elapsed() >= Duration::from_millis(60));
    }

    #[test]
    fn pick_or_wait_respects_cancel() {
        let s = MirrorSet::with_exclude_for(
            vec![mirror("http://a/"), mirror("http://b/")],
            Duration::from_secs(60),
        );
        s.claim(0);
        s.record_failure(0);
        s.claim(1);
        s.record_failure(1);
        let cancel = AtomicBool::new(true);
        assert!(s.pick_or_wait(Duration::from_secs(60), &cancel).is_none());
    }

    #[test]
    fn pick_or_wait_times_out_when_all_excluded() {
        let s = MirrorSet::with_exclude_for(
            vec![mirror("http://a/"), mirror("http://b/")],
            Duration::from_secs(60),
        );
        s.claim(0);
        s.record_failure(0);
        s.claim(1);
        s.record_failure(1);
        let cancel = AtomicBool::new(false);
        let started = Instant::now();
        assert!(s
            .pick_or_wait(Duration::from_millis(120), &cancel)
            .is_none());
        assert!(started.elapsed() >= Duration::from_millis(80));
    }

    #[test]
    fn single_mirror_failure_does_not_exclude() {
        // Per record_failure's contract: single-mirror runs lean on
        // the worker's retry-with-backoff and skip the picker-level
        // exclusion. Otherwise the only mirror would wedge for 30 s
        // after every transient 503.
        let s = MirrorSet::with_exclude_for(vec![mirror("http://only/")], Duration::from_secs(60));
        s.claim(0);
        s.record_failure(0);
        // The mirror is immediately pickable again.
        assert_eq!(s.pick(), Some(0));
        // The failure counter still incremented.
        assert_eq!(s.stats()[0].failures, 1);
    }

    #[test]
    fn pick_or_wait_claims_in_flight() {
        let s = MirrorSet::new(vec![mirror("http://a/")]);
        let cancel = AtomicBool::new(false);
        let idx = s
            .pick_or_wait(Duration::from_millis(50), &cancel)
            .expect("ok");
        assert_eq!(idx, 0);
        assert_eq!(s.stats()[0].in_flight, 1);
    }

    #[test]
    fn record_success_decrements_in_flight_and_updates_ema() {
        let s = MirrorSet::new(vec![mirror("http://a/")]);
        s.claim(0);
        s.record_success(0, Duration::from_millis(50));
        let stats = s.stats();
        assert_eq!(stats[0].in_flight, 0);
        assert_eq!(stats[0].successes, 1);
        assert!(stats[0].latency_ema_ns > 0);
    }

    #[test]
    fn record_failure_excludes_mirror() {
        let s = MirrorSet::with_exclude_for(
            vec![mirror("http://a/"), mirror("http://b/")],
            Duration::from_secs(10),
        );
        s.claim(0);
        s.record_failure(0);
        let stats = s.stats();
        assert_eq!(stats[0].failures, 1);
        assert_eq!(stats[0].in_flight, 0);
        assert_eq!(s.live_count(), 1);
    }

    #[test]
    fn pick_prefers_lower_latency_when_equal_load() {
        let s = MirrorSet::new(vec![mirror("http://slow/"), mirror("http://fast/")]);
        // Seed both with completed samples.
        s.claim(0);
        s.record_success(0, Duration::from_millis(500));
        s.claim(1);
        s.record_success(1, Duration::from_millis(50));
        // With equal in_flight (both 0), the faster mirror wins.
        assert_eq!(s.pick(), Some(1));
    }

    #[test]
    fn pick_balances_load_across_mirrors() {
        let s = MirrorSet::new(vec![mirror("http://a/"), mirror("http://b/")]);
        // First pick goes to whichever sorts first under tied
        // (in_flight=0, latency=1) score.
        let first = s
            .pick_or_wait(Duration::from_millis(10), &AtomicBool::new(false))
            .unwrap();
        // Second pick prefers the *other* mirror because the first
        // one's in_flight is now 1.
        let second = s
            .pick_or_wait(Duration::from_millis(10), &AtomicBool::new(false))
            .unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn record_methods_tolerate_out_of_range_idx() {
        let s = MirrorSet::new(vec![mirror("http://a/")]);
        s.record_success(99, Duration::from_millis(1));
        s.record_failure(99);
        let stats = s.stats();
        assert_eq!(stats[0].successes, 0);
        assert_eq!(stats[0].failures, 0);
    }
}
