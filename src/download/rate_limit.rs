//! Aggregate bandwidth limiter for the download workers
//! (`internal/PLAN_v2.md` §14).
//!
//! `peel`'s `--max-bandwidth <RATE>` flag throttles the rate at which
//! bytes are read off the wire. The limiter is a single token bucket
//! shared across every worker thread and (in multi-mirror runs) every
//! mirror — the cap is *aggregate*, not per-mirror.
//!
//! # Shape
//!
//! The hot-path API is two methods on [`RateLimiter`]:
//!
//! - [`RateLimiter::acquire`] blocks the caller until a positive number
//!   of tokens (= bytes) is available, deducts them from the bucket, and
//!   returns how many were granted. Cancellation is observed periodically
//!   so a stalled worker can still shut down promptly.
//! - [`RateLimiter::refund`] returns tokens deducted but unused — the
//!   adapter [`RateLimitedReader`] uses it when a `read` returns short.
//!
//! [`RateLimitedReader`] is the [`std::io::Read`] adapter the
//! [`crate::download::worker`] wraps the response body in. It splits
//! large reads into bounded chunks (the bucket capacity, capped further
//! by [`MAX_PER_READ`]) so a single `read_exact(&mut buf)` over a
//! megabyte body still pays the limiter's cadence rather than burning
//! the whole burst budget in one syscall.
//!
//! # Capacity heuristic
//!
//! Per `PLAN_v2.md` §14 step 1 the bucket capacity is
//! `max(1 MiB, rate * 250 ms)` — a quarter-second's worth of bytes,
//! floored at 1 MiB so very low rates still permit any single TCP
//! window's worth of bytes. `1 MiB` is also the lower-bound the
//! adaptive-chunk policy ([`crate::download::DEFAULT_INITIAL_DISPATCH_BYTES`])
//! happens to hit, so the limiter never starves a single dispatch's
//! first ranged GET.
//!
//! # No async
//!
//! The blocking primitive is [`std::sync::Condvar`] per the
//! `ENGINEERING_STANDARDS.md` §2.5 ban on async runtimes. Workers
//! call into the limiter from their existing blocking
//! [`std::io::Read`] loop and the limiter blocks the calling thread
//! directly.

#![cfg(unix)]

use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// Largest read the [`RateLimitedReader`] adapter performs in one
/// underlying `read` call.
///
/// The cap keeps the limiter's cadence responsive without forcing
/// per-byte syscalls: at 256 KiB a 100 MiB/s worker re-acquires
/// every ~2.5 ms, and at 1 GiB/s every ~250 µs — well above the
/// per-syscall cost.
pub const MAX_PER_READ: usize = 256 * 1024;

/// Floor on bucket capacity, in bytes. Per `PLAN_v2.md` §14 step 1
/// the capacity is `max(1 MiB, rate * 250 ms)`.
pub const MIN_CAPACITY: u64 = 1024 * 1024;

/// Burst window used to size the bucket (250 ms).
const BURST_WINDOW: Duration = Duration::from_millis(250);

/// Granularity of the cancellation check inside [`RateLimiter::acquire`].
/// Workers never wait longer than this between rechecks of the cancel
/// flag, so a rate that would otherwise sleep for many seconds can
/// still be torn down promptly.
const CANCEL_TICK: Duration = Duration::from_millis(50);

/// Token-bucket bandwidth limiter shared across the download workers.
///
/// Tokens are bytes; refill rate is the configured limit; capacity
/// is `max(1 MiB, rate * 250 ms)` per `PLAN_v2.md` §14.
#[derive(Debug)]
pub struct RateLimiter {
    state: Mutex<Bucket>,
    cv: Condvar,
    rate_per_sec: u64,
    capacity: u64,
}

#[derive(Debug)]
struct Bucket {
    /// Tokens currently in the bucket. Bounded by `capacity`.
    tokens: u64,
    /// Wall-clock time of the most recent refill calculation.
    last_refill: Instant,
}

impl RateLimiter {
    /// Construct a new limiter at `rate_bytes_per_sec`.
    ///
    /// Panics if `rate_bytes_per_sec == 0`: a zero-rate limiter would
    /// block forever and the CLI parser rejects that case before we
    /// get here.
    #[must_use]
    pub fn new(rate_bytes_per_sec: u64) -> Self {
        assert!(
            rate_bytes_per_sec > 0,
            "rate_bytes_per_sec must be positive"
        );
        // 250 ms of bytes, floored at 1 MiB. The fractional math is
        // done in u128 to avoid overflow at very large rates (a
        // theoretical 18 EB/s would overflow u64 * 250 ms).
        let burst =
            u64::try_from((u128::from(rate_bytes_per_sec) * BURST_WINDOW.as_millis()) / 1000)
                .unwrap_or(u64::MAX);
        let capacity = burst.max(MIN_CAPACITY);
        Self {
            state: Mutex::new(Bucket {
                tokens: capacity,
                last_refill: Instant::now(),
            }),
            cv: Condvar::new(),
            rate_per_sec: rate_bytes_per_sec,
            capacity,
        }
    }

    /// Configured refill rate, in bytes/sec.
    #[must_use]
    pub fn rate_per_sec(&self) -> u64 {
        self.rate_per_sec
    }

    /// Bucket capacity, in bytes. Equal to `max(1 MiB, rate * 250 ms)`.
    #[must_use]
    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Block until at least one token is available, deduct up to
    /// `want` tokens (capped further at the bucket capacity), and
    /// return the number granted.
    ///
    /// `cancel` is polled while the limiter is asleep; when it
    /// flips to `true` the call returns
    /// [`io::ErrorKind::Interrupted`] without granting any tokens.
    ///
    /// # Errors
    ///
    /// Returns `Err(io::ErrorKind::Interrupted)` when `cancel`
    /// becomes true before any tokens are granted.
    pub fn acquire(&self, want: u64, cancel: &AtomicBool) -> io::Result<u64> {
        if want == 0 {
            return Ok(0);
        }
        // INVARIANT: Mutex poisoning happens only if a previous
        // holder panicked while updating bucket state. The bucket is
        // not safety-load-bearing — recovering with `into_inner` would
        // be safe — but in practice a panic inside a held lock here
        // means the worker thread is going down anyway, so propagate
        // the cancel-shaped error so the caller exits cleanly.
        let mut bucket = self
            .state
            .lock()
            .map_err(|_| io::Error::other("rate-limiter mutex poisoned"))?;
        loop {
            if cancel.load(Ordering::Relaxed) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
            }
            self.refill_locked(&mut bucket);
            if bucket.tokens > 0 {
                let granted = bucket.tokens.min(want).min(self.capacity);
                bucket.tokens -= granted;
                // Wake another waiter — they can re-evaluate against
                // the (potentially still positive) bucket. Cheaper
                // than `notify_all` when most waiters lose the race.
                self.cv.notify_one();
                return Ok(granted);
            }
            // No tokens. Sleep until we'd have at least one, capped
            // by the cancel-check cadence so a stuck worker can
            // shut down within `CANCEL_TICK`.
            let needed = 1u64;
            let secs = needed as f64 / self.rate_per_sec as f64;
            let wait = Duration::from_secs_f64(secs).min(CANCEL_TICK);
            let (next, _to) = self
                .cv
                .wait_timeout(bucket, wait)
                .map_err(|_| io::Error::other("rate-limiter mutex poisoned"))?;
            bucket = next;
        }
    }

    /// Return tokens previously granted by [`Self::acquire`] but not
    /// consumed by the underlying read. Used by [`RateLimitedReader`]
    /// when `Read::read` returns short.
    ///
    /// Refunding more tokens than the bucket can hold is benign; the
    /// excess is silently dropped.
    pub fn refund(&self, tokens: u64) {
        if tokens == 0 {
            return;
        }
        // INVARIANT: see acquire — poisoning is treated as a
        // best-effort no-op so a partially torn-down worker doesn't
        // panic on the way out.
        let Ok(mut bucket) = self.state.lock() else {
            return;
        };
        bucket.tokens = bucket.tokens.saturating_add(tokens).min(self.capacity);
        self.cv.notify_one();
    }

    /// Wake every blocked waiter. Used by the scheduler at shutdown
    /// so workers stalled inside [`Self::acquire`] re-check `cancel`
    /// and exit promptly.
    pub fn shutdown(&self) {
        self.cv.notify_all();
    }

    /// Recompute `bucket.tokens` based on time elapsed since the last
    /// refill, capped at `capacity`.
    ///
    /// The refill is computed in u128 so the multiplication does not
    /// overflow at large rates (`u64::MAX * a few seconds`).
    fn refill_locked(&self, bucket: &mut Bucket) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(bucket.last_refill);
        if elapsed.is_zero() {
            return;
        }
        let nanos = elapsed.as_nanos();
        let refilled = (u128::from(self.rate_per_sec) * nanos) / 1_000_000_000;
        let refilled_u64 = u64::try_from(refilled).unwrap_or(u64::MAX);
        if refilled_u64 == 0 {
            // Defer the wall-clock advance until enough time has
            // accumulated to refill at least one byte. Otherwise
            // very-low-rate limiters round to zero forever.
            return;
        }
        bucket.tokens = bucket
            .tokens
            .saturating_add(refilled_u64)
            .min(self.capacity);
        bucket.last_refill = now;
    }
}

/// `Read` adapter that interposes a [`RateLimiter`] in front of a
/// network body.
///
/// Each call to [`Read::read`] acquires up to
/// `min(buf.len(), MAX_PER_READ, capacity)` tokens, performs the
/// underlying read against that capped slice, and refunds any tokens
/// the read did not actually consume. Standard library combinators
/// like [`Read::read_exact`] keep working unchanged: they call
/// `read` in a loop, and each iteration is rate-controlled.
pub struct RateLimitedReader<'a, R: Read> {
    inner: R,
    limiter: Arc<RateLimiter>,
    cancel: &'a AtomicBool,
}

impl<'a, R: Read> RateLimitedReader<'a, R> {
    /// Wrap `inner` so that every `read` is gated by `limiter`.
    pub fn new(inner: R, limiter: Arc<RateLimiter>, cancel: &'a AtomicBool) -> Self {
        Self {
            inner,
            limiter,
            cancel,
        }
    }

    /// Recover the wrapped reader.
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for RateLimitedReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let want = buf.len().min(MAX_PER_READ);
        // Cap by capacity so acquire never blocks forever on a request
        // larger than the bucket can hold.
        let cap = usize::try_from(self.limiter.capacity()).unwrap_or(usize::MAX);
        let want = want.min(cap).max(1);
        let granted = self.limiter.acquire(want as u64, self.cancel)?;
        let granted_usize = usize::try_from(granted).unwrap_or(usize::MAX);
        if granted_usize == 0 {
            // Defensive: acquire only returns zero on cancel (which
            // surfaces as Interrupted instead). Treat as a retryable
            // "no progress this iteration".
            return Ok(0);
        }
        let slice = &mut buf[..granted_usize];
        let n = self.inner.read(slice)?;
        if n < granted_usize {
            self.limiter.refund(granted.saturating_sub(n as u64));
        }
        Ok(n)
    }
}

/// Errors produced by [`parse_bandwidth`].
#[derive(Debug, thiserror::Error)]
pub enum ParseBandwidthError {
    /// The input was empty or contained no digits.
    #[error("bandwidth value is empty or has no numeric component: {input:?}")]
    Empty {
        /// The input the parser saw.
        input: String,
    },
    /// The numeric component did not parse as an integer / decimal.
    #[error("bandwidth value has invalid number {number:?}")]
    InvalidNumber {
        /// The numeric substring the parser tried.
        number: String,
        /// Underlying parse error.
        #[source]
        source: std::num::ParseFloatError,
    },
    /// The unit suffix did not match any known suffix.
    #[error(
        "unknown bandwidth unit {unit:?}; expected one of K, M, G, T (decimal) \
         or Ki, Mi, Gi, Ti (binary), optionally with a trailing B and /s"
    )]
    UnknownUnit {
        /// The suffix the parser saw.
        unit: String,
    },
    /// The parsed rate would round to zero bytes/sec.
    #[error("bandwidth value {input:?} parses to zero bytes/sec")]
    Zero {
        /// The input the parser saw.
        input: String,
    },
}

/// Parse a `--max-bandwidth` CLI value into bytes/sec.
///
/// Per `PLAN_v2.md` §14 step 3 the parser accepts decimal-prefix
/// suffixes (`K`, `M`, `G`, `T` — 1000-based, network convention) and
/// binary-prefix suffixes (`Ki`, `Mi`, `Gi`, `Ti` — 1024-based).
/// An optional trailing `B` ("bytes") and `/s` are accepted and
/// ignored. The numeric part may be a decimal (e.g. `1.5GB/s`).
///
/// Examples that all parse to `10_000_000` bytes/sec:
/// `10MB/s`, `10MB`, `10M`, `10000000`.
///
/// `1GiB/s` parses to `1_073_741_824` bytes/sec.
///
/// # Errors
///
/// [`ParseBandwidthError`] when the value is empty, the numeric part
/// is malformed, the unit suffix is unknown, or the result is zero.
pub fn parse_bandwidth(input: &str) -> Result<u64, ParseBandwidthError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(ParseBandwidthError::Empty {
            input: input.to_string(),
        });
    }
    // Strip an optional trailing `/s` (case-insensitive).
    let after_per_sec = strip_suffix_ci(trimmed, "/s").unwrap_or(trimmed);
    // Locate the boundary between the numeric prefix and the unit.
    let split = after_per_sec
        .find(|c: char| !c.is_ascii_digit() && c != '.' && c != '_')
        .unwrap_or(after_per_sec.len());
    let (number_part, unit_part) = after_per_sec.split_at(split);
    if number_part.is_empty() {
        return Err(ParseBandwidthError::Empty {
            input: input.to_string(),
        });
    }
    let number: f64 = number_part
        .parse()
        .map_err(|source| ParseBandwidthError::InvalidNumber {
            number: number_part.to_string(),
            source,
        })?;
    let multiplier = parse_unit(unit_part).ok_or_else(|| ParseBandwidthError::UnknownUnit {
        unit: unit_part.to_string(),
    })?;
    let bytes_per_sec_f = number * multiplier as f64;
    if !bytes_per_sec_f.is_finite() || bytes_per_sec_f < 0.0 {
        return Err(ParseBandwidthError::InvalidNumber {
            number: number_part.to_string(),
            // Reuse the float-parse error type by re-parsing a
            // guaranteed-bad input. Cheap and avoids a new error
            // variant for an arithmetic edge case the CLI rarely hits.
            source: "nan".parse::<f64>().unwrap_err(),
        });
    }
    let bytes_per_sec = bytes_per_sec_f.round();
    if bytes_per_sec >= u64::MAX as f64 {
        return Ok(u64::MAX);
    }
    let bps = bytes_per_sec as u64;
    if bps == 0 {
        return Err(ParseBandwidthError::Zero {
            input: input.to_string(),
        });
    }
    Ok(bps)
}

fn strip_suffix_ci<'a>(s: &'a str, suffix: &str) -> Option<&'a str> {
    if s.len() < suffix.len() {
        return None;
    }
    let split = s.len() - suffix.len();
    let (head, tail) = s.split_at(split);
    if tail.eq_ignore_ascii_case(suffix) {
        Some(head)
    } else {
        None
    }
}

fn parse_unit(unit: &str) -> Option<u64> {
    let trimmed = unit.trim();
    // Strip an optional trailing `B` (case-insensitive). We do this
    // before normalization so `MB`, `MiB`, and `M` all map to the
    // same prefix.
    let prefix = strip_suffix_ci(trimmed, "B").unwrap_or(trimmed);
    let prefix_lower = prefix.trim();
    match prefix_lower {
        "" => Some(1),
        // Decimal (1000-based; per `PLAN_v2.md` §14 step 3 — network
        // convention).
        "K" | "k" => Some(1_000),
        "M" | "m" => Some(1_000_000),
        "G" | "g" => Some(1_000_000_000),
        "T" | "t" => Some(1_000_000_000_000),
        // Binary (1024-based).
        "Ki" | "ki" | "KI" | "kI" => Some(1024),
        "Mi" | "mi" | "MI" | "mI" => Some(1024 * 1024),
        "Gi" | "gi" | "GI" | "gI" => Some(1024 * 1024 * 1024),
        "Ti" | "ti" | "TI" | "tI" => Some(1024u64 * 1024 * 1024 * 1024),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::thread;
    use std::time::Instant;

    // ---- parse_bandwidth ---------------------------------------------

    #[test]
    fn parses_bare_bytes_per_sec() {
        assert_eq!(parse_bandwidth("12345").unwrap(), 12_345);
    }

    #[test]
    fn parses_decimal_prefixes() {
        assert_eq!(parse_bandwidth("10K").unwrap(), 10_000);
        assert_eq!(parse_bandwidth("10MB/s").unwrap(), 10_000_000);
        assert_eq!(parse_bandwidth("1.5GB").unwrap(), 1_500_000_000);
        assert_eq!(parse_bandwidth("2T").unwrap(), 2_000_000_000_000);
    }

    #[test]
    fn parses_binary_prefixes() {
        assert_eq!(parse_bandwidth("1KiB/s").unwrap(), 1024);
        assert_eq!(parse_bandwidth("1MiB").unwrap(), 1024 * 1024);
        assert_eq!(parse_bandwidth("1GiB/s").unwrap(), 1024 * 1024 * 1024);
    }

    #[test]
    fn parse_is_case_insensitive_on_b_and_per_s() {
        assert_eq!(parse_bandwidth("10mb/S").unwrap(), 10_000_000);
        assert_eq!(parse_bandwidth("10mIb").unwrap(), 10 * 1024 * 1024);
    }

    #[test]
    fn rejects_empty_input() {
        assert!(matches!(
            parse_bandwidth(""),
            Err(ParseBandwidthError::Empty { .. })
        ));
        assert!(matches!(
            parse_bandwidth("MB/s"),
            Err(ParseBandwidthError::Empty { .. })
        ));
    }

    #[test]
    fn rejects_unknown_unit() {
        assert!(matches!(
            parse_bandwidth("10XB/s"),
            Err(ParseBandwidthError::UnknownUnit { .. })
        ));
    }

    #[test]
    fn rejects_zero_rate() {
        assert!(matches!(
            parse_bandwidth("0"),
            Err(ParseBandwidthError::Zero { .. })
        ));
        assert!(matches!(
            parse_bandwidth("0.0001"),
            Err(ParseBandwidthError::Zero { .. })
        ));
    }

    #[test]
    fn rejects_invalid_number() {
        assert!(matches!(
            parse_bandwidth("12.34.56MB"),
            Err(ParseBandwidthError::InvalidNumber { .. })
        ));
    }

    // ---- RateLimiter capacity ----------------------------------------

    #[test]
    fn capacity_is_floored_at_one_mib() {
        let l = RateLimiter::new(1);
        assert_eq!(l.capacity(), MIN_CAPACITY);
    }

    #[test]
    fn capacity_uses_quarter_second_burst_above_floor() {
        // 100 MiB/s -> 100 MiB * 0.25 = 25 MiB
        let rate = 100 * 1024 * 1024;
        let l = RateLimiter::new(rate);
        assert!(l.capacity() >= MIN_CAPACITY);
        // Within rounding of 25 MiB.
        let expected = rate / 4;
        let actual = l.capacity();
        let diff = actual.abs_diff(expected);
        assert!(diff < 1024, "capacity {actual} != ~{expected}");
    }

    // ---- RateLimiter behavior ----------------------------------------

    #[test]
    fn acquire_grants_bytes_immediately_from_initial_burst() {
        let l = RateLimiter::new(10_000_000); // 10 MB/s
        let cancel = AtomicBool::new(false);
        let n = l.acquire(1024, &cancel).expect("granted");
        assert_eq!(n, 1024);
    }

    #[test]
    fn acquire_caps_at_capacity() {
        let l = RateLimiter::new(1_000_000); // 1 MB/s -> 1 MiB capacity
        let cancel = AtomicBool::new(false);
        let cap = l.capacity();
        let n = l.acquire(cap * 4, &cancel).expect("granted");
        assert_eq!(n, cap);
    }

    #[test]
    fn refund_makes_tokens_available_again() {
        let l = RateLimiter::new(1_000_000);
        let cancel = AtomicBool::new(false);
        let cap = l.capacity();
        // Drain the bucket
        let drained = l.acquire(cap, &cancel).expect("drain");
        assert_eq!(drained, cap);
        l.refund(cap);
        // Should grant the full cap immediately again.
        let n = l.acquire(cap, &cancel).expect("after refund");
        assert_eq!(n, cap);
    }

    #[test]
    fn acquire_returns_interrupted_on_cancel() {
        // Use a tiny rate so the bucket does not refill measurably
        // during the test window — otherwise the spawned thread's
        // acquire could be granted a small number of bytes (from the
        // refill) before the cancel arrives, and the assertion would
        // race.
        let l = Arc::new(RateLimiter::new(1));
        let cancel = Arc::new(AtomicBool::new(false));
        // Drain so the next acquire blocks.
        l.acquire(l.capacity(), &cancel).expect("drain");

        let l_clone = Arc::clone(&l);
        let cancel_clone = Arc::clone(&cancel);
        let join = thread::spawn(move || {
            let cap = l_clone.capacity();
            l_clone.acquire(cap, &cancel_clone)
        });
        thread::sleep(Duration::from_millis(20));
        cancel.store(true, Ordering::Relaxed);
        l.shutdown();
        let result = join.join().expect("thread join");
        assert!(matches!(
            result.as_ref().map_err(|e| e.kind()),
            Err(io::ErrorKind::Interrupted)
        ));
    }

    #[test]
    fn rate_limited_reader_paces_reads_against_rate() {
        // 1 MiB/s rate, 1 MiB capacity. Read 3 MiB; should take
        // around 2 s (first 1 MiB is the initial burst, the next
        // 2 MiB pay the rate).
        let rate = 1024 * 1024;
        let l = Arc::new(RateLimiter::new(rate));
        let cancel = AtomicBool::new(false);
        let payload = vec![0u8; 3 * 1024 * 1024];
        let inner = Cursor::new(payload);
        let mut reader = RateLimitedReader::new(inner, Arc::clone(&l), &cancel);
        let mut sink = vec![0u8; 3 * 1024 * 1024];
        let started = Instant::now();
        reader.read_exact(&mut sink).expect("read_exact");
        let elapsed = started.elapsed();
        // Expect at least ~1.5 s (2 MiB above the burst at 1 MiB/s).
        // Generous lower bound to keep the test stable on loaded CI.
        assert!(
            elapsed >= Duration::from_millis(1500),
            "elapsed {elapsed:?} too small for 3 MiB at 1 MiB/s burst-1MiB",
        );
    }

    #[test]
    fn rate_limited_reader_passes_short_reads_through() {
        // The inner reader returns one byte per `read` call. The
        // limiter must still let the consumer drain the whole stream.
        struct OneByte<'a>(&'a [u8]);
        impl Read for OneByte<'_> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.0.is_empty() || buf.is_empty() {
                    return Ok(0);
                }
                buf[0] = self.0[0];
                self.0 = &self.0[1..];
                Ok(1)
            }
        }
        let rate = 10 * 1024 * 1024;
        let l = Arc::new(RateLimiter::new(rate));
        let cancel = AtomicBool::new(false);
        let payload = b"hello world".to_vec();
        let inner = OneByte(&payload);
        let mut reader = RateLimitedReader::new(inner, Arc::clone(&l), &cancel);
        let mut out = Vec::new();
        std::io::copy(&mut reader, &mut out).expect("copy");
        assert_eq!(out, payload);
    }

    #[test]
    fn rate_limited_reader_zero_buf_returns_zero() {
        let l = Arc::new(RateLimiter::new(1_000_000));
        let cancel = AtomicBool::new(false);
        let inner: &[u8] = b"abc";
        let mut reader = RateLimitedReader::new(inner, l, &cancel);
        let mut buf: [u8; 0] = [];
        assert_eq!(reader.read(&mut buf).unwrap(), 0);
    }
}
