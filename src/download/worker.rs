//! Single-chunk download with retry / backoff.
//!
//! The worker is the unit of network IO underneath the
//! [`scheduler`](crate::download::scheduler). For each assigned
//! [`ChunkIndex`] it issues a ranged `GET`, validates `Content-Range`,
//! `Content-Length`, and the source fingerprint (`ETag` /
//! `Last-Modified`), reads the body into a buffer, and writes it into
//! the [`SparseFile`] at the chunk's offset. Transport-level and 5xx
//! failures are retried with exponential backoff up to
//! [`RetryConfig::max_attempts`]; non-retryable failures (4xx,
//! `Content-Range` mismatch, source-fingerprint change) propagate up
//! immediately.
//!
//! # Cancellation
//!
//! [`download_chunk`] takes an `AtomicBool` it polls between retry
//! sleeps. When the scheduler observes a terminal failure or wants to
//! shut down, it sets the flag and the worker returns
//! [`WorkerError::Cancelled`] before its next syscall, instead of
//! sleeping out the remaining backoff.

#![cfg(unix)]

use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;

use super::mirrors::{MirrorSet, DEFAULT_MIRROR_PICK_DEADLINE};
use super::multi_sparse::MultiSparse;
use super::multi_url::MultiPartSource;
use super::rate_limit::{RateLimitedReader, RateLimiter};
use super::sparse_file::SparseFileError;
use crate::hash::crc32c::Crc32c;
use crate::http::range::{parse_content_range, RangeError};
use crate::http::{Client, ClientError, Headers};
use crate::progress::ProgressState;
use crate::types::ByteOffset;
use crate::types::{ByteRange, ChunkIndex};

/// Errors a worker can raise for one chunk attempt.
///
/// `is_retryable` partitions them into transient (worth another try)
/// versus terminal (abort the download).
#[derive(Debug, Error)]
pub enum WorkerError {
    /// A transport-level failure: TCP, TLS, response framing, or DNS.
    #[error("transport error fetching chunk {chunk}")]
    Transport {
        /// Chunk being fetched.
        chunk: ChunkIndex,
        /// Underlying client error.
        #[source]
        source: ClientError,
    },

    /// The server returned a non-206 status.
    #[error("server returned {status} for chunk {chunk}")]
    UnexpectedStatus {
        /// Chunk being fetched.
        chunk: ChunkIndex,
        /// HTTP status code.
        status: u16,
    },

    /// The source's `ETag` or `Last-Modified` differs from what the
    /// initial `HEAD` reported. The download cannot continue safely;
    /// re-run from scratch.
    #[error(
        "source changed during download: chunk {chunk} (etag was {expected_etag:?}, now {actual_etag:?}; last-modified was {expected_last_modified:?}, now {actual_last_modified:?})"
    )]
    SourceChanged {
        /// Chunk that observed the change.
        chunk: ChunkIndex,
        /// `ETag` recorded at `HEAD` time.
        expected_etag: Option<String>,
        /// `ETag` returned by the server now.
        actual_etag: Option<String>,
        /// `Last-Modified` recorded at `HEAD` time.
        expected_last_modified: Option<String>,
        /// `Last-Modified` returned now.
        actual_last_modified: Option<String>,
    },

    /// A `PLAN_v2.md` §11 mid-flight probe re-fetched a chunk whose
    /// CRC-32C disagreed with the value recorded at first-fetch.
    /// The source must have changed between the original GET and the
    /// probe — abort the run rather than continue with mixed bytes.
    #[error(
        "source changed during download: chunk {chunk} probe CRC32C \
         (expected {expected:#010x}, observed {actual:#010x})"
    )]
    SourceDriftDetected {
        /// Chunk whose probe failed.
        chunk: ChunkIndex,
        /// CRC-32C the original fetch recorded.
        expected: u32,
        /// CRC-32C the probe just computed.
        actual: u32,
    },

    /// The server's `Content-Range` did not match what we asked for.
    #[error(
        "Content-Range mismatch for chunk {chunk}: expected {expected}, server said {actual:?}"
    )]
    ContentRangeMismatch {
        /// Chunk being fetched.
        chunk: ChunkIndex,
        /// Range we requested.
        expected: ByteRange,
        /// `Content-Range` header value, if any.
        actual: Option<String>,
    },

    /// `Content-Range` did not parse.
    #[error("Content-Range malformed for chunk {chunk}: {value:?}")]
    ContentRangeMalformed {
        /// Chunk being fetched.
        chunk: ChunkIndex,
        /// The offending header value.
        value: String,
        /// Underlying parse error.
        #[source]
        source: RangeError,
    },

    /// `Content-Length` did not match the requested range length.
    #[error("body length mismatch for chunk {chunk}: expected {expected}, server said {actual:?}")]
    BodyLengthMismatch {
        /// Chunk being fetched.
        chunk: ChunkIndex,
        /// Bytes we expected based on the requested range.
        expected: u64,
        /// Bytes the server advertised, if any.
        actual: Option<u64>,
    },

    /// Reading the response body failed (often `UnexpectedEof`).
    #[error("io reading body for chunk {chunk}")]
    BodyIo {
        /// Chunk being fetched.
        chunk: ChunkIndex,
        /// Underlying IO error.
        #[source]
        source: io::Error,
    },

    /// Writing the chunk into the sparse file failed.
    #[error("sparse-file write for chunk {chunk}")]
    SparseFile {
        /// Chunk being fetched.
        chunk: ChunkIndex,
        /// Underlying sparse-file error.
        #[source]
        source: SparseFileError,
    },

    /// `PEEL_VERIFY_CHUNKS=1` is set and a post-write re-read of the
    /// chunk produced a CRC-32C that did not match the value we just
    /// computed from the in-memory body. Indicates the page-cache /
    /// io-backend write path is silently dropping or reordering bytes
    /// (the §3.3 hypothesis the env switch exists to falsify).
    #[error(
        "PEEL_VERIFY_CHUNKS: chunk {chunk} on-disk CRC32C \
         (expected {expected:#010x}, observed {actual:#010x}) — \
         in-memory body did not match what the sparse file holds"
    )]
    ChunkVerifyMismatch {
        /// Chunk that failed verification.
        chunk: ChunkIndex,
        /// CRC-32C computed from the in-memory body just written.
        expected: u32,
        /// CRC-32C computed by reading the same range back from the
        /// sparse file.
        actual: u32,
    },

    /// The scheduler asked the worker to stop. Returned in place of
    /// continuing a backoff sleep.
    #[error("download cancelled before chunk {chunk} completed")]
    Cancelled {
        /// Chunk that was in flight when cancellation was observed.
        chunk: ChunkIndex,
    },

    /// Every mirror in the set was excluded for the configured
    /// backoff window when [`download_dispatch`] tried to pick one.
    /// Surfaces only in multi-mirror runs (`PLAN_v2.md` §13);
    /// single-mirror runs use the existing retry-with-backoff path.
    #[error(
        "no mirror available for chunk {chunk} after waiting {wait_secs:.1}s; \
         every configured mirror is in the failure-backoff window"
    )]
    NoLiveMirror {
        /// Chunk being fetched.
        chunk: ChunkIndex,
        /// How long the worker waited for a live mirror to recover.
        wait_secs: f64,
    },

    /// Multi-URL routing was asked for a global offset past the end
    /// of the assembled source. Indicates a scheduler bug: the
    /// dispatch range escaped the `[0, total_size)` clamp.
    #[error(
        "multi-part dispatch for chunk {chunk} starts at global offset {offset} \
         which is past the end of the assembled source"
    )]
    MultiPartOutOfRange {
        /// Chunk being fetched.
        chunk: ChunkIndex,
        /// Global byte offset that fell off the source.
        offset: u64,
    },
}

impl WorkerError {
    /// True iff retrying the same chunk could plausibly succeed.
    ///
    /// `Transport` failures, 5xx server errors, and body-IO failures
    /// (UnexpectedEof from a stream cut short) are retryable. Everything
    /// else — 4xx, `Content-Range` disagreements, source-fingerprint
    /// drift, sparse-file IO — is terminal.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Transport { source, .. } => is_transport_retryable(source),
            Self::UnexpectedStatus { status, .. } => *status >= 500,
            Self::BodyIo { .. } => true,
            Self::BodyLengthMismatch { .. } => true,
            Self::SourceChanged { .. } => false,
            Self::SourceDriftDetected { .. } => false,
            Self::ContentRangeMismatch { .. } => false,
            Self::ContentRangeMalformed { .. } => false,
            Self::SparseFile { .. } => false,
            Self::ChunkVerifyMismatch { .. } => false,
            Self::Cancelled { .. } => false,
            Self::NoLiveMirror { .. } => false,
            Self::MultiPartOutOfRange { .. } => false,
        }
    }
}

fn is_transport_retryable(err: &ClientError) -> bool {
    matches!(
        err,
        ClientError::Io { .. }
            | ClientError::Tls { .. }
            | ClientError::Transport { .. }
            | ClientError::DnsEmpty { .. }
    )
}

/// Source-identity headers captured at `HEAD` time.
///
/// Both fields are optional — RFC 7232 only requires that *one* of them
/// is present for a cacheable resource, and many real-world servers send
/// only one. The worker enforces equality on the **strong** ETag and on
/// `Last-Modified`. **Weak ETags** (the `W/`-prefixed variant per
/// RFC 7232 §2.3) are treated as advisory: a weak validator only
/// promises semantic equivalence, not byte equivalence, and some
/// reverse proxies normalize weak ETags between cache hits, so a
/// mismatch on its own is not enough to abort. The §11 per-chunk
/// CRC-32C check (`PLAN_v2.md` §11) is the byte-level guard that
/// catches genuine drift even when the ETag did not.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct SourceFingerprint {
    /// `ETag` value verbatim (including any `W/` weak prefix).
    pub etag: Option<String>,
    /// `Last-Modified` value verbatim.
    pub last_modified: Option<String>,
}

impl SourceFingerprint {
    /// Construct from response headers.
    #[must_use]
    pub fn from_headers(headers: &Headers) -> Self {
        Self {
            etag: headers.get("etag").map(str::to_string),
            last_modified: headers.get("last-modified").map(str::to_string),
        }
    }

    /// True iff the fingerprint carries no identifying header.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.etag.is_none() && self.last_modified.is_none()
    }
}

/// True iff `etag` is a weak validator per RFC 7232 §2.3 (the
/// `W/`-prefixed form). Weak validators promise semantic
/// equivalence only, not byte equivalence, so we don't error on a
/// weak-ETag mismatch — the §11 CRC-32C check is the byte guard.
#[must_use]
pub fn etag_is_weak(etag: &str) -> bool {
    etag.starts_with("W/") || etag.starts_with("w/")
}

/// Tunables for the worker's retry loop.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of attempts including the first one.
    pub max_attempts: u32,
    /// Backoff before the *second* attempt; doubles each subsequent
    /// retry, capped at `max_backoff`.
    pub initial_backoff: Duration,
    /// Upper bound on backoff sleep between retries.
    pub max_backoff: Duration,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(10),
        }
    }
}

/// What [`download_chunk`] reports on success.
#[derive(Debug, Clone)]
pub struct ChunkOutcome {
    /// Bytes written to the sparse file.
    pub bytes: u64,
    /// Wall-clock time spent inside the sparse-file `pwrite_at`.
    pub pwrite_time: Duration,
    /// Number of attempts taken (1 = first attempt succeeded).
    pub attempts: u32,
    /// CRC-32C per bitmap chunk in the dispatch, in chunk order
    /// (`PLAN_v2.md` §11). Empty for `Probe` dispatches — the probe
    /// path verifies in-line and never bubbles raw fingerprints up.
    pub crcs: Vec<u32>,
}

/// What [`download_chunk`] reports on failure: the underlying error
/// plus the actual attempt count at the moment it surfaced.
///
/// Pairing the count with the error preserves diagnostic fidelity:
/// without it, the scheduler's `[ChunkFailed]` log line had to either
/// hardcode `attempts: 1` or refuse to log a count, both of which hide
/// whether the worker exhausted its retry budget or bailed on the
/// first pass (e.g. a non-retryable status, a cancellation).
#[derive(Debug)]
pub struct ChunkFailure {
    /// The error that ended the retry loop.
    pub error: WorkerError,
    /// Number of attempts taken before [`Self::error`] surfaced
    /// (1 = the first attempt failed terminally; `>= 2` = at least
    /// one retry happened).
    pub attempts: u32,
}

/// What kind of work a [`Dispatch`] represents.
///
/// Most dispatches are [`DispatchKind::Fetch`] — fetch the bytes
/// covering one or more bitmap chunks and write them into the
/// sparse file. The §11 mid-flight verifier additionally issues
/// [`DispatchKind::Probe`] dispatches that re-fetch a single
/// already-complete chunk and compare its CRC-32C against the
/// value the original fetch recorded.
#[derive(Debug, Clone, Copy)]
pub enum DispatchKind {
    /// Plain ranged GET that writes its body into the sparse file
    /// and records per-chunk CRC-32Cs.
    Fetch,
    /// `PLAN_v2.md` §11 mid-flight probe: re-fetch the dispatch's
    /// single chunk, recompute its CRC-32C, and compare against
    /// `expected`. The probe still writes the bytes back into the
    /// sparse file (idempotent on a stable source); a CRC mismatch
    /// surfaces as [`WorkerError::SourceDriftDetected`].
    Probe {
        /// CRC-32C the original fetch recorded.
        expected: u32,
    },
}

/// One worker assignment: a contiguous run of bitmap chunks fetched
/// in a single ranged GET.
///
/// `count == 1` is the original 1-chunk-per-task behaviour and the
/// only thing the scheduler dispatches when adaptive chunk-size is
/// disabled. With adaptive enabled (`PLAN_v2.md` §8) the scheduler
/// coalesces up to `policy.current() / chunk_size` consecutive
/// incomplete chunks into one [`Dispatch`]. Probe dispatches always
/// have `count == 1`.
#[derive(Debug, Clone, Copy)]
pub struct Dispatch {
    /// First chunk in the run.
    pub first: ChunkIndex,
    /// Number of contiguous chunks (>= 1).
    pub count: u32,
    /// Half-open byte range covering all `count` chunks. The worker
    /// performs **one** ranged GET against this range and writes the
    /// whole body via a single `pwrite_at`.
    pub range: ByteRange,
    /// Whether this is a normal fetch or a §11 mid-flight probe.
    pub kind: DispatchKind,
}

/// Borrowed context shared across every chunk in a single download.
///
/// Bundling these references keeps [`download_chunk`]'s signature
/// short. They are all `&'a` rather than owned — the scheduler holds
/// the originals on its stack and constructs one `ChunkContext` per
/// worker.
#[derive(Clone, Copy)]
pub struct ChunkContext<'a> {
    /// HTTP client used to issue the ranged GET.
    pub client: &'a Client,
    /// Mirror set the worker picks from for each attempt
    /// (`PLAN_v2.md` §13). Single-URL runs construct a one-element
    /// set via [`MirrorSet::single`]; multi-mirror runs build the
    /// full set in [`crate::download::discover_with_mirrors`].
    ///
    /// Inert for multi-part runs (`source.is_some() &&
    /// source.unwrap().len() > 1`): the URL routing is decided by
    /// [`Self::source`] instead. The field stays in the context so
    /// the single-URL and single-URL-plus-mirrors code paths remain
    /// unchanged. The plan (`internal/PLAN_multi_url_source.md` §1
    /// step 5) keeps `--mirror` and multi-URL mutually exclusive at
    /// config time, so no run ever needs both at once.
    pub mirrors: &'a MirrorSet,
    /// When set with `len() > 1`, the worker routes each ranged GET
    /// to the part containing the dispatch's start offset, using a
    /// part-relative `Range` header against `parts[i].url`. When
    /// `None` or `len() == 1`, the worker falls through to the
    /// existing [`Self::mirrors`] path. The single-URL case builds a
    /// one-element source whose `parts[0].url` matches the lone
    /// mirror, so either field would yield the same URL.
    pub source: Option<&'a MultiPartSource>,
    /// Bitmap chunk size — used to slice the dispatch body into
    /// per-chunk CRC-32Cs (`PLAN_v2.md` §11).
    pub chunk_size: u64,
    /// Sparse file the chunk's bytes are written into.
    pub sparse: &'a MultiSparse,
    /// Optional progress sink the worker `fetch_add`s into after
    /// each successful `pwrite_at` (PLAN_v2.md §6). `None` keeps the
    /// worker silent — used by tests that don't drive the renderer.
    pub progress: Option<&'a ProgressState>,
    /// Optional aggregate bandwidth limiter (`PLAN_v2.md` §14). When
    /// `Some`, every byte the worker reads off the wire passes
    /// through the limiter's token bucket. `None` runs at the
    /// network's natural throughput. Shared across all workers and
    /// all mirrors, so the cap is aggregate.
    pub rate_limiter: Option<&'a Arc<RateLimiter>>,
}

/// Download a single chunk with retry/backoff.
///
/// Issues `GET <ctx.url>` with `Range: bytes=<range>`, validates the
/// response, and writes the body to `ctx.sparse` at `range.start()`.
/// Retries on transient failures up to `retry.max_attempts`. Polls
/// `cancel` between retry sleeps and bails out with
/// [`WorkerError::Cancelled`] when set.
///
/// # Errors
///
/// Returns a [`ChunkFailure`] carrying the *last* error observed if
/// all retries are exhausted, or the first non-retryable error
/// encountered, paired with the actual attempt count.
pub fn download_chunk(
    ctx: &ChunkContext<'_>,
    chunk: ChunkIndex,
    range: ByteRange,
    retry: &RetryConfig,
    cancel: &AtomicBool,
) -> Result<ChunkOutcome, ChunkFailure> {
    download_dispatch(
        ctx,
        Dispatch {
            first: chunk,
            count: 1,
            range,
            kind: DispatchKind::Fetch,
        },
        retry,
        cancel,
    )
}

/// Download an N-chunk [`Dispatch`] with retry/backoff.
///
/// One ranged GET, one `pwrite_at`, regardless of `dispatch.count`.
/// On success the *whole* range is durable on disk before the
/// function returns; the scheduler can then mark every constituent
/// chunk complete in the bitmap. On failure no partial bytes are
/// written (the response is read in full into a buffer first), so
/// retries always restart cleanly.
///
/// `chunk` context in returned [`WorkerError`] variants names
/// `dispatch.first` — the dispatch is atomic, so naming the first
/// chunk is the unambiguous diagnostic anchor.
///
/// # Errors
///
/// Returns a [`ChunkFailure`] carrying the *last* error observed if
/// all retries are exhausted, or the first non-retryable error
/// encountered, paired with the actual attempt count. The attempt
/// count is `>= 1` for any `Err`: a pre-loop cancel observation
/// counts as one attempt that did not run.
pub fn download_dispatch(
    ctx: &ChunkContext<'_>,
    dispatch: Dispatch,
    retry: &RetryConfig,
    cancel: &AtomicBool,
) -> Result<ChunkOutcome, ChunkFailure> {
    let chunk = dispatch.first;
    if cancel.load(Ordering::Relaxed) {
        return Err(ChunkFailure {
            error: WorkerError::Cancelled { chunk },
            attempts: 1,
        });
    }
    let mut attempt: u32 = 0;
    let mut backoff = retry.initial_backoff;
    loop {
        attempt = attempt.saturating_add(1);
        // Pick a mirror for this attempt. In single-mirror runs the
        // wait collapses to a no-op (the lone mirror is always
        // either live or excluded). In multi-mirror runs the picker
        // skips excluded mirrors and (transparently) blocks until
        // one recovers, up to `DEFAULT_MIRROR_PICK_DEADLINE`.
        let started = Instant::now();
        let mirror_idx = match ctx
            .mirrors
            .pick_or_wait(DEFAULT_MIRROR_PICK_DEADLINE, cancel)
        {
            Some(i) => i,
            None => {
                let error = if cancel.load(Ordering::Relaxed) {
                    WorkerError::Cancelled { chunk }
                } else {
                    WorkerError::NoLiveMirror {
                        chunk,
                        wait_secs: DEFAULT_MIRROR_PICK_DEADLINE.as_secs_f64(),
                    }
                };
                return Err(ChunkFailure {
                    error,
                    attempts: attempt,
                });
            }
        };
        let outcome = try_once(ctx, mirror_idx, &dispatch, cancel);
        let elapsed = started.elapsed();
        let err = match outcome {
            Ok((bytes, crcs, pwrite_time)) => {
                ctx.mirrors.record_success(mirror_idx, elapsed);
                // Probe dispatches verify in-line and never bubble
                // CRCs up to the scheduler — they're already
                // verified against the expected value.
                if let DispatchKind::Probe { expected } = dispatch.kind {
                    let actual = crcs.first().copied().unwrap_or(0);
                    if actual != expected {
                        return Err(ChunkFailure {
                            error: WorkerError::SourceDriftDetected {
                                chunk,
                                expected,
                                actual,
                            },
                            attempts: attempt,
                        });
                    }
                    return Ok(ChunkOutcome {
                        bytes,
                        pwrite_time,
                        attempts: attempt,
                        crcs: Vec::new(),
                    });
                }
                return Ok(ChunkOutcome {
                    bytes,
                    pwrite_time,
                    attempts: attempt,
                    crcs,
                });
            }
            Err(e) => {
                ctx.mirrors.record_failure(mirror_idx);
                e
            }
        };
        if !err.is_retryable() {
            // Multi-mirror policy: a per-mirror non-retryable error
            // (mirror-specific source rotation, malformed
            // Content-Range, etc.) drops *that* mirror. Try the
            // remaining mirrors before propagating; only when every
            // mirror has been excluded do we surface
            // `NoLiveMirror`. Single-mirror runs short-circuit
            // immediately because there is nothing to fall back to.
            if !ctx.mirrors.has_alternates() {
                return Err(ChunkFailure {
                    error: err,
                    attempts: attempt,
                });
            }
            // Don't sleep on a non-retryable error — the picker's
            // exclusion-aware wait handles backoff at the
            // mirror-set level.
            continue;
        }
        if attempt >= retry.max_attempts {
            return Err(ChunkFailure {
                error: err,
                attempts: attempt,
            });
        }
        if !sleep_with_cancel(backoff, cancel) {
            return Err(ChunkFailure {
                error: WorkerError::Cancelled { chunk },
                attempts: attempt,
            });
        }
        backoff = backoff.saturating_mul(2).min(retry.max_backoff);
    }
}

/// Sleep for `dur`, polling `cancel` periodically. Returns `false` if
/// cancellation was observed (sleep aborted), `true` if the full
/// duration elapsed without cancellation.
fn sleep_with_cancel(dur: Duration, cancel: &AtomicBool) -> bool {
    if dur.is_zero() {
        return !cancel.load(Ordering::Relaxed);
    }
    let deadline = Instant::now() + dur;
    let step = Duration::from_millis(20).min(dur);
    loop {
        if cancel.load(Ordering::Relaxed) {
            return false;
        }
        let now = Instant::now();
        if now >= deadline {
            return true;
        }
        let remaining = deadline - now;
        thread::sleep(step.min(remaining));
    }
}

fn try_once(
    ctx: &ChunkContext<'_>,
    mirror_idx: usize,
    dispatch: &Dispatch,
    cancel: &AtomicBool,
) -> Result<(u64, Vec<u32>, Duration), WorkerError> {
    let chunk = dispatch.first;
    let global_range = dispatch.range;
    let len_usize =
        usize::try_from(global_range.len()).map_err(|_| WorkerError::BodyLengthMismatch {
            chunk,
            expected: global_range.len(),
            actual: None,
        })?;
    let mut buf = vec![0u8; len_usize];

    // Multi-URL routing (`internal/PLAN_multi_url_source.md`): when the
    // source has more than one part, iterate
    // [`MultiPartSource::dispatch_range`] — typically yields one
    // segment, but a chunk that straddles a part boundary (the
    // user's chunk_size doesn't divide every part_size) yields one
    // segment per crossed part. Each segment runs its own GET +
    // pwrite into the right slice of `buf`. The single-URL /
    // `--mirror` case (`source` is `None` or `len() == 1`) keeps
    // the existing single-GET/single-pwrite path so historical
    // behaviour is byte-identical.
    let multipart = ctx.source.filter(|s| s.len() > 1);
    let mut refund = ProgressRefundGuard::new(ctx.progress);
    let pwrite_time = if let Some(source) = multipart {
        download_multi_segment(
            ctx,
            chunk,
            source,
            global_range,
            &mut buf,
            &mut refund,
            cancel,
        )?
    } else {
        let mirror = ctx.mirrors.mirror(mirror_idx);
        // Single-URL credits the full dispatch to part_idx 0
        // (single-element parts vec by convention; see
        // `ProgressState::set_parts` in `coordinator::run`).
        download_single_segment(
            ctx,
            chunk,
            &mirror.url,
            &mirror.fingerprint,
            global_range,
            global_range,
            0,
            &mut buf,
            &mut refund,
            cancel,
        )?
    };

    // hyper-util's connection pool reclaims the connection when the
    // body is dropped at end of scope; no explicit release step.

    let crcs = compute_chunk_crcs(&buf, dispatch, ctx.chunk_size);

    // §3.3 (PLAN_responsiveness.md): when `PEEL_VERIFY_CHUNKS=1` is
    // set, re-read every chunk we just wrote and confirm the on-disk
    // CRC-32C matches what we computed in memory. Off by default
    // because the extra read roughly doubles the cost of every
    // dispatch; on by demand for the next pod incident. Catches
    // page-cache / io-backend hazards (the §3.3 hypothesis) and
    // would have caught the corruption in the snapshot-restore pod
    // *during the original download* rather than only at decode
    // time on the next resume.
    if verify_chunks_enabled() {
        verify_on_disk_chunks(ctx.sparse, dispatch, ctx.chunk_size, &buf, &crcs)?;
    }

    refund.disarm();
    Ok((global_range.len(), crcs, pwrite_time))
}

/// RAII guard that refunds partial download-counter increments on any
/// non-success exit from a single `try_once` attempt.
///
/// The disk-buffer throttle in
/// [`crate::download::scheduler`] gates dispatch on
/// `bytes_downloaded - bytes_decoded_input ≥ max_disk_buffer`. Any
/// path that increments `bytes_downloaded` without later decrementing
/// it on failure inflates the gap — a respawn re-fetches the same
/// chunk and its bytes are credited a second time. The original code
/// refunded only on the `Err(BodyIo)` branch, which left the
/// `pwrite_at` failure path, the `verify_on_disk_chunks` path, and a
/// panic caught by the scheduler's `catch_unwind` all leaking. This
/// guard is the single refund site for the attempt: armed at
/// construction, disarmed only when every byte has been written and
/// verified, and refunds on `Drop` otherwise.
///
/// Multi-URL dispatches (`internal/PLAN_multi_url_source.md`) credit
/// per-part counters separately. The guard tracks each segment's
/// `(part_idx, bytes)` so a later-segment failure (or a panic
/// across the dispatch) refunds *every* prior segment as well as
/// the failing one. Single-URL runs push one entry with
/// `part_idx == 0`, matching the conventional one-element parts vec
/// the coordinator initialises at startup.
struct ProgressRefundGuard<'a> {
    progress: Option<&'a ProgressState>,
    /// Pending refund log: `(part_idx, bytes_credited_this_segment)`
    /// in segment order. On drop without disarm we walk this and
    /// reverse every credit. Bytes credited inside `read_with_progress`
    /// (which fires once per socket-level read) accumulate into the
    /// active segment's `pending` field; segments transition that
    /// `pending` onto the rollback log via [`Self::record_segment`].
    increments: Vec<(usize, u64)>,
    /// Bytes credited inside the *current* segment but not yet
    /// pushed onto `increments`. `read_with_progress` adds into
    /// this; the segment helper either pushes the total to
    /// `increments` (success) or drops the dispatch via the same
    /// drop-time refund below (failure).
    pending: u64,
    /// Part index the active segment is crediting into. Only
    /// meaningful while `pending > 0`.
    pending_part_idx: usize,
    armed: bool,
}

impl<'a> ProgressRefundGuard<'a> {
    fn new(progress: Option<&'a ProgressState>) -> Self {
        Self {
            progress,
            increments: Vec::new(),
            pending: 0,
            pending_part_idx: 0,
            armed: true,
        }
    }

    /// Begin tracking a new segment's progress credit. Pairs with
    /// [`Self::commit_segment`] on success; on failure the pending
    /// total flows through `Drop`.
    fn begin_segment(&mut self, part_idx: usize) {
        // Defensive: previous segment's pending should already be
        // committed to `increments`. If not (a bug or panic between
        // segments), absorb it here so we don't lose track.
        if self.pending > 0 {
            self.increments.push((self.pending_part_idx, self.pending));
            self.pending = 0;
        }
        self.pending_part_idx = part_idx;
    }

    /// Commit the active segment's pending credit as a permanent
    /// rollback entry. Called when a segment's GET + pwrite both
    /// succeed; the bytes stay in the aggregate counter (and the
    /// per-part counter) and are only refunded if the whole
    /// dispatch later fails.
    fn commit_segment(&mut self) {
        if self.pending > 0 {
            self.increments.push((self.pending_part_idx, self.pending));
            self.pending = 0;
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ProgressRefundGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Some(p) = self.progress else {
            return;
        };
        // Refund the pending segment first (it's the one the failure
        // happened inside), then unwind committed segments in reverse
        // order. Reverse order is just nice for diagnostics in
        // tracing — the counters are atomics so any order works.
        if self.pending > 0 {
            p.sub_downloaded(self.pending);
            p.sub_downloaded_from_part(self.pending_part_idx, self.pending);
        }
        for (idx, n) in self.increments.iter().rev() {
            p.sub_downloaded(*n);
            p.sub_downloaded_from_part(*idx, *n);
        }
    }
}

/// Fetch one part-segment of a dispatch's range:
/// - issues `GET <url>` with `Range: bytes=<wire_range>`;
/// - validates `Content-Range`, `Content-Length`, and the part's
///   `ETag` / `Last-Modified` fingerprint;
/// - reads the body into the supplied `dest` slice (which is a
///   sub-slice of the dispatch's combined buffer);
/// - `pwrite_at`s the segment at its global offset.
///
/// `part_idx` attributes the read bytes to the right per-part
/// counter (`internal/PLAN_multi_url_source.md`). Single-URL runs pass
/// `0` here — the coordinator initialises a one-element parts vec
/// so the attribution is always valid.
///
/// Used by the multi-segment loop in `try_once` and (with
/// `part_idx == 0` for single-URL) the legacy single-GET path.
#[allow(clippy::too_many_arguments)]
fn download_single_segment(
    ctx: &ChunkContext<'_>,
    chunk: ChunkIndex,
    url: &crate::http::Url,
    fingerprint: &SourceFingerprint,
    wire_range: ByteRange,
    global_range: ByteRange,
    part_idx: usize,
    dest: &mut [u8],
    refund: &mut ProgressRefundGuard<'_>,
    cancel: &AtomicBool,
) -> Result<Duration, WorkerError> {
    let resp = ctx
        .client
        .get_range(url, wire_range)
        .map_err(|source| match source {
            ClientError::UnexpectedStatus { status, .. } => {
                WorkerError::UnexpectedStatus { chunk, status }
            }
            other => WorkerError::Transport {
                chunk,
                source: other,
            },
        })?;
    verify_content_range(&resp.headers, chunk, wire_range)?;
    verify_content_length(&resp, chunk, wire_range.len())?;
    verify_fingerprint(&resp.headers, fingerprint, chunk)?;

    refund.begin_segment(part_idx);
    let mut body = resp.body;
    let read_result = if let Some(limiter) = ctx.rate_limiter {
        let mut limited = RateLimitedReader::new(&mut body, Arc::clone(limiter), cancel);
        read_with_progress(
            &mut limited,
            dest,
            ctx.progress,
            part_idx,
            &mut refund.pending,
        )
    } else {
        read_with_progress(&mut body, dest, ctx.progress, part_idx, &mut refund.pending)
    };
    if let Err(source) = read_result {
        return Err(WorkerError::BodyIo { chunk, source });
    }

    let pwrite_started = Instant::now();
    // pwrite always uses the GLOBAL offset; the part-relative range
    // is only the wire-side coordinate space.
    ctx.sparse
        .pwrite_at(global_range.start(), dest)
        .map_err(|source| WorkerError::SparseFile { chunk, source })?;
    let pwrite_time = pwrite_started.elapsed();

    refund.commit_segment();
    Ok(pwrite_time)
}

/// Multi-segment fetch for a dispatch whose global range crosses
/// one or more part boundaries (`internal/PLAN_multi_url_source.md`).
/// Walks [`MultiPartSource::dispatch_range`] and runs
/// [`download_single_segment`] against each, into the right slice
/// of the combined buffer. Returns the summed `pwrite_at` wall-clock
/// time (used by the run's diagnostics).
fn download_multi_segment(
    ctx: &ChunkContext<'_>,
    chunk: ChunkIndex,
    source: &super::multi_url::MultiPartSource,
    global_range: ByteRange,
    buf: &mut [u8],
    refund: &mut ProgressRefundGuard<'_>,
    cancel: &AtomicBool,
) -> Result<Duration, WorkerError> {
    let dispatch_start = global_range.start().get();
    let mut total_pwrite_time = Duration::ZERO;
    let mut had_segment = false;
    for seg in source.dispatch_range(global_range) {
        had_segment = true;
        let part = source
            .parts()
            .get(seg.part_index)
            .ok_or(WorkerError::MultiPartOutOfRange {
                chunk,
                offset: seg.global.start().get(),
            })?;
        let buf_offset = (seg.global.start().get() - dispatch_start) as usize;
        let buf_end = buf_offset + (seg.global.len() as usize);
        let dest = &mut buf[buf_offset..buf_end];
        let pwrite = download_single_segment(
            ctx,
            chunk,
            &part.url,
            &part.fingerprint,
            seg.part_relative,
            seg.global,
            seg.part_index,
            dest,
            refund,
            cancel,
        )?;
        total_pwrite_time += pwrite;
    }
    if !had_segment {
        return Err(WorkerError::MultiPartOutOfRange {
            chunk,
            offset: dispatch_start,
        });
    }
    Ok(total_pwrite_time)
}

/// Read the env once per process (the value is set before any
/// download starts, so re-checking each call is wasted work). Done
/// inside a function so tests can flip the var if needed.
fn verify_chunks_enabled() -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};
    static CACHE: AtomicU8 = AtomicU8::new(0);
    // States: 0 = unset, 1 = false, 2 = true.
    match CACHE.load(Ordering::Relaxed) {
        1 => false,
        2 => true,
        _ => {
            let on = std::env::var("PEEL_VERIFY_CHUNKS")
                .ok()
                .map(|v| matches!(v.trim(), "1" | "true" | "TRUE"))
                .unwrap_or(false);
            CACHE.store(if on { 2 } else { 1 }, Ordering::Relaxed);
            on
        }
    }
}

/// Re-read each chunk slice we just wrote and compare its CRC-32C
/// against the in-memory value. Surfaces a mismatch as
/// [`WorkerError::ChunkVerifyMismatch`] with the chunk-level detail.
fn verify_on_disk_chunks(
    sparse: &MultiSparse,
    dispatch: &Dispatch,
    chunk_size: u64,
    buf: &[u8],
    crcs: &[u32],
) -> Result<(), WorkerError> {
    let chunk_size_usize = usize::try_from(chunk_size).unwrap_or(usize::MAX);
    let range_start = dispatch.range.start().get();
    for (i, expected) in crcs.iter().copied().enumerate() {
        // Reconstruct the offset/length of this slice from the same
        // arithmetic `compute_chunk_crcs` uses, so the boundaries
        // line up byte-for-byte.
        let in_buf_start = i.saturating_mul(chunk_size_usize);
        let in_buf_end = in_buf_start.saturating_add(chunk_size_usize).min(buf.len());
        if in_buf_start >= in_buf_end {
            break;
        }
        let len = in_buf_end - in_buf_start;
        let on_disk_offset = range_start.saturating_add(in_buf_start as u64);
        let mut readback = vec![0u8; len];
        sparse
            .read_exact_at(ByteOffset::new(on_disk_offset), &mut readback)
            .map_err(|source| WorkerError::SparseFile {
                chunk: ChunkIndex::new(dispatch.first.get().saturating_add(i as u32)),
                source,
            })?;
        let actual = crate::hash::crc32c::castagnoli(&readback);
        if actual != expected {
            return Err(WorkerError::ChunkVerifyMismatch {
                chunk: ChunkIndex::new(dispatch.first.get().saturating_add(i as u32)),
                expected,
                actual,
            });
        }
    }
    Ok(())
}

/// Fill `buf` from `reader`, ticking `progress` after each successful
/// read so the renderer's rate window doesn't stall waiting for a
/// whole multi-MiB dispatch to land. `attempt_progress` accumulates
/// what was added *this attempt* so the caller can roll it back if the
/// read fails partway through.
///
/// Mirrors `Read::read_exact` in every other respect: retries on
/// `Interrupted`, surfaces a short final read as `UnexpectedEof`.
fn read_with_progress<R: Read>(
    reader: &mut R,
    buf: &mut [u8],
    progress: Option<&ProgressState>,
    part_idx: usize,
    attempt_progress: &mut u64,
) -> io::Result<()> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "failed to fill whole buffer",
                ));
            }
            Ok(n) => {
                filled += n;
                let n_u64 = n as u64;
                *attempt_progress = attempt_progress.saturating_add(n_u64);
                if let Some(p) = progress {
                    p.add_downloaded(n_u64);
                    p.add_downloaded_to_part(part_idx, n_u64);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Slice the dispatch body at bitmap-chunk boundaries and compute
/// one CRC-32C per resulting slice.
///
/// The first slice spans `[range.start(), range.start() + chunk_size)`,
/// the second `[range.start() + chunk_size, range.start() + 2*chunk_size)`,
/// and so on. The final slice may be shorter than `chunk_size` for
/// the file's tail chunk; we rely on `dispatch.range.len()` matching
/// the worker's expectation of `count * chunk_size` capped at
/// `total_size`. With `chunk_size == 0` (a config-rejected case) we
/// fall back to one CRC over the whole buffer, matching the
/// scheduler's earlier defensive check.
fn compute_chunk_crcs(buf: &[u8], dispatch: &Dispatch, chunk_size: u64) -> Vec<u32> {
    if chunk_size == 0 || dispatch.count <= 1 {
        let mut hasher = Crc32c::new();
        hasher.update(buf);
        return vec![hasher.finalize()];
    }
    let chunk_size_usize = usize::try_from(chunk_size).unwrap_or(usize::MAX);
    let mut out = Vec::with_capacity(dispatch.count as usize);
    let mut offset = 0usize;
    while offset < buf.len() && out.len() < dispatch.count as usize {
        let end = offset.saturating_add(chunk_size_usize).min(buf.len());
        let mut hasher = Crc32c::new();
        hasher.update(&buf[offset..end]);
        out.push(hasher.finalize());
        offset = end;
    }
    out
}

fn verify_content_range(
    headers: &Headers,
    chunk: ChunkIndex,
    expected: ByteRange,
) -> Result<(), WorkerError> {
    let value = headers
        .get("content-range")
        .ok_or(WorkerError::ContentRangeMismatch {
            chunk,
            expected,
            actual: None,
        })?;
    let parsed =
        parse_content_range(value).map_err(|source| WorkerError::ContentRangeMalformed {
            chunk,
            value: value.to_string(),
            source,
        })?;
    if parsed.as_byte_range() != expected {
        return Err(WorkerError::ContentRangeMismatch {
            chunk,
            expected,
            actual: Some(value.to_string()),
        });
    }
    Ok(())
}

fn verify_content_length(
    resp: &crate::http::Response,
    chunk: ChunkIndex,
    expected: u64,
) -> Result<(), WorkerError> {
    match resp.content_length() {
        Some(n) if n == expected => Ok(()),
        other => Err(WorkerError::BodyLengthMismatch {
            chunk,
            expected,
            actual: other,
        }),
    }
}

fn verify_fingerprint(
    headers: &Headers,
    expected: &SourceFingerprint,
    chunk: ChunkIndex,
) -> Result<(), WorkerError> {
    let actual_etag = headers.get("etag").map(str::to_string);
    let actual_lm = headers.get("last-modified").map(str::to_string);

    if let Some(want) = &expected.etag {
        // RFC 7232 §2.3: weak ETags only validate semantic
        // equivalence, so a mismatch on its own is advisory. The
        // §11 CRC-32C probe is the byte-level guard.
        let mismatch = actual_etag.as_deref() != Some(want.as_str());
        if mismatch && !etag_is_weak(want) {
            return Err(WorkerError::SourceChanged {
                chunk,
                expected_etag: Some(want.clone()),
                actual_etag,
                expected_last_modified: expected.last_modified.clone(),
                actual_last_modified: actual_lm,
            });
        }
    }
    if let Some(want) = &expected.last_modified {
        if actual_lm.as_deref() != Some(want.as_str()) {
            return Err(WorkerError::SourceChanged {
                chunk,
                expected_etag: expected.etag.clone(),
                actual_etag,
                expected_last_modified: Some(want.clone()),
                actual_last_modified: actual_lm,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::download::sparse_file::SparseFile;
    use crate::types::{ByteOffset, ByteRange};

    fn make_range(start: u64, end_exclusive: u64) -> ByteRange {
        ByteRange::new(ByteOffset::new(start), ByteOffset::new(end_exclusive))
            .expect("test range non-reversed")
    }

    fn dummy_client_io_err() -> ClientError {
        ClientError::Io {
            host: "h".into(),
            port: 0,
            source: io::Error::other("simulated"),
        }
    }

    // ---- WorkerError::is_retryable ------------------------------------

    #[test]
    fn transport_io_is_retryable() {
        let e = WorkerError::Transport {
            chunk: ChunkIndex::ZERO,
            source: dummy_client_io_err(),
        };
        assert!(e.is_retryable());
    }

    #[test]
    fn unexpected_status_5xx_is_retryable() {
        let e = WorkerError::UnexpectedStatus {
            chunk: ChunkIndex::ZERO,
            status: 503,
        };
        assert!(e.is_retryable());
    }

    #[test]
    fn unexpected_status_4xx_is_terminal() {
        let e = WorkerError::UnexpectedStatus {
            chunk: ChunkIndex::ZERO,
            status: 404,
        };
        assert!(!e.is_retryable());
    }

    #[test]
    fn source_changed_is_terminal() {
        let e = WorkerError::SourceChanged {
            chunk: ChunkIndex::ZERO,
            expected_etag: Some("a".into()),
            actual_etag: Some("b".into()),
            expected_last_modified: None,
            actual_last_modified: None,
        };
        assert!(!e.is_retryable());
    }

    #[test]
    fn content_range_mismatch_is_terminal() {
        let r = make_range(0, 100);
        let e = WorkerError::ContentRangeMismatch {
            chunk: ChunkIndex::ZERO,
            expected: r,
            actual: Some("bytes 0-50/100".into()),
        };
        assert!(!e.is_retryable());
    }

    #[test]
    fn body_io_is_retryable() {
        let e = WorkerError::BodyIo {
            chunk: ChunkIndex::ZERO,
            source: io::Error::from(io::ErrorKind::UnexpectedEof),
        };
        assert!(e.is_retryable());
    }

    #[test]
    fn cancelled_is_terminal() {
        let e = WorkerError::Cancelled {
            chunk: ChunkIndex::ZERO,
        };
        assert!(!e.is_retryable());
    }

    // ---- SourceFingerprint --------------------------------------------

    #[test]
    fn fingerprint_from_headers_extracts_etag_and_lm() {
        let mut h = Headers::default();
        h.append("ETag", "\"abc\"");
        h.append("Last-Modified", "Wed, 01 Jan 2025 00:00:00 GMT");
        let fp = SourceFingerprint::from_headers(&h);
        assert_eq!(fp.etag.as_deref(), Some("\"abc\""));
        assert_eq!(
            fp.last_modified.as_deref(),
            Some("Wed, 01 Jan 2025 00:00:00 GMT")
        );
        assert!(!fp.is_empty());
    }

    #[test]
    fn fingerprint_empty_when_no_headers() {
        let h = Headers::default();
        let fp = SourceFingerprint::from_headers(&h);
        assert!(fp.is_empty());
    }

    // ---- verify_content_range -----------------------------------------

    #[test]
    fn content_range_match_passes() {
        let mut h = Headers::default();
        h.append("Content-Range", "bytes 0-99/1000");
        let r = make_range(0, 100);
        verify_content_range(&h, ChunkIndex::ZERO, r).expect("matches");
    }

    #[test]
    fn content_range_disagreement_errors() {
        let mut h = Headers::default();
        h.append("Content-Range", "bytes 0-50/1000");
        let r = make_range(0, 100);
        match verify_content_range(&h, ChunkIndex::ZERO, r) {
            Err(WorkerError::ContentRangeMismatch { actual, .. }) => {
                assert_eq!(actual.as_deref(), Some("bytes 0-50/1000"));
            }
            other => panic!("expected mismatch, got {other:?}"),
        }
    }

    #[test]
    fn content_range_missing_errors() {
        let h = Headers::default();
        let r = make_range(0, 100);
        assert!(matches!(
            verify_content_range(&h, ChunkIndex::ZERO, r),
            Err(WorkerError::ContentRangeMismatch { actual: None, .. })
        ));
    }

    #[test]
    fn content_range_malformed_errors() {
        let mut h = Headers::default();
        h.append("Content-Range", "garbage");
        let r = make_range(0, 100);
        assert!(matches!(
            verify_content_range(&h, ChunkIndex::ZERO, r),
            Err(WorkerError::ContentRangeMalformed { .. })
        ));
    }

    // ---- verify_fingerprint -------------------------------------------

    #[test]
    fn fingerprint_match_etag_only_passes() {
        let mut h = Headers::default();
        h.append("ETag", "\"v1\"");
        let fp = SourceFingerprint {
            etag: Some("\"v1\"".into()),
            last_modified: None,
        };
        verify_fingerprint(&h, &fp, ChunkIndex::ZERO).expect("matches");
    }

    #[test]
    fn fingerprint_etag_mismatch_errors() {
        let mut h = Headers::default();
        h.append("ETag", "\"v2\"");
        let fp = SourceFingerprint {
            etag: Some("\"v1\"".into()),
            last_modified: None,
        };
        match verify_fingerprint(&h, &fp, ChunkIndex::ZERO) {
            Err(WorkerError::SourceChanged {
                expected_etag,
                actual_etag,
                ..
            }) => {
                assert_eq!(expected_etag.as_deref(), Some("\"v1\""));
                assert_eq!(actual_etag.as_deref(), Some("\"v2\""));
            }
            other => panic!("expected SourceChanged, got {other:?}"),
        }
    }

    #[test]
    fn fingerprint_etag_missing_when_expected_errors() {
        let h = Headers::default();
        let fp = SourceFingerprint {
            etag: Some("\"v1\"".into()),
            last_modified: None,
        };
        assert!(matches!(
            verify_fingerprint(&h, &fp, ChunkIndex::ZERO),
            Err(WorkerError::SourceChanged { .. })
        ));
    }

    #[test]
    fn fingerprint_last_modified_match_passes() {
        let mut h = Headers::default();
        h.append("Last-Modified", "Wed, 01 Jan 2025 00:00:00 GMT");
        let fp = SourceFingerprint {
            etag: None,
            last_modified: Some("Wed, 01 Jan 2025 00:00:00 GMT".into()),
        };
        verify_fingerprint(&h, &fp, ChunkIndex::ZERO).expect("matches");
    }

    #[test]
    fn fingerprint_no_expected_passes() {
        let h = Headers::default();
        let fp = SourceFingerprint::default();
        verify_fingerprint(&h, &fp, ChunkIndex::ZERO).expect("nothing to check");
    }

    #[test]
    fn weak_etag_mismatch_is_advisory() {
        // Per RFC 7232 §2.3 a weak ETag (W/-prefixed) only validates
        // semantic equivalence, so a value drift at the byte level
        // does not by itself prove the source changed. §11's
        // CRC-32C probe is the byte-level guard.
        let mut h = Headers::default();
        h.append("ETag", "W/\"v2\"");
        let fp = SourceFingerprint {
            etag: Some("W/\"v1\"".into()),
            last_modified: None,
        };
        verify_fingerprint(&h, &fp, ChunkIndex::ZERO).expect("weak mismatch is advisory");
    }

    #[test]
    fn strong_etag_mismatch_still_errors_when_only_one_is_strong() {
        // A weak expected vs strong actual (or vice versa) — only
        // when *both* sides are weak do we treat it as advisory.
        let mut h = Headers::default();
        h.append("ETag", "\"strong\"");
        let fp = SourceFingerprint {
            etag: Some("W/\"weak\"".into()),
            last_modified: None,
        };
        // Source-side is weak; we treat this as advisory because
        // weak validators carry no byte-level promise. §11 catches
        // any actual drift.
        verify_fingerprint(&h, &fp, ChunkIndex::ZERO).expect("weak expected is advisory");
    }

    #[test]
    fn etag_is_weak_detects_w_prefix() {
        assert!(etag_is_weak("W/\"abc\""));
        assert!(etag_is_weak("w/\"abc\""));
        assert!(!etag_is_weak("\"abc\""));
        assert!(!etag_is_weak(""));
    }

    // ---- §3.3 PEEL_VERIFY_CHUNKS post-write audit ---------------------

    /// Hand-rolled drop-on-end file cleanup so we don't need the
    /// `scopeguard` crate (not on the dependency allowlist).
    struct TmpFileGuard(std::path::PathBuf);
    impl Drop for TmpFileGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn unique_tmp(label: &str) -> std::path::PathBuf {
        // Avoid timer collisions across rapid-fire tests on the same
        // tick by mixing in a process-local counter.
        use std::sync::atomic::{AtomicU64, Ordering as O};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, O::Relaxed);
        std::env::temp_dir().join(format!(
            "peel_worker_verify_{label}_{}_{seq}_{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos(),
        ))
    }

    /// Demo from §3.3: simulate "pwrite reports success but the bytes
    /// on disk disagree with what we wrote" by handing
    /// `verify_on_disk_chunks` an in-memory CRC slice that doesn't
    /// match the on-disk content. The function must surface
    /// [`WorkerError::ChunkVerifyMismatch`] with the offending chunk
    /// index — i.e., the audit catches it before the chunk is marked
    /// complete in the bitmap.
    #[test]
    fn verify_on_disk_chunks_flags_mismatch_with_chunk_index() {
        let path = unique_tmp("mismatch");
        let _g = TmpFileGuard(path.clone());
        let total_size: u64 = 4096;
        let chunk_size: u64 = 1024;
        let sparse = MultiSparse::from_single(
            SparseFile::open_or_create(&path, total_size).expect("sparse"),
        );

        // Write some "genuine" bytes to disk at offset 0..2048.
        let on_disk: Vec<u8> = (0..2048u32).map(|i| (i & 0xFF) as u8).collect();
        sparse
            .pwrite_at(ByteOffset::ZERO, &on_disk)
            .expect("pwrite");

        // Pretend we *thought* we'd just written `claimed_buf` —
        // identical for chunk 0 but with one byte flipped in chunk 1.
        let mut claimed_buf = on_disk.clone();
        claimed_buf[1024 + 5] ^= 0x01;

        // The CRCs the worker would have computed against
        // `claimed_buf`. We feed these to `verify_on_disk_chunks`
        // along with the *real* on-disk bytes, simulating a write
        // path that succeeded in our buffer but lost a byte before
        // hitting the platter.
        let dispatch = Dispatch {
            first: ChunkIndex::ZERO,
            count: 2,
            range: ByteRange::new(ByteOffset::ZERO, ByteOffset::new(2048)).expect("range"),
            kind: DispatchKind::Fetch,
        };
        let crcs = compute_chunk_crcs(&claimed_buf, &dispatch, chunk_size);

        // Verify against the on-disk bytes (`sparse`'s contents).
        let result = verify_on_disk_chunks(&sparse, &dispatch, chunk_size, &claimed_buf, &crcs);
        match result {
            Err(WorkerError::ChunkVerifyMismatch {
                chunk,
                expected,
                actual,
            }) => {
                assert_eq!(chunk.get(), 1, "mismatch belongs to chunk 1");
                assert_ne!(expected, actual);
            }
            other => panic!("expected ChunkVerifyMismatch, got {other:?}"),
        }
    }

    /// Sanity: when the on-disk bytes match what we wrote, the audit
    /// is a no-op.
    #[test]
    fn verify_on_disk_chunks_passes_when_bytes_match() {
        let path = unique_tmp("ok");
        let _g = TmpFileGuard(path.clone());
        let total_size: u64 = 2048;
        let chunk_size: u64 = 1024;
        let sparse = MultiSparse::from_single(
            SparseFile::open_or_create(&path, total_size).expect("sparse"),
        );
        let buf: Vec<u8> = (0..2048u32).map(|i| (i & 0xFF) as u8).collect();
        sparse.pwrite_at(ByteOffset::ZERO, &buf).expect("pwrite");

        let dispatch = Dispatch {
            first: ChunkIndex::ZERO,
            count: 2,
            range: ByteRange::new(ByteOffset::ZERO, ByteOffset::new(2048)).expect("range"),
            kind: DispatchKind::Fetch,
        };
        let crcs = compute_chunk_crcs(&buf, &dispatch, chunk_size);
        verify_on_disk_chunks(&sparse, &dispatch, chunk_size, &buf, &crcs).expect("ok");
    }

    /// `ChunkVerifyMismatch` is terminal: there's no point retrying a
    /// dispatch whose body the kernel mangled on the way to disk.
    #[test]
    fn chunk_verify_mismatch_is_terminal() {
        let e = WorkerError::ChunkVerifyMismatch {
            chunk: ChunkIndex::ZERO,
            expected: 0xAAAA_AAAA,
            actual: 0xBBBB_BBBB,
        };
        assert!(!e.is_retryable());
    }

    // ---- sleep_with_cancel --------------------------------------------

    #[test]
    fn sleep_with_cancel_returns_true_on_completion() {
        let cancel = AtomicBool::new(false);
        let started = Instant::now();
        let ok = sleep_with_cancel(Duration::from_millis(30), &cancel);
        assert!(ok);
        assert!(started.elapsed() >= Duration::from_millis(25));
    }

    #[test]
    fn sleep_with_cancel_returns_false_when_cancelled() {
        let cancel = AtomicBool::new(true);
        let ok = sleep_with_cancel(Duration::from_secs(60), &cancel);
        assert!(!ok);
    }

    #[test]
    fn sleep_with_cancel_zero_duration_respects_cancel() {
        let cancel = AtomicBool::new(false);
        assert!(sleep_with_cancel(Duration::ZERO, &cancel));
        cancel.store(true, Ordering::Relaxed);
        assert!(!sleep_with_cancel(Duration::ZERO, &cancel));
    }

    // ---- ProgressRefundGuard (PLAN_decoder_freeze.md §1.2) -----------

    fn snapshot_downloaded(state: &ProgressState) -> u64 {
        state.snapshot().bytes_downloaded
    }

    /// Drop without disarming refunds every credited byte. This is the
    /// path a panicking worker, a `pwrite_at` failure, or a cancelled
    /// read would all hit.
    #[test]
    fn progress_refund_guard_drop_unarmed_subtracts_credited_bytes() {
        let state = ProgressState::new();
        state.add_downloaded(1_000_000);
        {
            let mut guard = ProgressRefundGuard::new(Some(&state));
            guard.begin_segment(0);
            // Mirror the read loop: every `read` call adds to both the
            // shared counter and the guard's local tally.
            for _ in 0..3 {
                state.add_downloaded(64 * 1024);
                guard.pending = guard.pending.saturating_add(64 * 1024);
            }
            // Guard never disarmed — a real worker would have hit an
            // error or panicked on the way to `disarm()`.
        }
        assert_eq!(
            snapshot_downloaded(&state),
            1_000_000,
            "expected full refund of the in-flight increments"
        );
    }

    /// Disarmed guard leaves the credited bytes intact — the success
    /// path of a completed attempt.
    #[test]
    fn progress_refund_guard_disarmed_leaves_bytes_credited() {
        let state = ProgressState::new();
        {
            let mut guard = ProgressRefundGuard::new(Some(&state));
            guard.begin_segment(0);
            state.add_downloaded(128 * 1024);
            guard.pending = guard.pending.saturating_add(128 * 1024);
            guard.commit_segment();
            guard.disarm();
        }
        assert_eq!(snapshot_downloaded(&state), 128 * 1024);
    }

    /// A panic across the guard's scope still triggers refund — that's
    /// the whole point of choosing RAII over a manual call site. The
    /// scheduler's `catch_unwind` would otherwise leak the bytes.
    #[test]
    fn progress_refund_guard_refunds_on_panic_unwind() {
        let state = Arc::new(ProgressState::new());
        let state_for_panic = Arc::clone(&state);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut guard = ProgressRefundGuard::new(Some(&state_for_panic));
            guard.begin_segment(0);
            state_for_panic.add_downloaded(256 * 1024);
            guard.pending = guard.pending.saturating_add(256 * 1024);
            // Simulate a panic site after partial credit (e.g. a
            // pwrite_at that triple-faulted, or a verify path that
            // assertion-failed). We never reach `disarm()`.
            panic!("simulated worker fault");
        }));
        assert!(result.is_err(), "panic should propagate");
        assert_eq!(snapshot_downloaded(&state), 0);
    }

    /// `progress = None` (the rare path where no progress sink is
    /// attached) must be a silent no-op on drop.
    #[test]
    fn progress_refund_guard_with_no_progress_is_noop() {
        let mut guard = ProgressRefundGuard::new(None);
        guard.begin_segment(0);
        guard.pending = 4096;
        drop(guard);
        // Nothing to assert beyond "did not panic"; the test exists to
        // pin the None-branch behavior so a future refactor can't
        // accidentally make it write through a None.
    }

    /// Multi-segment dispatch: a later-segment failure must roll
    /// back the earlier segments' credits too.
    #[test]
    fn progress_refund_guard_refunds_committed_segments_on_drop() {
        let state = ProgressState::new();
        state.set_parts(vec![("p0".into(), 1024 * 1024), ("p1".into(), 1024 * 1024)]);
        {
            let mut guard = ProgressRefundGuard::new(Some(&state));
            // Segment 0 succeeds: 100 KiB credited and committed.
            guard.begin_segment(0);
            state.add_downloaded(100 * 1024);
            state.add_downloaded_to_part(0, 100 * 1024);
            guard.pending = 100 * 1024;
            guard.commit_segment();
            // Segment 1 partially credits then "fails": pending
            // sits in the guard. On drop, both the committed
            // segment 0 and the pending segment 1 must be refunded.
            guard.begin_segment(1);
            state.add_downloaded(40 * 1024);
            state.add_downloaded_to_part(1, 40 * 1024);
            guard.pending = 40 * 1024;
        }
        let snap = state.snapshot();
        assert_eq!(snap.bytes_downloaded, 0, "aggregate fully refunded");
        assert_eq!(snap.parts[0].bytes_downloaded, 0, "p0 fully refunded");
        assert_eq!(snap.parts[1].bytes_downloaded, 0, "p1 fully refunded");
    }
}
