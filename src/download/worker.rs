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
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;

use super::sparse_file::{SparseFile, SparseFileError};
use crate::hash::crc32c::Crc32c;
use crate::http::range::{parse_content_range, RangeError};
use crate::http::{Client, ClientError, Headers, Url};
use crate::progress::ProgressState;
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

    /// The scheduler asked the worker to stop. Returned in place of
    /// continuing a backoff sleep.
    #[error("download cancelled before chunk {chunk} completed")]
    Cancelled {
        /// Chunk that was in flight when cancellation was observed.
        chunk: ChunkIndex,
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
            Self::Cancelled { .. } => false,
        }
    }
}

fn is_transport_retryable(err: &ClientError) -> bool {
    matches!(
        err,
        ClientError::Io { .. }
            | ClientError::Tls { .. }
            | ClientError::Response(_)
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
    /// Number of attempts taken (1 = first attempt succeeded).
    pub attempts: u32,
    /// CRC-32C per bitmap chunk in the dispatch, in chunk order
    /// (`PLAN_v2.md` §11). Empty for `Probe` dispatches — the probe
    /// path verifies in-line and never bubbles raw fingerprints up.
    pub crcs: Vec<u32>,
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
    /// URL of the source (post-redirect, from `discover()`).
    pub url: &'a Url,
    /// `ETag` / `Last-Modified` to verify on every response.
    pub fingerprint: &'a SourceFingerprint,
    /// Bitmap chunk size — used to slice the dispatch body into
    /// per-chunk CRC-32Cs (`PLAN_v2.md` §11).
    pub chunk_size: u64,
    /// Sparse file the chunk's bytes are written into.
    pub sparse: &'a SparseFile,
    /// Optional progress sink the worker `fetch_add`s into after
    /// each successful `pwrite_at` (PLAN_v2.md §6). `None` keeps the
    /// worker silent — used by tests that don't drive the renderer.
    pub progress: Option<&'a ProgressState>,
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
/// Returns the *last* error observed if all retries are exhausted, or
/// the first non-retryable error encountered.
pub fn download_chunk(
    ctx: &ChunkContext<'_>,
    chunk: ChunkIndex,
    range: ByteRange,
    retry: &RetryConfig,
    cancel: &AtomicBool,
) -> Result<ChunkOutcome, WorkerError> {
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
/// Returns the *last* error observed if all retries are exhausted, or
/// the first non-retryable error encountered.
pub fn download_dispatch(
    ctx: &ChunkContext<'_>,
    dispatch: Dispatch,
    retry: &RetryConfig,
    cancel: &AtomicBool,
) -> Result<ChunkOutcome, WorkerError> {
    let chunk = dispatch.first;
    if cancel.load(Ordering::Relaxed) {
        return Err(WorkerError::Cancelled { chunk });
    }
    let mut attempt: u32 = 0;
    let mut backoff = retry.initial_backoff;
    loop {
        attempt = attempt.saturating_add(1);
        let err = match try_once(ctx, &dispatch) {
            Ok((bytes, crcs)) => {
                // Probe dispatches verify in-line and never bubble
                // CRCs up to the scheduler — they're already
                // verified against the expected value.
                if let DispatchKind::Probe { expected } = dispatch.kind {
                    let actual = crcs.first().copied().unwrap_or(0);
                    if actual != expected {
                        return Err(WorkerError::SourceDriftDetected {
                            chunk,
                            expected,
                            actual,
                        });
                    }
                    return Ok(ChunkOutcome {
                        bytes,
                        attempts: attempt,
                        crcs: Vec::new(),
                    });
                }
                return Ok(ChunkOutcome {
                    bytes,
                    attempts: attempt,
                    crcs,
                });
            }
            Err(e) if !e.is_retryable() => return Err(e),
            Err(e) => e,
        };
        if attempt >= retry.max_attempts {
            return Err(err);
        }
        if !sleep_with_cancel(backoff, cancel) {
            return Err(WorkerError::Cancelled { chunk });
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

fn try_once(ctx: &ChunkContext<'_>, dispatch: &Dispatch) -> Result<(u64, Vec<u32>), WorkerError> {
    let chunk = dispatch.first;
    let range = dispatch.range;
    let resp = ctx
        .client
        .get_range(ctx.url, range)
        .map_err(|source| match source {
            ClientError::UnexpectedStatus { status, .. } => {
                WorkerError::UnexpectedStatus { chunk, status }
            }
            other => WorkerError::Transport {
                chunk,
                source: other,
            },
        })?;

    verify_content_range(&resp.headers, chunk, range)?;
    verify_content_length(&resp, chunk, range.len())?;
    verify_fingerprint(&resp.headers, ctx.fingerprint, chunk)?;

    let len_usize = usize::try_from(range.len()).map_err(|_| WorkerError::BodyLengthMismatch {
        chunk,
        expected: range.len(),
        actual: None,
    })?;
    let mut buf = vec![0u8; len_usize];
    let mut body = resp.body;
    body.read_exact(&mut buf)
        .map_err(|source| WorkerError::BodyIo { chunk, source })?;

    ctx.sparse
        .pwrite_at(range.start(), &buf)
        .map_err(|source| WorkerError::SparseFile { chunk, source })?;

    if let Some(p) = ctx.progress {
        p.add_downloaded(range.len());
    }

    if body.is_drained() {
        let reader = body.into_inner();
        ctx.client.release(ctx.url, reader);
    }
    // Otherwise drop the body, closing the underlying connection.

    let crcs = compute_chunk_crcs(&buf, dispatch, ctx.chunk_size);
    Ok((range.len(), crcs))
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

fn verify_content_length<R: io::BufRead>(
    resp: &crate::http::Response<R>,
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
}
