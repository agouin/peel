//! Download scheduler: chunk planning and parallel worker dispatch.
//!
//! [`discover`] does the initial `HEAD` and returns a [`DownloadInfo`]
//! summarising the source. [`run`] orchestrates the actual transfer:
//! parallel ranged GETs when the server advertises
//! `Accept-Ranges: bytes`, single-stream fallback otherwise.
//!
//! # Threading
//!
//! Parallel mode uses [`std::thread::scope`] to spawn N worker threads.
//! Workers receive [`Dispatch`] assignments from a bounded
//! `mpsc::sync_channel` (the **task** channel) and report results on a
//! second `mpsc::channel` (the **completion** channel). Each
//! [`Dispatch`] covers one or more contiguous bitmap chunks fetched in
//! a single ranged GET (see `PLAN_v2.md` §8 — adaptive chunk size).
//! The calling thread serves as the scheduler: it picks the next
//! dispatch based on the decoder's cursor (chunks at or past the
//! cursor are preferred), waits on completions, and tracks progress.
//!
//! # Cursor priority
//!
//! The decoder's read cursor is exposed as a shared
//! [`AtomicU64`](std::sync::atomic::AtomicU64). On each dispatch the
//! scheduler reads the cursor, computes the corresponding chunk index,
//! and asks the dispatch bitmap for the next not-yet-claimed chunk at
//! or past that index. If every chunk past the cursor is already in
//! flight, dispatch wraps to the start of the file.
//!
//! # Resume
//!
//! The scheduler treats any chunk already marked complete in the
//! shared [`ChunkBitmap`] as a no-op: it skips dispatch for those
//! indices entirely. The caller wires resume by loading the bitmap
//! from a checkpoint before calling [`run`].

use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;

use super::chunk_fingerprints::ChunkFingerprints;
use super::chunk_policy::{ChunkSizePolicy, Sample};
use super::mirrors::{Mirror, MirrorSet};
use super::multi_sparse::MultiSparse;
use super::multi_url::{MultiPartSource, MultiPartSourceError};
use super::rate_limit::{RateLimitedReader, RateLimiter};
use super::sparse_file::SparseFileError;
use super::worker::{
    download_dispatch, ChunkContext, ChunkOutcome, Dispatch, DispatchKind, RetryConfig,
    SourceFingerprint, WorkerError,
};
use crate::bitmap::ChunkBitmap;
use crate::http::range::parse_content_range;
use crate::http::{Client, ClientError, Url};
use crate::progress::ProgressState;
use crate::types::{ByteOffset, ByteRange, ChunkIndex};

/// Default chunk size: 4 MiB. Matches `aria2c` and `curl`'s ranged
/// download defaults.
pub const DEFAULT_CHUNK_SIZE: u64 = 4 * 1024 * 1024;
/// Default worker count.
pub const DEFAULT_WORKERS: u32 = 4;
/// Default §11 mid-flight probe interval: every 32nd completed
/// dispatch triggers a re-fetch of an already-complete chunk.
/// Tunable via [`SchedulerConfig::probe`].
pub const DEFAULT_PROBE_INTERVAL: u32 = 32;
/// Cap on how many times the scheduler will respawn a dead worker
/// before treating the run as unrecoverable. Each respawn is logged
/// at `WARN`; exceeding the cap surfaces as
/// [`SchedulerError::WorkersExhausted`] so a pathologically panicking
/// worker doesn't loop forever.
const MAX_WORKER_RESPAWNS: u32 = 100;

/// Why a `--mirror` URL was rejected during the agreement check.
///
/// Not a [`SchedulerError`]: discovery only *drops* disagreeing
/// mirrors with a `tracing::warn!`, it does not fail the run as long
/// as the primary is reachable. This enum is exposed so library
/// callers and tests can introspect the dropped set.
#[derive(Debug, Clone)]
pub enum MirrorAgreementError {
    /// The mirror's `HEAD` failed (network error, 4xx/5xx, missing
    /// `Content-Length`, etc.).
    HeadFailed {
        /// URL the HEAD was issued against.
        url: String,
        /// Human-readable reason.
        reason: String,
    },
    /// The mirror's `Content-Length` did not match the primary.
    SizeMismatch {
        /// Mirror URL.
        url: String,
        /// Mirror's reported total size.
        actual: u64,
        /// Size the primary reported.
        expected: u64,
    },
    /// The mirror's `ETag` / `Last-Modified` disagreed with the
    /// primary's, and the run is not using `--sha256` to provide an
    /// alternative byte-level guarantee.
    FingerprintMismatch {
        /// Mirror URL.
        url: String,
        /// Mirror-side `ETag`, if any.
        actual_etag: Option<String>,
        /// Primary `ETag`, if any.
        expected_etag: Option<String>,
        /// Mirror-side `Last-Modified`, if any.
        actual_last_modified: Option<String>,
        /// Primary `Last-Modified`, if any.
        expected_last_modified: Option<String>,
    },
}

impl std::fmt::Display for MirrorAgreementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeadFailed { url, reason } => write!(f, "{url}: HEAD failed ({reason})"),
            Self::SizeMismatch {
                url,
                actual,
                expected,
            } => write!(f, "{url}: size {actual} disagrees with primary {expected}"),
            Self::FingerprintMismatch {
                url,
                actual_etag,
                expected_etag,
                actual_last_modified,
                expected_last_modified,
            } => write!(
                f,
                "{url}: fingerprint mismatch (etag {actual_etag:?} vs primary {expected_etag:?}, \
                 last-modified {actual_last_modified:?} vs primary {expected_last_modified:?})"
            ),
        }
    }
}

/// Errors produced by the scheduler.
#[derive(Debug, Error)]
pub enum SchedulerError {
    /// The discovery `HEAD` failed.
    #[error("HEAD request failed for {url}")]
    Head {
        /// URL that was probed.
        url: String,
        /// Underlying client error.
        #[source]
        source: ClientError,
    },

    /// The server's `HEAD` did not include `Content-Length`.
    #[error("server did not return Content-Length for {url}")]
    MissingContentLength {
        /// URL that was probed.
        url: String,
    },

    /// The supplied [`ChunkBitmap`] does not cover the chunk count
    /// implied by `total_size / chunk_size`.
    #[error("bitmap length {actual} does not match expected chunk count {expected}")]
    BitmapLengthMismatch {
        /// What the caller passed in.
        actual: u32,
        /// What the scheduler computed.
        expected: u32,
    },

    /// `chunk_size` was zero.
    #[error("chunk size must be greater than zero")]
    InvalidChunkSize,

    /// `workers` was zero.
    #[error("worker count must be greater than zero")]
    InvalidWorkerCount,

    /// `total_size / chunk_size` overflowed `u32`.
    #[error(
        "source is too large for the configured chunk size: {chunks} chunks needed (max {max})"
    )]
    TooManyChunks {
        /// Chunks the source would need.
        chunks: u64,
        /// Hard cap (`u32::MAX`).
        max: u64,
    },

    /// A worker failed all retry attempts for a chunk.
    #[error("chunk {chunk} failed after {attempts} attempts")]
    ChunkFailed {
        /// Chunk that exhausted retries.
        chunk: ChunkIndex,
        /// Total attempts made.
        attempts: u32,
        /// Underlying worker error.
        #[source]
        source: WorkerError,
    },

    /// A `PLAN_v2.md` §11 mid-flight probe re-fetched an
    /// already-complete chunk and observed a CRC-32C that disagreed
    /// with the value the original fetch recorded. The source must
    /// have changed between the two fetches.
    #[error(
        "source changed during download: chunk {chunk} probe CRC32C mismatch \
         (expected {expected:#010x}, observed {actual:#010x})"
    )]
    SourceChangedDuringDownload {
        /// Chunk whose probe failed.
        chunk: ChunkIndex,
        /// CRC-32C the original fetch recorded.
        expected: u32,
        /// CRC-32C the probe just computed.
        actual: u32,
    },

    /// The single-stream fallback hit a transport error or framing
    /// issue. Single-stream mode does no retries — fallback is a
    /// last-resort path.
    #[error("single-stream download of {url} failed")]
    SingleStream {
        /// URL being downloaded.
        url: String,
        /// Underlying client error.
        #[source]
        source: ClientError,
    },

    /// Single-stream body framing did not match `Content-Length`.
    #[error("single-stream body length mismatch: expected {expected}, got {actual}")]
    SingleStreamBodyLength {
        /// `Content-Length` reported by the server.
        expected: u64,
        /// Bytes actually delivered before EOF.
        actual: u64,
    },

    /// Constructing a [`MultiPartSource`] from the discovered parts
    /// failed (empty list, zero-sized part, or total-size overflow).
    /// The single-URL discovery path can only hit
    /// [`MultiPartSourceError::ZeroSizedPart`] in practice — the
    /// `Content-Length: 0` rejection upstream is what protects this
    /// arm — but we surface every variant cleanly so [`discover_multi`]
    /// can share the same error path.
    #[error("invalid multi-part source")]
    MultiPart(#[source] MultiPartSourceError),

    /// IO into the sparse file failed.
    #[error("sparse-file io")]
    SparseFile(#[source] SparseFileError),

    /// IO reading the streaming response body.
    #[error("io reading response body")]
    BodyIo(#[source] std::io::Error),

    /// Workers kept dying and the scheduler exceeded
    /// [`MAX_WORKER_RESPAWNS`] respawns. Surfaces a panic loop or a
    /// systemic failure (out of file descriptors, OS thread limit
    /// reached, etc.) instead of looping forever.
    #[error("download workers kept dying; respawned {respawns} times before giving up")]
    WorkersExhausted {
        /// Total respawn attempts before bailing.
        respawns: u32,
    },
}

/// Discovery summary returned by [`discover`] and [`discover_multi`].
///
/// The legacy fields (`url`, `total_size`, `fingerprint`) reflect the
/// **primary** part — for single-URL discovery they are identical to
/// the source's only part; for multi-URL discovery they describe
/// `source.parts()[0]` while `total_size` carries the sum across all
/// parts. The full per-part data lives in [`Self::source`]; downstream
/// code that needs to route ranged GETs per part reads from there
/// (`internal/PLAN_multi_url_source.md` §1).
#[derive(Debug, Clone)]
pub struct DownloadInfo {
    /// Final URL after redirects (primary part for multi-URL runs).
    pub url: Url,
    /// Total virtual source size in bytes — the sum of every part's
    /// `Content-Length` for multi-URL runs.
    pub total_size: u64,
    /// Source identity captured from `ETag` / `Last-Modified` of the
    /// primary part. Per-part fingerprints live on
    /// `source.parts()[i].fingerprint`.
    pub fingerprint: SourceFingerprint,
    /// True iff every part advertised `Accept-Ranges: bytes`. Without
    /// it, parallel ranged GETs are not safe; the run falls back to
    /// the single-stream path (which only supports a single URL).
    pub accept_ranges: bool,
    /// True when `total_size` is the real source size. `false` only for
    /// the unknown-size single-stream path: a range-less server that
    /// also omitted `Content-Length` (chunked / HTTP-2 / close-delimited).
    /// In that case `total_size` is `0` on entry and the real size is
    /// only learned by streaming the body to EOF (`internal` issue #8).
    pub size_known: bool,
    /// The full per-part view. For single-URL runs this is a
    /// one-element source whose fields agree with the legacy fields
    /// above; for multi-URL runs it carries every part with its own
    /// URL, size, and fingerprint.
    pub source: MultiPartSource,
}

/// Tunables for [`run`].
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Chunk size in bytes. Must be non-zero. This is the **bitmap
    /// chunk size** — the unit of completion tracked in the bitmap
    /// and persisted in checkpoints. With adaptive chunk sizing
    /// disabled (default for `--chunk-size <N>` runs), it is also
    /// the per-task dispatch size.
    pub chunk_size: u64,
    /// Number of parallel workers in `Accept-Ranges` mode. Must be
    /// non-zero. Single-stream mode ignores this.
    pub workers: u32,
    /// Per-chunk retry policy.
    pub retry: RetryConfig,
    /// Optional shared progress sink (`PLAN_v2.md` §6). When set, the
    /// scheduler updates `total_workers` once and workers update
    /// `bytes_downloaded` / `active_workers` as they fetch chunks.
    /// `None` keeps the scheduler silent.
    pub progress: Option<Arc<ProgressState>>,
    /// Optional adaptive chunk-size policy (`PLAN_v2.md` §8). When
    /// `Some`, the scheduler coalesces consecutive incomplete chunks
    /// into one ranged GET sized at `policy.current()`, and feeds
    /// completion samples back to the policy so it can grow / shrink
    /// the dispatch size over time. `None` (default) preserves the
    /// pre-§8 1-chunk-per-task behaviour.
    pub policy: Option<Arc<ChunkSizePolicy>>,
    /// Optional per-chunk CRC-32C fingerprint store (`PLAN_v2.md`
    /// §11). When set, the scheduler records each completed chunk's
    /// CRC-32C and periodically issues a probe re-fetch to verify
    /// the source has not drifted under us. `None` disables both
    /// recording and probing — the pre-§11 behaviour.
    pub fingerprints: Option<Arc<ChunkFingerprints>>,
    /// `PLAN_v2.md` §11 mid-flight probe configuration. Inert when
    /// `fingerprints` is `None`.
    pub probe: ProbeConfig,
    /// Multi-mirror routing (`PLAN_v2.md` §13). When set, workers
    /// pick from this set per dispatch attempt; failures exclude a
    /// mirror for the configured backoff window and other mirrors
    /// pick up the slack. When `None`, the scheduler builds a
    /// one-element [`MirrorSet`] from `info.url` /
    /// `info.fingerprint` so single-mirror runs share the same code
    /// path.
    pub mirrors: Option<Arc<MirrorSet>>,
    /// Aggregate bandwidth cap (`PLAN_v2.md` §14). When `Some`,
    /// every byte read off the wire (parallel-mode worker bodies
    /// and the single-stream fallback) passes through this token
    /// bucket. The limiter is shared across every worker and every
    /// mirror, so the cap is aggregate, not per-mirror. `None`
    /// disables rate limiting (the default).
    pub rate_limiter: Option<Arc<RateLimiter>>,
    /// Cap on bytes downloaded but not yet consumed by the decoder
    /// (the disk-side lookahead buffer). When `Some` and the gap
    /// `bytes_downloaded - bytes_decoded_input` reaches this value,
    /// the dispatch loop stops handing new chunks to workers until
    /// the decoder makes progress. This bounds the on-disk footprint
    /// of un-extracted compressed data so a fast network into a slow
    /// disk doesn't balloon the `.peel.part` file. `None` disables
    /// the throttle. Requires `progress` to be set; without it the
    /// scheduler has no way to read the decoder cursor and the field
    /// is ignored.
    pub max_disk_buffer: Option<u64>,
    /// External abort signal. When the flag flips to `true`, the
    /// dispatch loop stops handing out new tasks and the workers
    /// observe the same flag on their next iteration so they exit as
    /// soon as their current chunk completes. Without this signal
    /// `thread::scope`'s implicit join in
    /// [`crate::coordinator::run`] would block until the entire
    /// download completed naturally — turning any extractor error into
    /// an apparent hang for the user.
    ///
    /// Two callers flip this flag: the coordinator's `CancelOnDrop`
    /// guard (extractor errored on the consumer side) and the run-wide
    /// kill switch wired by `main` (SIGINT / SIGTERM). The coordinator
    /// merges the latter into this same `Arc` so download workers
    /// stop on a kubelet SIGTERM in parallel with the extraction
    /// unwind, rather than waiting for the reader → extractor →
    /// `CancelOnDrop` chain.
    pub abort: Option<Arc<AtomicBool>>,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            workers: DEFAULT_WORKERS,
            retry: RetryConfig::default(),
            progress: None,
            policy: None,
            fingerprints: None,
            probe: ProbeConfig::default(),
            mirrors: None,
            rate_limiter: None,
            max_disk_buffer: None,
            abort: None,
        }
    }
}

/// Knobs for the `PLAN_v2.md` §11 mid-flight verifier.
#[derive(Debug, Clone, Copy)]
pub struct ProbeConfig {
    /// Issue one probe every `interval` successful fetches. `0`
    /// disables probing while leaving fingerprint recording on,
    /// which is useful for the resume-only verification path.
    pub interval: u32,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            interval: DEFAULT_PROBE_INTERVAL,
        }
    }
}

/// Counters returned by [`run`] on success.
#[derive(Debug, Clone, Default)]
pub struct DownloadStats {
    /// Bytes written to the sparse file during this call (excludes
    /// chunks already complete on entry).
    pub bytes_downloaded: u64,
    /// Bytes passed to [`SparseFile::pwrite_at`] during this call,
    /// including probe writes.
    pub pwrite_bytes: u64,
    /// Wall-clock time spent inside [`SparseFile::pwrite_at`] calls.
    pub pwrite_time: Duration,
    /// Total chunks completed by this call.
    pub chunks_completed: u32,
    /// Total chunks already complete on entry (resume case).
    pub chunks_resumed: u32,
    /// Sum of `(attempts - 1)` over completed chunks.
    pub retries: u64,
    /// Wall-clock time spent in [`run`].
    pub elapsed: Duration,
    /// Which transfer mode actually ran.
    pub mode: DownloadMode,
}

/// Which transfer mode [`run`] used.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub enum DownloadMode {
    /// Parallel ranged-GET mode (the fast path).
    Parallel {
        /// Total chunks the file was divided into.
        chunks: u32,
        /// Workers spawned.
        workers: u32,
    },
    /// Single-stream fallback (server lacks `Accept-Ranges: bytes`).
    #[default]
    SingleStream,
}

/// Number of chunks needed to cover `total_size` at `chunk_size`.
///
/// # Errors
///
/// Returns [`SchedulerError::InvalidChunkSize`] for `chunk_size == 0`,
/// or [`SchedulerError::TooManyChunks`] if the count would not fit a
/// `u32`.
pub fn chunk_count(total_size: u64, chunk_size: u64) -> Result<u32, SchedulerError> {
    if chunk_size == 0 {
        return Err(SchedulerError::InvalidChunkSize);
    }
    let n = total_size.div_ceil(chunk_size);
    u32::try_from(n).map_err(|_| SchedulerError::TooManyChunks {
        chunks: n,
        max: u64::from(u32::MAX),
    })
}

/// Issue a `HEAD` and summarize the source.
///
/// When the `HEAD` does not yield a usable `Content-Length` — non-2xx
/// status (e.g. an S3/MinIO presigned URL signed for `GET` only that
/// rejects `HEAD` with `403 SignatureDoesNotMatch`), missing header,
/// or `Content-Length: 0` — a single-byte ranged `GET` is issued as a
/// fallback and the total is read from `Content-Range`. This is the
/// only way to discover size for a number of CDN/object-store hosts
/// that strip `Content-Length` from redirect responses or refuse
/// `HEAD` outright.
///
/// If that ranged probe comes back `200` (the server ignored the
/// `Range` header — i.e. no range support at all), discovery falls
/// back once more to a plain `GET`, reads the size from
/// `Content-Length`, and reports `accept_ranges = false` so the
/// download runs in single-stream mode.
///
/// # Errors
///
/// Returns [`SchedulerError::Head`] if the `HEAD` request fails at the
/// transport layer (the fallback is only attempted when `HEAD`
/// completed but didn't yield a usable answer), or
/// [`SchedulerError::MissingContentLength`] if neither the `HEAD` nor
/// the ranged-`GET` fallback produced a non-zero total.
pub fn discover(client: &Client, url: &Url) -> Result<DownloadInfo, SchedulerError> {
    let head = client.head(url).map_err(|source| SchedulerError::Head {
        url: url.to_string(),
        source,
    })?;
    let head_total = head
        .headers
        .get("content-length")
        .and_then(|v| v.trim().parse::<u64>().ok());
    if head.status.is_success() {
        if let Some(total_size) = head_total {
            if total_size > 0 {
                let accept_ranges = head
                    .headers
                    .get("accept-ranges")
                    .map(|v| v.eq_ignore_ascii_case("bytes"))
                    .unwrap_or(false);
                let fingerprint = SourceFingerprint::from_headers(&head.headers);
                let source = MultiPartSource::from_single(
                    head.final_url.clone(),
                    total_size,
                    fingerprint.clone(),
                    None,
                )
                .map_err(SchedulerError::MultiPart)?;
                return Ok(DownloadInfo {
                    url: head.final_url,
                    total_size,
                    fingerprint,
                    accept_ranges,
                    size_known: true,
                    source,
                });
            }
        }
    }
    discover_via_range_probe(client, url)
}

/// Fallback discovery path used when `HEAD` cannot tell us the total
/// size. Issues a `Range: bytes=0-0` GET, drops the body, and reads
/// the total from the `Content-Range` header. A 206 response
/// inherently confirms range support, so `accept_ranges = true` is
/// assumed.
fn discover_via_range_probe(client: &Client, url: &Url) -> Result<DownloadInfo, SchedulerError> {
    let probe = match ByteRange::from_start_len(ByteOffset::new(0), 1) {
        Some(r) => r,
        // INVARIANT: `ByteRange::from_start_len(0, 1)` only fails if
        // `0 + 1` overflows `u64`, which it cannot.
        None => unreachable!("0..1 is always a valid ByteRange"),
    };
    let resp = match client.get_range(url, probe) {
        Ok(resp) => resp,
        // A `200` to a `Range` request means the server ignored the
        // header — it has no range support. Fall back to a plain
        // streaming `GET`: discover the size from the full response
        // and let `run` single-stream the download.
        Err(ClientError::UnexpectedStatus { status: 200, .. }) => {
            return discover_via_full_get(client, url);
        }
        Err(source) => {
            return Err(SchedulerError::Head {
                url: url.to_string(),
                source,
            });
        }
    };
    let cr_value = resp
        .headers
        .get("content-range")
        .ok_or_else(|| SchedulerError::MissingContentLength {
            url: url.to_string(),
        })?
        .to_string();
    let total_size = parse_content_range(&cr_value)
        .ok()
        .and_then(|cr| cr.total())
        .filter(|t| *t > 0)
        .ok_or_else(|| SchedulerError::MissingContentLength {
            url: url.to_string(),
        })?;
    let fingerprint = SourceFingerprint::from_headers(&resp.headers);
    drop(resp.body);
    let source = MultiPartSource::from_single(url.clone(), total_size, fingerprint.clone(), None)
        .map_err(SchedulerError::MultiPart)?;
    Ok(DownloadInfo {
        url: url.clone(),
        total_size,
        fingerprint,
        accept_ranges: true,
        size_known: true,
        source,
    })
}

/// Last-resort discovery for a server that supports neither a usable
/// `HEAD` nor range requests: the `Range` probe came back `200` (range
/// ignored). Issue a plain `GET` and report `accept_ranges = false` so
/// [`run`] drives the single-stream path. The body is dropped unread —
/// hyper closes the connection rather than streaming the whole file
/// just to size it; `run_single_stream` / `run_single_stream_unknown`
/// re-fetches it.
///
/// When the `GET` carries a usable `Content-Length` the size is known
/// up front (`size_known = true`). When it does not — chunked transfer-
/// encoding, HTTP/2 without a length, or HTTP/1.1 close-delimited — the
/// size is unknown and is learned by streaming the body to EOF
/// (`size_known = false`, issue #8).
///
/// # Errors
///
/// [`SchedulerError::Head`] if the `GET` fails at the transport layer
/// or returns a non-2xx status.
fn discover_via_full_get(client: &Client, url: &Url) -> Result<DownloadInfo, SchedulerError> {
    let resp = client
        .get_full(url)
        .map_err(|source| SchedulerError::Head {
            url: url.to_string(),
            source,
        })?;
    if !resp.status.is_success() {
        return Err(SchedulerError::Head {
            url: url.to_string(),
            source: ClientError::UnexpectedStatus {
                method: crate::http::Method::Get,
                url: url.to_string(),
                status: resp.status.code,
            },
        });
    }
    let total_size = resp
        .headers
        .get("content-length")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|t| *t > 0);
    let fingerprint = SourceFingerprint::from_headers(&resp.headers);
    drop(resp.body);
    match total_size {
        Some(total_size) => {
            let source =
                MultiPartSource::from_single(url.clone(), total_size, fingerprint.clone(), None)
                    .map_err(SchedulerError::MultiPart)?;
            Ok(DownloadInfo {
                url: url.clone(),
                total_size,
                fingerprint,
                accept_ranges: false,
                size_known: true,
                source,
            })
        }
        // No usable Content-Length: stream the body to EOF and learn
        // the size as we go (issue #8).
        None => Ok(DownloadInfo {
            url: url.clone(),
            total_size: 0,
            fingerprint: fingerprint.clone(),
            accept_ranges: false,
            size_known: false,
            source: MultiPartSource::single_unknown(url.clone(), fingerprint),
        }),
    }
}

/// Discover N parts in parallel and bundle them into a multi-part
/// [`DownloadInfo`] (`internal/PLAN_multi_url_source.md` §1 step 3).
///
/// Each part is HEAD'd independently; the returned info's
/// `total_size` is the sum of every part's `Content-Length`,
/// `accept_ranges` is true iff *every* part advertised
/// `Accept-Ranges: bytes`, and the legacy `url` / `fingerprint`
/// fields reflect the first part.
///
/// Cross-part fingerprint agreement is **not** required: parts are
/// distinct objects whose ETags need not match. The agreement
/// machinery in [`discover_with_mirrors`] is for `--mirror`
/// alternates of the *same* file and is unrelated.
///
/// # Errors
///
/// Propagates the first per-part [`SchedulerError`] observed.
/// `parts.is_empty()` returns [`SchedulerError::MultiPart`] wrapping
/// [`MultiPartSourceError::Empty`] without issuing any HEAD requests.
pub fn discover_multi(client: &Client, urls: &[Url]) -> Result<DownloadInfo, SchedulerError> {
    if urls.is_empty() {
        return Err(SchedulerError::MultiPart(MultiPartSourceError::Empty));
    }
    if urls.len() == 1 {
        return discover(client, &urls[0]);
    }

    // Parallel HEADs: each part's discovery is independent of the
    // others, and serializing them would visibly delay startup
    // (especially against high-latency origins). Mirrors the pattern
    // in `discover_with_mirrors`.
    let results: Vec<Result<DownloadInfo, SchedulerError>> = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(urls.len());
        for url in urls {
            let client_ref = client;
            let url_clone = url.clone();
            let h = thread::Builder::new()
                .name("peel-multipart-discover".into())
                .spawn_scoped(scope, move || discover(client_ref, &url_clone))
                .ok();
            handles.push(h);
        }
        handles
            .into_iter()
            .map(|h| match h {
                Some(handle) => handle.join().unwrap_or_else(|_| {
                    Err(SchedulerError::Head {
                        url: "<panicked>".into(),
                        source: ClientError::DnsEmpty {
                            host: String::new(),
                            port: 0,
                        },
                    })
                }),
                None => Err(SchedulerError::Head {
                    url: "<spawn-failed>".into(),
                    source: ClientError::DnsEmpty {
                        host: String::new(),
                        port: 0,
                    },
                }),
            })
            .collect()
    });

    // Surface the first error; otherwise build a multi-part source.
    let mut parts: Vec<super::multi_url::PartDescriptor> = Vec::with_capacity(urls.len());
    let mut all_accept_ranges = true;
    let mut total_size: u64 = 0;
    for r in results {
        let info = r?;
        all_accept_ranges &= info.accept_ranges;
        total_size = total_size
            .checked_add(info.total_size)
            .ok_or(SchedulerError::MultiPart(
                MultiPartSourceError::TotalOverflow { index: parts.len() },
            ))?;
        parts.push(super::multi_url::PartDescriptor {
            url: info.url,
            size: info.total_size,
            fingerprint: info.fingerprint,
            expected_sha256: None,
        });
    }
    let source = MultiPartSource::new(parts).map_err(SchedulerError::MultiPart)?;
    let primary = source
        .parts()
        .first()
        .expect("MultiPartSource::new rejects empty input");
    Ok(DownloadInfo {
        url: primary.url.clone(),
        total_size,
        fingerprint: primary.fingerprint.clone(),
        accept_ranges: all_accept_ranges,
        size_known: true,
        source,
    })
}

/// Discover the primary URL and validate any `--mirror` alternates
/// in parallel (`PLAN_v2.md` §13).
///
/// Returns the primary's [`DownloadInfo`] alongside a [`MirrorSet`]
/// containing the primary plus every mirror that agreed with it on
/// `Content-Length` and (when `expected_sha256.is_none()`)
/// `ETag` / `Last-Modified`. Mirrors that disagree are dropped with
/// a `tracing::warn!`, accumulated into the second return value,
/// and not used for the run.
///
/// # Agreement rule
///
/// - **Always**: `Content-Length` must match the primary. A
///   mismatched-size mirror is unambiguously wrong, regardless of
///   any other check.
/// - **When `expected_sha256` is `None`**: at least one of the
///   primary's `ETag` (strong, per RFC 7232 §2.3) or `Last-Modified`
///   must equal the mirror's. Weak ETags only promise semantic
///   equivalence so a weak mismatch alone is advisory; the
///   `Last-Modified` fallback covers the common CDN case where
///   strong ETags differ but cache-validation timestamps agree.
/// - **When `expected_sha256` is `Some(_)`**: the per-attempt SHA-256
///   check at end-of-run is the byte-level guarantee, so per-mirror
///   `ETag` / `Last-Modified` disagreement is allowed.
///
/// # Errors
///
/// The primary's discovery is fatal: any [`SchedulerError`] from the
/// primary's `HEAD` propagates. Mirror failures are *not* fatal —
/// they are dropped and surfaced via the returned `Vec` of
/// [`MirrorAgreementError`].
pub fn discover_with_mirrors(
    client: &Client,
    primary_url: &Url,
    mirror_urls: &[Url],
    expected_sha256_provided: bool,
) -> Result<(DownloadInfo, MirrorSet, Vec<MirrorAgreementError>), SchedulerError> {
    let primary = discover(client, primary_url)?;
    if mirror_urls.is_empty() {
        let set = MirrorSet::single(primary.url.clone(), primary.fingerprint.clone());
        return Ok((primary, set, Vec::new()));
    }

    // Discover every mirror in parallel: each one's HEAD is independent
    // of the others, and serializing them would visibly delay startup.
    // `thread::scope` keeps the borrows on `client` alive without an
    // Arc clone.
    let results: Vec<Result<DownloadInfo, SchedulerError>> = thread::scope(|scope| {
        let mut handles = Vec::with_capacity(mirror_urls.len());
        for url in mirror_urls {
            let client_ref = client;
            let url_clone = url.clone();
            let h = thread::Builder::new()
                .name("peel-mirror-discover".into())
                .spawn_scoped(scope, move || discover(client_ref, &url_clone))
                .ok();
            handles.push(h);
        }
        handles
            .into_iter()
            .map(|h| match h {
                Some(handle) => handle.join().unwrap_or_else(|_| {
                    Err(SchedulerError::Head {
                        url: "<panicked>".into(),
                        source: ClientError::DnsEmpty {
                            host: String::new(),
                            port: 0,
                        },
                    })
                }),
                None => Err(SchedulerError::Head {
                    url: "<spawn-failed>".into(),
                    source: ClientError::DnsEmpty {
                        host: String::new(),
                        port: 0,
                    },
                }),
            })
            .collect()
    });

    let mut mirrors: Vec<Mirror> = vec![Mirror::new(
        primary.url.clone(),
        primary.fingerprint.clone(),
    )];
    let mut dropped: Vec<MirrorAgreementError> = Vec::new();

    for (mirror_url, result) in mirror_urls.iter().zip(results) {
        match result {
            Ok(info) => {
                if info.total_size != primary.total_size {
                    let err = MirrorAgreementError::SizeMismatch {
                        url: mirror_url.to_string(),
                        actual: info.total_size,
                        expected: primary.total_size,
                    };
                    tracing::warn!("dropping mirror: {}", err);
                    dropped.push(err);
                    continue;
                }
                if !expected_sha256_provided
                    && !fingerprints_agree(&primary.fingerprint, &info.fingerprint)
                {
                    let err = MirrorAgreementError::FingerprintMismatch {
                        url: mirror_url.to_string(),
                        actual_etag: info.fingerprint.etag.clone(),
                        expected_etag: primary.fingerprint.etag.clone(),
                        actual_last_modified: info.fingerprint.last_modified.clone(),
                        expected_last_modified: primary.fingerprint.last_modified.clone(),
                    };
                    tracing::warn!("dropping mirror: {}", err);
                    dropped.push(err);
                    continue;
                }
                mirrors.push(Mirror::new(info.url, info.fingerprint));
            }
            Err(scheduler_err) => {
                let err = MirrorAgreementError::HeadFailed {
                    url: mirror_url.to_string(),
                    reason: scheduler_err.to_string(),
                };
                tracing::warn!("dropping mirror: {}", err);
                dropped.push(err);
            }
        }
    }

    let set = MirrorSet::new(mirrors);
    Ok((primary, set, dropped))
}

/// Two fingerprints agree iff at least one of (strong ETag,
/// Last-Modified) is present on both sides and equal.
///
/// Mirrors that send no source-identity headers at all (no ETag,
/// no Last-Modified) cannot be proven byte-identical to the primary,
/// so they are kept (the primary's lack of headers is symmetric);
/// the §11 CRC-32C probe and `--sha256` (when set) catch any actual
/// drift later. Weak ETags are advisory per RFC 7232 §2.3.
fn fingerprints_agree(primary: &SourceFingerprint, mirror: &SourceFingerprint) -> bool {
    if primary.is_empty() && mirror.is_empty() {
        return true;
    }
    if let (Some(a), Some(b)) = (&primary.etag, &mirror.etag) {
        let weak = super::worker::etag_is_weak(a) || super::worker::etag_is_weak(b);
        if !weak && a == b {
            return true;
        }
    }
    if let (Some(a), Some(b)) = (&primary.last_modified, &mirror.last_modified) {
        if a == b {
            return true;
        }
    }
    // Both sides carry at least one identifier but none of them
    // match — that's a fingerprint mismatch.
    false
}

/// Run the download to completion (or first terminal error).
///
/// Picks parallel or single-stream mode from `info.accept_ranges` and
/// dispatches accordingly. The shared [`ChunkBitmap`] is updated as
/// chunks complete; the `cursor` is read but never written by this
/// function (the decoder, when it exists, will be the writer).
///
/// # Errors
///
/// Any of the [`SchedulerError`] variants. On error, partial progress
/// is preserved in the bitmap and on disk so the caller can retry.
pub fn run(
    client: &Client,
    info: &DownloadInfo,
    sparse: &MultiSparse,
    bitmap: &ChunkBitmap,
    cursor: &AtomicU64,
    config: &SchedulerConfig,
) -> Result<DownloadStats, SchedulerError> {
    if config.chunk_size == 0 {
        return Err(SchedulerError::InvalidChunkSize);
    }
    if config.workers == 0 {
        return Err(SchedulerError::InvalidWorkerCount);
    }

    let started = Instant::now();

    // Unknown source size (range-less server that also omitted
    // `Content-Length`): stream the body to EOF, learning the size as we
    // go (issue #8). This path can't size the chunk bitmap, so it
    // bypasses it entirely; the growable sparse file's live high-water
    // (`MultiSparse::total_size`) is what the reader gates on.
    if !info.size_known {
        if let Some(p) = config.progress.as_ref() {
            p.set_total_workers(1);
            p.set_max_disk_buffer(config.max_disk_buffer.unwrap_or(0));
        }
        let mut stats = run_single_stream_unknown(client, info, sparse, config)?;
        stats.elapsed = started.elapsed();
        return Ok(stats);
    }

    let total_chunks = chunk_count(info.total_size, config.chunk_size)?;
    if bitmap.len() != total_chunks {
        return Err(SchedulerError::BitmapLengthMismatch {
            actual: bitmap.len(),
            expected: total_chunks,
        });
    }

    if let Some(p) = config.progress.as_ref() {
        if info.accept_ranges {
            p.set_total_workers(u64::from(config.workers));
        } else {
            p.set_total_workers(1);
        }
        // Publish the configured disk-buffer cap so the renderer can
        // surface it. `0` is the "disabled" sentinel inside
        // `ProgressState`, which already maps to `None` on the
        // snapshot side.
        p.set_max_disk_buffer(config.max_disk_buffer.unwrap_or(0));
    }
    if info.accept_ranges {
        let mut stats = run_parallel(client, info, sparse, bitmap, cursor, config, total_chunks)?;
        stats.elapsed = started.elapsed();
        Ok(stats)
    } else {
        let mut stats = run_single_stream(client, info, sparse, bitmap, config, total_chunks)?;
        stats.elapsed = started.elapsed();
        Ok(stats)
    }
}

fn run_parallel(
    client: &Client,
    info: &DownloadInfo,
    sparse: &MultiSparse,
    bitmap: &ChunkBitmap,
    cursor: &AtomicU64,
    config: &SchedulerConfig,
    total_chunks: u32,
) -> Result<DownloadStats, SchedulerError> {
    let chunks_resumed = u32::try_from(bitmap.count_complete()).unwrap_or(u32::MAX);
    let stats = DownloadStats {
        chunks_resumed,
        mode: DownloadMode::Parallel {
            chunks: total_chunks,
            workers: config.workers,
        },
        ..DownloadStats::default()
    };

    if chunks_resumed == total_chunks {
        return Ok(stats);
    }

    // The scheduler-side bookkeeping bitmap. A bit set in `dispatched`
    // means "the scheduler has either handed this chunk off to a worker
    // OR it was already complete on entry." `mut` because the worker
    // respawn path rebuilds it from the completion `bitmap` when every
    // worker dies mid-flight: chunks claimed by workers that never
    // reported back must be re-issued.
    let mut dispatched = ChunkBitmap::new(total_chunks);
    for i in 0..total_chunks {
        let idx = ChunkIndex::new(i);
        if bitmap.is_complete(idx) {
            dispatched.mark_complete(idx);
        }
    }

    let workers = config.workers;
    let pool_capacity = usize::try_from(workers).unwrap_or(usize::MAX);
    let (task_tx, task_rx) = mpsc::sync_channel::<Dispatch>(pool_capacity);
    let (done_tx, done_rx) = mpsc::channel::<Completion>();
    let task_rx = Mutex::new(task_rx);
    let cancel = AtomicBool::new(false);

    // Build (or borrow) the mirror set the workers pick from.
    // Single-URL runs (no `--mirror` flag) collapse to a one-element
    // set so the worker code path stays uniform.
    let local_set: Arc<MirrorSet>;
    let mirrors: &MirrorSet = match config.mirrors.as_ref() {
        Some(set) => set.as_ref(),
        None => {
            local_set = Arc::new(MirrorSet::single(
                info.url.clone(),
                info.fingerprint.clone(),
            ));
            local_set.as_ref()
        }
    };

    // Tracks how many worker threads are currently inside their
    // run-loop. Pre-incremented by the scheduler before `spawn_scoped`
    // so the count is accurate the moment the spawn returns; the
    // worker decrements via a RAII guard at any exit point (clean
    // return, mutex poisoning, or caught panic). The scheduler watches
    // this on every dispatch tick and respawns workers when it dips
    // below `workers`.
    let alive_workers = AtomicU32::new(0);
    // Multi-URL routing (`internal/PLAN_multi_url_source.md` §1 step 4):
    // when the discovered source has more than one part, the worker
    // ignores the mirror set and fetches each chunk from the part
    // containing its global offset. The single-URL case (`len() == 1`)
    // keeps the mirror set as the source of truth so existing
    // `--mirror` runs are unchanged. `--mirror` plus multi-URL is
    // rejected by the CLI (§3 step 3) so neither field needs to handle
    // the combined case.
    let multi_part_source: Option<&MultiPartSource> = if info.source.len() > 1 {
        Some(&info.source)
    } else {
        None
    };

    let scheduler_outcome: Result<DownloadStats, SchedulerError> = thread::scope(|scope| {
        let ctx = ChunkContext {
            client,
            mirrors,
            source: multi_part_source,
            chunk_size: config.chunk_size,
            sparse,
            progress: config.progress.as_deref(),
            rate_limiter: config.rate_limiter.as_ref(),
        };

        // Spawn one worker. Pre-increments `alive_workers` before
        // the OS thread is created so a same-tick `load()` from the
        // scheduler always sees the new worker. If the spawn itself
        // fails (rare — typically OS thread limit), the increment is
        // undone before returning. Worker panics are absorbed via
        // `catch_unwind` so a single bad chunk doesn't unwind the
        // whole `thread::scope`; the scheduler re-detects the loss
        // through the alive-counter and respawns.
        let spawn_one = |w_id: u32| {
            let task_rx_ref: &Mutex<mpsc::Receiver<Dispatch>> = &task_rx;
            let cancel_ref: &AtomicBool = &cancel;
            let alive_ref: &AtomicU32 = &alive_workers;
            let done_tx_clone = done_tx.clone();
            let retry = config.retry.clone();
            alive_ref.fetch_add(1, Ordering::AcqRel);
            let result = thread::Builder::new()
                .name(format!("peel-download-worker-{w_id}"))
                .spawn_scoped(scope, move || {
                    struct AliveGuard<'a>(&'a AtomicU32);
                    impl Drop for AliveGuard<'_> {
                        fn drop(&mut self) {
                            self.0.fetch_sub(1, Ordering::AcqRel);
                        }
                    }
                    let _alive = AliveGuard(alive_ref);
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        worker_loop(&ctx, &retry, task_rx_ref, done_tx_clone, cancel_ref);
                    }));
                });
            if result.is_err() {
                alive_ref.fetch_sub(1, Ordering::AcqRel);
            }
        };

        // Spawn the initial worker pool. `next_worker_id` keeps
        // thread names distinct across the lifetime of the run so a
        // respawned worker doesn't collide with the dead one in
        // `tracing` output.
        let mut next_worker_id: u32 = 0;
        for _ in 0..workers {
            spawn_one(next_worker_id);
            next_worker_id = next_worker_id.wrapping_add(1);
        }

        // NOTE: unlike the pre-respawn version, we keep the
        // scheduler's `done_tx` clone alive for the entire dispatch
        // loop. A respawn can't clone from a worker that doesn't
        // exist yet, so the scheduler must own a clone we can fan
        // out from. The trade-off: `done_rx.recv_timeout` will never
        // see `Disconnected` while the loop is running, so loop
        // termination is gated solely on the explicit
        // `completed >= total_chunks && in_flight == 0` check below.

        // Dispatch + drain loop.
        let mut completed = chunks_resumed;
        let mut in_flight: u32 = 0;
        let mut stats_local = stats.clone();
        let mut shutdown_reason: Option<SchedulerError> = None;
        // Total respawn attempts across this run, capped by
        // `MAX_WORKER_RESPAWNS` so a worker that panics on every
        // chunk doesn't loop forever.
        let mut total_respawns: u32 = 0;
        // §11 mid-flight verifier state: counts successful Fetch
        // completions and queues a Probe every `probe.interval`
        // completions (when fingerprints are configured).
        let mut completions_since_probe: u32 = 0;
        // Lightweight LCG to randomise which already-complete chunk
        // we probe. Seeded from total_chunks so the choice differs
        // per run but stays deterministic given the same source.
        let mut probe_rng: u64 = (u64::from(total_chunks) << 32) ^ 0x9E37_79B9_7F4A_7C15;

        'outer: loop {
            // External abort signal (extractor errored on the
            // coordinator side, or the run-wide kill switch tripped —
            // the coordinator merges both into the same `Arc`).
            // Mirror it into the local `cancel` so workers exit as
            // soon as their current chunk completes, and stop
            // dispatching new ones. We do not produce a
            // `shutdown_reason` here because the failure already
            // surfaced via the extraction path (or as
            // `CoordinatorError::Aborted` for the kill-switch case);
            // a synthetic error would just race with it.
            if let Some(flag) = config.abort.as_ref() {
                if flag.load(Ordering::Acquire) {
                    cancel.store(true, Ordering::Relaxed);
                    break 'outer;
                }
            }

            // Worker-liveness check. If any workers have died (panic,
            // mutex poisoning, etc.) and there is still work to do,
            // respawn enough threads to refill the pool. When *every*
            // worker has died with chunks still in flight, those
            // chunks were claimed by dead workers and will never
            // complete: drain queued-but-unclaimed dispatches and
            // rebuild `dispatched` from the completion `bitmap` so
            // the lost chunks get re-issued by the next pass.
            let alive = alive_workers.load(Ordering::Acquire);
            if alive < workers && completed < total_chunks {
                let dead = workers - alive;
                if alive == 0 {
                    tracing::warn!(
                        target: "peel::download",
                        in_flight,
                        dead,
                        total_respawns,
                        "all download workers died; resetting dispatch state and respawning",
                    );
                    // Drain the task channel of dispatches the dead
                    // workers never picked up. We are the sole sender,
                    // and with `alive == 0` no peer holds the lock,
                    // so a poisoned mutex is recovered via `into_inner`.
                    let drain = |rx: &mpsc::Receiver<Dispatch>| while rx.try_recv().is_ok() {};
                    match task_rx.lock() {
                        Ok(rx) => drain(&rx),
                        Err(poisoned) => drain(&poisoned.into_inner()),
                    }
                    // Rebuild `dispatched`: any chunk not already
                    // marked complete in `bitmap` is fair game for
                    // the next dispatch pass.
                    dispatched = ChunkBitmap::new(total_chunks);
                    for i in 0..total_chunks {
                        let idx = ChunkIndex::new(i);
                        if bitmap.is_complete(idx) {
                            dispatched.mark_complete(idx);
                        }
                    }
                    in_flight = 0;
                } else {
                    tracing::warn!(
                        target: "peel::download",
                        dead,
                        total_respawns,
                        "{dead} download worker(s) died; respawning",
                    );
                }
                if total_respawns.saturating_add(dead) > MAX_WORKER_RESPAWNS {
                    shutdown_reason.get_or_insert(SchedulerError::WorkersExhausted {
                        respawns: total_respawns,
                    });
                    cancel.store(true, Ordering::Relaxed);
                    break 'outer;
                }
                total_respawns = total_respawns.saturating_add(dead);
                for _ in 0..dead {
                    spawn_one(next_worker_id);
                    next_worker_id = next_worker_id.wrapping_add(1);
                }
            }

            // Disk-buffer backpressure: if the decoder is far enough
            // behind the downloader that the on-disk lookahead has
            // hit the configured cap, hold off on dispatching new
            // chunks until the gap closes. The 50 ms timeout on
            // `done_rx.recv_timeout` below provides natural cadence;
            // we just skip the inner dispatch while-loop here. The
            // `disk_bound` flag tells the renderer the throttle is
            // active; it's cleared on the next un-throttled tick.
            let throttled = is_disk_buffer_full(config);
            if let Some(p) = config.progress.as_ref() {
                p.set_disk_bound(throttled);
            }

            // Dispatch as many as the channel will accept without
            // blocking — unless the disk-buffer throttle is engaged.
            while !throttled && in_flight < workers && completed + in_flight < total_chunks {
                let cursor_chunk =
                    cursor_to_chunk(cursor.load(Ordering::Relaxed), config.chunk_size);
                let target_chunks = target_chunk_count(config.policy.as_deref(), config.chunk_size);
                let Some(task) = pick_next_dispatch(
                    &dispatched,
                    cursor_chunk,
                    total_chunks,
                    target_chunks,
                    config.chunk_size,
                    info.total_size,
                    multi_part_source,
                ) else {
                    break;
                };
                match task_tx.try_send(task) {
                    Ok(()) => {
                        let end = task.first.get().saturating_add(task.count);
                        dispatched.complete_range(task.first, ChunkIndex::new(end));
                        in_flight += 1;
                    }
                    Err(mpsc::TrySendError::Full(_)) => break,
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        cancel.store(true, Ordering::Relaxed);
                        shutdown_reason.get_or_insert(SchedulerError::ChunkFailed {
                            chunk: task.first,
                            attempts: 0,
                            source: WorkerError::Cancelled { chunk: task.first },
                        });
                        break 'outer;
                    }
                }
            }

            // Exit only when the bitmap is full *and* no probes
            // are still mid-flight. A probe waiting to complete
            // could still discover drift; bailing on it would lose
            // the §11 signal.
            if completed >= total_chunks && in_flight == 0 {
                break;
            }

            // Wait on a completion. Use a short timeout so we re-check
            // the cursor periodically and pick up newly-prioritised
            // work while workers are mid-chunk.
            let msg = match done_rx.recv_timeout(Duration::from_millis(50)) {
                Ok(m) => m,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Some(policy) = config.policy.as_deref() {
                        let remaining = u64::from(total_chunks.saturating_sub(completed));
                        let _ = policy.evaluate(Instant::now(), remaining, workers);
                    }
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            };

            in_flight = in_flight.saturating_sub(1);
            stats_local.retries = stats_local
                .retries
                .saturating_add(u64::from(msg.attempts.saturating_sub(1)));
            match msg.result {
                Ok(()) => {
                    stats_local.pwrite_bytes = stats_local.pwrite_bytes.saturating_add(msg.bytes);
                    stats_local.pwrite_time =
                        stats_local.pwrite_time.saturating_add(msg.pwrite_time);
                    match msg.kind {
                        DispatchKind::Fetch => {
                            let end = msg.first.get().saturating_add(msg.count);
                            // §3.3 (PLAN_responsiveness.md): record the
                            // per-chunk CRC-32C fingerprints **before**
                            // marking the bitmap. The
                            // [`ChunkFingerprints`] module documents
                            // exactly this ordering ("a worker records
                            // the CRC-32C with `Ordering::Release`
                            // before its `ChunkBitmap` mark"); the prior
                            // arrangement (bitmap-first) opened a window
                            // where a reader could observe a chunk
                            // marked complete but with `fingerprints.get
                            // == 0`, which the §3.1 cursor audit would
                            // misinterpret as "no fingerprint to compare
                            // against" and silently skip. Recording
                            // first preserves the documented happens-
                            // before edge.
                            if let Some(fps) = config.fingerprints.as_deref() {
                                for (i, crc) in msg.crcs.iter().enumerate().take(msg.count as usize)
                                {
                                    let idx = msg.first.get().saturating_add(i as u32);
                                    if idx < total_chunks {
                                        fps.record(ChunkIndex::new(idx), *crc);
                                    }
                                }
                            }
                            bitmap.complete_range(msg.first, ChunkIndex::new(end));
                            stats_local.bytes_downloaded =
                                stats_local.bytes_downloaded.saturating_add(msg.bytes);
                            stats_local.chunks_completed =
                                stats_local.chunks_completed.saturating_add(msg.count);
                            completed = completed.saturating_add(msg.count);
                            if let Some(policy) = config.policy.as_deref() {
                                policy.record(Sample {
                                    at: Instant::now(),
                                    elapsed: msg.elapsed,
                                    retried: msg.attempts > 1,
                                });
                                let remaining = u64::from(total_chunks.saturating_sub(completed));
                                let _ = policy.evaluate(Instant::now(), remaining, workers);
                            }

                            // §11 probe scheduler: every Nth Fetch
                            // completion, pick a random already-complete
                            // chunk and queue a Probe re-fetch. Skip when
                            // fingerprints are off, when interval is 0,
                            // or when there is no chunk to probe yet.
                            completions_since_probe = completions_since_probe.saturating_add(1);
                            if let (Some(fps), Some(probe)) =
                                (config.fingerprints.as_deref(), Some(&config.probe))
                            {
                                if probe.interval > 0
                                    && completions_since_probe >= probe.interval
                                    && completed > 0
                                {
                                    completions_since_probe = 0;
                                    if let Some(probe_dispatch) = pick_probe_dispatch(
                                        bitmap,
                                        fps,
                                        total_chunks,
                                        config.chunk_size,
                                        info.total_size,
                                        &mut probe_rng,
                                    ) {
                                        // Best-effort enqueue: a full
                                        // channel just defers the probe
                                        // to the next cadence tick.
                                        if task_tx.try_send(probe_dispatch).is_ok() {
                                            in_flight += 1;
                                        }
                                    }
                                }
                            }
                        }
                        DispatchKind::Probe { expected: _ } => {
                            // Probe success: the worker already verified
                            // CRC-32C in-line. No bitmap update — the chunk
                            // was already complete before the probe.
                            //
                            // PLAN_decoder_freeze.md: the worker's
                            // [`read_with_progress`] credits `add_downloaded`
                            // on every socket read regardless of dispatch
                            // kind, which means a probe's bytes ARE counted
                            // again in `bytes_downloaded` — even though the
                            // chunk's bytes were already counted by the
                            // original Fetch. Without a refund here the
                            // counter inflates by one chunk per probe, so
                            // after enough probes the throttle equation
                            // `downloaded - decoded ≥ max_disk_buffer`
                            // engages on phantom bytes. Workers stop
                            // dispatching, the decoder reaches an
                            // undispatched chunk, and the run wedges with
                            // every counter flat at the cap — the
                            // production freeze documented in §2.5.
                            //
                            // Refund the probe's bytes here so the gross
                            // counter tracks real on-disk lookahead.
                            if let Some(p) = config.progress.as_ref() {
                                p.sub_downloaded(msg.bytes);
                            }
                        }
                    }
                }
                Err(err) => {
                    cancel.store(true, Ordering::Relaxed);
                    let mapped = match err {
                        WorkerError::SourceDriftDetected {
                            chunk,
                            expected,
                            actual,
                        } => SchedulerError::SourceChangedDuringDownload {
                            chunk,
                            expected,
                            actual,
                        },
                        other => SchedulerError::ChunkFailed {
                            chunk: msg.first,
                            attempts: msg.attempts,
                            source: other,
                        },
                    };
                    shutdown_reason.get_or_insert(mapped);
                    break;
                }
            }
        }

        // Closing the task channel signals workers to exit; the scope
        // join then waits for them.
        drop(task_tx);

        // §14: a worker stalled inside the rate limiter must observe
        // the cancel flag promptly. Wake every blocked waiter so they
        // re-check `cancel` and unwind without paying out the
        // remaining sleep cadence.
        if let Some(limiter) = config.rate_limiter.as_ref() {
            limiter.shutdown();
        }

        // Clear the disk-bound flag on shutdown so a stale "DISK"
        // badge doesn't survive past the run.
        if let Some(p) = config.progress.as_ref() {
            p.set_disk_bound(false);
        }

        match shutdown_reason {
            Some(e) => Err(e),
            None => Ok(stats_local),
        }
    });

    scheduler_outcome
}

/// Read the current disk-side lookahead (`bytes_downloaded -
/// bytes_decoded_input`) from the shared progress state and compare
/// it to the live cap. The cap comes from the snapshot rather than
/// the static config so the coordinator can disable the throttle
/// per-flow at runtime (notably, the ZIP pipeline calls
/// [`crate::progress::ProgressState::set_max_disk_buffer`] with `0`
/// because random-access ZIP downloads don't fit the streaming
/// "lookahead" model).
fn is_disk_buffer_full(config: &SchedulerConfig) -> bool {
    let Some(progress) = config.progress.as_ref() else {
        return false;
    };
    let snap = progress.snapshot();
    let Some(max) = snap.max_disk_buffer else {
        return false;
    };
    snap.bytes_downloaded
        .saturating_sub(snap.bytes_decoded_input)
        >= max
}

/// Map the policy's current target byte size to a chunk count
/// (rounded down). Returns `1` when the policy is absent — the
/// pre-§8 behaviour.
fn target_chunk_count(policy: Option<&ChunkSizePolicy>, chunk_size: u64) -> u32 {
    let Some(policy) = policy else {
        return 1;
    };
    if chunk_size == 0 {
        return 1;
    }
    let bytes = policy.current();
    let chunks = bytes / chunk_size;
    u32::try_from(chunks.max(1)).unwrap_or(u32::MAX)
}

/// One worker thread's lifetime: pull dispatches off the shared
/// receiver, execute, report the result, repeat. Exits cleanly when
/// the task channel closes or `cancel` becomes true.
fn worker_loop(
    ctx: &ChunkContext<'_>,
    retry: &RetryConfig,
    task_rx: &Mutex<mpsc::Receiver<Dispatch>>,
    done_tx: mpsc::Sender<Completion>,
    cancel: &AtomicBool,
) {
    loop {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        let dispatch = {
            // A panicking peer worker poisons this mutex via the
            // MutexGuard drop. The protected `mpsc::Receiver` has no
            // invariants that a panic could break, so we recover the
            // inner value and keep going — the scheduler relies on
            // this so its respawned workers can pick up where the
            // dead ones left off.
            let rx = match task_rx.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            match rx.recv() {
                Ok(d) => d,
                Err(_) => return,
            }
        };

        if let Some(p) = ctx.progress {
            p.worker_started();
        }
        let started = Instant::now();
        let outcome = download_dispatch(ctx, dispatch, retry, cancel);
        let elapsed = started.elapsed();
        if let Some(p) = ctx.progress {
            p.worker_finished();
        }

        let msg = match outcome {
            Ok(ChunkOutcome {
                bytes,
                pwrite_time,
                attempts,
                crcs,
            }) => Completion {
                first: dispatch.first,
                count: dispatch.count,
                bytes,
                pwrite_time,
                attempts,
                elapsed,
                kind: dispatch.kind,
                crcs,
                result: Ok(()),
            },
            Err(crate::download::worker::ChunkFailure { error, attempts }) => Completion {
                first: dispatch.first,
                count: dispatch.count,
                bytes: 0,
                pwrite_time: Duration::ZERO,
                attempts,
                elapsed,
                kind: dispatch.kind,
                crcs: Vec::new(),
                result: Err(error),
            },
        };
        if done_tx.send(msg).is_err() {
            return;
        }
    }
}

fn run_single_stream(
    client: &Client,
    info: &DownloadInfo,
    sparse: &MultiSparse,
    bitmap: &ChunkBitmap,
    config: &SchedulerConfig,
    total_chunks: u32,
) -> Result<DownloadStats, SchedulerError> {
    let chunks_resumed = u32::try_from(bitmap.count_complete()).unwrap_or(u32::MAX);
    let mut stats = DownloadStats {
        chunks_resumed,
        mode: DownloadMode::SingleStream,
        ..DownloadStats::default()
    };

    if chunks_resumed == total_chunks {
        return Ok(stats);
    }
    if chunks_resumed != 0 {
        // Single-stream mode cannot resume mid-file: the server has no
        // ranged-read capability. Discard prior progress by re-fetching
        // from byte 0.
        // Note: we don't clear the bitmap here; we simply overwrite the
        // file contents and re-mark chunks as we cross them.
    }

    let mut resp = client
        .get_full(&info.url)
        .map_err(|source| SchedulerError::SingleStream {
            url: info.url.to_string(),
            source,
        })?;

    if resp.status.code != 200 {
        return Err(SchedulerError::SingleStream {
            url: info.url.to_string(),
            source: ClientError::UnexpectedStatus {
                method: crate::http::Method::Get,
                url: info.url.to_string(),
                status: resp.status.code,
            },
        });
    }

    if !info.fingerprint.is_empty() {
        let actual = SourceFingerprint::from_headers(&resp.headers);
        if let Some(expected_etag) = &info.fingerprint.etag {
            if actual.etag.as_deref() != Some(expected_etag.as_str()) {
                return Err(SchedulerError::ChunkFailed {
                    chunk: ChunkIndex::ZERO,
                    attempts: 1,
                    source: WorkerError::SourceChanged {
                        chunk: ChunkIndex::ZERO,
                        expected_etag: Some(expected_etag.clone()),
                        actual_etag: actual.etag.clone(),
                        expected_last_modified: info.fingerprint.last_modified.clone(),
                        actual_last_modified: actual.last_modified.clone(),
                    },
                });
            }
        }
    }

    let chunk_size = config.chunk_size;
    let total_size = info.total_size;
    let mut written: u64 = 0;
    let mut buf = vec![
        0u8;
        usize::try_from(chunk_size)
            .unwrap_or(usize::MAX)
            .min(64 * 1024)
    ];

    if let Some(p) = config.progress.as_ref() {
        // Single-stream mode is one logical worker reading the body
        // sequentially; mark it active for the duration.
        p.worker_started();
    }
    let single_stream_progress = config.progress.clone();
    let _ss_guard = SingleStreamGuard {
        progress: single_stream_progress.as_deref(),
    };
    // The rate-limited reader needs a cancel flag to poll; mirror
    // the external abort into it so a `RateLimitedReader::read`
    // stalled inside the limiter unwinds promptly when the extractor
    // errors out. When no external signal is configured, the flag is
    // a never-flipped local — the limiter falls through to its normal
    // blocking behaviour.
    let ss_cancel = AtomicBool::new(false);
    while written < total_size {
        if let Some(flag) = config.abort.as_ref() {
            if flag.load(Ordering::Acquire) {
                // Wake the limiter (if any) so the next `read` call's
                // sleep doesn't pay the full quantum, then surface the
                // cancel so the coordinator's scope join unblocks. The
                // returned error is shadowed by whatever the extractor
                // already reported; we just need *some* terminal
                // result so the download thread exits.
                ss_cancel.store(true, Ordering::Release);
                return Err(SchedulerError::ChunkFailed {
                    chunk: ChunkIndex::ZERO,
                    attempts: 1,
                    source: WorkerError::Cancelled {
                        chunk: ChunkIndex::ZERO,
                    },
                });
            }
        }
        let remaining = total_size - written;
        let want = u64::try_from(buf.len()).unwrap_or(u64::MAX).min(remaining);
        let want_usize =
            usize::try_from(want).map_err(|_| SchedulerError::SingleStreamBodyLength {
                expected: total_size,
                actual: written,
            })?;
        let slice = &mut buf[..want_usize];
        let n = match config.rate_limiter.as_ref() {
            Some(limiter) => {
                let mut limited =
                    RateLimitedReader::new(&mut resp.body, Arc::clone(limiter), &ss_cancel);
                limited.read(slice).map_err(SchedulerError::BodyIo)?
            }
            None => resp.body.read(slice).map_err(SchedulerError::BodyIo)?,
        };
        if n == 0 {
            return Err(SchedulerError::SingleStreamBodyLength {
                expected: total_size,
                actual: written,
            });
        }
        let pwrite_started = Instant::now();
        sparse
            .pwrite_at(ByteOffset::new(written), &slice[..n])
            .map_err(SchedulerError::SparseFile)?;
        let pwrite_time = pwrite_started.elapsed();
        stats.pwrite_bytes = stats.pwrite_bytes.saturating_add(n as u64);
        stats.pwrite_time = stats.pwrite_time.saturating_add(pwrite_time);
        if let Some(p) = config.progress.as_ref() {
            p.add_downloaded(n as u64);
        }

        // Mark every chunk that's now fully covered by `written + n`.
        let prev_complete_end = written / chunk_size;
        let new_end = written + n as u64;
        let new_complete_end = new_end / chunk_size;
        if new_complete_end > prev_complete_end {
            let lo = u32::try_from(prev_complete_end).unwrap_or(u32::MAX);
            let hi = u32::try_from(new_complete_end).unwrap_or(u32::MAX);
            bitmap.complete_range(ChunkIndex::new(lo), ChunkIndex::new(hi));
            stats.chunks_completed = stats.chunks_completed.saturating_add(hi.saturating_sub(lo));
        }
        written = new_end;
    }

    // Final (possibly partial) chunk if total_size isn't a multiple of
    // chunk_size.
    if total_size % chunk_size != 0 {
        let last = u32::try_from(total_size / chunk_size).unwrap_or(u32::MAX);
        if last < total_chunks && !bitmap.is_complete(ChunkIndex::new(last)) {
            bitmap.mark_complete(ChunkIndex::new(last));
            stats.chunks_completed = stats.chunks_completed.saturating_add(1);
        }
    }

    stats.bytes_downloaded = written;
    Ok(stats)
}

/// Single-stream download of a source whose size is **not known** up
/// front — a range-less server that also omitted `Content-Length`
/// (issue #8). Streams the body sequentially into the growable sparse
/// file until EOF, learning the size as it goes.
///
/// Unlike [`run_single_stream`] there is no `total_size` stop condition
/// and no length-mismatch check: a clean EOF (`read` returns `0`) is the
/// terminator. Truncation safety rests on the body layer — a truncated
/// chunked / `Content-Length` / HTTP-2 body surfaces as an `io::Error`
/// from [`crate::http::BodyReader`] and propagates here; an HTTP/1.1
/// close-delimited body is indistinguishable from a complete one and is
/// caught downstream by decode failure / `--sha256` instead.
///
/// No chunk bitmap is touched: the bitmap can't be sized without the
/// total. The reader gates on the growable file's live high-water
/// (`MultiSparse::total_size`) instead, which each `pwrite_at` advances.
fn run_single_stream_unknown(
    client: &Client,
    info: &DownloadInfo,
    sparse: &MultiSparse,
    config: &SchedulerConfig,
) -> Result<DownloadStats, SchedulerError> {
    let mut stats = DownloadStats {
        mode: DownloadMode::SingleStream,
        ..DownloadStats::default()
    };

    let mut resp = client
        .get_full(&info.url)
        .map_err(|source| SchedulerError::SingleStream {
            url: info.url.to_string(),
            source,
        })?;

    if resp.status.code != 200 {
        return Err(SchedulerError::SingleStream {
            url: info.url.to_string(),
            source: ClientError::UnexpectedStatus {
                method: crate::http::Method::Get,
                url: info.url.to_string(),
                status: resp.status.code,
            },
        });
    }

    if !info.fingerprint.is_empty() {
        let actual = SourceFingerprint::from_headers(&resp.headers);
        if let Some(expected_etag) = &info.fingerprint.etag {
            if actual.etag.as_deref() != Some(expected_etag.as_str()) {
                return Err(SchedulerError::ChunkFailed {
                    chunk: ChunkIndex::ZERO,
                    attempts: 1,
                    source: WorkerError::SourceChanged {
                        chunk: ChunkIndex::ZERO,
                        expected_etag: Some(expected_etag.clone()),
                        actual_etag: actual.etag.clone(),
                        expected_last_modified: info.fingerprint.last_modified.clone(),
                        actual_last_modified: actual.last_modified.clone(),
                    },
                });
            }
        }
    }

    let mut written: u64 = 0;
    let mut buf = vec![0u8; 64 * 1024];

    if let Some(p) = config.progress.as_ref() {
        p.worker_started();
    }
    let single_stream_progress = config.progress.clone();
    let _ss_guard = SingleStreamGuard {
        progress: single_stream_progress.as_deref(),
    };
    let ss_cancel = AtomicBool::new(false);
    loop {
        if let Some(flag) = config.abort.as_ref() {
            if flag.load(Ordering::Acquire) {
                ss_cancel.store(true, Ordering::Release);
                return Err(SchedulerError::ChunkFailed {
                    chunk: ChunkIndex::ZERO,
                    attempts: 1,
                    source: WorkerError::Cancelled {
                        chunk: ChunkIndex::ZERO,
                    },
                });
            }
        }
        let n = match config.rate_limiter.as_ref() {
            Some(limiter) => {
                let mut limited =
                    RateLimitedReader::new(&mut resp.body, Arc::clone(limiter), &ss_cancel);
                limited.read(&mut buf).map_err(SchedulerError::BodyIo)?
            }
            None => resp.body.read(&mut buf).map_err(SchedulerError::BodyIo)?,
        };
        if n == 0 {
            // Clean EOF — the whole body has been streamed.
            break;
        }
        let pwrite_started = Instant::now();
        // `pwrite_at` on the growable file extends it and advances the
        // live high-water (Release), so the reader sees these bytes once
        // it observes the new `total_size`.
        sparse
            .pwrite_at(ByteOffset::new(written), &buf[..n])
            .map_err(SchedulerError::SparseFile)?;
        stats.pwrite_time = stats.pwrite_time.saturating_add(pwrite_started.elapsed());
        stats.pwrite_bytes = stats.pwrite_bytes.saturating_add(n as u64);
        written += n as u64;
        if let Some(p) = config.progress.as_ref() {
            p.add_downloaded(n as u64);
        }
    }

    stats.bytes_downloaded = written;
    Ok(stats)
}

/// Map a byte cursor to the chunk index it lies in, clamped to
/// `total_chunks`. Used to bias dispatch toward the decoder's read
/// position.
fn cursor_to_chunk(cursor: u64, chunk_size: u64) -> u32 {
    if chunk_size == 0 {
        return 0;
    }
    u32::try_from(cursor / chunk_size).unwrap_or(u32::MAX)
}

/// Pick the next chunk to dispatch: prefer chunks at or past
/// `cursor_chunk`, then wrap to 0 if every later chunk is already
/// dispatched.
fn pick_next_chunk(
    dispatched: &ChunkBitmap,
    cursor_chunk: u32,
    total_chunks: u32,
) -> Option<ChunkIndex> {
    let start = cursor_chunk.min(total_chunks);
    if let Some(idx) = dispatched.next_incomplete_after(ChunkIndex::new(start)) {
        return Some(idx);
    }
    if start == 0 {
        return None;
    }
    dispatched.next_incomplete_after(ChunkIndex::ZERO)
}

/// Pick the next [`Dispatch`] to assign to a worker.
///
/// Picks the same starting chunk as [`pick_next_chunk`], then walks
/// forward greedily as long as the next chunk is also incomplete and
/// the running count stays under `target_chunks`. Returns `None` when
/// every chunk is already dispatched.
///
/// `target_chunks` is the policy's current target in bitmap-chunk
/// units (always `>= 1`). The bound is a *cap*, not a target — a
/// run of fewer contiguous incomplete chunks is dispatched as-is so
/// the next run starts on the first new gap, not on a chunk we just
/// skipped because of the cap.
fn pick_next_dispatch(
    dispatched: &ChunkBitmap,
    cursor_chunk: u32,
    total_chunks: u32,
    target_chunks: u32,
    chunk_size: u64,
    total_size: u64,
    multi_part: Option<&MultiPartSource>,
) -> Option<Dispatch> {
    let first = pick_next_chunk(dispatched, cursor_chunk, total_chunks)?;
    let target = target_chunks.max(1);
    // Walk forward to see how many consecutive chunks we can
    // coalesce. Cap at `target_chunks`, `total_chunks`, and — for
    // multi-URL runs (`internal/PLAN_multi_url_source.md`) — keep the
    // dispatch within one part *for adaptive coalescing*. The first
    // chunk is always included even when its nominal range straddles
    // a part boundary; the worker iterates
    // [`MultiPartSource::dispatch_range`] and issues one ranged GET
    // per part-segment. The clamp here only prevents *additional*
    // chunks from extending into a second part, so the dispatch
    // crosses at most one boundary.
    let first_start = u64::from(first.get()).checked_mul(chunk_size)?;
    let first_chunk_end = first_start.checked_add(chunk_size)?.min(total_size);
    let coalesce_cap = match multi_part {
        Some(s) => {
            // After a chunk that straddles a boundary, further
            // coalescing must stay within the part the chunk's
            // *end* lives in, so the boundary the first chunk
            // crossed is the only one this dispatch hits.
            s.next_part_boundary_at_or_after(first_chunk_end.saturating_sub(1))
        }
        None => total_size,
    };
    let mut count: u32 = 1;
    while count < target {
        let next = first.get().checked_add(count)?;
        if next >= total_chunks {
            break;
        }
        // Add the next chunk only if its START is inside
        // `coalesce_cap`. Single-URL: cap is total_size, so the
        // legitimate truncated-last-chunk-of-source case still
        // gets included. Multi-URL: cap is the post-first-cross
        // boundary, so subsequent chunks must stay in one part.
        // The chunk's nominal range may extend past its part's
        // boundary; the worker iterates `dispatch_range` and
        // routes per-segment.
        let next_byte = u64::from(next).checked_mul(chunk_size)?;
        if next_byte >= coalesce_cap {
            break;
        }
        let next_idx = ChunkIndex::new(next);
        if dispatched.is_complete(next_idx) {
            break;
        }
        count += 1;
    }

    let start_byte = first_start;
    // The dispatch covers exactly `count` whole chunks (clamped at
    // total_size for the source's last chunk, which is the only
    // legitimate "partial" case). Never clamped at a part boundary —
    // the worker handles the at-most-one cross via multi-segment
    // routing.
    let end_byte = start_byte
        .checked_add(u64::from(count).checked_mul(chunk_size)?)?
        .min(total_size);
    let range = ByteRange::new(ByteOffset::new(start_byte), ByteOffset::new(end_byte))?;
    Some(Dispatch {
        first,
        count,
        range,
        kind: DispatchKind::Fetch,
    })
}

/// Pick a single already-complete chunk and build a [`Dispatch`]
/// that re-fetches it as a §11 verification probe.
///
/// Returns `None` when no probe-eligible chunk exists yet — either
/// the bitmap is fully empty (the very first dispatches haven't
/// landed) or fingerprints recording is racing the bitmap and the
/// CRC for the picked chunk hasn't been written. The §11 contract
/// is "every Nth completion *attempts* a probe"; we don't insist
/// every attempt actually finds a target.
fn pick_probe_dispatch(
    bitmap: &ChunkBitmap,
    fingerprints: &ChunkFingerprints,
    total_chunks: u32,
    chunk_size: u64,
    total_size: u64,
    rng_state: &mut u64,
) -> Option<Dispatch> {
    if total_chunks == 0 || chunk_size == 0 {
        return None;
    }
    // Sample up to 8 random indices and pick the first one whose
    // bitmap bit is set and whose fingerprint is non-zero.
    for _ in 0..8 {
        *rng_state = rng_state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let idx = u32::try_from(rng_state.wrapping_shr(32) % u64::from(total_chunks))
            .unwrap_or(0)
            .min(total_chunks - 1);
        let chunk_idx = ChunkIndex::new(idx);
        if !bitmap.is_complete(chunk_idx) {
            continue;
        }
        let expected = fingerprints.get(chunk_idx);
        if expected == 0 {
            continue;
        }
        let start_byte = u64::from(idx).checked_mul(chunk_size)?;
        if start_byte >= total_size {
            continue;
        }
        let end_byte = start_byte.saturating_add(chunk_size).min(total_size);
        let range = ByteRange::new(ByteOffset::new(start_byte), ByteOffset::new(end_byte))?;
        return Some(Dispatch {
            first: chunk_idx,
            count: 1,
            range,
            kind: DispatchKind::Probe { expected },
        });
    }
    None
}

#[derive(Debug)]
struct Completion {
    first: ChunkIndex,
    count: u32,
    bytes: u64,
    pwrite_time: Duration,
    attempts: u32,
    elapsed: Duration,
    kind: DispatchKind,
    crcs: Vec<u32>,
    result: Result<(), WorkerError>,
}

/// RAII guard for the single-stream path: fires
/// [`ProgressState::worker_finished`] on drop. Pairs with the
/// matching `worker_started` call earlier in [`run_single_stream`].
struct SingleStreamGuard<'a> {
    progress: Option<&'a ProgressState>,
}

impl Drop for SingleStreamGuard<'_> {
    fn drop(&mut self) {
        if let Some(p) = self.progress {
            p.worker_finished();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- chunk_count --------------------------------------------------

    #[test]
    fn chunk_count_rounds_up() {
        assert_eq!(chunk_count(0, 4096).unwrap(), 0);
        assert_eq!(chunk_count(1, 4096).unwrap(), 1);
        assert_eq!(chunk_count(4096, 4096).unwrap(), 1);
        assert_eq!(chunk_count(4097, 4096).unwrap(), 2);
        assert_eq!(chunk_count(4096 * 1000, 4096).unwrap(), 1000);
    }

    #[test]
    fn chunk_count_zero_size_rejected() {
        assert!(matches!(
            chunk_count(1, 0),
            Err(SchedulerError::InvalidChunkSize)
        ));
    }

    // ---- worker respawn ---------------------------------------------------

    #[test]
    fn workers_exhausted_error_renders_respawn_count() {
        let err = SchedulerError::WorkersExhausted { respawns: 17 };
        let rendered = err.to_string();
        assert!(
            rendered.contains("17"),
            "respawn count missing from {rendered:?}"
        );
        assert!(
            rendered.contains("respawn"),
            "rendered message missing 'respawn': {rendered:?}"
        );
    }

    #[test]
    fn rebuild_dispatched_recovers_chunks_lost_to_dead_workers() {
        // Simulates the "all workers died" branch: the scheduler had
        // marked chunks 0..4 as dispatched but only 0..2 are actually
        // complete in the shared bitmap. Rebuilding `dispatched` from
        // `bitmap` must un-dispatch chunks 2 and 3 so the next pass
        // can re-issue them.
        let total_chunks = 8;
        let bitmap = ChunkBitmap::new(total_chunks);
        bitmap.complete_range(ChunkIndex::ZERO, ChunkIndex::new(2));

        // Pre-respawn `dispatched`: the scheduler optimistically
        // marked 0..4 because it had handed those tasks to workers.
        let dispatched_before = ChunkBitmap::new(total_chunks);
        dispatched_before.complete_range(ChunkIndex::ZERO, ChunkIndex::new(4));

        // Mirror the rebuild loop in `run_parallel`.
        let dispatched_after = ChunkBitmap::new(total_chunks);
        for i in 0..total_chunks {
            let idx = ChunkIndex::new(i);
            if bitmap.is_complete(idx) {
                dispatched_after.mark_complete(idx);
            }
        }

        // Lost chunks (2, 3) are un-dispatched and the scheduler can
        // pick them up starting from cursor 0.
        assert_eq!(
            pick_next_chunk(&dispatched_after, 0, total_chunks),
            Some(ChunkIndex::new(2)),
            "first not-yet-dispatched chunk after rebuild",
        );
        // Sanity: pre-rebuild it would have skipped to 4.
        assert_eq!(
            pick_next_chunk(&dispatched_before, 0, total_chunks),
            Some(ChunkIndex::new(4)),
        );
    }

    // ---- is_disk_buffer_full ------------------------------------------

    #[test]
    fn disk_buffer_throttle_disabled_without_progress_state() {
        let cfg = SchedulerConfig {
            max_disk_buffer: Some(1024),
            ..Default::default()
        };
        // No progress state → throttle inert regardless of cap.
        assert!(!is_disk_buffer_full(&cfg));
    }

    #[test]
    fn disk_buffer_throttle_disabled_when_cap_unset() {
        let progress = ProgressState::new();
        progress.add_downloaded(1_000_000);
        progress.set_bytes_decoded_input(0);
        // `max_disk_buffer` left at the default 0 (= disabled).
        let cfg = SchedulerConfig {
            progress: Some(progress),
            max_disk_buffer: None,
            ..Default::default()
        };
        assert!(!is_disk_buffer_full(&cfg));
    }

    #[test]
    fn disk_buffer_throttle_engages_when_lookahead_at_cap() {
        let progress = ProgressState::new();
        // Scheduler publishes the live cap to progress on entry; we
        // mirror that here so `is_disk_buffer_full` reads it from the
        // snapshot.
        progress.set_max_disk_buffer(1024);
        progress.add_downloaded(2_000);
        progress.set_bytes_decoded_input(500); // lookahead = 1500 ≥ 1024
        let cfg = SchedulerConfig {
            progress: Some(progress),
            max_disk_buffer: Some(1024),
            ..Default::default()
        };
        assert!(is_disk_buffer_full(&cfg));
    }

    #[test]
    fn disk_buffer_throttle_releases_when_decoder_catches_up() {
        let progress = ProgressState::new();
        progress.set_max_disk_buffer(1024);
        progress.add_downloaded(1_000);
        progress.set_bytes_decoded_input(900); // lookahead = 100 < 1024
        let cfg = SchedulerConfig {
            progress: Some(progress),
            max_disk_buffer: Some(1024),
            ..Default::default()
        };
        assert!(!is_disk_buffer_full(&cfg));
    }

    #[test]
    fn disk_buffer_throttle_honors_runtime_disable() {
        // Static config has a cap set, but the coordinator pushed `0`
        // (= disabled) into progress at runtime — e.g. for the ZIP
        // path. Throttle should respect the live value.
        let progress = ProgressState::new();
        progress.set_max_disk_buffer(0);
        progress.add_downloaded(10_000_000);
        progress.set_bytes_decoded_input(0);
        let cfg = SchedulerConfig {
            progress: Some(progress),
            max_disk_buffer: Some(1024),
            ..Default::default()
        };
        assert!(!is_disk_buffer_full(&cfg));
    }

    #[test]
    fn chunk_count_overflow_rejected() {
        // chunk_size=1 with total_size > u32::MAX overflows u32.
        let total = u64::from(u32::MAX) + 2;
        match chunk_count(total, 1) {
            Err(SchedulerError::TooManyChunks { chunks, max }) => {
                assert_eq!(chunks, total);
                assert_eq!(max, u64::from(u32::MAX));
            }
            other => panic!("expected TooManyChunks, got {other:?}"),
        }
    }

    // ---- cursor_to_chunk ----------------------------------------------

    #[test]
    fn cursor_to_chunk_basic() {
        assert_eq!(cursor_to_chunk(0, 4096), 0);
        assert_eq!(cursor_to_chunk(4095, 4096), 0);
        assert_eq!(cursor_to_chunk(4096, 4096), 1);
        assert_eq!(cursor_to_chunk(4096 * 100, 4096), 100);
    }

    #[test]
    fn cursor_to_chunk_zero_chunk_size_returns_zero() {
        assert_eq!(cursor_to_chunk(1024, 0), 0);
    }

    // ---- pick_next_chunk ----------------------------------------------

    #[test]
    fn pick_next_chunk_prefers_cursor_position() {
        let dispatched = ChunkBitmap::new(10);
        // Cursor at chunk 5 means we want chunk 5 first.
        assert_eq!(
            pick_next_chunk(&dispatched, 5, 10),
            Some(ChunkIndex::new(5))
        );
    }

    #[test]
    fn pick_next_chunk_wraps_when_tail_exhausted() {
        let dispatched = ChunkBitmap::new(10);
        // Pretend chunks [5, 10) are dispatched.
        for i in 5..10 {
            dispatched.mark_complete(ChunkIndex::new(i));
        }
        // Cursor at 5 — no work above, should wrap to 0.
        assert_eq!(
            pick_next_chunk(&dispatched, 5, 10),
            Some(ChunkIndex::new(0))
        );
    }

    #[test]
    fn pick_next_chunk_returns_none_when_done() {
        let dispatched = ChunkBitmap::new(4);
        for i in 0..4 {
            dispatched.mark_complete(ChunkIndex::new(i));
        }
        assert!(pick_next_chunk(&dispatched, 0, 4).is_none());
        assert!(pick_next_chunk(&dispatched, 3, 4).is_none());
    }

    #[test]
    fn pick_next_chunk_handles_cursor_past_end() {
        let dispatched = ChunkBitmap::new(4);
        // Cursor past end: should wrap and find chunk 0.
        assert_eq!(
            pick_next_chunk(&dispatched, 100, 4),
            Some(ChunkIndex::new(0))
        );
    }

    #[test]
    fn pick_next_chunk_skips_already_dispatched() {
        let dispatched = ChunkBitmap::new(10);
        dispatched.mark_complete(ChunkIndex::new(0));
        dispatched.mark_complete(ChunkIndex::new(1));
        dispatched.mark_complete(ChunkIndex::new(2));
        // Cursor at 0 — first available is 3.
        assert_eq!(
            pick_next_chunk(&dispatched, 0, 10),
            Some(ChunkIndex::new(3))
        );
    }

    // ---- pick_next_dispatch -------------------------------------------

    #[test]
    fn pick_next_dispatch_single_chunk_when_target_one() {
        let dispatched = ChunkBitmap::new(8);
        let task =
            pick_next_dispatch(&dispatched, 0, 8, 1, 1024, 8 * 1024, None).expect("dispatch");
        assert_eq!(task.first.get(), 0);
        assert_eq!(task.count, 1);
        assert_eq!(task.range.len(), 1024);
    }

    #[test]
    fn pick_next_dispatch_coalesces_consecutive_incomplete() {
        let dispatched = ChunkBitmap::new(8);
        let task =
            pick_next_dispatch(&dispatched, 0, 8, 4, 1024, 8 * 1024, None).expect("dispatch");
        assert_eq!(task.first.get(), 0);
        assert_eq!(task.count, 4);
        assert_eq!(task.range.len(), 4 * 1024);
    }

    #[test]
    fn pick_next_dispatch_stops_at_already_dispatched() {
        let dispatched = ChunkBitmap::new(8);
        // Mark chunk 2 as already dispatched; the run starting at 0
        // can only cover 0,1.
        dispatched.mark_complete(ChunkIndex::new(2));
        let task =
            pick_next_dispatch(&dispatched, 0, 8, 8, 1024, 8 * 1024, None).expect("dispatch");
        assert_eq!(task.first.get(), 0);
        assert_eq!(task.count, 2);
        assert_eq!(task.range.len(), 2 * 1024);
    }

    #[test]
    fn pick_next_dispatch_truncates_last_partial_chunk() {
        // 3 chunks total but the last is half-sized.
        let dispatched = ChunkBitmap::new(3);
        let task = pick_next_dispatch(&dispatched, 0, 3, 8, 1_000, 2_500, None).expect("dispatch");
        assert_eq!(task.first.get(), 0);
        assert_eq!(task.count, 3);
        // 2*1000 (full) + 500 (truncated last)
        assert_eq!(task.range.len(), 2_500);
    }

    #[test]
    fn pick_next_dispatch_returns_none_when_done() {
        let dispatched = ChunkBitmap::new(4);
        for i in 0..4 {
            dispatched.mark_complete(ChunkIndex::new(i));
        }
        assert!(pick_next_dispatch(&dispatched, 0, 4, 8, 1024, 4 * 1024, None).is_none());
    }

    // ---- pick_next_dispatch: multi-part boundary clamp --------------

    /// Build a multi-part source with the given part sizes for use in
    /// the coalesce-clamp tests below.
    fn multipart_for(sizes: &[u64]) -> MultiPartSource {
        let parts: Vec<_> = sizes
            .iter()
            .enumerate()
            .map(|(i, &sz)| super::super::multi_url::PartDescriptor {
                url: Url::parse(&format!("https://h/p{i}")).expect("url"),
                size: sz,
                fingerprint: SourceFingerprint::default(),
                expected_sha256: None,
            })
            .collect();
        MultiPartSource::new(parts).expect("valid")
    }

    #[test]
    fn pick_next_dispatch_clamps_coalesce_at_part_boundary() {
        // 3 parts × 4 chunks each (chunk_size=1024, parts=4096 each).
        // From cursor=0, target=12 (the whole stream), the dispatch
        // would normally coalesce all 12 chunks into one GET. With the
        // multi-part clamp the coalesce stops at part 0's end (chunk 4).
        let dispatched = ChunkBitmap::new(12);
        let source = multipart_for(&[4096, 4096, 4096]);
        let task = pick_next_dispatch(&dispatched, 0, 12, 12, 1024, 12 * 1024, Some(&source))
            .expect("dispatch");
        assert_eq!(task.first.get(), 0);
        assert_eq!(task.count, 4, "coalesce must stop at part 0/1 boundary");
        assert_eq!(task.range.len(), 4 * 1024);
        assert_eq!(task.range.start().get(), 0);
        assert_eq!(task.range.end_exclusive().get(), 4096);
    }

    #[test]
    fn pick_next_dispatch_starts_a_new_dispatch_inside_each_part() {
        // After part 0 is done, the next dispatch starts at chunk 4
        // (= start of part 1) and again clamps at part 1's end.
        let dispatched = ChunkBitmap::new(12);
        for i in 0..4 {
            dispatched.mark_complete(ChunkIndex::new(i));
        }
        let source = multipart_for(&[4096, 4096, 4096]);
        let task = pick_next_dispatch(&dispatched, 4, 12, 12, 1024, 12 * 1024, Some(&source))
            .expect("dispatch");
        assert_eq!(task.first.get(), 4);
        assert_eq!(task.count, 4, "coalesce clamps at part 1/2 boundary");
        assert_eq!(task.range.start().get(), 4096);
        assert_eq!(task.range.end_exclusive().get(), 8192);
    }

    #[test]
    fn pick_next_dispatch_within_one_part_coalesces_normally() {
        // Cursor inside part 1 with target=2: coalesces 2 chunks
        // without ever hitting a boundary.
        let dispatched = ChunkBitmap::new(12);
        let source = multipart_for(&[4096, 4096, 4096]);
        let task = pick_next_dispatch(&dispatched, 5, 12, 2, 1024, 12 * 1024, Some(&source))
            .expect("dispatch");
        assert_eq!(task.first.get(), 5);
        assert_eq!(task.count, 2);
        assert_eq!(task.range.start().get(), 5 * 1024);
        assert_eq!(task.range.end_exclusive().get(), 7 * 1024);
    }

    #[test]
    fn pick_next_dispatch_emits_cross_boundary_chunk_for_misaligned_parts() {
        // Real-world Arb shape: chunk_size doesn't divide every
        // part_size, so a single bitmap chunk straddles a boundary.
        // Total = 5 KiB across 2 parts of 2.5 KiB each (gcd 512 B).
        // chunk_size = 1024 → 5 chunks total. Chunk 2 covers global
        // [2048, 3072) which spans the part 0 / part 1 boundary at
        // 2560.
        let dispatched = ChunkBitmap::new(5);
        let source = multipart_for(&[2560, 2560]);
        // From the source's start, target = 5 (request all). The
        // first dispatch must INCLUDE chunk 2 even though it
        // crosses, so the dispatch covers part 0 + the cross
        // chunk. Subsequent chunks (3, 4) are entirely in part 1
        // and should not be coalesced into this dispatch.
        let task =
            pick_next_dispatch(&dispatched, 0, 5, 5, 1024, 5120, Some(&source)).expect("dispatch");
        assert_eq!(task.first.get(), 0);
        // Chunks 0 (part 0), 1 (part 0), 2 (CROSSES). After chunk 2
        // the next chunk (3) starts at 3072 which is past the
        // post-boundary cap, so it stops here.
        assert_eq!(task.count, 3, "include the cross-boundary chunk only");
        assert_eq!(task.range.start().get(), 0);
        // The dispatch's nominal end is 3 * 1024 = 3072. NOT
        // truncated at the boundary (2560) — the worker handles
        // the cross via multi-segment routing.
        assert_eq!(task.range.end_exclusive().get(), 3072);
    }

    #[test]
    fn pick_next_dispatch_starts_at_cross_boundary_chunk_after_part_1_complete() {
        // After completing chunks 0..3 (which spans the boundary),
        // the next dispatch begins at chunk 3 in part 1.
        let dispatched = ChunkBitmap::new(5);
        for i in 0..3 {
            dispatched.mark_complete(ChunkIndex::new(i));
        }
        let source = multipart_for(&[2560, 2560]);
        let task =
            pick_next_dispatch(&dispatched, 3, 5, 5, 1024, 5120, Some(&source)).expect("dispatch");
        assert_eq!(task.first.get(), 3);
        // Chunks 3 and 4 cover [3072, 5120) which fits in part 1.
        // Both included, no further parts to cross.
        assert_eq!(task.count, 2);
        assert_eq!(task.range.start().get(), 3072);
        assert_eq!(task.range.end_exclusive().get(), 5120);
    }

    #[test]
    fn pick_next_dispatch_single_part_unaffected_by_clamp() {
        // For a 1-part source the boundary equals the total size, so
        // the clamp matches the unconstrained behaviour exactly.
        let dispatched = ChunkBitmap::new(8);
        let source = multipart_for(&[8 * 1024]);
        let with_source = pick_next_dispatch(&dispatched, 0, 8, 4, 1024, 8 * 1024, Some(&source))
            .expect("dispatch");
        let without_source =
            pick_next_dispatch(&dispatched, 0, 8, 4, 1024, 8 * 1024, None).expect("dispatch");
        assert_eq!(with_source.first, without_source.first);
        assert_eq!(with_source.count, without_source.count);
        assert_eq!(with_source.range.len(), without_source.range.len());
    }

    #[test]
    fn target_chunk_count_no_policy_returns_one() {
        assert_eq!(target_chunk_count(None, 4096), 1);
    }

    #[test]
    fn target_chunk_count_with_policy_divides() {
        let policy = Arc::new(ChunkSizePolicy::with_bounds(
            1024,
            4 * 1024,
            1024,
            64 * 1024,
            Duration::from_millis(10),
        ));
        assert_eq!(target_chunk_count(Some(&policy), 1024), 4);
    }
}
