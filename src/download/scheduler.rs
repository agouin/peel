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

#![cfg(unix)]

use std::io::Read;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;

use super::chunk_fingerprints::ChunkFingerprints;
use super::chunk_policy::{ChunkSizePolicy, Sample};
use super::sparse_file::{SparseFile, SparseFileError};
use super::worker::{
    download_dispatch, ChunkContext, ChunkOutcome, Dispatch, DispatchKind, RetryConfig,
    SourceFingerprint, WorkerError,
};
use crate::bitmap::ChunkBitmap;
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

    /// IO into the sparse file failed.
    #[error("sparse-file io")]
    SparseFile(#[source] SparseFileError),

    /// IO reading the streaming response body.
    #[error("io reading response body")]
    BodyIo(#[source] std::io::Error),
}

/// Discovery summary returned by [`discover`].
#[derive(Debug, Clone)]
pub struct DownloadInfo {
    /// Final URL after redirects.
    pub url: Url,
    /// Total source size in bytes.
    pub total_size: u64,
    /// Source identity captured from `ETag` / `Last-Modified`.
    pub fingerprint: SourceFingerprint,
    /// True iff the server advertised `Accept-Ranges: bytes`.
    pub accept_ranges: bool,
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
/// # Errors
///
/// Returns [`SchedulerError::Head`] if the request fails, or
/// [`SchedulerError::MissingContentLength`] if the server didn't supply
/// one.
pub fn discover(client: &Client, url: &Url) -> Result<DownloadInfo, SchedulerError> {
    let head = client.head(url).map_err(|source| SchedulerError::Head {
        url: url.to_string(),
        source,
    })?;
    let total_size = head
        .headers
        .get("content-length")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .ok_or_else(|| SchedulerError::MissingContentLength {
            url: head.final_url.to_string(),
        })?;
    let accept_ranges = head
        .headers
        .get("accept-ranges")
        .map(|v| v.eq_ignore_ascii_case("bytes"))
        .unwrap_or(false);
    let fingerprint = SourceFingerprint::from_headers(&head.headers);
    Ok(DownloadInfo {
        url: head.final_url,
        total_size,
        fingerprint,
        accept_ranges,
    })
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
    sparse: &SparseFile,
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
    sparse: &SparseFile,
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
    // OR it was already complete on entry."
    let dispatched = ChunkBitmap::new(total_chunks);
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

    let scheduler_outcome: Result<DownloadStats, SchedulerError> = thread::scope(|scope| {
        let ctx = ChunkContext {
            client,
            url: &info.url,
            fingerprint: &info.fingerprint,
            chunk_size: config.chunk_size,
            sparse,
            progress: config.progress.as_deref(),
        };
        // Spawn workers.
        for w_id in 0..workers {
            let task_rx = &task_rx;
            let done_tx = done_tx.clone();
            let cancel = &cancel;
            let retry = config.retry.clone();
            thread::Builder::new()
                .name(format!("peel-download-worker-{w_id}"))
                .spawn_scoped(scope, move || {
                    worker_loop(&ctx, &retry, task_rx, done_tx, cancel);
                })
                .ok();
        }
        // Drop the scheduler's clone of the completion sender so the
        // channel closes once every worker exits.
        drop(done_tx);

        // Dispatch + drain loop.
        let mut completed = chunks_resumed;
        let mut in_flight: u32 = 0;
        let mut stats_local = stats.clone();
        let mut shutdown_reason: Option<SchedulerError> = None;
        // §11 mid-flight verifier state: counts successful Fetch
        // completions and queues a Probe every `probe.interval`
        // completions (when fingerprints are configured).
        let mut completions_since_probe: u32 = 0;
        // Lightweight LCG to randomise which already-complete chunk
        // we probe. Seeded from total_chunks so the choice differs
        // per run but stays deterministic given the same source.
        let mut probe_rng: u64 = (u64::from(total_chunks) << 32) ^ 0x9E37_79B9_7F4A_7C15;

        'outer: loop {
            // Dispatch as many as the channel will accept without
            // blocking.
            while in_flight < workers && completed + in_flight < total_chunks {
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
                Ok(()) => match msg.kind {
                    DispatchKind::Fetch => {
                        let end = msg.first.get().saturating_add(msg.count);
                        bitmap.complete_range(msg.first, ChunkIndex::new(end));
                        stats_local.bytes_downloaded =
                            stats_local.bytes_downloaded.saturating_add(msg.bytes);
                        stats_local.chunks_completed =
                            stats_local.chunks_completed.saturating_add(msg.count);
                        completed = completed.saturating_add(msg.count);
                        // Record per-chunk CRC-32C fingerprints for
                        // §11's drift detector. The CRCs come back
                        // in chunk order; pad / trim defensively.
                        if let Some(fps) = config.fingerprints.as_deref() {
                            for (i, crc) in msg.crcs.iter().enumerate().take(msg.count as usize) {
                                let idx = msg.first.get().saturating_add(i as u32);
                                if idx < total_chunks {
                                    fps.record(ChunkIndex::new(idx), *crc);
                                }
                            }
                        }
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
                        // CRC-32C in-line. No bitmap / completion
                        // bookkeeping; the bytes were already counted
                        // in the original Fetch.
                    }
                },
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

        match shutdown_reason {
            Some(e) => Err(e),
            None => Ok(stats_local),
        }
    });

    scheduler_outcome
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
            // INVARIANT: the only writer to this Mutex is the scheduler
            // setting it up; if a worker panics holding the lock, all
            // threads die together inside thread::scope, so a poisoned
            // mutex is unreachable in practice. Treat poisoning as a
            // signal to exit cleanly.
            let rx = match task_rx.lock() {
                Ok(g) => g,
                Err(_) => return,
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
                attempts,
                crcs,
            }) => Completion {
                first: dispatch.first,
                count: dispatch.count,
                bytes,
                attempts,
                elapsed,
                kind: dispatch.kind,
                crcs,
                result: Ok(()),
            },
            Err(err) => Completion {
                first: dispatch.first,
                count: dispatch.count,
                bytes: 0,
                attempts: 1,
                elapsed,
                kind: dispatch.kind,
                crcs: Vec::new(),
                result: Err(err),
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
    sparse: &SparseFile,
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
    while written < total_size {
        let remaining = total_size - written;
        let want = u64::try_from(buf.len()).unwrap_or(u64::MAX).min(remaining);
        let want_usize =
            usize::try_from(want).map_err(|_| SchedulerError::SingleStreamBodyLength {
                expected: total_size,
                actual: written,
            })?;
        let slice = &mut buf[..want_usize];
        let n = resp.body.read(slice).map_err(SchedulerError::BodyIo)?;
        if n == 0 {
            return Err(SchedulerError::SingleStreamBodyLength {
                expected: total_size,
                actual: written,
            });
        }
        sparse
            .pwrite_at(ByteOffset::new(written), &slice[..n])
            .map_err(SchedulerError::SparseFile)?;
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
    if !total_size.is_multiple_of(chunk_size) {
        let last = u32::try_from(total_size / chunk_size).unwrap_or(u32::MAX);
        if last < total_chunks && !bitmap.is_complete(ChunkIndex::new(last)) {
            bitmap.mark_complete(ChunkIndex::new(last));
            stats.chunks_completed = stats.chunks_completed.saturating_add(1);
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
) -> Option<Dispatch> {
    let first = pick_next_chunk(dispatched, cursor_chunk, total_chunks)?;
    let target = target_chunks.max(1);
    // Walk forward to see how many consecutive chunks we can
    // coalesce. Cap at `target_chunks` and at `total_chunks`.
    let mut count: u32 = 1;
    while count < target {
        let next = first.get().checked_add(count)?;
        if next >= total_chunks {
            break;
        }
        let next_idx = ChunkIndex::new(next);
        if dispatched.is_complete(next_idx) {
            break;
        }
        count += 1;
    }

    let start_byte = u64::from(first.get()).checked_mul(chunk_size)?;
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
        let task = pick_next_dispatch(&dispatched, 0, 8, 1, 1024, 8 * 1024).expect("dispatch");
        assert_eq!(task.first.get(), 0);
        assert_eq!(task.count, 1);
        assert_eq!(task.range.len(), 1024);
    }

    #[test]
    fn pick_next_dispatch_coalesces_consecutive_incomplete() {
        let dispatched = ChunkBitmap::new(8);
        let task = pick_next_dispatch(&dispatched, 0, 8, 4, 1024, 8 * 1024).expect("dispatch");
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
        let task = pick_next_dispatch(&dispatched, 0, 8, 8, 1024, 8 * 1024).expect("dispatch");
        assert_eq!(task.first.get(), 0);
        assert_eq!(task.count, 2);
        assert_eq!(task.range.len(), 2 * 1024);
    }

    #[test]
    fn pick_next_dispatch_truncates_last_partial_chunk() {
        // 3 chunks total but the last is half-sized.
        let dispatched = ChunkBitmap::new(3);
        let task = pick_next_dispatch(&dispatched, 0, 3, 8, 1_000, 2_500).expect("dispatch");
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
        assert!(pick_next_dispatch(&dispatched, 0, 4, 8, 1024, 4 * 1024).is_none());
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
