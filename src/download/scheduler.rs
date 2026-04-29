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
//! Workers receive [`ChunkIndex`] assignments from a bounded
//! `mpsc::sync_channel` (the **task** channel) and report results on a
//! second `mpsc::channel` (the **completion** channel). The calling
//! thread serves as the scheduler: it picks the next chunk to dispatch
//! based on the decoder's cursor (chunks at or past the cursor are
//! preferred), waits on completions, and tracks progress.
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

use super::sparse_file::{SparseFile, SparseFileError};
use super::worker::{
    download_chunk, ChunkContext, ChunkOutcome, RetryConfig, SourceFingerprint, WorkerError,
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
    /// Chunk size in bytes. Must be non-zero.
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
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            workers: DEFAULT_WORKERS,
            retry: RetryConfig::default(),
            progress: None,
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
    let (task_tx, task_rx) = mpsc::sync_channel::<ChunkIndex>(pool_capacity);
    let (done_tx, done_rx) = mpsc::channel::<Completion>();
    let task_rx = Mutex::new(task_rx);
    let cancel = AtomicBool::new(false);

    let scheduler_outcome: Result<DownloadStats, SchedulerError> = thread::scope(|scope| {
        let ctx = ChunkContext {
            client,
            url: &info.url,
            fingerprint: &info.fingerprint,
            sparse,
            progress: config.progress.as_deref(),
        };
        // Spawn workers.
        for w_id in 0..workers {
            let task_rx = &task_rx;
            let done_tx = done_tx.clone();
            let cancel = &cancel;
            let chunk_size = config.chunk_size;
            let total_size = info.total_size;
            let retry = config.retry.clone();
            thread::Builder::new()
                .name(format!("peel-download-worker-{w_id}"))
                .spawn_scoped(scope, move || {
                    worker_loop(
                        &ctx, chunk_size, total_size, &retry, task_rx, done_tx, cancel,
                    );
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

        'outer: loop {
            // Dispatch as many as the channel will accept without
            // blocking.
            while in_flight < workers && completed + in_flight < total_chunks {
                let cursor_chunk =
                    cursor_to_chunk(cursor.load(Ordering::Relaxed), config.chunk_size);
                let next = pick_next_chunk(&dispatched, cursor_chunk, total_chunks);
                let Some(idx) = next else { break };
                match task_tx.try_send(idx) {
                    Ok(()) => {
                        dispatched.mark_complete(idx);
                        in_flight += 1;
                    }
                    Err(mpsc::TrySendError::Full(_)) => break,
                    Err(mpsc::TrySendError::Disconnected(_)) => {
                        cancel.store(true, Ordering::Relaxed);
                        shutdown_reason.get_or_insert(SchedulerError::ChunkFailed {
                            chunk: idx,
                            attempts: 0,
                            source: WorkerError::Cancelled { chunk: idx },
                        });
                        break 'outer;
                    }
                }
            }

            if completed >= total_chunks {
                break;
            }

            // Wait on a completion. Use a short timeout so we re-check
            // the cursor periodically and pick up newly-prioritised
            // work while workers are mid-chunk.
            let msg = match done_rx.recv_timeout(Duration::from_millis(50)) {
                Ok(m) => m,
                Err(mpsc::RecvTimeoutError::Timeout) => continue,
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            };

            in_flight = in_flight.saturating_sub(1);
            stats_local.retries = stats_local
                .retries
                .saturating_add(u64::from(msg.attempts.saturating_sub(1)));
            match msg.result {
                Ok(()) => {
                    bitmap.mark_complete(msg.chunk);
                    stats_local.bytes_downloaded =
                        stats_local.bytes_downloaded.saturating_add(msg.bytes);
                    stats_local.chunks_completed = stats_local.chunks_completed.saturating_add(1);
                    completed += 1;
                }
                Err(err) => {
                    cancel.store(true, Ordering::Relaxed);
                    shutdown_reason.get_or_insert(SchedulerError::ChunkFailed {
                        chunk: msg.chunk,
                        attempts: msg.attempts,
                        source: err,
                    });
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

/// One worker thread's lifetime: pull tasks off the shared receiver,
/// execute, report the result, repeat. Exits cleanly when the task
/// channel closes or `cancel` becomes true.
fn worker_loop(
    ctx: &ChunkContext<'_>,
    chunk_size: u64,
    total_size: u64,
    retry: &RetryConfig,
    task_rx: &Mutex<mpsc::Receiver<ChunkIndex>>,
    done_tx: mpsc::Sender<Completion>,
    cancel: &AtomicBool,
) {
    loop {
        if cancel.load(Ordering::Relaxed) {
            return;
        }
        let chunk = {
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
                Ok(idx) => idx,
                Err(_) => return,
            }
        };

        let range = match chunk_range(chunk, chunk_size, total_size) {
            Some(r) => r,
            None => {
                let _ = done_tx.send(Completion {
                    chunk,
                    bytes: 0,
                    attempts: 0,
                    result: Err(WorkerError::Cancelled { chunk }),
                });
                return;
            }
        };

        if let Some(p) = ctx.progress {
            p.worker_started();
        }
        let outcome = download_chunk(ctx, chunk, range, retry, cancel);
        if let Some(p) = ctx.progress {
            p.worker_finished();
        }

        let msg = match outcome {
            Ok(ChunkOutcome { bytes, attempts }) => Completion {
                chunk,
                bytes,
                attempts,
                result: Ok(()),
            },
            Err(err) => Completion {
                chunk,
                bytes: 0,
                attempts: 1,
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

/// The half-open byte range covered by chunk `idx`, given the chunk
/// size and the file's total size. Returns `None` if `idx` is past the
/// end of the file or if arithmetic would overflow `u64`.
fn chunk_range(idx: ChunkIndex, chunk_size: u64, total_size: u64) -> Option<ByteRange> {
    idx.byte_range(chunk_size, total_size)
}

#[derive(Debug)]
struct Completion {
    chunk: ChunkIndex,
    bytes: u64,
    attempts: u32,
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

    // ---- chunk_range --------------------------------------------------

    #[test]
    fn chunk_range_typical() {
        let r = chunk_range(ChunkIndex::new(2), 4096, 16_384).expect("range");
        assert_eq!(r.start(), ByteOffset::new(8192));
        assert_eq!(r.end_exclusive(), ByteOffset::new(12_288));
    }

    #[test]
    fn chunk_range_truncates_last_partial_chunk() {
        let r = chunk_range(ChunkIndex::new(3), 1_000, 3_500).expect("range");
        assert_eq!(r.len(), 500);
    }
}
