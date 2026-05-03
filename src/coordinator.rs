//! The §10 coordinator: ties the download scheduler, the extractor, and
//! the checkpoint module together into one resumable pipeline.
//!
//! [`run`] is the single public entry point. It opens (or reuses) the
//! sparse `<output>.peel.part` and `<output>.peel.ckpt` files alongside
//! the user's chosen output, issues a `HEAD` to discover the source's
//! size and identity, and either starts a fresh extraction or resumes an
//! existing one off the on-disk checkpoint.
//!
//! # Threading
//!
//! The download scheduler runs on a background thread. The extractor
//! runs on the calling thread. They communicate through three pieces of
//! shared state:
//!
//! - the [`SparseFile`] — workers write chunks at offset, the extractor
//!   reads sequentially from the front;
//! - the [`ChunkBitmap`] — workers mark complete chunks, the extractor
//!   blocks on the bit for the chunk it needs next;
//! - the cursor [`AtomicU64`] — the extractor advances it as it reads,
//!   the scheduler biases dispatch toward chunks at or past the cursor.
//!
//! When the download thread exits (success or error) it sets a shared
//! `download_done` flag and stashes its result in a mutex; the extractor's
//! [`BlockingSparseReader`] checks both whenever it is about to block on
//! a missing chunk.
//!
//! # Checkpoint cadence
//!
//! Quiescent advances fire many times a second on a fast pipeline.
//! Writing a checkpoint on every one would be wasteful. The coordinator
//! throttles: it writes a new checkpoint when *either* (a) at least
//! [`CoordinatorConfig::checkpoint_min_bytes`] bytes of source progress
//! have been made since the last write, or (b) at least
//! [`CoordinatorConfig::checkpoint_min_interval`] of wall-clock time has
//! elapsed since the last write. Either floor catches the slow case
//! (small archive, fast network) and the fast case (large archive,
//! slow disk).
//!
//! # Cleanup on success
//!
//! On a clean run the coordinator deletes `.peel.part` and
//! `.peel.ckpt`. Failures leave them in place so the next invocation
//! resumes. The output (the extracted directory or the raw output file)
//! is never deleted on failure — partial extraction state is the user's
//! to inspect.
//!
//! # Integrity invariants
//!
//! These are the durable facts every other module in the pipeline
//! relies on. They are stated here, in one place, because no single
//! file enforces all of them and the `PLAN_responsiveness.md` §3
//! audit was made harder by their being scattered across comments.
//!
//! ### What "chunk N is in the bitmap" means
//!
//! When [`ChunkBitmap::is_complete`] returns `true` for chunk `N`,
//! every byte covered by `[N * chunk_size, min((N+1) * chunk_size,
//! total_size))` is durable on disk *as of the most recent
//! [`SparseFile::sync_all`]*, and matches the CRC-32C recorded at
//! [`ChunkFingerprints::get(N)`] (when fingerprints are enabled).
//!
//! The happens-before edge is: a worker's
//! [`SparseFile::pwrite_at`] returns successfully → the scheduler
//! records [`ChunkFingerprints::record(N, crc)`] → the scheduler
//! calls [`ChunkBitmap::complete_range`] (this ordering is enforced
//! at [`crate::download::scheduler`]). Readers do the inverse: they
//! `Acquire`-load the bitmap bit, and only after observing it set
//! do they trust the matching fingerprint. The §11 source-drift
//! probe and the §3.1 cursor audit (see [`run_cursor_chunk_audit`])
//! both depend on this ordering.
//!
//! Bytes are *not* durable across a SIGKILL until either
//! [`SparseFile::sync_all`] runs (the checkpoint observer calls it
//! before persisting the `.peel.ckpt`) or the OS flushes the page
//! cache asynchronously. The bitmap-in-memory may therefore claim a
//! chunk complete that, after a crash, the kernel never wrote to
//! disk. The next run's resume loads only the **persisted**
//! checkpoint's bitmap, which is `sync_all`-clean by construction;
//! any chunk that was complete in memory but missed the
//! `sync_all` reverts to "not complete" on resume and is re-fetched
//! cleanly. The `.peel.part` file's bytes for those chunks are
//! either the genuine bytes (if they raced past the cache before
//! the crash) or zero (if not) — and the fresh fetch overwrites
//! either case.
//!
//! ### What `decoder_position` guarantees
//!
//! The [`Checkpoint::decoder_position`] is the source-byte offset
//! the streaming decoder will read first on resume. Two things
//! must be true at that offset:
//!
//! - Chunk `decoder_position / chunk_size` is in the resumed
//!   bitmap with bytes matching its fingerprint (the §3.1 cursor
//!   audit re-CRCs to confirm before letting the decoder run).
//! - Either (a) the decoder is mid-frame and the saved
//!   [`Checkpoint::decoder_state`] blob captures every piece of
//!   in-frame state needed to continue, with
//!   `bytes_consumed_at_capture == decoder_position` (V2 zstd blobs
//!   assert this; the typed
//!   [`crate::decode::DecodeError::ResumeMismatch`] is what fires
//!   if it doesn't hold); or (b) the decoder is at a frame
//!   boundary and `decoder_state` is `None`, in which case a
//!   freshly-constructed decoder reading from `decoder_position`
//!   onward produces byte-identical output.
//!
//! ### What `max_disk_buffer` measures
//!
//! `bytes_downloaded - bytes_decoded_input` is the on-disk
//! footprint of bytes downloaded but not yet read by the decoder
//! (= the lookahead). The scheduler's disk-buffer throttle stops
//! dispatching when this gap reaches `max_disk_buffer`, so under
//! steady state the gap oscillates around the cap. Two
//! transients break that intuition:
//!
//! - On resume, [`run`] pre-credits `bytes_downloaded` with the
//!   bytes for already-complete chunks (so the renderer doesn't
//!   snap from 0%) but `bytes_decoded_input` starts at the
//!   resumed `decoder_position`. The lookahead therefore reads
//!   `(resumed_dl_bytes − decoder_position)` immediately at
//!   startup, which can briefly exceed the cap until the decoder
//!   draws it down. This is benign and handled by the throttle's
//!   "stop dispatching" rule (= already at cap, nothing further
//!   to do).
//! - When the decoder hits source bytes it can't make progress on
//!   (the §3 corruption hypothesis), `bytes_decoded_input`
//!   freezes while `bytes_downloaded` continues until the cap is
//!   hit; the pipeline then deadlocks. The §1.2 stall heartbeat
//!   surfaces this within `STALL_WARN_INTERVAL`.
//!
//! ### Behavior under SIGKILL
//!
//! After a `kill -9`, the most recently-persisted `.peel.ckpt`
//! and `.peel.part` are durable. The next invocation re-loads
//! the checkpoint, runs the §11 server-side drift probe and the
//! §3.1 cursor-chunk local audit, and proceeds from
//! `decoder_position`. There is no "garbage collection" of the
//! sparse file: bytes for chunks that *were* written before the
//! kill but never persisted into the bitmap stay on disk and are
//! either overwritten by the resumed download (if the resumed
//! bitmap doesn't have them) or harmlessly ignored.

#![cfg(unix)]

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use thiserror::Error;

use crate::bitmap::{BitmapDecodeError, ChunkBitmap};
use crate::checkpoint::{Checkpoint, CheckpointError, SinkState};
use crate::decode::{DecodeError, DecoderFactory, DecoderRegistry, StreamingDecoder};
use crate::download::{
    chunk_count, discover_with_mirrors, run as run_scheduler, ChunkFingerprints, DownloadInfo,
    DownloadStats, ProbeConfig, RetryConfig, SchedulerConfig, SchedulerError, SourceFingerprint,
    SparseFile, SparseFileError, ZipPipeline, ZipPipelineConfig, ZipPipelineError,
    ZipPipelineEvent, ZipResumeState, DEFAULT_CHUNK_SIZE, DEFAULT_WORKERS,
};
use crate::extractor::{
    CheckpointAck, CheckpointInfo, ExtractionStats, Extractor, ExtractorConfig, ExtractorError,
    DEFAULT_PUNCH_THRESHOLD,
};
use crate::http::{Client, ClientError, Url, UrlError};
use crate::progress::ProgressState;
use crate::punch::{default_puncher, NoopPuncher, PunchHole};
use crate::sink::{RawSink, Sink, SinkError, TarSink, ZipSink};
use crate::types::{ByteOffset, ChunkIndex};
use crate::zip::FORMAT_NAME as ZIP_FORMAT_NAME;

/// Sentinel `io::Error` message used to thread kill-switch trips
/// through a layer (decoder, extractor observer, ZIP pipeline) that
/// only speaks `io::Error`. The outer `run_one` / `run_zip` matchers
/// recognize this string and translate it into a typed
/// [`CoordinatorError::Aborted`]; everything else surfaces as an
/// extractor / pipeline failure.
const KILL_SENTINEL: &str = "peel:kill-switch-tripped";

/// What kind of output the coordinator should produce.
#[derive(Debug, Clone)]
pub enum OutputTarget {
    /// Stream the decoded bytes verbatim into a single file.
    File(PathBuf),
    /// Extract the decoded archive (tar) into the given directory.
    /// The directory must exist (the coordinator will create it if
    /// missing).
    Dir(PathBuf),
}

impl OutputTarget {
    /// Path the .peel.part / .peel.ckpt sidecars are placed alongside.
    fn anchor(&self) -> &Path {
        match self {
            Self::File(p) | Self::Dir(p) => p.as_path(),
        }
    }
}

/// Tunable knobs for [`run`].
#[derive(Debug, Clone)]
pub struct CoordinatorConfig {
    /// HTTP-side: chunk size used when slicing the source for parallel
    /// ranged downloads. This is the **bitmap chunk size** — the
    /// unit of completion tracked in the bitmap and persisted in
    /// checkpoints. With adaptive sizing on (the default), the
    /// scheduler may coalesce several consecutive bitmap chunks into
    /// a single ranged GET; the bitmap unit itself stays fixed for
    /// the lifetime of the run (`PLAN_v2.md` §8).
    pub chunk_size: u64,
    /// Adaptive chunk-size policy (`PLAN_v2.md` §8). When `true`
    /// (default), the scheduler observes per-dispatch latency / retry
    /// rate and grows or shrinks the dispatch size accordingly,
    /// bounded below by `chunk_size` and above by 64 MiB. When
    /// `false`, the dispatch size stays equal to `chunk_size` for the
    /// whole run (matches the pre-§8 behaviour).
    pub adaptive_chunk_size: bool,
    /// HTTP-side: number of parallel download workers.
    pub workers: u32,
    /// Per-chunk retry policy (forwarded to the scheduler).
    pub retry: RetryConfig,
    /// Extractor-side: minimum gap between in-loop punch syscalls.
    pub punch_threshold: u64,
    /// Minimum source-byte progress between checkpoint writes.
    pub checkpoint_min_bytes: u64,
    /// Minimum wall-clock time between checkpoint writes.
    pub checkpoint_min_interval: Duration,
    /// Override the .peel.part / .peel.ckpt anchor (defaults to the
    /// output path itself). Set this for tests that point inputs and
    /// outputs at different temp directories.
    pub workdir: Option<PathBuf>,
    /// Sleep between polls when the [`BlockingSparseReader`] is waiting
    /// on a chunk that hasn't been downloaded yet. Tests use a small
    /// value; production is fine with the default.
    pub reader_poll_interval: Duration,
    /// Force a specific decoder, looked up by name in the
    /// [`DecoderRegistry`], bypassing both suffix and magic-byte
    /// detection. Mirrors the `--format <name>` CLI flag.
    ///
    /// Useful for URLs like
    /// `https://example.com/download?id=42` where the suffix is
    /// uninformative.
    pub forced_format: Option<String>,
    /// When set, a suffix/magic disagreement is resolved in favor of
    /// the magic-byte signature (with a warning) instead of returning
    /// [`CoordinatorError::FormatMismatch`]. Mirrors the
    /// `--force-format-from-magic` CLI flag.
    ///
    /// Mutually exclusive with [`Self::forced_format`] at the CLI
    /// boundary; left to coexist here so library callers can
    /// configure either independently.
    pub force_format_from_magic: bool,
    /// Choice of file-IO backend (PLAN_v2.md §7). `Auto` (default)
    /// tries `io_uring` on Linux and falls back to blocking on
    /// failure; `Blocking` forces the pre-§7 path; `Uring` requires
    /// `io_uring` and surfaces a clean error if the kernel does not
    /// support it. Mirrors the `--io-backend` CLI flag.
    pub io_backend: crate::io_backend::IoBackendChoice,
    /// SHA-256 of the expected source bytes (`docs/PLAN_v2.md` §10).
    /// When `Some(_)`, the coordinator interposes a
    /// [`crate::hash::HashingReader`] in front of the streaming
    /// decoder, snapshots the in-flight state into every checkpoint,
    /// and verifies the finalized digest at clean completion.
    /// Mismatches are surfaced as
    /// [`CoordinatorError::Integrity`] with a friendly explanation.
    /// Mirrors the `--sha256 <hex>` CLI flag.
    ///
    /// Streaming pipeline only: ZIP archives extract per-entry and
    /// the integrity check does not extend to that path in round-one
    /// of `PLAN_v2.md`.
    pub expected_sha256: Option<[u8; crate::hash::sha256::DIGEST_LEN]>,
    /// Additional mirror URLs (`PLAN_v2.md` §13). Each mirror is
    /// expected to serve byte-identical copies of the source. The
    /// coordinator runs `HEAD` against the primary plus every mirror
    /// in parallel, drops disagreeing mirrors with a
    /// `tracing::warn!`, and routes ranged GETs across the surviving
    /// set. Empty for single-URL runs (the historical default).
    /// Mirrors the repeatable `--mirror <URL>` CLI flag.
    pub mirror_urls: Vec<String>,
    /// Aggregate bandwidth cap, in bytes/sec
    /// (`PLAN_v2.md` §14). When `Some`, the coordinator builds a
    /// shared [`crate::download::RateLimiter`] and feeds every
    /// download worker (and every mirror) through it. The cap is
    /// aggregate across mirrors per the §14 step-5 contract. Mirrors
    /// the `--max-bandwidth <RATE>` CLI flag.
    pub max_bandwidth_bps: Option<u64>,
    /// Cap on bytes downloaded but not yet consumed by the decoder.
    /// When `Some`, the scheduler stops dispatching new chunks once
    /// `bytes_downloaded - bytes_decoded_input` hits this value,
    /// resuming when the decoder catches up. This bounds the on-disk
    /// `.peel.part` footprint when the network is faster than the
    /// disk / decoder. `None` disables the throttle. Mirrors the
    /// `--max-disk-buffer <SIZE>` CLI flag (default `1 GiB`,
    /// `none` to disable).
    pub max_disk_buffer: Option<u64>,
}

impl Default for CoordinatorConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            adaptive_chunk_size: true,
            workers: DEFAULT_WORKERS,
            retry: RetryConfig::default(),
            punch_threshold: DEFAULT_PUNCH_THRESHOLD,
            checkpoint_min_bytes: 8 * 1024 * 1024,
            checkpoint_min_interval: Duration::from_secs(2),
            workdir: None,
            reader_poll_interval: Duration::from_millis(5),
            forced_format: None,
            force_format_from_magic: false,
            io_backend: crate::io_backend::IoBackendChoice::default(),
            expected_sha256: None,
            mirror_urls: Vec::new(),
            max_bandwidth_bps: None,
            max_disk_buffer: Some(DEFAULT_MAX_DISK_BUFFER),
        }
    }
}

/// Default cap for [`CoordinatorConfig::max_disk_buffer`]: 1 GiB. Big
/// enough that a decently-fast disk+decoder will rarely throttle, small
/// enough that a slow disk doesn't fill /tmp on a multi-GiB archive.
pub const DEFAULT_MAX_DISK_BUFFER: u64 = 1 << 30;

/// Caller-supplied progress callback fired periodically while [`run`]
/// is running. Errors returned here surface as
/// [`CoordinatorError::Progress`] and abort the run.
pub type ProgressFn = Box<dyn FnMut(ProgressEvent<'_>) + Send>;

/// Diagnostic events the coordinator emits during a run.
///
/// The trait-object indirection keeps the public API ergonomic for
/// callers that just want to print progress; tests pass a counting
/// closure to verify cadence.
#[derive(Debug, Clone)]
pub enum ProgressEvent<'a> {
    /// Discovery completed; the run is starting.
    Started {
        /// The source URL after redirects.
        url: &'a Url,
        /// Total source size in bytes.
        total_size: u64,
        /// True if a prior checkpoint was found and is being resumed.
        resuming: bool,
        /// Total chunks the source was sliced into.
        total_chunks: u32,
        /// Chunks already complete on entry (resume case).
        chunks_resumed: u32,
    },
    /// A checkpoint was written.
    CheckpointWritten {
        /// Source byte offset the checkpoint refers to.
        source_position: u64,
        /// Bytes the decoder has consumed so far.
        bytes_in: u64,
        /// Bytes the sink has accepted so far.
        bytes_out: u64,
    },
    /// The run finished cleanly.
    Finished {
        /// Aggregated download statistics.
        download: DownloadStats,
        /// Aggregated extraction statistics.
        extraction: ExtractionStats,
    },
}

/// Knobs the [`run`] entry point asks the caller to supply.
pub struct RunArgs {
    /// Source URL (the `peel` CLI's positional argument).
    pub url: String,
    /// Where extracted output goes.
    pub output: OutputTarget,
    /// Tunables. Pass [`CoordinatorConfig::default`] for production.
    pub config: CoordinatorConfig,
    /// HTTP client. Tests inject one configured against the mock
    /// server; the default binary just calls [`Client::new`].
    pub client: Client,
    /// Decoder registry. The default is
    /// [`DecoderRegistry::with_defaults`].
    pub registry: DecoderRegistry,
    /// Optional progress callback.
    pub progress: Option<ProgressFn>,
    /// Optional shared progress state (`PLAN_v2.md` §6). When set, the
    /// coordinator passes it down to the scheduler (workers) and
    /// extractor (sink writes) so byte-level counters update
    /// continuously. The binary's renderer thread reads from this
    /// state on its own cadence; library callers may construct one
    /// for tests or programmatic monitoring.
    pub progress_state: Option<Arc<ProgressState>>,
    /// Optional shared atomic flag. When the flag transitions to
    /// `true` between checkpoint writes, the coordinator aborts with
    /// [`CoordinatorError::Aborted`], leaving the most recently
    /// written `.peel.part` and `.peel.ckpt` durable on disk so the
    /// next invocation can resume.
    ///
    /// This is the test-side hook the §10.3 crash-test harness uses
    /// to simulate `kill -9` at random points; production callers
    /// leave it `None`.
    pub kill_switch: Option<Arc<AtomicBool>>,
    /// Optional pre-resolved IO backend. When `Some`, [`run`] uses it
    /// directly and skips its own [`crate::io_backend::select_backend`]
    /// call; when `None`, [`run`] resolves the backend from
    /// [`CoordinatorConfig::io_backend`].
    ///
    /// The `peel` binary pre-resolves in `main` so it can print the
    /// `io_backend=…` banner as plain stderr scrollback BEFORE the
    /// TTY progress renderer starts redrawing. Library callers and
    /// tests typically leave this `None`.
    pub io_backend: Option<Arc<dyn crate::io_backend::IoBackend>>,
}

/// Aggregate result of a successful [`run`].
#[derive(Debug, Clone)]
pub struct RunStats {
    /// Source URL after redirects.
    pub final_url: Url,
    /// Total source size in bytes.
    pub total_size: u64,
    /// Whether the run resumed an existing checkpoint.
    pub resumed: bool,
    /// Source byte offset the *decoder* picked up at on resume.
    /// `None` for fresh runs; `Some(offset)` when [`Self::resumed`]
    /// is `true`. `Some(0)` is possible (and harmless) if the
    /// prior run aborted before the first frame-boundary advance.
    /// Crash-resume tests use this to confirm the resume actually
    /// picked up mid-stream rather than re-running from byte 0.
    pub resume_decoder_position: Option<u64>,
    /// Whether the resume path used the format's
    /// [`crate::decode::DecoderResumeFactory`] — i.e. the prior
    /// checkpoint captured a `decoder_state` blob and the
    /// registry knows a resume hook for the format. `false` for
    /// fresh runs and for resumes from coarser frame boundaries
    /// where `decoder_state` was not captured (e.g. gzip, identity
    /// tar, zip). Crash-resume tests use this to confirm the
    /// per-block / per-chunk mid-frame restart path actually
    /// fired for formats that depend on it (lz4, zstd, xz).
    pub resume_used_decoder_state: bool,
    /// Aggregated download statistics.
    pub download: DownloadStats,
    /// Aggregated extraction statistics.
    pub extraction: ExtractionStats,
    /// Wall-clock time spent inside [`run`].
    pub elapsed: Duration,
}

/// Errors produced by [`run`].
#[derive(Debug, Error)]
pub enum CoordinatorError {
    /// The user-supplied URL did not parse.
    #[error("invalid URL {url:?}")]
    InvalidUrl {
        /// The URL the user passed.
        url: String,
        /// Underlying parse error.
        #[source]
        source: UrlError,
    },

    /// Building the HTTP client failed.
    #[error("HTTP client setup failed")]
    Client(#[source] ClientError),

    /// The download scheduler failed.
    #[error("download failed")]
    Scheduler(#[source] SchedulerError),

    /// The extractor failed.
    #[error("extraction failed")]
    Extractor(#[source] ExtractorError),

    /// A sink error surfaced before extraction started (e.g. building
    /// the resume sink failed).
    #[error("sink setup failed")]
    Sink(#[source] SinkError),

    /// Decoder factory rejected the source on construction.
    #[error("decoder construction failed")]
    Decode(#[source] DecodeError),

    /// No decoder is registered for the resolved URL's filename.
    #[error("no decoder registered for {filename:?}")]
    NoDecoder {
        /// Filename component the registry was looked up against.
        filename: String,
    },

    /// The URL's suffix and the source's magic-byte signature point at
    /// different formats. The user must disambiguate with
    /// `--format <name>` or `--force-format-from-magic`.
    #[error(
        "format detection conflict: URL suffix indicates {suffix_format:?}, magic bytes \
         indicate {magic_format:?}. Pass --format <name> to force a specific decoder \
         or --force-format-from-magic to trust the magic"
    )]
    FormatMismatch {
        /// Format name resolved from the URL's filename suffix, if any.
        suffix_format: Option<String>,
        /// Format name resolved from the magic-byte signature, if any.
        magic_format: Option<String>,
    },

    /// The user passed `--format <name>` but no decoder is registered
    /// under that name.
    #[error("unknown format {name:?}; known formats: {available:?}")]
    UnknownFormatName {
        /// The name the user passed.
        name: String,
        /// Format names the registry knows about, for the error message.
        available: Vec<String>,
    },

    /// The output URL has no usable filename component to look up a
    /// decoder by suffix.
    #[error("URL {url:?} has no filename to derive a decoder from")]
    NoFilename {
        /// The URL being inspected.
        url: String,
    },

    /// IO setting up or tearing down a coordinator-owned file.
    #[error("io error operating on {path}")]
    Io {
        /// File involved.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: io::Error,
    },

    /// The sparse output file failed an operation.
    #[error("sparse file operation failed")]
    SparseFile(#[source] SparseFileError),

    /// Reading or writing a checkpoint failed.
    #[error("checkpoint operation failed")]
    Checkpoint(#[source] CheckpointError),

    /// A checkpoint exists but its bitmap could not be deserialized.
    #[error("checkpoint bitmap is corrupt")]
    CheckpointBitmap(#[source] BitmapDecodeError),

    /// The recorded checkpoint refers to a different source than the
    /// one the user asked us to fetch — either the URL changed, the
    /// total size changed, or the ETag/Last-Modified moved.
    #[error("source identity changed since the prior checkpoint: {reason}")]
    SourceChanged {
        /// Human-readable summary of the discrepancy.
        reason: String,
    },

    /// A `.peel.ckpt` checkpoint was loaded successfully but the
    /// matching `.peel.part` sparse file is missing or smaller than
    /// the source's total size. The bitmap inside the checkpoint
    /// claims chunks complete that — without the part file's bytes
    /// — would silently be replaced with zeros if we proceeded.
    /// Refuse to resume rather than corrupt the run; the user must
    /// either restore the part file or delete both sidecars and
    /// start fresh.
    ///
    /// Common cause in container/Kubernetes setups: the `.peel.ckpt`
    /// is on a persistent volume but the `.peel.part` was on
    /// ephemeral storage and got wiped on pod restart, or vice
    /// versa. The fix is to put both sidecars in the same durable
    /// directory — see `--workdir`.
    #[error(
        "checkpoint at {ckpt_path} is present but {reason}; \
         refusing to resume from an inconsistent state. \
         Either restore the part file, or delete both sidecars to \
         start fresh."
    )]
    CheckpointPartMismatch {
        /// Path of the checkpoint file we loaded.
        ckpt_path: PathBuf,
        /// Path of the part file we expected to find next to it.
        part_path: PathBuf,
        /// Human-readable summary of the inconsistency.
        reason: String,
    },

    /// The `PLAN_v2.md` §11 resume probe re-fetched a chunk we
    /// thought was already complete and observed a CRC-32C that
    /// disagreed with the value the prior run wrote into the
    /// checkpoint. The source must have changed between runs;
    /// the user must either delete the sidecars and start fresh
    /// or aim peel at the original bytes.
    #[error(
        "source changed since the prior checkpoint: chunk {chunk} probe CRC32C \
         (expected {expected:#010x}, observed {actual:#010x}). \
         Delete .peel.part / .peel.ckpt and re-run."
    )]
    SourceChangedSinceCheckpoint {
        /// Chunk whose probe failed.
        chunk: ChunkIndex,
        /// CRC-32C the prior run recorded.
        expected: u32,
        /// CRC-32C this run just computed.
        actual: u32,
    },

    /// The on-disk bytes for the chunk holding the resume cursor
    /// don't match the CRC-32C the prior run recorded for that
    /// chunk. Distinct from
    /// [`Self::SourceChangedSinceCheckpoint`]: the upstream source
    /// is fine, but the bytes in the local `.peel.part` were either
    /// damaged at rest or were never the bytes the bitmap claimed.
    /// The decoder was about to read garbage from this region, so
    /// refusing to start beats producing a malformed-block error
    /// thousands of bytes later.
    ///
    /// Surfaced by the `PLAN_responsiveness.md` §3.1 local re-CRC
    /// audit: on resume, the chunk containing `decoder_position` is
    /// re-checksummed against the stored fingerprint. The user must
    /// either repair the part file or delete both sidecars and
    /// restart fresh.
    #[error(
        "part file corrupted at the resume cursor: chunk {chunk} on-disk CRC32C \
         (expected {expected:#010x}, observed {actual:#010x}). \
         Delete .peel.part / .peel.ckpt and re-run."
    )]
    PartFileCorrupted {
        /// Chunk that holds `decoder_position`.
        chunk: ChunkIndex,
        /// CRC-32C the prior run recorded into the checkpoint.
        expected: u32,
        /// CRC-32C re-computed from the on-disk bytes.
        actual: u32,
    },

    /// The configured chunk count overflowed `u32`.
    #[error("source too large for the configured chunk size: {chunks} chunks")]
    TooManyChunks {
        /// How many chunks the source would need.
        chunks: u64,
    },

    /// The download thread panicked.
    #[error("download thread panicked")]
    DownloadPanicked,

    /// ZIP archives can only extract into a directory; the user
    /// passed `--output-file`.
    #[error(
        "ZIP archives can only be extracted into a directory; \
         re-run with `-C <DIR>` instead of `-o <FILE>`"
    )]
    ZipNeedsDirectory,

    /// The ZIP pipeline failed.
    #[error("ZIP extraction failed")]
    Zip(#[source] ZipPipelineError),

    /// The caller's [`RunArgs::kill_switch`] flipped to `true`
    /// between checkpoint writes. The .peel.part / .peel.ckpt
    /// sidecars are intentionally left on disk so the next call
    /// resumes.
    #[error("aborted by kill switch after {checkpoints_written} checkpoints")]
    Aborted {
        /// How many checkpoint writes had already completed at the
        /// moment of the abort.
        checkpoints_written: u64,
    },

    /// Resolving the configured [`crate::io_backend::IoBackendChoice`]
    /// into a concrete backend failed (e.g. `--io-backend uring`
    /// requested on a kernel without `io_uring` support).
    #[error("io_backend setup failed")]
    IoBackend(#[source] io::Error),

    /// The `--sha256` integrity check failed: either the digest of
    /// the bytes we received did not match the user's expected
    /// digest, or the saved hash state across runs disagreed with
    /// the current invocation's flags. Per `docs/PLAN_v2.md` §10 we
    /// surface this as its own variant so the binary can give it a
    /// distinct exit code.
    #[error("integrity check failed")]
    Integrity(#[source] crate::hash::IntegrityError),
}

/// Run the full pipeline.
///
/// # Errors
///
/// Any of the [`CoordinatorError`] variants. On error the `.peel.part`
/// and `.peel.ckpt` sidecars are left on disk so the next invocation
/// resumes.
pub fn run(args: RunArgs) -> Result<RunStats, CoordinatorError> {
    let started = Instant::now();
    let RunArgs {
        url,
        output,
        config,
        client,
        registry,
        mut progress,
        progress_state,
        kill_switch,
        io_backend: pre_resolved_io_backend,
    } = args;

    let parsed_url = Url::parse(&url).map_err(|source| CoordinatorError::InvalidUrl {
        url: url.clone(),
        source,
    })?;

    // Resolve the IO backend up front. With the move to hyper, HTTP
    // sockets are opened by hyper itself; `io_backend` only governs
    // filesystem IO from here on (sparse-file writes / hole punches).
    // The `peel` binary pre-resolves in `main` (so it can banner the
    // choice as plain stderr scrollback BEFORE the TTY renderer starts
    // redrawing); library callers leave `args.io_backend` unset and
    // we fall back to `select_backend` here. Either way,
    // `select_backend` is the single place the choice is materialized
    // and where the `io_backend=…` `tracing::info!` fires.
    let io_backend = match pre_resolved_io_backend {
        Some(b) => b,
        None => {
            crate::io_backend::select_backend(config.io_backend, config.workers)
                .map_err(CoordinatorError::IoBackend)?
                .0
        }
    };

    // Parse mirror URLs up front so a malformed `--mirror` errors
    // out before any network traffic.
    let mirror_urls: Vec<Url> = config
        .mirror_urls
        .iter()
        .map(|s| {
            Url::parse(s).map_err(|source| CoordinatorError::InvalidUrl {
                url: s.clone(),
                source,
            })
        })
        .collect::<Result<_, _>>()?;

    let (info, mirror_set, dropped_mirrors) = discover_with_mirrors(
        &client,
        &parsed_url,
        &mirror_urls,
        config.expected_sha256.is_some(),
    )
    .map_err(CoordinatorError::Scheduler)?;
    let mirror_set = Arc::new(mirror_set);
    let _ = dropped_mirrors; // surfaced via tracing::warn! inside discover_with_mirrors

    let part_path = sidecar_path(&output, &config, ".peel.part");
    let ckpt_path = sidecar_path(&output, &config, ".peel.ckpt");

    ensure_parent_dir(&part_path)?;
    ensure_parent_dir(&ckpt_path)?;
    if let OutputTarget::Dir(d) = &output {
        fs::create_dir_all(d).map_err(|source| CoordinatorError::Io {
            path: d.clone(),
            source,
        })?;
    }

    let prior = Checkpoint::read(&ckpt_path).map_err(CoordinatorError::Checkpoint)?;
    if prior.is_some() {
        // A checkpoint exists — refuse to silently fall back to a
        // fresh-zero part file. `open_sparse` would otherwise CREAT
        // and `set_len` the part to `total_size`, leaving the bitmap's
        // claim of complete chunks pointing at zero bytes. The §11
        // probe catches the resulting CRC drift later, but with a
        // misleading "source changed" message; this earlier check
        // surfaces the real cause (sidecars out of sync) up front.
        validate_part_file(&ckpt_path, &part_path, info.total_size)?;
    }
    let resume_plan = build_resume_plan(prior.as_ref(), &info, &url, &config, &output)?;
    let resuming = matches!(resume_plan, ResumePlan::Resume { .. });
    let resume_decoder_position = match &resume_plan {
        ResumePlan::Fresh => None,
        ResumePlan::Resume {
            decoder_position, ..
        } => Some(*decoder_position),
    };

    let total_chunks = chunk_count(info.total_size, config.chunk_size).map_err(|e| match e {
        SchedulerError::TooManyChunks { chunks, .. } => CoordinatorError::TooManyChunks { chunks },
        other => CoordinatorError::Scheduler(other),
    })?;

    // Build the bitmap. If we're resuming, repopulate it from the
    // checkpoint's serialized form; otherwise start empty.
    let bitmap = match &resume_plan {
        ResumePlan::Fresh => Arc::new(ChunkBitmap::new(total_chunks)),
        ResumePlan::Resume { bitmap_bytes, .. } => Arc::new(
            ChunkBitmap::from_bytes(total_chunks, bitmap_bytes)
                .map_err(CoordinatorError::CheckpointBitmap)?,
        ),
    };

    let chunks_resumed = u32::try_from(bitmap.count_complete()).unwrap_or(u32::MAX);

    // Startup banner: log what peel decided about the sidecars and
    // where it's reading them from. Visible in `kubectl logs` and
    // any other non-TTY environment so operators can confirm at a
    // glance whether resume is engaging — the symptom of a wiped PV
    // or a path mismatch is "[fresh]" appearing on every run.
    match resume_decoder_position {
        Some(pos) => tracing::info!(
            "[resume] checkpoint at {} part={} decoder_position={} chunks={}/{}",
            ckpt_path.display(),
            part_path.display(),
            pos,
            chunks_resumed,
            total_chunks,
        ),
        None => tracing::info!(
            "[fresh] no checkpoint at {} — starting from byte 0",
            ckpt_path.display(),
        ),
    }

    // §11 per-chunk CRC-32C fingerprint store. Pre-populated from
    // the prior checkpoint when resuming a v4 run; an empty store
    // when starting fresh or resuming a pre-§11 checkpoint.
    let fingerprints = Arc::new(build_fingerprints(total_chunks, &resume_plan)?);

    let sparse = Arc::new(open_sparse(
        &part_path,
        info.total_size,
        &config,
        &io_backend,
    )?);

    // §11 resume verification: when resuming with non-empty
    // per-chunk fingerprints, pick a random already-complete chunk
    // and re-fetch it. Mismatch ⇒ `SourceChangedSinceCheckpoint`.
    if matches!(resume_plan, ResumePlan::Resume { .. }) && bitmap.count_complete() > 0 {
        run_resume_probe(
            &client,
            &info,
            &sparse,
            &bitmap,
            &fingerprints,
            config.chunk_size,
            &config.retry,
        )?;
    }

    // §3.1 (PLAN_responsiveness.md): local re-CRC audit of the chunk
    // holding the resume cursor. Distinct from the §11 server-side
    // probe above: this catches *on-disk* corruption (bit flips at
    // rest, a stray write that landed in the part file, an io_uring
    // reorder hazard) that the server probe would silently miss.
    // The chunk containing `decoder_position` is the one the decoder
    // is about to read, so it's the one whose corruption would
    // manifest as the malformed-block error documented in the plan.
    if let ResumePlan::Resume {
        decoder_position, ..
    } = &resume_plan
    {
        run_cursor_chunk_audit(
            &sparse,
            &bitmap,
            &fingerprints,
            config.chunk_size,
            info.total_size,
            *decoder_position,
        )?;
    }

    let cursor = Arc::new(AtomicU64::new(match &resume_plan {
        ResumePlan::Fresh => 0,
        ResumePlan::Resume {
            decoder_position, ..
        } => *decoder_position,
    }));

    if let Some(state) = progress_state.as_ref() {
        state.set_total_size(info.total_size);
        // Pre-credit the resumed bytes so the renderer's progress bar
        // doesn't snap from 0% on the first tick of a resume.
        let resumed_bytes = u64::from(chunks_resumed).saturating_mul(config.chunk_size);
        let resumed_bytes = resumed_bytes.min(info.total_size);
        state.add_downloaded(resumed_bytes);
        // Pre-credit the resumed *extracted* count too: the sink's
        // checkpointed state already records what was written through
        // it, so the renderer should not rewind to 0 just because the
        // current process hasn't yet decoded anything. Without this,
        // a resumed run shows a download counter advancing at full
        // (cumulative) speed against an extract counter that just
        // restarted, which looks wrong even when nothing is broken.
        if let ResumePlan::Resume { sink_state, .. } = &resume_plan {
            let resumed_extracted = match sink_state {
                SinkState::Raw { bytes_written } => *bytes_written,
                SinkState::Tar {
                    in_flight: Some(s), ..
                } => s.archive_offset,
                SinkState::Tar {
                    in_flight: None, ..
                } => 0,
                // ZIP entries are byte-counted by the zip pipeline
                // separately; pre-crediting from here would require
                // re-reading entry sizes the resume plan doesn't carry.
                SinkState::Zip { .. } => 0,
            };
            state.add_extracted(resumed_extracted);
        }
        state.mark_started();
    }

    if let Some(cb) = progress.as_mut() {
        cb(ProgressEvent::Started {
            url: &info.url,
            total_size: info.total_size,
            resuming,
            total_chunks,
            chunks_resumed,
        });
    }

    let policy = if config.adaptive_chunk_size {
        Some(Arc::new(crate::download::ChunkSizePolicy::new(
            config.chunk_size,
            crate::download::DEFAULT_INITIAL_DISPATCH_BYTES,
        )))
    } else {
        None
    };

    // Aggregate bandwidth limiter (`PLAN_v2.md` §14). Constructed once
    // from the user-provided rate and shared across every worker and
    // every mirror so the cap is aggregate, not per-mirror. `None`
    // disables limiting (the historical default).
    let rate_limiter = config
        .max_bandwidth_bps
        .map(|bps| Arc::new(crate::download::RateLimiter::new(bps)));

    // External abort signal handed to the scheduler. Two callers
    // flip it: (a) the `CancelOnDrop` guard below, when the extraction
    // closure exits via an error path; (b) the run-wide kill switch
    // wired by `main` (SIGINT / SIGTERM). Wiring both into the same
    // `Arc` means a kubelet SIGTERM aborts download workers in
    // parallel with the extraction unwind — without it, the scheduler
    // would only stop after the reader returned the kill sentinel,
    // the extractor propagated it, and `CancelOnDrop` flipped a
    // separate flag. The previous arrangement turned a "stop now"
    // signal into a multi-stage relay race that could still leave
    // workers chugging on in-flight chunks well into the pod's
    // grace period.
    //
    // CancelOnDrop on a non-kill-switch failure path now also flips
    // the user-supplied kill_switch by virtue of sharing the Arc.
    // That is harmless: by the time CancelOnDrop fires the run is
    // already returning Err; the only kill_switch readers
    // (BlockingSparseReader, sniff_prefix, the extractor inner loop)
    // have either already returned or will not be called again.
    let download_abort = kill_switch
        .clone()
        .unwrap_or_else(|| Arc::new(AtomicBool::new(false)));

    let scheduler_cfg = SchedulerConfig {
        chunk_size: config.chunk_size,
        workers: config.workers,
        retry: config.retry.clone(),
        progress: progress_state.clone(),
        policy,
        fingerprints: Some(Arc::clone(&fingerprints)),
        probe: ProbeConfig::default(),
        mirrors: Some(Arc::clone(&mirror_set)),
        rate_limiter: rate_limiter.clone(),
        max_disk_buffer: config.max_disk_buffer,
        abort: Some(Arc::clone(&download_abort)),
    };

    let download_done = Arc::new(AtomicBool::new(false));
    let download_outcome: Arc<Mutex<Option<Result<DownloadStats, SchedulerError>>>> =
        Arc::new(Mutex::new(None));

    let total_size = info.total_size;
    let chunk_size = config.chunk_size;

    // Set inside the scoped thread when the decoder dispatch
    // picks the resume_factory branch (a `decoder_state` blob was
    // captured by the prior run AND a registered format hook
    // accepts it). Read after the thread joins so
    // [`RunStats::resume_used_decoder_state`] is populated.
    let used_decoder_state_flag = Arc::new(AtomicBool::new(false));

    let extraction_outcome =
        thread::scope(|scope| -> Result<ExtractionOutcome, CoordinatorError> {
            let used_decoder_state_flag = Arc::clone(&used_decoder_state_flag);
            // Drop guard: any path out of this closure that does not
            // explicitly disarm the guard (notably every `?` that
            // propagates an error from extraction or format detection)
            // flips the abort flag before scope's implicit join begins,
            // so the download thread tears down promptly instead of
            // running to completion. The Ok path calls
            // `disarm_cancel_guard` just before returning.
            let cancel_guard = CancelOnDrop::new(&download_abort);

            // Spawn the download thread.
            let dl_done = Arc::clone(&download_done);
            let dl_outcome = Arc::clone(&download_outcome);
            let dl_sparse = Arc::clone(&sparse);
            let dl_bitmap = Arc::clone(&bitmap);
            let dl_cursor = Arc::clone(&cursor);
            let dl_info = info.clone();
            let dl_client = client.clone();
            let dl_cfg = scheduler_cfg.clone();
            let dl_handle = thread::Builder::new()
                .name("peel-download-scheduler".into())
                .spawn_scoped(scope, move || {
                    let result = run_scheduler(
                        &dl_client, &dl_info, &dl_sparse, &dl_bitmap, &dl_cursor, &dl_cfg,
                    );
                    if let Ok(mut slot) = dl_outcome.lock() {
                        *slot = Some(result);
                    }
                    dl_done.store(true, Ordering::Release);
                })
                .map_err(|source| CoordinatorError::Io {
                    path: PathBuf::from("<spawn-download>"),
                    source,
                })?;

            // Resolve the decoder factory before constructing the
            // reader. Detection may need to wait for chunk 0 to land
            // so the magic-byte sniff has bytes to look at; doing it
            // here keeps the BlockingSparseReader from owning that
            // wait.
            let factory = select_decoder_factory(
                &registry,
                &info,
                &config,
                &sparse,
                &bitmap,
                &download_done,
                &download_outcome,
                kill_switch.as_ref(),
            )?;

            // Look up the resolved factory's name to decide which
            // pipeline to drive. ZIP archives go through the
            // per-entry pipeline; everything else goes through the
            // streaming decoder loop. The name lookup is reverse-
            // resolved by fn-pointer identity, which works for the
            // free-function factories every shipping format uses.
            let format_name = registry.name_for_factory(factory).map(String::from);
            let is_zip = format_name.as_deref() == Some(ZIP_FORMAT_NAME);

            let puncher: Box<dyn PunchHole> = make_puncher(&sparse);

            let extraction_stats = if is_zip {
                let dir = match &output {
                    OutputTarget::Dir(d) => d.clone(),
                    OutputTarget::File(_) => {
                        return Err(CoordinatorError::ZipNeedsDirectory);
                    }
                };
                run_zip(
                    &sparse,
                    &bitmap,
                    &fingerprints,
                    &cursor,
                    &download_done,
                    &download_outcome,
                    puncher.as_ref(),
                    &ckpt_path,
                    &info,
                    &url,
                    chunk_size,
                    total_size,
                    &dir,
                    &resume_plan,
                    &config,
                    progress.as_mut(),
                    progress_state.as_ref(),
                    kill_switch.as_ref(),
                )?
            } else {
                // Resolve the integrity-tracking hasher (if any) up
                // front: if --sha256 is on, build it from prior
                // hash_state (resume) or fresh, and skip the bytes
                // that were already hashed past `decoder_position`.
                // The same hasher is fed by the HashingReader and
                // snapshot by the checkpoint observer (`PLAN_v2.md`
                // §10 step 4).
                let reader_start = cursor.load(Ordering::Acquire);
                let hasher_setup = build_integrity_hasher(
                    config.expected_sha256.as_ref(),
                    prior.as_ref(),
                    &ckpt_path,
                    reader_start,
                )?;
                let reader = BlockingSparseReader::new(
                    Arc::clone(&sparse),
                    Arc::clone(&bitmap),
                    chunk_size,
                    total_size,
                    reader_start,
                    Arc::clone(&download_done),
                    Arc::clone(&download_outcome),
                    config.reader_poll_interval,
                );
                let reader = match progress_state.clone() {
                    Some(state) => reader.with_progress(state),
                    None => reader,
                };
                // §2.1: thread the run-wide kill switch into the reader
                // so a tripped flag short-circuits the source-read poll.
                let reader = match kill_switch.clone() {
                    Some(flag) => reader.with_kill_switch(flag),
                    None => reader,
                };

                // Interpose a HashingReader between the source and
                // the decoder when integrity tracking is on.
                let source: Box<dyn std::io::Read + Send> = match &hasher_setup {
                    Some(setup) => Box::new(crate::hash::HashingReader::with_skip(
                        Box::new(reader),
                        Arc::clone(&setup.hasher),
                        setup.skip_remaining,
                    )),
                    None => Box::new(reader),
                };
                // O.7b resume path: when the prior checkpoint
                // captured a decoder-private `decoder_state` blob and
                // the registry knows a resume factory for the
                // resolved format, build the decoder pre-seeded from
                // the blob instead of via the generic `factory`.
                // Falls through to `factory(source)` for
                // (a) fresh runs, (b) resume from a coarser
                // boundary where `decoder_state` is `None`, and
                // (c) formats with no resume hook registered.
                let resume_blob = match &resume_plan {
                    ResumePlan::Resume {
                        decoder_state: Some(blob),
                        decoder_position,
                        ..
                    } => Some((blob.clone(), *decoder_position)),
                    _ => None,
                };
                let resume_factory = format_name
                    .as_deref()
                    .and_then(|n| registry.resume_factory_for_name(n));
                let (mut decoder, used_decoder_state) = match (resume_factory, resume_blob) {
                    (Some(rf), Some((blob, start_offset))) => (
                        rf(source, &blob, start_offset).map_err(CoordinatorError::Decode)?,
                        true,
                    ),
                    _ => (factory(source).map_err(CoordinatorError::Decode)?, false),
                };
                used_decoder_state_flag.store(used_decoder_state, Ordering::Relaxed);

                // Run the extractor with a checkpoint observer that
                // writes a durable checkpoint every time the cadence
                // floor fires.
                let extractor = {
                    let base = Extractor::new(ExtractorConfig {
                        punch_threshold: config.punch_threshold,
                    });
                    let base = match progress_state.clone() {
                        Some(state) => base.with_progress(state),
                        None => base,
                    };
                    // §2.3: attach the kill switch so the extractor
                    // polls it once per decode_step iteration even when
                    // the decoder isn't reading source.
                    match kill_switch.clone() {
                        Some(flag) => base.with_kill_switch(flag),
                        None => base,
                    }
                };

                let hasher_handle = hasher_setup.as_ref().map(|s| Arc::clone(&s.hasher));
                let stats = match &output {
                    OutputTarget::File(path) => {
                        let sink = build_raw_sink(path, &resume_plan)?;
                        run_one(
                            &extractor,
                            &sparse,
                            &mut *decoder,
                            sink,
                            puncher.as_ref(),
                            &ckpt_path,
                            &part_path,
                            &info,
                            &url,
                            &bitmap,
                            &fingerprints,
                            chunk_size,
                            &config,
                            progress.as_mut(),
                            kill_switch.as_ref(),
                            hasher_handle.as_ref(),
                        )?
                    }
                    OutputTarget::Dir(path) => {
                        let sink = build_tar_sink(path, &resume_plan)?;
                        run_one(
                            &extractor,
                            &sparse,
                            &mut *decoder,
                            sink,
                            puncher.as_ref(),
                            &ckpt_path,
                            &part_path,
                            &info,
                            &url,
                            &bitmap,
                            &fingerprints,
                            chunk_size,
                            &config,
                            progress.as_mut(),
                            kill_switch.as_ref(),
                            hasher_handle.as_ref(),
                        )?
                    }
                };

                // Drop the decoder before finalizing the hasher: the
                // decoder owns the HashingReader, which holds a
                // clone of the SharedHasher. Dropping it releases
                // any buffered bytes still in the BufReader through
                // to the hasher (they were already counted) and
                // releases that Arc reference.
                drop(decoder);

                if let (Some(setup), Some(expected)) =
                    (hasher_setup, config.expected_sha256.as_ref())
                {
                    let inner = match Arc::try_unwrap(setup.hasher) {
                        Ok(mutex) => mutex.into_inner().map_err(|_| {
                            CoordinatorError::IoBackend(io::Error::other(
                                "hasher mutex poisoned at finalize",
                            ))
                        })?,
                        Err(arc) => {
                            // Defensive: someone else still holds
                            // the Arc. Clone the state, drop the
                            // outer reference, and finalize the
                            // clone. Functionally equivalent.
                            let snapshot = arc
                                .lock()
                                .map_err(|_| {
                                    CoordinatorError::IoBackend(io::Error::other(
                                        "hasher mutex poisoned at finalize",
                                    ))
                                })?
                                .clone();
                            snapshot
                        }
                    };
                    let computed = inner.finalize();
                    crate::hash::verify_digest(expected, &computed)
                        .map_err(CoordinatorError::Integrity)?;
                }

                stats
            };

            // Wait for the download thread to drain. By the time the
            // extractor reaches EOF, the bitmap is fully populated and
            // workers are exiting.
            dl_handle
                .join()
                .map_err(|_| CoordinatorError::DownloadPanicked)?;
            let download_stats = match download_outcome.lock() {
                Ok(mut slot) => slot.take(),
                Err(_) => None,
            };
            let download_stats = match download_stats {
                Some(Ok(s)) => s,
                Some(Err(e)) => return Err(CoordinatorError::Scheduler(e)),
                None => DownloadStats::default(),
            };

            // Extraction completed cleanly. The download thread is
            // already drained (`dl_handle.join` above); disarm so the
            // guard's Drop does not flip the abort flag we no longer
            // need.
            cancel_guard.disarm();

            Ok(ExtractionOutcome {
                extraction: extraction_stats,
                download: download_stats,
                used_decoder_state: used_decoder_state_flag.load(Ordering::Relaxed),
            })
        })?;

    // Drop the sparse file so the puncher's borrowed fd is no longer
    // alive, then delete the sidecars.
    drop(sparse);
    fs::remove_file(&part_path).ok();
    fs::remove_file(&ckpt_path).ok();
    fs::remove_file(crate::checkpoint::tmp_path_for(&ckpt_path)).ok();

    let outcome = RunStats {
        final_url: info.url,
        total_size: info.total_size,
        resumed: resuming,
        resume_decoder_position,
        resume_used_decoder_state: extraction_outcome.used_decoder_state,
        download: extraction_outcome.download.clone(),
        extraction: extraction_outcome.extraction,
        elapsed: started.elapsed(),
    };

    if let Some(cb) = progress.as_mut() {
        cb(ProgressEvent::Finished {
            download: outcome.download.clone(),
            extraction: outcome.extraction,
        });
    }

    Ok(outcome)
}

/// Internal: ferry the two stats blobs out of the scoped thread block.
struct ExtractionOutcome {
    extraction: ExtractionStats,
    download: DownloadStats,
    /// `true` if the decoder dispatch picked the resume_factory
    /// branch (a `decoder_state` blob was both captured by the
    /// prior run AND consumable by a registered format hook).
    /// Ferried through so [`RunStats::resume_used_decoder_state`]
    /// can be populated.
    used_decoder_state: bool,
}

/// Drop guard that flips an [`AtomicBool`] to `true` on drop unless
/// disarmed. Used inside [`run`]'s `thread::scope` closure so any
/// error path out of the closure (the many `?` propagations through
/// extraction and format detection) cancels the download thread
/// before scope's implicit join begins. Without this, an extractor
/// error would leave scope blocked until the entire archive was
/// downloaded — a 444 GiB / 1 MB-s combination would look like a
/// multi-day hang to the user.
struct CancelOnDrop<'a> {
    flag: &'a AtomicBool,
    armed: bool,
}

impl<'a> CancelOnDrop<'a> {
    fn new(flag: &'a AtomicBool) -> Self {
        Self { flag, armed: true }
    }

    /// Consume the guard without flipping the flag. Call on the Ok
    /// path once download cancellation is no longer wanted.
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for CancelOnDrop<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.flag.store(true, Ordering::Release);
        }
    }
}

/// What [`build_resume_plan`] decides to do with a prior checkpoint.
///
/// The `Resume` variant grew larger once `SinkState::Tar` started
/// carrying in-flight parser state in v6 (a few hundred bytes).
/// Boxing the variant would force every pattern match to deref the
/// box; we construct one [`ResumePlan`] per run and match it a
/// handful of times, so the allocation isn't worth the syntactic
/// noise. The lint is silenced locally with rationale.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum ResumePlan {
    Fresh,
    Resume {
        decoder_position: u64,
        bitmap_bytes: Vec<u8>,
        sink_state: SinkState,
        chunk_crc32c: Option<Vec<u32>>,
        /// Decoder-private resume state captured at the same step
        /// as `decoder_position` (`OPTIMIZATIONS.md` §O.7b). `Some`
        /// for lz4 mid-frame block boundaries; `None` for every
        /// other format and for every coarser boundary.
        decoder_state: Option<Vec<u8>>,
    },
}

/// Decide whether to resume off `prior` or start fresh.
fn build_resume_plan(
    prior: Option<&Checkpoint>,
    info: &DownloadInfo,
    requested_url: &str,
    config: &CoordinatorConfig,
    output: &OutputTarget,
) -> Result<ResumePlan, CoordinatorError> {
    let Some(prior) = prior else {
        return Ok(ResumePlan::Fresh);
    };

    if prior.url != requested_url && prior.url != info.url.to_string() {
        return Err(CoordinatorError::SourceChanged {
            reason: format!(
                "checkpoint URL was {:?}, current request is {:?}",
                prior.url, requested_url
            ),
        });
    }
    if prior.total_size != info.total_size {
        return Err(CoordinatorError::SourceChanged {
            reason: format!(
                "checkpoint total_size was {}, current source is {}",
                prior.total_size, info.total_size
            ),
        });
    }
    if prior.chunk_size != config.chunk_size {
        return Err(CoordinatorError::SourceChanged {
            reason: format!(
                "checkpoint chunk_size was {}, current chunk_size is {}",
                prior.chunk_size, config.chunk_size
            ),
        });
    }
    if !fingerprint_matches(prior, &info.fingerprint) {
        return Err(CoordinatorError::SourceChanged {
            reason: format!(
                "ETag/Last-Modified changed (was etag={:?} last_modified={:?}, \
                 now etag={:?} last_modified={:?})",
                prior.etag,
                prior.last_modified,
                info.fingerprint.etag,
                info.fingerprint.last_modified,
            ),
        });
    }
    let sink_compat = matches!(
        (output, &prior.sink_state),
        (OutputTarget::File(_), SinkState::Raw { .. })
            | (OutputTarget::Dir(_), SinkState::Tar { .. })
            | (OutputTarget::Dir(_), SinkState::Zip { .. })
    );
    if !sink_compat {
        return Err(CoordinatorError::SourceChanged {
            reason: "checkpoint sink type does not match the requested output".into(),
        });
    }
    Ok(ResumePlan::Resume {
        decoder_position: prior.decoder_position.get(),
        bitmap_bytes: prior.bitmap_completed.clone(),
        sink_state: prior.sink_state.clone(),
        chunk_crc32c: prior.chunk_crc32c.clone(),
        decoder_state: prior.decoder_state.clone(),
    })
}

fn fingerprint_matches(prior: &Checkpoint, fingerprint: &SourceFingerprint) -> bool {
    if let (Some(a), Some(b)) = (&prior.etag, &fingerprint.etag) {
        // Weak ETags only promise semantic equivalence (RFC 7232
        // §2.3); a weak-tag mismatch is advisory because §11's
        // per-chunk CRC-32C probe runs right after this and gives
        // us a real byte-level guard. Treating weak mismatches as
        // a hard error here would force users to re-download for
        // upstream cache normalization that didn't actually change
        // the bytes.
        if a != b
            && !crate::download::worker::etag_is_weak(a)
            && !crate::download::worker::etag_is_weak(b)
        {
            return false;
        }
    }
    if let (Some(a), Some(b)) = (&prior.last_modified, &fingerprint.last_modified) {
        if a != b {
            return false;
        }
    }
    // If neither side carries an identifier we fall through and accept
    // the resume; we cannot prove the source unchanged but neither can
    // a fresh `HEAD`, so the only honest move is to take the user's
    // request at face value. The §11 resume probe will catch any
    // genuine byte drift before we accept the bitmap.
    true
}

/// Internal: build the RawSink for either fresh or resumed mode.
fn build_raw_sink(path: &Path, plan: &ResumePlan) -> Result<RawSink, CoordinatorError> {
    let sink = match plan {
        ResumePlan::Fresh => RawSink::create(path).map_err(CoordinatorError::Sink)?,
        ResumePlan::Resume { sink_state, .. } => {
            let SinkState::Raw { bytes_written } = sink_state else {
                return Err(CoordinatorError::SourceChanged {
                    reason: "checkpoint sink_state is Tar but output is a File".into(),
                });
            };
            RawSink::resume(path, *bytes_written).map_err(CoordinatorError::Sink)?
        }
    };
    Ok(sink)
}

/// Internal: build the TarSink for either fresh or resumed mode.
///
/// Fresh runs and resumes from a coarser boundary (sink state
/// without `in_flight`) construct via [`TarSink::new`]: the decoded
/// byte stream picks up at a member boundary and the parser starts
/// at a 0-filled header buffer.
///
/// Resumes carrying a v6 [`crate::checkpoint::TarSinkState`] —
/// captured by [`crate::sink::Sink::sink_state`] at any decoder
/// block boundary, including mid-member ones — go through
/// [`TarSink::resume`], which reopens the in-flight file at the
/// already-written offset and seeds the parser state directly.
fn build_tar_sink(path: &Path, plan: &ResumePlan) -> Result<TarSink, CoordinatorError> {
    if let ResumePlan::Resume {
        sink_state: SinkState::Tar {
            in_flight: Some(state),
            ..
        },
        ..
    } = plan
    {
        return TarSink::resume(path, state).map_err(CoordinatorError::Sink);
    }
    TarSink::new(path).map_err(CoordinatorError::Sink)
}

/// Internal: drive the extractor with a checkpoint-writing observer.
#[allow(clippy::too_many_arguments)]
fn run_one<S: Sink>(
    extractor: &Extractor,
    sparse: &SparseFile,
    decoder: &mut dyn StreamingDecoder,
    sink: S,
    puncher: &dyn PunchHole,
    ckpt_path: &Path,
    part_path: &Path,
    info: &DownloadInfo,
    requested_url: &str,
    bitmap: &ChunkBitmap,
    fingerprints: &ChunkFingerprints,
    chunk_size: u64,
    config: &CoordinatorConfig,
    progress: Option<&mut ProgressFn>,
    kill_switch: Option<&Arc<AtomicBool>>,
    hasher_for_ckpt: Option<&crate::hash::SharedHasher>,
) -> Result<ExtractionStats, CoordinatorError> {
    let mut last_write_at = Instant::now()
        .checked_sub(config.checkpoint_min_interval)
        .unwrap_or_else(Instant::now);
    let mut last_position: u64 = 0;
    let mut progress_inner = progress;
    let mut checkpoints_written: u64 = 0;

    let result = extractor.extract_with_callback(
        sparse.as_fd(),
        decoder,
        sink,
        puncher,
        |info_cb: CheckpointInfo| -> io::Result<CheckpointAck> {
            // Throttle: write at most once per cadence floor. A
            // throttled call is reported back to the extractor as
            // `Throttled` so it does not advance hole-punching past
            // the most recently *persisted* position — punching past
            // a non-persisted boundary would otherwise zero the
            // bytes the still-current durable checkpoint references
            // and break resume.
            let elapsed = last_write_at.elapsed();
            let progressed = info_cb.source_position.saturating_sub(last_position);
            if progressed < config.checkpoint_min_bytes && elapsed < config.checkpoint_min_interval
            {
                return Ok(CheckpointAck::Throttled);
            }

            // Crash-test hook. We test the kill switch *before*
            // writing so the count of durable checkpoints exactly
            // matches the value the caller observed.
            if let Some(flag) = kill_switch {
                if flag.load(Ordering::Acquire) {
                    return Err(io::Error::other(KILL_SENTINEL));
                }
            }

            // Flush the sparse file's pending writes so the bitmap's
            // claim of "this chunk is durable" is honest. This is
            // best-effort; a failure here surfaces to the extractor as
            // an Observer error.
            sparse
                .sync_all()
                .map_err(|e| io::Error::other(format!("sparse sync_all: {e}")))?;

            let sink_state = info_cb.sink_state.clone();
            let hash_state = snapshot_hash_state(hasher_for_ckpt);
            let chunk_crc32c = if fingerprints.is_empty() {
                None
            } else {
                Some(fingerprints.to_vec())
            };
            let ckpt = Checkpoint {
                url: requested_url.to_string(),
                etag: info.fingerprint.etag.clone(),
                last_modified: info.fingerprint.last_modified.clone(),
                total_size: info.total_size,
                chunk_size,
                decoder_position: ByteOffset::new(info_cb.source_position),
                bitmap_completed: bitmap.to_bytes(),
                created_at: SystemTime::now(),
                sink_state,
                hash_state,
                chunk_crc32c,
                decoder_state: info_cb.decoder_state.clone(),
            };
            ckpt.write(ckpt_path)
                .map_err(|e| io::Error::other(format!("checkpoint write: {e}")))?;

            last_write_at = Instant::now();
            last_position = info_cb.source_position;
            checkpoints_written = checkpoints_written.saturating_add(1);
            if let Some(cb) = progress_inner.as_deref_mut() {
                cb(ProgressEvent::CheckpointWritten {
                    source_position: info_cb.source_position,
                    bytes_in: info_cb.bytes_in,
                    bytes_out: info_cb.bytes_out,
                });
            }
            Ok(CheckpointAck::Persisted)
        },
    );

    // Avoid unused-variable warnings even when no `Err` path runs.
    let _ = part_path;
    match result {
        Ok(stats) => Ok(stats),
        Err(ExtractorError::Observer(e)) if e.to_string() == KILL_SENTINEL => {
            Err(CoordinatorError::Aborted {
                checkpoints_written,
            })
        }
        // §2.1: a kill-switch trip inside `BlockingSparseReader::read`
        // (or anywhere else inside the decoder's source-read path)
        // surfaces as `DecodeError::Read` carrying our sentinel. Match
        // it so the operator gets `Aborted` instead of an apparent
        // decode failure.
        Err(ExtractorError::Decode(DecodeError::Read { source, .. }))
            if source.to_string() == KILL_SENTINEL =>
        {
            Err(CoordinatorError::Aborted {
                checkpoints_written,
            })
        }
        Err(other) => Err(CoordinatorError::Extractor(other)),
    }
}

/// Drive the ZIP per-entry pipeline with a checkpoint-writing
/// observer.
///
/// Mirrors [`run_one`]'s shape: same checkpoint cadence
/// (`checkpoint_min_bytes` / `checkpoint_min_interval`), same
/// kill-switch handling, same [`ProgressEvent::CheckpointWritten`]
/// emission. The differences are mechanical — the pipeline runs
/// per-entry rather than per-frame, and the checkpoint records
/// [`SinkState::Zip`] instead of `Tar` / `Raw`.
#[allow(clippy::too_many_arguments)]
fn run_zip(
    sparse: &SparseFile,
    bitmap: &ChunkBitmap,
    fingerprints: &ChunkFingerprints,
    cursor: &Arc<AtomicU64>,
    download_done: &Arc<AtomicBool>,
    download_outcome: &Arc<Mutex<Option<Result<DownloadStats, SchedulerError>>>>,
    puncher: &dyn PunchHole,
    ckpt_path: &Path,
    info: &DownloadInfo,
    requested_url: &str,
    chunk_size: u64,
    total_size: u64,
    output_dir: &Path,
    plan: &ResumePlan,
    config: &CoordinatorConfig,
    mut progress: Option<&mut ProgressFn>,
    progress_state: Option<&Arc<ProgressState>>,
    kill_switch: Option<&Arc<AtomicBool>>,
) -> Result<ExtractionStats, CoordinatorError> {
    fs::create_dir_all(output_dir).map_err(|source| CoordinatorError::Io {
        path: output_dir.to_path_buf(),
        source,
    })?;
    let mut sink = ZipSink::new(output_dir).map_err(CoordinatorError::Sink)?;

    // Translate the resume plan into the ZIP-specific shape.
    let resume = match plan {
        ResumePlan::Fresh => ZipResumeState::default(),
        ResumePlan::Resume { sink_state, .. } => match sink_state {
            SinkState::Zip {
                entries_completed,
                current_entry,
                current_entry_offset,
            } => ZipResumeState {
                entries_completed: entries_completed.clone(),
                current_entry: *current_entry,
                current_entry_offset: *current_entry_offset,
            },
            SinkState::Raw { .. } | SinkState::Tar { .. } => {
                return Err(CoordinatorError::SourceChanged {
                    reason: "checkpoint sink_state is not Zip but the resolved format is zip"
                        .into(),
                });
            }
        },
    };

    let pipeline_cfg = ZipPipelineConfig {
        total_size,
        chunk_size,
        poll_interval: config.reader_poll_interval,
        initial_tail_window: crate::zip::MAX_EOCD_TAIL_BYTES.min(total_size),
    };
    let pipeline = ZipPipeline {
        config: pipeline_cfg,
        sparse,
        bitmap,
        cursor,
        download_done,
        download_outcome,
        sparse_fd: sparse.as_fd(),
    };

    // Disable the disk-buffer throttle for the ZIP path. ZIP is
    // random-access (the pipeline jumps to the EOCD, then to each
    // entry's LFH), so the streaming "lookahead = downloaded -
    // decoded" metric the scheduler uses does not apply: the entire
    // archive is effectively "downloaded ahead of the cursor" but
    // none of it is wasted, since the pipeline will read from any
    // chunk the bitmap reports complete. Override the live cap to 0
    // (= disabled) for the duration of this run.
    if let Some(p) = progress_state {
        p.set_max_disk_buffer(0);
    }

    // Checkpoint cadence state, mirroring `run_one`.
    let mut last_write_at = Instant::now()
        .checked_sub(config.checkpoint_min_interval)
        .unwrap_or_else(Instant::now);
    let mut last_progress: u64 = 0;
    let mut bytes_extracted_total: u64 = 0;
    let mut bytes_punched_total: u64 = 0;
    let mut entries_completed: Vec<u32> = resume.entries_completed.clone();
    let mut entries_extracted_this_run: u64 = 0;
    let mut checkpoints_written: u64 = 0;

    let result = pipeline.run(&mut sink, puncher, resume, |event| -> io::Result<()> {
        // Kill-switch fires before any state mutation so the
        // user-observable "checkpoint count" matches what's durable
        // on disk.
        if let Some(flag) = kill_switch {
            if flag.load(Ordering::Acquire) {
                return Err(io::Error::other(KILL_SENTINEL));
            }
        }
        match event {
            ZipPipelineEvent::Started { .. } | ZipPipelineEvent::InEntryProgress { .. } => Ok(()),
            ZipPipelineEvent::EntryFinished {
                index,
                bytes_written,
                bytes_punched,
                ..
            } => {
                entries_completed.push(*index);
                bytes_extracted_total = bytes_extracted_total.saturating_add(*bytes_written);
                bytes_punched_total = bytes_punched_total.saturating_add(*bytes_punched);
                entries_extracted_this_run = entries_extracted_this_run.saturating_add(1);
                // Per-entry granularity for the renderer's
                // bytes_extracted counter — finer than per-checkpoint
                // (which the throttle below skips most of the time).
                if let Some(p) = progress_state {
                    p.add_extracted(*bytes_written);
                }

                // Throttle checkpoint writes. The "progress" we
                // measure is bytes_extracted_total — an entry-by-entry
                // proxy for source-byte progress that's monotonic,
                // bounded by the archive's uncompressed size, and
                // close to what a user would expect.
                let elapsed = last_write_at.elapsed();
                let progressed = bytes_extracted_total.saturating_sub(last_progress);
                if progressed < config.checkpoint_min_bytes
                    && elapsed < config.checkpoint_min_interval
                {
                    return Ok(());
                }

                // Flush the sparse file's pending writes so the
                // bitmap claim of "this chunk is durable" is honest.
                sparse
                    .sync_all()
                    .map_err(|e| io::Error::other(format!("sparse sync_all: {e}")))?;

                let chunk_crc32c = if fingerprints.is_empty() {
                    None
                } else {
                    Some(fingerprints.to_vec())
                };
                let ckpt = Checkpoint {
                    url: requested_url.to_string(),
                    etag: info.fingerprint.etag.clone(),
                    last_modified: info.fingerprint.last_modified.clone(),
                    total_size: info.total_size,
                    chunk_size,
                    decoder_position: ByteOffset::new(0),
                    bitmap_completed: bitmap.to_bytes(),
                    created_at: SystemTime::now(),
                    sink_state: SinkState::Zip {
                        entries_completed: entries_completed.clone(),
                        current_entry: None,
                        current_entry_offset: 0,
                    },
                    // Integrity tracking is implemented for the
                    // streaming pipeline only; ZIP runs leave it
                    // unset (`PLAN_v2.md` §10 + §5).
                    hash_state: None,
                    chunk_crc32c,
                    // ZIP entries don't carry decoder state — they
                    // resume per-entry via `current_entry`/_offset.
                    decoder_state: None,
                };
                ckpt.write(ckpt_path)
                    .map_err(|e| io::Error::other(format!("checkpoint write: {e}")))?;

                last_write_at = Instant::now();
                last_progress = bytes_extracted_total;
                checkpoints_written = checkpoints_written.saturating_add(1);
                if let Some(cb) = progress.as_deref_mut() {
                    cb(ProgressEvent::CheckpointWritten {
                        source_position: 0,
                        bytes_in: bytes_extracted_total,
                        bytes_out: bytes_extracted_total,
                    });
                }
                Ok(())
            }
        }
    });

    match result {
        Ok(stats) => {
            sink.close().map_err(CoordinatorError::Sink)?;
            // Translate ZipExtractionStats into the
            // ExtractionStats shape the rest of the coordinator
            // returns. Some fields don't have a natural ZIP
            // counterpart and stay zero.
            Ok(ExtractionStats {
                bytes_in: total_size,
                bytes_out: stats.bytes_written,
                bytes_punched: stats.bytes_punched,
                punch_calls: u64::from(stats.entries_extracted),
                punch_unsupported: false,
                frame_boundaries_observed: u64::from(stats.entries_extracted),
                quiescent_checkpoints: checkpoints_written,
                decode_time: Duration::default(),
                write_time: Duration::default(),
                punch_time: Duration::default(),
            })
        }
        Err(ZipPipelineError::Aborted(e)) if e.to_string() == KILL_SENTINEL => {
            Err(CoordinatorError::Aborted {
                checkpoints_written,
            })
        }
        Err(other) => Err(CoordinatorError::Zip(other)),
    }
}

/// Build a fresh [`ChunkFingerprints`] store sized to the run's
/// chunk count, pre-populated from the resume plan when applicable.
///
/// `Fresh` runs return an all-zero store. `Resume` runs whose
/// checkpoint carries a `chunk_crc32c` of matching length restore
/// every fingerprint into the store. A length mismatch surfaces as
/// [`CoordinatorError::SourceChanged`] — the chunk count derived
/// from `total_size / chunk_size` did not agree with what the
/// checkpoint recorded, which means the source layout shifted and
/// resume is unsafe.
fn build_fingerprints(
    total_chunks: u32,
    plan: &ResumePlan,
) -> Result<ChunkFingerprints, CoordinatorError> {
    let store = ChunkFingerprints::new(total_chunks);
    if let ResumePlan::Resume {
        chunk_crc32c: Some(crcs),
        ..
    } = plan
    {
        if u32::try_from(crcs.len()).unwrap_or(u32::MAX) != total_chunks {
            return Err(CoordinatorError::SourceChanged {
                reason: format!(
                    "checkpoint chunk_crc32c length {} does not match expected chunk \
                     count {total_chunks}",
                    crcs.len(),
                ),
            });
        }
        for (i, crc) in crcs.iter().enumerate() {
            store.record(ChunkIndex::new(i as u32), *crc);
        }
    }
    Ok(store)
}

/// Re-fetch a single already-complete chunk and verify its
/// CRC-32C against the stored fingerprint (`PLAN_v2.md` §11).
///
/// Picks a random chunk whose bitmap bit is set and whose
/// fingerprint is non-zero; bytes that have not been seen by §11
/// (resumed-from-pre-§11 checkpoints; chunks without a recorded
/// fingerprint) are silently skipped. A successful probe leaves
/// the sparse file unchanged. A CRC-32C mismatch is surfaced as
/// [`CoordinatorError::SourceChangedSinceCheckpoint`].
fn run_resume_probe(
    client: &Client,
    info: &DownloadInfo,
    sparse: &SparseFile,
    bitmap: &ChunkBitmap,
    fingerprints: &ChunkFingerprints,
    chunk_size: u64,
    retry: &RetryConfig,
) -> Result<(), CoordinatorError> {
    let total_chunks = bitmap.len();
    if total_chunks == 0 || chunk_size == 0 || fingerprints.is_empty() {
        return Ok(());
    }

    // Pick the first complete + fingerprinted chunk in a
    // pseudorandom walk. Deterministic-ish so the test harness can
    // reason about which chunk gets probed.
    let mut rng: u64 =
        (u64::from(total_chunks) << 32) ^ 0xC0DE_FACE_5A5A_5A5A_u64 ^ info.total_size;
    let mut picked: Option<(ChunkIndex, u32)> = None;
    for _ in 0..16 {
        rng = rng
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let idx = u32::try_from(rng.wrapping_shr(32) % u64::from(total_chunks))
            .unwrap_or(0)
            .min(total_chunks - 1);
        let chunk = ChunkIndex::new(idx);
        if !bitmap.is_complete(chunk) {
            continue;
        }
        let crc = fingerprints.get(chunk);
        if crc == 0 {
            continue;
        }
        picked = Some((chunk, crc));
        break;
    }

    let Some((chunk, expected)) = picked else {
        // No fingerprinted chunk to probe (resume from pre-§11
        // checkpoint, or every fingerprint slot is unset). The §11
        // contract is "verify what we can"; absent fingerprints
        // means we can't, and that's fine — fall through.
        return Ok(());
    };

    let start_byte = u64::from(chunk.get()).saturating_mul(chunk_size);
    if start_byte >= info.total_size {
        return Ok(());
    }
    let end_byte = start_byte.saturating_add(chunk_size).min(info.total_size);
    let Some(range) =
        crate::types::ByteRange::new(ByteOffset::new(start_byte), ByteOffset::new(end_byte))
    else {
        return Ok(());
    };

    let dispatch = crate::download::Dispatch {
        first: chunk,
        count: 1,
        range,
        kind: crate::download::DispatchKind::Probe { expected },
    };
    // The resume probe always speaks to the primary URL: per
    // `PLAN_v2.md` §11 the probe verifies that *the source we
    // checkpointed against* still serves the bytes we recorded. Even
    // when `--mirror` is in play, we only have a fingerprint
    // recorded against the URL the prior run discovered; cross-mirror
    // probing happens later via §11's mid-flight verifier.
    let probe_mirrors =
        crate::download::MirrorSet::single(info.url.clone(), info.fingerprint.clone());
    let ctx = crate::download::worker::ChunkContext {
        client,
        mirrors: &probe_mirrors,
        chunk_size,
        sparse,
        progress: None,
        rate_limiter: None,
    };
    let cancel = AtomicBool::new(false);
    match crate::download::worker::download_dispatch(&ctx, dispatch, retry, &cancel) {
        Ok(_) => Ok(()),
        Err(crate::download::ChunkFailure {
            error:
                crate::download::WorkerError::SourceDriftDetected {
                    chunk,
                    expected,
                    actual,
                },
            ..
        }) => Err(CoordinatorError::SourceChangedSinceCheckpoint {
            chunk,
            expected,
            actual,
        }),
        Err(crate::download::ChunkFailure {
            error: other,
            attempts,
        }) => Err(CoordinatorError::Scheduler(SchedulerError::ChunkFailed {
            chunk,
            attempts,
            source: other,
        })),
    }
}

/// `PLAN_responsiveness.md` §3.1: re-CRC the on-disk bytes for the
/// chunk that contains `decoder_position` and compare against the
/// fingerprint persisted in the prior checkpoint.
///
/// This is the local twin of [`run_resume_probe`]: the latter
/// re-fetches a random already-complete chunk from the server to
/// catch upstream drift; this one reads back the bytes peel itself
/// most recently wrote, to catch corruption in the part file. The
/// cursor chunk is the most likely suspect — it's the one the
/// decoder is about to read — so we always inspect it on resume.
///
/// Behaviour:
/// - No fingerprints recorded (resume from a pre-§11 checkpoint) ⇒
///   no-op.
/// - Cursor past EOF (degenerate; should not happen but the
///   resume path tolerates it) ⇒ no-op.
/// - Cursor chunk not marked complete in the bitmap ⇒ no-op: the
///   download path itself will block until the chunk lands, and the
///   reader's normal logic surfaces a clearer error if it never does.
/// - Cursor chunk fingerprint is `0` (unset) ⇒ no-op (an unset
///   fingerprint is indistinguishable from a genuine zero CRC, but
///   bitmap chunks are non-empty so the latter cannot arise in
///   practice — a `0` here means "not recorded yet").
/// - Otherwise: re-checksum the on-disk bytes; mismatch ⇒
///   [`CoordinatorError::PartFileCorrupted`].
fn run_cursor_chunk_audit(
    sparse: &SparseFile,
    bitmap: &ChunkBitmap,
    fingerprints: &ChunkFingerprints,
    chunk_size: u64,
    total_size: u64,
    decoder_position: u64,
) -> Result<(), CoordinatorError> {
    if chunk_size == 0 || total_size == 0 || fingerprints.is_empty() {
        return Ok(());
    }
    if decoder_position >= total_size {
        return Ok(());
    }
    let cursor_chunk_idx = decoder_position / chunk_size;
    let total_chunks = u64::from(bitmap.len());
    if cursor_chunk_idx >= total_chunks {
        return Ok(());
    }
    // INVARIANT: cursor_chunk_idx < total_chunks (≤ u32::MAX), so
    // the cast is lossless.
    let chunk = ChunkIndex::new(cursor_chunk_idx as u32);
    if !bitmap.is_complete(chunk) {
        // The reader will block on this chunk normally; no value in
        // a separate error here.
        return Ok(());
    }
    let expected = fingerprints.get(chunk);
    if expected == 0 {
        // Fingerprint not recorded — pre-§11 resume, or a slot the
        // worker never wrote. Nothing to compare against.
        return Ok(());
    }

    let start_byte = cursor_chunk_idx.saturating_mul(chunk_size);
    if decoder_position > start_byte {
        // Cursor is mid-chunk: bytes below it have been hole-punched
        // by the prior run's extractor (zeroed) up to roughly
        // `align_down(decoder_position, fs_block)`. The fingerprint
        // was recorded over the pristine pre-punch chunk, so a
        // whole-chunk re-CRC here would always mismatch and produce
        // a false-positive `PartFileCorrupted`. We skip rather than
        // alarm; on-disk corruption of the post-cursor bytes will
        // still surface as a decoder error when the decoder reads
        // them.
        return Ok(());
    }
    let end_byte = start_byte.saturating_add(chunk_size).min(total_size);
    let len = end_byte.saturating_sub(start_byte);
    // INVARIANT: len ≤ chunk_size which fits in usize on every
    // 64-bit target peel runs on. Defensive cast guards 32-bit
    // hosts (where chunk_size could in principle exceed usize).
    let len_usize = match usize::try_from(len) {
        Ok(n) => n,
        Err(_) => return Ok(()),
    };
    let mut buf = vec![0u8; len_usize];
    sparse
        .read_exact_at(ByteOffset::new(start_byte), &mut buf)
        .map_err(CoordinatorError::SparseFile)?;
    let actual = crate::hash::crc32c::castagnoli(&buf);
    if actual != expected {
        return Err(CoordinatorError::PartFileCorrupted {
            chunk,
            expected,
            actual,
        });
    }
    Ok(())
}

/// Combined SharedHasher + initial skip count returned by
/// [`build_integrity_hasher`] when integrity tracking is enabled.
struct IntegrityHasherSetup {
    hasher: crate::hash::SharedHasher,
    skip_remaining: u64,
}

/// Build the integrity hasher for this run, or `None` if `--sha256`
/// is not set.
///
/// Resume semantics (`docs/PLAN_v2.md` §10 step 4):
///
/// - **Fresh run + `--sha256`** → fresh hasher, skip = 0.
/// - **Resume + `--sha256` + saved hash_state** → restore hasher
///   from the saved state. The hasher's `bytes_processed` may be
///   larger than `decoder_position` because the previous run's
///   BufReader had prefetched past the boundary; subtract to get
///   the per-byte skip count for the new HashingReader.
/// - **Resume + `--sha256` + no saved hash_state** → hard error
///   (`IntegrityError::CheckpointMissingHashState`); we cannot
///   rebuild a faithful end-of-run digest from a half-tracked run.
/// - **Resume + no `--sha256` + saved hash_state** → hard error
///   (`IntegrityError::CheckpointHadHashState`); refusing keeps
///   the user's prior intent intact rather than silently losing it.
fn build_integrity_hasher(
    expected: Option<&[u8; crate::hash::sha256::DIGEST_LEN]>,
    prior: Option<&Checkpoint>,
    ckpt_path: &Path,
    reader_start: u64,
) -> Result<Option<IntegrityHasherSetup>, CoordinatorError> {
    let prior_hash_state = prior.and_then(|p| p.hash_state.as_ref());

    match (expected.is_some(), prior_hash_state) {
        (false, Some(_)) => Err(CoordinatorError::Integrity(
            crate::hash::IntegrityError::CheckpointHadHashState {
                ckpt_path: ckpt_path.to_path_buf(),
            },
        )),
        (false, None) => Ok(None),
        (true, None) => {
            // Fresh run (or a resume without integrity tracking
            // before — surface the latter as an error rather than
            // silently dropping coverage).
            if prior.is_some() {
                return Err(CoordinatorError::Integrity(
                    crate::hash::IntegrityError::CheckpointMissingHashState {
                        ckpt_path: ckpt_path.to_path_buf(),
                    },
                ));
            }
            Ok(Some(IntegrityHasherSetup {
                hasher: crate::hash::shared_hasher(crate::hash::sha256::Sha256::new()),
                skip_remaining: 0,
            }))
        }
        (true, Some(state_bytes)) => {
            let restored =
                crate::hash::sha256::Sha256::deserialize(state_bytes).map_err(|source| {
                    CoordinatorError::Integrity(
                        crate::hash::IntegrityError::CheckpointHashStateDecode { source },
                    )
                })?;
            // The saved hash covers source bytes
            // `[0, restored.bytes_processed())`, but the new
            // BlockingSparseReader will start handing out bytes from
            // `reader_start` (the resume's `decoder_position`).
            // Anything in `[reader_start, restored.bytes_processed())`
            // was already hashed last run; skip those.
            let already = restored.bytes_processed();
            let skip_remaining = already.saturating_sub(reader_start);
            Ok(Some(IntegrityHasherSetup {
                hasher: crate::hash::shared_hasher(restored),
                skip_remaining,
            }))
        }
    }
}

/// Snapshot the running SHA-256 hasher's state for inclusion in the
/// next checkpoint, when integrity tracking is on.
///
/// Locks the shared hasher, clones the (small, fixed-size) state,
/// drops the lock, and serializes outside the critical section. The
/// hasher remains usable for further `update`s — `Sha256` is `Clone`
/// and the clone is independent of the original.
fn snapshot_hash_state(
    hasher: Option<&crate::hash::SharedHasher>,
) -> Option<[u8; crate::hash::sha256::SERIALIZED_LEN]> {
    let h = hasher?;
    // INVARIANT: the mutex is touched from the extractor's thread
    // only — the checkpoint observer pauses the decoder before
    // calling here. Poisoning would mean a panic inside an
    // earlier hash update; surfacing the error would force the
    // coordinator into the panic path. Returning `None` (degrades
    // to "no integrity state captured this round") is the safe
    // option — a subsequent successful snapshot supersedes it.
    let snapshot = h.lock().ok()?.clone();
    Some(snapshot.serialize())
}

/// Construct the [`SparseFile`] for this run, picking between the
/// pwrite/pread storage (any platform, any non-mmap backend choice)
/// and the §9 `mmap` storage (Linux only).
///
/// `Mmap` is selected on Linux when the user passed
/// [`crate::io_backend::IoBackendChoice::Mmap`] *or*
/// [`crate::io_backend::IoBackendChoice::Auto`]. Auto resolves to
/// mmap on Linux because `tests/test_bench_streaming.rs` measured
/// it 20% faster than pwrite/pread on representative cluster
/// hardware, with no observed downside on filesystems that don't
/// support `MADV_REMOVE` (the puncher degrades to noop the same way
/// it does on the pwrite path).
fn open_sparse(
    path: &Path,
    total_size: u64,
    config: &CoordinatorConfig,
    io_backend: &Arc<dyn crate::io_backend::IoBackend>,
) -> Result<SparseFile, CoordinatorError> {
    #[cfg(target_os = "linux")]
    if matches!(
        config.io_backend,
        crate::io_backend::IoBackendChoice::Mmap | crate::io_backend::IoBackendChoice::Auto
    ) {
        return SparseFile::open_or_create_mmap(path, total_size)
            .map_err(CoordinatorError::SparseFile);
    }
    // `config` is only consulted on Linux (where mmap storage is
    // selectable). Bind it to `_` on non-Linux to keep the signature
    // uniform across platforms.
    #[cfg(not(target_os = "linux"))]
    let _ = config;

    SparseFile::open_or_create_with_backend(path, total_size, Arc::clone(io_backend))
        .map_err(CoordinatorError::SparseFile)
}

/// Choose the right puncher for this run: the `mmap`-mode
/// [`crate::punch::LinuxPuncher::for_mmap`] when the sparse file is
/// memory-mapped, otherwise the platform default
/// (`fallocate(PUNCH_HOLE)` on Linux, `fcntl(F_PUNCHHOLE)` on macOS,
/// [`crate::punch::NoopPuncher`] elsewhere).
fn make_puncher(sparse: &SparseFile) -> Box<dyn PunchHole> {
    #[cfg(target_os = "linux")]
    if let Some(p) = sparse.make_mmap_puncher() {
        return Box::new(p);
    }
    let _ = sparse;
    default_puncher()
}

/// Verify the `.peel.part` sparse file is consistent with the
/// `.peel.ckpt` we just loaded.
///
/// `open_sparse` is willing to CREAT + `set_len` the part file
/// unconditionally, which would silently turn a missing or truncated
/// part into a `total_size`-of-zeros sparse file. The bitmap inside
/// the checkpoint claims chunks complete that — without their bytes
/// — would now be all-zero garbage. This check fires before
/// `open_sparse` and surfaces the inconsistency as a hard error so
/// the user can either restore the part or delete both sidecars,
/// rather than discovering the corruption later via the §11 probe's
/// "source changed" message (or, if the checkpoint claimed zero
/// chunks complete, not at all).
///
/// Tolerates a part file that's *exactly* `total_size`, including
/// the freshly-created sparse case from a prior run that died before
/// any download had landed: in that case the bitmap claims zero
/// chunks and the resume effectively starts from byte 0 anyway.
fn validate_part_file(
    ckpt_path: &Path,
    part_path: &Path,
    total_size: u64,
) -> Result<(), CoordinatorError> {
    match fs::metadata(part_path) {
        Ok(meta) => {
            let actual = meta.len();
            if actual < total_size {
                return Err(CoordinatorError::CheckpointPartMismatch {
                    ckpt_path: ckpt_path.to_path_buf(),
                    part_path: part_path.to_path_buf(),
                    reason: format!(
                        "part file is {actual} bytes, source's total_size is {total_size}"
                    ),
                });
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            Err(CoordinatorError::CheckpointPartMismatch {
                ckpt_path: ckpt_path.to_path_buf(),
                part_path: part_path.to_path_buf(),
                reason: "part file is missing".into(),
            })
        }
        Err(source) => Err(CoordinatorError::Io {
            path: part_path.to_path_buf(),
            source,
        }),
    }
}

/// Compute `<anchor> + suffix` for the .peel.part / .peel.ckpt
/// sidecars, optionally redirected to `config.workdir`.
fn sidecar_path(output: &OutputTarget, config: &CoordinatorConfig, suffix: &str) -> PathBuf {
    let anchor = output.anchor();
    let basename = anchor
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("output"));
    let parent = config
        .workdir
        .clone()
        .or_else(|| anchor.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    let mut name = basename.into_os_string();
    name.push(suffix);
    parent.join(PathBuf::from(name))
}

fn ensure_parent_dir(path: &Path) -> Result<(), CoordinatorError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|source| CoordinatorError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
    }
    Ok(())
}

fn filename_from_url(url: &Url) -> Option<String> {
    let path = url.path().split('?').next()?;
    let last = path.rsplit('/').next()?;
    if last.is_empty() {
        None
    } else {
        Some(last.to_string())
    }
}

/// `Read` adapter that feeds the decoder from the sparse file,
/// blocking when the chunk it needs hasn't been downloaded yet.
///
/// Construct via [`Self::new`]; the type owns its own cursor. The
/// scheduler reads `cursor` to bias dispatch toward the chunk the
/// decoder is about to need.
pub struct BlockingSparseReader {
    sparse: Arc<SparseFile>,
    bitmap: Arc<ChunkBitmap>,
    chunk_size: u64,
    total_size: u64,
    cursor: Arc<AtomicU64>,
    download_done: Arc<AtomicBool>,
    download_outcome: Arc<Mutex<Option<Result<DownloadStats, SchedulerError>>>>,
    poll_interval: Duration,
    /// Optional shared progress state. When set, every advance of
    /// the cursor also publishes the new value as
    /// `bytes_decoded_input`, so the scheduler's disk-buffer throttle
    /// (and the renderer's lookahead indicator) can read it.
    progress_state: Option<Arc<ProgressState>>,
    /// Optional kill-switch the read loop polls between sleeps. When
    /// set, a tripped flag surfaces as
    /// `io::Error::other(KILL_SENTINEL)` so the outer `run_one`
    /// matcher maps it to [`CoordinatorError::Aborted`]
    /// (`PLAN_responsiveness.md` §2.1).
    kill_switch: Option<Arc<AtomicBool>>,
}

impl BlockingSparseReader {
    #[allow(clippy::too_many_arguments)]
    fn new(
        sparse: Arc<SparseFile>,
        bitmap: Arc<ChunkBitmap>,
        chunk_size: u64,
        total_size: u64,
        start_offset: u64,
        download_done: Arc<AtomicBool>,
        download_outcome: Arc<Mutex<Option<Result<DownloadStats, SchedulerError>>>>,
        poll_interval: Duration,
    ) -> Self {
        // Coordinator-level invariant: the cursor was set to
        // start_offset before construction; we don't reset it here so
        // the scheduler can't observe a transient regression.
        let cursor = Arc::new(AtomicU64::new(start_offset));
        Self {
            sparse,
            bitmap,
            chunk_size,
            total_size,
            cursor,
            download_done,
            download_outcome,
            poll_interval,
            progress_state: None,
            kill_switch: None,
        }
    }

    /// Hook the reader up to a shared progress state so cursor
    /// advances publish to `bytes_decoded_input`. Returns `self` for
    /// chained construction.
    #[must_use]
    fn with_progress(mut self, state: Arc<ProgressState>) -> Self {
        // Seed the progress state at the resume offset so the
        // first lookahead query (before the first read) reads the
        // correct value.
        state.set_bytes_decoded_input(self.cursor.load(Ordering::Acquire));
        self.progress_state = Some(state);
        self
    }

    /// Hook the reader up to the run-wide kill switch. When the flag
    /// flips, the next iteration of the read poll loop returns the
    /// kill sentinel `io::Error` so the outer `run_one` matcher
    /// surfaces a typed [`CoordinatorError::Aborted`]
    /// (`PLAN_responsiveness.md` §2.1).
    #[must_use]
    fn with_kill_switch(mut self, kill: Arc<AtomicBool>) -> Self {
        self.kill_switch = Some(kill);
        self
    }
}

impl Read for BlockingSparseReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // §1.3: enter a debug-level span around the source-read poll
        // loop so a stuck decoder shows up in the per-component
        // breakdown when the operator runs with `RUST_LOG=peel=debug`.
        // The span itself is filtered at default INFO and costs an
        // atomic-load + branch per `read`.
        let initial_pos = self.cursor.load(Ordering::Acquire);
        let span = tracing::debug_span!(
            target: "peel::reader",
            "blocking_sparse_read",
            cursor = initial_pos,
            buf_len = buf.len(),
        );
        let _enter = span.enter();
        // §2.1: poll the kill switch immediately on entry — the most
        // common stall site for the snapshot-restore bug was a decoder
        // that called into this read repeatedly without the surrounding
        // checkpoint observer ever firing, so SIGTERM had nowhere else
        // to land. Returning the kill sentinel here propagates as
        // `DecodeError::Read` and the outer `run_one` matcher maps it
        // to `CoordinatorError::Aborted`.
        if let Some(flag) = self.kill_switch.as_ref() {
            if flag.load(Ordering::Acquire) {
                return Err(io::Error::other(KILL_SENTINEL));
            }
        }
        // §2.5 (PLAN_decoder_freeze.md): one-shot diagnostic when the
        // poll loop has been waiting on the same chunk for too long.
        // The §2.4b watchdog fires from the renderer thread to flag
        // *that* a `decode_step` is hung; this dump prints the bitmap
        // state local to the read so we can distinguish:
        //   - gap   : `bitmap[N] = false` but `bitmap[N+1..]` = true
        //             → something orphaned a chunk in `dispatched`
        //   - cliff : `bitmap[N..] = false`
        //             → scheduler isn't dispatching N (likely the
        //               throttle-deadlock pattern)
        //   - other : `next_incomplete_after(N)` returns something
        //             unexpected → bitmap consistency bug
        // Local to the read invocation: each fresh `read()` resets the
        // counter, so a healthy short wait never triggers it.
        let read_started = Instant::now();
        let mut last_dump_at: Option<Instant> = None;
        let dump_interval = Duration::from_secs(30);
        loop {
            let pos = self.cursor.load(Ordering::Acquire);
            if pos >= self.total_size {
                return Ok(0);
            }

            // Identify the chunk this position lives in. If chunk_size
            // is somehow zero we already rejected at config time, but
            // we still saturate to avoid div-by-zero.
            if self.chunk_size == 0 {
                return Err(io::Error::other("zero chunk_size"));
            }
            let chunk_idx = (pos / self.chunk_size) as u32;
            if !self.bitmap.is_complete(ChunkIndex::new(chunk_idx)) {
                if self.download_done.load(Ordering::Acquire) {
                    if let Ok(mut slot) = self.download_outcome.lock() {
                        if let Some(Err(e)) = slot.take() {
                            // Wrap the typed scheduler error as the io::Error
                            // source rather than stringifying it. The outer-loop
                            // retry path in `main` walks `Error::source()` and
                            // matches on the `SchedulerError` / `WorkerError`
                            // types to decide whether to restart from checkpoint;
                            // collapsing to a `String` here would erase that.
                            return Err(io::Error::other(e));
                        }
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        format!(
                            "download finished but chunk {chunk_idx} (cursor {pos}) is not \
                             complete"
                        ),
                    ));
                }
                // §2.5 diagnostic: once we've been waiting `dump_interval`
                // (or `2 × dump_interval`, `3 ×`, …) on the same `read()`
                // invocation, dump the bitmap state around the cursor
                // chunk. Cheap (a handful of atomic loads) and scoped
                // to a true wedge.
                let elapsed = read_started.elapsed();
                if elapsed >= dump_interval {
                    let should_dump = last_dump_at.is_none_or(|prev| {
                        Instant::now().saturating_duration_since(prev) >= dump_interval
                    });
                    if should_dump {
                        last_dump_at = Some(Instant::now());
                        let next_incomplete = self
                            .bitmap
                            .next_incomplete_after(ChunkIndex::new(chunk_idx))
                            .map(ChunkIndex::get);
                        let mut neighbors: Vec<u8> = Vec::with_capacity(13);
                        let lo = chunk_idx.saturating_sub(2);
                        let hi = chunk_idx.saturating_add(10);
                        for i in lo..=hi {
                            neighbors.push(u8::from(self.bitmap.is_complete(ChunkIndex::new(i))));
                        }
                        tracing::warn!(
                            target: "peel::reader",
                            cursor = pos,
                            chunk_idx,
                            elapsed_secs = elapsed.as_secs(),
                            next_incomplete = ?next_incomplete,
                            window_lo = lo,
                            window_hi = hi,
                            neighbors = ?neighbors,
                            "blocking_sparse_read stuck waiting for chunk: \
                             cursor at byte {pos} (chunk {chunk_idx}), waiting {} s; \
                             next_incomplete_after={next_incomplete:?}; \
                             chunks [{lo}..={hi}]={neighbors:?}",
                            elapsed.as_secs(),
                        );
                    }
                }
                // §2.1: a decoder waiting for the next chunk to arrive
                // can sit here indefinitely on a slow network. Polling
                // before sleeping bounds the kill-switch latency to one
                // `poll_interval` (default 5 ms).
                if let Some(flag) = self.kill_switch.as_ref() {
                    if flag.load(Ordering::Acquire) {
                        return Err(io::Error::other(KILL_SENTINEL));
                    }
                }
                thread::sleep(self.poll_interval);
                continue;
            }

            let want = self.total_size.saturating_sub(pos).min(buf.len() as u64) as usize;
            // Also stop at the end of the current chunk so we don't
            // accidentally read into a chunk that hasn't been claimed
            // yet.
            let chunk_end = u64::from(chunk_idx)
                .saturating_add(1)
                .saturating_mul(self.chunk_size)
                .min(self.total_size);
            let chunk_remaining = chunk_end.saturating_sub(pos) as usize;
            let want = want.min(chunk_remaining);
            if want == 0 {
                return Ok(0);
            }
            let n = self
                .sparse
                .read_at(ByteOffset::new(pos), &mut buf[..want])
                .map_err(|e| io::Error::other(format!("sparse read: {e}")))?;
            if n == 0 {
                // Defensive: the sparse file is sized to total_size, so
                // a short read of zero here is unexpected. Surface as
                // an io error rather than spinning.
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("short read from sparse file at offset {pos}"),
                ));
            }
            let new_pos = self.cursor.fetch_add(n as u64, Ordering::Release) + n as u64;
            if let Some(p) = self.progress_state.as_ref() {
                p.set_bytes_decoded_input(new_pos);
            }
            return Ok(n);
        }
    }
}

/// Pick the decoder factory the run should use, applying (in order):
///
/// 1. `config.forced_format` — short-circuit, no sniffing.
/// 2. URL-suffix lookup against the registry.
/// 3. Magic-byte lookup against the first
///    `min(chunk_size, max_magic_window)` bytes of the source. Sniffing
///    waits for the chunks covering that prefix to be downloaded.
/// 4. Conflict resolution:
///    - both lookups agree → use that factory;
///    - both lookups disagree → return [`CoordinatorError::FormatMismatch`]
///      unless `config.force_format_from_magic` is set, in which case
///      the magic wins and a warning is emitted;
///    - only one lookup matched → use it;
///    - neither matched → return [`CoordinatorError::NoDecoder`].
#[allow(clippy::too_many_arguments)]
fn select_decoder_factory(
    registry: &DecoderRegistry,
    info: &DownloadInfo,
    config: &CoordinatorConfig,
    sparse: &SparseFile,
    bitmap: &ChunkBitmap,
    download_done: &Arc<AtomicBool>,
    download_outcome: &Arc<Mutex<Option<Result<DownloadStats, SchedulerError>>>>,
    kill_switch: Option<&Arc<AtomicBool>>,
) -> Result<DecoderFactory, CoordinatorError> {
    if let Some(name) = config.forced_format.as_deref() {
        return registry.factory_for_format_name(name).ok_or_else(|| {
            CoordinatorError::UnknownFormatName {
                name: name.to_string(),
                available: registry
                    .format_names()
                    .into_iter()
                    .map(String::from)
                    .collect(),
            }
        });
    }

    let suffix_factory = registry
        .factory_for_path(Path::new(info.url.path()))
        .or_else(|| filename_from_url(&info.url).and_then(|n| registry.factory_for_name(&n)));

    // The plan calls for sniffing the first
    // `min(chunk_size, max_magic_window)` bytes — but
    // `max_magic_window` is small (≤ a few hundred bytes for every
    // currently-registered format) and chunk_size is megabytes, so
    // `max_magic_window` always wins. We still cap by `total_size`
    // for the rare archive shorter than the magic window.
    let max_window = registry.max_magic_window();
    let prefix = if max_window == 0 {
        Vec::new()
    } else {
        sniff_prefix(
            sparse,
            bitmap,
            config.chunk_size,
            info.total_size,
            max_window,
            download_done,
            download_outcome,
            config.reader_poll_interval,
            kill_switch,
        )?
    };
    let magic_factory = registry.factory_for_prefix(&prefix);

    match (suffix_factory, magic_factory) {
        (Some(s), Some(m)) if std::ptr::fn_addr_eq(s, m) => Ok(s),
        (Some(s), Some(m)) => {
            let suffix_name = registry.name_for_factory(s).map(String::from);
            let magic_name = registry.name_for_factory(m).map(String::from);
            if config.force_format_from_magic {
                // User-facing notice. We don't pull in `tracing` for
                // this single call site — the rest of the binary uses
                // `eprintln!` for user-visible output (see main.rs)
                // and this is unambiguously user-facing rather than
                // diagnostic logging.
                eprintln!(
                    "[warn] format-detection conflict: URL suffix indicates {} but \
                     magic bytes indicate {}; using {} per --force-format-from-magic",
                    suffix_name.as_deref().unwrap_or("?"),
                    magic_name.as_deref().unwrap_or("?"),
                    magic_name.as_deref().unwrap_or("?"),
                );
                Ok(m)
            } else {
                Err(CoordinatorError::FormatMismatch {
                    suffix_format: suffix_name,
                    magic_format: magic_name,
                })
            }
        }
        (Some(s), None) => Ok(s),
        (None, Some(m)) => Ok(m),
        (None, None) => {
            let filename =
                filename_from_url(&info.url).unwrap_or_else(|| info.url.path().to_string());
            Err(CoordinatorError::NoDecoder { filename })
        }
    }
}

/// Wait for the chunks covering `[0, min(max_window, total_size))` to
/// be marked complete in `bitmap`, then read the prefix from `sparse`.
///
/// Returns a buffer that may be shorter than `max_window` if the
/// source itself is smaller. Surfaces a typed
/// [`CoordinatorError::Scheduler`] / [`CoordinatorError::Io`] if the
/// download thread finished before chunk 0 became available.
#[allow(clippy::too_many_arguments)]
fn sniff_prefix(
    sparse: &SparseFile,
    bitmap: &ChunkBitmap,
    chunk_size: u64,
    total_size: u64,
    max_window: usize,
    download_done: &Arc<AtomicBool>,
    download_outcome: &Arc<Mutex<Option<Result<DownloadStats, SchedulerError>>>>,
    poll_interval: Duration,
    kill_switch: Option<&Arc<AtomicBool>>,
) -> Result<Vec<u8>, CoordinatorError> {
    if max_window == 0 || total_size == 0 || chunk_size == 0 {
        return Ok(Vec::new());
    }
    let want = (max_window as u64).min(total_size);
    // §1.3: span around the sniff-prefix poll so a slow first chunk is
    // visible in the per-component breakdown.
    let span = tracing::debug_span!(target: "peel::sniff", "sniff_prefix", want);
    let _enter = span.enter();
    // Number of chunks required to cover offset 0..want. For typical
    // configs this is exactly 1 (chunk_size ≫ max_window).
    // INVARIANT: chunk_size > 0 (checked above) so div_ceil is sound.
    let chunks_needed = u32::try_from(want.div_ceil(chunk_size).max(1)).unwrap_or(u32::MAX);
    for i in 0..chunks_needed {
        let idx = ChunkIndex::new(i);
        loop {
            // §2.2: a SIGTERM during sniff (slow connect / TLS / DNS)
            // would otherwise hang until the chunk arrives. Surface
            // the kill switch as a typed `Aborted` with zero
            // checkpoints written, since nothing has been persisted
            // at this point in the run.
            if let Some(flag) = kill_switch {
                if flag.load(Ordering::Acquire) {
                    return Err(CoordinatorError::Aborted {
                        checkpoints_written: 0,
                    });
                }
            }
            if bitmap.is_complete(idx) {
                break;
            }
            if download_done.load(Ordering::Acquire) {
                let detail = match download_outcome.lock() {
                    Ok(slot) => match &*slot {
                        Some(Err(e)) => format!("download failed: {e}"),
                        _ => format!(
                            "download finished but chunk {i} (needed for format detection) \
                             is not complete"
                        ),
                    },
                    Err(_) => "download outcome poisoned".to_string(),
                };
                return Err(CoordinatorError::Io {
                    path: PathBuf::from("<sniff-prefix>"),
                    source: io::Error::new(io::ErrorKind::UnexpectedEof, detail),
                });
            }
            thread::sleep(poll_interval);
        }
    }
    // INVARIANT: want <= usize::MAX because want <= max_window: usize.
    let mut buf = vec![0u8; want as usize];
    let n = sparse
        .read_at(ByteOffset::ZERO, &mut buf)
        .map_err(CoordinatorError::SparseFile)?;
    buf.truncate(n);
    Ok(buf)
}

// Marker re-export so the unused-import warning doesn't fire when the
// `Read` import is only used through trait dispatch.
#[allow(dead_code)]
const _: fn() = || {
    let _ = NoopPuncher::new();
};

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::AtomicU64;

    static UNIQ: AtomicU64 = AtomicU64::new(0);

    fn unique_temp(label: &str) -> PathBuf {
        let pid = std::process::id();
        let n = UNIQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("peel_coord_unit_{label}_{pid}_{nanos}_{n}"))
    }

    fn sample_info(total_size: u64) -> DownloadInfo {
        DownloadInfo {
            url: Url::parse("https://example.com/x.tar.zst").expect("parse"),
            total_size,
            fingerprint: SourceFingerprint {
                etag: Some("\"abc\"".into()),
                last_modified: None,
            },
            accept_ranges: true,
        }
    }

    fn sample_checkpoint(url: &str, total_size: u64, chunk_size: u64) -> Checkpoint {
        Checkpoint {
            url: url.into(),
            etag: Some("\"abc\"".into()),
            last_modified: None,
            total_size,
            chunk_size,
            decoder_position: ByteOffset::new(0),
            bitmap_completed: vec![],
            created_at: SystemTime::now(),
            sink_state: SinkState::Tar {
                members_completed: vec![],
                in_flight: None,
            },
            hash_state: None,
            chunk_crc32c: None,
            decoder_state: None,
        }
    }

    #[test]
    fn build_resume_plan_returns_fresh_when_no_checkpoint() {
        let info = sample_info(1024);
        let cfg = CoordinatorConfig::default();
        let output = OutputTarget::Dir(PathBuf::from("/tmp/x"));
        let plan = build_resume_plan(None, &info, "https://example.com/x.tar.zst", &cfg, &output)
            .expect("plan");
        assert!(matches!(plan, ResumePlan::Fresh));
    }

    #[test]
    fn build_resume_plan_resumes_when_everything_matches() {
        let info = sample_info(1024);
        let cfg = CoordinatorConfig {
            chunk_size: 256,
            ..CoordinatorConfig::default()
        };
        let prior = sample_checkpoint("https://example.com/x.tar.zst", 1024, 256);
        let output = OutputTarget::Dir(PathBuf::from("/tmp/x"));
        let plan = build_resume_plan(
            Some(&prior),
            &info,
            "https://example.com/x.tar.zst",
            &cfg,
            &output,
        )
        .expect("plan");
        assert!(matches!(plan, ResumePlan::Resume { .. }));
    }

    #[test]
    fn build_resume_plan_rejects_etag_change() {
        let mut info = sample_info(1024);
        info.fingerprint.etag = Some("\"changed\"".into());
        let cfg = CoordinatorConfig {
            chunk_size: 256,
            ..CoordinatorConfig::default()
        };
        let prior = sample_checkpoint("https://example.com/x.tar.zst", 1024, 256);
        let output = OutputTarget::Dir(PathBuf::from("/tmp/x"));
        let err = build_resume_plan(
            Some(&prior),
            &info,
            "https://example.com/x.tar.zst",
            &cfg,
            &output,
        )
        .expect_err("should reject");
        match err {
            CoordinatorError::SourceChanged { reason } => {
                assert!(reason.contains("ETag") || reason.contains("etag"));
            }
            other => panic!("expected SourceChanged, got {other:?}"),
        }
    }

    #[test]
    fn build_resume_plan_rejects_size_change() {
        let info = sample_info(2048);
        let cfg = CoordinatorConfig {
            chunk_size: 256,
            ..CoordinatorConfig::default()
        };
        let prior = sample_checkpoint("https://example.com/x.tar.zst", 1024, 256);
        let output = OutputTarget::Dir(PathBuf::from("/tmp/x"));
        let err = build_resume_plan(
            Some(&prior),
            &info,
            "https://example.com/x.tar.zst",
            &cfg,
            &output,
        )
        .expect_err("should reject");
        match err {
            CoordinatorError::SourceChanged { reason } => {
                assert!(reason.contains("total_size"));
            }
            other => panic!("expected SourceChanged, got {other:?}"),
        }
    }

    #[test]
    fn build_resume_plan_rejects_url_mismatch() {
        let info = sample_info(1024);
        let cfg = CoordinatorConfig {
            chunk_size: 256,
            ..CoordinatorConfig::default()
        };
        let prior = sample_checkpoint("https://other.example/y.tar.zst", 1024, 256);
        let output = OutputTarget::Dir(PathBuf::from("/tmp/x"));
        let err = build_resume_plan(
            Some(&prior),
            &info,
            "https://example.com/x.tar.zst",
            &cfg,
            &output,
        )
        .expect_err("should reject");
        match err {
            CoordinatorError::SourceChanged { reason } => {
                assert!(reason.contains("URL"));
            }
            other => panic!("expected SourceChanged, got {other:?}"),
        }
    }

    #[test]
    fn build_resume_plan_rejects_sink_kind_mismatch() {
        let info = sample_info(1024);
        let cfg = CoordinatorConfig {
            chunk_size: 256,
            ..CoordinatorConfig::default()
        };
        // Prior was Tar, request is File.
        let prior = sample_checkpoint("https://example.com/x.tar.zst", 1024, 256);
        let output = OutputTarget::File(PathBuf::from("/tmp/y.bin"));
        let err = build_resume_plan(
            Some(&prior),
            &info,
            "https://example.com/x.tar.zst",
            &cfg,
            &output,
        )
        .expect_err("should reject");
        assert!(matches!(err, CoordinatorError::SourceChanged { .. }));
    }

    #[test]
    fn validate_part_file_errors_when_missing() {
        let dir = unique_temp("validate_missing");
        let _g = TmpDir(dir.clone());
        fs::create_dir_all(&dir).expect("mkdir");
        let ckpt = dir.join("out.bin.peel.ckpt");
        fs::write(&ckpt, b"placeholder").expect("write ckpt");
        let part = dir.join("out.bin.peel.part");
        let err = validate_part_file(&ckpt, &part, 1024).expect_err("should reject");
        match err {
            CoordinatorError::CheckpointPartMismatch { reason, .. } => {
                assert!(reason.contains("missing"), "got: {reason}");
            }
            other => panic!("expected CheckpointPartMismatch, got {other:?}"),
        }
    }

    #[test]
    fn validate_part_file_errors_when_undersized() {
        let dir = unique_temp("validate_short");
        let _g = TmpDir(dir.clone());
        fs::create_dir_all(&dir).expect("mkdir");
        let ckpt = dir.join("out.bin.peel.ckpt");
        fs::write(&ckpt, b"placeholder").expect("write ckpt");
        let part = dir.join("out.bin.peel.part");
        fs::File::create(&part)
            .expect("part create")
            .set_len(512)
            .expect("set_len");
        let err = validate_part_file(&ckpt, &part, 1024).expect_err("should reject");
        match err {
            CoordinatorError::CheckpointPartMismatch { reason, .. } => {
                assert!(
                    reason.contains("512") && reason.contains("1024"),
                    "got: {reason}"
                );
            }
            other => panic!("expected CheckpointPartMismatch, got {other:?}"),
        }
    }

    #[test]
    fn validate_part_file_accepts_exact_size() {
        let dir = unique_temp("validate_exact");
        let _g = TmpDir(dir.clone());
        fs::create_dir_all(&dir).expect("mkdir");
        let ckpt = dir.join("out.bin.peel.ckpt");
        fs::write(&ckpt, b"placeholder").expect("write ckpt");
        let part = dir.join("out.bin.peel.part");
        fs::File::create(&part)
            .expect("part create")
            .set_len(1024)
            .expect("set_len");
        validate_part_file(&ckpt, &part, 1024).expect("should accept");
    }

    #[test]
    fn sidecar_paths_alongside_output_by_default() {
        let cfg = CoordinatorConfig::default();
        let output = OutputTarget::File(PathBuf::from("/tmp/peel_test/out.bin"));
        let part = sidecar_path(&output, &cfg, ".peel.part");
        let ckpt = sidecar_path(&output, &cfg, ".peel.ckpt");
        assert_eq!(part, PathBuf::from("/tmp/peel_test/out.bin.peel.part"));
        assert_eq!(ckpt, PathBuf::from("/tmp/peel_test/out.bin.peel.ckpt"));
    }

    #[test]
    fn sidecar_paths_redirected_to_workdir_when_set() {
        let cfg = CoordinatorConfig {
            workdir: Some(PathBuf::from("/var/peel/work")),
            ..CoordinatorConfig::default()
        };
        let output = OutputTarget::File(PathBuf::from("/tmp/peel_test/out.bin"));
        let part = sidecar_path(&output, &cfg, ".peel.part");
        assert_eq!(part, PathBuf::from("/var/peel/work/out.bin.peel.part"));
    }

    #[test]
    fn filename_from_url_extracts_basename() {
        let u = Url::parse("https://host.example/path/to/file.tar.zst?cache=1").expect("parse");
        assert_eq!(filename_from_url(&u).as_deref(), Some("file.tar.zst"));
    }

    #[test]
    fn filename_from_url_returns_none_for_root() {
        let u = Url::parse("https://host.example/").expect("parse");
        assert!(filename_from_url(&u).is_none());
    }

    #[test]
    fn blocking_reader_returns_zero_at_eof() {
        // Build a tiny sparse file and matching bitmap; reader at the
        // end of the file must return Ok(0) immediately without
        // touching the bitmap.
        let path = unique_temp("eof");
        let _g = TmpFile(path.clone());
        let sparse = Arc::new(SparseFile::open_or_create(&path, 64).expect("sparse"));
        let bitmap = Arc::new(ChunkBitmap::new(1));
        let download_done = Arc::new(AtomicBool::new(true));
        let outcome = Arc::new(Mutex::new(Some(Ok(DownloadStats::default()))));
        let mut reader = BlockingSparseReader::new(
            sparse,
            bitmap,
            64,
            64,
            64,
            download_done,
            outcome,
            Duration::from_millis(1),
        );
        let mut buf = [0u8; 32];
        let n = reader.read(&mut buf).expect("read");
        assert_eq!(n, 0);
    }

    #[test]
    fn blocking_reader_reads_complete_chunk() {
        let path = unique_temp("ready");
        let _g = TmpFile(path.clone());
        let sparse = Arc::new(SparseFile::open_or_create(&path, 16).expect("sparse"));
        sparse
            .pwrite_at(ByteOffset::ZERO, b"abcdefghijklmnop")
            .expect("write");
        let bitmap = Arc::new(ChunkBitmap::new(1));
        bitmap.mark_complete(ChunkIndex::new(0));
        let download_done = Arc::new(AtomicBool::new(false));
        let outcome = Arc::new(Mutex::new(None));
        let mut reader = BlockingSparseReader::new(
            sparse,
            bitmap,
            16,
            16,
            0,
            download_done,
            outcome,
            Duration::from_millis(1),
        );
        let mut buf = [0u8; 32];
        let n = reader.read(&mut buf).expect("read");
        assert_eq!(n, 16);
        assert_eq!(&buf[..n], b"abcdefghijklmnop");
    }

    #[test]
    fn blocking_reader_errors_when_download_completes_with_missing_chunk() {
        let path = unique_temp("missing");
        let _g = TmpFile(path.clone());
        let sparse = Arc::new(SparseFile::open_or_create(&path, 32).expect("sparse"));
        let bitmap = Arc::new(ChunkBitmap::new(2));
        // Chunk 0 incomplete; download_done set means we should error.
        let download_done = Arc::new(AtomicBool::new(true));
        let outcome = Arc::new(Mutex::new(Some(Ok(DownloadStats::default()))));
        let mut reader = BlockingSparseReader::new(
            sparse,
            bitmap,
            16,
            32,
            0,
            download_done,
            outcome,
            Duration::from_millis(1),
        );
        let mut buf = [0u8; 32];
        let err = reader.read(&mut buf).expect_err("must error");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// §2.1: a [`BlockingSparseReader`] waiting for the next chunk to
    /// arrive must observe the kill switch within one `poll_interval`
    /// — otherwise SIGTERM hangs the pod through the full grace period.
    #[test]
    fn blocking_reader_returns_kill_sentinel_when_switch_trips() {
        let path = unique_temp("kill-poll");
        let _g = TmpFile(path.clone());
        // 32-byte file split into two 16-byte chunks. Chunk 0 is not
        // marked complete, so the reader will spin in the poll loop.
        let sparse = Arc::new(SparseFile::open_or_create(&path, 32).expect("sparse"));
        let bitmap = Arc::new(ChunkBitmap::new(2));
        let download_done = Arc::new(AtomicBool::new(false));
        let outcome = Arc::new(Mutex::new(None));
        let kill = Arc::new(AtomicBool::new(false));
        let mut reader = BlockingSparseReader::new(
            sparse,
            bitmap,
            16,
            32,
            0,
            download_done,
            outcome,
            Duration::from_millis(5),
        )
        .with_kill_switch(Arc::clone(&kill));

        // Spawn the read on a worker so the main thread can flip the
        // kill switch after the reader has started polling. A 1 s
        // sleep gives the reader several poll iterations before the
        // switch flips, so we exercise the in-loop poll site (not just
        // the entry-point check).
        let kill_for_worker = Arc::clone(&kill);
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let _ = kill_for_worker; // captured by reader.kill_switch
            let mut buf = [0u8; 32];
            let result = reader.read(&mut buf);
            let _ = tx.send(result);
        });
        std::thread::sleep(Duration::from_millis(50));
        kill.store(true, Ordering::Release);
        let result = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("kill switch should abort the read within 2s");
        let err = result.expect_err("must surface kill sentinel");
        assert_eq!(err.to_string(), "peel:kill-switch-tripped");
        handle.join().expect("worker join");
    }

    struct TmpFile(PathBuf);
    impl Drop for TmpFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    struct TmpDir(PathBuf);
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
