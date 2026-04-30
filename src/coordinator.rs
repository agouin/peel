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
    CheckpointInfo, ExtractionStats, Extractor, ExtractorConfig, ExtractorError,
    DEFAULT_PUNCH_THRESHOLD,
};
use crate::http::{Client, ClientError, Url, UrlError};
use crate::progress::ProgressState;
use crate::punch::{default_puncher, NoopPuncher, PunchHole};
use crate::sink::{RawSink, Sink, SinkError, TarSink, ZipSink};
use crate::types::{ByteOffset, ChunkIndex};
use crate::zip::FORMAT_NAME as ZIP_FORMAT_NAME;

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

    /// `true` when this target is a tar extraction directory.
    fn is_dir(&self) -> bool {
        matches!(self, Self::Dir(_))
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
        }
    }
}

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
    } = args;

    let parsed_url = Url::parse(&url).map_err(|source| CoordinatorError::InvalidUrl {
        url: url.clone(),
        source,
    })?;

    // Resolve the IO backend up front so it can be shared by the HTTP
    // client (sockets) and the sparse file (file IO). select_backend
    // is the single place where the user's --io-backend choice is
    // materialized; logging/warning side effects fire inside it.
    let io_backend = crate::io_backend::select_backend(config.io_backend, config.workers)
        .map_err(CoordinatorError::IoBackend)?;
    let client = client
        .with_backend(Arc::clone(&io_backend))
        .map_err(CoordinatorError::Client)?;

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
    let resume_plan = build_resume_plan(prior.as_ref(), &info, &url, &config, &output)?;
    let resuming = matches!(resume_plan, ResumePlan::Resume { .. });

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
    };

    let download_done = Arc::new(AtomicBool::new(false));
    let download_outcome: Arc<Mutex<Option<Result<DownloadStats, SchedulerError>>>> =
        Arc::new(Mutex::new(None));

    let total_size = info.total_size;
    let chunk_size = config.chunk_size;

    let extraction_outcome =
        thread::scope(|scope| -> Result<ExtractionOutcome, CoordinatorError> {
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
                let mut decoder = factory(source).map_err(CoordinatorError::Decode)?;

                // Run the extractor with a checkpoint observer that
                // writes a durable checkpoint every time the cadence
                // floor fires.
                let extractor = {
                    let base = Extractor::new(ExtractorConfig {
                        punch_threshold: config.punch_threshold,
                    });
                    match progress_state.clone() {
                        Some(state) => base.with_progress(state),
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
                            &output,
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
                            &output,
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

            Ok(ExtractionOutcome {
                extraction: extraction_stats,
                download: download_stats,
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
}

/// What [`build_resume_plan`] decides to do with a prior checkpoint.
#[derive(Debug)]
enum ResumePlan {
    Fresh,
    Resume {
        decoder_position: u64,
        bitmap_bytes: Vec<u8>,
        sink_state: SinkState,
        chunk_crc32c: Option<Vec<u32>>,
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
/// On resume we just construct a fresh sink: the decoded byte stream
/// picks up at a member boundary (the checkpoint discipline guarantees
/// that), so the sink starts processing the next member's header
/// immediately. Already-extracted members on disk are left alone.
fn build_tar_sink(path: &Path, _plan: &ResumePlan) -> Result<TarSink, CoordinatorError> {
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
    output: &OutputTarget,
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
    // Sentinel io::Error message used when the kill switch fires; the
    // caller pattern-matches on this to surface a typed
    // `CoordinatorError::Aborted` rather than a generic Extractor
    // failure.
    const KILL_SENTINEL: &str = "peel:kill-switch-tripped";

    let result = extractor.extract_with_callback(
        sparse.as_fd(),
        decoder,
        sink,
        puncher,
        |info_cb: CheckpointInfo| -> io::Result<()> {
            // Throttle: write at most once per cadence floor.
            let elapsed = last_write_at.elapsed();
            let progressed = info_cb.source_position.saturating_sub(last_position);
            if progressed < config.checkpoint_min_bytes && elapsed < config.checkpoint_min_interval
            {
                return Ok(());
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

            let sink_state = sink_state_for(output, info_cb.bytes_out);
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
            Ok(())
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
    const KILL_SENTINEL: &str = "peel:kill-switch-tripped";

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
        Err(crate::download::WorkerError::SourceDriftDetected {
            chunk,
            expected,
            actual,
        }) => Err(CoordinatorError::SourceChangedSinceCheckpoint {
            chunk,
            expected,
            actual,
        }),
        Err(other) => Err(CoordinatorError::Scheduler(SchedulerError::ChunkFailed {
            chunk,
            attempts: 1,
            source: other,
        })),
    }
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

/// Compute the appropriate [`SinkState`] for the configured output and
/// the current sink-byte counter. Tar's `members_completed` is left
/// empty here; we don't track member names through the extractor's
/// callback in the MVP. The on-disk artifacts are what carry the
/// resume signal for tar.
fn sink_state_for(output: &OutputTarget, bytes_out: u64) -> SinkState {
    if output.is_dir() {
        SinkState::Tar {
            members_completed: Vec::new(),
        }
    } else {
        SinkState::Raw {
            bytes_written: bytes_out,
        }
    }
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
        }
    }
}

impl Read for BlockingSparseReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
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
                            return Err(io::Error::other(format!("download failed: {e}")));
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
            self.cursor.fetch_add(n as u64, Ordering::Release);
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
) -> Result<Vec<u8>, CoordinatorError> {
    if max_window == 0 || total_size == 0 || chunk_size == 0 {
        return Ok(Vec::new());
    }
    let want = (max_window as u64).min(total_size);
    // Number of chunks required to cover offset 0..want. For typical
    // configs this is exactly 1 (chunk_size ≫ max_window).
    // INVARIANT: chunk_size > 0 (checked above) so div_ceil is sound.
    let chunks_needed = u32::try_from(want.div_ceil(chunk_size).max(1)).unwrap_or(u32::MAX);
    for i in 0..chunks_needed {
        let idx = ChunkIndex::new(i);
        loop {
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
            },
            hash_state: None,
            chunk_crc32c: None,
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

    struct TmpFile(PathBuf);
    impl Drop for TmpFile {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }
}
