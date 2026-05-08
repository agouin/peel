//! Download-side machinery: the sparse file workers write into, the
//! scheduler that plans and dispatches chunk assignments, and the
//! worker that performs each ranged GET with retry/backoff.
//!
//! The pieces fit together top-down:
//!
//! - [`scheduler`] sits at the top — it does the discovery `HEAD`,
//!   plans chunks against [`crate::bitmap::ChunkBitmap`], and either
//!   spawns N parallel workers (when the server advertises
//!   `Accept-Ranges: bytes`) or falls back to a single streaming GET.
//! - [`worker`] owns the per-chunk transfer: ranged GET, response
//!   validation (Content-Range, Content-Length, ETag/Last-Modified),
//!   retry on transient failures, and the actual `pwrite_at` into the
//!   sparse file.
//! - [`sparse_file`] is the on-disk landing pad — sparse pre-allocation,
//!   concurrent offset-addressed writes, hole punching after
//!   checkpoint.
//!
//! The module is Linux/Unix-only because [`sparse_file::SparseFile`]
//! relies on POSIX `pread`/`pwrite` semantics for race-free concurrent
//! IO from worker threads. Windows support, when it lands, will follow
//! the same trait shape.

#![cfg(unix)]

pub mod chunk_fingerprints;
pub mod chunk_policy;
pub mod mirrors;
pub mod mmap_region;
pub mod multi_url;
pub mod rate_limit;
pub mod scheduler;
pub mod sevenz_pipeline;
pub mod sparse_file;
pub mod worker;
pub mod zip_pipeline;

pub use chunk_fingerprints::{ChunkFingerprints, FingerprintsDecodeError};
pub use chunk_policy::{
    ChunkSizePolicy, ResizeDecision, Sample, DEFAULT_INITIAL_DISPATCH_BYTES, HYSTERESIS,
    MAX_DISPATCH_BYTES, MIN_DISPATCH_BYTES,
};
pub use mirrors::{
    Mirror, MirrorSet, MirrorStats, DEFAULT_MIRROR_EXCLUDE_FOR, DEFAULT_MIRROR_PICK_DEADLINE,
};
pub use mmap_region::MmapRegion;
pub use multi_url::{
    DispatchSegments, MultiPartSource, MultiPartSourceError, PartDescriptor, PartSegment,
};
pub use rate_limit::{
    parse_bandwidth, ParseBandwidthError, RateLimitedReader, RateLimiter, MAX_PER_READ,
    MIN_CAPACITY,
};
pub use scheduler::{
    chunk_count, discover, discover_multi, discover_with_mirrors, run, DownloadInfo, DownloadMode,
    DownloadStats, MirrorAgreementError, ProbeConfig, SchedulerConfig, SchedulerError,
    DEFAULT_CHUNK_SIZE, DEFAULT_PROBE_INTERVAL, DEFAULT_WORKERS,
};
pub use sparse_file::{SparseFile, SparseFileError};
pub use worker::{
    ChunkFailure, ChunkOutcome, Dispatch, DispatchKind, RetryConfig, SourceFingerprint, WorkerError,
};
pub use zip_pipeline::{
    BoundedSparseReader, ZipExtractionStats, ZipPipeline, ZipPipelineConfig, ZipPipelineError,
    ZipPipelineEvent, ZipResumeState,
};
