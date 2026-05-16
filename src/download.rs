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
//! The module is cross-platform via the
//! [`crate::io_backend::IoBackend`] and [`crate::punch::PunchHole`]
//! seams: POSIX `pread`/`pwrite` on Unix and `seek_write`/`seek_read`
//! on Windows, both addressed by absolute offset and safe under
//! concurrent worker calls. Linux-only optimizations (mmap storage,
//! io_uring) live behind their own `target_os = "linux"` gates inside
//! the submodules (`PLAN_v3_windows.md` §3).

pub mod chunk_fingerprints;
pub mod chunk_policy;
pub mod mirrors;
// Linux-only mmap storage backend (`PLAN_v2.md` §9 /
// `PLAN_v3_windows.md` §3). Other platforms compile without it; the
// `SparseFile::open_or_create_mmap` constructor is itself gated on
// `target_os = "linux"`.
#[cfg(target_os = "linux")]
pub mod mmap_region;
pub mod multi_sparse;
pub mod multi_url;
// Container-format pipelines live behind their respective Cargo
// features (`internal/PLAN_rar.md` §0.5 / §3); the coordinator's
// dispatch sites are gated to match.
#[cfg(feature = "rar")]
pub mod rar_pipeline;
pub mod rate_limit;
pub mod scheduler;
#[cfg(feature = "sevenz")]
pub mod sevenz_pipeline;
pub mod sparse_file;
pub mod worker;
#[cfg(feature = "zip")]
pub mod zip_pipeline;

pub use chunk_fingerprints::{ChunkFingerprints, FingerprintsDecodeError};
pub use chunk_policy::{
    ChunkSizePolicy, ResizeDecision, Sample, DEFAULT_INITIAL_DISPATCH_BYTES, HYSTERESIS,
    MAX_DISPATCH_BYTES, MIN_DISPATCH_BYTES,
};
pub use mirrors::{
    Mirror, MirrorSet, MirrorStats, DEFAULT_MIRROR_EXCLUDE_FOR, DEFAULT_MIRROR_PICK_DEADLINE,
};
#[cfg(target_os = "linux")]
pub use mmap_region::MmapRegion;
pub use multi_sparse::{MultiSparse, MultiSparseError, RoutingPuncher};
pub use multi_url::{
    DispatchSegments, MultiPartSource, MultiPartSourceError, PartDescriptor, PartSegment,
};
#[cfg(feature = "rar")]
pub use rar_pipeline::{
    RarExtractionStats, RarPipeline, RarPipelineConfig, RarPipelineError, RarPipelineEvent,
    RarResumeState,
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
#[cfg(feature = "zip")]
pub use zip_pipeline::{
    BoundedSparseReader, ZipExtractionStats, ZipPipeline, ZipPipelineConfig, ZipPipelineError,
    ZipPipelineEvent, ZipResumeState,
};
