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

pub mod chunk_policy;
pub mod mmap_region;
pub mod scheduler;
pub mod sparse_file;
pub mod worker;
pub mod zip_pipeline;

pub use chunk_policy::{
    ChunkSizePolicy, ResizeDecision, Sample, DEFAULT_INITIAL_DISPATCH_BYTES, HYSTERESIS,
    MAX_DISPATCH_BYTES, MIN_DISPATCH_BYTES,
};
pub use mmap_region::MmapRegion;
pub use scheduler::{
    chunk_count, discover, run, DownloadInfo, DownloadMode, DownloadStats, SchedulerConfig,
    SchedulerError, DEFAULT_CHUNK_SIZE, DEFAULT_WORKERS,
};
pub use sparse_file::{SparseFile, SparseFileError};
pub use worker::{ChunkOutcome, Dispatch, RetryConfig, SourceFingerprint, WorkerError};
pub use zip_pipeline::{
    BoundedSparseReader, ZipExtractionStats, ZipPipeline, ZipPipelineConfig, ZipPipelineError,
    ZipPipelineEvent, ZipResumeState,
};
