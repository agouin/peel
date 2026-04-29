//! Download-side machinery: the sparse file workers write into, and
//! eventually the scheduler/worker pool that performs the ranged HTTP
//! GETs.
//!
//! The MVP plan introduces these in stages (see `docs/PLAN.md` §3, §5);
//! at the current checkpoint only [`sparse_file`] exists. Everything
//! else is a deliberately empty future home.
//!
//! Today the module is Linux/Unix-only because [`sparse_file::SparseFile`]
//! relies on POSIX `pread`/`pwrite` semantics for race-free concurrent
//! IO from worker threads. Windows support, when it lands, will follow
//! the same trait shape.

#![cfg(unix)]

pub mod sparse_file;

pub use sparse_file::{SparseFile, SparseFileError};
