//! `pux` — streaming, resumable, space-efficient extraction of compressed
//! archives downloaded over HTTP.
//!
//! See [`docs/PLAN.md`] in the repository for the implementation plan and
//! [`docs/ENGINEERING_STANDARDS.md`] for the rules every module follows.
//!
//! # Layering
//!
//! Each module is added in the order described by the plan; this crate
//! root grows as new layers come online. The current layers are:
//!
//! - [`types`] — strongly-typed primitives (`ByteOffset`, `ChunkIndex`,
//!   `ByteRange`) shared across the codebase.
//! - [`error`] — documentation of the per-module typed-error convention.
//! - [`punch`] (Unix only) — the `PunchHole` trait and Linux/no-op
//!   implementations used to release blocks of the compressed source as
//!   the decoder advances.
//!
//! Future modules (`bitmap`, `checkpoint`, `http`, `download`,
//! `decode`, `sink`, `extractor`, `coordinator`) are introduced one
//! plan section at a time. Until they exist, the binary in
//! [`main.rs`](../src/main.rs) is intentionally a stub.
//!
//! [`docs/PLAN.md`]: https://github.com/ondofinance/pux/blob/main/docs/PLAN.md
//! [`docs/ENGINEERING_STANDARDS.md`]: https://github.com/ondofinance/pux/blob/main/docs/ENGINEERING_STANDARDS.md

#![deny(missing_docs)]
#![warn(unused, clippy::all)]

pub mod error;
#[cfg(unix)]
pub mod punch;
pub mod types;
