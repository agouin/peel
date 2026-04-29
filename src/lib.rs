//! `peel` — streaming, resumable, space-efficient extraction of compressed
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
//! - [`bitmap`] — lock-free chunk completion bitmap shared across the
//!   download workers, scheduler, and decoder.
//! - [`download`] (Unix only) — the sparse output file, the chunk
//!   scheduler, and the per-chunk worker that issues ranged GETs.
//! - [`http`] — hand-rolled HTTP/1.1 client with connection pooling and
//!   TLS via `rustls`, plus the typed [`http::request`] /
//!   [`http::response`] / [`http::range`] / [`http::url`] support
//!   modules.
//! - [`decode`] — the [`decode::StreamingDecoder`] protocol every
//!   format-specific decoder honors, plus the in-tree zstd
//!   implementation and a suffix-keyed [`decode::DecoderRegistry`].
//! - [`sink`] — the [`sink::Sink`] trait every extraction target
//!   honors, the always-quiescent [`sink::RawSink`], and the
//!   member-aligned streaming [`sink::TarSink`].
//!
//! Future modules (`checkpoint`, `extractor`, `coordinator`) are
//! introduced one plan section at a time. Until they exist, the
//! binary in [`main.rs`](../src/main.rs) is intentionally a stub.
//!
//! [`docs/PLAN.md`]: https://github.com/agouin/peel/blob/main/docs/PLAN.md
//! [`docs/ENGINEERING_STANDARDS.md`]: https://github.com/agouin/peel/blob/main/docs/ENGINEERING_STANDARDS.md

#![deny(missing_docs)]
#![warn(unused, clippy::all)]

pub mod bitmap;
pub mod decode;
#[cfg(unix)]
pub mod download;
pub mod error;
pub mod http;
#[cfg(unix)]
pub mod punch;
pub mod sink;
pub mod types;
