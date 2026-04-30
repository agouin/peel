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
//! - [`extractor`] (Unix only) — the [`extractor::Extractor`]
//!   coordinator that drives a decoder + sink + puncher loop and
//!   punches the source behind quiescent checkpoints.
//! - [`checkpoint`] — crash-safe persistence of a download +
//!   extraction in progress: the [`checkpoint::Checkpoint`] struct,
//!   its tiny custom binary format, and the atomic
//!   write-to-temp-then-rename dance that makes resume safe.
//! - [`coordinator`] (Unix only) — the §10 entry point that wires
//!   download + extractor + checkpoint into a single resumable
//!   pipeline. The `peel` binary calls into [`coordinator::run`]
//!   after parsing CLI flags.
//! - [`zip`] — ZIP archive support (parsers, sink, per-entry
//!   pipeline). ZIP's central-directory-at-the-end design forces a
//!   different pipeline shape than the streaming decoders in
//!   [`decode`]; see `docs/PLAN_v2.md` §5.
//! - [`progress`] — multi-field progress tracking (`PLAN_v2.md` §6):
//!   shared `ProgressState` updated by writers (workers, extractor,
//!   ZIP pipeline) plus a TTY / log renderer the binary spawns at
//!   the boundary.
//! - [`download::chunk_policy`] (Unix only) — adaptive chunk-size
//!   policy (`PLAN_v2.md` §8): a ring-buffered observer of recent
//!   per-dispatch latencies and retries that decides when to grow
//!   or shrink the size of each ranged GET. The scheduler queries
//!   `ChunkSizePolicy::current()` when planning a dispatch and feeds
//!   completion samples back via `record`. Default-on, with
//!   `--chunk-size <N>` and `--no-adaptive-chunk-size` CLI escape
//!   hatches.
//! - [`io_backend`] (Unix only) — file-IO and network-IO seam
//!   (`PLAN_v2.md` §7 + §7b): the [`io_backend::IoBackend`] trait
//!   every backend honors, the always-available
//!   [`io_backend::BlockingBackend`] wrapping `pwrite`/`pread`/`fsync`
//!   and `TcpStream::connect_timeout`, and (Linux only) the
//!   `io_backend::UringBackend` that batches both file IO and the HTTP
//!   client's TCP `recv`/`send` through a dedicated IO thread sharing
//!   one ring. The `--io-backend` CLI flag picks between `auto`
//!   (default; tries uring, falls back to blocking with a warning),
//!   `blocking`, and `uring`.
//!
//! [`docs/PLAN.md`]: https://github.com/agouin/peel/blob/main/docs/PLAN.md
//! [`docs/ENGINEERING_STANDARDS.md`]: https://github.com/agouin/peel/blob/main/docs/ENGINEERING_STANDARDS.md

#![deny(missing_docs)]
#![warn(unused, clippy::all)]

pub mod bitmap;
pub mod checkpoint;
#[cfg(unix)]
pub mod cli;
#[cfg(unix)]
pub mod coordinator;
pub mod decode;
#[cfg(unix)]
pub mod download;
pub mod error;
#[cfg(unix)]
pub mod extractor;
pub mod http;
#[cfg(unix)]
pub mod io_backend;
pub mod progress;
#[cfg(unix)]
pub mod punch;
pub mod sink;
pub mod types;
pub mod zip;
