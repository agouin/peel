//! `peel` — streaming, resumable, space-efficient extraction of compressed
//! archives downloaded over HTTP.
//!
//! See [`internal/PLAN.md`] in the repository for the implementation plan and
//! [`internal/ENGINEERING_STANDARDS.md`] for the rules every module follows.
//!
//! # Layering
//!
//! Each module is added in the order described by the plan; this crate
//! root grows as new layers come online. The current layers are:
//!
//! - [`types`] — strongly-typed primitives (`ByteOffset`, `ChunkIndex`,
//!   `ByteRange`) shared across the codebase.
//! - [`error`] — documentation of the per-module typed-error convention.
//! - [`punch`] — the [`punch::PunchHole`] trait and the
//!   Linux (`fallocate(PUNCH_HOLE)` + `madvise(MADV_REMOVE)`),
//!   macOS (`fcntl(F_PUNCHHOLE)`), Windows
//!   (`DeviceIoControl(FSCTL_SET_ZERO_DATA)`, `PLAN_v3_windows.md`
//!   §4) and [`punch::NoopPuncher`] implementations used to release
//!   blocks of the compressed source as the decoder advances.
//!
//! - [`os_fd`] — portable [`os_fd::OsFd`] borrowed-handle alias and
//!   [`os_fd::AsOsFd`] trait used by the [`punch::PunchHole`] and
//!   [`io_backend::IoBackend`] trait surfaces. Resolves to
//!   [`std::os::fd::BorrowedFd`] on Unix and
//!   [`std::os::windows::io::BorrowedHandle`] on Windows; the alias
//!   shape lets the trait signatures be portable without a second
//!   flavor per platform (`PLAN_v3_windows.md` §0.2).
//! - [`bitmap`] — lock-free chunk completion bitmap shared across the
//!   download workers, scheduler, and decoder.
//! - [`download`] — the sparse output file, the chunk
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
//! - [`extractor`] — the [`extractor::Extractor`]
//!   coordinator that drives a decoder + sink + puncher loop and
//!   punches the source behind quiescent checkpoints.
//! - [`checkpoint`] — crash-safe persistence of a download +
//!   extraction in progress: the [`checkpoint::Checkpoint`] struct,
//!   its tiny custom binary format, and the atomic
//!   write-to-temp-then-rename dance that makes resume safe.
//! - [`coordinator`] — the §10 entry point that wires
//!   download + extractor + checkpoint into a single resumable
//!   pipeline. The `peel` binary calls into [`coordinator::run`]
//!   after parsing CLI flags.
//! - [`zip`] — ZIP archive support (parsers, sink, per-entry
//!   pipeline). ZIP's central-directory-at-the-end design forces a
//!   different pipeline shape than the streaming decoders in
//!   [`decode`]; see `internal/PLAN_v2.md` §5.
//! - [`progress`] — multi-field progress tracking (`PLAN_v2.md` §6):
//!   shared `ProgressState` updated by writers (workers, extractor,
//!   ZIP pipeline) plus a TTY / log renderer the binary spawns at
//!   the boundary.
//! - [`download::chunk_policy`] — adaptive chunk-size
//!   policy (`PLAN_v2.md` §8): a ring-buffered observer of recent
//!   per-dispatch latencies and retries that decides when to grow
//!   or shrink the size of each ranged GET. The scheduler queries
//!   `ChunkSizePolicy::current()` when planning a dispatch and feeds
//!   completion samples back via `record`. Default-on, with
//!   `--chunk-size <N>` and `--no-adaptive-chunk-size` CLI escape
//!   hatches.
//! - [`hash`] — integrity hashing primitives. Currently hosts a
//!   hand-rolled SHA-256 with serializable mid-stream state
//!   (`PLAN_v2.md` §10) used by the `--sha256 <hex>` flag.
//! - [`download::rate_limit`] — aggregate bandwidth
//!   limiter (`PLAN_v2.md` §14): a token-bucket
//!   [`download::RateLimiter`] shared across every worker (and
//!   every mirror) plus a [`download::RateLimitedReader`] adapter
//!   the worker wraps the response body in. The `--max-bandwidth
//!   <RATE>` CLI flag opts in; the cap is aggregate, not per-mirror.
//! - [`io_backend`] — file-IO and network-IO seam
//!   (`PLAN_v2.md` §7 + §7b + §9): the [`io_backend::IoBackend`] trait
//!   every backend honors and the always-available
//!   [`io_backend::BlockingBackend`] wrapping `pwrite`/`pread`/`fsync`
//!   (Unix) or `seek_write`/`seek_read`/`FlushFileBuffers` (Windows,
//!   `PLAN_v3_windows.md` §2) and `TcpStream::connect_timeout`. The
//!   Linux-only `io_backend::UringBackend` batches both file IO and
//!   the HTTP client's TCP `recv`/`send` through a dedicated IO thread
//!   sharing one ring. A fourth choice — `mmap` (Linux only,
//!   `PLAN_v2.md` §9) — switches the sparse file's storage to a
//!   `MAP_SHARED` mapping with `madvise(MADV_REMOVE)` punching while
//!   leaving the socket path on the blocking backend. The
//!   `--io-backend` CLI flag picks between `auto` (default; tries
//!   uring, falls back to blocking with a warning), `blocking`,
//!   `uring`, and `mmap`. On Windows `auto` and `blocking` both
//!   resolve to the blocking backend; `uring` and `mmap` error
//!   cleanly the way they do on macOS.
//! - [`rar`] — RAR5 archive support (`internal/PLAN_rar.md`). Round-one
//!   ships the hand-rolled framing layer (§1), BLAKE2sp file-data
//!   integrity (§2), the STORED-method pipeline (§3), and a
//!   hand-rolled RAR5 decompressor (§4 / `PLAN_rar5_decoder.md`).
//!   Gated behind the `rar` Cargo feature, on by default; building
//!   `--no-default-features` drops the decoder LOC from the binary
//!   while still surfacing a precise "compiled without RAR support"
//!   diagnostic for `.rar` URLs.
//!
//! [`internal/PLAN.md`]: https://github.com/agouin/peel/blob/main/internal/PLAN.md
//! [`internal/ENGINEERING_STANDARDS.md`]: https://github.com/agouin/peel/blob/main/internal/ENGINEERING_STANDARDS.md

#![deny(missing_docs)]
#![warn(unused, clippy::all)]

pub mod bitmap;
pub mod checkpoint;
pub mod cli;
pub mod coordinator;
pub mod crypto;
pub mod decode;
pub mod download;
pub mod encryption;
pub mod error;
pub mod extractor;
pub mod hash;
pub mod http;
pub mod io_backend;
pub mod multivolume;
pub mod os_fd;
pub mod progress;
pub mod punch;
pub mod rar;
pub mod secret;
pub mod sevenz;
pub mod sink;
pub mod types;
pub mod zip;
