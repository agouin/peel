//! Sinks consume the bytes a [`crate::decode::StreamingDecoder`] emits
//! and turn them into something durable on disk.
//!
//! The trait is deliberately narrow:
//!
//! - [`Sink::write`] feeds the next chunk of decoded bytes. Calls are
//!   *byte-streaming*: an implementation must produce identical results
//!   regardless of how the same byte sequence is split across calls. The
//!   coordinator and the decoder both have their own buffering and
//!   neither aligns writes to any meaningful boundary.
//! - [`Sink::is_quiescent`] reports whether the sink is at a
//!   checkpoint-safe boundary — for [`raw::RawSink`] that is "always",
//!   for [`tar::TarSink`] it is "between members". The coordinator pairs
//!   this with [`crate::decode::StreamingDecoder::frame_boundary`] to
//!   align checkpoints with restart points that produce byte-identical
//!   output on resume.
//! - [`Sink::close`] is the post-condition: every byte fed in has been
//!   durably written and any deferred validation (final tar
//!   end-of-archive marker, final flush) has completed. Implementations
//!   are not expected to be idempotent across calls; the coordinator
//!   calls `close` exactly once on a successful run.
//!
//! # Implementations
//!
//! - [`raw::RawSink`] — writes every byte to a single output file.
//!   Always quiescent. The right choice when the source decompresses to
//!   one stream of bytes (`.zst`, `.gz` of a single file).
//! - [`tar::TarSink`] — streaming tar extractor. Hand-rolled because
//!   member-aligned quiescence is part of the contract and the upstream
//!   `tar` crate does not expose it. Quiescent between members.
//! - [`zip::ZipSink`] — per-entry ZIP extractor. Driven by the ZIP
//!   pipeline rather than via the [`Sink`] trait (ZIP entries arrive
//!   in discrete, pre-sized chunks rather than as one byte stream),
//!   but enforces the same path-safety rules and is quiescent
//!   between entries. See `docs/PLAN_v2.md` §5.
//!
//! # Errors
//!
//! All implementations return [`SinkError`]. The variants are specific
//! per `docs/ENGINEERING_BEST_PRACTICES.md` §3.1: a caller looking at a
//! sink failure can tell whether the failure is in the source archive
//! (malformed header, bad checksum), in the entry being written
//! (unsafe path, unsupported type), or in the local environment (IO).

pub mod raw;
pub mod sevenz;
pub mod tar;
pub mod zip;

pub use raw::RawSink;
pub use sevenz::SevenzSink;
pub use tar::TarSink;
pub use zip::{BeginEntryOutcome, EntryFinalize, ZipSink};

use std::path::PathBuf;

use thiserror::Error;

use crate::checkpoint::SinkState;

/// Errors produced by [`Sink`] implementations.
///
/// Each variant carries enough structured context that the message alone
/// is debuggable. Variants that only apply to the streaming tar sink
/// (header parsing, path escape) live here rather than in a separate
/// `TarSinkError` so callers can use one `match` for the whole sink
/// surface; in practice [`raw::RawSink`] only ever returns [`Self::Io`].
#[derive(Debug, Error)]
pub enum SinkError {
    /// A file-system IO call failed.
    #[error("io error operating on {path}")]
    Io {
        /// Path being operated on when the error surfaced.
        path: PathBuf,
        /// The underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// A tar entry's name normalized to a path that escapes the
    /// extraction root.
    ///
    /// Triggered by absolute paths, paths with `..` components, and
    /// paths that resolve to `root` itself. The check is purely
    /// lexical — it does not depend on filesystem state — and is
    /// deliberately stricter than POSIX `realpath`.
    #[error("entry {entry:?} escapes the extraction root {root}")]
    PathEscape {
        /// The original entry name from the archive.
        entry: String,
        /// The extraction root configured on the sink.
        root: PathBuf,
    },

    /// A tar header was malformed (bad magic, non-octal numeric field,
    /// invalid PAX framing, etc.).
    #[error("malformed tar header at archive offset {archive_offset}: {reason}")]
    MalformedHeader {
        /// Byte offset of the failing header within the archive.
        archive_offset: u64,
        /// Human-readable reason; already includes the field name when
        /// the failure is field-local.
        reason: String,
    },

    /// The header's recorded checksum did not match the bytes on the
    /// wire.
    #[error(
        "tar header checksum mismatch at archive offset {archive_offset}: \
         expected {expected:#o}, computed {computed:#o}"
    )]
    BadChecksum {
        /// Byte offset of the failing header within the archive.
        archive_offset: u64,
        /// Octal value the header recorded in its `chksum` field.
        expected: u32,
        /// The checksum we computed over the bytes received.
        computed: u32,
    },

    /// The tar entry uses a typeflag that the sink does not extract
    /// under the MVP scope (symlinks, hard links, device nodes,
    /// fifos).
    ///
    /// `docs/PLAN.md` §7 explicitly defers these; this variant lets
    /// callers detect the condition without scanning a free-form
    /// message.
    #[error("unsupported tar entry type {type_flag:?} for {entry:?}")]
    UnsupportedEntry {
        /// The raw `typeflag` byte from the header.
        type_flag: u8,
        /// The entry name (post PAX override) as a debug-printable
        /// string.
        entry: String,
    },

    /// A PAX 'x' extended header could not be parsed (length prefix
    /// out of range, missing `=`, value the sink cannot apply, …).
    #[error("malformed PAX extended header at archive offset {archive_offset}: {reason}")]
    MalformedPax {
        /// Byte offset of the failing PAX header within the archive.
        archive_offset: u64,
        /// Human-readable reason; field/key context included where
        /// available.
        reason: String,
    },

    /// The decoder fed bytes after the archive's end-of-archive marker
    /// (two consecutive zero blocks). Most real-world archives stop
    /// cleanly; trailing bytes indicate either a corrupted archive or
    /// a programmer error in the upstream pipeline.
    #[error("trailing data after end-of-archive marker at offset {archive_offset}")]
    TrailingData {
        /// Byte offset within the archive at which the trailing bytes
        /// started.
        archive_offset: u64,
    },

    /// The archive ended in the middle of an entry (header or body).
    #[error(
        "archive ended mid-entry at offset {archive_offset} (\
         {bytes_remaining} bytes still expected)"
    )]
    UnexpectedEof {
        /// Byte offset within the archive when EOF was observed.
        archive_offset: u64,
        /// Number of bytes the parser was still expecting to receive.
        bytes_remaining: u64,
    },
}

/// A streaming destination for decoded bytes.
///
/// Implementations buffer internally as needed and surface errors
/// either inline from [`Self::write`] (the common case) or, for
/// implementations that batch validation, deferred to [`Self::close`].
///
/// Implementations are `Send` so the coordinator can move the sink to a
/// dedicated extractor thread without `Arc<Mutex<…>>` plumbing.
pub trait Sink: Send {
    /// Append `buf` to the sink.
    ///
    /// Implementations must produce byte-identical results regardless
    /// of how the source byte stream is split across calls — the
    /// streaming tar parser, in particular, accepts arbitrary chunk
    /// boundaries.
    ///
    /// # Errors
    ///
    /// Returns the appropriate [`SinkError`] variant. Implementations
    /// move into a poisoned state on the first error and reject all
    /// subsequent writes; the coordinator surfaces the original error
    /// rather than retrying.
    fn write(&mut self, buf: &[u8]) -> Result<(), SinkError>;

    /// True when the sink is at a checkpoint-safe boundary.
    ///
    /// The coordinator pairs this with the decoder's frame-boundary
    /// observation to decide when to flush a checkpoint. A sink that
    /// reports `false` simply defers the next checkpoint to the next
    /// quiescent moment.
    ///
    /// Sinks that support full mid-stream resume (i.e. their
    /// [`Self::sink_state`] captures enough state to restart from
    /// any byte position) may return `true` unconditionally.
    fn is_quiescent(&self) -> bool;

    /// Snapshot of the sink's resume state at the current moment.
    ///
    /// Called by the coordinator's checkpoint observer at every
    /// quiescent advance; the returned [`SinkState`] is persisted
    /// verbatim into the checkpoint file. The companion construction
    /// path (e.g. `RawSink::resume`, `TarSink::resume`) consumes the
    /// same shape on the next invocation to pick up where the
    /// killed run left off.
    ///
    /// Implementations must produce a state whose corresponding
    /// resume constructor reproduces the sink's *exact* on-disk
    /// effect for any subsequent input bytes — i.e. byte-identical
    /// extraction across kill-resume boundaries.
    fn sink_state(&self) -> SinkState;

    /// Finalize the sink.
    ///
    /// Called exactly once on a successful run after every input byte
    /// has been fed via [`Self::write`]. Implementations validate the
    /// final state (e.g. the tar parser checks that it observed the
    /// end-of-archive marker) and flush any pending writes.
    ///
    /// # Errors
    ///
    /// Returns the [`SinkError`] variant matching the deferred check
    /// that failed; for [`raw::RawSink`] this is the flush errno.
    fn close(self) -> Result<(), SinkError>;
}
