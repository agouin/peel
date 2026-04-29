//! File-IO backend abstraction (PLAN_v2.md §7).
//!
//! `peel`'s download workers and the [`crate::download::SparseFile`]
//! land bytes on disk through `pwrite(2)` / `pread(2)` syscalls. At
//! high parallelism (the §7 demo runs N=64 workers) every chunk
//! completion costs at least one trip into the kernel for the write
//! and one for the metadata sync; that pile of independent syscalls
//! is what `io_uring` exists to batch.
//!
//! This module introduces [`IoBackend`], the seam every backend
//! implementation honors, and ships [`BlockingBackend`] — the
//! always-available implementation that wraps the existing `FileExt`
//! calls verbatim. The Linux `io_uring` backend lands behind this same
//! trait in §7.2 and the network-IO half (TCP `connect`/`send`/`recv`)
//! is the subject of §7b. The trait stays narrow on purpose: file IO
//! only, no socket primitives, no shape that requires an async runtime.
//!
//! # Threading
//!
//! Every method takes `&self`, so a single `Arc<dyn IoBackend>` can be
//! handed to the [`crate::download`] scheduler, the worker pool, and
//! the extractor without further synchronization. Implementations are
//! `Send + Sync`; the blocking impl is in fact zero-sized and the
//! `Arc` is just type-machinery.
//!
//! # Why `BorrowedFd`
//!
//! The trait operates on a [`BorrowedFd`] rather than `&File` so the
//! io_uring backend can submit SQEs against the kernel-side fd
//! directly. The blocking backend rebuilds a temporary [`File`] handle
//! around the borrowed fd via [`ManuallyDrop`] so we get the safe
//! [`FileExt`] surface without taking ownership of the underlying
//! descriptor.

#![cfg(unix)]

use std::fs::File;
use std::io;
use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd};
use std::os::unix::fs::FileExt;
use std::sync::Arc;

/// File-IO operations performed by the download workers and the
/// sparse file.
///
/// Implementations are object-safe and `Send + Sync`. A single shared
/// backend (typically held in an [`Arc`]) is cloned into every thread
/// that touches disk; the worker pool, the scheduler, and the extractor
/// all route through the same backend so the choice of implementation
/// is observable end-to-end.
///
/// [`std::fmt::Debug`] is required so structs that hold an
/// `Arc<dyn IoBackend>` (e.g. [`crate::download::SparseFile`]) can
/// derive `Debug` without manual plumbing.
pub trait IoBackend: Send + Sync + std::fmt::Debug {
    /// Diagnostic name (e.g. `"blocking"`, `"uring"`).
    ///
    /// Used in `tracing` log lines and surfaced in the `--io-backend`
    /// CLI flag.
    fn name(&self) -> &'static str;

    /// Write the entire `buf` at byte offset `offset`.
    ///
    /// Loops on partial writes; returns only after every byte has been
    /// committed (or an error fires). Equivalent in semantics to
    /// [`FileExt::write_all_at`].
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] for any OS-level failure
    /// (e.g. `EIO`, `ENOSPC`).
    fn pwrite_all_at(&self, fd: BorrowedFd<'_>, offset: u64, buf: &[u8]) -> io::Result<()>;

    /// Read up to `buf.len()` bytes starting at `offset` and return
    /// the number actually read.
    ///
    /// Short reads at end-of-file are reported by a return value less
    /// than `buf.len()`; a return value of `0` is the EOF indicator.
    /// Equivalent in semantics to [`FileExt::read_at`].
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] for any OS-level failure.
    fn pread_at(&self, fd: BorrowedFd<'_>, offset: u64, buf: &mut [u8]) -> io::Result<usize>;

    /// Read exactly `buf.len()` bytes starting at `offset`, looping on
    /// short reads.
    ///
    /// Equivalent in semantics to [`FileExt::read_exact_at`].
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::UnexpectedEof`] if EOF is reached
    /// before the buffer is filled, or any other [`io::Error`] for an
    /// OS-level failure.
    fn pread_exact_at(&self, fd: BorrowedFd<'_>, offset: u64, buf: &mut [u8]) -> io::Result<()>;

    /// Force the file's data and metadata to durable storage.
    ///
    /// Equivalent in semantics to [`File::sync_all`].
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] for any OS-level failure.
    fn sync_all(&self, fd: BorrowedFd<'_>) -> io::Result<()>;
}

/// Construct the default backend for the current platform.
///
/// In §7.1 this always returns a [`BlockingBackend`]. The §7.2
/// io_uring backend introduces selection logic (capability probe +
/// CLI override) that picks the best available implementation.
#[must_use]
pub fn default_backend() -> Arc<dyn IoBackend> {
    Arc::new(BlockingBackend::new())
}

/// The always-available blocking backend.
///
/// Wraps the existing `FileExt::{write_all_at, read_at, read_exact_at}`
/// calls and `File::sync_all`. Behaviorally indistinguishable from the
/// pre-§7 code; the indirection only matters for the `io_uring` backend
/// added in §7.2.
#[derive(Debug, Default, Clone, Copy)]
pub struct BlockingBackend;

impl BlockingBackend {
    /// Construct a fresh [`BlockingBackend`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl IoBackend for BlockingBackend {
    fn name(&self) -> &'static str {
        "blocking"
    }

    fn pwrite_all_at(&self, fd: BorrowedFd<'_>, offset: u64, buf: &[u8]) -> io::Result<()> {
        with_file(fd, |f| f.write_all_at(buf, offset))
    }

    fn pread_at(&self, fd: BorrowedFd<'_>, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        with_file(fd, |f| f.read_at(buf, offset))
    }

    fn pread_exact_at(&self, fd: BorrowedFd<'_>, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        with_file(fd, |f| f.read_exact_at(buf, offset))
    }

    fn sync_all(&self, fd: BorrowedFd<'_>) -> io::Result<()> {
        with_file(fd, File::sync_all)
    }
}

/// Run `f` against a [`File`] view of `fd` without taking ownership.
///
/// `BorrowedFd<'_>` only carries the lifetime invariant that the fd is
/// open for the borrow's duration. To call the safe [`FileExt`] /
/// [`File::sync_all`] surface we need a `&File`, which would normally
/// own the fd. We construct one via [`File::from_raw_fd`] and wrap it
/// in [`ManuallyDrop`] so the destructor — which would `close(2)` the
/// fd — never fires. The borrowed fd's lifetime governs the whole call.
fn with_file<R>(fd: BorrowedFd<'_>, f: impl FnOnce(&File) -> R) -> R {
    // SAFETY: `BorrowedFd<'_>` guarantees `fd.as_raw_fd()` is a valid,
    // open file descriptor for the duration of the borrow. We hand it
    // to `File::from_raw_fd`, which would normally take ownership and
    // close the fd on drop; wrapping the result in `ManuallyDrop`
    // suppresses the destructor so the fd stays open and the borrow is
    // honored. The closure receives only an `&File`, never an owned
    // `File`, so it cannot escape the wrapper.
    let file = ManuallyDrop::new(unsafe { File::from_raw_fd(fd.as_raw_fd()) });
    f(&file)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::fd::AsFd;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Process-unique counter so concurrent test threads do not collide
    /// on temp filenames.
    static UNIQ: AtomicU64 = AtomicU64::new(0);

    fn unique_temp_path(label: &str) -> std::path::PathBuf {
        let pid = std::process::id();
        let n = UNIQ.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("peel_iobackend_{label}_{pid}_{nanos}_{n}.bin"))
    }

    struct CleanupOnDrop(std::path::PathBuf);
    impl Drop for CleanupOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn open_temp(label: &str, len: u64) -> (File, CleanupOnDrop) {
        let path = unique_temp_path(label);
        let cleanup = CleanupOnDrop(path.clone());
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .expect("open temp");
        file.set_len(len).expect("set_len");
        (file, cleanup)
    }

    #[test]
    fn blocking_name_is_blocking() {
        let b = BlockingBackend::new();
        assert_eq!(b.name(), "blocking");
    }

    #[test]
    fn default_backend_is_blocking() {
        let b = default_backend();
        assert_eq!(b.name(), "blocking");
    }

    #[test]
    fn pwrite_all_at_writes_full_buffer() {
        let (mut file, _cleanup) = open_temp("pwrite_full", 1024);
        let backend = BlockingBackend::new();
        let payload: Vec<u8> = (0u8..32).collect();
        backend
            .pwrite_all_at(file.as_fd(), 64, &payload)
            .expect("pwrite");
        file.seek(SeekFrom::Start(64)).expect("seek");
        let mut got = vec![0u8; 32];
        file.read_exact(&mut got).expect("read");
        assert_eq!(got, payload);
    }

    #[test]
    fn pread_at_returns_bytes_read() {
        let (mut file, _cleanup) = open_temp("pread", 1024);
        let payload: [u8; 16] = [0xAA; 16];
        file.seek(SeekFrom::Start(100)).expect("seek");
        file.write_all(&payload).expect("write");
        let backend = BlockingBackend::new();
        let mut got = [0u8; 16];
        let n = backend
            .pread_at(file.as_fd(), 100, &mut got)
            .expect("pread");
        assert_eq!(n, 16);
        assert_eq!(got, payload);
    }

    #[test]
    fn pread_at_short_reads_at_eof() {
        let (file, _cleanup) = open_temp("pread_eof", 32);
        let backend = BlockingBackend::new();
        let mut got = vec![0u8; 64];
        let n = backend.pread_at(file.as_fd(), 16, &mut got).expect("pread");
        assert_eq!(n, 16);
    }

    #[test]
    fn pread_exact_at_errors_at_eof() {
        let (file, _cleanup) = open_temp("pread_exact_eof", 32);
        let backend = BlockingBackend::new();
        let mut got = vec![0u8; 64];
        let err = backend
            .pread_exact_at(file.as_fd(), 16, &mut got)
            .expect_err("expected EOF");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn sync_all_succeeds_on_regular_file() {
        let (file, _cleanup) = open_temp("sync_all", 32);
        let backend = BlockingBackend::new();
        backend.sync_all(file.as_fd()).expect("sync_all");
    }

    #[test]
    fn round_trip_through_arc_dyn() {
        // Smoke test: object-safety + Send + Sync + thread sharing.
        let (file, _cleanup) = open_temp("arc_dyn", 4096);
        let backend: Arc<dyn IoBackend> = default_backend();
        let payload: Vec<u8> = (0u8..64).collect();
        let backend2 = Arc::clone(&backend);
        let fd = file.as_fd();
        backend.pwrite_all_at(fd, 0, &payload).expect("write");
        let mut got = vec![0u8; payload.len()];
        backend2.pread_exact_at(fd, 0, &mut got).expect("read");
        assert_eq!(got, payload);
    }
}
