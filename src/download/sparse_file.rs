//! The on-disk landing pad for the compressed source download.
//!
//! `pux` writes downloaded chunks straight into a single file at their
//! eventual offsets, leaves the gaps as filesystem holes, and lets the
//! decoder follow the contiguous prefix forward. This module owns that
//! file: opening / creating it at the right size, performing concurrent
//! offset-addressed IO from worker threads, and dispatching hole-punch
//! requests to a [`PunchHole`] implementation.
//!
//! # Concurrency model
//!
//! [`SparseFile::pwrite_at`] and [`SparseFile::read_at`] use POSIX
//! `pwrite`/`pread` (via [`FileExt`]). Both take `&self`, do not move
//! the kernel-side file offset, and are safe to invoke concurrently
//! from any number of threads. Workers therefore only need to
//! coordinate on **which** chunk they write — the bitmap from
//! [`crate::bitmap`] — not on access to the file.
//!
//! # Punching
//!
//! The puncher is supplied per-call rather than stored in the
//! `SparseFile`. The coordinator owns one [`PunchHole`] for the whole
//! pipeline (Linux puncher, downgraded to noop on the first
//! `Unsupported`) and hands it to [`SparseFile::punch`] when the
//! decoder advances past a checkpoint. Keeping the puncher out of the
//! struct lets us share the file across threads with no further
//! plumbing.

#![cfg(unix)]

use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::punch::{PunchError, PunchHole};
use crate::types::ByteOffset;

/// Errors produced by [`SparseFile`].
#[derive(Debug, Error)]
pub enum SparseFileError {
    /// Opening or creating the file failed.
    #[error("opening sparse file at {path}")]
    Open {
        /// The path the caller asked us to open or create.
        path: PathBuf,
        /// The underlying OS error.
        #[source]
        source: io::Error,
    },

    /// `set_len` (i.e. `ftruncate`) of the file to the configured total
    /// size failed.
    #[error("setting sparse file at {path} to length {total_size}")]
    SetLen {
        /// The path being resized.
        path: PathBuf,
        /// The target logical length.
        total_size: u64,
        /// The underlying OS error.
        #[source]
        source: io::Error,
    },

    /// A write was rejected because it would extend past the file's
    /// declared total size.
    #[error("write of {len} bytes at offset {offset} exceeds total size {total_size}")]
    OutOfBounds {
        /// Offset at which the write was attempted.
        offset: u64,
        /// Length of the write that was rejected.
        len: u64,
        /// The configured total size of the sparse file.
        total_size: u64,
    },

    /// `offset + len` overflowed `u64`. Defensive: real-world offsets
    /// are far below `u64::MAX`.
    #[error("offset {offset} + length {len} overflowed u64")]
    OffsetOverflow {
        /// The offset passed in.
        offset: u64,
        /// The length passed in.
        len: u64,
    },

    /// A `pwrite_at` or `read_at` call failed at the OS level.
    #[error("io at offset {offset} length {len}")]
    Io {
        /// Offset of the failed IO.
        offset: u64,
        /// Length of the failed IO.
        len: u64,
        /// The underlying OS error.
        #[source]
        source: io::Error,
    },

    /// The wrapped [`PunchHole`] implementation returned an error.
    #[error("hole punch failed")]
    Punch(#[source] PunchError),
}

/// The compressed-source landing file.
///
/// A `SparseFile` is a thin wrapper around an [`std::fs::File`] opened
/// `O_RDWR | O_CREAT`. Construction sets the file's logical length to
/// `total_size` so that `pread` of any byte in `[0, total_size)`
/// succeeds, returning zeros for ranges that workers haven't written
/// yet.
///
/// # Lifecycle
///
/// 1. Coordinator calls [`SparseFile::open_or_create`] with the
///    expected total size from the HTTP `Content-Length`.
/// 2. Workers issue [`SparseFile::pwrite_at`] for downloaded chunks.
/// 3. The decoder reads bytes back via [`SparseFile::read_at`].
/// 4. After a checkpoint is durable, the coordinator calls
///    [`SparseFile::punch`] to release the underlying blocks.
#[derive(Debug)]
pub struct SparseFile {
    file: std::fs::File,
    total_size: u64,
    path: PathBuf,
}

impl SparseFile {
    /// Open `path` for read-write, creating it if needed, and set its
    /// logical length to `total_size`.
    ///
    /// Setting the length is unconditional: an existing file is
    /// resized to `total_size` (extending it produces holes; shrinking
    /// it discards the tail). The coordinator is responsible for
    /// deciding *whether* to resize — typically only after verifying
    /// the source's `ETag` matches what the checkpoint recorded.
    ///
    /// # Errors
    ///
    /// Returns [`SparseFileError::Open`] if the file cannot be opened
    /// or [`SparseFileError::SetLen`] if `ftruncate` fails.
    pub fn open_or_create(path: &Path, total_size: u64) -> Result<Self, SparseFileError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|source| SparseFileError::Open {
                path: path.to_path_buf(),
                source,
            })?;

        file.set_len(total_size)
            .map_err(|source| SparseFileError::SetLen {
                path: path.to_path_buf(),
                total_size,
                source,
            })?;

        Ok(Self {
            file,
            total_size,
            path: path.to_path_buf(),
        })
    }

    /// The configured total logical size of the file, in bytes.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// The on-disk path the file was opened from, useful for error
    /// reporting outside this module.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Borrow the underlying file descriptor for syscalls that need it
    /// directly (e.g., bypassing the [`PunchHole`] trait in a test).
    /// Prefer [`Self::punch`] for hole punching.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }

    /// Write `buf` at byte offset `offset`.
    ///
    /// Equivalent to `pwrite(2)`: does not move the file's kernel-side
    /// position, is safe to call concurrently from multiple threads,
    /// and writes the entire buffer (loops internally on partial
    /// writes).
    ///
    /// # Errors
    ///
    /// Returns [`SparseFileError::OutOfBounds`] if the write would
    /// extend past `total_size`,
    /// [`SparseFileError::OffsetOverflow`] if `offset + buf.len()`
    /// overflows `u64`, or [`SparseFileError::Io`] for any other OS
    /// error.
    pub fn pwrite_at(&self, offset: ByteOffset, buf: &[u8]) -> Result<(), SparseFileError> {
        let raw_offset = offset.get();
        let len = buf.len() as u64;
        let end = raw_offset
            .checked_add(len)
            .ok_or(SparseFileError::OffsetOverflow {
                offset: raw_offset,
                len,
            })?;
        if end > self.total_size {
            return Err(SparseFileError::OutOfBounds {
                offset: raw_offset,
                len,
                total_size: self.total_size,
            });
        }

        self.file
            .write_all_at(buf, raw_offset)
            .map_err(|source| SparseFileError::Io {
                offset: raw_offset,
                len,
                source,
            })
    }

    /// Read up to `buf.len()` bytes starting at `offset`, returning the
    /// number of bytes actually read.
    ///
    /// Short reads at end-of-file are reported by a return value less
    /// than `buf.len()`. Uses `pread(2)` via [`FileExt::read_at`] and
    /// is safe to call concurrently with other reads or writes.
    ///
    /// # Errors
    ///
    /// Returns [`SparseFileError::OffsetOverflow`] if `offset +
    /// buf.len()` overflows `u64` or [`SparseFileError::Io`] for an OS
    /// error. Reading entirely past `total_size` is **not** an error
    /// at this layer; it returns `Ok(0)` because the kernel will
    /// short-read.
    pub fn read_at(&self, offset: ByteOffset, buf: &mut [u8]) -> Result<usize, SparseFileError> {
        let raw_offset = offset.get();
        let len = buf.len() as u64;
        // Defensively reject offset arithmetic overflow even though
        // `read_at` itself would only return less data, never write
        // past the buffer.
        raw_offset
            .checked_add(len)
            .ok_or(SparseFileError::OffsetOverflow {
                offset: raw_offset,
                len,
            })?;

        self.file
            .read_at(buf, raw_offset)
            .map_err(|source| SparseFileError::Io {
                offset: raw_offset,
                len,
                source,
            })
    }

    /// Read exactly `buf.len()` bytes starting at `offset`, looping on
    /// short reads.
    ///
    /// # Errors
    ///
    /// Returns [`SparseFileError::Io`] (with the wrapped
    /// `io::ErrorKind::UnexpectedEof`) if end-of-file is hit before
    /// the buffer is filled, or any of the same errors as
    /// [`Self::read_at`] for OS-level failures.
    pub fn read_exact_at(&self, offset: ByteOffset, buf: &mut [u8]) -> Result<(), SparseFileError> {
        let raw_offset = offset.get();
        let len = buf.len() as u64;
        raw_offset
            .checked_add(len)
            .ok_or(SparseFileError::OffsetOverflow {
                offset: raw_offset,
                len,
            })?;

        self.file
            .read_exact_at(buf, raw_offset)
            .map_err(|source| SparseFileError::Io {
                offset: raw_offset,
                len,
                source,
            })
    }

    /// Release the underlying disk blocks for `[offset, offset + length)`.
    ///
    /// Wraps [`PunchHole::punch`] on the borrowed file descriptor;
    /// callers are expected to align `offset` and `length` to
    /// [`PunchHole::block_size_hint`]. The file's logical size is
    /// preserved.
    ///
    /// # Errors
    ///
    /// Returns [`SparseFileError::Punch`] wrapping the underlying
    /// [`PunchError`].
    pub fn punch(
        &self,
        puncher: &dyn PunchHole,
        offset: ByteOffset,
        length: u64,
    ) -> Result<(), SparseFileError> {
        puncher
            .punch(self.as_fd(), offset, length)
            .map_err(SparseFileError::Punch)
    }

    /// `fsync` the underlying file.
    ///
    /// # Errors
    ///
    /// Returns the OS error wrapped in [`SparseFileError::Io`] with
    /// `offset = 0` and `len = total_size`, since `fsync` covers the
    /// whole file.
    pub fn sync_all(&self) -> Result<(), SparseFileError> {
        self.file.sync_all().map_err(|source| SparseFileError::Io {
            offset: 0,
            len: self.total_size,
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};

    /// Process-unique counter so concurrent test threads don't collide
    /// on temp filenames. Same pattern as `tests/test_punch.rs`.
    static UNIQ: AtomicU64 = AtomicU64::new(0);

    fn unique_temp_path(label: &str) -> PathBuf {
        let pid = std::process::id();
        let n = UNIQ.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("pux_sparse_{label}_{pid}_{nanos}_{n}.bin"))
    }

    struct CleanupOnDrop(PathBuf);
    impl Drop for CleanupOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn open_or_create_sets_logical_size() {
        let path = unique_temp_path("set_len");
        let _cleanup = CleanupOnDrop(path.clone());

        let f = SparseFile::open_or_create(&path, 8192).expect("create");
        assert_eq!(f.total_size(), 8192);
        let meta = f.file.metadata().expect("metadata");
        assert_eq!(meta.len(), 8192);
    }

    #[test]
    fn open_or_create_resizes_existing_file() {
        let path = unique_temp_path("resize");
        let _cleanup = CleanupOnDrop(path.clone());

        let _ = SparseFile::open_or_create(&path, 1024).expect("first open");
        let f = SparseFile::open_or_create(&path, 4096).expect("second open");
        assert_eq!(f.total_size(), 4096);
        let meta = f.file.metadata().expect("metadata");
        assert_eq!(meta.len(), 4096);
    }

    #[test]
    fn pwrite_then_read_round_trips() {
        let path = unique_temp_path("round_trip");
        let _cleanup = CleanupOnDrop(path.clone());
        let f = SparseFile::open_or_create(&path, 1024).expect("open");

        let payload: Vec<u8> = (0u8..32).collect();
        f.pwrite_at(ByteOffset::new(64), &payload).expect("write");

        let mut buf = vec![0u8; payload.len()];
        f.read_exact_at(ByteOffset::new(64), &mut buf)
            .expect("read");
        assert_eq!(buf, payload);
    }

    #[test]
    fn read_before_write_returns_zeros() {
        let path = unique_temp_path("read_zeros");
        let _cleanup = CleanupOnDrop(path.clone());
        let f = SparseFile::open_or_create(&path, 4096).expect("open");

        let mut buf = vec![0xAAu8; 64];
        let n = f.read_at(ByteOffset::new(2048), &mut buf).expect("read");
        assert_eq!(n, 64);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn read_at_end_short_reads() {
        let path = unique_temp_path("short_read");
        let _cleanup = CleanupOnDrop(path.clone());
        let f = SparseFile::open_or_create(&path, 100).expect("open");

        let mut buf = vec![0u8; 200];
        let n = f.read_at(ByteOffset::new(50), &mut buf).expect("read");
        assert_eq!(n, 50);

        let mut empty = vec![0u8; 16];
        let n = f.read_at(ByteOffset::new(100), &mut empty).expect("read");
        assert_eq!(n, 0);
    }

    #[test]
    fn pwrite_past_total_size_is_out_of_bounds() {
        let path = unique_temp_path("oob");
        let _cleanup = CleanupOnDrop(path.clone());
        let f = SparseFile::open_or_create(&path, 100).expect("open");

        let buf = [0u8; 64];
        match f.pwrite_at(ByteOffset::new(50), &buf) {
            Err(SparseFileError::OutOfBounds {
                offset,
                len,
                total_size,
            }) => {
                assert_eq!(offset, 50);
                assert_eq!(len, 64);
                assert_eq!(total_size, 100);
            }
            other => panic!("expected OutOfBounds, got {other:?}"),
        }
    }

    #[test]
    fn pwrite_exactly_to_end_succeeds() {
        let path = unique_temp_path("exact_end");
        let _cleanup = CleanupOnDrop(path.clone());
        let f = SparseFile::open_or_create(&path, 64).expect("open");

        let buf = [7u8; 64];
        f.pwrite_at(ByteOffset::ZERO, &buf).expect("full write");

        let mut readback = vec![0u8; 64];
        f.read_exact_at(ByteOffset::ZERO, &mut readback)
            .expect("read");
        assert_eq!(readback, buf);
    }

    #[test]
    fn pwrite_offset_overflow_is_caught() {
        let path = unique_temp_path("offset_overflow");
        let _cleanup = CleanupOnDrop(path.clone());
        let f = SparseFile::open_or_create(&path, 16).expect("open");

        let big = vec![0u8; 8];
        // u64::MAX - 4 + 8 overflows.
        match f.pwrite_at(ByteOffset::new(u64::MAX - 4), &big) {
            Err(SparseFileError::OffsetOverflow { offset, len }) => {
                assert_eq!(offset, u64::MAX - 4);
                assert_eq!(len, 8);
            }
            other => panic!("expected OffsetOverflow, got {other:?}"),
        }
    }

    #[test]
    fn punch_via_noop_succeeds() {
        use crate::punch::NoopPuncher;
        let path = unique_temp_path("punch_noop");
        let _cleanup = CleanupOnDrop(path.clone());
        let f = SparseFile::open_or_create(&path, 8192).expect("open");
        f.punch(&NoopPuncher::new(), ByteOffset::ZERO, 4096)
            .expect("noop punch");
    }
}
