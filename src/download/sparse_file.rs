//! The on-disk landing pad for the compressed source download.
//!
//! `peel` writes downloaded chunks straight into a single file at their
//! eventual offsets, leaves the gaps as filesystem holes, and lets the
//! decoder follow the contiguous prefix forward. This module owns that
//! file: opening / creating it at the right size, performing concurrent
//! offset-addressed IO from worker threads, and dispatching hole-punch
//! requests to a [`PunchHole`] implementation.
//!
//! # Storage modes
//!
//! Two storage modes coexist behind the same public surface
//! (`PLAN_v2.md` §9):
//!
//! - **pwrite/pread** (default). Workers hit `pwrite(2)` / `pread(2)`
//!   syscalls routed through an [`IoBackend`]. The default
//!   [`crate::io_backend::BlockingBackend`] uses POSIX semantics: each
//!   call carries its own offset, does not move the kernel-side file
//!   position, and is safe to invoke concurrently from any number of
//!   threads. The §7.2 io_uring backend preserves those semantics while
//!   batching submissions through a dedicated IO thread.
//! - **mmap** (`--io-backend mmap`). Workers `memcpy` into a
//!   `MAP_SHARED` mapping of the file; the kernel handles writeback.
//!   `sync_all` translates to `msync(MS_ASYNC)` on the mapping.
//!   Selected explicitly via [`SparseFile::open_or_create_mmap`] (the
//!   coordinator wires it up when the `--io-backend` flag picks
//!   `mmap`). Linux-only: the corresponding mmap puncher uses
//!   `madvise(MADV_REMOVE)`, which is a Linux-specific syscall.
//!
//! Workers therefore only need to coordinate on **which** chunk they
//! write — the bitmap from [`crate::bitmap`] — not on access to the
//! file.
//!
//! # Punching
//!
//! The puncher is supplied per-call rather than stored in the
//! `SparseFile`. The coordinator owns one [`PunchHole`] for the whole
//! pipeline (Linux puncher, downgraded to noop on the first
//! `Unsupported`) and hands it to [`SparseFile::punch`] when the
//! decoder advances past a checkpoint. Keeping the puncher out of the
//! struct lets us share the file across threads with no further
//! plumbing. In `mmap` mode the coordinator constructs the puncher via
//! [`SparseFile::make_mmap_puncher`], which packages the mapping's
//! base + length into a [`crate::punch::LinuxPuncher::for_mmap`]
//! instance.

use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use thiserror::Error;

#[cfg(target_os = "linux")]
use super::mmap_region::MmapRegion;
use crate::io_backend::{default_backend, IoBackend};
use crate::os_fd::{AsOsFd, OsFd};
#[cfg(target_os = "linux")]
use crate::punch::LinuxPuncher;
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

    /// A write-side operation (`pwrite_at`, `punch`, `sync_all`,
    /// `order_writes`) was attempted on a read-only [`SparseFile`]
    /// (built via [`SparseFile::open_readonly`]). The local-file
    /// extraction path opens the user's archive read-only so the
    /// existing pipelines can drive it through [`MultiSparse`]
    /// without ever modifying the source; the pipelines never call
    /// the write-side methods themselves, so hitting this variant
    /// indicates a bug in the caller (typically the coordinator
    /// glue) rather than user input.
    #[error("operation not supported on a read-only sparse file at {path}")]
    ReadOnly {
        /// The on-disk path the read-only file was opened from.
        path: PathBuf,
    },

    /// `mmap`-mode construction failed before a [`SparseFile`] could be
    /// returned. Wrapped from the underlying `mmap(2)` failure.
    /// Linux-only because the mmap storage backend is gated on Linux
    /// (`PLAN_v2.md` §9 — relies on `madvise(MADV_REMOVE)`).
    #[cfg(target_os = "linux")]
    #[error("mmap of {path} (length {total_size}) failed")]
    Mmap {
        /// The path being mapped.
        path: PathBuf,
        /// The length the file was set to before mapping.
        total_size: u64,
        /// The underlying OS error.
        #[source]
        source: io::Error,
    },
}

/// The compressed-source landing file.
///
/// A `SparseFile` wraps an [`std::fs::File`] opened `O_RDWR | O_CREAT`
/// plus a chosen storage backend. Construction sets the file's logical
/// length to `total_size` so that `pread` of any byte in
/// `[0, total_size)` succeeds, returning zeros for ranges that workers
/// haven't written yet.
///
/// Two storage backends coexist behind the same public surface
/// (`PLAN_v2.md` §9):
///
/// - **pwrite/pread** ([`SparseFile::open_or_create`] /
///   [`SparseFile::open_or_create_with_backend`]). Default. Routes IO
///   through an [`IoBackend`] (blocking pwrite or io_uring).
/// - **mmap** ([`SparseFile::open_or_create_mmap`]). Linux-only.
///   Workers `memcpy` into a `MAP_SHARED` region; `sync_all` translates
///   to `msync(MS_ASYNC)`; the coordinator's puncher operates via
///   `madvise(MADV_REMOVE)` on the same region (constructed via
///   [`SparseFile::make_mmap_puncher`]).
///
/// # Lifecycle
///
/// 1. Coordinator picks one of the constructors based on
///    [`crate::io_backend::IoBackendChoice`].
/// 2. Workers issue [`SparseFile::pwrite_at`] for downloaded chunks.
/// 3. The decoder reads bytes back via [`SparseFile::read_at`].
/// 4. After a checkpoint is durable, the coordinator calls
///    [`SparseFile::punch`] to release the underlying blocks.
#[derive(Debug)]
pub struct SparseFile {
    file: std::fs::File,
    total_size: u64,
    path: PathBuf,
    storage: Storage,
    /// When `true` the file was opened by [`SparseFile::open_readonly`]
    /// — write/punch/sync operations fail with
    /// [`SparseFileError::ReadOnly`]. Read operations are always
    /// allowed. This exists to feed the user's archive into the
    /// existing zip/7z/rar pipelines (via [`crate::download::multi_sparse::MultiSparse`])
    /// without granting any write authority.
    readonly: bool,
    /// When `true` the file was opened by [`SparseFile::open_growable`]
    /// for the unknown-size single-stream path (issue #8): the source
    /// size is not known up front, so `pwrite_at` performs **no** upper-
    /// bound check and the file grows as bytes arrive. [`Self::total_size`]
    /// then reports the live high-water from [`Self::current_len`]
    /// instead of the fixed `total_size`.
    growable: bool,
    /// Live high-water (largest written end offset) for a growable file.
    /// Unused for fixed-size files. Updated with `fetch_max(Release)`
    /// after each `pwrite_at`; read with `Acquire` by [`Self::total_size`].
    current_len: AtomicU64,
}

/// Internal: the storage backend a [`SparseFile`] dispatches to.
///
/// `Pwrite` — the default — pushes every byte through an
/// [`IoBackend`] syscall. `Mmap` (Linux only) keeps an
/// `Arc<MmapRegion>` so the underlying mapping outlives any puncher we
/// hand out (the puncher's keepalive is a clone of this `Arc`).
#[derive(Debug)]
enum Storage {
    Pwrite {
        backend: Arc<dyn IoBackend>,
    },
    #[cfg(target_os = "linux")]
    Mmap {
        region: Arc<MmapRegion>,
    },
}

impl SparseFile {
    /// Open `path` for read-write, creating it if needed, and set its
    /// logical length to `total_size`. The caller-controlled IO path
    /// is the [`crate::io_backend::default_backend`] (currently
    /// [`crate::io_backend::BlockingBackend`]); use
    /// [`Self::open_or_create_with_backend`] to pin a specific
    /// backend.
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
        Self::open_or_create_with_backend(path, total_size, default_backend())
    }

    /// Open `path` and pin a specific [`IoBackend`] for every
    /// subsequent IO call.
    ///
    /// Identical semantics to [`Self::open_or_create`] except the
    /// caller chooses the backend explicitly. The coordinator uses
    /// this form once the §7.2 selection logic lands; tests use it to
    /// inject stub backends.
    ///
    /// # Errors
    ///
    /// Same as [`Self::open_or_create`].
    pub fn open_or_create_with_backend(
        path: &Path,
        total_size: u64,
        backend: Arc<dyn IoBackend>,
    ) -> Result<Self, SparseFileError> {
        let file = open_at_size(path, total_size)?;
        Ok(Self {
            file,
            total_size,
            path: path.to_path_buf(),
            storage: Storage::Pwrite { backend },
            readonly: false,
            growable: false,
            current_len: AtomicU64::new(total_size),
        })
    }

    /// Open `path` for read-write with **no fixed size** — the
    /// unknown-size single-stream path (issue #8). The file starts empty
    /// and `pwrite_at` extends it as bytes arrive, performing no upper-
    /// bound check. [`Self::total_size`] reports the live high-water.
    ///
    /// Always uses the default blocking backend: the unknown-size path
    /// is a single sequential writer, so the io_uring worker pool that
    /// motivates backend selection never applies.
    ///
    /// # Errors
    ///
    /// Returns [`SparseFileError::Open`] if the file cannot be opened or
    /// [`SparseFileError::SetLen`] if the initial `ftruncate` to 0 fails.
    pub fn open_growable(path: &Path) -> Result<Self, SparseFileError> {
        let file = open_at_size(path, 0)?;
        Ok(Self {
            file,
            total_size: 0,
            path: path.to_path_buf(),
            storage: Storage::Pwrite {
                backend: default_backend(),
            },
            readonly: false,
            growable: true,
            current_len: AtomicU64::new(0),
        })
    }

    /// Open `path` read-only and report its existing size as
    /// [`Self::total_size`]. No `set_len`, no write authority on the
    /// kernel fd. Used by the local-file extraction path so the
    /// existing zip/7z/rar pipelines can drive the user's archive
    /// through a [`crate::download::multi_sparse::MultiSparse`]
    /// wrapper without granting any write authority on the source.
    ///
    /// The pwrite/punch/sync methods on the returned [`SparseFile`]
    /// fail with [`SparseFileError::ReadOnly`]; the pipelines never
    /// call them, but the variant exists so a bug in the local-mode
    /// coordinator glue surfaces as a clean error rather than a
    /// silent write into the user's archive.
    ///
    /// The IO backend is left as the default (blocking pread) — the
    /// local path never benefits from `io_uring` because there is no
    /// concurrent worker pool issuing the reads.
    ///
    /// # Errors
    ///
    /// Returns [`SparseFileError::Open`] if the file cannot be opened
    /// (typically `ENOENT` or permission denied).
    pub fn open_readonly(path: &Path) -> Result<Self, SparseFileError> {
        let file =
            OpenOptions::new()
                .read(true)
                .open(path)
                .map_err(|source| SparseFileError::Open {
                    path: path.to_path_buf(),
                    source,
                })?;
        let total_size = file
            .metadata()
            .map_err(|source| SparseFileError::Open {
                path: path.to_path_buf(),
                source,
            })?
            .len();
        Ok(Self {
            file,
            total_size,
            path: path.to_path_buf(),
            storage: Storage::Pwrite {
                backend: default_backend(),
            },
            readonly: true,
            growable: false,
            current_len: AtomicU64::new(total_size),
        })
    }

    /// Open `path` and map its first `total_size` bytes via
    /// `mmap(MAP_SHARED)` (`PLAN_v2.md` §9). Workers write into the
    /// mapping with `memcpy`; reads memcpy out; `sync_all` becomes
    /// `msync(MS_ASYNC)`. The coordinator constructs the matching
    /// `madvise(MADV_REMOVE)` puncher via
    /// [`Self::make_mmap_puncher`].
    ///
    /// Setting the length is unconditional (matches
    /// [`Self::open_or_create`]); the file's logical size is then
    /// mapped end-to-end. `total_size == 0` is rejected because mmap
    /// of length 0 is undefined and the use case never asks for it.
    ///
    /// This constructor is Linux-only because the only supported
    /// puncher for the mmap path is
    /// [`crate::punch::LinuxPuncher::for_mmap`], which depends on
    /// `madvise(MADV_REMOVE)`.
    ///
    /// # Errors
    ///
    /// Returns [`SparseFileError::Open`] if the file cannot be opened,
    /// [`SparseFileError::SetLen`] if `ftruncate` fails, or
    /// [`SparseFileError::Mmap`] if the kernel rejects the mapping
    /// (`ENOMEM`, `ENODEV` on filesystems that don't support shared
    /// mappings, etc.).
    #[cfg(target_os = "linux")]
    pub fn open_or_create_mmap(path: &Path, total_size: u64) -> Result<Self, SparseFileError> {
        let file = open_at_size(path, total_size)?;
        let region =
            MmapRegion::map(&file, total_size).map_err(|source| SparseFileError::Mmap {
                path: path.to_path_buf(),
                total_size,
                source,
            })?;
        Ok(Self {
            file,
            total_size,
            path: path.to_path_buf(),
            storage: Storage::Mmap {
                region: Arc::new(region),
            },
            readonly: false,
            growable: false,
            current_len: AtomicU64::new(total_size),
        })
    }

    /// The total logical size of the file, in bytes. For a growable
    /// file (unknown-size path) this is the live high-water — the
    /// largest byte offset written so far — which equals the final
    /// source size once the download has reached EOF.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        if self.growable {
            self.current_len.load(Ordering::Acquire)
        } else {
            self.total_size
        }
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
    pub fn as_fd(&self) -> OsFd<'_> {
        self.file.as_os_fd()
    }

    /// The diagnostic name of the storage backend handling this file's
    /// IO (e.g. `"blocking"`, `"uring"`, `"mmap"`).
    #[must_use]
    pub fn backend_name(&self) -> &'static str {
        match &self.storage {
            Storage::Pwrite { backend } => backend.name(),
            #[cfg(target_os = "linux")]
            Storage::Mmap { .. } => "mmap",
        }
    }

    /// `true` iff this file is using the `mmap` storage backend.
    #[must_use]
    pub fn is_mmap(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            matches!(self.storage, Storage::Mmap { .. })
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Build the matching `madvise(MADV_REMOVE)` puncher for this
    /// file's mmap storage (`PLAN_v2.md` §9 step 2). Returns `None`
    /// when the file is in pwrite mode; callers in that case fall back
    /// to [`crate::punch::default_puncher`].
    ///
    /// The returned puncher captures an `Arc` clone of the underlying
    /// mapping so it remains valid for the puncher's lifetime even if
    /// the [`SparseFile`] is dropped first. The coordinator drops the
    /// puncher before the sparse file in practice; this is just
    /// belt-and-suspenders.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn make_mmap_puncher(&self) -> Option<LinuxPuncher> {
        let Storage::Mmap { region } = &self.storage else {
            return None;
        };
        let base = region.base();
        let len = region.len();
        // The let-binding's annotation is the coercion site that turns
        // `Arc<MmapRegion>` into `Arc<dyn Send + Sync>`; `MmapRegion`
        // is `Send + Sync` so the unsized coercion succeeds.
        let cloned: Arc<MmapRegion> = Arc::clone(region);
        let keepalive: Arc<dyn Send + Sync> = cloned;
        // SAFETY: `region` is an `Arc<MmapRegion>` whose mapping covers
        // exactly `[base, base + len)`. `keepalive` holds a clone of
        // that Arc, so the mapping is alive at least as long as the
        // returned puncher. The puncher's `madvise(MADV_REMOVE)` calls
        // operate on a sub-range of the mapping; the puncher itself
        // never dereferences the pointer in Rust-aliased terms.
        Some(unsafe { LinuxPuncher::for_mmap(base, len, keepalive) })
    }

    /// Write `buf` at byte offset `offset`.
    ///
    /// Routes the actual syscall through the configured [`IoBackend`].
    /// The blocking backend uses `pwrite(2)` semantics: the file's
    /// kernel-side position is untouched and the call is safe to
    /// invoke concurrently from multiple threads. The full buffer is
    /// always written (the backend loops on partial writes).
    ///
    /// # Errors
    ///
    /// Returns [`SparseFileError::OutOfBounds`] if the write would
    /// extend past `total_size`,
    /// [`SparseFileError::OffsetOverflow`] if `offset + buf.len()`
    /// overflows `u64`, or [`SparseFileError::Io`] for any other OS
    /// error.
    pub fn pwrite_at(&self, offset: ByteOffset, buf: &[u8]) -> Result<(), SparseFileError> {
        if self.readonly {
            return Err(SparseFileError::ReadOnly {
                path: self.path.clone(),
            });
        }
        let raw_offset = offset.get();
        let len = buf.len() as u64;
        let end = raw_offset
            .checked_add(len)
            .ok_or(SparseFileError::OffsetOverflow {
                offset: raw_offset,
                len,
            })?;
        // A growable file (unknown-size path) has no fixed upper bound:
        // `pwrite`/`seek_write` past EOF extends the file, and the
        // high-water is tracked in `current_len` below.
        if !self.growable && end > self.total_size {
            return Err(SparseFileError::OutOfBounds {
                offset: raw_offset,
                len,
                total_size: self.total_size,
            });
        }

        let result = match &self.storage {
            Storage::Pwrite { backend } => backend
                .pwrite_all_at(self.file.as_os_fd(), raw_offset, buf)
                .map_err(|source| SparseFileError::Io {
                    offset: raw_offset,
                    len,
                    source,
                }),
            #[cfg(target_os = "linux")]
            Storage::Mmap { region } => {
                region
                    .write_at(raw_offset, buf)
                    .map_err(|source| SparseFileError::Io {
                        offset: raw_offset,
                        len,
                        source,
                    })
            }
        };
        // Publish the new high-water *after* the bytes are durable in
        // the kernel, mirroring the bitmap's Release-after-pwrite edge:
        // a reader that loads `current_len` (Acquire) and sees `end`
        // is guaranteed to observe the bytes this call wrote.
        if result.is_ok() && self.growable {
            self.current_len.fetch_max(end, Ordering::Release);
        }
        result
    }

    /// Read up to `buf.len()` bytes starting at `offset`, returning the
    /// number of bytes actually read.
    ///
    /// Routes the actual syscall through the configured [`IoBackend`].
    /// Short reads at end-of-file are reported by a return value less
    /// than `buf.len()`. The blocking backend uses `pread(2)`; both
    /// backends are safe to invoke concurrently with other reads or
    /// writes.
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

        match &self.storage {
            Storage::Pwrite { backend } => backend
                .pread_at(self.file.as_os_fd(), raw_offset, buf)
                .map_err(|source| SparseFileError::Io {
                    offset: raw_offset,
                    len,
                    source,
                }),
            #[cfg(target_os = "linux")]
            Storage::Mmap { region } => {
                region
                    .read_at(raw_offset, buf)
                    .map_err(|source| SparseFileError::Io {
                        offset: raw_offset,
                        len,
                        source,
                    })
            }
        }
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

        match &self.storage {
            Storage::Pwrite { backend } => backend
                .pread_exact_at(self.file.as_os_fd(), raw_offset, buf)
                .map_err(|source| SparseFileError::Io {
                    offset: raw_offset,
                    len,
                    source,
                }),
            #[cfg(target_os = "linux")]
            Storage::Mmap { region } => {
                let n = region
                    .read_at(raw_offset, buf)
                    .map_err(|source| SparseFileError::Io {
                        offset: raw_offset,
                        len,
                        source,
                    })?;
                if n != buf.len() {
                    return Err(SparseFileError::Io {
                        offset: raw_offset,
                        len,
                        source: io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            format!(
                                "mmap read_exact_at hit EOF after {n} of {} bytes at offset {raw_offset}",
                                buf.len(),
                            ),
                        ),
                    });
                }
                Ok(())
            }
        }
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
        if self.readonly {
            return Err(SparseFileError::ReadOnly {
                path: self.path.clone(),
            });
        }
        puncher
            .punch(self.as_fd(), offset, length)
            .map_err(SparseFileError::Punch)
    }

    /// Flush pending writes for the entire file.
    ///
    /// In `pwrite` mode this is `fsync(2)` via the configured
    /// [`IoBackend`] (full durability). In `mmap` mode it is
    /// `msync(MS_ASYNC)` over the mapping per `PLAN_v2.md` §9 step 3:
    /// the call schedules writeback without waiting for it, bounding
    /// the kernel-side dirty-page window without paying the latency of
    /// a full sync. Resume safety in mmap mode is gated on the
    /// quiescent-checkpoint discipline rather than per-flush
    /// durability.
    ///
    /// # Errors
    ///
    /// Returns the OS error wrapped in [`SparseFileError::Io`] with
    /// `offset = 0` and `len = total_size`, since the operation covers
    /// the whole file.
    pub fn sync_all(&self) -> Result<(), SparseFileError> {
        match &self.storage {
            Storage::Pwrite { backend } => {
                backend
                    .sync_all(self.file.as_os_fd())
                    .map_err(|source| SparseFileError::Io {
                        offset: 0,
                        len: self.total_size,
                        source,
                    })
            }
            #[cfg(target_os = "linux")]
            Storage::Mmap { region } => {
                region.msync_async().map_err(|source| SparseFileError::Io {
                    offset: 0,
                    len: self.total_size,
                    source,
                })
            }
        }
    }

    /// Order pending writes against a subsequent durability event,
    /// without forcing a device-level flush.
    ///
    /// `PLAN_checkpoint_cadence_throughput.md` Phase 1 publication
    /// path. Used by the checkpoint observer to declare that every
    /// `pwrite` issued before this call hits stable storage no later
    /// than any `pwrite` issued after it. The pre-barrier writes may
    /// not be on disk yet when this returns — only the *ordering*
    /// against post-barrier writes is guaranteed. That is the contract
    /// a future resume relies on: if it observes the renamed
    /// `.peel.ckpt`, every page that checkpoint claims durable in the
    /// bitmap is at least as durable as the checkpoint itself.
    ///
    /// In `pwrite` mode this dispatches through
    /// [`IoBackend::order_writes`]: macOS gets `fcntl(F_BARRIERFSYNC)`,
    /// Linux gets `fdatasync(2)`, other platforms fall back to a
    /// full `sync_all`. In `mmap` mode this delegates to the same
    /// `msync(MS_ASYNC)` that [`Self::sync_all`] uses — the mapping
    /// has no cheaper ordering primitive, and `msync(MS_ASYNC)` is
    /// already non-blocking.
    ///
    /// Callers that need a literal device flush (the clean-completion
    /// sweep) keep using [`Self::sync_all`].
    ///
    /// # Errors
    ///
    /// Returns the OS error wrapped in [`SparseFileError::Io`] with
    /// `offset = 0` and `len = total_size`.
    pub fn order_writes(&self) -> Result<(), SparseFileError> {
        match &self.storage {
            Storage::Pwrite { backend } => {
                backend
                    .order_writes(self.file.as_os_fd())
                    .map_err(|source| SparseFileError::Io {
                        offset: 0,
                        len: self.total_size,
                        source,
                    })
            }
            #[cfg(target_os = "linux")]
            Storage::Mmap { region } => {
                region.msync_async().map_err(|source| SparseFileError::Io {
                    offset: 0,
                    len: self.total_size,
                    source,
                })
            }
        }
    }
}

/// Open `path` `O_RDWR | O_CREAT` and `ftruncate` it to `total_size`.
///
/// Shared between [`SparseFile::open_or_create_with_backend`] and
/// [`SparseFile::open_or_create_mmap`] so the open/truncate dance and
/// its error mapping stay in one place.
fn open_at_size(path: &Path, total_size: u64) -> Result<std::fs::File, SparseFileError> {
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

    // On Windows the sparse attribute must be set *before* `set_len`
    // for the zero-extension below to leave the file logically
    // `total_size` bytes long without allocating physical clusters
    // for the zeroed range. Without this, NTFS allocates the full
    // `total_size` up-front and the hole-punching workflow has
    // nothing to release. Best-effort: filesystems that reject the
    // FSCTL (FAT32, exFAT, network mounts) get a warning and we fall
    // back to the non-sparse layout — output is still correct, just
    // without the in-flight disk savings (`PLAN_v3_windows.md` §3).
    #[cfg(windows)]
    set_sparse_attribute(&file, path);

    file.set_len(total_size)
        .map_err(|source| SparseFileError::SetLen {
            path: path.to_path_buf(),
            total_size,
            source,
        })?;
    Ok(file)
}

/// Mark `file` as an NTFS sparse file via
/// `DeviceIoControl(FSCTL_SET_SPARSE)` (`PLAN_v3_windows.md` §3).
///
/// Best-effort: filesystems without sparse-file support
/// (FAT32, exFAT, most network mounts) return `ERROR_INVALID_FUNCTION`,
/// `ERROR_NOT_SUPPORTED`, or `ERROR_INVALID_PARAMETER`; in that case
/// the file remains non-sparse, future `set_len` zero-extensions
/// allocate physical clusters, and the
/// [`crate::punch::WindowsPuncher`] (`PLAN_v3_windows.md` §4) will
/// surface its own `Unsupported` from `FSCTL_SET_ZERO_DATA`. Both
/// degradations are warning-grade, not fatal.
#[cfg(windows)]
fn set_sparse_attribute(file: &std::fs::File, path: &Path) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::IO::DeviceIoControl;

    // `FSCTL_SET_SPARSE` from `<winioctl.h>`. Hard-coded so we don't
    // need the `Win32_System_Ioctl` feature in `windows-sys` —
    // matches the pattern `punch::macos` uses for `F_PUNCHHOLE`. The
    // value is part of the stable NT control-code ABI.
    const FSCTL_SET_SPARSE: u32 = 0x0009_00C4;

    let mut bytes_returned: u32 = 0;
    // SAFETY: `file` outlives this call, so the raw handle is valid.
    // Input buffer is null + length 0, which `FSCTL_SET_SPARSE`
    // accepts as "set sparse to true" per the Win32 docs. The output
    // buffer is null + length 0 because this FSCTL returns no data;
    // `bytes_returned` is required to be non-null but we discard the
    // value. No `OVERLAPPED` (synchronous handle).
    let rc = unsafe {
        DeviceIoControl(
            file.as_raw_handle() as _,
            FSCTL_SET_SPARSE,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
        )
    };
    if rc == 0 {
        // ERROR_INVALID_FUNCTION (1), ERROR_NOT_SUPPORTED (50),
        // ERROR_INVALID_PARAMETER (87) — all are "the filesystem
        // doesn't do sparse files"; downgrade silently the same way
        // the Linux puncher downgrades on `EOPNOTSUPP`. Anything
        // else is unexpected; surface at `warn` so a real bug isn't
        // lost in the noise.
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(1) | Some(50) | Some(87) => {
                tracing::debug!(
                    path = %path.display(),
                    error = %err,
                    "filesystem does not support sparse files; \
                     proceeding without space-saving holes",
                );
            }
            _ => {
                tracing::warn!(
                    path = %path.display(),
                    error = %err,
                    "FSCTL_SET_SPARSE failed unexpectedly; \
                     proceeding without sparse attribute",
                );
            }
        }
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
        std::env::temp_dir().join(format!("peel_sparse_{label}_{pid}_{nanos}_{n}.bin"))
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
    fn order_writes_succeeds_after_pwrite() {
        // `PLAN_checkpoint_cadence_throughput.md` Phase 1: the
        // publication-side ordering primitive must succeed after
        // realistic worker traffic. Default backend on this build —
        // pwrite mode on macOS, mmap mode on Linux when the §9
        // backend selects it — should both wire through the
        // platform-appropriate primitive.
        let path = unique_temp_path("order_writes");
        let _cleanup = CleanupOnDrop(path.clone());
        let f = SparseFile::open_or_create(&path, 1024).expect("open");

        let payload: Vec<u8> = (0u8..32).collect();
        f.pwrite_at(ByteOffset::new(64), &payload).expect("write");
        f.order_writes().expect("order_writes");

        // Bytes are still readable after the barrier — the call has
        // no observable effect on the page cache or the file's view.
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

    #[test]
    fn default_constructor_uses_blocking_backend() {
        let path = unique_temp_path("default_backend");
        let _cleanup = CleanupOnDrop(path.clone());
        let f = SparseFile::open_or_create(&path, 64).expect("open");
        assert_eq!(f.backend_name(), "blocking");
    }

    #[test]
    fn explicit_backend_constructor_round_trips() {
        use crate::io_backend::BlockingBackend;
        let path = unique_temp_path("explicit_backend");
        let _cleanup = CleanupOnDrop(path.clone());
        let backend: Arc<dyn crate::io_backend::IoBackend> = Arc::new(BlockingBackend::new());
        let f = SparseFile::open_or_create_with_backend(&path, 256, backend)
            .expect("open with backend");
        assert_eq!(f.backend_name(), "blocking");

        let payload: Vec<u8> = (0u8..32).collect();
        f.pwrite_at(ByteOffset::new(0), &payload).expect("write");
        let mut got = vec![0u8; payload.len()];
        f.read_exact_at(ByteOffset::new(0), &mut got).expect("read");
        assert_eq!(got, payload);
    }

    #[test]
    fn pwrite_mode_is_not_mmap() {
        let path = unique_temp_path("not_mmap");
        let _cleanup = CleanupOnDrop(path.clone());
        let f = SparseFile::open_or_create(&path, 64).expect("open");
        assert!(!f.is_mmap());
        assert!(f.make_mmap_puncher_returns_none_when_not_mmap());
    }

    impl SparseFile {
        // Test-only convenience: make sure `make_mmap_puncher` returns
        // `None` when the file is in pwrite mode. Linux-only because the
        // method itself is gated on Linux. On non-Linux platforms this
        // helper short-circuits to `true` so the public test above
        // remains portable.
        fn make_mmap_puncher_returns_none_when_not_mmap(&self) -> bool {
            #[cfg(target_os = "linux")]
            {
                self.make_mmap_puncher().is_none()
            }
            #[cfg(not(target_os = "linux"))]
            {
                true
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mmap_constructor_reports_mmap_backend() {
        let path = unique_temp_path("mmap_backend");
        let _cleanup = CleanupOnDrop(path.clone());
        let f = SparseFile::open_or_create_mmap(&path, 8192).expect("mmap");
        assert_eq!(f.backend_name(), "mmap");
        assert!(f.is_mmap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mmap_pwrite_then_read_round_trips() {
        let path = unique_temp_path("mmap_round_trip");
        let _cleanup = CleanupOnDrop(path.clone());
        let f = SparseFile::open_or_create_mmap(&path, 4096).expect("mmap");

        let payload: Vec<u8> = (0u8..32).collect();
        f.pwrite_at(ByteOffset::new(128), &payload).expect("write");

        let mut buf = vec![0u8; payload.len()];
        f.read_exact_at(ByteOffset::new(128), &mut buf)
            .expect("read");
        assert_eq!(buf, payload);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mmap_read_before_write_returns_zeros() {
        let path = unique_temp_path("mmap_read_zeros");
        let _cleanup = CleanupOnDrop(path.clone());
        let f = SparseFile::open_or_create_mmap(&path, 4096).expect("mmap");

        let mut buf = vec![0xAAu8; 64];
        let n = f.read_at(ByteOffset::new(2048), &mut buf).expect("read");
        assert_eq!(n, 64);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mmap_pwrite_past_total_size_is_out_of_bounds() {
        let path = unique_temp_path("mmap_oob");
        let _cleanup = CleanupOnDrop(path.clone());
        let f = SparseFile::open_or_create_mmap(&path, 100).expect("mmap");

        let buf = [0u8; 64];
        match f.pwrite_at(ByteOffset::new(50), &buf) {
            Err(SparseFileError::OutOfBounds { .. }) => {}
            other => panic!("expected OutOfBounds, got {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mmap_sync_all_succeeds() {
        let path = unique_temp_path("mmap_sync");
        let _cleanup = CleanupOnDrop(path.clone());
        let f = SparseFile::open_or_create_mmap(&path, 4096).expect("mmap");
        f.sync_all().expect("msync(MS_ASYNC)");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mmap_make_puncher_returns_some() {
        let path = unique_temp_path("mmap_puncher");
        let _cleanup = CleanupOnDrop(path.clone());
        let f = SparseFile::open_or_create_mmap(&path, 4096).expect("mmap");
        let p = f.make_mmap_puncher().expect("mmap puncher");
        assert!(p.is_mmap());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mmap_punch_via_noop_succeeds() {
        use crate::punch::NoopPuncher;
        let path = unique_temp_path("mmap_punch_noop");
        let _cleanup = CleanupOnDrop(path.clone());
        let f = SparseFile::open_or_create_mmap(&path, 8192).expect("mmap");
        // Noop punch should still succeed in mmap mode — we exercise
        // the dispatch path rather than the syscall.
        f.punch(&NoopPuncher::new(), ByteOffset::ZERO, 4096)
            .expect("noop punch");
    }
}
