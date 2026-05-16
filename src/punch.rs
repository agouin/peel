//! Hole punching: releasing the disk blocks underlying a byte range of a
//! file while preserving the file's logical size.
//!
//! # Why this matters
//!
//! `peel` writes the compressed source into a sparse file as it downloads
//! and, in parallel, decodes the prefix of that file into the extracted
//! output. Once the decoder has consumed bytes `[0, X)` of the source
//! and we have a durable checkpoint past that point, the underlying
//! blocks for `[0, X)` are no longer needed and can be released back to
//! the filesystem. This module is the OS-portable interface for that
//! release.
//!
//! # Layering
//!
//! - [`PunchHole`] is the trait every implementation satisfies. It is
//!   object-safe and `Send + Sync`, so a single shared puncher can be
//!   handed to the download and extractor threads.
//! - [`NoopPuncher`] is the always-available fallback. It returns
//!   success without releasing any blocks; the caller still gets correct
//!   output, just at the cost of holding the entire compressed source on
//!   disk until completion.
//! - [`LinuxPuncher`] (Linux only) calls
//!   `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)` directly via
//!   the C ABI in its default `fallocate` mode, or
//!   `madvise(MADV_REMOVE)` against an `mmap`'d region in its
//!   `for_mmap` mode (`PLAN_v2.md` §9). Filesystems that reject the
//!   operation (NFS, FAT, certain FUSE mounts) report
//!   `EOPNOTSUPP`/`ENOTSUP`/`EINVAL`, which is mapped to
//!   [`PunchError::Unsupported`] so the caller can downgrade to
//!   [`NoopPuncher`] without aborting.
//! - [`MacosPuncher`] (macOS only) calls `fcntl(F_PUNCHHOLE)` directly
//!   via the C ABI (`PLAN_v2.md` §12). APFS supports it; HFS+, FAT, and
//!   most network/FUSE volumes report `ENOTSUP`/`EOPNOTSUPP`/`EINVAL`,
//!   which is again mapped to [`PunchError::Unsupported`] so callers can
//!   downgrade to [`NoopPuncher`].
//! - [`WindowsPuncher`] (Windows only) calls
//!   `DeviceIoControl(FSCTL_SET_ZERO_DATA)` against the borrowed
//!   handle (`PLAN_v3_windows.md` §4). NTFS deallocates whole
//!   clusters within the punched range; FAT32, exFAT, and most
//!   network mounts return `ERROR_INVALID_FUNCTION` /
//!   `ERROR_NOT_SUPPORTED` / `ERROR_INVALID_PARAMETER`, all mapped
//!   to [`PunchError::Unsupported`] so the caller can downgrade to
//!   [`NoopPuncher`] without aborting. The sparse attribute the
//!   FSCTL requires is set at file-creation time by
//!   [`crate::download::sparse_file`] via `FSCTL_SET_SPARSE`.
//! - [`default_puncher`] picks the best implementation for the running
//!   platform.
//!
//! # Alignment
//!
//! Most filesystems require punched ranges to be aligned to the
//! filesystem block size; misaligned tails are silently retained by the
//! kernel rather than treated as an error. Callers should align with
//! [`align_down`] and [`PunchHole::block_size_hint`] before invoking
//! [`PunchHole::punch`].

use thiserror::Error;

use crate::os_fd::OsFd;
use crate::types::ByteOffset;

/// Errors produced by [`PunchHole`] implementations.
#[derive(Debug, Error)]
pub enum PunchError {
    /// The kernel or filesystem refused the punch as fundamentally
    /// unsupported for this file (errno `EOPNOTSUPP`, `ENOTSUP`, or
    /// `EINVAL`). Callers should replace the puncher with
    /// [`NoopPuncher`] and continue without space reclamation.
    #[error("hole punching is not supported on this filesystem (errno {errno})")]
    Unsupported {
        /// The raw errno value that triggered the downgrade.
        errno: i32,
    },

    /// The requested offset or length cannot be represented in the
    /// platform's signed `off_t`. Defensive; real-world file offsets are
    /// well below `i64::MAX`.
    #[error("punch offset {offset} or length {length} exceeds platform off_t limit")]
    OffsetOverflow {
        /// The offset that overflowed.
        offset: u64,
        /// The length that overflowed.
        length: u64,
    },

    /// The kernel returned an unexpected errno from the punch syscall.
    /// The original [`std::io::Error`] is preserved via `#[source]`, so
    /// the caller can recover [`std::io::Error::raw_os_error`] or walk
    /// the `Display` chain.
    #[error("fallocate(PUNCH_HOLE) failed at offset {offset} length {length}")]
    Io {
        /// The byte offset passed to the syscall.
        offset: u64,
        /// The byte length passed to the syscall.
        length: u64,
        /// The underlying OS error.
        #[source]
        source: std::io::Error,
    },
}

/// Releases disk blocks for byte ranges of an open file.
///
/// Implementations are object-safe (no generics on methods) and
/// `Send + Sync`, so a single puncher can be shared across threads. In
/// practice all implementations are zero-sized.
pub trait PunchHole: Send + Sync {
    /// Release the disk blocks underlying `[offset, offset + length)` of
    /// the file referenced by `fd`. The file's logical size is preserved
    /// and reads from the punched range observe zero bytes.
    ///
    /// `length == 0` is a valid no-op and never errors.
    ///
    /// # Errors
    ///
    /// Returns [`PunchError::Unsupported`] if the filesystem cannot punch
    /// the region, [`PunchError::OffsetOverflow`] if the arguments cannot
    /// fit the underlying syscall's `off_t`, or [`PunchError::Io`] for any
    /// other OS error.
    fn punch(&self, fd: OsFd<'_>, offset: ByteOffset, length: u64) -> Result<(), PunchError>;

    /// Filesystem block alignment expected by this puncher, in bytes.
    /// A conservative default for unknown filesystems is 4096.
    fn block_size_hint(&self) -> u64;
}

/// A puncher that never releases blocks. Always succeeds.
///
/// Use as a fallback when the platform has no hole-punching syscall, or
/// after observing [`PunchError::Unsupported`] from another puncher.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopPuncher;

impl NoopPuncher {
    /// Construct a fresh [`NoopPuncher`].
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl PunchHole for NoopPuncher {
    fn punch(&self, _fd: OsFd<'_>, _offset: ByteOffset, _length: u64) -> Result<(), PunchError> {
        Ok(())
    }

    fn block_size_hint(&self) -> u64 {
        4096
    }
}

/// Round `value` down to the nearest multiple of `alignment`.
///
/// Returns `None` if `alignment` is zero. Otherwise the result `r`
/// satisfies `r <= value` and `r % alignment == 0`.
///
/// # Examples
///
/// ```
/// use peel::punch::align_down;
///
/// assert_eq!(align_down(8195, 4096), Some(8192));
/// assert_eq!(align_down(4096, 4096), Some(4096));
/// assert_eq!(align_down(0, 4096), Some(0));
/// assert_eq!(align_down(8195, 0), None);
/// ```
#[must_use]
pub const fn align_down(value: u64, alignment: u64) -> Option<u64> {
    match value.checked_div(alignment) {
        // (value / alignment) * alignment is bounded above by `value`,
        // so the multiplication cannot overflow `u64`.
        Some(quotient) => Some(quotient * alignment),
        None => None,
    }
}

/// Round `value` up to the nearest multiple of `alignment`.
///
/// Returns `None` if `alignment` is zero or if the rounded result would
/// overflow `u64`. Otherwise the result `r` satisfies `r >= value` and
/// `r % alignment == 0`.
///
/// # Examples
///
/// ```
/// use peel::punch::align_up;
///
/// assert_eq!(align_up(8195, 4096), Some(12288));
/// assert_eq!(align_up(4096, 4096), Some(4096));
/// assert_eq!(align_up(0, 4096), Some(0));
/// assert_eq!(align_up(8195, 0), None);
/// ```
#[must_use]
pub const fn align_up(value: u64, alignment: u64) -> Option<u64> {
    if alignment == 0 {
        return None;
    }
    let rem = value % alignment;
    if rem == 0 {
        return Some(value);
    }
    let bump = alignment - rem;
    value.checked_add(bump)
}

/// Return the best [`PunchHole`] implementation for the current platform.
///
/// On Linux this is a [`LinuxPuncher`]; on macOS it is a
/// [`MacosPuncher`]; on Windows it is a [`WindowsPuncher`]
/// (`PLAN_v3_windows.md` §4); on every other platform without a
/// hole-punch syscall it is a [`NoopPuncher`]. Callers that observe
/// [`PunchError::Unsupported`] from the returned puncher should
/// replace it with [`NoopPuncher`] and continue.
#[must_use]
pub fn default_puncher() -> Box<dyn PunchHole> {
    #[cfg(target_os = "linux")]
    {
        Box::new(LinuxPuncher::new())
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(MacosPuncher::new())
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(WindowsPuncher::new())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Box::new(NoopPuncher::new())
    }
}

#[cfg(target_os = "linux")]
pub use linux::LinuxPuncher;

#[cfg(target_os = "macos")]
pub use macos::MacosPuncher;

#[cfg(target_os = "windows")]
pub use windows::WindowsPuncher;

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::c_void;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::ptr::NonNull;
    use std::sync::{Arc, OnceLock};

    use super::{OsFd, PunchError, PunchHole};
    use crate::types::ByteOffset;

    /// `fallocate` mode flag: keep the file's logical size unchanged.
    const FALLOC_FL_KEEP_SIZE: i32 = 0x01;
    /// `fallocate` mode flag: punch a hole over the indicated range.
    const FALLOC_FL_PUNCH_HOLE: i32 = 0x02;

    /// `madvise` advice value: tell the kernel the pages backing a range
    /// of an `mmap`'d region are no longer needed and the underlying
    /// blocks may be released. Equivalent to `fallocate(PUNCH_HOLE)` for
    /// the file-backed case but applied through the virtual-memory
    /// interface; supported on tmpfs and ext4 today (per `mmap(2)` /
    /// `madvise(2)` man pages).
    const MADV_REMOVE: i32 = 9;

    /// Linux errno: "operation not supported". On Linux `ENOTSUP` and
    /// `EOPNOTSUPP` share the same numeric value.
    const EOPNOTSUPP: i32 = 95;
    /// Linux errno: "invalid argument". Some filesystems use this in
    /// place of `EOPNOTSUPP` to report that a punch is unrepresentable.
    const EINVAL: i32 = 22;
    /// Linux errno: "function not implemented". Older kernels and some
    /// non-tmpfs/non-ext4 filesystems return this for `MADV_REMOVE`.
    const ENOSYS: i32 = 38;

    /// POSIX [`sysconf`] selector for the active system page size.
    /// 30 on every Linux libc (glibc, musl) across every supported
    /// architecture — the value is part of the kernel-userspace ABI.
    const SC_PAGESIZE: i32 = 30;

    /// Fallback alignment when `sysconf(_SC_PAGESIZE)` returns an
    /// implausible value. 4 KiB is the historical Linux page size and
    /// what `block_size_hint` returned before this query was wired in.
    const FALLBACK_PAGE_SIZE: u64 = 4096;

    extern "C" {
        // `int fallocate(int fd, int mode, off_t offset, off_t len);` —
        // the Linux-specific syscall wrapper, exposed by both glibc and
        // musl. We declare `off_t` as `i64` because every target we
        // support is 64-bit Linux, where `off_t` is always 64-bit. (We
        // can't use `fallocate64`: glibc exposes it as the explicit
        // 64-bit-offset alias, but musl does not — under musl `off_t`
        // is unconditionally 64-bit and only the bare `fallocate`
        // symbol exists.)
        fn fallocate(fd: i32, mode: i32, offset: i64, len: i64) -> i32;

        // `int madvise(void *addr, size_t length, int advice);` —
        // advisory hint to the kernel about how a memory region will be
        // used. We submit `MADV_REMOVE` to release the underlying blocks
        // of an `mmap`'d shared file range without taking the file
        // descriptor's `fallocate` path.
        fn madvise(addr: *mut c_void, length: usize, advice: i32) -> i32;

        // `long sysconf(int name);` — POSIX runtime configuration
        // query. We use it solely to discover the active page size,
        // which the puncher publishes via `block_size_hint` so callers
        // align their punch ranges to whole pages. On Apple Silicon
        // Asahi kernels (`+16k`) this is 16 KiB; on conventional
        // x86_64 kernels it is 4 KiB.
        fn sysconf(name: i32) -> i64;
    }

    /// Return the runtime page size reported by the kernel via
    /// `sysconf(_SC_PAGESIZE)`, cached after the first successful
    /// query.
    ///
    /// `madvise(MADV_REMOVE)` rounds its `length` argument **up** to
    /// the next page-size boundary and rejects non-page-aligned
    /// offsets with `EINVAL`. `fallocate(PUNCH_HOLE)` zeroes partial
    /// filesystem blocks within the requested range but releases only
    /// whole blocks. The aligned-down boundary the extractor computes
    /// from this hint is therefore the upper bound on what the kernel
    /// can safely release without bleeding into the decoder's
    /// lookahead — under-sized hints (the previously hard-coded 4096
    /// on 16 KiB-page kernels) cause madvise to over-release and
    /// zero-fill bytes the decoder has not yet consumed.
    fn system_page_size() -> u64 {
        static PAGE_SIZE: OnceLock<u64> = OnceLock::new();
        *PAGE_SIZE.get_or_init(|| {
            // SAFETY: `sysconf` is a thread-safe pure POSIX query
            // with no aliasing concerns. We carry the integer name
            // by value across the C ABI and read only the returned
            // integer. A negative or zero return signals failure or
            // an unknown selector, which we ignore in favour of the
            // safe 4 KiB fallback rather than aborting.
            let rc = unsafe { sysconf(SC_PAGESIZE) };
            if rc > 0 {
                // Sanity-check the upper bound: page sizes above
                // 1 MiB are not represented on any architecture we
                // build for and would cause the extractor to over-
                // align in surprising ways. Treat as a fallback.
                let v = rc as u64;
                if (FALLBACK_PAGE_SIZE..=1 << 20).contains(&v) && v.is_power_of_two() {
                    v
                } else {
                    FALLBACK_PAGE_SIZE
                }
            } else {
                FALLBACK_PAGE_SIZE
            }
        })
    }

    /// Linux puncher with two modes (`PLAN_v2.md` §9).
    ///
    /// In its default mode the puncher calls
    /// `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)` against
    /// the borrowed file descriptor — the same path the MVP `peel`
    /// shipped with. After [`Self::for_mmap`], the puncher instead calls
    /// `madvise(MADV_REMOVE)` against an `mmap`'d region, ignoring the
    /// passed-in `fd` argument: the mmap-backed `SparseFile` (`§9`)
    /// holds the mapped region, the puncher just dereferences into it.
    ///
    /// Works on ext4, xfs, btrfs, tmpfs, f2fs, and other modern Linux
    /// filesystems for the fallocate path; tmpfs and ext4 specifically
    /// support `MADV_REMOVE`. Filesystems that reject either operation
    /// report `EOPNOTSUPP`/`EINVAL`/`ENOSYS`, which is surfaced as
    /// [`PunchError::Unsupported`] so the caller can downgrade to
    /// [`super::NoopPuncher`] without aborting.
    #[derive(Debug, Clone)]
    pub struct LinuxPuncher {
        mode: PunchMode,
    }

    /// Internal: which syscall to issue. The `MadvRemove` arm carries
    /// the mmap region the puncher was bound to via [`LinuxPuncher::for_mmap`].
    #[derive(Debug, Clone)]
    enum PunchMode {
        Fallocate,
        MadvRemove(Arc<MmapHandle>),
    }

    /// The mmap region a `MadvRemove`-mode puncher writes through.
    ///
    /// `keepalive` is an opaque `Arc` that pins whatever owner holds the
    /// underlying mapping — typically `Arc<MmapRegion>` from
    /// [`crate::download::sparse_file`]. Storing it as
    /// `Arc<dyn Send + Sync>` keeps `punch.rs` free of `download`-layer
    /// types; the only contract is "drop me last".
    pub(super) struct MmapHandle {
        base: SendSyncPtr,
        len: usize,
        _keepalive: Arc<dyn Send + Sync>,
    }

    impl std::fmt::Debug for MmapHandle {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MmapHandle")
                .field("base", &self.base.0.as_ptr())
                .field("len", &self.len)
                .finish()
        }
    }

    /// `NonNull<u8>` is `!Send` + `!Sync` by default. The mmap base
    /// pointer is shared across threads safely: the kernel synchronizes
    /// reads/writes against the underlying file, and our puncher only
    /// passes the pointer back to `madvise(2)`, never dereferencing it.
    /// The `unsafe impl`s assert that contract.
    #[derive(Clone, Copy)]
    struct SendSyncPtr(NonNull<u8>);

    // SAFETY: the puncher only forwards the pointer to `madvise(2)`,
    // which is thread-safe. The kernel-side mmap region is `MAP_SHARED`
    // and kernel-synchronized.
    unsafe impl Send for SendSyncPtr {}
    // SAFETY: same justification as `Send`.
    unsafe impl Sync for SendSyncPtr {}

    impl LinuxPuncher {
        /// Construct a fresh [`LinuxPuncher`] in the default
        /// `fallocate(PUNCH_HOLE)` mode.
        #[must_use]
        pub const fn new() -> Self {
            Self {
                mode: PunchMode::Fallocate,
            }
        }

        /// Construct a [`LinuxPuncher`] that punches via
        /// `madvise(MADV_REMOVE)` against the `mmap`'d region
        /// `[base, base + len)`.
        ///
        /// `keepalive` must hold a reference (typically
        /// `Arc<MmapRegion>` from
        /// [`crate::download::sparse_file`]) that keeps the mapping
        /// alive for at least as long as this puncher, then drops it
        /// (so `munmap` runs) when the puncher is dropped. The puncher
        /// itself only forwards the pointer to `madvise(2)`; it never
        /// dereferences the memory.
        ///
        /// # Safety
        ///
        /// The caller must ensure:
        /// - `[base, base + len)` is a single contiguous `mmap`'d region
        ///   (typically `MAP_SHARED`) on a `mmap`-mappable filesystem.
        /// - `keepalive` keeps the mapping alive at least as long as the
        ///   returned puncher, so the pointer remains valid for every
        ///   `madvise(2)` call.
        /// - `len` is the exact length passed to `mmap(2)`. Range checks
        ///   inside `punch` assume `[base, base + len)` is the upper
        ///   bound on valid offsets.
        #[must_use]
        pub unsafe fn for_mmap(
            base: NonNull<u8>,
            len: usize,
            keepalive: Arc<dyn Send + Sync>,
        ) -> Self {
            Self {
                mode: PunchMode::MadvRemove(Arc::new(MmapHandle {
                    base: SendSyncPtr(base),
                    len,
                    _keepalive: keepalive,
                })),
            }
        }

        /// `true` iff this puncher is in `MadvRemove` mode (i.e., was
        /// constructed via [`Self::for_mmap`]).
        #[must_use]
        pub fn is_mmap(&self) -> bool {
            matches!(self.mode, PunchMode::MadvRemove(_))
        }
    }

    impl Default for LinuxPuncher {
        fn default() -> Self {
            Self::new()
        }
    }

    impl PunchHole for LinuxPuncher {
        fn punch(&self, fd: OsFd<'_>, offset: ByteOffset, length: u64) -> Result<(), PunchError> {
            if length == 0 {
                return Ok(());
            }
            match &self.mode {
                PunchMode::Fallocate => fallocate_punch(fd, offset, length),
                PunchMode::MadvRemove(handle) => madv_remove_punch(handle, offset, length),
            }
        }

        fn block_size_hint(&self) -> u64 {
            // Runtime-queried so 16 KiB-page kernels (e.g. Asahi on
            // Apple Silicon) align punches to whole pages and don't
            // over-release into the decoder's lookahead via
            // madvise(MADV_REMOVE) length round-up.
            system_page_size()
        }
    }

    fn fallocate_punch(fd: OsFd<'_>, offset: ByteOffset, length: u64) -> Result<(), PunchError> {
        let raw_offset = offset.get();
        let i_offset = i64::try_from(raw_offset).map_err(|_| PunchError::OffsetOverflow {
            offset: raw_offset,
            length,
        })?;
        let i_length = i64::try_from(length).map_err(|_| PunchError::OffsetOverflow {
            offset: raw_offset,
            length,
        })?;

        let mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
        // SAFETY: `fd` is a `BorrowedFd<'_>` whose lifetime brackets
        // this call, so `fd.as_raw_fd()` is a valid file descriptor
        // for the duration of the syscall. `mode`, `i_offset`, and
        // `i_length` are plain integers carried across the C ABI by
        // value and have no aliasing concerns. `fallocate` returns
        // an `int` status; on error it sets the thread-local errno
        // which we read via `io::Error::last_os_error`.
        let rc = unsafe { fallocate(fd.as_raw_fd(), mode, i_offset, i_length) };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(e) if e == EOPNOTSUPP || e == EINVAL => Err(PunchError::Unsupported { errno: e }),
            _ => Err(PunchError::Io {
                offset: raw_offset,
                length,
                source: err,
            }),
        }
    }

    fn madv_remove_punch(
        handle: &MmapHandle,
        offset: ByteOffset,
        length: u64,
    ) -> Result<(), PunchError> {
        let raw_offset = offset.get();
        // `madvise(2)` takes `size_t`; the existing `PunchError::OffsetOverflow`
        // arm covers ranges that don't fit. Reuse it on `usize` overflow,
        // mirroring the fallocate path's handling of `i64` overflow.
        let off = usize::try_from(raw_offset).map_err(|_| PunchError::OffsetOverflow {
            offset: raw_offset,
            length,
        })?;
        let len = usize::try_from(length).map_err(|_| PunchError::OffsetOverflow {
            offset: raw_offset,
            length,
        })?;
        let end = off.checked_add(len).ok_or(PunchError::OffsetOverflow {
            offset: raw_offset,
            length,
        })?;
        if end > handle.len {
            return Err(PunchError::Io {
                offset: raw_offset,
                length,
                source: io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "madvise(MADV_REMOVE) range [{off}, {end}) exceeds mapped length {}",
                        handle.len
                    ),
                ),
            });
        }

        // SAFETY: `[base, base + len)` is a contiguous mmap'd region
        // (the `for_mmap` constructor's contract). `off + len <=
        // handle.len`, so `base + off` and `base + off + len` are inside
        // the mapping. We do not dereference the pointer, only forward
        // it to `madvise(2)`.
        let addr = unsafe { handle.base.0.as_ptr().add(off) };

        // SAFETY: `addr` is page-aligned by construction (the caller
        // aligns `offset` to `block_size_hint()` — the runtime page
        // size reported by `sysconf(_SC_PAGESIZE)` — and the mmap
        // base itself is page-aligned by `mmap(2)`). `len` arrives
        // already a multiple of `block_size_hint()` from the
        // extractor's per-step `align_down(quiescent_at, block) -
        // last_punched`, so `madvise` will not round up and release
        // bytes past the consumed boundary. The kernel performs no
        // aliasing-relevant operations on our memory; it only
        // operates on its own page tables.
        let rc = unsafe { madvise(addr.cast::<c_void>(), len, MADV_REMOVE) };
        if rc == 0 {
            return Ok(());
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(e) if e == EOPNOTSUPP || e == EINVAL || e == ENOSYS => {
                Err(PunchError::Unsupported { errno: e })
            }
            _ => Err(PunchError::Io {
                offset: raw_offset,
                length,
                source: err,
            }),
        }
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::io;
    use std::os::fd::AsRawFd;

    use super::{OsFd, PunchError, PunchHole};
    use crate::types::ByteOffset;

    /// `fcntl` command number for "deallocate a range of the file"
    /// (`F_PUNCHHOLE`). Defined as `99` in Darwin's `<sys/fcntl.h>`
    /// (xnu's `bsd/sys/fcntl.h`). Hard-coded here instead of pulled from
    /// the `libc` crate because `libc` is not on the dependency
    /// allowlist (`internal/ENGINEERING_STANDARDS.md` §2.2) and the constant
    /// is part of the stable Darwin ABI.
    const F_PUNCHHOLE: i32 = 99;

    /// Darwin errno: "operation not supported". `fcntl(F_PUNCHHOLE)`
    /// returns this on filesystems whose VFS layer rejects the request
    /// outright (HFS+, FAT, most FUSE mounts).
    const ENOTSUP: i32 = 45;
    /// Darwin errno: "operation not supported on socket". On Darwin under
    /// `__DARWIN_UNIX03` userland this is a *distinct* numeric value from
    /// `ENOTSUP`, unlike Linux where they share `95`.
    const EOPNOTSUPP: i32 = 102;
    /// Darwin errno: "invalid argument". Returned when the filesystem
    /// accepts the command but rejects the arguments — e.g., misaligned
    /// offsets on an APFS volume that requires sector alignment. Same
    /// numeric value as Linux.
    const EINVAL: i32 = 22;

    /// `fcntl(2)` `F_PUNCHHOLE` argument struct, mirroring the
    /// `fpunchhole_t` definition in Darwin's `<sys/fcntl.h>`.
    ///
    /// The Darwin SDK declares **four** fields — the kernel reads all
    /// 24 bytes of the struct via `copyin(2)` and validates them
    /// (release-build APFS rejects nonzero `reserved` with `EINVAL`,
    /// even though the SDK header comments mark the field "for
    /// alignment"). The previous version of this struct declared only
    /// three fields and relied on `repr(C)` to insert the 4-byte
    /// padding between `fp_flags` and `fp_offset`; that padding was
    /// **uninitialized stack memory**, and any nonzero garbage in it
    /// surfaced as `Punch(Unsupported { errno: 22 })` from the
    /// puncher.
    ///
    /// The Rust crash-resume regression test
    /// (`tests/test_coordinator_rar.rs::
    /// crash_resume_mid_entry_produces_identical_output`) fired this
    /// reliably in release mode (where the optimizer reuses dirty
    /// stack slots) but not in debug. Declaring `reserved`
    /// explicitly forces all 24 bytes to be initialized to known
    /// values.
    #[repr(C)]
    struct Fpunchhole {
        /// Currently unused by the kernel; must be zero.
        fp_flags: u32,
        /// Reserved by the kernel for 8-byte alignment of `fp_offset`;
        /// must be zero. The SDK header comment says "to maintain
        /// 8-byte alignment", but APFS validates the field anyway.
        reserved: u32,
        /// Byte offset of the first byte to deallocate.
        fp_offset: i64,
        /// Length of the region to deallocate, in bytes.
        fp_length: i64,
    }

    extern "C" {
        // Darwin's `fcntl(2)` is variadic at the C level
        // (`int fcntl(int fildes, int cmd, ...);`). We declare it
        // variadic-correctly so the Apple arm64 ABI — which lays
        // variadic arguments out on the stack starting from the first
        // variadic slot — is followed. Calling extern variadics from
        // Rust is stable; only *defining* them requires nightly.
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    }

    /// macOS puncher driving `fcntl(F_PUNCHHOLE)` (`PLAN_v2.md` §12).
    ///
    /// APFS supports the operation; HFS+, FAT, SMB/AFP/NFS shares, and
    /// most FUSE mounts return `ENOTSUP`/`EOPNOTSUPP`/`EINVAL` and we
    /// surface those as [`PunchError::Unsupported`] so the caller can
    /// downgrade to [`super::NoopPuncher`] without aborting — the same
    /// graceful-degrade contract `LinuxPuncher` honors.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct MacosPuncher;

    impl MacosPuncher {
        /// Construct a fresh [`MacosPuncher`].
        #[must_use]
        pub const fn new() -> Self {
            Self
        }
    }

    impl PunchHole for MacosPuncher {
        fn punch(&self, fd: OsFd<'_>, offset: ByteOffset, length: u64) -> Result<(), PunchError> {
            if length == 0 {
                return Ok(());
            }

            let raw_offset = offset.get();
            let i_offset = i64::try_from(raw_offset).map_err(|_| PunchError::OffsetOverflow {
                offset: raw_offset,
                length,
            })?;
            let i_length = i64::try_from(length).map_err(|_| PunchError::OffsetOverflow {
                offset: raw_offset,
                length,
            })?;

            // The kernel reads all 24 bytes of `fpunchhole_t` via
            // `copyin(2)` and APFS validates `reserved == 0` even
            // though the SDK header marks the field "for alignment"
            // — see the doc comment on [`Fpunchhole`] for the full
            // story.
            let mut arg = Fpunchhole {
                fp_flags: 0,
                reserved: 0,
                fp_offset: i_offset,
                fp_length: i_length,
            };

            // SAFETY: `fd` is a `BorrowedFd<'_>` whose lifetime brackets
            // this call, so `fd.as_raw_fd()` is a valid file descriptor
            // for the duration of the syscall. `arg` is a stack-local
            // `#[repr(C)]` value matching Darwin's `fpunchhole_t`
            // layout, valid for reads/writes by the kernel for the
            // duration of the call. `fcntl` returns an `int`; on error
            // it sets the thread-local errno which we read via
            // `io::Error::last_os_error`.
            let rc = unsafe { fcntl(fd.as_raw_fd(), F_PUNCHHOLE, &mut arg as *mut Fpunchhole) };
            if rc == 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(e) if e == ENOTSUP || e == EOPNOTSUPP || e == EINVAL => {
                    Err(PunchError::Unsupported { errno: e })
                }
                _ => Err(PunchError::Io {
                    offset: raw_offset,
                    length,
                    source: err,
                }),
            }
        }

        fn block_size_hint(&self) -> u64 {
            // APFS reports a 4096-byte block size on every Mac shipped
            // since the format launched in 2017; matches the Linux
            // default and keeps the `align_down` math identical across
            // platforms.
            4096
        }
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use std::io;
    use std::os::windows::io::AsRawHandle;

    use super::{OsFd, PunchError, PunchHole};
    use crate::types::ByteOffset;

    /// `FSCTL_SET_ZERO_DATA` from `<winioctl.h>`. Hard-coded so we
    /// don't pull in the `Win32_System_Ioctl` feature of
    /// `windows-sys`; the constant is part of the stable NT
    /// device-IO ABI (same precedent as the macos puncher's
    /// `F_PUNCHHOLE = 99`).
    const FSCTL_SET_ZERO_DATA: u32 = 0x0009_80C8;

    /// Win32 error codes the puncher maps to
    /// [`PunchError::Unsupported`]. All three mean "this filesystem
    /// doesn't do hole-punching" rather than a real failure:
    ///
    /// * `ERROR_INVALID_FUNCTION` (1) — FAT32 / exFAT.
    /// * `ERROR_NOT_SUPPORTED` (50) — most network mounts (SMB,
    ///   WebDAV) and some FUSE-style drivers.
    /// * `ERROR_INVALID_PARAMETER` (87) — NTFS volumes where the
    ///   file is missing the sparse attribute (paired with a
    ///   `FSCTL_SET_SPARSE` failure in `download::sparse_file`);
    ///   degrading silently keeps the puncher consistent with the
    ///   pre-§4 `NoopPuncher` behavior on those volumes.
    const ERROR_INVALID_FUNCTION: i32 = 1;
    const ERROR_NOT_SUPPORTED: i32 = 50;
    const ERROR_INVALID_PARAMETER: i32 = 87;

    /// `FILE_ZERO_DATA_INFORMATION` from `<winioctl.h>`. Two `i64`s
    /// describing the half-open `[FileOffset, BeyondFinalZero)` range
    /// to zero / deallocate. NTFS deallocates whole clusters within
    /// that range; misaligned tails inside a cluster get zeroed
    /// without deallocation (mirroring the partial-block behavior of
    /// `fallocate(PUNCH_HOLE)`).
    #[repr(C)]
    struct FileZeroDataInformation {
        file_offset: i64,
        beyond_final_zero: i64,
    }

    /// NTFS hole-punching puncher (`PLAN_v3_windows.md` §4).
    ///
    /// Calls `DeviceIoControl(handle, FSCTL_SET_ZERO_DATA, …)` with
    /// a [`FileZeroDataInformation`] argument struct against the
    /// borrowed handle. Requires the file have the NTFS sparse
    /// attribute set (the matching call site is
    /// [`crate::download::sparse_file::open_at_size`], which calls
    /// `FSCTL_SET_SPARSE` on every fresh-create). On filesystems
    /// without sparse support (FAT32, exFAT, most network mounts)
    /// the puncher surfaces [`PunchError::Unsupported`] so the
    /// caller can downgrade to [`super::NoopPuncher`] without
    /// aborting, matching the macOS / Linux contract.
    #[derive(Debug, Default, Clone, Copy)]
    pub struct WindowsPuncher;

    impl WindowsPuncher {
        /// Construct a fresh [`WindowsPuncher`].
        #[must_use]
        pub const fn new() -> Self {
            Self
        }
    }

    impl PunchHole for WindowsPuncher {
        fn punch(&self, fd: OsFd<'_>, offset: ByteOffset, length: u64) -> Result<(), PunchError> {
            if length == 0 {
                return Ok(());
            }

            let raw_offset = offset.get();
            let off_i64 = i64::try_from(raw_offset).map_err(|_| PunchError::OffsetOverflow {
                offset: raw_offset,
                length,
            })?;
            let len_i64 = i64::try_from(length).map_err(|_| PunchError::OffsetOverflow {
                offset: raw_offset,
                length,
            })?;
            let end_i64 = off_i64
                .checked_add(len_i64)
                .ok_or(PunchError::OffsetOverflow {
                    offset: raw_offset,
                    length,
                })?;

            let arg = FileZeroDataInformation {
                file_offset: off_i64,
                beyond_final_zero: end_i64,
            };

            use windows_sys::Win32::System::IO::DeviceIoControl;
            let mut bytes_returned: u32 = 0;
            // SAFETY: `fd` is borrowed for the duration of this
            // call, so the raw handle stays valid. `arg` is a
            // stack-local `#[repr(C)]` value matching
            // `FILE_ZERO_DATA_INFORMATION`. We pass `&arg` as the
            // input buffer (16 bytes) and null+0 for the output
            // buffer (this FSCTL produces no output). The OVERLAPPED
            // pointer is null because peel always opens its sparse
            // files synchronously. `bytes_returned` is required to
            // be non-null but we discard the value.
            let rc = unsafe {
                DeviceIoControl(
                    fd.as_raw_handle() as _,
                    FSCTL_SET_ZERO_DATA,
                    std::ptr::addr_of!(arg).cast(),
                    std::mem::size_of::<FileZeroDataInformation>() as u32,
                    std::ptr::null_mut(),
                    0,
                    &mut bytes_returned,
                    std::ptr::null_mut(),
                )
            };
            if rc != 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(e)
                    if e == ERROR_INVALID_FUNCTION
                        || e == ERROR_NOT_SUPPORTED
                        || e == ERROR_INVALID_PARAMETER =>
                {
                    Err(PunchError::Unsupported { errno: e })
                }
                _ => Err(PunchError::Io {
                    offset: raw_offset,
                    length,
                    source: err,
                }),
            }
        }

        fn block_size_hint(&self) -> u64 {
            // NTFS default cluster size on volumes ≤ 16 TiB is
            // 4096 bytes; the spec allows up to 2 MiB on very
            // large volumes formatted with `format /A:nK`. The
            // under-aligned tail of a punch on a non-default
            // volume is silently retained by NTFS — correct, just
            // less effective. Querying the actual cluster size via
            // `GetDiskFreeSpaceW` is filed as `O.WIN.CLUSTER_SIZE`
            // (round-two follow-on).
            4096
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::os_fd::AsOsFd;

    // ---- align_down ---------------------------------------------------

    #[test]
    fn align_down_returns_zero_for_value_below_alignment() {
        assert_eq!(align_down(0, 4096), Some(0));
        assert_eq!(align_down(1, 4096), Some(0));
        assert_eq!(align_down(4095, 4096), Some(0));
    }

    #[test]
    fn align_down_passes_through_exact_multiples() {
        assert_eq!(align_down(4096, 4096), Some(4096));
        assert_eq!(align_down(4096 * 7, 4096), Some(4096 * 7));
    }

    #[test]
    fn align_down_truncates_partial_tail() {
        assert_eq!(align_down(8195, 4096), Some(8192));
        assert_eq!(align_down(12_999, 4096), Some(12_288));
    }

    #[test]
    fn align_down_rejects_zero_alignment() {
        assert_eq!(align_down(123, 0), None);
        assert_eq!(align_down(0, 0), None);
    }

    #[test]
    fn align_down_handles_max_value() {
        let r = align_down(u64::MAX, 4096).expect("non-zero alignment");
        assert_eq!(r % 4096, 0);
        assert_eq!(r, (u64::MAX / 4096) * 4096);
    }

    #[test]
    fn align_down_property_is_idempotent() {
        // Aligning an already-aligned value is the identity.
        for v in [0u64, 1, 4096, 8192, 1_000_000, u64::MAX / 2] {
            for a in [1u64, 2, 512, 4096, 65_536] {
                let once = align_down(v, a).expect("a > 0");
                let twice = align_down(once, a).expect("a > 0");
                assert_eq!(once, twice);
                assert_eq!(once % a, 0);
                assert!(once <= v);
            }
        }
    }

    // ---- align_up -----------------------------------------------------

    #[test]
    fn align_up_zero_stays_zero() {
        assert_eq!(align_up(0, 4096), Some(0));
    }

    #[test]
    fn align_up_passes_through_exact_multiples() {
        assert_eq!(align_up(4096, 4096), Some(4096));
        assert_eq!(align_up(4096 * 7, 4096), Some(4096 * 7));
    }

    #[test]
    fn align_up_rounds_partial_value_to_next_block() {
        assert_eq!(align_up(1, 4096), Some(4096));
        assert_eq!(align_up(4095, 4096), Some(4096));
        assert_eq!(align_up(8195, 4096), Some(12_288));
    }

    #[test]
    fn align_up_rejects_zero_alignment() {
        assert_eq!(align_up(123, 0), None);
        assert_eq!(align_up(0, 0), None);
    }

    #[test]
    fn align_up_returns_none_on_overflow() {
        assert_eq!(align_up(u64::MAX, 4096), None);
        assert_eq!(align_up(u64::MAX - 1, 4096), None);
    }

    // ---- NoopPuncher --------------------------------------------------

    #[test]
    fn noop_puncher_block_size_hint_is_4096() {
        assert_eq!(NoopPuncher::new().block_size_hint(), 4096);
    }

    #[test]
    fn noop_puncher_returns_ok_for_any_args() {
        // Any borrowed fd will do; stdout is always open.
        let stdout = std::io::stdout();
        let fd = stdout.as_os_fd();
        let p = NoopPuncher::new();
        assert!(p.punch(fd, ByteOffset::ZERO, 0).is_ok());
        assert!(p.punch(fd, ByteOffset::new(4096), 4096).is_ok());
        assert!(p
            .punch(fd, ByteOffset::new(u64::MAX / 2), u64::MAX / 2)
            .is_ok());
    }

    // ---- default_puncher ---------------------------------------------

    #[test]
    fn default_puncher_reports_nonzero_block_size_hint() {
        let p = default_puncher();
        assert!(p.block_size_hint() > 0);
    }

    // ---- LinuxPuncher (linux-only) -----------------------------------

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_puncher_rejects_offset_above_i64_max() {
        let stdout = std::io::stdout();
        let fd = stdout.as_os_fd();
        let p = LinuxPuncher::new();
        let off = ByteOffset::new(u64::try_from(i64::MAX).unwrap_or(0).wrapping_add(1));
        match p.punch(fd, off, 1) {
            Err(PunchError::OffsetOverflow { offset, length }) => {
                assert_eq!(offset, off.get());
                assert_eq!(length, 1);
            }
            other => panic!("expected OffsetOverflow, got {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_puncher_rejects_length_above_i64_max() {
        let stdout = std::io::stdout();
        let fd = stdout.as_os_fd();
        let p = LinuxPuncher::new();
        let len = u64::try_from(i64::MAX).unwrap_or(0).wrapping_add(1);
        match p.punch(fd, ByteOffset::ZERO, len) {
            Err(PunchError::OffsetOverflow { offset, length }) => {
                assert_eq!(offset, 0);
                assert_eq!(length, len);
            }
            other => panic!("expected OffsetOverflow, got {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_puncher_zero_length_is_noop_ok() {
        let stdout = std::io::stdout();
        let fd = stdout.as_os_fd();
        let p = LinuxPuncher::new();
        // No syscall happens for length 0, so a non-regular fd (stdout)
        // is fine; we are checking the early-return contract.
        assert!(p.punch(fd, ByteOffset::ZERO, 0).is_ok());
        assert!(p.punch(fd, ByteOffset::new(1024), 0).is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_puncher_default_mode_is_fallocate() {
        let p = LinuxPuncher::new();
        assert!(!p.is_mmap());
    }

    // for_mmap() construction itself is `unsafe`, but we can verify the
    // mode flag flips without dereferencing the (deliberately fake)
    // pointer.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_puncher_for_mmap_flips_mode() {
        use std::ptr::NonNull;
        use std::sync::Arc;

        // SAFETY: this puncher will not be used to call `punch`; we
        // only inspect `is_mmap`. The pointer is therefore never
        // dereferenced and the keepalive Arc is sufficient lifetime
        // glue for that read-only inspection.
        let p = unsafe {
            LinuxPuncher::for_mmap(
                NonNull::new(8usize as *mut u8).expect("nonzero"),
                4096,
                Arc::new(()) as Arc<dyn Send + Sync>,
            )
        };
        assert!(p.is_mmap());
    }

    // ---- MacosPuncher (macos-only) -----------------------------------

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_puncher_block_size_hint_is_4096() {
        assert_eq!(MacosPuncher::new().block_size_hint(), 4096);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_puncher_zero_length_is_noop_ok() {
        let stdout = std::io::stdout();
        let fd = stdout.as_os_fd();
        let p = MacosPuncher::new();
        // No syscall happens for length 0, so a non-regular fd (stdout)
        // is fine; we are checking the early-return contract.
        assert!(p.punch(fd, ByteOffset::ZERO, 0).is_ok());
        assert!(p.punch(fd, ByteOffset::new(1024), 0).is_ok());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_puncher_rejects_offset_above_i64_max() {
        let stdout = std::io::stdout();
        let fd = stdout.as_os_fd();
        let p = MacosPuncher::new();
        let off = ByteOffset::new(u64::try_from(i64::MAX).unwrap_or(0).wrapping_add(1));
        match p.punch(fd, off, 1) {
            Err(PunchError::OffsetOverflow { offset, length }) => {
                assert_eq!(offset, off.get());
                assert_eq!(length, 1);
            }
            other => panic!("expected OffsetOverflow, got {other:?}"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_puncher_rejects_length_above_i64_max() {
        let stdout = std::io::stdout();
        let fd = stdout.as_os_fd();
        let p = MacosPuncher::new();
        let len = u64::try_from(i64::MAX).unwrap_or(0).wrapping_add(1);
        match p.punch(fd, ByteOffset::ZERO, len) {
            Err(PunchError::OffsetOverflow { offset, length }) => {
                assert_eq!(offset, 0);
                assert_eq!(length, len);
            }
            other => panic!("expected OffsetOverflow, got {other:?}"),
        }
    }

    // ---- WindowsPuncher (windows-only) -------------------------------

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_puncher_block_size_hint_is_4096() {
        assert_eq!(WindowsPuncher::new().block_size_hint(), 4096);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_puncher_zero_length_is_noop_ok() {
        let stdout = std::io::stdout();
        let fd = stdout.as_os_fd();
        let p = WindowsPuncher::new();
        // No syscall happens for length 0, so a non-regular handle
        // (stdout) is fine; we are checking the early-return contract.
        assert!(p.punch(fd, ByteOffset::ZERO, 0).is_ok());
        assert!(p.punch(fd, ByteOffset::new(1024), 0).is_ok());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_puncher_rejects_offset_above_i64_max() {
        let stdout = std::io::stdout();
        let fd = stdout.as_os_fd();
        let p = WindowsPuncher::new();
        let off = ByteOffset::new(u64::try_from(i64::MAX).unwrap_or(0).wrapping_add(1));
        match p.punch(fd, off, 1) {
            Err(PunchError::OffsetOverflow { offset, length }) => {
                assert_eq!(offset, off.get());
                assert_eq!(length, 1);
            }
            other => panic!("expected OffsetOverflow, got {other:?}"),
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_puncher_rejects_length_above_i64_max() {
        let stdout = std::io::stdout();
        let fd = stdout.as_os_fd();
        let p = WindowsPuncher::new();
        let len = u64::try_from(i64::MAX).unwrap_or(0).wrapping_add(1);
        match p.punch(fd, ByteOffset::ZERO, len) {
            Err(PunchError::OffsetOverflow { offset, length }) => {
                assert_eq!(offset, 0);
                assert_eq!(length, len);
            }
            other => panic!("expected OffsetOverflow, got {other:?}"),
        }
    }

    /// End-to-end NTFS demo (`PLAN_v3_windows.md` §4): create a
    /// sparse file, write into it so disk clusters get allocated,
    /// punch a prefix, and verify the allocation drops while the
    /// logical length is preserved. Skipped (not failed) when the
    /// temp directory is not NTFS or the OS rejects the FSCTL —
    /// matches the macOS test's "skip on non-APFS" posture.
    #[cfg(target_os = "windows")]
    #[test]
    fn windows_puncher_releases_blocks_on_ntfs() {
        use std::fs::OpenOptions;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::IO::DeviceIoControl;

        // FSCTL_SET_SPARSE = 0x000900C4 (see `download::sparse_file::set_sparse_attribute`).
        const FSCTL_SET_SPARSE: u32 = 0x0009_00C4;

        // 16 MiB is comfortably > a single NTFS cluster (default
        // 4 KiB on volumes ≤ 16 TiB) and small enough to write
        // quickly in a unit test. Punching the first 8 MiB then
        // checking that `AllocationSize` drops by at least 4 MiB
        // is loose enough to pass on volumes with larger cluster
        // sizes (which a CI runner might have on a backup-style
        // disk) while still catching a no-op `WindowsPuncher`.
        let total: u64 = 16 * 1024 * 1024;
        let punch_len: u64 = 8 * 1024 * 1024;
        let min_drop: u64 = 4 * 1024 * 1024;

        let path = unique_temp_path("windows_punch_e2e");
        let _g = TempCleanup(path.clone());
        let file = match OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
        {
            Ok(f) => f,
            Err(e) => {
                eprintln!("skipping windows_puncher_releases_blocks: open failed: {e}");
                return;
            }
        };

        // Mark the file sparse before extending; otherwise the
        // `set_len` zero-extension allocates all 16 MiB up front
        // and there's nothing to punch.
        let handle = file.as_raw_handle();
        let mut bytes_returned: u32 = 0;
        // SAFETY: `file` outlives this call; null buffers because
        // FSCTL_SET_SPARSE takes no input/output payload in its
        // default "set true" form.
        let rc = unsafe {
            DeviceIoControl(
                handle as _,
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
            let err = std::io::Error::last_os_error();
            eprintln!(
                "skipping windows_puncher_releases_blocks: \
                 filesystem does not support sparse files ({err})",
            );
            return;
        }

        file.set_len(total).expect("set_len 16 MiB");

        // Write actual data so the clusters get allocated on disk
        // rather than staying as a logical hole. Use `seek_write` so
        // the file pointer never moves out from under any other test
        // (defensive — this test is solo against its own temp file).
        use std::os::windows::fs::FileExt as _;
        let chunk = vec![0xABu8; 64 * 1024];
        let mut written: u64 = 0;
        while written < total {
            let n = file
                .seek_write(&chunk, written)
                .expect("seek_write succeeds");
            written += n as u64;
        }
        file.sync_all().expect("sync_all after fill");

        let alloc_before = file_allocation_size(&file).expect("FILE_STANDARD_INFO before");
        // Sanity-check the test premise: writes actually allocated
        // disk space. If the filesystem decided to deduplicate or
        // skip allocation, the puncher's "release" is meaningless.
        assert!(
            alloc_before >= total - 64 * 1024,
            "expected pre-punch allocation near {total}, got {alloc_before}",
        );

        let puncher = WindowsPuncher::new();
        let fd = file.as_os_fd();
        match puncher.punch(fd, ByteOffset::ZERO, punch_len) {
            Ok(()) => {}
            Err(PunchError::Unsupported { errno }) => {
                eprintln!(
                    "skipping windows_puncher_releases_blocks: puncher unsupported (errno {errno})",
                );
                return;
            }
            Err(e) => panic!("punch failed: {e:?}"),
        }

        let alloc_after = file_allocation_size(&file).expect("FILE_STANDARD_INFO after");
        let logical_size = file.metadata().expect("metadata").len();
        assert_eq!(
            logical_size, total,
            "logical size must be preserved across punch"
        );
        let dropped = alloc_before.saturating_sub(alloc_after);
        assert!(
            dropped >= min_drop,
            "expected allocation to drop by at least {min_drop} bytes, \
             dropped {dropped} (before {alloc_before}, after {alloc_after})",
        );
    }

    #[cfg(target_os = "windows")]
    fn file_allocation_size(file: &std::fs::File) -> std::io::Result<u64> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            FileStandardInfo, GetFileInformationByHandleEx, FILE_STANDARD_INFO,
        };
        let mut info: FILE_STANDARD_INFO = unsafe { std::mem::zeroed() };
        // SAFETY: `file` outlives this call. The Win32 API writes
        // `size_of::<FILE_STANDARD_INFO>()` bytes into `info`; we
        // pass the exact size and a matching `info_class` value.
        let rc = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle() as _,
                FileStandardInfo,
                std::ptr::addr_of_mut!(info).cast(),
                std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
            )
        };
        if rc == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(info.AllocationSize as u64)
    }

    /// Local helpers reused by the Windows E2E test. Kept in
    /// `mod tests` so they don't leak into the public surface.
    #[cfg(target_os = "windows")]
    fn unique_temp_path(label: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static UNIQ: AtomicU64 = AtomicU64::new(0);
        let pid = std::process::id();
        let n = UNIQ.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("peel_punch_{label}_{pid}_{nanos}_{n}.bin"))
    }

    #[cfg(target_os = "windows")]
    struct TempCleanup(std::path::PathBuf);
    #[cfg(target_os = "windows")]
    impl Drop for TempCleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}
