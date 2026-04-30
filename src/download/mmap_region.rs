//! Safe wrapper around an `mmap(2)`'d shared file region for the
//! `mmap` storage variant of [`crate::download::SparseFile`]
//! (`PLAN_v2.md` §9).
//!
//! `MmapRegion` owns a `MAP_SHARED` mapping of a file's
//! `[0, total_size)` byte range. Workers write into the mapping via
//! [`MmapRegion::write_at`] (a bounded `memcpy` rather than a syscall);
//! the extractor reads through [`MmapRegion::read_at`]; the
//! coordinator's checkpoint cadence calls [`MmapRegion::msync_async`]
//! to bound the kernel's dirty-page window. The mmap-mode
//! [`crate::punch::LinuxPuncher::for_mmap`] uses [`MmapRegion::base`]
//! and [`MmapRegion::len`] to issue `madvise(MADV_REMOVE)` against
//! consumed-and-checkpointed prefixes.
//!
//! # Safety
//!
//! Construction of an `MmapRegion` issues an `unsafe` `mmap(2)` call;
//! everything else is `safe`. Each in-bounds offset/length pair maps to
//! a `memcpy` inside the mapping — within Rust's aliasing rules, every
//! such write is sound because:
//!
//! - The mapping is `MAP_SHARED` and we never hand out long-lived
//!   `&mut [u8]` references into it. We hold a single `NonNull<u8>` and
//!   `copy_nonoverlapping` from caller-supplied slices that live outside
//!   the mapping.
//! - Concurrent writes to disjoint sub-ranges are safe by construction:
//!   workers write at distinct chunk offsets (the bitmap arbitrates),
//!   and the kernel itself synchronizes shared-mapping writes with
//!   `pread`/`pwrite` from other threads. We do not rely on Rust
//!   reference-style aliasing rules across the mmap boundary; the
//!   region is always accessed through raw pointers + `copy_*` intrinsics.
//!
//! # Cleanup
//!
//! [`MmapRegion::drop`] calls `munmap(2)`. Keeping an `Arc<MmapRegion>`
//! alive keeps the mapping alive; the
//! [`crate::punch::LinuxPuncher::for_mmap`] keepalive is exactly that.

#![cfg(unix)]

use std::ffi::c_void;
use std::io;
use std::os::fd::AsRawFd;
use std::ptr::NonNull;

/// `mmap(2)` protection bit: pages may be read.
const PROT_READ: i32 = 0x01;
/// `mmap(2)` protection bit: pages may be written.
const PROT_WRITE: i32 = 0x02;
/// `mmap(2)` flag: shared mapping; writes are propagated to the
/// underlying file and visible to other mappings.
const MAP_SHARED: i32 = 0x01;
/// `msync(2)` flag: schedule the writeback but do not wait for it.
const MS_ASYNC: i32 = 0x01;

extern "C" {
    /// `void *mmap(void *addr, size_t length, int prot, int flags,
    ///              int fd, off_t offset);` — returns `MAP_FAILED`
    /// (`(void *)-1`) on error.
    fn mmap(
        addr: *mut c_void,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;

    /// `int munmap(void *addr, size_t length);`
    fn munmap(addr: *mut c_void, length: usize) -> i32;

    /// `int msync(void *addr, size_t length, int flags);`
    fn msync(addr: *mut c_void, length: usize, flags: i32) -> i32;
}

/// Owned `MAP_SHARED` mapping of a file's `[0, len)` range.
///
/// Constructed via [`MmapRegion::map`]. Drops via `munmap(2)`. `Send`
/// and `Sync` because the mapping is kernel-synchronized; concurrent
/// `write_at`/`read_at` calls to disjoint sub-ranges are safe.
pub struct MmapRegion {
    base: NonNull<u8>,
    len: usize,
}

// SAFETY: `NonNull<u8>` is `!Send + !Sync` by default, but the kernel
// synchronizes accesses to a `MAP_SHARED` region across threads. We
// only ever forward the pointer to `memcpy` / `madvise` / `msync` /
// `munmap`, never to operations that rely on Rust's reference-aliasing
// model.
unsafe impl Send for MmapRegion {}
// SAFETY: same justification as `Send`.
unsafe impl Sync for MmapRegion {}

impl MmapRegion {
    /// `mmap` the whole file `f` (offset `0`, length `len`) with
    /// `PROT_READ | PROT_WRITE` and `MAP_SHARED`.
    ///
    /// `len` must be the file's logical size (the caller is expected to
    /// `ftruncate` to the desired length first). Zero-length files are
    /// rejected — `mmap` of length 0 is undefined per POSIX, and the
    /// `peel` use case never asks to map a zero-byte source.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] for any `mmap(2)` failure
    /// (e.g. `ENOMEM`, `EACCES`, `ENODEV` on filesystems that don't
    /// support shared mappings).
    pub fn map<F: AsRawFd>(f: &F, len: u64) -> io::Result<Self> {
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "MmapRegion::map: zero-length mapping is undefined",
            ));
        }
        let len_usize = usize::try_from(len).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("MmapRegion::map: length {len} exceeds usize"),
            )
        })?;

        // SAFETY: `f.as_raw_fd()` is a valid fd for the duration of
        // this call (the borrow on `f` enforces that). We pass null as
        // the `addr` hint so the kernel chooses the address. `len_usize
        // > 0` per the early return above. `prot` and `flags` are
        // POSIX-defined integer constants.
        let raw = unsafe {
            mmap(
                std::ptr::null_mut(),
                len_usize,
                PROT_READ | PROT_WRITE,
                MAP_SHARED,
                f.as_raw_fd(),
                0,
            )
        };

        // `MAP_FAILED` is `(void *) -1`. Compare via `usize::MAX` cast
        // since Rust's `*mut c_void` doesn't have a sentinel constant.
        if raw as isize == -1 {
            return Err(io::Error::last_os_error());
        }
        let base = NonNull::new(raw as *mut u8)
            .ok_or_else(|| io::Error::other("mmap returned null without setting MAP_FAILED"))?;

        Ok(Self {
            base,
            len: len_usize,
        })
    }

    /// Pointer to the first byte of the mapping. Used by
    /// [`crate::punch::LinuxPuncher::for_mmap`] to compute
    /// `madvise(2)` addresses; not intended for direct dereferencing.
    #[must_use]
    pub fn base(&self) -> NonNull<u8> {
        self.base
    }

    /// Length of the mapping, in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` if the mapping is empty. Always `false` for a constructed
    /// `MmapRegion` (`map` rejects zero-length), kept for clippy's
    /// `len_without_is_empty` lint.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// `memcpy` `buf` into the mapping at byte offset `offset`.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] when `offset + buf.len()`
    /// would exceed the mapping. Concurrent `write_at` calls to
    /// disjoint ranges are safe; overlapping writes from multiple
    /// threads are *not* defined here (the bitmap-arbitrated chunk
    /// scheduling in [`crate::download::scheduler`] guarantees workers
    /// never collide).
    pub fn write_at(&self, offset: u64, buf: &[u8]) -> io::Result<()> {
        let off = usize::try_from(offset).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("MmapRegion::write_at: offset {offset} exceeds usize"),
            )
        })?;
        let end = off.checked_add(buf.len()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "MmapRegion::write_at: offset {off} + len {} overflows usize",
                    buf.len()
                ),
            )
        })?;
        if end > self.len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "MmapRegion::write_at: range [{off}, {end}) exceeds mapped length {}",
                    self.len
                ),
            ));
        }

        // SAFETY: `[off, end) ⊂ [0, self.len)` per the bounds check
        // above, so `self.base + off` and the next `buf.len()` bytes
        // are all inside the mapping. `buf` is borrowed for the
        // duration of the call and lives outside the mapping (Rust's
        // borrow checker enforces non-aliasing of the `&[u8]` source).
        // `copy_nonoverlapping` requires that source and destination
        // not alias; `buf` is a Rust-owned byte slice and the mapping
        // is kernel-owned memory, so they are disjoint.
        unsafe {
            std::ptr::copy_nonoverlapping(buf.as_ptr(), self.base.as_ptr().add(off), buf.len());
        }
        Ok(())
    }

    /// `memcpy` from the mapping at byte offset `offset` into `buf`,
    /// returning the number of bytes copied.
    ///
    /// Reads past the end of the mapping short-read (matching
    /// `pread(2)` / [`std::os::unix::fs::FileExt::read_at`]). Reading
    /// from offsets entirely past the end returns `Ok(0)`.
    ///
    /// # Errors
    ///
    /// Returns [`io::ErrorKind::InvalidInput`] when `offset` exceeds
    /// `usize::MAX`.
    pub fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let off = usize::try_from(offset).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("MmapRegion::read_at: offset {offset} exceeds usize"),
            )
        })?;
        if off >= self.len {
            return Ok(0);
        }
        let avail = self.len - off;
        let n = avail.min(buf.len());

        // SAFETY: `off < self.len`, `n <= self.len - off`, so
        // `self.base + off` and the next `n` bytes are inside the
        // mapping. `buf` is borrowed `&mut` for the duration of the
        // call and lives outside the mapping.
        unsafe {
            std::ptr::copy_nonoverlapping(self.base.as_ptr().add(off), buf.as_mut_ptr(), n);
        }
        Ok(n)
    }

    /// `msync(MS_ASYNC)` the entire mapping.
    ///
    /// Schedules writeback of dirty pages without waiting; bounds the
    /// kernel-side dirty window (`PLAN_v2.md` §9 step 3). For full
    /// durability the caller would need `MS_SYNC` plus an `fsync(2)` of
    /// the underlying fd; the §9 plan deliberately picks `MS_ASYNC`
    /// because checkpoint cadence already gates resume safety on
    /// quiescent boundaries, not on per-flush durability.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] for any `msync(2)` failure.
    pub fn msync_async(&self) -> io::Result<()> {
        // SAFETY: `[base, base + len)` is the live mapping. `msync` does
        // not perform any operation that the Rust aliasing model would
        // notice on caller-side memory; it operates on the kernel's
        // page tables and writeback queue.
        let rc = unsafe { msync(self.base.as_ptr().cast::<c_void>(), self.len, MS_ASYNC) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

impl std::fmt::Debug for MmapRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmapRegion")
            .field("base", &self.base.as_ptr())
            .field("len", &self.len)
            .finish()
    }
}

impl Drop for MmapRegion {
    fn drop(&mut self) {
        // SAFETY: `[base, base + len)` is the mapping we created in
        // `map`; `munmap` releases it. After this point no other code
        // holds a pointer into the region (the puncher's keepalive Arc
        // is dropped before the puncher itself is dropped, and we are
        // the last owner being torn down here).
        unsafe {
            let _ = munmap(self.base.as_ptr().cast::<c_void>(), self.len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::sync::atomic::{AtomicU64, Ordering};

    static UNIQ: AtomicU64 = AtomicU64::new(0);

    fn unique_temp_path(label: &str) -> std::path::PathBuf {
        let pid = std::process::id();
        let n = UNIQ.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("peel_mmap_{label}_{pid}_{nanos}_{n}.bin"))
    }

    struct CleanupOnDrop(std::path::PathBuf);
    impl Drop for CleanupOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn open_temp(label: &str, len: u64) -> (std::fs::File, CleanupOnDrop) {
        let path = unique_temp_path(label);
        let cleanup = CleanupOnDrop(path.clone());
        let file = OpenOptions::new()
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
    fn map_zero_length_is_rejected() {
        let (file, _cleanup) = open_temp("zero", 0);
        let err = MmapRegion::map(&file, 0).expect_err("must reject");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn write_at_round_trips_through_file_read() {
        let (mut file, _cleanup) = open_temp("write_round_trip", 4096);
        let r = MmapRegion::map(&file, 4096).expect("map");
        let payload: Vec<u8> = (0u8..32).collect();
        r.write_at(64, &payload).expect("write");
        // Force the kernel to flush before we re-read via the file
        // handle so this test is robust against pagecache lag.
        r.msync_async().expect("msync");

        file.seek(SeekFrom::Start(64)).expect("seek");
        let mut got = vec![0u8; 32];
        file.read_exact(&mut got).expect("read");
        assert_eq!(got, payload);
    }

    #[test]
    fn read_at_observes_file_writes() {
        let (mut file, _cleanup) = open_temp("read_round_trip", 4096);
        let payload: [u8; 16] = [0xAB; 16];
        file.seek(SeekFrom::Start(128)).expect("seek");
        file.write_all(&payload).expect("write");

        let r = MmapRegion::map(&file, 4096).expect("map");
        let mut got = [0u8; 16];
        let n = r.read_at(128, &mut got).expect("read");
        assert_eq!(n, 16);
        assert_eq!(got, payload);
    }

    #[test]
    fn read_past_eof_returns_zero() {
        let (file, _cleanup) = open_temp("read_eof", 32);
        let r = MmapRegion::map(&file, 32).expect("map");
        let mut got = vec![0u8; 16];
        let n = r.read_at(64, &mut got).expect("read");
        assert_eq!(n, 0);
    }

    #[test]
    fn read_short_at_eof() {
        let (file, _cleanup) = open_temp("read_short", 32);
        let r = MmapRegion::map(&file, 32).expect("map");
        let mut got = vec![0u8; 16];
        let n = r.read_at(24, &mut got).expect("read");
        assert_eq!(n, 8);
    }

    #[test]
    fn write_past_end_is_rejected() {
        let (file, _cleanup) = open_temp("write_oob", 64);
        let r = MmapRegion::map(&file, 64).expect("map");
        let err = r.write_at(48, &[0u8; 32]).expect_err("must reject");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }
}
