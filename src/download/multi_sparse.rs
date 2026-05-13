//! Multi-part sparse landing: N [`SparseFile`]s, one per source part,
//! flattened into a single global byte-offset space for callers.
//!
//! # Why a wrapper
//!
//! Today's HTTP coordinator owns a single [`SparseFile`] whose logical
//! size equals the sum of every part's size. For single-URL runs and
//! for byte-concatenated multi-URL runs that's fine. For multi-volume
//! archives the plan
//! (`docs/PLAN_multivolume_archives.md` §7) wants each source volume
//! to land in its own `.peel.part.<idx>` file so:
//!
//! - the puncher can release blocks per volume (per-fd cursors avoid
//!   accidentally punching into a not-yet-decoded volume's metadata
//!   header through misaligned tails);
//! - a fully-extracted volume can be deleted independently of the
//!   others;
//! - the `.peel.part.<idx>` is a 1:1 image of the source `.partN.rar`
//!   so a user keeping the sidecars has them in the same shape as the
//!   remote.
//!
//! [`MultiSparse`] preserves the single-sparse-file API the existing
//! coordinator/pipeline call sites depend on:
//!
//! - `pwrite_at(global_offset, buf)` writes through the right per-part
//!   file, splitting transparently if the buffer crosses a part
//!   boundary.
//! - `read_at` / `read_exact_at` work the same way.
//! - `punch_via(puncher, offset, length)` dispatches the puncher to
//!   the right per-part fd(s), so callers never see per-part fds.
//! - `sync_all` / `order_writes` apply to every part.
//!
//! The single-part case is the construction this commit uses
//! everywhere; it degenerates to a one-element `Vec<SparseFile>` and
//! every dispatch is a direct passthrough. Multi-part construction is
//! shaped in this file but not wired into the coordinator yet —
//! `docs/PLAN_multivolume_archives.md` §7 Phase 3 lights that up.

#![cfg(unix)]

use std::os::fd::BorrowedFd;
use std::path::Path;

use thiserror::Error;

use super::sparse_file::{SparseFile, SparseFileError};
use crate::punch::{PunchError, PunchHole};
use crate::types::ByteOffset;

/// Construction errors for [`MultiSparse`].
#[derive(Debug, Error)]
pub enum MultiSparseError {
    /// `parts` was empty. The coordinator always has at least one
    /// part (the seed URL or path), so this is a programming error.
    #[error("multi-sparse must contain at least one part")]
    Empty,
    /// A part declared `total_size == 0`. Zero-length parts break the
    /// `boundaries[i] < boundaries[i+1]` invariant that
    /// [`MultiSparse::locate`] relies on for a unique answer, so they
    /// are rejected at construction time — matching
    /// [`super::multi_url::MultiPartSource::new`].
    #[error("part {index} declares zero size; zero-length parts are not allowed")]
    ZeroSizedPart {
        /// Index of the offending part.
        index: usize,
    },
    /// The running sum of part sizes overflowed `u64`.
    /// Realistically unreachable.
    #[error("total source size overflows u64 at part {index}")]
    TotalOverflow {
        /// Index at which the running total overflowed.
        index: usize,
    },
}

/// N [`SparseFile`]s flattened into one virtual byte range.
///
/// `boundaries[i] = sum(parts[0..i].total_size())`. The vector is
/// strictly monotone because zero-sized parts are rejected, so
/// [`Self::locate`] returns a unique `(part_idx, in_part_offset)` for
/// any `global < total_size()`.
///
/// `parts.len() == 1` is the single-URL case the existing coordinator
/// has shipped against forever; every method takes a fast direct path
/// in that case so the overhead of the wrapper is zero.
#[derive(Debug)]
pub struct MultiSparse {
    parts: Vec<SparseFile>,
    /// `len() == parts.len() + 1`. `boundaries[0] == 0`,
    /// `boundaries[parts.len()] == total_size`.
    boundaries: Vec<u64>,
    total_size: u64,
}

impl MultiSparse {
    /// Wrap a single [`SparseFile`] — the single-URL case.
    #[must_use]
    pub fn from_single(part: SparseFile) -> Self {
        let total_size = part.total_size();
        Self {
            boundaries: vec![0, total_size],
            parts: vec![part],
            total_size,
        }
    }

    /// Build from an ordered list of [`SparseFile`]s, one per source
    /// part. The flattened virtual byte range is
    /// `[0, sum(parts[i].total_size()))` and reads/writes route
    /// through [`Self::locate`].
    ///
    /// # Errors
    ///
    /// - [`MultiSparseError::Empty`] if `parts` is empty.
    /// - [`MultiSparseError::ZeroSizedPart`] when any part declares
    ///   `total_size == 0`.
    /// - [`MultiSparseError::TotalOverflow`] when the running sum
    ///   overflows `u64`.
    pub fn from_parts(parts: Vec<SparseFile>) -> Result<Self, MultiSparseError> {
        if parts.is_empty() {
            return Err(MultiSparseError::Empty);
        }
        let mut boundaries = Vec::with_capacity(parts.len() + 1);
        boundaries.push(0u64);
        let mut acc: u64 = 0;
        for (i, p) in parts.iter().enumerate() {
            let size = p.total_size();
            if size == 0 {
                return Err(MultiSparseError::ZeroSizedPart { index: i });
            }
            acc = acc
                .checked_add(size)
                .ok_or(MultiSparseError::TotalOverflow { index: i })?;
            boundaries.push(acc);
        }
        Ok(Self {
            parts,
            boundaries,
            total_size: acc,
        })
    }

    /// Total virtual size in bytes — the sum of every part's size.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Number of parts (always ≥ 1).
    #[must_use]
    pub fn part_count(&self) -> usize {
        self.parts.len()
    }

    /// `true` when this wrapper holds exactly one part (the single-URL
    /// case). Useful for the few call sites that still want to feed a
    /// single fd to APIs that take [`BorrowedFd`] (e.g. the streaming
    /// [`crate::extractor::Extractor`]'s `source_fd` parameter); the
    /// routing puncher in [`Self::punch_via`] handles every other
    /// case.
    #[must_use]
    pub fn is_single(&self) -> bool {
        self.parts.len() == 1
    }

    /// Borrow part `idx`, or `None` if out of range.
    #[must_use]
    pub fn part(&self, idx: usize) -> Option<&SparseFile> {
        self.parts.get(idx)
    }

    /// Borrow every part in order.
    #[must_use]
    pub fn parts(&self) -> &[SparseFile] {
        &self.parts
    }

    /// Find the part holding `global_offset`. Returns
    /// `Some((part_index, in_part_offset))` for any
    /// `global_offset < total_size()`. Out-of-bound offsets return
    /// `None`.
    #[must_use]
    pub fn locate(&self, global_offset: u64) -> Option<(usize, u64)> {
        if global_offset >= self.total_size {
            return None;
        }
        // Same shape as MultiPartSource::locate — boundaries[0] == 0
        // and boundaries[last] == total_size, so partition_point lands
        // in 1..=parts.len() and the subtraction below never
        // underflows.
        let p = self.boundaries.partition_point(|&b| b <= global_offset);
        let part_idx = p - 1;
        let in_part = global_offset - self.boundaries[part_idx];
        Some((part_idx, in_part))
    }

    /// Borrow the only part's fd, or `None` for multi-part wrappers.
    /// Multi-part callers must use [`Self::punch_via`] (the routing
    /// puncher) or [`Self::fd_for_part`] for diagnostics.
    #[must_use]
    pub fn single_fd(&self) -> Option<BorrowedFd<'_>> {
        if self.parts.len() == 1 {
            Some(self.parts[0].as_fd())
        } else {
            None
        }
    }

    /// Borrow part `idx`'s fd, or `None` if out of range.
    #[must_use]
    pub fn fd_for_part(&self, idx: usize) -> Option<BorrowedFd<'_>> {
        self.parts.get(idx).map(SparseFile::as_fd)
    }

    /// On-disk paths of every part, in order. Diagnostic / logging
    /// helper; the [`crate::checkpoint::Checkpoint`] resume path uses
    /// the per-part paths to verify each `.peel.part.<idx>` is
    /// consistent with the recorded bitmap.
    pub fn paths(&self) -> impl Iterator<Item = &Path> {
        self.parts.iter().map(SparseFile::path)
    }

    /// Diagnostic backend name. When the parts disagree (in practice
    /// they don't, because the coordinator opens them with the same
    /// backend), returns `"mixed"` to flag the unusual configuration.
    #[must_use]
    pub fn backend_name(&self) -> &'static str {
        let first = self.parts[0].backend_name();
        if self.parts.iter().any(|p| p.backend_name() != first) {
            "mixed"
        } else {
            first
        }
    }

    /// `true` iff every part is in `mmap` storage mode.
    #[must_use]
    pub fn is_mmap(&self) -> bool {
        self.parts.iter().all(SparseFile::is_mmap)
    }

    /// Write `buf` starting at the global byte offset `offset`. Splits
    /// transparently across part boundaries if the write straddles
    /// one. Single-part wrappers take the fast direct path.
    ///
    /// # Errors
    ///
    /// Returns [`SparseFileError::OutOfBounds`] when the write would
    /// extend past `total_size()`,
    /// [`SparseFileError::OffsetOverflow`] when `offset + buf.len()`
    /// overflows `u64`, or [`SparseFileError::Io`] for an OS error
    /// from any per-part write.
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
        if buf.is_empty() {
            return Ok(());
        }
        if self.parts.len() == 1 {
            return self.parts[0].pwrite_at(offset, buf);
        }
        let mut cursor = raw_offset;
        let mut buf_cursor = 0usize;
        while buf_cursor < buf.len() {
            // INVARIANT: cursor < end <= total_size so locate is Some.
            let Some((idx, in_part)) = self.locate(cursor) else {
                break;
            };
            let part_size = self.parts[idx].total_size();
            let bytes_left_in_part = part_size - in_part;
            let bytes_in_segment =
                ((buf.len() - buf_cursor) as u64).min(bytes_left_in_part) as usize;
            self.parts[idx].pwrite_at(
                ByteOffset::new(in_part),
                &buf[buf_cursor..buf_cursor + bytes_in_segment],
            )?;
            cursor += bytes_in_segment as u64;
            buf_cursor += bytes_in_segment;
        }
        Ok(())
    }

    /// Read up to `buf.len()` bytes starting at global offset
    /// `offset`. The return value is the number of bytes actually
    /// read. End-of-file at the virtual boundary is reported as a
    /// short read; intermediate per-part short reads (which a sparse
    /// landing pad does not normally produce, since the file was
    /// ftruncate'd to the part size) similarly truncate the result.
    ///
    /// # Errors
    ///
    /// Returns [`SparseFileError::OffsetOverflow`] on `offset +
    /// buf.len()` overflow, [`SparseFileError::Io`] on a per-part OS
    /// error.
    pub fn read_at(&self, offset: ByteOffset, buf: &mut [u8]) -> Result<usize, SparseFileError> {
        let raw_offset = offset.get();
        let len = buf.len() as u64;
        raw_offset
            .checked_add(len)
            .ok_or(SparseFileError::OffsetOverflow {
                offset: raw_offset,
                len,
            })?;
        if buf.is_empty() {
            return Ok(0);
        }
        if self.parts.len() == 1 {
            return self.parts[0].read_at(offset, buf);
        }
        if raw_offset >= self.total_size {
            return Ok(0);
        }
        let mut cursor = raw_offset;
        let mut buf_cursor = 0usize;
        while buf_cursor < buf.len() {
            let Some((idx, in_part)) = self.locate(cursor) else {
                break;
            };
            let part_size = self.parts[idx].total_size();
            let bytes_left_in_part = part_size - in_part;
            let bytes_in_segment =
                ((buf.len() - buf_cursor) as u64).min(bytes_left_in_part) as usize;
            let got = self.parts[idx].read_at(
                ByteOffset::new(in_part),
                &mut buf[buf_cursor..buf_cursor + bytes_in_segment],
            )?;
            buf_cursor += got;
            cursor += got as u64;
            if got < bytes_in_segment {
                // Short read from the underlying per-part file: this
                // is a real-world impossibility for a well-formed
                // sparse-mode part (ftruncate'd to `part_size`) but
                // truncating here preserves the contract that
                // read_at returns `Ok(0)` past EOF rather than
                // blocking the caller.
                break;
            }
        }
        Ok(buf_cursor)
    }

    /// Read exactly `buf.len()` bytes starting at global offset
    /// `offset`, looping on short reads. Crosses part boundaries
    /// transparently.
    ///
    /// # Errors
    ///
    /// Returns [`SparseFileError::Io`] (with
    /// `io::ErrorKind::UnexpectedEof`) if the underlying reads
    /// truncated before the buffer was filled, otherwise the same
    /// error set as [`Self::read_at`].
    pub fn read_exact_at(&self, offset: ByteOffset, buf: &mut [u8]) -> Result<(), SparseFileError> {
        let raw_offset = offset.get();
        let len = buf.len() as u64;
        raw_offset
            .checked_add(len)
            .ok_or(SparseFileError::OffsetOverflow {
                offset: raw_offset,
                len,
            })?;
        if buf.is_empty() {
            return Ok(());
        }
        if self.parts.len() == 1 {
            return self.parts[0].read_exact_at(offset, buf);
        }
        let mut cursor = raw_offset;
        let mut buf_cursor = 0usize;
        while buf_cursor < buf.len() {
            let Some((idx, in_part)) = self.locate(cursor) else {
                return Err(SparseFileError::Io {
                    offset: raw_offset,
                    len,
                    source: std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!(
                            "MultiSparse::read_exact_at hit total_size {} before filling {} bytes at offset {}",
                            self.total_size,
                            buf.len(),
                            raw_offset
                        ),
                    ),
                });
            };
            let part_size = self.parts[idx].total_size();
            let bytes_left_in_part = part_size - in_part;
            let bytes_in_segment =
                ((buf.len() - buf_cursor) as u64).min(bytes_left_in_part) as usize;
            self.parts[idx].read_exact_at(
                ByteOffset::new(in_part),
                &mut buf[buf_cursor..buf_cursor + bytes_in_segment],
            )?;
            cursor += bytes_in_segment as u64;
            buf_cursor += bytes_in_segment;
        }
        Ok(())
    }

    /// Punch `[offset, offset + length)` of the virtual stream via
    /// `puncher`, dispatching each per-part segment against the
    /// matching part's fd. Cross-part punches split into one
    /// [`PunchHole::punch`] call per part the range touches.
    ///
    /// Callers should align `offset` and `length` to
    /// `puncher.block_size_hint()` before calling — alignment lives
    /// at the caller per the existing puncher contract.
    /// `length == 0` is a no-op and never errors.
    ///
    /// # Errors
    ///
    /// Returns [`PunchError`] verbatim from the first per-part failure.
    pub fn punch_via(
        &self,
        puncher: &dyn PunchHole,
        offset: ByteOffset,
        length: u64,
    ) -> Result<(), PunchError> {
        if length == 0 {
            return Ok(());
        }
        let raw_offset = offset.get();
        let end = raw_offset
            .checked_add(length)
            .ok_or(PunchError::OffsetOverflow {
                offset: raw_offset,
                length,
            })?;
        if end > self.total_size {
            return Err(PunchError::OffsetOverflow {
                offset: raw_offset,
                length,
            });
        }
        if self.parts.len() == 1 {
            return puncher.punch(self.parts[0].as_fd(), offset, length);
        }
        let mut cursor = raw_offset;
        let mut remaining = length;
        while remaining > 0 {
            // INVARIANT: cursor < end <= total_size, so locate is Some.
            let Some((idx, in_part)) = self.locate(cursor) else {
                break;
            };
            let part_size = self.parts[idx].total_size();
            let bytes_left_in_part = part_size - in_part;
            let segment = remaining.min(bytes_left_in_part);
            puncher.punch(self.parts[idx].as_fd(), ByteOffset::new(in_part), segment)?;
            cursor += segment;
            remaining -= segment;
        }
        Ok(())
    }

    /// Flush pending writes for every part. Per-part `sync_all`
    /// semantics: `fsync(2)` in pwrite mode, `msync(MS_ASYNC)` in
    /// mmap mode (see [`SparseFile::sync_all`]).
    ///
    /// # Errors
    ///
    /// Stops on the first per-part failure and returns its
    /// [`SparseFileError`].
    pub fn sync_all(&self) -> Result<(), SparseFileError> {
        for p in &self.parts {
            p.sync_all()?;
        }
        Ok(())
    }

    /// Issue a `order_writes` barrier on every part (see
    /// [`SparseFile::order_writes`] for semantics).
    ///
    /// # Errors
    ///
    /// Stops on the first per-part failure.
    pub fn order_writes(&self) -> Result<(), SparseFileError> {
        for p in &self.parts {
            p.order_writes()?;
        }
        Ok(())
    }
}

/// `PunchHole` adapter that dispatches every `punch` call through a
/// shared [`MultiSparse`] reference, ignoring the caller-supplied fd.
///
/// Use when wrapping a platform-default puncher (`LinuxPuncher`,
/// `MacosPuncher`, …) so the streaming
/// [`crate::extractor::Extractor`] — whose `source_fd` parameter is a
/// single [`BorrowedFd`] — keeps its existing shape while routing
/// punches per-part underneath. The caller's `source_fd` argument is
/// dropped on every call; the wrapper consults
/// [`MultiSparse::punch_via`] instead.
///
/// Single-part wrappers fall back to a direct passthrough — the
/// puncher's `fd` argument is the one part's own fd in that case, so
/// the routing layer is a no-op.
pub struct RoutingPuncher<'a> {
    /// The multi-part sparse this routes against.
    sparse: &'a MultiSparse,
    /// The platform puncher every per-part call dispatches through.
    inner: &'a dyn PunchHole,
}

impl<'a> RoutingPuncher<'a> {
    /// Wrap `inner` so that `punch` calls route via `sparse`.
    #[must_use]
    pub fn new(sparse: &'a MultiSparse, inner: &'a dyn PunchHole) -> Self {
        Self { sparse, inner }
    }
}

impl PunchHole for RoutingPuncher<'_> {
    fn punch(
        &self,
        _fd: BorrowedFd<'_>,
        offset: ByteOffset,
        length: u64,
    ) -> Result<(), PunchError> {
        self.sparse.punch_via(self.inner, offset, length)
    }

    fn block_size_hint(&self) -> u64 {
        self.inner.block_size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::os::fd::AsFd;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::punch::NoopPuncher;

    static UNIQ: AtomicU64 = AtomicU64::new(0);

    fn tmp_path(label: &str) -> PathBuf {
        let n = UNIQ.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let mut p = std::env::temp_dir();
        p.push(format!("peel_multi_sparse_{label}_{pid}_{n}"));
        p
    }

    fn sparse(label: &str, size: u64) -> SparseFile {
        let path = tmp_path(label);
        SparseFile::open_or_create(&path, size).expect("create sparse")
    }

    #[test]
    fn from_parts_rejects_empty() {
        let err = MultiSparse::from_parts(Vec::new()).unwrap_err();
        assert!(matches!(err, MultiSparseError::Empty));
    }

    #[test]
    fn from_single_total_size_and_locate() {
        let s = sparse("single", 4096);
        let m = MultiSparse::from_single(s);
        assert_eq!(m.total_size(), 4096);
        assert_eq!(m.part_count(), 1);
        assert!(m.is_single());
        assert_eq!(m.locate(0), Some((0, 0)));
        assert_eq!(m.locate(4095), Some((0, 4095)));
        assert_eq!(m.locate(4096), None);
    }

    #[test]
    fn from_parts_three_part_locate() {
        let parts = vec![sparse("a", 100), sparse("b", 250), sparse("c", 650)];
        let m = MultiSparse::from_parts(parts).expect("ok");
        assert_eq!(m.total_size(), 1000);
        assert_eq!(m.part_count(), 3);
        assert!(!m.is_single());
        assert_eq!(m.locate(0), Some((0, 0)));
        assert_eq!(m.locate(99), Some((0, 99)));
        assert_eq!(m.locate(100), Some((1, 0)));
        assert_eq!(m.locate(349), Some((1, 249)));
        assert_eq!(m.locate(350), Some((2, 0)));
        assert_eq!(m.locate(999), Some((2, 649)));
        assert_eq!(m.locate(1000), None);
    }

    #[test]
    fn pwrite_and_read_round_trip_within_single_part() {
        let m = MultiSparse::from_parts(vec![sparse("a", 4096), sparse("b", 4096)]).expect("ok");
        let body = vec![0xABu8; 1024];
        m.pwrite_at(ByteOffset::new(2048), &body).expect("write");
        let mut got = vec![0u8; 1024];
        m.read_exact_at(ByteOffset::new(2048), &mut got)
            .expect("read");
        assert_eq!(got, body);
    }

    #[test]
    fn pwrite_and_read_round_trip_across_part_boundary() {
        let m = MultiSparse::from_parts(vec![sparse("a", 4096), sparse("b", 4096)]).expect("ok");
        let mut body = Vec::with_capacity(2048);
        body.extend((0u16..1024).map(|x| (x & 0xFF) as u8));
        body.extend((0u16..1024).map(|x| ((x >> 1) & 0xFF) as u8));
        // Write starting 1 KiB before the boundary; 2 KiB total, so
        // 1 KiB lands in part 0, 1 KiB in part 1.
        m.pwrite_at(ByteOffset::new(3072), &body).expect("write");
        let mut got = vec![0u8; 2048];
        m.read_exact_at(ByteOffset::new(3072), &mut got)
            .expect("read");
        assert_eq!(got, body);

        // Confirm the bytes actually landed in the correct per-part
        // files: read the second half via part(1) directly.
        let mut just_b = vec![0u8; 1024];
        m.part(1)
            .expect("part 1")
            .read_exact_at(ByteOffset::new(0), &mut just_b)
            .expect("read part1");
        assert_eq!(&just_b[..], &body[1024..]);
    }

    #[test]
    fn pwrite_rejects_out_of_bounds() {
        let m = MultiSparse::from_parts(vec![sparse("a", 4096), sparse("b", 4096)]).expect("ok");
        let body = vec![0u8; 16];
        let err = m.pwrite_at(ByteOffset::new(8190), &body).unwrap_err();
        assert!(matches!(err, SparseFileError::OutOfBounds { .. }));
    }

    #[test]
    fn read_at_past_total_size_returns_zero() {
        let m = MultiSparse::from_parts(vec![sparse("a", 64), sparse("b", 64)]).expect("ok");
        let mut buf = [0u8; 16];
        let n = m.read_at(ByteOffset::new(200), &mut buf).expect("read");
        assert_eq!(n, 0);
    }

    #[test]
    fn punch_via_dispatches_across_parts() {
        // NoopPuncher accepts any (fd, offset, length); we use it to
        // verify the dispatcher walks every per-part segment without
        // panicking and without leaving the routing math half-done.
        let m = MultiSparse::from_parts(vec![sparse("a", 4096), sparse("b", 4096)]).expect("ok");
        let p = NoopPuncher::new();
        // 3 KiB starting 1 KiB before the boundary: 1 KiB in part 0,
        // 2 KiB in part 1.
        m.punch_via(&p, ByteOffset::new(3072), 3072).expect("punch");
    }

    #[test]
    fn punch_via_zero_length_is_noop() {
        let m = MultiSparse::from_parts(vec![sparse("a", 4096), sparse("b", 4096)]).expect("ok");
        let p = NoopPuncher::new();
        m.punch_via(&p, ByteOffset::new(1024), 0).expect("punch");
        m.punch_via(&p, ByteOffset::new(8192), 0).expect("punch");
    }

    #[test]
    fn punch_via_rejects_out_of_bounds() {
        let m = MultiSparse::from_parts(vec![sparse("a", 4096), sparse("b", 4096)]).expect("ok");
        let p = NoopPuncher::new();
        let err = m
            .punch_via(&p, ByteOffset::new(8190), 16)
            .expect_err("out of range");
        assert!(matches!(err, PunchError::OffsetOverflow { .. }));
    }

    /// Verifies that `RoutingPuncher` passes through to the
    /// configured underlying puncher when `MultiSparse` holds a
    /// single part (the common case after Phase 2 lands). Uses
    /// `NoopPuncher` so the test stays platform-agnostic; the goal
    /// is the dispatch shape, not the underlying syscall.
    #[test]
    fn routing_puncher_single_part_passthrough() {
        let m = MultiSparse::from_single(sparse("single_route", 4096));
        let p = NoopPuncher::new();
        let rp = RoutingPuncher::new(&m, &p);
        // The fd argument is ignored by the routing puncher; pass
        // stdout's fd as a deliberate sentinel.
        let stdout = std::io::stdout();
        rp.punch(stdout.as_fd(), ByteOffset::new(1024), 1024)
            .expect("route");
        assert_eq!(rp.block_size_hint(), p.block_size_hint());
    }

    /// Two-part routing: a single `RoutingPuncher::punch` against a
    /// cross-boundary range must dispatch one punch per part.
    /// `NoopPuncher` returns success unconditionally, so this test
    /// only verifies the wrapper doesn't short-circuit (the
    /// cross-boundary range is the only branch that would).
    #[test]
    fn routing_puncher_multi_part_dispatch() {
        let m =
            MultiSparse::from_parts(vec![sparse("rp_a", 4096), sparse("rp_b", 4096)]).expect("ok");
        let p = NoopPuncher::new();
        let rp = RoutingPuncher::new(&m, &p);
        let stdout = std::io::stdout();
        rp.punch(stdout.as_fd(), ByteOffset::new(3072), 3072)
            .expect("route");
    }

    /// Cleanup any files we left around. The test layer doesn't go
    /// through a managed temp dir because the SparseFile constructor
    /// expects an explicit path; we mop up here.
    #[test]
    fn paths_lists_every_part_in_order() {
        let m = MultiSparse::from_parts(vec![sparse("p1", 1024), sparse("p2", 2048)]).expect("ok");
        let paths: Vec<_> = m.paths().collect();
        assert_eq!(paths.len(), 2);
        assert!(paths[0]
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.contains("p1"))
            .unwrap_or(false));
        assert!(paths[1]
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.contains("p2"))
            .unwrap_or(false));
    }
}
