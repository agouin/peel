//! Multi-part source: N URLs whose byte-concatenation is one logical
//! archive stream (`internal/PLAN_multi_url_source.md` §1).
//!
//! Each part is a self-contained HTTP object with its own `Content-Length`,
//! `ETag`, and (optionally) per-part SHA-256 expectation. A
//! [`MultiPartSource`] flattens those parts into a single virtual byte
//! range `[0, sum(part_sizes))` so the rest of the pipeline — bitmap,
//! decoder cursor, hole-punching, checkpoint — keeps operating on one
//! global offset space.
//!
//! The two operations downstream code asks of this module:
//!
//! - [`MultiPartSource::locate`] — given a global byte offset, return the
//!   part it lives in and the in-part offset.
//! - [`MultiPartSource::dispatch_range`] — given a global ranged GET that
//!   may span a part boundary, split it into per-part segments. Each
//!   segment carries a part-relative range (for the `Range` request
//!   header) and a global range (for the sparse-file `pwrite_at`).
//!
//! The single-URL case is the `parts.len() == 1` case; existing pipeline
//! code constructs a one-element source and routes through the same
//! seam (`internal/PLAN_multi_url_source.md` §1 step 2).

#![cfg(unix)]

use thiserror::Error;

use super::worker::SourceFingerprint;
use crate::http::Url;
use crate::types::{ByteOffset, ByteRange};

/// One part of a multi-part source: a URL plus the metadata captured
/// at HEAD time and the optional per-part SHA-256.
#[derive(Debug, Clone)]
pub struct PartDescriptor {
    /// URL the worker issues ranged GETs against for bytes that fall
    /// within this part's range of the virtual stream.
    pub url: Url,
    /// `Content-Length` reported for this part. Must be non-zero —
    /// zero-byte parts are rejected by [`MultiPartSource::new`].
    pub size: u64,
    /// `ETag` / `Last-Modified` captured for *this* part at HEAD time.
    /// Each part has its own fingerprint; cross-part agreement is
    /// neither required nor expected (parts are distinct objects).
    pub fingerprint: SourceFingerprint,
    /// Expected SHA-256 of the part's bytes, if the user passed
    /// `--sha256` for it. Verified at the part-end boundary by
    /// `internal/PLAN_multi_url_source.md` §4.
    pub expected_sha256: Option<[u8; 32]>,
}

/// Construction errors for [`MultiPartSource`].
#[derive(Debug, Clone, Error)]
pub enum MultiPartSourceError {
    /// `parts` was empty.
    #[error("multi-part source must contain at least one part")]
    Empty,
    /// A part declared `size == 0`. Zero-length parts break the
    /// `boundaries[i] < boundaries[i+1]` invariant `locate` relies on
    /// for a unique answer, so they are rejected at construction time.
    #[error("part {index} declares zero size; zero-length parts are not allowed")]
    ZeroSizedPart {
        /// Index of the offending part.
        index: usize,
    },
    /// Sum of part sizes exceeded `u64::MAX`. Realistically unreachable
    /// (would need exabytes of source) but we surface it cleanly rather
    /// than wrapping silently.
    #[error("total source size overflows u64 at part {index}")]
    TotalOverflow {
        /// Index at which the running total overflowed.
        index: usize,
    },
}

/// N URLs flattened into one virtual byte range.
///
/// Built from a `Vec<PartDescriptor>`. The constructor computes
/// `boundaries[i] = sum(parts[0..i].size)` so [`locate`] is a single
/// `partition_point` lookup over the boundaries vec rather than a
/// linear scan over parts.
///
/// [`locate`]: Self::locate
#[derive(Debug, Clone)]
pub struct MultiPartSource {
    parts: Vec<PartDescriptor>,
    /// `len() == parts.len() + 1`. `boundaries[0] == 0`,
    /// `boundaries[parts.len()] == total_size`. Strictly monotone
    /// because zero-length parts are rejected.
    boundaries: Vec<u64>,
    total_size: u64,
}

impl MultiPartSource {
    /// Build a source from an ordered list of parts.
    ///
    /// # Errors
    ///
    /// - [`MultiPartSourceError::Empty`] if `parts` is empty.
    /// - [`MultiPartSourceError::ZeroSizedPart`] if any part declares
    ///   `size == 0`.
    /// - [`MultiPartSourceError::TotalOverflow`] if the running sum of
    ///   part sizes overflows `u64`.
    pub fn new(parts: Vec<PartDescriptor>) -> Result<Self, MultiPartSourceError> {
        if parts.is_empty() {
            return Err(MultiPartSourceError::Empty);
        }
        let mut boundaries = Vec::with_capacity(parts.len() + 1);
        boundaries.push(0u64);
        let mut acc: u64 = 0;
        for (i, p) in parts.iter().enumerate() {
            if p.size == 0 {
                return Err(MultiPartSourceError::ZeroSizedPart { index: i });
            }
            acc = acc
                .checked_add(p.size)
                .ok_or(MultiPartSourceError::TotalOverflow { index: i })?;
            boundaries.push(acc);
        }
        Ok(Self {
            parts,
            boundaries,
            total_size: acc,
        })
    }

    /// Convenience: build a single-part source from a primary URL,
    /// matching today's single-URL discovery output.
    ///
    /// # Errors
    ///
    /// Returns [`MultiPartSourceError::ZeroSizedPart`] when `size == 0`.
    pub fn from_single(
        url: Url,
        size: u64,
        fingerprint: SourceFingerprint,
        expected_sha256: Option<[u8; 32]>,
    ) -> Result<Self, MultiPartSourceError> {
        Self::new(vec![PartDescriptor {
            url,
            size,
            fingerprint,
            expected_sha256,
        }])
    }

    /// Total virtual size, i.e. the sum of all part sizes.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        self.total_size
    }

    /// Number of parts.
    #[must_use]
    pub fn len(&self) -> usize {
        self.parts.len()
    }

    /// Always `false` — a [`MultiPartSource`] holds at least one part by
    /// construction. Provided for completeness so call sites that need
    /// `is_empty` for `len`-paired clippy lints have a target.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    /// Borrow the part list in order.
    #[must_use]
    pub fn parts(&self) -> &[PartDescriptor] {
        &self.parts
    }

    /// Borrow part `idx`, or `None` if out of range.
    #[must_use]
    pub fn part(&self, idx: usize) -> Option<&PartDescriptor> {
        self.parts.get(idx)
    }

    /// Borrow the URL of part `idx`, or `None` if out of range.
    #[must_use]
    pub fn part_url(&self, idx: usize) -> Option<&Url> {
        self.parts.get(idx).map(|p| &p.url)
    }

    /// Borrow the half-open byte range covered by part `idx` in the
    /// virtual stream's coordinate space. Returns `None` if `idx` is
    /// out of range.
    #[must_use]
    pub fn part_global_range(&self, idx: usize) -> Option<ByteRange> {
        if idx >= self.parts.len() {
            return None;
        }
        let start = ByteOffset::new(self.boundaries[idx]);
        let end = ByteOffset::new(self.boundaries[idx + 1]);
        ByteRange::new(start, end)
    }

    /// Find the part containing `global_offset`.
    ///
    /// Returns `Some((part_index, in_part_offset))` for any
    /// `global_offset < total_size`; returns `None` for offsets at or
    /// past the end of the source.
    #[must_use]
    pub fn locate(&self, global_offset: u64) -> Option<(usize, u64)> {
        if global_offset >= self.total_size {
            return None;
        }
        // `partition_point` returns the first index whose boundary is
        // strictly greater than the target. Since `boundaries[0] == 0`
        // and `global_offset < total_size == boundaries[last]`, the
        // result is in `1..=parts.len()`, so the subtraction below
        // never underflows.
        let p = self.boundaries.partition_point(|&b| b <= global_offset);
        let part_idx = p - 1;
        let in_part = global_offset - self.boundaries[part_idx];
        Some((part_idx, in_part))
    }

    /// The global byte offset of the next part-boundary at or after
    /// `global_offset`, capped at `total_size` for the last part.
    /// Used by the scheduler to clamp adaptive-coalescing dispatches
    /// so they never cross a boundary.
    #[must_use]
    pub fn next_part_boundary_at_or_after(&self, global_offset: u64) -> u64 {
        // partition_point yields the first boundary strictly greater
        // than the target. With `boundaries[0] == 0`, the result is
        // in `1..=parts.len()`; reading `boundaries[idx]` always
        // returns the next boundary at or past `global_offset`.
        if global_offset >= self.total_size {
            return self.total_size;
        }
        let idx = self.boundaries.partition_point(|&b| b <= global_offset);
        // INVARIANT: idx is in 1..=parts.len() because
        // boundaries[0] == 0 <= global_offset. The boundary itself
        // (when global_offset is exactly on it) counts as "at or
        // after," and the +1 path covers offsets *inside* a part.
        self.boundaries[idx]
    }

    /// Split a global ranged GET into one segment per part it touches.
    ///
    /// Each yielded [`PartSegment`] carries a part-relative range
    /// (for the `Range` request header against `parts[idx].url`) and
    /// a global range (for `SparseFile::pwrite_at`). Empty input
    /// ranges produce no segments. Ranges that extend past
    /// `total_size` are silently clamped at the end — the scheduler
    /// already clamps to `total_size` at dispatch time so the clamp
    /// is defense-in-depth.
    pub fn dispatch_range(&self, global_range: ByteRange) -> DispatchSegments<'_> {
        DispatchSegments {
            source: self,
            cursor: global_range.start().get().min(self.total_size),
            end: global_range.end_exclusive().get().min(self.total_size),
        }
    }
}

/// One per-part segment of a global ranged GET.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PartSegment {
    /// Index into [`MultiPartSource::parts`] for the part this
    /// segment lives in.
    pub part_index: usize,
    /// Range within the part's own coordinate space `[0, part.size)`.
    /// Used as the `Range` request header value for the per-part GET.
    pub part_relative: ByteRange,
    /// Range within the virtual stream's coordinate space. Used as
    /// the `pwrite_at` offset on the sparse file.
    pub global: ByteRange,
}

/// Iterator returned by [`MultiPartSource::dispatch_range`]. Yields
/// at most `parts.len()` items.
#[derive(Debug)]
pub struct DispatchSegments<'a> {
    source: &'a MultiPartSource,
    cursor: u64,
    end: u64,
}

impl Iterator for DispatchSegments<'_> {
    type Item = PartSegment;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.end {
            return None;
        }
        // INVARIANT: `cursor < end <= total_size`, so `locate` returns Some.
        let (part_idx, in_part_start) = self.source.locate(self.cursor)?;
        let part_size = self.source.parts[part_idx].size;
        let bytes_left_in_part = part_size - in_part_start;
        let bytes_in_segment = (self.end - self.cursor).min(bytes_left_in_part);
        // INVARIANT: bytes_in_segment <= bytes_left_in_part, so the
        // part-relative end is in [0, part_size]; ByteRange::new accepts.
        let part_relative =
            ByteRange::from_start_len(ByteOffset::new(in_part_start), bytes_in_segment)?;
        let global = ByteRange::from_start_len(ByteOffset::new(self.cursor), bytes_in_segment)?;
        self.cursor += bytes_in_segment;
        Some(PartSegment {
            part_index: part_idx,
            part_relative,
            global,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).expect("test URL parses")
    }

    fn part(s: &str, size: u64) -> PartDescriptor {
        PartDescriptor {
            url: url(s),
            size,
            fingerprint: SourceFingerprint::default(),
            expected_sha256: None,
        }
    }

    fn three_part_source() -> MultiPartSource {
        // Sizes chosen so boundaries are 0, 100, 350, 1000.
        MultiPartSource::new(vec![
            part("https://h/p0", 100),
            part("https://h/p1", 250),
            part("https://h/p2", 650),
        ])
        .expect("valid")
    }

    // ---- construction ------------------------------------------------

    #[test]
    fn new_rejects_empty() {
        assert!(matches!(
            MultiPartSource::new(Vec::new()).unwrap_err(),
            MultiPartSourceError::Empty
        ));
    }

    #[test]
    fn new_rejects_zero_sized_part() {
        let parts = vec![part("https://h/p0", 100), part("https://h/p1", 0)];
        let err = MultiPartSource::new(parts).unwrap_err();
        assert!(matches!(
            err,
            MultiPartSourceError::ZeroSizedPart { index: 1 }
        ));
    }

    #[test]
    fn new_rejects_total_overflow() {
        let parts = vec![part("https://h/p0", u64::MAX - 5), part("https://h/p1", 10)];
        let err = MultiPartSource::new(parts).unwrap_err();
        assert!(matches!(
            err,
            MultiPartSourceError::TotalOverflow { index: 1 }
        ));
    }

    #[test]
    fn from_single_round_trips_to_one_part() {
        let s = MultiPartSource::from_single(
            url("https://h/only"),
            42,
            SourceFingerprint::default(),
            None,
        )
        .expect("ok");
        assert_eq!(s.len(), 1);
        assert_eq!(s.total_size(), 42);
        assert_eq!(
            s.part_url(0).map(Url::to_string).as_deref(),
            Some("https://h/only")
        );
    }

    #[test]
    fn total_size_is_sum_of_part_sizes() {
        let s = three_part_source();
        assert_eq!(s.total_size(), 1000);
        assert_eq!(s.len(), 3);
    }

    #[test]
    fn part_global_range_covers_each_part() {
        let s = three_part_source();
        let r0 = s.part_global_range(0).expect("p0");
        assert_eq!(r0.start().get(), 0);
        assert_eq!(r0.end_exclusive().get(), 100);
        let r1 = s.part_global_range(1).expect("p1");
        assert_eq!(r1.start().get(), 100);
        assert_eq!(r1.end_exclusive().get(), 350);
        let r2 = s.part_global_range(2).expect("p2");
        assert_eq!(r2.start().get(), 350);
        assert_eq!(r2.end_exclusive().get(), 1000);
        assert!(s.part_global_range(3).is_none());
    }

    // ---- locate ------------------------------------------------------

    #[test]
    fn locate_at_part_starts() {
        let s = three_part_source();
        assert_eq!(s.locate(0), Some((0, 0)));
        assert_eq!(s.locate(100), Some((1, 0)));
        assert_eq!(s.locate(350), Some((2, 0)));
    }

    #[test]
    fn locate_at_last_byte_of_each_part() {
        let s = three_part_source();
        assert_eq!(s.locate(99), Some((0, 99)));
        assert_eq!(s.locate(349), Some((1, 249)));
        assert_eq!(s.locate(999), Some((2, 649)));
    }

    #[test]
    fn locate_past_end_returns_none() {
        let s = three_part_source();
        assert_eq!(s.locate(1000), None);
        assert_eq!(s.locate(u64::MAX), None);
    }

    #[test]
    fn locate_in_middle_of_each_part() {
        let s = three_part_source();
        assert_eq!(s.locate(50), Some((0, 50)));
        assert_eq!(s.locate(225), Some((1, 125)));
        assert_eq!(s.locate(700), Some((2, 350)));
    }

    // ---- dispatch_range ---------------------------------------------

    fn segments(s: &MultiPartSource, start: u64, end: u64) -> Vec<PartSegment> {
        let r = ByteRange::new(ByteOffset::new(start), ByteOffset::new(end)).expect("valid range");
        s.dispatch_range(r).collect()
    }

    #[test]
    fn dispatch_empty_range_yields_nothing() {
        let s = three_part_source();
        assert!(segments(&s, 50, 50).is_empty());
    }

    #[test]
    fn dispatch_within_one_part_yields_one_segment() {
        let s = three_part_source();
        let segs = segments(&s, 25, 75);
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].part_index, 0);
        assert_eq!(segs[0].part_relative.start().get(), 25);
        assert_eq!(segs[0].part_relative.end_exclusive().get(), 75);
        assert_eq!(segs[0].global.start().get(), 25);
        assert_eq!(segs[0].global.end_exclusive().get(), 75);
    }

    #[test]
    fn dispatch_at_part_boundary_yields_one_segment() {
        // [0, 100) lands entirely in part 0; the boundary at 100 is
        // exclusive so part 1 is untouched.
        let s = three_part_source();
        let segs = segments(&s, 0, 100);
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].part_index, 0);
        assert_eq!(segs[0].part_relative.end_exclusive().get(), 100);
    }

    #[test]
    fn dispatch_spanning_two_parts_yields_two_segments() {
        let s = three_part_source();
        let segs = segments(&s, 50, 200);
        assert_eq!(segs.len(), 2);
        // Segment 0: part 0, [50, 100) global / [50, 100) part-relative.
        assert_eq!(segs[0].part_index, 0);
        assert_eq!(segs[0].part_relative.start().get(), 50);
        assert_eq!(segs[0].part_relative.end_exclusive().get(), 100);
        assert_eq!(segs[0].global.start().get(), 50);
        assert_eq!(segs[0].global.end_exclusive().get(), 100);
        // Segment 1: part 1, [100, 200) global / [0, 100) part-relative.
        assert_eq!(segs[1].part_index, 1);
        assert_eq!(segs[1].part_relative.start().get(), 0);
        assert_eq!(segs[1].part_relative.end_exclusive().get(), 100);
        assert_eq!(segs[1].global.start().get(), 100);
        assert_eq!(segs[1].global.end_exclusive().get(), 200);
    }

    #[test]
    fn dispatch_spanning_all_three_parts() {
        let s = three_part_source();
        let segs = segments(&s, 0, 1000);
        assert_eq!(segs.len(), 3);
        assert_eq!(segs[0].part_index, 0);
        assert_eq!(segs[0].part_relative.len(), 100);
        assert_eq!(segs[1].part_index, 1);
        assert_eq!(segs[1].part_relative.len(), 250);
        assert_eq!(segs[2].part_index, 2);
        assert_eq!(segs[2].part_relative.len(), 650);
        // Total covered must equal the input range length.
        let covered: u64 = segs.iter().map(|s| s.global.len()).sum();
        assert_eq!(covered, 1000);
    }

    #[test]
    fn dispatch_clamps_past_end() {
        let s = three_part_source();
        // Construct a range that legally extends past total_size; the
        // iterator should clamp at the source boundary.
        let r = ByteRange::new(ByteOffset::new(900), ByteOffset::new(1500)).expect("valid");
        let segs: Vec<_> = s.dispatch_range(r).collect();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].part_index, 2);
        assert_eq!(segs[0].global.end_exclusive().get(), 1000);
        assert_eq!(segs[0].part_relative.end_exclusive().get(), 650);
    }

    #[test]
    fn dispatch_starting_past_end_yields_nothing() {
        let s = three_part_source();
        let r = ByteRange::new(ByteOffset::new(2000), ByteOffset::new(3000)).expect("valid");
        assert!(s.dispatch_range(r).next().is_none());
    }

    #[test]
    fn dispatch_global_offsets_are_contiguous() {
        // For any range covering multiple parts, segment global ranges
        // must tile [start, end) without gap or overlap.
        let s = three_part_source();
        let segs = segments(&s, 75, 800);
        let mut cursor = 75u64;
        for seg in &segs {
            assert_eq!(seg.global.start().get(), cursor);
            cursor = seg.global.end_exclusive().get();
        }
        assert_eq!(cursor, 800);
    }

    #[test]
    fn dispatch_part_relative_offsets_match_part_layout() {
        let s = three_part_source();
        // [120, 360) -> part 1 [20, 250) + part 2 [0, 10)
        let segs = segments(&s, 120, 360);
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].part_index, 1);
        assert_eq!(segs[0].part_relative.start().get(), 20);
        assert_eq!(segs[0].part_relative.end_exclusive().get(), 250);
        assert_eq!(segs[1].part_index, 2);
        assert_eq!(segs[1].part_relative.start().get(), 0);
        assert_eq!(segs[1].part_relative.end_exclusive().get(), 10);
    }

    // ---- single-part source behaves like today ---------------------

    #[test]
    fn single_part_source_locate_and_dispatch_match_single_url() {
        let s = MultiPartSource::from_single(
            url("https://h/only"),
            1024,
            SourceFingerprint::default(),
            None,
        )
        .expect("ok");
        // Every offset in range maps to part 0 with in-part offset = global.
        assert_eq!(s.locate(0), Some((0, 0)));
        assert_eq!(s.locate(1023), Some((0, 1023)));
        assert_eq!(s.locate(1024), None);
        let segs = segments(&s, 256, 768);
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].part_index, 0);
        assert_eq!(segs[0].global, segs[0].part_relative);
    }

    // ---- next_part_boundary_at_or_after -----------------------------

    #[test]
    fn next_boundary_inside_each_part() {
        // boundaries: [0, 100, 350, 1000]
        let s = three_part_source();
        // Inside part 0 → next boundary is 100 (start of part 1).
        assert_eq!(s.next_part_boundary_at_or_after(0), 100);
        assert_eq!(s.next_part_boundary_at_or_after(50), 100);
        assert_eq!(s.next_part_boundary_at_or_after(99), 100);
        // Inside part 1 → next boundary is 350.
        assert_eq!(s.next_part_boundary_at_or_after(100), 350);
        assert_eq!(s.next_part_boundary_at_or_after(225), 350);
        assert_eq!(s.next_part_boundary_at_or_after(349), 350);
        // Inside part 2 → next boundary is total_size (1000).
        assert_eq!(s.next_part_boundary_at_or_after(350), 1000);
        assert_eq!(s.next_part_boundary_at_or_after(999), 1000);
    }

    #[test]
    fn next_boundary_at_or_past_total_returns_total() {
        let s = three_part_source();
        assert_eq!(s.next_part_boundary_at_or_after(1000), 1000);
        assert_eq!(s.next_part_boundary_at_or_after(2000), 1000);
    }

    #[test]
    fn next_boundary_for_single_part_returns_total() {
        // Single-part: the only boundary past any in-range offset is
        // the end of the source.
        let s = MultiPartSource::from_single(
            url("https://h/only"),
            4096,
            SourceFingerprint::default(),
            None,
        )
        .expect("ok");
        assert_eq!(s.next_part_boundary_at_or_after(0), 4096);
        assert_eq!(s.next_part_boundary_at_or_after(2048), 4096);
        assert_eq!(s.next_part_boundary_at_or_after(4095), 4096);
    }
}
