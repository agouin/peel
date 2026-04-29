//! Strongly-typed primitives shared across the crate.
//!
//! Byte offsets, chunk indices, and byte ranges all look like plain integers
//! to the compiler but are not interchangeable: a chunk index is not a byte
//! offset, a length is not a position. Wrapping them in newtypes catches a
//! whole class of bugs (passing a chunk index where an offset was expected)
//! at compile time. Arithmetic uses `checked_*` operations so overflow is
//! explicit rather than silent — see
//! `docs/ENGINEERING_STANDARDS.md` §3.3.

use std::fmt;

/// An absolute byte offset into a file or stream.
///
/// Wraps a [`u64`]. Arithmetic goes through [`Self::checked_add`] /
/// [`Self::checked_sub`] so overflow is impossible to miss.
///
/// # Examples
///
/// ```
/// use pux::types::ByteOffset;
///
/// let a = ByteOffset::new(1024);
/// let b = a.checked_add(2048).expect("no overflow");
/// assert_eq!(b.get(), 3072);
/// assert_eq!(b.checked_sub(a), Some(2048));
/// ```
#[derive(Copy, Clone, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ByteOffset(u64);

impl ByteOffset {
    /// The zero offset, i.e. the start of a file or stream.
    pub const ZERO: Self = Self(0);

    /// The maximum representable offset.
    pub const MAX: Self = Self(u64::MAX);

    /// Construct from a raw `u64`.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the wrapped `u64`.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Add `delta` bytes, returning `None` on overflow.
    #[must_use]
    pub const fn checked_add(self, delta: u64) -> Option<Self> {
        match self.0.checked_add(delta) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Compute `self - other` in bytes, returning `None` if `other > self`.
    #[must_use]
    pub const fn checked_sub(self, other: Self) -> Option<u64> {
        self.0.checked_sub(other.0)
    }

    /// Saturating add of `delta` bytes; clamps to [`Self::MAX`] on overflow.
    #[must_use]
    pub const fn saturating_add(self, delta: u64) -> Self {
        Self(self.0.saturating_add(delta))
    }
}

impl fmt::Debug for ByteOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ByteOffset({})", self.0)
    }
}

impl fmt::Display for ByteOffset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Index identifying a fixed-size chunk of the source download.
///
/// Wraps a [`u32`]. Chunk `N` covers the byte range
/// `[N * chunk_size, (N + 1) * chunk_size)` in the source, clamped to the
/// total size — see [`Self::byte_range`].
///
/// # Examples
///
/// ```
/// use pux::types::ChunkIndex;
///
/// let idx = ChunkIndex::new(7);
/// assert_eq!(idx.get(), 7);
/// assert_eq!(idx.checked_add(1).map(ChunkIndex::get), Some(8));
/// ```
#[derive(Copy, Clone, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ChunkIndex(u32);

impl ChunkIndex {
    /// The first chunk, index 0.
    pub const ZERO: Self = Self(0);

    /// The maximum representable chunk index.
    pub const MAX: Self = Self(u32::MAX);

    /// Construct from a raw `u32`.
    #[must_use]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Return the wrapped `u32`.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Step forward by `delta` chunks, returning `None` on overflow.
    #[must_use]
    pub const fn checked_add(self, delta: u32) -> Option<Self> {
        match self.0.checked_add(delta) {
            Some(v) => Some(Self(v)),
            None => None,
        }
    }

    /// Compute `self - other` in chunks, returning `None` if `other > self`.
    #[must_use]
    pub const fn checked_sub(self, other: Self) -> Option<u32> {
        self.0.checked_sub(other.0)
    }

    /// The half-open byte range covered by this chunk for a given
    /// `chunk_size`, clamped to `total_size`.
    ///
    /// Returns `None` if `chunk_size == 0`, if the chunk's start would
    /// exceed `total_size`, or if `start + chunk_size` overflows `u64`.
    #[must_use]
    pub fn byte_range(self, chunk_size: u64, total_size: u64) -> Option<ByteRange> {
        if chunk_size == 0 {
            return None;
        }
        let start = u64::from(self.0).checked_mul(chunk_size)?;
        if start > total_size {
            return None;
        }
        let nominal_end = start.checked_add(chunk_size)?;
        let end = if nominal_end < total_size {
            nominal_end
        } else {
            total_size
        };
        ByteRange::new(ByteOffset(start), ByteOffset(end))
    }
}

impl fmt::Debug for ChunkIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChunkIndex({})", self.0)
    }
}

impl fmt::Display for ChunkIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A half-open byte range `[start, end_exclusive)`.
///
/// Empty ranges (`start == end_exclusive`) are valid and round-trip
/// through every accessor; reversed ranges (`end_exclusive < start`) are
/// rejected by [`Self::new`].
///
/// # Examples
///
/// ```
/// use pux::types::{ByteOffset, ByteRange};
///
/// let r = ByteRange::new(ByteOffset::new(10), ByteOffset::new(30))
///     .expect("non-reversed");
/// assert_eq!(r.len(), 20);
/// assert!(r.contains(ByteOffset::new(15)));
/// assert!(!r.contains(ByteOffset::new(30)));
/// ```
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct ByteRange {
    start: ByteOffset,
    end_exclusive: ByteOffset,
}

impl ByteRange {
    /// Construct a range, returning `None` if `end_exclusive < start`.
    #[must_use]
    pub fn new(start: ByteOffset, end_exclusive: ByteOffset) -> Option<Self> {
        if end_exclusive < start {
            None
        } else {
            Some(Self {
                start,
                end_exclusive,
            })
        }
    }

    /// Construct a range of length `len` starting at `start`, or `None` on
    /// overflow.
    #[must_use]
    pub fn from_start_len(start: ByteOffset, len: u64) -> Option<Self> {
        let end = start.checked_add(len)?;
        Self::new(start, end)
    }

    /// The first byte included in the range.
    #[must_use]
    pub const fn start(self) -> ByteOffset {
        self.start
    }

    /// One past the last byte included in the range.
    #[must_use]
    pub const fn end_exclusive(self) -> ByteOffset {
        self.end_exclusive
    }

    /// Length of the range, in bytes.
    #[must_use]
    pub const fn len(self) -> u64 {
        // Invariant from `Self::new`: end_exclusive >= start, so saturating
        // and checked subtraction agree; saturating keeps this trivially
        // panic-free in all build profiles.
        self.end_exclusive.0.saturating_sub(self.start.0)
    }

    /// True iff the range contains zero bytes.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.start.0 == self.end_exclusive.0
    }

    /// True iff `offset` is within `[start, end_exclusive)`.
    #[must_use]
    pub fn contains(self, offset: ByteOffset) -> bool {
        offset >= self.start && offset < self.end_exclusive
    }

    /// True iff every byte of `other` lies within `self`. The empty range
    /// is contained by every range whose bounds enclose its position.
    #[must_use]
    pub fn contains_range(self, other: Self) -> bool {
        other.start >= self.start && other.end_exclusive <= self.end_exclusive
    }
}

impl fmt::Debug for ByteRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ByteRange [{}, {})", self.start.0, self.end_exclusive.0)
    }
}

impl fmt::Display for ByteRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {})", self.start.0, self.end_exclusive.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny linear-congruential generator used to drive the property-style
    /// tests. Hand-rolled rather than pulling in a PRNG crate (see the
    /// dependency policy in `docs/ENGINEERING_STANDARDS.md` §2).
    struct Lcg(u64);

    impl Lcg {
        const fn seeded(seed: u64) -> Self {
            // A non-zero state keeps the sequence from collapsing to all
            // zeros under the multiplier alone.
            Self(seed ^ 0x9E37_79B9_7F4A_7C15)
        }

        fn next_u64(&mut self) -> u64 {
            // Numerical Recipes constants — full-period over u64.
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }

        fn next_u32(&mut self) -> u32 {
            (self.next_u64() >> 32) as u32
        }
    }

    const ITERS: usize = 4096;

    // ---- ByteOffset ---------------------------------------------------

    #[test]
    fn byte_offset_default_is_zero() {
        assert_eq!(ByteOffset::default(), ByteOffset::ZERO);
    }

    #[test]
    fn byte_offset_new_get_round_trip() {
        for v in [0u64, 1, 4096, u64::MAX / 2, u64::MAX] {
            assert_eq!(ByteOffset::new(v).get(), v);
        }
    }

    #[test]
    fn byte_offset_ordering_matches_underlying_u64() {
        let a = ByteOffset::new(10);
        let b = ByteOffset::new(20);
        assert!(a < b);
        assert!(b > a);
        assert_eq!(a, ByteOffset::new(10));
    }

    #[test]
    fn byte_offset_checked_add_overflow_is_none() {
        assert_eq!(ByteOffset::MAX.checked_add(1), None);
        assert_eq!(ByteOffset::new(u64::MAX - 3).checked_add(10), None);
    }

    #[test]
    fn byte_offset_checked_sub_underflow_is_none() {
        let a = ByteOffset::new(5);
        let b = ByteOffset::new(10);
        assert_eq!(a.checked_sub(b), None);
    }

    #[test]
    fn byte_offset_saturating_add_clamps() {
        assert_eq!(ByteOffset::MAX.saturating_add(7), ByteOffset::MAX);
        assert_eq!(
            ByteOffset::new(100).saturating_add(50),
            ByteOffset::new(150)
        );
    }

    #[test]
    fn byte_offset_display_and_debug() {
        let o = ByteOffset::new(42);
        assert_eq!(format!("{o}"), "42");
        assert_eq!(format!("{o:?}"), "ByteOffset(42)");
    }

    #[test]
    fn byte_offset_arithmetic_property() {
        // For random pairs that fit, checked_add agrees with the underlying
        // u64 arithmetic, and round-trips through checked_sub.
        let mut rng = Lcg::seeded(0x42);
        for _ in 0..ITERS {
            let a = rng.next_u64() >> 1; // leave room for a second value
            let delta = rng.next_u64() >> 1;
            let off = ByteOffset::new(a);
            let sum = off.checked_add(delta).expect("upper bit clear");
            assert_eq!(sum.get(), a + delta);
            assert_eq!(sum.checked_sub(off), Some(delta));
        }
    }

    #[test]
    fn byte_offset_overflow_property() {
        // Whenever a + delta overflows u64, checked_add reports None.
        let mut rng = Lcg::seeded(0xC0FFEE);
        for _ in 0..ITERS {
            let a = rng.next_u64();
            let delta = rng.next_u64();
            let expected = a.checked_add(delta);
            let actual = ByteOffset::new(a).checked_add(delta).map(ByteOffset::get);
            assert_eq!(actual, expected);
        }
    }

    // ---- ChunkIndex ---------------------------------------------------

    #[test]
    fn chunk_index_default_is_zero() {
        assert_eq!(ChunkIndex::default(), ChunkIndex::ZERO);
    }

    #[test]
    fn chunk_index_new_get_round_trip() {
        for v in [0u32, 1, 1024, u32::MAX] {
            assert_eq!(ChunkIndex::new(v).get(), v);
        }
    }

    #[test]
    fn chunk_index_checked_add_and_sub() {
        assert_eq!(ChunkIndex::MAX.checked_add(1), None);
        assert_eq!(ChunkIndex::new(3).checked_sub(ChunkIndex::new(5)), None);
        assert_eq!(ChunkIndex::new(5).checked_sub(ChunkIndex::new(3)), Some(2));
    }

    #[test]
    fn chunk_index_byte_range_typical() {
        let idx = ChunkIndex::new(2);
        let r = idx.byte_range(4096, 16_384).expect("in-bounds");
        assert_eq!(r.start(), ByteOffset::new(8192));
        assert_eq!(r.end_exclusive(), ByteOffset::new(12_288));
        assert_eq!(r.len(), 4096);
    }

    #[test]
    fn chunk_index_byte_range_truncates_last_chunk() {
        let idx = ChunkIndex::new(3);
        let r = idx.byte_range(1_000, 3_500).expect("partial");
        assert_eq!(r.start(), ByteOffset::new(3_000));
        assert_eq!(r.end_exclusive(), ByteOffset::new(3_500));
        assert_eq!(r.len(), 500);
    }

    #[test]
    fn chunk_index_byte_range_past_total_is_none() {
        let idx = ChunkIndex::new(10);
        assert_eq!(idx.byte_range(1_000, 3_500), None);
    }

    #[test]
    fn chunk_index_byte_range_zero_size_is_none() {
        assert_eq!(ChunkIndex::new(0).byte_range(0, 100), None);
    }

    #[test]
    fn chunk_index_byte_range_overflow_is_none() {
        // A chunk size near u64::MAX with a non-zero index must overflow.
        let idx = ChunkIndex::new(2);
        assert_eq!(idx.byte_range(u64::MAX, u64::MAX), None);
    }

    #[test]
    fn chunk_index_byte_range_property_covers_total() {
        // For a valid (chunk_size, total_size), iterating chunk indices
        // until `byte_range` returns None must cover [0, total_size)
        // contiguously and exactly once.
        let mut rng = Lcg::seeded(0xDEAD_BEEF);
        for _ in 0..256 {
            let chunk_size = (rng.next_u32() % 4096 + 1) as u64;
            let total_size = rng.next_u32() as u64 % (chunk_size * 32 + 1);

            let mut cursor = 0u64;
            let mut idx = 0u32;
            loop {
                match ChunkIndex::new(idx).byte_range(chunk_size, total_size) {
                    None => break,
                    Some(r) => {
                        assert_eq!(r.start().get(), cursor, "non-contiguous start");
                        assert!(r.end_exclusive().get() <= total_size);
                        cursor = r.end_exclusive().get();
                        idx += 1;
                    }
                }
            }
            assert_eq!(cursor, total_size, "chunks must cover the total");
        }
    }

    #[test]
    fn chunk_index_display_and_debug() {
        let i = ChunkIndex::new(5);
        assert_eq!(format!("{i}"), "5");
        assert_eq!(format!("{i:?}"), "ChunkIndex(5)");
    }

    // ---- ByteRange ----------------------------------------------------

    #[test]
    fn byte_range_new_rejects_reversed() {
        let r = ByteRange::new(ByteOffset::new(10), ByteOffset::new(5));
        assert!(r.is_none());
    }

    #[test]
    fn byte_range_new_accepts_empty() {
        let r = ByteRange::new(ByteOffset::new(7), ByteOffset::new(7)).expect("empty is valid");
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn byte_range_from_start_len() {
        let r = ByteRange::from_start_len(ByteOffset::new(100), 50).expect("no overflow");
        assert_eq!(r.start(), ByteOffset::new(100));
        assert_eq!(r.end_exclusive(), ByteOffset::new(150));
        assert_eq!(r.len(), 50);
    }

    #[test]
    fn byte_range_from_start_len_overflow_is_none() {
        assert_eq!(
            ByteRange::from_start_len(ByteOffset::new(u64::MAX - 5), 10),
            None
        );
    }

    #[test]
    fn byte_range_contains_endpoint_behaviour() {
        let r = ByteRange::new(ByteOffset::new(10), ByteOffset::new(20)).unwrap();
        assert!(r.contains(ByteOffset::new(10)));
        assert!(r.contains(ByteOffset::new(19)));
        assert!(!r.contains(ByteOffset::new(20)));
        assert!(!r.contains(ByteOffset::new(9)));
    }

    #[test]
    fn byte_range_empty_contains_nothing() {
        let r = ByteRange::new(ByteOffset::new(7), ByteOffset::new(7)).unwrap();
        assert!(!r.contains(ByteOffset::new(7)));
    }

    #[test]
    fn byte_range_contains_range_works() {
        let outer = ByteRange::new(ByteOffset::new(0), ByteOffset::new(100)).unwrap();
        let inner = ByteRange::new(ByteOffset::new(10), ByteOffset::new(50)).unwrap();
        let exact = ByteRange::new(ByteOffset::new(0), ByteOffset::new(100)).unwrap();
        let overhang = ByteRange::new(ByteOffset::new(50), ByteOffset::new(150)).unwrap();

        assert!(outer.contains_range(inner));
        assert!(outer.contains_range(exact));
        assert!(!outer.contains_range(overhang));
    }

    #[test]
    fn byte_range_display_and_debug() {
        let r = ByteRange::new(ByteOffset::new(2), ByteOffset::new(8)).unwrap();
        assert_eq!(format!("{r}"), "[2, 8)");
        assert_eq!(format!("{r:?}"), "ByteRange [2, 8)");
    }

    #[test]
    fn byte_range_property_len_and_contains_consistent() {
        // For any well-formed range of length L, exactly L distinct offsets
        // satisfy `contains` over the range [start, end_exclusive).
        let mut rng = Lcg::seeded(0xFEED);
        for _ in 0..64 {
            let start = rng.next_u32() as u64 % 10_000;
            let len = rng.next_u32() as u64 % 256;
            let r = ByteRange::from_start_len(ByteOffset::new(start), len).unwrap();
            assert_eq!(r.len(), len);

            let mut hits = 0u64;
            for off in start..start + len {
                if r.contains(ByteOffset::new(off)) {
                    hits += 1;
                }
            }
            assert_eq!(hits, len);
            assert!(!r.contains(ByteOffset::new(start + len)));
        }
    }

    #[test]
    fn byte_range_property_construct_from_random_bounds() {
        // For arbitrary pairs (a, b), `new` accepts iff a <= b, and the
        // resulting len equals b - a.
        let mut rng = Lcg::seeded(0xBA5E);
        for _ in 0..ITERS {
            let a = rng.next_u64() >> 1;
            let b = rng.next_u64() >> 1;
            let lo = a.min(b);
            let hi = a.max(b);
            let r = ByteRange::new(ByteOffset::new(lo), ByteOffset::new(hi)).expect("non-reversed");
            assert_eq!(r.len(), hi - lo);
            assert_eq!(r.is_empty(), lo == hi);
        }
    }
}
