//! Lock-free completion bitmap for the chunk-parallel downloader.
//!
//! Each chunk in the source download is represented by a single bit. A
//! bit is `0` while the chunk is outstanding and flips to `1` exactly
//! once when a worker has finished writing the chunk into the sparse
//! output file. The bitmap is shared across the download workers, the
//! scheduler, and the decoder — so every operation is `&self`-safe and
//! backed by [`AtomicU64`](std::sync::atomic::AtomicU64).
//!
//! # Memory ordering
//!
//! Mark/clear operations use [`Ordering::Release`] and read operations
//! use [`Ordering::Acquire`]. That gives us a producer/consumer
//! synchronization edge: any `pwrite_at` a worker performs *before*
//! [`ChunkBitmap::mark_complete`] is observable by a thread that loads
//! the bit with [`ChunkBitmap::is_complete`] and sees it set.
//!
//! [`ChunkBitmap::count_complete`] is a best-effort statistic and uses
//! [`Ordering::Relaxed`]; it does not establish synchronization with
//! marker operations.
//!
//! # Bit layout
//!
//! Word `w` of [`ChunkBitmap::words`](self) holds chunk indices
//! `[w * 64, w * 64 + 64)`, with chunk `w * 64 + b` stored in bit `b`
//! (LSB-first). Bits beyond [`ChunkBitmap::len`] in the trailing word
//! are never written and treated as "out of range" by every reader, so
//! the tail of the last word does not need to be masked at construction
//! time.
//!
//! # Out-of-range indices
//!
//! Every method documents its `# Panics` behavior. The bitmap deals in
//! [`ChunkIndex`] values that the caller has already validated against
//! the total chunk count; receiving an out-of-range index is treated as
//! a programmer error rather than a recoverable condition.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::types::ChunkIndex;

/// Lock-free, multi-writer / multi-reader bit set keyed by
/// [`ChunkIndex`].
///
/// All mutating operations take `&self`; share a single bitmap across
/// threads with [`std::sync::Arc`] when concurrent producers are needed.
///
/// # Examples
///
/// ```
/// use peel::bitmap::ChunkBitmap;
/// use peel::types::ChunkIndex;
///
/// let bitmap = ChunkBitmap::new(10);
/// assert_eq!(bitmap.count_complete(), 0);
///
/// bitmap.mark_complete(ChunkIndex::new(3));
/// assert!(bitmap.is_complete(ChunkIndex::new(3)));
/// assert_eq!(bitmap.count_complete(), 1);
///
/// bitmap.complete_range(ChunkIndex::new(0), ChunkIndex::new(3));
/// assert_eq!(bitmap.count_complete(), 4);
/// assert_eq!(
///     bitmap.next_incomplete_after(ChunkIndex::new(0)),
///     Some(ChunkIndex::new(4)),
/// );
/// ```
#[derive(Debug)]
pub struct ChunkBitmap {
    words: Box<[AtomicU64]>,
    num_chunks: u32,
}

/// Number of chunks tracked by a single underlying word. Chosen for
/// cheap [`u64::trailing_zeros`] / popcount on every supported target.
const BITS_PER_WORD: u32 = 64;

impl ChunkBitmap {
    /// Construct an empty bitmap sized for `num_chunks` chunks.
    ///
    /// All bits start unset (zero chunks complete). Allocates
    /// `ceil(num_chunks / 64)` `AtomicU64` words; for `num_chunks == 0`
    /// no words are allocated.
    #[must_use]
    pub fn new(num_chunks: u32) -> Self {
        let word_count = words_required(num_chunks);
        let mut words = Vec::with_capacity(word_count);
        words.resize_with(word_count, || AtomicU64::new(0));
        Self {
            words: words.into_boxed_slice(),
            num_chunks,
        }
    }

    /// The number of chunks this bitmap tracks.
    #[must_use]
    pub fn len(&self) -> u32 {
        self.num_chunks
    }

    /// True iff this bitmap tracks no chunks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.num_chunks == 0
    }

    /// Mark `idx` as complete.
    ///
    /// Idempotent: marking an already-complete chunk is a no-op.
    /// Operations performed by the caller before `mark_complete` (for
    /// example, `pwrite_at` of the chunk's bytes) happen-before any
    /// reader that observes the bit set via [`Self::is_complete`] /
    /// [`Self::next_incomplete_after`].
    ///
    /// # Panics
    ///
    /// Panics if `idx.get() >= self.len()`.
    pub fn mark_complete(&self, idx: ChunkIndex) {
        let raw = idx.get();
        assert!(
            raw < self.num_chunks,
            "ChunkBitmap::mark_complete: idx {raw} out of range (len = {})",
            self.num_chunks,
        );
        let (word, bit) = locate(raw);
        // INVARIANT: `locate` produces a word index < `self.words.len()`
        // for any `raw < self.num_chunks`; the bounds check above
        // guarantees that.
        self.words[word].fetch_or(1u64 << bit, Ordering::Release);
    }

    /// Read the completion bit for `idx`.
    ///
    /// # Panics
    ///
    /// Panics if `idx.get() >= self.len()`.
    #[must_use]
    pub fn is_complete(&self, idx: ChunkIndex) -> bool {
        let raw = idx.get();
        assert!(
            raw < self.num_chunks,
            "ChunkBitmap::is_complete: idx {raw} out of range (len = {})",
            self.num_chunks,
        );
        let (word, bit) = locate(raw);
        let w = self.words[word].load(Ordering::Acquire);
        (w >> bit) & 1 == 1
    }

    /// Mark every chunk in `[start, end_exclusive)` as complete.
    ///
    /// Empty ranges (`start >= end_exclusive`) are a no-op. The range is
    /// applied word-at-a-time using a single `fetch_or` per word, so
    /// concurrent readers see at most a transient partial update at
    /// each word boundary; readers never see chunk `i` flip back to
    /// incomplete once it has been marked complete.
    ///
    /// # Panics
    ///
    /// Panics if `end_exclusive.get() > self.len()`.
    pub fn complete_range(&self, start: ChunkIndex, end_exclusive: ChunkIndex) {
        let lo = start.get();
        let hi = end_exclusive.get();
        assert!(
            hi <= self.num_chunks,
            "ChunkBitmap::complete_range: end {hi} exceeds len {}",
            self.num_chunks,
        );
        if lo >= hi {
            return;
        }

        let first_word = (lo / BITS_PER_WORD) as usize;
        let last_word = ((hi - 1) / BITS_PER_WORD) as usize;
        let first_bit = lo % BITS_PER_WORD;
        // `hi` is at least 1; `(hi - 1) % BITS_PER_WORD` is the last
        // bit included, which is `BITS_PER_WORD - 1` when `hi` is a
        // multiple of BITS_PER_WORD. Adding 1 yields the count of
        // bits set in the last word, in [1, BITS_PER_WORD].
        let last_bit_inclusive = (hi - 1) % BITS_PER_WORD;

        if first_word == last_word {
            let mask = mask_between(first_bit, last_bit_inclusive);
            self.words[first_word].fetch_or(mask, Ordering::Release);
            return;
        }

        // First word: bits [first_bit, 64).
        let first_mask = mask_high(first_bit);
        self.words[first_word].fetch_or(first_mask, Ordering::Release);

        // Wholly covered middle words.
        for w in (first_word + 1)..last_word {
            self.words[w].fetch_or(!0u64, Ordering::Release);
        }

        // Last word: bits [0, last_bit_inclusive].
        let last_mask = mask_low_inclusive(last_bit_inclusive);
        self.words[last_word].fetch_or(last_mask, Ordering::Release);
    }

    /// Return the smallest [`ChunkIndex`] `k >= start` whose bit is
    /// unset, or `None` if every chunk in `[start, len())` is already
    /// complete.
    ///
    /// Note the inclusive lower bound: the search begins **at** `start`,
    /// which is the most useful convention for callers that want the
    /// next chunk a worker should pick up given a cursor position.
    ///
    /// # Panics
    ///
    /// Panics if `start.get() > self.len()`. (`start.get() == self.len()`
    /// is a valid empty-search request and returns `None`.)
    #[must_use]
    pub fn next_incomplete_after(&self, start: ChunkIndex) -> Option<ChunkIndex> {
        let raw = start.get();
        assert!(
            raw <= self.num_chunks,
            "ChunkBitmap::next_incomplete_after: start {raw} exceeds len {}",
            self.num_chunks,
        );
        if raw == self.num_chunks {
            return None;
        }

        let mut w = (raw / BITS_PER_WORD) as usize;
        let first_bit = raw % BITS_PER_WORD;

        // First word: ignore bits below `first_bit` by treating them as
        // already complete via the high mask.
        let word = self.words[w].load(Ordering::Acquire) | mask_low_exclusive(first_bit);
        if let Some(idx) = first_unset_chunk(w, word, self.num_chunks) {
            return Some(idx);
        }

        w += 1;
        while w < self.words.len() {
            let word = self.words[w].load(Ordering::Acquire);
            if let Some(idx) = first_unset_chunk(w, word, self.num_chunks) {
                return Some(idx);
            }
            w += 1;
        }
        None
    }

    /// Total number of chunks marked complete.
    ///
    /// Reads each word with [`Ordering::Relaxed`] and sums their
    /// popcounts; the value is a snapshot that may lag concurrent
    /// updates. Suitable for progress display and tests, not for
    /// completion gating.
    #[must_use]
    pub fn count_complete(&self) -> u64 {
        // We never set bits beyond `num_chunks`, so unmasked popcount
        // is correct; no tail mask required.
        self.words
            .iter()
            .map(|w| u64::from(w.load(Ordering::Relaxed).count_ones()))
            .sum()
    }
}

/// Number of `AtomicU64` words required to back `num_chunks` bits.
const fn words_required(num_chunks: u32) -> usize {
    if num_chunks == 0 {
        return 0;
    }
    let n = num_chunks as u64;
    n.div_ceil(BITS_PER_WORD as u64) as usize
}

/// Map a chunk index to `(word_index, bit_within_word)`.
const fn locate(idx: u32) -> (usize, u32) {
    ((idx / BITS_PER_WORD) as usize, idx % BITS_PER_WORD)
}

/// Bits `[bit, 64)` set; bits below `bit` clear.
///
/// `bit == 0` returns `!0`; `bit == 64` returns `0`.
const fn mask_high(bit: u32) -> u64 {
    if bit >= BITS_PER_WORD {
        0
    } else {
        !0u64 << bit
    }
}

/// Bits `[0, bit)` set; bits at or above `bit` clear.
///
/// `bit == 0` returns `0`; `bit == 64` returns `!0`.
const fn mask_low_exclusive(bit: u32) -> u64 {
    if bit == 0 {
        0
    } else if bit >= BITS_PER_WORD {
        !0u64
    } else {
        (1u64 << bit) - 1
    }
}

/// Bits `[0, bit]` set (inclusive of `bit`).
///
/// Caller must pass `bit < 64`; that is the only way this helper is
/// invoked from inside this module.
const fn mask_low_inclusive(bit: u32) -> u64 {
    // `bit` ranges over `0..BITS_PER_WORD` at every call site, so the
    // shift never reaches the undefined-behavior boundary.
    if bit + 1 >= BITS_PER_WORD {
        !0u64
    } else {
        (1u64 << (bit + 1)) - 1
    }
}

/// Bits `[lo, hi]` set inclusive.
const fn mask_between(lo: u32, hi: u32) -> u64 {
    // Both endpoints lie in `0..BITS_PER_WORD`; combining the two
    // half-open masks gives the closed range without UB.
    mask_high(lo) & mask_low_inclusive(hi)
}

/// Given a word value (with bits below the search start already
/// pre-masked to 1), return the chunk index of the first unset bit
/// or `None` if there is none in range.
fn first_unset_chunk(word_index: usize, word: u64, num_chunks: u32) -> Option<ChunkIndex> {
    let inverted = !word;
    if inverted == 0 {
        return None;
    }
    let bit = inverted.trailing_zeros();
    // INVARIANT: `word_index < words_required(num_chunks) <= u32::MAX/64 + 1`
    // so `word_index * 64 + bit` fits in `u64`. We narrow back to `u32`
    // only after bounds-checking against `num_chunks`.
    let chunk = (word_index as u64) * u64::from(BITS_PER_WORD) + u64::from(bit);
    if chunk >= u64::from(num_chunks) {
        return None;
    }
    Some(ChunkIndex::new(chunk as u32))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::thread;

    /// Tiny LCG used to drive property-style tests, mirroring the
    /// pattern in `types.rs`.
    struct Lcg(u64);

    impl Lcg {
        fn seeded(seed: u64) -> Self {
            Self(seed ^ 0x9E37_79B9_7F4A_7C15)
        }

        fn next_u64(&mut self) -> u64 {
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

    // ---- words_required ----------------------------------------------

    #[test]
    fn words_required_zero_is_zero() {
        assert_eq!(words_required(0), 0);
    }

    #[test]
    fn words_required_rounds_up() {
        assert_eq!(words_required(1), 1);
        assert_eq!(words_required(63), 1);
        assert_eq!(words_required(64), 1);
        assert_eq!(words_required(65), 2);
        assert_eq!(words_required(128), 2);
        assert_eq!(words_required(129), 3);
    }

    #[test]
    fn words_required_handles_u32_max() {
        // Should not overflow.
        let w = words_required(u32::MAX);
        assert_eq!(w, (u32::MAX as u64).div_ceil(64) as usize);
    }

    // ---- mask helpers ------------------------------------------------

    #[test]
    fn mask_high_endpoints() {
        assert_eq!(mask_high(0), !0u64);
        assert_eq!(mask_high(1), !0u64 << 1);
        assert_eq!(mask_high(63), 1u64 << 63);
        assert_eq!(mask_high(64), 0);
    }

    #[test]
    fn mask_low_exclusive_endpoints() {
        assert_eq!(mask_low_exclusive(0), 0);
        assert_eq!(mask_low_exclusive(1), 1);
        assert_eq!(mask_low_exclusive(63), (1u64 << 63) - 1);
        assert_eq!(mask_low_exclusive(64), !0u64);
    }

    #[test]
    fn mask_low_inclusive_endpoints() {
        assert_eq!(mask_low_inclusive(0), 1);
        assert_eq!(mask_low_inclusive(1), 0b11);
        assert_eq!(mask_low_inclusive(63), !0u64);
    }

    #[test]
    fn mask_between_single_word() {
        // Bits [3, 7] inclusive -> 0b11111000.
        assert_eq!(mask_between(3, 7), 0b1111_1000);
        // Whole word.
        assert_eq!(mask_between(0, 63), !0u64);
    }

    // ---- ChunkBitmap -------------------------------------------------

    #[test]
    fn new_creates_all_zero_bitmap() {
        let b = ChunkBitmap::new(200);
        assert_eq!(b.len(), 200);
        assert!(!b.is_empty());
        assert_eq!(b.count_complete(), 0);
        for i in 0..200 {
            assert!(!b.is_complete(ChunkIndex::new(i)));
        }
    }

    #[test]
    fn new_zero_chunks_is_empty() {
        let b = ChunkBitmap::new(0);
        assert_eq!(b.len(), 0);
        assert!(b.is_empty());
        assert_eq!(b.count_complete(), 0);
        assert_eq!(b.next_incomplete_after(ChunkIndex::ZERO), None);
    }

    #[test]
    fn mark_and_check_single_chunk() {
        let b = ChunkBitmap::new(128);
        let idx = ChunkIndex::new(73);
        assert!(!b.is_complete(idx));
        b.mark_complete(idx);
        assert!(b.is_complete(idx));
        // No spillover into neighbors.
        assert!(!b.is_complete(ChunkIndex::new(72)));
        assert!(!b.is_complete(ChunkIndex::new(74)));
        assert_eq!(b.count_complete(), 1);
    }

    #[test]
    fn mark_complete_is_idempotent() {
        let b = ChunkBitmap::new(64);
        let idx = ChunkIndex::new(7);
        b.mark_complete(idx);
        b.mark_complete(idx);
        b.mark_complete(idx);
        assert_eq!(b.count_complete(), 1);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn mark_complete_panics_on_oob() {
        let b = ChunkBitmap::new(10);
        b.mark_complete(ChunkIndex::new(10));
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn is_complete_panics_on_oob() {
        let b = ChunkBitmap::new(10);
        let _ = b.is_complete(ChunkIndex::new(10));
    }

    #[test]
    #[should_panic(expected = "exceeds len")]
    fn complete_range_panics_when_end_exceeds_len() {
        let b = ChunkBitmap::new(10);
        b.complete_range(ChunkIndex::new(0), ChunkIndex::new(11));
    }

    #[test]
    fn complete_range_within_single_word() {
        let b = ChunkBitmap::new(64);
        b.complete_range(ChunkIndex::new(3), ChunkIndex::new(8));
        for i in 0..64 {
            let expected = (3..8).contains(&i);
            assert_eq!(b.is_complete(ChunkIndex::new(i)), expected, "bit {i}");
        }
        assert_eq!(b.count_complete(), 5);
    }

    #[test]
    fn complete_range_crosses_word_boundary() {
        let b = ChunkBitmap::new(200);
        b.complete_range(ChunkIndex::new(60), ChunkIndex::new(132));
        for i in 0..200 {
            let expected = (60..132).contains(&i);
            assert_eq!(b.is_complete(ChunkIndex::new(i)), expected, "bit {i}");
        }
        assert_eq!(b.count_complete(), 132 - 60);
    }

    #[test]
    fn complete_range_full_bitmap() {
        let b = ChunkBitmap::new(200);
        b.complete_range(ChunkIndex::ZERO, ChunkIndex::new(200));
        assert_eq!(b.count_complete(), 200);
        assert_eq!(b.next_incomplete_after(ChunkIndex::ZERO), None);
    }

    #[test]
    fn complete_range_empty_is_noop() {
        let b = ChunkBitmap::new(50);
        b.complete_range(ChunkIndex::new(10), ChunkIndex::new(10));
        b.complete_range(ChunkIndex::new(20), ChunkIndex::new(15));
        assert_eq!(b.count_complete(), 0);
    }

    #[test]
    fn next_incomplete_after_returns_starting_index_if_unset() {
        let b = ChunkBitmap::new(64);
        assert_eq!(
            b.next_incomplete_after(ChunkIndex::new(5)),
            Some(ChunkIndex::new(5))
        );
    }

    #[test]
    fn next_incomplete_after_skips_completed_run() {
        let b = ChunkBitmap::new(64);
        for i in 0..10 {
            b.mark_complete(ChunkIndex::new(i));
        }
        assert_eq!(
            b.next_incomplete_after(ChunkIndex::ZERO),
            Some(ChunkIndex::new(10))
        );
    }

    #[test]
    fn next_incomplete_after_returns_none_when_all_complete() {
        let b = ChunkBitmap::new(70);
        b.complete_range(ChunkIndex::ZERO, ChunkIndex::new(70));
        assert_eq!(b.next_incomplete_after(ChunkIndex::ZERO), None);
        assert_eq!(b.next_incomplete_after(ChunkIndex::new(69)), None);
    }

    #[test]
    fn next_incomplete_after_handles_tail_word() {
        // num_chunks not a multiple of 64 — the tail of the last word
        // is "out of range" and must not be reported.
        let b = ChunkBitmap::new(70);
        b.complete_range(ChunkIndex::ZERO, ChunkIndex::new(64));
        assert_eq!(
            b.next_incomplete_after(ChunkIndex::ZERO),
            Some(ChunkIndex::new(64))
        );
        b.complete_range(ChunkIndex::new(64), ChunkIndex::new(70));
        assert_eq!(b.next_incomplete_after(ChunkIndex::ZERO), None);
    }

    #[test]
    fn next_incomplete_after_at_len_is_none() {
        let b = ChunkBitmap::new(10);
        assert_eq!(b.next_incomplete_after(ChunkIndex::new(10)), None);
    }

    #[test]
    #[should_panic(expected = "exceeds len")]
    fn next_incomplete_after_panics_past_len() {
        let b = ChunkBitmap::new(10);
        let _ = b.next_incomplete_after(ChunkIndex::new(11));
    }

    #[test]
    fn count_complete_matches_marked_count() {
        let b = ChunkBitmap::new(1000);
        let marks = [0u32, 1, 63, 64, 65, 511, 512, 513, 999];
        for &m in &marks {
            b.mark_complete(ChunkIndex::new(m));
        }
        assert_eq!(b.count_complete(), marks.len() as u64);
    }

    // ---- Property tests ----------------------------------------------

    #[test]
    fn property_random_marks_match_oracle() {
        // For random sets of indices the bitmap reports the same
        // membership as a HashSet of the same indices.
        let mut rng = Lcg::seeded(0x1234_5678);
        for trial in 0..32 {
            let n = (rng.next_u32() % 4096 + 1).min(4096);
            let bitmap = ChunkBitmap::new(n);
            let mut oracle = std::collections::HashSet::new();

            let pulls = (rng.next_u32() % (n + 1)) as usize;
            for _ in 0..pulls {
                let idx = rng.next_u32() % n;
                bitmap.mark_complete(ChunkIndex::new(idx));
                oracle.insert(idx);
            }

            assert_eq!(
                bitmap.count_complete(),
                oracle.len() as u64,
                "trial {trial}"
            );
            for i in 0..n {
                assert_eq!(
                    bitmap.is_complete(ChunkIndex::new(i)),
                    oracle.contains(&i),
                    "trial {trial} bit {i}"
                );
            }
        }
    }

    #[test]
    fn property_complete_range_equivalent_to_loop() {
        // For random ranges, `complete_range` flips exactly the bits
        // that a per-index `mark_complete` loop would.
        let mut rng = Lcg::seeded(0xCAFE);
        for _ in 0..32 {
            let n = (rng.next_u32() % 512) + 1;
            let a = rng.next_u32() % (n + 1);
            let b = rng.next_u32() % (n + 1);
            let lo = a.min(b);
            let hi = a.max(b);

            let actual = ChunkBitmap::new(n);
            actual.complete_range(ChunkIndex::new(lo), ChunkIndex::new(hi));

            let expected = ChunkBitmap::new(n);
            for i in lo..hi {
                expected.mark_complete(ChunkIndex::new(i));
            }

            for i in 0..n {
                assert_eq!(
                    actual.is_complete(ChunkIndex::new(i)),
                    expected.is_complete(ChunkIndex::new(i)),
                    "n={n} lo={lo} hi={hi} bit={i}",
                );
            }
        }
    }

    #[test]
    fn property_next_incomplete_after_is_oracle_min() {
        // For a random subset of indices marked complete, the bitmap's
        // `next_incomplete_after(start)` is the smallest index `>=
        // start` that is *not* in the marked set, or `None` if every
        // index in `[start, n)` is marked.
        let mut rng = Lcg::seeded(0xBEEF);
        for _ in 0..16 {
            let n = (rng.next_u32() % 512) + 1;
            let bitmap = ChunkBitmap::new(n);
            let mut marked = vec![false; n as usize];

            let pulls = (rng.next_u32() % (n + 1)) as usize;
            for _ in 0..pulls {
                let idx = rng.next_u32() % n;
                bitmap.mark_complete(ChunkIndex::new(idx));
                marked[idx as usize] = true;
            }

            for start in 0..=n {
                let expected = (start..n)
                    .find(|&i| !marked[i as usize])
                    .map(ChunkIndex::new);
                let actual = bitmap.next_incomplete_after(ChunkIndex::new(start));
                assert_eq!(actual, expected, "n={n} start={start}");
            }
        }
    }

    // ---- Concurrency -------------------------------------------------

    #[test]
    fn concurrent_writers_record_every_mark() {
        // Eight threads each mark a disjoint slice of the bitmap. After
        // join, every chunk in [0, n) must be complete.
        const THREADS: u32 = 8;
        const PER_THREAD: u32 = 4096;
        let n = THREADS * PER_THREAD;
        let bitmap = Arc::new(ChunkBitmap::new(n));

        thread::scope(|scope| {
            for t in 0..THREADS {
                let bitmap = Arc::clone(&bitmap);
                scope.spawn(move || {
                    let lo = t * PER_THREAD;
                    let hi = lo + PER_THREAD;
                    for i in lo..hi {
                        bitmap.mark_complete(ChunkIndex::new(i));
                    }
                });
            }
        });

        assert_eq!(bitmap.count_complete(), u64::from(n));
        assert_eq!(bitmap.next_incomplete_after(ChunkIndex::ZERO), None);
    }

    #[test]
    fn concurrent_overlapping_marks_are_safe() {
        // Two threads racing on the same bits never lose updates and
        // never spuriously set bits outside their assigned range.
        const N: u32 = 4096;
        let bitmap = Arc::new(ChunkBitmap::new(N));

        thread::scope(|scope| {
            for _ in 0..4 {
                let bitmap = Arc::clone(&bitmap);
                scope.spawn(move || {
                    for i in 0..N {
                        bitmap.mark_complete(ChunkIndex::new(i));
                    }
                });
            }
        });

        assert_eq!(bitmap.count_complete(), u64::from(N));
    }
}
