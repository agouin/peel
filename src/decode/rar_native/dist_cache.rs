//! Four-slot LRU cache of recent match distances.
//!
//! RAR5's main alphabet reserves five symbols (`257..261`) for
//! "repeat" matches that index a 4-slot LRU of the most-recently
//! emitted match distances. Code 257 is "repeat the most-recent
//! match (with the same length)"; codes 258..=261 select cache
//! slot `code - 258` and pair it with a fresh length-code decode.
//!
//! Touching slot `idx` shifts every entry in `0..idx` one slot
//! deeper and promotes the touched value to slot 0. A fresh
//! [`Self::push`] (after a non-cached match) shifts every entry
//! one slot deeper, dropping slot 3.
//!
//! Constants and slot semantics match libarchive's `dist_cache`
//! / `dist_cache_push` / `dist_cache_touch` in
//! `archive_read_support_format_rar5.c` (Grzegorz Antoniak,
//! BSD 2-Clause; see [`NOTICE`](../../../NOTICE)).

/// Number of distance slots in the LRU.
pub const DIST_CACHE_SLOTS: usize = 4;

/// 4-slot most-recently-used distance cache.
///
/// Construction is empty (every slot is `0`). Empty slots are
/// not legal back-references, but the LZSS dispatcher only
/// touches a slot if the wire said to — there's no "is empty"
/// check at runtime; the cache returns whatever's there.
#[derive(Debug, Clone, Copy)]
pub struct DistCache {
    slots: [u32; DIST_CACHE_SLOTS],
}

impl Default for DistCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DistCache {
    /// Construct an empty cache (every slot zero).
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: [0; DIST_CACHE_SLOTS],
        }
    }

    /// Return the current contents of slot `idx` (0..[`DIST_CACHE_SLOTS`)
    /// without modifying the cache. Useful for diagnostics / tests.
    #[must_use]
    pub fn peek(&self, idx: usize) -> u32 {
        self.slots[idx]
    }

    /// Push a fresh match distance onto the cache.
    ///
    /// Shifts every existing entry one slot deeper, dropping the
    /// oldest, and writes `dist` into slot 0.
    pub fn push(&mut self, dist: u32) {
        self.slots[3] = self.slots[2];
        self.slots[2] = self.slots[1];
        self.slots[1] = self.slots[0];
        self.slots[0] = dist;
    }

    /// Touch the entry at slot `idx`: read its distance, shift
    /// slots `0..idx` one deeper, and promote the touched value
    /// to slot 0. Returns the distance that was read.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `idx >= DIST_CACHE_SLOTS`. The
    /// LZSS dispatcher always passes `idx = code - 258` for
    /// codes in 258..=261 so it never violates the bound.
    pub fn touch(&mut self, idx: usize) -> u32 {
        debug_assert!(idx < DIST_CACHE_SLOTS, "DistCache::touch idx out of range");
        let dist = self.slots[idx];
        // Shift `slots[0..idx]` one position deeper and write the
        // touched value into slot 0. libarchive's loop does this
        // top-down; we replicate the loop exactly so the slot
        // semantics match for any `idx`.
        let mut i = idx;
        while i > 0 {
            self.slots[i] = self.slots[i - 1];
            i -= 1;
        }
        self.slots[0] = dist;
        dist
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_zero_everywhere() {
        let c = DistCache::new();
        for i in 0..DIST_CACHE_SLOTS {
            assert_eq!(c.peek(i), 0);
        }
    }

    #[test]
    fn push_shifts_existing_entries_deeper() {
        let mut c = DistCache::new();
        c.push(1);
        c.push(2);
        c.push(3);
        c.push(4);
        // After 4 pushes, slot 0 = 4 (most recent), slot 3 = 1.
        assert_eq!(c.peek(0), 4);
        assert_eq!(c.peek(1), 3);
        assert_eq!(c.peek(2), 2);
        assert_eq!(c.peek(3), 1);
    }

    #[test]
    fn push_drops_oldest_when_full() {
        let mut c = DistCache::new();
        for d in 1..=5u32 {
            c.push(d);
        }
        // After 5 pushes, the original `1` is dropped.
        assert_eq!(c.peek(0), 5);
        assert_eq!(c.peek(1), 4);
        assert_eq!(c.peek(2), 3);
        assert_eq!(c.peek(3), 2);
    }

    #[test]
    fn touch_idx_0_is_a_noop_in_layout() {
        let mut c = DistCache::new();
        c.push(10);
        c.push(20);
        c.push(30);
        c.push(40);
        let snapshot_before = (c.peek(0), c.peek(1), c.peek(2), c.peek(3));
        let got = c.touch(0);
        assert_eq!(got, 40);
        assert_eq!(
            (c.peek(0), c.peek(1), c.peek(2), c.peek(3)),
            snapshot_before
        );
    }

    #[test]
    fn touch_idx_1_promotes_slot_1_to_slot_0() {
        // Cache: [40, 30, 20, 10]. touch(1) returns 30 and the
        // result becomes [30, 40, 20, 10].
        let mut c = DistCache::new();
        c.push(10);
        c.push(20);
        c.push(30);
        c.push(40);
        let got = c.touch(1);
        assert_eq!(got, 30);
        assert_eq!(c.peek(0), 30);
        assert_eq!(c.peek(1), 40);
        assert_eq!(c.peek(2), 20);
        assert_eq!(c.peek(3), 10);
    }

    #[test]
    fn touch_idx_2_promotes_slot_2_to_slot_0() {
        // Cache: [40, 30, 20, 10]. touch(2) returns 20 and the
        // result becomes [20, 40, 30, 10].
        let mut c = DistCache::new();
        c.push(10);
        c.push(20);
        c.push(30);
        c.push(40);
        let got = c.touch(2);
        assert_eq!(got, 20);
        assert_eq!(c.peek(0), 20);
        assert_eq!(c.peek(1), 40);
        assert_eq!(c.peek(2), 30);
        assert_eq!(c.peek(3), 10);
    }

    #[test]
    fn touch_idx_3_promotes_slot_3_to_slot_0() {
        // Cache: [40, 30, 20, 10]. touch(3) returns 10 and the
        // result becomes [10, 40, 30, 20].
        let mut c = DistCache::new();
        c.push(10);
        c.push(20);
        c.push(30);
        c.push(40);
        let got = c.touch(3);
        assert_eq!(got, 10);
        assert_eq!(c.peek(0), 10);
        assert_eq!(c.peek(1), 40);
        assert_eq!(c.peek(2), 30);
        assert_eq!(c.peek(3), 20);
    }

    #[test]
    fn touch_then_push_replaces_slot_0() {
        // After touching, slot 0 = the touched value. A subsequent
        // push shifts that value to slot 1, leaving slot 0 with the
        // newly-pushed distance.
        let mut c = DistCache::new();
        c.push(10);
        c.push(20);
        c.push(30);
        c.push(40);
        c.touch(2); // → [20, 40, 30, 10]
        c.push(99); // → [99, 20, 40, 30]
        assert_eq!(c.peek(0), 99);
        assert_eq!(c.peek(1), 20);
        assert_eq!(c.peek(2), 40);
        assert_eq!(c.peek(3), 30);
    }
}
