//! Four-slot LRU of recent match offsets for legacy RAR.
//!
//! Sibling of [`crate::decode::rar_native::dist_cache`] —
//! identical shape (four `u32` slots, MRU at index 0, oldest at
//! index 3) but its own fork per §C0's reuse-vs-fork posture so
//! each format's LZ dispatcher can evolve without dragging the
//! other along.
//!
//! # How legacy RAR's main code drives the cache
//!
//! The LZ-mode main alphabet (`MAIN_CODE_SIZE = 299`) has four
//! distinct regions for back-reference symbols (libarchive's
//! `expand` dispatch at line 2956):
//!
//! - `256` — block-end / reserved.
//! - `257` — read a fresh filter program; no cache interaction.
//! - `258` — "repeat last match" — emits a match using the most
//!   recent `(offset, length)` pair the dispatcher saw. The
//!   cache is **not** updated. (`last_offset` / `last_length`
//!   are dispatcher state — outside this module.)
//! - `259..=262` — touch slot `symbol - 259` of this cache:
//!   take its offset, promote it to slot 0, shift the older
//!   slots one position deeper. A fresh length-code decode
//!   pairs with it.
//! - `263..=270` — short-distance match (fixed base + extra
//!   bits). Push the resulting offset onto the cache via
//!   [`Self::push`]; length is fixed at 2.
//! - `271..=298` — full match: length code from `symbol - 271`,
//!   then a distance from the offset Huffman. Push the
//!   resulting offset onto the cache.
//!
//! "Pushing" shifts the existing entries one slot deeper
//! (dropping slot 3) and writes the new offset into slot 0.
//! "Touching" reads slot `idx`, shifts slots `0..idx` one
//! position deeper, and writes the read value into slot 0.
//! Both operations match libarchive's `oldoffset[]` semantics
//! at `archive_read_support_format_rar.c` lines 3030..=3048 /
//! 3113..=3115.

/// Number of slots in the LRU.
pub const DIST_CACHE_SLOTS: usize = 4;

/// 4-slot most-recently-used distance cache.
///
/// Construction starts with every slot at `0`. Empty slots are
/// not legal back-references, but the LZ dispatcher only
/// touches a slot when the wire said to — there's no runtime
/// "is empty" check here. A wire stream that touches an
/// untouched-since-construction slot surfaces a back-reference
/// underflow downstream in [`super::dict::Dict::copy_match`].
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

    /// Construct a cache from a snapshot of its slots. Reserved
    /// for §F1's resume path; today only the tests use it.
    #[must_use]
    pub fn from_slots(slots: [u32; DIST_CACHE_SLOTS]) -> Self {
        Self { slots }
    }

    /// Borrow the slot array (used by §F1's resume snapshot
    /// when it lands).
    #[must_use]
    pub fn slots(&self) -> [u32; DIST_CACHE_SLOTS] {
        self.slots
    }

    /// Read slot `idx` without mutating the cache. Diagnostic
    /// only; the dispatcher uses [`Self::touch`] for the live
    /// LRU pulls.
    #[must_use]
    pub fn peek(&self, idx: usize) -> u32 {
        self.slots[idx]
    }

    /// Push a fresh match offset onto the cache.
    ///
    /// Shifts every existing entry one slot deeper (dropping
    /// slot 3) and writes `offset` into slot 0. Called by the
    /// LZ dispatcher after symbols `263..=298` resolve to a new
    /// `(offset, length)` pair.
    pub fn push(&mut self, offset: u32) {
        self.slots[3] = self.slots[2];
        self.slots[2] = self.slots[1];
        self.slots[1] = self.slots[0];
        self.slots[0] = offset;
    }

    /// Touch slot `idx`: read its offset, shift slots
    /// `0..idx` one position deeper, write the read value into
    /// slot 0, return the offset.
    ///
    /// Called by the LZ dispatcher for main-code symbols
    /// `259..=262` with `idx = symbol - 259`.
    ///
    /// # Panics
    ///
    /// Debug-asserts `idx < DIST_CACHE_SLOTS`. The dispatcher
    /// only generates `idx ∈ 0..=3` so the bound holds at
    /// runtime in non-debug builds too.
    pub fn touch(&mut self, idx: usize) -> u32 {
        debug_assert!(idx < DIST_CACHE_SLOTS, "DistCache::touch idx out of range");
        let offset = self.slots[idx];
        let mut i = idx;
        while i > 0 {
            self.slots[i] = self.slots[i - 1];
            i -= 1;
        }
        self.slots[0] = offset;
        offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_zero_in_every_slot() {
        let c = DistCache::new();
        for i in 0..DIST_CACHE_SLOTS {
            assert_eq!(c.peek(i), 0);
        }
    }

    #[test]
    fn push_promotes_to_slot_zero_and_shifts_rest_deeper() {
        let mut c = DistCache::new();
        c.push(1);
        c.push(2);
        c.push(3);
        c.push(4);
        // Slot 0 = MRU = 4; slot 3 = oldest still resident = 1.
        assert_eq!(c.peek(0), 4);
        assert_eq!(c.peek(1), 3);
        assert_eq!(c.peek(2), 2);
        assert_eq!(c.peek(3), 1);
    }

    #[test]
    fn push_drops_slot_three_when_full() {
        let mut c = DistCache::new();
        for v in 1u32..=5 {
            c.push(v);
        }
        // After 5 pushes the original `1` has fallen off.
        assert_eq!(c.peek(0), 5);
        assert_eq!(c.peek(1), 4);
        assert_eq!(c.peek(2), 3);
        assert_eq!(c.peek(3), 2);
    }

    #[test]
    fn touch_zero_is_a_noop_on_slot_order() {
        let mut c = DistCache::from_slots([10, 20, 30, 40]);
        let got = c.touch(0);
        assert_eq!(got, 10);
        assert_eq!(c.slots(), [10, 20, 30, 40]);
    }

    #[test]
    fn touch_one_swaps_slots_zero_and_one() {
        let mut c = DistCache::from_slots([10, 20, 30, 40]);
        let got = c.touch(1);
        assert_eq!(got, 20);
        assert_eq!(c.slots(), [20, 10, 30, 40]);
    }

    #[test]
    fn touch_two_rotates_three_slots() {
        let mut c = DistCache::from_slots([10, 20, 30, 40]);
        let got = c.touch(2);
        assert_eq!(got, 30);
        assert_eq!(c.slots(), [30, 10, 20, 40]);
    }

    #[test]
    fn touch_three_rotates_all_slots() {
        let mut c = DistCache::from_slots([10, 20, 30, 40]);
        let got = c.touch(3);
        assert_eq!(got, 40);
        assert_eq!(c.slots(), [40, 10, 20, 30]);
    }

    /// Cross-check against libarchive's combined push + touch
    /// sequence: simulate the symbol stream `271, 259, 271, 261`
    /// (push 5, touch 0, push 11, touch 2) and walk through the
    /// expected slot transitions.
    #[test]
    fn libarchive_combined_push_and_touch_sequence() {
        let mut c = DistCache::new();
        // push(5) — symbol 271+ with offset 5.
        c.push(5);
        assert_eq!(c.slots(), [5, 0, 0, 0]);
        // touch(0) — symbol 259 with idx 0. (No reorder; just
        // returns slot 0's offset.)
        assert_eq!(c.touch(0), 5);
        assert_eq!(c.slots(), [5, 0, 0, 0]);
        // push(11) — symbol 271+ with offset 11.
        c.push(11);
        assert_eq!(c.slots(), [11, 5, 0, 0]);
        // touch(2) — symbol 261 with idx 2.
        assert_eq!(c.touch(2), 0);
        assert_eq!(c.slots(), [0, 11, 5, 0]);
    }

    #[test]
    fn from_slots_round_trips() {
        let c = DistCache::from_slots([7, 8, 9, 10]);
        assert_eq!(c.slots(), [7, 8, 9, 10]);
    }
}
