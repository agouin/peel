//! Move-to-front state for the per-block MTF inverse.
//!
//! `internal/PLAN_bz2_support.md` Phase 4. Bzip2 maintains a
//! per-block MTF alphabet seeded from the block-header "symbols
//! used" bitmap — *not* from `0..256`. The alphabet's initial
//! ordering is the sorted byte values that appear in this block
//! (ascending). Each [`MtfState::pop`] call returns the byte at the
//! given rank and moves it to the front of the list.

use super::error::Bzip2Error;

/// Move-to-front state. The active alphabet lives in
/// [`MtfState::table`]`[..len]`; entries past `len` are stale.
#[derive(Debug, Clone)]
pub struct MtfState {
    /// Sliding alphabet. Active entries live in `table[..len]`.
    /// Size cap 256 is the maximum possible alphabet (the full byte
    /// range); typical blocks use far fewer.
    table: [u8; 256],
    /// Number of valid entries in `table`.
    len: usize,
}

impl MtfState {
    /// Build a fresh MTF state seeded from the block-header
    /// "symbols used" bitmap. The initial alphabet ordering is the
    /// byte values from 0..256 that the bitmap marks present, in
    /// ascending order.
    #[must_use]
    pub fn new(symbols_used: &[bool; 256]) -> Self {
        let mut table = [0u8; 256];
        let mut len = 0usize;
        for (b, &used) in symbols_used.iter().enumerate() {
            if used {
                // INVARIANT: b < 256, fits in u8; len < 256 by the
                // loop bound.
                table[len] = b as u8;
                len += 1;
            }
        }
        Self { table, len }
    }

    /// Number of bytes in the active alphabet.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` when the active alphabet is empty. Bzip2 rejects
    /// empty symbol sets at the block-header stage, but the lint
    /// pairs with [`Self::len`] regardless.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Byte currently at MTF rank 0 (the byte RUNA/RUNB sequences
    /// expand into).
    #[must_use]
    pub fn front(&self) -> u8 {
        debug_assert!(self.len > 0, "MtfState::front called on empty alphabet");
        self.table[0]
    }

    /// Pop the byte at rank `rank` and move it to the front. The
    /// returned byte is the post-MTF stream byte for the symbol the
    /// caller decoded.
    ///
    /// # Errors
    ///
    /// - [`Bzip2Error::MalformedHuffman`] if `rank >= self.len` —
    ///   indicates source corruption (a Huffman symbol referenced an
    ///   MTF rank past the alphabet end).
    pub fn pop(&mut self, rank: usize) -> Result<u8, Bzip2Error> {
        if rank >= self.len {
            return Err(Bzip2Error::MalformedHuffman(
                "MTF rank exceeds active alphabet size",
            ));
        }
        let value = self.table[rank];
        // Shift table[0..rank] right by one to fill the gap, then
        // place `value` at position 0. INVARIANT: rank < len <= 256,
        // so the loop is bounded.
        let mut i = rank;
        while i > 0 {
            self.table[i] = self.table[i - 1];
            i -= 1;
        }
        self.table[0] = value;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn used_set(bytes: &[u8]) -> [bool; 256] {
        let mut s = [false; 256];
        for &b in bytes {
            s[b as usize] = true;
        }
        s
    }

    #[test]
    fn initial_alphabet_is_sorted_byte_values() {
        let mtf = MtfState::new(&used_set(&[0x41, 0x10, 0xFF, 0x02]));
        assert_eq!(mtf.len(), 4);
        assert_eq!(mtf.front(), 0x02);
        // Pop rank 3 → 0xFF (the largest).
        let mut mtf = mtf;
        assert_eq!(mtf.pop(3).expect("rank 3"), 0xFF);
        // Now table[..4] = [0xFF, 0x02, 0x10, 0x41].
        assert_eq!(mtf.front(), 0xFF);
        assert_eq!(mtf.pop(1).expect("rank 1"), 0x02);
        // Now [0x02, 0xFF, 0x10, 0x41].
        assert_eq!(mtf.front(), 0x02);
    }

    #[test]
    fn pop_rank_zero_returns_front_and_leaves_state_unchanged() {
        let mut mtf = MtfState::new(&used_set(&[0x10, 0x20]));
        assert_eq!(mtf.pop(0).expect("rank 0"), 0x10);
        assert_eq!(mtf.front(), 0x10);
    }

    #[test]
    fn pop_out_of_range_rejected() {
        let mut mtf = MtfState::new(&used_set(&[0x10]));
        match mtf.pop(1) {
            Err(Bzip2Error::MalformedHuffman(_)) => {}
            other => panic!("expected MalformedHuffman, got {other:?}"),
        }
    }

    #[test]
    fn alphabet_size_matches_used_set_count() {
        let mtf = MtfState::new(&used_set(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]));
        assert_eq!(mtf.len(), 11);
    }
}
