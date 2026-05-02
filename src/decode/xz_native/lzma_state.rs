//! LZMA 12-state machine and its four transition tables.
//!
//! Phase 3 of `docs/PLAN_xz_block_decoder.md`. The state encodes the
//! recent symbol history (literal vs. match vs. rep) so context
//! selection in the literal / `is_rep0_long` / `is_match` arrays
//! can adapt to short-range patterns. Every probability slot
//! indexed by `state` shares this 12-valued enum-of-ints.
//!
//! ```text
//! State numbering (LZMA spec, kept verbatim):
//!
//!   States 0..=6  — last emitted symbol was a *literal*.
//!   States 7..=11 — last emitted symbol was a *non-literal*
//!                  (match / rep0..3 / short-rep).
//! ```
//!
//! After observing the next symbol, `state` is replaced by the
//! corresponding entry of one of the four transition tables.
//!
//! # Why four tables
//!
//! The encoder/decoder must agree on `state` byte-for-byte; the
//! tables are baked into the format. There is no "compute from a
//! formula" shortcut — the state graph is hand-tuned by the LZMA
//! authors and the only way to be byte-correct against `xz` output
//! is to use exactly the same transitions. Transcribed from the
//! LZMA specification (`lzma-specification.txt`) per the
//! clean-room discipline of `docs/PLAN_xz_block_decoder.md`
//! §Risks/Open §4.

/// Total number of states in the LZMA state machine.
pub const STATES: usize = 12;

/// States `0..NUM_LIT_STATES` (i.e. `0..=6`) follow a literal;
/// states `NUM_LIT_STATES..STATES` (i.e. `7..=11`) follow a
/// non-literal. The literal decoder branches on this threshold:
/// post-match literals decode through the matched-byte tree,
/// post-literal literals decode through the plain tree.
pub const NUM_LIT_STATES: u8 = 7;

/// Decoder's starting state at the head of every LZMA Block (after
/// either an `0xE0..=0xFF` "reset state" LZMA2 control byte or the
/// implicit reset at the first LZMA chunk in a Block).
pub const STATE_INIT: u8 = 0;

/// Transition table after observing a literal.
///
/// Sources of each row (from the LZMA spec):
///
/// - rows 0..=3 collapse to state 0 — literals from a "settled"
///   post-literal state stay maximally settled.
/// - rows 4..=6 shift down by 3 — gradually re-approach state 0.
/// - rows 7..=9 (post-match family) drop to states 4..=6.
/// - rows 10..=11 (post-rep family) drop to states 4..=5.
pub const STATE_UPDATE_LIT: [u8; STATES] = [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 4, 5];

/// Transition table after observing a match (non-rep, fresh
/// distance).
///
/// All post-literal rows (0..=6) collapse to state 7 — "we just
/// observed a match." Post-non-literal rows (7..=11) collapse to
/// state 10 — "match after non-literal."
pub const STATE_UPDATE_MATCH: [u8; STATES] = [7, 7, 7, 7, 7, 7, 7, 10, 10, 10, 10, 10];

/// Transition table after observing a rep* (rep0/rep1/rep2/rep3
/// long-rep) match.
///
/// Symmetric in shape to [`STATE_UPDATE_MATCH`]: post-literal rows
/// collapse to state 8, post-non-literal rows collapse to state 11.
pub const STATE_UPDATE_REP: [u8; STATES] = [8, 8, 8, 8, 8, 8, 8, 11, 11, 11, 11, 11];

/// Transition table after observing a *short* rep0 (single-byte
/// repeat at distance `rep0`).
///
/// Differs from [`STATE_UPDATE_REP`] only in the post-literal
/// destination — short-rep distinguishes itself from full-length
/// rep so the literal decoder can distinguish them on the next
/// symbol.
pub const STATE_UPDATE_SHORT_REP: [u8; STATES] = [9, 9, 9, 9, 9, 9, 9, 11, 11, 11, 11, 11];

/// `true` if `state` is one of the post-literal states (`0..=6`).
///
/// The literal decoder takes the matched-byte path *only* when
/// `state >= NUM_LIT_STATES`. Codified here so the decoder doesn't
/// hard-code the magic number `7`.
#[inline]
#[must_use]
pub fn is_literal_state(state: u8) -> bool {
    state < NUM_LIT_STATES
}

/// Map `state` through [`STATE_UPDATE_LIT`].
///
/// Wrapped in a function (rather than indexing the const array
/// directly at call sites) so `tracing` instrumentation, debug
/// asserts, or future state-machine variants stay localized.
#[inline]
#[must_use]
pub fn after_literal(state: u8) -> u8 {
    debug_assert!((state as usize) < STATES);
    STATE_UPDATE_LIT[state as usize]
}

/// Map `state` through [`STATE_UPDATE_MATCH`].
#[inline]
#[must_use]
pub fn after_match(state: u8) -> u8 {
    debug_assert!((state as usize) < STATES);
    STATE_UPDATE_MATCH[state as usize]
}

/// Map `state` through [`STATE_UPDATE_REP`].
#[inline]
#[must_use]
pub fn after_rep(state: u8) -> u8 {
    debug_assert!((state as usize) < STATES);
    STATE_UPDATE_REP[state as usize]
}

/// Map `state` through [`STATE_UPDATE_SHORT_REP`].
#[inline]
#[must_use]
pub fn after_short_rep(state: u8) -> u8 {
    debug_assert!((state as usize) < STATES);
    STATE_UPDATE_SHORT_REP[state as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each transition table covers every starting state and never
    /// produces an out-of-range result.
    #[test]
    fn transitions_stay_in_range() {
        for s in 0..STATES as u8 {
            assert!((after_literal(s) as usize) < STATES);
            assert!((after_match(s) as usize) < STATES);
            assert!((after_rep(s) as usize) < STATES);
            assert!((after_short_rep(s) as usize) < STATES);
        }
    }

    /// All four match-shaped transitions land in the post-non-
    /// literal half (`7..=11`). This is a structural invariant of
    /// the state machine: emitting a non-literal forces the
    /// "after non-literal" half regardless of where you started.
    #[test]
    fn match_shaped_transitions_land_post_nonliteral() {
        for s in 0..STATES as u8 {
            assert!(after_match(s) >= NUM_LIT_STATES, "match {s}");
            assert!(after_rep(s) >= NUM_LIT_STATES, "rep {s}");
            assert!(after_short_rep(s) >= NUM_LIT_STATES, "shortrep {s}");
        }
    }

    /// Conversely, observing a literal ALWAYS lands in the post-
    /// literal half.
    #[test]
    fn literal_transitions_land_post_literal() {
        for s in 0..STATES as u8 {
            assert!(after_literal(s) < NUM_LIT_STATES, "lit {s}");
        }
    }

    /// `is_literal_state` agrees with the literal-half threshold.
    #[test]
    fn is_literal_state_matches_threshold() {
        for s in 0..STATES as u8 {
            assert_eq!(is_literal_state(s), s < NUM_LIT_STATES);
        }
    }

    /// Pin-table check: the four constants must equal the LZMA
    /// spec's transcribed values byte-for-byte. Catches an
    /// accidental edit of any single entry.
    #[test]
    fn transition_tables_match_spec() {
        assert_eq!(STATE_UPDATE_LIT, [0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 4, 5]);
        assert_eq!(
            STATE_UPDATE_MATCH,
            [7, 7, 7, 7, 7, 7, 7, 10, 10, 10, 10, 10]
        );
        assert_eq!(STATE_UPDATE_REP, [8, 8, 8, 8, 8, 8, 8, 11, 11, 11, 11, 11]);
        assert_eq!(
            STATE_UPDATE_SHORT_REP,
            [9, 9, 9, 9, 9, 9, 9, 11, 11, 11, 11, 11]
        );
    }
}
