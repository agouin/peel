//! Decoder state types — Phase 1 skeleton (no `lzma_decode_port`
//! body yet).
//!
//! Phase 1 of [`docs/PLAN_xz_liblzma_port.md`](../../../../docs/PLAN_xz_liblzma_port.md).
//! Mirror of liblzma's `lzma_decoder.c` decoder-state shape.
//! Phase 3 fills in the giant `lzma_decode_port` function that
//! drives this state via the [`super::range_coder`] macros.
//!
//! Three top-level types here:
//! - [`Sequence`]: the per-bit-decode resume cursor. Mirror of
//!   liblzma's `enum sequence` at `lzma_decoder.c:246-266`.
//! - [`LzmaProbs`]: every probability slot the LZMA model uses
//!   within one Block. Mirror of liblzma's struct at
//!   `lzma_decoder.c:170-216`.
//! - [`Lzma1Decoder`]: the full decoder state — probs + range
//!   coder + LZMA-state-machine + reps + resume cursor + symbol
//!   cursor. Mirror of liblzma's `lzma_lzma1_decoder` struct.
//!
//! All probability fields use **fixed-size arrays** sized to the
//! spec maximum (`LZMA_LCLP_MAX = 4` => `LITERAL_CODERS_MAX = 16`,
//! `LZMA_PB_MAX = 4` => `POS_STATES_MAX = 16`). At runtime the
//! active `(lc, lp, pb)` triple selects sub-regions; unused slots
//! sit dormant. Worst-case allocation is roughly
//! `16 * 0x300 * 2` bytes for `literal`, `12 * 16 * 2` for
//! `is_match`, `12 * 16 * 2` for `is_rep0_long`, plus another
//! ~16 KiB across the smaller tables — ~28 KiB total per
//! `Lzma1Decoder` instance. The existing
//! `xz_native::probs::LzmaProbs` sizes-on-construct via
//! `Box<[u16]>`; Phase A of
//! [`PLAN_xz_liblzma_deep_dive.md`](../../../../docs/PLAN_xz_liblzma_deep_dive.md)
//! identified the fat-pointer + heap-pointer chase as part of the
//! per-iteration register pressure that fixed-size arrays
//! eliminate.

use super::dict::LzmaDict;
use super::error::XzPortError;
use super::range_coder::{
    rc_bit, rc_direct, rc_if_0, rc_normalize, rc_read_init, rc_update_0, rc_update_1, RangeDecoder,
    PROB_INIT_VAL,
};

// ===== Spec constants (mirror of lzma_common.h) =====

/// Total number of states in the LZMA state machine. Mirror of
/// `STATES = 12`.
pub const STATES: usize = 12;

/// The lowest 7 states indicate that the previous state was a
/// literal. Mirror of `LIT_STATES = 7`.
pub const LIT_STATES: usize = 7;

/// Spec ceiling for `lc + lp`. Mirror of `LZMA_LCLP_MAX = 4`.
pub const LZMA_LCLP_MAX: u32 = 4;

/// Spec ceiling for `pb`. Mirror of `LZMA_PB_MAX = 4`.
pub const LZMA_PB_MAX: u32 = 4;

/// Maximum number of position states (`1 << LZMA_PB_MAX = 16`).
/// Mirror of `POS_STATES_MAX`.
pub const POS_STATES_MAX: usize = 1 << LZMA_PB_MAX;

/// Per-context literal probability count (`0x300`). Mirror of
/// `LITERAL_CODER_SIZE`.
pub const LITERAL_CODER_SIZE: usize = 0x300;

/// Maximum number of literal coders (`1 << LZMA_LCLP_MAX = 16`).
/// Mirror of `LITERAL_CODERS_MAX`.
pub const LITERAL_CODERS_MAX: usize = 1 << LZMA_LCLP_MAX;

/// Smallest match length the LZMA distance/length protocol can
/// represent. Mirror of `MATCH_LEN_MIN = 2`.
pub const MATCH_LEN_MIN: u32 = 2;

/// Length-decoder low subtree bit count. Mirror of `LEN_LOW_BITS = 3`.
pub const LEN_LOW_BITS: u32 = 3;
/// Length-decoder low subtree symbol count. Mirror of
/// `LEN_LOW_SYMBOLS = 8`.
pub const LEN_LOW_SYMBOLS: usize = 1 << LEN_LOW_BITS;
/// Length-decoder mid subtree bit count.
pub const LEN_MID_BITS: u32 = 3;
/// Length-decoder mid subtree symbol count.
pub const LEN_MID_SYMBOLS: usize = 1 << LEN_MID_BITS;
/// Length-decoder high subtree bit count.
pub const LEN_HIGH_BITS: u32 = 8;
/// Length-decoder high subtree symbol count.
pub const LEN_HIGH_SYMBOLS: usize = 1 << LEN_HIGH_BITS;
/// Total length symbols; max match length = `LEN_SYMBOLS - 1 + MATCH_LEN_MIN`.
pub const LEN_SYMBOLS: usize = LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS + LEN_HIGH_SYMBOLS;
/// Largest match length (`273`).
pub const MATCH_LEN_MAX: u32 = MATCH_LEN_MIN + LEN_SYMBOLS as u32 - 1;

/// Number of distance-state buckets. Mirror of `DIST_STATES = 4`.
pub const DIST_STATES: usize = 4;
/// Number of distance-slot bits (`6`); slots = `64`.
pub const DIST_SLOT_BITS: u32 = 6;
/// Distance-slot count (`64`).
pub const DIST_SLOTS: usize = 1 << DIST_SLOT_BITS;
/// First distance slot needing extra bits.
pub const DIST_MODEL_START: u32 = 4;
/// First distance slot using only direct + alignment bits.
pub const DIST_MODEL_END: u32 = 14;
/// Bits in the full-distances probability table (`7`).
pub const FULL_DISTANCES_BITS: u32 = DIST_MODEL_END / 2;
/// Number of slots in the shared full-distances table (`128`).
pub const FULL_DISTANCES: usize = 1 << FULL_DISTANCES_BITS;
/// Aligned-bits subtree bit count (`4`).
pub const ALIGN_BITS: u32 = 4;
/// Aligned-bits subtree slot count (`16`).
pub const ALIGN_SIZE: usize = 1 << ALIGN_BITS;
/// Bitmask for the aligned suffix.
pub const ALIGN_MASK: u32 = ALIGN_SIZE as u32 - 1;
/// Number of "most recent distance" slots LZMA tracks. Mirror of
/// `REPS = 4`.
pub const REPS: usize = 4;

/// Per-bit-decode resume cursor.
///
/// Mirror of liblzma's `enum sequence` declared inline at
/// `lzma_decoder.c:246-266`. Each variant marks a bit-decode site
/// in the giant dispatch loop where input underflow may occur
/// mid-byte; the loop saves the variant into
/// [`Lzma1Decoder::sequence`] and exits via `break 'main` so the
/// next call resumes at exactly that bit.
///
/// In Phase 1 the variants are declared but not yet used; Phase 3
/// will populate the inner-loop body that references them.
///
/// liblzma uses C macros (`seq_4`, `seq_6`, `seq_8`, `seq_len`)
/// to expand groups of `_0` ... `_N` enumerated values. This
/// Rust port lists them all explicitly — no macro needed because
/// Rust enums don't pay a runtime cost for having many variants.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Sequence {
    // The variants are bit-position labels mirroring liblzma's
    // SEQ_* enum values; their semantic content is "this is the
    // bit slot in the per-byte literal / matched-literal /
    // length / distance bit walk where execution paused on the
    // last input-underflow". Documenting each variant
    // individually would just say that 70 times. The Phase 3
    // dispatch loop's match arms are where the per-variant
    // semantics actually live.
    Normalize,
    IsMatch,
    Literal0,
    Literal1,
    Literal2,
    Literal3,
    Literal4,
    Literal5,
    Literal6,
    Literal7,
    LiteralMatched0,
    LiteralMatched1,
    LiteralMatched2,
    LiteralMatched3,
    LiteralMatched4,
    LiteralMatched5,
    LiteralMatched6,
    LiteralMatched7,
    LiteralWrite,
    IsRep,
    MatchLenChoice,
    MatchLenLow0,
    MatchLenLow1,
    MatchLenLow2,
    MatchLenChoice2,
    MatchLenMid0,
    MatchLenMid1,
    MatchLenMid2,
    MatchLenHigh0,
    MatchLenHigh1,
    MatchLenHigh2,
    MatchLenHigh3,
    MatchLenHigh4,
    MatchLenHigh5,
    MatchLenHigh6,
    MatchLenHigh7,
    DistSlot0,
    DistSlot1,
    DistSlot2,
    DistSlot3,
    DistSlot4,
    DistSlot5,
    DistModel,
    Direct,
    Align0,
    Align1,
    Align2,
    Align3,
    Eopm,
    IsRep0,
    ShortRep,
    IsRep0Long,
    IsRep1,
    IsRep2,
    RepLenChoice,
    RepLenLow0,
    RepLenLow1,
    RepLenLow2,
    RepLenChoice2,
    RepLenMid0,
    RepLenMid1,
    RepLenMid2,
    RepLenHigh0,
    RepLenHigh1,
    RepLenHigh2,
    RepLenHigh3,
    RepLenHigh4,
    RepLenHigh5,
    RepLenHigh6,
    RepLenHigh7,
    Copy,
}

/// LZMA model state machine value. Mirror of liblzma's
/// `lzma_lzma_state` (`lzma_common.h:56-69`).
///
/// Stored as a `u8` to keep the [`Lzma1Decoder`] struct compact;
/// the LZMA spec only uses 12 distinct values so a `u8` is
/// sufficient. Indexed into `is_match`, `is_rep`, etc.
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LzmaState {
    // Variants mirror liblzma's `lzma_lzma_state` enum names.
    // Each name encodes a recent-symbol-history fingerprint
    // (`STATE_oldest_older_previous`, `REP` = short or long rep,
    // `NONLIT` = any non-literal). Per-variant semantics are
    // determined by the LZMA spec's adaptation tables and used
    // only as indices into `is_match` / `is_rep*` arrays.
    LitLit = 0,
    MatchLitLit = 1,
    RepLitLit = 2,
    ShortRepLitLit = 3,
    MatchLit = 4,
    RepLit = 5,
    ShortRepLit = 6,
    LitMatch = 7,
    LitLongRep = 8,
    LitShortRep = 9,
    NonlitMatch = 10,
    NonlitRep = 11,
}

impl LzmaState {
    /// `true` if the previous state was a literal (states 0..=6).
    /// Mirror of `is_literal_state(state)`.
    #[inline]
    #[must_use]
    pub const fn is_literal_state(self) -> bool {
        (self as u8) < LIT_STATES as u8
    }
}

/// Length-decoder probability tables. Mirror of liblzma's
/// `lzma_length_decoder`:
///
/// ```c
/// typedef struct {
///     probability choice;
///     probability choice2;
///     probability low[POS_STATES_MAX][LEN_LOW_SYMBOLS];
///     probability mid[POS_STATES_MAX][LEN_MID_SYMBOLS];
///     probability high[LEN_HIGH_SYMBOLS];
/// } lzma_length_decoder;
/// ```
#[derive(Debug, Clone)]
pub struct LengthDecoder {
    /// Choice between low subtree (length 2-9) and mid/high.
    pub choice: u16,
    /// Choice between mid (length 10-17) and high (18-273).
    pub choice2: u16,
    /// Low subtree (length 2-9). Indexed `[pos_state][bit_tree_pos]`.
    pub low: [[u16; LEN_LOW_SYMBOLS]; POS_STATES_MAX],
    /// Mid subtree (length 10-17). Indexed
    /// `[pos_state][bit_tree_pos]`.
    pub mid: [[u16; LEN_MID_SYMBOLS]; POS_STATES_MAX],
    /// High subtree (length 18-273). Single shared subtree
    /// across pos-states.
    pub high: [u16; LEN_HIGH_SYMBOLS],
}

impl LengthDecoder {
    /// Construct a fresh length decoder with all slots at
    /// [`PROB_INIT_VAL`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            choice: PROB_INIT_VAL,
            choice2: PROB_INIT_VAL,
            low: [[PROB_INIT_VAL; LEN_LOW_SYMBOLS]; POS_STATES_MAX],
            mid: [[PROB_INIT_VAL; LEN_MID_SYMBOLS]; POS_STATES_MAX],
            high: [PROB_INIT_VAL; LEN_HIGH_SYMBOLS],
        }
    }

    /// Reset all slots to [`PROB_INIT_VAL`]. Called at LZMA2
    /// "reset state" boundaries.
    pub fn reset(&mut self) {
        self.choice = PROB_INIT_VAL;
        self.choice2 = PROB_INIT_VAL;
        for row in &mut self.low {
            row.fill(PROB_INIT_VAL);
        }
        for row in &mut self.mid {
            row.fill(PROB_INIT_VAL);
        }
        self.high.fill(PROB_INIT_VAL);
    }
}

impl Default for LengthDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Every probability slot the LZMA model uses within one Block.
///
/// Mirror of the `probability literal[...]; probability is_match[...]; ...`
/// fields at `lzma_decoder.c:170-216`. All fields are fixed-size
/// arrays so the call-site indexing compiles to plain offset
/// arithmetic — no fat pointer, no heap pointer chase, no
/// per-call bounds-check uncertainty.
///
/// Constructed via [`Self::new`] (all slots at [`PROB_INIT_VAL`]).
/// At runtime the active `(lc, lp, pb)` triple selects sub-regions
/// of `literal` / `is_match` / `is_rep0_long` / length-decoder
/// `low` / `mid` arrays; unused slots sit dormant.
#[derive(Debug, Clone)]
pub struct LzmaProbs {
    /// Literal-coder probabilities. Indexed
    /// `[literal_state][slot]` where `literal_state` is the
    /// `(pos & lp_mask) << lc | (prev_byte >> (8 - lc))`
    /// composition. Sized to the spec maximum of 16 contexts ×
    /// 0x300 slots = 24 KiB.
    pub literal: [[u16; LITERAL_CODER_SIZE]; LITERAL_CODERS_MAX],

    /// `is_match[state][pos_state]` — literal vs. non-literal.
    pub is_match: [[u16; POS_STATES_MAX]; STATES],

    /// `is_rep[state]` — fresh-distance match vs. rep match.
    pub is_rep: [u16; STATES],

    /// `is_rep0[state]` — rep0 vs. rep1/2/3.
    pub is_rep0: [u16; STATES],

    /// `is_rep1[state]` — rep1 vs. rep2/3.
    pub is_rep1: [u16; STATES],

    /// `is_rep2[state]` — rep2 vs. rep3.
    pub is_rep2: [u16; STATES],

    /// `is_rep0_long[state][pos_state]` — short-rep vs. long-rep
    /// (only consulted on rep0).
    pub is_rep0_long: [[u16; POS_STATES_MAX]; STATES],

    /// Distance pos-slot bit trees `[len_state][slot]`.
    pub dist_slot: [[u16; DIST_SLOTS]; DIST_STATES],

    /// Shared "extra-bits" probabilities for distance slots
    /// `4..=13`. Indexed `[dist - dist_slot]`.
    pub pos_special: [u16; FULL_DISTANCES],

    /// Aligned 4-bit reverse bit-tree at the bottom of distance
    /// slots `>= 14`.
    pub pos_align: [u16; ALIGN_SIZE],

    /// Length decoder for fresh-distance matches.
    pub match_len_decoder: LengthDecoder,
    /// Length decoder for rep matches.
    pub rep_len_decoder: LengthDecoder,
}

impl LzmaProbs {
    /// Construct a fresh probability table with every slot at
    /// [`PROB_INIT_VAL`]. Mirror of liblzma's `bittree_reset`
    /// applied to every sub-table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            literal: [[PROB_INIT_VAL; LITERAL_CODER_SIZE]; LITERAL_CODERS_MAX],
            is_match: [[PROB_INIT_VAL; POS_STATES_MAX]; STATES],
            is_rep: [PROB_INIT_VAL; STATES],
            is_rep0: [PROB_INIT_VAL; STATES],
            is_rep1: [PROB_INIT_VAL; STATES],
            is_rep2: [PROB_INIT_VAL; STATES],
            is_rep0_long: [[PROB_INIT_VAL; POS_STATES_MAX]; STATES],
            dist_slot: [[PROB_INIT_VAL; DIST_SLOTS]; DIST_STATES],
            pos_special: [PROB_INIT_VAL; FULL_DISTANCES],
            pos_align: [PROB_INIT_VAL; ALIGN_SIZE],
            match_len_decoder: LengthDecoder::new(),
            rep_len_decoder: LengthDecoder::new(),
        }
    }

    /// Reset every slot to [`PROB_INIT_VAL`]. Called when the
    /// LZMA2 chunk control byte requests a model reset.
    pub fn reset(&mut self) {
        for row in &mut self.literal {
            row.fill(PROB_INIT_VAL);
        }
        for row in &mut self.is_match {
            row.fill(PROB_INIT_VAL);
        }
        self.is_rep.fill(PROB_INIT_VAL);
        self.is_rep0.fill(PROB_INIT_VAL);
        self.is_rep1.fill(PROB_INIT_VAL);
        self.is_rep2.fill(PROB_INIT_VAL);
        for row in &mut self.is_rep0_long {
            row.fill(PROB_INIT_VAL);
        }
        for row in &mut self.dist_slot {
            row.fill(PROB_INIT_VAL);
        }
        self.pos_special.fill(PROB_INIT_VAL);
        self.pos_align.fill(PROB_INIT_VAL);
        self.match_len_decoder.reset();
        self.rep_len_decoder.reset();
    }
}

impl Default for LzmaProbs {
    fn default() -> Self {
        Self::new()
    }
}

/// Full LZMA1 decoder state — mirror of liblzma's
/// `lzma_lzma1_decoder` struct at `lzma_decoder.c:170-286`.
///
/// Holds:
/// - [`LzmaProbs`]: every probability slot.
/// - [`RangeDecoder`]: the rc state (range, code, init_bytes_left).
/// - [`LzmaState`]: 12-state machine value.
/// - `rep0..rep3`: most-recent encoded distances.
/// - `pos_mask`, `literal_context_bits`, `literal_pos_mask`:
///   precomputed `(lc, lp, pb)` derivatives.
/// - The "incomplete-symbol" resume state ([`Sequence`] cursor,
///   per-bit symbol cursor, plus `limit`, `offset`, `len`) that
///   Phase 3 will use to resume mid-byte across input-underflow
///   boundaries.
///
/// Phase 1 wires the struct only; Phase 3 implements the
/// `lzma_decode_port` function that drives it.
pub struct Lzma1Decoder {
    /// Probability tables.
    pub probs: LzmaProbs,

    /// Range coder state.
    pub rc: RangeDecoder,

    /// LZMA 12-state machine value.
    pub state: LzmaState,

    /// Distance of the latest match (rep0). Also the source for
    /// the matched-literal `match_byte` lookup.
    pub rep0: u32,
    /// Second-most-recent distance.
    pub rep1: u32,
    /// Third-most-recent distance.
    pub rep2: u32,
    /// Fourth-most-recent distance.
    pub rep3: u32,

    /// `(1 << pb) - 1`, precomputed for `is_match` / `is_rep0_long`
    /// indexing.
    pub pos_mask: u32,
    /// Active `lc` (literal-context bits, `0..=8`).
    pub literal_context_bits: u32,
    /// `(1 << lp) - 1`, precomputed for the literal-context formula.
    pub literal_pos_mask: u32,

    // ---- "incomplete symbol" state (Phase 3 will populate via the
    // sequence-resume path; Phase 1 just reserves the fields) ----
    /// Resume cursor — where to continue the dispatch loop on the
    /// next call.
    pub sequence: Sequence,
    /// Symbol being decoded. Also used as an index variable in
    /// bit-tree decoders (`probs[symbol]`).
    pub symbol: u32,
    /// Loop-termination condition for bit-tree / direct-bits
    /// decoders.
    pub limit: u32,
    /// Matched-literal decoder: `0x100` or `0` to help avoiding
    /// branches. Bit-tree reverse decoders: offset of the next
    /// bit (`1 << offset`).
    pub offset: u32,
    /// If decoding a literal: match byte. If decoding a match:
    /// length of the match.
    pub len: u32,
}

impl Lzma1Decoder {
    /// Construct a decoder positioned to consume the rc init
    /// prefix as its first action. All probs at [`PROB_INIT_VAL`],
    /// state machine at `LitLit`, reps zeroed.
    ///
    /// `pos_mask`, `literal_context_bits`, `literal_pos_mask` are
    /// initialized to defaults that match `(lc=0, lp=0, pb=0)`;
    /// the LZMA2 chunk dispatcher will overwrite them when the
    /// Block's properties byte is parsed (Phase 5).
    #[must_use]
    pub fn new() -> Self {
        Self {
            probs: LzmaProbs::new(),
            rc: RangeDecoder::new(),
            state: LzmaState::LitLit,
            rep0: 0,
            rep1: 0,
            rep2: 0,
            rep3: 0,
            pos_mask: 0,
            literal_context_bits: 0,
            literal_pos_mask: 0,
            sequence: Sequence::Normalize,
            symbol: 0,
            limit: 0,
            offset: 0,
            len: 0,
        }
    }

    /// Set the active `(lc, lp, pb)` triple, computing the
    /// derived masks. Called by the LZMA2 chunk dispatcher
    /// (Phase 5) when a chunk control byte declares new
    /// properties.
    ///
    /// # Panics (debug)
    ///
    /// `lc + lp <= LZMA_LCLP_MAX` and `pb <= LZMA_PB_MAX`. The
    /// chunk dispatcher is responsible for validating the
    /// properties byte at the spec boundary; this method is the
    /// internal "trust the caller" path.
    pub fn set_properties(&mut self, lc: u32, lp: u32, pb: u32) {
        debug_assert!(lc + lp <= LZMA_LCLP_MAX, "lc + lp out of range");
        debug_assert!(pb <= LZMA_PB_MAX, "pb out of range");
        self.literal_context_bits = lc;
        self.literal_pos_mask = (1u32 << lp) - 1;
        self.pos_mask = (1u32 << pb) - 1;
    }

    /// Reset the LZMA state machine + rep slots + per-symbol
    /// resume cursor. Mirror of liblzma's chunk dispatcher
    /// "reset state" path. Does NOT touch [`Self::probs`] or
    /// [`Self::rc`] — callers chain those resets per the
    /// chunk control byte's semantics.
    pub fn reset_state_machine(&mut self) {
        self.state = LzmaState::LitLit;
        self.rep0 = 0;
        self.rep1 = 0;
        self.rep2 = 0;
        self.rep3 = 0;
        self.sequence = Sequence::Normalize;
        self.symbol = 0;
        self.limit = 0;
        self.offset = 0;
        self.len = 0;
    }

    /// Full reset: probs + state machine + a fresh
    /// `RangeDecoder` (5 init bytes pending). Followed by
    /// [`Self::set_properties`] when the chunk dispatcher
    /// has parsed a properties byte.
    pub fn full_reset(&mut self) {
        self.probs.reset();
        self.reset_state_machine();
        self.rc = RangeDecoder::new();
    }
}

impl Default for Lzma1Decoder {
    fn default() -> Self {
        Self::new()
    }
}

// ===== State-transition helpers (mirror of lzma_common.h) =====

/// LZMA literal-state transition table. Mirror of liblzma's
/// `lzma_decoder.c:468-481` `next_state[]` lookup table that
/// the C code uses as the body of `update_literal`.
///
/// liblzma writes this as a `static const lzma_lzma_state
/// next_state[]` inside the dispatch function; the same shape
/// in Rust is a top-level `const` because `LzmaState` is a
/// trivially-`Copy` enum.
const LITERAL_NEXT_STATE: [u8; STATES] = [
    LzmaState::LitLit as u8,
    LzmaState::LitLit as u8,
    LzmaState::LitLit as u8,
    LzmaState::LitLit as u8,
    LzmaState::MatchLitLit as u8,
    LzmaState::RepLitLit as u8,
    LzmaState::ShortRepLitLit as u8,
    LzmaState::MatchLit as u8,
    LzmaState::RepLit as u8,
    LzmaState::ShortRepLit as u8,
    LzmaState::MatchLit as u8,
    LzmaState::RepLit as u8,
];

/// `update_literal(state)` — apply the post-literal state
/// transition. Mirror of liblzma's `lzma_decoder.c:464-482`
/// inline state machine.
#[inline]
#[must_use]
fn update_literal(state: LzmaState) -> LzmaState {
    let raw = LITERAL_NEXT_STATE[state as usize];
    // SAFETY: `LITERAL_NEXT_STATE` only contains valid
    // `LzmaState` discriminants (0..=11). The transmute is the
    // standard "u8 → repr(u8) enum" pattern; every byte in the
    // table is one of the 12 spec-defined variants.
    unsafe { std::mem::transmute::<u8, LzmaState>(raw) }
}

/// `update_match(state)` — apply the post-fresh-distance-match
/// transition. Mirror of `lzma_common.h`'s `update_match`.
#[inline]
#[must_use]
fn update_match(state: LzmaState) -> LzmaState {
    if state.is_literal_state() {
        LzmaState::LitMatch
    } else {
        LzmaState::NonlitMatch
    }
}

/// `update_long_rep(state)` — apply the post-long-rep
/// transition. Mirror of `lzma_common.h`'s `update_long_rep`.
#[inline]
#[must_use]
fn update_long_rep(state: LzmaState) -> LzmaState {
    if state.is_literal_state() {
        LzmaState::LitLongRep
    } else {
        LzmaState::NonlitRep
    }
}

/// `update_short_rep(state)` — apply the post-short-rep
/// transition. Mirror of `lzma_common.h`'s `update_short_rep`.
#[inline]
#[must_use]
fn update_short_rep(state: LzmaState) -> LzmaState {
    if state.is_literal_state() {
        LzmaState::LitShortRep
    } else {
        LzmaState::NonlitRep
    }
}

/// Map a match length to its `dist_state` bucket for distance
/// decoding. Mirror of `lzma_common.h`'s `get_dist_state(len)`:
///
/// ```c
/// ((len) < DIST_STATES + MATCH_LEN_MIN \
///     ? (len) - MATCH_LEN_MIN \
///     : DIST_STATES - 1)
/// ```
#[inline]
#[must_use]
fn get_dist_state(len: u32) -> usize {
    if len < DIST_STATES as u32 + MATCH_LEN_MIN {
        (len - MATCH_LEN_MIN) as usize
    } else {
        DIST_STATES - 1
    }
}

/// Compute the literal-coder context index for the byte at
/// `pos` with previous byte `prev_byte`. Mirror of
/// `literal_subcoder` in `lzma_common.h`.
///
/// Returns the index into `LzmaProbs::literal[..][LITERAL_CODER_SIZE]`.
#[inline]
#[must_use]
fn literal_context_index(pos: u64, prev_byte: u8, lc: u32, lp_mask: u32) -> usize {
    (((pos as u32 & lp_mask) << lc) | (u32::from(prev_byte) >> (8 - lc))) as usize
}

/// Status returned by [`lzma_decode_port`] indicating whether
/// the dispatch loop ran to completion or paused mid-stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeStatus {
    /// `dict.pos == dict.limit` — the chunk's output budget is
    /// fully written. The caller (LZMA2 dispatcher in Phase 5)
    /// can validate the final rc state and move to the next
    /// chunk.
    Done,
    /// Input slice exhausted mid-symbol. `coder.sequence` holds
    /// the saved resume cursor; the caller must feed more
    /// bytes and re-invoke. Phase 3 round-one tests don't
    /// exercise this path.
    NeedInput,
}

/// The giant LZMA decode dispatch function. Mirror of liblzma's
/// `lzma_decode` (`lzma_decoder.c:289-846`).
///
/// Drives [`Lzma1Decoder`] state through the LZMA bit-tree
/// decoders, writing emitted bytes into the [`LzmaDict`]. The
/// function runs until either:
/// - the dict's `limit` is reached (returns
///   [`DecodeStatus::Done`]); or
/// - the input slice is exhausted mid-symbol (returns
///   [`DecodeStatus::NeedInput`] with `coder.sequence` saved
///   for the next call to resume from).
///
/// **Phase 3 round-one limitation**: mid-symbol resume is not
/// yet implemented. If `coder.sequence` is anything other than
/// [`Sequence::Normalize`] or [`Sequence::IsMatch`] at entry,
/// the function returns
/// [`XzPortError::ResumeNotSupported`]. Phase F adds resume
/// support when the bench gate at Phase 4 clears.
///
/// # Errors
///
/// - [`XzPortError::RangeCoderInitMarker`] if the rc init
///   prefix's leading byte is non-zero.
/// - [`XzPortError::MatchOutOfRange`] if a decoded match
///   distance exceeds available history.
/// - [`XzPortError::UnexpectedEopm`] if the LZMA1 EOPM marker
///   is hit (we don't support EOPM-terminated streams).
/// - [`XzPortError::ResumeNotSupported`] for mid-symbol resume.
#[allow(unused_assignments)]
pub fn lzma_decode_port(
    coder: &mut Lzma1Decoder,
    dict: &mut LzmaDict,
    bytes: &[u8],
    in_pos: &mut usize,
) -> Result<DecodeStatus, XzPortError> {
    // Phase 3 limitation guard. The only mid-symbol resume
    // arm we support so far is `Sequence::Copy` — used when a
    // long match-copy straddles a dict-wrap boundary in the
    // chunk dispatcher (Phase 4 bench / future Phase 5
    // production). Everything else surfaces a typed error.
    match coder.sequence {
        Sequence::Normalize | Sequence::IsMatch | Sequence::Copy => {}
        other => return Err(XzPortError::ResumeNotSupported { sequence: other }),
    }

    // Cache pos_mask + lc + lp_mask in locals so the inner loop
    // doesn't re-read them through `coder.` each iteration.
    // Mirror of liblzma's `const uint32_t pos_mask = coder->pos_mask;`
    // at function entry.
    let pos_mask = coder.pos_mask;
    let lc = coder.literal_context_bits;
    let lp_mask = coder.literal_pos_mask;

    // Shadow the input cursor into a stack-local; the macros
    // require a plain `:ident` rather than a deref of a
    // `&mut usize`. We write back to `*in_pos` in the
    // epilogue. Mirror of liblzma's `size_t rc_in_pos =
    // (in_pos);` from `rc_to_local`.
    let mut bytes_pos: usize = *in_pos;

    // The labeled block is the Rust spelling of liblzma's
    // `goto out:` epilogue: any macro that detects input
    // underflow saves `coder.sequence` and `break $out`s here.
    'main: {
        // 5-byte rc init prefix. After this `coder.rc.code`
        // holds the initial state.
        rc_read_init!(bytes_pos, bytes, 'main, Sequence::Normalize, coder);

        // Stack-local copies of rc state — the load-bearing
        // piece. Per Phase A's deliverable, keeping these in
        // function-locals (not `&mut struct fields`) is what
        // lets LLVM keep them register-resident.
        let mut range: u32 = coder.rc.range;
        let mut code: u32 = coder.rc.code;
        let mut bound: u32;

        // Mid-Copy resume: if the previous call paused mid-
        // dict_repeat (because the dict's per-call limit was
        // reached), `coder.sequence == Copy` and `coder.len`
        // holds the remaining bytes to copy at distance
        // `coder.rep0`. The chunk dispatcher has set a fresh
        // limit; finish the in-flight match copy before
        // resuming the symbol-decode loop.
        if coder.sequence == Sequence::Copy {
            let mut len_local = coder.len;
            if dict.dict_repeat(coder.rep0, &mut len_local) {
                coder.len = len_local;
                coder.rc.range = range;
                coder.rc.code = code;
                *in_pos = bytes_pos;
                // sequence stays Copy; another resume needed.
                return Ok(DecodeStatus::NeedInput);
            }
            coder.len = 0;
            coder.sequence = Sequence::IsMatch;
        }

        // Cache the most-recently-emitted byte across the
        // outer loop. The literal-context-index formula
        // reads `prev_byte` per literal symbol; without the
        // cache that's `dict.dict_get(0)` per literal (5+
        // instructions) — a per-output-byte cost on LCG-shape
        // payloads, half-density on compressible. The cache:
        // - Initialized from `dict.dict_get(0)` once (or 0 if
        //   the dict is empty).
        // - Updated to the just-decoded byte after every
        //   literal / short-rep emission (free — the value is
        //   already in scope).
        // - Re-loaded via `dict.dict_get(0)` once per match
        //   copy (so multi-byte matches amortize to one
        //   dict_get per match, not per byte).
        //
        // Liblzma doesn't do this caching; we move ahead of
        // it on this lever. Predecessor `xz_native` Phase 2
        // shipped the same optimization with measurable gains.
        let mut prev_byte: u8 = if dict.is_empty() { 0 } else { dict.dict_get(0) };

        // Outer loop: produce one LZMA symbol per iteration
        // (literal byte, single-byte short-rep, or match
        // copy). Terminates when `dict.pos == dict.limit`.
        while dict.pos < dict.limit {
            let pos_state: u32 = (dict.pos as u32) & pos_mask;
            let state_idx = coder.state as usize;
            let pos_state_idx = pos_state as usize;

            // ===== is_match decode =====
            let is_match;
            {
                let prob = &mut coder.probs.is_match[state_idx][pos_state_idx];
                if rc_if_0!(
                    range, code, bytes_pos, bytes, bound, prob,
                    'main, Sequence::IsMatch, coder
                ) {
                    rc_update_0!(range, bound, prob);
                    is_match = false;
                } else {
                    rc_update_1!(range, code, bound, prob);
                    is_match = true;
                }
            }

            if !is_match {
                // ===== Literal =====
                // `prev_byte` cached across iterations; see
                // the cache comment above the outer loop.
                let lit_state = literal_context_index(dict.pos as u64, prev_byte, lc, lp_mask);
                let mut symbol: u32 = 1;

                if coder.state.is_literal_state() {
                    // Plain-path 8-bit walk. Mirror of
                    // liblzma's 8 unrolled `rc_bit_case`
                    // expansions for SEQ_LITERAL0..7.
                    for _ in 0..8 {
                        let prob = &mut coder.probs.literal[lit_state][symbol as usize];
                        rc_bit!(
                            range, code, bytes_pos, bytes, bound, symbol, prob,
                            {}, {},
                            'main, Sequence::IsMatch, coder
                        );
                    }
                } else {
                    // Matched-literal path. Uses liblzma's
                    // `offset` mask trick (`lzma_decoder.c:401-460`):
                    // pre-shift the match byte, init `offset =
                    // 0x100`, AND `offset` with `~match_bit` /
                    // `match_bit` per bit. When `offset`
                    // becomes 0 the matched-vs-plain divergence
                    // has happened; subsequent bits index the
                    // plain table automatically because
                    // `subcoder_index = 0 + 0 + symbol = symbol`.
                    let match_byte = dict.dict_get(coder.rep0);
                    let mut len_local: u32 = u32::from(match_byte) << 1;
                    let mut offset: u32 = 0x100;

                    for _ in 0..8 {
                        let match_bit = len_local & offset;
                        let subcoder_index = (offset + match_bit + symbol) as usize;
                        let prob = &mut coder.probs.literal[lit_state][subcoder_index];
                        rc_bit!(
                            range, code, bytes_pos, bytes, bound, symbol, prob,
                            { offset &= !match_bit; },
                            { offset &= match_bit; },
                            'main, Sequence::IsMatch, coder
                        );
                        len_local <<= 1;
                    }
                }

                coder.state = update_literal(coder.state);

                let byte = (symbol & 0xFF) as u8;
                prev_byte = byte;
                if dict.dict_put(byte) {
                    // dict full mid-literal. Phase F resume
                    // path; Phase 3 fixtures don't hit this
                    // because the test always sets `limit` to
                    // accept the full output.
                    coder.rc.range = range;
                    coder.rc.code = code;
                    *in_pos = bytes_pos;
                    coder.sequence = Sequence::LiteralWrite;
                    return Ok(DecodeStatus::NeedInput);
                }
                continue;
            }

            // ===== Non-literal (match) =====
            let is_rep;
            {
                let prob = &mut coder.probs.is_rep[state_idx];
                if rc_if_0!(
                    range, code, bytes_pos, bytes, bound, prob,
                    'main, Sequence::IsRep, coder
                ) {
                    rc_update_0!(range, bound, prob);
                    is_rep = false;
                } else {
                    rc_update_1!(range, code, bound, prob);
                    is_rep = true;
                }
            }

            let len: u32;

            if !is_rep {
                // ----- Fresh-distance match -----
                coder.state = update_match(coder.state);
                coder.rep3 = coder.rep2;
                coder.rep2 = coder.rep1;
                coder.rep1 = coder.rep0;

                // Length decode (match_len_decoder).
                len = decode_length_inline(
                    &mut range,
                    &mut code,
                    &mut bytes_pos,
                    bytes,
                    &mut coder.probs.match_len_decoder,
                    pos_state_idx,
                    &mut coder.sequence,
                    &mut coder.rc,
                    true,
                )?;

                // Distance decode.
                let dist_state = get_dist_state(len);
                let mut dist_symbol: u32 = 1;
                {
                    let probs = &mut coder.probs.dist_slot[dist_state];
                    for _ in 0..(DIST_SLOT_BITS as usize) {
                        let prob = &mut probs[dist_symbol as usize];
                        rc_bit!(
                            range, code, bytes_pos, bytes, bound, dist_symbol, prob,
                            {}, {},
                            'main, Sequence::DistSlot0, coder
                        );
                    }
                }
                let pos_slot = dist_symbol - DIST_SLOTS as u32;
                debug_assert!(pos_slot <= 63);

                if pos_slot < DIST_MODEL_START {
                    coder.rep0 = pos_slot;
                } else {
                    let direct_bits = (pos_slot >> 1) - 1;
                    debug_assert!((1..=30).contains(&direct_bits));
                    // Mirror of liblzma's `rep0 = 2 + (symbol &
                    // 1);` — NOT pre-shifted by direct_bits.
                    // The pos_special and direct+align paths
                    // each apply the right shift in the right
                    // place.
                    coder.rep0 = 2 | (pos_slot & 1);

                    if pos_slot < DIST_MODEL_END {
                        // Distance in [4, 127]: pre-shift by
                        // direct_bits, then read direct_bits
                        // probabilistic extra bits via
                        // pos_special's reverse bit-tree.
                        //
                        // liblzma uses `probs = pos_special +
                        // rep0 - pos_slot - 1` (pointer
                        // arithmetic that may land one before
                        // the array start), relying on the
                        // bit-tree always reading `probs[m]`
                        // with `m >= 1`. Rust slices can't
                        // express that; we fold the `-1` into
                        // the per-bit index instead, accessing
                        // `pos_special[(rep0 - pos_slot) + sym
                        // - 1]`. INVARIANT: `rep0 >= pos_slot`
                        // (rep0 was just set to `(2 | (pos_slot
                        // & 1)) << direct_bits`), so the
                        // subtraction is non-negative; `sym
                        // >= 1` keeps the inner add
                        // non-negative.
                        coder.rep0 <<= direct_bits;
                        let probs_base = (coder.rep0 - pos_slot) as usize;
                        let mut sym: u32 = 1;
                        for off in 0..direct_bits {
                            let idx = probs_base + sym as usize - 1;
                            let prob = &mut coder.probs.pos_special[idx];
                            rc_bit!(
                                range, code, bytes_pos, bytes, bound, sym, prob,
                                {},
                                { coder.rep0 += 1u32 << off; },
                                'main, Sequence::DistModel, coder
                            );
                        }
                    } else {
                        // Distance >= 128. liblzma's path:
                        // start with rep0 = 2|(slot&1) (NOT
                        // pre-shifted), accumulate
                        // `direct_bits - 4` raw bits via
                        // `rc_direct` (each call left-shifts
                        // rep0 by 1 and ORs in the bit), then
                        // shift by ALIGN_BITS, then add 4
                        // probability-driven align bits.
                        let direct_count = direct_bits - ALIGN_BITS;
                        let mut tmp = coder.rep0;
                        for _ in 0..direct_count {
                            rc_direct!(
                                range, code, bytes_pos, bytes, bound, tmp,
                                'main, Sequence::Direct, coder
                            );
                        }
                        coder.rep0 = tmp << ALIGN_BITS;

                        // 4-bit aligned reverse bit-tree.
                        let mut sym: u32 = 1;
                        for off in 0..ALIGN_BITS {
                            let prob = &mut coder.probs.pos_align[sym as usize];
                            rc_bit!(
                                range, code, bytes_pos, bytes, bound, sym, prob,
                                {},
                                { coder.rep0 += 1u32 << off; },
                                'main, Sequence::Align0, coder
                            );
                        }

                        if coder.rep0 == u32::MAX {
                            // LZMA1 end-of-payload marker —
                            // not legal in LZMA2. liblzma
                            // checks `uncompressed_size !=
                            // LZMA_VLI_UNKNOWN` and errors.
                            return Err(XzPortError::UnexpectedEopm);
                        }
                    }
                }

                if !dict.is_distance_valid(coder.rep0 as usize) {
                    return Err(XzPortError::MatchOutOfRange { dist: coder.rep0 });
                }
            } else {
                // ----- Rep match -----
                if !dict.is_distance_valid(0) {
                    return Err(XzPortError::MatchOutOfRange { dist: 0 });
                }

                // is_rep0 → rep0 vs rep1/2/3
                let pick_rep0;
                {
                    let prob = &mut coder.probs.is_rep0[state_idx];
                    if rc_if_0!(
                        range, code, bytes_pos, bytes, bound, prob,
                        'main, Sequence::IsRep0, coder
                    ) {
                        rc_update_0!(range, bound, prob);
                        pick_rep0 = true;
                    } else {
                        rc_update_1!(range, code, bound, prob);
                        pick_rep0 = false;
                    }
                }

                if pick_rep0 {
                    // is_rep0_long → short-rep (1 byte) vs long-rep
                    let long_rep;
                    {
                        let prob = &mut coder.probs.is_rep0_long[state_idx][pos_state_idx];
                        if rc_if_0!(
                            range, code, bytes_pos, bytes, bound, prob,
                            'main, Sequence::IsRep0Long, coder
                        ) {
                            rc_update_0!(range, bound, prob);
                            long_rep = false;
                        } else {
                            rc_update_1!(range, code, bound, prob);
                            long_rep = true;
                        }
                    }

                    if !long_rep {
                        // Short rep0: emit one byte at rep0.
                        coder.state = update_short_rep(coder.state);
                        let b = dict.dict_get(coder.rep0);
                        prev_byte = b;
                        if dict.dict_put(b) {
                            coder.rc.range = range;
                            coder.rc.code = code;
                            *in_pos = bytes_pos;
                            coder.sequence = Sequence::ShortRep;
                            return Ok(DecodeStatus::NeedInput);
                        }
                        continue;
                    }
                    // Long rep0: rep0 unchanged; fall through
                    // to length decode.
                } else {
                    // is_rep1 → rep1 vs rep2/3
                    let pick_rep1;
                    {
                        let prob = &mut coder.probs.is_rep1[state_idx];
                        if rc_if_0!(
                            range, code, bytes_pos, bytes, bound, prob,
                            'main, Sequence::IsRep1, coder
                        ) {
                            rc_update_0!(range, bound, prob);
                            pick_rep1 = true;
                        } else {
                            rc_update_1!(range, code, bound, prob);
                            pick_rep1 = false;
                        }
                    }

                    if pick_rep1 {
                        std::mem::swap(&mut coder.rep1, &mut coder.rep0);
                    } else {
                        // is_rep2 → rep2 vs rep3
                        let pick_rep2;
                        {
                            let prob = &mut coder.probs.is_rep2[state_idx];
                            if rc_if_0!(
                                range, code, bytes_pos, bytes, bound, prob,
                                'main, Sequence::IsRep2, coder
                            ) {
                                rc_update_0!(range, bound, prob);
                                pick_rep2 = true;
                            } else {
                                rc_update_1!(range, code, bound, prob);
                                pick_rep2 = false;
                            }
                        }

                        let distance = if pick_rep2 {
                            let d = coder.rep2;
                            coder.rep2 = coder.rep1;
                            d
                        } else {
                            let d = coder.rep3;
                            coder.rep3 = coder.rep2;
                            coder.rep2 = coder.rep1;
                            d
                        };
                        coder.rep1 = coder.rep0;
                        coder.rep0 = distance;
                    }
                }

                coder.state = update_long_rep(coder.state);
                len = decode_length_inline(
                    &mut range,
                    &mut code,
                    &mut bytes_pos,
                    bytes,
                    &mut coder.probs.rep_len_decoder,
                    pos_state_idx,
                    &mut coder.sequence,
                    &mut coder.rc,
                    false,
                )?;
            }

            // ----- Common: dict_repeat -----
            debug_assert!(len >= MATCH_LEN_MIN);
            debug_assert!(len <= MATCH_LEN_MAX);
            let mut len_local = len;
            if dict.dict_repeat(coder.rep0, &mut len_local) {
                // dict full mid-copy. Phase F resume.
                coder.len = len_local;
                coder.rc.range = range;
                coder.rc.code = code;
                *in_pos = bytes_pos;
                coder.sequence = Sequence::Copy;
                return Ok(DecodeStatus::NeedInput);
            }
            // Refresh prev_byte once per match copy. The
            // amortized cost is one dict_get per match (not
            // per byte of the match), so multi-byte matches
            // benefit most.
            prev_byte = dict.dict_get(0);
        }

        // dict.pos reached limit. Final normalize per liblzma's
        // `rc_normalize(SEQ_NORMALIZE); coder->sequence =
        // SEQ_IS_MATCH;` at the bottom of the dispatch loop.
        rc_normalize!(
            range, code, bytes_pos, bytes, 'main, Sequence::Normalize, coder
        );
        coder.sequence = Sequence::IsMatch;
        coder.rc.range = range;
        coder.rc.code = code;
    }

    // 'main: epilogue. Either we fell out of the while loop
    // (Done) or we broke via underflow (NeedInput). The macros
    // saved `coder.sequence` on underflow; we just need to
    // distinguish the two cases.
    *in_pos = bytes_pos;
    if coder.sequence == Sequence::IsMatch {
        Ok(DecodeStatus::Done)
    } else {
        Ok(DecodeStatus::NeedInput)
    }
}

/// Length-decode helper used by both fresh-distance and rep
/// match paths. Mirror of liblzma's `len_decode` macro
/// (`lzma_decoder.c:117-155`) — three subtrees (low/mid/high)
/// with different bit counts and length offsets.
///
/// The `_match_path` flag is purely for sequence-cursor
/// labeling (Phase F will use distinct sequence variants for
/// match-len vs rep-len resume); the decode itself is
/// identical.
///
/// **Inlining note**: `#[inline(always)]` was tried (Phase
/// 4.5) and **regressed LCG by 6 pp** (i-cache pressure on the
/// literal hot loop). Compressible was unchanged. Default
/// `#[inline]` shipped — LLVM's heuristic appears to inline
/// this body anyway when called from a single hot site.
#[allow(clippy::too_many_arguments)]
fn decode_length_inline(
    range: &mut u32,
    code: &mut u32,
    in_pos: &mut usize,
    bytes: &[u8],
    ld: &mut LengthDecoder,
    pos_state: usize,
    sequence: &mut Sequence,
    rc: &mut RangeDecoder,
    _match_path: bool,
) -> Result<u32, XzPortError> {
    // We can't use the macros directly from here because the
    // labeled-block escape requires the caller's `'main:`
    // label, which doesn't reach across function boundaries.
    // Instead we emulate the macros' behavior via plain code,
    // returning the decoded length on success or surfacing
    // the underflow as a typed error. Phase F will lift this
    // function inline into `lzma_decode_port` to support the
    // resume path properly; for now this is correct on the
    // full-input path.
    use super::range_coder::{RC_BIT_MODEL_TOTAL, RC_MOVE_BITS, RC_SHIFT_BITS, RC_TOP_VALUE};

    fn local_normalize(
        range: &mut u32,
        code: &mut u32,
        in_pos: &mut usize,
        bytes: &[u8],
        sequence: &mut Sequence,
        rc: &mut RangeDecoder,
        seq_save: Sequence,
    ) -> Result<(), XzPortError> {
        if *range < RC_TOP_VALUE {
            if *in_pos >= bytes.len() {
                *sequence = seq_save;
                rc.range = *range;
                rc.code = *code;
                return Err(XzPortError::RangeCoderUnderflow("len_decode"));
            }
            // SAFETY: just verified in_pos < bytes.len().
            let byte = unsafe { *bytes.as_ptr().add(*in_pos) };
            *range <<= RC_SHIFT_BITS;
            *code = (*code << RC_SHIFT_BITS) | u32::from(byte);
            *in_pos += 1;
        }
        Ok(())
    }

    fn local_decode_bit(
        range: &mut u32,
        code: &mut u32,
        in_pos: &mut usize,
        bytes: &[u8],
        prob: &mut u16,
        sequence: &mut Sequence,
        rc: &mut RangeDecoder,
        seq_save: Sequence,
    ) -> Result<u32, XzPortError> {
        local_normalize(range, code, in_pos, bytes, sequence, rc, seq_save)?;
        let v = u32::from(*prob);
        let bound = (*range >> super::range_coder::RC_BIT_MODEL_TOTAL_BITS) * v;
        let bit;
        if *code < bound {
            *prob = (v + ((RC_BIT_MODEL_TOTAL - v) >> RC_MOVE_BITS)) as u16;
            *range = bound;
            bit = 0;
        } else {
            *prob = (v - (v >> RC_MOVE_BITS)) as u16;
            *code -= bound;
            *range -= bound;
            bit = 1;
        }
        Ok(bit)
    }

    let seq_save = Sequence::MatchLenChoice;

    // choice: low (3 bits) vs mid+high
    let choice = local_decode_bit(
        range,
        code,
        in_pos,
        bytes,
        &mut ld.choice,
        sequence,
        rc,
        seq_save,
    )?;

    if choice == 0 {
        // Low subtree (length 2-9), 3 bits, MSB-first.
        let mut symbol: u32 = 1;
        for _ in 0..LEN_LOW_BITS {
            let bit = local_decode_bit(
                range,
                code,
                in_pos,
                bytes,
                &mut ld.low[pos_state][symbol as usize],
                sequence,
                rc,
                seq_save,
            )?;
            symbol = (symbol << 1) | bit;
        }
        return Ok(MATCH_LEN_MIN + (symbol - LEN_LOW_SYMBOLS as u32));
    }

    // choice == 1
    let choice2 = local_decode_bit(
        range,
        code,
        in_pos,
        bytes,
        &mut ld.choice2,
        sequence,
        rc,
        seq_save,
    )?;
    if choice2 == 0 {
        // Mid subtree (length 10-17), 3 bits.
        let mut symbol: u32 = 1;
        for _ in 0..LEN_MID_BITS {
            let bit = local_decode_bit(
                range,
                code,
                in_pos,
                bytes,
                &mut ld.mid[pos_state][symbol as usize],
                sequence,
                rc,
                seq_save,
            )?;
            symbol = (symbol << 1) | bit;
        }
        return Ok(MATCH_LEN_MIN + LEN_LOW_SYMBOLS as u32 + (symbol - LEN_MID_SYMBOLS as u32));
    }

    // High subtree (length 18-273), 8 bits.
    let mut symbol: u32 = 1;
    for _ in 0..LEN_HIGH_BITS {
        let bit = local_decode_bit(
            range,
            code,
            in_pos,
            bytes,
            &mut ld.high[symbol as usize],
            sequence,
            rc,
            seq_save,
        )?;
        symbol = (symbol << 1) | bit;
    }
    Ok(MATCH_LEN_MIN
        + (LEN_LOW_SYMBOLS + LEN_MID_SYMBOLS) as u32
        + (symbol - LEN_HIGH_SYMBOLS as u32))
}

impl std::fmt::Debug for Lzma1Decoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `LzmaProbs` is ~28 KiB of u16 slots; surfacing them in
        // `Debug` output is unhelpful. Just record the structural
        // fields a developer would actually want to see.
        f.debug_struct("Lzma1Decoder")
            .field("rc", &self.rc)
            .field("state", &self.state)
            .field("rep0", &self.rep0)
            .field("rep1", &self.rep1)
            .field("rep2", &self.rep2)
            .field("rep3", &self.rep3)
            .field("pos_mask", &self.pos_mask)
            .field("literal_context_bits", &self.literal_context_bits)
            .field("literal_pos_mask", &self.literal_pos_mask)
            .field("sequence", &self.sequence)
            .field("symbol", &self.symbol)
            .field("limit", &self.limit)
            .field("offset", &self.offset)
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::xz_liblzma::dict::LzmaDict;
    use crate::decode::xz_native::test_support::TestRangeEncoder;

    // ===== LZMA encoder test helper =====
    //
    // `LzmaTestEncoder` drives `TestRangeEncoder` while
    // maintaining a parallel `LzmaProbs` + `LzmaState` model
    // in the encode direction. Mirror of the decoder's state
    // mutations: every encode_* method matches a decoder
    // arm bit-for-bit.
    //
    // Constraints (round-one tests only):
    // - Distances stay in `[0, 3]` (slot < DIST_MODEL_START),
    //   so no pos_special / direct / align bits.
    // - Lengths stay in `[2, 9]` (low subtree only), so no
    //   choice2 / mid / high.
    //
    // These restrictions cover literal, fresh-distance match,
    // rep0 short, rep0 long, rep1, rep2, rep3 without the more
    // complex distance/length paths. Phase 4's bench fixtures
    // use real xz2-encoded inputs that exercise everything.

    struct LzmaTestEncoder {
        enc: TestRangeEncoder,
        probs: LzmaProbs,
        state: LzmaState,
        rep0: u32,
        rep1: u32,
        rep2: u32,
        rep3: u32,
        pos: u64,
        prev_byte: u8,
        lc: u32,
        lp_mask: u32,
        pb_mask: u32,
        // Track output bytes for matched-literal lookups.
        out: Vec<u8>,
    }

    impl LzmaTestEncoder {
        fn new(lc: u32, lp: u32, pb: u32) -> Self {
            Self {
                enc: TestRangeEncoder::new(),
                probs: LzmaProbs::new(),
                state: LzmaState::LitLit,
                rep0: 0,
                rep1: 0,
                rep2: 0,
                rep3: 0,
                pos: 0,
                prev_byte: 0,
                lc,
                lp_mask: (1u32 << lp) - 1,
                pb_mask: (1u32 << pb) - 1,
                out: Vec::new(),
            }
        }

        fn pos_state(&self) -> usize {
            (self.pos as u32 & self.pb_mask) as usize
        }

        fn encode_literal(&mut self, byte: u8) {
            // is_match = 0
            let pos_state = self.pos_state();
            let state_idx = self.state as usize;
            self.enc
                .encode_bit(&mut self.probs.is_match[state_idx][pos_state], 0);

            let lit_state = literal_context_index(self.pos, self.prev_byte, self.lc, self.lp_mask);
            let mut symbol: u32 = 1;

            if self.state.is_literal_state() {
                // Plain path: 8 bits MSB-first against
                // probs.literal[lit_state][symbol].
                for k in (0..8u32).rev() {
                    let bit = u32::from((byte >> k) & 1);
                    self.enc
                        .encode_bit(&mut self.probs.literal[lit_state][symbol as usize], bit);
                    symbol = (symbol << 1) | bit;
                }
            } else {
                // Matched path: offset-mask trick mirroring
                // the decoder.
                let match_byte = self.dict_get(self.rep0);
                let mut len_local: u32 = u32::from(match_byte) << 1;
                let mut offset: u32 = 0x100;
                for k in (0..8u32).rev() {
                    let match_bit = len_local & offset;
                    let bit = u32::from((byte >> k) & 1);
                    let subcoder_index = (offset + match_bit + symbol) as usize;
                    self.enc
                        .encode_bit(&mut self.probs.literal[lit_state][subcoder_index], bit);
                    if bit == 0 {
                        offset &= !match_bit;
                    } else {
                        offset &= match_bit;
                    }
                    symbol = (symbol << 1) | bit;
                    len_local <<= 1;
                }
            }

            self.state = update_literal(self.state);
            self.prev_byte = byte;
            self.out.push(byte);
            self.pos += 1;
        }

        /// Read the byte at `distance + 1` back from the
        /// encoded output. For round-one tests we keep the
        /// full output in a `Vec<u8>` so this is a simple
        /// `out[len - distance - 1]`.
        fn dict_get(&self, distance: u32) -> u8 {
            let n = self.out.len();
            assert!((distance as usize) < n, "dict_get out of bounds");
            self.out[n - 1 - distance as usize]
        }

        /// Encode a length value via the low subtree (`len`
        /// must be in `[2, 9]`).
        fn encode_length_low(&mut self, ld_match: bool, len: u32, pos_state: usize) {
            assert!(
                (MATCH_LEN_MIN..MATCH_LEN_MIN + LEN_LOW_SYMBOLS as u32).contains(&len),
                "test helper supports only low-subtree lengths [2, 9]"
            );
            let ld = if ld_match {
                &mut self.probs.match_len_decoder
            } else {
                &mut self.probs.rep_len_decoder
            };
            // choice = 0 (low subtree)
            self.enc.encode_bit(&mut ld.choice, 0);
            // 3 bits MSB-first against ld.low[pos_state][symbol]
            let raw = len - MATCH_LEN_MIN;
            let mut symbol: u32 = 1;
            for k in (0..LEN_LOW_BITS).rev() {
                let bit = (raw >> k) & 1;
                self.enc
                    .encode_bit(&mut ld.low[pos_state][symbol as usize], bit);
                symbol = (symbol << 1) | bit;
            }
        }

        /// Encode a fresh-distance match with distance `dist`
        /// in `[0, 3]` (no extra bits) and length in `[2, 9]`
        /// (low subtree only).
        fn encode_fresh_match(&mut self, dist: u32, len: u32) {
            assert!(dist < DIST_MODEL_START, "test helper restricts dist < 4");
            let pos_state = self.pos_state();
            let state_idx = self.state as usize;

            // is_match = 1
            self.enc
                .encode_bit(&mut self.probs.is_match[state_idx][pos_state], 1);
            // is_rep = 0 (fresh-distance)
            self.enc.encode_bit(&mut self.probs.is_rep[state_idx], 0);

            // Update encoder-side state (mirror decoder).
            self.state = update_match(self.state);
            self.rep3 = self.rep2;
            self.rep2 = self.rep1;
            self.rep1 = self.rep0;
            self.rep0 = dist;

            // Length decode (match_len).
            self.encode_length_low(true, len, pos_state);

            // Distance: 6-bit dist_slot (slot 0..3 = dist 0..3,
            // no extra bits).
            let dist_state = get_dist_state(len);
            let dist_slot = dist; // for slots < DIST_MODEL_START, slot == dist
            let mut symbol: u32 = 1;
            for k in (0..DIST_SLOT_BITS).rev() {
                let bit = (dist_slot >> k) & 1;
                self.enc
                    .encode_bit(&mut self.probs.dist_slot[dist_state][symbol as usize], bit);
                symbol = (symbol << 1) | bit;
            }

            // Emit the actual bytes that the dict_repeat would
            // produce, so prev_byte / dict_get on subsequent
            // literals match the decoder's view.
            for _ in 0..len {
                let byte = self.dict_get(dist);
                self.out.push(byte);
                self.prev_byte = byte;
                self.pos += 1;
            }
        }

        /// Encode a rep0 short (single byte at most-recent
        /// distance).
        fn encode_short_rep(&mut self) {
            let pos_state = self.pos_state();
            let state_idx = self.state as usize;

            // is_match = 1, is_rep = 1, is_rep0 = 0, is_rep0_long = 0
            self.enc
                .encode_bit(&mut self.probs.is_match[state_idx][pos_state], 1);
            self.enc.encode_bit(&mut self.probs.is_rep[state_idx], 1);
            self.enc.encode_bit(&mut self.probs.is_rep0[state_idx], 0);
            self.enc
                .encode_bit(&mut self.probs.is_rep0_long[state_idx][pos_state], 0);

            self.state = update_short_rep(self.state);
            let byte = self.dict_get(self.rep0);
            self.out.push(byte);
            self.prev_byte = byte;
            self.pos += 1;
        }

        /// Encode a rep0 long (length bytes at most-recent
        /// distance, length in `[2, 9]`).
        fn encode_long_rep0(&mut self, len: u32) {
            let pos_state = self.pos_state();
            let state_idx = self.state as usize;

            self.enc
                .encode_bit(&mut self.probs.is_match[state_idx][pos_state], 1);
            self.enc.encode_bit(&mut self.probs.is_rep[state_idx], 1);
            self.enc.encode_bit(&mut self.probs.is_rep0[state_idx], 0);
            self.enc
                .encode_bit(&mut self.probs.is_rep0_long[state_idx][pos_state], 1);

            self.state = update_long_rep(self.state);
            self.encode_length_low(false, len, pos_state);

            // Emit bytes at rep0 distance.
            for _ in 0..len {
                let byte = self.dict_get(self.rep0);
                self.out.push(byte);
                self.prev_byte = byte;
                self.pos += 1;
            }
        }

        fn finish(self) -> (Vec<u8>, Vec<u8>) {
            let stream = self.enc.finish();
            (stream, self.out)
        }
    }

    /// Decode `stream` via `lzma_decode_port` into a fresh
    /// dict, return the produced bytes.
    fn decode_via_port(stream: &[u8], lc: u32, lp: u32, pb: u32, expected_len: usize) -> Vec<u8> {
        let mut coder = Lzma1Decoder::new();
        coder.set_properties(lc, lp, pb);
        let mut dict = LzmaDict::new(8 * 1024);
        dict.set_limit(expected_len);
        let mut in_pos: usize = 0;
        let status = lzma_decode_port(&mut coder, &mut dict, stream, &mut in_pos)
            .expect("lzma_decode_port should not error");
        assert_eq!(
            status,
            DecodeStatus::Done,
            "decode did not run to completion"
        );
        // Output is dict.buf()[..pos] in the order it was
        // written.
        // SAFETY: dict.buf() is a `&[u8]` of length `size`;
        // the first `pos` bytes are the decoded output.
        dict.buf()[..dict.pos].to_vec()
    }

    // ===== Differential tests =====

    /// Round-trip a literal-only payload.
    #[test]
    fn round_trip_pure_literals() {
        let payload: Vec<u8> = (0..32u8).collect();
        let mut enc = LzmaTestEncoder::new(3, 0, 2);
        for &b in &payload {
            enc.encode_literal(b);
        }
        let (stream, expected_out) = enc.finish();
        assert_eq!(expected_out, payload);
        let got = decode_via_port(&stream, 3, 0, 2, payload.len());
        assert_eq!(got, payload);
    }

    /// Longer literal-only payload exercises multiple
    /// rc-normalize byte pulls.
    #[test]
    fn round_trip_long_literal_run() {
        // 256 bytes of pseudo-random content.
        let mut state: u64 = 0x00C0_FFEE_DEAD_BEEF_u64;
        let payload: Vec<u8> = (0..256)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                (state >> 24) as u8
            })
            .collect();
        let mut enc = LzmaTestEncoder::new(3, 0, 2);
        for &b in &payload {
            enc.encode_literal(b);
        }
        let (stream, expected_out) = enc.finish();
        let got = decode_via_port(&stream, 3, 0, 2, payload.len());
        assert_eq!(got, expected_out);
    }

    /// Literal + fresh-distance match. Output is "AB" + 2
    /// bytes copied at distance=0 (i.e., "BB") = "ABBB".
    #[test]
    fn round_trip_literal_then_fresh_match() {
        let mut enc = LzmaTestEncoder::new(3, 0, 2);
        enc.encode_literal(b'A');
        enc.encode_literal(b'B');
        enc.encode_fresh_match(0, 2); // dist=0 (1 back), len=2 → "BB"
        let (stream, expected_out) = enc.finish();
        assert_eq!(expected_out, b"ABBB");
        let got = decode_via_port(&stream, 3, 0, 2, expected_out.len());
        assert_eq!(got, b"ABBB");
    }

    /// Rep0 short: literal + 1-byte rep at distance 0.
    /// Output is "AB" + 1 byte repeating last byte = "ABB".
    #[test]
    fn round_trip_short_rep0() {
        let mut enc = LzmaTestEncoder::new(3, 0, 2);
        enc.encode_literal(b'A');
        enc.encode_literal(b'B');
        // Need a fresh match first to set rep0 to a valid
        // distance; use dist=0, len=2 → "BB", then rep0 short
        // → "B".
        enc.encode_fresh_match(0, 2);
        enc.encode_short_rep();
        let (stream, expected_out) = enc.finish();
        assert_eq!(expected_out, b"ABBBB");
        let got = decode_via_port(&stream, 3, 0, 2, expected_out.len());
        assert_eq!(got, b"ABBBB");
    }

    /// Rep0 long: literal + multi-byte rep at most-recent
    /// distance. After "ABCD" + fresh match dist=0 len=2 →
    /// "DD", rep0 long len=3 → "DDD". Output: "ABCDDDDDD".
    #[test]
    fn round_trip_long_rep0() {
        let mut enc = LzmaTestEncoder::new(3, 0, 2);
        for &b in b"ABCD" {
            enc.encode_literal(b);
        }
        enc.encode_fresh_match(0, 2); // "DD"
        enc.encode_long_rep0(3); // "DDD"
        let (stream, expected_out) = enc.finish();
        assert_eq!(expected_out, b"ABCDDDDDD");
        let got = decode_via_port(&stream, 3, 0, 2, expected_out.len());
        assert_eq!(got, b"ABCDDDDDD");
    }

    /// Mixed literal + fresh match + literal. Exercises the
    /// matched-literal path on the post-match literal.
    #[test]
    fn round_trip_mixed_literal_match_literal() {
        let mut enc = LzmaTestEncoder::new(3, 0, 2);
        for &b in b"ABCD" {
            enc.encode_literal(b);
        }
        // Fresh match dist=2 (3 bytes back, copying 'B'),
        // len=2 → "BC". Output so far: "ABCDBC".
        enc.encode_fresh_match(2, 2);
        // Literal after a match goes through the matched-path
        // arm (state is now post-match).
        enc.encode_literal(b'E');
        let (stream, expected_out) = enc.finish();
        assert_eq!(expected_out, b"ABCDBCE");
        let got = decode_via_port(&stream, 3, 0, 2, expected_out.len());
        assert_eq!(got, b"ABCDBCE");
    }

    /// `Lzma1Decoder::new` matches the documented invariants.
    #[test]
    fn fresh_decoder_invariants() {
        let coder = Lzma1Decoder::new();
        assert_eq!(coder.rc.range, u32::MAX);
        assert_eq!(coder.rc.code, 0);
        assert_eq!(coder.rc.init_bytes_left, 5);
        assert_eq!(coder.state, LzmaState::LitLit);
        assert_eq!(coder.rep0, 0);
        assert_eq!(coder.sequence, Sequence::Normalize);
        // Spot-check that probs are at PROB_INIT_VAL.
        assert_eq!(coder.probs.literal[0][0], PROB_INIT_VAL);
        assert_eq!(coder.probs.is_match[0][0], PROB_INIT_VAL);
        assert_eq!(coder.probs.match_len_decoder.choice, PROB_INIT_VAL);
    }

    /// `set_properties` computes masks correctly for the default
    /// xz preset (`lc=3, lp=0, pb=2`).
    #[test]
    fn set_properties_default_preset() {
        let mut coder = Lzma1Decoder::new();
        coder.set_properties(3, 0, 2);
        assert_eq!(coder.literal_context_bits, 3);
        assert_eq!(coder.literal_pos_mask, 0); // (1 << 0) - 1
        assert_eq!(coder.pos_mask, 3); // (1 << 2) - 1
    }

    /// `LzmaState::is_literal_state` honors the LIT_STATES
    /// threshold.
    #[test]
    fn is_literal_state_threshold() {
        assert!(LzmaState::LitLit.is_literal_state());
        assert!(LzmaState::ShortRepLit.is_literal_state());
        assert!(!LzmaState::LitMatch.is_literal_state());
        assert!(!LzmaState::NonlitRep.is_literal_state());
    }

    /// Reset zeroes the probs after mutation.
    #[test]
    fn probs_reset_restores_init() {
        let mut probs = LzmaProbs::new();
        probs.literal[0][0] = 7;
        probs.is_match[5][3] = 42;
        probs.match_len_decoder.choice = 99;
        probs.reset();
        assert_eq!(probs.literal[0][0], PROB_INIT_VAL);
        assert_eq!(probs.is_match[5][3], PROB_INIT_VAL);
        assert_eq!(probs.match_len_decoder.choice, PROB_INIT_VAL);
    }
}
