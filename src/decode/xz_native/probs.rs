//! LZMA probability tables and the literal / length / distance
//! decoders that consume them.
//!
//! Phase 3 of `docs/PLAN_xz_block_decoder.md`. Sits between Phase 2
//! ([`super::range_coder`], the bitstream layer) and Phase 4 (the
//! LZMA2 chunk decoder + sliding-window dictionary). The
//! free-functions here are the inner-loop primitives Phase 4 will
//! drive — they have no opinions about the dictionary, the chunk
//! boundary, or whose state machine the symbol belongs to.
//!
//! # Probability tables, big picture
//!
//! [`LzmaProbs`] holds every probability slot the LZMA model uses
//! within a single Block: the per-context literal table, the
//! `is_match` / `is_rep*` decision trees, the position-slot trees,
//! the shared `pos_decoders` and `align_decoders` arrays, and the
//! two [`LengthProbs`] (one for fresh-distance matches, one for
//! rep matches). It is sized at construction to the Block's
//! `lc`, `lp`, `pb` properties; default xz preset (`lc=3, lp=0,
//! pb=2`) totals ~14 KiB. The spec constraint `lc + lp ≤ 4` keeps
//! the literal table from blowing up — `lc=8, lp=4` is rejected
//! at construction.
//!
//! `pos_decoders` is allocated to [`NUM_FULL_DISTANCES`] (128)
//! rather than the spec's nominal `NUM_FULL_DISTANCES -
//! END_POS_MODEL_INDEX = 114`. The looser sizing is a deliberate
//! safety margin: the Phase 2 [`super::range_coder::bit_tree_reverse_decode`]
//! reads index `1..(1 << num_direct_bits)` of its slice, so for
//! the maximum-width slot 13 (`num_direct_bits = 5`, slice offset
//! `dist_base - pos_slot = 83`) the largest absolute index is
//! `83 + 31 = 114` — one past the end of a 114-slot array. The
//! 14 extra `u16` slots (28 bytes) we waste are noise next to the
//! kilobytes the literal tables consume, and the cleaner bounds
//! make the code easier to audit.
//!
//! # Decoders
//!
//! - [`decode_literal`]: emits one decoded byte. Branches on the
//!   state machine: post-literal states use the plain bit tree;
//!   post-non-literal states walk the matched-byte tree until
//!   their bit diverges from the matched byte's, then fall through
//!   to the plain tree.
//! - [`decode_length`]: emits a match length in
//!   `MATCH_MIN_LEN..=MATCH_MAX_LEN` (`2..=273`). Used both for
//!   fresh-distance matches and for rep matches; each call site
//!   passes its own [`LengthProbs`] so the contexts evolve
//!   independently.
//! - [`decode_distance`]: emits the encoded distance value (one
//!   less than the actual back-reference offset; the LZMA chunk
//!   decoder applies the `+ 1` before consulting the dictionary).
//!   Slots 0..=3 are direct, slots 4..=13 use the shared
//!   `pos_decoders` reverse bit-tree, slots 14..=63 use a mix of
//!   direct bits and the 4-bit aligned reverse bit-tree.
//!
//! All three functions surface [`super::error::XzError`] from the
//! range coder layer; they introduce no new error variants.

use super::error::XzError;
use super::lzma_state;
use super::range_coder::{bit_tree_decode, bit_tree_reverse_decode, RangeDecoder, PROB_INIT_VAL};

/// Number of "len-state" buckets the distance decoder uses (LZMA
/// spec `kNumLenToPosStates`). For matches with length less than
/// `MATCH_MIN_LEN + NUM_LEN_TO_POS_STATES`, the bucket is `len -
/// MATCH_MIN_LEN`; longer matches all share bucket
/// `NUM_LEN_TO_POS_STATES - 1`.
pub const NUM_LEN_TO_POS_STATES: usize = 4;

/// Number of "aligned" bits the distance decoder peels off the
/// bottom of slots ≥ 14 with a shared reverse bit-tree (LZMA spec
/// `kNumAlignBits`).
pub const NUM_ALIGN_BITS: u32 = 4;

/// Size of the aligned-bit reverse bit-tree (LZMA spec
/// `kAlignTableSize = 1 << kNumAlignBits = 16`).
pub const ALIGN_TABLE_SIZE: usize = 1 << NUM_ALIGN_BITS;

/// Distance-slot threshold below which `dist == pos_slot` (LZMA
/// spec `kStartPosModelIndex = 4`).
pub const START_POS_MODEL_INDEX: u32 = 4;

/// Distance-slot threshold above which the aligned-bit reverse
/// bit-tree replaces the shared `pos_decoders` array (LZMA spec
/// `kEndPosModelIndex = 14`).
pub const END_POS_MODEL_INDEX: u32 = 14;

/// `1 << (END_POS_MODEL_INDEX / 2) = 128`. Used as the safe
/// allocation size for `pos_decoders`; see module docs for why we
/// don't shrink to the spec's nominal 114.
pub const NUM_FULL_DISTANCES: usize = 1 << (END_POS_MODEL_INDEX / 2);

/// Number of bits in the per-len-state distance-slot bit tree
/// (LZMA spec `kNumPosSlotBits = 6`).
pub const NUM_POS_SLOT_BITS: u32 = 6;

/// `1 << NUM_POS_SLOT_BITS = 64` — total leaves per distance-slot
/// tree.
pub const NUM_POS_SLOTS: usize = 1 << NUM_POS_SLOT_BITS;

/// Number of bits in the length-decoder "low" subtree.
pub const LEN_NUM_LOW_BITS: u32 = 3;

/// Symbols emitted by the "low" subtree (lengths
/// `MATCH_MIN_LEN..MATCH_MIN_LEN + 8`).
pub const LEN_NUM_LOW_SYMBOLS: usize = 1 << LEN_NUM_LOW_BITS;

/// Number of bits in the length-decoder "mid" subtree.
pub const LEN_NUM_MID_BITS: u32 = 3;

/// Symbols emitted by the "mid" subtree.
pub const LEN_NUM_MID_SYMBOLS: usize = 1 << LEN_NUM_MID_BITS;

/// Number of bits in the length-decoder "high" subtree.
pub const LEN_NUM_HIGH_BITS: u32 = 8;

/// Symbols emitted by the "high" subtree.
pub const LEN_NUM_HIGH_SYMBOLS: usize = 1 << LEN_NUM_HIGH_BITS;

/// Smallest match length the LZMA distance/length protocol can
/// represent (LZMA spec `kMatchMinLen = 2`). The length decoder
/// returns values shifted by this constant.
pub const MATCH_MIN_LEN: u32 = 2;

/// Largest match length the LZMA distance/length protocol can
/// represent — the high subtree's last symbol plus the low/mid
/// run, shifted by [`MATCH_MIN_LEN`].
pub const MATCH_MAX_LEN: u32 =
    MATCH_MIN_LEN + (LEN_NUM_LOW_SYMBOLS + LEN_NUM_MID_SYMBOLS + LEN_NUM_HIGH_SYMBOLS) as u32 - 1;

/// Spec ceiling for `lc`. Default preset uses 3.
pub const MAX_LC: u32 = 8;

/// Spec ceiling for `lp`. Default preset uses 0.
pub const MAX_LP: u32 = 4;

/// Spec ceiling for `lc + lp`. Constrains the literal table to at
/// most `(1 << 4) * 0x300 == 12 KiB`.
pub const MAX_LC_PLUS_LP: u32 = 4;

/// Spec ceiling for `pb`. Default preset uses 2.
pub const MAX_PB: u32 = 4;

/// Per-context literal probability count (LZMA spec `0x300`):
/// 256 plain-tree slots + 256 matched-bit-0 slots + 256
/// matched-bit-1 slots.
pub const LITERAL_CODER_SIZE: usize = 0x300;

/// Length-decoder probability tables.
///
/// Allocated twice in [`LzmaProbs`]: once for fresh-distance
/// matches, once for rep matches. Both contexts share the same
/// internal layout but evolve independently.
#[derive(Debug)]
pub struct LengthProbs {
    /// Choice between low (`LEN_NUM_LOW_BITS`) and mid/high.
    pub choice: u16,
    /// Choice between mid (`LEN_NUM_MID_BITS`) and high.
    pub choice2: u16,
    /// Low subtree: `[(1 << pb)][LEN_NUM_LOW_SYMBOLS]`, packed.
    pub low: Box<[u16]>,
    /// Mid subtree: `[(1 << pb)][LEN_NUM_MID_SYMBOLS]`, packed.
    pub mid: Box<[u16]>,
    /// High subtree: a single `LEN_NUM_HIGH_SYMBOLS`-leaf tree
    /// shared across pos-states.
    pub high: Box<[u16; LEN_NUM_HIGH_SYMBOLS]>,
}

impl LengthProbs {
    /// Construct length probability tables sized to the Block's
    /// `pb` (position-state bits).
    #[must_use]
    pub fn new(pb: u8) -> Self {
        let pb_states = 1usize << pb;
        Self {
            choice: PROB_INIT_VAL,
            choice2: PROB_INIT_VAL,
            low: vec![PROB_INIT_VAL; pb_states * LEN_NUM_LOW_SYMBOLS].into_boxed_slice(),
            mid: vec![PROB_INIT_VAL; pb_states * LEN_NUM_MID_SYMBOLS].into_boxed_slice(),
            high: Box::new([PROB_INIT_VAL; LEN_NUM_HIGH_SYMBOLS]),
        }
    }

    /// Reset every slot to [`PROB_INIT_VAL`]. Called when the
    /// LZMA2 chunk control byte requests a state reset
    /// (`0xC0..=0xFF`).
    pub fn reset(&mut self) {
        self.choice = PROB_INIT_VAL;
        self.choice2 = PROB_INIT_VAL;
        self.low.fill(PROB_INIT_VAL);
        self.mid.fill(PROB_INIT_VAL);
        self.high.fill(PROB_INIT_VAL);
    }
}

/// Every probability slot the LZMA model uses within one Block.
///
/// Sized to the Block's `lc`, `lp`, `pb` at construction. Lives
/// for the lifetime of the Block: the LZMA2 chunk-decoder loop
/// (Phase 4) borrows it `&mut` per chunk, with optional `reset()`
/// calls between chunks driven by the chunk's control byte.
#[derive(Debug)]
pub struct LzmaProbs {
    /// `lc` (literal-context bits, 0..=8). Controls how many high
    /// bits of the previous byte index into the literal context.
    pub lc: u8,
    /// `lp` (literal-position bits, 0..=4). Low `lp` bits of the
    /// output byte position participate in the literal-context
    /// index.
    pub lp: u8,
    /// `pb` (position-state bits, 0..=4). Low `pb` bits of the
    /// output byte position drive `is_match`, `is_rep0_long`,
    /// and the length subtrees.
    pub pb: u8,
    /// `(1 << lp) - 1`, precomputed for the literal-context
    /// formula.
    pub lp_mask: u32,
    /// `(1 << pb) - 1`, precomputed for `is_match` indexing and
    /// length-decoder pos-state selection.
    pub pb_mask: u32,

    /// `is_match[STATES * (1 << pb)]`, packed
    /// `[state * pb_states + pos_state]`.
    pub is_match: Box<[u16]>,
    /// `is_rep[STATES]` — at a non-literal symbol, distinguishes
    /// fresh-distance match from rep match.
    pub is_rep: [u16; lzma_state::STATES],
    /// `is_rep_g0[STATES]` — at a rep, distinguishes rep0 from
    /// rep1/rep2/rep3.
    pub is_rep_g0: [u16; lzma_state::STATES],
    /// `is_rep_g1[STATES]` — at a non-rep0, distinguishes rep1
    /// from rep2/rep3.
    pub is_rep_g1: [u16; lzma_state::STATES],
    /// `is_rep_g2[STATES]` — at a non-rep0/non-rep1, distinguishes
    /// rep2 from rep3.
    pub is_rep_g2: [u16; lzma_state::STATES],
    /// `is_rep0_long[STATES * (1 << pb)]` — at a rep0,
    /// distinguishes long rep0 (full-length match) from short rep0
    /// (single-byte repeat).
    pub is_rep0_long: Box<[u16]>,

    /// Distance pos-slot bit trees: `[NUM_LEN_TO_POS_STATES *
    /// NUM_POS_SLOTS]`, packed.
    pub pos_slots: Box<[u16]>,
    /// Shared reverse bit-tree probabilities for distance slots
    /// 4..=13. See module docs for the [`NUM_FULL_DISTANCES`]
    /// safety margin (vs the spec's tighter 114).
    pub pos_decoders: [u16; NUM_FULL_DISTANCES],
    /// Aligned 4-bit reverse bit-tree at the bottom of distance
    /// slots ≥ 14.
    pub align_decoders: [u16; ALIGN_TABLE_SIZE],

    /// Length probabilities for fresh-distance matches.
    pub match_len: LengthProbs,
    /// Length probabilities for rep matches.
    pub rep_len: LengthProbs,

    /// Literal probabilities: `[(1 << (lc + lp))][LITERAL_CODER_SIZE]`,
    /// packed `[lit_state * 0x300 + slot]`.
    pub literal: Box<[u16]>,
}

impl LzmaProbs {
    /// Construct probability tables sized to a Block's
    /// `(lc, lp, pb)` property triple.
    ///
    /// All slots are initialized to [`PROB_INIT_VAL`].
    ///
    /// # Errors
    ///
    /// - [`XzError::MalformedBlockHeader`] if `lc > 8` or `lp > 4`.
    /// - [`XzError::LzmaPbTooLarge`] if `pb > 4`.
    /// - [`XzError::LzmaLcLpTooLarge`] if `lc + lp > 4`. Round-one
    ///   honors the spec's hard ceiling; the literal table caps at
    ///   `(1 << 4) * 0x300 = 12 KiB` regardless of how the bits
    ///   are distributed.
    pub fn new(lc: u8, lp: u8, pb: u8) -> Result<Self, XzError> {
        if u32::from(lc) > MAX_LC {
            return Err(XzError::MalformedBlockHeader("LZMA2 lc > 8"));
        }
        if u32::from(lp) > MAX_LP {
            return Err(XzError::MalformedBlockHeader("LZMA2 lp > 4"));
        }
        if u32::from(pb) > MAX_PB {
            return Err(XzError::LzmaPbTooLarge(u32::from(pb)));
        }
        if u32::from(lc) + u32::from(lp) > MAX_LC_PLUS_LP {
            return Err(XzError::LzmaLcLpTooLarge(u32::from(lc) + u32::from(lp)));
        }

        let pb_states = 1usize << pb;
        let literal_states = 1usize << (lc + lp);

        Ok(Self {
            lc,
            lp,
            pb,
            lp_mask: (1u32 << lp) - 1,
            pb_mask: (1u32 << pb) - 1,
            is_match: vec![PROB_INIT_VAL; lzma_state::STATES * pb_states].into_boxed_slice(),
            is_rep: [PROB_INIT_VAL; lzma_state::STATES],
            is_rep_g0: [PROB_INIT_VAL; lzma_state::STATES],
            is_rep_g1: [PROB_INIT_VAL; lzma_state::STATES],
            is_rep_g2: [PROB_INIT_VAL; lzma_state::STATES],
            is_rep0_long: vec![PROB_INIT_VAL; lzma_state::STATES * pb_states].into_boxed_slice(),
            pos_slots: vec![PROB_INIT_VAL; NUM_LEN_TO_POS_STATES * NUM_POS_SLOTS]
                .into_boxed_slice(),
            pos_decoders: [PROB_INIT_VAL; NUM_FULL_DISTANCES],
            align_decoders: [PROB_INIT_VAL; ALIGN_TABLE_SIZE],
            match_len: LengthProbs::new(pb),
            rep_len: LengthProbs::new(pb),
            literal: vec![PROB_INIT_VAL; literal_states * LITERAL_CODER_SIZE].into_boxed_slice(),
        })
    }

    /// Reset every probability slot to [`PROB_INIT_VAL`].
    ///
    /// Called by the LZMA2 chunk dispatcher (Phase 4) when a chunk
    /// control byte in `0xC0..=0xFF` requests a full state reset.
    pub fn reset(&mut self) {
        self.is_match.fill(PROB_INIT_VAL);
        self.is_rep.fill(PROB_INIT_VAL);
        self.is_rep_g0.fill(PROB_INIT_VAL);
        self.is_rep_g1.fill(PROB_INIT_VAL);
        self.is_rep_g2.fill(PROB_INIT_VAL);
        self.is_rep0_long.fill(PROB_INIT_VAL);
        self.pos_slots.fill(PROB_INIT_VAL);
        self.pos_decoders.fill(PROB_INIT_VAL);
        self.align_decoders.fill(PROB_INIT_VAL);
        self.match_len.reset();
        self.rep_len.reset();
        self.literal.fill(PROB_INIT_VAL);
    }

    /// Compute the literal-context index for a byte at output
    /// position `pos`, with `prev_byte` immediately preceding.
    ///
    /// Pulled out as a method so it can be unit-tested
    /// independently and reused by Phase 4's resume-state capture
    /// path.
    #[must_use]
    pub fn literal_state_index(&self, pos: u64, prev_byte: u8) -> usize {
        let pos_low = (pos as u32) & self.lp_mask;
        let prev_high = u32::from(prev_byte) >> (8 - u32::from(self.lc));
        ((pos_low << u32::from(self.lc)) | prev_high) as usize
    }
}

/// Decode one LZMA literal byte.
///
/// `state` selects between the plain-tree path (state in
/// `0..NUM_LIT_STATES`) and the matched-byte path (state ≥
/// `NUM_LIT_STATES`). On the matched path, the decoder walks both
/// the `match_byte` (which it knows is what's at output offset
/// `-rep0 - 1`) and the literal bit-tree in lockstep until the
/// chosen bit diverges from the matched bit, then falls through
/// to the plain tree for the rest of the byte.
///
/// `prev_byte` is the byte immediately preceding the position
/// being decoded; `pos` is the absolute output byte position
/// (only the low `lp` bits matter — see
/// [`LzmaProbs::literal_state_index`]).
///
/// # Errors
///
/// Forwarded from the range coder (slice underflow).
pub fn decode_literal(
    rc: &mut RangeDecoder<'_>,
    probs: &mut LzmaProbs,
    state: u8,
    prev_byte: u8,
    pos: u64,
    match_byte: u8,
) -> Result<u8, XzError> {
    let lit_state = probs.literal_state_index(pos, prev_byte);
    let context_offset = lit_state * LITERAL_CODER_SIZE;
    // INVARIANT: `lit_state < (1 << (lc + lp))` because the
    // formula in `literal_state_index` only sets bits in the low
    // `lc + lp` positions; the literal table is sized to exactly
    // that count of contexts.
    let context = &mut probs.literal[context_offset..context_offset + LITERAL_CODER_SIZE];

    // The "symbol" cursor walks one bit at a time MSB-first; once
    // it crosses 0x100 we've decoded all 8 bits.
    let mut symbol: u32 = 1;
    if !lzma_state::is_literal_state(state) {
        // Matched path: walk the matched byte's bits in lockstep.
        let mut match_byte_cursor = u32::from(match_byte);
        loop {
            let match_bit = (match_byte_cursor >> 7) & 1;
            match_byte_cursor = (match_byte_cursor << 1) & 0xFF;
            // probs index = ((1 + match_bit) << 8) | symbol —
            // symbol ∈ [1, 0x100), so the index lands in
            // [0x100, 0x300).
            let idx = (((1 + match_bit) << 8) | symbol) as usize;
            let bit = rc.decode_bit(&mut context[idx])?;
            symbol = (symbol << 1) | bit;
            if symbol >= 0x100 {
                return Ok((symbol - 0x100) as u8);
            }
            if match_bit != bit {
                // Match diverged; rest of byte through plain tree.
                break;
            }
        }
    }
    // Plain path: index by `symbol` directly into [1, 0x100).
    while symbol < 0x100 {
        let bit = rc.decode_bit(&mut context[symbol as usize])?;
        symbol = (symbol << 1) | bit;
    }
    Ok((symbol - 0x100) as u8)
}

/// Decode one LZMA match length, returning a value in
/// `MATCH_MIN_LEN..=MATCH_MAX_LEN` (`2..=273`).
///
/// `pos_state` is the low `pb` bits of the output byte position;
/// pre-mask with [`LzmaProbs::pb_mask`] before calling.
///
/// # Errors
///
/// Forwarded from the range coder.
pub fn decode_length(
    rc: &mut RangeDecoder<'_>,
    len_probs: &mut LengthProbs,
    pos_state: u32,
) -> Result<u32, XzError> {
    if rc.decode_bit(&mut len_probs.choice)? == 0 {
        // Low: 3-bit subtree, length in [MATCH_MIN_LEN, +8).
        let off = (pos_state as usize) * LEN_NUM_LOW_SYMBOLS;
        let slice = &mut len_probs.low[off..off + LEN_NUM_LOW_SYMBOLS];
        let raw = bit_tree_decode(rc, slice, LEN_NUM_LOW_BITS)?;
        return Ok(MATCH_MIN_LEN + raw);
    }
    if rc.decode_bit(&mut len_probs.choice2)? == 0 {
        // Mid: 3-bit subtree, length in [+8, +16).
        let off = (pos_state as usize) * LEN_NUM_MID_SYMBOLS;
        let slice = &mut len_probs.mid[off..off + LEN_NUM_MID_SYMBOLS];
        let raw = bit_tree_decode(rc, slice, LEN_NUM_MID_BITS)?;
        return Ok(MATCH_MIN_LEN + LEN_NUM_LOW_SYMBOLS as u32 + raw);
    }
    // High: 8-bit subtree, length in [+16, +272).
    let raw = bit_tree_decode(rc, &mut len_probs.high[..], LEN_NUM_HIGH_BITS)?;
    Ok(MATCH_MIN_LEN + (LEN_NUM_LOW_SYMBOLS + LEN_NUM_MID_SYMBOLS) as u32 + raw)
}

/// Map a match length to its `len_state` bucket for distance
/// decoding.
///
/// Per the LZMA spec, lengths in
/// `MATCH_MIN_LEN..MATCH_MIN_LEN + NUM_LEN_TO_POS_STATES` map to
/// buckets `0..NUM_LEN_TO_POS_STATES - 1`; longer lengths all
/// share the last bucket.
#[inline]
#[must_use]
pub fn len_to_pos_state(len: u32) -> usize {
    let cap = NUM_LEN_TO_POS_STATES as u32 + MATCH_MIN_LEN;
    if len >= cap {
        NUM_LEN_TO_POS_STATES - 1
    } else {
        // INVARIANT: `len >= MATCH_MIN_LEN` per the LZMA length
        // decoder's contract; debug-asserted here so an
        // out-of-range caller surfaces in tests rather than
        // silently underflowing.
        debug_assert!(len >= MATCH_MIN_LEN, "len = {len} < MATCH_MIN_LEN");
        (len - MATCH_MIN_LEN) as usize
    }
}

/// Decode one LZMA distance value for a match of length `len`.
///
/// Returns the *encoded* distance (`0..=2^32 - 2`); the LZMA
/// chunk decoder applies the spec's `+ 1` before consulting the
/// dictionary, and the special value `u32::MAX` is reserved as the
/// LZMA stream's "end-of-payload marker."
///
/// # Errors
///
/// Forwarded from the range coder.
pub fn decode_distance(
    rc: &mut RangeDecoder<'_>,
    probs: &mut LzmaProbs,
    len: u32,
) -> Result<u32, XzError> {
    let len_state = len_to_pos_state(len);
    let slot_off = len_state * NUM_POS_SLOTS;
    let slot_slice = &mut probs.pos_slots[slot_off..slot_off + NUM_POS_SLOTS];
    let pos_slot = bit_tree_decode(rc, slot_slice, NUM_POS_SLOT_BITS)?;

    if pos_slot < START_POS_MODEL_INDEX {
        return Ok(pos_slot);
    }

    let num_direct_bits = (pos_slot >> 1) - 1;
    let mut dist = (2 | (pos_slot & 1)) << num_direct_bits;

    if pos_slot < END_POS_MODEL_INDEX {
        // Slots 4..=13: extra bits via reverse bit-tree on the
        // shared `pos_decoders` array. Slice offset is
        // `dist - pos_slot`; see module docs for the safety
        // margin on `NUM_FULL_DISTANCES` vs the spec's nominal
        // 114.
        let offset = (dist - pos_slot) as usize;
        let extra =
            bit_tree_reverse_decode(rc, &mut probs.pos_decoders[offset..], num_direct_bits)?;
        dist = dist.wrapping_add(extra);
    } else {
        // Slots 14..=63: `(num_direct_bits - 4)` raw bits, then
        // the 4-bit aligned reverse bit-tree.
        let raw = rc.decode_direct_bits(num_direct_bits - NUM_ALIGN_BITS)?;
        dist = dist.wrapping_add(raw << NUM_ALIGN_BITS);
        let aligned = bit_tree_reverse_decode(rc, &mut probs.align_decoders[..], NUM_ALIGN_BITS)?;
        dist = dist.wrapping_add(aligned);
    }
    Ok(dist)
}

#[cfg(test)]
mod tests {
    use super::super::test_support::TestRangeEncoder;
    use super::*;

    /// Default xz preset properties.
    const DEFAULT_LC: u8 = 3;
    const DEFAULT_LP: u8 = 0;
    const DEFAULT_PB: u8 = 2;

    /// Constructor accepts the spec's default preset properties.
    #[test]
    fn allocates_at_default_preset() {
        let probs = LzmaProbs::new(DEFAULT_LC, DEFAULT_LP, DEFAULT_PB).expect("default");
        let pb_states = 1usize << DEFAULT_PB;
        let lit_states = 1usize << (DEFAULT_LC + DEFAULT_LP);
        assert_eq!(probs.is_match.len(), lzma_state::STATES * pb_states);
        assert_eq!(probs.is_rep0_long.len(), lzma_state::STATES * pb_states);
        assert_eq!(probs.pos_slots.len(), NUM_LEN_TO_POS_STATES * NUM_POS_SLOTS);
        assert_eq!(probs.literal.len(), lit_states * LITERAL_CODER_SIZE);
        assert_eq!(probs.match_len.low.len(), pb_states * LEN_NUM_LOW_SYMBOLS);
        assert_eq!(probs.match_len.mid.len(), pb_states * LEN_NUM_MID_SYMBOLS);
        assert_eq!(probs.rep_len.high.len(), LEN_NUM_HIGH_SYMBOLS);
        assert_eq!(probs.lp_mask, 0);
        assert_eq!(probs.pb_mask, 3);
    }

    /// All slots initialize to `PROB_INIT_VAL`.
    #[test]
    fn fresh_probs_are_init_value() {
        let probs = LzmaProbs::new(DEFAULT_LC, DEFAULT_LP, DEFAULT_PB).expect("default");
        assert!(probs.is_match.iter().all(|&p| p == PROB_INIT_VAL));
        assert!(probs.is_rep.iter().all(|&p| p == PROB_INIT_VAL));
        assert!(probs.literal.iter().all(|&p| p == PROB_INIT_VAL));
        assert_eq!(probs.match_len.choice, PROB_INIT_VAL);
        assert!(probs.match_len.low.iter().all(|&p| p == PROB_INIT_VAL));
        assert!(probs.pos_decoders.iter().all(|&p| p == PROB_INIT_VAL));
        assert!(probs.align_decoders.iter().all(|&p| p == PROB_INIT_VAL));
    }

    /// `reset()` zeroes a model that's been mutated.
    #[test]
    fn reset_restores_init_values() {
        let mut probs = LzmaProbs::new(DEFAULT_LC, DEFAULT_LP, DEFAULT_PB).expect("default");
        probs.is_match.fill(7);
        probs.literal.fill(123);
        probs.match_len.choice = 0;
        probs.reset();
        assert!(probs.is_match.iter().all(|&p| p == PROB_INIT_VAL));
        assert!(probs.literal.iter().all(|&p| p == PROB_INIT_VAL));
        assert_eq!(probs.match_len.choice, PROB_INIT_VAL);
    }

    /// Property bounds: each cap rejected with the right error.
    #[test]
    fn rejects_out_of_range_properties() {
        match LzmaProbs::new(9, 0, 2).unwrap_err() {
            XzError::MalformedBlockHeader(_) => {}
            other => panic!("expected MalformedBlockHeader, got {other:?}"),
        }
        match LzmaProbs::new(0, 5, 2).unwrap_err() {
            XzError::MalformedBlockHeader(_) => {}
            other => panic!("expected MalformedBlockHeader, got {other:?}"),
        }
        match LzmaProbs::new(0, 0, 5).unwrap_err() {
            XzError::LzmaPbTooLarge(p) => assert_eq!(p, 5),
            other => panic!("expected LzmaPbTooLarge, got {other:?}"),
        }
        match LzmaProbs::new(3, 2, 2).unwrap_err() {
            XzError::LzmaLcLpTooLarge(s) => assert_eq!(s, 5),
            other => panic!("expected LzmaLcLpTooLarge, got {other:?}"),
        }
    }

    /// Literal-context formula matches the LZMA spec's worked
    /// example (lc=3, lp=0): the index is the high 3 bits of the
    /// previous byte.
    #[test]
    fn literal_state_index_matches_lc3_lp0() {
        let probs = LzmaProbs::new(3, 0, 2).expect("default");
        for prev in 0u32..256 {
            let idx = probs.literal_state_index(0, prev as u8);
            assert_eq!(idx, (prev >> 5) as usize);
        }
    }

    /// At `lc=2, lp=2`, the index packs `(pos_low << lc) |
    /// (prev_byte >> (8 - lc))`. Pin a few worked values.
    #[test]
    fn literal_state_index_matches_lc2_lp2() {
        let probs = LzmaProbs::new(2, 2, 0).expect("lc2/lp2");
        // pos_low = pos & 3; lit_state = (pos_low << 2) |
        // (prev >> 6).
        assert_eq!(probs.literal_state_index(0, 0xC0), 0b0011);
        assert_eq!(probs.literal_state_index(1, 0x40), (1 << 2) | 0b01);
        assert_eq!(probs.literal_state_index(3, 0xFF), (3 << 2) | 0b11);
    }

    /// `len_to_pos_state` clamps long matches into the last
    /// bucket.
    #[test]
    fn len_to_pos_state_buckets() {
        assert_eq!(len_to_pos_state(2), 0);
        assert_eq!(len_to_pos_state(3), 1);
        assert_eq!(len_to_pos_state(4), 2);
        assert_eq!(len_to_pos_state(5), 3);
        // From here on, all clamp to NUM_LEN_TO_POS_STATES - 1.
        assert_eq!(len_to_pos_state(6), 3);
        assert_eq!(len_to_pos_state(MATCH_MAX_LEN), 3);
    }

    /// Round-trip every byte through the *plain* literal path
    /// (state 0). Exercises the 8-bit MSB-first symbol walk and
    /// the per-context probability lookup.
    #[test]
    fn round_trip_plain_literal_every_byte() {
        // Use a small lc / lp combo so each per-context
        // sub-table is independently exercised.
        for byte in 0u8..=255 {
            let mut enc_probs = LzmaProbs::new(0, 0, 2).expect("lc0/lp0");
            // Encode: walk the same plain-path tree as the
            // decoder.
            let mut enc = TestRangeEncoder::new();
            encode_plain_literal(&mut enc, &mut enc_probs.literal[..], byte);
            let stream = enc.finish();

            let mut rc = RangeDecoder::new(&stream).expect("init");
            let mut dec_probs = LzmaProbs::new(0, 0, 2).expect("lc0/lp0");
            let got = decode_literal(&mut rc, &mut dec_probs, 0, 0, 0, 0).expect("lit");
            assert_eq!(got, byte, "plain literal round-trip mismatch");
        }
    }

    /// Round-trip every (matched_byte, byte) pair where they
    /// agree on the leading bit (matched path stays alive at
    /// least one iteration). Plus a "diverge immediately" case.
    #[test]
    fn round_trip_matched_literal_agreeing_and_diverging() {
        // Pin a handful of byte/match_byte pairs that exercise
        // both "match dies on bit k" for k in 0..8 and the
        // "match agrees the whole byte" terminal case.
        let cases: &[(u8, u8)] = &[
            (0b1100_0000, 0b1011_0000), // diverge at bit 6
            (0b1010_1010, 0b1010_1010), // agree all 8 bits
            (0b0000_0001, 0b1111_1111), // diverge immediately
            (0b1111_1110, 0b1111_1101), // diverge at bit 0
            (0b0101_0101, 0b1010_1010), // diverge at bit 7
        ];
        for &(byte, match_byte) in cases {
            let mut enc_probs = LzmaProbs::new(0, 0, 2).expect("lc0/lp0");
            let mut enc = TestRangeEncoder::new();
            encode_matched_literal(&mut enc, &mut enc_probs.literal[..], byte, match_byte);
            let stream = enc.finish();

            let mut rc = RangeDecoder::new(&stream).expect("init");
            let mut dec_probs = LzmaProbs::new(0, 0, 2).expect("lc0/lp0");
            // state 7 is the smallest post-non-literal state.
            let got = decode_literal(&mut rc, &mut dec_probs, 7, 0, 0, match_byte).expect("lit");
            assert_eq!(
                got, byte,
                "matched literal round-trip mismatch (byte=0x{byte:02X}, match_byte=0x{match_byte:02X})"
            );
        }
    }

    /// Round-trip every length symbol across the low / mid / high
    /// boundaries at a representative pos_state.
    #[test]
    fn round_trip_length_decoder_boundaries() {
        let pos_state: u32 = 1;
        for &len in &[
            MATCH_MIN_LEN,
            MATCH_MIN_LEN + LEN_NUM_LOW_SYMBOLS as u32 - 1, // last low
            MATCH_MIN_LEN + LEN_NUM_LOW_SYMBOLS as u32,     // first mid
            MATCH_MIN_LEN + (LEN_NUM_LOW_SYMBOLS + LEN_NUM_MID_SYMBOLS) as u32 - 1, // last mid
            MATCH_MIN_LEN + (LEN_NUM_LOW_SYMBOLS + LEN_NUM_MID_SYMBOLS) as u32, // first high
            MATCH_MAX_LEN,
        ] {
            let mut enc_lp = LengthProbs::new(2);
            let mut enc = TestRangeEncoder::new();
            encode_length(&mut enc, &mut enc_lp, pos_state, len);
            let stream = enc.finish();

            let mut rc = RangeDecoder::new(&stream).expect("init");
            let mut dec_lp = LengthProbs::new(2);
            let got = decode_length(&mut rc, &mut dec_lp, pos_state).expect("len");
            assert_eq!(got, len, "length round-trip for {len}");
        }
    }

    /// Round-trip distance values across every slot family:
    /// direct (slots 0..=3), shared `pos_decoders` (slots
    /// 4..=13), and aligned + raw-direct (slots ≥ 14).
    #[test]
    fn round_trip_distance_decoder_slot_families() {
        // (len, dist) pairs picked to exercise specific slots.
        // dist values were derived from the spec's mapping so
        // they land in known slot ranges.
        let cases: &[(u32, u32)] = &[
            (2, 0),                // slot 0
            (2, 3),                // slot 3
            (2, 4),                // slot 4 (first reverse-tree)
            (2, 5),                // slot 4 cont.
            (2, 6),                // slot 5
            (2, 95),               // slot 13 (last shared pos_decoders)
            (2, 96),               // slot 13 boundary
            (2, 127),              // slot 13 last
            (2, 128),              // slot 14 (first aligned)
            (2, 1023),             // mid slot ≥ 14
            (2, (1u32 << 30) - 1), // very large slot
            (2, u32::MAX - 1),     // top of distance range
            (10, 50),              // different len bucket
        ];
        for &(len, dist) in cases {
            let mut enc_probs = LzmaProbs::new(0, 0, 2).expect("lc0/lp0");
            let mut enc = TestRangeEncoder::new();
            encode_distance(&mut enc, &mut enc_probs, len, dist);
            let stream = enc.finish();

            let mut rc = RangeDecoder::new(&stream).expect("init");
            let mut dec_probs = LzmaProbs::new(0, 0, 2).expect("lc0/lp0");
            let got = decode_distance(&mut rc, &mut dec_probs, len).expect("dist");
            assert_eq!(
                got, dist,
                "distance round-trip for (len={len}, dist={dist})"
            );
        }
    }

    // -------- test-only encoders mirroring the production
    // decoders. Each is the smallest possible inverse of its
    // decode_* counterpart. --------

    fn encode_plain_literal(enc: &mut TestRangeEncoder, literal_table: &mut [u16], byte: u8) {
        // lc=0, lp=0 → single context, offset 0.
        let context = &mut literal_table[..LITERAL_CODER_SIZE];
        let mut symbol: u32 = 1;
        for i in (0..8).rev() {
            let bit = ((byte >> i) & 1) as u32;
            enc.encode_bit(&mut context[symbol as usize], bit);
            symbol = (symbol << 1) | bit;
        }
    }

    fn encode_matched_literal(
        enc: &mut TestRangeEncoder,
        literal_table: &mut [u16],
        byte: u8,
        match_byte: u8,
    ) {
        let context = &mut literal_table[..LITERAL_CODER_SIZE];
        let mut symbol: u32 = 1;
        let mut matched = u32::from(match_byte);
        let mut diverged = false;
        for i in (0..8).rev() {
            let bit = ((byte >> i) & 1) as u32;
            if !diverged {
                let match_bit = (matched >> 7) & 1;
                matched = (matched << 1) & 0xFF;
                let idx = (((1 + match_bit) << 8) | symbol) as usize;
                enc.encode_bit(&mut context[idx], bit);
                if match_bit != bit {
                    diverged = true;
                }
            } else {
                enc.encode_bit(&mut context[symbol as usize], bit);
            }
            symbol = (symbol << 1) | bit;
        }
    }

    fn encode_length(enc: &mut TestRangeEncoder, lp: &mut LengthProbs, pos_state: u32, len: u32) {
        debug_assert!((MATCH_MIN_LEN..=MATCH_MAX_LEN).contains(&len));
        let raw = len - MATCH_MIN_LEN;
        if raw < LEN_NUM_LOW_SYMBOLS as u32 {
            enc.encode_bit(&mut lp.choice, 0);
            let off = (pos_state as usize) * LEN_NUM_LOW_SYMBOLS;
            let slice = &mut lp.low[off..off + LEN_NUM_LOW_SYMBOLS];
            enc.encode_bit_tree(slice, LEN_NUM_LOW_BITS, raw);
        } else if raw < (LEN_NUM_LOW_SYMBOLS + LEN_NUM_MID_SYMBOLS) as u32 {
            enc.encode_bit(&mut lp.choice, 1);
            enc.encode_bit(&mut lp.choice2, 0);
            let off = (pos_state as usize) * LEN_NUM_MID_SYMBOLS;
            let slice = &mut lp.mid[off..off + LEN_NUM_MID_SYMBOLS];
            enc.encode_bit_tree(slice, LEN_NUM_MID_BITS, raw - LEN_NUM_LOW_SYMBOLS as u32);
        } else {
            enc.encode_bit(&mut lp.choice, 1);
            enc.encode_bit(&mut lp.choice2, 1);
            enc.encode_bit_tree(
                &mut lp.high[..],
                LEN_NUM_HIGH_BITS,
                raw - (LEN_NUM_LOW_SYMBOLS + LEN_NUM_MID_SYMBOLS) as u32,
            );
        }
    }

    fn encode_distance(enc: &mut TestRangeEncoder, probs: &mut LzmaProbs, len: u32, dist: u32) {
        let len_state = len_to_pos_state(len);

        // Compute pos_slot from dist. Smallest slot s such that
        // dist < base(s+1), where base(s) = (2 | (s & 1)) << ((s
        // >> 1) - 1) for s ≥ 4 and base(s) = s for s < 4.
        let pos_slot = pos_slot_for_distance(dist);
        let slot_off = len_state * NUM_POS_SLOTS;
        let slot_slice = &mut probs.pos_slots[slot_off..slot_off + NUM_POS_SLOTS];
        enc.encode_bit_tree(slot_slice, NUM_POS_SLOT_BITS, pos_slot);

        if pos_slot < START_POS_MODEL_INDEX {
            return;
        }
        let num_direct_bits = (pos_slot >> 1) - 1;
        let base = (2 | (pos_slot & 1)) << num_direct_bits;
        let extra = dist.wrapping_sub(base);
        if pos_slot < END_POS_MODEL_INDEX {
            let offset = (base - pos_slot) as usize;
            enc.encode_bit_tree_reverse(&mut probs.pos_decoders[offset..], num_direct_bits, extra);
        } else {
            let raw = extra >> NUM_ALIGN_BITS;
            let aligned = extra & ((1 << NUM_ALIGN_BITS) - 1);
            enc.encode_direct_bits(raw, num_direct_bits - NUM_ALIGN_BITS);
            enc.encode_bit_tree_reverse(&mut probs.align_decoders[..], NUM_ALIGN_BITS, aligned);
        }
    }

    /// Inverse of the spec's `pos_slot → base distance` mapping:
    /// given a raw distance, return its slot.
    fn pos_slot_for_distance(dist: u32) -> u32 {
        if dist < START_POS_MODEL_INDEX {
            return dist;
        }
        // Find n such that 2^n <= dist < 2^(n+1).
        let n = 31 - dist.leading_zeros();
        // The slot encodes the next bit below the leading 1.
        let next_bit = (dist >> (n - 1)) & 1;
        (n * 2) + next_bit
    }

    /// Pin `pos_slot_for_distance` against worked spec values.
    /// If this drifts, the distance round-trip test surfaces a
    /// confusing "wrong slot" failure; pinning it here names the
    /// helper directly.
    #[test]
    fn pos_slot_for_distance_matches_spec() {
        // (dist, slot) pairs derived from base(slot) =
        //   (2 | (slot & 1)) << ((slot >> 1) - 1).
        let cases: &[(u32, u32)] = &[
            (0, 0),
            (1, 1),
            (2, 2),
            (3, 3),
            (4, 4),
            (5, 4),
            (6, 5),
            (7, 5),
            (8, 6),
            (11, 6),
            (12, 7),
            (15, 7),
            (16, 8),
            (23, 8),
            (24, 9),
            (31, 9),
            (96, 13),
            (127, 13),
            (128, 14),
        ];
        for &(d, s) in cases {
            assert_eq!(pos_slot_for_distance(d), s, "dist={d}");
        }
    }
}
