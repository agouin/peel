//! LZMA2 chunk decoder: the LZMA inner loop driven against an
//! [`super::dict::LzmaDict`] sliding window.
//!
//! Phase 4 of `docs/PLAN_xz_block_decoder.md`. Pulls Phase 2's
//! range coder, Phase 3's literal/length/distance decoders, and
//! the new dict together to emit one LZMA chunk's worth of
//! decompressed bytes.
//!
//! # State carried across chunks
//!
//! [`Lzma2State`] owns:
//!
//! - `dict`: the sliding-window dictionary, sized by the Block
//!   Header's `dict_size`.
//! - `probs`: probability tables sized to the most recently seen
//!   `(lc, lp, pb)` triple.
//! - `state`: the LZMA 12-state machine value.
//! - `rep0..rep3`: the four most-recent encoded distances. `rep0`
//!   is also the source for the matched-literal `match_byte`
//!   lookup.
//!
//! All five mutate continuously inside one chunk; only `dict`'s
//! buffer survives a chunk-control-byte `reset_props` or
//! `reset_state` request.
//!
//! # Range coder lifetime
//!
//! Per the LZMA2 spec, range-coder state does **not** carry across
//! LZMA2 chunks: each chunk re-initializes a fresh
//! [`super::range_coder::RangeDecoder`] over its own compressed
//! payload. This is what makes per-chunk boundaries clean restart
//! points for Phase 6's resume blob — the only state Phase 6 has
//! to capture is `dict + probs + state + reps`.
//!
//! # Chunk decode contract
//!
//! [`Lzma2State::decode_chunk`] takes:
//!
//! - the buffered compressed payload (the chunk's
//!   `Compressed_Size` bytes following the chunk header),
//! - the declared `Uncompressed_Size`,
//! - a sink to write the decompressed output to.
//!
//! It runs the inner loop until `Uncompressed_Size` bytes have
//! been emitted, validates that the range coder finished cleanly
//! and consumed exactly the declared `Compressed_Size`, then
//! returns. Any deviation surfaces a typed
//! [`super::error::XzError`] variant.

use std::io::Write;

use super::check::BlockCheckHasher;
use super::dict::LzmaDict;
use super::error::XzError;
use super::lzma_state;
use super::probs::{decode_distance, decode_length, decode_literal, LzmaProbs};
use super::range_coder::RangeDecoder;

/// Initial values for the four "most recent distance" slots at
/// the start of every fresh state machine. The LZMA spec
/// initializes them to all zeroes; rep matches that fire before
/// any fresh-distance match has been observed will hit the dict's
/// "before-start" path and read 0, which is exactly correct LZMA
/// behavior.
const INIT_REPS: [u32; 4] = [0; 4];

/// The full LZMA2 model state — dict + probs + state machine +
/// reps — needed to decode subsequent chunks of one Block.
///
/// One [`Lzma2State`] lives for the lifetime of a Block. Each
/// LZMA chunk is decoded against it in place; the chunk control
/// byte may request a partial reset (`state` only), a fuller
/// reset (`state + probs`), or a full reset (`state + probs +
/// dict`) before the chunk's bytes are pulled.
#[derive(Debug)]
pub struct Lzma2State {
    /// Sliding-window dictionary.
    pub dict: LzmaDict,
    /// LZMA model probabilities. Reallocated when the chunk's
    /// `properties` byte declares a different `(lc, lp, pb)` than
    /// the current allocation.
    pub probs: LzmaProbs,
    /// LZMA 12-state machine state in `0..=11`.
    pub state: u8,
    /// Most-recent encoded distance (the "rep0"). Also the source
    /// for the matched-literal `match_byte` lookup.
    pub rep0: u32,
    /// Second-most-recent distance.
    pub rep1: u32,
    /// Third-most-recent distance.
    pub rep2: u32,
    /// Fourth-most-recent distance.
    pub rep3: u32,
}

impl Lzma2State {
    /// Construct a fresh model with the given dict size and LZMA
    /// `(lc, lp, pb)`.
    ///
    /// # Errors
    ///
    /// Forwards [`LzmaProbs::new`]'s validation errors.
    pub fn new(dict_size: u32, lc: u8, lp: u8, pb: u8) -> Result<Self, XzError> {
        Ok(Self {
            dict: LzmaDict::new(dict_size),
            probs: LzmaProbs::new(lc, lp, pb)?,
            state: lzma_state::STATE_INIT,
            rep0: INIT_REPS[0],
            rep1: INIT_REPS[1],
            rep2: INIT_REPS[2],
            rep3: INIT_REPS[3],
        })
    }

    /// Construct an [`Lzma2State`] from already-hydrated pieces.
    ///
    /// Used by Phase 6's resume path
    /// ([`super::resume::XzResumeState::build_lzma2_state`]) to
    /// reconstitute the model from a serialized blob. The
    /// caller is trusted to supply pieces that came from a prior
    /// [`super::resume::XzResumeState::capture`] of a coherent
    /// state.
    #[must_use]
    pub fn from_parts(
        dict: super::dict::LzmaDict,
        probs: LzmaProbs,
        state: u8,
        rep0: u32,
        rep1: u32,
        rep2: u32,
        rep3: u32,
    ) -> Self {
        Self {
            dict,
            probs,
            state,
            rep0,
            rep1,
            rep2,
            rep3,
        }
    }

    /// Reset the dictionary cursor + probs + state machine + reps
    /// (mode `0b11` of the LZMA chunk control byte).
    ///
    /// New `(lc, lp, pb)` are accepted — the literal-table
    /// allocation is replaced if the new triple sizes the table
    /// differently. Rep slots reset to zero so the first rep
    /// match reads from "before the start" of the fresh dict and
    /// gets the spec's 0 byte.
    ///
    /// # Errors
    ///
    /// Forwards [`LzmaProbs::new`]'s validation errors.
    pub fn full_reset(&mut self, lc: u8, lp: u8, pb: u8) -> Result<(), XzError> {
        self.dict.reset();
        self.probs = LzmaProbs::new(lc, lp, pb)?;
        self.reset_state_and_reps();
        Ok(())
    }

    /// Reset probs + state machine + reps but keep dict contents
    /// (mode `0b10` of the LZMA chunk control byte).
    ///
    /// Same `(lc, lp, pb)` semantics as [`Self::full_reset`]: the
    /// caller passes the chunk's properties byte and we
    /// re-allocate if the size changed.
    ///
    /// # Errors
    ///
    /// Forwards [`LzmaProbs::new`]'s validation errors.
    pub fn reset_props_and_state(&mut self, lc: u8, lp: u8, pb: u8) -> Result<(), XzError> {
        self.probs = LzmaProbs::new(lc, lp, pb)?;
        self.reset_state_and_reps();
        Ok(())
    }

    /// Reset state machine + reps + reinitialize the probability
    /// tables to their default values (mode `0b101` of the LZMA
    /// chunk control byte — "Reset state"). The `(lc, lp, pb)`
    /// triple stays the same (no new properties read from the
    /// chunk header), so the probs tables are reallocated at the
    /// same size and re-seeded to `PROB_INIT_VAL`. The
    /// dictionary survives untouched.
    ///
    /// Per the LZMA2 spec, "reset state" means resetting BOTH the
    /// LZMA state machine *and* the probability tables — without
    /// the latter the decoder's probs evolve from where the prior
    /// chunk ended while the encoder's were re-initialized,
    /// causing the bitstream to drift out of sync.
    pub fn reset_state(&mut self) {
        let lc = self.probs.lc;
        let lp = self.probs.lp;
        let pb = self.probs.pb;
        // INVARIANT: `(lc, lp, pb)` already passed `LzmaProbs::new`
        // when the prior chunk's reset_props (or the Block's
        // first LZMA chunk) installed them, so reallocating with
        // the same triple cannot fail.
        self.probs = LzmaProbs::new(lc, lp, pb).expect("same triple revalidates");
        self.reset_state_and_reps();
    }

    fn reset_state_and_reps(&mut self) {
        self.state = lzma_state::STATE_INIT;
        self.rep0 = INIT_REPS[0];
        self.rep1 = INIT_REPS[1];
        self.rep2 = INIT_REPS[2];
        self.rep3 = INIT_REPS[3];
    }

    /// Decode one LZMA-compressed chunk's payload, emitting
    /// `uncompressed_size` bytes to `sink`.
    ///
    /// `compressed_payload` is the chunk's compressed bytes
    /// (exactly `Compressed_Size` bytes following the chunk
    /// header). The range coder is constructed fresh over this
    /// slice; the LZMA model picks up wherever this state was
    /// before the call.
    ///
    /// # Errors
    ///
    /// - [`XzError::RangeCoderInitMarker`] /
    ///   [`XzError::RangeCoderUnderflow`] from
    ///   [`RangeDecoder::new`] / mid-decode.
    /// - [`XzError::LzmaMatchOutOfRange`] when a back-reference
    ///   distance exceeds available history.
    /// - [`XzError::LzmaLengthOverrun`] when a match length
    ///   would push past the chunk's `Uncompressed_Size`.
    /// - [`XzError::LzmaUnexpectedEos`] if the stream emits the
    ///   legacy LZMA1 EOS marker (encoded distance `u32::MAX`).
    /// - [`XzError::LzmaUncompressedSizeMismatch`] if the inner
    ///   loop's emitted byte count differs from the declared
    ///   size at chunk end.
    /// - [`XzError::LzmaRangeCoderUnfinished`] if the range
    ///   coder's `code != 0` at chunk end or if compressed bytes
    ///   remain unconsumed.
    /// - [`XzError::SinkIo`] on a sink write failure.
    pub fn decode_chunk(
        &mut self,
        compressed_payload: &[u8],
        uncompressed_size: u32,
        check_hasher: &mut BlockCheckHasher,
        sink: &mut dyn Write,
    ) -> Result<(), XzError> {
        let mut rc = RangeDecoder::new(compressed_payload)?;
        let pb_states = 1usize << self.probs.pb;
        let pb_mask = self.probs.pb_mask;

        // Per-chunk staging buffer. Chunks emit at most
        // `uncompressed_size` bytes (≤ 2 MiB by LZMA2 spec); we
        // pre-allocate so the inner loop doesn't reallocate while
        // pushing.
        let mut staging: Vec<u8> = Vec::with_capacity(uncompressed_size as usize);

        // Cache of the last-pushed byte. Phase 2 of
        // `docs/PLAN_xz_decoder_optimization.md`: this avoids the
        // `byte_at(0)` call at the top of every literal iteration —
        // the value is already in scope from the prior `push`. The
        // initial value matches the LZMA spec's "before-start"
        // convention (`byte_at(0)` on an empty dict returns 0). For
        // chunks that resume mid-Block (the dict is non-empty), we
        // re-read it once before entering the loop.
        let mut prev_byte: u8 = if self.dict.is_empty() {
            0
        } else {
            self.dict.byte_at(0)
        };

        let mut produced: u32 = 0;
        while produced < uncompressed_size {
            let pos = self.dict.total();
            let pos_state = (pos as u32) & pb_mask;
            let state_pos_idx = (self.state as usize) * pb_states + (pos_state as usize);

            if rc.decode_bit(&mut self.probs.is_match[state_pos_idx])? == 0 {
                // ===== Literal =====
                let match_byte = if lzma_state::is_literal_state(self.state) {
                    0 // unused on the plain path
                } else {
                    self.dict.byte_at(self.rep0)
                };
                let b = decode_literal(
                    &mut rc,
                    &mut self.probs,
                    self.state,
                    prev_byte,
                    pos,
                    match_byte,
                )?;
                self.dict.push(b);
                staging.push(b);
                prev_byte = b;
                self.state = lzma_state::after_literal(self.state);
                produced += 1;
                continue;
            }

            // ===== Non-literal =====
            let len: u32;
            if rc.decode_bit(&mut self.probs.is_rep[self.state as usize])? == 0 {
                // Fresh-distance match.
                self.rep3 = self.rep2;
                self.rep2 = self.rep1;
                self.rep1 = self.rep0;
                len = decode_length(&mut rc, &mut self.probs.match_len, pos_state)?;
                self.rep0 = decode_distance(&mut rc, &mut self.probs, len)?;
                if self.rep0 == u32::MAX {
                    // LZMA1 EOS marker — never legal inside an
                    // LZMA2 chunk (LZMA2 carries explicit chunk
                    // sizes).
                    return Err(XzError::LzmaUnexpectedEos);
                }
                self.state = lzma_state::after_match(self.state);
            } else if rc.decode_bit(&mut self.probs.is_rep_g0[self.state as usize])? == 0 {
                // rep0 family: either short-rep0 (single byte) or
                // long-rep0 match.
                if rc.decode_bit(&mut self.probs.is_rep0_long[state_pos_idx])? == 0 {
                    // Short rep0: emit one byte at `rep0`
                    // distance; no length decoder.
                    if u64::from(self.rep0) + 1 > self.dict.total() {
                        return Err(XzError::LzmaMatchOutOfRange {
                            dist: self.rep0,
                            total: self.dict.total(),
                        });
                    }
                    let b = self.dict.byte_at(self.rep0);
                    self.dict.push(b);
                    staging.push(b);
                    prev_byte = b;
                    self.state = lzma_state::after_short_rep(self.state);
                    produced += 1;
                    continue;
                }
                // Long rep0: rep0 unchanged, decode rep_len.
                len = decode_length(&mut rc, &mut self.probs.rep_len, pos_state)?;
                self.state = lzma_state::after_rep(self.state);
            } else {
                // rep1/rep2/rep3.
                let new_rep0;
                if rc.decode_bit(&mut self.probs.is_rep_g1[self.state as usize])? == 0 {
                    new_rep0 = self.rep1;
                } else if rc.decode_bit(&mut self.probs.is_rep_g2[self.state as usize])? == 0 {
                    new_rep0 = self.rep2;
                    self.rep2 = self.rep1;
                } else {
                    new_rep0 = self.rep3;
                    self.rep3 = self.rep2;
                    self.rep2 = self.rep1;
                }
                self.rep1 = self.rep0;
                self.rep0 = new_rep0;
                len = decode_length(&mut rc, &mut self.probs.rep_len, pos_state)?;
                self.state = lzma_state::after_rep(self.state);
            }

            // Common path for all match-shaped emissions: copy
            // `len` bytes at `rep0 + 1` distance into the dict
            // and the staging buffer.
            if produced + len > uncompressed_size {
                return Err(XzError::LzmaLengthOverrun);
            }
            self.dict.match_copy(self.rep0, len, &mut staging)?;
            produced += len;
            // INVARIANT: `match_copy` pushed `len > 0` bytes; the
            // last one is now at `byte_at(0)`. We can read it from
            // the staging tail to avoid touching the dict ring.
            prev_byte = staging[staging.len() - 1];
        }

        // Per the spec: the range coder must be in the
        // "well-finished" state and we must have consumed exactly
        // `compressed_payload.len()` bytes.
        if !rc.is_finished_ok() || rc.bytes_consumed() != compressed_payload.len() {
            return Err(XzError::LzmaRangeCoderUnfinished {
                code: rc.code(),
                leftover: compressed_payload.len() - rc.bytes_consumed(),
            });
        }
        if produced != uncompressed_size {
            return Err(XzError::LzmaUncompressedSizeMismatch {
                produced,
                expected: uncompressed_size,
            });
        }

        check_hasher.update(&staging);
        sink.write_all(&staging).map_err(XzError::SinkIo)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::block::decode_lzma_properties;
    use super::super::probs::{len_to_pos_state, LengthProbs, LITERAL_CODER_SIZE, NUM_POS_SLOTS};
    use super::super::test_support::TestRangeEncoder;
    use super::*;

    /// Default xz preset.
    const LC: u8 = 3;
    const LP: u8 = 0;
    const PB: u8 = 2;
    const DICT_SIZE: u32 = 64 * 1024;

    /// Build the compressed bytes of an LZMA-only chunk emitting
    /// `payload_bytes` as N consecutive literals through the
    /// LZMA encoder. Uses fresh probs that mirror the production
    /// `Lzma2State::decode_chunk`. Returns the bytes that go on
    /// the wire after the chunk header.
    fn encode_literal_run(payload: &[u8], lc: u8, lp: u8, pb: u8) -> Vec<u8> {
        let mut probs = LzmaProbs::new(lc, lp, pb).expect("alloc");
        let mut enc = TestRangeEncoder::new();
        let pb_states = 1usize << pb;
        let pb_mask = (1u32 << pb) - 1;
        let mut state = lzma_state::STATE_INIT;
        let mut prev_byte: u8 = 0;
        for (i, &b) in payload.iter().enumerate() {
            let pos = i as u64;
            let pos_state = (pos as u32) & pb_mask;
            let state_pos = (state as usize) * pb_states + (pos_state as usize);
            // is_match = 0 (literal).
            enc.encode_bit(&mut probs.is_match[state_pos], 0);
            // Plain-path literal encoding.
            let lit_state = probs.literal_state_index(pos, prev_byte);
            let context_off = lit_state * LITERAL_CODER_SIZE;
            let context = &mut probs.literal[context_off..context_off + LITERAL_CODER_SIZE];
            let mut symbol: u32 = 1;
            for k in (0..8u32).rev() {
                let bit = u32::from((b >> k) & 1);
                enc.encode_bit(&mut context[symbol as usize], bit);
                symbol = (symbol << 1) | bit;
            }
            state = lzma_state::after_literal(state);
            prev_byte = b;
        }
        enc.finish()
    }

    /// Sanity: an LZMA chunk that encodes only literals decodes
    /// back to the original payload.
    #[test]
    fn round_trip_pure_literals() {
        let payload: Vec<u8> = (0..256u32).map(|i| (i & 0xFF) as u8).collect::<Vec<_>>();
        let stream = encode_literal_run(&payload, LC, LP, PB);

        let mut state = Lzma2State::new(DICT_SIZE, LC, LP, PB).expect("state");
        let mut sink = Vec::new();
        state
            .decode_chunk(
                &stream,
                payload.len() as u32,
                &mut BlockCheckHasher::new(super::super::stream::CheckId::None),
                &mut sink,
            )
            .expect("decode");
        assert_eq!(sink, payload);
        // After decode, dict reflects every emitted byte.
        assert_eq!(state.dict.total(), payload.len() as u64);
        // The state machine should have walked through literal
        // states and parked in one of the post-literal states
        // (0..=6).
        assert!(state.state < lzma_state::NUM_LIT_STATES);
    }

    /// A literal followed by a fresh-distance match round-trips
    /// the emitted bytes byte-identically. Pin: encoder emits
    /// "AB" as literals then a `dist=0, len=2` match (encoded
    /// distance 0 means actual distance 1, i.e. copy the last
    /// byte twice). Output should be "ABBB".
    #[test]
    fn round_trip_literal_then_fresh_match() {
        let mut probs = LzmaProbs::new(LC, LP, PB).expect("alloc");
        let mut enc = TestRangeEncoder::new();
        let pb_states = 1usize << PB;
        let pb_mask = (1u32 << PB) - 1;
        let mut state = lzma_state::STATE_INIT;

        // Two literals.
        let payload_lits = b"AB";
        let mut prev_byte: u8 = 0;
        for (i, &b) in payload_lits.iter().enumerate() {
            let pos = i as u64;
            let pos_state = (pos as u32) & pb_mask;
            let state_pos = (state as usize) * pb_states + (pos_state as usize);
            enc.encode_bit(&mut probs.is_match[state_pos], 0);
            let lit_state = probs.literal_state_index(pos, prev_byte);
            let context_off = lit_state * LITERAL_CODER_SIZE;
            let context = &mut probs.literal[context_off..context_off + LITERAL_CODER_SIZE];
            let mut symbol: u32 = 1;
            for k in (0..8u32).rev() {
                let bit = u32::from((b >> k) & 1);
                enc.encode_bit(&mut context[symbol as usize], bit);
                symbol = (symbol << 1) | bit;
            }
            state = lzma_state::after_literal(state);
            prev_byte = b;
        }

        // Fresh-distance match: dist=0, len=2 → expand to "BB".
        // After "AB", dict cursor is at position 2; copying from
        // "B" twice yields "BB". Final output: "ABBB".
        let pos = 2u64;
        let pos_state = (pos as u32) & pb_mask;
        let state_pos = (state as usize) * pb_states + (pos_state as usize);
        // is_match = 1 (non-literal).
        enc.encode_bit(&mut probs.is_match[state_pos], 1);
        // is_rep = 0 (fresh distance).
        enc.encode_bit(&mut probs.is_rep[state as usize], 0);
        // length = 2 → low subtree, raw=0.
        encode_length_helper(&mut enc, &mut probs.match_len, pos_state, 2);
        // distance = 0 → slot 0, no extra bits.
        encode_distance_slot_only(&mut enc, &mut probs, len_to_pos_state(2), 0);

        let stream = enc.finish();
        let mut decoder_state = Lzma2State::new(DICT_SIZE, LC, LP, PB).expect("state");
        let mut sink = Vec::new();
        decoder_state
            .decode_chunk(
                &stream,
                4,
                &mut BlockCheckHasher::new(super::super::stream::CheckId::None),
                &mut sink,
            )
            .expect("decode");
        assert_eq!(sink, b"ABBB");
        assert_eq!(decoder_state.rep0, 0);
    }

    fn encode_length_helper(
        enc: &mut TestRangeEncoder,
        lp: &mut LengthProbs,
        pos_state: u32,
        len: u32,
    ) {
        // Mirror probs::decode_length / encode_length.
        use super::super::probs::{
            LEN_NUM_HIGH_BITS, LEN_NUM_LOW_BITS, LEN_NUM_LOW_SYMBOLS, LEN_NUM_MID_BITS,
            LEN_NUM_MID_SYMBOLS, MATCH_MIN_LEN,
        };
        let raw = len - MATCH_MIN_LEN;
        if raw < LEN_NUM_LOW_SYMBOLS as u32 {
            enc.encode_bit(&mut lp.choice, 0);
            let off = (pos_state as usize) * LEN_NUM_LOW_SYMBOLS;
            enc.encode_bit_tree(
                &mut lp.low[off..off + LEN_NUM_LOW_SYMBOLS],
                LEN_NUM_LOW_BITS,
                raw,
            );
        } else if raw < (LEN_NUM_LOW_SYMBOLS + LEN_NUM_MID_SYMBOLS) as u32 {
            enc.encode_bit(&mut lp.choice, 1);
            enc.encode_bit(&mut lp.choice2, 0);
            let off = (pos_state as usize) * LEN_NUM_MID_SYMBOLS;
            enc.encode_bit_tree(
                &mut lp.mid[off..off + LEN_NUM_MID_SYMBOLS],
                LEN_NUM_MID_BITS,
                raw - LEN_NUM_LOW_SYMBOLS as u32,
            );
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

    fn encode_distance_slot_only(
        enc: &mut TestRangeEncoder,
        probs: &mut LzmaProbs,
        len_state: usize,
        dist: u32,
    ) {
        // For dist < START_POS_MODEL_INDEX (4), the slot IS the
        // distance and there are no extra bits.
        use super::super::probs::{NUM_POS_SLOT_BITS, START_POS_MODEL_INDEX};
        debug_assert!(
            dist < START_POS_MODEL_INDEX,
            "use full encoder for dist >= 4"
        );
        let slot_off = len_state * NUM_POS_SLOTS;
        enc.encode_bit_tree(
            &mut probs.pos_slots[slot_off..slot_off + NUM_POS_SLOTS],
            NUM_POS_SLOT_BITS,
            dist,
        );
    }

    /// Long literal run that exercises the "every byte produces a
    /// state-machine transition" path. Encodes 256 ascending
    /// bytes at preset (lc=3, lp=0, pb=2) and round-trips.
    #[test]
    fn round_trip_long_literal_run_at_default_preset() {
        let payload: Vec<u8> = (0..=255u8).collect();
        let stream = encode_literal_run(&payload, 3, 0, 2);

        let mut state = Lzma2State::new(DICT_SIZE, 3, 0, 2).expect("state");
        let mut sink = Vec::new();
        state
            .decode_chunk(
                &stream,
                payload.len() as u32,
                &mut BlockCheckHasher::new(super::super::stream::CheckId::None),
                &mut sink,
            )
            .expect("decode");
        assert_eq!(sink, payload);
    }

    /// LZMA spec: the first chunk's properties byte 0x5D decodes
    /// to `(lc=3, lp=0, pb=2)`. Pin against the helper Phase 4
    /// drives.
    #[test]
    fn default_preset_properties_byte() {
        assert_eq!(decode_lzma_properties(0x5D).expect("default"), (3, 0, 2));
    }

    /// Reset semantics: `full_reset` clears dict + state + probs.
    #[test]
    fn full_reset_clears_dict_and_state() {
        let mut state = Lzma2State::new(DICT_SIZE, LC, LP, PB).expect("state");
        state.dict.push(b'A');
        state.state = 7;
        state.rep0 = 42;
        state.full_reset(LC, LP, PB).expect("reset");
        assert!(state.dict.is_empty());
        assert_eq!(state.state, lzma_state::STATE_INIT);
        assert_eq!(state.rep0, 0);
    }

    /// `reset_state` keeps dict but zeros state and reps.
    #[test]
    fn reset_state_keeps_dict() {
        let mut state = Lzma2State::new(DICT_SIZE, LC, LP, PB).expect("state");
        state.dict.push(b'A');
        state.dict.push(b'B');
        state.state = 7;
        state.rep0 = 5;
        state.reset_state();
        assert_eq!(state.dict.total(), 2);
        assert_eq!(state.state, lzma_state::STATE_INIT);
        assert_eq!(state.rep0, 0);
    }

    /// Truncated compressed payload surfaces a typed underflow
    /// rather than panicking.
    #[test]
    fn truncated_compressed_payload_is_typed_error() {
        // Init prefix is 5 bytes; one byte of a 5-byte init slice
        // is too short. Any chunk decode call should fail.
        let too_short = [0u8; 3];
        let mut state = Lzma2State::new(DICT_SIZE, LC, LP, PB).expect("state");
        let mut sink = Vec::new();
        match state
            .decode_chunk(
                &too_short,
                1,
                &mut BlockCheckHasher::new(super::super::stream::CheckId::None),
                &mut sink,
            )
            .unwrap_err()
        {
            XzError::RangeCoderUnderflow(label) => assert_eq!(label, "init"),
            other => panic!("expected RangeCoderUnderflow, got {other:?}"),
        }
    }

    /// A chunk whose declared `Uncompressed_Size` differs from
    /// what the LZMA model emits surfaces a typed mismatch.
    /// Construct: encode 4 literals but tell the decoder to
    /// expect 8 — the inner loop runs out of compressed input
    /// before reaching 8 bytes and surfaces `RangeCoderUnderflow`
    /// rather than producing incorrect bytes.
    #[test]
    fn uncompressed_size_overrun_surfaces_typed_error() {
        let stream = encode_literal_run(b"ABCD", LC, LP, PB);
        let mut state = Lzma2State::new(DICT_SIZE, LC, LP, PB).expect("state");
        let mut sink = Vec::new();
        match state
            .decode_chunk(
                &stream,
                8,
                &mut BlockCheckHasher::new(super::super::stream::CheckId::None),
                &mut sink,
            )
            .unwrap_err()
        {
            XzError::RangeCoderUnderflow(_) | XzError::LzmaUncompressedSizeMismatch { .. } => {}
            other => panic!("expected typed error, got {other:?}"),
        }
    }
}
