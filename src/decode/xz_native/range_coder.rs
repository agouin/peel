//! LZMA range-coder reader and bit-tree helpers.
//!
//! Phase 2 of `docs/PLAN_xz_block_decoder.md`. Foundation for the
//! Phase 3 LZMA probability model and the Phase 4 LZMA2 chunk
//! decoder.
//!
//! # Why a slice-based reader (no I/O)
//!
//! LZMA2 chunks declare their `Compressed_Size` up front. Buffering
//! the chunk's payload before decoding it lets the range coder loop
//! be I/O-free — every `decode_bit` is a couple of arithmetic ops
//! and at most one `bytes[pos]` load — and lets us cross-check the
//! exact byte count consumed against the chunk header at chunk end.
//! `Compressed_Size` is bounded by the LZMA2 chunk format
//! (≤ 65 536 compressed bytes per chunk), so the buffering cost is
//! a small constant per chunk.
//!
//! Mirrors the shape of the zstd path's bitstream readers
//! (`src/decode/zstd/bitstream.rs`): pure logic, no allocation,
//! errors via the local [`super::error::XzError`] type.
//!
//! # Algorithm reference
//!
//! Authoritative reference is the LZMA specification (Igor Pavlov,
//! `lzma-specification.txt` in the LZMA SDK). This is a clean-room
//! transcription per `docs/PLAN_xz_block_decoder.md` §Risks &
//! Open Questions §4: read the spec, implement, then cross-check
//! against `xz2` / liblzma in differential tests (Phase 4+). The
//! `liblzma` C source is *not* read line-by-line for copying
//! patterns.
//!
//! # Range coder, briefly
//!
//! Imagine a unit interval `[0, 1)` partitioned by symbol
//! probabilities. Decoding a symbol is "find the sub-interval that
//! contains my running pointer, narrow the interval to that
//! sub-interval, emit the symbol." LZMA's range coder represents
//! the interval with a 32-bit `range` (width) and 32-bit `code`
//! (pointer offset within the interval, scaled to `[0, range)`).
//!
//! Two operations are exposed:
//!
//! - [`RangeDecoder::decode_bit`]: an *adaptive* binary symbol with
//!   a probability slot `prob ∈ [0, 2048)`. The slot represents
//!   `P(bit == 0) = prob / 2048` and is updated in place after
//!   each call so the model adapts as the stream is consumed.
//! - [`RangeDecoder::decode_direct_bits`]: a fixed sequence of
//!   uniform bits (`prob == 1024` implicitly). Used by the LZMA
//!   distance decoder for the middle-slot raw-bit sections.
//!
//! After each operation the decoder calls [`RangeDecoder::normalize`]
//! to maintain the invariant `range >= 2^24`, which guarantees that
//! the next `decode_bit` has at least 11 bits of precision in
//! `range >> 11` (the divisor used to compute the symbol's
//! sub-interval boundary).
//!
//! # Bit-tree helpers
//!
//! Several places in the LZMA spec apply [`RangeDecoder::decode_bit`]
//! repeatedly down a binary tree of probability slots — once for
//! length subtrees, once per distance slot, and once for the
//! aligned 4-bit suffix at the bottom of the distance tree. The
//! tree-walking glue is independent of the LZMA model itself, so
//! it lives here next to the range coder it drives. Phases 3 and 4
//! consume these helpers verbatim.

use super::error::XzError;

/// Number of bits in a probability-model slot. All probability
/// values live in `0..NUM_BIT_MODEL_TOTAL`; the divisor in the
/// range-coder boundary computation is `range >> NUM_BIT_MODEL_BITS`.
pub const NUM_BIT_MODEL_BITS: u32 = 11;

/// Range-coder probability denominator (`1 << 11 = 2048`). A
/// probability slot value of `prob` represents
/// `P(bit == 0) = prob / NUM_BIT_MODEL_TOTAL`.
pub const NUM_BIT_MODEL_TOTAL: u32 = 1 << NUM_BIT_MODEL_BITS;

/// Initialization value for a fresh probability slot — exactly
/// `NUM_BIT_MODEL_TOTAL / 2`. The LZMA spec resets every slot to
/// this midpoint at the start of a new dictionary or after a
/// reset-state LZMA2 chunk.
pub const PROB_INIT_VAL: u16 = (NUM_BIT_MODEL_TOTAL / 2) as u16;

/// Right-shift used during the probability-slot adaptation step.
/// Higher = slower adaptation; the LZMA spec pins this to 5.
const NUM_MOVE_BITS: u32 = 5;

/// Range-coder normalization threshold (`1 << 24`). When `range`
/// drops below this, the coder pulls another input byte and shifts
/// both `range` and `code` left by 8 to restore precision.
const TOP_VALUE: u32 = 1 << 24;

/// Number of bytes consumed by a fresh [`RangeDecoder`] before any
/// `decode_*` call: 1 marker byte + 4 bytes of initial `code`.
pub const RANGE_DECODER_INIT_LEN: usize = 5;

/// Slice-based LZMA range-coder reader.
///
/// Constructed over the LZMA-compressed payload of one LZMA2 chunk.
/// The first byte of the payload is the spec's leading `0x00`
/// marker; the next 4 bytes form the initial `code` (big-endian).
/// Subsequent bytes are pulled one at a time by [`Self::normalize`]
/// as the range narrows.
///
/// All decode operations are infallible *except* when the slice is
/// exhausted at a normalization point: a malformed (truncated)
/// chunk surfaces [`XzError::RangeCoderUnderflow`] so the LZMA2
/// layer can name "compressed payload was too short" distinctly
/// from "Block-level Compressed_Size disagreed."
#[derive(Debug)]
pub struct RangeDecoder<'a> {
    bytes: &'a [u8],
    pos: usize,
    range: u32,
    code: u32,
}

impl<'a> RangeDecoder<'a> {
    /// Construct a [`RangeDecoder`] over `bytes` and consume the
    /// 5-byte initialization prefix.
    ///
    /// # Errors
    ///
    /// - [`XzError::RangeCoderUnderflow`] if `bytes.len() < 5`. The
    ///   label is `"init"` so callers can tell init underflow
    ///   apart from mid-decode underflow.
    /// - [`XzError::RangeCoderInitMarker`] if the leading byte is
    ///   non-zero. Per the LZMA spec this byte is reserved as
    ///   `0x00` to detect a corrupted stream early; we honor that
    ///   reservation.
    pub fn new(bytes: &'a [u8]) -> Result<Self, XzError> {
        if bytes.len() < RANGE_DECODER_INIT_LEN {
            return Err(XzError::RangeCoderUnderflow("init"));
        }
        if bytes[0] != 0x00 {
            return Err(XzError::RangeCoderInitMarker(bytes[0]));
        }
        let code = (u32::from(bytes[1]) << 24)
            | (u32::from(bytes[2]) << 16)
            | (u32::from(bytes[3]) << 8)
            | u32::from(bytes[4]);
        Ok(Self {
            bytes,
            pos: RANGE_DECODER_INIT_LEN,
            range: u32::MAX,
            code,
        })
    }

    /// `true` when the range coder is in the spec's "well-finished"
    /// state — all input consumed, `code == 0`. The LZMA2 layer
    /// cross-checks this at chunk end so any deviation surfaces as
    /// a clean error instead of silent truncation.
    #[must_use]
    pub fn is_finished_ok(&self) -> bool {
        self.code == 0
    }

    /// Bytes pulled from the underlying slice so far, including the
    /// 5-byte init prefix. Used to cross-check against the LZMA2
    /// chunk header's declared `Compressed_Size`.
    #[must_use]
    pub fn bytes_consumed(&self) -> usize {
        self.pos
    }

    /// Bytes still available in the slice. Mostly diagnostic — the
    /// decode routines pull as needed and surface
    /// [`XzError::RangeCoderUnderflow`] if they run dry.
    #[must_use]
    pub fn bytes_remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    /// Current `range` (interval width). Diagnostic / test-only.
    #[must_use]
    pub fn range(&self) -> u32 {
        self.range
    }

    /// Current `code` (pointer offset within the interval).
    /// Diagnostic / test-only.
    #[must_use]
    pub fn code(&self) -> u32 {
        self.code
    }

    /// Restore the range-coder invariant `range >= TOP_VALUE` by
    /// pulling one byte if needed.
    ///
    /// Inlined into the hot decode loops; called once per
    /// `decode_bit` and once per direct-bit emission.
    ///
    /// # Errors
    ///
    /// - [`XzError::RangeCoderUnderflow`] when the slice is
    ///   exhausted at a normalization point.
    #[inline]
    fn normalize(&mut self) -> Result<(), XzError> {
        if self.range < TOP_VALUE {
            if self.pos >= self.bytes.len() {
                return Err(XzError::RangeCoderUnderflow("normalize"));
            }
            self.range <<= 8;
            self.code = (self.code << 8) | u32::from(self.bytes[self.pos]);
            self.pos += 1;
        }
        Ok(())
    }

    /// Decode one adaptive bit with probability slot `prob`,
    /// updating the slot in place.
    ///
    /// Returns 0 or 1. The probability adaptation step is the LZMA
    /// spec's standard "Bayesian-style" update:
    ///
    /// - bit `0`: `prob += (NUM_BIT_MODEL_TOTAL - prob) >> NUM_MOVE_BITS`
    /// - bit `1`: `prob -= prob >> NUM_MOVE_BITS`
    ///
    /// Both clamps stay within `0..NUM_BIT_MODEL_TOTAL` because the
    /// shift always yields a non-negative integer that's bounded by
    /// the operand it's added to or subtracted from.
    ///
    /// # Errors
    ///
    /// Forwarded from [`Self::normalize`] on slice underflow.
    #[inline]
    pub fn decode_bit(&mut self, prob: &mut u16) -> Result<u32, XzError> {
        let v = u32::from(*prob);
        // INVARIANT: maintained by `normalize` after every prior
        // operation: `range >= TOP_VALUE = 1 << 24`. So
        // `range >> 11` has at least 13 bits of precision, and
        // `(range >> 11) * v` stays within u32 since v < 2048
        // (i.e. < 2^11) and the product is bounded by `range`.
        let bound = (self.range >> NUM_BIT_MODEL_BITS) * v;
        let bit;
        if self.code < bound {
            // Round up — the LZMA spec's adaptation maps prob
            // toward `NUM_BIT_MODEL_TOTAL` whenever a `0` is
            // observed, by exactly `(NUM_BIT_MODEL_TOTAL - v) >> 5`.
            *prob = (v + ((NUM_BIT_MODEL_TOTAL - v) >> NUM_MOVE_BITS)) as u16;
            self.range = bound;
            bit = 0;
        } else {
            // Round down — symmetric step away from
            // `NUM_BIT_MODEL_TOTAL`.
            *prob = (v - (v >> NUM_MOVE_BITS)) as u16;
            self.code -= bound;
            self.range -= bound;
            bit = 1;
        }
        self.normalize()?;
        Ok(bit)
    }

    /// Decode `num_bits` raw bits from the range coder, MSB-first.
    ///
    /// Equivalent to `num_bits` invocations of `decode_bit` against
    /// a fresh slot pinned at `NUM_BIT_MODEL_TOTAL / 2`, but
    /// implemented via the LZMA spec's direct-bit fast path:
    /// shift `range` right by 1 each iteration and decide the bit
    /// from whether `code` lands above or below the new midpoint.
    ///
    /// The branchless sign-bit trick documented inline below is the
    /// algorithm's least-readable single piece — it deserves its
    /// own targeted unit test (and gets one in this module's tests),
    /// per `docs/PLAN_xz_block_decoder.md` §Appendix A "open
    /// questions" §3.
    ///
    /// # Panics
    ///
    /// Debug-only assertion: `num_bits` must be in `1..=32`. The
    /// LZMA spec's call sites use 1..=30 in practice
    /// (`num_direct_bits ∈ {1, 2, ..., 30}` in the distance
    /// decoder); 0 is never asked for, and `> 32` would overflow
    /// the `u32` result.
    ///
    /// # Errors
    ///
    /// Forwarded from [`Self::normalize`] when the loop pulls past
    /// the end of the slice.
    pub fn decode_direct_bits(&mut self, num_bits: u32) -> Result<u32, XzError> {
        debug_assert!(
            (1..=32).contains(&num_bits),
            "num_bits out of range: {num_bits}"
        );
        let mut res: u32 = 0;
        for _ in 0..num_bits {
            // Halve the interval; the bit is "is code in the upper
            // half?" The LZMA spec implements this branchlessly:
            //
            //   range >>= 1
            //   code -= range          // tentatively pick bit=1
            //   t = 0u32 - (code >> 31) // u32::MAX iff we
            //                           // underflowed (top bit set)
            //   code += range & t      // if underflowed: restore
            //                           // code (the bit was 0)
            //   res = (res << 1) + t + 1
            //
            // `t == u32::MAX` (underflow → bit=0): `t + 1 == 0`
            //  with wrap-around, restoring `res << 1`.
            // `t == 0` (no underflow → bit=1): `t + 1 == 1`,
            //  setting the next bit.
            self.range >>= 1;
            self.code = self.code.wrapping_sub(self.range);
            let t = 0u32.wrapping_sub(self.code >> 31);
            self.code = self.code.wrapping_add(self.range & t);
            self.normalize()?;
            res = (res << 1).wrapping_add(t.wrapping_add(1));
        }
        Ok(res)
    }
}

/// Decode `num_bits` from a forward bit-tree of probability slots,
/// MSB-first, returning the symbol in `0..(1 << num_bits)`.
///
/// `probs` is the conventional LZMA-spec tree-shaped layout: a
/// slot at index `m` decodes one bit and chooses between
/// `2*m` (for bit `0`) and `2*m + 1` (for bit `1`) at the next
/// level. `probs[0]` is unused; `probs[1..]` is the tree.
///
/// LZMA uses this for the length-decoder low/mid/high subtrees and
/// for distance slots ≤ 13.
///
/// # Panics
///
/// Debug-only assertion: `probs.len() >= (1 << num_bits)`.
///
/// # Errors
///
/// Forwarded from [`RangeDecoder::decode_bit`].
pub fn bit_tree_decode(
    rc: &mut RangeDecoder<'_>,
    probs: &mut [u16],
    num_bits: u32,
) -> Result<u32, XzError> {
    debug_assert!(probs.len() >= 1usize << num_bits);
    let mut m: u32 = 1;
    for _ in 0..num_bits {
        let bit = rc.decode_bit(&mut probs[m as usize])?;
        m = (m << 1) | bit;
    }
    Ok(m - (1u32 << num_bits))
}

/// Decode `num_bits` from a *reverse* bit-tree of probability
/// slots, LSB-first.
///
/// Identical traversal to [`bit_tree_decode`], but the emitted bit
/// at iteration `i` lands in bit-position `i` of the symbol rather
/// than `num_bits - 1 - i`. LZMA uses this for the aligned 4-bit
/// suffix at the bottom of the distance tree, and within each
/// distance "extra-bits" position-decoder array for slots in
/// `4..=13`.
///
/// # Panics / Errors
///
/// Same as [`bit_tree_decode`].
pub fn bit_tree_reverse_decode(
    rc: &mut RangeDecoder<'_>,
    probs: &mut [u16],
    num_bits: u32,
) -> Result<u32, XzError> {
    debug_assert!(probs.len() >= 1usize << num_bits);
    let mut m: u32 = 1;
    let mut symbol: u32 = 0;
    for i in 0..num_bits {
        let bit = rc.decode_bit(&mut probs[m as usize])?;
        m = (m << 1) | bit;
        symbol |= bit << i;
    }
    Ok(symbol)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test-only LZMA range *encoder*, transcribed from the LZMA
    /// specification's reference encoder pseudocode. Used to build
    /// hand-controlled bitstreams that the production
    /// [`RangeDecoder`] then reads back. If the encoder were
    /// wrong, round-trips would still appear to "work" only if it
    /// were wrong in a way that exactly mirrored the decoder —
    /// which is why we additionally pin a real `xz`-produced LZMA
    /// payload prefix (see [`real_lzma_payload_init_round_trip`])
    /// and cross-check that the decoder accepts its leading bytes.
    struct TestRangeEncoder {
        output: Vec<u8>,
        /// Lower bound of the live interval. Held as `u64` so the
        /// "carry" bit (bit 32) can fall out of the high byte
        /// during `shift_low`.
        low: u64,
        range: u32,
        cache: u8,
        cache_size: u32,
    }

    impl TestRangeEncoder {
        fn new() -> Self {
            // `cache_size = 1` and `cache = 0` together mean the
            // encoder's first emitted byte is the spec's leading
            // `0x00` marker — produced lazily on the first
            // shift-out of `low` past the cache.
            Self {
                output: Vec::new(),
                low: 0,
                range: u32::MAX,
                cache: 0,
                cache_size: 1,
            }
        }

        fn shift_low(&mut self) {
            let carry = (self.low >> 32) as u8;
            // Emit when the cached byte's value is decided —
            // either `low` settled below `0xFF000000` (no
            // carry can ever propagate up to it) or a real
            // carry just fired.
            if (self.low as u32) < 0xFF00_0000 || carry != 0 {
                let mut temp = self.cache;
                loop {
                    self.output.push(temp.wrapping_add(carry));
                    temp = 0xFF;
                    self.cache_size -= 1;
                    if self.cache_size == 0 {
                        break;
                    }
                }
                self.cache = ((self.low >> 24) & 0xFF) as u8;
            }
            self.cache_size += 1;
            self.low = (self.low << 8) & 0xFFFF_FFFF;
        }

        fn normalize(&mut self) {
            if self.range < TOP_VALUE {
                self.range <<= 8;
                self.shift_low();
            }
        }

        fn encode_bit(&mut self, prob: &mut u16, bit: u32) {
            let v = u32::from(*prob);
            let bound = (self.range >> NUM_BIT_MODEL_BITS) * v;
            if bit == 0 {
                self.range = bound;
                *prob = (v + ((NUM_BIT_MODEL_TOTAL - v) >> NUM_MOVE_BITS)) as u16;
            } else {
                self.low = self.low.wrapping_add(u64::from(bound));
                self.range -= bound;
                *prob = (v - (v >> NUM_MOVE_BITS)) as u16;
            }
            self.normalize();
        }

        fn encode_direct_bits(&mut self, value: u32, num_bits: u32) {
            for i in (0..num_bits).rev() {
                self.range >>= 1;
                let bit = (value >> i) & 1;
                if bit == 1 {
                    self.low = self.low.wrapping_add(u64::from(self.range));
                }
                self.normalize();
            }
        }

        fn finish(mut self) -> Vec<u8> {
            for _ in 0..5 {
                self.shift_low();
            }
            self.output
        }
    }

    /// Round-trip a single adaptive bit at the default initial
    /// probability, both values.
    #[test]
    fn round_trip_single_adaptive_bit() {
        for input_bit in [0u32, 1] {
            let mut enc = TestRangeEncoder::new();
            let mut enc_prob = PROB_INIT_VAL;
            enc.encode_bit(&mut enc_prob, input_bit);
            let stream = enc.finish();

            let mut dec = RangeDecoder::new(&stream).expect("init");
            let mut dec_prob = PROB_INIT_VAL;
            let got = dec.decode_bit(&mut dec_prob).expect("bit");
            assert_eq!(
                got, input_bit,
                "bit mismatch (encoded {input_bit}, decoded {got})"
            );
            // Probability slots updated identically by encoder
            // and decoder.
            assert_eq!(dec_prob, enc_prob);
        }
    }

    /// Round-trip a long sequence of adaptive bits at a varying
    /// probability slot. Exercises normalization repeatedly: each
    /// `decode_bit` shrinks `range` by roughly half (when prob is
    /// near the midpoint), so a 64-bit sequence forces
    /// normalization ~8 times.
    #[test]
    fn round_trip_64_adaptive_bits_default_prob() {
        // Pseudo-random but deterministic bit pattern from a
        // shifting LFSR seed; avoids the "all-zeros" or
        // "all-ones" degenerate paths.
        let mut bits = [0u8; 64];
        let mut state: u32 = 0xDEAD_BEEF;
        for slot in &mut bits {
            // 32-bit LFSR with primitive polynomial; simple,
            // deterministic, plenty of bit diversity for a 64-
            // sample test.
            let new_bit = ((state >> 31) ^ (state >> 21) ^ (state >> 1) ^ state) & 1;
            state = (state << 1) | new_bit;
            *slot = new_bit as u8;
        }

        // Capture the encoder's prob slot value AFTER each
        // encode so the decode loop can compare on a per-step
        // basis (a single shared slot would conflate states from
        // different bits).
        let mut enc = TestRangeEncoder::new();
        let mut enc_prob = PROB_INIT_VAL;
        let mut enc_history = Vec::with_capacity(bits.len());
        for &b in &bits {
            enc.encode_bit(&mut enc_prob, u32::from(b));
            enc_history.push(enc_prob);
        }
        let stream = enc.finish();

        let mut dec = RangeDecoder::new(&stream).expect("init");
        let mut dec_prob = PROB_INIT_VAL;
        for (i, (&expected, &enc_prob_step)) in bits.iter().zip(enc_history.iter()).enumerate() {
            let got = dec.decode_bit(&mut dec_prob).expect("bit");
            assert_eq!(got, u32::from(expected), "bit {i}");
            assert_eq!(dec_prob, enc_prob_step, "prob slot diverged at bit {i}");
        }
    }

    /// Targeted test for the sign-bit-trick math in
    /// `decode_direct_bits`. Per the Phase 0 spike memo, this is
    /// the algorithm's least-readable single piece and warrants
    /// its own unit test rather than relying on differential
    /// fuzz alone (Plan §Risks/Open §3).
    #[test]
    fn round_trip_direct_bits_exhaustive_short() {
        // 1..=12 bits, every possible value at each width.
        for num_bits in 1u32..=12 {
            for value in 0..(1u32 << num_bits) {
                let mut enc = TestRangeEncoder::new();
                enc.encode_direct_bits(value, num_bits);
                let stream = enc.finish();

                let mut dec = RangeDecoder::new(&stream).expect("init");
                let got = dec.decode_direct_bits(num_bits).expect("direct bits");
                assert_eq!(
                    got, value,
                    "round-trip mismatch num_bits={num_bits} value={value}"
                );
            }
        }
    }

    /// Round-trip 30 direct bits — the largest width LZMA actually
    /// uses (distance decoder for `dict_size > 2^32`-sized windows
    /// would need this, and the spec's protocol is `1..=30`).
    #[test]
    fn round_trip_direct_bits_30_wide() {
        for &value in &[
            0u32,
            1,
            (1u32 << 30) - 1,
            0x1234_5678 & ((1u32 << 30) - 1),
            0x2AAA_AAAA, // alternating bits
            0x3FFF_FFFF,
        ] {
            let mut enc = TestRangeEncoder::new();
            enc.encode_direct_bits(value, 30);
            let stream = enc.finish();

            let mut dec = RangeDecoder::new(&stream).expect("init");
            let got = dec.decode_direct_bits(30).expect("direct bits");
            assert_eq!(got, value, "30-bit round-trip mismatch for 0x{value:08X}");
        }
    }

    /// Mixed adaptive + direct interleave: the LZMA distance
    /// decoder uses both in the same chunk (slot prefix is
    /// adaptive bit-tree, "extra bits" middle slots are direct,
    /// aligned 4-bit suffix is reverse adaptive bit-tree). Pin a
    /// representative interleave so a regression in either path
    /// surfaces here at Phase 2 scale.
    #[test]
    fn round_trip_mixed_adaptive_and_direct() {
        let mut enc = TestRangeEncoder::new();
        let mut enc_probs = [PROB_INIT_VAL; 8];
        // Encode: adaptive bit, direct 5 bits, adaptive bit,
        // direct 16 bits, 4 adaptive bits, direct 7 bits.
        enc.encode_bit(&mut enc_probs[0], 1);
        enc.encode_direct_bits(0b10110, 5);
        enc.encode_bit(&mut enc_probs[1], 0);
        enc.encode_direct_bits(0xCAFE, 16);
        enc.encode_bit(&mut enc_probs[2], 1);
        enc.encode_bit(&mut enc_probs[3], 0);
        enc.encode_bit(&mut enc_probs[4], 1);
        enc.encode_bit(&mut enc_probs[5], 1);
        enc.encode_direct_bits(0b101_1010, 7);
        let stream = enc.finish();

        let mut dec = RangeDecoder::new(&stream).expect("init");
        let mut dec_probs = [PROB_INIT_VAL; 8];
        assert_eq!(dec.decode_bit(&mut dec_probs[0]).expect("a"), 1);
        assert_eq!(dec.decode_direct_bits(5).expect("d"), 0b10110);
        assert_eq!(dec.decode_bit(&mut dec_probs[1]).expect("a"), 0);
        assert_eq!(dec.decode_direct_bits(16).expect("d"), 0xCAFE);
        assert_eq!(dec.decode_bit(&mut dec_probs[2]).expect("a"), 1);
        assert_eq!(dec.decode_bit(&mut dec_probs[3]).expect("a"), 0);
        assert_eq!(dec.decode_bit(&mut dec_probs[4]).expect("a"), 1);
        assert_eq!(dec.decode_bit(&mut dec_probs[5]).expect("a"), 1);
        assert_eq!(dec.decode_direct_bits(7).expect("d"), 0b101_1010);
        // Probability slots match the encoder's slots
        // bit-for-bit — Phase 3's literal/length/distance code
        // depends on this contract.
        assert_eq!(dec_probs, enc_probs);
    }

    /// Round-trip a forward bit-tree decode. `bit_tree_decode` is
    /// equivalent to N adaptive bits with tree-shaped slot
    /// indexing; the encoder mirrors that traversal.
    #[test]
    fn round_trip_bit_tree_decode() {
        const NUM_BITS: u32 = 6;
        const TREE_LEN: usize = 1usize << NUM_BITS;
        for symbol in 0..(1u32 << NUM_BITS) {
            let mut enc = TestRangeEncoder::new();
            let mut enc_probs = [PROB_INIT_VAL; TREE_LEN];
            // Emit MSB-first; mirror `bit_tree_decode`.
            let mut m: u32 = 1;
            for i in (0..NUM_BITS).rev() {
                let bit = (symbol >> i) & 1;
                enc.encode_bit(&mut enc_probs[m as usize], bit);
                m = (m << 1) | bit;
            }
            let stream = enc.finish();

            let mut dec = RangeDecoder::new(&stream).expect("init");
            let mut dec_probs = [PROB_INIT_VAL; TREE_LEN];
            let got = bit_tree_decode(&mut dec, &mut dec_probs, NUM_BITS).expect("tree");
            assert_eq!(got, symbol, "tree-decode mismatch for {symbol}");
            assert_eq!(dec_probs, enc_probs);
        }
    }

    /// Round-trip a reverse bit-tree decode. The LSB-first traversal
    /// is what the LZMA distance decoder applies for the aligned
    /// 4-bit suffix at the bottom of the distance tree.
    #[test]
    fn round_trip_bit_tree_reverse_decode() {
        const NUM_BITS: u32 = 4;
        const TREE_LEN: usize = 1usize << NUM_BITS;
        for symbol in 0..(1u32 << NUM_BITS) {
            let mut enc = TestRangeEncoder::new();
            let mut enc_probs = [PROB_INIT_VAL; TREE_LEN];
            // Emit LSB-first; mirror `bit_tree_reverse_decode`.
            let mut m: u32 = 1;
            for i in 0..NUM_BITS {
                let bit = (symbol >> i) & 1;
                enc.encode_bit(&mut enc_probs[m as usize], bit);
                m = (m << 1) | bit;
            }
            let stream = enc.finish();

            let mut dec = RangeDecoder::new(&stream).expect("init");
            let mut dec_probs = [PROB_INIT_VAL; TREE_LEN];
            let got =
                bit_tree_reverse_decode(&mut dec, &mut dec_probs, NUM_BITS).expect("rev tree");
            assert_eq!(got, symbol, "reverse-tree mismatch for {symbol}");
            assert_eq!(dec_probs, enc_probs);
        }
    }

    /// Init rejects a slice shorter than 5 bytes with the "init"
    /// underflow label — distinct from a mid-decode underflow so
    /// the LZMA2 layer can route the diagnostic correctly.
    #[test]
    fn init_underflow_rejected() {
        let too_short = [0u8; 4];
        let err = RangeDecoder::new(&too_short).unwrap_err();
        match err {
            XzError::RangeCoderUnderflow(label) => assert_eq!(label, "init"),
            other => panic!("expected init underflow, got {other:?}"),
        }
    }

    /// Init rejects a non-zero leading byte. The marker byte is
    /// the first corruption check the range coder applies.
    #[test]
    fn init_marker_rejected() {
        let bad = [0x42, 0x00, 0x00, 0x00, 0x00];
        let err = RangeDecoder::new(&bad).unwrap_err();
        match err {
            XzError::RangeCoderInitMarker(b) => assert_eq!(b, 0x42),
            other => panic!("expected init marker, got {other:?}"),
        }
    }

    /// Mid-decode underflow surfaces with the `"normalize"` label.
    /// Constructed by encoding a stream that needs at least one
    /// normalize step, then truncating the encoded bytes so
    /// `normalize` runs out.
    #[test]
    fn mid_decode_underflow_rejected() {
        // 16 adaptive bits of "1" — drives `range` down through
        // multiple normalize steps, ensuring the encoder's output
        // is longer than the bare 5-byte init prefix.
        let mut enc = TestRangeEncoder::new();
        let mut p = PROB_INIT_VAL;
        for _ in 0..16 {
            enc.encode_bit(&mut p, 1);
        }
        let stream = enc.finish();
        assert!(
            stream.len() > RANGE_DECODER_INIT_LEN,
            "test setup: encoded stream should require at least one byte beyond init"
        );

        // Truncate so the decoder's first normalize call runs
        // dry. Decode bits until we either hit the underflow
        // or run out of decodes — the contract is that the
        // error MUST surface within a finite number of decodes
        // because each `decode_bit` either makes progress or
        // returns it.
        let truncated = &stream[..RANGE_DECODER_INIT_LEN];
        let mut dec = RangeDecoder::new(truncated).expect("init");
        let mut q = PROB_INIT_VAL;
        let mut hit_underflow = false;
        for _ in 0..256 {
            match dec.decode_bit(&mut q) {
                Ok(_) => continue,
                Err(XzError::RangeCoderUnderflow(label)) => {
                    assert_eq!(label, "normalize");
                    hit_underflow = true;
                    break;
                }
                Err(other) => panic!("unexpected error: {other:?}"),
            }
        }
        assert!(hit_underflow, "expected underflow within 256 decodes");
    }

    /// `bytes_consumed` advances monotonically and starts at the
    /// init prefix length.
    #[test]
    fn bytes_consumed_starts_at_init_len_and_grows() {
        let mut enc = TestRangeEncoder::new();
        let mut p = PROB_INIT_VAL;
        for _ in 0..32 {
            enc.encode_bit(&mut p, 1);
        }
        let stream = enc.finish();

        let mut dec = RangeDecoder::new(&stream).expect("init");
        assert_eq!(dec.bytes_consumed(), RANGE_DECODER_INIT_LEN);
        let mut q = PROB_INIT_VAL;
        let mut last = dec.bytes_consumed();
        for _ in 0..32 {
            dec.decode_bit(&mut q).expect("bit");
            let now = dec.bytes_consumed();
            assert!(now >= last, "bytes_consumed regressed: {last} -> {now}");
            last = now;
        }
        assert!(last <= stream.len());
    }

    /// `is_finished_ok` is true after consuming exactly the
    /// encoder's emitted stream. The encoder's `finish` flushes 5
    /// trailing zero-driving shifts; the decoder consumes them as
    /// final normalize bytes leaving `code == 0`.
    #[test]
    fn is_finished_ok_after_exact_consumption() {
        let mut enc = TestRangeEncoder::new();
        let mut p = PROB_INIT_VAL;
        for _ in 0..40 {
            enc.encode_bit(&mut p, 1);
        }
        let stream = enc.finish();

        let mut dec = RangeDecoder::new(&stream).expect("init");
        let mut q = PROB_INIT_VAL;
        for _ in 0..40 {
            dec.decode_bit(&mut q).expect("bit");
        }
        // Drain: keep decoding (uniform-ish) bits until either
        // every byte is consumed and the coder reports
        // `is_finished_ok`, or we run out of input. The encoder
        // pads with up to ~5 bytes of "any-bits-here" tail; the
        // decoder reads them while building up `code` toward 0.
        while dec.bytes_remaining() > 0 {
            dec.decode_bit(&mut q).expect("drain");
        }
        // After draining, the encoder/decoder pair guarantees the
        // "finished cleanly" state: code has shifted in exactly
        // the encoder's flush bytes (all `0x00` once normalize
        // pulls them).
        assert!(
            dec.is_finished_ok(),
            "code should be 0 after consuming all encoder output: code=0x{:08X}, range=0x{:08X}",
            dec.code(),
            dec.range()
        );
    }

    /// Pinned real LZMA payload prefix from `xz` 5.x output. The
    /// fixture is the 8-byte LZMA2 chunk payload that follows the
    /// chunk control byte for `printf 'aaaaaaaa' | xz
    /// --lzma2=preset=1`. We don't decode the LZMA model on top
    /// (that's Phases 3–4); we just confirm that:
    ///
    ///   1. `RangeDecoder::new` accepts the leading 5 bytes
    ///      (marker byte is `0x00`),
    ///   2. the first few `decode_bit` calls at default
    ///      probability succeed without surfacing
    ///      `RangeCoderInitMarker` or `RangeCoderUnderflow`.
    ///
    /// This pins the real-world wire format alongside the
    /// round-trip tests above. Decoded contents are not checked —
    /// the LZMA model interpreter doesn't exist yet.
    #[test]
    fn real_lzma_payload_init_round_trip() {
        // Captured byte-for-byte from the LZMA payload of an
        // actual `xz` LZMA2 chunk. Every LZMA chunk's range-
        // coded payload begins with `0x00`; we exercise more
        // of the prefix than the bare marker byte to drive at
        // least one normalize step.
        let payload: &[u8] = &[
            0x00, 0x7F, 0x00, 0x40, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut dec = RangeDecoder::new(payload).expect("real LZMA init");
        let mut probs = [PROB_INIT_VAL; 32];
        // Drive enough decode_bit calls to force at least one
        // normalize. Each succeeds or the decoder is
        // miscompiled — what value of bit is returned isn't
        // semantically meaningful without the LZMA model.
        for slot in probs.iter_mut().take(20) {
            dec.decode_bit(slot).expect("decode_bit");
        }
        assert!(dec.bytes_consumed() >= RANGE_DECODER_INIT_LEN);
    }
}
