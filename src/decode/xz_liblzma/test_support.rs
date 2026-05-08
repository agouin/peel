//! Test-only helpers shared by the `xz_liblzma` submodules.
//!
//! Compiles only under `#[cfg(test)]`. The reference LZMA range
//! *encoder* lives here so the range-coder + LZMA1-decoder
//! tests can drive synthetic streams without the .xz framing
//! layer.
//!
//! The encoder is transcribed from the LZMA specification's
//! reference encoder pseudocode (Igor Pavlov,
//! `lzma-specification.txt`, "Range Encoder" section). Producing
//! a stream the production decoder reads back is the simplest way
//! to assert byte-for-byte agreement on the spec's tricky
//! corners — sign-bit math, normalization carry, probability
//! adaptation step.

// Some helper methods (e.g. bit-tree encoders) are referenced
// only by the original `xz_native` test suite that Phase F.6
// retired. They're kept here for symmetry with the LZMA spec
// (and so future tests can pick them up), so silence the
// unused-method lint at the impl level rather than per-method.
#![allow(dead_code)]

// Constants are re-stated locally so this file doesn't depend on
// `pub`-leaking spec-internal numbers from `range_coder`. The
// values are the LZMA spec's published constants and are verified
// against the production decoder via the round-trip tests
// themselves.
const NUM_BIT_MODEL_BITS: u32 = 11;
const NUM_BIT_MODEL_TOTAL: u32 = 1 << NUM_BIT_MODEL_BITS;
const NUM_MOVE_BITS: u32 = 5;
const TOP_VALUE: u32 = 1 << 24;

/// Test-only LZMA range encoder. See module docs for rationale.
pub struct TestRangeEncoder {
    output: Vec<u8>,
    /// Lower bound of the live interval. Held as `u64` so the
    /// "carry" bit (bit 32) can fall out of the high byte during
    /// `shift_low`.
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u32,
}

impl Default for TestRangeEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl TestRangeEncoder {
    /// Construct an encoder positioned to emit the LZMA spec's
    /// leading `0x00` marker byte on the first byte-shift-out.
    pub fn new() -> Self {
        // `cache_size = 1` and `cache = 0` together mean the
        // encoder's first emitted byte is the spec's leading
        // `0x00` marker — produced lazily on the first shift-out
        // of `low` past the cache.
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
        // Emit when the cached byte's value is decided — either
        // `low` settled below `0xFF000000` (no carry can ever
        // propagate up to it) or a real carry just fired.
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

    /// Encode one adaptive bit, updating `prob` in place.
    pub fn encode_bit(&mut self, prob: &mut u16, bit: u32) {
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

    /// Encode `num_bits` MSB-first raw bits.
    pub fn encode_direct_bits(&mut self, value: u32, num_bits: u32) {
        for i in (0..num_bits).rev() {
            self.range >>= 1;
            let bit = (value >> i) & 1;
            if bit == 1 {
                self.low = self.low.wrapping_add(u64::from(self.range));
            }
            self.normalize();
        }
    }

    /// Encode `num_bits` MSB-first symbols against a forward bit-
    /// tree. Mirrors [`super::range_coder::bit_tree_decode`].
    ///
    /// `probs[0]` is unused; `probs[1..]` is the tree.
    pub fn encode_bit_tree(&mut self, probs: &mut [u16], num_bits: u32, symbol: u32) {
        debug_assert!(probs.len() >= 1usize << num_bits);
        let mut m: u32 = 1;
        for i in (0..num_bits).rev() {
            let bit = (symbol >> i) & 1;
            self.encode_bit(&mut probs[m as usize], bit);
            m = (m << 1) | bit;
        }
    }

    /// Encode `num_bits` LSB-first symbols against a reverse
    /// bit-tree. Mirrors
    /// [`super::range_coder::bit_tree_reverse_decode`].
    pub fn encode_bit_tree_reverse(&mut self, probs: &mut [u16], num_bits: u32, symbol: u32) {
        debug_assert!(probs.len() >= 1usize << num_bits);
        let mut m: u32 = 1;
        for i in 0..num_bits {
            let bit = (symbol >> i) & 1;
            self.encode_bit(&mut probs[m as usize], bit);
            m = (m << 1) | bit;
        }
    }

    /// Flush the encoder's internal buffer and return the byte
    /// stream. Matches the LZMA reference encoder's "5 trailing
    /// shift-low" tail.
    pub fn finish(mut self) -> Vec<u8> {
        for _ in 0..5 {
            self.shift_low();
        }
        self.output
    }
}
