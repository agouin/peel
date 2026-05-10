//! PPMd-II / PPMd7 range decoder.
//!
//! Bit-level entropy primitive shared by every layer of the PPMd
//! model. Round-one (`docs/PLAN_rar3.md` §B0) ships decode-only —
//! `peel` is decompression-only — with a test-only sister encoder
//! used to round-trip arbitrary symbol streams in tests.
//!
//! # Wire format
//!
//! The decoder reads from an arbitrary byte source, treating the
//! input as a sequence of 8-bit lanes. Initialisation reads
//! **5 bytes**: a leading marker byte (the LZMA SDK / 7z reference
//! emits `0x00`, and rejecting a non-zero leading byte is the
//! standard sanity check), followed by 4 big-endian bytes that
//! seed [`Self::code`].
//!
//! Two coding modes:
//!
//! - **n-ary** ([`Self::get_threshold`] + [`Self::decode`]). Used
//!   for symbols carved out of an arbitrary-sized total range.
//!   `total` partitions the unit interval into `[0, total)`; the
//!   caller learns which sub-interval `[start, start + size)` the
//!   current code falls into via `get_threshold`, then commits the
//!   decision via `decode`.
//! - **binary with adaptive probability** ([`Self::decode_bit`]).
//!   Used for escape decisions and other binary choices. The
//!   probability is an 11-bit fixed-point value the caller stores
//!   inline; the decoder updates it after each bit per the
//!   standard PPMd7 adaptation rule.
//!
//! # References
//!
//! - LZMA SDK `Ppmd7Dec.c` — the canonical PPMd7 range decoder.
//! - libarchive `archive_read_support_format_rar.c` — RAR3's
//!   integration of the same primitive.
//! - Shkarin's PPMII paper — the algorithm's original statement.

/// Threshold below which the range needs renormalisation. Equals
/// `1 << 24` per the PPMd7 reference.
const TOP_VALUE: u32 = 1 << 24;

/// Number of fractional bits in the binary-coding probability
/// state. The probability runs in `[0, BIT_MODEL_TOTAL)`; the
/// model updates it by `(kBitModelTotal - prob) >> bits` on a
/// 0-bit and `prob >> bits` on a 1-bit.
pub const BIT_MODEL_TOTAL_BITS: u32 = 11;

/// Total of the binary-coding probability range. Equals `1 << 11`
/// (`0x800`).
pub const BIT_MODEL_TOTAL: u32 = 1 << BIT_MODEL_TOTAL_BITS;

/// Errors produced by the range decoder.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum RangeDecoderError {
    /// The input ended before the decoder could read 5 init bytes
    /// or before it could refill on a normalisation step.
    #[error("PPMd-II range decoder ran out of input ({what})")]
    Truncated {
        /// Human-readable name of the field that overran.
        what: &'static str,
    },

    /// The leading marker byte was not `0x00`. Standard PPMd7
    /// streams always start with a zero; a non-zero leader is
    /// virtually always a sign of misframing (the caller fed a
    /// stream from the wrong block boundary, etc.).
    #[error("PPMd-II range decoder: leading marker byte must be 0x00, got 0x{leader:02x}")]
    BadLeader {
        /// The non-zero byte the decoder read.
        leader: u8,
    },

    /// The caller passed `total = 0` to [`RangeDecoder::get_threshold`],
    /// which would divide by zero. The PPMd model never legally
    /// emits a zero-width symbol space, so this is a programmer
    /// error in the model layer rather than a wire-format issue.
    #[error("PPMd-II range decoder: get_threshold called with total = 0")]
    ZeroTotal,
}

/// Decoder state for one PPMd-II / PPMd7 range-coded byte stream.
///
/// Owns a borrowed view into the compressed bytes so callers can
/// position the cursor (e.g. at an entry's data area) without
/// copying. The position is queryable via [`Self::position`] —
/// snapshotting the whole decoder for resume amounts to recording
/// `(range, code, position)` plus a backreference to the input.
#[derive(Debug)]
pub struct RangeDecoder<'a> {
    /// Lower bound of the currently-coded symbol's sub-interval,
    /// scaled up to the full 32-bit range. Updated on every
    /// `decode` / `decode_bit` call.
    code: u32,
    /// Width of the currently-coded sub-interval, also scaled to
    /// the 32-bit range. Halves (sometimes) on each decode and
    /// renormalises by 8 bits when it falls below [`TOP_VALUE`].
    range: u32,
    /// Borrowed input bytes. The decoder advances `pos` as it
    /// consumes them; callers can read `pos` via [`Self::position`].
    src: &'a [u8],
    /// Read offset into `src`.
    pos: usize,
}

impl<'a> RangeDecoder<'a> {
    /// Construct a decoder reading from `src`.
    ///
    /// Reads 5 bytes from `src`: the leading marker (must be
    /// `0x00`) and 4 big-endian bytes that seed [`Self::code`].
    /// Cursor is advanced past those bytes; the rest of `src` is
    /// available to subsequent decode calls.
    ///
    /// # Errors
    ///
    /// - [`RangeDecoderError::Truncated`] if `src.len() < 5`.
    /// - [`RangeDecoderError::BadLeader`] if `src[0] != 0`.
    pub fn new(src: &'a [u8]) -> Result<Self, RangeDecoderError> {
        if src.len() < 5 {
            return Err(RangeDecoderError::Truncated {
                what: "5-byte init prefix",
            });
        }
        if src[0] != 0 {
            return Err(RangeDecoderError::BadLeader { leader: src[0] });
        }
        let code = u32::from_be_bytes([src[1], src[2], src[3], src[4]]);
        Ok(Self {
            code,
            range: u32::MAX,
            src,
            pos: 5,
        })
    }

    /// Number of bytes consumed from the input so far. Includes
    /// the 5-byte init prefix.
    #[must_use]
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Total length of the input slice the decoder is reading from.
    /// Useful for callers that want to assert end-of-block.
    #[must_use]
    pub fn input_len(&self) -> usize {
        self.src.len()
    }

    /// Read one input byte, refilling the working `code` lane.
    /// Returns [`RangeDecoderError::Truncated`] if the input is
    /// exhausted; the PPMd7 reference implementation interprets
    /// end-of-stream as an infinite trailing run of zeros, but
    /// `peel`'s convention is to surface a typed error and let
    /// callers decide.
    fn read_byte(&mut self) -> Result<u8, RangeDecoderError> {
        let b = *self.src.get(self.pos).ok_or(RangeDecoderError::Truncated {
            what: "renormalisation byte",
        })?;
        self.pos += 1;
        Ok(b)
    }

    /// Renormalise: while `range` has shed enough mass that its
    /// top byte is empty, shift up by 8 bits and pull a fresh byte
    /// into `code`. Mirrors PPMd7's `RangeDec_Normalize` loop.
    fn normalize(&mut self) -> Result<(), RangeDecoderError> {
        while self.range < TOP_VALUE {
            let b = self.read_byte()?;
            self.range <<= 8;
            self.code = (self.code << 8) | u32::from(b);
        }
        Ok(())
    }

    /// Compute the threshold for an n-ary decode against a symbol
    /// space of width `total`.
    ///
    /// The caller compares the returned value against the
    /// running cumulative frequency table to identify which symbol
    /// the current `code` lands in, then commits the decision by
    /// calling [`Self::decode`] with the chosen sub-interval's
    /// `(start, size)`.
    ///
    /// **Side effect**: this call divides `range` by `total`.
    /// Mirroring the PPMd7 reference, the division must precede
    /// `decode` and a paired `decode` call is **required** before
    /// the next `get_threshold` — they form a two-step protocol.
    ///
    /// # Errors
    ///
    /// [`RangeDecoderError::ZeroTotal`] if `total == 0`.
    pub fn get_threshold(&mut self, total: u32) -> Result<u32, RangeDecoderError> {
        if total == 0 {
            return Err(RangeDecoderError::ZeroTotal);
        }
        self.range /= total;
        Ok(self.code / self.range)
    }

    /// Commit an n-ary decode for the sub-interval `[start, start + size)`.
    ///
    /// Must follow a [`Self::get_threshold`] call against the same
    /// `total`. Updates `code`, multiplies `range` by `size`, and
    /// renormalises if the working range drops below
    /// [`TOP_VALUE`].
    ///
    /// # Errors
    ///
    /// [`RangeDecoderError::Truncated`] if renormalisation needs a
    /// byte and the input is exhausted.
    pub fn decode(&mut self, start: u32, size: u32) -> Result<(), RangeDecoderError> {
        // `start * range` cannot overflow u32: the caller has just
        // computed `range = old_range / total` and must call
        // `decode` with `start + size <= total`, so
        // `start * range <= total * range = old_range <= 2^32 - 1`.
        self.code = self.code.wrapping_sub(start.wrapping_mul(self.range));
        self.range = self.range.wrapping_mul(size);
        self.normalize()
    }

    /// Decode one binary symbol against an adaptive probability.
    ///
    /// `prob` is an 11-bit fixed-point estimate of P(0) in
    /// `[0, BIT_MODEL_TOTAL)`; the decoder updates it in place per
    /// the standard PPMd7 rule (move toward the observed bit by
    /// `(kBitModelTotal - prob) >> 11` for a 0-bit and `prob >> 11`
    /// for a 1-bit).
    ///
    /// Returns `0` or `1`.
    ///
    /// # Errors
    ///
    /// [`RangeDecoderError::Truncated`] if renormalisation needs a
    /// byte and the input is exhausted.
    pub fn decode_bit(&mut self, prob: &mut u16) -> Result<u32, RangeDecoderError> {
        let bound = (self.range >> BIT_MODEL_TOTAL_BITS).wrapping_mul(u32::from(*prob));
        let bit = if self.code < bound {
            self.range = bound;
            *prob = (*prob).saturating_add(
                ((BIT_MODEL_TOTAL - u32::from(*prob)) >> BIT_MODEL_TOTAL_BITS) as u16,
            );
            0
        } else {
            self.code = self.code.wrapping_sub(bound);
            self.range = self.range.wrapping_sub(bound);
            *prob = (*prob).saturating_sub((u32::from(*prob) >> BIT_MODEL_TOTAL_BITS) as u16);
            1
        };
        self.normalize()?;
        Ok(bit)
    }
}

// ─────────────────────────────────────────────────────────────────
// Test-only sister encoder.
// ─────────────────────────────────────────────────────────────────
//
// Lives behind `#[cfg(test)]` so the production binary never links
// it. We need round-trip tests to validate the decoder against
// arbitrary symbol streams without committing reference vectors;
// the encoder is a pure mathematical inverse of the decoder and
// is small enough to keep co-located.
//
// Mirrors LZMA SDK's `Ppmd7Enc.c` API.

#[cfg(test)]
pub(crate) struct RangeEncoder {
    low: u64,
    range: u32,
    out: Vec<u8>,
    cache: u8,
    cache_size: u64,
}

#[cfg(test)]
impl RangeEncoder {
    pub fn new() -> Self {
        Self {
            low: 0,
            range: u32::MAX,
            out: Vec::new(),
            cache: 0,
            cache_size: 1,
        }
    }

    fn shift_low(&mut self) {
        if (self.low as u32) < 0xFF00_0000 || (self.low >> 32) != 0 {
            let mut temp = self.cache;
            loop {
                self.out.push(temp.wrapping_add((self.low >> 32) as u8));
                temp = 0xFF;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = ((self.low as u32) >> 24) as u8;
        }
        self.cache_size += 1;
        self.low = (self.low << 8) & 0xFFFF_FFFF;
    }

    fn normalize(&mut self) {
        while self.range < TOP_VALUE {
            self.range <<= 8;
            self.shift_low();
        }
    }

    pub fn encode(&mut self, start: u32, size: u32, total: u32) {
        self.range /= total;
        self.low = self
            .low
            .wrapping_add(u64::from(start) * u64::from(self.range));
        self.range = self.range.wrapping_mul(size);
        self.normalize();
    }

    pub fn encode_bit(&mut self, prob: &mut u16, bit: u32) {
        let bound = (self.range >> BIT_MODEL_TOTAL_BITS).wrapping_mul(u32::from(*prob));
        if bit == 0 {
            self.range = bound;
            *prob = (*prob).saturating_add(
                ((BIT_MODEL_TOTAL - u32::from(*prob)) >> BIT_MODEL_TOTAL_BITS) as u16,
            );
        } else {
            self.low = self.low.wrapping_add(u64::from(bound));
            self.range = self.range.wrapping_sub(bound);
            *prob = (*prob).saturating_sub((u32::from(*prob) >> BIT_MODEL_TOTAL_BITS) as u16);
        }
        self.normalize();
    }

    pub fn finish(mut self) -> Vec<u8> {
        for _ in 0..5 {
            self.shift_low();
        }
        // The encoder's *first* `shift_low` naturally emits the
        // initial cache (=0), which IS the leader byte the decoder
        // reads at init. Returning `self.out` verbatim keeps the
        // marker → 4-byte-code framing the decoder expects.
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a uniform 4-symbol code (each with weight 1) and
    /// verify the decoded sequence matches the input.
    #[test]
    fn round_trip_uniform_4ary() {
        let symbols: Vec<u32> = vec![0, 1, 2, 3, 0, 3, 2, 1, 0, 1, 1, 0, 3, 3, 2, 0];
        let total: u32 = 4;
        let mut enc = RangeEncoder::new();
        for &s in &symbols {
            enc.encode(s, 1, total);
        }
        let bytes = enc.finish();

        let mut dec = RangeDecoder::new(&bytes).expect("init");
        for (i, &expected) in symbols.iter().enumerate() {
            let t = dec.get_threshold(total).expect("threshold");
            assert_eq!(t, expected, "symbol {i}");
            dec.decode(t, 1).expect("commit");
        }
    }

    /// Round-trip with a heavily skewed distribution
    /// (symbol 0 weight 1000, symbol 1 weight 1) so the decoder
    /// exercises lopsided sub-intervals and frequent
    /// renormalisation.
    #[test]
    fn round_trip_skewed_binary_via_threshold() {
        let symbols: Vec<u32> = (0..200).map(|i| if i % 50 == 0 { 1 } else { 0 }).collect();
        let total: u32 = 1001;
        let mut enc = RangeEncoder::new();
        for &s in &symbols {
            if s == 0 {
                enc.encode(0, 1000, total);
            } else {
                enc.encode(1000, 1, total);
            }
        }
        let bytes = enc.finish();

        let mut dec = RangeDecoder::new(&bytes).expect("init");
        for (i, &expected) in symbols.iter().enumerate() {
            let t = dec.get_threshold(total).expect("threshold");
            let observed = if t < 1000 { 0 } else { 1 };
            assert_eq!(observed, expected, "symbol {i}: t={t}");
            if observed == 0 {
                dec.decode(0, 1000).expect("commit 0");
            } else {
                dec.decode(1000, 1).expect("commit 1");
            }
        }
    }

    /// Round-trip binary symbols with the adaptive probability
    /// path. Covers `decode_bit` end-to-end including the model
    /// update.
    #[test]
    fn round_trip_adaptive_binary() {
        let bits: Vec<u32> = vec![0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1];
        let mut prob_enc: u16 = (BIT_MODEL_TOTAL / 2) as u16;
        let mut enc = RangeEncoder::new();
        for &b in &bits {
            enc.encode_bit(&mut prob_enc, b);
        }
        let bytes = enc.finish();

        let mut prob_dec: u16 = (BIT_MODEL_TOTAL / 2) as u16;
        let mut dec = RangeDecoder::new(&bytes).expect("init");
        for (i, &expected) in bits.iter().enumerate() {
            let observed = dec.decode_bit(&mut prob_dec).expect("bit");
            assert_eq!(observed, expected, "bit {i}");
            // The encoder + decoder must walk the probability in
            // lockstep for the round-trip to work.
            assert_eq!(prob_dec, prob_enc, "prob diverged at bit {i}");
        }
    }

    /// Mixed n-ary + binary in the same stream — the model
    /// alternates between escape decisions (binary) and symbol
    /// emissions (n-ary), so the two coding modes must compose.
    #[test]
    fn round_trip_mixed_modes() {
        let mut prob_enc: u16 = (BIT_MODEL_TOTAL / 2) as u16;
        let mut enc = RangeEncoder::new();
        // Encode: bit 0, n-ary symbol 5/16, bit 1, n-ary symbol 12/16, …
        let script: Vec<(bool, u32)> = vec![
            (true, 0), // binary 0
            (false, 5),
            (true, 1),
            (false, 12),
            (false, 0),
            (true, 0),
            (false, 15),
            (true, 1),
        ];
        for &(is_bin, val) in &script {
            if is_bin {
                enc.encode_bit(&mut prob_enc, val);
            } else {
                enc.encode(val, 1, 16);
            }
        }
        let bytes = enc.finish();

        let mut prob_dec: u16 = (BIT_MODEL_TOTAL / 2) as u16;
        let mut dec = RangeDecoder::new(&bytes).expect("init");
        for (i, &(is_bin, expected)) in script.iter().enumerate() {
            if is_bin {
                let bit = dec.decode_bit(&mut prob_dec).expect("bit");
                assert_eq!(bit, expected, "step {i} (binary)");
            } else {
                let t = dec.get_threshold(16).expect("threshold");
                assert_eq!(t, expected, "step {i} (n-ary)");
                dec.decode(t, 1).expect("commit");
            }
        }
    }

    #[test]
    fn rejects_truncated_init_prefix() {
        let err = RangeDecoder::new(&[0, 1, 2, 3]).unwrap_err();
        assert!(matches!(err, RangeDecoderError::Truncated { .. }));
    }

    #[test]
    fn rejects_non_zero_leader() {
        let err = RangeDecoder::new(&[1, 0, 0, 0, 0]).unwrap_err();
        assert!(matches!(err, RangeDecoderError::BadLeader { leader: 1 }));
    }

    #[test]
    fn rejects_zero_total() {
        let mut dec = RangeDecoder::new(&[0, 0, 0, 0, 0, 0, 0]).expect("init");
        assert_eq!(
            dec.get_threshold(0).unwrap_err(),
            RangeDecoderError::ZeroTotal
        );
    }

    #[test]
    fn surfaces_truncated_renormalisation() {
        // Build a stream just long enough to init but too short to
        // sustain the renormalisation that the first n-ary decode
        // will require. After init pos=5; an n-ary decode that
        // pulls range below TOP_VALUE will need bytes 5+ which the
        // 5-byte buffer doesn't have.
        let bytes = vec![0u8, 0, 0, 0, 0];
        let mut dec = RangeDecoder::new(&bytes).expect("init");
        // Force a tiny range so renormalisation must happen.
        let _ = dec.get_threshold(0xFFFF_FFFF).expect("threshold");
        let result = dec.decode(0, 1);
        assert!(
            matches!(result, Err(RangeDecoderError::Truncated { .. })),
            "got {result:?}"
        );
    }

    /// Position reflects how many input bytes the decoder has
    /// consumed, including the 5-byte init prefix.
    #[test]
    fn position_advances_through_renormalisation() {
        let mut enc = RangeEncoder::new();
        for _ in 0..200 {
            enc.encode(7, 1, 256);
        }
        let bytes = enc.finish();
        let mut dec = RangeDecoder::new(&bytes).expect("init");
        assert_eq!(dec.position(), 5, "post-init");
        for _ in 0..200 {
            let t = dec.get_threshold(256).expect("threshold");
            assert_eq!(t, 7);
            dec.decode(t, 1).expect("commit");
        }
        assert!(dec.position() >= 5, "position monotonic non-decreasing");
        assert!(
            dec.position() <= dec.input_len(),
            "position never exceeds input length"
        );
    }
}
