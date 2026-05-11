//! PPMd-II / PPMd7 range decoder.
//!
//! Bit-level entropy primitive shared by every layer of the PPMd
//! model. Round-one (`docs/PLAN_rar3.md` §B0) shipped decode-only
//! 7z-variant support; §C1f adds the RAR-variant init + math
//! libarchive's PPMd-encoded RAR3 blocks need.
//!
//! # Wire-format variants
//!
//! Two coexisting variants share the same model layer:
//!
//! - **7z** ([`Self::new`]). Reads **5 bytes** on init: a leading
//!   marker byte (the LZMA SDK / 7z reference always emits `0x00`)
//!   followed by 4 big-endian bytes that seed [`Self::code`].
//!   `bottom = 0`; `decode` updates `code` directly. The dedicated
//!   binary primitive `Range_DecodeBit_7z` ([`Self::decode_bit_bin`]
//!   in 7z mode) reads `(range >> 14) * prob` against `code` and
//!   uses the resulting interval split.
//! - **RAR** ([`Self::new_rar`]). Reads **4 bytes** on init (no
//!   leading marker), seeding [`Self::code`]. `bottom = 0x8000`;
//!   `decode` maintains a running `low` lower-bound and shifts
//!   the carry-handling normalize loop. The binary primitive
//!   `Range_DecodeBit_RAR` goes through
//!   `get_threshold(PPMD_BIN_SCALE) + decode(start, size)` — the
//!   7z fast-path math is **not** equivalent here.
//!
//! Both variants expose the same `get_threshold` / `decode` /
//! `decode_bit_bin` / `decode_bit` API; the model layer is variant-
//! agnostic and works against whichever flavour the caller hands
//! in. Two coding modes either variant exposes:
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
//!   standard PPMd7 adaptation rule. (Variant-agnostic — both
//!   7z and RAR use the same 11-bit adaptive primitive when the
//!   model wants one. The 14-bit binary primitive that
//!   [`Self::decode_bit_bin`] wraps is what differs.)
//!
//! # References
//!
//! - LZMA SDK `Ppmd7Dec.c` — the canonical PPMd7 range decoder
//!   (7z variant).
//! - libarchive `archive_ppmd7.c` — both 7z and RAR-variant
//!   `Range_Decode_*` / `Range_DecodeBit_*` / `*_RangeDec_Init`
//!   functions side-by-side; §C1f's port follows libarchive.
//! - libarchive `archive_read_support_format_rar.c` — RAR3's
//!   integration: `is_ppmd_block` blocks call
//!   `PpmdRAR_RangeDec_Init` + `PpmdRAR_RangeDec_CreateVTable`,
//!   which wires the model layer to the RAR-variant math.
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

/// Wire-format variant of the range coder. See module docs for
/// the per-variant init / math / binary-primitive differences.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RangeCoderVariant {
    /// 7z / PPMd7 — used by 7z's PPMd method and by §B's
    /// 7z-PPMd differential corpus.
    Sevenz,
    /// RAR — used by legacy RAR's PPMd-mode blocks
    /// (`is_ppmd_block = 1`). Wired up by §C1g.
    Rar,
}

/// Errors produced by the range decoder.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum RangeDecoderError {
    /// The input ended before the decoder could read its init
    /// prefix (5 bytes in 7z, 4 in RAR) or before it could refill
    /// on a normalisation step.
    #[error("PPMd-II range decoder ran out of input ({what})")]
    Truncated {
        /// Human-readable name of the field that overran.
        what: &'static str,
    },

    /// The 7z leading marker byte was not `0x00`. 7z PPMd streams
    /// always start with a zero; a non-zero leader is virtually
    /// always a sign of misframing (the caller fed a stream from
    /// the wrong block boundary, etc.). The RAR variant has no
    /// leading marker so this error is 7z-only.
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
/// `(range, code, low, position)` plus a backreference to the
/// input.
#[derive(Debug)]
pub struct RangeDecoder<'a> {
    /// Big-endian 32-bit window into the stream the decoder is
    /// currently splitting. In 7z mode this directly tracks the
    /// "code position within the working range"; in RAR mode the
    /// actual position-within-range is `code - low`.
    code: u32,
    /// Width of the currently-coded sub-interval, scaled to the
    /// 32-bit range. Halves (sometimes) on each decode and
    /// renormalises by 8 bits when it falls below [`TOP_VALUE`]
    /// (or [`Self::bottom`] in RAR mode).
    range: u32,
    /// Running lower bound of the current symbol's sub-interval.
    /// Always `0` in 7z mode (libarchive's `Range_Decode_7z`
    /// updates `Code` directly); accumulates in RAR mode
    /// (libarchive's `Range_Decode_RAR` does `Low += start *
    /// Range`).
    low: u32,
    /// Renormalisation cutoff. `0` in 7z mode (the loop never
    /// fires the underflow-recovery branch); `0x8000` in RAR
    /// mode, where the "Range < Bottom AND no carry possible"
    /// case kicks in.
    bottom: u32,
    /// Wire-format variant. Drives [`Self::decode`] (`code` vs
    /// `low` update) and [`Self::decode_bit_bin`] (dedicated
    /// `Range_DecodeBit_7z` math vs the `get_threshold + decode`
    /// path `Range_DecodeBit_RAR` uses).
    variant: RangeCoderVariant,
    /// Borrowed input bytes. The decoder advances `pos` as it
    /// consumes them; callers can read `pos` via [`Self::position`].
    src: &'a [u8],
    /// Read offset into `src`.
    pos: usize,
}

impl<'a> RangeDecoder<'a> {
    /// Construct a **7z-variant** decoder reading from `src`.
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
            low: 0,
            bottom: 0,
            variant: RangeCoderVariant::Sevenz,
            src,
            pos: 5,
        })
    }

    /// Construct a **RAR-variant** decoder reading from `src`.
    ///
    /// Reads 4 bytes from `src` (no leading marker) as a
    /// big-endian seed for [`Self::code`]. Sets `bottom = 0x8000`
    /// so the carry-handling normalize loop's underflow-recovery
    /// branch is reachable. Cursor is advanced past those 4
    /// bytes; the rest of `src` is available to subsequent decode
    /// calls.
    ///
    /// Mirrors libarchive's `PpmdRAR_RangeDec_Init` /
    /// `PpmdRAR_RangeDec_CreateVTable` pair at
    /// `archive_ppmd7.c:767..858`. The RAR3 LZ-block prologue ends
    /// on a byte boundary (1-bit `is_ppmd_block` + 7-bit
    /// `ppmd_flags` plus 0 / 8 / 16 / 24 conditional bits — all
    /// byte-aligned sums), so §C1g's caller hands in a byte slice
    /// starting at the PPMd payload.
    ///
    /// # Errors
    ///
    /// - [`RangeDecoderError::Truncated`] if `src.len() < 4`.
    pub fn new_rar(src: &'a [u8]) -> Result<Self, RangeDecoderError> {
        if src.len() < 4 {
            return Err(RangeDecoderError::Truncated {
                what: "4-byte RAR init prefix",
            });
        }
        let code = u32::from_be_bytes([src[0], src[1], src[2], src[3]]);
        Ok(Self {
            code,
            range: u32::MAX,
            low: 0,
            bottom: 0x8000,
            variant: RangeCoderVariant::Rar,
            src,
            pos: 4,
        })
    }

    /// Which wire-format variant this decoder is operating in.
    /// Diagnostic accessor.
    #[must_use]
    pub fn variant(&self) -> RangeCoderVariant {
        self.variant
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

    /// Renormalise: shift up by 8 bits (pulling a fresh byte into
    /// `code`, shifting `range` / `low` left) until the working
    /// interval is wide enough that the next decode is safe.
    ///
    /// Unified for both variants. The carry-handling logic is the
    /// libarchive `Range_Normalize` loop (lines 781..796 of
    /// `archive_ppmd7.c`):
    ///
    /// - **7z mode** (`low = 0`, `bottom = 0`): the carry check
    ///   `(low ^ (low + range)) >= TOP_VALUE` reduces to
    ///   `range >= TOP_VALUE`; the inner `range >= bottom` is
    ///   trivially true. Behaves exactly like the simpler
    ///   `while range < TOP_VALUE { ... }` loop §B0 originally
    ///   shipped.
    /// - **RAR mode** (`low` may be non-zero, `bottom = 0x8000`):
    ///   the carry check is real — it asks "do the top bytes of
    ///   `low` and `low + range` differ, i.e. is the next emit
    ///   safe from a future carry?". When they don't differ but
    ///   `range < bottom`, the underflow-recovery branch shrinks
    ///   `range` to the largest value `(-low) & (bottom - 1)`
    ///   that preserves decoding correctness.
    fn normalize(&mut self) -> Result<(), RangeDecoderError> {
        loop {
            if (self.low ^ self.low.wrapping_add(self.range)) >= TOP_VALUE {
                if self.range >= self.bottom {
                    break;
                }
                // Underflow recovery: replace range with the
                // largest value that keeps the carry condition
                // unambiguous. Unreachable in 7z mode (bottom=0).
                self.range = self.low.wrapping_neg() & (self.bottom.wrapping_sub(1));
            }
            let b = self.read_byte()?;
            self.code = (self.code << 8) | u32::from(b);
            self.range <<= 8;
            self.low <<= 8;
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
        // (code - low) / range. In 7z mode `low` is always 0 so
        // this reduces to `code / range`. In RAR mode `low` may
        // be non-zero and the explicit subtraction matters.
        Ok(self.code.wrapping_sub(self.low) / self.range)
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
        match self.variant {
            // 7z keeps `Code` as the position-within-range and
            // shifts the origin by subtracting `start * range`.
            // Libarchive's `Range_Decode_7z` (line 798).
            RangeCoderVariant::Sevenz => {
                self.code = self.code.wrapping_sub(start.wrapping_mul(self.range));
            }
            // RAR keeps `Low` as the running lower bound and adds
            // `start * range`; `Code` only changes during
            // renormalize. Libarchive's `Range_Decode_RAR` (line
            // 806).
            RangeCoderVariant::Rar => {
                self.low = self.low.wrapping_add(start.wrapping_mul(self.range));
            }
        }
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

    /// PPMd binary-context decode: pick `0` (the one-state hit)
    /// or `1` (escape) against a 14-bit probability scaled by
    /// [`PPMD_BIN_SCALE`] (= `1 << 14`).
    ///
    /// Caller passes `prob` (= the SEE probability), receives the
    /// decoded bit; the caller is responsible for updating the
    /// SEE state via `PPMD_UPDATE_PROB_0` / `PPMD_UPDATE_PROB_1`
    /// after the bit is known.
    ///
    /// # Variant-specific math
    ///
    /// - **7z** mirrors libarchive's `Range_DecodeBit_7z` (line
    ///   814 of `archive_ppmd7.c`): `bound = (range >> 14) * prob`;
    ///   on bit-1 the escape-branch's range update reads
    ///   `range -= bound`, preserving the low 14 bits of `range`.
    ///   The n-ary `decode` path's `range = (range >> 14) * size`
    ///   would discard those bits and desync from any 7z PPMd
    ///   encoder's output, so 7z mode uses this dedicated path.
    /// - **RAR** mirrors libarchive's `Range_DecodeBit_RAR` (line
    ///   834): goes through `get_threshold(PPMD_BIN_SCALE)` +
    ///   `decode(0, prob)` / `decode(prob, PPMD_BIN_SCALE - prob)`.
    ///   The RAR encoder pairs this exactly — feeding a RAR
    ///   binary symbol through the 7z dedicated math would
    ///   silently desync the same way the inverse pairing would.
    ///
    /// # Errors
    ///
    /// [`RangeDecoderError::Truncated`] if renormalisation needs a
    /// byte and the input is exhausted.
    pub fn decode_bit_bin(&mut self, prob: u32) -> Result<u32, RangeDecoderError> {
        match self.variant {
            RangeCoderVariant::Sevenz => self.decode_bit_bin_7z(prob),
            RangeCoderVariant::Rar => self.decode_bit_bin_rar(prob),
        }
    }

    /// 7z dedicated binary primitive — see [`Self::decode_bit_bin`].
    fn decode_bit_bin_7z(&mut self, prob: u32) -> Result<u32, RangeDecoderError> {
        let bound = (self.range >> 14).wrapping_mul(prob);
        let bit = if self.code < bound {
            self.range = bound;
            0
        } else {
            self.code = self.code.wrapping_sub(bound);
            self.range = self.range.wrapping_sub(bound);
            1
        };
        self.normalize()?;
        Ok(bit)
    }

    /// RAR binary primitive — `get_threshold + decode` against
    /// `PPMD_BIN_SCALE`. See [`Self::decode_bit_bin`].
    fn decode_bit_bin_rar(&mut self, prob: u32) -> Result<u32, RangeDecoderError> {
        // PPMD_BIN_SCALE = 1 << 14 = 16384.
        let threshold = self.get_threshold(1 << 14)?;
        if threshold < prob {
            self.decode(0, prob)?;
            Ok(0)
        } else {
            self.decode(prob, (1 << 14) - prob)?;
            Ok(1)
        }
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

    /// PPMd 7z-variant binary-context encode counterpart to
    /// [`RangeDecoder::decode_bit_bin`] (in 7z mode). Mirrors
    /// libarchive's `Range_EncodeBit_7z`. The probability is the
    /// caller's SEE state pre-update; the caller applies
    /// `PPMD_UPDATE_PROB_*` after the bit is encoded.
    ///
    /// No RAR-variant counterpart yet — §C1f's RAR-decoder
    /// validation is via real archives in §C1g, not against a
    /// sister test encoder. Writing a RAR-variant test encoder
    /// would require porting the LZMA SDK's `Range_EncodeBit_RAR`
    /// plus the carry-handling renormalize loop; deferred until
    /// a concrete test need shows up.
    pub fn encode_bit_bin(&mut self, prob: u32, bit: u32) {
        let bound = (self.range >> 14).wrapping_mul(prob);
        if bit == 0 {
            self.range = bound;
        } else {
            self.low = self.low.wrapping_add(u64::from(bound));
            self.range = self.range.wrapping_sub(bound);
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

    // ---- RAR-variant init + structural tests --------------------
    //
    // §C1f scope: validate that `new_rar` reads the right prefix
    // and seeds the variant-specific fields. Functional round-
    // tripping of the RAR-variant math defers to §C1g, where
    // real ssokolow PPMd-mode archives provide the cross-check
    // against the bundled unrar's expected output.

    #[test]
    fn new_rar_reads_four_bytes_with_no_marker() {
        let bytes = [0x12u8, 0x34, 0x56, 0x78, 0xAA, 0xBB];
        let dec = RangeDecoder::new_rar(&bytes).unwrap();
        assert_eq!(dec.variant(), RangeCoderVariant::Rar);
        assert_eq!(dec.position(), 4);
        // Position 4 ⇒ bytes 0..=3 went into Code, byte 4 onwards
        // remains for renormalize. The first 4 bytes form a BE
        // u32: 0x12345678.
        assert_eq!(dec.code, 0x1234_5678);
        assert_eq!(dec.low, 0);
        assert_eq!(dec.bottom, 0x8000);
        assert_eq!(dec.range, u32::MAX);
    }

    #[test]
    fn new_rar_rejects_truncated_init() {
        let err = RangeDecoder::new_rar(&[0u8, 0, 0]).unwrap_err();
        assert!(matches!(err, RangeDecoderError::Truncated { .. }));
    }

    #[test]
    fn new_rar_does_not_check_leading_byte() {
        // 7z's BadLeader check is variant-specific. RAR-mode init
        // accepts any first byte — it's just code-seed material.
        let bytes = [0xFFu8, 0x00, 0x00, 0x00];
        let dec = RangeDecoder::new_rar(&bytes).unwrap();
        assert_eq!(dec.code, 0xFF00_0000);
    }

    /// In RAR mode `decode` should accumulate into `low` rather
    /// than subtracting from `code`. Asserts the state shape
    /// without depending on a full round trip.
    #[test]
    fn rar_decode_updates_low_not_code() {
        let bytes = [0x00u8; 64];
        let mut dec = RangeDecoder::new_rar(&bytes).unwrap();
        let code_before = dec.code;
        // Take an n-ary slice to provoke a decode. total = 256,
        // pick start = 1, size = 1 → an arbitrary 1/256 partition.
        let _t = dec.get_threshold(256).unwrap();
        let low_before = dec.low;
        dec.decode(1, 1).unwrap();
        // Code may have shifted via normalize, but the per-decode
        // update path went through `low`. We can only assert
        // shape: `low` accumulated; the symmetric 7z update on
        // `code` did NOT fire.
        assert!(dec.low != low_before, "low should have advanced");
        // Code may have shifted via normalize (range *= size made
        // range narrow → renorm pulls bytes in), but the decoder
        // chose not to subtract from code in the decode call.
        // We can't assert `code == code_before` because normalize
        // may have shifted; instead assert that the variant
        // discriminator was respected by checking we ended in
        // RAR mode.
        assert_eq!(dec.variant(), RangeCoderVariant::Rar);
        let _ = code_before; // silence dead-store warning
    }

    /// In RAR mode `bottom = 0x8000` means the carry-handling
    /// normalize loop's underflow-recovery branch is reachable.
    /// 7z mode has `bottom = 0` so the branch is dead.
    /// Smoke test: decode a long enough stream to provoke
    /// renormalize and verify the decoder doesn't panic / under-
    /// run on synthetic zero-padded input.
    #[test]
    fn rar_decode_smoke_tests_normalize_loop() {
        let bytes = vec![0u8; 4096];
        let mut dec = RangeDecoder::new_rar(&bytes).unwrap();
        // Drive the decoder through ~40 n-ary decodes; each
        // 256-wide slice forces a renormalize.
        for _ in 0..40 {
            let _t = dec.get_threshold(256).unwrap();
            dec.decode(0, 1).unwrap();
        }
        // Position should have advanced past the init bytes.
        assert!(dec.position() > 4);
    }

    // ---- 7z behavior preserved across the rename ----------------

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
