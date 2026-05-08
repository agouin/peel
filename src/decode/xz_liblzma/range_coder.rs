//! Range-coder primitives for the liblzma-port decoder.
//!
//! Phase 1 of [`docs/PLAN_xz_liblzma_port.md`](../../../../docs/PLAN_xz_liblzma_port.md).
//! Mirror of liblzma's `range_decoder.h` (~185 lines): a small
//! [`RangeDecoder`] state struct plus a set of `macro_rules!`
//! primitives ([`rc_normalize!`], [`rc_if_0!`], [`rc_update_0!`],
//! [`rc_update_1!`], [`rc_bit!`], [`rc_bit_last!`], [`rc_direct!`],
//! [`rc_read_init!`]) that the call site expands into the
//! inner-loop body of `lzma_decode_port` (Phase 3).
//!
//! # Why macros, not functions
//!
//! Phase A of [`PLAN_xz_liblzma_deep_dive.md`](../../../../docs/PLAN_xz_liblzma_deep_dive.md)
//! showed that liblzma's hot-loop register discipline depends on
//! the C preprocessor literally inlining `rc_normalize` /
//! `rc_if_0` / `rc_update_*` / `rc_bit` at every call site so
//! the compiler sees a single straight-line function body with
//! `range`, `code`, `in_pos` as plain function-local variables.
//! Phase C of that plan tested whether `#[inline(always)]` on
//! `&mut LocalRc`-taking helpers could achieve the same effect;
//! it could not — LLVM materialized the `LocalRc` struct on the
//! stack frame even with full inlining, because the `&mut` to
//! the struct gave LLVM a pointer it had to keep live.
//!
//! Rust's `macro_rules!` is the Rust-side equivalent of liblzma's
//! C preprocessor approach: each `rc_*!` invocation expands
//! literally at the call site, with `range` / `code` / `in_pos`
//! threaded as **caller-named identifiers** (passed as macro
//! parameters and substituted by hygiene-respecting metavariable
//! expansion).
//!
//! # Caller contract
//!
//! Every `rc_*!` macro takes the same first four arguments —
//! `$range:ident, $code:ident, $in_pos:ident, $bytes:expr` —
//! that the surrounding `lzma_decode_port` function will have
//! declared as stack-locals. The `$out:lifetime, $seq:expr,
//! $coder:expr` parameters follow when the macro may need to
//! checkpoint the resume cursor on input underflow (mirror of
//! liblzma's `goto out` pattern).
//!
//! Rust labels are hygienic — a `break 'main` inside a macro
//! body would refer to a `'main` distinct from the caller's
//! `'main:` block. To work around that, callers pass the
//! escape label as an explicit `:lifetime` parameter:
//! `rc_normalize!(range, code, in_pos, bytes, 'out_label, seq, coder)`.
//!
//! # `unsafe` posture
//!
//! [`rc_normalize!`] reads from `$bytes` via raw-pointer
//! indexing (`unsafe { *bytes.as_ptr().add(in_pos) }`) after
//! explicitly checking `in_pos < bytes.len()`. The `unsafe`
//! block carries a `// SAFETY:` proof of the bound. This
//! matches liblzma's `in[rc_in_pos++]` raw-array access; the
//! bench gate at Phase 4 is what justifies the policy
//! relaxation.

// In Phase 1 these primitives are exercised only from the
// in-file test module; the lib build (without `--tests`) sees
// them as unused. Phase 3 implements `lzma_decode_port` and the
// macros + constants become live in production code. Until then
// suppress the dead-code lints rather than leak `cfg(test)` into
// the macro definitions (which would block their use from the
// non-test Phase 3 dispatch loop).
#![allow(unused_macros, dead_code, unused_imports)]

/// Number of bits the range coder shifts in per pulled byte.
/// Mirror of `RC_SHIFT_BITS = 8`.
pub(crate) const RC_SHIFT_BITS: u32 = 8;

/// Range-coder normalization threshold (`1 << 24`).
/// Mirror of `RC_TOP_VALUE`.
pub(crate) const RC_TOP_VALUE: u32 = 1 << 24;

/// Number of bits in a probability-model slot.
/// Mirror of `RC_BIT_MODEL_TOTAL_BITS = 11`.
pub(crate) const RC_BIT_MODEL_TOTAL_BITS: u32 = 11;

/// Range-coder probability denominator (`1 << 11 = 2048`).
/// Mirror of `RC_BIT_MODEL_TOTAL`.
pub(crate) const RC_BIT_MODEL_TOTAL: u32 = 1 << RC_BIT_MODEL_TOTAL_BITS;

/// Right-shift used during the probability-slot adaptation
/// step. Mirror of `RC_MOVE_BITS = 5`.
pub(crate) const RC_MOVE_BITS: u32 = 5;

/// Initialization value for a fresh probability slot —
/// `RC_BIT_MODEL_TOTAL / 2`. Mirror of `bit_reset`.
pub(crate) const PROB_INIT_VAL: u16 = (RC_BIT_MODEL_TOTAL / 2) as u16;

/// Number of bytes consumed by the range coder's initial 5-byte
/// prefix.
pub(crate) const RC_INIT_BYTES_LEN: usize = 5;

/// Range-coder mutable state held by [`super::decoder::Lzma1Decoder`].
///
/// Mirror of liblzma's `lzma_range_decoder`:
///
/// ```c
/// typedef struct {
///     uint32_t range;
///     uint32_t code;
///     uint32_t init_bytes_left;
/// } lzma_range_decoder;
/// ```
#[derive(Debug, Clone, Copy)]
pub struct RangeDecoder {
    /// Range-coder interval width. Maintained `>= RC_TOP_VALUE`
    /// after every operation by [`rc_normalize!`].
    pub range: u32,
    /// Range-coder pointer offset within the interval.
    pub code: u32,
    /// Bytes still to be consumed from the 5-byte init prefix.
    pub init_bytes_left: u8,
}

impl Default for RangeDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RangeDecoder {
    /// Construct a fresh, uninitialized [`RangeDecoder`]. Five
    /// init bytes must be consumed (via [`Self::read_init_byte`]
    /// or [`rc_read_init!`]) before the dispatch loop runs.
    ///
    /// Mirror of `rc_reset(rc)`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            range: u32::MAX,
            code: 0,
            init_bytes_left: RC_INIT_BYTES_LEN as u8,
        }
    }

    /// `true` once the 5-byte init prefix is fully consumed.
    #[inline]
    #[must_use]
    pub const fn init_done(&self) -> bool {
        self.init_bytes_left == 0
    }

    /// `true` when the range coder is in the spec's
    /// "well-finished" state — `code == 0`. Mirror of
    /// `rc_is_finished`.
    #[inline]
    #[must_use]
    pub const fn is_finished_ok(&self) -> bool {
        self.code == 0
    }

    /// Consume one byte of the 5-byte init prefix.
    ///
    /// # Errors
    ///
    /// - [`super::error::XzPortError::RangeCoderInitMarker`] if
    ///   the leading byte is non-zero.
    pub fn read_init_byte(&mut self, byte: u8) -> Result<(), super::error::XzPortError> {
        debug_assert!(self.init_bytes_left > 0, "rc init already complete");
        if self.init_bytes_left == RC_INIT_BYTES_LEN as u8 && byte != 0x00 {
            return Err(super::error::XzPortError::RangeCoderInitMarker(byte));
        }
        self.code = (self.code << 8) | u32::from(byte);
        self.init_bytes_left -= 1;
        Ok(())
    }

    /// Bulk read of the 5-byte init prefix from a slice. Returns
    /// the number of bytes consumed.
    ///
    /// # Errors
    ///
    /// As [`Self::read_init_byte`].
    pub fn read_init(&mut self, bytes: &[u8]) -> Result<usize, super::error::XzPortError> {
        let take = bytes.len().min(self.init_bytes_left as usize);
        for &b in &bytes[..take] {
            self.read_init_byte(b)?;
        }
        Ok(take)
    }
}

// ===== Macro primitives =====

/// Read up to 5 init bytes from `$bytes` starting at `$in_pos`.
///
/// On underflow (slice exhausted before init complete), saves
/// `$seq` into `$coder.sequence` and `break $out`s. The init
/// marker is validated by [`RangeDecoder::read_init_byte`]; any
/// surfaced error is propagated via `?`.
///
/// **Caller contract**: must be inside a labeled block whose
/// label matches `$out`. Caller's function must return
/// `Result<_, XzPortError>` (the macro uses `?`).
macro_rules! rc_read_init {
    ($in_pos:ident, $bytes:expr, $out:lifetime, $seq:expr, $coder:expr) => {{
        while $coder.rc.init_bytes_left > 0 {
            if $in_pos >= $bytes.len() {
                $coder.sequence = $seq;
                break $out;
            }
            // SAFETY: just verified $in_pos < $bytes.len() above.
            let byte = unsafe { *$bytes.as_ptr().add($in_pos) };
            $coder.rc.read_init_byte(byte)?;
            $in_pos += 1;
        }
    }};
}
pub(crate) use rc_read_init;

/// Restore the range-coder invariant `range >= RC_TOP_VALUE` by
/// pulling one byte if needed.
///
/// On underflow saves `$seq` into `$coder.sequence` and
/// `break $out`s. Mirror of liblzma's `rc_normalize(seq)`.
macro_rules! rc_normalize {
    ($range:ident, $code:ident, $in_pos:ident, $bytes:expr, $out:lifetime, $seq:expr, $coder:expr) => {{
        if $range < $crate::decode::xz_liblzma::range_coder::RC_TOP_VALUE {
            if $in_pos >= $bytes.len() {
                $coder.sequence = $seq;
                break $out;
            }
            // SAFETY: just verified $in_pos < $bytes.len() above.
            let byte = unsafe { *$bytes.as_ptr().add($in_pos) };
            $range <<= $crate::decode::xz_liblzma::range_coder::RC_SHIFT_BITS;
            $code =
                ($code << $crate::decode::xz_liblzma::range_coder::RC_SHIFT_BITS) | u32::from(byte);
            $in_pos += 1;
        }
    }};
}
pub(crate) use rc_normalize;

/// Compute the bit-decode boundary, returning whether bit==0.
///
/// Mirror of liblzma's `rc_if_0(prob, seq)`. Caller usage:
/// `if rc_if_0!(...) { rc_update_0!(...); ... } else { rc_update_1!(...); ... }`.
macro_rules! rc_if_0 {
    ($range:ident, $code:ident, $in_pos:ident, $bytes:expr, $bound:ident, $prob:expr, $out:lifetime, $seq:expr, $coder:expr) => {{
        $crate::decode::xz_liblzma::range_coder::rc_normalize!(
            $range, $code, $in_pos, $bytes, $out, $seq, $coder
        );
        $bound = ($range >> $crate::decode::xz_liblzma::range_coder::RC_BIT_MODEL_TOTAL_BITS)
            * (*$prob as u32);
        $code < $bound
    }};
}
pub(crate) use rc_if_0;

/// Update the range-coder + probability slot for a decoded
/// bit==0. Mirror of liblzma's `rc_update_0(prob)`.
macro_rules! rc_update_0 {
    ($range:ident, $bound:ident, $prob:expr) => {{
        $range = $bound;
        let v = *$prob as u32;
        *$prob = (v
            + (($crate::decode::xz_liblzma::range_coder::RC_BIT_MODEL_TOTAL - v)
                >> $crate::decode::xz_liblzma::range_coder::RC_MOVE_BITS)) as u16;
    }};
}
pub(crate) use rc_update_0;

/// Update the range-coder + probability slot for a decoded
/// bit==1. Mirror of liblzma's `rc_update_1(prob)`.
macro_rules! rc_update_1 {
    ($range:ident, $code:ident, $bound:ident, $prob:expr) => {{
        $range -= $bound;
        $code -= $bound;
        let v = *$prob as u32;
        *$prob = (v - (v >> $crate::decode::xz_liblzma::range_coder::RC_MOVE_BITS)) as u16;
    }};
}
pub(crate) use rc_update_1;

/// Decode one bit, run `$action0` (bit==0) or `$action1` (bit==1)
/// per outcome, update the prob slot in place. Mirror of
/// liblzma's `rc_bit_last(prob, action0, action1, seq)`.
macro_rules! rc_bit_last {
    ($range:ident, $code:ident, $in_pos:ident, $bytes:expr, $bound:ident, $prob:expr, $action0:block, $action1:block, $out:lifetime, $seq:expr, $coder:expr) => {{
        if $crate::decode::xz_liblzma::range_coder::rc_if_0!(
            $range, $code, $in_pos, $bytes, $bound, $prob, $out, $seq, $coder
        ) {
            $crate::decode::xz_liblzma::range_coder::rc_update_0!($range, $bound, $prob);
            $action0
        } else {
            $crate::decode::xz_liblzma::range_coder::rc_update_1!($range, $code, $bound, $prob);
            $action1
        }
    }};
}
pub(crate) use rc_bit_last;

/// Decode one bit and update the LZMA `$symbol` cursor MSB-first.
///
/// Mirror of liblzma's `rc_bit(prob, action0, action1, seq)`.
/// Callers must have a `$symbol:ident` stack-local in scope.
macro_rules! rc_bit {
    ($range:ident, $code:ident, $in_pos:ident, $bytes:expr, $bound:ident, $symbol:ident, $prob:expr, $action0:block, $action1:block, $out:lifetime, $seq:expr, $coder:expr) => {{
        $crate::decode::xz_liblzma::range_coder::rc_bit_last!(
            $range,
            $code,
            $in_pos,
            $bytes,
            $bound,
            $prob,
            {
                $symbol <<= 1;
                $action0
            },
            {
                $symbol = ($symbol << 1) + 1;
                $action1
            },
            $out,
            $seq,
            $coder
        );
    }};
}
pub(crate) use rc_bit;

/// Decode one bit raw (no probability slot) by halving the
/// interval and choosing based on `$code`'s top bit. Mirror of
/// liblzma's `rc_direct(dest, seq)` — branchless sign-bit trick.
macro_rules! rc_direct {
    ($range:ident, $code:ident, $in_pos:ident, $bytes:expr, $bound:ident, $dest:ident, $out:lifetime, $seq:expr, $coder:expr) => {{
        $crate::decode::xz_liblzma::range_coder::rc_normalize!(
            $range, $code, $in_pos, $bytes, $out, $seq, $coder
        );
        $range >>= 1;
        $code = $code.wrapping_sub($range);
        $bound = 0u32.wrapping_sub($code >> 31);
        $code = $code.wrapping_add($range & $bound);
        $dest = ($dest << 1).wrapping_add($bound.wrapping_add(1));
    }};
}
pub(crate) use rc_direct;

#[cfg(test)]
mod tests {
    //! Round-trip tests against
    //! [`super::super::super::xz_native::test_support::TestRangeEncoder`].
    //!
    //! The encoder is the existing module's test helper; we drive
    //! it forward, capture the encoded bytes, then decode them via
    //! the new macros and assert byte-identical bit values + prob
    //! slot evolution.
    //!
    //! `unused_assignments` is allowed module-wide because the
    //! `$coder.sequence = $seq` save-on-underflow inside the
    //! macros is conditionally observable (only after `break $out`
    //! into a path that asserts on it). The macros are correct;
    //! clippy can't see through the conditional path.

    #![allow(unused_assignments)]

    use super::super::test_support::TestRangeEncoder;
    use super::*;
    use crate::decode::xz_liblzma::decoder::{Lzma1Decoder, Sequence};
    use crate::decode::xz_liblzma::error::XzPortError;

    /// Drive the rc init prefix + N rc_bit calls; return the
    /// decoded bits.
    fn round_trip_adaptive_bits(input_bits: &[u32]) -> Result<Vec<u32>, XzPortError> {
        let mut enc = TestRangeEncoder::new();
        let mut enc_prob = PROB_INIT_VAL;
        for &bit in input_bits {
            enc.encode_bit(&mut enc_prob, bit);
        }
        let stream = enc.finish();

        let mut coder = Lzma1Decoder::default();
        let mut bytes_pos: usize = 0;
        let mut decoded: Vec<u32> = Vec::with_capacity(input_bits.len());
        let mut dec_prob: u16 = PROB_INIT_VAL;

        // Locals declared inside the labeled block — `range` /
        // `code` are uninitialized until `rc_read_init!` finishes
        // pulling the 5-byte init prefix into the rc state.
        'main: {
            rc_read_init!(bytes_pos, stream, 'main, Sequence::Normalize, coder);
            let mut range: u32 = coder.rc.range;
            let mut code: u32 = coder.rc.code;
            let mut bound: u32;

            for _ in 0..input_bits.len() {
                let bit_decoded;
                if rc_if_0!(
                    range, code, bytes_pos, stream, bound, &mut dec_prob,
                    'main, Sequence::Normalize, coder
                ) {
                    rc_update_0!(range, bound, &mut dec_prob);
                    bit_decoded = 0;
                } else {
                    rc_update_1!(range, code, bound, &mut dec_prob);
                    bit_decoded = 1;
                }
                decoded.push(bit_decoded);
            }

            coder.rc.range = range;
            coder.rc.code = code;
        }

        Ok(decoded)
    }

    #[test]
    fn round_trip_single_bit_0() -> Result<(), XzPortError> {
        let decoded = round_trip_adaptive_bits(&[0])?;
        assert_eq!(decoded, vec![0]);
        Ok(())
    }

    #[test]
    fn round_trip_single_bit_1() -> Result<(), XzPortError> {
        let decoded = round_trip_adaptive_bits(&[1])?;
        assert_eq!(decoded, vec![1]);
        Ok(())
    }

    /// LFSR-derived 64-bit pattern; same shape as
    /// `xz_native::range_coder::tests::round_trip_64_adaptive_bits_default_prob`.
    #[test]
    fn round_trip_64_adaptive_bits() -> Result<(), XzPortError> {
        let mut bits = [0u32; 64];
        let mut state: u32 = 0xDEAD_BEEF;
        for slot in &mut bits {
            let new_bit = ((state >> 31) ^ (state >> 21) ^ (state >> 1) ^ state) & 1;
            state = (state << 1) | new_bit;
            *slot = new_bit;
        }
        let decoded = round_trip_adaptive_bits(&bits)?;
        assert_eq!(decoded, bits);
        Ok(())
    }

    /// Direct-bits round-trip — the branchless sign-bit trick
    /// from [`rc_direct!`].
    fn round_trip_direct_bits(value: u32, num_bits: u32) -> Result<u32, XzPortError> {
        let mut enc = TestRangeEncoder::new();
        enc.encode_direct_bits(value, num_bits);
        let stream = enc.finish();

        let mut coder = Lzma1Decoder::default();
        let mut bytes_pos: usize = 0;
        let mut symbol: u32 = 0;

        'main: {
            rc_read_init!(bytes_pos, stream, 'main, Sequence::Normalize, coder);
            let mut range: u32 = coder.rc.range;
            let mut code: u32 = coder.rc.code;
            let mut bound: u32;
            for _ in 0..num_bits {
                rc_direct!(
                    range, code, bytes_pos, stream, bound, symbol,
                    'main, Sequence::Normalize, coder
                );
            }
        }

        Ok(symbol)
    }

    #[test]
    fn round_trip_direct_bits_short() -> Result<(), XzPortError> {
        for num_bits in 1u32..=12 {
            for value in 0..(1u32 << num_bits) {
                let got = round_trip_direct_bits(value, num_bits)?;
                assert_eq!(got, value, "num_bits={num_bits} value={value}");
            }
        }
        Ok(())
    }

    #[test]
    fn round_trip_direct_bits_30_wide() -> Result<(), XzPortError> {
        for &value in &[
            0u32,
            1,
            (1u32 << 30) - 1,
            0x1234_5678 & ((1u32 << 30) - 1),
            0x2AAA_AAAA,
            0x3FFF_FFFF,
        ] {
            let got = round_trip_direct_bits(value, 30)?;
            assert_eq!(got, value, "30-bit round-trip mismatch for 0x{value:08X}");
        }
        Ok(())
    }

    /// Exercise [`rc_bit!`] (which threads `symbol` through the
    /// MSB-first update). Encodes a value bit-by-bit via a forward
    /// bit-tree and decodes via 6 explicit `rc_bit!` calls.
    fn round_trip_msb_first_bits(input_bits: &[u32]) -> Result<u32, XzPortError> {
        let mut enc = TestRangeEncoder::new();
        let mut enc_probs = vec![PROB_INIT_VAL; 1 << input_bits.len()];
        let mut m: u32 = 1;
        for &bit in input_bits {
            enc.encode_bit(&mut enc_probs[m as usize], bit);
            m = (m << 1) | bit;
        }
        let stream = enc.finish();

        let mut coder = Lzma1Decoder::default();
        let mut bytes_pos: usize = 0;
        let mut dec_probs = vec![PROB_INIT_VAL; 1 << input_bits.len()];
        let mut symbol: u32 = 1;

        'main: {
            rc_read_init!(bytes_pos, stream, 'main, Sequence::Normalize, coder);
            let mut range: u32 = coder.rc.range;
            let mut code: u32 = coder.rc.code;
            let mut bound: u32;

            for _ in 0..input_bits.len() {
                rc_bit!(
                    range, code, bytes_pos, stream, bound, symbol,
                    &mut dec_probs[symbol as usize],
                    {}, {},
                    'main, Sequence::Normalize, coder
                );
            }
        }

        Ok(symbol - (1u32 << input_bits.len()))
    }

    #[test]
    fn round_trip_rc_bit_msb_first() -> Result<(), XzPortError> {
        for value in 0u32..64 {
            let bits: Vec<u32> = (0..6).rev().map(|i| (value >> i) & 1).collect();
            let got = round_trip_msb_first_bits(&bits)?;
            assert_eq!(got, value, "6-bit round-trip mismatch for {value}");
        }
        Ok(())
    }

    /// Underflow path: feeding fewer than 5 init bytes triggers
    /// `break 'main` via [`rc_read_init!`] and saves the resume
    /// cursor.
    #[test]
    fn rc_read_init_underflow_saves_sequence() -> Result<(), XzPortError> {
        let mut coder = Lzma1Decoder::default();
        let stream: &[u8] = &[0x00, 0x12]; // only 2 of 5 init bytes
        let mut bytes_pos: usize = 0;

        'main: {
            rc_read_init!(bytes_pos, stream, 'main, Sequence::IsMatch, coder);
            // Should not reach this point — the macro's break
            // should have fired on init underflow.
            panic!("rc_read_init! did not break on init underflow");
        }
        // After break, sequence is IsMatch and we consumed both
        // bytes.
        assert_eq!(coder.sequence, Sequence::IsMatch);
        assert_eq!(bytes_pos, 2);
        assert_eq!(coder.rc.init_bytes_left, 3);
        Ok(())
    }

    /// Init marker: leading byte must be `0x00`.
    #[test]
    fn rc_read_init_rejects_nonzero_marker() {
        let mut coder = Lzma1Decoder::default();
        let bad_marker: u8 = 0x42;
        match coder.rc.read_init_byte(bad_marker) {
            Err(XzPortError::RangeCoderInitMarker(b)) => assert_eq!(b, 0x42),
            other => panic!("expected init marker error, got {other:?}"),
        }
    }
}
