//! RAR5 LZSS match-length decoder.
//!
//! Translates a length-code (0..=43) into a concrete match
//! length, reading any required extra bits off the bitstream.
//! Matches libarchive's `decode_code_length` in
//! `archive_read_support_format_rar5.c` (Grzegorz Antoniak,
//! BSD 2-Clause; see [`NOTICE`](../../../NOTICE)).
//!
//! # Encoding
//!
//! ```text
//! code 0..7  → length = 2 + code,                   no extra bits
//! code 8..43 → lbits  = code / 4 - 1
//!              length = 2 + ((4 | (code & 3)) << lbits) + extra(lbits)
//! ```
//!
//! Concretely:
//!
//! ```text
//! code  lbits  base   range (length values)
//!    0      0     2          2
//!    1      0     3          3
//!    ...
//!    7      0     9          9
//!    8      1    10         10..=11
//!    9      1    12         12..=13
//!   10      1    14         14..=15
//!   11      1    16         16..=17
//!   12      2    18         18..=21
//!   ...
//!   43      9  3586       3586..=4097
//! ```
//!
//! Length codes feed two callers in the LZSS dispatcher: fresh
//! matches read the length code from the literal/length Huffman
//! (`num - 262` after the `num >= 262` branch), and
//! distance-cache matches (`num in [258..=261]`) read it from the
//! repeated-distance Huffman. Both paths funnel into
//! [`decode_length`].

use thiserror::Error;

use super::bits::{BitReadError, BitReader};

/// Maximum length-code value the dispatcher can pass. Matches
/// libarchive's `HUFF_RC = 44`.
pub const MAX_LENGTH_CODE: u16 = 43;

/// Errors produced by [`decode_length`].
#[derive(Debug, Error)]
pub enum LengthError {
    /// The caller passed a code outside `0..=MAX_LENGTH_CODE`.
    /// Indicates either a malformed Huffman emission or a bug
    /// in the dispatcher's range translation.
    #[error("RAR5 length code {got} out of range 0..={MAX_LENGTH_CODE}")]
    CodeOutOfRange {
        /// The offending code value.
        got: u16,
    },

    /// The bit reader ran out while reading extra bits.
    #[error("RAR5 length decode underran the bitstream reading extra bits")]
    Underrun(#[from] BitReadError),
}

/// Decode the match length from `code` (0..=43), pulling any
/// required extra bits off `reader`.
///
/// Returns the resulting match length in bytes.
///
/// # Errors
///
/// - [`LengthError::CodeOutOfRange`] if `code > 43`.
/// - [`LengthError::Underrun`] if the bitstream runs out reading
///   the extra-bit tail.
pub fn decode_length(code: u16, reader: &mut BitReader<'_>) -> Result<u32, LengthError> {
    if code > MAX_LENGTH_CODE {
        return Err(LengthError::CodeOutOfRange { got: code });
    }
    let (base, lbits) = if code < 8 {
        (2u32 + u32::from(code), 0u32)
    } else {
        // INVARIANT: code in 8..=43, so code/4 - 1 in 1..=9.
        let lbits = u32::from(code) / 4 - 1;
        // INVARIANT: lbits ≤ 9, and (4 | (code & 3)) ≤ 7, so the
        // shift cannot overflow `u32` for any code in 0..=43.
        // Maximum: code = 43 → lbits = 9; (4|3) = 7; 7 << 9 = 3584.
        let base = 2u32 + ((4u32 | u32::from(code & 3)) << lbits);
        (base, lbits)
    };
    if lbits == 0 {
        return Ok(base);
    }
    let extra = reader.read_bits(lbits)?;
    Ok(base + extra)
}

/// Length-code lookup table for tests and reference. Returns
/// `(base, extra_bits)` for the supplied code.
///
/// # Panics
///
/// Panics if `code > MAX_LENGTH_CODE`.
#[must_use]
#[cfg(test)]
fn length_table_entry(code: u16) -> (u32, u32) {
    assert!(code <= MAX_LENGTH_CODE);
    if code < 8 {
        (2 + u32::from(code), 0)
    } else {
        let lbits = u32::from(code) / 4 - 1;
        let base = 2 + ((4 | u32::from(code & 3)) << lbits);
        (base, lbits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: pack a single `(value, n_bits)` pair into MSB-first
    /// bytes.
    fn pack_bits(value: u32, n: u32) -> Vec<u8> {
        let mut acc: u64 = 0;
        let mut nbits: u32 = 0;
        let mut out = Vec::new();
        let v = if n == 32 {
            value
        } else {
            value & ((1u32 << n) - 1)
        };
        acc |= u64::from(v) << (64 - n);
        nbits += n;
        while nbits >= 8 {
            out.push((acc >> 56) as u8);
            acc <<= 8;
            nbits -= 8;
        }
        if nbits > 0 {
            out.push((acc >> 56) as u8);
        }
        out
    }

    #[test]
    fn codes_0_through_7_are_zero_extra_bit() {
        for code in 0..=7u16 {
            let mut reader = BitReader::new(&[]);
            let len = decode_length(code, &mut reader).unwrap();
            assert_eq!(len, 2 + u32::from(code));
            assert_eq!(reader.bits_consumed(), 0);
        }
    }

    #[test]
    fn code_8_reads_1_extra_bit_with_base_10() {
        // code 8: base 10, range 10..=11.
        for extra in 0..=1u32 {
            let bytes = pack_bits(extra, 1);
            let mut reader = BitReader::new(&bytes);
            let len = decode_length(8, &mut reader).unwrap();
            assert_eq!(len, 10 + extra);
        }
    }

    #[test]
    fn code_11_reads_1_extra_bit_with_base_16() {
        // code 11: lbits=1, base=2 + ((4|3) << 1) = 2 + 14 = 16.
        let bytes = pack_bits(1, 1);
        let mut reader = BitReader::new(&bytes);
        let len = decode_length(11, &mut reader).unwrap();
        assert_eq!(len, 17);
    }

    #[test]
    fn code_12_reads_2_extra_bits_with_base_18() {
        // code 12: lbits=2, base=2 + ((4|0) << 2) = 2 + 16 = 18.
        for extra in 0..=3u32 {
            let bytes = pack_bits(extra, 2);
            let mut reader = BitReader::new(&bytes);
            let len = decode_length(12, &mut reader).unwrap();
            assert_eq!(len, 18 + extra);
        }
    }

    #[test]
    fn code_43_max_extras_yields_max_length() {
        // code 43: lbits=9, base=2 + ((4|3) << 9) = 2 + 3584 = 3586.
        // max length = 3586 + 511 = 4097.
        let bytes = pack_bits(511, 9);
        let mut reader = BitReader::new(&bytes);
        let len = decode_length(43, &mut reader).unwrap();
        assert_eq!(len, 4097);
    }

    #[test]
    fn out_of_range_code_errors() {
        let mut reader = BitReader::new(&[0xFFu8]);
        let err = decode_length(44, &mut reader).unwrap_err();
        assert!(matches!(err, LengthError::CodeOutOfRange { got: 44 }));
    }

    #[test]
    fn underrun_during_extra_bits_propagates() {
        let mut reader = BitReader::new(&[]);
        let err = decode_length(8, &mut reader).unwrap_err();
        assert!(matches!(err, LengthError::Underrun(_)));
    }

    #[test]
    fn full_length_table_matches_reference_formula() {
        // Cross-check every code 0..=43 against the reference
        // helper to catch any off-by-one in the shift / mask.
        for code in 0..=MAX_LENGTH_CODE {
            let (base, extra_bits) = length_table_entry(code);
            for extra in [0u32, (1u32 << extra_bits.min(31)).saturating_sub(1)] {
                let bytes = if extra_bits == 0 {
                    Vec::new()
                } else {
                    pack_bits(extra, extra_bits)
                };
                let mut reader = BitReader::new(&bytes);
                let got = decode_length(code, &mut reader).unwrap();
                let expected = base + extra;
                assert_eq!(
                    got, expected,
                    "code {code}, extra {extra} → expected {expected}"
                );
            }
        }
    }

    #[test]
    fn length_2_is_the_minimum() {
        let mut reader = BitReader::new(&[]);
        assert_eq!(decode_length(0, &mut reader).unwrap(), 2);
    }

    #[test]
    fn lbits_widths_match_libarchive_formula() {
        // Each code's lbits = code / 4 - 1 for code >= 8.
        let cases = [
            (8u16, 1u32),
            (11, 1),
            (12, 2),
            (15, 2),
            (16, 3),
            (19, 3),
            (20, 4),
            (40, 9),
            (43, 9),
        ];
        for (code, want_lbits) in cases {
            let (_base, lbits) = length_table_entry(code);
            assert_eq!(lbits, want_lbits, "code {code}");
        }
    }
}
