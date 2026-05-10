//! RAR5 LZSS match-distance decoder.
//!
//! Translates a distance-slot (0..=63) into a concrete match
//! distance, reading any required extra bits off the bitstream
//! and (for slots whose `dbits >= 4`) decoding the four
//! low-order bits via the low-distance Huffman alphabet.
//! Matches libarchive's distance-decoding branch in
//! `do_uncompress_block` (Grzegorz Antoniak, BSD 2-Clause; see
//! [`NOTICE`](../../../NOTICE)).
//!
//! # Encoding
//!
//! ```text
//! slot 0..3  → dist = 1 + slot,                     no extra bits
//! slot 4..63 → dbits = slot / 2 - 1
//!              dist  = 1 + ((2 | (slot & 1)) << dbits)
//!                     + (extra-bits or low-dist Huffman tail)
//! ```
//!
//! For `dbits < 4`: read exactly `dbits` extra bits as the
//! distance tail.
//!
//! For `dbits >= 4`: read `dbits - 4` extra bits as the
//! **high** part of the tail (positioned at bit 4 of the tail),
//! then decode the **low 4 bits** via the
//! `HUFF_LDC = 16`-symbol low-distance Huffman alphabet.
//! libarchive's source (in `do_uncompress_block`):
//!
//! ```text
//! if(dbits > 4) {
//!     read_bits_32(...);
//!     skip_bits(rar, dbits - 4);
//!     add = (add >> (36 - dbits)) << 4;
//!     dist += add;
//! }
//! decode_number(a, &rar->cstate.ldd, p, &low_dist);
//! dist += low_dist;
//! ```
//!
//! Concrete examples:
//!
//! ```text
//! slot  dbits  base   range
//!    0      0     1            1
//!    1      0     2            2
//!    2      0     3            3
//!    3      0     4            4
//!    4      1     5         5..=6
//!    5      1     7         7..=8
//!    6      2     9         9..=12
//!    7      2    13        13..=16
//!    8      3    17        17..=24
//!    9      3    25        25..=32
//!   10      4    33        33..=48      (split: 0 bits high, 4 low via LDD)
//!   11      4    49        49..=64
//!   12      5    65        65..=96      (split: 1 bit high, 4 low via LDD)
//!   ...
//!   62     30   ...
//!   63     30   ...
//! ```

use thiserror::Error;

use super::bits::{BitReadError, BitReader};
use super::huffman::{HuffTable, HuffmanError};

/// Maximum distance-slot the dispatcher can pass. Matches
/// libarchive's `HUFF_DC = 64` (slots 0..=63).
pub const MAX_DIST_SLOT: u16 = 63;

/// Errors produced by [`decode_distance`].
#[derive(Debug, Error)]
pub enum DistanceError {
    /// The caller passed a slot outside `0..=MAX_DIST_SLOT`.
    #[error("RAR5 distance slot {got} out of range 0..={MAX_DIST_SLOT}")]
    SlotOutOfRange {
        /// The offending slot value.
        got: u16,
    },

    /// The bit reader ran out while reading high-order extra bits.
    #[error("RAR5 distance decode underran the bitstream reading extra bits")]
    Underrun(#[from] BitReadError),

    /// The low-distance Huffman decode surfaced an error
    /// (under-subscribed match or bitstream underrun inside the
    /// peek).
    #[error("RAR5 distance decode failed reading low-bits via LDD Huffman")]
    LowDistDecode(#[source] HuffmanError),
}

/// Decode the match distance from `slot` (0..=63), pulling any
/// required extra bits off `reader` and (for slots whose
/// `dbits >= 4`) decoding the 4-bit low-order tail via
/// `low_dist_huffman`.
///
/// Returns the resulting back-reference distance in bytes.
///
/// # Errors
///
/// - [`DistanceError::SlotOutOfRange`] if `slot > 63`.
/// - [`DistanceError::Underrun`] if the bitstream runs out
///   during the high-bits read (slots whose `dbits >= 5`).
/// - [`DistanceError::LowDistDecode`] if the low-distance
///   Huffman miss-fires.
pub fn decode_distance(
    slot: u16,
    reader: &mut BitReader<'_>,
    low_dist_huffman: &HuffTable,
) -> Result<u32, DistanceError> {
    if slot > MAX_DIST_SLOT {
        return Err(DistanceError::SlotOutOfRange { got: slot });
    }
    if slot < 4 {
        return Ok(1 + u32::from(slot));
    }
    // INVARIANT: slot in 4..=63, so dbits in 1..=30.
    let dbits = u32::from(slot) / 2 - 1;
    let base = 1u32 + ((2u32 | u32::from(slot & 1)) << dbits);

    if dbits < 4 {
        // Direct extra-bits: read `dbits` bits as the tail.
        let extra = reader.read_bits(dbits)?;
        return Ok(base + extra);
    }

    // dbits >= 4: split into (dbits - 4)-bit high tail + 4-bit
    // low Huffman. libarchive reads `dbits - 4` extra bits and
    // shifts them up by 4 to leave room for the low Huffman
    // emission.
    let high = if dbits > 4 {
        reader.read_bits(dbits - 4)? << 4
    } else {
        0
    };
    let low = low_dist_huffman
        .decode(reader)
        .map_err(DistanceError::LowDistDecode)?;
    // INVARIANT: HUFF_LDC = 16, so low_dist_huffman emits
    // values 0..=15 — fits in 4 bits.
    Ok(base + high + u32::from(low))
}

/// Reference helper: return `(base, dbits)` for the supplied
/// slot. Used by tests to cross-check the dispatcher's
/// arithmetic.
#[must_use]
#[cfg(test)]
fn distance_table_entry(slot: u16) -> (u32, u32) {
    assert!(slot <= MAX_DIST_SLOT);
    if slot < 4 {
        (1 + u32::from(slot), 0)
    } else {
        let dbits = u32::from(slot) / 2 - 1;
        let base = 1 + ((2 | u32::from(slot & 1)) << dbits);
        (base, dbits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a flat 4-bit-per-symbol low-distance Huffman: every
    /// symbol 0..=15 uses 4 bits; canonical codes 0b0000..=0b1111
    /// in symbol order.
    fn flat_ldc_huffman() -> HuffTable {
        HuffTable::build(&[4u8; 16]).expect("flat 16-symbol alphabet")
    }

    /// Compute canonical code for the supplied lengths (RFC 1951
    /// §3.2.2 procedure).
    fn canonical_codes(code_lens: &[u8]) -> Vec<u32> {
        let mut bl_count = [0u32; 16];
        let mut max_len = 0u32;
        for &l in code_lens {
            if l != 0 {
                bl_count[l as usize] += 1;
                if u32::from(l) > max_len {
                    max_len = u32::from(l);
                }
            }
        }
        let mut next_code = [0u32; 17];
        let mut code: u32 = 0;
        for length in 1..=max_len {
            code = (code + bl_count[(length - 1) as usize]) << 1;
            next_code[length as usize] = code;
        }
        let mut out = vec![0u32; code_lens.len()];
        for (sym, &cl) in code_lens.iter().enumerate() {
            if cl != 0 {
                out[sym] = next_code[cl as usize];
                next_code[cl as usize] += 1;
            }
        }
        out
    }

    /// Pack a sequence of `(value, n_bits)` pairs into MSB-first
    /// bytes.
    fn pack_bits(pairs: &[(u32, u32)]) -> Vec<u8> {
        let mut acc: u64 = 0;
        let mut nbits: u32 = 0;
        let mut out = Vec::new();
        for &(value, n) in pairs {
            assert!(n > 0 && n <= 32);
            let v = if n == 32 {
                value
            } else {
                value & ((1u32 << n) - 1)
            };
            acc |= u64::from(v) << (64 - nbits - n);
            nbits += n;
            while nbits >= 8 {
                out.push((acc >> 56) as u8);
                acc <<= 8;
                nbits -= 8;
            }
        }
        if nbits > 0 {
            out.push((acc >> 56) as u8);
        }
        out
    }

    #[test]
    fn slots_0_through_3_are_zero_extra_bit() {
        let ldc = flat_ldc_huffman();
        for slot in 0..=3u16 {
            let mut reader = BitReader::new(&[]);
            let dist = decode_distance(slot, &mut reader, &ldc).unwrap();
            assert_eq!(dist, 1 + u32::from(slot));
            assert_eq!(reader.bits_consumed(), 0);
        }
    }

    #[test]
    fn slot_4_reads_1_extra_bit_with_base_5() {
        // slot 4: dbits=1, base=1+((2|0)<<1)=1+4=5; range 5..=6.
        let ldc = flat_ldc_huffman();
        for extra in 0..=1u32 {
            let bytes = pack_bits(&[(extra, 1)]);
            let mut reader = BitReader::new(&bytes);
            let dist = decode_distance(4, &mut reader, &ldc).unwrap();
            assert_eq!(dist, 5 + extra);
        }
    }

    #[test]
    fn slot_9_reads_3_extra_bits_with_base_25() {
        // slot 9: dbits=3, base=1+((2|1)<<3)=1+24=25; range 25..=32.
        let ldc = flat_ldc_huffman();
        for extra in 0..=7u32 {
            let bytes = pack_bits(&[(extra, 3)]);
            let mut reader = BitReader::new(&bytes);
            let dist = decode_distance(9, &mut reader, &ldc).unwrap();
            assert_eq!(dist, 25 + extra);
        }
    }

    #[test]
    fn slot_10_uses_low_dist_huffman_for_4_bits() {
        // slot 10: dbits=4, base=1+((2|0)<<4)=1+32=33; range 33..=48.
        // dbits == 4: no high extra bits, just 4 low bits via LDD.
        let ldc = flat_ldc_huffman();
        let codes = canonical_codes(&[4u8; 16]);
        for low in 0..=15u32 {
            let bytes = pack_bits(&[(codes[low as usize], 4)]);
            let mut reader = BitReader::new(&bytes);
            let dist = decode_distance(10, &mut reader, &ldc).unwrap();
            assert_eq!(dist, 33 + low);
        }
    }

    #[test]
    fn slot_12_combines_high_extra_with_low_dist_huffman() {
        // slot 12: dbits=5, base=1+((2|0)<<5)=1+64=65; range 65..=96.
        // dbits == 5: read 1 high extra bit (shifted up by 4) +
        // 4 low bits via LDD.
        let ldc = flat_ldc_huffman();
        let codes = canonical_codes(&[4u8; 16]);

        // high extra = 0, low = 0 → dist = 65 + 0 + 0 = 65
        let bytes = pack_bits(&[(0, 1), (codes[0], 4)]);
        let mut reader = BitReader::new(&bytes);
        assert_eq!(decode_distance(12, &mut reader, &ldc).unwrap(), 65);

        // high extra = 1, low = 0 → dist = 65 + 16 + 0 = 81
        let bytes = pack_bits(&[(1, 1), (codes[0], 4)]);
        let mut reader = BitReader::new(&bytes);
        assert_eq!(decode_distance(12, &mut reader, &ldc).unwrap(), 81);

        // high extra = 1, low = 15 → dist = 65 + 16 + 15 = 96
        let bytes = pack_bits(&[(1, 1), (codes[15], 4)]);
        let mut reader = BitReader::new(&bytes);
        assert_eq!(decode_distance(12, &mut reader, &ldc).unwrap(), 96);
    }

    #[test]
    fn slot_63_yields_huge_distance() {
        // slot 63: dbits=63/2-1=30; base=1+((2|1)<<30)=1+(3<<30).
        // 3 << 30 = 0xC0000000; base = 0xC0000001.
        // dbits=30 means 26 high extra bits + 4 low Huffman bits.
        let ldc = flat_ldc_huffman();
        let codes = canonical_codes(&[4u8; 16]);
        let bytes = pack_bits(&[(0, 26), (codes[0], 4)]);
        let mut reader = BitReader::new(&bytes);
        let dist = decode_distance(63, &mut reader, &ldc).unwrap();
        assert_eq!(dist, 0xC000_0001);
    }

    #[test]
    fn out_of_range_slot_errors() {
        let ldc = flat_ldc_huffman();
        let bytes = [0xFFu8];
        let mut reader = BitReader::new(&bytes);
        let err = decode_distance(64, &mut reader, &ldc).unwrap_err();
        assert!(matches!(err, DistanceError::SlotOutOfRange { got: 64 }));
    }

    #[test]
    fn underrun_during_extra_bits_propagates() {
        let ldc = flat_ldc_huffman();
        let mut reader = BitReader::new(&[]);
        let err = decode_distance(4, &mut reader, &ldc).unwrap_err();
        assert!(matches!(err, DistanceError::Underrun(_)));
    }

    #[test]
    fn distance_table_first_two_dozen_slots_match_reference() {
        // Cross-check the formula against a hand-picked
        // expected-base table for the first slots, which is the
        // most error-prone region.
        let expected = [
            (0u16, 1u32, 0u32),
            (1, 2, 0),
            (2, 3, 0),
            (3, 4, 0),
            (4, 5, 1),
            (5, 7, 1),
            (6, 9, 2),
            (7, 13, 2),
            (8, 17, 3),
            (9, 25, 3),
            (10, 33, 4),
            (11, 49, 4),
            (12, 65, 5),
            (13, 97, 5),
            (14, 129, 6),
            (15, 193, 6),
            (20, 1025, 9),
            (30, 32769, 14),
        ];
        for (slot, want_base, want_dbits) in expected {
            let (base, dbits) = distance_table_entry(slot);
            assert_eq!(base, want_base, "slot {slot}");
            assert_eq!(dbits, want_dbits, "slot {slot}");
        }
    }
}
