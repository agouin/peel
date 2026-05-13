//! Canonical Huffman decoder for the legacy RAR LZ pipeline.
//!
//! Sibling of [`crate::decode::rar_native::huffman`]: both modules
//! materialise an MSB-first canonical Huffman code as a flat
//! `1 << max_len` lookup table over [`super::bits::BitReader`].
//! The reuse-vs-fork decision (`internal/PLAN_rar3.md` §C0) keeps the
//! two implementations independent — the structure is similar
//! because both are doing the same job, but the legacy module
//! ships with its own constants (alphabet sizes, max code length)
//! and tests against legacy-realistic bit patterns.
//!
//! # Where legacy RAR uses Huffman codes
//!
//! Inside the LZ path (`unp_ver ∈ [29, 36]`, `method ∈ 0x31..=0x33`),
//! each non-PPMd block parses four canonical-Huffman trees from
//! its prologue — the literal/length tree (`MAIN_CODE_SIZE` = 299
//! symbols), the distance tree (`OFFSET_CODE_SIZE` = 60), the
//! low-distance-bits tree (`LOW_OFFSET_CODE_SIZE` = 17), and the
//! length tree (`LENGTH_CODE_SIZE` = 28). The four trees plus the
//! precode that decodes their lengths all share the
//! [`MAX_CODE_BITS`] = 15 ceiling on individual code length.
//!
//! The bootstrap layer at [`super::bootstrap`] handles the
//! precode + main-length extraction; this module is the
//! algorithm-agnostic canonical decoder both layers consume.
//!
//! # Lookup-table layout
//!
//! For an alphabet whose longest code is `max_len` bits, the
//! table is `1 << max_len` entries long. A canonical code `C` of
//! length `cl` occupies every index whose top `cl` bits equal `C`
//! — i.e. the entry is replicated at every
//! `idx = (C << (max_len - cl)) | tail` for `tail` in
//! `0..(1 << (max_len - cl))`. Decode is then a single
//! `peek_bits(max_len)` followed by an array index and a
//! `consume_bits(entry.len)`.
//!
//! # Round-one cap
//!
//! [`MAX_CODE_BITS`] = 15. Legacy RAR's spec caps Huffman code
//! lengths at 15 bits; the worst-case table is
//! `1 << 15 = 32 768` entries at 4 bytes each = 128 KiB. With
//! four trees per block, worst-case is 512 KiB — negligible
//! against the 4 MiB sliding-window dictionary §C1d lands.

use thiserror::Error;

use super::bits::{BitReadError, BitReader};

/// Maximum Huffman code length the decoder accepts. Legacy RAR
/// caps codes at 15 bits (`MAX_SYMBOL_LENGTH = 0xF` in libarchive's
/// `archive_read_support_format_rar.c`).
pub const MAX_CODE_BITS: u32 = 15;

/// Errors produced while building or decoding from a [`HuffmanCode`].
#[derive(Debug, Error)]
pub enum HuffmanError {
    /// A code-length value exceeded [`MAX_CODE_BITS`]. The
    /// bootstrap layer reads code lengths as 4-bit literals (max
    /// 15) so this is mostly a defensive guard for synthetic /
    /// fuzz-generated inputs.
    #[error("legacy RAR Huffman code length {got} exceeds MAX_CODE_BITS ({MAX_CODE_BITS})")]
    CodeLengthTooLarge {
        /// The offending length.
        got: u8,
    },

    /// The supplied code-length table over-subscribes the
    /// canonical tree (Kraft inequality violated:
    /// `Σ 2^(-len_i) > 1`). An over-subscribed tree would map
    /// some code prefix to multiple symbols.
    #[error(
        "legacy RAR Huffman over-subscribed: codes consume more than \
         the canonical 2^max_len budget"
    )]
    OverSubscribed,

    /// A peeked bit pattern landed on a table entry that was
    /// never installed (the alphabet is under-subscribed and the
    /// input hit one of the unfilled prefixes).
    #[error(
        "legacy RAR Huffman decode hit a missing prefix \
         (under-subscribed alphabet matched on bit pattern {peeked:#x})"
    )]
    MissingPrefix {
        /// The full `max_len`-bit pattern peeked off the bitstream
        /// at the moment of the miss.
        peeked: u32,
    },

    /// The bit reader ran out of input mid-symbol.
    #[error("legacy RAR Huffman decode underran the bitstream")]
    Underrun(#[from] BitReadError),
}

/// One entry in the flat lookup table. `len == 0` is the
/// "missing prefix" sentinel — reaching it during decode surfaces
/// [`HuffmanError::MissingPrefix`].
#[derive(Clone, Copy, Default, Debug)]
struct HuffEntry {
    /// Decoded symbol. Capped at `u16::MAX = 65535`; every legacy
    /// RAR alphabet has ≤ 404 symbols, far below the cap.
    sym: u16,
    /// Bit length of the canonical code that lands on this entry.
    /// `0` is the not-installed sentinel.
    len: u8,
}

/// Canonical Huffman decode table (MSB-first, lookup-backed).
///
/// Built from a slice of per-symbol code lengths via
/// [`HuffmanCode::build`]; queried via [`HuffmanCode::decode`].
/// One block of legacy RAR LZ output uses four of these (main,
/// offset, low-offset, length); the precode that decodes their
/// code-length tables is a fifth.
#[derive(Debug)]
pub struct HuffmanCode {
    /// Flat lookup keyed by [`BitReader::peek_bits`]`(bits)`.
    table: Box<[HuffEntry]>,
    /// Width, in bits, of the lookup index. Equals the longest
    /// code in the alphabet, clamped to ≥ 1 so an empty alphabet
    /// still has a well-defined `peek_bits(bits)` call.
    bits: u32,
    /// `true` once at least one symbol was installed. Empty
    /// alphabets — possible if a block declares no symbols of a
    /// given kind — construct successfully but
    /// [`HuffmanCode::decode`] surfaces [`HuffmanError::MissingPrefix`]
    /// on any read.
    populated: bool,
}

impl HuffmanCode {
    /// Build a canonical decode table from per-symbol code lengths.
    ///
    /// `code_lens[i]` is the bit-length of symbol `i`; `0` means
    /// the symbol is absent from the alphabet. Lengths must be at
    /// most [`MAX_CODE_BITS`].
    ///
    /// # Errors
    ///
    /// - [`HuffmanError::CodeLengthTooLarge`] if any length
    ///   exceeds [`MAX_CODE_BITS`].
    /// - [`HuffmanError::OverSubscribed`] if the canonical-code
    ///   accumulator overflows `1 << max_len` (Kraft inequality
    ///   violation).
    pub fn build(code_lens: &[u8]) -> Result<Self, HuffmanError> {
        // Step 1: bucket-count by length, track max length.
        let mut bl_count = [0u32; (MAX_CODE_BITS as usize) + 1];
        let mut max_len = 0u32;
        for &l in code_lens {
            if u32::from(l) > MAX_CODE_BITS {
                return Err(HuffmanError::CodeLengthTooLarge { got: l });
            }
            if l != 0 {
                bl_count[l as usize] = bl_count[l as usize].saturating_add(1);
                if u32::from(l) > max_len {
                    max_len = u32::from(l);
                }
            }
        }

        // Empty alphabet: 1-entry stub so peek_bits(1) is well-
        // defined. populated stays false; any decode hits
        // MissingPrefix.
        if max_len == 0 {
            return Ok(HuffmanCode {
                table: vec![HuffEntry::default(); 1].into_boxed_slice(),
                bits: 1,
                populated: false,
            });
        }

        // Step 2: derive the first canonical code for each length
        // via the RFC 1951 §3.2.2 procedure (shift left between
        // lengths, add the count of codes at the previous length).
        let mut next_code = [0u32; (MAX_CODE_BITS as usize) + 2];
        let mut code: u32 = 0;
        for length in 1..=max_len {
            code = code
                .checked_add(bl_count[(length - 1) as usize])
                .ok_or(HuffmanError::OverSubscribed)?
                << 1;
            next_code[length as usize] = code;
        }
        // Kraft check at the maximum length: the last code
        // assigned can't exceed `1 << max_len`.
        let limit = 1u32 << max_len;
        let last_assigned = code.saturating_add(bl_count[max_len as usize]);
        if last_assigned > limit {
            return Err(HuffmanError::OverSubscribed);
        }

        let bits = max_len;
        let table_size = 1usize << bits;
        let mut table = vec![HuffEntry::default(); table_size].into_boxed_slice();

        // Step 3: install symbols in symbol order. The canonical
        // code for symbol `i` is `next_code[cl]`, post-incremented.
        // MSB-first: a code of length `cl` is replicated across
        // `1 << (bits - cl)` consecutive table slots starting at
        // `canonical << (bits - cl)`.
        for (sym, &cl) in code_lens.iter().enumerate() {
            if cl == 0 {
                continue;
            }
            let cl = u32::from(cl);
            let canonical = next_code[cl as usize];
            next_code[cl as usize] = next_code[cl as usize].saturating_add(1);
            let stride = 1usize << (bits - cl);
            let base = (canonical as usize) << (bits - cl);
            for slot in table[base..base + stride].iter_mut() {
                *slot = HuffEntry {
                    // INVARIANT: `sym < code_lens.len() <=
                    // u16::MAX` for every legacy RAR alphabet
                    // (largest is 404 symbols).
                    sym: u16::try_from(sym).unwrap_or(u16::MAX),
                    // INVARIANT: `cl <= MAX_CODE_BITS = 15`, fits
                    // in `u8`.
                    len: cl as u8,
                };
            }
        }

        Ok(HuffmanCode {
            table,
            bits,
            populated: true,
        })
    }

    /// Width, in bits, of the table's lookup index. Equals the
    /// longest code in the alphabet (or 1 for an empty alphabet).
    #[must_use]
    pub fn bits(&self) -> u32 {
        self.bits
    }

    /// `true` when at least one symbol was installed during build.
    /// Distinguishes "empty alphabet" from "alphabet with a
    /// single-symbol code".
    #[must_use]
    pub fn is_populated(&self) -> bool {
        self.populated
    }

    /// Decode the next symbol from `reader`.
    ///
    /// Peeks [`Self::bits`] bits, looks them up, advances by the
    /// entry's code length.
    ///
    /// # Errors
    ///
    /// - [`HuffmanError::Underrun`] when the bitstream ran out
    ///   before [`Self::bits`] bits could be peeked.
    /// - [`HuffmanError::MissingPrefix`] when the peeked bits
    ///   landed on an unfilled entry (under-subscribed alphabet
    ///   or fully empty alphabet).
    pub fn decode(&self, reader: &mut BitReader<'_>) -> Result<u16, HuffmanError> {
        let peeked = reader.peek_bits(self.bits)?;
        if !self.populated {
            return Err(HuffmanError::MissingPrefix { peeked });
        }
        let entry = self.table[peeked as usize];
        if entry.len == 0 {
            return Err(HuffmanError::MissingPrefix { peeked });
        }
        // The peek validated we have ≥ self.bits bits and
        // entry.len ≤ self.bits, so this consume can't underrun.
        reader.consume_bits(u32::from(entry.len))?;
        Ok(entry.sym)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: pack a sequence of `(value, n_bits)` pairs MSB-first
    /// into a byte stream so the tests below can feed canonical
    /// codes into a [`BitReader`] and check the decoder's recovery.
    fn pack_msb(codes: &[(u32, u32)]) -> Vec<u8> {
        let mut acc: u64 = 0;
        let mut nbits: u32 = 0;
        let mut out = Vec::new();
        for &(value, n) in codes {
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

    /// Canonical code for each symbol in `code_lens` per the
    /// RFC 1951 §3.2.2 procedure. Tests use this to know which
    /// bit pattern encodes which symbol.
    fn canonical_codes(code_lens: &[u8]) -> Vec<u32> {
        let mut bl_count = [0u32; (MAX_CODE_BITS as usize) + 1];
        let mut max_len = 0u32;
        for &l in code_lens {
            if l != 0 {
                bl_count[l as usize] += 1;
                if u32::from(l) > max_len {
                    max_len = u32::from(l);
                }
            }
        }
        let mut next_code = [0u32; (MAX_CODE_BITS as usize) + 2];
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

    #[test]
    fn empty_alphabet_builds_and_decode_misses() {
        let code = HuffmanCode::build(&[]).unwrap();
        assert!(!code.is_populated());
        assert_eq!(code.bits(), 1);
        let data = [0xFFu8];
        let mut br = BitReader::new(&data);
        match code.decode(&mut br) {
            Err(HuffmanError::MissingPrefix { peeked }) => assert_eq!(peeked, 1),
            other => panic!("expected MissingPrefix, got {other:?}"),
        }
    }

    #[test]
    fn single_symbol_alphabet_decodes_one_bit_codes() {
        // Only symbol 7 is present with length 1.
        let lens = [0u8, 0, 0, 0, 0, 0, 0, 1];
        let code = HuffmanCode::build(&lens).unwrap();
        let bytes = pack_msb(&[(0, 1), (0, 1), (0, 1)]);
        let mut br = BitReader::new(&bytes);
        for _ in 0..3 {
            assert_eq!(code.decode(&mut br).unwrap(), 7);
        }
    }

    #[test]
    fn two_symbol_equal_length_decode() {
        // Symbols 0 and 1 with length 1 each → 0b0 → 0, 0b1 → 1.
        let lens = [1u8, 1];
        let code = HuffmanCode::build(&lens).unwrap();
        let bytes = pack_msb(&[(0, 1), (1, 1), (1, 1), (0, 1)]);
        let mut br = BitReader::new(&bytes);
        assert_eq!(code.decode(&mut br).unwrap(), 0);
        assert_eq!(code.decode(&mut br).unwrap(), 1);
        assert_eq!(code.decode(&mut br).unwrap(), 1);
        assert_eq!(code.decode(&mut br).unwrap(), 0);
    }

    #[test]
    fn canonical_round_trip_six_symbol_alphabet() {
        // 6 symbols at lengths (3,3,3,3,2,2) — a hand-checked
        // canonical tree. Codes:
        //  sym 4 (len 2) = 00
        //  sym 5 (len 2) = 01
        //  sym 0 (len 3) = 100
        //  sym 1 (len 3) = 101
        //  sym 2 (len 3) = 110
        //  sym 3 (len 3) = 111
        let lens = [3u8, 3, 3, 3, 2, 2];
        let canon = canonical_codes(&lens);
        assert_eq!(canon, &[0b100, 0b101, 0b110, 0b111, 0b00, 0b01]);
        let code = HuffmanCode::build(&lens).unwrap();
        let sequence = [4u32, 5, 0, 3, 2, 1, 4, 4, 5];
        let pairs: Vec<(u32, u32)> = sequence
            .iter()
            .map(|&s| (canon[s as usize], u32::from(lens[s as usize])))
            .collect();
        let bytes = pack_msb(&pairs);
        let mut br = BitReader::new(&bytes);
        for &s in &sequence {
            assert_eq!(u32::from(code.decode(&mut br).unwrap()), s);
        }
    }

    #[test]
    fn over_subscribed_tree_rejects() {
        // Three symbols at length 1 → Kraft sum > 1.
        let err = HuffmanCode::build(&[1u8, 1, 1]).unwrap_err();
        assert!(matches!(err, HuffmanError::OverSubscribed));
    }

    #[test]
    fn code_length_above_cap_rejects() {
        let mut lens = vec![0u8; 5];
        lens[0] = (MAX_CODE_BITS as u8) + 1;
        let err = HuffmanCode::build(&lens).unwrap_err();
        match err {
            HuffmanError::CodeLengthTooLarge { got } => {
                assert_eq!(u32::from(got), MAX_CODE_BITS + 1);
            }
            other => panic!("expected CodeLengthTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn under_subscribed_tree_builds_but_decode_misses_unused_prefixes() {
        // Only symbols 0 and 1 declared at length 2 → codes 00, 01;
        // prefixes 10, 11 are unfilled. Feeding 0b10 / 0b11 should
        // surface MissingPrefix without corrupting the cursor.
        let lens = [2u8, 2];
        let code = HuffmanCode::build(&lens).unwrap();
        let bytes = pack_msb(&[(0b10, 2)]);
        let mut br = BitReader::new(&bytes);
        match code.decode(&mut br) {
            Err(HuffmanError::MissingPrefix { peeked }) => {
                assert_eq!(peeked, 0b10);
            }
            other => panic!("expected MissingPrefix, got {other:?}"),
        }
    }

    #[test]
    fn decode_underrun_surfaces_typed_error() {
        // Single 3-bit code with no input.
        let lens = [1u8, 1];
        let code = HuffmanCode::build(&lens).unwrap();
        let mut br = BitReader::new(&[]);
        match code.decode(&mut br) {
            Err(HuffmanError::Underrun(_)) => {}
            other => panic!("expected Underrun, got {other:?}"),
        }
    }

    /// Build a "legacy-realistic" alphabet — every length from 1
    /// through 8 is exercised by at least one symbol, and the
    /// alphabet sums to a canonical tree. Round-trip 200 symbols
    /// drawn from it to give the decoder real spread.
    #[test]
    fn round_trip_mixed_length_alphabet() {
        // Hand-built code-length sequence: counts at lengths
        // 2 / 3 / 4 / 6 / 7 = 1 / 2 / 4 / 8 / 16 sum to a complete
        // tree (1/4 + 2/8 + 4/16 + 8/64 + 16/128 = 1).
        let mut lens = Vec::with_capacity(31);
        lens.push(2);
        lens.extend([3u8; 2]);
        lens.extend([4u8; 4]);
        lens.extend([6u8; 8]);
        lens.extend([7u8; 16]);
        assert_eq!(lens.len(), 31);
        let canon = canonical_codes(&lens);
        let code = HuffmanCode::build(&lens).unwrap();

        // 200 symbols cycling through the alphabet with an LCG-ish
        // shuffle so we exercise the table at a variety of indices.
        let mut sequence = Vec::with_capacity(200);
        let mut x: u32 = 1;
        for _ in 0..200 {
            x = x.wrapping_mul(2_654_435_761).wrapping_add(7);
            sequence.push((x as usize) % lens.len());
        }
        let pairs: Vec<(u32, u32)> = sequence
            .iter()
            .map(|&s| (canon[s], u32::from(lens[s])))
            .collect();
        let mut bytes = pack_msb(&pairs);
        // Pad with one zero byte: the final decode iteration
        // peeks `max_len = 7` bits even when the actual code is
        // shorter, so the bitstream needs `max_len - 1` extra
        // bits beyond the encoded sequence. A single zero byte
        // is more than enough. In real archives this padding is
        // implicit — the LZ dispatcher stops at a sentinel
        // before peek-runs-off-the-end.
        bytes.push(0);
        let mut br = BitReader::new(&bytes);
        for &s in &sequence {
            assert_eq!(usize::from(code.decode(&mut br).unwrap()), s);
        }
    }

    #[test]
    fn max_code_length_alphabet_builds() {
        // 32 symbols, all at length 15 → 32 / 32768 of the budget
        // consumed. Sub-subscribed but legal.
        let lens = [MAX_CODE_BITS as u8; 32];
        let code = HuffmanCode::build(&lens).unwrap();
        assert_eq!(code.bits(), MAX_CODE_BITS);
        // The first symbol gets code 0; feed 15 zero bits and
        // confirm we recover symbol 0.
        let bytes = pack_msb(&[(0, 15)]);
        let mut br = BitReader::new(&bytes);
        assert_eq!(code.decode(&mut br).unwrap(), 0);
    }
}
