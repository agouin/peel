//! Canonical Huffman decoder for the RAR5 LZSS layer.
//!
//! Round-one of `internal/PLAN_rar5_decoder.md` (§A2) ships the
//! format-agnostic canonical decoder: input is a slice of per-symbol
//! code lengths, output is a [`HuffTable`] that maps the next bits
//! off [`super::bits::BitReader`] to a `(symbol, length)` pair via a
//! flat lookup table. The RAR5-specific *bootstrap* parser — the
//! "level-0" 4-bit-per-symbol table that decodes the lengths of the
//! "level-1" main tables — is its own concern; that lives in a
//! follow-on §A3 phase next to the LZSS dispatcher (`decode/rar_native/lzss.rs`)
//! that will consume both layers. Splitting them keeps this file
//! focused on the single algorithm every Huffman-using format
//! shares.
//!
//! # Bit ordering
//!
//! RAR5 packs Huffman codes **MSB-first** within the bitstream
//! (matching the convention [`super::bits::BitReader`] reads).
//! Unlike `decode/deflate_native/huffman.rs` — which is LSB-first
//! and bit-reverses each canonical code on install — this module
//! installs canonical codes verbatim because the reader's
//! `peek_bits(n)` already returns the high-order `n` bits of the
//! upcoming stream as the high-order bits of a `u32`.
//!
//! # Lookup-table layout
//!
//! For an alphabet whose longest code is `max_len` bits, the table
//! is `1 << max_len` entries long. A canonical code `C` of length
//! `cl` occupies every index whose top `cl` bits equal `C` — i.e.
//! the entry is replicated at every `idx = (C << (max_len - cl)) |
//! tail` for `tail` in `0..(1 << (max_len - cl))`. Decode is then
//! a single `peek_bits(max_len)` followed by an array index and a
//! `consume_bits(entry.len)`.
//!
//! # Round-one cap
//!
//! [`MAX_CODE_BITS`] = 15. RAR5's spec caps Huffman code lengths
//! at 15 bits; the worst-case table is `1 << 15 = 32 768` entries
//! at 4 bytes each = 128 KiB. Negligible vs the LZSS dictionary's
//! up-to-4-GiB footprint and acceptable for round-one. §G can
//! revisit with a two-level table if profiling shows the L2 fills
//! degrade decode rate on small archives.

use thiserror::Error;

use super::bits::{BitReadError, BitReader};

/// Maximum Huffman code length the decoder accepts. Per the RAR5
/// spec, codes are at most 15 bits long.
pub const MAX_CODE_BITS: u32 = 15;

/// Errors produced while building or decoding from a [`HuffTable`].
#[derive(Debug, Error)]
pub enum HuffmanError {
    /// A code-length value exceeded [`MAX_CODE_BITS`].
    #[error("RAR5 Huffman code length {got} exceeds MAX_CODE_BITS ({MAX_CODE_BITS})")]
    CodeLengthTooLarge {
        /// The offending length.
        got: u8,
    },

    /// The supplied code-length table over-subscribes the canonical
    /// tree (Kraft inequality violated). RAR5 — like every other
    /// canonical-Huffman format — requires `Σ 2^(-len_i) ≤ 1` over
    /// every nonzero code length; an over-subscribed tree means
    /// some code prefix would map to multiple symbols.
    #[error(
        "RAR5 Huffman over-subscribed: codes consume more than \
         the canonical 2^max_len budget"
    )]
    OverSubscribed,

    /// A peeked bit pattern landed on a table entry that was never
    /// installed (the alphabet is under-subscribed and the input
    /// hit one of the unfilled prefixes). Distinguishing this from
    /// [`Self::OverSubscribed`] keeps malformed-input diagnostics
    /// specific.
    #[error(
        "RAR5 Huffman decode hit a missing prefix (under-subscribed \
         alphabet matched on bit pattern {peeked:#x})"
    )]
    MissingPrefix {
        /// The full `max_len`-bit pattern peeked off the bitstream
        /// at the moment of the miss.
        peeked: u32,
    },

    /// The bit reader ran out of input mid-symbol.
    #[error("RAR5 Huffman decode underran the bitstream")]
    Underrun(#[from] BitReadError),
}

/// One entry in the flat lookup table. `len == 0` is the
/// "missing prefix" sentinel — reaching it during decode surfaces
/// [`HuffmanError::MissingPrefix`].
#[derive(Clone, Copy, Default, Debug)]
struct HuffEntry {
    /// Decoded symbol. Capped at `u16::MAX = 65535` — adequate for
    /// every RAR5 alphabet (the largest are ≤ 404 symbols).
    sym: u16,
    /// Number of bits the canonical code occupies. `0` is the
    /// not-installed sentinel.
    len: u8,
}

/// Canonical Huffman decode table (MSB-first, lookup-backed).
#[derive(Debug)]
pub struct HuffTable {
    /// Flat lookup. Indexed by the top `bits` bits of
    /// [`BitReader::peek_bits`].
    table: Box<[HuffEntry]>,
    /// Width of the lookup index in bits = max code length in this
    /// alphabet, clamped to ≥ 1 so an empty alphabet still has a
    /// well-defined `peek_bits(bits)` call.
    bits: u32,
    /// `true` once at least one symbol has been installed. Empty
    /// alphabets — used by RAR5 blocks that declare no symbols
    /// of a given kind — construct successfully but
    /// [`Self::decode`] surfaces [`HuffmanError::MissingPrefix`] on
    /// any attempt to read.
    populated: bool,
}

impl HuffTable {
    /// Build a canonical decode table from per-symbol code lengths.
    ///
    /// `code_lens[i]` is the bit-length of symbol `i`; `0` means
    /// "symbol not present". Lengths are bounded at
    /// [`MAX_CODE_BITS`].
    ///
    /// # Errors
    ///
    /// - [`HuffmanError::CodeLengthTooLarge`] if any length
    ///   exceeds [`MAX_CODE_BITS`].
    /// - [`HuffmanError::OverSubscribed`] if the canonical-code
    ///   accumulator overflows `1 << max_len` (Kraft violation).
    pub fn build(code_lens: &[u8]) -> Result<Self, HuffmanError> {
        // Step 1: count by length.
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

        // Empty alphabet: 1-entry stub so `peek_bits(1)` is
        // well-defined; populated stays false.
        if max_len == 0 {
            return Ok(HuffTable {
                table: vec![HuffEntry::default(); 1].into_boxed_slice(),
                bits: 1,
                populated: false,
            });
        }

        // Step 2: compute the first canonical code for each length.
        // RFC 1951 §3.2.2 procedure: shift left between lengths, add
        // the count of codes at the previous length.
        let mut next_code = [0u32; (MAX_CODE_BITS as usize) + 2];
        let mut code: u32 = 0;
        for length in 1..=max_len {
            code = code
                .checked_add(bl_count[(length - 1) as usize])
                .ok_or(HuffmanError::OverSubscribed)?
                << 1;
            next_code[length as usize] = code;
        }
        // Kraft check at the maximum length.
        let limit = 1u32 << max_len;
        let last_assigned = code.saturating_add(bl_count[max_len as usize]);
        if last_assigned > limit {
            return Err(HuffmanError::OverSubscribed);
        }

        let bits = max_len;
        let table_size = 1usize << bits;
        let mut table = vec![HuffEntry::default(); table_size].into_boxed_slice();

        // Step 3: install symbols by walking `code_lens` in symbol
        // order. The canonical code for symbol `i` is `next_code[cl]`,
        // which we then increment. MSB-first: the entry is replicated
        // at every index whose top `cl` bits equal the code.
        for (sym, &cl) in code_lens.iter().enumerate() {
            if cl == 0 {
                continue;
            }
            let cl = u32::from(cl);
            let canonical = next_code[cl as usize];
            next_code[cl as usize] = next_code[cl as usize].saturating_add(1);
            // The base index in the lookup table is the canonical
            // code shifted left into the high `cl` bits, occupying
            // index range `[base, base + stride)`.
            let stride = 1usize << (bits - cl);
            let base = (canonical as usize) << (bits - cl);
            for slot in table[base..base + stride].iter_mut() {
                *slot = HuffEntry {
                    // INVARIANT: `sym < code_lens.len() <=
                    // u16::MAX` for every RAR5 alphabet.
                    sym: u16::try_from(sym).unwrap_or(u16::MAX),
                    // INVARIANT: `cl <= MAX_CODE_BITS = 15`, fits
                    // in `u8`.
                    len: cl as u8,
                };
            }
        }

        Ok(HuffTable {
            table,
            bits,
            populated: true,
        })
    }

    /// Width, in bits, of the table's lookup index.
    #[must_use]
    pub fn bits(&self) -> u32 {
        self.bits
    }

    /// `true` when at least one symbol was installed during build.
    #[must_use]
    pub fn is_populated(&self) -> bool {
        self.populated
    }

    /// Decode the next symbol from `reader`.
    ///
    /// Peeks `bits` bits, looks them up, advances by the entry's
    /// `len`. The peek may underrun at end-of-stream — surfaced
    /// via [`HuffmanError::Underrun`].
    ///
    /// # Errors
    ///
    /// - [`HuffmanError::Underrun`] when the bitstream ran out.
    /// - [`HuffmanError::MissingPrefix`] when the peeked bits
    ///   landed on an unfilled entry (under-subscribed alphabet).
    pub fn decode(&self, reader: &mut BitReader<'_>) -> Result<u16, HuffmanError> {
        if !self.populated {
            // Empty alphabet — peek the same width so the cursor
            // stays unmodified, then surface a missing-prefix
            // error. Peeking on an empty stream surfaces Underrun
            // directly, which is also fine.
            let peeked = reader.peek_bits(self.bits)?;
            return Err(HuffmanError::MissingPrefix { peeked });
        }
        let peeked = reader.peek_bits(self.bits)?;
        // INVARIANT: `peeked < 1 << self.bits == self.table.len()`.
        let entry = self.table[peeked as usize];
        if entry.len == 0 {
            return Err(HuffmanError::MissingPrefix { peeked });
        }
        // The peek already validated we have at least `bits` bits,
        // and `entry.len <= bits`, so `consume_bits(entry.len)`
        // can't underrun here.
        reader
            .consume_bits(u32::from(entry.len))
            .map_err(HuffmanError::Underrun)?;
        Ok(entry.sym)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: encode a sequence of `(symbol, code_length, canonical_code)`
    /// tuples into MSB-first bytes. Used by the tests below to feed
    /// known canonical codes into the [`BitReader`] and check the
    /// decoder's recovery.
    fn encode_codes(codes: &[(u32, u32)]) -> Vec<u8> {
        let mut acc: u64 = 0;
        let mut nbits: u32 = 0;
        let mut out = Vec::new();
        for &(value, n) in codes {
            assert!(n > 0 && n <= 32);
            // Mask in case the caller passed a value with extra
            // high bits.
            let v = value & ((1u32 << n) - 1);
            // Place the new code at positions
            // [64 - nbits - n, 64 - nbits) of `acc`.
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

    /// Compute canonical codes for the supplied `code_lens` (RFC
    /// 1951 §3.2.2 procedure). Used by tests to know which bit
    /// patterns to feed for which symbols.
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
    fn build_rejects_overlong_code_length() {
        let mut lens = vec![1u8; 4];
        lens.push(16); // > MAX_CODE_BITS
        let err = HuffTable::build(&lens).unwrap_err();
        assert!(matches!(err, HuffmanError::CodeLengthTooLarge { got: 16 }));
    }

    #[test]
    fn build_rejects_oversubscribed_alphabet() {
        // Three symbols, each at length 1: codes would be 0, 1, ?
        // — only two codes exist at length 1, so this over-subscribes.
        let lens = [1u8, 1, 1];
        let err = HuffTable::build(&lens).unwrap_err();
        assert!(matches!(err, HuffmanError::OverSubscribed));
    }

    #[test]
    fn build_accepts_balanced_4_symbol_alphabet() {
        // RFC 1951 example: 4 symbols at lengths [2, 1, 3, 3].
        // Canonical codes: A=10, B=0, C=110, D=111.
        let lens = [2u8, 1, 3, 3];
        let table = HuffTable::build(&lens).expect("balanced alphabet");
        assert_eq!(table.bits(), 3);
        assert!(table.is_populated());

        let codes = canonical_codes(&lens);
        assert_eq!(codes, [0b10, 0b0, 0b110, 0b111]);

        // Round-trip: encode "A B D C" and decode.
        let stream = encode_codes(&[(codes[0], 2), (codes[1], 1), (codes[3], 3), (codes[2], 3)]);
        let mut reader = BitReader::new(&stream);
        assert_eq!(table.decode(&mut reader).unwrap(), 0); // A
        assert_eq!(table.decode(&mut reader).unwrap(), 1); // B
        assert_eq!(table.decode(&mut reader).unwrap(), 3); // D
        assert_eq!(table.decode(&mut reader).unwrap(), 2); // C
    }

    #[test]
    fn build_handles_empty_alphabet() {
        let table = HuffTable::build(&[0u8; 5]).expect("empty alphabet builds");
        assert!(!table.is_populated());
        // Decoding from an empty alphabet always errors. Feed a
        // byte so the underlying peek doesn't underrun first.
        let bytes = [0xFFu8];
        let mut reader = BitReader::new(&bytes);
        match table.decode(&mut reader).unwrap_err() {
            HuffmanError::MissingPrefix { .. } => {}
            other => panic!("expected MissingPrefix, got {other:?}"),
        }
    }

    #[test]
    fn build_handles_single_symbol_alphabet() {
        // Single symbol at length 1: code = 0. Reading any 1 bit
        // returns symbol 0 (the lookup table is [sym=0, len=1; sym=0, len=1]
        // — both 0 and 1 land on the same symbol, since codes
        // beginning with 1 are not assigned).
        //
        // Wait — actually with a single symbol at length 1, the
        // tree is technically *under-subscribed* (Kraft = 1/2 < 1).
        // Decoding a 1-bit `1` would land on a missing-prefix
        // entry. Verify both outcomes.
        let lens = [1u8];
        let table = HuffTable::build(&lens).expect("single-symbol alphabet builds");
        assert_eq!(table.bits(), 1);

        // Encode "A" then a high bit (which should be a miss).
        let stream = encode_codes(&[(0, 1)]);
        let mut reader = BitReader::new(&stream);
        assert_eq!(table.decode(&mut reader).unwrap(), 0);

        let stream = encode_codes(&[(1, 1)]);
        let mut reader = BitReader::new(&stream);
        match table.decode(&mut reader).unwrap_err() {
            HuffmanError::MissingPrefix { .. } => {}
            other => panic!("expected MissingPrefix, got {other:?}"),
        }
    }

    #[test]
    fn under_subscribed_alphabet_surfaces_missing_prefix() {
        // 4 symbols at lengths [2, 2, 2, 0] — codes 00, 01, 10.
        // The canonical tree leaves 11 unassigned. Reading bits
        // "11" must surface MissingPrefix.
        let lens = [2u8, 2, 2, 0];
        let table = HuffTable::build(&lens).expect("under-subscribed builds");
        let stream = encode_codes(&[(0b11, 2)]);
        let mut reader = BitReader::new(&stream);
        match table.decode(&mut reader).unwrap_err() {
            HuffmanError::MissingPrefix { peeked } => {
                // The peek width is 2 (max_len), and the high 2
                // bits are 0b11 = 3.
                assert_eq!(peeked, 0b11);
            }
            other => panic!("expected MissingPrefix, got {other:?}"),
        }
    }

    #[test]
    fn decode_underrun_propagates_bit_reader_error() {
        let lens = [2u8, 2, 2, 2];
        let table = HuffTable::build(&lens).expect("balanced builds");
        let mut reader = BitReader::new(&[]);
        match table.decode(&mut reader).unwrap_err() {
            HuffmanError::Underrun(_) => {}
            other => panic!("expected Underrun, got {other:?}"),
        }
    }

    #[test]
    fn round_trips_random_symbol_sequence_in_a_64_symbol_alphabet() {
        // Random-looking but deterministic length distribution.
        // Build a balanced length pattern that satisfies Kraft.
        let mut lens = vec![0u8; 64];
        // 32 symbols at length 6, 16 at length 7, 16 at length 8.
        // Kraft: 32 * 1/64 + 16 * 1/128 + 16 * 1/256 = 0.5 + 0.125 + 0.0625 = 0.6875 < 1.
        // Under-subscribed but not over-subscribed.
        for slot in lens.iter_mut().take(32) {
            *slot = 6;
        }
        for slot in lens.iter_mut().take(48).skip(32) {
            *slot = 7;
        }
        for slot in lens.iter_mut().take(64).skip(48) {
            *slot = 8;
        }
        let table = HuffTable::build(&lens).expect("balanced builds");
        let codes = canonical_codes(&lens);

        // Pick a deterministic symbol sequence and encode it.
        let sequence: Vec<u16> = (0..200u32).map(|i| ((i * 13 + 7) % 64) as u16).collect();
        let encoded: Vec<(u32, u32)> = sequence
            .iter()
            .map(|&s| (codes[s as usize], u32::from(lens[s as usize])))
            .collect();
        let bytes = encode_codes(&encoded);

        let mut reader = BitReader::new(&bytes);
        for &expected in &sequence {
            assert_eq!(table.decode(&mut reader).unwrap(), expected);
        }
    }

    #[test]
    fn build_handles_max_15_bit_codes() {
        // One symbol per length 1..=15: codes 0, 10, 110, ...,
        // 111111111111110, 111111111111111. Kraft: Σ 1/2^k for
        // k = 1..=15 = 1 - 1/32768 < 1, so well-formed.
        let lens: Vec<u8> = (1u8..=15).collect();
        let table = HuffTable::build(&lens).expect("max-length alphabet builds");
        assert_eq!(table.bits(), 15);
        let codes = canonical_codes(&lens);

        // Round-trip every symbol once.
        let encoded: Vec<(u32, u32)> = (0..lens.len())
            .map(|i| (codes[i], u32::from(lens[i])))
            .collect();
        let bytes = encode_codes(&encoded);
        let mut reader = BitReader::new(&bytes);
        for (sym, _) in encoded.iter().enumerate() {
            assert_eq!(table.decode(&mut reader).unwrap(), sym as u16);
        }
    }
}
