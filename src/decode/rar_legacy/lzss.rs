//! Per-symbol LZ-block dispatcher for legacy RAR.
//!
//! Glues every §C1a..§C1d primitive into the single decode loop
//! that walks one block's symbol stream. Inside a block:
//!
//! - Decode one main-code symbol via [`super::huffman::HuffmanCode`].
//! - Dispatch on the symbol's value into one of six branches
//!   (literal, block-end, filter-decl, repeat-last,
//!   cached-distance, short-distance, full-match).
//! - Emit literals / matches to [`super::dict::Dict`].
//! - Update [`super::dist_cache::DistCache`] +
//!   `last_offset` / `last_length` / `last_low_offset` state.
//!
//! Equivalent to libarchive's `expand` function (lines
//! 2906..3132 of `archive_read_support_format_rar.c`); see
//! [`NOTICE`](../../../NOTICE) for the BSD-2-Clause attribution.
//!
//! # Scope of §C1e₁
//!
//! Round-one decodes one block at a time. The block-spanning
//! "symbol 256 with `new_file = false` → parse next block's
//! prologue, continue" loop lives in §C1h's solid-mode /
//! multi-block driver. Symbol 257 (filter declaration) is
//! surfaced as [`BlockEnd::FilterDecl`] for §C2 to act on; the
//! filter VM itself is §C2's responsibility.

use thiserror::Error;

use super::bits::{BitReadError, BitReader};
use super::bootstrap::MainTables;
use super::dict::{Dict, DictError};
use super::dist_cache::DistCache;
use super::huffman::HuffmanError;

/// Length-base table for length codes (libarchive's
/// `lengthbases`). 28 entries; the index is a `lengthcode`
/// symbol (cached-distance branch) or `symbol - 271`
/// (full-match branch).
const LENGTH_BASES: [u32; 28] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224,
];

/// Number of extra bits to read after each length code
/// (libarchive's `lengthbits`).
const LENGTH_BITS: [u32; 28] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5,
];

/// Offset-base table for full-match distance codes
/// (libarchive's `offsetbases`). 60 entries.
const OFFSET_BASES: [u32; 60] = [
    0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536,
    2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
    262144, 327680, 393216, 458752, 524288, 589824, 655360, 720896, 786432, 851968, 917504, 983040,
    1048576, 1310720, 1572864, 1835008, 2097152, 2359296, 2621440, 2883584, 3145728, 3407872,
    3670016, 3932160,
];

/// Number of extra bits to read after each offset code
/// (libarchive's `offsetbits`).
const OFFSET_BITS: [u32; 60] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13, 14, 14, 15, 15, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 18, 18, 18, 18, 18,
    18, 18, 18, 18, 18, 18, 18,
];

/// Short-distance base table (libarchive's `shortbases`).
/// Indexed by `symbol - 263` for main-code symbols 263..=270.
const SHORT_BASES: [u32; 8] = [0, 4, 8, 16, 32, 64, 128, 192];

/// Number of extra bits per short-distance symbol
/// (libarchive's `shortbits`).
const SHORT_BITS: [u32; 8] = [2, 2, 3, 4, 5, 6, 6, 6];

/// Errors produced by the LZ dispatcher.
#[derive(Debug, Error)]
pub enum LzError {
    /// The bitstream ran out mid-symbol.
    #[error("legacy RAR LZ dispatcher underran the bitstream")]
    Underrun(#[from] BitReadError),

    /// One of the per-block Huffman codes rejected the input.
    #[error("legacy RAR LZ dispatcher: Huffman decode failed")]
    Huffman(#[from] HuffmanError),

    /// The dict layer rejected an emit (zero distance,
    /// underflow, over-capacity).
    #[error("legacy RAR LZ dispatcher: dict emit failed")]
    Dict(#[from] DictError),

    /// A sub-decode returned a symbol outside its alphabet.
    /// Libarchive surfaces "bad data" for the same conditions.
    #[error(
        "legacy RAR LZ dispatcher: {alphabet} symbol {symbol} out of range \
         (alphabet size {size})"
    )]
    InvalidSymbol {
        /// Which sub-alphabet was hit (`"length"`, `"offset"`,
        /// `"low_offset"`).
        alphabet: &'static str,
        /// The decoded value.
        symbol: u16,
        /// The alphabet's symbol count.
        size: u32,
    },
}

/// Result of [`LzDecoder::decode_block`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockEnd {
    /// Symbol 256 with the `new_file` bit clear: this block is
    /// done; the entry's compressed stream continues with another
    /// block prologue. §C1h's driver is responsible for parsing
    /// it and re-entering the dispatcher.
    NextBlock,
    /// Symbol 256 with the `new_file` bit set: this block is
    /// done AND the entry's compressed stream is finished
    /// (libarchive's `start_new_table = 1` signal).
    EntryDone,
    /// Symbol 257: a filter program is being declared. §C2's
    /// filter VM is the eventual consumer; until §C2 lands the
    /// caller treats this as `UnsupportedFeature::Filters`.
    FilterDecl,
}

/// Per-entry LZ decoder state.
///
/// Owns the sliding-window dictionary, the 4-slot
/// recent-distance LRU, and the small per-entry tail libarchive
/// keeps to handle "repeat last match" (symbol 258) and the
/// large-distance low-offset repeat code (offset symbols ≥ 10).
#[derive(Debug)]
pub struct LzDecoder {
    /// Sliding window. Output bytes go here and to the caller's
    /// `out` buffer in lockstep.
    dict: Dict,
    /// 4-slot recent-distance LRU. Touched by cached-distance
    /// symbols (259..=262), pushed by short-distance
    /// (263..=270) and full-match (271..=298) symbols.
    dist_cache: DistCache,
    /// Last `(offset, length)` pair the dispatcher actually
    /// emitted. Symbol 258 reuses these. `last_length == 0`
    /// means "no match emitted yet"; libarchive skips a 258
    /// symbol when `lastlength == 0` rather than erroring.
    last_offset: u32,
    /// See `last_offset`.
    last_length: u32,
    /// Last "low 4 bits" decoded from `lowoffsetcode` (for
    /// distance codes ≥ 10). Used when `num_low_offset_repeats`
    /// is non-zero or when the lowoffsetcode emits its sentinel
    /// symbol 16.
    last_low_offset: u32,
    /// Repeat counter for the low-offset sentinel (symbol 16
    /// → 15 repeats of `last_low_offset`). Decrements on each
    /// large-distance symbol that consumes a repeat.
    num_low_offset_repeats: u32,
}

impl LzDecoder {
    /// Construct an empty decoder with a dictionary of
    /// `dict_capacity` bytes.
    ///
    /// # Errors
    ///
    /// Surfaces [`DictError`] from [`Dict::new`] (zero or
    /// over-cap capacity).
    pub fn new(dict_capacity: usize) -> Result<Self, DictError> {
        Ok(Self {
            dict: Dict::new(dict_capacity)?,
            dist_cache: DistCache::new(),
            last_offset: 0,
            last_length: 0,
            last_low_offset: 0,
            num_low_offset_repeats: 0,
        })
    }

    /// Total bytes the dictionary has emitted across all calls.
    /// Diagnostic accessor; tests use it to verify a block's
    /// output without inspecting the dict directly.
    #[must_use]
    pub fn output_position(&self) -> u64 {
        self.dict.total_written()
    }

    /// Borrow the dictionary (for §C2's filter VM, which needs
    /// to pull staged output via [`Dict::copy_recent_into`]).
    #[must_use]
    pub fn dict(&self) -> &Dict {
        &self.dict
    }

    /// Decode one block's symbol stream until either symbol
    /// 256 (block end) or symbol 257 (filter-decl) is hit.
    ///
    /// Emits literal bytes and match payloads to `out` in
    /// stream order; the caller can drain `out` between calls
    /// without breaking the dispatcher's state.
    ///
    /// # Errors
    ///
    /// - [`LzError::Underrun`] if the bitstream ran out.
    /// - [`LzError::Huffman`] if one of the Huffman codes
    ///   rejected the input.
    /// - [`LzError::Dict`] if a back-reference was malformed.
    /// - [`LzError::InvalidSymbol`] if the length / offset /
    ///   lowoffset sub-alphabets emitted an out-of-range value.
    pub fn decode_block(
        &mut self,
        reader: &mut BitReader<'_>,
        tables: &MainTables,
        out: &mut Vec<u8>,
    ) -> Result<BlockEnd, LzError> {
        loop {
            let symbol = tables.main.decode(reader)?;
            match symbol {
                // Literal byte.
                0..=255 => {
                    self.dict.push_literal(symbol as u8, out);
                }
                // Block end (sub-bit decides whether the entry
                // continues with another block or stops).
                256 => {
                    let new_file = reader.read_bits(1)? != 0;
                    return Ok(if new_file {
                        BlockEnd::EntryDone
                    } else {
                        BlockEnd::NextBlock
                    });
                }
                // Filter declaration — §C2 handles.
                257 => {
                    return Ok(BlockEnd::FilterDecl);
                }
                // Repeat last match.
                258 => {
                    if self.last_length == 0 {
                        // Libarchive's "skip silently" path —
                        // the encoder occasionally emits this
                        // at the start of a block where no
                        // prior match exists. We just keep
                        // decoding.
                        continue;
                    }
                    let offs = self.last_offset;
                    let len = self.last_length;
                    self.emit_match(offs, len, out)?;
                }
                // Cached-distance match: idx = symbol - 259.
                259..=262 => {
                    let idx = (symbol - 259) as usize;
                    let offs = self.dist_cache.touch(idx);
                    let len = self.decode_length(reader, &tables.length)?;
                    self.emit_match(offs, len, out)?;
                }
                // Short-distance match (fixed length 2).
                263..=270 => {
                    let i = (symbol - 263) as usize;
                    let mut offs = SHORT_BASES[i] + 1;
                    if SHORT_BITS[i] > 0 {
                        offs += reader.read_bits(SHORT_BITS[i])?;
                    }
                    self.dist_cache.push(offs);
                    self.emit_match(offs, 2, out)?;
                }
                // Full match.
                _ => {
                    let len_idx = (symbol - 271) as usize;
                    if len_idx >= LENGTH_BASES.len() {
                        return Err(LzError::InvalidSymbol {
                            alphabet: "main",
                            symbol,
                            size: 271 + LENGTH_BASES.len() as u32,
                        });
                    }
                    let mut len = LENGTH_BASES[len_idx] + 3;
                    if LENGTH_BITS[len_idx] > 0 {
                        len += reader.read_bits(LENGTH_BITS[len_idx])?;
                    }
                    let offs = self.decode_full_offset(reader, tables)?;
                    if offs >= 0x40000 {
                        len += 1;
                    }
                    if offs >= 0x2000 {
                        len += 1;
                    }
                    self.dist_cache.push(offs);
                    self.emit_match(offs, len, out)?;
                }
            }
        }
    }

    /// Decode a length symbol (`lengthcode` alphabet) and the
    /// extra bits that follow. Used by the cached-distance
    /// branch.
    fn decode_length(
        &self,
        reader: &mut BitReader<'_>,
        length_code: &super::huffman::HuffmanCode,
    ) -> Result<u32, LzError> {
        let lensym = length_code.decode(reader)?;
        let i = lensym as usize;
        if i >= LENGTH_BASES.len() {
            return Err(LzError::InvalidSymbol {
                alphabet: "length",
                symbol: lensym,
                size: LENGTH_BASES.len() as u32,
            });
        }
        let mut len = LENGTH_BASES[i] + 2;
        if LENGTH_BITS[i] > 0 {
            len += reader.read_bits(LENGTH_BITS[i])?;
        }
        Ok(len)
    }

    /// Decode a full-match offset via the offset code +
    /// (for codes ≥ 10) the low-offset code.
    fn decode_full_offset(
        &mut self,
        reader: &mut BitReader<'_>,
        tables: &MainTables,
    ) -> Result<u32, LzError> {
        let offsym = tables.offset.decode(reader)?;
        let i = offsym as usize;
        if i >= OFFSET_BASES.len() {
            return Err(LzError::InvalidSymbol {
                alphabet: "offset",
                symbol: offsym,
                size: OFFSET_BASES.len() as u32,
            });
        }
        let mut offs = OFFSET_BASES[i] + 1;
        if OFFSET_BITS[i] > 0 {
            if i > 9 {
                // High bits: everything above bit 4.
                let high_bits = OFFSET_BITS[i] - 4;
                if high_bits > 0 {
                    offs += reader.read_bits(high_bits)? << 4;
                }
                // Low 4 bits via lowoffsetcode (with repeat
                // counter).
                if self.num_low_offset_repeats > 0 {
                    self.num_low_offset_repeats -= 1;
                    offs += self.last_low_offset;
                } else {
                    let lowsym = tables.low_offset.decode(reader)?;
                    if lowsym == 16 {
                        self.num_low_offset_repeats = 15;
                        offs += self.last_low_offset;
                    } else if (lowsym as u32) < 16 {
                        offs += lowsym as u32;
                        self.last_low_offset = lowsym as u32;
                    } else {
                        return Err(LzError::InvalidSymbol {
                            alphabet: "low_offset",
                            symbol: lowsym,
                            size: 17,
                        });
                    }
                }
            } else {
                offs += reader.read_bits(OFFSET_BITS[i])?;
            }
        }
        Ok(offs)
    }

    /// Emit a match: write `length` bytes to the dictionary
    /// from `offset` bytes back, append the produced bytes to
    /// `out`, update `last_*` state.
    fn emit_match(&mut self, offset: u32, length: u32, out: &mut Vec<u8>) -> Result<(), LzError> {
        self.dict
            .copy_match(u64::from(offset), u64::from(length), out)?;
        self.last_offset = offset;
        self.last_length = length;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::rar_legacy::bootstrap::{
        LENGTH_CODE_SIZE, LOW_OFFSET_CODE_SIZE, MAIN_CODE_SIZE, OFFSET_CODE_SIZE,
    };
    use crate::decode::rar_legacy::huffman::HuffmanCode;

    /// Pack a sequence of `(value, n_bits)` MSB-first. Shared
    /// shape with the bits / huffman / bootstrap test helpers.
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

    /// Canonical codes per RFC 1951 §3.2.2. Tests use this to
    /// learn which bit pattern encodes which symbol.
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

    /// Build a `MainTables` from per-code symbol-length arrays.
    /// Empty (all-zero) arrays yield an empty alphabet — fine
    /// for tests that don't exercise that particular code.
    fn build_tables(
        main_lens: &[u8],
        length_lens: &[u8],
        offset_lens: &[u8],
        low_offset_lens: &[u8],
    ) -> MainTables {
        assert!(main_lens.len() <= MAIN_CODE_SIZE);
        assert!(length_lens.len() <= LENGTH_CODE_SIZE);
        assert!(offset_lens.len() <= OFFSET_CODE_SIZE);
        assert!(low_offset_lens.len() <= LOW_OFFSET_CODE_SIZE);
        let mut main = vec![0u8; MAIN_CODE_SIZE];
        main[..main_lens.len()].copy_from_slice(main_lens);
        let mut length = vec![0u8; LENGTH_CODE_SIZE];
        length[..length_lens.len()].copy_from_slice(length_lens);
        let mut offset = vec![0u8; OFFSET_CODE_SIZE];
        offset[..offset_lens.len()].copy_from_slice(offset_lens);
        let mut low_offset = vec![0u8; LOW_OFFSET_CODE_SIZE];
        low_offset[..low_offset_lens.len()].copy_from_slice(low_offset_lens);
        MainTables {
            main: HuffmanCode::build(&main).unwrap(),
            offset: HuffmanCode::build(&offset).unwrap(),
            low_offset: HuffmanCode::build(&low_offset).unwrap(),
            length: HuffmanCode::build(&length).unwrap(),
        }
    }

    // ---- literal-only blocks -------------------------------------

    #[test]
    fn literal_run_then_block_end_with_new_file() {
        // Main code: symbols 'A' (0x41) and 'B' (0x42) at len 2,
        // 256 (block-end) at len 1. Canonical codes:
        //   256 → 0
        //   0x41 → 10
        //   0x42 → 11
        let mut main_lens = [0u8; MAIN_CODE_SIZE];
        main_lens[0x41] = 2;
        main_lens[0x42] = 2;
        main_lens[256] = 1;
        let canon = canonical_codes(&main_lens);
        let tables = build_tables(&main_lens, &[], &[], &[]);

        // Emit "ABAB" then symbol 256 with new_file = 1.
        let mut pairs = Vec::new();
        for &sym in &[0x41u32, 0x42, 0x41, 0x42] {
            pairs.push((canon[sym as usize], u32::from(main_lens[sym as usize])));
        }
        pairs.push((canon[256], 1));
        pairs.push((1, 1)); // new_file = 1
        let mut bytes = pack_msb(&pairs);
        bytes.push(0); // tail padding for max-code-length peek

        let mut br = BitReader::new(&bytes);
        let mut dec = LzDecoder::new(64).unwrap();
        let mut out = Vec::new();
        let end = dec.decode_block(&mut br, &tables, &mut out).unwrap();
        assert_eq!(end, BlockEnd::EntryDone);
        assert_eq!(out, b"ABAB");
        assert_eq!(dec.output_position(), 4);
    }

    #[test]
    fn block_end_with_new_file_clear_returns_next_block() {
        let mut main_lens = [0u8; MAIN_CODE_SIZE];
        main_lens[256] = 1;
        main_lens[0x5A] = 1;
        let canon = canonical_codes(&main_lens);
        let tables = build_tables(&main_lens, &[], &[], &[]);

        // Emit just symbol 256 with new_file = 0.
        let pairs = vec![(canon[256], 1), (0, 1)];
        let mut bytes = pack_msb(&pairs);
        bytes.push(0);

        let mut br = BitReader::new(&bytes);
        let mut dec = LzDecoder::new(64).unwrap();
        let mut out = Vec::new();
        let end = dec.decode_block(&mut br, &tables, &mut out).unwrap();
        assert_eq!(end, BlockEnd::NextBlock);
        assert!(out.is_empty());
    }

    #[test]
    fn filter_decl_surfaces_directly() {
        let mut main_lens = [0u8; MAIN_CODE_SIZE];
        main_lens[257] = 1;
        main_lens[256] = 1;
        let canon = canonical_codes(&main_lens);
        let tables = build_tables(&main_lens, &[], &[], &[]);

        let pairs = vec![(canon[257], 1)];
        let mut bytes = pack_msb(&pairs);
        bytes.push(0);
        let mut br = BitReader::new(&bytes);
        let mut dec = LzDecoder::new(64).unwrap();
        let mut out = Vec::new();
        let end = dec.decode_block(&mut br, &tables, &mut out).unwrap();
        assert_eq!(end, BlockEnd::FilterDecl);
    }

    // ---- match-emit branches -------------------------------------

    /// Helper that builds a 4-symbol main code suitable for
    /// emitting a short-distance match (symbol 263+) followed
    /// by block-end. Returns the assembled bytes + tables.
    fn build_short_distance_fixture(
        short_symbol: u32,
        short_extra_bits_value: u32,
    ) -> (Vec<u8>, MainTables) {
        let short_index = short_symbol as usize - 263;
        assert!(short_index < SHORT_BASES.len());
        let mut main_lens = [0u8; MAIN_CODE_SIZE];
        main_lens[0x42] = 2; // literal 'B'
        main_lens[short_symbol as usize] = 2;
        main_lens[256] = 1;
        let canon = canonical_codes(&main_lens);
        let tables = build_tables(&main_lens, &[], &[], &[]);

        // Stream: 4 literal B's, then short-distance match.
        let mut pairs = Vec::new();
        for _ in 0..4 {
            pairs.push((canon[0x42], u32::from(main_lens[0x42])));
        }
        pairs.push((
            canon[short_symbol as usize],
            u32::from(main_lens[short_symbol as usize]),
        ));
        if SHORT_BITS[short_index] > 0 {
            pairs.push((short_extra_bits_value, SHORT_BITS[short_index]));
        }
        pairs.push((canon[256], 1));
        pairs.push((1, 1));
        let mut bytes = pack_msb(&pairs);
        bytes.push(0);
        (bytes, tables)
    }

    #[test]
    fn short_distance_symbol_263_emits_two_byte_match_at_distance_one() {
        // Symbol 263 → distance base = 0 + 1 = 1, +2 extra bits.
        // With extra-bits = 0, distance = 1. Match length is
        // always 2 for short-distance. After "BBBB" (4 bytes),
        // emit "BB" from distance 1, total "BBBBBB".
        let (bytes, tables) = build_short_distance_fixture(263, 0);
        let mut br = BitReader::new(&bytes);
        let mut dec = LzDecoder::new(64).unwrap();
        let mut out = Vec::new();
        let end = dec.decode_block(&mut br, &tables, &mut out).unwrap();
        assert_eq!(end, BlockEnd::EntryDone);
        assert_eq!(out, b"BBBBBB");
        // dist_cache slot 0 should hold the new offset.
        assert_eq!(dec.dist_cache.peek(0), 1);
    }

    #[test]
    fn short_distance_symbol_264_uses_base_four() {
        // Symbol 264 → base 4 + 1 = 5, +2 extra bits.
        // We need the dict to have at least 5 bytes of history.
        // Seed with 8 'B's, then 264 + extra = 0 → distance 5.
        let mut main_lens = [0u8; MAIN_CODE_SIZE];
        main_lens[0x42] = 2;
        main_lens[264] = 2;
        main_lens[256] = 1;
        let canon = canonical_codes(&main_lens);
        let tables = build_tables(&main_lens, &[], &[], &[]);

        let mut pairs = Vec::new();
        for _ in 0..8 {
            pairs.push((canon[0x42], 2));
        }
        pairs.push((canon[264], 2));
        pairs.push((0, 2));
        pairs.push((canon[256], 1));
        pairs.push((1, 1));
        let mut bytes = pack_msb(&pairs);
        bytes.push(0);
        let mut br = BitReader::new(&bytes);
        let mut dec = LzDecoder::new(64).unwrap();
        let mut out = Vec::new();
        dec.decode_block(&mut br, &tables, &mut out).unwrap();
        // 8 'B's + 2-byte match from distance 5 = "BBBBBBBBBB".
        assert_eq!(out, b"BBBBBBBBBB");
        assert_eq!(dec.dist_cache.peek(0), 5);
    }

    #[test]
    fn cached_distance_symbol_259_touches_slot_zero() {
        // 1) Push distance 5 via symbol 264 + extra 0 → distance 5.
        // 2) Emit literal C (different from the seed) at some point.
        // 3) Touch slot 0 via symbol 259 + lengthcode-symbol-0
        //    (length = 0 + 2 = 2).
        // Code lengths chosen for a complete Kraft tree:
        //   one len-1 (256) + four len-3 → 1/2 + 4/8 = 1.0.
        let mut main_lens = [0u8; MAIN_CODE_SIZE];
        main_lens[0x42] = 3; // 'B'
        main_lens[0x43] = 3; // 'C'
        main_lens[264] = 3; // push dist 5
        main_lens[259] = 3; // touch slot 0
        main_lens[256] = 1;
        let canon = canonical_codes(&main_lens);

        // Length code: just symbol 0 (len 1) → base 0 + 2 = 2.
        let mut length_lens = [0u8; LENGTH_CODE_SIZE];
        length_lens[0] = 1;
        let lcanon = canonical_codes(&length_lens);
        let tables = build_tables(&main_lens, &length_lens, &[], &[]);

        let mut pairs = Vec::new();
        // 8 'B's so dict has plenty of history.
        for _ in 0..8 {
            pairs.push((canon[0x42], 3));
        }
        // Push distance 5: symbol 264 + 2 extra bits = 0.
        pairs.push((canon[264], 3));
        pairs.push((0, 2));
        // Emit a literal 'C' so subsequent touch's match is
        // clearly distinguishable in output.
        pairs.push((canon[0x43], 3));
        // Now touch slot 0 (distance 5) with length 2.
        pairs.push((canon[259], 3));
        pairs.push((lcanon[0], 1));
        // Block end.
        pairs.push((canon[256], 1));
        pairs.push((1, 1));
        let mut bytes = pack_msb(&pairs);
        bytes.push(0);

        let mut br = BitReader::new(&bytes);
        let mut dec = LzDecoder::new(64).unwrap();
        let mut out = Vec::new();
        dec.decode_block(&mut br, &tables, &mut out).unwrap();
        // 8 B's + match-from-distance-5-len-2 → "BBBBBBBBBB", then
        // literal 'C' → "BBBBBBBBBBC", then match-from-distance-5-len-2
        // (touches slot 0 = 5) → pulls bytes at output position 6..=7,
        // which are 'B', 'B' → "BBBBBBBBBBCBB".
        assert_eq!(out, b"BBBBBBBBBBCBB");
    }

    #[test]
    fn repeat_last_symbol_258_replays_recent_pair() {
        // After establishing a short-distance match, symbol 258
        // replays the same (offset, length) without consulting
        // the cache.
        let mut main_lens = [0u8; MAIN_CODE_SIZE];
        main_lens[0x42] = 2;
        main_lens[263] = 2;
        main_lens[258] = 2;
        main_lens[256] = 2;
        let canon = canonical_codes(&main_lens);
        let tables = build_tables(&main_lens, &[], &[], &[]);

        let mut pairs = Vec::new();
        for _ in 0..4 {
            pairs.push((canon[0x42], 2));
        }
        // Match: symbol 263, distance 1, length 2 → "BB".
        pairs.push((canon[263], 2));
        pairs.push((0, 2));
        // Repeat-last: emit another "BB" via symbol 258.
        pairs.push((canon[258], 2));
        // Block end.
        pairs.push((canon[256], 2));
        pairs.push((1, 1));
        let mut bytes = pack_msb(&pairs);
        bytes.push(0);

        let mut br = BitReader::new(&bytes);
        let mut dec = LzDecoder::new(64).unwrap();
        let mut out = Vec::new();
        dec.decode_block(&mut br, &tables, &mut out).unwrap();
        // 4 B's + match BB + repeat BB = 8 B's.
        assert_eq!(out, b"BBBBBBBB");
    }

    #[test]
    fn symbol_258_at_block_start_is_skipped_silently() {
        // Symbol 258 before any match has been emitted → skipped,
        // not an error. Stream goes straight to block-end.
        let mut main_lens = [0u8; MAIN_CODE_SIZE];
        main_lens[258] = 1;
        main_lens[256] = 1;
        let canon = canonical_codes(&main_lens);
        let tables = build_tables(&main_lens, &[], &[], &[]);

        let pairs = vec![(canon[258], 1), (canon[256], 1), (1, 1)];
        let mut bytes = pack_msb(&pairs);
        bytes.push(0);
        let mut br = BitReader::new(&bytes);
        let mut dec = LzDecoder::new(64).unwrap();
        let mut out = Vec::new();
        let end = dec.decode_block(&mut br, &tables, &mut out).unwrap();
        assert_eq!(end, BlockEnd::EntryDone);
        assert!(out.is_empty());
    }

    #[test]
    fn full_match_symbol_271_small_distance() {
        // Symbol 271 → len base = 0 + 3 = 3, 0 extra bits.
        // Offset symbol 0 → base = 0 + 1 = 1, 0 extra bits.
        // After "BBBBBB", emit 3-byte match at distance 1 → "BBB".
        let mut main_lens = [0u8; MAIN_CODE_SIZE];
        main_lens[0x42] = 2;
        main_lens[271] = 2;
        main_lens[256] = 1;
        let canon = canonical_codes(&main_lens);
        let mut offset_lens = [0u8; OFFSET_CODE_SIZE];
        offset_lens[0] = 1;
        let ocanon = canonical_codes(&offset_lens);
        let tables = build_tables(&main_lens, &[], &offset_lens, &[]);

        let mut pairs = Vec::new();
        for _ in 0..6 {
            pairs.push((canon[0x42], 2));
        }
        // Symbol 271 (length-base 0 + 3 = 3, no extra bits).
        pairs.push((canon[271], 2));
        // Offset symbol 0 (distance-base 0 + 1 = 1, no extra bits).
        pairs.push((ocanon[0], 1));
        // Block end.
        pairs.push((canon[256], 1));
        pairs.push((1, 1));
        let mut bytes = pack_msb(&pairs);
        bytes.push(0);

        let mut br = BitReader::new(&bytes);
        let mut dec = LzDecoder::new(64).unwrap();
        let mut out = Vec::new();
        dec.decode_block(&mut br, &tables, &mut out).unwrap();
        // 6 B's + 3-byte match at distance 1 = 9 B's.
        assert_eq!(out, b"BBBBBBBBB");
        // Length-bump: offs < 0x2000 so no extra bump applied.
        assert_eq!(dec.last_length, 3);
    }

    #[test]
    fn full_match_offset_above_0x2000_bumps_length_by_one() {
        // Need distance > 0x2000 (= 8192). Offset symbol 26 →
        // base 8192 + extra-bits 12 → distance range
        // 8193..=12288 (all > 8192, all < 0x40000 = 262 144).
        // → exactly one length bump.
        // offsetbits[26] = 12; high-bits = 12 - 4 = 8; then low
        // 4 bits from lowoffsetcode.
        let mut main_lens = [0u8; MAIN_CODE_SIZE];
        main_lens[0x42] = 2;
        main_lens[271] = 2; // length-base 0 → len = 3 + bump
        main_lens[256] = 1;
        let canon = canonical_codes(&main_lens);
        let mut offset_lens = [0u8; OFFSET_CODE_SIZE];
        offset_lens[26] = 1;
        let ocanon = canonical_codes(&offset_lens);
        let mut low_lens = [0u8; LOW_OFFSET_CODE_SIZE];
        low_lens[0] = 1;
        let lcanon = canonical_codes(&low_lens);
        let tables = build_tables(&main_lens, &[], &offset_lens, &low_lens);

        let mut pairs = Vec::new();
        // Seed 8200 B's so dict has enough history for the
        // distance-8193 back-reference.
        for _ in 0..8200 {
            pairs.push((canon[0x42], 2));
        }
        // Symbol 271 (len = 3).
        pairs.push((canon[271], 2));
        // Offset symbol 26 (offset base 8192 + 1 = 8193).
        pairs.push((ocanon[26], 1));
        // High-bits (offsetbits[26] - 4 = 8) = 0.
        pairs.push((0, 8));
        // Low 4 bits via lowoffsetcode-symbol 0 (= 0).
        pairs.push((lcanon[0], 1));
        // Block end.
        pairs.push((canon[256], 1));
        pairs.push((1, 1));
        let mut bytes = pack_msb(&pairs);
        bytes.push(0);

        let mut br = BitReader::new(&bytes);
        let mut dec = LzDecoder::new(16384).unwrap();
        let mut out = Vec::new();
        dec.decode_block(&mut br, &tables, &mut out).unwrap();
        // Distance 8193: > 0x2000, < 0x40000 → exactly one
        // length bump: len = 3 + 1 = 4.
        assert_eq!(dec.last_length, 4);
        assert_eq!(dec.last_offset, 8193);
        // Total output: 8200 literals + 4 from match.
        assert_eq!(out.len(), 8204);
        // The match bytes should all be 'B' (seeded window is
        // all B).
        assert!(out[8200..].iter().all(|&b| b == b'B'));
    }

    #[test]
    fn full_match_low_offset_repeat_sentinel() {
        // Low-offset symbol 16 = "use last_low_offset, set repeat
        // counter to 15". Test by emitting two large-distance
        // matches in a row: first establishes last_low_offset = 0,
        // second uses symbol 16 to reuse it.
        let mut main_lens = [0u8; MAIN_CODE_SIZE];
        main_lens[0x42] = 2;
        main_lens[271] = 2;
        main_lens[256] = 1;
        let canon = canonical_codes(&main_lens);
        let mut offset_lens = [0u8; OFFSET_CODE_SIZE];
        offset_lens[24] = 1;
        let ocanon = canonical_codes(&offset_lens);
        // Low offset code: symbol 0 (low 4 bits = 0) and symbol
        // 16 (repeat sentinel), both at len 1. Codes: 0 → 0,
        // 16 → 1.
        let mut low_lens = [0u8; LOW_OFFSET_CODE_SIZE];
        low_lens[0] = 1;
        low_lens[16] = 1;
        let lcanon = canonical_codes(&low_lens);
        let tables = build_tables(&main_lens, &[], &offset_lens, &low_lens);

        let mut pairs = Vec::new();
        for _ in 0..4100 {
            pairs.push((canon[0x42], 2));
        }
        // First match: symbol 271 + offset-symbol 24 + 7-bit
        // high = 0 + lowoffsetcode = 0 (sets last_low_offset = 0).
        pairs.push((canon[271], 2));
        pairs.push((ocanon[24], 1));
        pairs.push((0, 7));
        pairs.push((lcanon[0], 1));
        // Second match: same offset symbol but lowoffsetcode = 16
        // (repeat sentinel, sets num_low_offset_repeats = 15 and
        // uses last_low_offset = 0).
        pairs.push((canon[271], 2));
        pairs.push((ocanon[24], 1));
        pairs.push((0, 7));
        pairs.push((lcanon[16], 1));
        // Third match: uses the repeat counter directly (no
        // lowoffsetcode read).
        pairs.push((canon[271], 2));
        pairs.push((ocanon[24], 1));
        pairs.push((0, 7));
        // Block end.
        pairs.push((canon[256], 1));
        pairs.push((1, 1));
        let mut bytes = pack_msb(&pairs);
        bytes.push(0);

        let mut br = BitReader::new(&bytes);
        let mut dec = LzDecoder::new(8192).unwrap();
        let mut out = Vec::new();
        dec.decode_block(&mut br, &tables, &mut out).unwrap();
        // After all three matches, num_low_offset_repeats should
        // have decremented once (from 15 to 14) on the third
        // match.
        assert_eq!(dec.num_low_offset_repeats, 14);
        assert_eq!(dec.last_low_offset, 0);
        assert_eq!(dec.last_offset, 4097);
    }

    // ---- error surfacing ------------------------------------------

    #[test]
    fn truncated_bitstream_surfaces_underrun() {
        let mut main_lens = [0u8; MAIN_CODE_SIZE];
        main_lens[0x42] = 1;
        main_lens[256] = 1;
        let canon = canonical_codes(&main_lens);
        let tables = build_tables(&main_lens, &[], &[], &[]);

        // Single literal symbol; no block-end follows.
        let pairs = vec![(canon[0x42], 1)];
        let bytes = pack_msb(&pairs);
        let mut br = BitReader::new(&bytes);
        let mut dec = LzDecoder::new(64).unwrap();
        let mut out = Vec::new();
        let err = dec.decode_block(&mut br, &tables, &mut out).unwrap_err();
        // The decoder consumed the literal then peeked past EOF
        // for the next symbol → Underrun via Huffman.
        match err {
            LzError::Huffman(HuffmanError::Underrun(_)) | LzError::Underrun(_) => {}
            other => panic!("expected Underrun, got {other:?}"),
        }
    }

    #[test]
    fn malformed_offset_underflow_surfaces_dict_error() {
        // Emit a full-match symbol 271 + offset symbol 0 (distance
        // = 1) BEFORE pushing any literals → back-reference
        // underflow.
        let mut main_lens = [0u8; MAIN_CODE_SIZE];
        main_lens[271] = 1;
        main_lens[256] = 1;
        let canon = canonical_codes(&main_lens);
        let mut offset_lens = [0u8; OFFSET_CODE_SIZE];
        offset_lens[0] = 1;
        let ocanon = canonical_codes(&offset_lens);
        let tables = build_tables(&main_lens, &[], &offset_lens, &[]);

        let pairs = vec![(canon[271], 1), (ocanon[0], 1)];
        let mut bytes = pack_msb(&pairs);
        bytes.push(0);
        let mut br = BitReader::new(&bytes);
        let mut dec = LzDecoder::new(64).unwrap();
        let mut out = Vec::new();
        let err = dec.decode_block(&mut br, &tables, &mut out).unwrap_err();
        assert!(matches!(
            err,
            LzError::Dict(DictError::BackReferenceUnderflow { .. })
        ));
    }
}
