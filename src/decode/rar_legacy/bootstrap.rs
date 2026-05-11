//! Per-block Huffman-table bootstrap for the legacy RAR LZ
//! pipeline.
//!
//! Each non-PPMd block in the LZ stream carries the four
//! Huffman trees it'll use (main / offset / low-offset / length).
//! The trees aren't shipped raw — they're materialised from a
//! single 404-entry "main length table" that's itself entropy-
//! coded via a 20-entry "precode" Huffman tree, which is in turn
//! shipped as twenty 4-bit literal lengths. This module
//! implements the three layers:
//!
//! 1. [`read_precode_lengths`] — 20 × 4-bit literals with a
//!    `0xF`-prefixed zero-run escape.
//! 2. [`read_main_lengths`] — 404 main-table lengths produced
//!    by decoding precode symbols (`0..=15` = delta mod 16,
//!    `16..=17` = repeat-last, `18..=19` = zero-run).
//! 3. [`build_main_tables`] — slice the 404 lengths into four
//!    sub-tables and run [`HuffmanCode::build`] on each.
//!
//! Layered so each step's invariants are independently testable;
//! §C1c's block-header parser stitches them together with the
//! `align_to_byte` + `is_ppmd_block` flag + `keep_old_tables`
//! flag the block prologue carries.
//!
//! # The delta-from-previous-block trick
//!
//! Libarchive's per-block `lengthtable` is *not* reset between
//! blocks — when a block's prologue clears the
//! `keep_old_tables` flag, the table is memset to zero; when the
//! flag is set, the table retains its values from the previous
//! block. Each main-length entry then encodes a *delta* from the
//! retained value: `lengthtable[i] = (lengthtable[i] + val) & 0xF`.
//! [`read_main_lengths`] takes the persistent `&mut [u8; 404]`
//! buffer and applies updates in place; the caller owns the
//! reset / retain decision.
//!
//! # Reference
//!
//! Libarchive's `parse_codes` function (lines 2301..2540 of
//! `archive_read_support_format_rar.c`). The repeat counts and
//! magic constants in this module match libarchive's bit-for-bit.

use thiserror::Error;

use super::bits::{BitReadError, BitReader};
use super::huffman::{HuffmanCode, HuffmanError};

/// Number of literal/length symbols in the main code
/// (libarchive's `MAINCODE_SIZE`).
pub const MAIN_CODE_SIZE: usize = 299;
/// Number of distance symbols in the offset code
/// (libarchive's `OFFSETCODE_SIZE`).
pub const OFFSET_CODE_SIZE: usize = 60;
/// Number of low-distance-bits symbols in the low-offset code
/// (libarchive's `LOWOFFSETCODE_SIZE`).
pub const LOW_OFFSET_CODE_SIZE: usize = 17;
/// Number of length symbols in the length code
/// (libarchive's `LENGTHCODE_SIZE`).
pub const LENGTH_CODE_SIZE: usize = 28;
/// Total size of the main length table (sum of the four sub-table
/// sizes). Libarchive's `HUFFMAN_TABLE_SIZE`.
pub const MAIN_TABLE_TOTAL: usize =
    MAIN_CODE_SIZE + OFFSET_CODE_SIZE + LOW_OFFSET_CODE_SIZE + LENGTH_CODE_SIZE;
/// Number of precode symbols (libarchive's `MAX_SYMBOLS`).
pub const PRECODE_SIZE: usize = 20;

/// Errors produced during the per-block Huffman bootstrap.
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// The bitstream ran out of input mid-table.
    #[error("legacy RAR block bootstrap underran the bitstream")]
    Underrun(#[from] BitReadError),

    /// Building one of the Huffman codes failed (over-/under-
    /// subscribed alphabet, code-length overflow, etc.).
    #[error("legacy RAR block bootstrap failed to build a Huffman code")]
    HuffmanBuild(#[from] HuffmanError),

    /// The main-length stream emitted a repeat-last opcode (16
    /// or 17) at index 0 — no previous entry exists to repeat.
    /// Matches libarchive's `Internal error extracting RAR file`
    /// at `parse_codes` line 2466.
    #[error(
        "legacy RAR block bootstrap saw a repeat-last opcode \
         ({opcode}) at index 0 — no previous length to repeat"
    )]
    RepeatLastAtStart {
        /// The opcode value (16 or 17).
        opcode: u16,
    },

    /// The precode decoded a symbol outside the valid `0..=19`
    /// range. Defensive guard: a successful [`HuffmanCode::build`]
    /// on a 20-entry alphabet can only return symbols in `0..20`,
    /// so this only fires if the build was given malformed input
    /// that nonetheless validated.
    #[error("legacy RAR block bootstrap precode emitted symbol {symbol} (expected 0..=19)")]
    InvalidPrecodeSymbol {
        /// The out-of-range symbol value.
        symbol: u16,
    },
}

/// The four Huffman codes a single block uses for its LZ
/// dispatch, returned by [`build_main_tables`].
#[derive(Debug)]
pub struct MainTables {
    /// Literal / length code (`MAIN_CODE_SIZE` = 299 symbols).
    pub main: HuffmanCode,
    /// Distance code (`OFFSET_CODE_SIZE` = 60 symbols).
    pub offset: HuffmanCode,
    /// Low-distance-bits code (`LOW_OFFSET_CODE_SIZE` = 17 symbols).
    pub low_offset: HuffmanCode,
    /// Length code (`LENGTH_CODE_SIZE` = 28 symbols).
    pub length: HuffmanCode,
}

/// Read the 20 precode bit-lengths from `reader`.
///
/// Wire format: twenty entries, each a 4-bit literal length. A
/// raw `0xF` is followed by another 4-bit `zerocount`; if
/// `zerocount > 0`, the `0xF` is replaced by `zerocount + 2`
/// zero entries (clamped to the remaining buffer space).
/// `zerocount == 0` keeps the `0xF` as a literal length-15 entry.
///
/// # Errors
///
/// - [`BootstrapError::Underrun`] if the bitstream runs out
///   before all 20 entries are filled.
pub fn read_precode_lengths(
    reader: &mut BitReader<'_>,
) -> Result<[u8; PRECODE_SIZE], BootstrapError> {
    let mut lens = [0u8; PRECODE_SIZE];
    let mut i = 0usize;
    while i < PRECODE_SIZE {
        let len = reader.read_bits(4)? as u8;
        lens[i] = len;
        i += 1;
        if len == 0xF {
            let zerocount = reader.read_bits(4)? as usize;
            if zerocount > 0 {
                // Overwrite the 0xF and fill with zeros. The
                // run is `zerocount + 2` entries, clamped to the
                // remaining buffer.
                i -= 1;
                let run = zerocount + 2;
                let end = (i + run).min(PRECODE_SIZE);
                while i < end {
                    lens[i] = 0;
                    i += 1;
                }
            }
        }
    }
    Ok(lens)
}

/// Read the 404 main-table bit-lengths from `reader` using the
/// supplied `precode`.
///
/// `lengths` is the persistent per-entry buffer the caller owns
/// across blocks. If the block's `keep_old_tables` flag was set,
/// the caller hands in the previous block's buffer; otherwise
/// the caller zeros it first. Each entry the precode emits is
/// either a delta from the existing value (`val ∈ 0..=15`), a
/// repeat-last opcode (16/17), or a zero-run opcode (18/19);
/// updates apply in place.
///
/// # Wire format
///
/// Symbol values, decoded one at a time via `precode`:
///
/// - `0..=15` — `lengths[i] = (lengths[i] + val) & 0xF`; advance.
/// - `16` — read 3 bits + 3 = repeat count in `3..=10`; fill
///   that many entries with `lengths[i-1]`. Errors if `i == 0`.
/// - `17` — read 7 bits + 11 = repeat count in `11..=138`; same
///   semantics as `16`.
/// - `18` — read 3 bits + 3 = zero-run count; fill that many
///   entries with `0`.
/// - `19` — read 7 bits + 11 = zero-run count; same semantics
///   as `18`.
///
/// Runs are clamped to the remaining buffer (`MAIN_TABLE_TOTAL -
/// i`) — libarchive tolerates over-long counts silently, and
/// `peel` matches that to stay byte-identical on the corpus.
///
/// # Errors
///
/// - [`BootstrapError::Underrun`] if the bitstream runs out
///   before all 404 entries are filled.
/// - [`BootstrapError::HuffmanBuild`] surfaced from
///   `precode.decode` if the precode rejected the input.
/// - [`BootstrapError::RepeatLastAtStart`] if a `16` / `17`
///   opcode lands at `i == 0`.
/// - [`BootstrapError::InvalidPrecodeSymbol`] if `precode`
///   decodes a symbol outside `0..=19`.
pub fn read_main_lengths(
    reader: &mut BitReader<'_>,
    precode: &HuffmanCode,
    lengths: &mut [u8; MAIN_TABLE_TOTAL],
) -> Result<(), BootstrapError> {
    let mut i = 0usize;
    while i < MAIN_TABLE_TOTAL {
        let val = precode.decode(reader)?;
        match val {
            0..=15 => {
                // Delta-mod-16 from the existing entry.
                lengths[i] = (lengths[i].wrapping_add(val as u8)) & 0xF;
                i += 1;
            }
            16 | 17 => {
                if i == 0 {
                    return Err(BootstrapError::RepeatLastAtStart { opcode: val });
                }
                let n = if val == 16 {
                    reader.read_bits(3)? as usize + 3
                } else {
                    reader.read_bits(7)? as usize + 11
                };
                let prev = lengths[i - 1];
                let end = (i + n).min(MAIN_TABLE_TOTAL);
                while i < end {
                    lengths[i] = prev;
                    i += 1;
                }
            }
            18 | 19 => {
                let n = if val == 18 {
                    reader.read_bits(3)? as usize + 3
                } else {
                    reader.read_bits(7)? as usize + 11
                };
                let end = (i + n).min(MAIN_TABLE_TOTAL);
                while i < end {
                    lengths[i] = 0;
                    i += 1;
                }
            }
            other => return Err(BootstrapError::InvalidPrecodeSymbol { symbol: other }),
        }
    }
    Ok(())
}

/// Slice the 404-entry length buffer into the four canonical
/// Huffman trees the LZ dispatcher consumes.
///
/// # Errors
///
/// Surfaces [`HuffmanError`] from [`HuffmanCode::build`] for any
/// of the four sub-tables (wrapped in [`BootstrapError::HuffmanBuild`]).
pub fn build_main_tables(lengths: &[u8; MAIN_TABLE_TOTAL]) -> Result<MainTables, BootstrapError> {
    let main_end = MAIN_CODE_SIZE;
    let offset_end = main_end + OFFSET_CODE_SIZE;
    let low_offset_end = offset_end + LOW_OFFSET_CODE_SIZE;
    let length_end = low_offset_end + LENGTH_CODE_SIZE;
    debug_assert_eq!(length_end, MAIN_TABLE_TOTAL);

    let main = HuffmanCode::build(&lengths[..main_end])?;
    let offset = HuffmanCode::build(&lengths[main_end..offset_end])?;
    let low_offset = HuffmanCode::build(&lengths[offset_end..low_offset_end])?;
    let length = HuffmanCode::build(&lengths[low_offset_end..length_end])?;
    Ok(MainTables {
        main,
        offset,
        low_offset,
        length,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: pack a sequence of (value, n_bits) tuples MSB-first
    /// into bytes. Same shape as the helpers in [`super::bits`]
    /// and [`super::huffman`] — duplicated here to keep each
    /// module's tests self-contained.
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

    /// Canonical-code lookup, used to manufacture wire-format
    /// streams for the precode-driven main-length tests.
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

    // ---- precode ---------------------------------------------------

    #[test]
    fn precode_reads_twenty_literal_four_bit_lengths() {
        // Each entry chosen so no entry equals 0xF (so no escape
        // path fires).
        let expected: [u8; PRECODE_SIZE] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0, 1, 2, 3, 4, 5,
        ];
        let pairs: Vec<(u32, u32)> = expected.iter().map(|&v| (u32::from(v), 4)).collect();
        let bytes = pack_msb(&pairs);
        let mut br = BitReader::new(&bytes);
        let got = read_precode_lengths(&mut br).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn precode_literal_15_is_kept_when_zerocount_is_zero() {
        // Entry 5 is literal 0xF (zerocount = 0).
        let mut pairs: Vec<(u32, u32)> = (0..PRECODE_SIZE)
            .map(|i| {
                if i == 5 {
                    // Will be followed by a 4-bit zerocount=0
                    (0xF, 4)
                } else {
                    (u32::from(((i as u8) & 0x07) + 1), 4)
                }
            })
            .collect();
        // Insert the zerocount = 0 directly after the 0xF entry.
        // Find the position of (0xF, 4) and add (0, 4) right after.
        let mut expanded = Vec::with_capacity(pairs.len() + 1);
        let mut inserted = false;
        for &p in pairs.iter() {
            expanded.push(p);
            if !inserted && p == (0xF, 4) {
                expanded.push((0, 4));
                inserted = true;
            }
        }
        pairs = expanded;
        let bytes = pack_msb(&pairs);
        let mut br = BitReader::new(&bytes);
        let got = read_precode_lengths(&mut br).unwrap();
        // Entry 5 should be 0xF; other entries match the input.
        assert_eq!(got[5], 0xF);
        for (i, &v) in got.iter().enumerate() {
            if i != 5 {
                assert_eq!(v, ((i as u8) & 0x07) + 1);
            }
        }
    }

    #[test]
    fn precode_zerocount_escape_writes_zerorun() {
        // Build: 3 literal entries, then 0xF + zerocount = 5 → 7
        // zeros, then literals to fill out to 20.
        // We need: indices 0..=2 literal, 0xF at index 3 with
        // zerocount=5, so indices 3..=9 become 0, then 10..=19
        // literal.
        let mut pairs: Vec<(u32, u32)> = vec![
            (1, 4),
            (2, 4),
            (3, 4),
            (0xF, 4),
            (5, 4), // zerocount = 5 → 7 zeros at indices 3..=9
        ];
        for i in 10..PRECODE_SIZE {
            pairs.push((u32::from(((i as u8) & 0x07) + 1), 4));
        }
        let bytes = pack_msb(&pairs);
        let mut br = BitReader::new(&bytes);
        let got = read_precode_lengths(&mut br).unwrap();
        assert_eq!(&got[..3], &[1u8, 2, 3]);
        for (i, v) in got.iter().enumerate().take(10).skip(3) {
            assert_eq!(*v, 0, "expected zero at index {i}");
        }
        for (i, v) in got.iter().enumerate().skip(10) {
            assert_eq!(*v, ((i as u8) & 0x07) + 1);
        }
    }

    #[test]
    fn precode_zerocount_run_truncates_at_buffer_end() {
        // Place 0xF at index 19 (the last slot) with a large
        // zerocount; the run should be silently truncated to a
        // single zero overwriting index 19.
        let mut pairs: Vec<(u32, u32)> = vec![(1, 4); 19];
        pairs.push((0xF, 4));
        pairs.push((15, 4)); // zerocount = 15 → 17 zeros, but only 1 slot left
        let bytes = pack_msb(&pairs);
        let mut br = BitReader::new(&bytes);
        let got = read_precode_lengths(&mut br).unwrap();
        for v in got.iter().take(19) {
            assert_eq!(*v, 1);
        }
        assert_eq!(got[19], 0);
    }

    #[test]
    fn precode_underruns_on_truncated_input() {
        let bytes = [0u8; 9]; // 9 bytes = 72 bits; need 80
        let mut br = BitReader::new(&bytes);
        let err = read_precode_lengths(&mut br).unwrap_err();
        assert!(matches!(err, BootstrapError::Underrun(_)));
    }

    // ---- main-length parser ---------------------------------------

    /// Build a simple precode whose first few symbols cover the
    /// special opcodes used by the main-length tests.
    fn precode_with_short_codes(symbol_to_len: &[(u16, u8)]) -> (HuffmanCode, Vec<u8>) {
        let mut lens = vec![0u8; PRECODE_SIZE];
        for &(sym, l) in symbol_to_len {
            lens[sym as usize] = l;
        }
        let code = HuffmanCode::build(&lens).unwrap();
        (code, lens)
    }

    #[test]
    fn main_lengths_delta_mod_sixteen_updates_in_place() {
        // Precode with two symbols: 0 (len 1) and 1 (len 1).
        // Stream: 404 reads alternating 0/1; each 0 leaves the
        // prior value, each 1 adds 1 mod 16. Seed `lengths` to a
        // ramp so we can see the deltas accumulate.
        let (precode, code_lens) = precode_with_short_codes(&[(0, 1), (1, 1)]);
        let canon = canonical_codes(&code_lens);
        // Stream 404 alternating 0,1 symbols.
        let pairs: Vec<(u32, u32)> = (0..MAIN_TABLE_TOTAL).map(|i| (canon[i & 1], 1)).collect();
        let bytes = pack_msb(&pairs);
        let mut br = BitReader::new(&bytes);
        let mut lengths = [0u8; MAIN_TABLE_TOTAL];
        // Seed every other slot at 5 so we can see (5+0)&15=5
        // and (5+1)&15=6 alternation.
        for i in (0..MAIN_TABLE_TOTAL).step_by(2) {
            lengths[i] = 5;
        }
        read_main_lengths(&mut br, &precode, &mut lengths).unwrap();
        for (i, &v) in lengths.iter().enumerate() {
            if i % 2 == 0 {
                assert_eq!(v, 5, "even index {i} should keep its seeded 5");
            } else {
                assert_eq!(v, 1, "odd index {i} should be 0+1=1");
            }
        }
    }

    #[test]
    fn main_lengths_repeat_last_small_opcode_fills_with_prev() {
        // Precode: symbol 5 (len 1) → encode 5, then ext 3-bit
        // value 0 → repeat-last 3 times. We seed lengths[0] so
        // the repeat-last has something to copy.
        // To get to lengths[0] = 5, we issue: (5, 1-bit code "0").
        // Then we need to keep going: emit val=16 followed by
        // 3-bit 0 → n=3 copies of lengths[0]=5 at lengths[1..=3].
        // Then we need to emit MAIN_TABLE_TOTAL - 4 more entries.
        // We'll use opcode 19 (zero-run, large) to bulk-fill.
        let (precode, code_lens) = precode_with_short_codes(&[(5, 2), (16, 2), (19, 1)]);
        let canon = canonical_codes(&code_lens);
        let mut pairs: Vec<(u32, u32)> = vec![
            // Emit symbol 5 once → lengths[0] = 0 + 5 = 5.
            (canon[5], 2),
            // Emit symbol 16 + 3-bit 0 → n = 3 repeats of lengths[0].
            (canon[16], 2),
            (0, 3),
        ];
        // After: i = 4. Need 400 more. Use opcode 19 + 7-bit value
        // 127 + 11 = 138 zeros — issue 19 enough times to fill.
        // 400 / 138 ≈ 2.9, so we issue 3 reps and the last gets
        // clamped to the buffer.
        for _ in 0..3 {
            pairs.push((canon[19], 1));
            pairs.push((127, 7));
        }
        let bytes = pack_msb(&pairs);
        let mut br = BitReader::new(&bytes);
        let mut lengths = [0u8; MAIN_TABLE_TOTAL];
        read_main_lengths(&mut br, &precode, &mut lengths).unwrap();
        assert_eq!(lengths[0], 5);
        for (i, v) in lengths.iter().enumerate().take(4).skip(1) {
            assert_eq!(*v, 5, "index {i} should be repeat-last 5");
        }
        for (i, v) in lengths.iter().enumerate().skip(4) {
            assert_eq!(*v, 0, "index {i} should be zero-filled");
        }
    }

    #[test]
    fn main_lengths_zero_run_opcode_skips_entries() {
        // Use symbol 18 + 3-bit value 0 → 3 zeros, and symbol 19
        // + 7-bit value 0 → 11 zeros, sprinkled with literal 5s
        // to fill the remainder.
        let (precode, code_lens) = precode_with_short_codes(&[(5, 2), (18, 2), (19, 1)]);
        let canon = canonical_codes(&code_lens);
        let mut pairs: Vec<(u32, u32)> = vec![
            // i=0: 18 + 0 → 3 zeros (i becomes 3, no change to delta=0).
            (canon[18], 2),
            (0, 3),
            // i=3: emit 5 once.
            (canon[5], 2),
            // i=4: 19 + 0 → 11 zeros (i becomes 15).
            (canon[19], 1),
            (0, 7),
        ];
        // i=15..: bulk zero-fill. Keep issuing 19+max-7-bit until
        // we overflow; runtime clamps the last one.
        for _ in 0..27 {
            pairs.push((canon[19], 1));
            pairs.push((127, 7));
        }
        let bytes = pack_msb(&pairs);
        let mut br = BitReader::new(&bytes);
        let mut lengths = [0u8; MAIN_TABLE_TOTAL];
        read_main_lengths(&mut br, &precode, &mut lengths).unwrap();
        for (i, v) in lengths.iter().enumerate().take(3) {
            assert_eq!(*v, 0, "zero-run at {i}");
        }
        assert_eq!(lengths[3], 5);
        for (i, v) in lengths.iter().enumerate().skip(4) {
            assert_eq!(*v, 0, "expected zero at {i}");
        }
    }

    #[test]
    fn main_lengths_repeat_last_at_zero_index_errors() {
        // First main-length symbol is 16 — illegal at i == 0.
        let (precode, code_lens) = precode_with_short_codes(&[(16, 1)]);
        let canon = canonical_codes(&code_lens);
        let pairs: Vec<(u32, u32)> = vec![(canon[16], 1), (0, 3)];
        let bytes = pack_msb(&pairs);
        let mut br = BitReader::new(&bytes);
        let mut lengths = [0u8; MAIN_TABLE_TOTAL];
        let err = read_main_lengths(&mut br, &precode, &mut lengths).unwrap_err();
        match err {
            BootstrapError::RepeatLastAtStart { opcode } => assert_eq!(opcode, 16),
            other => panic!("expected RepeatLastAtStart, got {other:?}"),
        }
    }

    #[test]
    fn main_lengths_seventeen_at_zero_index_errors() {
        let (precode, code_lens) = precode_with_short_codes(&[(17, 1)]);
        let canon = canonical_codes(&code_lens);
        let pairs: Vec<(u32, u32)> = vec![(canon[17], 1), (0, 7)];
        let bytes = pack_msb(&pairs);
        let mut br = BitReader::new(&bytes);
        let mut lengths = [0u8; MAIN_TABLE_TOTAL];
        let err = read_main_lengths(&mut br, &precode, &mut lengths).unwrap_err();
        match err {
            BootstrapError::RepeatLastAtStart { opcode } => assert_eq!(opcode, 17),
            other => panic!("expected RepeatLastAtStart, got {other:?}"),
        }
    }

    #[test]
    fn delta_mod_sixteen_wraps_at_15_plus_one() {
        // Seed lengths[0] = 15; emit symbol 1 → (15 + 1) & 0xF = 0.
        // Same as the libarchive masked-add semantic.
        let (precode, code_lens) = precode_with_short_codes(&[(1, 1), (19, 1)]);
        let canon = canonical_codes(&code_lens);
        let mut pairs: Vec<(u32, u32)> = vec![(canon[1], 1)];
        // Bulk-zero the remaining 403 with opcode 19.
        for _ in 0..3 {
            pairs.push((canon[19], 1));
            pairs.push((127, 7));
        }
        let bytes = pack_msb(&pairs);
        let mut br = BitReader::new(&bytes);
        let mut lengths = [0u8; MAIN_TABLE_TOTAL];
        lengths[0] = 15;
        read_main_lengths(&mut br, &precode, &mut lengths).unwrap();
        assert_eq!(lengths[0], 0, "(15 + 1) & 15 = 0");
    }

    // ---- four-tree extraction -------------------------------------

    #[test]
    fn build_main_tables_slices_into_four_canonical_codes() {
        // Build a 404-entry length table with a known per-section
        // distribution; verify each sub-table builds and the
        // populated/empty status comes out right.
        let mut lens = [0u8; MAIN_TABLE_TOTAL];
        // Main: every symbol at length 9 (a complete tree at
        // depth 9 holds 512 symbols, easily covering 299).
        for v in lens[..MAIN_CODE_SIZE].iter_mut() {
            *v = 9;
        }
        // Offset: complete length-6 tree for the first 60 symbols.
        for v in lens[MAIN_CODE_SIZE..MAIN_CODE_SIZE + OFFSET_CODE_SIZE].iter_mut() {
            *v = 6;
        }
        // Low-offset: leave empty — confirm the empty-alphabet
        // path lights up.
        // Length: length-5 tree for first 28.
        for v in lens[MAIN_CODE_SIZE + OFFSET_CODE_SIZE + LOW_OFFSET_CODE_SIZE..].iter_mut() {
            *v = 5;
        }
        let tables = build_main_tables(&lens).unwrap();
        assert_eq!(tables.main.bits(), 9);
        assert!(tables.main.is_populated());
        assert_eq!(tables.offset.bits(), 6);
        assert!(tables.offset.is_populated());
        assert!(!tables.low_offset.is_populated());
        assert_eq!(tables.length.bits(), 5);
        assert!(tables.length.is_populated());
    }

    #[test]
    fn build_main_tables_surfaces_huffman_error_on_oversub() {
        // Force the main code to over-subscribe: 3 symbols at
        // length 1 → Kraft > 1.
        let mut lens = [0u8; MAIN_TABLE_TOTAL];
        lens[0] = 1;
        lens[1] = 1;
        lens[2] = 1;
        let err = build_main_tables(&lens).unwrap_err();
        match err {
            BootstrapError::HuffmanBuild(HuffmanError::OverSubscribed) => {}
            other => panic!("expected HuffmanBuild(OverSubscribed), got {other:?}"),
        }
    }

    // ---- end-to-end small round trip ------------------------------

    #[test]
    fn end_to_end_precode_then_main_then_build() {
        // 1. Construct precode lengths covering the symbols we'll
        //    emit downstream: 5 / 16 / 18 / 19.
        let mut precode_lens = [0u8; PRECODE_SIZE];
        precode_lens[5] = 2;
        precode_lens[16] = 2;
        precode_lens[18] = 2;
        precode_lens[19] = 2;
        // 2. Encode the precode lengths as the 20 4-bit literals.
        let precode_pairs: Vec<(u32, u32)> =
            precode_lens.iter().map(|&v| (u32::from(v), 4)).collect();
        // 3. Build the precode tree and the canonical codes for
        //    its symbols.
        let precode = HuffmanCode::build(&precode_lens).unwrap();
        let canon = canonical_codes(&precode_lens);
        // 4. Encode a main-length stream: bulk-zero with 19 then
        //    add a literal 5 at position 100.
        let mut main_pairs: Vec<(u32, u32)> = Vec::new();
        // 100 zeros via 19 + 7-bit value (89 → +11 = 100).
        main_pairs.push((canon[19], 2));
        main_pairs.push((89, 7));
        // i = 100: emit 5 → length 5 at index 100.
        main_pairs.push((canon[5], 2));
        // Bulk-zero the rest: 19 + 7-bit max = 138 zeros each.
        // Need 303 more after i=101. 138*3 = 414 > 303, so 3 reps
        // suffice and the last is clamped.
        for _ in 0..3 {
            main_pairs.push((canon[19], 2));
            main_pairs.push((127, 7));
        }
        // 5. Concatenate precode lengths then main stream and
        //    drive the bootstrap end-to-end.
        let mut all = precode_pairs.clone();
        all.extend(main_pairs.iter().copied());
        let bytes = pack_msb(&all);
        let mut br = BitReader::new(&bytes);
        let read_lens = read_precode_lengths(&mut br).unwrap();
        assert_eq!(read_lens, precode_lens);
        let mut lengths = [0u8; MAIN_TABLE_TOTAL];
        read_main_lengths(&mut br, &precode, &mut lengths).unwrap();
        assert_eq!(lengths[100], 5);
        for (i, v) in lengths.iter().enumerate().take(100) {
            assert_eq!(*v, 0, "expected zero at {i}");
        }
        for (i, v) in lengths.iter().enumerate().skip(101) {
            assert_eq!(*v, 0, "expected zero at {i}");
        }
        // The build step also has to land. Main is empty except
        // at index 100 (length 5) → 1-symbol alphabet, populated.
        let tables = build_main_tables(&lengths).unwrap();
        assert!(tables.main.is_populated());
        assert!(!tables.offset.is_populated());
        assert!(!tables.low_offset.is_populated());
        assert!(!tables.length.is_populated());
    }
}
