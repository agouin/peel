//! RAR5 code-length bootstrap.
//!
//! Decodes the per-block code-length tables RAR5's LZSS dispatcher
//! needs from the input bitstream. The bootstrap layout matches
//! libarchive's `archive_read_support_format_rar5.c`'s
//! `parse_tables` function (Grzegorz Antoniak, BSD 2-Clause; see
//! [`NOTICE`](../../../NOTICE) at the repo root). Two stages:
//!
//! 1. Read [`HUFF_BC`] = 20 4-bit values into the meta-Huffman's
//!    code-length array. Stage-1 has a single ESCAPE marker (the
//!    nibble value `15`) that distinguishes "literal length 15"
//!    from "run of zeros" without spending a full meta-symbol per
//!    case.
//! 2. Build the meta-Huffman canonical decoder via
//!    [`super::huffman::HuffTable`] and use it to decode the
//!    [`HUFF_TABLE_SIZE`] = 430 main-table code lengths. Stage-2
//!    uses meta-symbols 0..15 for literal lengths and 16..19 for
//!    repeat / zero-fill codes (each with its own extra-bit
//!    width).
//!
//! # Stage-1 ESCAPE encoding (libarchive's `parse_tables` head)
//!
//! ```text
//! while emitted < HUFF_BC:
//!     v = read_4_bits()
//!     if v != 15:
//!         emit length v
//!     else:
//!         w = read_4_bits()
//!         if w == 0: emit length 15 (literal)
//!         else:      emit (w + 2) zeros
//! ```
//!
//! # Stage-2 meta-symbol semantics (libarchive's `parse_tables` body)
//!
//! ```text
//! while i < HUFF_TABLE_SIZE:
//!     num = meta_huffman.decode()
//!     if num <  16: table[i++] = num
//!     elif num == 16: read 3 extra bits, emit table[i-1] (3 + extra) times
//!     elif num == 17: read 7 extra bits, emit table[i-1] (11 + extra) times
//!     elif num == 18: read 3 extra bits, emit 0          (3 + extra) times
//!     elif num == 19: read 7 extra bits, emit 0          (11 + extra) times
//! ```
//!
//! Note this is **subtly different from RFC 1951 / DEFLATE**:
//! DEFLATE has 19 meta-symbols (16/17/18); RAR5 has 20 (16/17/18/19).
//! DEFLATE's 16 is "repeat-prev base 3, 2 extra"; RAR5's 16 is
//! "repeat-prev base 3, 3 extra". The base / extra-bit pairs
//! below come straight from libarchive's source.

use thiserror::Error;

use super::bits::{BitReadError, BitReader};
use super::huffman::{HuffTable, HuffmanError};

/// Number of meta-symbols in the meta-Huffman alphabet.
/// libarchive's `HUFF_BC` = 20.
pub const HUFF_BC: usize = 20;

/// Total main-table length count: literal/length + distance +
/// repeated-distance + low-distance. Matches libarchive's
/// `HUFF_TABLE_SIZE = HUFF_NC + HUFF_DC + HUFF_RC + HUFF_LDC =
/// 306 + 64 + 44 + 16 = 430`.
pub const HUFF_TABLE_SIZE: usize = 306 + 64 + 44 + 16;

/// Width of each stage-1 length nibble on the wire.
const STAGE1_LEN_BITS: u32 = 4;

/// Stage-1 ESCAPE marker: a 4-bit value of 15 in the meta-Huffman
/// code-length stream introduces a literal-15-or-zero-run choice
/// (see module docs).
const STAGE1_ESCAPE: u32 = 15;

/// Stage-2 wire codes that map to repeat / zero-fill meta-symbols.
/// Codes 0..15 are literal lengths.
const META_REPEAT_PREV_SHORT: u16 = 16; // 3 extra bits, base 3
const META_REPEAT_PREV_LONG: u16 = 17; // 7 extra bits, base 11
const META_ZERO_RUN_SHORT: u16 = 18; // 3 extra bits, base 3
const META_ZERO_RUN_LONG: u16 = 19; // 7 extra bits, base 11

/// Errors produced by the bootstrap decoder.
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// Stage-1 produced a fatal length value (e.g. emitted more
    /// than [`HUFF_BC`] entries via a runaway zero-fill).
    #[error("RAR5 bootstrap stage-1 emitted past HUFF_BC ({HUFF_BC})")]
    Stage1Overrun,

    /// Stage-2 emitted past the caller's expected count via a
    /// repeat-or-zero run.
    #[error(
        "RAR5 bootstrap stage-2 emitted past HUFF_TABLE_SIZE \
         ({HUFF_TABLE_SIZE}): would emit {would_emit}"
    )]
    Stage2Overrun {
        /// Symbol count after the overrunning repeat.
        would_emit: usize,
    },

    /// A `META_REPEAT_PREV_*` code fired before any literal
    /// length had been emitted in this block.
    #[error("RAR5 bootstrap repeat-previous before any literal length emitted")]
    RepeatPrevWithoutPrior,

    /// The meta-Huffman emitted a wire code outside `0..20`.
    /// Indicates either a malformed bitstream or a bug in
    /// stage-1 code-length assembly.
    #[error(
        "RAR5 bootstrap meta-Huffman emitted out-of-range code \
         {wire_code} (valid range 0..20)"
    )]
    BadMetaSymbol {
        /// The wire-code value the meta-Huffman emitted.
        wire_code: u16,
    },

    /// The supplied meta-Huffman length array failed
    /// canonical-Huffman validation.
    #[error("RAR5 bootstrap meta-Huffman alphabet rejected by canonical builder")]
    Stage1Huffman(#[source] HuffmanError),

    /// The meta-Huffman's [`HuffTable::decode`] surfaced a
    /// missing-prefix or under-subscribed match.
    #[error("RAR5 bootstrap stage-2 meta-Huffman decode failed")]
    Stage2Decode(#[source] HuffmanError),

    /// The bit reader ran out of input.
    #[error("RAR5 bootstrap underran the bitstream")]
    Underrun(#[from] BitReadError),
}

/// Read the meta-Huffman alphabet's code-length array off
/// `reader` (stage 1 of the bootstrap; libarchive's `parse_tables`
/// head).
///
/// Returns 20 lengths, each in 0..=15. The wire encoding uses
/// the ESCAPE convention described at the module level: a nibble
/// of `15` flips into a literal-vs-zero-run prefix.
///
/// # Errors
///
/// - [`BootstrapError::Underrun`] if the bitstream runs out.
/// - [`BootstrapError::Stage1Overrun`] if a runaway zero-run
///   would emit past the 20-symbol cap.
pub fn read_meta_huffman_lengths(
    reader: &mut BitReader<'_>,
) -> Result<[u8; HUFF_BC], BootstrapError> {
    let mut lengths = [0u8; HUFF_BC];
    let mut emitted: usize = 0;
    while emitted < HUFF_BC {
        let v = reader.read_bits(STAGE1_LEN_BITS)?;
        if v != STAGE1_ESCAPE {
            // Literal length value.
            lengths[emitted] = v as u8;
            emitted += 1;
        } else {
            // ESCAPE: read the next 4-bit nibble.
            let w = reader.read_bits(STAGE1_LEN_BITS)?;
            if w == 0 {
                // Literal length 15.
                lengths[emitted] = 15;
                emitted += 1;
            } else {
                // Run of (w + 2) zeros.
                let count = (w as usize) + 2;
                let next = emitted
                    .checked_add(count)
                    .ok_or(BootstrapError::Stage1Overrun)?;
                if next > HUFF_BC {
                    return Err(BootstrapError::Stage1Overrun);
                }
                // The slots are already zero from initialization;
                // just advance.
                emitted = next;
            }
        }
    }
    Ok(lengths)
}

/// Decode the main-table code lengths off `reader` using
/// `meta_huffman` (stage 2 of the bootstrap; libarchive's
/// `parse_tables` body).
///
/// `out` is sized to [`HUFF_TABLE_SIZE`] entries; on entry it must
/// be all-zero. The decoder writes lengths in order and uses
/// the meta-symbol semantics documented at the module level
/// (literal / repeat-prev-short / repeat-prev-long / zero-run-short
/// / zero-run-long).
///
/// # Errors
///
/// - [`BootstrapError::Stage2Decode`] for meta-Huffman miss.
/// - [`BootstrapError::BadMetaSymbol`] for a wire code ≥ 20.
/// - [`BootstrapError::RepeatPrevWithoutPrior`] for a
///   `repeat-prev` meta-symbol issued before any literal length.
/// - [`BootstrapError::Stage2Overrun`] for a runaway repeat or
///   zero-fill that pushes past `HUFF_TABLE_SIZE`.
/// - [`BootstrapError::Underrun`] for bitstream exhaustion.
pub fn decode_main_table_lengths(
    reader: &mut BitReader<'_>,
    meta_huffman: &HuffTable,
    out: &mut [u8; HUFF_TABLE_SIZE],
) -> Result<(), BootstrapError> {
    let mut i: usize = 0;
    while i < HUFF_TABLE_SIZE {
        let num = meta_huffman
            .decode(reader)
            .map_err(BootstrapError::Stage2Decode)?;
        if num < 16 {
            // INVARIANT: num < 16, so the cast is lossless.
            out[i] = num as u8;
            i += 1;
        } else {
            let (extra_bits, base, is_repeat_prev) = match num {
                META_REPEAT_PREV_SHORT => (3u32, 3usize, true),
                META_REPEAT_PREV_LONG => (7u32, 11usize, true),
                META_ZERO_RUN_SHORT => (3u32, 3usize, false),
                META_ZERO_RUN_LONG => (7u32, 11usize, false),
                other => return Err(BootstrapError::BadMetaSymbol { wire_code: other }),
            };
            let extra = reader.read_bits(extra_bits)? as usize;
            let count = base + extra;
            let next = i.checked_add(count).ok_or(BootstrapError::Stage2Overrun {
                would_emit: usize::MAX,
            })?;
            if next > HUFF_TABLE_SIZE {
                return Err(BootstrapError::Stage2Overrun { would_emit: next });
            }
            if is_repeat_prev {
                if i == 0 {
                    return Err(BootstrapError::RepeatPrevWithoutPrior);
                }
                let prev = out[i - 1];
                for slot in &mut out[i..next] {
                    *slot = prev;
                }
            }
            // For zero-run: slots are already zero; nothing to do.
            i = next;
        }
    }
    Ok(())
}

/// Convenience: build the meta-Huffman from a length array.
///
/// Translates [`HuffmanError`] into [`BootstrapError::Stage1Huffman`].
///
/// # Errors
///
/// - [`BootstrapError::Stage1Huffman`] for over-subscribed or
///   length-too-large alphabets.
pub fn build_meta_huffman(lengths: &[u8; HUFF_BC]) -> Result<HuffTable, BootstrapError> {
    HuffTable::build(lengths).map_err(BootstrapError::Stage1Huffman)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: encode `(value, n)` pairs into MSB-first bytes.
    fn encode_bits(pairs: &[(u32, u32)]) -> Vec<u8> {
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

    /// Helper: compute canonical codes for the supplied lengths.
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

    /// Helper: a flat 5-bit-per-symbol meta-Huffman (every code
    /// length = 5; total = 20 × 1/32 < 1 → well-formed).
    fn flat_meta_lengths() -> [u8; HUFF_BC] {
        [5u8; HUFF_BC]
    }

    #[test]
    fn stage1_reads_20_literal_nibbles() {
        // No ESCAPE: 20 nibbles in 0..15.
        let lengths: [u8; HUFF_BC] = std::array::from_fn(|i| (i % 15) as u8);
        let pairs: Vec<(u32, u32)> = lengths
            .iter()
            .map(|&l| (u32::from(l), STAGE1_LEN_BITS))
            .collect();
        let bytes = encode_bits(&pairs);
        let mut reader = BitReader::new(&bytes);
        let got = read_meta_huffman_lengths(&mut reader).unwrap();
        assert_eq!(got, lengths);
    }

    #[test]
    fn stage1_escape_with_zero_emits_literal_15() {
        // Emit lengths [3, 15, 7] then 17 zeros (filler) so the
        // total fits HUFF_BC = 20.
        // Literal 15 is encoded via ESCAPE+0:
        //   3, ESCAPE+0 (= literal 15), 7, then 17 zeros via two
        //   ESCAPE runs (15-byte run + 2-byte run).
        // To reach 20 emitted: 1 (3) + 1 (15) + 1 (7) + zeros.
        // Need 17 zeros: ESCAPE + 14 (run = 16 zeros) + ESCAPE + ?
        //   That's 16 zeros total; but a single ESCAPE run can be
        //   max 17 (w=15 → count 17). Use ESCAPE+15 → 17 zeros.
        let pairs: Vec<(u32, u32)> = vec![
            (3, 4),
            (15, 4),
            (0, 4), // ESCAPE+0 → literal 15
            (7, 4),
            (15, 4),
            (15, 4), // ESCAPE+15 → 17 zeros
        ];
        let bytes = encode_bits(&pairs);
        let mut reader = BitReader::new(&bytes);
        let got = read_meta_huffman_lengths(&mut reader).unwrap();
        let mut expected = [0u8; HUFF_BC];
        expected[0] = 3;
        expected[1] = 15;
        expected[2] = 7;
        // Slots 3..20 are zero — already initialized.
        assert_eq!(got, expected);
    }

    #[test]
    fn stage1_escape_with_w_emits_zero_run() {
        // ESCAPE+5 → 7 zeros. Then 13 literal nibbles.
        // 7 + 13 = 20 = HUFF_BC.
        let mut pairs: Vec<(u32, u32)> = vec![
            (15, 4),
            (5, 4), // ESCAPE+5 → 7 zeros
        ];
        for i in 0..13u32 {
            pairs.push(((i + 1) & 0xF, 4));
        }
        let bytes = encode_bits(&pairs);
        let mut reader = BitReader::new(&bytes);
        let got = read_meta_huffman_lengths(&mut reader).unwrap();
        let mut expected = [0u8; HUFF_BC];
        for (i, slot) in expected[7..20].iter_mut().enumerate() {
            *slot = ((i as u32 + 1) & 0xF) as u8;
        }
        assert_eq!(got, expected);
    }

    #[test]
    fn stage1_zero_run_overflowing_huff_bc_errors() {
        // 5 literal lengths, then ESCAPE+15 (17 zeros) — pushes
        // emitted to 22 > HUFF_BC.
        let mut pairs: Vec<(u32, u32)> = Vec::new();
        for _ in 0..5 {
            pairs.push((1, 4));
        }
        pairs.push((15, 4));
        pairs.push((15, 4));
        let bytes = encode_bits(&pairs);
        let mut reader = BitReader::new(&bytes);
        let err = read_meta_huffman_lengths(&mut reader).unwrap_err();
        assert!(matches!(err, BootstrapError::Stage1Overrun));
    }

    #[test]
    fn stage2_literal_lengths_round_trip() {
        let meta_lengths = flat_meta_lengths();
        let meta_table = build_meta_huffman(&meta_lengths).unwrap();
        let codes = canonical_codes(&meta_lengths);

        // Emit 430 literal lengths; encode each as the canonical
        // code for that length (0..15). Use a deterministic
        // pattern so we can assert exact recovery.
        let expected: Vec<u8> = (0..HUFF_TABLE_SIZE).map(|i| (i % 16) as u8).collect();
        let pairs: Vec<(u32, u32)> = expected.iter().map(|&l| (codes[l as usize], 5)).collect();
        let bytes = encode_bits(&pairs);
        let mut reader = BitReader::new(&bytes);
        let mut out = [0u8; HUFF_TABLE_SIZE];
        decode_main_table_lengths(&mut reader, &meta_table, &mut out).unwrap();
        assert_eq!(&out[..], &expected[..]);
    }

    #[test]
    fn stage2_repeat_prev_short_replays_3_extra() {
        // Emit Length(7), then META_REPEAT_PREV_SHORT (16) with
        // extra=0 (count=3) → expected [7, 7, 7, 7] at slots 0..4,
        // then literal 0 elsewhere.
        let meta_lengths = flat_meta_lengths();
        let meta_table = build_meta_huffman(&meta_lengths).unwrap();
        let codes = canonical_codes(&meta_lengths);

        let mut pairs: Vec<(u32, u32)> = Vec::new();
        pairs.push((codes[7], 5));
        pairs.push((codes[16], 5));
        pairs.push((0, 3)); // 3 extra bits, value 0 → count 3
                            // Pad with literal 0 lengths to fill out HUFF_TABLE_SIZE.
        for _ in 0..(HUFF_TABLE_SIZE - 4) {
            pairs.push((codes[0], 5));
        }
        let bytes = encode_bits(&pairs);
        let mut reader = BitReader::new(&bytes);
        let mut out = [0u8; HUFF_TABLE_SIZE];
        decode_main_table_lengths(&mut reader, &meta_table, &mut out).unwrap();
        assert_eq!(out[0], 7);
        assert_eq!(out[1], 7);
        assert_eq!(out[2], 7);
        assert_eq!(out[3], 7);
        for slot in &out[4..] {
            assert_eq!(*slot, 0);
        }
    }

    #[test]
    fn stage2_repeat_prev_long_replays_7_extra() {
        // Length(5), META_REPEAT_PREV_LONG (17) with extra=20
        // (count = 11 + 20 = 31). Slots 0..32 = 5; rest = 0.
        let meta_lengths = flat_meta_lengths();
        let meta_table = build_meta_huffman(&meta_lengths).unwrap();
        let codes = canonical_codes(&meta_lengths);

        let mut pairs: Vec<(u32, u32)> = Vec::new();
        pairs.push((codes[5], 5));
        pairs.push((codes[17], 5));
        pairs.push((20, 7));
        for _ in 0..(HUFF_TABLE_SIZE - 32) {
            pairs.push((codes[0], 5));
        }
        let bytes = encode_bits(&pairs);
        let mut reader = BitReader::new(&bytes);
        let mut out = [0u8; HUFF_TABLE_SIZE];
        decode_main_table_lengths(&mut reader, &meta_table, &mut out).unwrap();
        for slot in &out[..32] {
            assert_eq!(*slot, 5);
        }
        for slot in &out[32..] {
            assert_eq!(*slot, 0);
        }
    }

    #[test]
    fn stage2_repeat_prev_without_prior_errors() {
        // Very first meta-symbol is REPEAT_PREV_SHORT → error.
        let meta_lengths = flat_meta_lengths();
        let meta_table = build_meta_huffman(&meta_lengths).unwrap();
        let codes = canonical_codes(&meta_lengths);

        let pairs: Vec<(u32, u32)> = vec![(codes[16], 5), (0, 3)];
        let bytes = encode_bits(&pairs);
        let mut reader = BitReader::new(&bytes);
        let mut out = [0u8; HUFF_TABLE_SIZE];
        let err = decode_main_table_lengths(&mut reader, &meta_table, &mut out).unwrap_err();
        assert!(matches!(err, BootstrapError::RepeatPrevWithoutPrior));
    }

    #[test]
    fn stage2_zero_run_short_emits_3_extra() {
        // Length(3), META_ZERO_RUN_SHORT (18) with extra=2
        // (count = 3 + 2 = 5). Slot 0 = 3; slots 1..6 = 0; rest = 0.
        let meta_lengths = flat_meta_lengths();
        let meta_table = build_meta_huffman(&meta_lengths).unwrap();
        let codes = canonical_codes(&meta_lengths);

        let mut pairs: Vec<(u32, u32)> = Vec::new();
        pairs.push((codes[3], 5));
        pairs.push((codes[18], 5));
        pairs.push((2, 3));
        for _ in 0..(HUFF_TABLE_SIZE - 6) {
            pairs.push((codes[0], 5));
        }
        let bytes = encode_bits(&pairs);
        let mut reader = BitReader::new(&bytes);
        let mut out = [0u8; HUFF_TABLE_SIZE];
        decode_main_table_lengths(&mut reader, &meta_table, &mut out).unwrap();
        assert_eq!(out[0], 3);
        for slot in &out[1..6] {
            assert_eq!(*slot, 0);
        }
        for slot in &out[6..] {
            assert_eq!(*slot, 0);
        }
    }

    #[test]
    fn stage2_zero_run_long_emits_7_extra() {
        // META_ZERO_RUN_LONG (19) with extra=100
        // (count = 11 + 100 = 111). Slots 0..111 = 0; rest = literal 0s.
        let meta_lengths = flat_meta_lengths();
        let meta_table = build_meta_huffman(&meta_lengths).unwrap();
        let codes = canonical_codes(&meta_lengths);

        let mut pairs: Vec<(u32, u32)> = Vec::new();
        pairs.push((codes[19], 5));
        pairs.push((100, 7));
        for _ in 0..(HUFF_TABLE_SIZE - 111) {
            pairs.push((codes[0], 5));
        }
        let bytes = encode_bits(&pairs);
        let mut reader = BitReader::new(&bytes);
        let mut out = [0u8; HUFF_TABLE_SIZE];
        decode_main_table_lengths(&mut reader, &meta_table, &mut out).unwrap();
        for slot in &out[..] {
            assert_eq!(*slot, 0);
        }
    }

    #[test]
    fn stage2_repeat_overrunning_huff_table_size_errors() {
        // After 5 literals, REPEAT_PREV_LONG with extra=127
        // (count = 11 + 127 = 138). Total emitted = 5 + 138 = 143
        // < 430, so this isn't an overrun. Use a setup that
        // genuinely overruns: 425 literals + ZERO_RUN_LONG with
        // count > 5.
        let meta_lengths = flat_meta_lengths();
        let meta_table = build_meta_huffman(&meta_lengths).unwrap();
        let codes = canonical_codes(&meta_lengths);

        let mut pairs: Vec<(u32, u32)> = Vec::new();
        for _ in 0..425 {
            pairs.push((codes[1], 5));
        }
        // ZERO_RUN_LONG with extra=127 → count 138. Pushes
        // emitted to 425 + 138 = 563 > 430.
        pairs.push((codes[19], 5));
        pairs.push((127, 7));
        let bytes = encode_bits(&pairs);
        let mut reader = BitReader::new(&bytes);
        let mut out = [0u8; HUFF_TABLE_SIZE];
        let err = decode_main_table_lengths(&mut reader, &meta_table, &mut out).unwrap_err();
        match err {
            BootstrapError::Stage2Overrun { would_emit } => {
                assert_eq!(would_emit, 425 + 138);
            }
            other => panic!("expected Stage2Overrun, got {other:?}"),
        }
    }

    #[test]
    fn huff_table_size_matches_libarchive_constants() {
        // Sanity: HUFF_NC + HUFF_DC + HUFF_RC + HUFF_LDC.
        assert_eq!(HUFF_TABLE_SIZE, 306 + 64 + 44 + 16);
        assert_eq!(HUFF_TABLE_SIZE, 430);
        assert_eq!(HUFF_BC, 20);
    }
}
