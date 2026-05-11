//! Per-block prologue parser for the legacy RAR LZ pipeline.
//!
//! Each block in the compressed stream begins with a short
//! header that selects the mode (LZ vs. PPMd) and supplies the
//! per-block state the next layer needs:
//!
//! - **LZ mode** — a `keep_old_tables` flag controlling whether
//!   the persistent 404-entry length buffer carries over from
//!   the previous block, followed by the precode + main-length +
//!   four-tree extraction §C1b lands.
//! - **PPMd mode** — a 7-bit `ppmd_flags` byte whose
//!   `0x20` / `0x40` bits gate the dictionary-size + max-order
//!   re-init payload and the init-escape byte respectively.
//!
//! Mirrors libarchive's `parse_codes` (lines 2301..2540 of
//! `archive_read_support_format_rar.c`). The prologue's actual
//! state transitions — running the PPMd-context allocator,
//! kicking the range decoder, plumbing the new Huffman tables
//! into the LZ dispatcher — live in §C1e (LZ) and §C1g (PPMd);
//! this module is purely "read the bits, surface a typed result".
//!
//! # The first bit is byte-aligned
//!
//! Even though the inner LZ stream is a continuous bitstream,
//! every block begins on a byte boundary. The prologue's first
//! operation is therefore [`BitReader::align_to_byte`], matching
//! libarchive's `rar_br_consume_unaligned_bits` macro at line
//! 2314 of the reference.
//!
//! # State the caller owns
//!
//! [`parse_block_prologue`] takes a mutable reference to the
//! persistent 404-entry length buffer; in LZ mode the function
//! either zeros it (when `keep_old_tables` is cleared) or leaves
//! it as the caller supplied (when `keep_old_tables` is set) and
//! then applies the delta-mod-16 / repeat / zero-run updates the
//! precoded stream encodes. The caller's responsibility is just
//! to hand the same buffer across blocks; this module enforces
//! the reset / retain decision the block's flag bit demands.

use thiserror::Error;

use super::bits::{BitReadError, BitReader};
use super::bootstrap::{self, BootstrapError, MainTables, MAIN_TABLE_TOTAL};
use super::huffman::HuffmanCode;

/// Errors produced by [`parse_block_prologue`].
#[derive(Debug, Error)]
pub enum BlockHeaderError {
    /// The bitstream ran out mid-prologue.
    #[error("legacy RAR block prologue underran the bitstream")]
    Underrun(#[from] BitReadError),

    /// The LZ-mode tail (precode + main-length + tree build)
    /// failed. The wrapped [`BootstrapError`] carries the
    /// specific reason — under-/over-subscription, repeat-last
    /// at index 0, etc.
    #[error("legacy RAR block prologue: bootstrap failed")]
    Bootstrap(#[from] BootstrapError),

    /// PPMd's encoded `max_order` decoded to 1, which means the
    /// model would have only the order-0 context to fall back
    /// on and is rejected by libarchive (line 2354). Surfaced
    /// here so §C1g can convert it to the user-visible
    /// [`crate::rar::RarError::Malformed`] message at the
    /// archive boundary.
    #[error("legacy RAR PPMd block declared max_order = 1 (must be >= 2)")]
    PpmdMaxOrderTooSmall,
}

/// The parsed prologue of one block, ready for the LZ or PPMd
/// path to act on.
#[derive(Debug)]
pub enum BlockPrologue {
    /// LZ-mode block (`is_ppmd_block == 0`).
    Lz {
        /// The four canonical Huffman codes this block uses.
        /// `MainTables::main` indexes the literal/length tree,
        /// `MainTables::offset` the distance tree, etc.
        tables: MainTables,
        /// `true` when the block's `keep_old_tables` flag was
        /// set — the caller's length buffer carried over from
        /// the previous block before the precode-driven update
        /// applied. Diagnostic only; the buffer state after
        /// this call always reflects what `tables` is built
        /// from.
        kept_old_tables: bool,
    },

    /// PPMd-mode block (`is_ppmd_block == 1`). The fields here
    /// reproduce the ppmd_flags byte's conditional payload;
    /// §C1g acts on them.
    Ppmd {
        /// `true` when `ppmd_flags & 0x20` is set — the model is
        /// being re-initialised with a fresh dictionary and a
        /// new max_order. When `false`, only the range decoder
        /// is restarted and the prior context is reused (§C1g
        /// errors at this point if no prior context exists).
        restart: bool,
        /// Decoded dictionary size in bytes, present when
        /// `restart` is set. Wire format: an 8-bit field
        /// `dict_byte`; size = `(dict_byte + 1) << 20` (i.e.
        /// 1 MiB granularity, range `1 MiB..=256 MiB`).
        dictionary_size: Option<u32>,
        /// Decoded PPMd max-order, present when `restart` is
        /// set. Wire format: low 5 bits of `ppmd_flags` plus 1
        /// (raw range `1..=32`); values above 16 are remapped
        /// via `16 + (raw - 16) * 3` (final range `1..=64`).
        /// `raw == 0` after the `+1` is `1`, which is rejected
        /// (see [`BlockHeaderError::PpmdMaxOrderTooSmall`]).
        max_order: Option<u32>,
        /// Decoded init-escape byte, present when
        /// `ppmd_flags & 0x40` is set. When `None`, libarchive
        /// uses `2` for the block (line 2344); §C1g does the
        /// same.
        init_esc: Option<u8>,
    },
}

/// Parse one block's prologue from `reader`, advancing the
/// cursor to the first symbol of the block's payload.
///
/// `lengths` is the caller-owned persistent length buffer the
/// LZ path threads across blocks. PPMd blocks don't touch it;
/// LZ blocks zero it when `keep_old_tables` is cleared or apply
/// the precoded delta updates in place when it's set.
///
/// # Errors
///
/// - [`BlockHeaderError::Underrun`] if the bitstream runs out
///   before the prologue finishes.
/// - [`BlockHeaderError::Bootstrap`] if the LZ tail (precode +
///   main lengths + tree build) errors.
/// - [`BlockHeaderError::PpmdMaxOrderTooSmall`] if a restarting
///   PPMd block requests `max_order == 1`.
pub fn parse_block_prologue(
    reader: &mut BitReader<'_>,
    lengths: &mut [u8; MAIN_TABLE_TOTAL],
) -> Result<BlockPrologue, BlockHeaderError> {
    // Every block begins byte-aligned. align_to_byte is a no-op
    // if we're already aligned; otherwise drops the previous
    // block's tail bits.
    reader.align_to_byte();

    let is_ppmd = reader.read_bits(1)? != 0;
    if is_ppmd {
        parse_ppmd_prologue(reader)
    } else {
        parse_lz_prologue(reader, lengths)
    }
}

fn parse_lz_prologue(
    reader: &mut BitReader<'_>,
    lengths: &mut [u8; MAIN_TABLE_TOTAL],
) -> Result<BlockPrologue, BlockHeaderError> {
    let kept_old_tables = reader.read_bits(1)? != 0;
    if !kept_old_tables {
        // Reset the persistent length buffer per libarchive's
        // memset at line 2414.
        lengths.fill(0);
    }
    // §C1b's three stages: precode lengths → main lengths →
    // four sub-tree build.
    let precode_lens = bootstrap::read_precode_lengths(reader)?;
    let precode = HuffmanCode::build(&precode_lens)
        .map_err(|e| BlockHeaderError::Bootstrap(BootstrapError::HuffmanBuild(e)))?;
    bootstrap::read_main_lengths(reader, &precode, lengths)?;
    let tables = bootstrap::build_main_tables(lengths)?;
    Ok(BlockPrologue::Lz {
        tables,
        kept_old_tables,
    })
}

fn parse_ppmd_prologue(reader: &mut BitReader<'_>) -> Result<BlockPrologue, BlockHeaderError> {
    let ppmd_flags = reader.read_bits(7)? as u8;
    let restart = ppmd_flags & 0x20 != 0;
    // 0x20 gates BOTH the dictionary-size byte AND the max-order
    // re-init. They're physically separate bits in the wire
    // stream but always together: when the model is being
    // restarted, both come along.
    let dictionary_size = if restart {
        let dict_byte = reader.read_bits(8)?;
        // libarchive: (dict_byte + 1) << 20; range 1..=256 MiB.
        Some((dict_byte + 1) << 20)
    } else {
        None
    };

    // 0x40 is independent of 0x20: when set, the init-escape
    // byte is shipped explicitly; otherwise libarchive uses 2.
    let init_esc = if ppmd_flags & 0x40 != 0 {
        Some(reader.read_bits(8)? as u8)
    } else {
        None
    };

    let max_order = if restart {
        let raw = u32::from(ppmd_flags & 0x1F) + 1;
        let order = if raw > 16 { 16 + (raw - 16) * 3 } else { raw };
        if order == 1 {
            return Err(BlockHeaderError::PpmdMaxOrderTooSmall);
        }
        Some(order)
    } else {
        None
    };

    Ok(BlockPrologue::Ppmd {
        restart,
        dictionary_size,
        max_order,
        init_esc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pack a sequence of `(value, n_bits)` tuples MSB-first
    /// into a byte stream. Same helper shape as the other
    /// rar_legacy module tests use.
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

    /// Build an LZ-mode prologue's wire bytes from a precode-
    /// length sequence and a main-length-stream-pair sequence.
    /// Helper used by the LZ-mode tests below.
    fn build_lz_prologue_bytes(
        is_ppmd_bit: u32,
        keep_old: u32,
        precode_pairs: &[(u32, u32)],
        main_pairs: &[(u32, u32)],
    ) -> Vec<u8> {
        let mut all = vec![(is_ppmd_bit, 1), (keep_old, 1)];
        all.extend(precode_pairs.iter().copied());
        all.extend(main_pairs.iter().copied());
        pack_msb(&all)
    }

    // ---- PPMd prologue --------------------------------------------

    #[test]
    fn ppmd_minimal_no_flags_no_payload() {
        // ppmd_flags = 0: no 0x20 (so no dict / order / restart),
        // no 0x40 (so no init_esc).
        let bytes = pack_msb(&[(1, 1), (0, 7)]);
        let mut br = BitReader::new(&bytes);
        let mut lengths = [0u8; MAIN_TABLE_TOTAL];
        let prologue = parse_block_prologue(&mut br, &mut lengths).unwrap();
        match prologue {
            BlockPrologue::Ppmd {
                restart,
                dictionary_size,
                max_order,
                init_esc,
            } => {
                assert!(!restart);
                assert_eq!(dictionary_size, None);
                assert_eq!(max_order, None);
                assert_eq!(init_esc, None);
            }
            other => panic!("expected Ppmd, got {other:?}"),
        }
    }

    #[test]
    fn ppmd_restart_decodes_dict_size_and_max_order() {
        // ppmd_flags = 0x20 | 0x05  → restart, raw order = 5+1 = 6.
        // dict_byte = 7 → dict = (7 + 1) << 20 = 8 MiB.
        let ppmd_flags: u32 = 0x20 | 0x05;
        let dict_byte: u32 = 7;
        let bytes = pack_msb(&[(1, 1), (ppmd_flags, 7), (dict_byte, 8)]);
        let mut br = BitReader::new(&bytes);
        let mut lengths = [0u8; MAIN_TABLE_TOTAL];
        let prologue = parse_block_prologue(&mut br, &mut lengths).unwrap();
        match prologue {
            BlockPrologue::Ppmd {
                restart,
                dictionary_size,
                max_order,
                init_esc,
            } => {
                assert!(restart);
                assert_eq!(dictionary_size, Some(8 << 20));
                assert_eq!(max_order, Some(6));
                assert_eq!(init_esc, None);
            }
            other => panic!("expected Ppmd, got {other:?}"),
        }
    }

    #[test]
    fn ppmd_restart_remaps_high_max_order() {
        // raw = (0x1F + 1) = 32 → remap = 16 + (32 - 16) * 3 = 64.
        let ppmd_flags: u32 = 0x20 | 0x1F;
        let dict_byte: u32 = 0;
        let bytes = pack_msb(&[(1, 1), (ppmd_flags, 7), (dict_byte, 8)]);
        let mut br = BitReader::new(&bytes);
        let mut lengths = [0u8; MAIN_TABLE_TOTAL];
        let prologue = parse_block_prologue(&mut br, &mut lengths).unwrap();
        match prologue {
            BlockPrologue::Ppmd {
                max_order,
                dictionary_size,
                ..
            } => {
                assert_eq!(max_order, Some(64));
                assert_eq!(dictionary_size, Some(1 << 20));
            }
            other => panic!("expected Ppmd, got {other:?}"),
        }
    }

    #[test]
    fn ppmd_restart_max_order_of_one_errors() {
        // raw = 0 + 1 = 1 → libarchive rejects.
        let ppmd_flags: u32 = 0x20;
        let dict_byte: u32 = 0;
        let bytes = pack_msb(&[(1, 1), (ppmd_flags, 7), (dict_byte, 8)]);
        let mut br = BitReader::new(&bytes);
        let mut lengths = [0u8; MAIN_TABLE_TOTAL];
        let err = parse_block_prologue(&mut br, &mut lengths).unwrap_err();
        assert!(matches!(err, BlockHeaderError::PpmdMaxOrderTooSmall));
    }

    #[test]
    fn ppmd_init_escape_flag_consumes_one_extra_byte() {
        // ppmd_flags = 0x40 alone → no dict / no order, but
        // 8-bit init_esc follows directly.
        let ppmd_flags: u32 = 0x40;
        let bytes = pack_msb(&[(1, 1), (ppmd_flags, 7), (0xAB, 8)]);
        let mut br = BitReader::new(&bytes);
        let mut lengths = [0u8; MAIN_TABLE_TOTAL];
        let prologue = parse_block_prologue(&mut br, &mut lengths).unwrap();
        match prologue {
            BlockPrologue::Ppmd {
                restart,
                dictionary_size,
                max_order,
                init_esc,
            } => {
                assert!(!restart);
                assert_eq!(dictionary_size, None);
                assert_eq!(max_order, None);
                assert_eq!(init_esc, Some(0xAB));
            }
            other => panic!("expected Ppmd, got {other:?}"),
        }
    }

    #[test]
    fn ppmd_both_flags_orders_dict_then_init_esc_then_max_order() {
        // ppmd_flags = 0x20 | 0x40 | 0x03 → restart, init_esc shipped,
        // raw order = 3 + 1 = 4. Wire order:
        //   1-bit is_ppmd=1
        //   7-bit ppmd_flags
        //   8-bit dict_byte    (gated by 0x20)
        //   8-bit init_esc     (gated by 0x40)
        // The max_order field comes out of ppmd_flags' low 5 bits;
        // there's no separate max_order byte on the wire.
        let ppmd_flags: u32 = 0x20 | 0x40 | 0x03;
        let bytes = pack_msb(&[(1, 1), (ppmd_flags, 7), (0x10, 8), (0xCD, 8)]);
        let mut br = BitReader::new(&bytes);
        let mut lengths = [0u8; MAIN_TABLE_TOTAL];
        let prologue = parse_block_prologue(&mut br, &mut lengths).unwrap();
        match prologue {
            BlockPrologue::Ppmd {
                restart,
                dictionary_size,
                max_order,
                init_esc,
            } => {
                assert!(restart);
                assert_eq!(dictionary_size, Some((0x10 + 1) << 20));
                assert_eq!(max_order, Some(4));
                assert_eq!(init_esc, Some(0xCD));
            }
            other => panic!("expected Ppmd, got {other:?}"),
        }
    }

    // ---- LZ prologue ----------------------------------------------

    /// Canonical-code lookup, lifted from the bootstrap tests to
    /// keep this module self-contained.
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

    /// Encode a minimal LZ block whose precode covers only the
    /// symbols the test uses (5 = literal-length, 19 = zero-run
    /// large), zero-runs the entire 404-entry main table, and
    /// optionally sets keep_old_tables. Returns
    /// `(bytes, precode_lens, expected_lengths)`.
    fn minimal_lz_block(keep_old: u32) -> (Vec<u8>, [u8; 20], Vec<u8>) {
        let mut precode_lens = [0u8; 20];
        precode_lens[5] = 2;
        precode_lens[19] = 1;
        let precode_pairs: Vec<(u32, u32)> =
            precode_lens.iter().map(|&v| (u32::from(v), 4)).collect();
        let canon = canonical_codes(&precode_lens);
        let mut main_pairs: Vec<(u32, u32)> = Vec::new();
        // Three 138-zero runs cover 414 entries (> 404), so the
        // last one is clamped at the buffer end.
        for _ in 0..3 {
            main_pairs.push((canon[19], 1));
            main_pairs.push((127, 7));
        }
        let bytes = build_lz_prologue_bytes(0, keep_old, &precode_pairs, &main_pairs);
        let expected_lengths = vec![0u8; MAIN_TABLE_TOTAL];
        (bytes, precode_lens, expected_lengths)
    }

    #[test]
    fn lz_keep_old_zero_zeros_the_length_buffer() {
        let (bytes, _, expected_lengths) = minimal_lz_block(0);
        let mut br = BitReader::new(&bytes);
        // Pre-seed lengths with non-zero values to prove they get
        // wiped when keep_old_tables == 0.
        let mut lengths = [7u8; MAIN_TABLE_TOTAL];
        let prologue = parse_block_prologue(&mut br, &mut lengths).unwrap();
        match prologue {
            BlockPrologue::Lz {
                kept_old_tables, ..
            } => assert!(!kept_old_tables),
            other => panic!("expected Lz, got {other:?}"),
        }
        // The precode + main-length pass should have zeroed it,
        // then the bulk-zero opcodes leave it zero.
        assert_eq!(&lengths[..], &expected_lengths[..]);
    }

    #[test]
    fn lz_keep_old_one_preserves_length_buffer_before_deltas() {
        // keep_old = 1 → don't memset. The minimal block then
        // zero-runs from the buffer's existing state, which means
        // delta-mod-16 is never applied (zero-run opcodes only
        // assign 0). After the prologue the buffer is all zero
        // regardless — but the kept_old_tables flag should be
        // surfaced as true.
        let (bytes, _, _) = minimal_lz_block(1);
        let mut br = BitReader::new(&bytes);
        let mut lengths = [5u8; MAIN_TABLE_TOTAL];
        let prologue = parse_block_prologue(&mut br, &mut lengths).unwrap();
        match prologue {
            BlockPrologue::Lz {
                kept_old_tables, ..
            } => assert!(kept_old_tables),
            other => panic!("expected Lz, got {other:?}"),
        }
        // The bulk-zero opcodes leave the buffer zero.
        assert!(lengths.iter().all(|&v| v == 0));
    }

    #[test]
    fn lz_prologue_returns_built_main_tables() {
        // Same minimal block — the four sub-tables build cleanly,
        // all empty (no symbols at non-zero length).
        let (bytes, _, _) = minimal_lz_block(0);
        let mut br = BitReader::new(&bytes);
        let mut lengths = [0u8; MAIN_TABLE_TOTAL];
        let prologue = parse_block_prologue(&mut br, &mut lengths).unwrap();
        match prologue {
            BlockPrologue::Lz { tables, .. } => {
                assert!(!tables.main.is_populated());
                assert!(!tables.offset.is_populated());
                assert!(!tables.low_offset.is_populated());
                assert!(!tables.length.is_populated());
            }
            other => panic!("expected Lz, got {other:?}"),
        }
    }

    #[test]
    fn block_prologue_aligns_to_byte_boundary_first() {
        // Wire layout: 3 stray bits (simulating the tail of a
        // hypothetical previous block's symbol decode), 5 bits of
        // byte-tail padding, then 1-bit is_ppmd = 1 and 7-bit
        // ppmd_flags = 0 sitting cleanly in byte 1.
        // align_to_byte should jump from byte 0 bit 3 to byte 1
        // bit 0, then the prologue reads 8 bits there.
        let bytes = pack_msb(&[
            (0b101, 3), // 3 stray bits
            (0, 5),     // byte-tail padding to byte boundary
            (1, 1),     // is_ppmd = 1
            (0, 7),     // ppmd_flags = 0
        ]);
        let mut br = BitReader::new(&bytes);
        br.read_bits(3).unwrap();
        assert_eq!(br.byte_position(), (0, 3));
        let mut lengths = [0u8; MAIN_TABLE_TOTAL];
        let prologue = parse_block_prologue(&mut br, &mut lengths).unwrap();
        assert!(matches!(prologue, BlockPrologue::Ppmd { .. }));
        // After the prologue: byte 0's tail dropped (cursor →
        // byte 1 bit 0), then 8 bits read from byte 1.
        assert_eq!(br.byte_position(), (2, 0));
    }

    #[test]
    fn truncated_prologue_returns_underrun() {
        let bytes = [0u8; 0];
        let mut br = BitReader::new(&bytes);
        let mut lengths = [0u8; MAIN_TABLE_TOTAL];
        let err = parse_block_prologue(&mut br, &mut lengths).unwrap_err();
        assert!(matches!(err, BlockHeaderError::Underrun(_)));
    }
}
