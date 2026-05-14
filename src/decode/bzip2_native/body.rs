//! Per-block Huffman-symbol decode loop.
//!
//! `internal/PLAN_bz2_support.md` Phase 3 (wiring) + Phase 4
//! (consumer). Given the per-block selectors and the per-group
//! Huffman tables, walks the bit stream and emits the symbol stream
//! into a `Vec<u16>`: RUNA / RUNB / MTF-ranks / EOB.
//!
//! - Symbol value `0` = RUNA, value `1` = RUNB. Together these encode
//!   a base-2 expansion of a zero-rank run in the MTF index stream
//!   (consumed by [`super::rle2`]).
//! - Symbol values `2..=alpha_size - 2` encode MTF ranks `1..` —
//!   the encoder subtracts 1 before Huffman-coding non-zero MTF
//!   ranks; the decoder un-shifts in [`super::mtf`].
//! - Symbol value `alpha_size - 1` = EOB. Terminates the block.

use super::bitstream::BitReader;
use super::error::Bzip2Error;
use super::huffman::{read_code_lengths, HuffTable};
use super::selectors::{Selectors, GROUP_SIZE};

/// Decoded block symbol stream + the per-block alphabet size.
///
/// The alphabet size is `num_symbols_used + 2`, where the `+2`
/// covers RUNA and RUNB. The EOB symbol is the highest value
/// (`alpha_size - 1`).
#[derive(Debug)]
pub struct BlockSymbols {
    /// Decoded symbols, in order. Includes RUNA/RUNB markers; does
    /// NOT include the EOB symbol (the loop stops on EOB without
    /// emitting it).
    pub symbols: Vec<u16>,
    /// Number of distinct entries in the Huffman alphabet =
    /// `num_symbols_used + 2`.
    pub alpha_size: u16,
}

/// Read the per-block Huffman code-length tables (one per group) and
/// then the symbol stream until EOB.
///
/// `num_symbols_used` is the count of distinct bytes the block
/// declares via its "symbols used" bitmap (from
/// [`super::block::BlockHeader::num_symbols_used`]).
///
/// `selectors.selectors[k]` chooses the group for symbol slice
/// `k * GROUP_SIZE .. (k+1) * GROUP_SIZE`. The decoder pre-builds
/// every group's [`HuffTable`] and dispatches at group boundaries
/// rather than per symbol.
///
/// `max_symbols` is the block's symbol ceiling — for level `L` it's
/// `100_000 * L + small_slack`; exceeding it surfaces as
/// [`Bzip2Error::BlockTooLarge`].
///
/// # Errors
///
/// - Forwarded errors from the Huffman / bit-reader layers.
/// - [`Bzip2Error::BlockMissingEob`] if the symbol stream runs out
///   of selectors before EOB is observed.
/// - [`Bzip2Error::BlockTooLarge`] if the decoder emits more than
///   `max_symbols` non-EOB symbols (defensive bound, since EOB will
///   normally fire much earlier).
pub fn decode_block_symbols(
    br: &mut BitReader,
    selectors: &Selectors,
    num_symbols_used: usize,
    max_symbols: u32,
) -> Result<BlockSymbols, Bzip2Error> {
    // INVARIANT: bzip2 always has at least one symbol used (Phase 2
    // rejects EmptySymbolSet earlier), so alpha_size >= 3 (RUNA +
    // one MTF + EOB).
    let alpha_size = (num_symbols_used + 2) as u32;
    if alpha_size > u32::from(u16::MAX) {
        // Unreachable in practice (alpha_size <= 258), but guard
        // the cast.
        return Err(Bzip2Error::MalformedHuffman(
            "block alphabet size exceeds 16 bits",
        ));
    }
    let eob_sym = (alpha_size - 1) as u16;

    // Build one HuffTable per group.
    let mut tables = Vec::with_capacity(selectors.n_groups as usize);
    for _ in 0..selectors.n_groups {
        let lengths = read_code_lengths(br, alpha_size)?;
        tables.push(HuffTable::build(&lengths)?);
    }

    let mut symbols = Vec::new();
    let mut group_idx = 0usize;
    let mut in_group = 0usize;
    loop {
        if in_group == 0 && group_idx >= selectors.selectors.len() {
            return Err(Bzip2Error::BlockMissingEob);
        }
        let group = selectors.selectors[group_idx];
        // INVARIANT: selectors validation in `super::selectors`
        // ensures group < n_groups <= tables.len().
        let table = &tables[group as usize];
        let sym = table.decode(br)?;
        if sym == eob_sym {
            break;
        }
        symbols.push(sym);
        if (symbols.len() as u64) > u64::from(max_symbols) {
            return Err(Bzip2Error::BlockTooLarge {
                seen: max_symbols.saturating_add(1),
                max: max_symbols,
            });
        }
        in_group += 1;
        if in_group >= GROUP_SIZE {
            in_group = 0;
            group_idx += 1;
        }
    }
    // INVARIANT: alpha_size <= u16::MAX checked above.
    Ok(BlockSymbols {
        symbols,
        alpha_size: alpha_size as u16,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::decode::bzip2_native::selectors::Selectors;

    use std::io::Cursor;

    fn br(bytes: Vec<u8>) -> BitReader {
        BitReader::new(Box::new(Cursor::new(bytes)))
    }

    fn pack_bits(items: &[(u32, u32)]) -> Vec<u8> {
        let mut bits: Vec<bool> = Vec::new();
        for &(v, w) in items {
            for i in (0..w).rev() {
                bits.push((v >> i) & 1 != 0);
            }
        }
        while !bits.len().is_multiple_of(8) {
            bits.push(false);
        }
        let mut bytes = Vec::with_capacity(bits.len() / 8);
        for chunk in bits.chunks(8) {
            let mut byte = 0u8;
            for (i, &b) in chunk.iter().enumerate() {
                if b {
                    byte |= 1 << (7 - i);
                }
            }
            bytes.push(byte);
        }
        bytes
    }

    /// Encode `lengths` using the delta-coded format
    /// `read_code_lengths` consumes. The first symbol's length is
    /// emitted relative to the 5-bit `initial` value; subsequent
    /// symbols are emitted relative to the previous symbol's length.
    fn encode_lengths(initial: u32, lengths: &[u8]) -> Vec<(u32, u32)> {
        let mut bits = vec![(initial, 5)];
        let mut current = initial;
        for &l in lengths {
            let target = u32::from(l);
            while current < target {
                bits.push((1, 1)); // toggle
                bits.push((0, 1)); // +1
                current += 1;
            }
            while current > target {
                bits.push((1, 1)); // toggle
                bits.push((1, 1)); // -1
                current -= 1;
            }
            bits.push((0, 1)); // commit
        }
        bits
    }

    #[test]
    fn decode_block_symbols_emits_runa_eob_for_trivial_block() {
        // Smallest possible alphabet: num_symbols_used = 1. Then
        // alpha_size = 3 (RUNA=0, MTF=1, EOB=2). Build a Huffman
        // table with lengths [1, 2, 2]: codes RUNA=0, MTF=10,
        // EOB=11.
        //
        // Single group, single selector.
        let group_lengths = encode_lengths(1, &[1, 2, 2]);
        // After lengths, the body is: RUNA (0), EOB (11). Read
        // RUNA = code "0", then EOB = code "11".
        let mut bits = Vec::new();
        bits.extend(group_lengths);
        bits.push((0b0, 1)); // RUNA
        bits.push((0b11, 2)); // EOB
        let bytes = pack_bits(&bits);

        let mut r = br(bytes);
        let sel = Selectors {
            n_groups: 1,
            selectors: vec![0],
        };
        // n_groups=1 is technically invalid per the wire format
        // (selectors module enforces 2..=6), but body.rs trusts its
        // caller — we're testing it in isolation here.
        let block = decode_block_symbols(&mut r, &sel, 1, 1000).expect("decode");
        assert_eq!(block.alpha_size, 3);
        assert_eq!(block.symbols, vec![0]); // RUNA, then EOB stops
    }

    #[test]
    fn decode_block_symbols_advances_group_at_50_symbols() {
        // Two groups, both with the same Huffman table (lengths
        // [1, 2, 2]: RUNA=0, MTF=10, EOB=11). Two selectors so the
        // body can run across a group boundary. We'll emit 51 RUNA
        // symbols then EOB; the boundary check must walk to
        // selector index 1 after the 50th symbol.
        let group_lengths = encode_lengths(1, &[1, 2, 2]);
        let mut bits = Vec::new();
        // Two groups: write the same lengths twice.
        bits.extend(&group_lengths);
        bits.extend(&group_lengths);
        // 51 RUNAs + EOB.
        for _ in 0..51 {
            bits.push((0b0, 1));
        }
        bits.push((0b11, 2));

        let mut r = br(pack_bits(&bits));
        let sel = Selectors {
            n_groups: 2,
            selectors: vec![0, 1],
        };
        let block = decode_block_symbols(&mut r, &sel, 1, 1000).expect("decode");
        assert_eq!(block.symbols.len(), 51);
        assert!(block.symbols.iter().all(|&s| s == 0));
    }

    #[test]
    fn decode_block_symbols_rejects_overflow() {
        // Trivial alphabet, but cap max_symbols at 1 — emit 5
        // RUNAs and check we fail with BlockTooLarge before EOB.
        let group_lengths = encode_lengths(1, &[1, 2, 2]);
        let mut bits = Vec::new();
        bits.extend(group_lengths);
        for _ in 0..5 {
            bits.push((0b0, 1));
        }
        bits.push((0b11, 2));

        let mut r = br(pack_bits(&bits));
        let sel = Selectors {
            n_groups: 1,
            selectors: vec![0],
        };
        match decode_block_symbols(&mut r, &sel, 1, 1) {
            Err(Bzip2Error::BlockTooLarge { seen, max }) => {
                assert_eq!(seen, 2);
                assert_eq!(max, 1);
            }
            other => panic!("expected BlockTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn decode_block_symbols_surfaces_missing_eob_when_selectors_run_out() {
        // Block declares 1 selector but the body emits > 50
        // symbols. After group_idx advances past the end, the
        // decoder fails with BlockMissingEob.
        let group_lengths = encode_lengths(1, &[1, 2, 2]);
        let mut bits = Vec::new();
        bits.extend(group_lengths);
        // 51 RUNAs — the 51st triggers the group boundary, advances
        // group_idx to 1, and the next iteration finds no selector.
        for _ in 0..51 {
            bits.push((0b0, 1));
        }

        let mut r = br(pack_bits(&bits));
        let sel = Selectors {
            n_groups: 1,
            selectors: vec![0],
        };
        match decode_block_symbols(&mut r, &sel, 1, 1000) {
            Err(Bzip2Error::BlockMissingEob) => {}
            other => panic!("expected BlockMissingEob, got {other:?}"),
        }
    }
}
