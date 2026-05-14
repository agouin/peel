//! Canonical Huffman decoder for the hand-rolled bzip2 decoder.
//!
//! `internal/PLAN_bz2_support.md` Phase 3. Bzip2's Huffman layer is
//! canonical (lengths-only on the wire, code values assigned by
//! standard canonical-code construction). Two real differences from
//! deflate:
//!
//! 1. **Max code length is 20 bits**, not 15. The flat lookup table
//!    is sized to `1 << max_len_observed` so blocks that declare
//!    only short codes do not pay the 4 MiB worst-case footprint —
//!    in practice typical bzip2 blocks use ≤ 17-bit codes, putting
//!    each table at ≤ 512 KiB.
//! 2. **No bit-reverse on install.** Bzip2's wire format is MSB-
//!    first within each byte (`super::bitstream::BitReader` returns
//!    [`super::bitstream::BitReader::peek_bits`] with the most-
//!    recently-shifted bits in the *high* positions of the result),
//!    and Huffman codes are written MSB-first on the wire. The
//!    canonical code value therefore aligns directly with the high
//!    bits of a `peek_bits(max_len)` window — no reversal needed.
//!    Deflate must reverse because its bit reader is LSB-first within
//!    bytes; bzip2 does not.

use super::bitstream::BitReader;
use super::error::Bzip2Error;

/// Hard ceiling on Huffman code length in any bzip2 block, per the
/// reference `decompress.c`. Lengths outside `1..=20` surface as
/// [`Bzip2Error::HuffmanLengthOutOfRange`].
pub const MAX_CODE_BITS: u32 = 20;

/// One entry in the flat lookup table. `len == 0` means "no
/// canonical code reaches this index"; hitting such an entry from
/// [`HuffTable::decode`] indicates a malformed bit pattern.
#[derive(Clone, Copy, Default, Debug)]
struct HuffEntry {
    /// Decoded symbol. Bzip2's Huffman alphabet has at most 258
    /// entries (256 byte values + RUNA + RUNB + EOB capped at 258),
    /// so `u16` is generous.
    sym: u16,
    /// Number of bits the canonical code occupies; `0` is the
    /// not-installed sentinel.
    len: u8,
}

/// Canonical Huffman decode table.
///
/// Built once per block per group (bzip2 packs 2..=6 tables per
/// block). The flat lookup table is sized to `1 << observed_max_len`
/// where `observed_max_len` is the largest length declared in this
/// table's lengths vector. Typical blocks declare 14–17-bit codes
/// (256 KiB – 4 MiB transient per table) and free at end-of-block.
#[derive(Debug)]
pub struct HuffTable {
    table: Box<[HuffEntry]>,
    /// Width of the lookup index in bits (= observed max code
    /// length).
    bits: u32,
}

impl HuffTable {
    /// Build a canonical Huffman decode table from per-symbol code
    /// lengths.
    ///
    /// `code_lens[i]` is the canonical code length (in bits) for
    /// alphabet symbol `i`. Every symbol must have a non-zero
    /// length — bzip2 does not admit "symbol not in alphabet" the
    /// way deflate does (the alphabet size is exactly the number of
    /// symbols the block uses, computed as `nInUse + 2`).
    ///
    /// # Errors
    ///
    /// - [`Bzip2Error::HuffmanLengthOutOfRange`] if any length is 0
    ///   or > 20.
    /// - [`Bzip2Error::MalformedHuffman`] if the canonical codes
    ///   overflow `1 << max_len` (Kraft inequality violated).
    pub fn build(code_lens: &[u8]) -> Result<Self, Bzip2Error> {
        let mut bl_count = [0u32; (MAX_CODE_BITS as usize) + 1];
        let mut max_len = 0u32;
        for &l in code_lens {
            let l = u32::from(l);
            if l == 0 || l > MAX_CODE_BITS {
                return Err(Bzip2Error::HuffmanLengthOutOfRange { length: l });
            }
            bl_count[l as usize] = bl_count[l as usize].saturating_add(1);
            if l > max_len {
                max_len = l;
            }
        }
        // INVARIANT: code_lens is non-empty (callers guarantee
        // nSymbols >= 3 — RUNA + at least one MTF + EOB). So
        // max_len >= 1.
        debug_assert!(
            max_len >= 1,
            "Huffman alphabet must have at least one symbol"
        );

        let mut next_code = [0u32; (MAX_CODE_BITS as usize) + 2];
        let mut code: u32 = 0;
        for length in 1..=max_len {
            code = code.checked_add(bl_count[(length - 1) as usize]).ok_or(
                Bzip2Error::MalformedHuffman("canonical code accumulator overflowed"),
            )? << 1;
            next_code[length as usize] = code;
        }
        let limit = 1u32 << max_len;
        let last_assigned = code.saturating_add(bl_count[max_len as usize]);
        if last_assigned > limit {
            return Err(Bzip2Error::MalformedHuffman(
                "Huffman tree over-subscribed (Kraft inequality violated)",
            ));
        }

        let bits = max_len;
        let table_size = 1usize << bits;
        let mut table = vec![HuffEntry::default(); table_size].into_boxed_slice();

        for (sym, &cl) in code_lens.iter().enumerate() {
            let cl = u32::from(cl);
            // Empty lengths already rejected above; cl >= 1 here.
            let canonical = next_code[cl as usize];
            next_code[cl as usize] = next_code[cl as usize].saturating_add(1);
            // MSB-first install: canonical code occupies the high
            // `cl` bits of the peek window; all 2^(bits-cl) values
            // of the low don't-care bits map to the same entry.
            let high_shift = bits - cl;
            let base = (canonical as usize) << high_shift;
            // INVARIANT: base + (1 << high_shift) - 1 < table_size,
            // because canonical < 1 << cl and (1 << cl) * (1 << high_shift)
            // = 1 << bits = table_size.
            let span = 1usize << high_shift;
            for idx in base..base + span {
                table[idx] = HuffEntry {
                    // INVARIANT: sym < code_lens.len() <= 258, fits
                    // in u16.
                    sym: sym as u16,
                    // INVARIANT: cl in 1..=20, fits in u8.
                    len: cl as u8,
                };
            }
        }
        Ok(HuffTable { table, bits })
    }

    /// Maximum code length used in this table; the width of the
    /// peek window required to decode a symbol.
    #[must_use]
    pub fn max_bits(&self) -> u32 {
        self.bits
    }

    /// Decode the next symbol from `br`. Peeks `self.bits`, looks
    /// up the entry, and consumes the entry's actual code length.
    ///
    /// # Errors
    ///
    /// - [`Bzip2Error::UnexpectedEof`] on truncation.
    /// - [`Bzip2Error::SourceIo`] on underlying IO failure.
    /// - [`Bzip2Error::MalformedHuffman`] if the peeked bits land
    ///   on a not-installed table entry — by construction this
    ///   cannot happen for a well-formed table, so it indicates
    ///   source corruption.
    pub fn decode(&self, br: &mut BitReader) -> Result<u16, Bzip2Error> {
        // Soft-ensure: a block's last symbol may end within a
        // partial byte at end-of-stream, in which case the peek's
        // implicit zero-padding still resolves to a valid entry
        // for short codes. The bits_buffered() check after the
        // ensure guards the strict case.
        br.ensure(self.bits)?;
        let idx = br.peek_bits(self.bits) as usize;
        // INVARIANT: idx < 1 << self.bits = table.len().
        let entry = self.table[idx];
        if entry.len == 0 {
            return Err(Bzip2Error::MalformedHuffman(
                "peeked bits resolve to an uninstalled Huffman entry",
            ));
        }
        if u32::from(entry.len) > br.bits_buffered() {
            // We zero-extended in the peek but didn't actually
            // have those bits available — strict truncation.
            return Err(Bzip2Error::UnexpectedEof("Huffman code"));
        }
        br.consume_bits(u32::from(entry.len));
        Ok(entry.sym)
    }
}

/// Read the per-block Huffman code-length table for one of the
/// 2..=6 groups in the block.
///
/// Wire format (libbz2 `decompress.c`):
///
/// 1. 5-bit initial length.
/// 2. For each of `n_symbols` alphabet positions:
///    - Loop:
///      - Read 1 bit. If `0`, the symbol's length is set to the
///        current accumulator.
///      - Else read another bit. If `0`, accumulator += 1; if `1`,
///        accumulator -= 1. Continue the loop.
///
/// The accumulator must stay in `1..=20` throughout. Out-of-range
/// values surface as [`Bzip2Error::HuffmanLengthOutOfRange`].
///
/// # Errors
///
/// - Forwarded from the bit reader / above checks.
pub fn read_code_lengths(br: &mut BitReader, n_symbols: u32) -> Result<Vec<u8>, Bzip2Error> {
    let mut current = br
        .read_bits(5)
        .map_err(|e| relabel_eof(e, "Huffman initial length"))?;
    let mut lengths = Vec::with_capacity(n_symbols as usize);
    for _ in 0..n_symbols {
        loop {
            let toggle = br
                .read_bits(1)
                .map_err(|e| relabel_eof(e, "Huffman length toggle"))?;
            if toggle == 0 {
                break;
            }
            let dir = br
                .read_bits(1)
                .map_err(|e| relabel_eof(e, "Huffman length direction"))?;
            if dir == 0 {
                current = current
                    .checked_add(1)
                    .ok_or(Bzip2Error::HuffmanLengthOutOfRange { length: u32::MAX })?;
            } else {
                current = current
                    .checked_sub(1)
                    .ok_or(Bzip2Error::HuffmanLengthOutOfRange { length: u32::MAX })?;
            }
        }
        if current == 0 || current > MAX_CODE_BITS {
            return Err(Bzip2Error::HuffmanLengthOutOfRange { length: current });
        }
        // INVARIANT: current in 1..=20, fits in u8.
        lengths.push(current as u8);
    }
    Ok(lengths)
}

fn relabel_eof(e: Bzip2Error, label: &'static str) -> Bzip2Error {
    match e {
        Bzip2Error::UnexpectedEof(_) => Bzip2Error::UnexpectedEof(label),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    fn br(bytes: Vec<u8>) -> BitReader {
        BitReader::new(Box::new(Cursor::new(bytes)))
    }

    /// Pack a sequence of `(value, width)` into MSB-first bytes.
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

    #[test]
    fn build_table_decodes_two_symbol_alphabet() {
        // Alphabet {A=0, B=1} with lengths [1, 1]. Canonical codes:
        //   A → "0" (0b0)
        //   B → "1" (0b1)
        let table = HuffTable::build(&[1, 1]).expect("build");
        assert_eq!(table.max_bits(), 1);
        // Read "01" = symbol A then symbol B.
        let bytes = pack_bits(&[(0, 1), (1, 1)]);
        let mut r = br(bytes);
        assert_eq!(table.decode(&mut r).expect("A"), 0);
        assert_eq!(table.decode(&mut r).expect("B"), 1);
    }

    #[test]
    fn build_table_decodes_canonical_lengths_2_2_3_3_3_3() {
        // 6-symbol alphabet, lengths [2, 2, 3, 3, 3, 3].
        // Canonical: sym0=00, sym1=01, sym2=100, sym3=101, sym4=110,
        // sym5=111.
        let table = HuffTable::build(&[2, 2, 3, 3, 3, 3]).expect("build");
        assert_eq!(table.max_bits(), 3);
        // Decode sym2 = 0b100, sym5 = 0b111, sym0 = 0b00.
        let bytes = pack_bits(&[(0b100, 3), (0b111, 3), (0b00, 2)]);
        let mut r = br(bytes);
        assert_eq!(table.decode(&mut r).expect("sym2"), 2);
        assert_eq!(table.decode(&mut r).expect("sym5"), 5);
        assert_eq!(table.decode(&mut r).expect("sym0"), 0);
    }

    #[test]
    fn build_rejects_zero_length_symbol() {
        match HuffTable::build(&[1, 0, 1]) {
            Err(Bzip2Error::HuffmanLengthOutOfRange { length }) => assert_eq!(length, 0),
            other => panic!("expected HuffmanLengthOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn build_rejects_over_subscribed_tree() {
        // Lengths [1, 1, 1] over-subscribe a tree (Kraft would
        // require sum 2^-len <= 1, but 3 × 2^-1 = 1.5 > 1).
        match HuffTable::build(&[1, 1, 1]) {
            Err(Bzip2Error::MalformedHuffman(msg)) => {
                assert!(msg.contains("over-subscribed"));
            }
            other => panic!("expected MalformedHuffman, got {other:?}"),
        }
    }

    #[test]
    fn build_rejects_length_over_20() {
        match HuffTable::build(&[21]) {
            Err(Bzip2Error::HuffmanLengthOutOfRange { length }) => assert_eq!(length, 21),
            other => panic!("expected HuffmanLengthOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn read_code_lengths_decodes_simple_block() {
        // Initial = 3, three symbols all length 3 (toggle=0 each).
        // Bits: 00011 (5-bit init) | 0 | 0 | 0
        let bytes = pack_bits(&[(3, 5), (0, 1), (0, 1), (0, 1)]);
        let mut r = br(bytes);
        let lens = read_code_lengths(&mut r, 3).expect("lengths");
        assert_eq!(lens, vec![3, 3, 3]);
    }

    #[test]
    fn read_code_lengths_decodes_delta_up_and_down() {
        // Initial = 5. Symbol 0: +1 (10 then 10 then 0) — toggle=1,
        // dir=0, toggle=1, dir=0, toggle=0 → +2 → length 7. Then
        // symbol 1: -1 (toggle=1, dir=1, toggle=0) → length 6.
        // Then symbol 2: stay → length 6.
        let bytes = pack_bits(&[
            (5, 5), // initial 5
            (1, 1),
            (0, 1), // +1 → 6
            (1, 1),
            (0, 1), // +1 → 7
            (0, 1), // commit symbol 0 = 7
            (1, 1),
            (1, 1), // -1 → 6
            (0, 1), // commit symbol 1 = 6
            (0, 1), // commit symbol 2 = 6
        ]);
        let mut r = br(bytes);
        let lens = read_code_lengths(&mut r, 3).expect("lengths");
        assert_eq!(lens, vec![7, 6, 6]);
    }

    #[test]
    fn read_code_lengths_rejects_zero_via_under_run() {
        // Initial = 1, then -1 → 0 → out of range.
        let bytes = pack_bits(&[
            (1, 5),
            (1, 1),
            (1, 1), // -1 → 0
            (0, 1), // commit
        ]);
        let mut r = br(bytes);
        match read_code_lengths(&mut r, 1) {
            Err(Bzip2Error::HuffmanLengthOutOfRange { length }) => assert_eq!(length, 0),
            other => panic!("expected HuffmanLengthOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn decode_surfaces_unexpected_eof_when_source_empty() {
        // Any valid 2-symbol alphabet; empty source means the
        // peek's zero-padding resolves to entry 0, but the entry's
        // length exceeds the (zero) bits actually buffered, so
        // decode surfaces UnexpectedEof rather than consuming
        // padding bits that aren't on the wire.
        let table = HuffTable::build(&[1, 1]).expect("build");
        let mut r = br(Vec::new());
        match table.decode(&mut r) {
            Err(Bzip2Error::UnexpectedEof(_)) => {}
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }
}
