//! Canonical-Huffman tree for zstd literal decoding (RFC 8478 §4.2).
//!
//! Phase 3 implements only the **direct-encoding** weight description
//! (header byte ≥ 128, weights packed 4 bits per symbol). The FSE-coded
//! weight description (header byte < 128) lands in Phase 4 alongside
//! the rest of the FSE infrastructure — see
//! `docs/PLAN_zstd_block_decoder.md` for the phasing rationale.
//!
//! # Wire format recap
//!
//! For a symbol with weight `w >= 1`:
//!
//! ```text
//! code_length = max_weight + 1 - w
//! cells_in_decode_table = 1 << (w - 1)
//! ```
//!
//! Symbols with `w == 0` are absent from the alphabet. The longest
//! code length is `max_weight` (for symbols with `w == 1`); the
//! decode table therefore has `2^max_weight` entries.
//!
//! Sum invariant (RFC 8478 §4.2.1): `sum(2^w for w >= 1) ==
//! 2^(max_weight + 1)`. The encoder writes `n - 1` weights explicitly
//! and the decoder computes the implicit n-th weight from this sum.
//!
//! # Decoding
//!
//! [`HuffmanTree::decode`] reads one symbol from a [`ReverseBitReader`]
//! by peeking `max_weight` bits (always exactly that many), looking
//! up the entry, and advancing by the entry's code length. Per the
//! plan §Phase 3, we use the straight bit-by-bit table — fast-path
//! tables (Huffman X2 / X4) are deferred to Phase 11.

use super::bitstream::{ForwardBitReader, ReverseBitReader};
use super::error::ZstdError;
use super::fse::{parse_distribution, FseTable, MAX_FSE_HUFFMAN_ACCURACY_LOG};

/// RFC 8478 caps Huffman code lengths at 11 bits (`max_weight <= 11`).
///
/// Round one validates against this cap at parse time so callers
/// never over-allocate the decode table beyond `2^11 = 2048` cells.
pub const MAX_HUFFMAN_CODE_BITS: u32 = 11;

/// One cell of the canonical-Huffman lookup table.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
struct DecodeCell {
    /// Symbol whose code prefix matches this cell's index.
    symbol: u8,
    /// Length in bits of the code; the decoder consumes exactly
    /// this many bits from the reverse bitstream when this cell
    /// is hit.
    code_length: u8,
}

/// A canonical Huffman tree built from per-symbol weights.
///
/// The decode table has `2^max_num_bits` entries. Each peek of
/// `max_num_bits` bits indexes directly into the table, and the
/// returned cell carries both the symbol and the code length to
/// advance.
#[derive(Debug, Clone)]
pub struct HuffmanTree {
    table: Vec<DecodeCell>,
    max_num_bits: u32,
}

impl HuffmanTree {
    /// Build a Huffman tree from a complete weight vector.
    ///
    /// `weights[i]` is the weight of symbol `i` (in `0..=255`),
    /// where `0` means the symbol is absent. The caller is
    /// responsible for having already computed the implicit final
    /// weight via [`compute_implicit_weight`] if the wire format
    /// elided it.
    ///
    /// # Errors
    ///
    /// - [`ZstdError::MalformedFrameHeader`] when the weights
    ///   don't form a complete Huffman code (sum-of-2^w ≠
    ///   power of two), when no symbol has a positive weight, or
    ///   when `max_weight > MAX_HUFFMAN_CODE_BITS`.
    pub fn from_direct_weights(weights: &[u8]) -> Result<Self, ZstdError> {
        if weights.is_empty() {
            return Err(ZstdError::MalformedFrameHeader(
                "Huffman: empty weight vector",
            ));
        }
        let max_weight = weights.iter().copied().max().unwrap_or(0);
        if max_weight == 0 {
            return Err(ZstdError::MalformedFrameHeader(
                "Huffman: no symbol has a positive weight",
            ));
        }
        let max_num_bits = u32::from(max_weight);
        if max_num_bits > MAX_HUFFMAN_CODE_BITS {
            return Err(ZstdError::MalformedFrameHeader(
                "Huffman: max code length > 11 bits",
            ));
        }
        // Sum invariant: sum(2^w) over present symbols == 2^(max_weight+1).
        // Compute it as a u64 to keep headroom even though for
        // max_weight <= 11 a u32 would suffice.
        let mut weight_sum: u64 = 0;
        for &w in weights {
            if w == 0 {
                continue;
            }
            if u32::from(w) > max_num_bits {
                // Should not happen if max_weight is the actual max,
                // but defend against programmer error in callers.
                return Err(ZstdError::MalformedFrameHeader(
                    "Huffman: weight exceeds declared max",
                ));
            }
            weight_sum = weight_sum.saturating_add(1u64 << w);
        }
        let expected = 1u64 << (max_num_bits + 1);
        if weight_sum != expected {
            return Err(ZstdError::MalformedFrameHeader(
                "Huffman: sum-of-2^w not a complete power of two",
            ));
        }

        let table_size = 1usize << max_num_bits;
        let mut table: Vec<DecodeCell> = vec![
            DecodeCell {
                symbol: 0,
                code_length: 0,
            };
            table_size
        ];

        // Sort present symbols: descending weight first (= shortest
        // code first), then ascending symbol index as a tiebreaker.
        // Canonical-order placement fills cells contiguously.
        let mut sorted: Vec<u32> = (0..weights.len() as u32)
            .filter(|&i| weights[i as usize] > 0)
            .collect();
        sorted.sort_by(|&a, &b| {
            let wa = weights[a as usize];
            let wb = weights[b as usize];
            wb.cmp(&wa).then(a.cmp(&b))
        });

        let mut cursor = 0usize;
        for sym in sorted {
            let w = weights[sym as usize];
            // INVARIANT: w > 0 by the filter above; max_num_bits >= w
            // by the per-weight validation loop above.
            let code_length = max_num_bits - u32::from(w) + 1;
            let cells = 1usize << (u32::from(w) - 1);
            // INVARIANT: by the sum check above, cumulative `cells`
            // across all present symbols equals `table_size`, so the
            // slice access cannot exceed bounds.
            for slot in &mut table[cursor..cursor + cells] {
                *slot = DecodeCell {
                    // INVARIANT: sym fits in u8 because the weights
                    // vector is at most 256 entries long; callers
                    // enforce this at the wire-format layer.
                    symbol: sym as u8,
                    // INVARIANT: code_length <= max_num_bits <= 11,
                    // so the `as u8` cast cannot truncate.
                    code_length: code_length as u8,
                };
            }
            cursor += cells;
        }
        // Sanity: every cell got filled.
        debug_assert_eq!(cursor, table_size);

        Ok(Self {
            table,
            max_num_bits,
        })
    }

    /// Decode one symbol from `bits`.
    ///
    /// Peeks `max_num_bits` bits to index the decode table, then
    /// advances the bitstream by the cell's `code_length` — which
    /// may be shorter (canonical Huffman codes are variable-length).
    ///
    /// # Errors
    ///
    /// - [`ZstdError::UnexpectedEof`] when the bitstream has fewer
    ///   than `code_length` bits remaining (the peek itself fails
    ///   first if there are fewer than `max_num_bits` available).
    pub fn decode(&self, bits: &mut ReverseBitReader) -> Result<u8, ZstdError> {
        let (sym, code_length) = self.peek_lookup(bits)?;
        bits.advance(u32::from(code_length))?;
        Ok(sym)
    }

    /// Peek a single decode without advancing the bitstream.
    ///
    /// Returns `(symbol, code_length)`. The caller advances the
    /// stream by `code_length`. This is the building block of
    /// [`Self::decode`]; exposed separately so the literals
    /// decoder can fuse a peek and advance with surrounding work
    /// (e.g., bounds checks against the regenerated-size budget).
    ///
    /// When the bitstream has fewer than `max_num_bits` bits
    /// remaining the peek pads the missing low bits with zeros so
    /// the lookup still resolves to *some* symbol. Callers who
    /// care about EOF before consuming a partial last symbol must
    /// check [`ReverseBitReader::bits_remaining`] themselves.
    ///
    /// # Errors
    ///
    /// - [`ZstdError::MalformedFrameHeader`] only if the bitstream
    ///   reader's invariants are broken upstream; structurally this
    ///   call cannot fail today.
    pub fn peek_lookup(&self, bits: &mut ReverseBitReader) -> Result<(u8, u8), ZstdError> {
        let want = self.max_num_bits;
        let avail = bits.bits_remaining() as u32;
        let peek_bits = want.min(avail);
        let raw = bits.peek(peek_bits)?;
        // The decode table is indexed by `max_num_bits` bits MSB-aligned.
        // When fewer bits are available, shift left to pad the missing
        // low bits with zeros — this matches how libzstd handles the
        // tail of a Huffman stream where the last symbol may be shorter
        // than max_num_bits.
        let idx_shifted = raw << (want - peek_bits);
        let idx = (idx_shifted as usize) & (self.table.len() - 1);
        let cell = self.table[idx];
        Ok((cell.symbol, cell.code_length))
    }

    /// Maximum Huffman code length (in bits) — the table has
    /// `2^Self::max_num_bits` entries.
    #[must_use]
    pub fn max_num_bits(&self) -> u32 {
        self.max_num_bits
    }
}

/// Compute the implicit final weight from a vector of `n - 1`
/// explicit weights.
///
/// The wire format elides the last weight; the decoder reconstructs
/// it from the sum invariant
/// `sum(2^w for w >= 1) == 2^(max_weight + 1)`.
///
/// # Errors
///
/// - [`ZstdError::MalformedFrameHeader`] when the partial sum is
///   already at or above `2^(max_weight + 1)`, when the residual is
///   not a power of two, or when the resulting weight would exceed
///   `max_weight`.
pub fn compute_implicit_weight(explicit: &[u8]) -> Result<u8, ZstdError> {
    if explicit.is_empty() {
        return Err(ZstdError::MalformedFrameHeader(
            "Huffman: cannot derive implicit weight from empty list",
        ));
    }
    let max_weight = explicit.iter().copied().max().unwrap_or(0);
    if max_weight == 0 {
        return Err(ZstdError::MalformedFrameHeader(
            "Huffman: explicit weights all zero",
        ));
    }
    if u32::from(max_weight) > MAX_HUFFMAN_CODE_BITS {
        return Err(ZstdError::MalformedFrameHeader("Huffman: max weight > 11"));
    }
    let mut sum: u64 = 0;
    for &w in explicit {
        if w == 0 {
            continue;
        }
        sum = sum.saturating_add(1u64 << w);
    }
    let target = 1u64 << (u32::from(max_weight) + 1);
    if sum >= target {
        return Err(ZstdError::MalformedFrameHeader(
            "Huffman: explicit weights overflow the complete-code budget",
        ));
    }
    let residual = target - sum;
    if !residual.is_power_of_two() {
        return Err(ZstdError::MalformedFrameHeader(
            "Huffman: implicit residual is not a power of two",
        ));
    }
    // residual = 2^w_implicit. trailing_zeros gives w_implicit.
    let w_implicit = residual.trailing_zeros();
    if w_implicit > u32::from(max_weight) {
        return Err(ZstdError::MalformedFrameHeader(
            "Huffman: implicit weight exceeds max weight",
        ));
    }
    // INVARIANT: 0 <= w_implicit <= max_weight <= 11, so the
    // `as u8` cast cannot truncate.
    Ok(w_implicit as u8)
}

/// Parse an FSE-coded weight description (RFC 8478 §4.2.1.2) from
/// `bytes`. The first byte of `bytes` is the on-wire header byte
/// `< 128`, and `bytes[0]` itself is interpreted as the
/// **compressed size** of the FSE description plus weight bitstream
/// — i.e. the number of bytes the parser will consume from
/// `bytes[1..]`.
///
/// Returns the full weight vector (including the implicit final
/// weight) and the number of bytes consumed from `bytes`
/// (`1 + bytes[0] as usize`).
///
/// # Errors
///
/// - [`ZstdError::UnexpectedEof`] when `bytes` is shorter than
///   `1 + bytes[0]`.
/// - [`ZstdError::MalformedFrameHeader`] when the FSE distribution
///   or downstream weight stream is structurally invalid.
pub fn parse_fse_weights(bytes: &[u8]) -> Result<(Vec<u8>, usize), ZstdError> {
    if bytes.is_empty() {
        return Err(ZstdError::UnexpectedEof("Huffman FSE weight description"));
    }
    let header_byte = bytes[0];
    if header_byte >= 128 {
        return Err(ZstdError::MalformedFrameHeader(
            "Huffman FSE weights: header byte >= 128 (direct mode)",
        ));
    }
    let compressed_size = usize::from(header_byte);
    if bytes.len() < 1 + compressed_size {
        return Err(ZstdError::UnexpectedEof(
            "Huffman FSE weights: payload truncated",
        ));
    }
    let payload = &bytes[1..1 + compressed_size];

    // Parse the FSE distribution from a forward bitstream over
    // `payload`. Cap the symbol space at 255 (Huffman alphabet is
    // bytes), the accuracy_log at the FSE-Huffman cap.
    let mut fwd = ForwardBitReader::new(payload);
    let parsed = parse_distribution(&mut fwd, MAX_FSE_HUFFMAN_ACCURACY_LOG, 255)?;
    let table = FseTable::build(&parsed.counts, parsed.accuracy_log)?;

    // The weight stream is whatever bytes remain after the
    // distribution description.
    if parsed.bytes_consumed > payload.len() {
        return Err(ZstdError::MalformedFrameHeader(
            "Huffman FSE weights: distribution overran payload",
        ));
    }
    let stream = &payload[parsed.bytes_consumed..];
    let weights = decode_fse_weight_stream(stream, &table)?;

    if weights.is_empty() {
        return Err(ZstdError::MalformedFrameHeader(
            "Huffman FSE weights: zero weights decoded",
        ));
    }
    let mut full = weights;
    let implicit = compute_implicit_weight(&full)?;
    full.push(implicit);
    Ok((full, 1 + compressed_size))
}

/// Decode a 2-state FSE weight stream from a reverse bitstream.
///
/// RFC 8478 §4.2.1.2 specifies that two FSE states alternate, with
/// state1 emitting the weight at index 0, state2 at index 1, state1
/// at index 2, and so on. The decoder stops when there aren't
/// enough bits left to perform a state transition; at that point
/// both remaining states emit one final symbol each.
fn decode_fse_weight_stream(stream: &[u8], table: &FseTable) -> Result<Vec<u8>, ZstdError> {
    let mut br = ReverseBitReader::new(stream)?;
    let mut state1 = table.read_initial(&mut br)?;
    let mut state2 = table.read_initial(&mut br)?;
    let mut weights: Vec<u8> = Vec::new();
    // Cap the loop so a bug in num_bits accounting can't loop forever.
    // Huffman alphabet is at most 256 symbols, so weight count <= 255.
    const MAX_WEIGHTS: usize = 255;
    loop {
        let cell1 = *table.cell(state1)?;
        weights.push(cell1.symbol);
        if weights.len() >= MAX_WEIGHTS {
            break;
        }
        if br.bits_remaining() < usize::from(cell1.num_bits) {
            // Cannot transition state1 — emit state2's final
            // symbol and stop.
            let cell2 = table.cell(state2)?;
            weights.push(cell2.symbol);
            break;
        }
        state1 = table.transition(&cell1, &mut br)?;

        let cell2 = *table.cell(state2)?;
        weights.push(cell2.symbol);
        if weights.len() >= MAX_WEIGHTS {
            break;
        }
        if br.bits_remaining() < usize::from(cell2.num_bits) {
            // Cannot transition state2 — emit state1's final
            // symbol (already updated) and stop.
            let cell1_final = table.cell(state1)?;
            weights.push(cell1_final.symbol);
            break;
        }
        state2 = table.transition(&cell2, &mut br)?;
    }
    Ok(weights)
}

/// Parse a direct-encoded weight description (RFC 8478 §4.2.1.1)
/// from `bytes`.
///
/// `n_symbols_minus_1` is the count taken from the header byte:
/// the on-wire description carries `n_symbols_minus_1` weights and
/// the decoder reconstructs the implicit final weight. Returns
/// the full weight vector (length `n_symbols_minus_1 + 1`) and the
/// number of bytes consumed from `bytes`.
///
/// # Errors
///
/// - [`ZstdError::UnexpectedEof`] when `bytes` is shorter than
///   `ceil(n_symbols_minus_1 / 2)`.
/// - [`ZstdError::MalformedFrameHeader`] when the implicit weight
///   computation fails (see [`compute_implicit_weight`]).
pub fn parse_direct_weights(
    bytes: &[u8],
    n_symbols_minus_1: usize,
) -> Result<(Vec<u8>, usize), ZstdError> {
    let bytes_needed = n_symbols_minus_1.div_ceil(2);
    if bytes.len() < bytes_needed {
        return Err(ZstdError::UnexpectedEof("Huffman direct weights"));
    }
    let mut weights = Vec::with_capacity(n_symbols_minus_1 + 1);
    for i in 0..n_symbols_minus_1 {
        let byte_idx = i / 2;
        // High nibble first per RFC §4.2.1.1.
        let nibble = if i % 2 == 0 {
            bytes[byte_idx] >> 4
        } else {
            bytes[byte_idx] & 0x0F
        };
        if u32::from(nibble) > MAX_HUFFMAN_CODE_BITS {
            return Err(ZstdError::MalformedFrameHeader(
                "Huffman direct weight > 11",
            ));
        }
        weights.push(nibble);
    }
    let implicit = compute_implicit_weight(&weights)?;
    weights.push(implicit);
    Ok((weights, bytes_needed))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Index every cell of the decode table for sanity-checking
    /// canonical placement. Goes via the `peek_lookup` path with a
    /// hand-crafted reverse bitstream whose first `max_num_bits`
    /// peek-bits are exactly `idx`.
    fn lookup_via_table(tree: &HuffmanTree, idx: u32) -> (u8, u8) {
        // Build a reverse bitstream containing exactly `max_num_bits`
        // bits of value `idx` (MSB-first), padded with a sentinel.
        let n = tree.max_num_bits();
        // Bit layout (MSB-first across the byte buffer):
        //   [zero pad...][sentinel 1][idx bits MSB-first]
        // Shortest single-byte encoding works for n + 1 <= 8.
        // For wider trees we'd need multi-byte encoding; Phase 3's
        // tests stay in the n <= 4 regime so this is enough.
        assert!(n < 8, "test helper only supports tiny trees");
        let mut byte: u8 = 0;
        // Place data bits in positions n-1..=0.
        for bit in 0..n {
            let b = (idx >> (n - 1 - bit)) & 1;
            byte |= (b as u8) << (n - 1 - bit);
        }
        // Sentinel one position above MSB of data.
        byte |= 1 << n;
        let buf = [byte];
        let mut br = ReverseBitReader::new(&buf).expect("ok");
        tree.peek_lookup(&mut br).expect("lookup")
    }

    #[test]
    fn from_direct_weights_simple_two_symbol_tree() {
        // Two symbols with weight 1 each: codes 0 and 1, both 1 bit.
        // max_weight = 1, table_size = 2, code_length = 1.
        // sum(2^w) = 2 + 2 = 4 = 2^(1+1). ✓
        let tree = HuffmanTree::from_direct_weights(&[1, 1]).expect("build");
        assert_eq!(tree.max_num_bits(), 1);
        assert_eq!(lookup_via_table(&tree, 0), (0, 1));
        assert_eq!(lookup_via_table(&tree, 1), (1, 1));
    }

    #[test]
    fn from_direct_weights_three_symbol_unbalanced_tree() {
        // Symbol 0 weight 2 (code length 1, 1 bit), symbols 1 and 2
        // weight 1 (code length 2, 2 bits each).
        // sum(2^w) = 4 + 2 + 2 = 8 = 2^(2+1). ✓
        // Canonical assignment (descending weight, then symbol):
        //   sym 0: w=2, length=1, 2 cells [0..2)
        //   sym 1: w=1, length=2, 1 cell [2..3)
        //   sym 2: w=1, length=2, 1 cell [3..4)
        let tree = HuffmanTree::from_direct_weights(&[2, 1, 1]).expect("build");
        assert_eq!(tree.max_num_bits(), 2);
        assert_eq!(lookup_via_table(&tree, 0), (0, 1));
        assert_eq!(lookup_via_table(&tree, 1), (0, 1));
        assert_eq!(lookup_via_table(&tree, 2), (1, 2));
        assert_eq!(lookup_via_table(&tree, 3), (2, 2));
    }

    #[test]
    fn from_direct_weights_rejects_incomplete_code() {
        // sum = 2 + 2 + 2 = 6, target = 8. Residual = 2 (a power
        // of two!) — but that would mean adding another symbol of
        // weight 1, not the malformedness we want to assert.
        // Use [2, 1] which sums to 6, target 8, residual 2 — still
        // valid as a 3-symbol tree if the caller forgot the
        // implicit weight, but `from_direct_weights` is the
        // *post-implicit* call so [2, 1] alone (sum=6) is incomplete.
        let r = HuffmanTree::from_direct_weights(&[2, 1]);
        assert!(matches!(r, Err(ZstdError::MalformedFrameHeader(_))));
    }

    #[test]
    fn from_direct_weights_rejects_all_zero() {
        let r = HuffmanTree::from_direct_weights(&[0, 0, 0]);
        assert!(matches!(r, Err(ZstdError::MalformedFrameHeader(_))));
    }

    #[test]
    fn from_direct_weights_rejects_max_weight_above_11() {
        let mut weights = vec![0u8; 4];
        weights[0] = 12;
        let r = HuffmanTree::from_direct_weights(&weights);
        assert!(matches!(r, Err(ZstdError::MalformedFrameHeader(_))));
    }

    #[test]
    fn from_direct_weights_handles_zero_weight_symbols() {
        // 4 symbols, two absent, two present with weight 1.
        // Tree should ignore the zero-weight ones.
        let tree = HuffmanTree::from_direct_weights(&[0, 1, 0, 1]).expect("build");
        assert_eq!(tree.max_num_bits(), 1);
        assert_eq!(lookup_via_table(&tree, 0), (1, 1));
        assert_eq!(lookup_via_table(&tree, 1), (3, 1));
    }

    #[test]
    fn compute_implicit_weight_basic() {
        // Explicit [2, 1] sums to 6; max_weight = 2; target = 8;
        // residual = 2 = 2^1, implicit = 1.
        assert_eq!(compute_implicit_weight(&[2, 1]).expect("ok"), 1);
    }

    #[test]
    fn compute_implicit_weight_zero_implicit() {
        // Explicit [2, 1, 1] sums to 8; target = 8; residual = 0
        // — implicit weight should be ... well, residual=0 means
        // no implicit symbol, but the wire format always carries
        // one. We surface this as malformed because residual 0 is
        // not a positive power of two.
        assert!(compute_implicit_weight(&[2, 1, 1]).is_err());
    }

    #[test]
    fn compute_implicit_weight_overflow_is_error() {
        // Explicit weights overshoot the budget.
        assert!(compute_implicit_weight(&[3, 3]).is_err());
    }

    #[test]
    fn compute_implicit_weight_residual_must_be_power_of_two() {
        // Sum = 2^3 + 2^1 = 10; max_weight = 3; target = 16;
        // residual = 6 — not a power of two.
        assert!(compute_implicit_weight(&[3, 1]).is_err());
    }

    #[test]
    fn parse_direct_weights_round_trips_packed_nibbles() {
        // 4 symbols: explicit weights [3, 1, 1] + implicit weight.
        //   sum = 8 + 2 + 2 = 12, max_weight = 3, target = 16,
        //   residual = 4 = 2^2 -> implicit = 2.
        // n_symbols_minus_1 = 3 -> 3 nibbles -> 2 bytes (last byte's
        // low nibble unused).
        // Nibbles 3, 1, 1 packed high-first: 0x31, 0x10.
        let bytes = [0x31, 0x10];
        let (weights, consumed) = parse_direct_weights(&bytes, 3).expect("parse");
        assert_eq!(consumed, 2);
        assert_eq!(weights, vec![3, 1, 1, 2]);
    }

    #[test]
    fn parse_direct_weights_even_count() {
        // n_symbols_minus_1 = 4 -> 2 bytes, 4 nibbles, no waste.
        // Weights: [3, 2, 2, 1, ?]. sum = 8 + 4 + 4 + 2 = 18,
        // max_weight = 3, target = 16. 18 > 16 -> overflow.
        let bytes = [0x32, 0x21];
        let r = parse_direct_weights(&bytes, 4);
        assert!(matches!(r, Err(ZstdError::MalformedFrameHeader(_))));
    }

    #[test]
    fn parse_direct_weights_rejects_truncated() {
        let bytes = [0x21];
        let r = parse_direct_weights(&bytes, 4);
        assert!(matches!(r, Err(ZstdError::UnexpectedEof(_))));
    }

    #[test]
    fn parse_direct_weights_rejects_nibble_above_11() {
        // 0xCC has both nibbles = 12, which is above the cap.
        let bytes = [0xCC];
        let r = parse_direct_weights(&bytes, 1);
        assert!(matches!(r, Err(ZstdError::MalformedFrameHeader(_))));
    }

    /// Round-trip: encode a known sequence MSB-first into a
    /// reverse bitstream and decode it through the canonical
    /// table. Locks the bit ordering so a future "cleanup" of
    /// peek_lookup or the bitstream reader can't silently flip
    /// it.
    #[test]
    fn decode_round_trips_canonical_sequence() {
        // Tree: sym 0 -> '0' (1 bit), sym 1 -> '10' (2 bits),
        // sym 2 -> '11' (2 bits). Canonical 3-symbol Huffman.
        let tree = HuffmanTree::from_direct_weights(&[2, 1, 1]).expect("build");

        // Sequence in stream order: sym 0 (code '0'), sym 1
        // (code '10'), sym 2 (code '11'). MSB-first bit pattern:
        //   0  1 0  1 1  = 5 data bits.
        // Reverse-bitstream layout (one byte): top of byte = sentinel,
        // then data MSB-first.
        //   bit 7 (MSB): 0 (zero-pad above sentinel)
        //   bit 6      : 1 (sentinel)
        //   bit 5      : 0 (sym 0)
        //   bit 4      : 1 \
        //   bit 3      : 0  } sym 1
        //   bit 2      : 1 \
        //   bit 1      : 1  } sym 2
        //   bit 0      : 0 (unused — total 5 data bits but byte has 6 below sentinel)
        // Wait: with sentinel at bit 6, there are 6 data bits below
        // (bits 5..0). We have 5 data bits, so bit 0 is "extra" and
        // would be a 6th data bit at the end.
        //
        // To keep the math clean, pad data with one extra leading
        // 0 (read first, ignored by us before the test). Stream:
        //   bit 7: 0 (zero pad)
        //   bit 6: 1 (sentinel)
        //   bit 5: 0 (sym 0)
        //   bit 4: 1 (sym 1, top)
        //   bit 3: 0 (sym 1, bottom)
        //   bit 2: 1 (sym 2, top)
        //   bit 1: 1 (sym 2, bottom)
        //   bit 0: 0 (trailing pad — never reached)
        // = 0b0_1_0_1_0_1_1_0 = 0x56.
        let stream = [0x56u8];
        let mut br = ReverseBitReader::new(&stream).expect("ok");
        // First decode reads 1 bit (sym 0 has code_length 1).
        assert_eq!(tree.decode(&mut br).expect("sym 0"), 0);
        // Second decode reads 2 bits (sym 1 has code_length 2).
        assert_eq!(tree.decode(&mut br).expect("sym 1"), 1);
        // Third decode reads 2 bits (sym 2 has code_length 2).
        assert_eq!(tree.decode(&mut br).expect("sym 2"), 2);
        // After three decodes, only the trailing pad bit remains.
        assert_eq!(br.bits_remaining(), 1);
    }
}
