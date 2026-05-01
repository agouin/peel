//! Canonical-Huffman tree for zstd literal decoding (RFC 8478 §4.2).
//!
//! Both encodings of the weight description are supported:
//!
//! - **Direct** (header byte ≥ 128): weights are packed 4 bits per
//!   symbol, high nibble first. See [`parse_direct_weights`].
//! - **FSE-coded** (header byte < 128): the 1-byte header gives the
//!   compressed size of an FSE distribution description plus a
//!   2-state interleaved weight bitstream. See [`parse_fse_weights`].
//!
//! # Wire format recap
//!
//! For a symbol with weight `w >= 1`:
//!
//! ```text
//! code_length = max_num_bits + 1 - w
//! cells_in_decode_table = 1 << (w - 1)
//! ```
//!
//! Symbols with `w == 0` are absent from the alphabet.
//!
//! Sum invariant (RFC 8478 §4.2.1): `sum(2^w for w >= 1) ==
//! 2^(max_num_bits + 1)`, where `max_num_bits` is the longest
//! Huffman code length. The encoder writes `n - 1` weights
//! explicitly and the decoder computes the implicit n-th weight
//! from this sum. `max_num_bits` is derived from the *sum*, not
//! from `max(weights)`: when no symbol carries the longest code
//! length the implicit weight does, and `max_num_bits` exceeds
//! every explicit weight (matches libzstd's `HUF_readStats_body`).
//!
//! # Decoding
//!
//! [`HuffmanTree::decode`] reads one symbol from a [`ReverseBitReader`]
//! by peeking `max_num_bits` bits (always exactly that many),
//! looking up the entry, and advancing by the entry's code length.
//! Per the plan §Phase 3, we use the straight bit-by-bit table —
//! fast-path tables (Huffman X2 / X4) are deferred to Phase 11.

use super::bitstream::{ForwardBitReader, ReverseBitReader};
use super::error::ZstdError;
use super::fse::{parse_distribution, FseTable, MAX_FSE_HUFFMAN_ACCURACY_LOG};

/// RFC 8478 caps Huffman code lengths at 11 bits
/// (`max_num_bits <= 11`).
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
    ///   when the resulting `max_num_bits > MAX_HUFFMAN_CODE_BITS`.
    pub fn from_direct_weights(weights: &[u8]) -> Result<Self, ZstdError> {
        if weights.is_empty() {
            return Err(ZstdError::MalformedFrameHeader(
                "Huffman: empty weight vector",
            ));
        }
        // Sum invariant (RFC 8478 §4.2.1): `sum(2^w) over present
        // symbols == 2^(max_num_bits + 1)`, where `max_num_bits` is
        // the longest Huffman code length. `max_num_bits` is derived
        // from the sum, NOT from `max(weights)`: it can exceed every
        // explicit weight when no symbol has the longest code length
        // (e.g. an implicit weight of 1 with only `weight ≤ 8`
        // explicits can still yield `max_num_bits = 9`).
        let mut weight_sum: u64 = 0;
        for &w in weights {
            if w == 0 {
                continue;
            }
            if u32::from(w) > MAX_HUFFMAN_CODE_BITS {
                return Err(ZstdError::MalformedFrameHeader("Huffman: weight > 11"));
            }
            weight_sum = weight_sum.saturating_add(1u64 << w);
        }
        if weight_sum == 0 {
            return Err(ZstdError::MalformedFrameHeader(
                "Huffman: no symbol has a positive weight",
            ));
        }
        if !weight_sum.is_power_of_two() {
            return Err(ZstdError::MalformedFrameHeader(
                "Huffman: sum-of-2^w not a complete power of two",
            ));
        }
        // weight_sum == 2^(max_num_bits + 1), so max_num_bits =
        // log2(weight_sum) - 1 = trailing_zeros(weight_sum) - 1.
        let max_num_bits = weight_sum.trailing_zeros() - 1;
        if max_num_bits > MAX_HUFFMAN_CODE_BITS {
            return Err(ZstdError::MalformedFrameHeader(
                "Huffman: max code length > 11 bits",
            ));
        }
        for &w in weights {
            if u32::from(w) > max_num_bits {
                return Err(ZstdError::MalformedFrameHeader(
                    "Huffman: weight exceeds derived max code length",
                ));
            }
        }

        let table_size = 1usize << max_num_bits;
        let mut table: Vec<DecodeCell> = vec![
            DecodeCell {
                symbol: 0,
                code_length: 0,
            };
            table_size
        ];

        // Canonical-Huffman placement per RFC 8478 §4.2.1.3:
        // "Symbols are first sorted by Weight, then by natural
        // sequential order. ... starting from lowest Weight (hence
        // highest Number_of_Bits), prefix codes are assigned in
        // ascending order." So we sort ascending by weight, then
        // ascending by symbol index, and place each symbol's cells
        // consecutively from cursor 0. This produces a table where
        // the lowest indices map to the lowest-numbered codes (long
        // codes), matching libzstd's `HUF_readDTableX1_wksp`.
        let mut sorted: Vec<u32> = (0..weights.len() as u32)
            .filter(|&i| weights[i as usize] > 0)
            .collect();
        sorted.sort_by(|&a, &b| {
            let wa = weights[a as usize];
            let wb = weights[b as usize];
            wa.cmp(&wb).then(a.cmp(&b))
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
/// `sum(2^w for w >= 1) == 2^(max_num_bits + 1)`, where
/// `max_num_bits` is the longest Huffman code length (the FSE-style
/// "tableLog"). `max_num_bits` is derived from the *sum* of explicit
/// weights, not from `max(explicit)`: when no symbol carries the
/// longest code length, `max_num_bits` can legitimately exceed every
/// explicit weight (matches libzstd's `HUF_readStats_body`).
///
/// # Errors
///
/// - [`ZstdError::MalformedFrameHeader`] when the partial sum is
///   zero or non-positive, when the residual is not a power of two,
///   or when the derived `max_num_bits` exceeds
///   [`MAX_HUFFMAN_CODE_BITS`].
pub fn compute_implicit_weight(explicit: &[u8]) -> Result<u8, ZstdError> {
    if explicit.is_empty() {
        return Err(ZstdError::MalformedFrameHeader(
            "Huffman: cannot derive implicit weight from empty list",
        ));
    }
    // Sum (2^(w-1)) over explicit weights. This is libzstd's
    // `weightTotal` in `HUF_readStats_body`. Use 2^(w-1) (not 2^w)
    // so the implicit weight's contribution (also a power of two)
    // tops up `weightTotal` to the next higher power of two — that
    // power is `2^max_num_bits`, and the bit count of the residual
    // gives the implicit weight directly.
    let mut weight_total: u64 = 0;
    for &w in explicit {
        if w == 0 {
            continue;
        }
        if u32::from(w) > MAX_HUFFMAN_CODE_BITS {
            return Err(ZstdError::MalformedFrameHeader("Huffman: weight > 11"));
        }
        // (1 << w) >> 1 == 1 << (w-1) when w >= 1.
        weight_total = weight_total.saturating_add(1u64 << (u32::from(w) - 1));
    }
    if weight_total == 0 {
        return Err(ZstdError::MalformedFrameHeader(
            "Huffman: explicit weights all zero",
        ));
    }
    // max_num_bits = floor(log2(weight_total)) + 1 = ceil(log2(weight_total + 1)).
    // For weight_total in [1, 2047] (cap from MAX_HUFFMAN_CODE_BITS),
    // 64 - leading_zeros gives floor(log2(x)) + 1 directly.
    let max_num_bits = 64 - weight_total.leading_zeros();
    if max_num_bits > MAX_HUFFMAN_CODE_BITS {
        return Err(ZstdError::MalformedFrameHeader(
            "Huffman: derived max code length > 11 bits",
        ));
    }
    let target = 1u64 << max_num_bits;
    let rest = target - weight_total;
    if rest == 0 || !rest.is_power_of_two() {
        return Err(ZstdError::MalformedFrameHeader(
            "Huffman: implicit residual is not a power of two",
        ));
    }
    // rest = 2^(w_implicit - 1). trailing_zeros gives w_implicit - 1.
    let w_implicit = rest.trailing_zeros() + 1;
    // INVARIANT: 1 <= w_implicit <= max_num_bits <= 11, so the
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
        // sum(2^w) = 4 + 2 + 2 = 8 = 2^(2+1) -> max_num_bits = 2.
        // Canonical assignment per RFC 8478 §4.2.1.3 (ascending
        // weight, then symbol; codes start at 0):
        //   sym 1: w=1, code=00, 1 cell [0..1)
        //   sym 2: w=1, code=01, 1 cell [1..2)
        //   sym 0: w=2, code=1,  2 cells [2..4)
        let tree = HuffmanTree::from_direct_weights(&[2, 1, 1]).expect("build");
        assert_eq!(tree.max_num_bits(), 2);
        assert_eq!(lookup_via_table(&tree, 0), (1, 2));
        assert_eq!(lookup_via_table(&tree, 1), (2, 2));
        assert_eq!(lookup_via_table(&tree, 2), (0, 1));
        assert_eq!(lookup_via_table(&tree, 3), (0, 1));
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
    fn compute_implicit_weight_can_exceed_max_explicit() {
        // Explicit [2, 1, 1]: weight_total = sum(2^(w-1)) = 2+1+1
        // = 4. max_num_bits = floor(log2(4)) + 1 = 3, target = 8,
        // rest = 4 = 2^2 -> implicit weight = 3, which exceeds
        // max(explicit) = 2. Per RFC 8478 §4.2.1 / libzstd's
        // `HUF_readStats_body` this is valid: the implicit symbol
        // simply carries the longest code length when no explicit
        // symbol does.
        assert_eq!(compute_implicit_weight(&[2, 1, 1]).expect("ok"), 3);
    }

    #[test]
    fn compute_implicit_weight_powers_of_two_cap_implicit_at_max_num_bits() {
        // Explicit [3, 3]: weight_total = 4 + 4 = 8 = 2^3.
        // max_num_bits = floor(log2(8)) + 1 = 4, target = 16,
        // rest = 8 = 2^3 -> implicit weight = 4. Tree:
        // [3, 3, 4] with code lengths [2, 2, 1].
        assert_eq!(compute_implicit_weight(&[3, 3]).expect("ok"), 4);
    }

    #[test]
    fn compute_implicit_weight_residual_must_be_power_of_two() {
        // Explicit [3, 1]: weight_total = 4 + 1 = 5.
        // max_num_bits = floor(log2(5)) + 1 = 3, target = 8,
        // rest = 3 — not a power of two -> malformed.
        assert!(compute_implicit_weight(&[3, 1]).is_err());
    }

    #[test]
    fn compute_implicit_weight_rejects_weight_above_11() {
        // Any explicit weight > 11 is rejected before any other
        // arithmetic.
        assert!(compute_implicit_weight(&[12, 1]).is_err());
    }

    #[test]
    fn compute_implicit_weight_real_libzstd_shaped_input() {
        // Mirrors the failing fixture from the
        // `fse_huffman_weights_decode_against_libzstd_frames`
        // validation test: 217 weight-1, 35 weight-2, 1 weight-6,
        // 1 weight-7, 1 weight-8 — total 255 explicit weights.
        // weight_total = 217 + 70 + 32 + 64 + 128 = 511.
        // max_num_bits = floor(log2(511)) + 1 = 9, target = 512,
        // rest = 1 = 2^0 -> implicit weight = 1.
        let mut explicit = vec![1u8; 217];
        explicit.extend(std::iter::repeat_n(2u8, 35));
        explicit.extend([6u8, 7, 8]);
        assert_eq!(compute_implicit_weight(&explicit).expect("ok"), 1);
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
    /// table. Locks the bit ordering and the canonical-Huffman
    /// code assignment (RFC 8478 §4.2.1.3) so a future "cleanup"
    /// of peek_lookup, the bitstream reader, or the canonical
    /// placement direction can't silently flip them.
    #[test]
    fn decode_round_trips_canonical_sequence() {
        // Tree: weights = [2, 1, 1]. Canonical assignment per RFC
        // §4.2.1.3 (ascending weight, then symbol; codes start at
        // 0): sym 1 -> '00' (2 bits), sym 2 -> '01' (2 bits),
        // sym 0 -> '1' (1 bit). The shortest code goes to the
        // highest-weight symbol; lower-weight symbols share a
        // prefix that begins with 0.
        let tree = HuffmanTree::from_direct_weights(&[2, 1, 1]).expect("build");

        // Sequence in stream order: sym 0, sym 1, sym 2.
        // MSB-first bit pattern: 1 00 01 = 5 data bits.
        // Reverse-stream layout (one byte): leading-zero pad +
        // sentinel + data MSB-first + trailing pad.
        //   bit 7: 0 (zero pad above sentinel)
        //   bit 6: 1 (sentinel)
        //   bit 5: 1 (sym 0)
        //   bit 4: 0 (sym 1, top)
        //   bit 3: 0 (sym 1, bottom)
        //   bit 2: 0 (sym 2, top)
        //   bit 1: 1 (sym 2, bottom)
        //   bit 0: 0 (trailing pad — never reached)
        // = 0b0_1_1_0_0_0_1_0 = 0x62.
        let stream = [0x62u8];
        let mut br = ReverseBitReader::new(&stream).expect("ok");
        assert_eq!(tree.decode(&mut br).expect("sym 0"), 0);
        assert_eq!(tree.decode(&mut br).expect("sym 1"), 1);
        assert_eq!(tree.decode(&mut br).expect("sym 2"), 2);
        // After three decodes, only the trailing pad bit remains.
        assert_eq!(br.bits_remaining(), 1);
    }
}
