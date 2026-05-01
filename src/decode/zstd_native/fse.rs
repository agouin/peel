//! Finite-State Entropy (FSE) — distribution wire-format parsing,
//! state-table construction, and per-symbol decoding (RFC 8478 §4.1).
//!
//! FSE shows up in two places inside a Compressed_Block:
//!
//! - The Huffman weight description (RFC §4.2.1.2) when the
//!   header byte is `< 128`. That use site is wired up by
//!   [`super::huffman`] in Phase 4b.
//! - The sequences section's three independent tables for
//!   Literal_Length, Match_Length, and Offset codes (RFC §3.1.1.4).
//!   Wired up by `sequences.rs` in Phase 4b.
//!
//! Phase 4a — this file — lands the format-agnostic primitives both
//! callers share:
//!
//! - [`parse_distribution`] reads a normalized-counts array from a
//!   forward bitstream (RFC §4.1.1).
//! - [`FseTable::build`] constructs a state-table (RFC §4.1.1) from
//!   a normalized-counts array.
//! - [`FseTable::next_state`] is the per-decode-step state machine.
//! - [`PREDEFINED_LL`], [`PREDEFINED_ML`], [`PREDEFINED_OF`] hold
//!   the spec-mandated default distributions used by
//!   `Predefined_Mode` sequence tables.
//!
//! # Wire format recap (§4.1.1)
//!
//! For each symbol from index 0 onwards the encoder writes a value
//! `v ∈ [0, remaining]`:
//!
//! | `v`      | meaning                | `remaining` decrement |
//! |----------|------------------------|-----------------------|
//! | `0`      | probability = −1       | 1                     |
//! | `1`      | probability = 0 + RLE  | 1                     |
//! | `≥ 2`    | probability = `v − 1`  | `v − 1`               |
//!
//! `bit_count = ceil(log2(remaining + 1))`. Codes split:
//!
//! - Short: `v < L` where `L = (1 << bit_count) − 1 − remaining`
//!   uses `bit_count − 1` bits and is encoded as itself.
//! - Long:  `v >= L` uses `bit_count` bits, mapped so that the
//!   decoder reads `bit_count − 1` bits as `low_val`, sees
//!   `low_val >= L`, reads one more bit as `extra`, treats the
//!   combined `bit_count`-bit value as `full_value =
//!   low_val | (extra << (bit_count - 1))`, then reconstructs
//!   `v = full_value − L * extra`. (The high bit being set means
//!   the encoder folded the value down by L to keep its low
//!   `bit_count − 1` bits >= L; the decoder undoes that fold.)
//!
//! After a `v == 1` (probability-zero symbol), the encoder writes
//! a 2-bit RLE count of *additional* zero-probability symbols; if
//! that count is `3`, it reads 2 more bits and continues until a
//! value `< 3` terminates.
//!
//! See `docs/PLAN_zstd_block_decoder.md` Appendix A for the Phase 0
//! spike memo that flagged the FSE parser as the trickiest single
//! piece in the whole spec.

use super::bitstream::{ForwardBitReader, ReverseBitReader};
use super::error::ZstdError;

// ---- Spec caps -----------------------------------------------------

/// Largest `accuracy_log` (table-log) any FSE table in zstd uses.
///
/// Per RFC 8478 §4.1.1, `accuracy_log <= 12` for FSE_Compressed_Mode
/// tables. Phase 4a enforces this cap at parse time.
pub const MAX_FSE_ACCURACY_LOG: u32 = 12;

/// Per-table caps on `accuracy_log` for the three sequence-section
/// FSE tables (RFC 8478 §3.1.1.4). FSE-coded Huffman weight tables
/// share the [`MAX_FSE_HUFFMAN_ACCURACY_LOG`] cap below.
pub const MAX_LL_ACCURACY_LOG: u32 = 9;
/// See [`MAX_LL_ACCURACY_LOG`].
pub const MAX_ML_ACCURACY_LOG: u32 = 9;
/// See [`MAX_LL_ACCURACY_LOG`].
pub const MAX_OF_ACCURACY_LOG: u32 = 8;
/// Cap on `accuracy_log` for FSE-coded Huffman weight tables.
pub const MAX_FSE_HUFFMAN_ACCURACY_LOG: u32 = 6;

/// Maximum symbol values for the three sequence-section codes.
pub const MAX_LL_CODE: u32 = 35;
/// See [`MAX_LL_CODE`].
pub const MAX_ML_CODE: u32 = 52;
/// See [`MAX_LL_CODE`].
pub const MAX_OF_CODE: u32 = 31;

// ---- Predefined distributions --------------------------------------
//
// Transcribed from RFC 8478 §3.1.1.4 Appendix A. These are the
// default distributions used by `Predefined_Mode` sequence tables.

/// Predefined Literal_Length distribution (RFC §3.1.1.4.1.1).
///
/// `accuracy_log = 6`, 36 symbols.
pub const PREDEFINED_LL: ([i16; 36], u32) = (
    [
        4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1,
        1, 1, -1, -1, -1, -1,
    ],
    6,
);

/// Predefined Match_Length distribution (RFC §3.1.1.4.1.2).
///
/// `accuracy_log = 6`, 53 symbols.
pub const PREDEFINED_ML: ([i16; 53], u32) = (
    [
        1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1,
    ],
    6,
);

/// Predefined Offset distribution (RFC §3.1.1.4.1.3).
///
/// `accuracy_log = 5`, 29 symbols.
pub const PREDEFINED_OF: ([i16; 29], u32) = (
    [
        1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1,
    ],
    5,
);

// ---- Distribution parser -------------------------------------------

/// Parsed result of [`parse_distribution`]: the resolved
/// `accuracy_log`, the per-symbol normalized counts (0-padded to
/// `max_symbol_value + 1`), and the number of source bytes the
/// reader consumed.
#[derive(Debug, Clone)]
pub struct ParsedDistribution {
    /// Effective accuracy_log (5..=12 for sequences-section tables;
    /// 5..=6 for FSE-coded Huffman weights).
    pub accuracy_log: u32,
    /// Per-symbol normalized counts. `0` = absent symbol, `-1` =
    /// "less probable" (one cell at the high end of the table),
    /// `>= 1` = explicit probability.
    pub counts: Vec<i16>,
    /// Bytes the parser advanced past in the underlying buffer
    /// (i.e., the size of the FSE description on the wire). Always
    /// rounded up to a whole byte even if the bit cursor stopped
    /// mid-byte.
    pub bytes_consumed: usize,
}

/// Parse an FSE normalized-counts distribution from a forward
/// bitstream.
///
/// `max_accuracy_log` is the largest accuracy_log the caller will
/// accept (e.g., 9 for LL, 6 for FSE-coded Huffman weights —
/// see the per-table constants above). `max_symbol_value` is the
/// largest legal symbol index for this table (e.g., 35 for LL).
///
/// # Errors
///
/// - [`ZstdError::MalformedFrameHeader`] when the encoded
///   `accuracy_log` exceeds `max_accuracy_log`, when the symbol
///   count overflows `max_symbol_value + 1`, when the encoded
///   distribution doesn't sum to the required total, or when a
///   single symbol's encoded value is outside `[0, remaining]`.
/// - [`ZstdError::UnexpectedEof`] when the underlying bitstream
///   runs out mid-symbol.
pub fn parse_distribution(
    reader: &mut ForwardBitReader<'_>,
    max_accuracy_log: u32,
    max_symbol_value: u32,
) -> Result<ParsedDistribution, ZstdError> {
    let accuracy_log = reader.read(4)? + 5;
    if accuracy_log > max_accuracy_log {
        return Err(ZstdError::MalformedFrameHeader(
            "FSE: accuracy_log exceeds per-table cap",
        ));
    }
    let table_size: i32 = 1 << accuracy_log;
    let mut counts: Vec<i16> = Vec::with_capacity(max_symbol_value as usize + 1);
    let mut remaining: i32 = table_size + 1;

    while remaining > 1 {
        if counts.len() > max_symbol_value as usize {
            return Err(ZstdError::MalformedFrameHeader(
                "FSE: too many symbols in distribution",
            ));
        }

        // bit_count = ceil(log2(remaining + 1)). Cast through u32
        // because next_power_of_two requires unsigned. The +1 is
        // safe since remaining is at least 2 here.
        let r_plus_one = (remaining as u32).saturating_add(1);
        let bit_count = r_plus_one.next_power_of_two().trailing_zeros();
        // INVARIANT: 1 <= bit_count <= MAX_FSE_ACCURACY_LOG + 1 = 13.
        let max_value: u32 = (1u32 << bit_count) - 1;
        let l: u32 = max_value - remaining as u32;

        // Read low (bit_count - 1) bits.
        let low_val = reader.read(bit_count - 1)?;
        let v: u32 = if low_val < l {
            // Short code: bit_count - 1 bits used (already read).
            low_val
        } else {
            // Long code: read 1 more bit, treat the resulting
            // bit_count-bit value as `full_value`. If the high bit
            // is set (extra == 1), the encoder folded the value
            // down by L to keep the wire-form's low (bit_count-1)
            // bits >= L. Reverse that:
            //   v = full_value - L * extra
            // For extra==0: v = full_value = low_val (range [L, 2^(bit_count-1)-1]).
            // For extra==1: v = full_value - L (range [2^(bit_count-1), 2^bit_count - 1 - L]).
            // This matches the libzstd FSE_readNCount rule
            // ("if (count >= threshold) count -= max").
            let extra = reader.read(1)?;
            let full_value = low_val | (extra << (bit_count - 1));
            full_value.saturating_sub(l * extra)
        };
        if v as i32 > remaining {
            return Err(ZstdError::MalformedFrameHeader(
                "FSE: encoded value exceeds remaining budget",
            ));
        }

        match v {
            0 => {
                // count = -1 ("less probable") — contributes 1 cell
                // at the table's high end, so decrement remaining
                // by 1.
                counts.push(-1);
                remaining -= 1;
            }
            1 => {
                // count = 0 (absent) — contributes 0 cells, so
                // remaining stays put. RLE follows for additional
                // zero-probability symbols.
                counts.push(0);
                loop {
                    let extra = reader.read(2)?;
                    for _ in 0..extra {
                        if counts.len() > max_symbol_value as usize {
                            return Err(ZstdError::MalformedFrameHeader(
                                "FSE: zero-RLE overflows max_symbol_value",
                            ));
                        }
                        counts.push(0);
                    }
                    if extra < 3 {
                        break;
                    }
                }
            }
            _ => {
                // count = v - 1, contributes (v - 1) cells.
                let count: i32 = v as i32 - 1;
                // INVARIANT: count fits in i16 because count <=
                // table_size <= 4096 (MAX_FSE_ACCURACY_LOG = 12) and
                // i16::MAX = 32767.
                counts.push(count as i16);
                remaining -= count;
            }
        }
    }

    // Pad trailing absent symbols out to max_symbol_value + 1.
    while counts.len() <= max_symbol_value as usize {
        counts.push(0);
    }

    // Round byte cursor up to next byte boundary so the caller's
    // `bytes_consumed` is wire-aligned. The bitstream may stop mid
    // byte (e.g. 33 bits for an AL=5 distribution).
    reader.align_to_byte();
    let bytes_consumed = reader.byte_position();

    Ok(ParsedDistribution {
        accuracy_log,
        counts,
        bytes_consumed,
    })
}

// ---- State-table construction --------------------------------------

/// One cell of a built FSE decode table. The `next_state` machinery
/// turns a bitstream and a current state into `(symbol, next_state,
/// bits_to_read_next)`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FseCell {
    /// Symbol associated with this state.
    pub symbol: u8,
    /// Bits to read from the bitstream for the *next* state
    /// transition.
    pub num_bits: u8,
    /// Base value the next state is read from: the new state is
    /// `base_state + (num_bits-bit value read from bitstream)`.
    pub base_state: u16,
}

/// A fully built FSE decode table.
#[derive(Debug, Clone)]
pub struct FseTable {
    /// `accuracy_log` of the table (`table.len() == 1 <<
    /// accuracy_log`).
    accuracy_log: u32,
    /// One cell per state index.
    cells: Vec<FseCell>,
}

impl FseTable {
    /// Build an FSE decode table from a normalized-counts
    /// distribution.
    ///
    /// `counts` is the per-symbol distribution from
    /// [`ParsedDistribution::counts`]. Each `>= 1` count becomes
    /// that many cells; each `-1` count becomes one cell at the
    /// high end of the table; `0` counts are skipped. The
    /// position-step permutation (RFC §4.1.1) places positive-
    /// probability symbols in a deterministic order so the
    /// encoder and decoder agree on cell layout.
    ///
    /// # Errors
    ///
    /// - [`ZstdError::MalformedFrameHeader`] when the counts don't
    ///   sum to `1 << accuracy_log` or when `accuracy_log >
    ///   MAX_FSE_ACCURACY_LOG`.
    pub fn build(counts: &[i16], accuracy_log: u32) -> Result<Self, ZstdError> {
        if accuracy_log == 0 || accuracy_log > MAX_FSE_ACCURACY_LOG {
            return Err(ZstdError::MalformedFrameHeader(
                "FSE: accuracy_log out of range for table build",
            ));
        }
        let table_size: u32 = 1u32 << accuracy_log;
        // Sum check: positive counts + count of -1 cells == table_size.
        let mut sum: i32 = 0;
        for &c in counts {
            if c == -1 {
                sum += 1;
            } else if c > 0 {
                sum += c as i32;
            } else if c < -1 {
                return Err(ZstdError::MalformedFrameHeader(
                    "FSE: count below -1 is invalid",
                ));
            }
        }
        if sum != table_size as i32 {
            return Err(ZstdError::MalformedFrameHeader(
                "FSE: counts do not sum to table size",
            ));
        }

        // Initial cells: symbol=0, num_bits=0, base_state=0; we
        // overwrite as we place symbols.
        let mut cells: Vec<FseCell> = vec![
            FseCell {
                symbol: 0,
                num_bits: 0,
                base_state: 0,
            };
            table_size as usize
        ];

        // Place "less probable" (-1) symbols at the high end,
        // decreasing index.
        let mut high_threshold = table_size;
        for (sym, &c) in counts.iter().enumerate() {
            if c == -1 {
                high_threshold -= 1;
                cells[high_threshold as usize].symbol = sym as u8;
            }
        }

        // Place positive-probability symbols using the position-
        // step permutation. Skip cells already claimed by -1
        // symbols (anything at index >= high_threshold).
        let position_step = (table_size >> 1) + (table_size >> 3) + 3;
        let position_mask = table_size - 1;
        let mut pos: u32 = 0;
        for (sym, &c) in counts.iter().enumerate() {
            if c <= 0 {
                continue;
            }
            for _ in 0..c {
                cells[pos as usize].symbol = sym as u8;
                loop {
                    pos = (pos + position_step) & position_mask;
                    if pos < high_threshold {
                        break;
                    }
                }
            }
        }

        // Compute num_bits and base_state for every cell.
        // next_state[sym] starts at:
        //   1 if c == -1
        //   c if c > 0
        // For each cell we visit (in cell-index order), look up its
        // symbol's next_state, derive num_bits = accuracy_log -
        // highest_bit(next_state[sym]), set base_state =
        // (next_state[sym] << num_bits) - table_size, then
        // increment next_state[sym].
        let mut next_state: Vec<u32> = vec![0; counts.len()];
        for (sym, &c) in counts.iter().enumerate() {
            if c == -1 {
                next_state[sym] = 1;
            } else if c > 0 {
                next_state[sym] = c as u32;
            }
        }
        for cell in cells.iter_mut() {
            let sym = cell.symbol as usize;
            // INVARIANT: sym's next_state is positive at this point
            // because every cell was assigned to a present symbol
            // by the placement step above.
            let ns = next_state[sym];
            let highest_bit = 32 - ns.leading_zeros() - 1;
            let nb: u32 = accuracy_log - highest_bit;
            let base = (ns << nb) - table_size;
            // INVARIANT: nb <= MAX_FSE_ACCURACY_LOG = 12 so it
            // fits in u8; base < (1 << accuracy_log) <= 4096 so
            // it fits in u16.
            cell.num_bits = nb as u8;
            cell.base_state = base as u16;
            next_state[sym] = ns.saturating_add(1);
        }

        Ok(Self {
            accuracy_log,
            cells,
        })
    }

    /// Build a table from one of the predefined LL/ML/OF
    /// distributions (used by `Predefined_Mode` sequence tables).
    pub fn from_predefined(counts: &[i16], accuracy_log: u32) -> Result<Self, ZstdError> {
        Self::build(counts, accuracy_log)
    }

    /// Build a single-cell table for `RLE_Mode` (RFC 8478 §3.1.1.4).
    ///
    /// `accuracy_log = 0`, `table_size = 1`. The lone cell holds
    /// `symbol` with `num_bits = 0` and `base_state = 0`, so every
    /// state read and transition yields the same symbol without
    /// consuming bits — the caller bounds the loop by the
    /// `Number_of_Sequences` field instead.
    #[must_use]
    pub fn rle(symbol: u8) -> Self {
        Self {
            accuracy_log: 0,
            cells: vec![FseCell {
                symbol,
                num_bits: 0,
                base_state: 0,
            }],
        }
    }

    /// Number of cells in the decode table (`1 << accuracy_log`).
    #[must_use]
    pub fn table_size(&self) -> u32 {
        // INVARIANT: accuracy_log <= MAX_FSE_ACCURACY_LOG (built
        // checks this), so 1 << accuracy_log fits in u32.
        1u32 << self.accuracy_log
    }

    /// `accuracy_log` of this table.
    #[must_use]
    pub fn accuracy_log(&self) -> u32 {
        self.accuracy_log
    }

    /// Read the cell at `state`. Used for the initial state read
    /// (when the decoder reads `accuracy_log` bits from the
    /// reverse bitstream and looks up the resulting state) and for
    /// each subsequent transition.
    ///
    /// # Errors
    ///
    /// - [`ZstdError::MalformedFrameHeader`] when `state` is out
    ///   of range.
    pub fn cell(&self, state: u32) -> Result<&FseCell, ZstdError> {
        self.cells
            .get(state as usize)
            .ok_or(ZstdError::MalformedFrameHeader(
                "FSE: state index out of range",
            ))
    }

    /// Initial state read: pulls `accuracy_log` bits from the
    /// reverse bitstream and returns the resulting cell. The
    /// caller uses [`FseCell::symbol`] for the first decoded
    /// symbol; subsequent symbols come from
    /// [`Self::transition`].
    ///
    /// # Errors
    ///
    /// - [`ZstdError::UnexpectedEof`] from the underlying reader.
    pub fn read_initial(&self, bits: &mut ReverseBitReader<'_>) -> Result<u32, ZstdError> {
        let s = bits.read(self.accuracy_log)?;
        // INVARIANT: state is always < table_size after a
        // legitimate read. Defensive bound check below.
        if s >= self.table_size() {
            return Err(ZstdError::MalformedFrameHeader(
                "FSE: initial state out of range",
            ));
        }
        Ok(s)
    }

    /// Advance the FSE state machine: given the *current* state's
    /// cell, read `num_bits` from the reverse bitstream, and
    /// return the next state (`base_state + bits_read`).
    ///
    /// # Errors
    ///
    /// - [`ZstdError::UnexpectedEof`] from the underlying reader.
    pub fn transition(
        &self,
        cell: &FseCell,
        bits: &mut ReverseBitReader<'_>,
    ) -> Result<u32, ZstdError> {
        let extra = bits.read(u32::from(cell.num_bits))?;
        let next = u32::from(cell.base_state) + extra;
        if next >= self.table_size() {
            return Err(ZstdError::MalformedFrameHeader(
                "FSE: transition produced out-of-range state",
            ));
        }
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Predefined-distribution sanity checks ------------------

    #[test]
    fn predefined_ll_sums_to_table_size() {
        let (counts, al) = PREDEFINED_LL;
        let mut sum: i32 = 0;
        for &c in counts.iter() {
            if c == -1 {
                sum += 1;
            } else if c > 0 {
                sum += c as i32;
            }
        }
        assert_eq!(sum, 1 << al);
    }

    #[test]
    fn predefined_ml_sums_to_table_size() {
        let (counts, al) = PREDEFINED_ML;
        let mut sum: i32 = 0;
        for &c in counts.iter() {
            if c == -1 {
                sum += 1;
            } else if c > 0 {
                sum += c as i32;
            }
        }
        assert_eq!(sum, 1 << al);
    }

    #[test]
    fn predefined_of_sums_to_table_size() {
        let (counts, al) = PREDEFINED_OF;
        let mut sum: i32 = 0;
        for &c in counts.iter() {
            if c == -1 {
                sum += 1;
            } else if c > 0 {
                sum += c as i32;
            }
        }
        assert_eq!(sum, 1 << al);
    }

    // ---- Table builder ------------------------------------------

    #[test]
    fn build_table_predefined_ll_has_table_size_cells() {
        let (counts, al) = PREDEFINED_LL;
        let t = FseTable::build(&counts, al).expect("build");
        assert_eq!(t.table_size(), 1 << al);
        assert_eq!(t.cells.len(), 64);
    }

    #[test]
    fn build_table_predefined_of_has_correct_layout() {
        let (counts, al) = PREDEFINED_OF;
        let t = FseTable::build(&counts, al).expect("build");
        assert_eq!(t.table_size(), 32);
        // -1 symbols (25..=28) live at the high end. They each
        // claim exactly one cell.
        let high_4_syms: Vec<u8> = (28..32).map(|s| t.cells[s].symbol).collect();
        // Order at the high end is the order they were placed —
        // from sym=25 (first -1) to sym=28 (last -1), with
        // high_threshold decrementing each time. So high_threshold
        // walked 31, 30, 29, 28; cells[31].symbol = 25, cells[30] = 26,
        // cells[29] = 27, cells[28] = 28.
        assert_eq!(high_4_syms, vec![28, 27, 26, 25]);
    }

    #[test]
    fn build_table_rejects_count_sum_mismatch() {
        // 4 symbols, AL=2 (table_size=4), counts sum to 5.
        let counts = [1i16, 1, 1, 2];
        let r = FseTable::build(&counts, 2);
        assert!(matches!(r, Err(ZstdError::MalformedFrameHeader(_))));
    }

    #[test]
    fn build_table_rejects_below_minus_one_count() {
        let counts = [1i16, -2, 3];
        let r = FseTable::build(&counts, 2);
        assert!(matches!(r, Err(ZstdError::MalformedFrameHeader(_))));
    }

    #[test]
    fn build_table_rejects_accuracy_log_above_cap() {
        let counts = vec![1i16; 8192];
        let r = FseTable::build(&counts, 13);
        assert!(matches!(r, Err(ZstdError::MalformedFrameHeader(_))));
    }

    /// Single-symbol table: AL=2, one symbol with count=4
    /// (RLE-style). Every cell points at the same symbol with
    /// `num_bits == 0`: there's no ambiguity in the symbol, so
    /// the state machine simply rotates through cells 0..=3 with
    /// no bits consumed per transition.
    #[test]
    fn build_single_symbol_table() {
        let counts = [4i16];
        let t = FseTable::build(&counts, 2).expect("build");
        for cell in &t.cells {
            assert_eq!(cell.symbol, 0);
            assert_eq!(cell.num_bits, 0);
        }
        // base_state cycles 0..=3 across the cells (in cell-index
        // order, since next_state walked 4, 5, 6, 7 -> shifted by
        // 0 bits each -> minus table_size 4).
        let bases: Vec<u16> = t.cells.iter().map(|c| c.base_state).collect();
        assert_eq!(bases, vec![0, 1, 2, 3]);
    }

    // ---- Distribution wire parser -------------------------------

    /// Hand-encode a small distribution to the wire format and
    /// parse it back.
    ///
    /// Distribution: AL=5 (table_size=32), counts = [16, 16] (so
    /// only symbols 0 and 1 are present, each with prob 16; 2..=N
    /// are absent). This is the smallest case where both a short
    /// and a long encoding are exercised.
    ///
    /// Symbol 0: remaining=33, bit_count=ceil(log2(34))=6,
    ///           max_value=63, L=63-33=30.
    ///   v=count+1=17. v < L so short code: write 17 in 5 bits.
    ///   17 = 0b10001. Bits in stream order (LSB-first): 1,0,0,0,1.
    /// remaining -= count = 16. remaining = 17.
    ///
    /// Symbol 1: remaining=17, bit_count=ceil(log2(18))=5,
    ///           max_value=31, L=31-17=14.
    ///   v=17. v >= L=14 so long code.
    ///     low_val = L + (v - L) / 2 = 14 + 3/2 = 14 + 1 = 15. extra = (v-L)%2 = 1.
    ///   Wait — let me recompute. We have v = 17. Long code:
    ///     decoder formula: v = 2*low_val - L + extra.
    ///     so low_val = (v + L - extra) / 2.
    ///     With L=14, v=17:
    ///       extra=1: low_val = (17+14-1)/2 = 15.   Verify: 2*15-14+1 = 17. ✓
    ///       extra=0: low_val = (17+14)/2 = 15.5 — not integer; invalid.
    ///   So encoder writes low_val=15 (4 bits), extra=1 (1 bit).
    ///   Bits in stream order LSB-first: low_val first as 4 bits,
    ///   then extra as 1 bit:
    ///     low_val=15 -> bits 1,1,1,1
    ///     extra=1    -> bit  1
    /// remaining -= 16. remaining = 1. Loop exits.
    ///
    /// Total bits in stream so far (after AL header):
    ///   Symbol 0 (5 bits): 1,0,0,0,1
    ///   Symbol 1 (5 bits): 1,1,1,1,1
    /// AL header (4 bits, AL=5 -> encoded value AL-5=0):
    ///   0,0,0,0
    ///
    /// Stream LSB-first: 0,0,0,0, 1,0,0,0,1, 1,1,1,1,1 = 14 bits.
    /// Pad to byte boundary: bits 14..15 = 0,0.
    /// Total 16 bits = 2 bytes.
    ///
    /// Bits packed LSB-first into bytes:
    ///   byte 0 (bits 0..7):  bit 0=0, 1=0, 2=0, 3=0, 4=1, 5=0, 6=0, 7=0
    ///                        -> 0b00010000 = 0x10
    ///   byte 1 (bits 8..15): bit 8=1, 9=1, 10=1, 11=1, 12=1, 13=1, 14=0, 15=0
    ///                        -> 0b00111111 = 0x3F
    #[test]
    fn parse_distribution_two_symbol_round_trip() {
        let bytes = [0x10, 0x3F];
        let mut reader = ForwardBitReader::new(&bytes);
        // max_symbol_value chosen so we pad sym=2,3,... with 0s.
        let parsed = parse_distribution(&mut reader, 12, 35).expect("parse");
        assert_eq!(parsed.accuracy_log, 5);
        // Counts vector length must include the padding to
        // max_symbol_value+1.
        assert_eq!(parsed.counts.len(), 36);
        assert_eq!(parsed.counts[0], 16);
        assert_eq!(parsed.counts[1], 16);
        for i in 2..36 {
            assert_eq!(parsed.counts[i], 0, "sym {i} should be 0");
        }
        // 14 data bits + 4 header bits = 18 bits before alignment;
        // wait that's wrong. Header is 4 bits, then 5+5 = 10 bits,
        // total 14 bits. Aligned up to 2 bytes.
        assert_eq!(parsed.bytes_consumed, 2);
    }

    #[test]
    fn parse_distribution_rejects_accuracy_log_above_cap() {
        // accuracy_log = 5 + 8 = 13 > MAX = 12. Encode AL=8 in
        // 4-bit header.
        let bytes = [0x08];
        let mut reader = ForwardBitReader::new(&bytes);
        let r = parse_distribution(&mut reader, 12, 35);
        assert!(matches!(r, Err(ZstdError::MalformedFrameHeader(_))));
    }

    /// Distribution parsing followed by table building, end-to-end
    /// against the predefined LL distribution. There's no wire
    /// fixture here — Predefined_Mode tables don't go through the
    /// distribution parser at all (they use the constants
    /// directly). But the table builder needs to handle each
    /// predefined distribution without error, and that's the part
    /// we lock down.
    #[test]
    fn build_each_predefined_distribution() {
        let (ll_counts, ll_al) = PREDEFINED_LL;
        let _ll = FseTable::build(&ll_counts, ll_al).expect("LL");
        let (ml_counts, ml_al) = PREDEFINED_ML;
        let _ml = FseTable::build(&ml_counts, ml_al).expect("ML");
        let (of_counts, of_al) = PREDEFINED_OF;
        let _of = FseTable::build(&of_counts, of_al).expect("OF");
    }

    // ---- State-machine round trip --------------------------------

    /// Exercise the [`FseTable::transition`] state machine by
    /// stepping through a single-symbol AL=2 table. Every cell
    /// points at sym=0 with num_bits=0 (no ambiguity -> no bits
    /// consumed per transition), so the next state is just
    /// `base_state` regardless of the bitstream.
    #[test]
    fn transition_in_single_symbol_table() {
        let counts = [4i16];
        let table = FseTable::build(&counts, 2).expect("build");
        // Reverse stream containing 2 bits (initial state read)
        // plus a sentinel. [0x80] places the sentinel at the MSB;
        // the 7 bits below it are zero data.
        let stream = [0x80u8];
        let mut br = ReverseBitReader::new(&stream).expect("ok");
        let initial = table.read_initial(&mut br).expect("initial");
        let cell = table.cell(initial).expect("cell");
        assert_eq!(cell.symbol, 0);
        assert_eq!(cell.num_bits, 0);
        let next = table.transition(cell, &mut br).expect("transition");
        // num_bits=0 means the transition reads zero bits and the
        // next state is exactly base_state.
        assert_eq!(next, u32::from(cell.base_state));
        assert!(next < table.table_size());
    }
}
