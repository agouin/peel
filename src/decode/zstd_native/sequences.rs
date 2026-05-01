//! Sequences-section decoder (RFC 8478 §3.1.1.4 + §4.2.2).
//!
//! Each `Compressed_Block` ends with a sequences section that
//! describes a run-length-encoded list of (literal_run, match_back-
//! reference) pairs. This module:
//!
//! 1. Parses the variable-size `Number_of_Sequences` (1–3 bytes)
//!    and the 1-byte `Symbol_Compression_Modes`.
//! 2. Resolves the three FSE tables — Literals_Length (LL),
//!    Offset (OF), Match_Length (ML) — per their declared mode
//!    (`Predefined`, `RLE`, `FSE_Compressed`, `Repeat`).
//! 3. Reads the reverse bitstream's three initial states (LL, OF,
//!    ML in that order) and decodes `Number_of_Sequences` triples.
//!    For each sequence the spec mandates the order: read OF
//!    extra bits, then ML extras, then LL extras; then update
//!    states LL, ML, OF (skip the update on the last sequence).
//!
//! Output is a [`Vec<Sequence>`] in stream order. The caller
//! (Phase 5 sequence-execution) walks this list against a sliding
//! window to materialize decompressed bytes; the `offset_value`
//! returned here is the *raw* `Offset_Value` from the spec, before
//! the repeat-offset translation in §3.1.1.5.

use super::bitstream::{ForwardBitReader, ReverseBitReader};
use super::error::ZstdError;
use super::fse::{
    parse_distribution, FseTable, MAX_LL_ACCURACY_LOG, MAX_LL_CODE, MAX_ML_ACCURACY_LOG,
    MAX_ML_CODE, MAX_OF_ACCURACY_LOG, MAX_OF_CODE, PREDEFINED_LL, PREDEFINED_ML, PREDEFINED_OF,
};

/// One decoded sequence command: a literal-run length, a match-
/// run length, and a raw `Offset_Value` (RFC 8478 §3.1.1.5).
///
/// The repeat-offset translation (`Offset_Value <= 3` → repeat-
/// slot lookup; `> 3` → literal `Offset_Value - 3`) lives in the
/// sequence-execution layer (Phase 5), so callers see the
/// pre-translation value here.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Sequence {
    /// Number of literal bytes to emit from the literals buffer
    /// before this sequence's back-reference.
    pub literals_length: u32,
    /// Length of the back-reference's match copy.
    pub match_length: u32,
    /// Raw `Offset_Value` per RFC 8478 §3.1.1.5; the
    /// repeat-offset translation is the executor's job.
    pub offset_value: u32,
}

/// Tables carried forward across blocks for `Repeat_Mode`
/// resolution.
///
/// Per RFC 8478 §3.1.1.4, a block whose
/// `Number_of_Sequences == 0` does not update these slots; any
/// other compressed block updates the slot for each table type
/// — even for `Predefined_Mode` and `RLE_Mode`, since
/// `Repeat_Mode` in a later block may reuse those tables.
#[derive(Debug, Clone, Default)]
pub struct PrevSequenceTables {
    /// Literals_Length table from the previous compressed block,
    /// or `None` if no compressed block has been seen yet.
    pub ll: Option<FseTable>,
    /// Offset table from the previous compressed block.
    pub of: Option<FseTable>,
    /// Match_Length table from the previous compressed block.
    pub ml: Option<FseTable>,
}

/// Per-table `Symbol_Compression_Mode` (RFC 8478 §3.1.1.4).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum CompressionMode {
    Predefined,
    Rle,
    FseCompressed,
    Repeat,
}

impl CompressionMode {
    fn from_two_bits(b: u8) -> Self {
        match b & 0b11 {
            0 => Self::Predefined,
            1 => Self::Rle,
            2 => Self::FseCompressed,
            3 => Self::Repeat,
            // INVARIANT: `b & 0b11` is in 0..=3.
            _ => unreachable!("two-bit field is 0..=3"),
        }
    }
}

/// Which of the three sequence-table types we're resolving;
/// drives per-table predefined distributions, accuracy-log caps,
/// and max-symbol caps.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TableKind {
    Ll,
    Of,
    Ml,
}

impl TableKind {
    fn predefined_table(self) -> Result<FseTable, ZstdError> {
        match self {
            Self::Ll => FseTable::from_predefined(&PREDEFINED_LL.0, PREDEFINED_LL.1),
            Self::Of => FseTable::from_predefined(&PREDEFINED_OF.0, PREDEFINED_OF.1),
            Self::Ml => FseTable::from_predefined(&PREDEFINED_ML.0, PREDEFINED_ML.1),
        }
    }

    fn max_accuracy_log(self) -> u32 {
        match self {
            Self::Ll => MAX_LL_ACCURACY_LOG,
            Self::Of => MAX_OF_ACCURACY_LOG,
            Self::Ml => MAX_ML_ACCURACY_LOG,
        }
    }

    fn max_symbol(self) -> u32 {
        match self {
            Self::Ll => MAX_LL_CODE,
            Self::Of => MAX_OF_CODE,
            Self::Ml => MAX_ML_CODE,
        }
    }
}

/// LL_Code → (Baseline, Number_of_Bits) lookup (RFC 8478 §3.1.1.4).
const LL_BASELINE: [u32; 36] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64,
    128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
];
const LL_EXTRA_BITS: [u32; 36] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16,
];

/// ML_Code → (Baseline, Number_of_Bits) lookup (RFC 8478 §3.1.1.4).
const ML_BASELINE: [u32; 53] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027,
    2051, 4099, 8195, 16387, 32771, 65539,
];
const ML_EXTRA_BITS: [u32; 53] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
];

/// Conservative cap on `OF_Code`. RFC 8478 lets implementations
/// pick their own ceiling; we cap at 31 because
/// `Offset_Value = (1 << OF_Code) + readNBits(OF_Code)` overflows
/// `u32` at `OF_Code == 32`. Phase-1 framework limits
/// `windowLog <= 27`, so the largest legitimate offset for our
/// frames is well below this cap.
const MAX_OF_CODE_BITS: u32 = 31;

/// Parse the sequences section and decode it into a list of
/// [`Sequence`]s.
///
/// `section` must be exactly the bytes of the sequences section
/// (the slice after the literals section ends, ending at the
/// block boundary). `prev` carries the FSE tables across blocks
/// for `Repeat_Mode` resolution.
///
/// On success returns the decoded sequences. As a side effect:
/// if `Number_of_Sequences > 0`, `prev` is updated so a later
/// block's `Repeat_Mode` reuses the tables this block resolved.
///
/// # Errors
///
/// - [`ZstdError::UnexpectedEof`] when `section` is shorter than
///   the structurally-required prefix.
/// - [`ZstdError::MalformedFrameHeader`] for any spec violation
///   (reserved bits non-zero, `Repeat_Mode` with no prior table,
///   RLE symbol out of range, bitstream not fully consumed, etc.).
pub fn decode_sequences(
    section: &[u8],
    prev: &mut PrevSequenceTables,
) -> Result<Vec<Sequence>, ZstdError> {
    if section.is_empty() {
        return Err(ZstdError::UnexpectedEof("sequences-section header"));
    }
    let mut cursor = 0usize;

    // Number_of_Sequences (1–3 bytes).
    let b0 = section[0];
    let (n_sequences, n_bytes): (u32, usize) = if b0 < 128 {
        (u32::from(b0), 1)
    } else if b0 < 255 {
        if section.len() < 2 {
            return Err(ZstdError::UnexpectedEof("Number_of_Sequences (2-byte)"));
        }
        let n = ((u32::from(b0) - 0x80) << 8) + u32::from(section[1]);
        (n, 2)
    } else {
        if section.len() < 3 {
            return Err(ZstdError::UnexpectedEof("Number_of_Sequences (3-byte)"));
        }
        let n = u32::from(section[1]) + (u32::from(section[2]) << 8) + 0x7F00;
        (n, 3)
    };
    cursor += n_bytes;

    if n_sequences == 0 {
        // Per spec: section ends here, prev tables not updated.
        if cursor != section.len() {
            return Err(ZstdError::MalformedFrameHeader(
                "sequences section: trailing bytes after Number_of_Sequences=0",
            ));
        }
        return Ok(Vec::new());
    }

    // Symbol_Compression_Modes byte.
    if cursor >= section.len() {
        return Err(ZstdError::UnexpectedEof("Symbol_Compression_Modes"));
    }
    let modes_byte = section[cursor];
    cursor += 1;
    if modes_byte & 0b11 != 0 {
        return Err(ZstdError::MalformedFrameHeader(
            "sequences modes: reserved bits 1-0 must be zero",
        ));
    }
    let ll_mode = CompressionMode::from_two_bits(modes_byte >> 6);
    let of_mode = CompressionMode::from_two_bits(modes_byte >> 4);
    let ml_mode = CompressionMode::from_two_bits(modes_byte >> 2);

    // Resolve LL, OF, ML tables in the spec-mandated order.
    let (ll_table, n) = resolve_table(ll_mode, &section[cursor..], &prev.ll, TableKind::Ll)?;
    cursor += n;
    let (of_table, n) = resolve_table(of_mode, &section[cursor..], &prev.of, TableKind::Of)?;
    cursor += n;
    let (ml_table, n) = resolve_table(ml_mode, &section[cursor..], &prev.ml, TableKind::Ml)?;
    cursor += n;

    // Sequence bitstream: the rest of the section.
    let stream = &section[cursor..];
    let sequences = decode_sequence_stream(stream, n_sequences, &ll_table, &of_table, &ml_table)?;

    // Update the carried tables so the next block's Repeat_Mode
    // can reuse them. The spec updates these even for Predefined
    // and RLE modes, not just FSE_Compressed.
    prev.ll = Some(ll_table);
    prev.of = Some(of_table);
    prev.ml = Some(ml_table);

    Ok(sequences)
}

/// Resolve a single FSE table per its declared mode.
///
/// Returns the resolved table and the number of bytes consumed
/// from `bytes`. Predefined and Repeat modes consume 0 bytes;
/// RLE consumes 1; FSE_Compressed consumes the FSE description's
/// length.
fn resolve_table(
    mode: CompressionMode,
    bytes: &[u8],
    prev: &Option<FseTable>,
    kind: TableKind,
) -> Result<(FseTable, usize), ZstdError> {
    match mode {
        CompressionMode::Predefined => Ok((kind.predefined_table()?, 0)),
        CompressionMode::Rle => {
            if bytes.is_empty() {
                return Err(ZstdError::UnexpectedEof("FSE RLE table symbol"));
            }
            let symbol = bytes[0];
            if u32::from(symbol) > kind.max_symbol() {
                return Err(ZstdError::MalformedFrameHeader(
                    "sequences RLE table: symbol exceeds per-table cap",
                ));
            }
            Ok((FseTable::rle(symbol), 1))
        }
        CompressionMode::FseCompressed => {
            let mut fwd = ForwardBitReader::new(bytes);
            let parsed = parse_distribution(&mut fwd, kind.max_accuracy_log(), kind.max_symbol())?;
            let table = FseTable::build(&parsed.counts, parsed.accuracy_log)?;
            Ok((table, parsed.bytes_consumed))
        }
        CompressionMode::Repeat => {
            let _ = kind; // future: include `kind` in the error label
            let table = prev
                .as_ref()
                .ok_or(ZstdError::MalformedFrameHeader(
                    "sequences Repeat_Mode without a prior block's table",
                ))?
                .clone();
            Ok((table, 0))
        }
    }
}

/// Decode the 3-state interleaved sequence bitstream.
///
/// Initial state read order: LL, OF, ML (RFC 8478 §4.2.2).
/// Per-iter bit consumption order: OF extras, ML extras,
/// LL extras. State update order on non-final iterations:
/// LL, ML, OF.
fn decode_sequence_stream(
    stream: &[u8],
    n_sequences: u32,
    ll_table: &FseTable,
    of_table: &FseTable,
    ml_table: &FseTable,
) -> Result<Vec<Sequence>, ZstdError> {
    let mut br = ReverseBitReader::new(stream)?;

    let mut ll_state = ll_table.read_initial(&mut br)?;
    let mut of_state = of_table.read_initial(&mut br)?;
    let mut ml_state = ml_table.read_initial(&mut br)?;

    let mut out: Vec<Sequence> = Vec::with_capacity(n_sequences as usize);

    for i in 0..n_sequences {
        let ll_cell = *ll_table.cell(ll_state)?;
        let of_cell = *of_table.cell(of_state)?;
        let ml_cell = *ml_table.cell(ml_state)?;

        if u32::from(ll_cell.symbol) > MAX_LL_CODE {
            return Err(ZstdError::MalformedFrameHeader(
                "sequences: literals_length code out of range",
            ));
        }
        if u32::from(ml_cell.symbol) > MAX_ML_CODE {
            return Err(ZstdError::MalformedFrameHeader(
                "sequences: match_length code out of range",
            ));
        }
        if u32::from(of_cell.symbol) > MAX_OF_CODE_BITS {
            return Err(ZstdError::MalformedFrameHeader(
                "sequences: offset code > 31 (would overflow u32)",
            ));
        }

        // Read extra bits in spec order: offset, then match
        // length, then literals length. Use `read_padded` so the
        // very last sequence's extras can pull zero-padded LSBs
        // when the encoder under-wrote them — libzstd's
        // `BIT_DStream_overflow` semantics, see [`ReverseBitReader::read_padded`].
        let of_bits = u32::from(of_cell.symbol);
        let of_low = br.read_padded(of_bits)?;
        // INVARIANT: of_bits <= 31 (checked above), so 1 << of_bits
        // fits in u32 and the addition cannot overflow.
        let offset_value = (1u32 << of_bits) + of_low;

        let ml_extra = ML_EXTRA_BITS[ml_cell.symbol as usize];
        let ml_low = br.read_padded(ml_extra)?;
        let match_length = ML_BASELINE[ml_cell.symbol as usize] + ml_low;

        let ll_extra = LL_EXTRA_BITS[ll_cell.symbol as usize];
        let ll_low = br.read_padded(ll_extra)?;
        let literals_length = LL_BASELINE[ll_cell.symbol as usize] + ll_low;

        out.push(Sequence {
            literals_length,
            match_length,
            offset_value,
        });

        // State updates only on non-final iterations: LL, ML, OF.
        // Transitions also use the lenient reader so a
        // legitimately-short tail doesn't surface as EOF.
        if i + 1 < n_sequences {
            ll_state = transition_padded(ll_table, &ll_cell, &mut br)?;
            ml_state = transition_padded(ml_table, &ml_cell, &mut br)?;
            of_state = transition_padded(of_table, &of_cell, &mut br)?;
        }
    }

    // Spec: "the bitstream shall be entirely consumed". libzstd's
    // `BIT_DStream_completed` accepts both exact consumption and
    // zero-padded over-read — what's *not* allowed is leftover
    // unconsumed data bits.
    if br.has_leftover() {
        return Err(ZstdError::MalformedFrameHeader(
            "sequences: bitstream has leftover bits",
        ));
    }

    Ok(out)
}

/// State transition that uses the lenient (zero-padded) bit
/// reader. The result is still bound-checked against the table's
/// `table_size` so a runaway state can't index out of bounds.
fn transition_padded(
    table: &FseTable,
    cell: &super::fse::FseCell,
    bits: &mut ReverseBitReader<'_>,
) -> Result<u32, ZstdError> {
    let extra = bits.read_padded(u32::from(cell.num_bits))?;
    let next = u32::from(cell.base_state) + extra;
    if next >= table.table_size() {
        return Err(ZstdError::MalformedFrameHeader(
            "FSE: transition produced out-of-range state",
        ));
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Number_of_Sequences encoding -------------------------

    #[test]
    fn n_sequences_one_byte() {
        // byte0 = 50 < 128 -> n = 50, 1 byte.
        // Followed by an empty section is malformed (we expect
        // modes byte for n > 0), so check via UnexpectedEof.
        let mut prev = PrevSequenceTables::default();
        match decode_sequences(&[50], &mut prev) {
            Err(ZstdError::UnexpectedEof(_)) => {}
            other => panic!("expected UnexpectedEof for missing modes, got {other:?}"),
        }
    }

    #[test]
    fn n_sequences_zero_returns_empty() {
        let mut prev = PrevSequenceTables::default();
        let seqs = decode_sequences(&[0], &mut prev).expect("decode");
        assert!(seqs.is_empty());
        assert!(prev.ll.is_none(), "prev not updated on zero sequences");
    }

    #[test]
    fn n_sequences_zero_with_trailing_bytes_errors() {
        // Spec: 0-sequence section ends at the count byte; any
        // trailing bytes are malformed.
        let mut prev = PrevSequenceTables::default();
        match decode_sequences(&[0, 0xAB], &mut prev) {
            Err(ZstdError::MalformedFrameHeader(_)) => {}
            other => panic!("expected malformed, got {other:?}"),
        }
    }

    #[test]
    fn n_sequences_two_byte_form_decodes() {
        // byte0 = 0x80 (means 2-byte form), byte1 = 0xFF.
        // n = ((0x80 - 0x80) << 8) + 0xFF = 0xFF = 255.
        // Then we'd need a modes byte etc; we just verify the
        // count parsed without panicking by feeding only the
        // count and expecting an EOF on the modes byte.
        let mut prev = PrevSequenceTables::default();
        match decode_sequences(&[0x80, 0xFF], &mut prev) {
            Err(ZstdError::UnexpectedEof(msg)) => {
                assert!(msg.contains("Symbol_Compression_Modes"), "msg: {msg}");
            }
            other => panic!("expected UnexpectedEof on modes, got {other:?}"),
        }
    }

    #[test]
    fn n_sequences_three_byte_form_decodes() {
        // byte0 = 0xFF (3-byte form), byte1 = 0x00, byte2 = 0x80.
        // n = 0x00 + (0x80 << 8) + 0x7F00 = 0x8000 + 0x7F00 = 0xFF00.
        let mut prev = PrevSequenceTables::default();
        match decode_sequences(&[0xFF, 0x00, 0x80], &mut prev) {
            Err(ZstdError::UnexpectedEof(msg)) => {
                assert!(msg.contains("Symbol_Compression_Modes"), "msg: {msg}");
            }
            other => panic!("expected UnexpectedEof on modes, got {other:?}"),
        }
    }

    // ---- Mode-byte validation ---------------------------------

    #[test]
    fn modes_byte_reserved_bits_rejected() {
        // n_sequences = 1, modes byte with reserved bits (1-0) set.
        let modes = 0b00_00_00_01u8; // reserved low bits non-zero
        let mut prev = PrevSequenceTables::default();
        match decode_sequences(&[1, modes], &mut prev) {
            Err(ZstdError::MalformedFrameHeader(msg)) => {
                assert!(msg.contains("reserved"), "msg: {msg}");
            }
            other => panic!("expected malformed, got {other:?}"),
        }
    }

    #[test]
    fn repeat_mode_without_prior_table_errors() {
        // Modes: LL=Repeat (0b11), OF=Predefined, ML=Predefined.
        // Without a prior table, Repeat_Mode is malformed.
        let modes = 0b11_00_00_00u8;
        let mut prev = PrevSequenceTables::default();
        match decode_sequences(&[1, modes], &mut prev) {
            Err(ZstdError::MalformedFrameHeader(msg)) => {
                assert!(msg.contains("Repeat_Mode"), "msg: {msg}");
            }
            other => panic!("expected malformed, got {other:?}"),
        }
    }

    #[test]
    fn rle_offset_symbol_above_cap_rejected() {
        // Modes: LL=RLE, OF=RLE, ML=RLE.
        // OF RLE byte = 32 > MAX_OF_CODE (31) — out of range.
        let modes = 0b01_01_01_00u8;
        let mut prev = PrevSequenceTables::default();
        // n_sequences=1, modes, LL_RLE_byte=0, OF_RLE_byte=32 (bad), ML_RLE_byte=0.
        match decode_sequences(&[1, modes, 0, 32, 0], &mut prev) {
            Err(ZstdError::MalformedFrameHeader(msg)) => {
                assert!(msg.contains("RLE"), "msg: {msg}");
            }
            other => panic!("expected malformed, got {other:?}"),
        }
    }

    // ---- End-to-end with all-RLE tables -----------------------

    /// Hand-build the smallest possible sequences section with a
    /// single sequence, all three tables in `RLE_Mode`. Verifies
    /// the spec-mandated bit-consumption order (OF, ML, LL).
    #[test]
    fn single_sequence_rle_round_trip() {
        // Modes: LL=RLE, OF=RLE, ML=RLE.
        let modes = 0b01_01_01_00u8;
        // RLE bytes: LL=0 (ll_code 0 -> ll = 0, no extras),
        //            OF=2 (of_code 2 -> 2 extra bits),
        //            ML=0 (ml_code 0 -> ml = 3, no extras).
        let ll_rle = 0u8;
        let of_rle = 2u8;
        let ml_rle = 0u8;
        // Reverse bitstream: 1 sequence consumes only the OF
        // extras (2 bits). Init reads are 0 bits each (RLE
        // accuracy_log = 0). For OF extras = 0b11 (3),
        // Offset_Value = (1<<2) + 3 = 7.
        //
        // The spec requires the bitstream to be fully consumed,
        // so we pack pad+sentinel+data tight into the byte (5
        // leading zeros + 1 sentinel + 2 data bits = 8 bits):
        //   bits 7..3: 0 (5-bit zero pad)
        //   bit 2    : 1 (sentinel)
        //   bit 1    : 1 (OF extra MSB)
        //   bit 0    : 1 (OF extra LSB)
        // = 0b0000_0111 = 0x07.
        let stream = 0x07u8;

        let section = [1u8, modes, ll_rle, of_rle, ml_rle, stream];
        let mut prev = PrevSequenceTables::default();
        let seqs = decode_sequences(&section, &mut prev).expect("decode");
        assert_eq!(seqs.len(), 1);
        assert_eq!(
            seqs[0],
            Sequence {
                literals_length: 0,
                match_length: 3,
                offset_value: 7,
            }
        );
        // After a non-zero block, prev is updated.
        assert!(prev.ll.is_some());
        assert!(prev.of.is_some());
        assert!(prev.ml.is_some());
    }

    /// Two-block scenario: a first all-RLE block establishes the
    /// tables, a second block declares `Repeat_Mode` for all
    /// three and reuses them. Locks the carried-tables contract.
    #[test]
    fn repeat_mode_reuses_prior_tables() {
        // Block 1: same as `single_sequence_rle_round_trip`.
        let modes_rle = 0b01_01_01_00u8;
        let block1 = [1u8, modes_rle, 0, 2, 0, 0x07];
        let mut prev = PrevSequenceTables::default();
        let s1 = decode_sequences(&block1, &mut prev).expect("block 1");
        assert_eq!(s1.len(), 1);

        // Block 2: 1 sequence, all three modes = Repeat (0b11),
        // reusing the RLE tables. No FSE descriptions on the
        // wire — only the count, modes, and the bitstream byte.
        let modes_repeat = 0b11_11_11_00u8;
        let block2 = [1u8, modes_repeat, 0x07];
        let s2 = decode_sequences(&block2, &mut prev).expect("block 2");
        assert_eq!(s2, s1, "repeat-mode block should decode identically");
    }

    // ---- Differential against libzstd-encoded frames ----------

    /// Walk a libzstd-produced frame, run the sequences decoder
    /// on every Compressed_Block's sequences section, and assert:
    /// (a) decode succeeds, (b) the bitstream is fully consumed,
    /// (c) per-sequence values respect their per-code caps.
    ///
    /// This is the Phase 4c exit-criteria differential. It does
    /// not yet cross-check the *values* of decoded sequences
    /// against libzstd's (that requires sequence execution, which
    /// is Phase 5), but it locks the parser against malformed-
    /// decode regressions on real frames.
    #[test]
    fn sequences_decode_against_libzstd_text_frames() {
        use super::super::block::{parse_block_header, BlockType, BLOCK_HEADER_LEN};
        use super::super::frame::parse_frame_header;
        use super::super::literals::{decode_literals, parse_literals_header};

        let payload: Vec<u8> = b"the quick brown fox jumps over the lazy dog. \
            pack my box with five dozen liquor jugs. how vexingly quick \
            daft zebras jump! sphinx of black quartz, judge my vow. "
            .repeat(200);
        let compressed = ::zstd::encode_all(&payload[..], 3).expect("encode");
        let fh = parse_frame_header(&compressed).expect("frame header");
        let mut p = fh.header_size;
        let mut prev_huffman = None;
        let mut prev_seq = PrevSequenceTables::default();
        let mut blocks_seen = 0usize;
        loop {
            let bh = parse_block_header(&compressed[p..]).expect("block header");
            p += BLOCK_HEADER_LEN;
            if let BlockType::Compressed = bh.block_type {
                let block_payload = &compressed[p..p + bh.block_size as usize];
                let lh = parse_literals_header(block_payload).expect("literals header");
                let lit_end = usize::from(lh.header_size) + lh.payload_size as usize;
                let lit_payload = &block_payload[usize::from(lh.header_size)..lit_end];
                let _literals =
                    decode_literals(&lh, lit_payload, &mut prev_huffman).expect("literals");
                let seq_section = &block_payload[lit_end..];
                let seqs = decode_sequences(seq_section, &mut prev_seq).expect("sequences");
                for s in &seqs {
                    assert!(s.literals_length <= 131_072, "ll out of range: {s:?}");
                    assert!(s.match_length <= 131_074, "ml out of range: {s:?}");
                    assert!(s.offset_value > 0, "offset_value must be >= 1: {s:?}");
                }
                blocks_seen += 1;
            }
            p += bh.payload_on_wire() as usize;
            if bh.last_block {
                break;
            }
        }
        assert!(blocks_seen >= 1, "no compressed blocks observed");
    }

    /// Same shape as the text test, but with the wide-alphabet
    /// fixture from the literals validation. Stresses the
    /// sequences decoder against blocks where the encoder picks
    /// `FSE_Compressed_Mode` for one or more of LL/OF/ML.
    #[test]
    fn sequences_decode_against_libzstd_wide_alphabet_frames() {
        use super::super::block::{parse_block_header, BlockType, BLOCK_HEADER_LEN};
        use super::super::frame::parse_frame_header;
        use super::super::literals::{decode_literals, parse_literals_header};

        // Same generator as `decode::zstd_native::tests::wide_alphabet_compressible_payload`.
        let mut payload = Vec::with_capacity(32 * 1024);
        for i in 0..32 * 1024 {
            let block = i / 17;
            let byte = match i % 17 {
                0 => b'<',
                1 => b'r',
                2 => b'>',
                _ => ((block + i) % 256) as u8,
            };
            payload.push(byte);
        }
        let compressed = ::zstd::encode_all(&payload[..], 3).expect("encode");
        let fh = parse_frame_header(&compressed).expect("frame header");
        let mut p = fh.header_size;
        let mut prev_huffman = None;
        let mut prev_seq = PrevSequenceTables::default();
        let mut blocks_seen = 0usize;
        loop {
            let bh = parse_block_header(&compressed[p..]).expect("block header");
            p += BLOCK_HEADER_LEN;
            if let BlockType::Compressed = bh.block_type {
                let block_payload = &compressed[p..p + bh.block_size as usize];
                let lh = parse_literals_header(block_payload).expect("literals header");
                let lit_end = usize::from(lh.header_size) + lh.payload_size as usize;
                let lit_payload = &block_payload[usize::from(lh.header_size)..lit_end];
                let _literals =
                    decode_literals(&lh, lit_payload, &mut prev_huffman).expect("literals");
                let seq_section = &block_payload[lit_end..];
                let _seqs = decode_sequences(seq_section, &mut prev_seq).expect("sequences");
                blocks_seen += 1;
            }
            p += bh.payload_on_wire() as usize;
            if bh.last_block {
                break;
            }
        }
        assert!(blocks_seen >= 1, "no compressed blocks observed");
    }
}
