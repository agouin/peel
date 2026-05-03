//! Dynamic-Huffman block preamble parser (RFC 1951 §3.2.7).
//!
//! Dynamic-Huffman blocks (BTYPE=10) carry a per-block declaration of
//! the lit/length and distance Huffman alphabets, encoded as a
//! three-stage preamble:
//!
//! 1. **HLIT / HDIST / HCLEN counts.** 5 + 5 + 4 bits, declaring the
//!    number of lit/length codes (`HLIT + 257`, range 257..=286), the
//!    number of distance codes (`HDIST + 1`, range 1..=30), and the
//!    number of code-length-code lengths the encoder will declare
//!    (`HCLEN + 4`, range 4..=19).
//! 2. **Code-length-code (CL) lengths.** `HCLEN + 4` 3-bit lengths in
//!    the permuted spec order
//!    `[16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]`.
//!    The CL alphabet has 19 symbols (0..=18) — symbols 0..=15 are
//!    direct code-length values, 16 / 17 / 18 are RLE shorthands.
//! 3. **Lit/length + distance code-length sequence.** A flat array of
//!    `HLIT + HDIST + 258` code lengths (i.e. one length per symbol
//!    in the lit/length and distance alphabets, concatenated). Each
//!    entry is decoded via the CL Huffman from stage 2; RLE codes
//!    16 / 17 / 18 expand to multi-entry runs per the spec.
//!
//! [`parse_preamble`] consumes all three stages off the bit reader
//! and returns the constructed lit/length and distance Huffman
//! tables. The distance table is `Option<HuffTable>` because RFC
//! 1951 §3.2.7 special-cases an all-literals block (HDIST=1 with
//! the single distance code's length 0) — the inner block-decode
//! treats `dist = None` as "no back-references permitted" and
//! surfaces a typed error if a length symbol is decoded.
//!
//! # Spec gotchas
//!
//! - **CL alphabet permutation.** The 19 CL lengths are not stored
//!   in alphabet order; they're stored in a fixed permutation that
//!   front-loads the high-frequency CL symbols. A reader that uses
//!   `0..hclen` directly is silently wrong.
//! - **RLE code 16 needs a previous length.** Code 16 means "repeat
//!   the previous code length". If it's the first entry in the
//!   sequence, there is no previous length — a malformed input.
//! - **RLE codes can cross the lit/length / distance boundary.** RFC
//!   1951 §3.2.7 explicitly allows this: a single RLE run can span
//!   the implicit boundary at index `HLIT + 257`. The implementation
//!   uses a flat `Vec<u8>` of length `HLIT + HDIST + 258` and slices
//!   it into the two alphabets after decoding.
//! - **EOB code (lit/length 256) must have a non-zero length.** A
//!   block with no decodable EOB symbol can never end — surface as
//!   malformed at preamble-build time rather than letting the inner
//!   loop spin until the source runs out.

use super::bitstream::BitReader;
use super::error::DeflateError;
use super::huffman::{HuffTable, MAX_CODE_BITS};

/// Permuted order RFC 1951 §3.2.7 declares the code-length-code
/// lengths in. `CLEN_ORDER[i]` is the CL alphabet index whose
/// length is read at preamble position `i`.
const CLEN_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Maximum code length the CL alphabet may declare (RFC 1951
/// §3.2.7: each CL length is a 3-bit field, so ≤ 7 by encoding;
/// we still validate against [`MAX_CODE_BITS`] for symmetry with
/// the lit/length and distance code-length validation).
const CL_MAX_BITS: u32 = 7;

/// Index of the EOB symbol in the lit/length alphabet
/// (RFC 1951 §3.2.5).
const EOB_SYMBOL: usize = 256;

/// Parse a dynamic-Huffman block's preamble off `br` and return
/// the constructed `(lit/length, distance)` Huffman tables.
///
/// Returns `(lit_table, None)` for the RFC 1951 §3.2.7 special case
/// of "no distance codes used" (HDIST=1 with the single distance
/// code's length 0); the inner block-decode treats this as
/// "literals-only" and rejects any back-reference symbol.
///
/// # Errors
///
/// - [`DeflateError::UnexpectedEof`] if the source runs out before
///   the preamble is fully consumed.
/// - [`DeflateError::MalformedHuffman`] for any spec violation:
///   HLIT > 286, HDIST > 30, an over-subscribed Huffman tree, an
///   RLE code 16 with no previous code length, an RLE run that
///   overshoots the length sequence, an unrecognized CL symbol, or
///   a lit/length alphabet that doesn't include the EOB code.
/// - [`DeflateError::SourceIo`] for any underlying source IO
///   failure.
pub fn parse_preamble(br: &mut BitReader) -> Result<(HuffTable, Option<HuffTable>), DeflateError> {
    // Stage 1: HLIT / HDIST / HCLEN counts.
    let hlit_field = br.read_bits(5)?;
    let hdist_field = br.read_bits(5)?;
    let hclen_field = br.read_bits(4)?;

    // INVARIANT: 5-bit reads return 0..=31 / 4-bit returns 0..=15,
    // so the additions below cannot overflow u32.
    let hlit = hlit_field as usize + 257;
    let hdist = hdist_field as usize + 1;
    let hclen = hclen_field as usize + 4;

    if hlit > 286 {
        return Err(DeflateError::MalformedHuffman(
            "HLIT declares lit/length alphabet > 286 symbols",
        ));
    }
    if hdist > 30 {
        return Err(DeflateError::MalformedHuffman(
            "HDIST declares distance alphabet > 30 symbols",
        ));
    }
    // HCLEN has a hard ceiling of 19 by construction (4-bit field +
    // 4 = max 19), so no upper-bound check needed; left as a
    // defensive assert in case the field width ever changes.
    debug_assert!(hclen <= 19);

    // Stage 2: read CL alphabet code lengths in the permuted order.
    let mut clen_lens = [0u8; 19];
    for &slot in &CLEN_ORDER[..hclen] {
        let len = br.read_bits(3)? as u8;
        if u32::from(len) > CL_MAX_BITS {
            // A 3-bit field returns 0..=7, and CL_MAX_BITS=7, so this
            // is unreachable; left as a defensive check so a future
            // refactor can't silently pass an over-long CL length.
            return Err(DeflateError::MalformedHuffman(
                "CL code length exceeds 7 bits",
            ));
        }
        clen_lens[slot] = len;
    }
    let clen_table = HuffTable::build(&clen_lens)?;

    // Stage 3: decode the flat lit/length + distance code-length
    // sequence. RLE codes can cross the HLIT-vs-HDIST boundary, so
    // the decode walks a single flat array.
    let total = hlit + hdist;
    let mut lengths = vec![0u8; total];
    let mut i = 0;
    while i < total {
        let sym = clen_table.decode(br)?;
        match sym {
            0..=15 => {
                // Direct length value.
                if u32::from(sym) > MAX_CODE_BITS {
                    // CL symbols 0..=15 map to lengths 0..=15, all
                    // within MAX_CODE_BITS. Defensive guard.
                    return Err(DeflateError::MalformedHuffman(
                        "decoded code length exceeds 15",
                    ));
                }
                // INVARIANT: sym <= 15 fits in u8.
                lengths[i] = sym as u8;
                i += 1;
            }
            16 => {
                // Repeat the previous code length 3 + 2-bit-extra
                // times.
                if i == 0 {
                    return Err(DeflateError::MalformedHuffman(
                        "RLE code 16 at start of length sequence",
                    ));
                }
                let prev = lengths[i - 1];
                let repeat = br.read_bits(2)? as usize + 3;
                if i + repeat > total {
                    return Err(DeflateError::MalformedHuffman(
                        "RLE code 16 run overshoots length sequence",
                    ));
                }
                for _ in 0..repeat {
                    lengths[i] = prev;
                    i += 1;
                }
            }
            17 => {
                // 3-bit-extra zero run, range 3..=10.
                let repeat = br.read_bits(3)? as usize + 3;
                if i + repeat > total {
                    return Err(DeflateError::MalformedHuffman(
                        "RLE code 17 run overshoots length sequence",
                    ));
                }
                for _ in 0..repeat {
                    lengths[i] = 0;
                    i += 1;
                }
            }
            18 => {
                // 7-bit-extra zero run, range 11..=138.
                let repeat = br.read_bits(7)? as usize + 11;
                if i + repeat > total {
                    return Err(DeflateError::MalformedHuffman(
                        "RLE code 18 run overshoots length sequence",
                    ));
                }
                for _ in 0..repeat {
                    lengths[i] = 0;
                    i += 1;
                }
            }
            other => {
                // Unreachable: the CL alphabet only declares
                // symbols 0..=18. A value past 18 means
                // [`HuffTable::decode`] returned a symbol from a
                // table that shouldn't have it — defensive guard.
                let _ = other;
                return Err(DeflateError::MalformedHuffman(
                    "code-length-code symbol > 18",
                ));
            }
        }
    }
    debug_assert_eq!(i, total);

    // Build the lit/length table. EOB (symbol 256) MUST have a
    // non-zero length — otherwise the block can never end.
    let lit_lens = &lengths[..hlit];
    if lit_lens[EOB_SYMBOL] == 0 {
        return Err(DeflateError::MalformedHuffman(
            "lit/length alphabet is missing the EOB code",
        ));
    }
    let lit_table = HuffTable::build(lit_lens)?;

    // Build the distance table or short-circuit to None when the
    // alphabet is "empty" (RFC 1951 §3.2.7 literals-only special
    // case: HDIST=1 with the single code's length 0).
    let dist_lens = &lengths[hlit..];
    let dist_table = if dist_lens.iter().all(|&l| l == 0) {
        None
    } else {
        Some(HuffTable::build(dist_lens)?)
    };

    Ok((lit_table, dist_table))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    /// Bit-level encoder mirroring the test helper used in
    /// `super::tests` (kept local to this module so dynamic-preamble
    /// tests can build fixtures without exporting the writer).
    struct BitWriter {
        bytes: Vec<u8>,
        acc: u64,
        nbits: u32,
    }

    impl BitWriter {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                acc: 0,
                nbits: 0,
            }
        }

        fn write_bits(&mut self, value: u32, n: u32) {
            self.acc |= u64::from(value) << self.nbits;
            self.nbits += n;
            while self.nbits >= 8 {
                self.bytes.push(self.acc as u8);
                self.acc >>= 8;
                self.nbits -= 8;
            }
        }

        fn finish(mut self) -> Vec<u8> {
            if self.nbits > 0 {
                self.bytes.push(self.acc as u8);
            }
            self.bytes
        }
    }

    fn br(bytes: Vec<u8>) -> BitReader {
        BitReader::new(Box::new(Cursor::new(bytes)))
    }

    /// Reverse the low `n` bits of `v`. Used to emit canonical
    /// Huffman codes (which the encoder writes MSB-first) into the
    /// LSB-first stream the bit reader consumes.
    fn rev(mut v: u32, n: u32) -> u32 {
        let mut r = 0u32;
        for _ in 0..n {
            r = (r << 1) | (v & 1);
            v >>= 1;
        }
        r
    }

    /// Build a minimal dynamic-Huffman preamble that declares:
    /// - HLIT = 257 (alphabet covers symbols 0..=256, only EOB used)
    /// - HDIST = 1 with length 0 (no distance codes)
    /// - HCLEN = 18 (the maximum needed to encode our chosen CL
    ///   lengths in the permuted order without surfacing trailing
    ///   zeros at unused permutation slots — keeps the fixture
    ///   easy to reason about)
    /// - CL alphabet: clen[0]=1 (single CL code with 1-bit
    ///   canonical), clen[18]=1 (single CL code with 1-bit
    ///   canonical) — i.e. two symbols at length 1, one at length 0
    ///   (Kraft equality: 2 × 2^-1 = 1).
    /// - Lit/length lengths via RLE 18 (long zero run for symbols
    ///   0..=255), then symbol 256 (EOB) at length 1, then
    ///   distance length 0.
    ///
    /// Result: a parseable preamble whose lit table contains only
    /// EOB. The block body is just the EOB symbol, so a properly
    /// decoded block emits zero bytes.
    fn encode_minimal_preamble_eob_only_block() -> Vec<u8> {
        let mut w = BitWriter::new();
        // BFINAL=1, BTYPE=10.
        w.write_bits(1, 1);
        w.write_bits(0b10, 2);

        // HLIT=0 (257 lit/length codes).
        w.write_bits(0, 5);
        // HDIST=0 (1 distance code).
        w.write_bits(0, 5);
        // HCLEN=15 (19 CL lengths declared, the maximum, so all
        // permutation slots are explicit).
        w.write_bits(15, 4);

        // CL lengths in permuted order: CLEN_ORDER =
        //   [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2,
        //    14, 1, 15]
        // We want clen[0] = 1, clen[18] = 1, all others = 0.
        // Position-by-position:
        //   pos 0  -> CL16 (we need 0)
        //   pos 1  -> CL17 (0)
        //   pos 2  -> CL18 (1)
        //   pos 3  -> CL0  (1)
        //   pos 4  -> CL8  (0)
        //   pos 5  -> CL7  (0)
        //   ... rest 0
        let cl_at_pos = [0u32, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for &len in &cl_at_pos {
            w.write_bits(len, 3);
        }
        // Now CL alphabet has symbols { 0: len 1, 18: len 1 }. Both
        // 1-bit, canonical assignments (next_code start):
        //   length 1: codes 0 and 1 in canonical order → sym 0 = 0,
        //   sym 18 = 1.
        // Reversed (1-bit values are self-reversed): sym 0 = stream
        // bit 0; sym 18 = stream bit 1.

        // Lit/length + distance lengths via the CL alphabet:
        //   - Symbols 0..=255 (256 entries): all length 0, encoded
        //     via RLE 18 runs (max 138 per run).
        //     138 + 118 = 256 entries via two RLE 18 runs.
        //     RLE 18 takes 7 extra bits: value+11 = run length.
        //     Run 1: 138 entries → extra = 138 - 11 = 127.
        //     Run 2: 118 entries → extra = 118 - 11 = 107.
        //   - Symbol 256 (EOB): length 1, encoded as direct CL
        //     symbol 1... wait, symbol 1 in CL alphabet means "code
        //     length 1" in the lit/length context. But we declared
        //     clen[1]=0 (CL symbol 1 not present in the alphabet).
        //     So we can't directly encode lit/length code length 1.

        // Hmm, this won't work. We need a CL symbol that decodes to
        // length 1. Let me redesign: keep clen[1]=1 (CL symbol 1
        // assigns lit/length code length 1).
        //
        // But this would mean the CL alphabet has 3+ symbols at
        // various lengths, and we'd have to handle the more general
        // canonical-code construction. Simpler:
        //   clen[0]=1 (symbol 0 used to assign length 0)
        //   clen[1]=2 (symbol 1 used to assign length 1)
        //   clen[18]=2 (symbol 18 used for long zero runs)
        // Three symbols at lengths 1, 2, 2 — Kraft: 2^-1 + 2^-2 +
        // 2^-2 = 1 ✓.
        // Canonical: length 1 first → sym 0 = 0 (1 bit). Length 2
        // codes start at (0+1)<<1 = 2. sym 1 = 2 (2 bits, binary
        // 10). sym 18 = 3 (2 bits, binary 11). Reversed:
        //   sym 0 → 0 (1 bit)
        //   sym 1 → rev(2, 2) = 0b01 (2 bits)
        //   sym 18 → rev(3, 2) = 0b11 (2 bits)
        let _unused = w; // discard the wrong-direction CL declaration
        let mut w = BitWriter::new();
        // BFINAL=1, BTYPE=10.
        w.write_bits(1, 1);
        w.write_bits(0b10, 2);

        // HLIT=0 (257 lit/length codes).
        w.write_bits(0, 5);
        // HDIST=0 (1 distance code).
        w.write_bits(0, 5);
        // HCLEN=15 (19 CL lengths declared).
        w.write_bits(15, 4);

        // CLEN_ORDER permutation positions:
        //   pos 0 -> CL16 (length 0)
        //   pos 1 -> CL17 (length 0)
        //   pos 2 -> CL18 (length 2)
        //   pos 3 -> CL0  (length 1)
        //   pos 4 -> CL8  (0)
        //   pos 5 -> CL7  (0)
        //   pos 6 -> CL9  (0)
        //   pos 7 -> CL6  (0)
        //   pos 8 -> CL10 (0)
        //   pos 9 -> CL5  (0)
        //   pos 10 -> CL11 (0)
        //   pos 11 -> CL4  (0)
        //   pos 12 -> CL12 (0)
        //   pos 13 -> CL3  (0)
        //   pos 14 -> CL13 (0)
        //   pos 15 -> CL2  (0)
        //   pos 16 -> CL14 (0)
        //   pos 17 -> CL1  (length 2)
        //   pos 18 -> CL15 (0)
        // i.e. clen[16]=0, clen[17]=0, clen[18]=2, clen[0]=1,
        //      everything else 0 except clen[1]=2.
        let cl_at_pos = [0u32, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0];
        for &len in &cl_at_pos {
            w.write_bits(len, 3);
        }
        // CL canonical:
        //   sym 0 (length 1): code 0 (1 bit), reversed 0
        //   sym 1 (length 2): code 0b10, reversed 0b01
        //   sym 18 (length 2): code 0b11, reversed 0b11

        // Lit/length sequence (257 entries): 256 zeros, then a 1 at
        // index 256.
        // Encode as: RLE 18 (138 zeros) + RLE 18 (118 zeros) +
        //            CL symbol 1 (length value 1, for index 256).
        // RLE 18 emit: CL symbol 18, then 7 extra bits = run-11.

        // 138-zero RLE 18: extra = 127.
        w.write_bits(rev(0b11, 2), 2); // CL sym 18
        w.write_bits(127, 7);
        // 118-zero RLE 18: extra = 107.
        w.write_bits(rev(0b11, 2), 2);
        w.write_bits(107, 7);
        // Lit/length symbol 256 = length 1, via CL sym 1.
        w.write_bits(rev(0b10, 2), 2);

        // Distance sequence (1 entry): length 0, via CL sym 0.
        w.write_bits(0, 1); // sym 0 = 1-bit code "0"

        // Block body: just EOB. Lit/length table has only one
        // populated symbol (256, length 1). Canonical code for
        // symbol 256 with length 1: 0. Reversed: 0.
        w.write_bits(0, 1); // EOB

        w.finish()
    }

    #[test]
    fn parse_minimal_preamble_eob_only_block() {
        let bytes = encode_minimal_preamble_eob_only_block();
        let mut bits = br(bytes);
        // Strip BFINAL+BTYPE off the front (parse_preamble assumes
        // it's called after the block-type bits have been consumed).
        bits.read_bits(1).expect("BFINAL");
        bits.read_bits(2).expect("BTYPE");
        let (lit, dist) = parse_preamble(&mut bits).expect("preamble");
        assert!(lit.is_populated());
        assert!(
            dist.is_none(),
            "all-zero distance alphabet should yield None"
        );
    }

    #[test]
    fn parse_preamble_rejects_hlit_too_large() {
        // Encode a fixture with HLIT field = 30 (-> hlit=287).
        let mut w = BitWriter::new();
        w.write_bits(30, 5); // HLIT = 287
        w.write_bits(0, 5); // HDIST = 1
        w.write_bits(0, 4); // HCLEN = 4
        let bytes = w.finish();
        let mut bits = br(bytes);
        match parse_preamble(&mut bits) {
            Err(DeflateError::MalformedHuffman(msg)) => {
                assert!(msg.contains("HLIT"));
            }
            other => panic!("expected MalformedHuffman, got {other:?}"),
        }
    }

    #[test]
    fn parse_preamble_rejects_hdist_too_large() {
        let mut w = BitWriter::new();
        w.write_bits(0, 5); // HLIT = 257
        w.write_bits(31, 5); // HDIST = 32
        w.write_bits(0, 4); // HCLEN = 4
        let bytes = w.finish();
        let mut bits = br(bytes);
        match parse_preamble(&mut bits) {
            Err(DeflateError::MalformedHuffman(msg)) => {
                assert!(msg.contains("HDIST"));
            }
            other => panic!("expected MalformedHuffman, got {other:?}"),
        }
    }

    #[test]
    fn parse_preamble_rejects_rle_16_at_start() {
        // HLIT=257, HDIST=1, HCLEN=4 (CL alphabet covers only CL16,
        // CL17, CL18, CL0). Set CL16 length 1 — that lets us emit
        // CL symbol 16 (RLE-repeat) as the very first length, which
        // is illegal because there's no previous length yet.
        let mut w = BitWriter::new();
        w.write_bits(0, 5); // HLIT
        w.write_bits(0, 5); // HDIST
        w.write_bits(0, 4); // HCLEN = 4
                            // 4 CL lengths in permuted order: CL16, CL17, CL18, CL0.
                            // Set clen[16]=1, others=0.
        w.write_bits(1, 3);
        w.write_bits(0, 3);
        w.write_bits(0, 3);
        w.write_bits(0, 3);
        // CL symbol 16 has length 1, canonical 0 (1 bit). Emit as
        // the first length-sequence symbol.
        w.write_bits(0, 1);
        let bytes = w.finish();
        let mut bits = br(bytes);
        match parse_preamble(&mut bits) {
            Err(DeflateError::MalformedHuffman(msg)) => {
                assert!(msg.contains("RLE code 16"));
            }
            other => panic!("expected MalformedHuffman, got {other:?}"),
        }
    }

    #[test]
    fn parse_preamble_rejects_missing_eob_code() {
        // HLIT=257, HDIST=1. Construct a fixture where every
        // lit/length length is 0 (including symbol 256 = EOB), so
        // no symbols are decodable.
        // CL alphabet: only CL18 active (long-zero RLE).
        // HCLEN = 15 ensures all 19 permutation slots are
        // explicitly declared.
        let mut w = BitWriter::new();
        w.write_bits(1, 1); // BFINAL=1
        w.write_bits(0b10, 2); // BTYPE=10
        w.write_bits(0, 5); // HLIT=0 (257)
        w.write_bits(0, 5); // HDIST=0 (1)
        w.write_bits(15, 4); // HCLEN=15 (19)

        // CLEN_ORDER positions: [16, 17, 18, 0, 8, 7, 9, 6, 10, 5,
        //   11, 4, 12, 3, 13, 2, 14, 1, 15]
        // We want clen[18] = 1 (1-bit code), all others = 0.
        let cl_at_pos = [0u32, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for &len in &cl_at_pos {
            w.write_bits(len, 3);
        }
        // CL alphabet: only sym 18 has length 1 → canonical 0 → 1
        // bit, "0".

        // Encode 258 zero entries via two RLE 18 runs (138 + 120):
        //   Run 1: 138 zeros, extra = 127.
        //   Run 2: 120 zeros, extra = 109.
        w.write_bits(0, 1); // CL sym 18
        w.write_bits(127, 7); // extra bits → run length 138
        w.write_bits(0, 1); // CL sym 18
        w.write_bits(109, 7); // extra → 120 zeros
                              // Total emitted: 258 entries. hlit + hdist = 257 + 1 = 258.

        let bytes = w.finish();
        let mut bits = br(bytes);
        bits.read_bits(1).expect("BFINAL");
        bits.read_bits(2).expect("BTYPE");
        match parse_preamble(&mut bits) {
            Err(DeflateError::MalformedHuffman(msg)) => {
                assert!(msg.contains("EOB"));
            }
            other => panic!("expected MalformedHuffman about EOB, got {other:?}"),
        }
    }

    #[test]
    fn parse_preamble_rejects_rle_run_overshooting() {
        // HLIT=257, HDIST=1, HCLEN=15. CL alphabet declares clen[18]=1.
        // Then a single RLE 18 with extra=127 declares 138 entries —
        // far short of 258 needed, but a SECOND RLE 18 with extra=127
        // would push past 258. Use a single RLE 18 with extra=127 +
        // another RLE 18 with extra > 119 to overshoot.
        let mut w = BitWriter::new();
        w.write_bits(1, 1); // BFINAL
        w.write_bits(0b10, 2); // BTYPE
        w.write_bits(0, 5); // HLIT=0
        w.write_bits(0, 5); // HDIST=0
        w.write_bits(15, 4); // HCLEN=15
        let cl_at_pos = [0u32, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for &len in &cl_at_pos {
            w.write_bits(len, 3);
        }
        // RLE 18, extra=127 → 138 entries (need 258, so 120 left).
        w.write_bits(0, 1);
        w.write_bits(127, 7);
        // RLE 18, extra=127 → 138 entries (overshoots by 18).
        w.write_bits(0, 1);
        w.write_bits(127, 7);

        let bytes = w.finish();
        let mut bits = br(bytes);
        bits.read_bits(1).expect("BFINAL");
        bits.read_bits(2).expect("BTYPE");
        match parse_preamble(&mut bits) {
            Err(DeflateError::MalformedHuffman(msg)) => {
                assert!(msg.contains("overshoots"));
            }
            other => panic!("expected MalformedHuffman, got {other:?}"),
        }
    }
}
