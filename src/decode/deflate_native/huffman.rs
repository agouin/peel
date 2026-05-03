//! Canonical Huffman decoder + RFC 1951 §3.2.6 precomputed fixed
//! tables + RFC 1951 §3.2.5 length / distance base tables.
//!
//! # Canonical Huffman decode
//!
//! [`HuffTable`] is the central type. Construction (`HuffTable::build`)
//! takes a slice of per-symbol code lengths (`code_lens[i]` =
//! bit-length of symbol `i`; `0` = "symbol not in alphabet") and
//! produces a flat `1 << max_len` lookup table indexed by
//! [`super::bitstream::BitReader::peek_bits`]. Decode (`HuffTable::decode`)
//! peeks `max_len` bits, looks up the entry, advances by the entry's
//! actual code length. This is O(1) per symbol at the cost of a
//! 2 × `max_len` memory footprint — fine for deflate where
//! `max_len ≤ 15` (32 KiB worst case).
//!
//! Bit-ordering quirk worth highlighting: the deflate stream is
//! LSB-first within each byte (RFC 1951 §3.1.1), but Huffman codes
//! are written **MSB-first** into the stream. So when a canonical
//! 8-bit code `0b10010001` is written, the high bit (`1`) lands at
//! the *highest* bit position in its 8-bit window on the wire, and
//! [`super::bitstream::BitReader::peek_bits`] reads that as the
//! *highest-order* bit of the returned `u32`. To make the flat
//! table work, the build path bit-reverses each canonical code
//! before installing it (see [`bit_reverse`]). Phase 0 spike
//! Appendix A flagged this as the single easiest piece of inflate
//! to bungle; the bit-reverse helper below is the explicit hook.
//!
//! # Fixed-Huffman tables (RFC 1951 §3.2.6)
//!
//! [`FIXED_LITLEN_TABLE`] and [`FIXED_DIST_TABLE`] are global
//! [`std::sync::LazyLock`] singletons built from the spec's fixed
//! code lengths the first time a fixed-Huffman block is decoded.
//! Built once per process, shared across every [`super::Decoder`].
//! The fixed lit/length alphabet's max code length is 9 bits, so the
//! lookup table is 1 KiB; the fixed distance alphabet's max is 5
//! bits = 64 bytes. Negligible.
//!
//! Distance codes 30 and 31 are present in the fixed distance
//! alphabet (it's a flat 5-bit code) but RFC 1951 reserves them —
//! no valid base distance is defined. The [`super::Decoder`]
//! validates the decoded distance symbol and surfaces
//! [`super::error::DeflateError::ReservedDistanceCode`] when one is
//! observed.
//!
//! # Length / distance base tables (RFC 1951 §3.2.5)
//!
//! [`LENGTH_BASE`] and [`DIST_BASE`] map the post-Huffman-decode
//! length / distance codes to their `(extra_bits, base_value)`
//! pairs. Both are referenced by the inner block-decode loop in
//! [`super::Decoder`] and reused identically by Phase 4's dynamic
//! Huffman path.

use std::sync::LazyLock;

use super::bitstream::BitReader;
use super::error::DeflateError;

/// Maximum Huffman code length per RFC 1951 §3.2.7. Both
/// fixed-Huffman tables (max 9 bits) and dynamic-Huffman tables
/// (declared per-block, capped at 15 by the spec) fit under this
/// ceiling.
pub const MAX_CODE_BITS: u32 = 15;

/// One entry in the flat lookup table. `len == 0` means "no
/// canonical code maps to this index"; reaching such an entry from
/// [`HuffTable::decode`] indicates a malformed bit pattern in the
/// source.
#[derive(Clone, Copy, Default, Debug)]
struct HuffEntry {
    /// Decoded symbol (≤ alphabet size; `u16` is plenty since the
    /// largest deflate alphabet, lit/length, has 286 entries).
    sym: u16,
    /// Number of bits the canonical code occupies; `0` is a
    /// not-installed sentinel.
    len: u8,
}

/// Canonical Huffman decode table.
///
/// Round-one allocates the flat table per build, sized at
/// `1 << max_code_length`. Phase 11 may revisit with a two-level
/// table (root + secondary) for cache friendliness; round-one
/// throughput is fine for the puncher-coverage goal.
#[derive(Debug)]
pub struct HuffTable {
    /// Flat lookup. Indexed by `peek_bits(self.bits)`.
    table: Box<[HuffEntry]>,
    /// Width of the lookup index in bits (= max code length in this
    /// alphabet, clamped to ≥ 1 for empty alphabets so `peek_bits(0)`
    /// is never called).
    bits: u32,
    /// True when the table has at least one symbol (i.e. at least
    /// one `code_lens[i] != 0`). Empty alphabets — used by Phase 4
    /// dynamic blocks that declare no distances — are constructable
    /// (the build succeeds) but [`Self::decode`] surfaces
    /// [`DeflateError::MalformedHuffman`] if anyone tries to read
    /// from one.
    populated: bool,
}

impl HuffTable {
    /// Build a canonical Huffman decode table from per-symbol code
    /// lengths.
    ///
    /// `code_lens[i]` is the bit-length of symbol `i`; `0` means
    /// "symbol not present in this alphabet". Lengths are bounded
    /// at [`MAX_CODE_BITS`].
    ///
    /// # Errors
    ///
    /// - [`DeflateError::MalformedHuffman`] when a code length
    ///   exceeds [`MAX_CODE_BITS`], or when the assigned canonical
    ///   codes overflow `1 << bits` (Kraft-inequality violation —
    ///   "over-subscribed" tree). Under-subscribed trees are
    ///   permitted by RFC 1951 (an over-allocated alphabet with
    ///   missing entries is well-formed); reads that land on the
    ///   missing entries surface as malformed at decode time.
    pub fn build(code_lens: &[u8]) -> Result<Self, DeflateError> {
        // RFC 1951 §3.2.2 procedure: count by length, compute
        // next_code per length, assign canonical codes by symbol.
        let mut bl_count = [0u32; (MAX_CODE_BITS as usize) + 1];
        let mut max_len = 0u32;
        for &l in code_lens {
            if u32::from(l) > MAX_CODE_BITS {
                return Err(DeflateError::MalformedHuffman("code length > 15"));
            }
            if l != 0 {
                bl_count[l as usize] = bl_count[l as usize].saturating_add(1);
                if u32::from(l) > max_len {
                    max_len = u32::from(l);
                }
            }
        }

        // Empty alphabet: still build a 1-entry stub so `peek_bits(1)`
        // is well-defined; mark `populated = false` so any decode
        // attempt surfaces [`DeflateError::MalformedHuffman`].
        if max_len == 0 {
            return Ok(HuffTable {
                table: vec![HuffEntry::default(); 1].into_boxed_slice(),
                bits: 1,
                populated: false,
            });
        }

        // Compute first canonical code for each length.
        let mut next_code = [0u32; (MAX_CODE_BITS as usize) + 2];
        let mut code: u32 = 0;
        for length in 1..=max_len {
            code = code.checked_add(bl_count[(length - 1) as usize]).ok_or(
                DeflateError::MalformedHuffman("canonical code accumulator overflowed"),
            )? << 1;
            next_code[length as usize] = code;
        }
        // Kraft check: at length `max_len` the running code value
        // after assignment must not exceed `1 << max_len`.
        let limit = 1u32 << max_len;
        let last_assigned = code.saturating_add(bl_count[max_len as usize]);
        if last_assigned > limit {
            return Err(DeflateError::MalformedHuffman(
                "Huffman tree over-subscribed (Kraft inequality violated)",
            ));
        }

        let bits = max_len;
        let table_size = 1usize << bits;
        let mut table = vec![HuffEntry::default(); table_size].into_boxed_slice();

        // Assign canonical codes in symbol order, replicating each
        // entry across the high bits we don't care about. RFC 1951
        // packs Huffman codes MSB-first into the stream, but the
        // bit reader returns LSB-first peek values, so each
        // canonical code is bit-reversed before installation —
        // see the module-level commentary on this quirk.
        for (sym, &cl) in code_lens.iter().enumerate() {
            if cl == 0 {
                continue;
            }
            let cl = u32::from(cl);
            let canonical = next_code[cl as usize];
            next_code[cl as usize] = next_code[cl as usize].saturating_add(1);
            // INVARIANT: cl is in 1..=15 and canonical is in
            // 0..(1 << cl) by the Kraft check above. The reversed
            // value is therefore in the same range.
            let reversed = bit_reverse(canonical, cl);
            let stride = 1usize << cl;
            // Replicate `(sym, cl)` into every entry whose low `cl`
            // bits equal `reversed`.
            let mut idx = reversed as usize;
            // INVARIANT: `cl <= bits` (we set `bits = max_len`),
            // so the stride fits in the table and the loop
            // terminates after `table_size / stride` iterations.
            while idx < table_size {
                table[idx] = HuffEntry {
                    // INVARIANT: `sym < code_lens.len() <= alphabet
                    // size`, which for every deflate alphabet fits
                    // in `u16`.
                    sym: sym as u16,
                    // INVARIANT: `cl <= MAX_CODE_BITS = 15`, fits
                    // in `u8`.
                    len: cl as u8,
                };
                idx += stride;
            }
        }

        Ok(HuffTable {
            table,
            bits,
            populated: true,
        })
    }

    /// Decode the next Huffman symbol off `br`.
    ///
    /// Performs the canonical "peek max-len bits, look up entry,
    /// consume actual code length" cycle. Uses the bit reader's
    /// soft [`BitReader::ensure`] so a stream that ends exactly at
    /// the EOB code's last bit (an extremely common case for
    /// Huffman-block deflate streams) decodes cleanly without a
    /// false-positive truncation: the lookup table's entries for
    /// short codes are replicated across every high-bit pattern
    /// of the lookup index, so an "ensure-up-to" peek with
    /// implicit zero-padding above `bits_buffered` still hits the
    /// correct entry.
    ///
    /// # Errors
    ///
    /// - [`DeflateError::UnexpectedEof`] when the source is
    ///   exhausted *and* fewer bits than the entry's actual code
    ///   length are buffered (i.e. the stream truly couldn't
    ///   provide enough bits for the next symbol).
    /// - [`DeflateError::SourceIo`] for any underlying source IO
    ///   error during refill.
    /// - [`DeflateError::MalformedHuffman`] when this table has no
    ///   symbols (an empty alphabet — caller must not invoke
    ///   `decode` on those) or when the peeked bit pattern lands
    ///   on an unfilled table entry.
    pub fn decode(&self, br: &mut BitReader) -> Result<u16, DeflateError> {
        if !self.populated {
            return Err(DeflateError::MalformedHuffman(
                "decode from empty Huffman alphabet",
            ));
        }
        // Best-effort refill — short reads near EOF are tolerated;
        // the per-entry length check below catches the case where
        // we genuinely don't have enough bits for the symbol.
        br.ensure(self.bits)?;
        if br.bits_buffered() == 0 {
            return Err(DeflateError::UnexpectedEof("bit stream"));
        }
        let key = br.peek_bits(self.bits) as usize;
        let entry = self.table[key];
        if entry.len == 0 {
            return Err(DeflateError::MalformedHuffman(
                "bit pattern not assigned to any code",
            ));
        }
        if u32::from(entry.len) > br.bits_buffered() {
            // The lookup landed on a symbol whose code length
            // exceeds what's actually available in the stream —
            // legitimate truncation.
            return Err(DeflateError::UnexpectedEof("bit stream"));
        }
        br.consume_bits(u32::from(entry.len));
        Ok(entry.sym)
    }

    /// Width of the flat lookup table, in bits. Equals the maximum
    /// code length in the alphabet (with a `1` fallback for empty
    /// alphabets so `peek_bits(0)` is never invoked).
    #[must_use]
    pub fn lookup_bits(&self) -> u32 {
        self.bits
    }

    /// True when at least one symbol is present in this table.
    /// Phase 4 dynamic blocks may build empty distance tables when
    /// the block uses literals only; callers must check this before
    /// dispatching to [`Self::decode`].
    #[must_use]
    pub fn is_populated(&self) -> bool {
        self.populated
    }
}

/// Reverse the low `n` bits of `v`. Used by [`HuffTable::build`] to
/// align canonical (MSB-first) codes with the LSB-first stream
/// order [`super::bitstream::BitReader`] returns.
///
/// Phase 0 spike Q2: production should replace this naive bit-by-bit
/// loop with either an inlined constant-time 16-bit reverse or a
/// 256-byte precomputed table. Round-one keeps the loop because
/// `bit_reverse` is called once per **populated symbol** during
/// table construction — not on every Huffman-decode lookup —
/// so the common case is a few hundred calls per dynamic block,
/// which the spike's 228 MiB/s low-redundancy throughput already
/// absorbs comfortably.
#[must_use]
fn bit_reverse(mut v: u32, n: u32) -> u32 {
    debug_assert!(n <= 32);
    let mut r = 0u32;
    for _ in 0..n {
        r = (r << 1) | (v & 1);
        v >>= 1;
    }
    r
}

/// RFC 1951 §3.2.5 length-code table. The `i`th entry corresponds
/// to lit/length code `257 + i` and gives `(extra_bits, base_value)`.
/// 29 entries cover codes 257..=285. Codes 286 and 287 are reserved
/// in the fixed-Huffman alphabet (decoded but never used by valid
/// encoders).
pub const LENGTH_BASE: [(u8, u32); 29] = [
    (0, 3),
    (0, 4),
    (0, 5),
    (0, 6),
    (0, 7),
    (0, 8),
    (0, 9),
    (0, 10),
    (1, 11),
    (1, 13),
    (1, 15),
    (1, 17),
    (2, 19),
    (2, 23),
    (2, 27),
    (2, 31),
    (3, 35),
    (3, 43),
    (3, 51),
    (3, 59),
    (4, 67),
    (4, 83),
    (4, 99),
    (4, 115),
    (5, 131),
    (5, 163),
    (5, 195),
    (5, 227),
    (0, 258),
];

/// RFC 1951 §3.2.5 distance-code table. The `i`th entry gives
/// `(extra_bits, base_value)` for distance code `i`. 30 entries
/// cover codes 0..=29; codes 30 and 31 are reserved (no valid base
/// distance) and surface as
/// [`DeflateError::ReservedDistanceCode`] when decoded by the
/// outer state machine.
pub const DIST_BASE: [(u8, u32); 30] = [
    (0, 1),
    (0, 2),
    (0, 3),
    (0, 4),
    (1, 5),
    (1, 7),
    (2, 9),
    (2, 13),
    (3, 17),
    (3, 25),
    (4, 33),
    (4, 49),
    (5, 65),
    (5, 97),
    (6, 129),
    (6, 193),
    (7, 257),
    (7, 385),
    (8, 513),
    (8, 769),
    (9, 1025),
    (9, 1537),
    (10, 2049),
    (10, 3073),
    (11, 4097),
    (11, 6145),
    (12, 8193),
    (12, 12289),
    (13, 16385),
    (13, 24577),
];

/// Code-length sequence for the fixed lit/length alphabet
/// (RFC 1951 §3.2.6). 288 entries: `0..=143` are 8 bits; `144..=255`
/// are 9 bits; `256..=279` are 7 bits; `280..=287` are 8 bits.
const FIXED_LITLEN_LENGTHS: [u8; 288] = {
    let mut a = [0u8; 288];
    let mut i = 0;
    while i < 144 {
        a[i] = 8;
        i += 1;
    }
    while i < 256 {
        a[i] = 9;
        i += 1;
    }
    while i < 280 {
        a[i] = 7;
        i += 1;
    }
    while i < 288 {
        a[i] = 8;
        i += 1;
    }
    a
};

/// Code-length sequence for the fixed distance alphabet
/// (RFC 1951 §3.2.6): 32 entries, each 5 bits. Codes 30 / 31 are
/// reserved — see module commentary.
const FIXED_DIST_LENGTHS: [u8; 32] = [5; 32];

/// Lazily-built fixed lit/length Huffman table. Built once per
/// process from [`FIXED_LITLEN_LENGTHS`].
pub static FIXED_LITLEN_TABLE: LazyLock<HuffTable> = LazyLock::new(|| {
    HuffTable::build(&FIXED_LITLEN_LENGTHS)
        // SAFETY-OF-CONSTRUCTION: the lengths are spec-mandated and
        // satisfy the Kraft inequality with equality (288 codes,
        // sum of `2^-len` = 1 exactly). Any failure here would be
        // a bug in `HuffTable::build`, not a legitimate source-side
        // error.
        .expect("fixed lit/length table build is infallible by RFC 1951 §3.2.6")
});

/// Lazily-built fixed distance Huffman table. Built once per
/// process from [`FIXED_DIST_LENGTHS`].
pub static FIXED_DIST_TABLE: LazyLock<HuffTable> = LazyLock::new(|| {
    HuffTable::build(&FIXED_DIST_LENGTHS)
        // SAFETY-OF-CONSTRUCTION: a uniform 5-bit alphabet with 32
        // entries satisfies the Kraft inequality exactly.
        .expect("fixed distance table build is infallible")
});

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    fn br(bytes: Vec<u8>) -> BitReader {
        BitReader::new(Box::new(Cursor::new(bytes)))
    }

    #[test]
    fn bit_reverse_round_trips_under_double_application() {
        // bit_reverse is its own inverse for any fixed `n`.
        for n in 1..=15u32 {
            let mask = if n == 32 { u32::MAX } else { (1u32 << n) - 1 };
            for v in 0..mask.min(64).saturating_add(1) {
                let r = bit_reverse(v, n);
                let r2 = bit_reverse(r, n);
                assert_eq!(r2, v, "double-reverse mismatch at n={n} v={v}");
            }
        }
    }

    #[test]
    fn bit_reverse_known_values() {
        // 0b10010001 (8 bits) reversed = 0b10001001.
        assert_eq!(bit_reverse(0b1001_0001, 8), 0b1000_1001);
        // 0b1011 (4 bits) reversed = 0b1101.
        assert_eq!(bit_reverse(0b1011, 4), 0b1101);
        // Single bit is its own reverse.
        assert_eq!(bit_reverse(1, 1), 1);
        assert_eq!(bit_reverse(0, 1), 0);
    }

    #[test]
    fn build_rejects_code_length_above_max() {
        let mut lens = vec![0u8; 16];
        lens[0] = 16; // > MAX_CODE_BITS
        match HuffTable::build(&lens) {
            Err(DeflateError::MalformedHuffman(msg)) => {
                assert!(msg.contains("> 15"));
            }
            other => panic!("expected MalformedHuffman, got {other:?}"),
        }
    }

    #[test]
    fn build_rejects_oversubscribed_tree() {
        // Three symbols with length 1 — but length 1 only fits 2
        // codes in a binary tree.
        let lens = [1u8, 1, 1];
        match HuffTable::build(&lens) {
            Err(DeflateError::MalformedHuffman(msg)) => {
                assert!(msg.contains("over-subscribed"));
            }
            other => panic!("expected MalformedHuffman, got {other:?}"),
        }
    }

    #[test]
    fn build_accepts_fixed_litlen_lengths() {
        let t = HuffTable::build(&FIXED_LITLEN_LENGTHS).expect("fixed lit/length valid");
        assert_eq!(t.lookup_bits(), 9);
        assert!(t.is_populated());
    }

    #[test]
    fn build_accepts_fixed_dist_lengths() {
        let t = HuffTable::build(&FIXED_DIST_LENGTHS).expect("fixed distance valid");
        assert_eq!(t.lookup_bits(), 5);
        assert!(t.is_populated());
    }

    #[test]
    fn build_accepts_empty_alphabet() {
        let t = HuffTable::build(&[0u8; 5]).expect("empty alphabet builds");
        assert!(!t.is_populated());
        // Decoding from an empty alphabet errors out cleanly.
        let mut r = br(vec![0xFFu8; 4]);
        match t.decode(&mut r) {
            Err(DeflateError::MalformedHuffman(msg)) => {
                assert!(msg.contains("empty Huffman alphabet"));
            }
            other => panic!("expected MalformedHuffman, got {other:?}"),
        }
    }

    /// Spec sanity for the fixed lit/length table: the 7-bit code
    /// for symbol 256 (EOB) is canonical 0b0000000 = 0. After
    /// bit-reversing for LSB-first lookup, that lands at table
    /// index 0.
    #[test]
    fn fixed_litlen_eob_decodes_from_seven_zero_bits() {
        let mut r = br(vec![0u8, 0u8]);
        let sym = FIXED_LITLEN_TABLE.decode(&mut r).expect("EOB decodes");
        assert_eq!(sym, 256);
        // EOB is 7 bits — 1 bit of byte 0 left after the decode.
        assert_eq!(r.byte_position(), (0, 7));
    }

    /// RFC 1951 §3.2.6: literal `'A'` (= 0x41 = 65) has canonical
    /// 8-bit code `0b0011_0000 + 65 = 0b0111_0001 = 0x71`. Reversed
    /// for LSB-first lookup that's `bit_reverse(0x71, 8)`. The
    /// stream byte that decodes to 'A' (BFINAL/BTYPE not in scope
    /// here) is therefore `bit_reverse(0x71, 8)`.
    #[test]
    fn fixed_litlen_literal_a_decodes() {
        let canonical = 0x71u32;
        let reversed = bit_reverse(canonical, 8);
        let mut r = br(vec![reversed as u8, 0u8]);
        let sym = FIXED_LITLEN_TABLE.decode(&mut r).expect("'A' decodes");
        assert_eq!(sym, 65);
    }

    /// Distance code 0 = 5-bit code `0b00000`; reversed is also 0.
    /// A stream whose first 5 bits are zero decodes to distance
    /// code 0.
    #[test]
    fn fixed_dist_code_zero_decodes() {
        let mut r = br(vec![0u8, 0u8]);
        let sym = FIXED_DIST_TABLE.decode(&mut r).expect("dist 0 decodes");
        assert_eq!(sym, 0);
    }

    /// Decoding from a single byte fully then trying to read more
    /// surfaces UnexpectedEof, not a panic.
    #[test]
    fn decode_past_eof_surfaces_typed_error() {
        // Build a trivial 1-symbol alphabet: code length 1 → table
        // has a single-bit code. `[1, 0]` lengths means symbol 0 has
        // a 1-bit code; symbol 1 isn't present.
        let t = HuffTable::build(&[1u8]).expect("single-symbol table");
        let mut r = br(Vec::new());
        match t.decode(&mut r) {
            Err(DeflateError::UnexpectedEof(_)) => {}
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn fixed_litlen_table_round_trip_known_codes() {
        // Codes 0..=143 are 8-bit canonical `0x30 + sym`; we test a
        // few across the range to exercise different bit-reversal
        // outcomes.
        for &sym in &[0u16, 1, 65, 100, 143] {
            let canonical = 0x30u32 + u32::from(sym);
            let reversed = bit_reverse(canonical, 8);
            let mut r = br(vec![reversed as u8, 0]);
            let decoded = FIXED_LITLEN_TABLE.decode(&mut r).expect("decode");
            assert_eq!(decoded, sym);
        }
        // Symbol 144..=255 are 9-bit canonical `0x190 + (sym - 144)`.
        for &sym in &[144u16, 200, 255] {
            let canonical = 0x190u32 + u32::from(sym - 144);
            let reversed = bit_reverse(canonical, 9);
            // Pack 9 bits LSB-first into bytes.
            let bytes = vec![(reversed & 0xFF) as u8, ((reversed >> 8) & 0xFF) as u8];
            let mut r = br(bytes);
            let decoded = FIXED_LITLEN_TABLE.decode(&mut r).expect("decode 9-bit");
            assert_eq!(decoded, sym);
        }
    }

    #[test]
    fn length_base_table_matches_rfc_for_extremes() {
        // RFC 1951 §3.2.5 spot-checks:
        // code 257 → length 3, 0 extra bits.
        assert_eq!(LENGTH_BASE[0], (0, 3));
        // code 285 → length 258, 0 extra bits (the fixed-length
        // top-of-range entry).
        assert_eq!(LENGTH_BASE[28], (0, 258));
        // code 264 → length 10, 0 extra bits (transition right
        // before extra-bit encoding starts).
        assert_eq!(LENGTH_BASE[7], (0, 10));
        // code 265 → length 11, 1 extra bit.
        assert_eq!(LENGTH_BASE[8], (1, 11));
    }

    #[test]
    fn dist_base_table_matches_rfc_for_extremes() {
        // code 0 → distance 1, 0 extra bits.
        assert_eq!(DIST_BASE[0], (0, 1));
        // code 3 → distance 4, 0 extra bits (last of the 0-extra-bit
        // group: codes 0..=3 use literal distances 1..=4).
        assert_eq!(DIST_BASE[3], (0, 4));
        // code 4 → distance 5, 1 extra bit.
        assert_eq!(DIST_BASE[4], (1, 5));
        // code 29 → distance 24577, 13 extra bits (top of range,
        // max distance after extras = 32768).
        assert_eq!(DIST_BASE[29], (13, 24577));
    }

    /// LazyLock works across threads — sanity check that
    /// `FIXED_*_TABLE` access from multiple threads doesn't race.
    #[test]
    fn fixed_tables_are_thread_safe() {
        use std::thread;
        let handles: Vec<_> = (0..4)
            .map(|_| {
                thread::spawn(|| {
                    let _ = FIXED_LITLEN_TABLE.lookup_bits();
                    let _ = FIXED_DIST_TABLE.lookup_bits();
                })
            })
            .collect();
        for h in handles {
            h.join().expect("thread joined");
        }
    }
}
