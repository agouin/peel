//! DEFLATE block-level parsing (RFC 1951 §3.2.3).
//!
//! Pure logic over `&[u8]`s — no IO. The [`super::Decoder`] is
//! responsible for assembling the bytes and threading the sink
//! writes; this module only knows the wire format.
//!
//! The block layer's Phase 1 surface:
//!
//! - Parse the 3-bit block header (`BFINAL` + `BTYPE`) carried in the
//!   low 3 bits of a single byte. Stored blocks immediately
//!   byte-align after these 3 bits, discarding the high 5 bits, so
//!   the parser can be byte-oriented; Phase 2's bit reader supplants
//!   this surface for fixed/dynamic blocks.
//! - Parse the 4-byte stored-block length pair (`LEN`, `NLEN`) per
//!   RFC 1951 §3.2.4 and validate the `LEN ^ 0xFFFF == NLEN`
//!   invariant.
//! - Reject `BTYPE=11` (reserved) and surface fixed/dynamic block
//!   types as deliberate placeholder errors per
//!   `internal/PLAN_deflate_block_decoder.md` §Phase 1.
//!
//! # Bit layout reminder (RFC 1951 §3.1.1)
//!
//! Bytes are written into the stream low-byte first, and bits within
//! a byte are packed LSB-first. So if a byte's hex value is `0x4B`
//! (binary `0b01001011`), the first bit read off the stream is bit 0
//! (the LSB) = `1`, the second is bit 1 = `1`, the third is bit 2 =
//! `0`, and so on. For a stored block the layout of byte 0 is
//! therefore:
//!
//! ```text
//!   bit 0:    BFINAL (1 = last block, 0 = more follow)
//!   bits 1–2: BTYPE  (low bit first)
//!   bits 3–7: discarded — RFC 1951 §3.2.4 byte alignment for stored
//!             blocks
//! ```
//!
//! Fixed (BTYPE=01) and dynamic (BTYPE=10) blocks do **not**
//! byte-align after the 3-bit header — the next Huffman code starts
//! at bit 3 of the same byte. Phase 1 doesn't decode those anyway,
//! but the boundary matters for Phase 3+ and is called out here so
//! the byte-vs-bit decoder split is explicit.

use super::error::DeflateError;

/// Length of the stored-block header (`LEN` + `NLEN`) on the wire,
/// after the BTYPE byte and after byte alignment per RFC 1951 §3.2.4.
pub const STORED_HEADER_LEN: usize = 4;

/// RFC 1951 §3.2.4: the stored block's `LEN` field is a 16-bit count,
/// so payload size is bounded at 65535 bytes per block.
pub const STORED_MAX_LEN: u16 = u16::MAX;

/// Block-type tag from a parsed block header (RFC 1951 §3.2.3).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BlockType {
    /// `BTYPE=00`. Stored (uncompressed) block. After the 3-bit
    /// header the stream byte-aligns, then four header bytes
    /// (`LEN_lo`, `LEN_hi`, `NLEN_lo`, `NLEN_hi`) precede a verbatim
    /// payload of `LEN` bytes.
    Stored,
    /// `BTYPE=01`. Fixed Huffman block. Decoded with the precomputed
    /// canonical tables in RFC 1951 §3.2.6. Phase 3 fills this in;
    /// Phase 1 surfaces [`DeflateError::FixedHuffmanUnimplemented`].
    FixedHuffman,
    /// `BTYPE=10`. Dynamic Huffman block. Carries an inline
    /// code-length-codes preamble (HLIT/HDIST/HCLEN, RFC 1951
    /// §3.2.7). Phase 4 fills this in; Phase 1 surfaces
    /// [`DeflateError::DynamicHuffmanUnimplemented`].
    DynamicHuffman,
}

/// A parsed block header (the BFINAL+BTYPE pair, before any
/// type-specific body).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BlockHeader {
    /// `true` when the `BFINAL` bit is set, meaning this is the last
    /// block in the deflate stream. Subsequent bytes after the block
    /// body belong to the consumer's framing layer (gzip trailer,
    /// zip data descriptor, raw EOF).
    pub last: bool,
    /// Tag identifying the block body's encoding.
    pub ty: BlockType,
}

/// Parse a stored-block BTYPE byte: extract `BFINAL`, `BTYPE`, and
/// implicitly discard the high 5 bits (the byte-alignment padding
/// the stored block immediately performs per RFC 1951 §3.2.4).
///
/// # Errors
///
/// - [`DeflateError::ReservedBlockType`] when `BTYPE=11`.
///
/// Note that `BTYPE=01` and `BTYPE=10` are *not* errors at this
/// layer: the parser surfaces them as [`BlockType::FixedHuffman`] /
/// [`BlockType::DynamicHuffman`] tags so the caller can decide
/// whether to dispatch to a Phase-3/4 body or fail with the
/// phase-specific placeholder error.
pub fn parse_block_type_byte(byte: u8) -> Result<BlockHeader, DeflateError> {
    let bfinal = (byte & 0b0000_0001) != 0;
    // RFC 1951 §3.1.1: bits within a byte are LSB-first. So bit 1
    // is the low bit of BTYPE and bit 2 is the high bit; when
    // recombined as a 2-bit value, the encoding is
    // `(byte >> 1) & 0b11`.
    let btype = (byte >> 1) & 0b0000_0011;
    let ty = match btype {
        0b00 => BlockType::Stored,
        0b01 => BlockType::FixedHuffman,
        0b10 => BlockType::DynamicHuffman,
        0b11 => return Err(DeflateError::ReservedBlockType),
        // INVARIANT: `(byte >> 1) & 0b11` is in `0..=3` by
        // construction; the four arms above are exhaustive.
        _ => unreachable!("two-bit BTYPE enumerates 0..=3"),
    };
    Ok(BlockHeader { last: bfinal, ty })
}

/// Parse the 4-byte `(LEN_lo, LEN_hi, NLEN_lo, NLEN_hi)` header that
/// follows a stored-block BTYPE byte after RFC 1951 §3.2.4 byte
/// alignment.
///
/// Returns the validated `LEN` (the byte count of the verbatim
/// payload that follows). Phase 1's hand-built fixtures in
/// [`super::Decoder`]'s test module exercise both the success path
/// and the [`DeflateError::StoredLenMismatch`] failure path.
///
/// # Errors
///
/// - [`DeflateError::StoredLenMismatch`] when `LEN ^ 0xFFFF != NLEN`.
pub fn parse_stored_lengths(buf: [u8; STORED_HEADER_LEN]) -> Result<u16, DeflateError> {
    let len = u16::from_le_bytes([buf[0], buf[1]]);
    let nlen = u16::from_le_bytes([buf[2], buf[3]]);
    if len ^ 0xFFFF != nlen {
        return Err(DeflateError::StoredLenMismatch { len, nlen });
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_block_type_byte_extracts_bfinal_and_btype() {
        // BFINAL=1, BTYPE=00, padding=00000 → 0b0000_0001 = 0x01.
        let h = parse_block_type_byte(0x01).expect("stored");
        assert!(h.last);
        assert_eq!(h.ty, BlockType::Stored);

        // BFINAL=0, BTYPE=00, padding=11111 → high bits are
        // *discarded* by the stored-block alignment, so any value of
        // the high 5 bits round-trips identically.
        let h = parse_block_type_byte(0b1111_1000).expect("stored");
        assert!(!h.last);
        assert_eq!(h.ty, BlockType::Stored);
    }

    #[test]
    fn parse_block_type_byte_recognizes_fixed_huffman() {
        // BFINAL=1, BTYPE=01 → bit 0 = 1, bits 2:1 = 01 → 0b011 = 3.
        let h = parse_block_type_byte(0x03).expect("fixed");
        assert!(h.last);
        assert_eq!(h.ty, BlockType::FixedHuffman);
    }

    #[test]
    fn parse_block_type_byte_recognizes_dynamic_huffman() {
        // BFINAL=1, BTYPE=10 → bit 0 = 1, bits 2:1 = 10 → 0b101 = 5.
        let h = parse_block_type_byte(0x05).expect("dynamic");
        assert!(h.last);
        assert_eq!(h.ty, BlockType::DynamicHuffman);
    }

    #[test]
    fn parse_block_type_byte_rejects_reserved() {
        // BFINAL=1, BTYPE=11 → bit 0 = 1, bits 2:1 = 11 → 0b111 = 7.
        match parse_block_type_byte(0x07) {
            Err(DeflateError::ReservedBlockType) => {}
            other => panic!("expected ReservedBlockType, got {other:?}"),
        }
        // BFINAL=0, BTYPE=11 → 0b110 = 6.
        match parse_block_type_byte(0x06) {
            Err(DeflateError::ReservedBlockType) => {}
            other => panic!("expected ReservedBlockType, got {other:?}"),
        }
    }

    #[test]
    fn parse_stored_lengths_accepts_valid_pair() {
        // LEN = 0x0010 = 16, NLEN = !0x0010 = 0xFFEF.
        let buf = [0x10, 0x00, 0xEF, 0xFF];
        let len = parse_stored_lengths(buf).expect("valid");
        assert_eq!(len, 16);
    }

    #[test]
    fn parse_stored_lengths_accepts_zero_length() {
        // Empty stored block: LEN = 0, NLEN = 0xFFFF.
        let buf = [0x00, 0x00, 0xFF, 0xFF];
        let len = parse_stored_lengths(buf).expect("empty stored block is valid");
        assert_eq!(len, 0);
    }

    #[test]
    fn parse_stored_lengths_accepts_max_length() {
        // LEN = 0xFFFF (the spec maximum), NLEN = 0x0000.
        let buf = [0xFF, 0xFF, 0x00, 0x00];
        let len = parse_stored_lengths(buf).expect("max stored block");
        assert_eq!(len, STORED_MAX_LEN);
    }

    #[test]
    fn parse_stored_lengths_rejects_corrupted_pair() {
        // LEN = 0x0010, but NLEN = 0xDEAD (does not equal !LEN).
        let buf = [0x10, 0x00, 0xAD, 0xDE];
        match parse_stored_lengths(buf) {
            Err(DeflateError::StoredLenMismatch { len, nlen }) => {
                assert_eq!(len, 0x0010);
                assert_eq!(nlen, 0xDEAD);
            }
            other => panic!("expected StoredLenMismatch, got {other:?}"),
        }
    }

    #[test]
    fn parse_stored_lengths_uses_little_endian_byte_order() {
        // RFC 1951 §3.2.4 specifies LEN/NLEN as 16-bit little-endian.
        // 0x1234 LE → bytes [0x34, 0x12].
        let buf = [0x34, 0x12, 0xCB, 0xED];
        let len = parse_stored_lengths(buf).expect("LE round-trip");
        assert_eq!(len, 0x1234);
    }
}
