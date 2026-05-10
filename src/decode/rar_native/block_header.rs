//! RAR5 LZSS block-header parsing.
//!
//! Each compressed-data block begins with a 2-byte prologue:
//!
//! ```text
//! offset  size  field
//!   0      1   block_flags_u8 (bitfield, see below)
//!   1      1   block_cksum    (xor-checksum of preceding byte)
//! ```
//!
//! After the prologue come `byte_count + 1` bytes of LE
//! block-size data, followed by the block's bitstream of
//! `block_size` total bytes (where the **last byte uses only
//! `bit_size` bits**, the rest being padding).
//!
//! `block_flags_u8` layout (matches libarchive's
//! `bf_*` accessors in
//! `archive_read_support_format_rar5.c`; Grzegorz Antoniak,
//! BSD 2-Clause; see [`NOTICE`](../../../NOTICE)):
//!
//! ```text
//!  bits 2..0  bit_size           (0..7) — bits used in the last
//!                                 block byte. Special-cases the
//!                                 fact that compressed data
//!                                 doesn't necessarily end on a
//!                                 byte boundary.
//!  bits 5..3  byte_count_minus_1 (0..7) — `block_size_bytes - 1`,
//!                                 so the actual byte_count is
//!                                 `((flags >> 3) & 7) + 1`.
//!  bit  6     is_last_block      — terminate the block-walk
//!                                 after this block.
//!  bit  7     is_table_present   — whether this block carries
//!                                 fresh Huffman tables (otherwise
//!                                 reuses the previous block's).
//! ```

use thiserror::Error;

/// Errors produced while parsing a block header.
#[derive(Debug, Error)]
pub enum BlockHeaderError {
    /// The supplied buffer was too short to read the 2-byte
    /// prologue plus `byte_count` block-size bytes.
    #[error(
        "RAR5 block header truncated: needed {needed} more bytes, \
         got buffer of length {buf_len}"
    )]
    Truncated {
        /// Bytes the parser still needed.
        needed: usize,
        /// Length of the supplied buffer.
        buf_len: usize,
    },

    /// The xor-checksum of `block_flags_u8` did not match the
    /// `block_cksum` byte that followed it. RAR5's prologue
    /// stamps a self-cksum to catch single-byte corruption.
    #[error(
        "RAR5 block header checksum mismatch: flags = {flags:#04x}, \
         expected_cksum = {expected:#04x}, got_cksum = {got:#04x}"
    )]
    BadChecksum {
        /// `block_flags_u8`.
        flags: u8,
        /// `flags ^ 0x5A` (libarchive's `block_cksum` formula).
        expected: u8,
        /// `block_cksum` byte from the wire.
        got: u8,
    },
}

/// Decoded block-header fields.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BlockHeader {
    /// Number of bits used in the last block byte. `0..=7`.
    pub bit_size: u8,
    /// Number of bytes the block-size field occupies on the
    /// wire. `1..=8` (the wire stores `byte_count - 1` so the
    /// raw nibble fits in 3 bits).
    pub byte_count: u8,
    /// `true` when this is the last block in the entry.
    pub is_last_block: bool,
    /// `true` when this block carries fresh Huffman tables. When
    /// `false`, the dispatcher reuses the previous block's
    /// tables.
    pub is_table_present: bool,
    /// Total block size in bytes (parsed from the wire's
    /// little-endian `byte_count` bytes immediately after the
    /// prologue). Includes every byte of the block's bitstream;
    /// the last of those bytes uses only `bit_size` of its 8
    /// bits, the rest being padding.
    pub block_size: u64,
    /// Total bytes the prologue + size field consume on the wire
    /// (`2 + byte_count`). The block's bitstream begins
    /// immediately after.
    pub header_bytes: usize,
}

/// Parse a block header from the start of `buf`. Returns the
/// decoded fields and the number of header bytes consumed.
///
/// `buf[0]` must be `block_flags_u8`; `buf[1]` is the checksum;
/// `buf[2..2 + byte_count]` is the LE block-size field.
///
/// # Errors
///
/// - [`BlockHeaderError::Truncated`] if `buf` is shorter than
///   `2 + byte_count`.
/// - [`BlockHeaderError::BadChecksum`] if the stamped checksum
///   doesn't match the recomputed one.
pub fn parse_block_header(buf: &[u8]) -> Result<BlockHeader, BlockHeaderError> {
    if buf.len() < 2 {
        return Err(BlockHeaderError::Truncated {
            needed: 2 - buf.len(),
            buf_len: buf.len(),
        });
    }
    let flags = buf[0];
    let got_cksum = buf[1];
    let expected_cksum = block_flags_checksum(flags);
    if got_cksum != expected_cksum {
        return Err(BlockHeaderError::BadChecksum {
            flags,
            expected: expected_cksum,
            got: got_cksum,
        });
    }

    let bit_size = flags & 0b0000_0111;
    let byte_count = ((flags >> 3) & 0b0000_0111) + 1;
    let is_last_block = (flags & 0b0100_0000) != 0;
    let is_table_present = (flags & 0b1000_0000) != 0;

    let header_bytes = 2 + usize::from(byte_count);
    if buf.len() < header_bytes {
        return Err(BlockHeaderError::Truncated {
            needed: header_bytes - buf.len(),
            buf_len: buf.len(),
        });
    }
    // LE block-size: `byte_count` bytes starting at offset 2.
    let mut block_size: u64 = 0;
    for (i, &b) in buf[2..header_bytes].iter().enumerate() {
        block_size |= u64::from(b) << (i * 8);
    }
    Ok(BlockHeader {
        bit_size,
        byte_count,
        is_last_block,
        is_table_present,
        block_size,
        header_bytes,
    })
}

/// Recompute the block-flags checksum byte. libarchive's
/// `parse_block_header` validates `block_cksum == flags ^ 0x5A`;
/// the constant comes from the RAR5 reference decoder.
#[must_use]
fn block_flags_checksum(flags: u8) -> u8 {
    flags ^ 0x5A
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: assemble a block-header byte from the four
    /// fields, then append a valid checksum.
    fn build_flags(
        bit_size: u8,
        byte_count: u8,
        is_last_block: bool,
        is_table_present: bool,
    ) -> u8 {
        assert!(bit_size <= 7);
        assert!((1..=8).contains(&byte_count));
        let mut f = bit_size & 0b111;
        f |= ((byte_count - 1) & 0b111) << 3;
        if is_last_block {
            f |= 0b0100_0000;
        }
        if is_table_present {
            f |= 0b1000_0000;
        }
        f
    }

    fn build_prologue(flags: u8, block_size_bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + block_size_bytes.len());
        out.push(flags);
        out.push(block_flags_checksum(flags));
        out.extend_from_slice(block_size_bytes);
        out
    }

    #[test]
    fn parses_minimal_header_with_byte_count_1() {
        let flags = build_flags(3, 1, false, true);
        let buf = build_prologue(flags, &[0xCD]);
        let hdr = parse_block_header(&buf).unwrap();
        assert_eq!(hdr.bit_size, 3);
        assert_eq!(hdr.byte_count, 1);
        assert!(!hdr.is_last_block);
        assert!(hdr.is_table_present);
        assert_eq!(hdr.block_size, 0xCD);
        assert_eq!(hdr.header_bytes, 3);
    }

    #[test]
    fn parses_header_with_le_block_size() {
        // byte_count = 3 → 3 LE bytes → block_size = 0x00ABCDEF.
        let flags = build_flags(0, 3, false, false);
        let buf = build_prologue(flags, &[0xEF, 0xCD, 0xAB]);
        let hdr = parse_block_header(&buf).unwrap();
        assert_eq!(hdr.byte_count, 3);
        assert_eq!(hdr.block_size, 0x00AB_CDEF);
        assert_eq!(hdr.header_bytes, 5);
    }

    #[test]
    fn parses_last_block_flag() {
        let flags = build_flags(5, 2, true, true);
        let buf = build_prologue(flags, &[0x10, 0x20]);
        let hdr = parse_block_header(&buf).unwrap();
        assert_eq!(hdr.bit_size, 5);
        assert_eq!(hdr.byte_count, 2);
        assert!(hdr.is_last_block);
        assert!(hdr.is_table_present);
        assert_eq!(hdr.block_size, 0x2010);
    }

    #[test]
    fn parses_table_absent() {
        let flags = build_flags(0, 1, false, false);
        let buf = build_prologue(flags, &[1]);
        let hdr = parse_block_header(&buf).unwrap();
        assert!(!hdr.is_table_present);
    }

    #[test]
    fn parses_byte_count_8_max() {
        // byte_count = 8 → 8 LE bytes for block_size.
        let flags = build_flags(7, 8, true, true);
        let mut size_bytes = [0u8; 8];
        size_bytes[0] = 0x01;
        size_bytes[7] = 0x80;
        let buf = build_prologue(flags, &size_bytes);
        let hdr = parse_block_header(&buf).unwrap();
        assert_eq!(hdr.byte_count, 8);
        assert_eq!(hdr.bit_size, 7);
        assert_eq!(hdr.block_size, 0x8000_0000_0000_0001);
        assert_eq!(hdr.header_bytes, 10);
    }

    #[test]
    fn rejects_truncated_prologue() {
        let err = parse_block_header(&[0xAB]).unwrap_err();
        match err {
            BlockHeaderError::Truncated { needed, buf_len } => {
                assert_eq!(needed, 1);
                assert_eq!(buf_len, 1);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn rejects_truncated_size_field() {
        // byte_count = 4 expects 4 size bytes; supply 2.
        let flags = build_flags(0, 4, false, false);
        let mut buf = vec![flags, block_flags_checksum(flags)];
        buf.extend_from_slice(&[0x10, 0x20]); // only 2 bytes
        let err = parse_block_header(&buf).unwrap_err();
        assert!(matches!(err, BlockHeaderError::Truncated { needed: 2, .. }));
    }

    #[test]
    fn rejects_bad_checksum() {
        let flags = build_flags(0, 1, false, false);
        let buf = vec![
            flags,
            block_flags_checksum(flags) ^ 0x01, // corrupt checksum
            0x01,
        ];
        let err = parse_block_header(&buf).unwrap_err();
        match err {
            BlockHeaderError::BadChecksum {
                flags: f,
                expected,
                got,
            } => {
                assert_eq!(f, flags);
                assert_ne!(expected, got);
            }
            other => panic!("expected BadChecksum, got {other:?}"),
        }
    }

    #[test]
    fn checksum_formula_matches_libarchive() {
        // libarchive: cksum = flags ^ 0x5A.
        for flags in 0u8..=255u8 {
            assert_eq!(block_flags_checksum(flags), flags ^ 0x5A);
        }
    }

    #[test]
    fn round_trips_every_bit_size_and_byte_count_combination() {
        for bit_size in 0u8..=7 {
            for byte_count in 1u8..=8 {
                for is_last in [false, true] {
                    for has_table in [false, true] {
                        let flags = build_flags(bit_size, byte_count, is_last, has_table);
                        let mut size_bytes = vec![0u8; usize::from(byte_count)];
                        size_bytes[0] = 0x42;
                        let buf = build_prologue(flags, &size_bytes);
                        let hdr = parse_block_header(&buf).unwrap();
                        assert_eq!(hdr.bit_size, bit_size);
                        assert_eq!(hdr.byte_count, byte_count);
                        assert_eq!(hdr.is_last_block, is_last);
                        assert_eq!(hdr.is_table_present, has_table);
                        assert_eq!(hdr.block_size, 0x42);
                    }
                }
            }
        }
    }
}
