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
//!  bits 5..3  byte_count_minus_1 (0..2) — `block_size_bytes - 1`,
//!                                 so the actual byte_count is
//!                                 `((flags >> 3) & 7) + 1` and
//!                                 lives in `1..=3`. Wire values
//!                                 of 3..=7 surface as
//!                                 [`BlockHeaderError::UnsupportedByteCount`]
//!                                 — libarchive's reference
//!                                 decoder caps the field at 3
//!                                 and `rar a` never emits more.
//!  bit  6     is_last_block      — terminate the block-walk
//!                                 after this block.
//!  bit  7     is_table_present   — whether this block carries
//!                                 fresh Huffman tables (otherwise
//!                                 reuses the previous block's).
//! ```
//!
//! The checksum is `0x5A ^ flags ^ size[0] ^ size[1] ^ size[2]`,
//! where `size[0..3]` is the LE block-size field zero-padded to
//! 3 bytes. Libarchive folds every byte of the size into the
//! checksum even when `byte_count < 3` — the upper-byte XOR is
//! identity against the implicit zero, so the formula is
//! `calc = 0x5A ^ flags ^ (block_size_bytes XORed)`.

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

    /// The xor-checksum of the prologue did not match the
    /// stamped `block_cksum` byte. The checksum covers
    /// `flags + the LE block-size bytes` per libarchive's
    /// `parse_block_header` formula
    /// (`0x5A ^ flags ^ size[0] ^ size[1] ^ size[2]`).
    #[error(
        "RAR5 block header checksum mismatch: flags = {flags:#04x}, \
         expected_cksum = {expected:#04x}, got_cksum = {got:#04x}"
    )]
    BadChecksum {
        /// `block_flags_u8`.
        flags: u8,
        /// Computed checksum (`0x5A ^ flags ^ size_xor`).
        expected: u8,
        /// `block_cksum` byte from the wire.
        got: u8,
    },

    /// The wire `byte_count_minus_1` field is 3..=7 (i.e.,
    /// `byte_count > 3`). Libarchive's reference decoder only
    /// supports 1..=3 size bytes; rejecting larger values
    /// surfaces malformed / future-format input as a precise
    /// diagnostic instead of a checksum mismatch.
    #[error(
        "RAR5 block header byte_count {got} out of supported range 1..=3 \
         (libarchive caps at 3)"
    )]
    UnsupportedByteCount {
        /// The decoded `byte_count` value (`1..=8`).
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

    let bit_size = flags & 0b0000_0111;
    let byte_count = ((flags >> 3) & 0b0000_0111) + 1;
    let is_last_block = (flags & 0b0100_0000) != 0;
    let is_table_present = (flags & 0b1000_0000) != 0;
    if byte_count > 3 {
        return Err(BlockHeaderError::UnsupportedByteCount { got: byte_count });
    }

    let header_bytes = 2 + usize::from(byte_count);
    if buf.len() < header_bytes {
        return Err(BlockHeaderError::Truncated {
            needed: header_bytes - buf.len(),
            buf_len: buf.len(),
        });
    }
    // LE block-size: `byte_count` bytes starting at offset 2. The
    // checksum folds these into `flags ^ 0x5A` per libarchive's
    // `parse_block_header` formula.
    let mut block_size: u64 = 0;
    let mut size_xor: u8 = 0;
    for (i, &b) in buf[2..header_bytes].iter().enumerate() {
        block_size |= u64::from(b) << (i * 8);
        size_xor ^= b;
    }
    let expected_cksum = block_prologue_checksum(flags, size_xor);
    if got_cksum != expected_cksum {
        return Err(BlockHeaderError::BadChecksum {
            flags,
            expected: expected_cksum,
            got: got_cksum,
        });
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

/// Recompute the block-prologue checksum. Libarchive's
/// `parse_block_header` validates
/// `block_cksum == 0x5A ^ flags ^ size[0] ^ size[1] ^ size[2]`;
/// the upper size bytes XOR-fold to identity when `byte_count < 3`,
/// so the caller passes an `xor` that already covers all bytes
/// it actually read.
#[must_use]
fn block_prologue_checksum(flags: u8, size_xor: u8) -> u8 {
    0x5A ^ flags ^ size_xor
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

    fn xor_all(bytes: &[u8]) -> u8 {
        bytes.iter().fold(0u8, |acc, &b| acc ^ b)
    }

    fn build_prologue(flags: u8, block_size_bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + block_size_bytes.len());
        out.push(flags);
        out.push(block_prologue_checksum(flags, xor_all(block_size_bytes)));
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
    fn parses_byte_count_3_max() {
        // libarchive caps `byte_count` at 3 size bytes; we mirror
        // that limit. Verify the max-supported case round-trips.
        let flags = build_flags(7, 3, true, true);
        let size_bytes = [0xEFu8, 0xCD, 0xAB];
        let buf = build_prologue(flags, &size_bytes);
        let hdr = parse_block_header(&buf).unwrap();
        assert_eq!(hdr.byte_count, 3);
        assert_eq!(hdr.bit_size, 7);
        assert_eq!(hdr.block_size, 0x00AB_CDEF);
        assert_eq!(hdr.header_bytes, 5);
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
        // byte_count = 3 expects 3 size bytes; supply 1.
        let flags = build_flags(0, 3, false, false);
        let mut buf = vec![flags, block_prologue_checksum(flags, 0x10)];
        buf.extend_from_slice(&[0x10]); // only 1 byte
        let err = parse_block_header(&buf).unwrap_err();
        assert!(matches!(err, BlockHeaderError::Truncated { needed: 2, .. }));
    }

    #[test]
    fn rejects_bad_checksum() {
        let flags = build_flags(0, 1, false, false);
        let buf = vec![
            flags,
            block_prologue_checksum(flags, 0x01) ^ 0x01, // corrupt checksum
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
    fn rejects_byte_count_above_three() {
        // Wire `byte_count_minus_1 = 3` → byte_count = 4.
        // libarchive's `parse_block_header` caps at 3 size bytes;
        // we surface the rejection precisely.
        let flags: u8 = 0b0001_1000; // byte_count_minus_1 = 3 (bits 5..3)
        let buf = vec![flags, 0x00, 0x00, 0x00, 0x00, 0x00];
        let err = parse_block_header(&buf).unwrap_err();
        assert!(matches!(
            err,
            BlockHeaderError::UnsupportedByteCount { got: 4 }
        ));
    }

    #[test]
    fn checksum_formula_matches_libarchive() {
        // libarchive: cksum = 0x5A ^ flags ^ size[0] ^ size[1] ^ size[2].
        for flags in 0u8..=255u8 {
            for s0 in [0u8, 0x18, 0xCD, 0xFF] {
                for s1 in [0u8, 0x10, 0xAA] {
                    let xor = s0 ^ s1;
                    assert_eq!(
                        block_prologue_checksum(flags, xor),
                        0x5A ^ flags ^ xor,
                        "flags={flags:#04x} s0={s0:#04x} s1={s1:#04x}",
                    );
                }
            }
        }
    }

    #[test]
    fn matches_libarchive_solid_archive_prologue() {
        // Bytes lifted verbatim from `testfile.rar5.solid.rar`'s
        // first block prologue (offset 0x3E in the archive). flags
        // = 0xC6 (bit_size=6, byte_count=1, is_last=true,
        // is_table_present=true), block_size byte = 0x18 (24).
        // libarchive's expected checksum is
        // `0x5A ^ 0xC6 ^ 0x18 = 0x84` — proves the §E1 fix
        // covers the "first byte of size XOR'd into the cksum" arm.
        let buf = [0xC6, 0x84, 0x18];
        let hdr = parse_block_header(&buf).expect("solid prologue parses");
        assert_eq!(hdr.bit_size, 6);
        assert_eq!(hdr.byte_count, 1);
        assert!(hdr.is_last_block);
        assert!(hdr.is_table_present);
        assert_eq!(hdr.block_size, 0x18);
    }

    #[test]
    fn round_trips_every_bit_size_and_byte_count_combination() {
        for bit_size in 0u8..=7 {
            for byte_count in 1u8..=3 {
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
