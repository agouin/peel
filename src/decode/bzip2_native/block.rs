//! Bzip2 per-block framing: 48-bit marker (`0x314159265359` /
//! `0x177245385090`) and the pre-Huffman block header (block CRC,
//! randomised flag, BWT origin pointer, "symbols used" bitmap).
//!
//! `internal/PLAN_bz2_support.md` Phase 2.

use super::bitstream::BitReader;
use super::error::Bzip2Error;

/// 48-bit magic that precedes every compressed block:
/// `pi = 3.14159265359` packed BCD.
pub const BLOCK_START_MAGIC: u64 = 0x3141_5926_5359;

/// 48-bit magic that ends a bzip2 stream:
/// `sqrt(pi) = 1.77245385090` packed BCD.
pub const STREAM_END_MAGIC: u64 = 0x1772_4538_5090;

/// Result of reading the 48-bit block marker.
///
/// Bzip2 streams alternate between compressed blocks (each preceded
/// by [`BLOCK_START_MAGIC`]) and end-of-stream markers
/// ([`STREAM_END_MAGIC`]). The block-magic loop in the decoder
/// dispatches on which one came next.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BlockMarker {
    /// Compressed block follows.
    BlockStart,
    /// End of stream. The 32-bit combined stream CRC follows.
    StreamEnd,
}

/// Read the 48-bit block marker at the current bit cursor.
///
/// # Errors
///
/// - [`Bzip2Error::BadBlockMarker`] if the 48 bits match neither
///   magic.
/// - [`Bzip2Error::UnexpectedEof`] on truncation.
pub fn parse_block_marker(br: &mut BitReader) -> Result<BlockMarker, Bzip2Error> {
    let hi = br
        .read_bits(24)
        .map_err(|e| relabel_eof(e, "block-marker high 24 bits"))?;
    let lo = br
        .read_bits(24)
        .map_err(|e| relabel_eof(e, "block-marker low 24 bits"))?;
    let marker = (u64::from(hi) << 24) | u64::from(lo);
    match marker {
        BLOCK_START_MAGIC => Ok(BlockMarker::BlockStart),
        STREAM_END_MAGIC => Ok(BlockMarker::StreamEnd),
        _ => Err(Bzip2Error::BadBlockMarker { marker }),
    }
}

/// Pre-Huffman block-header fields parsed from the bit stream
/// immediately after [`BLOCK_START_MAGIC`].
#[derive(Debug, Clone)]
pub struct BlockHeader {
    /// 32-bit CRC of the pre-RLE1 byte stream (the input to the
    /// final RLE1 inverse). Validated by Phase 5 once the body
    /// decodes.
    pub block_crc: u32,
    /// BWT origin pointer — the row in the BWT-permuted matrix that
    /// holds the start of the original sequence. Range
    /// `0..block_len` after the body decodes; out-of-range values
    /// surface as [`Bzip2Error::OriginPointerOutOfRange`] in Phase
    /// 4 / 5.
    pub orig_ptr: u32,
    /// Bit-set of which of the 256 possible byte values appear in
    /// this block. Indexed `[0..256)`. Used to seed the per-block
    /// MTF table.
    pub symbols_used: [bool; 256],
}

impl BlockHeader {
    /// Number of distinct bytes present in this block — the
    /// alphabet size for the MTF inverse.
    #[must_use]
    pub fn num_symbols_used(&self) -> usize {
        self.symbols_used.iter().filter(|&&b| b).count()
    }
}

/// Parse the pre-Huffman block header (CRC + randomised flag +
/// origPtr + symbols-used bitmap) at the current bit cursor.
///
/// # Errors
///
/// - [`Bzip2Error::RandomisedBlock`] if the 1-bit `randomised`
///   field is set (legacy bzip 0.9.0; see `PLAN_bz2_support.md`
///   §Deferred).
/// - [`Bzip2Error::EmptySymbolSet`] if the bitmap declares no
///   used symbols.
/// - [`Bzip2Error::UnexpectedEof`] on truncation.
pub fn parse_block_header(br: &mut BitReader) -> Result<BlockHeader, Bzip2Error> {
    let block_crc = br.read_u32_be().map_err(|e| relabel_eof(e, "block CRC"))?;
    let randomised = br
        .read_bits(1)
        .map_err(|e| relabel_eof(e, "block randomised flag"))?;
    if randomised != 0 {
        return Err(Bzip2Error::RandomisedBlock);
    }
    let orig_ptr = br
        .read_bits(24)
        .map_err(|e| relabel_eof(e, "block origin pointer"))?;
    let symbols_used = parse_symbols_used(br)?;
    if !symbols_used.iter().any(|&b| b) {
        return Err(Bzip2Error::EmptySymbolSet);
    }
    Ok(BlockHeader {
        block_crc,
        orig_ptr,
        symbols_used,
    })
}

/// Parse the "symbols used" sparse-bitmap encoding. The bzip2
/// reference (`decompress.c:bzDecompressReadStateField`) treats the
/// 256 possible byte values as 16 rows of 16 symbols each: 16 bits
/// of row-presence are read first (bit `(15 - row)` set ⇒ row is
/// populated), then for each populated row a further 16 bits of
/// symbol-presence (bit `(15 - col)` set ⇒ symbol `row*16+col` is
/// used).
fn parse_symbols_used(br: &mut BitReader) -> Result<[bool; 256], Bzip2Error> {
    let row_map = br
        .read_bits(16)
        .map_err(|e| relabel_eof(e, "symbols-used row map"))?;
    let mut symbols_used = [false; 256];
    for row in 0..16u32 {
        // Bit `(15 - row)` of row_map names row `row`. MSB-first
        // numbering matches the bzip2 reference.
        let row_bit = 1u32 << (15 - row);
        if row_map & row_bit == 0 {
            continue;
        }
        let cols = br
            .read_bits(16)
            .map_err(|e| relabel_eof(e, "symbols-used column map"))?;
        for col in 0..16u32 {
            let col_bit = 1u32 << (15 - col);
            if cols & col_bit != 0 {
                // INVARIANT: row*16+col is in 0..256.
                symbols_used[(row * 16 + col) as usize] = true;
            }
        }
    }
    Ok(symbols_used)
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

    /// Build a 48-bit value into 6 big-endian bytes for fixture
    /// construction.
    fn u48_be(v: u64) -> Vec<u8> {
        vec![
            ((v >> 40) & 0xFF) as u8,
            ((v >> 32) & 0xFF) as u8,
            ((v >> 24) & 0xFF) as u8,
            ((v >> 16) & 0xFF) as u8,
            ((v >> 8) & 0xFF) as u8,
            (v & 0xFF) as u8,
        ]
    }

    #[test]
    fn block_start_magic_parses() {
        let mut r = br(u48_be(BLOCK_START_MAGIC));
        let marker = parse_block_marker(&mut r).expect("block start");
        assert_eq!(marker, BlockMarker::BlockStart);
    }

    #[test]
    fn stream_end_magic_parses() {
        let mut r = br(u48_be(STREAM_END_MAGIC));
        let marker = parse_block_marker(&mut r).expect("stream end");
        assert_eq!(marker, BlockMarker::StreamEnd);
    }

    #[test]
    fn unknown_marker_rejected() {
        let mut r = br(u48_be(0xDEAD_BEEF_CAFE));
        match parse_block_marker(&mut r) {
            Err(Bzip2Error::BadBlockMarker { marker }) => {
                assert_eq!(marker, 0xDEAD_BEEF_CAFE);
            }
            other => panic!("expected BadBlockMarker, got {other:?}"),
        }
    }

    #[test]
    fn marker_at_bit_offset_decodes_correctly() {
        // Stuff one leading bit so the marker starts at bit 1 of
        // byte 0; the framing parser must walk through it.
        let payload = u48_be(BLOCK_START_MAGIC);
        // Re-encode `1` followed by `payload` as a single bit stream,
        // MSB-first. The leading 1-bit goes into the top of byte 0;
        // each subsequent byte shifts in the next 8 bits of payload,
        // smeared across two source bytes.
        let mut stream = Vec::new();
        let mut acc: u64 = 1;
        let mut nbits: u32 = 1;
        for byte in payload {
            acc = (acc << 8) | u64::from(byte);
            nbits += 8;
            while nbits >= 8 {
                let shift = nbits - 8;
                let out = ((acc >> shift) & 0xFF) as u8;
                stream.push(out);
                acc &= (1u64 << shift) - 1;
                nbits = shift;
            }
        }
        // Flush any trailing bits with zero padding.
        if nbits > 0 {
            let out = ((acc << (8 - nbits)) & 0xFF) as u8;
            stream.push(out);
        }

        let mut r = br(stream);
        // Skip the leading 1-bit.
        assert_eq!(r.read_bits(1).expect("leading 1"), 1);
        let marker = parse_block_marker(&mut r).expect("marker after bit-offset");
        assert_eq!(marker, BlockMarker::BlockStart);
    }

    #[test]
    fn truncated_marker_surfaces_unexpected_eof() {
        let mut r = br(vec![0x31, 0x41]);
        match parse_block_marker(&mut r) {
            Err(Bzip2Error::UnexpectedEof(label)) => {
                assert_eq!(label, "block-marker high 24 bits");
            }
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    /// Hand-build a minimal pre-Huffman block header for testing:
    /// CRC=0x11223344, randomised=0, origPtr=0x000042, symbol set
    /// = {0x41}. Returned as the byte stream of the bits.
    fn minimal_block_header_bytes() -> Vec<u8> {
        // Bits in MSB-first order, fed through a bit-stream
        // serializer.
        let mut bits: Vec<bool> = Vec::new();

        fn push(bits: &mut Vec<bool>, v: u32, width: u32) {
            for i in (0..width).rev() {
                bits.push((v >> i) & 1 != 0);
            }
        }

        push(&mut bits, 0x1122_3344, 32); // block CRC
        push(&mut bits, 0, 1); // randomised flag = 0
        push(&mut bits, 0x42, 24); // origPtr
                                   // Symbols used: row 4 (covers 0x40..0x4F), column 1 → 0x41.
        let mut row_map: u32 = 0;
        row_map |= 1 << (15 - 4);
        push(&mut bits, row_map, 16);
        // Row 4's column map: column 1 set.
        let mut cols: u32 = 0;
        cols |= 1 << (15 - 1);
        push(&mut bits, cols, 16);

        // Pad to byte boundary.
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
    fn parse_block_header_recovers_crc_origptr_and_symbol_set() {
        let bytes = minimal_block_header_bytes();
        let mut r = br(bytes);
        let hdr = parse_block_header(&mut r).expect("header");
        assert_eq!(hdr.block_crc, 0x1122_3344);
        assert_eq!(hdr.orig_ptr, 0x42);
        assert!(hdr.symbols_used[0x41]);
        assert_eq!(hdr.num_symbols_used(), 1);
    }

    #[test]
    fn randomised_block_rejected() {
        // Same header shape but flip the randomised bit.
        let mut bits: Vec<bool> = Vec::new();
        fn push(bits: &mut Vec<bool>, v: u32, width: u32) {
            for i in (0..width).rev() {
                bits.push((v >> i) & 1 != 0);
            }
        }
        push(&mut bits, 0, 32);
        push(&mut bits, 1, 1); // randomised = 1
        push(&mut bits, 0, 24);
        push(&mut bits, 1 << 15, 16); // row 0 populated
        push(&mut bits, 1 << 15, 16); // column 0 populated → symbol 0
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

        let mut r = br(bytes);
        match parse_block_header(&mut r) {
            Err(Bzip2Error::RandomisedBlock) => {}
            other => panic!("expected RandomisedBlock, got {other:?}"),
        }
    }

    #[test]
    fn empty_symbol_set_rejected() {
        let mut bits: Vec<bool> = Vec::new();
        fn push(bits: &mut Vec<bool>, v: u32, width: u32) {
            for i in (0..width).rev() {
                bits.push((v >> i) & 1 != 0);
            }
        }
        push(&mut bits, 0, 32);
        push(&mut bits, 0, 1);
        push(&mut bits, 0, 24);
        push(&mut bits, 0, 16); // no rows populated
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

        let mut r = br(bytes);
        match parse_block_header(&mut r) {
            Err(Bzip2Error::EmptySymbolSet) => {}
            other => panic!("expected EmptySymbolSet, got {other:?}"),
        }
    }
}
