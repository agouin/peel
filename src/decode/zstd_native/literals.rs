//! Literals section of a `Compressed_Block` (RFC 8478 §3.1.1.3 +
//! §4.2).
//!
//! A literals section sits at the start of every Compressed_Block
//! and carries the raw-byte literals that the sequences section
//! later interleaves with back-references into a single output
//! stream. Four section flavours exist:
//!
//! | Type           | Wire payload                                |
//! |----------------|---------------------------------------------|
//! | Raw_Literals   | `regenerated_size` opaque bytes             |
//! | RLE_Literals   | 1 opaque byte, repeated `regenerated_size` |
//! | Compressed_Literals  | Huffman tree description + 1/4 Huffman streams |
//! | Treeless_Literals    | 1/4 Huffman streams only (reuse prior tree) |
//!
//! Phase 3 implements all four section types end-to-end, with two
//! caveats per `docs/PLAN_zstd_block_decoder.md`:
//!
//! - **FSE-coded Huffman weight descriptions** (RFC 8478 §4.2.1.2)
//!   return [`ZstdError::UnsupportedFrameFeature`] until Phase 4.
//!   Real-world `zstd -3` output uses these for any block with
//!   more than ~a-handful of unique bytes; the direct-encoding
//!   path covers small alphabets and our hand-built test
//!   fixtures.
//! - **Block_Maximum_Decompressed_Size** is the same 128 KiB cap
//!   the block layer enforces (RFC §3.1.1.2). Literals
//!   regenerated_size is also bounded by this.

use super::bitstream::ReverseBitReader;
use super::error::ZstdError;
use super::huffman::{parse_direct_weights, parse_fse_weights, HuffmanTree};

/// Block-type tag from a literals header (RFC 8478 §3.1.1.3,
/// 2 bits at the LSB of the first header byte).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LiteralsBlockType {
    /// Verbatim bytes in the literals section.
    Raw,
    /// One byte repeated.
    Rle,
    /// Huffman-encoded literals; section starts with a tree
    /// description.
    Compressed,
    /// Huffman-encoded literals; section reuses the tree from a
    /// preceding Compressed_Literals_Block in the same frame.
    Treeless,
}

/// Parsed literals-section header.
///
/// `header_size` is the number of bytes the header itself occupies
/// (1 to 5). `payload_size` is the number of bytes in the section
/// **after** the header — for Raw it's `regenerated_size`, for RLE
/// it's `1`, for Compressed/Treeless it's the encoded
/// `compressed_size`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct LiteralsHeader {
    /// Block-type tag.
    pub block_type: LiteralsBlockType,
    /// Number of decompressed literal bytes the section produces.
    pub regenerated_size: u32,
    /// Bytes occupied by the header itself.
    pub header_size: u8,
    /// Bytes the section's payload occupies on the wire (after
    /// the header).
    pub payload_size: u32,
    /// `true` when the Huffman bitstream is split into 4
    /// independent sub-streams; `false` when single-stream. Always
    /// `false` for Raw/RLE.
    pub four_stream: bool,
}

/// Parse a literals-section header from the start of `bytes`.
///
/// # Errors
///
/// - [`ZstdError::UnexpectedEof`] when `bytes` is shorter than the
///   structurally-required prefix.
pub fn parse_literals_header(bytes: &[u8]) -> Result<LiteralsHeader, ZstdError> {
    if bytes.is_empty() {
        return Err(ZstdError::UnexpectedEof("literals header"));
    }
    let b0 = bytes[0];
    let block_type = match b0 & 0b11 {
        0 => LiteralsBlockType::Raw,
        1 => LiteralsBlockType::Rle,
        2 => LiteralsBlockType::Compressed,
        3 => LiteralsBlockType::Treeless,
        // INVARIANT: `b0 & 0b11` is in 0..=3.
        _ => unreachable!("literals block type is 0..=3"),
    };
    let size_format = (b0 >> 2) & 0b11;

    match block_type {
        LiteralsBlockType::Raw | LiteralsBlockType::Rle => {
            // Raw/RLE: size_format encodes only regenerated_size.
            // SF=0 and SF=2 are equivalent (5-bit single-byte header).
            let (regen, header_size): (u32, u8) = match size_format {
                0 | 2 => (u32::from(b0 >> 3), 1),
                1 => {
                    if bytes.len() < 2 {
                        return Err(ZstdError::UnexpectedEof("literals header (12-bit regen)"));
                    }
                    let regen = (u32::from(b0) >> 4) | (u32::from(bytes[1]) << 4);
                    (regen, 2)
                }
                3 => {
                    if bytes.len() < 3 {
                        return Err(ZstdError::UnexpectedEof("literals header (20-bit regen)"));
                    }
                    let regen = (u32::from(b0) >> 4)
                        | (u32::from(bytes[1]) << 4)
                        | (u32::from(bytes[2]) << 12);
                    (regen, 3)
                }
                // INVARIANT: size_format is 2 bits.
                _ => unreachable!("size_format is 0..=3"),
            };
            let payload_size = match block_type {
                LiteralsBlockType::Raw => regen,
                LiteralsBlockType::Rle => 1,
                _ => unreachable!(),
            };
            Ok(LiteralsHeader {
                block_type,
                regenerated_size: regen,
                header_size,
                payload_size,
                four_stream: false,
            })
        }
        LiteralsBlockType::Compressed | LiteralsBlockType::Treeless => {
            // Compressed/Treeless: size_format encodes both
            // regen_size and comp_size, plus single-vs-4-stream.
            // SF=0 -> 1-stream, 10b regen, 10b comp, 3-byte header.
            // SF=1 -> 4-stream, 10b regen, 10b comp, 3-byte header.
            // SF=2 -> 4-stream, 14b regen, 14b comp, 4-byte header.
            // SF=3 -> 4-stream, 18b regen, 18b comp, 5-byte header.
            let (header_size, regen_bits): (u8, u32) = match size_format {
                0 | 1 => (3, 10),
                2 => (4, 14),
                3 => (5, 18),
                // INVARIANT: size_format is 2 bits.
                _ => unreachable!("size_format is 0..=3"),
            };
            if bytes.len() < usize::from(header_size) {
                return Err(ZstdError::UnexpectedEof("literals header (compressed)"));
            }
            // Pack the header bytes into a u64 LE so the variable
            // bit-field extraction is uniform.
            let mut packed: u64 = 0;
            for (i, &byte) in bytes.iter().take(usize::from(header_size)).enumerate() {
                packed |= u64::from(byte) << (i * 8);
            }
            // Bits 0-3 = block_type + size_format (already consumed).
            // Bits 4..(4+regen_bits) = regenerated_size.
            // Bits (4+regen_bits)..(4+2*regen_bits) = compressed_size.
            let mask = (1u64 << regen_bits) - 1;
            let regen = ((packed >> 4) & mask) as u32;
            let comp = ((packed >> (4 + regen_bits)) & mask) as u32;
            let four_stream = size_format != 0;
            Ok(LiteralsHeader {
                block_type,
                regenerated_size: regen,
                header_size,
                payload_size: comp,
                four_stream,
            })
        }
    }
}

/// Decode a literals section's payload into the regenerated
/// literal bytes.
///
/// `payload` must begin at the byte immediately after the header
/// (so its length is exactly [`LiteralsHeader::payload_size`]
/// bytes). `prev_huffman` is the slot the decoder reuses across
/// successive Compressed/Treeless blocks within one frame: a
/// Compressed_Literals_Block writes a freshly-built tree into it,
/// and a Treeless_Literals_Block reads it.
///
/// # Errors
///
/// Mirrors [`parse_literals_header`] for header-level issues and
/// adds:
///
/// - [`ZstdError::UnsupportedFrameFeature`] when the Huffman
///   weight description uses the FSE-coded encoding (deferred to
///   Phase 4).
/// - [`ZstdError::MalformedFrameHeader`] when a Treeless block
///   references a tree that hasn't been seen yet, or when the
///   payload's size doesn't match what the streams consume.
pub fn decode_literals(
    header: &LiteralsHeader,
    payload: &[u8],
    prev_huffman: &mut Option<HuffmanTree>,
) -> Result<Vec<u8>, ZstdError> {
    if payload.len() != header.payload_size as usize {
        return Err(ZstdError::MalformedFrameHeader(
            "literals payload size mismatch",
        ));
    }
    match header.block_type {
        LiteralsBlockType::Raw => Ok(payload.to_vec()),
        LiteralsBlockType::Rle => {
            // RLE literals: 1 byte repeated regenerated_size times.
            if payload.len() != 1 {
                return Err(ZstdError::MalformedFrameHeader(
                    "RLE literals payload must be 1 byte",
                ));
            }
            Ok(vec![payload[0]; header.regenerated_size as usize])
        }
        LiteralsBlockType::Compressed => {
            // Tree description + Huffman streams.
            let (tree, consumed) = parse_tree_description(payload)?;
            let streams = &payload[consumed..];
            let out = decode_huffman_streams(
                streams,
                header.regenerated_size,
                header.four_stream,
                &tree,
            )?;
            *prev_huffman = Some(tree);
            Ok(out)
        }
        LiteralsBlockType::Treeless => {
            let tree = prev_huffman
                .as_ref()
                .ok_or(ZstdError::MalformedFrameHeader(
                    "Treeless_Literals_Block before any Compressed_Literals_Block",
                ))?;
            decode_huffman_streams(payload, header.regenerated_size, header.four_stream, tree)
        }
    }
}

/// Parse a Huffman tree description (RFC 8478 §4.2.1) from the
/// start of `bytes`. Returns the tree and the number of bytes
/// consumed.
///
/// # Errors
///
/// - [`ZstdError::UnexpectedEof`] when `bytes` is shorter than the
///   description's structural minimum.
/// - [`ZstdError::UnsupportedFrameFeature`] when the description
///   uses FSE-coded weights (Phase 4).
fn parse_tree_description(bytes: &[u8]) -> Result<(HuffmanTree, usize), ZstdError> {
    if bytes.is_empty() {
        return Err(ZstdError::UnexpectedEof("Huffman tree description"));
    }
    let header_byte = bytes[0];
    if header_byte < 128 {
        // FSE-coded weights (RFC §4.2.1.2). Phase 4b.
        let (weights, consumed) = parse_fse_weights(bytes)?;
        let tree = HuffmanTree::from_direct_weights(&weights)?;
        return Ok((tree, consumed));
    }
    // Direct encoding: header_byte - 127 = total number of
    // symbols, with the last weight implicit. Number of weights
    // explicitly on the wire is therefore `total - 1`.
    let n_symbols_total = u32::from(header_byte - 127);
    if n_symbols_total < 2 {
        return Err(ZstdError::MalformedFrameHeader(
            "Huffman direct encoding: need at least 2 symbols",
        ));
    }
    let n_explicit = (n_symbols_total - 1) as usize;
    let (weights, weight_bytes) = parse_direct_weights(&bytes[1..], n_explicit)?;
    let tree = HuffmanTree::from_direct_weights(&weights)?;
    Ok((tree, 1 + weight_bytes))
}

/// Decode 1- or 4-stream Huffman literals from `streams` into a
/// `regenerated_size`-byte buffer.
///
/// 4-stream framing (RFC 8478 §3.1.1.3.1.5): the first 6 bytes of
/// `streams` form a jump table of three little-endian u16s giving
/// the sizes of streams 1, 2, and 3. Stream 4's size is the
/// remainder of `streams` after the jump table and the first three
/// streams.
fn decode_huffman_streams(
    streams: &[u8],
    regenerated_size: u32,
    four_stream: bool,
    tree: &HuffmanTree,
) -> Result<Vec<u8>, ZstdError> {
    let mut out = Vec::with_capacity(regenerated_size as usize);
    if four_stream {
        if streams.len() < 6 {
            return Err(ZstdError::UnexpectedEof("4-stream jump table"));
        }
        let s1 = u16::from_le_bytes([streams[0], streams[1]]) as usize;
        let s2 = u16::from_le_bytes([streams[2], streams[3]]) as usize;
        let s3 = u16::from_le_bytes([streams[4], streams[5]]) as usize;
        let body = &streams[6..];
        let header_total = s1.checked_add(s2).and_then(|x| x.checked_add(s3));
        let Some(header_total) = header_total else {
            return Err(ZstdError::MalformedFrameHeader(
                "4-stream jump-table size overflow",
            ));
        };
        if body.len() < header_total {
            return Err(ZstdError::UnexpectedEof("4-stream payload"));
        }
        let s4 = body.len() - header_total;
        let stream_lens = [s1, s2, s3, s4];
        // Each of the 4 streams produces ceil(regenerated_size / 4)
        // bytes, except the last which absorbs the remainder.
        let per = (regenerated_size as usize).div_ceil(4);
        let stream_outputs: [usize; 4] = [
            per,
            per,
            per,
            (regenerated_size as usize).saturating_sub(per * 3),
        ];
        let mut cursor = 0usize;
        for i in 0..4 {
            let len = stream_lens[i];
            let stream = &body[cursor..cursor + len];
            cursor += len;
            decode_one_huffman_stream(stream, stream_outputs[i], tree, &mut out)?;
        }
    } else {
        decode_one_huffman_stream(streams, regenerated_size as usize, tree, &mut out)?;
    }
    if out.len() != regenerated_size as usize {
        return Err(ZstdError::MalformedFrameHeader(
            "Huffman literals: regenerated size mismatch",
        ));
    }
    Ok(out)
}

/// Decode one Huffman-coded reverse bitstream into `expected_bytes`
/// literal bytes, appending them to `out`.
fn decode_one_huffman_stream(
    stream: &[u8],
    expected_bytes: usize,
    tree: &HuffmanTree,
    out: &mut Vec<u8>,
) -> Result<(), ZstdError> {
    let mut br = ReverseBitReader::new(stream)?;
    for _ in 0..expected_bytes {
        let sym = tree.decode(&mut br)?;
        out.push(sym);
    }
    // Trailing bits beyond what `expected_bytes` consumed are
    // either zero padding or a partial code that the encoder
    // truncated; either way we don't care, but we sanity-check
    // that the stream isn't *under*-consumed by an entire byte
    // (which would mean we miscounted).
    if br.bits_remaining() >= 8 {
        return Err(ZstdError::MalformedFrameHeader(
            "Huffman literals stream over-long",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_raw_5bit_size() {
        // RFC 8478 §3.1.1.3.1.1 Format 0 (SF=00 or 10): Size_Format
        // uses *1 bit*, Regenerated_Size uses 5 bits starting at
        // bit 3. So byte layout:
        //   bits 0..1 = type (00 = Raw)
        //   bit  2    = SF low bit (0)
        //   bits 3..7 = 5-bit regen
        // For regen=10: byte = (10 << 3) | (0 << 2) | 0 = 80 = 0x50.
        let bytes = [0x50];
        let h = parse_literals_header(&bytes).expect("parse");
        assert_eq!(h.block_type, LiteralsBlockType::Raw);
        assert_eq!(h.regenerated_size, 10);
        assert_eq!(h.header_size, 1);
        assert_eq!(h.payload_size, 10);
        assert!(!h.four_stream);
    }

    #[test]
    fn parse_raw_12bit_size() {
        // Format 1 (SF=01): 12-bit regen at bits 4..15. Field-fits
        // value (12-bit max is 4095). Use 0xABC = 2748.
        //   byte 0: type=00, SF=01, low 4 of regen at bits 4..7 = 0xC
        //   byte 1: high 8 of regen = 0xAB
        let regen: u16 = 0xABC;
        let byte0 = 0b0000_0100 | ((regen as u8 & 0xF) << 4);
        let byte1 = (regen >> 4) as u8;
        let bytes = [byte0, byte1];
        let h = parse_literals_header(&bytes).expect("parse");
        assert_eq!(h.regenerated_size, u32::from(regen));
        assert_eq!(h.header_size, 2);
    }

    #[test]
    fn parse_raw_20bit_size() {
        // Format 2 (SF=11): 20-bit regen at bits 4..23. 20-bit max
        // = 0xFFFFF; we use 0xABCDE.
        let regen: u32 = 0xABCDE;
        let byte0 = 0b0000_1100 | ((regen as u8 & 0xF) << 4);
        let byte1 = ((regen >> 4) & 0xFF) as u8;
        let byte2 = ((regen >> 12) & 0xFF) as u8;
        let bytes = [byte0, byte1, byte2];
        let h = parse_literals_header(&bytes).expect("parse");
        assert_eq!(h.regenerated_size, regen);
        assert_eq!(h.header_size, 3);
    }

    #[test]
    fn parse_rle_payload_is_one_byte() {
        // RLE, SF=00 (Format 0), regen=8. Same 5-bit layout as Raw.
        //   byte = (8 << 3) | (0 << 2) | 0b01 = 64 | 1 = 0x41.
        let bytes = [0x41];
        let h = parse_literals_header(&bytes).expect("parse");
        assert_eq!(h.block_type, LiteralsBlockType::Rle);
        assert_eq!(h.regenerated_size, 8);
        // RLE payload on the wire is always 1 byte.
        assert_eq!(h.payload_size, 1);
    }

    #[test]
    fn parse_compressed_sf0_single_stream() {
        // Type=Compressed (10), SF=0, regen=N, comp=M, 3-byte header,
        // 10-bit fields each.
        let regen: u32 = 100;
        let comp: u32 = 50;
        // Bits (LSB-first packed): 2(type) + 2(SF=0) + 10(regen) + 10(comp) = 24 bits.
        let packed: u64 = 0b10 | (u64::from(regen) << 4) | (u64::from(comp) << 14);
        let bytes = [packed as u8, (packed >> 8) as u8, (packed >> 16) as u8];
        let h = parse_literals_header(&bytes).expect("parse");
        assert_eq!(h.block_type, LiteralsBlockType::Compressed);
        assert_eq!(h.regenerated_size, regen);
        assert_eq!(h.payload_size, comp);
        assert!(!h.four_stream);
        assert_eq!(h.header_size, 3);
    }

    #[test]
    fn parse_compressed_sf1_four_streams() {
        // Type=Compressed, SF=1 -> 4-stream, 10-bit fields, 3-byte header.
        let packed: u64 = 0b10 | (0b01 << 2) | (200u64 << 4) | (75u64 << 14);
        let bytes = [packed as u8, (packed >> 8) as u8, (packed >> 16) as u8];
        let h = parse_literals_header(&bytes).expect("parse");
        assert!(h.four_stream);
        assert_eq!(h.regenerated_size, 200);
        assert_eq!(h.payload_size, 75);
    }

    #[test]
    fn parse_compressed_sf2_14bit_fields() {
        // Type=Compressed, SF=2 -> 4-byte header, 14-bit fields.
        let regen: u32 = 5000;
        let comp: u32 = 1234;
        let packed: u64 = 0b10 | (0b10 << 2) | (u64::from(regen) << 4) | (u64::from(comp) << 18);
        let bytes = [
            packed as u8,
            (packed >> 8) as u8,
            (packed >> 16) as u8,
            (packed >> 24) as u8,
        ];
        let h = parse_literals_header(&bytes).expect("parse");
        assert_eq!(h.regenerated_size, regen);
        assert_eq!(h.payload_size, comp);
        assert!(h.four_stream);
        assert_eq!(h.header_size, 4);
    }

    #[test]
    fn parse_compressed_sf3_18bit_fields() {
        // Type=Compressed, SF=3 -> 5-byte header, 18-bit fields.
        let regen: u32 = 100_000;
        let comp: u32 = 75_000;
        let packed: u64 = 0b10 | (0b11 << 2) | (u64::from(regen) << 4) | (u64::from(comp) << 22);
        let bytes = [
            packed as u8,
            (packed >> 8) as u8,
            (packed >> 16) as u8,
            (packed >> 24) as u8,
            (packed >> 32) as u8,
        ];
        let h = parse_literals_header(&bytes).expect("parse");
        assert_eq!(h.regenerated_size, regen);
        assert_eq!(h.payload_size, comp);
        assert!(h.four_stream);
        assert_eq!(h.header_size, 5);
    }

    #[test]
    fn parse_treeless_uses_compressed_layout() {
        // Type=Treeless (11), SF=0, 3-byte header.
        let packed: u64 = 0b11 | (300u64 << 4) | (100u64 << 14);
        let bytes = [packed as u8, (packed >> 8) as u8, (packed >> 16) as u8];
        let h = parse_literals_header(&bytes).expect("parse");
        assert_eq!(h.block_type, LiteralsBlockType::Treeless);
    }

    #[test]
    fn decode_raw_round_trips() {
        let h = LiteralsHeader {
            block_type: LiteralsBlockType::Raw,
            regenerated_size: 5,
            header_size: 1,
            payload_size: 5,
            four_stream: false,
        };
        let mut prev = None;
        let out = decode_literals(&h, b"hello", &mut prev).expect("decode");
        assert_eq!(out, b"hello");
    }

    #[test]
    fn decode_rle_regenerates() {
        let h = LiteralsHeader {
            block_type: LiteralsBlockType::Rle,
            regenerated_size: 7,
            header_size: 1,
            payload_size: 1,
            four_stream: false,
        };
        let mut prev = None;
        let out = decode_literals(&h, b"Q", &mut prev).expect("decode");
        assert_eq!(out, b"QQQQQQQ");
    }

    #[test]
    fn decode_treeless_without_prev_huffman_errors() {
        let h = LiteralsHeader {
            block_type: LiteralsBlockType::Treeless,
            regenerated_size: 10,
            header_size: 3,
            payload_size: 5,
            four_stream: false,
        };
        let mut prev = None;
        let r = decode_literals(&h, &[0u8; 5], &mut prev);
        assert!(matches!(r, Err(ZstdError::MalformedFrameHeader(_))));
    }

    #[test]
    fn decode_compressed_truncated_fse_weights_errors_cleanly() {
        // Tree description header_byte < 128 means FSE-coded
        // weights — Phase 4b lights this up. Here we ensure a
        // *malformed* FSE-coded weight description (header
        // declares 50 bytes but only 2 are present) surfaces
        // as a typed error rather than a panic.
        let h = LiteralsHeader {
            block_type: LiteralsBlockType::Compressed,
            regenerated_size: 1,
            header_size: 3,
            payload_size: 3,
            four_stream: false,
        };
        let payload = [50u8, 0xAA, 0xBB];
        let mut prev = None;
        match decode_literals(&h, &payload, &mut prev) {
            Err(ZstdError::UnexpectedEof(_)) | Err(ZstdError::MalformedFrameHeader(_)) => {}
            other => panic!("expected typed error, got {other:?}"),
        }
    }

    /// End-to-end: Compressed_Literals with direct-encoded weights.
    /// We hand-build the smallest possible one-stream block.
    #[test]
    fn decode_compressed_direct_weights_one_stream() {
        // Tree: 3 symbols (sym 0 weight 2, sym 1 weight 1, sym 2 weight 1).
        //   header_byte = 127 + 3 = 130
        //   explicit weights on wire: [2, 1] (the implicit is 1)
        //   direct-weight bytes: 1 byte (high nibble 2, low nibble 1) = 0x21.
        //
        // Code map: sym 0 -> '0' (1b), sym 1 -> '10' (2b), sym 2 -> '11' (2b).
        // Encode literal sequence: 0, 1, 2 -> bits MSB-first: 0  10  11 = 5 bits.
        //
        // Reverse bitstream layout (one byte):
        //   bit 7 (MSB): 0  (zero pad above sentinel)
        //   bit 6      : 1  (sentinel)
        //   bit 5      : 0  (sym 0)
        //   bit 4      : 1  (sym 1, top)
        //   bit 3      : 0  (sym 1, bottom)
        //   bit 2      : 1  (sym 2, top)
        //   bit 1      : 1  (sym 2, bottom)
        //   bit 0      : 0  (trailing pad)
        // = 0b0_1_0_1_0_1_1_0 = 0x56
        //
        // Payload = [tree desc header, weight bytes, stream byte]
        //         = [130, 0x21, 0x56] = 3 bytes total.
        let payload = [130u8, 0x21, 0x56];
        let h = LiteralsHeader {
            block_type: LiteralsBlockType::Compressed,
            regenerated_size: 3,
            header_size: 3,
            payload_size: payload.len() as u32,
            four_stream: false,
        };
        let mut prev = None;
        let out = decode_literals(&h, &payload, &mut prev).expect("decode");
        assert_eq!(out, vec![0u8, 1, 2]);
        // The fresh tree must be parked in `prev` for any
        // following Treeless block in this frame.
        assert!(prev.is_some());
    }

    /// Treeless literals reuse the previous tree.
    #[test]
    fn decode_treeless_reuses_prev_huffman() {
        // Build the same 3-symbol tree as
        // `decode_compressed_direct_weights_one_stream`. Then run a
        // Treeless block whose stream alone (no tree desc) decodes
        // to the same sequence.
        let tree = HuffmanTree::from_direct_weights(&[2, 1, 1]).expect("build");
        let mut prev = Some(tree);
        let h = LiteralsHeader {
            block_type: LiteralsBlockType::Treeless,
            regenerated_size: 3,
            header_size: 3,
            payload_size: 1,
            four_stream: false,
        };
        let out = decode_literals(&h, &[0x56], &mut prev).expect("decode");
        assert_eq!(out, vec![0u8, 1, 2]);
    }

    #[test]
    fn decode_payload_size_mismatch_errors() {
        let h = LiteralsHeader {
            block_type: LiteralsBlockType::Raw,
            regenerated_size: 5,
            header_size: 1,
            payload_size: 5,
            four_stream: false,
        };
        let mut prev = None;
        let r = decode_literals(&h, b"hello!", &mut prev);
        assert!(matches!(r, Err(ZstdError::MalformedFrameHeader(_))));
    }
}
