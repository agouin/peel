//! Zstandard block-level parsing (RFC 8478 §3.1.1.2).
//!
//! Pure logic over `&[u8]`s — no IO. The [`super::Decoder`] is
//! responsible for assembling the bytes and threading the
//! sliding-window writes; this module only knows the wire format.
//!
//! The block layer has three concerns in Phase 1:
//!
//! - Parse the 3-byte block header into
//!   `(last_block, block_type, block_size)`.
//! - Apply `Raw_Block` (verbatim copy) and `RLE_Block` (1-byte
//!   payload, repeated `block_size` times).
//! - Reject `Compressed_Block` with a deliberate "not yet
//!   implemented" placeholder per
//!   `internal/PLAN_zstd_block_decoder.md` §Phase 1; the literals +
//!   sequences stack lands in Phases 3-5.
//!
//! # Spec gotcha worth highlighting (RFC 8478 §3.1.1.2.2)
//!
//! For [`BlockType::Rle`], the `block_size` field is the
//! **regenerated** size — i.e. the number of times the single
//! payload byte repeats — and the on-wire payload is **always
//! exactly 1 byte**. For [`BlockType::Raw`] and
//! [`BlockType::Compressed`], `block_size` is the on-wire payload
//! length. A reader who fixes the parser to "always advance by
//! `block_size`" silently corrupts every multi-block frame
//! containing an RLE block. The Phase 0 spike's [Appendix A]
//! caught this; tests below pin the asymmetry.
//!
//! [Appendix A]: ../../../../internal/PLAN_zstd_block_decoder.md

use super::error::ZstdError;

/// Length of the 3-byte block header on the wire.
pub const BLOCK_HEADER_LEN: usize = 3;

/// RFC 8478 §3.1.1.2 block-size cap: 128 KiB. Independent of the
/// frame's `Window_Size`; a frame with a smaller window will tighten
/// this cap further, which the decoder enforces at the frame layer.
pub const BLOCK_MAX_SIZE: u32 = 128 * 1024;

/// Block-type tag from a parsed block header.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BlockType {
    /// Verbatim payload of `block_size` bytes copied straight to
    /// the output (and the sliding window).
    Raw,
    /// A single payload byte repeated `block_size` times. The
    /// on-wire payload is always 1 byte regardless of
    /// `block_size`.
    Rle,
    /// A compressed block whose body contains a literals section
    /// and a sequences section. Round-one returns
    /// [`ZstdError::CompressedBlockUnimplemented`] for this
    /// variant; Phases 3-5 fill it in.
    Compressed,
}

/// A parsed block header.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BlockHeader {
    /// `true` when this block's `Last_Block` flag is set,
    /// meaning the next block starts a new frame (or the stream
    /// is at end-of-frame).
    pub last_block: bool,
    /// Tag identifying the block body's encoding.
    pub block_type: BlockType,
    /// For `Raw`/`Compressed`: bytes of payload to consume from
    /// the stream. For `Rle`: number of times the (always 1-byte)
    /// payload repeats in the regenerated output. See module
    /// docs for the asymmetry.
    pub block_size: u32,
}

impl BlockHeader {
    /// Number of source bytes the on-wire payload occupies after
    /// the 3-byte block header.
    ///
    /// For `Rle`, this is always 1 regardless of [`Self::block_size`].
    /// For `Raw` and `Compressed`, this is [`Self::block_size`].
    #[must_use]
    pub fn payload_on_wire(&self) -> u32 {
        match self.block_type {
            BlockType::Rle => 1,
            BlockType::Raw | BlockType::Compressed => self.block_size,
        }
    }
}

/// Parse a 3-byte block header from the start of `input`.
///
/// # Errors
///
/// - [`ZstdError::UnexpectedEof`] when `input` is shorter than
///   [`BLOCK_HEADER_LEN`].
/// - [`ZstdError::ReservedBlockType`] when the type field is `3`
///   (the reserved value).
/// - [`ZstdError::BlockTooLarge`] when `block_size` exceeds
///   [`BLOCK_MAX_SIZE`].
pub fn parse_block_header(input: &[u8]) -> Result<BlockHeader, ZstdError> {
    if input.len() < BLOCK_HEADER_LEN {
        return Err(ZstdError::UnexpectedEof("block header"));
    }
    // Header is little-endian 24 bits:
    //   bit 0      : Last_Block
    //   bits 1-2   : Block_Type
    //   bits 3-23  : Block_Size
    let h = u32::from(input[0]) | (u32::from(input[1]) << 8) | (u32::from(input[2]) << 16);
    let last_block = (h & 1) == 1;
    let block_type = match (h >> 1) & 0b11 {
        0 => BlockType::Raw,
        1 => BlockType::Rle,
        2 => BlockType::Compressed,
        3 => return Err(ZstdError::ReservedBlockType),
        // INVARIANT: `(h >> 1) & 0b11` is in 0..=3; the four arms
        // above are exhaustive.
        _ => unreachable!("block_type is 0..=3 by construction"),
    };
    let block_size = h >> 3;
    if block_size > BLOCK_MAX_SIZE {
        return Err(ZstdError::BlockTooLarge {
            size: block_size,
            cap: BLOCK_MAX_SIZE,
        });
    }
    Ok(BlockHeader {
        last_block,
        block_type,
        block_size,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: pack a `(last, type, size)` triple back into the
    /// 3-byte wire form so test setup mirrors the RFC bit layout
    /// exactly. Symmetric to [`parse_block_header`] for sanity.
    fn pack(last: bool, ty: u32, size: u32) -> [u8; 3] {
        let h = u32::from(last) | (ty << 1) | (size << 3);
        [
            (h & 0xFF) as u8,
            ((h >> 8) & 0xFF) as u8,
            ((h >> 16) & 0xFF) as u8,
        ]
    }

    #[test]
    fn parse_raw_block_header() {
        let bytes = pack(false, 0, 4);
        let hdr = parse_block_header(&bytes).expect("parse");
        assert!(!hdr.last_block);
        assert_eq!(hdr.block_type, BlockType::Raw);
        assert_eq!(hdr.block_size, 4);
        assert_eq!(hdr.payload_on_wire(), 4);
    }

    #[test]
    fn parse_rle_block_header_payload_is_one_byte() {
        let bytes = pack(true, 1, 1024);
        let hdr = parse_block_header(&bytes).expect("parse");
        assert!(hdr.last_block);
        assert_eq!(hdr.block_type, BlockType::Rle);
        // Regenerated size is 1024, but the on-wire payload is 1 byte.
        assert_eq!(hdr.block_size, 1024);
        assert_eq!(hdr.payload_on_wire(), 1);
    }

    #[test]
    fn parse_compressed_block_header() {
        let bytes = pack(false, 2, 256);
        let hdr = parse_block_header(&bytes).expect("parse");
        assert_eq!(hdr.block_type, BlockType::Compressed);
        assert_eq!(hdr.payload_on_wire(), 256);
    }

    #[test]
    fn parse_rejects_reserved_type() {
        let bytes = pack(false, 3, 0);
        assert!(matches!(
            parse_block_header(&bytes),
            Err(ZstdError::ReservedBlockType)
        ));
    }

    #[test]
    fn parse_rejects_block_size_above_cap() {
        let bytes = pack(false, 0, BLOCK_MAX_SIZE + 1);
        match parse_block_header(&bytes) {
            Err(ZstdError::BlockTooLarge { size, cap }) => {
                assert_eq!(size, BLOCK_MAX_SIZE + 1);
                assert_eq!(cap, BLOCK_MAX_SIZE);
            }
            other => panic!("expected BlockTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn parse_at_block_size_cap_succeeds() {
        let bytes = pack(false, 0, BLOCK_MAX_SIZE);
        let hdr = parse_block_header(&bytes).expect("at-cap is valid");
        assert_eq!(hdr.block_size, BLOCK_MAX_SIZE);
    }

    #[test]
    fn parse_rejects_truncated() {
        for take in 0..BLOCK_HEADER_LEN {
            let buf = vec![0u8; take];
            assert!(matches!(
                parse_block_header(&buf),
                Err(ZstdError::UnexpectedEof(_))
            ));
        }
    }

    /// Last-block flag round-trips at both extremes of the size
    /// field, so the bit-layout decode isn't fooled by carry.
    #[test]
    fn last_block_flag_round_trips_at_size_extremes() {
        for last in [false, true] {
            for size in [0u32, 1, BLOCK_MAX_SIZE] {
                let bytes = pack(last, 0, size);
                let hdr = parse_block_header(&bytes).expect("parse");
                assert_eq!(hdr.last_block, last, "size={size} last={last}");
                assert_eq!(hdr.block_size, size);
            }
        }
    }
}
