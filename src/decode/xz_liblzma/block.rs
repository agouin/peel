//! Block-layer parsing for the .xz file format.
//!
//! Pure logic over `&[u8]` — no IO. The [`super::Decoder`] is
//! responsible for assembling the bytes and threading the
//! sliding-window writes; this module only knows the wire format.
//!
//! Three concerns in Phase 1:
//!
//! - Parse the variable-length Block Header (.xz spec §3.1):
//!   `Block_Header_Size`, `Block_Flags`, optional
//!   `Compressed_Size` / `Uncompressed_Size` varints, the filter
//!   chain, header padding, and the trailing CRC32.
//! - Validate the filter chain holds exactly one LZMA2 filter
//!   (filter ID `0x21`) with a 1-byte properties field encoding a
//!   dictionary size ≤ 64 MiB. BCJ pre-filters and `dict_size > 64
//!   MiB` are out of scope per
//!   `docs/PLAN_xz_block_decoder.md` §Scope.
//! - Parse the LZMA2 chunk control byte at the head of the
//!   compressed payload. Phase 1 understands uncompressed-with-reset
//!   (`0x01`), uncompressed-no-reset (`0x02`), and end-of-stream
//!   (`0x00`); LZMA chunks (control bytes `0x80..=0xFF`) surface
//!   [`XzError::LzmaChunkUnimplemented`] until Phase 4.

use super::stream::{crc32, read_multibyte, DICT_SIZE_CAP};
use super::xz_error::XzError;

/// Filter ID for LZMA2 (the only filter Phase 1 accepts).
pub const LZMA2_FILTER_ID: u64 = 0x21;

/// Smallest possible Block_Header_Size byte value.
///
/// `0x00` is the Index Indicator (handled by the Stream layer);
/// real Block Headers store `(real_size / 4) - 1` here, so the
/// smallest legal value is `0x01` (a 4 + 4 = 8-byte header — the
/// minimum being 1 byte size + 1 byte flags + 1 byte filter ID +
/// 1 byte props size + 1 byte props + padding + 4 byte CRC; rounds
/// up to 16 bytes in practice).
pub const MIN_BLOCK_HEADER_SIZE_BYTE: u8 = 0x01;

/// Largest possible Block_Header_Size byte value (`0xFF`), giving
/// a 1024-byte Block Header.
pub const MAX_BLOCK_HEADER_SIZE_BYTE: u8 = 0xFF;

/// Convert a raw `Block_Header_Size` byte to the real header
/// length in bytes. Real length = `(stored + 1) * 4`.
///
/// Caller is responsible for separating `0x00` (the Index
/// Indicator) before calling this — passing `0x00` here yields a
/// nonsensical 4-byte length. The decoder catches the indicator
/// case at the dispatch site.
#[must_use]
pub const fn block_header_real_size(stored: u8) -> usize {
    (stored as usize + 1) * 4
}

/// A parsed Block Header.
///
/// Captures only the fields the Phase 1 decoder needs: the
/// declared sizes (when present), the LZMA2 dictionary size, and
/// the on-wire header length so the caller can advance past
/// padding + CRC. Filter-chain validation has already happened
/// at parse time.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BlockHeader {
    /// Declared on-wire size of the LZMA2 stream that follows the
    /// Block Header — does **not** include Block Padding or the
    /// trailing Check. `None` if the encoder omitted the field.
    pub compressed_size: Option<u64>,
    /// Declared decompressed size of this Block. `None` if the
    /// encoder omitted the field.
    pub uncompressed_size: Option<u64>,
    /// LZMA2 dictionary size in bytes (≤ [`DICT_SIZE_CAP`]).
    /// Decoded from the single LZMA2 properties byte.
    pub dict_size: u32,
    /// Total on-wire length of this Block Header, including the
    /// `Block_Header_Size` byte and the trailing 4-byte CRC.
    pub header_size_bytes: usize,
}

/// Parse a Block Header given the entire on-wire header bytes.
///
/// `input` must be exactly [`block_header_real_size`] bytes long
/// (the caller has already pulled that many bytes after seeing
/// the leading `Block_Header_Size` byte).
///
/// # Errors
///
/// - [`XzError::InvalidBlockHeaderSize`] if the size byte is
///   `0x00` (the caller should have routed Index Indicators to
///   the Stream-layer parser).
/// - [`XzError::MalformedBlockHeader`] for reserved-bit
///   violations, oversize length fields, or padding-not-zero.
/// - [`XzError::UnsupportedFilterChain`] for any chain other
///   than `[LZMA2]`.
/// - [`XzError::DictTooLarge`] if the LZMA2 dict_size exceeds
///   [`DICT_SIZE_CAP`].
/// - [`XzError::ReservedDictEncoding`] if the dictionary encoding
///   byte exceeds the spec's 0..=40 range.
/// - [`XzError::BlockHeaderCrcMismatch`] if the trailing CRC32
///   doesn't match.
pub fn parse_block_header(input: &[u8]) -> Result<BlockHeader, XzError> {
    if input.is_empty() {
        return Err(XzError::UnexpectedEof("Block Header"));
    }
    let size_byte = input[0];
    if size_byte == 0x00 {
        return Err(XzError::InvalidBlockHeaderSize(0x00));
    }
    let real_size = block_header_real_size(size_byte);
    if input.len() < real_size {
        return Err(XzError::UnexpectedEof("Block Header"));
    }
    if input.len() != real_size {
        return Err(XzError::MalformedBlockHeader(
            "input length doesn't match Block_Header_Size",
        ));
    }

    let crc_stored = u32::from_le_bytes([
        input[real_size - 4],
        input[real_size - 3],
        input[real_size - 2],
        input[real_size - 1],
    ]);
    let crc_computed = crc32(&input[..real_size - 4]);
    if crc_stored != crc_computed {
        return Err(XzError::BlockHeaderCrcMismatch {
            expected: crc_stored,
            got: crc_computed,
        });
    }

    // Bytes that hold the parsed fields (everything after the
    // size byte and before the CRC32 trailer + padding).
    let body = &input[1..real_size - 4];
    let mut cursor = 0usize;

    if body.is_empty() {
        return Err(XzError::MalformedBlockHeader(
            "no Block_Flags byte after size",
        ));
    }
    let flags = body[cursor];
    cursor += 1;

    // Block_Flags layout (.xz spec §3.1.2):
    //   bits 0-1 : Number_of_Filters - 1   (so 0..=3 means 1..=4)
    //   bits 2-5 : Reserved (must be zero)
    //   bit  6   : Compressed_Size present
    //   bit  7   : Uncompressed_Size present
    if flags & 0b0011_1100 != 0 {
        return Err(XzError::MalformedBlockHeader(
            "reserved Block_Flags bits set",
        ));
    }
    let num_filters = (flags & 0b11) + 1;
    let has_compressed_size = flags & 0b0100_0000 != 0;
    let has_uncompressed_size = flags & 0b1000_0000 != 0;

    let compressed_size = if has_compressed_size {
        let (v, n) = read_multibyte(&body[cursor..])?;
        cursor += n;
        Some(v)
    } else {
        None
    };
    let uncompressed_size = if has_uncompressed_size {
        let (v, n) = read_multibyte(&body[cursor..])?;
        cursor += n;
        Some(v)
    } else {
        None
    };

    if num_filters != 1 {
        return Err(XzError::UnsupportedFilterChain(
            "round-one accepts a single LZMA2 filter only",
        ));
    }
    let (filter_id, n) = read_multibyte(&body[cursor..])?;
    cursor += n;
    if filter_id != LZMA2_FILTER_ID {
        return Err(XzError::UnsupportedFilterChain(
            "non-LZMA2 filter ID (BCJ pre-filters are out of round-one scope)",
        ));
    }
    let (props_size, n) = read_multibyte(&body[cursor..])?;
    cursor += n;
    if props_size != 1 {
        return Err(XzError::UnsupportedFilterChain(
            "LZMA2 filter properties must be exactly 1 byte",
        ));
    }
    if cursor >= body.len() {
        return Err(XzError::UnexpectedEof("LZMA2 filter properties"));
    }
    let dict_encoded = body[cursor];
    cursor += 1;
    let dict_size = decode_dict_size(dict_encoded)?;
    if u64::from(dict_size) > DICT_SIZE_CAP {
        return Err(XzError::DictTooLarge {
            dict_size: u64::from(dict_size),
            cap: DICT_SIZE_CAP,
        });
    }

    // Whatever remains in `body` must be Header Padding (zero
    // bytes). The .xz spec mandates the encoder zero-pad to fill
    // the declared `Block_Header_Size`; non-zero padding is a
    // hard error.
    for &b in &body[cursor..] {
        if b != 0x00 {
            return Err(XzError::MalformedBlockHeader(
                "non-zero Header Padding byte",
            ));
        }
    }

    Ok(BlockHeader {
        compressed_size,
        uncompressed_size,
        dict_size,
        header_size_bytes: real_size,
    })
}

/// Decode an LZMA2 dictionary-size byte (.xz spec §5.3.1).
///
/// Encoded values 0..=39 expand to dict sizes via
/// `(2 | (e & 1)) << ((e / 2) + 11)` (so even encodings give a
/// power-of-two dict, odd encodings give 1.5× a power-of-two).
/// `40` is a special-case alias for `u32::MAX` (4 GiB - 1).
/// Anything beyond `40` is reserved and surfaces a clean error.
pub fn decode_dict_size(encoded: u8) -> Result<u32, XzError> {
    match encoded {
        e @ 0..=39 => {
            // Maximum legitimate shift count: (39/2) + 11 = 30, so
            // the result fits in u32.
            let base = 2u32 | u32::from(e & 1);
            Ok(base << ((u32::from(e) / 2) + 11))
        }
        40 => Ok(u32::MAX),
        other => Err(XzError::ReservedDictEncoding(other)),
    }
}

/// LZMA2 chunk header parsed from the stream's control byte and
/// any following length / properties bytes.
///
/// Phase 1 decodes only the three "structural" variants — the
/// LZMA-payload variant is a placeholder that surfaces
/// [`XzError::LzmaChunkUnimplemented`] when actually decoded; we
/// still parse its header so multi-chunk validation lines up
/// once Phase 4 fills the inner decoder in.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Lzma2ChunkHeader {
    /// `0x00` — final chunk in the LZMA2 stream. No payload.
    EndOfStream,
    /// `0x01` / `0x02` — uncompressed chunk. The decoder copies
    /// the next `uncompressed_size` source bytes verbatim into
    /// the dictionary and the sink.
    Uncompressed {
        /// `true` for `0x01` (the LZMA2 dictionary must be
        /// reinitialized before this chunk).
        reset_dict: bool,
        /// 1..=65536. Decoded from the 16-bit BE length field
        /// that follows the control byte (spec stores `size - 1`).
        uncompressed_size: u32,
    },
    /// `0x80..=0xFF` — LZMA-compressed chunk.
    Lzma {
        /// `true` if the LZMA state machine must be reset to
        /// initial probabilities before this chunk.
        reset_state: bool,
        /// `true` if the chunk carries a fresh 1-byte LZMA
        /// properties field (lc/lp/pb), implying a state reset
        /// too.
        reset_props: bool,
        /// `true` if the LZMA2 dictionary must be reinitialized
        /// before this chunk (implies state + props reset too).
        reset_dict: bool,
        /// 1..=2^21. Decoded from the 5 low bits of the control
        /// byte and the 16-bit BE length field that follows.
        uncompressed_size: u32,
        /// 1..=65536. Decoded from the 16-bit BE length field
        /// that follows `uncompressed_size`.
        compressed_size: u32,
        /// LZMA properties byte (encoding `(pb, lp, lc)`). `Some`
        /// only when `reset_props` is set; otherwise the chunk
        /// inherits the previous chunk's properties.
        properties: Option<u8>,
    },
}

impl Lzma2ChunkHeader {
    /// Number of source bytes the chunk header itself occupies on
    /// the wire (excluding the LZMA properties byte and the
    /// payload). Useful so callers can advance past the header
    /// without re-deriving the length from the variant.
    #[must_use]
    pub const fn wire_size(self) -> usize {
        match self {
            Lzma2ChunkHeader::EndOfStream => 1,
            Lzma2ChunkHeader::Uncompressed { .. } => 3,
            Lzma2ChunkHeader::Lzma { reset_props, .. } => {
                if reset_props {
                    6
                } else {
                    5
                }
            }
        }
    }

    /// `true` if this chunk type forces an LZMA2 dictionary
    /// reset. The first chunk in a Block must be one of these.
    #[must_use]
    pub const fn resets_dict(self) -> bool {
        match self {
            Lzma2ChunkHeader::EndOfStream => false,
            Lzma2ChunkHeader::Uncompressed { reset_dict, .. } => reset_dict,
            Lzma2ChunkHeader::Lzma { reset_dict, .. } => reset_dict,
        }
    }
}

/// Parse an LZMA2 chunk header from the start of `input`.
///
/// Returns the parsed variant.
///
/// # Errors
///
/// - [`XzError::UnexpectedEof`] if `input` is shorter than the
///   variant's [`Lzma2ChunkHeader::wire_size`].
/// - [`XzError::ReservedLzma2Control`] for control bytes in
///   `0x03..=0x7F`.
pub fn parse_lzma2_chunk_header(input: &[u8]) -> Result<Lzma2ChunkHeader, XzError> {
    if input.is_empty() {
        return Err(XzError::UnexpectedEof("LZMA2 chunk control byte"));
    }
    let ctl = input[0];
    match ctl {
        0x00 => Ok(Lzma2ChunkHeader::EndOfStream),
        0x01 | 0x02 => {
            if input.len() < 3 {
                return Err(XzError::UnexpectedEof("LZMA2 uncompressed chunk header"));
            }
            // 16-bit BE length field stores (size - 1), so the
            // decoded size is in 1..=65536.
            let raw = (u32::from(input[1]) << 8) | u32::from(input[2]);
            let uncompressed_size = raw + 1;
            Ok(Lzma2ChunkHeader::Uncompressed {
                reset_dict: ctl == 0x01,
                uncompressed_size,
            })
        }
        0x03..=0x7F => Err(XzError::ReservedLzma2Control(ctl)),
        // 0x80..=0xFF — LZMA-compressed chunk. Bit layout
        // (LZMA2 spec):
        //   bits 7-5 : reset mode
        //              0b100 = no reset
        //              0b101 = reset state (props/dict kept)
        //              0b110 = reset state + new props (dict kept)
        //              0b111 = reset state + new props + dict
        //   bits 4-0 : high 5 bits of (uncompressed_size - 1).
        //              The next 2 bytes (BE) carry the low 16 bits.
        // After uncompressed_size: 16-bit BE compressed_size - 1.
        // If reset_props, one LZMA properties byte; else not.
        0x80..=0xFF => {
            let mode = (ctl >> 5) & 0b011;
            let reset_state = mode >= 1;
            let reset_props = mode >= 2;
            let reset_dict = mode == 3;
            let need = if reset_props { 6 } else { 5 };
            if input.len() < need {
                return Err(XzError::UnexpectedEof("LZMA2 LZMA chunk header"));
            }
            let high_5 = u32::from(ctl & 0b0001_1111);
            let low_16 = (u32::from(input[1]) << 8) | u32::from(input[2]);
            let uncompressed_size = ((high_5 << 16) | low_16) + 1;
            let comp_low_16 = (u32::from(input[3]) << 8) | u32::from(input[4]);
            let compressed_size = comp_low_16 + 1;
            let properties = if reset_props { Some(input[5]) } else { None };
            Ok(Lzma2ChunkHeader::Lzma {
                reset_state,
                reset_props,
                reset_dict,
                uncompressed_size,
                compressed_size,
                properties,
            })
        }
    }
}

/// Decode an LZMA properties byte into `(lc, lp, pb)`.
///
/// The encoding is `(pb * 5 + lp) * 9 + lc`, with `lc + lp ≤ 4`,
/// `lc ≤ 8`, `lp ≤ 4`, `pb ≤ 4` enforced by the spec. The legal
/// raw range is `0..=224`; bytes ≥ 225 are reserved.
///
/// # Errors
///
/// - [`XzError::LzmaInvalidProperties`] if `byte >= 225`.
/// - [`XzError::LzmaLcLpTooLarge`] if the decoded `lc + lp > 4`.
///   Round-one rejects this per
///   `docs/PLAN_xz_block_decoder.md` §Scope.
pub fn decode_lzma_properties(byte: u8) -> Result<(u8, u8, u8), XzError> {
    if byte >= 9 * 5 * 5 {
        return Err(XzError::LzmaInvalidProperties(byte));
    }
    let pb = byte / 45;
    let p = byte % 45;
    let lp = p / 9;
    let lc = p % 9;
    if u32::from(lc) + u32::from(lp) > 4 {
        return Err(XzError::LzmaLcLpTooLarge(u32::from(lc) + u32::from(lp)));
    }
    Ok((lc, lp, pb))
}

#[cfg(test)]
mod tests {
    use super::super::stream::{write_multibyte, CheckId};
    use super::*;

    /// Build a Block Header that declares `[LZMA2 dict=encoded]`,
    /// optional `compressed_size` / `uncompressed_size`, and
    /// auto-pads + auto-CRCs to a valid wire form.
    fn build_block_header(comp: Option<u64>, uncomp: Option<u64>, dict_encoded: u8) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        let mut flags: u8 = 0; // num_filters=1 -> raw bits 0..=1 = 0
        if comp.is_some() {
            flags |= 0b0100_0000;
        }
        if uncomp.is_some() {
            flags |= 0b1000_0000;
        }
        body.push(flags);
        if let Some(v) = comp {
            write_multibyte(v, &mut body);
        }
        if let Some(v) = uncomp {
            write_multibyte(v, &mut body);
        }
        write_multibyte(LZMA2_FILTER_ID, &mut body); // 0x21
        write_multibyte(1, &mut body); // properties size
        body.push(dict_encoded);

        // Pick the smallest legal Block_Header_Size that fits
        // body + size byte + 4 byte CRC, rounded up to mult of 4.
        let total_unpadded = body.len() + 1 + 4;
        let total = (total_unpadded + 3) & !3;
        let pad = total - total_unpadded;
        body.resize(body.len() + pad, 0x00);
        let stored = ((total / 4) - 1) as u8;
        let mut full = Vec::with_capacity(total);
        full.push(stored);
        full.extend_from_slice(&body);
        let crc = crc32(&full);
        full.extend_from_slice(&crc.to_le_bytes());
        full
    }

    /// Round-trip a Block Header that declares both sizes and a
    /// 256 KiB dictionary (encoded value `12`, matching what
    /// `xz --lzma2=preset=0` emits on `printf 'hello'`).
    #[test]
    fn block_header_round_trip_typical_xz() {
        let bytes = build_block_header(Some(9), Some(5), 12);
        let parsed = parse_block_header(&bytes).expect("parse");
        assert_eq!(parsed.compressed_size, Some(9));
        assert_eq!(parsed.uncompressed_size, Some(5));
        assert_eq!(parsed.dict_size, 256 * 1024);
        assert_eq!(parsed.header_size_bytes, bytes.len());
    }

    /// A header with no declared sizes still parses cleanly.
    #[test]
    fn block_header_round_trip_no_sizes() {
        let bytes = build_block_header(None, None, 0);
        let parsed = parse_block_header(&bytes).expect("parse");
        assert!(parsed.compressed_size.is_none());
        assert!(parsed.uncompressed_size.is_none());
        // dict_encoded == 0 -> 4 KiB
        assert_eq!(parsed.dict_size, 4096);
    }

    #[test]
    fn block_header_rejects_bad_crc() {
        let mut bytes = build_block_header(Some(9), Some(5), 12);
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        assert!(matches!(
            parse_block_header(&bytes),
            Err(XzError::BlockHeaderCrcMismatch { .. })
        ));
    }

    #[test]
    fn block_header_rejects_reserved_flag_bits() {
        let mut bytes = build_block_header(Some(9), Some(5), 12);
        // Set a reserved bit in Block_Flags (byte 1).
        bytes[1] |= 0b0000_0100;
        // Recompute CRC so the reserved-bit check fires before
        // the CRC check.
        let n = bytes.len();
        let crc = crc32(&bytes[..n - 4]);
        bytes[n - 4..].copy_from_slice(&crc.to_le_bytes());
        assert!(matches!(
            parse_block_header(&bytes),
            Err(XzError::MalformedBlockHeader(_))
        ));
    }

    #[test]
    fn block_header_rejects_size_byte_zero() {
        // 0x00 = Index Indicator, must be routed by the Stream
        // layer, never seen here.
        let bytes = [0x00u8, 0x00, 0x00, 0x00];
        assert!(matches!(
            parse_block_header(&bytes),
            Err(XzError::InvalidBlockHeaderSize(0x00))
        ));
    }

    #[test]
    fn block_header_rejects_non_lzma2_filter() {
        let mut body: Vec<u8> = vec![0u8]; // flags
        write_multibyte(0x03, &mut body); // some other filter (delta = 0x03)
        write_multibyte(1, &mut body);
        body.push(0x00);
        let total_unpadded = body.len() + 1 + 4;
        let total = (total_unpadded + 3) & !3;
        let pad = total - total_unpadded;
        body.resize(body.len() + pad, 0x00);
        let stored = ((total / 4) - 1) as u8;
        let mut full = Vec::with_capacity(total);
        full.push(stored);
        full.extend_from_slice(&body);
        let crc = crc32(&full);
        full.extend_from_slice(&crc.to_le_bytes());
        assert!(matches!(
            parse_block_header(&full),
            Err(XzError::UnsupportedFilterChain(_))
        ));
    }

    #[test]
    fn block_header_rejects_multi_filter_chain() {
        // num_filters = 2 (raw 0b01)
        let mut body: Vec<u8> = vec![0b0000_0001];
        write_multibyte(LZMA2_FILTER_ID, &mut body);
        write_multibyte(1, &mut body);
        body.push(0x00);
        // Add a second filter to make wire-shape consistent.
        write_multibyte(0x03, &mut body);
        write_multibyte(0, &mut body);
        let total_unpadded = body.len() + 1 + 4;
        let total = (total_unpadded + 3) & !3;
        let pad = total - total_unpadded;
        body.resize(body.len() + pad, 0x00);
        let stored = ((total / 4) - 1) as u8;
        let mut full = Vec::with_capacity(total);
        full.push(stored);
        full.extend_from_slice(&body);
        let crc = crc32(&full);
        full.extend_from_slice(&crc.to_le_bytes());
        assert!(matches!(
            parse_block_header(&full),
            Err(XzError::UnsupportedFilterChain(_))
        ));
    }

    #[test]
    fn block_header_rejects_dict_above_cap() {
        // encoded 29 -> dict_size = (3) << 25 = 96 MiB > 64 MiB cap.
        let bytes = build_block_header(None, None, 29);
        match parse_block_header(&bytes) {
            Err(XzError::DictTooLarge { dict_size, cap }) => {
                assert_eq!(dict_size, 96 * 1024 * 1024);
                assert_eq!(cap, DICT_SIZE_CAP);
            }
            other => panic!("expected DictTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn block_header_accepts_dict_exactly_at_cap() {
        // encoded 28 -> 64 MiB exactly.
        let bytes = build_block_header(None, None, 28);
        let parsed = parse_block_header(&bytes).expect("parse");
        assert_eq!(parsed.dict_size as u64, DICT_SIZE_CAP);
    }

    #[test]
    fn block_header_rejects_reserved_dict_encoding() {
        let bytes = build_block_header(None, None, 41);
        assert!(matches!(
            parse_block_header(&bytes),
            Err(XzError::DictTooLarge { .. } | XzError::ReservedDictEncoding(_))
        ));
        // Force a definitely-reserved encoding (255) and verify
        // we get the reserved variant.
        let bytes = build_block_header(None, None, 255);
        match parse_block_header(&bytes) {
            Err(XzError::ReservedDictEncoding(255)) => {}
            other => panic!("expected ReservedDictEncoding(255), got {other:?}"),
        }
    }

    #[test]
    fn block_header_rejects_non_zero_padding() {
        let mut bytes = build_block_header(Some(9), Some(5), 12);
        // Find a padding byte (it sits between the LZMA2 props
        // byte and the CRC32 trailer). The simplest valid
        // mutation: flip the byte just before the CRC32 to 0xFF.
        let n = bytes.len();
        bytes[n - 5] = 0xFF;
        // Recompute CRC so the padding check fires before the
        // CRC check.
        let crc = crc32(&bytes[..n - 4]);
        bytes[n - 4..].copy_from_slice(&crc.to_le_bytes());
        match parse_block_header(&bytes) {
            Err(XzError::MalformedBlockHeader(msg)) => {
                assert!(msg.contains("Padding"), "unexpected msg: {msg}");
            }
            other => panic!("expected MalformedBlockHeader, got {other:?}"),
        }
    }

    #[test]
    fn dict_size_table_known_values() {
        // Spot-check a few values from the .xz spec table.
        assert_eq!(decode_dict_size(0).expect("0"), 4 * 1024); // 4 KiB
        assert_eq!(decode_dict_size(1).expect("1"), 6 * 1024); // 6 KiB
        assert_eq!(decode_dict_size(12).expect("12"), 256 * 1024); // 256 KiB
        assert_eq!(decode_dict_size(28).expect("28"), 64 * 1024 * 1024); // 64 MiB
        assert_eq!(decode_dict_size(40).expect("40"), u32::MAX); // 4 GiB - 1
        assert!(matches!(
            decode_dict_size(41),
            Err(XzError::ReservedDictEncoding(41))
        ));
    }

    #[test]
    fn lzma2_eos_chunk_header() {
        let buf = [0x00];
        let parsed = parse_lzma2_chunk_header(&buf).expect("parse");
        assert_eq!(parsed, Lzma2ChunkHeader::EndOfStream);
        assert_eq!(parsed.wire_size(), 1);
        assert!(!parsed.resets_dict());
    }

    #[test]
    fn lzma2_uncompressed_with_reset() {
        // size - 1 = 4 (BE 0x00 0x04) -> size = 5
        let buf = [0x01u8, 0x00, 0x04];
        let parsed = parse_lzma2_chunk_header(&buf).expect("parse");
        assert_eq!(
            parsed,
            Lzma2ChunkHeader::Uncompressed {
                reset_dict: true,
                uncompressed_size: 5,
            }
        );
        assert_eq!(parsed.wire_size(), 3);
        assert!(parsed.resets_dict());
    }

    #[test]
    fn lzma2_uncompressed_no_reset() {
        let buf = [0x02u8, 0xFF, 0xFF]; // size - 1 = 65535 -> 65536
        let parsed = parse_lzma2_chunk_header(&buf).expect("parse");
        assert_eq!(
            parsed,
            Lzma2ChunkHeader::Uncompressed {
                reset_dict: false,
                uncompressed_size: 65_536,
            }
        );
        assert!(!parsed.resets_dict());
    }

    #[test]
    fn lzma2_rejects_reserved_control() {
        for ctl in [0x03u8, 0x40, 0x7F] {
            assert!(matches!(
                parse_lzma2_chunk_header(&[ctl]),
                Err(XzError::ReservedLzma2Control(_))
            ));
        }
    }

    #[test]
    fn lzma2_lzma_chunk_header_full_reset() {
        // 0xE0 = 0b1110_0000 -> mode 0b11 (full reset), high 5
        // bits of size = 0. Size: 0..=2^21.
        let buf = [0xE0u8, 0x00, 0x00, 0x00, 0x00, 0x40];
        let parsed = parse_lzma2_chunk_header(&buf).expect("parse");
        match parsed {
            Lzma2ChunkHeader::Lzma {
                reset_state,
                reset_props,
                reset_dict,
                uncompressed_size,
                compressed_size,
                properties,
            } => {
                assert!(reset_state);
                assert!(reset_props);
                assert!(reset_dict);
                assert_eq!(uncompressed_size, 1);
                assert_eq!(compressed_size, 1);
                assert_eq!(properties, Some(0x40));
            }
            other => panic!("expected Lzma, got {other:?}"),
        }
        assert_eq!(parsed.wire_size(), 6);
        assert!(parsed.resets_dict());
    }

    #[test]
    fn lzma2_lzma_chunk_header_state_no_props() {
        // 0xA0 = 0b1010_0000 -> mode 0b01 (state reset only)
        let buf = [0xA0u8, 0x00, 0x00, 0x00, 0x00];
        let parsed = parse_lzma2_chunk_header(&buf).expect("parse");
        match parsed {
            Lzma2ChunkHeader::Lzma {
                reset_state,
                reset_props,
                reset_dict,
                ..
            } => {
                assert!(reset_state);
                assert!(!reset_props);
                assert!(!reset_dict);
            }
            other => panic!("expected Lzma, got {other:?}"),
        }
        // wire_size == 5 because no props byte follows.
        assert_eq!(parsed.wire_size(), 5);
    }

    #[test]
    fn lzma2_chunk_header_truncated() {
        // Uncompressed needs 3 bytes
        assert!(matches!(
            parse_lzma2_chunk_header(&[0x01u8, 0x00]),
            Err(XzError::UnexpectedEof(_))
        ));
        // LZMA needs 5 (no props) or 6 (props) bytes
        assert!(matches!(
            parse_lzma2_chunk_header(&[0xA0u8, 0x00, 0x00, 0x00]),
            Err(XzError::UnexpectedEof(_))
        ));
        assert!(matches!(
            parse_lzma2_chunk_header(&[0xE0u8, 0x00, 0x00, 0x00, 0x00]),
            Err(XzError::UnexpectedEof(_))
        ));
    }

    /// Pin: dict_size == 256 KiB matches the value `xz` emits at
    /// preset 0 on a tiny payload (the `printf 'hello' | xz
    /// --lzma2=preset=0` fixture in the spike memo). Catches a
    /// future regression in the (e/2 + 11) shift formula.
    #[test]
    fn dict_size_matches_xz_preset_0_default() {
        // The xz CLI at preset=0 emits LZMA2 props byte 0x0C.
        assert_eq!(decode_dict_size(0x0C).expect("12"), 256 * 1024);
    }

    /// Sanity: every CheckId.size() value matches the spec's
    /// table — pin against a pasted list rather than the impl.
    #[test]
    fn check_id_sizes_pin() {
        assert_eq!(CheckId::None.size(), 0);
        assert_eq!(CheckId::Crc32.size(), 4);
        assert_eq!(CheckId::Crc64.size(), 8);
        assert_eq!(CheckId::Sha256.size(), 32);
    }

    /// `decode_lzma_properties` round-trip across the spec's
    /// representative `(lc, lp, pb)` triples. Default xz preset
    /// (`lc=3, lp=0, pb=2`) encodes as `0x5D` (= 2*45 + 0*9 + 3).
    #[test]
    fn lzma_properties_decode_default_and_corners() {
        assert_eq!(decode_lzma_properties(0x5D).expect("default"), (3, 0, 2));
        assert_eq!(decode_lzma_properties(0).expect("zero"), (0, 0, 0));
        // Maximum legal triple at the lc+lp ≤ 4 ceiling.
        // pb=4, lp=0, lc=4 -> 4*45 + 4 = 184.
        assert_eq!(decode_lzma_properties(184).expect("hi"), (4, 0, 4));
    }

    /// Properties byte ≥ 225 is reserved.
    #[test]
    fn lzma_properties_rejects_reserved() {
        match decode_lzma_properties(225).unwrap_err() {
            XzError::LzmaInvalidProperties(b) => assert_eq!(b, 225),
            other => panic!("expected LzmaInvalidProperties, got {other:?}"),
        }
    }

    /// `lc + lp > 4` rejected at decode time so the LZMA2 chunk
    /// dispatcher doesn't allocate a multi-MiB literal table.
    #[test]
    fn lzma_properties_rejects_lc_lp_over_four() {
        // pb=0, lp=3, lc=2 -> 0 + 3*9 + 2 = 29; lc+lp=5.
        match decode_lzma_properties(29).unwrap_err() {
            XzError::LzmaLcLpTooLarge(s) => assert_eq!(s, 5),
            other => panic!("expected LzmaLcLpTooLarge, got {other:?}"),
        }
    }
}
