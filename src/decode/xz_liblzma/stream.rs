//! Stream-layer parsing for the .xz file format.
//!
//! Pure logic over `&[u8]` — no IO. The [`super::Decoder`] is
//! responsible for pulling bytes into an in-memory buffer before
//! calling into here.
//!
//! The Stream layer is what the .xz spec
//! ([tukaani.org/xz/xz-file-format.txt]) describes around the Block
//! list:
//!
//! ```text
//!   +-------------------+       6 + 2 + 4   = 12 bytes
//!   | Stream Header     |
//!   +-------------------+
//!   | Block 1           |
//!   | ...               |       (variable, parsed by `block.rs`)
//!   | Block N           |
//!   +-------------------+
//!   | Index             |       1 + varint + records + pad + 4
//!   +-------------------+
//!   | Stream Footer     |       4 + 4 + 2 + 2 = 12 bytes
//!   +-------------------+
//! ```
//!
//! This module also hosts the two cross-module utilities used by
//! both `stream.rs` and `block.rs`: the multibyte (varint) integer
//! reader from .xz spec §1.2, and a small CRC-32/ISO-HDLC helper
//! used by Stream Header, Stream Footer, Block Header, and Index
//! integrity checks. The CRC helper moves to `src/hash/crc32.rs` in
//! Phase 5 once the Block Check verification path needs to share it
//! with Stream-level callers; for now it stays private to
//! `xz_native`.
//!
//! [tukaani.org/xz/xz-file-format.txt]: https://tukaani.org/xz/xz-file-format.txt

use super::xz_error::XzError;

/// Stream Header magic: `0xFD '7' 'z' 'X' 'Z' 0x00`. The 6-byte
/// prefix that identifies an .xz stream on the wire.
pub const STREAM_HEADER_MAGIC: [u8; 6] = [0xFD, b'7', b'z', b'X', b'Z', 0x00];

/// Stream Footer magic: `'Y' 'Z'`. The 2-byte suffix that
/// terminates an .xz stream.
pub const STREAM_FOOTER_MAGIC: [u8; 2] = [b'Y', b'Z'];

/// Length of a Stream Header on the wire.
pub const STREAM_HEADER_LEN: usize = 12;

/// Length of a Stream Footer on the wire.
pub const STREAM_FOOTER_LEN: usize = 12;

/// Maximum length of a multibyte (varint) integer in bytes.
///
/// The .xz spec caps the encoding at 9 bytes (each byte carries
/// 7 data bits, so 9 bytes give 63 bits — values in `0..(1<<63)`
/// only). Encoders must use the shortest legal form; a multi-byte
/// encoding whose final byte is zero is non-canonical and rejected.
pub const MAX_MULTIBYTE_LEN: usize = 9;

/// Round-one cap on LZMA2 dictionary size (64 MiB), as bytes.
///
/// Larger dictionaries are rejected at Block Header parse time so
/// the resume blob in Phase 6 stays bounded — see
/// `docs/PLAN_xz_block_decoder.md` §Scope.
pub const DICT_SIZE_CAP: u64 = 64 * 1024 * 1024;

/// Stream Check IDs the round-one decoder recognises.
///
/// Anything else in the 4-bit `Check_Type` field is reserved (the
/// spec partitions `0x00..=0x0F` into "this list" and "reserved",
/// not "this list" and "user-defined"). [`super::Decoder`] surfaces
/// reserved IDs as [`XzError::ReservedCheckId`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CheckId {
    /// `0x00`: no Check follows the Block. Block Padding is the
    /// only trailer.
    None,
    /// `0x01`: 4-byte CRC32/ISO-HDLC over the decompressed Block
    /// payload.
    Crc32,
    /// `0x04`: 8-byte CRC64/ECMA-182-reflected over the decompressed
    /// Block payload. The default for `xz` CLI emits.
    Crc64,
    /// `0x0A`: 32-byte SHA-256 over the decompressed Block payload.
    Sha256,
}

impl CheckId {
    /// Number of bytes the Check field occupies after a Block's
    /// compressed payload + Block Padding.
    #[must_use]
    pub const fn size(self) -> usize {
        match self {
            CheckId::None => 0,
            CheckId::Crc32 => 4,
            CheckId::Crc64 => 8,
            CheckId::Sha256 => 32,
        }
    }

    /// 4-bit encoding of this Check ID as it appears in the Stream
    /// Flags low nibble.
    #[must_use]
    pub const fn raw(self) -> u8 {
        match self {
            CheckId::None => 0x00,
            CheckId::Crc32 => 0x01,
            CheckId::Crc64 => 0x04,
            CheckId::Sha256 => 0x0A,
        }
    }

    /// Decode a 4-bit Check ID from the low nibble of Stream Flags
    /// byte 1.
    ///
    /// # Errors
    ///
    /// Returns [`XzError::ReservedCheckId`] for any value not in
    /// `{0x00, 0x01, 0x04, 0x0A}`.
    pub fn from_raw(value: u8) -> Result<Self, XzError> {
        match value {
            0x00 => Ok(CheckId::None),
            0x01 => Ok(CheckId::Crc32),
            0x04 => Ok(CheckId::Crc64),
            0x0A => Ok(CheckId::Sha256),
            other => Err(XzError::ReservedCheckId(other)),
        }
    }
}

/// Parsed Stream Flags (the 2-byte field present in both Stream
/// Header and Stream Footer).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct StreamFlags {
    /// Identifies the integrity check that trails each Block in
    /// this Stream.
    pub check: CheckId,
}

impl StreamFlags {
    /// Pack this `StreamFlags` back into the 2 wire bytes for
    /// header/footer cross-compare and CRC computation.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 2] {
        [0x00, self.check.raw()]
    }

    /// 16-bit LE view of the Stream Flags wire bytes — only used
    /// in error messages so a caller can render the value
    /// numerically.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        let bytes = self.to_bytes();
        (bytes[0] as u16) | ((bytes[1] as u16) << 8)
    }
}

/// Parse a 12-byte Stream Header.
///
/// # Errors
///
/// - [`XzError::UnexpectedEof`] if `input` is shorter than
///   [`STREAM_HEADER_LEN`].
/// - [`XzError::BadStreamMagic`] if the leading 6 bytes don't
///   match [`STREAM_HEADER_MAGIC`].
/// - [`XzError::MalformedStreamFlags`] if the reserved byte or
///   nibble is non-zero.
/// - [`XzError::ReservedCheckId`] if the Check ID is reserved.
/// - [`XzError::StreamHeaderCrcMismatch`] if the trailing CRC32
///   doesn't match what we computed over the Stream Flags bytes.
pub fn parse_stream_header(input: &[u8]) -> Result<StreamFlags, XzError> {
    if input.len() < STREAM_HEADER_LEN {
        return Err(XzError::UnexpectedEof("Stream Header"));
    }
    if input[..6] != STREAM_HEADER_MAGIC {
        return Err(XzError::BadStreamMagic);
    }
    let flags_bytes = [input[6], input[7]];
    let flags = parse_stream_flags(flags_bytes)?;
    let crc_stored = u32::from_le_bytes([input[8], input[9], input[10], input[11]]);
    let crc_computed = crc32(&flags_bytes);
    if crc_stored != crc_computed {
        return Err(XzError::StreamHeaderCrcMismatch {
            expected: crc_stored,
            got: crc_computed,
        });
    }
    Ok(flags)
}

/// Parse a 12-byte Stream Footer and return the parsed flags plus
/// the *real-units* Backward Size (already multiplied by 4).
///
/// # Errors
///
/// - [`XzError::UnexpectedEof`] if `input` is shorter than
///   [`STREAM_FOOTER_LEN`].
/// - [`XzError::BadStreamFooterMagic`] if the trailing 2 bytes
///   aren't `'Y' 'Z'`.
/// - [`XzError::MalformedStreamFlags`] / [`XzError::ReservedCheckId`]
///   if the Stream Flags fail spec validation.
/// - [`XzError::StreamFooterCrcMismatch`] if the leading CRC32
///   doesn't match what we computed over Backward Size + Stream
///   Flags.
pub fn parse_stream_footer(input: &[u8]) -> Result<(StreamFlags, u64), XzError> {
    if input.len() < STREAM_FOOTER_LEN {
        return Err(XzError::UnexpectedEof("Stream Footer"));
    }
    if input[10..12] != STREAM_FOOTER_MAGIC {
        return Err(XzError::BadStreamFooterMagic);
    }
    let crc_stored = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    let backward_size_raw = u32::from_le_bytes([input[4], input[5], input[6], input[7]]) as u64;
    let flags_bytes = [input[8], input[9]];
    let flags = parse_stream_flags(flags_bytes)?;
    let crc_computed = crc32(&input[4..10]);
    if crc_stored != crc_computed {
        return Err(XzError::StreamFooterCrcMismatch {
            expected: crc_stored,
            got: crc_computed,
        });
    }
    // Real Backward Size in bytes = (stored + 1) * 4. Stored fits
    // in u32, so the product fits in u64 without overflow.
    let backward_size = (backward_size_raw + 1) * 4;
    Ok((flags, backward_size))
}

fn parse_stream_flags(bytes: [u8; 2]) -> Result<StreamFlags, XzError> {
    if bytes[0] != 0x00 {
        return Err(XzError::MalformedStreamFlags(
            "reserved high byte must be zero",
        ));
    }
    if bytes[1] & 0xF0 != 0 {
        return Err(XzError::MalformedStreamFlags(
            "reserved high nibble must be zero",
        ));
    }
    let check = CheckId::from_raw(bytes[1] & 0x0F)?;
    Ok(StreamFlags { check })
}

/// Read a multibyte (varint) integer from the start of `input`.
///
/// Returns the decoded value and how many bytes were consumed.
///
/// .xz spec §1.2: each byte carries 7 data bits in the low bits;
/// the high bit (`0x80`) signals "more bytes follow". The encoding
/// is little-endian (low-order bits come first). The maximum
/// length is 9 bytes; the 9th byte must therefore be `0x00..=0x01`
/// so the total stays within 64 bits. Encoders must use the
/// shortest legal form: a multibyte whose final byte is `0x00`
/// (a non-canonical leading zero) is rejected.
///
/// # Errors
///
/// - [`XzError::UnexpectedEof`] if `input` is empty or runs out
///   mid-encoding.
/// - [`XzError::MalformedMultibyte`] for an over-long encoding,
///   a 9th byte exceeding `0x01`, or a non-canonical trailing
///   zero on a multi-byte form.
pub fn read_multibyte(input: &[u8]) -> Result<(u64, usize), XzError> {
    if input.is_empty() {
        return Err(XzError::UnexpectedEof("multibyte integer"));
    }
    // Single-byte fast path: high bit clear means the value is
    // exactly that byte and we're done. The non-canonical-zero
    // rule applies only to multi-byte forms, so a single 0x00
    // byte legitimately decodes to 0.
    let first = input[0];
    if first & 0x80 == 0 {
        return Ok((u64::from(first), 1));
    }
    let mut value: u64 = u64::from(first & 0x7F);
    let mut shift: u32 = 7;
    let mut len: usize = 1;
    loop {
        if len >= MAX_MULTIBYTE_LEN {
            return Err(XzError::MalformedMultibyte("encoding exceeds 9 bytes"));
        }
        if len >= input.len() {
            return Err(XzError::UnexpectedEof("multibyte integer"));
        }
        let byte = input[len];
        len += 1;
        // The 9th byte (index 8) terminates the encoding. The .xz
        // spec disallows setting the continuation bit there
        // because that would extend the encoding past the 63-bit
        // ceiling.
        if len == MAX_MULTIBYTE_LEN && byte & 0x80 != 0 {
            return Err(XzError::MalformedMultibyte(
                "9th byte sets the continuation bit",
            ));
        }
        if byte & 0x80 == 0 {
            // Terminator. The terminating byte must not be zero;
            // that would make the encoding non-canonical (a
            // shorter form encodes the same value).
            if byte == 0 {
                return Err(XzError::MalformedMultibyte(
                    "non-canonical trailing zero byte",
                ));
            }
            value |= u64::from(byte) << shift;
            return Ok((value, len));
        }
        value |= u64::from(byte & 0x7F) << shift;
        shift += 7;
    }
}

/// Encode `value` as a multibyte integer into `out`. Returns the
/// number of bytes written.
///
/// Helper for tests that build hand-crafted .xz fixtures from
/// pre-known field values; not used by the runtime decode path.
#[cfg(test)]
pub fn write_multibyte(value: u64, out: &mut Vec<u8>) -> usize {
    let mut v = value;
    let start = out.len();
    while v >= 0x80 {
        out.push(((v & 0x7F) as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
    out.len() - start
}

/// Compute CRC-32/ISO-HDLC over `bytes`.
///
/// Reflected polynomial `0xEDB88320`, initial value `0xFFFFFFFF`,
/// XOR-out `0xFFFFFFFF`. Same parameters as zlib's `crc32`,
/// gzip's header CRC, and the .xz spec's "CRC32" choice for both
/// header CRCs and the optional `Check_Type = 0x01` Block trailer.
#[must_use]
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bytes {
        let idx = ((crc as u8) ^ b) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[idx];
    }
    crc ^ 0xFFFF_FFFF
}

/// Precomputed CRC-32/ISO-HDLC byte-table.
///
/// `CRC32_TABLE[i]` is `crc(i, 0xFFFFFFFF)` undone — i.e. the
/// reflected-polynomial reduction of the byte `i` viewed as a
/// degree-7 polynomial. Computed once at compile time from the
/// generating polynomial `0xEDB88320`.
const CRC32_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut c = i;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 == 1 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i as usize] = c;
        i += 1;
    }
    t
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-checks the table-driven CRC32 against three IEEE
    /// CRC-32 test vectors that are stable across implementations.
    #[test]
    fn crc32_known_vectors() {
        // RFC 3720 / standard test vectors for CRC-32/ISO-HDLC.
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn check_id_size_table() {
        assert_eq!(CheckId::None.size(), 0);
        assert_eq!(CheckId::Crc32.size(), 4);
        assert_eq!(CheckId::Crc64.size(), 8);
        assert_eq!(CheckId::Sha256.size(), 32);
    }

    #[test]
    fn check_id_round_trip() {
        for id in [
            CheckId::None,
            CheckId::Crc32,
            CheckId::Crc64,
            CheckId::Sha256,
        ] {
            assert_eq!(CheckId::from_raw(id.raw()).expect("round trip"), id);
        }
    }

    #[test]
    fn check_id_rejects_reserved() {
        for raw in [0x02, 0x03, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0B, 0x0C, 0x0F] {
            assert!(matches!(
                CheckId::from_raw(raw),
                Err(XzError::ReservedCheckId(_))
            ));
        }
    }

    /// Assemble the 12-byte Stream Header for a given Check ID
    /// the way `xz` does: magic + flags + CRC32 of flags.
    fn build_stream_header(check: CheckId) -> [u8; STREAM_HEADER_LEN] {
        let flags = StreamFlags { check };
        let flag_bytes = flags.to_bytes();
        let crc = crc32(&flag_bytes);
        let mut out = [0u8; STREAM_HEADER_LEN];
        out[..6].copy_from_slice(&STREAM_HEADER_MAGIC);
        out[6..8].copy_from_slice(&flag_bytes);
        out[8..12].copy_from_slice(&crc.to_le_bytes());
        out
    }

    #[test]
    fn stream_header_round_trip_all_checks() {
        for check in [
            CheckId::None,
            CheckId::Crc32,
            CheckId::Crc64,
            CheckId::Sha256,
        ] {
            let bytes = build_stream_header(check);
            let parsed = parse_stream_header(&bytes).expect("parse");
            assert_eq!(parsed, StreamFlags { check });
        }
    }

    #[test]
    fn stream_header_rejects_bad_magic() {
        let mut bytes = build_stream_header(CheckId::Crc64);
        bytes[3] ^= 0xFF;
        assert!(matches!(
            parse_stream_header(&bytes),
            Err(XzError::BadStreamMagic)
        ));
    }

    #[test]
    fn stream_header_rejects_bad_crc() {
        let mut bytes = build_stream_header(CheckId::Crc64);
        bytes[8] ^= 0xFF;
        assert!(matches!(
            parse_stream_header(&bytes),
            Err(XzError::StreamHeaderCrcMismatch { .. })
        ));
    }

    #[test]
    fn stream_header_rejects_reserved_high_nibble() {
        // Build a header whose Stream Flags low byte has high nibble
        // bits set; the CRC is updated to match so the header gets
        // past the integrity check first.
        let mut flag_bytes = [0x00u8, 0x14u8]; // reserved high-nibble bit set
        let crc = crc32(&flag_bytes);
        let mut out = [0u8; STREAM_HEADER_LEN];
        out[..6].copy_from_slice(&STREAM_HEADER_MAGIC);
        out[6..8].copy_from_slice(&flag_bytes);
        out[8..12].copy_from_slice(&crc.to_le_bytes());
        assert!(matches!(
            parse_stream_header(&out),
            Err(XzError::MalformedStreamFlags(_))
        ));
        // And the truly reserved-byte path:
        flag_bytes = [0x01, 0x04];
        let crc = crc32(&flag_bytes);
        out[6..8].copy_from_slice(&flag_bytes);
        out[8..12].copy_from_slice(&crc.to_le_bytes());
        assert!(matches!(
            parse_stream_header(&out),
            Err(XzError::MalformedStreamFlags(_))
        ));
    }

    #[test]
    fn stream_header_truncated_is_unexpected_eof() {
        for take in 0..STREAM_HEADER_LEN {
            let buf = vec![0u8; take];
            assert!(matches!(
                parse_stream_header(&buf),
                Err(XzError::UnexpectedEof(_))
            ));
        }
    }

    fn build_stream_footer(check: CheckId, backward_size: u64) -> [u8; STREAM_FOOTER_LEN] {
        let flags = StreamFlags { check };
        let flag_bytes = flags.to_bytes();
        // Real-units backward size has to be a multiple of 4 in
        // [4, (1u64<<34)] so the encoded form fits in u32.
        let raw = u32::try_from((backward_size / 4) - 1).expect("backward size in range");
        let mut middle = [0u8; 6];
        middle[..4].copy_from_slice(&raw.to_le_bytes());
        middle[4..6].copy_from_slice(&flag_bytes);
        let crc = crc32(&middle);
        let mut out = [0u8; STREAM_FOOTER_LEN];
        out[..4].copy_from_slice(&crc.to_le_bytes());
        out[4..10].copy_from_slice(&middle);
        out[10..12].copy_from_slice(&STREAM_FOOTER_MAGIC);
        out
    }

    #[test]
    fn stream_footer_round_trip() {
        let bytes = build_stream_footer(CheckId::Crc64, 12);
        let (flags, bs) = parse_stream_footer(&bytes).expect("parse");
        assert_eq!(flags.check, CheckId::Crc64);
        assert_eq!(bs, 12);
    }

    #[test]
    fn stream_footer_rejects_bad_magic() {
        let mut bytes = build_stream_footer(CheckId::Crc64, 12);
        bytes[10] = b'X';
        assert!(matches!(
            parse_stream_footer(&bytes),
            Err(XzError::BadStreamFooterMagic)
        ));
    }

    #[test]
    fn stream_footer_rejects_bad_crc() {
        let mut bytes = build_stream_footer(CheckId::Crc64, 12);
        bytes[0] ^= 0xFF;
        assert!(matches!(
            parse_stream_footer(&bytes),
            Err(XzError::StreamFooterCrcMismatch { .. })
        ));
    }

    #[test]
    fn multibyte_single_byte_values() {
        for v in 0u8..0x80 {
            let buf = [v];
            let (got, n) = read_multibyte(&buf).expect("decode");
            assert_eq!(got, u64::from(v));
            assert_eq!(n, 1);
        }
    }

    #[test]
    fn multibyte_two_byte_values() {
        // 0x80 = LSB; 0x01 = MSB. Value = 0x80 (least significant
        // byte first, 7 bits per byte).
        let (got, n) = read_multibyte(&[0x80, 0x01]).expect("decode");
        assert_eq!(got, 0x80);
        assert_eq!(n, 2);
        // Value = 16385 (0x4001) -> bytes 0x81, 0x80, 0x01.
        let (got, n) = read_multibyte(&[0x81, 0x80, 0x01]).expect("decode");
        assert_eq!(got, 16385);
        assert_eq!(n, 3);
    }

    #[test]
    fn multibyte_round_trips() {
        // .xz multibyte caps at 63 bits; values in `0..(1<<63)`.
        let cases = [
            0u64,
            1,
            127,
            128,
            255,
            256,
            16_383,
            16_384,
            1 << 32,
            (1u64 << 56) - 1,
            1u64 << 56,
            (1u64 << 63) - 1,
        ];
        for &v in &cases {
            let mut buf = Vec::new();
            write_multibyte(v, &mut buf);
            let (got, n) = read_multibyte(&buf).expect("decode");
            assert_eq!(got, v, "value {v}");
            assert_eq!(n, buf.len(), "len {v}");
        }
    }

    #[test]
    fn multibyte_rejects_non_canonical_zero_terminator() {
        // 0x80 0x00: continuation set on first, second is zero —
        // the spec bans this because a single 0x00 byte already
        // encodes the value 0 (canonical form).
        assert!(matches!(
            read_multibyte(&[0x80, 0x00]),
            Err(XzError::MalformedMultibyte(_))
        ));
    }

    #[test]
    fn multibyte_rejects_unterminated() {
        let nine_continuations = [0x80u8; MAX_MULTIBYTE_LEN];
        assert!(matches!(
            read_multibyte(&nine_continuations),
            Err(XzError::MalformedMultibyte(_))
        ));
    }

    #[test]
    fn multibyte_rejects_short_buffer() {
        assert!(matches!(
            read_multibyte(&[]),
            Err(XzError::UnexpectedEof(_))
        ));
        assert!(matches!(
            read_multibyte(&[0x80]),
            Err(XzError::UnexpectedEof(_))
        ));
    }

    #[test]
    fn multibyte_rejects_continuation_bit_on_ninth_byte() {
        // 8 continuation bytes (0x80) followed by a 9th byte whose
        // continuation bit is also set would extend the encoding
        // past 9 bytes. The .xz spec caps at 9.
        let mut buf = vec![0x80u8; 8];
        buf.push(0x80);
        assert!(matches!(
            read_multibyte(&buf),
            Err(XzError::MalformedMultibyte(_))
        ));
    }

    /// Round-trip against a real `xz` Stream Header to pin the
    /// exact bytes the spec produces (the prefix from
    /// `printf 'hello' | xz --lzma2=preset=0`).
    #[test]
    fn stream_header_matches_real_xz_prefix() {
        let prefix: [u8; STREAM_HEADER_LEN] = [
            0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00, 0x04, 0xE6, 0xD6, 0xB4, 0x46,
        ];
        let parsed = parse_stream_header(&prefix).expect("parse");
        assert_eq!(parsed.check, CheckId::Crc64);
    }
}
