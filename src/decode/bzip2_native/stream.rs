//! Bzip2 stream-header parser.
//!
//! `internal/PLAN_bz2_support.md` Phase 2. Parses the four-byte
//! stream header `BZh<level>` where `<level>` is an ASCII digit in
//! `'1'..='9'` encoding the max block size (level × 100 KB
//! uncompressed). The legacy "marker" stream `BZh0` from bzip2
//! 0.9.0 is rejected — no modern encoder emits it.

use super::bitstream::BitReader;
use super::error::Bzip2Error;

/// Three-byte magic prefix every bzip2 stream begins with: `'B' 'Z' 'h'`.
pub const STREAM_MAGIC: [u8; 3] = [b'B', b'Z', b'h'];

/// Parsed stream header.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct StreamHeader {
    /// Level byte, in `1..=9`. The block-size ceiling in symbols is
    /// `level * 100_000` (the bzip2 reference uses base-100 000, not
    /// 1024-based units).
    pub level: u8,
}

impl StreamHeader {
    /// Maximum number of post-MTF/RLE2 symbols a single block may
    /// hold. Bzip2 uses `level * 100_000` (a real symbol count, not
    /// a byte count — the BWT works in symbols). The reference
    /// `decompress.c` allocates `100000 * level + 19` slots; we
    /// match that ceiling for the BWT-table guard rail.
    #[must_use]
    pub fn max_block_symbols(self) -> u32 {
        u32::from(self.level) * 100_000
    }
}

/// Parse the four-byte stream header from `br`. Consumes 32 bits
/// from the stream.
///
/// # Errors
///
/// - [`Bzip2Error::BadStreamMagic`] if the first three bytes are not
///   `BZh`.
/// - [`Bzip2Error::UnsupportedLevel`] if the level byte is outside
///   `'1'..='9'`. Specifically, the legacy marker stream `BZh0` is
///   rejected here.
/// - [`Bzip2Error::UnexpectedEof`] / [`Bzip2Error::SourceIo`] on
///   truncation / IO failure during the four-byte read.
pub fn parse_stream_header(br: &mut BitReader) -> Result<StreamHeader, Bzip2Error> {
    // 4 byte reads. Cursor is byte-aligned at stream start; each
    // read_bits(8) returns the byte value verbatim per the MSB-first
    // convention.
    let id1 = read_byte(br, "stream magic byte 1")?;
    let id2 = read_byte(br, "stream magic byte 2")?;
    let id3 = read_byte(br, "stream magic byte 3")?;
    if [id1, id2, id3] != STREAM_MAGIC {
        return Err(Bzip2Error::BadStreamMagic { id1, id2, id3 });
    }
    let level = read_byte(br, "stream level byte")?;
    if !(b'1'..=b'9').contains(&level) {
        return Err(Bzip2Error::UnsupportedLevel { level });
    }
    Ok(StreamHeader {
        level: level - b'0',
    })
}

/// Try to parse a stream header at the current bit cursor; returns
/// `Ok(None)` on clean source EOF before any bits have been read,
/// which signals "no more streams in this multi-stream file" to the
/// outer loop. Any partial header (one byte in, then EOF) surfaces
/// as `Bzip2Error::UnexpectedEof` per the strict-magic-or-error
/// contract.
///
/// # Errors
///
/// Forwards every error variant from [`parse_stream_header`] except
/// when zero bytes have been delivered before EOF, in which case
/// returns `Ok(None)`.
pub fn try_parse_stream_header(br: &mut BitReader) -> Result<Option<StreamHeader>, Bzip2Error> {
    // Peek one byte without committing: if the source is at clean
    // EOF, `ensure(8)` reports `bits_buffered() < 8` without raising.
    br.ensure(8)?;
    if br.bits_buffered() < 8 {
        return Ok(None);
    }
    parse_stream_header(br).map(Some)
}

fn read_byte(br: &mut BitReader, label: &'static str) -> Result<u8, Bzip2Error> {
    let v = br.read_bits(8).map_err(|e| relabel_eof(e, label))?;
    // INVARIANT: read_bits(8) returns 0..=255, fits in u8.
    Ok(v as u8)
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

    #[test]
    fn parses_each_supported_level() {
        for level in b'1'..=b'9' {
            let mut r = br(vec![b'B', b'Z', b'h', level]);
            let hdr = parse_stream_header(&mut r).expect("valid header");
            assert_eq!(hdr.level, level - b'0');
        }
    }

    #[test]
    fn rejects_bad_magic() {
        let mut r = br(vec![b'X', b'Z', b'h', b'9']);
        match parse_stream_header(&mut r) {
            Err(Bzip2Error::BadStreamMagic { id1, id2, id3 }) => {
                assert_eq!(id1, b'X');
                assert_eq!(id2, b'Z');
                assert_eq!(id3, b'h');
            }
            other => panic!("expected BadStreamMagic, got {other:?}"),
        }
    }

    #[test]
    fn rejects_legacy_zero_level() {
        let mut r = br(vec![b'B', b'Z', b'h', b'0']);
        match parse_stream_header(&mut r) {
            Err(Bzip2Error::UnsupportedLevel { level }) => assert_eq!(level, b'0'),
            other => panic!("expected UnsupportedLevel, got {other:?}"),
        }
    }

    #[test]
    fn rejects_non_digit_level() {
        let mut r = br(vec![b'B', b'Z', b'h', b'A']);
        match parse_stream_header(&mut r) {
            Err(Bzip2Error::UnsupportedLevel { level }) => assert_eq!(level, b'A'),
            other => panic!("expected UnsupportedLevel, got {other:?}"),
        }
    }

    #[test]
    fn unexpected_eof_during_magic_surfaces_labelled() {
        let mut r = br(vec![b'B']);
        match parse_stream_header(&mut r) {
            Err(Bzip2Error::UnexpectedEof(label)) => {
                assert_eq!(label, "stream magic byte 2");
            }
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn unexpected_eof_during_level_surfaces_labelled() {
        let mut r = br(vec![b'B', b'Z', b'h']);
        match parse_stream_header(&mut r) {
            Err(Bzip2Error::UnexpectedEof(label)) => {
                assert_eq!(label, "stream level byte");
            }
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn try_parse_at_eof_returns_none() {
        let mut r = br(Vec::new());
        match try_parse_stream_header(&mut r) {
            Ok(None) => {}
            other => panic!("expected Ok(None) at EOF, got {other:?}"),
        }
    }

    #[test]
    fn try_parse_after_one_byte_then_eof_surfaces_unexpected_eof() {
        let mut r = br(vec![b'B']);
        match try_parse_stream_header(&mut r) {
            Err(Bzip2Error::UnexpectedEof(_)) => {}
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn max_block_symbols_scales_with_level() {
        assert_eq!(StreamHeader { level: 1 }.max_block_symbols(), 100_000);
        assert_eq!(StreamHeader { level: 9 }.max_block_symbols(), 900_000);
    }
}
