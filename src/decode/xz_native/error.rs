//! Local error type for the hand-rolled xz / LZMA decoder.
//!
//! Mirrors `crate::decode::zstd::error::ZstdError`: a structured
//! `thiserror`-derived enum lives next to the [`super::Decoder`]
//! state machine where the variants help unit-test exact failure
//! modes; conversion into [`crate::decode::DecodeError`] happens at
//! the [`crate::decode::StreamingDecoder`] boundary so the rest of
//! the crate keeps seeing the protocol-level error type it already
//! understands.
//!
//! # Why a local type
//!
//! Per `docs/ENGINEERING_BEST_PRACTICES.md` §3.1: errors are
//! documentation. "Block Header CRC32 mismatch" or "unsupported
//! filter ID" is far more useful in test assertions and `tracing`
//! fields than the generic `std::io::Error::other(...)` we'd
//! otherwise stuff into [`DecodeError::Read`]. The boundary
//! conversion in [`super::Decoder::decode_step`] preserves the
//! message via the `#[source]` chain so end-user log output stays
//! diagnosable.

use std::io;

use thiserror::Error;

use crate::decode::DecodeError;

/// Errors produced inside the hand-rolled xz / LZMA decoder.
///
/// Variants are grouped by which .xz spec section surfaced the
/// failure (Stream Header, Block Header, LZMA2 chunk) so test
/// assertions and `tracing` fields can target the right layer
/// without parsing message strings.
#[derive(Debug, Error)]
pub enum XzError {
    /// Input source surfaced an underlying IO error while the
    /// decoder was reading more bytes. Distinct from "the bytes we
    /// read were malformed."
    #[error("xz decoder source IO failed")]
    SourceIo(#[source] io::Error),

    /// The sink rejected a write. Surfaces as
    /// [`DecodeError::Write`] so the extractor's sink-error path
    /// can recover the typed `SinkError` the adapter captured.
    #[error("xz decoder sink IO failed")]
    SinkIo(#[source] io::Error),

    /// The 6-byte Stream Header magic did not match
    /// `0xFD '7' 'z' 'X' 'Z' 0x00`.
    #[error("xz: bad Stream Header magic")]
    BadStreamMagic,

    /// The 2-byte Stream Footer magic did not match `'Y' 'Z'`.
    #[error("xz: bad Stream Footer magic")]
    BadStreamFooterMagic,

    /// The Stream Flags field violated the spec — either the
    /// reserved first byte was non-zero or the high nibble of the
    /// second byte was non-zero.
    #[error("xz: malformed Stream Flags: {0}")]
    MalformedStreamFlags(&'static str),

    /// Stream Header CRC32 over the 2-byte Stream Flags did not
    /// match the trailing 4-byte CRC.
    #[error("xz: Stream Header CRC32 mismatch (expected 0x{expected:08X}, got 0x{got:08X})")]
    StreamHeaderCrcMismatch {
        /// CRC32 stored in the Stream Header trailer.
        expected: u32,
        /// CRC32 we computed over the 2-byte Stream Flags field.
        got: u32,
    },

    /// Stream Footer CRC32 over Backward_Size + Stream_Flags did
    /// not match the leading 4-byte CRC.
    #[error("xz: Stream Footer CRC32 mismatch (expected 0x{expected:08X}, got 0x{got:08X})")]
    StreamFooterCrcMismatch {
        /// CRC32 stored at the start of the Stream Footer.
        expected: u32,
        /// CRC32 we computed over Backward_Size + Stream_Flags.
        got: u32,
    },

    /// The Stream Footer's Stream Flags did not match the Stream
    /// Header's Stream Flags.
    #[error("xz: Stream Footer flags mismatch (header 0x{header:04X}, footer 0x{footer:04X})")]
    StreamFlagsMismatch {
        /// Stream Flags as stored in the Stream Header.
        header: u16,
        /// Stream Flags as stored in the Stream Footer.
        footer: u16,
    },

    /// Stream Footer's Backward Size did not match the actual
    /// Index length.
    #[error("xz: Stream Footer Backward_Size mismatch (declared {declared}, actual {actual})")]
    BackwardSizeMismatch {
        /// Real-units backward size from the Stream Footer.
        declared: u64,
        /// Actual length of the Index region we observed.
        actual: u64,
    },

    /// A Stream's Check ID was a reserved value (one of `0x02`,
    /// `0x03`, `0x05`..`0x09`, `0x0B`..`0x0F`).
    #[error("xz: reserved Check ID 0x{0:02X}")]
    ReservedCheckId(u8),

    /// A Block Header's Block_Header_Size field encoded a value
    /// outside `0x01..=0xFF`. `0x00` is the Index Indicator (handled
    /// at the Stream layer); the multiplier-by-4 logic produces
    /// `0x04..=0x400` valid byte sizes for the rest.
    #[error("xz: invalid Block_Header_Size 0x{0:02X}")]
    InvalidBlockHeaderSize(u8),

    /// A Block Header reserved bit was set (bits 2..=5 of
    /// Block_Flags must be zero).
    #[error("xz: malformed Block Header: {0}")]
    MalformedBlockHeader(&'static str),

    /// Block Header CRC32 over the (size + flags + sizes + filter
    /// flags + padding) bytes did not match the trailing 4-byte CRC.
    #[error("xz: Block Header CRC32 mismatch (expected 0x{expected:08X}, got 0x{got:08X})")]
    BlockHeaderCrcMismatch {
        /// CRC32 stored in the Block Header trailer.
        expected: u32,
        /// CRC32 we computed over the rest of the Block Header.
        got: u32,
    },

    /// A multibyte (varint) integer was malformed: too long
    /// (> 9 bytes), unterminated, or non-canonical (the final byte
    /// was zero).
    #[error("xz: malformed multibyte integer: {0}")]
    MalformedMultibyte(&'static str),

    /// The filter chain declared something other than a single
    /// LZMA2 filter. Round-one rejects BCJ pre-filters and
    /// multi-filter chains; surface a clean error so the user can
    /// fall back to liblzma.
    #[error("xz: unsupported filter chain: {0}")]
    UnsupportedFilterChain(&'static str),

    /// The LZMA2 dictionary size declared in the filter properties
    /// exceeds round-one's 64 MiB cap. The cap exists so the resume
    /// blob in Phase 6 stays bounded; presets above 6 that declare
    /// > 64 MiB are out of scope.
    #[error("xz: LZMA2 dictionary size {dict_size} exceeds {cap}-byte cap")]
    DictTooLarge {
        /// Declared dictionary size in bytes.
        dict_size: u64,
        /// Round-one cap, in bytes (64 MiB).
        cap: u64,
    },

    /// LZMA2 properties byte declared a reserved dictionary size
    /// encoding (raw value > 40).
    #[error("xz: reserved LZMA2 dictionary size encoding 0x{0:02X}")]
    ReservedDictEncoding(u8),

    /// An LZMA2 chunk control byte was reserved (`0x03..=0x7F`).
    #[error("xz: reserved LZMA2 chunk control byte 0x{0:02X}")]
    ReservedLzma2Control(u8),

    /// An LZMA2 stream's first chunk was not a "reset dict"
    /// uncompressed chunk (`0x01`) or LZMA chunk with full reset
    /// (`0xE0..=0xFF`). Either of those is required by the LZMA2
    /// spec to put the dictionary into a known state.
    #[error("xz: first LZMA2 chunk must reset dict; got control 0x{0:02X}")]
    Lzma2MissingInitialReset(u8),

    /// An LZMA chunk reached a code path the Phase 1 implementation
    /// hasn't been taught yet. Replaced by the real LZMA decoder in
    /// Phase 4 of `docs/PLAN_xz_block_decoder.md`.
    #[error("xz: LZMA chunk decoding not yet implemented")]
    LzmaChunkUnimplemented,

    /// Block-layer Compressed_Size or Uncompressed_Size declared
    /// in the Block Header did not match what the LZMA2 stream
    /// actually produced.
    #[error("xz: Block size mismatch ({field}: declared {declared}, actual {actual})")]
    BlockSizeMismatch {
        /// Which field disagreed: `"Compressed_Size"` or
        /// `"Uncompressed_Size"`.
        field: &'static str,
        /// Size declared in the Block Header.
        declared: u64,
        /// Size we observed while decoding the Block.
        actual: u64,
    },

    /// The source ended before a structurally complete piece of
    /// input had been consumed (Stream Header truncated, Block
    /// Header truncated, etc.). Carries a short human-readable
    /// label naming what was being parsed.
    #[error("xz: unexpected EOF while reading {0}")]
    UnexpectedEof(&'static str),

    /// Stream Padding (zero-byte alignment between concatenated
    /// Streams) is rejected today, mirroring the wrapper at
    /// `src/decode/xz.rs`. Kept rejected per
    /// `docs/PLAN_xz_block_decoder.md` §Scope.
    #[error("xz: Stream Padding between concatenated streams is not supported")]
    StreamPaddingUnsupported,
}

impl XzError {
    /// Convert this internal error into the protocol-level
    /// [`DecodeError`].
    ///
    /// `consumed` is the source-byte high-water mark at the moment
    /// the failure surfaced; it's threaded through to
    /// [`DecodeError::Read::consumed`] so the extractor's resume
    /// hint stays accurate.
    #[must_use]
    pub fn into_decode_error(self, consumed: u64) -> DecodeError {
        match self {
            XzError::SourceIo(source) => DecodeError::Read { consumed, source },
            XzError::SinkIo(source) => DecodeError::Write(source),
            other => DecodeError::Read {
                consumed,
                source: io::Error::other(other.to_string()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bad_magic_renders_clean_message() {
        let e = XzError::BadStreamMagic;
        assert_eq!(e.to_string(), "xz: bad Stream Header magic");
    }

    #[test]
    fn into_decode_error_preserves_consumed_and_message() {
        let e = XzError::ReservedCheckId(0x02);
        match e.into_decode_error(42) {
            DecodeError::Read { consumed, source } => {
                assert_eq!(consumed, 42);
                assert!(source.to_string().contains("reserved Check ID"));
            }
            other => panic!("expected Read, got {other:?}"),
        }
    }

    #[test]
    fn into_decode_error_passes_through_source_io_kind() {
        let inner = io::Error::new(io::ErrorKind::ConnectionAborted, "boom");
        match XzError::SourceIo(inner).into_decode_error(7) {
            DecodeError::Read { consumed, source } => {
                assert_eq!(consumed, 7);
                assert_eq!(source.kind(), io::ErrorKind::ConnectionAborted);
            }
            other => panic!("expected Read, got {other:?}"),
        }
    }

    #[test]
    fn sink_io_maps_to_write_variant() {
        let inner = io::Error::new(io::ErrorKind::BrokenPipe, "pipe");
        match XzError::SinkIo(inner).into_decode_error(99) {
            DecodeError::Write(source) => {
                assert_eq!(source.kind(), io::ErrorKind::BrokenPipe);
            }
            other => panic!("expected Write, got {other:?}"),
        }
    }

    #[test]
    fn unimplemented_lzma_chunk_message_is_stable() {
        // Tests assert on this string; pin it.
        assert_eq!(
            XzError::LzmaChunkUnimplemented.to_string(),
            "xz: LZMA chunk decoding not yet implemented"
        );
    }
}
