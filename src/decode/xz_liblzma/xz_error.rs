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

    /// LZMA range decoder's leading marker byte was non-zero. The
    /// LZMA spec mandates a `0x00` byte at the head of every
    /// range-coded payload as an early corruption check; surfaces
    /// here when an LZMA2 chunk's compressed payload doesn't start
    /// with one.
    #[error("xz: LZMA range coder init marker byte was 0x{0:02X} (expected 0x00)")]
    RangeCoderInitMarker(u8),

    /// LZMA range decoder asked for more compressed bytes than the
    /// LZMA2 chunk's buffered payload contains. Either the chunk's
    /// declared `Compressed_Size` was wrong or the LZMA stream
    /// itself is truncated. The label names which range-coder
    /// state surfaced the underflow (e.g. `"normalize"`).
    #[error("xz: LZMA range coder ran past end of compressed payload at {0}")]
    RangeCoderUnderflow(&'static str),

    /// LZMA literal-context properties (`lc + lp`) exceeded the
    /// spec maximum of 4. Default preset uses `lc=3, lp=0` (sum 3);
    /// the spec allows up to `lc=8, lp=4` individually but
    /// constrains `lc + lp ≤ 4`. Surfaces a clean error rather
    /// than silently allocating a multi-MiB literal table.
    #[error("xz: LZMA lc + lp = {0} exceeds spec max of 4")]
    LzmaLcLpTooLarge(u32),

    /// LZMA `pb` (position-state bits) exceeded the spec maximum
    /// of 4.
    #[error("xz: LZMA pb = {0} exceeds spec max of 4")]
    LzmaPbTooLarge(u32),

    /// LZMA properties byte was outside the legal range (`0..=224`,
    /// the encoded form of `(pb, lp, lc)` with `lc + lp ≤ 4` and
    /// `pb ≤ 4`).
    #[error("xz: LZMA properties byte 0x{0:02X} is out of range")]
    LzmaInvalidProperties(u8),

    /// LZMA back-reference distance pointed before the start of
    /// the dictionary's available history. Either the encoder
    /// emitted an invalid distance or the chunk's `reset_dict`
    /// flag is wrong.
    #[error("xz: LZMA match distance {dist} exceeds available history {total} bytes")]
    LzmaMatchOutOfRange {
        /// Encoded (0-based) distance from the LZMA stream.
        dist: u32,
        /// Bytes accumulated in the dictionary so far.
        total: u64,
    },

    /// LZMA encoder emitted a length that, when expanded, would
    /// overrun the chunk's declared `Uncompressed_Size`. Surfaces
    /// here as a clean error rather than silently truncating the
    /// match.
    #[error("xz: LZMA match length overruns chunk uncompressed_size")]
    LzmaLengthOverrun,

    /// LZMA legacy "end of payload" distance marker (`u32::MAX`)
    /// appeared inside an LZMA2 chunk. LZMA2 carries explicit
    /// chunk sizes, so an EOS marker is never legal inside a
    /// chunk's compressed payload.
    #[error("xz: LZMA EOS marker is not legal inside an LZMA2 chunk")]
    LzmaUnexpectedEos,

    /// LZMA range coder did not finish in the spec's "well-
    /// terminated" state at chunk end (either `code != 0` or
    /// compressed bytes were left unconsumed). Surfaces the
    /// observed state for diagnostics.
    #[error("xz: LZMA range coder did not finish cleanly: code=0x{code:08X}, leftover={leftover}")]
    LzmaRangeCoderUnfinished {
        /// Final `code` value of the range decoder. Should be 0
        /// for a clean finish.
        code: u32,
        /// Bytes of compressed payload not consumed by the range
        /// decoder.
        leftover: usize,
    },

    /// LZMA chunk's declared `Uncompressed_Size` was not produced
    /// by the time the LZMA inner loop exhausted the compressed
    /// payload.
    #[error("xz: LZMA chunk produced {produced} bytes, expected {expected}")]
    LzmaUncompressedSizeMismatch {
        /// Bytes the LZMA model actually emitted.
        produced: u32,
        /// Bytes the chunk header declared.
        expected: u32,
    },

    /// First LZMA chunk in a Block (or after a `reset_dict` /
    /// `reset_props`) did not carry an LZMA properties byte. The
    /// decoder needs `(lc, lp, pb)` to size its probability
    /// tables; without them the chunk cannot be decoded.
    #[error("xz: first LZMA2 chunk must carry properties (reset_props)")]
    Lzma2MissingFirstProperties,

    /// Block-trailer Check (CRC32/CRC64/SHA-256) did not match
    /// the hash of the decompressed Block bytes. Names the
    /// specific Check variant so the caller can route the
    /// diagnostic. This is the load-bearing
    /// "the file got corrupted in transit / on disk" signal
    /// the .xz format provides.
    #[error("xz: Block Check verification failed ({kind})")]
    BlockCheckMismatch {
        /// One of `"CRC32"`, `"CRC64"`, `"SHA-256"`.
        kind: &'static str,
    },

    /// Index Block-record count or one of its size fields did
    /// not match the bytes the decoder actually pulled. The .xz
    /// format places an Index after the last Block in every
    /// Stream as a redundant cross-check; mismatch here is the
    /// "file structure was tampered with" signal.
    #[error("xz: Index {field} mismatch (declared {declared}, observed {observed})")]
    IndexMismatch {
        /// One of `"record count"`, `"unpadded_size"`, or
        /// `"uncompressed_size"`.
        field: &'static str,
        /// The Index's declared value.
        declared: u64,
        /// The decoder's observed value.
        observed: u64,
    },

    /// Index CRC32 trailer did not match the CRC the decoder
    /// computed over the Index bytes (Indicator + records +
    /// padding).
    #[error("xz: Index CRC32 mismatch (expected 0x{expected:08X}, got 0x{got:08X})")]
    IndexCrcMismatch {
        /// CRC32 stored in the Index trailer.
        expected: u32,
        /// CRC32 we computed over the Index bytes.
        got: u32,
    },

    /// Phase 6 resume blob ended before all expected fields were
    /// read. Carries a label naming the field that was being
    /// pulled when the blob ran out.
    #[error("xz: resume blob truncated at field {0}")]
    ResumeBlobTruncated(&'static str),

    /// Phase 6 resume blob's declared field length disagrees with
    /// the expected value computed from `(lc, lp, pb)` or the
    /// Stream's Check ID.
    #[error(
        "xz: resume blob length mismatch at {field} (declared {declared}, expected {expected})"
    )]
    ResumeBlobLength {
        /// Which field was being checked.
        field: &'static str,
        /// Length declared in the blob.
        declared: u64,
        /// Length the decoder expected.
        expected: u64,
    },

    /// Resume blob's leading magic / version did not match
    /// `b"XDR2"` + version byte 2 (current) or `b"XDR1"` +
    /// version byte 1 (legacy, read-only).
    #[error("xz: resume blob has bad magic or unsupported format version")]
    ResumeBlobMagic,

    /// V1 resume blob's trailing CRC32 did not match the hash
    /// over the rest of the blob — the blob was corrupted in
    /// storage / transit. V2 blobs do not carry a trailing CRC32
    /// and never raise this error; their integrity is checked by
    /// the surrounding `Checkpoint` body's fnv1a64.
    #[error("xz: resume blob CRC32 mismatch (expected 0x{expected:08X}, got 0x{got:08X})")]
    ResumeBlobCrc {
        /// CRC32 stored in the blob trailer.
        expected: u32,
        /// CRC32 we computed over the rest of the blob.
        got: u32,
    },
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
