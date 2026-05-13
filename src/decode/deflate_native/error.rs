//! Local error type for the hand-rolled DEFLATE decoder.
//!
//! Mirrors [`crate::decode::zstd::error::ZstdError`] / the xz-native
//! analogue: an `internal` error type lives next to the
//! [`super::Decoder`] state machine where the structured variants help
//! unit-test exact failure modes; conversion into
//! [`crate::decode::DecodeError`] happens at the
//! [`crate::decode::StreamingDecoder`] boundary so the rest of the
//! crate (extractor, coordinator, registry) keeps seeing the
//! protocol-level error type it already understands.
//!
//! # Why a local type
//!
//! Following `internal/ENGINEERING_BEST_PRACTICES.md` §3.1: errors are
//! documentation. "Reserved BTYPE 11 at offset N" or "stored-block
//! LEN/NLEN mismatch" is far more useful in test assertions and
//! tracing fields than the generic `std::io::Error::other(...)` we'd
//! otherwise stuff into [`DecodeError::Read`]. The boundary
//! conversion in [`super::Decoder::decode_step`] preserves the
//! message via the `#[source]` chain so end-user log output stays
//! diagnosable.

use std::io;

use thiserror::Error;

use crate::decode::DecodeError;

/// Errors produced inside the hand-rolled DEFLATE decoder.
///
/// Variants are grouped by which RFC 1951 layer surfaced the failure
/// (block header, stored-block frame, fixed/dynamic Huffman) so test
/// assertions and `tracing` fields can target the right layer
/// without parsing message strings.
#[derive(Debug, Error)]
pub enum DeflateError {
    /// Input source surfaced an underlying IO error while the decoder
    /// was reading more bytes. Distinct from "the bytes we read were
    /// malformed."
    #[error("deflate decoder source IO failed")]
    SourceIo(#[source] io::Error),

    /// The sink we were writing decoded output into rejected a write.
    /// Surfaces as [`DecodeError::Write`] at the trait boundary so the
    /// extractor's sink-error path (`src/extractor.rs`) can recover the
    /// typed `SinkError` the adapter captured.
    #[error("deflate decoder sink IO failed")]
    SinkIo(#[source] io::Error),

    /// A block header used the reserved block-type value `3`
    /// (RFC 1951 §3.2.3 — `BTYPE=11` is reserved for future use).
    #[error("deflate: reserved block type (BTYPE=11)")]
    ReservedBlockType,

    /// A stored block's `LEN` and `NLEN` fields did not satisfy the
    /// `LEN ^ 0xFFFF == NLEN` invariant (RFC 1951 §3.2.4). Likely
    /// indicates source corruption.
    #[error("deflate: stored-block LEN/NLEN mismatch (LEN={len:#06x}, NLEN={nlen:#06x})")]
    StoredLenMismatch {
        /// Little-endian 16-bit `LEN` field as read from the stream.
        len: u16,
        /// Little-endian 16-bit `NLEN` field as read from the stream.
        nlen: u16,
    },

    /// The source ended before a structurally complete piece of input
    /// had been consumed (block header truncated, stored-block
    /// LEN/NLEN truncated, payload short). Carries a short
    /// human-readable label naming what was being parsed.
    #[error("deflate: unexpected EOF while reading {0}")]
    UnexpectedEof(&'static str),

    /// Generic Huffman-layer failure. Variants include an
    /// over/under-subscribed code-length table (Kraft inequality
    /// violation), a code length exceeding RFC 1951's 15-bit cap,
    /// and a peeked bit pattern with no matching code in the
    /// canonical table. Carries a static reason string so test
    /// assertions and tracing can distinguish failure modes
    /// without parsing the message.
    #[error("deflate: malformed Huffman code: {0}")]
    MalformedHuffman(&'static str),

    /// A back-reference distance code in `30..=31` was decoded.
    /// RFC 1951 §3.2.5 reserves these (the distance-code alphabet
    /// is 30 entries; encoders never emit them). Surfacing as a
    /// dedicated variant keeps the per-symbol diagnostic separate
    /// from the more general
    /// [`Self::MalformedHuffman`] failures (Phase 0 spike Q3 calls
    /// out the value of typed rejection here).
    #[error("deflate: reserved distance code {code} (only 0..=29 are valid)")]
    ReservedDistanceCode {
        /// The reserved code (30 or 31).
        code: u16,
    },

    /// A back-reference's `(distance, length)` declared a copy
    /// from past the start of the decoded stream. Indicates
    /// either source corruption or a decoder bug.
    #[error("deflate: back-reference distance {distance} exceeds available history {available}")]
    BackReferenceUnderflow {
        /// Distance the back-reference declared.
        distance: u32,
        /// Bytes of decoded output available for the copy.
        available: u64,
    },

    /// A gzip member's two-byte magic (`ID1 ID2` per RFC 1952
    /// §2.3.1.1) was not `1F 8B`. Surfaced from the gzip wrapper
    /// when a stream's first member has an invalid magic, or when
    /// trailing bytes after a clean trailer don't form the start
    /// of a new member.
    #[error("gzip: bad magic bytes {id1:#04x} {id2:#04x} (expected 1F 8B)")]
    GzipBadMagic {
        /// First byte of the would-be magic.
        id1: u8,
        /// Second byte of the would-be magic.
        id2: u8,
    },

    /// A gzip member declared a compression method other than 8
    /// (`deflate`). RFC 1952 reserves all other values; round-one
    /// rejects them with this variant rather than treating them
    /// as malformed bytes.
    #[error("gzip: unsupported compression method {cm} (only CM=8 / deflate is supported)")]
    GzipUnsupportedCompressionMethod {
        /// The unsupported method byte.
        cm: u8,
    },

    /// A gzip member's FLG byte set one of the reserved bits
    /// (5..=7 per RFC 1952 §2.3.1.2). Surface as a typed error
    /// rather than silently ignoring; encoders that set these
    /// bits are non-conformant.
    #[error("gzip: reserved FLG bits set: {flg:#010b}")]
    GzipReservedFlag {
        /// The non-conformant FLG byte.
        flg: u8,
    },

    /// A gzip member's trailing CRC32 (RFC 1952 §2.3.1.5) did not
    /// match the CRC32 we computed over the decompressed bytes.
    /// Indicates either source corruption or a decoder bug — the
    /// output is not safe to consume.
    #[error("gzip: CRC32 mismatch (expected {expected:#010x}, computed {computed:#010x})")]
    GzipCrcMismatch {
        /// CRC32 the trailer recorded.
        expected: u32,
        /// CRC32 we computed.
        computed: u32,
    },

    /// A gzip member's trailing ISIZE (RFC 1952 §2.3.1.5) did not
    /// match the low 32 bits of the decompressed byte count we
    /// observed. Indicates source corruption or a decoder bug;
    /// the output is not safe to consume.
    #[error("gzip: ISIZE mismatch (expected {expected}, computed {computed})")]
    GzipIsizeMismatch {
        /// ISIZE the trailer recorded.
        expected: u32,
        /// Low 32 bits of the count we observed.
        computed: u32,
    },

    /// A Phase-7 resume blob was structurally malformed. Surfaced
    /// from [`super::resume::DflResumeState::deserialize`] when
    /// the magic / version / fields don't satisfy the layout
    /// described in `super::resume`. Carries a static reason
    /// string so test assertions and tracing can distinguish
    /// failure modes without parsing the message.
    #[error("deflate: resume blob rejected: {0}")]
    ResumeBlob(&'static str),
}

impl DeflateError {
    /// Convert this internal error into the protocol-level
    /// [`DecodeError`].
    ///
    /// `consumed` is the source-byte high-water mark at the moment
    /// the failure surfaced; it's threaded through to
    /// [`DecodeError::Read::consumed`] so the extractor's resume hint
    /// stays accurate.
    #[must_use]
    pub fn into_decode_error(self, consumed: u64) -> DecodeError {
        match self {
            DeflateError::SourceIo(source) => DecodeError::Read { consumed, source },
            DeflateError::SinkIo(source) => DecodeError::Write(source),
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
    fn stored_len_mismatch_renders_hex() {
        let e = DeflateError::StoredLenMismatch {
            len: 0x1234,
            nlen: 0x5678,
        };
        assert_eq!(
            e.to_string(),
            "deflate: stored-block LEN/NLEN mismatch (LEN=0x1234, NLEN=0x5678)"
        );
    }

    #[test]
    fn into_decode_error_preserves_consumed_and_message() {
        let e = DeflateError::ReservedBlockType;
        match e.into_decode_error(42) {
            DecodeError::Read { consumed, source } => {
                assert_eq!(consumed, 42);
                assert!(source.to_string().contains("reserved block type"));
            }
            other => panic!("expected Read, got {other:?}"),
        }
    }

    #[test]
    fn into_decode_error_passes_through_source_io_kind() {
        let inner = io::Error::new(io::ErrorKind::ConnectionAborted, "boom");
        match DeflateError::SourceIo(inner).into_decode_error(7) {
            DecodeError::Read { consumed, source } => {
                assert_eq!(consumed, 7);
                assert_eq!(source.kind(), io::ErrorKind::ConnectionAborted);
            }
            other => panic!("expected Read, got {other:?}"),
        }
    }

    #[test]
    fn into_decode_error_routes_sink_io_to_write_variant() {
        let inner = io::Error::new(io::ErrorKind::BrokenPipe, "no");
        match DeflateError::SinkIo(inner).into_decode_error(99) {
            DecodeError::Write(source) => {
                assert_eq!(source.kind(), io::ErrorKind::BrokenPipe);
            }
            other => panic!("expected Write, got {other:?}"),
        }
    }

    #[test]
    fn malformed_huffman_carries_static_reason() {
        let e = DeflateError::MalformedHuffman("code length > 15");
        assert!(e.to_string().contains("code length > 15"));
    }

    #[test]
    fn reserved_distance_code_renders_value() {
        let e = DeflateError::ReservedDistanceCode { code: 30 };
        assert!(e.to_string().contains("30"));
    }
}
