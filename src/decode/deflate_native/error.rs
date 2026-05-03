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
//! Following `docs/ENGINEERING_BEST_PRACTICES.md` §3.1: errors are
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

    /// A `BTYPE=01` (fixed Huffman) block was observed. Phase 1 ships
    /// stored blocks only; fixed-Huffman support arrives in Phase 3
    /// per `docs/PLAN_deflate_block_decoder.md`. Distinct variant so
    /// the gate can be lifted phase-by-phase without churning every
    /// call site.
    #[error("deflate: fixed Huffman block (BTYPE=01) decoding not yet implemented")]
    FixedHuffmanUnimplemented,

    /// A `BTYPE=10` (dynamic Huffman) block was observed. Phase 1
    /// ships stored blocks only; dynamic-Huffman support arrives in
    /// Phase 4 per `docs/PLAN_deflate_block_decoder.md`.
    #[error("deflate: dynamic Huffman block (BTYPE=10) decoding not yet implemented")]
    DynamicHuffmanUnimplemented,
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
    fn unimplemented_variants_carry_phase_specific_messages() {
        assert!(DeflateError::FixedHuffmanUnimplemented
            .to_string()
            .contains("BTYPE=01"));
        assert!(DeflateError::DynamicHuffmanUnimplemented
            .to_string()
            .contains("BTYPE=10"));
    }
}
