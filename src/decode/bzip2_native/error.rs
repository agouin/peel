//! Local error type for the hand-rolled bzip2 decoder.
//!
//! Mirrors [`crate::decode::deflate_native::error::DeflateError`] in
//! shape and purpose: a structured `thiserror`-based enum lives next
//! to the decoder so test assertions can target specific failure modes
//! (truncated Huffman selector list vs. block CRC mismatch vs. bad
//! stream magic) without parsing strings, and the conversion into
//! [`crate::decode::DecodeError`] happens at the
//! [`crate::decode::StreamingDecoder`] trait boundary so the rest of
//! the crate keeps seeing the protocol-level error type it already
//! understands.

use std::io;

use thiserror::Error;

use crate::decode::DecodeError;

/// Errors produced inside the hand-rolled bzip2 decoder.
///
/// Variants are grouped by which bzip2-format layer surfaced the
/// failure (stream header, block frame, Huffman, MTF/RLE, BWT, CRC,
/// RLE1) so test assertions and `tracing` fields can target the right
/// layer without parsing message strings.
#[derive(Debug, Error)]
pub enum Bzip2Error {
    /// Input source surfaced an underlying IO error while the decoder
    /// was reading more bytes. Distinct from "the bytes we read were
    /// malformed."
    #[error("bzip2 decoder source IO failed")]
    SourceIo(#[source] io::Error),

    /// The sink we were writing decoded output into rejected a write.
    /// Surfaces as [`DecodeError::Write`] at the trait boundary so the
    /// extractor's sink-error path (`src/extractor.rs`) can recover
    /// the typed `SinkError` the adapter captured.
    #[error("bzip2 decoder sink IO failed")]
    SinkIo(#[source] io::Error),

    /// The source ended before a structurally complete piece of input
    /// had been consumed. Carries a short human-readable label naming
    /// what was being parsed.
    #[error("bzip2: unexpected EOF while reading {0}")]
    UnexpectedEof(&'static str),

    /// The stream's three-byte magic was not `42 5A 68` (`BZh`).
    /// Surfaced from the stream-header parser on the first block of a
    /// stream and on every additional stream encountered in a
    /// multi-stream file.
    #[error("bzip2: bad stream magic {id1:#04x} {id2:#04x} {id3:#04x} (expected 42 5A 68)")]
    BadStreamMagic {
        /// First magic byte (`'B'`).
        id1: u8,
        /// Second magic byte (`'Z'`).
        id2: u8,
        /// Third magic byte (`'h'`).
        id3: u8,
    },

    /// The stream-header level byte was outside `'1'..='9'`. The
    /// special value `'0'` (legacy marker stream from bzip 0.9.0 and
    /// before) is rejected here as deferred — see
    /// `internal/PLAN_bz2_support.md` §Deferred.
    #[error("bzip2: unsupported level byte {level:#04x} (expected '1'..='9')")]
    UnsupportedLevel {
        /// The level byte as read from the stream.
        level: u8,
    },

    /// A 48-bit block-marker sequence matched neither the
    /// compressed-block magic (`0x314159265359`) nor the
    /// end-of-stream magic (`0x177245385090`).
    #[error("bzip2: bad block marker {marker:#014x} (expected compressed-block or EOS magic)")]
    BadBlockMarker {
        /// The 48-bit marker as read from the stream, packed in the
        /// low bits of a `u64`.
        marker: u64,
    },

    /// A block declared the legacy "randomised" flag (bzip2 0.9.0 and
    /// earlier). Round one rejects these — see
    /// `internal/PLAN_bz2_support.md` §Deferred for the rationale.
    #[error(
        "bzip2: randomised block (bzip2 0.9.0 legacy) is not supported \
         — see internal/PLAN_bz2_support.md §Deferred"
    )]
    RandomisedBlock,

    /// A block's BWT origin pointer was >= the block's symbol count,
    /// which would index past the end of the BWT inverse table.
    #[error("bzip2: block origin pointer {orig_ptr} out of range (block has {block_len} symbols)")]
    OriginPointerOutOfRange {
        /// `origPtr` as read from the block header.
        orig_ptr: u32,
        /// Symbol count after MTF/RLE2 inverse.
        block_len: u32,
    },

    /// The "symbols used" map had no symbols set. A bzip2 block must
    /// declare at least one symbol it uses.
    #[error("bzip2: block declares an empty symbol set")]
    EmptySymbolSet,

    /// The block's Huffman-table count `nGroups` was outside
    /// `2..=6`. Bzip2 packs between 2 and 6 Huffman tables per block;
    /// any other count is malformed.
    #[error("bzip2: invalid Huffman group count {n_groups} (expected 2..=6)")]
    InvalidGroupCount {
        /// The count as read from the stream.
        n_groups: u8,
    },

    /// The block's selector count `nSelectors` was outside `1..=18002`
    /// (the upper bound is `900 KB / 50 + 2` rounded up).
    #[error("bzip2: invalid selector count {n_selectors} (expected 1..=18002)")]
    InvalidSelectorCount {
        /// The count as read from the stream.
        n_selectors: u32,
    },

    /// A delta-coded selector ranking pointed at a group index >=
    /// `n_groups`. Indicates source corruption.
    #[error("bzip2: selector index {index} out of range (only {n_groups} groups declared)")]
    SelectorOutOfRange {
        /// The decoded selector value.
        index: u8,
        /// Number of Huffman groups declared in this block.
        n_groups: u8,
    },

    /// A Huffman code-length field was outside `1..=20`. Bzip2 caps
    /// canonical code lengths at 20 bits.
    #[error("bzip2: Huffman code length {length} out of range (expected 1..=20)")]
    HuffmanLengthOutOfRange {
        /// The decoded length.
        length: u32,
    },

    /// Generic Huffman-layer failure (over/under-subscribed table,
    /// peeked bits with no matching code).
    #[error("bzip2: malformed Huffman code: {0}")]
    MalformedHuffman(&'static str),

    /// A block's symbol stream contained more than the maximum
    /// allowed symbols after MTF inverse (900_000 + a few).
    #[error("bzip2: block decoded too many symbols (saw {seen}, max {max})")]
    BlockTooLarge {
        /// Number of symbols emitted before the overflow check fired.
        seen: u32,
        /// The configured per-block ceiling for this stream level.
        max: u32,
    },

    /// A block's symbol stream ran out of input before the EOB
    /// symbol. Indicates source truncation or corruption.
    #[error("bzip2: block ended without an EOB symbol")]
    BlockMissingEob,

    /// A block's CRC trailer did not match the CRC computed over the
    /// block's pre-RLE1 output bytes.
    #[error("bzip2: block CRC mismatch (expected {expected:#010x}, computed {computed:#010x})")]
    BlockCrcMismatch {
        /// CRC the block header recorded.
        expected: u32,
        /// CRC we computed.
        computed: u32,
    },

    /// The stream's combined CRC trailer (after the EOS marker) did
    /// not match the running stream-CRC accumulator.
    #[error("bzip2: stream CRC mismatch (expected {expected:#010x}, computed {computed:#010x})")]
    StreamCrcMismatch {
        /// CRC the stream trailer recorded.
        expected: u32,
        /// CRC we computed.
        computed: u32,
    },

    /// A resume blob was structurally malformed. Surfaced from
    /// [`super::resume::Bzip2ResumeState::deserialize`] when the magic
    /// / version / fields don't satisfy the layout documented in
    /// `super::resume`. Carries a static reason so test assertions can
    /// distinguish failure modes without parsing the message.
    #[error("bzip2: resume blob rejected: {0}")]
    ResumeBlob(&'static str),
}

impl Bzip2Error {
    /// Convert this internal error into the protocol-level
    /// [`DecodeError`].
    ///
    /// `consumed` is the source-byte high-water mark at the moment
    /// the failure surfaced; threaded through to
    /// [`DecodeError::Read::consumed`] so the extractor's resume hint
    /// stays accurate.
    #[must_use]
    pub fn into_decode_error(self, consumed: u64) -> DecodeError {
        match self {
            Bzip2Error::SourceIo(source) => DecodeError::Read { consumed, source },
            Bzip2Error::SinkIo(source) => DecodeError::Write(source),
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
    fn bad_stream_magic_renders_hex() {
        let e = Bzip2Error::BadStreamMagic {
            id1: 0x01,
            id2: 0x02,
            id3: 0x03,
        };
        assert!(e.to_string().contains("0x01"));
        assert!(e.to_string().contains("0x02"));
        assert!(e.to_string().contains("0x03"));
    }

    #[test]
    fn into_decode_error_preserves_consumed_and_message() {
        let e = Bzip2Error::RandomisedBlock;
        match e.into_decode_error(123) {
            DecodeError::Read { consumed, source } => {
                assert_eq!(consumed, 123);
                assert!(source.to_string().contains("randomised block"));
            }
            other => panic!("expected Read, got {other:?}"),
        }
    }

    #[test]
    fn into_decode_error_routes_source_io_with_kind_preserved() {
        let inner = io::Error::new(io::ErrorKind::ConnectionAborted, "boom");
        match Bzip2Error::SourceIo(inner).into_decode_error(7) {
            DecodeError::Read { consumed, source } => {
                assert_eq!(consumed, 7);
                assert_eq!(source.kind(), io::ErrorKind::ConnectionAborted);
            }
            other => panic!("expected Read, got {other:?}"),
        }
    }

    #[test]
    fn into_decode_error_routes_sink_io_to_write() {
        let inner = io::Error::new(io::ErrorKind::BrokenPipe, "no");
        match Bzip2Error::SinkIo(inner).into_decode_error(0) {
            DecodeError::Write(source) => {
                assert_eq!(source.kind(), io::ErrorKind::BrokenPipe);
            }
            other => panic!("expected Write, got {other:?}"),
        }
    }

    #[test]
    fn crc_mismatch_renders_both_values() {
        let e = Bzip2Error::BlockCrcMismatch {
            expected: 0xDEAD_BEEF,
            computed: 0xCAFE_F00D,
        };
        let s = e.to_string();
        assert!(s.contains("0xdeadbeef"));
        assert!(s.contains("0xcafef00d"));
    }
}
