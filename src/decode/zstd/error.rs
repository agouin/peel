//! Local error type for the hand-rolled zstd decoder.
//!
//! This is an `internal` error type: it lives next to the
//! [`super::Decoder`] state machine where the structured variants
//! help unit-test exact failure modes. Conversion into
//! [`crate::decode::DecodeError`] happens at the
//! [`crate::decode::StreamingDecoder`] boundary so the rest of the
//! crate (extractor, coordinator, registry) keeps seeing the
//! protocol-level error type it already understands.
//!
//! # Why a local type
//!
//! Following `docs/ENGINEERING_BEST_PRACTICES.md` §3.1: errors are
//! documentation. A "bad windowLog" or "reserved block type" is far
//! more useful in test assertions and tracing fields than the
//! generic `std::io::Error::other(...)` we'd otherwise stuff into
//! [`DecodeError::Read`]. The boundary conversion in
//! [`super::Decoder::decode_step`] preserves the message via the
//! `#[source]` chain so end-user log output remains diagnosable.

use std::io;

use thiserror::Error;

use crate::decode::DecodeError;

/// Errors produced inside the hand-rolled zstd decoder.
///
/// Variants are grouped by which RFC 8478 layer surfaced the
/// failure (frame header, block header, content checksum) so test
/// assertions and `tracing` fields can target the right layer
/// without parsing message strings.
#[derive(Debug, Error)]
pub enum ZstdError {
    /// Input source surfaced an underlying IO error while the
    /// decoder was reading more bytes. Distinct from "the bytes we
    /// read were malformed."
    #[error("zstd decoder source IO failed")]
    SourceIo(#[source] io::Error),

    /// The sink we were writing decoded output into rejected a
    /// write. Surfaces as [`DecodeError::Write`] so the extractor's
    /// sink-error path (`src/extractor.rs`) can recover the typed
    /// `SinkError` the adapter captured.
    #[error("zstd decoder sink IO failed")]
    SinkIo(#[source] io::Error),

    /// The initial 4-byte magic did not match a known frame magic
    /// (regular `0xFD2FB528` LE or skippable `0x184D2A50..=0x184D2A5F`).
    #[error("zstd: bad frame magic 0x{magic:08X}")]
    BadMagic {
        /// Little-endian 4-byte value read from the stream.
        magic: u32,
    },

    /// A frame header field violated the spec.
    #[error("zstd: malformed frame header: {0}")]
    MalformedFrameHeader(&'static str),

    /// A frame declared a feature this decoder doesn't yet support.
    /// Distinct from "malformed" so callers can render an actionable
    /// "use the upstream `zstd` crate as a fallback" hint.
    #[error("zstd: unsupported frame feature: {0}")]
    UnsupportedFrameFeature(&'static str),

    /// A block header used the reserved block-type value `3`
    /// (RFC 8478 §3.1.1.2).
    #[error("zstd: reserved block type")]
    ReservedBlockType,

    /// A block declared an on-the-wire size larger than the
    /// 128 KiB cap RFC 8478 §3.1.1.2 imposes on every block type.
    #[error("zstd: block size {size} exceeds RFC 8478 cap of {cap} bytes")]
    BlockTooLarge {
        /// Size declared by the block header.
        size: u32,
        /// The 128 KiB RFC cap.
        cap: u32,
    },

    /// The source ended before a structurally complete piece of
    /// input had been consumed (frame header truncated, block
    /// header truncated, etc.). Carries a short human-readable
    /// label naming what was being parsed.
    #[error("zstd: unexpected EOF while reading {0}")]
    UnexpectedEof(&'static str),

    /// `Compressed_Block` reached a block whose decoding the
    /// hand-rolled decoder hasn't yet been taught. Used as a
    /// deliberate Phase-1 placeholder per
    /// `docs/PLAN_zstd_block_decoder.md` §Phase 1; removed in
    /// Phase 5 once sequence execution lands.
    #[error("zstd: compressed block decoding not yet implemented")]
    CompressedBlockUnimplemented,

    /// The frame's trailing 4-byte content checksum did not match
    /// the low 32 bits of the XXH64 we computed over the
    /// decompressed output (RFC 8478 §3.1.1.1.1, `Content_Checksum_Flag`).
    /// Indicates either source corruption or a decoder bug — either
    /// way the output is not safe to consume.
    #[error("zstd: content-checksum mismatch (expected 0x{expected:08X}, got 0x{got:08X})")]
    ChecksumMismatch {
        /// Low 32 bits of the trailer the producer wrote.
        expected: u32,
        /// Low 32 bits of the XXH64 we computed.
        got: u32,
    },

    /// The frame declared a `Frame_Content_Size` in its header but
    /// the actual byte count we decoded didn't match it
    /// (RFC 8478 §3.1.1.1.4). Distinct from `ChecksumMismatch`
    /// because it surfaces even on frames without a checksum, and
    /// can be diagnosed independently of the XXH64 verifier.
    #[error("zstd: Frame_Content_Size mismatch (declared {declared}, decoded {actual})")]
    FrameContentSizeMismatch {
        /// Bytes the header promised would emerge from the frame.
        declared: u64,
        /// Bytes our sequence executor actually wrote.
        actual: u64,
    },
}

impl ZstdError {
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
            ZstdError::SourceIo(source) => DecodeError::Read { consumed, source },
            ZstdError::SinkIo(source) => DecodeError::Write(source),
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
    fn bad_magic_renders_hex() {
        let e = ZstdError::BadMagic { magic: 0xDEAD_BEEF };
        assert_eq!(e.to_string(), "zstd: bad frame magic 0xDEADBEEF");
    }

    #[test]
    fn into_decode_error_preserves_consumed_and_message() {
        let e = ZstdError::ReservedBlockType;
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
        match ZstdError::SourceIo(inner).into_decode_error(7) {
            DecodeError::Read { consumed, source } => {
                assert_eq!(consumed, 7);
                assert_eq!(source.kind(), io::ErrorKind::ConnectionAborted);
            }
            other => panic!("expected Read, got {other:?}"),
        }
    }
}
