//! Local error type for the liblzma-port decoder.
//!
//! Phase 1 of [`docs/PLAN_xz_liblzma_port.md`](../../../../docs/PLAN_xz_liblzma_port.md).
//! Mirrors the structure of [`super::super::xz_native::error::XzError`]
//! but is a separate type so the two decoders can evolve
//! independently. Phase 1 only populates the range-coder /
//! LZMA-model variants; Stream / Block / LZMA2 variants land in
//! Phase 6.
//!
//! Per `docs/ENGINEERING_BEST_PRACTICES.md` §3.1: errors are
//! documentation; structured variants beat opaque `io::Error`
//! payloads at debug time.
//!
//! Conversion into [`crate::decode::DecodeError`] happens at the
//! [`crate::decode::StreamingDecoder`] boundary the public
//! `Decoder` exposes (Phase 6).

use std::io;

use thiserror::Error;

/// Errors produced inside the liblzma-port decoder.
///
/// The variants are grouped by spec layer; only the range-coder
/// layer is exercised in Phase 1.
#[derive(Debug, Error)]
pub enum XzPortError {
    /// Input source surfaced an underlying IO error while the
    /// decoder was reading more bytes.
    #[error("xz_liblzma decoder source IO failed")]
    SourceIo(#[source] io::Error),

    /// The sink rejected a write.
    #[error("xz_liblzma decoder sink IO failed")]
    SinkIo(#[source] io::Error),

    /// The range coder ran out of input bytes mid-decode.
    ///
    /// liblzma's equivalent surface is `LZMA_DATA_ERROR` whenever
    /// `rc_normalize`'s `goto out` reaches the end of the chunk
    /// without producing the declared output. Our resume model
    /// (Phase F) will use this to drive an "input-needed" return
    /// in the future.
    #[error("xz_liblzma: range coder underflow at {0}")]
    RangeCoderUnderflow(&'static str),

    /// The range coder's leading marker byte was not `0x00`.
    /// liblzma's `rc_read_init` rejects any non-zero leading byte
    /// in the first 5-byte init prefix; mirrored here.
    #[error("xz_liblzma: range coder init marker non-zero (got 0x{0:02X})")]
    RangeCoderInitMarker(u8),

    /// The range coder did not finish in the spec's
    /// "code == 0" state at chunk end.
    ///
    /// Surfaces a corrupt stream when the LZMA model has consumed
    /// all input but the range coder's residual `code` is non-zero
    /// (per the LZMA spec, this state is reserved as a corruption
    /// detector).
    #[error("xz_liblzma: range coder unfinished (code=0x{code:08X})")]
    RangeCoderUnfinished {
        /// The non-zero `code` value at chunk end.
        code: u32,
    },

    /// A match (fresh-distance, rep0, rep1, rep2, or rep3) had a
    /// distance value that exceeds available history. liblzma's
    /// equivalent is `LZMA_DATA_ERROR` from
    /// `dict_is_distance_valid`.
    #[error("xz_liblzma: match distance out of range (dist={dist})")]
    MatchOutOfRange {
        /// The decoded distance the LZMA model produced.
        dist: u32,
    },

    /// LZMA1 end-of-payload marker (encoded distance `u32::MAX`)
    /// hit when `uncompressed_size` was known. Mirror of
    /// liblzma's `ret = LZMA_DATA_ERROR; goto out;` at the EOPM
    /// path.
    #[error("xz_liblzma: unexpected end-of-payload marker")]
    UnexpectedEopm,

    /// Phase 3-only limitation: the dispatch loop entered with
    /// a `Sequence` cursor pointing at a mid-symbol resume
    /// position. Round-one of the port doesn't support resume
    /// (the test fixtures feed full payloads at once); Phase F
    /// implements the resume arms.
    #[error("xz_liblzma: mid-symbol resume not supported in round one (sequence={sequence:?})")]
    ResumeNotSupported {
        /// The unsupported [`super::decoder::Sequence`] variant
        /// the caller's saved state pointed at.
        sequence: super::decoder::Sequence,
    },

    /// LZMA2 chunk framing produced an error. Round-one
    /// borrows
    /// [`crate::decode::xz_native::block::parse_lzma2_chunk_header`]
    /// for chunk parsing; its [`crate::decode::xz_native::error::XzError`]
    /// values are surfaced here as a string. Phase 6 ports the
    /// framing parsers into `xz_liblzma` directly and gives
    /// these structured variants.
    #[error("xz_liblzma: LZMA2 framing error: {0}")]
    Framing(String),

    /// The first LZMA2 chunk in a Block didn't request a
    /// dict reset. liblzma rejects this; the spec requires
    /// the first chunk to be one of the dict-resetting modes
    /// (`0x01` uncompressed-with-reset or `0xE0..=0xFF` LZMA-
    /// with-full-reset).
    #[error("xz_liblzma: first LZMA2 chunk did not reset the dictionary (control byte 0x{0:02X})")]
    FirstChunkMustResetDict(u8),

    /// An LZMA chunk demands an `lc/lp/pb` properties byte
    /// (because the prior chunk reset state, or this is the
    /// first chunk) but the chunk header didn't carry one.
    /// Mirror of liblzma's `LZMA_DATA_ERROR` in the same
    /// conditional.
    #[error("xz_liblzma: LZMA2 chunk needs properties byte but didn't reset_props")]
    ChunkNeedsProperties,

    /// The range coder didn't end in the spec's "well-finished"
    /// state at chunk end (`code != 0` or unconsumed input
    /// bytes). Mirror of liblzma's
    /// `LZMA_DATA_ERROR` from the same check.
    #[error(
        "xz_liblzma: LZMA2 chunk range coder unfinished \
         (code=0x{code:08X}, leftover={leftover})"
    )]
    ChunkRangeCoderUnfinished {
        /// The non-zero `code` value at chunk end (or `0` if
        /// the leftover-bytes check is what fired).
        code: u32,
        /// Bytes left unconsumed in the chunk's compressed
        /// payload after decode.
        leftover: usize,
    },

    /// LZMA2 chunk payload was shorter than the chunk
    /// header's declared `compressed_size`.
    #[error(
        "xz_liblzma: LZMA2 chunk truncated (declared {compressed_size} bytes, \
         {available} available)"
    )]
    ChunkTruncated {
        /// `compressed_size` from the chunk header.
        compressed_size: u32,
        /// Bytes actually available in the input slice.
        available: usize,
    },
}

// --- conversion from the framing-layer parsers' XzError ---

impl From<super::xz_error::XzError> for XzPortError {
    fn from(e: super::xz_error::XzError) -> Self {
        XzPortError::Framing(format!("{e}"))
    }
}
