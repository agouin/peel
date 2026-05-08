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
}
