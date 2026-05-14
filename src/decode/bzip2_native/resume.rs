//! Resume-blob serialization for the hand-rolled bzip2 decoder.
//!
//! `internal/PLAN_bz2_support.md` Phase 8. The blob is captured at
//! every per-block frame boundary inside a stream — the only point
//! where every block-internal scratch (BWT table, MTF state,
//! Huffman tables) is freshly empty by spec, so the blob only has
//! to carry the cross-block state:
//!
//! - `bit_cursor`: the source byte position the bit cursor is
//!   currently inside, plus the bit-offset within that byte. Bzip2
//!   block boundaries are bit-aligned (not byte-aligned), so the
//!   bit-offset is mandatory.
//! - `stream_crc`: running CRC accumulator across all blocks
//!   decoded so far in the current stream. Resets at every stream
//!   boundary.
//! - `rle1_last` / `rle1_run`: cross-block RLE1 state (the
//!   stream-level RLE1 inverse is stateful and carries across
//!   blocks within a stream).
//! - `level`: stream-header level byte. Needed to compute the
//!   per-block symbol ceiling for the resumed block.

use std::io::Read;

use crate::decode::{DecodeError, StreamingDecoder};

use super::bitstream::BitReader;
use super::error::Bzip2Error;
use super::{Bzip2Decoder, State};

/// 4-byte magic prefix that identifies a bzip2 resume blob to
/// downstream tooling (mismatches surface as
/// [`Bzip2Error::ResumeBlob`] before any other state is touched).
pub const RESUME_MAGIC: [u8; 4] = *b"PB2R";

/// Wire-format version. Bump only when the blob layout changes.
pub const RESUME_VERSION: u8 = 0x01;

/// Total on-wire blob size in bytes.
pub const RESUME_BLOB_SIZE: usize = 25;

/// Parsed resume blob fields.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Bzip2ResumeState {
    /// Stream-header level byte, in `1..=9`.
    pub level: u8,
    /// Source byte the bit cursor is currently inside.
    pub byte_offset: u64,
    /// Bit offset within `byte_offset`, in `0..=7`.
    pub bit_offset: u8,
    /// Running stream-CRC accumulator (the post-finalize value, the
    /// way [`crate::hash::crc32_bzip2::combine_stream`] combines).
    pub stream_crc: u32,
    /// Cross-block RLE1 state: last emitted byte.
    pub rle1_last: u8,
    /// Cross-block RLE1 state: consecutive-byte count in `0..=4`.
    pub rle1_run: u8,
}

impl Bzip2ResumeState {
    /// Serialize this state to the on-wire blob bytes. Always
    /// appends exactly [`RESUME_BLOB_SIZE`] bytes to `out`.
    pub fn serialize_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&RESUME_MAGIC);
        out.push(RESUME_VERSION);
        out.push(self.level);
        out.push(self.bit_offset);
        out.extend_from_slice(&self.byte_offset.to_le_bytes());
        out.extend_from_slice(&self.stream_crc.to_le_bytes());
        out.push(self.rle1_last);
        out.push(self.rle1_run);
        // Reserved bytes (zero, for forward compatibility).
        out.extend_from_slice(&[0u8; 4]);
    }

    /// Parse a blob from `bytes`. Length must equal
    /// [`RESUME_BLOB_SIZE`] exactly.
    ///
    /// # Errors
    ///
    /// - [`Bzip2Error::ResumeBlob`] for any structural failure
    ///   (bad magic, wrong version, out-of-range fields).
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Bzip2Error> {
        if bytes.len() != RESUME_BLOB_SIZE {
            return Err(Bzip2Error::ResumeBlob("blob size mismatch"));
        }
        if bytes[0..4] != RESUME_MAGIC {
            return Err(Bzip2Error::ResumeBlob("bad magic prefix"));
        }
        if bytes[4] != RESUME_VERSION {
            return Err(Bzip2Error::ResumeBlob("unsupported version"));
        }
        let level = bytes[5];
        if !(1..=9).contains(&level) {
            return Err(Bzip2Error::ResumeBlob("level outside 1..=9"));
        }
        let bit_offset = bytes[6];
        if bit_offset > 7 {
            return Err(Bzip2Error::ResumeBlob("bit_offset outside 0..=7"));
        }
        // INVARIANT: bytes.len() == 25 checked above; the field
        // slices are in range.
        let byte_offset = u64::from_le_bytes(bytes[7..15].try_into().unwrap_or([0; 8]));
        let stream_crc = u32::from_le_bytes(bytes[15..19].try_into().unwrap_or([0; 4]));
        let rle1_last = bytes[19];
        let rle1_run = bytes[20];
        if rle1_run > 4 {
            return Err(Bzip2Error::ResumeBlob("rle1_run outside 0..=4"));
        }
        // Reserved bytes 21..25 are ignored; future revisions can
        // require non-zero values to opt in to new fields.
        Ok(Self {
            level,
            byte_offset,
            bit_offset,
            stream_crc,
            rle1_last,
            rle1_run,
        })
    }
}

/// Parse the blob and cross-check it against `start_offset`.
/// `start_offset` is the source byte the wrapped reader will deliver
/// first — must equal the blob's `byte_offset`.
///
/// # Errors
///
/// - [`DecodeError::ResumeMismatch`] when `start_offset !=
///   blob.byte_offset`.
/// - [`DecodeError::Construct`] when the blob itself is malformed.
pub fn deserialize_at_boundary(
    blob: &[u8],
    start_offset: u64,
) -> Result<Bzip2ResumeState, DecodeError> {
    let state = Bzip2ResumeState::deserialize(blob)
        .map_err(|e| DecodeError::Construct(std::io::Error::other(e.to_string())))?;
    if state.byte_offset != start_offset {
        return Err(DecodeError::ResumeMismatch {
            expected: state.byte_offset,
            actual: start_offset,
        });
    }
    Ok(state)
}

/// Build a [`Bzip2Decoder`] pre-seeded from `state` and positioned
/// to deliver byte-identical output past the saved boundary.
///
/// `start_offset` must equal `state.byte_offset` (already verified
/// by [`deserialize_at_boundary`] when the public
/// [`resume_factory`] entry point is used).
fn resume(src: Box<dyn Read + Send>, state: Bzip2ResumeState) -> Result<Bzip2Decoder, DecodeError> {
    let mut bits = BitReader::new_at(src, state.byte_offset);
    // Skip the consumed-bits prefix of the first delivered byte so
    // the cursor lands on the boundary bit-offset captured by the
    // blob.
    if state.bit_offset > 0 {
        bits.read_bits(u32::from(state.bit_offset)).map_err(|e| {
            DecodeError::Construct(std::io::Error::other(format!(
                "bzip2 resume: cannot skip bit_offset: {e}"
            )))
        })?;
    }
    let mut decoder = Bzip2Decoder {
        bits,
        state: State::AwaitingBlockMarker { level: state.level },
        stream_crc: state.stream_crc,
        rle1: super::rle1::Rle1State::new(),
        last_frame_boundary: Some(crate::types::ByteOffset::new(state.byte_offset)),
    };
    // INVARIANT: rle1_run <= 4 by deserialize validation.
    decoder
        .rle1
        .set(state.rle1_last, state.rle1_run)
        .map_err(|e| {
            DecodeError::Construct(std::io::Error::other(format!(
                "bzip2 resume: invalid rle1 state: {e}"
            )))
        })?;
    Ok(decoder)
}

/// [`crate::decode::DecoderResumeFactory`] adapter for the hand-
/// rolled bzip2 decoder.
///
/// # Errors
///
/// - [`DecodeError::Construct`] on structurally malformed blob.
/// - [`DecodeError::ResumeMismatch`] when the seeded `start_offset`
///   disagrees with the blob's captured cursor.
pub fn resume_factory(
    src: Box<dyn Read + Send>,
    state_blob: &[u8],
    start_offset: u64,
) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    let state = deserialize_at_boundary(state_blob, start_offset)?;
    Ok(Box::new(resume(src, state)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_serialize_deserialize() {
        let state = Bzip2ResumeState {
            level: 9,
            byte_offset: 0x1234_5678_9ABC_DEF0,
            bit_offset: 5,
            stream_crc: 0xDEAD_BEEF,
            rle1_last: 0x42,
            rle1_run: 3,
        };
        let mut blob = Vec::new();
        state.serialize_into(&mut blob);
        assert_eq!(blob.len(), RESUME_BLOB_SIZE);
        let parsed = Bzip2ResumeState::deserialize(&blob).expect("parse");
        assert_eq!(parsed, state);
    }

    #[test]
    fn bad_magic_rejected() {
        let mut blob = vec![0u8; RESUME_BLOB_SIZE];
        blob[0..4].copy_from_slice(b"XXXX");
        match Bzip2ResumeState::deserialize(&blob) {
            Err(Bzip2Error::ResumeBlob(msg)) => assert!(msg.contains("magic")),
            other => panic!("expected ResumeBlob, got {other:?}"),
        }
    }

    #[test]
    fn bad_version_rejected() {
        let mut blob = vec![0u8; RESUME_BLOB_SIZE];
        blob[0..4].copy_from_slice(&RESUME_MAGIC);
        blob[4] = 0xFF;
        match Bzip2ResumeState::deserialize(&blob) {
            Err(Bzip2Error::ResumeBlob(msg)) => assert!(msg.contains("version")),
            other => panic!("expected ResumeBlob, got {other:?}"),
        }
    }

    #[test]
    fn level_zero_rejected() {
        let state = Bzip2ResumeState {
            level: 0,
            byte_offset: 0,
            bit_offset: 0,
            stream_crc: 0,
            rle1_last: 0,
            rle1_run: 0,
        };
        let mut blob = Vec::new();
        state.serialize_into(&mut blob);
        match Bzip2ResumeState::deserialize(&blob) {
            Err(Bzip2Error::ResumeBlob(msg)) => assert!(msg.contains("level")),
            other => panic!("expected ResumeBlob, got {other:?}"),
        }
    }

    #[test]
    fn bit_offset_out_of_range_rejected() {
        let mut blob = Vec::new();
        Bzip2ResumeState {
            level: 9,
            byte_offset: 0,
            bit_offset: 0,
            stream_crc: 0,
            rle1_last: 0,
            rle1_run: 0,
        }
        .serialize_into(&mut blob);
        blob[6] = 8;
        match Bzip2ResumeState::deserialize(&blob) {
            Err(Bzip2Error::ResumeBlob(msg)) => assert!(msg.contains("bit_offset")),
            other => panic!("expected ResumeBlob, got {other:?}"),
        }
    }

    #[test]
    fn rle1_run_out_of_range_rejected() {
        let mut blob = Vec::new();
        Bzip2ResumeState {
            level: 9,
            byte_offset: 0,
            bit_offset: 0,
            stream_crc: 0,
            rle1_last: 0,
            rle1_run: 0,
        }
        .serialize_into(&mut blob);
        blob[20] = 5;
        match Bzip2ResumeState::deserialize(&blob) {
            Err(Bzip2Error::ResumeBlob(msg)) => assert!(msg.contains("rle1_run")),
            other => panic!("expected ResumeBlob, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_at_boundary_rejects_offset_mismatch() {
        let state = Bzip2ResumeState {
            level: 9,
            byte_offset: 100,
            bit_offset: 0,
            stream_crc: 0,
            rle1_last: 0,
            rle1_run: 0,
        };
        let mut blob = Vec::new();
        state.serialize_into(&mut blob);
        match deserialize_at_boundary(&blob, 99) {
            Err(DecodeError::ResumeMismatch { expected, actual }) => {
                assert_eq!(expected, 100);
                assert_eq!(actual, 99);
            }
            other => panic!("expected ResumeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn size_hint_matches_blob_size() {
        assert_eq!(RESUME_BLOB_SIZE, 25);
    }
}
