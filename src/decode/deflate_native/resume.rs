//! Resume blob format for the hand-rolled deflate / gzip /
//! zip-DEFLATE decoders.
//!
//! Mirrors the lz4 / zstd / xz resume contracts: a checkpoint
//! captures an opaque blob via
//! [`crate::decode::StreamingDecoder::decoder_state`]; resume
//! reconstructs a decoder pre-seeded with that blob via the
//! registered [`crate::decode::DecoderResumeFactory`]. The
//! deflate-native module emits one of three blob shapes
//! depending on which framing layer is active:
//!
//! - `Container::RawDeflate` (0): the [`super::Decoder`] (raw
//!   deflate body) emitted the blob. `running_crc32` and
//!   `total_decompressed_in_member` are both 0; the resumer
//!   skips them.
//! - `Container::Gzip` (1): the [`super::gzip::GzipDecoder`]
//!   emitted the blob mid-member. The wrapper's running CRC32
//!   and per-member byte count are captured for trailer
//!   validation on resume.
//! - `Container::ZipDeflate` (2): emitted by the zip pipeline
//!   in Phase 9. Same layout as `Gzip` but with the running
//!   CRC32 over the entry's decompressed bytes (zip records
//!   per-entry CRC32 in the central directory).
//!
//! # Layout (format_version = 1)
//!
//! ```text
//!  off  size  field
//!  ---  ----  -----
//!   0   4     magic = b"DDR1"
//!   4   1     format_version (1)
//!   5   1     container (0=raw deflate, 1=gzip, 2=zip-DEFLATE)
//!   6   1     bit_offset_in_first_byte (0..=7)
//!   7   8     source_byte_position (u64 LE — first byte the
//!             resumed reader will deliver; equals the
//!             checkpoint's `decoder_position`)
//!  15   2     window_filled (u16 LE; 0..=32 768)
//!  17   N     window_contents (N = window_filled bytes; the
//!             chronological tail of the sliding window)
//!  17+N 8     total_decompressed (u64 LE; cumulative for raw
//!             deflate / per-member for gzip / per-entry for
//!             zip-DEFLATE)
//!  25+N 4     running_crc32 (u32 LE; 0 for raw deflate;
//!             `Crc32::current()` for gzip / zip-DEFLATE)
//!  29+N 1     bfinal_seen (reserved for the mid-final-block
//!             resume case; always 0 in the round-one
//!             implementation, which checkpoints only at
//!             AwaitingBlockType where no block has yet been
//!             started)
//! ```
//!
//! Total worst-case size: ~33 KiB (window_filled = 32 768 +
//! ~30 bytes of fixed framing). Three orders of magnitude
//! smaller than the zstd plan's 128 MiB ceiling; per-checkpoint
//! write cost is negligible against the existing 8 MiB cadence
//! floor (`docs/PLAN_deflate_block_decoder.md` §Phase 7
//! commentary).

use std::io;

use crate::decode::DecodeError;

use super::error::DeflateError;
use super::window::MAX_WINDOW_SIZE;

/// Magic bytes that identify a deflate-native resume blob.
/// "DDR1" = "Deflate Decoder Resume v1".
pub const RESUME_MAGIC: [u8; 4] = *b"DDR1";

/// Format version this build writes. Bumped when the layout
/// changes; older blobs are rejected at deserialize time with
/// [`DeflateError::ResumeBlob`].
pub const RESUME_FORMAT_VERSION: u8 = 1;

/// Fixed prefix length: magic (4) + format_version (1) +
/// container (1) + bit_offset (1) + source_byte_position (8) +
/// window_filled (2) = 17 bytes.
const FIXED_PREFIX_LEN: usize = 17;

/// Suffix after the variable-length window contents:
/// total_decompressed (8) + running_crc32 (4) + bfinal_seen (1)
/// = 13 bytes.
const FIXED_SUFFIX_LEN: usize = 13;

/// Which container framing layer emitted this blob. The resumer
/// validates this matches the layer it's trying to resume into:
/// a raw-deflate factory rejects a gzip-shaped blob and vice
/// versa.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum Container {
    /// [`super::Decoder`] — raw deflate stream, no framing.
    RawDeflate = 0,
    /// [`super::gzip::GzipDecoder`] — gzip member envelope (RFC 1952).
    Gzip = 1,
    /// Phase 9 zip-DEFLATE entry. Reserved here so the blob
    /// format covers all three layers from the start; populated
    /// when the zip pipeline lands resume support.
    ZipDeflate = 2,
}

impl Container {
    fn from_byte(b: u8) -> Result<Self, DeflateError> {
        match b {
            0 => Ok(Container::RawDeflate),
            1 => Ok(Container::Gzip),
            2 => Ok(Container::ZipDeflate),
            _ => Err(DeflateError::ResumeBlob("unknown container byte")),
        }
    }
}

/// Parsed view of a resume blob. See the module-level layout
/// commentary for field semantics.
#[derive(Debug, Clone)]
pub struct DflResumeState {
    /// Which framing layer emitted the blob.
    pub container: Container,
    /// Source byte position the resumed bit reader will deliver
    /// first. Equals the checkpoint's `decoder_position`.
    pub source_byte_position: u64,
    /// Bits already consumed from the first delivered byte; the
    /// resumed bit reader skips them so the cursor lands at the
    /// captured position.
    pub bit_offset: u8,
    /// Most-recent up-to-32 KiB of decompressed output, in
    /// chronological order. Empty if no bytes have been emitted
    /// yet (in which case `total_decompressed` is also 0).
    pub window_contents: Vec<u8>,
    /// Cumulative decompressed-byte count. For raw deflate, the
    /// stream's total. For gzip / zip-DEFLATE, the current
    /// member's / entry's total.
    pub total_decompressed: u64,
    /// Running CRC32 (the live `Crc32::current()` value, NOT
    /// finalised). 0 for raw deflate.
    pub running_crc32: u32,
    /// Reserved for the mid-final-block resume case. Always
    /// `false` in the round-one implementation.
    pub bfinal_seen: bool,
}

impl DflResumeState {
    /// Encode the state as a length-prefixed blob.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let n = self.window_contents.len();
        let mut out = Vec::with_capacity(FIXED_PREFIX_LEN + n + FIXED_SUFFIX_LEN);
        out.extend_from_slice(&RESUME_MAGIC);
        out.push(RESUME_FORMAT_VERSION);
        out.push(self.container as u8);
        out.push(self.bit_offset);
        out.extend_from_slice(&self.source_byte_position.to_le_bytes());
        // INVARIANT: `n <= MAX_WINDOW_SIZE = 32 768`, fits in u16.
        out.extend_from_slice(&(n as u16).to_le_bytes());
        out.extend_from_slice(&self.window_contents);
        out.extend_from_slice(&self.total_decompressed.to_le_bytes());
        out.extend_from_slice(&self.running_crc32.to_le_bytes());
        out.push(u8::from(self.bfinal_seen));
        out
    }

    /// Decode a blob produced by [`Self::serialize`].
    ///
    /// # Errors
    ///
    /// - [`DeflateError::ResumeBlob`] for any structural
    ///   violation: short blob, bad magic, unsupported version,
    ///   bit_offset > 7, window_filled > 32 KiB, body shorter
    ///   than the declared window length.
    pub fn deserialize(blob: &[u8]) -> Result<Self, DeflateError> {
        if blob.len() < FIXED_PREFIX_LEN {
            return Err(DeflateError::ResumeBlob("blob shorter than fixed prefix"));
        }
        if blob[..4] != RESUME_MAGIC {
            return Err(DeflateError::ResumeBlob("magic mismatch"));
        }
        if blob[4] != RESUME_FORMAT_VERSION {
            return Err(DeflateError::ResumeBlob("unsupported format version"));
        }
        let container = Container::from_byte(blob[5])?;
        let bit_offset = blob[6];
        if bit_offset > 7 {
            return Err(DeflateError::ResumeBlob("bit_offset > 7"));
        }
        let source_byte_position = u64::from_le_bytes([
            blob[7], blob[8], blob[9], blob[10], blob[11], blob[12], blob[13], blob[14],
        ]);
        let window_filled = u16::from_le_bytes([blob[15], blob[16]]) as usize;
        if window_filled > MAX_WINDOW_SIZE {
            return Err(DeflateError::ResumeBlob("window_filled > MAX_WINDOW_SIZE"));
        }
        let body_start = FIXED_PREFIX_LEN;
        let body_end = body_start + window_filled;
        if blob.len() < body_end + FIXED_SUFFIX_LEN {
            return Err(DeflateError::ResumeBlob(
                "blob shorter than declared window + suffix",
            ));
        }
        let window_contents = blob[body_start..body_end].to_vec();
        let total_decompressed = u64::from_le_bytes([
            blob[body_end],
            blob[body_end + 1],
            blob[body_end + 2],
            blob[body_end + 3],
            blob[body_end + 4],
            blob[body_end + 5],
            blob[body_end + 6],
            blob[body_end + 7],
        ]);
        let running_crc32 = u32::from_le_bytes([
            blob[body_end + 8],
            blob[body_end + 9],
            blob[body_end + 10],
            blob[body_end + 11],
        ]);
        let bfinal_seen = blob[body_end + 12] != 0;
        // `total_decompressed >= window_contents.len()` invariant
        // — the snapshot can never carry more bytes than the
        // window has ever seen.
        if total_decompressed < window_contents.len() as u64 {
            return Err(DeflateError::ResumeBlob(
                "total_decompressed < window_contents length",
            ));
        }

        Ok(Self {
            container,
            source_byte_position,
            bit_offset,
            window_contents,
            total_decompressed,
            running_crc32,
            bfinal_seen,
        })
    }
}

/// Peek the blob's `source_byte_position` field without
/// fully deserializing — useful for the zip pipeline, which
/// needs to know where in the compressed stream the resumed
/// codec expects to pick up so it can position its source
/// reader. Returns `None` if the blob is too short to carry the
/// field; in that case the caller surfaces a typed error via the
/// regular [`DflResumeState::deserialize`] path.
#[must_use]
pub fn peek_source_byte_position(blob: &[u8]) -> Option<u64> {
    if blob.len() < FIXED_PREFIX_LEN || blob[..4] != RESUME_MAGIC {
        return None;
    }
    Some(u64::from_le_bytes([
        blob[7], blob[8], blob[9], blob[10], blob[11], blob[12], blob[13], blob[14],
    ]))
}

/// Convenience: deserialize a blob and translate any error into
/// [`DecodeError::Construct`] with a leading "deflate resume blob
/// rejected:" prefix. Used by the resume factories so callers see
/// a uniform error type at the trait boundary.
pub(super) fn deserialize_at_boundary(
    blob: &[u8],
    start_offset: u64,
) -> Result<DflResumeState, DecodeError> {
    let state = DflResumeState::deserialize(blob).map_err(|e| {
        DecodeError::Construct(io::Error::other(format!(
            "deflate resume blob rejected: {e}"
        )))
    })?;
    if state.source_byte_position != start_offset {
        return Err(DecodeError::ResumeMismatch {
            expected: state.source_byte_position,
            actual: start_offset,
        });
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(state: &DflResumeState) {
        let blob = state.serialize();
        let parsed = DflResumeState::deserialize(&blob).expect("round-trip parse");
        assert_eq!(parsed.container, state.container);
        assert_eq!(parsed.source_byte_position, state.source_byte_position);
        assert_eq!(parsed.bit_offset, state.bit_offset);
        assert_eq!(parsed.window_contents, state.window_contents);
        assert_eq!(parsed.total_decompressed, state.total_decompressed);
        assert_eq!(parsed.running_crc32, state.running_crc32);
        assert_eq!(parsed.bfinal_seen, state.bfinal_seen);
    }

    #[test]
    fn round_trip_empty_window() {
        round_trip(&DflResumeState {
            container: Container::RawDeflate,
            source_byte_position: 0,
            bit_offset: 0,
            window_contents: Vec::new(),
            total_decompressed: 0,
            running_crc32: 0,
            bfinal_seen: false,
        });
    }

    #[test]
    fn round_trip_short_window() {
        round_trip(&DflResumeState {
            container: Container::Gzip,
            source_byte_position: 12_345,
            bit_offset: 5,
            window_contents: b"the quick brown fox".to_vec(),
            total_decompressed: 19,
            running_crc32: 0xCAFE_BABE,
            bfinal_seen: false,
        });
    }

    #[test]
    fn round_trip_full_window() {
        let mut window = vec![0u8; MAX_WINDOW_SIZE];
        for (i, b) in window.iter_mut().enumerate() {
            *b = (i & 0xFF) as u8;
        }
        round_trip(&DflResumeState {
            container: Container::Gzip,
            source_byte_position: 100_000,
            bit_offset: 3,
            window_contents: window,
            total_decompressed: 1_000_000,
            running_crc32: 0xDEAD_BEEF,
            bfinal_seen: false,
        });
    }

    #[test]
    fn round_trip_zip_deflate_container() {
        round_trip(&DflResumeState {
            container: Container::ZipDeflate,
            source_byte_position: 7,
            bit_offset: 0,
            window_contents: b"abc".to_vec(),
            total_decompressed: 3,
            running_crc32: 0x1234_5678,
            bfinal_seen: false,
        });
    }

    #[test]
    fn deserialize_rejects_short_blob() {
        match DflResumeState::deserialize(&[0u8; 5]) {
            Err(DeflateError::ResumeBlob(msg)) => assert!(msg.contains("fixed prefix")),
            other => panic!("expected ResumeBlob, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_bad_magic() {
        let mut blob = vec![0u8; FIXED_PREFIX_LEN + FIXED_SUFFIX_LEN];
        blob[..4].copy_from_slice(b"BADM");
        match DflResumeState::deserialize(&blob) {
            Err(DeflateError::ResumeBlob(msg)) => assert!(msg.contains("magic")),
            other => panic!("expected ResumeBlob, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_unsupported_version() {
        let mut blob = DflResumeState {
            container: Container::RawDeflate,
            source_byte_position: 0,
            bit_offset: 0,
            window_contents: Vec::new(),
            total_decompressed: 0,
            running_crc32: 0,
            bfinal_seen: false,
        }
        .serialize();
        blob[4] = 0xFF;
        match DflResumeState::deserialize(&blob) {
            Err(DeflateError::ResumeBlob(msg)) => assert!(msg.contains("version")),
            other => panic!("expected ResumeBlob, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_bit_offset_above_seven() {
        let mut blob = DflResumeState {
            container: Container::RawDeflate,
            source_byte_position: 0,
            bit_offset: 0,
            window_contents: Vec::new(),
            total_decompressed: 0,
            running_crc32: 0,
            bfinal_seen: false,
        }
        .serialize();
        blob[6] = 8;
        match DflResumeState::deserialize(&blob) {
            Err(DeflateError::ResumeBlob(msg)) => assert!(msg.contains("bit_offset")),
            other => panic!("expected ResumeBlob, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_total_below_window_length() {
        let mut state = DflResumeState {
            container: Container::Gzip,
            source_byte_position: 0,
            bit_offset: 0,
            window_contents: b"abc".to_vec(),
            total_decompressed: 2,
            running_crc32: 0,
            bfinal_seen: false,
        };
        let blob = state.serialize();
        match DflResumeState::deserialize(&blob) {
            Err(DeflateError::ResumeBlob(msg)) => {
                assert!(msg.contains("total_decompressed"));
            }
            other => panic!("expected ResumeBlob, got {other:?}"),
        }
        // Sanity: the serialize-deserialize round trip works when
        // total_decompressed >= window_contents length.
        state.total_decompressed = 3;
        round_trip(&state);
    }
}
