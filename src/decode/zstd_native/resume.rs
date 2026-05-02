//! Mid-frame resume blob for the hand-rolled zstd decoder
//! (`docs/PLAN_zstd_block_decoder.md` §Phase 7).
//!
//! The streaming decoder pauses at every block boundary inside a
//! frame and reports a [`crate::decode::StreamingDecoder::decoder_state`]
//! blob; the coordinator persists that blob alongside the
//! [`crate::decode::StreamingDecoder::frame_boundary`] offset in the
//! checkpoint. After a `kill -9`, [`super::Decoder::resume`] rebuilds a
//! decoder from the saved blob plus a fresh source positioned at the
//! checkpointed offset, and the decoded output continues
//! byte-identically.
//!
//! # Wire layout (round one — `format_version = 1`)
//!
//! ```text
//!  4 B  magic = b"ZDR1"
//!  1 B  format_version (1)
//!
//!  -- Frame header restoration --
//!  8 B  window_size (u64 LE)
//!  1 B  has_checksum (0/1)
//!  1 B  has_fcs (0/1)
//!  8 B  fcs value (u64 LE; 0 if !has_fcs)
//!  8 B  decoded_in_frame (u64 LE)
//!  8 B  frame_start_offset (u64 LE — diagnostic only)
//!
//!  -- Sliding window --
//!  8 B  total_written (u64 LE)
//!  4 B  window_data_len (u32 LE; ≤ window_size, capped 128 MiB)
//!  N B  window data (chronological order, oldest first)
//!
//!  -- Repeat offsets --
//!  3 × 4 B  repeat_offsets (u32 LE each)
//!
//!  -- Prior Huffman tree --
//!  1 B  has_prev_huffman (0/1)
//!  if present:
//!      2 B  weights_len (u16 LE; ≤ 256)
//!      M B  weights (1 byte per symbol; absent symbols → 0)
//!
//!  -- Prior FSE tables (LL, OF, ML in this order) --
//!  per table:
//!      1 B  has_prev (0/1)
//!      if present:
//!          1 B  accuracy_log
//!          4 B  cell_count (u32 LE; 1 << accuracy_log, or 1 if AL=0)
//!          C × 4 B  cells (u8 symbol, u8 num_bits, u16 base_state LE)
//!
//!  -- XXH64 hasher state --
//!  73 B  serialized hasher state (see hash::xxh64::SERIALIZED_LEN)
//! ```
//!
//! Total size is bounded by `window_size + ~10 KiB`. At
//! `windowLog = 27` (128 MiB cap, see `frame.rs::MAX_WINDOW_LOG`)
//! that puts the worst-case blob at 128 MiB plus change; smaller
//! windows produce proportionally smaller blobs.

use std::io::Read;

use crate::decode::DecodeError;
use crate::decode::StreamingDecoder;
use crate::hash::xxh64::{self, Xxh64};

use super::error::ZstdError;
use super::frame::{FrameHeader, MAX_WINDOW_LOG};
use super::fse::{FseCell, FseTable, MAX_FSE_ACCURACY_LOG};
use super::huffman::HuffmanTree;
use super::sequences::{PrevSequenceTables, RepeatOffsets};
use super::window::{SlidingWindow, MAX_WINDOW_SIZE};
use super::{Decoder, FrameDecodeState, State};

/// Magic prefix identifying a Phase-7 zstd resume blob.
pub const RESUME_MAGIC: [u8; 4] = *b"ZDR1";

/// Current resume-blob format version. Bump on any layout change so
/// stale blobs surface a clean rejection instead of silently
/// corrupting decode.
pub const RESUME_FORMAT_V1: u8 = 1;

/// All the fields the Phase-7 resume blob captures, in a flat struct
/// the serializer/deserializer can crunch without poking through the
/// live decoder.
pub(super) struct ZstdResumeState {
    pub window_size: u64,
    pub has_checksum: bool,
    pub fcs: Option<u64>,
    pub decoded_in_frame: u64,
    pub frame_start_offset: u64,
    pub window_total_written: u64,
    pub window_recent: Vec<u8>,
    pub repeats: [u32; 3],
    pub prev_huffman_weights: Option<Vec<u8>>,
    pub prev_ll: Option<SerializedFseTable>,
    pub prev_of: Option<SerializedFseTable>,
    pub prev_ml: Option<SerializedFseTable>,
    pub xxh64_state: [u8; xxh64::SERIALIZED_LEN],
}

/// One FSE table in serialization-friendly form. Round-trips through
/// [`FseTable::cells_view`] / [`FseTable::from_raw_cells`].
pub(super) struct SerializedFseTable {
    pub accuracy_log: u32,
    pub cells: Vec<FseCell>,
}

impl ZstdResumeState {
    /// Encode the state into the wire format documented at the top
    /// of this module.
    pub(super) fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&RESUME_MAGIC);
        out.push(RESUME_FORMAT_V1);

        // Frame-header restoration block.
        out.extend_from_slice(&self.window_size.to_le_bytes());
        out.push(u8::from(self.has_checksum));
        out.push(u8::from(self.fcs.is_some()));
        out.extend_from_slice(&self.fcs.unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&self.decoded_in_frame.to_le_bytes());
        out.extend_from_slice(&self.frame_start_offset.to_le_bytes());

        // Sliding window.
        out.extend_from_slice(&self.window_total_written.to_le_bytes());
        // INVARIANT: window_recent.len() ≤ window_size ≤
        // MAX_WINDOW_SIZE = 1 << 27, so the cast cannot truncate.
        out.extend_from_slice(&(self.window_recent.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.window_recent);

        // Repeat offsets.
        for slot in self.repeats {
            out.extend_from_slice(&slot.to_le_bytes());
        }

        // Prior Huffman tree.
        match &self.prev_huffman_weights {
            Some(w) => {
                out.push(1);
                // INVARIANT: w.len() ≤ 256 (one byte per symbol).
                out.extend_from_slice(&(w.len() as u16).to_le_bytes());
                out.extend_from_slice(w);
            }
            None => out.push(0),
        }

        // Prior FSE tables.
        for table in [&self.prev_ll, &self.prev_of, &self.prev_ml] {
            serialize_fse_table(&mut out, table);
        }

        // XXH64 hasher state (fixed 73 bytes).
        out.extend_from_slice(&self.xxh64_state);

        out
    }

    /// Decode a wire-format blob produced by [`Self::serialize`].
    pub(super) fn deserialize(bytes: &[u8]) -> Result<Self, &'static str> {
        let mut r = ByteReader::new(bytes);
        let magic = r.read_array::<4>()?;
        if magic != RESUME_MAGIC {
            return Err("zstd resume: bad magic");
        }
        let version = r.read_u8()?;
        if version != RESUME_FORMAT_V1 {
            return Err("zstd resume: unknown format version");
        }

        let window_size = r.read_u64()?;
        if window_size == 0 || window_size > MAX_WINDOW_SIZE {
            return Err("zstd resume: window_size out of range");
        }
        let has_checksum = r.read_bool("has_checksum")?;
        let has_fcs = r.read_bool("has_fcs")?;
        let fcs_value = r.read_u64()?;
        let fcs = if has_fcs { Some(fcs_value) } else { None };
        let decoded_in_frame = r.read_u64()?;
        let frame_start_offset = r.read_u64()?;

        let window_total_written = r.read_u64()?;
        let window_data_len = r.read_u32()? as usize;
        if window_data_len as u64 > window_size {
            return Err("zstd resume: window snapshot longer than window_size");
        }
        let window_recent = r.read_slice(window_data_len)?.to_vec();

        let mut repeats = [0u32; 3];
        for slot in &mut repeats {
            *slot = r.read_u32()?;
        }

        let huff_present = r.read_bool("has_prev_huffman")?;
        let prev_huffman_weights = if huff_present {
            let len = r.read_u16()? as usize;
            if len > 256 {
                return Err("zstd resume: huffman weights length > 256");
            }
            Some(r.read_slice(len)?.to_vec())
        } else {
            None
        };

        let prev_ll = deserialize_fse_table(&mut r)?;
        let prev_of = deserialize_fse_table(&mut r)?;
        let prev_ml = deserialize_fse_table(&mut r)?;

        let xxh64_state: [u8; xxh64::SERIALIZED_LEN] = r.read_array()?;

        if !r.is_at_end() {
            return Err("zstd resume: trailing bytes after blob payload");
        }

        Ok(Self {
            window_size,
            has_checksum,
            fcs,
            decoded_in_frame,
            frame_start_offset,
            window_total_written,
            window_recent,
            repeats,
            prev_huffman_weights,
            prev_ll,
            prev_of,
            prev_ml,
            xxh64_state,
        })
    }
}

fn serialize_fse_table(out: &mut Vec<u8>, table: &Option<SerializedFseTable>) {
    match table {
        None => out.push(0),
        Some(t) => {
            out.push(1);
            // INVARIANT: accuracy_log ≤ MAX_FSE_ACCURACY_LOG = 12, so
            // the `as u8` cast cannot truncate.
            out.push(t.accuracy_log as u8);
            // INVARIANT: cells.len() == 1 << accuracy_log (or 1 for
            // RLE), well within u32 range.
            out.extend_from_slice(&(t.cells.len() as u32).to_le_bytes());
            for cell in &t.cells {
                out.push(cell.symbol);
                out.push(cell.num_bits);
                out.extend_from_slice(&cell.base_state.to_le_bytes());
            }
        }
    }
}

fn deserialize_fse_table(
    r: &mut ByteReader<'_>,
) -> Result<Option<SerializedFseTable>, &'static str> {
    let present = r.read_bool("has_prev_fse")?;
    if !present {
        return Ok(None);
    }
    let accuracy_log = u32::from(r.read_u8()?);
    if accuracy_log > MAX_FSE_ACCURACY_LOG {
        return Err("zstd resume: FSE accuracy_log out of range");
    }
    let count = r.read_u32()? as usize;
    let expected = if accuracy_log == 0 {
        1
    } else {
        1usize << accuracy_log
    };
    if count != expected {
        return Err("zstd resume: FSE cell count does not match accuracy_log");
    }
    let mut cells = Vec::with_capacity(count);
    for _ in 0..count {
        let symbol = r.read_u8()?;
        let num_bits = r.read_u8()?;
        let base_state = r.read_u16()?;
        cells.push(FseCell {
            symbol,
            num_bits,
            base_state,
        });
    }
    Ok(Some(SerializedFseTable {
        accuracy_log,
        cells,
    }))
}

/// Capture the live decoder's resume state into a serializable form.
///
/// Returns the in-memory state struct; the caller is responsible
/// for serializing it into the wire format. Splitting the two
/// makes the unit-test of state-capture independent of the wire
/// format.
pub(super) fn capture(decoder: &Decoder) -> Option<ZstdResumeState> {
    if !decoder.between_blocks {
        return None;
    }
    let State::InFrame {
        header,
        decoded_in_frame,
    } = &decoder.state
    else {
        return None;
    };
    let frame_state = decoder.frame_state.as_ref()?;

    let prev_huffman_weights = frame_state
        .prev_huffman
        .as_ref()
        .map(HuffmanTree::derive_weights);

    let prev_ll = frame_state.prev_seq_tables.ll.as_ref().map(serialize_table);
    let prev_of = frame_state.prev_seq_tables.of.as_ref().map(serialize_table);
    let prev_ml = frame_state.prev_seq_tables.ml.as_ref().map(serialize_table);

    Some(ZstdResumeState {
        window_size: header.window_size,
        has_checksum: header.has_checksum,
        fcs: header.fcs,
        decoded_in_frame: *decoded_in_frame,
        frame_start_offset: frame_state.frame_start_offset,
        window_total_written: frame_state.window.total_written(),
        window_recent: frame_state.window.recent_in_order(),
        repeats: frame_state.repeats.slots(),
        prev_huffman_weights,
        prev_ll,
        prev_of,
        prev_ml,
        xxh64_state: frame_state.xxh64.serialize(),
    })
}

fn serialize_table(t: &FseTable) -> SerializedFseTable {
    SerializedFseTable {
        accuracy_log: t.accuracy_log(),
        cells: t.cells_view().to_vec(),
    }
}

/// Reconstruct a [`Decoder`] from a Phase-7 resume blob and a fresh
/// source.
///
/// `start_offset` is the source byte offset at which `src` will
/// deliver its first byte — the `decoder_position` saved alongside
/// the blob. The decoder seeds its `bytes_consumed` to that value so
/// the high-water mark stays consistent across the boundary, and
/// installs the blob's `last_frame_boundary` as the just-resumed
/// position so callers see a stable anchor until the next block
/// completes.
///
/// On success the decoder sits in [`State::InFrame`] with the frame
/// context fully restored. The next bytes pulled from `src` must be
/// the start of a block header — exactly what the original run was
/// about to read when it captured the blob.
///
/// # Errors
///
/// Returns [`DecodeError::Construct`] when the blob is structurally
/// malformed or when `windowLog > 27` (the round-one cap from
/// `frame.rs::MAX_WINDOW_LOG`).
pub fn resume(
    src: Box<dyn Read + Send>,
    state_blob: &[u8],
    start_offset: u64,
) -> Result<Decoder, DecodeError> {
    let resume = ZstdResumeState::deserialize(state_blob).map_err(|reason| {
        DecodeError::Construct(std::io::Error::other(format!(
            "zstd resume blob rejected: {reason}",
        )))
    })?;

    // Mirror the frame-header parser's windowLog cap so a corrupt
    // blob can't construct a Decoder that would have been rejected
    // had the same frame been decoded fresh.
    if resume.window_size > 1u64 << MAX_WINDOW_LOG {
        return Err(DecodeError::Construct(std::io::Error::other(
            "zstd resume blob rejected: windowLog > 27",
        )));
    }

    rebuild(src, resume, start_offset).map_err(|err| {
        DecodeError::Construct(std::io::Error::other(format!(
            "zstd resume blob rejected: {err}",
        )))
    })
}

fn rebuild(
    src: Box<dyn Read + Send>,
    state: ZstdResumeState,
    start_offset: u64,
) -> Result<Decoder, RebuildError> {
    let window = SlidingWindow::from_snapshot(
        state.window_size,
        state.window_total_written,
        &state.window_recent,
    )
    .map_err(RebuildError::Internal)?;

    let prev_huffman = match state.prev_huffman_weights {
        Some(weights) => {
            Some(HuffmanTree::from_direct_weights(&weights).map_err(RebuildError::Internal)?)
        }
        None => None,
    };

    let prev_seq_tables = PrevSequenceTables {
        ll: rebuild_table(state.prev_ll)?,
        of: rebuild_table(state.prev_of)?,
        ml: rebuild_table(state.prev_ml)?,
    };

    let xxh64 = Xxh64::deserialize(&state.xxh64_state).map_err(RebuildError::HasherBlob)?;

    let frame_state = FrameDecodeState {
        window,
        repeats: RepeatOffsets::from_slots(state.repeats),
        prev_huffman,
        prev_seq_tables,
        xxh64,
        frame_start_offset: state.frame_start_offset,
    };

    let header = FrameHeader {
        fcs: state.fcs,
        window_size: state.window_size,
        // Custom dictionaries are rejected at the regular
        // frame-header parse path; the blob captures none.
        dict_id: None,
        has_checksum: state.has_checksum,
        // Single_segment is observation-only after the frame header
        // is consumed (only the Window_Size derivation depends on
        // it). Pick a deterministic value; downstream code does not
        // re-read it.
        single_segment: false,
        // header_size is unused by the InFrame state machine — see
        // the field comment in frame.rs. Any value works.
        header_size: 0,
    };

    Ok(Decoder {
        source: Some(src),
        state: State::InFrame {
            header,
            decoded_in_frame: state.decoded_in_frame,
        },
        bytes_consumed: start_offset,
        last_frame_boundary: Some(crate::types::ByteOffset::new(start_offset)),
        between_blocks: true,
        payload_buf: Vec::new(),
        skip_buf: Vec::new(),
        block_out: Vec::new(),
        frame_state: Some(frame_state),
    })
}

fn rebuild_table(t: Option<SerializedFseTable>) -> Result<Option<FseTable>, RebuildError> {
    match t {
        None => Ok(None),
        Some(s) => FseTable::from_raw_cells(s.accuracy_log, s.cells)
            .map(Some)
            .map_err(RebuildError::Internal),
    }
}

enum RebuildError {
    Internal(ZstdError),
    HasherBlob(&'static str),
}

impl std::fmt::Display for RebuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RebuildError::Internal(e) => write!(f, "{e}"),
            RebuildError::HasherBlob(s) => f.write_str(s),
        }
    }
}

/// `crate::decode::DecoderResumeFactory` adapter for Phase-7 resume.
///
/// Registered via [`crate::decode::DecoderRegistry::register_resume_factory`]
/// in Phase 8 once the registry swaps to this module's
/// [`super::factory`].
///
/// # Errors
///
/// Forwards any error returned by [`resume`].
pub fn resume_factory(
    src: Box<dyn Read + Send>,
    state_blob: &[u8],
    start_offset: u64,
) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    Ok(Box::new(resume(src, state_blob, start_offset)?))
}

// ---- Tiny byte-cursor reader -----------------------------------------

struct ByteReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_at_end(&self) -> bool {
        self.pos == self.buf.len()
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], &'static str> {
        if self.pos + N > self.buf.len() {
            return Err("zstd resume: blob truncated");
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    fn read_slice(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        if self.pos + n > self.buf.len() {
            return Err("zstd resume: blob truncated");
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn read_u8(&mut self) -> Result<u8, &'static str> {
        Ok(self.read_array::<1>()?[0])
    }

    fn read_u16(&mut self) -> Result<u16, &'static str> {
        Ok(u16::from_le_bytes(self.read_array::<2>()?))
    }

    fn read_u32(&mut self) -> Result<u32, &'static str> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }

    fn read_u64(&mut self) -> Result<u64, &'static str> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }

    fn read_bool(&mut self, label: &'static str) -> Result<bool, &'static str> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => {
                let _ = label;
                Err("zstd resume: bool field outside {0, 1}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tiny minimally-valid resume state for round-trip tests.
    fn small_state() -> ZstdResumeState {
        ZstdResumeState {
            window_size: 1024,
            has_checksum: true,
            fcs: Some(42),
            decoded_in_frame: 1000,
            frame_start_offset: 256,
            window_total_written: 5000,
            window_recent: (0..1024).map(|i| (i & 0xFF) as u8).collect(),
            repeats: [1, 4, 8],
            prev_huffman_weights: Some(vec![2, 1, 1]),
            prev_ll: None,
            prev_of: None,
            prev_ml: None,
            xxh64_state: Xxh64::new().serialize(),
        }
    }

    #[test]
    fn round_trip_empty_optionals() {
        let state = small_state();
        let blob = state.serialize();
        let back = ZstdResumeState::deserialize(&blob).expect("deserialize");
        assert_eq!(back.window_size, state.window_size);
        assert_eq!(back.fcs, state.fcs);
        assert_eq!(back.decoded_in_frame, state.decoded_in_frame);
        assert_eq!(back.window_recent, state.window_recent);
        assert_eq!(back.repeats, state.repeats);
        assert_eq!(back.prev_huffman_weights, state.prev_huffman_weights);
        assert!(back.prev_ll.is_none());
    }

    #[test]
    fn round_trip_with_fse_tables() {
        let mut state = small_state();
        state.prev_ll = Some(SerializedFseTable {
            accuracy_log: 5,
            cells: vec![
                FseCell {
                    symbol: 0,
                    num_bits: 5,
                    base_state: 0,
                };
                32
            ],
        });
        state.prev_of = Some(SerializedFseTable {
            accuracy_log: 0,
            cells: vec![FseCell {
                symbol: 7,
                num_bits: 0,
                base_state: 0,
            }],
        });
        let blob = state.serialize();
        let back = ZstdResumeState::deserialize(&blob).expect("deserialize");
        let ll = back.prev_ll.expect("ll present");
        assert_eq!(ll.accuracy_log, 5);
        assert_eq!(ll.cells.len(), 32);
        let of = back.prev_of.expect("of present");
        assert_eq!(of.accuracy_log, 0);
        assert_eq!(of.cells.len(), 1);
        assert_eq!(of.cells[0].symbol, 7);
        assert!(back.prev_ml.is_none());
    }

    #[test]
    fn deserialize_rejects_bad_magic() {
        let mut blob = small_state().serialize();
        blob[0] = b'X';
        assert!(ZstdResumeState::deserialize(&blob).is_err());
    }

    #[test]
    fn deserialize_rejects_unknown_version() {
        let mut blob = small_state().serialize();
        blob[4] = 99;
        assert!(ZstdResumeState::deserialize(&blob).is_err());
    }

    #[test]
    fn deserialize_rejects_trailing_bytes() {
        let mut blob = small_state().serialize();
        blob.push(0xFF);
        assert!(ZstdResumeState::deserialize(&blob).is_err());
    }

    #[test]
    fn deserialize_rejects_truncated_blob() {
        let blob = small_state().serialize();
        for cut in [0, 4, 10, blob.len() - 1] {
            assert!(
                ZstdResumeState::deserialize(&blob[..cut]).is_err(),
                "expected error on truncation to {cut}",
            );
        }
    }

    #[test]
    fn deserialize_rejects_window_size_zero() {
        let mut state = small_state();
        state.window_size = 0;
        let blob = state.serialize();
        assert!(ZstdResumeState::deserialize(&blob).is_err());
    }

    #[test]
    fn deserialize_rejects_window_size_above_cap() {
        let mut state = small_state();
        state.window_size = MAX_WINDOW_SIZE + 1;
        // Recent must still respect the cap to avoid the length
        // sanity check tripping first; truncate it.
        state.window_recent.clear();
        let blob = state.serialize();
        assert!(ZstdResumeState::deserialize(&blob).is_err());
    }
}
