//! `RarLegacyStreamDecoder` — `StreamingDecoder` adapter for
//! legacy (RAR3 / RAR4) per-entry payloads.
//!
//! Per `docs/PLAN_rar3.md` §E1 this is the integration seam: the
//! §A2 walker exposes the per-entry compressed range, the §B / §C
//! decoder layers ship a synchronous
//! [`super::entry::decode_payload`] that produces the entry's
//! decoded bytes, and this module wraps that pair in the
//! bounded-step / `bytes_consumed` / `frame_boundary` contract
//! the rest of the crate already speaks for `tar.zst` / `tar.xz` /
//! `.lz4` / RAR5.
//!
//! # Round-one shape
//!
//! Round-one (Phase E §E1) buffers the entry's full
//! `packed_size`-byte compressed payload into memory, runs the
//! synchronous decoder, then drains the resulting decoded buffer to
//! the caller's sink in `STREAM_CHUNK_BYTES` chunks. This mirrors
//! the §E1 RAR5 path's "buffer-then-stream" posture
//! (`docs/PLAN_rar5_decoder.md` §E1) and the analogous buffering in
//! the zip / 7z pipelines. The cost is bounded by the file header's
//! `packed_size` + `unpacked_size`; Phase G's streaming-rework
//! (`O.RAR.STREAMING_DECOMPRESS`) lifts it to a block-by-block
//! reader against the §C decoder primitives.
//!
//! # Mid-entry resume (§F1)
//!
//! Phase F (`docs/PLAN_rar3.md` §F1) wires
//! [`StreamingDecoder::frame_boundary`] and
//! [`StreamingDecoder::decoder_state_into`]. The round-one
//! buffer-then-stream shape means the snapshot can be tiny: the
//! synchronous [`decode_payload`] call is deterministic in
//! `(compressed, method, dict_capacity, unpacked_size)`, so the
//! blob only needs to record the per-entry header fields plus
//! `decoded_pos` (how many output bytes were already emitted
//! before the snapshot). On resume, [`Self::resume`] re-runs
//! `decode_payload` against the same source bytes — yielding the
//! same `decoded` buffer — and skips ahead to the saved
//! `decoded_pos` before emitting the suffix.
//!
//! That makes `source_cursor_from_blob` always report `0`: the
//! resuming decoder needs the *full* entry payload to re-build the
//! decoded buffer, not a tail-only slice. The
//! [`super::super::super::download::rar_pipeline`] slicing logic
//! (mirrored from the RAR5 path) handles `cursor == 0` as a no-op
//! `compressed.split_off(0)`, so the pipeline integration drops
//! straight in.

use std::io::{ErrorKind, Read, Write};

use crate::decode::{DecodeError, DecodeStatus, StreamingDecoder};
use crate::types::ByteOffset;

use super::entry::{decode_payload, LegacyEntryError};

/// Maximum bytes emitted to the sink per [`StreamingDecoder::decode_step`]
/// drain step. Matches the RAR5 / zstd / xz staging-drain cadence and
/// keeps the coordinator's punch / checkpoint interleave responsive.
const STREAM_CHUNK_BYTES: usize = 64 * 1024;

/// Magic bytes identifying a [`RarLegacyStreamDecoder`] resume blob.
/// Stamped at offset 0 so a stray cross-decoder blob (e.g. a RAR5
/// snapshot whose magic is `b"RR5S"`) can't be mis-routed into the
/// legacy resume path.
const SNAPSHOT_MAGIC: [u8; 4] = *b"RR3S";

/// Wire version of the snapshot format. Bumped whenever the layout
/// changes; the legacy decoder's entry-resume contract permits
/// silent rejection of future-version blobs (the resume falls
/// back to byte-0 restart, which still produces byte-identical
/// output because [`decode_payload`] is deterministic).
const SNAPSHOT_VERSION: u32 = 1;

/// Hard cap on per-entry `packed_size` we'll buffer in memory.
///
/// Legacy RAR file headers can declare a 64-bit `packed_size` via the
/// `LHD_LARGE` flag (low + high u32 parts). Round-one rejects entries
/// whose declared payload exceeds this cap rather than risking an
/// adversarial OOM allocation — real legacy archives in the wild
/// never approach this. The cap is generous (1 GiB) so legitimate
/// large entries from the curated corpus decode without bumping it;
/// Phase G's streaming rework eliminates the in-memory buffer
/// entirely.
const MAX_PACKED_BYTES: u64 = 1 << 30;

/// Hard cap on per-entry `unpacked_size`. Same rationale as
/// [`MAX_PACKED_BYTES`]; sized so the curated round-one corpus
/// decodes without bumping it.
const MAX_UNPACKED_BYTES: u64 = 1 << 30;

/// `RarLegacyStreamDecoder` per-entry instance.
///
/// One instance per legacy entry. The `src` source delivers the
/// entry's compressed bytes (`packed_size` bytes, exactly); the
/// decoded output flows into the caller's `Write` sink via
/// [`StreamingDecoder::decode_step`].
pub struct RarLegacyStreamDecoder {
    /// Pull-style source of the entry's compressed bytes. `None`
    /// once the full `packed_size` has been buffered (the source
    /// handle is released as soon as its bytes are consumed).
    src: Option<Box<dyn Read + Send>>,
    /// Cumulative bytes pulled from `src`. Combined with
    /// [`Self::src_start_offset`] to produce the global
    /// `bytes_consumed` value.
    src_consumed: u64,
    /// Source-stream byte offset where this decoder's `src` begins
    /// delivering bytes. Seeded via
    /// [`StreamingDecoder::set_source_start_offset`] for runs that
    /// resume from a non-zero offset; fresh runs leave it at 0.
    src_start_offset: u64,
    /// Bytes the file header promised the source would deliver.
    /// Equals the entry's packed_size.
    packed_size: u64,
    /// Bytes the file header promised the decoder would emit.
    /// Equals the entry's unpacked_size; tracked here for diagnostic
    /// framing if the decode short-emits.
    unpacked_size: u64,
    /// Compression-method byte from the file header
    /// (`0x30..=0x35`). Drives the [`decode_payload`] dispatch.
    method: u8,
    /// Per-entry LZ sliding-window capacity (from the file header's
    /// `LHD_WINDOW` selector). Ignored on the STORED branch.
    dict_capacity: usize,
    /// Decoded output, populated after the first `decode_step`
    /// finishes buffering + running the synchronous decoder. Drained
    /// to the sink in [`STREAM_CHUNK_BYTES`] increments on
    /// subsequent steps.
    decoded: Vec<u8>,
    /// Byte index into [`Self::decoded`] of the next chunk to emit.
    decoded_pos: usize,
    /// `true` once the source has been fully drained and the
    /// synchronous decoder has produced its output (the
    /// "buffer-and-decode" step has completed).
    decoded_ready: bool,
    /// Latched `Eof` flag. Once set, [`StreamingDecoder::decode_step`]
    /// idempotently returns `Eof` without further work.
    eof_emitted: bool,
}

impl std::fmt::Debug for RarLegacyStreamDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RarLegacyStreamDecoder")
            .field("src_consumed", &self.src_consumed)
            .field("src_start_offset", &self.src_start_offset)
            .field("packed_size", &self.packed_size)
            .field("unpacked_size", &self.unpacked_size)
            .field("method", &format_args!("0x{:02X}", self.method))
            .field("dict_capacity", &self.dict_capacity)
            .field("decoded_len", &self.decoded.len())
            .field("decoded_pos", &self.decoded_pos)
            .field("decoded_ready", &self.decoded_ready)
            .field("eof_emitted", &self.eof_emitted)
            .finish()
    }
}

impl RarLegacyStreamDecoder {
    /// Construct a decoder for one legacy entry.
    ///
    /// `src` must deliver exactly `packed_size` bytes — the entry's
    /// compressed payload as recorded in the legacy file header.
    /// `method` is the wire-format method byte (`0x30..=0x35`);
    /// `dict_capacity` is the per-entry LZ sliding-window size
    /// (unused on the STORED branch but required upfront so the
    /// constructor can reject obviously-invalid values without
    /// pulling bytes from `src`).
    ///
    /// # Errors
    ///
    /// - [`DecodeError::Construct`] when `packed_size` /
    ///   `unpacked_size` exceed the per-entry caps
    ///   ([`MAX_PACKED_BYTES`] / [`MAX_UNPACKED_BYTES`]), or when
    ///   `method` is outside the supported `0x30..=0x35` range.
    pub fn new(
        src: Box<dyn Read + Send>,
        packed_size: u64,
        unpacked_size: u64,
        method: u8,
        dict_capacity: usize,
    ) -> Result<Self, DecodeError> {
        if packed_size > MAX_PACKED_BYTES {
            return Err(DecodeError::Construct(std::io::Error::other(format!(
                "legacy RAR stream decoder: packed_size {packed_size} exceeds round-one cap {MAX_PACKED_BYTES}",
            ))));
        }
        if unpacked_size > MAX_UNPACKED_BYTES {
            return Err(DecodeError::Construct(std::io::Error::other(format!(
                "legacy RAR stream decoder: unpacked_size {unpacked_size} exceeds round-one cap {MAX_UNPACKED_BYTES}",
            ))));
        }
        if !(0x30..=0x35).contains(&method) {
            return Err(DecodeError::Construct(std::io::Error::other(format!(
                "legacy RAR stream decoder: method byte 0x{method:02X} is outside the supported 0x30..=0x35 range",
            ))));
        }
        Ok(Self {
            src: Some(src),
            src_consumed: 0,
            src_start_offset: 0,
            packed_size,
            unpacked_size,
            method,
            dict_capacity,
            decoded: Vec::new(),
            decoded_pos: 0,
            decoded_ready: false,
            eof_emitted: false,
        })
    }

    /// Pull the entry's compressed bytes into a `Vec` and run the
    /// synchronous decoder. Releases the source handle once the
    /// payload has been consumed.
    fn buffer_and_decode(&mut self) -> Result<(), DecodeError> {
        let packed = self.packed_size;
        let mut compressed = Vec::with_capacity(packed as usize);
        if packed > 0 {
            let src = self.src.as_mut().ok_or_else(|| DecodeError::Read {
                consumed: self.src_start_offset + self.src_consumed,
                source: std::io::Error::other(
                    "legacy RAR stream decoder: source closed before payload was buffered",
                ),
            })?;
            let want = packed as usize;
            compressed.resize(want, 0);
            let mut filled = 0usize;
            while filled < want {
                match src.read(&mut compressed[filled..]) {
                    Ok(0) => {
                        return Err(DecodeError::Read {
                            consumed: self.src_start_offset + self.src_consumed + filled as u64,
                            source: std::io::Error::new(
                                ErrorKind::UnexpectedEof,
                                format!(
                                    "legacy RAR stream decoder: short read on entry payload \
                                     (wanted {want} bytes, got {filled})"
                                ),
                            ),
                        });
                    }
                    Ok(got) => filled += got,
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    Err(source) => {
                        return Err(DecodeError::Read {
                            consumed: self.src_start_offset + self.src_consumed + filled as u64,
                            source,
                        });
                    }
                }
            }
            self.src_consumed = self.src_consumed.saturating_add(packed);
        }
        // Source fully drained — release the handle. Any
        // subsequent decode_step call works against the decoded
        // buffer alone.
        self.src = None;

        let decoded = decode_payload(
            &compressed,
            self.method,
            self.dict_capacity,
            self.unpacked_size,
        )
        .map_err(legacy_err_to_decode_err)?;
        if (decoded.len() as u64) != self.unpacked_size {
            return Err(DecodeError::Read {
                consumed: self.src_start_offset + self.src_consumed,
                source: std::io::Error::other(format!(
                    "legacy RAR stream decoder: decoder produced {got} bytes, expected {expected} \
                     per the file header's unpacked_size",
                    got = decoded.len(),
                    expected = self.unpacked_size,
                )),
            });
        }
        self.decoded = decoded;
        self.decoded_pos = 0;
        self.decoded_ready = true;
        Ok(())
    }
}

impl StreamingDecoder for RarLegacyStreamDecoder {
    fn decode_step(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, DecodeError> {
        if self.eof_emitted {
            return Ok(DecodeStatus::Eof);
        }
        if !self.decoded_ready {
            self.buffer_and_decode()?;
            // Fall through to drain the first chunk. For zero-byte
            // entries (unpacked_size == 0) the loop body below will
            // observe an empty decoded buffer and report Eof
            // directly.
        }

        let remaining = self.decoded.len().saturating_sub(self.decoded_pos);
        if remaining == 0 {
            self.eof_emitted = true;
            return Ok(DecodeStatus::Eof);
        }
        let take = remaining.min(STREAM_CHUNK_BYTES);
        sink.write_all(&self.decoded[self.decoded_pos..self.decoded_pos + take])
            .map_err(DecodeError::Write)?;
        self.decoded_pos += take;
        if self.decoded_pos >= self.decoded.len() {
            self.eof_emitted = true;
            // Free the now-drained buffer eagerly so the entry's
            // unpacked footprint isn't pinned past EOF.
            self.decoded = Vec::new();
            return Ok(DecodeStatus::Eof);
        }
        Ok(DecodeStatus::MoreData)
    }

    fn bytes_consumed(&self) -> ByteOffset {
        ByteOffset::new(self.src_start_offset + self.src_consumed)
    }

    fn frame_boundary(&self) -> Option<ByteOffset> {
        // Round-one's only natural frame boundary is end-of-entry:
        // after [`buffer_and_decode`] has run, every source byte
        // has been consumed and the synchronous decoder has
        // produced its full output. Subsequent decode_step calls
        // only drain the captured `decoded` buffer to the sink, so
        // every snapshot we can take is end-of-source-payload.
        // The pipeline never actually pulls from `src` past this
        // boundary; the resume factory re-reads the full entry
        // payload to reconstruct the decoded buffer
        // (`source_cursor_from_blob` always reports 0).
        if self.decoded_ready {
            Some(ByteOffset::new(self.src_start_offset + self.packed_size))
        } else {
            None
        }
    }

    fn set_source_start_offset(&mut self, offset: u64) {
        self.src_start_offset = offset;
    }

    fn decoder_state_into(&self, out: &mut Vec<u8>) -> bool {
        // Only checkpoint between drain steps once the synchronous
        // decoder has actually run. Before [`buffer_and_decode`]
        // there's no useful state to capture (the resuming
        // decoder would just re-do the same work from scratch);
        // after [`eof_emitted`] the entry is finished and the
        // pipeline never asks for a state past EOF.
        if !self.decoded_ready || self.eof_emitted {
            return false;
        }
        self.serialize_into(out);
        true
    }

    fn decoder_state_size_hint(&self) -> usize {
        // Tiny fixed-size header; the legacy snapshot intentionally
        // does *not* capture the decoded buffer (resume re-runs
        // [`decode_payload`] deterministically).
        SNAPSHOT_FIXED_HEADER_LEN
    }
}

/// Bytes consumed by the snapshot's fixed layout. Used by
/// [`RarLegacyStreamDecoder::decoder_state_size_hint`] and the
/// serializer's [`Vec::reserve`] call.
const SNAPSHOT_FIXED_HEADER_LEN: usize = 4 // magic
    + 4 // version
    + 8 // src_start_offset
    + 8 // packed_size
    + 8 // unpacked_size
    + 1 // method
    + 8 // dict_capacity (u64 for wire stability across 32/64-bit targets)
    + 8; // decoded_pos

impl RarLegacyStreamDecoder {
    /// Serialize the decoder's state into `out`, in the exact
    /// shape [`Self::resume`] consumes. Stable across patch
    /// releases per `PLAN_rar3.md` §F1's checkpoint compatibility
    /// contract.
    fn serialize_into(&self, out: &mut Vec<u8>) {
        out.reserve(SNAPSHOT_FIXED_HEADER_LEN);
        out.extend_from_slice(&SNAPSHOT_MAGIC);
        out.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.src_start_offset.to_le_bytes());
        out.extend_from_slice(&self.packed_size.to_le_bytes());
        out.extend_from_slice(&self.unpacked_size.to_le_bytes());
        out.push(self.method);
        out.extend_from_slice(&(self.dict_capacity as u64).to_le_bytes());
        out.extend_from_slice(&(self.decoded_pos as u64).to_le_bytes());
    }

    /// Inspect a snapshot blob and return the source-byte cursor
    /// it was captured at. For the round-one legacy decoder this
    /// is always `0` — resume re-buffers the full entry payload
    /// to re-run the synchronous decode. Surfaces the same
    /// magic / version diagnostics the pipeline expects.
    ///
    /// # Errors
    ///
    /// - [`DecodeError::Construct`] when the magic / version
    ///   header is wrong, or the blob is too short to even hold
    ///   the fixed header.
    pub fn source_cursor_from_blob(blob: &[u8]) -> Result<u64, DecodeError> {
        if blob.len() < SNAPSHOT_FIXED_HEADER_LEN {
            return Err(blob_construct_err(format!(
                "snapshot too short: got {} bytes, expected at least {SNAPSHOT_FIXED_HEADER_LEN}",
                blob.len()
            )));
        }
        if blob[..4] != SNAPSHOT_MAGIC {
            return Err(blob_construct_err(format!(
                "snapshot magic mismatch: got {:?}, expected {:?}",
                &blob[..4],
                SNAPSHOT_MAGIC
            )));
        }
        let version = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]);
        if version != SNAPSHOT_VERSION {
            return Err(blob_construct_err(format!(
                "snapshot version mismatch: got {version}, expected {SNAPSHOT_VERSION}"
            )));
        }
        // Round-one always resumes from byte 0 of the entry's
        // compressed payload. The blob records the absolute
        // source-stream offset of byte 0 (in `src_start_offset`),
        // but the *cursor within the entry's compressed bytes*
        // is unconditionally 0.
        Ok(0)
    }

    /// Construct a decoder seeded from the saved snapshot. `src`
    /// must deliver the entry's full `packed_size` compressed
    /// bytes (the pipeline slices `compressed[source_cursor..]`
    /// which is the whole vec for the round-one cursor of 0).
    /// The caller passes the file-header's `packed_size`,
    /// `unpacked_size`, `method`, and `dict_capacity` for
    /// cross-checking against the saved blob.
    ///
    /// # Errors
    ///
    /// - [`DecodeError::Construct`] for any structural issue with
    ///   the blob (truncation, magic / version mismatch, header
    ///   field disagreement, `decoded_pos > unpacked_size`), or
    ///   for synchronous-decode failures that propagate from
    ///   [`decode_payload`].
    pub fn resume(
        src: Box<dyn Read + Send>,
        packed_size: u64,
        unpacked_size: u64,
        method: u8,
        dict_capacity: usize,
        blob: &[u8],
    ) -> Result<Self, DecodeError> {
        if blob.len() != SNAPSHOT_FIXED_HEADER_LEN {
            return Err(blob_construct_err(format!(
                "snapshot length {} disagrees with fixed layout {SNAPSHOT_FIXED_HEADER_LEN}",
                blob.len()
            )));
        }
        if blob[..4] != SNAPSHOT_MAGIC {
            return Err(blob_construct_err(format!(
                "snapshot magic mismatch: got {:?}, expected {:?}",
                &blob[..4],
                SNAPSHOT_MAGIC
            )));
        }
        let version = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]);
        if version != SNAPSHOT_VERSION {
            return Err(blob_construct_err(format!(
                "snapshot version mismatch: got {version}, expected {SNAPSHOT_VERSION}"
            )));
        }
        let src_start_offset = u64::from_le_bytes(blob[8..16].try_into().expect("16-byte slice"));
        let saved_packed = u64::from_le_bytes(blob[16..24].try_into().expect("24-byte slice"));
        let saved_unpacked = u64::from_le_bytes(blob[24..32].try_into().expect("32-byte slice"));
        let saved_method = blob[32];
        let saved_dict_capacity =
            u64::from_le_bytes(blob[33..41].try_into().expect("41-byte slice"));
        let decoded_pos =
            u64::from_le_bytes(blob[41..49].try_into().expect("49-byte slice")) as usize;

        if saved_packed != packed_size {
            return Err(blob_construct_err(format!(
                "snapshot packed_size {saved_packed} disagrees with file-header \
                 packed_size {packed_size}"
            )));
        }
        if saved_unpacked != unpacked_size {
            return Err(blob_construct_err(format!(
                "snapshot unpacked_size {saved_unpacked} disagrees with file-header \
                 unpacked_size {unpacked_size}"
            )));
        }
        if saved_method != method {
            return Err(blob_construct_err(format!(
                "snapshot method 0x{saved_method:02X} disagrees with file-header \
                 method 0x{method:02X}"
            )));
        }
        if saved_dict_capacity != dict_capacity as u64 {
            return Err(blob_construct_err(format!(
                "snapshot dict_capacity {saved_dict_capacity} disagrees with file-header \
                 dict_capacity {dict_capacity}"
            )));
        }
        if decoded_pos as u64 > unpacked_size {
            return Err(blob_construct_err(format!(
                "snapshot decoded_pos {decoded_pos} exceeds unpacked_size {unpacked_size}"
            )));
        }

        let mut dec = Self::new(src, packed_size, unpacked_size, method, dict_capacity)?;
        dec.src_start_offset = src_start_offset;
        // Drive the synchronous decode now: subsequent decode_step
        // calls only drain the buffer, so the resumed decoder
        // mirrors the original's post-buffer-and-decode state.
        dec.buffer_and_decode()?;
        // Skip past the bytes the original run already emitted.
        if decoded_pos > dec.decoded.len() {
            return Err(blob_construct_err(format!(
                "snapshot decoded_pos {decoded_pos} exceeds replay-decoded buffer length {}",
                dec.decoded.len()
            )));
        }
        dec.decoded_pos = decoded_pos;
        Ok(dec)
    }
}

fn blob_construct_err(msg: String) -> DecodeError {
    DecodeError::Construct(std::io::Error::other(format!(
        "legacy RAR stream decoder snapshot: {msg}"
    )))
}

/// Map a [`LegacyEntryError`] into a [`DecodeError`] so the
/// streaming surface keeps a uniform error type with the rest of
/// the in-tree decoders.
///
/// The legacy entry decoder surfaces every fault as
/// [`std::io::ErrorKind::Other`] — the variant's `Display` carries
/// the precise diagnostic (which sub-decoder failed, the offending
/// method byte, the size shortfall, etc.). The coordinator's
/// existing `decode_err_to_rar` chain (in `src/download/rar_pipeline.rs`)
/// then re-wraps these into `RarPipelineError::Rar(...)` so callers
/// see the same shape they do for RAR5 decode failures.
fn legacy_err_to_decode_err(err: LegacyEntryError) -> DecodeError {
    DecodeError::Read {
        consumed: 0,
        source: std::io::Error::other(format!("legacy RAR decode failed: {err}")),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::decode::{DecodeStatus, StreamingDecoder};
    use crate::rar::legacy::walk_archive;

    use super::*;

    const TESTFILE_NON_SOLID: &[u8] =
        include_bytes!("../../../tests/fixtures/rar_legacy/testfile.rar3.rar");
    const EXPECTED_PLAINTEXT: &[u8] =
        include_bytes!("../../../tests/fixtures/rar_legacy/testfile.rar3.txt");

    const FILTER_E8_RAR: &[u8] = include_bytes!("../../../tests/fixtures/rar_legacy/filter_e8.rar");
    const FILTER_E8_BIN: &[u8] = include_bytes!("../../../tests/fixtures/rar_legacy/filter_e8.bin");

    /// Drive the decoder to completion and return the bytes it
    /// emitted to a captured `Vec<u8>` sink. Asserts bounded-work
    /// behavior: each `decode_step` returns either `MoreData` or
    /// `Eof`, and the loop always converges in a finite number of
    /// iterations.
    fn drain_to_vec(mut dec: RarLegacyStreamDecoder) -> Vec<u8> {
        let mut out = Vec::new();
        let mut steps = 0usize;
        loop {
            let status = dec.decode_step(&mut out).expect("decode_step ok");
            steps += 1;
            assert!(steps < 1_000_000, "decoder failed to converge");
            if matches!(status, DecodeStatus::Eof) {
                break;
            }
        }
        // Idempotent EOF: subsequent steps stay EOF and emit nothing.
        let before = out.len();
        let status = dec.decode_step(&mut out).expect("decode_step ok at EOF");
        assert!(matches!(status, DecodeStatus::Eof));
        assert_eq!(out.len(), before);
        out
    }

    #[test]
    fn streams_single_ppmd_entry_to_completion() {
        let summary = walk_archive(TESTFILE_NON_SOLID).unwrap();
        let entry = &summary.entries[0];
        let compressed = &TESTFILE_NON_SOLID
            [entry.data_offset as usize..(entry.data_offset + entry.header.packed_size) as usize];
        let dict_capacity = entry.header.file_flags.dictionary_size().unwrap() as usize;
        let dec = RarLegacyStreamDecoder::new(
            Box::new(Cursor::new(compressed.to_vec())),
            entry.header.packed_size,
            entry.header.unpacked_size,
            entry.header.method,
            dict_capacity,
        )
        .expect("construct");
        let out = drain_to_vec(dec);
        assert_eq!(out, EXPECTED_PLAINTEXT);
    }

    #[test]
    fn streams_lz_entry_with_e8_filter() {
        let summary = walk_archive(FILTER_E8_RAR).unwrap();
        let entry = &summary.entries[0];
        let compressed = &FILTER_E8_RAR
            [entry.data_offset as usize..(entry.data_offset + entry.header.packed_size) as usize];
        let dict_capacity = entry.header.file_flags.dictionary_size().unwrap() as usize;
        let dec = RarLegacyStreamDecoder::new(
            Box::new(Cursor::new(compressed.to_vec())),
            entry.header.packed_size,
            entry.header.unpacked_size,
            entry.header.method,
            dict_capacity,
        )
        .expect("construct");
        let out = drain_to_vec(dec);
        assert_eq!(out, FILTER_E8_BIN);
    }

    /// 256 KiB Goldilocks fixture (`-ma4 -m3`) round-trips
    /// byte-identical. Decoded size > `STREAM_CHUNK_BYTES` so the
    /// streaming decoder takes multiple drain steps — proves the
    /// §F1 mid-drain snapshot path is exercisable by the live
    /// `decode_step` loop, not just the synthetic-blob unit
    /// tests. Provenance: rar 5.0.0 Linux via Docker, see
    /// `tests/fixtures/rar_legacy/README.md`.
    const LARGE_LZ_NORMAL_RAR: &[u8] =
        include_bytes!("../../../tests/fixtures/rar_legacy/large_lz_normal.rar");
    const LARGE_LZ_NORMAL_BIN: &[u8] =
        include_bytes!("../../../tests/fixtures/rar_legacy/large_lz_normal.bin");

    #[test]
    fn streams_large_lz_normal_entry_round_trips() {
        let summary = walk_archive(LARGE_LZ_NORMAL_RAR).unwrap();
        let entry = &summary.entries[0];
        let compressed = &LARGE_LZ_NORMAL_RAR
            [entry.data_offset as usize..(entry.data_offset + entry.header.packed_size) as usize];
        let dict_capacity = entry.header.file_flags.dictionary_size().unwrap() as usize;
        let dec = RarLegacyStreamDecoder::new(
            Box::new(Cursor::new(compressed.to_vec())),
            entry.header.packed_size,
            entry.header.unpacked_size,
            entry.header.method,
            dict_capacity,
        )
        .expect("construct");
        let out = drain_to_vec(dec);
        assert_eq!(out.len(), LARGE_LZ_NORMAL_BIN.len());
        assert_eq!(out, LARGE_LZ_NORMAL_BIN);
    }

    #[test]
    fn bytes_consumed_advances_after_first_step() {
        let summary = walk_archive(FILTER_E8_RAR).unwrap();
        let entry = &summary.entries[0];
        let compressed = &FILTER_E8_RAR
            [entry.data_offset as usize..(entry.data_offset + entry.header.packed_size) as usize];
        let dict_capacity = entry.header.file_flags.dictionary_size().unwrap() as usize;
        let mut dec = RarLegacyStreamDecoder::new(
            Box::new(Cursor::new(compressed.to_vec())),
            entry.header.packed_size,
            entry.header.unpacked_size,
            entry.header.method,
            dict_capacity,
        )
        .expect("construct");
        // Before the first step the source has not been touched.
        assert_eq!(dec.bytes_consumed().get(), 0);
        let mut sink = Vec::new();
        let _ = dec.decode_step(&mut sink).expect("first step ok");
        // After the first step the full packed_size has been pulled.
        assert_eq!(dec.bytes_consumed().get(), entry.header.packed_size);
    }

    #[test]
    fn set_source_start_offset_shifts_bytes_consumed() {
        // A decoder seeded with a non-zero source-stream start
        // offset must report `bytes_consumed` in global coordinates.
        let summary = walk_archive(FILTER_E8_RAR).unwrap();
        let entry = &summary.entries[0];
        let compressed = &FILTER_E8_RAR
            [entry.data_offset as usize..(entry.data_offset + entry.header.packed_size) as usize];
        let dict_capacity = entry.header.file_flags.dictionary_size().unwrap() as usize;
        let mut dec = RarLegacyStreamDecoder::new(
            Box::new(Cursor::new(compressed.to_vec())),
            entry.header.packed_size,
            entry.header.unpacked_size,
            entry.header.method,
            dict_capacity,
        )
        .expect("construct");
        let seed: u64 = 1_000_000;
        dec.set_source_start_offset(seed);
        assert_eq!(dec.bytes_consumed().get(), seed);
        let _ = drain_to_vec(dec);
    }

    #[test]
    fn rejects_method_out_of_supported_range() {
        let err = RarLegacyStreamDecoder::new(
            Box::new(Cursor::new(Vec::<u8>::new())),
            0,
            0,
            0x36,
            0x10000,
        )
        .expect_err("unsupported method byte rejected");
        assert!(matches!(err, DecodeError::Construct(_)), "got {err:?}");
    }

    #[test]
    fn rejects_packed_size_above_cap() {
        let err = RarLegacyStreamDecoder::new(
            Box::new(Cursor::new(Vec::<u8>::new())),
            MAX_PACKED_BYTES + 1,
            0,
            0x30,
            0x10000,
        )
        .expect_err("oversize packed_size rejected");
        assert!(matches!(err, DecodeError::Construct(_)), "got {err:?}");
    }

    #[test]
    fn stored_passthrough_zero_payload_is_immediate_eof() {
        // A STORED entry with packed_size == 0 (an unusual edge —
        // a zero-byte file) should immediately reach EOF without
        // touching the source's read path.
        let dec = RarLegacyStreamDecoder::new(
            Box::new(Cursor::new(Vec::<u8>::new())),
            0,
            0,
            0x30,
            0x10000,
        )
        .expect("construct");
        let out = drain_to_vec(dec);
        assert!(out.is_empty());
    }

    /// Decoder offers no snapshot before any output has been
    /// drained — `decoder_state_into` returns `false` and
    /// `frame_boundary` is `None` until [`buffer_and_decode`] has
    /// run.
    #[test]
    fn decoder_state_unavailable_before_first_step() {
        let summary = walk_archive(FILTER_E8_RAR).unwrap();
        let entry = &summary.entries[0];
        let compressed = &FILTER_E8_RAR
            [entry.data_offset as usize..(entry.data_offset + entry.header.packed_size) as usize];
        let dict_capacity = entry.header.file_flags.dictionary_size().unwrap() as usize;
        let dec = RarLegacyStreamDecoder::new(
            Box::new(Cursor::new(compressed.to_vec())),
            entry.header.packed_size,
            entry.header.unpacked_size,
            entry.header.method,
            dict_capacity,
        )
        .expect("construct");
        assert_eq!(dec.frame_boundary(), None);
        assert!(dec.decoder_state().is_none());
    }

    /// Helper: synthesize a snapshot blob with caller-chosen
    /// header fields. Lets tests probe `resume`'s cross-check
    /// logic without driving a live decoder (the in-tree
    /// fixtures decode to <64 KiB and so never expose a
    /// mid-drain snapshot via [`StreamingDecoder::decoder_state`]).
    fn synth_blob(
        src_start_offset: u64,
        packed_size: u64,
        unpacked_size: u64,
        method: u8,
        dict_capacity: u64,
        decoded_pos: u64,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(SNAPSHOT_FIXED_HEADER_LEN);
        out.extend_from_slice(&SNAPSHOT_MAGIC);
        out.extend_from_slice(&SNAPSHOT_VERSION.to_le_bytes());
        out.extend_from_slice(&src_start_offset.to_le_bytes());
        out.extend_from_slice(&packed_size.to_le_bytes());
        out.extend_from_slice(&unpacked_size.to_le_bytes());
        out.push(method);
        out.extend_from_slice(&dict_capacity.to_le_bytes());
        out.extend_from_slice(&decoded_pos.to_le_bytes());
        out
    }

    /// Drive a decoder to completion and capture the decoded
    /// reference. Returns the reference bytes + the entry's
    /// per-decoder parameters so callers can build resume blobs
    /// for the same entry.
    fn decode_reference() -> (Vec<u8>, Vec<u8>, u64, u64, u8, usize) {
        let summary = walk_archive(FILTER_E8_RAR).unwrap();
        let entry = &summary.entries[0];
        let compressed_bytes = FILTER_E8_RAR
            [entry.data_offset as usize..(entry.data_offset + entry.header.packed_size) as usize]
            .to_vec();
        let dict_capacity = entry.header.file_flags.dictionary_size().unwrap() as usize;
        let packed = entry.header.packed_size;
        let unpacked = entry.header.unpacked_size;
        let method = entry.header.method;
        (
            compressed_bytes,
            FILTER_E8_BIN.to_vec(),
            packed,
            unpacked,
            method,
            dict_capacity,
        )
    }

    /// For every byte boundary in the reference output, build a
    /// synthetic snapshot blob recording that `decoded_pos`,
    /// then resume + drain the suffix. Concatenating the
    /// hand-tracked prefix with the resumed suffix must equal
    /// the reference. Exercises the snapshot/resume contract at
    /// fine granularity — every internal `decoded_pos` value
    /// the decoder might serialize, even on fixtures whose
    /// decoded size is below [`STREAM_CHUNK_BYTES`] and so never
    /// expose a mid-drain snapshot through the public
    /// `decode_step` path.
    #[test]
    fn synthetic_blob_resume_round_trips_at_every_decoded_pos() {
        let (compressed, reference, packed, unpacked, method, dict_capacity) = decode_reference();
        assert!(!reference.is_empty(), "fixture must decode to something");
        // Test a representative spread of `decoded_pos` values —
        // every byte boundary in 0..reference.len() (small
        // enough for an exhaustive sweep on the 512-byte
        // fixture). Skip `reference.len()` itself: a snapshot
        // with no bytes left to emit is unrepresentable in the
        // live decoder (it has already set `eof_emitted`).
        for decoded_pos in 0..reference.len() {
            let blob = synth_blob(
                0,
                packed,
                unpacked,
                method,
                dict_capacity as u64,
                decoded_pos as u64,
            );
            let src: Box<dyn Read + Send> = Box::new(Cursor::new(compressed.clone()));
            let mut resumed =
                RarLegacyStreamDecoder::resume(src, packed, unpacked, method, dict_capacity, &blob)
                    .expect("resume from snapshot");
            let mut suffix = Vec::new();
            loop {
                let status = resumed.decode_step(&mut suffix).expect("decode_step");
                if matches!(status, DecodeStatus::Eof) {
                    break;
                }
            }
            let mut combined = reference[..decoded_pos].to_vec();
            combined.extend_from_slice(&suffix);
            assert_eq!(
                combined,
                reference,
                "resume from decoded_pos = {decoded_pos} must produce byte-identical \
                 output (suffix.len() = {})",
                suffix.len(),
            );
        }
    }

    /// `serialize_into` round-trips through `resume`: take a
    /// snapshot of a decoder mid-way through emit (synthesised
    /// via the `synth_blob` shortcut because the small fixture
    /// never exposes a mid-drain snapshot through the public
    /// API), then verify the resumed decoder produces the same
    /// `decoder_state()` output. Locks the wire layout.
    #[test]
    fn serialize_round_trips_through_resume() {
        let (compressed, _reference, packed, unpacked, method, dict_capacity) = decode_reference();
        let decoded_pos: u64 = 7; // arbitrary mid-emit value
        let blob_in = synth_blob(
            42,
            packed,
            unpacked,
            method,
            dict_capacity as u64,
            decoded_pos,
        );
        let src: Box<dyn Read + Send> = Box::new(Cursor::new(compressed));
        let resumed =
            RarLegacyStreamDecoder::resume(src, packed, unpacked, method, dict_capacity, &blob_in)
                .expect("resume");
        let blob_out = resumed.decoder_state().expect("snapshot available");
        assert_eq!(blob_in, blob_out, "snapshot round-trip is lossless");
    }

    /// `source_cursor_from_blob` is always 0 for the legacy
    /// decoder — round-one re-runs the synchronous decode from
    /// byte 0, so a freshly-resumed decoder's source must
    /// deliver the full entry payload.
    #[test]
    fn source_cursor_is_always_zero() {
        let blob = synth_blob(1_000, 32, 16, 0x33, 0x10000, 8);
        let cursor =
            RarLegacyStreamDecoder::source_cursor_from_blob(&blob).expect("well-formed blob");
        assert_eq!(cursor, 0);
    }

    /// `source_cursor_from_blob` rejects malformed blobs.
    #[test]
    fn source_cursor_rejects_bad_magic() {
        let mut blob = vec![b'X', b'X', b'X', b'X']; // wrong magic
        blob.extend_from_slice(&1u32.to_le_bytes()); // version
        blob.extend_from_slice(&[0u8; SNAPSHOT_FIXED_HEADER_LEN - 8]); // pad
        let err = RarLegacyStreamDecoder::source_cursor_from_blob(&blob).expect_err("bad magic");
        let dbg = format!("{err:?}");
        assert!(dbg.contains("magic mismatch"), "unexpected: {dbg}");
    }

    #[test]
    fn source_cursor_rejects_short_header() {
        let blob: Vec<u8> = b"RR3S\x01\x00\x00\x00".to_vec(); // magic + version only
        let err = RarLegacyStreamDecoder::source_cursor_from_blob(&blob).expect_err("short header");
        let dbg = format!("{err:?}");
        assert!(dbg.contains("too short"), "unexpected: {dbg}");
    }

    #[test]
    fn source_cursor_rejects_wrong_version() {
        let mut blob = SNAPSHOT_MAGIC.to_vec();
        blob.extend_from_slice(&99u32.to_le_bytes());
        blob.extend_from_slice(&[0u8; SNAPSHOT_FIXED_HEADER_LEN - 8]);
        let err =
            RarLegacyStreamDecoder::source_cursor_from_blob(&blob).expect_err("wrong version");
        let dbg = format!("{err:?}");
        assert!(dbg.contains("version mismatch"), "unexpected: {dbg}");
    }

    /// `resume` rejects blobs whose recorded header fields
    /// disagree with the caller's file-header values — a stale
    /// or cross-archive checkpoint must not be silently
    /// reinterpreted.
    #[test]
    fn resume_rejects_method_mismatch() {
        let (compressed, _reference, packed, unpacked, method, dict_capacity) = decode_reference();
        let blob = synth_blob(0, packed, unpacked, method, dict_capacity as u64, 0);
        let wrong_method = if method == 0x33 { 0x34 } else { 0x33 };
        let src: Box<dyn Read + Send> = Box::new(Cursor::new(compressed));
        let err = RarLegacyStreamDecoder::resume(
            src,
            packed,
            unpacked,
            wrong_method,
            dict_capacity,
            &blob,
        )
        .expect_err("resume must reject method mismatch");
        assert!(matches!(err, DecodeError::Construct(_)), "got {err:?}");
    }

    #[test]
    fn resume_rejects_dict_capacity_mismatch() {
        let (compressed, _reference, packed, unpacked, method, dict_capacity) = decode_reference();
        let blob = synth_blob(0, packed, unpacked, method, dict_capacity as u64, 0);
        let src: Box<dyn Read + Send> = Box::new(Cursor::new(compressed));
        let err =
            RarLegacyStreamDecoder::resume(src, packed, unpacked, method, dict_capacity * 2, &blob)
                .expect_err("resume must reject dict_capacity mismatch");
        assert!(matches!(err, DecodeError::Construct(_)), "got {err:?}");
    }

    #[test]
    fn resume_rejects_packed_size_mismatch() {
        let (compressed, _reference, packed, unpacked, method, dict_capacity) = decode_reference();
        let blob = synth_blob(0, packed + 1, unpacked, method, dict_capacity as u64, 0);
        let src: Box<dyn Read + Send> = Box::new(Cursor::new(compressed));
        let err =
            RarLegacyStreamDecoder::resume(src, packed, unpacked, method, dict_capacity, &blob)
                .expect_err("resume must reject packed_size mismatch");
        assert!(matches!(err, DecodeError::Construct(_)), "got {err:?}");
    }

    #[test]
    fn resume_rejects_decoded_pos_past_unpacked_size() {
        let (compressed, _reference, packed, unpacked, method, dict_capacity) = decode_reference();
        let blob = synth_blob(
            0,
            packed,
            unpacked,
            method,
            dict_capacity as u64,
            unpacked + 1,
        );
        let src: Box<dyn Read + Send> = Box::new(Cursor::new(compressed));
        let err =
            RarLegacyStreamDecoder::resume(src, packed, unpacked, method, dict_capacity, &blob)
                .expect_err("resume must reject decoded_pos past unpacked_size");
        assert!(matches!(err, DecodeError::Construct(_)), "got {err:?}");
    }

    #[test]
    fn short_source_read_surfaces_unexpected_eof() {
        // packed_size = 16 but source delivers only 8 bytes.
        let mut dec = RarLegacyStreamDecoder::new(
            Box::new(Cursor::new(vec![0xAAu8; 8])),
            16,
            16,
            0x30,
            0x10000,
        )
        .expect("construct");
        let mut sink = Vec::new();
        let err = dec.decode_step(&mut sink).expect_err("must error");
        match err {
            DecodeError::Read { source, .. } => {
                assert_eq!(source.kind(), ErrorKind::UnexpectedEof);
            }
            other => panic!("expected DecodeError::Read, got {other:?}"),
        }
    }
}
