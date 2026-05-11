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
//! # No resume yet
//!
//! [`StreamingDecoder::frame_boundary`] returns `None` and
//! [`StreamingDecoder::decoder_state_into`] keeps the trait
//! default (`false`). Mid-entry resume support for legacy lands in
//! Phase F (`docs/PLAN_rar3.md` §F1), which adds a snapshot blob
//! covering the LZ dict / PPMd model state.

use std::io::{ErrorKind, Read, Write};

use crate::decode::{DecodeError, DecodeStatus, StreamingDecoder};
use crate::types::ByteOffset;

use super::entry::{decode_payload, LegacyEntryError};

/// Maximum bytes emitted to the sink per [`StreamingDecoder::decode_step`]
/// drain step. Matches the RAR5 / zstd / xz staging-drain cadence and
/// keeps the coordinator's punch / checkpoint interleave responsive.
const STREAM_CHUNK_BYTES: usize = 64 * 1024;

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
        // Round-one (Phase E §E1) has no mid-entry restart point —
        // a fresh decoder always starts from byte 0 of the entry's
        // payload. Phase F (`docs/PLAN_rar3.md` §F1) adds a
        // snapshot blob and wires this through.
        None
    }

    fn set_source_start_offset(&mut self, offset: u64) {
        self.src_start_offset = offset;
    }
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
