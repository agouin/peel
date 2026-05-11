//! Per-entry decoder front-door for legacy RAR (§C1h).
//!
//! Wraps §C1e₁'s [`LzDecoder`] and §C1g's [`PpmdSession`]
//! behind a single [`decode_entry`] function so callers (the
//! `rar_pipeline` plumbing, the integration tests) don't have
//! to thread the bit reader / prologue parser / range coder
//! state themselves. Dispatches on the first block's mode and
//! drives the dispatcher loop until the entry is fully
//! decoded.
//!
//! # Scope of §C1h
//!
//! Round-one ships:
//!
//! - **STORED** (`method == 0x30`) — direct byte copy from the
//!   archive's data area; the existing pipeline §A2b path
//!   already handles this, but routing it through
//!   [`decode_entry`] gives callers a unified API.
//! - **PPMd-mode entries** (single-block) — the ssokolow
//!   corpus's posture; uses [`PpmdSession`] verbatim and
//!   surfaces a precise error if the encoder emits a "new
//!   table" sub-code (multi-block-within-entry, deferred).
//! - **LZ-mode entries** (single-block) — uses [`LzDecoder`];
//!   surfaces a precise error on `NextBlock` (multi-block
//!   continuation, deferred). LZ-mode archives don't exist in
//!   the ssokolow corpus, so the LZ branch here is only
//!   exercised by §C1e₁'s synthetic-fixture tests at the
//!   layer below.
//!
//! Filed for follow-on work:
//!
//! - **Multi-block continuation within an entry** — same-mode
//!   transitions (LZ→LZ or PPMd→PPMd). Surfaces
//!   [`LegacyEntryError::MultiBlockNotSupported`] today; the
//!   §C1d `Dict` and §C1g `PpmdSession` both carry per-call
//!   state correctly, so wiring this is mostly a loop refactor
//!   when a multi-block fixture surfaces.
//! - **Cross-mode block transitions** (LZ↔PPMd within one
//!   entry) — requires the §C1d `Dict` to be shared across
//!   the two decoders. Filed for §G when a real archive
//!   surfaces that needs it; surfaces
//!   [`LegacyEntryError::CrossModeNotSupported`] today.
//! - **Solid mode** (`MHD_SOLID`) — cross-entry shared state.
//!   The non-solid ssokolow corpus doesn't exercise this; we
//!   detect `MHD_SOLID` archives at the walker level (§A2)
//!   and don't propagate the flag here. The
//!   `testfile.rar3.solid.rar` fixture has only one entry so
//!   non-solid logic decodes it correctly; multi-entry solid
//!   archives are a follow-on.

use thiserror::Error;

use crate::decode::ppmd2::range_dec::{RangeDecoder, RangeDecoderError};
use crate::rar::legacy::LegacyFileEntry;

use super::bits::BitReader;
use super::block_header::{parse_block_prologue, BlockHeaderError, BlockPrologue};
use super::bootstrap::MAIN_TABLE_TOTAL;
use super::dict::DictError;
use super::lzss::{BlockEnd, LzDecoder, LzError};
use super::ppmd_entry::{PpmdBlockEnd, PpmdEntryError, PpmdSession};

/// Errors produced by [`decode_entry`].
#[derive(Debug, Error)]
pub enum LegacyEntryError {
    /// Failed to parse the first block prologue.
    #[error("legacy RAR entry: prologue parse failed")]
    BlockHeader(#[from] BlockHeaderError),

    /// The PPMd entry decoder reported a fault.
    #[error("legacy RAR entry: PPMd decode failed")]
    Ppmd(#[from] PpmdEntryError),

    /// The LZ block dispatcher reported a fault.
    #[error("legacy RAR entry: LZ decode failed")]
    Lz(#[from] LzError),

    /// Dict construction failed (zero / over-cap capacity).
    #[error("legacy RAR entry: dict allocation failed")]
    Dict(#[from] DictError),

    /// The range decoder reported a fault at init time.
    #[error("legacy RAR entry: range decoder init failed")]
    Range(#[from] RangeDecoderError),

    /// The entry's compressed data area extends past the
    /// archive bytes the caller supplied — `data_offset +
    /// packed_size > archive.len()`.
    #[error(
        "legacy RAR entry: data area extends past archive bytes \
         (offset {data_offset}, packed_size {packed_size}, archive_len {archive_len})"
    )]
    DataAreaOverrun {
        /// Entry's `data_offset` from the file header.
        data_offset: u64,
        /// Entry's `packed_size` from the file header.
        packed_size: u64,
        /// Archive byte slice length the caller passed in.
        archive_len: u64,
    },

    /// The entry is a directory marker (its dictionary-size
    /// flag selector reads as `0b111`). Directory entries have
    /// no compressed payload to decode; the caller should
    /// surface this as a flag, not call [`decode_entry`].
    #[error("legacy RAR entry: directory marker has no payload to decode")]
    DirectoryEntry,

    /// The compression method byte is outside the round-one
    /// supported range (`0x30..=0x35`). The walker should
    /// reject this earlier but the front-door surfaces a
    /// specific error rather than panic.
    #[error("legacy RAR entry: unsupported compression method 0x{method:02X}")]
    UnsupportedMethod {
        /// The offending method byte.
        method: u8,
    },

    /// After the prologue parse the bit-cursor wasn't byte-
    /// aligned. PPMd-mode payloads start on a byte boundary,
    /// so this can only fire if the prologue parser emitted
    /// a malformed result (programmer error in §C1c).
    #[error(
        "legacy RAR entry: post-prologue bit-cursor at byte {byte_idx} \
         bit {bit_off} is not byte-aligned (PPMd payload requires alignment)"
    )]
    PostPrologueUnaligned {
        /// Byte position the cursor was at.
        byte_idx: u64,
        /// Bit-within-byte the cursor was at.
        bit_off: u8,
    },

    /// The entry's first prologue declared PPMd mode but the
    /// dispatcher surfaced a `NewTable` outcome — the encoder
    /// is asking for a fresh prologue mid-entry. Round-one
    /// doesn't support this multi-block-within-entry case.
    #[error(
        "legacy RAR entry: multi-block continuation not yet \
         supported (PPMd code-0 or LZ symbol-256/new_file=0 \
         encountered mid-entry)"
    )]
    MultiBlockNotSupported,

    /// The entry's first prologue declared one mode but a
    /// continuation block uses the other (LZ↔PPMd within an
    /// entry). Requires a shared dict; deferred to §G.
    #[error(
        "legacy RAR entry: cross-mode block transition \
         (LZ ↔ PPMd within an entry) not yet supported"
    )]
    CrossModeNotSupported,

    /// The decoder emitted fewer bytes than `unpacked_size`
    /// before hitting an end-of-data marker. Either the wire
    /// stream is malformed or the encoder under-emitted.
    #[error(
        "legacy RAR entry: decoded {got} bytes, expected {expected} \
         per the file header's unpacked_size"
    )]
    SizeShortfall {
        /// Bytes the decoder produced.
        got: u64,
        /// Bytes the header promised.
        expected: u64,
    },

    /// LZ-mode block dispatcher returned [`BlockEnd::FilterDecl`]
    /// — the entry contains an archive-supplied filter
    /// program. §C2's RarVM lands that path; surface a
    /// precise error today.
    #[error("legacy RAR entry: filter declaration (LZ symbol 257) is unsupported until §C2 lands")]
    UnsupportedFilter,
}

/// Decode one entry's compressed payload from a legacy RAR
/// archive's bytes.
///
/// Returns the entry's uncompressed contents as a `Vec<u8>`
/// of length `entry.header.unpacked_size`. Internally:
///
/// 1. Slices the compressed range from `archive_bytes`.
/// 2. STORED (`method == 0x30`) → byte-copy.
/// 3. Compressed (`method ∈ 0x31..=0x35`) → parse the first
///    block prologue; route to either [`LzDecoder`] or
///    [`PpmdSession`] based on the prologue's mode; run the
///    dispatcher until the entry is decoded.
///
/// # Errors
///
/// Any [`LegacyEntryError`] variant — see the type-level
/// docs for each.
pub fn decode_entry(
    archive_bytes: &[u8],
    entry: &LegacyFileEntry,
) -> Result<Vec<u8>, LegacyEntryError> {
    let data_offset = entry.data_offset;
    let packed_size = entry.header.packed_size;
    let unpacked_size = entry.header.unpacked_size;

    // Bounds-check the compressed range.
    let archive_len = archive_bytes.len() as u64;
    let end = data_offset
        .checked_add(packed_size)
        .ok_or(LegacyEntryError::DataAreaOverrun {
            data_offset,
            packed_size,
            archive_len,
        })?;
    if end > archive_len {
        return Err(LegacyEntryError::DataAreaOverrun {
            data_offset,
            packed_size,
            archive_len,
        });
    }
    let compressed = &archive_bytes[data_offset as usize..end as usize];

    match entry.header.method {
        // STORED — direct byte copy. Truncate / pad as the
        // header's unpacked_size dictates; for STORED the two
        // sizes always match.
        0x30 => Ok(compressed.to_vec()),
        // Compressed: decide LZ vs PPMd at first-prologue
        // parse time.
        0x31..=0x35 => decode_compressed_entry(compressed, entry, unpacked_size),
        method => Err(LegacyEntryError::UnsupportedMethod { method }),
    }
}

fn decode_compressed_entry(
    compressed: &[u8],
    entry: &LegacyFileEntry,
    unpacked_size: u64,
) -> Result<Vec<u8>, LegacyEntryError> {
    let dict_capacity = entry
        .header
        .file_flags
        .dictionary_size()
        .ok_or(LegacyEntryError::DirectoryEntry)? as usize;

    let mut br = BitReader::new(compressed);
    let mut lengths = [0u8; MAIN_TABLE_TOTAL];
    let mut output = Vec::with_capacity(unpacked_size as usize);

    let prologue = parse_block_prologue(&mut br, &mut lengths)?;

    match prologue {
        BlockPrologue::Ppmd { .. } => {
            decode_ppmd_entry(
                &prologue,
                compressed,
                &br,
                dict_capacity,
                unpacked_size,
                &mut output,
            )?;
        }
        BlockPrologue::Lz { ref tables, .. } => {
            decode_lz_entry(&mut br, tables, dict_capacity, unpacked_size, &mut output)?;
        }
    }

    Ok(output)
}

fn decode_ppmd_entry(
    prologue: &BlockPrologue,
    compressed: &[u8],
    br: &BitReader<'_>,
    dict_capacity: usize,
    unpacked_size: u64,
    output: &mut Vec<u8>,
) -> Result<(), LegacyEntryError> {
    // Locate the byte-aligned cursor where the range decoder
    // takes over. The prologue parser guarantees byte
    // alignment for PPMd-mode (the conditional payload bits
    // sum to multiples of 8 — 1 + 7 + 0/8/16/24).
    let (byte_idx, bit_off) = br.byte_position();
    if bit_off != 0 {
        return Err(LegacyEntryError::PostPrologueUnaligned { byte_idx, bit_off });
    }
    let rd_src = &compressed[byte_idx as usize..];

    let mut session = PpmdSession::new(dict_capacity)?;
    session.apply_prologue(prologue)?;

    let mut rd = RangeDecoder::new_rar(rd_src)?;
    let outcome = session.decode_block(&mut rd, output, unpacked_size)?;
    match outcome {
        PpmdBlockEnd::SizeReached | PpmdBlockEnd::EndOfData => {
            // Truncate output to unpacked_size. The PPMd code-4
            // / code-5 match path can emit a tail run that
            // overshoots the header's declared size; libarchive
            // similarly clips at `offset >= unp_size`.
            output.truncate(unpacked_size as usize);
            if (output.len() as u64) < unpacked_size {
                return Err(LegacyEntryError::SizeShortfall {
                    got: output.len() as u64,
                    expected: unpacked_size,
                });
            }
            Ok(())
        }
        PpmdBlockEnd::NewTable => Err(LegacyEntryError::MultiBlockNotSupported),
    }
}

fn decode_lz_entry(
    br: &mut BitReader<'_>,
    tables: &super::bootstrap::MainTables,
    dict_capacity: usize,
    unpacked_size: u64,
    output: &mut Vec<u8>,
) -> Result<(), LegacyEntryError> {
    let mut decoder = LzDecoder::new(dict_capacity)?;
    let outcome = decoder.decode_block(br, tables, output)?;
    match outcome {
        BlockEnd::EntryDone => {
            // The LZ dispatcher may emit a small overshoot
            // past unpacked_size on the last match (matches
            // can be up to ~260 bytes). Truncate to the
            // header-declared size; libarchive does the same.
            output.truncate(unpacked_size as usize);
            if (output.len() as u64) < unpacked_size {
                return Err(LegacyEntryError::SizeShortfall {
                    got: output.len() as u64,
                    expected: unpacked_size,
                });
            }
            Ok(())
        }
        BlockEnd::NextBlock => Err(LegacyEntryError::MultiBlockNotSupported),
        BlockEnd::FilterDecl => Err(LegacyEntryError::UnsupportedFilter),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rar::legacy::walk_archive;

    const TESTFILE_NON_SOLID: &[u8] =
        include_bytes!("../../../tests/fixtures/rar_legacy/testfile.rar3.rar");
    const EXPECTED_PLAINTEXT: &[u8] =
        include_bytes!("../../../tests/fixtures/rar_legacy/testfile.rar3.txt");

    #[test]
    fn decode_entry_emits_expected_plaintext_for_single_ppmd_entry() {
        let summary = walk_archive(TESTFILE_NON_SOLID).unwrap();
        assert_eq!(summary.entries.len(), 1);
        let entry = &summary.entries[0];
        let out = decode_entry(TESTFILE_NON_SOLID, entry).unwrap();
        assert_eq!(out, EXPECTED_PLAINTEXT);
    }

    #[test]
    fn decode_entry_surfaces_data_area_overrun_on_truncated_archive() {
        // Hand the function a sliced-too-short archive: walk
        // the original to get entry metadata, then call
        // decode_entry on a truncated slice that doesn't cover
        // the entry's data area.
        let summary = walk_archive(TESTFILE_NON_SOLID).unwrap();
        let entry = &summary.entries[0];
        let truncated = &TESTFILE_NON_SOLID[..(entry.data_offset as usize) + 4];
        let err = decode_entry(truncated, entry).unwrap_err();
        assert!(
            matches!(err, LegacyEntryError::DataAreaOverrun { .. }),
            "expected DataAreaOverrun, got {err:?}",
        );
    }

    #[test]
    fn decode_entry_rejects_unsupported_method() {
        let summary = walk_archive(TESTFILE_NON_SOLID).unwrap();
        let mut entry = summary.entries[0].clone();
        // Forge an unsupported method byte (0x36 is past the
        // legal 0x30..=0x35 range; matches the §A2 walker's
        // rejection range).
        entry.header.method = 0x36;
        let err = decode_entry(TESTFILE_NON_SOLID, &entry).unwrap_err();
        match err {
            LegacyEntryError::UnsupportedMethod { method } => {
                assert_eq!(method, 0x36);
            }
            other => panic!("expected UnsupportedMethod, got {other:?}"),
        }
    }
}
