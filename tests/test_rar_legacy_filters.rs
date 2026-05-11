//! End-to-end LZ + standard-filter legacy RAR decode against
//! the §C2b corpus.
//!
//! Exercises the per-entry front-door
//! [`peel::decode::rar_legacy::entry::decode_entry`] (landed
//! §C1h, extended §C2b) for the LZ-mode + RarVM-filter path.
//! Round-one §C2b ships:
//!
//! 1. Multi-block LZ entries (both `BlockEnd::EntryDone` and
//!    `BlockEnd::NextBlock` terminators are treated as "block
//!    done, re-parse prologue if more bytes remain"; libarchive's
//!    `parse_codes` + `start_new_table` pattern).
//! 2. Per-entry `FilterStack` accumulation: `symbol 257` decls
//!    parse via [`peel::decode::rar_legacy::vm::parse_filter_declaration`]
//!    and queue onto the stack.
//! 3. Post-decode filter dispatch via
//!    [`peel::decode::rar_legacy::vm::apply_pending_filters_in_place`]
//!    over the four WinRAR standard filters
//!    (DELTA / E8 / E8E9 / RGB / AUDIO; E8E9 isn't exercised here
//!    because `rar 3.93`'s encoder picks pure-E8 for x86 inputs,
//!    but the executor is shared with E8 so the E8 fixture covers
//!    80% of the E8E9 path).
//!
//! Corpus generated against `rar 3.93` (Linux x86_64 binary,
//! RARLAB public release) under Docker `linux/amd64` emulation,
//! with `-mcT-` to disable PPMd and `-mcX+` to force each
//! standard filter. See `tests/fixtures/rar_legacy/README.md`
//! for the encode recipe and `docs/PLAN_rar3.md` §C2b for the
//! corpus-sourcing rationale.

#![cfg(feature = "rar")]

use peel::decode::rar_legacy::entry::decode_entry;
use peel::rar::legacy::walk_archive;

const FILTER_E8_RAR: &[u8] = include_bytes!("fixtures/rar_legacy/filter_e8.rar");
const FILTER_E8_BIN: &[u8] = include_bytes!("fixtures/rar_legacy/filter_e8.bin");

const FILTER_RGB_RAR: &[u8] = include_bytes!("fixtures/rar_legacy/filter_rgb.rar");
const FILTER_RGB_BIN: &[u8] = include_bytes!("fixtures/rar_legacy/filter_rgb.bin");

const FILTER_AUDIO_RAR: &[u8] = include_bytes!("fixtures/rar_legacy/filter_audio.rar");
const FILTER_AUDIO_BIN: &[u8] = include_bytes!("fixtures/rar_legacy/filter_audio.bin");

const FILTER_DELTA_RAR: &[u8] = include_bytes!("fixtures/rar_legacy/filter_delta.rar");
const FILTER_DELTA_BIN: &[u8] = include_bytes!("fixtures/rar_legacy/filter_delta.bin");

const FILTER_MULTI_RAR: &[u8] = include_bytes!("fixtures/rar_legacy/filter_multi.rar");
const FILTER_MULTI_BIN: &[u8] = include_bytes!("fixtures/rar_legacy/filter_multi.bin");

/// Decode the single entry in `archive` and assert the bytes
/// match `expected` exactly (no truncation, no padding).
fn decode_and_compare(archive: &[u8], expected: &[u8], tag: &str) {
    let summary = walk_archive(archive).unwrap_or_else(|e| panic!("{tag}: walk_archive: {e}"));
    assert_eq!(summary.entries.len(), 1, "{tag}: entry count");
    let entry = &summary.entries[0];
    assert_eq!(
        entry.header.unpacked_size,
        expected.len() as u64,
        "{tag}: unpacked_size from header"
    );
    let decoded =
        decode_entry(archive, entry).unwrap_or_else(|e| panic!("{tag}: decode_entry: {e}"));
    assert_eq!(decoded.len(), expected.len(), "{tag}: decoded byte count");
    assert_eq!(decoded, expected, "{tag}: decoded bytes mismatch");
}

#[test]
fn e8_filter_archive_decodes_byte_perfectly() {
    decode_and_compare(FILTER_E8_RAR, FILTER_E8_BIN, "filter_e8");
}

#[test]
fn rgb_filter_archive_decodes_byte_perfectly() {
    decode_and_compare(FILTER_RGB_RAR, FILTER_RGB_BIN, "filter_rgb");
}

#[test]
fn audio_filter_archive_decodes_byte_perfectly() {
    decode_and_compare(FILTER_AUDIO_RAR, FILTER_AUDIO_BIN, "filter_audio");
}

#[test]
fn delta_filter_archive_decodes_byte_perfectly() {
    decode_and_compare(FILTER_DELTA_RAR, FILTER_DELTA_BIN, "filter_delta");
}

/// Multi-filter entry: 3 filter declarations (E8 + Delta + E8
/// with program-cache reuse) in a single LZ block, exercising
/// the dispatcher's FIFO drain, the `flags & 0x10` register-
/// mask path on the Delta declaration, and the
/// `flags & 0x40` +258 block-start bias + `!(flags & 0x20)`
/// implicit-block-length path on the third E8 reuse.
#[test]
fn multi_filter_archive_decodes_byte_perfectly() {
    decode_and_compare(FILTER_MULTI_RAR, FILTER_MULTI_BIN, "filter_multi");
}
