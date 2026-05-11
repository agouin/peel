//! End-to-end PPMd-mode legacy RAR decode against the
//! ssokolow CC0 corpus.
//!
//! Exercises the per-entry front-door
//! [`peel::decode::rar_legacy::entry::decode_entry`] (landed
//! §C1h). The full stack underneath:
//!
//! 1. `walk_archive` — header parse (§A2).
//! 2. `decode_entry`:
//!    - slice the entry's compressed data area;
//!    - parse the first block prologue (§C1c) to discover the
//!      mode;
//!    - PPMd → `PpmdSession` (§C1g) over a
//!      `RangeDecoder::new_rar` (§C1f); LZ → `LzDecoder`
//!      (§C1e₁) over `parse_block_prologue`'s returned
//!      `MainTables`;
//!    - truncate to `unpacked_size`.
//!
//! The ssokolow corpus is PPMd-only (§C1e₂'s discovery), so the
//! LZ branch isn't exercised here — `src/decode/rar_legacy/lzss.rs`
//! covers it with synthetic fixtures.

#![cfg(feature = "rar")]

use peel::decode::rar_legacy::entry::decode_entry;
use peel::rar::legacy::walk_archive;

const TESTFILE_NON_SOLID: &[u8] = include_bytes!("fixtures/rar_legacy/testfile.rar3.rar");
const TESTFILE_SOLID: &[u8] = include_bytes!("fixtures/rar_legacy/testfile.rar3.solid.rar");
const EXPECTED_PLAINTEXT: &[u8] = include_bytes!("fixtures/rar_legacy/testfile.rar3.txt");

const TESTFILE_CBR: &[u8] = include_bytes!("fixtures/rar_legacy/testfile.rar3.cbr");
const EXPECTED_CBR_JPG: &[u8] = include_bytes!("fixtures/rar_legacy/testfile.cbr.jpg");
const EXPECTED_CBR_PNG: &[u8] = include_bytes!("fixtures/rar_legacy/testfile.cbr.png");

/// Decode every entry in an archive and return a `Vec` of
/// `(entry name, decoded bytes)` pairs. Asserts the §C1h
/// front-door surfaces no errors.
fn decode_all_entries(archive: &[u8]) -> Vec<(String, Vec<u8>)> {
    let summary = walk_archive(archive).expect("walk");
    summary
        .entries
        .iter()
        .map(|entry| {
            let bytes = decode_entry(archive, entry).expect("decode_entry");
            (entry.header.name.clone(), bytes)
        })
        .collect()
}

#[test]
fn ssokolow_testfile_non_solid_decodes_to_expected_plaintext() {
    let entries = decode_all_entries(TESTFILE_NON_SOLID);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].0, "testfile.txt");
    assert_eq!(&entries[0].1[..], EXPECTED_PLAINTEXT);
}

#[test]
fn ssokolow_testfile_solid_decodes_to_expected_plaintext() {
    let entries = decode_all_entries(TESTFILE_SOLID);
    assert_eq!(entries.len(), 1);
    assert_eq!(&entries[0].1[..], EXPECTED_PLAINTEXT);
}

#[test]
fn ssokolow_testfile_cbr_decodes_both_entries_byte_perfectly() {
    let entries = decode_all_entries(TESTFILE_CBR);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].0, "testfile.jpg");
    assert_eq!(
        &entries[0].1[..],
        EXPECTED_CBR_JPG,
        "testfile.jpg decoded {} bytes; expected {}",
        entries[0].1.len(),
        EXPECTED_CBR_JPG.len(),
    );
    assert_eq!(entries[1].0, "testfile.png");
    assert_eq!(
        &entries[1].1[..],
        EXPECTED_CBR_PNG,
        "testfile.png decoded {} bytes; expected {}",
        entries[1].1.len(),
        EXPECTED_CBR_PNG.len(),
    );
}

#[test]
fn fixture_summary_carries_expected_metadata() {
    let summary = walk_archive(TESTFILE_NON_SOLID).expect("walk");
    assert_eq!(summary.entries.len(), 1);
    let entry = &summary.entries[0];
    assert_eq!(entry.header.name, "testfile.txt");
    assert_eq!(entry.header.unpacked_size, EXPECTED_PLAINTEXT.len() as u64);
    assert_eq!(entry.header.method, 0x35);
    assert!(
        (29..=36).contains(&entry.header.unp_ver),
        "unp_ver = {} should be in [29..=36]",
        entry.header.unp_ver,
    );
}

#[test]
fn solid_fixture_main_header_carries_solid_flag() {
    let summary = walk_archive(TESTFILE_SOLID).expect("walk");
    assert!(summary.solid, "solid fixture should set MHD_SOLID");
}

#[test]
fn cbr_fixture_is_not_solid() {
    // `.cbr` is just a renamed RAR archive; this one's
    // non-solid (each entry has independent compression state).
    let summary = walk_archive(TESTFILE_CBR).expect("walk");
    assert!(!summary.solid);
    assert_eq!(summary.entries.len(), 2);
}
