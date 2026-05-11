//! End-to-end PPMd-mode legacy RAR decode against the
//! ssokolow CC0 corpus.
//!
//! This is §C1g's real-archive cross-check. The full stack
//! exercised here is:
//!
//! 1. `crate::rar::legacy::walk_archive` — header parse +
//!    per-entry data-offset walk (§A2).
//! 2. `crate::decode::rar_legacy::bits::BitReader` — over the
//!    entry's compressed payload (§C1a).
//! 3. `parse_block_prologue` — byte-align + `is_ppmd_block`
//!    flag + 7-bit `ppmd_flags` + conditional dict / max-order
//!    / init-escape payload (§C1c).
//! 4. `RangeDecoder::new_rar` — 4-byte init prefix over the
//!    post-prologue bytes (§C1f).
//! 5. `PpmdSession::apply_prologue` + `decode_block` — model
//!    alloc + symbol-level dispatch (§C1g).
//!
//! Both ssokolow archives ship the same 12-byte plaintext
//! ("Testing 123\n") via a single PPMd block per entry. The
//! `solid` variant just toggles the main-header `MHD_SOLID`
//! flag and bumps the per-entry dict size (128 KiB → 1 MiB);
//! at the wire-format level the compressed payload is
//! identical. The cross-check passes when both byte streams
//! decode to the same 12-byte plaintext.

#![cfg(feature = "rar")]

use peel::decode::ppmd2::range_dec::RangeDecoder;
use peel::decode::rar_legacy::bits::BitReader;
use peel::decode::rar_legacy::block_header::{parse_block_prologue, BlockPrologue};
use peel::decode::rar_legacy::bootstrap::MAIN_TABLE_TOTAL;
use peel::decode::rar_legacy::ppmd_entry::{PpmdBlockEnd, PpmdSession};
use peel::rar::legacy::walk_archive;

const TESTFILE_NON_SOLID: &[u8] = include_bytes!("fixtures/rar_legacy/testfile.rar3.rar");
const TESTFILE_SOLID: &[u8] = include_bytes!("fixtures/rar_legacy/testfile.rar3.solid.rar");
const EXPECTED_PLAINTEXT: &[u8] = include_bytes!("fixtures/rar_legacy/testfile.rar3.txt");

/// Decode a single-entry archive's PPMd payload through the
/// full stack and return the emitted bytes.
fn decode_single_entry_ppmd(archive: &[u8]) -> Vec<u8> {
    let summary = walk_archive(archive).expect("walk");
    assert_eq!(summary.entries.len(), 1, "fixture should be single-entry");
    let entry = &summary.entries[0];

    // Slice out the compressed payload.
    let data_start = entry.data_offset as usize;
    let data_end = data_start + entry.header.packed_size as usize;
    let compressed = &archive[data_start..data_end];

    // Drive the prologue parser over the compressed bytes.
    // The block prologue is bit-level (1-bit is_ppmd + 7-bit
    // flags + conditional bytes); the post-prologue cursor
    // lands on a byte boundary, which is where the range
    // decoder picks up.
    let mut br = BitReader::new(compressed);
    let mut lengths = [0u8; MAIN_TABLE_TOTAL];
    let prologue = parse_block_prologue(&mut br, &mut lengths).expect("prologue");

    // Sanity-check: this fixture is PPMd-mode.
    assert!(
        matches!(prologue, BlockPrologue::Ppmd { .. }),
        "expected PPMd prologue, got {prologue:?}"
    );

    // Locate the byte-aligned cursor where the range decoder
    // takes over. The block_header parser guarantees byte
    // alignment after the prologue payload (1 + 7 + 0/8/16/24
    // bits all sum to a byte boundary).
    let (byte_idx, bit_off) = br.byte_position();
    assert_eq!(
        bit_off, 0,
        "post-prologue cursor must be byte-aligned for the RangeDecoder",
    );
    let rd_src = &compressed[byte_idx as usize..];

    // Size the dict from the file header. The encoder picks
    // dict size from `unp_size`; the file flags carry the
    // 64 KiB..=4 MiB selector for back-compat.
    let dict_capacity = entry
        .header
        .file_flags
        .dictionary_size()
        .expect("non-directory entry should have a dict-size flag")
        as usize;

    let mut session = PpmdSession::new(dict_capacity).expect("session");
    session.apply_prologue(&prologue).expect("apply_prologue");

    let mut rd = RangeDecoder::new_rar(rd_src).expect("range decoder init");
    let mut out = Vec::with_capacity(entry.header.unpacked_size as usize);
    let outcome = session
        .decode_block(&mut rd, &mut out, entry.header.unpacked_size)
        .expect("decode_block");
    // Allow both SizeReached (decoder hit unp_size) and
    // EndOfData (encoder emitted a code-2 EOD marker before
    // or right at unp_size). Both are valid termination
    // conditions per libarchive's `read_data_compressed` loop.
    assert!(
        matches!(outcome, PpmdBlockEnd::SizeReached | PpmdBlockEnd::EndOfData),
        "unexpected block-end outcome: {outcome:?}",
    );
    out
}

#[test]
fn ssokolow_testfile_non_solid_decodes_to_expected_plaintext() {
    let out = decode_single_entry_ppmd(TESTFILE_NON_SOLID);
    assert_eq!(
        &out[..EXPECTED_PLAINTEXT.len()],
        EXPECTED_PLAINTEXT,
        "non-solid fixture decoded {} bytes; expected {:?}",
        out.len(),
        std::str::from_utf8(EXPECTED_PLAINTEXT).unwrap_or("<non-utf8>"),
    );
}

#[test]
fn ssokolow_testfile_solid_decodes_to_expected_plaintext() {
    let out = decode_single_entry_ppmd(TESTFILE_SOLID);
    assert_eq!(
        &out[..EXPECTED_PLAINTEXT.len()],
        EXPECTED_PLAINTEXT,
        "solid fixture decoded {} bytes; expected {:?}",
        out.len(),
        std::str::from_utf8(EXPECTED_PLAINTEXT).unwrap_or("<non-utf8>"),
    );
}

#[test]
fn fixture_summary_carries_expected_metadata() {
    let summary = walk_archive(TESTFILE_NON_SOLID).expect("walk");
    assert_eq!(summary.entries.len(), 1);
    let entry = &summary.entries[0];
    assert_eq!(entry.header.name, "testfile.txt");
    assert_eq!(entry.header.unpacked_size, EXPECTED_PLAINTEXT.len() as u64);
    // The encoder picks compression v29..36 (the RAR3 family);
    // method 0x35 == "-m5" (max).
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
