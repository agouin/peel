//! Integration tests for the RAR5 wire-format walker
//! (`peel::rar::archive::walk_archive`).
//!
//! The §1 demo's behavior — open archive, list entries, surface the
//! solid flag, refuse multi-volume / encrypted / RAR4 cleanly — is
//! exercised end-to-end here against fixtures synthesized by
//! `tests/support/rar_fixtures.rs`. Wire-format unit tests live next
//! to the parsers in `src/rar/format.rs`; this file only covers the
//! archive-level walker.

#![cfg(feature = "rar")]

#[path = "support/mod.rs"]
mod support;

use peel::rar::archive::walk_archive;
use peel::rar::format::arc_flags;
use peel::rar::RarError;

use support::rar_fixtures::{
    build_rar4_magic_only, build_rar5, build_rar5_encrypted_header, RarEntrySpec,
};

#[test]
fn walk_non_solid_archive_with_three_stored_entries() {
    let entries = vec![
        RarEntrySpec::stored("alpha.txt", b"hello".to_vec()),
        RarEntrySpec::stored("nested/beta.txt", b"world!".to_vec()),
        RarEntrySpec::stored("gamma.bin", vec![0x42; 64]),
    ];
    let archive = build_rar5(0, None, &entries);
    let summary = walk_archive(&archive).expect("walk should succeed");
    assert!(!summary.solid);
    assert!(!summary.has_recovery_record);
    assert!(!summary.locked);
    assert!(!summary.eof_more_volumes);
    assert_eq!(summary.entries.len(), 3);

    assert_eq!(summary.entries[0].header.name, "alpha.txt");
    assert_eq!(
        summary.entries[0].header.unpacked_size,
        b"hello".len() as u64
    );
    assert_eq!(summary.entries[0].packed_size, b"hello".len() as u64);
    assert_eq!(summary.entries[0].header.compression.method(), 0);

    assert_eq!(summary.entries[1].header.name, "nested/beta.txt");
    assert_eq!(summary.entries[2].header.name, "gamma.bin");
    assert_eq!(summary.entries[2].packed_size, 64);

    // data_offsets must be strictly increasing (the walker visits
    // entries in archive order) and bounded by the archive length.
    for window in summary.entries.windows(2) {
        assert!(window[0].data_offset < window[1].data_offset);
    }
    let last = summary.entries.last().unwrap();
    assert!(last.data_offset + last.packed_size < archive.len() as u64);
}

#[test]
fn walk_solid_archive_flips_solid_flag() {
    let entries = vec![
        RarEntrySpec::stored("a", b"AAA".to_vec()),
        RarEntrySpec::stored("b", b"BBBB".to_vec()),
        RarEntrySpec::stored("c", b"CCCCC".to_vec()),
    ];
    let archive = build_rar5(arc_flags::SOLID, None, &entries);
    let summary = walk_archive(&archive).expect("walk should succeed");
    assert!(summary.solid);
    assert_eq!(summary.entries.len(), 3);
}

#[test]
fn walk_multi_volume_archive_rejects_with_volume_number() {
    let archive = build_rar5(
        arc_flags::VOLUME | arc_flags::VOLUME_NUMBER,
        Some(3),
        &[RarEntrySpec::stored("only.txt", b"x".to_vec())],
    );
    let err = walk_archive(&archive).expect_err("walk should fail on multi-volume");
    match err {
        RarError::UnsupportedFeature { feature } => {
            assert!(
                feature.contains("multi-volume") && feature.contains("volume 3"),
                "unexpected feature label: {feature}"
            );
        }
        other => panic!("expected UnsupportedFeature, got {other:?}"),
    }
}

#[test]
fn walk_multi_volume_without_volume_number_still_rejects() {
    let archive = build_rar5(
        arc_flags::VOLUME,
        None,
        &[RarEntrySpec::stored("only.txt", b"x".to_vec())],
    );
    let err = walk_archive(&archive).expect_err("walk should fail on multi-volume");
    match err {
        RarError::UnsupportedFeature { feature } => {
            assert!(feature.contains("multi-volume"), "got {feature}");
        }
        other => panic!("expected UnsupportedFeature, got {other:?}"),
    }
}

#[test]
fn walk_archive_encryption_header_rejects_with_encryption_label() {
    let entries = vec![RarEntrySpec::stored("locked.txt", b"x".to_vec())];
    let archive = build_rar5_encrypted_header(&entries);
    let err = walk_archive(&archive).expect_err("walk should fail on encryption");
    match err {
        RarError::UnsupportedFeature { feature } => {
            assert!(feature.contains("encryption"), "got {feature}");
        }
        other => panic!("expected UnsupportedFeature, got {other:?}"),
    }
}

#[test]
fn walk_rar4_archive_rejects_with_unsupported_format_version() {
    let archive = build_rar4_magic_only();
    let err = walk_archive(&archive).expect_err("walk should fail on RAR4");
    match err {
        RarError::UnsupportedFormatVersion { major, minor } => {
            assert_eq!(major, 4);
            assert_eq!(minor, 0);
        }
        other => panic!("expected UnsupportedFormatVersion, got {other:?}"),
    }
}

#[test]
fn walk_truncated_archive_surfaces_specific_error() {
    let archive = build_rar5(0, None, &[RarEntrySpec::stored("x", b"y".to_vec())]);
    // Truncate just before the end-of-archive header — the walker
    // should surface a structural error, not silently succeed.
    let truncated = &archive[..archive.len() - 4];
    let err = walk_archive(truncated).expect_err("truncated archive should fail");
    assert!(
        matches!(
            err,
            RarError::Truncated { .. }
                | RarError::CorruptHeader { .. }
                | RarError::HeaderCrc32Mismatch { .. }
        ),
        "expected structural error, got {err:?}"
    );
}

#[test]
fn walk_archive_lists_compressed_entry_with_method_metadata() {
    use peel::rar::format::{file_flags, hdr_flags};
    use support::rar_fixtures::{
        build_end_of_archive, build_generic_header, build_main_header, encode_vint,
    };

    // After §E1 of `PLAN_rar5_decoder.md`, the walker no longer
    // rejects standard-algorithm entries — listing surfaces them
    // intact and the §3 pipeline dispatches through the
    // hand-rolled decoder. The walker still rejects reserved
    // method codes (6, 7) because they're undefined by the spec.
    let mut fields = Vec::new();
    fields.extend_from_slice(&encode_vint(0)); // file flags
    fields.extend_from_slice(&encode_vint(0)); // unpacked size
    fields.extend_from_slice(&encode_vint(0)); // attributes
    let comp_info: u64 = 1u64 << 7; // method = 1 (bits 7..9)
    fields.extend_from_slice(&encode_vint(comp_info));
    fields.extend_from_slice(&encode_vint(1)); // host os
    fields.extend_from_slice(&encode_vint(1)); // name length
    fields.push(b'q');
    let _ = file_flags::DIRECTORY; // suppress unused-import lint
    let _ = hdr_flags::DATA_AREA;

    let mut archive = Vec::new();
    archive.extend_from_slice(&peel::rar::SIGNATURE_MAGIC);
    archive.extend_from_slice(&build_main_header(0, None));
    archive.extend_from_slice(&build_generic_header(2, 0, &fields, &[], None));
    archive.extend_from_slice(&build_end_of_archive());

    let summary = walk_archive(&archive).expect("compressed listing succeeds");
    assert_eq!(summary.entries.len(), 1);
    assert_eq!(summary.entries[0].header.compression.method(), 1);
    assert_eq!(summary.entries[0].header.name, "q");
}

#[test]
fn walk_archive_rejects_reserved_compression_method() {
    use peel::rar::format::{file_flags, hdr_flags};
    use support::rar_fixtures::{
        build_end_of_archive, build_generic_header, build_main_header, encode_vint,
    };

    // Methods 6 and 7 are reserved by the RAR5 spec and never
    // produced by current encoders. The walker rejects them so
    // future RARs that mis-set the field surface as a precise
    // diagnostic rather than getting fed to the hand-rolled
    // decoder.
    let mut fields = Vec::new();
    fields.extend_from_slice(&encode_vint(0));
    fields.extend_from_slice(&encode_vint(0));
    fields.extend_from_slice(&encode_vint(0));
    let comp_info: u64 = 6u64 << 7; // method = 6 (reserved)
    fields.extend_from_slice(&encode_vint(comp_info));
    fields.extend_from_slice(&encode_vint(1));
    fields.extend_from_slice(&encode_vint(1));
    fields.push(b'r');
    let _ = file_flags::DIRECTORY;
    let _ = hdr_flags::DATA_AREA;

    let mut archive = Vec::new();
    archive.extend_from_slice(&peel::rar::SIGNATURE_MAGIC);
    archive.extend_from_slice(&build_main_header(0, None));
    archive.extend_from_slice(&build_generic_header(2, 0, &fields, &[], None));
    archive.extend_from_slice(&build_end_of_archive());

    let err = walk_archive(&archive).expect_err("reserved method should fail");
    match err {
        RarError::UnsupportedFeature { feature } => {
            assert!(
                feature.contains("method 6") && feature.contains("reserved"),
                "got {feature}"
            );
        }
        other => panic!("expected UnsupportedFeature, got {other:?}"),
    }
}
