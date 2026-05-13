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

use peel::encryption::EncryptionError;
use peel::rar::archive::walk_archive;
use peel::rar::format::arc_flags;
use peel::rar::RarError;

use support::rar_fixtures::{
    build_end_of_archive_with_flags, build_file_header, build_main_header, build_rar4_magic_only,
    build_rar5, build_rar5_encrypted_header, build_rar5_per_file_encrypted, EncryptedEntrySpec,
    RarEntrySpec,
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
fn walk_first_volume_in_isolation_succeeds_when_no_more_volumes_follow() {
    // After `internal/PLAN_multivolume_archives.md` §2b the walker no
    // longer rejects `MHD_VOLUME` archives at the main header. A
    // self-contained single buffer whose end-of-archive header
    // clears the `more_volumes` flag is treated like any other
    // single-volume archive: the entry list is returned.
    let archive = build_rar5(
        arc_flags::VOLUME | arc_flags::VOLUME_NUMBER,
        Some(0), // 0-based wire encoding for "first volume"
        &[RarEntrySpec::stored("only.txt", b"x".to_vec())],
    );
    let summary = walk_archive(&archive).expect("self-contained MHD_VOLUME walk succeeds");
    assert_eq!(summary.entries.len(), 1);
    assert_eq!(summary.entries[0].header.name, "only.txt");
    assert!(!summary.eof_more_volumes);
}

#[test]
fn walk_first_volume_with_more_volumes_flag_surfaces_volume_set_mismatch() {
    // Real multi-volume archives have the first volume's
    // end-of-archive header set `more_volumes = true`; feeding only
    // the first volume to the single-buffer `walk_archive` entry
    // point now surfaces a precise `VolumeSetMismatch` instead of
    // the pre-§2b `UnsupportedFeature` blanket rejection, so callers
    // can dispatch to multi-volume discovery on the strength of the
    // diagnostic.
    let mut archive = Vec::new();
    archive.extend_from_slice(&peel::rar::SIGNATURE_MAGIC);
    archive.extend_from_slice(&build_main_header(
        arc_flags::VOLUME | arc_flags::VOLUME_NUMBER,
        Some(0),
    ));
    let (header, data) = build_file_header(&RarEntrySpec::stored("only.txt", b"x".to_vec()));
    archive.extend_from_slice(&header);
    archive.extend_from_slice(&data);
    archive.extend_from_slice(&build_end_of_archive_with_flags(true));

    let err = walk_archive(&archive).expect_err("missing further volumes must surface");
    match err {
        RarError::VolumeSetMismatch { detail } => {
            assert!(
                detail.contains("more_volumes=true") && detail.contains("not supplied"),
                "unexpected detail: {detail}"
            );
        }
        other => panic!("expected VolumeSetMismatch, got {other:?}"),
    }
}

#[test]
fn walk_archive_encryption_header_rejects_with_encryption_label() {
    // Archive-header encryption (HEAD_CRYPT) currently surfaces a
    // unified [`EncryptionError::UnsupportedCipher`] until the
    // walker-side header-stream wrapping lands (`internal/PLAN_archive_encryption.md`
    // §4). Per-file encryption is supported separately via the file
    // header's encryption extra record.
    let entries = vec![RarEntrySpec::stored("locked.txt", b"x".to_vec())];
    let archive = build_rar5_encrypted_header(&entries);
    let err = walk_archive(&archive).expect_err("walk should fail on encryption");
    match err {
        RarError::Encryption(EncryptionError::UnsupportedCipher { detail }) => {
            assert!(detail.contains("archive-header encryption"), "got {detail}");
        }
        other => panic!("expected Encryption(UnsupportedCipher), got {other:?}"),
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

#[test]
fn walk_per_file_encrypted_archive_surfaces_encryption_record() {
    let password = b"hunter2";
    let entries = vec![
        EncryptedEntrySpec::stored("alpha.txt", b"hello, RAR".to_vec()),
        EncryptedEntrySpec::stored("nested/beta.bin", vec![0x42u8; 1024]),
    ];
    let archive = build_rar5_per_file_encrypted(password, &entries);

    let summary = walk_archive(&archive).expect("walk encrypted archive");
    assert_eq!(summary.entries.len(), 2);
    for (got, spec) in summary.entries.iter().zip(entries.iter()) {
        assert_eq!(got.header.name, spec.name);
        // packed_size is round-up-to-16 of plaintext length.
        let expected_packed = (spec.uncompressed.len() + 15) & !15;
        assert_eq!(got.packed_size, expected_packed as u64);
        let enc = got.encryption.as_ref().expect("entry is encrypted");
        assert_eq!(enc.salt, spec.salt);
        assert_eq!(enc.iv, spec.iv);
        assert_eq!(enc.kdf_count, spec.kdf_count);
        assert!(enc.pswcheck.is_some());
    }
}
