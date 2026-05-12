//! Integration tests for RAR5 multi-volume support
//! (`docs/PLAN_multivolume_archives.md` §2).
//!
//! Sub-phases are layered onto the same on-disk fixture set in
//! `tests/fixtures/rar5_multivolume/` (real archives produced by
//! WinRAR 7.22 — see the directory's `README.md`):
//!
//! - **§2a** — baseline: `walk_archive` is fed only the first
//!   volume; the diagnostic must name the multi-volume continuation
//!   so users know to supply the rest of the set.
//! - **§2b** — `walk_archive_multivolume` accepts a buffer set,
//!   skips per-volume signature+main headers, and surfaces
//!   `FHD_SPLIT_AFTER` / `FHD_SPLIT_BEFORE` as a precise
//!   `UnsupportedFeature` naming the affected entry.
//! - **§2c+** — `RarPipeline` consumes the volume set end-to-end.
//!
//! Real-fixture details (`tests/fixtures/rar5_multivolume/`):
//!
//! - `multi.part1.rar` — first of three volumes (STORED, `-v16k`).
//!   Carries the main archive header, the small entry, and the
//!   leading slice of the spanning entry (`FHD_SPLIT_AFTER`).
//! - `multi.part2.rar` — second volume; spanning entry continues
//!   with both `FHD_SPLIT_BEFORE` and `FHD_SPLIT_AFTER`.
//! - `multi.part3.rar` — third volume; spanning entry's trailing
//!   slice (`FHD_SPLIT_BEFORE` only) + the `EndArchive` marker.

#![cfg(feature = "rar")]

#[path = "support/mod.rs"]
mod support;

use std::path::PathBuf;

use peel::rar::archive::{walk_archive, walk_archive_multivolume};
use peel::rar::format::arc_flags;
use peel::rar::RarError;

use support::rar_fixtures::{
    build_end_of_archive_with_flags, build_file_header, build_main_header, build_rar5_multivolume,
    RarEntrySpec,
};

/// Repo path to the committed multi-volume fixture directory.
fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("rar5_multivolume")
}

fn read_volume(name: &str) -> Vec<u8> {
    std::fs::read(fixture_dir().join(name)).unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
}

#[test]
fn walk_first_volume_alone_surfaces_split_diagnostic() {
    // §2a / §2b interplay: the committed multi.part1.rar carries a
    // small entry and the leading slice of a spanning entry
    // (FHD_SPLIT_AFTER). The walker now traverses the first
    // volume's headers and, on reaching the spanning entry's file
    // header, surfaces an UnsupportedFeature naming the entry — a
    // strictly more specific diagnostic than the pre-§2b
    // "multi-volume archive (volume N)" label, which only told the
    // user the archive *was* multi-volume rather than *what*
    // peel didn't yet handle about it.
    let archive = read_volume("multi.part1.rar");
    let err = walk_archive(&archive).expect_err("first-volume-only walk must surface a diagnostic");
    match err {
        RarError::UnsupportedFeature { feature } => {
            assert!(
                feature.contains("multi-volume file continuation")
                    && feature.contains("big.bin")
                    && feature.contains("continues into next volume"),
                "unexpected feature label: {feature}"
            );
        }
        other => panic!("expected UnsupportedFeature, got {other:?}"),
    }
}

#[test]
fn walk_full_set_of_real_volumes_surfaces_split_diagnostic_at_first_split() {
    // The committed three-volume real fixture's `big.bin` entry
    // spans every volume. Until §2d teaches the walker to fold
    // matching SPLIT_AFTER / SPLIT_BEFORE pairs into one logical
    // entry, walking the full set still surfaces a precise
    // UnsupportedFeature naming the entry in volume 1.
    let v1 = read_volume("multi.part1.rar");
    let v2 = read_volume("multi.part2.rar");
    let v3 = read_volume("multi.part3.rar");
    let err = walk_archive_multivolume(&[&v1[..], &v2[..], &v3[..]])
        .expect_err("real fixture set spans entries; §2b rejects SPLIT");
    match err {
        RarError::UnsupportedFeature { feature } => {
            assert!(
                feature.contains("multi-volume file continuation") && feature.contains("big.bin"),
                "unexpected feature label: {feature}"
            );
        }
        other => panic!("expected UnsupportedFeature, got {other:?}"),
    }
}

#[test]
fn walk_multivolume_succeeds_when_no_entry_spans_a_boundary() {
    // Synthetic fixture: three small entries, one per volume, none
    // spanning. The walker should aggregate entry metadata across
    // the volumes and report data_offsets in the global
    // (concatenated) byte space.
    let per_volume = vec![
        vec![RarEntrySpec::stored("a.txt", b"AAAA".to_vec())],
        vec![RarEntrySpec::stored("b.txt", b"BBBB".to_vec())],
        vec![RarEntrySpec::stored("c.txt", b"CCCC".to_vec())],
    ];
    let volumes = build_rar5_multivolume(&per_volume);
    let v: Vec<&[u8]> = volumes.iter().map(Vec::as_slice).collect();
    let summary =
        walk_archive_multivolume(&v).expect("synthetic non-spanning multi-volume walks cleanly");

    assert_eq!(summary.entries.len(), 3);
    assert_eq!(summary.entries[0].header.name, "a.txt");
    assert_eq!(summary.entries[1].header.name, "b.txt");
    assert_eq!(summary.entries[2].header.name, "c.txt");
    assert!(!summary.eof_more_volumes);

    // data_offsets are absolute global offsets. Volume 0's offset
    // for a.txt is internal to volume 0; b.txt's offset must be
    // ≥ |volume 0| (i.e. b.txt sits in volume 1's bytes).
    let v0_len = volumes[0].len() as u64;
    let v1_len = volumes[1].len() as u64;
    assert!(summary.entries[0].data_offset < v0_len);
    assert!(
        summary.entries[1].data_offset >= v0_len
            && summary.entries[1].data_offset < v0_len + v1_len
    );
    assert!(summary.entries[2].data_offset >= v0_len + v1_len);
}

#[test]
fn walk_multivolume_rejects_extra_supplied_volume() {
    // Build a single-volume archive (final EOA, more_volumes=false)
    // and feed it as if it were the leading volume of a two-volume
    // set: the second buffer is the same archive bytes. The walker
    // must error on the first volume's final EOA because the input
    // has another volume past it.
    let per_volume = vec![vec![RarEntrySpec::stored("solo.txt", b"x".to_vec())]];
    let mut volumes = build_rar5_multivolume(&per_volume);
    // build_rar5_multivolume(single-element) produces a non-final
    // EOA by inversion (`!is_last`); rebuild here as a one-volume
    // archive whose EOA clears more_volumes, then re-use it as both
    // entries of the bogus input list.
    let solo = volumes.pop().expect("one volume");
    // The single-element call above already sets the lone volume's
    // EOA to `more_volumes=false` because `is_last=true` → flag=!is_last=false.
    let v: Vec<&[u8]> = vec![&solo[..], &solo[..]];
    let err = walk_archive_multivolume(&v).expect_err("extra trailing volume must surface");
    match err {
        RarError::VolumeSetMismatch { detail } => {
            assert!(
                detail.contains("terminates the archive") && detail.contains("supplied beyond"),
                "unexpected detail: {detail}"
            );
        }
        other => panic!("expected VolumeSetMismatch, got {other:?}"),
    }
}

#[test]
fn walk_multivolume_rejects_volume_number_mismatch() {
    // Hand-build two volumes whose end-of-archive flags pair up
    // consistently with their input position (so the EOA `more_volumes`
    // shape check passes) but whose main-header `volume_number`
    // fields disagree with the input order. Volume 2's wire number
    // is forced to 99 while the walker expects 1 (0-based for the
    // second supplied volume).
    let mut v0 = Vec::new();
    v0.extend_from_slice(&peel::rar::SIGNATURE_MAGIC);
    v0.extend_from_slice(&build_main_header(
        arc_flags::VOLUME | arc_flags::VOLUME_NUMBER,
        Some(0),
    ));
    let (h0, d0) = build_file_header(&RarEntrySpec::stored("a.txt", b"A".to_vec()));
    v0.extend_from_slice(&h0);
    v0.extend_from_slice(&d0);
    v0.extend_from_slice(&build_end_of_archive_with_flags(true));

    let mut v1 = Vec::new();
    v1.extend_from_slice(&peel::rar::SIGNATURE_MAGIC);
    v1.extend_from_slice(&build_main_header(
        arc_flags::VOLUME | arc_flags::VOLUME_NUMBER,
        Some(99), // expected 1 — must mismatch
    ));
    let (h1, d1) = build_file_header(&RarEntrySpec::stored("b.txt", b"B".to_vec()));
    v1.extend_from_slice(&h1);
    v1.extend_from_slice(&d1);
    v1.extend_from_slice(&build_end_of_archive_with_flags(false));

    let v: Vec<&[u8]> = vec![&v0[..], &v1[..]];
    let err = walk_archive_multivolume(&v).expect_err("mismatched wire volume_number must surface");
    match err {
        RarError::VolumeSetMismatch { detail } => {
            assert!(
                detail.contains("volume_number=99") && detail.contains("expected 1"),
                "unexpected detail: {detail}"
            );
        }
        other => panic!("expected VolumeSetMismatch, got {other:?}"),
    }
}
