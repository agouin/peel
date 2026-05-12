//! Integration tests for RAR5 multi-volume support
//! (`docs/PLAN_multivolume_archives.md` §2).
//!
//! Sub-phases are layered onto the same on-disk fixture set in
//! `tests/fixtures/rar5_multivolume/` (real archives produced by
//! WinRAR 7.22 — see the directory's `README.md`):
//!
//! - **§2a** — baseline rejection. `walk_archive` is fed only the
//!   first volume; it must still surface
//!   [`RarError::UnsupportedFeature`] with a multi-volume label so a
//!   regression doesn't downgrade the diagnostic to a generic
//!   parse failure.
//! - **§2b+** (forthcoming) — `walk_archive` accepts a multi-volume
//!   buffer set, skips per-volume signature+main headers, and
//!   surfaces `FHD_SPLIT_AFTER` / `FHD_SPLIT_BEFORE` as
//!   discriminated entries.
//! - **§2c+** — `RarPipeline` consumes the volume set end-to-end.
//!
//! Fixture details (committed under
//! `tests/fixtures/rar5_multivolume/`):
//!
//! - `multi.part1.rar` — first of three volumes (STORED, `-v16k`).
//!   Carries the main archive header, the small entry, and the
//!   leading slice of the spanning entry (`FHD_SPLIT_AFTER`).
//! - `multi.part2.rar` — second volume; spanning entry continues
//!   with both `FHD_SPLIT_BEFORE` and `FHD_SPLIT_AFTER`.
//! - `multi.part3.rar` — third volume; spanning entry's trailing
//!   slice (`FHD_SPLIT_BEFORE` only) + the `EndArchive` marker.

#![cfg(feature = "rar")]

use std::path::PathBuf;

use peel::rar::archive::walk_archive;
use peel::rar::RarError;

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
fn baseline_walk_archive_rejects_first_volume_with_multi_volume_label() {
    // §2a baseline: today's walker rejects the first volume of a
    // multi-volume set at the main archive header because the
    // `MHD_VOLUME` flag is set. The error must mention "multi-volume"
    // so users + downstream tooling can detect the situation cleanly
    // (and so §2b's behaviour change shows up here as a deliberate
    // assertion update rather than a silent regression).
    let archive = read_volume("multi.part1.rar");
    let err = walk_archive(&archive).expect_err("first volume must reject under §2a");
    match err {
        RarError::UnsupportedFeature { feature } => {
            assert!(
                feature.contains("multi-volume"),
                "expected multi-volume label, got: {feature}"
            );
        }
        other => panic!("expected UnsupportedFeature, got {other:?}"),
    }
}
