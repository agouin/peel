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
#![cfg(unix)]

#[path = "support/mod.rs"]
mod support;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use peel::bitmap::ChunkBitmap;
use peel::download::{RarPipeline, RarPipelineConfig, RarResumeState, SparseFile};
use peel::punch::NoopPuncher;
use peel::rar::archive::{walk_archive, walk_archive_multivolume};
use peel::rar::format::arc_flags;
use peel::rar::RarError;
use peel::sink::RarSink;
use peel::types::{ByteOffset, ChunkIndex};

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

/// Repo path to the compressed-multi-volume fixture directory.
fn compressed_fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("rar5_multivolume_compressed")
}

fn read_compressed_volume(name: &str) -> Vec<u8> {
    std::fs::read(compressed_fixture_dir().join(name))
        .unwrap_or_else(|e| panic!("read compressed fixture {name}: {e}"))
}

#[test]
fn walk_first_volume_alone_surfaces_volume_set_mismatch_after_2d() {
    // The committed multi.part1.rar's EOA carries `more_volumes`
    // — feeding only the first volume to the single-buffer
    // `walk_archive` entry point now surfaces VolumeSetMismatch,
    // not a SPLIT diagnostic (§2d's split-folding is lenient
    // enough that the leading SPLIT_AFTER header is accepted
    // and the missing continuation surfaces at EOA time).
    let archive = read_volume("multi.part1.rar");
    let err = walk_archive(&archive).expect_err("first-volume-only walk must surface a diagnostic");
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
fn walk_full_set_of_real_volumes_folds_spanning_entry() {
    // §2d: the committed three-volume real fixture has `big.bin`
    // spanning all three volumes. `walk_archive_multivolume`
    // returns a single FileEntry whose `extra_segments` records
    // the continuation slices in volumes 2 and 3, and whose
    // header.crc32 has been cleared (WinRAR writes per-segment
    // Pack-CRC32, not a cumulative whole-file checksum).
    let v1 = read_volume("multi.part1.rar");
    let v2 = read_volume("multi.part2.rar");
    let v3 = read_volume("multi.part3.rar");
    let summary = walk_archive_multivolume(&[&v1[..], &v2[..], &v3[..]])
        .expect("real fixture walks cleanly after §2d");
    assert_eq!(summary.entries.len(), 2);
    let small = &summary.entries[0];
    assert_eq!(small.header.name, "small.txt");
    assert!(small.extra_segments.is_empty());

    let big = &summary.entries[1];
    assert_eq!(big.header.name, "big.bin");
    assert_eq!(big.header.unpacked_size, 35_000);
    assert_eq!(big.extra_segments.len(), 2, "big.bin spans 3 volumes");
    assert!(
        big.header.crc32.is_none(),
        "spanning entry crc32 must be cleared because WinRAR writes per-segment Pack-CRC32"
    );
    let total_packed: u64 = big.packed_size
        + big
            .extra_segments
            .iter()
            .map(|s| s.packed_size)
            .sum::<u64>();
    assert_eq!(total_packed, 35_000, "STORED: total packed == unpacked");
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

// ─────────────────────────────────────────────────────────────────
// §2c: RarPipeline drives multi-volume input end-to-end (no SPLIT)
// ─────────────────────────────────────────────────────────────────

/// Make a temp directory that cleans itself up on drop.
fn tempdir(label: &str) -> CleanupDir {
    static UNIQ: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!("peel_rar_mv_{label}_{pid}_{nanos}_{n}"));
    std::fs::create_dir_all(&path).expect("create temp dir");
    CleanupDir(path)
}

struct CleanupDir(PathBuf);
impl Drop for CleanupDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
impl CleanupDir {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

/// Assemble a concatenated byte buffer of `volumes` and a parallel
/// `volume_starts` vector recording where each volume begins in
/// the global byte space.
fn concat_with_starts(volumes: &[Vec<u8>]) -> (Vec<u8>, Vec<u64>) {
    let mut bytes = Vec::new();
    let mut starts = Vec::with_capacity(volumes.len());
    for v in volumes {
        starts.push(bytes.len() as u64);
        bytes.extend_from_slice(v);
    }
    (bytes, starts)
}

#[test]
fn pipeline_extracts_three_non_spanning_volumes() {
    // §2c demo: drive the pipeline against a hand-built 3-volume
    // archive whose three entries each fit inside their volume
    // (no SPLIT). The pipeline walker must accept the per-volume
    // signature + main archive headers, jump across EOA-with-
    // more_volumes transitions, and extract each entry to disk.
    let payload_a = b"alpha payload\n".to_vec();
    let payload_b = vec![0x42u8; 4096];
    let payload_c = b"gamma\n".to_vec();
    let per_volume = vec![
        vec![RarEntrySpec::stored("a.txt", payload_a.clone())],
        vec![RarEntrySpec::stored("b.bin", payload_b.clone())],
        vec![RarEntrySpec::stored("nested/c.txt", payload_c.clone())],
    ];
    let volumes = build_rar5_multivolume(&per_volume);
    let (bytes, volume_starts) = concat_with_starts(&volumes);
    let total_size = bytes.len() as u64;

    // SparseFile holding the full multi-volume concatenation.
    let tmp = tempdir("pipeline_3vol");
    let sparse_path = tmp.path().join("archive.bin");
    let sparse = SparseFile::open_or_create(&sparse_path, total_size).expect("sparse");
    sparse
        .pwrite_at(ByteOffset::new(0), &bytes)
        .expect("seed sparse");

    // Bitmap with everything already complete: the pipeline only
    // reads; in this direct test we pre-fill rather than running a
    // scheduler.
    let chunk_size: u64 = 64 * 1024;
    let num_chunks = total_size.div_ceil(chunk_size) as u32;
    let bitmap = ChunkBitmap::new(num_chunks);
    bitmap.complete_range(ChunkIndex::new(0), ChunkIndex::new(num_chunks));

    let cursor = Arc::new(AtomicU64::new(0));
    let download_done = Arc::new(AtomicBool::new(true));
    let download_outcome = Arc::new(Mutex::new(None));

    let pipeline = RarPipeline {
        config: RarPipelineConfig {
            total_size,
            chunk_size,
            poll_interval: Duration::from_millis(1),
            initial_header_window: 64 * 1024,
            volume_starts: volume_starts.clone(),
        },
        sparse: &sparse,
        bitmap: &bitmap,
        cursor: &cursor,
        download_done: &download_done,
        download_outcome: &download_outcome,
        sparse_fd: sparse.as_fd(),
        progress_state: None,
        password_source: None,
        password_label: "test://multivolume",
    };

    let out_dir = tmp.path().join("out");
    std::fs::create_dir_all(&out_dir).expect("mkdir out");
    let mut sink = RarSink::new(&out_dir).expect("rar sink");
    let puncher = NoopPuncher::new();

    let stats = pipeline
        .run(&mut sink, &puncher, RarResumeState::default(), |_| Ok(()))
        .expect("multi-volume pipeline run");

    assert_eq!(stats.entries_extracted, 3);

    let got_a = std::fs::read(out_dir.join("a.txt")).expect("read a.txt");
    assert_eq!(got_a, payload_a);
    let got_b = std::fs::read(out_dir.join("b.bin")).expect("read b.bin");
    assert_eq!(got_b, payload_b);
    let got_c = std::fs::read(out_dir.join("nested/c.txt")).expect("read c.txt");
    assert_eq!(got_c, payload_c);
}

#[test]
fn pipeline_extracts_real_stored_spanning_entry() {
    // §2d STORED end-to-end: the committed three-volume fixture
    // ships a spanning `big.bin` entry (35 000 bytes of 'X'). The
    // pipeline walks the volume set, folds the three SPLIT
    // segments into one logical entry, and concatenates their
    // bytes into a byte-identical output file.
    let v1 = read_volume("multi.part1.rar");
    let v2 = read_volume("multi.part2.rar");
    let v3 = read_volume("multi.part3.rar");
    let volumes = vec![v1, v2, v3];
    let (bytes, volume_starts) = concat_with_starts(&volumes);
    let total_size = bytes.len() as u64;

    let tmp = tempdir("pipeline_split_stored");
    let sparse_path = tmp.path().join("archive.bin");
    let sparse = SparseFile::open_or_create(&sparse_path, total_size).expect("sparse");
    sparse
        .pwrite_at(ByteOffset::new(0), &bytes)
        .expect("seed sparse");

    let chunk_size: u64 = 64 * 1024;
    let num_chunks = total_size.div_ceil(chunk_size) as u32;
    let bitmap = ChunkBitmap::new(num_chunks);
    bitmap.complete_range(ChunkIndex::new(0), ChunkIndex::new(num_chunks));

    let cursor = Arc::new(AtomicU64::new(0));
    let download_done = Arc::new(AtomicBool::new(true));
    let download_outcome = Arc::new(Mutex::new(None));
    let pipeline = RarPipeline {
        config: RarPipelineConfig {
            total_size,
            chunk_size,
            poll_interval: Duration::from_millis(1),
            initial_header_window: 64 * 1024,
            volume_starts: volume_starts.clone(),
        },
        sparse: &sparse,
        bitmap: &bitmap,
        cursor: &cursor,
        download_done: &download_done,
        download_outcome: &download_outcome,
        sparse_fd: sparse.as_fd(),
        progress_state: None,
        password_source: None,
        password_label: "test://split-stored",
    };

    let out_dir = tmp.path().join("out");
    std::fs::create_dir_all(&out_dir).expect("mkdir out");
    let mut sink = RarSink::new(&out_dir).expect("rar sink");
    let puncher = NoopPuncher::new();

    let stats = pipeline
        .run(&mut sink, &puncher, RarResumeState::default(), |_| Ok(()))
        .expect("multi-volume STORED-SPLIT extraction succeeds");
    assert_eq!(stats.entries_extracted, 2);

    let got_small = std::fs::read(out_dir.join("small.txt")).expect("read small.txt");
    let expected_small: Vec<u8> = b"Hello from multivol\n".repeat(50);
    assert_eq!(got_small, expected_small);

    let got_big = std::fs::read(out_dir.join("big.bin")).expect("read big.bin");
    let expected_big = vec![b'X'; 35_000];
    assert_eq!(got_big, expected_big);
}

/// SHA-256 of the expected `comp_a.bin` plaintext (30 000 bytes
/// over `ABCDEFGHabcdefgh `). Captured from `unrar x multi.part1.rar`
/// when the fixture was generated; regenerating the fixture
/// requires updating this digest.
const COMP_A_SHA256: [u8; 32] = [
    0xc6, 0x44, 0xa7, 0x54, 0x4f, 0x64, 0xde, 0x26, 0x88, 0x5c, 0x88, 0x6e, 0x45, 0xd2, 0x01, 0xba,
    0x93, 0xca, 0x74, 0xc4, 0xad, 0x79, 0x19, 0x2d, 0x2e, 0x88, 0xe7, 0x84, 0x5c, 0x4b, 0x22, 0x76,
];

/// SHA-256 of the expected `comp_b.bin` plaintext (20 000 bytes
/// over `XYZxyz `). Captured from `unrar x` at fixture-creation time.
const COMP_B_SHA256: [u8; 32] = [
    0xde, 0x72, 0xfe, 0x84, 0x33, 0x74, 0x3b, 0x74, 0x1c, 0x12, 0x5e, 0x51, 0x92, 0xd8, 0x3b, 0xa0,
    0xe8, 0xf4, 0xcc, 0xfc, 0xa6, 0xd3, 0x29, 0x2c, 0x1e, 0xf3, 0x4b, 0x2f, 0x54, 0xad, 0x52, 0xc1,
];

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use peel::crypto::BlockHash;
    use peel::hash::sha256::Sha256;
    Sha256::digest(bytes).as_ref().try_into().expect("32 bytes")
}

#[test]
fn pipeline_extracts_real_compressed_spanning_entries() {
    // §2d compressed end-to-end: the four-volume fixture's
    // `comp_a.bin` spans volumes 1→2→3 and `comp_b.bin` spans
    // volumes 3→4 (so volume 3 carries a SPLIT_BEFORE entry
    // immediately followed by a SPLIT_AFTER entry — exercises
    // back-to-back SPLIT-folding in the walker). The pipeline
    // gathers each entry's compressed segments into one buffer,
    // hands it to the RAR5 decoder, and writes byte-identical
    // plaintext to the sink.
    let v1 = read_compressed_volume("multi.part1.rar");
    let v2 = read_compressed_volume("multi.part2.rar");
    let v3 = read_compressed_volume("multi.part3.rar");
    let v4 = read_compressed_volume("multi.part4.rar");
    let volumes = vec![v1, v2, v3, v4];
    let (bytes, volume_starts) = concat_with_starts(&volumes);
    let total_size = bytes.len() as u64;

    let tmp = tempdir("pipeline_split_compressed");
    let sparse_path = tmp.path().join("archive.bin");
    let sparse = SparseFile::open_or_create(&sparse_path, total_size).expect("sparse");
    sparse
        .pwrite_at(ByteOffset::new(0), &bytes)
        .expect("seed sparse");

    let chunk_size: u64 = 64 * 1024;
    let num_chunks = total_size.div_ceil(chunk_size) as u32;
    let bitmap = ChunkBitmap::new(num_chunks);
    bitmap.complete_range(ChunkIndex::new(0), ChunkIndex::new(num_chunks));

    let cursor = Arc::new(AtomicU64::new(0));
    let download_done = Arc::new(AtomicBool::new(true));
    let download_outcome = Arc::new(Mutex::new(None));
    let pipeline = RarPipeline {
        config: RarPipelineConfig {
            total_size,
            chunk_size,
            poll_interval: Duration::from_millis(1),
            initial_header_window: 64 * 1024,
            volume_starts: volume_starts.clone(),
        },
        sparse: &sparse,
        bitmap: &bitmap,
        cursor: &cursor,
        download_done: &download_done,
        download_outcome: &download_outcome,
        sparse_fd: sparse.as_fd(),
        progress_state: None,
        password_source: None,
        password_label: "test://split-compressed",
    };

    let out_dir = tmp.path().join("out");
    std::fs::create_dir_all(&out_dir).expect("mkdir out");
    let mut sink = RarSink::new(&out_dir).expect("rar sink");
    let puncher = NoopPuncher::new();

    let stats = pipeline
        .run(&mut sink, &puncher, RarResumeState::default(), |_| Ok(()))
        .expect("multi-volume compressed-SPLIT extraction succeeds");
    assert_eq!(stats.entries_extracted, 2);

    let got_a = std::fs::read(out_dir.join("comp_a.bin")).expect("read comp_a.bin");
    assert_eq!(got_a.len(), 30_000);
    assert_eq!(
        sha256(&got_a),
        COMP_A_SHA256,
        "comp_a.bin SHA-256 must match the pinned digest"
    );

    let got_b = std::fs::read(out_dir.join("comp_b.bin")).expect("read comp_b.bin");
    assert_eq!(got_b.len(), 20_000);
    assert_eq!(
        sha256(&got_b),
        COMP_B_SHA256,
        "comp_b.bin SHA-256 must match the pinned digest"
    );
}
