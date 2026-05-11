//! Integration tests for `peel::coordinator::local::run`
//! (`docs/PLAN_local_file_extract.md` §2).
//!
//! These tests exercise the local-file path end-to-end without an
//! HTTP server: build a compressed archive on disk, hand its path
//! to the coordinator, and check the produced output (and the
//! source-file post-state for destructive vs. keep-archive runs).

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::atomic::AtomicU64;

use peel::coordinator::local::{run as local_run, LocalRunArgs};
use peel::coordinator::{CoordinatorError, OutputTarget};

mod support;
use support::tar_fixtures;

static UNIQ: AtomicU64 = AtomicU64::new(0);

fn unique_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "peel_local_{}_{}_{}_{}",
        label,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
        UNIQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
    ));
    std::fs::create_dir_all(&dir).expect("create unique dir");
    dir
}

/// Build a small `.tar.zst` archive with two file members and
/// return the path to the written file.
fn build_tar_zst(dir: &std::path::Path, files: &[(&str, &[u8])]) -> PathBuf {
    let tar = tar_fixtures::build_simple_archive(files);
    let zst = zstd::encode_all(tar.as_slice(), 1).expect("encode zstd");
    let path = dir.join("archive.tar.zst");
    std::fs::write(&path, &zst).expect("write archive");
    path
}

/// Build a raw `.zst` file (no tar wrapping) over `payload`.
fn build_raw_zst(dir: &std::path::Path, payload: &[u8]) -> PathBuf {
    let zst = zstd::encode_all(payload, 1).expect("encode zstd");
    let path = dir.join("payload.zst");
    std::fs::write(&path, &zst).expect("write payload");
    path
}

#[test]
fn local_tar_zst_extracts_destructive_default_deletes_source() {
    let dir = unique_dir("destructive_default");
    let source = build_tar_zst(
        &dir,
        &[
            ("hello.txt", b"hello world\n"),
            ("dir/inside.txt", b"nested\n"),
        ],
    );
    let out = dir.join("out");

    let mut args = LocalRunArgs::new(source.clone(), OutputTarget::Dir(out.clone()));
    args.keep_archive = false;
    local_run(args).expect("local run");

    // Output tree present.
    let hello = std::fs::read(out.join("hello.txt")).expect("read hello");
    assert_eq!(hello, b"hello world\n");
    let nested = std::fs::read(out.join("dir/inside.txt")).expect("read nested");
    assert_eq!(nested, b"nested\n");

    // Destructive default: source deleted (or, if the FS didn't
    // support punching, preserved — the implementation surfaces a
    // tracing::warn! in that case but the test runs on macOS APFS
    // or Linux tmpfs both of which do support punching).
    assert!(
        !source.exists(),
        "destructive default should delete the source archive"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn local_tar_zst_with_keep_archive_preserves_source() {
    let dir = unique_dir("keep_archive");
    let source = build_tar_zst(&dir, &[("a.txt", b"alpha\n"), ("b.txt", b"beta\n")]);
    let archive_size_before = std::fs::metadata(&source).expect("stat").len();
    let out = dir.join("out");

    let mut args = LocalRunArgs::new(source.clone(), OutputTarget::Dir(out.clone()));
    args.keep_archive = true;
    local_run(args).expect("local run");

    let a = std::fs::read(out.join("a.txt")).expect("read a");
    assert_eq!(a, b"alpha\n");
    // Source preserved at full size.
    let archive_size_after = std::fs::metadata(&source).expect("stat after").len();
    assert_eq!(
        archive_size_after, archive_size_before,
        "-k must preserve the source file's size"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn local_raw_zst_extracts_to_file_target() {
    let dir = unique_dir("raw_zst");
    let payload = b"the quick brown fox jumps over the lazy dog";
    let source = build_raw_zst(&dir, payload);
    let out = dir.join("decoded.bin");

    let mut args = LocalRunArgs::new(source.clone(), OutputTarget::File(out.clone()));
    args.keep_archive = true; // don't litter
    local_run(args).expect("local run");

    let decoded = std::fs::read(&out).expect("read decoded");
    assert_eq!(decoded, payload);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn local_unknown_format_errors_cleanly() {
    let dir = unique_dir("unknown_format");
    let source = dir.join("payload.bin");
    std::fs::write(&source, b"\x00\x01\x02\x03\x04\x05not-a-known-archive").expect("write source");
    let out = dir.join("decoded.bin");

    let args = LocalRunArgs::new(source, OutputTarget::File(out));
    let err = local_run(args).expect_err("must error");
    assert!(matches!(err, CoordinatorError::NoDecoder { .. }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn local_format_shape_mismatch_errors_before_extract() {
    // `.tar.zst` is Tree shape but the user supplied a File-shaped
    // output target. The coordinator catches this before any sink
    // open.
    let dir = unique_dir("shape_mismatch");
    let source = build_tar_zst(&dir, &[("a.txt", b"x")]);
    let out = dir.join("file_target.bin");

    let args = LocalRunArgs::new(source, OutputTarget::File(out));
    let err = local_run(args).expect_err("must error");
    assert!(matches!(err, CoordinatorError::OutputShapeMismatch { .. }));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn local_forced_format_overrides_filename_suffix() {
    // The source's filename has no archive suffix; `--format zstd`
    // tells the coordinator to decode as raw zstd. Stream-shape
    // output, no magic detection needed.
    let dir = unique_dir("forced_format");
    let payload = b"forced-format decoded payload";
    let zst = zstd::encode_all(&payload[..], 1).expect("encode");
    let source = dir.join("opaque");
    std::fs::write(&source, &zst).expect("write source");
    let out = dir.join("decoded.bin");

    let mut args = LocalRunArgs::new(source, OutputTarget::File(out.clone()));
    args.forced_format = Some("zstd".to_string());
    args.keep_archive = true;
    local_run(args).expect("local run");

    let decoded = std::fs::read(&out).expect("read decoded");
    assert_eq!(decoded, payload);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn local_run_pumps_progress_state_counters() {
    // §4 (PLAN_local_file_extract.md): the shared ProgressState is
    // fed by the local-mode source-read pump. After a clean run,
    // `bytes_downloaded` and `bytes_decoded_input` should both
    // equal the source file size (every byte was read by the
    // decoder), and `bytes_extracted` should be > 0.
    use std::sync::Arc;
    let dir = unique_dir("progress");
    let source = build_tar_zst(&dir, &[("a.txt", b"alpha-payload-1234567890")]);
    let archive_size = std::fs::metadata(&source).expect("stat").len();
    let out = dir.join("out");

    let state = peel::progress::ProgressState::new();
    let mut args = LocalRunArgs::new(source, OutputTarget::Dir(out));
    args.keep_archive = true; // so the run doesn't unlink the source mid-test
    args.progress_state = Some(Arc::clone(&state));
    local_run(args).expect("local run");

    let snap = state.snapshot();
    assert_eq!(
        snap.bytes_downloaded, archive_size,
        "ProgressReader must pump every source byte into add_downloaded",
    );
    assert_eq!(
        snap.bytes_decoded_input, archive_size,
        "ProgressReader must pump bytes_decoded_input too",
    );
    assert!(
        snap.bytes_extracted > 0,
        "extractor must have written some output bytes",
    );
    // Local mode does not register workers; the renderer just
    // displays "workers 0/0".
    assert_eq!(snap.active_workers, 0);
    assert_eq!(snap.total_workers, 0);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn local_zip_rejected_with_clear_error() {
    // ZIP / RAR / 7z are random-access formats; local-file mode
    // currently surfaces a `NoDecoder` error pointing the user at
    // the HTTP path until the per-format local extractor lands.
    let dir = unique_dir("zip_rejected");
    let zip = support::zip_fixtures::build_zip(&[support::zip_fixtures::ZipEntrySpec::stored(
        "hello.txt",
        b"hi\n",
    )]);
    let source = dir.join("archive.zip");
    std::fs::write(&source, &zip).expect("write zip");
    let out = dir.join("out");

    let args = LocalRunArgs::new(source, OutputTarget::Dir(out));
    let err = local_run(args).expect_err("must error");
    match err {
        CoordinatorError::NoDecoder { filename } => {
            assert!(
                filename.contains("zip"),
                "error message should name the offending format, got: {filename:?}",
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn local_run_produces_consistent_run_stats() {
    let dir = unique_dir("run_stats");
    let source = build_tar_zst(&dir, &[("x.txt", b"x-payload\n")]);
    let total_size = std::fs::metadata(&source).expect("stat").len();
    let out = dir.join("out");

    let mut args = LocalRunArgs::new(source, OutputTarget::Dir(out));
    args.keep_archive = true;
    let stats = local_run(args).expect("local run");

    assert_eq!(stats.total_size, total_size);
    assert!(!stats.resumed);
    assert_eq!(stats.resume_decoder_position, None);
    assert!(!stats.resume_used_decoder_state);
    // Extraction stats should reflect at least one frame and one
    // member's worth of output.
    assert!(stats.extraction.bytes_out > 0);
    assert!(stats.extraction.bytes_in > 0);

    let _ = std::fs::remove_dir_all(&dir);
}
