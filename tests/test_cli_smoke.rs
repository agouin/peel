//! CLI subprocess smoke tests — the floor that proves the
//! [`tests/support/peel_cli`] harness actually launches the binary,
//! drives it through a full extract, and exits with the documented
//! code. Every other `tests/test_cli_*.rs` file leans on this same
//! harness, so a regression here surfaces before the bigger
//! flag/encryption/multipart suites have a chance to mask it.
//!
//! Scope deliberately narrow: one tree-shape extract, one stream-shape
//! extract, and one local-source path. The rest of the binary's
//! surface lives in the per-bucket files.

#![cfg(unix)]

#[path = "support/mod.rs"]
mod support;

use std::io::Write;

use support::mock_server::{MockResponse, MockServer};
use support::peel_cli::{assert_tree_exactly, peel_cmd};
use support::tar_fixtures::build_simple_archive;
use support::work::{unique_dir, CleanupDir};

/// Encode `payload` as a single-member gzip blob at the default
/// compression level — the on-wire shape `tar -z` produces and which
/// peel's hand-rolled `decode::deflate_native::gzip` backend decodes
/// in production. Mirrors [`tests/test_bench_streaming.rs`]
/// `encode_gzip`; copied here rather than promoted to support to
/// avoid pulling the bench module's dependency surface into the
/// regular test set.
fn encode_gzip(payload: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    let mut encoder = GzEncoder::new(
        Vec::with_capacity(payload.len() / 2 + 256),
        Compression::default(),
    );
    encoder.write_all(payload).expect("encode gzip");
    encoder.finish().expect("finish gzip")
}

#[test]
fn http_tar_gz_to_dir_extracts_tree() {
    let entries: Vec<(&str, &[u8])> = vec![
        ("alpha.txt", b"hello, peel cli\n"),
        ("nested/beta.bin", &[0xA5u8; 1024]),
    ];
    let tar = build_simple_archive(&entries);
    let body = encode_gzip(&tar);
    let server = MockServer::start(move |_, _| MockResponse::ok(body.clone()));
    let url = format!("{}/bundle.tar.gz", server.base_url());

    let work = unique_dir("smoke_dir");
    let _g = CleanupDir(work.clone());

    let out = peel_cmd().arg(&url).out_dir(&work).run();
    assert_eq!(
        out.code,
        0,
        "peel exited {}; stderr=\n{}",
        out.code,
        out.stderr_str()
    );
    assert_tree_exactly(&work, &entries);
}

#[test]
fn http_gz_stream_to_file_writes_decoded_bytes() {
    // Stream-shape: a raw `.gz` (no tar wrapper). peel writes the
    // decoded plaintext to `-o <path>` verbatim. Catches the
    // gz-without-tar dispatch and the file-shape output target.
    let payload: Vec<u8> = (0..16 * 1024u32).map(|i| (i * 7) as u8).collect();
    let body = encode_gzip(&payload);
    let server = MockServer::start(move |_, _| MockResponse::ok(body.clone()));
    let url = format!("{}/blob.gz", server.base_url());

    let work = unique_dir("smoke_file");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("blob.bin");

    let out = peel_cmd().arg(&url).out_file(&out_path).run();
    assert_eq!(
        out.code,
        0,
        "peel exited {}; stderr=\n{}",
        out.code,
        out.stderr_str()
    );
    let extracted = std::fs::read(&out_path).expect("read extracted blob");
    assert_eq!(extracted, payload);
}

#[test]
fn local_source_non_destructive_default_preserves_archive() {
    // Local mode is non-destructive by default; running `peel <path>
    // -o out/` must leave the source archive bytes intact on disk.
    let entries: Vec<(&str, &[u8])> = vec![("only.txt", b"local mode preserves me\n")];
    let tar = build_simple_archive(&entries);
    let body = encode_gzip(&tar);

    let scratch = unique_dir("smoke_local");
    let _g = CleanupDir(scratch.clone());
    let archive = scratch.join("bundle.tar.gz");
    std::fs::write(&archive, &body).expect("write archive");
    let out_dir = scratch.join("out");
    std::fs::create_dir_all(&out_dir).expect("mkdir out");

    let out = peel_cmd().arg(&archive).out_dir(&out_dir).run();
    assert_eq!(
        out.code,
        0,
        "peel exited {}; stderr=\n{}",
        out.code,
        out.stderr_str()
    );
    let after = std::fs::read(&archive).expect("source archive still readable");
    assert_eq!(
        after, body,
        "non-destructive local mode must leave source archive intact"
    );
    assert_tree_exactly(&out_dir, &entries);
}
