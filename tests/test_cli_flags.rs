//! End-to-end CLI tests for flags whose *effect* only becomes
//! observable at the binary boundary — exit code, on-disk
//! side-effects, error message shape. Flag parsing and dispatch
//! routing are covered exhaustively in [`src/cli.rs`]'s
//! `#[cfg(test)]` module; these tests pin the runtime behaviours
//! the in-process API doesn't see (e.g. argv → exit-code mapping,
//! whether `--destructive` actually deletes the source archive on
//! clean completion).
//!
//! Deliberately narrow: one assertion per flag. The combinatorial
//! flag-permutation matrix lives in the CLI parser tests, where it
//! belongs; binary-level coverage focuses on the *outcomes* the
//! parser tests cannot see.

#![cfg(unix)]

#[path = "support/mod.rs"]
mod support;

use std::io::Write;

use support::mock_server::{MockRequest, MockResponse, MockServer};
use support::peel_cli::{assert_tree_exactly, peel_cmd};
use support::tar_fixtures::build_simple_archive;
use support::work::{unique_dir, CleanupDir};

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

/// Hex-encode bytes; used to format `--sha256` arguments.
fn hex_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(ALPHABET[(b >> 4) as usize] as char);
        out.push(ALPHABET[(b & 0x0F) as usize] as char);
    }
    out
}

fn sha256_of(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_slice());
    out
}

/// MockServer that always returns `body` on GET and supports HEAD +
/// Range so peel takes its production fast path.
fn body_server(body: Vec<u8>) -> MockServer {
    let body = std::sync::Arc::new(body);
    MockServer::start(move |req: &MockRequest, _| {
        if req.method.eq_ignore_ascii_case("HEAD") {
            return MockResponse::Reply {
                status: 200,
                reason: "OK",
                headers: vec![
                    ("content-length".into(), body.len().to_string()),
                    ("accept-ranges".into(), "bytes".into()),
                ],
                body: Vec::new(),
            };
        }
        let range = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("range"))
            .and_then(|(_, v)| parse_range_header(v));
        if let Some((a, b)) = range {
            let end = (b as usize + 1).min(body.len());
            return MockResponse::Reply {
                status: 206,
                reason: "Partial Content",
                headers: vec![(
                    "content-range".into(),
                    format!("bytes {a}-{}/{}", end - 1, body.len()),
                )],
                body: body[a as usize..end].to_vec(),
            };
        }
        MockResponse::ok((*body).clone()).with_header("accept-ranges", "bytes")
    })
}

fn parse_range_header(value: &str) -> Option<(u64, u64)> {
    let after = value.strip_prefix("bytes=")?;
    let (a, b) = after.split_once('-')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

#[test]
fn sha256_match_succeeds() {
    let entries: Vec<(&str, &[u8])> = vec![("one.txt", b"sha matches\n")];
    let tar = build_simple_archive(&entries);
    let body = encode_gzip(&tar);
    let digest = sha256_of(&body);
    let server = body_server(body);
    let url = format!("{}/blob.tar.gz", server.base_url());
    let work = unique_dir("flags_sha_ok");
    let _g = CleanupDir(work.clone());

    let out = peel_cmd()
        .arg(&url)
        .out_dir(&work)
        .arg("--sha256")
        .arg(hex_lower(&digest))
        .run();
    assert_eq!(
        out.code,
        0,
        "matched sha256 should succeed; stderr=\n{}",
        out.stderr_str()
    );
    assert_tree_exactly(&work, &entries);
}

#[test]
fn sha256_mismatch_exits_nonzero_and_not_4() {
    // Mismatched sha is a generic integrity failure, not a password
    // problem; must surface as exit 1, never 4 (which would confuse
    // scripts that re-prompt on 4 per internal/ENCRYPTION.md).
    let entries: Vec<(&str, &[u8])> = vec![("one.txt", b"sha should mismatch\n")];
    let tar = build_simple_archive(&entries);
    let body = encode_gzip(&tar);
    let server = body_server(body);
    let url = format!("{}/blob.tar.gz", server.base_url());
    let work = unique_dir("flags_sha_bad");
    let _g = CleanupDir(work.clone());

    let out = peel_cmd()
        .arg(&url)
        .out_dir(&work)
        .arg("--sha256")
        .arg(hex_lower(&[0u8; 32])) // definitely wrong
        .run();
    assert_ne!(out.code, 0, "sha mismatch must fail");
    assert_ne!(
        out.code,
        4,
        "sha mismatch is not a password issue; stderr=\n{}",
        out.stderr_str()
    );
}

#[test]
fn no_extract_downloads_archive_without_extracting_tree() {
    // `--no-extract` writes the source bytes verbatim to `-o <path>`
    // (or `<output_dir>/<urlbasename>` when given a directory) and
    // skips the decoder entirely.
    let entries: Vec<(&str, &[u8])> = vec![("inside.txt", b"never extracted\n")];
    let tar = build_simple_archive(&entries);
    let body = encode_gzip(&tar);
    let server = body_server(body.clone());
    let url = format!("{}/blob.tar.gz", server.base_url());
    let work = unique_dir("flags_no_extract");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("blob.tar.gz");

    let out = peel_cmd()
        .arg(&url)
        .arg("-o")
        .arg(&out_path)
        .arg("--no-extract")
        .run();
    assert_eq!(
        out.code,
        0,
        "--no-extract should succeed; stderr=\n{}",
        out.stderr_str()
    );
    let downloaded = std::fs::read(&out_path).expect("read downloaded archive");
    assert_eq!(downloaded, body, "downloaded bytes must match source");
    // No tree should have been extracted — the archive file is the
    // only artifact under `work`.
    assert_tree_exactly(&work, &[("blob.tar.gz", &body)]);
}

#[test]
fn keep_archive_preserves_source_alongside_extracted_tree() {
    // `-k` (bare) preserves the archive at `<parent-of-output>/<url-basename>`
    // per [src/cli.rs] `resolve_keep_archive`. The test nests the
    // extraction target so the parent-of-output is a controlled
    // scratch dir; the kept archive lands as a sibling of that
    // target, both under `work`.
    let entries: Vec<(&str, &[u8])> = vec![("kept.txt", b"both should survive\n")];
    let tar = build_simple_archive(&entries);
    let body = encode_gzip(&tar);
    let server = body_server(body.clone());
    let url = format!("{}/keepme.tar.gz", server.base_url());
    let work = unique_dir("flags_keep");
    let _g = CleanupDir(work.clone());
    let extract_dir = work.join("extract");

    let out = peel_cmd().arg(&url).out_dir(&extract_dir).arg("-k").run();
    assert_eq!(
        out.code,
        0,
        "-k should succeed; stderr=\n{}",
        out.stderr_str()
    );
    let archive_path = work.join("keepme.tar.gz");
    let preserved = std::fs::read(&archive_path).expect("read kept archive");
    assert_eq!(preserved, body, "kept archive must match the source bytes");
    // Tree under `work` should contain both the preserved archive
    // and the extracted entries (each prefixed by `extract/`).
    let prefixed: Vec<(String, &[u8])> = entries
        .iter()
        .map(|(n, b)| (format!("extract/{n}"), *b))
        .collect();
    let mut expected: Vec<(&str, &[u8])> = prefixed.iter().map(|(n, b)| (n.as_str(), *b)).collect();
    expected.push(("keepme.tar.gz", body.as_slice()));
    assert_tree_exactly(&work, &expected);
}

#[test]
fn destructive_on_local_path_deletes_source_on_success() {
    // Local mode is non-destructive by default; `-d` opts in to the
    // HTTP-style disk-pressure contract — source is hole-punched as
    // the decoder advances and unlinked on clean completion (see
    // [src/coordinator/local.rs] §destructive cleanup).
    let entries: Vec<(&str, &[u8])> = vec![("inside.txt", b"will outlive its archive\n")];
    let tar = build_simple_archive(&entries);
    let body = encode_gzip(&tar);

    let scratch = unique_dir("flags_destructive");
    let _g = CleanupDir(scratch.clone());
    let archive_path = scratch.join("doomed.tar.gz");
    std::fs::write(&archive_path, &body).expect("write archive");
    let out_dir = scratch.join("out");
    std::fs::create_dir_all(&out_dir).expect("mkdir out");

    let out = peel_cmd()
        .arg(&archive_path)
        .out_dir(&out_dir)
        .arg("-d")
        .run();
    assert_eq!(
        out.code,
        0,
        "destructive local extract should succeed; stderr=\n{}",
        out.stderr_str()
    );
    assert!(
        !archive_path.exists(),
        "destructive mode must delete the source archive on clean completion"
    );
    assert_tree_exactly(&out_dir, &entries);
}

#[test]
fn force_format_from_magic_overrides_misleading_suffix() {
    // The URL says `.zip` but the bytes are gzip-compressed. Magic
    // detection registers gzip with its default Stream shape (see
    // [src/decode.rs] `register_format("gzip", FormatShape::Stream,
    // ...)`), so the resolved output is a single file — not a tree.
    // `--no-auto-discover` is required because a `.zip` seed would
    // otherwise trigger spanned-ZIP probing against the mock origin
    // (which returns 200 for every path).
    let payload: Vec<u8> = (0..4 * 1024u32).map(|i| (i * 13) as u8).collect();
    let body = encode_gzip(&payload);
    let server = body_server(body);
    let url = format!("{}/mislabelled.zip", server.base_url());
    let work = unique_dir("flags_force_magic");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("decoded.bin");

    let out = peel_cmd()
        .arg(&url)
        .arg("-o")
        .arg(&out_path)
        .arg("--force-format-from-magic")
        .arg("--no-auto-discover")
        .run();
    assert_eq!(
        out.code,
        0,
        "--force-format-from-magic should let a mislabelled gzip stream extract; \
         stderr=\n{}",
        out.stderr_str()
    );
    let decoded = std::fs::read(&out_path).expect("read decoded stream");
    assert_eq!(decoded, payload);
}

#[test]
fn forced_format_overrides_suffix_detection() {
    // `--format <name>` is the explicit-decoder companion to
    // `--force-format-from-magic`. URL has no usable suffix
    // (`opaque`); `--format gzip` tells peel exactly what to run.
    // `gzip` is a stream-shape format, so the output target is a
    // file path — not a directory (peel rejects the shape mismatch
    // at parse time).
    let payload: Vec<u8> = (0..8 * 1024u32).map(|i| (i * 11) as u8).collect();
    let body = encode_gzip(&payload);
    let server = body_server(body);
    let url = format!("{}/opaque", server.base_url());
    let work = unique_dir("flags_forced_format");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("decoded.bin");

    let out = peel_cmd()
        .arg(&url)
        .arg("-o")
        .arg(&out_path)
        .arg("--format")
        .arg("gzip")
        .run();
    assert_eq!(
        out.code,
        0,
        "--format gzip on suffix-less URL should succeed; stderr=\n{}",
        out.stderr_str()
    );
    let decoded = std::fs::read(&out_path).expect("read decoded stream");
    assert_eq!(decoded, payload);
}

#[test]
fn unknown_flag_produces_clap_error_and_nonzero_exit() {
    // Sanity gate: clap's parse-time errors come back through the
    // binary as a non-zero exit with a structured message on
    // stderr. Catches a regression where a stray `#[arg]` change
    // silently downgrades to accepting unknown flags.
    let work = unique_dir("flags_unknown");
    let _g = CleanupDir(work.clone());

    let out = peel_cmd()
        .arg("https://example.invalid/x.tar.gz")
        .out_dir(&work)
        .arg("--nonsense-flag-that-does-not-exist")
        .run();
    assert_ne!(out.code, 0, "unknown flag should fail at parse time");
    let stderr = out.stderr_str();
    assert!(
        stderr.contains("unexpected argument") || stderr.contains("error:"),
        "expected a clap error mention; stderr=\n{stderr}"
    );
}
