//! End-to-end CLI tests for multi-volume archives — the `.part<N>.rar`
//! auto-discovery wiring described in `internal/PLAN_multivolume_archives.md`.
//!
//! The existing [`tests/test_cli_multivolume.rs`] only covers the
//! parser surface (`Cli::try_parse_from(...).into_run_args()`) and
//! [`tests/test_multivolume_discovery.rs`] only exercises HEAD
//! probing in isolation. Neither proves the binary actually
//! *extracts* a multi-volume archive end-to-end. These tests close
//! that gap: real WinRAR-produced volumes from
//! `tests/fixtures/rar5_multivolume/` are served from a mock origin
//! and the extracted tree is byte-compared against the expected
//! payloads documented in that directory's `README.md`.
//!
//! Gated behind the `rar` Cargo feature (per `internal/PLAN_rar.md`
//! §0.5); without it the runtime decoder refuses RAR5 archives and
//! these tests would not be meaningful.

#![cfg(feature = "rar")]
#![cfg(unix)]

#[path = "support/mod.rs"]
mod support;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use support::mock_server::{MockRequest, MockResponse, MockServer};
use support::peel_cli::{assert_tree_exactly, peel_cmd};
use support::work::{unique_dir, CleanupDir};

/// Read every committed `multi.partN.rar` volume into memory, keyed
/// by request path. The fixture set produces the exact two-file tree
/// the README enumerates; the bodies live in `tests/fixtures/`.
fn load_volumes() -> HashMap<String, Vec<u8>> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("rar5_multivolume");
    let mut by_path = HashMap::new();
    for name in ["multi.part1.rar", "multi.part2.rar", "multi.part3.rar"] {
        let body =
            std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("read fixture {name}: {e}"));
        by_path.insert(format!("/{name}"), body);
    }
    by_path
}

/// Expected extracted tree per `tests/fixtures/rar5_multivolume/README.md`:
/// `small.txt` (1000 B, repeating banner) and `big.bin` (35 000 B, all `X`).
fn expected_tree() -> Vec<(String, Vec<u8>)> {
    let small: Vec<u8> = b"Hello from multivol\n"
        .iter()
        .copied()
        .cycle()
        .take(20 * 50)
        .collect();
    debug_assert_eq!(small.len(), 1000);
    let big: Vec<u8> = std::iter::repeat_n(b'X', 35_000).collect();
    vec![("small.txt".into(), small), ("big.bin".into(), big)]
}

/// Build a `MockServer` whose handler honours HEAD (returns headers
/// only), GET (full body) and GET-with-Range (206 Partial Content)
/// for every path in `volumes`. Anything else returns 404.
///
/// The handler intentionally announces `Accept-Ranges: bytes` and a
/// truthful `Content-Length` on HEAD so peel's discovery + scheduler
/// follow the production fast path (parallel ranged GETs) rather
/// than a fallback that would mask wiring regressions.
fn volume_server(volumes: HashMap<String, Vec<u8>>) -> MockServer {
    let volumes = Arc::new(volumes);
    MockServer::start(move |req: &MockRequest, _| {
        let Some(body) = volumes.get(&req.path).cloned() else {
            return MockResponse::Reply {
                status: 404,
                reason: "Not Found",
                headers: vec![("content-length".into(), "0".into())],
                body: Vec::new(),
            };
        };
        let total = body.len();
        let common = vec![
            ("accept-ranges".to_string(), "bytes".to_string()),
            (
                "content-type".to_string(),
                "application/octet-stream".into(),
            ),
        ];
        if req.method.eq_ignore_ascii_case("HEAD") {
            let mut headers = common.clone();
            headers.push(("content-length".into(), total.to_string()));
            return MockResponse::Reply {
                status: 200,
                reason: "OK",
                headers,
                body: Vec::new(),
            };
        }
        let range = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("range"))
            .and_then(|(_, v)| parse_range_header(v));
        if let Some((a, b)) = range {
            let end = (b as usize + 1).min(total);
            let slice = body[a as usize..end].to_vec();
            let mut headers = common;
            headers.push((
                "content-range".to_string(),
                format!("bytes {a}-{}/{}", end - 1, total),
            ));
            return MockResponse::Reply {
                status: 206,
                reason: "Partial Content",
                headers,
                body: slice,
            };
        }
        MockResponse::ok(body).with_header("accept-ranges", "bytes")
    })
}

fn parse_range_header(value: &str) -> Option<(u64, u64)> {
    let after = value.strip_prefix("bytes=")?;
    let (a, b) = after.split_once('-')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

fn expected_tree_refs(expected: &[(String, Vec<u8>)]) -> Vec<(&str, &[u8])> {
    expected
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect()
}

#[test]
fn auto_discovers_and_extracts_rar5_multivolume_seeded_at_part1() {
    let server = volume_server(load_volumes());
    let url = format!("{}/multi.part1.rar", server.base_url());
    let work = unique_dir("mp_seed1");
    let _g = CleanupDir(work.clone());

    let out = peel_cmd().arg(&url).out_dir(&work).run();
    assert_eq!(
        out.code,
        0,
        "peel exited {}; stderr=\n{}",
        out.code,
        out.stderr_str()
    );
    let expected = expected_tree();
    assert_tree_exactly(&work, &expected_tree_refs(&expected));
}

#[test]
fn auto_discovers_when_user_seeds_middle_volume() {
    // Discovery is supposed to normalise the seed back to part1 and
    // walk forward — proves [`peel::cli::Cli::into_run_args`]'s
    // `url`-rewrite step survives the trip through the binary
    // (the parse-level test in tests/test_cli_multivolume.rs asserts
    // the rewrite happens; this test asserts the rewritten URL set
    // actually drives a successful extraction).
    let server = volume_server(load_volumes());
    let url = format!("{}/multi.part2.rar", server.base_url());
    let work = unique_dir("mp_seed_mid");
    let _g = CleanupDir(work.clone());

    let out = peel_cmd().arg(&url).out_dir(&work).run();
    assert_eq!(
        out.code,
        0,
        "peel exited {}; stderr=\n{}",
        out.code,
        out.stderr_str()
    );
    let expected = expected_tree();
    assert_tree_exactly(&work, &expected_tree_refs(&expected));
}

#[test]
fn missing_middle_volume_surfaces_clear_error() {
    // Origin is missing volume 2; discovery's contiguity check must
    // refuse the set rather than silently extracting an incomplete
    // archive.
    let mut volumes = load_volumes();
    volumes.remove("/multi.part2.rar");
    let server = volume_server(volumes);
    let url = format!("{}/multi.part1.rar", server.base_url());
    let work = unique_dir("mp_missing");
    let _g = CleanupDir(work.clone());

    let out = peel_cmd().arg(&url).out_dir(&work).run();
    assert_ne!(
        out.code,
        0,
        "missing volume should fail; stderr=\n{}",
        out.stderr_str()
    );
    let stderr = out.stderr_str();
    assert!(
        stderr.contains("volume") || stderr.contains("Volume"),
        "expected an error mentioning the volume set; stderr=\n{stderr}"
    );
}

#[test]
fn no_auto_discover_disables_volume_walk_end_to_end() {
    // Parse-level coverage in tests/test_cli_multivolume.rs already
    // checks `--no-auto-discover` skips the HEAD probes. This test
    // confirms the runtime consequence: feeding part1 alone to the
    // RAR pipeline surfaces `VolumeSetMismatch` (the EOA marker's
    // `more_volumes=true` flag without a continuation supplied),
    // exit code 1.
    let server = volume_server(load_volumes());
    let url = format!("{}/multi.part1.rar", server.base_url());
    let work = unique_dir("mp_no_auto");
    let _g = CleanupDir(work.clone());

    let out = peel_cmd()
        .arg(&url)
        .out_dir(&work)
        .arg("--no-auto-discover")
        .run();

    assert_ne!(
        out.code,
        0,
        "--no-auto-discover on a multi-volume seed should fail; stderr=\n{}",
        out.stderr_str()
    );
}
