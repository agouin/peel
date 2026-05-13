//! Integration tests for the CLI's multi-volume HTTP auto-discovery
//! wiring (`docs/PLAN_multivolume_archives.md` §7 Phase 5).
//!
//! The discovery primitive itself is exercised by
//! [`tests/test_multivolume_discovery.rs`]; this file pins the
//! *integration* — that
//! [`peel::cli::Cli::into_run_args`] notices a seed URL whose
//! basename looks multi-volume, runs auto-discovery against the
//! origin, populates `additional_urls` with the resolved set, and
//! flips `CoordinatorConfig::multi_part_storage` so the run lands
//! per-volume `.peel.part.NNN` sidecars.

#![cfg(unix)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use clap::Parser;

#[path = "support/mod.rs"]
mod support;
use support::mock_server::{MockRequest, MockResponse, MockServer};

/// Mock origin that returns 200 for any path listed in `present`,
/// 404 otherwise. The body is empty because discovery only HEADs —
/// matches the pattern used in tests/test_multivolume_discovery.rs.
fn presence_server(present: &'static [&'static str]) -> MockServer {
    MockServer::start(move |req: &MockRequest, _: u64| {
        if present.contains(&req.path.as_str()) {
            MockResponse::Reply {
                status: 200,
                reason: "OK",
                headers: vec![
                    ("content-length".into(), "100".into()),
                    ("accept-ranges".into(), "bytes".into()),
                ],
                body: Vec::new(),
            }
        } else {
            MockResponse::Reply {
                status: 404,
                reason: "Not Found",
                headers: vec![("content-length".into(), "0".into())],
                body: Vec::new(),
            }
        }
    })
}

#[test]
fn cli_auto_discovers_rar5_multi_volume_seed() {
    let server = presence_server(&[
        "/dir/foo.part0001.rar",
        "/dir/foo.part0002.rar",
        "/dir/foo.part0003.rar",
    ]);
    let seed = format!("{}/dir/foo.part0001.rar", server.base_url());
    let cli = peel::cli::Cli::try_parse_from(["peel", &seed, "-o", "/tmp/out/"]).expect("parse");
    let args = cli.into_run_args().expect("into_run_args");

    // Auto-discovery populated the volume set, so the coordinator
    // can drive the multi-part code path.
    assert!(
        args.config.multi_part_storage,
        "multi-volume seed should flip multi_part_storage"
    );
    assert_eq!(args.additional_urls.len(), 2);
    assert!(args.url.ends_with("foo.part0001.rar"));
    assert!(args.additional_urls[0].ends_with("foo.part0002.rar"));
    assert!(args.additional_urls[1].ends_with("foo.part0003.rar"));
}

#[test]
fn cli_auto_discovers_7z_multi_volume_seed() {
    let server = presence_server(&["/a/bar.7z.001", "/a/bar.7z.002", "/a/bar.7z.003"]);
    let seed = format!("{}/a/bar.7z.001", server.base_url());
    let cli = peel::cli::Cli::try_parse_from(["peel", &seed, "-o", "/tmp/out/"]).expect("parse");
    let args = cli.into_run_args().expect("into_run_args");
    assert!(args.config.multi_part_storage);
    assert_eq!(args.additional_urls.len(), 2);
    assert!(args.url.ends_with("bar.7z.001"));
    assert!(args.additional_urls[0].ends_with("bar.7z.002"));
    assert!(args.additional_urls[1].ends_with("bar.7z.003"));
}

#[test]
fn cli_normalises_seed_to_volume_one_even_when_user_passes_middle_volume() {
    // The discovery walker always starts at volume 1, so a seed
    // pointing at volume 3 still resolves with volume 1 at the head
    // of the returned vec. The CLI integration must mirror that —
    // the coordinator expects `args.url` to be the seed of the
    // *resolved* set, not the user's literal input.
    let server = presence_server(&[
        "/v/q.part0001.rar",
        "/v/q.part0002.rar",
        "/v/q.part0003.rar",
        "/v/q.part0004.rar",
    ]);
    let seed = format!("{}/v/q.part0003.rar", server.base_url());
    let cli = peel::cli::Cli::try_parse_from(["peel", &seed, "-o", "/tmp/out/"]).expect("parse");
    let args = cli.into_run_args().expect("into_run_args");
    assert!(args.config.multi_part_storage);
    assert!(args.url.ends_with("q.part0001.rar"));
    assert_eq!(args.additional_urls.len(), 3);
}

#[test]
fn cli_single_volume_only_no_auto_discovery() {
    // Only one volume exists on origin. Discovery returns a
    // single-element vec; the CLI treats that as a single-URL run
    // and does not flip `multi_part_storage`. (The seed pattern was
    // recognised, but with no siblings the multi-part bookkeeping
    // would be useless overhead.)
    let server = presence_server(&["/solo.part0001.rar"]);
    let seed = format!("{}/solo.part0001.rar", server.base_url());
    let cli = peel::cli::Cli::try_parse_from(["peel", &seed, "-o", "/tmp/out/"]).expect("parse");
    let args = cli.into_run_args().expect("into_run_args");
    assert!(
        !args.config.multi_part_storage,
        "single-volume seed should not flip multi_part_storage"
    );
    assert!(args.additional_urls.is_empty());
}

#[test]
fn cli_url_without_multi_volume_pattern_skips_discovery() {
    // A URL whose basename doesn't match any multi-volume
    // convention is treated as plain single-URL. Crucially, no HEAD
    // probes fire — the test server here has no path table at all,
    // and any probe would 404, but `parse_volume_name` short-circuits
    // before we'd reach the origin.
    let server = presence_server(&[]);
    let seed = format!("{}/archive.tar.zst", server.base_url());
    let cli = peel::cli::Cli::try_parse_from(["peel", &seed, "-o", "/tmp/out/"]).expect("parse");
    let args = cli.into_run_args().expect("into_run_args");
    assert!(!args.config.multi_part_storage);
    assert!(args.additional_urls.is_empty());
}

#[test]
fn cli_explicit_additional_urls_disable_auto_discovery() {
    // When the user supplies multiple URLs explicitly, the CLI is
    // *not* in auto-discovery mode — the user is being explicit
    // about parts. Multi-part storage stays off; the legacy
    // single-`.peel.part` byte-concat layout drives the run. This
    // preserves multi-URL byte-concat semantics
    // (`docs/PLAN_multi_url_source.md`) byte-for-byte.
    let server = presence_server(&[
        // The CLI never probes here because additional_urls is
        // non-empty before the discovery branch runs.
        "/p0", "/p1",
    ]);
    let url0 = format!("{}/p0", server.base_url());
    let url1 = format!("{}/p1", server.base_url());
    let cli =
        peel::cli::Cli::try_parse_from(["peel", &url0, &url1, "-o", "/tmp/out/"]).expect("parse");
    let args = cli.into_run_args().expect("into_run_args");
    assert!(!args.config.multi_part_storage);
    assert_eq!(args.additional_urls.len(), 1);
}

#[test]
fn cli_missing_lower_volume_surfaces_volume_discovery_error() {
    // Origin has volumes 2 and 3 but volume 1 is absent. The user
    // seeded at volume 3. Discovery walks backward, hits 404 on
    // volume 1, and surfaces `MvError::MissingVolume`. The CLI must
    // surface that as `CliError::VolumeDiscovery` so the operator
    // knows the seed pattern *was* recognised — silently swallowing
    // it would leave the user with a confusing single-URL run that
    // 404s mid-fetch.
    let server = presence_server(&["/d/y.part0002.rar", "/d/y.part0003.rar"]);
    let seed = format!("{}/d/y.part0003.rar", server.base_url());
    let cli = peel::cli::Cli::try_parse_from(["peel", &seed, "-o", "/tmp/out/"]).expect("parse");
    match cli.into_run_args() {
        Ok(_) => panic!("expected VolumeDiscovery error, got Ok"),
        Err(peel::cli::CliError::VolumeDiscovery(_)) => {}
        Err(other) => panic!("expected VolumeDiscovery, got {other:?}"),
    }
}

/// Touch the AtomicU64 import so the unused-import lint stays clear
/// for future test additions that need it.
#[test]
fn module_imports_compile() {
    let _ = Arc::new(AtomicU64::new(0)).load(Ordering::Acquire);
}
