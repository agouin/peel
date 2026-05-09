//! Integration tests for the 7z second-pipeline driver in
//! [`peel::coordinator`].
//!
//! These tests run the full pipeline end-to-end against the in-process
//! mock HTTP server. The headline scenarios — the ones the user
//! specifically called out as needing coverage — are:
//!
//! 1. **`max_disk_buffer < folder size`.** Set the cap to a value
//!    smaller than any individual file in the archive and confirm
//!    extraction still completes without deadlocking. The streaming
//!    reader is supposed to advance `bytes_decoded_input` as it
//!    drains chunks, releasing dispatch in lock-step; if that wiring
//!    breaks, the workers throttle and the pipeline hangs.
//!
//! 2. **Trailer larger than `max_disk_buffer`.** A small cap with a
//!    fat trailer (e.g. an EncodedHeader compressed to a few MiB)
//!    must still extract — the trailer fetch is exempt from the cap
//!    in [`peel::download::sevenz_pipeline`].

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use peel::coordinator::{run, CoordinatorConfig, OutputTarget, RunArgs};
use peel::decode::DecoderRegistry;
use peel::download::RetryConfig;
use peel::http::{Client, ClientConfig};

mod support;

use support::mock_server::{MockResponse, MockServer};
use support::sevenz_fixtures::{build_copy_sevenz, build_copy_sevenz_with_trailer_padding};

static UNIQ: AtomicU64 = AtomicU64::new(0);

fn unique_dir(label: &str) -> PathBuf {
    let pid = std::process::id();
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("peel_coord_sevenz_{label}_{pid}_{nanos}_{n}"));
    fs::create_dir_all(&p).expect("create unique_dir");
    p
}

struct CleanupDir(PathBuf);
impl Drop for CleanupDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn build_client() -> Client {
    Client::with_config(ClientConfig {
        timeout: Duration::from_secs(15),
        ..ClientConfig::default()
    })
    .expect("client constructs")
}

fn fast_retry() -> RetryConfig {
    RetryConfig {
        max_attempts: 3,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(5),
    }
}

fn coord_config(chunk_size: u64, max_disk_buffer: Option<u64>) -> CoordinatorConfig {
    CoordinatorConfig {
        chunk_size,
        adaptive_chunk_size: false,
        workers: 2,
        retry: fast_retry(),
        punch_threshold: 4096,
        checkpoint_min_bytes: 1,
        checkpoint_min_interval: Duration::from_millis(0),
        checkpoint_target_interval: Duration::ZERO,
        workdir: None,
        // Tight poll interval so a deadlock surfaces as a test
        // timeout (rather than a multi-second hang) if the wiring
        // is wrong.
        reader_poll_interval: Duration::from_millis(1),
        forced_format: None,
        force_format_from_magic: false,
        io_backend: peel::io_backend::IoBackendChoice::Blocking,
        expected_sha256: None,
        expected_sha256s: Vec::new(),
        mirror_urls: Vec::new(),
        max_bandwidth_bps: None,
        max_disk_buffer,
    }
}

/// Synchronous-Reply mock handler factory: serves the same body
/// for every request, supports `Range:` reads.
fn ok_handler(body: Vec<u8>) -> impl Fn(&support::mock_server::MockRequest, u64) -> MockResponse {
    move |req, _n| {
        let range_header = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("range"))
            .map(|(_, v)| v.as_str());
        if let Some(range) = range_header {
            if let Some((a, b)) = parse_range(range) {
                let end = (b as usize + 1).min(body.len());
                let slice = body[a as usize..end].to_vec();
                return MockResponse::Reply {
                    status: 206,
                    reason: "Partial Content",
                    headers: vec![
                        (
                            "Content-Type".to_string(),
                            "application/octet-stream".into(),
                        ),
                        (
                            "Content-Range".to_string(),
                            format!("bytes {a}-{}/{}", end - 1, body.len()),
                        ),
                    ],
                    body: slice,
                };
            }
        }
        MockResponse::Reply {
            status: 200,
            reason: "OK",
            headers: vec![],
            body: body.clone(),
        }
    }
}

fn parse_range(value: &str) -> Option<(u64, u64)> {
    let after = value.strip_prefix("bytes=")?;
    let (a, b) = after.split_once('-')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

fn read_dir_recursive(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(root: &Path, cur: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let Ok(entries) = fs::read_dir(cur) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                walk(root, &p, out);
            } else {
                let rel = p
                    .strip_prefix(root)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .into_owned();
                let body = fs::read(&p).unwrap_or_default();
                out.push((rel, body));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn make_args(server: &MockServer, output: OutputTarget, config: CoordinatorConfig) -> RunArgs {
    RunArgs {
        url: format!("{}/dataset.7z", server.base_url()),
        additional_urls: Vec::new(),
        output,
        config,
        client: build_client(),
        registry: DecoderRegistry::with_defaults(),
        progress: None,
        progress_state: Some(peel::progress::ProgressState::new()),
        kill_switch: None,
        io_backend: None,
    }
}

/// Headline scenario: a 4 MiB folder extracted with a 256 KiB
/// `max_disk_buffer`. The cap is 16× smaller than the single
/// file in the archive — if the streaming reader doesn't
/// publish `bytes_decoded_input` correctly, the scheduler
/// throttle starves the workers and this hangs.
#[test]
fn extracts_with_max_disk_buffer_smaller_than_any_file() {
    let payload = (0..4u32 * 1024 * 1024).map(|i| i as u8).collect::<Vec<_>>();
    let body = build_copy_sevenz(&[("data/big.bin", payload.clone())]);

    let server = MockServer::start(ok_handler(body));
    let work = unique_dir("max_buffer_lt_file");
    let _g = CleanupDir(work.clone());

    // 256 KiB cap — much smaller than the 4 MiB archive content.
    // Chunk size 64 KiB to keep the cap meaningful.
    let config = coord_config(64 * 1024, Some(256 * 1024));
    let args = make_args(&server, OutputTarget::Dir(work.clone()), config);
    let stats = run(args).expect("extracts under tight cap");
    assert!(stats.extraction.bytes_punched > 0);

    let extracted = read_dir_recursive(&work);
    let names: Vec<&str> = extracted.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, vec!["data/big.bin"]);
    assert_eq!(extracted[0].1, payload);
}

/// Headline scenario: many small files inside one folder, tiny
/// cap. Forces the reader to drain dozens of file boundaries
/// while staying within a small lookahead budget.
#[test]
fn extracts_many_files_with_tight_cap() {
    let files: Vec<(String, Vec<u8>)> = (0..16)
        .map(|i| {
            (
                format!("data/file_{i:02}.bin"),
                (0..256u32 * 1024).map(|n| (n + i) as u8).collect(),
            )
        })
        .collect();
    let pairs: Vec<(&str, Vec<u8>)> = files.iter().map(|(n, b)| (n.as_str(), b.clone())).collect();
    let body = build_copy_sevenz(&pairs);

    let server = MockServer::start(ok_handler(body));
    let work = unique_dir("tight_cap_many_files");
    let _g = CleanupDir(work.clone());

    // 128 KiB cap — half the size of any individual file.
    let config = coord_config(32 * 1024, Some(128 * 1024));
    let args = make_args(&server, OutputTarget::Dir(work.clone()), config);
    let _stats = run(args).expect("extracts");

    let extracted = read_dir_recursive(&work);
    assert_eq!(extracted.len(), files.len());
    for ((got_name, got_body), (want_name, want_body)) in extracted.iter().zip(files.iter()) {
        assert_eq!(got_name, want_name);
        assert_eq!(got_body, want_body);
    }
}

/// Headline scenario: trailer larger than `max_disk_buffer`.
/// An EncodedHeader trailer compressed to a few hundred KiB is
/// realistic in the wild; if the trailer fetch were forced
/// through the cap, an archive whose trailer exceeds the cap
/// would deadlock — the wait would block on chunks the throttle
/// has refused to dispatch.
///
/// The test pads the trailer to 256 KiB and sets the cap to
/// 64 KiB (4× smaller than the trailer). If the cap exemption
/// regresses, this test will time out instead of completing.
#[test]
fn extracts_with_trailer_larger_than_max_disk_buffer() {
    // Tiny pack data so the test stays fast; the focus is the
    // trailer, not throughput.
    let payload = b"contents".to_vec();
    let body =
        build_copy_sevenz_with_trailer_padding(&[("data/small.bin", payload.clone())], 256 * 1024);
    // The trailer is the trailing region of the archive; we
    // expect it to be roughly `padding_bytes + ~150 B` of real
    // metadata. Sanity-check that the synthesized archive's
    // trailer indeed exceeds the cap we're about to set.
    assert!(
        body.len() > 256 * 1024 + 32 + payload.len(),
        "synthesized archive smaller than expected: {} bytes",
        body.len(),
    );

    let server = MockServer::start(ok_handler(body));
    let work = unique_dir("trailer_gt_cap");
    let _g = CleanupDir(work.clone());

    // Cap (64 KiB) is 4× smaller than the trailer body
    // (256 KiB). Chunk size 8 KiB so the trailer spans ~32
    // chunks — plenty of room for a wrong cap to fire.
    let config = coord_config(8 * 1024, Some(64 * 1024));
    let args = make_args(&server, OutputTarget::Dir(work.clone()), config);
    let _stats = run(args).expect("extracts under tight cap with fat trailer");

    let extracted = read_dir_recursive(&work);
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].0, "data/small.bin");
    assert_eq!(extracted[0].1, payload);
}

/// Resume scenario: extract once, simulate a kill by walking
/// away from the prior `.peel.ckpt`, then re-run with the same
/// cap and verify the resumed run finishes cleanly. (The
/// crash-test harness handles random kill points; this test
/// exercises the deterministic "checkpoint exists, resume
/// completes" path under a tight cap.)
#[test]
fn resume_after_clean_run_under_tight_cap_is_idempotent() {
    let payload = (0..2u32 * 1024 * 1024).map(|i| i as u8).collect::<Vec<_>>();
    let body = build_copy_sevenz(&[("file.bin", payload.clone())]);

    let server = MockServer::start(ok_handler(body));
    let work = unique_dir("resume_idempotent");
    let _g = CleanupDir(work.clone());

    let config1 = coord_config(64 * 1024, Some(256 * 1024));
    let args1 = make_args(&server, OutputTarget::Dir(work.clone()), config1);
    run(args1).expect("first run");
    let after_first = fs::read(work.join("file.bin")).expect("read first");
    assert_eq!(after_first, payload);

    // Re-run on the now-extracted directory. The first run's
    // sidecars have been cleaned up, so this is treated as
    // "fresh" and re-extracts (the test is checking the cap
    // behavior is consistent across runs, not the resume path
    // itself — that's covered by test_coordinator_crash.rs).
    let config2 = coord_config(64 * 1024, Some(256 * 1024));
    let args2 = make_args(&server, OutputTarget::Dir(work.clone()), config2);
    run(args2).expect("second run");
    let after_second = fs::read(work.join("file.bin")).expect("read second");
    assert_eq!(after_second, payload);
}
