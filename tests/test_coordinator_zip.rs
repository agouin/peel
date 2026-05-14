#![cfg(feature = "zip")]
//! Integration tests for the zip second-pipeline driver in
//! [`peel::coordinator`].
//!
//! Sister file to `test_coordinator_sevenz.rs`. The headline
//! scenarios — the ones the user specifically called out as
//! needing coverage — are:
//!
//! 1. **`max_disk_buffer < entry size`.** Set the cap to a value
//!    smaller than any individual entry in the archive and confirm
//!    extraction still completes without deadlocking. The
//!    [`peel::download::zip_pipeline::BoundedSparseReader`] is
//!    supposed to advance `bytes_decoded_input` as it drains
//!    chunks, releasing dispatch in lock-step; if that wiring
//!    breaks, the workers throttle and the pipeline hangs.
//!
//! 2. **EOCD comment larger than `max_disk_buffer`.** A fat EOCD
//!    comment (the PKWARE APPNOTE allows up to 65 535 bytes) plus
//!    a small cap must still extract — the EOCD/CD fetches are
//!    exempt from the cap in [`peel::download::zip_pipeline`].

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
use support::zip_fixtures::{build_zip, build_zip_with_comment, ZipEntrySpec};

static UNIQ: AtomicU64 = AtomicU64::new(0);

fn unique_dir(label: &str) -> PathBuf {
    let pid = std::process::id();
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("peel_coord_zip_{label}_{pid}_{nanos}_{n}"));
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
        // timeout (rather than a multi-second hang) if the
        // wiring is wrong.
        reader_poll_interval: Duration::from_millis(1),
        forced_format: None,
        force_format_from_magic: false,
        io_backend: peel::io_backend::IoBackendChoice::Blocking,
        expected_sha256: None,
        expected_sha256s: Vec::new(),
        mirror_urls: Vec::new(),
        max_bandwidth_bps: None,
        max_disk_buffer,
        no_extract: false,
        keep_archive: None,
        strict_format: false,
        password_source: None,
        multi_part_storage: false,
    }
}

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
        url: format!("{}/dataset.zip", server.base_url()),
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

/// Headline scenario: a 4 MiB STORED entry extracted with a
/// 256 KiB `max_disk_buffer`. The cap is 16× smaller than the
/// single entry in the archive — if the bounded reader doesn't
/// publish `bytes_decoded_input` correctly, the scheduler
/// throttle starves the workers and this hangs.
#[test]
fn extracts_with_max_disk_buffer_smaller_than_any_entry() {
    let payload = (0..4u32 * 1024 * 1024).map(|i| i as u8).collect::<Vec<_>>();
    let body = build_zip(&[ZipEntrySpec::stored("data/big.bin", payload.clone())]);

    let server = MockServer::start(ok_handler(body));
    let work = unique_dir("max_buffer_lt_entry");
    let _g = CleanupDir(work.clone());

    let config = coord_config(64 * 1024, Some(256 * 1024));
    let args = make_args(&server, OutputTarget::Dir(work.clone()), config);
    let _stats = run(args).expect("extracts under tight cap");

    let extracted = read_dir_recursive(&work);
    let names: Vec<&str> = extracted.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, vec!["data/big.bin"]);
    assert_eq!(extracted[0].1, payload);
}

/// Headline scenario: many small entries with a tight cap.
/// Forces the bounded reader to drain dozens of entry
/// boundaries while staying within a small lookahead budget.
#[test]
fn extracts_many_entries_with_tight_cap() {
    let entries: Vec<ZipEntrySpec> = (0..16)
        .map(|i| {
            ZipEntrySpec::stored(
                format!("data/file_{i:02}.bin"),
                (0..256u32 * 1024)
                    .map(|n| (n + i) as u8)
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    let body = build_zip(&entries);

    let server = MockServer::start(ok_handler(body));
    let work = unique_dir("tight_cap_many_entries");
    let _g = CleanupDir(work.clone());

    let config = coord_config(32 * 1024, Some(128 * 1024));
    let args = make_args(&server, OutputTarget::Dir(work.clone()), config);
    let _stats = run(args).expect("extracts");

    let extracted = read_dir_recursive(&work);
    assert_eq!(extracted.len(), entries.len());
    for ((got_name, got_body), spec) in extracted.iter().zip(entries.iter()) {
        assert_eq!(got_name, &spec.name);
        assert_eq!(got_body, &spec.uncompressed);
    }
}

/// Headline scenario: EOCD comment larger than the cap. The
/// zip pipeline reads the trailing `MAX_EOCD_TAIL_BYTES` of the
/// archive in one bulk wait to find the EOCD signature; if
/// that wait went through the cap, a fat-comment archive
/// (PKWARE allows up to 65 535 bytes of comment) would
/// deadlock under a tight cap. The `bytes_decoded_input =
/// total_size` exemption around the EOCD/CD fetches keeps the
/// cap from firing in that window.
#[test]
fn extracts_with_eocd_comment_larger_than_max_disk_buffer() {
    let payload = b"file body".to_vec();
    let comment = vec![b'#'; 32 * 1024]; // 32 KiB comment
    let body = build_zip_with_comment(
        &[ZipEntrySpec::stored("greeting.txt", payload.clone())],
        &comment,
    );

    let server = MockServer::start(ok_handler(body));
    let work = unique_dir("eocd_comment_gt_cap");
    let _g = CleanupDir(work.clone());

    // Cap (8 KiB) is 4× smaller than the comment alone.
    let config = coord_config(2 * 1024, Some(8 * 1024));
    let args = make_args(&server, OutputTarget::Dir(work.clone()), config);
    let _stats = run(args).expect("extracts under tight cap with fat EOCD comment");

    let extracted = read_dir_recursive(&work);
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].0, "greeting.txt");
    assert_eq!(extracted[0].1, payload);
}

/// Resume idempotence under a tight cap.
#[test]
fn resume_after_clean_run_under_tight_cap_is_idempotent() {
    let payload = (0..2u32 * 1024 * 1024).map(|i| i as u8).collect::<Vec<_>>();
    let body = build_zip(&[ZipEntrySpec::stored("file.bin", payload.clone())]);

    let server = MockServer::start(ok_handler(body));
    let work = unique_dir("zip_resume_tight_cap");
    let _g = CleanupDir(work.clone());

    let config = coord_config(64 * 1024, Some(256 * 1024));
    let args = make_args(&server, OutputTarget::Dir(work.clone()), config);
    run(args).expect("first run");
    let after_first = fs::read(work.join("file.bin")).expect("read first");
    assert_eq!(after_first, payload);

    let config2 = coord_config(64 * 1024, Some(256 * 1024));
    let args2 = make_args(&server, OutputTarget::Dir(work.clone()), config2);
    run(args2).expect("second run");
    let after_second = fs::read(work.join("file.bin")).expect("read second");
    assert_eq!(after_second, payload);
}
