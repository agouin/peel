//! Integration tests for legacy (RAR3 / RAR4) archive extraction
//! through the second-pipeline coordinator.
//!
//! Sister to `test_coordinator_rar.rs` but exercises the legacy
//! signature path landed in `docs/PLAN_rar3.md` §A2b. Round-one
//! ships STORED-method (`m=0`) extraction end-to-end; compressed
//! methods surface a precise `UnsupportedFeature` diagnostic and
//! the decoder generations land in §B / §C.

#![cfg(unix)]
#![cfg(feature = "rar")]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use peel::coordinator::{run, CoordinatorConfig, CoordinatorError, OutputTarget, RunArgs};
use peel::decode::DecoderRegistry;
use peel::download::RetryConfig;
use peel::http::{Client, ClientConfig};

mod support;

use support::mock_server::{MockResponse, MockServer};
use support::rar_fixtures::{
    build_legacy_archive, build_legacy_block, build_legacy_endarc_header, build_legacy_main_header,
    LegacyEntrySpec,
};

static UNIQ: AtomicU64 = AtomicU64::new(0);

fn unique_dir(label: &str) -> PathBuf {
    let pid = std::process::id();
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("peel_coord_rar3_{label}_{pid}_{nanos}_{n}"));
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

fn coord_config(chunk_size: u64) -> CoordinatorConfig {
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
        reader_poll_interval: Duration::from_millis(1),
        forced_format: None,
        force_format_from_magic: false,
        io_backend: peel::io_backend::IoBackendChoice::Blocking,
        expected_sha256: None,
        expected_sha256s: Vec::new(),
        mirror_urls: Vec::new(),
        max_bandwidth_bps: None,
        max_disk_buffer: None,
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
        url: format!("{}/dataset.rar", server.base_url()),
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

fn three_file_legacy_stored() -> (Vec<u8>, Vec<LegacyEntrySpec>) {
    let entries = vec![
        LegacyEntrySpec::stored("alpha.txt", b"hello, legacy RAR".to_vec()),
        LegacyEntrySpec::stored(
            "nested/beta.bin",
            (0..2048u32).map(|i| (i & 0xFF) as u8).collect::<Vec<u8>>(),
        ),
        LegacyEntrySpec::stored("gamma.dat", vec![0xA5u8; 4096]),
    ];
    let body = build_legacy_archive(0, &entries);
    (body, entries)
}

#[test]
fn round_trip_three_file_legacy_stored_archive() {
    let (body, entries) = three_file_legacy_stored();
    let server = MockServer::start(ok_handler(body));
    let work = unique_dir("round_trip");
    let _g = CleanupDir(work.clone());

    let args = make_args(
        &server,
        OutputTarget::Dir(work.clone()),
        coord_config(64 * 1024),
    );
    let _stats = run(args).expect("extracts cleanly");

    let extracted = read_dir_recursive(&work);
    assert_eq!(extracted.len(), entries.len(), "found: {extracted:?}");
    let mut sorted_specs = entries.clone();
    sorted_specs.sort_by(|a, b| a.name.cmp(&b.name));
    for (got, spec) in extracted.iter().zip(sorted_specs.iter()) {
        assert_eq!(got.0, spec.name);
        assert_eq!(got.1, spec.uncompressed);
    }
}

#[test]
fn round_trip_solid_legacy_stored_archive() {
    // Solid mode is a flag-only difference for STORED entries —
    // their data areas are still independent byte ranges. The flag
    // matters once compressed entries land (§B/§C) and share a
    // decompression context. Until then, MHD_SOLID should not
    // change extraction output.
    let entries = vec![
        LegacyEntrySpec::stored("a.bin", b"AAAAAAAA".to_vec()),
        LegacyEntrySpec::stored("b.bin", b"BBBBBBBB".to_vec()),
    ];
    let body = build_legacy_archive(0x0008 /* MHD_SOLID */, &entries);
    let server = MockServer::start(ok_handler(body));
    let work = unique_dir("solid");
    let _g = CleanupDir(work.clone());

    let args = make_args(
        &server,
        OutputTarget::Dir(work.clone()),
        coord_config(64 * 1024),
    );
    run(args).expect("extracts cleanly");

    let extracted = read_dir_recursive(&work);
    assert_eq!(extracted.len(), 2);
    for (got, spec) in extracted.iter().zip(entries.iter()) {
        assert_eq!(got.0, spec.name);
        assert_eq!(got.1, spec.uncompressed);
    }
}

#[test]
fn rejects_compressed_legacy_archive_with_specific_diagnostic() {
    // Synthesize a legacy archive whose single FILE_HEAD reports
    // method 0x33 (m=3, the "normal" RAR3 compression) instead of
    // STORED. The walker must reject at parse time with a
    // diagnostic that names the version + method byte; until §B/§C
    // land, no archive with `m≥1` should slip through to a generic
    // failure.
    let mut buf = Vec::new();
    buf.extend_from_slice(&peel::rar::LEGACY_SIGNATURE_MAGIC);
    buf.extend_from_slice(&build_legacy_main_header(0));

    let payload = b"compressed-payload-placeholder".to_vec();
    let pack_size: u32 = payload.len() as u32;
    let mut body = Vec::new();
    body.extend_from_slice(&(payload.len() as u32).to_le_bytes()); // unp_size_low
    body.push(3); // host_os = Unix
    body.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // file_crc placeholder
    body.extend_from_slice(&[0; 4]); // dos_mtime
    body.push(36); // unp_ver = 3.6 / 4.x
    body.push(0x33); // method = m=3 (compressed)
    body.extend_from_slice(&(8u16).to_le_bytes()); // name_size
    body.extend_from_slice(&[0; 4]); // attr
    body.extend_from_slice(b"squish.x"); // name
    let header = build_legacy_block(0x74, 0, &body, Some(pack_size));
    buf.extend_from_slice(&header);
    buf.extend_from_slice(&payload);
    buf.extend_from_slice(&build_legacy_endarc_header());

    let server = MockServer::start(ok_handler(buf));
    let work = unique_dir("compressed");
    let _g = CleanupDir(work.clone());

    let args = make_args(&server, OutputTarget::Dir(work), coord_config(64 * 1024));
    let err = run(args).expect_err("compressed legacy must be rejected");
    // The outer CoordinatorError variant carries the
    // RarPipelineError as `#[source]`; thiserror prints only the
    // top-level "RAR extraction failed" string for `Display`. Walk
    // the chain to verify the diagnostic at its origin.
    let mut chain_msgs: Vec<String> = Vec::new();
    let mut cur: Option<&dyn std::error::Error> = Some(&err);
    while let Some(e) = cur {
        chain_msgs.push(e.to_string());
        cur = e.source();
    }
    let combined = chain_msgs.join(" / ");
    assert!(
        combined.contains("legacy RAR compression method"),
        "diagnostic should name the legacy compression method, got chain: {combined}"
    );
    // Sanity-check the error type so test breakage points at the
    // pipeline rather than a coordinator framing change.
    assert!(matches!(err, CoordinatorError::Rar(_)), "got {err:?}");
}
