//! Smoke validation for the rar bench fixture pipeline.
//!
//! Bakes the 8 MiB RAR5 + RAR3 STORED cells through the real
//! encoders, then verifies that (a) `unrar` can extract them and
//! (b) `peel`'s coordinator extracts them to identical contents.
//! Cheap to run on demand:
//!
//! ```sh
//! cargo test --release --test test_bench_rar_smoke -- --ignored --nocapture
//! ```

#![cfg(feature = "rar")]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use peel::coordinator::{run, CoordinatorConfig, OutputTarget, RunArgs};
use peel::decode::DecoderRegistry;
use peel::download::RetryConfig;
use peel::http::{Client, ClientConfig};

#[path = "support/mod.rs"]
mod support;

use support::mock_server::{MockResponse, MockServer};
use support::rar_bench_fixtures::{
    ensure_rar3_stored, ensure_rar5_stored, rar3_encoder_present, rar5_encoder_present, unrar_path,
};

static UNIQ: AtomicU64 = AtomicU64::new(0);

fn unique_dir(label: &str) -> PathBuf {
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let dir = std::env::temp_dir().join(format!("peel-rar-smoke-{label}-{pid}-{n}"));
    fs::create_dir_all(&dir).expect("mkdir unique_dir");
    dir
}

struct CleanupDir(PathBuf);
impl Drop for CleanupDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn random_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed ^ 0x9E37_79B9_7F4A_7C15_u64;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

fn build_entries(total_bytes: usize) -> Vec<(String, Vec<u8>)> {
    const FILES: usize = 8;
    let per = total_bytes / FILES;
    (0..FILES)
        .map(|i| {
            (
                format!("data/file_{i:02}.bin"),
                random_bytes(0xBEEF + i as u64, per),
            )
        })
        .collect()
}

fn coord_config() -> CoordinatorConfig {
    CoordinatorConfig {
        chunk_size: 1 << 20,
        adaptive_chunk_size: true,
        workers: 4,
        retry: RetryConfig {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
        },
        punch_threshold: 1 << 20,
        checkpoint_min_bytes: 8 * 1024 * 1024,
        checkpoint_min_interval: Duration::from_secs(2),
        checkpoint_target_interval: Duration::from_millis(200),
        workdir: None,
        reader_poll_interval: Duration::from_millis(2),
        forced_format: None,
        force_format_from_magic: false,
        io_backend: peel::io_backend::IoBackendChoice::Blocking,
        expected_sha256: None,
        expected_sha256s: Vec::new(),
        mirror_urls: Vec::new(),
        max_bandwidth_bps: None,
        max_disk_buffer: None,
        no_extract: false,
        keep_archive: None,
        strict_format: false,
    }
}

fn build_client() -> Client {
    Client::with_config(ClientConfig {
        timeout: Duration::from_secs(30),
        ..ClientConfig::default()
    })
    .expect("client constructs")
}

fn run_peel(body: Vec<u8>, suffix: &str, dir: PathBuf) {
    let server = MockServer::start(move |_req, _id| MockResponse::ok(body.clone()));
    let args = RunArgs {
        url: format!("{}/{suffix}", server.base_url()),
        additional_urls: Vec::new(),
        output: OutputTarget::Dir(dir),
        config: coord_config(),
        client: build_client(),
        registry: DecoderRegistry::with_defaults(),
        progress: None,
        progress_state: None,
        kill_switch: None,
        io_backend: None,
    };
    run(args).expect("peel run");
}

fn assert_dir_matches(dir: &std::path::Path, entries: &[(String, Vec<u8>)]) {
    for (name, body) in entries {
        let path = dir.join(name);
        let actual = fs::read(&path).expect("read extracted file");
        assert_eq!(actual.len(), body.len(), "size mismatch on {name}");
        assert_eq!(actual, *body, "contents mismatch on {name}");
    }
}

#[test]
#[ignore = "rar bench smoke; opt-in via --ignored"]
fn rar5_8mib_round_trip() {
    if !rar5_encoder_present() {
        eprintln!("skip: native rar 7.22 not at ~/Downloads/rar/rar");
        return;
    }
    let entries = build_entries(8 * 1024 * 1024);
    let body = ensure_rar5_stored(&entries, 8 * 1024 * 1024);
    eprintln!("rar5 archive size: {} bytes", body.len());

    if let Some(unrar) = unrar_path() {
        let dir = unique_dir("rar5_unrar");
        let _g = CleanupDir(dir.clone());
        let archive = dir.join("bundle.rar");
        let out = dir.join("out");
        fs::create_dir_all(&out).expect("mkdir out");
        fs::write(&archive, &body).expect("write archive");
        let status = Command::new(&unrar)
            .arg("x")
            .arg("-inul")
            .arg("-y")
            .arg(&archive)
            .arg(format!("{}/", out.display()))
            .status()
            .expect("invoke unrar");
        assert!(status.success(), "unrar extraction failed");
        assert_dir_matches(&out, &entries);
    }

    let dir = unique_dir("rar5_peel");
    let _g = CleanupDir(dir.clone());
    run_peel(body, "bundle.rar", dir.clone());
    assert_dir_matches(&dir, &entries);
}

#[test]
#[ignore = "rar bench smoke; opt-in via --ignored"]
fn rar3_8mib_round_trip() {
    if !rar3_encoder_present() {
        eprintln!("skip: docker + rar 5.0.0 Linux tarball not available");
        return;
    }
    let entries = build_entries(8 * 1024 * 1024);
    let body = ensure_rar3_stored(&entries, 8 * 1024 * 1024);
    eprintln!("rar3 archive size: {} bytes", body.len());

    if let Some(unrar) = unrar_path() {
        let dir = unique_dir("rar3_unrar");
        let _g = CleanupDir(dir.clone());
        let archive = dir.join("bundle.rar");
        let out = dir.join("out");
        fs::create_dir_all(&out).expect("mkdir out");
        fs::write(&archive, &body).expect("write archive");
        let status = Command::new(&unrar)
            .arg("x")
            .arg("-inul")
            .arg("-y")
            .arg(&archive)
            .arg(format!("{}/", out.display()))
            .status()
            .expect("invoke unrar");
        assert!(status.success(), "unrar extraction failed");
        assert_dir_matches(&out, &entries);
    }

    let dir = unique_dir("rar3_peel");
    let _g = CleanupDir(dir.clone());
    run_peel(body, "bundle.rar", dir.clone());
    assert_dir_matches(&dir, &entries);
}
