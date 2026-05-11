//! Integration tests for the RAR5 second-pipeline driver in
//! [`peel::coordinator`].
//!
//! Sister file to `test_coordinator_zip.rs` and
//! `test_coordinator_sevenz.rs`. Round-one §3 ships STORED-method
//! (`compression method = 0`) extraction; the §4 hand-rolled
//! decoder will land integration tests against the standard RAR5
//! algorithm in a follow-on file.
//!
//! Headline scenarios:
//!
//! 1. **3-file STORED archive round-trips byte-identical.**
//! 2. **Resume after a clean run is idempotent** (the second run
//!    sees the on-disk extraction and exits cleanly).
//! 3. **Crash-test mid-entry resume produces byte-identical
//!    output.** The first run aborts via the kill-switch after the
//!    first checkpoint; the second run picks the in-flight entry
//!    up at the saved offset (truncate + re-read prefix to seed
//!    the running BLAKE2sp + CRC-32) and finishes the rest.

#![cfg(unix)]
#![cfg(feature = "rar")]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use peel::coordinator::{
    run, CoordinatorConfig, CoordinatorError, OutputTarget, ProgressEvent, RunArgs,
};
use peel::decode::DecoderRegistry;
use peel::download::RetryConfig;
use peel::http::{Client, ClientConfig};

mod support;

use support::mock_server::{MockResponse, MockServer};
use support::rar_fixtures::{build_rar5, RarEntrySpec};

static UNIQ: AtomicU64 = AtomicU64::new(0);

fn unique_dir(label: &str) -> PathBuf {
    let pid = std::process::id();
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("peel_coord_rar_{label}_{pid}_{nanos}_{n}"));
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
        // Tight floor so the crash-test's kill-after-first-checkpoint
        // path exercises actual mid-entry resume.
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
        no_extract: false,
        keep_archive: None,
        strict_format: false,
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

fn make_args(
    server: &MockServer,
    output: OutputTarget,
    config: CoordinatorConfig,
    kill_switch: Option<Arc<AtomicBool>>,
    progress: Option<peel::coordinator::ProgressFn>,
) -> RunArgs {
    RunArgs {
        url: format!("{}/dataset.rar", server.base_url()),
        additional_urls: Vec::new(),
        output,
        config,
        client: build_client(),
        registry: DecoderRegistry::with_defaults(),
        progress,
        progress_state: Some(peel::progress::ProgressState::new()),
        kill_switch,
        io_backend: None,
    }
}

fn three_file_stored_archive() -> (Vec<u8>, Vec<RarEntrySpec>) {
    let entries = vec![
        RarEntrySpec::stored("alpha.txt", b"hello, RAR".to_vec()),
        RarEntrySpec::stored(
            "nested/beta.bin",
            (0..1024u32).map(|i| (i & 0xFF) as u8).collect::<Vec<u8>>(),
        ),
        RarEntrySpec::stored("gamma.dat", vec![0xA5u8; 4096]),
    ];
    let body = build_rar5(0, None, &entries);
    (body, entries)
}

#[test]
fn round_trip_three_file_stored_archive() {
    let (body, entries) = three_file_stored_archive();
    let server = MockServer::start(ok_handler(body));
    let work = unique_dir("round_trip");
    let _g = CleanupDir(work.clone());

    let args = make_args(
        &server,
        OutputTarget::Dir(work.clone()),
        coord_config(64 * 1024),
        None,
        None,
    );
    let _stats = run(args).expect("extracts cleanly");

    let extracted = read_dir_recursive(&work);
    assert_eq!(extracted.len(), entries.len(), "found: {extracted:?}");
    // `read_dir_recursive` sorts by relative path; sort the
    // specs the same way before zipping so the archive's
    // emit-order doesn't have to match the filesystem walk order.
    let mut sorted_specs = entries.clone();
    sorted_specs.sort_by(|a, b| a.name.cmp(&b.name));
    for (got, spec) in extracted.iter().zip(sorted_specs.iter()) {
        assert_eq!(got.0, spec.name);
        assert_eq!(got.1, spec.uncompressed);
    }
}

#[test]
fn resume_after_clean_run_is_idempotent() {
    let (body, entries) = three_file_stored_archive();
    let server = MockServer::start(ok_handler(body));
    let work = unique_dir("resume_clean");
    let _g = CleanupDir(work.clone());

    let args = make_args(
        &server,
        OutputTarget::Dir(work.clone()),
        coord_config(64 * 1024),
        None,
        None,
    );
    run(args).expect("first run");
    for spec in &entries {
        let on_disk = fs::read(work.join(&spec.name)).expect("first read");
        assert_eq!(on_disk, spec.uncompressed);
    }

    let args2 = make_args(
        &server,
        OutputTarget::Dir(work.clone()),
        coord_config(64 * 1024),
        None,
        None,
    );
    run(args2).expect("second run");
    for spec in &entries {
        let on_disk = fs::read(work.join(&spec.name)).expect("second read");
        assert_eq!(on_disk, spec.uncompressed);
    }
}

/// Mid-entry crash-test: kill the run after the first checkpoint
/// fires (which the tight `checkpoint_min_*` config triggers
/// mid-first-entry), then resume in a fresh process. The on-disk
/// extraction must be byte-identical to the clean run.
#[test]
fn crash_resume_mid_entry_produces_identical_output() {
    // Use a 4 MiB single-entry archive so the first checkpoint
    // reliably fires before the entry finishes.
    let payload: Vec<u8> = (0..4u32 * 1024 * 1024).map(|i| (i * 31) as u8).collect();
    let entries = vec![RarEntrySpec::stored("big.bin", payload.clone())];
    let body = build_rar5(0, None, &entries);
    let server = MockServer::start(ok_handler(body));

    let work = unique_dir("crash_resume");
    let _g = CleanupDir(work.clone());

    // First run: kill after the first CheckpointWritten event.
    let kill = Arc::new(AtomicBool::new(false));
    let kill_for_cb = Arc::clone(&kill);
    let counter = Arc::new(AtomicU64::new(0));
    let counter_for_cb = Arc::clone(&counter);
    let progress: peel::coordinator::ProgressFn = Box::new(move |event| {
        if let ProgressEvent::CheckpointWritten { .. } = event {
            let n = counter_for_cb.fetch_add(1, Ordering::Relaxed) + 1;
            if n >= 1 {
                kill_for_cb.store(true, Ordering::Release);
            }
        }
    });
    let args = make_args(
        &server,
        OutputTarget::Dir(work.clone()),
        coord_config(64 * 1024),
        Some(Arc::clone(&kill)),
        Some(progress),
    );
    match run(args) {
        Err(CoordinatorError::Aborted { .. }) => {}
        other => panic!("expected Aborted, got {other:?}"),
    }

    // Second run: no kill-switch; resume should pick up where the
    // first run left off and finish.
    let args2 = make_args(
        &server,
        OutputTarget::Dir(work.clone()),
        coord_config(64 * 1024),
        None,
        None,
    );
    run(args2).expect("resume run");
    let on_disk = fs::read(work.join("big.bin")).expect("read big.bin");
    assert_eq!(on_disk.len(), payload.len());
    assert_eq!(
        on_disk, payload,
        "resumed extraction must be byte-identical"
    );
}

/// §F1 mid-compressed-entry crash-resume: drive the curated
/// `multi_block_p27.rar` fixture (2.8 KB compressed, 67.5 MB
/// decoded — Goldilocks-sized for the tight checkpoint cadence)
/// through the coordinator. Kill after the first
/// `CheckpointWritten` event, then resume in a fresh run; the
/// on-disk extraction must be byte-identical to a clean run.
///
/// Unblocked by the multi-block decode fix that landed in
/// `src/decode/rar_native/{stream,lzss}.rs` per
/// `docs/PLAN_rar5_multi_block_decode.md`'s "Resolution" note.
/// Until that fix, the decoder underran the bitstream by 2 bits
/// at each block seam; the entry never reached EOF and this
/// test couldn't possibly pass.
#[test]
fn crash_resume_mid_compressed_entry_produces_identical_output() {
    // 67.5 MB decoded — sized large enough that
    // `checkpoint_min_bytes = 1` lands a mid-entry
    // `CheckpointWritten` well before EOF, and small enough that
    // the test finishes in a few seconds on a developer laptop.
    let body: Vec<u8> =
        fs::read("tests/fixtures/rar5/multi_block_p27.rar").expect("fixture present");
    let expected_len: usize = 27 * 2_500_000;
    let server = MockServer::start(ok_handler(body));

    let work = unique_dir("crash_resume_compressed");
    let _g = CleanupDir(work.clone());

    let kill = Arc::new(AtomicBool::new(false));
    let kill_for_cb = Arc::clone(&kill);
    let counter = Arc::new(AtomicU64::new(0));
    let counter_for_cb = Arc::clone(&counter);
    let progress: peel::coordinator::ProgressFn = Box::new(move |event| {
        if let ProgressEvent::CheckpointWritten { .. } = event {
            let n = counter_for_cb.fetch_add(1, Ordering::Relaxed) + 1;
            if n >= 1 {
                kill_for_cb.store(true, Ordering::Release);
            }
        }
    });
    let args = make_args(
        &server,
        OutputTarget::Dir(work.clone()),
        coord_config(64 * 1024),
        Some(Arc::clone(&kill)),
        Some(progress),
    );
    match run(args) {
        Err(CoordinatorError::Aborted { .. }) => {}
        other => panic!("expected Aborted, got {other:?}"),
    }

    let args2 = make_args(
        &server,
        OutputTarget::Dir(work.clone()),
        coord_config(64 * 1024),
        None,
        None,
    );
    run(args2).expect("resume run");

    // The fixture's payload is `b'X' * 67_500_000`. Walk the
    // extracted directory to find the entry (the fixture's
    // entry name is opaque to this test); there must be exactly
    // one regular file of the expected size and content.
    let extracted = read_dir_recursive(&work);
    assert_eq!(extracted.len(), 1, "expected one entry, got: {extracted:?}");
    assert_eq!(
        extracted[0].1.len(),
        expected_len,
        "decoded length mismatch"
    );
    assert!(
        extracted[0].1.iter().all(|&b| b == b'X'),
        "decoded bytes contained a non-'X' byte"
    );
}
