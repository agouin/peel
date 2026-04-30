//! Integration tests for [`peel::coordinator`].
//!
//! These tests run the full pipeline end-to-end against the in-process
//! mock HTTP server: discovery → ranged download → blocking sparse
//! reader → zstd decoder → sink → checkpoint. Plan §10.3 acceptance
//! criteria covered:
//!
//! - Happy path: full download + extraction byte-identical to source.
//! - Resume: a checkpoint left by an earlier run is picked up cleanly
//!   and produces byte-identical output.
//! - ETag mismatch: the source identity changing between runs aborts
//!   resume cleanly with a typed error.
//! - Sidecar cleanup: `.peel.part` and `.peel.ckpt` are removed after a
//!   clean run.
//!
//! The crash-test harness — kill at random points and verify resume
//! reproduces a clean run's output — lives in `test_coordinator_crash.rs`
//! to keep it isolatable when you want to skip the longer suite.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use peel::checkpoint::{Checkpoint, SinkState};
use peel::coordinator::{
    run, CoordinatorConfig, CoordinatorError, OutputTarget, ProgressEvent, ProgressFn, RunArgs,
};
use peel::decode::DecoderRegistry;
use peel::download::RetryConfig;
use peel::http::{Client, ClientConfig};
use peel::progress::{spawn_renderer, ProgressRenderer, ProgressSnapshot, ProgressState};
use peel::types::ByteOffset;

#[path = "support/mod.rs"]
mod support;

use support::mock_server::{MockRequest, MockResponse, MockServer};
use support::tar_fixtures::{build_header, build_pax_body, build_simple_archive, end_of_archive};
use support::zip_fixtures::{build_zip, ZipEntrySpec};

// ---- helpers -----------------------------------------------------------

static UNIQ: AtomicU64 = AtomicU64::new(0);

fn unique_dir(label: &str) -> PathBuf {
    let pid = std::process::id();
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("peel_coord_it_{label}_{pid}_{nanos}_{n}"));
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
        timeout: Duration::from_secs(5),
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

fn coord_config_for_test(chunk_size: u64) -> CoordinatorConfig {
    CoordinatorConfig {
        chunk_size,
        workers: 2,
        retry: fast_retry(),
        punch_threshold: 4096,
        checkpoint_min_bytes: 1, // write on every quiescent advance
        checkpoint_min_interval: Duration::from_millis(0),
        workdir: None,
        reader_poll_interval: Duration::from_millis(2),
        forced_format: None,
        force_format_from_magic: false,
        io_backend: peel::io_backend::IoBackendChoice::Blocking,
    }
}

/// Encode `payload` as a single-frame zstd stream.
fn encode_zstd(payload: &[u8]) -> Vec<u8> {
    zstd::encode_all(payload, 1).expect("encode zstd")
}

/// Encode `payloads` as a multi-frame zstd stream so the extractor's
/// quiescent-checkpoint cadence has somewhere to land.
fn encode_zstd_frames(payloads: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in payloads {
        out.extend_from_slice(&zstd::encode_all(*p, 1).expect("encode zstd frame"));
    }
    out
}

/// Encode `payload` as a single-frame, single-block, uncompressed
/// LZ4 archive with no checksums and no content size — the minimum
/// viable shape `decode/lz4.rs` accepts. Hand-rolled here so the
/// coordinator integration test stays independent of any specific
/// lz4 encoder library.
fn encode_lz4_uncompressed_frame(payload: &[u8]) -> Vec<u8> {
    const PRIME32_1: u32 = 0x9E37_79B1;
    const PRIME32_2: u32 = 0x85EB_CA77;
    const PRIME32_3: u32 = 0xC2B2_AE3D;
    const PRIME32_4: u32 = 0x27D4_EB2F;
    const PRIME32_5: u32 = 0x1656_67B1;

    fn read_u32_le(bs: &[u8]) -> u32 {
        u32::from_le_bytes([bs[0], bs[1], bs[2], bs[3]])
    }
    fn round(acc: u32, lane: u32) -> u32 {
        acc.wrapping_add(lane.wrapping_mul(PRIME32_2))
            .rotate_left(13)
            .wrapping_mul(PRIME32_1)
    }
    fn xxh32(input: &[u8]) -> u32 {
        let mut p = 0usize;
        let len = input.len();
        let mut h: u32;
        if len >= 16 {
            let mut v1 = PRIME32_1.wrapping_add(PRIME32_2);
            let mut v2 = PRIME32_2;
            let mut v3 = 0u32;
            let mut v4 = 0u32.wrapping_sub(PRIME32_1);
            let limit = len - 16;
            loop {
                v1 = round(v1, read_u32_le(&input[p..]));
                v2 = round(v2, read_u32_le(&input[p + 4..]));
                v3 = round(v3, read_u32_le(&input[p + 8..]));
                v4 = round(v4, read_u32_le(&input[p + 12..]));
                p += 16;
                if p > limit {
                    break;
                }
            }
            h = v1
                .rotate_left(1)
                .wrapping_add(v2.rotate_left(7))
                .wrapping_add(v3.rotate_left(12))
                .wrapping_add(v4.rotate_left(18));
        } else {
            h = PRIME32_5;
        }
        h = h.wrapping_add(len as u32);
        while p + 4 <= len {
            h = h.wrapping_add(read_u32_le(&input[p..]).wrapping_mul(PRIME32_3));
            h = h.rotate_left(17).wrapping_mul(PRIME32_4);
            p += 4;
        }
        while p < len {
            h = h.wrapping_add(u32::from(input[p]).wrapping_mul(PRIME32_5));
            h = h.rotate_left(11).wrapping_mul(PRIME32_1);
            p += 1;
        }
        h ^= h >> 15;
        h = h.wrapping_mul(PRIME32_2);
        h ^= h >> 13;
        h = h.wrapping_mul(PRIME32_3);
        h ^= h >> 16;
        h
    }

    let mut out = Vec::new();
    out.extend_from_slice(&0x184D_2204u32.to_le_bytes());
    let flg: u8 = 0b0110_0000;
    let bd: u8 = 0b0111_0000;
    out.push(flg);
    out.push(bd);
    let hc = ((xxh32(&[flg, bd]) >> 8) & 0xff) as u8;
    out.push(hc);
    let header = (payload.len() as u32) | 0x8000_0000;
    out.extend_from_slice(&header.to_le_bytes());
    out.extend_from_slice(payload);
    out.extend_from_slice(&[0u8; 4]);
    out
}

/// Encode `payload` as a single-Stream xz blob using liblzma's easy
/// encoder at preset 6 (matching `xz`'s default).
fn encode_xz(payload: &[u8]) -> Vec<u8> {
    use xz2::stream::{Action, Check, Status, Stream};

    let mut encoder = Stream::new_easy_encoder(6, Check::Crc64).expect("encoder");
    let mut out: Vec<u8> = Vec::with_capacity(payload.len() / 2 + 256);
    let mut input_pos = 0usize;
    let mut scratch = vec![0u8; 1 << 14];
    loop {
        let action = if input_pos < payload.len() {
            Action::Run
        } else {
            Action::Finish
        };
        let prev_in = encoder.total_in();
        let prev_out = encoder.total_out();
        let res = encoder
            .process(&payload[input_pos..], &mut scratch, action)
            .expect("encode step");
        input_pos += (encoder.total_in() - prev_in) as usize;
        let produced = (encoder.total_out() - prev_out) as usize;
        out.extend_from_slice(&scratch[..produced]);
        if let Status::StreamEnd = res {
            break;
        }
    }
    out
}

/// "Well-behaved" mock handler: HEAD reports size + ETag + Accept-Ranges,
/// every range request gets a 206 with the matching slice.
fn ok_handler(
    body: Vec<u8>,
    etag: Option<&'static str>,
) -> impl Fn(&MockRequest, u64) -> MockResponse + Send + Sync + 'static {
    move |req, _| serve(req, &body, etag.map(str::to_string))
}

fn serve(req: &MockRequest, body: &[u8], etag: Option<String>) -> MockResponse {
    let mut head_headers: Vec<(String, String)> = vec![
        ("Content-Length".into(), body.len().to_string()),
        ("Accept-Ranges".into(), "bytes".into()),
    ];
    if let Some(e) = &etag {
        head_headers.push(("ETag".into(), e.clone()));
    }
    if req.method == "HEAD" {
        return MockResponse::Reply {
            status: 200,
            reason: "OK",
            headers: head_headers,
            body: Vec::new(),
        };
    }
    if let Some(range_hdr) = req.header("range") {
        if let Some((a, b)) = parse_range(range_hdr) {
            let a_us = a as usize;
            let b_us = b as usize;
            if b_us >= body.len() {
                return MockResponse::Reply {
                    status: 416,
                    reason: "Range Not Satisfiable",
                    headers: vec![],
                    body: Vec::new(),
                };
            }
            let slice = body[a_us..=b_us].to_vec();
            let mut h = vec![(
                "Content-Range".into(),
                format!("bytes {a}-{b}/{}", body.len()),
            )];
            if let Some(e) = &etag {
                h.push(("ETag".into(), e.clone()));
            }
            return MockResponse::Reply {
                status: 206,
                reason: "Partial Content",
                headers: h,
                body: slice,
            };
        }
    }
    MockResponse::Reply {
        status: 200,
        reason: "OK",
        headers: vec![],
        body: body.to_vec(),
    }
}

fn parse_range(value: &str) -> Option<(u64, u64)> {
    let after = value.strip_prefix("bytes=")?;
    let (a, b) = after.split_once('-')?;
    Some((a.parse().ok()?, b.parse().ok()?))
}

fn make_args(
    server: &MockServer,
    suffix: &str,
    output: OutputTarget,
    config: CoordinatorConfig,
) -> RunArgs {
    RunArgs {
        url: format!("{}/{suffix}", server.base_url()),
        output,
        config,
        client: build_client(),
        registry: DecoderRegistry::with_defaults(),
        progress: None,
        progress_state: None,
        kill_switch: None,
    }
}

fn read_dir_recursive(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

fn walk(root: &Path, cur: &Path, out: &mut Vec<(String, Vec<u8>)>) {
    let entries = match fs::read_dir(cur) {
        Ok(e) => e,
        Err(_) => return,
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

// ---- happy path: file output ------------------------------------------

#[test]
fn happy_path_zst_to_file_round_trips_bytes() {
    let payload = b"plain payload for the raw sink, ".repeat(1024);
    let body = encode_zstd(&payload);
    let body_len = body.len() as u64;
    let server = MockServer::start(ok_handler(body, Some("\"v1\"")));

    let work = unique_dir("happy_file");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");

    let mut config = coord_config_for_test(4096);
    config.chunk_size = 1024.max(body_len.div_ceil(8));
    let args = make_args(
        &server,
        "data.zst",
        OutputTarget::File(out_path.clone()),
        config,
    );

    let stats = run(args).expect("happy run");
    assert_eq!(stats.extraction.bytes_out, payload.len() as u64);
    assert!(!stats.resumed);
    assert_eq!(fs::read(&out_path).expect("read"), payload);

    // Sidecars cleaned up.
    assert!(!work.join("out.bin.peel.part").exists());
    assert!(!work.join("out.bin.peel.ckpt").exists());
}

// ---- happy path: tar output --------------------------------------------

#[test]
fn happy_path_tar_zst_to_dir_extracts_archive() {
    let archive = build_simple_archive(&[
        ("dir/a.txt", b"hello-a"),
        ("dir/sub/b.bin", &[42u8; 256]),
        ("dir/c.empty", b""),
    ]);
    let body = encode_zstd_frames(&[&archive[..archive.len() / 2], &archive[archive.len() / 2..]]);
    let server = MockServer::start(ok_handler(body, Some("\"v-tar\"")));

    let work = unique_dir("happy_tar");
    let _g = CleanupDir(work.clone());
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).expect("create out dir");

    let args = make_args(
        &server,
        "x.tar.zst",
        OutputTarget::Dir(out_dir.clone()),
        coord_config_for_test(4096),
    );

    let stats = run(args).expect("tar happy run");
    assert!(!stats.resumed);

    let entries = read_dir_recursive(&out_dir);
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"dir/a.txt"));
    assert!(names.contains(&"dir/sub/b.bin"));
    assert_eq!(fs::read(out_dir.join("dir/a.txt")).unwrap(), b"hello-a");
    assert_eq!(
        fs::read(out_dir.join("dir/sub/b.bin")).unwrap(),
        vec![42u8; 256]
    );

    // Sidecars cleaned up.
    let sidecar_part = work.join("out.peel.part");
    let sidecar_ckpt = work.join("out.peel.ckpt");
    assert!(
        !sidecar_part.exists(),
        "expected no .part: {sidecar_part:?}"
    );
    assert!(
        !sidecar_ckpt.exists(),
        "expected no .ckpt: {sidecar_ckpt:?}"
    );
}

// ---- happy path: tar.xz output (PLAN_v2 §3) ---------------------------

#[test]
fn happy_path_tar_xz_to_dir_extracts_archive() {
    let archive = build_simple_archive(&[
        ("dir/a.txt", b"hello-xz-a"),
        ("dir/sub/b.bin", &[7u8; 1024]),
        ("dir/c.empty", b""),
    ]);
    let body = encode_xz(&archive);
    let server = MockServer::start(ok_handler(body, Some("\"v-tar-xz\"")));

    let work = unique_dir("happy_tar_xz");
    let _g = CleanupDir(work.clone());
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).expect("create out dir");

    let args = make_args(
        &server,
        "x.tar.xz",
        OutputTarget::Dir(out_dir.clone()),
        coord_config_for_test(4096),
    );

    let stats = run(args).expect("tar.xz happy run");
    assert!(!stats.resumed);

    let entries = read_dir_recursive(&out_dir);
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"dir/a.txt"));
    assert!(names.contains(&"dir/sub/b.bin"));
    assert_eq!(fs::read(out_dir.join("dir/a.txt")).unwrap(), b"hello-xz-a");
    assert_eq!(
        fs::read(out_dir.join("dir/sub/b.bin")).unwrap(),
        vec![7u8; 1024]
    );

    let sidecar_part = work.join("out.peel.part");
    let sidecar_ckpt = work.join("out.peel.ckpt");
    assert!(
        !sidecar_part.exists(),
        "expected no .part: {sidecar_part:?}"
    );
    assert!(
        !sidecar_ckpt.exists(),
        "expected no .ckpt: {sidecar_ckpt:?}"
    );
}

// ---- happy path: tar.lz4 output (PLAN_v2 §4) --------------------------

#[test]
fn happy_path_tar_lz4_to_dir_extracts_archive() {
    let archive = build_simple_archive(&[
        ("dir/a.txt", b"hello-lz4-a"),
        ("dir/sub/b.bin", &[19u8; 1024]),
        ("dir/c.empty", b""),
    ]);
    let body = encode_lz4_uncompressed_frame(&archive);
    let server = MockServer::start(ok_handler(body, Some("\"v-tar-lz4\"")));

    let work = unique_dir("happy_tar_lz4");
    let _g = CleanupDir(work.clone());
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).expect("create out dir");

    let args = make_args(
        &server,
        "x.tar.lz4",
        OutputTarget::Dir(out_dir.clone()),
        coord_config_for_test(4096),
    );

    let stats = run(args).expect("tar.lz4 happy run");
    assert!(!stats.resumed);

    let entries = read_dir_recursive(&out_dir);
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"dir/a.txt"));
    assert!(names.contains(&"dir/sub/b.bin"));
    assert_eq!(fs::read(out_dir.join("dir/a.txt")).unwrap(), b"hello-lz4-a");
    assert_eq!(
        fs::read(out_dir.join("dir/sub/b.bin")).unwrap(),
        vec![19u8; 1024]
    );

    let sidecar_part = work.join("out.peel.part");
    let sidecar_ckpt = work.join("out.peel.ckpt");
    assert!(
        !sidecar_part.exists(),
        "expected no .part: {sidecar_part:?}"
    );
    assert!(
        !sidecar_ckpt.exists(),
        "expected no .ckpt: {sidecar_ckpt:?}"
    );
}

// ---- progress events fire ---------------------------------------------

#[test]
fn progress_callback_observes_started_and_finished() {
    let payload = b"track-progress".repeat(8192);
    let body = encode_zstd_frames(&[&payload[..payload.len() / 2], &payload[payload.len() / 2..]]);
    let server = MockServer::start(ok_handler(body, Some("\"v-prog\"")));

    let work = unique_dir("progress");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");

    let observed: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
    let observed_cb = Arc::clone(&observed);
    let progress: ProgressFn = Box::new(move |event| match event {
        ProgressEvent::Started { .. } => observed_cb.lock().unwrap().push("started"),
        ProgressEvent::CheckpointWritten { .. } => observed_cb.lock().unwrap().push("ckpt"),
        ProgressEvent::Finished { .. } => observed_cb.lock().unwrap().push("finished"),
    });

    let mut args = make_args(
        &server,
        "track.zst",
        OutputTarget::File(out_path.clone()),
        coord_config_for_test(4096),
    );
    args.progress = Some(progress);

    run(args).expect("run with progress");
    let events = observed.lock().unwrap().clone();
    assert!(events.starts_with(&["started"]));
    assert_eq!(events.last().copied(), Some("finished"));
}

// ---- progress state plumbed end-to-end (PLAN_v2.md §6) ----------------

/// Recording renderer: stores every snapshot it receives so the test
/// can assert a non-trivial number of ticks fired and the counters
/// progressed monotonically.
struct RecordingRenderer {
    snaps: Arc<Mutex<Vec<ProgressSnapshot>>>,
    finish_called: Arc<std::sync::atomic::AtomicBool>,
}

impl ProgressRenderer for RecordingRenderer {
    fn render(&mut self, snap: &ProgressSnapshot) {
        self.snaps.lock().unwrap().push(*snap);
    }
    fn finish(&mut self) {
        self.finish_called
            .store(true, std::sync::atomic::Ordering::Release);
    }
}

#[test]
fn progress_state_counters_advance_during_a_run() {
    // Use a multi-frame body so checkpoints fire and the extractor's
    // SinkAdapter has multiple chances to update bytes_extracted.
    let payload_a = b"prog-frame-a-".repeat(2048);
    let payload_b = b"prog-frame-b-larger-".repeat(4096);
    let body = encode_zstd_frames(&[&payload_a, &payload_b]);
    let total_compressed = body.len() as u64;
    let total_decoded = (payload_a.len() + payload_b.len()) as u64;
    let server = MockServer::start(ok_handler(body, Some("\"v-progstate\"")));

    let work = unique_dir("progstate");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");

    let state = ProgressState::new();
    let snaps: Arc<Mutex<Vec<ProgressSnapshot>>> = Arc::new(Mutex::new(Vec::new()));
    let finish_called = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let renderer = RecordingRenderer {
        snaps: Arc::clone(&snaps),
        finish_called: Arc::clone(&finish_called),
    };
    // Tight render cadence so the test sees several mid-run ticks.
    let render_handle = spawn_renderer(Arc::clone(&state), renderer, Duration::from_millis(5))
        .expect("spawn recording renderer");

    let mut args = make_args(
        &server,
        "progstate.zst",
        OutputTarget::File(out_path.clone()),
        coord_config_for_test(4096),
    );
    args.progress_state = Some(Arc::clone(&state));

    let stats = run(args).expect("run with progress state");
    state.mark_done();
    render_handle.join().expect("renderer thread");

    // Pipeline-side counters reach the totals.
    assert_eq!(state.snapshot().bytes_downloaded, total_compressed);
    assert_eq!(state.snapshot().bytes_extracted, total_decoded);
    assert_eq!(state.snapshot().total_size, Some(total_compressed));
    // Workers all retired.
    assert_eq!(state.snapshot().active_workers, 0);
    assert!(state.snapshot().total_workers >= 1);
    assert!(state.snapshot().started);
    assert!(state.snapshot().done);
    // Renderer ran finish() at shutdown.
    assert!(finish_called.load(std::sync::atomic::Ordering::Acquire));

    // Renderer recorded a sequence of monotonically non-decreasing
    // counters and saw at least some non-zero values mid-run.
    let recorded = snaps.lock().unwrap().clone();
    assert!(
        recorded.len() >= 2,
        "expected several render ticks, got {}",
        recorded.len(),
    );
    let mut prev_dl = 0u64;
    let mut prev_ex = 0u64;
    for s in &recorded {
        assert!(s.bytes_downloaded >= prev_dl);
        assert!(s.bytes_extracted >= prev_ex);
        prev_dl = s.bytes_downloaded;
        prev_ex = s.bytes_extracted;
    }
    // The final tick after mark_done() reflects the terminal totals.
    let last = recorded.last().expect("at least one snapshot");
    assert_eq!(last.bytes_downloaded, total_compressed);
    assert_eq!(last.bytes_extracted, total_decoded);

    // Underlying `RunStats` agrees with what the state ended up at.
    assert_eq!(stats.download.bytes_downloaded, total_compressed);
    assert_eq!(stats.extraction.bytes_out, total_decoded);
}

// ---- resume: pick up where we left off --------------------------------

#[test]
fn resume_picks_up_from_existing_checkpoint() {
    // Strategy: do a full clean run first to learn what `out.bin`
    // should look like. Then for the resume run, manually pre-stage:
    //   - the .part file fully populated (mimic that workers had
    //     already finished)
    //   - the .ckpt file claiming all chunks complete and
    //     decoder_position past the last frame boundary
    //   - a partially extracted out.bin
    // The resumed run should still produce an identical out.bin.

    let payload_a = b"resume-frame-a".repeat(1024);
    let payload_b = b"resume-frame-b-larger".repeat(2048);
    let body = encode_zstd_frames(&[&payload_a, &payload_b]);
    let body_len = body.len() as u64;
    let payload: Vec<u8> = payload_a.iter().chain(payload_b.iter()).copied().collect();

    let server = MockServer::start(ok_handler(body.clone(), Some("\"v-resume\"")));

    // Phase 1: a clean run to confirm the expected output.
    let work1 = unique_dir("resume_phase1");
    let _g1 = CleanupDir(work1.clone());
    let out_path1 = work1.join("out.bin");
    let args1 = make_args(
        &server,
        "resume.zst",
        OutputTarget::File(out_path1.clone()),
        coord_config_for_test(4096),
    );
    let stats1 = run(args1).expect("phase1");
    assert!(!stats1.resumed);
    let expected = fs::read(&out_path1).expect("phase1 output");
    assert_eq!(expected, payload);

    // Phase 2: resume from a hand-constructed checkpoint that says
    // "everything downloaded, half written." We pre-stage the .part
    // with the full body bytes so the workers have nothing to do.
    let work2 = unique_dir("resume_phase2");
    let _g2 = CleanupDir(work2.clone());
    let out_path2 = work2.join("out.bin");

    // Pre-write the partial output (first frame's payload).
    fs::write(&out_path2, &payload_a).expect("partial output");

    // Pre-write the part file with the *full* compressed body.
    let part_path = work2.join("out.bin.peel.part");
    fs::write(&part_path, &body).expect("part body");

    // Pre-write a checkpoint that claims chunk 0..N all complete and
    // decoder_position == compressed_len_of_first_frame so the
    // resumed decoder picks up at the second frame.
    let chunk_size = 4096u64;
    let total_chunks = body_len.div_ceil(chunk_size) as u32;
    let bitmap_bytes = {
        let b = peel::bitmap::ChunkBitmap::new(total_chunks);
        for i in 0..total_chunks {
            b.mark_complete(peel::types::ChunkIndex::new(i));
        }
        b.to_bytes()
    };
    let frame_a_compressed_len = zstd::encode_all(&payload_a[..], 1).expect("ea").len() as u64;
    let ckpt = Checkpoint {
        url: format!("{}/resume.zst", server.base_url()),
        etag: Some("\"v-resume\"".into()),
        last_modified: None,
        total_size: body_len,
        chunk_size,
        decoder_position: ByteOffset::new(frame_a_compressed_len),
        bitmap_completed: bitmap_bytes,
        created_at: SystemTime::now(),
        sink_state: SinkState::Raw {
            bytes_written: payload_a.len() as u64,
        },
    };
    let ckpt_path = work2.join("out.bin.peel.ckpt");
    ckpt.write(&ckpt_path).expect("ckpt write");

    let args2 = make_args(
        &server,
        "resume.zst",
        OutputTarget::File(out_path2.clone()),
        CoordinatorConfig {
            chunk_size,
            ..coord_config_for_test(chunk_size)
        },
    );
    let stats2 = run(args2).expect("phase2");
    assert!(stats2.resumed);

    let got = fs::read(&out_path2).expect("phase2 output");
    assert_eq!(got, expected);
}

// ---- ETag mismatch on resume -----------------------------------------

#[test]
fn etag_mismatch_on_resume_aborts_cleanly() {
    let payload = b"etag-mismatch-payload".repeat(512);
    let body = encode_zstd(&payload);
    let body_len = body.len() as u64;
    // Server's current ETag is "\"v2\"" but the prior checkpoint
    // recorded "\"v1\"".
    let server = MockServer::start(ok_handler(body, Some("\"v2\"")));

    let work = unique_dir("etag_mismatch");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");

    let chunk_size = 4096u64;
    let total_chunks = body_len.div_ceil(chunk_size) as u32;
    let bitmap_bytes = peel::bitmap::ChunkBitmap::new(total_chunks).to_bytes();
    let ckpt = Checkpoint {
        url: format!("{}/x.zst", server.base_url()),
        etag: Some("\"v1\"".into()),
        last_modified: None,
        total_size: body_len,
        chunk_size,
        decoder_position: ByteOffset::new(0),
        bitmap_completed: bitmap_bytes,
        created_at: SystemTime::now(),
        sink_state: SinkState::Raw { bytes_written: 0 },
    };
    let ckpt_path = work.join("out.bin.peel.ckpt");
    ckpt.write(&ckpt_path).expect("ckpt write");

    let args = make_args(
        &server,
        "x.zst",
        OutputTarget::File(out_path),
        CoordinatorConfig {
            chunk_size,
            ..coord_config_for_test(chunk_size)
        },
    );
    let err = run(args).expect_err("etag mismatch must abort");
    match err {
        CoordinatorError::SourceChanged { reason } => {
            assert!(reason.to_lowercase().contains("etag") || reason.contains("Last-Modified"));
        }
        other => panic!("expected SourceChanged, got {other:?}"),
    }
}

// ---- url change on resume -------------------------------------------

#[test]
fn url_change_on_resume_aborts_cleanly() {
    let payload = b"url-change-payload".repeat(512);
    let body = encode_zstd(&payload);
    let body_len = body.len() as u64;
    let server = MockServer::start(ok_handler(body, Some("\"v1\"")));

    let work = unique_dir("url_change");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");

    let chunk_size = 4096u64;
    let total_chunks = body_len.div_ceil(chunk_size) as u32;
    let bitmap_bytes = peel::bitmap::ChunkBitmap::new(total_chunks).to_bytes();
    let ckpt = Checkpoint {
        url: "http://different.example/y.zst".into(),
        etag: Some("\"v1\"".into()),
        last_modified: None,
        total_size: body_len,
        chunk_size,
        decoder_position: ByteOffset::new(0),
        bitmap_completed: bitmap_bytes,
        created_at: SystemTime::now(),
        sink_state: SinkState::Raw { bytes_written: 0 },
    };
    let ckpt_path = work.join("out.bin.peel.ckpt");
    ckpt.write(&ckpt_path).expect("ckpt write");

    let args = make_args(
        &server,
        "x.zst",
        OutputTarget::File(out_path),
        CoordinatorConfig {
            chunk_size,
            ..coord_config_for_test(chunk_size)
        },
    );
    let err = run(args).expect_err("url change must abort");
    assert!(matches!(err, CoordinatorError::SourceChanged { .. }));
}

// ---- uncompressed `.tar` (PLAN_v2 §2) ---------------------------------

/// North-star happy path against an uncompressed `.tar`: the identity
/// decoder hands bytes straight through to `TarSink` and the on-disk
/// extracted tree matches the archive contents.
#[test]
fn happy_path_plain_tar_to_dir_extracts_archive() {
    let archive = build_simple_archive(&[
        ("dir/a.txt", b"hello-uncompressed-tar"),
        ("dir/sub/b.bin", &[7u8; 1024]),
        ("dir/c.empty", b""),
    ]);
    let server = MockServer::start(ok_handler(archive, Some("\"v-plain-tar\"")));

    let work = unique_dir("happy_plain_tar");
    let _g = CleanupDir(work.clone());
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).expect("create out dir");

    let args = make_args(
        &server,
        "x.tar",
        OutputTarget::Dir(out_dir.clone()),
        coord_config_for_test(4096),
    );
    let stats = run(args).expect("plain-tar happy run");
    assert!(!stats.resumed);

    let entries = read_dir_recursive(&out_dir);
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    assert!(names.contains(&"dir/a.txt"));
    assert!(names.contains(&"dir/sub/b.bin"));
    assert!(names.contains(&"dir/c.empty"));
    assert_eq!(
        fs::read(out_dir.join("dir/a.txt")).unwrap(),
        b"hello-uncompressed-tar"
    );
    assert_eq!(
        fs::read(out_dir.join("dir/sub/b.bin")).unwrap(),
        vec![7u8; 1024]
    );

    // Sidecars cleaned up.
    assert!(!work.join("out.peel.part").exists());
    assert!(!work.join("out.peel.ckpt").exists());
}

/// A URL with no recognized suffix still routes to the tar identity
/// decoder via the magic-byte path: `ustar\0` at offset 257 is the
/// only registered tar signature and the only registered signature
/// that doesn't live at offset 0, so this exercises the offset-aware
/// branch of [`peel::decode::DecoderRegistry::factory_for_prefix`].
#[test]
fn tar_magic_only_path_extracts_when_url_has_no_suffix() {
    let archive = build_simple_archive(&[("a.txt", b"magic-detected-tar"), ("b.bin", &[3u8; 33])]);
    let server = MockServer::start(ok_handler(archive, Some("\"v-magic-tar\"")));

    let work = unique_dir("tar_magic_only");
    let _g = CleanupDir(work.clone());
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).expect("create out dir");

    // The URL ends in a generic, unrecognized suffix; only the magic
    // byte detection can pick the tar factory.
    let args = make_args(
        &server,
        "download.bin",
        OutputTarget::Dir(out_dir.clone()),
        coord_config_for_test(4096),
    );
    let stats = run(args).expect("tar magic run");
    assert!(!stats.resumed);

    assert_eq!(
        fs::read(out_dir.join("a.txt")).unwrap(),
        b"magic-detected-tar"
    );
    assert_eq!(fs::read(out_dir.join("b.bin")).unwrap(), vec![3u8; 33]);
}

/// Empty archive (just the two-zero-block end-of-archive marker) is
/// 1024 bytes of zeros — there is *no* `ustar` magic to detect, so
/// magic-byte detection misses entirely. The suffix-only path must
/// still route the run to the identity decoder; the tar sink validates
/// the marker and `close()` succeeds.
#[test]
fn empty_tar_archive_resolves_via_suffix_only() {
    let body = end_of_archive();
    let server = MockServer::start(ok_handler(body, Some("\"v-empty-tar\"")));

    let work = unique_dir("empty_tar");
    let _g = CleanupDir(work.clone());
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).expect("create out dir");

    let args = make_args(
        &server,
        "empty.tar",
        OutputTarget::Dir(out_dir.clone()),
        coord_config_for_test(4096),
    );
    let stats = run(args).expect("empty tar run");
    assert!(!stats.resumed);
    assert!(read_dir_recursive(&out_dir).is_empty());
}

/// PAX-prefixed entry: the first 512-byte block in the archive is a
/// PAX 'x' extended header (typeflag `x`, magic still `ustar\0` at
/// offset 257) overriding the next member's path. Magic-byte
/// detection must accept this — offset 257 in the *first* block
/// satisfies the registered tar magic — and the parser must traverse
/// the PAX record to extract the long-named member that follows.
#[test]
fn pax_prefixed_tar_extracts_via_magic_detection() {
    // A "long" path that requires PAX overriding, since USTAR caps
    // the name at 100 bytes (with optional 155-byte prefix). We pick
    // a path comfortably above 100 bytes so the override is the only
    // viable encoding.
    let long_path = format!("dir/{}/leaf.txt", "a".repeat(120));
    let payload: &[u8] = b"pax-overridden-payload";

    let pax_body = build_pax_body(&[("path", &long_path)]);
    let pax_padded = {
        // pad PAX body to a 512-byte block.
        let mut v = pax_body.clone();
        let rem = v.len() % 512;
        if rem != 0 {
            v.resize(v.len() + (512 - rem), 0);
        }
        v
    };

    let mut archive: Vec<u8> = Vec::new();
    // PAX 'x' header — first 512 bytes carry the ustar magic at 257.
    archive.extend_from_slice(&build_header(
        "PaxHeaders/leaf.txt",
        pax_body.len() as u64,
        b'x',
    ));
    archive.extend_from_slice(&pax_padded);
    // Followed by the regular file whose path PAX overrides.
    archive.extend_from_slice(&build_header("ignored", payload.len() as u64, b'0'));
    archive.extend_from_slice(payload);
    let pad = (512 - payload.len() % 512) % 512;
    archive.extend(std::iter::repeat_n(0u8, pad));
    archive.extend_from_slice(&end_of_archive());

    let server = MockServer::start(ok_handler(archive, Some("\"v-pax-tar\"")));

    let work = unique_dir("pax_tar");
    let _g = CleanupDir(work.clone());
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).expect("create out dir");

    // Generic suffix forces the magic-byte path. The PAX block leads
    // and still carries the registered ustar magic at offset 257.
    let args = make_args(
        &server,
        "data.bin",
        OutputTarget::Dir(out_dir.clone()),
        coord_config_for_test(4096),
    );
    run(args).expect("pax tar run");
    let extracted = fs::read(out_dir.join(&long_path)).expect("pax-overridden file present");
    assert_eq!(extracted, payload);
}

// ---- happy path: zip output (PLAN_v2 §5) ----------------------------

#[test]
fn happy_path_zip_to_dir_extracts_mixed_methods() {
    // Multi-entry archive exercising all three round-one methods.
    // The DEFLATE payload is large enough that DEFLATE actually
    // does work (so the test exercises a non-trivial flate2 path).
    let mut deflate_payload = Vec::with_capacity(32 * 1024);
    while deflate_payload.len() < 32 * 1024 {
        deflate_payload.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
    }
    deflate_payload.truncate(32 * 1024);
    let zstd_payload = b"zstd entry payload, ".repeat(200);

    let archive = build_zip(&[
        ZipEntrySpec::stored("readme.txt", b"hello, zip!".to_vec()),
        ZipEntrySpec::deflate("compressible.txt", deflate_payload.clone()),
        ZipEntrySpec::zstd("nested/big.bin", zstd_payload.clone()),
        ZipEntrySpec::directory("emptydir"),
    ]);
    let archive_len = archive.len() as u64;
    let server = MockServer::start(ok_handler(archive, Some("\"v-zip\"")));

    let work = unique_dir("happy_zip");
    let _g = CleanupDir(work.clone());
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).expect("create out dir");

    let mut config = coord_config_for_test(4096);
    config.chunk_size = 1024.max(archive_len.div_ceil(8));
    let args = make_args(
        &server,
        "release.zip",
        OutputTarget::Dir(out_dir.clone()),
        config,
    );

    let stats = run(args).expect("zip happy run");
    assert!(!stats.resumed);
    let total_uncompressed =
        b"hello, zip!".len() as u64 + deflate_payload.len() as u64 + zstd_payload.len() as u64;
    assert_eq!(stats.extraction.bytes_out, total_uncompressed);

    assert_eq!(
        fs::read(out_dir.join("readme.txt")).unwrap(),
        b"hello, zip!"
    );
    assert_eq!(
        fs::read(out_dir.join("compressible.txt")).unwrap(),
        deflate_payload,
    );
    assert_eq!(
        fs::read(out_dir.join("nested/big.bin")).unwrap(),
        zstd_payload,
    );
    assert!(out_dir.join("emptydir").is_dir());

    // Sidecars cleaned up on success.
    let sidecar_part = work.join("out.peel.part");
    let sidecar_ckpt = work.join("out.peel.ckpt");
    assert!(
        !sidecar_part.exists(),
        "expected no .part: {sidecar_part:?}"
    );
    assert!(
        !sidecar_ckpt.exists(),
        "expected no .ckpt: {sidecar_ckpt:?}"
    );
}

#[test]
fn zip_to_file_output_is_rejected() {
    let archive = build_zip(&[ZipEntrySpec::stored("a.txt", b"hi".to_vec())]);
    let server = MockServer::start(ok_handler(archive, Some("\"v-zipfile\"")));

    let work = unique_dir("zip_file_out");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");

    let args = make_args(
        &server,
        "release.zip",
        OutputTarget::File(out_path),
        coord_config_for_test(4096),
    );
    let err = run(args).expect_err("zip + -o must abort");
    assert!(matches!(err, CoordinatorError::ZipNeedsDirectory));
}

#[test]
fn zip_unsupported_method_surfaces_specific_feature_name() {
    // Manually craft a zip with method 14 (LZMA) — round-one should
    // refuse with a feature-named UnsupportedFeature error.
    let mut archive = Vec::new();
    // LFH for a single entry, method = 14 (LZMA), 0-byte content.
    archive.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    archive.extend_from_slice(&20u16.to_le_bytes()); // version_needed
    archive.extend_from_slice(&0u16.to_le_bytes()); // gp_flags
    archive.extend_from_slice(&14u16.to_le_bytes()); // compression_method = LZMA
    archive.extend_from_slice(&0u16.to_le_bytes()); // mtime
    archive.extend_from_slice(&0u16.to_le_bytes()); // mdate
    archive.extend_from_slice(&0u32.to_le_bytes()); // crc
    archive.extend_from_slice(&0u32.to_le_bytes()); // compressed_size
    archive.extend_from_slice(&0u32.to_le_bytes()); // uncompressed_size
    let name = b"weird.bin";
    archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes()); // extra
    archive.extend_from_slice(name);
    let lfh_offset = 0u32;
    let cd_offset = archive.len() as u32;
    // CDE
    archive.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    archive.extend_from_slice(&20u16.to_le_bytes()); // made_by
    archive.extend_from_slice(&20u16.to_le_bytes()); // needed
    archive.extend_from_slice(&0u16.to_le_bytes()); // gp_flags
    archive.extend_from_slice(&14u16.to_le_bytes()); // method
    archive.extend_from_slice(&0u16.to_le_bytes()); // mtime
    archive.extend_from_slice(&0u16.to_le_bytes()); // mdate
    archive.extend_from_slice(&0u32.to_le_bytes()); // crc
    archive.extend_from_slice(&0u32.to_le_bytes()); // csize
    archive.extend_from_slice(&0u32.to_le_bytes()); // usize
    archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes()); // extra
    archive.extend_from_slice(&0u16.to_le_bytes()); // comment
    archive.extend_from_slice(&0u16.to_le_bytes()); // disk_start
    archive.extend_from_slice(&0u16.to_le_bytes()); // internal
    archive.extend_from_slice(&0u32.to_le_bytes()); // external
    archive.extend_from_slice(&lfh_offset.to_le_bytes());
    archive.extend_from_slice(name);
    let cd_size = archive.len() as u32 - cd_offset;
    // EOCD
    archive.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes()); // disk
    archive.extend_from_slice(&0u16.to_le_bytes()); // cd_start_disk
    archive.extend_from_slice(&1u16.to_le_bytes()); // entries_this_disk
    archive.extend_from_slice(&1u16.to_le_bytes()); // entries_total
    archive.extend_from_slice(&cd_size.to_le_bytes());
    archive.extend_from_slice(&cd_offset.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes()); // comment

    let server = MockServer::start(ok_handler(archive, Some("\"v-lzma-zip\"")));
    let work = unique_dir("zip_lzma");
    let _g = CleanupDir(work.clone());
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).unwrap();

    let args = make_args(
        &server,
        "weird.zip",
        OutputTarget::Dir(out_dir),
        coord_config_for_test(4096),
    );
    let err = run(args).expect_err("LZMA in zip must be rejected");
    // Walk the error chain looking for "LZMA" — the message lives
    // inside the wrapped EntryDecodeError → ZipError chain.
    let mut found = false;
    let top: &dyn std::error::Error = &err;
    if top.to_string().contains("LZMA") {
        found = true;
    } else {
        let mut cur = top.source();
        while let Some(s) = cur {
            if s.to_string().contains("LZMA") {
                found = true;
                break;
            }
            cur = s.source();
        }
    }
    assert!(found, "expected LZMA in error chain, got {err:?}");
}

#[test]
fn zip_resume_skips_already_extracted_entries() {
    // Build a multi-entry zip; run it once with the kill switch
    // tripping after the first entry's checkpoint write; resume and
    // verify the remaining entries land cleanly with the first
    // entry's on-disk content preserved.
    let archive = build_zip(&[
        ZipEntrySpec::stored("a.txt", b"first entry payload".to_vec()),
        ZipEntrySpec::stored("b.txt", b"second entry payload".to_vec()),
        ZipEntrySpec::stored("c.txt", b"third entry payload".to_vec()),
    ]);
    let server = MockServer::start(ok_handler(archive, Some("\"v-zip-resume\"")));

    let work = unique_dir("zip_resume");
    let _g = CleanupDir(work.clone());
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).expect("create out dir");

    // Phase 1: kill after the first checkpoint write.
    let kill_switch = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut cfg1 = coord_config_for_test(64);
    cfg1.checkpoint_min_bytes = 1; // every entry triggers a checkpoint
    cfg1.checkpoint_min_interval = Duration::from_millis(0);
    let kill_switch_inner = Arc::clone(&kill_switch);
    let mut after_first_ckpt = false;
    let args1 = RunArgs {
        url: format!("{}/release.zip", server.base_url()),
        output: OutputTarget::Dir(out_dir.clone()),
        config: cfg1,
        client: build_client(),
        registry: DecoderRegistry::with_defaults(),
        progress: Some(Box::new(move |event: ProgressEvent<'_>| {
            if let ProgressEvent::CheckpointWritten { .. } = event {
                if !after_first_ckpt {
                    after_first_ckpt = true;
                    kill_switch_inner.store(true, std::sync::atomic::Ordering::Release);
                }
            }
        }) as ProgressFn),
        progress_state: None,
        kill_switch: Some(Arc::clone(&kill_switch)),
    };
    let err = run(args1).expect_err("phase1 must abort");
    assert!(matches!(err, CoordinatorError::Aborted { .. }));
    // First entry should be on disk; checkpoint should exist.
    assert_eq!(
        fs::read(out_dir.join("a.txt")).unwrap(),
        b"first entry payload",
    );
    assert!(work.join("out.peel.ckpt").exists());

    // Phase 2: resume cleanly.
    let cfg2 = coord_config_for_test(64);
    let args2 = make_args(
        &server,
        "release.zip",
        OutputTarget::Dir(out_dir.clone()),
        cfg2,
    );
    let stats = run(args2).expect("phase2");
    assert!(stats.resumed);
    assert_eq!(
        fs::read(out_dir.join("a.txt")).unwrap(),
        b"first entry payload",
    );
    assert_eq!(
        fs::read(out_dir.join("b.txt")).unwrap(),
        b"second entry payload",
    );
    assert_eq!(
        fs::read(out_dir.join("c.txt")).unwrap(),
        b"third entry payload",
    );
    assert!(!work.join("out.peel.part").exists());
    assert!(!work.join("out.peel.ckpt").exists());
}

// ---- no decoder for filename ----------------------------------------

#[test]
fn unrecognized_suffix_returns_no_decoder() {
    let payload = b"no-decoder-here";
    let server = MockServer::start(ok_handler(payload.to_vec(), Some("\"v1\"")));

    let work = unique_dir("no_decoder");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");

    let args = make_args(
        &server,
        "datafile.unknown",
        OutputTarget::File(out_path),
        coord_config_for_test(4096),
    );
    let err = run(args).expect_err("must error");
    assert!(matches!(err, CoordinatorError::NoDecoder { .. }));
}
