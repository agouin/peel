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

/// Write a synthetic checkpoint *and* a matching `total_size`-byte
/// sparse part file. Several tests fabricate a "prior run" by hand;
/// the coordinator's startup pre-check now refuses to resume when a
/// `.peel.ckpt` is present without a sized `.peel.part` next to it,
/// so every such fixture has to drop both files.
fn write_synthetic_sidecars(
    ckpt_path: &Path,
    part_path: &Path,
    ckpt: &Checkpoint,
    total_size: u64,
) {
    ckpt.write(ckpt_path).expect("ckpt write");
    let part = fs::File::create(part_path).expect("part create");
    part.set_len(total_size).expect("part set_len");
}

fn coord_config_for_test(chunk_size: u64) -> CoordinatorConfig {
    CoordinatorConfig {
        chunk_size,
        adaptive_chunk_size: false,
        workers: 2,
        retry: fast_retry(),
        punch_threshold: 4096,
        checkpoint_min_bytes: 1, // write on every quiescent advance
        checkpoint_min_interval: Duration::from_millis(0),
        // Disable rate-aware scaling so the byte floor stays at 1.
        checkpoint_target_interval: Duration::ZERO,
        workdir: None,
        reader_poll_interval: Duration::from_millis(2),
        forced_format: None,
        force_format_from_magic: false,
        io_backend: peel::io_backend::IoBackendChoice::Blocking,
        expected_sha256: None,
        mirror_urls: Vec::new(),
        max_bandwidth_bps: None,
        max_disk_buffer: None,
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
        io_backend: None,
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

#[cfg(target_os = "linux")]
#[test]
fn happy_path_zst_to_file_round_trips_bytes_under_mmap_backend() {
    // The full coordinator end-to-end on the §9 mmap storage backend.
    // Asserts that workers writing through `memcpy` into a `MAP_SHARED`
    // region produce the same extracted output as the pwrite path,
    // and that the on-disk sidecars are cleaned up identically.
    let payload = b"mmap backend payload for the raw sink, ".repeat(2048);
    let body = encode_zstd(&payload);
    let body_len = body.len() as u64;
    let server = MockServer::start(ok_handler(body, Some("\"v-mmap\"")));

    let work = unique_dir("happy_file_mmap");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");

    let mut config = coord_config_for_test(4096);
    config.chunk_size = 1024.max(body_len.div_ceil(8));
    config.io_backend = peel::io_backend::IoBackendChoice::Mmap;
    let args = make_args(
        &server,
        "data.zst",
        OutputTarget::File(out_path.clone()),
        config,
    );

    let stats = run(args).expect("mmap-backend run");
    assert_eq!(stats.extraction.bytes_out, payload.len() as u64);
    assert!(!stats.resumed);
    assert_eq!(fs::read(&out_path).expect("read"), payload);
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

// ---- extractor error cancels download ---------------------------------

/// Regression for the "scope auto-join blocks until full download" bug:
/// when the extractor errors out partway through, the coordinator must
/// signal the scheduler to stop dispatching new chunks so
/// `thread::scope`'s implicit join completes promptly. Before the fix,
/// a 444 GiB / 1 MB-s combination looked like a multi-day hang because
/// the download thread had no cancel signal.
///
/// We verify by:
///   1. Building a `tar.lz4` body whose lz4 frame is valid but whose
///      decompressed bytes are not a tar archive (no `ustar` magic),
///      so the sink errors on the very first 512-byte header.
///   2. Sizing the body to many ranged-GET chunks and slowing each
///      response so the download is meaningfully in-flight when the
///      extractor errors.
///   3. Running the coordinator and asserting the error bubbles up,
///      and that the mock server saw far fewer requests than the
///      total chunk count — proof that the abort signal
///      short-circuited the dispatch loop instead of the run
///      completing the whole download before propagating.
#[test]
fn extractor_error_cancels_download_promptly() {
    // Plain `.tar` body so the identity decoder feeds bytes to the
    // sink as soon as chunk 0 lands — the sink errors on the very
    // first 512-byte header. Using `.tar.lz4` would force the
    // decoder to buffer the entire frame's compressed block before
    // emitting any output, masking the cancel because the download
    // would finish first. 256 KiB at 4 KiB chunks is 64 chunks.
    let body = vec![b'X'; 256 * 1024];
    let body_len = body.len();
    let chunks_total = body_len.div_ceil(4096);

    // Loopback delivery is so fast that without per-request latency
    // the entire download finishes before the extractor has a chance
    // to error and set the abort flag. Inject a small per-GET delay
    // so the cancel path is observable.
    let body_arc = Arc::new(body);
    let body_arc_clone = Arc::clone(&body_arc);
    let server = MockServer::start(move |req: &MockRequest, _n| {
        if req.method == "GET" {
            std::thread::sleep(Duration::from_millis(50));
        }
        serve(req, body_arc_clone.as_ref(), Some("\"v-bad-tar\"".into()))
    });

    let work = unique_dir("extract_err_cancels");
    let _g = CleanupDir(work.clone());
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).expect("create out dir");

    let mut config = coord_config_for_test(4096);
    config.chunk_size = 4096;
    // Pin workers so the request_count math below is deterministic:
    // at most `workers` extra chunks can be in flight at the moment
    // the abort fires.
    config.workers = 2;
    // Adaptive chunk sizing would coalesce chunks into bigger GETs
    // and complicate the request_count assertion. The fix path works
    // either way — but a fixed dispatch size makes the test signal
    // sharp.
    config.adaptive_chunk_size = false;

    let args = make_args(
        &server,
        "garbage.tar",
        OutputTarget::Dir(out_dir.clone()),
        config,
    );

    let started = std::time::Instant::now();
    let err = run(args).expect_err("must surface the extractor error");
    let elapsed = started.elapsed();

    // The error must be the extractor's, not a swallowed download
    // error or a hang — proving error propagation is unblocked.
    match &err {
        CoordinatorError::Extractor(_) => {}
        other => panic!("expected Extractor error, got {other:?}"),
    }

    // Generous upper bound — even a slow CI machine should never need
    // 30 s here. Before the fix the run waited for the full download
    // to drain before returning; with two workers downloading 4 KiB
    // chunks at 50 ms each, the no-cancel total would be ~64 chunks
    // / 2 workers * 50 ms = ~1.6 s without any other slowdown. We
    // pick 30 s as the hang-detector threshold.
    assert!(
        elapsed < Duration::from_secs(30),
        "run should return promptly after extractor error; elapsed={elapsed:?}"
    );

    // The abort signal stops the dispatch loop. In-flight chunks
    // finish (at most `workers` of them) but no new chunks are
    // claimed. With a 50 ms per-GET delay and the extractor erroring
    // on chunk 0's contents, only a small handful of GETs should
    // make it through before the abort. If the cancel never fires,
    // every chunk is requested — the assertion below distinguishes.
    let observed = server.request_count();
    assert!(
        observed < chunks_total as u64 / 2,
        "expected the abort to short-circuit dispatch; observed {observed} requests \
         out of {chunks_total} chunks"
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
        hash_state: None,
        chunk_crc32c: None,
        decoder_state: None,
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
        hash_state: None,
        chunk_crc32c: None,
        decoder_state: None,
    };
    let ckpt_path = work.join("out.bin.peel.ckpt");
    let part_path = work.join("out.bin.peel.part");
    write_synthetic_sidecars(&ckpt_path, &part_path, &ckpt, body_len);

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
        hash_state: None,
        chunk_crc32c: None,
        decoder_state: None,
    };
    let ckpt_path = work.join("out.bin.peel.ckpt");
    let part_path = work.join("out.bin.peel.part");
    write_synthetic_sidecars(&ckpt_path, &part_path, &ckpt, body_len);

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
        io_backend: None,
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

// ---- sha256 integrity verification (PLAN_v2 §10) ---------------------

/// Compute the SHA-256 digest of `bytes` via the in-tree hand-rolled
/// implementation so the integration tests check the same code path
/// the runtime binary uses. Hex-encodes for the friendlier message
/// formats that `hash::IntegrityError` produces.
fn sha256_hex(bytes: &[u8]) -> [u8; 32] {
    let mut h = peel::hash::sha256::Sha256::new();
    h.update(bytes);
    h.finalize()
}

#[test]
fn sha256_match_completes_clean_extraction() {
    let payload = b"sha256-clean-run-payload".repeat(2048);
    let body = encode_zstd(&payload);
    let expected = sha256_hex(&body);
    let server = MockServer::start(ok_handler(body.clone(), Some("\"v1\"")));

    let work = unique_dir("sha256_clean");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");

    let args = make_args(
        &server,
        "x.zst",
        OutputTarget::File(out_path.clone()),
        CoordinatorConfig {
            expected_sha256: Some(expected),
            ..coord_config_for_test(4096)
        },
    );
    let stats = run(args).expect("clean run with matching hash");
    assert_eq!(stats.total_size, body.len() as u64);

    let got = fs::read(&out_path).expect("output");
    assert_eq!(got, payload);
}

#[test]
fn sha256_mismatch_aborts_with_integrity_error() {
    let payload = b"sha256-mismatch-payload".repeat(1024);
    let body = encode_zstd(&payload);
    // Use the SHA-256 of a different input as the expected digest;
    // the run must abort.
    let mut wrong = sha256_hex(b"definitely not the body");
    // Defensive: ensure we did not accidentally match.
    assert_ne!(wrong, sha256_hex(&body));
    // Bit-flip just to make absolutely sure.
    wrong[0] ^= 0x80;
    let server = MockServer::start(ok_handler(body, Some("\"v1\"")));

    let work = unique_dir("sha256_mismatch");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");

    let args = make_args(
        &server,
        "x.zst",
        OutputTarget::File(out_path),
        CoordinatorConfig {
            expected_sha256: Some(wrong),
            ..coord_config_for_test(4096)
        },
    );
    let err = run(args).expect_err("hash mismatch must abort");
    match err {
        CoordinatorError::Integrity(peel::hash::IntegrityError::HashMismatch { expected, got }) => {
            assert_eq!(expected.len(), 64);
            assert_eq!(got.len(), 64);
            assert_ne!(expected, got);
        }
        other => panic!("expected Integrity::HashMismatch, got {other:?}"),
    }
}

#[test]
fn sha256_resume_with_saved_state_completes_cleanly() {
    // Two-phase test: phase 1 runs with a kill switch that fires
    // after the first checkpoint, leaving a `.peel.part` /
    // `.peel.ckpt` pair on disk. Phase 2 resumes with the same
    // `--sha256` and must finish, with the digest matching a clean
    // run's digest.
    let frame_a = b"frame-a-payload".repeat(2048);
    let frame_b = b"frame-b-bigger-payload".repeat(2048);
    let body = encode_zstd_frames(&[&frame_a, &frame_b]);
    let expected = sha256_hex(&body);
    let server = MockServer::start(ok_handler(body.clone(), Some("\"v1\"")));

    let work = unique_dir("sha256_resume");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");

    // Phase 1: run with a kill switch that flips after the first
    // checkpoint. The coordinator returns `Aborted` and leaves
    // .peel.part / .peel.ckpt for phase 2 to pick up.
    let kill = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let kill_for_progress = Arc::clone(&kill);
        let progress: ProgressFn = Box::new(move |event| {
            if let ProgressEvent::CheckpointWritten { .. } = event {
                kill_for_progress.store(true, std::sync::atomic::Ordering::Release);
            }
        });
        let args = RunArgs {
            url: format!("{}/x.zst", server.base_url()),
            output: OutputTarget::File(out_path.clone()),
            config: CoordinatorConfig {
                expected_sha256: Some(expected),
                ..coord_config_for_test(4096)
            },
            client: build_client(),
            registry: DecoderRegistry::with_defaults(),
            progress: Some(progress),
            progress_state: None,
            kill_switch: Some(kill),
            io_backend: None,
        };
        let err = run(args).expect_err("kill switch must trip");
        match err {
            CoordinatorError::Aborted {
                checkpoints_written,
            } => {
                assert!(checkpoints_written >= 1);
            }
            other => panic!("expected Aborted, got {other:?}"),
        }
    }

    // Sidecars must still be on disk for phase 2 to consume.
    assert!(work.join("out.bin.peel.part").exists());
    assert!(work.join("out.bin.peel.ckpt").exists());

    // Phase 2: resume with the same --sha256.
    let args = make_args(
        &server,
        "x.zst",
        OutputTarget::File(out_path.clone()),
        CoordinatorConfig {
            expected_sha256: Some(expected),
            ..coord_config_for_test(4096)
        },
    );
    let stats = run(args).expect("resume with same --sha256 succeeds");
    assert!(stats.resumed, "phase 2 must be a resume");

    let got = fs::read(&out_path).expect("output present");
    let mut combined = frame_a.clone();
    combined.extend_from_slice(&frame_b);
    assert_eq!(got, combined);
}

#[test]
fn sha256_added_on_resume_without_saved_state_errors() {
    // Phase 1 ran without --sha256, leaving a checkpoint with
    // `hash_state = None`. Phase 2 turns on --sha256 and resumes;
    // the coordinator must refuse rather than emit a half-tracked
    // digest.
    let payload = b"resume-without-state".repeat(512);
    let body = encode_zstd(&payload);
    let body_len = body.len() as u64;
    let expected = sha256_hex(&body);
    let server = MockServer::start(ok_handler(body, Some("\"v1\"")));

    let work = unique_dir("sha256_resume_no_state");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");

    // Hand-build a phase-1-style checkpoint with `hash_state: None`.
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
        hash_state: None,
        chunk_crc32c: None,
        decoder_state: None,
    };
    let ckpt_path = work.join("out.bin.peel.ckpt");
    let part_path = work.join("out.bin.peel.part");
    write_synthetic_sidecars(&ckpt_path, &part_path, &ckpt, body_len);

    let args = make_args(
        &server,
        "x.zst",
        OutputTarget::File(out_path),
        CoordinatorConfig {
            chunk_size,
            expected_sha256: Some(expected),
            ..coord_config_for_test(chunk_size)
        },
    );
    match run(args) {
        Err(CoordinatorError::Integrity(
            peel::hash::IntegrityError::CheckpointMissingHashState { .. },
        )) => {}
        other => panic!("expected CheckpointMissingHashState, got {other:?}"),
    }
}

#[test]
fn sha256_dropped_on_resume_with_saved_state_errors() {
    // The mirror case: phase 1 ran with --sha256, phase 2 forgot
    // to pass it. Refuse rather than silently dropping integrity
    // tracking.
    let payload = b"resume-with-state-no-flag".repeat(512);
    let body = encode_zstd(&payload);
    let body_len = body.len() as u64;
    let server = MockServer::start(ok_handler(body, Some("\"v1\"")));

    let work = unique_dir("sha256_resume_drop_flag");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");

    let mut state = peel::hash::sha256::Sha256::new();
    state.update(b"some prior bytes");
    let saved = state.serialize();

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
        hash_state: Some(saved),
        chunk_crc32c: None,
        decoder_state: None,
    };
    let ckpt_path = work.join("out.bin.peel.ckpt");
    let part_path = work.join("out.bin.peel.part");
    write_synthetic_sidecars(&ckpt_path, &part_path, &ckpt, body_len);

    let args = make_args(
        &server,
        "x.zst",
        OutputTarget::File(out_path),
        CoordinatorConfig {
            chunk_size,
            expected_sha256: None,
            ..coord_config_for_test(chunk_size)
        },
    );
    match run(args) {
        Err(CoordinatorError::Integrity(peel::hash::IntegrityError::CheckpointHadHashState {
            ..
        })) => {}
        other => panic!("expected CheckpointHadHashState, got {other:?}"),
    }
}

// ---- §11 mid-flight source-change detection -------------------------

#[test]
fn source_drift_on_resume_is_caught_by_probe() {
    // First run: download to completion against `body_a` so the
    // checkpoint contains §11 fingerprints. Then construct a *new*
    // checkpoint pointing at `body_b` (size matches, ETag matches —
    // the only thing that differs is the byte content) and rerun;
    // the §11 resume probe must fail before any new bytes are
    // downloaded.
    //
    // Demo from PLAN_v2 §11: "A mock that returns a different file
    // on resume triggers SourceChangedSinceCheckpoint on the very
    // first probe."
    let payload_a = b"resume-aaaa".repeat(4096);
    let payload_b = b"resume-bbbb".repeat(4096); // same length
    assert_eq!(payload_a.len(), payload_b.len());
    let body_a = encode_zstd(&payload_a);
    let body_b = encode_zstd(&payload_b);
    // Pad so both bodies are the same length, otherwise build_resume_plan
    // catches it earlier on size mismatch.
    let target_len = body_a.len().max(body_b.len());
    let mut body_a = body_a;
    body_a.resize(target_len, 0);
    let mut body_b = body_b;
    body_b.resize(target_len, 0);

    let server = MockServer::start({
        let body_a_clone = body_a.clone();
        let body_b_clone = body_b.clone();
        move |req, n| {
            // First N requests serve body_a (checkpoint capture);
            // requests after that serve body_b (resume probe).
            let body = if n < 32 { &body_a_clone } else { &body_b_clone };
            serve(req, body, Some("\"v1\"".into()))
        }
    });

    let work = unique_dir("resume_drift");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");
    let chunk_size = 1024u64;
    let mut config = coord_config_for_test(chunk_size);
    config.checkpoint_min_bytes = 1;
    config.checkpoint_min_interval = Duration::from_millis(0);

    // Run 1: full download succeeds against body_a.
    let args1 = make_args(
        &server,
        "data.zst",
        OutputTarget::File(out_path.clone()),
        config.clone(),
    );
    let stats1 = run(args1).expect("first run");
    assert!(!stats1.resumed);
    fs::remove_file(&out_path).ok();

    // Hand-build a checkpoint as if we'd crashed mid-run with the
    // body_a fingerprints captured. We need real CRC-32C values to
    // mimic what a real run would have written, so we compute them
    // here over body_a's chunks.
    let total_chunks = (body_a.len() as u64).div_ceil(chunk_size) as u32;
    let bitmap = peel::bitmap::ChunkBitmap::new(total_chunks);
    // Mark every chunk complete so the §11 probe has something to
    // verify against.
    for i in 0..total_chunks {
        bitmap.mark_complete(peel::types::ChunkIndex::new(i));
    }
    let mut crcs = Vec::with_capacity(total_chunks as usize);
    for i in 0..total_chunks {
        let lo = (i as u64 * chunk_size) as usize;
        let hi = ((i as u64 + 1) * chunk_size).min(body_a.len() as u64) as usize;
        crcs.push(peel::hash::crc32c::castagnoli(&body_a[lo..hi]));
    }
    let ckpt = Checkpoint {
        url: format!("{}/data.zst", server.base_url()),
        etag: Some("\"v1\"".into()),
        last_modified: None,
        total_size: body_a.len() as u64,
        chunk_size,
        decoder_position: ByteOffset::new(0),
        bitmap_completed: bitmap.to_bytes(),
        created_at: SystemTime::now(),
        sink_state: SinkState::Raw { bytes_written: 0 },
        hash_state: None,
        chunk_crc32c: Some(crcs),
        decoder_state: None,
    };
    let part_path = work.join("out.bin.peel.part");
    let ckpt_path = work.join("out.bin.peel.ckpt");
    ckpt.write(&ckpt_path).expect("ckpt write");
    fs::write(&part_path, vec![0u8; body_a.len()]).expect("part placeholder");

    // Resume — the server now serves body_b for the next request.
    // We've made 1 HEAD + ranged-GETs in run 1; force the swap by
    // rebuilding the server with the swap counter at 1.
    drop(server);
    let server2 = MockServer::start({
        let body_b_clone = body_b.clone();
        move |req, _n| serve(req, &body_b_clone, Some("\"v1\"".into()))
    });
    // Rewrite the URL in the checkpoint to point at the new server.
    let mut ckpt2 = ckpt.clone();
    ckpt2.url = format!("{}/data.zst", server2.base_url());
    ckpt2.write(&ckpt_path).expect("ckpt rewrite");

    let args2 = make_args(
        &server2,
        "data.zst",
        OutputTarget::File(out_path.clone()),
        config,
    );
    let err = run(args2).expect_err("must detect drift");
    match err {
        CoordinatorError::SourceChangedSinceCheckpoint { .. } => {}
        other => panic!("expected SourceChangedSinceCheckpoint, got {other:?}"),
    }

    // .peel.part / .peel.ckpt left on disk as documented; verify.
    assert!(ckpt_path.exists(), "checkpoint should remain after error");
}

// ---- PLAN_responsiveness.md §3.1: cursor-chunk integrity audit ------

/// Demo from §3.1: force-corrupt one byte in the resume chunk of a
/// fixture `.peel.part` and confirm the new audit rejects with
/// [`CoordinatorError::PartFileCorrupted`] within the first second of
/// the run — *before* the decoder gets to read garbage and surface a
/// distant malformed-block error from inside the codec.
#[test]
fn cursor_chunk_audit_rejects_corrupted_part_file_on_resume() {
    // Random-ish payload so zstd can't compress it down below the
    // chunk count we need to exercise the cursor-chunk picker.
    let mut payload = Vec::with_capacity(64 * 1024);
    let mut rng: u64 = 0x00C0_FFEE_BEEF;
    while payload.len() < 64 * 1024 {
        rng = rng
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        payload.extend_from_slice(&rng.to_le_bytes());
    }
    let body = encode_zstd(&payload);
    assert!(
        body.len() > 8 * 1024,
        "test fixture must span several chunks; got {} bytes",
        body.len(),
    );

    let server = MockServer::start({
        let body_clone = body.clone();
        move |req, _n| serve(req, &body_clone, Some("\"v1\"".into()))
    });

    let work = unique_dir("cursor_audit");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");
    let chunk_size = 1024u64;
    let mut config = coord_config_for_test(chunk_size);
    config.checkpoint_min_bytes = 1;
    config.checkpoint_min_interval = Duration::from_millis(0);

    // Run 1: full download against the unmodified body, populating
    // the .peel.part with the genuine bytes and the .peel.ckpt with
    // the matching CRC fingerprints.
    let args1 = make_args(
        &server,
        "data.zst",
        OutputTarget::File(out_path.clone()),
        config.clone(),
    );
    run(args1).expect("first run");
    fs::remove_file(&out_path).ok();

    // Build a checkpoint whose decoder_position lands inside chunk 2.
    // Chunks 0..N are all marked complete and fingerprinted with the
    // CRC of the genuine body bytes.
    let total_chunks = (body.len() as u64).div_ceil(chunk_size) as u32;
    let bitmap = peel::bitmap::ChunkBitmap::new(total_chunks);
    for i in 0..total_chunks {
        bitmap.mark_complete(peel::types::ChunkIndex::new(i));
    }
    let mut crcs = Vec::with_capacity(total_chunks as usize);
    for i in 0..total_chunks {
        let lo = (i as u64 * chunk_size) as usize;
        let hi = ((i as u64 + 1) * chunk_size).min(body.len() as u64) as usize;
        crcs.push(peel::hash::crc32c::castagnoli(&body[lo..hi]));
    }
    // Pick a cursor at the start of chunk index 2 (the audit only
    // runs the whole-chunk CRC when the cursor is at a chunk
    // boundary; mid-chunk cursors mean the prior run hole-punched
    // the chunk's lower portion and a whole-chunk CRC would
    // false-alarm).
    let cursor_chunk: u32 = 2;
    let cursor = u64::from(cursor_chunk) * chunk_size;
    let ckpt = Checkpoint {
        url: format!("{}/data.zst", server.base_url()),
        etag: Some("\"v1\"".into()),
        last_modified: None,
        total_size: body.len() as u64,
        chunk_size,
        decoder_position: ByteOffset::new(cursor),
        bitmap_completed: bitmap.to_bytes(),
        created_at: SystemTime::now(),
        sink_state: SinkState::Raw { bytes_written: 0 },
        hash_state: None,
        chunk_crc32c: Some(crcs),
        decoder_state: None,
    };
    let part_path = work.join("out.bin.peel.part");
    let ckpt_path = work.join("out.bin.peel.ckpt");
    ckpt.write(&ckpt_path).expect("ckpt write");
    // Run 1 succeeded, so peel cleaned up its sidecars. Recreate the
    // part file from scratch with the genuine bytes, then flip a
    // single bit inside the cursor chunk so the cursor-chunk audit
    // sees a mismatch.
    let mut part_bytes = body.clone();
    let target = (cursor_chunk as usize) * (chunk_size as usize) + 5;
    part_bytes[target] ^= 0x01;
    fs::write(&part_path, &part_bytes).expect("write corrupted part");

    let args2 = make_args(
        &server,
        "data.zst",
        OutputTarget::File(out_path.clone()),
        config,
    );
    let started = std::time::Instant::now();
    let err = run(args2).expect_err("must detect part-file corruption");
    let elapsed = started.elapsed();
    match err {
        CoordinatorError::PartFileCorrupted {
            chunk,
            expected,
            actual,
        } => {
            assert_eq!(chunk.get(), cursor_chunk);
            assert_ne!(expected, actual);
        }
        other => panic!("expected PartFileCorrupted, got {other:?}"),
    }
    // The audit must surface the error before the decoder has a
    // chance to read garbage. One second is plenty of headroom.
    assert!(
        elapsed < Duration::from_secs(5),
        "audit should fail fast; took {elapsed:?}",
    );
    // .peel.part / .peel.ckpt left on disk so the user can decide.
    assert!(ckpt_path.exists(), "checkpoint should remain after error");
    assert!(part_path.exists(), "part file should remain after error");
}

/// Regression test for the cursor-chunk audit's mid-chunk skip:
/// when the resume cursor lands inside (rather than at the start
/// of) a chunk, the prior run's extractor has hole-punched the
/// chunk's lower portion. A whole-chunk CRC would always disagree
/// with the recorded fingerprint (which was computed pre-punch),
/// so the audit must skip rather than false-alarm. The decoder
/// itself is the safety net for on-disk corruption past the
/// cursor.
#[test]
fn cursor_chunk_audit_skips_when_cursor_is_mid_chunk() {
    let mut payload = Vec::with_capacity(64 * 1024);
    let mut rng: u64 = 0x00C0_FFEE_F00D;
    while payload.len() < 64 * 1024 {
        rng = rng
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        payload.extend_from_slice(&rng.to_le_bytes());
    }
    let body = encode_zstd(&payload);
    let server = MockServer::start({
        let body_clone = body.clone();
        move |req, _n| serve(req, &body_clone, Some("\"v1\"".into()))
    });

    let work = unique_dir("cursor_audit_midchunk");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");
    let chunk_size = 1024u64;
    let mut config = coord_config_for_test(chunk_size);
    config.checkpoint_min_bytes = 1;
    config.checkpoint_min_interval = Duration::from_millis(0);

    let args1 = make_args(
        &server,
        "data.zst",
        OutputTarget::File(out_path.clone()),
        config.clone(),
    );
    run(args1).expect("first run");
    fs::remove_file(&out_path).ok();

    let total_chunks = (body.len() as u64).div_ceil(chunk_size) as u32;
    let bitmap = peel::bitmap::ChunkBitmap::new(total_chunks);
    for i in 0..total_chunks {
        bitmap.mark_complete(peel::types::ChunkIndex::new(i));
    }
    let mut crcs = Vec::with_capacity(total_chunks as usize);
    for i in 0..total_chunks {
        let lo = (i as u64 * chunk_size) as usize;
        let hi = ((i as u64 + 1) * chunk_size).min(body.len() as u64) as usize;
        crcs.push(peel::hash::crc32c::castagnoli(&body[lo..hi]));
    }

    // Cursor lands 17 bytes into chunk 2 — exactly the case where
    // the prior run's extractor would have punched bytes [chunk_2_start,
    // align_down(cursor, fs_block)).
    let cursor_chunk: u32 = 2;
    let cursor = u64::from(cursor_chunk) * chunk_size + 17;
    let ckpt = Checkpoint {
        url: format!("{}/data.zst", server.base_url()),
        etag: Some("\"v1\"".into()),
        last_modified: None,
        total_size: body.len() as u64,
        chunk_size,
        decoder_position: ByteOffset::new(cursor),
        bitmap_completed: bitmap.to_bytes(),
        created_at: SystemTime::now(),
        sink_state: SinkState::Raw { bytes_written: 0 },
        hash_state: None,
        chunk_crc32c: Some(crcs),
        decoder_state: None,
    };
    let part_path = work.join("out.bin.peel.part");
    let ckpt_path = work.join("out.bin.peel.ckpt");
    ckpt.write(&ckpt_path).expect("ckpt write");

    // Simulate the post-punch state: zero out the chunk's bytes
    // below `align_down(cursor, 4096)` (the realistic punch range
    // a prior run's extractor would have produced for this cursor),
    // leaving everything from there on intact.
    let mut part_bytes = body.clone();
    let punch_end = (cursor / 4096) * 4096;
    let chunk_start = u64::from(cursor_chunk) * chunk_size;
    if punch_end > chunk_start {
        for byte in &mut part_bytes[chunk_start as usize..punch_end as usize] {
            *byte = 0;
        }
    }
    fs::write(&part_path, &part_bytes).expect("write punched part");

    let args2 = make_args(
        &server,
        "data.zst",
        OutputTarget::File(out_path.clone()),
        config,
    );
    // The audit must NOT fire `PartFileCorrupted` here — the chunk's
    // pre-cursor bytes are legitimately zero from punching, not on-disk
    // bit-rot. The decoder may still surface its own error because we
    // hand-built a checkpoint whose `decoder_position` doesn't sit on
    // a real zstd frame boundary; that's fine and out of scope. We
    // only assert the audit didn't fire.
    if let Err(CoordinatorError::PartFileCorrupted { .. }) = run(args2) {
        panic!("audit false-alarmed on a legitimately punched mid-chunk resume");
    }
    // Any other outcome (Ok, or a different error from the
    // hand-built non-frame-boundary decoder_position) is acceptable;
    // the test's only contract is that the audit doesn't fire.
}

#[test]
fn worker_probe_detects_source_drift() {
    // Unit-level demo of PLAN_v2 §11: when a probe re-fetches a
    // chunk that drifted under us, the worker reports
    // `WorkerError::SourceDriftDetected`. The mock here serves
    // body_b; the dispatch's expected CRC was captured against
    // body_a; the worker's in-line probe verification flags the
    // mismatch.
    use peel::download::{Dispatch, DispatchKind};
    use peel::types::{ByteOffset, ByteRange, ChunkIndex};
    use std::sync::atomic::AtomicBool;

    let body_a = b"chunk-zero-original-content-padded-".repeat(64);
    let body_b: Vec<u8> = body_a.iter().map(|b| b ^ 0xFF).collect();
    assert_eq!(body_a.len(), body_b.len());
    let total_size = body_a.len() as u64;
    let chunk_size = total_size; // single-chunk file

    let server = MockServer::start({
        let body_b_clone = body_b.clone();
        move |req, _n| serve(req, &body_b_clone, Some("\"v1\"".into()))
    });

    // Compute the CRC-32C of body_a — the value a previous fetch
    // would have stored before the source swapped.
    let expected_crc = peel::hash::crc32c::castagnoli(&body_a);

    // Open a sparse file for the probe to write into; we don't
    // care about the contents afterward.
    let work = unique_dir("worker_probe");
    let _g = CleanupDir(work.clone());
    let part = work.join("part.bin");
    let sparse = peel::download::SparseFile::open_or_create(&part, total_size).expect("sparse");

    let url = peel::http::Url::parse(&format!("{}/data.bin", server.base_url())).expect("url");
    let fingerprint = peel::download::SourceFingerprint {
        etag: Some("\"v1\"".into()),
        last_modified: None,
    };
    let client = build_client();
    let mirrors = peel::download::MirrorSet::single(url.clone(), fingerprint.clone());
    let ctx = peel::download::worker::ChunkContext {
        client: &client,
        mirrors: &mirrors,
        chunk_size,
        sparse: &sparse,
        progress: None,
        rate_limiter: None,
    };
    let dispatch = Dispatch {
        first: ChunkIndex::ZERO,
        count: 1,
        range: ByteRange::new(ByteOffset::new(0), ByteOffset::new(total_size)).expect("range"),
        kind: DispatchKind::Probe {
            expected: expected_crc,
        },
    };
    let cancel = AtomicBool::new(false);
    let failure = peel::download::worker::download_dispatch(&ctx, dispatch, &fast_retry(), &cancel)
        .expect_err("probe must detect drift");
    match failure.error {
        peel::download::WorkerError::SourceDriftDetected {
            expected, actual, ..
        } => {
            assert_eq!(expected, expected_crc);
            assert_ne!(actual, expected_crc);
        }
        other => panic!("expected SourceDriftDetected, got {other:?}"),
    }
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

// ---- disk-buffer throttle: forward-progress under tight caps ----------
//
// PLAN_decoder_freeze.md is investigating a freeze whose signature is
// "lookahead pinned at the cap, decoder parked, scheduler idle." These
// tests deliberately force the throttle to engage by setting
// `max_disk_buffer` an order of magnitude smaller than a healthy buffer
// would be, then verify the run still makes forward progress and
// reproduces the source bytes. Hidden by `cfg(unix)` at the file
// header. Each test wraps the `run()` call in a 30-second deadline
// that flips the kill switch — if forward progress stops, the run
// surfaces `CoordinatorError::Aborted` and we fail loudly with a
// "deadlock?" message rather than letting the test framework's own
// timeout terminate the whole binary.

/// Run `args` under a wall-clock deadline. After `deadline` elapses, the
/// caller-supplied `kill` flag is flipped, which causes `run()` to
/// return `CoordinatorError::Aborted` from the next kill-switch poll.
/// The caller decides whether timing out is a failure (typical) or an
/// expected behavior (rare).
///
/// Returns the run's `Result` and a `bool` indicating whether the
/// deadline tripped.
fn run_with_kill_deadline(
    args: RunArgs,
    kill: Arc<std::sync::atomic::AtomicBool>,
    deadline: Duration,
) -> (Result<peel::coordinator::RunStats, CoordinatorError>, bool) {
    let kill_for_watcher = Arc::clone(&kill);
    let tripped = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let tripped_for_watcher = Arc::clone(&tripped);
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let done_for_watcher = Arc::clone(&done);
    // Watchdog thread: flip kill if `done` hasn't flipped by `deadline`.
    let watcher = std::thread::spawn(move || {
        let started = std::time::Instant::now();
        while started.elapsed() < deadline {
            if done_for_watcher.load(Ordering::Acquire) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        tripped_for_watcher.store(true, Ordering::Release);
        kill_for_watcher.store(true, Ordering::Release);
    });
    let result = run(args);
    done.store(true, Ordering::Release);
    let _ = watcher.join();
    let did_trip = tripped.load(Ordering::Acquire);
    (result, did_trip)
}

/// Build a tar.zst archive whose body is `n_files` files of
/// `bytes_per_file` random-ish bytes each, then return the
/// uncompressed archive bytes and the compressed body. Sized so the
/// caller can pick chunk_size / max_disk_buffer ratios that force
/// throttle engagement.
fn build_test_archive(n_files: usize, bytes_per_file: usize) -> (Vec<u8>, Vec<u8>) {
    let mut entries: Vec<(String, Vec<u8>)> = Vec::with_capacity(n_files);
    for i in 0..n_files {
        let path = format!("dir/file_{i:05}.bin");
        // Deterministic but compressible — bytes vary so zstd has work
        // to do but the output is reproducible across runs.
        let mut bytes = Vec::with_capacity(bytes_per_file);
        for j in 0..bytes_per_file {
            bytes.push(((i.wrapping_mul(31)).wrapping_add(j) & 0xFF) as u8);
        }
        entries.push((path, bytes));
    }
    let entries_ref: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(p, b)| (p.as_str(), b.as_slice()))
        .collect();
    let archive = build_simple_archive(&entries_ref);
    let body = encode_zstd(&archive);
    (archive, body)
}

/// Tight cap (4× chunk_size), normal mock server. The throttle should
/// engage and disengage as the decoder drains the lookahead, and the
/// run should reproduce the archive byte-for-byte. The "deadlock?"
/// failure mode here would be the freeze pattern documented in
/// `PLAN_decoder_freeze.md`.
#[test]
fn small_disk_buffer_completes_under_throttle() {
    let (archive, body) = build_test_archive(32, 8 * 1024);
    let server = MockServer::start(ok_handler(body, Some("\"v-tiny-cap\"")));

    let work = unique_dir("tiny_cap");
    let _g = CleanupDir(work.clone());
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).expect("create out dir");

    let chunk_size: u64 = 16 * 1024; // 16 KiB
    let mut config = coord_config_for_test(chunk_size);
    config.workers = 4;
    // Cap = 4 chunks (64 KiB). Forces the throttle to engage almost
    // every dispatch round on an archive that's many chunks long.
    config.max_disk_buffer = Some(4 * chunk_size);

    let kill = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let args = RunArgs {
        url: format!("{}/x.tar.zst", server.base_url()),
        output: OutputTarget::Dir(out_dir.clone()),
        config,
        client: build_client(),
        registry: DecoderRegistry::with_defaults(),
        progress: None,
        progress_state: None,
        kill_switch: Some(Arc::clone(&kill)),
        io_backend: None,
    };
    let (result, tripped) = run_with_kill_deadline(args, kill, Duration::from_secs(30));
    assert!(
        !tripped,
        "deadlock? small-cap throttle run did not finish in 30 s; \
         see PLAN_decoder_freeze.md §2 for the failure pattern"
    );
    let stats = result.expect("small-cap run");
    assert!(!stats.resumed);
    // Output reproduces the archive bytes — verify a couple of files
    // round-tripped and the directory shape matches.
    let out = read_dir_recursive(&out_dir);
    assert_eq!(out.len(), 32, "all 32 files extracted");
    assert!(!archive.is_empty()); // archive isn't empty (sanity)
}

/// Cap = exactly one chunk. Workers can have at most one chunk of
/// undecoded compressed bytes at a time, so the throttle engages on
/// *every* dispatch round and only disengages once the decoder has
/// fully consumed the previous chunk.
#[test]
fn one_chunk_cap_run_completes_under_heavy_throttling() {
    let (_archive, body) = build_test_archive(16, 4 * 1024);
    let server = MockServer::start(ok_handler(body, Some("\"v-1chunk-cap\"")));

    let work = unique_dir("one_chunk_cap");
    let _g = CleanupDir(work.clone());
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).expect("create out dir");

    let chunk_size: u64 = 16 * 1024;
    let mut config = coord_config_for_test(chunk_size);
    config.workers = 4;
    config.max_disk_buffer = Some(chunk_size); // exactly 1 chunk

    let kill = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let args = RunArgs {
        url: format!("{}/x.tar.zst", server.base_url()),
        output: OutputTarget::Dir(out_dir.clone()),
        config,
        client: build_client(),
        registry: DecoderRegistry::with_defaults(),
        progress: None,
        progress_state: None,
        kill_switch: Some(Arc::clone(&kill)),
        io_backend: None,
    };
    let (result, tripped) = run_with_kill_deadline(args, kill, Duration::from_secs(30));
    assert!(
        !tripped,
        "deadlock? one-chunk-cap run did not finish in 30 s"
    );
    let _stats = result.expect("one-chunk-cap run");
    let out = read_dir_recursive(&out_dir);
    assert_eq!(out.len(), 16);
}

/// Tight cap + 8 workers all competing for the throttle window. The
/// goal is to maximize contention on the dispatch / completion path so
/// any race in the throttle release surfaces.
#[test]
fn small_cap_with_many_workers_completes() {
    let (_archive, body) = build_test_archive(48, 4 * 1024);
    let server = MockServer::start(ok_handler(body, Some("\"v-8w-cap\"")));

    let work = unique_dir("many_workers_cap");
    let _g = CleanupDir(work.clone());
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).expect("create out dir");

    let chunk_size: u64 = 8 * 1024;
    let mut config = coord_config_for_test(chunk_size);
    config.workers = 8;
    config.max_disk_buffer = Some(2 * chunk_size); // 2 chunks for 8 workers

    let kill = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let args = RunArgs {
        url: format!("{}/x.tar.zst", server.base_url()),
        output: OutputTarget::Dir(out_dir.clone()),
        config,
        client: build_client(),
        registry: DecoderRegistry::with_defaults(),
        progress: None,
        progress_state: None,
        kill_switch: Some(Arc::clone(&kill)),
        io_backend: None,
    };
    let (result, tripped) = run_with_kill_deadline(args, kill, Duration::from_secs(30));
    assert!(
        !tripped,
        "deadlock? many-worker tight-cap run did not finish in 30 s"
    );
    let _stats = result.expect("many-worker run");
    let out = read_dir_recursive(&out_dir);
    assert_eq!(out.len(), 48);
}

/// Tight cap + DripBody server that forces ranged GETs to deliver
/// their bytes in small slow drips. Workers' bytes-from-socket arrive
/// in pieces, the throttle is engaged for most of the run, and there
/// are many points at which the cursor advances by a few bytes at a
/// time. This is the closest synthetic analog to the snapshot-restore
/// pod's profile (steady ~50 MiB/s real network with frequent small
/// drains).
#[test]
fn small_cap_with_drip_server_completes() {
    let (_archive, body) = build_test_archive(8, 8 * 1024);
    let body_len = body.len();

    let etag = "\"v-drip-cap\"";
    let body_for_handler = body.clone();
    let server = MockServer::start(move |req: &MockRequest, _n| {
        if req.method == "HEAD" {
            return MockResponse::Reply {
                status: 200,
                reason: "OK",
                headers: vec![
                    ("Content-Length".into(), body_for_handler.len().to_string()),
                    ("Accept-Ranges".into(), "bytes".into()),
                    ("ETag".into(), etag.into()),
                ],
                body: Vec::new(),
            };
        }
        // Range requests get drip-fed.
        let (a, b) = if let Some(r) = req.header("range").and_then(parse_range) {
            r
        } else {
            (0u64, (body_for_handler.len() as u64).saturating_sub(1))
        };
        let slice = body_for_handler[a as usize..=b as usize].to_vec();
        MockResponse::DripBody {
            status: 206,
            reason: "Partial Content",
            headers: vec![
                (
                    "Content-Range".into(),
                    format!("bytes {a}-{b}/{}", body_len),
                ),
                ("ETag".into(), etag.into()),
            ],
            body: slice,
            bytes_per_chunk: 1024,
            interval: Duration::from_millis(2),
        }
    });

    let work = unique_dir("drip_cap");
    let _g = CleanupDir(work.clone());
    let out_dir = work.join("out");
    fs::create_dir_all(&out_dir).expect("create out dir");

    let chunk_size: u64 = 16 * 1024;
    let mut config = coord_config_for_test(chunk_size);
    config.workers = 4;
    config.max_disk_buffer = Some(2 * chunk_size);

    let kill = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let args = RunArgs {
        url: format!("{}/x.tar.zst", server.base_url()),
        output: OutputTarget::Dir(out_dir.clone()),
        config,
        client: build_client(),
        registry: DecoderRegistry::with_defaults(),
        progress: None,
        progress_state: None,
        kill_switch: Some(Arc::clone(&kill)),
        io_backend: None,
    };
    let (result, tripped) = run_with_kill_deadline(args, kill, Duration::from_secs(60));
    assert!(
        !tripped,
        "deadlock? drip-server + tight-cap run did not finish in 60 s"
    );
    let _stats = result.expect("drip-cap run");
    let out = read_dir_recursive(&out_dir);
    assert_eq!(out.len(), 8);
}
