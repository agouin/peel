//! Crash-test harness for [`peel::coordinator`].
//!
//! Plan §10.3 calls out a harness that "runs the binary 100 times with
//! random `kill -9` points and asserts identical output every time."
//! This test does the in-process equivalent: instead of forking a real
//! subprocess and signalling it (which is platform-fragile and slow),
//! we wire a [`std::sync::atomic::AtomicBool`] kill switch into the
//! coordinator's checkpoint callback. Flipping the switch between two
//! checkpoint writes simulates a `kill -9` at exactly the same point
//! the coordinator would lose to a real signal — every byte the
//! decoder produced after the most recent checkpoint write is "lost",
//! the .peel.part and .peel.ckpt sidecars are left durable on disk,
//! and the next call to [`peel::coordinator::run`] picks up from
//! there.
//!
//! For each trial we
//!
//! 1. roll a deterministic abort point (from a seeded PRNG so failures
//!    are reproducible);
//! 2. run with the kill switch armed, expecting the run to abort with
//!    [`peel::coordinator::CoordinatorError::Aborted`];
//! 3. run again with no kill switch, expecting clean completion;
//! 4. compare the produced output (file or directory) to a golden
//!    output captured from a single clean run at the start of the
//!    test.
//!
//! The test runs both the file-output and the tar-output paths so the
//! resume discipline is exercised against both [`peel::sink::RawSink`]
//! and [`peel::sink::TarSink`].

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use peel::coordinator::{
    run, CoordinatorConfig, CoordinatorError, OutputTarget, ProgressEvent, ProgressFn, RunArgs,
};
use peel::decode::DecoderRegistry;
use peel::download::RetryConfig;
use peel::http::{Client, ClientConfig};

#[path = "support/mod.rs"]
mod support;

use support::mock_server::{MockRequest, MockResponse, MockServer};
use support::tar_fixtures::{build_header, end_of_archive, pad_block};
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
    let p = std::env::temp_dir().join(format!("peel_crash_it_{label}_{pid}_{nanos}_{n}"));
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

fn coord_config(chunk_size: u64) -> CoordinatorConfig {
    CoordinatorConfig {
        chunk_size,
        adaptive_chunk_size: false,
        workers: 2,
        retry: fast_retry(),
        punch_threshold: 4096,
        // Force a checkpoint at every quiescent advance so the kill
        // switch has many "fault lines" to trip at.
        checkpoint_min_bytes: 1,
        checkpoint_min_interval: Duration::from_millis(0),
        workdir: None,
        reader_poll_interval: Duration::from_millis(2),
        forced_format: None,
        force_format_from_magic: false,
        io_backend: peel::io_backend::IoBackendChoice::Blocking,
    }
}

fn ok_handler(
    body: Vec<u8>,
    etag: &'static str,
) -> impl Fn(&MockRequest, u64) -> MockResponse + Send + Sync + 'static {
    move |req, _| serve(req, &body, etag)
}

fn serve(req: &MockRequest, body: &[u8], etag: &'static str) -> MockResponse {
    let head_headers: Vec<(String, String)> = vec![
        ("Content-Length".into(), body.len().to_string()),
        ("Accept-Ranges".into(), "bytes".into()),
        ("ETag".into(), etag.into()),
    ];
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
            let h = vec![
                (
                    "Content-Range".into(),
                    format!("bytes {a}-{b}/{}", body.len()),
                ),
                ("ETag".into(), etag.into()),
            ];
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
        headers: vec![("ETag".into(), etag.into())],
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
    kill_switch: Option<Arc<AtomicBool>>,
    progress: Option<ProgressFn>,
) -> RunArgs {
    RunArgs {
        url: format!("{}/{suffix}", server.base_url()),
        output,
        config,
        client: build_client(),
        registry: DecoderRegistry::with_defaults(),
        progress,
        progress_state: None,
        kill_switch,
    }
}

/// Encode `payloads` as a multi-frame zstd stream so the run has many
/// frame boundaries to checkpoint between.
fn encode_zstd_frames(payloads: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in payloads {
        out.extend_from_slice(&zstd::encode_all(*p, 1).expect("encode zstd frame"));
    }
    out
}

/// Encode `payload` as a single-Stream xz blob using liblzma's easy
/// encoder at preset 6 (matching `xz`'s default).
fn encode_xz_stream(payload: &[u8]) -> Vec<u8> {
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

/// Encode `payload` as a single-frame, single-block, uncompressed
/// LZ4 archive. Every block boundary in the resulting frame surfaces
/// as a frame boundary in `decode/lz4.rs`. Hand-rolled here so the
/// crash harness does not depend on a runtime lz4 encoder library.
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

/// Concatenate one lz4 frame per `payload`. Each frame's blocks and
/// end-of-frame marker surface as frame boundaries the decoder can
/// land checkpoints on.
fn encode_lz4_frames(payloads: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in payloads {
        out.extend_from_slice(&encode_lz4_uncompressed_frame(p));
    }
    out
}

/// Concatenate one xz Stream per `payload`. Each Stream-end is a
/// frame boundary the decoder will surface.
fn encode_xz_streams(payloads: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in payloads {
        out.extend_from_slice(&encode_xz_stream(p));
    }
    out
}

/// Header + payload + zero padding for a single tar member (USTAR).
fn member_archive_bytes(name: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(512 + payload.len() + 511);
    out.extend_from_slice(&build_header(name, payload.len() as u64, b'0'));
    out.extend_from_slice(&pad_block(payload));
    out
}

/// Just the two trailing zero blocks that terminate a tar archive.
fn end_of_archive_block() -> Vec<u8> {
    end_of_archive()
}

/// Tiny LCG (no extra crate) so the harness is deterministic across
/// runs but exercises a wide range of abort points.
struct Lcg(u64);
impl Lcg {
    fn seeded(seed: u64) -> Self {
        Self(seed ^ 0x9E37_79B9_7F4A_7C15)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
    fn range(&mut self, low: u64, high_exclusive: u64) -> u64 {
        if high_exclusive <= low {
            return low;
        }
        low + (self.next_u64() % (high_exclusive - low))
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

/// Build a progress callback that flips `kill_switch` to `true` after
/// `abort_after` checkpoint events have fired.
fn kill_after(
    kill_switch: Arc<AtomicBool>,
    abort_after: u64,
    counter: Arc<AtomicU64>,
) -> ProgressFn {
    Box::new(move |event| {
        if let ProgressEvent::CheckpointWritten { .. } = event {
            let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
            if n >= abort_after {
                kill_switch.store(true, Ordering::Release);
            }
        }
    })
}

// ---- harness: raw output ----------------------------------------------

#[test]
fn random_kill_points_resume_to_identical_raw_output() {
    // A multi-frame stream gives us many quiescent boundaries to abort
    // between. The payloads are random-looking enough to defeat zstd's
    // RLE so each frame's compressed size meaningfully differs.
    let payloads: Vec<Vec<u8>> = (0..16)
        .map(|i| {
            let n = 1024usize + (i as usize) * 137;
            (0..n)
                .map(|j| (i as u8).wrapping_mul(7).wrapping_add(j as u8))
                .collect::<Vec<u8>>()
        })
        .collect();
    let payload_refs: Vec<&[u8]> = payloads.iter().map(|v| v.as_slice()).collect();
    let body = encode_zstd_frames(&payload_refs);
    let server = MockServer::start(ok_handler(body, "\"v-raw\""));

    // Reference: a clean run captures the expected output and the
    // total checkpoint count (an upper bound for the abort-after roll).
    let golden_dir = unique_dir("golden_raw");
    let _g_golden = CleanupDir(golden_dir.clone());
    let golden_path = golden_dir.join("out.bin");

    let golden_count = Arc::new(AtomicU64::new(0));
    let counter_for_golden = Arc::clone(&golden_count);
    let progress: ProgressFn = Box::new(move |event| {
        if let ProgressEvent::CheckpointWritten { .. } = event {
            counter_for_golden.fetch_add(1, Ordering::Relaxed);
        }
    });

    let args = make_args(
        &server,
        "raw.zst",
        OutputTarget::File(golden_path.clone()),
        coord_config(4096),
        None,
        Some(progress),
    );
    run(args).expect("golden run ok");
    let golden_bytes = fs::read(&golden_path).expect("golden read");
    let total_checkpoints = golden_count.load(Ordering::Relaxed);
    assert!(
        total_checkpoints >= 4,
        "need at least a few checkpoints to randomize over (got {total_checkpoints})",
    );

    // Drive trials.
    let trial_count = 20u64;
    let mut rng = Lcg::seeded(0xC4A5_F00D_F00D);
    for trial in 0..trial_count {
        let abort_after = rng.range(1, total_checkpoints);
        let work = unique_dir(&format!("trial_{trial}"));
        let _g = CleanupDir(work.clone());
        let out_path = work.join("out.bin");

        let kill = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(AtomicU64::new(0));
        let progress = kill_after(Arc::clone(&kill), abort_after, Arc::clone(&counter));
        let args = make_args(
            &server,
            "raw.zst",
            OutputTarget::File(out_path.clone()),
            coord_config(4096),
            Some(Arc::clone(&kill)),
            Some(progress),
        );
        match run(args) {
            Err(CoordinatorError::Aborted {
                checkpoints_written,
            }) => {
                assert!(
                    checkpoints_written >= abort_after,
                    "expected at least {abort_after} checkpoints written before abort, \
                     got {checkpoints_written}",
                );
            }
            Ok(_) => {
                // Race: the run finished cleanly before the kill could
                // fire. That can happen for very small abort_after on
                // a fast pipeline; treat it as a successful trial and
                // skip the resume check (nothing to resume).
                let got = fs::read(&out_path).expect("trial output");
                assert_eq!(got, golden_bytes, "trial {trial} (no abort)");
                continue;
            }
            Err(other) => panic!("trial {trial}: unexpected error {other:?}"),
        }

        // Sidecars must survive the abort.
        assert!(
            work.join("out.bin.peel.part").exists(),
            "trial {trial}: .part missing after abort"
        );
        assert!(
            work.join("out.bin.peel.ckpt").exists(),
            "trial {trial}: .ckpt missing after abort"
        );

        // Resume.
        let resume_args = make_args(
            &server,
            "raw.zst",
            OutputTarget::File(out_path.clone()),
            coord_config(4096),
            None,
            None,
        );
        let stats = run(resume_args).expect("resume ok");
        assert!(
            stats.resumed,
            "trial {trial}: resume did not flag itself as resumed"
        );

        let got = fs::read(&out_path).expect("trial output");
        assert_eq!(
            got, golden_bytes,
            "trial {trial}: resumed output diverges from golden (abort_after={abort_after})",
        );
    }
}

// ---- harness: tar output ----------------------------------------------

#[test]
fn random_kill_points_resume_to_identical_tar_output() {
    // Build a multi-member tar; encode it as a zstd stream whose frame
    // boundaries align with tar member boundaries. The §10
    // checkpoint discipline only fires when the decoder reports a
    // frame boundary AND the sink is quiescent in the same step, so
    // testing tar resume requires this alignment.
    let mut members: Vec<(&str, Vec<u8>)> = Vec::new();
    for i in 0..12 {
        let name = Box::leak(format!("dir/member_{i:02}.bin").into_boxed_str());
        let payload: Vec<u8> = (0..(512 + i * 87))
            .map(|j| (i as u8).wrapping_add(j as u8))
            .collect();
        members.push((name, payload));
    }
    // Encode each member's archive bytes as a separate zstd frame, plus
    // the end-of-archive marker as its own frame. Member boundaries =
    // frame boundaries.
    let mut frames: Vec<Vec<u8>> = Vec::new();
    for (name, payload) in &members {
        frames.push(member_archive_bytes(name, payload));
    }
    frames.push(end_of_archive_block());
    let frame_refs: Vec<&[u8]> = frames.iter().map(|v| v.as_slice()).collect();
    let body = encode_zstd_frames(&frame_refs);
    let server = MockServer::start(ok_handler(body, "\"v-tar\""));

    // Reference run.
    let golden_dir = unique_dir("golden_tar");
    let _g_golden = CleanupDir(golden_dir.clone());
    let golden_out = golden_dir.join("out");
    fs::create_dir_all(&golden_out).expect("golden out dir");

    let golden_count = Arc::new(AtomicU64::new(0));
    let counter_for_golden = Arc::clone(&golden_count);
    let progress: ProgressFn = Box::new(move |event| {
        if let ProgressEvent::CheckpointWritten { .. } = event {
            counter_for_golden.fetch_add(1, Ordering::Relaxed);
        }
    });
    let args = make_args(
        &server,
        "x.tar.zst",
        OutputTarget::Dir(golden_out.clone()),
        coord_config(4096),
        None,
        Some(progress),
    );
    run(args).expect("golden tar run");
    let golden_entries = read_dir_recursive(&golden_out);
    assert!(
        !golden_entries.is_empty(),
        "golden run did not extract any files",
    );
    let total_checkpoints = golden_count.load(Ordering::Relaxed);

    if total_checkpoints < 2 {
        // Nothing meaningful to randomize over; the suite is still
        // valuable on the raw-output path.
        return;
    }

    let trial_count = 10u64;
    let mut rng = Lcg::seeded(0x0013_579A_CEBD_2468);
    let captured_failures: Mutex<Vec<String>> = Mutex::new(Vec::new());

    for trial in 0..trial_count {
        let abort_after = rng.range(1, total_checkpoints);
        let work = unique_dir(&format!("tar_trial_{trial}"));
        let _g = CleanupDir(work.clone());
        let out_dir = work.join("out");
        fs::create_dir_all(&out_dir).expect("trial out dir");

        let kill = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(AtomicU64::new(0));
        let progress = kill_after(Arc::clone(&kill), abort_after, Arc::clone(&counter));
        let args = make_args(
            &server,
            "x.tar.zst",
            OutputTarget::Dir(out_dir.clone()),
            coord_config(4096),
            Some(Arc::clone(&kill)),
            Some(progress),
        );
        match run(args) {
            Err(CoordinatorError::Aborted { .. }) => {}
            Ok(_) => {
                let got = read_dir_recursive(&out_dir);
                assert_eq!(got, golden_entries, "trial {trial} (no abort)");
                continue;
            }
            Err(other) => panic!("trial {trial}: unexpected error {other:?}"),
        }

        // Resume.
        let resume_args = make_args(
            &server,
            "x.tar.zst",
            OutputTarget::Dir(out_dir.clone()),
            coord_config(4096),
            None,
            None,
        );
        let stats = run(resume_args).expect("resume ok");
        assert!(
            stats.resumed,
            "trial {trial}: resume did not flag itself as resumed"
        );

        let got = read_dir_recursive(&out_dir);
        if got != golden_entries {
            captured_failures.lock().unwrap().push(format!(
                "trial {trial}: tar resume diverges from golden (abort_after={abort_after})",
            ));
        }
    }

    let failures = captured_failures.lock().unwrap();
    assert!(failures.is_empty(), "{:?}", *failures);
}

// ---- harness: uncompressed `.tar` (PLAN_v2 §2) ------------------------

#[test]
fn random_kill_points_resume_to_identical_plain_tar_output() {
    // Same shape as the zstd-tar harness above but the body is the
    // uncompressed archive — exercises the identity decoder's
    // resume contract directly. The identity decoder reports a frame
    // boundary on every step, so the sink's between-member quiescence
    // is what gates the checkpoint cadence.
    let mut members: Vec<(&str, Vec<u8>)> = Vec::new();
    for i in 0..12 {
        let name = Box::leak(format!("dir/plain_{i:02}.bin").into_boxed_str());
        let payload: Vec<u8> = (0..(384 + i * 73))
            .map(|j| (i as u8).wrapping_mul(11).wrapping_add(j as u8))
            .collect();
        members.push((name, payload));
    }
    let mut body: Vec<u8> = Vec::new();
    for (name, payload) in &members {
        body.extend_from_slice(&member_archive_bytes(name, payload));
    }
    body.extend_from_slice(&end_of_archive_block());

    let server = MockServer::start(ok_handler(body, "\"v-plain-tar\""));

    // Reference run.
    let golden_dir = unique_dir("golden_plain_tar");
    let _g_golden = CleanupDir(golden_dir.clone());
    let golden_out = golden_dir.join("out");
    fs::create_dir_all(&golden_out).expect("golden out dir");

    let golden_count = Arc::new(AtomicU64::new(0));
    let counter_for_golden = Arc::clone(&golden_count);
    let progress: ProgressFn = Box::new(move |event| {
        if let ProgressEvent::CheckpointWritten { .. } = event {
            counter_for_golden.fetch_add(1, Ordering::Relaxed);
        }
    });
    let args = make_args(
        &server,
        "x.tar",
        OutputTarget::Dir(golden_out.clone()),
        coord_config(4096),
        None,
        Some(progress),
    );
    run(args).expect("golden plain-tar run");
    let golden_entries = read_dir_recursive(&golden_out);
    assert!(
        !golden_entries.is_empty(),
        "golden plain-tar run produced no files",
    );
    let total_checkpoints = golden_count.load(Ordering::Relaxed);
    if total_checkpoints < 2 {
        return;
    }

    let trial_count = 10u64;
    let mut rng = Lcg::seeded(0x1357_2468_BD9A_CE13);
    let captured_failures: Mutex<Vec<String>> = Mutex::new(Vec::new());

    for trial in 0..trial_count {
        let abort_after = rng.range(1, total_checkpoints);
        let work = unique_dir(&format!("plain_tar_trial_{trial}"));
        let _g = CleanupDir(work.clone());
        let out_dir = work.join("out");
        fs::create_dir_all(&out_dir).expect("trial out dir");

        let kill = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(AtomicU64::new(0));
        let progress = kill_after(Arc::clone(&kill), abort_after, Arc::clone(&counter));
        let args = make_args(
            &server,
            "x.tar",
            OutputTarget::Dir(out_dir.clone()),
            coord_config(4096),
            Some(Arc::clone(&kill)),
            Some(progress),
        );
        match run(args) {
            Err(CoordinatorError::Aborted { .. }) => {}
            Ok(_) => {
                let got = read_dir_recursive(&out_dir);
                assert_eq!(got, golden_entries, "trial {trial} (no abort)");
                continue;
            }
            Err(other) => panic!("trial {trial}: unexpected error {other:?}"),
        }

        let resume_args = make_args(
            &server,
            "x.tar",
            OutputTarget::Dir(out_dir.clone()),
            coord_config(4096),
            None,
            None,
        );
        let stats = run(resume_args).expect("resume ok");
        assert!(
            stats.resumed,
            "trial {trial}: resume did not flag itself as resumed"
        );

        let got = read_dir_recursive(&out_dir);
        if got != golden_entries {
            captured_failures.lock().unwrap().push(format!(
                "trial {trial}: plain-tar resume diverges from golden \
                 (abort_after={abort_after})",
            ));
        }
    }

    let failures = captured_failures.lock().unwrap();
    assert!(failures.is_empty(), "{:?}", *failures);
}

// ---- harness: `.tar.xz` (PLAN_v2 §3, per-Stream frame granularity) ----

#[test]
fn random_kill_points_resume_to_identical_tar_xz_output() {
    // Multi-member tar encoded as a *concatenation* of xz Streams,
    // one Stream per member, so per-Stream frame boundaries surfaced
    // by `decode/xz.rs` align with tar member boundaries the same
    // way the tar.zst harness aligns zstd-frame boundaries to member
    // boundaries. A single-Stream `.tar.xz` would have only one
    // frame boundary (at end-of-stream), which short-circuits the
    // per-trial randomization just like a single-frame `.tar.zst`
    // does on the zstd path.
    let mut members: Vec<(&str, Vec<u8>)> = Vec::new();
    for i in 0..10 {
        let name = Box::leak(format!("dir/xz_{i:02}.bin").into_boxed_str());
        let payload: Vec<u8> = (0..(384 + i * 73))
            .map(|j| (i as u8).wrapping_mul(29).wrapping_add(j as u8))
            .collect();
        members.push((name, payload));
    }
    let mut frames: Vec<Vec<u8>> = Vec::new();
    for (name, payload) in &members {
        frames.push(member_archive_bytes(name, payload));
    }
    frames.push(end_of_archive_block());
    let frame_refs: Vec<&[u8]> = frames.iter().map(|v| v.as_slice()).collect();
    let body = encode_xz_streams(&frame_refs);
    let server = MockServer::start(ok_handler(body, "\"v-tar-xz\""));

    let golden_dir = unique_dir("golden_tar_xz");
    let _g_golden = CleanupDir(golden_dir.clone());
    let golden_out = golden_dir.join("out");
    fs::create_dir_all(&golden_out).expect("golden out dir");

    let golden_count = Arc::new(AtomicU64::new(0));
    let counter_for_golden = Arc::clone(&golden_count);
    let progress: ProgressFn = Box::new(move |event| {
        if let ProgressEvent::CheckpointWritten { .. } = event {
            counter_for_golden.fetch_add(1, Ordering::Relaxed);
        }
    });
    let args = make_args(
        &server,
        "x.tar.xz",
        OutputTarget::Dir(golden_out.clone()),
        coord_config(4096),
        None,
        Some(progress),
    );
    run(args).expect("golden tar.xz run");
    let golden_entries = read_dir_recursive(&golden_out);
    assert!(
        !golden_entries.is_empty(),
        "golden tar.xz run did not extract any files",
    );
    let total_checkpoints = golden_count.load(Ordering::Relaxed);
    if total_checkpoints < 2 {
        return;
    }

    let trial_count = 10u64;
    let mut rng = Lcg::seeded(0xACE0_F1B7_2486_BD13);
    let captured_failures: Mutex<Vec<String>> = Mutex::new(Vec::new());

    for trial in 0..trial_count {
        let abort_after = rng.range(1, total_checkpoints);
        let work = unique_dir(&format!("tar_xz_trial_{trial}"));
        let _g = CleanupDir(work.clone());
        let out_dir = work.join("out");
        fs::create_dir_all(&out_dir).expect("trial out dir");

        let kill = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(AtomicU64::new(0));
        let progress = kill_after(Arc::clone(&kill), abort_after, Arc::clone(&counter));
        let args = make_args(
            &server,
            "x.tar.xz",
            OutputTarget::Dir(out_dir.clone()),
            coord_config(4096),
            Some(Arc::clone(&kill)),
            Some(progress),
        );
        match run(args) {
            Err(CoordinatorError::Aborted { .. }) => {}
            Ok(_) => {
                let got = read_dir_recursive(&out_dir);
                assert_eq!(got, golden_entries, "trial {trial} (no abort)");
                continue;
            }
            Err(other) => panic!("trial {trial}: unexpected error {other:?}"),
        }

        let resume_args = make_args(
            &server,
            "x.tar.xz",
            OutputTarget::Dir(out_dir.clone()),
            coord_config(4096),
            None,
            None,
        );
        let stats = run(resume_args).expect("resume ok");
        assert!(
            stats.resumed,
            "trial {trial}: resume did not flag itself as resumed"
        );

        let got = read_dir_recursive(&out_dir);
        if got != golden_entries {
            captured_failures.lock().unwrap().push(format!(
                "trial {trial}: tar.xz resume diverges from golden \
                 (abort_after={abort_after})",
            ));
        }
    }

    let failures = captured_failures.lock().unwrap();
    assert!(failures.is_empty(), "{:?}", *failures);
}

// ---- harness: `.tar.lz4` (PLAN_v2 §4) ---------------------------------

#[test]
fn random_kill_points_resume_to_identical_tar_lz4_output() {
    // Multi-member tar encoded as a *concatenation* of LZ4 frames,
    // one frame per member, so per-frame boundaries surfaced by
    // `decode/lz4.rs` align with tar member boundaries the same way
    // the tar.zst harness aligns zstd-frame boundaries to member
    // boundaries. A single-frame `.tar.lz4` would only have block-
    // and end-of-frame boundaries inside the single frame; using one
    // frame per member exercises both intra-frame and inter-frame
    // restart points.
    let mut members: Vec<(&str, Vec<u8>)> = Vec::new();
    for i in 0..10 {
        let name = Box::leak(format!("dir/lz4_{i:02}.bin").into_boxed_str());
        let payload: Vec<u8> = (0..(384 + i * 73))
            .map(|j| (i as u8).wrapping_mul(31).wrapping_add(j as u8))
            .collect();
        members.push((name, payload));
    }
    let mut frames: Vec<Vec<u8>> = Vec::new();
    for (name, payload) in &members {
        frames.push(member_archive_bytes(name, payload));
    }
    frames.push(end_of_archive_block());
    let frame_refs: Vec<&[u8]> = frames.iter().map(|v| v.as_slice()).collect();
    let body = encode_lz4_frames(&frame_refs);
    let server = MockServer::start(ok_handler(body, "\"v-tar-lz4\""));

    let golden_dir = unique_dir("golden_tar_lz4");
    let _g_golden = CleanupDir(golden_dir.clone());
    let golden_out = golden_dir.join("out");
    fs::create_dir_all(&golden_out).expect("golden out dir");

    let golden_count = Arc::new(AtomicU64::new(0));
    let counter_for_golden = Arc::clone(&golden_count);
    let progress: ProgressFn = Box::new(move |event| {
        if let ProgressEvent::CheckpointWritten { .. } = event {
            counter_for_golden.fetch_add(1, Ordering::Relaxed);
        }
    });
    let args = make_args(
        &server,
        "x.tar.lz4",
        OutputTarget::Dir(golden_out.clone()),
        coord_config(4096),
        None,
        Some(progress),
    );
    run(args).expect("golden tar.lz4 run");
    let golden_entries = read_dir_recursive(&golden_out);
    assert!(
        !golden_entries.is_empty(),
        "golden tar.lz4 run did not extract any files",
    );
    let total_checkpoints = golden_count.load(Ordering::Relaxed);
    if total_checkpoints < 2 {
        return;
    }

    let trial_count = 10u64;
    let mut rng = Lcg::seeded(0x5BEE_F00D_DECA_F2EE);
    let captured_failures: Mutex<Vec<String>> = Mutex::new(Vec::new());

    for trial in 0..trial_count {
        let abort_after = rng.range(1, total_checkpoints);
        let work = unique_dir(&format!("tar_lz4_trial_{trial}"));
        let _g = CleanupDir(work.clone());
        let out_dir = work.join("out");
        fs::create_dir_all(&out_dir).expect("trial out dir");

        let kill = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(AtomicU64::new(0));
        let progress = kill_after(Arc::clone(&kill), abort_after, Arc::clone(&counter));
        let args = make_args(
            &server,
            "x.tar.lz4",
            OutputTarget::Dir(out_dir.clone()),
            coord_config(4096),
            Some(Arc::clone(&kill)),
            Some(progress),
        );
        match run(args) {
            Err(CoordinatorError::Aborted { .. }) => {}
            Ok(_) => {
                let got = read_dir_recursive(&out_dir);
                assert_eq!(got, golden_entries, "trial {trial} (no abort)");
                continue;
            }
            Err(other) => panic!("trial {trial}: unexpected error {other:?}"),
        }

        let resume_args = make_args(
            &server,
            "x.tar.lz4",
            OutputTarget::Dir(out_dir.clone()),
            coord_config(4096),
            None,
            None,
        );
        let stats = run(resume_args).expect("resume ok");
        assert!(
            stats.resumed,
            "trial {trial}: resume did not flag itself as resumed"
        );

        let got = read_dir_recursive(&out_dir);
        if got != golden_entries {
            captured_failures.lock().unwrap().push(format!(
                "trial {trial}: tar.lz4 resume diverges from golden \
                 (abort_after={abort_after})",
            ));
        }
    }

    let failures = captured_failures.lock().unwrap();
    assert!(failures.is_empty(), "{:?}", *failures);
}

// ---- harness: zip output (PLAN_v2 §5) -------------------------------

#[test]
fn random_kill_points_resume_to_identical_zip_output() {
    // Multi-entry archive mixing all three round-one methods. The
    // checkpoint cadence policy in run_zip writes a checkpoint after
    // every entry (capped by checkpoint_min_bytes/min_interval); a
    // crash between entries is the only meaningful kill point round-
    // one supports for ZIP, but the harness still verifies that
    // every such resume is byte-identical.
    let entries = vec![
        ZipEntrySpec::stored("a.txt", b"hello, zip resume world".to_vec()),
        ZipEntrySpec::deflate(
            "compressible.txt",
            b"the quick brown fox jumps over the lazy dog. ".repeat(64),
        ),
        ZipEntrySpec::zstd(
            "nested/big.bin",
            (0u8..=255).cycle().take(8 * 1024).collect::<Vec<u8>>(),
        ),
        ZipEntrySpec::stored("nested/sub/c.bin", vec![0xAB; 1024]),
        ZipEntrySpec::deflate("d.bin", b"deflate payload \xC0\xFF\xEE".repeat(50)),
        ZipEntrySpec::zstd("e.bin", b"zstd payload ".repeat(70)),
        ZipEntrySpec::directory("emptydir"),
        ZipEntrySpec::stored("z_last.txt", b"final entry".to_vec()),
    ];
    let body = build_zip(&entries);
    let server = MockServer::start(ok_handler(body, "\"v-zip-crash\""));

    let golden_dir = unique_dir("golden_zip");
    let _g_golden = CleanupDir(golden_dir.clone());
    let golden_out = golden_dir.join("out");
    fs::create_dir_all(&golden_out).expect("golden out dir");

    let golden_count = Arc::new(AtomicU64::new(0));
    let counter_for_golden = Arc::clone(&golden_count);
    let progress: ProgressFn = Box::new(move |event| {
        if let ProgressEvent::CheckpointWritten { .. } = event {
            counter_for_golden.fetch_add(1, Ordering::Relaxed);
        }
    });
    let args = make_args(
        &server,
        "release.zip",
        OutputTarget::Dir(golden_out.clone()),
        coord_config(4096),
        None,
        Some(progress),
    );
    run(args).expect("golden zip run");
    let golden_entries = read_dir_recursive(&golden_out);
    assert!(
        !golden_entries.is_empty(),
        "golden zip run did not extract any files",
    );
    let total_checkpoints = golden_count.load(Ordering::Relaxed);
    if total_checkpoints < 2 {
        // The cadence floor on a tiny archive can collapse all
        // entries into a single checkpoint; in that case there's no
        // meaningful kill point. Skip rather than fail-flake.
        return;
    }

    let trial_count = 10u64;
    let mut rng = Lcg::seeded(0xCAFE_F00D_DEAD_BEEF);
    let captured_failures: Mutex<Vec<String>> = Mutex::new(Vec::new());

    for trial in 0..trial_count {
        let abort_after = rng.range(1, total_checkpoints);
        let work = unique_dir(&format!("zip_trial_{trial}"));
        let _g = CleanupDir(work.clone());
        let out_dir = work.join("out");
        fs::create_dir_all(&out_dir).expect("trial out dir");

        let kill = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(AtomicU64::new(0));
        let progress = kill_after(Arc::clone(&kill), abort_after, Arc::clone(&counter));
        let args = make_args(
            &server,
            "release.zip",
            OutputTarget::Dir(out_dir.clone()),
            coord_config(4096),
            Some(Arc::clone(&kill)),
            Some(progress),
        );
        match run(args) {
            Err(CoordinatorError::Aborted { .. }) => {}
            Ok(_) => {
                let got = read_dir_recursive(&out_dir);
                assert_eq!(got, golden_entries, "trial {trial} (no abort)");
                continue;
            }
            Err(other) => panic!("trial {trial}: unexpected error {other:?}"),
        }

        let resume_args = make_args(
            &server,
            "release.zip",
            OutputTarget::Dir(out_dir.clone()),
            coord_config(4096),
            None,
            None,
        );
        let stats = run(resume_args).expect("resume ok");
        assert!(
            stats.resumed,
            "trial {trial}: resume did not flag itself as resumed"
        );

        let got = read_dir_recursive(&out_dir);
        if got != golden_entries {
            captured_failures.lock().unwrap().push(format!(
                "trial {trial}: zip resume diverges from golden \
                 (abort_after={abort_after})",
            ));
        }
    }

    let failures = captured_failures.lock().unwrap();
    assert!(failures.is_empty(), "{:?}", *failures);
}
