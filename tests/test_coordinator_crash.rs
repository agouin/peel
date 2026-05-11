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
    RunStats,
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
        // Disable rate-aware scaling: the kill harness wants a
        // checkpoint per advance, and a fast loopback bench would
        // otherwise scale the live floor up to multi-MiB and
        // suppress most checkpoints.
        checkpoint_target_interval: Duration::ZERO,
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
        additional_urls: Vec::new(),
        output,
        config,
        client: build_client(),
        registry: DecoderRegistry::with_defaults(),
        progress,
        progress_state: None,
        kill_switch,
        io_backend: None,
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

/// Encode `payload` as a *single* zstd frame at the given level. This
/// matches what the default `zstd` CLI emits — one frame for the whole
/// input, regardless of size. Phase 10's harness needs this shape
/// because the production failure that motivated the hand-rolled
/// decoder (3.7 TiB single-frame `tar.zst` with no checkpoints) was
/// specifically the single-frame case.
fn encode_zstd_single_frame(payload: &[u8], level: i32) -> Vec<u8> {
    zstd::encode_all(payload, level).expect("encode single-frame zstd")
}

/// LCG-generated pseudo-random bytes. The single-frame `.tar.zst`
/// harness needs payloads with enough entropy that zstd emits multiple
/// compressed blocks per frame (rather than collapsing to a single
/// huge RLE block), so the harness has many in-frame block boundaries
/// to abort between.
fn random_payload(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
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

/// Build a single-frame `.tar.zst` whose tar members are sized
/// awkwardly (a prime byte count) so member boundaries do not align
/// with zstd block boundaries — the Phase 10 worst-case shape that
/// pre-hand-rolled-decoder peel could not checkpoint inside.
fn build_misaligned_tar_zst_body(
    member_count: usize,
    payload_per_member: usize,
    zstd_level: i32,
    seed: u64,
) -> Vec<u8> {
    let mut tar_body: Vec<u8> = Vec::new();
    for i in 0..member_count {
        let name = format!("dir/zst_member_{i:03}.bin");
        let payload = random_payload(
            seed ^ (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15),
            payload_per_member,
        );
        tar_body.extend_from_slice(&member_archive_bytes(&name, &payload));
    }
    tar_body.extend_from_slice(&end_of_archive_block());
    encode_zstd_single_frame(&tar_body, zstd_level)
}

/// Run a golden-then-trials pass against `body`, asserting every
/// abort-and-resume produces directory output byte-identical to the
/// golden run. Used by the Phase 10 single-frame `.tar.zst` tests
/// below; factored out because the loop body is almost identical
/// across compression-level variations and the older inline copies
/// already span ~100 lines each.
///
/// `seed` is the LCG seed used to randomize abort points; `etag` must
/// be a `'static` literal because [`MockServer`]'s handler is `'static`.
/// What the per-format crash-resume tests expect to see in
/// [`RunStats::resume_used_decoder_state`] across N randomized
/// kill-and-resume trials.
///
/// "Properly resuming from the checkpoint" means more than
/// "the output matches the golden run" — a format that
/// silently re-decodes from byte 0 on every resume would also
/// produce byte-identical output, but would fail the §"What
/// this project is" load-bearing claim ("survive `kill -9`
/// from where you left off"). These modes pin the test to the
/// right resume path.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[allow(clippy::enum_variant_names, dead_code)]
enum ExpectedResumeMode {
    /// Every trial must take the resume_factory path. Used by
    /// formats whose only resume points are mid-frame —
    /// single-Block xz, single-frame zstd, single-frame lz4 —
    /// where the regular factory cannot pick up at the
    /// checkpoint's source offset because it would land
    /// mid-Stream.
    AllDecoderState,
    /// At least one trial across the run must take the
    /// resume_factory path. Used by multi-frame formats whose
    /// per-block / per-chunk frame boundaries fire alongside
    /// the per-frame ones; randomized kill points should hit
    /// both kinds across N trials. Multi-Stream `.tar.xz`,
    /// multi-frame `.tar.zst`, multi-block `.tar.lz4`.
    SomeDecoderState,
    /// No trials should take the resume_factory path. Used by
    /// formats whose frame boundaries are all positions the
    /// regular factory can pick up cleanly — gzip, zip,
    /// uncompressed `.tar`, identity. Asserts the absence so a
    /// future format-mis-registration doesn't silently fall
    /// through to the resume_factory path.
    NeverDecoderState,
}

/// Per-trial assertion: the resume's `RunStats` shape is
/// consistent with the coordinator detecting and using a prior
/// checkpoint. Independent of [`ExpectedResumeMode`] — the mode
/// gates the aggregate, this helper gates the per-trial.
///
/// We check `resumed` and that `resume_decoder_position` is
/// `Some(_)`. We don't strictly require `position > 0` because:
///
/// - The zip pipeline carries no decoder-position concept — its
///   resume state lives in the bitmap of completed download
///   chunks plus the sink's per-entry state, not a single
///   monotonic decoder offset.
/// - Some streaming formats can legitimately hit a checkpoint
///   at position 0 if every prior frame_boundary captured during
///   the abort window happened to be at offset 0 (rare in
///   practice but not a protocol violation).
///
/// The aggregate [`assert_resume_mode`] is the load-bearing
/// "the right resume path actually fired" assertion; this
/// helper is just the per-trial sanity check.
fn assert_real_resume(label: &str, trial: u64, stats: &RunStats) {
    assert!(
        stats.resumed,
        "{label} trial {trial}: resume did not flag itself as resumed"
    );
    assert!(
        stats.resume_decoder_position.is_some(),
        "{label} trial {trial}: resume_decoder_position should be Some on resume"
    );
}

/// Aggregate assertion across N trials: the format's
/// `resume_used_decoder_state` distribution matches the
/// expected mode.
fn assert_resume_mode(
    label: &str,
    decoder_state_count: u64,
    trial_count: u64,
    mode: ExpectedResumeMode,
) {
    match mode {
        ExpectedResumeMode::AllDecoderState => assert_eq!(
            decoder_state_count, trial_count,
            "{label}: every trial must use the decoder_state resume path \
             (got {decoder_state_count}/{trial_count})"
        ),
        ExpectedResumeMode::SomeDecoderState => assert!(
            decoder_state_count >= 1,
            "{label}: at least one trial must use the decoder_state resume \
             path (got 0/{trial_count})"
        ),
        ExpectedResumeMode::NeverDecoderState => assert_eq!(
            decoder_state_count, 0,
            "{label}: no trials should use the decoder_state path \
             (got {decoder_state_count}/{trial_count})"
        ),
    }
}

fn run_dir_kill_resume_trials(
    label: &str,
    suffix: &str,
    body: Vec<u8>,
    etag: &'static str,
    seed: u64,
    trial_count: u64,
    resume_mode: ExpectedResumeMode,
) {
    let cfg = || CoordinatorConfig {
        checkpoint_min_bytes: 1,
        checkpoint_min_interval: Duration::ZERO,
        ..coord_config(4096)
    };
    let server = MockServer::start(ok_handler(body, etag));

    let golden_dir = unique_dir(&format!("golden_{label}"));
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
        suffix,
        OutputTarget::Dir(golden_out.clone()),
        cfg(),
        None,
        Some(progress),
    );
    run(args).expect("golden run");
    let golden_entries = read_dir_recursive(&golden_out);
    assert!(
        !golden_entries.is_empty(),
        "{label}: golden run produced no files",
    );
    let total_checkpoints = golden_count.load(Ordering::Relaxed);
    assert!(
        total_checkpoints >= 2,
        "{label}: golden run produced {total_checkpoints} checkpoints, need ≥2 to randomize. \
         For a single-frame `.tar.zst` ≥2 proves the hand-rolled decoder is firing per-block \
         frame_boundary advances — pre-Phase-8 the wrapper crate produced 0 here.",
    );

    let mut rng = Lcg::seeded(seed);
    let captured_failures: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut decoder_state_count: u64 = 0;
    let mut real_trial_count: u64 = 0;
    for trial in 0..trial_count {
        let abort_after = rng.range(1, total_checkpoints);
        let work = unique_dir(&format!("{label}_trial_{trial}"));
        let _g = CleanupDir(work.clone());
        let out_dir = work.join("out");
        fs::create_dir_all(&out_dir).expect("trial out dir");

        let kill = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(AtomicU64::new(0));
        let progress = kill_after(Arc::clone(&kill), abort_after, Arc::clone(&counter));
        let args = make_args(
            &server,
            suffix,
            OutputTarget::Dir(out_dir.clone()),
            cfg(),
            Some(Arc::clone(&kill)),
            Some(progress),
        );
        match run(args) {
            Err(CoordinatorError::Aborted { .. }) => {}
            Ok(_) => {
                let got = read_dir_recursive(&out_dir);
                assert_eq!(got, golden_entries, "{label} trial {trial} (no abort)");
                continue;
            }
            Err(other) => panic!("{label} trial {trial}: unexpected error {other:?}"),
        }

        let resume_args = make_args(
            &server,
            suffix,
            OutputTarget::Dir(out_dir.clone()),
            cfg(),
            None,
            None,
        );
        let stats = run(resume_args).expect("resume ok");
        assert_real_resume(label, trial, &stats);
        if stats.resume_used_decoder_state {
            decoder_state_count += 1;
        }
        real_trial_count += 1;

        let got = read_dir_recursive(&out_dir);
        if got != golden_entries {
            captured_failures.lock().unwrap().push(format!(
                "{label} trial {trial}: resume diverges from golden \
                 (abort_after={abort_after})",
            ));
        }
    }
    let failures = captured_failures.lock().unwrap();
    assert!(failures.is_empty(), "{:?}", *failures);
    // `real_trial_count` excludes trials where the abort fired
    // after the run had already finished — those are no-op
    // resumes that don't exercise the resume path at all.
    assert_resume_mode(label, decoder_state_count, real_trial_count, resume_mode);
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

/// Encode the entire `payload` as a *single* uncompressed LZ4 frame
/// whose body is split into sequential blocks of at most
/// `block_max` bytes — the worst-case shape `OPTIMIZATIONS.md` §O.7b
/// targets (one big frame, many blocks). The producer only emits
/// the four valid spec values for `block_max` (64K, 256K, 1M, 4M);
/// any other value panics.
fn encode_lz4_multi_block_single_frame(payload: &[u8], block_max: u32) -> Vec<u8> {
    use crate::xxh32_nocrate as xxh32_local;
    let bd_size_code: u8 = match block_max {
        65_536 => 4,
        262_144 => 5,
        1_048_576 => 6,
        4_194_304 => 7,
        other => panic!("invalid block_max {other}"),
    };
    let mut out = Vec::new();
    out.extend_from_slice(&0x184D_2204u32.to_le_bytes());
    let flg: u8 = 0b0110_0000; // version=01, block-independent, no checksums, no content size
    let bd: u8 = bd_size_code << 4;
    out.push(flg);
    out.push(bd);
    let hc = ((xxh32_local::xxh32(&[flg, bd]) >> 8) & 0xff) as u8;
    out.push(hc);
    for chunk in payload.chunks(block_max as usize) {
        let header = (chunk.len() as u32) | 0x8000_0000;
        out.extend_from_slice(&header.to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&[0u8; 4]); // EndMark
    out
}

/// Local hand-rolled xxh32 used only by the multi-block-frame
/// encoder above. Same algorithm as the in-tree implementation; we
/// duplicate it here so the crash test stays self-contained
/// (matching the existing `encode_lz4_uncompressed_frame` style).
mod xxh32_nocrate {
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
    pub fn xxh32(input: &[u8]) -> u32 {
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
}

/// Encode `payload` as a single xz Stream / single Block at the
/// given preset. Matches the shape of what `xz` CLI emits by
/// default — one Stream and one Block for any input that fits in
/// the dictionary. Phase 9 of `docs/PLAN_xz_block_decoder.md`
/// uses this to drive crash-resume tests across the per-LZMA2-
/// chunk frame_boundary cadence; pre-Phase-7 the wrapper crate
/// would have collapsed every checkpoint to end-of-Stream and
/// every kill -9 mid-extraction would lose all decoder progress.
fn encode_xz_single_block(payload: &[u8], preset: u32) -> Vec<u8> {
    use std::io::Write as _;
    let mut compressed = Vec::new();
    let mut encoder = xz2::write::XzEncoder::new(&mut compressed, preset);
    encoder.write_all(payload).expect("xz2 encode");
    encoder.finish().expect("xz2 finish");
    compressed
}

/// Generate `len` bytes of LZMA-friendly content: pseudo-random
/// pseudo-English sentences with mild variation. Compressible
/// enough to defeat xz's "switch to uncompressed chunks for
/// incompressible input" heuristic (which would leave the LZMA
/// model un-allocated and silence per-chunk `frame_boundary`
/// advances), varied enough that the compressed-side byte count
/// scales with `len` and hits the 64 KiB LZMA2-chunk
/// compressed-size cap multiple times. Mirrors the analogous
/// helper in `tests/test_xz_native.rs`.
fn build_lzma_friendly_input(len: usize, seed: u32) -> Vec<u8> {
    let lines: &[&[u8]] = &[
        b"the quick brown fox jumps over the lazy dog ",
        b"alpha bravo charlie delta echo foxtrot golf ",
        b"every good boy deserves favor and this is line ",
        b"the rain in spain falls mainly on the plain ",
        b"to be or not to be that is the question whether ",
        b"in the beginning was the word and the word was with ",
    ];
    let mut out = Vec::with_capacity(len);
    let mut state = seed;
    while out.len() < len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let line = lines[(state >> 24) as usize % lines.len()];
        out.extend_from_slice(line);
        let digits = state % 1_000_000;
        out.extend_from_slice(format!("{digits:06} ").as_bytes());
    }
    out.truncate(len);
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
    let mut decoder_state_count: u64 = 0;
    let mut real_trial_count: u64 = 0;
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
        assert_real_resume("raw_zst", trial, &stats);
        if stats.resume_used_decoder_state {
            decoder_state_count += 1;
        }
        real_trial_count += 1;

        let got = fs::read(&out_path).expect("trial output");
        assert_eq!(
            got, golden_bytes,
            "trial {trial}: resumed output diverges from golden (abort_after={abort_after})",
        );
    }
    // Multi-frame zstd raw with small (~3 KiB) per-frame
    // payloads: each frame is a single zstd block, so every
    // frame_boundary advance lands at end-of-frame where the
    // hand-rolled decoder reports `decoder_state = None`. The
    // regular factory handles the source seek cleanly and the
    // resume_factory path is never taken. (Multi-block frames
    // would land in `SomeDecoderState`; single-frame fixtures
    // would land in `AllDecoderState`.)
    assert_resume_mode(
        "raw_zst",
        decoder_state_count,
        real_trial_count,
        ExpectedResumeMode::NeverDecoderState,
    );
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
    let mut decoder_state_count: u64 = 0;
    let mut real_trial_count: u64 = 0;

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
        assert_real_resume("tar_zst_multi_frame", trial, &stats);
        if stats.resume_used_decoder_state {
            decoder_state_count += 1;
        }
        real_trial_count += 1;

        let got = read_dir_recursive(&out_dir);
        if got != golden_entries {
            captured_failures.lock().unwrap().push(format!(
                "trial {trial}: tar resume diverges from golden (abort_after={abort_after})",
            ));
        }
    }

    let failures = captured_failures.lock().unwrap();
    assert!(failures.is_empty(), "{:?}", *failures);
    // Multi-frame zstd-wrapped tar with small (~few-KiB)
    // per-frame payloads: frames are single-block, so all
    // checkpoints fall at end-of-frame where
    // `decoder_state = None`. Resume happens via the regular
    // factory at the frame-boundary offset.
    assert_resume_mode(
        "tar_zst_multi_frame",
        decoder_state_count,
        real_trial_count,
        ExpectedResumeMode::NeverDecoderState,
    );
}

// ---- harness: single-frame `.tar.zst` (Phase 10) ----------------------

#[test]
fn random_kill_points_resume_mid_member_tar_zst_misaligned() {
    // The production shape that motivated `docs/PLAN_zstd_block_decoder.md`:
    // a single zstd frame wrapping a multi-member tar archive whose
    // member boundaries do not align with the zstd block grid. Pre-
    // Phase-8 the upstream `zstd` crate's `frame_boundary` only fired
    // at end-of-frame, so checkpoint discipline collapsed to one
    // checkpoint per *whole archive* — a `kill -9` at any point lost
    // every byte the decoder had produced. With the hand-rolled
    // decoder advancing per block, every block boundary fires the
    // checkpoint observer and resume is byte-identical.
    //
    // Member size 20_011 is prime, so the cumulative offsets after
    // each tar member are pairwise distinct mod any plausible zstd
    // block size; member boundaries effectively never coincide with
    // block boundaries on this corpus. With v6 in-flight tar resume
    // every block boundary still fires a checkpoint, even mid-member.
    let body = build_misaligned_tar_zst_body(16, 20_011, 3, 0xA5A5_5A5A_DEAD_F00D);
    run_dir_kill_resume_trials(
        "misaligned_tar_zst",
        "x.tar.zst",
        body,
        "\"v-misaligned-tar-zst\"",
        0xCAFE_BABE_F00D_BEEF,
        25,
        // Single-frame zstd: every checkpoint fires mid-frame
        // and captures a `decoder_state` blob; resume must
        // always take the resume_factory path.
        ExpectedResumeMode::AllDecoderState,
    );
}

#[test]
fn random_kill_points_resume_single_frame_tar_zst_property() {
    // Property bar from `PLAN_zstd_block_decoder.md` Phase 10: vary
    // compression level and member sizes; every (level, size) shape
    // must produce byte-identical resumes. Levels span zstd's
    // recommended range (fast=1, default=3, mid=9, ultra=19); sizes
    // are all prime so member boundaries mis-align with block
    // boundaries differently for each config.
    //
    // Aggregate trial count: 4 configs × 20 trials = 80 single-frame
    // crash-resume runs, plus the 25 from
    // `..._misaligned` above = 105 — comfortably past the plan's
    // "100 randomized crash-resume runs" exit criterion.
    for &(level, count, size, label, etag, seed_arch, seed_trials) in &[
        (
            1i32,
            12usize,
            17_389usize,
            "prop_lvl1",
            "\"v-prop-zst-lvl1\"",
            0x1111_2222_3333_4444u64,
            0xAAAA_BBBB_CCCC_DDDDu64,
        ),
        (
            3,
            16,
            20_011,
            "prop_lvl3",
            "\"v-prop-zst-lvl3\"",
            0x5555_6666_7777_8888,
            0xEEEE_FFFF_0000_1111,
        ),
        (
            9,
            20,
            16_007,
            "prop_lvl9",
            "\"v-prop-zst-lvl9\"",
            0x9999_AAAA_BBBB_CCCC,
            0x2222_3333_4444_5555,
        ),
        (
            19,
            8,
            24_001,
            "prop_lvl19",
            "\"v-prop-zst-lvl19\"",
            0xDDDD_EEEE_FFFF_0000,
            0x6666_7777_8888_9999,
        ),
    ] {
        let body = build_misaligned_tar_zst_body(count, size, level, seed_arch);
        run_dir_kill_resume_trials(
            label,
            "x.tar.zst",
            body,
            etag,
            seed_trials,
            20,
            // Single-frame zstd: every checkpoint captures a
            // `decoder_state` blob; resume must always take
            // the resume_factory path.
            ExpectedResumeMode::AllDecoderState,
        );
    }
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
    let mut decoder_state_count: u64 = 0;
    let mut real_trial_count: u64 = 0;

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
        assert_real_resume("plain_tar", trial, &stats);
        if stats.resume_used_decoder_state {
            decoder_state_count += 1;
        }
        real_trial_count += 1;

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
    // Plain (uncompressed) tar: there's no decoder state to
    // capture, only per-source-byte-chunk frame boundaries that
    // the regular `factory` resumes from cleanly.
    assert_resume_mode(
        "plain_tar",
        decoder_state_count,
        real_trial_count,
        ExpectedResumeMode::NeverDecoderState,
    );
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
    let mut decoder_state_count: u64 = 0;
    let mut real_trial_count: u64 = 0;

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
        assert_real_resume("tar_xz_multi_stream", trial, &stats);
        if stats.resume_used_decoder_state {
            decoder_state_count += 1;
        }
        real_trial_count += 1;

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
    // Multi-Stream xz with small per-Stream payloads: the
    // hand-rolled decoder advances `frame_boundary` per LZMA2
    // chunk inside each Block (Phase 6 of
    // `PLAN_xz_block_decoder.md`) AND at end-of-Stream where
    // `decoder_state = None`. Randomized kill points hit both
    // kinds across 10 trials, so at least one trial takes the
    // `resume_factory` (decoder_state) path.
    assert_resume_mode(
        "tar_xz_multi_stream",
        decoder_state_count,
        real_trial_count,
        ExpectedResumeMode::SomeDecoderState,
    );
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
    let mut decoder_state_count: u64 = 0;
    let mut real_trial_count: u64 = 0;

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
        assert_real_resume("tar_lz4_multi_frame", trial, &stats);
        if stats.resume_used_decoder_state {
            decoder_state_count += 1;
        }
        real_trial_count += 1;

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
    // Multi-frame lz4 with one frame per tar member: lz4's
    // per-block `frame_boundary` advances inside each frame
    // (`docs/OPTIMIZATIONS.md` §O.7b) AND at end-of-frame where
    // `decoder_state = None`. Randomized kill points hit both
    // kinds across 10 trials.
    assert_resume_mode(
        "tar_lz4_multi_frame",
        decoder_state_count,
        real_trial_count,
        ExpectedResumeMode::SomeDecoderState,
    );
}

#[test]
fn random_kill_points_resume_to_identical_single_frame_tar_lz4_output() {
    // O.7b regression: a multi-member tar archive wrapped in *one*
    // LZ4 frame split across many blocks — the shape Polkachu's
    // snapshot service produces, where round-one peel had no
    // checkpoint-eligible boundary at all. With O.7b the per-block
    // boundaries inside the single frame fire the checkpoint
    // observer whenever the tar sink is also quiescent (between
    // members). Random-kill-and-resume must produce byte-identical
    // output to a clean run.
    //
    // Member size is engineered so each tar member exactly fills
    // one 64 KiB LZ4 block (512-byte tar header + 65024-byte
    // payload = 65536 bytes). Every block boundary is therefore a
    // tar-member boundary; the harness gets one quiescent
    // checkpoint per block, which is plenty for `abort_after` to
    // not always pick the final one. The Polkachu shape is the
    // same in spirit (many small-to-mid members + a single huge
    // frame), just less perfectly aligned.
    const PAYLOAD_PER_MEMBER: usize = 65024; // 64 KiB - 512 tar header
    const MEMBER_COUNT: usize = 8;
    let mut members: Vec<(&str, Vec<u8>)> = Vec::new();
    for i in 0..MEMBER_COUNT {
        let name = Box::leak(format!("dir/single_frame_{i:02}.bin").into_boxed_str());
        let payload: Vec<u8> = (0..PAYLOAD_PER_MEMBER)
            .map(|j| (i as u8).wrapping_mul(31).wrapping_add(j as u8))
            .collect();
        members.push((name, payload));
    }
    let mut tar_body: Vec<u8> = Vec::new();
    for (name, payload) in &members {
        tar_body.extend_from_slice(&member_archive_bytes(name, payload));
    }
    tar_body.extend_from_slice(&end_of_archive_block());

    let body = encode_lz4_multi_block_single_frame(&tar_body, 64 * 1024);
    let server = MockServer::start(ok_handler(body, "\"v-single-frame-tar-lz4\""));

    let golden_dir = unique_dir("golden_single_frame_tar_lz4");
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
        // Drop the cadence floor so the harness sees per-member
        // checkpoints in the test corpus instead of waiting on
        // the 8 MiB / 2 s production default.
        CoordinatorConfig {
            checkpoint_min_bytes: 1,
            checkpoint_min_interval: std::time::Duration::ZERO,
            ..coord_config(4096)
        },
        None,
        Some(progress),
    );
    run(args).expect("golden single-frame tar.lz4 run");
    let golden_entries = read_dir_recursive(&golden_out);
    assert!(
        !golden_entries.is_empty(),
        "golden single-frame tar.lz4 run did not extract any files",
    );
    let total_checkpoints = golden_count.load(Ordering::Relaxed);
    assert!(
        total_checkpoints >= 2,
        "O.7b regression: single-frame tar.lz4 produced {total_checkpoints} checkpoints, \
         expected ≥2 (per-block boundaries inside a single frame should fire when the \
         tar sink is between members)",
    );

    let trial_count = 10u64;
    let mut rng = Lcg::seeded(0x07B0_07B0_07B0_07B0);
    let captured_failures: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut decoder_state_count: u64 = 0;
    let mut real_trial_count: u64 = 0;

    for trial in 0..trial_count {
        let abort_after = rng.range(1, total_checkpoints);
        let work = unique_dir(&format!("single_frame_tar_lz4_trial_{trial}"));
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
            CoordinatorConfig {
                checkpoint_min_bytes: 1,
                checkpoint_min_interval: std::time::Duration::ZERO,
                ..coord_config(4096)
            },
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
            CoordinatorConfig {
                checkpoint_min_bytes: 1,
                checkpoint_min_interval: std::time::Duration::ZERO,
                ..coord_config(4096)
            },
            None,
            None,
        );
        let stats = run(resume_args).expect("resume ok");
        assert_real_resume("single_frame_tar_lz4", trial, &stats);
        if stats.resume_used_decoder_state {
            decoder_state_count += 1;
        }
        real_trial_count += 1;

        let got = read_dir_recursive(&out_dir);
        if got != golden_entries {
            captured_failures.lock().unwrap().push(format!(
                "trial {trial}: single-frame tar.lz4 resume diverges from golden \
                 (abort_after={abort_after})",
            ));
        }
    }

    let failures = captured_failures.lock().unwrap();
    assert!(failures.is_empty(), "{:?}", *failures);
    // Single-frame lz4: every checkpoint inside the lone frame
    // captures a `decoder_state` blob; resume must always take
    // the resume_factory path.
    assert_resume_mode(
        "single_frame_tar_lz4",
        decoder_state_count,
        real_trial_count,
        ExpectedResumeMode::AllDecoderState,
    );
}

#[test]
fn random_kill_points_resume_mid_member_tar_lz4_misaligned() {
    // The Polkachu shape: a single LZ4 frame whose tar members do
    // *not* align with any LZ4 block boundary. Pre-v6 this
    // produced zero checkpoints across the entire run because the
    // extractor's quiescent gate required block ends to land on
    // member boundaries; with the v6 tar in-flight resume support,
    // every block boundary fires a checkpoint and a kill mid-member
    // resumes byte-identically.
    //
    // Member size 5121 bytes (= 10*512 + 1) makes each member span
    // 11 tar blocks: 1 header + 10 data + padding. The cumulative
    // size after each member is `i * (12*512 + 512) = i * 6656`,
    // which never coincides with a 64-KiB LZ4 block boundary
    // (gcd(6656, 65536) = 512 — boundaries align only at multiples
    // of 65536/(6656/512) which doesn't happen in our 30-member
    // window).
    let mut members: Vec<(&str, Vec<u8>)> = Vec::new();
    for i in 0..30 {
        let name = Box::leak(format!("dir/misaligned_{i:02}.bin").into_boxed_str());
        let payload: Vec<u8> = (0..5121)
            .map(|j| (i as u8).wrapping_mul(37).wrapping_add(j as u8))
            .collect();
        members.push((name, payload));
    }
    let mut tar_body: Vec<u8> = Vec::new();
    for (name, payload) in &members {
        tar_body.extend_from_slice(&member_archive_bytes(name, payload));
    }
    tar_body.extend_from_slice(&end_of_archive_block());

    let body = encode_lz4_multi_block_single_frame(&tar_body, 64 * 1024);
    let server = MockServer::start(ok_handler(body, "\"v-misaligned-tar-lz4\""));

    let golden_dir = unique_dir("golden_misaligned_tar_lz4");
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
        CoordinatorConfig {
            checkpoint_min_bytes: 1,
            checkpoint_min_interval: std::time::Duration::ZERO,
            ..coord_config(4096)
        },
        None,
        Some(progress),
    );
    run(args).expect("golden misaligned tar.lz4 run");
    let golden_entries = read_dir_recursive(&golden_out);
    assert_eq!(
        golden_entries.len(),
        30,
        "golden run should extract 30 files"
    );

    let total_checkpoints = golden_count.load(Ordering::Relaxed);
    assert!(
        total_checkpoints >= 2,
        "v6 tar mid-member resume should produce ≥2 checkpoints across this archive; \
         got {total_checkpoints} — alignment between LZ4 block ends and tar member \
         boundaries is essentially never satisfied for this corpus, so any non-trivial \
         count proves the in-flight state plumbing is firing.",
    );

    let trial_count = 12u64;
    let mut rng = Lcg::seeded(0xBEEF_BEEF_BEEF_BEEF);
    let captured_failures: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut decoder_state_count: u64 = 0;
    let mut real_trial_count: u64 = 0;

    for trial in 0..trial_count {
        let abort_after = rng.range(1, total_checkpoints);
        let work = unique_dir(&format!("misaligned_tar_lz4_trial_{trial}"));
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
            CoordinatorConfig {
                checkpoint_min_bytes: 1,
                checkpoint_min_interval: std::time::Duration::ZERO,
                ..coord_config(4096)
            },
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
            CoordinatorConfig {
                checkpoint_min_bytes: 1,
                checkpoint_min_interval: std::time::Duration::ZERO,
                ..coord_config(4096)
            },
            None,
            None,
        );
        let stats = run(resume_args).expect("resume ok");
        assert_real_resume("misaligned_tar_lz4", trial, &stats);
        if stats.resume_used_decoder_state {
            decoder_state_count += 1;
        }
        real_trial_count += 1;

        let got = read_dir_recursive(&out_dir);
        if got != golden_entries {
            captured_failures.lock().unwrap().push(format!(
                "trial {trial}: misaligned tar.lz4 resume diverges from golden \
                 (abort_after={abort_after})",
            ));
        }
    }

    let failures = captured_failures.lock().unwrap();
    assert!(failures.is_empty(), "{:?}", *failures);
    // Single-frame lz4 with mid-member kill points: every
    // checkpoint inside the frame captures a `decoder_state`
    // blob.
    assert_resume_mode(
        "misaligned_tar_lz4",
        decoder_state_count,
        real_trial_count,
        ExpectedResumeMode::AllDecoderState,
    );
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
    let mut decoder_state_count: u64 = 0;
    let mut real_trial_count: u64 = 0;

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
        assert_real_resume("zip", trial, &stats);
        if stats.resume_used_decoder_state {
            decoder_state_count += 1;
        }
        real_trial_count += 1;

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
    // Zip: per-entry pipeline; each entry has its own decoder
    // and resume happens at entry boundaries via the regular
    // factory path (no `decoder_state` blob captured).
    assert_resume_mode(
        "zip",
        decoder_state_count,
        real_trial_count,
        ExpectedResumeMode::NeverDecoderState,
    );
}

// ---- harness: sha256 integrity verification across resume ------------

/// `PLAN_v2.md` §10 demo bar: a mid-download `kill -9` followed by a
/// resume produces a digest equal to a clean-run digest. The
/// coordinator surfaces a hash mismatch as
/// [`CoordinatorError::Integrity`] and a successful run with the
/// correct digest is byte-identical to a clean run; here we exercise
/// the full kill-then-resume loop with `--sha256` armed and assert
/// the resumed run completes cleanly (i.e. the verify step at end
/// of run did not fire a mismatch).
#[test]
fn sha256_match_after_random_kill_points_resume() {
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
    let mut hasher = peel::hash::sha256::Sha256::new();
    hasher.update(&body);
    let expected = hasher.finalize();

    let server = MockServer::start(ok_handler(body, "\"v-sha256\""));

    // Reference golden run: same as the §10 unit-tests but here we
    // capture the byte stream and the checkpoint count so the trial
    // loop has an upper bound to randomize over.
    let golden_dir = unique_dir("sha256_golden");
    let _g_golden = CleanupDir(golden_dir.clone());
    let golden_path = golden_dir.join("out.bin");

    let golden_count = Arc::new(AtomicU64::new(0));
    let counter_for_golden = Arc::clone(&golden_count);
    let progress: ProgressFn = Box::new(move |event| {
        if let ProgressEvent::CheckpointWritten { .. } = event {
            counter_for_golden.fetch_add(1, Ordering::Relaxed);
        }
    });
    let cfg = CoordinatorConfig {
        expected_sha256: Some(expected),
        expected_sha256s: Vec::new(),
        ..coord_config(4096)
    };
    let args = make_args(
        &server,
        "raw.zst",
        OutputTarget::File(golden_path.clone()),
        cfg,
        None,
        Some(progress),
    );
    run(args).expect("golden sha256 run ok");
    let golden_bytes = fs::read(&golden_path).expect("golden read");
    let total_checkpoints = golden_count.load(Ordering::Relaxed);
    assert!(
        total_checkpoints >= 4,
        "need at least a few checkpoints to randomize over (got {total_checkpoints})"
    );

    let trial_count = 10u64;
    let mut rng = Lcg::seeded(0x5_F00D_BEEF_5E55);
    let mut decoder_state_count: u64 = 0;
    let mut real_trial_count: u64 = 0;
    for trial in 0..trial_count {
        let abort_after = rng.range(1, total_checkpoints);
        let work = unique_dir(&format!("sha256_trial_{trial}"));
        let _g = CleanupDir(work.clone());
        let out_path = work.join("out.bin");

        let kill = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(AtomicU64::new(0));
        let progress = kill_after(Arc::clone(&kill), abort_after, Arc::clone(&counter));
        let cfg = CoordinatorConfig {
            expected_sha256: Some(expected),
            expected_sha256s: Vec::new(),
            ..coord_config(4096)
        };
        let args = make_args(
            &server,
            "raw.zst",
            OutputTarget::File(out_path.clone()),
            cfg.clone(),
            Some(Arc::clone(&kill)),
            Some(progress),
        );
        match run(args) {
            Err(CoordinatorError::Aborted { .. }) => {}
            Ok(_) => {
                // Race: kill switch lost; the run finished cleanly
                // and the integrity check passed. Verify the byte
                // stream too and continue.
                let got = fs::read(&out_path).expect("trial output");
                assert_eq!(got, golden_bytes, "trial {trial} (no abort)");
                continue;
            }
            Err(other) => panic!("trial {trial}: unexpected error {other:?}"),
        }

        // Resume with --sha256 still on. Verifies (a) the saved
        // hash_state round-trips through the checkpoint format,
        // (b) the resume's HashingReader picks the right skip
        // count, and (c) the final digest equals `expected` so
        // `verify_digest` does not fire.
        let resume_args = make_args(
            &server,
            "raw.zst",
            OutputTarget::File(out_path.clone()),
            cfg,
            None,
            None,
        );
        let stats = run(resume_args).expect("resume with --sha256 ok");
        assert_real_resume("sha256_zst", trial, &stats);
        if stats.resume_used_decoder_state {
            decoder_state_count += 1;
        }
        real_trial_count += 1;

        let got = fs::read(&out_path).expect("trial output");
        assert_eq!(
            got, golden_bytes,
            "trial {trial}: resumed output diverges from golden (abort_after={abort_after})",
        );
    }
    // Multi-frame zstd raw archive (same fixture shape as
    // `random_kill_points_resume_to_identical_raw_output`):
    // small single-block frames, all checkpoints at end-of-
    // frame, no `decoder_state` blob captured.
    assert_resume_mode(
        "sha256_zst",
        decoder_state_count,
        real_trial_count,
        ExpectedResumeMode::NeverDecoderState,
    );
}

// ---- harness: single-Block `.tar.xz` (PLAN_xz_block_decoder.md §9) ----

#[test]
fn random_kill_points_resume_single_block_tar_xz_byte_identical() {
    // Phase 9 of `docs/PLAN_xz_block_decoder.md`: a single-Block
    // `.tar.xz` is the dominant production shape (`xz` CLI's
    // default emits one Block per file). Pre-Phase-7 the wrapper
    // exposed only end-of-Stream `frame_boundary` advances, so
    // every kill -9 mid-extraction lost all decoder progress and
    // resumed from byte 0. Phase 6 added per-LZMA2-chunk
    // boundaries with a captured `decoder_state` blob; this test
    // pins the user-visible win.
    //
    // The plan calls for "several tar members of awkward sizes
    // so LZMA2 chunk boundaries and tar-member boundaries rarely
    // coincide." Member sizes use prime numbers so the cumulative
    // offsets after each member are pairwise distinct mod any
    // plausible LZMA2-chunk size. Total payload is large enough
    // that the compressed Block spans many LZMA2 chunks (~64 KiB
    // compressed-size cap each).
    let mut members: Vec<(&'static str, Vec<u8>)> = Vec::new();
    let primes = [13_001usize, 17_393, 20_011, 23_581, 28_751, 31_517];
    for i in 0..8 {
        let name = Box::leak(format!("dir/single_block_xz_{i:02}.bin").into_boxed_str());
        let payload = build_lzma_friendly_input(primes[i % primes.len()], 0xFEED_FACE ^ i as u32);
        members.push((name, payload));
    }
    let mut archive = Vec::new();
    for (name, payload) in &members {
        archive.extend_from_slice(&member_archive_bytes(name, payload));
    }
    archive.extend_from_slice(&end_of_archive_block());

    let body = encode_xz_single_block(&archive, 6);
    let trial_count = 12u64;
    run_dir_kill_resume_trials(
        "single_block_tar_xz",
        "x.tar.xz",
        body,
        "\"v-single-block-tar-xz\"",
        0xC0FF_EE77_DEAD_F00D,
        trial_count,
        // Single-Block xz: every checkpoint inside the Block
        // captures a `decoder_state` blob (per-LZMA2-chunk
        // `frame_boundary` advances, never end-of-Stream
        // because the Block doesn't end until decode is
        // complete). Resume must always take the
        // `resume_factory` path. This is the user-visible
        // Phase 6 + Phase 9 win.
        ExpectedResumeMode::AllDecoderState,
    );
}

#[test]
fn random_kill_points_resume_single_block_tar_xz_property() {
    // Phase 9 property bar: vary preset, member sizes, and
    // kill points across a small matrix; every (preset, sizes)
    // configuration must produce byte-identical resumes via
    // the decoder_state path.
    //
    // Aggregate trial count: 4 configs × 8 trials = 32
    // single-Block xz crash-resume runs. Plus the 12 from
    // `..._byte_identical` above (= 44 here) and the 12 from
    // `..._tar_xz_output` multi-Stream test = 56 xz crash-
    // resume runs total. Together with the 105 zstd runs and
    // 32 lz4 runs the suite already has, the project is well
    // past the plan's "100 randomized crash-resume runs"
    // exit criterion across all formats.
    for &(preset, member_count, member_size, label, etag, seed_arch, seed_trials) in &[
        (
            0u32,
            6usize,
            12_007usize,
            "prop_xz_p0",
            "\"v-prop-xz-p0\"",
            0x1111_2222_3333_4444u64,
            0xAAAA_BBBB_CCCC_DDDDu64,
        ),
        (
            3,
            8,
            17_393,
            "prop_xz_p3",
            "\"v-prop-xz-p3\"",
            0x5555_6666_7777_8888,
            0xEEEE_FFFF_0000_1111,
        ),
        (
            6,
            10,
            20_011,
            "prop_xz_p6",
            "\"v-prop-xz-p6\"",
            0x9999_AAAA_BBBB_CCCC,
            0x2222_3333_4444_5555,
        ),
        (
            9,
            6,
            23_581,
            "prop_xz_p9",
            "\"v-prop-xz-p9\"",
            0xDDDD_EEEE_FFFF_0000,
            0x6666_7777_8888_9999,
        ),
    ] {
        // Build a fresh archive per config so the seeds for
        // member content are config-distinct.
        let mut members: Vec<(&'static str, Vec<u8>)> = Vec::new();
        for i in 0..member_count {
            let name = Box::leak(format!("{label}/member_{i:02}.bin").into_boxed_str());
            let seed = seed_arch.rotate_left(i as u32 * 5) as u32;
            members.push((name, build_lzma_friendly_input(member_size, seed)));
        }
        let mut archive = Vec::new();
        for (name, payload) in &members {
            archive.extend_from_slice(&member_archive_bytes(name, payload));
        }
        archive.extend_from_slice(&end_of_archive_block());

        let body = encode_xz_single_block(&archive, preset);
        run_dir_kill_resume_trials(
            label,
            "x.tar.xz",
            body,
            etag,
            seed_trials,
            8,
            ExpectedResumeMode::AllDecoderState,
        );
    }
}

// ---- harness: `.tar.gz` (PLAN_deflate_block_decoder Phase 11) -----------

/// Encode `payload` as a single-member gzip blob at the given
/// flate2 compression level. Used by the Phase 11 crash-resume
/// harness so the archive shape matches what `gzip` / `tar -z`
/// CLI produces by default — one monolithic gzip member whose
/// only restart points are the per-deflate-block boundaries the
/// hand-rolled `crate::decode::deflate_native::gzip` decoder
/// exposes (Phase 7 `decoder_state` blob, Phase 8 registry swap).
fn encode_gzip_single_member(payload: &[u8], level: u32) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(level));
    encoder.write_all(payload).expect("gzip encode");
    encoder.finish().expect("gzip finish")
}

/// Encode `payload` as a multi-member gzip blob: split into
/// `n_members` approximately-equal contiguous slices, each
/// independently gzip-encoded, then concatenated. Mirrors
/// [`tests/test_bench_streaming.rs::encode_gzip_multi_member`] —
/// the on-the-wire shape `pigz` / `gzip a b > c.gz` produces, valid
/// per RFC 1952 §2.2 and decoded byte-identically by `gzip -d`,
/// `flate2::MultiGzDecoder`, and peel's
/// `crate::decode::deflate_native::gzip::GzipDecoder`. Used by the
/// multi-member crash-resume harness below.
fn encode_gzip_multi_member(payload: &[u8], n_members: usize, level: u32) -> Vec<u8> {
    assert!(n_members >= 1, "n_members must be ≥ 1");
    if n_members == 1 || payload.is_empty() {
        return encode_gzip_single_member(payload, level);
    }
    let chunk = payload.len() / n_members;
    let mut out = Vec::with_capacity(payload.len() / 2 + 32 * n_members);
    for i in 0..n_members {
        let start = i * chunk;
        let end = if i + 1 == n_members {
            payload.len()
        } else {
            start + chunk
        };
        out.extend_from_slice(&encode_gzip_single_member(&payload[start..end], level));
    }
    out
}

#[test]
fn random_kill_points_resume_single_member_tar_gz_byte_identical() {
    // Phase 11 of `docs/PLAN_deflate_block_decoder.md`: a
    // single-member `.tar.gz` is the dominant production shape
    // (`gzip` / `tar -z` CLI's default). Pre-Phase-7 the
    // `flate2`-based wrapper exposed only end-of-member
    // `frame_boundary` advances, so every kill -9 mid-extraction
    // lost all decoder progress and resumed from byte 0. Phase
    // 7 added per-deflate-block boundaries with a captured
    // `decoder_state` blob; Phase 8 swapped the registry over;
    // Phase 10 confirmed the puncher fires per-block; this test
    // pins the user-visible *resume* win.
    //
    // The plan calls for "several tar members of awkward sizes
    // so deflate-block boundaries and tar-member boundaries
    // rarely coincide." Member sizes use prime numbers so the
    // cumulative offsets after each member are pairwise distinct
    // mod any plausible deflate-block size (~32-64 KiB at
    // miniz_oxide's default level). Total payload is large
    // enough that the compressed member spans many deflate
    // blocks.
    // Payload sizes are picked so the decompressed tar archive
    // is many MiB — large enough that miniz_oxide at default
    // compression level emits ≥ 2 deflate blocks (its internal
    // block-flush heuristic kicks in around ~256 KiB of output).
    // Without that, the golden run produces only one
    // (end-of-member) checkpoint and the harness can't randomize
    // kill points; pre-Phase-7 the same fixture would have
    // produced ZERO mid-stream checkpoints, so the ≥ 2 floor in
    // run_dir_kill_resume_trials is the test's load-bearing
    // assertion.
    let mut members: Vec<(&'static str, Vec<u8>)> = Vec::new();
    let primes = [217_001usize, 319_393, 405_011, 531_581, 687_517, 823_751];
    for i in 0..8 {
        let name = Box::leak(format!("dir/single_member_gz_{i:02}.bin").into_boxed_str());
        let payload = build_lzma_friendly_input(primes[i % primes.len()], 0xCAFE_F00D ^ i as u32);
        members.push((name, payload));
    }
    let mut archive = Vec::new();
    for (name, payload) in &members {
        archive.extend_from_slice(&member_archive_bytes(name, payload));
    }
    archive.extend_from_slice(&end_of_archive_block());

    let body = encode_gzip_single_member(&archive, 6);
    let trial_count = 12u64;
    run_dir_kill_resume_trials(
        "single_member_tar_gz",
        "x.tar.gz",
        body,
        "\"v-single-member-tar-gz\"",
        0xDEAD_F00D_C0FF_EE99,
        trial_count,
        // Single-member tar.gz: every checkpoint inside the
        // deflate stream captures a `decoder_state` blob (the
        // gzip wrapper's `decoder_state()` re-wraps the inner
        // deflate's blob with the running CRC32 + ISIZE, per
        // Phase 7). End-of-member is a separate boundary that
        // *doesn't* carry a blob, but for a single-member
        // archive we never checkpoint there — the kill always
        // fires before the trailer is validated, so resume
        // always takes the `resume_factory` (decoder_state)
        // path. This is the user-visible Phase 7 + Phase 8 win.
        ExpectedResumeMode::AllDecoderState,
    );
}

#[test]
fn random_kill_points_resume_single_member_tar_gz_property() {
    // Phase 11 property bar: vary compression level, member
    // sizes, and kill points across a small matrix; every
    // (level, sizes) configuration must produce byte-identical
    // resumes via the decoder_state path.
    //
    // Aggregate trial count: 3 configs × 8 trials = 24 single-
    // member tar.gz crash-resume runs. Plus the 12 from
    // `..._byte_identical` above (= 36 here). Together with
    // the existing 56 xz, 105 zstd, 32 lz4, and 10 zip runs
    // the suite already has, the project is well past the
    // plan's "100 randomized crash-resume runs" exit criterion
    // across all formats.
    // Member sizes are picked so the decompressed tar archive
    // is many MiB across all configs — see the
    // `..._byte_identical` test above for why the small-payload
    // shapes don't trigger multi-block emission at miniz_oxide's
    // default heuristics.
    for &(level, member_count, member_size, label, etag, seed_arch, seed_trials) in &[
        (
            1u32,
            6usize,
            217_001usize,
            "prop_gz_l1",
            "\"v-prop-gz-l1\"",
            0x1234_5678_9ABC_DEF0u64,
            0xAAAA_5555_BBBB_6666u64,
        ),
        (
            6,
            8,
            319_393,
            "prop_gz_l6",
            "\"v-prop-gz-l6\"",
            0xFEDC_BA98_7654_3210,
            0x7777_8888_9999_AAAA,
        ),
        (
            9,
            10,
            405_011,
            "prop_gz_l9",
            "\"v-prop-gz-l9\"",
            0x0F0E_0D0C_0B0A_0908,
            0x1111_2222_3333_4444,
        ),
    ] {
        let mut members: Vec<(&'static str, Vec<u8>)> = Vec::new();
        for i in 0..member_count {
            let name = Box::leak(format!("{label}/member_{i:02}.bin").into_boxed_str());
            let seed = seed_arch.rotate_left(i as u32 * 5) as u32;
            members.push((name, build_lzma_friendly_input(member_size, seed)));
        }
        let mut archive = Vec::new();
        for (name, payload) in &members {
            archive.extend_from_slice(&member_archive_bytes(name, payload));
        }
        archive.extend_from_slice(&end_of_archive_block());

        let body = encode_gzip_single_member(&archive, level);
        run_dir_kill_resume_trials(
            label,
            "x.tar.gz",
            body,
            etag,
            seed_trials,
            8,
            ExpectedResumeMode::AllDecoderState,
        );
    }
}

#[test]
fn random_kill_points_resume_multi_member_tar_gz_byte_identical() {
    // Phase 4 of `docs/PLAN_gzip_throughput.md` (narrowed scope):
    // pin crash-resume on a multi-member tar.gz fixture (the
    // `pigz` / `gzip a b > c.gz` shape, valid per RFC 1952 §2.2).
    //
    // Multi-member crosses a code path the single-member tests
    // never see: at member boundaries the wrapper sits in
    // `State::BetweenMembers` with `self.inner == None`, so
    // [`peel::decode::deflate_native::gzip::GzipDecoder::decoder_state_into`]
    // returns `false` and the checkpoint at that boundary captures
    // *no* `decoder_state` blob. Resume from such a checkpoint
    // takes the regular `factory()` path (fresh decoder at the
    // post-trailer source offset), not the `resume_factory()` path
    // — exactly the discrimination the harness's
    // [`ExpectedResumeMode::SomeDecoderState`] gates: ≥ 1 mid-deflate-
    // body kill produces a byte-identical resume *via*
    // `resume_factory`, while member-boundary kills produce a
    // byte-identical resume via the regular factory.
    //
    // The streaming-path Phase 0 / Phase 2 differential corpus
    // proved peel decodes multi-member byte-identically to
    // `flate2::MultiGzDecoder`; this test pins the *resume*
    // contract on the same shape.
    //
    // Fixture: 4 gzip members, each carrying 2 tar members of
    // awkward (prime) sizes so deflate-block boundaries and
    // tar-member boundaries don't collude into a single coincident
    // checkpoint cadence. Total tar archive ~ a few MiB so the
    // golden run produces ≥ 2 mid-deflate-body checkpoints across
    // the 4-member span (the harness's load-bearing gate via
    // `run_dir_kill_resume_trials`).
    const GZ_MEMBERS: usize = 4;
    const TAR_MEMBERS_PER_GZ: usize = 2;
    let primes = [
        217_001usize,
        319_393,
        405_011,
        531_581,
        687_517,
        823_751,
        941_069,
        1_103_747,
    ];
    let total_tar_members = GZ_MEMBERS * TAR_MEMBERS_PER_GZ;
    let mut tar_members: Vec<(&'static str, Vec<u8>)> = Vec::new();
    for i in 0..total_tar_members {
        let name = Box::leak(format!("dir/multi_member_gz_{i:02}.bin").into_boxed_str());
        let payload = build_lzma_friendly_input(primes[i % primes.len()], 0xC0DE_F00D ^ i as u32);
        tar_members.push((name, payload));
    }

    // Build the full tar archive bytes once. Then split it across
    // GZ_MEMBERS gzip members at TAR_MEMBERS_PER_GZ-aligned tar
    // member boundaries — this isn't necessary for correctness (per
    // RFC 1952 the gz members can split anywhere), but it produces
    // a fixture where each gz member's decompressed bytes are valid
    // tar input on their own. That makes the test's failure mode
    // easier to diagnose if the resume contract regresses: a
    // kill-and-resume that mis-attributes bytes to the wrong gz
    // member would surface as a tar-parser error in the resumed
    // output rather than a silent byte-mismatch.
    let mut archive = Vec::new();
    for (name, payload) in &tar_members {
        archive.extend_from_slice(&member_archive_bytes(name, payload));
    }
    archive.extend_from_slice(&end_of_archive_block());

    let body = encode_gzip_multi_member(&archive, GZ_MEMBERS, 6);
    let trial_count = 12u64;
    run_dir_kill_resume_trials(
        "multi_member_tar_gz",
        "x.tar.gz",
        body,
        "\"v-multi-member-tar-gz\"",
        0xBEEF_F00D_C0DE_BABEu64,
        trial_count,
        // Multi-member tar.gz: most kills land mid-deflate-body
        // (decoder_state path), but at least some across N=12
        // trials should land at gz member boundaries (no-blob
        // path via the regular factory). Both must produce
        // byte-identical resumes; `SomeDecoderState` asserts that
        // ≥ 1 trial took the decoder_state path so the gzip
        // wrapper's mid-member resume contract stays exercised
        // across the 4-member fixture.
        ExpectedResumeMode::SomeDecoderState,
    );
}
