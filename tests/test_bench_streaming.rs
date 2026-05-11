//! Comparative streaming-extraction benchmarks: `peel` vs `curl | tool`.
//!
//! For every supported source format the suite builds a representative
//! archive in memory, serves it from the in-process `MockServer`, then
//! times two extraction strategies against the same byte stream:
//!
//! 1. `peel::coordinator::run` driving the full pipeline (parallel
//!    ranged GETs → streaming decode → sink → punch).
//! 2. The traditional baseline a user would type into a shell —
//!    `curl URL | <decompressor> | tar -xf -` (or the format-specific
//!    equivalent), spawned via `bash -c` so the pipe stages match what
//!    a human invocation would do.
//!
//! Both runs target a fresh empty directory (or output file). The
//! reference payload is verified for correctness on both sides; the
//! durations are then printed in a tab-separated row keyed by format.
//!
//! ## How to run
//!
//! These tests are `#[ignore]`d so `cargo test` skips them. Invoke
//! explicitly, in `--release` for representative numbers:
//!
//! ```text
//! cargo test --release --test test_bench_streaming -- --ignored --nocapture
//! ```
//!
//! The `--nocapture` flag is what makes the comparison rows appear on
//! stdout. Tests run sequentially via `--test-threads=1` is *not*
//! required (each test owns its mock server and tempdir), but
//! ad-hoc-running them serially produces less noisy timings:
//!
//! ```text
//! cargo test --release --test test_bench_streaming -- --ignored --nocapture --test-threads=1
//! ```
//!
//! ## Tool availability
//!
//! Each baseline shells out to a particular CLI tool (`curl`, `tar`,
//! `zstd`, `xz`, `lz4`, `unzip`). When a tool is missing from `PATH`
//! the corresponding benchmark prints a `[skip]` line and returns
//! cleanly rather than failing — the benchmark grid is meant to run on
//! whatever tools the developer happens to have installed.

#![cfg(unix)]

use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

use peel::coordinator::{run, CoordinatorConfig, OutputTarget, RunArgs, RunStats};
use peel::decode::DecoderRegistry;
use peel::download::RetryConfig;
use peel::http::{Client, ClientConfig};

#[path = "support/mod.rs"]
mod support;

use support::mock_server::{MockRequest, MockResponse, MockServer};
#[cfg(feature = "rar")]
use support::rar_bench_fixtures::{
    ensure_rar3_stored, ensure_rar5_stored, rar3_encoder_present, rar5_encoder_present, unrar_path,
};
use support::sevenz_fixtures::build_copy_sevenz;
use support::tar_fixtures::build_simple_archive;
use support::zip_fixtures::{build_zip, ZipEntrySpec};

// ---- harness helpers --------------------------------------------------

static UNIQ: AtomicU64 = AtomicU64::new(0);

fn unique_dir(label: &str) -> PathBuf {
    let pid = std::process::id();
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("peel_bench_{label}_{pid}_{nanos}_{n}"));
    fs::create_dir_all(&p).expect("create unique_dir");
    p
}

struct CleanupDir(PathBuf);
impl Drop for CleanupDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// True if `name` resolves on `PATH`.
fn tool_present(name: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {name} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Build a mostly-incompressible payload via an LCG so the on-the-wire
/// size of every codec stays close to the raw payload size — that
/// keeps "throughput" numbers from being dominated by a codec with a
/// pathologically high compression ratio on a degenerate input.
fn random_bytes(seed: u64, len: usize) -> Vec<u8> {
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

// ---- codec encoders (in-process) --------------------------------------

fn encode_zstd(payload: &[u8]) -> Vec<u8> {
    zstd::encode_all(payload, 1).expect("encode zstd")
}

fn encode_identity(payload: &[u8]) -> Vec<u8> {
    payload.to_vec()
}

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

/// Single-member gzip blob at the default compression level — the
/// shape `gzip` / `tar -z` CLI produces, and which peel's hand-rolled
/// [`peel::decode::deflate_native::gzip`] backend decodes.
fn encode_gzip(payload: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut encoder = GzEncoder::new(
        Vec::with_capacity(payload.len() / 2 + 256),
        Compression::default(),
    );
    encoder.write_all(payload).expect("encode gzip");
    encoder.finish().expect("finish gzip")
}

/// Multi-member gzip blob: `payload` split into `n_members`
/// approximately-equal contiguous slices, each encoded as a
/// stand-alone gzip member, then concatenated. Per RFC 1952 §2.2 this
/// is a valid gzip stream (`gunzip -c`, `gzip -d`, `flate2`'s
/// `MultiGzDecoder`, and peel's [`peel::decode::deflate_native::gzip`]
/// all decode it back to `payload`).
///
/// This is the on-the-wire shape `pigz` / `gzip a b > c.gz` produces.
/// Phase 0 of `docs/PLAN_gzip_throughput.md`: the round-one parallel-
/// member decoder targets exactly this shape; baseline `gzip -d` does
/// not parallelize across members but does decode them sequentially,
/// so the same baseline pipe row applies.
/// Pick a member count for a multi-member gzip fixture given the
/// total payload size. Targets ~32 MiB per member (the size `pigz -B
/// 32M` produces and the size at which member-discovery overhead
/// amortizes well over the deflate work). Caps at 8 members so the
/// bench grid's smaller cells don't fragment to triviality, and
/// requires ≥ 2 MiB per member so a 4-member 8 MiB fixture still has
/// non-trivial deflate bodies. Returns 1 (i.e. fall back to the
/// single-member row) when the payload is too small to split.
fn pick_gz_member_count(payload_bytes: usize) -> usize {
    const TARGET_MEMBER_BYTES: usize = 32 * 1024 * 1024;
    const MIN_MEMBER_BYTES: usize = 2 * 1024 * 1024;
    const MAX_MEMBERS: usize = 8;
    if payload_bytes < 2 * MIN_MEMBER_BYTES {
        return 1;
    }
    let by_target = payload_bytes.div_ceil(TARGET_MEMBER_BYTES).max(2);
    let by_floor = payload_bytes / MIN_MEMBER_BYTES;
    by_target.min(by_floor).clamp(2, MAX_MEMBERS)
}

fn encode_gzip_multi_member(payload: &[u8], n_members: usize) -> Vec<u8> {
    assert!(n_members >= 1, "n_members must be ≥ 1");
    if n_members == 1 || payload.is_empty() {
        return encode_gzip(payload);
    }
    let chunk = payload.len() / n_members;
    // Last member absorbs the remainder so the input length round-trips
    // exactly; with `chunk = len / n` the first `n-1` members are
    // `chunk` bytes and the last is `len - (n-1)*chunk`.
    let mut out = Vec::with_capacity(payload.len() / 2 + 32 * n_members);
    for i in 0..n_members {
        let start = i * chunk;
        let end = if i + 1 == n_members {
            payload.len()
        } else {
            start + chunk
        };
        out.extend_from_slice(&encode_gzip(&payload[start..end]));
    }
    out
}

/// Single-frame, single-block, *uncompressed* LZ4 archive — the
/// minimum-viable shape `peel::decode::lz4` accepts and which `lz4 -d`
/// also decodes. Re-implemented here (rather than depending on a
/// frame-format encoder crate) to keep the benchmark independent of
/// dev-dep choices made elsewhere.
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

    // BD byte selects the per-block max size. Bits 4-6 = 7 selects
    // 4 MiB blocks, the largest the LZ4 Frame Format permits; we
    // chunk the payload into ≤ 4 MiB blocks and write each as a
    // separate uncompressed block (high bit of the size prefix set).
    const BLOCK_MAX: usize = 4 * 1024 * 1024;
    let mut out = Vec::new();
    out.extend_from_slice(&0x184D_2204u32.to_le_bytes());
    let flg: u8 = 0b0110_0000;
    let bd: u8 = 0b0111_0000;
    out.push(flg);
    out.push(bd);
    let hc = ((xxh32(&[flg, bd]) >> 8) & 0xff) as u8;
    out.push(hc);
    for chunk in payload.chunks(BLOCK_MAX) {
        let header = (chunk.len() as u32) | 0x8000_0000;
        out.extend_from_slice(&header.to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&[0u8; 4]);
    out
}

// ---- HTTP serving -----------------------------------------------------

fn ok_handler(body: Vec<u8>) -> impl Fn(&MockRequest, u64) -> MockResponse + Send + Sync + 'static {
    move |req, _| serve(req, &body)
}

fn serve(req: &MockRequest, body: &[u8]) -> MockResponse {
    let head_headers: Vec<(String, String)> = vec![
        ("Content-Length".into(), body.len().to_string()),
        ("Accept-Ranges".into(), "bytes".into()),
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
            let h = vec![(
                "Content-Range".into(),
                format!("bytes {a}-{b}/{}", body.len()),
            )];
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

// ---- peel-side glue ---------------------------------------------------

fn build_client() -> Client {
    Client::with_config(ClientConfig {
        timeout: Duration::from_secs(30),
        ..ClientConfig::default()
    })
    .expect("client constructs")
}

fn coord_config() -> CoordinatorConfig {
    // Mirrors `CoordinatorConfig::default()` for the cadence-relevant
    // fields (`checkpoint_min_bytes` = 8 MiB, `checkpoint_min_interval`
    // = 2 s, `checkpoint_target_interval` = 200 ms) so the bench grid
    // measures production behavior. An earlier revision used a 50 ms
    // time floor to stress resume granularity; the result was up to
    // ~189 checkpoints on long-running tar.xz runs (vs ~26 in
    // production) and a corresponding inflation of the bench's
    // `tar.xz` ratio. `PLAN_xz_bench_profile.md` Phase 1 + the
    // bench cadence audit walk through the math.
    CoordinatorConfig {
        chunk_size: 1 << 20, // 1 MiB
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
    }
}

fn run_peel(server: &MockServer, suffix: &str, output: OutputTarget) -> RunStats {
    let args = RunArgs {
        url: format!("{}/{suffix}", server.base_url()),
        additional_urls: Vec::new(),
        output,
        config: coord_config(),
        client: build_client(),
        registry: DecoderRegistry::with_defaults(),
        progress: None,
        progress_state: None,
        kill_switch: None,
        io_backend: None,
    };
    run(args).expect("peel run succeeds")
}

// ---- baseline pipeline (curl | … | tar) -------------------------------

/// Run `bash -c <pipeline>` and return wall-clock duration plus stderr
/// for diagnosis on failure. The pipeline is given the URL via the
/// `URL` env var so callers don't have to escape it into the script.
fn time_pipeline(url: &str, pipeline: &str) -> Duration {
    let started = Instant::now();
    let output = Command::new("bash")
        .arg("-eu")
        .arg("-o")
        .arg("pipefail")
        .arg("-c")
        .arg(pipeline)
        .env("URL", url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn bash for baseline pipeline");
    let elapsed = started.elapsed();
    if !output.status.success() {
        panic!(
            "baseline pipeline exited {}: stderr=\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    elapsed
}

// ---- result reporting -------------------------------------------------

struct BenchRow {
    format: &'static str,
    payload_bytes: u64,
    on_wire_bytes: u64,
    peel: Duration,
    baseline: Duration,
    baseline_tools: &'static str,
}

impl BenchRow {
    fn print(&self) {
        let mib = (self.payload_bytes as f64) / (1024.0 * 1024.0);
        let on_wire_mib = (self.on_wire_bytes as f64) / (1024.0 * 1024.0);
        let peel_s = self.peel.as_secs_f64();
        let base_s = self.baseline.as_secs_f64();
        let ratio = if base_s > 0.0 { peel_s / base_s } else { 0.0 };
        println!(
            "[bench] {fmt:<10} payload={mib:6.1} MiB  wire={wire:6.1} MiB  peel={peel:6.3}s  {tools}={base:6.3}s  ratio={ratio:.2}x",
            fmt = self.format,
            mib = mib,
            wire = on_wire_mib,
            peel = peel_s,
            tools = self.baseline_tools,
            base = base_s,
            ratio = ratio,
        );
    }
}

fn skip(format: &str, missing: &str) {
    println!("[bench] {format:<10} [skip] {missing} not on PATH");
}

// ---- payload size knob -------------------------------------------------

/// 256 MiB raw payload is large enough that wall-clock differences are
/// resolvable on a fast loopback yet small enough that the full grid
/// completes in a few seconds on a developer laptop.
const PAYLOAD_BYTES: usize = 256 * 1024 * 1024;

/// Build a tar archive whose raw byte total is approximately
/// `PAYLOAD_BYTES`, split across a handful of files so per-member
/// overhead is exercised but doesn't dominate.
fn build_tar_payload() -> Vec<u8> {
    const FILES: usize = 8;
    let per = PAYLOAD_BYTES / FILES;
    let names: Vec<String> = (0..FILES)
        .map(|i| format!("data/file_{i:02}.bin"))
        .collect();
    let bodies: Vec<Vec<u8>> = (0..FILES)
        .map(|i| random_bytes(0xBEEF + i as u64, per))
        .collect();
    let pairs: Vec<(&str, &[u8])> = names
        .iter()
        .zip(bodies.iter())
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    build_simple_archive(&pairs)
}

fn assert_extracted_tar_matches(dir: &std::path::Path, archive: &[u8]) {
    // The fixture layout is the same `data/file_NN.bin` set used by
    // `build_tar_payload`. We validate by re-deriving the expected
    // bodies and reading them back rather than parsing the archive.
    const FILES: usize = 8;
    let per = PAYLOAD_BYTES / FILES;
    let _ = archive; // kept in signature to make the relationship explicit
    for i in 0..FILES {
        let path = dir.join(format!("data/file_{i:02}.bin"));
        let actual = fs::read(&path).expect("extracted file present");
        let expected = random_bytes(0xBEEF + i as u64, per);
        assert_eq!(actual.len(), expected.len(), "size mismatch on file {i:02}");
        assert_eq!(actual, expected, "contents mismatch on file {i:02}");
    }
}

// ---- benchmarks --------------------------------------------------------

#[test]
#[ignore = "benchmark; opt-in via --ignored"]
fn bench_raw_zstd_to_file() {
    if !tool_present("curl") {
        skip("zstd-raw", "curl");
        return;
    }
    if !tool_present("zstd") {
        skip("zstd-raw", "zstd");
        return;
    }

    let payload = random_bytes(0xC0FFEE, PAYLOAD_BYTES);
    let body = encode_zstd(&payload);
    let url_suffix = "data.zst";

    let server = MockServer::start(ok_handler(body.clone()));
    let url = format!("{}/{url_suffix}", server.base_url());

    // ---- peel: stream zstd into a single output file ----------------
    let work = unique_dir("zstd_raw_peel");
    let _g_peel = CleanupDir(work.clone());
    let out_file = work.join("out.bin");
    let started = Instant::now();
    let stats = run_peel(&server, url_suffix, OutputTarget::File(out_file.clone()));
    let peel_elapsed = started.elapsed();
    assert_eq!(stats.extraction.bytes_out, payload.len() as u64);
    assert_eq!(fs::read(&out_file).expect("read peel output"), payload);

    // ---- baseline: curl | zstd -d > file ----------------------------
    let work_b = unique_dir("zstd_raw_curl");
    let _g_base = CleanupDir(work_b.clone());
    let base_file = work_b.join("out.bin");
    let pipeline = format!(
        r#"curl -sS "$URL" | zstd -d -q -o {}"#,
        shell_quote(&base_file)
    );
    let base_elapsed = time_pipeline(&url, &pipeline);
    assert_eq!(fs::read(&base_file).expect("read baseline output"), payload);

    BenchRow {
        format: "zstd-raw",
        payload_bytes: payload.len() as u64,
        on_wire_bytes: body.len() as u64,
        peel: peel_elapsed,
        baseline: base_elapsed,
        baseline_tools: "curl|zstd",
    }
    .print();
}

#[test]
#[ignore = "benchmark; opt-in via --ignored"]
fn bench_tar_zstd_extraction() {
    if !tool_present("curl") {
        skip("tar.zst", "curl");
        return;
    }
    if !tool_present("zstd") {
        skip("tar.zst", "zstd");
        return;
    }
    if !tool_present("tar") {
        skip("tar.zst", "tar");
        return;
    }

    let archive = build_tar_payload();
    let body = encode_zstd(&archive);
    let suffix = "bundle.tar.zst";

    let server = MockServer::start(ok_handler(body.clone()));
    let url = format!("{}/{suffix}", server.base_url());

    let work_p = unique_dir("tar_zst_peel");
    let _g_p = CleanupDir(work_p.clone());
    let started = Instant::now();
    let stats = run_peel(&server, suffix, OutputTarget::Dir(work_p.clone()));
    let peel_elapsed = started.elapsed();
    assert_eq!(stats.extraction.bytes_out, archive.len() as u64);
    assert_extracted_tar_matches(&work_p, &archive);

    let work_b = unique_dir("tar_zst_curl");
    let _g_b = CleanupDir(work_b.clone());
    let pipeline = format!(
        r#"curl -sS "$URL" | zstd -d -q | tar -xf - -C {}"#,
        shell_quote(&work_b)
    );
    let base_elapsed = time_pipeline(&url, &pipeline);
    assert_extracted_tar_matches(&work_b, &archive);

    BenchRow {
        format: "tar.zst",
        payload_bytes: archive.len() as u64,
        on_wire_bytes: body.len() as u64,
        peel: peel_elapsed,
        baseline: base_elapsed,
        baseline_tools: "curl|zstd|tar",
    }
    .print();
}

#[test]
#[ignore = "benchmark; opt-in via --ignored"]
fn bench_tar_xz_extraction() {
    if !tool_present("curl") {
        skip("tar.xz", "curl");
        return;
    }
    if !tool_present("xz") {
        skip("tar.xz", "xz");
        return;
    }
    if !tool_present("tar") {
        skip("tar.xz", "tar");
        return;
    }

    let archive = build_tar_payload();
    let body = encode_xz(&archive);
    let suffix = "bundle.tar.xz";

    let server = MockServer::start(ok_handler(body.clone()));
    let url = format!("{}/{suffix}", server.base_url());

    let work_p = unique_dir("tar_xz_peel");
    let _g_p = CleanupDir(work_p.clone());
    let started = Instant::now();
    let stats = run_peel(&server, suffix, OutputTarget::Dir(work_p.clone()));
    let peel_elapsed = started.elapsed();
    assert_eq!(stats.extraction.bytes_out, archive.len() as u64);
    assert_extracted_tar_matches(&work_p, &archive);

    let work_b = unique_dir("tar_xz_curl");
    let _g_b = CleanupDir(work_b.clone());
    let pipeline = format!(
        r#"curl -sS "$URL" | xz -d -q | tar -xf - -C {}"#,
        shell_quote(&work_b)
    );
    let base_elapsed = time_pipeline(&url, &pipeline);
    assert_extracted_tar_matches(&work_b, &archive);

    BenchRow {
        format: "tar.xz",
        payload_bytes: archive.len() as u64,
        on_wire_bytes: body.len() as u64,
        peel: peel_elapsed,
        baseline: base_elapsed,
        baseline_tools: "curl|xz|tar",
    }
    .print();
}

#[test]
#[ignore = "benchmark; opt-in via --ignored"]
fn bench_tar_lz4_extraction() {
    if !tool_present("curl") {
        skip("tar.lz4", "curl");
        return;
    }
    if !tool_present("lz4") {
        skip("tar.lz4", "lz4");
        return;
    }
    if !tool_present("tar") {
        skip("tar.lz4", "tar");
        return;
    }

    let archive = build_tar_payload();
    // Single uncompressed lz4 frame: peel and `lz4 -d` both accept it,
    // and the on-wire size matches the tar's raw bytes (so this row is
    // measuring framing/pipe overhead more than a compression ratio).
    let body = encode_lz4_uncompressed_frame(&archive);
    let suffix = "bundle.tar.lz4";

    let server = MockServer::start(ok_handler(body.clone()));
    let url = format!("{}/{suffix}", server.base_url());

    let work_p = unique_dir("tar_lz4_peel");
    let _g_p = CleanupDir(work_p.clone());
    let started = Instant::now();
    let stats = run_peel(&server, suffix, OutputTarget::Dir(work_p.clone()));
    let peel_elapsed = started.elapsed();
    assert_eq!(stats.extraction.bytes_out, archive.len() as u64);
    assert_extracted_tar_matches(&work_p, &archive);

    let work_b = unique_dir("tar_lz4_curl");
    let _g_b = CleanupDir(work_b.clone());
    let pipeline = format!(
        r#"curl -sS "$URL" | lz4 -d -q | tar -xf - -C {}"#,
        shell_quote(&work_b)
    );
    let base_elapsed = time_pipeline(&url, &pipeline);
    assert_extracted_tar_matches(&work_b, &archive);

    BenchRow {
        format: "tar.lz4",
        payload_bytes: archive.len() as u64,
        on_wire_bytes: body.len() as u64,
        peel: peel_elapsed,
        baseline: base_elapsed,
        baseline_tools: "curl|lz4|tar",
    }
    .print();
}

#[test]
#[ignore = "benchmark; opt-in via --ignored"]
fn bench_plain_tar_extraction() {
    if !tool_present("curl") {
        skip("tar", "curl");
        return;
    }
    if !tool_present("tar") {
        skip("tar", "tar");
        return;
    }

    let archive = build_tar_payload();
    let suffix = "bundle.tar";

    let server = MockServer::start(ok_handler(archive.clone()));
    let url = format!("{}/{suffix}", server.base_url());

    let work_p = unique_dir("tar_plain_peel");
    let _g_p = CleanupDir(work_p.clone());
    let started = Instant::now();
    let stats = run_peel(&server, suffix, OutputTarget::Dir(work_p.clone()));
    let peel_elapsed = started.elapsed();
    assert_eq!(stats.extraction.bytes_out, archive.len() as u64);
    assert_extracted_tar_matches(&work_p, &archive);

    let work_b = unique_dir("tar_plain_curl");
    let _g_b = CleanupDir(work_b.clone());
    let pipeline = format!(r#"curl -sS "$URL" | tar -xf - -C {}"#, shell_quote(&work_b));
    let base_elapsed = time_pipeline(&url, &pipeline);
    assert_extracted_tar_matches(&work_b, &archive);

    BenchRow {
        format: "tar",
        payload_bytes: archive.len() as u64,
        on_wire_bytes: archive.len() as u64,
        peel: peel_elapsed,
        baseline: base_elapsed,
        baseline_tools: "curl|tar",
    }
    .print();
}

#[test]
#[ignore = "benchmark; opt-in via --ignored"]
fn bench_zip_extraction() {
    if !tool_present("curl") {
        skip("zip", "curl");
        return;
    }
    if !tool_present("unzip") {
        skip("zip", "unzip");
        return;
    }

    // Build a multi-entry ZIP with the same logical layout as the
    // tar fixture so the on-disk-output check below can reuse the same
    // verifier. STORED entries keep the on-wire size dominated by the
    // raw payloads (matching the lz4 row's framing-only spirit).
    const FILES: usize = 8;
    let per = PAYLOAD_BYTES / FILES;
    let entries: Vec<ZipEntrySpec> = (0..FILES)
        .map(|i| {
            ZipEntrySpec::stored(
                format!("data/file_{i:02}.bin"),
                random_bytes(0xBEEF + i as u64, per),
            )
        })
        .collect();
    let body = build_zip(&entries);
    let suffix = "bundle.zip";

    let server = MockServer::start(ok_handler(body.clone()));
    let url = format!("{}/{suffix}", server.base_url());

    let work_p = unique_dir("zip_peel");
    let _g_p = CleanupDir(work_p.clone());
    let started = Instant::now();
    let _stats = run_peel(&server, suffix, OutputTarget::Dir(work_p.clone()));
    let peel_elapsed = started.elapsed();
    assert_extracted_tar_matches(&work_p, &[]);

    // ZIP's central directory lives at the *end* of the archive, so a
    // streaming `curl | unzip` pipe is not a valid baseline. The
    // canonical user-typed equivalent is download-then-extract; we
    // measure that as the comparison.
    let work_b = unique_dir("zip_curl");
    let _g_b = CleanupDir(work_b.clone());
    let zip_path = work_b.join("bundle.zip");
    let extract_dir = work_b.join("out");
    fs::create_dir_all(&extract_dir).expect("mkdir extract");
    let pipeline = format!(
        r#"curl -sS -o {zip} "$URL" && unzip -q {zip} -d {dir}"#,
        zip = shell_quote(&zip_path),
        dir = shell_quote(&extract_dir),
    );
    let base_elapsed = time_pipeline(&url, &pipeline);
    assert_extracted_tar_matches(&extract_dir, &[]);

    BenchRow {
        format: "zip",
        payload_bytes: (PAYLOAD_BYTES) as u64,
        on_wire_bytes: body.len() as u64,
        peel: peel_elapsed,
        baseline: base_elapsed,
        baseline_tools: "curl+unzip",
    }
    .print();
}

// ---- diagnostic: where does peel's tar overhead come from? -----------

/// Run the plain-tar payload under several `CoordinatorConfig`
/// variants and print a per-phase breakdown for each. The intent is
/// to attribute the gap between `peel` and `curl|tar` (visible in
/// `bench_plain_tar_extraction`) to specific knobs:
///
/// * `default` — the same config every other benchmark uses (4
///   workers, 1 MiB chunks, adaptive chunk-sizing on, checkpoints
///   every 8 MiB, 2 ms reader poll).
/// * `single_worker_one_chunk` — one worker, chunk size = entire
///   body, adaptive chunk-sizing off. Eliminates ranged-GET
///   amplification (HEAD + 1 GET, like `curl`).
/// * `no_checkpoints` — checkpoint floor raised so high it never
///   fires. Isolates checkpoint-write cost.
/// * `tight_reader_poll` — reader_poll_interval reduced to
///   `Duration::ZERO`. Isolates the polling-induced wait.
///
/// The breakdown columns are:
///
/// * `download` — `RunStats::download.elapsed` (network + part-file writes).
/// * `decode`   — `ExtractionStats::decode_time` (decode minus sink-write).
/// * `write`    — `ExtractionStats::write_time` (sink writes only).
/// * `punch`    — `ExtractionStats::punch_time` (hole-punch syscalls;
///   near-zero on macOS where the puncher is the noop fallback).
/// * `total`    — `RunStats::elapsed` (wall-clock for the whole run).
///
/// Sums of the per-phase columns are *less than* `total` because
/// download and extraction overlap; the gap is the streaming-overlap
/// budget peel is supposed to deliver.
#[test]
#[ignore = "diagnostic; opt-in via --ignored"]
fn diag_plain_tar_breakdown() {
    let archive = build_tar_payload();
    let suffix = "bundle.tar";
    let server = MockServer::start(ok_handler(archive.clone()));

    let body_len = archive.len() as u64;
    type VariantBuilder = fn(u64) -> CoordinatorConfig;
    let variants: &[(&str, VariantBuilder)] = &[
        ("default                ", |_| coord_config()),
        ("single_worker_one_chunk", |body| {
            let mut c = coord_config();
            c.workers = 1;
            c.chunk_size = body;
            c.adaptive_chunk_size = false;
            c
        }),
        ("no_checkpoints         ", |_| {
            let mut c = coord_config();
            c.checkpoint_min_bytes = u64::MAX;
            c.checkpoint_min_interval = Duration::from_secs(60 * 60);
            c
        }),
        ("tight_reader_poll      ", |_| {
            let mut c = coord_config();
            c.reader_poll_interval = Duration::ZERO;
            c
        }),
    ];

    println!(
        "[diag] {:24} {:>9} {:>9} {:>9} {:>9} {:>9}  chunks",
        "variant", "download", "decode", "write", "punch", "total"
    );
    for (label, build) in variants {
        let work = unique_dir(&format!("diag_{}", label.trim()));
        let _g = CleanupDir(work.clone());
        let args = RunArgs {
            url: format!("{}/{suffix}", server.base_url()),
            additional_urls: Vec::new(),
            output: OutputTarget::Dir(work.clone()),
            config: build(body_len),
            client: build_client(),
            registry: DecoderRegistry::with_defaults(),
            progress: None,
            progress_state: None,
            kill_switch: None,
            io_backend: None,
        };
        let stats = run(args).expect("peel run succeeds");
        let chunks = stats.download.chunks_completed;
        println!(
            "[diag] {label} {dl:>8.3}s {dec:>8.3}s {wr:>8.3}s {pn:>8.3}s {tot:>8.3}s  {chunks}",
            dl = stats.download.elapsed.as_secs_f64(),
            dec = stats.extraction.decode_time.as_secs_f64(),
            wr = stats.extraction.write_time.as_secs_f64(),
            pn = stats.extraction.punch_time.as_secs_f64(),
            tot = stats.elapsed.as_secs_f64(),
        );
        assert_extracted_tar_matches(&work, &archive);
    }
}

// ---- diagnostic: tar.xz pipeline overhead breakdown ------------------

/// Phase 0b of `docs/PLAN_xz_throughput.md`. Same shape as
/// `diag_plain_tar_breakdown` above but on the tar.xz fixture, and
/// with two extra columns and one extra variant aimed at
/// pinpointing the ~14× pipeline-overhead gap that Phase 0
/// surfaced (decode-only is at 29.4 MiB/s on this machine; the
/// full bench-grid xz row at 1 Gbps is ~2.4 MB/s).
///
/// Extra columns:
///
/// * `frames` — `frame_boundaries_observed` from
///   [`peel::extractor::ExtractionStats`]. For xz_native this
///   advances per LZMA2 chunk (~64 KiB of decoded output), so on a
///   256 MiB single-Block fixture we expect ~4096.
/// * `quiesc` — `quiescent_checkpoints`, the count of times the
///   extractor decided "boundary advanced AND sink quiescent" and
///   called the observer with a [`CheckpointInfo`]. **Crucially,
///   this fires once per `decoder_state()` call**: every quiescent
///   advance constructs the resume blob *before* the observer's
///   throttle decision runs (`src/extractor.rs:594-606`,
///   `src/coordinator.rs:1568-1571`). For an xz Block at preset 6
///   that's ~8 MiB of dict serialization per quiescent advance.
/// * `overlap` — `total - download - decode - write - punch`. The
///   three timed phases are disjoint
///   ([`peel::extractor::ExtractionStats`] docstring); whatever's
///   left is the streaming-overlap budget *plus* anything the
///   timing didn't capture (the per-iteration boundary check, the
///   `decoder_state()` call, the observer's `Throttled` returns).
///   On the plain-tar fixture this is healthy "we waited on the
///   network while the decoder ran"; on tar.xz a fast-decoder
///   suspect would expect overlap to be small. If overlap is
///   *large* on tar.xz, that's the smoking gun for blob-
///   construction overhead.
///
/// Extra variant:
///
/// * `no_punch` — `punch_threshold = u64::MAX` so the puncher
///   never fires inside the loop (the final sweep still runs but
///   is cheap on the 256 MiB fixture). Isolates per-loop punch
///   syscall cost from the rest.
#[test]
#[ignore = "diagnostic; opt-in via --ignored"]
fn diag_tar_xz_breakdown() {
    let archive = build_tar_payload();
    let body = encode_xz(&archive);
    let suffix = "bundle.tar.xz";
    let server = MockServer::start(ok_handler(body.clone()));

    let body_len = body.len() as u64;
    type VariantBuilder = fn(u64) -> CoordinatorConfig;
    let variants: &[(&str, VariantBuilder)] = &[
        ("default                ", |_| coord_config()),
        ("single_worker_one_chunk", |body| {
            let mut c = coord_config();
            c.workers = 1;
            c.chunk_size = body;
            c.adaptive_chunk_size = false;
            c
        }),
        ("no_checkpoints         ", |_| {
            let mut c = coord_config();
            c.checkpoint_min_bytes = u64::MAX;
            c.checkpoint_min_interval = Duration::from_secs(60 * 60);
            c
        }),
        ("no_punch               ", |_| {
            let mut c = coord_config();
            c.punch_threshold = u64::MAX;
            c
        }),
        ("tight_reader_poll      ", |_| {
            let mut c = coord_config();
            c.reader_poll_interval = Duration::ZERO;
            c
        }),
    ];

    println!(
        "[diag-xz] {:24} {:>9} {:>9} {:>9} {:>9} {:>9} {:>9}  {:>7} {:>7} {:>7}",
        "variant",
        "download",
        "decode",
        "write",
        "punch",
        "total",
        "overlap",
        "chunks",
        "frames",
        "quiesc",
    );
    for (label, build) in variants {
        let work = unique_dir(&format!("diag_xz_{}", label.trim()));
        let _g = CleanupDir(work.clone());
        let args = RunArgs {
            url: format!("{}/{suffix}", server.base_url()),
            additional_urls: Vec::new(),
            output: OutputTarget::Dir(work.clone()),
            config: build(body_len),
            client: build_client(),
            registry: DecoderRegistry::with_defaults(),
            progress: None,
            progress_state: None,
            kill_switch: None,
            io_backend: None,
        };
        let stats = run(args).expect("peel run succeeds");
        let chunks = stats.download.chunks_completed;
        let frames = stats.extraction.frame_boundaries_observed;
        let quiesc = stats.extraction.quiescent_checkpoints;
        let dl = stats.download.elapsed.as_secs_f64();
        let dec = stats.extraction.decode_time.as_secs_f64();
        let wr = stats.extraction.write_time.as_secs_f64();
        let pn = stats.extraction.punch_time.as_secs_f64();
        let tot = stats.elapsed.as_secs_f64();
        // overlap = whatever is not in any of the timed phases.
        // Negative values are possible if download and decode raced;
        // we clamp at 0 for a clean printout.
        let overlap = (tot - dl - dec - wr - pn).max(0.0);
        println!(
            "[diag-xz] {label} {dl:>8.3}s {dec:>8.3}s {wr:>8.3}s {pn:>8.3}s {tot:>8.3}s {ov:>8.3}s  \
             {chunks:>7} {frames:>7} {quiesc:>7}",
            ov = overlap,
        );
        assert_extracted_tar_matches(&work, &archive);
    }
}

// ---- diagnostic: streaming hot-lane source pipeline ------------------

const TEN_GBPS_BYTES_PER_SEC: u64 = 10_000_000_000 / 8;

struct HotLaneFormat {
    label: &'static str,
    suffix: &'static str,
    encode: fn(&[u8]) -> Vec<u8>,
}

struct HotLaneVariant {
    label: &'static str,
    build: fn(CoordinatorConfig) -> CoordinatorConfig,
}

fn hot_lane_10gbps(mut config: CoordinatorConfig) -> CoordinatorConfig {
    config.max_bandwidth_bps = Some(TEN_GBPS_BYTES_PER_SEC);
    config
}

fn hot_lane_uncapped(config: CoordinatorConfig) -> CoordinatorConfig {
    config
}

fn hot_lane_no_checkpoints(mut config: CoordinatorConfig) -> CoordinatorConfig {
    config.max_bandwidth_bps = Some(TEN_GBPS_BYTES_PER_SEC);
    config.checkpoint_min_bytes = u64::MAX;
    config.checkpoint_min_interval = Duration::from_secs(60 * 60);
    config
}

fn hot_lane_no_punch(mut config: CoordinatorConfig) -> CoordinatorConfig {
    config.max_bandwidth_bps = Some(TEN_GBPS_BYTES_PER_SEC);
    config.punch_threshold = u64::MAX;
    config
}

fn hot_lane_tight_reader_poll(mut config: CoordinatorConfig) -> CoordinatorConfig {
    config.max_bandwidth_bps = Some(TEN_GBPS_BYTES_PER_SEC);
    config.reader_poll_interval = Duration::ZERO;
    config
}

#[cfg(target_os = "linux")]
fn hot_lane_mmap_10gbps(mut config: CoordinatorConfig) -> CoordinatorConfig {
    config.max_bandwidth_bps = Some(TEN_GBPS_BYTES_PER_SEC);
    config.io_backend = peel::io_backend::IoBackendChoice::Mmap;
    config
}

#[cfg(target_os = "linux")]
fn hot_lane_uring_10gbps(mut config: CoordinatorConfig) -> CoordinatorConfig {
    config.max_bandwidth_bps = Some(TEN_GBPS_BYTES_PER_SEC);
    config.io_backend = peel::io_backend::IoBackendChoice::Uring;
    config
}

fn mib(bytes: u64) -> f64 {
    bytes as f64 / 1024.0 / 1024.0
}

fn mib_per_sec(bytes: u64, elapsed: Duration) -> f64 {
    let secs = elapsed.as_secs_f64();
    if secs > 0.0 {
        mib(bytes) / secs
    } else {
        0.0
    }
}

/// Phase 0 of `docs/PLAN_streaming_hot_lane_throughput.md`: run the
/// same hot-lane configuration matrix across the streaming tar-family
/// formats and print a source/download/extraction breakdown.
///
/// The rows answer the cross-format ramp question directly: at the
/// 10 Gbps cap, are we spending the missing time in source bitmap
/// waits, sparse `pread`, download `pwrite`, checkpoint/punch work, or
/// decoder/sink time? `default_uncapped` is the control row for "is the
/// rate limiter itself part of the 10 Gbps ceiling?"
#[test]
#[ignore = "diagnostic; opt-in via --ignored"]
fn diag_streaming_source_pipeline_10gbps() {
    let archive = build_tar_payload();
    let formats = &[
        HotLaneFormat {
            label: "tar",
            suffix: "bundle.tar",
            encode: encode_identity,
        },
        HotLaneFormat {
            label: "tar.zst",
            suffix: "bundle.tar.zst",
            encode: encode_zstd,
        },
        HotLaneFormat {
            label: "tar.lz4",
            suffix: "bundle.tar.lz4",
            encode: encode_lz4_uncompressed_frame,
        },
        HotLaneFormat {
            label: "tar.xz",
            suffix: "bundle.tar.xz",
            encode: encode_xz,
        },
        HotLaneFormat {
            label: "tar.gz",
            suffix: "bundle.tar.gz",
            encode: encode_gzip,
        },
    ];

    let variants = vec![
        HotLaneVariant {
            label: "default_10gbps_cap",
            build: hot_lane_10gbps,
        },
        HotLaneVariant {
            label: "default_uncapped",
            build: hot_lane_uncapped,
        },
        HotLaneVariant {
            label: "no_checkpoints",
            build: hot_lane_no_checkpoints,
        },
        HotLaneVariant {
            label: "no_punch",
            build: hot_lane_no_punch,
        },
        HotLaneVariant {
            label: "tight_reader_poll",
            build: hot_lane_tight_reader_poll,
        },
    ];
    #[cfg(target_os = "linux")]
    let variants = {
        let mut variants = variants;
        variants.push(HotLaneVariant {
            label: "mmap_10gbps",
            build: hot_lane_mmap_10gbps,
        });
        variants.push(HotLaneVariant {
            label: "uring_10gbps",
            build: hot_lane_uring_10gbps,
        });
        variants
    };

    println!(
        "[diag-hot] {:7} {:18} {:>8} {:>9} {:>8} {:>8} {:>8} {:>8} {:>8} {:>8} {:>7} {:>7} {:>8} {:>8} {:>8} {:>7} {:>7} {:>7}",
        "format",
        "variant",
        "total",
        "srcMiB/s",
        "dl",
        "pwMiB",
        "pwrite",
        "rdMiB",
        "pread",
        "wait",
        "waits",
        "sleeps",
        "decode",
        "write",
        "punch",
        "chunks",
        "frames",
        "quiesc",
    );
    // Second header line for the per-checkpoint cost decomposition
    // emitted alongside each `[diag-hot]` row.
    // `PLAN_checkpoint_cadence_throughput.md` Phase 0.
    println!(
        "[ckpt-hot] {:7} {:18} {:>9} {:>8} {:>9} {:>9} {:>9} {:>9} {:>9} {:>7} {:>9} {:>9} {:>7}",
        "format",
        "variant",
        "decstate",
        "obs",
        "spsync",
        "serial",
        "tmpwr",
        "tmpfs",
        "rename",
        "dirfs#",
        "dirfs",
        "sum",
        "ckpts",
    );

    for format in formats {
        let body = (format.encode)(&archive);
        let body_len = body.len() as u64;
        let server = MockServer::start(ok_handler(body));

        for variant in &variants {
            let work = unique_dir(&format!(
                "diag_hot_{}_{}",
                format.label.replace('.', "_"),
                variant.label
            ));
            let _g = CleanupDir(work.clone());
            // Phase 2 of `PLAN_checkpoint_cadence_throughput.md`:
            // wire up a ProgressState so the rate-aware byte floor
            // can read realized download throughput. The
            // production CLI does the same (`src/main.rs`); the
            // diagnostic must mirror that for its numbers to track
            // production behavior.
            let progress_state = std::sync::Arc::new(peel::progress::ProgressState::new());
            let args = RunArgs {
                url: format!("{}/{}", server.base_url(), format.suffix),
                additional_urls: Vec::new(),
                output: OutputTarget::Dir(work.clone()),
                config: (variant.build)(coord_config()),
                client: build_client(),
                registry: DecoderRegistry::with_defaults(),
                progress: None,
                progress_state: Some(std::sync::Arc::clone(&progress_state)),
                kill_switch: None,
                io_backend: None,
            };
            let stats = match run(args) {
                Ok(stats) => stats,
                Err(e) => {
                    println!(
                        "[diag-hot] {:7} {:18} [skip] {e}",
                        format.label, variant.label
                    );
                    continue;
                }
            };
            assert_extracted_tar_matches(&work, &archive);
            println!(
                "[diag-hot] {fmt:7} {var:18} {tot:>7.3}s {src:>9.1} {dl:>7.3}s \
                 {pw_mib:>8.1} {pw:>7.3}s {rd_mib:>8.1} {rd:>7.3}s {wait:>7.3}s \
                 {waits:>7} {sleeps:>7} {dec:>7.3}s {wr:>7.3}s {pn:>7.3}s \
                 {chunks:>7} {frames:>7} {quiesc:>7}",
                fmt = format.label,
                var = variant.label,
                tot = stats.elapsed.as_secs_f64(),
                src = mib_per_sec(body_len, stats.elapsed),
                dl = stats.download.elapsed.as_secs_f64(),
                pw_mib = mib(stats.download.pwrite_bytes),
                pw = stats.download.pwrite_time.as_secs_f64(),
                rd_mib = mib(stats.extraction.source_sparse_read_bytes),
                rd = stats.extraction.source_sparse_read_time.as_secs_f64(),
                wait = stats.extraction.source_wait_time.as_secs_f64(),
                waits = stats.extraction.source_wait_count,
                sleeps = stats.extraction.source_poll_sleeps,
                dec = stats.extraction.decode_time.as_secs_f64(),
                wr = stats.extraction.write_time.as_secs_f64(),
                pn = stats.extraction.punch_time.as_secs_f64(),
                chunks = stats.download.chunks_completed,
                frames = stats.extraction.frame_boundaries_observed,
                quiesc = stats.extraction.quiescent_checkpoints,
            );
            // Per-checkpoint cost decomposition. The per-step
            // columns are non-overlapping; `sum` is their total
            // and should match `decstate + obs` within
            // syscall-noise. A material gap means a stage isn't
            // being timed. `PLAN_checkpoint_cadence_throughput.md`
            // Phase 0; `decstate` column added in
            // `PLAN_xz_bench_profile.md` Phase 1 to attribute the
            // `decoder_state()` call which fires *outside* the
            // observer closure.
            let e = &stats.extraction;
            let sum = e.ckpt_decoder_state_time
                + e.ckpt_sparse_sync_time
                + e.ckpt_serialize_time
                + e.ckpt_tmp_write_time
                + e.ckpt_tmp_fsync_time
                + e.ckpt_rename_time
                + e.ckpt_dir_fsync_time;
            println!(
                "[ckpt-hot] {fmt:7} {var:18} {decstate:>8.3}s {obs:>7.3}s {spsync:>8.3}s \
                 {serial:>8.3}s {tmpwr:>8.3}s {tmpfs:>8.3}s {rename:>8.3}s \
                 {dfs_n:>7} {dfs:>8.3}s {sum:>8.3}s {ckpts:>7}",
                fmt = format.label,
                var = variant.label,
                decstate = e.ckpt_decoder_state_time.as_secs_f64(),
                obs = e.ckpt_observer_time.as_secs_f64(),
                spsync = e.ckpt_sparse_sync_time.as_secs_f64(),
                serial = e.ckpt_serialize_time.as_secs_f64(),
                tmpwr = e.ckpt_tmp_write_time.as_secs_f64(),
                tmpfs = e.ckpt_tmp_fsync_time.as_secs_f64(),
                rename = e.ckpt_rename_time.as_secs_f64(),
                dfs_n = e.ckpt_dir_fsync_calls,
                dfs = e.ckpt_dir_fsync_time.as_secs_f64(),
                sum = sum.as_secs_f64(),
                ckpts = e.quiescent_checkpoints,
            );
        }
    }
}

// ---- diagnostic: IO backend A/B (blocking vs mmap vs uring) ----------

/// Run the plain-tar payload under each IO backend and print a
/// breakdown row per backend.
///
/// The hypothesis we're testing: the loopback gap between `peel` and
/// `curl|tar` is dominated by the part-file double-hop (workers
/// `pwrite` to disk; decoder `pread`s back). The mmap backend should
/// largely close that gap because workers and decoder share the same
/// `MAP_SHARED` pages — no double memcpy through the page cache. If
/// mmap closes most of the gap, the K8s/multi-TB use case can stay
/// on the existing design with a backend swap rather than needing the
/// full RAM-ring redesign.
///
/// The `mmap` and `uring` rows are Linux-only — on macOS/Windows the
/// backend constructor errors out and we print a `[skip]` line. Run
/// on Linux (a dev box, a CI runner, or a Linux Docker container —
/// `docker run -it --rm -v $PWD:/src -w /src rust:1.93 bash` works)
/// to get real numbers.
///
/// One caveat for the K8s use case: when run inside a container,
/// `/tmp` typically lives on overlayfs. `madvise(MADV_REMOVE)` may or
/// may not propagate cleanly to the underlying filesystem depending
/// on storage class. The numbers you see here reflect the FS the
/// system temp dir resolves to; for a representative K8s read, run
/// this inside a pod with the same volume class the snapshot job
/// will use.
#[test]
#[ignore = "diagnostic; opt-in via --ignored"]
fn diag_plain_tar_io_backends() {
    let archive = build_tar_payload();
    let suffix = "bundle.tar";
    let server = MockServer::start(ok_handler(archive.clone()));

    println!(
        "[diag] {:>10} {:>9} {:>9} {:>9} {:>9} {:>9}  notes",
        "backend", "download", "decode", "write", "punch", "total"
    );

    let backends: &[(&str, peel::io_backend::IoBackendChoice, bool)] = &[
        // blocking is the default backend used by every other bench
        // and works everywhere. The mmap/uring rows are Linux-only
        // and the runtime check below skips them on other platforms.
        (
            "blocking",
            peel::io_backend::IoBackendChoice::Blocking,
            true,
        ),
        (
            "mmap    ",
            peel::io_backend::IoBackendChoice::Mmap,
            cfg!(target_os = "linux"),
        ),
        (
            "uring   ",
            peel::io_backend::IoBackendChoice::Uring,
            cfg!(target_os = "linux"),
        ),
    ];

    for (label, choice, supported) in backends {
        if !*supported {
            println!("[diag] {label} [skip] backend unavailable on this platform");
            continue;
        }
        let work = unique_dir(&format!("io_{}", label.trim()));
        let _g = CleanupDir(work.clone());
        let mut config = coord_config();
        config.io_backend = *choice;
        let args = RunArgs {
            url: format!("{}/{suffix}", server.base_url()),
            additional_urls: Vec::new(),
            output: OutputTarget::Dir(work.clone()),
            config,
            client: build_client(),
            registry: DecoderRegistry::with_defaults(),
            progress: None,
            progress_state: None,
            kill_switch: None,
            io_backend: None,
        };
        let stats = match run(args) {
            Ok(s) => s,
            Err(e) => {
                println!("[diag] {label} [skip] backend selection failed: {e}");
                continue;
            }
        };
        assert_extracted_tar_matches(&work, &archive);
        println!(
            "[diag] {label} {dl:>8.3}s {dec:>8.3}s {wr:>8.3}s {pn:>8.3}s {tot:>8.3}s  punch_calls={pc} bytes_punched={bp}",
            dl = stats.download.elapsed.as_secs_f64(),
            dec = stats.extraction.decode_time.as_secs_f64(),
            wr = stats.extraction.write_time.as_secs_f64(),
            pn = stats.extraction.punch_time.as_secs_f64(),
            tot = stats.elapsed.as_secs_f64(),
            pc = stats.extraction.punch_calls,
            bp = stats.extraction.bytes_punched,
        );
    }
}

// ---- benchmark: realistic-WAN-rate grid (peel vs curl|tool) ----------

/// Compare `peel` against `curl | <decompressor> | tar` at four
/// representative WAN rates: 10 Mbps, 100 Mbps, 1 Gbps, 10 Gbps. Both
/// sides share the same cap (peel via [`CoordinatorConfig::max_bandwidth_bps`],
/// curl via `--limit-rate` in bytes/sec).
///
/// The hypothesis: at sub-WAN-saturating rates, peel's per-byte
/// overhead is hidden inside the network wait, so peel and the shell
/// pipe finish within noise of each other for fast codecs. As the
/// rate climbs into multi-gigabit territory the slower decoders (here:
/// peel's single-threaded xz, then peel itself for any codec) become
/// the bottleneck and peel falls behind.
///
/// Payload sizes are scaled per rate so each row's wall-clock budget
/// stays near 5 s of network wait — long enough to drown out
/// connection setup, short enough that the whole grid finishes in a
/// few minutes.
#[test]
#[ignore = "benchmark; opt-in via --ignored"]
fn bench_throttled_realistic_grid() {
    if !tool_present("curl") {
        skip("net", "curl");
        return;
    }

    let rates = &[
        Rate {
            label: "10 Mbps",
            bytes_per_sec: 10_000_000 / 8,
            payload_bytes: 8 * 1024 * 1024,
        },
        Rate {
            label: "100 Mbps",
            bytes_per_sec: 100_000_000 / 8,
            payload_bytes: 32 * 1024 * 1024,
        },
        Rate {
            label: "1 Gbps",
            bytes_per_sec: 1_000_000_000 / 8,
            payload_bytes: 128 * 1024 * 1024,
        },
        Rate {
            label: "10 Gbps",
            bytes_per_sec: 10_000_000_000 / 8,
            payload_bytes: 256 * 1024 * 1024,
        },
    ];

    println!(
        "[net] {:>10}  {:>9}  {:<8}  {:>9}  {:>13}  {:>6}  tools",
        "rate", "payload", "format", "peel", "curl|tool", "ratio"
    );

    for rate in rates {
        let (archive, entries) = build_tar_payload_sized(rate.payload_bytes);
        let mib = (rate.payload_bytes as f64) / (1024.0 * 1024.0);

        // ---- plain tar -------------------------------------------------
        if tool_present("tar") {
            run_throttled_case(
                rate,
                mib,
                "tar",
                "curl|tar",
                &archive,
                &archive,
                &entries,
                "bundle.tar",
                |dir| {
                    format!(
                        r#"curl -sS --limit-rate {limit} "$URL" | tar -xf - -C {dir}"#,
                        limit = rate.bytes_per_sec,
                        dir = shell_quote(dir),
                    )
                },
            );
        }

        // ---- tar.zst ---------------------------------------------------
        if tool_present("tar") && tool_present("zstd") {
            let body = encode_zstd(&archive);
            run_throttled_case(
                rate,
                mib,
                "tar.zst",
                "curl|zstd|tar",
                &body,
                &archive,
                &entries,
                "bundle.tar.zst",
                |dir| {
                    format!(
                        r#"curl -sS --limit-rate {limit} "$URL" | zstd -d -q | tar -xf - -C {dir}"#,
                        limit = rate.bytes_per_sec,
                        dir = shell_quote(dir),
                    )
                },
            );
        }

        // ---- tar.xz ----------------------------------------------------
        if tool_present("tar") && tool_present("xz") {
            let body = encode_xz(&archive);
            run_throttled_case(
                rate,
                mib,
                "tar.xz",
                "curl|xz|tar",
                &body,
                &archive,
                &entries,
                "bundle.tar.xz",
                |dir| {
                    format!(
                        r#"curl -sS --limit-rate {limit} "$URL" | xz -d -q | tar -xf - -C {dir}"#,
                        limit = rate.bytes_per_sec,
                        dir = shell_quote(dir),
                    )
                },
            );
        }

        // ---- tar.gz (single-member, default-`gzip` shape) -------------
        if tool_present("tar") && tool_present("gzip") {
            let body = encode_gzip(&archive);
            run_throttled_case(
                rate,
                mib,
                "tar.gz",
                "curl|gzip|tar",
                &body,
                &archive,
                &entries,
                "bundle.tar.gz",
                |dir| {
                    format!(
                        r#"curl -sS --limit-rate {limit} "$URL" | gzip -d -q | tar -xf - -C {dir}"#,
                        limit = rate.bytes_per_sec,
                        dir = shell_quote(dir),
                    )
                },
            );
        }

        // ---- tar.gz (multi-member, `pigz`/concat shape) ---------------
        // Phase 0 of `docs/PLAN_gzip_throughput.md`: this row exists so
        // the README grid can show "tar.gz · multi" alongside the
        // single-member row once parallel-member decode lands. The
        // baseline pipe is the same `gzip -d` (handles concatenated
        // members natively per RFC 1952 §2.2 — single-threaded), so the
        // ratio is directly comparable to the row above. `peel` is
        // currently single-threaded on this fixture too; the row
        // becomes the regression-gate for Phase 3's parallel decode.
        //
        // Smaller cells: skip when `n_members > payload / 1 MiB`
        // (members below 1 MiB stop being representative — `pigz`
        // defaults to 128 KiB but real-world fixtures cluster at
        // ~32 MiB members).
        if tool_present("tar") && tool_present("gzip") {
            let n_members = pick_gz_member_count(rate.payload_bytes);
            if n_members >= 2 {
                let body = encode_gzip_multi_member(&archive, n_members);
                run_throttled_case(
                    rate,
                    mib,
                    "tar.gz·m",
                    "curl|gzip|tar",
                    &body,
                    &archive,
                    &entries,
                    "bundle.tar.gz",
                    |dir| {
                        format!(
                            r#"curl -sS --limit-rate {limit} "$URL" | gzip -d -q | tar -xf - -C {dir}"#,
                            limit = rate.bytes_per_sec,
                            dir = shell_quote(dir),
                        )
                    },
                );
            }
        }

        // ---- tar.lz4 (uncompressed frame; framing-only test) ----------
        if tool_present("tar") && tool_present("lz4") {
            let body = encode_lz4_uncompressed_frame(&archive);
            run_throttled_case(
                rate,
                mib,
                "tar.lz4",
                "curl|lz4|tar",
                &body,
                &archive,
                &entries,
                "bundle.tar.lz4",
                |dir| {
                    format!(
                        r#"curl -sS --limit-rate {limit} "$URL" | lz4 -d -q | tar -xf - -C {dir}"#,
                        limit = rate.bytes_per_sec,
                        dir = shell_quote(dir),
                    )
                },
            );
        }
    }
}

/// Diagnostic: sweep `workers` at the 10 Mbps × 8 MiB cell to test the
/// hypothesis that `peel`'s 4–14% slowdown vs `curl --limit-rate | tar`
/// at this row is dominated by trailing-edge drain across multiple
/// ranged GETs (workers idle out one by one as the body finishes; the
/// last worker drains the token bucket alone, so the trailing edge
/// runs below the cap). If the hypothesis holds, `workers=1` should
/// tie or beat the curl baseline.
///
/// Methodology mirrors `bench_throttled_realistic_grid`'s tar row:
/// in-process mock server on loopback, blocking IO backend, two
/// consecutive runs averaged.
#[test]
#[ignore = "diagnostic; opt-in via --ignored"]
fn diag_throttled_10mbps_tar_worker_sweep() {
    if !tool_present("curl") || !tool_present("tar") {
        skip("net", "curl/tar");
        return;
    }

    let rate = Rate {
        label: "10 Mbps",
        bytes_per_sec: 10_000_000 / 8,
        payload_bytes: 8 * 1024 * 1024,
    };
    let (archive, entries) = build_tar_payload_sized(rate.payload_bytes);
    let body_len = archive.len() as u64;

    let server = MockServer::start(ok_handler(archive.clone()));
    let url = format!("{}/bundle.tar", server.base_url());

    type VariantBuilder = fn(u64, u64) -> CoordinatorConfig;
    let variants: &[(&str, VariantBuilder)] = &[
        ("workers=1, adaptive=off, chunk=body  ", |body, rate_bps| {
            let mut c = coord_config();
            c.workers = 1;
            c.chunk_size = body;
            c.adaptive_chunk_size = false;
            c.max_bandwidth_bps = Some(rate_bps);
            c
        }),
        ("workers=2, adaptive=on               ", |_, rate_bps| {
            let mut c = coord_config();
            c.workers = 2;
            c.max_bandwidth_bps = Some(rate_bps);
            c
        }),
        ("workers=4, adaptive=on (current grid)", |_, rate_bps| {
            let mut c = coord_config();
            c.workers = 4;
            c.max_bandwidth_bps = Some(rate_bps);
            c
        }),
        ("workers=8, adaptive=on (prod default)", |_, rate_bps| {
            let mut c = coord_config();
            c.workers = 8;
            c.max_bandwidth_bps = Some(rate_bps);
            c
        }),
    ];

    println!(
        "[diag] {label:<40} {r1:>9} {r2:>9}  {avg:>9}",
        label = "variant",
        r1 = "run1",
        r2 = "run2",
        avg = "avg"
    );

    for (label, build) in variants {
        let mut runs = [0.0f64; 2];
        for (i, slot) in runs.iter_mut().enumerate() {
            let work = unique_dir(&format!("diag_sweep_{i}"));
            let _g = CleanupDir(work.clone());
            let args = RunArgs {
                url: url.clone(),
                additional_urls: Vec::new(),
                output: OutputTarget::Dir(work.clone()),
                config: build(body_len, rate.bytes_per_sec),
                client: build_client(),
                registry: DecoderRegistry::with_defaults(),
                progress: None,
                progress_state: None,
                kill_switch: None,
                io_backend: None,
            };
            let started = Instant::now();
            let stats = run(args).expect("peel run succeeds");
            *slot = started.elapsed().as_secs_f64();
            assert_eq!(stats.extraction.bytes_out, archive.len() as u64);
            assert_dir_matches(&work, &entries);
        }
        let avg = (runs[0] + runs[1]) / 2.0;
        println!(
            "[diag] {label:<40} {r1:>8.3}s {r2:>8.3}s  {avg:>8.3}s",
            r1 = runs[0],
            r2 = runs[1],
        );
    }

    // curl baseline (single TCP, --limit-rate). Runs twice.
    let mut curl_runs = [0.0f64; 2];
    for (i, slot) in curl_runs.iter_mut().enumerate() {
        let work = unique_dir(&format!("diag_sweep_curl_{i}"));
        let _g = CleanupDir(work.clone());
        let pipeline = format!(
            r#"curl -sS --limit-rate {limit} "$URL" | tar -xf - -C {dir}"#,
            limit = rate.bytes_per_sec,
            dir = shell_quote(&work),
        );
        *slot = time_pipeline(&url, &pipeline).as_secs_f64();
        assert_dir_matches(&work, &entries);
    }
    let curl_avg = (curl_runs[0] + curl_runs[1]) / 2.0;
    println!(
        "[diag] {label:<40} {r1:>8.3}s {r2:>8.3}s  {avg:>8.3}s",
        label = "curl|tar baseline                    ",
        r1 = curl_runs[0],
        r2 = curl_runs[1],
        avg = curl_avg,
    );
}

/// One throttled (peel, curl|tool) comparison row.
///
/// `body` is the on-the-wire bytes (post-encoding); `archive` is the
/// raw tar bytes used for the post-extraction integrity check via
/// `entries` (the same `(path, content)` pairs that built the archive).
struct Rate {
    label: &'static str,
    bytes_per_sec: u64,
    #[allow(dead_code)]
    payload_bytes: usize,
}

#[allow(clippy::too_many_arguments)]
fn run_throttled_case(
    rate: &Rate,
    payload_mib: f64,
    format_label: &str,
    tools_label: &str,
    body: &[u8],
    archive: &[u8],
    entries: &[(String, Vec<u8>)],
    suffix: &str,
    baseline_pipeline: impl Fn(&std::path::Path) -> String,
) {
    let server = MockServer::start(ok_handler(body.to_vec()));
    let url = format!("{}/{suffix}", server.base_url());

    // ---- peel ----
    let work_p = unique_dir(&format!("net_{format_label}_peel"));
    let _g_p = CleanupDir(work_p.clone());
    let mut config = coord_config();
    config.max_bandwidth_bps = Some(rate.bytes_per_sec);
    // Phase 2 of `PLAN_checkpoint_cadence_throughput.md`: the
    // rate-aware byte floor only activates when a `ProgressState`
    // is wired up. The production CLI does so unconditionally
    // (`src/main.rs`); mirror that here so the grid numbers track
    // production behavior.
    let progress_state = std::sync::Arc::new(peel::progress::ProgressState::new());
    let args = RunArgs {
        url: url.clone(),
        additional_urls: Vec::new(),
        output: OutputTarget::Dir(work_p.clone()),
        config,
        client: build_client(),
        registry: DecoderRegistry::with_defaults(),
        progress: None,
        progress_state: Some(std::sync::Arc::clone(&progress_state)),
        kill_switch: None,
        io_backend: None,
    };
    let started = Instant::now();
    let stats = run(args).expect("peel run succeeds");
    let peel_elapsed = started.elapsed();
    assert_eq!(stats.extraction.bytes_out, archive.len() as u64);
    assert_dir_matches(&work_p, entries);

    // ---- curl|tool ----
    let work_b = unique_dir(&format!("net_{format_label}_curl"));
    let _g_b = CleanupDir(work_b.clone());
    let pipeline = baseline_pipeline(&work_b);
    let base_elapsed = time_pipeline(&url, &pipeline);
    assert_dir_matches(&work_b, entries);

    let peel_s = peel_elapsed.as_secs_f64();
    let base_s = base_elapsed.as_secs_f64();
    println!(
        "[net] {rate:>10}  {payload:>6.1} MiB  {fmt:<8}  {peel:>7.3}s  {base:>11.3}s  {ratio:>5.2}x  {tools}",
        rate = rate.label,
        payload = payload_mib,
        fmt = format_label,
        peel = peel_s,
        base = base_s,
        ratio = peel_s / base_s.max(1e-9),
        tools = tools_label,
    );
}

/// Like [`build_tar_payload`] but takes a target raw-byte total. Files
/// are split evenly into `FILES` (8) entries; deterministic content
/// per-index so the post-extraction check can re-derive the bodies.
///
/// Returns `(archive_bytes, entries)` where `entries` is the
/// `(path, content)` list used by [`assert_dir_matches`].
fn build_tar_payload_sized(approx_total: usize) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    const FILES: usize = 8;
    let per = approx_total / FILES;
    let entries: Vec<(String, Vec<u8>)> = (0..FILES)
        .map(|i| {
            (
                format!("data/file_{i:02}.bin"),
                random_bytes(0xBEEF + i as u64, per),
            )
        })
        .collect();
    let pairs: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    let archive = build_simple_archive(&pairs);
    (archive, entries)
}

fn assert_dir_matches(dir: &std::path::Path, entries: &[(String, Vec<u8>)]) {
    for (name, body) in entries {
        let path = dir.join(name);
        let actual = fs::read(&path).expect("read extracted file");
        assert_eq!(actual.len(), body.len(), "size mismatch on {name}");
        assert_eq!(actual, *body, "contents mismatch on {name}");
    }
}

// ---- download-then-extract grid --------------------------------------

/// Companion to [`bench_throttled_realistic_grid`] but with a different
/// baseline: instead of `curl URL | tool -d | tar -xf -` (streaming
/// pipe), this grid measures the download-fully-then-extract-then-
/// delete-archive workflow:
///
/// ```text
/// curl --limit-rate <R> -o <file> <URL> && <extract <file> into dir> && rm <file>
/// ```
///
/// This is the canonical workflow forced on a user when:
/// * The format has a tail-anchored index (`.zip` central directory,
///   `.7z` SignatureHeader → trailer pointer) — there is no useful
///   `curl | tool` pipeline because the decoder must seek to the end
///   before it can decode the first byte.
/// * The user is following a tutorial / install script that just says
///   "download `foo.tar.zst`, then run `tar -xf foo.tar.zst`".
/// * Tooling on the box doesn't compose into a pipeline (a Docker
///   layer that has `curl` and `7z` but no shell-pipe glue).
///
/// `peel`'s wall-clock for these rows is fundamentally the wire-time
/// (the decoder runs in parallel with the download). The baseline's
/// is `wire-time + decode-time + extract-time + rm`. So peel saves
/// the decode/extract phase outright, plus picks up some additional
/// margin from parallel ranged GETs at higher rates.
///
/// `.zip` and `.7z` rows have no streaming-pipe baseline at all —
/// peel turns them from "download-then-extract only" into
/// "stream-as-you-go", which is the headline this grid exists to
/// quantify.
#[test]
#[ignore = "benchmark; opt-in via --ignored"]
fn bench_throttled_download_then_extract_grid() {
    if !tool_present("curl") {
        skip("dnx", "curl");
        return;
    }

    let rates = &[
        Rate {
            label: "10 Mbps",
            bytes_per_sec: 10_000_000 / 8,
            payload_bytes: 8 * 1024 * 1024,
        },
        Rate {
            label: "100 Mbps",
            bytes_per_sec: 100_000_000 / 8,
            payload_bytes: 32 * 1024 * 1024,
        },
        Rate {
            label: "1 Gbps",
            bytes_per_sec: 1_000_000_000 / 8,
            payload_bytes: 128 * 1024 * 1024,
        },
        Rate {
            label: "10 Gbps",
            bytes_per_sec: 10_000_000_000 / 8,
            payload_bytes: 256 * 1024 * 1024,
        },
    ];

    println!(
        "[dnx] {:>10}  {:>9}  {:<8}  {:>9}  {:>13}  {:>6}  tools",
        "rate", "payload", "format", "peel", "curl+extract", "ratio"
    );

    for rate in rates {
        let (archive, entries) = build_tar_payload_sized(rate.payload_bytes);
        let mib = (rate.payload_bytes as f64) / (1024.0 * 1024.0);

        // ---- plain tar -------------------------------------------------
        if tool_present("tar") {
            run_throttled_dnx_case(
                rate,
                mib,
                "tar",
                "curl+tar",
                &archive,
                &entries,
                "bundle.tar",
                |file, dir| {
                    format!(
                        r#"curl -sS --limit-rate {limit} -o {file} "$URL" && tar -xf {file} -C {dir} && rm {file}"#,
                        limit = rate.bytes_per_sec,
                        file = shell_quote(file),
                        dir = shell_quote(dir),
                    )
                },
            );
        }

        // ---- tar.zst ---------------------------------------------------
        if tool_present("tar") && tool_present("zstd") {
            let body = encode_zstd(&archive);
            run_throttled_dnx_case(
                rate,
                mib,
                "tar.zst",
                "curl+zstd+tar",
                &body,
                &entries,
                "bundle.tar.zst",
                |file, dir| {
                    format!(
                        r#"curl -sS --limit-rate {limit} -o {file} "$URL" && zstd -dc -q {file} | tar -xf - -C {dir} && rm {file}"#,
                        limit = rate.bytes_per_sec,
                        file = shell_quote(file),
                        dir = shell_quote(dir),
                    )
                },
            );
        }

        // ---- tar.xz ----------------------------------------------------
        if tool_present("tar") && tool_present("xz") {
            let body = encode_xz(&archive);
            run_throttled_dnx_case(
                rate,
                mib,
                "tar.xz",
                "curl+xz+tar",
                &body,
                &entries,
                "bundle.tar.xz",
                |file, dir| {
                    format!(
                        r#"curl -sS --limit-rate {limit} -o {file} "$URL" && xz -dc -q {file} | tar -xf - -C {dir} && rm {file}"#,
                        limit = rate.bytes_per_sec,
                        file = shell_quote(file),
                        dir = shell_quote(dir),
                    )
                },
            );
        }

        // ---- tar.gz (single-member) ------------------------------------
        if tool_present("tar") && tool_present("gzip") {
            let body = encode_gzip(&archive);
            run_throttled_dnx_case(
                rate,
                mib,
                "tar.gz",
                "curl+gzip+tar",
                &body,
                &entries,
                "bundle.tar.gz",
                |file, dir| {
                    format!(
                        r#"curl -sS --limit-rate {limit} -o {file} "$URL" && gzip -dc -q {file} | tar -xf - -C {dir} && rm {file}"#,
                        limit = rate.bytes_per_sec,
                        file = shell_quote(file),
                        dir = shell_quote(dir),
                    )
                },
            );
        }

        // ---- tar.lz4 (uncompressed frame) ------------------------------
        if tool_present("tar") && tool_present("lz4") {
            let body = encode_lz4_uncompressed_frame(&archive);
            run_throttled_dnx_case(
                rate,
                mib,
                "tar.lz4",
                "curl+lz4+tar",
                &body,
                &entries,
                "bundle.tar.lz4",
                |file, dir| {
                    format!(
                        r#"curl -sS --limit-rate {limit} -o {file} "$URL" && lz4 -dc -q {file} | tar -xf - -C {dir} && rm {file}"#,
                        limit = rate.bytes_per_sec,
                        file = shell_quote(file),
                        dir = shell_quote(dir),
                    )
                },
            );
        }

        // ---- zip (STORED entries) --------------------------------------
        // The streaming-pipe baseline is impossible here (central
        // directory at the tail), so this is the *only* fair head-to-
        // head: a real-world `curl -O && unzip && rm` sequence.
        if tool_present("unzip") {
            let zip_entries: Vec<ZipEntrySpec> = entries
                .iter()
                .map(|(n, b)| ZipEntrySpec::stored(n.clone(), b.clone()))
                .collect();
            let body = build_zip(&zip_entries);
            run_throttled_dnx_case(
                rate,
                mib,
                "zip",
                "curl+unzip",
                &body,
                &entries,
                "bundle.zip",
                |file, dir| {
                    format!(
                        r#"curl -sS --limit-rate {limit} -o {file} "$URL" && unzip -q {file} -d {dir} && rm {file}"#,
                        limit = rate.bytes_per_sec,
                        file = shell_quote(file),
                        dir = shell_quote(dir),
                    )
                },
            );
        }

        // ---- 7z (COPY-coded) -------------------------------------------
        // Same story as zip: no streaming-pipe baseline exists; peel
        // turns "download fully then extract" into "extract while
        // downloading" via the second-pipeline driver
        // (`docs/PLAN_7z_support.md` §8).
        if tool_present("7z") {
            let pairs: Vec<(&str, Vec<u8>)> = entries
                .iter()
                .map(|(n, b)| (n.as_str(), b.clone()))
                .collect();
            let body = build_copy_sevenz(&pairs);
            run_throttled_dnx_case(
                rate,
                mib,
                "7z",
                "curl+7z",
                &body,
                &entries,
                "bundle.7z",
                |file, dir| {
                    // -y assume yes (no prompt); -bd no progress;
                    // -bb0 quiet output.
                    format!(
                        r#"curl -sS --limit-rate {limit} -o {file} "$URL" && 7z x -y -bd -bb0 -o{dir} {file} >/dev/null && rm {file}"#,
                        limit = rate.bytes_per_sec,
                        file = shell_quote(file),
                        dir = shell_quote(dir),
                    )
                },
            );
        }

        // ---- rar5 + rar3 (STORED) --------------------------------------
        // Same shape as zip / 7z: `unrar` requires a seekable file, so
        // the only fair baseline is `curl -O && unrar x && rm`. Peel
        // streams RAR end-to-end (headers + data interleaved in stream
        // order) — the highlight this grid quantifies. Encoder output
        // comes from the real `rar` binaries (`tests/support/
        // rar_bench_fixtures.rs`) so the third-party `unrar` baseline
        // is decoding genuine RAR wire bytes, not a peel-built dialect.
        #[cfg(feature = "rar")]
        {
            if let Some(unrar) = unrar_path() {
                if rar5_encoder_present() {
                    let body = ensure_rar5_stored(&entries, rate.payload_bytes);
                    let unrar = unrar.clone();
                    run_throttled_dnx_case(
                        rate,
                        mib,
                        "rar5",
                        "curl+unrar",
                        &body,
                        &entries,
                        "bundle.rar",
                        move |file, dir| {
                            // -inul: suppress all output. -y: yes to
                            // prompts. Trailing slash on the dest is
                            // required for `unrar x`.
                            format!(
                                r#"curl -sS --limit-rate {limit} -o {file} "$URL" && {unrar} x -inul -y {file} {dir}/ && rm {file}"#,
                                limit = rate.bytes_per_sec,
                                file = shell_quote(file),
                                dir = shell_quote(dir),
                                unrar = unrar,
                            )
                        },
                    );
                }
                if rar3_encoder_present() {
                    let body = ensure_rar3_stored(&entries, rate.payload_bytes);
                    let unrar = unrar.clone();
                    run_throttled_dnx_case(
                        rate,
                        mib,
                        "rar3",
                        "curl+unrar",
                        &body,
                        &entries,
                        "bundle.rar",
                        move |file, dir| {
                            format!(
                                r#"curl -sS --limit-rate {limit} -o {file} "$URL" && {unrar} x -inul -y {file} {dir}/ && rm {file}"#,
                                limit = rate.bytes_per_sec,
                                file = shell_quote(file),
                                dir = shell_quote(dir),
                                unrar = unrar,
                            )
                        },
                    );
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_throttled_dnx_case(
    rate: &Rate,
    payload_mib: f64,
    format_label: &str,
    tools_label: &str,
    body: &[u8],
    entries: &[(String, Vec<u8>)],
    suffix: &str,
    baseline_pipeline: impl Fn(&std::path::Path, &std::path::Path) -> String,
) {
    let server = MockServer::start(ok_handler(body.to_vec()));
    let url = format!("{}/{suffix}", server.base_url());

    // ---- peel ----
    let work_p = unique_dir(&format!("dnx_{format_label}_peel"));
    let _g_p = CleanupDir(work_p.clone());
    let mut config = coord_config();
    config.max_bandwidth_bps = Some(rate.bytes_per_sec);
    let progress_state = std::sync::Arc::new(peel::progress::ProgressState::new());
    let args = RunArgs {
        url: url.clone(),
        additional_urls: Vec::new(),
        output: OutputTarget::Dir(work_p.clone()),
        config,
        client: build_client(),
        registry: DecoderRegistry::with_defaults(),
        progress: None,
        progress_state: Some(std::sync::Arc::clone(&progress_state)),
        kill_switch: None,
        io_backend: None,
    };
    let started = Instant::now();
    let _stats = run(args).expect("peel run succeeds");
    let peel_elapsed = started.elapsed();
    assert_dir_matches(&work_p, entries);

    // ---- curl -O && extract && rm ----
    let work_b = unique_dir(&format!("dnx_{format_label}_baseline"));
    let _g_b = CleanupDir(work_b.clone());
    let archive_path = work_b.join(suffix);
    let extract_dir = work_b.join("out");
    fs::create_dir_all(&extract_dir).expect("mkdir extract");
    let pipeline = baseline_pipeline(&archive_path, &extract_dir);
    let base_elapsed = time_pipeline(&url, &pipeline);
    assert_dir_matches(&extract_dir, entries);

    let peel_s = peel_elapsed.as_secs_f64();
    let base_s = base_elapsed.as_secs_f64();
    println!(
        "[dnx] {rate:>10}  {payload:>6.1} MiB  {fmt:<8}  {peel:>7.3}s  {base:>11.3}s  {ratio:>5.2}x  {tools}",
        rate = rate.label,
        payload = payload_mib,
        fmt = format_label,
        peel = peel_s,
        base = base_s,
        ratio = peel_s / base_s.max(1e-9),
        tools = tools_label,
    );
}

// ---- shell quoting (POSIX single-quote) -------------------------------

/// Quote `path` for inclusion in a `bash -c` script. Wraps the string
/// in single quotes and escapes any embedded `'`. Tempdir paths
/// generated by [`unique_dir`] never contain `'`, so this is mostly
/// defensive — but the cost of doing it right once is small.
fn shell_quote(path: &std::path::Path) -> String {
    let s = path.to_string_lossy();
    let escaped = s.replace('\'', "'\\''");
    format!("'{escaped}'")
}
