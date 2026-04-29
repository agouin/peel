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
use peel::types::ByteOffset;

#[path = "support/mod.rs"]
mod support;

use support::mock_server::{MockRequest, MockResponse, MockServer};
use support::tar_fixtures::{build_header, build_pax_body, build_simple_archive, end_of_archive};

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
