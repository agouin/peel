//! Integration tests for the §1 magic-byte format-detection path.
//!
//! Phase A §1 of `docs/PLAN_v2.md` extends the [`DecoderRegistry`] with
//! a magic-byte map and teaches the coordinator to combine suffix and
//! magic detection into a single resolution policy. The four scenarios
//! encoded below mirror the four cases the plan's demo specifies:
//!
//! 1. `x.zst` — suffix matches a registered factory; the run succeeds.
//! 2. `x.bin` — no suffix is registered; magic-byte detection finds
//!    zstd content and the run succeeds.
//! 3. `x.gz` carrying zstd content — suffix and magic disagree; the
//!    run aborts cleanly with [`CoordinatorError::FormatMismatch`].
//! 4. Same as (3) but with `--force-format-from-magic`; the run
//!    succeeds, the magic wins, and a warning is emitted on stderr.
//!
//! A fifth case covers `--format <name>`: the suffix is stripped from
//! the URL entirely, the user names the decoder explicitly, and the
//! run succeeds without invoking any sniffing.
//!
//! The "gz" decoder used in cases (3) and (4) is a stub that always
//! errors on first decode_step; observing FormatMismatch *before* any
//! decode happens confirms detection short-circuited correctly, and
//! observing a successful decode in case (4) confirms the magic-byte
//! factory (real zstd) was selected instead.

#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use peel::coordinator::{run, CoordinatorConfig, CoordinatorError, OutputTarget, RunArgs};
use peel::decode::{DecodeError, DecodeStatus, DecoderRegistry, MagicSignature, StreamingDecoder};
use peel::download::RetryConfig;
use peel::http::{Client, ClientConfig};
use peel::types::ByteOffset;

#[path = "support/mod.rs"]
mod support;

use support::mock_server::{MockRequest, MockResponse, MockServer};

// ---- helpers (trimmed copies of the test_coordinator.rs scaffolding) --

static UNIQ: AtomicU64 = AtomicU64::new(0);

fn unique_dir(label: &str) -> PathBuf {
    let pid = std::process::id();
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("peel_fmt_it_{label}_{pid}_{nanos}_{n}"));
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
        checkpoint_min_bytes: 1,
        checkpoint_min_interval: Duration::from_millis(0),
        workdir: None,
        reader_poll_interval: Duration::from_millis(2),
        forced_format: None,
        force_format_from_magic: false,
    }
}

fn encode_zstd(payload: &[u8]) -> Vec<u8> {
    zstd::encode_all(payload, 1).expect("encode zstd")
}

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

// ---- the stub "gz" factory ---------------------------------------------

/// Stub decoder that errors on the first `decode_step`.
///
/// Selected by the registry whenever the URL ends in `.gz`. We rely on
/// observing that the *factory* itself is the one constructed (or not)
/// to verify which detection path won. In tests where the magic-byte
/// path should win, the real `zstd::factory` is constructed and decoding
/// succeeds; in tests where this stub is the wrong choice, the decoder
/// either is never built (FormatMismatch short-circuits before
/// construction) or fails immediately on first step.
struct GzStubDecoder;
impl StreamingDecoder for GzStubDecoder {
    fn decode_step(&mut self, _sink: &mut dyn Write) -> Result<DecodeStatus, DecodeError> {
        Err(DecodeError::Read {
            consumed: 0,
            source: std::io::Error::other("gz stub: would have decoded gzip here"),
        })
    }
    fn bytes_consumed(&self) -> ByteOffset {
        ByteOffset::ZERO
    }
    fn frame_boundary(&self) -> Option<ByteOffset> {
        None
    }
}

fn gz_stub_factory(_src: Box<dyn Read + Send>) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    Ok(Box::new(GzStubDecoder))
}

/// Registry for these tests: zstd's defaults plus a `.gz` / "gzip"
/// stub registered with the gzip magic at offset 0 (`1F 8B`).
fn registry_with_gzip_stub() -> DecoderRegistry {
    let mut r = DecoderRegistry::with_defaults();
    r.register_format(
        "gzip",
        &[".gz"],
        &[MagicSignature {
            offset: 0,
            bytes: &[0x1F, 0x8B],
        }],
        gz_stub_factory,
    );
    r
}

fn make_args(
    server: &MockServer,
    suffix: &str,
    output: OutputTarget,
    config: CoordinatorConfig,
    registry: DecoderRegistry,
) -> RunArgs {
    RunArgs {
        url: format!("{}/{suffix}", server.base_url()),
        output,
        config,
        client: build_client(),
        registry,
        progress: None,
        progress_state: None,
        kill_switch: None,
    }
}

// ---- (1) suffix path works --------------------------------------------

#[test]
fn detection_suffix_only_path_extracts_zst() {
    let payload = b"suffix-only-payload, ".repeat(1024);
    let body = encode_zstd(&payload);
    let server = MockServer::start(ok_handler(body, Some("\"v-suffix\"")));

    let work = unique_dir("suffix");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");

    let args = make_args(
        &server,
        "x.zst",
        OutputTarget::File(out_path.clone()),
        coord_config_for_test(4096),
        registry_with_gzip_stub(),
    );
    let stats = run(args).expect("suffix path run");
    assert_eq!(stats.extraction.bytes_out, payload.len() as u64);
    assert_eq!(fs::read(&out_path).expect("read"), payload);
}

// ---- (2) magic-only path works ----------------------------------------

#[test]
fn detection_magic_only_path_extracts_when_no_suffix_registered() {
    // URL ends in `.bin` — neither the default registry nor the gzip
    // stub registers that suffix. The body is real zstd; the magic
    // detector must pick the zstd factory off the prefix.
    let payload = b"magic-only-payload, ".repeat(1024);
    let body = encode_zstd(&payload);
    let server = MockServer::start(ok_handler(body, Some("\"v-magic\"")));

    let work = unique_dir("magic");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");

    let args = make_args(
        &server,
        "data.bin",
        OutputTarget::File(out_path.clone()),
        coord_config_for_test(4096),
        registry_with_gzip_stub(),
    );
    let stats = run(args).expect("magic path run");
    assert_eq!(stats.extraction.bytes_out, payload.len() as u64);
    assert_eq!(fs::read(&out_path).expect("read"), payload);
}

// ---- (3) suffix vs. magic conflict --> FormatMismatch ------------------

#[test]
fn detection_conflict_aborts_with_format_mismatch() {
    // URL ends in `.gz` (suffix → gzip stub) but body is zstd
    // (magic → zstd). Without an override, the run must abort with a
    // typed FormatMismatch error before any decoding happens.
    let payload = b"conflict-payload, ".repeat(1024);
    let body = encode_zstd(&payload);
    let server = MockServer::start(ok_handler(body, Some("\"v-conflict\"")));

    let work = unique_dir("conflict");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");

    let args = make_args(
        &server,
        "x.gz",
        OutputTarget::File(out_path),
        coord_config_for_test(4096),
        registry_with_gzip_stub(),
    );
    let err = run(args).expect_err("must mismatch");
    match err {
        CoordinatorError::FormatMismatch {
            suffix_format,
            magic_format,
        } => {
            assert_eq!(suffix_format.as_deref(), Some("gzip"));
            assert_eq!(magic_format.as_deref(), Some("zstd"));
        }
        other => panic!("expected FormatMismatch, got {other:?}"),
    }
}

// ---- (4) --force-format-from-magic resolves the conflict --------------

#[test]
fn detection_conflict_resolved_by_force_format_from_magic() {
    let payload = b"force-magic-payload, ".repeat(1024);
    let body = encode_zstd(&payload);
    let server = MockServer::start(ok_handler(body, Some("\"v-forced\"")));

    let work = unique_dir("force_magic");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");

    let mut config = coord_config_for_test(4096);
    config.force_format_from_magic = true;
    let args = make_args(
        &server,
        "x.gz",
        OutputTarget::File(out_path.clone()),
        config,
        registry_with_gzip_stub(),
    );
    let stats = run(args).expect("force-magic run");
    assert_eq!(stats.extraction.bytes_out, payload.len() as u64);
    assert_eq!(fs::read(&out_path).expect("read"), payload);
}

// ---- --format <name> bypasses both detectors --------------------------

#[test]
fn detection_forced_format_name_bypasses_sniff() {
    // The URL has no suffix at all — neither suffix nor magic-aware
    // mode would normally short-circuit it. With `--format zstd` the
    // user names the decoder explicitly.
    let payload = b"forced-name-payload, ".repeat(1024);
    let body = encode_zstd(&payload);
    let server = MockServer::start(ok_handler(body, Some("\"v-forced-name\"")));

    let work = unique_dir("forced_name");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");

    let mut config = coord_config_for_test(4096);
    config.forced_format = Some("zstd".into());
    let args = make_args(
        &server,
        "download",
        OutputTarget::File(out_path.clone()),
        config,
        registry_with_gzip_stub(),
    );
    let stats = run(args).expect("forced-name run");
    assert_eq!(stats.extraction.bytes_out, payload.len() as u64);
    assert_eq!(fs::read(&out_path).expect("read"), payload);
}

#[test]
fn detection_forced_format_unknown_name_errors_cleanly() {
    let payload = b"unknown-name-payload";
    let body = encode_zstd(payload);
    let server = MockServer::start(ok_handler(body, Some("\"v-unknown\"")));

    let work = unique_dir("unknown_name");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");

    let mut config = coord_config_for_test(4096);
    config.forced_format = Some("brotli".into());
    let args = make_args(
        &server,
        "x.zst",
        OutputTarget::File(out_path),
        config,
        registry_with_gzip_stub(),
    );
    let err = run(args).expect_err("unknown format must error");
    match err {
        CoordinatorError::UnknownFormatName { name, available } => {
            assert_eq!(name, "brotli");
            assert!(
                available.iter().any(|n| n == "zstd"),
                "expected zstd in available formats, got {available:?}"
            );
        }
        other => panic!("expected UnknownFormatName, got {other:?}"),
    }
}

// ---- no decoder at all when neither suffix nor magic match ------------

#[test]
fn detection_no_signal_returns_no_decoder() {
    // Use a body that is not a valid zstd or gzip stream and a URL
    // suffix that nothing handles. Both paths must miss; the
    // coordinator must surface NoDecoder, not FormatMismatch.
    let body = vec![0u8; 1024];
    let server = MockServer::start(ok_handler(body, Some("\"v-nope\"")));

    let work = unique_dir("no_decoder");
    let _g = CleanupDir(work.clone());
    let out_path = work.join("out.bin");

    let args = make_args(
        &server,
        "datafile.unknown",
        OutputTarget::File(out_path),
        coord_config_for_test(4096),
        registry_with_gzip_stub(),
    );
    let err = run(args).expect_err("must error");
    assert!(
        matches!(err, CoordinatorError::NoDecoder { .. }),
        "expected NoDecoder, got {err:?}"
    );
}
