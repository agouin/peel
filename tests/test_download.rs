//! Integration tests for `peel::download::scheduler`.
//!
//! Each test starts a fresh [`MockServer`], constructs a sparse file
//! and a [`ChunkBitmap`] sized to the source, then drives
//! `peel::download::run` against the mock. Assertions exercise the
//! plan §5 acceptance criteria: parallel happy path, retry-on-5xx,
//! abort on ETag change, single-stream fallback, resume, missing
//! Content-Length, and cursor-based dispatch priority.

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use peel::bitmap::ChunkBitmap;
use peel::download::{
    chunk_count, discover, discover_with_mirrors, run, ChunkSizePolicy, DownloadMode, MirrorSet,
    RetryConfig, SchedulerConfig, SchedulerError, SparseFile, WorkerError,
};
use peel::http::{Client, ClientConfig, Url};
use peel::types::ChunkIndex;

#[path = "support/mod.rs"]
mod support;

use support::mock_server::{MockRequest, MockResponse, MockServer};

// ---- helpers -----------------------------------------------------------

fn temp_path(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static UNIQ: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("peel_test_download_{label}_{pid}_{nanos}_{n}.bin"))
}

struct CleanupOnDrop(PathBuf);
impl Drop for CleanupOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn build_client() -> Client {
    let cfg = ClientConfig {
        timeout: Duration::from_secs(5),
        ..ClientConfig::default()
    };
    Client::with_config(cfg).expect("client constructs")
}

fn url(server: &MockServer, path: &str) -> Url {
    Url::parse(&format!("{}{path}", server.base_url())).expect("url parses")
}

fn fast_retry() -> RetryConfig {
    RetryConfig {
        max_attempts: 5,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(5),
    }
}

fn cfg(chunk_size: u64, workers: u32) -> SchedulerConfig {
    SchedulerConfig {
        chunk_size,
        workers,
        retry: fast_retry(),
        progress: None,
        policy: None,
        fingerprints: None,
        probe: peel::download::ProbeConfig::default(),
        mirrors: None,
        rate_limiter: None,
        max_disk_buffer: None,
        abort: None,
    }
}

/// Parse a `Range: bytes=A-B` header (inclusive) into `(a, b)`.
fn parse_range(value: &str) -> Option<(u64, u64)> {
    let after = value.strip_prefix("bytes=")?;
    let (a, b) = after.split_once('-')?;
    let a: u64 = a.parse().ok()?;
    let b: u64 = b.parse().ok()?;
    Some((a, b))
}

/// Build a deterministic source body of `len` bytes (cycle of 0..=255).
fn make_body(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i & 0xFF) as u8).collect()
}

/// Standard "well-behaved server" handler factory: HEAD reports
/// `Content-Length`, `Accept-Ranges: bytes`, and the supplied `etag`;
/// every range request gets a 206 with the matching slice and echoed
/// `ETag`.
fn ok_handler(
    body: Vec<u8>,
    etag: Option<&'static str>,
) -> impl Fn(&MockRequest, u64) -> MockResponse + Send + Sync + 'static {
    move |req, _n| serve(req, &body, etag.map(str::to_string), None)
}

fn serve(
    req: &MockRequest,
    body: &[u8],
    etag: Option<String>,
    last_modified: Option<String>,
) -> MockResponse {
    let mut head_headers: Vec<(String, String)> = vec![
        ("Content-Length".into(), body.len().to_string()),
        ("Accept-Ranges".into(), "bytes".into()),
    ];
    if let Some(e) = &etag {
        head_headers.push(("ETag".into(), e.clone()));
    }
    if let Some(lm) = &last_modified {
        head_headers.push(("Last-Modified".into(), lm.clone()));
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
            if let Some(lm) = &last_modified {
                h.push(("Last-Modified".into(), lm.clone()));
            }
            return MockResponse::Reply {
                status: 206,
                reason: "Partial Content",
                headers: h,
                body: slice,
            };
        }
    }
    // Full GET
    let mut h: Vec<(String, String)> = Vec::new();
    if let Some(e) = &etag {
        h.push(("ETag".into(), e.clone()));
    }
    if let Some(lm) = &last_modified {
        h.push(("Last-Modified".into(), lm.clone()));
    }
    MockResponse::Reply {
        status: 200,
        reason: "OK",
        headers: h,
        body: body.to_vec(),
    }
}

/// Read the sparse file's contents fully.
fn read_full(path: &std::path::Path) -> Vec<u8> {
    std::fs::read(path).expect("read sparse file")
}

// ---- discover ----------------------------------------------------------

#[test]
fn discover_extracts_size_etag_and_accept_ranges() {
    let body = make_body(1234);
    let server = MockServer::start(ok_handler(body, Some("\"v1\"")));
    let client = build_client();

    let info = discover(&client, &url(&server, "/foo")).expect("discover ok");
    assert_eq!(info.total_size, 1234);
    assert_eq!(info.fingerprint.etag.as_deref(), Some("\"v1\""));
    assert!(info.accept_ranges);
    assert_eq!(info.url.path(), "/foo");
}

#[test]
fn discover_records_no_accept_ranges_when_absent() {
    let server = MockServer::start(|req: &MockRequest, _n| {
        assert_eq!(req.method, "HEAD");
        MockResponse::Reply {
            status: 200,
            reason: "OK",
            headers: vec![("Content-Length".into(), "100".into())],
            body: Vec::new(),
        }
    });
    let client = build_client();
    let info = discover(&client, &url(&server, "/")).expect("discover ok");
    assert_eq!(info.total_size, 100);
    assert!(!info.accept_ranges);
    assert!(info.fingerprint.is_empty());
}

#[test]
fn discover_errors_when_content_length_missing() {
    // HEAD returns no Content-Length and the ranged-GET fallback also
    // fails to surface one (no Content-Range). Discovery must report
    // `MissingContentLength` rather than silently succeeding.
    let server = MockServer::start(|req: &MockRequest, _n| {
        if req.method == "HEAD" {
            // The Reply helper auto-adds Content-Length, so build the
            // wire bytes directly. Connection: close terminates the
            // body so hyper doesn't wait on a Content-Length.
            let raw =
                b"HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n".to_vec();
            return MockResponse::RawBytesThenClose(raw);
        }
        // 206 with no Content-Range: get_range accepts the status but
        // the fallback parser refuses without a total.
        MockResponse::Reply {
            status: 206,
            reason: "Partial Content",
            headers: vec![],
            body: vec![0],
        }
    });
    let client = build_client();
    let err = discover(&client, &url(&server, "/")).expect_err("must error");
    assert!(matches!(err, SchedulerError::MissingContentLength { .. }));
}

#[test]
fn discover_falls_back_to_range_probe_when_head_returns_403() {
    // Mirrors the publicnode/MinIO presigned-URL bug: HEAD redirects
    // to a URL signed only for GET, which 403s every HEAD with
    // `content-length: 0`. The fallback ranged GET succeeds and
    // returns the real total via Content-Range.
    let body = make_body(8192);
    let body_clone = body.clone();
    let server = MockServer::start(move |req: &MockRequest, _n| {
        if req.method == "HEAD" {
            return MockResponse::Reply {
                status: 403,
                reason: "Forbidden",
                headers: vec![("Content-Length".into(), "0".into())],
                body: Vec::new(),
            };
        }
        let range_hdr = req.header("range").expect("worker must send Range");
        let (a, b) = parse_range(range_hdr).expect("Range parses");
        let a_us = a as usize;
        let b_us = b as usize;
        let slice = body_clone[a_us..=b_us].to_vec();
        MockResponse::Reply {
            status: 206,
            reason: "Partial Content",
            headers: vec![(
                "Content-Range".into(),
                format!("bytes {a}-{b}/{}", body_clone.len()),
            )],
            body: slice,
        }
    });
    let client = build_client();
    let info = discover(&client, &url(&server, "/")).expect("discover via fallback");
    assert_eq!(info.total_size, body.len() as u64);
    assert!(info.accept_ranges);
}

#[test]
fn discover_falls_back_when_head_2xx_has_zero_content_length() {
    // CDN edge case: HEAD returns 200 with `Content-Length: 0` (the
    // edge stripped CL on the redirect response). Fallback recovers
    // the real total.
    let body = make_body(4096);
    let body_clone = body.clone();
    let server = MockServer::start(move |req: &MockRequest, _n| {
        if req.method == "HEAD" {
            return MockResponse::Reply {
                status: 200,
                reason: "OK",
                headers: vec![("Content-Length".into(), "0".into())],
                body: Vec::new(),
            };
        }
        let range_hdr = req.header("range").expect("worker must send Range");
        let (a, b) = parse_range(range_hdr).expect("Range parses");
        let a_us = a as usize;
        let b_us = b as usize;
        let slice = body_clone[a_us..=b_us].to_vec();
        MockResponse::Reply {
            status: 206,
            reason: "Partial Content",
            headers: vec![(
                "Content-Range".into(),
                format!("bytes {a}-{b}/{}", body_clone.len()),
            )],
            body: slice,
        }
    });
    let client = build_client();
    let info = discover(&client, &url(&server, "/")).expect("discover via fallback");
    assert_eq!(info.total_size, body.len() as u64);
}

// ---- run: parallel happy path -----------------------------------------

#[test]
fn run_parallel_downloads_full_body_byte_identical() {
    let body = make_body(40_000);
    let body_clone = body.clone();
    let server = MockServer::start(ok_handler(body, Some("\"v1\"")));
    let client = build_client();

    let info = discover(&client, &url(&server, "/data")).expect("discover");
    let chunk_size = 4096;
    let total_chunks = chunk_count(info.total_size, chunk_size).unwrap();

    let path = temp_path("parallel");
    let _cleanup = CleanupOnDrop(path.clone());
    let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");
    let bitmap = ChunkBitmap::new(total_chunks);
    let cursor = AtomicU64::new(0);

    let stats = run(
        &client,
        &info,
        &sparse,
        &bitmap,
        &cursor,
        &cfg(chunk_size, 4),
    )
    .expect("run ok");

    assert_eq!(stats.bytes_downloaded as usize, body_clone.len());
    assert_eq!(stats.chunks_completed, total_chunks);
    assert_eq!(stats.chunks_resumed, 0);
    assert!(matches!(
        stats.mode,
        DownloadMode::Parallel { workers: 4, .. }
    ));
    for i in 0..total_chunks {
        assert!(bitmap.is_complete(ChunkIndex::new(i)));
    }
    assert_eq!(read_full(&path), body_clone);
}

#[test]
fn run_parallel_handles_partial_last_chunk() {
    let body = make_body(10_000); // not a multiple of chunk_size=3000
    let body_clone = body.clone();
    let server = MockServer::start(ok_handler(body, None));
    let client = build_client();

    let info = discover(&client, &url(&server, "/")).expect("discover");
    let chunk_size = 3000;
    let total_chunks = chunk_count(info.total_size, chunk_size).unwrap();
    assert_eq!(total_chunks, 4); // 3 full + 1 partial

    let path = temp_path("partial_tail");
    let _cleanup = CleanupOnDrop(path.clone());
    let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");
    let bitmap = ChunkBitmap::new(total_chunks);
    let cursor = AtomicU64::new(0);

    run(
        &client,
        &info,
        &sparse,
        &bitmap,
        &cursor,
        &cfg(chunk_size, 2),
    )
    .expect("run ok");
    assert_eq!(read_full(&path), body_clone);
}

// ---- run: retry on 5xx -------------------------------------------------

#[test]
fn run_retries_on_503_then_succeeds() {
    let body = make_body(8000);
    let body_clone = body.clone();
    let fail_once: Arc<Mutex<std::collections::HashSet<(u64, u64)>>> =
        Arc::new(Mutex::new(Default::default()));
    let fail_once_clone = Arc::clone(&fail_once);

    let server = MockServer::start(move |req: &MockRequest, _n| {
        if req.method == "HEAD" {
            return MockResponse::Reply {
                status: 200,
                reason: "OK",
                headers: vec![
                    ("Content-Length".into(), body.len().to_string()),
                    ("Accept-Ranges".into(), "bytes".into()),
                ],
                body: Vec::new(),
            };
        }
        if let Some(range_hdr) = req.header("range") {
            if let Some((a, b)) = parse_range(range_hdr) {
                let mut seen = fail_once_clone.lock().unwrap();
                if !seen.contains(&(a, b)) {
                    seen.insert((a, b));
                    drop(seen);
                    return MockResponse::Reply {
                        status: 503,
                        reason: "Service Unavailable",
                        headers: vec![("Retry-After".into(), "0".into())],
                        body: Vec::new(),
                    };
                }
                let slice = body[a as usize..=b as usize].to_vec();
                return MockResponse::Reply {
                    status: 206,
                    reason: "Partial Content",
                    headers: vec![(
                        "Content-Range".into(),
                        format!("bytes {a}-{b}/{}", body.len()),
                    )],
                    body: slice,
                };
            }
        }
        MockResponse::Reply {
            status: 400,
            reason: "Bad Request",
            headers: vec![],
            body: Vec::new(),
        }
    });
    let client = build_client();

    let info = discover(&client, &url(&server, "/")).expect("discover");
    let chunk_size = 2000;
    let total_chunks = chunk_count(info.total_size, chunk_size).unwrap();
    let path = temp_path("retry_503");
    let _cleanup = CleanupOnDrop(path.clone());
    let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");
    let bitmap = ChunkBitmap::new(total_chunks);
    let cursor = AtomicU64::new(0);

    let stats = run(
        &client,
        &info,
        &sparse,
        &bitmap,
        &cursor,
        &cfg(chunk_size, 2),
    )
    .expect("run");
    assert_eq!(stats.chunks_completed, total_chunks);
    // Each chunk failed once (503) and then succeeded, so retries == chunks.
    assert_eq!(stats.retries, u64::from(total_chunks));
    assert_eq!(read_full(&path), body_clone);
}

// ---- run: ETag change aborts ------------------------------------------

#[test]
fn run_aborts_when_etag_changes_mid_download() {
    let body = make_body(10_000);
    let head_count: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let counter = Arc::clone(&head_count);

    let server = MockServer::start(move |req: &MockRequest, _n| {
        if req.method == "HEAD" {
            return MockResponse::Reply {
                status: 200,
                reason: "OK",
                headers: vec![
                    ("Content-Length".into(), body.len().to_string()),
                    ("Accept-Ranges".into(), "bytes".into()),
                    ("ETag".into(), "\"v1\"".into()),
                ],
                body: Vec::new(),
            };
        }
        // Range request: first one returns the original ETag, every
        // subsequent one returns a different ETag to simulate the
        // source rotating mid-download.
        if let Some(range_hdr) = req.header("range") {
            if let Some((a, b)) = parse_range(range_hdr) {
                let n = counter.fetch_add(1, Ordering::Relaxed);
                let etag = if n == 0 { "\"v1\"" } else { "\"v2\"" };
                let slice = body[a as usize..=b as usize].to_vec();
                return MockResponse::Reply {
                    status: 206,
                    reason: "Partial Content",
                    headers: vec![
                        (
                            "Content-Range".into(),
                            format!("bytes {a}-{b}/{}", body.len()),
                        ),
                        ("ETag".into(), etag.into()),
                    ],
                    body: slice,
                };
            }
        }
        MockResponse::Reply {
            status: 400,
            reason: "Bad Request",
            headers: vec![],
            body: Vec::new(),
        }
    });
    let client = build_client();

    let info = discover(&client, &url(&server, "/")).expect("discover");
    let chunk_size = 2500;
    let total_chunks = chunk_count(info.total_size, chunk_size).unwrap();
    let path = temp_path("etag_change");
    let _cleanup = CleanupOnDrop(path.clone());
    let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");
    let bitmap = ChunkBitmap::new(total_chunks);
    let cursor = AtomicU64::new(0);

    let err = run(
        &client,
        &info,
        &sparse,
        &bitmap,
        &cursor,
        &cfg(chunk_size, 2),
    )
    .expect_err("must error");
    match err {
        SchedulerError::ChunkFailed { source, .. } => {
            assert!(matches!(source, WorkerError::SourceChanged { .. }));
        }
        other => panic!("expected ChunkFailed/SourceChanged, got {other:?}"),
    }
}

// ---- run: single-stream fallback --------------------------------------

#[test]
fn run_falls_back_to_single_stream_when_ranges_unsupported() {
    let body = make_body(7000);
    let body_clone = body.clone();
    // No Accept-Ranges header, so discover() reports accept_ranges=false.
    let server = MockServer::start(move |req: &MockRequest, _n| {
        if req.method == "HEAD" {
            return MockResponse::Reply {
                status: 200,
                reason: "OK",
                headers: vec![("Content-Length".into(), body.len().to_string())],
                body: Vec::new(),
            };
        }
        // A full GET; ignore any Range header the client may send.
        MockResponse::Reply {
            status: 200,
            reason: "OK",
            headers: vec![],
            body: body.clone(),
        }
    });
    let client = build_client();

    let info = discover(&client, &url(&server, "/")).expect("discover");
    assert!(!info.accept_ranges);
    let chunk_size = 2000;
    let total_chunks = chunk_count(info.total_size, chunk_size).unwrap();
    let path = temp_path("single_stream");
    let _cleanup = CleanupOnDrop(path.clone());
    let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");
    let bitmap = ChunkBitmap::new(total_chunks);
    let cursor = AtomicU64::new(0);

    let stats = run(
        &client,
        &info,
        &sparse,
        &bitmap,
        &cursor,
        &cfg(chunk_size, 2),
    )
    .expect("run");
    assert!(matches!(stats.mode, DownloadMode::SingleStream));
    assert_eq!(stats.bytes_downloaded as usize, body_clone.len());
    assert_eq!(stats.chunks_completed, total_chunks);
    for i in 0..total_chunks {
        assert!(bitmap.is_complete(ChunkIndex::new(i)));
    }
    assert_eq!(read_full(&path), body_clone);
}

// ---- run: resume from prior checkpoint --------------------------------

#[test]
fn run_skips_chunks_already_marked_complete() {
    let body = make_body(20_000);
    let body_clone = body.clone();
    let server = MockServer::start(ok_handler(body, Some("\"v1\"")));
    let client = build_client();

    let info = discover(&client, &url(&server, "/")).expect("discover");
    let chunk_size = 4000;
    let total_chunks = chunk_count(info.total_size, chunk_size).unwrap();
    assert_eq!(total_chunks, 5);

    let path = temp_path("resume");
    let _cleanup = CleanupOnDrop(path.clone());
    let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");

    // Pre-write the bytes for chunks 0 and 2 into the sparse file (as
    // if a prior run had completed them) and pre-mark them in the
    // bitmap. A correct scheduler must then only fetch chunks 1, 3, 4.
    sparse
        .pwrite_at(peel::types::ByteOffset::new(0), &body_clone[0..4000])
        .expect("pre-write 0");
    sparse
        .pwrite_at(
            peel::types::ByteOffset::new(8000),
            &body_clone[8000..12_000],
        )
        .expect("pre-write 2");
    let bitmap = ChunkBitmap::new(total_chunks);
    bitmap.mark_complete(ChunkIndex::new(0));
    bitmap.mark_complete(ChunkIndex::new(2));

    let cursor = AtomicU64::new(0);
    let stats = run(
        &client,
        &info,
        &sparse,
        &bitmap,
        &cursor,
        &cfg(chunk_size, 2),
    )
    .expect("run");
    assert_eq!(stats.chunks_resumed, 2);
    assert_eq!(stats.chunks_completed, total_chunks - 2);

    // Inspect the requests the server saw: HEAD + 3 ranged GETs.
    let reqs = server.snapshot_requests();
    let range_reqs: Vec<_> = reqs.iter().filter(|r| r.method == "GET").collect();
    assert_eq!(range_reqs.len(), 3, "must skip the two pre-marked chunks");
    let mut starts: Vec<u64> = range_reqs
        .iter()
        .filter_map(|r| r.header("range").and_then(parse_range).map(|(a, _)| a))
        .collect();
    starts.sort_unstable();
    assert_eq!(starts, vec![4000, 12_000, 16_000]);
    assert_eq!(read_full(&path), body_clone);
}

// ---- run: cursor-based dispatch priority ------------------------------

#[test]
fn run_dispatches_chunks_starting_at_cursor() {
    // workers=1 makes dispatch order deterministic: chunk N is
    // requested only after chunk dispatched-before-it has completed.
    // With cursor pre-set to chunk 5, the *first* request must be for
    // chunk 5.
    let body = make_body(10_000);
    let server = MockServer::start(ok_handler(body, None));
    let client = build_client();

    let info = discover(&client, &url(&server, "/")).expect("discover");
    let chunk_size = 1000;
    let total_chunks = chunk_count(info.total_size, chunk_size).unwrap();
    assert_eq!(total_chunks, 10);

    let path = temp_path("cursor_priority");
    let _cleanup = CleanupOnDrop(path.clone());
    let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");
    let bitmap = ChunkBitmap::new(total_chunks);
    // Cursor starts at chunk 5's byte offset.
    let cursor = AtomicU64::new(5 * chunk_size);

    run(
        &client,
        &info,
        &sparse,
        &bitmap,
        &cursor,
        &cfg(chunk_size, 1),
    )
    .expect("run");

    let reqs = server.snapshot_requests();
    let range_starts: Vec<u64> = reqs
        .iter()
        .filter(|r| r.method == "GET")
        .filter_map(|r| r.header("range").and_then(parse_range).map(|(a, _)| a))
        .collect();
    assert_eq!(range_starts.len(), total_chunks as usize);
    assert_eq!(range_starts[0], 5 * chunk_size, "cursor priority");
    // After exhausting chunks 5..10, the scheduler wraps to 0..5.
    let expected: Vec<u64> = (5..10).chain(0..5).map(|i| i * chunk_size).collect();
    assert_eq!(range_starts, expected);
}

// ---- run: bitmap-length validation ------------------------------------

#[test]
fn run_rejects_mismatched_bitmap_length() {
    let body = make_body(8000);
    let server = MockServer::start(ok_handler(body, None));
    let client = build_client();

    let info = discover(&client, &url(&server, "/")).expect("discover");
    let chunk_size = 2000;
    // Wrong size: should be 4 chunks, but pass 5.
    let bitmap = ChunkBitmap::new(5);
    let path = temp_path("bitmap_mismatch");
    let _cleanup = CleanupOnDrop(path.clone());
    let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");
    let cursor = AtomicU64::new(0);

    let err = run(
        &client,
        &info,
        &sparse,
        &bitmap,
        &cursor,
        &cfg(chunk_size, 2),
    )
    .expect_err("must error");
    assert!(matches!(
        err,
        SchedulerError::BitmapLengthMismatch {
            actual: 5,
            expected: 4
        }
    ));
}

// ---- run: zero workers / zero chunk size ------------------------------

#[test]
fn run_rejects_zero_chunk_size() {
    let body = make_body(100);
    let server = MockServer::start(ok_handler(body, None));
    let client = build_client();
    let info = discover(&client, &url(&server, "/")).expect("discover");
    let path = temp_path("zero_chunk");
    let _cleanup = CleanupOnDrop(path.clone());
    let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");
    let bitmap = ChunkBitmap::new(0);
    let cursor = AtomicU64::new(0);
    let bad = SchedulerConfig {
        chunk_size: 0,
        workers: 1,
        retry: fast_retry(),
        progress: None,
        policy: None,
        fingerprints: None,
        probe: peel::download::ProbeConfig::default(),
        mirrors: None,
        rate_limiter: None,
        max_disk_buffer: None,
        abort: None,
    };
    let err = run(&client, &info, &sparse, &bitmap, &cursor, &bad).expect_err("must error");
    assert!(matches!(err, SchedulerError::InvalidChunkSize));
}

#[test]
fn run_rejects_zero_workers() {
    let body = make_body(100);
    let server = MockServer::start(ok_handler(body, None));
    let client = build_client();
    let info = discover(&client, &url(&server, "/")).expect("discover");
    let path = temp_path("zero_workers");
    let _cleanup = CleanupOnDrop(path.clone());
    let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");
    let bitmap = ChunkBitmap::new(chunk_count(info.total_size, 50).unwrap());
    let cursor = AtomicU64::new(0);
    let bad = SchedulerConfig {
        chunk_size: 50,
        workers: 0,
        retry: fast_retry(),
        progress: None,
        policy: None,
        fingerprints: None,
        probe: peel::download::ProbeConfig::default(),
        mirrors: None,
        rate_limiter: None,
        max_disk_buffer: None,
        abort: None,
    };
    let err = run(&client, &info, &sparse, &bitmap, &cursor, &bad).expect_err("must error");
    assert!(matches!(err, SchedulerError::InvalidWorkerCount));
}

// ---- adaptive chunk size (PLAN_v2 §8) -----------------------------------

/// Wraps the standard `ok_handler` and counts how many `Range:` headers
/// the server actually saw. With dispatch coalescing on, a download
/// of N bitmap chunks can finish in N/coalesce_factor server hits, so
/// a smaller hit count is direct evidence the policy is taking effect.
fn ok_handler_with_range_counter(
    body: Vec<u8>,
    range_count: Arc<AtomicU64>,
) -> impl Fn(&MockRequest, u64) -> MockResponse + Send + Sync + 'static {
    move |req, _n| {
        if req.method == "GET" && req.header("range").is_some() {
            range_count.fetch_add(1, Ordering::Relaxed);
        }
        serve(req, &body, None, None)
    }
}

#[test]
fn run_with_policy_extracts_byte_identical_output() {
    // Adaptive enabled, against the same body the non-adaptive happy
    // path uses. The output must be byte-identical to a clean
    // non-adaptive run — the policy must never corrupt the file.
    let body = make_body(40_000);
    let body_clone = body.clone();
    let range_count = Arc::new(AtomicU64::new(0));
    let server = MockServer::start(ok_handler_with_range_counter(
        body,
        Arc::clone(&range_count),
    ));
    let client = build_client();
    let info = discover(&client, &url(&server, "/data")).expect("discover");
    let chunk_size = 1024;
    let total_chunks = chunk_count(info.total_size, chunk_size).unwrap();

    let path = temp_path("adaptive_byte_identical");
    let _cleanup = CleanupOnDrop(path.clone());
    let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");
    let bitmap = ChunkBitmap::new(total_chunks);
    let cursor = AtomicU64::new(0);

    let policy = Arc::new(ChunkSizePolicy::with_bounds(
        chunk_size,
        4 * 1024,
        chunk_size,
        16 * 1024,
        Duration::from_millis(0),
    ));

    let cfg = SchedulerConfig {
        chunk_size,
        workers: 4,
        retry: fast_retry(),
        progress: None,
        policy: Some(Arc::clone(&policy)),
        fingerprints: None,
        probe: peel::download::ProbeConfig::default(),
        mirrors: None,
        rate_limiter: None,
        max_disk_buffer: None,
        abort: None,
    };

    let stats = run(&client, &info, &sparse, &bitmap, &cursor, &cfg).expect("adaptive run");
    assert_eq!(stats.bytes_downloaded as usize, body_clone.len());
    assert_eq!(stats.chunks_completed, total_chunks);
    for i in 0..total_chunks {
        assert!(bitmap.is_complete(ChunkIndex::new(i)));
    }
    assert_eq!(read_full(&path), body_clone);
}

#[test]
fn run_with_policy_coalesces_dispatches_into_fewer_range_requests() {
    // 40 KiB body at 1 KiB bitmap chunks = 40 bitmap chunks. With a
    // policy that has dispatched at 4-chunk granularity from the
    // start, we expect ~10 range requests, not 40.
    let body = make_body(40_000);
    let total_chunks = 40u32;
    let chunk_size = 1024u64;
    let range_count = Arc::new(AtomicU64::new(0));
    let server = MockServer::start(ok_handler_with_range_counter(
        body,
        Arc::clone(&range_count),
    ));
    let client = build_client();
    let info = discover(&client, &url(&server, "/data")).expect("discover");

    let path = temp_path("adaptive_coalesce");
    let _cleanup = CleanupOnDrop(path.clone());
    let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");
    let bitmap = ChunkBitmap::new(total_chunks);
    let cursor = AtomicU64::new(0);

    // Pin the policy at 4 chunks per dispatch by setting min == max.
    let policy = Arc::new(ChunkSizePolicy::with_bounds(
        chunk_size,
        4 * chunk_size,
        4 * chunk_size,
        4 * chunk_size,
        Duration::from_millis(0),
    ));

    let cfg = SchedulerConfig {
        chunk_size,
        workers: 4,
        retry: fast_retry(),
        progress: None,
        policy: Some(Arc::clone(&policy)),
        fingerprints: None,
        probe: peel::download::ProbeConfig::default(),
        mirrors: None,
        rate_limiter: None,
        max_disk_buffer: None,
        abort: None,
    };

    let stats = run(&client, &info, &sparse, &bitmap, &cursor, &cfg).expect("adaptive run");
    assert_eq!(stats.chunks_completed, total_chunks);
    let observed = range_count.load(Ordering::Relaxed);
    // 40 chunks / 4 per dispatch = 10 expected range requests. Allow a
    // small slack for the cursor wrap-around path that can re-pick a
    // run shorter than 4 once the tail has fewer remaining chunks
    // than the target — but we're tightly bounded above by 40 (the
    // pre-§8 1-chunk-per-task baseline).
    assert!(
        observed <= 12,
        "expected <= 12 range requests with 4-chunk dispatch, got {observed}"
    );
    assert!(
        observed < u64::from(total_chunks),
        "expected fewer requests than the {total_chunks}-chunk baseline, got {observed}"
    );
}

#[test]
fn run_without_policy_keeps_one_range_per_chunk() {
    // Sanity baseline: with policy = None, every bitmap chunk is its
    // own ranged GET — the pre-§8 behaviour. Pairs with the
    // coalescing test above.
    let body = make_body(40_000);
    let total_chunks = 40u32;
    let chunk_size = 1024u64;
    let range_count = Arc::new(AtomicU64::new(0));
    let server = MockServer::start(ok_handler_with_range_counter(
        body,
        Arc::clone(&range_count),
    ));
    let client = build_client();
    let info = discover(&client, &url(&server, "/data")).expect("discover");

    let path = temp_path("nonadaptive_baseline");
    let _cleanup = CleanupOnDrop(path.clone());
    let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");
    let bitmap = ChunkBitmap::new(total_chunks);
    let cursor = AtomicU64::new(0);

    let cfg = SchedulerConfig {
        chunk_size,
        workers: 4,
        retry: fast_retry(),
        progress: None,
        policy: None,
        fingerprints: None,
        probe: peel::download::ProbeConfig::default(),
        mirrors: None,
        rate_limiter: None,
        max_disk_buffer: None,
        abort: None,
    };

    run(&client, &info, &sparse, &bitmap, &cursor, &cfg).expect("baseline run");
    let observed = range_count.load(Ordering::Relaxed);
    assert_eq!(observed, u64::from(total_chunks));
}

#[test]
fn run_with_policy_resume_honors_existing_bitmap() {
    // Adaptive sizing must not re-dispatch chunks that resumed
    // already-complete. We pre-mark the first half of the bitmap and
    // verify the post-run byte count reflects only the new bytes.
    let body = make_body(20_000);
    let chunk_size = 1024u64;
    let range_count = Arc::new(AtomicU64::new(0));
    let server = MockServer::start(ok_handler_with_range_counter(
        body.clone(),
        Arc::clone(&range_count),
    ));
    let client = build_client();
    let info = discover(&client, &url(&server, "/data")).expect("discover");
    let total_chunks = chunk_count(info.total_size, chunk_size).unwrap();

    let path = temp_path("adaptive_resume");
    let _cleanup = CleanupOnDrop(path.clone());
    let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");
    // Pre-write the first half of the file and mark those bitmap
    // chunks complete to simulate a resume.
    let half_chunks = total_chunks / 2;
    use peel::types::ByteOffset;
    sparse
        .pwrite_at(
            ByteOffset::new(0),
            &body[..(half_chunks as u64 * chunk_size) as usize],
        )
        .expect("pre-fill");
    let bitmap = ChunkBitmap::new(total_chunks);
    for i in 0..half_chunks {
        bitmap.mark_complete(ChunkIndex::new(i));
    }
    let cursor = AtomicU64::new(0);

    let policy = Arc::new(ChunkSizePolicy::with_bounds(
        chunk_size,
        2 * chunk_size,
        chunk_size,
        4 * chunk_size,
        Duration::from_millis(0),
    ));

    let cfg = SchedulerConfig {
        chunk_size,
        workers: 4,
        retry: fast_retry(),
        progress: None,
        policy: Some(policy),
        fingerprints: None,
        probe: peel::download::ProbeConfig::default(),
        mirrors: None,
        rate_limiter: None,
        max_disk_buffer: None,
        abort: None,
    };

    let stats = run(&client, &info, &sparse, &bitmap, &cursor, &cfg).expect("adaptive resume");
    assert_eq!(stats.chunks_resumed, half_chunks);
    // Only the second half was downloaded.
    let remaining_bytes = info.total_size - half_chunks as u64 * chunk_size;
    assert_eq!(stats.bytes_downloaded, remaining_bytes);
    // And byte-identical reassembly.
    assert_eq!(read_full(&path), body);
}

// ---- §11 mid-flight verifier ----------------------------------------

#[test]
fn scheduler_records_per_chunk_crc32c_when_fingerprints_configured() {
    // The §11 contract step 1: workers compute CRC-32C per bitmap
    // chunk and the scheduler stores them in the fingerprint store
    // alongside the bitmap-bit set.
    let chunk_size = 1024u64;
    let total_chunks = 8u32;
    let body = make_body((chunk_size as u32 * total_chunks) as usize);
    let server = MockServer::start(ok_handler(body.clone(), Some("\"v1\"")));

    let url = url(&server, "/data.bin");
    let client = build_client();
    let info = discover(&client, &url).expect("discover");

    let path = temp_path("crc_records");
    let _g = CleanupOnDrop(path.clone());
    let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");
    let bitmap = ChunkBitmap::new(total_chunks);
    let fingerprints = Arc::new(peel::download::ChunkFingerprints::new(total_chunks));
    let cursor = AtomicU64::new(0);

    let scheduler_cfg = SchedulerConfig {
        chunk_size,
        workers: 2,
        retry: fast_retry(),
        progress: None,
        policy: None,
        fingerprints: Some(Arc::clone(&fingerprints)),
        probe: peel::download::ProbeConfig { interval: 0 }, // recording only
        mirrors: None,
        rate_limiter: None,
        max_disk_buffer: None,
        abort: None,
    };
    let stats = run(&client, &info, &sparse, &bitmap, &cursor, &scheduler_cfg).expect("download");
    assert_eq!(stats.chunks_completed, total_chunks);

    // Every chunk's stored CRC-32C must match a fresh computation
    // over the same byte range.
    for i in 0..total_chunks {
        let lo = (i as u64 * chunk_size) as usize;
        let hi = lo + chunk_size as usize;
        let want = peel::hash::crc32c::castagnoli(&body[lo..hi]);
        assert_eq!(
            fingerprints.get(ChunkIndex::new(i)),
            want,
            "chunk {i} fingerprint disagrees",
        );
    }
}

#[test]
fn scheduler_aborts_on_probe_drift_with_typed_error() {
    // Demo from PLAN_v2 §11: the §11 probe re-fetches an
    // already-complete chunk and surfaces drift as
    // `SourceChangedDuringDownload`. We force the probe to land
    // by setting probe.interval = 1, completing every chunk
    // ourselves to seed the fingerprint store with a known-bad
    // CRC, and then watching the scheduler probe and abort.
    let chunk_size = 1024u64;
    let total_chunks = 4u32;
    let body = make_body((chunk_size as u32 * total_chunks) as usize);
    let server = MockServer::start(ok_handler(body.clone(), Some("\"v1\"")));

    let url = url(&server, "/data.bin");
    let client = build_client();
    let info = discover(&client, &url).expect("discover");

    let path = temp_path("probe_drift");
    let _g = CleanupOnDrop(path.clone());
    let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");
    let bitmap = ChunkBitmap::new(total_chunks);

    // Pre-mark every chunk as complete and seed the fingerprint
    // store with deliberately-wrong CRC values, so the scheduler's
    // very first probe immediately observes a mismatch. The
    // scheduler-side dispatch loop won't bother fetching the
    // already-complete chunks, but it *will* tick its
    // completions counter when probes come back.
    //
    // To make probes fire at all, we leave the last chunk
    // incomplete so the scheduler still has work to do. After it
    // completes that one chunk the probe interval (=1) fires and
    // re-fetches a (real) prior chunk against a wrong stored CRC.
    let fingerprints = Arc::new(peel::download::ChunkFingerprints::new(total_chunks));
    for i in 0..total_chunks - 1 {
        bitmap.mark_complete(ChunkIndex::new(i));
        // Wrong CRC: anything that disagrees with the actual
        // body bytes. Use 0xDEAD_BEEF as a deterministic sentinel.
        fingerprints.record(ChunkIndex::new(i), 0xDEAD_BEEF);
    }
    let cursor = AtomicU64::new(0);

    let scheduler_cfg = SchedulerConfig {
        chunk_size,
        workers: 1,
        retry: fast_retry(),
        progress: None,
        policy: None,
        fingerprints: Some(Arc::clone(&fingerprints)),
        // Probe after every Fetch — the very first completion
        // should trigger a probe that hits one of the seeded-wrong
        // chunks.
        probe: peel::download::ProbeConfig { interval: 1 },
        mirrors: None,
        rate_limiter: None,
        max_disk_buffer: None,
        abort: None,
    };
    let err =
        run(&client, &info, &sparse, &bitmap, &cursor, &scheduler_cfg).expect_err("must abort");
    match err {
        SchedulerError::SourceChangedDuringDownload { expected, .. } => {
            assert_eq!(expected, 0xDEAD_BEEF);
        }
        other => panic!("expected SourceChangedDuringDownload, got {other:?}"),
    }
}

// ---- multi-mirror downloads (PLAN_v2 §13) -------------------------------

/// Standard "well-behaved server" handler factory that also tracks
/// every range request it served. The returned tuple is `(handler,
/// hit_counter)` where the counter increments once per non-HEAD
/// request the server processes.
fn counted_ok_handler(
    body: Vec<u8>,
    etag: Option<&'static str>,
) -> (
    impl Fn(&MockRequest, u64) -> MockResponse + Send + Sync + 'static,
    Arc<AtomicU64>,
) {
    let counter = Arc::new(AtomicU64::new(0));
    let counter_for_handler = Arc::clone(&counter);
    let handler = move |req: &MockRequest, _n: u64| {
        if req.method != "HEAD" {
            counter_for_handler.fetch_add(1, Ordering::Relaxed);
        }
        serve(req, &body, etag.map(str::to_string), None)
    };
    (handler, counter)
}

#[test]
fn discover_with_mirrors_keeps_agreeing_mirrors() {
    let body = make_body(8000);
    let body_clone = body.clone();
    let primary = MockServer::start(ok_handler(body, Some("\"v1\"")));
    let mirror = MockServer::start(ok_handler(body_clone, Some("\"v1\"")));
    let client = build_client();
    let primary_url = url(&primary, "/data");
    let mirror_url = url(&mirror, "/data");

    let (info, set, dropped) =
        discover_with_mirrors(&client, &primary_url, &[mirror_url], false).expect("discover");
    assert_eq!(info.total_size, 8000);
    assert_eq!(set.len(), 2);
    assert!(dropped.is_empty());
}

#[test]
fn discover_with_mirrors_drops_size_disagreers() {
    let body = make_body(8000);
    let primary = MockServer::start(ok_handler(body, Some("\"v1\"")));
    // Same content but a different size.
    let mirror = MockServer::start(ok_handler(make_body(7999), Some("\"v1\"")));
    let client = build_client();
    let primary_url = url(&primary, "/data");
    let mirror_url = url(&mirror, "/data");

    let (info, set, dropped) =
        discover_with_mirrors(&client, &primary_url, &[mirror_url], false).expect("discover");
    assert_eq!(info.total_size, 8000);
    assert_eq!(set.len(), 1, "size-disagreeing mirror must be dropped");
    assert_eq!(dropped.len(), 1);
}

#[test]
fn discover_with_mirrors_drops_etag_disagreers_without_sha256() {
    let body = make_body(8000);
    let body_clone = body.clone();
    let primary = MockServer::start(ok_handler(body, Some("\"v1\"")));
    // Same size, different ETag, no Last-Modified to fall back on.
    let mirror = MockServer::start(ok_handler(body_clone, Some("\"different\"")));
    let client = build_client();
    let primary_url = url(&primary, "/data");
    let mirror_url = url(&mirror, "/data");

    let (_info, set, dropped) =
        discover_with_mirrors(&client, &primary_url, &[mirror_url], false).expect("discover");
    assert_eq!(set.len(), 1);
    assert_eq!(dropped.len(), 1);
}

#[test]
fn discover_with_mirrors_keeps_etag_disagreers_when_sha256_set() {
    // With --sha256 set, the run has a byte-level guarantee at end
    // of run, so per-mirror ETag disagreement is allowed.
    let body = make_body(8000);
    let body_clone = body.clone();
    let primary = MockServer::start(ok_handler(body, Some("\"v1\"")));
    let mirror = MockServer::start(ok_handler(body_clone, Some("\"different\"")));
    let client = build_client();
    let primary_url = url(&primary, "/data");
    let mirror_url = url(&mirror, "/data");

    let (_info, set, dropped) =
        discover_with_mirrors(&client, &primary_url, &[mirror_url], true).expect("discover");
    assert_eq!(set.len(), 2, "differing ETag is OK when --sha256 is set");
    assert!(dropped.is_empty());
}

#[test]
fn run_routes_chunks_across_two_mirrors() {
    // Two mirrors serving identical bytes; `workers > 1` so requests
    // can fan out concurrently. We expect *both* mirrors to see at
    // least one ranged GET.
    let body = make_body(40_000);
    let body_clone = body.clone();
    let body_for_mirror = body.clone();

    let (h1, hits1) = counted_ok_handler(body, Some("\"v1\""));
    let (h2, hits2) = counted_ok_handler(body_for_mirror, Some("\"v1\""));
    let primary = MockServer::start(h1);
    let mirror = MockServer::start(h2);
    let client = build_client();
    let primary_url = url(&primary, "/data");
    let mirror_url = url(&mirror, "/data");

    let (info, set, dropped) =
        discover_with_mirrors(&client, &primary_url, &[mirror_url], false).expect("discover");
    assert!(dropped.is_empty());
    assert_eq!(set.len(), 2);
    let mirrors = Arc::new(set);

    let chunk_size = 4096;
    let total_chunks = chunk_count(info.total_size, chunk_size).unwrap();
    let path = temp_path("two_mirrors");
    let _cleanup = CleanupOnDrop(path.clone());
    let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");
    let bitmap = ChunkBitmap::new(total_chunks);
    let cursor = AtomicU64::new(0);
    let scheduler_cfg = SchedulerConfig {
        chunk_size,
        workers: 4,
        retry: fast_retry(),
        progress: None,
        policy: None,
        fingerprints: None,
        probe: peel::download::ProbeConfig::default(),
        mirrors: Some(Arc::clone(&mirrors)),
        rate_limiter: None,
        max_disk_buffer: None,
        abort: None,
    };
    run(&client, &info, &sparse, &bitmap, &cursor, &scheduler_cfg).expect("run");

    assert_eq!(read_full(&path), body_clone);
    let h1_hits = hits1.load(Ordering::Relaxed);
    let h2_hits = hits2.load(Ordering::Relaxed);
    assert!(
        h1_hits > 0 && h2_hits > 0,
        "expected both mirrors to serve at least one chunk; got primary={h1_hits} mirror={h2_hits}",
    );
    assert_eq!(h1_hits + h2_hits, u64::from(total_chunks));
}

#[test]
fn run_falls_back_when_one_mirror_dies() {
    // Mirror A serves the first request then drops every subsequent
    // connection, simulating an outage. Mirror B is healthy. The
    // download must complete via B once A is excluded.
    let body = make_body(40_000);
    let body_clone = body.clone();

    let a_count: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    let counter_a = Arc::clone(&a_count);
    let body_for_a = body.clone();
    let primary_handler = move |req: &MockRequest, _n: u64| {
        if req.method == "HEAD" {
            return serve(req, &body_for_a, Some("\"v1\"".into()), None);
        }
        let n = counter_a.fetch_add(1, Ordering::Relaxed);
        if n == 0 {
            // Serve the first chunk normally.
            serve(req, &body_for_a, Some("\"v1\"".into()), None)
        } else {
            // Then start dropping connections.
            MockResponse::DropConnection
        }
    };
    let primary = MockServer::start(primary_handler);
    let (h_b, hits_b) = counted_ok_handler(body.clone(), Some("\"v1\""));
    let mirror = MockServer::start(h_b);
    let client = build_client();
    let primary_url = url(&primary, "/data");
    let mirror_url = url(&mirror, "/data");

    let (info, set, dropped) =
        discover_with_mirrors(&client, &primary_url, &[mirror_url], false).expect("discover");
    assert!(dropped.is_empty());
    // Construct the live MirrorSet with a tiny exclusion window so
    // that a flaky mirror's exclusion does not stretch the test
    // timeout. The default is 30 s, way too long for a unit test.
    let mirrors = Arc::new(MirrorSet::with_exclude_for(
        vec![
            peel::download::Mirror::new(
                set.mirror(0).url.clone(),
                set.mirror(0).fingerprint.clone(),
            ),
            peel::download::Mirror::new(
                set.mirror(1).url.clone(),
                set.mirror(1).fingerprint.clone(),
            ),
        ],
        Duration::from_millis(50),
    ));

    let chunk_size = 4096;
    let total_chunks = chunk_count(info.total_size, chunk_size).unwrap();
    let path = temp_path("one_mirror_dies");
    let _cleanup = CleanupOnDrop(path.clone());
    let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");
    let bitmap = ChunkBitmap::new(total_chunks);
    let cursor = AtomicU64::new(0);
    let scheduler_cfg = SchedulerConfig {
        chunk_size,
        workers: 2,
        retry: fast_retry(),
        progress: None,
        policy: None,
        fingerprints: None,
        probe: peel::download::ProbeConfig::default(),
        mirrors: Some(Arc::clone(&mirrors)),
        rate_limiter: None,
        max_disk_buffer: None,
        abort: None,
    };
    run(&client, &info, &sparse, &bitmap, &cursor, &scheduler_cfg)
        .expect("run completes despite mirror A failing");

    assert_eq!(read_full(&path), body_clone);
    // Mirror B must have served the bulk of the chunks.
    let b_hits = hits_b.load(Ordering::Relaxed);
    assert!(
        b_hits >= u64::from(total_chunks) - 1,
        "expected mirror B to serve almost every chunk after A failed; got {b_hits}",
    );
}

#[test]
fn run_completes_after_all_mirrors_recover() {
    // Both mirrors fail their first non-HEAD request, then succeed
    // afterwards. With a tiny exclusion window the picker waits
    // briefly for a recovery and the download finishes. This covers
    // the "transient failure on every mirror does not fail the
    // whole download" rule from PLAN_v2.md §13.
    let body = make_body(8000);
    let body_clone = body.clone();

    let make_flaky = |body: Vec<u8>| {
        let counter: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
        let counter_h = Arc::clone(&counter);
        let handler = move |req: &MockRequest, _n: u64| {
            if req.method == "HEAD" {
                return serve(req, &body, Some("\"v1\"".into()), None);
            }
            let n = counter_h.fetch_add(1, Ordering::Relaxed);
            if n == 0 {
                MockResponse::Reply {
                    status: 503,
                    reason: "Service Unavailable",
                    headers: vec![],
                    body: Vec::new(),
                }
            } else {
                serve(req, &body, Some("\"v1\"".into()), None)
            }
        };
        (handler, counter)
    };
    let (ha, _ca) = make_flaky(body.clone());
    let (hb, _cb) = make_flaky(body.clone());
    let primary = MockServer::start(ha);
    let mirror = MockServer::start(hb);
    let client = build_client();
    let primary_url = url(&primary, "/data");
    let mirror_url = url(&mirror, "/data");

    let (info, set, dropped) =
        discover_with_mirrors(&client, &primary_url, &[mirror_url], false).expect("discover");
    assert!(dropped.is_empty());
    // Tiny exclusion window so the picker recovers quickly when
    // every mirror has failed at least once.
    let mirrors = Arc::new(MirrorSet::with_exclude_for(
        vec![
            peel::download::Mirror::new(
                set.mirror(0).url.clone(),
                set.mirror(0).fingerprint.clone(),
            ),
            peel::download::Mirror::new(
                set.mirror(1).url.clone(),
                set.mirror(1).fingerprint.clone(),
            ),
        ],
        Duration::from_millis(50),
    ));

    let chunk_size = 2000;
    let total_chunks = chunk_count(info.total_size, chunk_size).unwrap();
    let path = temp_path("all_recover");
    let _cleanup = CleanupOnDrop(path.clone());
    let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");
    let bitmap = ChunkBitmap::new(total_chunks);
    let cursor = AtomicU64::new(0);
    let scheduler_cfg = SchedulerConfig {
        chunk_size,
        workers: 2,
        retry: RetryConfig {
            max_attempts: 5,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(5),
        },
        progress: None,
        policy: None,
        fingerprints: None,
        probe: peel::download::ProbeConfig::default(),
        mirrors: Some(Arc::clone(&mirrors)),
        rate_limiter: None,
        max_disk_buffer: None,
        abort: None,
    };
    run(&client, &info, &sparse, &bitmap, &cursor, &scheduler_cfg).expect("recovers");
    assert_eq!(read_full(&path), body_clone);
}

// ---- §14: aggregate bandwidth limiter --------------------------------

#[test]
fn run_parallel_with_rate_limiter_extracts_byte_identical() {
    // The limiter must not corrupt bytes — it merely paces them. Run
    // the standard happy path with a generous limit (so the test
    // itself isn't slow) and assert byte-identical output.
    let body = make_body(40_000);
    let body_clone = body.clone();
    let server = MockServer::start(ok_handler(body, Some("\"v1\"")));
    let client = build_client();

    let info = discover(&client, &url(&server, "/data")).expect("discover");
    let chunk_size = 4096;
    let total_chunks = chunk_count(info.total_size, chunk_size).unwrap();

    let path = temp_path("rate_limit_byte_identical");
    let _cleanup = CleanupOnDrop(path.clone());
    let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");
    let bitmap = ChunkBitmap::new(total_chunks);
    let cursor = AtomicU64::new(0);

    let limiter = Arc::new(peel::download::RateLimiter::new(100 * 1024 * 1024));
    let scheduler_cfg = SchedulerConfig {
        chunk_size,
        workers: 4,
        retry: fast_retry(),
        progress: None,
        policy: None,
        fingerprints: None,
        probe: peel::download::ProbeConfig::default(),
        mirrors: None,
        rate_limiter: Some(Arc::clone(&limiter)),
        max_disk_buffer: None,
        abort: None,
    };
    run(&client, &info, &sparse, &bitmap, &cursor, &scheduler_cfg).expect("run ok");
    assert_eq!(read_full(&path), body_clone);
}

#[test]
fn run_parallel_with_rate_limiter_paces_below_uncapped_rate() {
    // Run twice against the same body — once unlimited, once at
    // 1 MiB/s — and assert the limited run takes meaningfully longer.
    // The body is 4 MiB so the limited run pays the rate for the bulk
    // of the bytes, well above measurement noise even on slow CI.
    let body = make_body(4 * 1024 * 1024);
    let body_clone = body.clone();
    let server = MockServer::start(ok_handler(body, Some("\"v1\"")));
    let client = build_client();

    let info = discover(&client, &url(&server, "/data")).expect("discover");
    let chunk_size = 256 * 1024;
    let total_chunks = chunk_count(info.total_size, chunk_size).unwrap();

    let measure = |limiter: Option<Arc<peel::download::RateLimiter>>| -> Duration {
        let path = temp_path("rate_limit_paces");
        let cleanup = CleanupOnDrop(path.clone());
        let sparse = SparseFile::open_or_create(&path, info.total_size).expect("sparse");
        let bitmap = ChunkBitmap::new(total_chunks);
        let cursor = AtomicU64::new(0);
        let scheduler_cfg = SchedulerConfig {
            chunk_size,
            workers: 4,
            retry: fast_retry(),
            progress: None,
            policy: None,
            fingerprints: None,
            probe: peel::download::ProbeConfig::default(),
            mirrors: None,
            rate_limiter: limiter,
            max_disk_buffer: None,
            abort: None,
        };
        let started = std::time::Instant::now();
        run(&client, &info, &sparse, &bitmap, &cursor, &scheduler_cfg).expect("run ok");
        let elapsed = started.elapsed();
        assert_eq!(read_full(&path), body_clone);
        drop(cleanup);
        elapsed
    };

    let unlimited = measure(None);
    let rate = 1024 * 1024; // 1 MiB/s -> 4 MiB body should take ~3 s after the burst
    let limited = measure(Some(Arc::new(peel::download::RateLimiter::new(rate))));

    // The unlimited path against a localhost mock typically completes
    // in tens of milliseconds. The limited path must take at least
    // ~2 s (3 MiB above the 1 MiB initial burst at 1 MiB/s, minus a
    // generous slack for the mock's per-chunk overhead).
    assert!(
        limited >= Duration::from_millis(2000),
        "limited run too fast: {limited:?}"
    );
    assert!(
        limited > unlimited * 5,
        "limiter did not slow the run noticeably: limited={limited:?}, unlimited={unlimited:?}"
    );
}
