//! Integration tests for `pux::download::scheduler`.
//!
//! Each test starts a fresh [`MockServer`], constructs a sparse file
//! and a [`ChunkBitmap`] sized to the source, then drives
//! `pux::download::run` against the mock. Assertions exercise the
//! plan §5 acceptance criteria: parallel happy path, retry-on-5xx,
//! abort on ETag change, single-stream fallback, resume, missing
//! Content-Length, and cursor-based dispatch priority.

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pux::bitmap::ChunkBitmap;
use pux::download::{
    chunk_count, discover, run, DownloadMode, RetryConfig, SchedulerConfig, SchedulerError,
    SparseFile, WorkerError,
};
use pux::http::{Client, ClientConfig, Url};
use pux::types::ChunkIndex;

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
    std::env::temp_dir().join(format!("pux_test_download_{label}_{pid}_{nanos}_{n}.bin"))
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
    // The mock server's `Reply` helper auto-adds `Content-Length`, so
    // we hand-roll the wire bytes via `RawBytesThenClose` to send a
    // response with neither Content-Length nor Transfer-Encoding.
    // `Connection: close` is required so the body is read-until-EOF
    // rather than the parser hanging waiting for a length.
    let raw = b"HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n".to_vec();
    let server = MockServer::start(move |_req, _n| MockResponse::RawBytesThenClose(raw.clone()));
    let client = build_client();
    let err = discover(&client, &url(&server, "/")).expect_err("must error");
    assert!(matches!(err, SchedulerError::MissingContentLength { .. }));
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
        .pwrite_at(pux::types::ByteOffset::new(0), &body_clone[0..4000])
        .expect("pre-write 0");
    sparse
        .pwrite_at(pux::types::ByteOffset::new(8000), &body_clone[8000..12_000])
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
    };
    let err = run(&client, &info, &sparse, &bitmap, &cursor, &bad).expect_err("must error");
    assert!(matches!(err, SchedulerError::InvalidWorkerCount));
}
