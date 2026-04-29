//! Integration tests for `pux::http` against the mock server.
//!
//! Every test starts a fresh mock server on `127.0.0.1:<auto>`, points
//! a fresh `Client` at it, drives one or more requests, and asserts on
//! the parsed response. The mock server is dropped (and torn down) at
//! the end of each test.

use std::io::Read;
use std::time::Duration;

use pux::http::range::{parse_content_range, ContentRange};
use pux::http::Url;
use pux::http::{Client, ClientConfig, ClientError};
use pux::types::{ByteOffset, ByteRange};

#[path = "support/mod.rs"]
mod support;

use support::mock_server::{MockRequest, MockResponse, MockServer};

fn build_client() -> Client {
    let cfg = ClientConfig {
        timeout: Duration::from_secs(5),
        ..ClientConfig::default()
    };
    Client::with_config(cfg).expect("client constructs")
}

fn url(server: &MockServer, path: &str) -> Url {
    let s = format!("{}{path}", server.base_url());
    Url::parse(&s).expect("url parses")
}

// ---- HEAD --------------------------------------------------------------

#[test]
fn head_returns_status_and_headers() {
    let server = MockServer::start(|_req: &MockRequest, _n| MockResponse::Reply {
        status: 200,
        reason: "OK",
        headers: vec![
            ("Content-Length".into(), "1234".into()),
            ("ETag".into(), "\"v1\"".into()),
            ("Accept-Ranges".into(), "bytes".into()),
        ],
        body: Vec::new(),
    });

    let client = build_client();
    let r = client.head(&url(&server, "/foo")).expect("head ok");
    assert_eq!(r.status.code, 200);
    assert_eq!(r.headers.get("Content-Length"), Some("1234"));
    assert_eq!(r.headers.get("ETag"), Some("\"v1\""));
    assert_eq!(r.headers.get("Accept-Ranges"), Some("bytes"));
    assert_eq!(r.final_url.path(), "/foo");
}

#[test]
fn head_request_method_is_head_on_wire() {
    let server = MockServer::start(|_req, _n| MockResponse::ok(""));
    let client = build_client();
    let _ = client.head(&url(&server, "/")).expect("head ok");
    let reqs = server.snapshot_requests();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method, "HEAD");
}

// ---- 200 GET -----------------------------------------------------------

#[test]
fn get_full_returns_body() {
    let payload = b"hello world".to_vec();
    let payload_for_handler = payload.clone();
    let server = MockServer::start(move |_req, _n| MockResponse::ok(payload_for_handler.clone()));

    let client = build_client();
    let mut resp = client.get_full(&url(&server, "/data")).expect("get ok");
    assert_eq!(resp.status.code, 200);
    let mut body = Vec::new();
    resp.body.read_to_end(&mut body).expect("read body");
    assert_eq!(body, payload);
}

#[test]
fn get_full_handles_empty_body() {
    let server = MockServer::start(|_req, _n| MockResponse::ok(""));
    let client = build_client();
    let mut resp = client.get_full(&url(&server, "/")).expect("get ok");
    let mut body = Vec::new();
    resp.body.read_to_end(&mut body).expect("read body");
    assert!(body.is_empty());
}

// ---- 206 Range ---------------------------------------------------------

#[test]
fn get_range_returns_206_and_correct_slice() {
    let full: Vec<u8> = (0u8..=255).cycle().take(10_000).collect();
    let full_for_handler = full.clone();
    let server = MockServer::start(move |req, _n| {
        let range_hdr = req.header("range").unwrap_or("");
        let after = range_hdr.strip_prefix("bytes=").unwrap_or(range_hdr);
        let (a, b) = after.split_once('-').unwrap_or((after, "0"));
        let a: usize = a.parse().unwrap_or(0);
        let b: usize = b.parse().unwrap_or(0);
        let slice = full_for_handler[a..=b].to_vec();
        MockResponse::Reply {
            status: 206,
            reason: "Partial Content",
            headers: vec![(
                "Content-Range".into(),
                format!("bytes {a}-{b}/{}", full_for_handler.len()),
            )],
            body: slice,
        }
    });

    let client = build_client();
    let r = ByteRange::new(ByteOffset::new(100), ByteOffset::new(300)).unwrap();
    let mut resp = client
        .get_range(&url(&server, "/d"), r)
        .expect("get_range ok");
    assert_eq!(resp.status.code, 206);

    let cr = parse_content_range(resp.headers.get("Content-Range").expect("CR")).expect("parse");
    assert_eq!(cr.first_byte(), 100);
    assert_eq!(cr.last_byte(), 299);
    assert_eq!(cr.total(), Some(10_000));

    let mut body = Vec::new();
    resp.body.read_to_end(&mut body).expect("read body");
    assert_eq!(body, full[100..=299]);
}

#[test]
fn get_range_rejects_200_when_range_was_sent() {
    let server = MockServer::start(|_req, _n| MockResponse::ok("ignored"));
    let client = build_client();
    let r = ByteRange::new(ByteOffset::new(0), ByteOffset::new(10)).unwrap();
    let err = client
        .get_range(&url(&server, "/"), r)
        .expect_err("must error on 200");
    match err {
        ClientError::UnexpectedStatus { status, .. } => assert_eq!(status, 200),
        other => panic!("unexpected {other:?}"),
    }
}

// ---- 301/302 redirects -------------------------------------------------

#[test]
fn follows_relative_redirect() {
    let server = MockServer::start(|req, _n| {
        if req.path == "/old" {
            MockResponse::Reply {
                status: 301,
                reason: "Moved Permanently",
                headers: vec![("Location".into(), "/new".into())],
                body: Vec::new(),
            }
        } else {
            MockResponse::ok("redirected")
        }
    });

    let client = build_client();
    let mut resp = client.get_full(&url(&server, "/old")).expect("get ok");
    assert_eq!(resp.status.code, 200);
    let mut body = Vec::new();
    resp.body.read_to_end(&mut body).expect("read");
    assert_eq!(body, b"redirected");

    let reqs = server.snapshot_requests();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].path, "/old");
    assert_eq!(reqs[1].path, "/new");
}

#[test]
fn redirect_loop_aborts_with_too_many_redirects() {
    let server = MockServer::start(|_req, _n| MockResponse::Reply {
        status: 302,
        reason: "Found",
        headers: vec![("Location".into(), "/loop".into())],
        body: Vec::new(),
    });

    let cfg = ClientConfig {
        max_redirects: 3,
        timeout: Duration::from_secs(5),
        ..ClientConfig::default()
    };
    let client = Client::with_config(cfg).expect("client");
    let err = client
        .get_full(&url(&server, "/loop"))
        .expect_err("must error");
    match err {
        ClientError::TooManyRedirects { limit } => assert_eq!(limit, 3),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn redirect_without_location_errors_cleanly() {
    let server = MockServer::start(|_req, _n| MockResponse::Reply {
        status: 301,
        reason: "Moved",
        headers: vec![],
        body: Vec::new(),
    });
    let client = build_client();
    let err = client.head(&url(&server, "/x")).expect_err("must error");
    match err {
        ClientError::MissingLocation { status } => assert_eq!(status, 301),
        other => panic!("unexpected {other:?}"),
    }
}

// ---- 404 / 503 ---------------------------------------------------------

#[test]
fn passes_through_404() {
    let server = MockServer::start(|_req, _n| MockResponse::Reply {
        status: 404,
        reason: "Not Found",
        headers: vec![],
        body: b"missing".to_vec(),
    });

    let client = build_client();
    let mut resp = client.get_full(&url(&server, "/nope")).expect("get ok");
    assert_eq!(resp.status.code, 404);
    let mut body = Vec::new();
    resp.body.read_to_end(&mut body).expect("read");
    assert_eq!(body, b"missing");
}

#[test]
fn passes_through_503() {
    let server = MockServer::start(|_req, _n| MockResponse::Reply {
        status: 503,
        reason: "Service Unavailable",
        headers: vec![("Retry-After".into(), "1".into())],
        body: Vec::new(),
    });

    let client = build_client();
    let resp = client.head(&url(&server, "/")).expect("head ok");
    assert_eq!(resp.status.code, 503);
    assert_eq!(resp.headers.get("Retry-After"), Some("1"));
}

// ---- Chunked transfer encoding ----------------------------------------

#[test]
fn parses_chunked_response() {
    // Build a chunked-encoded body the client must reassemble.
    let body =
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n7\r\n, world\r\n0\r\n\r\n";
    let server = MockServer::start(move |_req, _n| MockResponse::RawBytesThenClose(body.to_vec()));

    let client = build_client();
    let mut resp = client.get_full(&url(&server, "/")).expect("get ok");
    assert_eq!(resp.status.code, 200);
    let mut decoded = Vec::new();
    resp.body.read_to_end(&mut decoded).expect("read");
    assert_eq!(decoded, b"hello, world");
}

// ---- Connection drops --------------------------------------------------

#[test]
fn early_disconnect_returns_response_error() {
    let server = MockServer::start(|_req, _n| MockResponse::DropConnection);
    let client = build_client();
    let err = client
        .get_full(&url(&server, "/"))
        .expect_err("dropped conn must error");
    // The response parser sees zero bytes and reports UnexpectedEof.
    matches!(err, ClientError::Response(_));
}

#[test]
fn truncated_body_during_read_errors() {
    // Server promises 100 bytes but only sends 5 then closes.
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nhello";
    let server = MockServer::start(move |_req, _n| MockResponse::RawBytesThenClose(raw.to_vec()));
    let client = build_client();
    let mut resp = client.get_full(&url(&server, "/")).expect("headers ok");
    let mut body = Vec::new();
    let err = resp.body.read_to_end(&mut body).expect_err("must error");
    assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
}

// ---- Connection pool ---------------------------------------------------

#[test]
fn head_responses_populate_idle_pool() {
    let server = MockServer::start(|_req, _n| MockResponse::ok(""));
    let client = build_client();
    assert_eq!(client.pool_size(), 0);
    let _ = client.head(&url(&server, "/a")).expect("head ok");
    assert_eq!(client.pool_size(), 1);
    let _ = client.head(&url(&server, "/b")).expect("head ok");
    // Same host: should reuse the pooled connection rather than open a
    // second one. Pool stays at 1.
    assert_eq!(client.pool_size(), 1);
    // The mock server saw both requests on the same connection, so it
    // recorded request_count=2.
    assert_eq!(server.request_count(), 2);
}

#[test]
fn connection_close_keeps_pool_empty() {
    let server = MockServer::start(|_req, _n| MockResponse::Reply {
        status: 200,
        reason: "OK",
        headers: vec![("Connection".into(), "close".into())],
        body: Vec::new(),
    });
    let client = build_client();
    let _ = client.head(&url(&server, "/")).expect("head ok");
    assert_eq!(client.pool_size(), 0);
}

// ---- ContentRange round-trip via full client path ----------------------

#[test]
fn content_range_round_trips_through_real_request() {
    let total = 4096u64;
    let server = MockServer::start(move |req, _n| {
        let r = req.header("range").unwrap_or("bytes=0-0");
        let after = r.strip_prefix("bytes=").unwrap_or(r);
        let (a, b) = after.split_once('-').unwrap_or((after, "0"));
        let a: u64 = a.parse().unwrap_or(0);
        let b: u64 = b.parse().unwrap_or(0);
        let body: Vec<u8> = (a..=b).map(|x| (x & 0xFF) as u8).collect();
        MockResponse::Reply {
            status: 206,
            reason: "Partial Content",
            headers: vec![("Content-Range".into(), format!("bytes {a}-{b}/{total}"))],
            body,
        }
    });
    let client = build_client();
    let r = ByteRange::new(ByteOffset::new(1024), ByteOffset::new(2048)).unwrap();
    let resp = client
        .get_range(&url(&server, "/"), r)
        .expect("get_range ok");
    let cr = parse_content_range(resp.headers.get("Content-Range").unwrap()).expect("parse");
    let parsed: ContentRange = cr;
    assert_eq!(parsed.first_byte(), 1024);
    assert_eq!(parsed.last_byte(), 2047);
    assert_eq!(parsed.total(), Some(total));
    assert_eq!(parsed.as_byte_range(), r);
}
