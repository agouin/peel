//! End-to-end HTTP/2 tests against an in-process h2c server.
//!
//! These exercise the H2 frame-handling path in
//! [`peel::http::client`] without requiring TLS infrastructure. The
//! [`peel::http::HttpVersion::Http2Only`] knob forces the legacy
//! client to speak H2 prior-knowledge over plaintext, which matches
//! the [`support::h2c_server`] server side.
//!
//! ALPN-over-TLS is intentionally not exercised here; that path is
//! rustls's responsibility and expanding the test surface to verify
//! it would require self-signed-cert plumbing that does not earn
//! its keep for an MVP. The protocol-level guarantees (multiplexed
//! requests, HPACK header round-trip, body framing) are what these
//! tests cover.

#[path = "support/mod.rs"]
mod support;

use std::io::Read;
use std::time::Duration;

use peel::http::{Client, ClientConfig, HttpVersion, Url};

use support::h2c_server::{H2Response, H2cServer};

fn build_h2_client() -> Client {
    Client::with_config(ClientConfig {
        timeout: Duration::from_secs(5),
        http_version: HttpVersion::Http2Only,
        ..ClientConfig::default()
    })
    .expect("client constructs")
}

fn url_for(server: &H2cServer, path: &str) -> Url {
    Url::parse(&format!("{}{path}", server.base_url())).expect("parse url")
}

#[test]
fn h2_get_returns_body_over_prior_knowledge_h2c() {
    let server = H2cServer::start(|_req, _n| {
        H2Response::ok(b"hello h2".to_vec())
            .with_header("content-length", "8")
            .with_header("content-type", "text/plain")
    });
    let client = build_h2_client();

    let mut resp = client
        .get_full(&url_for(&server, "/data"))
        .expect("h2 GET ok");
    assert_eq!(resp.status.code, 200);
    assert_eq!(resp.headers.get("content-type"), Some("text/plain"));
    let mut body = Vec::new();
    resp.body.read_to_end(&mut body).expect("read body");
    assert_eq!(body, b"hello h2");
    // The handler ran exactly once.
    assert_eq!(server.request_count(), 1);
}

#[test]
fn h2_ranged_get_returns_206_and_correct_slice() {
    // The h2c server doesn't natively serve ranges; we hand-roll a
    // 206 with the right headers to confirm the client's range
    // handling works over H2 (matching the H1 wire-protocol test).
    let payload: Vec<u8> = (0..256).map(|i| i as u8).collect();
    let payload_for_handler = payload.clone();
    let server = H2cServer::start(move |req, _n| {
        let range = req.header("range").expect("range header present");
        // Accept only the exact form used in the test.
        assert_eq!(range, "bytes=64-127");
        let slice = payload_for_handler[64..128].to_vec();
        H2Response::ok(slice.clone())
            .with_status(206)
            .with_header("content-length", &slice.len().to_string())
            .with_header(
                "content-range",
                &format!("bytes 64-127/{}", payload_for_handler.len()),
            )
    });
    let client = build_h2_client();

    let url = url_for(&server, "/r");
    let range = peel::types::ByteRange::new(
        peel::types::ByteOffset::new(64),
        peel::types::ByteOffset::new(128),
    )
    .expect("non-empty range");
    let mut resp = client.get_range(&url, range).expect("ranged H2 GET ok");
    assert_eq!(resp.status.code, 206);
    let mut body = Vec::new();
    resp.body.read_to_end(&mut body).expect("read body");
    assert_eq!(body, payload[64..128]);
}

#[test]
fn h2_concurrent_requests_share_a_connection() {
    // H2 multiplexes requests on a single TCP connection. This test
    // does not introspect the connection (hyper-util's pool is
    // opaque) but it does send several parallel requests through one
    // shared `Client` and asserts they all complete correctly. The
    // server records the request count.
    let server = H2cServer::start(|req, n| {
        // Echo a synthetic ID + the request path so each response is
        // distinguishable.
        let body = format!("n={n} path={}", req.path).into_bytes();
        H2Response::ok(body.clone()).with_header("content-length", &body.len().to_string())
    });
    let client = build_h2_client();
    let base = server.base_url();

    let handles: Vec<_> = (0..8)
        .map(|i| {
            let client = client.clone();
            let url = Url::parse(&format!("{base}/p{i}")).expect("parse");
            std::thread::spawn(move || {
                let mut resp = client.get_full(&url).expect("h2 GET ok");
                let mut body = Vec::new();
                resp.body.read_to_end(&mut body).expect("read body");
                let body_str = String::from_utf8(body).expect("ascii");
                assert!(
                    body_str.contains(&format!("path=/p{i}")),
                    "response body {body_str:?} missing /p{i}"
                );
            })
        })
        .collect();
    for h in handles {
        h.join().expect("worker thread");
    }
    assert_eq!(server.request_count(), 8);
}

#[test]
fn http1_only_client_against_h2_server_fails_cleanly() {
    // Confirms that forcing H1 against an h2c-only server surfaces a
    // transport error rather than hanging or panicking. The h2c
    // server we run only speaks H2 frames; an H1 GET will desync.
    let server = H2cServer::start(|_req, _n| H2Response::ok(b"unused".to_vec()));
    let client = Client::with_config(ClientConfig {
        timeout: Duration::from_secs(2),
        http_version: HttpVersion::Http1Only,
        ..ClientConfig::default()
    })
    .expect("client constructs");

    let err = client
        .get_full(&url_for(&server, "/"))
        .expect_err("must error");
    let msg = err.to_string();
    assert!(
        msg.contains("hyper") || msg.contains("transport") || msg.contains("io"),
        "expected transport-shaped error, got {msg:?}"
    );
}
