//! End-to-end tests for the `--insecure` / `ClientConfig::insecure`
//! TLS-verification bypass against a real self-signed TLS server.
//!
//! These cross the certificate-verification boundary that the
//! verifier-level unit tests in `src/http/client.rs` cannot: an actual
//! rustls handshake against an untrusted certificate. The server
//! ([`support::tls_server`]) advertises both `h2` and `http/1.1` in
//! ALPN, so the insecure path is exercised over both protocols.
//!
//! Contract under test:
//! - A default (verifying) client **fails** the handshake — the
//!   self-signed cert is not in any trust store.
//! - An `insecure: true` client **succeeds** and reads the body, over
//!   `Auto` (ALPN-negotiated), forced `h2`, and forced `h1`.

#[path = "support/mod.rs"]
mod support;

use std::io::Read;
use std::time::Duration;

use peel::http::{Client, ClientConfig, HttpVersion, Url};

use support::tls_server::{TlsServer, RESPONSE_BODY};

fn client(insecure: bool, http_version: HttpVersion) -> Client {
    Client::with_config(ClientConfig {
        timeout: Duration::from_secs(5),
        http_version,
        insecure,
        ..ClientConfig::default()
    })
    .expect("client constructs")
}

fn url(server: &TlsServer, path: &str) -> Url {
    Url::parse(&format!("{}{path}", server.base_url())).expect("parse url")
}

/// The baseline: without `--insecure`, the self-signed certificate is
/// rejected and no request reaches the server. Guards against the
/// verifier being silently bypassed for everyone.
#[test]
fn default_client_rejects_self_signed_cert() {
    let server = TlsServer::start();
    let client = client(false, HttpVersion::Auto);

    let result = client.get_full(&url(&server, "/data"));

    assert!(
        result.is_err(),
        "verifying client must reject the self-signed certificate",
    );
    assert_eq!(
        server.request_count(),
        0,
        "no request should reach the server when the handshake is rejected",
    );
}

/// `--insecure` with the default `Auto` HTTP version: ALPN negotiates
/// (the server prefers `h2`), the handshake is accepted despite the
/// untrusted cert, and the body comes back intact.
#[test]
fn insecure_client_accepts_self_signed_cert_auto() {
    let server = TlsServer::start();
    let client = client(true, HttpVersion::Auto);

    let mut resp = client
        .get_full(&url(&server, "/data"))
        .expect("insecure GET succeeds over auto ALPN");
    assert_eq!(resp.status.code, 200);
    let mut body = Vec::new();
    resp.body.read_to_end(&mut body).expect("read body");
    assert_eq!(body, RESPONSE_BODY);
    assert_eq!(server.request_count(), 1);
}

/// `--insecure` forced to HTTP/2 over TLS: proves the bypass composes
/// with the `h2` ALPN arm specifically.
#[test]
fn insecure_client_accepts_self_signed_cert_h2() {
    let server = TlsServer::start();
    let client = client(true, HttpVersion::Http2Only);

    let mut resp = client
        .get_full(&url(&server, "/data"))
        .expect("insecure GET succeeds over forced h2");
    assert_eq!(resp.status.code, 200);
    let mut body = Vec::new();
    resp.body.read_to_end(&mut body).expect("read body");
    assert_eq!(body, RESPONSE_BODY);
    assert_eq!(server.request_count(), 1);
}

/// `--insecure` forced to HTTP/1.1 over TLS: the H1 ALPN arm.
#[test]
fn insecure_client_accepts_self_signed_cert_h1() {
    let server = TlsServer::start();
    let client = client(true, HttpVersion::Http1Only);

    let mut resp = client
        .get_full(&url(&server, "/data"))
        .expect("insecure GET succeeds over forced h1");
    assert_eq!(resp.status.code, 200);
    let mut body = Vec::new();
    resp.body.read_to_end(&mut body).expect("read body");
    assert_eq!(body, RESPONSE_BODY);
    assert_eq!(server.request_count(), 1);
}
