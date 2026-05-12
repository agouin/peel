//! Integration tests for HTTP-mode multi-volume discovery
//! (`docs/PLAN_multivolume_archives.md` §1).
//!
//! The local-mode discovery path is exercised by unit tests in
//! `src/multivolume.rs`. HTTP-mode discovery needs the real `peel`
//! HTTP client driving a mock origin, so those tests live here.

#![cfg(unix)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use peel::http::{Client, ClientConfig, Url};
use peel::multivolume::{discover_http, MvError, VolumeKind};

#[path = "support/mod.rs"]
mod support;
use support::mock_server::{MockRequest, MockResponse, MockServer};

fn build_client() -> Client {
    Client::with_config(ClientConfig {
        timeout: Duration::from_secs(5),
        ..ClientConfig::default()
    })
    .expect("client constructs")
}

fn url(server: &MockServer, path: &str) -> Url {
    Url::parse(&format!("{}{path}", server.base_url())).expect("url parses")
}

/// Server that returns 200 for paths listed in `present` and 404
/// for anything else. The response body is empty (we only HEAD
/// these URLs in discovery) so keep-alive across multiple HEADs on
/// one connection stays consistent — the mock server does not
/// special-case HEAD, so a non-empty body would leak into the next
/// pipelined request as garbage.
fn presence_server(present: &'static [&'static str]) -> MockServer {
    MockServer::start(move |req: &MockRequest, _: u64| {
        if present.contains(&req.path.as_str()) {
            MockResponse::Reply {
                status: 200,
                reason: "OK",
                headers: vec![
                    ("content-length".into(), "100".into()),
                    ("accept-ranges".into(), "bytes".into()),
                ],
                body: Vec::new(),
            }
        } else {
            MockResponse::Reply {
                status: 404,
                reason: "Not Found",
                headers: vec![("content-length".into(), "0".into())],
                body: Vec::new(),
            }
        }
    })
}

#[test]
fn http_discover_rar5_three_volumes_seed_first() {
    let server = presence_server(&[
        "/dir/foo.part0001.rar",
        "/dir/foo.part0002.rar",
        "/dir/foo.part0003.rar",
    ]);
    let client = build_client();
    let seed = url(&server, "/dir/foo.part0001.rar");
    let got = discover_http(&client, &seed).expect("ok");
    assert_eq!(got.len(), 3);
    for (i, u) in got.iter().enumerate() {
        let n = i + 1;
        assert!(
            u.path().ends_with(&format!("foo.part{n:04}.rar")),
            "{u} should end with foo.part{n:04}.rar"
        );
    }
}

#[test]
fn http_discover_rar5_seed_in_middle_walks_from_one() {
    let server = presence_server(&[
        "/a/x.part0001.rar",
        "/a/x.part0002.rar",
        "/a/x.part0003.rar",
        "/a/x.part0004.rar",
    ]);
    let client = build_client();
    let seed = url(&server, "/a/x.part0003.rar");
    let got = discover_http(&client, &seed).expect("ok");
    assert_eq!(got.len(), 4);
    assert!(got[0].path().ends_with("x.part0001.rar"));
    assert!(got[3].path().ends_with("x.part0004.rar"));
}

#[test]
fn http_discover_rar5_missing_lower_volume_errors() {
    // Only volumes 2 and 3 exist on origin; seed points at 3.
    let server = presence_server(&["/y.part0002.rar", "/y.part0003.rar"]);
    let client = build_client();
    let seed = url(&server, "/y.part0003.rar");
    let err = discover_http(&client, &seed).unwrap_err();
    assert!(matches!(
        err,
        MvError::MissingVolume {
            kind: VolumeKind::Rar5,
            ..
        }
    ));
}

#[test]
fn http_discover_7z_three_volumes() {
    let server = presence_server(&["/snap.7z.001", "/snap.7z.002", "/snap.7z.003"]);
    let client = build_client();
    let seed = url(&server, "/snap.7z.001");
    let got = discover_http(&client, &seed).expect("ok");
    assert_eq!(got.len(), 3);
    assert!(got[2].path().ends_with("snap.7z.003"));
}

#[test]
fn http_discover_zip_spanned() {
    let server = presence_server(&["/m.z01", "/m.z02", "/m.zip"]);
    let client = build_client();
    let seed = url(&server, "/m.z01");
    let got = discover_http(&client, &seed).expect("ok");
    assert_eq!(got.len(), 3);
    assert!(got[0].path().ends_with("m.z01"));
    assert!(got[1].path().ends_with("m.z02"));
    assert!(got[2].path().ends_with("m.zip"));
}

#[test]
fn http_discover_zip_seed_is_final() {
    let server = presence_server(&["/m.z01", "/m.z02", "/m.zip"]);
    let client = build_client();
    let seed = url(&server, "/m.zip");
    let got = discover_http(&client, &seed).expect("ok");
    assert_eq!(got.len(), 3);
    assert!(got[2].path().ends_with("m.zip"));
}

#[test]
fn http_discover_zip_single_volume_falls_through() {
    let server = presence_server(&["/solo.zip"]);
    let client = build_client();
    let seed = url(&server, "/solo.zip");
    let got = discover_http(&client, &seed).expect("ok");
    assert_eq!(got.len(), 1);
    assert!(got[0].path().ends_with("solo.zip"));
}

#[test]
fn http_discover_zip_missing_final_errors() {
    let server = presence_server(&["/partial.z01", "/partial.z02"]);
    let client = build_client();
    let seed = url(&server, "/partial.z01");
    let err = discover_http(&client, &seed).unwrap_err();
    assert!(matches!(err, MvError::FinalVolumeMissing { .. }));
}

#[test]
fn http_discover_pattern_not_recognised() {
    let server = presence_server(&["/archive.tar.zst"]);
    let client = build_client();
    let seed = url(&server, "/archive.tar.zst");
    let err = discover_http(&client, &seed).unwrap_err();
    assert!(matches!(err, MvError::PatternNotRecognised { .. }));
}

#[test]
fn http_discover_unexpected_status_surfaces() {
    // Server returns 500 instead of 200 / 404; expect a clean error.
    let req_count = Arc::new(AtomicU64::new(0));
    let req_count_for_handler = Arc::clone(&req_count);
    let server = MockServer::start(move |_req: &MockRequest, _: u64| {
        req_count_for_handler.fetch_add(1, Ordering::Relaxed);
        MockResponse::Reply {
            status: 500,
            reason: "Internal Server Error",
            headers: Vec::new(),
            body: Vec::new(),
        }
    });
    let client = build_client();
    let seed = url(&server, "/foo.part0001.rar");
    let err = discover_http(&client, &seed).unwrap_err();
    assert!(matches!(err, MvError::UnexpectedStatus { status: 500, .. }));
}
