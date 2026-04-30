//! In-process plaintext HTTP/2 ("h2c", prior-knowledge) server used
//! by [`tests/test_http_h2.rs`].
//!
//! `peel::http::Client` configured with `HttpVersion::Http2Only`
//! forces H2 prior-knowledge over plaintext sockets, which is what
//! this server speaks. We deliberately avoid TLS to keep test
//! infrastructure small — verifying the H2 wire protocol path is
//! orthogonal to verifying ALPN, and ALPN is rustls's job which we
//! trust.
//!
//! Architecture: a tokio thread runs hyper's `server::conn::http2`
//! against accepted connections. The provided handler is a
//! `Fn(&MockRequest, u64) -> MockResponse` clone of the existing
//! `mock_server` shape so tests read uniformly.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{Request as HRequest, Response as HResponse};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio::runtime::Builder as RuntimeBuilder;
use tokio::sync::oneshot;

/// Minimal request shape passed to the handler. Mirrors the public
/// fields of `mock_server::MockRequest` so tests can swap servers.
#[derive(Debug, Clone)]
pub struct H2Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
}

impl H2Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Response shape returned by the handler. Compact subset sufficient
/// for current H2 tests.
#[derive(Debug, Clone)]
pub struct H2Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl H2Response {
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    pub fn with_status(mut self, code: u16) -> Self {
        self.status = code;
        self
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

pub struct H2cServer {
    addr: SocketAddr,
    request_count: Arc<AtomicU64>,
    shutdown: Option<oneshot::Sender<()>>,
    runtime_thread: Option<JoinHandle<()>>,
}

impl H2cServer {
    pub fn start<F>(handler: F) -> Self
    where
        F: Fn(&H2Request, u64) -> H2Response + Send + Sync + 'static,
    {
        let handler = Arc::new(handler);
        let request_count = Arc::new(AtomicU64::new(0));
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<SocketAddr>();

        let request_count_thread = Arc::clone(&request_count);
        let runtime_thread = std::thread::Builder::new()
            .name("peel-h2c-test".into())
            .spawn(move || {
                let rt = RuntimeBuilder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("h2c rt");
                rt.block_on(async move {
                    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
                    let addr = listener.local_addr().expect("local_addr");
                    ready_tx.send(addr).expect("ready");

                    tokio::pin!(shutdown_rx);
                    loop {
                        tokio::select! {
                            biased;
                            _ = &mut shutdown_rx => break,
                            accept = listener.accept() => {
                                let Ok((stream, _)) = accept else { continue };
                                let handler = Arc::clone(&handler);
                                let counter = Arc::clone(&request_count_thread);
                                tokio::spawn(async move {
                                    let io = TokioIo::new(stream);
                                    let svc = service_fn(move |req: HRequest<Incoming>| {
                                        let handler = Arc::clone(&handler);
                                        let counter = Arc::clone(&counter);
                                        async move {
                                            let n = counter.fetch_add(1, Ordering::Relaxed);
                                            let mock = to_h2_request(&req).await;
                                            let resp = handler(&mock, n);
                                            Ok::<_, Infallible>(to_hyper_response(resp))
                                        }
                                    });
                                    let _ = http2::Builder::new(TokioExecutor::new())
                                        .serve_connection(io, svc)
                                        .await;
                                });
                            }
                        }
                    }
                });
            })
            .expect("spawn h2c server thread");

        let addr = ready_rx.recv().expect("h2c ready");
        Self {
            addr,
            request_count,
            shutdown: Some(shutdown_tx),
            runtime_thread: Some(runtime_thread),
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn request_count(&self) -> u64 {
        self.request_count.load(Ordering::Relaxed)
    }
}

impl Drop for H2cServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.runtime_thread.take() {
            let _ = handle.join();
        }
    }
}

async fn to_h2_request(req: &HRequest<Incoming>) -> H2Request {
    let method = req.method().as_str().to_string();
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let headers = req
        .headers()
        .iter()
        .map(|(n, v)| (n.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    H2Request {
        method,
        path,
        headers,
    }
}

fn to_hyper_response(
    resp: H2Response,
) -> HResponse<http_body_util::combinators::BoxBody<Bytes, Infallible>> {
    let mut builder = HResponse::builder().status(resp.status);
    for (name, value) in resp.headers {
        builder = builder.header(name, value);
    }
    let body = Full::new(Bytes::from(resp.body)).boxed();
    builder.body(body).expect("build response")
}
