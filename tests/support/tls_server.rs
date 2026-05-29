//! In-process **TLS** server presenting a self-signed certificate,
//! used by [`tests/test_http_insecure.rs`] to exercise the
//! `--insecure` / `ClientConfig::insecure` path end-to-end.
//!
//! Unlike [`super::h2c_server`] (plaintext h2c), this server speaks
//! real TLS so the test crosses the certificate-verification boundary:
//! a default `peel::http::Client` must *reject* the handshake (the cert
//! is untrusted), while an `insecure: true` client must *accept* it.
//!
//! ALPN: the server advertises both `h2` and `http/1.1` and dispatches
//! the accepted connection to hyper's `http2` or `http1` server codec
//! based on what rustls negotiated. That lets one server cover both the
//! H1 and H2 arms of the insecure path with a single fixture.
//!
//! The certificate and key are **static PEM fixtures** under
//! `tests/support/testdata/` (long-lived self-signed, SAN
//! `localhost` + `127.0.0.1`). We deliberately do not generate certs
//! at runtime — that would pull a cert-generation crate for no real
//! gain (`internal/ENGINEERING_STANDARDS.md` §2.1).

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper::service::service_fn;
use hyper::{Request as HRequest, Response as HResponse};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::runtime::Builder as RuntimeBuilder;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

/// Self-signed certificate fixture (PEM). Long-lived, SAN covers
/// `localhost` and `127.0.0.1`. No real trust store would accept it —
/// which is exactly the point.
const CERT_PEM: &[u8] = include_bytes!("testdata/self_signed_cert.pem");
/// Private key matching [`CERT_PEM`] (PKCS#8 PEM).
const KEY_PEM: &[u8] = include_bytes!("testdata/self_signed_key.pem");

/// Body bytes every request to this server receives, regardless of
/// path. Tests assert against this exact payload.
pub const RESPONSE_BODY: &[u8] = b"insecure tls ok";

/// A running self-signed TLS server. Drops cleanly on `Drop`.
pub struct TlsServer {
    addr: SocketAddr,
    request_count: Arc<AtomicU64>,
    shutdown: Option<oneshot::Sender<()>>,
    runtime_thread: Option<JoinHandle<()>>,
}

impl TlsServer {
    /// Start the server on an ephemeral `127.0.0.1` port. Returns once
    /// the listener is bound. Every request is answered `200` with
    /// [`RESPONSE_BODY`] and a matching `content-length`.
    pub fn start() -> Self {
        let request_count = Arc::new(AtomicU64::new(0));
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<SocketAddr>();

        let acceptor = build_acceptor();
        let request_count_thread = Arc::clone(&request_count);
        let runtime_thread = std::thread::Builder::new()
            .name("peel-tls-test".into())
            .spawn(move || {
                let rt = RuntimeBuilder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("tls test rt");
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
                                let acceptor = acceptor.clone();
                                let counter = Arc::clone(&request_count_thread);
                                tokio::spawn(async move {
                                    serve_conn(acceptor, stream, counter).await;
                                });
                            }
                        }
                    }
                });
            })
            .expect("spawn tls server thread");

        let addr = ready_rx.recv().expect("tls ready");
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

    /// `https://127.0.0.1:<port>` — the IP literal matches the cert's
    /// `127.0.0.1` SAN, so a *verifying* client fails on trust (the
    /// self-signed chain), not on a name mismatch.
    pub fn base_url(&self) -> String {
        format!("https://{}", self.addr)
    }

    pub fn request_count(&self) -> u64 {
        self.request_count.load(Ordering::Relaxed)
    }
}

impl Drop for TlsServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.runtime_thread.take() {
            let _ = handle.join();
        }
    }
}

/// Build a rustls `ServerConfig` from the static fixture, advertising
/// both `h2` and `http/1.1` in ALPN (preference order h2 first).
fn build_acceptor() -> TlsAcceptor {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(CERT_PEM)
        .collect::<Result<_, _>>()
        .expect("parse cert fixture");
    let key = PrivateKeyDer::from_pem_slice(KEY_PEM).expect("parse key fixture");

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server config");
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    TlsAcceptor::from(Arc::new(config))
}

/// Complete the TLS handshake, then dispatch to the hyper server codec
/// matching the negotiated ALPN protocol (`h2` → http2, otherwise
/// http1). A handshake failure (e.g. a verifying client refusing the
/// self-signed cert) is dropped silently — the client side surfaces
/// the error, which is what the test asserts on.
async fn serve_conn(acceptor: TlsAcceptor, stream: tokio::net::TcpStream, counter: Arc<AtomicU64>) {
    let Ok(tls) = acceptor.accept(stream).await else {
        return;
    };
    let is_h2 = matches!(tls.get_ref().1.alpn_protocol(), Some(b"h2"));
    let io = TokioIo::new(tls);

    let svc = service_fn(move |_req: HRequest<Incoming>| {
        let counter = Arc::clone(&counter);
        async move {
            counter.fetch_add(1, Ordering::Relaxed);
            let body = Full::new(Bytes::from_static(RESPONSE_BODY));
            let resp = HResponse::builder()
                .status(200)
                .header("content-length", RESPONSE_BODY.len().to_string())
                .header("content-type", "application/octet-stream")
                .body(body)
                .expect("build response");
            Ok::<_, Infallible>(resp)
        }
    });

    if is_h2 {
        let _ = http2::Builder::new(TokioExecutor::new())
            .serve_connection(io, svc)
            .await;
    } else {
        let _ = http1::Builder::new().serve_connection(io, svc).await;
    }
}
