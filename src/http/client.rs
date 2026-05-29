//! HTTP client backed by `hyper` + `hyper-util` + `hyper-rustls`,
//! ALPN-negotiating between HTTP/1.1 and HTTP/2 per origin.
//!
//! # Architecture
//!
//! All hyper-related work runs on a current-thread `tokio::runtime`
//! that this client owns. The runtime runs on a dedicated OS thread
//! spawned by [`Client::new`] and lives until the last `Client` clone
//! is dropped. The synchronous public API (`head`, `get_full`,
//! `get_range`) submits work to the runtime via an unbounded mpsc
//! channel and blocks the caller's thread on a oneshot reply.
//!
//! Per-body reads use a second channel: each
//! [`BodyReader`](super::response::BodyReader) owns an `mpsc::Sender`
//! that the runtime task on the other end services by `await`-ing
//! frames from `hyper::body::Incoming`. The calling thread blocks on
//! a oneshot per frame. The result is that callers see a normal
//! [`std::io::Read`] body with no async surface, while hyper retains
//! its frame-driven behavior under the covers.
//!
//! Connection pooling is handled inside `hyper-util`'s legacy client.
//! The per-host idle pool is sized by `ClientConfig::pool_capacity`
//! via `hyper_util::client::legacy::Builder::pool_max_idle_per_host`.
//! There is no caller-visible "release" step — drop the body when
//! you are done with it and the pool reclaims the connection.
//!
//! Redirects, `UnexpectedStatus` checks, and the per-request timeout
//! live in this module — those are the reasons the boundary in
//! `internal/ENGINEERING_STANDARDS.md` §2.3 stops at `legacy::Client`,
//! not higher.

use std::io;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use bytes::Bytes;
use http::header::HeaderName;
use http::{HeaderValue, Method as HttpMethod, Request as HttpRequest, Uri};
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client as LegacyClient;
use hyper_util::rt::TokioExecutor;
use rustls::RootCertStore;
use thiserror::Error;
use tokio::runtime::Builder as RuntimeBuilder;
use tokio::sync::{mpsc, oneshot};

use super::range::format_range_header;
use super::request::Method;
use super::response::{BodyCommand, BodyReader, Headers, Response, Status};
use super::url::{Url, UrlError};
use crate::types::ByteRange;

/// Default cap on the number of redirects a single call will follow.
pub const DEFAULT_MAX_REDIRECTS: u8 = 5;
/// Default cap on the cumulative size of response status line +
/// headers, in bytes. Honored on H1 only (hyper's H1 codec); H2
/// uses HPACK and applies a much larger SETTINGS-derived cap.
pub const DEFAULT_MAX_HEADER_BYTES: usize = 64 * 1024;
/// Default connect / request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default per-frame idle timeout for response bodies. Only the
/// initial connect-and-headers phase is bounded by [`DEFAULT_TIMEOUT`];
/// once the response starts streaming, hyper's `Incoming::frame()`
/// will park indefinitely waiting on the next data frame. A wedged
/// origin or middlebox that holds the TCP connection open without
/// sending bytes would otherwise leave a download worker stuck —
/// it is alive, holds a chunk, and reports no error. The body pump
/// wraps each `frame()` await in this deadline so a stalled stream
/// surfaces as an IO error and the worker's retry path opens a fresh
/// connection.
pub const DEFAULT_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Default minimum acceptable throughput for an in-progress response
/// body, in bytes per second. Catches the trickle case — frames
/// arrive often enough to keep the per-frame idle timeout happy, but
/// the cumulative rate is so low the connection is functionally
/// stuck. 128 KiB/s ≈ 1 Mbps per worker; below this is well outside
/// any realistic downloader's working range. Set to `0` to disable
/// the watchdog (useful when running behind an aggressive
/// `--rate-limit` cap).
pub const DEFAULT_BODY_MIN_THROUGHPUT: u64 = 128 * 1024;
/// Window (in seconds) over which body throughput is averaged before
/// the watchdog evaluates it. Short windows false-positive on
/// network jitter; long windows take longer to recover from real
/// stalls. 15s is a reasonable middle ground.
pub const DEFAULT_BODY_THROUGHPUT_WINDOW: Duration = Duration::from_secs(15);
/// Grace period after a body starts streaming before the watchdog
/// arms. Covers TCP slow-start and TLS handshake settling so the
/// initial low-throughput phase doesn't trip the deadline.
pub const DEFAULT_BODY_THROUGHPUT_GRACE: Duration = Duration::from_secs(30);
/// Default upper bound on cached idle connections per host.
pub const DEFAULT_POOL_CAPACITY: usize = 16;
/// Default capacity of the per-connection read buffer, in bytes.
/// Retained as a configuration knob even though hyper's legacy client
/// does not expose a direct equivalent — we apply it as the H1 max
/// header buffer ceiling.
pub const DEFAULT_READ_BUFFER_BYTES: usize = 8 * 1024;

/// Errors produced by [`Client`] operations.
#[derive(Debug, Error)]
pub enum ClientError {
    /// The supplied URL could not be parsed or could not be coerced
    /// into a hyper [`Uri`].
    #[error("invalid URL: {0}")]
    Url(#[from] UrlError),

    /// Building or sending the [`super::range`]-encoded `Range:`
    /// header failed.
    #[error("invalid Range: {0}")]
    Range(#[from] super::range::RangeError),

    /// Building the underlying TLS configuration failed.
    #[error("tls config error")]
    Tls(#[source] rustls::Error),

    /// The hostname in the URL could not be used as a TLS server name
    /// (only checked at URL-coercion time; hyper-rustls does its own
    /// validation thereafter).
    #[error("invalid TLS server name {host:?}")]
    InvalidServerName {
        /// The offending hostname.
        host: String,
    },

    /// hyper / hyper-util returned a transport error: connect failure,
    /// timeout, mid-stream close, ALPN mismatch, etc.
    #[error("hyper transport error to {host:?}:{port}: {detail}")]
    Transport {
        /// Host the connection was for.
        host: String,
        /// Port the connection was for.
        port: u16,
        /// Underlying error rendered as a message. Hyper's error
        /// types are not stable enough to expose verbatim, so we
        /// flatten to a string at the boundary.
        detail: String,
    },

    /// IO error reading the response body, or other low-level
    /// failure that surfaces from the runtime task as a synthesized
    /// [`io::Error`]. Preserves the host / port shape from before
    /// the hyper migration so callers can keep matching on it.
    #[error("socket io to {host:?}:{port}")]
    Io {
        /// Host the connection was for.
        host: String,
        /// Port the connection was for.
        port: u16,
        /// Underlying OS error.
        #[source]
        source: io::Error,
    },

    /// DNS lookup returned no addresses. (Typically surfaced via
    /// [`Self::Transport`] today; preserved for callers that match
    /// on it.)
    #[error("DNS lookup for {host:?}:{port} returned no addresses")]
    DnsEmpty {
        /// Host being resolved.
        host: String,
        /// Port being resolved.
        port: u16,
    },

    /// Server replied with a redirect status but no `Location` header.
    #[error("server returned {status} redirect with no Location header")]
    MissingLocation {
        /// The redirect status code.
        status: u16,
    },

    /// More than [`ClientConfig::max_redirects`] hops were attempted on
    /// a single call.
    #[error("redirect chain exceeded {limit} hops")]
    TooManyRedirects {
        /// The cap that was exceeded.
        limit: u8,
    },

    /// The server's reply did not match the request shape we expect
    /// (e.g. 200 in response to a `Range:` request when the spec says
    /// 206).
    #[error("unexpected status {status} for {method} of {url}")]
    UnexpectedStatus {
        /// HTTP method that was sent.
        method: Method,
        /// URL being fetched (after redirects).
        url: String,
        /// The status code returned.
        status: u16,
    },

    /// Background runtime thread terminated before the request could
    /// be served. Indicates a panic on the runtime task or that the
    /// last `Client` clone was already dropping.
    #[error("http client runtime is shut down")]
    RuntimeGone,
}

impl ClientError {
    /// True iff retrying the same request could plausibly succeed.
    ///
    /// Transport-layer failures (`Io`, `Tls`, `Transport`, `DnsEmpty`)
    /// and 5xx `UnexpectedStatus` responses are transient. 4xx
    /// statuses (404, 403, 410, …), config errors (`Url`, `Range`,
    /// `InvalidServerName`), and protocol violations
    /// (`MissingLocation`, `TooManyRedirects`) are terminal —
    /// retrying just burns the retry budget on something that won't
    /// fix itself.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Io { .. } | Self::Tls { .. } | Self::Transport { .. } | Self::DnsEmpty { .. } => {
                true
            }
            Self::UnexpectedStatus { status, .. } => *status >= 500,
            Self::Url(_)
            | Self::Range(_)
            | Self::InvalidServerName { .. }
            | Self::MissingLocation { .. }
            | Self::TooManyRedirects { .. }
            | Self::RuntimeGone => false,
        }
    }
}

/// Tunable knobs for [`Client`].
/// Which HTTP version(s) the client may use.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Default)]
pub enum HttpVersion {
    /// Default: ALPN-negotiate over TLS (preferring H2 when the server
    /// offers it, falling back to H1.1), and use HTTP/1.1 over
    /// plaintext where ALPN does not apply.
    #[default]
    Auto,
    /// Use HTTP/1.1 only. Disables H2 ALPN advertisement.
    Http1Only,
    /// Use HTTP/2 only. Over TLS this requires the server to negotiate
    /// `h2`; over plaintext it forces "prior-knowledge" h2c, which
    /// only works against servers that explicitly speak h2c.
    Http2Only,
}

/// Tunable knobs for [`Client`].
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Maximum redirects followed on a single call. Defaults to
    /// [`DEFAULT_MAX_REDIRECTS`].
    pub max_redirects: u8,
    /// Cap on response header size for H1 connections; ignored on H2.
    /// Defaults to [`DEFAULT_MAX_HEADER_BYTES`].
    pub max_header_bytes: usize,
    /// Connect / request timeout. Defaults to [`DEFAULT_TIMEOUT`].
    pub timeout: Duration,
    /// Per-frame idle timeout while reading a response body. Defaults
    /// to [`DEFAULT_BODY_IDLE_TIMEOUT`]. See that constant for the
    /// rationale; a value of `Duration::ZERO` disables the deadline
    /// (the pre-fix behaviour, only useful for tests that intentionally
    /// drive a slow stream).
    pub body_idle_timeout: Duration,
    /// Minimum acceptable body throughput in bytes per second. After
    /// [`Self::body_throughput_grace`] elapses, every
    /// [`Self::body_throughput_window`] the watchdog measures the
    /// rate over the window; if it is below this floor, the body
    /// pump errors out so the worker's retry path opens a fresh
    /// connection. Defaults to [`DEFAULT_BODY_MIN_THROUGHPUT`].
    /// `0` disables the watchdog.
    pub body_min_throughput: u64,
    /// Tumbling window length used by the throughput watchdog.
    /// Defaults to [`DEFAULT_BODY_THROUGHPUT_WINDOW`].
    pub body_throughput_window: Duration,
    /// Grace period after the body starts streaming before the
    /// throughput watchdog arms. Defaults to
    /// [`DEFAULT_BODY_THROUGHPUT_GRACE`].
    pub body_throughput_grace: Duration,
    /// Maximum idle connections cached per host. Defaults to
    /// [`DEFAULT_POOL_CAPACITY`].
    pub pool_capacity: usize,
    /// Capacity of the per-connection read buffer.
    pub read_buffer_bytes: usize,
    /// Optional `User-Agent` override; if `None`, `peel/<version>`
    /// is sent.
    pub user_agent: Option<String>,
    /// Which HTTP version(s) to use. Defaults to
    /// [`HttpVersion::Auto`] (ALPN-negotiated H1 / H2).
    pub http_version: HttpVersion,
    /// Skip TLS certificate and hostname verification (`curl -k`).
    ///
    /// When `true`, the rustls client is configured with a verifier
    /// that accepts any presented certificate chain and any hostname.
    /// This disables protection against man-in-the-middle attacks and
    /// is only ever set when the user explicitly opts in via
    /// `--insecure`. Defaults to `false`.
    pub insecure: bool,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            max_redirects: DEFAULT_MAX_REDIRECTS,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            timeout: DEFAULT_TIMEOUT,
            body_idle_timeout: DEFAULT_BODY_IDLE_TIMEOUT,
            body_min_throughput: DEFAULT_BODY_MIN_THROUGHPUT,
            body_throughput_window: DEFAULT_BODY_THROUGHPUT_WINDOW,
            body_throughput_grace: DEFAULT_BODY_THROUGHPUT_GRACE,
            pool_capacity: DEFAULT_POOL_CAPACITY,
            read_buffer_bytes: DEFAULT_READ_BUFFER_BYTES,
            user_agent: None,
            http_version: HttpVersion::Auto,
            insecure: false,
        }
    }
}

/// Hyper-backed HTTP client.
///
/// `Client` is `Send + Sync` and inexpensive to clone; clones share
/// the same connection pool, runtime thread, and TLS configuration.
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    config: ClientConfig,
    request_tx: Option<mpsc::UnboundedSender<RequestEnvelope>>,
    runtime_thread: Option<JoinHandle<()>>,
}

impl Drop for ClientInner {
    fn drop(&mut self) {
        // INVARIANT: dropping `request_tx` is what unblocks the
        // runtime task's `request_rx.recv().await`, which is what
        // lets `rt.block_on(...)` return and the OS thread exit.
        // The sender must be dropped *before* the join, or the
        // join deadlocks. The natural drop-order of struct fields
        // would join first, so we take + drop explicitly here.
        self.request_tx.take();
        if let Some(handle) = self.runtime_thread.take() {
            let _ = handle.join();
        }
    }
}

/// The result of a `HEAD` request.
#[derive(Debug)]
pub struct HeadResult {
    /// Status of the final (non-redirect) response.
    pub status: Status,
    /// Headers of the final response.
    pub headers: Headers,
    /// URL the redirect chain settled on (== the input URL when no
    /// redirects were followed).
    pub final_url: Url,
}

/// Response shape returned by `get_full` / `get_range`. Kept as a
/// type alias for backwards compatibility with callers that named it
/// directly; in this module everything is just [`Response`].
pub type ClientResponse = Response;

impl Client {
    /// Construct a client with default configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Tls`] if rustls fails to initialize.
    pub fn new() -> Result<Self, ClientError> {
        Self::with_config(ClientConfig::default())
    }

    /// Construct a client with custom [`ClientConfig`].
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Tls`] if rustls fails to initialize.
    pub fn with_config(config: ClientConfig) -> Result<Self, ClientError> {
        let tls = build_tls_config(config.insecure)?;
        let (request_tx, request_rx) = mpsc::unbounded_channel::<RequestEnvelope>();
        let runtime_thread = spawn_runtime_thread(tls, &config, request_rx);
        Ok(Self {
            inner: Arc::new(ClientInner {
                config,
                request_tx: Some(request_tx),
                runtime_thread: Some(runtime_thread),
            }),
        })
    }

    /// Issue a `HEAD` request, following redirects up to the
    /// configured limit.
    ///
    /// # Errors
    ///
    /// Any of the [`ClientError`] variants.
    pub fn head(&self, url: &Url) -> Result<HeadResult, ClientError> {
        let outcome = self.send_with_redirects(Method::Head, url, None)?;
        let SendOutcome {
            status,
            headers,
            final_url,
            ..
        } = outcome;
        Ok(HeadResult {
            status,
            headers,
            final_url,
        })
    }

    /// Issue a full `GET` for the resource at `url`.
    ///
    /// # Errors
    ///
    /// Any of the [`ClientError`] variants.
    pub fn get_full(&self, url: &Url) -> Result<ClientResponse, ClientError> {
        let outcome = self.send_with_redirects(Method::Get, url, None)?;
        Ok(Response {
            status: outcome.status,
            headers: outcome.headers,
            body: outcome.body,
        })
    }

    /// Issue a ranged `GET` for the half-open `range` of `url`.
    ///
    /// # Errors
    ///
    /// In addition to the [`ClientError`] variants, returns
    /// [`ClientError::UnexpectedStatus`] if the server replied with
    /// `200` (range ignored) or any other non-206 status.
    pub fn get_range(&self, url: &Url, range: ByteRange) -> Result<ClientResponse, ClientError> {
        let outcome = self.send_with_redirects(Method::Get, url, Some(range))?;
        if outcome.status.code != 206 {
            return Err(ClientError::UnexpectedStatus {
                method: Method::Get,
                url: outcome.final_url.to_string(),
                status: outcome.status.code,
            });
        }
        Ok(Response {
            status: outcome.status,
            headers: outcome.headers,
            body: outcome.body,
        })
    }

    fn send_with_redirects(
        &self,
        method: Method,
        url: &Url,
        range: Option<ByteRange>,
    ) -> Result<SendOutcome, ClientError> {
        let mut current = url.clone();
        let mut hops: u8 = 0;
        loop {
            let outcome = self.send_one(method, &current, range)?;
            if !outcome.status.is_redirect() {
                return Ok(outcome);
            }
            if hops >= self.inner.config.max_redirects {
                return Err(ClientError::TooManyRedirects {
                    limit: self.inner.config.max_redirects,
                });
            }
            let location = outcome
                .headers
                .get("location")
                .ok_or(ClientError::MissingLocation {
                    status: outcome.status.code,
                })?
                .to_string();
            // Drop the redirect body; hyper's pool reclaims the
            // connection automatically when the body future is
            // dropped.
            drop(outcome.body);
            current = current.join(&location)?;
            hops += 1;
        }
    }

    fn send_one(
        &self,
        method: Method,
        url: &Url,
        range: Option<ByteRange>,
    ) -> Result<SendOutcome, ClientError> {
        let host = url.host().to_string();
        let port = url.port();

        let uri: Uri = url
            .to_string()
            .parse()
            .map_err(|e: http::uri::InvalidUri| {
                ClientError::Url(UrlError::InvalidUri {
                    detail: e.to_string(),
                })
            })?;

        let mut builder = HttpRequest::builder()
            .method(match method {
                Method::Get => HttpMethod::GET,
                Method::Head => HttpMethod::HEAD,
            })
            .uri(uri);

        // Headers we always need.
        let ua_value = self
            .inner
            .config
            .user_agent
            .clone()
            .unwrap_or_else(|| format!("peel/{}", env!("CARGO_PKG_VERSION")));
        builder = builder.header(http::header::USER_AGENT, ua_value);
        builder = builder.header(http::header::ACCEPT, "*/*");

        if let Some(r) = range {
            let value = format_range_header(r)?;
            builder = builder.header(http::header::RANGE, value);
        }

        let request = builder.body(Empty::<Bytes>::new()).map_err(|e| {
            ClientError::Url(UrlError::InvalidUri {
                detail: e.to_string(),
            })
        })?;

        let expect_body = method == Method::Get;

        let (reply_tx, reply_rx) = oneshot::channel::<RequestReply>();
        let envelope = RequestEnvelope {
            request,
            expect_body,
            reply: reply_tx,
        };
        let tx = self
            .inner
            .request_tx
            .as_ref()
            .ok_or(ClientError::RuntimeGone)?;
        if tx.send(envelope).is_err() {
            return Err(ClientError::RuntimeGone);
        }
        let reply = reply_rx
            .blocking_recv()
            .map_err(|_| ClientError::RuntimeGone)?;
        match reply {
            Ok((status, headers, body)) => Ok(SendOutcome {
                status,
                headers,
                body,
                final_url: url.clone(),
            }),
            Err(e) => Err(map_send_error(e, host, port)),
        }
    }
}

/// Internal: outcome of a single (post-redirect-hop) request.
struct SendOutcome {
    status: Status,
    headers: Headers,
    final_url: Url,
    body: BodyReader,
}

/// Internal: reply payload from the runtime thread to a calling
/// thread.
type RequestReply = Result<(Status, Headers, BodyReader), SendError>;

/// Internal: an envelope submitted to the runtime task.
struct RequestEnvelope {
    request: HttpRequest<Empty<Bytes>>,
    expect_body: bool,
    reply: oneshot::Sender<RequestReply>,
}

/// Internal: cause of a transport-layer failure.
#[derive(Debug)]
enum SendError {
    /// hyper-util's legacy client returned an error before/while
    /// sending the request.
    Legacy(String),
    /// Per-request timeout fired.
    Timeout,
    /// The status line / headers parsed but the response was
    /// unusable (e.g. an invalid header value).
    InvalidResponse(String),
}

fn map_send_error(err: SendError, host: String, port: u16) -> ClientError {
    let msg = match err {
        SendError::Legacy(s) => s,
        SendError::Timeout => "request timed out".to_string(),
        SendError::InvalidResponse(s) => format!("invalid response: {s}"),
    };
    ClientError::Transport {
        host,
        port,
        detail: msg,
    }
}

fn build_tls_config(insecure: bool) -> Result<rustls::ClientConfig, ClientError> {
    // Install the default crypto provider once per process.
    let _ = rustls::crypto::ring::default_provider().install_default();

    if insecure {
        // `--insecure` / `-k`-equivalent: accept any certificate chain
        // and any hostname. Routed through the `dangerous()` builder so
        // the call site reads as deliberately unsafe. `NoCertVerification`
        // still delegates the handshake *signature* checks to the crypto
        // provider so the connection is encrypted — it only drops trust
        // (chain + hostname) verification.
        return Ok(rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertVerification::new()))
            .with_no_client_auth());
    }

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

/// A rustls [`ServerCertVerifier`] that accepts any certificate chain
/// and any server name without checking it against a trust anchor.
///
/// Installed only when the user passes `--insecure`. It disables the
/// protection TLS gives against man-in-the-middle attacks: a proxy or
/// attacker presenting *any* certificate is accepted. The transport is
/// still encrypted (the handshake signatures are verified against the
/// presented key via the crypto provider), but the peer's *identity*
/// is not authenticated. Mirrors `curl -k` / `wget --no-check-certificate`.
///
/// The signature-verification methods delegate to the standard webpki
/// helpers using the process default crypto provider's algorithms, so
/// only chain/name trust is skipped — not the cryptographic integrity
/// of the handshake itself.
#[derive(Debug)]
struct NoCertVerification {
    supported: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl NoCertVerification {
    fn new() -> Self {
        // INVARIANT: `with_config` calls `install_default()` before this
        // runs, so a process default provider is always present. Fall back
        // to the ring provider's algorithm set if (defensively) it is not.
        let supported = rustls::crypto::CryptoProvider::get_default()
            .map(|p| p.signature_verification_algorithms)
            .unwrap_or_else(|| {
                rustls::crypto::ring::default_provider().signature_verification_algorithms
            });
        Self { supported }
    }
}

impl rustls::client::danger::ServerCertVerifier for NoCertVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported.supported_schemes()
    }
}

fn spawn_runtime_thread(
    tls: rustls::ClientConfig,
    config: &ClientConfig,
    mut request_rx: mpsc::UnboundedReceiver<RequestEnvelope>,
) -> JoinHandle<()> {
    let pool_capacity = config.pool_capacity;
    let read_buffer_bytes = config.read_buffer_bytes;
    let max_header_bytes = config.max_header_bytes;
    let timeout = config.timeout;
    let body_idle_timeout = config.body_idle_timeout;
    let body_throughput = BodyThroughputConfig {
        min_bytes_per_sec: config.body_min_throughput,
        window: config.body_throughput_window,
        grace: config.body_throughput_grace,
    };
    let http_version = config.http_version;

    thread::Builder::new()
        .name("peel-http-rt".into())
        .spawn(move || {
            // Build a current-thread runtime confined to this thread.
            // `enable_all` activates net + time, both of which hyper
            // needs.
            let rt = match RuntimeBuilder::new_current_thread().enable_all().build() {
                Ok(rt) => rt,
                Err(e) => {
                    // Drain pending requests with errors so the
                    // calling threads don't deadlock.
                    while let Ok(env) = request_rx.try_recv() {
                        let _ = env.reply.send(Err(SendError::Legacy(format!(
                            "tokio runtime build failed: {e}"
                        ))));
                    }
                    return;
                }
            };

            rt.block_on(async move {
                let mut http_connector = HttpConnector::new();
                http_connector.set_nodelay(true);
                http_connector.set_connect_timeout(Some(timeout));
                http_connector.enforce_http(false);

                // The ALPN advertisement on the TLS connector and the
                // protocol forced on plaintext connections are
                // controlled separately; both follow `http_version`.
                // Over TLS, hyper-rustls advertises only the protocols
                // we enable here. Over plaintext, hyper-util uses H1
                // by default; setting `http2_only(true)` on the
                // legacy::Client builder forces H2 prior-knowledge
                // (h2c) for the H2-only path.
                let https_base = HttpsConnectorBuilder::new()
                    .with_tls_config(tls)
                    .https_or_http();
                let https = match http_version {
                    HttpVersion::Auto => https_base
                        .enable_http1()
                        .enable_http2()
                        .wrap_connector(http_connector),
                    HttpVersion::Http1Only => {
                        https_base.enable_http1().wrap_connector(http_connector)
                    }
                    HttpVersion::Http2Only => {
                        https_base.enable_http2().wrap_connector(http_connector)
                    }
                };

                let mut builder = LegacyClient::builder(TokioExecutor::new());
                builder
                    .pool_max_idle_per_host(pool_capacity)
                    .http1_max_buf_size(max_header_bytes.max(read_buffer_bytes));
                if matches!(http_version, HttpVersion::Http2Only) {
                    builder.http2_only(true);
                }
                let hyper_client: LegacyClient<_, Empty<Bytes>> = builder.build(https);

                while let Some(envelope) = request_rx.recv().await {
                    let client = hyper_client.clone();
                    let timeout_dur = timeout;
                    let body_idle = body_idle_timeout;
                    let throughput_cfg = body_throughput;
                    tokio::spawn(async move {
                        handle_request(client, envelope, timeout_dur, body_idle, throughput_cfg)
                            .await;
                    });
                }
            });
        })
        .expect("spawn http runtime thread")
}

async fn handle_request(
    client: LegacyClient<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>>,
    envelope: RequestEnvelope,
    timeout: Duration,
    body_idle_timeout: Duration,
    throughput: BodyThroughputConfig,
) {
    let RequestEnvelope {
        request,
        expect_body,
        reply,
        ..
    } = envelope;

    let send_fut = client.request(request);
    let send_result = tokio::time::timeout(timeout, send_fut).await;
    let response = match send_result {
        Err(_) => {
            let _ = reply.send(Err(SendError::Timeout));
            return;
        }
        Ok(Err(e)) => {
            let _ = reply.send(Err(SendError::Legacy(e.to_string())));
            return;
        }
        Ok(Ok(r)) => r,
    };

    let (parts, body) = response.into_parts();
    let status = Status {
        code: parts.status.as_u16(),
        reason: parts.status.canonical_reason().unwrap_or("").to_string(),
    };
    let headers = match translate_headers(&parts.headers) {
        Ok(h) => h,
        Err(e) => {
            let _ = reply.send(Err(SendError::InvalidResponse(e)));
            return;
        }
    };

    let body_reader = if expect_body
        && status.code != 204
        && status.code != 304
        && !(100..200).contains(&status.code)
    {
        let (body_tx, body_rx) = mpsc::unbounded_channel::<BodyCommand>();
        tokio::spawn(body_pump(body, body_rx, body_idle_timeout, throughput));
        BodyReader::streaming(body_tx)
    } else {
        BodyReader::empty()
    };

    let _ = reply.send(Ok((status, headers, body_reader)));
}

async fn body_pump(
    mut body: Incoming,
    mut rx: mpsc::UnboundedReceiver<BodyCommand>,
    idle_timeout: Duration,
    throughput: BodyThroughputConfig,
) {
    let mut watchdog = ThroughputWatchdog::new(std::time::Instant::now(), throughput);
    while let Some(cmd) = rx.recv().await {
        let BodyCommand::NextFrame { reply } = cmd;
        loop {
            // Bound each `frame()` await with the idle deadline so a
            // wedged origin/middlebox can't park a worker indefinitely.
            // `Duration::ZERO` opts out (used by tests that intentionally
            // drive a slow stream against a stub server).
            let next = if idle_timeout.is_zero() {
                body.frame().await
            } else {
                match tokio::time::timeout(idle_timeout, body.frame()).await {
                    Ok(frame) => frame,
                    Err(_) => {
                        let _ = reply.send(Err(format!(
                            "body read stalled: no frame for {idle_timeout:?}",
                        )));
                        // Drop `body` by returning so hyper closes the
                        // connection rather than returning it to the
                        // idle pool — the next attempt opens a fresh
                        // socket instead of inheriting the wedged one.
                        return;
                    }
                }
            };
            match next {
                None => {
                    let _ = reply.send(Ok(None));
                    return;
                }
                Some(Err(e)) => {
                    let _ = reply.send(Err(e.to_string()));
                    return;
                }
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(bytes) if !bytes.is_empty() => {
                        let now = std::time::Instant::now();
                        watchdog.record(now, bytes.len() as u64);
                        if let Some(rate) = watchdog.evaluate(now) {
                            // Cumulative-window rate has fallen below
                            // the configured floor. Drop the body so
                            // hyper closes the connection; the worker
                            // retries on a fresh socket.
                            let _ = reply.send(Err(format!(
                                "body throughput {rate:.0} B/s below floor {} B/s over {:?}",
                                throughput.min_bytes_per_sec, throughput.window,
                            )));
                            return;
                        }
                        let _ = reply.send(Ok(Some(bytes)));
                        break;
                    }
                    // Empty data frame or trailers: keep pulling
                    // without bothering the caller.
                    _ => continue,
                },
            }
        }
    }
}

/// Snapshot of the throughput-watchdog tunables, captured per-request.
#[derive(Debug, Clone, Copy)]
struct BodyThroughputConfig {
    /// Minimum acceptable bytes-per-second floor; `0` disables the
    /// watchdog entirely.
    min_bytes_per_sec: u64,
    /// Length of one tumbling-window evaluation interval.
    window: Duration,
    /// Time after the body starts streaming during which the watchdog
    /// is silent (TCP slow-start, TLS settle, etc.).
    grace: Duration,
}

/// Per-body throughput watchdog driven from `body_pump`.
///
/// Maintains a tumbling window: every `window` of wall-clock time
/// since the last evaluation, `evaluate` checks how many bytes
/// arrived in that interval and reports the rate when it falls
/// below `min_bytes_per_sec`. The first window starts after `grace`
/// so a slow start doesn't trip the deadline.
struct ThroughputWatchdog {
    config: BodyThroughputConfig,
    /// Bytes accumulated since `body_pump` started.
    cumulative: u64,
    /// Bytes accumulated at the last anchor point (start of the
    /// current window). Used with `cumulative` to derive a delta.
    anchor_bytes: u64,
    /// Wall-clock at the last anchor point. The first anchor sits
    /// `grace` into the future from construction so the watchdog
    /// stays silent during slow start.
    anchor_at: std::time::Instant,
}

impl ThroughputWatchdog {
    fn new(now: std::time::Instant, config: BodyThroughputConfig) -> Self {
        Self {
            config,
            cumulative: 0,
            anchor_bytes: 0,
            anchor_at: now + config.grace,
        }
    }

    fn record(&mut self, _now: std::time::Instant, bytes: u64) {
        self.cumulative = self.cumulative.saturating_add(bytes);
    }

    /// If a window has elapsed since the last anchor, evaluate the
    /// rate over that window. Returns `Some(rate)` when below the
    /// floor (caller treats that as a fatal stall); otherwise `None`
    /// and the anchor advances. Disabled (`min_bytes_per_sec == 0`)
    /// always returns `None`.
    fn evaluate(&mut self, now: std::time::Instant) -> Option<f64> {
        if self.config.min_bytes_per_sec == 0 {
            return None;
        }
        if now < self.anchor_at {
            return None;
        }
        let dt = now.duration_since(self.anchor_at);
        if dt < self.config.window {
            return None;
        }
        let bytes = self.cumulative - self.anchor_bytes;
        let secs = dt.as_secs_f64();
        // Advance the anchor regardless of pass/fail so consecutive
        // failing windows don't compound across the same delta.
        self.anchor_at = now;
        self.anchor_bytes = self.cumulative;
        if secs <= 0.0 {
            return None;
        }
        let rate = bytes as f64 / secs;
        if rate < self.config.min_bytes_per_sec as f64 {
            Some(rate)
        } else {
            None
        }
    }
}

fn translate_headers(map: &http::HeaderMap<HeaderValue>) -> Result<Headers, String> {
    let mut headers = Headers::default();
    for (name, value) in map.iter() {
        let value_str = value.to_str().map_err(|e| {
            format!(
                "invalid utf-8 in header {name}: {e}",
                name = name.as_str(),
                e = e
            )
        })?;
        headers.append(canonical_header_name(name), value_str.to_string());
    }
    Ok(headers)
}

fn canonical_header_name(name: &HeaderName) -> String {
    // hyper lowercases header names internally; round-trip through
    // the canonical (lowercase) wire form. Our `Headers::get` is
    // case-insensitive so this does not alter caller-visible
    // behavior.
    name.as_str().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_secure_tls_config_by_default() {
        // The default (verifying) path must construct without error and
        // is what every normal run uses.
        assert!(build_tls_config(false).is_ok());
    }

    #[test]
    fn builds_insecure_tls_config() {
        // `--insecure` swaps in the `NoCertVerification` verifier via the
        // `dangerous()` builder; constructing it must succeed.
        assert!(build_tls_config(true).is_ok());
    }

    #[test]
    fn client_builds_with_insecure_flag() {
        let client = Client::with_config(ClientConfig {
            insecure: true,
            ..ClientConfig::default()
        });
        assert!(client.is_ok());
    }

    #[test]
    fn insecure_defaults_off() {
        assert!(!ClientConfig::default().insecure);
    }

    #[test]
    fn no_cert_verification_accepts_supported_schemes() {
        // The verifier must advertise a non-empty scheme list pulled from
        // the process default crypto provider, or the handshake would have
        // nothing to negotiate.
        let verifier = NoCertVerification::new();
        use rustls::client::danger::ServerCertVerifier;
        assert!(!verifier.supported_verify_schemes().is_empty());
    }

    #[test]
    fn no_cert_verification_accepts_an_untrusted_cert() {
        // The core security-relevant behaviour of `--insecure`: the
        // verifier accepts a certificate that no real trust store would
        // (here, arbitrary bytes that aren't even a valid X.509 cert) for
        // a hostname that doesn't match anything. `verify_server_cert`
        // never parses the chain — it unconditionally asserts success —
        // so junk bytes exercise exactly the "trust is skipped" path.
        use rustls::client::danger::ServerCertVerifier;
        use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let verifier = NoCertVerification::new();
        let bogus = CertificateDer::from(vec![0xde, 0xad, 0xbe, 0xef]);
        let name = ServerName::try_from("not-a-real-host.invalid").expect("server name");

        let result = verifier.verify_server_cert(&bogus, &[], &name, &[], UnixTime::now());
        assert!(
            result.is_ok(),
            "insecure verifier must accept an untrusted certificate",
        );
    }
}
