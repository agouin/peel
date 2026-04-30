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
//! `docs/ENGINEERING_STANDARDS.md` §2.3 stops at `legacy::Client`,
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
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            max_redirects: DEFAULT_MAX_REDIRECTS,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            timeout: DEFAULT_TIMEOUT,
            pool_capacity: DEFAULT_POOL_CAPACITY,
            read_buffer_bytes: DEFAULT_READ_BUFFER_BYTES,
            user_agent: None,
            http_version: HttpVersion::Auto,
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
        let tls = build_tls_config()?;
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

fn build_tls_config() -> Result<rustls::ClientConfig, ClientError> {
    // Install the default crypto provider once per process.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
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
                    tokio::spawn(async move {
                        handle_request(client, envelope, timeout_dur).await;
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
        tokio::spawn(body_pump(body, body_rx));
        BodyReader::streaming(body_tx)
    } else {
        BodyReader::empty()
    };

    let _ = reply.send(Ok((status, headers, body_reader)));
}

async fn body_pump(mut body: Incoming, mut rx: mpsc::UnboundedReceiver<BodyCommand>) {
    while let Some(cmd) = rx.recv().await {
        let BodyCommand::NextFrame { reply } = cmd;
        loop {
            match body.frame().await {
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
