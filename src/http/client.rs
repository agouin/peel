//! HTTP/1.1 client: connection management, TLS, and the `head`/`get_*`
//! convenience methods.
//!
//! The client owns a small idle-connection cache keyed by `(host, port,
//! scheme)`. Each request either reuses a cached buffered reader (and
//! the underlying socket beneath it) or opens a fresh `TcpStream`,
//! optionally wrapping it in `rustls::StreamOwned` for HTTPS. The
//! buffered reader carries any bytes that the response parser read
//! ahead of the body, so reuse is safe.
//!
//! The MVP does **not** retry on transport errors; it surfaces them to
//! the caller. Retries with exponential backoff live in the download
//! scheduler (PLAN §5).

use std::io::{self, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConnection, RootCertStore, StreamOwned};
use thiserror::Error;

use super::request::{Method, Request, RequestError};
use super::response::{BodyReader, Headers, Response, ResponseError, Status};
use super::url::{Scheme, Url, UrlError};
use crate::types::ByteRange;

/// Default cap on the number of redirects a single call will follow.
pub const DEFAULT_MAX_REDIRECTS: u8 = 5;
/// Default cap on the cumulative size of response status line +
/// headers, in bytes.
pub const DEFAULT_MAX_HEADER_BYTES: usize = 64 * 1024;
/// Default connect/read/write timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default upper bound on cached idle connections (across all hosts).
pub const DEFAULT_POOL_CAPACITY: usize = 16;
/// Default capacity of the per-connection buffered reader, in bytes.
pub const DEFAULT_READ_BUFFER_BYTES: usize = 8 * 1024;

/// Errors produced by [`Client`] operations.
#[derive(Debug, Error)]
pub enum ClientError {
    /// The supplied URL could not be parsed.
    #[error("invalid URL: {0}")]
    Url(#[from] UrlError),

    /// Constructing the [`Request`] failed.
    #[error("invalid request: {0}")]
    Request(#[from] RequestError),

    /// Reading or parsing the response failed.
    #[error("invalid response: {0}")]
    Response(#[from] ResponseError),

    /// DNS resolution returned no addresses.
    #[error("DNS lookup for {host:?}:{port} returned no addresses")]
    DnsEmpty {
        /// Host being resolved.
        host: String,
        /// Port being resolved.
        port: u16,
    },

    /// `connect`, `write`, or `read` syscall failed at the socket layer.
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

    /// TLS handshake or session failed.
    #[error("tls error to {host:?}")]
    Tls {
        /// Host being contacted.
        host: String,
        /// Underlying TLS error.
        #[source]
        source: rustls::Error,
    },

    /// The hostname in the URL is not a valid TLS server name.
    #[error("invalid TLS server name {host:?}")]
    InvalidServerName {
        /// The offending hostname.
        host: String,
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
}

/// Tunable knobs for [`Client`].
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Maximum redirects followed on a single call. Defaults to
    /// [`DEFAULT_MAX_REDIRECTS`].
    pub max_redirects: u8,
    /// Cap on the cumulative size of status line + response headers.
    /// Defaults to [`DEFAULT_MAX_HEADER_BYTES`].
    pub max_header_bytes: usize,
    /// Connect / read / write timeout. Defaults to [`DEFAULT_TIMEOUT`].
    pub timeout: Duration,
    /// Maximum idle connections cached across all hosts. Defaults to
    /// [`DEFAULT_POOL_CAPACITY`].
    pub pool_capacity: usize,
    /// Capacity of the per-connection buffered reader. Defaults to
    /// [`DEFAULT_READ_BUFFER_BYTES`].
    pub read_buffer_bytes: usize,
    /// Optional `User-Agent` override; if `None`, the default
    /// `peel/<version>` from [`Request::write_to`] is used.
    pub user_agent: Option<String>,
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
        }
    }
}

/// A connection that can read and write bytes synchronously. Implemented
/// by [`TcpStream`] and `rustls::StreamOwned<...>`.
trait ReadWrite: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWrite for T {}

/// Concrete connection type carried inside the pool and inside
/// caller-visible response bodies. Hides whether the stream is plaintext
/// or TLS-wrapped.
pub struct ConnStream {
    inner: Box<dyn ReadWrite + Send>,
}

impl ConnStream {
    fn new(inner: Box<dyn ReadWrite + Send>) -> Self {
        Self { inner }
    }
}

impl Read for ConnStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for ConnStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl std::fmt::Debug for ConnStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnStream").finish_non_exhaustive()
    }
}

/// Buffered reader over a [`ConnStream`].
pub type ConnReader = BufReader<ConnStream>;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct HostKey {
    host: String,
    port: u16,
    scheme: Scheme,
}

impl HostKey {
    fn from_url(url: &Url) -> Self {
        Self {
            host: url.host().to_string(),
            port: url.port(),
            scheme: url.scheme(),
        }
    }
}

struct PooledConn {
    host_key: HostKey,
    reader: ConnReader,
}

/// HTTP/1.1 client.
///
/// A `Client` owns:
/// - a `rustls::ClientConfig` with WebPKI roots installed.
/// - a small bounded cache of idle connections keyed by
///   `(host, port, scheme)`.
/// - the connect / read / write timeout applied to each socket.
///
/// `Client` is `Send + Sync` and inexpensive to clone; clones share the
/// same connection pool and TLS configuration.
#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
}

struct ClientInner {
    tls_config: Arc<rustls::ClientConfig>,
    pool: Mutex<Vec<PooledConn>>,
    config: ClientConfig,
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

/// A `Response` whose body is backed by a connection from the pool.
pub type ClientResponse = Response<ConnReader>;

impl Client {
    /// Construct a client with default configuration and the bundled
    /// WebPKI root store.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Tls`] if rustls fails to initialize its
    /// default cryptographic provider (extremely unusual; would imply a
    /// build/feature mismatch).
    pub fn new() -> Result<Self, ClientError> {
        Self::with_config(ClientConfig::default())
    }

    /// Construct a client with custom [`ClientConfig`].
    ///
    /// # Errors
    ///
    /// Same conditions as [`Self::new`].
    pub fn with_config(config: ClientConfig) -> Result<Self, ClientError> {
        let tls_config = build_tls_config()?;
        Ok(Self {
            inner: Arc::new(ClientInner {
                tls_config: Arc::new(tls_config),
                pool: Mutex::new(Vec::new()),
                config,
            }),
        })
    }

    /// Issue a `HEAD` request, following redirects up to the configured
    /// limit.
    ///
    /// The body is always empty so the connection is immediately
    /// returned to the pool.
    ///
    /// # Errors
    ///
    /// Any of the [`ClientError`] variants.
    pub fn head(&self, url: &Url) -> Result<HeadResult, ClientError> {
        let resp = self.send_with_redirects(Method::Head, url, None)?;
        let SendResult {
            status,
            headers,
            final_url,
            body,
        } = resp;
        let reusable = connection_is_reusable(&headers);
        let reader = body.into_inner();
        if reusable {
            self.return_connection(HostKey::from_url(&final_url), reader);
        }
        // Otherwise drop, closing the connection.
        Ok(HeadResult {
            status,
            headers,
            final_url,
        })
    }

    /// Issue a full `GET` for the resource at `url`.
    ///
    /// The returned [`Response`] streams the body from the underlying
    /// connection. The connection is **not** automatically returned to
    /// the pool when the body is dropped — the caller may have read
    /// only part of the body, leaving the stream in an inconsistent
    /// state. To opt in to reuse, drain the body and call
    /// [`Self::release`] with the recovered reader.
    ///
    /// # Errors
    ///
    /// Any of the [`ClientError`] variants.
    pub fn get_full(&self, url: &Url) -> Result<ClientResponse, ClientError> {
        let resp = self.send_with_redirects(Method::Get, url, None)?;
        let SendResult {
            status,
            headers,
            body,
            ..
        } = resp;
        Ok(Response {
            status,
            headers,
            body,
        })
    }

    /// Issue a ranged `GET` for the half-open `range` of `url`.
    ///
    /// Asserts the server replied with `206 Partial Content`. Use
    /// [`Self::get_full`] when you genuinely want the full body.
    ///
    /// # Errors
    ///
    /// In addition to the [`ClientError`] variants, returns
    /// [`ClientError::UnexpectedStatus`] if the server replied with
    /// `200` (range ignored) or any other non-206 status.
    pub fn get_range(&self, url: &Url, range: ByteRange) -> Result<ClientResponse, ClientError> {
        let resp = self.send_with_redirects(Method::Get, url, Some(range))?;
        if resp.status.code != 206 {
            return Err(ClientError::UnexpectedStatus {
                method: Method::Get,
                url: resp.final_url.to_string(),
                status: resp.status.code,
            });
        }
        let SendResult {
            status,
            headers,
            body,
            ..
        } = resp;
        Ok(Response {
            status,
            headers,
            body,
        })
    }

    /// Return a fully-drained connection to the idle pool for reuse.
    ///
    /// Pass the [`ConnReader`] recovered from
    /// [`BodyReader::into_inner`] after the body has been read to EOF.
    /// If the connection is incomplete or the pool is full, the reader
    /// is dropped (closing the connection); this is always safe.
    pub fn release(&self, url: &Url, reader: ConnReader) {
        self.return_connection(HostKey::from_url(url), reader);
    }

    /// Number of idle connections currently in the pool.
    ///
    /// Exposed for diagnostics and tests; the value is non-deterministic
    /// under concurrent calls and should not be used to gate behavior.
    #[doc(hidden)]
    #[must_use]
    pub fn pool_size(&self) -> usize {
        // INVARIANT: a poisoned mutex is only possible if a previous
        // holder panicked while inserting; reporting zero is safe and
        // only used for diagnostics.
        match self.inner.pool.lock() {
            Ok(p) => p.len(),
            Err(_) => 0,
        }
    }

    fn send_with_redirects(
        &self,
        method: Method,
        url: &Url,
        range: Option<ByteRange>,
    ) -> Result<SendResult, ClientError> {
        let mut current = url.clone();
        let mut hops: u8 = 0;
        loop {
            let mut reader = self.acquire(&current)?;

            let mut req = match method {
                Method::Head => Request::head(&current),
                Method::Get => match range {
                    Some(r) => Request::get_range(&current, r)?,
                    None => Request::get(&current),
                },
            };
            if let Some(ua) = self.inner.config.user_agent.as_deref() {
                req.header("User-Agent", ua)?;
            }

            // Write the request directly to the underlying stream
            // (BufReader::get_mut), bypassing the read buffer.
            req.write_to(reader.get_mut()).map_err(|e| match e {
                RequestError::Io(io_err) => ClientError::Io {
                    host: current.host().to_string(),
                    port: current.port(),
                    source: io_err,
                },
                other => ClientError::Request(other),
            })?;

            let response = Response::read_from(
                reader,
                method != Method::Head,
                self.inner.config.max_header_bytes,
            )?;
            let Response {
                status,
                headers,
                body,
            } = response;

            if status.is_redirect() {
                if hops >= self.inner.config.max_redirects {
                    return Err(ClientError::TooManyRedirects {
                        limit: self.inner.config.max_redirects,
                    });
                }
                let location = match headers.get("location") {
                    Some(v) => v.to_string(),
                    None => {
                        return Err(ClientError::MissingLocation {
                            status: status.code,
                        })
                    }
                };
                let next = current.join(&location)?;
                // For redirect responses we don't need the body; drain
                // it so the connection is reusable for the next hop on
                // the same host (or pooled if the host changes).
                let drained = drain_body(body);
                if let Ok(recovered) = drained {
                    self.return_connection(HostKey::from_url(&current), recovered);
                }
                hops += 1;
                current = next;
                continue;
            }

            return Ok(SendResult {
                status,
                headers,
                final_url: current,
                body,
            });
        }
    }

    fn acquire(&self, url: &Url) -> Result<ConnReader, ClientError> {
        let key = HostKey::from_url(url);

        // Try to pull a cached connection. Take the most recent (LIFO)
        // so connections that have been idle longest are evicted first
        // by capacity pressure rather than reused into possible TCP
        // RST.
        if let Ok(mut pool) = self.inner.pool.lock() {
            if let Some(idx) = pool.iter().rposition(|p| p.host_key == key) {
                let p = pool.swap_remove(idx);
                return Ok(p.reader);
            }
        }

        // Otherwise dial fresh.
        let stream = self.dial(url)?;
        let reader = BufReader::with_capacity(self.inner.config.read_buffer_bytes, stream);
        Ok(reader)
    }

    fn dial(&self, url: &Url) -> Result<ConnStream, ClientError> {
        let addr = (url.host(), url.port())
            .to_socket_addrs()
            .map_err(|e| ClientError::Io {
                host: url.host().to_string(),
                port: url.port(),
                source: e,
            })?
            .next()
            .ok_or_else(|| ClientError::DnsEmpty {
                host: url.host().to_string(),
                port: url.port(),
            })?;

        let tcp = self.connect_tcp(addr, url)?;

        if url.scheme().is_tls() {
            let server_name = ServerName::try_from(url.host().to_string()).map_err(|_| {
                ClientError::InvalidServerName {
                    host: url.host().to_string(),
                }
            })?;
            let conn = ClientConnection::new(self.inner.tls_config.clone(), server_name).map_err(
                |source| ClientError::Tls {
                    host: url.host().to_string(),
                    source,
                },
            )?;
            let stream = StreamOwned::new(conn, tcp);
            Ok(ConnStream::new(Box::new(stream)))
        } else {
            Ok(ConnStream::new(Box::new(tcp)))
        }
    }

    fn connect_tcp(&self, addr: SocketAddr, url: &Url) -> Result<TcpStream, ClientError> {
        let timeout = self.inner.config.timeout;
        let map_io = |source: io::Error| ClientError::Io {
            host: url.host().to_string(),
            port: url.port(),
            source,
        };
        let tcp = TcpStream::connect_timeout(&addr, timeout).map_err(map_io)?;
        tcp.set_read_timeout(Some(timeout)).map_err(map_io)?;
        tcp.set_write_timeout(Some(timeout)).map_err(map_io)?;
        tcp.set_nodelay(true).map_err(map_io)?;
        Ok(tcp)
    }

    fn return_connection(&self, host_key: HostKey, reader: ConnReader) {
        if let Ok(mut pool) = self.inner.pool.lock() {
            if pool.len() >= self.inner.config.pool_capacity {
                // Drop the oldest entry (front).
                pool.remove(0);
            }
            pool.push(PooledConn { host_key, reader });
        }
        // If lock acquisition failed (poisoned), the reader is simply
        // dropped — correct outcome on a panicking peer.
    }
}

struct SendResult {
    status: Status,
    headers: Headers,
    final_url: Url,
    body: BodyReader<ConnReader>,
}

fn connection_is_reusable(headers: &Headers) -> bool {
    match headers.get("connection") {
        Some(v) => !v.eq_ignore_ascii_case("close"),
        None => true,
    }
}

fn drain_body(mut body: BodyReader<ConnReader>) -> io::Result<ConnReader> {
    // Read body to EOF. For redirect responses the body is usually
    // small (a few hundred bytes of HTML); we cap our patience at
    // 64 KiB to defend against pathological servers that try to
    // stream a redirect body forever.
    const REDIRECT_BODY_LIMIT: u64 = 64 * 1024;
    let mut sink = Vec::new();
    (&mut body)
        .take(REDIRECT_BODY_LIMIT)
        .read_to_end(&mut sink)?;
    if !body.is_drained() {
        return Err(io::Error::other("redirect body exceeded 64 KiB limit"));
    }
    Ok(body.into_inner())
}

fn build_tls_config() -> Result<rustls::ClientConfig, ClientError> {
    // Install the default crypto provider once per process.
    // `install_default` returns Err if a provider is already
    // installed; that's fine for us, we want exactly-one.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    Ok(rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

#[cfg(test)]
mod tests {
    // Networked tests live in tests/test_http.rs against a mock
    // server; this module only covers client construction.

    use super::*;

    #[test]
    fn client_default_constructs() {
        let _c = Client::new().expect("default client constructs");
    }

    #[test]
    fn client_with_custom_config() {
        let cfg = ClientConfig {
            max_redirects: 1,
            max_header_bytes: 1024,
            timeout: Duration::from_secs(1),
            pool_capacity: 2,
            read_buffer_bytes: 1024,
            user_agent: Some("test/0".into()),
        };
        let c = Client::with_config(cfg).expect("custom client constructs");
        assert_eq!(c.inner.config.max_redirects, 1);
        assert_eq!(c.inner.config.max_header_bytes, 1024);
        assert_eq!(c.inner.config.pool_capacity, 2);
        assert_eq!(c.inner.config.user_agent.as_deref(), Some("test/0"));
        assert_eq!(c.pool_size(), 0);
    }

    #[test]
    fn config_default_values() {
        let cfg = ClientConfig::default();
        assert_eq!(cfg.max_redirects, DEFAULT_MAX_REDIRECTS);
        assert_eq!(cfg.max_header_bytes, DEFAULT_MAX_HEADER_BYTES);
        assert_eq!(cfg.pool_capacity, DEFAULT_POOL_CAPACITY);
        assert_eq!(cfg.read_buffer_bytes, DEFAULT_READ_BUFFER_BYTES);
        assert_eq!(cfg.timeout, DEFAULT_TIMEOUT);
        assert!(cfg.user_agent.is_none());
    }

    #[test]
    fn connection_is_reusable_default_true() {
        let h = Headers::default();
        assert!(connection_is_reusable(&h));
    }

    #[test]
    fn connection_is_reusable_false_on_close() {
        let mut h = Headers::default();
        h.append("Connection", "close");
        assert!(!connection_is_reusable(&h));
    }

    #[test]
    fn connection_is_reusable_keep_alive_returns_true() {
        let mut h = Headers::default();
        h.append("Connection", "keep-alive");
        assert!(connection_is_reusable(&h));
    }
}
