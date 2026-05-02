//! Mock HTTP/1.1 server for testing the `peel` HTTP client.
//!
//! Spins up a real `TcpListener` on `127.0.0.1` (auto-assigned port),
//! accepts connections, parses just enough of each request to dispatch
//! to a per-request handler, and writes whatever bytes the handler asks
//! for. The handler can also opt out of normal response writing and
//! drop the connection mid-stream to simulate failure modes.
//!
//! This is *not* an HTTP server in any general sense; it's a
//! deterministic byte fixture that happens to speak enough HTTP for
//! `peel::http::Client` to drive it.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// One incoming request, as parsed by the mock server.
#[derive(Debug, Clone)]
pub struct MockRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl MockRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// What a handler tells the mock server to do for one request.
pub enum MockResponse {
    /// Send `status` + reason + headers + body. The mock server adds
    /// `Content-Length` automatically if the handler hasn't.
    Reply {
        status: u16,
        reason: &'static str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    },
    /// Write `bytes` verbatim and close the connection. Used to test
    /// chunked encoding, malformed responses, partial bodies, etc.
    RawBytesThenClose(Vec<u8>),
    /// Read the request, then close the connection without sending
    /// anything (simulates a server that disconnects mid-flight).
    DropConnection,
    /// Send headers + a partial body, then sleep `stall` without
    /// sending the rest. Used to simulate a wedged origin / middlebox
    /// that holds the TCP socket open after streaming has started.
    /// The advertised `Content-Length` is `partial_body.len() +
    /// remaining`, so the client thinks more bytes are coming. After
    /// `stall` elapses the mock just drops the connection.
    StallAfterPartialBody {
        status: u16,
        reason: &'static str,
        headers: Vec<(String, String)>,
        partial_body: Vec<u8>,
        remaining: u64,
        stall: Duration,
    },
    /// Send headers, then drip the body in `bytes_per_chunk` slices
    /// separated by `interval`. Frames keep arriving so the per-frame
    /// idle watchdog stays satisfied, but the cumulative rate is
    /// arbitrarily slow — designed to exercise the body-throughput
    /// watchdog. The advertised `Content-Length` is the full body
    /// length; the connection is closed cleanly after the last drip.
    DripBody {
        status: u16,
        reason: &'static str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        bytes_per_chunk: usize,
        interval: Duration,
    },
}

impl MockResponse {
    pub fn ok(body: impl Into<Vec<u8>>) -> Self {
        let body = body.into();
        Self::Reply {
            status: 200,
            reason: "OK",
            headers: Vec::new(),
            body,
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        if let Self::Reply { headers, .. } = &mut self {
            headers.push((name.to_string(), value.to_string()));
        }
        self
    }
}

type Handler = Arc<dyn Fn(&MockRequest, u64) -> MockResponse + Send + Sync>;

/// A running mock server, dropped to shut down.
pub struct MockServer {
    addr: SocketAddr,
    join: Option<JoinHandle<()>>,
    shutdown: Arc<AtomicBool>,
    request_count: Arc<AtomicU64>,
    requests: Arc<Mutex<Vec<MockRequest>>>,
}

impl MockServer {
    /// Start a mock server with the supplied handler.
    pub fn start<F>(handler: F) -> Self
    where
        F: Fn(&MockRequest, u64) -> MockResponse + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0");
        listener
            .set_nonblocking(true)
            .expect("set listener non-blocking");
        let addr = listener.local_addr().expect("local_addr");

        let shutdown = Arc::new(AtomicBool::new(false));
        let request_count = Arc::new(AtomicU64::new(0));
        let requests: Arc<Mutex<Vec<MockRequest>>> = Arc::new(Mutex::new(Vec::new()));
        let handler: Handler = Arc::new(handler);

        let join = {
            let shutdown = Arc::clone(&shutdown);
            let request_count = Arc::clone(&request_count);
            let requests = Arc::clone(&requests);
            thread::Builder::new()
                .name("mock-http-server".into())
                .spawn(move || {
                    server_loop(listener, shutdown, handler, request_count, requests);
                })
                .expect("spawn mock server")
        };

        Self {
            addr,
            join: Some(join),
            shutdown,
            request_count,
            requests,
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

    pub fn snapshot_requests(&self) -> Vec<MockRequest> {
        self.requests.lock().expect("lock").clone()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // Kick the listener loop with a no-op connect so it exits the
        // accept-poll cycle promptly.
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(200));
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn server_loop(
    listener: TcpListener,
    shutdown: Arc<AtomicBool>,
    handler: Handler,
    request_count: Arc<AtomicU64>,
    requests: Arc<Mutex<Vec<MockRequest>>>,
) {
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
                stream.set_nonblocking(false).ok();
                let handler = Arc::clone(&handler);
                let request_count = Arc::clone(&request_count);
                let requests = Arc::clone(&requests);
                thread::Builder::new()
                    .name("mock-http-conn".into())
                    .spawn(move || {
                        handle_connection(stream, handler, request_count, requests);
                    })
                    .ok();
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                break;
            }
        }
    }
}

fn handle_connection(
    stream: TcpStream,
    handler: Handler,
    request_count: Arc<AtomicU64>,
    requests: Arc<Mutex<Vec<MockRequest>>>,
) {
    let stream_clone = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut reader = BufReader::new(stream);
    let mut writer = stream_clone;

    // Loop to support keep-alive.
    loop {
        let req = match read_request(&mut reader) {
            Ok(Some(r)) => r,
            Ok(None) => return, // Clean close.
            Err(_) => return,
        };

        let n = request_count.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut q) = requests.lock() {
            q.push(req.clone());
        }

        let resp = handler(&req, n);

        let close_after = match resp {
            MockResponse::Reply {
                status,
                reason,
                ref headers,
                ref body,
            } => {
                let close = headers.iter().any(|(n, v)| {
                    n.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("close")
                });
                if write_reply(&mut writer, status, reason, headers, body).is_err() {
                    return;
                }
                close
            }
            MockResponse::RawBytesThenClose(bytes) => {
                let _ = writer.write_all(&bytes);
                return;
            }
            MockResponse::DropConnection => return,
            MockResponse::StallAfterPartialBody {
                status,
                reason,
                ref headers,
                ref partial_body,
                remaining,
                stall,
            } => {
                let total_len = partial_body.len() as u64 + remaining;
                let mut hdrs = headers.clone();
                if !hdrs
                    .iter()
                    .any(|(n, _)| n.eq_ignore_ascii_case("content-length"))
                {
                    hdrs.push(("Content-Length".into(), total_len.to_string()));
                }
                if write_reply(&mut writer, status, reason, &hdrs, partial_body).is_err() {
                    return;
                }
                // Hold the socket open without sending anything else.
                // After the stall elapses, returning drops the
                // connection, surfacing a clean read EOF for the
                // client (in lieu of timing out first).
                thread::sleep(stall);
                return;
            }
            MockResponse::DripBody {
                status,
                reason,
                ref headers,
                ref body,
                bytes_per_chunk,
                interval,
            } => {
                let mut hdrs = headers.clone();
                if !hdrs
                    .iter()
                    .any(|(n, _)| n.eq_ignore_ascii_case("content-length"))
                {
                    hdrs.push(("Content-Length".into(), body.len().to_string()));
                }
                // Write the response line + headers but no body, then
                // drip the body out chunk-at-a-time with `interval`
                // between chunks. We deliberately bypass `write_reply`
                // for the body so we can flush between chunks.
                let mut buf = Vec::with_capacity(256);
                let _ = write!(buf, "HTTP/1.1 {status} {reason}\r\n");
                for (n, v) in &hdrs {
                    let _ = write!(buf, "{n}: {v}\r\n");
                }
                buf.extend_from_slice(b"\r\n");
                if writer.write_all(&buf).is_err() || writer.flush().is_err() {
                    return;
                }
                let chunk = bytes_per_chunk.max(1);
                let mut sent = 0usize;
                while sent < body.len() {
                    let end = (sent + chunk).min(body.len());
                    if writer.write_all(&body[sent..end]).is_err() {
                        return;
                    }
                    if writer.flush().is_err() {
                        return;
                    }
                    sent = end;
                    if sent < body.len() {
                        thread::sleep(interval);
                    }
                }
                return;
            }
        };

        if close_after {
            return;
        }
        // Connection: close from the client?
        if req
            .header("connection")
            .map(|v| v.eq_ignore_ascii_case("close"))
            .unwrap_or(false)
        {
            return;
        }
    }
}

fn read_request<R: BufRead>(reader: &mut R) -> std::io::Result<Option<MockRequest>> {
    let mut line = String::new();
    let n = reader.read_line(&mut line)?;
    if n == 0 {
        return Ok(None);
    }
    let line = line.trim_end_matches(['\r', '\n']);
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    if method.is_empty() || path.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad request line",
        ));
    }

    let mut headers = Vec::new();
    let mut header_map: HashMap<String, String> = HashMap::new();
    loop {
        let mut h = String::new();
        let n = reader.read_line(&mut h)?;
        if n == 0 {
            break;
        }
        let h = h.trim_end_matches(['\r', '\n']);
        if h.is_empty() {
            break;
        }
        if let Some((name, value)) = h.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            header_map.insert(name.to_ascii_lowercase(), value.clone());
            headers.push((name, value));
        }
    }

    let mut body = Vec::new();
    if let Some(len) = header_map
        .get("content-length")
        .and_then(|v| v.parse::<u64>().ok())
    {
        let mut taker = reader.take(len);
        taker.read_to_end(&mut body)?;
    }

    Ok(Some(MockRequest {
        method,
        path,
        headers,
        body,
    }))
}

fn write_reply<W: Write>(
    writer: &mut W,
    status: u16,
    reason: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> std::io::Result<()> {
    let mut buf = Vec::with_capacity(256);
    write!(buf, "HTTP/1.1 {status} {reason}\r\n")?;
    let has_cl = headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("content-length"));
    let has_te = headers
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case("transfer-encoding"));
    for (n, v) in headers {
        write!(buf, "{n}: {v}\r\n")?;
    }
    if !has_cl && !has_te {
        // Only auto-add Content-Length when the handler isn't doing
        // chunked or some other framing.
        write!(buf, "Content-Length: {}\r\n", body.len())?;
    }
    buf.extend_from_slice(b"\r\n");
    writer.write_all(&buf)?;
    if !has_te {
        writer.write_all(body)?;
    }
    writer.flush()?;
    Ok(())
}
