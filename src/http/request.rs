//! Typed HTTP requests and their on-the-wire serialization.
//!
//! `pux` only ever sends two kinds of requests: a `HEAD` to discover the
//! source's size and capabilities, and a `GET` (full or ranged) to pull
//! bytes. Both have empty bodies and a small fixed set of headers we
//! actually use, so the [`Request`] type is intentionally minimal.

use std::fmt;
use std::io::{self, Write};

use thiserror::Error;

use super::range::format_range_header;
use super::range::RangeError;
use super::url::Url;
use crate::types::ByteRange;

/// Errors produced while building or serializing a [`Request`].
#[derive(Debug, Error)]
pub enum RequestError {
    /// A header name or value contains a byte we refuse to send (CR, LF,
    /// or NUL).
    #[error("invalid header {name:?}: contains control character")]
    InvalidHeader {
        /// The offending header name, included for diagnostics.
        name: String,
    },

    /// Constructing a `Range:` value from the supplied [`ByteRange`]
    /// failed.
    #[error("invalid Range: {source}")]
    Range {
        /// The wrapped [`RangeError`].
        #[source]
        source: RangeError,
    },

    /// Writing serialized bytes to the connection failed.
    #[error("io while writing request")]
    Io(#[source] io::Error),
}

/// HTTP method. Only `GET` and `HEAD` are used.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Method {
    /// Retrieve the resource (or a `Range:`-restricted slice of it).
    Get,
    /// Retrieve only the response headers; the server returns no body.
    Head,
}

impl Method {
    /// The method token as it appears on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A request ready to be written to a connection.
///
/// Construct with [`Self::head`] / [`Self::get`] / [`Self::get_range`],
/// optionally add headers via [`Self::header`], then serialize with
/// [`Self::write_to`]. The struct stores headers verbatim — `Host:` and
/// `User-Agent:` are added by [`Self::write_to`] just before transmission
/// (and skipped if the caller already supplied them).
#[derive(Debug, Clone)]
pub struct Request<'u> {
    method: Method,
    url: &'u Url,
    headers: Vec<(String, String)>,
}

impl<'u> Request<'u> {
    /// Build a `HEAD` request for `url`.
    #[must_use]
    pub fn head(url: &'u Url) -> Self {
        Self::new(Method::Head, url)
    }

    /// Build a full `GET` request for `url`.
    #[must_use]
    pub fn get(url: &'u Url) -> Self {
        Self::new(Method::Get, url)
    }

    /// Build a `GET` request restricted to the half-open `range`.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::Range`] if `range` is empty, since the
    /// HTTP grammar can't express it.
    pub fn get_range(url: &'u Url, range: ByteRange) -> Result<Self, RequestError> {
        let value = format_range_header(range).map_err(|source| RequestError::Range { source })?;
        let mut req = Self::new(Method::Get, url);
        // INVARIANT: format_range_header only emits ASCII alphanumerics,
        // '=', '-', and digits, so no control character can appear.
        req.headers.push(("Range".to_string(), value));
        Ok(req)
    }

    fn new(method: Method, url: &'u Url) -> Self {
        Self {
            method,
            url,
            headers: Vec::with_capacity(4),
        }
    }

    /// Add a custom header, replacing any prior occurrence with the same
    /// case-insensitive name.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::InvalidHeader`] if `name` or `value`
    /// contains a CR, LF, or NUL.
    pub fn header(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<&mut Self, RequestError> {
        let name = name.into();
        let value = value.into();
        if !is_valid_header(&name, &value) {
            return Err(RequestError::InvalidHeader { name });
        }
        // Replace by case-insensitive match.
        let lower = name.to_ascii_lowercase();
        self.headers
            .retain(|(n, _)| n.to_ascii_lowercase() != lower);
        self.headers.push((name, value));
        Ok(self)
    }

    /// The request method.
    #[must_use]
    pub fn method(&self) -> Method {
        self.method
    }

    /// The destination URL.
    #[must_use]
    pub fn url(&self) -> &Url {
        self.url
    }

    /// The headers added so far, in insertion order.
    #[must_use]
    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    /// Look up a header by case-insensitive name.
    #[must_use]
    pub fn get_header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(n, _)| n.to_ascii_lowercase() == lower)
            .map(|(_, v)| v.as_str())
    }

    /// Write the request to `out` in HTTP/1.1 wire format.
    ///
    /// Inserts a default `Host:` header if none was supplied and a
    /// default `User-Agent: pux/<version>` if none was supplied. Adds
    /// the trailing CRLF that terminates the headers but writes no body.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError::Io`] if the underlying writer fails.
    pub fn write_to<W: Write>(&self, out: &mut W) -> Result<(), RequestError> {
        let mut buf = Vec::with_capacity(256);
        write!(
            buf,
            "{} {} HTTP/1.1\r\n",
            self.method.as_str(),
            self.url.path()
        )
        .map_err(RequestError::Io)?;

        let has_host = self.has_header("host");
        if !has_host {
            write!(buf, "Host: {}\r\n", self.url.host_header_value()).map_err(RequestError::Io)?;
        }
        let has_ua = self.has_header("user-agent");
        if !has_ua {
            write!(buf, "User-Agent: pux/{}\r\n", env!("CARGO_PKG_VERSION"))
                .map_err(RequestError::Io)?;
        }
        let has_conn = self.has_header("connection");
        if !has_conn {
            buf.extend_from_slice(b"Connection: keep-alive\r\n");
        }
        let has_accept = self.has_header("accept");
        if !has_accept {
            buf.extend_from_slice(b"Accept: */*\r\n");
        }

        for (name, value) in &self.headers {
            write!(buf, "{name}: {value}\r\n").map_err(RequestError::Io)?;
        }
        buf.extend_from_slice(b"\r\n");

        out.write_all(&buf).map_err(RequestError::Io)?;
        Ok(())
    }

    /// Serialize to a `Vec<u8>` for tests and diagnostics.
    #[must_use]
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        // INVARIANT: write_to only returns RequestError::Io, and writes
        // to `Vec<u8>` are infallible. The Err arm therefore cannot occur.
        if let Err(e) = self.write_to(&mut buf) {
            unreachable!("Vec<u8> writes are infallible, got {e}");
        }
        buf
    }

    fn has_header(&self, lower_name: &str) -> bool {
        self.headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(lower_name))
    }
}

fn is_valid_header(name: &str, value: &str) -> bool {
    let bad = |s: &str| s.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0);
    !name.is_empty() && !bad(name) && !bad(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ByteOffset;

    fn parse(url: &str) -> Url {
        Url::parse(url).expect("test URL parses")
    }

    #[test]
    fn head_request_wire_format() {
        let url = parse("http://example.com/foo");
        let req = Request::head(&url);
        let wire = String::from_utf8(req.to_wire_bytes()).expect("ascii");
        assert!(wire.starts_with("HEAD /foo HTTP/1.1\r\n"));
        assert!(wire.contains("Host: example.com\r\n"));
        assert!(wire.contains("User-Agent: pux/"));
        assert!(wire.contains("Connection: keep-alive\r\n"));
        assert!(wire.ends_with("\r\n\r\n"));
    }

    #[test]
    fn get_request_wire_format() {
        let url = parse("https://example.com/path?x=1");
        let req = Request::get(&url);
        let wire = String::from_utf8(req.to_wire_bytes()).expect("ascii");
        assert!(wire.starts_with("GET /path?x=1 HTTP/1.1\r\n"));
        assert!(wire.contains("Host: example.com\r\n"));
    }

    #[test]
    fn get_range_request_includes_range_header() {
        let url = parse("http://example.com/a");
        let r = ByteRange::new(ByteOffset::new(100), ByteOffset::new(200)).unwrap();
        let req = Request::get_range(&url, r).expect("non-empty range");
        assert_eq!(req.get_header("range"), Some("bytes=100-199"));
        let wire = String::from_utf8(req.to_wire_bytes()).expect("ascii");
        assert!(wire.contains("Range: bytes=100-199\r\n"));
    }

    #[test]
    fn get_range_rejects_empty_range() {
        let url = parse("http://example.com/");
        let r = ByteRange::new(ByteOffset::new(7), ByteOffset::new(7)).unwrap();
        assert!(matches!(
            Request::get_range(&url, r),
            Err(RequestError::Range { .. })
        ));
    }

    #[test]
    fn host_header_includes_explicit_port() {
        let url = parse("http://example.com:8080/foo");
        let req = Request::head(&url);
        let wire = String::from_utf8(req.to_wire_bytes()).expect("ascii");
        assert!(wire.contains("Host: example.com:8080\r\n"));
    }

    #[test]
    fn custom_header_replaces_default_user_agent() {
        let url = parse("http://example.com/");
        let mut req = Request::get(&url);
        req.header("User-Agent", "test/1").expect("valid");
        let wire = String::from_utf8(req.to_wire_bytes()).expect("ascii");
        assert!(wire.contains("User-Agent: test/1\r\n"));
        // The default User-Agent must not also appear.
        assert!(!wire.contains("pux/"));
    }

    #[test]
    fn header_replaces_case_insensitively() {
        let url = parse("http://example.com/");
        let mut req = Request::get(&url);
        req.header("Accept", "text/plain").expect("valid");
        req.header("accept", "application/json").expect("valid");
        assert_eq!(req.headers().len(), 1);
        assert_eq!(req.get_header("Accept"), Some("application/json"));
    }

    #[test]
    fn rejects_header_with_crlf() {
        let url = parse("http://example.com/");
        let mut req = Request::get(&url);
        let err = req
            .header("X-Bad", "value\r\nInjected: yes")
            .expect_err("must reject");
        match err {
            RequestError::InvalidHeader { name } => assert_eq!(name, "X-Bad"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_header_name() {
        let url = parse("http://example.com/");
        let mut req = Request::get(&url);
        assert!(matches!(
            req.header("", "v"),
            Err(RequestError::InvalidHeader { .. })
        ));
    }

    #[test]
    fn root_path_emitted_when_no_path_given() {
        let url = parse("http://example.com");
        let req = Request::get(&url);
        let wire = String::from_utf8(req.to_wire_bytes()).expect("ascii");
        assert!(wire.starts_with("GET / HTTP/1.1\r\n"));
    }
}
