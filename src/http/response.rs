//! Streaming HTTP/1.1 response parser.
//!
//! [`Response::read_from`] reads from a [`BufRead`] until the end of the
//! headers, parses the status line and headers, and leaves the caller a
//! [`BodyReader`] positioned at the first body byte. The body is exposed
//! as another [`Read`]: length-delimited (`Content-Length`), chunked
//! (`Transfer-Encoding: chunked`), empty (for `HEAD` and `204`/`304`),
//! or read-until-EOF (HTTP/1.0 fallback).
//!
//! The parser deliberately consumes a [`BufRead`] (not a [`Read`]) so
//! that the [`Client`](super::client::Client) connection pool can hold
//! the same buffered reader across requests: after the caller drains
//! the body, [`BodyReader::into_inner`] hands the underlying buffered
//! reader back, ready to parse the next response from the server's
//! `keep-alive` stream.

use std::io::{self, BufRead, Read};

use thiserror::Error;

/// Errors produced while parsing an HTTP response.
#[derive(Debug, Error)]
pub enum ResponseError {
    /// IO error while reading bytes from the underlying connection.
    #[error("io while reading response")]
    Io(#[source] io::Error),

    /// The response did not start with a valid `HTTP/1.x` status line.
    #[error("invalid status line: {line:?}")]
    InvalidStatusLine {
        /// The offending bytes, lossy-decoded for diagnostics.
        line: String,
    },

    /// A header line could not be parsed (no `:` separator, invalid
    /// bytes, or oversized).
    #[error("invalid header line: {line:?}")]
    InvalidHeader {
        /// The offending bytes, lossy-decoded for diagnostics.
        line: String,
    },

    /// The response had a `Transfer-Encoding` we don't implement.
    #[error("unsupported transfer-encoding: {value:?}")]
    UnsupportedTransferEncoding {
        /// The header value seen on the wire.
        value: String,
    },

    /// The response set both `Content-Length` and
    /// `Transfer-Encoding: chunked`, which the spec forbids.
    #[error("response has both Content-Length and Transfer-Encoding: chunked")]
    AmbiguousFraming,

    /// `Content-Length` could not be parsed as a `u64`.
    #[error("invalid Content-Length: {value:?}")]
    InvalidContentLength {
        /// The header value seen on the wire.
        value: String,
    },

    /// Headers exceeded the configured size cap.
    #[error("response headers exceed maximum size {limit} bytes")]
    HeadersTooLarge {
        /// The cap that was exceeded.
        limit: usize,
    },

    /// The connection closed before the headers terminated.
    #[error("connection closed before end of response headers")]
    UnexpectedEof,
}

/// HTTP status returned by the server.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Status {
    /// Numeric status code, e.g. 200, 206, 404.
    pub code: u16,
    /// The reason phrase verbatim from the response, useful for
    /// diagnostics. Some servers omit it; in that case this is empty.
    pub reason: String,
}

impl Status {
    /// True iff the status is in the 2xx range.
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.code)
    }

    /// True iff the status is in the 3xx range.
    #[must_use]
    pub fn is_redirect(&self) -> bool {
        (300..400).contains(&self.code)
    }
}

/// Header collection preserving insertion order; lookup is
/// case-insensitive.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct Headers {
    fields: Vec<(String, String)>,
}

impl Headers {
    /// True iff the collection contains no headers.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Number of headers stored.
    #[must_use]
    pub fn len(&self) -> usize {
        self.fields.len()
    }

    /// First value for the case-insensitive `name`, if any.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// All values for the case-insensitive `name`, in insertion order.
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.fields
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Iterate `(name, value)` pairs in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.fields.iter().map(|(n, v)| (n.as_str(), v.as_str()))
    }

    /// Add a header. Names are stored verbatim; lookups are case-insensitive.
    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.fields.push((name.into(), value.into()));
    }
}

/// A response whose status and headers have been parsed.
///
/// The body is exposed as a separate [`BodyReader`] so the caller can
/// stream it. Constructing a `Response` moves the underlying buffered
/// reader into the body reader; [`BodyReader::into_inner`] recovers it
/// once the body has been fully drained.
#[derive(Debug)]
pub struct Response<R: BufRead> {
    /// The status line.
    pub status: Status,
    /// Response headers, in arrival order, with case-insensitive lookup.
    pub headers: Headers,
    /// The body reader, framed according to `Content-Length` and
    /// `Transfer-Encoding`.
    pub body: BodyReader<R>,
}

impl<R: BufRead> Response<R> {
    /// Read and parse the status line and headers from `reader`,
    /// leaving it positioned at the first body byte.
    ///
    /// `expect_body` should be `false` for `HEAD` requests; the
    /// returned [`BodyReader`] is then [`BodyReader::Empty`] regardless
    /// of header values. Status codes `204`, `304`, and `1xx` always
    /// carry no body and override `expect_body` accordingly.
    ///
    /// `max_header_bytes` caps the cumulative size of the status line
    /// and headers to defend against runaway servers; recommended value
    /// is 64 KiB.
    ///
    /// # Errors
    ///
    /// Any of the [`ResponseError`] variants.
    pub fn read_from(
        mut reader: R,
        expect_body: bool,
        max_header_bytes: usize,
    ) -> Result<Self, ResponseError> {
        let mut consumed: usize = 0;

        let status_line = read_crlf_line(&mut reader, max_header_bytes, &mut consumed)?;
        let status = parse_status_line(&status_line)?;

        let mut headers = Headers::default();
        loop {
            let line = read_crlf_line(&mut reader, max_header_bytes, &mut consumed)?;
            if line.is_empty() {
                break;
            }
            // RFC 7230 §3.2.4 deprecates header folding; we reject
            // continuation lines (leading SP/HTAB) with a clear error
            // rather than silently misparse.
            if line.starts_with(' ') || line.starts_with('\t') {
                return Err(ResponseError::InvalidHeader { line });
            }
            let (name, value) = parse_header_line(&line)?;
            headers.append(name, value);
        }

        let body = build_body_reader(reader, &headers, &status, expect_body)?;
        Ok(Self {
            status,
            headers,
            body,
        })
    }

    /// `Content-Length` parsed as a `u64`, or `None` if the header was
    /// absent or unparseable.
    #[must_use]
    pub fn content_length(&self) -> Option<u64> {
        self.headers
            .get("content-length")
            .and_then(|v| v.trim().parse::<u64>().ok())
    }
}

/// The framing of a response body.
#[derive(Debug)]
pub enum BodyReader<R: BufRead> {
    /// `Content-Length`-delimited: read at most `remaining` bytes, then
    /// EOF.
    Lengthed {
        /// Bytes remaining to read.
        remaining: u64,
        /// The wrapped buffered reader.
        reader: R,
    },
    /// `Transfer-Encoding: chunked`: framed by chunk-size lines.
    Chunked(ChunkedReader<R>),
    /// No body expected (HEAD response, 204, 304, …). The reader is
    /// retained so the caller can recover it via [`Self::into_inner`].
    Empty(R),
    /// `Content-Length` absent and not chunked: read until EOF on the
    /// connection. Used as the HTTP/1.0 fallback.
    UntilEof(R),
}

impl<R: BufRead> BodyReader<R> {
    /// Recover the inner buffered reader once the body has been
    /// drained.
    ///
    /// The caller is responsible for having consumed the body fully;
    /// otherwise the returned reader is positioned in the middle of a
    /// body and is not safe to reuse for subsequent responses on the
    /// same connection.
    pub fn into_inner(self) -> R {
        match self {
            Self::Lengthed { reader, .. } => reader,
            Self::Chunked(c) => c.into_inner(),
            Self::Empty(r) => r,
            Self::UntilEof(r) => r,
        }
    }

    /// True iff the body is fully drained and the underlying reader is
    /// at the end of the response (and therefore safe to reuse).
    #[must_use]
    pub fn is_drained(&self) -> bool {
        match self {
            Self::Lengthed { remaining, .. } => *remaining == 0,
            Self::Chunked(c) => c.finished,
            Self::Empty(_) => true,
            // `UntilEof` is only ever drained by reading; we cannot tell
            // from outside, so report false defensively.
            Self::UntilEof(_) => false,
        }
    }
}

impl<R: BufRead> Read for BodyReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            BodyReader::Lengthed { remaining, reader } => {
                if *remaining == 0 {
                    return Ok(0);
                }
                let cap = (*remaining).min(buf.len() as u64) as usize;
                let n = reader.read(&mut buf[..cap])?;
                if n == 0 && *remaining > 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed mid-body",
                    ));
                }
                *remaining -= n as u64;
                Ok(n)
            }
            BodyReader::Chunked(c) => c.read(buf),
            BodyReader::Empty(_) => Ok(0),
            BodyReader::UntilEof(r) => r.read(buf),
        }
    }
}

/// Chunked-transfer-encoding decoder.
#[derive(Debug)]
pub struct ChunkedReader<R: BufRead> {
    reader: R,
    /// Bytes remaining to deliver from the current chunk.
    remaining: u64,
    /// Set once the 0-sized terminating chunk has been consumed.
    finished: bool,
}

impl<R: BufRead> ChunkedReader<R> {
    fn new(reader: R) -> Self {
        Self {
            reader,
            remaining: 0,
            finished: false,
        }
    }

    /// Recover the inner reader. See
    /// [`BodyReader::into_inner`] for the same caveat about draining.
    pub fn into_inner(self) -> R {
        self.reader
    }
}

impl<R: BufRead> Read for ChunkedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.finished || buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.remaining > 0 {
                let cap = self.remaining.min(buf.len() as u64) as usize;
                let n = self.reader.read(&mut buf[..cap])?;
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "connection closed mid-chunk",
                    ));
                }
                self.remaining -= n as u64;
                if self.remaining == 0 {
                    consume_crlf(&mut self.reader)?;
                }
                return Ok(n);
            }
            let size_line = read_size_line(&mut self.reader)?;
            let size = parse_chunk_size(&size_line).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid chunk size {size_line:?}: {e}"),
                )
            })?;
            if size == 0 {
                // Optional trailers, then a final CRLF. We accept and
                // discard the trailers without parsing them.
                loop {
                    let line = read_size_line(&mut self.reader)?;
                    if line.is_empty() {
                        break;
                    }
                }
                self.finished = true;
                return Ok(0);
            }
            self.remaining = size;
        }
    }
}

fn read_size_line<R: BufRead>(reader: &mut R) -> io::Result<String> {
    let mut buf = Vec::with_capacity(32);
    reader.read_until(b'\n', &mut buf)?;
    if !buf.ends_with(b"\n") {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "chunk size line truncated",
        ));
    }
    if buf.ends_with(b"\r\n") {
        buf.truncate(buf.len() - 2);
    } else {
        buf.truncate(buf.len() - 1);
    }
    String::from_utf8(buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-utf8 in chunk size line"))
}

fn consume_crlf<R: BufRead>(reader: &mut R) -> io::Result<()> {
    let mut two = [0u8; 2];
    reader.read_exact(&mut two)?;
    if &two != b"\r\n" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing CRLF after chunk data",
        ));
    }
    Ok(())
}

fn parse_chunk_size(line: &str) -> Result<u64, &'static str> {
    let hex = match line.find(';') {
        Some(i) => &line[..i],
        None => line,
    };
    let hex = hex.trim();
    if hex.is_empty() {
        return Err("empty chunk size");
    }
    u64::from_str_radix(hex, 16).map_err(|_| "non-hex chunk size")
}

fn read_crlf_line<R: BufRead>(
    reader: &mut R,
    max_total: usize,
    consumed: &mut usize,
) -> Result<String, ResponseError> {
    let mut buf = Vec::with_capacity(128);
    let n = reader
        .read_until(b'\n', &mut buf)
        .map_err(ResponseError::Io)?;
    if n == 0 {
        return Err(ResponseError::UnexpectedEof);
    }
    *consumed = consumed.saturating_add(n);
    if *consumed > max_total {
        return Err(ResponseError::HeadersTooLarge { limit: max_total });
    }
    if !buf.ends_with(b"\n") {
        return Err(ResponseError::UnexpectedEof);
    }
    if buf.ends_with(b"\r\n") {
        buf.truncate(buf.len() - 2);
    } else {
        buf.truncate(buf.len() - 1);
    }
    String::from_utf8(buf).map_err(|e| ResponseError::InvalidHeader {
        line: String::from_utf8_lossy(e.as_bytes()).into_owned(),
    })
}

fn parse_status_line(line: &str) -> Result<Status, ResponseError> {
    if !(line.starts_with("HTTP/1.0 ") || line.starts_with("HTTP/1.1 ")) {
        return Err(ResponseError::InvalidStatusLine {
            line: line.to_string(),
        });
    }
    let after = &line[9..];
    let (code_str, reason) = match after.find(' ') {
        Some(i) => (&after[..i], after[i + 1..].to_string()),
        None => (after, String::new()),
    };
    let code: u16 = code_str
        .parse()
        .map_err(|_| ResponseError::InvalidStatusLine {
            line: line.to_string(),
        })?;
    if !(100..1000).contains(&code) {
        return Err(ResponseError::InvalidStatusLine {
            line: line.to_string(),
        });
    }
    Ok(Status { code, reason })
}

fn parse_header_line(line: &str) -> Result<(String, String), ResponseError> {
    let (name, value) = line
        .split_once(':')
        .ok_or_else(|| ResponseError::InvalidHeader {
            line: line.to_string(),
        })?;
    if name.is_empty() {
        return Err(ResponseError::InvalidHeader {
            line: line.to_string(),
        });
    }
    if !name.bytes().all(is_tchar) {
        return Err(ResponseError::InvalidHeader {
            line: line.to_string(),
        });
    }
    Ok((name.to_string(), value.trim().to_string()))
}

fn is_tchar(b: u8) -> bool {
    matches!(b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-'
        | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z')
}

fn build_body_reader<R: BufRead>(
    reader: R,
    headers: &Headers,
    status: &Status,
    expect_body: bool,
) -> Result<BodyReader<R>, ResponseError> {
    if !expect_body || matches!(status.code, 204 | 304) || (100..200).contains(&status.code) {
        return Ok(BodyReader::Empty(reader));
    }

    let te = headers.get("transfer-encoding");
    let chunked = match te {
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.eq_ignore_ascii_case("chunked") {
                true
            } else {
                return Err(ResponseError::UnsupportedTransferEncoding {
                    value: value.to_string(),
                });
            }
        }
        None => false,
    };

    let cl = headers.get("content-length");
    if chunked && cl.is_some() {
        return Err(ResponseError::AmbiguousFraming);
    }

    if chunked {
        return Ok(BodyReader::Chunked(ChunkedReader::new(reader)));
    }

    if let Some(value) = cl {
        let n = value
            .trim()
            .parse::<u64>()
            .map_err(|_| ResponseError::InvalidContentLength {
                value: value.to_string(),
            })?;
        return Ok(BodyReader::Lengthed {
            remaining: n,
            reader,
        });
    }

    Ok(BodyReader::UntilEof(reader))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::BufReader;

    fn parse(input: &[u8], expect_body: bool) -> Response<BufReader<&[u8]>> {
        let r = BufReader::with_capacity(8192, input);
        Response::read_from(r, expect_body, 64 * 1024).expect("parse")
    }

    fn parse_err(input: &[u8], expect_body: bool) -> ResponseError {
        let r = BufReader::with_capacity(8192, input);
        Response::read_from(r, expect_body, 64 * 1024).unwrap_err()
    }

    #[test]
    fn parses_minimal_200() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let mut resp = parse(raw, true);
        assert_eq!(resp.status.code, 200);
        assert_eq!(resp.status.reason, "OK");
        assert_eq!(resp.content_length(), Some(5));
        let mut body = String::new();
        resp.body.read_to_string(&mut body).expect("body reads");
        assert_eq!(body, "hello");
        assert!(resp.body.is_drained());
    }

    #[test]
    fn parses_206_with_content_range() {
        let raw = b"HTTP/1.1 206 Partial Content\r\nContent-Length: 3\r\nContent-Range: bytes 0-2/100\r\n\r\nabc";
        let mut resp = parse(raw, true);
        assert_eq!(resp.status.code, 206);
        assert_eq!(resp.headers.get("Content-Range"), Some("bytes 0-2/100"));
        let mut body = Vec::new();
        resp.body.read_to_end(&mut body).unwrap();
        assert_eq!(body, b"abc");
    }

    #[test]
    fn parses_chunked_body() {
        let raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut resp = parse(raw, true);
        let mut body = String::new();
        resp.body.read_to_string(&mut body).unwrap();
        assert_eq!(body, "hello world");
        assert!(resp.body.is_drained());
    }

    #[test]
    fn parses_chunked_with_extension_and_trailer() {
        let raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n0\r\nX-Foo: bar\r\n\r\n";
        let mut resp = parse(raw, true);
        let mut body = String::new();
        resp.body.read_to_string(&mut body).unwrap();
        assert_eq!(body, "hello");
    }

    #[test]
    fn head_response_has_empty_body_reader() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
        let mut resp = parse(raw, false);
        assert_eq!(resp.status.code, 200);
        let mut body = Vec::new();
        resp.body.read_to_end(&mut body).unwrap();
        assert!(body.is_empty());
        assert!(resp.body.is_drained());
    }

    #[test]
    fn parses_status_without_reason() {
        let raw = b"HTTP/1.1 200\r\nContent-Length: 0\r\n\r\n";
        let resp = parse(raw, true);
        assert_eq!(resp.status.code, 200);
        assert_eq!(resp.status.reason, "");
    }

    #[test]
    fn parses_204_no_content_has_empty_body() {
        let raw = b"HTTP/1.1 204 No Content\r\n\r\n";
        let mut resp = parse(raw, true);
        let mut body = Vec::new();
        resp.body.read_to_end(&mut body).unwrap();
        assert!(body.is_empty());
    }

    #[test]
    fn parses_redirect() {
        let raw = b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://other.example/\r\nContent-Length: 0\r\n\r\n";
        let resp = parse(raw, true);
        assert_eq!(resp.status.code, 301);
        assert!(resp.status.is_redirect());
        assert_eq!(resp.headers.get("Location"), Some("https://other.example/"));
    }

    #[test]
    fn rejects_ambiguous_framing() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello";
        assert!(matches!(
            parse_err(raw, true),
            ResponseError::AmbiguousFraming
        ));
    }

    #[test]
    fn rejects_invalid_status_line() {
        let raw = b"HTPP/1.1 200 OK\r\n\r\n";
        assert!(matches!(
            parse_err(raw, true),
            ResponseError::InvalidStatusLine { .. }
        ));
    }

    #[test]
    fn rejects_invalid_header_line() {
        let raw = b"HTTP/1.1 200 OK\r\nX Bad: 1\r\n\r\n";
        assert!(matches!(
            parse_err(raw, true),
            ResponseError::InvalidHeader { .. }
        ));
    }

    #[test]
    fn rejects_oversized_headers() {
        let mut raw = b"HTTP/1.1 200 OK\r\n".to_vec();
        for i in 0..2000 {
            raw.extend_from_slice(format!("X-{i}: padding\r\n").as_bytes());
        }
        raw.extend_from_slice(b"\r\n");
        let r = BufReader::new(&raw[..]);
        let err = Response::read_from(r, true, 1024).unwrap_err();
        assert!(matches!(err, ResponseError::HeadersTooLarge { .. }));
    }

    #[test]
    fn rejects_unsupported_transfer_encoding() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n";
        assert!(matches!(
            parse_err(raw, true),
            ResponseError::UnsupportedTransferEncoding { .. }
        ));
    }

    #[test]
    fn unexpected_eof_during_status_line() {
        let raw = b"HTTP/1.1";
        assert!(matches!(parse_err(raw, true), ResponseError::UnexpectedEof));
    }

    #[test]
    fn truncated_body_returns_io_error() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhi";
        let mut resp = parse(raw, true);
        let mut buf = Vec::new();
        let err = resp.body.read_to_end(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let resp = parse(raw, true);
        assert_eq!(resp.headers.get("content-length"), Some("0"));
        assert_eq!(resp.headers.get("CONTENT-LENGTH"), Some("0"));
    }

    #[test]
    fn multiple_headers_same_name() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n";
        let resp = parse(raw, true);
        let cookies: Vec<&str> = resp.headers.get_all("Set-Cookie").collect();
        assert_eq!(cookies, vec!["a=1", "b=2"]);
    }

    #[test]
    fn into_inner_returns_buffered_reader_after_drain() {
        // Two responses pipelined back-to-back. After draining the
        // first we must still be able to read the second response from
        // the recovered reader.
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nbye";
        let r = BufReader::with_capacity(8192, &raw[..]);
        let mut first = Response::read_from(r, true, 64 * 1024).expect("parse first");
        let mut body = Vec::new();
        first.body.read_to_end(&mut body).unwrap();
        assert_eq!(body, b"hello");

        let recovered = first.body.into_inner();
        let mut second = Response::read_from(recovered, true, 64 * 1024).expect("parse second");
        let mut body2 = Vec::new();
        second.body.read_to_end(&mut body2).unwrap();
        assert_eq!(body2, b"bye");
    }
}
