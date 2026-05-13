//! Response types: [`Status`], [`Headers`], [`Response`], and the
//! [`BodyReader`] adapter that exposes hyper's frame-based body as a
//! synchronous [`std::io::Read`].
//!
//! The hand-rolled status-line / header / chunked-body parsers that
//! lived here before the hyper migration are gone. Wire framing is
//! now hyper's job; this module's role is to translate hyper types
//! into the synchronous shapes the rest of the codebase consumes,
//! per the boundary rule in `internal/ENGINEERING_STANDARDS.md` §2.3.
//!
//! Code outside `http::client` constructs `Status` / `Headers` only
//! via the [`Client`](super::client::Client), and consumes
//! [`BodyReader`] only as a `Read`. There are no `hyper`/`http`/
//! `tokio` types in any of the public APIs in this module.

use std::io::{self, Read};

use bytes::{Buf, Bytes};
use tokio::sync::{mpsc, oneshot};

/// HTTP status returned by the server.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Status {
    /// Numeric status code, e.g. 200, 206, 404.
    pub code: u16,
    /// Reason phrase. HTTP/2 omits the wire-level reason phrase, so
    /// for H2 responses this is the canonical IANA reason for `code`,
    /// or an empty string if `code` is unrecognized. For H1 responses
    /// it is also the canonical reason (we do not preserve the
    /// server-supplied phrase, which is informational and often
    /// elided).
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
/// stream it without buffering the whole response in memory.
#[derive(Debug)]
pub struct Response {
    /// The status line.
    pub status: Status,
    /// Response headers, in arrival order, with case-insensitive lookup.
    pub headers: Headers,
    /// The body reader. For methods that elide the body (HEAD, 204,
    /// 304, 1xx) this is constructed in the immediately-drained state.
    pub body: BodyReader,
}

impl Response {
    /// `Content-Length` parsed as a `u64`, or `None` if the header was
    /// absent or unparseable.
    ///
    /// Both H1 and H2 expose `content-length` as a normal header when
    /// the server sends it, so this works uniformly across protocol
    /// versions. H2 streams without a content-length will return
    /// `None` here.
    #[must_use]
    pub fn content_length(&self) -> Option<u64> {
        self.headers
            .get("content-length")
            .and_then(|v| v.trim().parse::<u64>().ok())
    }
}

/// Commands sent from a [`BodyReader`] to the runtime task that owns
/// the underlying hyper body.
///
/// Constructed and handled inside [`super::client::Client`]; exposed
/// here only because [`BodyReader`] holds the sender end.
pub(super) enum BodyCommand {
    /// Pull the next data frame from the body. The receiver replies
    /// with `Ok(Some(bytes))` for a data frame, `Ok(None)` for end of
    /// body, or `Err(message)` if hyper reported an error.
    NextFrame {
        reply: oneshot::Sender<Result<Option<Bytes>, String>>,
    },
}

/// Synchronous `Read` adapter over a hyper response body.
///
/// Each `read()` call either drains the in-memory residue from the
/// most recently received frame, or — when the residue is empty —
/// asks the runtime task to await the next frame and blocks the
/// calling thread until the reply arrives. Once the body has reached
/// end-of-stream or errored, subsequent reads return EOF / the same
/// error shape.
///
/// `BodyReader` is not `Send + Sync` across all states intentionally
/// (the `mpsc::Sender` and `oneshot::Sender` types are `Send`); the
/// public callers that move bodies between threads should keep doing
/// so via owned moves rather than shared references.
pub struct BodyReader {
    state: BodyState,
}

enum BodyState {
    /// No body to read. Constructed for HEAD responses and for
    /// status codes that the spec defines as carrying no body
    /// (204, 304, 1xx).
    Empty,
    /// A body that is being streamed from the runtime task.
    Streaming {
        /// Channel to the runtime-thread task that owns the
        /// `hyper::body::Incoming`.
        tx: mpsc::UnboundedSender<BodyCommand>,
        /// Bytes left over from the most recent frame.
        residue: Bytes,
        /// True once a `NextFrame` reply was `Ok(None)` (clean EOS)
        /// or the channel was closed.
        finished: bool,
    },
}

impl std::fmt::Debug for BodyReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match &self.state {
            BodyState::Empty => "Empty",
            BodyState::Streaming { .. } => "Streaming",
        };
        f.debug_struct("BodyReader").field("state", &kind).finish()
    }
}

impl BodyReader {
    pub(super) fn empty() -> Self {
        Self {
            state: BodyState::Empty,
        }
    }

    pub(super) fn streaming(tx: mpsc::UnboundedSender<BodyCommand>) -> Self {
        Self {
            state: BodyState::Streaming {
                tx,
                residue: Bytes::new(),
                finished: false,
            },
        }
    }

    /// True iff the body is fully drained (either it was constructed
    /// empty, or the streaming peer reported end-of-stream and the
    /// residue buffer is empty).
    #[must_use]
    pub fn is_drained(&self) -> bool {
        match &self.state {
            BodyState::Empty => true,
            BodyState::Streaming {
                residue, finished, ..
            } => *finished && residue.is_empty(),
        }
    }
}

impl Read for BodyReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let BodyState::Streaming {
            tx,
            residue,
            finished,
        } = &mut self.state
        else {
            return Ok(0);
        };
        loop {
            if !residue.is_empty() {
                let n = residue.len().min(buf.len());
                buf[..n].copy_from_slice(&residue[..n]);
                residue.advance(n);
                return Ok(n);
            }
            if *finished {
                return Ok(0);
            }
            let (reply_tx, reply_rx) = oneshot::channel();
            if tx.send(BodyCommand::NextFrame { reply: reply_tx }).is_err() {
                // Runtime task gone (Client dropped, or a fatal error
                // tore down the task). Treat as EOS.
                *finished = true;
                return Ok(0);
            }
            match reply_rx.blocking_recv() {
                Err(_) => {
                    *finished = true;
                    return Ok(0);
                }
                Ok(Ok(None)) => {
                    *finished = true;
                    return Ok(0);
                }
                Ok(Ok(Some(bytes))) => {
                    *residue = bytes;
                    // Fall through to the residue-copy branch.
                }
                Ok(Err(msg)) => {
                    *finished = true;
                    return Err(io::Error::other(msg));
                }
            }
        }
    }
}
