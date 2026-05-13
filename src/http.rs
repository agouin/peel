//! HTTP/1.1 + HTTP/2 client used by the download scheduler.
//!
//! Built on `hyper` + `hyper-util` + `hyper-rustls`, with ALPN
//! auto-negotiating H1↔H2 per origin. Higher-level wrapper crates
//! (`reqwest`, `ureq`, etc.) are still avoided: everything above
//! `hyper-util::client::legacy::Client` — redirect handling,
//! `UnexpectedStatus` checks, the synchronous public API, the
//! `Read`-shaped body adapter that callers consume — lives in
//! [`client`]. See `internal/ENGINEERING_STANDARDS.md` §2.3 for the
//! rationale and §2.5 for how the `tokio` runtime is confined to this
//! module.
//!
//! # Layering
//!
//! - [`url`] — minimal URL parser sufficient for the schemes (`http`,
//!   `https`) and authorities the client supports.
//! - [`range`] — `Range:` / `Content-Range:` header parsing.
//! - [`request`] — the [`Method`](request::Method) enum surfaced by
//!   [`ClientError::UnexpectedStatus`](client::ClientError::UnexpectedStatus).
//!   The hand-rolled request serializer that previously lived here is
//!   gone; hyper now constructs the wire-level request itself.
//! - [`response`] — [`Headers`](response::Headers), [`Status`](response::Status),
//!   and the [`BodyReader`](response::BodyReader) `std::io::Read` adapter
//!   over hyper's body stream.
//! - [`client`] — the [`Client`](client::Client) itself: hyper-based
//!   connection management, TLS via `hyper-rustls`, redirect handling,
//!   [`HEAD`](client::Client::head),
//!   [`get_full`](client::Client::get_full), and
//!   [`get_range`](client::Client::get_range).
//!
//! # Scope
//!
//! HTTP/1.1 and HTTP/2 (selected by ALPN). HTTPS via `rustls` with
//! WebPKI roots; plaintext HTTP supported. No compression, no cookies,
//! no proxies. The only request bodies the client knows how to send
//! are zero bytes.

// `client` is gated to `cfg(unix)` only because the underlying
// `hyper-util` connector implementation we use brings in a tokio
// runtime and currently inherits Unix-only paths from the wider
// codebase. The HTTP path itself no longer touches
// `crate::io_backend`; that boundary moved out with the migration
// to hyper.
#[cfg(unix)]
pub mod client;
pub mod range;
pub mod request;
pub mod response;
pub mod url;

#[cfg(unix)]
pub use client::{Client, ClientConfig, ClientError, HttpVersion};
pub use range::{ContentRange, RangeError};
pub use request::Method;
pub use response::{BodyReader, Headers, Response, Status};
pub use url::{Scheme, Url, UrlError};
