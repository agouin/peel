//! Hand-rolled HTTP/1.1 client used by the download scheduler.
//!
//! `peel` deliberately avoids `reqwest`/`hyper`/`ureq`. The wire-level
//! behaviour we depend on (HEAD, ranged GET, basic redirects, ETag and
//! `Content-Range` round-tripping) is small enough to write ourselves on
//! top of [`std::net::TcpStream`] and `rustls`. See
//! `docs/ENGINEERING_STANDARDS.md` §2.3 for the rationale.
//!
//! # Layering
//!
//! - [`url`] — minimal URL parser sufficient for the schemes (`http`,
//!   `https`) and authorities the client supports.
//! - [`range`] — `Range:` / `Content-Range:` header parsing.
//! - [`request`] — typed [`Request`](request::Request) and its on-the-wire
//!   serialization.
//! - [`response`] — streaming [`Response`](response::Response) parser and
//!   body readers (length-delimited and `chunked`).
//! - [`client`] — the [`Client`](client::Client) itself: connection pool,
//!   TLS, redirect handling, [`HEAD`](client::Client::head),
//!   [`get_full`](client::Client::get_full), and
//!   [`get_range`](client::Client::get_range).
//!
//! # Scope
//!
//! HTTP/1.1 only. Plaintext over [`TcpStream`](std::net::TcpStream) and
//! TLS via `rustls` with WebPKI roots. No HTTP/2, no compression, no
//! cookies, no proxies. The only request bodies the client knows how to
//! send are zero bytes.

pub mod client;
pub mod range;
pub mod request;
pub mod response;
pub mod url;

pub use client::{Client, ClientConfig, ClientError};
pub use range::{ContentRange, RangeError};
pub use request::{Method, Request, RequestError};
pub use response::{BodyReader, Headers, Response, ResponseError, Status};
pub use url::{Scheme, Url, UrlError};
