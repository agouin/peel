//! HTTP method enum used in error reporting.
//!
//! Before the hyper migration this module also held a hand-rolled
//! request builder and wire-format serializer. Those were dropped
//! when [`super::client::Client`] moved to `hyper`, which constructs
//! the request itself. The [`Method`] enum is retained because
//! [`super::client::ClientError::UnexpectedStatus`] surfaces it to
//! callers and one downstream module ([`crate::download::scheduler`])
//! constructs that variant directly.

use std::fmt;

/// HTTP method. Only `GET` and `HEAD` are used by `peel`.
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
