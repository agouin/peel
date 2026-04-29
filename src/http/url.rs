//! Minimal URL parser for the HTTP client.
//!
//! `pux` only needs to understand the URL shapes the download scheduler
//! actually hands the client: an absolute `http`/`https` URL with an
//! authority, an optional port, an optional path, and an optional query.
//! Fragments are stripped (servers never see them); userinfo (`user:pass@`)
//! and IPv6 literals are unsupported and rejected explicitly. This is
//! deliberately not a general-purpose URL crate: it covers the URLs we
//! issue and refuses everything else with a typed error.

use std::fmt;

use thiserror::Error;

/// Errors produced while parsing a URL via [`Url::parse`].
#[derive(Debug, Error)]
pub enum UrlError {
    /// The input did not begin with `http://` or `https://`.
    #[error("URL must start with http:// or https://")]
    UnsupportedScheme,

    /// The URL had no host component.
    #[error("URL has no host component")]
    MissingHost,

    /// The host contained characters disallowed in DNS names — most
    /// commonly an IPv6 literal in `[...]` form, which the MVP client
    /// does not implement.
    #[error("host {host:?} contains characters not supported by the MVP client")]
    UnsupportedHost {
        /// The offending host string, with surrounding URL context
        /// stripped.
        host: String,
    },

    /// The port component was not a valid `u16`.
    #[error("invalid port {port:?} in URL")]
    InvalidPort {
        /// The raw port substring that failed to parse.
        port: String,
    },

    /// The URL contained `userinfo@authority` syntax, which we reject
    /// rather than silently leaking credentials in `Host:` headers.
    #[error("userinfo (`user:pass@`) is not supported in URLs")]
    UserinfoNotSupported,
}

/// The two URL schemes the HTTP client supports.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum Scheme {
    /// Plaintext HTTP, default port 80.
    Http,
    /// HTTP over TLS, default port 443.
    Https,
}

impl Scheme {
    /// The default TCP port for this scheme.
    #[must_use]
    pub const fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }

    /// True iff this scheme uses TLS.
    #[must_use]
    pub const fn is_tls(self) -> bool {
        matches!(self, Self::Https)
    }

    /// Lowercase scheme name without trailing `://`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parsed absolute HTTP/HTTPS URL.
///
/// Holds a normalized representation: scheme, lowercased host, resolved
/// port (defaulted from the scheme when absent), and a request-target
/// path (always non-empty — `"/"` is substituted when the URL omits the
/// path). The query string, if any, is preserved on [`Self::path`].
///
/// # Examples
///
/// ```
/// use pux::http::{Scheme, Url};
///
/// let u = Url::parse("https://example.com/foo?x=1#frag").expect("valid");
/// assert_eq!(u.scheme(), Scheme::Https);
/// assert_eq!(u.host(), "example.com");
/// assert_eq!(u.port(), 443);
/// assert_eq!(u.path(), "/foo?x=1");
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Url {
    scheme: Scheme,
    host: String,
    port: u16,
    path: String,
}

impl Url {
    /// Parse a URL string.
    ///
    /// # Errors
    ///
    /// Returns one of the [`UrlError`] variants if the input is missing a
    /// supported scheme, omits the host, has an invalid port, contains
    /// `userinfo`, or otherwise cannot be normalized. Fragments are
    /// stripped silently.
    pub fn parse(input: &str) -> Result<Self, UrlError> {
        let (scheme, rest) = if let Some(rest) = input.strip_prefix("http://") {
            (Scheme::Http, rest)
        } else if let Some(rest) = input.strip_prefix("https://") {
            (Scheme::Https, rest)
        } else {
            return Err(UrlError::UnsupportedScheme);
        };

        // Strip fragment. Per RFC 3986 the fragment is never sent to the
        // origin server, so we just discard it.
        let rest = match rest.find('#') {
            Some(i) => &rest[..i],
            None => rest,
        };

        // Split authority from path. The path begins at the first '/' or
        // '?'; if the URL has neither, the path is "/".
        let (authority, path) = match rest.find(['/', '?']) {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };

        if authority.contains('@') {
            return Err(UrlError::UserinfoNotSupported);
        }

        let (host_raw, port_opt) = match authority.rfind(':') {
            Some(i) => (&authority[..i], Some(&authority[i + 1..])),
            None => (authority, None),
        };

        if host_raw.is_empty() {
            return Err(UrlError::MissingHost);
        }
        if !is_valid_host(host_raw) {
            return Err(UrlError::UnsupportedHost {
                host: host_raw.to_string(),
            });
        }

        let port = match port_opt {
            None => scheme.default_port(),
            Some(p) => p.parse::<u16>().map_err(|_| UrlError::InvalidPort {
                port: p.to_string(),
            })?,
        };

        // Path may begin with '?' (query without explicit '/'); normalize
        // to "/?...". Empty path becomes "/".
        let path = if path.starts_with('?') {
            format!("/{path}")
        } else if path.is_empty() {
            "/".to_string()
        } else {
            path.to_string()
        };

        Ok(Self {
            scheme,
            host: host_raw.to_ascii_lowercase(),
            port,
            path,
        })
    }

    /// The URL scheme (`http` or `https`).
    #[must_use]
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The host, lowercased, without surrounding brackets.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The TCP port, defaulted from the scheme when the URL omitted it.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The request-target path including query string, e.g. `/foo?x=1`.
    /// Always non-empty.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// `host:port` formatted as it appears in the `Host:` header.
    /// The port is omitted when it equals the scheme's default port.
    #[must_use]
    pub fn host_header_value(&self) -> String {
        if self.port == self.scheme.default_port() {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Resolve a redirect target — either an absolute URL or a relative
    /// path/path-and-query — against this URL.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::parse`] when `location` is an
    /// absolute URL with an unsupported scheme or invalid component.
    pub fn join(&self, location: &str) -> Result<Self, UrlError> {
        if location.starts_with("http://") || location.starts_with("https://") {
            return Self::parse(location);
        }
        let trimmed = match location.find('#') {
            Some(i) => &location[..i],
            None => location,
        };
        let new_path = if trimmed.starts_with('/') {
            trimmed.to_string()
        } else if trimmed.starts_with('?') {
            // Query-only redirect: replace query of current path.
            let base = match self.path.find('?') {
                Some(i) => &self.path[..i],
                None => self.path.as_str(),
            };
            format!("{base}{trimmed}")
        } else {
            // Relative path, resolved against the current path's
            // directory component.
            let base_dir = match self.path.rfind('/') {
                Some(i) => &self.path[..=i],
                None => "/",
            };
            format!("{base_dir}{trimmed}")
        };
        Ok(Self {
            scheme: self.scheme,
            host: self.host.clone(),
            port: self.port,
            path: if new_path.is_empty() {
                "/".to_string()
            } else {
                new_path
            },
        })
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.port == self.scheme.default_port() {
            write!(f, "{}://{}{}", self.scheme, self.host, self.path)
        } else {
            write!(
                f,
                "{}://{}:{}{}",
                self.scheme, self.host, self.port, self.path
            )
        }
    }
}

/// True iff every character in `host` is valid for the DNS-like names we
/// allow here (ASCII alphanumerics, `.`, `-`, `_`). Crucially this also
/// rejects `[...]` IPv6 literals, which we explicitly do not support.
fn is_valid_host(host: &str) -> bool {
    !host.is_empty()
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_with_default_port() {
        let u = Url::parse("http://example.com/").expect("valid");
        assert_eq!(u.scheme(), Scheme::Http);
        assert_eq!(u.host(), "example.com");
        assert_eq!(u.port(), 80);
        assert_eq!(u.path(), "/");
    }

    #[test]
    fn parse_https_with_default_port() {
        let u = Url::parse("https://example.com/").expect("valid");
        assert_eq!(u.scheme(), Scheme::Https);
        assert_eq!(u.port(), 443);
    }

    #[test]
    fn parse_explicit_port() {
        let u = Url::parse("http://example.com:8080/foo").expect("valid");
        assert_eq!(u.port(), 8080);
        assert_eq!(u.path(), "/foo");
    }

    #[test]
    fn parse_no_path_defaults_to_slash() {
        let u = Url::parse("http://example.com").expect("valid");
        assert_eq!(u.path(), "/");
    }

    #[test]
    fn parse_query_only() {
        let u = Url::parse("http://example.com?x=1").expect("valid");
        assert_eq!(u.path(), "/?x=1");
    }

    #[test]
    fn parse_query_with_path() {
        let u = Url::parse("http://example.com/a/b?x=1&y=2").expect("valid");
        assert_eq!(u.path(), "/a/b?x=1&y=2");
    }

    #[test]
    fn parse_strips_fragment() {
        let u = Url::parse("http://example.com/foo#bar").expect("valid");
        assert_eq!(u.path(), "/foo");
    }

    #[test]
    fn parse_lowercases_host() {
        let u = Url::parse("http://EXAMPLE.com/").expect("valid");
        assert_eq!(u.host(), "example.com");
    }

    #[test]
    fn host_header_value_omits_default_port() {
        let u = Url::parse("https://example.com/").expect("valid");
        assert_eq!(u.host_header_value(), "example.com");
    }

    #[test]
    fn host_header_value_includes_explicit_port() {
        let u = Url::parse("http://example.com:8080/").expect("valid");
        assert_eq!(u.host_header_value(), "example.com:8080");
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert!(matches!(
            Url::parse("ftp://example.com/"),
            Err(UrlError::UnsupportedScheme)
        ));
        assert!(matches!(
            Url::parse("example.com"),
            Err(UrlError::UnsupportedScheme)
        ));
    }

    #[test]
    fn rejects_missing_host() {
        assert!(matches!(
            Url::parse("http:///foo"),
            Err(UrlError::MissingHost)
        ));
    }

    #[test]
    fn rejects_invalid_port() {
        match Url::parse("http://example.com:notaport/") {
            Err(UrlError::InvalidPort { port }) => assert_eq!(port, "notaport"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rejects_port_overflow() {
        assert!(matches!(
            Url::parse("http://example.com:99999/"),
            Err(UrlError::InvalidPort { .. })
        ));
    }

    #[test]
    fn rejects_userinfo() {
        assert!(matches!(
            Url::parse("http://user:pass@example.com/"),
            Err(UrlError::UserinfoNotSupported)
        ));
    }

    #[test]
    fn rejects_ipv6_literal() {
        assert!(matches!(
            Url::parse("http://[::1]/"),
            Err(UrlError::UnsupportedHost { .. })
        ));
    }

    #[test]
    fn display_roundtrip_default_port() {
        let u = Url::parse("https://example.com/foo").expect("valid");
        assert_eq!(u.to_string(), "https://example.com/foo");
    }

    #[test]
    fn display_roundtrip_explicit_port() {
        let u = Url::parse("http://example.com:8080/").expect("valid");
        assert_eq!(u.to_string(), "http://example.com:8080/");
    }

    #[test]
    fn join_absolute_replaces_everything() {
        let base = Url::parse("https://a.example/path").expect("valid");
        let joined = base.join("http://b.example/x").expect("valid");
        assert_eq!(joined.host(), "b.example");
        assert_eq!(joined.scheme(), Scheme::Http);
        assert_eq!(joined.path(), "/x");
    }

    #[test]
    fn join_absolute_path() {
        let base = Url::parse("https://example.com/a/b/c").expect("valid");
        let joined = base.join("/d").expect("valid");
        assert_eq!(joined.host(), "example.com");
        assert_eq!(joined.path(), "/d");
    }

    #[test]
    fn join_relative_path_uses_directory() {
        let base = Url::parse("https://example.com/a/b/c.html").expect("valid");
        let joined = base.join("d.html").expect("valid");
        assert_eq!(joined.path(), "/a/b/d.html");
    }

    #[test]
    fn join_query_only_replaces_query() {
        let base = Url::parse("https://example.com/foo?old=1").expect("valid");
        let joined = base.join("?new=2").expect("valid");
        assert_eq!(joined.path(), "/foo?new=2");
    }

    #[test]
    fn join_strips_fragment_in_relative() {
        let base = Url::parse("https://example.com/a/b").expect("valid");
        let joined = base.join("c#frag").expect("valid");
        assert_eq!(joined.path(), "/a/c");
    }
}
