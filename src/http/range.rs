//! `Range:` and `Content-Range:` header serialization and parsing.
//!
//! The download scheduler sends `Range: bytes=a-b` to ask for a slice of
//! the source file and verifies the server's reply by parsing
//! `Content-Range: bytes a-b/total`. This module owns both directions and
//! the typed errors produced when a server's reply doesn't match what we
//! asked for.
//!
//! # Inclusive vs. half-open
//!
//! HTTP byte ranges are *inclusive on both ends*: `bytes=0-99` requests
//! the first 100 bytes. Internally `peel` uses [`crate::types::ByteRange`]
//! which is half-open (`[start, end_exclusive)`). The conversions in
//! this module are explicit so the two conventions never collide
//! silently.

use std::fmt;

use thiserror::Error;

use crate::types::{ByteOffset, ByteRange};

/// Errors produced while parsing or constructing range headers.
#[derive(Debug, Error)]
pub enum RangeError {
    /// The header did not start with `bytes ` or `bytes=` as required.
    #[error("range header missing `bytes` unit: {value:?}")]
    MissingBytesUnit {
        /// The offending header value.
        value: String,
    },

    /// The numeric components of the range could not be parsed.
    #[error("range header has malformed numeric component: {value:?}")]
    Malformed {
        /// The offending header value.
        value: String,
    },

    /// The decoded range is empty or reversed
    /// (`first_byte > last_byte_inclusive`), which the spec forbids.
    #[error("range header has invalid bounds: first={first}, last={last}, total={total:?}")]
    InvalidBounds {
        /// `first-byte-pos` value the header carried.
        first: u64,
        /// `last-byte-pos` value the header carried.
        last: u64,
        /// Total size, if any, from `Content-Range`.
        total: Option<u64>,
    },

    /// We asked for an empty range (`start == end_exclusive`), which
    /// cannot be expressed as an HTTP range header.
    #[error("cannot serialize an empty byte range as a Range header")]
    EmptyRange,
}

/// Format a [`ByteRange`] as the value of a `Range:` request header.
///
/// HTTP byte ranges are inclusive on both ends, so a half-open range
/// `[start, end_exclusive)` of length `n` becomes
/// `bytes=start-(end_exclusive - 1)`.
///
/// # Errors
///
/// Returns [`RangeError::EmptyRange`] if the input range is empty.
///
/// # Examples
///
/// ```
/// use peel::http::range::format_range_header;
/// use peel::types::{ByteOffset, ByteRange};
///
/// let r = ByteRange::new(ByteOffset::new(0), ByteOffset::new(100)).unwrap();
/// assert_eq!(format_range_header(r).unwrap(), "bytes=0-99");
/// ```
pub fn format_range_header(range: ByteRange) -> Result<String, RangeError> {
    if range.is_empty() {
        return Err(RangeError::EmptyRange);
    }
    let first = range.start().get();
    // INVARIANT: range is non-empty (checked above), so `len() >= 1` and
    // `first + len - 1` cannot overflow because `end_exclusive` itself
    // fits in u64.
    let last = range
        .end_exclusive()
        .get()
        .checked_sub(1)
        .ok_or(RangeError::EmptyRange)?;
    Ok(format!("bytes={first}-{last}"))
}

/// A successfully parsed `Content-Range: bytes <first>-<last>/<total>`
/// header.
///
/// `total` is `None` when the server sent `*` for the resource's total
/// size — RFC 7233 permits this, and the scheduler treats it as "size
/// unknown" rather than aborting.
///
/// All instances are well-formed: `first_byte <= last_byte`, and if
/// `total` is `Some(t)` then `last_byte < t`. Construct via
/// [`Self::new`] or [`parse_content_range`].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct ContentRange {
    first_byte: u64,
    last_byte: u64,
    total: Option<u64>,
}

impl ContentRange {
    /// Construct a [`ContentRange`] with explicit components.
    ///
    /// # Errors
    ///
    /// Returns [`RangeError::InvalidBounds`] if `last_byte < first_byte`,
    /// or if `total = Some(t)` and `last_byte >= t`.
    pub fn new(first_byte: u64, last_byte: u64, total: Option<u64>) -> Result<Self, RangeError> {
        if last_byte < first_byte {
            return Err(RangeError::InvalidBounds {
                first: first_byte,
                last: last_byte,
                total,
            });
        }
        if let Some(t) = total {
            if last_byte >= t {
                return Err(RangeError::InvalidBounds {
                    first: first_byte,
                    last: last_byte,
                    total,
                });
            }
        }
        Ok(Self {
            first_byte,
            last_byte,
            total,
        })
    }

    /// Inclusive lower bound of the byte range.
    #[must_use]
    pub fn first_byte(&self) -> u64 {
        self.first_byte
    }

    /// Inclusive upper bound of the byte range.
    #[must_use]
    pub fn last_byte(&self) -> u64 {
        self.last_byte
    }

    /// Total resource size, if the server provided one.
    #[must_use]
    pub fn total(&self) -> Option<u64> {
        self.total
    }

    /// Convert to a half-open [`ByteRange`].
    #[must_use]
    pub fn as_byte_range(&self) -> ByteRange {
        // INVARIANT: `Self::new` and `parse_content_range` both enforce
        // last_byte >= first_byte, and ByteRange::new only fails when
        // end_exclusive < start. saturating_add tops out at u64::MAX,
        // which is still >= self.first_byte under the invariant.
        let end = self.last_byte.saturating_add(1);
        match ByteRange::new(ByteOffset::new(self.first_byte), ByteOffset::new(end)) {
            Some(r) => r,
            None => unreachable!("ContentRange invariant: last_byte >= first_byte"),
        }
    }

    /// Length of the range in bytes (inclusive on both ends, so
    /// `last - first + 1`).
    #[must_use]
    pub fn len(&self) -> u64 {
        // INVARIANT: last_byte >= first_byte, so subtraction never
        // underflows. Saturating add tolerates last_byte == u64::MAX.
        self.last_byte
            .saturating_sub(self.first_byte)
            .saturating_add(1)
    }

    /// Always `false`: `ContentRange` cannot represent a zero-length
    /// range (HTTP byte ranges are inclusive, so the smallest legal
    /// range is one byte). Provided so the `clippy::len_without_is_empty`
    /// lint stays satisfied.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }
}

impl fmt::Display for ContentRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.total {
            Some(t) => write!(f, "bytes {}-{}/{}", self.first_byte, self.last_byte, t),
            None => write!(f, "bytes {}-{}/*", self.first_byte, self.last_byte),
        }
    }
}

/// Parse a `Content-Range` response header value.
///
/// Accepts the only shape we care about,
/// `bytes <first>-<last>/<total>`, where `<total>` may be `*`.
/// Whitespace inside the value is tolerated; an entirely empty value or
/// a `bytes */<total>` "unsatisfied range" reply is rejected because the
/// scheduler should never see one.
///
/// # Errors
///
/// Returns one of the [`RangeError`] variants on malformed input.
pub fn parse_content_range(value: &str) -> Result<ContentRange, RangeError> {
    let trimmed = value.trim();
    let rest = trimmed
        .strip_prefix("bytes")
        .ok_or_else(|| RangeError::MissingBytesUnit {
            value: value.to_string(),
        })?;
    // Spec syntax has a single SP after "bytes"; tolerate extra
    // whitespace and accept "bytes=" defensively (some servers misuse it
    // here even though "=" is the request-header separator).
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=').unwrap_or(rest).trim_start();

    let (range_part, total_part) = rest.split_once('/').ok_or_else(|| RangeError::Malformed {
        value: value.to_string(),
    })?;

    let (first_str, last_str) =
        range_part
            .split_once('-')
            .ok_or_else(|| RangeError::Malformed {
                value: value.to_string(),
            })?;

    let first = first_str
        .trim()
        .parse::<u64>()
        .map_err(|_| RangeError::Malformed {
            value: value.to_string(),
        })?;
    let last = last_str
        .trim()
        .parse::<u64>()
        .map_err(|_| RangeError::Malformed {
            value: value.to_string(),
        })?;

    let total = match total_part.trim() {
        "*" => None,
        s => Some(s.parse::<u64>().map_err(|_| RangeError::Malformed {
            value: value.to_string(),
        })?),
    };

    ContentRange::new(first, last, total)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- format_range_header ------------------------------------------

    #[test]
    fn format_range_header_simple() {
        let r = ByteRange::new(ByteOffset::new(0), ByteOffset::new(100)).unwrap();
        assert_eq!(format_range_header(r).unwrap(), "bytes=0-99");
    }

    #[test]
    fn format_range_header_offset() {
        let r = ByteRange::new(ByteOffset::new(1024), ByteOffset::new(2048)).unwrap();
        assert_eq!(format_range_header(r).unwrap(), "bytes=1024-2047");
    }

    #[test]
    fn format_range_header_single_byte() {
        let r = ByteRange::new(ByteOffset::new(5), ByteOffset::new(6)).unwrap();
        assert_eq!(format_range_header(r).unwrap(), "bytes=5-5");
    }

    #[test]
    fn format_range_header_rejects_empty() {
        let r = ByteRange::new(ByteOffset::new(7), ByteOffset::new(7)).unwrap();
        assert!(matches!(
            format_range_header(r),
            Err(RangeError::EmptyRange)
        ));
    }

    // ---- parse_content_range ------------------------------------------

    #[test]
    fn parse_content_range_basic() {
        let cr = parse_content_range("bytes 0-99/200").unwrap();
        assert_eq!(cr.first_byte(), 0);
        assert_eq!(cr.last_byte(), 99);
        assert_eq!(cr.total(), Some(200));
        assert_eq!(cr.len(), 100);
    }

    #[test]
    fn parse_content_range_unknown_total() {
        let cr = parse_content_range("bytes 100-199/*").unwrap();
        assert_eq!(cr.first_byte(), 100);
        assert_eq!(cr.last_byte(), 199);
        assert_eq!(cr.total(), None);
    }

    #[test]
    fn parse_content_range_with_extra_whitespace() {
        let cr = parse_content_range("bytes   1024-2047 / 8192").unwrap();
        assert_eq!(cr.first_byte(), 1024);
        assert_eq!(cr.last_byte(), 2047);
        assert_eq!(cr.total(), Some(8192));
    }

    #[test]
    fn parse_content_range_tolerates_equals() {
        // Some servers send "bytes=" (the request syntax) by mistake.
        let cr = parse_content_range("bytes=0-9/10").unwrap();
        assert_eq!(cr.first_byte(), 0);
        assert_eq!(cr.last_byte(), 9);
    }

    #[test]
    fn parse_content_range_rejects_missing_unit() {
        match parse_content_range("0-99/200") {
            Err(RangeError::MissingBytesUnit { value }) => assert_eq!(value, "0-99/200"),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_content_range_rejects_malformed() {
        assert!(matches!(
            parse_content_range("bytes nonsense"),
            Err(RangeError::Malformed { .. })
        ));
        assert!(matches!(
            parse_content_range("bytes 0-/200"),
            Err(RangeError::Malformed { .. })
        ));
        assert!(matches!(
            parse_content_range("bytes 0-9"),
            Err(RangeError::Malformed { .. })
        ));
    }

    #[test]
    fn parse_content_range_rejects_reversed_bounds() {
        match parse_content_range("bytes 200-100/300") {
            Err(RangeError::InvalidBounds { first, last, total }) => {
                assert_eq!(first, 200);
                assert_eq!(last, 100);
                assert_eq!(total, Some(300));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_content_range_rejects_last_at_or_past_total() {
        // last must be < total (since both are 0-indexed, total=10
        // means valid range bytes are 0..=9).
        assert!(matches!(
            parse_content_range("bytes 0-10/10"),
            Err(RangeError::InvalidBounds { .. })
        ));
    }

    // ---- ContentRange conversions ------------------------------------

    #[test]
    fn content_range_to_byte_range_is_half_open() {
        let cr = ContentRange::new(0, 99, Some(200)).unwrap();
        let r = cr.as_byte_range();
        assert_eq!(r.start(), ByteOffset::new(0));
        assert_eq!(r.end_exclusive(), ByteOffset::new(100));
        assert_eq!(r.len(), 100);
    }

    #[test]
    fn content_range_new_validates() {
        assert!(matches!(
            ContentRange::new(50, 10, None),
            Err(RangeError::InvalidBounds { .. })
        ));
        assert!(matches!(
            ContentRange::new(0, 10, Some(10)),
            Err(RangeError::InvalidBounds { .. })
        ));
    }

    #[test]
    fn content_range_display_with_total() {
        let cr = ContentRange::new(0, 99, Some(200)).unwrap();
        assert_eq!(cr.to_string(), "bytes 0-99/200");
    }

    #[test]
    fn content_range_display_without_total() {
        let cr = ContentRange::new(100, 199, None).unwrap();
        assert_eq!(cr.to_string(), "bytes 100-199/*");
    }

    // ---- Round-trip property ------------------------------------------

    /// LCG, identical pattern to the one in `crate::types`. Avoids a
    /// PRNG dependency.
    struct Lcg(u64);
    impl Lcg {
        const fn seeded(seed: u64) -> Self {
            Self(seed ^ 0x9E37_79B9_7F4A_7C15)
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }
    }

    #[test]
    fn property_format_then_parse_round_trips() {
        let mut rng = Lcg::seeded(0xABCD_1234);
        for _ in 0..512 {
            let start = rng.next_u64() % 1_000_000_000;
            let len = (rng.next_u64() % 1_000_000) + 1;
            let total = start
                .saturating_add(len)
                .saturating_add(rng.next_u64() % 1_000_000);

            let r = ByteRange::from_start_len(ByteOffset::new(start), len).expect("len < 1e6");
            let header = format_range_header(r).expect("non-empty");
            // Strip "bytes=" prefix; we can synthesize a Content-Range
            // by appending /total.
            let cr_value = format!("bytes {}/{}", header.strip_prefix("bytes=").unwrap(), total);
            let parsed = parse_content_range(&cr_value).expect("well-formed");
            assert_eq!(parsed.first_byte(), start);
            assert_eq!(parsed.last_byte(), start + len - 1);
            assert_eq!(parsed.total(), Some(total));
            assert_eq!(parsed.as_byte_range(), r);
        }
    }
}
