//! Typed errors for the 7z parser and extraction pipeline.
//!
//! Variants are intentionally specific. The `internal/PLAN_7z_support.md`
//! "the user should see 'AES-256 encryption is not supported', not a
//! generic parse failure" rule motivates [`Self::UnsupportedFeature`]
//! carrying a free-form name; the rest of the variants distinguish
//! recoverable framing trouble ([`Self::Truncated`]) from malformed
//! inputs ([`Self::CorruptHeader`]) and unsupported wire-format
//! versions ([`Self::UnsupportedVersion`]).
//!
//! New variants land alongside the phase that needs them; phases
//! that come later in the plan extend this enum rather than
//! replacing it.

use thiserror::Error;

use crate::encryption::EncryptionError;

/// Errors produced while parsing or extracting a 7z archive.
///
/// Per `internal/ENGINEERING_STANDARDS.md` §3.1 every variant carries
/// enough structured context that the message alone is debuggable.
#[derive(Debug, Error)]
pub enum SevenzError {
    /// A parser ran out of bytes before it could read a field whose
    /// layout requires more. Recoverable iff the caller can fetch
    /// more bytes (the second-pipeline driver does exactly that for
    /// the trailer region).
    #[error("7z parse truncated: needed {needed} more byte(s) for {what}")]
    Truncated {
        /// Human-readable name of the field that overran. Includes
        /// the parser's current expectation (e.g. `"Number high
        /// byte 3"`, `"BoolVector body for 8 bits"`).
        what: String,
        /// How many additional bytes the parser needed beyond the
        /// end of the supplied buffer. Always `≥ 1`.
        needed: usize,
    },

    /// A wire-format parser succeeded structurally but the resulting
    /// value is rejected (e.g. a reserved bit pattern, a length that
    /// would overflow a `u64`, or an internally inconsistent
    /// header). Distinct from [`Self::Truncated`]: the caller
    /// fetching more bytes will not change the outcome.
    #[error("7z corrupt header: {reason}")]
    CorruptHeader {
        /// Human-readable reason.
        reason: String,
    },

    /// A file name in the archive failed UTF-16LE decode or path-
    /// safety validation. Distinct from
    /// [`crate::sink::SinkError::PathEscape`] (which the §7 sink
    /// surfaces): this variant catches the failure at parse time so
    /// the pipeline never plans a download for an entry it would
    /// later reject.
    #[error("7z file name rejected: {reason}")]
    BadName {
        /// Human-readable reason: `"invalid UTF-16LE"`, `"embedded
        /// NUL"`, `"absolute path"`, `"path component '..'"`,
        /// `"empty after sanitization"`, or similar.
        reason: String,
    },

    /// The archive uses a feature this build does not support.
    ///
    /// `feature` is human-readable (e.g. `"BCJ filter"`,
    /// `"AES-256 encryption"`, `"coder id 04 02 02 (BZIP2)"`). The
    /// pipeline surfaces it verbatim so the user sees a specific
    /// message rather than a generic parse failure, per the plan's
    /// `UnsupportedFeature` rule.
    #[error("unsupported 7z feature: {feature}")]
    UnsupportedFeature {
        /// Human-readable feature name.
        feature: String,
    },

    /// The archive's `ArchiveVersion` field disagrees with what
    /// this build accepts. The reference says the only version
    /// in the wild is `0.4`; round-one rejects anything else.
    #[error("unsupported 7z archive version {major}.{minor}")]
    UnsupportedVersion {
        /// `ArchiveVersion.major` byte from the SignatureHeader.
        major: u8,
        /// `ArchiveVersion.minor` byte from the SignatureHeader.
        minor: u8,
    },

    /// Encryption-specific failure: missing password, wrong password,
    /// or integrity-tag / CRC mismatch under a successfully derived
    /// key. The shared [`EncryptionError`] enum
    /// (`internal/PLAN_archive_encryption.md` §6) carries the variant;
    /// this is the 7z-side container.
    #[error("7z encryption: {0}")]
    Encryption(#[source] EncryptionError),
}
