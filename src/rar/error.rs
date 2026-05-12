//! Typed errors for the RAR5 parser and extraction pipeline.
//!
//! Variants are intentionally specific. The `docs/PLAN_rar.md`
//! "users see the specific feature, not 'malformed header'" rule
//! motivates [`Self::UnsupportedFeature`] carrying a free-form name;
//! the rest of the variants distinguish recoverable framing trouble
//! ([`Self::Truncated`]) from malformed inputs
//! ([`Self::CorruptHeader`]) and unsupported wire-format versions
//! ([`Self::UnsupportedFormatVersion`]).
//!
//! New variants land alongside the phase that needs them; phases
//! later in the plan extend this enum rather than replacing it.

use thiserror::Error;

use crate::encryption::EncryptionError;

/// Errors produced while parsing or extracting a RAR5 archive.
///
/// Per `docs/ENGINEERING_BEST_PRACTICES.md` §3.1 every variant
/// carries enough structured context that the message alone is
/// debuggable.
#[derive(Debug, Error)]
pub enum RarError {
    /// The archive's first bytes do not start with the RAR5 magic
    /// (`52 61 72 21 1A 07 01 00`). Distinct from
    /// [`Self::UnsupportedFormatVersion`] (which fires when the
    /// magic *is* a recognized older RAR version).
    #[error(
        "RAR signature mismatch: expected RAR5 magic \
         52 61 72 21 1a 07 01 00 at offset 0"
    )]
    BadSignature,

    /// The archive begins with a recognized RAR magic that is not
    /// RAR5. Round-one supports RAR5 only; the parser surfaces the
    /// detected version so the diagnostic is specific.
    #[error(
        "unsupported RAR format version {major}.{minor}: this build \
         supports RAR5 only (see docs/PLAN_rar.md \"What this plan \
         deliberately does not include\")"
    )]
    UnsupportedFormatVersion {
        /// Major version detected from the magic. RAR4 reports 4.
        major: u8,
        /// Minor version detected from the magic. RAR4 reports 0.
        minor: u8,
    },

    /// A parser ran out of bytes before it could read a field whose
    /// layout requires more. Recoverable iff the caller can fetch
    /// more bytes (the §3 pipeline does exactly that for
    /// not-yet-downloaded ranges).
    #[error("RAR parse truncated: needed {needed} more byte(s) for {what}")]
    Truncated {
        /// Human-readable name of the field that overran. Includes
        /// the parser's current expectation (e.g. `"vint byte 4"`,
        /// `"file header name (24 bytes)"`).
        what: String,
        /// How many additional bytes the parser needed beyond the
        /// end of the supplied buffer. Always `≥ 1`.
        needed: usize,
    },

    /// A wire-format parser succeeded structurally but the resulting
    /// value is rejected (e.g. a vint overflowed `u64`, a header
    /// CRC32 disagreed with the body, or a length field was
    /// internally inconsistent). Distinct from [`Self::Truncated`]:
    /// the caller fetching more bytes will not change the outcome.
    #[error("RAR corrupt header at archive offset {archive_offset}: {reason}")]
    CorruptHeader {
        /// Byte offset within the archive where the failing header
        /// begins.
        archive_offset: u64,
        /// Human-readable reason; includes field name where useful.
        reason: String,
    },

    /// Header CRC32 in a generic-header prologue did not match the
    /// CRC32 the parser computed over the rest of the header.
    /// Distinct from [`Self::CorruptHeader`]: the structural parse
    /// succeeded; the integrity check did not.
    #[error(
        "RAR header CRC32 mismatch at archive offset {archive_offset}: \
         expected {expected:#010x}, computed {computed:#010x}"
    )]
    HeaderCrc32Mismatch {
        /// Byte offset within the archive where the failing header
        /// begins.
        archive_offset: u64,
        /// CRC32 the header recorded for itself.
        expected: u32,
        /// CRC32 the parser computed over the header body.
        computed: u32,
    },

    /// Header CRC-16 in a legacy (RAR3/RAR4) base-block header did
    /// not match the CRC-16 the parser computed over the rest of the
    /// header. RAR3/4 stores the low 16 bits of the IEEE CRC-32 over
    /// the bytes from `head_type` onward; see
    /// [`crate::rar::legacy::format`] for the layout. Structural
    /// counterpart to [`Self::HeaderCrc32Mismatch`].
    #[error(
        "RAR legacy header CRC-16 mismatch at archive offset {archive_offset}: \
         expected {expected:#06x}, computed {computed:#06x}"
    )]
    HeaderCrc16Mismatch {
        /// Byte offset within the archive where the failing header
        /// begins (the offset of the `head_crc` field).
        archive_offset: u64,
        /// CRC-16 the header recorded for itself.
        expected: u16,
        /// CRC-16 the parser computed over the header body.
        computed: u16,
    },

    /// A file name in the archive failed UTF-8 decode or path-safety
    /// validation. Caught at parse time so the pipeline never plans
    /// a download for an entry it would later reject.
    #[error("RAR file name rejected: {reason}")]
    BadName {
        /// Human-readable reason: `"invalid UTF-8"`, `"embedded NUL"`,
        /// `"absolute path"`, `"path component '..'"`,
        /// `"empty after sanitization"`, or similar.
        reason: String,
    },

    /// The archive uses a feature this build does not support.
    ///
    /// `feature` is human-readable (e.g. `"multi-volume archive
    /// (volume 3)"`, `"encryption (header)"`, `"compression method 1
    /// (RAR5 standard algorithm)"`). The pipeline surfaces it
    /// verbatim so the user sees a specific message rather than a
    /// generic parse failure, per the plan's `UnsupportedFeature`
    /// rule.
    #[error("unsupported RAR feature: {feature}")]
    UnsupportedFeature {
        /// Human-readable feature name.
        feature: String,
    },

    /// BLAKE2sp / CRC32 of a decompressed entry did not match the
    /// value recorded in the file header. Lands in §3 / §4.
    #[error(
        "RAR integrity hash mismatch for entry {entry_name:?}: {hash} \
         expected {expected}, computed {computed}"
    )]
    HashMismatch {
        /// The entry whose hash failed.
        entry_name: String,
        /// Hash kind (`"BLAKE2sp"` or `"CRC32"`).
        hash: &'static str,
        /// Hash the file header recorded, hex-encoded.
        expected: String,
        /// Hash the extractor computed over the decompressed bytes,
        /// hex-encoded.
        computed: String,
    },

    /// Encryption-specific failure: missing password, wrong password,
    /// or integrity-tag mismatch under a successfully derived key.
    /// The shared [`EncryptionError`] enum
    /// (`docs/PLAN_archive_encryption.md` §6) carries the variant;
    /// this is the rar-side container.
    #[error("RAR encryption: {0}")]
    Encryption(#[source] EncryptionError),

    /// The supplied set of volume buffers does not match the
    /// multi-volume archive's declared shape — either a volume past
    /// the end of the supplied set carries the end-of-archive
    /// `more_volumes` flag (caller did not supply enough volumes),
    /// or an end-of-archive marker without `more_volumes` was
    /// observed before all supplied volumes were consumed (caller
    /// supplied extra volumes). Distinct from [`Self::CorruptHeader`]:
    /// every individual volume parses cleanly; the mismatch is
    /// between volumes.
    #[error("RAR volume-set mismatch: {detail}")]
    VolumeSetMismatch {
        /// Human-readable detail naming the affected volume and the
        /// nature of the mismatch.
        detail: String,
    },
}
