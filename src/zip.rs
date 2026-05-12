//! ZIP archive support.
//!
//! Unlike the streaming formats handled by [`crate::decode`], ZIP's
//! central directory lives at the *end* of the archive — so extraction
//! cannot start until the trailing region has been downloaded, and
//! per-entry compressed data is pulled by ranged GET against offsets
//! recorded in the central directory. `docs/PLAN_v2.md` §5 calls this
//! out as a "second pipeline architecture" and motivates the layout
//! split below.
//!
//! Pieces in this module:
//!
//! - [`format`] — pure wire-format parsers (EOCD, central-directory
//!   entries, local file headers). Hand-rolled to mirror the
//!   tar-parser precedent in [`crate::sink::tar`] (`docs/PLAN.md`
//!   §7.3): the format is small enough that the audit story benefits
//!   from byte-for-byte visibility, and the upstream `zip` crate
//!   does not expose the per-entry boundary semantics our extractor
//!   needs.
//!
//! Subsequent commits add `sink` (the per-entry [`crate::sink::Sink`]),
//! `decode` (the STORED/DEFLATE/zstd dispatcher), and `pipeline` (the
//! per-entry download driver).
//!
//! # Round-one scope (`docs/PLAN_v2.md` §5, locked 2026-04-29)
//!
//! Supported:
//!
//! - Compression methods **STORED (0)**, **DEFLATE (8)**, **zstd (93)**.
//! - Single-disk archives.
//! - Optional data descriptor (general-purpose flag bit 3 set, sizes
//!   in the LFH zeroed; the central directory carries the authoritative
//!   values).
//!
//! Out of scope (filed as `O.8b` in `docs/OPTIMIZATIONS.md`):
//!
//! - AES, traditional PKWARE, and any other encryption (general-purpose
//!   flag bit 0 or bit 6).
//! - Zip64 — sizes ≥ 4 GiB or entry count ≥ 65535.
//! - Multi-disk / spanned archives (`disk_start != 0`).
//! - Compression methods other than the three listed above.
//!
//! Encountering an out-of-scope feature returns a clean
//! [`ZipError::UnsupportedFeature`] naming the specific feature, per
//! the plan's "the user should see 'AES encryption is not supported',
//! not 'malformed header'" guideline.

pub mod aes_decrypt;
pub mod crc32;
pub mod decode;
pub mod encrypt_legacy;
pub mod format;

pub use aes_decrypt::AesDecryptReader;
pub use crc32::{ieee, Crc32};
pub use decode::{decompress_entry, EntryDecodeError, COPY_BUFFER_LEN};
pub use encrypt_legacy::ZipCryptoReader;
pub use format::{
    find_aes_extra, find_eocd, parse_central_directory, AesExtra, AesStrength, AesVersion,
    CentralDirectoryEntry, CompressionMethod, EndOfCentralDirectory, GeneralPurposeFlags,
    LocalFileHeader, AES_EXTRA_HEADER_ID, MAX_EOCD_TAIL_BYTES, METHOD_CODE_AES_MARKER,
    SIGNATURE_CDE, SIGNATURE_DATA_DESCRIPTOR, SIGNATURE_EOCD, SIGNATURE_LFH,
};

use std::io::Read;

use thiserror::Error;

use crate::decode::{DecodeError, StreamingDecoder};

/// Format name [`crate::decode::DecoderRegistry::with_defaults`]
/// registers ZIP under. The coordinator looks up this exact string
/// (case-insensitive) when deciding whether to dispatch a run to
/// [`crate::download::zip_pipeline`] instead of the streaming
/// decoder loop.
pub const FORMAT_NAME: &str = "zip";

/// Sentinel [`crate::decode::DecoderFactory`] registered for the
/// [`FORMAT_NAME`] format.
///
/// ZIP archives go through [`crate::download::zip_pipeline`], not
/// the streaming-decoder loop, so this factory is **never invoked
/// in normal operation**. It exists so the standard
/// [`crate::decode::DecoderRegistry`] machinery (suffix matching,
/// magic-byte sniffing, `--format <name>` override, format-mismatch
/// detection) resolves `.zip` URLs the same way it resolves any
/// other format. The coordinator pre-checks the resolved name
/// against [`FORMAT_NAME`] and dispatches before invoking the
/// factory; this body is reached only by a programming error
/// (caller used [`crate::decode::DecoderRegistry`] outside the
/// coordinator path) and surfaces a clear diagnostic.
///
/// # Errors
///
/// Always returns [`DecodeError::Construct`] with an explanatory
/// message.
pub fn streaming_factory_placeholder(
    _src: Box<dyn Read + Send>,
) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    Err(DecodeError::Construct(std::io::Error::other(
        "internal error: ZIP factory invoked instead of dispatching to the ZIP pipeline",
    )))
}

/// Errors produced while parsing or extracting a ZIP archive.
///
/// Variants are intentionally specific. The pipeline distinguishes:
///
/// - **Recoverable framing trouble** ([`Self::EocdNotFound`]): the
///   caller can fetch a wider tail window and retry.
/// - **Hard refusals** ([`Self::UnsupportedFeature`]): the archive is
///   well-formed but uses something this build does not implement; the
///   user sees the specific feature name (e.g. "AES encryption" or
///   "Zip64"), not a generic parse failure.
/// - **Bug-level wire-format failures** ([`Self::BadSignature`],
///   [`Self::MalformedHeader`], [`Self::Truncated`],
///   [`Self::LfhCdMismatch`]): the bytes do not satisfy the PKWARE
///   APPNOTE at all; the message includes the failing offset.
/// - **Integrity failures** ([`Self::Crc32Mismatch`]): the archive
///   parses but a per-entry CRC32 over decompressed bytes does not
///   match the one the central directory recorded.
///
/// Per `docs/ENGINEERING_BEST_PRACTICES.md` §3.1 every variant carries
/// enough structured context that the message alone is debuggable.
#[derive(Debug, Error)]
pub enum ZipError {
    /// A 4-byte signature header had an unexpected value.
    #[error(
        "ZIP signature mismatch at archive offset {archive_offset}: \
         expected {expected:#010x}, found {found:#010x}"
    )]
    BadSignature {
        /// Byte offset within the archive where the header begins.
        archive_offset: u64,
        /// The signature the parser was looking for.
        expected: u32,
        /// The signature it actually saw.
        found: u32,
    },

    /// A header parsed cleanly up to the signature but a subsequent
    /// field had an out-of-range or otherwise impossible value.
    #[error("malformed ZIP header at archive offset {archive_offset}: {reason}")]
    MalformedHeader {
        /// Byte offset within the archive where the failing header
        /// begins.
        archive_offset: u64,
        /// Human-readable reason; includes field name where useful.
        reason: String,
    },

    /// A buffer handed to a parser was shorter than the field layout
    /// requires. Recoverable iff the caller can fetch more bytes.
    #[error("ZIP parse truncated: {reason}")]
    Truncated {
        /// Human-readable detail naming the field that overran.
        reason: String,
    },

    /// The central-directory entry and the corresponding local-file
    /// header disagree about a field that must match (e.g. compression
    /// method or filename).
    #[error(
        "ZIP local-file-header / central-directory mismatch for entry \
         {entry_name:?}: field {field} = {lfh} (LFH) vs {cd} (CD)"
    )]
    LfhCdMismatch {
        /// Filename of the entry, taken from the central directory.
        entry_name: String,
        /// Name of the field that disagrees.
        field: &'static str,
        /// Value the local file header recorded.
        lfh: u64,
        /// Value the central directory recorded.
        cd: u64,
    },

    /// The trailing region we searched did not contain an
    /// `0x06054b50` end-of-central-directory signature.
    #[error(
        "ZIP end-of-central-directory not found in the last {window} bytes; \
         retry with a larger trailing window or the archive is malformed"
    )]
    EocdNotFound {
        /// Number of bytes searched.
        window: u64,
    },

    /// The archive uses a feature this build does not support.
    ///
    /// `feature` is human-readable (e.g. "AES encryption", "Zip64
    /// end-of-central-directory locator", "compression method 14
    /// (LZMA)"); the pipeline surfaces it verbatim so the user sees a
    /// specific message rather than "malformed header".
    #[error("unsupported ZIP feature: {feature}")]
    UnsupportedFeature {
        /// Human-readable feature name. The convention is "what",
        /// then "(why we know)" — e.g. "compression method 14 (LZMA)".
        feature: String,
    },

    /// CRC-32 of a decompressed entry did not match the value recorded
    /// in the central directory.
    #[error(
        "CRC-32 mismatch for entry {entry_name:?}: expected {expected:#010x}, \
         computed {computed:#010x}"
    )]
    Crc32Mismatch {
        /// The entry whose CRC failed.
        entry_name: String,
        /// CRC-32 the central directory recorded.
        expected: u32,
        /// CRC-32 the extractor computed over the decompressed bytes.
        computed: u32,
    },

    /// Encryption-specific failure: missing password, wrong password,
    /// or HMAC integrity-tag mismatch. The plan's §6 calls for a
    /// shared `EncryptionError` enum across the three encrypted
    /// formats; this variant is the zip-side container.
    #[error("ZIP encryption: {0}")]
    Encryption(#[source] EncryptionError),
}

/// Encryption-layer failures surfaced through
/// [`ZipError::Encryption`] (and, once §4 / §5 of
/// `docs/PLAN_archive_encryption.md` land, through `RarError` /
/// `SevenZError` too).
///
/// Variants are deliberately small. The CLI maps each one to a
/// dedicated exit code in §6; until then the binary maps the whole
/// `Encryption` arm to its generic "extraction failed" code.
#[derive(Debug, Clone, Error)]
pub enum EncryptionError {
    /// The archive declares an encrypted entry but the user did not
    /// supply a password (no `--password-from`). The CLI shouldn't
    /// land here in practice because it offers `prompt` as the
    /// default for encrypted archives, but library callers may.
    #[error(
        "archive contains an encrypted entry but no password source was configured \
         (pass --password-from <SOURCE>)"
    )]
    PasswordMissing,

    /// The user-supplied password did not match the archive's
    /// password-verifier (or, when no verifier exists, the integrity
    /// check failed in a way that strongly suggests the wrong
    /// password). The CLI re-prompts on interactive sources.
    #[error("password did not match the archive's stored verifier")]
    PasswordIncorrect,

    /// The HMAC / integrity-tag check failed *after* the password
    /// matched its verifier — the archive itself is corrupt or
    /// tampered. Distinct from [`Self::PasswordIncorrect`] so the
    /// user knows retrying with the same password won't help.
    #[error(
        "integrity check failed for entry {entry_name:?} (HMAC mismatch — \
         archive may be corrupt or tampered)"
    )]
    IntegrityCheckFailed {
        /// The entry whose integrity tag failed.
        entry_name: String,
    },

    /// The archive uses an encryption scheme this build does not
    /// support (e.g. the legacy PKWARE "ZipCrypto" before §3b lands,
    /// or an unknown AES strength). The message is verbatim from
    /// the format-specific parser.
    #[error("unsupported encryption scheme: {detail}")]
    Unsupported {
        /// Human-readable detail.
        detail: String,
    },
}
