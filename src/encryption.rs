//! Format-agnostic encryption-layer error type
//! (`docs/PLAN_archive_encryption.md` §6).
//!
//! Every encrypted archive format peel supports (ZIP-AES, ZipCrypto,
//! RAR5, 7z) surfaces decryption failures through the same enum so
//! the CLI / library callers can pattern-match once instead of three
//! times. Format-specific error types (`zip::ZipError`,
//! `rar::RarError`, `sevenz::SevenzError`) each carry a
//! `Encryption(EncryptionError)` variant; the CLI binary maps
//! [`EncryptionError::PasswordIncorrect`] to exit code 4 so scripts
//! can distinguish "wrong password" from "extraction failed".
//!
//! # Why a single enum
//!
//! The four supported encryption schemes share a small set of failure
//! modes:
//!
//! - **Missing password** — the archive needs one and the user didn't
//!   supply a `--password-from <SOURCE>`. The CLI offers `prompt` as
//!   the default when an encrypted entry is encountered, but library
//!   callers may not, so this stays a first-class variant.
//! - **Wrong password** — the password didn't match the archive's
//!   stored verifier (PBKDF2-derived 2-byte verifier for ZIP-AES,
//!   CRC32 high byte for ZipCrypto, truncated HMAC-SHA256 of a known
//!   constant for RAR5; 7z lacks a verifier so its CRC32 mismatch on
//!   the first decompressed entry surfaces this).
//! - **Integrity check failed** — the password matched but the
//!   authenticated-encryption tag did not (HMAC-SHA1-80 trailer for
//!   ZIP-AES, BLAKE2sp hash mismatch for RAR5 file data, CRC32
//!   mismatch after decompression for the formats that lack a
//!   stronger auth tag).
//! - **Unsupported cipher / KDF** — the archive declares an encryption
//!   scheme this build doesn't implement (e.g. the PKWARE strong
//!   encryption central-directory variant, or a 7z coder ID we don't
//!   recognise).
//!
//! Per-variant `entry_name` / `detail` fields preserve the format-
//! specific context the user needs to debug the failure.

use thiserror::Error;

/// Encryption-layer failures shared by every encrypted-archive format.
///
/// See the module-level documentation for the threat-model rationale.
/// `Clone` is implemented because format-specific error wrappers
/// (e.g. `ZipError::Encryption`) sometimes re-wrap a borrowed
/// reference and need to take ownership.
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

    /// The archive uses a key-derivation function this build does not
    /// support (e.g. a RAR5 iteration count outside the spec's range,
    /// or a 7z `power` parameter we refuse to accept).
    #[error("unsupported encryption KDF: {detail}")]
    UnsupportedKdf {
        /// Human-readable detail.
        detail: String,
    },

    /// The archive uses a cipher this build does not support (e.g. an
    /// AES strength we don't recognise, or a 7z encryption coder ID
    /// outside the round-one set).
    #[error("unsupported encryption cipher: {detail}")]
    UnsupportedCipher {
        /// Human-readable detail.
        detail: String,
    },
}
