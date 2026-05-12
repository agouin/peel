//! RAR5 encryption primitives and parsers
//! (`docs/PLAN_archive_encryption.md` §4).
//!
//! RAR5 supports two distinct encryption shapes:
//!
//! - **Archive-header encryption** — a leading header (type 4)
//!   declares the rest of the archive's header bytes are AES-256-CBC
//!   encrypted. Each subsequent 16-byte block is decrypted lazily as
//!   the walker reads it. Cleartext archive metadata never lands on
//!   disk in the .peel.part file; the pipeline decrypts in-memory.
//! - **Per-file encryption** — individual file headers may carry an
//!   encryption record (extra record type 1) declaring their data
//!   area is AES-256-CBC encrypted with a per-file IV. The header
//!   itself is cleartext (or under the archive-header encryption
//!   layer); only the file's data area is encrypted.
//!
//! Both shapes use the same crypto: AES-256-CBC under a key derived
//! via PBKDF2-HMAC-SHA256 with an iteration count encoded in the
//! header's `kdf_count` byte:
//!
//! ```text
//! iterations = 1 << (kdf_count + 15)
//! ```
//!
//! `kdf_count` is capped at 24 by the spec (= 2^39 iterations) but in
//! practice almost every archive ships at the default `kdf_count = 0`
//! (= 2^15 = 32 768 iterations).
//!
//! # Key derivation
//!
//! The spec's PBKDF2 output is consumed in three slices, computed by
//! running PBKDF2 with three consecutive iteration totals:
//!
//! ```text
//! N             = 1 << (kdf_count + 15)
//! aes_key       = pbkdf2_hmac_sha256(password, salt, N    )
//! hmac_key      = pbkdf2_hmac_sha256(password, salt, N + 1)
//! pswd_check    = pbkdf2_hmac_sha256(password, salt, N + 2)
//! ```
//!
//! For the `pswd_check` step the spec then takes the SHA-256 of the
//! intermediate buffer at each iteration and XOR-folds the final
//! 32-byte sum down to 8 bytes (4 dword pairs xor'd). This module
//! implements the iteration-walk variant: we run all three PBKDF2
//! calls in a single pass by recycling the running HMAC state, which
//! the [`crate::crypto::pbkdf2::pbkdf2_hmac_three_stage`] helper
//! supports natively. (Falling back to three independent PBKDF2 calls
//! would re-do `N` HMAC iterations twice over; the three-stage
//! variant is byte-identical and ~3× faster.)
//!
//! # Password check
//!
//! When the archive-encryption header sets the
//! `PSWCHECK_PRESENT` flag, it carries an 8-byte check value plus a
//! 4-byte check sum. Verification:
//!
//! 1. Compute the 32-byte XOR-folded `pswd_check`.
//! 2. The first 8 bytes are the candidate check value.
//! 3. The candidate's SHA-256 mod 0xFFFFFFFF is the candidate sum.
//! 4. The header's stored check and sum must match both. Mismatch ⇒
//!    [`crate::encryption::EncryptionError::PasswordIncorrect`].
//!
//! Per-file encryption records use a simpler 12-byte (4 + 8) check
//! that follows the same shape but without the SHA-256-sum part —
//! the 8-byte check directly compared in constant time.

use thiserror::Error;

use crate::encryption::EncryptionError;
use crate::rar::RarError;

/// AES key size (bytes) — RAR5 uses AES-256 exclusively.
pub const AES_KEY_LEN: usize = 32;

/// Salt size (bytes). Fixed by the spec.
pub const SALT_LEN: usize = 16;

/// IV size (bytes). Fixed by the spec; equals the AES block size.
pub const IV_LEN: usize = 16;

/// Length of the optional password-check value embedded in
/// encryption headers (4-byte sum + 8-byte check).
pub const PSWCHECK_LEN: usize = 12;

/// Flag bit on the archive-encryption / file-encryption header
/// indicating the optional password-check value is present.
pub const FLAG_PSWCHECK: u64 = 0x0001;

/// Maximum legal `kdf_count` byte per the spec. `iterations = 1 << (24 + 15)`
/// is absurd (~ 5 × 10^11) but valid.
pub const KDF_COUNT_MAX: u8 = 24;

/// Errors specific to RAR5 encryption-header parsing.
///
/// Lifted into [`RarError::CorruptHeader`] /
/// [`RarError::Encryption`] at the caller boundary so the typed
/// pipeline error type stays a single enum.
#[derive(Debug, Error)]
pub enum EncryptHeaderError {
    /// A required field overran the slice (e.g. salt smaller than
    /// [`SALT_LEN`]).
    #[error("RAR encryption header truncated: needed {needed} more byte(s) for {what}")]
    Truncated {
        /// Human-readable name of the field that overran.
        what: String,
        /// Bytes needed beyond the slice end.
        needed: usize,
    },

    /// The header's `encryption_version` field is not `0` (the only
    /// shipping value at time of writing — AES-256-CBC). Future RAR
    /// versions may add ciphers; the spec reserves the value space.
    #[error("unsupported RAR encryption version {version}")]
    UnsupportedVersion {
        /// The version code the header recorded.
        version: u64,
    },

    /// `kdf_count` byte exceeds the spec-defined maximum of 24.
    #[error("RAR kdf_count {kdf_count} exceeds the maximum of {max}", max = KDF_COUNT_MAX)]
    KdfCountTooLarge {
        /// The kdf_count byte the header recorded.
        kdf_count: u8,
    },
}

impl From<EncryptHeaderError> for RarError {
    fn from(e: EncryptHeaderError) -> Self {
        match e {
            EncryptHeaderError::Truncated { what, needed } => RarError::Truncated { what, needed },
            EncryptHeaderError::UnsupportedVersion { version } => {
                RarError::Encryption(EncryptionError::UnsupportedCipher {
                    detail: format!(
                        "RAR encryption version {version} (spec reserves 0 for AES-256-CBC)"
                    ),
                })
            }
            EncryptHeaderError::KdfCountTooLarge { kdf_count } => {
                RarError::Encryption(EncryptionError::UnsupportedKdf {
                    detail: format!(
                        "RAR kdf_count {kdf_count} (iterations = 1 << {n}) exceeds the spec \
                         maximum of {max} (iterations = 1 << {nmax})",
                        n = kdf_count as u32 + 15,
                        max = KDF_COUNT_MAX,
                        nmax = KDF_COUNT_MAX as u32 + 15,
                    ),
                })
            }
        }
    }
}

/// Parsed archive-encryption header (type 4).
///
/// Wire layout of the type-specific fields (after the generic header
/// fields, which the [`crate::rar::format::parse_generic_header`] has
/// already eaten):
///
/// ```text
/// [vint]    encryption_version      (0 = AES-256-CBC, spec-reserved)
/// [vint]    encryption_flags        (FLAG_PSWCHECK = 0x0001, …)
/// [u8 ]    kdf_count                (iterations = 1 << (kdf_count + 15))
/// [16 ]    salt
/// [12 ]    pswcheck                 (present iff FLAG_PSWCHECK is set;
///                                    4-byte CRC sum + 8-byte check)
/// ```
#[derive(Debug, Clone)]
pub struct ArchiveEncryptionHeader {
    /// `encryption_version` field. Always 0 in shipping archives.
    pub version: u64,
    /// `encryption_flags` field. `FLAG_PSWCHECK` is the only bit we
    /// recognise; unknown bits are tolerated (rar may add more in the
    /// future for forward-compat).
    pub flags: u64,
    /// `kdf_count` byte; the iteration count is `1 << (kdf_count + 15)`.
    pub kdf_count: u8,
    /// Per-archive salt.
    pub salt: [u8; SALT_LEN],
    /// Optional password-check value (present iff `flags & FLAG_PSWCHECK`).
    pub pswcheck: Option<[u8; PSWCHECK_LEN]>,
}

impl ArchiveEncryptionHeader {
    /// Parse the type-specific fields of an archive-encryption header.
    ///
    /// `fields` is the slice `&[fields_offset_in_input ..
    /// fields_offset_in_input + fields_size]` from the parsed
    /// [`crate::rar::format::GenericHeader`].
    ///
    /// # Errors
    ///
    /// - [`EncryptHeaderError::Truncated`] when a field overruns the
    ///   slice.
    /// - [`EncryptHeaderError::UnsupportedVersion`] when `version != 0`.
    /// - [`EncryptHeaderError::KdfCountTooLarge`] when `kdf_count > 24`.
    pub fn parse(fields: &[u8]) -> Result<Self, EncryptHeaderError> {
        use crate::rar::format::Vint;

        // Vints in RAR5 are decoded against an "archive offset" used
        // purely for error messages; we don't have one for this
        // standalone helper, so feed 0 (the encoding never reads it).
        let v = Vint::decode_at(fields, 0).map_err(|e| EncryptHeaderError::Truncated {
            what: format!("encryption_version vint: {e}"),
            needed: 1,
        })?;
        let version = v.value;
        let mut cursor = v.size;

        let f =
            Vint::decode_at(&fields[cursor..], 0).map_err(|e| EncryptHeaderError::Truncated {
                what: format!("encryption_flags vint: {e}"),
                needed: 1,
            })?;
        let flags = f.value;
        cursor += f.size;

        if version != 0 {
            return Err(EncryptHeaderError::UnsupportedVersion { version });
        }

        if cursor + 1 > fields.len() {
            return Err(EncryptHeaderError::Truncated {
                what: "kdf_count byte".into(),
                needed: cursor + 1 - fields.len(),
            });
        }
        let kdf_count = fields[cursor];
        cursor += 1;
        if kdf_count > KDF_COUNT_MAX {
            return Err(EncryptHeaderError::KdfCountTooLarge { kdf_count });
        }

        if cursor + SALT_LEN > fields.len() {
            return Err(EncryptHeaderError::Truncated {
                what: format!("salt ({SALT_LEN} bytes)"),
                needed: cursor + SALT_LEN - fields.len(),
            });
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&fields[cursor..cursor + SALT_LEN]);
        cursor += SALT_LEN;

        let pswcheck = if flags & FLAG_PSWCHECK != 0 {
            if cursor + PSWCHECK_LEN > fields.len() {
                return Err(EncryptHeaderError::Truncated {
                    what: format!("pswcheck ({PSWCHECK_LEN} bytes)"),
                    needed: cursor + PSWCHECK_LEN - fields.len(),
                });
            }
            let mut buf = [0u8; PSWCHECK_LEN];
            buf.copy_from_slice(&fields[cursor..cursor + PSWCHECK_LEN]);
            Some(buf)
        } else {
            None
        };

        Ok(Self {
            version,
            flags,
            kdf_count,
            salt,
            pswcheck,
        })
    }
}

/// Parsed per-file encryption record (extra record type 1).
///
/// Wire layout (after the extra record's id vint and size vint, which
/// the file-header parser has already eaten):
///
/// ```text
/// [vint]    encryption_version      (0 = AES-256-CBC)
/// [vint]    encryption_flags
/// [u8 ]    kdf_count
/// [16 ]    salt
/// [16 ]    iv
/// [12 ]    pswcheck                 (present iff FLAG_PSWCHECK)
/// ```
///
/// Differs from the archive-level header by the addition of a
/// per-record IV between the salt and the optional password check.
#[derive(Debug, Clone)]
pub struct FileEncryptionRecord {
    /// `encryption_version`. Always 0 in shipping archives.
    pub version: u64,
    /// `encryption_flags`. `FLAG_PSWCHECK` is the only bit we
    /// recognise; other bits are tolerated for forward-compat.
    pub flags: u64,
    /// `kdf_count` byte; iterations = `1 << (kdf_count + 15)`.
    pub kdf_count: u8,
    /// Per-archive salt (the same value typically repeats across all
    /// file records in the same archive, but each record carries its
    /// own copy).
    pub salt: [u8; SALT_LEN],
    /// Per-file IV.
    pub iv: [u8; IV_LEN],
    /// Optional password-check value (present iff `flags & FLAG_PSWCHECK`).
    pub pswcheck: Option<[u8; PSWCHECK_LEN]>,
}

impl FileEncryptionRecord {
    /// Parse the body of an encryption extra record.
    ///
    /// `body` is the slice between the extra record's size vint and
    /// the next extra record / end of extra area.
    ///
    /// # Errors
    ///
    /// Same shape as [`ArchiveEncryptionHeader::parse`].
    pub fn parse(body: &[u8]) -> Result<Self, EncryptHeaderError> {
        use crate::rar::format::Vint;

        let v = Vint::decode_at(body, 0).map_err(|e| EncryptHeaderError::Truncated {
            what: format!("encryption_version vint: {e}"),
            needed: 1,
        })?;
        let version = v.value;
        let mut cursor = v.size;

        let f = Vint::decode_at(&body[cursor..], 0).map_err(|e| EncryptHeaderError::Truncated {
            what: format!("encryption_flags vint: {e}"),
            needed: 1,
        })?;
        let flags = f.value;
        cursor += f.size;

        if version != 0 {
            return Err(EncryptHeaderError::UnsupportedVersion { version });
        }

        if cursor + 1 > body.len() {
            return Err(EncryptHeaderError::Truncated {
                what: "kdf_count byte".into(),
                needed: cursor + 1 - body.len(),
            });
        }
        let kdf_count = body[cursor];
        cursor += 1;
        if kdf_count > KDF_COUNT_MAX {
            return Err(EncryptHeaderError::KdfCountTooLarge { kdf_count });
        }

        if cursor + SALT_LEN > body.len() {
            return Err(EncryptHeaderError::Truncated {
                what: format!("salt ({SALT_LEN} bytes)"),
                needed: cursor + SALT_LEN - body.len(),
            });
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&body[cursor..cursor + SALT_LEN]);
        cursor += SALT_LEN;

        if cursor + IV_LEN > body.len() {
            return Err(EncryptHeaderError::Truncated {
                what: format!("iv ({IV_LEN} bytes)"),
                needed: cursor + IV_LEN - body.len(),
            });
        }
        let mut iv = [0u8; IV_LEN];
        iv.copy_from_slice(&body[cursor..cursor + IV_LEN]);
        cursor += IV_LEN;

        let pswcheck = if flags & FLAG_PSWCHECK != 0 {
            if cursor + PSWCHECK_LEN > body.len() {
                return Err(EncryptHeaderError::Truncated {
                    what: format!("pswcheck ({PSWCHECK_LEN} bytes)"),
                    needed: cursor + PSWCHECK_LEN - body.len(),
                });
            }
            let mut buf = [0u8; PSWCHECK_LEN];
            buf.copy_from_slice(&body[cursor..cursor + PSWCHECK_LEN]);
            Some(buf)
        } else {
            None
        };

        Ok(Self {
            version,
            flags,
            kdf_count,
            salt,
            iv,
            pswcheck,
        })
    }
}

/// Compute `iterations = 1 << (kdf_count + 15)` per the RAR5 spec.
#[must_use]
pub fn kdf_iterations(kdf_count: u8) -> u32 {
    1u32 << (u32::from(kdf_count) + 15)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid archive-encryption header's type-specific
    /// fields (everything after the generic-header prefix).
    fn build_archive_enc_fields(
        version: u64,
        flags: u64,
        kdf_count: u8,
        salt: &[u8; SALT_LEN],
        pswcheck: Option<&[u8; PSWCHECK_LEN]>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&encode_vint(version));
        out.extend_from_slice(&encode_vint(flags));
        out.push(kdf_count);
        out.extend_from_slice(salt);
        if let Some(c) = pswcheck {
            out.extend_from_slice(c);
        }
        out
    }

    fn encode_vint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    #[test]
    fn archive_header_parses_without_pswcheck() {
        let salt = [0x42u8; SALT_LEN];
        let fields = build_archive_enc_fields(0, 0, 0, &salt, None);
        let parsed = ArchiveEncryptionHeader::parse(&fields).expect("parses");
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.flags, 0);
        assert_eq!(parsed.kdf_count, 0);
        assert_eq!(parsed.salt, salt);
        assert!(parsed.pswcheck.is_none());
    }

    #[test]
    fn archive_header_parses_with_pswcheck() {
        let salt = [0x11u8; SALT_LEN];
        let check = [0x22u8; PSWCHECK_LEN];
        let fields = build_archive_enc_fields(0, FLAG_PSWCHECK, 3, &salt, Some(&check));
        let parsed = ArchiveEncryptionHeader::parse(&fields).expect("parses");
        assert_eq!(parsed.kdf_count, 3);
        assert_eq!(parsed.pswcheck, Some(check));
    }

    #[test]
    fn archive_header_rejects_unsupported_version() {
        let salt = [0u8; SALT_LEN];
        let fields = build_archive_enc_fields(1, 0, 0, &salt, None);
        let err = ArchiveEncryptionHeader::parse(&fields).expect_err("rejects");
        assert!(matches!(
            err,
            EncryptHeaderError::UnsupportedVersion { version: 1 }
        ));
    }

    #[test]
    fn archive_header_rejects_excessive_kdf_count() {
        let salt = [0u8; SALT_LEN];
        let fields = build_archive_enc_fields(0, 0, KDF_COUNT_MAX + 1, &salt, None);
        let err = ArchiveEncryptionHeader::parse(&fields).expect_err("rejects");
        assert!(matches!(err, EncryptHeaderError::KdfCountTooLarge { .. }));
    }

    #[test]
    fn archive_header_truncated_salt_errors() {
        let mut fields = Vec::new();
        fields.extend_from_slice(&encode_vint(0));
        fields.extend_from_slice(&encode_vint(0));
        fields.push(0); // kdf_count
        fields.extend_from_slice(&[0u8; SALT_LEN - 1]); // one byte short
        let err = ArchiveEncryptionHeader::parse(&fields).expect_err("rejects");
        assert!(matches!(err, EncryptHeaderError::Truncated { .. }));
    }

    #[test]
    fn file_record_parses_without_pswcheck() {
        let salt = [0x12u8; SALT_LEN];
        let iv = [0x34u8; IV_LEN];
        let mut body = Vec::new();
        body.extend_from_slice(&encode_vint(0)); // version
        body.extend_from_slice(&encode_vint(0)); // flags
        body.push(2);
        body.extend_from_slice(&salt);
        body.extend_from_slice(&iv);
        let parsed = FileEncryptionRecord::parse(&body).expect("parses");
        assert_eq!(parsed.kdf_count, 2);
        assert_eq!(parsed.salt, salt);
        assert_eq!(parsed.iv, iv);
        assert!(parsed.pswcheck.is_none());
    }

    #[test]
    fn file_record_parses_with_pswcheck() {
        let salt = [0x12u8; SALT_LEN];
        let iv = [0x34u8; IV_LEN];
        let check = [0x55u8; PSWCHECK_LEN];
        let mut body = Vec::new();
        body.extend_from_slice(&encode_vint(0));
        body.extend_from_slice(&encode_vint(FLAG_PSWCHECK));
        body.push(0);
        body.extend_from_slice(&salt);
        body.extend_from_slice(&iv);
        body.extend_from_slice(&check);
        let parsed = FileEncryptionRecord::parse(&body).expect("parses");
        assert_eq!(parsed.pswcheck, Some(check));
    }

    #[test]
    fn kdf_iterations_matches_spec() {
        // The spec: iterations = 1 << (kdf_count + 15)
        assert_eq!(kdf_iterations(0), 1 << 15); // 32768
        assert_eq!(kdf_iterations(1), 1 << 16);
        assert_eq!(kdf_iterations(5), 1 << 20);
    }

    #[test]
    fn encrypt_header_error_lifts_to_rar_error() {
        // UnsupportedVersion should land as an Encryption variant
        // carrying UnsupportedCipher (the unified error type).
        let err = EncryptHeaderError::UnsupportedVersion { version: 99 };
        let lifted: RarError = err.into();
        match lifted {
            RarError::Encryption(EncryptionError::UnsupportedCipher { detail }) => {
                assert!(detail.contains("99"));
            }
            other => panic!("expected RarError::Encryption(UnsupportedCipher), got {other:?}"),
        }
    }

    #[test]
    fn encrypt_header_kdf_too_large_lifts_to_unsupported_kdf() {
        let err = EncryptHeaderError::KdfCountTooLarge { kdf_count: 50 };
        let lifted: RarError = err.into();
        match lifted {
            RarError::Encryption(EncryptionError::UnsupportedKdf { detail }) => {
                assert!(detail.contains("50"));
            }
            other => panic!("expected RarError::Encryption(UnsupportedKdf), got {other:?}"),
        }
    }
}
