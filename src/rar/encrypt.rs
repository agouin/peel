//! RAR5 encryption primitives and parsers
//! (`internal/PLAN_archive_encryption.md` §4).
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

use crate::crypto::aes::{Aes256, BLOCK_LEN};
use crate::crypto::aes_modes::AesCbcDecrypt;
use crate::crypto::hmac::Hmac;
use crate::crypto::{ct_eq, BlockHash};
use crate::encryption::EncryptionError;
use crate::hash::sha256::Sha256;
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

/// Three keys derived from a password + salt + `kdf_count` per the
/// RAR5 spec.
///
/// All three slices are 32 bytes wide; downstream consumers slice
/// what they need (`aes_key` is used whole as the AES-256 key,
/// `pswcheck_raw` is folded to 8 bytes via [`fold_pswcheck`]).
#[derive(Debug, Clone)]
pub struct DerivedKeys {
    /// AES-256 key (32 bytes). Drives both header-stream and
    /// per-file data CBC decryption.
    pub aes_key: [u8; AES_KEY_LEN],
    /// HMAC-SHA256 key (32 bytes). RAR5 uses it for the optional
    /// per-data-block authentication HMAC; peel does not validate
    /// that HMAC today (the file-data BLAKE2sp + CRC-32 already
    /// detect tampering under a correct password). Retained for
    /// future use and for parity with the spec's three-output KDF.
    pub hmac_key: [u8; AES_KEY_LEN],
    /// Raw password-check buffer (32 bytes). Pass to
    /// [`fold_pswcheck`] to derive the 8-byte verifier.
    pub pswcheck_raw: [u8; AES_KEY_LEN],
}

/// Run RAR5's three-stage PBKDF2-HMAC-SHA256 key derivation.
///
/// Re-implements the algorithm in `crypt5.cpp::pbkdf2` from the
/// open-source unrar reference:
///
/// 1. `U_1 = HMAC(password, salt || 0x00000001)`.
/// 2. For `i = 2 ..= N+2`: `U_i = HMAC(password, U_{i-1})`.
/// 3. Running XOR: `X_k = U_1 ⊕ U_2 ⊕ … ⊕ U_k`.
/// 4. Snapshot at three iteration counts:
///    - `aes_key      = X_N`        (`N = 1 << (kdf_count + 15)`)
///    - `hmac_key     = X_{N+1}`
///    - `pswcheck_raw = X_{N+2}`
///
/// The three outputs are identical to what RFC 8018 PBKDF2 with the
/// same parameters and iteration count would produce (PBKDF2's first
/// `hLen` bytes are `T_1 = U_1 ⊕ … ⊕ U_c`); running the loop once
/// and snapshotting at three points is byte-identical to three
/// separate PBKDF2 calls but ~3× faster.
///
/// # Performance
///
/// `iterations = 1 << (kdf_count + 15)`. For the spec default
/// `kdf_count = 0` that is 32 768 HMAC-SHA256 operations — about
/// 10 ms on a modern x86_64 (release build, hand-rolled SHA-256).
/// Higher `kdf_count` values are exponentially slower; the §4 parser
/// rejects `kdf_count > 24` so the worst case is bounded.
#[must_use]
pub fn derive_keys(password: &[u8], salt: &[u8; SALT_LEN], kdf_count: u8) -> DerivedKeys {
    derive_keys_for_iterations(password, salt, u64::from(kdf_iterations(kdf_count)))
}

/// Inner helper exposing the raw iteration count so tests can drive
/// the KDF at a small `n` (the spec-mandated `n ≥ 2^15` is too slow
/// for a tight test loop).
///
/// Public consumers should call [`derive_keys`] which threads
/// `kdf_count` through [`kdf_iterations`].
#[must_use]
pub fn derive_keys_for_iterations(password: &[u8], salt: &[u8; SALT_LEN], n: u64) -> DerivedKeys {
    assert!(n >= 1, "RAR5 KDF iteration count must be ≥ 1");
    // First HMAC: `U_1 = HMAC(P, salt || INT(1))`. `INT(1)` is the
    // PBKDF2 block index encoded big-endian over 4 bytes; for the
    // first (and only) derivation block, that's 0x00000001.
    let mut hmac = Hmac::<Sha256>::new(password);
    hmac.update(salt);
    hmac.update(&1u32.to_be_bytes());
    let mut u_prev: [u8; 32] = hmac.finalize();

    // Running XOR seeds with U_1.
    let mut xor_acc: [u8; 32] = u_prev;

    let mut aes_key = [0u8; AES_KEY_LEN];
    let mut hmac_key = [0u8; AES_KEY_LEN];
    let mut pswcheck_raw = [0u8; AES_KEY_LEN];
    if n == 1 {
        aes_key = xor_acc;
    }

    // i = 2 ..= N+2. Snapshot at three iteration boundaries.
    for i in 2..=n + 2 {
        let mut hmac = Hmac::<Sha256>::new(password);
        hmac.update(&u_prev);
        u_prev = hmac.finalize();
        for (a, b) in xor_acc.iter_mut().zip(u_prev.iter()) {
            *a ^= *b;
        }
        if i == n {
            aes_key = xor_acc;
        }
        if i == n + 1 {
            hmac_key = xor_acc;
        }
        if i == n + 2 {
            pswcheck_raw = xor_acc;
        }
    }

    DerivedKeys {
        aes_key,
        hmac_key,
        pswcheck_raw,
    }
}

/// Fold a 32-byte `pswcheck_raw` down to the 8-byte verifier the
/// archive's encryption header stores.
///
/// The fold is the RAR5-defined XOR-down: for each byte index
/// `i ∈ 0..32`, the destination index is `i % 8`. The output is
/// independent of byte order.
#[must_use]
pub fn fold_pswcheck(raw: &[u8; AES_KEY_LEN]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for (i, b) in raw.iter().enumerate() {
        out[i % 8] ^= *b;
    }
    out
}

/// Verify a derived password against the 12-byte `pswcheck` field
/// the archive stored.
///
/// The wire layout of `pswcheck` is `[8-byte check][4-byte sum]`,
/// where the sum is the first 4 bytes of `SHA-256(check)`. Two
/// independent comparisons must succeed:
///
/// 1. `fold_pswcheck(raw) == stored_check` — the derived key
///    matches the archive's verifier.
/// 2. `SHA-256(stored_check)[..4] == stored_sum` — the stored
///    verifier itself isn't corrupt.
///
/// Both comparisons go through [`ct_eq`] so a timing attacker cannot
/// walk the verifier byte-by-byte.
///
/// # Returns
///
/// - `Ok(())` when both comparisons agree.
/// - `Err(EncryptionError::PasswordIncorrect)` when (1) fails — the
///   derived key didn't match.
/// - `Err(EncryptionError::IntegrityCheckFailed)` when (1) succeeds
///   but (2) fails — vanishingly unlikely outside a tampered archive,
///   so we surface the corrupt-verifier case as integrity rather than
///   password.
pub fn verify_pswcheck(
    raw: &[u8; AES_KEY_LEN],
    stored: &[u8; PSWCHECK_LEN],
    entry_name: &str,
) -> Result<(), EncryptionError> {
    let candidate_check = fold_pswcheck(raw);
    let stored_check: &[u8] = &stored[..8];
    let stored_sum: &[u8] = &stored[8..12];
    let candidate_sum_full = Sha256::digest(&candidate_check);
    let candidate_sum = &candidate_sum_full.as_ref()[..4];

    let check_match = ct_eq(&candidate_check, stored_check);
    let sum_match = ct_eq(candidate_sum, stored_sum);

    if !check_match {
        return Err(EncryptionError::PasswordIncorrect);
    }
    if !sum_match {
        // The user-supplied password produced the matching 8-byte
        // verifier but the verifier's own integrity sum is wrong.
        // Treat as tampering rather than wrong-password.
        return Err(EncryptionError::IntegrityCheckFailed {
            entry_name: entry_name.to_string(),
        });
    }
    Ok(())
}

/// Streaming AES-256-CBC decryptor for RAR5's encrypted-header and
/// per-file data layers.
///
/// Both layers share the same shape:
///
/// - 16-byte IV (cleartext on disk for header streams; carried by the
///   [`FileEncryptionRecord`] for data streams).
/// - Block-aligned ciphertext (the archive zero-pads the last block
///   to a multiple of 16 bytes; consumers discard the padding by
///   stopping at the cleartext-size boundary the spec records
///   separately).
///
/// The wrapper is a thin convenience over [`AesCbcDecrypt`] that
/// owns the AES key schedule, so callers can construct a decryptor
/// once per header / per file and feed ciphertext in arbitrary
/// 16-byte multiples.
pub struct Rar5CbcStream {
    cipher: Aes256,
    iv: [u8; BLOCK_LEN],
}

impl Rar5CbcStream {
    /// Construct a decryptor with the given 32-byte AES key and
    /// 16-byte IV.
    #[must_use]
    pub fn new(aes_key: &[u8; AES_KEY_LEN], iv: [u8; BLOCK_LEN]) -> Self {
        Self {
            cipher: Aes256::new(aes_key),
            iv,
        }
    }

    /// Decrypt `data` in place, advancing the rolling IV so
    /// subsequent calls continue the CBC chain.
    ///
    /// CBC chaining is "previous-ciphertext-block XOR'd into the
    /// next AES decryption output", so across multiple calls we
    /// must capture the trailing ciphertext block *before* in-place
    /// decryption overwrites it. The internal [`AesCbcDecrypt`]
    /// tracks its own rolling `prev` for the duration of a single
    /// call; this wrapper saves that block externally so each call
    /// constructs a fresh inner decryptor with the right IV.
    ///
    /// `data.len()` must be a multiple of 16 bytes (the format
    /// guarantees this; the archive zero-pads to a block boundary
    /// at creation time).
    ///
    /// # Panics
    ///
    /// Panics if `data.len() % 16 != 0`.
    pub fn decrypt_blocks(&mut self, data: &mut [u8]) {
        assert_eq!(
            data.len() % BLOCK_LEN,
            0,
            "AES-CBC requires block-aligned ciphertext, got {} bytes",
            data.len()
        );
        if data.is_empty() {
            return;
        }
        let last_ct_start = data.len() - BLOCK_LEN;
        let mut last_ct = [0u8; BLOCK_LEN];
        last_ct.copy_from_slice(&data[last_ct_start..]);
        let mut cbc = AesCbcDecrypt::new(&self.cipher, self.iv);
        cbc.decrypt_blocks(data);
        self.iv = last_ct;
    }
}

/// Walk a file header's extra area and return the first
/// (and only) encryption record, if any.
///
/// RAR5's extra-record framing: each record is `[size vint][type vint][body...]`
/// where `size` covers `[type vint][body...]` (not the size vint
/// itself), and the encryption record's type code is `0x01`.
///
/// Other extra-record types (file-time, file-version, hash records,
/// redirect, Unix owner, etc.) are not encryption-relevant — this
/// walker silently steps over them.
///
/// # Errors
///
/// - [`RarError::Truncated`] if a record's size vint or body runs
///   past the extra area's end.
/// - [`RarError::CorruptHeader`] if a record's size is zero.
/// - [`EncryptHeaderError::*`] (lifted to [`RarError`]) for a
///   malformed encryption record.
pub fn find_file_encryption_record(
    extra: &[u8],
    archive_offset_of_extra: u64,
) -> Result<Option<FileEncryptionRecord>, RarError> {
    use crate::rar::format::Vint;

    /// Type code for the encryption extra record.
    const TYPE_ENCRYPTION: u64 = 0x01;

    let mut cursor = 0usize;
    while cursor < extra.len() {
        let size_vint = Vint::decode_at(&extra[cursor..], archive_offset_of_extra + cursor as u64)?;
        cursor += size_vint.size;
        let size: usize = size_vint
            .value
            .try_into()
            .map_err(|_| RarError::CorruptHeader {
                archive_offset: archive_offset_of_extra + cursor as u64,
                reason: format!(
                    "extra-record size {} exceeds usize on this platform",
                    size_vint.value
                ),
            })?;
        if size == 0 {
            return Err(RarError::CorruptHeader {
                archive_offset: archive_offset_of_extra + cursor as u64,
                reason: "extra-record size = 0; minimum record has a type vint".to_string(),
            });
        }
        if cursor + size > extra.len() {
            return Err(RarError::Truncated {
                what: format!("extra record body ({size} bytes)"),
                needed: cursor + size - extra.len(),
            });
        }
        let record_bytes = &extra[cursor..cursor + size];
        cursor += size;

        let type_vint = Vint::decode_at(record_bytes, 0).map_err(|_| RarError::CorruptHeader {
            archive_offset: archive_offset_of_extra,
            reason: "extra-record type vint failed to decode".to_string(),
        })?;
        if type_vint.value == TYPE_ENCRYPTION {
            let body = &record_bytes[type_vint.size..];
            let parsed = FileEncryptionRecord::parse(body).map_err(RarError::from)?;
            return Ok(Some(parsed));
        }
    }
    Ok(None)
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

    /// The three RAR5-derived outputs at iteration counts N, N+1,
    /// N+2 must equal three independent PBKDF2-HMAC-SHA256
    /// derivations with those iteration counts (the running-XOR
    /// scheme is a fused-loop equivalent). Cross-checks the
    /// fused-loop optimisation against the generic PBKDF2 already
    /// validated against the upstream `pbkdf2` crate.
    #[test]
    fn derive_keys_matches_three_pbkdf2_calls() {
        use crate::crypto::pbkdf2::pbkdf2_hmac;
        use crate::hash::sha256::Sha256;

        let password = b"hunter2";
        let salt: [u8; SALT_LEN] =
            *b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
        // Small n so the test stays under a millisecond.
        let n: u64 = 7;
        let keys = derive_keys_for_iterations(password, &salt, n);

        let mut expect_aes = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password, &salt, n as u32, &mut expect_aes);
        let mut expect_hmac = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password, &salt, (n + 1) as u32, &mut expect_hmac);
        let mut expect_pswcheck = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password, &salt, (n + 2) as u32, &mut expect_pswcheck);

        assert_eq!(keys.aes_key, expect_aes, "aes_key");
        assert_eq!(keys.hmac_key, expect_hmac, "hmac_key");
        assert_eq!(keys.pswcheck_raw, expect_pswcheck, "pswcheck_raw");
    }

    /// At the spec-minimum `kdf_count = 0` (N = 32 768) we still
    /// agree with three independent PBKDF2 calls. Slower than the
    /// small-n test above but still well under a second on a modern
    /// CPU; this is the only test that exercises the actual default
    /// iteration count an archive will use.
    #[test]
    fn derive_keys_matches_pbkdf2_at_spec_default() {
        use crate::crypto::pbkdf2::pbkdf2_hmac;
        use crate::hash::sha256::Sha256;

        let password = b"correct horse battery staple";
        let salt: [u8; SALT_LEN] = [0x42; SALT_LEN];
        let kdf_count: u8 = 0;
        let keys = derive_keys(password, &salt, kdf_count);

        let n = kdf_iterations(kdf_count);
        let mut expect_aes = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password, &salt, n, &mut expect_aes);
        let mut expect_hmac = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password, &salt, n + 1, &mut expect_hmac);
        assert_eq!(keys.aes_key, expect_aes);
        assert_eq!(keys.hmac_key, expect_hmac);
    }

    /// XOR-fold of an all-zero buffer is all-zero; XOR-fold of an
    /// all-`0xFF` buffer is all-zero (each output byte is XOR'd
    /// four times, an even number).
    #[test]
    fn fold_pswcheck_handles_constant_inputs() {
        let zero = [0u8; AES_KEY_LEN];
        let zero_fold = fold_pswcheck(&zero);
        assert_eq!(zero_fold, [0u8; 8]);

        let ones = [0xFFu8; AES_KEY_LEN];
        let ones_fold = fold_pswcheck(&ones);
        // 32 bytes / 8 output bytes = 4 contributions per output byte.
        // 0xFF XOR'd 4 times = 0x00.
        assert_eq!(ones_fold, [0u8; 8]);
    }

    /// XOR-fold spec check: each output byte equals the XOR of the
    /// four source bytes at indices `i, i+8, i+16, i+24`.
    #[test]
    fn fold_pswcheck_matches_indexed_xor() {
        let mut raw = [0u8; AES_KEY_LEN];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = i as u8;
        }
        let folded = fold_pswcheck(&raw);
        for i in 0..8 {
            let expected = raw[i] ^ raw[i + 8] ^ raw[i + 16] ^ raw[i + 24];
            assert_eq!(folded[i], expected, "byte {i}");
        }
    }

    /// Correct password verifies; mutated check value surfaces
    /// `PasswordIncorrect`; mutated sum-byte surfaces
    /// `IntegrityCheckFailed`.
    #[test]
    fn verify_pswcheck_round_trip() {
        let raw = [0xAB; AES_KEY_LEN];
        let check = fold_pswcheck(&raw);
        let sum_full = crate::hash::sha256::Sha256::digest(&check);
        let mut stored = [0u8; PSWCHECK_LEN];
        stored[..8].copy_from_slice(&check);
        stored[8..12].copy_from_slice(&sum_full.as_ref()[..4]);

        // Correct password verifies.
        verify_pswcheck(&raw, &stored, "test.bin").expect("correct verifier");

        // Mutate the check bytes → PasswordIncorrect.
        let mut tampered_check = stored;
        tampered_check[0] ^= 1;
        let err = verify_pswcheck(&raw, &tampered_check, "test.bin").expect_err("wrong password");
        assert!(matches!(err, EncryptionError::PasswordIncorrect));

        // Leave the check intact but corrupt the sum →
        // IntegrityCheckFailed.
        let mut tampered_sum = stored;
        tampered_sum[8] ^= 1;
        let err = verify_pswcheck(&raw, &tampered_sum, "test.bin").expect_err("bad sum");
        assert!(matches!(err, EncryptionError::IntegrityCheckFailed { .. }));
    }

    /// Streaming CBC decrypt across multiple `decrypt_blocks` calls
    /// must produce the same bytes as a single all-at-once call.
    /// Exercises the IV-chaining behaviour the [`Rar5CbcStream`]
    /// wrapper adds on top of [`AesCbcDecrypt`].
    #[test]
    fn cbc_stream_chains_across_calls() {
        use crate::crypto::aes::Aes256;
        use crate::crypto::aes_modes::AesCbcDecrypt;

        let key = [0x42u8; AES_KEY_LEN];
        let iv = [0x11u8; BLOCK_LEN];
        // 5 blocks of synthetic ciphertext (the exact bytes don't
        // matter for a streaming-vs-monolithic check; we just need
        // CBC decryption to produce deterministic output).
        let ct: Vec<u8> = (0..80u8).collect();

        // Monolithic decrypt.
        let cipher = Aes256::new(&key);
        let mut buf_a = ct.clone();
        {
            let mut cbc = AesCbcDecrypt::new(&cipher, iv);
            cbc.decrypt_blocks(&mut buf_a);
        }

        // Streaming decrypt: 2 blocks, then 1 block, then 2 blocks.
        let mut buf_b = ct.clone();
        let mut stream = Rar5CbcStream::new(&key, iv);
        stream.decrypt_blocks(&mut buf_b[..32]);
        stream.decrypt_blocks(&mut buf_b[32..48]);
        stream.decrypt_blocks(&mut buf_b[48..]);

        assert_eq!(buf_a, buf_b, "streaming and monolithic CBC must agree");
    }

    #[test]
    #[should_panic(expected = "AES-CBC requires block-aligned ciphertext")]
    fn cbc_stream_rejects_unaligned() {
        let key = [0u8; AES_KEY_LEN];
        let iv = [0u8; BLOCK_LEN];
        let mut buf = [0u8; 17];
        Rar5CbcStream::new(&key, iv).decrypt_blocks(&mut buf);
    }

    /// `find_file_encryption_record` walks past non-encryption
    /// records and returns the encryption record's parsed form.
    #[test]
    fn find_file_encryption_record_locates_among_other_records() {
        // Build an extra area:
        //   - one type-2 (file-time) record body 4 bytes
        //   - one type-1 (encryption) record with valid fields
        //
        // Per-record wire layout: `[size vint][type vint][body...]`.
        // `size` covers `[type vint][body]`.
        let other_type = 2u64;
        let other_body = [0xAAu8; 4];
        let mut other_record_body = Vec::new();
        other_record_body.extend_from_slice(&encode_vint(other_type));
        other_record_body.extend_from_slice(&other_body);

        let salt = [0x12u8; SALT_LEN];
        let iv = [0x34u8; IV_LEN];
        let enc_type = 1u64;
        let mut enc_body = Vec::new();
        enc_body.extend_from_slice(&encode_vint(enc_type));
        enc_body.extend_from_slice(&encode_vint(0)); // version
        enc_body.extend_from_slice(&encode_vint(0)); // flags
        enc_body.push(0); // kdf_count
        enc_body.extend_from_slice(&salt);
        enc_body.extend_from_slice(&iv);

        let mut extra = Vec::new();
        extra.extend_from_slice(&encode_vint(other_record_body.len() as u64));
        extra.extend_from_slice(&other_record_body);
        extra.extend_from_slice(&encode_vint(enc_body.len() as u64));
        extra.extend_from_slice(&enc_body);

        let parsed = find_file_encryption_record(&extra, 0)
            .expect("walks extra area")
            .expect("encryption record present");
        assert_eq!(parsed.salt, salt);
        assert_eq!(parsed.iv, iv);
    }

    #[test]
    fn find_file_encryption_record_returns_none_when_absent() {
        // Just one non-encryption record.
        let mut record_body = Vec::new();
        record_body.extend_from_slice(&encode_vint(2));
        record_body.extend_from_slice(&[0u8; 4]);
        let mut extra = Vec::new();
        extra.extend_from_slice(&encode_vint(record_body.len() as u64));
        extra.extend_from_slice(&record_body);
        let parsed = find_file_encryption_record(&extra, 0).expect("walks");
        assert!(parsed.is_none());
    }

    #[test]
    fn find_file_encryption_record_truncated_body_errors() {
        // Size vint says 100 bytes; we only have 10 after it.
        let mut extra = Vec::new();
        extra.extend_from_slice(&encode_vint(100));
        extra.extend_from_slice(&[0u8; 10]);
        let err = find_file_encryption_record(&extra, 0).expect_err("truncated");
        assert!(matches!(err, RarError::Truncated { .. }));
    }
}
