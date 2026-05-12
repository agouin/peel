//! WinZip AES (AE-1 / AE-2) decryption for ZIP entries
//! (`docs/PLAN_archive_encryption.md` §3).
//!
//! # Wire layout
//!
//! For a method-99 entry whose central-directory record carries a
//! valid [`AesExtra`], the entry's *compressed* payload looks like:
//!
//! ```text
//! [salt:           salt_len bytes]    salt_len = strength.salt_len()
//! [pw_verifier:    2 bytes        ]
//! [ciphertext:     N bytes        ]    N = compressed_size - salt_len - 12
//! [HMAC-SHA1-80:   10 bytes       ]
//! ```
//!
//! The 2-byte verifier is bytes `[2*key_len, 2*key_len + 2)` of the
//! PBKDF2(password, salt, 1000) output (with output length =
//! `2*key_len + 2`); the first `key_len` bytes are the AES key, the
//! next `key_len` bytes are the HMAC-SHA1 key. The HMAC is computed
//! over the *ciphertext* (Encrypt-then-MAC).
//!
//! The CTR-mode counter is a 16-byte little-endian integer starting
//! at **1** (not 0); each AES block increments it by 1, with carry
//! propagating low-byte-first.
//!
//! # Streaming
//!
//! [`AesDecryptReader`] wraps a `Read` that yields the entry's full
//! compressed payload (`compressed_size` bytes). On the first call,
//! it consumes the salt + verifier, verifies the password, and
//! initialises CTR + HMAC. Subsequent reads stream decrypted bytes
//! to the caller while feeding ciphertext into the HMAC. Once the
//! payload section is exhausted (or [`Self::finalize`] is called),
//! the 10-byte trailer is read and compared in constant time. A
//! verifier mismatch surfaces as
//! [`EncryptionError::PasswordIncorrect`]; a trailer mismatch
//! surfaces as [`EncryptionError::IntegrityCheckFailed`].
//!
//! # Design notes
//!
//! - The reader is a state machine, not a pre-buffered design. AES
//!   entries can be arbitrarily large; we don't want to materialize
//!   the whole ciphertext.
//! - The HMAC must see *every* ciphertext byte for the trailer
//!   compare to be meaningful. Downstream decompressors (DEFLATE /
//!   zstd) may stop reading before consuming the full payload —
//!   in that case the caller MUST drive [`Self::finalize`] to drain
//!   the rest before checking the tag.
//! - All comparisons go through [`crate::crypto::ct_eq`] so the
//!   timing profile is independent of the per-byte mismatch
//!   position.

use std::io::{self, Read};

use crate::crypto::aes::{Aes128, Aes192, Aes256, AesBlockCipher, BLOCK_LEN};
use crate::crypto::ct_eq;
use crate::crypto::hmac::Hmac;
use crate::crypto::pbkdf2::pbkdf2_hmac;
use crate::crypto::sha1::Sha1;
use crate::secret::Password;
use crate::zip::format::{AesExtra, AesStrength};
use crate::zip::EncryptionError;

/// WinZip AES PBKDF2 iteration count. Fixed by the spec; not a
/// per-archive parameter.
pub const PBKDF2_ITERATIONS: u32 = 1000;

/// Length of the password-verifier inside the PBKDF2 output (bytes).
pub const VERIFIER_LEN: usize = 2;

/// Length of the HMAC-SHA1-80 trailer (bytes).
pub const HMAC_TRAILER_LEN: usize = 10;

/// Type-erased keystream-applier. Constructed once per entry from
/// the AES key the PBKDF2 derived; lets [`AesDecryptReader`] handle
/// all three strengths without monomorphizing the whole reader.
enum CtrCipher {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

impl CtrCipher {
    fn new(strength: AesStrength, key: &[u8]) -> Self {
        debug_assert_eq!(
            key.len(),
            strength.key_len(),
            "CTR key length must match strength",
        );
        match strength {
            AesStrength::Aes128 => Self::Aes128(Aes128::new(key)),
            AesStrength::Aes192 => Self::Aes192(Aes192::new(key)),
            AesStrength::Aes256 => Self::Aes256(Aes256::new(key)),
        }
    }

    fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
        match self {
            Self::Aes128(c) => c.encrypt_block(block),
            Self::Aes192(c) => c.encrypt_block(block),
            Self::Aes256(c) => c.encrypt_block(block),
        }
    }
}

/// Stateful AES-CTR keystream — wraps a [`CtrCipher`] in the
/// mode-agnostic [`AesCtr`] machinery. Owned by the reader so the
/// counter advances across read calls.
struct Keystream {
    cipher: CtrCipher,
    counter: [u8; BLOCK_LEN],
    keystream: [u8; BLOCK_LEN],
    keystream_used: usize,
}

impl Keystream {
    fn new(cipher: CtrCipher) -> Self {
        // WinZip AES starts the counter at 1, little-endian.
        let mut counter = [0u8; BLOCK_LEN];
        counter[0] = 1;
        Self {
            cipher,
            counter,
            keystream: [0u8; BLOCK_LEN],
            keystream_used: BLOCK_LEN,
        }
    }

    /// XOR `data.len()` keystream bytes into `data` in place.
    /// Matches the byte-for-byte semantics of
    /// [`AesCtr::apply_keystream`] but tied to our internal
    /// `CtrCipher` enum to avoid generic monomorphization at every
    /// call site.
    fn apply(&mut self, mut data: &mut [u8]) {
        while !data.is_empty() {
            if self.keystream_used == BLOCK_LEN {
                self.keystream = self.counter;
                self.cipher.encrypt_block(&mut self.keystream);
                Self::increment_counter_le(&mut self.counter);
                self.keystream_used = 0;
            }
            let take = (BLOCK_LEN - self.keystream_used).min(data.len());
            for (i, byte) in data[..take].iter_mut().enumerate() {
                *byte ^= self.keystream[self.keystream_used + i];
            }
            self.keystream_used += take;
            data = &mut data[take..];
        }
    }

    /// Little-endian counter increment (matches
    /// [`CounterEndian::Little`] in [`AesCtr`]).
    fn increment_counter_le(counter: &mut [u8; BLOCK_LEN]) {
        for byte in counter.iter_mut() {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                return;
            }
        }
    }
}

/// Sanity-check that our private [`Keystream`] matches the public
/// [`AesCtr`] wrapper. The CTR-mode tests in
/// [`crate::crypto::aes_modes`] already vet the latter against NIST
/// vectors; if our enum-wrapped variant drifts, this assertion
/// fires the moment the cross-check test runs.
#[cfg(test)]
fn keystream_matches_aesctr(strength: AesStrength, key: &[u8], data: &[u8]) -> bool {
    use crate::crypto::aes_modes::{AesCtr, CounterEndian};
    let mut a = data.to_vec();
    let cipher = CtrCipher::new(strength, key);
    let mut ks = Keystream::new(cipher);
    ks.apply(&mut a);

    let mut b = data.to_vec();
    let mut init = [0u8; BLOCK_LEN];
    init[0] = 1;
    match strength {
        AesStrength::Aes128 => {
            let c = Aes128::new(key);
            AesCtr::new(&c, init, CounterEndian::Little).apply_keystream(&mut b);
        }
        AesStrength::Aes192 => {
            let c = Aes192::new(key);
            AesCtr::new(&c, init, CounterEndian::Little).apply_keystream(&mut b);
        }
        AesStrength::Aes256 => {
            let c = Aes256::new(key);
            AesCtr::new(&c, init, CounterEndian::Little).apply_keystream(&mut b);
        }
    }
    a == b
}

/// Derive the AES key, HMAC key, and password verifier from the
/// raw password and per-entry salt.
///
/// The PBKDF2 output is `2 * strength.key_len() + 2` bytes laid
/// out as:
///
/// ```text
/// [ AES key                  : key_len bytes ]
/// [ HMAC-SHA1 key            : key_len bytes ]
/// [ password verifier        : 2 bytes       ]
/// ```
///
/// The verifier is what we compare against the 2 bytes the encoder
/// emitted at the start of the ciphertext: equal → password correct,
/// unequal → [`EncryptionError::PasswordIncorrect`].
pub struct AesKeys {
    /// AES key (length depends on strength).
    pub aes_key: Vec<u8>,
    /// HMAC-SHA1 key (same length as `aes_key`).
    pub hmac_key: Vec<u8>,
    /// Two-byte password verifier.
    pub verifier: [u8; VERIFIER_LEN],
}

impl AesKeys {
    /// Run PBKDF2-HMAC-SHA1 with the fixed 1000 iterations the WinZip
    /// AES spec mandates.
    #[must_use]
    pub fn derive(password: &Password, strength: AesStrength, salt: &[u8]) -> Self {
        let key_len = strength.key_len();
        let mut out = vec![0u8; 2 * key_len + VERIFIER_LEN];
        pbkdf2_hmac::<Sha1>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut out);
        let (aes_key, rest) = out.split_at(key_len);
        let (hmac_key, ver) = rest.split_at(key_len);
        let mut verifier = [0u8; VERIFIER_LEN];
        verifier.copy_from_slice(&ver[..VERIFIER_LEN]);
        let aes_key = aes_key.to_vec();
        let hmac_key = hmac_key.to_vec();
        // Zero the temporary buffer holding the full PBKDF2 output;
        // `out` is dropped here either way, but a defensive volatile
        // overwrite mirrors the `Password` zeroiser pattern.
        for b in out.iter_mut() {
            // SAFETY: pointer + offset are in-range and the buffer
            // is mutably borrowed. `write_volatile` defeats
            // dead-store elimination on the soon-to-drop vector.
            unsafe { std::ptr::write_volatile(b as *mut u8, 0u8) };
        }
        Self {
            aes_key,
            hmac_key,
            verifier,
        }
    }
}

/// `Read` wrapper that decrypts a single WinZip-AES ZIP entry.
pub struct AesDecryptReader<R: Read> {
    inner: R,
    strength: AesStrength,
    entry_name: String,
    /// Bytes of the entry's ciphertext (the slice between
    /// `salt + verifier` and the 10-byte trailer).
    payload_total: u64,
    payload_yielded: u64,
    keystream: Keystream,
    hmac: Option<Hmac<Sha1>>,
    /// Once `payload_yielded == payload_total` we read & verify the
    /// trailer; this flag prevents repeating the work on subsequent
    /// `Ok(0)` returns.
    finalized: bool,
}

impl<R: Read> AesDecryptReader<R> {
    /// Wrap `inner`, which must yield exactly `compressed_size` bytes
    /// of the AES-encrypted entry. `compressed_size` is the value
    /// from the central directory.
    ///
    /// Consumes the salt + 2-byte verifier from `inner` immediately
    /// and verifies the password.
    ///
    /// # Errors
    ///
    /// - `io::Error` wrapping `EncryptionError::PasswordIncorrect`
    ///   when the verifier mismatches.
    /// - `io::Error` from short reads on the inner source.
    pub fn new(
        mut inner: R,
        password: &Password,
        extra: AesExtra,
        compressed_size: u64,
        entry_name: &str,
    ) -> io::Result<Self> {
        let strength = extra.strength;
        let salt_len = strength.salt_len();
        let prefix_len = salt_len as u64 + VERIFIER_LEN as u64;
        let suffix_len = HMAC_TRAILER_LEN as u64;
        let min_overhead = prefix_len + suffix_len;
        if compressed_size < min_overhead {
            return Err(encryption_io(EncryptionError::IntegrityCheckFailed {
                entry_name: entry_name.to_string(),
            }));
        }
        let payload_total = compressed_size - min_overhead;

        let mut salt = vec![0u8; salt_len];
        inner.read_exact(&mut salt)?;
        let mut wire_verifier = [0u8; VERIFIER_LEN];
        inner.read_exact(&mut wire_verifier)?;

        let keys = AesKeys::derive(password, strength, &salt);
        if !ct_eq(&keys.verifier, &wire_verifier) {
            return Err(encryption_io(EncryptionError::PasswordIncorrect));
        }

        let mut hmac = Hmac::<Sha1>::new(&keys.hmac_key);
        // HMAC is over ciphertext only. The salt + verifier are
        // *not* included (per the WinZip AES spec).
        // `hmac` will be fed the ciphertext bytes as the reader
        // consumes them in `read`.
        // We intentionally let `keys` drop here; the AES key is
        // moved into the cipher and the HMAC key is consumed by
        // `Hmac::new`. The verifier doesn't need to persist.
        let cipher = CtrCipher::new(strength, &keys.aes_key);
        // Defensive zeroize of the temporary key buffers — `keys`
        // is dropped at the end of this fn but the Vecs themselves
        // don't zeroise.
        let mut aes_key = keys.aes_key;
        let mut hmac_key = keys.hmac_key;
        for b in aes_key.iter_mut().chain(hmac_key.iter_mut()) {
            // SAFETY: same volatile-overwrite pattern as
            // `Password::drop`.
            unsafe { std::ptr::write_volatile(b as *mut u8, 0u8) };
        }
        // Drain the hmac state once so the borrow-checker is happy
        // when we re-feed it during reads (we re-construct the
        // wrapper via Option<Hmac> below).
        let _ = &mut hmac;
        Ok(Self {
            inner,
            strength,
            entry_name: entry_name.to_string(),
            payload_total,
            payload_yielded: 0,
            keystream: Keystream::new(cipher),
            hmac: Some(hmac),
            finalized: false,
        })
    }

    /// Drain any payload bytes the downstream decompressor did not
    /// consume, then read and verify the 10-byte HMAC trailer.
    ///
    /// Called from `read` once `payload_yielded == payload_total`
    /// (the streaming case), and explicitly by callers when the
    /// downstream decompressor stops mid-stream (e.g. zstd's
    /// end-of-frame before the source EOF). Safe to call multiple
    /// times — subsequent calls after the first are no-ops.
    ///
    /// # Errors
    ///
    /// - `io::Error` wrapping `EncryptionError::IntegrityCheckFailed`
    ///   when the HMAC trailer mismatches.
    /// - `io::Error` from short reads on the inner source.
    pub fn finalize(&mut self) -> io::Result<()> {
        if self.finalized {
            return Ok(());
        }
        let mut tmp = [0u8; 4096];
        while self.payload_yielded < self.payload_total {
            let remaining = self.payload_total - self.payload_yielded;
            let take = remaining.min(tmp.len() as u64) as usize;
            self.inner.read_exact(&mut tmp[..take])?;
            // HMAC over ciphertext only — no need to decrypt here
            // since we're discarding the plaintext.
            if let Some(h) = self.hmac.as_mut() {
                h.update(&tmp[..take]);
            }
            self.payload_yielded += take as u64;
        }
        let mut trailer = [0u8; HMAC_TRAILER_LEN];
        self.inner.read_exact(&mut trailer)?;
        // Past this point we have consumed the trailer; mark
        // `finalized` so a second call (e.g. the explicit
        // backstop in `decompress_aes_entry` after the inner
        // decoder has already surfaced our HMAC error through the
        // `read` path) is a clean no-op rather than another
        // read_exact past EOF.
        self.finalized = true;
        let hmac = self
            .hmac
            .take()
            .expect("hmac state only consumed in finalize");
        let tag = hmac.finalize();
        let computed = &tag.as_ref()[..HMAC_TRAILER_LEN];
        if !ct_eq(computed, &trailer) {
            return Err(encryption_io(EncryptionError::IntegrityCheckFailed {
                entry_name: self.entry_name.clone(),
            }));
        }
        Ok(())
    }

    /// AES strength (exposed for diagnostics / tests).
    #[must_use]
    pub fn strength(&self) -> AesStrength {
        self.strength
    }
}

impl<R: Read> Read for AesDecryptReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.payload_yielded == self.payload_total {
            if !self.finalized {
                self.finalize()?;
            }
            return Ok(0);
        }
        let remaining = self.payload_total - self.payload_yielded;
        let want = (buf.len() as u64).min(remaining) as usize;
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "AES entry {:?}: source EOF with {} payload bytes still owed",
                    self.entry_name, remaining,
                ),
            ));
        }
        // HMAC must see ciphertext, *before* CTR decrypts in-place.
        if let Some(h) = self.hmac.as_mut() {
            h.update(&buf[..n]);
        }
        self.keystream.apply(&mut buf[..n]);
        self.payload_yielded += n as u64;
        Ok(n)
    }
}

/// Lift an [`EncryptionError`] into an [`io::Error`] so it can
/// travel through the `Read` chain back to the pipeline.
///
/// The pipeline (zip_pipeline.rs / decode.rs) re-extracts the
/// `EncryptionError` via `io::Error::downcast_ref` so the
/// user-facing error message stays specific.
pub fn encryption_io(err: EncryptionError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

/// Try to extract an [`EncryptionError`] from an [`io::Error`]
/// produced by [`encryption_io`] (or chained through any number of
/// `Read` adapters that preserve the inner-error type).
///
/// Returns `None` when the IO error is unrelated to the encryption
/// layer — the caller falls back to the generic `Read`/decode
/// error path.
#[must_use]
pub fn downcast_encryption_error(err: &io::Error) -> Option<&EncryptionError> {
    err.get_ref().and_then(|inner| inner.downcast_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zip::format::{AesVersion, CompressionMethod};
    use std::io::Cursor;

    fn make_extra(strength: AesStrength) -> AesExtra {
        AesExtra {
            version: AesVersion::Ae2,
            strength,
            actual_method: CompressionMethod::Stored,
        }
    }

    /// Build a complete ZIP-AES ciphertext envelope from a plaintext
    /// payload: salt + verifier + AES-CTR(plaintext) + HMAC tag.
    /// Mirrors what `zip -e` / `7z a -p` produce on the wire.
    fn encrypt_envelope(
        password: &Password,
        strength: AesStrength,
        salt: &[u8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        assert_eq!(salt.len(), strength.salt_len());
        let keys = AesKeys::derive(password, strength, salt);
        let cipher = CtrCipher::new(strength, &keys.aes_key);
        let mut ks = Keystream::new(cipher);
        let mut ciphertext = plaintext.to_vec();
        ks.apply(&mut ciphertext);

        let mut hmac = Hmac::<Sha1>::new(&keys.hmac_key);
        hmac.update(&ciphertext);
        let tag = hmac.finalize();

        let mut out =
            Vec::with_capacity(salt.len() + VERIFIER_LEN + ciphertext.len() + HMAC_TRAILER_LEN);
        out.extend_from_slice(salt);
        out.extend_from_slice(&keys.verifier);
        out.extend_from_slice(&ciphertext);
        out.extend_from_slice(&tag.as_ref()[..HMAC_TRAILER_LEN]);
        out
    }

    #[test]
    fn keystream_matches_aes_ctr_wrapper_all_strengths() {
        let data: Vec<u8> = (0..200u8).collect();
        let key128 = vec![0xABu8; 16];
        let key192 = vec![0xABu8; 24];
        let key256 = vec![0xABu8; 32];
        assert!(keystream_matches_aesctr(
            AesStrength::Aes128,
            &key128,
            &data
        ));
        assert!(keystream_matches_aesctr(
            AesStrength::Aes192,
            &key192,
            &data
        ));
        assert!(keystream_matches_aesctr(
            AesStrength::Aes256,
            &key256,
            &data
        ));
    }

    #[test]
    fn round_trip_aes256_stored_short_payload() {
        let pw = Password::new(b"hunter2".to_vec());
        let salt = vec![0x11u8; AesStrength::Aes256.salt_len()];
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        let envelope = encrypt_envelope(&pw, AesStrength::Aes256, &salt, plaintext);

        let mut reader = AesDecryptReader::new(
            Cursor::new(envelope.clone()),
            &pw,
            make_extra(AesStrength::Aes256),
            envelope.len() as u64,
            "test.bin",
        )
        .expect("construct");
        let mut out = Vec::new();
        reader.read_to_end(&mut out).expect("read_to_end");
        assert_eq!(out, plaintext);
    }

    #[test]
    fn round_trip_aes128_long_payload_streaming() {
        let pw = Password::new(b"correct horse battery staple".to_vec());
        let salt = vec![0x42u8; AesStrength::Aes128.salt_len()];
        let plaintext: Vec<u8> = (0..(8 * 1024)).map(|i| (i % 251) as u8).collect();
        let envelope = encrypt_envelope(&pw, AesStrength::Aes128, &salt, &plaintext);

        let mut reader = AesDecryptReader::new(
            Cursor::new(envelope.clone()),
            &pw,
            make_extra(AesStrength::Aes128),
            envelope.len() as u64,
            "long.bin",
        )
        .expect("construct");
        // Byte-at-a-time reads exercise the keystream's
        // partial-block path and the HMAC streaming-update path.
        let mut out = Vec::with_capacity(plaintext.len());
        let mut tmp = [0u8; 1];
        loop {
            match reader.read(&mut tmp).expect("read") {
                0 => break,
                _ => out.push(tmp[0]),
            }
        }
        assert_eq!(out, plaintext);
    }

    #[test]
    fn round_trip_aes192_aligned_payload() {
        let pw = Password::new(b"p192".to_vec());
        let salt = vec![0x77u8; AesStrength::Aes192.salt_len()];
        // Block-aligned plaintext (multiple of 16) — separate code
        // path than the unaligned `_short_payload` case above.
        let plaintext = vec![0x55u8; 64];
        let envelope = encrypt_envelope(&pw, AesStrength::Aes192, &salt, &plaintext);

        let mut reader = AesDecryptReader::new(
            Cursor::new(envelope.clone()),
            &pw,
            make_extra(AesStrength::Aes192),
            envelope.len() as u64,
            "aligned.bin",
        )
        .expect("construct");
        let mut out = Vec::new();
        reader.read_to_end(&mut out).expect("read_to_end");
        assert_eq!(out, plaintext);
    }

    #[test]
    fn wrong_password_surfaces_password_incorrect() {
        let pw = Password::new(b"hunter2".to_vec());
        let wrong = Password::new(b"hunter3".to_vec());
        let salt = vec![0x33u8; AesStrength::Aes256.salt_len()];
        let plaintext = b"x";
        let envelope = encrypt_envelope(&pw, AesStrength::Aes256, &salt, plaintext);

        let err = match AesDecryptReader::new(
            Cursor::new(envelope.clone()),
            &wrong,
            make_extra(AesStrength::Aes256),
            envelope.len() as u64,
            "x.bin",
        ) {
            Ok(_) => panic!("must reject wrong password"),
            Err(e) => e,
        };
        let inner = downcast_encryption_error(&err).expect("encryption err");
        assert!(matches!(inner, EncryptionError::PasswordIncorrect));
    }

    #[test]
    fn tampered_trailer_surfaces_integrity_check_failed() {
        let pw = Password::new(b"hunter2".to_vec());
        let salt = vec![0x33u8; AesStrength::Aes256.salt_len()];
        let plaintext = b"payload-bytes";
        let mut envelope = encrypt_envelope(&pw, AesStrength::Aes256, &salt, plaintext);

        // Flip the last trailer byte.
        let last = envelope.len() - 1;
        envelope[last] ^= 0xFF;

        let mut reader = AesDecryptReader::new(
            Cursor::new(envelope.clone()),
            &pw,
            make_extra(AesStrength::Aes256),
            envelope.len() as u64,
            "tamper.bin",
        )
        .expect("verifier still passes since we only touched the trailer");
        let mut out = Vec::new();
        let err = reader
            .read_to_end(&mut out)
            .expect_err("trailer must fail at EOF");
        let inner = downcast_encryption_error(&err).expect("encryption err");
        assert!(matches!(
            inner,
            EncryptionError::IntegrityCheckFailed { .. }
        ));
    }

    #[test]
    fn tampered_ciphertext_surfaces_integrity_check_failed() {
        let pw = Password::new(b"hunter2".to_vec());
        let salt = vec![0x33u8; AesStrength::Aes256.salt_len()];
        let plaintext = b"payload-bytes-32-long-enough!!!!";
        let mut envelope = encrypt_envelope(&pw, AesStrength::Aes256, &salt, plaintext);

        // Flip a byte inside the ciphertext region (after salt+verifier,
        // before the 10-byte trailer).
        let mid = AesStrength::Aes256.salt_len() + VERIFIER_LEN + plaintext.len() / 2;
        envelope[mid] ^= 0x01;

        let mut reader = AesDecryptReader::new(
            Cursor::new(envelope.clone()),
            &pw,
            make_extra(AesStrength::Aes256),
            envelope.len() as u64,
            "tamper-ct.bin",
        )
        .expect("construct");
        let mut out = Vec::new();
        let err = reader
            .read_to_end(&mut out)
            .expect_err("HMAC must catch the tamper");
        let inner = downcast_encryption_error(&err).expect("encryption err");
        assert!(matches!(
            inner,
            EncryptionError::IntegrityCheckFailed { .. }
        ));
    }

    #[test]
    fn finalize_drains_unread_payload_then_verifies_trailer() {
        // Simulates the zstd / DEFLATE early-stop case: the downstream
        // decompressor consumes fewer ciphertext bytes than the
        // envelope contains. `finalize` must drain the rest before
        // checking the HMAC trailer.
        let pw = Password::new(b"hunter2".to_vec());
        let salt = vec![0x33u8; AesStrength::Aes256.salt_len()];
        let plaintext: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
        let envelope = encrypt_envelope(&pw, AesStrength::Aes256, &salt, &plaintext);

        let mut reader = AesDecryptReader::new(
            Cursor::new(envelope.clone()),
            &pw,
            make_extra(AesStrength::Aes256),
            envelope.len() as u64,
            "drain.bin",
        )
        .expect("construct");
        // Only consume the first 100 plaintext bytes, then bail.
        let mut head = vec![0u8; 100];
        reader.read_exact(&mut head).expect("read prefix");
        assert_eq!(head, plaintext[..100]);
        // Now drain + verify trailer.
        reader.finalize().expect("finalize must succeed");
    }

    #[test]
    fn compressed_size_smaller_than_overhead_errors() {
        let pw = Password::new(b"hunter2".to_vec());
        // Only 5 bytes — well under salt + verifier + trailer for
        // any strength.
        let envelope = vec![0u8; 5];
        let err = match AesDecryptReader::new(
            Cursor::new(envelope),
            &pw,
            make_extra(AesStrength::Aes128),
            5,
            "tiny.bin",
        ) {
            Ok(_) => panic!("must refuse undersize compressed_size"),
            Err(e) => e,
        };
        let inner = downcast_encryption_error(&err).expect("encryption err");
        assert!(matches!(
            inner,
            EncryptionError::IntegrityCheckFailed { .. }
        ));
    }

    #[test]
    fn ae1_and_ae2_envelopes_share_decoder_path() {
        // The AES extra's `version` field doesn't gate the decoder
        // — both AE-1 and AE-2 entries decode identically through
        // this reader. (AE-1 vs AE-2 only changes how the *outer*
        // pipeline interprets the CDE's CRC field.)
        let pw = Password::new(b"hunter2".to_vec());
        let salt = vec![0x33u8; AesStrength::Aes256.salt_len()];
        let plaintext = b"version-doesnt-matter";
        let envelope = encrypt_envelope(&pw, AesStrength::Aes256, &salt, plaintext);

        for version in [AesVersion::Ae1, AesVersion::Ae2] {
            let extra = AesExtra {
                version,
                strength: AesStrength::Aes256,
                actual_method: CompressionMethod::Stored,
            };
            let mut reader = AesDecryptReader::new(
                Cursor::new(envelope.clone()),
                &pw,
                extra,
                envelope.len() as u64,
                "v.bin",
            )
            .expect("construct");
            let mut out = Vec::new();
            reader.read_to_end(&mut out).expect("read");
            assert_eq!(out, plaintext);
        }
    }
}
