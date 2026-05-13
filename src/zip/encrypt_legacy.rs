//! PKWARE "ZipCrypto" — the legacy ZIP encryption scheme
//! (`internal/PLAN_archive_encryption.md` §3b).
//!
//! This is the 1989-era ZIP encryption that ships behind general-
//! purpose flag bit 0 when no WinZip-AES extra field is attached.
//! It is **not secure**: a 12-byte known-plaintext attack reveals the
//! internal state, and several public tools (`bkcrack`, `pkcrack`)
//! recover plaintext without the password in seconds. peel decodes
//! it anyway because the format is ubiquitous in legacy and CTF
//! archives, but every successful decode emits a `tracing::warn!`
//! reminding the user that the contents were never confidential.
//!
//! # Wire layout
//!
//! For a bit-0-encrypted entry, the entry's *compressed* payload looks
//! like:
//!
//! ```text
//! [encryption header: 12 bytes, encrypted under the same scheme]
//! [ciphertext:        compressed_size - 12 bytes               ]
//! ```
//!
//! The 12-byte header's first 11 bytes are random salt; the 12th byte
//! is a verifier. After decrypting under the user's password, the
//! verifier MUST equal the high byte of the CRC-32 of the (unencrypted,
//! pre-decompression) plaintext — which the central directory records.
//! Mismatch ⇒ wrong password.
//!
//! # Algorithm (PKWARE APPNOTE 6.0 §6.1)
//!
//! Three 32-bit keys, initialized to fixed constants:
//!
//! ```text
//! key[0] = 0x12345678
//! key[1] = 0x23456789
//! key[2] = 0x34567890
//! ```
//!
//! After every byte `c` (password byte or recovered plaintext byte):
//!
//! ```text
//! update_keys(c):
//!     key[0] = crc32_step(key[0], c)
//!     key[1] = (key[1] + (key[0] & 0xFF)) * 0x08088405 + 1   (mod 2^32)
//!     key[2] = crc32_step(key[2], (key[1] >> 24) & 0xFF)
//! ```
//!
//! The keystream byte at each step is derived from `key[2]`:
//!
//! ```text
//! stream_byte():
//!     temp = (key[2] | 3) as u16
//!     ((temp * (temp ^ 1)) >> 8) & 0xFF
//! ```
//!
//! Decryption is `plain = cipher ^ stream_byte()`, then `update_keys(plain)`.
//!
//! # Streaming
//!
//! [`ZipCryptoReader`] wraps a `Read` that yields the entry's full
//! compressed payload (`compressed_size` bytes). On construction it
//! consumes 12 header bytes, verifies the password against the high
//! byte of the entry's CRC-32, and primes the keystream. Subsequent
//! reads stream decrypted bytes to the caller.

use std::io::{self, Read};

use tracing::warn;

use crate::secret::Password;
use crate::zip::aes_decrypt::encryption_io;
use crate::zip::crc32::crc32_step;
use crate::zip::EncryptionError;

/// Length of the encryption header that precedes every ZipCrypto
/// entry's ciphertext.
pub const HEADER_LEN: usize = 12;

/// The three-key state advanced by every password / plaintext byte.
///
/// Held in registers in the hot loop; copy semantics keep the inner
/// `decrypt_byte` cheap.
#[derive(Debug, Clone, Copy)]
struct Keys {
    k0: u32,
    k1: u32,
    k2: u32,
}

impl Keys {
    /// Fresh keys per the PKWARE spec.
    fn new() -> Self {
        Self {
            k0: 0x1234_5678,
            k1: 0x2345_6789,
            k2: 0x3456_7890,
        }
    }

    /// Mix one byte into all three keys.
    #[inline]
    fn update(&mut self, byte: u8) {
        self.k0 = crc32_step(self.k0, byte);
        // 32-bit wrapping arithmetic; the spec is explicit that the
        // truncation happens at 2^32 per step.
        self.k1 = self
            .k1
            .wrapping_add(self.k0 & 0xFF)
            .wrapping_mul(0x0808_8405)
            .wrapping_add(1);
        self.k2 = crc32_step(self.k2, (self.k1 >> 24) as u8);
    }

    /// Mix every byte of `data` into the keys, in order.
    fn update_all(&mut self, data: &[u8]) {
        for &b in data {
            self.update(b);
        }
    }

    /// Derive the next keystream byte (does NOT advance the keys —
    /// the caller advances them with the recovered plaintext after
    /// XOR-ing).
    #[inline]
    fn stream_byte(&self) -> u8 {
        // `temp` is a u16 in the spec; the `& 0xFFFF` is explicit so
        // we don't drift into wrapping-mul-on-u32 territory.
        let temp = ((self.k2 | 3) & 0xFFFF) as u16;
        // `temp * (temp ^ 1)` overflows a u16 (the spec computes in
        // u32 / u16 ambiguously across implementations; PKWARE
        // reference code uses 16-bit wrapping multiplication which
        // is what we want here).
        let prod = (temp as u32).wrapping_mul((temp ^ 1) as u32);
        ((prod >> 8) & 0xFF) as u8
    }

    /// Decrypt one ciphertext byte and advance the keys.
    #[inline]
    fn decrypt_byte(&mut self, cipher: u8) -> u8 {
        let plain = cipher ^ self.stream_byte();
        self.update(plain);
        plain
    }
}

/// `Read` wrapper that decrypts a single ZipCrypto-protected ZIP
/// entry.
///
/// Constructed from the entry's raw compressed reader, the user's
/// password, the entry's compressed size (from the central directory),
/// and the high byte of the entry's CRC-32 (also from the central
/// directory — the value the encryption header's verifier must match).
pub struct ZipCryptoReader<R: Read> {
    inner: R,
    keys: Keys,
    /// Bytes of ciphertext left after the 12-byte header.
    payload_remaining: u64,
    entry_name: String,
}

impl<R: Read> ZipCryptoReader<R> {
    /// Wrap `inner`, which must yield exactly `compressed_size` bytes
    /// of the ZipCrypto-encrypted entry.
    ///
    /// The 12-byte header is consumed from `inner` immediately and
    /// the password is verified against `crc32_high_byte`. The
    /// verification is **not** constant-time vs. the password: the
    /// PKWARE scheme does not have a cryptographic verifier, and the
    /// timing of decryption-byte work dwarfs any byte compare. See
    /// the module-level note about the scheme's lack of confidentiality.
    ///
    /// # Errors
    ///
    /// - `io::Error` wrapping [`EncryptionError::PasswordIncorrect`]
    ///   when the verifier byte mismatches.
    /// - `io::Error` wrapping [`EncryptionError::IntegrityCheckFailed`]
    ///   when `compressed_size < 12`.
    /// - `io::Error` from short reads on the inner source.
    pub fn new(
        mut inner: R,
        password: &Password,
        compressed_size: u64,
        crc32_high_byte: u8,
        entry_name: &str,
    ) -> io::Result<Self> {
        if compressed_size < HEADER_LEN as u64 {
            return Err(encryption_io(EncryptionError::IntegrityCheckFailed {
                entry_name: entry_name.to_string(),
            }));
        }
        let mut keys = Keys::new();
        keys.update_all(password.as_bytes());

        let mut header = [0u8; HEADER_LEN];
        inner.read_exact(&mut header)?;
        for byte in &mut header {
            *byte = keys.decrypt_byte(*byte);
        }
        // The last header byte must equal the high byte of the
        // recorded CRC-32. The scheme provides no stronger
        // verification; a wrong-password decryption has a 1/256 chance
        // of accidentally passing the check, in which case the
        // downstream CRC32 over the decompressed plaintext catches it.
        if header[HEADER_LEN - 1] != crc32_high_byte {
            return Err(encryption_io(EncryptionError::PasswordIncorrect));
        }

        // One-shot caveat banner per session per archive would
        // require global state; per-entry is acceptable for the rare
        // case of a ZipCrypto archive, and the warning is at info
        // level so it does not flood by default.
        warn!(
            entry = entry_name,
            "ZipCrypto-encrypted entry (1989 PKWARE scheme); peel extracts it but this format \
             provides no real confidentiality — treat the contents as if they had not been \
             encrypted at all",
        );

        Ok(Self {
            inner,
            keys,
            payload_remaining: compressed_size - HEADER_LEN as u64,
            entry_name: entry_name.to_string(),
        })
    }
}

impl<R: Read> Read for ZipCryptoReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.payload_remaining == 0 {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.payload_remaining) as usize;
        let n = self.inner.read(&mut buf[..want])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "ZipCrypto entry {:?}: source EOF with {} payload bytes still owed",
                    self.entry_name, self.payload_remaining,
                ),
            ));
        }
        for byte in &mut buf[..n] {
            *byte = self.keys.decrypt_byte(*byte);
        }
        self.payload_remaining -= n as u64;
        Ok(n)
    }
}

/// Apply the ZipCrypto key-derivation + 12-byte-header check WITHOUT
/// actually constructing a decoding reader.
///
/// Used by the pipeline to verify a candidate password against an
/// entry's encryption header before deciding whether to cache it or
/// re-prompt. The header bytes come from a sparse-file read at the
/// entry's data offset (`compressed_size >= 12` is the caller's
/// responsibility).
///
/// Returns `true` when the decrypted header's verifier byte equals
/// `crc32_high_byte`, `false` otherwise.
#[must_use]
pub fn verify_password(
    password: &Password,
    header: &[u8; HEADER_LEN],
    crc32_high_byte: u8,
) -> bool {
    let mut keys = Keys::new();
    keys.update_all(password.as_bytes());
    let mut decrypted_last = 0u8;
    for &byte in header {
        decrypted_last = keys.decrypt_byte(byte);
    }
    decrypted_last == crc32_high_byte
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use crate::zip::aes_decrypt::downcast_encryption_error;

    /// Encrypt `plaintext` under `password`, producing the on-wire
    /// 12-byte header + ciphertext that `unzip` would write. The
    /// header's leading 11 bytes are taken from `header_salt`
    /// (typically random); the verifier byte is `crc32_high_byte`,
    /// which the consumer cross-checks against the entry's stored
    /// CRC-32.
    fn zipcrypto_encrypt(
        password: &Password,
        plaintext: &[u8],
        header_salt: &[u8; 11],
        crc32_high_byte: u8,
    ) -> Vec<u8> {
        let mut keys = Keys::new();
        keys.update_all(password.as_bytes());

        let mut plain_header = [0u8; HEADER_LEN];
        plain_header[..11].copy_from_slice(header_salt);
        plain_header[11] = crc32_high_byte;

        let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len());
        for &p in &plain_header {
            let c = p ^ keys.stream_byte();
            keys.update(p);
            out.push(c);
        }
        for &p in plaintext {
            let c = p ^ keys.stream_byte();
            keys.update(p);
            out.push(c);
        }
        out
    }

    #[test]
    fn round_trip_short_payload() {
        let pw = Password::new(b"hunter2".to_vec());
        let plaintext = b"the quick brown fox jumps over the lazy dog";
        // Pick a CRC byte we control; in real archives this is the
        // high byte of `ieee(plaintext)`.
        let cipher = zipcrypto_encrypt(&pw, plaintext, &[0xAA; 11], 0x42);

        let mut reader = ZipCryptoReader::new(
            Cursor::new(cipher.clone()),
            &pw,
            cipher.len() as u64,
            0x42,
            "test.bin",
        )
        .expect("construct");
        let mut out = Vec::new();
        reader.read_to_end(&mut out).expect("read");
        assert_eq!(out, plaintext);
    }

    #[test]
    fn round_trip_byte_at_a_time_long_payload() {
        let pw = Password::new(b"correct horse battery staple".to_vec());
        let plaintext: Vec<u8> = (0..(4 * 1024)).map(|i| (i % 251) as u8).collect();
        let cipher = zipcrypto_encrypt(&pw, &plaintext, &[0x11; 11], 0x99);

        let mut reader = ZipCryptoReader::new(
            Cursor::new(cipher.clone()),
            &pw,
            cipher.len() as u64,
            0x99,
            "long.bin",
        )
        .expect("construct");
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
    fn wrong_password_surfaces_password_incorrect() {
        let pw = Password::new(b"hunter2".to_vec());
        let wrong = Password::new(b"hunter3".to_vec());
        let plaintext = b"x";
        let cipher = zipcrypto_encrypt(&pw, plaintext, &[0x33; 11], 0x42);

        // The wrong password produces a different verifier byte
        // 255/256 of the time; pick a CRC byte and verify the
        // constructor refuses.
        let err = match ZipCryptoReader::new(
            Cursor::new(cipher.clone()),
            &wrong,
            cipher.len() as u64,
            0x42,
            "x.bin",
        ) {
            Ok(_) => {
                // 1/256 false positive — try a different salt and
                // retry until it doesn't.
                let mut salt = [0x33u8; 11];
                let mut retries = 8;
                loop {
                    salt[0] = salt[0].wrapping_add(1);
                    let cipher = zipcrypto_encrypt(&pw, plaintext, &salt, 0x42);
                    match ZipCryptoReader::new(
                        Cursor::new(cipher.clone()),
                        &wrong,
                        cipher.len() as u64,
                        0x42,
                        "x.bin",
                    ) {
                        Ok(_) => {
                            retries -= 1;
                            if retries == 0 {
                                panic!("never refused after 8 retries");
                            }
                        }
                        Err(e) => break e,
                    }
                }
            }
            Err(e) => e,
        };
        let inner = downcast_encryption_error(&err).expect("encryption err");
        assert!(matches!(inner, EncryptionError::PasswordIncorrect));
    }

    #[test]
    fn compressed_size_smaller_than_header_errors() {
        let pw = Password::new(b"hunter2".to_vec());
        let envelope = vec![0u8; 5];
        let err = match ZipCryptoReader::new(Cursor::new(envelope), &pw, 5, 0x00, "tiny.bin") {
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
    fn verify_password_accepts_correct_and_rejects_wrong() {
        let pw = Password::new(b"hunter2".to_vec());
        let wrong = Password::new(b"hunter3".to_vec());
        let plaintext = b"hello";
        let cipher = zipcrypto_encrypt(&pw, plaintext, &[0x55; 11], 0x77);
        let mut header = [0u8; HEADER_LEN];
        header.copy_from_slice(&cipher[..HEADER_LEN]);

        assert!(verify_password(&pw, &header, 0x77));
        // 1/256 false positive possible; try a couple of distinct
        // verifier bytes to make a wrong-password reject statistically
        // certain.
        let mut bad = 0u32;
        for ver in 0x00..=0x10u8 {
            if !verify_password(&wrong, &header, ver) {
                bad += 1;
            }
        }
        assert!(bad >= 15, "wrong password should fail nearly always");
    }

    #[test]
    fn keystream_first_bytes_match_pkware_reference_algorithm() {
        // The PKWARE APPNOTE does not publish a fixed KAT, but the
        // algorithm is small enough to recompute from the spec by
        // hand for a short password and known-leading bytes.
        //
        // This test recomputes the first 4 keystream bytes after the
        // password "AB" using the spec verbatim and asserts the
        // implementation matches.
        //
        // Reference computation (each step shown by stepping the
        // algorithm; the `crc32_step` operation is the reflected
        // CRC32 inner-loop transform):
        //
        //   init:   k0=0x12345678 k1=0x23456789 k2=0x34567890
        //   update('A' = 0x41):
        //     k0 = crc32_step(0x12345678, 0x41)
        //     k1 = (k1 + (k0 & 0xFF)) * 0x08088405 + 1
        //     k2 = crc32_step(k2, (k1 >> 24) & 0xFF)
        //   update('B' = 0x42):  same, with the updated keys
        //
        // After the two-byte password feed, the keystream byte is
        // ((temp * (temp ^ 1)) >> 8) & 0xFF where
        // temp = (k2 | 3) & 0xFFFF.
        //
        // We don't hand-publish the resulting bytes (they're
        // implementation-defined intermediate states); instead we
        // pin the *shape* of the inner loop by verifying that
        // running the same sequence through our `Keys` and through
        // a stripped-down spec-literal re-implementation produces
        // identical streams. This catches any future drift in the
        // hot path (wrap-around, mul-modulus, table indexing).
        fn spec_literal_keystream(password: &[u8], plaintext: &[u8]) -> Vec<u8> {
            // Inline copy of the reflected CRC-32 step table over
            // u32, computed at runtime so the spec-literal version
            // shares zero code with `crate::zip::crc32`.
            let mut table = [0u32; 256];
            for (i, slot) in table.iter_mut().enumerate() {
                let mut c = i as u32;
                for _ in 0..8 {
                    c = if c & 1 != 0 {
                        (c >> 1) ^ 0xEDB8_8320
                    } else {
                        c >> 1
                    };
                }
                *slot = c;
            }
            let step = |state: u32, b: u8| -> u32 {
                table[((state ^ u32::from(b)) & 0xFF) as usize] ^ (state >> 8)
            };
            let mut k0 = 0x1234_5678u32;
            let mut k1 = 0x2345_6789u32;
            let mut k2 = 0x3456_7890u32;
            let update = |c: u8, k0: &mut u32, k1: &mut u32, k2: &mut u32| {
                *k0 = step(*k0, c);
                *k1 = k1
                    .wrapping_add(*k0 & 0xFF)
                    .wrapping_mul(0x0808_8405)
                    .wrapping_add(1);
                *k2 = step(*k2, (*k1 >> 24) as u8);
            };
            for &c in password {
                update(c, &mut k0, &mut k1, &mut k2);
            }
            let mut stream = Vec::with_capacity(plaintext.len());
            for &p in plaintext {
                let temp = ((k2 | 3) & 0xFFFF) as u16;
                let prod = (temp as u32).wrapping_mul((temp ^ 1) as u32);
                let kb = ((prod >> 8) & 0xFF) as u8;
                stream.push(kb);
                update(p, &mut k0, &mut k1, &mut k2);
            }
            stream
        }

        let pw = Password::new(b"AB".to_vec());
        let plaintext = b"hello!";
        let mut keys = Keys::new();
        keys.update_all(pw.as_bytes());
        let mut ours = Vec::with_capacity(plaintext.len());
        for &p in plaintext {
            let kb = keys.stream_byte();
            ours.push(kb);
            keys.update(p);
        }

        let theirs = spec_literal_keystream(pw.as_bytes(), plaintext);
        assert_eq!(ours, theirs);
    }
}
