//! AES-CTR and AES-CBC mode wrappers
//! (`internal/PLAN_archive_encryption.md` §2). Layered on top of any
//! [`AesBlockCipher`] from [`super::aes`].
//!
//! # Modes
//!
//! - [`AesCtr`] — CTR (counter) mode. Encryption and decryption are
//!   the same operation (XOR with a key-stream). The counter is a
//!   16-byte block; the caller picks the increment endianness via
//!   [`CounterEndian`]. ZIP-AES (WinZip AE-1/AE-2) uses
//!   [`CounterEndian::Little`] with the counter starting at 1.
//!   RAR5 uses [`CounterEndian::Big`] with a 16-byte IV from the
//!   file's encryption record.
//! - [`AesCbcDecrypt`] — CBC decryption. 7z's per-folder coder
//!   (`06 F1 07 01`) is the only consumer. peel does not implement
//!   CBC encryption — the project doesn't encrypt.
//!
//! Both wrappers operate on borrowed slices and do not buffer past
//! a single block, so they compose cleanly with the streaming
//! `Read` chain in §3 / §5.

use super::aes::{AesBlockCipher, BLOCK_LEN};

/// Direction in which a CTR counter increments.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CounterEndian {
    /// Interpret the 16-byte counter as a 128-bit little-endian
    /// integer (byte 0 carries to byte 1, ...). ZIP-AES.
    Little,
    /// Interpret the 16-byte counter as a 128-bit big-endian
    /// integer (byte 15 carries to byte 14, ...). RAR5, RFC 3686.
    Big,
}

/// AES-CTR streaming cipher.
///
/// CTR is a self-inverse stream cipher: the same operation
/// encrypts and decrypts. Construct with the initial counter
/// block and feed bytes through [`Self::apply_keystream`] in any
/// chunking; the cipher buffers the unused suffix of the current
/// counter-derived keystream block internally so callers can
/// `read(&mut buf)` whatever the source happens to produce.
pub struct AesCtr<'a, C: AesBlockCipher> {
    cipher: &'a C,
    counter: [u8; BLOCK_LEN],
    endian: CounterEndian,
    keystream: [u8; BLOCK_LEN],
    keystream_used: usize,
}

impl<'a, C: AesBlockCipher> AesCtr<'a, C> {
    /// Construct a CTR stream against `cipher`. `initial_counter`
    /// is the 16-byte counter block whose AES encryption forms the
    /// first keystream block; the counter increments as a 128-bit
    /// integer per `endian` after each block.
    pub fn new(cipher: &'a C, initial_counter: [u8; BLOCK_LEN], endian: CounterEndian) -> Self {
        Self {
            cipher,
            counter: initial_counter,
            endian,
            keystream: [0u8; BLOCK_LEN],
            // Force a refill on the first call to `apply_keystream`.
            keystream_used: BLOCK_LEN,
        }
    }

    /// XOR `data` with the next `data.len()` bytes of keystream
    /// in place. May be called any number of times with any
    /// chunking; the cipher internally tracks a partial-keystream
    /// remainder so byte-at-a-time updates produce the same
    /// output as one-shot calls.
    pub fn apply_keystream(&mut self, mut data: &mut [u8]) {
        while !data.is_empty() {
            if self.keystream_used == BLOCK_LEN {
                self.keystream = self.counter;
                self.cipher.encrypt_block(&mut self.keystream);
                self.advance_counter();
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

    fn advance_counter(&mut self) {
        match self.endian {
            CounterEndian::Little => {
                for byte in &mut self.counter {
                    let (next, carry) = byte.overflowing_add(1);
                    *byte = next;
                    if !carry {
                        return;
                    }
                }
            }
            CounterEndian::Big => {
                for byte in self.counter.iter_mut().rev() {
                    let (next, carry) = byte.overflowing_add(1);
                    *byte = next;
                    if !carry {
                        return;
                    }
                }
            }
        }
    }
}

/// AES-CBC decryption.
///
/// 7z stores the IV inline with each encrypted folder's coder
/// header; the decrypted ciphertext is then chained through the
/// rest of the folder's filter graph (LZMA2, BCJ, etc.). This
/// wrapper consumes whole 16-byte ciphertext blocks. Partial
/// trailing blocks are a format error at the call site — CBC has
/// no inherent length signalling.
pub struct AesCbcDecrypt<'a, C: AesBlockCipher> {
    cipher: &'a C,
    prev: [u8; BLOCK_LEN],
}

impl<'a, C: AesBlockCipher> AesCbcDecrypt<'a, C> {
    /// Construct a CBC-decrypt stream against `cipher` with the
    /// per-folder 16-byte initialisation vector.
    pub fn new(cipher: &'a C, iv: [u8; BLOCK_LEN]) -> Self {
        Self { cipher, prev: iv }
    }

    /// Decrypt one 16-byte ciphertext block in place. The caller
    /// must hand whole blocks; if a stream's trailing block is
    /// shorter, the format itself is malformed.
    pub fn decrypt_block(&mut self, block: &mut [u8; BLOCK_LEN]) {
        let saved_ct = *block;
        self.cipher.decrypt_block(block);
        for (b, p) in block.iter_mut().zip(self.prev.iter()) {
            *b ^= *p;
        }
        self.prev = saved_ct;
    }

    /// Decrypt a contiguous slice in place. `data.len()` must be
    /// a multiple of [`BLOCK_LEN`]; panics otherwise (the
    /// invariant is enforced at the call site in §5, where 7z's
    /// folder layout guarantees block-aligned ciphertext).
    pub fn decrypt_blocks(&mut self, data: &mut [u8]) {
        assert_eq!(
            data.len() % BLOCK_LEN,
            0,
            "AES-CBC requires block-aligned ciphertext, got {} bytes",
            data.len(),
        );
        for chunk in data.chunks_exact_mut(BLOCK_LEN) {
            // INVARIANT: `chunks_exact_mut` yields slices of
            // exactly BLOCK_LEN bytes.
            let block: &mut [u8; BLOCK_LEN] = chunk
                .try_into()
                .expect("chunks_exact_mut produces 16-byte chunks");
            self.decrypt_block(block);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::aes::{Aes128, Aes256};

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// NIST SP 800-38A §F.5.1 AES-128-CTR test vector (encrypt
    /// path; decryption is the same operation).
    #[test]
    fn nist_sp800_38a_aes128_ctr_be() {
        let key = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        let init_ctr = unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        let plaintext = unhex(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710",
        ));
        let expected = concat!(
            "874d6191b620e3261bef6864990db6ce",
            "9806f66b7970fdff8617187bb9fffdff",
            "5ae4df3edbd5d35e5b4f09020db03eab",
            "1e031dda2fbe03d1792170a0f3009cee",
        );
        let cipher = Aes128::new(&key);
        let mut ctr = AesCtr::new(&cipher, init_ctr.try_into().unwrap(), CounterEndian::Big);
        let mut buf = plaintext.clone();
        ctr.apply_keystream(&mut buf);
        assert_eq!(hex(&buf), expected);
    }

    /// CTR is self-inverse: applying the same keystream to the
    /// ciphertext yields the plaintext back.
    #[test]
    fn aes_ctr_round_trips() {
        let key = unhex("000102030405060708090a0b0c0d0e0f");
        let init = [0x42u8; 16];
        let cipher = Aes128::new(&key);
        let mut data: Vec<u8> = (0..=255u8).collect();
        let original = data.clone();
        let mut enc = AesCtr::new(&cipher, init, CounterEndian::Big);
        enc.apply_keystream(&mut data);
        assert_ne!(data, original);
        let mut dec = AesCtr::new(&cipher, init, CounterEndian::Big);
        dec.apply_keystream(&mut data);
        assert_eq!(data, original);
    }

    /// Byte-at-a-time `apply_keystream` produces the same output
    /// as one whole-buffer call.
    #[test]
    fn aes_ctr_streaming_invariance() {
        let key = unhex("000102030405060708090a0b0c0d0e0f");
        let init = [0x42u8; 16];
        let cipher = Aes128::new(&key);
        let data: Vec<u8> = (0..200u8).collect();

        let mut a = data.clone();
        AesCtr::new(&cipher, init, CounterEndian::Little).apply_keystream(&mut a);

        let mut b = data.clone();
        let mut ctr = AesCtr::new(&cipher, init, CounterEndian::Little);
        for byte in b.iter_mut() {
            let mut single = [*byte];
            ctr.apply_keystream(&mut single);
            *byte = single[0];
        }
        assert_eq!(a, b);
    }

    /// Little-endian counter increment carries through byte 0.
    /// Start at counter `[0xFF, 0, 0, …]`; after the first block,
    /// the counter advances to `[0, 1, 0, …]` and the second
    /// keystream block matches an independent AES of that counter.
    #[test]
    fn ctr_counter_le_increment_crosses_byte_boundary() {
        let key = [0u8; 16];
        let cipher = Aes128::new(&key);

        let mut ctr1 = [0u8; 16];
        ctr1[0] = 0xFF;
        let mut a = AesCtr::new(&cipher, ctr1, CounterEndian::Little);
        // First block: keystream over fresh zero buffer == AES(ctr1).
        let mut buf_first = [0u8; 16];
        a.apply_keystream(&mut buf_first);
        // Second block: keystream over a fresh zero buffer ==
        // AES(post-increment counter [0, 1, 0, …, 0]).
        let mut buf_second = [0u8; 16];
        a.apply_keystream(&mut buf_second);

        let mut ctr_next = [0u8; 16];
        ctr_next[1] = 1;
        let mut expected_block = ctr_next;
        cipher.encrypt_block(&mut expected_block);
        assert_eq!(buf_second, expected_block);
    }

    /// Big-endian counter increment carries through byte 15.
    #[test]
    fn ctr_counter_be_increment_crosses_byte_boundary() {
        let key = [0u8; 16];
        let cipher = Aes128::new(&key);
        let mut ctr1 = [0u8; 16];
        ctr1[15] = 0xFF;
        let mut a = AesCtr::new(&cipher, ctr1, CounterEndian::Big);
        let mut buf_first = [0u8; 16];
        a.apply_keystream(&mut buf_first);
        let mut buf_second = [0u8; 16];
        a.apply_keystream(&mut buf_second);
        let mut ctr_next = [0u8; 16];
        ctr_next[14] = 1;
        let mut expected_block = ctr_next;
        cipher.encrypt_block(&mut expected_block);
        assert_eq!(buf_second, expected_block);
    }

    /// NIST SP 800-38A §F.2.5 AES-256-CBC decryption test vector.
    #[test]
    fn nist_sp800_38a_aes256_cbc_decrypt() {
        let key = unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let iv = unhex("000102030405060708090a0b0c0d0e0f");
        let ciphertext = unhex(concat!(
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
            "9cfc4e967edb808d679f777bc6702c7d",
            "39f23369a9d9bacfa530e26304231461",
            "b2eb05e2c39be9fcda6c19078c6a9d1b",
        ));
        let expected = concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710",
        );
        let cipher = Aes256::new(&key);
        let mut cbc = AesCbcDecrypt::new(&cipher, iv.try_into().unwrap());
        let mut buf = ciphertext.clone();
        cbc.decrypt_blocks(&mut buf);
        assert_eq!(hex(&buf), expected);
    }

    /// CBC block-at-a-time and slice-at-a-time produce the same
    /// output, exercising the `decrypt_block` API directly.
    #[test]
    fn aes_cbc_block_streaming_invariance() {
        let key = unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let iv: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f")
            .try_into()
            .unwrap();
        let cipher = Aes256::new(&key);
        let ciphertext: Vec<u8> = unhex(concat!(
            "f58c4c04d6e5f1ba779eabfb5f7bfbd6",
            "9cfc4e967edb808d679f777bc6702c7d",
            "39f23369a9d9bacfa530e26304231461",
            "b2eb05e2c39be9fcda6c19078c6a9d1b",
        ));
        let mut buf_a = ciphertext.clone();
        AesCbcDecrypt::new(&cipher, iv).decrypt_blocks(&mut buf_a);
        let mut buf_b = ciphertext.clone();
        let mut cbc = AesCbcDecrypt::new(&cipher, iv);
        for chunk in buf_b.chunks_exact_mut(16) {
            let block: &mut [u8; 16] = chunk.try_into().unwrap();
            cbc.decrypt_block(block);
        }
        assert_eq!(buf_a, buf_b);
    }

    #[test]
    #[should_panic(expected = "AES-CBC requires block-aligned ciphertext")]
    fn aes_cbc_rejects_unaligned_input() {
        let key = [0u8; 16];
        let cipher = Aes128::new(&key);
        let mut buf = [0u8; 17]; // not a multiple of 16
        AesCbcDecrypt::new(&cipher, [0u8; 16]).decrypt_blocks(&mut buf);
    }
}
