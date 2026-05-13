//! Hand-rolled FIPS 180-4 SHA-1 (`internal/PLAN_archive_encryption.md`
//! §2). SHA-1 is cryptographically broken for collision resistance,
//! but ZIP-AES (the WinZip "AE-1/AE-2" scheme) pins PBKDF2 and the
//! file-data HMAC to SHA-1 by format specification. We implement
//! exactly what the spec asks for; nothing more is exposed.
//!
//! The implementation follows the same `update` / `finalize` shape
//! as [`crate::hash::sha256::Sha256`] and impls
//! [`crate::crypto::BlockHash`] so HMAC and PBKDF2 can be generic
//! over the underlying hash. There is no serialize/deserialize
//! pair here — SHA-1 in this crate is only used for short-lived,
//! single-call digests inside the per-entry decryption pipeline,
//! and crashing mid-PBKDF2 just means re-running the iteration
//! loop (cheap on the iteration counts ZIP-AES uses).
//!
//! Cross-checked against the RustCrypto `sha1` crate held in
//! `[dev-dependencies]`; see `tests/test_crypto_diff.rs`.

use crate::crypto::BlockHash;

/// FIPS 180-4 §5.3.1 initial hash value.
const H0: [u32; 5] = [
    0x6745_2301,
    0xEFCD_AB89,
    0x98BA_DCFE,
    0x1032_5476,
    0xC3D2_E1F0,
];

/// FIPS 180-4 §4.2.1 round constants. Indexed by `t / 20`.
const K: [u32; 4] = [0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xCA62_C1D6];

/// Output digest length in bytes.
pub const DIGEST_LEN: usize = 20;

/// Internal compression-function block size in bytes.
pub const BLOCK_SIZE: usize = 64;

/// Streaming SHA-1 hasher.
///
/// Buffers partial blocks internally; `update` may be called any
/// number of times with any chunking, including byte-at-a-time.
/// `finalize` consumes the hasher and returns the 20-byte digest.
#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    buffer: [u8; BLOCK_SIZE],
    buffer_len: usize,
    bytes_processed: u64,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    /// A fresh SHA-1 hasher with the canonical IV.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: H0,
            buffer: [0u8; BLOCK_SIZE],
            buffer_len: 0,
            bytes_processed: 0,
        }
    }

    /// Feed bytes into the hash.
    pub fn update(&mut self, mut input: &[u8]) {
        // INVARIANT: `bytes_processed` will overflow only for
        // streams ≥ 2^61 bytes; the format-spec inputs are file
        // entries that never come close. We use `wrapping_add` so
        // a degenerate fuzz input doesn't panic, but the length
        // word in `finalize` is computed in bits and will be
        // truncated for streams ≥ 2^61, matching every other
        // SHA-1 impl on the planet.
        self.bytes_processed = self.bytes_processed.wrapping_add(input.len() as u64);

        // Drain the partial-block buffer first.
        if self.buffer_len > 0 {
            let need = BLOCK_SIZE - self.buffer_len;
            let take = need.min(input.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&input[..take]);
            self.buffer_len += take;
            input = &input[take..];
            if self.buffer_len == BLOCK_SIZE {
                let block = self.buffer;
                self.process_block(&block);
                self.buffer_len = 0;
            }
        }

        // Process whole blocks directly out of the input.
        while input.len() >= BLOCK_SIZE {
            let (head, tail) = input.split_at(BLOCK_SIZE);
            // INVARIANT: `head.len() == BLOCK_SIZE` by the split.
            let block: &[u8; BLOCK_SIZE] = head.try_into().expect("split_at preserves length");
            self.process_block(block);
            input = tail;
        }

        // Stash the tail.
        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffer_len = input.len();
        }
    }

    /// Consume the hasher and return the 20-byte digest.
    #[must_use]
    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        // FIPS 180-4 §5.1.1 padding: append 0x80, then enough 0x00
        // bytes to make the message length a multiple of 64, then
        // an 8-byte big-endian bit-count word.
        let bit_len = self.bytes_processed.wrapping_mul(8);

        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;

        // If there isn't room for the 8-byte length word in this
        // block, flush a zero-padded block first.
        if self.buffer_len > BLOCK_SIZE - 8 {
            for b in &mut self.buffer[self.buffer_len..] {
                *b = 0;
            }
            let block = self.buffer;
            self.process_block(&block);
            self.buffer_len = 0;
        }
        for b in &mut self.buffer[self.buffer_len..BLOCK_SIZE - 8] {
            *b = 0;
        }
        self.buffer[BLOCK_SIZE - 8..BLOCK_SIZE].copy_from_slice(&bit_len.to_be_bytes());
        let block = self.buffer;
        self.process_block(&block);

        let mut out = [0u8; DIGEST_LEN];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    fn process_block(&mut self, block: &[u8; BLOCK_SIZE]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];

        for (t, &wt) in w.iter().enumerate() {
            let (f, k) = match t {
                0..=19 => (((b & c) | ((!b) & d)), K[0]),
                20..=39 => ((b ^ c ^ d), K[1]),
                40..=59 => (((b & c) | (b & d) | (c & d)), K[2]),
                _ => ((b ^ c ^ d), K[3]),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wt);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

impl BlockHash for Sha1 {
    const OUTPUT_LEN: usize = DIGEST_LEN;
    const BLOCK_SIZE: usize = BLOCK_SIZE;
    type Output = [u8; DIGEST_LEN];

    fn new() -> Self {
        Self::new()
    }
    fn update(&mut self, data: &[u8]) {
        Self::update(self, data);
    }
    fn finalize(self) -> Self::Output {
        Self::finalize(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 180-1 KAT: SHA-1("abc") = a9993e36...
    #[test]
    fn kat_abc() {
        let d = Sha1::digest(b"abc");
        assert_eq!(hex(&d), "a9993e364706816aba3e25717850c26c9cd0d89d",);
    }

    /// FIPS 180-1 KAT: SHA-1("") = da39a3ee...
    #[test]
    fn kat_empty() {
        let d = Sha1::digest(b"");
        assert_eq!(hex(&d), "da39a3ee5e6b4b0d3255bfef95601890afd80709",);
    }

    /// FIPS 180-1 KAT: SHA-1(56 chars "abcdbcde...") spans two blocks.
    #[test]
    fn kat_two_block_message() {
        let d = Sha1::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
        assert_eq!(hex(&d), "84983e441c3bd26ebaae4aa1f95129e5e54670f1",);
    }

    /// Streaming-update invariance: SHA-1 is independent of the
    /// chunk boundaries that `update` is called with.
    #[test]
    fn streaming_invariance_across_chunk_boundaries() {
        let msg = b"The quick brown fox jumps over the lazy dog";
        let whole = Sha1::digest(msg);
        for chunk in [1usize, 7, 13, 32, 41, 63, 64, 65] {
            let mut h = Sha1::new();
            for piece in msg.chunks(chunk) {
                h.update(piece);
            }
            assert_eq!(h.finalize(), whole, "chunk size {chunk}");
        }
    }

    /// Padding edge: a 55-byte message + 0x80 + 8-byte length fits
    /// in exactly one block.
    #[test]
    fn padding_fills_first_block_at_55_bytes() {
        let msg = vec![b'a'; 55];
        // Just verify it produces a digest matching a streaming run.
        let one_shot = Sha1::digest(&msg);
        let mut h = Sha1::new();
        for c in msg.chunks(7) {
            h.update(c);
        }
        assert_eq!(h.finalize(), one_shot);
    }

    /// Padding edge: a 56-byte message forces a second padding block.
    #[test]
    fn padding_overflows_to_second_block_at_56_bytes() {
        let msg = vec![b'a'; 56];
        let one_shot = Sha1::digest(&msg);
        let mut h = Sha1::new();
        h.update(&msg);
        assert_eq!(h.finalize(), one_shot);
    }

    /// Trait impl uses the same code path as the inherent API.
    #[test]
    fn block_hash_impl_matches_inherent() {
        let msg = b"hello world";
        let inherent = Sha1::digest(msg);
        let mut h = <Sha1 as BlockHash>::new();
        h.update(msg);
        let via_trait = <Sha1 as BlockHash>::finalize(h);
        assert_eq!(inherent, via_trait);
        assert_eq!(<Sha1 as BlockHash>::OUTPUT_LEN, 20);
        assert_eq!(<Sha1 as BlockHash>::BLOCK_SIZE, 64);
    }

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }
}
