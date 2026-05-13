//! Hand-rolled SHA-256 (FIPS 180-4) with serializable mid-stream state.
//!
//! `peel` integrates an integrity-check mode (`PLAN_v2.md` §10) where
//! the user passes the expected SHA-256 of the compressed source on
//! the command line and the binary verifies the assembled bytes
//! incrementally as the decoder consumes them. To make that hash
//! survive a `kill -9` and a subsequent resume, the hasher's internal
//! state has to be serializable into the [`crate::checkpoint::Checkpoint`]
//! and round-trip back into a working hasher on the next run.
//!
//! The upstream `sha2` crate does not expose its internal state for
//! serialization; getting at it would require `unsafe` transmutes
//! against private fields. Hand-rolling is short — the FIPS 180-4
//! reference is on the order of 150 lines of straightforward integer
//! work — and pure-Rust SHA-256 measures 300–500 MiB/s on a single
//! core, which is well above the network-bound ceiling `peel`
//! operates under, so the asm/AVX2 acceleration `sha2` would buy us
//! is irrelevant in practice.
//!
//! `sha2` lives in `[dev-dependencies]` only: tests cross-check this
//! implementation against it for correctness, but the runtime binary
//! does not link it (see `internal/ENGINEERING_STANDARDS.md` §2.2).
//!
//! # Wire format
//!
//! [`Sha256::serialize`] produces a fixed-size [`SERIALIZED_LEN`]-byte
//! blob with this layout:
//!
//! ```text
//! offset  size  field
//!   0      32   state[0..8]            // little-endian u32 each
//!  32      64   buffer                 // raw bytes; only the first
//!                                       // buffer_len are meaningful
//!  96       8   bytes_processed (u64 LE)
//! 104       1   buffer_len (u8)
//! ```
//!
//! The format is deliberately independent of the in-memory struct
//! layout so the checkpoint stays stable across compiler versions
//! and target endianness. Multi-byte integers are little-endian
//! (matching the rest of the checkpoint format) even though SHA-256
//! itself processes blocks in big-endian order — that endianness
//! conversion happens inside [`Sha256::process_block`] and is not
//! observable on the wire.

use thiserror::Error;

/// FIPS 180-4 §5.3.3 initial hash value.
///
/// These eight 32-bit words are the fractional parts of the square
/// roots of the first eight primes, each multiplied by `2^32` and
/// truncated.
const H0: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

/// FIPS 180-4 §4.2.2 round constants.
///
/// The fractional parts of the cube roots of the first 64 primes,
/// each multiplied by `2^32` and truncated.
const K: [u32; 64] = [
    0x428A_2F98,
    0x7137_4491,
    0xB5C0_FBCF,
    0xE9B5_DBA5,
    0x3956_C25B,
    0x59F1_11F1,
    0x923F_82A4,
    0xAB1C_5ED5,
    0xD807_AA98,
    0x1283_5B01,
    0x2431_85BE,
    0x550C_7DC3,
    0x72BE_5D74,
    0x80DE_B1FE,
    0x9BDC_06A7,
    0xC19B_F174,
    0xE49B_69C1,
    0xEFBE_4786,
    0x0FC1_9DC6,
    0x240C_A1CC,
    0x2DE9_2C6F,
    0x4A74_84AA,
    0x5CB0_A9DC,
    0x76F9_88DA,
    0x983E_5152,
    0xA831_C66D,
    0xB003_27C8,
    0xBF59_7FC7,
    0xC6E0_0BF3,
    0xD5A7_9147,
    0x06CA_6351,
    0x1429_2967,
    0x27B7_0A85,
    0x2E1B_2138,
    0x4D2C_6DFC,
    0x5338_0D13,
    0x650A_7354,
    0x766A_0ABB,
    0x81C2_C92E,
    0x9272_2C85,
    0xA2BF_E8A1,
    0xA81A_664B,
    0xC24B_8B70,
    0xC76C_51A3,
    0xD192_E819,
    0xD699_0624,
    0xF40E_3585,
    0x106A_A070,
    0x19A4_C116,
    0x1E37_6C08,
    0x2748_774C,
    0x34B0_BCB5,
    0x391C_0CB3,
    0x4ED8_AA4A,
    0x5B9C_CA4F,
    0x682E_6FF3,
    0x748F_82EE,
    0x78A5_636F,
    0x84C8_7814,
    0x8CC7_0208,
    0x90BE_FFFA,
    0xA450_6CEB,
    0xBEF9_A3F7,
    0xC671_78F2,
];

/// Block size in bytes. SHA-256 operates on 512-bit chunks.
const BLOCK_BYTES: usize = 64;

/// Length, in bytes, of [`Sha256::serialize`] output and the buffer
/// passed to [`Sha256::deserialize`].
///
/// The format is fully described in the [module docs](self).
pub const SERIALIZED_LEN: usize = 105;

/// Length, in bytes, of a final SHA-256 digest.
pub const DIGEST_LEN: usize = 32;

/// Errors produced by [`Sha256::deserialize`] and [`parse_hex_digest`].
#[derive(Debug, Error)]
pub enum Sha256DeserializeError {
    /// The serialized form recorded a `buffer_len` that exceeds the
    /// 64-byte block size. Either the bytes were corrupted in transit
    /// or the producer wrote an out-of-spec value.
    #[error("serialized SHA-256 state has invalid buffer_len {value} (must be < 64)")]
    InvalidBufferLen {
        /// The out-of-range value as it appeared on the wire.
        value: u8,
    },
}

/// Errors produced by [`parse_hex_digest`].
#[derive(Debug, Error)]
pub enum ParseHexDigestError {
    /// The input string had the wrong length.
    #[error("expected {expected} hex characters, got {got}")]
    BadLength {
        /// The expected character count (always 64 for a SHA-256
        /// digest).
        expected: usize,
        /// The actual character count we observed.
        got: usize,
    },

    /// The input contained a character that wasn't `[0-9a-fA-F]`.
    #[error("invalid hex character {ch:?} at position {position}")]
    BadCharacter {
        /// The offending character.
        ch: char,
        /// Zero-indexed position within the input string.
        position: usize,
    },
}

/// Streaming SHA-256 hasher with a serializable mid-stream state.
///
/// The hasher consumes byte slices via [`Self::update`] and produces
/// a final 32-byte digest via [`Self::finalize`]. Between updates the
/// state can be serialized with [`Self::serialize`] and restored later
/// with [`Self::deserialize`]; resuming a hash from the saved state
/// and feeding the *remaining* bytes produces a digest byte-identical
/// to a clean run that fed all bytes in one pass.
///
/// # Examples
///
/// ```
/// use peel::hash::sha256::Sha256;
///
/// let mut h = Sha256::new();
/// h.update(b"abc");
/// // FIPS 180-4 SHA-256("abc") test vector.
/// let digest = h.finalize();
/// assert_eq!(
///     digest,
///     [
///         0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE,
///         0x5D, 0xAE, 0x22, 0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C,
///         0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD,
///     ]
/// );
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Sha256 {
    /// Eight 32-bit working state words, mutated in place by each
    /// processed block.
    state: [u32; 8],
    /// Accumulator for partial blocks. Only the first `buffer_len`
    /// bytes are meaningful at any instant; the rest are stale data
    /// from prior writes that don't affect correctness.
    buffer: [u8; BLOCK_BYTES],
    /// Bytes currently buffered in [`Self::buffer`]. Invariant:
    /// `buffer_len < BLOCK_BYTES` outside of the inner update loop;
    /// when it would reach the block size, the block is processed
    /// and `buffer_len` is reset to zero before returning.
    buffer_len: u8,
    /// Total bytes consumed by [`Self::update`] over the lifetime of
    /// this hasher (including bytes still in `buffer` and bytes from
    /// any pre-deserialization state). Used to compute the bit length
    /// the FIPS 180-4 padding step appends to the final block.
    bytes_processed: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Create a fresh hasher with the FIPS 180-4 initial hash value.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: H0,
            buffer: [0; BLOCK_BYTES],
            buffer_len: 0,
            bytes_processed: 0,
        }
    }

    /// Total bytes consumed by [`Self::update`] over the lifetime of
    /// this hasher.
    ///
    /// Diagnostic only — equality of two hashers' digests does not
    /// require equality of this counter (different chunkings of the
    /// same input are equivalent).
    #[must_use]
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }

    /// Feed `input` into the hasher.
    ///
    /// Calling `update` with any sequence of slices whose
    /// concatenation is `X` is equivalent to a single `update(X)`:
    /// chunking is observationally invisible.
    pub fn update(&mut self, mut input: &[u8]) {
        // Track total length up front; FIPS 180-4 padding needs the
        // pre-finalize byte total. We use `wrapping_add` because the
        // counter is u64 and overflow only happens beyond 16 EiB of
        // input — outside any realistic peel use case, but
        // saturating would silently wedge the hash if it ever did.
        // The spec is undefined past 2^64 - 1 bits of input anyway.
        self.bytes_processed = self.bytes_processed.wrapping_add(input.len() as u64);

        let mut buffer_len = self.buffer_len as usize;

        // 1) Drain any partially-filled buffer first.
        if buffer_len > 0 {
            let want = BLOCK_BYTES - buffer_len;
            let take = input.len().min(want);
            self.buffer[buffer_len..buffer_len + take].copy_from_slice(&input[..take]);
            buffer_len += take;
            input = &input[take..];
            if buffer_len == BLOCK_BYTES {
                let block = self.buffer;
                self.process_block(&block);
                buffer_len = 0;
            }
        }

        // 2) Process whole blocks straight from the caller's slice
        //    (no copy through the buffer when we have ≥64 bytes
        //    available).
        while input.len() >= BLOCK_BYTES {
            // INVARIANT: `input.len() >= BLOCK_BYTES` so the first
            // `BLOCK_BYTES`-element subslice is in bounds.
            let mut block = [0u8; BLOCK_BYTES];
            block.copy_from_slice(&input[..BLOCK_BYTES]);
            self.process_block(&block);
            input = &input[BLOCK_BYTES..];
        }

        // 3) Stash the trailing remainder for the next call.
        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            buffer_len = input.len();
        }
        // INVARIANT: by construction `buffer_len < BLOCK_BYTES`
        // (256 > BLOCK_BYTES so the cast is lossless).
        self.buffer_len = buffer_len as u8;
    }

    /// Consume the hasher and produce the final 32-byte digest.
    ///
    /// Performs the FIPS 180-4 padding step: append `0x80`, fill with
    /// zeros up to 8 bytes before the block boundary, then append the
    /// big-endian total bit count as a 64-bit field.
    #[must_use]
    pub fn finalize(mut self) -> [u8; DIGEST_LEN] {
        let total_bits = self.bytes_processed.wrapping_mul(8);

        // INVARIANT (`update` post-condition): `buffer_len < BLOCK_BYTES`,
        // so writing one more byte at `buffer_len` is in bounds.
        let len = self.buffer_len as usize;
        self.buffer[len] = 0x80;

        if len + 1 > BLOCK_BYTES - 8 {
            // Not enough room for the 8-byte length in the current
            // block: zero-fill and process, then continue with a
            // fresh zeroed block for the length suffix.
            for byte in &mut self.buffer[len + 1..BLOCK_BYTES] {
                *byte = 0;
            }
            let block = self.buffer;
            self.process_block(&block);
            self.buffer = [0; BLOCK_BYTES];
        } else {
            for byte in &mut self.buffer[len + 1..BLOCK_BYTES - 8] {
                *byte = 0;
            }
        }

        self.buffer[BLOCK_BYTES - 8..].copy_from_slice(&total_bits.to_be_bytes());
        let block = self.buffer;
        self.process_block(&block);

        let mut out = [0u8; DIGEST_LEN];
        for (i, &word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        out
    }

    /// FIPS 180-4 §6.2.2 compression. Mutates `state` in place.
    fn process_block(&mut self, block: &[u8; BLOCK_BYTES]) {
        let mut w = [0u32; 64];

        // Step 1: prepare the message schedule.
        for i in 0..16 {
            // INVARIANT: i in 0..16, so `i*4..i*4+4 <= 64 = BLOCK_BYTES`.
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        // Step 2: initialize the eight working variables from the
        // current state.
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;

        // Step 3: 64 compression rounds.
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        // Step 4: feed the working variables back into the running
        // state.
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    /// Serialize the hasher's state to a fixed-size byte array.
    ///
    /// The output's layout is documented in the [module docs](self).
    /// Pair with [`Self::deserialize`] to round-trip across a
    /// process boundary.
    #[must_use]
    pub fn serialize(&self) -> [u8; SERIALIZED_LEN] {
        let mut out = [0u8; SERIALIZED_LEN];
        for (i, &word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out[32..96].copy_from_slice(&self.buffer);
        out[96..104].copy_from_slice(&self.bytes_processed.to_le_bytes());
        out[104] = self.buffer_len;
        out
    }

    /// Reconstruct a hasher from the bytes produced by
    /// [`Self::serialize`].
    ///
    /// # Errors
    ///
    /// Returns [`Sha256DeserializeError::InvalidBufferLen`] when the
    /// stored `buffer_len` is at or above the block size — the only
    /// invariant the wire format can violate without becoming
    /// shorter or longer than [`SERIALIZED_LEN`].
    pub fn deserialize(bytes: &[u8; SERIALIZED_LEN]) -> Result<Self, Sha256DeserializeError> {
        let mut state = [0u32; 8];
        for (i, slot) in state.iter_mut().enumerate() {
            // INVARIANT: i in 0..8, so `i*4..i*4+4 <= 32` is in
            // bounds for `bytes`.
            let mut word = [0u8; 4];
            word.copy_from_slice(&bytes[i * 4..i * 4 + 4]);
            *slot = u32::from_le_bytes(word);
        }
        let mut buffer = [0u8; BLOCK_BYTES];
        buffer.copy_from_slice(&bytes[32..96]);
        let mut bp = [0u8; 8];
        bp.copy_from_slice(&bytes[96..104]);
        let bytes_processed = u64::from_le_bytes(bp);
        let buffer_len = bytes[104];

        if (buffer_len as usize) >= BLOCK_BYTES {
            return Err(Sha256DeserializeError::InvalidBufferLen { value: buffer_len });
        }

        Ok(Self {
            state,
            buffer,
            buffer_len,
            bytes_processed,
        })
    }
}

/// Parse a 64-character lowercase / mixed-case ASCII hex string into
/// a SHA-256 digest.
///
/// Spaces, `0x` prefixes, and other formatting are not accepted —
/// the input must be exactly 64 hex characters.
///
/// # Errors
///
/// See [`ParseHexDigestError`].
pub fn parse_hex_digest(s: &str) -> Result<[u8; DIGEST_LEN], ParseHexDigestError> {
    if s.len() != DIGEST_LEN * 2 {
        return Err(ParseHexDigestError::BadLength {
            expected: DIGEST_LEN * 2,
            got: s.len(),
        });
    }
    let mut out = [0u8; DIGEST_LEN];
    let bytes = s.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = decode_nibble(bytes[i * 2], i * 2)?;
        let lo = decode_nibble(bytes[i * 2 + 1], i * 2 + 1)?;
        *slot = (hi << 4) | lo;
    }
    Ok(out)
}

fn decode_nibble(b: u8, position: usize) -> Result<u8, ParseHexDigestError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(ParseHexDigestError::BadCharacter {
            ch: char::from(b),
            position,
        }),
    }
}

/// Format a SHA-256 digest as a 64-character lowercase hex string.
///
/// Convenience helper used by error messages so a mismatch surfaces
/// expected vs. observed in a copy-pasteable form.
#[must_use]
pub fn format_hex_digest(digest: &[u8; DIGEST_LEN]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(DIGEST_LEN * 2);
    for &b in digest {
        out.push(char::from(HEX[(b >> 4) as usize]));
        out.push(char::from(HEX[(b & 0x0F) as usize]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 180-4 byte-string test vector: SHA-256("abc").
    const ABC_DIGEST: [u8; 32] = [
        0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22,
        0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00,
        0x15, 0xAD,
    ];

    /// FIPS 180-4 byte-string test vector: SHA-256(empty string).
    const EMPTY_DIGEST: [u8; 32] = [
        0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9,
        0x24, 0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52,
        0xB8, 0x55,
    ];

    /// FIPS 180-4 byte-string test vector: SHA-256("abcdbcdec...nopq" — the
    /// 56-byte two-block example from the spec appendix).
    const TWO_BLOCK_INPUT: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const TWO_BLOCK_DIGEST: [u8; 32] = [
        0x24, 0x8D, 0x6A, 0x61, 0xD2, 0x06, 0x38, 0xB8, 0xE5, 0xC0, 0x26, 0x93, 0x0C, 0x3E, 0x60,
        0x39, 0xA3, 0x3C, 0xE4, 0x59, 0x64, 0xFF, 0x21, 0x67, 0xF6, 0xEC, 0xED, 0xD4, 0x19, 0xDB,
        0x06, 0xC1,
    ];

    #[test]
    fn hashes_empty_input() {
        assert_eq!(Sha256::new().finalize(), EMPTY_DIGEST);
    }

    #[test]
    fn hashes_abc() {
        let mut h = Sha256::new();
        h.update(b"abc");
        assert_eq!(h.finalize(), ABC_DIGEST);
    }

    #[test]
    fn hashes_two_block_fips_vector() {
        let mut h = Sha256::new();
        h.update(TWO_BLOCK_INPUT);
        assert_eq!(h.finalize(), TWO_BLOCK_DIGEST);
    }

    #[test]
    fn hashes_million_a_fips_long_vector() {
        // FIPS 180-4 longer vector: 1,000,000 'a' bytes.
        // Expected digest is published in the spec.
        let mut h = Sha256::new();
        let chunk = vec![b'a'; 4096];
        let total = 1_000_000usize;
        let mut written = 0usize;
        while written < total {
            let take = chunk.len().min(total - written);
            h.update(&chunk[..take]);
            written += take;
        }
        let digest = h.finalize();
        let expected: [u8; 32] = [
            0xCD, 0xC7, 0x6E, 0x5C, 0x99, 0x14, 0xFB, 0x92, 0x81, 0xA1, 0xC7, 0xE2, 0x84, 0xD7,
            0x3E, 0x67, 0xF1, 0x80, 0x9A, 0x48, 0xA4, 0x97, 0x20, 0x0E, 0x04, 0x6D, 0x39, 0xCC,
            0xC7, 0x11, 0x2C, 0xD0,
        ];
        assert_eq!(digest, expected);
    }

    #[test]
    fn hashes_55_byte_padding_edge_case() {
        // 55 bytes is the largest input where the 0x80 padding byte
        // and the 8-byte length still fit in the same final block.
        let input = vec![0xA5u8; 55];
        let mut h = Sha256::new();
        h.update(&input);
        let ours = h.finalize();
        // Cross-check: feed all bytes one by one; result must be
        // the same.
        let mut h2 = Sha256::new();
        for b in &input {
            h2.update(std::slice::from_ref(b));
        }
        assert_eq!(ours, h2.finalize());
    }

    #[test]
    fn hashes_56_byte_padding_edge_case() {
        // 56 bytes triggers the two-block padding path.
        let input = vec![0x5Au8; 56];
        let mut h = Sha256::new();
        h.update(&input);
        let ours = h.finalize();
        let mut h2 = Sha256::new();
        h2.update(&input[..32]);
        h2.update(&input[32..]);
        assert_eq!(ours, h2.finalize());
    }

    /// Hand-rolled LCG, used by the property tests (matches the
    /// pattern in `crate::types::tests` etc.).
    struct Lcg(u64);

    impl Lcg {
        fn seeded(seed: u64) -> Self {
            Self(seed ^ 0x9E37_79B9_7F4A_7C15)
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }
        fn next_byte(&mut self) -> u8 {
            (self.next_u64() >> 56) as u8
        }
        fn next_bounded(&mut self, max: usize) -> usize {
            // `max` capped well below u64 range; modulo bias
            // negligible for test inputs.
            (self.next_u64() % (max as u64)) as usize
        }
    }

    fn random_bytes(rng: &mut Lcg, len: usize) -> Vec<u8> {
        (0..len).map(|_| rng.next_byte()).collect()
    }

    #[test]
    fn chunking_invariance_at_every_boundary() {
        // For each input length `n` in [0, 130], hashing the same
        // bytes split at every possible boundary must yield the same
        // digest as hashing them in one pass. This catches buffer
        // bookkeeping bugs around the 55/56-byte padding edge and
        // the 64-byte block boundary.
        let mut rng = Lcg::seeded(0xCAFE_F00D);
        for n in 0..=130 {
            let input = random_bytes(&mut rng, n);
            let mut h_full = Sha256::new();
            h_full.update(&input);
            let want = h_full.finalize();

            for split in 0..=n {
                let mut h = Sha256::new();
                h.update(&input[..split]);
                h.update(&input[split..]);
                assert_eq!(h.finalize(), want, "n={n} split={split}");
            }
        }
    }

    #[test]
    fn serialize_deserialize_round_trip_mid_stream() {
        let mut rng = Lcg::seeded(0xBADC_0FFEE);
        for trial in 0..32 {
            let total_len = rng.next_bounded(8 * 1024);
            let split = rng.next_bounded(total_len.max(1));
            let input = random_bytes(&mut rng, total_len);

            let mut clean = Sha256::new();
            clean.update(&input);
            let want = clean.finalize();

            let mut paused = Sha256::new();
            paused.update(&input[..split]);
            let serialized = paused.serialize();
            let mut resumed = Sha256::deserialize(&serialized).expect("round-trip");
            resumed.update(&input[split..]);
            let got = resumed.finalize();

            assert_eq!(
                got, want,
                "trial={trial} total_len={total_len} split={split}"
            );
        }
    }

    #[test]
    fn deserialize_rejects_invalid_buffer_len() {
        // Build a valid serialization, then poke an out-of-range
        // buffer_len. The deserializer must surface
        // `InvalidBufferLen` rather than silently accept it (and
        // later panic in `update`'s slice indexing).
        let mut bytes = Sha256::new().serialize();
        bytes[104] = 64; // == BLOCK_BYTES, must reject
        match Sha256::deserialize(&bytes).unwrap_err() {
            Sha256DeserializeError::InvalidBufferLen { value } => assert_eq!(value, 64),
        }
        // A larger value also rejects.
        bytes[104] = 200;
        match Sha256::deserialize(&bytes).unwrap_err() {
            Sha256DeserializeError::InvalidBufferLen { value } => assert_eq!(value, 200),
        }
    }

    #[test]
    fn serialize_layout_is_stable() {
        // Pin the byte layout so a future "I'll just rearrange the
        // serializer" change is caught loudly. The fresh hasher has
        // state = H0, buffer = zeroes, bytes_processed = 0,
        // buffer_len = 0; the produced bytes are entirely
        // predictable.
        let bytes = Sha256::new().serialize();
        // First 32 bytes: H0 in little-endian u32 order.
        for (i, expected) in H0.iter().enumerate() {
            let got = u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
            assert_eq!(got, *expected, "state[{i}]");
        }
        // 32..96: zeroed buffer.
        assert!(bytes[32..96].iter().all(|&b| b == 0));
        // 96..104: bytes_processed = 0.
        assert_eq!(&bytes[96..104], &[0u8; 8]);
        // 104: buffer_len = 0.
        assert_eq!(bytes[104], 0);
    }

    #[test]
    fn parse_hex_digest_round_trips() {
        let bytes = ABC_DIGEST;
        let hex = format_hex_digest(&bytes);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
        let back = parse_hex_digest(&hex).expect("round-trip");
        assert_eq!(back, bytes);
    }

    #[test]
    fn parse_hex_digest_accepts_uppercase_and_mixed_case() {
        let lower = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let upper = lower.to_ascii_uppercase();
        let mixed: String = lower
            .chars()
            .enumerate()
            .map(|(i, c)| {
                if i % 2 == 0 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            })
            .collect();
        let want = ABC_DIGEST;
        assert_eq!(parse_hex_digest(lower).expect("lower"), want);
        assert_eq!(parse_hex_digest(&upper).expect("upper"), want);
        assert_eq!(parse_hex_digest(&mixed).expect("mixed"), want);
    }

    #[test]
    fn parse_hex_digest_rejects_wrong_length() {
        match parse_hex_digest("abc").unwrap_err() {
            ParseHexDigestError::BadLength { expected, got } => {
                assert_eq!(expected, 64);
                assert_eq!(got, 3);
            }
            other => panic!("expected BadLength, got {other:?}"),
        }
    }

    #[test]
    fn parse_hex_digest_rejects_non_hex_character() {
        let mut bad = "0".repeat(64);
        bad.replace_range(7..8, "Z");
        match parse_hex_digest(&bad).unwrap_err() {
            ParseHexDigestError::BadCharacter { ch, position } => {
                assert_eq!(ch, 'Z');
                assert_eq!(position, 7);
            }
            other => panic!("expected BadCharacter, got {other:?}"),
        }
    }

    #[test]
    fn bytes_processed_counts_all_updates() {
        let mut h = Sha256::new();
        assert_eq!(h.bytes_processed(), 0);
        h.update(&[0u8; 17]);
        assert_eq!(h.bytes_processed(), 17);
        h.update(&[0u8; 200]);
        assert_eq!(h.bytes_processed(), 217);
    }

    /// Cross-check 256 random inputs against the `sha2` crate
    /// (dev-dependency only, per `internal/ENGINEERING_STANDARDS.md` §2.2).
    /// FIPS vectors above pin the trivial cases; this catches anything
    /// the canonical vectors miss.
    #[test]
    fn matches_sha2_crate_for_random_inputs() {
        use sha2::Digest;
        let mut rng = Lcg::seeded(0xDEAD_BEEF_DEAD_BEEF);
        for _ in 0..256 {
            let len = rng.next_bounded(4 * 1024 + 1);
            let input = random_bytes(&mut rng, len);
            let mut ours = Sha256::new();
            ours.update(&input);
            let mine = ours.finalize();

            let mut reference = sha2::Sha256::new();
            reference.update(&input);
            let theirs: [u8; 32] = reference.finalize().into();

            assert_eq!(mine, theirs, "len={len}");
        }
    }
}
