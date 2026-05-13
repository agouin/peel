//! FIPS 197 AES-128 / AES-192 / AES-256 block cipher core
//! (`internal/PLAN_archive_encryption.md` §2). The CTR and CBC modes
//! layered on top live in [`super::aes_modes`].
//!
//! # Constant-time discipline
//!
//! This is a table-based ("T-less" — S-box only, no T-tables)
//! implementation. It is **not** fully constant-time: the S-box
//! lookup is a 256-byte memory access whose address depends on
//! input bytes, and modern CPUs cache it. A cache-timing attacker
//! co-located on the same physical core can recover key material;
//! see the threat model in `internal/PLAN_archive_encryption.md` §7.
//! Hardware AES (AES-NI) via a runtime probe is on the roadmap
//! (plan §2 "out of scope" note); when it lands, this module stays
//! as the software fallback.
//!
//! Where timing matters (tag verification, password-verifier
//! comparison), the call sites already route through
//! [`super::ct_eq`].
//!
//! # API shape
//!
//! Three concrete types — [`Aes128`], [`Aes192`], [`Aes256`] —
//! constructed from a key, each exposing the same
//! `encrypt_block` / `decrypt_block` shape. The mode wrappers in
//! [`super::aes_modes`] are generic over a [`AesBlockCipher`]
//! trait the three types share.
//!
//! Cross-checked against the RustCrypto `aes` crate held in
//! `[dev-dependencies]`; see `tests/test_crypto_diff.rs`.

/// FIPS 197 §5.1.1 forward S-box.
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// FIPS 197 §5.1.3 inverse S-box (the inverse of [`SBOX`]).
const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// FIPS 197 §5.2 round constants. Only `RCON[1..]` is used; entry
/// 0 is a placeholder so indices align with the spec.
const RCON: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

/// AES block size in bytes (the standard is fixed at 128 bits).
pub const BLOCK_LEN: usize = 16;

/// Trait every AES key-size shares: a 16-byte block in, a 16-byte
/// block out, in either direction. Used by the mode wrappers in
/// [`super::aes_modes`] so callers can name the key size at
/// compile time.
pub trait AesBlockCipher {
    /// Encrypt one 16-byte block in place.
    fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]);
    /// Decrypt one 16-byte block in place.
    fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]);
}

macro_rules! define_aes {
    ($name:ident, $key_len:expr, $nk:expr, $nr:expr) => {
        /// AES with the documented key size.
        ///
        /// Pre-computes the round key schedule once in
        /// [`Self::new`]; encryption / decryption then just iterate
        /// through it. No interior mutability — safe to share
        /// across threads.
        #[derive(Clone)]
        pub struct $name {
            // (Nr + 1) round keys, each 16 bytes. Stored
            // contiguously so the encrypt/decrypt hot loop indexes
            // by `round * 16`.
            round_keys: [u8; (BLOCK_LEN * ($nr + 1))],
        }

        impl $name {
            /// Key length in bytes for this AES variant.
            pub const KEY_LEN: usize = $key_len;
            /// Number of rounds (10 / 12 / 14 for 128 / 192 / 256).
            pub const ROUNDS: usize = $nr;

            /// Construct a cipher with the documented key.
            ///
            /// # Panics
            /// Panics if `key.len() != Self::KEY_LEN`.
            pub fn new(key: &[u8]) -> Self {
                assert_eq!(
                    key.len(),
                    Self::KEY_LEN,
                    "AES key must be exactly {} bytes",
                    Self::KEY_LEN,
                );
                let mut round_keys = [0u8; BLOCK_LEN * ($nr + 1)];
                key_schedule(key, $nk, $nr, &mut round_keys);
                Self { round_keys }
            }
        }

        impl AesBlockCipher for $name {
            fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
                encrypt_block_impl(&self.round_keys, $nr, block);
            }
            fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]) {
                decrypt_block_impl(&self.round_keys, $nr, block);
            }
        }
    };
}

define_aes!(Aes128, 16, 4, 10);
define_aes!(Aes192, 24, 6, 12);
define_aes!(Aes256, 32, 8, 14);

/// FIPS 197 §5.2 key expansion. Fills `out` with `(nr + 1) * 16`
/// bytes of round keys.
fn key_schedule(key: &[u8], nk: usize, nr: usize, out: &mut [u8]) {
    let total_words = 4 * (nr + 1);
    // Each word is 4 bytes. We store words as `u32` big-endian-on-bytes
    // in the byte buffer; the spec is column-major so word `i` lives at
    // bytes `[i*4 .. i*4+4]` of the round-key block once unrolled.
    let mut words = vec![0u32; total_words];
    for i in 0..nk {
        words[i] = u32::from_be_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    for i in nk..total_words {
        let mut temp = words[i - 1];
        if i % nk == 0 {
            temp = sub_word(rot_word(temp)) ^ ((RCON[i / nk] as u32) << 24);
        } else if nk > 6 && i % nk == 4 {
            temp = sub_word(temp);
        }
        words[i] = words[i - nk] ^ temp;
    }
    for (i, w) in words.iter().enumerate() {
        let b = w.to_be_bytes();
        out[i * 4..i * 4 + 4].copy_from_slice(&b);
    }
}

fn rot_word(w: u32) -> u32 {
    w.rotate_left(8)
}

fn sub_word(w: u32) -> u32 {
    let b = w.to_be_bytes();
    u32::from_be_bytes([
        SBOX[b[0] as usize],
        SBOX[b[1] as usize],
        SBOX[b[2] as usize],
        SBOX[b[3] as usize],
    ])
}

/// FIPS 197 §5.1 encryption: AddRoundKey, then `nr` rounds of
/// (SubBytes, ShiftRows, MixColumns, AddRoundKey), with the final
/// round skipping MixColumns.
fn encrypt_block_impl(round_keys: &[u8], nr: usize, state: &mut [u8; BLOCK_LEN]) {
    add_round_key(state, &round_keys[..BLOCK_LEN]);
    for round in 1..nr {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(
            state,
            &round_keys[round * BLOCK_LEN..(round + 1) * BLOCK_LEN],
        );
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &round_keys[nr * BLOCK_LEN..(nr + 1) * BLOCK_LEN]);
}

/// FIPS 197 §5.3 inverse cipher. Equivalent inverse cipher
/// ordering is also valid (Inv versions of SubBytes/ShiftRows are
/// commutative through Inv MixColumns up to round-key rewrite); we
/// use the straight inverse for simplicity.
fn decrypt_block_impl(round_keys: &[u8], nr: usize, state: &mut [u8; BLOCK_LEN]) {
    add_round_key(state, &round_keys[nr * BLOCK_LEN..(nr + 1) * BLOCK_LEN]);
    inv_shift_rows(state);
    inv_sub_bytes(state);
    for round in (1..nr).rev() {
        add_round_key(
            state,
            &round_keys[round * BLOCK_LEN..(round + 1) * BLOCK_LEN],
        );
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bytes(state);
    }
    add_round_key(state, &round_keys[..BLOCK_LEN]);
}

fn add_round_key(state: &mut [u8; BLOCK_LEN], rk: &[u8]) {
    for i in 0..BLOCK_LEN {
        state[i] ^= rk[i];
    }
}

fn sub_bytes(state: &mut [u8; BLOCK_LEN]) {
    for b in state.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

fn inv_sub_bytes(state: &mut [u8; BLOCK_LEN]) {
    for b in state.iter_mut() {
        *b = INV_SBOX[*b as usize];
    }
}

/// Cyclic left-shift of each row (the state is column-major:
/// bytes 0,4,8,12 are row 0; 1,5,9,13 row 1; etc.). Row 0 shifts
/// by 0; row r shifts by r.
fn shift_rows(s: &mut [u8; BLOCK_LEN]) {
    // Row 1 (bytes 1,5,9,13) shifts left by 1.
    let t = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = t;
    // Row 2 (bytes 2,6,10,14) shifts left by 2.
    s.swap(2, 10);
    s.swap(6, 14);
    // Row 3 (bytes 3,7,11,15) shifts left by 3, == right by 1.
    let t = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = t;
}

fn inv_shift_rows(s: &mut [u8; BLOCK_LEN]) {
    // Row 1 right by 1.
    let t = s[13];
    s[13] = s[9];
    s[9] = s[5];
    s[5] = s[1];
    s[1] = t;
    // Row 2 by 2 (involution).
    s.swap(2, 10);
    s.swap(6, 14);
    // Row 3 right by 3, == left by 1.
    let t = s[3];
    s[3] = s[7];
    s[7] = s[11];
    s[11] = s[15];
    s[15] = t;
}

/// FIPS 197 §4.2.1 / xtime: multiplication by 2 in GF(2^8) with
/// the AES reduction polynomial.
fn xtime(b: u8) -> u8 {
    let hi = (b & 0x80) >> 7;
    // Conditional XOR of 0x1B without a branch: `0x1B & (-hi)` is
    // `0x1B` when `hi == 1` and `0` when `hi == 0`.
    (b << 1) ^ (0x1B & hi.wrapping_neg())
}

fn mix_columns(s: &mut [u8; BLOCK_LEN]) {
    for col in 0..4 {
        let off = col * 4;
        let a0 = s[off];
        let a1 = s[off + 1];
        let a2 = s[off + 2];
        let a3 = s[off + 3];
        let t = a0 ^ a1 ^ a2 ^ a3;
        s[off] ^= t ^ xtime(a0 ^ a1);
        s[off + 1] ^= t ^ xtime(a1 ^ a2);
        s[off + 2] ^= t ^ xtime(a2 ^ a3);
        s[off + 3] ^= t ^ xtime(a3 ^ a0);
    }
}

fn inv_mix_columns(s: &mut [u8; BLOCK_LEN]) {
    // Equivalent to multiplying each column by the inverse mix
    // matrix {0e, 0b, 0d, 09}. Express each multiplication via
    // xtime: 0e = 0x02*0x07, 0b = 0x02*0x05 + 1, 0d = 0x02*0x06 + 1,
    // 09 = 0x02*0x04 + 1. Pre-compute the doubled columns and
    // combine.
    for col in 0..4 {
        let off = col * 4;
        let a = [s[off], s[off + 1], s[off + 2], s[off + 3]];
        let mul = |x: u8, n: u8| -> u8 {
            let mut acc = 0u8;
            let mut base = x;
            let mut k = n;
            while k != 0 {
                if (k & 1) == 1 {
                    acc ^= base;
                }
                base = xtime(base);
                k >>= 1;
            }
            acc
        };
        s[off] = mul(a[0], 0x0e) ^ mul(a[1], 0x0b) ^ mul(a[2], 0x0d) ^ mul(a[3], 0x09);
        s[off + 1] = mul(a[0], 0x09) ^ mul(a[1], 0x0e) ^ mul(a[2], 0x0b) ^ mul(a[3], 0x0d);
        s[off + 2] = mul(a[0], 0x0d) ^ mul(a[1], 0x09) ^ mul(a[2], 0x0e) ^ mul(a[3], 0x0b);
        s[off + 3] = mul(a[0], 0x0b) ^ mul(a[1], 0x0d) ^ mul(a[2], 0x09) ^ mul(a[3], 0x0e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// FIPS 197 Appendix B AES-128 worked example.
    #[test]
    fn aes128_fips197_appendix_b() {
        let key = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        let pt = unhex("3243f6a8885a308d313198a2e0370734");
        let expected_ct = "3925841d02dc09fbdc118597196a0b32";
        let cipher = Aes128::new(&key);
        let mut block: [u8; 16] = pt.try_into().unwrap();
        cipher.encrypt_block(&mut block);
        assert_eq!(hex(&block), expected_ct);
        cipher.decrypt_block(&mut block);
        assert_eq!(hex(&block), "3243f6a8885a308d313198a2e0370734");
    }

    /// FIPS 197 Appendix C.1 AES-128 KAT.
    #[test]
    fn aes128_fips197_appendix_c1() {
        let key = unhex("000102030405060708090a0b0c0d0e0f");
        let pt = unhex("00112233445566778899aabbccddeeff");
        let cipher = Aes128::new(&key);
        let mut block: [u8; 16] = pt.try_into().unwrap();
        cipher.encrypt_block(&mut block);
        assert_eq!(hex(&block), "69c4e0d86a7b0430d8cdb78070b4c55a");
        cipher.decrypt_block(&mut block);
        assert_eq!(hex(&block), "00112233445566778899aabbccddeeff");
    }

    /// FIPS 197 Appendix C.2 AES-192 KAT.
    #[test]
    fn aes192_fips197_appendix_c2() {
        let key = unhex("000102030405060708090a0b0c0d0e0f1011121314151617");
        let pt = unhex("00112233445566778899aabbccddeeff");
        let cipher = Aes192::new(&key);
        let mut block: [u8; 16] = pt.try_into().unwrap();
        cipher.encrypt_block(&mut block);
        assert_eq!(hex(&block), "dda97ca4864cdfe06eaf70a0ec0d7191");
        cipher.decrypt_block(&mut block);
        assert_eq!(hex(&block), "00112233445566778899aabbccddeeff");
    }

    /// FIPS 197 Appendix C.3 AES-256 KAT.
    #[test]
    fn aes256_fips197_appendix_c3() {
        let key = unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let pt = unhex("00112233445566778899aabbccddeeff");
        let cipher = Aes256::new(&key);
        let mut block: [u8; 16] = pt.try_into().unwrap();
        cipher.encrypt_block(&mut block);
        assert_eq!(hex(&block), "8ea2b7ca516745bfeafc49904b496089");
        cipher.decrypt_block(&mut block);
        assert_eq!(hex(&block), "00112233445566778899aabbccddeeff");
    }

    /// MixColumns is its own inverse only when combined with
    /// InvMixColumns; this round-trips a single MixColumns through
    /// InvMixColumns and verifies the identity.
    #[test]
    fn mix_columns_round_trips_through_inverse() {
        let mut state = [
            0xdb, 0x13, 0x53, 0x45, 0xf2, 0x0a, 0x22, 0x5c, 0x01, 0x01, 0x01, 0x01, 0xc6, 0xc6,
            0xc6, 0xc6,
        ];
        let original = state;
        mix_columns(&mut state);
        inv_mix_columns(&mut state);
        assert_eq!(state, original);
    }

    /// SubBytes is its own inverse only when combined with
    /// InvSubBytes; round-trip check.
    #[test]
    fn sub_bytes_round_trips_through_inverse() {
        let mut state = *b"abcdefghijklmnop";
        let original = state;
        sub_bytes(&mut state);
        inv_sub_bytes(&mut state);
        assert_eq!(state, original);
    }

    #[test]
    #[should_panic(expected = "AES key must be exactly 16 bytes")]
    fn aes128_wrong_key_size_panics() {
        let _ = Aes128::new(&[0u8; 15]);
    }

    #[test]
    #[should_panic(expected = "AES key must be exactly 24 bytes")]
    fn aes192_wrong_key_size_panics() {
        let _ = Aes192::new(&[0u8; 16]);
    }

    #[test]
    #[should_panic(expected = "AES key must be exactly 32 bytes")]
    fn aes256_wrong_key_size_panics() {
        let _ = Aes256::new(&[0u8; 24]);
    }
}
