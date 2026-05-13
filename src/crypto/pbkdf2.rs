//! PBKDF2-HMAC (RFC 8018 §5.2) generic over any
//! [`crate::crypto::BlockHash`]
//! (`internal/PLAN_archive_encryption.md` §2).
//!
//! Two instantiations are used by peel today:
//!
//! - PBKDF2-HMAC-SHA1 with a fixed 1000 iterations and the per-entry
//!   salt for ZIP-AES (WinZip AE-1/AE-2).
//! - PBKDF2-HMAC-SHA256 with `1 << (kdf_count + 15)` iterations
//!   (header-supplied, capped at 24 = 2^39) for RAR5 key derivation.
//!
//! The iteration count is fully under the caller's control; this
//! module deliberately picks no "sensible default" — the format
//! dictates it, and second-guessing produces wrong keys.
//!
//! Cross-checked against the RustCrypto `pbkdf2` crate held in
//! `[dev-dependencies]`.

use crate::crypto::hmac::Hmac;
use crate::crypto::BlockHash;

/// Derive `out.len()` bytes via PBKDF2-HMAC-`H`.
///
/// # Parameters
///
/// - `password`: the user's password bytes (or the post-KDF master
///   key in nested-derivation schemes).
/// - `salt`: the per-entry / per-archive salt from the format
///   metadata.
/// - `iterations`: iteration count. **Must be ≥ 1**; the spec
///   technically permits any positive value, and the function does
///   *not* refuse small values because the format-spec invariant
///   sits at the call site (ZIP-AES requires exactly 1000; RAR5
///   requires `1 << (kdf_count + 15)`).
/// - `out`: output buffer. May be of any length; the function
///   produces `ceil(out.len() / H::OUTPUT_LEN)` derivation blocks
///   and copies the prefix into `out`. Maximum `dk_len` per RFC
///   8018 is `(2^32 - 1) * h_len`, which we enforce.
///
/// # Panics
///
/// Panics if `iterations == 0` (the spec defines the function only
/// for `c ≥ 1`; `c = 0` would silently return the salt unchanged,
/// which is almost certainly a caller bug). Also panics if
/// `out.len()` exceeds the RFC 8018 maximum derivation length.
pub fn pbkdf2_hmac<H: BlockHash>(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    assert!(iterations >= 1, "PBKDF2 iterations must be ≥ 1");
    let h_len = H::OUTPUT_LEN;
    // RFC 8018 §5.2: derivable length is at most (2^32 - 1) * hLen.
    // We assert because exceeding it indicates a caller bug (no
    // format under peel asks for anywhere near this much output).
    let max_len = (u32::MAX as usize).saturating_mul(h_len);
    assert!(
        out.len() <= max_len,
        "PBKDF2 output exceeds RFC 8018 maximum ({} > {})",
        out.len(),
        max_len,
    );

    let blocks = out.len().div_ceil(h_len);
    let mut block = vec![0u8; h_len];
    let mut prev = vec![0u8; h_len];
    for i in 1..=blocks {
        // U_1 = HMAC(P, S || INT(i)). `INT(i)` is i big-endian over
        // 4 bytes.
        let mut hmac = Hmac::<H>::new(password);
        hmac.update(salt);
        hmac.update(&(i as u32).to_be_bytes());
        let u1 = hmac.finalize();
        let u1_bytes = u1.as_ref();
        // T_i = U_1
        block.copy_from_slice(u1_bytes);
        prev.copy_from_slice(u1_bytes);

        // T_i ^= U_2 ^ U_3 ^ ... ^ U_c
        for _ in 1..iterations {
            let mut hmac = Hmac::<H>::new(password);
            hmac.update(&prev);
            let u = hmac.finalize();
            let u_bytes = u.as_ref();
            for (b, x) in block.iter_mut().zip(u_bytes.iter()) {
                *b ^= *x;
            }
            prev.copy_from_slice(u_bytes);
        }

        // Copy this block's contribution into out.
        let dst_start = (i - 1) * h_len;
        let dst_end = (dst_start + h_len).min(out.len());
        let copy_len = dst_end - dst_start;
        out[dst_start..dst_end].copy_from_slice(&block[..copy_len]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha1::Sha1;
    use crate::hash::sha256::Sha256;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RFC 6070 §2 PBKDF2-HMAC-SHA1 test vector 1.
    #[test]
    fn rfc6070_sha1_case_1() {
        let mut out = [0u8; 20];
        pbkdf2_hmac::<Sha1>(b"password", b"salt", 1, &mut out);
        assert_eq!(hex(&out), "0c60c80f961f0e71f3a9b524af6012062fe037a6");
    }

    /// RFC 6070 §2 PBKDF2-HMAC-SHA1 test vector 2.
    #[test]
    fn rfc6070_sha1_case_2() {
        let mut out = [0u8; 20];
        pbkdf2_hmac::<Sha1>(b"password", b"salt", 2, &mut out);
        assert_eq!(hex(&out), "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
    }

    /// RFC 6070 §2 PBKDF2-HMAC-SHA1 test vector 4 — 4096 iterations,
    /// 25-byte output spanning two derivation blocks.
    #[test]
    fn rfc6070_sha1_case_4_25_byte_two_block_output() {
        let mut out = [0u8; 25];
        pbkdf2_hmac::<Sha1>(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            &mut out,
        );
        assert_eq!(
            hex(&out),
            "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
        );
    }

    /// RFC 7914 §11 PBKDF2-HMAC-SHA256 test vector 1.
    #[test]
    fn rfc7914_sha256_case_1() {
        let mut out = [0u8; 64];
        pbkdf2_hmac::<Sha256>(b"passwd", b"salt", 1, &mut out);
        assert_eq!(
            hex(&out),
            "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
             49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
        );
    }

    /// PBKDF2 output length 0 produces no work and an empty buffer.
    #[test]
    fn zero_length_output_is_a_noop() {
        let mut out = [0u8; 0];
        pbkdf2_hmac::<Sha1>(b"pw", b"salt", 1, &mut out);
        // Just verifying no panic.
    }

    /// 32-byte output from SHA-1 PBKDF2 covers two derivation blocks
    /// and the second is the prefix of a third — exercises the
    /// `dst_end - dst_start` truncation arithmetic.
    #[test]
    fn unaligned_output_length() {
        let mut out = [0u8; 21]; // 1 byte past one block
        pbkdf2_hmac::<Sha1>(b"password", b"salt", 100, &mut out);
        // Reference: derive 40 bytes, take prefix.
        let mut full = [0u8; 40];
        pbkdf2_hmac::<Sha1>(b"password", b"salt", 100, &mut full);
        assert_eq!(out, full[..21]);
    }

    /// Iteration count 0 is rejected.
    #[test]
    #[should_panic(expected = "PBKDF2 iterations must be ≥ 1")]
    fn zero_iterations_panics() {
        let mut out = [0u8; 20];
        pbkdf2_hmac::<Sha1>(b"password", b"salt", 0, &mut out);
    }
}
