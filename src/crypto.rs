//! Hand-rolled cryptographic primitives for encrypted-archive
//! decryption (`internal/PLAN_archive_encryption.md` §2).
//!
//! This module hosts the building blocks every format-specific
//! decryption path in §3–§5 shares: AES (§2b), HMAC, PBKDF2, SHA-1,
//! the 7z round-tower KDF, and a constant-time byte comparison
//! helper. Following the same std-first / dev-deps-for-cross-check
//! pattern that `hash::sha256` and `hash::blake2sp` already
//! established, the runtime binary links no crypto crate; each
//! primitive lives next to a differential test suite that compares
//! it against the RustCrypto reference impl held in
//! `[dev-dependencies]`.
//!
//! # Threat model
//!
//! See the project-level threat model in
//! `internal/PLAN_archive_encryption.md` §7. Briefly: we decrypt, we
//! don't authenticate the user, and we don't pretend to protect
//! against an attacker with read access to `/proc/<pid>/mem`. The
//! one rule we do codify in code is the constant-time comparison
//! helper [`ct_eq`]: every password-verification check and every
//! HMAC tag comparison routes through it so a timing attacker
//! cannot byte-walk a tag.
//!
//! # Module layout
//!
//! - [`sha1`] — FIPS 180-4 SHA-1. Hand-rolled for use as the
//!   underlying H in ZIP-AES's PBKDF2 / HMAC, which the format spec
//!   pins to SHA-1.
//! - [`hmac`] — generic `HMAC<H>` over any [`BlockHash`].
//! - [`pbkdf2`] — generic PBKDF2 over any [`BlockHash`] used by an
//!   HMAC; ZIP-AES uses SHA-1 with 1000 iterations, RAR5 uses
//!   SHA-256 with `1 << (kdf_count + 15)` iterations.
//!
//! AES, the AES modes (CTR, CBC), and the 7z round-tower KDF land
//! in their own submodules in §2b of the plan.

pub mod aes;
pub mod aes_modes;
pub mod hmac;
pub mod pbkdf2;
pub mod sevenz_kdf;
pub mod sha1;

/// Compare two byte slices in constant time relative to the input
/// length.
///
/// Returns `false` immediately when the lengths differ — the bytes
/// themselves are never inspected, so length is not a side channel
/// for the value (only for the presence of the slice, which the
/// caller already knows). When the lengths match, every byte is
/// XORed into an accumulator and the result is `0` iff every pair
/// agreed. The compiler is forbidden from short-circuiting because
/// the accumulator's value is fed into the final return through
/// `std::hint::black_box`.
///
/// # Threat model
///
/// Format-specific decoders call this for password-verifier checks
/// (ZIP-AES, RAR5 with CHECK) and HMAC tag comparisons (ZIP-AES).
/// A timing-side-channel attacker who can observe per-byte
/// comparison latency cannot walk a tag byte-by-byte through this
/// function. The protection only holds against a relative-timing
/// attacker; an attacker with a cycle-accurate side channel
/// (Spectre-class, cache-timing on a co-located VM) requires
/// hardware-level mitigations outside the scope of this code.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..a.len() {
        // SAFETY: `i < a.len()` and `a.len() == b.len()`, so both
        // indexes are in-bounds. We use `get_unchecked` to keep the
        // bounds check from contributing a length-dependent branch
        // to the timing profile.
        unsafe {
            diff |= a.get_unchecked(i) ^ b.get_unchecked(i);
        }
    }
    std::hint::black_box(diff) == 0
}

/// A streaming hash function with compile-time-known block and
/// output sizes, usable as the underlying H in HMAC and PBKDF2.
///
/// Implementations:
///
/// - [`sha1::Sha1`] — FIPS 180-4 SHA-1 (output 20 bytes, block 64).
/// - [`crate::hash::sha256::Sha256`] — pre-existing FIPS 180-4
///   SHA-256 (output 32 bytes, block 64). The impl block lives in
///   [`crate::crypto::sha2_adapter`] so this module is the single
///   import point for HMAC / PBKDF2.
///
/// The associated `Output` type is concrete (`[u8; N]`) per
/// implementation; HMAC uses [`AsRef<[u8]>`] to handle both
/// uniformly.
pub trait BlockHash: Sized {
    /// Output digest length in bytes.
    const OUTPUT_LEN: usize;
    /// Internal block size in bytes (the size HMAC's key padding
    /// uses, not the size of [`Self::update`]'s input chunks).
    const BLOCK_SIZE: usize;
    /// The concrete output buffer type. Fixed-size to keep HMAC /
    /// PBKDF2 alloc-free per round.
    type Output: AsRef<[u8]> + Default + Copy;

    /// A fresh hasher with the canonical IV.
    fn new() -> Self;

    /// Feed bytes into the hash.
    fn update(&mut self, data: &[u8]);

    /// Consume the hasher and return its digest.
    fn finalize(self) -> Self::Output;

    /// One-shot helper: hash a single slice in one call.
    fn digest(data: &[u8]) -> Self::Output {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

mod sha2_adapter;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ct_eq_equal_slices_match() {
        assert!(ct_eq(b"hunter2", b"hunter2"));
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(&[0xFFu8; 32], &[0xFFu8; 32]));
    }

    #[test]
    fn ct_eq_different_lengths_dont_match() {
        assert!(!ct_eq(b"hunter2", b"hunter22"));
        assert!(!ct_eq(b"", b"x"));
    }

    #[test]
    fn ct_eq_different_bytes_dont_match() {
        assert!(!ct_eq(b"hunter2", b"hunter3"));
        assert!(!ct_eq(&[0x00u8; 32], &[0x01u8; 32]));
    }

    #[test]
    fn ct_eq_single_byte_difference_at_end() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        a[15] = 1;
        b[15] = 2;
        assert!(!ct_eq(&a, &b));
    }

    #[test]
    fn ct_eq_single_byte_difference_at_start() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        a[0] = 1;
        b[0] = 2;
        assert!(!ct_eq(&a, &b));
    }
}
