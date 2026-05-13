//! 7z password key-derivation function
//! (`internal/PLAN_archive_encryption.md` §2; consumer is §5).
//!
//! 7z's `06 F1 07 01` AES-256-CBC coder pins its key derivation to
//! a bespoke "round-tower" scheme defined in `7zFormat.txt`. It is
//! not PBKDF2 — there is no HMAC, no separate inner/outer pass.
//! The shape is:
//!
//! ```text
//! H = SHA-256()                      // fresh state
//! for round in 0 .. 2^power:
//!     H.update(salt)                 // salt may be empty
//!     H.update(password_utf16le)     // UTF-16 little-endian
//!     H.update(round_le_8_bytes)     // 8-byte little-endian counter
//! key = H.finalize()                 // 32 bytes — the AES-256 key
//! ```
//!
//! The `power` byte and salt come from the coder's `properties`
//! field; `power` is capped at 63 by the spec (2^63 rounds is
//! absurd but valid). Number of rounds = `1u64 << power`.
//!
//! Two edge cases:
//!
//! - `power == 0` produces `1 << 0 = 1` round (not zero). The
//!   single iteration still feeds `salt || password || 0u64_le`
//!   into the hash, so the password is *not* ignored at power 0.
//! - The salt is the bytes the coder header carried; if the
//!   archive omits salt, `salt` is empty (zero-length slice).
//! - Practical: `power` values above ~24 mean the run will be
//!   compute-bound for hours; the format does permit values up
//!   to [`MAX_POWER`] (63 = 2^63 iterations), but no real-world
//!   producer ships archives anywhere near the top of that range.
//!   We do not special-case `power == 0x3F` here; the 7-Zip
//!   reference implementation has a "key = raw password" shortcut
//!   at that value, but the documented spec does not require it
//!   and no archive in our corpus uses it. If one surfaces, the
//!   shortcut goes in here behind a clear comment.
//!
//! There is no upstream "7z KDF" crate to cross-check against, so
//! the differential corpus uses fixed vectors derived against the
//! reference 7z source's behaviour (the spec is concrete enough
//! that the implementation is mechanical).

use crate::hash::sha256::Sha256;

/// AES-256 key length in bytes, the only output size 7z's KDF
/// produces.
pub const KEY_LEN: usize = 32;

/// Maximum `power` value the format spec permits. Values above
/// this would overflow a `u64` round counter.
pub const MAX_POWER: u8 = 63;

/// Derive the 32-byte AES-256 key for a 7z `06 F1 07 01` coder.
///
/// # Parameters
///
/// - `password_utf16le`: the password as UTF-16 little-endian
///   bytes (so a 4-char ASCII password is 8 bytes long). 7z's
///   format spec is explicit about this; converting from UTF-8
///   is the caller's job, not this primitive's.
/// - `salt`: zero or more bytes from the coder's properties.
/// - `power`: round-count exponent. The number of rounds is
///   `1u64 << power`. Capped at [`MAX_POWER`].
///
/// # Panics
///
/// Panics if `power > MAX_POWER`. The caller is expected to
/// surface this as a typed format error before reaching here.
pub fn sevenz_derive_key(password_utf16le: &[u8], salt: &[u8], power: u8) -> [u8; KEY_LEN] {
    assert!(
        power <= MAX_POWER,
        "7z power={power} exceeds the format spec maximum of {MAX_POWER}",
    );
    let mut h = Sha256::new();
    let rounds: u64 = if power == 64 {
        // Defensive: the assertion above keeps `power <= 63`, so
        // `1u64 << power` is well-defined and this branch is
        // unreachable. Kept for completeness — a future refactor
        // that raises MAX_POWER would have to revisit this.
        u64::MAX
    } else {
        1u64 << power
    };
    let mut counter_bytes = [0u8; 8];
    for round in 0..rounds {
        h.update(salt);
        h.update(password_utf16le);
        counter_bytes.copy_from_slice(&round.to_le_bytes());
        h.update(&counter_bytes);
    }
    h.finalize()
}

/// Convert a UTF-8 password into 7z's UTF-16-LE wire format.
///
/// Each `char` is encoded as one or two UTF-16 code units (the
/// BMP fits in one; supra-BMP characters need two via surrogate
/// pairs). Each code unit is then little-endian-encoded as two
/// bytes. The result is what [`sevenz_derive_key`] consumes.
#[must_use]
pub fn password_to_utf16le(password: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(password.len() * 2);
    for unit in password.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `power == 0` runs exactly one round (1 << 0 = 1). The
    /// single iteration feeds `salt || password || counter` —
    /// with empty salt, empty password, that's just the 8-byte
    /// little-endian counter `0`. So the key is
    /// `SHA-256(00 00 00 00 00 00 00 00)`.
    #[test]
    fn power_zero_runs_one_round_over_counter_zero() {
        let key = sevenz_derive_key(b"", b"", 0);
        let mut h = Sha256::new();
        h.update(&0u64.to_le_bytes());
        let expected = h.finalize();
        assert_eq!(key, expected);
    }

    /// `power == 0` does NOT ignore the password — the single
    /// round still feeds it into the hash.
    #[test]
    fn power_zero_uses_password() {
        let a = sevenz_derive_key(b"", b"", 0);
        let b = sevenz_derive_key(b"hunter2", b"", 0);
        assert_ne!(a, b);
    }

    /// `power == 0` walks counter 0 only (1 round). Hand-traced
    /// against an inline SHA-256 invocation.
    #[test]
    fn power_zero_traces_counter_zero() {
        let pw = password_to_utf16le("a");
        assert_eq!(pw, vec![0x61, 0x00]);
        let key = sevenz_derive_key(&pw, b"", 0);
        let mut h = Sha256::new();
        h.update(b"");
        h.update(&[0x61, 0x00]);
        h.update(&0u64.to_le_bytes());
        let expected = h.finalize();
        assert_eq!(key, expected);
    }

    /// `power == 1` walks counters 0 and 1 (2 rounds), with salt
    /// and password threaded into each. Hand-traced.
    #[test]
    fn power_one_traces_counters_zero_and_one() {
        let salt = b"saltsalt";
        let pw = password_to_utf16le("hunter2");
        let key = sevenz_derive_key(&pw, salt, 1);
        let mut h = Sha256::new();
        for round in 0u64..2 {
            h.update(salt);
            h.update(&pw);
            h.update(&round.to_le_bytes());
        }
        let expected = h.finalize();
        assert_eq!(key, expected);
    }

    /// `power == 5` runs 32 rounds; the counter walks `0..32`.
    #[test]
    fn power_five_walks_counter_0_through_31() {
        let pw = password_to_utf16le("p");
        let salt = b"s";
        let key = sevenz_derive_key(&pw, salt, 5);
        let mut h = Sha256::new();
        for round in 0u64..32 {
            h.update(salt);
            h.update(&pw);
            h.update(&round.to_le_bytes());
        }
        let expected = h.finalize();
        assert_eq!(key, expected);
    }

    #[test]
    #[should_panic(expected = "exceeds the format spec maximum")]
    fn power_above_max_panics() {
        let _ = sevenz_derive_key(b"", b"", 64);
    }

    /// UTF-16-LE round-trips ASCII.
    #[test]
    fn password_to_utf16le_ascii() {
        let bytes = password_to_utf16le("Hi");
        assert_eq!(bytes, vec![0x48, 0x00, 0x69, 0x00]);
    }

    /// UTF-16-LE BMP non-ASCII (single code unit).
    #[test]
    fn password_to_utf16le_bmp_unicode() {
        let bytes = password_to_utf16le("ä"); // U+00E4
        assert_eq!(bytes, vec![0xE4, 0x00]);
    }

    /// UTF-16-LE supra-BMP needs a surrogate pair (two code units).
    #[test]
    fn password_to_utf16le_supra_bmp_surrogate_pair() {
        let bytes = password_to_utf16le("\u{1F600}"); // 😀
                                                      // U+1F600 surrogate pair: 0xD83D, 0xDE00
        assert_eq!(bytes, vec![0x3D, 0xD8, 0x00, 0xDE]);
    }
}
