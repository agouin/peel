//! HMAC (RFC 2104) over any [`crate::crypto::BlockHash`]
//! (`internal/PLAN_archive_encryption.md` §2).
//!
//! HMAC instantiates with two concrete hashes in this crate:
//!
//! - HMAC-SHA1 — used by ZIP-AES (PBKDF2 key derivation + the
//!   10-byte AE-1/AE-2 authentication tag at the end of each
//!   encrypted entry).
//! - HMAC-SHA256 — used by RAR5 (PBKDF2 key derivation + the
//!   optional `CHECK` value that lets us distinguish "wrong
//!   password" from "corrupt archive").
//!
//! The output-truncation step that ZIP-AES requires (10 bytes of
//! the 20-byte HMAC-SHA1 tag) is intentionally *not* inside this
//! module: it lives at the call site, so a reader doesn't have to
//! reason about partial-output semantics when comparing this
//! implementation against the HMAC spec.

use crate::crypto::BlockHash;

/// Inner pad byte: every block-sized key byte XOR'd with this is
/// the prefix of the inner hash input.
const IPAD: u8 = 0x36;
/// Outer pad byte: every block-sized key byte XOR'd with this is
/// the prefix of the outer hash input.
const OPAD: u8 = 0x5C;

/// HMAC-`H` state.
///
/// Constructed from a key of any length; bytes can then be fed in
/// via [`Hmac::update`] and the final tag retrieved with
/// [`Hmac::finalize`]. Callers comparing a computed tag against an
/// untrusted value should route through
/// [`crate::crypto::ct_eq`] to avoid leaking the per-byte equality
/// pattern to a timing-side-channel observer.
///
/// HMAC-SHA1 truncation (ZIP-AES wants 10 bytes of the 20-byte tag)
/// is the caller's job: take the first N bytes of the returned
/// digest.
pub struct Hmac<H: BlockHash> {
    inner: H,
    outer_key: Vec<u8>,
}

impl<H: BlockHash> Hmac<H> {
    /// Construct an HMAC-`H` with the given key.
    ///
    /// Keys longer than the underlying hash's block size are first
    /// hashed down to `OUTPUT_LEN` bytes, then right-padded to
    /// `BLOCK_SIZE` with zeros (RFC 2104 §2). Keys shorter than the
    /// block size are right-padded directly. The empty key is a
    /// valid input (degenerate case; the spec permits it).
    pub fn new(key: &[u8]) -> Self {
        let mut padded_key = vec![0u8; H::BLOCK_SIZE];
        if key.len() > H::BLOCK_SIZE {
            // Long-key path: K' = H(K).
            let digest = H::digest(key);
            let bytes = digest.as_ref();
            padded_key[..bytes.len()].copy_from_slice(bytes);
        } else {
            padded_key[..key.len()].copy_from_slice(key);
        }

        // Pre-feed the inner hasher with (K' ⊕ ipad). The outer key
        // (K' ⊕ opad) is constructed lazily in `finalize` to keep
        // the in-memory footprint of a long-running HMAC bounded
        // by one hash state + one block-sized key buffer.
        let mut inner = H::new();
        let mut ipad_block = vec![0u8; H::BLOCK_SIZE];
        for (i, k) in padded_key.iter().enumerate() {
            ipad_block[i] = k ^ IPAD;
        }
        inner.update(&ipad_block);

        Self {
            inner,
            outer_key: padded_key,
        }
    }

    /// Feed message bytes into the inner hash.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return the full-width HMAC tag.
    ///
    /// Callers that want a truncated tag (e.g. ZIP-AES's 10-byte
    /// AE-1/AE-2 trailer) take the first N bytes of the returned
    /// digest at the call site.
    pub fn finalize(self) -> H::Output {
        let inner_digest = self.inner.finalize();
        let mut opad_block = vec![0u8; H::BLOCK_SIZE];
        for (i, k) in self.outer_key.iter().enumerate() {
            opad_block[i] = k ^ OPAD;
        }
        let mut outer = H::new();
        outer.update(&opad_block);
        outer.update(inner_digest.as_ref());
        outer.finalize()
    }

    /// One-shot helper: compute HMAC-`H`(key, msg) in one call.
    pub fn mac(key: &[u8], msg: &[u8]) -> H::Output {
        let mut h = Self::new(key);
        h.update(msg);
        h.finalize()
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

    /// RFC 2202 §3 test case 1: HMAC-SHA1 with a 20-byte 0x0b key
    /// and "Hi There" message.
    #[test]
    fn rfc2202_hmac_sha1_case_1() {
        let key = [0x0bu8; 20];
        let msg = b"Hi There";
        let tag = Hmac::<Sha1>::mac(&key, msg);
        assert_eq!(hex(&tag), "b617318655057264e28bc0b6fb378c8ef146be00");
    }

    /// RFC 2202 §3 case 2: HMAC-SHA1 with the ASCII key "Jefe" and
    /// "what do ya want for nothing?" message — the entry test for
    /// the short-key padding path.
    #[test]
    fn rfc2202_hmac_sha1_case_2() {
        let tag = Hmac::<Sha1>::mac(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(hex(&tag), "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
    }

    /// RFC 2202 §3 case 5: HMAC-SHA1 with a long key — exercises
    /// the K' = H(K) reduction.
    #[test]
    fn rfc2202_hmac_sha1_long_key_path() {
        let key = vec![0xaau8; 80];
        let msg = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let tag = Hmac::<Sha1>::mac(&key, msg);
        assert_eq!(hex(&tag), "aa4ae5e15272d00e95705637ce8a3b55ed402112");
    }

    /// RFC 4231 §4.2: HMAC-SHA256 test case 1, the entry test for
    /// the RAR5 path.
    #[test]
    fn rfc4231_hmac_sha256_case_1() {
        let key = [0x0bu8; 20];
        let tag = Hmac::<Sha256>::mac(&key, b"Hi There");
        assert_eq!(
            hex(&tag),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    /// RFC 4231 §4.5: HMAC-SHA256 with a key longer than the block
    /// size — same K' = H(K) reduction we exercise for SHA-1 in
    /// RFC 2202 case 5.
    #[test]
    fn rfc4231_hmac_sha256_long_key_path() {
        let key = vec![0xaau8; 131];
        let msg = b"Test Using Larger Than Block-Size Key - Hash Key First";
        let tag = Hmac::<Sha256>::mac(&key, msg);
        assert_eq!(
            hex(&tag),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    /// Streaming HMAC over byte-at-a-time updates produces the same
    /// tag as the one-shot helper.
    #[test]
    fn hmac_streaming_invariance() {
        let key = b"hunter2";
        let msg = b"the quick brown fox jumps over the lazy dog";
        let one_shot = Hmac::<Sha1>::mac(key, msg);
        let mut h = Hmac::<Sha1>::new(key);
        for byte in msg {
            h.update(&[*byte]);
        }
        let streamed = h.finalize();
        assert_eq!(one_shot, streamed);
    }

    /// Edge: empty-key, empty-msg HMAC-SHA1. Sanity check the
    /// degenerate input doesn't panic and matches the upstream value.
    #[test]
    fn hmac_sha1_empty_inputs() {
        let tag = Hmac::<Sha1>::mac(b"", b"");
        assert_eq!(hex(&tag), "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d");
    }
}
