//! [`BlockHash`] adapter for the pre-existing
//! [`crate::hash::sha256::Sha256`] hand-rolled SHA-256
//! (`internal/PLAN_archive_encryption.md` §2).
//!
//! The impl lives in a separate file (rather than in `hash::sha256`)
//! so that module stays focused on its original use case — the
//! `--sha256` integrity-check pipeline — and so the encryption-only
//! `BlockHash` trait doesn't leak into the wider crate when the
//! `rar` feature is off. RAR5's PBKDF2-HMAC-SHA256 (§4) pulls in
//! this impl through [`crate::crypto::hmac::Hmac<Sha256>`].

use crate::crypto::BlockHash;
use crate::hash::sha256::{Sha256, DIGEST_LEN};

impl BlockHash for Sha256 {
    const OUTPUT_LEN: usize = DIGEST_LEN;
    /// SHA-256 processes 512-bit blocks. The block size matters for
    /// HMAC's key-padding step, not for [`update`]'s chunking.
    ///
    /// [`update`]: crate::hash::sha256::Sha256::update
    const BLOCK_SIZE: usize = 64;
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

    /// FIPS 180-4 SHA-256("abc") =
    /// ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    #[test]
    fn block_hash_sha256_kat() {
        let d = <Sha256 as BlockHash>::digest(b"abc");
        let hex: String = d.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn block_hash_sha256_constants() {
        assert_eq!(<Sha256 as BlockHash>::OUTPUT_LEN, 32);
        assert_eq!(<Sha256 as BlockHash>::BLOCK_SIZE, 64);
    }
}
