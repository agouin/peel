//! Differential tests for the hand-rolled crypto primitives in
//! `src/crypto/` (`docs/PLAN_archive_encryption.md` §2).
//!
//! For each primitive we run 1 000+ random inputs through both
//! peel's hand-rolled implementation and the RustCrypto reference
//! held in `[dev-dependencies]`, then assert byte-identical output.
//! The reference crates (`sha1`, `hmac`, `pbkdf2`) are dev-only;
//! the runtime `peel` binary links none of them.
//!
//! The same pattern is established by
//! `src/hash/sha256.rs::tests::matches_sha2_crate_for_random_inputs`
//! (the §10 SHA-256 hand-roll) and the BLAKE2sp differential corpus
//! in `src/hash/blake2sp.rs`.
//!
//! AES + AES-CTR + AES-CBC + 7z KDF land in §2b; their differential
//! checks will be appended to this file when those primitives ship.

use hmac::{Hmac as RefHmac, Mac};
use peel::crypto::hmac::Hmac;
use peel::crypto::pbkdf2::pbkdf2_hmac;
use peel::crypto::sha1::Sha1;
use peel::crypto::BlockHash;
use peel::hash::sha256::Sha256;

/// Deterministic xorshift64 PRNG so the differential corpus is
/// reproducible across runs and architectures. We deliberately do
/// not pull `rand` for this — the test asserts mathematical
/// equivalence between two implementations, not statistical
/// properties of the input distribution.
struct Xs64(u64);

impl Xs64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut i = 0;
        while i + 8 <= out.len() {
            let v = self.next_u64().to_le_bytes();
            out[i..i + 8].copy_from_slice(&v);
            i += 8;
        }
        if i < out.len() {
            let v = self.next_u64().to_le_bytes();
            let tail = out.len() - i;
            out[i..].copy_from_slice(&v[..tail]);
        }
    }
    fn vec(&mut self, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        self.fill_bytes(&mut v);
        v
    }
    /// A random length in `[0, max]`. Two-step (`len_up_to` then
    /// `vec`) to keep two mutable borrows from overlapping in the
    /// caller.
    fn len_up_to(&mut self, max: usize) -> usize {
        (self.next_u64() as usize) % (max + 1)
    }
}

#[test]
fn sha1_matches_reference_for_1000_random_inputs() {
    use sha1::Digest;
    let mut rng = Xs64::new(0xC0FF_EE15_DEFA_CED1);
    for _ in 0..1024 {
        let len = rng.len_up_to(256);
        let buf = rng.vec(len);

        let ours = <Sha1 as BlockHash>::digest(&buf);

        let mut theirs_h = sha1::Sha1::new();
        theirs_h.update(&buf);
        let theirs = theirs_h.finalize();

        assert_eq!(ours.as_slice(), theirs.as_slice(), "len={len}");
    }
}

#[test]
fn sha1_matches_reference_for_block_size_boundaries() {
    use sha1::Digest;
    for &len in &[
        0usize, 1, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 129, 191, 192, 193, 1023, 1024,
        1025,
    ] {
        let buf = vec![0xA5u8; len];
        let ours = <Sha1 as BlockHash>::digest(&buf);
        let mut theirs_h = sha1::Sha1::new();
        theirs_h.update(&buf);
        let theirs = theirs_h.finalize();
        assert_eq!(ours.as_slice(), theirs.as_slice(), "len={len}");
    }
}

#[test]
fn hmac_sha1_matches_reference_for_1000_random_inputs() {
    let mut rng = Xs64::new(0xC0FF_EE15_FEED_FACE);
    type RefH = RefHmac<sha1::Sha1>;
    for _ in 0..1024 {
        let key_len = rng.len_up_to(128);
        let key = rng.vec(key_len);
        let msg_len = rng.len_up_to(512);
        let msg = rng.vec(msg_len);

        let ours = Hmac::<Sha1>::mac(&key, &msg);

        let mut theirs_h = <RefH as Mac>::new_from_slice(&key).expect("ref hmac sha1");
        theirs_h.update(&msg);
        let theirs = theirs_h.finalize().into_bytes();

        assert_eq!(
            ours.as_slice(),
            theirs.as_slice(),
            "key_len={} msg_len={}",
            key.len(),
            msg.len()
        );
    }
}

#[test]
fn hmac_sha256_matches_reference_for_1000_random_inputs() {
    let mut rng = Xs64::new(0xDEAD_BEEF_CAFE_BABE);
    type RefH = RefHmac<sha2::Sha256>;
    for _ in 0..1024 {
        let key_len = rng.len_up_to(128);
        let key = rng.vec(key_len);
        let msg_len = rng.len_up_to(512);
        let msg = rng.vec(msg_len);

        let ours = Hmac::<Sha256>::mac(&key, &msg);

        let mut theirs_h = <RefH as Mac>::new_from_slice(&key).expect("ref hmac sha256");
        theirs_h.update(&msg);
        let theirs = theirs_h.finalize().into_bytes();

        assert_eq!(
            ours.as_slice(),
            theirs.as_slice(),
            "key_len={} msg_len={}",
            key.len(),
            msg.len()
        );
    }
}

#[test]
fn hmac_sha1_long_key_path_matches_reference() {
    // The K' = H(K) reduction is conditional on key.len() > block
    // size (64 for SHA-1). Hit that explicit branch with random
    // keys of 64..256 bytes.
    let mut rng = Xs64::new(0x1234_5678_9ABC_DEF0);
    type RefH = RefHmac<sha1::Sha1>;
    for _ in 0..256 {
        let extra = (rng.next_u64() as usize) % 192;
        let key = rng.vec(64 + extra);
        let msg_len = rng.len_up_to(256);
        let msg = rng.vec(msg_len);

        let ours = Hmac::<Sha1>::mac(&key, &msg);
        let mut theirs_h = <RefH as Mac>::new_from_slice(&key).expect("ref hmac sha1");
        theirs_h.update(&msg);
        let theirs = theirs_h.finalize().into_bytes();
        assert_eq!(ours.as_slice(), theirs.as_slice());
    }
}

#[test]
fn pbkdf2_sha1_matches_reference_random_short_iterations() {
    // Short iteration count keeps the test fast (1000 cases × ≤200
    // iters ≈ 200 000 HMAC-SHA1 evaluations); the iteration count
    // doesn't affect correctness, only cost.
    let mut rng = Xs64::new(0xABBA_DABA_DEAD_F00D);
    for _ in 0..1000 {
        let pw_len = rng.len_up_to(64);
        let password = rng.vec(pw_len);
        let salt_len = rng.len_up_to(64);
        let salt = rng.vec(salt_len);
        let iters = 1u32 + (rng.next_u64() as u32) % 200;
        let out_len = 1 + rng.len_up_to(64);

        let mut ours = vec![0u8; out_len];
        pbkdf2_hmac::<Sha1>(&password, &salt, iters, &mut ours);

        let mut theirs = vec![0u8; out_len];
        pbkdf2::pbkdf2_hmac::<sha1::Sha1>(&password, &salt, iters, &mut theirs);

        assert_eq!(
            ours,
            theirs,
            "pw_len={} salt_len={} iters={} out_len={}",
            password.len(),
            salt.len(),
            iters,
            out_len,
        );
    }
}

#[test]
fn pbkdf2_sha256_matches_reference_random_short_iterations() {
    let mut rng = Xs64::new(0xBADC_AB1E_BEEF_FEED);
    for _ in 0..1000 {
        let pw_len = rng.len_up_to(64);
        let password = rng.vec(pw_len);
        let salt_len = rng.len_up_to(64);
        let salt = rng.vec(salt_len);
        let iters = 1u32 + (rng.next_u64() as u32) % 200;
        let out_len = 1 + rng.len_up_to(96);

        let mut ours = vec![0u8; out_len];
        pbkdf2_hmac::<Sha256>(&password, &salt, iters, &mut ours);

        let mut theirs = vec![0u8; out_len];
        pbkdf2::pbkdf2_hmac::<sha2::Sha256>(&password, &salt, iters, &mut theirs);

        assert_eq!(
            ours,
            theirs,
            "pw_len={} salt_len={} iters={} out_len={}",
            password.len(),
            salt.len(),
            iters,
            out_len,
        );
    }
}

/// Pin the zip-AES iteration count (1000) and PBKDF2-SHA1 against
/// the reference. The iteration count itself is a hot-spot constant
/// in §3 and worth a dedicated check independent of the random
/// corpus.
#[test]
fn pbkdf2_sha1_zip_aes_1000_iter_matches_reference() {
    let mut rng = Xs64::new(0x9999_AAAA_BBBB_CCCC);
    for _ in 0..32 {
        let pw_len = rng.len_up_to(48);
        let password = rng.vec(pw_len);
        let salt_len = rng.len_up_to(16);
        let salt = rng.vec(salt_len);
        // zip-AES derives 2 * key_size + 2 (for AES-256: 66 bytes).
        for out_len in [34, 50, 66] {
            let mut ours = vec![0u8; out_len];
            pbkdf2_hmac::<Sha1>(&password, &salt, 1000, &mut ours);

            let mut theirs = vec![0u8; out_len];
            pbkdf2::pbkdf2_hmac::<sha1::Sha1>(&password, &salt, 1000, &mut theirs);

            assert_eq!(ours, theirs, "out_len={out_len}");
        }
    }
}
