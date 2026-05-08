//! Running Block-Check hasher: the `(check_id, accumulator)` pair
//! that runs alongside Block decompression and gets compared
//! against the trailer at Block end.
//!
//! Phase 5 of `docs/PLAN_xz_block_decoder.md`. The .xz Stream
//! Flags carry one of four Check IDs (`None` / `CRC32` / `CRC64`
//! / `SHA-256`); the Block trailer (after Block Padding) is the
//! corresponding hash over the decompressed Block bytes. Phase 1
//! reads and discarded the trailer; this module computes the
//! comparison value and verifies it.
//!
//! The hasher accumulates incrementally as the chunk decoder
//! emits bytes — both for the literal/match path inside LZMA
//! chunks and for the byte-stream path of uncompressed chunks.
//! At Block end the [`BlockCheckHasher::verify`] method consumes
//! the read trailer bytes and surfaces a clean
//! [`super::xz_error::XzError::BlockCheckMismatch`] on disagreement.
//!
//! # Why an enum
//!
//! The four Check variants have different state sizes (0 / 4 /
//! 8 / 32 bytes) and finalization signatures. An enum with one
//! variant per Check ID keeps the `update` hot path
//! statically-dispatched (the `match` is monomorphized at
//! compile time) and lets the `verify` step name the right
//! width-specific reference value. Nothing else in the crate
//! needs the abstraction; the per-format hashers in
//! [`crate::hash`] stay independent.

use crate::hash::{crc32::Crc32, crc64::Crc64, sha256::Sha256};

use super::stream::CheckId;
use super::xz_error::XzError;

/// Streaming hasher for the Block-Check trailer.
///
/// Initialized from a Block's [`CheckId`], updated with every
/// decompressed byte the chunk decoder emits, finalized at Block
/// end via [`Self::verify`].
#[derive(Debug, Clone)]
pub enum BlockCheckHasher {
    /// `Check ID = 0x00`: no trailer; verify always succeeds with
    /// an empty `expected` slice.
    None,
    /// `Check ID = 0x01`: 4-byte CRC32/ISO-HDLC.
    Crc32(Crc32),
    /// `Check ID = 0x04`: 8-byte CRC64/XZ (ECMA-182, reflected).
    Crc64(Crc64),
    /// `Check ID = 0x0A`: 32-byte SHA-256.
    Sha256(Sha256),
}

impl BlockCheckHasher {
    /// Construct a fresh hasher for the given Check variant.
    #[must_use]
    pub fn new(check: CheckId) -> Self {
        match check {
            CheckId::None => Self::None,
            CheckId::Crc32 => Self::Crc32(Crc32::new()),
            CheckId::Crc64 => Self::Crc64(Crc64::new()),
            CheckId::Sha256 => Self::Sha256(Sha256::new()),
        }
    }

    /// Feed `data` into the running hash. No-op for
    /// [`CheckId::None`].
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::None => {}
            Self::Crc32(h) => h.update(data),
            Self::Crc64(h) => h.update(data),
            Self::Sha256(h) => h.update(data),
        }
    }

    /// Serialized state length for this hasher variant. Used by
    /// the Phase 6 resume blob to cross-check the declared
    /// Check ID against the hasher-state byte payload.
    #[must_use]
    pub fn serialized_state_len(&self) -> usize {
        match self {
            Self::None => 0,
            Self::Crc32(_) => 4,
            Self::Crc64(_) => 8,
            Self::Sha256(_) => crate::hash::sha256::SERIALIZED_LEN,
        }
    }

    /// Append the running hasher state to `out`. Layout per
    /// variant:
    ///
    /// - `None`: 0 bytes.
    /// - `CRC32`: 4 bytes, the running u32 (after final XOR), LE.
    /// - `CRC64`: 8 bytes, the running u64 (after final XOR), LE.
    /// - `SHA-256`: 105 bytes, [`Sha256::serialize`]'s
    ///   self-describing blob.
    ///
    /// Pairs with [`Self::deserialize_state`].
    pub fn serialize_state(&self, out: &mut Vec<u8>) {
        match self {
            Self::None => {}
            Self::Crc32(h) => out.extend_from_slice(&h.current().to_le_bytes()),
            Self::Crc64(h) => out.extend_from_slice(&h.current().to_le_bytes()),
            Self::Sha256(h) => out.extend_from_slice(&h.serialize()),
        }
    }

    /// Reconstruct a hasher of the given Check kind from a
    /// previously [`Self::serialize_state`]-produced byte slice.
    ///
    /// # Errors
    ///
    /// - [`super::xz_error::XzError::ResumeBlobLength`] if `bytes`
    ///   length doesn't match the variant's expected size.
    /// - [`super::xz_error::XzError::ResumeBlobTruncated`] if a
    ///   variant-internal deserializer (e.g. SHA-256) rejects
    ///   the slice as malformed.
    pub fn deserialize_state(check: CheckId, bytes: &[u8]) -> Result<Self, XzError> {
        let expected = BlockCheckHasher::new(check).serialized_state_len();
        if bytes.len() != expected {
            return Err(XzError::ResumeBlobLength {
                field: "Block Check hasher state",
                declared: bytes.len() as u64,
                expected: expected as u64,
            });
        }
        match check {
            CheckId::None => Ok(Self::None),
            CheckId::Crc32 => {
                let partial = u32::from_le_bytes(bytes.try_into().expect("len 4 by check above"));
                let mut h = Crc32::new();
                h.seed(partial);
                Ok(Self::Crc32(h))
            }
            CheckId::Crc64 => {
                let partial = u64::from_le_bytes(bytes.try_into().expect("len 8 by check above"));
                let mut h = Crc64::new();
                h.seed(partial);
                Ok(Self::Crc64(h))
            }
            CheckId::Sha256 => {
                let arr: &[u8; crate::hash::sha256::SERIALIZED_LEN] =
                    bytes.try_into().expect("len 105 by check above");
                let h = Sha256::deserialize(arr)
                    .map_err(|_| XzError::ResumeBlobTruncated("Block Check SHA-256 state"))?;
                Ok(Self::Sha256(h))
            }
        }
    }

    /// Finalize the hash and compare against `expected` (the
    /// bytes read from the Block trailer).
    ///
    /// The expected length must match the [`CheckId`]'s wire
    /// width: 0 / 4 / 8 / 32 bytes.
    ///
    /// # Errors
    ///
    /// - [`XzError::BlockCheckMismatch`] if the computed hash
    ///   does not match `expected`. The variant carries a
    ///   diagnostic name (`"CRC32"` / `"CRC64"` / `"SHA-256"`).
    pub fn verify(self, expected: &[u8]) -> Result<(), XzError> {
        match self {
            Self::None => {
                debug_assert!(
                    expected.is_empty(),
                    "CheckId::None expects empty trailer slice"
                );
                Ok(())
            }
            Self::Crc32(h) => {
                debug_assert_eq!(expected.len(), 4);
                let got = h.finalize();
                let exp = u32::from_le_bytes(
                    expected
                        .try_into()
                        .expect("len 4 from outer match on CheckId::size"),
                );
                if got == exp {
                    Ok(())
                } else {
                    Err(XzError::BlockCheckMismatch { kind: "CRC32" })
                }
            }
            Self::Crc64(h) => {
                debug_assert_eq!(expected.len(), 8);
                let got = h.finalize();
                let exp = u64::from_le_bytes(
                    expected
                        .try_into()
                        .expect("len 8 from outer match on CheckId::size"),
                );
                if got == exp {
                    Ok(())
                } else {
                    Err(XzError::BlockCheckMismatch { kind: "CRC64" })
                }
            }
            Self::Sha256(h) => {
                debug_assert_eq!(expected.len(), 32);
                let got = h.finalize();
                if got.as_slice() == expected {
                    Ok(())
                } else {
                    Err(XzError::BlockCheckMismatch { kind: "SHA-256" })
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `CheckId::None` ignores updates and always verifies.
    #[test]
    fn none_check_always_verifies() {
        let mut h = BlockCheckHasher::new(CheckId::None);
        h.update(b"some bytes");
        h.verify(&[]).expect("none always ok");
    }

    /// CRC32 round-trip: hash some bytes, verify with the
    /// expected LE bytes.
    #[test]
    fn crc32_verify_round_trip() {
        let payload = b"the quick brown fox";
        let mut h = BlockCheckHasher::new(CheckId::Crc32);
        h.update(payload);
        let expected = crate::hash::crc32::ieee(payload).to_le_bytes();
        h.verify(&expected).expect("crc32 ok");
    }

    /// CRC32 mismatch surfaces a typed error naming "CRC32".
    #[test]
    fn crc32_mismatch_named_error() {
        let mut h = BlockCheckHasher::new(CheckId::Crc32);
        h.update(b"abc");
        match h.verify(&[0u8, 0, 0, 0]) {
            Err(XzError::BlockCheckMismatch { kind }) => assert_eq!(kind, "CRC32"),
            other => panic!("expected BlockCheckMismatch, got {other:?}"),
        }
    }

    /// CRC64 round-trip.
    #[test]
    fn crc64_verify_round_trip() {
        let payload = b"123456789";
        let mut h = BlockCheckHasher::new(CheckId::Crc64);
        h.update(payload);
        let expected = crate::hash::crc64::xz(payload).to_le_bytes();
        h.verify(&expected).expect("crc64 ok");
    }

    /// SHA-256 round-trip.
    #[test]
    fn sha256_verify_round_trip() {
        let payload = b"sha256 trailer test";
        let mut h = BlockCheckHasher::new(CheckId::Sha256);
        h.update(payload);
        let mut ref_h = Sha256::new();
        ref_h.update(payload);
        let expected = ref_h.finalize();
        h.verify(&expected).expect("sha256 ok");
    }

    /// SHA-256 mismatch surfaces a typed error naming "SHA-256".
    #[test]
    fn sha256_mismatch_named_error() {
        let mut h = BlockCheckHasher::new(CheckId::Sha256);
        h.update(b"abc");
        match h.verify(&[0u8; 32]) {
            Err(XzError::BlockCheckMismatch { kind }) => assert_eq!(kind, "SHA-256"),
            other => panic!("expected BlockCheckMismatch, got {other:?}"),
        }
    }

    /// Streaming `update` with arbitrary chunking matches a
    /// single-shot update.
    #[test]
    fn crc64_chunked_update_matches_one_shot() {
        let payload: Vec<u8> = (0..=255u8).chain(0..=255u8).collect();
        let mut a = BlockCheckHasher::new(CheckId::Crc64);
        a.update(&payload);

        let mut b = BlockCheckHasher::new(CheckId::Crc64);
        b.update(&payload[..1]);
        b.update(&payload[1..16]);
        b.update(&payload[16..]);

        // Both verify against the same expected trailer.
        let expected = crate::hash::crc64::xz(&payload).to_le_bytes();
        a.verify(&expected).expect("a ok");
        b.verify(&expected).expect("b ok");
    }
}
