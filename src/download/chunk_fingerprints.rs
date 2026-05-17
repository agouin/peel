//! Per-chunk CRC-32C fingerprint store for `PLAN_v2.md` §11's
//! mid-flight source-change detector.
//!
//! Sits alongside the [`crate::bitmap::ChunkBitmap`] but stores a
//! 32-bit fingerprint per chunk instead of a single completion bit.
//! Used by:
//!
//! - the worker, which records the CRC-32C of each chunk it
//!   downloads;
//! - the scheduler, which periodically issues a "probe" re-fetch
//!   and compares the freshly-computed CRC-32C against the stored
//!   value. Mismatch ⇒ `SourceChangedDuringDownload`.
//! - the coordinator's resume path, which re-fetches a single
//!   already-complete chunk and verifies its CRC-32C before accepting
//!   the persisted bitmap as authoritative. Mismatch ⇒
//!   `SourceChangedSinceCheckpoint`.
//!
//! # Memory ordering
//!
//! Fingerprints are written-once-then-read: a worker records the
//! CRC-32C with [`Ordering::Release`] before its [`ChunkBitmap`]
//! mark; a probe / verifier reads the CRC-32C with
//! [`Ordering::Acquire`] only after observing the bitmap bit set.
//! That matches the bitmap's discipline and gives us the same
//! happens-before edge for consumers.

use std::sync::atomic::{AtomicU32, Ordering};

use crate::types::ChunkIndex;

/// Per-chunk CRC-32C fingerprints, indexed by [`ChunkIndex`].
///
/// `0` is used as the "unset" sentinel. CRC-32C of the empty input
/// is `0`, so treating `0` as "unset" precludes a (vanishingly
/// unlikely) genuine zero fingerprint — but bitmap chunks are
/// always non-empty so the conflict cannot arise in practice.
/// Callers that need to distinguish "unset" from "zero" should
/// gate the fingerprint read on the bitmap bit.
#[derive(Debug)]
pub struct ChunkFingerprints {
    crcs: Box<[AtomicU32]>,
    num_chunks: u32,
}

impl ChunkFingerprints {
    /// Construct an empty fingerprint store sized for `num_chunks`
    /// chunks. All slots start at `0`.
    #[must_use]
    pub fn new(num_chunks: u32) -> Self {
        let count = usize::try_from(num_chunks).unwrap_or(usize::MAX);
        let mut crcs = Vec::with_capacity(count);
        crcs.resize_with(count, || AtomicU32::new(0));
        Self {
            crcs: crcs.into_boxed_slice(),
            num_chunks,
        }
    }

    /// Number of chunks tracked.
    #[must_use]
    pub fn len(&self) -> u32 {
        self.num_chunks
    }

    /// True iff this store tracks no chunks.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.num_chunks == 0
    }

    /// Store `crc` for `idx`.
    ///
    /// # Panics
    ///
    /// Panics if `idx.get() >= self.len()`.
    pub fn record(&self, idx: ChunkIndex, crc: u32) {
        let raw = idx.get();
        assert!(
            raw < self.num_chunks,
            "ChunkFingerprints::record: idx {raw} out of range (len = {})",
            self.num_chunks,
        );
        self.crcs[raw as usize].store(crc, Ordering::Release);
    }

    /// Read the recorded CRC for `idx`. Returns `0` if no value
    /// has been recorded yet.
    ///
    /// # Panics
    ///
    /// Panics if `idx.get() >= self.len()`.
    #[must_use]
    pub fn get(&self, idx: ChunkIndex) -> u32 {
        let raw = idx.get();
        assert!(
            raw < self.num_chunks,
            "ChunkFingerprints::get: idx {raw} out of range (len = {})",
            self.num_chunks,
        );
        self.crcs[raw as usize].load(Ordering::Acquire)
    }

    /// Snapshot every fingerprint as a plain `Vec<u32>` in chunk
    /// order. Used at checkpoint write time.
    #[must_use]
    pub fn to_vec(&self) -> Vec<u32> {
        self.crcs
            .iter()
            .map(|c| c.load(Ordering::Acquire))
            .collect()
    }

    /// Construct a fingerprint store and pre-populate every slot
    /// from `values`. Used at resume time.
    ///
    /// # Errors
    ///
    /// Returns [`FingerprintsDecodeError::LengthMismatch`] when
    /// `values.len()` does not match `num_chunks`.
    pub fn from_slice(num_chunks: u32, values: &[u32]) -> Result<Self, FingerprintsDecodeError> {
        let expected = num_chunks as usize;
        if values.len() != expected {
            return Err(FingerprintsDecodeError::LengthMismatch {
                expected,
                actual: values.len(),
            });
        }
        let store = Self::new(num_chunks);
        for (i, v) in values.iter().enumerate() {
            store.crcs[i].store(*v, Ordering::Release);
        }
        Ok(store)
    }
}

/// Errors returned by [`ChunkFingerprints::from_slice`].
#[derive(Debug, thiserror::Error)]
pub enum FingerprintsDecodeError {
    /// Input length did not match `num_chunks`.
    #[error("fingerprint length {actual} does not match expected chunk count {expected}")]
    LengthMismatch {
        /// Expected length (`num_chunks`).
        expected: usize,
        /// Actual length of the input slice.
        actual: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::thread;

    #[test]
    fn new_creates_zero_initialised_store() {
        let f = ChunkFingerprints::new(4);
        assert_eq!(f.len(), 4);
        for i in 0..4 {
            assert_eq!(f.get(ChunkIndex::new(i)), 0);
        }
    }

    #[test]
    fn empty_store_reports_empty() {
        let f = ChunkFingerprints::new(0);
        assert!(f.is_empty());
        assert!(f.to_vec().is_empty());
    }

    #[test]
    fn record_then_get_round_trips() {
        let f = ChunkFingerprints::new(8);
        f.record(ChunkIndex::new(2), 0xDEAD_BEEF);
        f.record(ChunkIndex::new(5), 0xCAFE_F00D);
        assert_eq!(f.get(ChunkIndex::new(2)), 0xDEAD_BEEF);
        assert_eq!(f.get(ChunkIndex::new(5)), 0xCAFE_F00D);
        // Untouched slots stay zero.
        assert_eq!(f.get(ChunkIndex::new(0)), 0);
        assert_eq!(f.get(ChunkIndex::new(7)), 0);
    }

    #[test]
    fn to_vec_round_trips_through_from_slice() {
        let f = ChunkFingerprints::new(3);
        f.record(ChunkIndex::new(0), 0x0000_0001);
        f.record(ChunkIndex::new(1), 0x0000_0002);
        f.record(ChunkIndex::new(2), 0x0000_0003);
        let vec = f.to_vec();
        let restored = ChunkFingerprints::from_slice(3, &vec).expect("decode");
        assert_eq!(restored.to_vec(), vec);
    }

    #[test]
    fn from_slice_rejects_length_mismatch() {
        match ChunkFingerprints::from_slice(4, &[0, 0]) {
            Err(FingerprintsDecodeError::LengthMismatch { expected, actual }) => {
                assert_eq!(expected, 4);
                assert_eq!(actual, 2);
            }
            other => panic!("expected LengthMismatch, got {other:?}"),
        }
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn record_panics_on_oob() {
        let f = ChunkFingerprints::new(4);
        f.record(ChunkIndex::new(4), 0);
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn get_panics_on_oob() {
        let f = ChunkFingerprints::new(4);
        let _ = f.get(ChunkIndex::new(4));
    }

    #[test]
    fn concurrent_writers_record_every_value() {
        const N: u32 = 256;
        let f = Arc::new(ChunkFingerprints::new(N));
        thread::scope(|scope| {
            for t in 0..4u32 {
                let f = Arc::clone(&f);
                scope.spawn(move || {
                    for i in 0..N {
                        // Each thread writes a deterministic value;
                        // the last writer wins per slot, but every
                        // slot ends up populated.
                        f.record(ChunkIndex::new(i), 0x1000_0000 + t * 0x100 + i);
                    }
                });
            }
        });
        for i in 0..N {
            assert_ne!(f.get(ChunkIndex::new(i)), 0);
        }
    }
}
