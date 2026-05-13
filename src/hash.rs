//! Cryptographic / integrity hashes used at the binary boundary.
//!
//! Today this module hosts a hand-rolled, FIPS 180-4 SHA-256
//! implementation with a serializable mid-stream state. See
//! [`sha256`] for the implementation rationale (`internal/PLAN_v2.md`
//! §10) — the short version is that resumable hashing needs the
//! state to be saveable between runs, and the upstream `sha2` crate
//! does not expose that without poking at private fields.
//!
//! On top of that primitive sit three pieces of plumbing:
//!
//! - [`IntegrityHasher`] — a part-aware state machine that wraps a
//!   single [`Sha256`]. For single-URL runs it has exactly one part
//!   covering `[0, total_size)` and behaves byte-identically to a
//!   plain hasher with an end-of-stream `verify_digest` call. For
//!   multi-URL runs (`internal/PLAN_multi_url_source.md` §4) it carries
//!   one expected digest per part, finalizes and verifies as the
//!   stream crosses each part boundary, and fails fast at the part
//!   that produced the bad bytes — a corrupted part 1 fails before
//!   part 2 starts decoding instead of waiting for end-of-stream.
//! - [`HashingReader`] — a `Read` adapter that tees every byte
//!   pulled from an inner source into a shared [`IntegrityHasher`],
//!   with optional skip-on-resume support so the in-progress
//!   hash state survives a `kill -9` (`PLAN_v2.md` §10 step 4).
//! - [`IntegrityError`] — the typed error the binary surfaces
//!   when the user's `--sha256 <hex>` does not match the digest
//!   of the bytes we received.
//!
//! Both are crate-public so the coordinator can wire them in at
//! the source-reader boundary; production callers go through the
//! `--sha256` CLI flag rather than touching this module directly.

// BLAKE2sp lives behind the `rar` Cargo feature: it's used only by
// the RAR5 file-data integrity path (`internal/PLAN_rar.md` §2). When
// the feature is disabled the module is excluded entirely so the
// 250-LOC compression core doesn't ship in the slim binary.
#[cfg(feature = "rar")]
pub mod blake2sp;
pub mod crc32;
pub mod crc32c;
pub mod crc64;
pub mod sha256;
pub mod xxh64;

use std::io::Read;
use std::sync::{Arc, Mutex};

use thiserror::Error;

use sha256::{format_hex_digest, Sha256, DIGEST_LEN};

/// Errors produced when a `--sha256` integrity check fails.
///
/// Surfaced separately from the coordinator's other errors so the
/// binary can give it a friendlier message and a distinct exit code:
/// extraction completed but the *source* did not match what the user
/// said it would.
#[derive(Debug, Error)]
pub enum IntegrityError {
    /// The computed digest of the source bytes did not match the
    /// expected digest the user provided. Single-URL only — multi-URL
    /// runs surface [`Self::PartMismatch`] with a part index instead.
    #[error(
        "the file you got is not the file you expected; this usually means the source \
         changed during download or the expected hash is for a different file \
         (expected {expected}, got {got})"
    )]
    HashMismatch {
        /// Expected digest formatted as 64 lowercase hex characters.
        expected: String,
        /// Computed digest formatted as 64 lowercase hex characters.
        got: String,
    },

    /// A multi-URL run (`internal/PLAN_multi_url_source.md` §4) received
    /// bytes for part `part_index` whose SHA-256 did not match the
    /// per-part digest the user supplied. Surfaced *as soon as that
    /// part finishes streaming* so a corrupted part 1 does not waste
    /// hours of decode work on parts 2..N.
    #[error(
        "the file you got is not the file you expected: part {part_index} did not match \
         the expected hash; the part likely changed mid-download or the expected hash \
         is for a different revision (expected {expected}, got {got})"
    )]
    PartMismatch {
        /// Index into the multi-URL part list (`0`-based).
        part_index: usize,
        /// Expected digest formatted as 64 lowercase hex characters.
        expected: String,
        /// Computed digest formatted as 64 lowercase hex characters.
        got: String,
    },

    /// The user passed `--sha256` while resuming a checkpoint that
    /// was written without integrity tracking. The hasher would only
    /// see post-resume bytes, so a faithful end-of-run check is
    /// impossible. The user must either re-run from scratch (after
    /// deleting the checkpoint) or drop the `--sha256` flag.
    #[error(
        "--sha256 was requested but the existing checkpoint at {ckpt_path:?} was \
         created without integrity tracking. Delete the checkpoint to start fresh, \
         or drop --sha256 to resume without verification"
    )]
    CheckpointMissingHashState {
        /// Path to the checkpoint that lacks a saved hash state.
        ckpt_path: std::path::PathBuf,
    },

    /// The user dropped `--sha256` between runs while resuming a
    /// checkpoint that *did* track integrity. The mid-stream hash
    /// would never reach a useful final state, so we refuse rather
    /// than silently discarding the saved progress.
    #[error(
        "the existing checkpoint at {ckpt_path:?} was created with --sha256 enabled; \
         re-run with the same --sha256 hex to continue, or delete the checkpoint to \
         drop integrity tracking"
    )]
    CheckpointHadHashState {
        /// Path to the checkpoint that carries a saved hash state.
        ckpt_path: std::path::PathBuf,
    },

    /// The serialized hash state inside a checkpoint failed to decode
    /// (`buffer_len` out of range). The checkpoint is salvageable for
    /// non-integrity resume, but the integrity check would be wrong;
    /// surface this rather than silently dropping the saved state.
    #[error("checkpoint hash state failed to decode")]
    CheckpointHashStateDecode {
        /// Underlying decoder error.
        #[source]
        source: sha256::Sha256DeserializeError,
    },

    /// The checkpoint's `active_part_idx` is out of range for the
    /// current run's part list — typically because the user changed
    /// the URL list (or count) between runs while keeping the same
    /// checkpoint sidecar. Delete the `.peel.ckpt` to start fresh.
    #[error(
        "checkpoint at {ckpt_path:?} records active_part_idx={active_part_idx} but \
         this run has only {part_count} parts; the source layout changed between \
         runs — delete the checkpoint to start fresh"
    )]
    CheckpointPartIndexOutOfRange {
        /// Path to the checkpoint that cannot be safely resumed.
        ckpt_path: std::path::PathBuf,
        /// `active_part_idx` recorded in the checkpoint.
        active_part_idx: usize,
        /// Part count the current run discovered.
        part_count: usize,
    },
}

/// Captured fields for a deferred [`IntegrityError`] reconstruction.
///
/// [`IntegrityError`] does not implement [`Clone`] (its
/// [`IntegrityError::CheckpointHashStateDecode`] variant wraps a
/// non-`Clone` `source`), so we store the raw bytes that
/// [`IntegrityHasher::error`] needs to reproduce the variant on
/// every read. `part_index == None` reproduces a [`HashMismatch`];
/// `Some(_)` reproduces [`PartMismatch`].
#[derive(Debug, Clone)]
struct StoredError {
    part_index: Option<usize>,
    expected: [u8; DIGEST_LEN],
    got: [u8; DIGEST_LEN],
}

impl StoredError {
    fn to_integrity_error(&self) -> IntegrityError {
        match self.part_index {
            Some(idx) => IntegrityError::PartMismatch {
                part_index: idx,
                expected: format_hex_digest(&self.expected),
                got: format_hex_digest(&self.got),
            },
            None => IntegrityError::HashMismatch {
                expected: format_hex_digest(&self.expected),
                got: format_hex_digest(&self.got),
            },
        }
    }
}

/// Part-aware streaming SHA-256 verifier
/// (`internal/PLAN_multi_url_source.md` §4).
///
/// Conceptually a state machine over a sequence of parts. The
/// active part's bytes accumulate in [`Sha256`]; when the global
/// byte cursor reaches the active part's end boundary, the active
/// hasher is finalized, compared against the per-part expected
/// digest, and (on match) reset for the next part. A mismatch
/// stores the error in [`Self::error`]; subsequent
/// [`Self::update`] calls become no-ops and surface the same error
/// so the caller can short-circuit cleanly.
///
/// # Single-URL backwards compatibility
///
/// A `single`-constructed hasher has exactly one part covering
/// `[0, total_size)`. Verification fires at end-of-stream — the same
/// moment the previous `Sha256 + verify_digest` flow did — and emits
/// [`IntegrityError::HashMismatch`] (the historical variant) rather
/// than [`IntegrityError::PartMismatch`] so existing tests and CLI
/// help text continue to read naturally.
pub struct IntegrityHasher {
    active: Sha256,
    active_part_idx: usize,
    /// `boundaries[i]` is the global byte offset where part `i`
    /// ends. Always non-empty and strictly monotone.
    boundaries: Vec<u64>,
    /// Per-part expected digest, parallel to `boundaries`. `None`
    /// for parts the user did not supply a hash for; verification
    /// is skipped for those parts but the hasher still ticks
    /// through the boundary.
    expected: Vec<Option<[u8; DIGEST_LEN]>>,
    bytes_processed: u64,
    error: Option<StoredError>,
}

impl IntegrityHasher {
    /// Build a single-part hasher whose only boundary is
    /// `total_size`. Equivalent to today's `Sha256 + verify_digest`
    /// flow; the single-URL coordinator path goes through this.
    #[must_use]
    pub fn single(total_size: u64, expected: Option<[u8; DIGEST_LEN]>) -> Self {
        Self {
            active: Sha256::new(),
            active_part_idx: 0,
            boundaries: vec![total_size],
            expected: vec![expected],
            bytes_processed: 0,
            error: None,
        }
    }

    /// Build a multi-part hasher over `part_sizes`, one per
    /// (in-order) part. `expected` must have the same length as
    /// `part_sizes`; entries can be `None` to skip verification of
    /// individual parts (mainly useful for tests — the CLI either
    /// passes one hash per part or none at all).
    ///
    /// # Panics
    ///
    /// Panics if `part_sizes` is empty, if `expected.len() !=
    /// part_sizes.len()`, or if the running sum of part sizes
    /// overflows `u64`. Callers building from a
    /// [`crate::download::MultiPartSource`] have already validated
    /// these invariants upstream so the panic path is unreachable
    /// from production code.
    #[must_use]
    pub fn multi_part(part_sizes: &[u64], expected: Vec<Option<[u8; DIGEST_LEN]>>) -> Self {
        assert!(
            !part_sizes.is_empty(),
            "IntegrityHasher::multi_part requires at least one part"
        );
        assert_eq!(
            part_sizes.len(),
            expected.len(),
            "IntegrityHasher::multi_part: expected.len() must equal part_sizes.len()"
        );
        let mut boundaries = Vec::with_capacity(part_sizes.len());
        let mut acc: u64 = 0;
        for &sz in part_sizes {
            acc = acc
                .checked_add(sz)
                .expect("IntegrityHasher::multi_part: total source size overflows u64");
            boundaries.push(acc);
        }
        Self {
            active: Sha256::new(),
            active_part_idx: 0,
            boundaries,
            expected,
            bytes_processed: 0,
            error: None,
        }
    }

    /// Total bytes hashed across the whole virtual stream.
    #[must_use]
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }

    /// Sum of all part sizes — the value `bytes_processed` reaches
    /// at clean completion.
    #[must_use]
    pub fn total_size(&self) -> u64 {
        // INVARIANT: `boundaries` is non-empty.
        *self.boundaries.last().expect("non-empty boundaries")
    }

    /// True iff `bytes_processed` has reached the last part
    /// boundary (every part has been finalized and verified).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.bytes_processed == self.total_size()
    }

    /// First integrity error observed during streaming, if any.
    /// Reconstructs the variant on each call so the caller can
    /// surface it without consuming the hasher.
    #[must_use]
    pub fn error(&self) -> Option<IntegrityError> {
        self.error.as_ref().map(StoredError::to_integrity_error)
    }

    /// Snapshot the active part's [`Sha256`] state for inclusion in
    /// the next checkpoint. Returns `None` if a prior boundary
    /// crossing already errored (no point checkpointing a doomed
    /// hash state). Used by single-URL runs today; multi-URL
    /// resume support requires the active part index too and lands
    /// in `internal/PLAN_multi_url_source.md` §5.
    #[must_use]
    pub fn snapshot_active_serialized(&self) -> Option<[u8; sha256::SERIALIZED_LEN]> {
        if self.error.is_some() {
            return None;
        }
        Some(self.active.clone().serialize())
    }

    /// Active part index. Useful for diagnostics and for the
    /// upcoming v8 checkpoint format (`internal/PLAN_multi_url_source.md`
    /// §5) which will serialize this alongside the active hasher.
    #[must_use]
    pub fn active_part_idx(&self) -> usize {
        self.active_part_idx
    }

    /// Number of parts the hasher tracks. `1` for single-URL.
    #[must_use]
    pub fn part_count(&self) -> usize {
        self.boundaries.len()
    }

    /// Reconstruct a single-part hasher from its checkpointed
    /// `Sha256` snapshot. Used by the single-URL resume path.
    #[must_use]
    pub fn from_single_snapshot(
        active: Sha256,
        total_size: u64,
        expected: Option<[u8; DIGEST_LEN]>,
    ) -> Self {
        let bytes_processed = active.bytes_processed();
        Self {
            active,
            active_part_idx: 0,
            boundaries: vec![total_size],
            expected: vec![expected],
            bytes_processed,
            error: None,
        }
    }

    /// Reconstruct a multi-part hasher from its checkpointed
    /// snapshot (`internal/PLAN_multi_url_source.md` §5). Parts before
    /// `active_part_idx` are treated as already verified; the
    /// active hasher continues from `active`'s mid-stream state.
    /// `bytes_processed` is `prefix_sum(part_sizes[0..idx]) +
    /// active.bytes_processed()`.
    ///
    /// # Errors
    ///
    /// Returns
    /// [`crate::hash::sha256::Sha256DeserializeError`] when the
    /// caller passes a malformed `active`; otherwise returns the
    /// reconstructed hasher.
    ///
    /// # Panics
    ///
    /// Panics if `part_sizes.is_empty()`, `expected.len() !=
    /// part_sizes.len()`, `active_part_idx >= part_sizes.len()`,
    /// or if `active.bytes_processed() > part_sizes[active_part_idx]`
    /// (the saved hasher overshot its own part).
    #[must_use]
    pub fn from_multi_part_snapshot(
        active: Sha256,
        part_sizes: &[u64],
        expected: Vec<Option<[u8; DIGEST_LEN]>>,
        active_part_idx: usize,
    ) -> Self {
        assert!(
            !part_sizes.is_empty(),
            "from_multi_part_snapshot requires at least one part"
        );
        assert_eq!(
            part_sizes.len(),
            expected.len(),
            "from_multi_part_snapshot: expected length must match part count"
        );
        assert!(
            active_part_idx < part_sizes.len(),
            "from_multi_part_snapshot: active_part_idx out of range"
        );
        assert!(
            active.bytes_processed() <= part_sizes[active_part_idx],
            "from_multi_part_snapshot: active.bytes_processed() exceeds active part size"
        );
        let mut boundaries = Vec::with_capacity(part_sizes.len());
        let mut acc: u64 = 0;
        for &sz in part_sizes {
            acc = acc
                .checked_add(sz)
                .expect("from_multi_part_snapshot: total source size overflows u64");
            boundaries.push(acc);
        }
        let bytes_processed = if active_part_idx == 0 {
            active.bytes_processed()
        } else {
            boundaries[active_part_idx - 1] + active.bytes_processed()
        };
        Self {
            active,
            active_part_idx,
            boundaries,
            expected,
            bytes_processed,
            error: None,
        }
    }

    /// Feed `bytes` through the active part hasher, crossing part
    /// boundaries as the cumulative byte count reaches them.
    ///
    /// On the first cross that fails verification, stores the
    /// error in [`Self::error`] and returns it. Subsequent calls
    /// short-circuit and re-emit the same error.
    ///
    /// # Errors
    ///
    /// - [`IntegrityError::HashMismatch`] (single-URL) when the
    ///   end-of-stream digest disagrees with the user's
    ///   `--sha256`.
    /// - [`IntegrityError::PartMismatch`] (multi-URL) when a
    ///   part-end digest disagrees with the per-part `--sha256`.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), IntegrityError> {
        if let Some(stored) = &self.error {
            return Err(stored.to_integrity_error());
        }
        let mut remaining = bytes;
        while !remaining.is_empty() {
            // Past the last boundary = caller bug; the source-side
            // BlockingSparseReader caps at total_size. Treat it as
            // a no-op; a future mismatch report would be misleading
            // because we'd have lost the original bytes' context.
            if self.bytes_processed >= self.total_size() {
                break;
            }
            let active_end = self.boundaries[self.active_part_idx];
            let remaining_in_part = active_end - self.bytes_processed;
            let take_u64 = (remaining.len() as u64).min(remaining_in_part);
            // INVARIANT: `take_u64 <= remaining.len()`, so the
            // `as usize` cast is lossless.
            let take = take_u64 as usize;
            let head = &remaining[..take];
            self.active.update(head);
            self.bytes_processed = self.bytes_processed.saturating_add(take_u64);
            // Did we just reach the active part's boundary?
            if self.bytes_processed == active_end {
                let computed = std::mem::take(&mut self.active).finalize();
                if let Some(expected) = self.expected[self.active_part_idx] {
                    if computed != expected {
                        let part_index = if self.boundaries.len() == 1 {
                            None
                        } else {
                            Some(self.active_part_idx)
                        };
                        let stored = StoredError {
                            part_index,
                            expected,
                            got: computed,
                        };
                        let err = stored.to_integrity_error();
                        self.error = Some(stored);
                        return Err(err);
                    }
                }
                // Advance to the next part if any. Past the last
                // part we keep the index pinned so the bookkeeping
                // above (and the `bytes_processed >= total_size`
                // guard) still holds.
                if self.active_part_idx + 1 < self.boundaries.len() {
                    self.active_part_idx += 1;
                }
            }
            remaining = &remaining[take..];
        }
        Ok(())
    }

    /// Run any verification still pending at end-of-decode. For a
    /// run that streamed every byte through [`Self::update`] this
    /// is a no-op (the last boundary fired the last verify
    /// in-line). For a partial read — the decoder reached EOF
    /// before total_size — finalize the active hasher and compare
    /// against the active part's expected digest, matching today's
    /// "decoder bailed early; surface the partial-digest mismatch"
    /// behaviour.
    ///
    /// # Errors
    ///
    /// Returns the stored error if one was observed earlier. May
    /// also return a fresh mismatch error when the decoder stopped
    /// before reaching the last boundary AND the partial active
    /// digest fails verification.
    pub fn finalize_remaining(&mut self) -> Result<(), IntegrityError> {
        if let Some(stored) = &self.error {
            return Err(stored.to_integrity_error());
        }
        if self.is_complete() {
            return Ok(());
        }
        let active = std::mem::take(&mut self.active);
        if active.bytes_processed() == 0 {
            return Ok(());
        }
        let computed = active.finalize();
        if let Some(expected) = self.expected[self.active_part_idx] {
            if computed != expected {
                let part_index = if self.boundaries.len() == 1 {
                    None
                } else {
                    Some(self.active_part_idx)
                };
                let stored = StoredError {
                    part_index,
                    expected,
                    got: computed,
                };
                let err = stored.to_integrity_error();
                self.error = Some(stored);
                return Err(err);
            }
        }
        Ok(())
    }
}

/// Shared, mutex-protected handle to a streaming
/// [`IntegrityHasher`].
///
/// The handle is held by both the [`HashingReader`] (which feeds
/// bytes in from one thread on every `read`) and the coordinator
/// (which snapshots the state at quiescent checkpoints and
/// inspects [`IntegrityHasher::error`] at run end). Only one writer
/// touches it at a time in practice — the extractor's decoder
/// runs on a single thread and the checkpoint observer pauses it
/// — so the mutex sees no contention; we use it only because the
/// underlying [`Box<dyn Read + Send>`] erases lifetimes and forbids
/// borrowing.
pub type SharedHasher = Arc<Mutex<IntegrityHasher>>;

/// Wrap `inner` in a [`Mutex`] and return a fresh [`SharedHasher`].
///
/// Convenience constructor used at the binary boundary; tests
/// build the same shape with [`Arc::new`] +
/// [`Mutex::new`] directly.
#[must_use]
pub fn shared_hasher(inner: IntegrityHasher) -> SharedHasher {
    Arc::new(Mutex::new(inner))
}

/// `Read` adapter that tees source bytes into a [`SharedHasher`].
///
/// Sits between the sparse-file reader and the decoder: every byte
/// the decoder pulls flows through `read`, gets forwarded to the
/// shared [`IntegrityHasher`], and is then handed back to the
/// decoder. The decoder is unaware the adapter exists. When the
/// hasher's `update` returns an error (for example, a bad part 1
/// in a multi-URL run finished streaming), this `Read` impl
/// short-circuits subsequent reads with [`std::io::Error::other`]
/// so the decoder unwinds promptly. The coordinator then queries
/// the shared hasher for the typed error.
///
/// # Resume / `skip_remaining`
///
/// On resume we restore the SHA-256 state at byte-position `Y`
/// (where `Y` is whatever `bytes_processed` the previous run had
/// committed in the checkpoint), but the source itself is seeked
/// to `decoder_position = X ≤ Y` (the most recent frame boundary).
/// The bytes in the range `[X, Y)` were already hashed by the
/// previous run; re-hashing them here would invalidate the digest.
/// `skip_remaining` is initialised to `Y - X` so the first that
/// many bytes the new reader hands out are *not* fed into the
/// hasher. Subsequent bytes are.
///
/// At clean completion `hasher.bytes_processed() == total_size`
/// regardless of how many resumes happened in between: the `Y`
/// from the previous run plus the post-`Y` bytes hashed by this
/// run sum to exactly the source length.
pub struct HashingReader {
    inner: Box<dyn Read + Send>,
    hasher: SharedHasher,
    skip_remaining: u64,
}

impl HashingReader {
    /// Construct a reader that feeds every byte read from `inner`
    /// into `hasher`.
    #[must_use]
    pub fn new(inner: Box<dyn Read + Send>, hasher: SharedHasher) -> Self {
        Self {
            inner,
            hasher,
            skip_remaining: 0,
        }
    }

    /// Construct a reader that ignores its first `skip` bytes for
    /// hashing purposes (forwarding them to the decoder unchanged).
    ///
    /// Used by the coordinator's resume path — see the type-level
    /// docs for the invariant.
    #[must_use]
    pub fn with_skip(inner: Box<dyn Read + Send>, hasher: SharedHasher, skip: u64) -> Self {
        Self {
            inner,
            hasher,
            skip_remaining: skip,
        }
    }

    /// Borrow the shared hasher handle. The caller can lock and
    /// inspect / snapshot the hash state on its own cadence.
    #[must_use]
    pub fn hasher(&self) -> SharedHasher {
        Arc::clone(&self.hasher)
    }
}

impl Read for HashingReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 {
            return Ok(0);
        }
        let bytes = &buf[..n];
        // u64 conversion is safe — `n <= buf.len() <= isize::MAX`.
        let n_u64 = n as u64;
        if self.skip_remaining >= n_u64 {
            self.skip_remaining -= n_u64;
            return Ok(n);
        }
        let to_skip = self.skip_remaining as usize;
        self.skip_remaining = 0;
        let to_hash = &bytes[to_skip..];
        if !to_hash.is_empty() {
            // INVARIANT: the mutex is only ever locked from this
            // thread (extractor) and the checkpoint observer (same
            // thread, between decode steps). Poisoning would mean
            // one of those panicked — fail closed by surfacing it
            // as an io::Error so the extractor's error path takes
            // over rather than silently dropping bytes from the
            // hash.
            let mut guard = self
                .hasher
                .lock()
                .map_err(|_| std::io::Error::other("hasher mutex poisoned"))?;
            // `update` returns the typed `IntegrityError` on
            // boundary mismatch. We surface it through `io::Error`
            // so the decoder's error path unwinds; the coordinator
            // re-reads the typed error from the shared hasher
            // afterwards.
            if let Err(e) = guard.update(to_hash) {
                return Err(std::io::Error::other(format!(
                    "source integrity check failed: {e}"
                )));
            }
        }
        Ok(n)
    }
}

/// Compare a finalized digest against the expected digest the user
/// supplied on the CLI.
///
/// # Errors
///
/// Returns [`IntegrityError::HashMismatch`] if the two digests
/// differ.
pub fn verify_digest(
    expected: &[u8; DIGEST_LEN],
    computed: &[u8; DIGEST_LEN],
) -> Result<(), IntegrityError> {
    if expected == computed {
        Ok(())
    } else {
        Err(IntegrityError::HashMismatch {
            expected: format_hex_digest(expected),
            got: format_hex_digest(computed),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    use sha256::parse_hex_digest;

    fn empty_digest_hex() -> String {
        // SHA-256 of the empty string.
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into()
    }

    fn sha256_of(payload: &[u8]) -> [u8; DIGEST_LEN] {
        let mut h = Sha256::new();
        h.update(payload);
        h.finalize()
    }

    // ---- HashingReader -------------------------------------------

    #[test]
    fn hashing_reader_passes_through_bytes_and_verifies_at_end() {
        let payload = b"the quick brown fox jumps over the lazy dog".to_vec();
        let expected = sha256_of(&payload);
        let hasher = shared_hasher(IntegrityHasher::single(
            payload.len() as u64,
            Some(expected),
        ));
        let mut reader =
            HashingReader::new(Box::new(Cursor::new(payload.clone())), Arc::clone(&hasher));
        let mut sink = Vec::new();
        std::io::copy(&mut reader, &mut sink).expect("copy");
        assert_eq!(sink, payload);

        let h = hasher.lock().expect("lock");
        // Crossing the only boundary at end-of-stream verified the
        // digest in-line; no error stored.
        assert!(h.error().is_none());
        assert!(h.is_complete());
        assert_eq!(h.bytes_processed(), payload.len() as u64);
    }

    #[test]
    fn hashing_reader_surfaces_mismatch_via_io_error() {
        let payload = b"abcdefghij".to_vec();
        let wrong = [0xFFu8; DIGEST_LEN];
        let hasher = shared_hasher(IntegrityHasher::single(payload.len() as u64, Some(wrong)));
        let mut reader = HashingReader::new(Box::new(Cursor::new(payload)), Arc::clone(&hasher));
        let mut sink = Vec::new();
        // The mismatch fires when the last byte crosses the
        // boundary, so `copy` may either complete cleanly (no read
        // call after the boundary) or surface an io::Error on the
        // next call. Assert the error is recorded either way.
        let _ = std::io::copy(&mut reader, &mut sink);
        let h = hasher.lock().expect("lock");
        match h.error() {
            Some(IntegrityError::HashMismatch { .. }) => {}
            other => panic!("expected HashMismatch, got {other:?}"),
        }
    }

    #[test]
    fn hashing_reader_skip_remaining_consumes_prefix() {
        // Mimic the resume path: the last run hashed `Y` bytes;
        // this run reads from byte X (X < Y), so the first (Y-X)
        // bytes go through unchanged from the hasher's POV.
        let payload = b"abcdefghijklmnop".to_vec();
        let skip = 5u64;
        let expected = sha256_of(&payload);
        // Pre-populate the active hasher with the bytes the prior
        // run already committed (the first `skip` bytes here).
        let mut active = Sha256::new();
        active.update(&payload[..skip as usize]);
        let inner =
            IntegrityHasher::from_single_snapshot(active, payload.len() as u64, Some(expected));
        assert_eq!(inner.bytes_processed(), skip);
        let hasher = shared_hasher(inner);

        let mut reader = HashingReader::with_skip(
            Box::new(Cursor::new(payload.clone())),
            Arc::clone(&hasher),
            skip,
        );
        let mut sink = Vec::new();
        std::io::copy(&mut reader, &mut sink).expect("copy");
        assert_eq!(sink, payload);

        let h = hasher.lock().expect("lock");
        assert!(h.error().is_none());
        assert!(h.is_complete());
    }

    #[test]
    fn hashing_reader_skip_zero_means_hash_everything() {
        let payload = vec![0x42u8; 1024];
        let expected = sha256_of(&payload);
        let hasher = shared_hasher(IntegrityHasher::single(
            payload.len() as u64,
            Some(expected),
        ));
        let mut reader = HashingReader::with_skip(
            Box::new(Cursor::new(payload.clone())),
            Arc::clone(&hasher),
            0,
        );
        std::io::copy(&mut reader, &mut std::io::sink()).expect("copy");
        let h = hasher.lock().expect("lock");
        assert!(h.error().is_none());
        assert!(h.is_complete());
    }

    #[test]
    fn verify_digest_accepts_matching() {
        let expected = parse_hex_digest(&empty_digest_hex()).expect("parse");
        let computed = Sha256::new().finalize();
        verify_digest(&expected, &computed).expect("matching digests accepted");
    }

    #[test]
    fn verify_digest_rejects_mismatch_with_friendly_message() {
        let expected = [0x11u8; DIGEST_LEN];
        let computed = Sha256::new().finalize();
        match verify_digest(&expected, &computed).unwrap_err() {
            IntegrityError::HashMismatch { expected, got } => {
                assert!(expected.starts_with("11"));
                assert!(got.starts_with("e3b0"));
            }
            other => panic!("expected HashMismatch, got {other:?}"),
        }
    }

    // ---- IntegrityHasher single-part ----------------------------

    #[test]
    fn single_part_no_expected_runs_to_completion_silently() {
        let payload = b"hello world".to_vec();
        let mut h = IntegrityHasher::single(payload.len() as u64, None);
        h.update(&payload).expect("update");
        assert!(h.is_complete());
        assert!(h.error().is_none());
    }

    #[test]
    fn single_part_matching_digest_no_error() {
        let payload = b"hello world".to_vec();
        let expected = sha256_of(&payload);
        let mut h = IntegrityHasher::single(payload.len() as u64, Some(expected));
        h.update(&payload).expect("update");
        assert!(h.is_complete());
        assert!(h.error().is_none());
    }

    #[test]
    fn single_part_mismatch_emits_hash_mismatch_at_eos() {
        let payload = b"hello world".to_vec();
        let wrong = [0xAAu8; DIGEST_LEN];
        let mut h = IntegrityHasher::single(payload.len() as u64, Some(wrong));
        let err = h.update(&payload).unwrap_err();
        match err {
            IntegrityError::HashMismatch { .. } => {}
            other => panic!("expected HashMismatch, got {other:?}"),
        }
        // The error sticks: subsequent updates short-circuit.
        let err2 = h.update(b"x").unwrap_err();
        assert!(matches!(err2, IntegrityError::HashMismatch { .. }));
    }

    #[test]
    fn single_part_partial_read_finalize_remaining_emits_mismatch() {
        let payload = b"abcdefgh".to_vec();
        let expected = sha256_of(&payload);
        let mut h = IntegrityHasher::single(payload.len() as u64, Some(expected));
        // Decoder stops mid-way (only consumed 4 bytes).
        h.update(&payload[..4]).expect("update");
        assert!(!h.is_complete());
        let err = h.finalize_remaining().unwrap_err();
        assert!(matches!(err, IntegrityError::HashMismatch { .. }));
    }

    #[test]
    fn finalize_remaining_after_clean_run_is_noop() {
        let payload = b"abc".to_vec();
        let expected = sha256_of(&payload);
        let mut h = IntegrityHasher::single(payload.len() as u64, Some(expected));
        h.update(&payload).expect("update");
        h.finalize_remaining().expect("noop");
    }

    // ---- IntegrityHasher multi-part -----------------------------

    #[test]
    fn multi_part_all_parts_match_no_error() {
        // Three parts, each verified, all clean.
        let p0 = b"part-zero-bytes".to_vec();
        let p1 = b"part-one-bytes-here".to_vec();
        let p2 = b"part-two-final-bytes".to_vec();
        let sizes = [p0.len() as u64, p1.len() as u64, p2.len() as u64];
        let expected = vec![
            Some(sha256_of(&p0)),
            Some(sha256_of(&p1)),
            Some(sha256_of(&p2)),
        ];
        let mut h = IntegrityHasher::multi_part(&sizes, expected);
        // Stream bytes in arbitrary chunks across boundaries.
        let mut full = Vec::new();
        full.extend_from_slice(&p0);
        full.extend_from_slice(&p1);
        full.extend_from_slice(&p2);
        for chunk in full.chunks(7) {
            h.update(chunk).expect("update");
        }
        assert!(h.is_complete());
        assert!(h.error().is_none());
        assert_eq!(h.active_part_idx(), 2);
    }

    #[test]
    fn multi_part_corrupted_part_one_fails_at_boundary_one() {
        // Three parts; part 1's bytes are wrong → verification
        // fires the moment part 1 finishes (before part 2 starts).
        let p0 = b"part-zero-bytes".to_vec();
        let p1_correct = b"part-one-correct".to_vec();
        let p1_corrupt = b"part-one-CORRUPT".to_vec();
        let p2 = b"part-two-final-bytes".to_vec();
        let sizes = [p0.len() as u64, p1_correct.len() as u64, p2.len() as u64];
        // Caller still expects the *original* part-1 digest.
        let expected = vec![
            Some(sha256_of(&p0)),
            Some(sha256_of(&p1_correct)),
            Some(sha256_of(&p2)),
        ];
        let mut h = IntegrityHasher::multi_part(&sizes, expected);
        h.update(&p0).expect("part 0 ok");
        // Part 0 done — error shouldn't appear yet.
        assert!(h.error().is_none());
        assert_eq!(h.active_part_idx(), 1);

        let err = h.update(&p1_corrupt).unwrap_err();
        match err {
            IntegrityError::PartMismatch { part_index, .. } => {
                assert_eq!(part_index, 1);
            }
            other => panic!("expected PartMismatch, got {other:?}"),
        }
        // Subsequent updates are no-ops — the run is doomed.
        let err2 = h.update(&p2).unwrap_err();
        assert!(matches!(
            err2,
            IntegrityError::PartMismatch { part_index: 1, .. }
        ));
        // Still records the part 1 boundary as the failure point.
        assert_eq!(h.active_part_idx(), 1);
    }

    #[test]
    fn multi_part_skips_verification_when_expected_is_none() {
        // 3 parts; part 1 has no expected hash. Bad bytes in part
        // 1 should NOT trigger an error; part 2's verification
        // still runs.
        let p0 = b"zero".to_vec();
        let p1 = b"junk".to_vec(); // any bytes; not verified
        let p2 = b"two!".to_vec();
        let sizes = [p0.len() as u64, p1.len() as u64, p2.len() as u64];
        let expected = vec![Some(sha256_of(&p0)), None, Some(sha256_of(&p2))];
        let mut h = IntegrityHasher::multi_part(&sizes, expected);
        h.update(&p0).expect("p0");
        h.update(&p1).expect("p1 (skipped verification)");
        h.update(&p2).expect("p2");
        assert!(h.is_complete());
        assert!(h.error().is_none());
    }

    #[test]
    fn multi_part_byte_at_a_time_streaming_still_finds_boundaries() {
        let p0 = b"hello".to_vec();
        let p1 = b"world".to_vec();
        let sizes = [p0.len() as u64, p1.len() as u64];
        let expected = vec![Some(sha256_of(&p0)), Some(sha256_of(&p1))];
        let mut h = IntegrityHasher::multi_part(&sizes, expected);
        let full = [p0.clone(), p1.clone()].concat();
        for byte in full {
            h.update(&[byte]).expect("byte");
        }
        assert!(h.is_complete());
        assert!(h.error().is_none());
    }

    #[test]
    fn multi_part_active_part_idx_advances_per_boundary() {
        let sizes = [3u64, 4u64, 5u64];
        let expected = vec![None, None, None];
        let mut h = IntegrityHasher::multi_part(&sizes, expected);
        assert_eq!(h.active_part_idx(), 0);
        h.update(b"abc").expect("p0");
        assert_eq!(h.active_part_idx(), 1);
        h.update(b"defg").expect("p1");
        assert_eq!(h.active_part_idx(), 2);
        h.update(b"hijkl").expect("p2");
        // Stays pinned at the last index after end-of-stream.
        assert_eq!(h.active_part_idx(), 2);
        assert!(h.is_complete());
    }

    #[test]
    fn multi_part_split_at_boundary_emits_mismatch_with_part_zero() {
        // Mismatch at part 0 boundary should report part_index = 0.
        let p0 = b"abc".to_vec();
        let wrong = [0u8; DIGEST_LEN];
        let sizes = [p0.len() as u64, 3u64];
        let expected = vec![Some(wrong), None];
        let mut h = IntegrityHasher::multi_part(&sizes, expected);
        let err = h.update(&p0).unwrap_err();
        match err {
            IntegrityError::PartMismatch { part_index: 0, .. } => {}
            other => panic!("expected PartMismatch part 0, got {other:?}"),
        }
    }

    // ---- snapshot / from_single_snapshot --------------------------

    #[test]
    fn snapshot_active_serialized_round_trips_for_single_url() {
        let payload = b"the quick brown fox".to_vec();
        let mut h = IntegrityHasher::single(payload.len() as u64 * 2, None);
        h.update(&payload).expect("update");
        let serialized = h
            .snapshot_active_serialized()
            .expect("snapshot present pre-error");
        let restored = Sha256::deserialize(&serialized).expect("deserialize");
        assert_eq!(restored.bytes_processed(), payload.len() as u64);
        // Reconstruct the hasher from the snapshot and continue
        // streaming the second half.
        let total = payload.len() as u64 * 2;
        let final_expected = {
            let mut full = Vec::new();
            full.extend_from_slice(&payload);
            full.extend_from_slice(&payload);
            sha256_of(&full)
        };
        let mut h2 = IntegrityHasher::from_single_snapshot(restored, total, Some(final_expected));
        h2.update(&payload).expect("second half");
        assert!(h2.is_complete());
        assert!(h2.error().is_none());
    }

    #[test]
    fn snapshot_returns_none_after_error() {
        let payload = b"abcde".to_vec();
        let wrong = [0xFFu8; DIGEST_LEN];
        let mut h = IntegrityHasher::single(payload.len() as u64, Some(wrong));
        let _ = h.update(&payload).unwrap_err();
        assert!(h.snapshot_active_serialized().is_none());
    }
}
