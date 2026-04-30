//! Cryptographic / integrity hashes used at the binary boundary.
//!
//! Today this module hosts a hand-rolled, FIPS 180-4 SHA-256
//! implementation with a serializable mid-stream state. See
//! [`sha256`] for the implementation rationale (`docs/PLAN_v2.md`
//! §10) — the short version is that resumable hashing needs the
//! state to be saveable between runs, and the upstream `sha2` crate
//! does not expose that without poking at private fields.
//!
//! On top of that primitive sit two pieces of plumbing:
//!
//! - [`HashingReader`] — a `Read` adapter that tees every byte
//!   pulled from an inner source into a shared SHA-256 hasher,
//!   with optional skip-on-resume support so the in-progress
//!   hash state survives a `kill -9` (`PLAN_v2.md` §10 step 4).
//! - [`IntegrityError`] — the typed error the binary surfaces
//!   when the user's `--sha256 <hex>` does not match the digest
//!   of the bytes we received.
//!
//! Both are crate-public so the coordinator can wire them in at
//! the source-reader boundary; production callers go through the
//! `--sha256` CLI flag rather than touching this module directly.

pub mod crc32c;
pub mod sha256;

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
    /// expected digest the user provided.
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
}

/// Shared, mutex-protected handle to a streaming SHA-256 hasher.
///
/// The handle is held by both the [`HashingReader`] (which feeds
/// bytes in from one thread on every `read`) and the coordinator
/// (which snapshots the state at quiescent checkpoints and
/// finalizes at end of run). Only one writer touches it at a time
/// in practice — the extractor's decoder runs on a single thread
/// and the checkpoint observer pauses it — so the mutex sees no
/// contention; we use it only because the underlying
/// [`Box<dyn Read + Send>`] erases lifetimes and forbids
/// borrowing.
pub type SharedHasher = Arc<Mutex<Sha256>>;

/// Wrap `inner` in a [`Mutex`] and return a fresh [`SharedHasher`].
///
/// Convenience constructor used at the binary boundary; tests
/// build the same shape with [`Arc::new`] +
/// [`Mutex::new`] directly.
#[must_use]
pub fn shared_hasher(inner: Sha256) -> SharedHasher {
    Arc::new(Mutex::new(inner))
}

/// `Read` adapter that tees source bytes into a [`SharedHasher`].
///
/// Sits between the sparse-file reader and the decoder: every byte
/// the decoder pulls flows through `read`, gets forwarded to the
/// hasher, and is then handed back to the decoder. The decoder is
/// unaware the adapter exists.
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
    /// snapshot or finalize the hash state on its own cadence.
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
            guard.update(to_hash);
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

    #[test]
    fn hashing_reader_hashes_pass_through_bytes() {
        let payload = b"the quick brown fox jumps over the lazy dog".to_vec();
        let hasher = shared_hasher(Sha256::new());
        let mut reader =
            HashingReader::new(Box::new(Cursor::new(payload.clone())), Arc::clone(&hasher));
        let mut sink = Vec::new();
        std::io::copy(&mut reader, &mut sink).expect("copy");
        assert_eq!(sink, payload);

        let mut clean = Sha256::new();
        clean.update(&payload);
        let want = clean.finalize();
        let got = hasher.lock().expect("lock").clone().finalize();
        assert_eq!(got, want);
    }

    #[test]
    fn hashing_reader_skip_remaining_consumes_prefix() {
        // Mimic the resume path: the last run hashed `Y` bytes;
        // this run reads from byte X (X < Y), so the first (Y-X)
        // bytes go through unchanged from the hasher's POV.
        let payload = b"abcdefghijklmnop".to_vec();
        let skip = 5;
        let hasher = shared_hasher(Sha256::new());
        // Pre-populate the hasher with the bytes that the previous
        // run had already committed (the first `skip` bytes here).
        hasher
            .lock()
            .expect("lock")
            .update(&payload[..skip as usize]);

        let mut reader = HashingReader::with_skip(
            Box::new(Cursor::new(payload.clone())),
            Arc::clone(&hasher),
            skip,
        );
        let mut sink = Vec::new();
        std::io::copy(&mut reader, &mut sink).expect("copy");
        assert_eq!(sink, payload);

        // Final digest must match the digest of the *whole* payload.
        let mut clean = Sha256::new();
        clean.update(&payload);
        let want = clean.finalize();
        let got = hasher.lock().expect("lock").clone().finalize();
        assert_eq!(got, want);
    }

    #[test]
    fn hashing_reader_skip_zero_means_hash_everything() {
        let payload = vec![0x42u8; 1024];
        let hasher = shared_hasher(Sha256::new());
        let mut reader = HashingReader::with_skip(
            Box::new(Cursor::new(payload.clone())),
            Arc::clone(&hasher),
            0,
        );
        std::io::copy(&mut reader, &mut std::io::sink()).expect("copy");

        let mut clean = Sha256::new();
        clean.update(&payload);
        assert_eq!(
            hasher.lock().expect("lock").clone().finalize(),
            clean.finalize(),
        );
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
}
