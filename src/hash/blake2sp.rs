//! Hand-rolled BLAKE2sp (parallel BLAKE2s, 8 lanes).
//!
//! BLAKE2sp is RAR5's file-data integrity hash. It is *not* used
//! anywhere else in `peel` (`internal/PLAN_v2.md` §10's integrity check
//! is SHA-256; ZIP and 7z use CRC-32 / BLAKE3 / no-op variants), so
//! this module ships alongside the rest of the RAR support per
//! `internal/PLAN_rar.md` §2.
//!
//! # Construction
//!
//! BLAKE2sp wraps eight independent [`Blake2s`] instances ("lanes")
//! running at tree-depth 0 plus one root [`Blake2s`] at tree-depth 1.
//! Input bytes are striped across the lanes at 64-byte block
//! granularity: the first 64-byte block goes to lane 0, the second
//! to lane 1, …, the eighth to lane 7, the ninth back to lane 0,
//! and so on. After the input is exhausted each lane is finalized
//! into a 32-byte digest, the eight digests are concatenated, and
//! the resulting 256-byte block is fed to the root. Lane 7 and the
//! root carry the `last_node` flag (set on their final compression
//! along with `last_block`) per the BLAKE2 reference
//! (`blake2sp.c` / RFC 7693 §B + the BLAKE2 paper).
//!
//! # Why hand-rolled
//!
//! Mainstream Rust BLAKE2 crates have dropped the parallel
//! variants — `blake2 = "0.10"` exposes only `Blake2s` and
//! `Blake2b`, not `Blake2sp` / `Blake2bp` — and the older crates
//! that still expose them are unmaintained. The `digest`-style API
//! we'd want for the §3 STORED-method pipeline (mid-entry resume
//! via serialized internal state) is also not on offer. Hand-rolling
//! the construction is short — RFC 7693 §2.5 + §3 + the BLAKE2 paper
//! §3.3 covers everything — and the `[dev-dependencies]`-only
//! `blake2` crate gives us a battle-tested BLAKE2s primitive to
//! cross-check the underlying compression function against. The
//! tree construction itself is verified against the BLAKE2 reference
//! corpus's empty-input KAT vector (`testvectors/blake2-kat.json`).
//! Same precedent as [`crate::hash::sha256`]'s `sha2` cross-check.
//!
//! # Round-one limitations
//!
//! - **No keyed mode.** BLAKE2 supports a keyed hash (HMAC-style
//!   prefix) but RAR5 uses the unkeyed digest exclusively.
//! - **No salt / personalization.** RAR5 leaves both the salt and
//!   personalization fields zero.
//! - **No mid-stream serialization yet.** §3 plans to add it for
//!   STORED-method resume; round-one §2 ships the basic
//!   `new` / `update` / `finalize` only.

use thiserror::Error;

/// BLAKE2s output length, in bytes. Matches the 32-byte
/// fixed-output BLAKE2sp produces.
pub const DIGEST_LEN: usize = 32;

/// BLAKE2s block size, in bytes. The compression function
/// processes one block per call.
const BLOCK_LEN: usize = 64;

/// BLAKE2s parallelism degree for BLAKE2sp.
const PARALLELISM: usize = 8;

/// BLAKE2s initial hash value (FIPS 180-4 SHA-256 IV — the BLAKE2
/// designers reused these eight constants per RFC 7693 §3.2).
const IV: [u32; 8] = [
    0x6A09_E667,
    0xBB67_AE85,
    0x3C6E_F372,
    0xA54F_F53A,
    0x510E_527F,
    0x9B05_688C,
    0x1F83_D9AB,
    0x5BE0_CD19,
];

/// BLAKE2 round permutations (RFC 7693 §2.7 / §3.1). Indexed by
/// round (`r % 10`) and column-index within the round.
const SIGMA: [[u8; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

/// Errors produced when deserializing a saved BLAKE2sp state.
///
/// §3 will add the serialization API; the variants are defined here
/// so the `mod.rs` re-export surface is stable.
#[derive(Debug, Error)]
pub enum Blake2spDeserializeError {
    /// Saved blob was the wrong length for the on-wire layout.
    #[error("BLAKE2sp serialized blob has length {got}, expected {expected}")]
    BadLength {
        /// Length of the supplied buffer.
        got: usize,
        /// Length the deserializer expected.
        expected: usize,
    },
    /// Saved blob's version byte was not recognized.
    #[error("BLAKE2sp serialized blob has unrecognized version byte {got}")]
    BadVersion {
        /// The version byte we found.
        got: u8,
    },
    /// Saved blob carried an out-of-range field (e.g. a `buf_len` >
    /// 64 inside a leaf state).
    #[error("BLAKE2sp serialized blob is corrupt: {reason}")]
    BadField {
        /// Human-readable reason.
        reason: String,
    },
}

/// BLAKE2s parameter block (RFC 7693 §2.5). Round-one only sets
/// the fields BLAKE2sp uses; salt + personalization stay zero.
#[derive(Debug, Clone, Copy)]
struct Blake2sParams {
    digest_length: u8,
    fanout: u8,
    depth: u8,
    node_offset: u64,
    node_depth: u8,
    inner_length: u8,
}

impl Blake2sParams {
    /// Render the parameter block to its on-wire 32-byte form so
    /// the BLAKE2s init step can XOR it into `h`.
    fn to_bytes(self) -> [u8; 32] {
        let mut p = [0u8; 32];
        p[0] = self.digest_length;
        // p[1] = key_length (always 0 for BLAKE2sp)
        p[2] = self.fanout;
        p[3] = self.depth;
        // p[4..8] = leaf_length (always 0 for BLAKE2sp; sequential
        //           hashing has no leaf-length pre-commitment).
        // node_offset is 48-bit LE.
        let no = self.node_offset.to_le_bytes();
        p[8..14].copy_from_slice(&no[0..6]);
        p[14] = self.node_depth;
        p[15] = self.inner_length;
        // p[16..32] = salt + personalization (all zero in RAR5).
        p
    }
}

/// Parameter block for plain (non-tree-mode) BLAKE2s. Sets
/// `fanout = 1, depth = 1, inner_length = 0`. Used by the
/// underlying-primitive cross-check tests; the production
/// BLAKE2sp construction never instantiates a [`Blake2s`] this way
/// (every leaf uses [`leaf_params`] and the root uses
/// [`root_params`]).
#[cfg(test)]
fn plain_params() -> Blake2sParams {
    Blake2sParams {
        digest_length: DIGEST_LEN as u8,
        fanout: 1,
        depth: 1,
        node_offset: 0,
        node_depth: 0,
        inner_length: 0,
    }
}

/// Parameter block for BLAKE2sp leaf number `lane` (0..8).
fn leaf_params(lane: u64) -> Blake2sParams {
    Blake2sParams {
        digest_length: DIGEST_LEN as u8,
        fanout: PARALLELISM as u8,
        depth: 2,
        node_offset: lane,
        node_depth: 0,
        inner_length: DIGEST_LEN as u8,
    }
}

/// Parameter block for the BLAKE2sp root.
fn root_params() -> Blake2sParams {
    Blake2sParams {
        digest_length: DIGEST_LEN as u8,
        fanout: PARALLELISM as u8,
        depth: 2,
        node_offset: 0,
        node_depth: 1,
        inner_length: DIGEST_LEN as u8,
    }
}

/// Single-lane BLAKE2s. Internal building block — public callers
/// use [`Blake2sp`].
#[derive(Debug, Clone, Copy)]
struct Blake2s {
    h: [u32; 8],
    /// Bytes processed so far including the partial buffer.
    /// Doubles as the BLAKE2 counter `t` (interpreted as `u64`).
    bytes_processed: u64,
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    /// `true` for the rightmost node at the leaves' depth (i.e.
    /// lane 7) and for the root. Sets the `f1` finalization flag
    /// on the final compression.
    last_node: bool,
}

impl Blake2s {
    /// Initialize from the supplied parameter block.
    fn with_params(params: Blake2sParams) -> Self {
        let mut h = IV;
        let p = params.to_bytes();
        for (i, hi) in h.iter_mut().enumerate() {
            let pi = u32::from_le_bytes([p[i * 4], p[i * 4 + 1], p[i * 4 + 2], p[i * 4 + 3]]);
            *hi ^= pi;
        }
        Self {
            h,
            bytes_processed: 0,
            buf: [0u8; BLOCK_LEN],
            buf_len: 0,
            last_node: false,
        }
    }

    /// BLAKE2s compression function (RFC 7693 §3.2).
    ///
    /// Compresses one 64-byte block into the running state. The
    /// `last_block` flag stamps `f0 = 0xFFFFFFFF`; if the lane's
    /// `last_node` is set, `f1 = 0xFFFFFFFF` is also stamped.
    fn compress(&mut self, block: &[u8; BLOCK_LEN], last_block: bool) {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            *word = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }

        let mut v = [0u32; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.bytes_processed as u32;
        v[13] ^= (self.bytes_processed >> 32) as u32;
        if last_block {
            v[14] ^= 0xFFFF_FFFF;
            if self.last_node {
                v[15] ^= 0xFFFF_FFFF;
            }
        }

        for s in &SIGMA {
            // Column step.
            g(&mut v, 0, 4, 8, 12, m[s[0] as usize], m[s[1] as usize]);
            g(&mut v, 1, 5, 9, 13, m[s[2] as usize], m[s[3] as usize]);
            g(&mut v, 2, 6, 10, 14, m[s[4] as usize], m[s[5] as usize]);
            g(&mut v, 3, 7, 11, 15, m[s[6] as usize], m[s[7] as usize]);
            // Diagonal step.
            g(&mut v, 0, 5, 10, 15, m[s[8] as usize], m[s[9] as usize]);
            g(&mut v, 1, 6, 11, 12, m[s[10] as usize], m[s[11] as usize]);
            g(&mut v, 2, 7, 8, 13, m[s[12] as usize], m[s[13] as usize]);
            g(&mut v, 3, 4, 9, 14, m[s[14] as usize], m[s[15] as usize]);
        }

        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }

    /// Feed `input` into the running state. Buffers up to one
    /// 64-byte block at a time so the final call (which sets
    /// `last_block`) can be deferred until [`Self::finalize`].
    fn update(&mut self, mut input: &[u8]) {
        if input.is_empty() {
            return;
        }
        // Top up the existing buffer first; only compress it if we
        // have at least one byte beyond what fills it (so the last
        // block is held back for finalize, which sets f0).
        if self.buf_len > 0 {
            let space = BLOCK_LEN - self.buf_len;
            if input.len() > space {
                self.buf[self.buf_len..].copy_from_slice(&input[..space]);
                self.bytes_processed = self.bytes_processed.wrapping_add(BLOCK_LEN as u64);
                let block = self.buf;
                self.compress(&block, false);
                self.buf_len = 0;
                input = &input[space..];
            } else {
                self.buf[self.buf_len..self.buf_len + input.len()].copy_from_slice(input);
                self.buf_len += input.len();
                return;
            }
        }
        // Compress full blocks while there's strictly more than a
        // block of input left (so the very last full block is held
        // back for finalize).
        while input.len() > BLOCK_LEN {
            let mut block = [0u8; BLOCK_LEN];
            block.copy_from_slice(&input[..BLOCK_LEN]);
            self.bytes_processed = self.bytes_processed.wrapping_add(BLOCK_LEN as u64);
            self.compress(&block, false);
            input = &input[BLOCK_LEN..];
        }
        // Anything left (1..=64 bytes) becomes the new partial buffer.
        self.buf[..input.len()].copy_from_slice(input);
        self.buf_len = input.len();
    }

    /// Finalize the running state and return the 32-byte digest.
    fn finalize(mut self) -> [u8; DIGEST_LEN] {
        self.bytes_processed = self.bytes_processed.wrapping_add(self.buf_len as u64);
        // Zero-pad the partial buffer to the full block size.
        for b in &mut self.buf[self.buf_len..] {
            *b = 0;
        }
        let block = self.buf;
        self.compress(&block, true);
        let mut out = [0u8; DIGEST_LEN];
        for (i, word) in self.h.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

/// One BLAKE2 G mixing step (RFC 7693 §3.1).
#[inline]
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

/// BLAKE2sp: parallel BLAKE2s with 8 lanes.
///
/// Use [`Blake2sp::new`] to construct a fresh hasher, [`Blake2sp::update`]
/// to feed input bytes (in any chunking — the lane routing is
/// position-driven, not chunk-driven), and [`Blake2sp::finalize`] to
/// finish and produce the 32-byte digest.
#[derive(Debug, Clone, Copy)]
pub struct Blake2sp {
    leaves: [Blake2s; PARALLELISM],
    root: Blake2s,
    /// Total input bytes consumed at the BLAKE2sp level. Drives
    /// the lane-routing arithmetic (`block_index = bytes / 64`,
    /// `lane = block_index % 8`).
    total_bytes: u64,
}

impl Default for Blake2sp {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake2sp {
    /// Initialize a fresh BLAKE2sp hasher.
    #[must_use]
    pub fn new() -> Self {
        let mut leaves: [Blake2s; PARALLELISM] =
            std::array::from_fn(|i| Blake2s::with_params(leaf_params(i as u64)));
        // Only the rightmost leaf at the leaves' depth is the
        // "last node"; the root is the only node at its depth so
        // `last_node` is set there too.
        leaves[PARALLELISM - 1].last_node = true;
        let mut root = Blake2s::with_params(root_params());
        root.last_node = true;
        Self {
            leaves,
            root,
            total_bytes: 0,
        }
    }

    /// Feed a chunk of input bytes through the hasher. Stripes the
    /// bytes across the eight lanes at 64-byte block granularity:
    /// block `i` of the *whole input stream* (counting from byte 0
    /// of the first `update` call) goes to lane `i % 8`.
    pub fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            let lane = ((self.total_bytes / BLOCK_LEN as u64) % PARALLELISM as u64) as usize;
            let block_off = (self.total_bytes % BLOCK_LEN as u64) as usize;
            let take = (BLOCK_LEN - block_off).min(input.len());
            self.leaves[lane].update(&input[..take]);
            self.total_bytes = self.total_bytes.wrapping_add(take as u64);
            input = &input[take..];
        }
    }

    /// Finalize the hasher and return the 32-byte digest.
    #[must_use]
    pub fn finalize(self) -> [u8; DIGEST_LEN] {
        let Self {
            leaves,
            mut root,
            total_bytes: _,
        } = self;
        // Concatenate the eight lane digests into a 256-byte
        // pseudo-input for the root.
        let mut leaf_digests = [0u8; PARALLELISM * DIGEST_LEN];
        for (i, leaf) in leaves.into_iter().enumerate() {
            let d = leaf.finalize();
            leaf_digests[i * DIGEST_LEN..(i + 1) * DIGEST_LEN].copy_from_slice(&d);
        }
        root.update(&leaf_digests);
        root.finalize()
    }
}

/// Convenience: full-buffer BLAKE2sp in one call.
#[must_use]
pub fn hash(input: &[u8]) -> [u8; DIGEST_LEN] {
    let mut h = Blake2sp::new();
    h.update(input);
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    use blake2::digest::consts::U32;
    use blake2::digest::Update;
    use blake2::Blake2s;
    use blake2::Digest as RefDigest;

    /// Reference plain BLAKE2s (sequential, fanout=1, depth=1)
    /// computed via the `blake2 = 0.10` dev-dep. Used to
    /// cross-check our [`Blake2s`] primitive on plain inputs;
    /// indirectly verifies the compression function, the message
    /// schedule, and the IV / parameter-block XOR.
    ///
    /// The dev-dep does not expose BLAKE2sp; we cross-check the
    /// tree construction separately against the well-known
    /// empty-input KAT vector.
    fn ref_plain_blake2s(input: &[u8]) -> [u8; DIGEST_LEN] {
        let mut h = <Blake2s<U32> as RefDigest>::new();
        Update::update(&mut h, input);
        let out = h.finalize();
        let mut bytes = [0u8; DIGEST_LEN];
        bytes.copy_from_slice(&out);
        bytes
    }

    fn our_plain_blake2s(input: &[u8]) -> [u8; DIGEST_LEN] {
        let mut h = super::Blake2s::with_params(plain_params());
        h.update(input);
        h.finalize()
    }

    #[test]
    fn primitive_matches_reference_on_empty_input() {
        // Plain BLAKE2s of empty input has a fixed RFC-7693 §B
        // value; the dev-dep encodes it.
        assert_eq!(our_plain_blake2s(b""), ref_plain_blake2s(b""));
    }

    #[test]
    fn primitive_matches_reference_on_abc() {
        assert_eq!(our_plain_blake2s(b"abc"), ref_plain_blake2s(b"abc"));
    }

    #[test]
    fn primitive_matches_reference_on_one_full_block() {
        let payload = [0x5Au8; 64];
        assert_eq!(our_plain_blake2s(&payload), ref_plain_blake2s(&payload));
    }

    #[test]
    fn primitive_matches_reference_on_block_plus_one() {
        let payload = [0x42u8; 65];
        assert_eq!(our_plain_blake2s(&payload), ref_plain_blake2s(&payload));
    }

    #[test]
    fn primitive_matches_reference_on_random_input_4kib() {
        let mut payload = vec![0u8; 4 * 1024];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (((i as u64).wrapping_mul(11_400_714_819_323_198_485)) >> 53) as u8;
        }
        assert_eq!(our_plain_blake2s(&payload), ref_plain_blake2s(&payload));
    }

    #[test]
    fn primitive_streaming_invariant_against_reference() {
        // Same input, hashed at every possible single split point,
        // must agree with the one-shot reference call.
        let payload: Vec<u8> = (0..200u32).map(|i| ((i * 17 + 3) & 0xFF) as u8).collect();
        let baseline = ref_plain_blake2s(&payload);
        for split in 0..=payload.len() {
            let mut h = super::Blake2s::with_params(plain_params());
            h.update(&payload[..split]);
            h.update(&payload[split..]);
            assert_eq!(h.finalize(), baseline, "split at {split} disagreed");
        }
    }

    /// BLAKE2sp(`""`) — the well-known KAT vector from the BLAKE2
    /// reference test corpus
    /// (`testvectors/blake2-kat.json`, also reproduced in the BLAKE2
    /// paper's §B.4). The empty-input digest is a tight sanity
    /// check on the entire tree construction: an off-by-one in
    /// the parameter block, lane routing, or last-node flagging
    /// shifts every byte.
    const EMPTY_INPUT_BLAKE2SP_KAT: [u8; DIGEST_LEN] = [
        0xdd, 0x0e, 0x89, 0x17, 0x76, 0x93, 0x3f, 0x43, 0xc7, 0xd0, 0x32, 0xb0, 0x8a, 0x91, 0x7e,
        0x25, 0x74, 0x1f, 0x8a, 0xa9, 0xa1, 0x2c, 0x12, 0xe1, 0xca, 0xc8, 0x80, 0x15, 0x00, 0xf2,
        0xca, 0x4f,
    ];

    #[test]
    fn matches_kat_vector_for_empty_input() {
        assert_eq!(hash(b""), EMPTY_INPUT_BLAKE2SP_KAT);
    }

    #[test]
    fn streaming_chunks_match_one_shot() {
        let payload = b"the quick brown fox jumps over the lazy dog \
                        ___ extra bytes to push us across multiple lane \
                        boundaries and into a partial trailing block.";
        let one_shot = hash(payload);
        let mut streamed = Blake2sp::new();
        for b in payload {
            streamed.update(&[*b]);
        }
        assert_eq!(streamed.finalize(), one_shot);
    }

    #[test]
    fn chunking_invariance_across_arbitrary_split_points() {
        // Same payload hashed at every possible single split point
        // must yield the same digest as the one-shot call. This
        // catches bugs in the lane routing where mid-stream split
        // points would otherwise rotate the lane assignment.
        let payload: Vec<u8> = (0..200u32).map(|i| ((i * 17 + 3) & 0xFF) as u8).collect();
        let baseline = hash(&payload);
        for split in 0..=payload.len() {
            let mut h = Blake2sp::new();
            h.update(&payload[..split]);
            h.update(&payload[split..]);
            assert_eq!(h.finalize(), baseline, "split at {split} disagreed");
        }
    }

    #[test]
    fn chunking_invariance_across_lane_boundaries() {
        // Specifically split at every 64-byte lane boundary in a
        // multi-pass input to stress the lane-routing arithmetic.
        let payload: Vec<u8> = (0..1024u32).map(|i| (i & 0xFF) as u8).collect();
        let baseline = hash(&payload);
        for boundary in (0..=payload.len()).step_by(64) {
            let mut h = Blake2sp::new();
            h.update(&payload[..boundary]);
            h.update(&payload[boundary..]);
            assert_eq!(
                h.finalize(),
                baseline,
                "split at lane boundary {boundary} disagreed"
            );
        }
    }

    #[test]
    fn distinct_inputs_produce_distinct_digests() {
        // Trivial avalanche check: flipping any byte must change
        // the digest. Catches mistakes that would collapse the
        // hash to a constant or to an input prefix.
        let payload = b"hello, world".to_vec();
        let baseline = hash(&payload);
        for i in 0..payload.len() {
            let mut mutated = payload.clone();
            mutated[i] ^= 0x01;
            assert_ne!(hash(&mutated), baseline, "byte {i} flip produced collision");
        }
    }

    #[test]
    fn determinism() {
        let payload: Vec<u8> = (0..1234u32).map(|i| (i & 0xFF) as u8).collect();
        let a = hash(&payload);
        let b = hash(&payload);
        assert_eq!(a, b);
    }
}
