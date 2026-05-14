//! Inverse Burrows–Wheeler Transform for the hand-rolled bzip2
//! decoder.
//!
//! `internal/PLAN_bz2_support.md` Phase 5. Given the BWT-permuted
//! "last column" `L` of a sorted-rotations matrix and an origin
//! pointer `origPtr` (the row of the original sequence), this module
//! reconstructs the original byte order in O(N) time and O(N)
//! memory.
//!
//! # Algorithm
//!
//! libbz2's "tt" walk, packed into a single `T: Vec<u32>` so the
//! hot loop does one indexed load per byte. Build:
//!
//! ```text
//! LF(i) = starts[L[i]] + (count of L[j] == L[i] for j < i)
//! starts[b] = number of characters in L strictly less than b
//!
//! T[LF(i)] = (i << 8) | L[i]
//! ```
//!
//! So `T[k]` stores `(i, L[i])` for the unique `i` such that
//! `LF(i) == k`. Equivalently `T` packs the **FL mapping** (the
//! inverse of LF). Walking from `origPtr`:
//!
//! ```text
//! state = T[origPtr]
//! for k in 0..N {
//!     emit state & 0xFF
//!     state = T[state >> 8]
//! }
//! ```
//!
//! emits the original sequence in **forward** order. The plan's
//! prose described the LF-side formulation (`T[i] = L[i] | (LF(i)
//! << 8)`); that walks in reverse, which is why the FL form here is
//! preferred — it preserves the one-indexed-load-per-byte cost and
//! drops a trailing reverse-in-place pass.
//!
//! The walk is the hot path; one indexed load + one shift + one
//! mask per byte. Working memory is `4 * N` bytes (the `T` array)
//! plus the 256-entry `starts` / `running` scratch — bounded at
//! ~3.6 MiB for a 900 KB block (the maximum bzip2 level).

use super::error::Bzip2Error;

/// Run the BWT inverse on `l` with origin pointer `orig_ptr`.
///
/// `l` is the BWT-permuted "last column" (the post-MTF byte stream
/// from [`super::rle2::apply_inverse`]). `orig_ptr` is read from the
/// block header in [`super::block::parse_block_header`].
///
/// Returns the post-BWT byte stream — equivalently, the bytes the
/// encoder passed *into* the BWT and *out of* the RLE1 stage (i.e.
/// the input to the per-block CRC and to the stream-level RLE1
/// inverse).
///
/// # Errors
///
/// - [`Bzip2Error::OriginPointerOutOfRange`] if `orig_ptr >= l.len()`.
pub fn invert(l: &[u8], orig_ptr: u32) -> Result<Vec<u8>, Bzip2Error> {
    let n = l.len();
    if n == 0 {
        // A bzip2 block can't be empty (the symbol-set bitmap is
        // non-empty by Phase 2 invariant, and at least one
        // RUNA/MTF symbol always precedes EOB), but bound the
        // empty-input path anyway.
        return Ok(Vec::new());
    }
    let orig_ptr_usize = orig_ptr as usize;
    if orig_ptr_usize >= n {
        // INVARIANT: n fits in u32 (block size <= 900_000).
        return Err(Bzip2Error::OriginPointerOutOfRange {
            orig_ptr,
            block_len: n as u32,
        });
    }

    // Count occurrences of each byte in L.
    let mut counts = [0u32; 256];
    for &b in l {
        counts[b as usize] = counts[b as usize].saturating_add(1);
    }
    // Build `starts`: prefix-sum of `counts`. `starts[b]` is the
    // row in F where the first instance of byte `b` appears.
    let mut starts = [0u32; 256];
    let mut acc = 0u32;
    for b in 0..256 {
        starts[b] = acc;
        acc = acc.saturating_add(counts[b]);
    }
    debug_assert_eq!(acc as usize, n);

    // Reuse a fresh counter as the "running rank" tracker.
    let mut running = [0u32; 256];
    // Build T[LF(i)] = (i << 8) | L[i] — the FL mapping, so the
    // walk emits forward.
    let mut t: Vec<u32> = vec![0; n];
    for (i, &b) in l.iter().enumerate() {
        let lf = starts[b as usize] + running[b as usize];
        running[b as usize] = running[b as usize].saturating_add(1);
        // INVARIANT: i <= n-1 < 2^24 (bzip2 caps blocks at
        // 900_000), so packing `(i << 8) | byte` fits in u32.
        // INVARIANT: lf < n by construction (prefix-sum
        // cardinality argument).
        t[lf as usize] = ((i as u32) << 8) | u32::from(b);
    }

    // Walk from `orig_ptr`. `T[orig_ptr]` already carries the
    // first emit, so we step `state = T[state >> 8]` afterwards.
    // INVARIANT: every `state >> 8` index lands in `0..n` because
    // the FL mapping is a permutation of `0..n`.
    let mut out = Vec::with_capacity(n);
    let mut state = t[orig_ptr_usize];
    for _ in 0..n {
        out.push((state & 0xFF) as u8);
        state = t[(state >> 8) as usize];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Forward BWT on `s`: produce `(L, orig_ptr)` for testing
    /// round-trips. Slow (O(N^2 log N)) — only used to verify the
    /// inverse against small fixtures.
    fn bwt_forward(s: &[u8]) -> (Vec<u8>, u32) {
        let n = s.len();
        let mut rotations: Vec<usize> = (0..n).collect();
        rotations.sort_by(|&a, &b| {
            for k in 0..n {
                let ca = s[(a + k) % n];
                let cb = s[(b + k) % n];
                if ca != cb {
                    return ca.cmp(&cb);
                }
            }
            std::cmp::Ordering::Equal
        });
        let l: Vec<u8> = rotations.iter().map(|&r| s[(r + n - 1) % n]).collect();
        // INVARIANT: `s.len() <= u32::MAX` for any practical input.
        let orig_ptr = rotations.iter().position(|&r| r == 0).expect("orig row") as u32;
        (l, orig_ptr)
    }

    #[test]
    fn round_trips_short_string() {
        let s = b"banana".to_vec();
        let (l, orig_ptr) = bwt_forward(&s);
        let recovered = invert(&l, orig_ptr).expect("invert");
        assert_eq!(recovered, s);
    }

    #[test]
    fn round_trips_alphabetic_string() {
        let s: Vec<u8> = (b'a'..=b'z').collect();
        let (l, orig_ptr) = bwt_forward(&s);
        let recovered = invert(&l, orig_ptr).expect("invert");
        assert_eq!(recovered, s);
    }

    #[test]
    fn round_trips_repeat_heavy_string() {
        let s = b"aaaabbbbccccddddeeeeffffgggghhhh".to_vec();
        let (l, orig_ptr) = bwt_forward(&s);
        let recovered = invert(&l, orig_ptr).expect("invert");
        assert_eq!(recovered, s);
    }

    #[test]
    fn round_trips_random_bytes() {
        // Deterministic PRNG: linear-congruential, kept short
        // (256 bytes) because the in-test forward BWT is
        // O(N² log N) on full-string compares and would dominate
        // debug-build test time at larger sizes.
        let mut state = 0x1234_5678u32;
        let mut s = vec![0u8; 256];
        for b in &mut s {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            *b = (state >> 16) as u8;
        }
        let (l, orig_ptr) = bwt_forward(&s);
        let recovered = invert(&l, orig_ptr).expect("invert");
        assert_eq!(recovered, s);
    }

    #[test]
    fn rejects_out_of_range_orig_ptr() {
        let l = vec![0u8, 1, 2, 3];
        match invert(&l, 4) {
            Err(Bzip2Error::OriginPointerOutOfRange {
                orig_ptr,
                block_len,
            }) => {
                assert_eq!(orig_ptr, 4);
                assert_eq!(block_len, 4);
            }
            other => panic!("expected OriginPointerOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn single_byte_block_round_trips() {
        let s = b"!".to_vec();
        let (l, orig_ptr) = bwt_forward(&s);
        let recovered = invert(&l, orig_ptr).expect("invert");
        assert_eq!(recovered, s);
    }

    #[test]
    fn empty_input_returns_empty() {
        let out = invert(&[], 0).expect("empty");
        assert!(out.is_empty());
    }
}
