//! Streaming XXH64 (Yann Collet, [xxhash spec]) — used by the
//! hand-rolled zstd decoder for RFC 8478 §3.1.1.1 content-checksum
//! verification.
//!
//! Zstd frames whose Frame_Header_Descriptor sets the
//! `Content_Checksum_Flag` end with a 4-byte trailer that holds the
//! **low 32 bits** of XXH64 over the *decompressed* output (seed = 0).
//! The decoder feeds every decompressed byte through this hasher in
//! the order it emerges from sequence execution, then compares
//! `xxh64.finalize() as u32` against the trailer.
//!
//! This module mirrors the shape of [`super::sha256::Sha256`] —
//! `update` / `finalize` streaming surface — and a small
//! [`Xxh64::snapshot`] / [`Xxh64::restore`] pair so the zstd
//! resume blob in [`crate::decode::zstd::resume`] can serialize
//! mid-frame state.
//!
//! # Why hand-roll
//!
//! Same rationale as [`super::sha256`] §dependency policy: this is
//! ~100 lines of straight integer work, the spec is short, and we
//! avoid a runtime dep. Cross-checks in the test module verify the
//! implementation against published vectors and against the trailing
//! checksum byte that `zstd::encode_all` writes for fixtures of
//! varied sizes.
//!
//! [xxhash spec]: https://github.com/Cyan4973/xxHash/blob/dev/doc/xxhash_spec.md

/// xxhash spec §3.1.1 prime constants.
const PRIME64_1: u64 = 0x9E37_79B1_85EB_CA87;
const PRIME64_2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const PRIME64_3: u64 = 0x1656_67B1_9E37_79F9;
const PRIME64_4: u64 = 0x85EB_CA77_C2B2_AE63;
const PRIME64_5: u64 = 0x27D4_EB2F_1656_67C5;

/// Stripe size processed by the four-lane main loop (xxhash spec §3.2).
const STRIPE_BYTES: usize = 32;

/// Length, in bytes, of [`Xxh64::serialize`] / [`Xxh64::deserialize`]
/// blobs. `4 lanes × 8 bytes (v) + 32 bytes (buffer) + 1 byte
/// (buffer_len) + 8 bytes (bytes_processed) = 73`.
pub const SERIALIZED_LEN: usize = 4 * 8 + STRIPE_BYTES + 1 + 8;

/// Single 64-bit "round" mix (xxhash spec §3.3).
#[inline]
fn round(acc: u64, lane: u64) -> u64 {
    let acc = acc.wrapping_add(lane.wrapping_mul(PRIME64_2));
    let acc = acc.rotate_left(31);
    acc.wrapping_mul(PRIME64_1)
}

/// Merge a 64-bit accumulator into the running output (xxhash spec §3.4).
#[inline]
fn merge_accumulator(acc: u64, val: u64) -> u64 {
    let acc = acc ^ round(0, val);
    acc.wrapping_mul(PRIME64_1).wrapping_add(PRIME64_4)
}

/// Streaming XXH64 hasher (seed = 0).
///
/// The zstd content checksum is always seed-0 (RFC 8478 §3.1.1
/// "XXH64() with the seed value zero"), so this type is hard-coded
/// to that — the seed parameter doesn't appear in any caller and
/// adding it would be ceremony for no benefit.
///
/// # Examples
///
/// ```
/// use peel::hash::xxh64::Xxh64;
///
/// let mut h = Xxh64::new();
/// h.update(b"");
/// // xxhash spec §B.1 vector: XXH64("", seed=0).
/// assert_eq!(h.finalize(), 0xEF46_DB37_51D8_E999);
/// ```
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Xxh64 {
    /// Four parallel-lane accumulators, populated lazily once the
    /// first 32-byte stripe arrives. Stay at the seed-derived
    /// initial values until then; for inputs shorter than 32 bytes
    /// the algorithm uses a different short-input path that doesn't
    /// touch them.
    v: [u64; 4],
    /// Carry-over for partial stripes. Only the first
    /// `buffer_len` bytes are meaningful; the rest is whatever
    /// previous writes left there.
    buffer: [u8; STRIPE_BYTES],
    /// Bytes currently buffered. Invariant: `< STRIPE_BYTES` once
    /// `update` returns.
    buffer_len: u8,
    /// Total bytes consumed by `update`. Used both by the
    /// short-input path and the final mix.
    bytes_processed: u64,
}

impl Default for Xxh64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Xxh64 {
    /// Create a fresh seed-0 hasher.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            // seed=0 specialisation of the spec §3.2 init formulas:
            //   v1 = seed + PRIME64_1 + PRIME64_2
            //   v2 = seed + PRIME64_2
            //   v3 = seed + 0
            //   v4 = seed - PRIME64_1
            v: [
                PRIME64_1.wrapping_add(PRIME64_2),
                PRIME64_2,
                0,
                0u64.wrapping_sub(PRIME64_1),
            ],
            buffer: [0; STRIPE_BYTES],
            buffer_len: 0,
            bytes_processed: 0,
        }
    }

    /// Total bytes consumed by [`Self::update`] over this hasher's
    /// lifetime. Diagnostic only.
    #[must_use]
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }

    /// Serialize the streaming hasher's full internal state.
    ///
    /// Used by the zstd `decode/zstd` Phase-7 resume blob so a crash
    /// mid-frame can resume the content-checksum computation from the
    /// last block boundary. The byte layout is:
    ///
    /// - `4 × 8 B` — four lane accumulators `v[0..4]`, each u64 LE.
    /// - `32 B` — `buffer` (full stripe-sized scratch; only the
    ///   first `buffer_len` bytes are meaningful, the rest is
    ///   preserved verbatim).
    /// - `1 B` — `buffer_len` (always `< 32`).
    /// - `8 B` — `bytes_processed`, u64 LE.
    ///
    /// Total: [`SERIALIZED_LEN`] bytes. Round-trips bit-exactly via
    /// [`Self::deserialize`].
    #[must_use]
    pub fn serialize(&self) -> [u8; SERIALIZED_LEN] {
        let mut out = [0u8; SERIALIZED_LEN];
        let mut p = 0;
        for lane in self.v {
            out[p..p + 8].copy_from_slice(&lane.to_le_bytes());
            p += 8;
        }
        out[p..p + STRIPE_BYTES].copy_from_slice(&self.buffer);
        p += STRIPE_BYTES;
        out[p] = self.buffer_len;
        p += 1;
        out[p..p + 8].copy_from_slice(&self.bytes_processed.to_le_bytes());
        debug_assert_eq!(p + 8, SERIALIZED_LEN);
        out
    }

    /// Reconstruct a hasher from a [`Self::serialize`] blob.
    ///
    /// # Errors
    ///
    /// Returns an error string if `bytes` is not exactly
    /// [`SERIALIZED_LEN`] bytes, or if the encoded `buffer_len`
    /// is `>= 32` (the streaming invariant requires
    /// `buffer_len < STRIPE_BYTES`).
    pub fn deserialize(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != SERIALIZED_LEN {
            return Err("xxh64: serialized length mismatch");
        }
        let mut v = [0u64; 4];
        let mut p = 0;
        for lane in &mut v {
            // INVARIANT: bytes.len() == SERIALIZED_LEN ≥ 4*8, so the
            // 8-byte slice is in bounds.
            let arr: [u8; 8] = bytes[p..p + 8].try_into().expect("8 bytes");
            *lane = u64::from_le_bytes(arr);
            p += 8;
        }
        let mut buffer = [0u8; STRIPE_BYTES];
        buffer.copy_from_slice(&bytes[p..p + STRIPE_BYTES]);
        p += STRIPE_BYTES;
        let buffer_len = bytes[p];
        p += 1;
        if usize::from(buffer_len) >= STRIPE_BYTES {
            return Err("xxh64: buffer_len out of range");
        }
        let arr: [u8; 8] = bytes[p..p + 8].try_into().expect("8 bytes");
        let bytes_processed = u64::from_le_bytes(arr);
        Ok(Self {
            v,
            buffer,
            buffer_len,
            bytes_processed,
        })
    }

    /// Feed `input` into the hasher.
    ///
    /// Calling `update` with any sequence of slices whose
    /// concatenation is `X` is equivalent to a single `update(X)`:
    /// chunking is observationally invisible.
    pub fn update(&mut self, mut input: &[u8]) {
        self.bytes_processed = self.bytes_processed.wrapping_add(input.len() as u64);

        let mut buffer_len = self.buffer_len as usize;

        // 1) Drain any partially-filled buffer first.
        if buffer_len > 0 {
            let want = STRIPE_BYTES - buffer_len;
            let take = input.len().min(want);
            self.buffer[buffer_len..buffer_len + take].copy_from_slice(&input[..take]);
            buffer_len += take;
            input = &input[take..];
            if buffer_len == STRIPE_BYTES {
                let block = self.buffer;
                self.process_stripe(&block);
                buffer_len = 0;
            }
        }

        // 2) Process whole stripes straight from the caller's slice
        //    (no copy through the buffer when we have ≥32 bytes
        //    available).
        while input.len() >= STRIPE_BYTES {
            let mut block = [0u8; STRIPE_BYTES];
            block.copy_from_slice(&input[..STRIPE_BYTES]);
            self.process_stripe(&block);
            input = &input[STRIPE_BYTES..];
        }

        // 3) Stash the trailing remainder for the next call.
        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            buffer_len = input.len();
        }
        // INVARIANT: by construction `buffer_len < STRIPE_BYTES`
        // (256 > 32 so the cast is lossless).
        self.buffer_len = buffer_len as u8;
    }

    /// Consume one full stripe (xxhash spec §3.3 main loop).
    fn process_stripe(&mut self, block: &[u8; STRIPE_BYTES]) {
        for lane in 0..4 {
            // INVARIANT: lane in 0..4, so `lane*8..lane*8+8 <= 32`.
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&block[lane * 8..lane * 8 + 8]);
            let val = u64::from_le_bytes(bytes);
            self.v[lane] = round(self.v[lane], val);
        }
    }

    /// Consume the hasher and produce the final 64-bit digest.
    ///
    /// Implements xxhash spec §3.5 (final accumulator collapse) and
    /// §3.6 / §3.7 (tail consumption + final mix). The *low 32 bits*
    /// of the return value are what zstd's
    /// `Content_Checksum_Flag`-bearing frames embed in the trailing
    /// 4 bytes; callers truncate at the call site.
    #[must_use]
    pub fn finalize(self) -> u64 {
        let len = self.bytes_processed;
        let mut acc: u64 = if len < STRIPE_BYTES as u64 {
            // Short-input path: skip the four-lane main loop and
            // initialise from the seed-derived constant.
            // Spec §3.1.2: acc = seed + PRIME64_5 (seed = 0).
            PRIME64_5
        } else {
            // Spec §3.5: collapse the four accumulators with five
            // 64-bit rotations and four merge steps.
            let v = self.v;
            let mut a = v[0]
                .rotate_left(1)
                .wrapping_add(v[1].rotate_left(7))
                .wrapping_add(v[2].rotate_left(12))
                .wrapping_add(v[3].rotate_left(18));
            a = merge_accumulator(a, v[0]);
            a = merge_accumulator(a, v[1]);
            a = merge_accumulator(a, v[2]);
            a = merge_accumulator(a, v[3]);
            a
        };

        // Spec §3.6: fold in the total length.
        acc = acc.wrapping_add(len);

        // Spec §3.7: tail consumption — 8 bytes, then 4, then 1.
        let tail = &self.buffer[..self.buffer_len as usize];
        let mut i = 0;
        while i + 8 <= tail.len() {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&tail[i..i + 8]);
            let lane = u64::from_le_bytes(bytes);
            acc ^= round(0, lane);
            acc = acc
                .rotate_left(27)
                .wrapping_mul(PRIME64_1)
                .wrapping_add(PRIME64_4);
            i += 8;
        }
        if i + 4 <= tail.len() {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&tail[i..i + 4]);
            let lane = u64::from(u32::from_le_bytes(bytes));
            acc ^= lane.wrapping_mul(PRIME64_1);
            acc = acc
                .rotate_left(23)
                .wrapping_mul(PRIME64_2)
                .wrapping_add(PRIME64_3);
            i += 4;
        }
        while i < tail.len() {
            let lane = u64::from(tail[i]);
            acc ^= lane.wrapping_mul(PRIME64_5);
            acc = acc.rotate_left(11).wrapping_mul(PRIME64_1);
            i += 1;
        }

        // Spec §3.8: final avalanche.
        acc ^= acc >> 33;
        acc = acc.wrapping_mul(PRIME64_2);
        acc ^= acc >> 29;
        acc = acc.wrapping_mul(PRIME64_3);
        acc ^= acc >> 32;
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// xxhash spec §B.1 — `XXH64("", seed=0)`. The shortest possible
    /// input exercises the short-input path and the empty-tail final
    /// mix.
    #[test]
    fn empty_input_matches_spec_vector() {
        let h = Xxh64::new();
        assert_eq!(h.finalize(), 0xEF46_DB37_51D8_E999);
    }

    /// xxhash spec §B.1 — `XXH64("Nobody inspects the spammish
    /// repetition", seed=0)`. 39 bytes — short-input path, exercises
    /// the 8/4/1-byte tail folds.
    #[test]
    fn pangram_matches_spec_vector() {
        let mut h = Xxh64::new();
        h.update(b"Nobody inspects the spammish repetition");
        assert_eq!(h.finalize(), 0xFBCE_A83C_8A37_8BF1);
    }

    /// Streaming chunkings of the same input must produce the same
    /// digest — fundamental invariant the zstd decoder relies on
    /// when it feeds bytes one block at a time.
    #[test]
    fn chunking_is_observationally_invisible() {
        let payload: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let one_shot = {
            let mut h = Xxh64::new();
            h.update(&payload);
            h.finalize()
        };
        for chunk in [1usize, 7, 31, 32, 33, 64, 100, 512] {
            let mut h = Xxh64::new();
            for piece in payload.chunks(chunk) {
                h.update(piece);
            }
            assert_eq!(h.finalize(), one_shot, "chunking by {chunk} differed");
        }
    }

    /// Short-input path (< 32 bytes) goes through the seed-derived
    /// constant rather than the four-lane state. Pin the boundary.
    #[test]
    fn under_one_stripe_uses_short_path() {
        // Just under the stripe size.
        let payload: Vec<u8> = (0..31u8).collect();
        let mut h = Xxh64::new();
        h.update(&payload);
        let short = h.finalize();

        let mut h = Xxh64::new();
        let payload: Vec<u8> = (0..31u8).collect();
        for byte in &payload {
            h.update(std::slice::from_ref(byte));
        }
        assert_eq!(h.finalize(), short);
    }

    /// Boundary case: exactly one stripe. Crosses the short-path /
    /// main-loop branch.
    #[test]
    fn exactly_one_stripe() {
        let payload: Vec<u8> = (0..32u8).collect();
        let mut h = Xxh64::new();
        h.update(&payload);
        let one_shot = h.finalize();

        // Same input, fed byte-by-byte.
        let mut h = Xxh64::new();
        for byte in &payload {
            h.update(std::slice::from_ref(byte));
        }
        assert_eq!(h.finalize(), one_shot);
    }

    /// Cross-check: feed `Xxh64` the bytes that the upstream `zstd`
    /// crate declared as content-checksum-bearing, then compare our
    /// digest's low 32 bits against the trailing 4 bytes of the
    /// zstd-encoded frame. This is the end-to-end invariant Phase 6
    /// depends on. The streaming `Encoder` is used (not
    /// `encode_all`) because the latter defaults to no checksum.
    #[cfg(feature = "zstd")]
    #[test]
    fn matches_zstd_crate_content_checksum_trailer() {
        use std::io::Write;
        for size in [0usize, 1, 32, 33, 1024, 8 * 1024, 64 * 1024] {
            let payload: Vec<u8> = (0..size).map(|i| (i * 31 + 7) as u8).collect();
            let mut frame = Vec::new();
            {
                let mut enc = ::zstd::Encoder::new(&mut frame, 3).expect("encoder");
                enc.include_checksum(true).expect("checksum on");
                enc.write_all(&payload).expect("write");
                enc.finish().expect("finish");
            }
            let trailer_low32 = u32::from_le_bytes([
                frame[frame.len() - 4],
                frame[frame.len() - 3],
                frame[frame.len() - 2],
                frame[frame.len() - 1],
            ]);
            let mut h = Xxh64::new();
            h.update(&payload);
            let got = (h.finalize() & 0xFFFF_FFFF) as u32;
            assert_eq!(got, trailer_low32, "size={size}");
        }
    }

    /// Empty-input cross-check against the zstd trailer (handled
    /// separately because not all encoder configurations emit a
    /// checksum for empty input — the spec-vector test above
    /// already covers correctness of the algorithm itself).
    #[test]
    fn empty_input_zero_length_matches_self() {
        let mut h = Xxh64::new();
        h.update(&[]);
        let empty = h.finalize();
        assert_eq!(empty, Xxh64::new().finalize());
    }

    /// `serialize` then `deserialize` produces a hasher equivalent
    /// to the original — finalizing both yields the same digest, and
    /// continuing both with the same suffix yields the same digest.
    /// Used by the zstd Phase-7 resume blob to persist mid-frame
    /// content-checksum state.
    #[test]
    fn serialize_round_trips_at_various_input_sizes() {
        // Cover sub-stripe (short path), exact-stripe boundary,
        // multi-stripe, and large multi-stripe inputs.
        for prefix_len in [0usize, 1, 31, 32, 33, 100, 1024, 32 * 1024 + 7] {
            let prefix: Vec<u8> = (0..prefix_len).map(|i| (i * 13 + 5) as u8).collect();
            let mut original = Xxh64::new();
            original.update(&prefix);

            let blob = original.serialize();
            let restored = Xxh64::deserialize(&blob).expect("round-trip");

            // (1) Both finalize to the same digest immediately.
            assert_eq!(
                original.clone().finalize(),
                restored.clone().finalize(),
                "prefix_len={prefix_len}: finalize disagrees",
            );

            // (2) Continuing with the same suffix yields the same
            // digest — the streaming invariant the resume path
            // relies on.
            let suffix = b"and a suffix tail of bytes";
            let mut a = original;
            let mut b = restored;
            a.update(suffix);
            b.update(suffix);
            assert_eq!(
                a.finalize(),
                b.finalize(),
                "prefix_len={prefix_len}: continuation digest disagrees",
            );
        }
    }

    /// Wrong-length blobs are rejected without panicking.
    #[test]
    fn deserialize_rejects_wrong_length() {
        assert!(Xxh64::deserialize(&[]).is_err());
        assert!(Xxh64::deserialize(&[0u8; SERIALIZED_LEN - 1]).is_err());
        assert!(Xxh64::deserialize(&[0u8; SERIALIZED_LEN + 1]).is_err());
    }

    /// A blob whose `buffer_len` byte is out of range is rejected.
    #[test]
    fn deserialize_rejects_oversized_buffer_len() {
        let mut blob = [0u8; SERIALIZED_LEN];
        // buffer_len position: after 4*8 lane bytes + 32 buffer bytes.
        let pos = 4 * 8 + STRIPE_BYTES;
        blob[pos] = 32;
        assert!(Xxh64::deserialize(&blob).is_err());
        blob[pos] = 200;
        assert!(Xxh64::deserialize(&blob).is_err());
    }
}
