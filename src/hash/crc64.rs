//! CRC-64/XZ (ECMA-182, reflected) — the variant the .xz Block
//! Check uses when `Check ID = 0x04`.
//!
//! Phase 5 of `internal/PLAN_xz_block_decoder.md` calls for "a new
//! small module mirroring the SHA-256 module's style." This
//! module's API shape — `Crc64::new` / `update` / `finalize` —
//! matches [`super::crc32::Crc32`] and [`super::sha256::Sha256`]
//! so the .xz Block-Check verifier can drive whichever variant
//! the Stream Flags name.
//!
//! # Polynomial and parameters
//!
//! - Polynomial (reflected): `0xC96C_5795_D787_0F42`. This is
//!   the reverse of the ECMA-182 generator `0x42F0_E1EB_A9EA_3693`
//!   and is what `xz` / `liblzma` and the canonical "CRC-64/XZ"
//!   alias publish.
//! - Initial / final XOR: `!0u64`. (Same convention as the
//!   reflected CRC-32 above and `liblzma`.)
//! - Reflected input / reflected output: yes.
//!
//! Hand-rolled per `internal/ENGINEERING_STANDARDS.md` §2.1; the
//! lookup tables are `const`-folded at compile time.
//!
//! # Inner loop: slicing-by-16
//!
//! `update` processes 16 input bytes per iteration via 16
//! precomputed 256-entry tables — the standard slicing-by-N
//! reformulation for reflected CRCs (Intel "Fast CRC computation
//! for generic polynomials" 2009). Going from N=8 to N=16 cuts
//! per-iteration loop overhead in half, which on the M4 Max moves
//! the 1 GiB microbench from 3.9× to ~5× over byte-by-byte. Phase
//! 1 of [`internal/PLAN_xz_decoder_optimization.md`] uses this to
//! close the ~7 % of `xz_native` decode self-time the byte-by-byte
//! loop was claiming.

/// 256-entry lookup table for the byte-at-a-time CRC-64/XZ
/// fallback. The first row of [`TABLES`]. Used by the < 16-byte
/// tail path and the differential test helper.
const TABLE: [u64; 256] = build_byte_table();

/// Sixteen 256-entry tables driving the slicing-by-16 inner loop.
/// `TABLES[k][b]` is the CRC of `b` followed by `k` zero bytes —
/// precomputed so 16 input bytes can be folded into the running
/// CRC with sixteen independent table lookups instead of sixteen
/// sequential dependent ones.
///
/// `static` (not `const`): the table is 32 KiB and clippy flags
/// `const` arrays of this size for the load-from-rodata pattern
/// (the alternative is duplicating the table at every use site).
static TABLES: [[u64; 256]; 16] = build_slice_tables();

const fn build_byte_table() -> [u64; 256] {
    const POLY: u64 = 0xC96C_5795_D787_0F42;
    let mut table = [0u64; 256];
    let mut i = 0u64;
    while i < 256 {
        let mut c = i;
        let mut j = 0;
        while j < 8 {
            if c & 1 != 0 {
                c = (c >> 1) ^ POLY;
            } else {
                c >>= 1;
            }
            j += 1;
        }
        table[i as usize] = c;
        i += 1;
    }
    table
}

const fn build_slice_tables() -> [[u64; 256]; 16] {
    let byte_table = build_byte_table();
    let mut tables = [[0u64; 256]; 16];
    let mut b = 0usize;
    while b < 256 {
        tables[0][b] = byte_table[b];
        b += 1;
    }
    // T[k+1][b] is "feed byte b followed by (k+1) zero bytes" =
    // step-once on T[k][b] with input zero:
    //   T[k+1][b] = (T[k][b] >> 8) ^ T[0][T[k][b] & 0xff]
    let mut k = 0usize;
    while k < 15 {
        let mut b = 0usize;
        while b < 256 {
            let prev = tables[k][b];
            tables[k + 1][b] = (prev >> 8) ^ tables[0][(prev & 0xff) as usize];
            b += 1;
        }
        k += 1;
    }
    tables
}

/// Streaming CRC-64/XZ hasher.
///
/// Construct with [`Self::new`], feed bytes via [`Self::update`],
/// extract the final CRC with [`Self::finalize`]. Mirrors the
/// shape of [`super::crc32::Crc32`] and the SHA-256 hasher.
#[derive(Debug, Clone, Copy)]
pub struct Crc64 {
    state: u64,
}

impl Default for Crc64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc64 {
    /// Fresh, empty hasher. Equivalent to [`Self::default`].
    #[must_use]
    pub const fn new() -> Self {
        Self { state: !0u64 }
    }

    /// Feed the next chunk of input into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        self.state = update_portable(self.state, data);
    }
}

/// Scalar slicing-by-16 inner loop. Kept as a free function (not a
/// method) so a future aarch64 PMULL-accelerated path can delegate to
/// it for the < 16-byte tail without going through
/// [`Crc64::update`]'s feature-detection branch.
///
/// # Known gap
///
/// On aarch64 hosts with the `pmull` extension (every M-series CPU
/// and most modern server cores), liblzma uses PMULL2 carry-less
/// multiply for CRC-64/XZ at ~20 GB/s. peel's slicing-by-16 runs at
/// ~2.85 GB/s on those same cores ([`tests/test_bench_hash.rs::bench_crc64_64kib`]).
/// For 100 MiB of xz output that's ~30 ms of avoidable wall-clock —
/// most of the peel/`xz -d` gap on the local-decode bench. Closing it
/// requires a fold-by-1 PMULL implementation with Barrett reduction;
/// see [Intel "Fast CRC Computation Using PCLMULQDQ Instruction"
/// (2009)] (the algorithm transcribed to ARM `PMULL`/`PMULL2`) for the
/// reference structure. Deferred until a focused effort can land a
/// verified implementation alongside the byte-by-byte differential
/// test that already covers the slicing-by-16 path.
///
/// [Intel "Fast CRC Computation Using PCLMULQDQ Instruction" (2009)]:
/// https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/fast-crc-computation-generic-polynomials-pclmulqdq-paper.pdf
#[inline]
fn update_portable(state: u64, data: &[u8]) -> u64 {
    let mut state = state;
    let mut chunks = data.chunks_exact(16);
    for chunk in &mut chunks {
        // INVARIANT: `chunks_exact(16)` yields slices of length 16;
        // `try_into` cannot fail here.
        let arr: [u8; 16] = chunk.try_into().unwrap();
        // First 8 input bytes XOR-into the state; the next 8 are
        // pure inputs. All 16 lookups are independent, so LLVM is
        // free to schedule them across the load ports. Indexing
        // through `u8` indices folds the bounds checks (visible
        // in `cargo asm` on Apple aarch64).
        let lo = (state
            ^ u64::from_le_bytes([
                arr[0], arr[1], arr[2], arr[3], arr[4], arr[5], arr[6], arr[7],
            ]))
        .to_le_bytes();
        state = TABLES[15][lo[0] as usize]
            ^ TABLES[14][lo[1] as usize]
            ^ TABLES[13][lo[2] as usize]
            ^ TABLES[12][lo[3] as usize]
            ^ TABLES[11][lo[4] as usize]
            ^ TABLES[10][lo[5] as usize]
            ^ TABLES[9][lo[6] as usize]
            ^ TABLES[8][lo[7] as usize]
            ^ TABLES[7][arr[8] as usize]
            ^ TABLES[6][arr[9] as usize]
            ^ TABLES[5][arr[10] as usize]
            ^ TABLES[4][arr[11] as usize]
            ^ TABLES[3][arr[12] as usize]
            ^ TABLES[2][arr[13] as usize]
            ^ TABLES[1][arr[14] as usize]
            ^ TABLES[0][arr[15] as usize];
    }
    for &b in chunks.remainder() {
        state = TABLE[((state ^ u64::from(b)) & 0xFF) as usize] ^ (state >> 8);
    }
    state
}

impl Crc64 {
    /// Final CRC-64/XZ over all bytes fed so far.
    #[must_use]
    pub fn finalize(self) -> u64 {
        !self.state
    }

    /// Snapshot the running CRC without consuming the hasher.
    #[must_use]
    pub fn current(&self) -> u64 {
        !self.state
    }

    /// Restore a hasher to a state that, if [`Self::finalize`]
    /// were called immediately, would produce `partial_crc`.
    /// Mirror of [`super::crc32::Crc32::seed`] for the Phase 6
    /// resume blob.
    pub fn seed(&mut self, partial_crc: u64) {
        self.state = !partial_crc;
    }
}

/// Convenience: full-buffer CRC-64/XZ in one call.
#[must_use]
pub fn xz(data: &[u8]) -> u64 {
    let mut c = Crc64::new();
    c.update(data);
    c.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CRC-64/XZ of the empty string is 0 (the initial `!0u64`
    /// state, finalized via final XOR with `!0u64`, produces 0).
    #[test]
    fn empty_input_is_zero() {
        assert_eq!(xz(b""), 0);
    }

    /// Canonical CRC-64/XZ "check" vector — `0x995DC9BBDF1939FA`
    /// for the ASCII string `"123456789"`. This is the
    /// `liblzma` / `crc64fast`-published reference value for the
    /// ECMA-182-reflected polynomial with `init = !0` and
    /// `xorout = !0`. Pin so any drift from the polynomial
    /// transcription surfaces directly.
    #[test]
    fn known_vector_check_string() {
        assert_eq!(xz(b"123456789"), 0x995D_C9BB_DF19_39FA);
    }

    /// Streaming `update` chunked at arbitrary boundaries
    /// produces the same CRC as a single one-shot call.
    #[test]
    fn streaming_matches_one_shot() {
        let payload: Vec<u8> = (0..=255u8).chain(0..=255u8).collect();
        let one_shot = xz(&payload);
        let mut c = Crc64::new();
        c.update(&payload[..1]);
        c.update(&payload[1..6]);
        c.update(&payload[6..]);
        assert_eq!(c.finalize(), one_shot);
    }

    /// `current()` previews without consuming.
    #[test]
    fn current_previews_without_consuming() {
        let mut c = Crc64::new();
        c.update(b"abc");
        let preview = c.current();
        assert_eq!(preview, xz(b"abc"));
        c.update(b"def");
        assert_eq!(c.finalize(), xz(b"abcdef"));
    }

    /// Reference byte-at-a-time CRC-64/XZ — the previous production
    /// inner loop, kept here as the differential oracle for the
    /// slicing-by-8 path. Phase 1 of
    /// `internal/PLAN_xz_decoder_optimization.md` requires every commit
    /// to be byte-identical to slicing-by-1.
    fn xz_byte_by_byte(data: &[u8]) -> u64 {
        let mut state = !0u64;
        for &b in data {
            state = TABLE[((state ^ u64::from(b)) & 0xFF) as usize] ^ (state >> 8);
        }
        !state
    }

    /// Slicing-by-8 must produce byte-identical CRCs to the byte-at-
    /// a-time reference across a randomized fixture corpus. Spans
    /// every (length mod 8) class so the chunked main path *and*
    /// the < 8-byte tail fallback are both covered.
    #[test]
    fn slicing_matches_byte_by_byte_random() {
        // Same LCG as `tests/test_bench_xz_native.rs::random_bytes`
        // so both the slicing path and the test fixture share the
        // same notion of "randomized corpus."
        fn lcg_buf(seed: u64, len: usize) -> Vec<u8> {
            let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
            let mut out = Vec::with_capacity(len);
            while out.len() < len {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                out.extend_from_slice(&state.to_le_bytes());
            }
            out.truncate(len);
            out
        }

        // Lengths 0..=64 hit every (len % 8) class plus a couple of
        // multi-chunk shapes; 1024 and 65535 cover bigger buffers
        // where any off-by-one in the chunked main path surfaces.
        for len in (0..=64).chain([100, 1024, 65535, 1 << 20]) {
            for seed in [0u64, 1, 0xDEADBEEF, 0xC0FFEE] {
                let buf = lcg_buf(seed, len);
                let one_shot = xz(&buf);
                let reference = xz_byte_by_byte(&buf);
                assert_eq!(
                    one_shot, reference,
                    "slicing-by-8 disagrees with byte-by-byte at len={len}, seed={seed:#x}",
                );

                // Streaming chunked at arbitrary boundaries must
                // also match — exercises the > 8-byte / < 8-byte
                // alternation between calls.
                let mut hasher = Crc64::new();
                let mut pos = 0;
                let mut step = 1usize;
                while pos < buf.len() {
                    let end = (pos + step).min(buf.len());
                    hasher.update(&buf[pos..end]);
                    pos = end;
                    step = step.wrapping_mul(3).wrapping_add(7) & 31;
                    step = step.max(1);
                }
                assert_eq!(
                    hasher.finalize(),
                    reference,
                    "streaming-chunked slicing-by-8 disagrees at len={len}, seed={seed:#x}",
                );
            }
        }
    }
}
