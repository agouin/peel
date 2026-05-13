//! CRC-32 (IEEE 802.3) — the variant the ZIP format records in every
//! local file header and central directory entry, and the variant the
//! gzip per-member trailer carries (RFC 1952 §2.3).
//!
//! Hand-rolled per `internal/ENGINEERING_STANDARDS.md` §2.1.
//!
//! The polynomial is the reflected form `0xEDB8_8320` and the
//! initial / final XOR is `!0u32`, matching what `zlib`'s `crc32`,
//! `gzip`, and ZIP all use.
//!
//! # Inner loop: slicing-by-16
//!
//! `update` processes 16 input bytes per iteration via 16 precomputed
//! 256-entry tables — the standard slicing-by-N reformulation for
//! reflected CRCs (Intel "Fast CRC computation for generic polynomials"
//! 2009). The < 16-byte tail falls back to the byte-at-a-time table.
//!
//! Phase 1 of [`internal/PLAN_gzip_throughput.md`] ports this from
//! [`super::super::hash::crc64`]'s slicing-by-16 path; the gzip
//! per-member trailer's running CRC32 was ~7 % of decode self-time
//! at byte-by-byte (mirrors the xz decoder-side CRC64 share Phase 1
//! of [`internal/PLAN_xz_decoder_optimization.md`] recovered). The exit
//! gate for that plan's Phase 1 is "≥ 5× scalar throughput
//! improvement" on the 64 KiB microbench in
//! [`tests/test_bench_deflate_native.rs`].

/// 256-entry lookup table for the byte-at-a-time CRC-32 fallback.
/// The first row of [`TABLES`]; used by the < 16-byte tail path and
/// by the differential test helper.
const TABLE: [u32; 256] = build_byte_table();

/// Sixteen 256-entry tables driving the slicing-by-16 inner loop.
/// `TABLES[k][b]` is the CRC of `b` followed by `k` zero bytes —
/// precomputed so 16 input bytes can be folded into the running CRC
/// with sixteen independent table lookups instead of sixteen
/// sequential dependent ones.
///
/// `static` (not `const`): clippy flags `const` arrays of this size
/// for the load-from-rodata pattern. Total footprint is 16 KiB
/// (16 × 256 × 4 B) — half the size of [`super::super::hash::crc64`]'s
/// equivalent because the state is u32 not u64.
static TABLES: [[u32; 256]; 16] = build_slice_tables();

const fn build_byte_table() -> [u32; 256] {
    const POLY: u32 = 0xEDB8_8320;
    let mut table = [0u32; 256];
    let mut i = 0u32;
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

const fn build_slice_tables() -> [[u32; 256]; 16] {
    let byte_table = build_byte_table();
    let mut tables = [[0u32; 256]; 16];
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

/// Streaming CRC-32 hasher.
///
/// Construct with [`Self::new`], feed bytes via [`Self::update`],
/// extract the final CRC with [`Self::finalize`]. The state can also
/// be primed mid-stream via [`Self::seed`] so the ZIP pipeline can
/// resume an entry that was partially extracted before a crash —
/// it re-reads the already-written bytes off disk and replays them
/// here rather than serializing the running CRC into the checkpoint.
#[derive(Debug, Clone, Copy)]
pub struct Crc32 {
    state: u32,
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    /// New, empty hasher. Equivalent to [`Self::default`].
    #[must_use]
    pub const fn new() -> Self {
        Self { state: !0u32 }
    }

    /// Feed the next chunk of input into the hasher. Processes
    /// 16 input bytes per iteration via slicing-by-16; the < 16-byte
    /// tail falls back to the byte-at-a-time table.
    pub fn update(&mut self, data: &[u8]) {
        let mut state = self.state;
        let mut chunks = data.chunks_exact(16);
        for chunk in &mut chunks {
            // INVARIANT: `chunks_exact(16)` yields slices of length 16;
            // `try_into` cannot fail here.
            let arr: [u8; 16] = chunk.try_into().unwrap();
            // First 4 bytes XOR-into the u32 state; the next 12 are
            // pure inputs. All 16 lookups are independent, so LLVM is
            // free to schedule them across the load ports. Indexing
            // through `u8` indices folds the bounds checks.
            let lo = (state ^ u32::from_le_bytes([arr[0], arr[1], arr[2], arr[3]])).to_le_bytes();
            state = TABLES[15][lo[0] as usize]
                ^ TABLES[14][lo[1] as usize]
                ^ TABLES[13][lo[2] as usize]
                ^ TABLES[12][lo[3] as usize]
                ^ TABLES[11][arr[4] as usize]
                ^ TABLES[10][arr[5] as usize]
                ^ TABLES[9][arr[6] as usize]
                ^ TABLES[8][arr[7] as usize]
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
            state = TABLE[((state ^ u32::from(b)) & 0xFF) as usize] ^ (state >> 8);
        }
        self.state = state;
    }

    /// Replace the running state with one that, if [`Self::finalize`]
    /// were called immediately, would produce `partial_crc`. Used by
    /// resume after re-reading the already-extracted prefix.
    pub fn seed(&mut self, partial_crc: u32) {
        self.state = !partial_crc;
    }

    /// Return the final CRC-32 value over all bytes fed so far.
    #[must_use]
    pub fn finalize(self) -> u32 {
        !self.state
    }

    /// Snapshot the running CRC without consuming the hasher. Mostly
    /// useful for diagnostics and tests.
    #[must_use]
    pub fn current(&self) -> u32 {
        !self.state
    }
}

/// Convenience: full-buffer CRC-32 in one call.
///
/// Equivalent to constructing a [`Crc32`], feeding `data` through
/// [`Crc32::update`], and returning [`Crc32::finalize`]. Used by
/// tests and by callers that already have the full byte string.
#[must_use]
pub fn ieee(data: &[u8]) -> u32 {
    let mut c = Crc32::new();
    c.update(data);
    c.finalize()
}

/// Apply one byte of the reflected CRC-32 step to `state` and return
/// the new state, without the initial / final `!` inversion the
/// [`Crc32`] hasher applies.
///
/// This is the raw inner-loop transform used by the PKWARE
/// "ZipCrypto" key-update routine (`internal/PLAN_archive_encryption.md`
/// §3b): each input byte advances three 32-bit keys, and two of
/// those advances are exactly one CRC-32 step over a key value whose
/// initial state is NOT `!0u32` (it's `0x1234_5678` / `0x3456_7890`).
/// Reusing the existing [`TABLE`] keeps the polynomial / endianness
/// invariants in one place; this helper is the seam.
///
/// Not exposed publicly outside the crate; ZipCrypto is the only
/// caller.
#[must_use]
pub(crate) fn crc32_step(state: u32, byte: u8) -> u32 {
    TABLE[((state ^ u32::from(byte)) & 0xFF) as usize] ^ (state >> 8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_zero() {
        // CRC-32 of the empty string is 0 by definition (the
        // initial !0u32 state, finalized via final XOR with !0u32,
        // produces 0).
        assert_eq!(ieee(b""), 0);
    }

    #[test]
    fn known_vector_a_through_z() {
        // Reference vector: CRC-32 of "abcdefghijklmnopqrstuvwxyz"
        // is 0x4C2750BD per the ZIP/zlib reference implementations.
        assert_eq!(ieee(b"abcdefghijklmnopqrstuvwxyz"), 0x4C2750BD);
    }

    #[test]
    fn known_vector_numeric_run() {
        // Reference vector: CRC-32 of "123456789" is 0xCBF43926
        // (the canonical "check" vector).
        assert_eq!(ieee(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let payload: Vec<u8> = (0..=255u8).chain(0..=255u8).collect();
        let one_shot = ieee(&payload);

        // Feed one byte at a time, then five bytes at a time, then
        // the rest in one chunk — chunking must not change the
        // result.
        let mut c = Crc32::new();
        c.update(&payload[..1]);
        c.update(&payload[1..6]);
        c.update(&payload[6..]);
        assert_eq!(c.finalize(), one_shot);
    }

    #[test]
    fn seed_replays_a_prefix() {
        // Producing the CRC of "abcdef" by computing the prefix CRC
        // separately, seeding a fresh hasher with it, and continuing
        // through "def" yields the same result as a single pass.
        let full = ieee(b"abcdef");
        let prefix = ieee(b"abc");
        let mut resumed = Crc32::new();
        resumed.seed(prefix);
        resumed.update(b"def");
        assert_eq!(resumed.finalize(), full);
    }

    #[test]
    fn current_returns_partial_crc_without_consuming_hasher() {
        let mut c = Crc32::new();
        c.update(b"abc");
        let snap = c.current();
        c.update(b"def");
        let final_value = c.finalize();
        assert_eq!(snap, ieee(b"abc"));
        assert_eq!(final_value, ieee(b"abcdef"));
    }

    /// Reference byte-at-a-time CRC-32/IEEE — the previous production
    /// inner loop, kept here as the differential oracle for the
    /// slicing-by-16 path. Phase 1 of
    /// [`internal/PLAN_gzip_throughput.md`] requires every commit to be
    /// byte-identical to slicing-by-1.
    fn ieee_byte_by_byte(data: &[u8]) -> u32 {
        let mut state = !0u32;
        for &b in data {
            state = TABLE[((state ^ u32::from(b)) & 0xFF) as usize] ^ (state >> 8);
        }
        !state
    }

    /// Slicing-by-16 must produce byte-identical CRCs to the byte-at-
    /// a-time reference across a randomized fixture corpus. Spans
    /// every (length mod 16) class so the chunked main path *and*
    /// the < 16-byte tail fallback are both covered, then exercises
    /// streaming `update` with adversarial chunk-boundary alternation
    /// so any per-chunk vs cross-chunk drift surfaces.
    #[test]
    fn slicing_matches_byte_by_byte_random() {
        // Same LCG as `tests/test_bench_xz_native.rs::random_bytes` /
        // `tests/test_bench_streaming.rs::random_bytes` so both the
        // slicing path and the test fixture share the same notion of
        // "randomized corpus."
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

        // Lengths 0..=64 hit every (len % 16) class plus a couple of
        // multi-chunk shapes; 1024 / 65535 / 1 MiB cover bigger
        // buffers where any off-by-one in the chunked main path
        // surfaces.
        for len in (0..=64).chain([100, 1024, 65535, 1 << 20]) {
            for seed in [0u64, 1, 0xDEADBEEF, 0xC0FFEE] {
                let buf = lcg_buf(seed, len);
                let one_shot = ieee(&buf);
                let reference = ieee_byte_by_byte(&buf);
                assert_eq!(
                    one_shot, reference,
                    "slicing-by-16 disagrees with byte-by-byte at len={len}, seed={seed:#x}",
                );

                // Streaming chunked at arbitrary boundaries must also
                // match — exercises the > 16-byte / < 16-byte
                // alternation between calls so the tail-into-next-
                // chunk path stays byte-identical.
                let mut hasher = Crc32::new();
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
                    "streaming-chunked slicing-by-16 disagrees at len={len}, seed={seed:#x}",
                );
            }
        }
    }

    /// Cross-validate against `flate2`'s production CRC-32 (used by
    /// `flate2`'s gzip + zlib paths). `flate2` is already a
    /// `[dev-dependencies]` so this adds no new crate. Shared coverage
    /// with the byte-by-byte oracle above: that one pins the
    /// algorithmic transform; this one pins the polynomial /
    /// initial-XOR / final-XOR conventions match the gzip wire
    /// format.
    #[test]
    fn matches_flate2_crc32_random() {
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

        for len in (0..=64).chain([100, 1024, 65535]) {
            for seed in [0u64, 1, 0xDEADBEEF, 0xC0FFEE] {
                let buf = lcg_buf(seed, len);
                let mine = ieee(&buf);
                let mut theirs = flate2::Crc::new();
                theirs.update(&buf);
                assert_eq!(
                    mine,
                    theirs.sum(),
                    "Crc32::ieee disagrees with flate2::Crc at len={len}, seed={seed:#x}",
                );
            }
        }
    }
}
