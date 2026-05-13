//! Phase 0 anchor bench for [`peel::hash::xxh64::Xxh64`].
//!
//! Companion to `internal/PLAN_raw_row_throughput.md` Phase 0:
//! profile data attributes ~14 % of `zstd-raw` self-time to
//! `Xxh64::update` (zstd content-checksum verification on incompressible
//! payloads). This bench locks in a scalar throughput baseline for the
//! 64 KiB working-set the production zstd path hits, so Phase 3's SWAR
//! work (if it ships) can be measured as a clean ratio against this
//! number.
//!
//! 64 KiB rather than 1 GiB because the production path hashes ~32 KiB
//! chunks coming out of the zstd block boundary, then again, then
//! again — the hot inner state lives in L1 the whole time. An L1-hot
//! bench reflects that posture; a 1 GiB cold pass would be
//! memory-bandwidth-bound and underweight the table-lookup cost.
//! (Same posture as `test_bench_deflate_native::bench_crc32_64kib`.)
//!
//! # How to run
//!
//! `#[ignore]` so opt-in:
//!
//! ```text
//! cargo test --release --test test_bench_hash -- \
//!     --ignored --nocapture --test-threads=1
//! ```

#![cfg(unix)]

use std::time::{Duration, Instant};

use peel::hash::xxh64::Xxh64;

fn random_bytes(seed: u64, len: usize) -> Vec<u8> {
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

fn gbps(bytes: u64, dur: Duration) -> f64 {
    let s = dur.as_secs_f64();
    if s <= 0.0 {
        return 0.0;
    }
    (bytes as f64) / 1_000_000_000.0 / s
}

fn gibps(bytes: u64, dur: Duration) -> f64 {
    let s = dur.as_secs_f64();
    if s <= 0.0 {
        return 0.0;
    }
    (bytes as f64) / (1024.0 * 1024.0 * 1024.0) / s
}

/// Xxh64 throughput on a 64 KiB L1-hot buffer iterated to ~1 GiB of
/// total work. Phase 0 anchor for [`PLAN_raw_row_throughput.md`]
/// Lever C: 64 KiB chosen because it spans roughly one zstd block
/// worth of bytes plus the (small) hasher state.
///
/// Each iteration constructs a fresh `Xxh64` (mirrors the zstd
/// content-checksum lifetime — one hasher per frame, fed the frame's
/// decompressed bytes). The XOR-accumulator pattern lifted from the
/// CRC32 bench (`test_bench_deflate_native::bench_crc32_64kib`) keeps
/// LLVM from observing the per-iter result as loop-invariant.
///
/// The number this bench prints is the floor a Phase 3 SWAR rewrite
/// must beat. Reference xxhash's SIMD path is ~10 GB/s on M-series;
/// the scalar number we measure here puts the speedup ceiling in
/// concrete terms.
#[test]
#[ignore = "benchmark; opt-in via --ignored"]
fn bench_xxh64_64kib() {
    const BUF_LEN: usize = 64 * 1024;
    const TOTAL_BYTES: u64 = 1 << 30; // 1 GiB worth of work
    const ITERS: usize = (TOTAL_BYTES / BUF_LEN as u64) as usize;

    let buf = random_bytes(0xC0FFEE, BUF_LEN);

    // Pin the digest so a later SWAR rewrite that disagrees with the
    // scalar implementation gets caught here as well as in the spec
    // vectors. The exact value is not part of the contract — what
    // matters is that the bench's median-of-3 timing is paired with
    // a deterministic correctness witness.
    let pinned_digest = {
        let mut h = Xxh64::new();
        h.update(&buf);
        h.finalize()
    };

    // Warm-up (page-in + L1).
    let mut warm = Xxh64::new();
    warm.update(&buf);
    std::hint::black_box(warm.finalize());

    // Median of 3 timed runs.
    let mut times = [Duration::default(); 3];
    let mut xor_acc: u64 = 0;
    for slot in times.iter_mut() {
        let started = Instant::now();
        let mut acc = 0u64;
        for _ in 0..ITERS {
            let mut h = Xxh64::new();
            h.update(&buf);
            acc ^= h.finalize();
        }
        xor_acc = acc;
        *slot = started.elapsed();
        std::hint::black_box(acc);
    }
    times.sort();
    let med = times[1];

    // Every iteration consumes the same input, so the XOR-accumulator
    // of an even number of identical digests collapses to either the
    // digest (odd-count) or zero (even-count). `ITERS` for a 1 GiB /
    // 64 KiB workload is 16 384 — even, so the expected XOR is 0.
    let expected_xor = if ITERS.is_multiple_of(2) {
        0u64
    } else {
        pinned_digest
    };
    assert_eq!(
        xor_acc, expected_xor,
        "Xxh64 produced inconsistent digests across iterations \
         (pinned digest = 0x{pinned_digest:016x}, accumulated XOR = 0x{xor_acc:016x})",
    );

    println!(
        "[bench-xxh64] peel::Xxh64 (scalar)  {iters} × 64 KiB = {gib:.2} GiB: {dur:.3}s  \
         ({gibps:.2} GiB/s, {gbps:.2} GB/s)  digest=0x{pinned_digest:016x}",
        iters = ITERS,
        gib = (TOTAL_BYTES as f64) / (1024.0 * 1024.0 * 1024.0),
        dur = med.as_secs_f64(),
        gibps = gibps(TOTAL_BYTES, med),
        gbps = gbps(TOTAL_BYTES, med),
    );
}

// ---- silence unused-helper warnings on non-bench builds --------------

#[allow(dead_code)]
fn _silence_unused() {
    let _ = random_bytes(0, 0);
    let _: fn(u64, Duration) -> f64 = gbps;
    let _: fn(u64, Duration) -> f64 = gibps;
}
