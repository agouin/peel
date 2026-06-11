#![cfg(feature = "lz4")]
//! Throughput gate for the hand-rolled LZ4 block decoder
//! ([`peel::decode::lz4_native::decompress_block`]).
//!
//! Phase 2 of [`internal/PLAN_lz4_block_decoder.md`]. The plan's
//! non-goal section sets a floor: **≥ 500 MB/s** sustained decode on a
//! single-block-in-a-tight-loop microbenchmark, with a hard revisit
//! below 200 MB/s. This bench measures decode-only block throughput
//! and gates on the 500 MB/s floor, printing the native and `lz4_flex`
//! reference numbers side by side.
//!
//! # What this measures
//!
//! Decode-only, no frame parsing, no checksums, no sink syscalls: a
//! corpus of ≤ 4 MiB blocks (the LZ4 block ceiling) pre-compressed
//! once with the `lz4_flex` reference encoder, then decoded in a tight
//! loop into a reused output buffer. The shapes mix
//! match-heavy (RLE / repeating-word) and literal-heavy (LCG) data so
//! the number reflects both the `copy_within` match path and the
//! `copy_from_slice` literal path.
//!
//! # How to run
//!
//! `#[ignore]`d. Invoke explicitly, in `--release` (a debug build's
//! numbers are meaningless):
//!
//! ```text
//! RUSTFLAGS="-C target-cpu=native" \
//!     cargo test --release --test test_bench_lz4_native -- \
//!     --ignored --nocapture --test-threads=1
//! ```

use std::time::Instant;

use peel::decode::lz4_native::decompress_block;

const BLOCK: usize = 4 * 1024 * 1024;

fn lcg_bytes(seed: u32, n: usize) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((state >> 16) as u8);
    }
    out
}

/// A spread of 4 MiB payloads exercising both the literal and match
/// copy paths.
fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("rle", vec![b'Z'; BLOCK]),
        (
            "word_repeat",
            std::iter::repeat(b"the quick brown fox ")
                .flatten()
                .copied()
                .take(BLOCK)
                .collect(),
        ),
        ("pseudo_random", lcg_bytes(0xDEAD_BEEF, BLOCK)),
        (
            "alternating",
            std::iter::repeat([b'A', b'B', b'C', b'D'])
                .flatten()
                .take(BLOCK)
                .collect(),
        ),
    ]
}

fn lz4_flex_compress(payload: &[u8]) -> Vec<u8> {
    let max = lz4_flex::block::get_maximum_output_size(payload.len());
    let mut buf = vec![0u8; max];
    let n = lz4_flex::block::compress_into(payload, &mut buf).expect("lz4_flex compress");
    buf.truncate(n);
    buf
}

#[test]
#[ignore = "throughput bench; run with --release --ignored --nocapture"]
fn lz4_block_decode_throughput() {
    let fixtures: Vec<(&'static str, Vec<u8>, usize)> = corpus()
        .into_iter()
        .map(|(label, payload)| {
            let block = lz4_flex_compress(&payload);
            (label, block, payload.len())
        })
        .collect();

    // Correctness gate first — a fast wrong decoder is worthless.
    let mut out = vec![0u8; BLOCK];
    for (label, block, plen) in &fixtures {
        let n = decompress_block(block, &mut out).expect("native decode");
        assert_eq!(n, *plen, "{label}: decoded length mismatch");
        let reference = {
            let mut b = vec![0u8; *plen];
            let m = lz4_flex::block::decompress_into(block, &mut b).expect("ref decode");
            b.truncate(m);
            b
        };
        assert_eq!(&out[..n], &reference[..], "{label}: native != lz4_flex");
    }

    const REPS: usize = 64;
    println!(
        "\n{:<14} {:>12} {:>12} {:>12} {:>10}",
        "shape", "in (KiB)", "out (MiB)", "native MB/s", "flex MB/s"
    );

    let mut total_bytes: u128 = 0;
    let mut total_secs = 0.0f64;
    for (label, block, plen) in &fixtures {
        // Native.
        let start = Instant::now();
        for _ in 0..REPS {
            let n = decompress_block(block, &mut out).expect("native decode");
            std::hint::black_box(&out[..n]);
        }
        let native_secs = start.elapsed().as_secs_f64();
        let bytes = (*plen as u128) * (REPS as u128);
        let native_mbs = bytes as f64 / 1e6 / native_secs;

        // lz4_flex reference.
        let mut refbuf = vec![0u8; *plen];
        let start = Instant::now();
        for _ in 0..REPS {
            let m = lz4_flex::block::decompress_into(block, &mut refbuf).expect("ref decode");
            std::hint::black_box(&refbuf[..m]);
        }
        let flex_secs = start.elapsed().as_secs_f64();
        let flex_mbs = bytes as f64 / 1e6 / flex_secs;

        println!(
            "{:<14} {:>12} {:>12} {:>12.0} {:>10.0}",
            label,
            block.len() / 1024,
            plen / (1024 * 1024),
            native_mbs,
            flex_mbs
        );

        total_bytes += bytes;
        total_secs += native_secs;
    }

    let overall_mbs = total_bytes as f64 / 1e6 / total_secs;
    println!("\noverall native decode: {overall_mbs:.0} MB/s\n");

    // Phase 2 exit criterion: ≥ 500 MB/s, hard floor 200 MB/s.
    assert!(
        overall_mbs >= 500.0,
        "native LZ4 block decode {overall_mbs:.0} MB/s is below the 500 MB/s floor"
    );
}
