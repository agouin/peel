#![cfg(feature = "lz4")]
//! Phase 2 of [`internal/PLAN_lz4_block_decoder.md`](../internal/PLAN_lz4_block_decoder.md):
//! the **differential corpus** for the hand-rolled
//! [`peel::decode::lz4_native::decompress_block`].
//!
//! Every valid LZ4 block that the `lz4_flex` reference encoder emits
//! must decode byte-identically through both `lz4_flex`'s reference
//! decoder and ours. Three layers:
//!
//! 1. **Curated corpus** — named, easily-debuggable shapes (single
//!    byte / alphabet / RLE / alternating / repeating-word /
//!    pseudo-random / mixed-1-MiB). Catches algorithmic bugs in inputs
//!    you can read in a failure message.
//! 2. **2000 randomized fixtures** with seed-controlled size
//!    (log-uniform over 1 B – 4 MiB, the LZ4 block ceiling) and shape
//!    (LCG / RLE / alternating / repeating-word / structured-text /
//!    mixed). Probes the long tail at the cadence that caught the
//!    second zstd bug (see
//!    `.claude/.../feedback_differential_fuzz_codec_fixes_against_reference.md`).
//! 3. **Truncation robustness** — every prefix of a valid block, plus
//!    raw pseudo-random bytes, fed to our decoder. The assertion is
//!    simply that it returns (`Ok`/`Err`) without panicking: the
//!    bounds checks must hold against adversarial input the way a
//!    decoder of untrusted downloads requires.
//!
//! `lz4_flex` is a dev-dependency only (the runtime decode path is
//! ours); it stays in the loop here as the reference, the same way
//! `xz2` does for the xz decoders and `flate2` for DEFLATE.

use peel::decode::lz4_native::{decompress_block, BlockDecodeError};

/// Largest block the LZ4 spec admits (BD bits 6-4 = 7 ⇒ 4 MiB).
const MAX_BLOCK_SIZE: usize = 4 * 1024 * 1024;

// ---- lz4_flex reference round-trip helpers --------------------------

fn lz4_flex_compress(payload: &[u8]) -> Vec<u8> {
    let max = lz4_flex::block::get_maximum_output_size(payload.len());
    let mut buf = vec![0u8; max];
    let n = lz4_flex::block::compress_into(payload, &mut buf).expect("lz4_flex compress");
    buf.truncate(n);
    buf
}

fn lz4_flex_decompress(block: &[u8], cap: usize) -> Vec<u8> {
    let mut buf = vec![0u8; cap];
    let n = lz4_flex::block::decompress_into(block, &mut buf).expect("lz4_flex decompress");
    buf.truncate(n);
    buf
}

fn native_decompress(block: &[u8], cap: usize) -> Vec<u8> {
    let mut buf = vec![0u8; cap];
    let n = decompress_block(block, &mut buf).expect("native decompress");
    buf.truncate(n);
    buf
}

/// Three-way differential: compress with `lz4_flex`, then decode the
/// resulting block through both `lz4_flex` and the native decoder, and
/// assert all three (payload, reference, native) agree.
fn assert_diff(payload: &[u8], label: &str) {
    // Empty payloads are handled at the frame layer and never reach
    // block compression in peel, so the degenerate empty-block
    // encoding is out of scope for the differential.
    if payload.is_empty() {
        return;
    }
    let block = lz4_flex_compress(payload);
    // Decompress into a buffer sized exactly to the payload — the
    // strictest test of the decoder's overrun checks.
    let cap = payload.len();
    let reference = lz4_flex_decompress(&block, cap);
    let native = native_decompress(&block, cap);
    assert_eq!(reference, payload, "{label}: lz4_flex reference != payload");
    assert_eq!(native, payload, "{label}: native != payload");
    assert_eq!(native, reference, "{label}: native != lz4_flex reference");
}

// ---- payload generators (deterministic; no `rand` crate) -----------

fn lcg_bytes(seed: u32, n: usize) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((state >> 16) as u8);
    }
    out
}

fn build_mixed_1mib() -> Vec<u8> {
    let mut out = Vec::with_capacity(1024 * 1024);
    let blocks: [fn(&mut Vec<u8>); 4] = [
        |out| out.extend(std::iter::repeat_n(b'.', 16 * 1024)),
        |out| {
            out.extend(
                std::iter::repeat(b"the quick brown fox jumps over the lazy dog ")
                    .flatten()
                    .copied()
                    .take(16 * 1024),
            )
        },
        |out| out.extend(lcg_bytes(0x1234_5678, 16 * 1024)),
        |out| {
            out.extend(
                std::iter::repeat([b'A', b'B', b'C', b'D'])
                    .flatten()
                    .take(16 * 1024),
            )
        },
    ];
    let mut i = 0;
    while out.len() < 1024 * 1024 {
        let want = (1024 * 1024 - out.len()).min(16 * 1024);
        let mut tmp = Vec::with_capacity(want);
        blocks[i % blocks.len()](&mut tmp);
        tmp.truncate(want);
        out.extend_from_slice(&tmp);
        i += 1;
    }
    out
}

fn curated_corpus() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("single_byte", vec![b'X']),
        ("two_bytes", vec![b'A', b'B']),
        ("hello_world", b"hello, world!".to_vec()),
        ("alphabet", (b'a'..=b'z').collect()),
        ("twelve_incompressible", lcg_bytes(0xCAFE_F00D, 12)),
        ("thirteen_incompressible", lcg_bytes(0xCAFE_F00D, 13)),
        ("rle_a_4kib", vec![b'A'; 4 * 1024]),
        ("rle_a_1b", vec![b'A'; 1]),
        (
            "alternate_ab_4kib",
            std::iter::repeat([b'A', b'B'])
                .flatten()
                .take(4 * 1024)
                .collect(),
        ),
        (
            "word_repeat_4kib",
            std::iter::repeat(b"abcd")
                .flatten()
                .copied()
                .take(4 * 1024)
                .collect(),
        ),
        ("pseudo_random_4kib", lcg_bytes(0xDEAD_BEEF, 4 * 1024)),
        ("mixed_1mib", build_mixed_1mib()),
        ("rle_4mib_max_block", vec![b'Z'; MAX_BLOCK_SIZE]),
    ]
}

/// Build one randomized fixture from a seed: size log-uniform over
/// `[1, 4 MiB]`, shape one of six families.
fn random_fixture(seed: u64) -> Vec<u8> {
    let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
    let mut next_u64 = || -> u64 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state
    };

    // Size log-uniform over [1, 4 MiB]: pick a magnitude bucket
    // (0..=22 ⇒ up to 2^22 = 4 MiB), then jitter within it. Biased
    // toward smaller inputs, where decoder bugs typically hide.
    let size_bits = (next_u64() % 23) as u32; // 0..=22
    let base = 1usize << size_bits;
    let jitter = (next_u64() as usize) % base.max(1);
    let size = (base + jitter).clamp(1, MAX_BLOCK_SIZE);

    let shape = next_u64() % 6;
    let mut payload = Vec::with_capacity(size);
    match shape {
        // LCG pseudo-random (mostly literals, few matches).
        0 => payload = lcg_bytes((seed as u32) ^ 0xAA55_AA55, size),
        // RLE: one byte repeated (deep overlap matches).
        1 => payload.resize(size, (next_u64() & 0xFF) as u8),
        // Alternating two bytes.
        2 => {
            let a = (next_u64() & 0xFF) as u8;
            let b = (next_u64() & 0xFF) as u8;
            for i in 0..size {
                payload.push(if i & 1 == 0 { a } else { b });
            }
        }
        // Repeating 4-byte word.
        3 => {
            let w = next_u64().to_le_bytes();
            for i in 0..size {
                payload.push(w[i & 3]);
            }
        }
        // Structured text: a sentence repeated, with occasional noise.
        4 => {
            let sentence = b"the quick brown fox jumps over the lazy dog. ";
            while payload.len() < size {
                payload.extend_from_slice(sentence);
            }
            payload.truncate(size);
            // Sprinkle in a few literal bytes to break long matches.
            let n = payload.len();
            if n > 0 {
                for _ in 0..(n / 512) {
                    let i = (next_u64() as usize) % n;
                    payload[i] = (next_u64() & 0xFF) as u8;
                }
            }
        }
        // Mixed regions concatenated then truncated to size.
        _ => {
            let mixed = build_mixed_1mib();
            while payload.len() < size {
                let take = (size - payload.len()).min(mixed.len());
                payload.extend_from_slice(&mixed[..take]);
            }
            payload.truncate(size);
        }
    }
    payload
}

// ---- tests ----------------------------------------------------------

#[test]
fn curated_corpus_differential() {
    for (label, payload) in curated_corpus() {
        assert_diff(&payload, label);
    }
}

#[test]
fn randomized_differential_2000_iterations() {
    for seed in 0..2000u64 {
        let payload = random_fixture(seed);
        assert_diff(&payload, &format!("seed {seed} (len {})", payload.len()));
    }
}

/// Every prefix of a valid block, plus raw pseudo-random "blocks",
/// must be handled without panicking — the bounds checks have to hold
/// against truncated and adversarial input.
#[test]
fn truncation_and_garbage_never_panic() {
    // Truncated prefixes of valid blocks of varied shapes.
    let payloads = [
        lcg_bytes(0x1111_2222, 333),
        vec![b'Q'; 4096],
        std::iter::repeat(b"abcd")
            .flatten()
            .copied()
            .take(2000)
            .collect::<Vec<u8>>(),
    ];
    for payload in &payloads {
        let block = lz4_flex_compress(payload);
        let mut scratch = vec![0u8; payload.len() + 16];
        for cut in 0..=block.len() {
            // Result intentionally ignored: the assertion is that the
            // call returns rather than panics or reads out of bounds.
            let _: Result<usize, BlockDecodeError> = decompress_block(&block[..cut], &mut scratch);
        }
    }

    // Raw pseudo-random bytes interpreted as a "block".
    let mut scratch = vec![0u8; 64 * 1024];
    for seed in 0..512u32 {
        let garbage = lcg_bytes(seed.wrapping_mul(2_654_435_761), (seed as usize % 4096) + 1);
        let _: Result<usize, BlockDecodeError> = decompress_block(&garbage, &mut scratch);
    }

    // Tiny adversarial blocks targeting each error path.
    let mut tiny = vec![0u8; 32];
    for b0 in 0u16..=255 {
        let _: Result<usize, BlockDecodeError> = decompress_block(&[b0 as u8], &mut tiny);
        let _: Result<usize, BlockDecodeError> =
            decompress_block(&[b0 as u8, 0x01, 0x00, 0x00], &mut tiny);
    }
}
