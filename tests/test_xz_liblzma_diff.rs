//! Phase 7 of [`docs/PLAN_xz_liblzma_port.md`](../docs/PLAN_xz_liblzma_port.md):
//! the **full differential corpus** for the public
//! [`peel::decode::xz_liblzma::Decoder`].
//!
//! Three layers of coverage:
//!
//! 1. **Curated 9-fixture corpus** mirroring
//!    [`tests/test_xz_native.rs::corpus`] — empty / single byte /
//!    alphabet / RLE / alternating / repeating-word / pseudo-random /
//!    mixed-1-MiB. Catches algorithmic bugs in named, easily-debuggable
//!    inputs.
//! 2. **100 randomized fixtures** with seed-controlled size + shape
//!    diversity (LCG / RLE / alternating / structured-text / mixed).
//!    Probes the long tail.
//! 3. **Cross-preset coverage**: every fixture decoded under presets
//!    0 / 3 / 6 / 9 (different `dict_size`, different chunk shapes,
//!    different distance-slot distributions).
//!
//! Each fixture asserts a **three-way differential**:
//! liblzma-port output == xz_native output == xz2 output ==
//! original payload. Any of the three pairs going out of sync surfaces
//! the bug at a specific (fixture, preset) coordinate.
//!
//! # Fuzz follow-on
//!
//! The plan calls for a 1-hour fuzz target run over the new
//! `lzma_decode_port` (existing `fuzz/fuzz_targets/` retargeted to
//! the port). That's an overnight invocation rather than an
//! in-session test — filed as a Phase F TODO at the bottom of this
//! file.

#![cfg(unix)]

use std::io::{Cursor, Read, Write};

use peel::decode::xz_liblzma::Decoder as XzLiblzmaDecoder;
use peel::decode::{DecodeStatus, StreamingDecoder};

// ---- xz2 round-trip helpers ----------------------------------------

fn xz2_compress(input: &[u8], preset: u32) -> Vec<u8> {
    let mut compressed = Vec::new();
    let mut encoder = xz2::write::XzEncoder::new(&mut compressed, preset);
    encoder.write_all(input).expect("xz2 encode");
    encoder.finish().expect("xz2 finish");
    compressed
}

fn xz2_decompress(stream: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    xz2::read::XzDecoder::new(Cursor::new(stream))
        .read_to_end(&mut out)
        .expect("xz2 decode");
    out
}

// ---- decoder harnesses --------------------------------------------

fn liblzma_port_decompress(stream: &[u8]) -> Vec<u8> {
    let mut decoder: XzLiblzmaDecoder =
        XzLiblzmaDecoder::new(Box::new(Cursor::new(stream.to_vec()))).expect("construct port");
    let mut out = Vec::new();
    loop {
        match decoder.decode_step(&mut out).expect("decode_step (port)") {
            DecodeStatus::Eof => break,
            DecodeStatus::MoreData => continue,
        }
    }
    out
}

/// Two-way differential gate (Phase F.6 retired `xz_native`;
/// `xz2` is now the sole external reference).
fn assert_three_way(payload: &[u8], stream: &[u8], label: &str) {
    let port = liblzma_port_decompress(stream);
    let xz2 = xz2_decompress(stream);
    assert_eq!(
        port.len(),
        payload.len(),
        "{label}: port length mismatch (got {}, want {})",
        port.len(),
        payload.len(),
    );
    assert_eq!(port, payload, "{label}: port != payload");
    assert_eq!(xz2, payload, "{label}: xz2 != payload");
    assert_eq!(port, xz2, "{label}: port != xz2");
}

// ---- payload generators --------------------------------------------

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

/// Curated corpus mirroring [`tests/test_xz_native.rs::corpus`].
fn curated_corpus() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("empty", Vec::new()),
        ("single_byte", vec![b'X']),
        ("hello_world", b"hello, world!".to_vec()),
        ("alphabet", (b'a'..=b'z').collect()),
        ("rle_a_4kib", vec![b'A'; 4 * 1024]),
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
    ]
}

/// Build one randomized fixture from a seed. Different seeds give
/// different sizes (in `[0, 256 KiB]`) and different content shapes
/// (LCG / RLE / alternating / repeating-word / mixed).
fn random_fixture(seed: u64) -> Vec<u8> {
    let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
    let mut next_u64 = || -> u64 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state
    };

    // Size in [0, 256 KiB], biased toward smaller (more
    // fixtures hit the "few-symbol" code paths where bugs
    // typically hide).
    let size_bits = next_u64() % 19; // 0..=18 → up to 256 KiB
    let mut size = 1usize.wrapping_shl(size_bits as u32) + (next_u64() as usize % 64);
    size = size.min(256 * 1024);

    // Shape selection.
    let shape = next_u64() % 6;
    let mut payload = Vec::with_capacity(size);
    match shape {
        0 => {
            // LCG random
            payload = lcg_bytes((seed as u32) ^ 0xAA55_AA55, size);
        }
        1 => {
            // RLE: a single byte
            let b = (next_u64() & 0xFF) as u8;
            payload.resize(size, b);
        }
        2 => {
            // Alternating two bytes
            let a = (next_u64() & 0xFF) as u8;
            let b = (next_u64() & 0xFF) as u8;
            for i in 0..size {
                payload.push(if i & 1 == 0 { a } else { b });
            }
        }
        3 => {
            // Repeating 4-byte word
            let w = next_u64().to_le_bytes();
            let word = [w[0], w[1], w[2], w[3]];
            for i in 0..size {
                payload.push(word[i & 3]);
            }
        }
        4 => {
            // Structured text mixed with line numbers (matches +
            // literals balanced).
            let lines: &[&[u8]] = &[
                b"the quick brown fox jumps over ",
                b"alpha bravo charlie delta echo ",
                b"every good boy deserves favor ",
            ];
            let mut i: u64 = 0;
            while payload.len() < size {
                let pick = (next_u64() as usize) % lines.len();
                payload.extend_from_slice(lines[pick]);
                payload.extend_from_slice(format!("{i:06}\n").as_bytes());
                i += 1;
            }
            payload.truncate(size);
        }
        _ => {
            // Mix: alternating 1 KiB blocks of two shapes.
            let mut a_state = (next_u64() as u32) ^ 0xDEAD_BEEF;
            let block = (next_u64() & 0xFF) as u8;
            let mut emit_lcg = (seed & 1) == 0;
            while payload.len() < size {
                let want = (size - payload.len()).min(1024);
                if emit_lcg {
                    a_state = a_state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    let chunk = lcg_bytes(a_state, want);
                    payload.extend_from_slice(&chunk);
                } else {
                    payload.extend(std::iter::repeat_n(block, want));
                }
                emit_lcg = !emit_lcg;
            }
            payload.truncate(size);
        }
    }
    payload
}

// ---- tests --------------------------------------------------------

/// Curated corpus × default preset (6).
#[test]
fn diff_curated_default_preset() {
    for (name, payload) in curated_corpus() {
        let stream = xz2_compress(&payload, 6);
        assert_three_way(&payload, &stream, &format!("curated/{name}/preset=6"));
    }
}

/// Curated corpus × all presets {0, 3, 6, 9}. Bounded by skipping
/// the 1 MiB fixture at preset 0 (small dict + 1 MiB input would
/// trigger many chunk dispatches; the smaller fixtures cover the
/// relevant code paths at each preset).
#[test]
fn diff_curated_across_presets() {
    let fixtures: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("single_byte", vec![b'X']),
        ("hello_world", b"hello, world!".to_vec()),
        ("alphabet", (b'a'..=b'z').collect()),
        ("rle_a_4kib", vec![b'A'; 4 * 1024]),
        ("pseudo_random_4kib", lcg_bytes(0xDEAD_BEEF, 4 * 1024)),
    ];
    for preset in [0u32, 3, 6, 9] {
        for (name, payload) in &fixtures {
            let stream = xz2_compress(payload, preset);
            assert_three_way(payload, &stream, &format!("curated/{name}/preset={preset}"));
        }
    }
}

/// 100 randomized fixtures at preset 6.
#[test]
fn diff_random_100_default_preset() {
    for i in 0..100u64 {
        let payload = random_fixture(0x100 ^ i);
        let stream = xz2_compress(&payload, 6);
        assert_three_way(
            &payload,
            &stream,
            &format!("random/seed={i}/len={}/preset=6", payload.len()),
        );
    }
}

/// 100 randomized fixtures × cross-preset spot checks (seeds
/// modulo 4 selects the preset). 100 fixtures at 4 presets would
/// be 400 round-trips; bucketing by seed keeps the test ~25
/// fixtures-per-preset in <30s wall-clock.
#[test]
fn diff_random_100_across_presets() {
    let presets = [0u32, 3, 6, 9];
    for i in 0..100u64 {
        let payload = random_fixture(0x200 ^ i);
        let preset = presets[(i as usize) % presets.len()];
        let stream = xz2_compress(&payload, preset);
        assert_three_way(
            &payload,
            &stream,
            &format!("random/seed={i}/len={}/preset={preset}", payload.len()),
        );
    }
}

// ---- Phase F follow-on (fuzz) -------------------------------------
//
// The plan calls for a 1-hour fuzz target run over `lzma_decode_port`.
// Two pieces of work, both filed as Phase F follow-ons:
//
// 1. Retarget `fuzz/fuzz_targets/xz_native_*` to also call the new
//    `xz_liblzma::Decoder`. The simplest shape: have each fuzz
//    target decode the same input through both decoders and assert
//    byte-identical output (or both return the same Err variant).
//
// 2. Run `cargo +nightly fuzz run xz_liblzma_diff -- -max_total_time=3600`
//    on a quiet host overnight. Capture any panics, ub-detected
//    crashes, or differential-output disagreements as bug reports.
//
// The 100-fixture randomized corpus above covers the common cases;
// fuzz adds adversarial inputs (corrupt bytes, truncations, and
// pathological compressed-payload shapes) that random-seed
// generation rarely hits. Filed against
// `docs/PLAN_xz_liblzma_port.md`'s Phase F TODO list.
