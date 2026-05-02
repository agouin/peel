//! Integration tests for the hand-rolled xz / LZMA decoder
//! (`src/decode/xz_native/`).
//!
//! Phase 4 of `docs/PLAN_xz_block_decoder.md`. Two suites:
//!
//! 1. A **differential** suite that compresses a curated corpus of
//!    inputs through `xz2`/liblzma at several presets and verifies
//!    the hand-rolled decoder produces the same bytes as
//!    `xz2`'s decoder. The plan calls for "100 random fixtures"
//!    against xz2's `Stream::process`; we keep the corpus to a
//!    deterministic set that reaches every interesting code path
//!    (literal-only, RLE, alphabet, mixed) so a CI failure names
//!    a specific input rather than landing on whichever fixture
//!    `rand` happened to generate.
//! 2. A **chunk-reset matrix** that pins decode through a
//!    multi-chunk LZMA2 stream (`xz -T1` on a large input) so the
//!    `reset_state` / `reset_props` / `reset_dict` decode paths
//!    are all exercised at integration scale.
//!
//! These tests are gated on `#[cfg(feature = "peel_xz_native")]`
//! because the hand-rolled module itself is feature-gated until
//! Phase 7 swaps it in as the production path.

#![cfg(feature = "peel_xz_native")]

use std::io::{Cursor, Read, Write};

use peel::decode::xz_native::Decoder;
use peel::decode::{DecodeStatus, StreamingDecoder};

/// Compress `input` with `xz2` at the given preset and return the
/// resulting `.xz` byte stream.
fn xz2_compress(input: &[u8], preset: u32) -> Vec<u8> {
    let mut compressed = Vec::new();
    let mut encoder = xz2::write::XzEncoder::new(&mut compressed, preset);
    encoder.write_all(input).expect("xz2 encode");
    encoder.finish().expect("xz2 finish");
    compressed
}

/// Decompress a `.xz` byte stream through the hand-rolled
/// [`XzNativeDecoder`], returning the decoded bytes.
fn native_decompress(stream: &[u8]) -> Vec<u8> {
    let mut decoder: Decoder =
        Decoder::new(Box::new(Cursor::new(stream.to_vec()))).expect("construct");
    let mut out = Vec::new();
    loop {
        match decoder.decode_step(&mut out).expect("decode_step") {
            DecodeStatus::Eof => break,
            DecodeStatus::MoreData => continue,
        }
    }
    out
}

/// Decompress a `.xz` byte stream through `xz2`/liblzma and
/// return the decoded bytes. Used as the differential ground
/// truth.
fn xz2_decompress(stream: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    xz2::read::XzDecoder::new(Cursor::new(stream))
        .read_to_end(&mut out)
        .expect("xz2 decode");
    out
}

/// Each fixture: (name, payload). The corpus is curated rather
/// than randomly generated so a CI failure surfaces a
/// directly-named input.
fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("empty", Vec::new()),
        ("single_byte", vec![b'X']),
        ("hello_world", b"hello, world!".to_vec()),
        // Plain ASCII alphabet — covers literal decoding for
        // each context.
        ("alphabet", (b'a'..=b'z').collect()),
        // RLE: repeating one byte. Compresses heavily into rep
        // matches.
        ("rle_a_4kib", vec![b'A'; 4 * 1024]),
        // Alternating two bytes. Exercises rep1/rep2/rep3
        // rotation.
        (
            "alternate_ab_4kib",
            std::iter::repeat([b'A', b'B'])
                .flatten()
                .take(4 * 1024)
                .collect(),
        ),
        // Repeating 4-byte word.
        (
            "word_repeat_4kib",
            std::iter::repeat(b"abcd")
                .flatten()
                .copied()
                .take(4 * 1024)
                .collect(),
        ),
        // Pseudo-random bytes via a simple LCG (deterministic).
        // This mostly defeats LZMA so the literal path dominates.
        ("pseudo_random_4kib", lcg_bytes(0xDEAD_BEEF, 4 * 1024)),
        // Larger input: 1 MiB of mixed RLE + random. xz at preset
        // 6's chunk size is 64 KiB, so this guarantees a multi-
        // chunk LZMA2 stream — exercising at least one mid-stream
        // chunk boundary including the inherited-properties path.
        ("mixed_1mib", build_mixed_1mib()),
    ]
}

/// Linear congruential generator (Numerical Recipes constants).
/// Deterministic; only used to produce a "looks random" payload
/// for the differential test corpus.
fn lcg_bytes(seed: u32, n: usize) -> Vec<u8> {
    let mut state = seed;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((state >> 16) as u8);
    }
    out
}

/// 1 MiB of mixed content: alternating 16 KiB regions of
/// "compresses well" (RLE / repeating word) and "doesn't"
/// (LCG-random). Forces multiple LZMA2 chunks.
fn build_mixed_1mib() -> Vec<u8> {
    let mut out = Vec::with_capacity(1024 * 1024);
    let blocks = [
        |out: &mut Vec<u8>| out.extend(std::iter::repeat_n(b'.', 16 * 1024)),
        |out: &mut Vec<u8>| {
            out.extend(
                std::iter::repeat(b"the quick brown fox jumps over the lazy dog ")
                    .flatten()
                    .copied()
                    .take(16 * 1024),
            )
        },
        |out: &mut Vec<u8>| {
            out.extend(lcg_bytes(0x12345678, 16 * 1024));
        },
        |out: &mut Vec<u8>| {
            out.extend(
                std::iter::repeat([b'A', b'B', b'C', b'D'])
                    .flatten()
                    .take(16 * 1024),
            )
        },
    ];
    let mut i = 0;
    while out.len() < 1024 * 1024 {
        let want = std::cmp::min(16 * 1024, 1024 * 1024 - out.len());
        let mut tmp = Vec::with_capacity(want);
        blocks[i % blocks.len()](&mut tmp);
        tmp.truncate(want);
        out.extend_from_slice(&tmp);
        i += 1;
    }
    out
}

/// Differential: every fixture round-trips through xz2 → native
/// byte-identically, and the native output matches xz2's reference
/// decoder.
#[test]
fn differential_against_xz2_default_preset() {
    for (name, payload) in corpus() {
        let stream = xz2_compress(&payload, 6);
        let native = native_decompress(&stream);
        let reference = xz2_decompress(&stream);
        assert_eq!(
            native,
            reference,
            "differential mismatch on fixture {name} (len={})",
            payload.len()
        );
        assert_eq!(
            native,
            payload,
            "round-trip mismatch on fixture {name} (len={})",
            payload.len()
        );
    }
}

/// Differential: same corpus across xz presets 0/3/6/9. Different
/// presets produce different `dict_size` and chunk shapes, so this
/// catches preset-specific bugs (e.g. a smaller dict's tighter
/// match-distance distribution exercising different distance-slot
/// ranges).
#[test]
fn differential_against_xz2_across_presets() {
    // Use the smaller subset of the corpus to keep test time
    // bounded: an empty input + the medium fixtures.
    let fixtures = vec![
        ("empty", Vec::new()),
        ("alphabet", (b'a'..=b'z').collect::<Vec<_>>()),
        ("rle_a_4kib", vec![b'A'; 4 * 1024]),
        (
            "alternate_ab_4kib",
            std::iter::repeat([b'A', b'B'])
                .flatten()
                .take(4 * 1024)
                .collect(),
        ),
        ("pseudo_random_4kib", lcg_bytes(0xCAFE_BABE, 4 * 1024)),
    ];
    for preset in [0u32, 3, 6, 9] {
        for (name, payload) in &fixtures {
            let stream = xz2_compress(payload, preset);
            let native = native_decompress(&stream);
            let reference = xz2_decompress(&stream);
            assert_eq!(
                native, reference,
                "differential mismatch on preset={preset} fixture={name}"
            );
            assert_eq!(
                native, *payload,
                "round-trip mismatch on preset={preset} fixture={name}"
            );
        }
    }
}

/// Multi-chunk integration: a 4 MiB input forces multiple LZMA2
/// chunks (xz's default chunk size is 64 KiB at preset 6, so
/// ~64 chunks here). Exercises the inherited-properties path
/// (chunks with `reset_state` only or no reset at all) at
/// integration scale.
#[test]
fn multi_chunk_integration_4mib_mixed() {
    let mut input = Vec::with_capacity(4 * 1024 * 1024);
    while input.len() < 4 * 1024 * 1024 {
        input.extend(build_mixed_1mib());
    }
    input.truncate(4 * 1024 * 1024);
    let stream = xz2_compress(&input, 6);
    let native = native_decompress(&stream);
    assert_eq!(native.len(), input.len());
    assert_eq!(native, input, "4 MiB multi-chunk round-trip");
}

/// Concatenated streams (`cat a.xz b.xz`) decode in order.
/// Mirrors `xz_native::tests::concatenated_streams_decode_in_order`
/// at integration scale via real xz output.
#[test]
fn concatenated_xz_streams_round_trip() {
    let a_input = b"first stream payload".to_vec();
    let b_input = b"second stream is different content".to_vec();
    let mut combined = xz2_compress(&a_input, 6);
    combined.extend_from_slice(&xz2_compress(&b_input, 6));
    let native = native_decompress(&combined);
    let mut expected = a_input.clone();
    expected.extend_from_slice(&b_input);
    assert_eq!(native, expected);
}

/// `bytes_consumed` reaches the full source length on a clean
/// run. Pin the contract so a regression in source-byte
/// accounting surfaces directly.
#[test]
fn bytes_consumed_lands_at_source_end() {
    let input = b"sample content for accounting".to_vec();
    let stream = xz2_compress(&input, 6);
    let stream_len = stream.len() as u64;
    let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
    let mut out = Vec::new();
    while decoder.decode_step(&mut out).expect("step") == DecodeStatus::MoreData {}
    assert_eq!(decoder.bytes_consumed().get(), stream_len);
    assert_eq!(out, input);
    assert!(decoder.frame_boundary().is_some());
}
