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
//! Phase 7 swapped the hand-rolled decoder in as the production
//! path; these tests no longer need a feature gate.

use std::io::{Cursor, Read, Write};

use peel::decode::xz_native::{resume_factory, Decoder};
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

/// Generate `n` bytes of LZMA-friendly content: distinct
/// pseudo-English sentences with light variation. The content
/// compresses heavily through LZMA's match-finder (so xz picks
/// LZMA chunks over uncompressed) while the input size
/// guarantees a bounded number of output bytes per chunk —
/// we use this to force multi-LZMA-chunk Blocks for the
/// Phase 6 resume tests.
fn build_lzma_friendly_input(n: usize) -> Vec<u8> {
    let lines: &[&[u8]] = &[
        b"the quick brown fox jumps over the lazy dog ",
        b"alpha bravo charlie delta echo foxtrot golf ",
        b"every good boy deserves favor and this is line ",
        b"the rain in spain falls mainly on the plain ",
        b"to be or not to be that is the question whether ",
        b"in the beginning was the word and the word was with ",
    ];
    let mut out = Vec::with_capacity(n);
    let mut state: u32 = 0x1234_5678;
    while out.len() < n {
        // Pick a line at LCG-random; append a 6-digit decimal
        // marker so each emitted chunk is *almost* but not
        // exactly a copy of an earlier one (LZMA's rep matches
        // still cover most of the bytes).
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let line = lines[(state >> 24) as usize % lines.len()];
        out.extend_from_slice(line);
        let digits = state % 1_000_000;
        out.extend_from_slice(format!("{digits:06} ").as_bytes());
    }
    out.truncate(n);
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

/// Incompressible (LCG-random) payload large enough that liblzma
/// emits LZMA2 Uncompressed chunks (control bytes 0x01/0x02) for
/// most of the stream. The decoder must mirror those bytes into
/// the LZMA dict so that any LZMA chunk the encoder emits later
/// can match back into them; without that, the first such match
/// rejects with `LzmaMatchOutOfRange` against an essentially
/// empty dict. 1 MiB is well above liblzma's per-chunk cap (so
/// there are many Uncompressed chunks) and small enough to keep
/// test time bounded.
#[test]
fn incompressible_payload_round_trips() {
    let input = lcg_bytes(0xFEED_FACE, 1024 * 1024);
    let stream = xz2_compress(&input, 6);
    let native = native_decompress(&stream);
    let reference = xz2_decompress(&stream);
    assert_eq!(native, reference, "differential mismatch");
    assert_eq!(native, input, "round-trip mismatch");
}

/// Mixed-content payload — alternating regions of incompressible
/// random bytes and zero padding — that drives liblzma to emit a
/// chunk pattern with reset_state-only LZMA chunks (control mode
/// `0b101`, i.e. 0xA0..=0xBF) interleaved with Uncompressed
/// chunks. The reset_state chunk requires the decoder to
/// reinitialize the probability tables (not just the LZMA state
/// machine + reps) so the bitstream stays in sync with the
/// encoder, which has done the same. Two random regions plus a
/// zero-padding region between them is the smallest shape that
/// reliably exercises this path at preset 6.
#[test]
fn mixed_random_and_zeros_round_trips() {
    let mut input = Vec::with_capacity(2 * 1024 * 1024 + 4096);
    input.extend(lcg_bytes(0xBEEFu32, 1024 * 1024));
    input.extend(std::iter::repeat_n(0u8, 4096));
    input.extend(lcg_bytes(0xBEEFu32 + 1, 1024 * 1024));
    input.extend(std::iter::repeat_n(0u8, 4096));
    let stream = xz2_compress(&input, 6);
    let native = native_decompress(&stream);
    let reference = xz2_decompress(&stream);
    assert_eq!(native, reference, "differential mismatch");
    assert_eq!(native, input, "round-trip mismatch");
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

/// Phase 6: capture `decoder_state` at every LZMA2 chunk
/// boundary inside a Block, resume from each, and verify the
/// suffix is byte-identical to a clean run. Mirrors the
/// `frame_boundary_property_is_a_valid_restart_point` exit
/// criterion from `docs/PLAN_xz_block_decoder.md`.
#[test]
fn resume_at_every_chunk_boundary_yields_identical_suffix() {
    // ~1 MiB of LCG-pseudo-random bytes forces multiple LZMA2
    // chunks: a chunk's compressed-size cap is 64 KiB, and
    // pseudo-random content compresses near 1:1, so 1 MiB
    // produces ≥16 chunks at preset 6.
    // ~4 MiB of structured text repeated. xz at preset 6
    // compresses repeating English-like content as LZMA chunks
    // (high compressibility); the uncompressed-side cap on a
    // single LZMA2 chunk is 2 MiB, so a 4 MiB input is
    // guaranteed to span at least two LZMA chunks regardless
    // of how favorably the model compresses.
    let input = build_lzma_friendly_input(4 * 1024 * 1024);
    let stream = xz2_compress(&input, 6);

    // Walk the clean run, snapshotting (offset, blob, output_len)
    // at every step where `decoder_state` returns Some.
    let mut decoder = Decoder::new(Box::new(Cursor::new(stream.clone()))).expect("clean");
    let mut out = Vec::new();
    let mut snapshots: Vec<(u64, Vec<u8>, usize)> = Vec::new();
    loop {
        let pre_len = out.len();
        let status = decoder.decode_step(&mut out).expect("step");
        if let Some(blob) = decoder.decoder_state() {
            let offset = decoder.bytes_consumed().get();
            snapshots.push((offset, blob, out.len()));
            // bytes_consumed at this step is after the chunk's
            // bytes, so `out.len() >= pre_len`.
            assert!(out.len() >= pre_len);
        }
        if status == DecodeStatus::Eof {
            break;
        }
    }
    let clean_output = out;

    // We should have hit at least 2 chunk boundaries on a 256 KiB
    // input.
    assert!(
        snapshots.len() >= 2,
        "expected ≥2 chunk-boundary snapshots, got {}",
        snapshots.len()
    );

    // Resume from each snapshot. The decoded suffix must equal
    // `clean_output[snapshot.output_len..]`.
    for (idx, (offset, blob, output_len)) in snapshots.iter().enumerate() {
        let suffix_src: Vec<u8> = stream[*offset as usize..].to_vec();
        let mut resumed =
            resume_factory(Box::new(Cursor::new(suffix_src)), blob, *offset).expect("resume");
        let mut suffix_out = Vec::new();
        loop {
            match resumed.decode_step(&mut suffix_out).expect("resumed step") {
                DecodeStatus::Eof => break,
                DecodeStatus::MoreData => continue,
            }
        }
        assert_eq!(
            suffix_out,
            clean_output[*output_len..],
            "snapshot {idx} (offset={offset}, output_len={output_len}) suffix mismatch"
        );
    }
}

/// Phase 6 frame_boundary contract: between LZMA2 chunks of a
/// single Block, `frame_boundary` advances per-chunk (matching
/// `decoder_state` returning Some). Pin so a regression in the
/// per-chunk advance fires here.
#[test]
fn frame_boundary_advances_per_chunk_inside_block() {
    let input = build_lzma_friendly_input(4 * 1024 * 1024);
    let stream = xz2_compress(&input, 6);
    let mut decoder = Decoder::new(Box::new(Cursor::new(stream))).expect("construct");
    let mut out = Vec::new();
    let mut boundaries: Vec<u64> = Vec::new();
    loop {
        let prior = decoder.frame_boundary();
        let status = decoder.decode_step(&mut out).expect("step");
        let next = decoder.frame_boundary();
        if next != prior {
            if let Some(b) = next {
                boundaries.push(b.get());
            }
        }
        if status == DecodeStatus::Eof {
            break;
        }
    }
    // Two distinct sources of advance: per-chunk (inside Block)
    // and the Stream-end advance. Total must be > 2.
    assert!(
        boundaries.len() >= 3,
        "expected at least 3 frame_boundary advances (≥2 chunk + 1 Stream-end), got {boundaries:?}",
    );
    // And boundaries must be monotonically increasing.
    for w in boundaries.windows(2) {
        assert!(w[0] < w[1], "boundaries regressed: {w:?}");
    }
}

/// Phase 6 property test: deterministic-but-varied seeds
/// produce inputs that span multiple LZMA2 chunks; we resume
/// from the *kth* chunk boundary (k chosen by a small LCG over
/// the seed) and verify byte-identical suffix output. Catches
/// regressions where the resume blob captures one chunk
/// boundary correctly but drifts at later ones.
#[test]
fn resume_property_random_kill_points_across_seeds() {
    for seed in [0xDEAD_BEEFu32, 0xCAFE_BABE, 0x1234_5678, 0xFEED_FACE] {
        // Synthesize a per-seed input by perturbing the
        // LZMA-friendly fixture with the seed's low byte.
        let mut input = build_lzma_friendly_input(1024 * 1024);
        let perturb = (seed & 0x1F) as u8;
        for chunk in input.chunks_mut(64 * 1024) {
            for b in chunk.iter_mut().step_by(257) {
                *b = b.wrapping_add(perturb);
            }
        }
        let stream = xz2_compress(&input, 6);

        // Walk to collect snapshots.
        let mut decoder = Decoder::new(Box::new(Cursor::new(stream.clone()))).expect("clean");
        let mut out = Vec::new();
        let mut snapshots: Vec<(u64, Vec<u8>, usize)> = Vec::new();
        loop {
            let status = decoder.decode_step(&mut out).expect("step");
            if let Some(blob) = decoder.decoder_state() {
                snapshots.push((decoder.bytes_consumed().get(), blob, out.len()));
            }
            if status == DecodeStatus::Eof {
                break;
            }
        }
        let clean_output = out;
        assert!(
            !snapshots.is_empty(),
            "seed 0x{seed:08X}: no chunk-boundary snapshots"
        );

        // Pick the kth snapshot by LCG over the seed.
        let kk = (seed.wrapping_mul(1_664_525) >> 8) as usize % snapshots.len();
        let (offset, blob, output_len) = &snapshots[kk];
        let suffix_src: Vec<u8> = stream[*offset as usize..].to_vec();
        let mut resumed =
            resume_factory(Box::new(Cursor::new(suffix_src)), blob, *offset).expect("resume");
        let mut suffix_out = Vec::new();
        loop {
            match resumed.decode_step(&mut suffix_out).expect("resumed step") {
                DecodeStatus::Eof => break,
                DecodeStatus::MoreData => continue,
            }
        }
        assert_eq!(
            suffix_out,
            clean_output[*output_len..],
            "seed 0x{seed:08X} snapshot {kk}/{}: suffix mismatch",
            snapshots.len()
        );
    }
}

/// A misshapen resume blob (here: mangled magic) surfaces a
/// typed `DecodeError::Construct` rather than panicking. V2 no
/// longer carries an inner CRC32 — `PLAN_checkpoint_blob_dedup.md`
/// Phase 1 — so mid-body bit flips are delegated to the outer
/// `Checkpoint` body fnv1a64 (validated above this layer); this
/// test pins the structural rejection paths the resume layer
/// still owns.
#[test]
fn corrupted_resume_blob_surfaces_typed_error() {
    let input = b"resume-corruption-test".repeat(512);
    let stream = xz2_compress(&input, 6);

    // Walk to the first chunk boundary, capture the blob.
    let mut decoder = Decoder::new(Box::new(Cursor::new(stream.clone()))).expect("walk");
    let mut out = Vec::new();
    let blob = loop {
        let _ = decoder.decode_step(&mut out).expect("step");
        if let Some(b) = decoder.decoder_state() {
            break b;
        }
    };

    // Mangle the magic so the parser rejects deterministically.
    let mut corrupted = blob.clone();
    corrupted[0] ^= 0x42;

    // Resume should fail before the first decode_step.
    let result = resume_factory(Box::new(Cursor::new(Vec::new())), &corrupted, 0);
    assert!(result.is_err(), "expected resume rejection on corruption");
}

/// Wrap a current (V2) resume blob's bytes in a V1 envelope so
/// the legacy read path can be exercised end-to-end through
/// `resume_factory`. V1's wire shape is `b"XDR1" || 0x01 || body
/// || crc32_le(body)`; V2's is `b"XDR2" || 0x02 || body`. The
/// body bytes are identical between versions, so we copy them
/// verbatim and re-wrap.
///
/// `PLAN_checkpoint_blob_dedup.md` Phase 1 — exercises the
/// upgrade-from-pre-Phase-1 case where an existing `.peel.ckpt`
/// file holds a V1 blob inside its `decoder_state` field.
fn v1_envelope_around_v2_body(v2_blob: &[u8]) -> Vec<u8> {
    use peel::hash::crc32::Crc32;
    assert_eq!(&v2_blob[..4], b"XDR2", "expected current writer to emit V2");
    assert_eq!(v2_blob[4], 0x02);
    let body = &v2_blob[5..];
    let mut out = Vec::with_capacity(v2_blob.len() + 4);
    out.extend_from_slice(b"XDR1");
    out.push(0x01);
    out.extend_from_slice(body);
    let mut crc = Crc32::new();
    crc.update(&out);
    out.extend_from_slice(&crc.finalize().to_le_bytes());
    out
}

/// V1 fixture round-trip — hands a hand-crafted V1 envelope to
/// `resume_factory` and asserts the decoded suffix matches a
/// clean run byte-for-byte. This is the upgrade path: a user on
/// pre-Phase-1 peel has a `.peel.ckpt` containing a V1
/// `decoder_state`, then upgrades to a Phase-1 binary. The new
/// reader must accept the old blob.
#[test]
fn resume_blob_v1_envelope_resumes_byte_identically() {
    let input = build_lzma_friendly_input(1024 * 1024);
    let stream = xz2_compress(&input, 6);

    // Clean run: capture every chunk-boundary snapshot (offset,
    // V2 blob, output_len).
    let mut decoder = Decoder::new(Box::new(Cursor::new(stream.clone()))).expect("clean");
    let mut out = Vec::new();
    let mut snapshots: Vec<(u64, Vec<u8>, usize)> = Vec::new();
    loop {
        let status = decoder.decode_step(&mut out).expect("step");
        if let Some(blob) = decoder.decoder_state() {
            snapshots.push((decoder.bytes_consumed().get(), blob, out.len()));
        }
        if status == DecodeStatus::Eof {
            break;
        }
    }
    let clean_output = out;
    assert!(
        !snapshots.is_empty(),
        "no chunk-boundary snapshots — fixture too small?"
    );

    // Resume from the middle snapshot via a V1 envelope.
    let mid = snapshots.len() / 2;
    let (offset, v2_blob, output_len) = &snapshots[mid];
    let v1_blob = v1_envelope_around_v2_body(v2_blob);
    assert_eq!(v1_blob.len(), v2_blob.len() + 4, "V1 adds 4 B trailer");

    let suffix_src: Vec<u8> = stream[*offset as usize..].to_vec();
    let mut resumed =
        resume_factory(Box::new(Cursor::new(suffix_src)), &v1_blob, *offset).expect("v1 resume");
    let mut suffix_out = Vec::new();
    loop {
        match resumed.decode_step(&mut suffix_out).expect("resumed step") {
            DecodeStatus::Eof => break,
            DecodeStatus::MoreData => continue,
        }
    }
    assert_eq!(
        suffix_out,
        clean_output[*output_len..],
        "V1 envelope suffix mismatch (offset={offset}, output_len={output_len})"
    );
}

/// V1 envelope's trailing CRC32 is still verified — flip a byte
/// in the middle of a hand-crafted V1 blob and watch
/// `resume_factory` reject it.
#[test]
fn v1_envelope_rejects_corrupted_body_via_trailing_crc() {
    let input = b"resume-corruption-test".repeat(512);
    let stream = xz2_compress(&input, 6);

    let mut decoder = Decoder::new(Box::new(Cursor::new(stream.clone()))).expect("walk");
    let mut out = Vec::new();
    let v2_blob = loop {
        let _ = decoder.decode_step(&mut out).expect("step");
        if let Some(b) = decoder.decoder_state() {
            break b;
        }
    };

    let mut v1_blob = v1_envelope_around_v2_body(&v2_blob);
    // Flip a byte in the body (after magic+version, before
    // trailing CRC). The V1 trailer must reject.
    let mid = v1_blob.len() / 2;
    v1_blob[mid] ^= 0x42;
    let result = resume_factory(Box::new(Cursor::new(Vec::new())), &v1_blob, 0);
    assert!(
        result.is_err(),
        "V1 envelope should reject body corruption via trailing CRC32"
    );
}
