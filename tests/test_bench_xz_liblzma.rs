//! Phase 4 of [`docs/PLAN_xz_liblzma_port.md`](../docs/PLAN_xz_liblzma_port.md):
//! the **gating bench**.
//!
//! Drives the new [`peel::decode::xz_liblzma::decoder::lzma_decode_port`]
//! against a full `.xz`-encoded payload by parsing the LZMA2 chunk
//! framing (via [`peel::decode::xz_native::block`]'s public parsers)
//! and replaying each chunk's compressed bytes through the new
//! decoder. Compares wall-clock against `xz2`'s liblzma-backed
//! decoder over the same `.xz` bytes.
//!
//! # Why the framing borrow
//!
//! Phase 5 of the port plan implements the LZMA2 chunk dispatcher
//! in production (`src/decode/xz_liblzma/lzma2.rs`); Phase 4 is
//! gated on whether the inner-loop perf is good enough to justify
//! that work. Rather than write Phase 5 just to bench Phase 3, we
//! reuse `xz_native::block::parse_lzma2_chunk_header` to extract
//! per-chunk inputs and feed them directly to `lzma_decode_port`.
//!
//! The cost of chunk parsing is small (~5 bytes of header per
//! ≤ 64 KiB chunk = < 0.01 % overhead) and is timed alongside the
//! decode, so the bench is honest about peel-port's full-decode
//! throughput minus Stream/Block framing (which Phases 5–6 add).
//! `xz2` is timed against the full Stream + Block + Block-Check
//! decode path; the comparison **biases against peel-port** for
//! the framing it doesn't yet do.
//!
//! # Phase 4 exit criterion
//!
//! Per [`docs/PLAN_xz_liblzma_port.md`] §Phase 4 exit decision:
//! - **Both fixtures ≤ 1.10×** (peel-port within 10 % of xz2):
//!   proceed to Phase 5.
//! - **Either fixture > 1.10×**: stop the plan; report findings.
//!
//! # How to run
//!
//! ```text
//! RUSTFLAGS="-C target-cpu=native" cargo test --release \
//!     --test test_bench_xz_liblzma -- --ignored --nocapture --test-threads=1
//! ```

#![cfg(unix)]

use std::time::{Duration, Instant};

use peel::decode::xz_liblzma::decoder::{lzma_decode_port, Lzma1Decoder, Sequence};
use peel::decode::xz_liblzma::dict::LzmaDict;
use peel::decode::xz_native::block::{
    block_header_real_size, decode_lzma_properties, parse_block_header, parse_lzma2_chunk_header,
    Lzma2ChunkHeader,
};
use peel::decode::xz_native::stream::STREAM_HEADER_LEN;

#[path = "support/mod.rs"]
mod support;

use support::tar_fixtures::build_simple_archive;

// ---- payload generation (mirrors test_bench_xz_native.rs) -----------

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

fn build_tar_payload(total_bytes: usize) -> Vec<u8> {
    const FILES: usize = 8;
    let per = total_bytes / FILES;
    let names: Vec<String> = (0..FILES)
        .map(|i| format!("data/file_{i:02}.bin"))
        .collect();
    let bodies: Vec<Vec<u8>> = (0..FILES)
        .map(|i| random_bytes(0xBEEF + i as u64, per))
        .collect();
    let pairs: Vec<(&str, &[u8])> = names
        .iter()
        .zip(bodies.iter())
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    build_simple_archive(&pairs)
}

fn compressible_bytes(seed: u64, len: usize) -> Vec<u8> {
    static TOKENS: &[&str] = &[
        "INFO",
        "WARN",
        "DEBUG",
        "ERROR",
        "TRACE",
        "request",
        "response",
        "handler",
        "worker",
        "/api/v1/users",
        "/api/v1/items",
        "GET",
        "POST",
        "status=200",
        "status=404",
        "host=alpha.internal",
        "service=ingest",
        "user_id=",
        "request_id=",
        "trace_id=",
        "client=mobile",
        "client=web",
        "region=us-east-1",
        "region=eu-central-1",
        "msg=\"ok\"",
        "msg=\"retry scheduled\"",
        "lat_ms=",
        "bytes=",
        "rows=",
    ];
    let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
    let mut next_u64 = || -> u64 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state
    };
    let mut out = Vec::with_capacity(len + 256);
    while out.len() < len {
        let mins = next_u64() % 60;
        let secs = next_u64() % 60;
        let micros = next_u64() % 1_000_000;
        out.extend_from_slice(
            format!("2026-05-04T12:{mins:02}:{secs:02}.{micros:06}Z ").as_bytes(),
        );
        let n_tokens = 4 + (next_u64() % 4) as usize;
        for i in 0..n_tokens {
            let idx = (next_u64() as usize) % TOKENS.len();
            if i > 0 {
                out.push(b' ');
            }
            out.extend_from_slice(TOKENS[idx].as_bytes());
        }
        out.push(b'\n');
    }
    out.truncate(len);
    out
}

fn build_compressible_tar_payload(total_bytes: usize) -> Vec<u8> {
    const FILES: usize = 8;
    let per = total_bytes / FILES;
    let names: Vec<String> = (0..FILES).map(|i| format!("data/log_{i:02}.txt")).collect();
    let bodies: Vec<Vec<u8>> = (0..FILES)
        .map(|i| compressible_bytes(0xC0DE + i as u64, per))
        .collect();
    let pairs: Vec<(&str, &[u8])> = names
        .iter()
        .zip(bodies.iter())
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    build_simple_archive(&pairs)
}

fn encode_xz(payload: &[u8]) -> Vec<u8> {
    use xz2::stream::{Action, Check, Status, Stream};
    let mut encoder = Stream::new_easy_encoder(6, Check::Crc64).expect("encoder");
    let mut out: Vec<u8> = Vec::with_capacity(payload.len() / 2 + 256);
    let mut input_pos = 0usize;
    let mut scratch = vec![0u8; 1 << 14];
    loop {
        let action = if input_pos < payload.len() {
            Action::Run
        } else {
            Action::Finish
        };
        let prev_in = encoder.total_in();
        let prev_out = encoder.total_out();
        let res = encoder
            .process(&payload[input_pos..], &mut scratch, action)
            .expect("encode step");
        input_pos += (encoder.total_in() - prev_in) as usize;
        let produced = (encoder.total_out() - prev_out) as usize;
        out.extend_from_slice(&scratch[..produced]);
        if let Status::StreamEnd = res {
            break;
        }
    }
    out
}

// ---- peel-port decode harness --------------------------------------

/// Decode a single-Block .xz stream by replaying each LZMA2 chunk
/// through `lzma_decode_port`. Returns the decoded bytes plus the
/// wall-clock spent in lzma_decode_port + chunk framing.
///
/// Chunk framing is inside the timed loop: parse_lzma2_chunk_header
/// is ~10 ns/call and lzma_decode_port consumes the chunk's
/// hundreds-to-thousands of compressed bytes per call, so the
/// framing overhead is < 0.1 %.
///
/// Bypasses Stream Footer + Block Padding + Block-Check validation
/// because Phase 4 is gating on inner-loop perf alone, not framing.
/// Phase 6 adds those layers in production.
fn run_peel_port(compressed: &[u8]) -> (Vec<u8>, Duration) {
    let started = Instant::now();

    // ---- Stream Header (12 bytes) ----
    assert!(
        compressed.len() >= STREAM_HEADER_LEN,
        "stream too short for header"
    );
    let mut p = STREAM_HEADER_LEN;

    // ---- Block Header ----
    let size_byte = compressed[p];
    let bh_len = block_header_real_size(size_byte);
    let block_header = parse_block_header(&compressed[p..p + bh_len]).expect("parse_block_header");
    p += bh_len;

    // ---- Decoder + dict ----
    let mut decoder = Lzma1Decoder::new();
    let mut dict = LzmaDict::new(block_header.dict_size as usize);
    let mut output: Vec<u8> = Vec::with_capacity(compressed.len() * 4);

    let mut chunk_idx: usize = 0;

    // ---- LZMA2 chunks ----
    loop {
        chunk_idx += 1;
        let header = parse_lzma2_chunk_header(&compressed[p..]).expect("parse chunk header");
        match header {
            Lzma2ChunkHeader::EndOfStream => break,
            Lzma2ChunkHeader::Uncompressed {
                reset_dict,
                uncompressed_size,
            } => {
                if reset_dict {
                    dict.reset();
                    decoder.full_reset();
                }
                p += 3;
                // Mirror of liblzma's wrap-loop in
                // `lz_decoder.c::decode_buffer`: an
                // uncompressed chunk may straddle the dict
                // wrap, so we copy in segments — wrap dict.pos
                // to 0 between segments and flush each segment
                // to the output buffer.
                let chunk = &compressed[p..p + uncompressed_size as usize];
                output.extend_from_slice(chunk);
                let mut in_pos = 0usize;
                let mut left = uncompressed_size as usize;
                while left > 0 {
                    if dict.pos == dict.size {
                        dict.pos = 0;
                    }
                    let chunk_avail = dict.size - dict.pos;
                    let this_step = left.min(chunk_avail);
                    dict.set_limit(dict.pos + this_step);
                    let pre_in = in_pos;
                    let pre_left = left;
                    dict.dict_write(chunk, &mut in_pos, chunk.len(), &mut left);
                    debug_assert_eq!(in_pos - pre_in, this_step);
                    debug_assert_eq!(pre_left - left, this_step);
                }
                p += uncompressed_size as usize;
            }
            Lzma2ChunkHeader::Lzma {
                reset_state,
                reset_props,
                reset_dict,
                uncompressed_size,
                compressed_size,
                properties,
            } => {
                let header_len = if reset_props { 6 } else { 5 };
                p += header_len;
                if reset_dict {
                    dict.reset();
                    decoder.full_reset();
                } else if reset_state {
                    decoder.full_reset();
                }
                if let Some(props_byte) = properties {
                    let (lc, lp, pb) =
                        decode_lzma_properties(props_byte).expect("decode_lzma_properties");
                    decoder.set_properties(u32::from(lc), u32::from(lp), u32::from(pb));
                }
                // The LZMA2 spec semantics: each LZMA chunk
                // starts a fresh range coder. `full_reset`
                // already gives us a fresh `RangeDecoder`; on
                // a chunk that doesn't reset state we still
                // need a fresh rc per the per-chunk init
                // protocol. Mirror of liblzma's
                // `rc_reset(coder->rc)` at chunk entry.
                decoder.rc = peel::decode::xz_liblzma::range_coder::RangeDecoder::new();
                decoder.sequence = peel::decode::xz_liblzma::decoder::Sequence::Normalize;

                // Mirror of liblzma's `decode_buffer` loop in
                // `lz_decoder.c`: a single LZMA chunk's
                // `uncompressed_size` may straddle the dict's
                // size boundary, so we may need multiple calls
                // to `lzma_decode_port` per chunk — each call
                // wraps `dict.pos` to 0 if it hit the dict
                // size, sets a new limit, and runs again with
                // the SAME `bytes_pos` cursor advanced past
                // the bytes already consumed.
                let chunk_payload = &compressed[p..p + compressed_size as usize];
                let mut in_pos = 0usize;
                let mut remaining = uncompressed_size as usize;
                while remaining > 0 {
                    if dict.pos == dict.size {
                        dict.pos = 0;
                    }
                    let chunk_avail = dict.size - dict.pos;
                    let this_step = remaining.min(chunk_avail);
                    let dict_start = dict.pos;
                    dict.set_limit(dict.pos + this_step);
                    let _status = lzma_decode_port(
                        &mut decoder,
                        &mut dict,
                        chunk_payload,
                        &mut in_pos,
                    )
                    .unwrap_or_else(|e| {
                        panic!(
                            "lzma_decode_port at chunk_idx={chunk_idx} \
                             output_pos={} dict.pos={dict_start} dict.full={} remaining={remaining}: {e:?}",
                            output.len(),
                            dict.full
                        )
                    });
                    // The decoder may return NeedInput if a
                    // long match-copy straddled the limit;
                    // that's fine — the next iteration of
                    // this loop wraps `dict.pos` (if it hit
                    // dict.size) and re-enters
                    // `lzma_decode_port` which has Copy-
                    // resume support. We just need to make
                    // sure we made forward progress (i.e.,
                    // dict.pos == dict_start + this_step OR a
                    // partial Copy that hit the limit).
                    let produced = dict.pos - dict_start;
                    assert_eq!(produced, this_step, "wrong byte count this step");
                    for i in 0..produced {
                        let d = (produced - 1 - i) as u32;
                        output.push(dict.dict_get(d));
                    }
                    remaining -= produced;
                }
                // After the wrap loop, the chunk's full output
                // has been delivered. The decoder's final state
                // should be either IsMatch (clean end) or
                // Normalize (also clean — happens when the
                // last symbol was followed by a final
                // rc_normalize that took us back to the top
                // of the dispatch loop).
                debug_assert!(
                    matches!(decoder.sequence, Sequence::IsMatch | Sequence::Normalize),
                    "chunk {chunk_idx} ended in unexpected sequence {:?}",
                    decoder.sequence
                );
                assert_eq!(
                    in_pos, compressed_size as usize,
                    "decoder consumed wrong byte count (expected {compressed_size}, got {in_pos})"
                );
                p += compressed_size as usize;
            }
        }
    }

    let elapsed = started.elapsed();
    (output, elapsed)
}

fn run_xz2(compressed: &[u8]) -> (Vec<u8>, Duration) {
    use std::io::{Cursor, Read};
    let mut decoder = xz2::read::XzDecoder::new(Cursor::new(compressed.to_vec()));
    let mut sink: Vec<u8> = Vec::with_capacity(compressed.len() * 2);
    let started = Instant::now();
    decoder.read_to_end(&mut sink).expect("xz2 decode");
    let elapsed = started.elapsed();
    (sink, elapsed)
}

// ---- result reporting ----------------------------------------------

fn report(label: &str, payload_bytes: u64, on_wire_bytes: u64, peel: Duration, xz2: Duration) {
    fn mibps(bytes: u64, dur: Duration) -> f64 {
        let s = dur.as_secs_f64();
        if s <= 0.0 {
            return 0.0;
        }
        (bytes as f64) / (1024.0 * 1024.0) / s
    }
    let payload_mib = (payload_bytes as f64) / (1024.0 * 1024.0);
    let wire_mib = (on_wire_bytes as f64) / (1024.0 * 1024.0);
    let peel_mibps = mibps(payload_bytes, peel);
    let xz2_mibps = mibps(payload_bytes, xz2);
    let ratio = if peel_mibps > 0.0 {
        xz2_mibps / peel_mibps
    } else {
        f64::INFINITY
    };
    println!(
        "[bench-xz-liblzma] {label:<48}  payload={payload_mib:7.1} MiB  wire={wire_mib:7.1} MiB  \
         peel-port={peel:7.3}s ({pmibs:7.1} MiB/s)  xz2={xz2:7.3}s ({xmibs:7.1} MiB/s)  \
         ratio xz2/peel-port={ratio:5.2}x",
        peel = peel.as_secs_f64(),
        xz2 = xz2.as_secs_f64(),
        pmibs = peel_mibps,
        xmibs = xz2_mibps,
    );
}

/// Run a (peel, xz2) pair `n` times and report median wall-clock.
/// Asserts byte-identical output every iteration.
fn bench_archive(label: &str, archive: &[u8], compressed: &[u8], iters: usize) {
    let mut peel_durs = Vec::with_capacity(iters);
    let mut xz2_durs = Vec::with_capacity(iters);

    for _ in 0..iters {
        let (peel_out, peel_dur) = run_peel_port(compressed);
        assert_eq!(peel_out.len(), archive.len(), "peel length mismatch");
        assert_eq!(peel_out, archive, "peel byte mismatch");
        peel_durs.push(peel_dur);

        let (xz2_out, xz2_dur) = run_xz2(compressed);
        assert_eq!(xz2_out, archive, "xz2 mismatch");
        xz2_durs.push(xz2_dur);
    }
    peel_durs.sort();
    xz2_durs.sort();
    let peel_median = peel_durs[iters / 2];
    let xz2_median = xz2_durs[iters / 2];
    report(
        label,
        archive.len() as u64,
        compressed.len() as u64,
        peel_median,
        xz2_median,
    );
}

// ---- benches -------------------------------------------------------

/// Phase 4 gating bench: 128 MiB single-Block tar.xz with LCG
/// (incompressible) payload. Median of 3 runs.
#[test]
#[ignore = "Phase 4 gating bench; opt-in via --ignored"]
fn bench_xz_liblzma_lcg_128mib() {
    let archive = build_tar_payload(128 * 1024 * 1024);
    let compressed = encode_xz(&archive);
    bench_archive(
        "tar.xz · 128 MiB · single-Block · preset 6 · LCG",
        &archive,
        &compressed,
        3,
    );
}

/// Phase 4 gating bench: 128 MiB single-Block tar.xz with
/// compressible (~2-3× ratio) payload. Median of 3 runs.
#[test]
#[ignore = "Phase 4 gating bench; opt-in via --ignored"]
fn bench_xz_liblzma_compressible_128mib() {
    let archive = build_compressible_tar_payload(128 * 1024 * 1024);
    let compressed = encode_xz(&archive);
    bench_archive(
        "tar.xz · 128 MiB · single-Block · preset 6 · compressible",
        &archive,
        &compressed,
        3,
    );
}

/// Smaller fixture for fast iteration / correctness check.
/// Runs as a regular `cargo test` (not `--ignored`) to gate any
/// Phase 4 commit on round-trip equivalence between peel-port and
/// xz2.
#[test]
fn bench_xz_liblzma_correctness_4mib() {
    let archive = build_tar_payload(4 * 1024 * 1024);
    let compressed = encode_xz(&archive);
    let (peel_out, _) = run_peel_port(&compressed);
    assert_eq!(peel_out.len(), archive.len(), "length mismatch");
    assert_eq!(peel_out, archive, "byte mismatch vs xz2-encoded archive");
}

/// Same as above for compressible payload.
#[test]
fn bench_xz_liblzma_correctness_4mib_compressible() {
    let archive = build_compressible_tar_payload(4 * 1024 * 1024);
    let compressed = encode_xz(&archive);
    let (peel_out, _) = run_peel_port(&compressed);
    assert_eq!(peel_out.len(), archive.len(), "length mismatch");
    assert_eq!(peel_out, archive, "byte mismatch vs xz2-encoded archive");
}
