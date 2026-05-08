//! Phase 6 of [`docs/PLAN_xz_liblzma_port.md`](../docs/PLAN_xz_liblzma_port.md):
//! differential test suite for the public
//! [`peel::decode::xz_liblzma::Decoder`] type. Phase F.6 retired
//! `xz_native` so the differential reference is now `xz2` only.
//!
//! Drives the new public decoder against `xz2`-encoded
//! fixtures and compares output byte-for-byte against `xz2`.
//!
//! The .xz framing layers (Stream Header, Block Header,
//! Block-Check, Index, Stream Footer) are exercised here on
//! the public surface; the lib's `decode::xz_liblzma::*` tests
//! cover the LZMA2 chunk dispatcher in isolation.

#![cfg(unix)]

use std::io::{Cursor, Read};

use peel::decode::xz_liblzma::Decoder as XzLiblzmaDecoder;
use peel::decode::{DecodeStatus, StreamingDecoder};

#[path = "support/mod.rs"]
mod support;

use support::tar_fixtures::build_simple_archive;

// ---- payload generators --------------------------------------------

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
    const FILES: usize = 4;
    let per = total_bytes / FILES;
    let names: Vec<String> = (0..FILES).map(|i| format!("data/file_{i}.bin")).collect();
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

fn compressible_payload(len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 256);
    let mut i = 0;
    while out.len() < len {
        out.extend_from_slice(
            format!(
                "2026-05-08T08:30:{i:02}.000Z INFO request handler /api/v1/users 200 ok\n",
                i = i % 60
            )
            .as_bytes(),
        );
        i += 1;
    }
    out.truncate(len);
    out
}

// ---- xz2 encoder ---------------------------------------------------

fn encode_xz(payload: &[u8], preset: u32) -> Vec<u8> {
    use xz2::stream::{Action, Check, Status, Stream};
    let mut encoder = Stream::new_easy_encoder(preset, Check::Crc64).expect("encoder");
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

fn encode_xz_check(payload: &[u8], preset: u32, check: xz2::stream::Check) -> Vec<u8> {
    use xz2::stream::{Action, Status, Stream};
    let mut encoder = Stream::new_easy_encoder(preset, check).expect("encoder");
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

// ---- decode harnesses ----------------------------------------------

fn decode_via_liblzma_port(compressed: &[u8]) -> Vec<u8> {
    let source = Cursor::new(compressed.to_vec());
    let mut decoder = XzLiblzmaDecoder::new(Box::new(source)).expect("XzLiblzmaDecoder::new");
    let mut sink: Vec<u8> = Vec::with_capacity(compressed.len() * 4);
    loop {
        match decoder.decode_step(&mut sink).expect("decode_step") {
            DecodeStatus::Eof => break,
            DecodeStatus::MoreData => {}
        }
    }
    sink
}

fn decode_via_xz2(compressed: &[u8]) -> Vec<u8> {
    let mut decoder = xz2::read::XzDecoder::new(Cursor::new(compressed.to_vec()));
    let mut sink: Vec<u8> = Vec::new();
    decoder.read_to_end(&mut sink).expect("xz2 decode");
    sink
}

/// Differential gate: liblzma-port == xz2 == original payload.
fn diff_check(payload: &[u8], preset: u32) {
    let compressed = encode_xz(payload, preset);
    let port = decode_via_liblzma_port(&compressed);
    let xz2 = decode_via_xz2(&compressed);
    assert_eq!(port.len(), payload.len(), "port length");
    assert_eq!(port, payload, "port != payload");
    assert_eq!(xz2, payload, "xz2 != payload");
    assert_eq!(port, xz2, "port != xz2");
}

// ---- tests --------------------------------------------------------

/// Tiny LCG: 64 bytes, single chunk, default preset (Crc64).
#[test]
fn round_trip_tiny_lcg() {
    let payload = random_bytes(0xC0FFEE, 64);
    diff_check(&payload, 6);
}

/// 4 KiB LCG: still single chunk, hits the rc init path
/// multiple times.
#[test]
fn round_trip_lcg_4kib() {
    let payload = random_bytes(0xBEEF, 4 * 1024);
    diff_check(&payload, 6);
}

/// 64 KiB LCG: spans multiple LZMA2 chunks (xz emits ~64 KiB
/// uncompressed-chunk maxes for incompressible data).
#[test]
fn round_trip_lcg_64kib() {
    let payload = random_bytes(0xCAFE, 64 * 1024);
    diff_check(&payload, 6);
}

/// 256 KiB LCG: multiple chunks, dict has begun filling.
#[test]
fn round_trip_lcg_256kib() {
    let payload = random_bytes(0xDEAD, 256 * 1024);
    diff_check(&payload, 6);
}

/// Compressible: ~256 KiB of structured logs, exercises the
/// match-heavy path.
#[test]
fn round_trip_compressible_256kib() {
    let payload = compressible_payload(256 * 1024);
    diff_check(&payload, 6);
}

/// Tar archive (mixed metadata + random content).
#[test]
fn round_trip_tar_payload() {
    let payload = build_tar_payload(128 * 1024);
    diff_check(&payload, 6);
}

/// Cross-preset round-trip: presets 1 / 3 / 6 / 9 differ in
/// dict_size (256 KiB / 4 MiB / 8 MiB / 64 MiB) and chunk
/// shape.
#[test]
fn round_trip_across_presets() {
    let payload = compressible_payload(64 * 1024);
    for preset in [1u32, 3, 6, 9] {
        let compressed = encode_xz(&payload, preset);
        let port = decode_via_liblzma_port(&compressed);
        let xz2_out = decode_via_xz2(&compressed);
        assert_eq!(port, payload, "preset {preset}: port != payload");
        assert_eq!(port, xz2_out, "preset {preset}: port != xz2");
    }
}

/// Cross-Check-ID round-trip: NONE / CRC32 / CRC64 / SHA256.
/// Phase 6's Block-Check verification path covers all four.
#[test]
fn round_trip_across_check_ids() {
    let payload = compressible_payload(8 * 1024);
    let cases: &[(xz2::stream::Check, &str)] = &[
        (xz2::stream::Check::None, "None"),
        (xz2::stream::Check::Crc32, "Crc32"),
        (xz2::stream::Check::Crc64, "Crc64"),
        (xz2::stream::Check::Sha256, "Sha256"),
    ];
    for &(check, label) in cases {
        let compressed = encode_xz_check(&payload, 6, check);
        let port = decode_via_liblzma_port(&compressed);
        let xz2_out = decode_via_xz2(&compressed);
        assert_eq!(port, payload, "check {label}: port != payload");
        assert_eq!(port, xz2_out, "check {label}: port != xz2");
    }
}

/// Empty payload: xz emits a 0-block stream.
#[test]
fn round_trip_empty_payload() {
    diff_check(&[], 6);
}

/// Single-byte payload — edge case for the Block Header's
/// uncompressed_size field encoding.
#[test]
fn round_trip_single_byte() {
    diff_check(&[0x42], 6);
}

// ===== Phase F.4 + F.5 checkpoint blob + resume =====

/// Capture `decoder_state_into` at every LZMA2 chunk boundary
/// inside a Block, resume from each via `xz_liblzma::resume`,
/// and verify the suffix is byte-identical to a clean run.
/// Round-trip gate for the F.4 blob format + F.5
/// resume_factory.
#[test]
fn resume_at_every_chunk_boundary_yields_identical_suffix() {
    // ~256 KiB of LCG-pseudo-random bytes forces multiple
    // LZMA2 chunks (compressed-size cap is 64 KiB; LCG
    // compresses ~1:1 so 256 KiB → ≥4 chunks).
    let input = random_bytes(0x00C0_FFEE_DEAD, 256 * 1024);
    let stream = encode_xz(&input, 6);

    // Clean reference run; collect (offset, blob, output_len)
    // snapshots wherever `decoder_state_into` returns true.
    let mut decoder =
        XzLiblzmaDecoder::new(Box::new(Cursor::new(stream.clone()))).expect("decoder");
    let mut out: Vec<u8> = Vec::new();
    let mut snapshots: Vec<(u64, Vec<u8>, usize)> = Vec::new();
    loop {
        let pre_len = out.len();
        let status = decoder.decode_step(&mut out).expect("decode_step");
        let mut blob = Vec::new();
        if decoder.decoder_state_into(&mut blob) {
            let offset = decoder.bytes_consumed().get();
            snapshots.push((offset, blob, out.len()));
            assert!(out.len() >= pre_len);
        }
        if status == DecodeStatus::Eof {
            break;
        }
    }
    let clean_output = out;
    assert_eq!(clean_output, input, "clean run output mismatch");
    assert!(
        snapshots.len() >= 2,
        "expected ≥ 2 chunk-boundary snapshots, got {}",
        snapshots.len()
    );

    // Resume from each snapshot.
    for (idx, (offset, blob, output_len)) in snapshots.iter().enumerate() {
        let suffix_src: Vec<u8> = stream[*offset as usize..].to_vec();
        let mut resumed = peel::decode::xz_liblzma::Decoder::resume(
            blob,
            Box::new(Cursor::new(suffix_src)),
            *offset,
        )
        .expect("resume");
        let mut suffix_out = Vec::new();
        loop {
            match resumed.decode_step(&mut suffix_out).expect("resumed step") {
                DecodeStatus::Eof => break,
                DecodeStatus::MoreData => continue,
            }
        }
        assert_eq!(
            suffix_out,
            &clean_output[*output_len..],
            "snapshot {idx} (offset={offset}, output_len={output_len}) suffix mismatch"
        );
    }
}

/// `frame_boundary` advances per-LZMA2-chunk inside a Block
/// (so the coordinator's checkpoint cadence fires at every
/// resumable point), in addition to the Stream-end boundary.
#[test]
fn frame_boundary_advances_per_chunk_inside_block() {
    let input = random_bytes(0x1234_5678, 256 * 1024);
    let stream = encode_xz(&input, 6);
    let mut decoder = XzLiblzmaDecoder::new(Box::new(Cursor::new(stream))).expect("decoder");
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
    assert!(
        boundaries.len() >= 3,
        "expected at least 3 frame_boundary advances (≥2 chunk + 1 Stream-end), got {boundaries:?}"
    );
    for w in boundaries.windows(2) {
        assert!(w[0] < w[1], "boundaries regressed: {w:?}");
    }
}

// ===== Phase F.3 multi-Block + multi-Stream =====

/// Encode `payload` via `xz -T2`-equivalent: split into N
/// pieces, encode each as its own .xz Stream via xz2, then
/// concatenate. Each Stream is single-Block, but the resulting
/// bytes match what `xz` produces when threading is enabled
/// (multiple Blocks in xz's threaded encoder are stored as
/// concatenated single-Block Streams in the same file —
/// equivalent to a multi-Stream file from a decoder's view).
fn encode_multi_stream(payload: &[u8], preset: u32, n_streams: usize) -> Vec<u8> {
    assert!(n_streams >= 1);
    let chunk_size = payload.len().div_ceil(n_streams).max(1);
    let mut out = Vec::with_capacity(payload.len() + 256);
    for piece in payload.chunks(chunk_size) {
        let one = encode_xz(piece, preset);
        out.extend_from_slice(&one);
    }
    out
}

/// Multi-Stream: `cat a.xz b.xz > c.xz`-style concatenated
/// streams. The decoder must walk past one Stream Footer and
/// resume at the next Stream Header.
#[test]
fn round_trip_multi_stream_two_streams() {
    let payload = compressible_payload(64 * 1024);
    let compressed = encode_multi_stream(&payload, 6, 2);
    let port = decode_via_liblzma_port(&compressed);
    assert_eq!(port, payload, "two-Stream concatenation round-trip failed");
}

/// Three concatenated Streams of mixed compressible content.
/// Differential reference: xz2's `Stream::new_stream_decoder`
/// in `Concatenated` mode (the bare `XzDecoder` rejects
/// multi-stream input by default).
#[test]
fn round_trip_multi_stream_three_streams_compressible() {
    let payload = compressible_payload(48 * 1024);
    let compressed = encode_multi_stream(&payload, 6, 3);
    let port = decode_via_liblzma_port(&compressed);
    let xz2 = decode_via_xz2_multi_stream(&compressed);
    assert_eq!(port, payload);
    assert_eq!(port, xz2);
}

/// Multi-stream xz2 reference. The default `XzDecoder` only
/// accepts single-stream input; for concatenated streams we
/// need an explicit `Stream::new_stream_decoder` with the
/// `CONCATENATED` flag.
fn decode_via_xz2_multi_stream(compressed: &[u8]) -> Vec<u8> {
    use xz2::stream::{Action, Status, Stream};
    let mut decoder =
        Stream::new_stream_decoder(u64::MAX, xz2::stream::CONCATENATED).expect("xz2 multi-decoder");
    let mut sink: Vec<u8> = Vec::with_capacity(compressed.len() * 4);
    let mut input_pos = 0usize;
    let mut scratch = vec![0u8; 1 << 14];
    loop {
        let action = if input_pos < compressed.len() {
            Action::Run
        } else {
            Action::Finish
        };
        let prev_in = decoder.total_in();
        let prev_out = decoder.total_out();
        let res = decoder
            .process(&compressed[input_pos..], &mut scratch, action)
            .expect("decode step");
        input_pos += (decoder.total_in() - prev_in) as usize;
        let produced = (decoder.total_out() - prev_out) as usize;
        sink.extend_from_slice(&scratch[..produced]);
        if let Status::StreamEnd = res {
            break;
        }
    }
    sink
}

/// True multi-Block (single Stream): produced by the system
/// `xz -T2` (multi-threaded encoder emits multiple Blocks per
/// Stream). Skipped if `xz` binary not present in PATH.
#[test]
fn round_trip_xz_multithread_multi_block() {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let xz_path = "/opt/homebrew/bin/xz";
    if !std::path::Path::new(xz_path).exists() {
        // Different platform layout; skip cleanly.
        eprintln!("system xz not at /opt/homebrew/bin/xz; skipping");
        return;
    }

    // Generate ~2 MiB of mixed compressible content; -T2
    // splits this across multiple Blocks (one per worker).
    let mut payload = Vec::with_capacity(2 * 1024 * 1024);
    for i in 0..50_000 {
        payload.extend_from_slice(format!("entry {i:08}: status=ok action=ingest\n").as_bytes());
    }

    let mut child = Command::new(xz_path)
        .args(["-c", "-T2", "-6"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn xz");
    child
        .stdin
        .as_mut()
        .expect("xz stdin")
        .write_all(&payload)
        .expect("write payload");
    let out = child.wait_with_output().expect("xz wait");
    assert!(out.status.success(), "xz failed: {:?}", out.stderr);
    let compressed = out.stdout;

    let port = decode_via_liblzma_port(&compressed);
    assert_eq!(port.len(), payload.len(), "decoded length");
    assert_eq!(port, payload, "decoded bytes != payload");
}

/// Multi-Stream LCG (incompressible) — exercises uncompressed
/// chunks across stream boundaries. Source delivers bytes in
/// 13-byte chunks (prime so reads land mid-stream-header).
#[test]
fn round_trip_multi_stream_lcg_streamed() {
    let payload = random_bytes(0x00C0_FFEE_DEAD, 32 * 1024);
    let compressed = encode_multi_stream(&payload, 6, 4);
    let source = ChunkedReader {
        bytes: compressed.clone(),
        pos: 0,
        chunk_size: 13,
    };
    let mut decoder = XzLiblzmaDecoder::new(Box::new(source)).expect("decoder");
    let mut sink: Vec<u8> = Vec::new();
    loop {
        match decoder.decode_step(&mut sink).expect("decode_step") {
            DecodeStatus::Eof => break,
            DecodeStatus::MoreData => {}
        }
    }
    assert_eq!(sink, payload);
}

// ===== Phase F.2 streaming: source delivers bytes incrementally =====

/// `Read` adapter that delivers `chunk_size` bytes per `read`
/// call. Lets the decode_step loop exercise its incremental
/// state machine across many call/read cycles.
struct ChunkedReader {
    bytes: Vec<u8>,
    pos: usize,
    chunk_size: usize,
}

impl Read for ChunkedReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.bytes.len() {
            return Ok(0);
        }
        let take = self
            .chunk_size
            .min(buf.len())
            .min(self.bytes.len() - self.pos);
        buf[..take].copy_from_slice(&self.bytes[self.pos..self.pos + take]);
        self.pos += take;
        Ok(take)
    }
}

/// Streaming round-trip: source delivers 1 byte per read.
/// Forces the maximum number of decode_step / NeedInput
/// cycles. Output must still be byte-identical to the bulk
/// path.
#[test]
fn streaming_one_byte_at_a_time_compressible() {
    let payload = compressible_payload(8 * 1024);
    let compressed = encode_xz(&payload, 6);
    let source = ChunkedReader {
        bytes: compressed.clone(),
        pos: 0,
        chunk_size: 1,
    };
    let mut decoder = XzLiblzmaDecoder::new(Box::new(source)).expect("decoder");
    let mut sink: Vec<u8> = Vec::new();
    loop {
        match decoder.decode_step(&mut sink).expect("decode_step") {
            DecodeStatus::Eof => break,
            DecodeStatus::MoreData => {}
        }
    }
    assert_eq!(sink, payload);
    assert_eq!(decoder.bytes_consumed().get(), compressed.len() as u64);
}

/// Streaming round-trip on incompressible 256 KiB LCG; 17-byte
/// chunks (a prime so reads land mid-header / mid-payload at
/// arbitrary offsets).
#[test]
fn streaming_prime_chunks_lcg_256kib() {
    let payload = random_bytes(0x00C0_FFEE_DEAD, 256 * 1024);
    let compressed = encode_xz(&payload, 6);
    let source = ChunkedReader {
        bytes: compressed.clone(),
        pos: 0,
        chunk_size: 17,
    };
    let mut decoder = XzLiblzmaDecoder::new(Box::new(source)).expect("decoder");
    let mut sink: Vec<u8> = Vec::new();
    loop {
        match decoder.decode_step(&mut sink).expect("decode_step") {
            DecodeStatus::Eof => break,
            DecodeStatus::MoreData => {}
        }
    }
    assert_eq!(sink, payload);
}

/// Streaming round-trip across presets — different chunk shapes
/// in the LZMA2 stream, all decoded byte-by-byte from source.
#[test]
fn streaming_one_byte_at_a_time_across_presets() {
    let mut payload = Vec::new();
    for i in 0..400 {
        payload.extend_from_slice(format!("row {i:05} | data | value\n").as_bytes());
    }
    for preset in [1u32, 3, 6, 9] {
        let compressed = encode_xz(&payload, preset);
        let source = ChunkedReader {
            bytes: compressed.clone(),
            pos: 0,
            chunk_size: 1,
        };
        let mut decoder = XzLiblzmaDecoder::new(Box::new(source)).expect("decoder");
        let mut sink: Vec<u8> = Vec::new();
        loop {
            match decoder.decode_step(&mut sink).expect("decode_step") {
                DecodeStatus::Eof => break,
                DecodeStatus::MoreData => {}
            }
        }
        assert_eq!(sink, payload, "preset {preset} streaming round-trip failed");
    }
}

/// Decoder consistency: bytes_consumed advances to the source
/// length, frame_boundary reports it after Eof.
#[test]
fn decoder_state_after_eof() {
    let payload = compressible_payload(8 * 1024);
    let compressed = encode_xz(&payload, 6);
    let source = Cursor::new(compressed.clone());
    let mut decoder = XzLiblzmaDecoder::new(Box::new(source)).expect("decoder");
    let mut sink: Vec<u8> = Vec::new();
    loop {
        match decoder.decode_step(&mut sink).expect("decode_step") {
            DecodeStatus::Eof => break,
            DecodeStatus::MoreData => {}
        }
    }
    assert_eq!(sink, payload);
    let consumed = decoder.bytes_consumed().get();
    assert_eq!(consumed, compressed.len() as u64);
    let fb = decoder.frame_boundary().expect("frame_boundary");
    assert_eq!(fb.get(), compressed.len() as u64);
    // After Eof, no checkpoint blob — the decoder is in
    // `Done` state, not `InBlock`, so `decoder_state_into`
    // returns false. (Mid-Block snapshots are exercised by
    // `resume_at_every_chunk_boundary_yields_identical_suffix`.)
    let mut blob = Vec::new();
    let needs_blob = decoder.decoder_state_into(&mut blob);
    assert!(!needs_blob, "decoder_state_into at Eof should return false");
    assert!(blob.is_empty());
}
