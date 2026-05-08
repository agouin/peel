//! Phase 6 of [`docs/PLAN_xz_liblzma_port.md`](../docs/PLAN_xz_liblzma_port.md):
//! differential test suite for the public
//! [`peel::decode::xz_liblzma::Decoder`] type.
//!
//! Drives the new public decoder against `xz2`-encoded
//! fixtures and compares output byte-for-byte against both
//! `xz2` (liblzma) and the existing
//! [`peel::decode::xz_native::Decoder`].
//!
//! The .xz framing layers (Stream Header, Block Header,
//! Block-Check, Index, Stream Footer) are exercised here for
//! the first time on the public surface; the prior phases
//! tested only the LZMA2 chunk dispatcher in isolation.

#![cfg(unix)]

use std::io::{Cursor, Read};

use peel::decode::xz_liblzma::Decoder as XzLiblzmaDecoder;
use peel::decode::xz_native::Decoder as XzNativeDecoder;
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

fn decode_via_xz_native(compressed: &[u8]) -> Vec<u8> {
    let source = Cursor::new(compressed.to_vec());
    let mut decoder = XzNativeDecoder::new(Box::new(source)).expect("XzNativeDecoder::new");
    let mut sink: Vec<u8> = Vec::new();
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

/// Three-way differential gate: liblzma-port == xz_native == xz2 ==
/// original payload.
fn diff_check(payload: &[u8], preset: u32) {
    let compressed = encode_xz(payload, preset);
    let port = decode_via_liblzma_port(&compressed);
    let native = decode_via_xz_native(&compressed);
    let xz2 = decode_via_xz2(&compressed);
    assert_eq!(port.len(), payload.len(), "port length");
    assert_eq!(port, payload, "port != payload");
    assert_eq!(native, payload, "native != payload");
    assert_eq!(xz2, payload, "xz2 != payload");
    assert_eq!(port, native, "port != native");
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
        let native = decode_via_xz_native(&compressed);
        assert_eq!(port, payload, "preset {preset}: port != payload");
        assert_eq!(port, native, "preset {preset}: port != native");
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
        let native = decode_via_xz_native(&compressed);
        assert_eq!(port, payload, "check {label}: port != payload");
        assert_eq!(port, native, "check {label}: port != native");
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
    // No checkpoint blob in round-one.
    let mut blob = Vec::new();
    let needs_blob = decoder.decoder_state_into(&mut blob);
    assert!(!needs_blob, "Phase 6 round-one: no checkpoint blob");
    assert!(blob.is_empty());
}
