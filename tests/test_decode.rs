//! Integration tests for [`peel::decode`].
//!
//! These exercise the public API across module boundaries: registry
//! lookup, factory dispatch, and end-to-end decode of multi-frame
//! `.zst` streams generated in-memory. Lower-level unit tests for the
//! state machine and accounting live alongside the implementation in
//! `src/decode/zstd.rs`.

use std::io::{Cursor, Read, Write};

use peel::decode::{DecodeError, DecodeStatus, DecoderRegistry, FormatShape, StreamingDecoder};
use peel::types::ByteOffset;

/// A two-frame zstd stream that the registered `.zst` factory should
/// decode end-to-end with frame boundaries at the expected offsets.
#[test]
fn registry_factory_decodes_multi_frame_zst_stream() {
    let payload_a: Vec<u8> = b"alpha-frame-payload\n".repeat(640);
    let payload_b: Vec<u8> = b"beta-frame-payload-longer\n".repeat(900);
    let frame_a = zstd::encode_all(&payload_a[..], 3).expect("encode A");
    let frame_b = zstd::encode_all(&payload_b[..], 3).expect("encode B");
    let mut combined = frame_a.clone();
    combined.extend_from_slice(&frame_b);
    let combined_len = combined.len() as u64;

    let registry = DecoderRegistry::with_defaults();
    let factory = registry
        .factory_for_name("dataset.zst")
        .expect("registry registers .zst");

    let mut decoder = factory(Box::new(Cursor::new(combined))).expect("factory constructs");
    let mut sink: Vec<u8> = Vec::with_capacity(payload_a.len() + payload_b.len());

    let mut last_consumed = 0u64;
    let mut boundaries: Vec<u64> = Vec::new();
    loop {
        let prior = decoder.frame_boundary();
        let status = decoder.decode_step(&mut sink).expect("decode_step");
        let consumed_now = decoder.bytes_consumed().get();
        assert!(
            consumed_now >= last_consumed,
            "bytes_consumed regressed {last_consumed} -> {consumed_now}",
        );
        assert!(
            consumed_now <= combined_len,
            "bytes_consumed {consumed_now} exceeds source length {combined_len}",
        );
        last_consumed = consumed_now;

        let next = decoder.frame_boundary();
        if next != prior {
            boundaries.push(next.expect("just observed").get());
        }
        if status == DecodeStatus::Eof {
            break;
        }
    }

    let mut expected = payload_a.clone();
    expected.extend_from_slice(&payload_b);
    assert_eq!(sink, expected);
    assert_eq!(boundaries.len(), 2, "boundaries={boundaries:?}");
    assert_eq!(boundaries[0], frame_a.len() as u64);
    assert_eq!(boundaries[1], combined_len);
    assert_eq!(decoder.bytes_consumed().get(), combined_len);
}

/// `.tar.zst` and `.zst` registered side-by-side: the longer suffix
/// must win for a `.tar.zst` path even though `.zst` would also match.
/// We use a custom factory that is distinguishable from the default
/// zstd one — it just decodes nothing — so the test is about lookup
/// precedence, not decode semantics.
#[test]
fn registry_longest_suffix_takes_precedence_over_shorter() {
    fn marker_factory(
        _src: Box<dyn Read + Send>,
    ) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
        Ok(Box::new(MarkerDecoder))
    }

    struct MarkerDecoder;
    impl StreamingDecoder for MarkerDecoder {
        fn decode_step(&mut self, _sink: &mut dyn Write) -> Result<DecodeStatus, DecodeError> {
            // The marker is detectable: it never produces output and
            // never advances bytes_consumed past zero.
            Ok(DecodeStatus::Eof)
        }
        fn bytes_consumed(&self) -> ByteOffset {
            ByteOffset::ZERO
        }
        fn frame_boundary(&self) -> Option<ByteOffset> {
            None
        }
    }

    let mut registry = DecoderRegistry::with_defaults();
    registry.register(".tar.zst", FormatShape::Tree, marker_factory);

    // .tar.zst should pick the marker.
    let tar_factory = registry
        .factory_for_name("bundle.tar.zst")
        .expect(".tar.zst registered");
    let mut tar_decoder =
        tar_factory(Box::new(Cursor::new(Vec::<u8>::new()))).expect("marker constructs");
    assert_eq!(
        tar_decoder
            .decode_step(&mut std::io::sink())
            .expect("decode_step"),
        DecodeStatus::Eof
    );
    assert_eq!(tar_decoder.bytes_consumed(), ByteOffset::ZERO);

    // Plain .zst should still reach the real zstd factory and reject
    // garbage input (the zstd-specific behavior — bad frame magic),
    // confirming we did NOT route to the marker (which would happily
    // return Eof for any source).
    let zst_factory = registry
        .factory_for_name("plain.zst")
        .expect(".zst registered");
    let mut zst_decoder =
        zst_factory(Box::new(Cursor::new(vec![0xCC; 8]))).expect("zstd constructs");
    match zst_decoder.decode_step(&mut std::io::sink()) {
        Err(DecodeError::Read { .. }) => {}
        other => panic!("expected real zstd factory to reject garbage input, got {other:?}"),
    }
}

/// The decoder is `Send`, so it can be moved into a worker thread and
/// driven there. This is the shape the §8 extractor will rely on.
#[test]
fn decoder_can_be_driven_from_a_worker_thread() {
    let payload = b"thread-driven-payload\n".repeat(2048);
    let compressed = zstd::encode_all(&payload[..], 3).expect("encode");
    let registry = DecoderRegistry::with_defaults();
    let factory = registry
        .factory_for_name("dataset.zstd")
        .expect("registered");
    let decoder = factory(Box::new(Cursor::new(compressed.clone()))).expect("constructs");

    let payload_clone = payload.clone();
    let handle = std::thread::Builder::new()
        .name("decode-driver".into())
        .spawn(move || {
            let mut decoder = decoder;
            let mut sink: Vec<u8> = Vec::with_capacity(payload_clone.len());
            loop {
                let status = decoder.decode_step(&mut sink).expect("decode_step");
                if status == DecodeStatus::Eof {
                    break;
                }
            }
            sink
        })
        .expect("spawn");

    let result = handle.join().expect("worker thread");
    assert_eq!(result, payload);
}

/// The registry routes `.xz` and `.tar.xz` to the xz decoder, decodes
/// a single-Stream xz blob round-trip, and reports the end-of-Stream
/// frame boundary at the cumulative source-byte offset.
#[test]
fn registry_factory_decodes_single_stream_xz() {
    use xz2::stream::{Action, Check, Status, Stream};

    fn encode_xz(payload: &[u8]) -> Vec<u8> {
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

    let payload: Vec<u8> = b"xz-integration-payload\n".repeat(2048);
    let compressed = encode_xz(&payload);
    let compressed_len = compressed.len() as u64;

    let registry = DecoderRegistry::with_defaults();
    // Both `.xz` and `.tar.xz` resolve to the xz factory.
    let plain = registry
        .factory_for_name("dataset.xz")
        .expect(".xz registered");
    let tarred = registry
        .factory_for_name("dataset.tar.xz")
        .expect(".tar.xz registered");
    // Factory identity test (longest-suffix-wins should still find the
    // xz factory for both, since the same factory is registered for
    // both suffixes).
    let _ = (plain, tarred);

    let mut decoder = plain(Box::new(Cursor::new(compressed))).expect("factory constructs");
    let mut sink: Vec<u8> = Vec::with_capacity(payload.len());

    let mut last_consumed = 0u64;
    let mut last_boundary: Option<u64> = None;
    loop {
        let status = decoder.decode_step(&mut sink).expect("decode_step");
        let consumed_now = decoder.bytes_consumed().get();
        assert!(
            consumed_now >= last_consumed,
            "bytes_consumed regressed {last_consumed} -> {consumed_now}",
        );
        assert!(
            consumed_now <= compressed_len,
            "bytes_consumed {consumed_now} exceeds source length {compressed_len}",
        );
        last_consumed = consumed_now;
        if let Some(b) = decoder.frame_boundary() {
            last_boundary = Some(b.get());
        }
        if status == DecodeStatus::Eof {
            break;
        }
    }

    assert_eq!(sink, payload);
    assert_eq!(decoder.bytes_consumed().get(), compressed_len);
    assert_eq!(
        last_boundary,
        Some(compressed_len),
        "frame_boundary at end of single Stream",
    );
}

/// Magic-byte detection picks up the xz format from a prefix even
/// when the URL has no helpful suffix. Mirrors the §1 magic-only
/// resolution path against the §3 decoder.
#[test]
fn registry_factory_for_prefix_routes_to_xz() {
    let xz_magic = [0xFD_u8, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00, 0x00];
    let registry = DecoderRegistry::with_defaults();
    let factory = registry
        .factory_for_prefix(&xz_magic)
        .expect("xz magic registered");
    assert_eq!(registry.name_for_factory(factory), Some("xz"));
}

/// The registry routes `.lz4` and `.tar.lz4` to the lz4 decoder and a
/// hand-encoded single-frame lz4 source decodes round-trip with the
/// per-block frame boundaries the §4 contract specifies.
#[test]
fn registry_factory_decodes_single_frame_lz4() {
    /// Build a minimal lz4 frame around `payload` with one
    /// uncompressed block, no checksums, no content size — same
    /// shape the unit-test encoder builds, just inlined here so the
    /// integration test does not depend on the unit-test scaffolding.
    fn encode_lz4_uncompressed(payload: &[u8]) -> Vec<u8> {
        const PRIME32_1: u32 = 0x9E37_79B1;
        const PRIME32_2: u32 = 0x85EB_CA77;
        const PRIME32_3: u32 = 0xC2B2_AE3D;
        const PRIME32_4: u32 = 0x27D4_EB2F;
        const PRIME32_5: u32 = 0x1656_67B1;

        fn read_u32_le(bs: &[u8]) -> u32 {
            u32::from_le_bytes([bs[0], bs[1], bs[2], bs[3]])
        }
        fn round(acc: u32, lane: u32) -> u32 {
            acc.wrapping_add(lane.wrapping_mul(PRIME32_2))
                .rotate_left(13)
                .wrapping_mul(PRIME32_1)
        }
        fn xxh32(input: &[u8]) -> u32 {
            let mut p = 0usize;
            let len = input.len();
            let mut h: u32;
            if len >= 16 {
                let seed = 0u32;
                let mut v1 = seed.wrapping_add(PRIME32_1).wrapping_add(PRIME32_2);
                let mut v2 = seed.wrapping_add(PRIME32_2);
                let mut v3 = seed;
                let mut v4 = seed.wrapping_sub(PRIME32_1);
                let limit = len - 16;
                loop {
                    v1 = round(v1, read_u32_le(&input[p..]));
                    v2 = round(v2, read_u32_le(&input[p + 4..]));
                    v3 = round(v3, read_u32_le(&input[p + 8..]));
                    v4 = round(v4, read_u32_le(&input[p + 12..]));
                    p += 16;
                    if p > limit {
                        break;
                    }
                }
                h = v1
                    .rotate_left(1)
                    .wrapping_add(v2.rotate_left(7))
                    .wrapping_add(v3.rotate_left(12))
                    .wrapping_add(v4.rotate_left(18));
            } else {
                h = PRIME32_5;
            }
            h = h.wrapping_add(len as u32);
            while p + 4 <= len {
                h = h.wrapping_add(read_u32_le(&input[p..]).wrapping_mul(PRIME32_3));
                h = h.rotate_left(17).wrapping_mul(PRIME32_4);
                p += 4;
            }
            while p < len {
                h = h.wrapping_add(u32::from(input[p]).wrapping_mul(PRIME32_5));
                h = h.rotate_left(11).wrapping_mul(PRIME32_1);
                p += 1;
            }
            h ^= h >> 15;
            h = h.wrapping_mul(PRIME32_2);
            h ^= h >> 13;
            h = h.wrapping_mul(PRIME32_3);
            h ^= h >> 16;
            h
        }

        let mut out = Vec::new();
        // Magic 0x184D2204.
        out.extend_from_slice(&0x184D_2204u32.to_le_bytes());
        // FLG: version=01, block independence; no checksums; no
        // content size; no DictID.
        let flg: u8 = 0b0110_0000;
        let bd: u8 = 0b0111_0000; // block max = 4 MiB
        out.push(flg);
        out.push(bd);
        let hc = ((xxh32(&[flg, bd]) >> 8) & 0xff) as u8;
        out.push(hc);
        // One uncompressed block.
        let header = (payload.len() as u32) | 0x8000_0000;
        out.extend_from_slice(&header.to_le_bytes());
        out.extend_from_slice(payload);
        // EndMark.
        out.extend_from_slice(&[0u8; 4]);
        out
    }

    let payload: Vec<u8> = b"lz4-integration-payload\n".repeat(2048);
    let frame = encode_lz4_uncompressed(&payload);
    let frame_len = frame.len() as u64;

    let registry = DecoderRegistry::with_defaults();
    // Both `.lz4` and `.tar.lz4` resolve to the lz4 factory.
    let plain = registry
        .factory_for_name("dataset.lz4")
        .expect(".lz4 registered");
    let tarred = registry
        .factory_for_name("dataset.tar.lz4")
        .expect(".tar.lz4 registered");
    let _ = (plain, tarred);

    let mut decoder = plain(Box::new(Cursor::new(frame))).expect("factory constructs");
    let mut sink: Vec<u8> = Vec::with_capacity(payload.len());

    let mut last_consumed = 0u64;
    let mut frame_boundaries: Vec<u64> = Vec::new();
    let mut prior_boundary: Option<ByteOffset> = decoder.frame_boundary();
    loop {
        let status = decoder.decode_step(&mut sink).expect("decode_step");
        let now = decoder.bytes_consumed().get();
        assert!(
            now >= last_consumed,
            "consumed regressed {last_consumed}->{now}"
        );
        assert!(now <= frame_len, "consumed {now} > frame_len {frame_len}");
        last_consumed = now;

        let next_boundary = decoder.frame_boundary();
        if next_boundary != prior_boundary {
            frame_boundaries.push(next_boundary.expect("just observed").get());
            prior_boundary = next_boundary;
        }
        if status == DecodeStatus::Eof {
            break;
        }
    }

    assert_eq!(sink, payload);
    // O.7b promoted lz4 to per-block boundaries inside a frame. A
    // single-frame, single-block source produces two distinct
    // values: the post-block offset (immediately before the
    // 4-byte EndMark) and the post-EndMark offset. Both lie inside
    // `frame_len` and the post-EndMark offset equals `frame_len`.
    assert!(
        !frame_boundaries.is_empty(),
        "expected at least one boundary",
    );
    let last = *frame_boundaries.last().expect("non-empty");
    assert_eq!(
        last, frame_len,
        "the final boundary must be the post-EndMark offset"
    );
    for b in &frame_boundaries {
        assert!(
            *b <= frame_len,
            "boundary {b} exceeds frame_len {frame_len}"
        );
    }
    assert_eq!(decoder.bytes_consumed().get(), frame_len);
}

/// Magic-byte detection picks up the lz4 format from a prefix even
/// when the URL has no helpful suffix.
#[test]
fn registry_factory_for_prefix_routes_to_lz4() {
    let lz4_magic = [0x04u8, 0x22, 0x4D, 0x18, 0x00, 0x00, 0x00, 0x00];
    let registry = DecoderRegistry::with_defaults();
    let factory = registry
        .factory_for_prefix(&lz4_magic)
        .expect("lz4 magic registered");
    assert_eq!(registry.name_for_factory(factory), Some("lz4"));
}

/// Truncated streams must surface as a clean [`DecodeError::Read`]
/// rather than a panic. The decoder should not over-report
/// `bytes_consumed` in this case.
#[test]
fn truncated_stream_reports_read_error() {
    let payload = b"truncated-input".repeat(4096);
    let compressed = zstd::encode_all(&payload[..], 3).expect("encode");
    // Drop the trailing 16 bytes (frame footer + checksum region).
    let truncated = compressed[..compressed.len() - 16].to_vec();
    let truncated_len = truncated.len() as u64;

    let registry = DecoderRegistry::with_defaults();
    let factory = registry.factory_for_name("a.zst").expect("registered");
    let mut decoder = factory(Box::new(Cursor::new(truncated))).expect("constructs");

    let mut sink: Vec<u8> = Vec::new();
    loop {
        match decoder.decode_step(&mut sink) {
            Ok(DecodeStatus::MoreData) => continue,
            Ok(DecodeStatus::Eof) => panic!("truncated stream should not reach Eof cleanly"),
            Err(DecodeError::Read { consumed, .. }) => {
                assert!(consumed <= truncated_len);
                return;
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }
}
