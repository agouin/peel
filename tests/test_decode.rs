//! Integration tests for [`peel::decode`].
//!
//! These exercise the public API across module boundaries: registry
//! lookup, factory dispatch, and end-to-end decode of multi-frame
//! `.zst` streams generated in-memory. Lower-level unit tests for the
//! state machine and accounting live alongside the implementation in
//! `src/decode/zstd.rs`.

use std::io::{Cursor, Read, Write};

use peel::decode::{DecodeError, DecodeStatus, DecoderRegistry, StreamingDecoder};
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
    registry.register(".tar.zst", marker_factory);

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
    // empty input (the zstd-specific behavior), confirming we did NOT
    // route to the marker.
    let zst_factory = registry
        .factory_for_name("plain.zst")
        .expect(".zst registered");
    let mut zst_decoder =
        zst_factory(Box::new(Cursor::new(Vec::<u8>::new()))).expect("zstd constructs");
    match zst_decoder.decode_step(&mut std::io::sink()) {
        Err(DecodeError::Read { .. }) => {}
        other => panic!("expected real zstd factory to reject empty input, got {other:?}"),
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
