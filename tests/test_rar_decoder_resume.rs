//! `PLAN_rar5_decoder.md` §F1 — mid-entry decoder snapshot
//! round-trip.
//!
//! Drives [`peel::decode::rar_native::RarStreamDecoder`] partway
//! through the compressed bytes from
//! [`tests/fixtures/rar5/testfile.rar5.solid.rar`] (a 97-byte
//! single-entry RAR5 method-5 archive whose payload is
//! `Testing 123\n`), captures a snapshot, then constructs a
//! fresh decoder via [`RarStreamDecoder::resume`] seeded with the
//! captured state and the source bytes from the saved cursor
//! onward. The two decoded outputs concatenated must equal the
//! reference clean-decode output — the §F1 byte-identity
//! contract.
//!
//! These tests live as integration tests rather than unit tests
//! so the fixture file (CC0, ~100 B) can stay alongside the
//! per-format `tests/fixtures/rar5/` directory and not bleed
//! into `src/`'s test binaries.

#![cfg(feature = "rar")]

use std::io::Cursor;

use peel::decode::rar_native::dict::MAX_DICT_BYTES;
use peel::decode::rar_native::RarStreamDecoder;
use peel::decode::{DecodeStatus, StreamingDecoder};

/// Compressed-bitstream slice for the single entry in the
/// `testfile.rar5.solid.rar` fixture: starts at archive offset
/// 0x3E (`data_offset = 62`) and runs for the file header's
/// `packed_size = 27` bytes.
const FIXTURE: &[u8] = include_bytes!("fixtures/rar5/testfile.rar5.solid.rar");
const FIXTURE_DATA_OFFSET: usize = 62;
const FIXTURE_PACKED_SIZE: usize = 27;
const FIXTURE_UNPACKED: &[u8] = b"Testing 123\n";
/// Dictionary size from the file header's `dict_size_selector =
/// 3`: `128 KiB << 3 = 1 MiB`.
const FIXTURE_DICT_CAPACITY: usize = 1024 * 1024;

/// Multi-block regression fixture. See
/// `tests/fixtures/rar5/README.md` and
/// `docs/PLAN_rar5_multi_block_decode.md` for the open gap this
/// pins.
const MB_FIXTURE: &[u8] = include_bytes!("fixtures/rar5/multi_block_p27.rar");
const MB_DATA_OFFSET: usize = 70;
const MB_PACKED_SIZE: usize = 2841;
/// Dict size from the entry header (selector = 8 → 128 KiB << 8 =
/// 32 MiB). Pulled from the `rar_list` example's reading of the
/// fixture.
const MB_DICT_CAPACITY: usize = 32 * 1024 * 1024;

fn fixture_bitstream() -> &'static [u8] {
    &FIXTURE[FIXTURE_DATA_OFFSET..FIXTURE_DATA_OFFSET + FIXTURE_PACKED_SIZE]
}

fn fresh_decoder() -> RarStreamDecoder {
    let src: Box<dyn std::io::Read + Send> = Box::new(Cursor::new(fixture_bitstream().to_vec()));
    RarStreamDecoder::new(src, FIXTURE_DICT_CAPACITY).expect("construct fresh decoder")
}

/// Drive `decoder` until clean EOF, accumulating decoded bytes
/// into `out`. Returns the number of `decode_step` calls. Stops
/// after `step_cap` to keep a buggy decoder from spinning.
fn drain_until_eof(decoder: &mut RarStreamDecoder, out: &mut Vec<u8>) -> u32 {
    for steps in 1..=1024 {
        let status = decoder.decode_step(out).expect("decode_step");
        if matches!(status, DecodeStatus::Eof) {
            return steps;
        }
    }
    panic!("decoder did not reach Eof in 1024 steps");
}

/// Sanity: a fresh decoder reproduces the reference payload from
/// the fixture. Pins the round-one §E1 contract before §F1's
/// snapshot path is exercised.
#[test]
fn fresh_decode_matches_reference_payload() {
    let mut dec = fresh_decoder();
    let mut out = Vec::new();
    drain_until_eof(&mut dec, &mut out);
    assert_eq!(
        out, FIXTURE_UNPACKED,
        "fresh decode must match the reference payload"
    );
}

/// §F1 round-trip at every captured snapshot point: take a
/// snapshot, build a resumed decoder, finish decoding, and
/// verify byte-identity vs the reference payload. We loop the
/// step count from 1 upward so the test exercises the snapshot
/// path at multiple block boundaries (the fixture's entry has
/// only one block, but the `decode_step` boundary itself splits
/// into "decoded the block" + "drained safe staging" mid-call,
/// which gives several distinct snapshot points).
#[test]
fn snapshot_resume_round_trips_at_every_step() {
    // Reference: clean decode.
    let mut reference_out = Vec::new();
    let reference_steps = {
        let mut dec = fresh_decoder();
        drain_until_eof(&mut dec, &mut reference_out)
    };
    assert_eq!(reference_out, FIXTURE_UNPACKED);

    // For every step S in 1..reference_steps, snapshot at the
    // boundary, then resume + finish and compare.
    for snapshot_after in 1..reference_steps {
        let mut dec = fresh_decoder();
        let mut prefix = Vec::new();
        for _ in 0..snapshot_after {
            let status = dec.decode_step(&mut prefix).expect("decode_step");
            if matches!(status, DecodeStatus::Eof) {
                // Reached EOF before the planned snapshot point;
                // means `reference_steps` is shorter than this
                // iteration expected. Skip rather than fail.
                break;
            }
        }

        let blob = match dec.decoder_state() {
            Some(b) => b,
            None => {
                // No snapshotable state at this step (the very
                // first step before any block has decoded falls
                // through here). Skip.
                continue;
            }
        };
        let cursor =
            RarStreamDecoder::source_cursor_from_blob(&blob).expect("source_cursor_from_blob ok");
        let bitstream = fixture_bitstream();
        assert!(
            (cursor as usize) <= bitstream.len(),
            "blob cursor {cursor} > bitstream len {}",
            bitstream.len()
        );

        let tail = bitstream[cursor as usize..].to_vec();
        let src: Box<dyn std::io::Read + Send> = Box::new(Cursor::new(tail));
        let mut resumed = RarStreamDecoder::resume(src, FIXTURE_DICT_CAPACITY, &blob)
            .expect("resume from snapshot");
        // The prefix the original decoder emitted is what the
        // resumed run picks up after; concatenating the two must
        // equal the reference output.
        let mut suffix = Vec::new();
        drain_until_eof(&mut resumed, &mut suffix);
        let mut combined = prefix.clone();
        combined.extend_from_slice(&suffix);
        assert_eq!(
            combined,
            FIXTURE_UNPACKED,
            "resume from step {snapshot_after} must produce byte-identical output \
             (prefix.len() = {}, suffix.len() = {})",
            prefix.len(),
            suffix.len(),
        );
    }
}

/// `source_cursor_from_blob` rejects malformed blobs: wrong
/// magic, wrong version, truncated header. Defensive — the
/// pipeline always pairs a checkpoint blob with its archive, so
/// in practice these errors never fire, but the precise
/// diagnostic helps when a corrupted `.peel.ckpt` survives a
/// disk corruption event.
#[test]
fn source_cursor_rejects_bad_magic() {
    let mut blob = vec![b'X', b'X', b'X', b'X']; // wrong magic
    blob.extend_from_slice(&1u32.to_le_bytes()); // version
    blob.extend_from_slice(&0u64.to_le_bytes()); // src_consumed
    let err = RarStreamDecoder::source_cursor_from_blob(&blob).expect_err("bad magic");
    assert!(
        format!("{err}").contains("magic mismatch") || format!("{err:?}").contains("magic"),
        "unexpected: {err:?}"
    );
}

#[test]
fn source_cursor_rejects_short_header() {
    // 4 magic + 4 version + only 4 cursor bytes (need 8)
    let blob: Vec<u8> = b"RR5S\x01\x00\x00\x00\x00\x00\x00\x00".to_vec();
    let err = RarStreamDecoder::source_cursor_from_blob(&blob).expect_err("short header");
    assert!(
        format!("{err:?}").contains("snapshot")
            || format!("{err}").contains("snapshot")
            || format!("{err}").contains("too short"),
        "unexpected: {err:?}"
    );
}

/// `RarStreamDecoder::resume` rejects a blob whose recorded
/// `dict_capacity` disagrees with the file-header capacity: the
/// resumed decoder cannot reuse the dictionary contents at a
/// different size.
#[test]
fn resume_rejects_dict_capacity_mismatch() {
    // Step the decoder until it offers a snapshot (the first
    // step that decodes a block). The fixture's entry holds just
    // one block, so the EOF transition can come a step or two
    // later — we stop at the first `Some(blob)`.
    let mut dec = fresh_decoder();
    let mut staging = Vec::new();
    let blob = loop {
        let status = dec.decode_step(&mut staging).expect("decode_step");
        if let Some(b) = dec.decoder_state() {
            break b;
        }
        if matches!(status, DecodeStatus::Eof) {
            panic!("decoder reached EOF without ever exposing a snapshotable boundary");
        }
    };
    let bitstream = fixture_bitstream().to_vec();
    let src: Box<dyn std::io::Read + Send> = Box::new(Cursor::new(bitstream));
    // Mismatched capacity: 128 KiB instead of 1 MiB.
    let err = RarStreamDecoder::resume(src, 128 * 1024, &blob)
        .expect_err("resume rejects dict_capacity mismatch");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("dict_capacity"),
        "expected dict_capacity diagnostic, got: {msg}"
    );
    let _ = MAX_DICT_BYTES; // keep the import in scope for readability
}

/// Regression: the smallest known archive whose compressed entry
/// spans two RAR5 blocks (`block 0` has `is_last_block=False`).
/// Pins the libarchive-parity 4-byte lookahead fix in
/// [`super::stream::RarStreamDecoder::read_block`] — without
/// the lookahead the round-one decoder underran the bitstream
/// by 2 bits at the block-0 boundary. See
/// `docs/PLAN_rar5_multi_block_decode.md` for the original
/// diagnosis and `docs/PLAN_rar5_decoder.md` §F2 for the fix
/// landing.
#[test]
fn multi_block_archive_decodes_byte_identical() {
    let bitstream = MB_FIXTURE[MB_DATA_OFFSET..MB_DATA_OFFSET + MB_PACKED_SIZE].to_vec();
    let src: Box<dyn std::io::Read + Send> = Box::new(Cursor::new(bitstream));
    let mut dec = RarStreamDecoder::new(src, MB_DICT_CAPACITY).expect("construct decoder");
    let mut out = Vec::new();
    // Use a generous step cap — the entry decompresses to 67.5 MB
    // and each `decode_step` does at most one block of work.
    for _ in 0..1_000_000 {
        match dec.decode_step(&mut out).expect("decode_step") {
            DecodeStatus::Eof => break,
            DecodeStatus::MoreData => continue,
        }
    }
    // The payload was `b'X' * 27 * 2_500_000`; every byte is `b'X'`.
    let expected_len = 27usize * 2_500_000;
    assert_eq!(
        out.len(),
        expected_len,
        "decoded length mismatch: got {}, want {expected_len}",
        out.len(),
    );
    assert!(
        out.iter().all(|&b| b == b'X'),
        "decoded bytes contained a non-'X' byte"
    );
}
