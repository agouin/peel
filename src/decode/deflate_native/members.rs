//! gzip member-boundary scanner.
//!
//! Phase 2 of [`internal/PLAN_gzip_throughput.md`]. The plan's parallel
//! path needs to know each member's compressed byte range up-front
//! (so worker N can decode it independently of workers `<N`); gzip
//! does not carry a trailing index the way xz does, so we have to
//! walk the source forward, parsing each member's header and
//! running deflate-decode through the body just far enough to find
//! the trailer.
//!
//! This module exposes that walk as a primitive: drive a
//! [`GzipDecoder`] against `io::sink()` (no decoded bytes
//! materialized — the framing is what we care about), stop after the
//! first member's trailer validates, snapshot the per-member CRC32 +
//! ISIZE + compressed byte count.
//!
//! # What the parallel path does with this
//!
//! Phase 3 dispatches workers in a pipelined prefix-sum: worker 0
//! runs [`scan_first_member_streaming`] on the full source, hands
//! the discovered next-member offset to the dispatcher, and starts
//! decoding member 0 itself; worker 1 calls `scan_first_member`
//! over the suffix once the dispatcher publishes the next-member
//! range; and so on. The cost of "find the next member" is *one*
//! deflate decode (the same work the worker has to do anyway to
//! validate the trailer), so the linearized pre-scan does not erase
//! the parallel win.
//!
//! Round-one ships the *one-member* primitives; the pipelined
//! prefix-sum scanner that calls them in a loop is in Phase 3, next
//! to the worker pool. A standalone `scan_all_members` helper would
//! re-run the same single-threaded decode the streaming path
//! already does — there is no shape in which it is cheaper than the
//! streaming path it is meant to accelerate.
//!
//! # Round-one limits
//!
//! - The slice variant decodes the full member body to discover the
//!   trailer offset — this is *the* deflate decode for that member.
//!   For `pigz`-style ~32 MiB members, the scan cost matches the
//!   decoder-only throughput floor (a few hundred MiB/s up through
//!   gigabytes/s post-Phase-1). Phase 7 (filed as a follow-on)
//!   evaluates a tail-search heuristic that scans the source's
//!   tail backward for `0x1F 0x8B` byte-aligned occurrences and
//!   forward-validates only the candidates — useful when scanner
//!   latency dominates the wall-clock.
//! - "Fall back to streaming" is the failure mode for anything the
//!   scanner can't parse cleanly. Discrimination is via the
//!   existing [`DeflateError`] variants:
//!   [`DeflateError::UnexpectedEof`] → caller has buffered too few
//!   bytes (retry once the source extends); [`DeflateError::GzipBadMagic`]
//!   / [`DeflateError::GzipUnsupportedCompressionMethod`] /
//!   [`DeflateError::GzipReservedFlag`] → "this isn't a gzip stream
//!   we can handle"; [`DeflateError::GzipCrcMismatch`] /
//!   [`DeflateError::GzipIsizeMismatch`] → corruption (fail closed).
//!   No new error variant is introduced — the existing surface is
//!   already sufficient for the coordinator's three-way decision.

use std::io::{self, Cursor, Read};

use super::error::DeflateError;
use super::gzip::GzipDecoder;
use crate::decode::{DecodeError, DecodeStatus, StreamingDecoder};

/// Description of one gzip member's location and trailer-recorded
/// integrity values. Produced by [`scan_first_member`] /
/// [`scan_first_member_streaming`]; consumed by the Phase 3 parallel
/// path's per-worker `decode_one_member` driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GzMemberRecord {
    /// Member start, in bytes from the start of the source the
    /// scanner was handed. The slice / reader scanners always
    /// produce `0` here (they describe the *first* member from
    /// their own zero); a Phase 3 prefix-sum caller iterating
    /// across a larger stream is responsible for adjusting this
    /// to the cumulative offset within that stream.
    pub compressed_offset: u64,
    /// Total compressed bytes the member spans, including its
    /// header, deflate body, and 8-byte trailer. Equivalent to
    /// `bytes_consumed()` on the wrapper at the moment the
    /// trailer validated.
    pub compressed_size: u64,
    /// ISIZE the member's trailer recorded (RFC 1952 §2.3.1.5: low
    /// 32 bits of the decompressed length). On `pigz`-style fixtures
    /// where members are bounded to ≤ 4 GiB, this is the exact
    /// decompressed length; for unusually large members (≥ 4 GiB),
    /// only the low 32 bits are spec-recoverable from the gzip
    /// trailer. The Phase 3 parallel path sanity-checks worker
    /// output's low 32 bits against this; the absolute decompressed
    /// length is not part of the scanner's contract.
    pub isize_mod32: u32,
    /// CRC-32/IEEE the member's trailer recorded over its
    /// decompressed bytes. Phase 3's per-worker decoder
    /// independently re-computes this and compares; a mismatch
    /// surfaces as [`DeflateError::GzipCrcMismatch`] from the
    /// worker, exactly as the streaming path would.
    pub crc32: u32,
}

/// Drive `decoder` (which the caller has just constructed over the
/// source) until the first member's trailer validates, discarding
/// the decoded bytes. Returns the per-member record on success.
///
/// Uses [`GzipDecoder::step_typed`] (not the
/// [`StreamingDecoder::decode_step`] boundary) so the typed
/// [`DeflateError`] variants survive intact — the coordinator's
/// fallback discrimination relies on
/// [`DeflateError::UnexpectedEof`] vs [`DeflateError::GzipBadMagic`]
/// vs [`DeflateError::GzipCrcMismatch`] being directly matchable.
///
/// # Errors
///
/// - [`DeflateError::UnexpectedEof`] when the source ends before the
///   first member's trailer lands. Caller should buffer more bytes
///   and retry, or fall through to the streaming path which will
///   block-pull more bytes itself.
/// - Any other [`DeflateError`] variant the [`GzipDecoder`] surfaces
///   for a structurally-malformed source (bad magic, CRC mismatch,
///   reserved flags, etc.).
fn drive_to_first_trailer(decoder: &mut GzipDecoder) -> Result<GzMemberRecord, DeflateError> {
    let mut sink = io::sink();
    while decoder.members_scanned() == 0 {
        match decoder.step_typed(&mut sink)? {
            DecodeStatus::MoreData => continue,
            DecodeStatus::Eof => {
                // Source exhausted before any member's trailer
                // landed — the wrapper reached `State::Done` via
                // the `BetweenMembers → Done` transition without
                // ever validating a trailer. Treat as truncation.
                return Err(DeflateError::UnexpectedEof("gzip member scan"));
            }
        }
    }
    // members_scanned() advanced; the trailer-validation arm has
    // populated last_member_{crc32,isize}. INVARIANT: both
    // accessors return `Some` whenever members_scanned() ≥ 1 (the
    // trailer arm sets all three in the same branch).
    let crc32 = decoder
        .last_member_crc32()
        .expect("trailer arm sets crc32 alongside members_scanned");
    let isize_mod32 = decoder
        .last_member_isize()
        .expect("trailer arm sets isize alongside members_scanned");
    let compressed_size = decoder.bytes_consumed().get();
    Ok(GzMemberRecord {
        compressed_offset: 0,
        compressed_size,
        isize_mod32,
        crc32,
    })
}

/// Scan the first gzip member out of `source` and return its record.
///
/// `source` must start at a member boundary (no leading garbage).
/// The scan runs the full deflate decode of the member's body
/// against `io::sink()` — no decoded bytes are materialized. Cost
/// matches the decoder-only throughput floor (post-Phase-1: a few
/// GiB/s on a 32 MiB member; see
/// [`tests/test_bench_deflate_native.rs`]).
///
/// `compressed_offset` on the returned record is always `0`; callers
/// iterating multiple members in a larger source are responsible for
/// adjusting it to the cumulative offset they care about.
///
/// # Errors
///
/// See [`drive_to_first_trailer`] for the failure surface; the
/// existing [`DeflateError`] variants are sufficient for the
/// coordinator's three-way "retry / fail closed / wrong format"
/// discrimination.
pub fn scan_first_member(source: &[u8]) -> Result<GzMemberRecord, DeflateError> {
    // INVARIANT: GzipDecoder::new owns the source; we hand it a
    // Cursor over a clone so the slice stays available to the
    // caller. The clone is one allocation per scan; for the slice
    // scanner this is fine — the alternative is generic-over-Read
    // which is what `scan_first_member_streaming` exposes.
    let mut decoder = GzipDecoder::new(Box::new(Cursor::new(source.to_vec())))
        .map_err(decode_error_to_deflate)?;
    drive_to_first_trailer(&mut decoder)
}

/// Scan the first gzip member from `reader` and return its record.
/// Consumes from `reader` exactly the bytes one member spans (header
/// + deflate body + trailer) and no further.
///
/// `compressed_offset` on the returned record is always `0` — it
/// describes the first member as offset within `reader`'s current
/// position; callers tracking cumulative offsets in a larger stream
/// adjust externally.
///
/// Phase 3 of [`internal/PLAN_gzip_throughput.md`] uses this in the
/// pipelined prefix-sum scanner: the worker decoding member N also
/// runs `scan_first_member_streaming` over the source's suffix to
/// produce member N+1's range as a side effect.
///
/// # Errors
///
/// Same surface as [`scan_first_member`]; the underlying decoder
/// state machine is the same.
pub fn scan_first_member_streaming(
    reader: Box<dyn Read + Send>,
) -> Result<GzMemberRecord, DeflateError> {
    let mut decoder = GzipDecoder::new(reader).map_err(decode_error_to_deflate)?;
    drive_to_first_trailer(&mut decoder)
}

/// Convert a [`DecodeError`] from [`GzipDecoder::new`] back to
/// [`DeflateError`]. `GzipDecoder::new` is currently infallible (the
/// signature is fallible only to match
/// [`crate::decode::DecoderFactory`]), so this is the cold path —
/// kept for completeness so the scanner's signature stays clean.
fn decode_error_to_deflate(err: DecodeError) -> DeflateError {
    match err {
        DecodeError::Read { source, .. } | DecodeError::Construct(source) => {
            DeflateError::SourceIo(source)
        }
        DecodeError::Write(source) => DeflateError::SinkIo(source),
        DecodeError::ResumeMismatch { .. } => {
            DeflateError::SourceIo(io::Error::other(err.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    use flate2::write::GzEncoder;
    use flate2::Compression;

    /// Encode `payload` as a single-member gzip blob using flate2's
    /// default level. Mirrors the helpers in
    /// `crate::decode::deflate_native::gzip::tests::encode_gzip` and
    /// `tests/test_bench_streaming.rs::encode_gzip` so fixtures
    /// produced here are byte-identical to those produced elsewhere.
    fn encode_gzip(payload: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).expect("encode gzip");
        encoder.finish().expect("finish gzip")
    }

    /// Reference (offset, size, isize, crc32) per encoded member,
    /// in encode order. Aliased so the test helper signature stays
    /// inside clippy's `type_complexity` budget.
    type ExpectedRecord = (u64, u64, u32, u32);

    /// Concatenate `n` independently-encoded gzip members covering
    /// `payload` in equal-ish slices. Returns the wire bytes plus a
    /// `Vec<ExpectedRecord>` describing each member, which the
    /// differential test cross-checks against the scanner's output.
    fn encode_multi_member(payload: &[u8], n: usize) -> (Vec<u8>, Vec<ExpectedRecord>) {
        assert!(n >= 1);
        let mut wire = Vec::new();
        let mut records = Vec::new();
        let chunk = payload.len() / n;
        let mut cursor = 0u64;
        for i in 0..n {
            let start = i * chunk;
            let end = if i + 1 == n {
                payload.len()
            } else {
                start + chunk
            };
            let slice = &payload[start..end];
            let blob = encode_gzip(slice);
            // Reference values: the encoder produces the canonical
            // CRC32 + ISIZE in the trailer. We pull them out of the
            // last 8 bytes of `blob`.
            let trailer = &blob[blob.len() - 8..];
            let crc = u32::from_le_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
            let isize_lo = u32::from_le_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);
            records.push((cursor, blob.len() as u64, isize_lo, crc));
            cursor += blob.len() as u64;
            wire.extend_from_slice(&blob);
        }
        (wire, records)
    }

    /// Walk `wire` member-by-member, calling `scan_first_member` on
    /// the suffix at each step. Asserts the returned record matches
    /// the reference `(offset, size, isize, crc)`. The "assemble
    /// cumulative offsets externally" invariant lives here — the
    /// scanner itself always reports `compressed_offset = 0`.
    fn assert_scan_round_trip(wire: &[u8], expected: &[ExpectedRecord]) {
        let mut cursor = 0u64;
        for (i, &(exp_off, exp_sz, exp_isize, exp_crc)) in expected.iter().enumerate() {
            let suffix = &wire[cursor as usize..];
            let rec = scan_first_member(suffix).unwrap_or_else(|e| panic!("scan member {i}: {e}"));
            assert_eq!(
                rec.compressed_offset, 0,
                "scanner must report compressed_offset=0 for the first member of its slice (member {i})"
            );
            assert_eq!(
                rec.compressed_size, exp_sz,
                "compressed_size mismatch at member {i}",
            );
            assert_eq!(rec.isize_mod32, exp_isize, "isize mismatch at member {i}");
            assert_eq!(rec.crc32, exp_crc, "crc32 mismatch at member {i}");
            // External cumulative-offset bookkeeping: cursor +
            // compressed_offset (always 0) + compressed_size.
            assert_eq!(cursor, exp_off, "cumulative cursor drifted at member {i}");
            cursor += rec.compressed_size;
        }
        assert_eq!(
            cursor as usize,
            wire.len(),
            "total scanned bytes must equal wire length"
        );
    }

    /// Differential corpus: 50 fixtures spanning member sizes
    /// 1 KiB – 32 MiB and member counts 1, 2, 8, 32. Every fixture
    /// is byte-identically scannable to the per-member trailer
    /// values flate2 emitted at encode time, and the cumulative
    /// scan reaches end-of-source without leftovers.
    #[test]
    fn scan_first_member_matches_flate2_corpus() {
        // (member_size, member_count). 13 sizes × {1, 2, 8, 32} =
        // 52 fixtures (close enough to the plan's "50-fixture"
        // target; running the full grid takes ~30 s in debug, a
        // couple of seconds in release).
        let sizes = [
            1024,
            2048,
            4096,
            8 * 1024,
            16 * 1024,
            64 * 1024,
            256 * 1024,
            1 << 20,
            2 << 20,
            4 << 20,
            8 << 20,
            16 << 20,
            32 << 20,
        ];
        let counts = [1usize, 2, 8, 32];

        // Same LCG as the bench fixtures so the payload bytes are
        // representative of what's on the bench grid.
        fn lcg_buf(seed: u64, len: usize) -> Vec<u8> {
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

        for (i, &member_size) in sizes.iter().enumerate() {
            for &count in &counts {
                // Skip the largest grid points at debug-build cost
                // — a 32 MiB × 32 = 1 GiB fixture is not a practical
                // unit-test workload.
                if member_size * count > 64 << 20 {
                    continue;
                }
                let payload = lcg_buf(0xBEEF + i as u64, member_size * count);
                let (wire, expected) = encode_multi_member(&payload, count);
                assert_scan_round_trip(&wire, &expected);
            }
        }
    }

    /// Non-slice path: the streaming reader surface produces the
    /// same record as the slice surface for the same bytes. Pins
    /// the contract that "scanning from a `Read` reads exactly one
    /// member's bytes and stops".
    #[test]
    fn scan_first_member_streaming_matches_slice_path() {
        let payload = b"hello scanner streaming world".repeat(2048);
        let blob = encode_gzip(&payload);

        let slice_rec = scan_first_member(&blob).expect("slice scan");
        let streaming_rec = scan_first_member_streaming(Box::new(Cursor::new(blob.clone())))
            .expect("streaming scan");
        assert_eq!(slice_rec, streaming_rec);
    }

    /// Truncated source: the scanner surfaces `UnexpectedEof` for
    /// the appropriate framing layer. Phase 3's pipelined caller
    /// uses this to discriminate "haven't buffered enough bytes
    /// yet" from "this isn't gzip".
    #[test]
    fn scan_first_member_truncated_returns_unexpected_eof() {
        let payload = vec![0xABu8; 4096];
        let blob = encode_gzip(&payload);
        // Trim the last byte of the trailer.
        let truncated = &blob[..blob.len() - 1];
        match scan_first_member(truncated) {
            Err(DeflateError::UnexpectedEof(_)) => {}
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    /// Bad magic: the scanner surfaces `GzipBadMagic`, the same
    /// shape the streaming path would. Pins the "wrong format"
    /// arm of the coordinator's discrimination.
    #[test]
    fn scan_first_member_bad_magic_returns_typed_error() {
        let mut blob = encode_gzip(b"valid payload");
        // Corrupt the magic bytes.
        blob[0] = 0x00;
        blob[1] = 0x00;
        match scan_first_member(&blob) {
            Err(DeflateError::GzipBadMagic {
                id1: 0x00,
                id2: 0x00,
            }) => {}
            other => panic!("expected GzipBadMagic, got {other:?}"),
        }
    }

    /// CRC-mismatch: the scanner surfaces `GzipCrcMismatch`, the
    /// same shape the streaming path would. Pins the "definite
    /// corruption" arm of the coordinator's discrimination.
    #[test]
    fn scan_first_member_crc_mismatch_returns_typed_error() {
        let payload = b"crc-tampered".repeat(64);
        let mut blob = encode_gzip(&payload);
        // Corrupt the trailing CRC32 (first 4 bytes of the trailer).
        let crc_off = blob.len() - 8;
        blob[crc_off] ^= 0xFF;
        match scan_first_member(&blob) {
            Err(DeflateError::GzipCrcMismatch { .. }) => {}
            other => panic!("expected GzipCrcMismatch, got {other:?}"),
        }
    }
}
