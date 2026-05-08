//! Clean-room Rust port of liblzma's xz decoder, structurally
//! faithful.
//!
//! Phase 1 of [`docs/PLAN_xz_liblzma_port.md`](../../../docs/PLAN_xz_liblzma_port.md).
//! Sibling to [`super::xz_native`]: the existing decoder is the
//! production path; this module is an experimental sibling that
//! ports liblzma's giant-single-function decoder shape into Rust.
//!
//! # Why a parallel module
//!
//! [`PLAN_xz_liblzma_deep_dive.md`](../../../docs/PLAN_xz_liblzma_deep_dive.md)
//! Phase A documented liblzma's hot-loop register discipline and
//! attributed peel's 1.5× per-byte gap to per-bit memory-store
//! costs that liblzma's compiled output avoids. Phase C of that
//! plan tested whether a struct-shape change ("LocalRc"
//! stack-staging) inside the existing decoder could close the
//! gap; it could not. The diagnosis was that closing the gap
//! requires the same overall function shape liblzma uses — a
//! single dispatch loop where the rc state, dict pointer, and
//! prob-base pointer all stay register-resident across thousands
//! of expansion sites. That shape is incompatible with the
//! existing decoder's per-LZMA2-chunk dispatch boundary, which is
//! load-bearing for the checkpoint mechanism.
//!
//! Rather than refactor the production path, this plan builds a
//! parallel module that mirrors liblzma's shape without
//! checkpoint constraints. If Phase 4's bench gate clears, Phase F
//! adds checkpoint support back. If it doesn't clear, the
//! experiment is the deliverable: we've established the
//! architectural ceiling is genuinely past what struct-shape
//! changes alone can move.
//!
//! # `unsafe` posture
//!
//! Liberal — `unsafe` admitted wherever liblzma uses raw pointers,
//! with `// SAFETY:` comments on every block. The strict
//! ≥ 5 % microbench-gain gate from
//! [`PLAN_xz_decoder_optimization.md`](../../../docs/PLAN_xz_decoder_optimization.md)
//! is dropped; parity with liblzma is itself the perf
//! justification.
//!
//! # Round-one scope
//!
//! No checkpoint support, no resume blob, no public crate-API
//! integration. The module is wired into `pub mod` so its tests
//! and benches build, but it is not exposed via
//! [`crate::decode`]'s public surface.

pub mod decoder;
pub mod dict;
pub mod error;
pub mod lzma2;
pub mod range_coder;

use std::io::{Read, Write};

use crate::decode::xz_native::block::{block_header_real_size, parse_block_header};
use crate::decode::xz_native::stream::{
    parse_stream_footer, parse_stream_header, read_multibyte, CheckId, StreamFlags,
    STREAM_FOOTER_LEN, STREAM_HEADER_LEN,
};
use crate::decode::{DecodeError, DecodeStatus, StreamingDecoder};
use crate::hash::{crc32::Crc32, crc64::Crc64, sha256::Sha256};
use crate::types::ByteOffset;

use self::lzma2::Lzma2Decoder;

/// Public `xz` streaming decoder built on the liblzma-port
/// inner loop.
///
/// Phase 6 of [`docs/PLAN_xz_liblzma_port.md`](../../../docs/PLAN_xz_liblzma_port.md).
/// Implements [`StreamingDecoder`] with the same shape as
/// [`super::xz_native::Decoder`] so the bench grid can swap
/// between them. Internally:
///
/// 1. **First `decode_step`**: slurps the entire compressed
///    source into an in-memory buffer, parses the Stream
///    Header / Block Header / Block-Check, dispatches the
///    Block's body through [`Lzma2Decoder`], validates the
///    Block-Check + Stream Footer, writes the full decoded
///    payload to the sink. Returns
///    [`DecodeStatus::MoreData`] (more bytes may still be
///    waiting in the sink's pipeline).
/// 2. **Subsequent calls**: return [`DecodeStatus::Eof`].
///
/// # Round-one limitations
///
/// - **Single-Block streams only.** `xz2` emits single-Block
///   `.xz` files at any preset; the differential corpus uses
///   that shape exclusively. Multi-Block support is filed as
///   a Phase F follow-on.
/// - **No streaming of input.** The whole compressed stream
///   is read up front. True per-`decode_step` byte-pull
///   shape (matching [`super::xz_native::Decoder`]) is also
///   filed as Phase F — it requires `lzma_decode_port`'s
///   resume arms (`Sequence::Literal0` ... etc.) which were
///   deferred per the plan's "without checkpoints for round
///   one" framing.
/// - **No checkpoint blob.** [`StreamingDecoder::decoder_state_into`]
///   returns `false` (the offset alone restarts cleanly at
///   end-of-stream).
/// - **Stream / Block / Check parsers borrowed from
///   [`super::xz_native`].** They're well-tested clean-room
///   ports already; re-porting would duplicate code without
///   changing behavior. Phase F can extract them if
///   true module isolation matters.
pub struct Decoder {
    source: Option<Box<dyn Read + Send>>,
    bytes_consumed: u64,
    /// Once decoded, set to the total source byte count so
    /// `frame_boundary` reports the end-of-stream offset and
    /// `bytes_consumed` aligns with the source's full length.
    finished: bool,
    last_frame_boundary: Option<ByteOffset>,
}

impl Decoder {
    /// Construct a [`Decoder`] over `source`. Construction
    /// never reads from the source; the first
    /// [`StreamingDecoder::decode_step`] does the slurp.
    ///
    /// # Errors
    ///
    /// Currently never returns `Err`. Signature kept fallible
    /// to match [`super::DecoderFactory`] without an adapter.
    pub fn new(source: Box<dyn Read + Send>) -> Result<Self, DecodeError> {
        Ok(Self {
            source: Some(source),
            bytes_consumed: 0,
            finished: false,
            last_frame_boundary: None,
        })
    }

    /// One-shot full-stream decode. Reads everything from the
    /// source, validates the .xz framing, dispatches the
    /// Block payload through [`Lzma2Decoder`], writes
    /// uncompressed bytes to `sink`.
    fn slurp_and_decode(&mut self, sink: &mut dyn Write) -> Result<(), DecodeError> {
        let Some(mut source) = self.source.take() else {
            // Already consumed; nothing to do.
            return Ok(());
        };
        let mut compressed: Vec<u8> = Vec::new();
        source
            .read_to_end(&mut compressed)
            .map_err(|e| DecodeError::Read {
                consumed: 0,
                source: e,
            })?;
        decode_xz_stream(&compressed, sink).map_err(|e| {
            // Errors are terminal; surface as Read with the
            // bytes-consumed cursor at where we were.
            DecodeError::Read {
                consumed: compressed.len() as u64,
                source: std::io::Error::other(format!("xz_liblzma: {e}")),
            }
        })?;
        self.bytes_consumed = compressed.len() as u64;
        self.last_frame_boundary = Some(ByteOffset::new(self.bytes_consumed));
        self.finished = true;
        Ok(())
    }
}

impl StreamingDecoder for Decoder {
    fn decode_step(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, DecodeError> {
        if self.finished {
            return Ok(DecodeStatus::Eof);
        }
        self.slurp_and_decode(sink)?;
        Ok(DecodeStatus::Eof)
    }

    fn bytes_consumed(&self) -> ByteOffset {
        ByteOffset::new(self.bytes_consumed)
    }

    fn frame_boundary(&self) -> Option<ByteOffset> {
        self.last_frame_boundary
    }

    fn set_source_start_offset(&mut self, offset: u64) {
        self.bytes_consumed = offset;
    }
}

/// [`crate::decode::DecoderFactory`] adapter for [`Decoder`].
///
/// Same shape as
/// [`super::xz_native::factory`]; lets the fuzz harness +
/// bench grid plug the port decoder in via the same trait
/// object as the production decoder. Not registered by
/// [`crate::decode::DecoderRegistry::with_defaults`] —
/// integration into the production path is gated on
/// Phase 8 / 9.
///
/// # Errors
///
/// Forwards any error returned by [`Decoder::new`] (currently
/// none).
pub fn factory(src: Box<dyn Read + Send>) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    Ok(Box::new(Decoder::new(src)?))
}

/// Validate the .xz framing around `compressed`, dispatch the
/// Block body through [`Lzma2Decoder`], write the decoded
/// payload to `sink`. Round-one: single-Block only.
fn decode_xz_stream(compressed: &[u8], sink: &mut dyn Write) -> Result<(), error::XzPortError> {
    use crate::decode::xz_native::error::XzError;

    // ---- Stream Header (12 bytes) ----
    if compressed.len() < STREAM_HEADER_LEN + STREAM_FOOTER_LEN {
        return Err(error::XzPortError::Framing(format!(
            "input too short for Stream Header + Footer: {} bytes",
            compressed.len()
        )));
    }
    let header_flags: StreamFlags = parse_stream_header(&compressed[..STREAM_HEADER_LEN])?;

    // ---- Block Header ----
    let mut p = STREAM_HEADER_LEN;
    if compressed[p] == 0x00 {
        // Index Indicator: empty stream (no Blocks). Just
        // validate the footer below.
        return validate_empty_stream(&compressed[p..], header_flags);
    }
    let bh_size_byte = compressed[p];
    let bh_real_size = block_header_real_size(bh_size_byte);
    if p + bh_real_size > compressed.len() {
        return Err(error::XzPortError::Framing(format!(
            "Block Header extends past input: need {} bytes, have {}",
            bh_real_size,
            compressed.len() - p,
        )));
    }
    let block_header = parse_block_header(&compressed[p..p + bh_real_size])?;
    p += bh_real_size;

    // ---- LZMA2 stream (Block body) ----
    let mut decoded_buf: Vec<u8> = Vec::new();
    let mut dec = Lzma2Decoder::new(block_header.dict_size);
    let consumed = dec.decode_stream(&compressed[p..], &mut decoded_buf)?;
    let block_payload_consumed = consumed;
    p += block_payload_consumed;

    // Cross-check declared sizes if present.
    if let Some(decl_uncomp) = block_header.uncompressed_size {
        if decoded_buf.len() as u64 != decl_uncomp {
            return Err(error::XzPortError::Framing(format!(
                "Block Header uncompressed_size = {decl_uncomp} but \
                 decoder produced {}",
                decoded_buf.len()
            )));
        }
    }

    // ---- Block Padding (0..=3 bytes of 0x00 to align to 4) ----
    let block_payload_total = bh_real_size + block_payload_consumed;
    let pad = (4 - (block_payload_total & 3)) & 3;
    if p + pad > compressed.len() {
        return Err(error::XzPortError::Framing(
            "Block Padding extends past input".into(),
        ));
    }
    for &b in &compressed[p..p + pad] {
        if b != 0x00 {
            return Err(error::XzPortError::Framing(format!(
                "Block Padding byte non-zero: 0x{b:02X}"
            )));
        }
    }
    p += pad;

    // ---- Block Check ----
    let check_size = header_flags.check.size();
    if p + check_size > compressed.len() {
        return Err(error::XzPortError::Framing(
            "Block Check extends past input".into(),
        ));
    }
    verify_block_check(
        header_flags.check,
        &decoded_buf,
        &compressed[p..p + check_size],
    )?;
    p += check_size;

    // Write the decoded payload to the sink. Done after
    // Block-Check validation so we don't emit bytes from a
    // stream that fails its checksum.
    sink.write_all(&decoded_buf)
        .map_err(error::XzPortError::SinkIo)?;

    // ---- Index ----
    // For single-Block round one we just walk past the Index
    // (1 byte indicator + VLI records + VLI count + padding +
    // CRC32). xz_native's `read_multibyte` parses VLIs.
    if p >= compressed.len() || compressed[p] != 0x00 {
        return Err(error::XzPortError::Framing(format!(
            "expected Index Indicator (0x00) at offset {p}; got {:?}",
            compressed.get(p)
        )));
    }
    p += 1;
    // Index records count (VLI): for single-Block streams = 1.
    let (num_records, consumed_count) = read_multibyte(&compressed[p..])
        .map_err(|e: XzError| error::XzPortError::Framing(format!("Index count VLI: {e}")))?;
    p += consumed_count;
    if num_records > 1 {
        return Err(error::XzPortError::Framing(format!(
            "multi-Block streams not supported in round-one: Index claims {num_records} records"
        )));
    }
    // Per record: unpadded_size VLI + uncompressed_size VLI.
    for _ in 0..num_records {
        let (_uns, n) = read_multibyte(&compressed[p..])
            .map_err(|e: XzError| error::XzPortError::Framing(format!("Index VLI: {e}")))?;
        p += n;
        let (_uss, n2) = read_multibyte(&compressed[p..])
            .map_err(|e: XzError| error::XzPortError::Framing(format!("Index VLI: {e}")))?;
        p += n2;
    }
    // Index Padding (0..=3 bytes of 0x00 to align to 4) +
    // 4-byte CRC32 over the Index. The Index started at
    // `index_start` (right after the Block-Check); we're
    // currently at `p` after consuming Indicator + count VLI
    // + record VLIs.
    let index_start = STREAM_HEADER_LEN + bh_real_size + block_payload_consumed + pad + check_size;
    let index_consumed_so_far = p - index_start;
    let index_pad = (4 - (index_consumed_so_far & 3)) & 3;
    for &b in &compressed[p..p + index_pad] {
        if b != 0x00 {
            return Err(error::XzPortError::Framing(format!(
                "Index Padding byte non-zero: 0x{b:02X}"
            )));
        }
    }
    p += index_pad;
    if p + 4 > compressed.len() {
        return Err(error::XzPortError::Framing(
            "Index CRC32 extends past input".into(),
        ));
    }
    let index_crc_stored = u32::from_le_bytes([
        compressed[p],
        compressed[p + 1],
        compressed[p + 2],
        compressed[p + 3],
    ]);
    let mut crc = Crc32::new();
    crc.update(&compressed[index_start..p]);
    let index_crc_computed = crc.finalize();
    if index_crc_stored != index_crc_computed {
        return Err(error::XzPortError::Framing(format!(
            "Index CRC32 mismatch: stored 0x{index_crc_stored:08X}, computed 0x{index_crc_computed:08X}"
        )));
    }
    p += 4;

    // ---- Stream Footer (12 bytes) ----
    if p + STREAM_FOOTER_LEN > compressed.len() {
        return Err(error::XzPortError::Framing(format!(
            "Stream Footer extends past input: need {STREAM_FOOTER_LEN}, have {}",
            compressed.len() - p,
        )));
    }
    let (footer_flags, _backward_size) =
        parse_stream_footer(&compressed[p..p + STREAM_FOOTER_LEN])?;
    if footer_flags.check != header_flags.check {
        return Err(error::XzPortError::Framing(format!(
            "Stream Footer Check ID disagrees with Header: header={:?}, footer={:?}",
            header_flags.check, footer_flags.check
        )));
    }

    Ok(())
}

/// Hash the decoded bytes per the Stream Header's Check ID
/// and compare against the `check` field (`check.len() ==
/// check_id.size()`).
fn verify_block_check(
    check_id: CheckId,
    payload: &[u8],
    expected: &[u8],
) -> Result<(), error::XzPortError> {
    debug_assert_eq!(expected.len(), check_id.size());
    match check_id {
        CheckId::None => Ok(()),
        CheckId::Crc32 => {
            let mut h = Crc32::new();
            h.update(payload);
            let computed = h.finalize();
            let stored = u32::from_le_bytes([expected[0], expected[1], expected[2], expected[3]]);
            if computed != stored {
                return Err(error::XzPortError::Framing(format!(
                    "Block CRC32 mismatch: stored 0x{stored:08X}, computed 0x{computed:08X}"
                )));
            }
            Ok(())
        }
        CheckId::Crc64 => {
            let mut h = Crc64::new();
            h.update(payload);
            let computed = h.finalize();
            let stored = u64::from_le_bytes([
                expected[0],
                expected[1],
                expected[2],
                expected[3],
                expected[4],
                expected[5],
                expected[6],
                expected[7],
            ]);
            if computed != stored {
                return Err(error::XzPortError::Framing(format!(
                    "Block CRC64 mismatch: stored 0x{stored:016X}, computed 0x{computed:016X}"
                )));
            }
            Ok(())
        }
        CheckId::Sha256 => {
            let mut h = Sha256::new();
            h.update(payload);
            let computed = h.finalize();
            if computed != expected {
                return Err(error::XzPortError::Framing("Block SHA-256 mismatch".into()));
            }
            Ok(())
        }
    }
}

/// Validate an empty `.xz` stream — i.e., one where the byte
/// after the Stream Header is the Index Indicator (0x00),
/// meaning zero Blocks. xz emits this for empty payloads.
fn validate_empty_stream(
    after_header: &[u8],
    header_flags: StreamFlags,
) -> Result<(), error::XzPortError> {
    use crate::decode::xz_native::error::XzError;

    let mut p = 0;
    if after_header.is_empty() || after_header[p] != 0x00 {
        return Err(error::XzPortError::Framing(
            "expected Index Indicator (0x00) for empty stream".into(),
        ));
    }
    p += 1;
    let (num_records, consumed_count) = read_multibyte(&after_header[p..])
        .map_err(|e: XzError| error::XzPortError::Framing(format!("Index count VLI: {e}")))?;
    p += consumed_count;
    if num_records != 0 {
        return Err(error::XzPortError::Framing(format!(
            "empty-stream Index claims {num_records} records"
        )));
    }
    let index_so_far = 1 + consumed_count;
    let index_pad = (4 - (index_so_far & 3)) & 3;
    p += index_pad;
    if p + 4 > after_header.len() {
        return Err(error::XzPortError::Framing(
            "empty-stream Index CRC32 extends past input".into(),
        ));
    }
    let stored = u32::from_le_bytes([
        after_header[p],
        after_header[p + 1],
        after_header[p + 2],
        after_header[p + 3],
    ]);
    let mut crc = Crc32::new();
    crc.update(&after_header[..p]);
    if crc.finalize() != stored {
        return Err(error::XzPortError::Framing(
            "empty-stream Index CRC32 mismatch".into(),
        ));
    }
    p += 4;
    if p + STREAM_FOOTER_LEN > after_header.len() {
        return Err(error::XzPortError::Framing(
            "empty-stream Footer extends past input".into(),
        ));
    }
    let (footer_flags, _backward_size) =
        parse_stream_footer(&after_header[p..p + STREAM_FOOTER_LEN])?;
    if footer_flags.check != header_flags.check {
        return Err(error::XzPortError::Framing(
            "empty-stream Footer Check ID mismatch".into(),
        ));
    }
    Ok(())
}
