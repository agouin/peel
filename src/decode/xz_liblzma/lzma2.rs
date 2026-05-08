//! LZMA2 chunk dispatcher for the liblzma-port decoder.
//!
//! Phase 5 of [`docs/PLAN_xz_liblzma_port.md`](../../../../docs/PLAN_xz_liblzma_port.md).
//! Mirror of liblzma's `lzma2_decoder.c` (~310 lines): parses
//! LZMA2 chunk control bytes, applies the requested resets to
//! the [`super::decoder::Lzma1Decoder`] + [`super::dict::LzmaDict`],
//! and drives [`super::decoder::lzma_decode_port`] against each
//! LZMA chunk's compressed payload.
//!
//! # LZMA2 chunk control byte
//!
//! - `0x00`: end of LZMA2 stream.
//! - `0x01`: uncompressed chunk, dict reset.
//! - `0x02`: uncompressed chunk, no dict reset.
//! - `0x03..=0x7F`: reserved / invalid.
//! - `0x80..=0xFF`: LZMA chunk. Top 3 bits encode the reset
//!   mode (none / state / state+props / state+props+dict);
//!   bottom 5 bits combine with the next two header bytes to
//!   form `uncompressed_size - 1` (in `[0, 2^21 - 1]`,
//!   yielding sizes `1..=2 MiB`).
//!
//! Parsing of the chunk header is borrowed from
//! [`crate::decode::xz_native::block::parse_lzma2_chunk_header`]
//! for round one; Phase 6 ports the parser into `xz_liblzma`
//! directly.
//!
//! # Dict-wrap loop
//!
//! Each LZMA chunk's `uncompressed_size` may straddle the dict
//! ring's wrap boundary, requiring multiple calls to
//! [`super::decoder::lzma_decode_port`] per chunk. Mirror of
//! liblzma's `decode_buffer` outer loop in `lz_decoder.c`: wrap
//! `dict.pos` to 0 when it hits `dict.size`, set a fresh
//! `dict.limit`, run the inner decoder.
//!
//! # Output staging
//!
//! Bytes produced by each chunk are read out of the dict via
//! [`super::dict::LzmaDict::dict_get`] (which handles the
//! ring wraparound) and written to the caller's `&mut dyn
//! Write` sink. liblzma uses a per-call output buffer slice;
//! we use a `dyn Write` sink to align with the existing
//! `crate::decode::StreamingDecoder` shape.

use std::io::Write;

use crate::decode::xz_native::block::{
    decode_lzma_properties, parse_lzma2_chunk_header, Lzma2ChunkHeader,
};

use super::decoder::{lzma_decode_port, Lzma1Decoder, Sequence};
use super::dict::LzmaDict;
use super::error::XzPortError;
use super::range_coder::RangeDecoder;

/// LZMA2 chunk dispatcher. Mirror of liblzma's
/// `lzma2_coder` shape:
///
/// ```c
/// struct lzma2_coder {
///     enum sequence sequence;
///     bool need_properties;
///     bool need_dictionary_reset;
///     uint32_t uncompressed_size;
///     uint32_t compressed_size;
///     bool next_sequence;
///     ...
///     lzma_lzma1_decoder lzma;
/// };
/// ```
///
/// Round-one shape: holds the full
/// [`super::decoder::Lzma1Decoder`] + [`super::dict::LzmaDict`]
/// inline. Phase 6 may split them apart if the public
/// `Decoder` API needs separate ownership.
pub struct Lzma2Decoder {
    decoder: Lzma1Decoder,
    dict: LzmaDict,
    /// Per-chunk output staging buffer. Bytes produced by
    /// `lzma_decode_port` are read out of the dict ring (via
    /// `dict_get`) into this buffer, then flushed to the sink
    /// in one `write_all` call per chunk. Per-byte
    /// `sink.write_all(&[b])` calls would go through dynamic
    /// dispatch on each byte, costing ~30 % decoder
    /// throughput on compressible payloads. Reused across
    /// chunks to amortize allocation.
    staging: Vec<u8>,
    /// `true` when the next LZMA chunk MUST carry a properties
    /// byte (because either no properties have been seen yet,
    /// or the prior chunk reset state). Mirror of liblzma's
    /// `coder->need_properties`.
    needs_props: bool,
    /// `true` when the next chunk MUST be one of the
    /// dict-resetting modes (the very first chunk of a Block,
    /// or after a coder-level reset). Mirror of liblzma's
    /// `coder->need_dictionary_reset`.
    needs_dict_reset: bool,
}

impl Lzma2Decoder {
    /// Construct a fresh LZMA2 decoder with a `dict_size`-byte
    /// sliding window dictionary. The dict + decoder state are
    /// fully reset; the first chunk is required to be one of
    /// the dict-resetting variants.
    ///
    /// `dict_size` should match the Block Header's LZMA2 filter
    /// properties byte. Phase 6's stream-level driver will
    /// extract `dict_size` from the parsed Block Header.
    #[must_use]
    pub fn new(dict_size: u32) -> Self {
        Self {
            decoder: Lzma1Decoder::new(),
            dict: LzmaDict::new(dict_size as usize),
            // Pre-allocate to a typical chunk's uncompressed
            // size (LZMA2 caps at 2 MiB but most chunks are <
            // 64 KiB). 64 KiB upfront keeps the inner loop
            // off the alloc path for the common case.
            staging: Vec::with_capacity(64 * 1024),
            needs_props: true,
            needs_dict_reset: true,
        }
    }

    /// Decode one LZMA2 stream from `input`, writing
    /// uncompressed bytes to `sink`. Returns the number of
    /// bytes consumed from `input` (including the
    /// `EndOfStream` chunk's 1-byte control).
    ///
    /// `input` must contain a complete LZMA2 stream terminated
    /// by an `EndOfStream` chunk (`0x00` control byte).
    /// Streaming-input shape with mid-stream resume comes in
    /// Phase F.
    ///
    /// # Errors
    ///
    /// - [`XzPortError::Framing`] for malformed chunk headers.
    /// - [`XzPortError::FirstChunkMustResetDict`] if the first
    ///   chunk doesn't request a dict reset.
    /// - [`XzPortError::ChunkNeedsProperties`] if a chunk
    ///   demands properties but the chunk header didn't reset
    ///   them.
    /// - [`XzPortError::ChunkRangeCoderUnfinished`] if the
    ///   range coder ends in a non-clean state at chunk end.
    /// - [`XzPortError::ChunkTruncated`] if the input slice
    ///   ends mid-chunk.
    /// - [`XzPortError::SinkIo`] if the output sink errors.
    /// - Other variants surfaced from
    ///   [`super::decoder::lzma_decode_port`].
    pub fn decode_stream(
        &mut self,
        input: &[u8],
        sink: &mut dyn Write,
    ) -> Result<usize, XzPortError> {
        let mut p: usize = 0;
        loop {
            let header = parse_lzma2_chunk_header(&input[p..])?;
            match header {
                Lzma2ChunkHeader::EndOfStream => {
                    p += 1;
                    return Ok(p);
                }
                Lzma2ChunkHeader::Uncompressed {
                    reset_dict,
                    uncompressed_size,
                } => {
                    self.dispatch_uncompressed(input, &mut p, reset_dict, uncompressed_size, sink)?;
                }
                Lzma2ChunkHeader::Lzma {
                    reset_state,
                    reset_props,
                    reset_dict,
                    uncompressed_size,
                    compressed_size,
                    properties,
                } => {
                    self.dispatch_lzma(
                        input,
                        &mut p,
                        reset_state,
                        reset_props,
                        reset_dict,
                        uncompressed_size,
                        compressed_size,
                        properties,
                        sink,
                    )?;
                }
            }
        }
    }

    fn dispatch_uncompressed(
        &mut self,
        input: &[u8],
        p: &mut usize,
        reset_dict: bool,
        uncompressed_size: u32,
        sink: &mut dyn Write,
    ) -> Result<(), XzPortError> {
        if self.needs_dict_reset && !reset_dict {
            // Liblzma also enforces this — first chunk in a
            // Block must reset the dict.
            return Err(XzPortError::FirstChunkMustResetDict(input[*p]));
        }
        if reset_dict {
            self.dict.reset();
            self.decoder.full_reset();
            self.needs_props = true;
            self.needs_dict_reset = false;
        }
        // Header is 3 bytes (control + 2-byte BE size-1).
        *p += 3;

        let chunk_end = p
            .checked_add(uncompressed_size as usize)
            .filter(|&e| e <= input.len())
            .ok_or(XzPortError::ChunkTruncated {
                compressed_size: uncompressed_size,
                available: input.len() - *p,
            })?;
        let chunk = &input[*p..chunk_end];

        // Send the bytes to the sink up front; the dict-write
        // loop below maintains the ring's `pos`/`full` so any
        // subsequent LZMA chunk's match-copies have the right
        // history.
        sink.write_all(chunk).map_err(XzPortError::SinkIo)?;

        // Wrap-loop: an uncompressed chunk may straddle the
        // dict's `size` boundary. Mirror of liblzma's
        // `decode_buffer` for the LZ-write path.
        let mut in_pos = 0usize;
        let mut left = uncompressed_size as usize;
        while left > 0 {
            if self.dict.pos == self.dict.size {
                self.dict.pos = 0;
            }
            let chunk_avail = self.dict.size - self.dict.pos;
            let this_step = left.min(chunk_avail);
            self.dict.set_limit(self.dict.pos + this_step);
            let pre_in = in_pos;
            let pre_left = left;
            self.dict
                .dict_write(chunk, &mut in_pos, chunk.len(), &mut left);
            debug_assert_eq!(in_pos - pre_in, this_step);
            debug_assert_eq!(pre_left - left, this_step);
        }
        *p = chunk_end;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn dispatch_lzma(
        &mut self,
        input: &[u8],
        p: &mut usize,
        reset_state: bool,
        reset_props: bool,
        reset_dict: bool,
        uncompressed_size: u32,
        compressed_size: u32,
        properties: Option<u8>,
        sink: &mut dyn Write,
    ) -> Result<(), XzPortError> {
        if self.needs_dict_reset && !reset_dict {
            return Err(XzPortError::FirstChunkMustResetDict(input[*p]));
        }

        if reset_dict {
            self.dict.reset();
            self.decoder.full_reset();
            self.needs_props = true;
            self.needs_dict_reset = false;
        } else if reset_state {
            self.decoder.full_reset();
            // Spec quirk: state-only reset KEEPS the prior
            // properties; needs_props stays as-is. But
            // `reset_props` (mode 0b110) sets a new properties
            // byte below.
        }

        // Header length: 5 bytes (control + 2-byte uncomp size
        // + 2-byte comp size) plus 1 byte if reset_props.
        let header_len = if reset_props { 6 } else { 5 };
        *p += header_len;

        if let Some(props_byte) = properties {
            let (lc, lp, pb) = decode_lzma_properties(props_byte)?;
            self.decoder
                .set_properties(u32::from(lc), u32::from(lp), u32::from(pb));
            self.needs_props = false;
        } else if self.needs_props {
            return Err(XzPortError::ChunkNeedsProperties);
        }

        // Each LZMA chunk starts a fresh range coder per the
        // LZMA2 spec. Mirror of liblzma's `rc_reset` at chunk
        // entry.
        self.decoder.rc = RangeDecoder::new();
        self.decoder.sequence = Sequence::Normalize;

        let chunk_end = p
            .checked_add(compressed_size as usize)
            .filter(|&e| e <= input.len())
            .ok_or(XzPortError::ChunkTruncated {
                compressed_size,
                available: input.len() - *p,
            })?;
        let chunk_payload = &input[*p..chunk_end];
        let mut in_pos = 0usize;
        let mut remaining = uncompressed_size as usize;

        // Reuse the staging buffer across chunks; clear() keeps
        // the allocation, only resets the length cursor.
        self.staging.clear();
        self.staging.reserve(uncompressed_size as usize);

        // Wrap-loop: see `dispatch_uncompressed` for the
        // rationale. liblzma's `decode_buffer` runs the same
        // shape for LZMA chunks too.
        while remaining > 0 {
            if self.dict.pos == self.dict.size {
                self.dict.pos = 0;
            }
            let chunk_avail = self.dict.size - self.dict.pos;
            let this_step = remaining.min(chunk_avail);
            let dict_start = self.dict.pos;
            self.dict.set_limit(self.dict.pos + this_step);
            let _status = lzma_decode_port(
                &mut self.decoder,
                &mut self.dict,
                chunk_payload,
                &mut in_pos,
            )?;
            let produced = self.dict.pos - dict_start;
            debug_assert_eq!(produced, this_step, "wrong byte count this step");
            // Pull produced bytes out of the dict ring into
            // the staging buffer in chronological order.
            // dict_get handles the wraparound, so we don't
            // need to special-case wrap here. Bulk-flushed to
            // the sink once per chunk, below.
            for i in 0..produced {
                let d = (produced - 1 - i) as u32;
                self.staging.push(self.dict.dict_get(d));
            }
            remaining -= produced;
        }
        sink.write_all(&self.staging).map_err(XzPortError::SinkIo)?;

        // Per the LZMA2 spec: the LZMA chunk's range coder
        // must be in the well-finished state at chunk end and
        // have consumed exactly the declared compressed_size.
        if !self.decoder.rc.is_finished_ok() || in_pos != compressed_size as usize {
            return Err(XzPortError::ChunkRangeCoderUnfinished {
                code: self.decoder.rc.code,
                leftover: compressed_size as usize - in_pos,
            });
        }

        *p = chunk_end;
        Ok(())
    }

    /// Return a read-only view of the inner dict. Mostly for
    /// tests / Phase 6 integration.
    #[must_use]
    pub fn dict_size(&self) -> usize {
        self.dict.size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::xz_native::block::{block_header_real_size, parse_block_header};
    use crate::decode::xz_native::stream::STREAM_HEADER_LEN;
    use crate::decode::xz_native::Decoder as XzNativeDecoder;
    use crate::decode::{DecodeStatus, StreamingDecoder};
    use std::io::Cursor;

    /// Encode `payload` with `xz2` at the given preset. Mirror
    /// of `tests/test_bench_xz_liblzma.rs::encode_xz`.
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

    /// Decode an `.xz` stream via [`Lzma2Decoder`], using
    /// `xz_native::block` to parse the Stream Header + Block
    /// Header (Phase 6 will port those). Returns the decoded
    /// bytes.
    fn decode_via_port(compressed: &[u8]) -> Vec<u8> {
        let mut p = STREAM_HEADER_LEN;
        let bh_len = block_header_real_size(compressed[p]);
        let block_header = parse_block_header(&compressed[p..p + bh_len]).expect("block header");
        p += bh_len;

        let mut dec = Lzma2Decoder::new(block_header.dict_size);
        let mut out: Vec<u8> = Vec::new();
        dec.decode_stream(&compressed[p..], &mut out)
            .expect("decode_stream");
        out
    }

    /// Decode the same .xz stream via the production
    /// `xz_native` decoder. Reference for differential tests.
    fn decode_via_xz_native(compressed: &[u8]) -> Vec<u8> {
        let source = Cursor::new(compressed.to_vec());
        let mut decoder = XzNativeDecoder::new(Box::new(source)).expect("xz_native decoder");
        let mut sink: Vec<u8> = Vec::new();
        loop {
            match decoder.decode_step(&mut sink).expect("decode_step") {
                DecodeStatus::Eof => break,
                DecodeStatus::MoreData => {}
            }
        }
        sink
    }

    /// Differential gate: peel-port output == xz_native
    /// output, both byte-identical to original payload.
    fn diff_check(payload: &[u8], preset: u32) {
        let compressed = encode_xz(payload, preset);
        let port = decode_via_port(&compressed);
        let native = decode_via_xz_native(&compressed);
        assert_eq!(port.len(), payload.len(), "port length mismatch");
        assert_eq!(native.len(), payload.len(), "native length mismatch");
        assert_eq!(port, payload, "port bytes != payload");
        assert_eq!(native, payload, "native bytes != payload");
        assert_eq!(port, native, "port bytes != native bytes");
    }

    /// Tiny: 32 bytes, single chunk.
    #[test]
    fn round_trip_tiny_lcg() {
        let payload: Vec<u8> = (0..32u32).map(|i| (i * 13) as u8).collect();
        diff_check(&payload, 6);
    }

    /// Highly-compressible 256-byte run — repeating a fixed
    /// vocabulary so xz emits matches.
    #[test]
    fn round_trip_repeating_pattern() {
        let mut payload = Vec::new();
        for _ in 0..16 {
            payload.extend_from_slice(b"the quick brown fox jumps over the lazy dog\n");
        }
        diff_check(&payload, 6);
    }

    /// Larger payload that spans multiple LZMA2 chunks.
    /// Compressible structured data → matches across chunk
    /// boundaries; exercises the dispatcher's chunk-to-chunk
    /// state preservation.
    #[test]
    fn round_trip_multi_chunk_compressible() {
        let mut payload = Vec::with_capacity(256 * 1024);
        for i in 0..2000 {
            payload
                .extend_from_slice(format!("entry {i:08}: status=ok action=ingest\n").as_bytes());
        }
        diff_check(&payload, 6);
    }

    /// Incompressible-ish (LCG) 256 KiB. Exercises uncompressed
    /// chunks (xz emits these for incompressible regions).
    #[test]
    fn round_trip_lcg_256kib() {
        let mut state: u64 = 0x00C0_FFEE_DEAD;
        let payload: Vec<u8> = (0..256 * 1024)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                (state >> 24) as u8
            })
            .collect();
        diff_check(&payload, 6);
    }

    /// Mixed: half compressible logs + half random — exercises
    /// the encoder's mode-switching across chunks.
    #[test]
    fn round_trip_mixed_compressible_and_random() {
        let mut payload = Vec::with_capacity(128 * 1024);
        for i in 0..500 {
            payload.extend_from_slice(format!("log {i}: GET /api/v1/users 200\n").as_bytes());
        }
        let mut state: u64 = 0xDEAD_BEEF_CAFE;
        for _ in 0..(64 * 1024) {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            payload.push((state >> 24) as u8);
        }
        diff_check(&payload, 6);
    }

    /// Cross-preset: same payload under presets 1, 6, and 9
    /// (different dict sizes, different chunk shapes).
    #[test]
    fn round_trip_across_presets() {
        let mut payload = Vec::new();
        for i in 0..1000 {
            payload.extend_from_slice(format!("row {i:05} | data | value\n").as_bytes());
        }
        for preset in [1u32, 3, 6, 9] {
            let compressed = encode_xz(&payload, preset);
            let port = decode_via_port(&compressed);
            assert_eq!(port, payload, "preset {preset} round-trip failed");
        }
    }

    // Empty-payload edge case is deferred to Phase 6: xz
    // encodes an empty payload as a 0-block stream where the
    // first byte after the Stream Header is the Index
    // Indicator (`0x00`), not a Block Header. Phase 6's
    // Stream-level dispatcher will route Index vs Block.
}
