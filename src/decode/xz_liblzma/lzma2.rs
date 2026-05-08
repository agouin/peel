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
//!
//! # Chunk-level streaming (Phase F.1)
//!
//! [`Lzma2Decoder::step`] consumes the caller's `input` slice
//! incrementally, returning [`Lzma2StepStatus::NeedInput`] when
//! the slice ends mid-chunk-header or mid-chunk-payload. The
//! decoder maintains a [`Lzma2Stage`] state machine across
//! calls so the caller can append more bytes and call again
//! without losing progress.
//!
//! Each LZMA2 chunk is still decoded by a single
//! [`super::decoder::lzma_decode_port`] call once its compressed
//! payload is fully buffered (≤ 64 KiB by spec). This avoids
//! per-bit Sequence-resume arms inside the inner loop while
//! still letting [`super::Decoder::decode_step`] interleave
//! source-reads with decode work — the slurp-first regression
//! at low bandwidth (Phase 8 cells 10 Mbps / 100 Mbps) is gone
//! once Phase F.2 wires this method into `Decoder::decode_step`.

use std::io::Write;

use super::block::{decode_lzma_properties, parse_lzma2_chunk_header, Lzma2ChunkHeader};

use super::decoder::{lzma_decode_port, Lzma1Decoder, Sequence};
use super::dict::LzmaDict;
use super::error::XzPortError;
use super::range_coder::RangeDecoder;

/// Chunk-level state machine for [`Lzma2Decoder::step`]. Mirror
/// of liblzma's `coder->sequence` member at the LZMA2 layer.
#[derive(Debug, Clone, Copy)]
enum Lzma2Stage {
    /// Need 1 byte: the chunk control byte. Either decodes to
    /// EndOfStream (single-byte chunk) or selects a header
    /// length and transitions to [`Lzma2Stage::AwaitHeader`].
    AwaitControl,
    /// Have the chunk control byte; need `header_len - 1` more
    /// bytes to parse the full header. `control` is reserved
    /// for re-checking on resume; `header_len` is the total
    /// header length on the wire (3 / 5 / 6 bytes).
    AwaitHeader { control: u8, header_len: u8 },
    /// Header parsed and applied; accumulating the chunk's
    /// compressed payload. `compressed_size` is from the
    /// header. `uncompressed_size` is the same. `is_lzma`
    /// distinguishes uncompressed-chunk from LZMA-chunk
    /// payload handling.
    AwaitPayload {
        is_lzma: bool,
        uncompressed_size: u32,
        compressed_size: u32,
    },
    /// EndOfStream chunk consumed; further calls report it.
    EndOfStream,
}

/// Result of one [`Lzma2Decoder::step`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lzma2StepStatus {
    /// Input slice exhausted before the in-flight stage could
    /// complete. Caller should append more bytes (preserving
    /// the prefix not yet consumed — `*in_pos` indicates how
    /// many bytes were consumed) and call `step` again.
    NeedInput,
    /// One LZMA2 chunk's worth of output was decoded and
    /// written to the sink. Caller may invoke `step` again to
    /// continue with the next chunk.
    Produced,
    /// The LZMA2 EndOfStream chunk has been consumed. No more
    /// LZMA2 work; the caller's stream-level walker should
    /// validate Block padding / Block check / Index / Stream
    /// Footer.
    EndOfStream,
}

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
/// Holds the full [`super::decoder::Lzma1Decoder`] +
/// [`super::dict::LzmaDict`] inline. The chunk-level state
/// machine ([`Lzma2Stage`]) lets the decoder pause between
/// chunks (Phase F.1) so input can be streamed in incrementally.
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
    /// Chunk-level state machine cursor. See [`Lzma2Stage`].
    stage: Lzma2Stage,
}

/// Length on the wire of an LZMA2 chunk header given its
/// control byte, before the compressed payload begins. Mirror
/// of [`crate::decode::xz_native::block::Lzma2ChunkHeader::wire_size`]
/// but derivable from the control byte alone — needed so the
/// streaming dispatcher can wait for the right number of header
/// bytes to arrive before parsing.
fn lzma2_header_len(control: u8) -> Result<usize, XzPortError> {
    match control {
        0x00 => Ok(1),
        0x01 | 0x02 => Ok(3),
        0x03..=0x7F => Err(XzPortError::Framing(format!(
            "reserved LZMA2 control byte 0x{control:02X}"
        ))),
        0x80..=0xFF => {
            // bits 7-5 : reset mode; reset_props is mode >= 0b110.
            let mode = (control >> 5) & 0b011;
            Ok(if mode >= 2 { 6 } else { 5 })
        }
    }
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
            stage: Lzma2Stage::AwaitControl,
        }
    }

    /// `true` if the last [`Lzma2Decoder::step`] call consumed
    /// the LZMA2 EndOfStream chunk. Useful for the stream-level
    /// driver (Phase F.2) to decide when to transition to Block
    /// Padding / Block-Check parsing.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        matches!(self.stage, Lzma2Stage::EndOfStream)
    }

    /// `true` if the decoder is between LZMA2 chunks (at
    /// [`Lzma2Stage::AwaitControl`]) and at least one chunk has
    /// already been processed (so `needs_dict_reset` is false
    /// and either props are set or we've only seen Uncompressed
    /// chunks). The Phase F.4 checkpoint blob captures only at
    /// this boundary; other stages would need per-bit cursor
    /// state we don't serialize.
    #[must_use]
    pub fn is_at_chunk_boundary(&self) -> bool {
        matches!(self.stage, Lzma2Stage::AwaitControl) && !self.needs_dict_reset
    }

    /// Read-only accessor: borrowed [`Lzma1Decoder`] state.
    /// Used by [`super::resume`] to snapshot probs / reps /
    /// state.
    #[must_use]
    pub fn decoder(&self) -> &Lzma1Decoder {
        &self.decoder
    }

    /// Read-only accessor: borrowed [`LzmaDict`].
    #[must_use]
    pub fn dict(&self) -> &LzmaDict {
        &self.dict
    }

    /// Read-only accessor: `needs_props` flag.
    #[must_use]
    pub fn needs_props(&self) -> bool {
        self.needs_props
    }

    /// Read-only accessor: `needs_dict_reset` flag.
    #[must_use]
    pub fn needs_dict_reset(&self) -> bool {
        self.needs_dict_reset
    }

    /// Reconstruct a [`Lzma2Decoder`] from a
    /// [`super::resume::XzPortResumeState`] capture. The
    /// returned decoder is positioned at
    /// [`Lzma2Stage::AwaitControl`] with the captured dict +
    /// probs + reps + state restored. Used by the Phase F.5
    /// resume_factory.
    #[must_use]
    pub fn from_resume(
        decoder: Lzma1Decoder,
        dict: LzmaDict,
        needs_props: bool,
        needs_dict_reset: bool,
    ) -> Self {
        Self {
            decoder,
            dict,
            staging: Vec::with_capacity(64 * 1024),
            needs_props,
            needs_dict_reset,
            stage: Lzma2Stage::AwaitControl,
        }
    }

    /// Decode one LZMA2 stream from `input`, writing
    /// uncompressed bytes to `sink`. Returns the number of
    /// bytes consumed from `input` (including the
    /// `EndOfStream` chunk's 1-byte control).
    ///
    /// `input` must contain a complete LZMA2 stream terminated
    /// by an `EndOfStream` chunk (`0x00` control byte). For
    /// incremental input, use [`Self::step`] directly.
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
            match self.step(input, &mut p, sink)? {
                Lzma2StepStatus::EndOfStream => return Ok(p),
                Lzma2StepStatus::Produced => {}
                Lzma2StepStatus::NeedInput => {
                    // The full-slice API mandates the entire
                    // LZMA2 stream is present; surfacing
                    // NeedInput here means the caller's slice
                    // was truncated mid-chunk.
                    let avail = input.len().saturating_sub(p);
                    return Err(XzPortError::ChunkTruncated {
                        compressed_size: 0,
                        available: avail,
                    });
                }
            }
        }
    }

    /// Drive the decoder forward consuming bytes from `input`
    /// (advancing `*in_pos`). Writes any decoded uncompressed
    /// bytes to `sink`. Phase F.1's chunk-level streaming
    /// entry point.
    ///
    /// Each call processes at most one LZMA2 chunk. If the
    /// input slice ends mid-header or mid-payload, the call
    /// returns [`Lzma2StepStatus::NeedInput`] without consuming
    /// bytes from the partial header / payload (so the caller's
    /// next call can re-supply them). The caller is responsible
    /// for ensuring the slice grows monotonically (i.e., bytes
    /// already inspected are still present at the same offsets
    /// on a re-call) until the decoder advances past them.
    ///
    /// # Errors
    ///
    /// As [`Self::decode_stream`], minus [`XzPortError::ChunkTruncated`]
    /// (the streaming model returns [`Lzma2StepStatus::NeedInput`]
    /// instead).
    pub fn step(
        &mut self,
        input: &[u8],
        in_pos: &mut usize,
        sink: &mut dyn Write,
    ) -> Result<Lzma2StepStatus, XzPortError> {
        loop {
            match self.stage {
                Lzma2Stage::EndOfStream => return Ok(Lzma2StepStatus::EndOfStream),
                Lzma2Stage::AwaitControl => {
                    if *in_pos >= input.len() {
                        return Ok(Lzma2StepStatus::NeedInput);
                    }
                    let control = input[*in_pos];
                    let header_len = lzma2_header_len(control)?;
                    if control == 0x00 {
                        // EndOfStream chunk: 1-byte header,
                        // no payload.
                        *in_pos += 1;
                        self.stage = Lzma2Stage::EndOfStream;
                        return Ok(Lzma2StepStatus::EndOfStream);
                    }
                    self.stage = Lzma2Stage::AwaitHeader {
                        control,
                        header_len: header_len as u8,
                    };
                    // Loop continues; AwaitHeader checks if we
                    // already have enough bytes.
                }
                Lzma2Stage::AwaitHeader {
                    control,
                    header_len,
                } => {
                    let need = header_len as usize;
                    if input.len() - *in_pos < need {
                        return Ok(Lzma2StepStatus::NeedInput);
                    }
                    let header = parse_lzma2_chunk_header(&input[*in_pos..*in_pos + need])?;
                    match header {
                        Lzma2ChunkHeader::EndOfStream => {
                            // Single-byte header — should have
                            // taken the AwaitControl shortcut.
                            // Belt-and-suspenders for forward
                            // compat.
                            *in_pos += 1;
                            self.stage = Lzma2Stage::EndOfStream;
                            return Ok(Lzma2StepStatus::EndOfStream);
                        }
                        Lzma2ChunkHeader::Uncompressed {
                            reset_dict,
                            uncompressed_size,
                        } => {
                            self.apply_uncompressed_resets(control, reset_dict)?;
                            *in_pos += need;
                            self.stage = Lzma2Stage::AwaitPayload {
                                is_lzma: false,
                                uncompressed_size,
                                compressed_size: uncompressed_size,
                            };
                        }
                        Lzma2ChunkHeader::Lzma {
                            reset_state,
                            reset_props,
                            reset_dict,
                            uncompressed_size,
                            compressed_size,
                            properties,
                        } => {
                            self.apply_lzma_resets(
                                control,
                                reset_state,
                                reset_props,
                                reset_dict,
                                properties,
                            )?;
                            *in_pos += need;
                            self.stage = Lzma2Stage::AwaitPayload {
                                is_lzma: true,
                                uncompressed_size,
                                compressed_size,
                            };
                        }
                    }
                }
                Lzma2Stage::AwaitPayload {
                    is_lzma,
                    uncompressed_size,
                    compressed_size,
                } => {
                    let need = compressed_size as usize;
                    if input.len() - *in_pos < need {
                        return Ok(Lzma2StepStatus::NeedInput);
                    }
                    let payload = &input[*in_pos..*in_pos + need];
                    if is_lzma {
                        self.decode_lzma_chunk(payload, uncompressed_size, compressed_size, sink)?;
                    } else {
                        self.decode_uncompressed_chunk(payload, uncompressed_size, sink)?;
                    }
                    *in_pos += need;
                    self.stage = Lzma2Stage::AwaitControl;
                    return Ok(Lzma2StepStatus::Produced);
                }
            }
        }
    }

    fn apply_uncompressed_resets(
        &mut self,
        control: u8,
        reset_dict: bool,
    ) -> Result<(), XzPortError> {
        if self.needs_dict_reset && !reset_dict {
            // Liblzma also enforces this — first chunk in a
            // Block must reset the dict.
            return Err(XzPortError::FirstChunkMustResetDict(control));
        }
        if reset_dict {
            self.dict.reset();
            self.decoder.full_reset();
            self.needs_props = true;
            self.needs_dict_reset = false;
        }
        Ok(())
    }

    fn apply_lzma_resets(
        &mut self,
        control: u8,
        reset_state: bool,
        _reset_props: bool,
        reset_dict: bool,
        properties: Option<u8>,
    ) -> Result<(), XzPortError> {
        if self.needs_dict_reset && !reset_dict {
            return Err(XzPortError::FirstChunkMustResetDict(control));
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

        if let Some(props_byte) = properties {
            let (lc, lp, pb) = decode_lzma_properties(props_byte)?;
            self.decoder
                .set_properties(u32::from(lc), u32::from(lp), u32::from(pb));
            self.needs_props = false;
        } else if self.needs_props {
            return Err(XzPortError::ChunkNeedsProperties);
        }

        Ok(())
    }

    fn decode_uncompressed_chunk(
        &mut self,
        chunk: &[u8],
        uncompressed_size: u32,
        sink: &mut dyn Write,
    ) -> Result<(), XzPortError> {
        debug_assert_eq!(chunk.len(), uncompressed_size as usize);

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
        Ok(())
    }

    fn decode_lzma_chunk(
        &mut self,
        chunk_payload: &[u8],
        uncompressed_size: u32,
        compressed_size: u32,
        sink: &mut dyn Write,
    ) -> Result<(), XzPortError> {
        debug_assert_eq!(chunk_payload.len(), compressed_size as usize);

        // Each LZMA chunk starts a fresh range coder per the
        // LZMA2 spec. Mirror of liblzma's `rc_reset` at chunk
        // entry.
        self.decoder.rc = RangeDecoder::new();
        self.decoder.sequence = Sequence::Normalize;

        let mut in_pos = 0usize;
        let mut remaining = uncompressed_size as usize;

        // Reuse the staging buffer across chunks; clear() keeps
        // the allocation, only resets the length cursor.
        self.staging.clear();
        self.staging.reserve(uncompressed_size as usize);

        // Wrap-loop: see `decode_uncompressed_chunk` for the
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
    use crate::decode::xz_liblzma::block::{block_header_real_size, parse_block_header};
    use crate::decode::xz_liblzma::stream::STREAM_HEADER_LEN;
    use std::io::{Cursor, Read};

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
    /// the local Stream Header / Block Header parsers. Returns
    /// the decoded bytes.
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

    /// Decode the same .xz stream via `xz2` (the third-party
    /// liblzma binding). Reference for differential tests.
    fn decode_via_xz2(compressed: &[u8]) -> Vec<u8> {
        let mut decoder = xz2::read::XzDecoder::new(Cursor::new(compressed.to_vec()));
        let mut sink: Vec<u8> = Vec::new();
        decoder.read_to_end(&mut sink).expect("xz2 decode");
        sink
    }

    /// Differential gate: peel-port output == xz2 output ==
    /// original payload.
    fn diff_check(payload: &[u8], preset: u32) {
        let compressed = encode_xz(payload, preset);
        let port = decode_via_port(&compressed);
        let xz2_out = decode_via_xz2(&compressed);
        assert_eq!(port.len(), payload.len(), "port length mismatch");
        assert_eq!(xz2_out.len(), payload.len(), "xz2 length mismatch");
        assert_eq!(port, payload, "port bytes != payload");
        assert_eq!(xz2_out, payload, "xz2 bytes != payload");
        assert_eq!(port, xz2_out, "port bytes != xz2 bytes");
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

    // ===== Phase F.1: chunk-level streaming via `step` =====

    /// Drive `Lzma2Decoder::step` against the LZMA2 substream
    /// of `compressed` (the bytes after the Stream Header and
    /// Block Header), exposing the input one byte at a time,
    /// and verify that the streaming path produces the same
    /// output as the bulk `decode_stream` path.
    fn decode_via_step_byte_at_a_time(compressed: &[u8]) -> Vec<u8> {
        let mut p = STREAM_HEADER_LEN;
        let bh_len = block_header_real_size(compressed[p]);
        let block_header = parse_block_header(&compressed[p..p + bh_len]).expect("block header");
        p += bh_len;
        let lzma2_full = &compressed[p..];

        let mut dec = Lzma2Decoder::new(block_header.dict_size);
        let mut out: Vec<u8> = Vec::new();
        let mut visible: usize = 0;
        let mut consumed: usize = 0;
        loop {
            let mut local_pos = consumed;
            match dec
                .step(&lzma2_full[..visible], &mut local_pos, &mut out)
                .expect("step")
            {
                Lzma2StepStatus::EndOfStream => return out,
                Lzma2StepStatus::Produced => {
                    consumed = local_pos;
                }
                Lzma2StepStatus::NeedInput => {
                    consumed = local_pos;
                    if visible >= lzma2_full.len() {
                        panic!(
                            "step asked for input past end of LZMA2 stream \
                             (visible={visible}, consumed={consumed})"
                        );
                    }
                    visible += 1;
                }
            }
        }
    }

    /// Same shape as `decode_via_step_byte_at_a_time` but
    /// reveals randomly-sized chunks, exercising the
    /// AwaitHeader / AwaitPayload partial paths under varied
    /// boundaries.
    fn decode_via_step_random_chunks(compressed: &[u8], seed: u64) -> Vec<u8> {
        let mut p = STREAM_HEADER_LEN;
        let bh_len = block_header_real_size(compressed[p]);
        let block_header = parse_block_header(&compressed[p..p + bh_len]).expect("block header");
        p += bh_len;
        let lzma2_full = &compressed[p..];

        let mut state = seed;
        let mut next_chunk = || {
            // Tiny LCG; uniform on 1..=4096.
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            ((state >> 33) as usize % 4096) + 1
        };

        let mut dec = Lzma2Decoder::new(block_header.dict_size);
        let mut out: Vec<u8> = Vec::new();
        let mut visible: usize = 0;
        let mut consumed: usize = 0;
        loop {
            let mut local_pos = consumed;
            match dec
                .step(&lzma2_full[..visible], &mut local_pos, &mut out)
                .expect("step")
            {
                Lzma2StepStatus::EndOfStream => return out,
                Lzma2StepStatus::Produced => {
                    consumed = local_pos;
                }
                Lzma2StepStatus::NeedInput => {
                    consumed = local_pos;
                    if visible >= lzma2_full.len() {
                        panic!(
                            "step asked for input past end of LZMA2 stream \
                             (visible={visible}, consumed={consumed})"
                        );
                    }
                    let bump = next_chunk().min(lzma2_full.len() - visible);
                    visible += bump;
                }
            }
        }
    }

    /// Compressible payload via byte-at-a-time streaming.
    /// Validates that step()'s NeedInput / AwaitControl /
    /// AwaitHeader / AwaitPayload state machine reaches the
    /// same output as the bulk path.
    #[test]
    fn step_byte_at_a_time_compressible() {
        let mut payload = Vec::new();
        for _ in 0..32 {
            payload.extend_from_slice(b"the quick brown fox jumps over the lazy dog\n");
        }
        let compressed = encode_xz(&payload, 6);
        let got = decode_via_step_byte_at_a_time(&compressed);
        assert_eq!(got, payload);
    }

    /// Larger compressible payload (multi-chunk LZMA2 stream),
    /// random-chunk streaming. Exercises the dispatcher with
    /// hundreds of NeedInput / Produced transitions.
    #[test]
    fn step_random_chunks_multi_chunk_compressible() {
        let mut payload = Vec::with_capacity(256 * 1024);
        for i in 0..2000 {
            payload
                .extend_from_slice(format!("entry {i:08}: status=ok action=ingest\n").as_bytes());
        }
        let compressed = encode_xz(&payload, 6);
        let got = decode_via_step_random_chunks(&compressed, 0xDEAD_BEEF_CAFE);
        assert_eq!(got, payload);
    }

    /// LCG (incompressible) payload — xz emits uncompressed
    /// chunks here, so the streaming path exercises the
    /// uncompressed-chunk branch heavily.
    #[test]
    fn step_random_chunks_incompressible_lcg() {
        let mut state: u64 = 0x00C0_FFEE_DEAD;
        let payload: Vec<u8> = (0..256 * 1024)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                (state >> 24) as u8
            })
            .collect();
        let compressed = encode_xz(&payload, 6);
        let got = decode_via_step_random_chunks(&compressed, 0xFEED_FACE);
        assert_eq!(got, payload);
    }

    /// Cross-preset streaming: same payload at presets 1/3/6/9
    /// via random-chunk streaming.
    #[test]
    fn step_random_chunks_across_presets() {
        let mut payload = Vec::new();
        for i in 0..1000 {
            payload.extend_from_slice(format!("row {i:05} | data | value\n").as_bytes());
        }
        for preset in [1u32, 3, 6, 9] {
            let compressed = encode_xz(&payload, preset);
            let got = decode_via_step_random_chunks(&compressed, 0x1234_5678 ^ u64::from(preset));
            assert_eq!(got, payload, "preset {preset} streaming round-trip failed");
        }
    }
}
