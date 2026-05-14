//! Hand-rolled, pure-Rust bzip2 streaming decoder.
//!
//! Implements `internal/PLAN_bz2_support.md`. The bzip2 wire format
//! is fixed by the original `bzip2` reference implementation
//! (Julian Seward, 1996–2010) and has not changed since 1.0.0.
//!
//! Bzip2 decoding inverts these stages, in order from the wire:
//!
//! 1. **Stream / block framing.** `BZh<level>` stream header, per-
//!    block 48-bit magic (`0x314159265359`), end-of-stream magic
//!    (`0x177245385090`), 32-bit stream CRC trailer.
//! 2. **Per-block header.** 32-bit block CRC, 1-bit randomised flag
//!    (rejected — see `internal/PLAN_bz2_support.md` §Deferred),
//!    24-bit BWT origin pointer, 16/256-bit "symbols used" map,
//!    3-bit `nGroups` (Huffman-table count, 2..=6), 15-bit
//!    `nSelectors` (group ranking length), delta-coded selector
//!    ranking, 2-6 canonical Huffman code-length tables.
//! 3. **Huffman + RLE2 inverse.** Decode symbols (MTF indices,
//!    RUNA, RUNB, EOB) through the per-group Huffman tables,
//!    expanding RUNA/RUNB into MTF-zero runs along the way.
//! 4. **MTF inverse.** Translate MTF indices back into bytes through
//!    a 256-entry move-to-front table seeded from the block's
//!    "symbols used" set.
//! 5. **BWT inverse.** Walk the FL-mapping table built from the
//!    block's `(L, origPtr)` to emit the original-order pre-RLE1
//!    byte stream.
//! 6. **CRC32.** Compute the bzip2 dialect of the IEEE 802.3 CRC
//!    over the pre-RLE1 bytes, compare to the block-header CRC,
//!    and combine into the running stream CRC via the bzip2
//!    rotate-and-XOR combiner.
//! 7. **RLE1 inverse.** Stream-level: the post-BWT bytes from every
//!    block run through a single RLE1 expansion whose state carries
//!    across block boundaries (but resets at every stream
//!    boundary). The final output is byte-identical to `bzip2 -d`.

use std::io::{Read, Write};

use crate::decode::{DecodeError, DecodeStatus, StreamingDecoder};
use crate::hash::crc32_bzip2::{combine_stream, Crc32Bzip2};
use crate::types::ByteOffset;

pub mod bitstream;
pub mod block;
pub mod body;
pub mod bwt;
pub mod error;
pub mod huffman;
pub mod mtf;
pub mod resume;
pub mod rle1;
pub mod rle2;
pub mod selectors;
pub mod stream;

use self::bitstream::BitReader;
use self::block::{parse_block_header, parse_block_marker, BlockHeader, BlockMarker};
use self::body::decode_block_symbols;
use self::bwt::invert as bwt_invert;
use self::error::Bzip2Error;
use self::mtf::MtfState;
use self::rle1::Rle1State;
use self::rle2::apply_inverse as rle2_inverse;
use self::selectors::parse_selectors;
use self::stream::{parse_stream_header, try_parse_stream_header, StreamHeader};

/// State machine driving the trait-level [`Bzip2Decoder::decode_step`].
#[derive(Debug)]
pub(super) enum State {
    /// No bytes consumed yet. The next step parses the stream
    /// header.
    AwaitingStreamHeader,
    /// Stream header parsed; the next step reads a 48-bit block
    /// marker.
    AwaitingBlockMarker { level: u8 },
    /// Compressed-block magic observed; the next step parses the
    /// pre-Huffman block header.
    AwaitingBlockHeader { level: u8 },
    /// Block header parsed; the next step decodes the block body
    /// (selectors + Huffman + MTF + BWT + CRC + RLE1 emit). The
    /// header is boxed to keep the [`State`] enum compact —
    /// `BlockHeader` carries a 256-byte symbol bitmap.
    AwaitingBlockBody { level: u8, header: Box<BlockHeader> },
    /// EOS magic observed; the next step reads the 32-bit
    /// combined-stream CRC.
    AwaitingStreamTrailer,
    /// Stream trailer validated; the next step probes for a
    /// following stream (multi-stream `.bz2`).
    AwaitingMultiStreamProbe,
    /// Stream is finished — every subsequent step is a no-op.
    Done,
}

/// Streaming pure-Rust bzip2 decoder.
///
/// Owns its source on construction (via [`BitReader`]); subsequent
/// [`StreamingDecoder::decode_step`] calls do not need it passed back
/// in. `Send` because the source and every inner buffer is `Send`.
pub struct Bzip2Decoder {
    pub(super) bits: BitReader,
    pub(super) state: State,
    /// Running CRC accumulator across every block in the current
    /// stream. Reset at every stream boundary.
    pub(super) stream_crc: u32,
    /// Cross-block RLE1 state. Reset at every stream boundary.
    pub(super) rle1: Rle1State,
    /// Latest restart-safe boundary inside the source, in source
    /// bytes. Updated at every transition into `AwaitingBlockMarker`
    /// / `AwaitingMultiStreamProbe`. Phase 8 attaches the per-
    /// boundary `decoder_state` blob to the bit-offset within this
    /// byte and the running state needed to resume.
    pub(super) last_frame_boundary: Option<ByteOffset>,
}

impl Bzip2Decoder {
    /// Construct a decoder over `src`. Does not pull any bytes from
    /// the source.
    ///
    /// # Errors
    ///
    /// Currently never returns `Err`; the signature is fallible to
    /// match [`crate::decode::DecoderFactory`].
    pub fn new(src: Box<dyn Read + Send>) -> Result<Self, DecodeError> {
        Ok(Self {
            bits: BitReader::new(src),
            state: State::AwaitingStreamHeader,
            stream_crc: 0,
            rle1: Rle1State::new(),
            last_frame_boundary: None,
        })
    }

    /// Internal: one step of the state machine, returning the
    /// internal error type. The trait-level `decode_step` wraps this
    /// with the [`Bzip2Error::into_decode_error`] boundary.
    fn step_inner(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, Bzip2Error> {
        loop {
            match &self.state {
                State::Done => return Ok(DecodeStatus::Eof),

                State::AwaitingStreamHeader => {
                    // The very first stream's header is required —
                    // an empty source is not a valid bzip2 file.
                    let header = parse_stream_header(&mut self.bits)?;
                    self.transition_to_block_marker(header.level);
                    // Don't return — keep going so the first
                    // observable step actually decodes a block.
                }

                State::AwaitingBlockMarker { level } => {
                    let level = *level;
                    let marker = parse_block_marker(&mut self.bits)?;
                    match marker {
                        BlockMarker::BlockStart => {
                            self.state = State::AwaitingBlockHeader { level };
                        }
                        BlockMarker::StreamEnd => {
                            self.state = State::AwaitingStreamTrailer;
                        }
                    }
                }

                State::AwaitingBlockHeader { level } => {
                    let level = *level;
                    let header = parse_block_header(&mut self.bits)?;
                    self.state = State::AwaitingBlockBody {
                        level,
                        header: Box::new(header),
                    };
                }

                State::AwaitingBlockBody { level, header } => {
                    let level = *level;
                    let header = (**header).clone();
                    self.process_block(level, &header, sink)?;
                    // After the block emits, expose the post-block
                    // boundary and yield so the extractor can punch
                    // / checkpoint.
                    self.transition_to_block_marker(level);
                    return Ok(DecodeStatus::MoreData);
                }

                State::AwaitingStreamTrailer => {
                    let trailer = self.bits.read_u32_be().map_err(|e| match e {
                        Bzip2Error::UnexpectedEof(_) => {
                            Bzip2Error::UnexpectedEof("combined stream CRC")
                        }
                        other => other,
                    })?;
                    if trailer != self.stream_crc {
                        return Err(Bzip2Error::StreamCrcMismatch {
                            expected: trailer,
                            computed: self.stream_crc,
                        });
                    }
                    self.state = State::AwaitingMultiStreamProbe;
                }

                State::AwaitingMultiStreamProbe => {
                    // Reset stream-scoped state (RLE1 + stream CRC)
                    // *before* probing the next header. This must
                    // happen even if the probe returns None, since
                    // any state we hold is for the just-finished
                    // stream.
                    self.rle1.reset();
                    self.stream_crc = 0;
                    // Align to the next byte boundary before
                    // looking for the next stream's header. The
                    // bzip2 encoder calls `bsFinishWrite` at the
                    // end of every stream, which drains and
                    // zero-pads the last byte; multi-stream
                    // archives (`cat a.bz2 b.bz2 > c.bz2`) place
                    // each subsequent stream's header byte at the
                    // next byte boundary. Without this skip the
                    // 8-bit `BZh<level>` reads would smear across
                    // the padding bits and surface as bad-magic.
                    self.bits.align_to_byte();
                    match try_parse_stream_header(&mut self.bits)? {
                        Some(StreamHeader { level }) => {
                            self.transition_to_block_marker(level);
                            // Yield so the boundary is observable
                            // — the stream boundary is a clean
                            // restart point.
                            return Ok(DecodeStatus::MoreData);
                        }
                        None => {
                            self.state = State::Done;
                            return Ok(DecodeStatus::Eof);
                        }
                    }
                }
            }
        }
    }

    /// Decode one full block. Reads selectors + Huffman tables +
    /// symbol stream from the bit reader, inverts MTF / RLE2 / BWT,
    /// runs the bytes through the stream-level RLE1 inverter into
    /// a per-block staging buffer, validates the block CRC against
    /// that buffer's CRC32, and flushes the buffer into `sink`.
    ///
    /// The block CRC is computed over the RLE1-**expanded** byte
    /// stream — i.e. the bytes the decoder ultimately emits for
    /// this block, not the BWT-inverse output. (The bzip2
    /// reference's `BZ_FINALISE_CRC` macro updates the per-block
    /// hasher in the output emit loop, after RLE1 expansion;
    /// `internal/PLAN_bz2_support.md` Phase 5's prose elided this
    /// distinction.) The RLE1 inverter's state carries across the
    /// block boundary so a run that straddles two blocks decodes
    /// without seam artefacts.
    fn process_block(
        &mut self,
        level: u8,
        header: &BlockHeader,
        sink: &mut dyn Write,
    ) -> Result<(), Bzip2Error> {
        let selectors = parse_selectors(&mut self.bits)?;
        let num_used = header.num_symbols_used();
        let max_symbols = u32::from(level) * 100_000;
        let symbols = decode_block_symbols(&mut self.bits, &selectors, num_used, max_symbols)?;
        let mut mtf_state = MtfState::new(&header.symbols_used);
        let post_mtf = rle2_inverse(&symbols.symbols, &mut mtf_state, max_symbols)?;
        let post_bwt = bwt_invert(&post_mtf, header.orig_ptr)?;

        // Stage the RLE1-expanded output into a per-block buffer so
        // we can hash it before handing it to the sink. RLE1 state
        // carries across block boundaries (same `self.rle1`
        // instance), but the buffer + block CRC are scoped per
        // block. A `Vec<u8>` is `std::io::Write` so the RLE1
        // inverter writes to it directly.
        //
        // The buffer's worst-case size is `post_bwt.len() + 255 *
        // count_byte_count`, but we don't bound that here — the
        // RLE1 inverter does its own per-byte append and the
        // outer block-symbol cap (Phase 4's `BlockTooLarge` guard)
        // already bounds total output growth.
        let mut block_out: Vec<u8> = Vec::with_capacity(post_bwt.len());
        self.rle1.feed_slice(&post_bwt, &mut block_out)?;

        let mut block_hasher = Crc32Bzip2::new();
        block_hasher.update(&block_out);
        let computed = block_hasher.finalize();
        if computed != header.block_crc {
            return Err(Bzip2Error::BlockCrcMismatch {
                expected: header.block_crc,
                computed,
            });
        }
        // Fold the block CRC into the running stream CRC.
        self.stream_crc = combine_stream(self.stream_crc, computed);

        // Flush the staged output to the sink.
        sink.write_all(&block_out).map_err(Bzip2Error::SinkIo)?;
        Ok(())
    }

    fn transition_to_block_marker(&mut self, level: u8) {
        // Record the byte-floor boundary at this transition. The
        // boundary's bit-offset within the byte (typically
        // non-zero) goes on the Phase 8 resume blob; callers that
        // ignore the blob and resume via the regular factory
        // observe byte-aligned semantics, which is correct only at
        // stream boundaries that happen to fall on byte ends.
        let (byte_pos, _bit_off) = self.bits.byte_position();
        self.last_frame_boundary = Some(ByteOffset::new(byte_pos));
        self.state = State::AwaitingBlockMarker { level };
    }
}

impl StreamingDecoder for Bzip2Decoder {
    fn decode_step(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, DecodeError> {
        if matches!(self.state, State::Done) {
            return Ok(DecodeStatus::Eof);
        }
        match self.step_inner(sink) {
            Ok(status) => Ok(status),
            Err(e) => {
                let consumed = self.bits.byte_position().0;
                // Errors are terminal — clamp to Done so further
                // calls short-circuit cleanly.
                self.state = State::Done;
                Err(e.into_decode_error(consumed))
            }
        }
    }

    fn bytes_consumed(&self) -> ByteOffset {
        // Bit-reader byte-floor: bytes strictly before this index
        // are fully consumed and safe for the puncher to release.
        ByteOffset::new(self.bits.byte_position().0)
    }

    fn frame_boundary(&self) -> Option<ByteOffset> {
        // Advanced at every transition into `AwaitingBlockMarker`
        // / `AwaitingMultiStreamProbe`. Phase 8 adds the
        // `decoder_state` blob with the bit-offset within the
        // returned byte; callers that bypass the blob get byte-
        // aligned semantics only — correct only at stream
        // boundaries that happen to land on a byte end.
        self.last_frame_boundary
    }

    fn set_source_start_offset(&mut self, offset: u64) {
        // Only seed when the BitReader is fresh (no bits buffered,
        // no bytes pulled). Resume factory builds the BitReader
        // already positioned at the saved offset and may have
        // consumed bits to skip past the boundary's bit-offset —
        // reseating after that smear would either underreport or
        // trip the BitReader::set_byte_offset guard.
        if self.bits.is_untouched() {
            self.bits.set_byte_offset(offset);
        }
    }

    fn decoder_state_into(&self, out: &mut Vec<u8>) -> bool {
        // Resume blob is only snapshotable at the per-block
        // boundary inside a stream — the point where every block-
        // internal scratch (BWT inverse table, MTF table, Huffman
        // tables) is freshly empty by spec. Other states either
        // hold mid-block scratch we don't serialize, or land at
        // points where the regular factory already works (the
        // initial pre-stream-header state).
        let State::AwaitingBlockMarker { level } = self.state else {
            return false;
        };
        if self.last_frame_boundary.is_none() {
            return false;
        }
        let (byte_offset, bit_offset) = self.bits.byte_position();
        let blob = resume::Bzip2ResumeState {
            level,
            byte_offset,
            bit_offset,
            stream_crc: self.stream_crc,
            rle1_last: self.rle1.last(),
            rle1_run: self.rle1.run(),
        };
        blob.serialize_into(out);
        true
    }

    fn decoder_state_size_hint(&self) -> usize {
        resume::RESUME_BLOB_SIZE
    }
}

/// [`crate::decode::DecoderFactory`] adapter for [`Bzip2Decoder`].
///
/// # Errors
///
/// Forwards any error returned by [`Bzip2Decoder::new`].
pub fn factory(src: Box<dyn Read + Send>) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    Ok(Box::new(Bzip2Decoder::new(src)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;
    use std::process::{Command, Stdio};

    /// Compress `input` via the system `bzip2 -c` CLI at level 9,
    /// returning the encoded bytes. Used for end-to-end byte-
    /// identical round-trip checks against the upstream reference.
    fn bzip2_encode(input: &[u8], level: u8) -> Vec<u8> {
        let level_flag = format!("-{level}");
        let mut child = Command::new("bzip2")
            .arg("-c")
            .arg(level_flag)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn bzip2");
        {
            use std::io::Write as _;
            let stdin = child.stdin.as_mut().expect("stdin");
            stdin.write_all(input).expect("write stdin");
        }
        let out = child.wait_with_output().expect("wait bzip2");
        assert!(out.status.success(), "bzip2 -c failed: {:?}", out.status);
        out.stdout
    }

    fn decode_to_vec(compressed: Vec<u8>) -> Result<Vec<u8>, DecodeError> {
        let mut decoder = Bzip2Decoder::new(Box::new(Cursor::new(compressed)))?;
        let mut sink = Vec::new();
        while decoder.decode_step(&mut sink)? == DecodeStatus::MoreData {}
        Ok(sink)
    }

    #[test]
    fn round_trips_hello_world() {
        let input = b"hello, world\n".to_vec();
        let compressed = bzip2_encode(&input, 9);
        let decoded = decode_to_vec(compressed).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn round_trips_short_repeating_input() {
        let input = b"aaaaabbbbbcccccddddd".to_vec();
        let compressed = bzip2_encode(&input, 9);
        let decoded = decode_to_vec(compressed).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn round_trips_lipsum_at_level_1() {
        // Level 1 forces blocks at 100 KB — input here is shorter
        // so we get a single block, but the smaller alphabet
        // exercises shorter Huffman codes than level 9.
        let lipsum = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(10);
        let input = lipsum.as_bytes().to_vec();
        let compressed = bzip2_encode(&input, 1);
        let decoded = decode_to_vec(compressed).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn round_trips_120kb_forces_multiple_blocks_at_level_1() {
        // 120 KB at level 1 (100 KB block) → 2 blocks. Exercises
        // the per-block CRC + stream CRC + cross-block RLE1 state
        // path together. Capped at 120 KB so the unit-test pass
        // stays under a few seconds in debug builds; a larger
        // exercise lives in the crash-test harness (Phase 11).
        let mut state = 0x1357_9BDFu32;
        let mut input = vec![0u8; 120 * 1024];
        for b in &mut input {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            *b = (state >> 16) as u8;
        }
        let compressed = bzip2_encode(&input, 1);
        let decoded = decode_to_vec(compressed).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn round_trips_run_heavy_input() {
        // Long runs trigger RLE1: 1000 'a's then 1000 'b's then
        // 1000 'c's. Each run forces the RLE1 inverter to consume
        // count bytes; the runs span block boundaries at level 1
        // only at much larger sizes, so this is a single-block
        // test for the RLE1 inverter inside one block.
        let mut input = Vec::new();
        input.extend(std::iter::repeat_n(b'a', 1000));
        input.extend(std::iter::repeat_n(b'b', 1000));
        input.extend(std::iter::repeat_n(b'c', 1000));
        let compressed = bzip2_encode(&input, 9);
        let decoded = decode_to_vec(compressed).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn multi_stream_concatenation_decodes_concatenated_output() {
        let a = b"first stream contents\n".to_vec();
        let b = b"second stream contents\n".to_vec();
        let mut concat = bzip2_encode(&a, 9);
        concat.extend(bzip2_encode(&b, 9));
        let decoded = decode_to_vec(concat).expect("decode");
        let mut expected = a;
        expected.extend(b);
        assert_eq!(decoded, expected);
    }

    #[test]
    fn empty_input_is_a_valid_bzip2_stream() {
        let input = Vec::new();
        let compressed = bzip2_encode(&input, 9);
        // bzip2 emits a valid stream for empty input — the
        // resulting stream has a stream header, no compressed
        // blocks, an EOS marker, and a zero stream CRC. Decoder
        // must accept it cleanly.
        let decoded = decode_to_vec(compressed).expect("decode");
        assert!(decoded.is_empty());
    }

    #[test]
    fn bytes_consumed_is_monotone() {
        let input = b"some input text for monotonicity testing\n".to_vec();
        let compressed = bzip2_encode(&input, 9);
        let compressed_len = compressed.len();
        let mut decoder = Bzip2Decoder::new(Box::new(Cursor::new(compressed))).expect("construct");
        let mut sink = Vec::new();
        let mut prev = 0u64;
        loop {
            let status = decoder.decode_step(&mut sink).expect("step");
            let now = decoder.bytes_consumed().get();
            assert!(now >= prev, "bytes_consumed regressed from {prev} to {now}");
            assert!(
                now <= compressed_len as u64,
                "bytes_consumed exceeded source"
            );
            prev = now;
            if status == DecodeStatus::Eof {
                break;
            }
        }
    }

    #[test]
    fn frame_boundary_advances_at_block_boundaries() {
        // 120 KB at level 1 → 2 blocks → at least 2 frame
        // boundary updates over the run.
        let mut state = 0xAAAA_5555u32;
        let mut input = vec![0u8; 120 * 1024];
        for b in &mut input {
            state = state.wrapping_mul(1103515245).wrapping_add(12345);
            *b = (state >> 16) as u8;
        }
        let compressed = bzip2_encode(&input, 1);
        let mut decoder = Bzip2Decoder::new(Box::new(Cursor::new(compressed))).expect("construct");
        let mut sink = Vec::new();
        let mut prev_boundary: Option<u64> = None;
        let mut boundary_updates = 0u32;
        loop {
            let status = decoder.decode_step(&mut sink).expect("step");
            if let Some(b) = decoder.frame_boundary() {
                let val = b.get();
                if prev_boundary != Some(val) {
                    boundary_updates += 1;
                    prev_boundary = Some(val);
                }
            }
            if status == DecodeStatus::Eof {
                break;
            }
        }
        assert!(
            boundary_updates >= 2,
            "expected ≥ 2 frame boundary updates, got {boundary_updates}"
        );
        assert_eq!(sink, input);
    }

    #[test]
    fn repeated_calls_after_eof_stay_eof() {
        let input = b"steady-state\n".to_vec();
        let compressed = bzip2_encode(&input, 9);
        let mut decoder = Bzip2Decoder::new(Box::new(Cursor::new(compressed))).expect("construct");
        let mut sink = Vec::new();
        loop {
            if decoder.decode_step(&mut sink).expect("step") == DecodeStatus::Eof {
                break;
            }
        }
        for _ in 0..5 {
            assert_eq!(
                decoder.decode_step(&mut sink).expect("idempotent eof"),
                DecodeStatus::Eof
            );
        }
    }

    #[test]
    fn bad_magic_surfaces_decode_error() {
        let mut compressed = bzip2_encode(b"data", 9);
        compressed[0] = b'X';
        match decode_to_vec(compressed) {
            Err(DecodeError::Read { source, .. }) => {
                assert!(source.to_string().contains("bad stream magic"));
            }
            other => panic!("expected DecodeError::Read, got {other:?}"),
        }
    }

    #[test]
    fn truncated_stream_surfaces_unexpected_eof() {
        let mut compressed = bzip2_encode(b"data", 9);
        // Drop the last 4 bytes (the trailing combined CRC) and
        // we should still emit the body but fail at trailer time.
        let original_len = compressed.len();
        compressed.truncate(original_len - 4);
        match decode_to_vec(compressed) {
            Err(DecodeError::Read { source, .. }) => {
                let s = source.to_string();
                assert!(
                    s.contains("unexpected EOF") || s.contains("EOF"),
                    "unexpected message: {s}"
                );
            }
            Ok(_) => panic!("expected error, got Ok"),
            other => panic!("expected DecodeError::Read, got {other:?}"),
        }
    }

    /// Drive a decoder until it next reports a frame boundary; return
    /// every per-block boundary observed (as `(blob, source_offset,
    /// output_so_far)`) plus the final decoded output.
    fn collect_boundary_blobs(compressed: &[u8]) -> (Vec<BoundaryObservation>, Vec<u8>) {
        let mut decoder =
            Bzip2Decoder::new(Box::new(Cursor::new(compressed.to_vec()))).expect("construct");
        let mut sink = Vec::new();
        let mut blobs: Vec<BoundaryObservation> = Vec::new();
        let mut last_recorded: Option<u64> = None;
        loop {
            let status = decoder.decode_step(&mut sink).expect("step");
            let boundary = decoder.frame_boundary().map(|b| b.get());
            // Capture a blob the first time we observe each fresh
            // boundary value, while we're still at a snapshot-able
            // state. The trait's `decoder_state` returns `Some` only
            // at `AwaitingBlockMarker` boundaries.
            if let Some(boundary_offset) = boundary {
                if last_recorded != Some(boundary_offset) {
                    if let Some(blob) = decoder.decoder_state() {
                        blobs.push(BoundaryObservation {
                            blob,
                            source_offset: boundary_offset,
                            output_prefix: sink.clone(),
                        });
                        last_recorded = Some(boundary_offset);
                    }
                }
            }
            if status == DecodeStatus::Eof {
                break;
            }
        }
        (blobs, sink)
    }

    /// `(resume blob, source byte offset, decoded output up to that
    /// point)` for a single captured frame-boundary observation.
    struct BoundaryObservation {
        blob: Vec<u8>,
        source_offset: u64,
        output_prefix: Vec<u8>,
    }

    #[test]
    fn resume_blob_round_trips_at_every_block_boundary() {
        // A multi-block input at level 1 — picked to give at least
        // a few per-block boundary captures we can resume from.
        // 130 KB at level 1 → 2 blocks, so we get one mid-stream
        // boundary to resume from.
        let mut state = 0xCAFE_BABEu32;
        let mut input = vec![0u8; 130 * 1024];
        for b in &mut input {
            state = state.wrapping_mul(1103515245).wrapping_add(12345);
            *b = (state >> 16) as u8;
        }
        let compressed = bzip2_encode(&input, 1);
        let (blobs, expected) = collect_boundary_blobs(&compressed);
        assert_eq!(expected, input);
        assert!(
            !blobs.is_empty(),
            "expected at least one captured resume blob"
        );

        // For each captured boundary, resume from there with a
        // fresh decoder and verify the concatenation matches the
        // full expected output.
        for obs in &blobs {
            let suffix_source = compressed[obs.source_offset as usize..].to_vec();
            let mut resumed = resume::resume_factory(
                Box::new(Cursor::new(suffix_source)),
                &obs.blob,
                obs.source_offset,
            )
            .expect("resume_factory");
            let mut sink = Vec::new();
            while resumed.decode_step(&mut sink).expect("resumed step") == DecodeStatus::MoreData {}
            let mut combined = obs.output_prefix.clone();
            combined.extend(sink);
            assert_eq!(
                combined, input,
                "resume from boundary at offset {} produced wrong output",
                obs.source_offset,
            );
        }
    }

    #[test]
    fn resume_factory_rejects_offset_mismatch() {
        let input = b"some payload data\n".to_vec();
        let compressed = bzip2_encode(&input, 9);
        let (blobs, _) = collect_boundary_blobs(&compressed);
        if let Some(obs) = blobs.first() {
            // Construct with the wrong start_offset — should
            // surface `ResumeMismatch` per the
            // `PLAN_responsiveness.md` §3.2 contract.
            let suffix_source = compressed[obs.source_offset as usize..].to_vec();
            let bad_offset = obs.source_offset.saturating_add(1);
            let result =
                resume::resume_factory(Box::new(Cursor::new(suffix_source)), &obs.blob, bad_offset);
            match result {
                Err(DecodeError::ResumeMismatch { expected, actual }) => {
                    assert_eq!(expected, obs.source_offset);
                    assert_eq!(actual, bad_offset);
                }
                Err(e) => panic!("expected ResumeMismatch, got {e:?}"),
                Ok(_) => panic!("expected ResumeMismatch, got Ok"),
            }
        }
        // If no boundaries were captured (input was too small for
        // multi-block), the test silently passes — the mismatch
        // path is exercised by the resume module's own unit tests.
    }
}
