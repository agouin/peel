//! Phase 6 resume-blob layout for the hand-rolled xz decoder.
//!
//! Mirrors the contracts established by [`crate::decode::lz4`] and
//! [`crate::decode::zstd`]: a [`StreamingDecoder::decoder_state`]
//! call at an LZMA2-chunk boundary returns a self-describing byte
//! blob; a paired [`crate::decode::DecoderRegistry::register_resume_factory`]
//! handler consumes the blob plus the source byte offset and
//! reconstructs the decoder mid-Block, so a subsequent
//! `decode_step` produces the suffix of a clean run byte-
//! identically.
//!
//! # Why per-chunk granularity
//!
//! `docs/PLAN_xz_block_decoder.md` §"Why we're doing this": the
//! xz wrapper at `src/decode/xz.rs` only exposes per-Stream
//! resume points; on a single-Block `.tar.xz` (the dominant
//! shape) that means "restart from byte 0 on every kill -9." The
//! hand-rolled decoder's per-LZMA2-chunk boundaries (LZMA2
//! re-initializes the range coder per chunk; chunk-end is the
//! one place where compressed input is decoupled from in-flight
//! decoder state) make every chunk a clean restart point. The
//! resume blob captures everything else needed to make that
//! restart byte-identical.
//!
//! # What gets captured
//!
//! - Stream-level: Check ID, prior Blocks' `(unpadded,
//!   uncompressed)` Index records, records-seen counter.
//! - Block-level: Block Header geometry (size, optional declared
//!   compressed/uncompressed sizes, `dict_size`), running
//!   counters (LZMA2-stream start offset, decompressed-so-far),
//!   first-chunk flag.
//! - LZMA model: `(lc, lp, pb)`, 12-state machine state, `rep0..3`,
//!   the full probability tables.
//! - Dict: capacity, monotonic byte counter, the most recent
//!   `min(total, capacity)` bytes (chronological).
//! - Block-Check hasher: kind + variant-specific state (4 / 8 /
//!   105 bytes for CRC32 / CRC64 / SHA-256).
//!
//! Per the spike memo (Appendix A §1), the dict carries `total`
//! (not just `recent_bytes`) so the literal-context formula and
//! `pos_state` survive resume even when the dict has wrapped.
//! Multi-Block dict-floor tracking is round-one-deferred; the
//! blob shape leaves room for it via a future `format_version`
//! bump.
//!
//! # Wire format (`format_version = 1`)
//!
//! Every multi-byte integer is little-endian.
//!
//! ```text
//!  4 B    magic                 = b"XDR1"
//!  1 B    format_version        = 1
//!  1 B    stream_check          (raw CheckId nibble)
//!  4 B    records_seen          (u32 LE)
//!  records_seen * 16 B
//!         stream_block_records  (u64 LE unpadded, u64 LE uncomp) per record
//!  4 B    block_header_size_bytes (u32 LE)
//!  1 B    bit-flag byte:
//!           bit 0 — block_compressed_size declared
//!           bit 1 — block_uncompressed_size declared
//!           bit 2 — block_seen_first_chunk
//!           bit 3 — block_lzma2_finished
//!  8 B    block_compressed_size_declared (u64 LE; 0 when absent)
//!  8 B    block_uncompressed_size_declared (u64 LE; 0 when absent)
//!  4 B    block_dict_size (u32 LE)
//!  8 B    block_lzma2_start_offset (u64 LE)
//!  8 B    block_decompressed_so_far (u64 LE)
//!  1 B    lc
//!  1 B    lp
//!  1 B    pb
//!  1 B    state
//!  4*4 B  rep0..rep3 (u32 LE x 4)
//!  4 B    dict_capacity (u32 LE)
//!  8 B    dict_total (u64 LE)
//!  4 B    dict_data_len (u32 LE)
//!  N B    dict_data (chronological, oldest first)
//!  4 B    probs_len (u32 LE)
//!  N B    probs (per LzmaProbs::serialize_slots)
//!  4 B    check_state_len (u32 LE)
//!  N B    check_state (per BlockCheckHasher::serialize_state)
//!  4 B    crc32 over every byte from offset 0 through the byte
//!         immediately preceding this trailer
//! ```

use crate::hash::crc32::Crc32;

use super::block::BlockHeader;
use super::check::BlockCheckHasher;
use super::dict::LzmaDict;
use super::error::XzError;
use super::lzma2::Lzma2State;
use super::probs::LzmaProbs;
use super::stream::CheckId;

/// Magic at the head of every Phase 6 blob. ASCII for
/// `XDR1` — "Xz Decoder Resume version 1." Bumps to v2 happen by
/// changing the magic plus the format-version byte.
pub const MAGIC: &[u8; 4] = b"XDR1";

/// `format_version` byte for the v1 layout.
pub const FORMAT_VERSION: u8 = 1;

/// Captured state at an LZMA2 chunk boundary; everything needed
/// to resume the decoder byte-identically at that source offset.
#[derive(Debug, Clone)]
pub struct XzResumeState {
    /// `CheckId` of the surrounding Stream — the Block trailer's
    /// hash kind.
    pub stream_check: CheckId,
    /// Per-Block `(unpadded_size, uncompressed_size)` records
    /// observed in this Stream so far. Multi-Block streams
    /// inherit prior records here so the Index validation at
    /// Stream end is round-trip-correct.
    pub stream_block_records: Vec<(u64, u64)>,

    /// On-wire Block Header length (for Index `unpadded_size`
    /// recomputation at Block end).
    pub block_header_size_bytes: u32,
    /// Optional declared `Compressed_Size` from the Block Header.
    pub block_compressed_size_declared: Option<u64>,
    /// Optional declared `Uncompressed_Size` from the Block
    /// Header.
    pub block_uncompressed_size_declared: Option<u64>,
    /// Block Header's `dict_size` (capped at 64 MiB).
    pub block_dict_size: u32,
    /// Source-byte offset where the Block's LZMA2 stream began.
    pub block_lzma2_start_offset: u64,
    /// Decompressed bytes emitted in this Block so far.
    pub block_decompressed_so_far: u64,
    /// Whether at least one LZMA2 chunk in this Block has been
    /// processed (the "first chunk must reset dict" guard relies
    /// on this).
    pub block_seen_first_chunk: bool,
    /// Whether the LZMA2 EOS chunk (`0x00`) has been observed.
    /// Always `false` at a chunk-boundary capture point, but
    /// included for completeness so a future format bump can
    /// allow post-EOS captures.
    pub block_lzma2_finished: bool,

    /// LZMA literal-context bits.
    pub lc: u8,
    /// LZMA literal-position bits.
    pub lp: u8,
    /// LZMA position-state bits.
    pub pb: u8,
    /// LZMA 12-state machine state.
    pub lzma_state: u8,
    /// LZMA most-recent encoded distance (also the matched-
    /// literal source).
    pub rep0: u32,
    /// LZMA second-most-recent encoded distance.
    pub rep1: u32,
    /// LZMA third-most-recent encoded distance.
    pub rep2: u32,
    /// LZMA fourth-most-recent encoded distance.
    pub rep3: u32,

    /// Dict ring-buffer capacity.
    pub dict_capacity: u32,
    /// Dict monotonic byte counter (may exceed `dict_capacity`
    /// once the ring has wrapped).
    pub dict_total: u64,
    /// Dict's most recent `min(dict_total, dict_capacity)` bytes,
    /// chronological (oldest first).
    pub dict_data: Vec<u8>,

    /// Serialized LZMA probability tables. Exact byte count
    /// depends on `(lc, lp, pb)`.
    pub probs: Vec<u8>,

    /// Serialized Block-Check hasher state. Length depends on
    /// `stream_check`: 0 / 4 / 8 / 105 bytes.
    pub check_state: Vec<u8>,
}

impl XzResumeState {
    /// Bit-flag positions inside the 1-byte "block flags" field.
    const FLAG_COMPRESSED_DECLARED: u8 = 1 << 0;
    const FLAG_UNCOMPRESSED_DECLARED: u8 = 1 << 1;
    const FLAG_SEEN_FIRST_CHUNK: u8 = 1 << 2;
    const FLAG_LZMA2_FINISHED: u8 = 1 << 3;

    /// Capture state from a live `BlockCtx`-shaped tuple of
    /// references. Decoded at the [`super::Decoder::decoder_state`]
    /// call site; the fragment-shaped argument list keeps
    /// `xz_native.rs` free of a long borrow argument list.
    #[must_use]
    pub fn capture(args: CaptureArgs<'_>) -> Self {
        let probs_serialized = {
            let mut buf = Vec::with_capacity(args.lzma_state.probs.serialized_byte_len());
            args.lzma_state.probs.serialize_slots(&mut buf);
            buf
        };
        let check_state = {
            let mut buf = Vec::with_capacity(args.check_hasher.serialized_state_len());
            args.check_hasher.serialize_state(&mut buf);
            buf
        };
        let dict_capacity = args.lzma_state.dict.capacity() as u32;
        let dict_total = args.lzma_state.dict.total();
        let dict_data = args.lzma_state.dict.recent(args.lzma_state.dict.capacity());
        Self {
            stream_check: args.stream_check,
            stream_block_records: args.stream_block_records.to_vec(),
            block_header_size_bytes: args.block_header.header_size_bytes as u32,
            block_compressed_size_declared: args.block_header.compressed_size,
            block_uncompressed_size_declared: args.block_header.uncompressed_size,
            block_dict_size: args.block_header.dict_size,
            block_lzma2_start_offset: args.block_lzma2_start_offset,
            block_decompressed_so_far: args.block_decompressed_so_far,
            block_seen_first_chunk: args.block_seen_first_chunk,
            block_lzma2_finished: args.block_lzma2_finished,
            lc: args.lzma_state.probs.lc,
            lp: args.lzma_state.probs.lp,
            pb: args.lzma_state.probs.pb,
            lzma_state: args.lzma_state.state,
            rep0: args.lzma_state.rep0,
            rep1: args.lzma_state.rep1,
            rep2: args.lzma_state.rep2,
            rep3: args.lzma_state.rep3,
            dict_capacity,
            dict_total,
            dict_data,
            probs: probs_serialized,
            check_state,
        }
    }

    /// Encode `self` as a Phase 6 resume blob (see module docs).
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.estimated_size());
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.push(self.stream_check.raw());
        out.extend_from_slice(&(self.stream_block_records.len() as u32).to_le_bytes());
        for &(u, c) in &self.stream_block_records {
            out.extend_from_slice(&u.to_le_bytes());
            out.extend_from_slice(&c.to_le_bytes());
        }
        out.extend_from_slice(&self.block_header_size_bytes.to_le_bytes());
        let mut flags = 0u8;
        if self.block_compressed_size_declared.is_some() {
            flags |= Self::FLAG_COMPRESSED_DECLARED;
        }
        if self.block_uncompressed_size_declared.is_some() {
            flags |= Self::FLAG_UNCOMPRESSED_DECLARED;
        }
        if self.block_seen_first_chunk {
            flags |= Self::FLAG_SEEN_FIRST_CHUNK;
        }
        if self.block_lzma2_finished {
            flags |= Self::FLAG_LZMA2_FINISHED;
        }
        out.push(flags);
        out.extend_from_slice(
            &self
                .block_compressed_size_declared
                .unwrap_or(0)
                .to_le_bytes(),
        );
        out.extend_from_slice(
            &self
                .block_uncompressed_size_declared
                .unwrap_or(0)
                .to_le_bytes(),
        );
        out.extend_from_slice(&self.block_dict_size.to_le_bytes());
        out.extend_from_slice(&self.block_lzma2_start_offset.to_le_bytes());
        out.extend_from_slice(&self.block_decompressed_so_far.to_le_bytes());
        out.extend_from_slice(&[self.lc, self.lp, self.pb, self.lzma_state]);
        out.extend_from_slice(&self.rep0.to_le_bytes());
        out.extend_from_slice(&self.rep1.to_le_bytes());
        out.extend_from_slice(&self.rep2.to_le_bytes());
        out.extend_from_slice(&self.rep3.to_le_bytes());
        out.extend_from_slice(&self.dict_capacity.to_le_bytes());
        out.extend_from_slice(&self.dict_total.to_le_bytes());
        out.extend_from_slice(&(self.dict_data.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.dict_data);
        out.extend_from_slice(&(self.probs.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.probs);
        out.extend_from_slice(&(self.check_state.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.check_state);
        // Trailing CRC32 over everything before this point.
        let mut crc = Crc32::new();
        crc.update(&out);
        out.extend_from_slice(&crc.finalize().to_le_bytes());
        out
    }

    /// Decode a Phase 6 resume blob. The reverse of
    /// [`Self::serialize`].
    ///
    /// # Errors
    ///
    /// - [`XzError::ResumeBlobMagic`] for bad magic / version.
    /// - [`XzError::ResumeBlobTruncated`] when the blob ends mid-
    ///   field.
    /// - [`XzError::ResumeBlobLength`] when a declared field
    ///   length disagrees with the size implied by the
    ///   surrounding properties.
    /// - [`XzError::ResumeBlobCrc`] when the trailing CRC32 does
    ///   not match the computed hash.
    /// - [`XzError::ReservedCheckId`] / property errors via
    ///   [`LzmaProbs::deserialize`] when the embedded values are
    ///   out of spec range.
    pub fn deserialize(blob: &[u8]) -> Result<Self, XzError> {
        // Trailing CRC32: 4 bytes at the end.
        if blob.len() < 4 + MAGIC.len() + 1 {
            return Err(XzError::ResumeBlobTruncated("magic+version+CRC trailer"));
        }
        let crc_off = blob.len() - 4;
        let body = &blob[..crc_off];
        let mut crc = Crc32::new();
        crc.update(body);
        let got = crc.finalize();
        let expected = u32::from_le_bytes(blob[crc_off..].try_into().expect("len 4"));
        if expected != got {
            return Err(XzError::ResumeBlobCrc { expected, got });
        }

        let mut r = Reader::new(body);
        let magic = r.take(4, "magic")?;
        if magic != MAGIC {
            return Err(XzError::ResumeBlobMagic);
        }
        let version = r.read_u8("format_version")?;
        if version != FORMAT_VERSION {
            return Err(XzError::ResumeBlobMagic);
        }
        let stream_check = CheckId::from_raw(r.read_u8("stream_check")?)?;
        let records_seen = r.read_u32_le("records_seen")?;
        let mut stream_block_records = Vec::with_capacity(records_seen as usize);
        for _ in 0..records_seen {
            let unpadded = r.read_u64_le("Index unpadded_size")?;
            let uncomp = r.read_u64_le("Index uncompressed_size")?;
            stream_block_records.push((unpadded, uncomp));
        }
        let block_header_size_bytes = r.read_u32_le("block_header_size_bytes")?;
        let block_flags = r.read_u8("block_flags")?;
        let raw_compressed = r.read_u64_le("block_compressed_size_declared")?;
        let raw_uncompressed = r.read_u64_le("block_uncompressed_size_declared")?;
        let block_compressed_size_declared =
            (block_flags & Self::FLAG_COMPRESSED_DECLARED != 0).then_some(raw_compressed);
        let block_uncompressed_size_declared =
            (block_flags & Self::FLAG_UNCOMPRESSED_DECLARED != 0).then_some(raw_uncompressed);
        let block_dict_size = r.read_u32_le("block_dict_size")?;
        let block_lzma2_start_offset = r.read_u64_le("block_lzma2_start_offset")?;
        let block_decompressed_so_far = r.read_u64_le("block_decompressed_so_far")?;
        let lc = r.read_u8("lc")?;
        let lp = r.read_u8("lp")?;
        let pb = r.read_u8("pb")?;
        let lzma_state = r.read_u8("lzma_state")?;
        let rep0 = r.read_u32_le("rep0")?;
        let rep1 = r.read_u32_le("rep1")?;
        let rep2 = r.read_u32_le("rep2")?;
        let rep3 = r.read_u32_le("rep3")?;
        let dict_capacity = r.read_u32_le("dict_capacity")?;
        let dict_total = r.read_u64_le("dict_total")?;
        let dict_data_len = r.read_u32_le("dict_data_len")? as usize;
        let dict_data = r.take(dict_data_len, "dict_data")?.to_vec();
        let probs_len = r.read_u32_le("probs_len")? as usize;
        let probs = r.take(probs_len, "probs")?.to_vec();
        let check_state_len = r.read_u32_le("check_state_len")? as usize;
        let check_state = r.take(check_state_len, "check_state")?.to_vec();
        if !r.is_empty() {
            return Err(XzError::ResumeBlobLength {
                field: "trailing slack",
                declared: r.remaining() as u64,
                expected: 0,
            });
        }
        Ok(Self {
            stream_check,
            stream_block_records,
            block_header_size_bytes,
            block_compressed_size_declared,
            block_uncompressed_size_declared,
            block_dict_size,
            block_lzma2_start_offset,
            block_decompressed_so_far,
            block_seen_first_chunk: block_flags & Self::FLAG_SEEN_FIRST_CHUNK != 0,
            block_lzma2_finished: block_flags & Self::FLAG_LZMA2_FINISHED != 0,
            lc,
            lp,
            pb,
            lzma_state,
            rep0,
            rep1,
            rep2,
            rep3,
            dict_capacity,
            dict_total,
            dict_data,
            probs,
            check_state,
        })
    }

    fn estimated_size(&self) -> usize {
        4 + 1
            + 1
            + 4
            + self.stream_block_records.len() * 16
            + 4
            + 1
            + 8
            + 8
            + 4
            + 8
            + 8
            + 4
            + 16
            + 4
            + 8
            + 4
            + self.dict_data.len()
            + 4
            + self.probs.len()
            + 4
            + self.check_state.len()
            + 4
    }

    /// Reconstruct an [`Lzma2State`] from this blob.
    ///
    /// # Errors
    ///
    /// Forwards [`LzmaProbs::deserialize`] failures (out-of-range
    /// `(lc, lp, pb)` or `probs` length mismatch).
    pub fn build_lzma2_state(&self) -> Result<Lzma2State, XzError> {
        let probs = LzmaProbs::deserialize(self.lc, self.lp, self.pb, &self.probs)?;
        let mut dict = LzmaDict::new(self.dict_capacity);
        if self.dict_data.len() > dict.capacity() {
            return Err(XzError::ResumeBlobLength {
                field: "dict_data",
                declared: self.dict_data.len() as u64,
                expected: dict.capacity() as u64,
            });
        }
        dict.reload(&self.dict_data, self.dict_total);
        Ok(Lzma2State::from_parts(
            dict,
            probs,
            self.lzma_state,
            self.rep0,
            self.rep1,
            self.rep2,
            self.rep3,
        ))
    }

    /// Reconstruct a [`BlockCheckHasher`] from this blob.
    ///
    /// # Errors
    ///
    /// Forwards [`BlockCheckHasher::deserialize_state`] failures.
    pub fn build_check_hasher(&self) -> Result<BlockCheckHasher, XzError> {
        BlockCheckHasher::deserialize_state(self.stream_check, &self.check_state)
    }

    /// Reconstruct the [`BlockHeader`] portion of `BlockCtx`.
    #[must_use]
    pub fn block_header(&self) -> BlockHeader {
        BlockHeader {
            compressed_size: self.block_compressed_size_declared,
            uncompressed_size: self.block_uncompressed_size_declared,
            dict_size: self.block_dict_size,
            header_size_bytes: self.block_header_size_bytes as usize,
        }
    }
}

/// Borrowed argument bundle for [`XzResumeState::capture`].
/// Keeping the surface area focused on "the things `BlockCtx`
/// already has handy" — the resume module shouldn't reach into
/// xz_native's `Decoder` internals beyond what's spelled out
/// here.
pub struct CaptureArgs<'a> {
    /// The Stream's Check ID.
    pub stream_check: CheckId,
    /// Per-Block records observed in the current Stream so far.
    pub stream_block_records: &'a [(u64, u64)],
    /// The current Block's parsed Block Header.
    pub block_header: &'a BlockHeader,
    /// Source-byte offset where the Block's LZMA2 stream began.
    pub block_lzma2_start_offset: u64,
    /// Decompressed-bytes-so-far counter for the current Block.
    pub block_decompressed_so_far: u64,
    /// `BlockCtx::seen_first_chunk`.
    pub block_seen_first_chunk: bool,
    /// `BlockCtx::lzma2_finished`.
    pub block_lzma2_finished: bool,
    /// Live LZMA model state.
    pub lzma_state: &'a Lzma2State,
    /// Live Block Check hasher.
    pub check_hasher: &'a BlockCheckHasher,
}

/// Tiny no-allocation reader over a byte slice; used to walk the
/// resume blob's wire format without pulling in a full
/// `bytes::Buf`-style API. Mirrors the
/// [`crate::decode::lz4`] / [`crate::decode::zstd`] resume
/// modules' deserializer style.
struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.cursor)
    }

    fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn take(&mut self, n: usize, label: &'static str) -> Result<&'a [u8], XzError> {
        if self.remaining() < n {
            return Err(XzError::ResumeBlobTruncated(label));
        }
        let out = &self.bytes[self.cursor..self.cursor + n];
        self.cursor += n;
        Ok(out)
    }

    fn read_u8(&mut self, label: &'static str) -> Result<u8, XzError> {
        Ok(self.take(1, label)?[0])
    }

    fn read_u32_le(&mut self, label: &'static str) -> Result<u32, XzError> {
        Ok(u32::from_le_bytes(
            self.take(4, label)?.try_into().expect("len 4"),
        ))
    }

    fn read_u64_le(&mut self, label: &'static str) -> Result<u64, XzError> {
        Ok(u64::from_le_bytes(
            self.take(8, label)?.try_into().expect("len 8"),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::super::stream::DICT_SIZE_CAP;
    use super::*;

    /// Build a minimal `XzResumeState` for serialization tests.
    fn fixture_state() -> XzResumeState {
        // Build a fresh Lzma2State at default preset, push a few
        // bytes through the dict, capture.
        let mut state = Lzma2State::new(64 * 1024, 3, 0, 2).expect("alloc state");
        for &b in b"resume-fixture-payload" {
            state.dict.push(b);
        }
        state.state = 4;
        state.rep0 = 7;
        state.rep1 = 1;
        state.rep2 = 2;
        state.rep3 = 3;
        let mut hasher = BlockCheckHasher::new(CheckId::Crc64);
        hasher.update(b"hashed-bytes");

        let header = BlockHeader {
            compressed_size: Some(123),
            uncompressed_size: Some(456),
            dict_size: 64 * 1024,
            header_size_bytes: 12,
        };
        XzResumeState::capture(CaptureArgs {
            stream_check: CheckId::Crc64,
            stream_block_records: &[(40, 100)],
            block_header: &header,
            block_lzma2_start_offset: 12 + 12,
            block_decompressed_so_far: 22,
            block_seen_first_chunk: true,
            block_lzma2_finished: false,
            lzma_state: &state,
            check_hasher: &hasher,
        })
    }

    /// Round-trip serialize → deserialize matches every captured
    /// field.
    #[test]
    fn serialize_round_trip_preserves_all_fields() {
        let captured = fixture_state();
        let blob = captured.serialize();
        let restored = XzResumeState::deserialize(&blob).expect("deserialize");

        assert_eq!(captured.stream_check, restored.stream_check);
        assert_eq!(captured.stream_block_records, restored.stream_block_records);
        assert_eq!(
            captured.block_header_size_bytes,
            restored.block_header_size_bytes
        );
        assert_eq!(
            captured.block_compressed_size_declared,
            restored.block_compressed_size_declared
        );
        assert_eq!(
            captured.block_uncompressed_size_declared,
            restored.block_uncompressed_size_declared
        );
        assert_eq!(captured.block_dict_size, restored.block_dict_size);
        assert_eq!(
            captured.block_lzma2_start_offset,
            restored.block_lzma2_start_offset
        );
        assert_eq!(
            captured.block_decompressed_so_far,
            restored.block_decompressed_so_far
        );
        assert_eq!(
            captured.block_seen_first_chunk,
            restored.block_seen_first_chunk
        );
        assert_eq!(captured.lc, restored.lc);
        assert_eq!(captured.lp, restored.lp);
        assert_eq!(captured.pb, restored.pb);
        assert_eq!(captured.lzma_state, restored.lzma_state);
        assert_eq!(captured.rep0, restored.rep0);
        assert_eq!(captured.rep1, restored.rep1);
        assert_eq!(captured.rep2, restored.rep2);
        assert_eq!(captured.rep3, restored.rep3);
        assert_eq!(captured.dict_capacity, restored.dict_capacity);
        assert_eq!(captured.dict_total, restored.dict_total);
        assert_eq!(captured.dict_data, restored.dict_data);
        assert_eq!(captured.probs, restored.probs);
        assert_eq!(captured.check_state, restored.check_state);
    }

    /// `build_lzma2_state` produces a state whose dict / probs /
    /// reps match the captured originals byte-for-byte.
    #[test]
    fn build_lzma2_state_round_trip() {
        let captured = fixture_state();
        let blob = captured.serialize();
        let restored = XzResumeState::deserialize(&blob).expect("deserialize");
        let restored_state = restored.build_lzma2_state().expect("build");
        assert_eq!(restored_state.dict.total(), captured.dict_total);
        assert_eq!(restored_state.state, captured.lzma_state);
        assert_eq!(restored_state.rep0, captured.rep0);
        assert_eq!(restored_state.rep1, captured.rep1);
        assert_eq!(restored_state.rep2, captured.rep2);
        assert_eq!(restored_state.rep3, captured.rep3);
        assert_eq!(restored_state.probs.lc, captured.lc);
        assert_eq!(restored_state.probs.lp, captured.lp);
        assert_eq!(restored_state.probs.pb, captured.pb);
    }

    /// Deserialize rejects bad magic.
    #[test]
    fn deserialize_rejects_bad_magic() {
        let captured = fixture_state();
        let mut blob = captured.serialize();
        blob[0] = b'B';
        // Need to recompute the trailing CRC since we changed
        // the body.
        let crc_off = blob.len() - 4;
        let mut crc = Crc32::new();
        crc.update(&blob[..crc_off]);
        let new_crc = crc.finalize().to_le_bytes();
        blob[crc_off..].copy_from_slice(&new_crc);
        match XzResumeState::deserialize(&blob).unwrap_err() {
            XzError::ResumeBlobMagic => {}
            other => panic!("expected ResumeBlobMagic, got {other:?}"),
        }
    }

    /// Deserialize rejects a bit-flipped blob via the trailing
    /// CRC32 check — even when the magic, version, and lengths
    /// are still valid.
    #[test]
    fn deserialize_rejects_corrupted_body() {
        let captured = fixture_state();
        let mut blob = captured.serialize();
        // Corrupt one byte in the middle.
        let mid = blob.len() / 2;
        blob[mid] ^= 0x42;
        match XzResumeState::deserialize(&blob).unwrap_err() {
            XzError::ResumeBlobCrc { .. } => {}
            other => panic!("expected ResumeBlobCrc, got {other:?}"),
        }
    }

    /// Deserialize rejects a truncated blob.
    #[test]
    fn deserialize_rejects_truncation() {
        let captured = fixture_state();
        let blob = captured.serialize();
        let truncated = &blob[..blob.len() / 2];
        match XzResumeState::deserialize(truncated).unwrap_err() {
            XzError::ResumeBlobTruncated(_)
            | XzError::ResumeBlobLength { .. }
            | XzError::ResumeBlobMagic
            | XzError::ResumeBlobCrc { .. } => {}
            other => panic!("expected resume-blob error, got {other:?}"),
        }
    }

    /// dict_size > 64 MiB at deserialize time still routes through
    /// LzmaDict::new (which silently caps via MIN_DICT_SIZE only).
    /// The blob shape doesn't enforce the spec cap; that's the
    /// Block-Header parser's job. Pin this so the contract stays
    /// explicit.
    #[test]
    fn dict_capacity_above_spec_cap_round_trips() {
        let mut captured = fixture_state();
        // Note: this is *not* honoring the spec's cap; the
        // resume module is layer-blind.
        captured.dict_capacity = (DICT_SIZE_CAP + 1) as u32;
        let blob = captured.serialize();
        let restored = XzResumeState::deserialize(&blob).expect("deserialize");
        assert_eq!(restored.dict_capacity, captured.dict_capacity);
    }
}
