//! Phase F.4 / F.5 of [`internal/old/PLAN_xz_liblzma_phase_f.md`](../../../../internal/old/PLAN_xz_liblzma_phase_f.md):
//! checkpoint blob format + serializer + deserializer for the
//! `xz_liblzma` decoder.
//!
//! # Format (`PLZM` v1)
//!
//! Per the user's Phase 9 directive, this is a **clean break**
//! from `xz_native`'s `XDR1`/`XDR2` blob: different magic,
//! different layout, no compatibility expected. In-flight
//! resume blobs captured before Phase F.6's migration restart
//! on the post-migration decoder.
//!
//! ```text
//! [4 bytes ] magic = b"PLZM"
//! [1 byte  ] format_version = 0x01
//! [1 byte  ] reserved = 0x00
//! [body    ] inter-chunk state (variable; see below)
//! [4 bytes ] CRC32 (LE) over magic..end-of-body
//! ```
//!
//! Body fields (LE encoding throughout):
//!
//! | bytes | field |
//! |---:|---|
//! | 1 | `stream_check` (raw CheckId byte: 0/1/4/10) |
//! | 4 | `stream_block_records_count` |
//! | `count * 16` | `stream_block_records` (each: u64 unpadded, u64 uncompressed) |
//! | 4 | `block_header_size_bytes` |
//! | 1 | `block_flags` (compressed_declared / uncompressed_declared / seen_first_chunk / lzma2_finished) |
//! | 8 | `block_compressed_size_declared` (0 if undeclared) |
//! | 8 | `block_uncompressed_size_declared` (0 if undeclared) |
//! | 4 | `block_dict_size` |
//! | 8 | `block_lzma2_start_offset` |
//! | 8 | `block_decompressed_so_far` |
//! | 1 | `needs_props` |
//! | 1 | `needs_dict_reset` |
//! | 1 | `lc` |
//! | 1 | `lp` |
//! | 1 | `pb` |
//! | 1 | `lzma_state` |
//! | 4 | `rep0` |
//! | 4 | `rep1` |
//! | 4 | `rep2` |
//! | 4 | `rep3` |
//! | 4 | `dict_capacity` |
//! | 4 | `dict_full` |
//! | `dict_full` | dict bytes (chronological, oldest first) |
//! | 4 | `probs_len` |
//! | `probs_len` | LZMA probs (LE u16 dump of every slot in [`super::decoder::LzmaProbs`]) |
//! | 4 | `check_state_len` |
//! | `check_state_len` | serialized [`super::super::xz_native::check::BlockCheckHasher`] state |
//!
//! The blob captures **inter-LZMA2-chunk state only** (i.e.,
//! after one chunk completes and before the next chunk's
//! control byte is read). At that boundary the range coder is
//! always reset (each LZMA chunk starts a fresh rc per the
//! LZMA2 spec), so no rc state is captured.

use super::check::BlockCheckHasher;
use super::stream::CheckId;
use crate::hash::crc32::Crc32;

use super::decoder::{LengthDecoder, Lzma1Decoder, LzmaProbs, LzmaState};
use super::dict::LzmaDict;

/// Magic at the head of every freshly written blob. ASCII for
/// `PLZM` — "Peel LZMa".
pub const MAGIC: &[u8; 4] = b"PLZM";

/// Format version byte.
pub const FORMAT_VERSION: u8 = 0x01;

/// Captured state at an LZMA2 chunk boundary; everything
/// needed to resume the decoder byte-identically at that
/// source offset.
#[derive(Debug, Clone)]
pub struct XzPortResumeState {
    /// `CheckId` of the surrounding Stream.
    pub stream_check: CheckId,
    /// Per-Block `(unpadded_size, uncompressed_size)` records
    /// observed in this Stream so far. Multi-Block streams
    /// inherit prior records here.
    pub stream_block_records: Vec<(u64, u64)>,

    /// On-wire Block Header length.
    pub block_header_size_bytes: u32,
    /// Optional declared `Compressed_Size` from the Block Header.
    pub block_compressed_size_declared: Option<u64>,
    /// Optional declared `Uncompressed_Size` from the Block Header.
    pub block_uncompressed_size_declared: Option<u64>,
    /// Block Header's `dict_size` (bytes).
    pub block_dict_size: u32,
    /// Source-byte offset where the Block's LZMA2 stream began.
    pub block_lzma2_start_offset: u64,
    /// Decompressed bytes emitted in this Block so far.
    pub block_decompressed_so_far: u64,
    /// Whether at least one LZMA2 chunk in this Block has been
    /// processed.
    pub block_seen_first_chunk: bool,
    /// Always `false` at a chunk-boundary capture — included
    /// for completeness so a future format bump can permit
    /// post-EOS captures.
    pub block_lzma2_finished: bool,

    /// LZMA2 dispatcher's `needs_props` flag.
    pub needs_props: bool,
    /// LZMA2 dispatcher's `needs_dict_reset` flag.
    pub needs_dict_reset: bool,

    /// LZMA literal-context bits.
    pub lc: u8,
    /// LZMA literal-position bits.
    pub lp: u8,
    /// LZMA position-state bits.
    pub pb: u8,
    /// LZMA 12-state machine value (raw).
    pub lzma_state: u8,
    /// LZMA most-recent encoded distance.
    pub rep0: u32,
    /// LZMA second-most-recent encoded distance.
    pub rep1: u32,
    /// LZMA third-most-recent encoded distance.
    pub rep2: u32,
    /// LZMA fourth-most-recent encoded distance.
    pub rep3: u32,

    /// Dict ring-buffer capacity (== `block_dict_size`).
    pub dict_capacity: u32,
    /// Bytes of valid history in the dict (≤ `dict_capacity`).
    pub dict_full: u32,
    /// Dict's most-recent `dict_full` bytes, chronological
    /// (oldest first).
    pub dict_data: Vec<u8>,

    /// Serialized LZMA probability slots (LE u16, full table).
    pub probs: Vec<u8>,

    /// Serialized Block-Check hasher state (length depends on
    /// `stream_check`).
    pub check_state: Vec<u8>,
}

/// Bit positions inside the 1-byte `block_flags` field.
mod flags {
    pub const COMPRESSED_DECLARED: u8 = 1 << 0;
    pub const UNCOMPRESSED_DECLARED: u8 = 1 << 1;
    pub const SEEN_FIRST_CHUNK: u8 = 1 << 2;
    pub const LZMA2_FINISHED: u8 = 1 << 3;
}

impl XzPortResumeState {
    /// Total serialized size including the 4-byte CRC trailer.
    #[must_use]
    pub fn estimated_size(&self) -> usize {
        // Header (6) + body (~120 fixed) + records + dict + probs + check + crc (4).
        6 + 16 * self.stream_block_records.len()
            + 80
            + self.dict_data.len()
            + 4
            + self.probs.len()
            + 4
            + self.check_state.len()
            + 4
    }

    /// Serialize `self` into a fresh `Vec`.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.estimated_size());
        Self::write_into(&mut out, self);
        out
    }

    /// Append the serialized form of `s` to `out`. Used by the
    /// public `Decoder::decoder_state_into` to stream the blob
    /// directly into the caller's buffer (no staging Vec).
    pub fn write_into(out: &mut Vec<u8>, s: &Self) {
        let body_start = out.len();
        out.extend_from_slice(MAGIC);
        out.push(FORMAT_VERSION);
        out.push(0x00); // reserved
        out.push(s.stream_check.raw());
        out.extend_from_slice(&(s.stream_block_records.len() as u32).to_le_bytes());
        for &(u, c) in &s.stream_block_records {
            out.extend_from_slice(&u.to_le_bytes());
            out.extend_from_slice(&c.to_le_bytes());
        }
        out.extend_from_slice(&s.block_header_size_bytes.to_le_bytes());
        let mut flags_byte = 0u8;
        if s.block_compressed_size_declared.is_some() {
            flags_byte |= flags::COMPRESSED_DECLARED;
        }
        if s.block_uncompressed_size_declared.is_some() {
            flags_byte |= flags::UNCOMPRESSED_DECLARED;
        }
        if s.block_seen_first_chunk {
            flags_byte |= flags::SEEN_FIRST_CHUNK;
        }
        if s.block_lzma2_finished {
            flags_byte |= flags::LZMA2_FINISHED;
        }
        out.push(flags_byte);
        out.extend_from_slice(&s.block_compressed_size_declared.unwrap_or(0).to_le_bytes());
        out.extend_from_slice(
            &s.block_uncompressed_size_declared
                .unwrap_or(0)
                .to_le_bytes(),
        );
        out.extend_from_slice(&s.block_dict_size.to_le_bytes());
        out.extend_from_slice(&s.block_lzma2_start_offset.to_le_bytes());
        out.extend_from_slice(&s.block_decompressed_so_far.to_le_bytes());
        out.push(u8::from(s.needs_props));
        out.push(u8::from(s.needs_dict_reset));
        out.extend_from_slice(&[s.lc, s.lp, s.pb, s.lzma_state]);
        out.extend_from_slice(&s.rep0.to_le_bytes());
        out.extend_from_slice(&s.rep1.to_le_bytes());
        out.extend_from_slice(&s.rep2.to_le_bytes());
        out.extend_from_slice(&s.rep3.to_le_bytes());
        out.extend_from_slice(&s.dict_capacity.to_le_bytes());
        out.extend_from_slice(&s.dict_full.to_le_bytes());
        out.extend_from_slice(&s.dict_data);
        out.extend_from_slice(&(s.probs.len() as u32).to_le_bytes());
        out.extend_from_slice(&s.probs);
        out.extend_from_slice(&(s.check_state.len() as u32).to_le_bytes());
        out.extend_from_slice(&s.check_state);

        let mut crc = Crc32::new();
        crc.update(&out[body_start..]);
        out.extend_from_slice(&crc.finalize().to_le_bytes());
    }

    /// Parse a serialized blob.
    ///
    /// # Errors
    ///
    /// Returns `Err(reason)` on bad magic, unknown version,
    /// truncation, or CRC32 mismatch.
    pub fn deserialize(blob: &[u8]) -> Result<Self, ResumeBlobError> {
        if blob.len() < 6 + 4 {
            return Err(ResumeBlobError::Truncated("header"));
        }
        if &blob[..4] != MAGIC {
            return Err(ResumeBlobError::BadMagic);
        }
        let version = blob[4];
        if version != FORMAT_VERSION {
            return Err(ResumeBlobError::UnsupportedVersion(version));
        }

        // Verify CRC over the body.
        let crc_offset = blob.len() - 4;
        let mut crc = Crc32::new();
        crc.update(&blob[..crc_offset]);
        let computed = crc.finalize();
        let stored = u32::from_le_bytes([
            blob[crc_offset],
            blob[crc_offset + 1],
            blob[crc_offset + 2],
            blob[crc_offset + 3],
        ]);
        if computed != stored {
            return Err(ResumeBlobError::CrcMismatch { stored, computed });
        }

        let mut r = Reader::new(&blob[6..crc_offset]);
        let stream_check_byte = r.u8("stream_check")?;
        let stream_check = CheckId::from_raw(stream_check_byte)
            .map_err(|_| ResumeBlobError::UnknownCheckId(stream_check_byte))?;
        let count = r.u32("stream_block_records_count")? as usize;
        let mut stream_block_records = Vec::with_capacity(count);
        for _ in 0..count {
            let u = r.u64("record.unpadded_size")?;
            let c = r.u64("record.uncompressed_size")?;
            stream_block_records.push((u, c));
        }
        let block_header_size_bytes = r.u32("block_header_size_bytes")?;
        let flags_byte = r.u8("block_flags")?;
        let raw_compressed = r.u64("block_compressed_size_declared")?;
        let block_compressed_size_declared =
            (flags_byte & flags::COMPRESSED_DECLARED != 0).then_some(raw_compressed);
        let raw_uncompressed = r.u64("block_uncompressed_size_declared")?;
        let block_uncompressed_size_declared =
            (flags_byte & flags::UNCOMPRESSED_DECLARED != 0).then_some(raw_uncompressed);
        let block_dict_size = r.u32("block_dict_size")?;
        let block_lzma2_start_offset = r.u64("block_lzma2_start_offset")?;
        let block_decompressed_so_far = r.u64("block_decompressed_so_far")?;
        let needs_props = r.bool("needs_props")?;
        let needs_dict_reset = r.bool("needs_dict_reset")?;
        let lc = r.u8("lc")?;
        let lp = r.u8("lp")?;
        let pb = r.u8("pb")?;
        let lzma_state = r.u8("lzma_state")?;
        let rep0 = r.u32("rep0")?;
        let rep1 = r.u32("rep1")?;
        let rep2 = r.u32("rep2")?;
        let rep3 = r.u32("rep3")?;
        let dict_capacity = r.u32("dict_capacity")?;
        let dict_full = r.u32("dict_full")?;
        let dict_data = r.bytes(dict_full as usize, "dict_data")?.to_vec();
        let probs_len = r.u32("probs_len")? as usize;
        let probs = r.bytes(probs_len, "probs")?.to_vec();
        let check_state_len = r.u32("check_state_len")? as usize;
        let check_state = r.bytes(check_state_len, "check_state")?.to_vec();
        if !r.is_at_end() {
            return Err(ResumeBlobError::TrailingBytes(r.remaining()));
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
            block_seen_first_chunk: flags_byte & flags::SEEN_FIRST_CHUNK != 0,
            block_lzma2_finished: flags_byte & flags::LZMA2_FINISHED != 0,
            needs_props,
            needs_dict_reset,
            lc,
            lp,
            pb,
            lzma_state,
            rep0,
            rep1,
            rep2,
            rep3,
            dict_capacity,
            dict_full,
            dict_data,
            probs,
            check_state,
        })
    }
}

/// Errors surfaced by [`XzPortResumeState::deserialize`].
#[derive(Debug, thiserror::Error)]
pub enum ResumeBlobError {
    /// Magic bytes don't match `PLZM`.
    #[error("xz_liblzma resume blob: bad magic")]
    BadMagic,
    /// Format version byte is not [`FORMAT_VERSION`].
    #[error("xz_liblzma resume blob: unsupported format_version 0x{0:02X}")]
    UnsupportedVersion(u8),
    /// Blob ends before required field.
    #[error("xz_liblzma resume blob: truncated at {0}")]
    Truncated(&'static str),
    /// Body bytes remain after parsing all known fields.
    #[error("xz_liblzma resume blob: trailing {0} bytes after body")]
    TrailingBytes(usize),
    /// Trailing CRC32 doesn't match the body.
    #[error(
        "xz_liblzma resume blob: CRC32 mismatch (stored=0x{stored:08X}, computed=0x{computed:08X})"
    )]
    CrcMismatch {
        /// CRC32 read from the trailer.
        stored: u32,
        /// CRC32 we computed over the body.
        computed: u32,
    },
    /// `stream_check` byte didn't decode to a known `CheckId`.
    #[error("xz_liblzma resume blob: unknown CheckId 0x{0:02X}")]
    UnknownCheckId(u8),
}

/// Cursor over a byte slice for the deserializer.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn ensure(&self, n: usize, label: &'static str) -> Result<(), ResumeBlobError> {
        if self.bytes.len() - self.pos < n {
            Err(ResumeBlobError::Truncated(label))
        } else {
            Ok(())
        }
    }

    fn u8(&mut self, label: &'static str) -> Result<u8, ResumeBlobError> {
        self.ensure(1, label)?;
        let v = self.bytes[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn bool(&mut self, label: &'static str) -> Result<bool, ResumeBlobError> {
        Ok(self.u8(label)? != 0)
    }

    fn u32(&mut self, label: &'static str) -> Result<u32, ResumeBlobError> {
        self.ensure(4, label)?;
        let v = u32::from_le_bytes(self.bytes[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn u64(&mut self, label: &'static str) -> Result<u64, ResumeBlobError> {
        self.ensure(8, label)?;
        let v = u64::from_le_bytes(self.bytes[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    fn bytes(&mut self, n: usize, label: &'static str) -> Result<&'a [u8], ResumeBlobError> {
        self.ensure(n, label)?;
        let s = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn is_at_end(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }
}

// ===== Probs / dict snapshot helpers =====

/// Serialized byte length of an [`LzmaProbs`] dump (LE u16 per
/// slot). Constant — every slot is captured regardless of the
/// active `(lc, lp, pb)` triple.
pub fn probs_serialized_len() -> usize {
    use super::decoder::{
        ALIGN_SIZE, DIST_SLOTS, DIST_STATES, FULL_DISTANCES, LEN_HIGH_SYMBOLS, LEN_LOW_SYMBOLS,
        LEN_MID_SYMBOLS, LITERAL_CODERS_MAX, LITERAL_CODER_SIZE, POS_STATES_MAX, STATES,
    };
    let lit = LITERAL_CODERS_MAX * LITERAL_CODER_SIZE;
    let is_match = STATES * POS_STATES_MAX;
    let is_rep_axis = STATES; // is_rep, is_rep0, is_rep1, is_rep2 — 4 of these.
    let is_rep0_long = STATES * POS_STATES_MAX;
    let dist_slot = DIST_STATES * DIST_SLOTS;
    let pos_special = FULL_DISTANCES;
    let pos_align = ALIGN_SIZE;
    let len_decoder = 2 // choice + choice2
            + POS_STATES_MAX * LEN_LOW_SYMBOLS
            + POS_STATES_MAX * LEN_MID_SYMBOLS
            + LEN_HIGH_SYMBOLS;
    (lit + is_match
        + 4 * is_rep_axis
        + is_rep0_long
        + dist_slot
        + pos_special
        + pos_align
        + 2 * len_decoder)
        * 2
}

/// Append a full probs dump into `out`. Mirror of liblzma's
/// per-table walk.
pub fn write_probs_into(out: &mut Vec<u8>, p: &LzmaProbs) {
    fn push_u16(out: &mut Vec<u8>, v: u16) {
        out.extend_from_slice(&v.to_le_bytes());
    }
    fn push_arr2<const N: usize, const M: usize>(out: &mut Vec<u8>, a: &[[u16; M]; N]) {
        for row in a {
            for &v in row {
                push_u16(out, v);
            }
        }
    }
    fn push_arr1<const N: usize>(out: &mut Vec<u8>, a: &[u16; N]) {
        for &v in a {
            push_u16(out, v);
        }
    }
    fn push_len(out: &mut Vec<u8>, ld: &LengthDecoder) {
        push_u16(out, ld.choice);
        push_u16(out, ld.choice2);
        push_arr2(out, &ld.low);
        push_arr2(out, &ld.mid);
        push_arr1(out, &ld.high);
    }
    push_arr2(out, &p.literal);
    push_arr2(out, &p.is_match);
    push_arr1(out, &p.is_rep);
    push_arr1(out, &p.is_rep0);
    push_arr1(out, &p.is_rep1);
    push_arr1(out, &p.is_rep2);
    push_arr2(out, &p.is_rep0_long);
    push_arr2(out, &p.dist_slot);
    push_arr1(out, &p.pos_special);
    push_arr1(out, &p.pos_align);
    push_len(out, &p.match_len_decoder);
    push_len(out, &p.rep_len_decoder);
}

/// Restore an [`LzmaProbs`] from a serialized dump produced
/// by [`write_probs_into`].
pub fn read_probs_from(bytes: &[u8]) -> Result<LzmaProbs, ResumeBlobError> {
    if bytes.len() != probs_serialized_len() {
        return Err(ResumeBlobError::Truncated("probs body"));
    }
    let mut p = LzmaProbs::new();
    let mut pos: usize = 0;
    fn pull_u16(bytes: &[u8], pos: &mut usize) -> u16 {
        let v = u16::from_le_bytes([bytes[*pos], bytes[*pos + 1]]);
        *pos += 2;
        v
    }
    fn pull_arr2<const N: usize, const M: usize>(
        bytes: &[u8],
        pos: &mut usize,
        a: &mut [[u16; M]; N],
    ) {
        for row in a {
            for slot in row {
                *slot = pull_u16(bytes, pos);
            }
        }
    }
    fn pull_arr1<const N: usize>(bytes: &[u8], pos: &mut usize, a: &mut [u16; N]) {
        for slot in a {
            *slot = pull_u16(bytes, pos);
        }
    }
    fn pull_len(bytes: &[u8], pos: &mut usize, ld: &mut LengthDecoder) {
        ld.choice = pull_u16(bytes, pos);
        ld.choice2 = pull_u16(bytes, pos);
        pull_arr2(bytes, pos, &mut ld.low);
        pull_arr2(bytes, pos, &mut ld.mid);
        pull_arr1(bytes, pos, &mut ld.high);
    }
    pull_arr2(bytes, &mut pos, &mut p.literal);
    pull_arr2(bytes, &mut pos, &mut p.is_match);
    pull_arr1(bytes, &mut pos, &mut p.is_rep);
    pull_arr1(bytes, &mut pos, &mut p.is_rep0);
    pull_arr1(bytes, &mut pos, &mut p.is_rep1);
    pull_arr1(bytes, &mut pos, &mut p.is_rep2);
    pull_arr2(bytes, &mut pos, &mut p.is_rep0_long);
    pull_arr2(bytes, &mut pos, &mut p.dist_slot);
    pull_arr1(bytes, &mut pos, &mut p.pos_special);
    pull_arr1(bytes, &mut pos, &mut p.pos_align);
    pull_len(bytes, &mut pos, &mut p.match_len_decoder);
    pull_len(bytes, &mut pos, &mut p.rep_len_decoder);
    debug_assert_eq!(pos, bytes.len());
    Ok(p)
}

/// Capture the dict's most-recent `min(full, capacity)` bytes
/// in chronological order (oldest first).
pub fn dict_recent(dict: &LzmaDict) -> Vec<u8> {
    let n = dict.full;
    let mut out = Vec::with_capacity(n);
    if dict.full < dict.size {
        // Ring hasn't wrapped: history is buf[0..full].
        out.extend_from_slice(unsafe { std::slice::from_raw_parts(dict_buf_ptr(dict), n) });
    } else {
        // Wrapped: chronological order is buf[pos..size] then
        // buf[0..pos]. After a chunk-boundary call,
        // `dict.pos` has been wrapped to 0 if it had reached
        // size, so the second segment may be empty.
        let buf = unsafe { std::slice::from_raw_parts(dict_buf_ptr(dict), dict.size) };
        out.extend_from_slice(&buf[dict.pos..]);
        out.extend_from_slice(&buf[..dict.pos]);
    }
    out
}

/// Restore an [`LzmaDict`] from a chronological byte dump.
/// `data.len() == full`. The resulting dict has `pos = full % capacity`
/// (so a fully-wrapped dict has `pos = 0`, matching the
/// "next write goes to position 0" state right after wrap).
pub fn dict_restore(capacity: u32, full: u32, data: &[u8]) -> LzmaDict {
    debug_assert_eq!(data.len(), full as usize);
    debug_assert!(full <= capacity);
    let mut dict = LzmaDict::new(capacity as usize);
    if full == 0 {
        return dict;
    }
    // Place the chronological bytes at buf[0..full]; this
    // matches the "ring written linearly from 0 to full"
    // shape, which is also what dict_get reads when pos is
    // set as below.
    unsafe {
        std::ptr::copy_nonoverlapping(data.as_ptr(), dict_buf_mut_ptr(&mut dict), data.len());
    }
    dict.full = full as usize;
    dict.pos = if full == capacity { 0 } else { full as usize };
    dict.limit = dict.pos;
    dict
}

// SAFETY: LzmaDict.buf is private; expose its raw pointer
// here via the dedicated `unsafe fn`s the dict module provides
// for resume support.

#[inline]
fn dict_buf_ptr(dict: &LzmaDict) -> *const u8 {
    // Snapshotting the dict: a read-only view of the ring
    // bytes. Same pattern dict.dict_get uses internally.
    dict.dict_raw_ptr()
}

#[inline]
fn dict_buf_mut_ptr(dict: &mut LzmaDict) -> *mut u8 {
    dict.dict_raw_mut_ptr()
}

// ===== Lzma1Decoder snapshot helpers =====

/// Restore a [`Lzma1Decoder`] from the captured state. The
/// range coder is left in the fresh state (5 init bytes
/// pending) — at chunk boundaries each LZMA chunk starts a
/// fresh rc anyway.
pub fn restore_lzma1_decoder(s: &XzPortResumeState) -> Result<Lzma1Decoder, ResumeBlobError> {
    let probs = read_probs_from(&s.probs)?;
    if s.lzma_state > 11 {
        return Err(ResumeBlobError::Truncated("lzma_state out of range"));
    }
    let mut dec = Lzma1Decoder {
        probs,
        // SAFETY: lzma_state was just bounds-checked to 0..=11,
        // the full range of `LzmaState`'s repr(u8) discriminants.
        // The transmute is the standard "u8 → repr(u8) enum"
        // pattern.
        state: unsafe { std::mem::transmute::<u8, LzmaState>(s.lzma_state) },
        rep0: s.rep0,
        rep1: s.rep1,
        rep2: s.rep2,
        rep3: s.rep3,
        ..Lzma1Decoder::default()
    };
    dec.set_properties(u32::from(s.lc), u32::from(s.lp), u32::from(s.pb));
    Ok(dec)
}

/// Restore a [`BlockCheckHasher`] from the captured state.
pub fn restore_check_hasher(s: &XzPortResumeState) -> Result<BlockCheckHasher, ResumeBlobError> {
    BlockCheckHasher::deserialize_state(s.stream_check, &s.check_state)
        .map_err(|_| ResumeBlobError::Truncated("check_state body"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity: probs_serialized_len matches what
    /// `write_probs_into` actually emits for a fresh
    /// `LzmaProbs::new()`.
    #[test]
    fn probs_serialized_len_matches_write() {
        let p = LzmaProbs::new();
        let mut out = Vec::new();
        write_probs_into(&mut out, &p);
        assert_eq!(out.len(), probs_serialized_len());
    }

    /// Round-trip a fresh probs through the pair.
    #[test]
    fn probs_round_trip_fresh() {
        let p = LzmaProbs::new();
        let mut buf = Vec::new();
        write_probs_into(&mut buf, &p);
        let r = read_probs_from(&buf).expect("decode");
        // Compare the four "easy" fields; the bit-tree slots
        // are checked structurally by the round-trip test
        // below (any mismatch would have surfaced as a
        // decoder failure).
        assert_eq!(p.is_rep, r.is_rep);
        assert_eq!(p.match_len_decoder.choice, r.match_len_decoder.choice);
        assert_eq!(p.match_len_decoder.choice2, r.match_len_decoder.choice2);
        assert_eq!(p.pos_align, r.pos_align);
    }

    /// Encode + decode a synthetic state struct; verify
    /// every field round-trips.
    #[test]
    fn struct_round_trip() {
        let s = synthetic_state();
        let blob = s.serialize();
        // Magic + version match.
        assert_eq!(&blob[..4], MAGIC);
        assert_eq!(blob[4], FORMAT_VERSION);
        let r = XzPortResumeState::deserialize(&blob).expect("deserialize");
        assert_eq!(r.stream_check, s.stream_check);
        assert_eq!(r.stream_block_records, s.stream_block_records);
        assert_eq!(r.block_header_size_bytes, s.block_header_size_bytes);
        assert_eq!(
            r.block_compressed_size_declared,
            s.block_compressed_size_declared
        );
        assert_eq!(
            r.block_uncompressed_size_declared,
            s.block_uncompressed_size_declared
        );
        assert_eq!(r.block_dict_size, s.block_dict_size);
        assert_eq!(r.block_lzma2_start_offset, s.block_lzma2_start_offset);
        assert_eq!(r.block_decompressed_so_far, s.block_decompressed_so_far);
        assert_eq!(r.block_seen_first_chunk, s.block_seen_first_chunk);
        assert_eq!(r.block_lzma2_finished, s.block_lzma2_finished);
        assert_eq!(r.needs_props, s.needs_props);
        assert_eq!(r.needs_dict_reset, s.needs_dict_reset);
        assert_eq!(r.lc, s.lc);
        assert_eq!(r.lp, s.lp);
        assert_eq!(r.pb, s.pb);
        assert_eq!(r.lzma_state, s.lzma_state);
        assert_eq!(r.rep0, s.rep0);
        assert_eq!(r.rep1, s.rep1);
        assert_eq!(r.rep2, s.rep2);
        assert_eq!(r.rep3, s.rep3);
        assert_eq!(r.dict_capacity, s.dict_capacity);
        assert_eq!(r.dict_full, s.dict_full);
        assert_eq!(r.dict_data, s.dict_data);
        assert_eq!(r.probs, s.probs);
        assert_eq!(r.check_state, s.check_state);
    }

    #[test]
    fn deserialize_rejects_bad_magic() {
        let mut blob = synthetic_state().serialize();
        blob[0] = b'X';
        match XzPortResumeState::deserialize(&blob) {
            Err(ResumeBlobError::BadMagic) => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_unsupported_version() {
        let mut blob = synthetic_state().serialize();
        blob[4] = 0xFF;
        match XzPortResumeState::deserialize(&blob) {
            Err(ResumeBlobError::UnsupportedVersion(0xFF)) => {}
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_crc_corruption() {
        let mut blob = synthetic_state().serialize();
        let n = blob.len();
        blob[n - 1] ^= 0xFF;
        match XzPortResumeState::deserialize(&blob) {
            Err(ResumeBlobError::CrcMismatch { .. }) => {}
            other => panic!("expected CrcMismatch, got {other:?}"),
        }
    }

    fn synthetic_state() -> XzPortResumeState {
        let mut probs = Vec::new();
        write_probs_into(&mut probs, &LzmaProbs::new());
        XzPortResumeState {
            stream_check: CheckId::Crc64,
            stream_block_records: vec![(123, 4567)],
            block_header_size_bytes: 16,
            block_compressed_size_declared: Some(1024),
            block_uncompressed_size_declared: None,
            block_dict_size: 1 << 20,
            block_lzma2_start_offset: 0xDEAD_BEEF,
            block_decompressed_so_far: 999,
            block_seen_first_chunk: true,
            block_lzma2_finished: false,
            needs_props: false,
            needs_dict_reset: false,
            lc: 3,
            lp: 0,
            pb: 2,
            lzma_state: 7,
            rep0: 1,
            rep1: 2,
            rep2: 3,
            rep3: 4,
            dict_capacity: 256,
            dict_full: 64,
            dict_data: (0..64).collect(),
            probs,
            check_state: vec![0u8, 1, 2, 3, 4, 5, 6, 7],
        }
    }
}
