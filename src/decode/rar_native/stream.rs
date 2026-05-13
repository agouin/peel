//! `RarStreamDecoder` — `StreamingDecoder` adapter that drives the
//! [`super::lzss::LzssDecoder`] over an entry's compressed bytes.
//!
//! Per `internal/PLAN_rar5_decoder.md` §E1 this is the integration
//! seam: the layers committed in §A1/§A2/§B1/§B2/§C1 produce
//! `decode_block`-shaped primitives; this module wraps them in
//! the bounded-step / `bytes_consumed` / `frame_boundary` contract
//! the rest of `peel` already speaks for `tar.zst` / `tar.xz` /
//! `.lz4` etc. The §3 RAR pipeline flips its `method != 0` reject
//! into a dispatch through this decoder.
//!
//! # Block / filter sequencing
//!
//! Each call to [`StreamingDecoder::decode_step`] does at most one
//! block's worth of LZSS work and then drains as much of the
//! filter-pending staging buffer as is safe to emit:
//!
//! 1. Read the next block's prologue (2 + `byte_count` bytes), use
//!    that to read the block's `block_size`-byte bitstream.
//! 2. Hand the contiguous block buffer to
//!    [`super::lzss::LzssDecoder::decode_block`]; freshly-decoded
//!    bytes append onto [`Self::staging`]. Pull the LZSS layer's
//!    pending-filter queue into our local `filters` queue.
//! 3. Walk the head of `filters` in order: a filter is "ready"
//!    when staging covers `[block_start, block_start +
//!    block_length)`. Apply ready filters in place to staging,
//!    pop them off the queue. Stop at the first non-ready filter
//!    (filters must be applied in encounter order — libarchive's
//!    `merge_block` discipline).
//! 4. Drain staging up to either (a) the head pending filter's
//!    `block_start` if one remains, or (b) the full staging length
//!    if no filter is pending. The drained bytes are written to
//!    the caller's `sink`.
//! 5. Repeat from step 1 until the LZSS layer reports
//!    `is_last_block` and staging + filters are both empty, at
//!    which point we transition to [`DecodeStatus::Eof`].
//!
//! Per-step bounded work matches every other in-tree streaming
//! decoder so the coordinator can interleave punch / checkpoint
//! cadence with decode.

use std::collections::VecDeque;
use std::io::{ErrorKind, Read, Write};

use super::bootstrap::HUFF_TABLE_SIZE;
use super::dict::{Dict, DictError};
use super::dist_cache::DistCache;
use super::filters::{apply as apply_filter, Filter, FilterType};
use super::lzss::{LzssDecoder, LzssError};
use crate::decode::{DecodeError, DecodeStatus, StreamingDecoder};
use crate::types::ByteOffset;

/// Magic bytes identifying a [`RarStreamDecoder`] resume blob.
/// Stamped at offset 0 so a stray cross-decoder blob (e.g. an lz4
/// or xz snapshot) can't be mis-routed into the RAR resume path.
const SNAPSHOT_MAGIC: [u8; 4] = *b"RR5S";

/// Wire version of the snapshot format. Bumped whenever the layout
/// changes; the RAR5 decoder's entry-resume contract permits
/// silent rejection of future-version blobs (the resume falls
/// back to byte-0 restart, which still produces byte-identical
/// output).
const SNAPSHOT_VERSION: u32 = 1;

/// Hard cap on the per-block bitstream we'll buffer. Any block
/// claiming a larger `block_size` is treated as malformed input —
/// real RAR5 archives in the wild produce blocks in the
/// "few-hundred-KB" range, and libarchive's reference decoder
/// never sets a `block_size` past 4 MiB. The cap protects against
/// an adversarial archive that uses a giant `byte_count` field to
/// induce an OOM allocation.
const MAX_BLOCK_BYTES: u64 = 64 * 1024 * 1024;

/// `RarStreamDecoder` per-entry instance.
///
/// One instance per RAR5 entry. The `src` source delivers the
/// entry's compressed bytes (a sequence of LZSS blocks ending with
/// `is_last_block`). Decoded bytes flow into the caller's `Write`
/// sink via [`StreamingDecoder::decode_step`].
///
/// `Debug` is implemented manually because the trait-object source
/// cannot derive it; the printed form covers every field except the
/// `src` handle.
pub struct RarStreamDecoder {
    /// Pull-style source of the entry's compressed bytes. `None`
    /// once a clean EOF has been observed at a block boundary; we
    /// release the underlying file handle as soon as the
    /// last-block marker fires.
    src: Option<Box<dyn Read + Send>>,
    /// Bytes that were pulled from `src` past the end of a non-last
    /// block's bitstream as **lookahead** for the LZSS dispatcher's
    /// peek_bits — see [`Self::BLOCK_LOOKAHEAD_BYTES`] and the
    /// libarchive parity discussion in
    /// `internal/PLAN_rar5_multi_block_decode.md`. Replayed at the
    /// start of the next [`Self::read_block`] call so the next
    /// block's prologue parses normally; never re-pulled from
    /// `src`. Empty between block reads.
    prepend_buf: Vec<u8>,
    /// Cumulative bytes pulled from `src`. Combined with
    /// [`Self::src_start_offset`] to produce the global
    /// [`Self::bytes_consumed`] value.
    src_consumed: u64,
    /// Source-stream byte offset where this decoder's `src` begins
    /// delivering bytes. The coordinator seeds this via
    /// [`StreamingDecoder::set_source_start_offset`] for runs that
    /// resume from a non-zero offset; fresh runs leave it at 0.
    src_start_offset: u64,
    /// LZSS dispatcher + dict + filter queue. Owns the per-entry
    /// decoder state.
    lzss: LzssDecoder,
    /// Bytes the LZSS layer has decoded but we have not yet
    /// emitted to the sink. The first byte's absolute output-stream
    /// position is [`Self::staging_start_pos`]. The buffer grows
    /// as blocks decode and shrinks as bytes drain to the sink;
    /// pending filters keep bytes parked until their block_length
    /// is fully covered.
    staging: Vec<u8>,
    /// Absolute position in the (unfiltered) LZSS output stream of
    /// `staging[0]`. Equal to "bytes already emitted to sink"
    /// since filter application is in-place and length-preserving.
    staging_start_pos: u64,
    /// In-flight filter queue, drained from `lzss.take_pending_filters()`
    /// after each block. Filters are applied in encounter order;
    /// staging holds bytes until the head filter's range is fully
    /// covered.
    filters: VecDeque<Filter>,
    /// `true` once the LZSS layer has reported `is_last_block`. We
    /// keep decoding/emitting from staging until it drains, then
    /// transition to EOF.
    last_block_seen: bool,
    /// Frame boundary as a global source-stream offset. `Some(off)`
    /// after the first block ends; `off` is the source byte
    /// position immediately after the most recently consumed
    /// block's bitstream. Returned verbatim by
    /// [`StreamingDecoder::frame_boundary`].
    last_frame_end: Option<u64>,
    /// Latched `Eof` flag. Once set, [`StreamingDecoder::decode_step`]
    /// idempotently returns `Eof` without further work.
    eof_emitted: bool,
}

impl std::fmt::Debug for RarStreamDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RarStreamDecoder")
            .field("src_consumed", &self.src_consumed)
            .field("src_start_offset", &self.src_start_offset)
            .field("staging_len", &self.staging.len())
            .field("staging_start_pos", &self.staging_start_pos)
            .field("filters_pending", &self.filters.len())
            .field("last_block_seen", &self.last_block_seen)
            .field("last_frame_end", &self.last_frame_end)
            .field("eof_emitted", &self.eof_emitted)
            .finish()
    }
}

impl RarStreamDecoder {
    /// Construct a decoder over `src` with `dict_capacity` bytes
    /// of LZSS dictionary. The capacity is per-entry and comes
    /// from the file header's `dict_size_selector` field
    /// (`128 KiB << selector`).
    ///
    /// # Errors
    ///
    /// - [`DecodeError::Construct`] wrapping the underlying
    ///   [`DictError`] when `dict_capacity` is zero or exceeds
    ///   [`super::dict::MAX_DICT_BYTES`].
    pub fn new(src: Box<dyn Read + Send>, dict_capacity: usize) -> Result<Self, DecodeError> {
        let lzss = LzssDecoder::new(dict_capacity).map_err(|e| {
            DecodeError::Construct(std::io::Error::other(format!(
                "RAR5 stream decoder: dict construction failed: {e}",
            )))
        })?;
        Ok(Self {
            src: Some(src),
            prepend_buf: Vec::new(),
            src_consumed: 0,
            src_start_offset: 0,
            lzss,
            staging: Vec::new(),
            staging_start_pos: 0,
            filters: VecDeque::new(),
            last_block_seen: false,
            last_frame_end: None,
            eof_emitted: false,
        })
    }

    /// Number of lookahead bytes the dispatcher needs past a
    /// non-last block's bitstream so the LD-symbol Huffman peek
    /// (libarchive's `read_bits_16`, our [`super::huffman::HuffTable::decode`])
    /// doesn't underrun on a symbol whose bits straddle the block
    /// boundary. Libarchive's `process_block` reserves the same 4
    /// bytes via `read_ahead(a, 4 + cur_block_size, &p)`. The
    /// peeked-but-not-consumed lookahead bytes are replayed via
    /// [`Self::prepend_buf`] as the next block's prologue.
    const BLOCK_LOOKAHEAD_BYTES: usize = 4;

    /// Read exactly `n` bytes from `src` into a fresh `Vec<u8>`.
    ///
    /// Drains [`Self::prepend_buf`] first (bytes pulled-but-replayed
    /// from the previous block's lookahead), then pulls the
    /// remainder from `src`.
    ///
    /// Returns `Ok(None)` only when the very first read returns 0
    /// (clean EOF before any byte was read for this block);
    /// otherwise either fills a full buffer or surfaces
    /// [`ErrorKind::UnexpectedEof`].
    fn read_exact(&mut self, n: usize) -> Result<Option<Vec<u8>>, DecodeError> {
        let mut buf = vec![0u8; n];
        let mut filled = 0usize;
        // Drain replayed lookahead first. The bytes were pulled
        // from `src` already (and counted in `src_consumed` at that
        // time), so we don't re-bump the counter here.
        if !self.prepend_buf.is_empty() {
            let take = self.prepend_buf.len().min(n);
            buf[..take].copy_from_slice(&self.prepend_buf[..take]);
            self.prepend_buf.drain(..take);
            filled = take;
            if filled == n {
                return Ok(Some(buf));
            }
        }
        let Some(src) = self.src.as_mut() else {
            if filled == 0 {
                return Ok(None);
            }
            return Err(DecodeError::Read {
                consumed: self.src_start_offset + self.src_consumed,
                source: std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    format!(
                        "RAR5 stream decoder: short read mid-block: \
                         wanted {n} bytes, got {filled} (src closed)"
                    ),
                ),
            });
        };
        while filled < n {
            match src.read(&mut buf[filled..]) {
                Ok(0) => {
                    if filled == 0 {
                        return Ok(None);
                    }
                    return Err(DecodeError::Read {
                        consumed: self.src_start_offset + self.src_consumed,
                        source: std::io::Error::new(
                            ErrorKind::UnexpectedEof,
                            format!(
                                "RAR5 stream decoder: short read mid-block: \
                                 wanted {n} bytes, got {filled}"
                            ),
                        ),
                    });
                }
                Ok(got) => filled += got,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(source) => {
                    let consumed = self.src_start_offset + self.src_consumed;
                    return Err(DecodeError::Read { consumed, source });
                }
            }
        }
        self.src_consumed = self.src_consumed.saturating_add(n as u64);
        Ok(Some(buf))
    }

    /// Read one full block (prologue + size field + bitstream)
    /// off `src`. For non-last blocks, also pulls
    /// [`Self::BLOCK_LOOKAHEAD_BYTES`] from `src` and appends them
    /// to the returned buffer so the LZSS dispatcher's last-symbol
    /// peek can read past the block boundary; the same bytes are
    /// saved in [`Self::prepend_buf`] so the next [`Self::read_block`]
    /// call replays them as the next block's prologue. Returns
    /// `Ok(None)` if the source EOF'd at a clean block boundary
    /// before any byte was pulled — that is only valid when the
    /// previous block had `is_last_block` set, which the caller
    /// validates.
    fn read_block(&mut self) -> Result<Option<Vec<u8>>, DecodeError> {
        // Prologue is 2 bytes; the second's checksum lets us
        // sanity-check the first before allocating for the size
        // field.
        let prologue = match self.read_exact(2)? {
            Some(p) => p,
            None => return Ok(None),
        };
        let flags = prologue[0];
        let is_last_block = (flags & 0b0100_0000) != 0;
        let byte_count = (((flags >> 3) & 0b111) + 1) as usize;
        let mut block = prologue;
        // Size field: `byte_count` LE bytes after the prologue.
        let size_field = self.read_exact_required(byte_count)?;
        block.extend_from_slice(&size_field);
        let mut block_size: u64 = 0;
        for (i, &b) in size_field.iter().enumerate() {
            block_size |= u64::from(b) << (i * 8);
        }
        if block_size == 0 {
            return Err(DecodeError::Read {
                consumed: self.src_start_offset + self.src_consumed,
                source: std::io::Error::other(
                    "RAR5 stream decoder: block_size = 0 (every block must have at least one byte)",
                ),
            });
        }
        if block_size > MAX_BLOCK_BYTES {
            return Err(DecodeError::Read {
                consumed: self.src_start_offset + self.src_consumed,
                source: std::io::Error::other(format!(
                    "RAR5 stream decoder: block_size {block_size} exceeds \
                     {MAX_BLOCK_BYTES} cap (probably a malformed archive)"
                )),
            });
        }
        let bitstream = self.read_exact_required(block_size as usize)?;
        block.extend_from_slice(&bitstream);

        // Non-last blocks: pull lookahead so the dispatcher can
        // peek past the block boundary into the next block's
        // prologue bytes (libarchive parity, see
        // `internal/PLAN_rar5_multi_block_decode.md`). Whatever we
        // pull goes into both `block` (for the dispatcher to see)
        // and `prepend_buf` (so the next prologue read sees the
        // same bytes). For the last block we don't bother — the
        // entry's bit budget terminates the loop cleanly without
        // any lookahead.
        if !is_last_block {
            let mut lookahead = Vec::with_capacity(Self::BLOCK_LOOKAHEAD_BYTES);
            // Try to fill `BLOCK_LOOKAHEAD_BYTES`; tolerate a
            // short pull (entry-final block whose successor is
            // shorter than 4 bytes, rare but possible in adversarial
            // archives).
            while lookahead.len() < Self::BLOCK_LOOKAHEAD_BYTES {
                let want = Self::BLOCK_LOOKAHEAD_BYTES - lookahead.len();
                match self.read_exact(want)? {
                    Some(chunk) => lookahead.extend_from_slice(&chunk),
                    None => break,
                }
            }
            block.extend_from_slice(&lookahead);
            self.prepend_buf.extend_from_slice(&lookahead);
        }

        Ok(Some(block))
    }

    /// `read_exact` flavour that translates a clean-EOF return
    /// into an [`ErrorKind::UnexpectedEof`] wrap because the
    /// caller has already committed to reading more bytes.
    fn read_exact_required(&mut self, n: usize) -> Result<Vec<u8>, DecodeError> {
        match self.read_exact(n)? {
            Some(v) => Ok(v),
            None => Err(DecodeError::Read {
                consumed: self.src_start_offset + self.src_consumed,
                source: std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    format!("RAR5 stream decoder: source EOF mid-block (wanted {n} bytes)"),
                ),
            }),
        }
    }

    /// Apply every leading pending filter whose range is now
    /// fully covered by [`Self::staging`].
    ///
    /// Filters are applied in encounter order (libarchive's
    /// `merge_block` discipline); we stop at the first filter
    /// whose range extends past the current staging end.
    ///
    /// # Errors
    ///
    /// - [`DecodeError::Read`] wrapping the underlying
    ///   filter / bookkeeping diagnostic when a filter references
    ///   an output position outside what staging currently holds
    ///   (only reachable on a malformed bitstream that, e.g.,
    ///   queues a filter pointing into bytes the LZSS layer has
    ///   already emitted past).
    fn apply_ready_filters(&mut self) -> Result<(), DecodeError> {
        while let Some(head) = self.filters.front() {
            let start = head.block_start;
            let length = u64::from(head.block_length);
            // The filter's range is [start, start + length).
            // staging covers [staging_start_pos, staging_start_pos + len).
            let end = start.checked_add(length).ok_or_else(|| DecodeError::Read {
                consumed: self.src_start_offset + self.src_consumed,
                source: std::io::Error::other(format!(
                    "RAR5 filter range overflow: block_start {start} + block_length {length}",
                )),
            })?;
            let staging_end = self.staging_start_pos + self.staging.len() as u64;
            if end > staging_end {
                // Not enough bytes yet — wait for more decoded output.
                return Ok(());
            }
            if start < self.staging_start_pos {
                return Err(DecodeError::Read {
                    consumed: self.src_start_offset + self.src_consumed,
                    source: std::io::Error::other(format!(
                        "RAR5 filter references already-emitted output: \
                         block_start {start} < staging_start {start_pos}",
                        start_pos = self.staging_start_pos
                    )),
                });
            }
            // INVARIANT: start..end is fully within staging, and
            // length fits in a u32 (per filter::MAX_FILTER_BLOCK_LENGTH).
            let off = (start - self.staging_start_pos) as usize;
            let len = head.block_length as usize;
            // Apply filter in place. `apply` takes separate
            // `source` and `output` slices so we copy through a
            // small scratch — block_length is bounded by 4 MiB.
            let mut scratch = vec![0u8; len];
            apply_filter(head, &self.staging[off..off + len], &mut scratch).map_err(|e| {
                DecodeError::Read {
                    consumed: self.src_start_offset + self.src_consumed,
                    source: std::io::Error::other(format!("RAR5 filter apply failed: {e}")),
                }
            })?;
            self.staging[off..off + len].copy_from_slice(&scratch);
            self.filters.pop_front();
        }
        Ok(())
    }

    /// Emit as many bytes of [`Self::staging`] as we can — those
    /// not held back by a still-pending filter — to the caller's
    /// `sink`. Drained bytes are removed from staging and
    /// [`Self::staging_start_pos`] advances accordingly.
    fn drain_staging(&mut self, sink: &mut dyn Write) -> Result<usize, DecodeError> {
        // The "high water" we can emit is either the head pending
        // filter's block_start (which keeps us from emitting bytes
        // a filter still needs to transform) or — when no filter
        // is pending — the full staging length (LZSS output is
        // safe to emit immediately if no transform is queued).
        let high_water = match self.filters.front() {
            Some(head) => {
                let head_start = head.block_start;
                if head_start <= self.staging_start_pos {
                    return Ok(0);
                }
                let avail = head_start - self.staging_start_pos;
                avail.min(self.staging.len() as u64) as usize
            }
            None => self.staging.len(),
        };
        if high_water == 0 {
            return Ok(0);
        }
        sink.write_all(&self.staging[..high_water])
            .map_err(DecodeError::Write)?;
        self.staging.drain(..high_water);
        self.staging_start_pos = self.staging_start_pos.saturating_add(high_water as u64);
        Ok(high_water)
    }
}

impl StreamingDecoder for RarStreamDecoder {
    fn decode_step(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, DecodeError> {
        if self.eof_emitted {
            return Ok(DecodeStatus::Eof);
        }

        // First, apply any filters whose range was completed by a
        // previous step's decode but whose drain didn't fit in the
        // bounded step's emit budget. Cheap when filters is empty
        // (every entry without filter symbols).
        self.apply_ready_filters()?;
        let drained = self.drain_staging(sink)?;

        // If the LZSS layer has signalled the entry-end and our
        // staging drained fully, transition to Eof. We hold off
        // releasing `src` until the boundary is crystal clean so
        // callers' `bytes_consumed` reports the final source
        // offset rather than 0 from a re-construction.
        if self.last_block_seen && self.staging.is_empty() && self.filters.is_empty() {
            self.src = None;
            self.eof_emitted = true;
            return Ok(DecodeStatus::Eof);
        }

        // If we made progress on the staging side this step, hand
        // control back so the coordinator can punch / checkpoint
        // before we pull another block off the wire.
        if drained > 0 {
            return Ok(DecodeStatus::MoreData);
        }

        // Otherwise we need a fresh block. The previous block may
        // have set `is_last_block`; in that case the source EOFs
        // at this point.
        if self.last_block_seen {
            // Staging non-empty but no filter ready and no more
            // blocks to pull — that's a malformed archive (the
            // last block left bytes that no filter / sink-drain
            // can resolve). Reachable only on adversarial input.
            if !self.staging.is_empty() || !self.filters.is_empty() {
                return Err(DecodeError::Read {
                    consumed: self.src_start_offset + self.src_consumed,
                    source: std::io::Error::other(format!(
                        "RAR5 stream decoder: last block consumed but {staging_left} bytes \
                         and {filters_left} filters still pending",
                        staging_left = self.staging.len(),
                        filters_left = self.filters.len(),
                    )),
                });
            }
            self.src = None;
            self.eof_emitted = true;
            return Ok(DecodeStatus::Eof);
        }

        let Some(block) = self.read_block()? else {
            // Source EOF before a `is_last_block` block — round-one
            // §3 truncates at packed_size, so this only fires on a
            // genuinely malformed archive.
            return Err(DecodeError::Read {
                consumed: self.src_start_offset + self.src_consumed,
                source: std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "RAR5 stream decoder: source EOF before last-block marker",
                ),
            });
        };

        let is_last = self
            .lzss
            .decode_block(&block, &mut self.staging)
            .map_err(map_lzss_err)?;
        // Drain newly-queued filters into our local queue. Order
        // is preserved (encounter order = application order).
        for f in self.lzss.take_pending_filters() {
            self.filters.push_back(f);
        }
        self.last_block_seen = is_last;
        self.last_frame_end = Some(self.src_start_offset + self.src_consumed);

        // Apply filters that the new block's bytes just made
        // ready, then return — the next step picks up the drain.
        // (We deliberately don't drain here so each step is a
        // small, predictable unit of work.)
        self.apply_ready_filters()?;

        Ok(DecodeStatus::MoreData)
    }

    fn bytes_consumed(&self) -> ByteOffset {
        ByteOffset::new(self.src_start_offset + self.src_consumed)
    }

    fn frame_boundary(&self) -> Option<ByteOffset> {
        self.last_frame_end.map(ByteOffset::new)
    }

    fn set_source_start_offset(&mut self, offset: u64) {
        // Identical contract to every other in-tree decoder: the
        // run-local `src_consumed` is bytes pulled in *this* run;
        // the global high-water mark = start_offset + src_consumed.
        // Resume seeds this from the saved blob via [`Self::resume`];
        // fresh runs leave it at 0.
        self.src_start_offset = offset;
    }

    fn decoder_state_into(&self, out: &mut Vec<u8>) -> bool {
        // Only return a snapshot when one is actually useful: at
        // least one block must have been decoded (so the Huffman
        // tables exist), and the entry must not have already
        // EOF'd (no point checkpointing a finished entry).
        if self.eof_emitted || self.lzss.table_lengths().is_none() {
            return false;
        }
        self.serialize_into(out);
        true
    }

    fn decoder_state_size_hint(&self) -> usize {
        // Header + fixed fields + table lengths + dict snapshot +
        // staging + filters. The `dict.live_bytes` term dominates
        // for entries with multi-MiB dictionaries; the rest is a
        // few hundred bytes.
        let dict_live = self.lzss.dict().live_bytes() as usize;
        let staging = self.staging.len();
        let filters = self.filters.len() * 16;
        SNAPSHOT_FIXED_HEADER_LEN + HUFF_TABLE_SIZE + dict_live + staging + filters + 64
    }
}

/// Translate an [`LzssError`] from the LZSS dispatcher into a
/// [`DecodeError`]. Read / format errors fold into
/// [`DecodeError::Read`]; the dictionary's bounded-allocation
/// errors (which §B1 makes unreachable for well-formed input)
/// are also folded in via the same `other()` wrap.
fn map_lzss_err(e: LzssError) -> DecodeError {
    DecodeError::Read {
        // The dispatcher doesn't expose its own consumed-bytes
        // counter (it's a per-block primitive). The caller's
        // outer counter is what the coordinator needs anyway.
        consumed: 0,
        source: std::io::Error::other(e.to_string()),
    }
}

/// Translate a [`DictError`] into a [`DecodeError::Construct`].
/// Used by the §F1 resume factory when the on-wire dict capacity
/// disagrees with the saved blob.
fn map_dict_err(e: DictError) -> DecodeError {
    DecodeError::Construct(std::io::Error::other(e.to_string()))
}

/// Bytes consumed by the fixed (non-array) header / state fields
/// of a snapshot, used by [`RarStreamDecoder::decoder_state_size_hint`].
/// Doesn't include variable-length sections (table lengths, dict
/// snapshot, staging, filters); those are added at hint time.
const SNAPSHOT_FIXED_HEADER_LEN: usize = 4 // magic
    + 4 // version
    + 8 // src_consumed
    + 8 // src_start_offset
    + 8 // staging_start_pos
    + 4 // staging_len
    + 1 // last_block_seen
    + 1 // eof_emitted
    + 1 // last_frame_end presence
    + 8 // last_frame_end value
    + 4 // filter_count
    + 4 // dict_capacity
    + 8 // dict_total_written
    + 4 // dict_snapshot_len
    + (4 * 4) // dist_cache slots
    + 4 // last_len
    + 8 // output_pos
    + 1; // table_lengths presence

/// Filter-type wire tag. Mirrors libarchive's `FILTER_*`
/// constants but is private to the snapshot format because the
/// RAR5 spec leaves type code numbering authoritative on the
/// wire and we don't want a future rename of [`FilterType`] to
/// silently invalidate older blobs.
const FILTER_TAG_DELTA: u8 = 0;
const FILTER_TAG_E8: u8 = 1;
const FILTER_TAG_E8E9: u8 = 2;
const FILTER_TAG_ARM: u8 = 3;

impl RarStreamDecoder {
    /// Serialize the decoder's state into `out`, exactly the
    /// shape [`Self::resume`] consumes. Stable across patch
    /// releases per `PLAN_rar5_decoder.md` §F1's checkpoint
    /// compatibility contract.
    fn serialize_into(&self, out: &mut Vec<u8>) {
        out.reserve(self.decoder_state_size_hint());
        out.extend_from_slice(&SNAPSHOT_MAGIC);
        write_u32_le(out, SNAPSHOT_VERSION);
        // Subtract any pulled-but-replayed lookahead bytes
        // ([`Self::prepend_buf`]) from the serialized source
        // cursor. Those bytes were pulled from `src` (so
        // `src_consumed` counts them) but never processed by
        // the LZSS dispatcher — they live in `prepend_buf` for
        // replay as the next block's prologue. On resume the
        // pipeline slices `compressed[cursor..]` and the new
        // decoder starts with an empty `prepend_buf`; rewinding
        // the cursor by `prepend_buf.len()` means the new src
        // delivers those lookahead bytes again at the right
        // moment (now as fresh `src` reads instead of
        // prepend-buf drains). Byte-equivalent to the original
        // state and avoids serializing the lookahead bytes
        // themselves.
        //
        // For single-block entries `prepend_buf` is always
        // empty (the last block never pulls lookahead), so this
        // is a no-op on the existing single-block test corpus.
        let logical_src_consumed = self
            .src_consumed
            .saturating_sub(self.prepend_buf.len() as u64);
        write_u64_le(out, logical_src_consumed);
        write_u64_le(out, self.src_start_offset);
        write_u64_le(out, self.staging_start_pos);
        // staging
        let staging_len = u32::try_from(self.staging.len()).unwrap_or(u32::MAX);
        write_u32_le(out, staging_len);
        out.extend_from_slice(&self.staging[..staging_len as usize]);
        // flags
        out.push(u8::from(self.last_block_seen));
        out.push(u8::from(self.eof_emitted));
        match self.last_frame_end {
            Some(v) => {
                out.push(1);
                write_u64_le(out, v);
            }
            None => {
                out.push(0);
                write_u64_le(out, 0);
            }
        }
        // filters
        let filter_count = u32::try_from(self.filters.len()).unwrap_or(u32::MAX);
        write_u32_le(out, filter_count);
        for f in self.filters.iter().take(filter_count as usize) {
            let (tag, channels) = match f.kind {
                FilterType::Delta { channels } => (FILTER_TAG_DELTA, channels),
                FilterType::E8 => (FILTER_TAG_E8, 0),
                FilterType::E8e9 => (FILTER_TAG_E8E9, 0),
                FilterType::Arm => (FILTER_TAG_ARM, 0),
            };
            out.push(tag);
            out.push(channels);
            write_u64_le(out, f.block_start);
            write_u32_le(out, f.block_length);
        }
        // LZSS state
        let dict = self.lzss.dict();
        let dict_capacity = u32::try_from(dict.capacity()).unwrap_or(u32::MAX);
        write_u32_le(out, dict_capacity);
        write_u64_le(out, dict.total_written());
        let dict_snapshot_start = out.len();
        // Reserve placeholder for snapshot length, then append.
        write_u32_le(out, 0);
        let snapshot_bytes_start = out.len();
        dict.snapshot_into(out);
        let written = out.len() - snapshot_bytes_start;
        let written_u32 = u32::try_from(written).unwrap_or(u32::MAX);
        let len_bytes = written_u32.to_le_bytes();
        out[dict_snapshot_start..dict_snapshot_start + 4].copy_from_slice(&len_bytes);

        let dc = self.lzss.dist_cache().slots();
        for slot in dc {
            write_u32_le(out, slot);
        }
        write_u32_le(out, self.lzss.last_len());
        write_u64_le(out, self.lzss.output_pos());
        match self.lzss.table_lengths() {
            Some(lengths) => {
                out.push(1);
                out.extend_from_slice(lengths.as_slice());
            }
            None => out.push(0),
        }
    }

    /// Inspect a snapshot blob and return the source-byte cursor
    /// it was captured at. Lets the caller slice an in-memory
    /// compressed buffer to construct a `Read` source positioned
    /// at the same point as the prior run before invoking
    /// [`Self::resume`].
    ///
    /// # Errors
    ///
    /// - [`DecodeError::Construct`] when the magic / version
    ///   header is wrong, or the blob is too short to even hold
    ///   the cursor field.
    pub fn source_cursor_from_blob(blob: &[u8]) -> Result<u64, DecodeError> {
        if blob.len() < 4 + 4 + 8 {
            return Err(blob_construct_err(format!(
                "snapshot too short for header: got {} bytes",
                blob.len()
            )));
        }
        if blob[..4] != SNAPSHOT_MAGIC {
            return Err(blob_construct_err(format!(
                "snapshot magic mismatch: got {:?}, expected {:?}",
                &blob[..4],
                SNAPSHOT_MAGIC
            )));
        }
        let version = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]);
        if version != SNAPSHOT_VERSION {
            return Err(blob_construct_err(format!(
                "snapshot version mismatch: got {version}, expected {SNAPSHOT_VERSION}"
            )));
        }
        let src_consumed = u64::from_le_bytes([
            blob[8], blob[9], blob[10], blob[11], blob[12], blob[13], blob[14], blob[15],
        ]);
        Ok(src_consumed)
    }

    /// Construct a decoder seeded from the saved snapshot. `src`
    /// must deliver bytes starting at the source-byte cursor
    /// recorded in the blob (caller slices via
    /// [`Self::source_cursor_from_blob`]).
    ///
    /// # Errors
    ///
    /// - [`DecodeError::Construct`] for any structural issue with
    ///   the blob (truncation, magic / version mismatch, dict
    ///   capacity or filter parameters out of range).
    pub fn resume(
        src: Box<dyn Read + Send>,
        dict_capacity: usize,
        blob: &[u8],
    ) -> Result<Self, DecodeError> {
        let mut cur = SnapshotCursor::new(blob);
        cur.expect_magic()?;
        cur.expect_version()?;

        let src_consumed = cur.read_u64("src_consumed")?;
        let src_start_offset = cur.read_u64("src_start_offset")?;
        let staging_start_pos = cur.read_u64("staging_start_pos")?;

        let staging_len = cur.read_u32("staging_len")? as usize;
        let staging = cur.read_slice(staging_len, "staging")?.to_vec();

        let last_block_seen = cur.read_u8("last_block_seen")? != 0;
        let eof_emitted = cur.read_u8("eof_emitted")? != 0;
        let last_frame_end_present = cur.read_u8("last_frame_end_present")?;
        let last_frame_end_value = cur.read_u64("last_frame_end_value")?;
        let last_frame_end = if last_frame_end_present == 0 {
            None
        } else {
            Some(last_frame_end_value)
        };

        let filter_count = cur.read_u32("filter_count")? as usize;
        let mut filters = VecDeque::with_capacity(filter_count);
        for i in 0..filter_count {
            let tag = cur.read_u8("filter.tag")?;
            let channels = cur.read_u8("filter.channels")?;
            let block_start = cur.read_u64("filter.block_start")?;
            let block_length = cur.read_u32("filter.block_length")?;
            let kind = match tag {
                FILTER_TAG_DELTA => FilterType::Delta { channels },
                FILTER_TAG_E8 => FilterType::E8,
                FILTER_TAG_E8E9 => FilterType::E8e9,
                FILTER_TAG_ARM => FilterType::Arm,
                other => {
                    return Err(blob_construct_err(format!(
                        "snapshot filter[{i}] tag {other} not in 0..=3"
                    )));
                }
            };
            filters.push_back(Filter {
                kind,
                block_start,
                block_length,
            });
        }

        let saved_dict_capacity = cur.read_u32("dict_capacity")? as usize;
        if saved_dict_capacity != dict_capacity {
            return Err(blob_construct_err(format!(
                "snapshot dict_capacity {saved_dict_capacity} \
                 disagrees with file-header capacity {dict_capacity}"
            )));
        }
        let dict_total_written = cur.read_u64("dict_total_written")?;
        let dict_snapshot_len = cur.read_u32("dict_snapshot_len")? as usize;
        let dict_snapshot = cur.read_slice(dict_snapshot_len, "dict_snapshot")?;

        let mut dict = Dict::new(dict_capacity).map_err(map_dict_err)?;
        dict.restore_from_snapshot(dict_snapshot, dict_total_written)
            .map_err(map_dict_err)?;

        let mut dc_slots = [0u32; 4];
        for slot in &mut dc_slots {
            *slot = cur.read_u32("dist_cache.slot")?;
        }
        let dist_cache = DistCache::from_slots(dc_slots);

        let last_len = cur.read_u32("last_len")?;
        let output_pos = cur.read_u64("output_pos")?;

        let table_lengths_present = cur.read_u8("table_lengths_present")?;
        let table_lengths = if table_lengths_present == 0 {
            None
        } else {
            let bytes = cur.read_slice(HUFF_TABLE_SIZE, "table_lengths")?;
            let mut arr = [0u8; HUFF_TABLE_SIZE];
            arr.copy_from_slice(bytes);
            Some(arr)
        };

        if !cur.is_drained() {
            return Err(blob_construct_err(format!(
                "snapshot has {} trailing bytes after the last field",
                cur.remaining()
            )));
        }

        let mut lzss = LzssDecoder::new(dict_capacity).map_err(map_dict_err)?;
        // Plug the restored dict + dist_cache + bookkeeping
        // counters in directly; the LzssDecoder built fresh has
        // them at defaults.
        *lzss.dict_mut() = dict;
        *lzss.dist_cache_mut() = dist_cache;
        lzss.set_last_len(last_len);
        lzss.set_output_pos(output_pos);
        if let Some(arr) = table_lengths {
            lzss.install_tables_from_lengths(&arr).map_err(|e| {
                DecodeError::Construct(std::io::Error::other(format!(
                    "snapshot Huffman table rebuild: {e}"
                )))
            })?;
        }

        Ok(Self {
            src: Some(src),
            // Resume from snapshot starts mid-entry but at a clean
            // block boundary — the snapshot format reseats the bit
            // cursor at the start of the next block, so no
            // pending lookahead carries forward.
            prepend_buf: Vec::new(),
            src_consumed,
            src_start_offset,
            lzss,
            staging,
            staging_start_pos,
            filters,
            last_block_seen,
            last_frame_end,
            eof_emitted,
        })
    }
}

/// Tiny LE-cursor over a snapshot blob with field-name diagnostics.
/// Used only by [`RarStreamDecoder::resume`]; lives in this file so
/// the snapshot format stays a single-module concern.
struct SnapshotCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> SnapshotCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn is_drained(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn read_slice<'b>(&'b mut self, n: usize, name: &str) -> Result<&'b [u8], DecodeError> {
        if self.remaining() < n {
            return Err(blob_construct_err(format!(
                "snapshot field '{name}': need {n} bytes, have {}",
                self.remaining()
            )));
        }
        let out = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn expect_magic(&mut self) -> Result<(), DecodeError> {
        let bytes = self.read_slice(4, "magic")?;
        if bytes != SNAPSHOT_MAGIC {
            return Err(blob_construct_err(format!(
                "snapshot magic mismatch: got {bytes:?}, expected {SNAPSHOT_MAGIC:?}"
            )));
        }
        Ok(())
    }

    fn expect_version(&mut self) -> Result<(), DecodeError> {
        let v = self.read_u32("version")?;
        if v != SNAPSHOT_VERSION {
            return Err(blob_construct_err(format!(
                "snapshot version mismatch: got {v}, expected {SNAPSHOT_VERSION}"
            )));
        }
        Ok(())
    }

    fn read_u8(&mut self, name: &str) -> Result<u8, DecodeError> {
        let bytes = self.read_slice(1, name)?;
        Ok(bytes[0])
    }

    fn read_u32(&mut self, name: &str) -> Result<u32, DecodeError> {
        let bytes = self.read_slice(4, name)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self, name: &str) -> Result<u64, DecodeError> {
        let bytes = self.read_slice(8, name)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }
}

fn blob_construct_err(msg: String) -> DecodeError {
    DecodeError::Construct(std::io::Error::other(format!(
        "RAR5 stream decoder snapshot: {msg}"
    )))
}

fn write_u32_le(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn write_u64_le(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    use super::super::dict::MAX_DICT_BYTES;

    /// Constructing with `dict_capacity = 0` surfaces a precise
    /// [`DecodeError::Construct`].
    #[test]
    fn new_rejects_zero_dict_capacity() {
        let src: Box<dyn Read + Send> = Box::new(Cursor::new(Vec::<u8>::new()));
        let err = RarStreamDecoder::new(src, 0).expect_err("zero capacity rejected");
        match err {
            DecodeError::Construct(io) => {
                assert!(
                    io.to_string().contains("dict construction failed"),
                    "unexpected: {io}"
                );
            }
            other => panic!("expected Construct, got {other:?}"),
        }
    }

    /// Constructing with `dict_capacity > MAX_DICT_BYTES` is
    /// rejected the same way.
    #[test]
    fn new_rejects_oversized_dict_capacity() {
        let src: Box<dyn Read + Send> = Box::new(Cursor::new(Vec::<u8>::new()));
        let err = RarStreamDecoder::new(src, MAX_DICT_BYTES + 1).expect_err("oversize rejected");
        assert!(matches!(err, DecodeError::Construct(_)));
    }

    /// `bytes_consumed` starts at the `set_source_start_offset`
    /// seed and stays there until the first read.
    #[test]
    fn bytes_consumed_tracks_start_offset() {
        let src: Box<dyn Read + Send> = Box::new(Cursor::new(Vec::<u8>::new()));
        let mut dec = RarStreamDecoder::new(src, 128 * 1024).expect("construct");
        assert_eq!(dec.bytes_consumed().get(), 0);
        dec.set_source_start_offset(1_234);
        assert_eq!(dec.bytes_consumed().get(), 1_234);
        assert_eq!(dec.frame_boundary(), None);
    }

    /// A source that EOFs immediately surfaces a precise
    /// `UnexpectedEof`-flavoured `Read` error rather than a
    /// silent `Eof` (a clean EOF before any block is malformed —
    /// every entry must end with an `is_last_block` marker).
    #[test]
    fn empty_source_surfaces_unexpected_eof() {
        let src: Box<dyn Read + Send> = Box::new(Cursor::new(Vec::<u8>::new()));
        let mut dec = RarStreamDecoder::new(src, 128 * 1024).expect("construct");
        let mut sink: Vec<u8> = Vec::new();
        let err = dec
            .decode_step(&mut sink)
            .expect_err("empty source rejected");
        match err {
            DecodeError::Read { consumed, source } => {
                assert_eq!(consumed, 0);
                assert_eq!(source.kind(), ErrorKind::UnexpectedEof);
                assert!(
                    source.to_string().contains("before last-block marker"),
                    "unexpected: {source}"
                );
            }
            other => panic!("expected Read, got {other:?}"),
        }
    }

    /// A truncated block prologue (one byte of the 2-byte header)
    /// surfaces as a `Read` / `UnexpectedEof` error tagged with
    /// the source's running consumed count (1 byte past start).
    #[test]
    fn truncated_block_prologue_surfaces_read_error() {
        let src: Box<dyn Read + Send> = Box::new(Cursor::new(vec![0xC0u8]));
        let mut dec = RarStreamDecoder::new(src, 128 * 1024).expect("construct");
        let mut sink: Vec<u8> = Vec::new();
        let err = dec.decode_step(&mut sink).expect_err("partial prologue");
        match err {
            DecodeError::Read { source, .. } => {
                assert_eq!(source.kind(), ErrorKind::UnexpectedEof);
            }
            other => panic!("expected Read, got {other:?}"),
        }
    }

    /// A block whose `block_size` exceeds [`MAX_BLOCK_BYTES`] is
    /// rejected before we allocate the bitstream buffer (so a
    /// malicious archive can't induce an OOM via a crafted
    /// `byte_count` field).
    #[test]
    fn oversized_block_size_is_rejected() {
        // flags: bit_size=0, byte_count_minus_1=7 => byte_count=8
        // (max). is_table_present=1.
        let flags: u8 = 0b1011_1000;
        let cksum = flags ^ 0x5A;
        let mut wire = vec![flags, cksum];
        // 8-byte LE block_size = u64::MAX/2 (way past the cap).
        let big: u64 = u64::MAX / 2;
        wire.extend_from_slice(&big.to_le_bytes());
        let src: Box<dyn Read + Send> = Box::new(Cursor::new(wire));
        let mut dec = RarStreamDecoder::new(src, 128 * 1024).expect("construct");
        let mut sink: Vec<u8> = Vec::new();
        let err = dec.decode_step(&mut sink).expect_err("oversized rejected");
        match err {
            DecodeError::Read { source, .. } => {
                assert!(
                    source.to_string().contains("exceeds"),
                    "unexpected: {source}"
                );
            }
            other => panic!("expected Read, got {other:?}"),
        }
    }

    /// A block_size = 0 wire surfaces a precise diagnostic before
    /// the LZSS dispatcher gets to it (which would also reject,
    /// but with a less precise message).
    #[test]
    fn zero_block_size_is_rejected() {
        // flags: bit_size=0, byte_count_minus_1=0 (=> byte_count=1),
        // is_table_present=0, is_last_block=0.
        let flags: u8 = 0;
        let cksum = flags ^ 0x5A;
        let wire = vec![flags, cksum, 0x00];
        let src: Box<dyn Read + Send> = Box::new(Cursor::new(wire));
        let mut dec = RarStreamDecoder::new(src, 128 * 1024).expect("construct");
        let mut sink: Vec<u8> = Vec::new();
        let err = dec.decode_step(&mut sink).expect_err("zero rejected");
        match err {
            DecodeError::Read { source, .. } => {
                assert!(
                    source.to_string().contains("block_size = 0"),
                    "unexpected: {source}"
                );
            }
            other => panic!("expected Read, got {other:?}"),
        }
    }

    /// Calling `decode_step` after a clean EOF stays at `Eof`
    /// idempotently — same contract identity / lz4 / xz uphold.
    #[test]
    fn eof_is_idempotent_once_latched() {
        let src: Box<dyn Read + Send> = Box::new(Cursor::new(Vec::<u8>::new()));
        let mut dec = RarStreamDecoder::new(src, 128 * 1024).expect("construct");
        // Force the latch by hand — exercising it via the
        // happy-path requires a hand-rolled valid bitstream which
        // libarchive's encoder is the easiest source for and is
        // out of scope for this unit. The §E1 demo (per the plan)
        // is a corpus differential against `unrar`, not a unit
        // test; we cover the *protocol* invariants here.
        dec.eof_emitted = true;
        dec.last_block_seen = true;
        let mut sink: Vec<u8> = Vec::new();
        for _ in 0..5 {
            assert_eq!(
                dec.decode_step(&mut sink).expect("idempotent eof"),
                DecodeStatus::Eof
            );
        }
    }

    /// Driving `apply_ready_filters` with a filter whose range
    /// references already-emitted output surfaces a precise
    /// diagnostic — defensive, since well-formed archives never
    /// queue such a filter (the LZSS layer assigns
    /// `block_start = output_pos + block_start_offset`).
    #[test]
    fn filter_referencing_pre_staging_bytes_is_rejected() {
        let src: Box<dyn Read + Send> = Box::new(Cursor::new(Vec::<u8>::new()));
        let mut dec = RarStreamDecoder::new(src, 128 * 1024).expect("construct");
        // Pretend we've already emitted 100 bytes.
        dec.staging_start_pos = 100;
        // Push a filter pointing at byte 50 (in the past).
        dec.filters.push_back(Filter {
            kind: super::super::filters::FilterType::E8,
            block_start: 50,
            block_length: 4,
        });
        // Stuff staging with enough bytes to span 50..54 if it
        // started at 50, but it starts at 100, so the apply will
        // refuse before touching the buffer.
        dec.staging.extend_from_slice(&[0u8; 64]);
        let err = dec
            .apply_ready_filters()
            .expect_err("backward filter rejected");
        match err {
            DecodeError::Read { source, .. } => {
                assert!(
                    source.to_string().contains("already-emitted output"),
                    "unexpected: {source}"
                );
            }
            other => panic!("expected Read, got {other:?}"),
        }
    }

    /// `drain_staging` emits every byte when no filter is queued
    /// and reports its byte count via the return value — used by
    /// `decode_step` to decide whether to bow out for a
    /// punch/checkpoint cycle vs. immediately pull the next block.
    #[test]
    fn drain_staging_emits_full_buffer_with_no_filters() {
        let src: Box<dyn Read + Send> = Box::new(Cursor::new(Vec::<u8>::new()));
        let mut dec = RarStreamDecoder::new(src, 128 * 1024).expect("construct");
        dec.staging.extend_from_slice(b"hello rar");
        let mut sink: Vec<u8> = Vec::new();
        let drained = dec.drain_staging(&mut sink).expect("drain ok");
        assert_eq!(drained, 9);
        assert_eq!(sink, b"hello rar");
        assert!(dec.staging.is_empty());
        assert_eq!(dec.staging_start_pos, 9);
    }

    /// `drain_staging` honours the head pending filter's
    /// `block_start` — bytes before it emit, bytes within it stay
    /// buffered until the filter applies.
    #[test]
    fn drain_staging_stops_at_pending_filter() {
        let src: Box<dyn Read + Send> = Box::new(Cursor::new(Vec::<u8>::new()));
        let mut dec = RarStreamDecoder::new(src, 128 * 1024).expect("construct");
        dec.staging_start_pos = 0;
        dec.staging.extend_from_slice(&[0u8; 32]);
        dec.filters.push_back(Filter {
            kind: super::super::filters::FilterType::E8,
            block_start: 16,
            block_length: 8,
        });
        let mut sink: Vec<u8> = Vec::new();
        let drained = dec.drain_staging(&mut sink).expect("drain partial");
        assert_eq!(drained, 16);
        assert_eq!(sink.len(), 16);
        assert_eq!(dec.staging.len(), 32 - 16);
        assert_eq!(dec.staging_start_pos, 16);
    }
}
