//! `RarStreamDecoder` — `StreamingDecoder` adapter that drives the
//! [`super::lzss::LzssDecoder`] over an entry's compressed bytes.
//!
//! Per `docs/PLAN_rar5_decoder.md` §E1 this is the integration
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

use super::dict::DictError;
use super::filters::{apply as apply_filter, Filter};
use super::lzss::{LzssDecoder, LzssError};
use crate::decode::{DecodeError, DecodeStatus, StreamingDecoder};
use crate::types::ByteOffset;

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

    /// Read exactly `n` bytes from `src` into a fresh `Vec<u8>`.
    ///
    /// Returns `Ok(None)` only when the very first read returns 0
    /// (clean EOF before any byte was read for this block);
    /// otherwise either fills a full buffer or surfaces
    /// [`ErrorKind::UnexpectedEof`].
    fn read_exact(&mut self, n: usize) -> Result<Option<Vec<u8>>, DecodeError> {
        let Some(src) = self.src.as_mut() else {
            return Ok(None);
        };
        let mut buf = vec![0u8; n];
        let mut filled = 0usize;
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
    /// off `src`. Returns `Ok(None)` if the source EOF'd at a
    /// clean block boundary before any byte was pulled — that is
    /// only valid when the previous block had `is_last_block` set,
    /// which the caller validates.
    fn read_block(&mut self) -> Result<Option<Vec<u8>>, DecodeError> {
        // Prologue is 2 bytes; the second's checksum lets us
        // sanity-check the first before allocating for the size
        // field.
        let prologue = match self.read_exact(2)? {
            Some(p) => p,
            None => return Ok(None),
        };
        let flags = prologue[0];
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
        // Resume support for mid-entry RAR5 lands in §F1 (this
        // setter is a no-op for fresh runs since src_consumed = 0,
        // and §F1 will seed both fields from the saved blob).
        self.src_start_offset = offset;
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
/// Unused by the run-time decode path (the LZSS dispatcher has
/// its own typed forwarding for distance / underflow errors); kept
/// here so §F1's resume factory can reuse it without a duplicate
/// adapter.
#[allow(dead_code)]
pub(crate) fn map_dict_err(e: DictError) -> DecodeError {
    DecodeError::Construct(std::io::Error::other(e.to_string()))
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
