//! RAR5 LZSS dispatcher — orchestrates a block's decode loop.
//!
//! This module ports the symbol-dispatch loop libarchive
//! ships as `do_uncompress_block` in
//! `archive_read_support_format_rar5.c` (Grzegorz Antoniak,
//! BSD 2-Clause; see [`NOTICE`](../../../NOTICE) at the repo
//! root). It glues together the building blocks committed in
//! §A1/§A2/§B1/§B2/§C1:
//!
//! - [`super::bits::BitReader`] (§A1) — bitstream over the
//!   block's compressed bytes.
//! - [`super::huffman::HuffTable`] (§A2) — canonical Huffman
//!   decoder.
//! - [`super::dict::Dict`] (§B1) — sliding-window dictionary.
//! - [`super::block_header::parse_block_header`] (§B2) — the
//!   block prologue.
//! - [`super::bootstrap::read_meta_huffman_lengths`] /
//!   [`super::bootstrap::decode_main_table_lengths`] (§B2) —
//!   the per-block code-length table parser.
//! - [`super::dist_cache::DistCache`] (§B2) — recent-distance
//!   LRU.
//! - [`super::distance::decode_distance`] (§B2) — distance code
//!   slot to real distance.
//! - [`super::length::decode_length`] (§B2) — length code to
//!   match length.
//! - [`super::filters::Filter`] / [`super::filters::FilterType`]
//!   (§C1) — filter descriptors queued by code-256.
//!
//! # Symbol semantics (libarchive's `do_uncompress_block`)
//!
//! Each iteration decodes one symbol `num` from the LD (literal
//! / length) Huffman:
//!
//! - `num < 256` — literal byte. Push to dict + output.
//! - `num == 256` — new filter descriptor. Read parameters
//!   ([`parse_filter`]) and queue for the upper layer.
//! - `num == 257` — repeat the most-recent match (length =
//!   [`Self::last_len`]) at distance [`DistCache::peek`]`(0)`.
//!   No-op if no match has been emitted yet (libarchive's
//!   `last_len != 0` guard).
//! - `258 ≤ num ≤ 261` — distance-cache hit. `idx = num - 258`,
//!   distance = [`DistCache::touch`]`(idx)`, length code from
//!   the RD (repeat) Huffman, length = [`decode_length`].
//! - `num ≥ 262` — fresh match. Length code = `num - 262`,
//!   length = [`decode_length`]; distance slot from the DD
//!   Huffman, distance = [`decode_distance`] (uses the LDD
//!   Huffman for the low 4 bits of large-distance slots).
//!   Length is bumped by `+1/+2/+3` for distances exceeding
//!   `0x100 / 0x2000 / 0x40000` respectively (libarchive lines
//!   3296-3306).
//!
//! Block end is signalled by the bit cursor reaching the
//! block's last bit, not by a sentinel symbol — see
//! [`block_bit_budget`].
//!
//! # State persistence across blocks
//!
//! [`LzssDecoder`] retains [`Dict`], [`DistCache`], `last_len`,
//! and `output_pos` across `decode_block` calls (these belong
//! to the entry, not the block). The 4 Huffman tables (LD/DD/
//! LDD/RD) are also retained: the block prologue's
//! `is_table_present` flag tells the dispatcher whether to
//! parse fresh tables or reuse the previous block's. Filters
//! queued by code-256 stay in [`Self::pending_filters`] until
//! the upper layer drains them via
//! [`Self::take_pending_filters`].
//!
//! # Out of scope
//!
//! - Filter *application* — the dispatcher queues filters but
//!   does not apply them. The upper layer (§E1's
//!   `RarStreamDecoder`) buffers raw output and applies queued
//!   filters at the right output position.
//! - Block sequencing — the upper layer feeds one block at a
//!   time. The dispatcher returns the `is_last_block` flag so
//!   the caller knows when to stop.
//! - Multi-volume continuation, encryption, solid-archive
//!   carry-over — all out of scope per `docs/PLAN_rar5_decoder.md`.

use thiserror::Error;

use super::bits::{BitReadError, BitReader};
use super::block_header::{parse_block_header, BlockHeader, BlockHeaderError};
use super::bootstrap::{
    build_meta_huffman, decode_main_table_lengths, read_meta_huffman_lengths, BootstrapError,
    HUFF_TABLE_SIZE,
};
use super::dict::{Dict, DictError};
use super::dist_cache::DistCache;
use super::distance::{decode_distance, DistanceError};
use super::filters::{Filter, FilterError, FilterType};
use super::huffman::{HuffTable, HuffmanError};
use super::length::{decode_length, LengthError};

/// Length of the LD (literal / length) sub-table inside the
/// 430-element main code-length array. libarchive's
/// `HUFF_NC = 306`.
pub const HUFF_NC: usize = 306;

/// Length of the DD (distance) sub-table. libarchive's
/// `HUFF_DC = 64`.
pub const HUFF_DC: usize = 64;

/// Length of the LDD (low-distance) sub-table. libarchive's
/// `HUFF_LDC = 16`.
pub const HUFF_LDC: usize = 16;

/// Length of the RD (repeat-distance) sub-table. libarchive's
/// `HUFF_RC = 44`.
pub const HUFF_RC: usize = 44;

// Static check: the four sub-tables must sum to the bootstrap's
// HUFF_TABLE_SIZE, otherwise the splitter below would over- or
// under-read the parsed lengths.
const _: () = assert!(HUFF_NC + HUFF_DC + HUFF_LDC + HUFF_RC == HUFF_TABLE_SIZE);

/// Symbol number that signals "create a new filter descriptor"
/// in libarchive's main alphabet.
pub const SYMBOL_FILTER: u32 = 256;

/// Symbol number that signals "repeat the previous match's
/// length at the most-recent distance" (libarchive's `num == 257`
/// branch).
pub const SYMBOL_REPEAT_LAST: u32 = 257;

/// First symbol that selects a [`DistCache`] slot
/// (`num - SYMBOL_DIST_CACHE_BASE` indexes the cache).
pub const SYMBOL_DIST_CACHE_BASE: u32 = 258;

/// First symbol that decodes as a fresh `(length, distance)`
/// match. `num - SYMBOL_LENGTH_CODE_BASE` is the length code
/// fed to [`decode_length`].
pub const SYMBOL_LENGTH_CODE_BASE: u32 = 262;

/// Maximum allowed filter `block_length` (libarchive caps it at
/// 4 MiB — `0x40_0000`).
pub const MAX_FILTER_BLOCK_LENGTH: u32 = 0x0040_0000;

/// Minimum allowed filter `block_length`. E8/E8E9/ARM read
/// 4-byte instructions, so a sub-4-byte block is malformed.
pub const MIN_FILTER_BLOCK_LENGTH: u32 = 4;

/// Errors produced by the dispatcher.
#[derive(Debug, Error)]
pub enum LzssError {
    /// The block prologue parser surfaced a [`BlockHeaderError`].
    #[error("LZSS dispatcher: block header: {0}")]
    BlockHeader(#[from] BlockHeaderError),

    /// `block_size + header_bytes` exceeded the supplied byte
    /// slice's length.
    #[error(
        "LZSS dispatcher: block runs past supplied buffer (header_bytes = {header_bytes}, \
         block_size = {block_size}, buf_len = {buf_len})"
    )]
    BlockTruncated {
        /// Header bytes the prologue parser consumed.
        header_bytes: usize,
        /// `BlockHeader::block_size`.
        block_size: u64,
        /// The supplied buffer's length.
        buf_len: usize,
    },

    /// The bit cursor went past the block's last bit before the
    /// dispatcher could decode the next symbol. Caller should
    /// treat as a malformed-archive error.
    #[error("LZSS dispatcher: block_size = 0 (every block must have at least 1 byte)")]
    EmptyBlock,

    /// Bootstrap of the per-block code-length tables failed.
    #[error("LZSS dispatcher: bootstrap: {0}")]
    Bootstrap(#[from] BootstrapError),

    /// Building one of the 4 sub-tables (LD/DD/LDD/RD) from the
    /// bootstrap's lengths failed.
    #[error("LZSS dispatcher: build {table} Huffman: {source}")]
    BuildHuffman {
        /// Which sub-table failed: `"LD"`, `"DD"`, `"LDD"`, or `"RD"`.
        table: &'static str,
        /// The underlying [`HuffmanError`].
        #[source]
        source: HuffmanError,
    },

    /// The dispatcher was asked to decode a block that didn't
    /// carry fresh tables (`is_table_present == false`) before
    /// any prior block had landed tables. libarchive rejects this
    /// (it implies the encoder lied about table presence).
    #[error("LZSS dispatcher: first block must carry Huffman tables (is_table_present = false)")]
    TablesMissing,

    /// Decoding a symbol from the LD/DD/RD/LDD Huffman miss-fired.
    #[error("LZSS dispatcher: decode {table} symbol: {source}")]
    HuffDecode {
        /// Which sub-table fired: `"LD"`, `"DD"`, `"LDD"`, or `"RD"`.
        table: &'static str,
        /// The underlying [`HuffmanError`].
        #[source]
        source: HuffmanError,
    },

    /// Bitstream ran out mid-decode (between symbols, or while
    /// reading extra bits).
    #[error("LZSS dispatcher: bitstream underrun: {0}")]
    BitRead(#[from] BitReadError),

    /// [`decode_length`] surfaced an error (out-of-range code or
    /// underrun).
    #[error("LZSS dispatcher: decode length: {0}")]
    Length(#[from] LengthError),

    /// [`decode_distance`] surfaced an error.
    #[error("LZSS dispatcher: decode distance: {0}")]
    Distance(#[from] DistanceError),

    /// [`Dict::push_literal`] / [`Dict::copy_match`] surfaced an
    /// error.
    #[error("LZSS dispatcher: dictionary: {0}")]
    Dict(#[from] DictError),

    /// [`FilterType::from_wire`] rejected the type code or the
    /// DELTA channel count.
    #[error("LZSS dispatcher: filter: {0}")]
    Filter(#[from] FilterError),

    /// `parse_filter`'s `block_length` was outside the
    /// `[`MIN_FILTER_BLOCK_LENGTH`], `[`MAX_FILTER_BLOCK_LENGTH`]]
    /// range.
    #[error("LZSS dispatcher: filter block_length {got} out of range")]
    InvalidFilterBlockLength {
        /// The wire-decoded `block_length`.
        got: u32,
    },

    /// Computing the filter's absolute `block_start` overflowed
    /// `u64`.
    #[error("LZSS dispatcher: filter block_start overflow (output_pos + offset)")]
    FilterBlockStartOverflow,

    /// Deriving the dist-cache index from `num` underflowed —
    /// reachable only if a future change miscategorises `num`,
    /// kept as a defensive guard.
    #[error("LZSS dispatcher: dist-cache symbol {got} below SYMBOL_DIST_CACHE_BASE")]
    DistCacheUnderflow {
        /// Offending `num`.
        got: u32,
    },
}

/// LZSS dispatcher state. One instance per RAR5 entry.
#[derive(Debug)]
pub struct LzssDecoder {
    dict: Dict,
    dist_cache: DistCache,
    /// libarchive's `cstate.last_len` — the length of the most
    /// recent match. Used by the `num == 257` branch to repeat
    /// the previous match. Persists across blocks.
    last_len: u32,
    /// Absolute byte position in the decoded output stream.
    /// Filter descriptors store positions relative to this.
    output_pos: u64,
    /// Filters queued by `num == 256` symbols. The upper layer
    /// drains these via [`Self::take_pending_filters`].
    pending_filters: Vec<Filter>,
    /// LD (literal / length) Huffman, persisted across blocks.
    /// Set by the first block with `is_table_present`.
    ld: Option<HuffTable>,
    /// DD (distance slot) Huffman, persisted across blocks.
    dd: Option<HuffTable>,
    /// LDD (low-distance) Huffman, persisted across blocks.
    ldd: Option<HuffTable>,
    /// RD (repeat-distance length code) Huffman, persisted
    /// across blocks.
    rd: Option<HuffTable>,
}

impl LzssDecoder {
    /// Construct a fresh decoder with a [`Dict`] of `dict_capacity`
    /// bytes.
    ///
    /// # Errors
    ///
    /// Forwards any [`DictError`] from [`Dict::new`] (capacity
    /// zero or above [`super::dict::MAX_DICT_BYTES`]).
    pub fn new(dict_capacity: usize) -> Result<Self, DictError> {
        Ok(Self {
            dict: Dict::new(dict_capacity)?,
            dist_cache: DistCache::default(),
            last_len: 0,
            output_pos: 0,
            pending_filters: Vec::new(),
            ld: None,
            dd: None,
            ldd: None,
            rd: None,
        })
    }

    /// Decode one block. `block` covers the prologue (2 bytes +
    /// `byte_count` bytes for the block-size field) followed by
    /// the block's `block_size`-byte bitstream — exactly what
    /// the upper layer reads from the wire.
    ///
    /// Decoded bytes are appended to `out`. Returns `true` if
    /// the prologue's `is_last_block` flag is set, signalling
    /// the dispatcher's caller that the entry's bitstream is
    /// complete after applying any pending filters.
    ///
    /// # Errors
    ///
    /// Wraps every underlying module's error type into
    /// [`LzssError`]. Per AGENTS.md the dispatcher does not
    /// silently swallow corruption; every propagated error
    /// indicates a malformed archive or an internal invariant
    /// violation.
    pub fn decode_block(&mut self, block: &[u8], out: &mut Vec<u8>) -> Result<bool, LzssError> {
        let hdr = parse_block_header(block)?;
        let buf_len = block.len();
        if hdr.block_size == 0 {
            return Err(LzssError::EmptyBlock);
        }
        let block_size_usz =
            usize::try_from(hdr.block_size).map_err(|_| LzssError::BlockTruncated {
                header_bytes: hdr.header_bytes,
                block_size: hdr.block_size,
                buf_len,
            })?;
        let bitstream_end =
            hdr.header_bytes
                .checked_add(block_size_usz)
                .ok_or(LzssError::BlockTruncated {
                    header_bytes: hdr.header_bytes,
                    block_size: hdr.block_size,
                    buf_len,
                })?;
        if bitstream_end > buf_len {
            return Err(LzssError::BlockTruncated {
                header_bytes: hdr.header_bytes,
                block_size: hdr.block_size,
                buf_len,
            });
        }
        let bitstream = &block[hdr.header_bytes..bitstream_end];
        let mut reader = BitReader::new(bitstream);

        if hdr.is_table_present {
            self.parse_tables(&mut reader)?;
        }
        // Direct field access yields disjoint borrows: ld/dd/ldd/rd
        // hold immutable refs to the Option<HuffTable> fields, while
        // dispatch_symbol below borrows the orthogonal state fields
        // mutably. Going through a `&self` helper would conflate
        // them under a single whole-struct borrow and trip the
        // checker.
        let ld = self.ld.as_ref().ok_or(LzssError::TablesMissing)?;
        let dd = self.dd.as_ref().ok_or(LzssError::TablesMissing)?;
        let ldd = self.ldd.as_ref().ok_or(LzssError::TablesMissing)?;
        let rd = self.rd.as_ref().ok_or(LzssError::TablesMissing)?;

        let total_bits = block_bit_budget(&hdr);

        loop {
            if reader.bits_consumed() >= total_bits {
                break;
            }
            let num = ld
                .decode(&mut reader)
                .map_err(|source| LzssError::HuffDecode {
                    table: "LD",
                    source,
                })?;
            dispatch_symbol(
                &mut self.dict,
                &mut self.dist_cache,
                &mut self.last_len,
                &mut self.output_pos,
                &mut self.pending_filters,
                dd,
                ldd,
                rd,
                u32::from(num),
                &mut reader,
                out,
            )?;
        }

        Ok(hdr.is_last_block)
    }

    /// Parse a fresh set of code-length tables from the
    /// bitstream and rebuild all 4 sub-Huffmans.
    fn parse_tables(&mut self, reader: &mut BitReader<'_>) -> Result<(), LzssError> {
        let meta_lengths = read_meta_huffman_lengths(reader)?;
        let meta = build_meta_huffman(&meta_lengths)?;
        let mut combined = [0u8; HUFF_TABLE_SIZE];
        decode_main_table_lengths(reader, &meta, &mut combined)?;

        let split_dd = HUFF_NC;
        let split_ldd = split_dd + HUFF_DC;
        let split_rd = split_ldd + HUFF_LDC;

        self.ld = Some(HuffTable::build(&combined[..split_dd]).map_err(|source| {
            LzssError::BuildHuffman {
                table: "LD",
                source,
            }
        })?);
        self.dd = Some(
            HuffTable::build(&combined[split_dd..split_ldd]).map_err(|source| {
                LzssError::BuildHuffman {
                    table: "DD",
                    source,
                }
            })?,
        );
        self.ldd = Some(
            HuffTable::build(&combined[split_ldd..split_rd]).map_err(|source| {
                LzssError::BuildHuffman {
                    table: "LDD",
                    source,
                }
            })?,
        );
        self.rd = Some(HuffTable::build(&combined[split_rd..]).map_err(|source| {
            LzssError::BuildHuffman {
                table: "RD",
                source,
            }
        })?);
        Ok(())
    }

    /// Borrow the pending-filter list. The upper layer applies
    /// them at the right output offset; the dispatcher itself
    /// never inspects this list after queueing.
    #[must_use]
    pub fn pending_filters(&self) -> &[Filter] {
        &self.pending_filters
    }

    /// Drain the pending-filter list, transferring ownership to
    /// the caller. Used by §E1's integration to apply queued
    /// filters between dispatcher calls.
    pub fn take_pending_filters(&mut self) -> Vec<Filter> {
        std::mem::take(&mut self.pending_filters)
    }

    /// Borrow the underlying [`Dict`] for the upper layer's
    /// resume snapshot or filter-window read-back.
    #[must_use]
    pub fn dict(&self) -> &Dict {
        &self.dict
    }

    /// Mutable borrow on the underlying [`Dict`]. Used by §F1
    /// resume to restore from snapshot bytes.
    pub fn dict_mut(&mut self) -> &mut Dict {
        &mut self.dict
    }

    /// Cumulative bytes the dispatcher has written into `out`
    /// over its lifetime. Used by the upper layer to position
    /// queued filters and to drive the entry's progress meter.
    #[must_use]
    pub fn output_pos(&self) -> u64 {
        self.output_pos
    }

    /// Length of the most-recent match (libarchive's
    /// `cstate.last_len`). Useful for the §F1 resume blob.
    #[must_use]
    pub fn last_len(&self) -> u32 {
        self.last_len
    }

    /// Borrow the recent-distance cache.
    #[must_use]
    pub fn dist_cache(&self) -> &DistCache {
        &self.dist_cache
    }
}

/// Dispatch one decoded `num` per the libarchive symbol
/// semantics described at the module-level doc.
///
/// Free function rather than a method so the caller can pass
/// disjoint `&mut` refs to the decoder's state fields without
/// fighting the borrow checker — the loop in
/// [`LzssDecoder::decode_block`] holds an immutable borrow on
/// `self.ld` for the duration of the loop.
#[allow(clippy::too_many_arguments)]
fn dispatch_symbol(
    dict: &mut Dict,
    dist_cache: &mut DistCache,
    last_len: &mut u32,
    output_pos: &mut u64,
    pending_filters: &mut Vec<Filter>,
    dd: &HuffTable,
    ldd: &HuffTable,
    rd: &HuffTable,
    num: u32,
    reader: &mut BitReader<'_>,
    out: &mut Vec<u8>,
) -> Result<(), LzssError> {
    if num < 256 {
        // Literal byte.
        dict.push_literal(num as u8, out);
        *output_pos = output_pos.saturating_add(1);
        Ok(())
    } else if num >= SYMBOL_LENGTH_CODE_BASE {
        // Fresh (length, distance) match.
        let len_code = u16::try_from(num - SYMBOL_LENGTH_CODE_BASE).unwrap_or(u16::MAX);
        let length_raw = decode_length(len_code, reader)?;
        let dist_slot = dd.decode(reader).map_err(|source| LzssError::HuffDecode {
            table: "DD",
            source,
        })?;
        let distance = decode_distance(dist_slot, reader, ldd)?;
        // libarchive's distance-dependent length bumps (lines
        // 3296-3306). Saturating add keeps the path panic-free
        // against malformed distances.
        let mut adjusted = length_raw;
        if distance > 0x100 {
            adjusted = adjusted.saturating_add(1);
        }
        if distance > 0x2000 {
            adjusted = adjusted.saturating_add(1);
        }
        if distance > 0x40000 {
            adjusted = adjusted.saturating_add(1);
        }
        dist_cache.push(distance);
        *last_len = adjusted;
        dict.copy_match(u64::from(distance), u64::from(adjusted), out)?;
        *output_pos = output_pos.saturating_add(u64::from(adjusted));
        Ok(())
    } else if num == SYMBOL_FILTER {
        let filter = parse_filter(*output_pos, reader)?;
        pending_filters.push(filter);
        Ok(())
    } else if num == SYMBOL_REPEAT_LAST {
        // Code 257: repeat the previous match using the
        // most-recent distance (no cache shift).
        if *last_len != 0 {
            let dist = dist_cache.peek(0);
            dict.copy_match(u64::from(dist), u64::from(*last_len), out)?;
            *output_pos = output_pos.saturating_add(u64::from(*last_len));
        }
        Ok(())
    } else {
        // 258..=261: dist-cache hit. `num - 258` indexes the
        // cache; the length code comes from the RD Huffman.
        let idx = num
            .checked_sub(SYMBOL_DIST_CACHE_BASE)
            .ok_or(LzssError::DistCacheUnderflow { got: num })? as usize;
        let dist = dist_cache.touch(idx);
        let len_code = rd.decode(reader).map_err(|source| LzssError::HuffDecode {
            table: "RD",
            source,
        })?;
        let length = decode_length(len_code, reader)?;
        *last_len = length;
        dict.copy_match(u64::from(dist), u64::from(length), out)?;
        *output_pos = output_pos.saturating_add(u64::from(length));
        Ok(())
    }
}

/// Parse a filter descriptor off the bitstream (libarchive's
/// `parse_filter` at line 3029). Reads:
///
/// 1. A `parse_filter_data`-encoded `block_start_offset`
///    (relative to `output_pos`).
/// 2. A `parse_filter_data`-encoded `block_length`.
/// 3. 3 bits of `filter_type`.
/// 4. (DELTA only) 5 bits of `channels - 1`.
fn parse_filter(output_pos: u64, reader: &mut BitReader<'_>) -> Result<Filter, LzssError> {
    let block_start_offset = parse_filter_data(reader)?;
    let block_length = parse_filter_data(reader)?;
    let type_code = reader.read_bits(3)? as u8;

    if !(MIN_FILTER_BLOCK_LENGTH..=MAX_FILTER_BLOCK_LENGTH).contains(&block_length) {
        return Err(LzssError::InvalidFilterBlockLength { got: block_length });
    }

    let block_start = output_pos
        .checked_add(u64::from(block_start_offset))
        .ok_or(LzssError::FilterBlockStartOverflow)?;

    let channels = if type_code == 0 {
        // DELTA: 5 bits encode `channels - 1`.
        (reader.read_bits(5)? as u8).saturating_add(1)
    } else {
        // Other filters: channel count is unused; pass 1 to
        // satisfy `FilterType::from_wire`'s validator (which
        // only inspects channels for DELTA).
        1
    };

    let kind = FilterType::from_wire(type_code, channels)?;
    Ok(Filter {
        kind,
        block_start,
        block_length,
    })
}

/// Decode a `parse_filter_data`-encoded integer from the
/// bitstream. The wire format is: 2 bits of `byte_count - 1`
/// (so 1..=4 bytes follow), then `byte_count` bytes laid out
/// little-endian (byte 0 is bits 0..8 of the result, byte 1 is
/// bits 8..16, ...).
///
/// Mirrors libarchive's `parse_filter_data` at line 2976.
///
/// # Errors
///
/// - [`BitReadError`] from any of the 1+`byte_count` reads.
fn parse_filter_data(reader: &mut BitReader<'_>) -> Result<u32, BitReadError> {
    // 2 bits give the byte count - 1, so 1..=4 bytes follow.
    let bytes = reader.read_bits(2)? + 1;
    let mut data: u32 = 0;
    for i in 0..bytes {
        let byte = reader.read_bits(8)?;
        // INVARIANT: bytes <= 4, so i <= 3 and i*8 <= 24, which
        // means the shift never exceeds u32's width.
        data |= byte << (i * 8);
    }
    Ok(data)
}

/// Total bits the dispatcher should consume from the block's
/// bitstream before treating the block as done. Mirrors
/// libarchive's `bit_size = 1 + bf_bit_size(hdr)` plus the
/// loop-end check.
///
/// Returns `(block_size - 1) * 8 + (bit_size + 1)`. For the
/// degenerate `block_size = 0` case the helper saturates to
/// 0 — the caller is responsible for rejecting empty blocks
/// (the [`LzssDecoder::decode_block`] entry point does so
/// before calling this).
fn block_bit_budget(hdr: &BlockHeader) -> u64 {
    let block_bytes = hdr.block_size;
    if block_bytes == 0 {
        return 0;
    }
    let last_byte_bits = u64::from(hdr.bit_size) + 1;
    (block_bytes - 1) * 8 + last_byte_bits
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a sequence of `(value, n_bits)` tuples into
    /// MSB-first bytes. Mirrors `huffman::tests::encode_codes`,
    /// reused here so tests construct hand-crafted bitstreams
    /// without cross-module wiring.
    fn encode_bits(groups: &[(u32, u32)]) -> Vec<u8> {
        let mut acc: u64 = 0;
        let mut nbits: u32 = 0;
        let mut out = Vec::new();
        for &(value, n) in groups {
            assert!(n > 0 && n <= 32);
            let masked = value & ((1u64 << n) - 1) as u32;
            acc |= u64::from(masked) << (64 - nbits - n);
            nbits += n;
            while nbits >= 8 {
                out.push((acc >> 56) as u8);
                acc <<= 8;
                nbits -= 8;
            }
        }
        if nbits > 0 {
            out.push((acc >> 56) as u8);
        }
        out
    }

    #[test]
    fn parse_filter_data_round_trips_one_byte_value() {
        // 2 bits of byte_count - 1 = 0 (=> 1 byte follows), then
        // 8 bits of 0x42.
        let wire = encode_bits(&[(0b00, 2), (0x42, 8)]);
        let mut reader = BitReader::new(&wire);
        let got = parse_filter_data(&mut reader).expect("well-formed wire");
        assert_eq!(got, 0x42);
    }

    #[test]
    fn parse_filter_data_round_trips_three_byte_value() {
        // 2 bits = 0b10 (byte_count - 1 = 2 => 3 bytes), bytes
        // = 0xAA, 0xBB, 0xCC, laying out little-endian:
        // result = 0xAA | (0xBB << 8) | (0xCC << 16) = 0x00CC_BBAA.
        let wire = encode_bits(&[(0b10, 2), (0xAA, 8), (0xBB, 8), (0xCC, 8)]);
        let mut reader = BitReader::new(&wire);
        let got = parse_filter_data(&mut reader).expect("well-formed wire");
        assert_eq!(got, 0x00CC_BBAA);
    }

    #[test]
    fn parse_filter_data_round_trips_four_byte_value() {
        let wire = encode_bits(&[(0b11, 2), (0x11, 8), (0x22, 8), (0x33, 8), (0x44, 8)]);
        let mut reader = BitReader::new(&wire);
        let got = parse_filter_data(&mut reader).expect("well-formed wire");
        assert_eq!(got, 0x4433_2211);
    }

    #[test]
    fn parse_filter_data_propagates_underrun() {
        // 2 bits say 4 bytes follow, but only 1 byte of data
        // remains.
        let wire = encode_bits(&[(0b11, 2), (0x55, 8)]);
        let mut reader = BitReader::new(&wire);
        let err = parse_filter_data(&mut reader).expect_err("source under-supplies");
        assert!(matches!(err, BitReadError::Underrun { .. }));
    }

    #[test]
    fn block_bit_budget_handles_full_last_byte() {
        // bit_size = 7 means the last byte uses all 8 bits
        // (libarchive's `1 + 7 = 8`). With block_size = 3 the
        // budget is (3 - 1)*8 + 8 = 24 bits.
        let hdr = BlockHeader {
            bit_size: 7,
            byte_count: 1,
            is_last_block: false,
            is_table_present: true,
            block_size: 3,
            header_bytes: 3,
        };
        assert_eq!(block_bit_budget(&hdr), 24);
    }

    #[test]
    fn block_bit_budget_handles_partial_last_byte() {
        // bit_size = 0 => last byte holds only 1 bit. block_size
        // = 5 => budget is 4*8 + 1 = 33 bits.
        let hdr = BlockHeader {
            bit_size: 0,
            byte_count: 1,
            is_last_block: false,
            is_table_present: true,
            block_size: 5,
            header_bytes: 3,
        };
        assert_eq!(block_bit_budget(&hdr), 33);
    }

    #[test]
    fn block_bit_budget_zero_for_empty_block() {
        let hdr = BlockHeader {
            bit_size: 0,
            byte_count: 1,
            is_last_block: false,
            is_table_present: true,
            block_size: 0,
            header_bytes: 3,
        };
        assert_eq!(block_bit_budget(&hdr), 0);
    }

    #[test]
    fn new_constructs_with_default_state() {
        let dec = LzssDecoder::new(64).expect("64-byte dict OK");
        assert_eq!(dec.dict().capacity(), 64);
        assert_eq!(dec.dict().total_written(), 0);
        assert_eq!(dec.last_len(), 0);
        assert_eq!(dec.output_pos(), 0);
        assert_eq!(dec.pending_filters().len(), 0);
    }

    #[test]
    fn new_propagates_dict_errors() {
        let err = LzssDecoder::new(0).expect_err("zero capacity rejected");
        assert!(matches!(err, DictError::CapacityZero));
    }

    #[test]
    fn take_pending_filters_drains_in_order() {
        let mut dec = LzssDecoder::new(16).expect("dict OK");
        dec.pending_filters.push(Filter {
            kind: FilterType::E8,
            block_start: 100,
            block_length: 256,
        });
        dec.pending_filters.push(Filter {
            kind: FilterType::Arm,
            block_start: 400,
            block_length: 512,
        });
        let drained = dec.take_pending_filters();
        assert_eq!(drained.len(), 2);
        assert!(matches!(drained[0].kind, FilterType::E8));
        assert!(matches!(drained[1].kind, FilterType::Arm));
        assert_eq!(dec.take_pending_filters().len(), 0);
    }

    #[test]
    fn decode_block_rejects_truncated_block_buffer() {
        // A valid 2-byte prologue with byte_count = 1 says the
        // block is 0xFF bytes long, but we only supply the
        // 3-byte header.
        let flags: u8 = 0b1100_0111; // is_last_block + is_table_present + bit_size=7, byte_count_minus_1=0
        let cksum = flags ^ 0x5A;
        let block = [flags, cksum, 0xFF];
        let mut dec = LzssDecoder::new(64).expect("dict OK");
        let mut out = Vec::new();
        let err = dec
            .decode_block(&block, &mut out)
            .expect_err("buffer too short");
        assert!(matches!(err, LzssError::BlockTruncated { .. }));
    }

    #[test]
    fn decode_block_rejects_empty_block_size() {
        // block_size = 0 violates the header invariant. The
        // dispatcher catches it before any bitstream work.
        let flags: u8 = 0b0000_0000; // is_last_block=0, is_table_present=0, bit_size=0, byte_count_minus_1=0
        let cksum = flags ^ 0x5A;
        let block = [flags, cksum, 0x00];
        let mut dec = LzssDecoder::new(64).expect("dict OK");
        let mut out = Vec::new();
        let err = dec
            .decode_block(&block, &mut out)
            .expect_err("empty block rejected");
        assert!(matches!(err, LzssError::EmptyBlock));
    }

    #[test]
    fn decode_block_rejects_first_block_without_tables() {
        // is_table_present = 0, but no prior block has set the
        // tables. block_size = 1, bit_size = 0 (1 valid bit) so
        // the dispatcher gets to the table check before reading
        // anything from the bitstream.
        let flags: u8 = 0b0000_0000;
        let cksum = flags ^ 0x5A;
        // block_size = 1 (LE byte after prologue), bitstream =
        // 1 byte of all zeros (won't be read because tables
        // missing).
        let block = [flags, cksum, 0x01, 0x00];
        let mut dec = LzssDecoder::new(64).expect("dict OK");
        let mut out = Vec::new();
        let err = dec
            .decode_block(&block, &mut out)
            .expect_err("no tables yet");
        assert!(matches!(err, LzssError::TablesMissing));
    }

    #[test]
    fn const_assertion_holds() {
        // The const_assert above the type defs already enforces
        // this, but a runtime test makes the failure mode
        // friendlier if the constants ever drift.
        assert_eq!(HUFF_NC + HUFF_DC + HUFF_LDC + HUFF_RC, HUFF_TABLE_SIZE);
    }
}
