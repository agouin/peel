//! PPMd-II / PPMd7 model and decode loop.
//!
//! Hand-rolled port of LZMA SDK's `Ppmd7.c` model layer. Round-one
//! (`docs/PLAN_rar3.md` §B2) lands the model in three sub-phases:
//!
//! 1. **§B2a (this file's first commit)** — types, lookup tables,
//!    [`Model::new`] / [`Model::restart`], and the SEE-table init.
//!    No decode yet: this commit stands up the foundation that
//!    §B2b's decode loop and update-model code will sit on top of.
//! 2. **§B2b** — [`Model::decode_symbol`], `update_model`,
//!    `create_successors`, `rescale`, `make_esc_freq`, plus a
//!    test-only sister encoder for round-trip verification.
//! 3. **§B2c** — edge-case stress (max-order, model exhaustion,
//!    repeated restarts).
//!
//! # Layout
//!
//! Every model node lives in the [`Allocator`] arena as a sequence
//! of unit-aligned bytes. Two on-disk struct shapes:
//!
//! - **`State`** (6 bytes, two per [`UNIT_SIZE`]-byte unit): one
//!   `(symbol, freq, successor)` triple. The successor is a 32-bit
//!   value carried as `(SuccessorLow: u16, SuccessorHigh: u16)` so
//!   the struct stays 6 bytes packed regardless of compiler
//!   alignment rules.
//! - **`Context`** (12 bytes, exactly one unit): an order-N tree
//!   node. For multi-state contexts (`num_stats > 1`) the layout is
//!   `(num_stats, summ_freq, stats_ref, suffix_ref)`. For 1-state
//!   contexts the inline state replaces `summ_freq` + `stats_ref`,
//!   so the on-disk shape stays 12 bytes either way.
//!
//! The model's "text region" — bytes [`Allocator::text`] grows
//! through — stores the linear sequence of emitted symbols. State
//! `successor` fields can point either into the text region (a
//! "bytes-yet-to-be-promoted" link) or into the unit region (a
//! "branch into a child context"). The promotion happens lazily in
//! `create_successors` (B2b).
//!
//! # References
//!
//! - LZMA SDK `Ppmd7.c` — public domain (Igor Pavlov), based on
//!   PPMd var.H by Dmitry Shkarin (2001). The canonical reference.
//! - libarchive `archive_ppmd7.c` — BSD-2-Clause; the libarchive
//!   redistribution adds the `PpmdRAR_*` range-coder variant the
//!   legacy RAR pipeline ultimately needs (the model itself is
//!   variant-agnostic).
//! - Shkarin, *PPM: one step to practicality*, DCC 2002 — the
//!   algorithm's original statement.

use thiserror::Error;

use super::alloc::{AllocError, Allocator, Ref, PPMD_NUM_INDEXES, UNITS_TO_INDX, UNIT_SIZE};
use super::range_dec::{RangeDecoder, RangeDecoderError};

/// Lower bound on supported model order (`maxOrder` parameter).
/// Order 1 reduces the model to a degenerate 2-symbol predictor;
/// the LZMA SDK refuses to construct one. Round-one matches.
pub const MIN_ORDER: u32 = 2;

/// Upper bound on supported model order. The LZMA SDK caps at 64;
/// in practice legacy RAR archives top out around order-16 (the
/// archive's `unp_ver` byte carries the order in the low bits of the
/// PPMd "info" header). Round-one accepts the full SDK range.
pub const MAX_ORDER: u32 = 64;

/// Smallest arena the model can run in. Just below the LZMA SDK's
/// `PPMD7_MIN_MEM_SIZE = 1 << 11 = 2048`. Sized so the model's
/// initial 129-unit (1548-byte) working set fits without taking the
/// rare allocation path.
pub const MIN_MEM_SIZE: usize = 2048;

/// Maximum arena. Mirrors the LZMA SDK's `PPMD7_MAX_MEM_SIZE`
/// (`0xFFFFFFFFu - 12 * 3`), which is the largest 32-bit-clean size
/// after the trailing alignment slack.
pub const MAX_MEM_SIZE: usize = 0xFFFF_FFFFu32 as usize - 12 * 3;

/// Total of the binary-context probability scale (≡ `1 << 14`).
/// Mirrors libarchive / LZMA SDK's `PPMD_BIN_SCALE`.
const PPMD_BIN_SCALE: u32 = 1 << 14;

/// Per-state frequency cap. When [`Model::update1_0`] / [`Model::update1`]
/// pushes a state's frequency above this, [`Model::rescale`] kicks in
/// and halves every frequency in the context. Matches LZMA SDK's
/// `MAX_FREQ`.
const MAX_FREQ: u32 = 124;

/// Initial seeds for the binary-context SEE table, indexed by the
/// low 3 bits of the previous-context bucket index. The full
/// initial value (per `RestartModel`) is
/// `BIN_SCALE - K_INIT_BIN_ESC[k] / (i + 2)` where `i ∈ [0, 128)`.
const K_INIT_BIN_ESC: [u16; 8] = [
    0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051,
];

/// Adaptive escape-probability multiplier table. Indexed by
/// `prob >> 10` (the top 4 bits of a binary-SEE prob). After the
/// binary path observes a 1-bit (escape), the model loads
/// `init_esc` from this table to drive the masked-escape walk.
const K_EXP_ESCAPE: [u8; 16] = [25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2];

/// `Ppmd_See_Update` shift in [`See::update`]. Equals
/// `PPMD_PERIOD_BITS` from `archive_ppmd_private.h`.
const PPMD_PERIOD_BITS: u8 = 7;

// ── Lookup tables ────────────────────────────────────────────────

/// Maps `num_stats - 1` to a binary-SEE bucket multiplier. Pattern:
/// `[0]=0, [1]=2, [2..11]=4, [11..]=6`. Mirrors `RestartModel`'s
/// `NS2BSIndx` initialiser in libarchive `archive_ppmd7.c`.
const NS2_BS_INDX: [u8; 256] = build_ns2_bs_indx();

/// Maps `num_stats - 1` to an n-ary SEE bucket index (`0..25`).
/// Pattern: 0, 1, 2, then `m` repeated `m - 2` times for
/// `m = 3, 4, 5, ...`. Indexes into [`Model::see`] via `make_esc_freq`.
const NS2_INDX: [u8; 256] = build_ns2_indx();

/// Maps a symbol to a "high-bits flag" (0 or 8). Symbols with bit 6
/// set (`>= 0x40`) map to 8; the rest to 0. The flag is added to
/// the n-ary SEE index in `make_esc_freq`.
const HB2_FLAG: [u8; 256] = build_hb2_flag();

const fn build_ns2_bs_indx() -> [u8; 256] {
    let mut arr = [0u8; 256];
    arr[0] = 0;
    arr[1] = 2;
    let mut i = 2;
    while i < 11 {
        arr[i] = 4;
        i += 1;
    }
    while i < 256 {
        arr[i] = 6;
        i += 1;
    }
    arr
}

const fn build_ns2_indx() -> [u8; 256] {
    let mut arr = [0u8; 256];
    let mut i = 0;
    while i < 3 {
        arr[i] = i as u8;
        i += 1;
    }
    let mut m: u8 = 3;
    let mut k: u8 = 1;
    while i < 256 {
        arr[i] = m;
        k -= 1;
        if k == 0 {
            m += 1;
            k = m - 2;
        }
        i += 1;
    }
    arr
}

const fn build_hb2_flag() -> [u8; 256] {
    let mut arr = [0u8; 256];
    let mut i = 0x40;
    while i < 256 {
        arr[i] = 8;
        i += 1;
    }
    arr
}

// ── State / Context byte-offset accessors ─────────────────────────
//
// On-disk layouts (matching LZMA SDK Ppmd7.c, in turn matching
// libarchive's `archive_ppmd7_private.h`):
//
//   CPpmd_State (6 bytes):
//     +0  Symbol         u8
//     +1  Freq           u8
//     +2  SuccessorLow   u16 LE
//     +4  SuccessorHigh  u16 LE
//
//   CPpmd7_Context (12 bytes = 1 UNIT_SIZE):
//     +0  NumStats       u16 LE
//     +2  SummFreq       u16 LE   (multi-state) /
//         Symbol+Freq    2× u8    (1-state inline; +2 = symbol, +3 = freq)
//     +4  Stats          u32 LE   (multi-state ref) /
//         SuccessorLow+H 2× u16   (1-state inline)
//     +8  Suffix         u32 LE
//
// Single-state contexts overlay the inline `State` at offset +2,
// reusing the 4 bytes that would carry SummFreq + the Stats ref.

const CTX_NUM_STATS_OFF: usize = 0;
const CTX_SUMM_FREQ_OFF: usize = 2;
const CTX_STATS_OFF: usize = 4;
const CTX_SUFFIX_OFF: usize = 8;

/// Byte offset within a 1-state context where the inline state begins.
/// The 6-byte state overlays bytes [2, 8) — replacing the multi-state
/// layout's `SummFreq` (bytes 2..4) and `Stats` ref (bytes 4..8).
const CTX_INLINE_STATE_OFF: usize = 2;

const STATE_SYMBOL_OFF: usize = 0;
const STATE_FREQ_OFF: usize = 1;
const STATE_SUCCESSOR_LOW_OFF: usize = 2;
const STATE_SUCCESSOR_HIGH_OFF: usize = 4;

/// Bytes per State.
pub(crate) const STATE_SIZE: usize = 6;

#[inline]
fn read_u16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

#[inline]
fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

#[inline]
fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

#[inline]
fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Combine the two `SuccessorLow` / `SuccessorHigh` u16 halves at
/// the given State offset into the 32-bit successor ref.
#[inline]
fn read_successor(buf: &[u8], state_off: usize) -> u32 {
    let lo = read_u16(buf, state_off + STATE_SUCCESSOR_LOW_OFF);
    let hi = read_u16(buf, state_off + STATE_SUCCESSOR_HIGH_OFF);
    u32::from(lo) | (u32::from(hi) << 16)
}

/// Split a 32-bit successor ref into the State's two u16 halves.
#[inline]
fn write_successor(buf: &mut [u8], state_off: usize, v: u32) {
    write_u16(buf, state_off + STATE_SUCCESSOR_LOW_OFF, v as u16);
    write_u16(buf, state_off + STATE_SUCCESSOR_HIGH_OFF, (v >> 16) as u16);
}

// Compile-time assertion that the on-disk Context layout's
// 1-state inline overlay aligns with the multi-state field offsets.
// The 1-state state's `SuccessorLow` u16 (at state offset +2)
// must land where the multi-state context's `Stats` ref begins
// (at context offset +4 — i.e. CTX_INLINE_STATE_OFF + 2 = 4).
// If this ever drifts, both the tests and §B2b's typed accessors
// would silently corrupt one of the two overlays.
const _: () = {
    assert!(CTX_INLINE_STATE_OFF + STATE_SUCCESSOR_LOW_OFF == CTX_STATS_OFF);
    assert!(CTX_INLINE_STATE_OFF + STATE_SYMBOL_OFF == CTX_SUMM_FREQ_OFF);
    assert!(STATE_SIZE == 6);
};

// ── Errors ────────────────────────────────────────────────────────

/// Errors from [`Model::new`] / [`Model::restart`].
#[derive(Debug, Error, Eq, PartialEq)]
pub enum ModelError {
    /// Caller-supplied `max_order` was out of [[`MIN_ORDER`], [`MAX_ORDER`]].
    #[error("PPMd-II model order {order} out of [{MIN_ORDER}, {MAX_ORDER}]")]
    BadOrder {
        /// The rejected order value.
        order: u32,
    },
    /// Caller-supplied arena was too small. Mirrors
    /// [`AllocError::ArenaTooSmall`] but catches the model-specific
    /// minimum ([`MIN_MEM_SIZE`] = 2 KiB) before it reaches the
    /// allocator (whose own minimum is one unit + padding).
    #[error("PPMd-II model arena too small: {requested} bytes (minimum {MIN_MEM_SIZE})")]
    ArenaTooSmall {
        /// The rejected size in bytes.
        requested: usize,
    },
    /// Caller-supplied arena exceeded [`MAX_MEM_SIZE`]. Surfaced via
    /// the underlying [`AllocError::ArenaTooLarge`].
    #[error("PPMd-II model arena too large: {requested} bytes (maximum {MAX_MEM_SIZE})")]
    ArenaTooLarge {
        /// The rejected size in bytes.
        requested: usize,
    },
    /// The arena was sized within [`MIN_MEM_SIZE`] / [`MAX_MEM_SIZE`]
    /// but the underlying allocator rejected it. Currently
    /// unreachable in production — round-one always validates
    /// against the model bounds first — but kept as a typed escape
    /// hatch in case the allocator gains tighter constraints later.
    #[error("PPMd-II allocator rejected arena: {0}")]
    Alloc(#[from] AllocError),
}

/// Errors raised by [`Model::decode_symbol`].
#[derive(Debug, Error, Eq, PartialEq)]
pub enum DecodeError {
    /// The range coder ran out of input, returned a zero total, or
    /// otherwise reported a wire-level fault.
    #[error("PPMd-II decode: range coder: {0}")]
    Range(#[from] RangeDecoderError),
    /// The masked-escape walk reached the order-0 root context with
    /// every symbol already masked. Happens when an encoder writes
    /// the literal end-marker (negative-one symbol) and the decoder
    /// keeps walking past the end of the legitimate output. The
    /// caller should stop consuming the stream.
    #[error("PPMd-II decode: end-marker reached (root context fully masked)")]
    EndMarker,
    /// The range coder produced a threshold past the context's
    /// running total. Indicates a mis-framed input — the decoder
    /// state has diverged from the encoder's. Recoverable only by
    /// abandoning the current PPMd block.
    #[error("PPMd-II decode: malformed symbol (threshold exceeds context summFreq)")]
    Malformed,
}

// ── Per-context SEE state ─────────────────────────────────────────

/// Adaptive escape-probability state for an n-ary context. Each
/// entry tracks a smoothed sum (`summ`) shifted by `shift` bits,
/// with `count` decrementing toward a `shift`-bump deadline. Mirrors
/// `CPpmd_See` from the LZMA SDK reference.
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq)]
struct See {
    summ: u16,
    shift: u8,
    count: u8,
}

impl See {
    /// Decrement the counter; if it hits zero (and `shift` is below
    /// the saturation cap) double the running sum and bump `shift`.
    /// Matches `Ppmd_See_Update` in `archive_ppmd_private.h`.
    fn update(&mut self) {
        if self.shift < PPMD_PERIOD_BITS {
            self.count -= 1;
            if self.count == 0 {
                self.summ = self.summ.wrapping_mul(2);
                self.count = 3 << self.shift;
                self.shift += 1;
            }
        }
    }
}

// ── Model ─────────────────────────────────────────────────────────

/// PPMd-II / PPMd7 decoder model.
///
/// One instance maps to one PPMd block in a legacy RAR archive
/// (`m=4` / `m=5`). Construct via [`Self::new`]; reset between
/// blocks with [`Self::restart`]. The decode loop ([`Self::decode_symbol`],
/// landing in §B2b) consumes a [`super::range_dec::RangeDecoder`].
///
/// The model owns the underlying [`Allocator`] arena. The arena
/// holds the order-N context tree, the per-context state arrays,
/// and the linear text-region byte log the contexts reference.
#[derive(Debug)]
pub struct Model {
    /// Arena holding the context tree, state arrays, and text log.
    alloc: Allocator,
    /// `MinContext` ref — the deepest context that still has the
    /// just-decoded symbol. Updates after every successful symbol
    /// decode.
    min_context: u32,
    /// `MaxContext` ref — the deepest *available* context (≥
    /// `MinContext`). The decode loop walks back from `MaxContext`
    /// toward the suffix tree's root when the model "falls" through
    /// missing symbols.
    max_context: u32,
    /// Byte offset of the just-found state within whichever context
    /// the decoder selected most recently.
    found_state: u32,
    /// Number of orders the decoder fell on the last symbol. Reset
    /// to zero on a hit; bumped by 1 on each escape.
    order_fall: u32,
    /// Initial escape probability in the range coder. Cached at the
    /// last binary-context decode and read by `update_model` /
    /// `make_esc_freq`. Encoded as one of `K_EXP_ESCAPE`.
    init_esc: u32,
    /// `1` if the last symbol decode was a "shortcut hit" (the
    /// first state's freq dominated the context's summFreq). `0`
    /// otherwise. Drives the binary-SEE bucket lookup.
    prev_success: u32,
    /// Caller-configured max model order (the depth at which the
    /// suffix tree truncates).
    max_order: u32,
    /// Cached `HB2Flag[FoundState->Symbol]` from the last decode.
    /// The masked-escape walk re-uses it instead of re-fetching.
    hi_bits_flag: u32,
    /// Trailing run length, used for the binary-SEE prob lookup.
    /// Initialised to `init_rl` at every restart and after every
    /// `update2` call.
    run_length: i32,
    /// Initial value `run_length` is reset to. Computed at restart
    /// from `max_order`.
    init_rl: i32,
    /// SEE table for n-ary contexts: 25 buckets × 16 sub-buckets.
    /// Flattened row-major; access via `see_at(row, col)`.
    see: Vec<See>,
    /// Placeholder SEE entry returned by `make_esc_freq` when the
    /// context is the order-0 root (`num_stats == 256`). Mirrors
    /// the LZMA SDK's `DummySee` field.
    dummy_see: See,
    /// Binary-SEE table: 128 buckets × 64 sub-buckets, each a 14-bit
    /// fixed-point probability. Flattened row-major.
    bin_summ: Vec<u16>,
}

impl Model {
    /// Construct and initialise a fresh model with the given order
    /// and arena size. Performs the equivalent of LZMA SDK's
    /// `Ppmd7_Construct` + `Ppmd7_Alloc` + `Ppmd7_Init` in one call.
    ///
    /// # Errors
    ///
    /// - [`ModelError::BadOrder`] if `max_order` ∉ [[`MIN_ORDER`], [`MAX_ORDER`]].
    /// - [`ModelError::ArenaTooSmall`] if `arena_bytes < MIN_MEM_SIZE`.
    /// - [`ModelError::ArenaTooLarge`] if `arena_bytes > MAX_MEM_SIZE`.
    /// - [`ModelError::Alloc`] if the underlying allocator rejected
    ///   the arena (currently unreachable — both ranges are
    ///   strictly tighter than the allocator's).
    pub fn new(arena_bytes: usize, max_order: u32) -> Result<Self, ModelError> {
        if !(MIN_ORDER..=MAX_ORDER).contains(&max_order) {
            return Err(ModelError::BadOrder { order: max_order });
        }
        if arena_bytes < MIN_MEM_SIZE {
            return Err(ModelError::ArenaTooSmall {
                requested: arena_bytes,
            });
        }
        if arena_bytes > MAX_MEM_SIZE {
            return Err(ModelError::ArenaTooLarge {
                requested: arena_bytes,
            });
        }
        let alloc = Allocator::new(arena_bytes)?;
        let mut me = Self {
            alloc,
            min_context: 0,
            max_context: 0,
            found_state: 0,
            order_fall: 0,
            init_esc: 0,
            prev_success: 0,
            max_order,
            hi_bits_flag: 0,
            run_length: 0,
            init_rl: 0,
            see: vec![See::default(); 25 * 16],
            dummy_see: See::default(),
            bin_summ: vec![0u16; 128 * 64],
        };
        me.restart();
        // `Ppmd7_Init` post-RestartModel touch-up: the `DummySee`
        // never participates in `Ppmd_See_Update` (its Shift is at
        // saturation), so initialise it to a stable shape.
        me.dummy_see = See {
            summ: 0,
            shift: 7, // PPMD_PERIOD_BITS — saturated
            count: 64,
        };
        Ok(me)
    }

    /// Reset the model to its post-init state. Wipes the arena via
    /// [`Allocator::restart`], rebuilds the order-0 root context
    /// (256 states with `freq = 1, symbol = i, successor = 0`),
    /// and seeds the binary / n-ary SEE tables.
    ///
    /// Mirrors `RestartModel` in the LZMA SDK.
    pub fn restart(&mut self) {
        // Reset allocator. After this, `lo_unit..hi_unit` covers the
        // initial unit region (~7/8 of the arena), text region is at
        // `align_offset`, and all freelists are empty.
        self.alloc.restart();

        self.order_fall = self.max_order;
        // INVARIANT: max_order ∈ [MIN_ORDER (=2), MAX_ORDER (=64)],
        // so the cast to i32 cannot lose precision.
        let init_rl = -((if self.max_order < 12 {
            self.max_order
        } else {
            12
        }) as i32)
            - 1;
        self.run_length = init_rl;
        self.init_rl = init_rl;
        self.prev_success = 0;
        self.init_esc = 0;
        self.hi_bits_flag = 0;

        // Allocate the root context (1 unit) and the 128-unit (256
        // states × 6 bytes) state array. Both come straight off the
        // initial unit region without touching the freelists, so
        // `alloc_context` / `alloc_units(37)` are guaranteed to
        // succeed on any arena ≥ MIN_MEM_SIZE.
        // INVARIANT: MIN_MEM_SIZE = 2 KiB sizes the unit region at
        // ≥ 7/8 × ≈2032 ≈ 1778 bytes ≥ 1548 bytes (1 + 128 units).
        let root_ctx = self
            .alloc
            .alloc_context()
            .expect("INVARIANT: MIN_MEM_SIZE leaves room for root context");
        let stats_ref = self
            .alloc
            .alloc_units((PPMD_NUM_INDEXES - 1) as u32)
            .expect("INVARIANT: MIN_MEM_SIZE leaves room for 128-unit state array");

        self.min_context = root_ctx.byte_offset();
        self.max_context = root_ctx.byte_offset();
        self.found_state = stats_ref.byte_offset();

        // Initialise the root context: NumStats = 256 (full
        // alphabet), SummFreq = 257 (each symbol freq=1, plus an
        // implicit escape mass of 1), Stats ref → state array,
        // Suffix = 0 (root has no parent).
        self.write_context_root_init(root_ctx, stats_ref);

        // Initialise the 256 states: symbol = i, freq = 1,
        // successor = 0. Successors get filled in lazily as the
        // model walks the input.
        for i in 0..256u32 {
            let off = stats_ref.byte_offset() + i * STATE_SIZE as u32;
            let buf = self.alloc.arena_mut();
            buf[off as usize + STATE_SYMBOL_OFF] = i as u8;
            buf[off as usize + STATE_FREQ_OFF] = 1;
            write_u16(buf, off as usize + STATE_SUCCESSOR_LOW_OFF, 0);
            write_u16(buf, off as usize + STATE_SUCCESSOR_HIGH_OFF, 0);
        }

        // Seed `BinSumm[i][k]` = `BIN_SCALE - K_INIT_BIN_ESC[k] / (i + 2)`
        // for `i ∈ [0, 128)`, `k ∈ [0, 8)`, replicated across all 8
        // sub-buckets (`m ∈ {0, 8, 16, ..., 56}`).
        for i in 0..128u32 {
            for k in 0..8u32 {
                let val = (PPMD_BIN_SCALE - u32::from(K_INIT_BIN_ESC[k as usize]) / (i + 2)) as u16;
                let mut m = 0u32;
                while m < 64 {
                    self.bin_summ[(i * 64 + k + m) as usize] = val;
                    m += 8;
                }
            }
        }

        // Seed `See[i][k] = (summ: (5*i + 10) << shift, shift: PPMD_PERIOD_BITS - 4 = 3, count: 4)`
        // for `i ∈ [0, 25)`, `k ∈ [0, 16)`.
        for i in 0..25u32 {
            for k in 0..16u32 {
                let shift: u8 = 7 - 4; // PPMD_PERIOD_BITS - 4
                self.see[(i * 16 + k) as usize] = See {
                    summ: ((5 * i + 10) << shift) as u16,
                    shift,
                    count: 4,
                };
            }
        }
    }

    /// Caller-configured max model order.
    #[must_use]
    pub fn max_order(&self) -> u32 {
        self.max_order
    }

    /// Borrow the underlying allocator (read-only). Useful for
    /// integration code that wants to inspect arena usage.
    #[must_use]
    pub fn allocator(&self) -> &Allocator {
        &self.alloc
    }

    // ── Internal byte-level accessors ────────────────────────────

    fn write_context_root_init(&mut self, ctx: Ref, stats: Ref) {
        let off = ctx.byte_offset() as usize;
        let buf = self.alloc.arena_mut();
        write_u16(buf, off + CTX_NUM_STATS_OFF, 256);
        write_u16(buf, off + CTX_SUMM_FREQ_OFF, 256 + 1);
        write_u32(buf, off + CTX_STATS_OFF, stats.byte_offset());
        write_u32(buf, off + CTX_SUFFIX_OFF, 0);
    }

    // ── Typed accessors for State / Context fields ──────────────
    //
    // All ports read & write through the allocator's raw byte view.
    // Refs (the `u32` byte offsets) carry no type info — these
    // helpers are the discipline that keeps the multi-state and
    // 1-state context layouts coherent.

    #[inline]
    fn ctx_num_stats(&self, ctx: u32) -> u16 {
        read_u16(self.alloc.arena(), ctx as usize + CTX_NUM_STATS_OFF)
    }

    #[inline]
    fn ctx_set_num_stats(&mut self, ctx: u32, v: u16) {
        write_u16(self.alloc.arena_mut(), ctx as usize + CTX_NUM_STATS_OFF, v);
    }

    #[inline]
    fn ctx_summ_freq(&self, ctx: u32) -> u16 {
        read_u16(self.alloc.arena(), ctx as usize + CTX_SUMM_FREQ_OFF)
    }

    #[inline]
    fn ctx_set_summ_freq(&mut self, ctx: u32, v: u16) {
        write_u16(self.alloc.arena_mut(), ctx as usize + CTX_SUMM_FREQ_OFF, v);
    }

    #[inline]
    fn ctx_stats_ref(&self, ctx: u32) -> u32 {
        read_u32(self.alloc.arena(), ctx as usize + CTX_STATS_OFF)
    }

    #[inline]
    fn ctx_set_stats_ref(&mut self, ctx: u32, v: u32) {
        write_u32(self.alloc.arena_mut(), ctx as usize + CTX_STATS_OFF, v);
    }

    #[inline]
    fn ctx_suffix(&self, ctx: u32) -> u32 {
        read_u32(self.alloc.arena(), ctx as usize + CTX_SUFFIX_OFF)
    }

    #[inline]
    fn ctx_set_suffix(&mut self, ctx: u32, v: u32) {
        write_u32(self.alloc.arena_mut(), ctx as usize + CTX_SUFFIX_OFF, v);
    }

    /// Byte offset of the inline `State` carried by a 1-state
    /// context. Mirrors `Ppmd7Context_OneState(p)` =
    /// `(CPpmd_State *)&(p)->SummFreq`.
    #[inline]
    fn ctx_one_state_off(ctx: u32) -> u32 {
        ctx + CTX_INLINE_STATE_OFF as u32
    }

    #[inline]
    fn state_symbol(&self, st: u32) -> u8 {
        self.alloc.arena()[st as usize + STATE_SYMBOL_OFF]
    }

    #[inline]
    fn state_set_symbol(&mut self, st: u32, v: u8) {
        self.alloc.arena_mut()[st as usize + STATE_SYMBOL_OFF] = v;
    }

    #[inline]
    fn state_freq(&self, st: u32) -> u8 {
        self.alloc.arena()[st as usize + STATE_FREQ_OFF]
    }

    #[inline]
    fn state_set_freq(&mut self, st: u32, v: u8) {
        self.alloc.arena_mut()[st as usize + STATE_FREQ_OFF] = v;
    }

    #[inline]
    fn state_successor(&self, st: u32) -> u32 {
        read_successor(self.alloc.arena(), st as usize)
    }

    #[inline]
    fn state_set_successor(&mut self, st: u32, v: u32) {
        write_successor(self.alloc.arena_mut(), st as usize, v);
    }

    /// Swap the State at offset `a` with the State at offset `b`.
    /// `state_swap(a, a)` is a no-op.
    fn state_swap(&mut self, a: u32, b: u32) {
        if a == b {
            return;
        }
        let buf = self.alloc.arena_mut();
        let (lo, hi) = if a < b { (a, b) } else { (b, a) };
        let (lo_buf, rest) = buf.split_at_mut(lo as usize + STATE_SIZE);
        let lo_slice = &mut lo_buf[lo as usize..lo as usize + STATE_SIZE];
        let hi_slice = &mut rest[(hi - lo) as usize - STATE_SIZE..(hi - lo) as usize];
        lo_slice.swap_with_slice(hi_slice);
    }

    /// Copy the State at `src` to `dst`. Both must reference
    /// disjoint slots; this is a `memcpy`-style move that does not
    /// touch freelist links.
    fn state_copy(&mut self, src: u32, dst: u32) {
        if src == dst {
            return;
        }
        let buf = self.alloc.arena_mut();
        let src_off = src as usize;
        let dst_off = dst as usize;
        let mut tmp = [0u8; STATE_SIZE];
        tmp.copy_from_slice(&buf[src_off..src_off + STATE_SIZE]);
        buf[dst_off..dst_off + STATE_SIZE].copy_from_slice(&tmp);
    }

    /// `BinSumm[freq - 1][prev_success + NS2BSIndx[suffix.numStats - 1]
    ///                  + HiBitsFlag (set as side effect)
    ///                  + 2 * HB2Flag[oneState.symbol]
    ///                  + ((RunLength >> 26) & 0x20)]`
    ///
    /// Mirrors libarchive's `Ppmd7_GetBinSumm` macro. Returns the
    /// flat `bin_summ` index *and* sets `self.hi_bits_flag` as a
    /// side effect — both are shared with the masked-escape walk
    /// downstream. The returned index spans the table's 128×64 grid.
    fn bin_summ_index(&mut self) -> usize {
        let one_state = Self::ctx_one_state_off(self.min_context);
        let one_freq = self.state_freq(one_state) as usize;
        let one_symbol = self.state_symbol(one_state) as usize;
        let suffix_ctx = self.ctx_suffix(self.min_context);
        let suffix_ns = self.ctx_num_stats(suffix_ctx) as usize;
        let found_symbol = self.state_symbol(self.found_state) as usize;
        // SIDE EFFECT: cache HiBitsFlag for the masked-escape walk.
        self.hi_bits_flag = u32::from(HB2_FLAG[found_symbol]);
        let row = one_freq - 1;
        let col = self.prev_success as usize
            + NS2_BS_INDX[suffix_ns - 1] as usize
            + self.hi_bits_flag as usize
            + 2 * HB2_FLAG[one_symbol] as usize
            + ((self.run_length >> 26) & 0x20) as usize;
        row * 64 + col
    }

    // ── decode_symbol + update path ─────────────────────────────

    /// Decode one byte from the range coder.
    ///
    /// Mirrors libarchive's `Ppmd7_DecodeSymbol`. The model state
    /// (context tree, FoundState, OrderFall, …) is updated as a
    /// side effect via [`Self::update_model`] / its peers.
    ///
    /// # Errors
    ///
    /// - [`DecodeError::Range`] if the range coder runs out of input
    ///   or the underlying [`RangeDecoder`] reports a fault.
    /// - [`DecodeError::EndMarker`] if the masked-escape walk
    ///   reaches the order-0 root with every symbol masked. The
    ///   encoder emits this to mark end-of-stream; the caller
    ///   should stop decoding rather than treat it as a payload byte.
    /// - [`DecodeError::Malformed`] if the range coder produces a
    ///   threshold past the active context's running total. The
    ///   PPMd block's framing has diverged from the encoder's.
    pub fn decode_symbol(&mut self, rc: &mut RangeDecoder<'_>) -> Result<u8, DecodeError> {
        // 256-byte mask (one bit per symbol) tracking which symbols
        // are still candidates after each masked-escape iteration.
        // Initialised in the n-ary or binary path before the
        // masked-walk loop is entered.
        let mut char_mask = [0u8; 256];

        let num_stats = self.ctx_num_stats(self.min_context);

        if num_stats != 1 {
            // ── Multi-state path ────────────────────────────────
            let stats = self.ctx_stats_ref(self.min_context);
            let summ_freq = u32::from(self.ctx_summ_freq(self.min_context));
            let count = rc.get_threshold(summ_freq)?;

            // First state shortcut: if count < first.freq, hit.
            let first_freq = u32::from(self.state_freq(stats));
            if count < first_freq {
                rc.decode(0, first_freq)?;
                self.found_state = stats;
                let symbol = self.state_symbol(stats);
                self.update1_0();
                return Ok(symbol);
            }

            // Walk the remaining states accumulating frequencies.
            self.prev_success = 0;
            let mut hi_cnt = first_freq;
            let mut s = stats + STATE_SIZE as u32;
            for _ in 1..num_stats {
                let f = u32::from(self.state_freq(s));
                hi_cnt += f;
                if hi_cnt > count {
                    rc.decode(hi_cnt - f, f)?;
                    self.found_state = s;
                    let symbol = self.state_symbol(s);
                    self.update1();
                    return Ok(symbol);
                }
                s += STATE_SIZE as u32;
            }

            if count >= summ_freq {
                return Err(DecodeError::Malformed);
            }
            // Escape: range-code the [hi_cnt, summ_freq) sub-interval
            // and mask all the symbols this context already covers.
            self.hi_bits_flag = u32::from(HB2_FLAG[self.state_symbol(self.found_state) as usize]);
            rc.decode(hi_cnt, summ_freq - hi_cnt)?;
            char_mask.fill(0xFF);
            // Last walked state is one past `s` from the loop —
            // back up by one and walk N entries to mask each symbol.
            let last = s - STATE_SIZE as u32;
            char_mask[self.state_symbol(last) as usize] = 0;
            let mut cursor = last;
            for _ in 1..num_stats {
                cursor -= STATE_SIZE as u32;
                char_mask[self.state_symbol(cursor) as usize] = 0;
            }
        } else {
            // ── Binary path ─────────────────────────────────────
            let prob_idx = self.bin_summ_index();
            let prob = u32::from(self.bin_summ[prob_idx]);
            // Pure binary decode against PPMD_BIN_SCALE — works for
            // both the 7z and RAR range-coder variants.
            let value = rc.get_threshold(PPMD_BIN_SCALE)?;
            if value < prob {
                rc.decode(0, prob)?;
                self.bin_summ[prob_idx] = ppmd_update_prob_0(prob) as u16;
                let one_state = Self::ctx_one_state_off(self.min_context);
                self.found_state = one_state;
                let symbol = self.state_symbol(one_state);
                self.update_bin();
                return Ok(symbol);
            }
            rc.decode(prob, PPMD_BIN_SCALE - prob)?;
            self.bin_summ[prob_idx] = ppmd_update_prob_1(prob) as u16;
            self.init_esc = u32::from(K_EXP_ESCAPE[(prob >> 10) as usize]);
            char_mask.fill(0xFF);
            let one_state = Self::ctx_one_state_off(self.min_context);
            char_mask[self.state_symbol(one_state) as usize] = 0;
            self.prev_success = 0;
        }

        // ── Masked-escape walk ─────────────────────────────────
        loop {
            let num_masked = u32::from(self.ctx_num_stats(self.min_context));

            // Walk the suffix chain until we land in a context
            // whose state count exceeds the masked count (i.e.
            // there's at least one un-masked candidate).
            loop {
                self.order_fall += 1;
                let suffix = self.ctx_suffix(self.min_context);
                if suffix == 0 {
                    return Err(DecodeError::EndMarker);
                }
                self.min_context = suffix;
                if u32::from(self.ctx_num_stats(self.min_context)) != num_masked {
                    break;
                }
            }

            // Sum the un-masked frequencies and capture pointers
            // to each surviving candidate state. The stash holds at
            // most one entry per context state, so it must fit the
            // 256-symbol alphabet (the order-0 root case). Mirrors
            // libarchive's `CPpmd_State *ps[256]`.
            let ctx_ns = u32::from(self.ctx_num_stats(self.min_context));
            let stats = self.ctx_stats_ref(self.min_context);
            let mut ps = [0u32; 256];
            let unmasked_count = ctx_ns - num_masked;
            let mut hi_cnt: u32 = 0;
            let mut found = 0usize;
            let mut cursor = stats;
            for _ in 0..ctx_ns {
                let symbol = self.state_symbol(cursor) as usize;
                let mask_bit = char_mask[symbol]; // 0xFF if candidate, 0 if masked
                if mask_bit != 0 {
                    hi_cnt += u32::from(self.state_freq(cursor));
                    ps[found] = cursor;
                    found += 1;
                    if found == unmasked_count as usize {
                        break;
                    }
                }
                cursor += STATE_SIZE as u32;
            }

            let (see_offset, esc_freq) = self.make_esc_freq(num_masked);
            let freq_sum = hi_cnt + esc_freq;
            let count = rc.get_threshold(freq_sum)?;

            if count < hi_cnt {
                // Hit: pick the first state whose accumulated freq
                // exceeds `count`.
                let mut acc: u32 = 0;
                let mut idx = 0usize;
                while idx < found {
                    let f = u32::from(self.state_freq(ps[idx]));
                    if acc + f > count {
                        break;
                    }
                    acc += f;
                    idx += 1;
                }
                let s = ps[idx];
                let f = u32::from(self.state_freq(s));
                rc.decode(acc, f)?;
                self.see_apply_update(see_offset);
                self.found_state = s;
                let symbol = self.state_symbol(s);
                self.update2();
                return Ok(symbol);
            }
            if count >= freq_sum {
                return Err(DecodeError::Malformed);
            }
            // Escape: bump the SEE summ by the full freq_sum and
            // mask every un-masked candidate before the next
            // suffix-chain walk.
            rc.decode(hi_cnt, esc_freq)?;
            self.see_summ_add(see_offset, freq_sum);
            for &state_off in ps.iter().take(found) {
                let symbol = self.state_symbol(state_off) as usize;
                char_mask[symbol] = 0;
            }
        }
    }

    /// Inner heart of `update_model`'s SEE-bucket lookup.
    ///
    /// Returns either an index into [`Self::see`] (for non-root
    /// contexts) or [`SeeOffset::Dummy`] (for the order-0 root,
    /// whose escape is fixed at 1). Side-effect: shrinks the
    /// returned bucket's `summ` by `summ >> shift` (consuming the
    /// "sticky" portion). Mirrors `Ppmd7_MakeEscFreq`.
    fn make_esc_freq(&mut self, num_masked: u32) -> (SeeOffset, u32) {
        let ctx_ns = u32::from(self.ctx_num_stats(self.min_context));
        if ctx_ns == 256 {
            // Order-0 root: escape mass is always 1; the dummy SEE
            // never participates in `Ppmd_See_Update`.
            return (SeeOffset::Dummy, 1);
        }
        let non_masked = ctx_ns - num_masked;
        let suffix_ns = u32::from(self.ctx_num_stats(self.ctx_suffix(self.min_context)));
        let summ_freq = u32::from(self.ctx_summ_freq(self.min_context));
        // Compute the SEE row × column index.
        let row = NS2_INDX[(non_masked - 1) as usize] as u32;
        let col = u32::from(non_masked < suffix_ns - ctx_ns)
            + 2 * u32::from(summ_freq < 11 * ctx_ns)
            + 4 * u32::from(num_masked > non_masked)
            + self.hi_bits_flag;
        let off = (row * 16 + col) as usize;
        let entry = self.see[off];
        let shifted = u32::from(entry.summ) >> entry.shift;
        let new_summ = u32::from(entry.summ).wrapping_sub(shifted);
        self.see[off] = See {
            summ: new_summ as u16,
            shift: entry.shift,
            count: entry.count,
        };
        let scale = if shifted == 0 { 1 } else { shifted };
        (SeeOffset::At(off), scale)
    }

    fn see_apply_update(&mut self, off: SeeOffset) {
        match off {
            SeeOffset::Dummy => self.dummy_see.update(),
            SeeOffset::At(i) => self.see[i].update(),
        }
    }

    fn see_summ_add(&mut self, off: SeeOffset, by: u32) {
        match off {
            SeeOffset::Dummy => {
                self.dummy_see.summ = self.dummy_see.summ.wrapping_add(by as u16);
            }
            SeeOffset::At(i) => {
                let e = &mut self.see[i];
                e.summ = e.summ.wrapping_add(by as u16);
            }
        }
    }

    /// Shortcut path: the FoundState was the *first* state in a
    /// multi-state context. Bumps its frequency and the context's
    /// summFreq; updates `prev_success` and `run_length`.
    fn update1_0(&mut self) {
        let summ = u32::from(self.ctx_summ_freq(self.min_context));
        let f = u32::from(self.state_freq(self.found_state));
        self.prev_success = u32::from(2 * f > summ);
        self.run_length = self.run_length.wrapping_add(self.prev_success as i32);
        self.ctx_set_summ_freq(self.min_context, (summ + 4) as u16);
        let new_f = f + 4;
        self.state_set_freq(self.found_state, new_f as u8);
        if new_f > MAX_FREQ {
            self.rescale();
        }
        self.next_context();
    }

    /// Standard path: the FoundState was a non-first multi-state
    /// hit. Bumps freqs, possibly swaps with the previous state,
    /// and may rescale.
    fn update1(&mut self) {
        let s = self.found_state;
        let new_f = u32::from(self.state_freq(s)) + 4;
        self.state_set_freq(s, new_f as u8);
        let summ = u32::from(self.ctx_summ_freq(self.min_context));
        self.ctx_set_summ_freq(self.min_context, (summ + 4) as u16);
        let prev = s - STATE_SIZE as u32;
        if self.state_freq(s) > self.state_freq(prev) {
            self.state_swap(s, prev);
            self.found_state = prev;
            if u32::from(self.state_freq(prev)) > MAX_FREQ {
                self.rescale();
            }
        }
        self.next_context();
    }

    /// Binary-context hit path: bumps the inline state's freq
    /// (saturating below 128), sets `prev_success = 1`, and
    /// transitions.
    fn update_bin(&mut self) {
        let f = self.state_freq(self.found_state);
        if f < 128 {
            self.state_set_freq(self.found_state, f + 1);
        }
        self.prev_success = 1;
        self.run_length = self.run_length.wrapping_add(1);
        self.next_context();
    }

    /// Masked-escape hit path: bumps the FoundState's freq,
    /// resets RunLength, and unconditionally calls UpdateModel
    /// (the order-fall has crossed at least one suffix link).
    fn update2(&mut self) {
        let f = u32::from(self.state_freq(self.found_state)) + 4;
        self.state_set_freq(self.found_state, f as u8);
        let summ = u32::from(self.ctx_summ_freq(self.min_context));
        self.ctx_set_summ_freq(self.min_context, (summ + 4) as u16);
        if f > MAX_FREQ {
            self.rescale();
        }
        self.run_length = self.init_rl;
        self.update_model();
    }

    /// Fast transition: if `OrderFall == 0` and the FoundState's
    /// successor points into the unit region (a real child context,
    /// not an unpromoted text-region byte), commit `MinContext = MaxContext = successor`.
    /// Otherwise fall through to `UpdateModel`.
    fn next_context(&mut self) {
        let succ = self.state_successor(self.found_state);
        if self.order_fall == 0 && succ > self.alloc.text() {
            self.min_context = succ;
            self.max_context = succ;
        } else {
            self.update_model();
        }
    }

    /// Halve every frequency in the active multi-state context's
    /// state array, re-sort by frequency (move the just-decoded
    /// state to the front), and possibly shrink the context to a
    /// 1-state if every other state's frequency hit zero. Mirrors
    /// `Rescale`.
    fn rescale(&mut self) {
        let stats = self.ctx_stats_ref(self.min_context);
        let mut s_off = self.found_state;

        // Step 1: rotate FoundState to the front of the array.
        // The C code stashes FoundState in tmp, shifts everything
        // between stats..s back by one, and writes tmp at stats.
        if s_off != stats {
            let mut tmp = [0u8; STATE_SIZE];
            tmp.copy_from_slice(&self.alloc.arena()[s_off as usize..s_off as usize + STATE_SIZE]);
            let mut cur = s_off;
            while cur != stats {
                let prev = cur - STATE_SIZE as u32;
                self.state_copy(prev, cur);
                cur = prev;
            }
            self.alloc.arena_mut()[stats as usize..stats as usize + STATE_SIZE]
                .copy_from_slice(&tmp);
            s_off = stats;
        }

        // Step 2: halve frequencies.
        let summ_freq = u32::from(self.ctx_summ_freq(self.min_context));
        let mut esc_freq = summ_freq - u32::from(self.state_freq(s_off));
        let f0 = u32::from(self.state_freq(s_off)) + 4;
        self.state_set_freq(s_off, f0 as u8);
        let adder: u32 = u32::from(self.order_fall != 0);
        let new_first = (u32::from(self.state_freq(s_off)) + adder) >> 1;
        self.state_set_freq(s_off, new_first as u8);
        let mut sum_freq: u32 = new_first;
        let num_stats = u32::from(self.ctx_num_stats(self.min_context));

        // Step 3: walk the rest of the states, halving each freq
        // and bubble-sorting the runs into descending-freq order.
        let mut cur = s_off + STATE_SIZE as u32;
        for _ in 1..num_stats {
            let f = u32::from(self.state_freq(cur));
            esc_freq -= f;
            let new_f = (f + adder) >> 1;
            self.state_set_freq(cur, new_f as u8);
            sum_freq += new_f;
            // If the new freq exceeds the previous state's, bubble
            // up by inserting `cur`'s entry at the right rank.
            let prev = cur - STATE_SIZE as u32;
            if self.state_freq(cur) > self.state_freq(prev) {
                let mut tmp = [0u8; STATE_SIZE];
                tmp.copy_from_slice(&self.alloc.arena()[cur as usize..cur as usize + STATE_SIZE]);
                let mut s1 = cur;
                loop {
                    let p = s1 - STATE_SIZE as u32;
                    self.state_copy(p, s1);
                    s1 = p;
                    if s1 == stats || tmp[STATE_FREQ_OFF] <= self.state_freq(s1 - STATE_SIZE as u32)
                    {
                        break;
                    }
                }
                self.alloc.arena_mut()[s1 as usize..s1 as usize + STATE_SIZE].copy_from_slice(&tmp);
            }
            cur += STATE_SIZE as u32;
        }

        // Step 4: handle states whose freq dropped to zero.
        let last_off = stats + (num_stats - 1) * STATE_SIZE as u32;
        if self.state_freq(last_off) == 0 {
            // Walk back from `last_off` while freq == 0.
            let mut zero_count: u32 = 0;
            let mut cur = last_off;
            while self.state_freq(cur) == 0 {
                zero_count += 1;
                if cur == stats {
                    break;
                }
                cur -= STATE_SIZE as u32;
            }
            esc_freq += zero_count;
            let new_ns = num_stats - zero_count;
            self.ctx_set_num_stats(self.min_context, new_ns as u16);
            if new_ns == 1 {
                // Collapse to a 1-state context: copy stats[0]'s
                // payload into the inline slot, free the state
                // array, and exit.
                let mut tmp = [0u8; STATE_SIZE];
                tmp.copy_from_slice(
                    &self.alloc.arena()[stats as usize..stats as usize + STATE_SIZE],
                );
                // Halve `tmp.freq` until escFreq <= 1, mirroring
                // the C reference.
                let mut tmp_freq = tmp[STATE_FREQ_OFF] as u32;
                let mut esc = esc_freq;
                loop {
                    tmp_freq -= tmp_freq >> 1;
                    esc >>= 1;
                    if esc <= 1 {
                        break;
                    }
                }
                tmp[STATE_FREQ_OFF] = tmp_freq as u8;
                // Free the (now-orphaned) state array.
                let old_indx = Self::units_indx_for_states(num_stats);
                // INVARIANT: every prior call carved this exact
                // slot out of the freelist or the central gap, so
                // the inverse free is well-typed.
                let r = Ref::new(stats).expect("INVARIANT: stats is non-zero");
                self.alloc.free_units(r, old_indx);
                let one_state = Self::ctx_one_state_off(self.min_context);
                self.alloc.arena_mut()[one_state as usize..one_state as usize + STATE_SIZE]
                    .copy_from_slice(&tmp);
                self.found_state = one_state;
                return;
            }
            // Otherwise: shrink the state array to fit the new
            // count if the size class changed.
            let n0 = Self::units_indx_for_states(num_stats);
            let n1 = Self::units_indx_for_states(new_ns);
            if n0 != n1 {
                let r = Ref::new(stats).expect("INVARIANT: stats non-zero");
                let new_r = self.alloc.shrink_units(r, n0, n1);
                self.ctx_set_stats_ref(self.min_context, new_r.byte_offset());
            }
        }
        let new_summ = sum_freq + esc_freq - (esc_freq >> 1);
        self.ctx_set_summ_freq(self.min_context, new_summ as u16);
        self.found_state = self.ctx_stats_ref(self.min_context);
    }

    /// Translate a state count (`num_stats`) to the freelist size
    /// class that holds the matching state-array allocation. Each
    /// state is `STATE_SIZE = 6` bytes, so two states pack into one
    /// 12-byte unit; the array spans `(num_stats + 1) >> 1` units.
    fn units_indx_for_states(num_stats: u32) -> u32 {
        let units = (num_stats + 1) >> 1;
        // INVARIANT: 1 ≤ units ≤ 128; fits the freelist's 128-unit
        // upper bound without saturation.
        u32::from(UNITS_TO_INDX[units as usize - 1])
    }

    /// Walk every context from `MaxContext` back through `MinContext`
    /// promoting the just-decoded symbol up the suffix chain. The
    /// workhorse of the PPMd update step.
    fn update_model(&mut self) {
        // Stash the FoundState's successor before we mutate.
        let mut f_successor = self.state_successor(self.found_state);
        let mut successor: u32;

        // ── Pass 1: update the immediate suffix's freq for the
        // just-decoded symbol (without growing the model). Mirrors
        // the C code's leading `if (FoundState->Freq < MAX_FREQ/4 ...)` block.
        let found_freq = u32::from(self.state_freq(self.found_state));
        let min_suffix = self.ctx_suffix(self.min_context);
        if found_freq < MAX_FREQ / 4 && min_suffix != 0 {
            let suffix_ns = u32::from(self.ctx_num_stats(min_suffix));
            if suffix_ns == 1 {
                let one = Self::ctx_one_state_off(min_suffix);
                let f = self.state_freq(one);
                if f < 32 {
                    self.state_set_freq(one, f + 1);
                }
            } else {
                let stats = self.ctx_stats_ref(min_suffix);
                let target_symbol = self.state_symbol(self.found_state);
                // Linear search for the matching state.
                let mut s = stats;
                loop {
                    if self.state_symbol(s) == target_symbol {
                        break;
                    }
                    s += STATE_SIZE as u32;
                }
                if s != stats {
                    let prev = s - STATE_SIZE as u32;
                    if self.state_freq(s) >= self.state_freq(prev) {
                        self.state_swap(s, prev);
                        s = prev;
                    }
                }
                let f = u32::from(self.state_freq(s));
                if f < MAX_FREQ - 9 {
                    self.state_set_freq(s, (f + 2) as u8);
                    let summ = u32::from(self.ctx_summ_freq(min_suffix));
                    self.ctx_set_summ_freq(min_suffix, (summ + 2) as u16);
                }
            }
        }

        // ── Order-fall == 0: shortcut. Promote MinContext to a
        // freshly-built deeper-order context via CreateSuccessors.
        if self.order_fall == 0 {
            match self.create_successors(true) {
                None => {
                    self.restart();
                    return;
                }
                Some(c) => {
                    self.min_context = c;
                    self.max_context = c;
                    self.state_set_successor(self.found_state, c);
                }
            }
            return;
        }

        // ── Otherwise: log the just-emitted symbol in the text
        // region. The new "successor" is the position right after
        // the byte we just wrote.
        let symbol = self.state_symbol(self.found_state);
        self.alloc.write_text_byte(symbol);
        successor = self.alloc.text();
        if self.alloc.text() >= self.alloc.units_start() {
            self.restart();
            return;
        }

        if f_successor != 0 {
            if f_successor <= successor {
                // FoundState's successor still points into the text
                // region — promote it to a real context first.
                match self.create_successors(false) {
                    None => {
                        self.restart();
                        return;
                    }
                    Some(c) => {
                        f_successor = c;
                    }
                }
            }
            self.order_fall -= 1;
            if self.order_fall == 0 {
                successor = f_successor;
                if self.max_context != self.min_context {
                    self.alloc.dec_text();
                }
            }
        } else {
            self.state_set_successor(self.found_state, successor);
            f_successor = self.min_context;
        }

        // ── Pass 2: walk MaxContext back through MinContext,
        // adding the new symbol as a state to each context whose
        // state array doesn't yet have it. `MinContext` is invariant
        // through this pass — its NumStats is captured up front as
        // `ns_min` and read inside the loop without re-fetching.
        let ns_min = u32::from(self.ctx_num_stats(self.min_context));
        let s0 = u32::from(self.ctx_summ_freq(self.min_context))
            - ns_min
            - (u32::from(self.state_freq(self.found_state)) - 1);

        let mut c = self.max_context;
        while c != self.min_context {
            let ns1 = u32::from(self.ctx_num_stats(c));
            if ns1 != 1 {
                if (ns1 & 1) == 0 {
                    // Even count: maybe expand to next bin.
                    let old_nu = ns1 >> 1;
                    let i = u32::from(UNITS_TO_INDX[(old_nu - 1) as usize]);
                    let i_next = u32::from(UNITS_TO_INDX[old_nu as usize]);
                    if i != i_next {
                        // Allocate a larger block, copy, and free
                        // the old one.
                        match self.alloc.alloc_units(i + 1) {
                            None => {
                                self.restart();
                                return;
                            }
                            Some(new_ref) => {
                                let old_stats = self.ctx_stats_ref(c);
                                let new_off = new_ref.byte_offset();
                                // Copy old_nu * 12 bytes (the live
                                // half of the new block holds the
                                // existing states).
                                let bytes = (old_nu as usize) * UNIT_SIZE;
                                let buf = self.alloc.arena_mut();
                                buf.copy_within(
                                    old_stats as usize..old_stats as usize + bytes,
                                    new_off as usize,
                                );
                                let r = Ref::new(old_stats).expect("INVARIANT: stats non-zero");
                                self.alloc.free_units(r, i);
                                self.ctx_set_stats_ref(c, new_off);
                            }
                        }
                    }
                }
                let summ = u32::from(self.ctx_summ_freq(c));
                let bump = u32::from(2 * ns1 < ns_min)
                    + 2 * u32::from((4 * ns1 <= ns_min) && (summ <= 8 * ns1));
                self.ctx_set_summ_freq(c, (summ + bump) as u16);
            } else {
                // 1-state context: promote to a multi-state by
                // allocating a 1-unit (= 2-state) block, copying
                // the inline state to it, and bumping num_stats.
                match self.alloc.alloc_units(0) {
                    None => {
                        self.restart();
                        return;
                    }
                    Some(new_ref) => {
                        let old_one = Self::ctx_one_state_off(c);
                        let new_off = new_ref.byte_offset();
                        let mut tmp = [0u8; STATE_SIZE];
                        tmp.copy_from_slice(
                            &self.alloc.arena()[old_one as usize..old_one as usize + STATE_SIZE],
                        );
                        self.alloc.arena_mut()[new_off as usize..new_off as usize + STATE_SIZE]
                            .copy_from_slice(&tmp);
                        self.ctx_set_stats_ref(c, new_off);
                        let f = tmp[STATE_FREQ_OFF] as u32;
                        let new_freq = if f < MAX_FREQ / 4 - 1 {
                            f * 2
                        } else {
                            MAX_FREQ - 4
                        };
                        self.alloc.arena_mut()[new_off as usize + STATE_FREQ_OFF] = new_freq as u8;
                        // ns > 3 ? +1 : +0, plus init_esc, plus
                        // the new freq. Mirrors the C reference's
                        // `c->SummFreq = s->Freq + p->InitEsc + (ns > 3)`.
                        let extra = u32::from(ns_min > 3);
                        let new_summ = new_freq + self.init_esc + extra;
                        self.ctx_set_summ_freq(c, new_summ as u16);
                    }
                }
            }

            // Compute the new state's freq via the libarchive
            // formula, append it to `c`'s state array, and bump
            // num_stats.
            let summ = u32::from(self.ctx_summ_freq(c));
            let cf_raw = 2 * found_freq * (summ + 6);
            let sf = s0 + summ;
            let (cf, summ_inc) = if cf_raw < 6 * sf {
                let v = 1 + u32::from(cf_raw > sf) + u32::from(cf_raw >= 4 * sf);
                (v, 3)
            } else {
                let v = 4
                    + u32::from(cf_raw >= 9 * sf)
                    + u32::from(cf_raw >= 12 * sf)
                    + u32::from(cf_raw >= 15 * sf);
                (v, v)
            };
            self.ctx_set_summ_freq(c, (summ + summ_inc) as u16);
            let stats = self.ctx_stats_ref(c);
            let new_state_off = stats + ns1 * STATE_SIZE as u32;
            self.state_set_symbol(new_state_off, symbol);
            self.state_set_freq(new_state_off, cf as u8);
            self.state_set_successor(new_state_off, successor);
            self.ctx_set_num_stats(c, (ns1 + 1) as u16);

            c = self.ctx_suffix(c);
        }

        self.min_context = f_successor;
        self.max_context = f_successor;
    }

    /// Build (or reuse) child contexts so that `MinContext` ends up
    /// pointing at a deeper-order context. Returns `None` only when
    /// the arena is exhausted.
    ///
    /// The walk: starting at `MinContext`, follow the suffix chain.
    /// For each context whose matching state still points into the
    /// text region (matching the FoundState's pre-update successor),
    /// stash a pointer to that state. When we either run out of
    /// suffixes or hit a state whose successor *already* points at
    /// a real context, switch direction and chain new 1-state
    /// child contexts from each stashed pointer up to MinContext.
    fn create_successors(&mut self, skip: bool) -> Option<u32> {
        let mut c = self.min_context;
        let up_branch = self.state_successor(self.found_state);
        let target_symbol = self.state_symbol(self.found_state);

        // Stack of stashed states. PPMD7_MAX_ORDER = 64 is the
        // libarchive cap; our MAX_ORDER matches.
        let mut ps = [0u32; MAX_ORDER as usize];
        let mut num_ps = 0usize;
        if !skip {
            ps[num_ps] = self.found_state;
            num_ps += 1;
        }

        while self.ctx_suffix(c) != 0 {
            c = self.ctx_suffix(c);
            let s = if self.ctx_num_stats(c) != 1 {
                let stats = self.ctx_stats_ref(c);
                let mut cur = stats;
                while self.state_symbol(cur) != target_symbol {
                    cur += STATE_SIZE as u32;
                }
                cur
            } else {
                Self::ctx_one_state_off(c)
            };
            let succ = self.state_successor(s);
            if succ != up_branch {
                c = succ;
                if num_ps == 0 {
                    return Some(c);
                }
                break;
            }
            ps[num_ps] = s;
            num_ps += 1;
        }

        // Compute the upState that every newly-created child will
        // inherit.
        let up_state_symbol = self.alloc.read_byte(up_branch);
        let up_state_successor = up_branch + 1;
        let up_state_freq = if self.ctx_num_stats(c) == 1 {
            self.state_freq(Self::ctx_one_state_off(c))
        } else {
            // Search the multi-state context for the up_state_symbol.
            let stats = self.ctx_stats_ref(c);
            let mut cur = stats;
            while self.state_symbol(cur) != up_state_symbol {
                cur += STATE_SIZE as u32;
            }
            let cf = u32::from(self.state_freq(cur)) - 1;
            let s0 = u32::from(self.ctx_summ_freq(c)) - u32::from(self.ctx_num_stats(c)) - cf;
            let f = if 2 * cf <= s0 {
                u32::from(5 * cf > s0)
            } else {
                (2 * cf + 3 * s0 - 1) / (2 * s0)
            };
            (1 + f) as u8
        };

        // Build the chain of child contexts from outermost
        // stashed state down to MinContext.
        while num_ps != 0 {
            let c1 = self.alloc.alloc_context()?;
            let c1_off = c1.byte_offset();
            self.ctx_set_num_stats(c1_off, 1);
            let one = Self::ctx_one_state_off(c1_off);
            self.state_set_symbol(one, up_state_symbol);
            self.state_set_freq(one, up_state_freq);
            self.state_set_successor(one, up_state_successor);
            self.ctx_set_suffix(c1_off, c);
            num_ps -= 1;
            self.state_set_successor(ps[num_ps], c1_off);
            c = c1_off;
        }
        Some(c)
    }
}

/// Either an offset into [`Model::see`] or the order-0 root's
/// [`Model::dummy_see`] sentinel. Returned by
/// [`Model::make_esc_freq`] so the caller can apply the matching
/// update.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum SeeOffset {
    /// Index into the flat 25 × 16 SEE table.
    At(usize),
    /// The order-0 dummy SEE entry.
    Dummy,
}

/// PPMd binary-context probability adaptation: 0-bit branch.
/// Mirrors `PPMD_UPDATE_PROB_0(prob)`.
#[inline]
fn ppmd_update_prob_0(prob: u32) -> u32 {
    prob + (1 << 7) - ppmd_get_mean(prob)
}

/// PPMd binary-context probability adaptation: 1-bit branch.
/// Mirrors `PPMD_UPDATE_PROB_1(prob)`.
#[inline]
fn ppmd_update_prob_1(prob: u32) -> u32 {
    prob - ppmd_get_mean(prob)
}

/// `PPMD_GET_MEAN(prob)` per `archive_ppmd_private.h`:
/// `(prob + (1 << 5)) >> 7`.
#[inline]
fn ppmd_get_mean(prob: u32) -> u32 {
    (prob + (1 << 5)) >> 7
}

// ─────────────────────────────────────────────────────────────────
// Test-only sister encoder.
// ─────────────────────────────────────────────────────────────────
//
// Mirrors libarchive's `Ppmd7_EncodeSymbol` structurally. Uses the
// existing 7z [`RangeEncoder`] from `range_dec.rs` (also `cfg(test)`)
// to drive a model in lockstep with the decoder, so arbitrary byte
// streams can round-trip end-to-end. Round-one targets correctness
// over performance — this code path never ships.
//
// The encoder reuses Model's update functions because the model
// state must stay in lockstep with the decoder. Public surface
// stops at `Model::encode_symbol`; the rest of the encode-side
// helpers live in this section.

#[cfg(test)]
impl Model {
    /// Encode one byte to the range encoder. Updates the model
    /// state identically to [`Self::decode_symbol`].
    pub(crate) fn encode_symbol(&mut self, rc: &mut super::range_dec::RangeEncoder, symbol: u8) {
        let mut char_mask = [0u8; 256];

        let num_stats = self.ctx_num_stats(self.min_context);
        if num_stats != 1 {
            // ── Multi-state path ────────────────────────────────
            let stats = self.ctx_stats_ref(self.min_context);
            let summ_freq = u32::from(self.ctx_summ_freq(self.min_context));
            let first_symbol = self.state_symbol(stats);
            let first_freq = u32::from(self.state_freq(stats));
            if first_symbol == symbol {
                rc.encode(0, first_freq, summ_freq);
                self.found_state = stats;
                self.update1_0();
                return;
            }
            self.prev_success = 0;
            let mut sum = first_freq;
            let mut s = stats + STATE_SIZE as u32;
            for _ in 1..num_stats {
                let s_symbol = self.state_symbol(s);
                let s_freq = u32::from(self.state_freq(s));
                if s_symbol == symbol {
                    rc.encode(sum, s_freq, summ_freq);
                    self.found_state = s;
                    self.update1();
                    return;
                }
                sum += s_freq;
                s += STATE_SIZE as u32;
            }
            // No match — escape this context.
            self.hi_bits_flag = u32::from(HB2_FLAG[self.state_symbol(self.found_state) as usize]);
            char_mask.fill(0xFF);
            // Mask all `num_stats` symbols. After the loop, `s`
            // points one past the last walked state.
            let last = s - STATE_SIZE as u32;
            char_mask[self.state_symbol(last) as usize] = 0;
            let mut cursor = last;
            for _ in 1..num_stats {
                cursor -= STATE_SIZE as u32;
                char_mask[self.state_symbol(cursor) as usize] = 0;
            }
            rc.encode(sum, summ_freq - sum, summ_freq);
        } else {
            // ── Binary path ─────────────────────────────────────
            let prob_idx = self.bin_summ_index();
            let prob = u32::from(self.bin_summ[prob_idx]);
            let one_state = Self::ctx_one_state_off(self.min_context);
            if self.state_symbol(one_state) == symbol {
                // bit 0
                rc.encode(0, prob, PPMD_BIN_SCALE);
                self.bin_summ[prob_idx] = ppmd_update_prob_0(prob) as u16;
                self.found_state = one_state;
                self.update_bin();
                return;
            }
            // bit 1
            rc.encode(prob, PPMD_BIN_SCALE - prob, PPMD_BIN_SCALE);
            self.bin_summ[prob_idx] = ppmd_update_prob_1(prob) as u16;
            self.init_esc = u32::from(K_EXP_ESCAPE[(prob >> 10) as usize]);
            char_mask.fill(0xFF);
            char_mask[self.state_symbol(one_state) as usize] = 0;
            self.prev_success = 0;
        }

        // ── Masked-escape walk ─────────────────────────────────
        loop {
            let num_masked = u32::from(self.ctx_num_stats(self.min_context));
            // Walk suffix chain until a context with new candidates.
            loop {
                self.order_fall += 1;
                let suffix = self.ctx_suffix(self.min_context);
                if suffix == 0 {
                    // The encoder reached the end-marker. The
                    // libarchive encoder simply returns; the
                    // decoder side surfaces DecodeError::EndMarker.
                    // For round-trip tests we never feed symbols
                    // that are unmodelled in the order-0 root, so
                    // this branch is unreachable in practice — but
                    // still typed-safe.
                    return;
                }
                self.min_context = suffix;
                if u32::from(self.ctx_num_stats(self.min_context)) != num_masked {
                    break;
                }
            }

            let (see_offset, esc_freq) = self.make_esc_freq(num_masked);
            let stats = self.ctx_stats_ref(self.min_context);
            let ctx_ns = u32::from(self.ctx_num_stats(self.min_context));
            let mut sum: u32 = 0;
            let mut cursor = stats;
            let mut remaining = ctx_ns;
            loop {
                let cur_symbol = self.state_symbol(cursor);
                if cur_symbol == symbol {
                    // Match. Walk `cursor` and the `remaining`
                    // states after it, summing un-masked freqs into
                    // `sum` (which already holds the prefix sum).
                    // Mirrors libarchive's inner `do { sum +=
                    // s->Freq & MASK(s->Symbol); s++; } while(--i);`.
                    let low = sum;
                    let s1 = cursor;
                    let mut walk = cursor;
                    let mut walk_count = remaining;
                    loop {
                        let mask = char_mask[self.state_symbol(walk) as usize];
                        if mask != 0 {
                            sum += u32::from(self.state_freq(walk));
                        }
                        walk += STATE_SIZE as u32;
                        walk_count -= 1;
                        if walk_count == 0 {
                            break;
                        }
                    }
                    let s1_freq = u32::from(self.state_freq(s1));
                    rc.encode(low, s1_freq, sum + esc_freq);
                    self.see_apply_update(see_offset);
                    self.found_state = s1;
                    self.update2();
                    return;
                }
                let mask = char_mask[cur_symbol as usize];
                if mask != 0 {
                    sum += u32::from(self.state_freq(cursor));
                }
                char_mask[cur_symbol as usize] = 0;
                cursor += STATE_SIZE as u32;
                remaining -= 1;
                if remaining == 0 {
                    break;
                }
            }
            // No state in this context's un-masked candidates
            // matched — emit an escape, mark every un-masked
            // candidate as masked for the next iteration's walk,
            // and try the next-shallower context.
            rc.encode(sum, esc_freq, sum + esc_freq);
            self.see_summ_add(see_offset, sum + esc_freq);
        }
    }
}

#[cfg(test)]
mod round_trip_tests {
    use super::*;
    use crate::decode::ppmd2::range_dec::{RangeDecoder, RangeEncoder};

    fn round_trip(input: &[u8], order: u32, arena_bytes: usize) {
        let mut enc_model = Model::new(arena_bytes, order).expect("encoder model");
        let mut enc = RangeEncoder::new();
        for &b in input {
            enc_model.encode_symbol(&mut enc, b);
        }
        let bytes = enc.finish();

        let mut dec_model = Model::new(arena_bytes, order).expect("decoder model");
        let mut dec = RangeDecoder::new(&bytes).expect("range decoder init");
        let mut got = Vec::with_capacity(input.len());
        for _ in 0..input.len() {
            let b = dec_model
                .decode_symbol(&mut dec)
                .unwrap_or_else(|e| panic!("decode at index {}: {e}", got.len()));
            got.push(b);
        }
        assert_eq!(got, input, "round-trip with order={order}");
    }

    #[test]
    fn round_trip_single_byte_through_order_zero() {
        // The simplest possible stream: one byte. Forces the
        // multi-state path against the order-0 root context, the
        // first state's `freq=1` shortcut, and update1_0.
        round_trip(b"A", 4, 16 * 1024);
    }

    #[test]
    fn round_trip_repeated_byte_drives_binary_path() {
        // Repeated bytes after the first cycle through 1-state
        // contexts; the binary fast path with adaptive prob.
        let input: Vec<u8> = std::iter::repeat_n(b'X', 128).collect();
        round_trip(&input, 4, 16 * 1024);
    }

    #[test]
    fn round_trip_alternating_bytes_exercises_swap() {
        // Two-symbol alphabet keeps states swapping into the front
        // position via update1 / update1_0 and exercises rescale
        // (since freqs grow to MAX_FREQ on long inputs).
        let input: Vec<u8> = (0..400)
            .map(|i| if i % 2 == 0 { b'A' } else { b'B' })
            .collect();
        round_trip(&input, 4, 16 * 1024);
    }

    #[test]
    fn round_trip_short_ascii() {
        let input = b"the quick brown fox jumps over the lazy dog";
        round_trip(input, 4, 16 * 1024);
    }

    #[test]
    fn round_trip_short_ascii_higher_order() {
        let input = b"the quick brown fox jumps over the lazy dog. ".repeat(8);
        round_trip(&input, 8, 32 * 1024);
    }

    #[test]
    fn round_trip_pseudorandom_1k() {
        // LCG-driven byte stream, 1 KiB. Varies enough to walk a
        // reasonable cross-section of the order-N tree.
        let mut x: u32 = 0x12345678;
        let input: Vec<u8> = (0..1024)
            .map(|_| {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                (x >> 16) as u8
            })
            .collect();
        round_trip(&input, 4, 64 * 1024);
    }

    #[test]
    fn round_trip_high_entropy_min_arena_min_order() {
        // Stresses the model on the smallest arena it accepts and
        // the smallest order. The MIN_MEM_SIZE guard must hold.
        let mut x: u32 = 0xCAFEBABE;
        let input: Vec<u8> = (0..256)
            .map(|_| {
                x = x.wrapping_mul(1103515245).wrapping_add(12345);
                (x >> 8) as u8
            })
            .collect();
        round_trip(&input, MIN_ORDER, MIN_MEM_SIZE);
    }

    #[test]
    fn round_trip_zeros_only() {
        // All-zero stream exercises the longest possible
        // single-state-context chains.
        let input = vec![0u8; 256];
        round_trip(&input, 4, 16 * 1024);
    }

    #[test]
    fn round_trip_full_alphabet_each_byte_once() {
        // Each of the 256 symbols once — every escape walks the
        // full alphabet at the order-0 root. Stresses the masked-
        // escape walk's fall-through path heavily.
        let input: Vec<u8> = (0..=255u8).collect();
        round_trip(&input, 4, 16 * 1024);
    }
}

#[cfg(test)]
mod edge_case_tests {
    //! §B2c — edge-case stress.
    //!
    //! Round-trips at every supported model order, repeated-session
    //! tests verifying [`Model::restart`] is clean across uses, the
    //! "small arena, big input" path where the model restarts
    //! internally mid-stream, and decoder-only paths that surface
    //! [`DecodeError`] variants without panicking.

    use super::*;
    use crate::decode::ppmd2::range_dec::{RangeDecoder, RangeEncoder};

    fn round_trip(input: &[u8], order: u32, arena_bytes: usize) {
        let mut enc_model = Model::new(arena_bytes, order).expect("encoder model");
        let mut enc = RangeEncoder::new();
        for &b in input {
            enc_model.encode_symbol(&mut enc, b);
        }
        let bytes = enc.finish();
        let mut dec_model = Model::new(arena_bytes, order).expect("decoder model");
        let mut dec = RangeDecoder::new(&bytes).expect("range decoder init");
        let mut got = Vec::with_capacity(input.len());
        for _ in 0..input.len() {
            let b = dec_model.decode_symbol(&mut dec).expect("decode");
            got.push(b);
        }
        assert_eq!(got, input);
    }

    /// Pseudorandom byte stream of `len` bytes, seeded from `seed`.
    /// Used by the order-grid and exhaustion tests. The LCG is the
    /// Numerical Recipes constants — sufficient for spreading bytes
    /// across the alphabet without committing the test to a real
    /// PRNG dependency.
    fn lcg_stream(len: usize, seed: u32) -> Vec<u8> {
        let mut x = seed;
        (0..len)
            .map(|_| {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                (x >> 16) as u8
            })
            .collect()
    }

    #[test]
    fn round_trip_works_at_every_supported_order() {
        // Same input, varying orders. Each combination drives
        // create_successors to a different depth before the model
        // levels off. 32 KiB arena keeps every order from hitting
        // the internal restart branch.
        let input = lcg_stream(512, 0xDEADBEEF);
        for &order in &[MIN_ORDER, 3, 4, 8, 16, 32, MAX_ORDER] {
            round_trip(&input, order, 32 * 1024);
        }
    }

    #[test]
    fn round_trip_with_two_sessions_separated_by_restart() {
        // Two independent payloads through a single Model instance,
        // with `restart()` between them. Verifies the model fully
        // wipes its state between blocks — legacy RAR's solid mode
        // does NOT call this, but `m=4` / `m=5` non-solid blocks do.
        let payload_a = b"first session payload";
        let payload_b = b"second session, different data";
        let order = 4;
        let arena = 16 * 1024;

        let mut enc_a = RangeEncoder::new();
        let mut m_enc = Model::new(arena, order).expect("enc");
        for &b in payload_a {
            m_enc.encode_symbol(&mut enc_a, b);
        }
        let bytes_a = enc_a.finish();

        m_enc.restart();
        let mut enc_b = RangeEncoder::new();
        for &b in payload_b {
            m_enc.encode_symbol(&mut enc_b, b);
        }
        let bytes_b = enc_b.finish();

        let mut m_dec = Model::new(arena, order).expect("dec");
        let mut rc_a = RangeDecoder::new(&bytes_a).expect("init A");
        let got_a: Vec<u8> = (0..payload_a.len())
            .map(|_| m_dec.decode_symbol(&mut rc_a).expect("decode A"))
            .collect();
        assert_eq!(got_a, payload_a);

        m_dec.restart();
        let mut rc_b = RangeDecoder::new(&bytes_b).expect("init B");
        let got_b: Vec<u8> = (0..payload_b.len())
            .map(|_| m_dec.decode_symbol(&mut rc_b).expect("decode B"))
            .collect();
        assert_eq!(got_b, payload_b);
    }

    #[test]
    fn round_trip_long_stream_does_not_run_out_of_arena() {
        // 32 KiB pseudorandom payload through a 256 KiB arena.
        // Comfortably exceeds the initial 7/8-of-arena unit region
        // so the freelists, glue-driven coalescing, and shrink_units
        // all fire in production. Worth running in --release too
        // to catch any release-mode-only arithmetic surprises (CI
        // does this via the `cargo test --release` lane).
        let input = lcg_stream(32 * 1024, 0x12345678);
        round_trip(&input, 8, 256 * 1024);
    }

    #[test]
    fn round_trip_with_internal_restart_on_small_arena() {
        // 16 KiB pseudorandom stream through the canonical 2 KiB
        // arena. The model will hit the "text catches up to
        // UnitsStart" path repeatedly and call `restart()`
        // internally; encoder and decoder must do so in lockstep
        // for the round-trip to remain byte-identical.
        let input = lcg_stream(16 * 1024, 0xCAFEBABE);
        round_trip(&input, 4, MIN_MEM_SIZE);
    }

    #[test]
    fn round_trip_repeating_256_byte_pattern() {
        // A 4 KiB stream of the pattern (0, 1, 2, ..., 255) repeated.
        // Cycles the model through every possible order-1 transition
        // and stress-tests the masked-escape walk on near-miss bytes.
        let pattern: Vec<u8> = (0..=255u8).collect();
        let input: Vec<u8> = pattern.iter().cycle().take(4 * 1024).copied().collect();
        round_trip(&input, 4, 32 * 1024);
    }

    #[test]
    fn round_trip_max_order_with_compressible_input() {
        // MAX_ORDER (= 64) on highly redundant input. The first
        // ~64 bytes establish the order-64 chain; subsequent
        // repetitions exercise the deep-context fast path.
        let unit = b"AAAAAAAA";
        let input: Vec<u8> = unit.iter().cycle().take(2048).copied().collect();
        round_trip(&input, MAX_ORDER, 64 * 1024);
    }

    #[test]
    fn decoder_surfaces_truncated_input_as_range_error() {
        // Encode a payload, then truncate the wire bytes to less
        // than the 5-byte range-coder init prefix. The decoder
        // must surface a typed Range error rather than panic.
        let mut enc = RangeEncoder::new();
        let mut m_enc = Model::new(MIN_MEM_SIZE, 4).expect("enc");
        for &b in b"hello" {
            m_enc.encode_symbol(&mut enc, b);
        }
        let bytes = enc.finish();
        let truncated = &bytes[..bytes.len().min(3)];
        // RangeDecoder::new itself errors on < 5 bytes.
        let dec_init = RangeDecoder::new(truncated);
        assert!(matches!(
            dec_init,
            Err(crate::decode::ppmd2::range_dec::RangeDecoderError::Truncated { .. })
        ));
    }

    #[test]
    fn decoder_surfaces_mid_stream_truncation() {
        // 5-byte init succeeds; mid-stream renormalisation hits EOF.
        let mut enc = RangeEncoder::new();
        let mut m_enc = Model::new(MIN_MEM_SIZE, 4).expect("enc");
        for &b in b"the quick brown fox jumps over the lazy dog".iter() {
            m_enc.encode_symbol(&mut enc, b);
        }
        let bytes = enc.finish();
        // Keep just the 5-byte init prefix; every subsequent decode
        // step must surface a Truncated error at the first byte
        // the n-ary decode would need from past the init prefix.
        let truncated = &bytes[..5];
        let mut m_dec = Model::new(MIN_MEM_SIZE, 4).expect("dec");
        let mut dec = RangeDecoder::new(truncated).expect("init");
        // The first decode will succeed only as long as the range
        // coder doesn't need to renormalize. After enough symbols
        // it will, and that surfaces as DecodeError::Range. The
        // important behaviour is "no panic" — verify by consuming
        // many symbols and asserting we eventually see an error.
        let mut saw_error = false;
        for _ in 0..256 {
            match m_dec.decode_symbol(&mut dec) {
                Ok(_) => continue,
                Err(DecodeError::Range(_)) => {
                    saw_error = true;
                    break;
                }
                Err(e) => panic!("expected Range error, got {e:?}"),
            }
        }
        assert!(saw_error, "expected Range error within 256 decode attempts");
    }

    #[test]
    fn allocator_view_exposes_arena_size() {
        let m = Model::new(16 * 1024, 4).expect("model");
        let alloc = m.allocator();
        // 16 KiB arena → 16380 bytes of working region (16384 -
        // 4 align - 0 since 16380 % 12 = 0). The exact post-pad
        // size is allocator-internal; we just verify the accessor
        // returns something plausible.
        assert!(alloc.size() > 0);
        assert!(alloc.size() <= 16 * 1024);
    }

    #[test]
    fn max_order_accessor_returns_constructor_value() {
        let m = Model::new(16 * 1024, 7).expect("model");
        assert_eq!(m.max_order(), 7);
    }

    #[test]
    fn round_trip_single_byte_streams_at_every_order() {
        // One-byte payloads exercise the very first context lookup
        // at every order. At restart, MinContext is the order-0
        // root with NumStats=256 — every byte is decoded via the
        // multi-state path on the first call regardless of order.
        for &order in &[MIN_ORDER, 3, 16, MAX_ORDER] {
            round_trip(b"!", order, MIN_MEM_SIZE);
            round_trip(&[0u8], order, MIN_MEM_SIZE);
            round_trip(&[255u8], order, MIN_MEM_SIZE);
        }
    }

    #[test]
    fn restart_after_decode_does_not_leak_state() {
        // Decode a stream, restart, encode-and-decode a different
        // stream. Verifies the model's restart() wipes all of
        // FoundState / MinContext / MaxContext / OrderFall /
        // PrevSuccess / RunLength back to canonical post-init.
        let mut m = Model::new(16 * 1024, 4).expect("model");
        let mut enc = RangeEncoder::new();
        for &b in b"first" {
            m.encode_symbol(&mut enc, b);
        }
        let _bytes_a = enc.finish();
        // Snapshot post-encode state (irrelevant — we restart).
        m.restart();
        // Round-trip a *different* payload now.
        let payload = b"second";
        let mut enc_b = RangeEncoder::new();
        for &b in payload {
            m.encode_symbol(&mut enc_b, b);
        }
        let bytes_b = enc_b.finish();
        m.restart();
        let mut dec = RangeDecoder::new(&bytes_b).expect("init");
        let got: Vec<u8> = (0..payload.len())
            .map(|_| m.decode_symbol(&mut dec).expect("decode"))
            .collect();
        assert_eq!(got, payload);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Comfortable arena for tests: 16 KiB. Large enough that the
    /// initial 129-unit allocations leave plenty of headroom; small
    /// enough to allocate quickly across hundreds of test cases.
    const TEST_ARENA: usize = 16 * 1024;

    /// Convenience: build a model and unwrap the success path.
    fn model() -> Model {
        Model::new(TEST_ARENA, 4).expect("model")
    }

    #[test]
    fn rejects_order_zero() {
        let err = Model::new(TEST_ARENA, 0).unwrap_err();
        assert!(matches!(err, ModelError::BadOrder { order: 0 }));
    }

    #[test]
    fn rejects_order_one() {
        let err = Model::new(TEST_ARENA, 1).unwrap_err();
        assert!(matches!(err, ModelError::BadOrder { order: 1 }));
    }

    #[test]
    fn rejects_order_above_max() {
        let err = Model::new(TEST_ARENA, MAX_ORDER + 1).unwrap_err();
        assert!(matches!(err, ModelError::BadOrder { .. }));
    }

    #[test]
    fn rejects_arena_below_min() {
        let err = Model::new(MIN_MEM_SIZE - 1, 4).unwrap_err();
        assert!(matches!(err, ModelError::ArenaTooSmall { .. }));
    }

    #[test]
    fn accepts_canonical_min_arena() {
        // 2 KiB is the LZMA SDK's PPMD7_MIN_MEM_SIZE; the model
        // must construct successfully there with both endpoints of
        // the supported order range.
        let _m = Model::new(MIN_MEM_SIZE, MIN_ORDER).expect("min order, min arena");
        let _m = Model::new(MIN_MEM_SIZE, MAX_ORDER).expect("max order, min arena");
    }

    #[test]
    fn restart_invariants_post_init() {
        let m = model();
        // MinContext == MaxContext at restart.
        assert_eq!(m.min_context, m.max_context);
        // The root context is the most-recent `alloc_context()`,
        // i.e. the top of the unit region minus one unit.
        assert!(m.min_context >= m.alloc.text());
        // OrderFall set to max_order; PrevSuccess clear.
        assert_eq!(m.order_fall, m.max_order);
        assert_eq!(m.prev_success, 0);
        // RunLength initialised to InitRL = -(min(max_order, 12)) - 1.
        let expected_rl = -(m.max_order.min(12) as i32) - 1;
        assert_eq!(m.run_length, expected_rl);
        assert_eq!(m.init_rl, expected_rl);
    }

    #[test]
    fn restart_root_context_has_full_alphabet() {
        let m = model();
        let ctx = m.min_context as usize;
        let arena = m.alloc.arena();
        // NumStats (u16 LE @ +0).
        assert_eq!(read_u16(arena, ctx + CTX_NUM_STATS_OFF), 256);
        // SummFreq (u16 LE @ +2): 256 symbols × freq 1 + escape mass 1.
        assert_eq!(read_u16(arena, ctx + CTX_SUMM_FREQ_OFF), 257);
        // Suffix (u32 LE @ +8): root has no parent.
        assert_eq!(read_u32(arena, ctx + CTX_SUFFIX_OFF), 0);
        // Stats ref (u32 LE @ +4) aliases FoundState.
        let stats = read_u32(arena, ctx + CTX_STATS_OFF);
        assert_eq!(stats, m.found_state, "FoundState aliases stats[0]");
        // All 256 states: symbol = i, freq = 1, successor = 0.
        for i in 0..256u32 {
            let s = (stats + i * STATE_SIZE as u32) as usize;
            assert_eq!(arena[s + STATE_SYMBOL_OFF], i as u8, "state[{i}].symbol");
            assert_eq!(arena[s + STATE_FREQ_OFF], 1, "state[{i}].freq");
            assert_eq!(
                read_u16(arena, s + STATE_SUCCESSOR_LOW_OFF),
                0,
                "state[{i}].successor_low"
            );
            assert_eq!(
                read_u16(arena, s + STATE_SUCCESSOR_HIGH_OFF),
                0,
                "state[{i}].successor_high"
            );
        }
    }

    #[test]
    fn restart_seeds_bin_summ_table() {
        let m = model();
        // Spot-check the recurrence: BinSumm[i][k]
        //   = BIN_SCALE - K_INIT_BIN_ESC[k] / (i + 2)
        // for k ∈ [0, 8), replicated 8× across the 64-wide row.
        for i in 0u32..128 {
            for k in 0u32..8 {
                let expected =
                    (PPMD_BIN_SCALE - u32::from(K_INIT_BIN_ESC[k as usize]) / (i + 2)) as u16;
                for m_off in (0u32..64).step_by(8) {
                    let got = m.bin_summ[(i * 64 + k + m_off) as usize];
                    assert_eq!(got, expected, "bin_summ[{i}][{}]", k + m_off);
                }
            }
        }
    }

    #[test]
    fn restart_seeds_see_table() {
        let m = model();
        // Spot-check the formula: See[i][k] = { summ: (5*i + 10) << 3, shift: 3, count: 4 }
        for i in 0u32..25 {
            for k in 0u32..16 {
                let entry = m.see[(i * 16 + k) as usize];
                assert_eq!(entry.summ, ((5 * i + 10) << 3) as u16, "see[{i}][{k}].summ");
                assert_eq!(entry.shift, 3, "see[{i}][{k}].shift");
                assert_eq!(entry.count, 4, "see[{i}][{k}].count");
            }
        }
    }

    #[test]
    fn dummy_see_set_to_saturated_shift() {
        // The order-0 root context routes through `dummy_see`; its
        // shift must start at PPMD_PERIOD_BITS so subsequent
        // `update()` calls are no-ops.
        let m = model();
        assert_eq!(m.dummy_see.shift, 7);
    }

    #[test]
    fn restart_idempotent_under_repeat() {
        let mut m = model();
        let ctx0 = m.min_context;
        let stats0 = m.found_state;
        m.restart();
        // Second restart should produce the same layout — the
        // allocator's bump pointers are deterministic given the same
        // arena size.
        assert_eq!(m.min_context, ctx0);
        assert_eq!(m.found_state, stats0);
    }

    #[test]
    fn k_init_bin_esc_values_match_lzma_sdk() {
        assert_eq!(K_INIT_BIN_ESC[0], 0x3CDD);
        assert_eq!(K_INIT_BIN_ESC[7], 0x6051);
    }

    // Layout constants are exercised by the file-level
    // `const _: () = { assert!(...); };` block, which fails to
    // compile if any offset drifts. No runtime test is needed.
}
