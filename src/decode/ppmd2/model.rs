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

use super::alloc::{AllocError, Allocator, Ref, PPMD_NUM_INDEXES};

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

/// Initial seeds for the binary-context SEE table, indexed by the
/// low 3 bits of the previous-context bucket index. The full
/// initial value (per `RestartModel`) is
/// `BIN_SCALE - K_INIT_BIN_ESC[k] / (i + 2)` where `i ∈ [0, 128)`.
const K_INIT_BIN_ESC: [u16; 8] = [
    0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051,
];

// The lookup tables `NS2_BS_INDX`, `NS2_INDX`, `HB2_FLAG`, the
// `K_EXP_ESCAPE` table, and the `MAX_FREQ` rescale threshold all
// participate in the decode loop and `update_model`. They land with
// §B2b alongside the code that consumes them.

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
fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

#[inline]
fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
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

// `See::update` (the `Ppmd_See_Update` adaptation rule) lands with
// §B2b alongside the decode loop that calls it.

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
}

// Field accessors (`ctx_num_stats`, `state_symbol`, etc.) used by
// the decode / update path land with §B2b. The B2a tests below
// reach into the arena through the public [`Allocator::arena`]
// view since their job is to validate the on-disk byte layout.

#[cfg(test)]
mod tests {
    use super::*;

    /// Comfortable arena for tests: 16 KiB. Large enough that the
    /// initial 129-unit allocations leave plenty of headroom; small
    /// enough to allocate quickly across hundreds of test cases.
    const TEST_ARENA: usize = 16 * 1024;

    fn read_u16(buf: &[u8], off: usize) -> u16 {
        u16::from_le_bytes([buf[off], buf[off + 1]])
    }

    fn read_u32(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
    }

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
