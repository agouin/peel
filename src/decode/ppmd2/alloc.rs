//! PPMd-II / PPMd7 sub-allocator.
//!
//! Custom slab allocator the PPMd model uses for its variable-order
//! context tree. Round-one (`docs/PLAN_rar3.md` §B1) ships the
//! allocator in isolation; §B2 plugs the context tree and decode
//! loop on top.
//!
//! # Layout
//!
//! The arena is one contiguous byte buffer. Every allocation is a
//! multiple of [`UNIT_SIZE`] (12 bytes), and freelists are
//! quantised into [`PPMD_NUM_INDEXES`] (38) size classes via the
//! [`INDX_TO_UNITS`] table.
//!
//! ```text
//! 0       align_offset             units_start            arena.len()
//! |- pad -|---- text region -------|---- units region ----|---tail---|
//!                                  ^         ^
//!                                  lo_unit   hi_unit
//!                                   grows up  grows down
//! ```
//!
//! - `text` grows upward from `align_offset`. The model writes one
//!   byte per emitted symbol (the linear stream the order-N context
//!   graph's [`Ref`]-typed Successor fields point into).
//! - `lo_unit` grows up, `hi_unit` grows down. Multi-unit
//!   allocations come off the bottom; one-unit "context"
//!   allocations come off the top.
//! - `units_start` is the lower bound of the unit region; rare-path
//!   allocations can move it down (toward `text`) to claim more
//!   space when the freelists and the central gap are both
//!   exhausted. The initial split puts 7/8 of the working area in
//!   the unit region and 1/8 in the text region — matching the
//!   canonical LZMA SDK Ppmd7 layout, which is sized so that the
//!   model's initial 129-unit working set (1× root context + 128×
//!   state-array units for 256 order-0 states) fits without taking
//!   the rare path.
//!
//! # Refs
//!
//! Allocations are returned as opaque [`Ref`] byte offsets into the
//! arena. The first 4 bytes are reserved as alignment padding so
//! the offset value `0` can serve as the null sentinel — every
//! valid [`Ref`] therefore wraps a [`NonZeroU32`].
//!
//! Callers read / write the typed contents via [`Allocator::slot`]
//! / [`Allocator::slot_mut`]. The allocator does not interpret slot
//! contents while a slot is live; only when a slot is on a freelist
//! does the allocator touch it (storing the `Next` pointer + `NU`
//! count for [`Allocator::glue_free_blocks`]).
//!
//! # Glue-driven compaction
//!
//! When the freelists are exhausted and the central gap can't
//! satisfy a multi-unit request, the rare path scans larger size
//! classes for a block to split. If that fails, the allocator
//! either pulls more space from `units_start` (shrinking the text
//! region) or — once `glue_count` decays to zero — runs
//! [`Allocator::glue_free_blocks`] to coalesce physically-adjacent
//! free blocks into bigger ones. Glue is bounded: at most one
//! `O(n²)` insertion-sort over the live freelist contents per
//! invocation, with `n` ≪ arena unit count in practice.
//!
//! # References
//!
//! - LZMA SDK `Ppmd7.c` — canonical reference; public domain.
//! - libarchive `archive_read_support_format_rar.c` — RAR3's PPMd
//!   integration; same allocator semantics.

use std::num::NonZeroU32;

use thiserror::Error;

/// Bytes per allocator "unit". Every alloc is a multiple of this.
pub const UNIT_SIZE: usize = 12;

/// Number of distinct freelist size classes. Buckets cover from
/// 1 unit (12 bytes) up to 128 units (1.5 KiB); see
/// [`INDX_TO_UNITS`].
pub const PPMD_NUM_INDEXES: usize = 38;

/// Largest single-block size (in units) handled by the freelists.
/// Glue splits coalesced blocks into ≤ 128-unit chunks before
/// inserting them.
const MAX_FREELIST_UNITS: usize = 128;

/// Bytes of zero padding at the start of the arena. Reserves the
/// `Ref` value `0` as a null sentinel — no valid allocation can
/// land in the first 4 bytes.
const ALIGN_PAD: usize = 4;

/// Bytes of zero padding at the end of the arena. Matches the
/// LZMA SDK's `+12` overshoot: the allocator's logical size is
/// rounded down to a unit boundary, and the trailing slack avoids
/// one-past-the-end arithmetic surprises if the model layer later
/// reads byte-by-byte beyond `hi_unit`.
const TAIL_PAD: usize = UNIT_SIZE;

/// Lower bound on a usable arena. One unit + padding. Anything
/// smaller can't even hold a single context allocation.
pub const MIN_ARENA_BYTES: usize = ALIGN_PAD + UNIT_SIZE + TAIL_PAD;

/// Upper bound on arena size. RAR3 / 7z PPMd archives in the wild
/// declare up to 256 MiB; the cap protects against an adversarial
/// header forcing a multi-GiB up-front allocation. Lifting the cap
/// is filed under §G alongside the dict cap in
/// [`crate::decode::rar_native::dict`].
pub const MAX_ARENA_BYTES: usize = 256 * 1024 * 1024;

/// Refresh value `glue_count` is reset to after [`Allocator::glue_free_blocks`].
/// Matches the LZMA SDK constant — every 256 cycles through the
/// "shrink units_start" rare path triggers another glue pass.
const GLUE_REFRESH: u32 = 255;

/// Index → units lookup, computed once at compile time per the
/// PPMd7 quantisation rule (`step = (i >= 12) ? 4 : (i >> 2) + 1`).
/// Values: 1, 2, 3, 4, 6, 8, 10, 12, 15, 18, 21, 24, then 28, 32,
/// … 128 in steps of 4.
pub const INDX_TO_UNITS: [u8; PPMD_NUM_INDEXES] = build_indx_to_units();

/// Units → index lookup (indexed by `units - 1`). Maps each unit
/// count from 1 to [`MAX_FREELIST_UNITS`] to the smallest freelist
/// index that fits it.
pub const UNITS_TO_INDX: [u8; MAX_FREELIST_UNITS] = build_units_to_indx();

const fn build_indx_to_units() -> [u8; PPMD_NUM_INDEXES] {
    let mut arr = [0u8; PPMD_NUM_INDEXES];
    let mut i = 0usize;
    let mut k = 0u32;
    while i < PPMD_NUM_INDEXES {
        let step = if i >= 12 { 4 } else { (i as u32 >> 2) + 1 };
        k += step;
        arr[i] = k as u8;
        i += 1;
    }
    arr
}

const fn build_units_to_indx() -> [u8; MAX_FREELIST_UNITS] {
    let mut arr = [0u8; MAX_FREELIST_UNITS];
    let mut i = 0usize;
    let mut k = 0usize;
    while i < PPMD_NUM_INDEXES {
        let step = if i >= 12 { 4 } else { (i >> 2) + 1 };
        let mut s = step;
        while s > 0 {
            arr[k] = i as u8;
            k += 1;
            s -= 1;
        }
        i += 1;
    }
    arr
}

/// Errors produced by [`Allocator`] construction.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum AllocError {
    /// `arena_bytes < MIN_ARENA_BYTES`.
    #[error(
        "PPMd-II allocator arena too small: {requested} bytes \
         (minimum {MIN_ARENA_BYTES})"
    )]
    ArenaTooSmall {
        /// Caller's requested arena size in bytes.
        requested: usize,
    },
    /// `arena_bytes > MAX_ARENA_BYTES`.
    #[error(
        "PPMd-II allocator arena too large: {requested} bytes \
         (maximum {MAX_ARENA_BYTES})"
    )]
    ArenaTooLarge {
        /// Caller's requested arena size in bytes.
        requested: usize,
    },
}

/// Opaque byte-offset reference into the allocator arena.
///
/// Wraps a [`NonZeroU32`] so the offset value `0` is reserved for
/// the null sentinel (the first [`ALIGN_PAD`] bytes of the arena
/// are alignment padding and never returned as an allocation).
///
/// Refs are stable for the lifetime of the [`Allocator`] until the
/// caller frees the slot or the allocator is restarted; they are
/// not stable across [`Allocator::glue_free_blocks`] (which moves
/// content within the arena? no — glue does *not* move allocated
/// content, only relinks free blocks; live refs remain valid).
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct Ref(NonZeroU32);

impl Ref {
    /// Construct a `Ref` from a non-zero byte offset.
    #[must_use]
    fn new(offset: u32) -> Option<Self> {
        NonZeroU32::new(offset).map(Self)
    }

    /// Byte offset into the arena. Always non-zero.
    #[must_use]
    pub fn byte_offset(self) -> u32 {
        self.0.get()
    }
}

/// PPMd-II sub-allocator owning a single arena.
///
/// Construct with [`Self::new`]; reset between archives / decoders
/// with [`Self::restart`]. Allocations come from
/// [`Self::alloc_units`] (multi-unit, freelist-backed) or
/// [`Self::alloc_context`] (one-unit, top-of-arena).
#[derive(Debug)]
pub struct Allocator {
    /// Backing storage. Held as `Box<[u8]>` so the allocator's
    /// stack footprint stays small while the arena itself lives on
    /// the heap.
    arena: Box<[u8]>,
    /// Logical "size" in bytes — the working area between
    /// `align_offset` and the tail pad. Always a multiple of
    /// [`UNIT_SIZE`].
    size: u32,
    /// Bytes of alignment padding at the start of `arena`. Equal
    /// to [`ALIGN_PAD`] = 4. Reserved so [`Ref`] = 0 is null.
    align_offset: u32,
    /// High water mark of the text region (byte-stream area). The
    /// model layer (§B2) bumps this on each emitted byte; round-one
    /// keeps it pinned at `align_offset`.
    text: u32,
    /// Lower boundary of the unit region. The rare-path fallback
    /// can lower this toward `text` to claim more unit space when
    /// the freelists and the central gap are exhausted.
    units_start: u32,
    /// Low watermark of the unit region (multi-unit allocations
    /// grow upward from here).
    lo_unit: u32,
    /// High watermark of the unit region (one-unit context
    /// allocations grow downward from here).
    hi_unit: u32,
    /// Decrementing counter that gates [`Self::glue_free_blocks`].
    /// Zero triggers a glue on the next rare-path miss; refreshed
    /// to [`GLUE_REFRESH`] after each glue.
    glue_count: u32,
    /// Per-size-class freelist heads. `0` means empty.
    free_list: [u32; PPMD_NUM_INDEXES],
}

// Free-node layout, written into the first 8 bytes of a freed slot:
//   offset 0..4 : Next ref (u32 little-endian; 0 = end of list)
//   offset 4..8 : NU count (u32 little-endian; units in this block)
// Bytes 8..12 of a 1-unit slot are unused while on the freelist.
// Multi-unit slots have plenty of additional slack the model can
// reuse once the slot is allocated again.
const NEXT_OFFSET: usize = 0;
const NU_OFFSET: usize = 4;

impl Allocator {
    /// Construct an allocator over a fresh `arena_bytes`-byte
    /// arena.
    ///
    /// # Errors
    ///
    /// - [`AllocError::ArenaTooSmall`] if `arena_bytes < MIN_ARENA_BYTES`.
    /// - [`AllocError::ArenaTooLarge`] if `arena_bytes > MAX_ARENA_BYTES`.
    pub fn new(arena_bytes: usize) -> Result<Self, AllocError> {
        if arena_bytes < MIN_ARENA_BYTES {
            return Err(AllocError::ArenaTooSmall {
                requested: arena_bytes,
            });
        }
        if arena_bytes > MAX_ARENA_BYTES {
            return Err(AllocError::ArenaTooLarge {
                requested: arena_bytes,
            });
        }
        // Logical size: the working area between the alignment pad
        // and the tail pad, rounded down to a unit boundary.
        let usable = arena_bytes - ALIGN_PAD - TAIL_PAD;
        let size = usable - (usable % UNIT_SIZE);
        // INVARIANT: arena_bytes >= MIN_ARENA_BYTES guarantees size >= UNIT_SIZE.
        debug_assert!(size >= UNIT_SIZE);
        let arena = vec![0u8; arena_bytes].into_boxed_slice();
        let mut me = Self {
            arena,
            // INVARIANT: size <= MAX_ARENA_BYTES (≪ u32::MAX).
            size: size as u32,
            align_offset: ALIGN_PAD as u32,
            text: 0,
            units_start: 0,
            lo_unit: 0,
            hi_unit: 0,
            glue_count: 0,
            free_list: [0u32; PPMD_NUM_INDEXES],
        };
        me.restart();
        Ok(me)
    }

    /// Reset the allocator to its initial empty state. Drops all
    /// outstanding allocations (callers' [`Ref`]s become invalid)
    /// and clears every freelist.
    pub fn restart(&mut self) {
        self.free_list.fill(0);
        self.text = self.align_offset;
        self.hi_unit = self.text + self.size;
        // Initial 7:1 unit-to-text split, matching the LZMA SDK Ppmd7
        // RestartModel layout. The model's first action is to allocate
        // 129 units (1 root context + 128-unit state array) — sizing
        // the unit region at ≥ 7/8 of the working area lets that
        // succeed on a 2 KiB arena without taking the rare path.
        let initial_units_bytes = (self.size / 8 / UNIT_SIZE as u32) * 7 * UNIT_SIZE as u32;
        self.lo_unit = self.hi_unit - initial_units_bytes;
        self.units_start = self.lo_unit;
        self.glue_count = 0;
    }

    /// Total bytes the arena occupies, including padding.
    #[must_use]
    pub fn arena_bytes(&self) -> usize {
        self.arena.len()
    }

    /// Logical working size in bytes (excludes leading and trailing
    /// padding). Always a multiple of [`UNIT_SIZE`].
    #[must_use]
    pub fn size(&self) -> u32 {
        self.size
    }

    /// Quantise a unit count to the smallest freelist index that
    /// fits it. Returns `None` for `units == 0` or `units > MAX_FREELIST_UNITS`.
    #[must_use]
    pub fn units_to_indx(units: u32) -> Option<u32> {
        if units == 0 || units as usize > MAX_FREELIST_UNITS {
            None
        } else {
            Some(UNITS_TO_INDX[(units - 1) as usize] as u32)
        }
    }

    /// Number of units in the freelist size class `indx`.
    ///
    /// # Panics
    ///
    /// Panics if `indx >= PPMD_NUM_INDEXES`.
    #[must_use]
    pub fn indx_to_units(indx: u32) -> u32 {
        INDX_TO_UNITS[indx as usize] as u32
    }

    /// Borrow the bytes for one allocation slot, scoped by the
    /// freelist index that was passed at alloc / free time. The
    /// returned slice is exactly `INDX_TO_UNITS[indx] * UNIT_SIZE`
    /// bytes long.
    ///
    /// # Panics
    ///
    /// Panics if `indx >= PPMD_NUM_INDEXES` or if the offset would
    /// reach past the arena end.
    #[must_use]
    pub fn slot(&self, ptr: Ref, indx: u32) -> &[u8] {
        let off = ptr.byte_offset() as usize;
        let len = Self::indx_to_units(indx) as usize * UNIT_SIZE;
        &self.arena[off..off + len]
    }

    /// Mutably borrow the bytes for one allocation slot. See
    /// [`Self::slot`] for shape.
    pub fn slot_mut(&mut self, ptr: Ref, indx: u32) -> &mut [u8] {
        let off = ptr.byte_offset() as usize;
        let len = Self::indx_to_units(indx) as usize * UNIT_SIZE;
        &mut self.arena[off..off + len]
    }

    /// Borrow the bytes for a one-unit context slot. Always 12
    /// bytes ([`UNIT_SIZE`]).
    #[must_use]
    pub fn context_slot(&self, ptr: Ref) -> &[u8] {
        let off = ptr.byte_offset() as usize;
        &self.arena[off..off + UNIT_SIZE]
    }

    /// Mutably borrow a one-unit context slot.
    pub fn context_slot_mut(&mut self, ptr: Ref) -> &mut [u8] {
        let off = ptr.byte_offset() as usize;
        &mut self.arena[off..off + UNIT_SIZE]
    }

    /// Read one arbitrary byte from the arena. The model uses this to
    /// look up text-region bytes referenced by a state's Successor
    /// field (which doubles as a byte offset when the upstream chain
    /// has not yet been promoted into the unit region).
    ///
    /// # Panics
    ///
    /// Panics if `off >= self.arena_bytes()`.
    #[must_use]
    pub fn read_byte(&self, off: u32) -> u8 {
        self.arena[off as usize]
    }

    /// Current text high-water mark (next free text-region byte).
    /// Bytes `[align_offset, text)` hold the model's emitted byte
    /// stream; bytes `[text, units_start)` are unwritten.
    #[must_use]
    pub fn text(&self) -> u32 {
        self.text
    }

    /// Lower bound of the unit region. The model checks
    /// `text >= units_start` after each text-region write to detect
    /// arena exhaustion.
    #[must_use]
    pub fn units_start(&self) -> u32 {
        self.units_start
    }

    /// Append one byte to the text region and return the offset where
    /// it was written. Advances `text` by 1.
    ///
    /// The model is expected to check `text() < units_start()` after
    /// the call; if the inequality has flipped, the arena is
    /// exhausted and the model must restart.
    ///
    /// # Panics
    ///
    /// Panics if writing would land outside the arena bounds. In
    /// practice this cannot happen: `text` advances at most one byte
    /// past `units_start`, and the [`TAIL_PAD`] = `UNIT_SIZE` bytes
    /// of slack at the end of the arena absorb that overshoot.
    pub fn write_text_byte(&mut self, b: u8) -> u32 {
        let pos = self.text;
        self.arena[pos as usize] = b;
        self.text += 1;
        pos
    }

    /// Decrement `text` by 1. Used by the model when a context
    /// transition rolls back the most recent text-region write
    /// because the new `MaxContext` already covers the byte.
    ///
    /// # Panics
    ///
    /// Panics if `text == align_offset`. The model layer guards
    /// against this by only calling `dec_text` after a paired
    /// [`Self::write_text_byte`].
    pub fn dec_text(&mut self) {
        // INVARIANT: every call site is paired with a prior
        // write_text_byte that bumped text past align_offset.
        debug_assert!(self.text > self.align_offset);
        self.text -= 1;
    }

    /// Raw view of the arena bytes. The model layer reads multi-byte
    /// state and context fields directly off this slice.
    #[must_use]
    pub fn arena(&self) -> &[u8] {
        &self.arena
    }

    /// Mutable raw view of the arena bytes. The model layer writes
    /// state and context fields directly through this slice.
    pub fn arena_mut(&mut self) -> &mut [u8] {
        &mut self.arena
    }

    /// Allocate a block of `INDX_TO_UNITS[indx]` units.
    ///
    /// Tries the per-index freelist first; falls back to carving
    /// from the central `[lo_unit, hi_unit)` gap; failing that,
    /// runs the rare path (glue + larger-bucket-split + units_start
    /// shrink). Returns `None` only when every avenue is
    /// exhausted.
    ///
    /// # Panics
    ///
    /// Panics if `indx >= PPMD_NUM_INDEXES`.
    pub fn alloc_units(&mut self, indx: u32) -> Option<Ref> {
        assert!((indx as usize) < PPMD_NUM_INDEXES);
        if self.free_list[indx as usize] != 0 {
            return Some(self.remove_node(indx));
        }
        let bytes = Self::indx_to_units(indx) * UNIT_SIZE as u32;
        if self.lo_unit + bytes <= self.hi_unit {
            let r = self.lo_unit;
            self.lo_unit += bytes;
            return Ref::new(r);
        }
        self.alloc_units_rare(indx)
    }

    /// Allocate a one-unit block from the top of the unit region.
    /// Used by the model for context-tree nodes; faster path than
    /// [`Self::alloc_units`] because it never checks freelists when
    /// the central gap can satisfy.
    pub fn alloc_context(&mut self) -> Option<Ref> {
        if self.hi_unit != self.lo_unit {
            self.hi_unit -= UNIT_SIZE as u32;
            return Ref::new(self.hi_unit);
        }
        if self.free_list[0] != 0 {
            return Some(self.remove_node(0));
        }
        self.alloc_units_rare(0)
    }

    /// Return a previously-allocated block to the freelist for
    /// `indx`.
    ///
    /// # Panics
    ///
    /// Panics if `indx >= PPMD_NUM_INDEXES`.
    pub fn free_units(&mut self, ptr: Ref, indx: u32) {
        assert!((indx as usize) < PPMD_NUM_INDEXES);
        self.insert_node(ptr, indx);
    }

    /// Shrink an allocation from `old_indx`-units down to
    /// `new_indx`-units. Returns the [`Ref`] of the (possibly new)
    /// block holding the kept content; the caller's `old_ptr`
    /// becomes invalid and must not be used.
    ///
    /// If the new freelist has a free block, the kept content is
    /// copied into that block and the source is freed at
    /// `old_indx`. Otherwise the source is split in place and the
    /// trailing remainder is dropped onto the appropriate
    /// freelist(s).
    ///
    /// # Panics
    ///
    /// Panics if either index is out of range or if `new_indx > old_indx`.
    pub fn shrink_units(&mut self, old_ptr: Ref, old_indx: u32, new_indx: u32) -> Ref {
        assert!((old_indx as usize) < PPMD_NUM_INDEXES);
        assert!((new_indx as usize) < PPMD_NUM_INDEXES);
        assert!(new_indx <= old_indx);
        if old_indx == new_indx {
            return old_ptr;
        }
        if self.free_list[new_indx as usize] != 0 {
            let new_ptr = self.remove_node(new_indx);
            let new_nu = Self::indx_to_units(new_indx) as usize;
            self.copy_units(old_ptr, new_ptr, new_nu);
            self.insert_node(old_ptr, old_indx);
            new_ptr
        } else {
            self.split_block(old_ptr, old_indx, new_indx);
            old_ptr
        }
    }

    /// Coalesce physically-adjacent free blocks into bigger blocks
    /// and rebuild the freelists.
    ///
    /// Public so tests can drive it directly; the rare-path
    /// allocator also calls it internally when `glue_count == 0`.
    /// Each call resets `glue_count` to [`GLUE_REFRESH`].
    pub fn glue_free_blocks(&mut self) {
        self.glue_count = GLUE_REFRESH;

        // Step 1: drain every freelist into a single chain sorted
        // by ascending byte offset. We re-use each node's Next
        // field as the chain link; NU is set to the source
        // freelist's unit count so step 2 can compute physical
        // adjacency.
        let mut head: u32 = 0;
        for (i, &bin_units) in INDX_TO_UNITS.iter().enumerate() {
            let nu = bin_units as u32;
            let mut next = self.free_list[i];
            self.free_list[i] = 0;
            while next != 0 {
                // Snapshot the original Next before we overwrite it.
                let saved_next = self.read_next(next);
                self.write_nu(next, nu);
                head = self.insert_sorted(head, next);
                next = saved_next;
            }
        }

        // Step 2: walk the sorted chain, merging blocks whose
        // address + size equals the next block's address.
        let mut node = head;
        while node != 0 {
            loop {
                let nu = self.read_nu(node);
                let next = self.read_next(node);
                if next == 0 {
                    break;
                }
                if node.checked_add(nu * UNIT_SIZE as u32) != Some(next) {
                    break;
                }
                let next_nu = self.read_nu(next);
                let next_next = self.read_next(next);
                self.write_nu(node, nu + next_nu);
                self.write_next(node, next_next);
            }
            node = self.read_next(node);
        }

        // Step 3: redistribute the (possibly merged) blocks back
        // into freelists, splitting blocks larger than
        // MAX_FREELIST_UNITS into ≤ 128-unit chunks.
        let mut node = head;
        while node != 0 {
            let saved_next = self.read_next(node);
            let mut nu = self.read_nu(node);
            let mut cur = node;
            while nu > MAX_FREELIST_UNITS as u32 {
                // INVARIANT: cur is a non-zero offset because it
                // started as `node` (a valid freelist offset) and
                // was only incremented.
                let r = Ref::new(cur).expect("non-zero offset");
                self.insert_node(r, (PPMD_NUM_INDEXES - 1) as u32);
                cur += MAX_FREELIST_UNITS as u32 * UNIT_SIZE as u32;
                nu -= MAX_FREELIST_UNITS as u32;
            }
            if nu != 0 {
                let r = Ref::new(cur).expect("non-zero offset");
                let i = UNITS_TO_INDX[(nu - 1) as usize] as u32;
                if INDX_TO_UNITS[i as usize] as u32 != nu {
                    // Doesn't fit a single bin: split into largest
                    // fitting bin (i-1) plus a 1..3-unit remainder.
                    let i = i - 1;
                    let k = INDX_TO_UNITS[i as usize] as u32;
                    let remainder_off = cur + k * UNIT_SIZE as u32;
                    let remainder_indx = nu - k - 1;
                    // INVARIANT: across all 38 bins the gap to the
                    // next bin is at most 4 units, so `nu - k` is
                    // in 1..=3 and `remainder_indx` ∈ {0, 1, 2}.
                    let rem = Ref::new(remainder_off).expect("non-zero offset");
                    self.insert_node(rem, remainder_indx);
                    self.insert_node(r, i);
                } else {
                    self.insert_node(r, i);
                }
            }
            node = saved_next;
        }
    }

    // ── Internal helpers ────────────────────────────────────────

    fn alloc_units_rare(&mut self, indx: u32) -> Option<Ref> {
        if self.glue_count == 0 {
            self.glue_free_blocks();
            if self.free_list[indx as usize] != 0 {
                return Some(self.remove_node(indx));
            }
        }
        // Search for a larger size class with free blocks; if
        // found, split one and return the head.
        let mut i = indx as usize;
        loop {
            i += 1;
            if i == PPMD_NUM_INDEXES {
                // Exhausted larger size classes. Try to claim
                // bytes from the text region by lowering
                // units_start.
                self.glue_count = self.glue_count.saturating_sub(1);
                let bytes = Self::indx_to_units(indx) * UNIT_SIZE as u32;
                if self.units_start - self.text >= bytes {
                    self.units_start -= bytes;
                    return Ref::new(self.units_start);
                }
                return None;
            }
            if self.free_list[i] != 0 {
                break;
            }
        }
        let ptr = self.remove_node(i as u32);
        self.split_block(ptr, i as u32, indx);
        Some(ptr)
    }

    fn split_block(&mut self, ptr: Ref, old_indx: u32, new_indx: u32) {
        let new_nu = Self::indx_to_units(new_indx);
        let u_diff = Self::indx_to_units(old_indx) - new_nu;
        // INVARIANT: split_block is only called when old_indx > new_indx
        // (caller in shrink_units / alloc_units_rare guards), so the
        // bin gap is at least one unit.
        debug_assert!(u_diff > 0);
        let split_off = ptr.byte_offset() + new_nu * UNIT_SIZE as u32;
        let mut i = UNITS_TO_INDX[(u_diff - 1) as usize] as u32;
        if INDX_TO_UNITS[i as usize] as u32 != u_diff {
            // Remainder doesn't match a bin exactly. Insert the
            // largest fitting bin (i - 1) plus a 1..3-unit tail.
            i -= 1;
            let k = INDX_TO_UNITS[i as usize] as u32;
            let remainder_off = split_off + k * UNIT_SIZE as u32;
            let remainder_indx = u_diff - k - 1;
            // INVARIANT: see glue_free_blocks step 3.
            let rem = Ref::new(remainder_off).expect("non-zero offset");
            self.insert_node(rem, remainder_indx);
        }
        let main = Ref::new(split_off).expect("non-zero offset");
        self.insert_node(main, i);
    }

    fn copy_units(&mut self, src: Ref, dst: Ref, nu: usize) {
        let bytes = nu * UNIT_SIZE;
        let src_off = src.byte_offset() as usize;
        let dst_off = dst.byte_offset() as usize;
        // Source and destination are independent allocator slots
        // with disjoint footprints, so a non-overlapping copy is
        // safe — and copy_within enforces that at runtime.
        self.arena.copy_within(src_off..src_off + bytes, dst_off);
    }

    fn insert_node(&mut self, ptr: Ref, indx: u32) {
        let nu = Self::indx_to_units(indx);
        let next = self.free_list[indx as usize];
        self.write_next(ptr.byte_offset(), next);
        self.write_nu(ptr.byte_offset(), nu);
        self.free_list[indx as usize] = ptr.byte_offset();
    }

    fn remove_node(&mut self, indx: u32) -> Ref {
        let head = self.free_list[indx as usize];
        // INVARIANT: callers in alloc_units / alloc_context /
        // shrink_units check `free_list[i] != 0` before invoking.
        debug_assert_ne!(head, 0);
        let next = self.read_next(head);
        self.free_list[indx as usize] = next;
        Ref::new(head).expect("free_list head is non-zero by INVARIANT")
    }

    /// Insert `node` into the chain rooted at `head`, ordered by
    /// ascending byte offset. Returns the new chain head. Used by
    /// glue step 1 to build a sorted chain — `O(n)` per insert,
    /// `O(n²)` overall, but `n` here is bounded by the live
    /// freelist count which is typically a few hundred entries.
    fn insert_sorted(&mut self, head: u32, node: u32) -> u32 {
        if head == 0 || node < head {
            self.write_next(node, head);
            return node;
        }
        let mut cur = head;
        loop {
            let next = self.read_next(cur);
            if next == 0 || next > node {
                self.write_next(node, next);
                self.write_next(cur, node);
                return head;
            }
            cur = next;
        }
    }

    fn read_next(&self, off: u32) -> u32 {
        let i = off as usize + NEXT_OFFSET;
        let bytes: [u8; 4] = self.arena[i..i + 4]
            .try_into()
            .expect("4-byte slice from valid arena offset");
        u32::from_le_bytes(bytes)
    }

    fn write_next(&mut self, off: u32, value: u32) {
        let i = off as usize + NEXT_OFFSET;
        self.arena[i..i + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn read_nu(&self, off: u32) -> u32 {
        let i = off as usize + NU_OFFSET;
        let bytes: [u8; 4] = self.arena[i..i + 4]
            .try_into()
            .expect("4-byte slice from valid arena offset");
        u32::from_le_bytes(bytes)
    }

    fn write_nu(&mut self, off: u32, value: u32) {
        let i = off as usize + NU_OFFSET;
        self.arena[i..i + 4].copy_from_slice(&value.to_le_bytes());
    }
}

#[cfg(test)]
impl Allocator {
    /// Test-only accessor for the freelist heads. Used to assert
    /// invariants the public API doesn't expose.
    pub(crate) fn free_list_head(&self, indx: u32) -> u32 {
        self.free_list[indx as usize]
    }

    /// Test-only accessor for `lo_unit`.
    pub(crate) fn lo_unit(&self) -> u32 {
        self.lo_unit
    }

    /// Test-only accessor for `hi_unit`.
    pub(crate) fn hi_unit(&self) -> u32 {
        self.hi_unit
    }

    /// Test-only accessor for `glue_count`.
    pub(crate) fn glue_count(&self) -> u32 {
        self.glue_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny helper: arena big enough for ~85 units of working area
    /// (≈ 1 KiB). Big enough to exercise multi-bucket allocs but
    /// small enough that the rare path is reachable in tests.
    const TEST_ARENA_BYTES: usize = 1024;

    /// Bigger arena for tests that need plenty of room.
    const BIG_ARENA_BYTES: usize = 64 * 1024;

    #[test]
    fn lookup_tables_match_lzma_sdk() {
        // Spot-check a few values against the LZMA SDK reference
        // (Ppmd7.c's runtime initialiser):
        assert_eq!(INDX_TO_UNITS[0], 1);
        assert_eq!(INDX_TO_UNITS[3], 4);
        assert_eq!(INDX_TO_UNITS[4], 6);
        assert_eq!(INDX_TO_UNITS[7], 12);
        assert_eq!(INDX_TO_UNITS[8], 15);
        assert_eq!(INDX_TO_UNITS[11], 24);
        assert_eq!(INDX_TO_UNITS[12], 28);
        assert_eq!(INDX_TO_UNITS[37], 128);

        assert_eq!(UNITS_TO_INDX[0], 0); // 1 unit → bin 0
        assert_eq!(UNITS_TO_INDX[3], 3); // 4 units → bin 3
        assert_eq!(UNITS_TO_INDX[4], 4); // 5 units → bin 4 (size 6)
        assert_eq!(UNITS_TO_INDX[5], 4); // 6 units → bin 4
        assert_eq!(UNITS_TO_INDX[127], 37); // 128 units → bin 37
    }

    #[test]
    fn lookup_tables_are_consistent() {
        // For every unit count 1..=128 the bin's I2U is >= units.
        for nu in 1u32..=128 {
            let i = UNITS_TO_INDX[(nu - 1) as usize] as usize;
            assert!(
                INDX_TO_UNITS[i] as u32 >= nu,
                "U2I[{nu}] = {i}; I2U[{i}] = {} should be >= {nu}",
                INDX_TO_UNITS[i]
            );
            // And the previous bin is too small.
            if i > 0 {
                assert!(
                    (INDX_TO_UNITS[i - 1] as u32) < nu,
                    "U2I[{nu}] should be the smallest bin >= {nu}",
                );
            }
        }
    }

    #[test]
    fn rejects_too_small_arena() {
        let err = Allocator::new(MIN_ARENA_BYTES - 1).unwrap_err();
        assert!(matches!(err, AllocError::ArenaTooSmall { .. }));
    }

    #[test]
    fn rejects_too_large_arena() {
        let err = Allocator::new(MAX_ARENA_BYTES + 1).unwrap_err();
        assert!(matches!(err, AllocError::ArenaTooLarge { .. }));
    }

    #[test]
    fn fresh_allocator_invariants() {
        let a = Allocator::new(TEST_ARENA_BYTES).expect("alloc");
        // Working area is unit-aligned and within bounds.
        assert!((a.size() as usize).is_multiple_of(UNIT_SIZE));
        assert!((a.size() as usize) <= TEST_ARENA_BYTES);
        // Initial unit region carved off the top, text region empty.
        assert_eq!(a.lo_unit(), a.units_start());
        assert!(a.hi_unit() > a.lo_unit());
        // No outstanding freelist blocks.
        for i in 0..PPMD_NUM_INDEXES as u32 {
            assert_eq!(a.free_list_head(i), 0, "freelist[{i}] non-empty");
        }
        // First allocation has a non-zero offset (Ref(0) sentinel).
        assert_eq!(a.glue_count(), 0);
    }

    #[test]
    fn alloc_context_consumes_top_of_arena() {
        let mut a = Allocator::new(BIG_ARENA_BYTES).expect("alloc");
        let initial_hi = a.hi_unit();
        let r = a.alloc_context().expect("context");
        assert_eq!(r.byte_offset() + UNIT_SIZE as u32, initial_hi);
        assert_eq!(a.hi_unit(), initial_hi - UNIT_SIZE as u32);
    }

    #[test]
    fn alloc_units_consumes_bottom_of_arena() {
        let mut a = Allocator::new(BIG_ARENA_BYTES).expect("alloc");
        let initial_lo = a.lo_unit();
        // 6-unit block (indx 4 → 6 units = 72 bytes)
        let r = a.alloc_units(4).expect("units");
        assert_eq!(r.byte_offset(), initial_lo);
        assert_eq!(a.lo_unit(), initial_lo + 6 * UNIT_SIZE as u32);
    }

    #[test]
    fn free_then_realloc_reuses_freelist() {
        let mut a = Allocator::new(BIG_ARENA_BYTES).expect("alloc");
        let r1 = a.alloc_units(4).expect("alloc1");
        let r2 = a.alloc_units(4).expect("alloc2");
        let lo_after_two = a.lo_unit();
        a.free_units(r1, 4);
        // Freelist[4] should now hold r1.
        assert_eq!(a.free_list_head(4), r1.byte_offset());
        // Re-alloc should pop the freelist instead of advancing lo_unit.
        let r3 = a.alloc_units(4).expect("alloc3");
        assert_eq!(r3, r1);
        assert_eq!(a.lo_unit(), lo_after_two);
        // Bookkeeping: freelist[4] back to empty, r2 untouched.
        assert_eq!(a.free_list_head(4), 0);
        assert_ne!(r2, r3);
    }

    #[test]
    fn freelist_lifo_order() {
        let mut a = Allocator::new(BIG_ARENA_BYTES).expect("alloc");
        let r1 = a.alloc_units(0).expect("alloc1");
        let r2 = a.alloc_units(0).expect("alloc2");
        let r3 = a.alloc_units(0).expect("alloc3");
        a.free_units(r1, 0);
        a.free_units(r2, 0);
        a.free_units(r3, 0);
        // Last freed should pop first.
        assert_eq!(a.alloc_units(0).expect("re1"), r3);
        assert_eq!(a.alloc_units(0).expect("re2"), r2);
        assert_eq!(a.alloc_units(0).expect("re3"), r1);
    }

    #[test]
    fn slot_round_trip_writes_and_reads() {
        let mut a = Allocator::new(BIG_ARENA_BYTES).expect("alloc");
        // 12-unit block = 144 bytes.
        let r = a.alloc_units(7).expect("alloc");
        let payload: Vec<u8> = (0..144).map(|i| (i ^ 0xA5) as u8).collect();
        a.slot_mut(r, 7).copy_from_slice(&payload);
        assert_eq!(a.slot(r, 7), &payload[..]);
    }

    #[test]
    fn restart_clears_state() {
        let mut a = Allocator::new(BIG_ARENA_BYTES).expect("alloc");
        let r = a.alloc_units(3).expect("alloc");
        a.free_units(r, 3);
        assert_ne!(a.free_list_head(3), 0);
        a.restart();
        for i in 0..PPMD_NUM_INDEXES as u32 {
            assert_eq!(a.free_list_head(i), 0);
        }
        assert_eq!(a.lo_unit(), a.units_start());
        assert_eq!(a.glue_count(), 0);
    }

    #[test]
    fn shrink_no_op_when_indices_match() {
        let mut a = Allocator::new(BIG_ARENA_BYTES).expect("alloc");
        let r = a.alloc_units(5).expect("alloc");
        let r2 = a.shrink_units(r, 5, 5);
        assert_eq!(r, r2);
    }

    #[test]
    fn shrink_in_place_when_no_free_target_block() {
        let mut a = Allocator::new(BIG_ARENA_BYTES).expect("alloc");
        // Allocate a 12-unit block (indx 7, units 12).
        let r = a.alloc_units(7).expect("alloc");
        // Shrink to 8 units (indx 5). Freelists for indx 5 are
        // empty, so shrink should split in place: keep [0..8) units
        // and free the trailing 4 units (= bin 3).
        let r2 = a.shrink_units(r, 7, 5);
        assert_eq!(r, r2);
        assert_ne!(a.free_list_head(3), 0, "remainder should be on freelist[3]");
    }

    #[test]
    fn shrink_uses_target_freelist_when_available() {
        let mut a = Allocator::new(BIG_ARENA_BYTES).expect("alloc");
        // Pre-populate freelist[5] (8 units): alloc + free.
        let donor = a.alloc_units(5).expect("donor");
        a.free_units(donor, 5);
        // Allocate a fresh 12-unit block (indx 7).
        let r = a.alloc_units(7).expect("alloc");
        // Write a recognisable pattern into the first 8 units.
        let pattern: Vec<u8> = (0..8 * UNIT_SIZE).map(|i| i as u8).collect();
        a.slot_mut(r, 7)[..pattern.len()].copy_from_slice(&pattern);
        // Shrink: kept content should land on the freelist[5] donor block.
        let r2 = a.shrink_units(r, 7, 5);
        assert_eq!(r2, donor);
        assert_eq!(&a.slot(r2, 5)[..pattern.len()], &pattern[..]);
        // Original block is now on freelist[7].
        assert_eq!(a.free_list_head(7), r.byte_offset());
        // freelist[5] drained.
        assert_eq!(a.free_list_head(5), 0);
    }

    #[test]
    fn split_block_inserts_remainder_on_correct_freelist() {
        let mut a = Allocator::new(BIG_ARENA_BYTES).expect("alloc");
        // Allocate at indx 6 (10 units), shrink to indx 4 (6 units).
        // Diff = 4 units, which equals INDX_TO_UNITS[3] exactly.
        let r = a.alloc_units(6).expect("alloc");
        a.shrink_units(r, 6, 4);
        assert_ne!(a.free_list_head(3), 0, "diff-4 remainder on freelist[3]");
    }

    #[test]
    fn split_block_with_inexact_diff_uses_two_bins() {
        let mut a = Allocator::new(BIG_ARENA_BYTES).expect("alloc");
        // Allocate at indx 8 (15 units), shrink to indx 5 (8 units).
        // Diff = 7 units. INDX_TO_UNITS[4]=6, [5]=8.
        // U2I[6] (= U2I[7-1]) = 5; I2U[5]=8 ≠ 7 → split.
        // Falls back to bin 4 (6 units) + 1-unit remainder.
        let r = a.alloc_units(8).expect("alloc");
        a.shrink_units(r, 8, 5);
        assert_ne!(a.free_list_head(4), 0, "6-unit chunk on freelist[4]");
        assert_ne!(a.free_list_head(0), 0, "1-unit remainder on freelist[0]");
    }

    #[test]
    fn alloc_units_rare_steals_from_larger_bucket() {
        let mut a = Allocator::new(BIG_ARENA_BYTES).expect("alloc");
        // Pre-populate freelist[6] (10 units).
        let donor = a.alloc_units(6).expect("donor");
        a.free_units(donor, 6);
        // Drain the central gap so the freelist path is the only option.
        drain_to_full(&mut a);
        // Now request a 6-unit block (indx 4). Freelist[4] is
        // empty, central gap is empty, but freelist[6] has a block —
        // rare path must split it.
        let r = a.alloc_units(4).expect("rare alloc");
        assert_eq!(r.byte_offset(), donor.byte_offset());
        // freelist[6] drained, remainder (4 units = bin 3) on freelist[3].
        assert_eq!(a.free_list_head(6), 0);
        assert_ne!(a.free_list_head(3), 0);
    }

    #[test]
    fn alloc_units_rare_falls_back_to_units_start_shrink() {
        let mut a = Allocator::new(BIG_ARENA_BYTES).expect("alloc");
        let initial_units_start = a.units_start();
        // Drain the central gap; no freelists populated.
        drain_to_full(&mut a);
        assert_eq!(a.lo_unit(), a.hi_unit(), "central gap drained");
        // Now ask for a fresh 1-unit allocation. Rare path should
        // shrink units_start (since text_region == align_offset is
        // small and units_start - text > 12 bytes still holds).
        let r = a.alloc_units(0).expect("rare alloc via units_start");
        assert!(a.units_start() < initial_units_start);
        assert_eq!(r.byte_offset(), a.units_start());
    }

    #[test]
    fn alloc_returns_none_when_arena_truly_exhausted() {
        let mut a = Allocator::new(MIN_ARENA_BYTES + 32).expect("alloc");
        // Drain everything we can.
        let mut count = 0;
        while a.alloc_units(0).is_some() {
            count += 1;
            assert!(count < 100_000, "alloc loop runaway");
        }
        // One more attempt must return None.
        assert_eq!(a.alloc_units(0), None);
    }

    #[test]
    fn glue_coalesces_adjacent_blocks() {
        let mut a = Allocator::new(BIG_ARENA_BYTES).expect("alloc");
        // Allocate two adjacent 6-unit blocks, then free them in
        // order. Freelist[4] now holds two blocks whose addresses
        // are 6*12 = 72 bytes apart.
        let r1 = a.alloc_units(4).expect("alloc1");
        let r2 = a.alloc_units(4).expect("alloc2");
        a.free_units(r1, 4);
        a.free_units(r2, 4);
        assert_ne!(a.free_list_head(4), 0);
        // Glue should merge them into a single 12-unit block on
        // freelist[7].
        a.glue_free_blocks();
        assert_eq!(a.free_list_head(4), 0, "freelist[4] drained by glue");
        assert_ne!(
            a.free_list_head(7),
            0,
            "merged 12-unit block on freelist[7]"
        );
        assert_eq!(a.glue_count(), GLUE_REFRESH);
    }

    #[test]
    fn glue_does_not_merge_non_adjacent_blocks() {
        let mut a = Allocator::new(BIG_ARENA_BYTES).expect("alloc");
        // Allocate three 6-unit blocks; free the outer two so
        // they're separated by the still-allocated middle one.
        let r1 = a.alloc_units(4).expect("alloc1");
        let r2 = a.alloc_units(4).expect("alloc2");
        let r3 = a.alloc_units(4).expect("alloc3");
        a.free_units(r1, 4);
        a.free_units(r3, 4);
        a.glue_free_blocks();
        // r1 and r3 are not physically adjacent (r2 sits between
        // them), so glue should leave both as separate 6-unit
        // entries. Walk freelist[4] and count.
        let mut count = 0;
        let mut head = a.free_list_head(4);
        while head != 0 {
            count += 1;
            head = a.read_next(head);
            assert!(count < 100, "freelist walk runaway");
        }
        assert_eq!(
            count, 2,
            "two non-adjacent 6-unit blocks should survive glue"
        );
        // r2 is still considered allocated; glue must not have
        // touched its slot.
        let _ = r2;
    }

    #[test]
    fn glue_handles_blocks_larger_than_max_freelist_units() {
        let mut a = Allocator::new(BIG_ARENA_BYTES).expect("alloc");
        // Allocate and free a chain of adjacent 64-unit blocks
        // (indx 21 → 64 units). Two of them yields 128 units
        // (= bin 37); three yields 192 which exceeds
        // MAX_FREELIST_UNITS and must be split.
        let r1 = a.alloc_units(21).expect("alloc1");
        let r2 = a.alloc_units(21).expect("alloc2");
        let r3 = a.alloc_units(21).expect("alloc3");
        a.free_units(r1, 21);
        a.free_units(r2, 21);
        a.free_units(r3, 21);
        a.glue_free_blocks();
        // After merge: 192-unit block. Step 3 splits it into one
        // 128-unit block (bin 37) plus a 64-unit remainder (bin 21).
        assert_ne!(a.free_list_head(37), 0, "128-unit chunk");
        assert_ne!(a.free_list_head(21), 0, "64-unit remainder");
    }

    #[test]
    fn glue_runs_automatically_via_rare_path() {
        let mut a = Allocator::new(BIG_ARENA_BYTES).expect("alloc");
        // Stage two adjacent 6-unit blocks on freelist[4].
        let r1 = a.alloc_units(4).expect("alloc1");
        let r2 = a.alloc_units(4).expect("alloc2");
        a.free_units(r1, 4);
        a.free_units(r2, 4);
        // Drain the rest of the central gap so any subsequent
        // alloc has to take the rare path.
        drain_to_full(&mut a);
        // glue_count starts at 0, so the first rare-path call
        // should fire glue and find the merged block on
        // freelist[7].
        let r = a
            .alloc_units(7)
            .expect("rare alloc finds glue-merged block");
        assert_eq!(r.byte_offset(), r1.byte_offset());
        assert_eq!(a.glue_count(), GLUE_REFRESH);
    }

    #[test]
    fn restart_uses_canonical_seven_eighths_unit_split() {
        // Match the LZMA SDK Ppmd7 layout: unit region = 7/8 of size,
        // text region = 1/8. Concretely, on a 1024-byte arena the
        // working size is 1008 bytes (1024 - 4 align - 12 tail), and
        // (1008 / 96) * 7 * 12 = 840 bytes belong to the unit region.
        let a = Allocator::new(1024).expect("alloc");
        assert_eq!(a.size(), 1008);
        let unit_region = a.hi_unit() - a.lo_unit();
        assert_eq!(unit_region, 840, "unit region should be 7/8 of size");
        // text starts pinned at align_offset (the post-alignment-pad position).
        assert_eq!(a.text(), 4);
        assert_eq!(a.units_start(), a.lo_unit());
    }

    #[test]
    fn restart_keeps_room_for_initial_model_allocations() {
        // A 2 KiB arena (the canonical PPMD7_MIN_MEM_SIZE) must hold
        // the model's initial 129-unit (1548-byte) working set:
        //   1× root context (HiUnit -= 12 bytes)
        // + 128 units (1536 bytes) of state array (LoUnit += 128*12).
        let a = Allocator::new(2048).expect("alloc");
        let unit_region = a.hi_unit() - a.lo_unit();
        assert!(
            unit_region >= 1548,
            "unit region {unit_region} bytes should hold 129-unit \
             initial allocations on 2 KiB arena"
        );
    }

    #[test]
    fn write_text_byte_advances_text_high_water_mark() {
        let mut a = Allocator::new(BIG_ARENA_BYTES).expect("alloc");
        let initial_text = a.text();
        let pos = a.write_text_byte(0xAA);
        assert_eq!(pos, initial_text);
        assert_eq!(a.text(), initial_text + 1);
        assert_eq!(a.read_byte(pos), 0xAA);
        // Second write lands at the next position.
        let pos2 = a.write_text_byte(0x55);
        assert_eq!(pos2, initial_text + 1);
        assert_eq!(a.read_byte(pos2), 0x55);
        assert_eq!(a.text(), initial_text + 2);
    }

    #[test]
    fn dec_text_rolls_back_one_byte() {
        let mut a = Allocator::new(BIG_ARENA_BYTES).expect("alloc");
        let initial = a.text();
        a.write_text_byte(0xCC);
        a.dec_text();
        assert_eq!(a.text(), initial);
        // The byte itself is still in the arena; dec_text only adjusts
        // the high-water mark. The next write overwrites it.
        let pos = a.write_text_byte(0xDD);
        assert_eq!(pos, initial);
        assert_eq!(a.read_byte(pos), 0xDD);
    }

    /// Drain `lo_unit..hi_unit` by alternating 1-unit allocations
    /// from the bottom and from the top until the gap closes.
    fn drain_to_full(a: &mut Allocator) {
        // Burn through the central gap with 1-unit allocations.
        // Both alloc_context (top-down) and alloc_units(0)
        // (bottom-up) consume one unit each.
        loop {
            if a.lo_unit() == a.hi_unit() {
                break;
            }
            // Use whichever side has room; prefer top so we don't
            // accidentally trip the freelist[0] path.
            if a.alloc_context().is_some() {
                continue;
            }
            if a.alloc_units(0).is_some() {
                continue;
            }
            break;
        }
    }
}
