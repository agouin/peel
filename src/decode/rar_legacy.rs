//! Hand-rolled legacy RAR (RAR3 / RAR4) decompression pipeline.
//!
//! Sibling of [`crate::decode::rar_native`] (RAR5 algorithm) and
//! [`crate::decode::ppmd2`] (PPMd-II model). Round-one scope is
//! locked in `docs/PLAN_rar3.md` §0: `unp_ver ∈ [29, 36]` (the
//! WinRAR 2.9 / 3.x / 4.x algorithm family — one decoder for the
//! three generations). Pre-2.9 archives surface
//! [`crate::rar::RarError::UnsupportedFeature`] at parse time per
//! §A2's walker.
//!
//! # Layering (`docs/PLAN_rar3.md` §C)
//!
//! Submodules land one per sub-phase, mirroring the §B
//! discipline. Empty for now (§C0 scaffolds; first real
//! submodule lands in §C1a):
//!
//! - **§C0** ✅ — sub-phasing + this module entry.
//! - **§C1a** ✅ — [`bits`]: MSB-first bitstream reader with
//!   byte-alignment for block boundaries (libarchive's
//!   `rar_br_consume_unaligned_bits` equivalent).
//! - **§C1b** ✅ — [`huffman`] + [`bootstrap`]: canonical Huffman
//!   builder (15-bit max, flat-lookup table) and per-block
//!   bootstrap (20-entry precode → 404-entry main length table →
//!   four canonical sub-trees for `MAIN_CODE_SIZE` = 299,
//!   `OFFSET_CODE_SIZE` = 60, `LOW_OFFSET_CODE_SIZE` = 17,
//!   `LENGTH_CODE_SIZE` = 28).
//! - **§C1c** ✅ — [`block_header`]: byte-aligned per-block
//!   prologue parser; routes LZ vs. PPMd modes and surfaces the
//!   `keep_old_tables` flag plus the PPMd dictionary / max-order
//!   / init-escape payload.
//! - **§C1d** ✅ — [`dict`] + [`dist_cache`]: sliding-window
//!   dictionary (4 MiB cap, ring buffer with overlap-by-design
//!   match copy + recent-window read for the filter VM) plus the
//!   4-slot LRU of recent match offsets RAR3 keeps for symbols
//!   `259..=262`.
//! - **§C1e₁** ✅ — [`lzss`]: per-symbol dispatcher
//!   (`LzDecoder::decode_block`) for one block, with the
//!   libarchive constant tables inlined. Synthetic-fixture
//!   tests cover every main-code branch.
//! - **§C1e₂** — first end-to-end LZ demo against the ssokolow
//!   `testfile.rar3.rar` corpus + bundled `unrar` cross-check.
//! - **§C1f** ✅ — RAR-variant range coder added to
//!   [`crate::decode::ppmd2::range_dec`] (not in this tree).
//! - **§C1g** ✅ — [`ppmd_entry`]: `PpmdSession` wraps
//!   [`crate::decode::ppmd2::Model`] for the PPMd-mode dispatch
//!   loop libarchive runs at `read_data_compressed` lines
//!   2158..=2238 — literals + escape sub-codes for EOD / large
//!   LZ match (code 4) / short LZ match (code 5) / escape-of-
//!   escape literals.
//! - **§C1h** — `solid`: solid-mode driver + multi-block
//!   continuation across entries.
//! - **§C2a** — `vm::filters`: standard filter set
//!   (e8/e9/itanium/rgb/audio/delta) via the `VM_STANDARD_FILTERS`
//!   shortcut encoding.
//! - **§C2b** — `vm::interp`: archive-supplied bytecode interpreter
//!   with strict per-reference bounds checking.
//! - **§C2c** — fuzz harness + custom-filter differential corpus.
//!
//! # Reuse-vs-fork posture
//!
//! Sibling modules; no `pub use` of anything from
//! [`crate::decode::rar_native`]. The two formats share a few
//! conventions (MSB-first bits, 4-deep distance cache) but differ
//! enough in detail (RAR3's bit alignment, four Huffman trees,
//! fixed-4-MiB dict) that sharing leaky generics is worse than the
//! duplication. Cross-module factoring, if it's worth doing, lands
//! as a separate clean-up commit after §C2 ships.
//!
//! # Build flag
//!
//! Same `rar` Cargo feature the rest of the RAR module tree uses —
//! no new feature surface. The `--no-default-features` build does
//! not compile this module.

pub mod bits;
pub mod block_header;
pub mod bootstrap;
pub mod dict;
pub mod dist_cache;
pub mod huffman;
pub mod lzss;
pub mod ppmd_entry;
