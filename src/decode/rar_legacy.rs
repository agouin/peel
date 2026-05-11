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
//! - **§C1b** — `huffman` + `bootstrap`: canonical Huffman builder
//!   and 4-tree code-length parser (literals 299, distances 60,
//!   lower-distance bits 17, repeats 28).
//! - **§C1c** — `block_header`: block-type discriminator and
//!   "tables present" / "use previous block's tables" flag.
//! - **§C1d** — `dict`: 4 MiB sliding-window dictionary with a
//!   4-deep recent-distance cache.
//! - **§C1e** — `lzss`: per-block decode dispatcher integrating
//!   §C1a–d. First end-to-end LZ demo against the ssokolow
//!   `testfile.rar3.rar` corpus.
//! - **§C1f** — RAR-variant range coder added to
//!   [`crate::decode::ppmd2::range_dec`] (not in this tree).
//! - **§C1g** — `ppmd_entry`: wire
//!   [`crate::decode::ppmd2::Model`] through the legacy per-entry
//!   pipeline for `m=4` / `m=5` entries.
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
