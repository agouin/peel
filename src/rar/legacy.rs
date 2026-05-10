//! Legacy (RAR3 / RAR4) archive support.
//!
//! Implementation tracks `docs/PLAN_rar3.md`. The legacy archive
//! format is the on-disk container shipped by WinRAR 1.5–4.x; RARLAB
//! calls it "RAR 4 archive format", third-party readers more often
//! call it "RAR3", and the wire-format discriminator is the 7-byte
//! magic `Rar!\x1A\x07\x00` at offset 0 (vs. RAR5's 8-byte
//! `Rar!\x1A\x07\x01\x00`). The two formats share nothing structural
//! beyond the leading six magic bytes.
//!
//! # Round-one scope (`docs/PLAN_rar3.md` §0, locked 2026-05-10)
//!
//! Supported:
//!
//! - Legacy archives whose file headers report `unp_ver ∈ [29, 36]`
//!   (the WinRAR 2.9 / 3.x / 4.x compression-algorithm family —
//!   they share a single decoder).
//! - Compression methods `0x30`..`0x35` (`m=0`..`m=5`) gated by the
//!   per-version decoders that land in §B and §C of the plan.
//! - Solid mode (`MHD_SOLID`): handled by the same single-stream
//!   serial driver the RAR5 path uses; `rar_pipeline` learns to
//!   dispatch on signature in §A2.
//! - Single-volume archives.
//!
//! Out of scope (each surfaces a specific
//! [`crate::rar::RarError::UnsupportedFeature`] message rather than
//! a generic parse failure):
//!
//! - **Pre-2.9 algorithms** (`unp_ver < 29`). Filed as conditional
//!   §D in `docs/PLAN_rar3.md`. Pre-1.5 archives (no fixed magic)
//!   are filed as `O.RAR.LEGACY15` and never reach this module.
//! - **Multi-volume archives** (`MHD_VOLUME`). Surfaced from the
//!   `MAIN_HEAD` parser the same way the RAR5 path does (filed as
//!   `O.RAR.MV`).
//! - **Encryption** (`MHD_PASSWORD` / per-file `LHD_PASSWORD`).
//!   Filed as `O.RAR.ENC`.
//! - **Self-extracting archives**. Round-one's magic detector does
//!   not scan past offset 0; SFX archives need `--format rar`
//!   (filed as `O.RAR.SFX`).
//! - **Recovery records** (`PROTECT_HEAD` / `NEWSUB_HEAD` "RR"
//!   subtype). Skipped silently if present.
//!
//! # Build-time feature flag
//!
//! Lives behind the same `rar` Cargo feature as the RAR5 module —
//! one feature, both formats, no separate flag.

#[cfg(feature = "rar")]
pub mod format;

#[cfg(feature = "rar")]
pub use format::{
    parse_endarc_header, parse_file_header, parse_generic_header, parse_main_archive_header,
    parse_signature, BaseBlock, BlockType, EndarcFlags, EndarcHeader, FileFlags, FileHeader,
    MainArchiveFlags, MainArchiveHeader, LEGACY_SIGNATURE_MAGIC, MAX_SUPPORTED_UNP_VER,
    MIN_SUPPORTED_UNP_VER,
};
