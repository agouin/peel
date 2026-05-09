//! RAR5 archive support.
//!
//! Implementation tracks `docs/PLAN_rar.md`. Round-one ships in
//! phases:
//!
//! 1. **§1** — wire-format scaffolding: hand-rolled vint codec,
//!    generic-header layout, main / file / service / end-of-archive
//!    parsers. Lives in [`format`]. Validates §0 decisions cheaply
//!    (solid-mode detection, multi-volume detection, RAR4 rejection,
//!    unsupported-feature surfacing) before any decompressor LOC is
//!    written.
//! 2. **§2** — BLAKE2sp (RAR5's parallel-BLAKE2s file-data
//!    integrity hash) lands as a sibling of the existing SHA-256
//!    in [`crate::hash`].
//! 3. **§3** — STORED-method (`m=0`) extraction: per-entry sink, the
//!    RAR pipeline, the [`crate::checkpoint::Checkpoint`] state
//!    field, and feature-gated CLI dispatch. STORED is uncompressed
//!    so this phase exercises the full plumbing without touching the
//!    decoder.
//! 4. **§4** — hand-rolled RAR5 decoder (LZSS + PPMd-II + filters)
//!    per `docs/PLAN_rar5_decoder.md` (the §0.1 hand-roll resolution
//!    spawned a sibling sub-plan modeled on
//!    `PLAN_zstd_block_decoder.md`).
//!
//! Like ZIP and 7z, the bytes for a RAR archive do not flow through
//! the streaming-decoder loop in [`crate::decode`]. The archive
//! begins with a generic header at offset 0 and is laid out as a
//! sequence of headers with optional data areas; a per-entry
//! pipeline (lands in §3 as `crate::download::rar_pipeline`) drives
//! the per-entry download + decompress + sink loop. The factory
//! registered against [`FORMAT_NAME`] is therefore a sentinel —
//! invoking it directly is a programming error — and the
//! coordinator is responsible for dispatching to the pipeline by
//! name.
//!
//! # Round-one scope (`docs/PLAN_rar.md` §0, locked 2026-05-09)
//!
//! Supported:
//!
//! - RAR5 archives only (8-byte magic `52 61 72 21 1A 07 01 00`).
//! - Compression methods: STORED (method = 0) in §3; the standard
//!   RAR5 algorithm (method ≥ 1) lands in §4.
//! - Solid mode (`MHD_SOLID`): handled by single-stream sequential
//!   decoding inside the pipeline (§0.2). Download stays parallel.
//! - Single-volume archives.
//!
//! Out of scope (each surfaces a specific
//! [`RarError::UnsupportedFeature`] message rather than a generic
//! parse failure):
//!
//! - **RAR4** (legacy, pre-2013). The 7-byte RAR4 magic is detected
//!   at parse time and surfaces [`RarError::UnsupportedFormatVersion`]
//!   with `major: 4, minor: 0`. Filed as `O.RAR4`.
//! - **Multi-volume archives** (`MHD_VOLUME`). The header parser
//!   decodes the volume number from the main archive header so the
//!   diagnostic can name it. Filed as `O.RAR.MV`.
//! - **Encryption** (header type 4 or per-file encryption flags).
//!   Filed as `O.RAR.ENC`.
//! - **Self-extracting archives** (executable prefix in front of the
//!   magic). Round-one's magic detector does not scan past offset 0;
//!   SFX archives need `--format rar`. Filed as `O.RAR.SFX`.
//! - **Recovery records** (Reed-Solomon). Skipped silently if
//!   present; validation filed as `O.RAR.RECOVERY`.
//!
//! # Build-time feature flag
//!
//! The whole module is gated behind the `rar` Cargo feature (on by
//! default). Building `--no-default-features` produces a binary
//! that:
//!
//! - Does not compile [`format`] or any of the §3+ pipeline modules.
//! - Still exports [`FORMAT_NAME`], [`SIGNATURE_MAGIC`], and
//!   [`streaming_factory_placeholder`], which
//!   [`crate::decode::DecoderRegistry::with_defaults`] uses to
//!   register `.rar` and the RAR5 magic. The factory then surfaces a
//!   precise "compiled without `rar` feature" diagnostic instead of
//!   "unknown format".
//!
//! See `docs/PLAN_rar.md` §0.5 for the rationale.

#[cfg(feature = "rar")]
pub mod archive;
#[cfg(feature = "rar")]
pub mod error;
#[cfg(feature = "rar")]
pub mod format;

#[cfg(feature = "rar")]
pub use archive::{walk_archive, ArchiveSummary, FileEntry};
#[cfg(feature = "rar")]
pub use error::RarError;
#[cfg(feature = "rar")]
pub use format::{
    parse_generic_header, parse_main_archive_header, ArchiveFlags, FileFlags, GenericHeader,
    HeaderType, MainArchiveHeader, Vint,
};

use std::io::Read;

use crate::decode::{DecodeError, StreamingDecoder};

/// Format name [`crate::decode::DecoderRegistry::with_defaults`]
/// registers RAR under (`docs/PLAN_rar.md` §1). The coordinator
/// pre-checks the resolved factory against this constant and
/// (post-§3) dispatches to `crate::download::rar_pipeline` instead
/// of invoking the streaming decoder loop.
pub const FORMAT_NAME: &str = "rar";

/// 8-byte RAR5 magic at offset 0 of every RAR5 archive: ASCII
/// `Rar!\x1A\x07\x01\x00`.
///
/// RAR4's magic is the same first six bytes (`Rar!\x1A\x07`)
/// followed by `0x00` (one byte instead of two). The §0.3 resolution
/// is to register only the RAR5 magic in
/// [`crate::decode::DecoderRegistry`]; archives whose URL ends
/// `.rar` but whose bytes are RAR4 reach the format-level parser by
/// way of the suffix path and surface a precise
/// [`RarError::UnsupportedFormatVersion`].
pub const SIGNATURE_MAGIC: [u8; 8] = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00];

/// Sentinel [`crate::decode::DecoderFactory`] registered for the
/// [`FORMAT_NAME`] format.
///
/// RAR archives go through `crate::download::rar_pipeline` (lands
/// in §3), not the streaming-decoder loop, so this factory is
/// **never invoked in normal operation**. It exists so the standard
/// [`crate::decode::DecoderRegistry`] machinery (suffix matching,
/// magic-byte sniffing, `--format <name>` override, format-mismatch
/// detection) resolves `.rar` URLs the same way it resolves any
/// other format. The coordinator pre-checks the resolved name
/// against [`FORMAT_NAME`] and dispatches before invoking the
/// factory; this body is reached only by a programming error
/// (caller used [`crate::decode::DecoderRegistry`] outside the
/// coordinator path) and surfaces a clear diagnostic.
///
/// When the `rar` Cargo feature is **disabled**, this factory's
/// body is the user-facing diagnostic for `.rar` URLs: rather than
/// "unknown format" they see "this build of `peel` was compiled
/// without the `rar` feature; rebuild with default features (or
/// `--features rar`) to extract RAR archives." See `docs/PLAN_rar.md`
/// §0.5.
///
/// # Errors
///
/// Always returns [`DecodeError::Construct`]. The wrapped message
/// distinguishes the two reachable paths (feature-disabled vs.
/// programmer-error inside a feature-enabled build).
pub fn streaming_factory_placeholder(
    _src: Box<dyn Read + Send>,
) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    #[cfg(feature = "rar")]
    {
        Err(DecodeError::Construct(std::io::Error::other(
            "internal error: RAR factory invoked instead of dispatching to the RAR pipeline",
        )))
    }
    #[cfg(not(feature = "rar"))]
    {
        Err(DecodeError::Construct(std::io::Error::other(
            "this build of `peel` was compiled without the `rar` feature; \
             rebuild with default features (or `--features rar`) to extract RAR archives",
        )))
    }
}
