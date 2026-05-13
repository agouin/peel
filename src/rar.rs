//! RAR5 archive support.
//!
//! Implementation tracks `internal/PLAN_rar.md`. Round-one ships in
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
//!    per `internal/PLAN_rar5_decoder.md` (the §0.1 hand-roll resolution
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
//! # Round-one scope (`internal/PLAN_rar.md` §0, locked 2026-05-09)
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
//! See `internal/PLAN_rar.md` §0.5 for the rationale.

#[cfg(feature = "rar")]
pub mod archive;
#[cfg(feature = "rar")]
pub mod encrypt;
#[cfg(feature = "rar")]
pub mod error;
#[cfg(feature = "rar")]
pub mod format;
/// Legacy (RAR3 / RAR4) format support — sibling of [`format`].
///
/// Phase A1 of `internal/PLAN_rar3.md` lands the wire-format parser
/// here. Pipeline dispatch (`parse_signature` enum, walker
/// integration) follows in §A2; the decoder generations land in
/// §B / §C.
#[cfg(feature = "rar")]
pub mod legacy;

#[cfg(feature = "rar")]
pub use archive::{walk_archive, ArchiveSummary, FileEntry};
#[cfg(feature = "rar")]
pub use error::RarError;
#[cfg(feature = "rar")]
pub use format::{
    parse_generic_header, parse_main_archive_header, ArchiveFlags, FileFlags, GenericHeader,
    HeaderType, MainArchiveHeader, Vint,
};
#[cfg(feature = "rar")]
pub use legacy::format::LEGACY_SIGNATURE_MAGIC;

use std::io::Read;

use crate::decode::{DecodeError, StreamingDecoder};

/// Format name [`crate::decode::DecoderRegistry::with_defaults`]
/// registers RAR under (`internal/PLAN_rar.md` §1). The coordinator
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

/// Which on-disk RAR archive format begins at offset 0 of the input
/// buffer. Returned by [`detect_signature`].
///
/// The two formats share the leading six bytes (`Rar!\x1A\x07`) and
/// diverge at byte 6: legacy is a single zero byte (7-byte magic);
/// RAR5 is `0x01 0x00` (8-byte magic). Pipeline integration in
/// `internal/PLAN_rar3.md` §A2 dispatches on this enum.
#[cfg(feature = "rar")]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SignatureKind {
    /// 8-byte RAR5 magic ([`SIGNATURE_MAGIC`]).
    Rar5,
    /// 7-byte legacy magic ([`LEGACY_SIGNATURE_MAGIC`]) — RAR3 / RAR4
    /// archive (WinRAR 1.5–4.x).
    Legacy,
}

/// Detect the RAR archive format at the start of `buf` and return the
/// [`SignatureKind`] together with the number of bytes the signature
/// occupies (`7` for legacy, `8` for RAR5).
///
/// `buf` must start at the very beginning of the archive (byte 0).
///
/// # Errors
///
/// - [`RarError::Truncated`] if `buf` is shorter than 7 bytes (the
///   minimum required to disambiguate legacy from RAR5).
/// - [`RarError::BadSignature`] if the leading bytes match neither
///   format.
#[cfg(feature = "rar")]
pub fn detect_signature(buf: &[u8]) -> Result<(SignatureKind, usize), RarError> {
    // The first six bytes (`Rar!\x1A\x07`) are common; the
    // discriminator byte at offset 6 is `0x00` for legacy and
    // `0x01` for RAR5. A RAR5 signature requires one further byte
    // at offset 7 (the trailing `0x00`).
    if buf.len() < legacy::format::LEGACY_SIGNATURE_MAGIC.len() {
        return Err(RarError::Truncated {
            what: "RAR magic (need ≥ 7 bytes to disambiguate legacy vs RAR5)".to_string(),
            needed: legacy::format::LEGACY_SIGNATURE_MAGIC.len() - buf.len(),
        });
    }
    if buf[..legacy::format::LEGACY_SIGNATURE_MAGIC.len()] == legacy::format::LEGACY_SIGNATURE_MAGIC
    {
        return Ok((
            SignatureKind::Legacy,
            legacy::format::LEGACY_SIGNATURE_MAGIC.len(),
        ));
    }
    if buf.len() < SIGNATURE_MAGIC.len() {
        return Err(RarError::Truncated {
            what: "RAR5 magic (8 bytes)".to_string(),
            needed: SIGNATURE_MAGIC.len() - buf.len(),
        });
    }
    if buf[..SIGNATURE_MAGIC.len()] == SIGNATURE_MAGIC {
        Ok((SignatureKind::Rar5, SIGNATURE_MAGIC.len()))
    } else {
        Err(RarError::BadSignature)
    }
}

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
/// `--features rar`) to extract RAR archives." See `internal/PLAN_rar.md`
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

#[cfg(all(test, feature = "rar"))]
mod tests {
    use super::*;

    #[test]
    fn detect_signature_recognizes_rar5() {
        let (kind, size) = detect_signature(&SIGNATURE_MAGIC).expect("detects");
        assert_eq!(kind, SignatureKind::Rar5);
        assert_eq!(size, 8);
    }

    #[test]
    fn detect_signature_recognizes_legacy() {
        let (kind, size) = detect_signature(&LEGACY_SIGNATURE_MAGIC).expect("detects");
        assert_eq!(kind, SignatureKind::Legacy);
        assert_eq!(size, 7);
    }

    #[test]
    fn detect_signature_rejects_garbage() {
        assert!(matches!(
            detect_signature(b"hello!!!").unwrap_err(),
            RarError::BadSignature
        ));
    }

    #[test]
    fn detect_signature_truncated_below_seven() {
        let err = detect_signature(b"Rar!").unwrap_err();
        assert!(matches!(err, RarError::Truncated { needed: 3, .. }));
    }

    #[test]
    fn detect_signature_truncated_between_seven_and_eight() {
        // Leading 7 bytes look RAR5-y (last byte 0x01), so we need
        // to read byte 7 to disambiguate. Buffer is 7 bytes.
        let buf: [u8; 7] = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01];
        let err = detect_signature(&buf).unwrap_err();
        assert!(matches!(err, RarError::Truncated { needed: 1, .. }));
    }

    #[test]
    fn detect_signature_eight_byte_legacy_takes_legacy_branch() {
        // Trailing byte after the 7-byte legacy magic is irrelevant —
        // the dispatcher returns `Legacy, 7` regardless.
        let buf: [u8; 8] = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00, 0xFF];
        let (kind, size) = detect_signature(&buf).expect("detects");
        assert_eq!(kind, SignatureKind::Legacy);
        assert_eq!(size, 7);
    }
}
