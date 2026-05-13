//! 7z archive support.
//!
//! The 7z format is the closest architectural sibling to ZIP among
//! the formats `peel` already supports — metadata lives at the tail,
//! the streaming pipeline ([`crate::decode`]) cannot be used
//! directly, and a separate "second-pipeline" driver
//! (`internal/PLAN_v2.md` §5 / `internal/PLAN_7z_support.md` §8) is the
//! right shape. It also inherits ZIP's "many compression methods,
//! scope what we ship" discipline.
//!
//! 7z is, however, *not* a clone of ZIP — it has solid compression
//! (a `Folder` groups multiple files into one decoded stream),
//! coder chains (e.g. LZMA → BCJ → ...), commonly compressed
//! headers ("EncodedHeader"), and no formal RFC. See
//! `internal/PLAN_7z_support.md` for the full design and the
//! round-one feature list.
//!
//! # Layout
//!
//! - [`error`] — typed errors shared across the parser, the
//!   `decode::sevenz` runtime, and the
//!   `download::sevenz_pipeline` driver.
//!
//! Subsequent phases add the wire-format header parser, the
//! `FilesInfo`/`StreamsInfo` model, and the second-pipeline
//! driver under `decode::sevenz` and `download::sevenz_pipeline`.
//!
//! # Round-one scope
//!
//! See `internal/PLAN_7z_support.md` §"What round-one deliberately
//! does *not* include" for the full list. The summary:
//!
//! - **Supported coders**: `COPY`, `DEFLATE`, `LZMA`, `LZMA2`.
//! - **Supported headers**: plain `Header` and unencrypted
//!   `EncodedHeader`.
//! - **Single-volume archives only** (`.7z`, not `.7z.001`).
//! - **One-folder-at-a-time resume**: a kill mid-folder restarts
//!   that folder from the start of its packed range.
//!
//! Encountering a deferred feature returns a clean
//! [`SevenzError::UnsupportedFeature`] naming the specific feature
//! (`"BCJ filter"`, `"AES-256 encryption"`, etc.).

pub mod error;

pub use error::SevenzError;

use std::io::Read;

use crate::decode::{DecodeError, StreamingDecoder};

/// Format name [`crate::decode::DecoderRegistry::with_defaults`]
/// registers 7z under (`internal/PLAN_7z_support.md` §10). The
/// coordinator pre-checks the resolved factory against this
/// constant and dispatches to
/// [`crate::download::sevenz_pipeline`] instead of invoking the
/// streaming decoder loop.
pub const FORMAT_NAME: &str = "7z";

/// Sentinel [`crate::decode::DecoderFactory`] registered for
/// the [`FORMAT_NAME`] format.
///
/// 7z archives go through
/// [`crate::download::sevenz_pipeline`], not the streaming-
/// decoder loop, so this factory is **never invoked in normal
/// operation**. It exists so the standard
/// [`crate::decode::DecoderRegistry`] machinery (suffix
/// matching, magic-byte sniffing, `--format <name>` override,
/// format-mismatch detection) resolves `.7z` URLs the same way
/// it resolves any other format. The coordinator pre-checks
/// the resolved name against [`FORMAT_NAME`] and dispatches
/// before invoking the factory; this body is reached only by a
/// programming error and surfaces a clear diagnostic.
///
/// # Errors
///
/// Always returns [`DecodeError::Construct`] with an
/// explanatory message.
pub fn streaming_factory_placeholder(
    _src: Box<dyn Read + Send>,
) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
    Err(DecodeError::Construct(std::io::Error::other(
        "internal error: 7z factory invoked instead of dispatching to the 7z pipeline",
    )))
}

/// SignatureHeader magic that begins every 7z archive: `7z¼¯' \x1c`
/// in ASCII view, `37 7A BC AF 27 1C` in hex. Defined here (rather
/// than in `decode::sevenz::format`) so the
/// [`crate::decode::DecoderRegistry`] entry registered in §10 has
/// a stable crate-level constant to reference.
pub const SIGNATURE_MAGIC: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
