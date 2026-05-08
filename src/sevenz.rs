//! 7z archive support.
//!
//! The 7z format is the closest architectural sibling to ZIP among
//! the formats `peel` already supports — metadata lives at the tail,
//! the streaming pipeline ([`crate::decode`]) cannot be used
//! directly, and a separate "second-pipeline" driver
//! (`docs/PLAN_v2.md` §5 / `docs/PLAN_7z_support.md` §8) is the
//! right shape. It also inherits ZIP's "many compression methods,
//! scope what we ship" discipline.
//!
//! 7z is, however, *not* a clone of ZIP — it has solid compression
//! (a `Folder` groups multiple files into one decoded stream),
//! coder chains (e.g. LZMA → BCJ → ...), commonly compressed
//! headers ("EncodedHeader"), and no formal RFC. See
//! `docs/PLAN_7z_support.md` for the full design and the
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
//! See `docs/PLAN_7z_support.md` §"What round-one deliberately
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

/// Format name [`crate::decode::DecoderRegistry::with_defaults`]
/// will register 7z under once §10 of `docs/PLAN_7z_support.md`
/// lands. Defined now so earlier phases that introduce parsers can
/// reference the canonical name without forward-declaring it.
pub const FORMAT_NAME: &str = "7z";

/// SignatureHeader magic that begins every 7z archive: `7z¼¯' \x1c`
/// in ASCII view, `37 7A BC AF 27 1C` in hex. Defined here (rather
/// than in `decode::sevenz::format`) so the
/// [`crate::decode::DecoderRegistry`] entry registered in §10 has
/// a stable crate-level constant to reference.
pub const SIGNATURE_MAGIC: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
