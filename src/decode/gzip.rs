//! gzip streaming decoder (RFC 1952).
//!
//! Phase 8 of `docs/PLAN_deflate_block_decoder.md` swapped the old
//! `flate2` / `miniz_oxide` wrapper out for the hand-rolled,
//! pure-Rust implementation in [`super::deflate_native::gzip`].
//! This file is now a thin re-export so
//! [`crate::decode::gzip::factory`] and
//! [`crate::decode::gzip::resume_factory`] resolve to the new
//! implementations without forcing every external caller to
//! migrate to the `deflate_native::` path.
//!
//! See [`super::deflate_native::gzip`] for the implementation,
//! the wire-format coverage, and the resume contract. Phase 8's
//! exit criterion is "`flate2` is no longer a *runtime* dependency
//! of the streaming-pipeline gzip path"; that is now true. The
//! `flate2` crate stays in `[dependencies]` for the moment because
//! the zip-DEFLATE pipeline (`src/zip/decode.rs`) still uses it;
//! Phase 9 swaps that too.

pub use super::deflate_native::gzip::factory;
pub use super::deflate_native::gzip::resume_factory;
pub use super::deflate_native::gzip::GzipDecoder;
