//! xz / LZMA streaming decoder ([XZ file format]).
//!
//! Phase 7 of `docs/PLAN_xz_block_decoder.md` swapped the old
//! `xz2`/liblzma binding wrapper out for the hand-rolled,
//! pure-Rust implementation in [`super::xz_native`]. This file
//! is now a thin re-export so [`crate::decode::xz::factory`] and
//! [`crate::decode::xz::resume_factory`] resolve to the new
//! implementations without forcing every external caller to
//! migrate to the `xz_native::` path.
//!
//! See [`super::xz_native`] for the implementation, the wire-
//! format coverage, and the resume contract. The plan's exit
//! criterion for Phase 7 is "the `xz2` crate is no longer a
//! *runtime* dependency for our decode path"; that is now true.
//! `xz2` remains as a `[dev-dependencies]` entry for the
//! differential test suite in `tests/test_xz_native.rs` only.
//!
//! [XZ file format]: https://tukaani.org/xz/xz-file-format.txt

pub use super::xz_native::factory;
pub use super::xz_native::resume_factory;
pub use super::xz_native::Decoder;

/// Public alias matching the pre-Phase-7 spelling so existing
/// callers that name the type by `xz::XzDecoder` keep working.
pub use Decoder as XzDecoder;
