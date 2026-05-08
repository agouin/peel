//! xz / LZMA streaming decoder ([XZ file format]).
//!
//! Phase F.6 of `docs/PLAN_xz_liblzma_phase_f.md` swapped the
//! production xz path from the original hand-rolled
//! `xz_native` decoder over to the structural port at
//! [`super::xz_liblzma`]. This module is a thin re-export so
//! `crate::decode::xz::factory` and `crate::decode::xz::resume_factory`
//! resolve to the new implementations without forcing every
//! external caller to migrate to the `xz_liblzma::` path.
//!
//! See [`super::xz_liblzma`] for the implementation, the wire-
//! format coverage (single-Block, multi-Block, multi-Stream),
//! the per-LZMA2-chunk frame-boundary contract, and the
//! checkpoint blob format (`PLZM` v1).
//!
//! [XZ file format]: https://tukaani.org/xz/xz-file-format.txt

pub use super::xz_liblzma::factory;
pub use super::xz_liblzma::resume_factory;
pub use super::xz_liblzma::Decoder;

/// Public alias matching the pre-port spelling so existing
/// callers that name the type by `xz::XzDecoder` keep working.
pub use Decoder as XzDecoder;
