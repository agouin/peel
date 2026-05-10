//! PPMd-II decoder.
//!
//! Hand-rolled implementation of the PPMd "version II" variant
//! (a.k.a. PPMd7 in the LZMA SDK), the algorithm used by:
//!
//! - **Legacy RAR (RAR3 / RAR4)** for `m=4` and `m=5` entries
//!   — the first consumer of this module (`docs/PLAN_rar3.md` §B).
//! - **7z** for the PPMd method (today surfaced as
//!   [`crate::sevenz::SevenzError::UnsupportedMethod`]; once §B
//!   stabilises, the 7z pipeline can wire the same decoder in).
//! - Hypothetical PPMd-encoded RAR5 archives (`O.RAR.PPM5`
//!   follow-on; the spec reserves the slot but no encoder emits
//!   them today).
//!
//! Sibling of [`crate::decode::rar_native`]; the two share nothing
//! algorithmically (RAR5 dropped PPMd) but live next to each other
//! because the RAR pipeline dispatches between them per entry.
//!
//! # Round-one phasing (`docs/PLAN_rar3.md` §B)
//!
//! 1. **§B0** — range coder ([`range_dec`]). Bit-level entropy
//!    primitive every layer above depends on. Self-contained,
//!    round-trippable against a test-only sister encoder.
//! 2. **§B1** — sub-allocator (next). Custom slab allocator the
//!    PPMd model uses for its variable-order context tree.
//! 3. **§B2** — context tree + symbol-decode loop. Bulk of the
//!    algorithm.
//! 4. **§B3** — differential cross-check against `unrar`-produced
//!    fixtures.
//!
//! Each phase ends with a runnable demo / passing test before the
//! next one begins, mirroring the `PLAN_rar5_decoder.md` discipline.

#[cfg(feature = "rar")]
pub mod range_dec;

#[cfg(feature = "rar")]
pub use range_dec::{RangeDecoder, RangeDecoderError};
