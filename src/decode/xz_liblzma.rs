//! Clean-room Rust port of liblzma's xz decoder, structurally
//! faithful.
//!
//! Phase 1 of [`docs/PLAN_xz_liblzma_port.md`](../../../docs/PLAN_xz_liblzma_port.md).
//! Sibling to [`super::xz_native`]: the existing decoder is the
//! production path; this module is an experimental sibling that
//! ports liblzma's giant-single-function decoder shape into Rust.
//!
//! # Why a parallel module
//!
//! [`PLAN_xz_liblzma_deep_dive.md`](../../../docs/PLAN_xz_liblzma_deep_dive.md)
//! Phase A documented liblzma's hot-loop register discipline and
//! attributed peel's 1.5× per-byte gap to per-bit memory-store
//! costs that liblzma's compiled output avoids. Phase C of that
//! plan tested whether a struct-shape change ("LocalRc"
//! stack-staging) inside the existing decoder could close the
//! gap; it could not. The diagnosis was that closing the gap
//! requires the same overall function shape liblzma uses — a
//! single dispatch loop where the rc state, dict pointer, and
//! prob-base pointer all stay register-resident across thousands
//! of expansion sites. That shape is incompatible with the
//! existing decoder's per-LZMA2-chunk dispatch boundary, which is
//! load-bearing for the checkpoint mechanism.
//!
//! Rather than refactor the production path, this plan builds a
//! parallel module that mirrors liblzma's shape without
//! checkpoint constraints. If Phase 4's bench gate clears, Phase F
//! adds checkpoint support back. If it doesn't clear, the
//! experiment is the deliverable: we've established the
//! architectural ceiling is genuinely past what struct-shape
//! changes alone can move.
//!
//! # `unsafe` posture
//!
//! Liberal — `unsafe` admitted wherever liblzma uses raw pointers,
//! with `// SAFETY:` comments on every block. The strict
//! ≥ 5 % microbench-gain gate from
//! [`PLAN_xz_decoder_optimization.md`](../../../docs/PLAN_xz_decoder_optimization.md)
//! is dropped; parity with liblzma is itself the perf
//! justification.
//!
//! # Round-one scope
//!
//! No checkpoint support, no resume blob, no public crate-API
//! integration. The module is wired into `pub mod` so its tests
//! and benches build, but it is not exposed via
//! [`crate::decode`]'s public surface.

pub mod decoder;
pub mod dict;
pub mod error;
pub mod range_coder;
