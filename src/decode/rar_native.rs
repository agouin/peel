//! Hand-rolled RAR5 standard-algorithm decoder.
//!
//! Implementation tracks `internal/PLAN_rar5_decoder.md`, the §4
//! sub-plan of `internal/PLAN_rar.md` that landed when §0.1 resolved
//! against the `unrar` C++ FFI on licensing grounds. Round-one of
//! `internal/PLAN_rar.md` (§§1–3) ships a STORED-method extractor that
//! drives the [`crate::sink::RarSink`] surface; this module adds
//! the standard RAR5 algorithm decoder so `compression
//! method = 1..5` entries flow through the same per-entry pipeline.
//!
//! # Layering (sub-plan phases)
//!
//! - **Phase A** — bitstream reader ([`bits`]) + Huffman decoder
//!   (lands in §A2).
//! - **Phase B** — sliding-window dictionary + LZSS block
//!   dispatcher.
//! - **Phase C** — RAR-VM filter bytecode interpreter for the
//!   standard filter set (e8/e9/itanium/rgb/audio/delta).
//! - **Phase E** — `RarStreamDecoder` that owns the bitstream +
//!   dict + filter VM and exposes the
//!   [`crate::decode::StreamingDecoder`] trait.
//! - **Phase F** — mid-entry serialize/deserialize for resume.
//! - **Phase G** — throughput.
//!
//! Each phase ends with a runnable demo per the plan; the
//! [`stream::RarStreamDecoder`] integration landed in §E1 and is
//! the runtime API the §3 RAR pipeline dispatches to for
//! `compression method != 0` entries. Phase A–C primitives stay
//! exposed as `pub mod` children for tests to exercise and for
//! §F1 resume to seed.
//!
//! # Build flag
//!
//! Gated behind the `rar` Cargo feature alongside the rest of the
//! RAR5 module tree (`internal/PLAN_rar.md` §0.5). The `--no-default-features`
//! build does not compile this module.

pub mod bits;
pub mod block_header;
pub mod bootstrap;
pub mod dict;
pub mod dist_cache;
pub mod distance;
pub mod filters;
pub mod huffman;
pub mod length;
pub mod lzss;
pub mod stream;

pub use stream::RarStreamDecoder;
