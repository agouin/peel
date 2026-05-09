//! Hand-rolled RAR5 standard-algorithm decoder.
//!
//! Implementation tracks `docs/PLAN_rar5_decoder.md`, the §4
//! sub-plan of `docs/PLAN_rar.md` that landed when §0.1 resolved
//! against the `unrar` C++ FFI on licensing grounds. Round-one of
//! `docs/PLAN_rar.md` (§§1–3) ships a STORED-method extractor that
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
//! - **Phase D** — PPMd-II range coder + model state for
//!   RAR5's opt-in alternate coding mode.
//! - **Phase E** — `RarStreamDecoder` that owns the bitstream +
//!   dict + filter VM + PPMd state and exposes the
//!   [`crate::decode::StreamingDecoder`] trait.
//! - **Phase F** — mid-entry serialize/deserialize for resume.
//! - **Phase G** — throughput.
//!
//! Each phase ends with a runnable demo per the plan; the module
//! re-export surface (below) is empty until Phase E lands the
//! decoder. Earlier phases publish their primitives as `pub mod`
//! children for tests to exercise but keep the runtime API
//! private until the integration phase wires them together.
//!
//! # Build flag
//!
//! Gated behind the `rar` Cargo feature alongside the rest of the
//! RAR5 module tree (`docs/PLAN_rar.md` §0.5). The `--no-default-features`
//! build does not compile this module.

pub mod bits;
pub mod bootstrap;
pub mod dict;
pub mod huffman;
