//! 7z decoder runtime.
//!
//! Sibling to [`crate::sevenz`] (which holds the crate-level public
//! surface — errors, format-name constant, magic). This module
//! holds the actually-running parsers and decoders that the
//! second-pipeline driver in `crate::download::sevenz_pipeline`
//! will plug into.
//!
//! # Phase 1 (`docs/PLAN_7z_support.md` §1)
//!
//! Wire-format primitive parsers live in [`number`]: the
//! variable-length unsigned integer ([`number::parse_number`]),
//! bit-vectors ([`number::parse_bool_vector`]), property-id tags
//! ([`number::parse_propid`]), and zero-terminated UTF-16LE names
//! with anti-traversal sanitization
//! ([`number::read_name_utf16le_zero_terminated`]). Every later
//! phase composes these primitives — getting them right once,
//! with property tests, beats catching off-by-ones in §3 / §4.
//!
//! # Phase 2 (`docs/PLAN_7z_support.md` §2)
//!
//! [`format`] holds the fixed 32-byte
//! [`format::parse_signature_header`] that reads the
//! [`format::SignatureHeader`] every 7z archive begins with —
//! magic, ArchiveVersion, StartHeaderCRC validation, and the
//! trailer location the §8 pipeline drives the next ranged GET
//! against.

pub mod format;
pub mod number;
