//! Legacy RAR (RAR3 / RAR4) RarVM — filter declaration parser +
//! standard filter set (DELTA / E8 / E8E9 / RGB / AUDIO).
//!
//! `docs/PLAN_rar3.md` §C2a deliverable. The LZ dispatcher
//! ([`super::lzss::LzDecoder::decode_block`]) surfaces symbol 257
//! as [`super::lzss::BlockEnd::FilterDecl`]; the caller is then
//! responsible for reading the filter declaration's flags + size
//! prefix + bytecode payload from the same [`super::bits::BitReader`]
//! and handing the payload to this module.
//!
//! The module is split into three pieces, mirroring the layout
//! libarchive's `archive_read_support_format_rar.c` carries out:
//!
//! - **[`membits`]** — memory-only MSB-first bit reader plus the
//!   `next_rarvm_number` 2-bit-tag width-encoded integer codec
//!   (libarchive lines 3596..3622). The codec is what the
//!   bytecode-internal stream uses to encode register values,
//!   block length, program length, and global-data length.
//! - **[`parse`]** — `read_filter_declaration_bytes` reads the
//!   on-wire `(flags, length-extension, bytecode)` triple
//!   straight out of the LZ bit reader (libarchive's `read_filter`
//!   at lines 3641..3688); `parse_filter_declaration` interprets
//!   the bytecode payload against an in-flight [`FilterStack`]
//!   (libarchive's `parse_filter` at lines 3258..3397). One
//!   declaration may either declare a fresh program (with
//!   embedded bytecode + optional static-data blob) or reference
//!   a previously-declared program by index.
//! - **[`standard`]** — the five WinRAR standard filter programs
//!   (DELTA / E8 / E8E9 / RGB / AUDIO) recognised by the
//!   libarchive-style `crc32(bytecode) | (len << 32)` fingerprint
//!   shortcut (libarchive's `execute_filter` switch at lines
//!   3876..3891) and the native executors for each. Unrecognised
//!   bytecode surfaces a precise error today and routes to §C2b's
//!   VM interpreter when that lands.
//!
//! # What §C2a does **not** include
//!
//! - Live wiring through [`super::entry::decode_entry`]. The
//!   filter stack + dispatch (LZ output → VM memory → filter →
//!   filtered output → LZ output) is the §C2b deliverable, since
//!   it depends on the full VM interpreter being ready for
//!   archive-supplied (non-standard) bytecode and on a corpus
//!   that exercises filters (`docs/PLAN_rar3.md` §C2a's corpus
//!   note: the ssokolow round-one corpus is all PPMd, and the
//!   bundled `rar 7.22` no longer creates legacy archives, so
//!   filter-using fixtures are sourced separately when §C2b is
//!   ready to consume them).
//! - The full VM bytecode interpreter for archive-supplied
//!   custom filter programs. That's §C2b — the standard-filter
//!   recognition shortcut handles the cases the encoder actually
//!   emits in practice (and matches what libarchive ships), but
//!   the spec allows custom bytecode and §C2b makes that
//!   reachable.
//!
//! # Reuse-vs-fork posture (`docs/PLAN_rar3.md` §C0)
//!
//! Sibling of [`crate::decode::rar_native::filters`] (RAR5
//! filter VM); no shared code. The two formats both ship DELTA
//! and x86-call rewriters, but the RAR3 algorithm differs from
//! RAR5's even where they look alike — DELTA in RAR3 writes
//! to a separate destination buffer where RAR5 deinterleaves in
//! place over the same buffer; E8 in RAR3 uses
//! `address < 0 ? address + filesize : address - currpos` where
//! RAR5 uses a sign-flip predicate. Cross-module factoring lands
//! as a separate clean-up commit after §C2c ships, if it lands
//! at all.

pub mod dispatch;
pub mod membits;
pub mod parse;
pub mod standard;

pub use dispatch::{apply_pending_filters_in_place, DispatchError};
pub use membits::{next_rarvm_number, MemBitReader, MEMBR_MAX_BITS_PER_READ};
pub use parse::{
    parse_filter_declaration, read_filter_declaration_bytes, FilterDeclaration, FilterStack,
    Program, ProgramClassification, RawFilterDecl, VmParseError, MAX_GLOBAL_DATA_LEN,
    MAX_PROGRAM_LENGTH, PROGRAM_GLOBAL_SIZE, PROGRAM_SYSTEM_GLOBAL_ADDRESS,
    PROGRAM_SYSTEM_GLOBAL_SIZE, PROGRAM_USER_GLOBAL_SIZE, PROGRAM_WORK_SIZE, VM_MEMORY_SIZE,
};
pub use standard::{
    execute_audio, execute_delta, execute_e8, execute_rgb, recognize_standard_filter,
    FilterExecError, StandardFilter, FINGERPRINT_AUDIO, FINGERPRINT_DELTA, FINGERPRINT_E8,
    FINGERPRINT_E8E9, FINGERPRINT_RGB,
};
