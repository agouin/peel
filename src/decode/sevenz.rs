//! 7z decoder runtime.
//!
//! Sibling to [`crate::sevenz`] (which holds the crate-level public
//! surface — errors, format-name constant, magic). This module
//! holds the actually-running parsers and decoders that the
//! second-pipeline driver in `crate::download::sevenz_pipeline`
//! will plug into.
//!
//! # Phase 1 (`internal/PLAN_7z_support.md` §1)
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
//! # Phase 2 (`internal/PLAN_7z_support.md` §2)
//!
//! [`format`] holds the fixed 32-byte
//! [`format::parse_signature_header`] that reads the
//! [`format::SignatureHeader`] every 7z archive begins with —
//! magic, ArchiveVersion, StartHeaderCRC validation, and the
//! trailer location the §8 pipeline drives the next ranged GET
//! against.
//!
//! # Phase 3 (`internal/PLAN_7z_support.md` §3)
//!
//! [`header`] decodes the trailer the §2 parser pointed at into
//! a typed [`header::Header`] / [`header::StreamsInfo`] /
//! [`header::FileRecord`] tree. Two entry points cover the two
//! trailer shapes:
//!
//! - [`header::parse_trailer`] for the outermost trailer, which
//!   may be a plain `Header` or an `EncodedHeader`.
//! - [`header::parse_decoded_header`] for the bytes produced by
//!   running an `EncodedHeader`'s folder through the §6 folder
//!   decoder; rejects nested encoded headers.
//!
//! # Phase 4 (`internal/PLAN_7z_support.md` §4)
//!
//! [`coders`] holds the [`coders::CoderImpl`] dispatch surface
//! and the round-one COPY / DEFLATE coders. LZMA / LZMA2 land
//! in §5 and slot into the same [`coders::dispatch`] match arm
//! without changing any caller.
//!
//! # Phase 5 (`internal/PLAN_7z_support.md` §5)
//!
//! [`coders::dispatch`] now resolves `[0x03, 0x01, 0x01]` /
//! `[0x21]` to runtime LZMA / LZMA2 coders backed by
//! [`crate::decode::xz_liblzma::raw`]. The xz_liblzma side
//! exposes new `decode_lzma1_raw` / `decode_lzma2_raw` entry
//! points the §6 folder decoder will drive once it lands.
//!
//! # Phase 6 (`internal/PLAN_7z_support.md` §6)
//!
//! [`folder`] ties §4 + §5 together: [`folder::FolderDecoder`]
//! takes a parsed [`header::Folder`] (linear coder chain) plus
//! a packed-bytes source and feeds the decoded substream bytes
//! into a [`folder::FolderSink`] in substream order. Per-folder
//! CRC32 is validated at end-of-folder; the sink owns
//! per-substream CRC validation.

pub mod coders;
pub mod folder;
pub mod format;
pub mod header;
pub mod number;
