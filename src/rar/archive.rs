//! Archive-level walker over a RAR5 byte buffer.
//!
//! Drives [`crate::rar::format`]'s per-header parsers from the
//! signature at offset 0 to the end-of-archive marker, surfacing the
//! archive-wide flags and the per-file metadata the §1 demo prints.
//! Round-one consumers feed the entire archive bytes (the §3
//! pipeline streams ranged downloads on top of the same parser
//! primitives, but for §1's "open archive, list entries" milestone
//! the in-memory walker is the simplest exercise of the wire-format
//! layer end-to-end).
//!
//! The walker enforces the §0 round-one rejections:
//!
//! - **RAR4** — surfaced by [`crate::rar::format::parse_signature`]
//!   as [`crate::rar::RarError::UnsupportedFormatVersion`].
//! - **Multi-volume** (`MHD_VOLUME` set in the main archive header)
//!   — [`crate::rar::RarError::UnsupportedFeature`] naming the
//!   detected volume number.
//! - **Archive encryption header** (header type 4) —
//!   [`crate::rar::RarError::UnsupportedFeature`].

use crate::rar::error::RarError;
use crate::rar::format::{
    parse_end_of_archive_header, parse_file_header, parse_generic_header,
    parse_main_archive_header, parse_signature, FileHeader, HeaderType,
};

/// Summary of the archive's metadata after a full walk.
///
/// Carries everything the §1 demo binary needs to print and
/// everything the §3 pipeline needs to plan per-entry downloads
/// (modulo per-entry data-area offsets, which the pipeline computes
/// on the fly from the same generic-header bytes).
#[derive(Debug, Clone)]
pub struct ArchiveSummary {
    /// `true` iff the main archive header set `MHD_SOLID`.
    pub solid: bool,
    /// `true` iff the main archive header carried the
    /// "recovery record present" advisory bit. Round-one ignores
    /// the actual recovery records (they live in service headers).
    pub has_recovery_record: bool,
    /// `true` iff the archive is "locked" (advisory bit).
    pub locked: bool,
    /// `true` iff the end-of-archive header carried the
    /// `more_volumes` flag — informational only in round-one
    /// (multi-volume archives are rejected at the main header).
    pub eof_more_volumes: bool,
    /// One entry per file header (header type 2). Service headers
    /// (type 3) are skipped — round-one does not extract recovery
    /// records, comments, quick-open tables, or Unix ACLs.
    pub entries: Vec<FileEntry>,
}

/// Per-entry summary captured during a walk.
#[derive(Debug, Clone)]
pub struct FileEntry {
    /// Decoded file-header metadata.
    pub header: FileHeader,
    /// Byte offset of the entry's compressed data within the
    /// archive (the offset of the first byte of the data area
    /// following the file header). The §3 pipeline uses this to
    /// schedule a ranged download for the entry's payload.
    pub data_offset: u64,
    /// Compressed-data length in bytes (i.e. the file header's
    /// `data_size`). Equals [`FileHeader::unpacked_size`] for
    /// STORED-method entries.
    pub packed_size: u64,
}

/// Walk an entire RAR5 archive in `buf` and produce the
/// [`ArchiveSummary`].
///
/// `buf` must start at the very beginning of the archive (byte 0,
/// the start of the magic) and contain the full archive contents
/// through the end-of-archive header.
///
/// # Errors
///
/// - [`RarError::BadSignature`] / [`RarError::UnsupportedFormatVersion`]
///   from [`parse_signature`].
/// - [`RarError::UnsupportedFeature`] for multi-volume archives,
///   archive-encryption headers (type 4), or unknown header types
///   that lack the `SKIP_IF_UNKNOWN` flag.
/// - [`RarError::CorruptHeader`] / [`RarError::Truncated`] /
///   [`RarError::HeaderCrc32Mismatch`] from the per-header parsers.
/// - [`RarError::CorruptHeader`] (`reason = "missing end-of-archive
///   marker"`) if the byte stream ends before a header-type-5
///   header is observed.
pub fn walk_archive(buf: &[u8]) -> Result<ArchiveSummary, RarError> {
    let sig_size = parse_signature(buf)?;
    let mut cursor: usize = sig_size;
    let mut summary = ArchiveSummary {
        solid: false,
        has_recovery_record: false,
        locked: false,
        eof_more_volumes: false,
        entries: Vec::new(),
    };
    let mut saw_main = false;
    loop {
        if cursor >= buf.len() {
            return Err(RarError::CorruptHeader {
                archive_offset: cursor as u64,
                reason: "archive ends before end-of-archive marker".to_string(),
            });
        }
        let header = parse_generic_header(&buf[cursor..], cursor as u64)?;
        // The per-header parser returns offsets relative to its own
        // input slice; translate the offsets we'll later index back
        // into `buf` with by adding the slice's position.
        let header_in_buf = HeaderInBuf {
            inner: header,
            slice_start: cursor,
        };
        match header.header_type {
            HeaderType::MainArchive => {
                if saw_main {
                    return Err(RarError::CorruptHeader {
                        archive_offset: header.archive_offset,
                        reason: "second main archive header encountered".to_string(),
                    });
                }
                saw_main = true;
                let main = parse_main_archive_header(&header, &buf[cursor..])?;
                if main.archive_flags.is_volume() {
                    let label = match main.volume_number {
                        Some(n) => format!("multi-volume archive (volume {n})"),
                        None => "multi-volume archive".to_string(),
                    };
                    return Err(RarError::UnsupportedFeature { feature: label });
                }
                summary.solid = main.archive_flags.is_solid();
                summary.has_recovery_record = main.archive_flags.has_recovery_record();
                summary.locked = main.archive_flags.is_locked();
            }
            HeaderType::File => {
                let file = parse_file_header(&header, &buf[cursor..])?;
                let packed_size = header.data_size.unwrap_or(0);
                let data_offset = (cursor as u64) + header.total_header_bytes as u64;
                let method = file.compression.method();
                if method != 0 {
                    return Err(RarError::UnsupportedFeature {
                        feature: format!(
                            "compression method {method} (RAR5 standard \
                             algorithm) — round-one ships STORED only; the \
                             hand-rolled decoder lands in §4 \
                             (PLAN_rar5_decoder.md)"
                        ),
                    });
                }
                summary.entries.push(FileEntry {
                    header: file,
                    data_offset,
                    packed_size,
                });
            }
            HeaderType::Service => {
                // Skipped: comments, recovery records, quick-open
                // tables, Unix ACLs. Round-one neither parses nor
                // refuses these — we just step over them.
            }
            HeaderType::ArchiveEncryption => {
                return Err(RarError::UnsupportedFeature {
                    feature: "encryption (header)".to_string(),
                });
            }
            HeaderType::EndOfArchive => {
                let eof = parse_end_of_archive_header(&header, &buf[cursor..])?;
                summary.eof_more_volumes = eof.more_volumes;
                return Ok(summary);
            }
            HeaderType::Other(code) => {
                if header.header_flags & crate::rar::format::hdr_flags::SKIP_IF_UNKNOWN == 0 {
                    return Err(RarError::UnsupportedFeature {
                        feature: format!(
                            "unknown RAR header type {code} without \
                             SKIP_IF_UNKNOWN flag"
                        ),
                    });
                }
            }
        }
        cursor = cursor
            .checked_add(header.total_header_bytes)
            .and_then(|c| c.checked_add(header.data_size.unwrap_or(0).try_into().ok()?))
            .ok_or_else(|| RarError::CorruptHeader {
                archive_offset: header_in_buf.inner.archive_offset,
                reason: "header + data offset overflows usize".to_string(),
            })?;
    }
}

/// Internal helper carrying a parsed header along with the offset of
/// its slice in the larger input buffer. Used so error paths can
/// emit absolute archive offsets without re-deriving them.
struct HeaderInBuf {
    inner: crate::rar::format::GenericHeader,
    #[allow(dead_code)]
    slice_start: usize,
}
