//! Archive-level walker over a RAR5 byte buffer (or buffer set).
//!
//! Drives [`crate::rar::format`]'s per-header parsers from the
//! signature at offset 0 to the end-of-archive marker, surfacing the
//! archive-wide flags and the per-file metadata the §1 demo prints.
//! The walker exposes two front doors with the same shape:
//!
//! - [`walk_archive`] takes a single byte buffer containing one
//!   self-contained archive (single-volume or, after
//!   `internal/PLAN_multivolume_archives.md` §2, the first volume of a
//!   set when the caller only has the first volume in hand).
//! - [`walk_archive_multivolume`] takes an ordered slice of volume
//!   buffers and stitches them into one [`ArchiveSummary`] whose
//!   `data_offset` fields are absolute byte offsets into the byte
//!   concatenation of the volumes in input order. Each volume's
//!   leading signature and main archive header are skipped; the
//!   walker still counts the bytes they occupy in the global offset
//!   space because the §3 pipeline addresses entries through a
//!   [`crate::download::multi_url::MultiPartSource`] whose virtual
//!   stream is exactly that concatenation.
//!
//! The walker enforces the round-one rejections:
//!
//! - **RAR4** — surfaced by [`crate::rar::format::parse_signature`]
//!   as [`crate::rar::RarError::UnsupportedFormatVersion`].
//! - **Archive encryption header** (header type 4) —
//!   [`crate::rar::RarError::UnsupportedFeature`].
//!
//! Multi-volume support layers in by sub-phase
//! (`internal/PLAN_multivolume_archives.md` §2). §2b lands the
//! per-volume walk but rejects file headers carrying
//! `FHD_SPLIT_BEFORE` / `FHD_SPLIT_AFTER` with a precise
//! [`RarError::UnsupportedFeature`] naming the affected entry — the
//! cross-volume continuation logic lands in §2d.

use crate::encryption::EncryptionError;
use crate::rar::encrypt::{
    find_file_encryption_record, ArchiveEncryptionHeader, FileEncryptionRecord,
};
use crate::rar::error::RarError;
use crate::rar::format::{
    arc_flags, hdr_flags, parse_end_of_archive_header, parse_file_header, parse_generic_header,
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
    /// `true` iff the **final** processed volume's end-of-archive
    /// header carried the `more_volumes` flag. After
    /// [`walk_archive_multivolume`] returns successfully on a
    /// multi-volume input this is always `false` (otherwise the
    /// walker would have surfaced [`RarError::VolumeSetMismatch`]).
    /// For the single-volume [`walk_archive`] entry point, `true`
    /// means the caller fed the first volume of a multi-volume set
    /// and would need to provide the rest to extract entries.
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
    /// following the file header). For [`walk_archive_multivolume`]
    /// this is the absolute offset into the byte concatenation of
    /// all volumes in input order — directly consumable by the §3
    /// pipeline's [`crate::download::multi_url::MultiPartSource`]
    /// without further translation.
    ///
    /// For multi-volume continuation entries this is the offset of
    /// the entry's **first** segment (in the volume that carries
    /// the leading file header). Additional segments are in
    /// [`Self::extra_segments`].
    pub data_offset: u64,
    /// Compressed-data length in bytes (i.e. the file header's
    /// `data_size`). For unencrypted STORED entries this equals
    /// [`FileHeader::unpacked_size`]. For encrypted entries it is
    /// `round_up_16(plaintext_data_size)` — the archive zero-pads
    /// the data area to a 16-byte boundary so AES-CBC can decrypt
    /// it block-aligned; the [`FileEncryptionRecord`] on the entry
    /// signals the padding semantics.
    ///
    /// For multi-volume continuation entries this is the size of
    /// the entry's **first** segment only — i.e. the `data_size`
    /// on the leading file header that carries `FHD_SPLIT_AFTER`.
    /// Additional segments' sizes live in [`Self::extra_segments`];
    /// the entry's total on-disk packed size is
    /// `packed_size + extra_segments.iter().map(|s| s.packed_size).sum::<u64>()`.
    pub packed_size: u64,
    /// Trailing segments for entries whose data spans more than
    /// one volume (`internal/PLAN_multivolume_archives.md` §2d). Empty
    /// for entries that fit in a single volume.
    ///
    /// Each [`EntrySegment`] records the byte offset (in the
    /// global concatenated-volume coordinate space) and length of
    /// one of the entry's continuation file headers' data areas.
    /// Segments are stored in archive order (i.e. volume order);
    /// concatenating their bytes (in order, starting from the
    /// leading segment described by [`Self::data_offset`] /
    /// [`Self::packed_size`]) reconstructs the entry's full
    /// compressed (or plaintext, for STORED) payload.
    pub extra_segments: Vec<EntrySegment>,
    /// Parsed encryption record from the file-header extra area,
    /// when the entry's data is per-file-encrypted (the extra area
    /// carries a type-1 record). `None` for unencrypted entries.
    /// Independent of archive-header encryption (which encrypts the
    /// header itself; the data area may or may not also be encrypted
    /// via this field).
    pub encryption: Option<FileEncryptionRecord>,
}

/// One segment of a multi-volume entry's data area. See
/// [`FileEntry::extra_segments`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct EntrySegment {
    /// Absolute byte offset of this segment's data area in the
    /// global concatenated-volume byte space.
    pub data_offset: u64,
    /// Size of this segment's data area, in bytes (the segment's
    /// file-header `data_size`).
    pub packed_size: u64,
}

/// Walk a single RAR5 buffer and produce the [`ArchiveSummary`].
///
/// Convenience wrapper around [`walk_archive_multivolume`] for the
/// common single-volume case. `buf` must start at byte 0 of the
/// archive and contain the full archive contents through the
/// end-of-archive header.
///
/// When `buf` is the first volume of a multi-volume set and any
/// entry spans into a following volume, the walker surfaces
/// [`RarError::UnsupportedFeature`] naming the affected entry (per
/// `internal/PLAN_multivolume_archives.md` §2b). Callers that hold the
/// rest of the volumes route through [`walk_archive_multivolume`].
///
/// # Errors
///
/// See [`walk_archive_multivolume`].
pub fn walk_archive(buf: &[u8]) -> Result<ArchiveSummary, RarError> {
    walk_archive_multivolume(&[buf])
}

/// Walk an ordered set of RAR5 volume buffers and produce one
/// [`ArchiveSummary`] over the whole set.
///
/// Each `volumes[i]` must start at byte 0 of its respective volume
/// (the RAR5 signature). Volumes are processed left-to-right; the
/// walker:
///
/// - parses each volume's signature + main archive header;
/// - records the archive-wide flags from the **first** volume's
///   main header (the spec requires `MHD_SOLID` and recovery-record
///   flags to match across volumes; volumes 2+ are spot-checked
///   only for `MHD_VOLUME` and the optional volume number);
/// - aggregates [`FileEntry`] metadata across volumes, with
///   `data_offset` in the global byte space (i.e. accounting for
///   prior volumes' on-disk sizes);
/// - verifies each non-final volume terminates with an
///   `EndArchive` header carrying `more_volumes = true`, and the
///   final volume's `EndArchive` clears the bit.
///
/// `FHD_SPLIT_AFTER` / `FHD_SPLIT_BEFORE` headers fold into one
/// [`FileEntry`] whose [`FileEntry::extra_segments`] records the
/// continuation segments' offsets and sizes
/// (`internal/PLAN_multivolume_archives.md` §2d). The spec requires
/// the spanning entry's name, unpacked size, and (when present)
/// CRC32 to match across all of its file headers; the walker
/// surfaces [`RarError::CorruptHeader`] when a continuation's
/// metadata disagrees with the leading header.
///
/// # Errors
///
/// - [`RarError::CorruptHeader`] if `volumes` is empty.
/// - [`RarError::BadSignature`] / [`RarError::UnsupportedFormatVersion`]
///   from [`parse_signature`] on any volume.
/// - [`RarError::UnsupportedFeature`] for archive-encryption
///   headers (type 4) or unknown header types missing
///   `SKIP_IF_UNKNOWN`.
/// - [`RarError::CorruptHeader`] / [`RarError::Truncated`] /
///   [`RarError::HeaderCrc32Mismatch`] from per-header parsers.
/// - [`RarError::CorruptHeader`] (`reason = "volume ends before
///   end-of-archive marker"`) if any volume terminates without an
///   `EndArchive` header.
/// - [`RarError::VolumeSetMismatch`] if a non-final volume omits
///   `more_volumes`, the final volume sets it, or the supplied
///   volume_number field disagrees with the input order.
pub fn walk_archive_multivolume(volumes: &[&[u8]]) -> Result<ArchiveSummary, RarError> {
    if volumes.is_empty() {
        return Err(RarError::CorruptHeader {
            archive_offset: 0,
            reason: "walk_archive_multivolume called with no volume buffers".to_string(),
        });
    }
    let multi = volumes.len() > 1;
    let mut summary = ArchiveSummary {
        solid: false,
        has_recovery_record: false,
        locked: false,
        eof_more_volumes: false,
        entries: Vec::new(),
    };
    let mut saw_first_main = false;
    let mut volume_base: u64 = 0;
    // §2d: when a file header sets SPLIT_AFTER but not SPLIT_BEFORE,
    // the entry continues into the next volume; we stash the index
    // into `summary.entries` of the leading entry so the matching
    // SPLIT_BEFORE header in the next volume can append its data
    // segment instead of pushing a fresh entry. Cleared after the
    // matching SPLIT_BEFORE-without-SPLIT_AFTER is observed (i.e.
    // the entry's trailing segment).
    let mut pending_split_entry: Option<usize> = None;
    for (vol_idx, buf) in volumes.iter().copied().enumerate() {
        let is_last_vol = vol_idx + 1 == volumes.len();
        let sig_size = parse_signature(buf)?;
        let mut cursor: usize = sig_size;
        let mut saw_volume_main = false;
        let eoa_more_volumes: bool = loop {
            if cursor >= buf.len() {
                return Err(RarError::CorruptHeader {
                    archive_offset: volume_base + cursor as u64,
                    reason: format!("volume {} ends before end-of-archive marker", vol_idx + 1),
                });
            }
            let header_archive_offset = volume_base + cursor as u64;
            let header = parse_generic_header(&buf[cursor..], header_archive_offset)?;
            match header.header_type {
                HeaderType::MainArchive => {
                    if saw_volume_main {
                        return Err(RarError::CorruptHeader {
                            archive_offset: header.archive_offset,
                            reason: format!("second main archive header in volume {}", vol_idx + 1),
                        });
                    }
                    saw_volume_main = true;
                    let main = parse_main_archive_header(&header, &buf[cursor..])?;
                    if vol_idx == 0 {
                        if saw_first_main {
                            return Err(RarError::CorruptHeader {
                                archive_offset: header.archive_offset,
                                reason: "second main archive header encountered".to_string(),
                            });
                        }
                        saw_first_main = true;
                        summary.solid = main.archive_flags.is_solid();
                        summary.has_recovery_record = main.archive_flags.has_recovery_record();
                        summary.locked = main.archive_flags.is_locked();
                        if multi && !main.archive_flags.is_volume() {
                            return Err(RarError::CorruptHeader {
                                archive_offset: header.archive_offset,
                                reason: "first volume of multi-volume input \
                                         missing MHD_VOLUME flag"
                                    .to_string(),
                            });
                        }
                    } else {
                        if main.archive_flags.0 & arc_flags::VOLUME == 0 {
                            return Err(RarError::CorruptHeader {
                                archive_offset: header.archive_offset,
                                reason: format!(
                                    "volume {} main header missing MHD_VOLUME flag",
                                    vol_idx + 1
                                ),
                            });
                        }
                        // The wire encodes volume_number 0-based; the
                        // first volume omits the field entirely
                        // (implicit 0). Validate the recorded value
                        // matches the input order when present.
                        if let Some(vn) = main.volume_number {
                            let expected = vol_idx as u64;
                            if vn != expected {
                                return Err(RarError::VolumeSetMismatch {
                                    detail: format!(
                                        "supplied volume {} carries wire \
                                         volume_number={vn}; expected {expected} \
                                         (0-based) for that position in the set",
                                        vol_idx + 1
                                    ),
                                });
                            }
                        }
                    }
                }
                HeaderType::File => {
                    let file = parse_file_header(&header, &buf[cursor..])?;
                    let split_before = header.header_flags & hdr_flags::SPLIT_BEFORE != 0;
                    let split_after = header.header_flags & hdr_flags::SPLIT_AFTER != 0;
                    let packed_size = header.data_size.unwrap_or(0);
                    let data_offset = header_archive_offset + header.total_header_bytes as u64;
                    let method = file.compression.method();
                    if method > 5 {
                        return Err(RarError::UnsupportedFeature {
                            feature: format!(
                                "compression method {method} (reserved by RAR5 \
                                 spec for future use)"
                            ),
                        });
                    }
                    let extra = &buf[cursor + header.extra_offset_in_input
                        ..cursor + header.extra_offset_in_input + header.extra_size_in_input];
                    let encryption = find_file_encryption_record(
                        extra,
                        header.archive_offset + header.extra_offset_in_input as u64,
                    )?;
                    if split_before {
                        // §2d continuation. Match against the
                        // pending leading entry and append the
                        // segment.
                        let leading_idx =
                            pending_split_entry.ok_or_else(|| RarError::CorruptHeader {
                                archive_offset: header.archive_offset,
                                reason: format!(
                                    "file {:?} carries FHD_SPLIT_BEFORE but no \
                                     matching FHD_SPLIT_AFTER preceded it",
                                    file.name
                                ),
                            })?;
                        let leading = &summary.entries[leading_idx];
                        if leading.header.name != file.name {
                            return Err(RarError::CorruptHeader {
                                archive_offset: header.archive_offset,
                                reason: format!(
                                    "multi-volume continuation file {:?} does \
                                     not match preceding split entry {:?}",
                                    file.name, leading.header.name
                                ),
                            });
                        }
                        if leading.header.unpacked_size != file.unpacked_size {
                            return Err(RarError::CorruptHeader {
                                archive_offset: header.archive_offset,
                                reason: format!(
                                    "multi-volume continuation {:?} declares \
                                     unpacked_size={}, leading segment had {}",
                                    file.name, file.unpacked_size, leading.header.unpacked_size
                                ),
                            });
                        }
                        // WinRAR populates the file-header `crc32`
                        // field with the *per-segment* Pack-CRC32
                        // for SPLIT continuation headers — not a
                        // cumulative whole-file checksum. Drop the
                        // leading segment's `crc32` once we know the
                        // entry spans volumes so the sink does not
                        // try to verify a partial checksum against
                        // the assembled output. The walker's spec
                        // contract is name + unpacked_size match
                        // across segments; whole-file integrity for
                        // spanning entries falls back to the
                        // BLAKE2sp extra-record subtype (or nothing
                        // when neither is present).
                        summary.entries[leading_idx].header.crc32 = None;
                        summary.entries[leading_idx]
                            .extra_segments
                            .push(EntrySegment {
                                data_offset,
                                packed_size,
                            });
                        if !split_after {
                            // Trailing segment — clear the pending
                            // marker so the next file header in this
                            // (or a later) volume starts a fresh
                            // entry.
                            pending_split_entry = None;
                        }
                    } else {
                        if pending_split_entry.is_some() {
                            return Err(RarError::CorruptHeader {
                                archive_offset: header.archive_offset,
                                reason: format!(
                                    "file {:?} does not carry FHD_SPLIT_BEFORE but \
                                     a prior file's FHD_SPLIT_AFTER is still \
                                     pending continuation",
                                    file.name
                                ),
                            });
                        }
                        let new_entry = FileEntry {
                            header: file,
                            data_offset,
                            packed_size,
                            extra_segments: Vec::new(),
                            encryption,
                        };
                        summary.entries.push(new_entry);
                        if split_after {
                            pending_split_entry = Some(summary.entries.len() - 1);
                        }
                    }
                }
                HeaderType::Service => {
                    // Skipped: comments, recovery records,
                    // quick-open tables, Unix ACLs. Round-one
                    // neither parses nor refuses these — we just
                    // step over them. Real archives place these
                    // between the last file entry and the
                    // end-of-archive marker (one per volume in
                    // multi-volume sets, since the recovery record
                    // is per-volume).
                }
                HeaderType::ArchiveEncryption => {
                    let fields = &buf[cursor + header.fields_offset_in_input
                        ..cursor + header.fields_offset_in_input + header.fields_size];
                    let _enc = ArchiveEncryptionHeader::parse(fields).map_err(RarError::from)?;
                    return Err(RarError::Encryption(EncryptionError::UnsupportedCipher {
                        detail: "archive-header encryption (RAR5 AES-256-CBC, encryption \
                                 header type 4) — peel parses the encryption header but \
                                 does not yet decrypt the subsequent header stream"
                            .to_string(),
                    }));
                }
                HeaderType::EndOfArchive => {
                    let eof = parse_end_of_archive_header(&header, &buf[cursor..])?;
                    // Step over the EOA's bytes only for the
                    // overflow check; the volume's remaining bytes
                    // belong to whatever the producer appended after
                    // the marker (typically nothing).
                    let _next = advance_cursor(cursor, &header, header_archive_offset)?;
                    break eof.more_volumes;
                }
                HeaderType::Other(code) => {
                    if header.header_flags & hdr_flags::SKIP_IF_UNKNOWN == 0 {
                        return Err(RarError::UnsupportedFeature {
                            feature: format!(
                                "unknown RAR header type {code} without \
                                 SKIP_IF_UNKNOWN flag"
                            ),
                        });
                    }
                }
            }
            cursor = advance_cursor(cursor, &header, header_archive_offset)?;
        };
        if eoa_more_volumes && is_last_vol {
            return Err(RarError::VolumeSetMismatch {
                detail: format!(
                    "supplied volume {} (the last in the set) carries \
                     more_volumes=true; additional volumes were not supplied",
                    vol_idx + 1
                ),
            });
        }
        if !eoa_more_volumes && !is_last_vol {
            return Err(RarError::VolumeSetMismatch {
                detail: format!(
                    "supplied volume {} terminates the archive \
                     (more_volumes=false) but {} additional volume(s) were \
                     supplied beyond it",
                    vol_idx + 1,
                    volumes.len() - vol_idx - 1
                ),
            });
        }
        // For multi-volume input the final summary's
        // `eof_more_volumes` is always false here (otherwise we'd
        // have errored above). For single-volume input the field
        // mirrors the lone EOA's flag, which preserves the previous
        // walker's behaviour for callers that inspect it.
        summary.eof_more_volumes = eoa_more_volumes;
        volume_base =
            volume_base
                .checked_add(buf.len() as u64)
                .ok_or_else(|| RarError::CorruptHeader {
                    archive_offset: volume_base,
                    reason: "cumulative volume size overflows u64".to_string(),
                })?;
    }
    if let Some(idx) = pending_split_entry {
        let name = summary.entries[idx].header.name.clone();
        return Err(RarError::CorruptHeader {
            archive_offset: volume_base,
            reason: format!(
                "file {name:?} carries FHD_SPLIT_AFTER on its last segment but \
                 no continuation volume was supplied"
            ),
        });
    }
    Ok(summary)
}

/// Advance an in-volume cursor past a parsed header *and* its
/// trailing data area. Returns the new cursor or a
/// [`RarError::CorruptHeader`] on overflow.
fn advance_cursor(
    cursor: usize,
    header: &crate::rar::format::GenericHeader,
    header_archive_offset: u64,
) -> Result<usize, RarError> {
    cursor
        .checked_add(header.total_header_bytes)
        .and_then(|c| c.checked_add(header.data_size.unwrap_or(0).try_into().ok()?))
        .ok_or_else(|| RarError::CorruptHeader {
            archive_offset: header_archive_offset,
            reason: "header + data offset overflows usize".to_string(),
        })
}
