//! ZIP wire-format parsers.
//!
//! Hand-rolled per the dependency policy in
//! `docs/ENGINEERING_STANDARDS.md` §2.1 and the format-audit
//! preference in `docs/PLAN_v2.md` §5. Every parser is pure: input
//! goes in as a byte slice, output comes out as a typed struct, and
//! no IO happens here. Higher layers (the per-entry pipeline) do the
//! ranged downloads and feed the right bytes to the right parser.
//!
//! # Layout reference
//!
//! All multi-byte integers are little-endian. The PKWARE APPNOTE
//! (`https://support.pkware.com/pkzip/appnote`) is the spec; sections
//! we lean on most:
//!
//! - **§4.3.6** — local file header
//! - **§4.3.12** — central directory header (CDE)
//! - **§4.3.16** — end-of-central-directory record (EOCD)
//!
//! ```text
//! Local File Header (LFH)            min 30 bytes + name + extra
//!  0  u32 signature        0x04034b50
//!  4  u16 version_needed
//!  6  u16 gp_flags
//!  8  u16 compression_method
//! 10  u16 last_mod_time
//! 12  u16 last_mod_date
//! 14  u32 crc32                       (0 if data descriptor flag set)
//! 18  u32 compressed_size             (0 if data descriptor flag set)
//! 22  u32 uncompressed_size           (0 if data descriptor flag set)
//! 26  u16 filename_length
//! 28  u16 extra_length
//! 30  filename + extra + data
//!
//! Central Directory Entry (CDE)      min 46 bytes + name + extra + comment
//!  0  u32 signature        0x02014b50
//!  4  u16 version_made_by
//!  6  u16 version_needed
//!  8  u16 gp_flags
//! 10  u16 compression_method
//! 12  u16 last_mod_time
//! 14  u16 last_mod_date
//! 16  u32 crc32                       authoritative for the entry
//! 20  u32 compressed_size             authoritative for the entry
//! 24  u32 uncompressed_size           authoritative for the entry
//! 28  u16 filename_length
//! 30  u16 extra_length
//! 32  u16 comment_length
//! 34  u16 disk_start
//! 36  u16 internal_attrs
//! 38  u32 external_attrs
//! 42  u32 lfh_offset                  authoritative for the entry
//! 46  filename + extra + comment
//!
//! End of Central Directory (EOCD)    22 bytes + comment ≤ 65535
//!  0  u32 signature        0x06054b50
//!  4  u16 disk_number
//!  6  u16 cd_start_disk
//!  8  u16 cd_entries_this_disk
//! 10  u16 cd_entries_total
//! 12  u32 cd_size
//! 16  u32 cd_offset
//! 20  u16 comment_length
//! 22  comment bytes
//! ```
//!
//! # Sentinel values
//!
//! The PKWARE APPNOTE encodes "this value lives in a Zip64 extra
//! field" via:
//!
//! - `u32` size or offset = `0xFFFF_FFFF`
//! - `u16` entry count = `0xFFFF`
//!
//! Round-one rejects all of these as
//! [`crate::zip::ZipError::UnsupportedFeature`]. Round-one also
//! rejects:
//!
//! - `gp_flags` bit 0 set ("encrypted") or bit 6 set ("strong
//!   encryption") — see `is_encrypted`.
//! - any compression method other than the three round-one supports.
//! - any `disk_start != 0` or `cd_start_disk != 0` ("multi-disk").
//!
//! Per the plan's "the user should see 'AES encryption is not
//! supported', not 'malformed header'" rule, those refusals carry the
//! feature name in the [`crate::zip::ZipError::UnsupportedFeature`]
//! message rather than failing as a generic parse error.

use crate::zip::ZipError;

/// 4-byte signature at the start of every local file header.
pub const SIGNATURE_LFH: u32 = 0x0403_4b50;

/// 4-byte signature at the start of every central-directory entry.
pub const SIGNATURE_CDE: u32 = 0x0201_4b50;

/// 4-byte signature at the start of the end-of-central-directory
/// record.
pub const SIGNATURE_EOCD: u32 = 0x0605_4b50;

/// 4-byte signature that may precede the optional data descriptor when
/// general-purpose flag bit 3 is set.
pub const SIGNATURE_DATA_DESCRIPTOR: u32 = 0x0807_4b50;

/// 4-byte signature for the Zip64 EOCD record. Not supported in
/// round-one.
pub const SIGNATURE_ZIP64_EOCD: u32 = 0x0606_4b50;

/// 4-byte signature for the Zip64 EOCD locator. Not supported in
/// round-one.
pub const SIGNATURE_ZIP64_EOCD_LOCATOR: u32 = 0x0706_4b50;

/// Maximum number of bytes the EOCD record (with comment) can occupy.
///
/// 22-byte fixed header + 65535-byte comment. [`find_eocd`] uses this
/// to size its search window; callers that need a fallback for
/// pathological cases (an EOCD signature appearing inside the comment)
/// can request larger windows but the window cannot exceed this value
/// without a malformed archive.
pub const MAX_EOCD_TAIL_BYTES: u64 = 22 + (u16::MAX as u64);

/// Minimum size of a fixed EOCD record, before the variable-length
/// comment.
const EOCD_FIXED_LEN: usize = 22;

/// Minimum size of a fixed CDE record, before the variable-length
/// filename / extra / comment fields.
pub const CDE_FIXED_LEN: usize = 46;

/// Minimum size of a fixed LFH record, before the variable-length
/// filename / extra fields.
pub const LFH_FIXED_LEN: usize = 30;

/// Compression method recorded in the LFH and CDE.
///
/// Round-one decodes only the three named variants. [`Self::Other`]
/// captures every code we recognize as defined by the APPNOTE but do
/// not implement, so the pipeline can surface a precise
/// [`ZipError::UnsupportedFeature`] message.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CompressionMethod {
    /// `0` — no compression; entry data is the raw bytes.
    Stored,
    /// `8` — DEFLATE (RFC 1951). Decoded via the hand-rolled
    /// [`crate::decode::deflate_native::Decoder`] since Phase 9a
    /// of `docs/PLAN_deflate_block_decoder.md`.
    Deflate,
    /// `93` — zstd. Decoded via the existing `zstd` crate binding.
    Zstd,
    /// Any other compression method the APPNOTE defines but we do
    /// not support. The wire value is preserved so the
    /// [`ZipError::UnsupportedFeature`] message can name it.
    Other(u16),
}

impl CompressionMethod {
    /// Decode the wire-level method code.
    #[must_use]
    pub fn from_code(code: u16) -> Self {
        match code {
            0 => Self::Stored,
            8 => Self::Deflate,
            93 => Self::Zstd,
            other => Self::Other(other),
        }
    }

    /// Wire-level code of this method.
    #[must_use]
    pub fn code(self) -> u16 {
        match self {
            Self::Stored => 0,
            Self::Deflate => 8,
            Self::Zstd => 93,
            Self::Other(c) => c,
        }
    }

    /// Human-readable name suitable for use in error messages.
    ///
    /// For [`Self::Other`] this includes the method code so the user
    /// can correlate it against the APPNOTE.
    #[must_use]
    pub fn label(self) -> String {
        match self {
            Self::Stored => "STORED (0)".into(),
            Self::Deflate => "DEFLATE (8)".into(),
            Self::Zstd => "zstd (93)".into(),
            Self::Other(c) => match c {
                1 => "SHRUNK (1)".into(),
                2..=5 => format!("REDUCED (level {c})"),
                6 => "IMPLODED (6)".into(),
                9 => "DEFLATE64 (9)".into(),
                10 => "PKWARE IMPLODE (10)".into(),
                12 => "BZIP2 (12)".into(),
                14 => "LZMA (14)".into(),
                18 => "IBM TERSE (18)".into(),
                19 => "IBM LZ77 (19)".into(),
                95 => "XZ (95)".into(),
                96 => "JPEG (96)".into(),
                97 => "WAVPACK (97)".into(),
                98 => "PPMD (98)".into(),
                99 => "AES (99 — encryption marker)".into(),
                _ => format!("compression method {c}"),
            },
        }
    }
}

/// General-purpose bit-flag word from the LFH / CDE.
///
/// We model only the flags round-one cares about. The wire `u16` is
/// preserved verbatim so future round-twos can broaden the surface
/// without re-parsing.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct GeneralPurposeFlags(pub u16);

impl GeneralPurposeFlags {
    /// Bit 0: entry data is encrypted (traditional PKWARE encryption).
    #[must_use]
    pub fn is_encrypted(self) -> bool {
        self.0 & 0x0001 != 0
    }

    /// Bit 3: a data descriptor follows the compressed data, and the
    /// LFH's CRC / sizes are zeroed; the central directory carries the
    /// authoritative values.
    #[must_use]
    pub fn has_data_descriptor(self) -> bool {
        self.0 & 0x0008 != 0
    }

    /// Bit 6: strong encryption (incompatible with bit-0 encryption).
    #[must_use]
    pub fn is_strong_encrypted(self) -> bool {
        self.0 & 0x0040 != 0
    }

    /// Bit 11: filename and comment are UTF-8 (otherwise CP437).
    ///
    /// We always interpret as UTF-8 in round-one and reject names that
    /// don't decode. The flag is informational here.
    #[must_use]
    pub fn is_utf8(self) -> bool {
        self.0 & 0x0800 != 0
    }
}

/// Parsed end-of-central-directory record.
///
/// Held without the comment bytes; the comment is informational and
/// the pipeline doesn't need it after locating the record.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EndOfCentralDirectory {
    /// Byte offset within the archive where the EOCD signature begins.
    /// Used by hole-punching policy to release everything after the
    /// last entry once we no longer need the EOCD or CD.
    pub eocd_offset: u64,
    /// Number of central-directory entries.
    pub cd_entry_count: u32,
    /// Size of the central directory in bytes.
    pub cd_size: u64,
    /// Byte offset within the archive where the central directory
    /// begins.
    pub cd_offset: u64,
}

/// Parsed central-directory entry.
///
/// Field semantics match the APPNOTE; round-one preserves only the
/// fields the pipeline reads. `disk_start` and `cd_start_disk` are
/// validated at parse time (must both be `0`) but not stored.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CentralDirectoryEntry {
    /// UTF-8 filename. Slashes are kept as-is for path resolution; the
    /// extractor's path-safety check rejects absolute paths and
    /// `..` components.
    pub name: String,
    /// Compression method declared in the central directory; this is
    /// the value the LFH must agree with (`docs/PLAN_v2.md` §5
    /// step 4 cross-validates).
    pub method: CompressionMethod,
    /// General-purpose flag word.
    pub flags: GeneralPurposeFlags,
    /// CRC-32 of the *uncompressed* entry data. Authoritative — the
    /// LFH's CRC is zero when bit 3 is set.
    pub crc32: u32,
    /// Compressed size in bytes. Authoritative.
    pub compressed_size: u64,
    /// Uncompressed size in bytes. Authoritative.
    pub uncompressed_size: u64,
    /// Byte offset within the archive where the entry's local file
    /// header begins.
    pub lfh_offset: u64,
    /// Byte offset within the archive where this CDE begins. Used to
    /// punch the CDE region after the last entry is extracted.
    pub cde_offset: u64,
    /// On-wire size of this CDE record (fixed + name + extra +
    /// comment). The next CDE starts at `cde_offset + cde_size`.
    pub cde_size: u64,
}

impl CentralDirectoryEntry {
    /// Whether this entry's filename names a directory.
    ///
    /// PKWARE convention: directory entries end with `/` and have
    /// zero compressed/uncompressed size and method STORED. We accept
    /// the trailing-slash heuristic and let path-safety reject any
    /// bogus directory entries that smuggle data.
    #[must_use]
    pub fn is_directory(&self) -> bool {
        self.name.ends_with('/')
    }
}

/// Parsed local-file-header record.
///
/// `compressed_size`, `uncompressed_size`, and `crc32` are *not*
/// considered authoritative when the data-descriptor flag is set; the
/// pipeline cross-checks against the central directory's values
/// regardless.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LocalFileHeader {
    /// UTF-8 filename declared in the LFH. Must match the central
    /// directory's name.
    pub name: String,
    /// Compression method declared in the LFH. Must match the central
    /// directory.
    pub method: CompressionMethod,
    /// General-purpose flag word.
    pub flags: GeneralPurposeFlags,
    /// CRC-32 declared in the LFH. May be zero when
    /// [`GeneralPurposeFlags::has_data_descriptor`].
    pub crc32: u32,
    /// Compressed size declared in the LFH. May be zero when
    /// [`GeneralPurposeFlags::has_data_descriptor`].
    pub compressed_size: u64,
    /// Uncompressed size declared in the LFH. May be zero when
    /// [`GeneralPurposeFlags::has_data_descriptor`].
    pub uncompressed_size: u64,
    /// Byte offset, *relative to* `lfh_offset`, where the entry's
    /// compressed data begins. Equal to
    /// `LFH_FIXED_LEN + filename_len + extra_len`.
    pub data_offset_relative: u64,
}

/// Locate the EOCD record inside `tail`, where `tail` is a contiguous
/// slice of the archive's *final* `tail.len()` bytes and
/// `archive_total_size` is the archive's full byte length.
///
/// The search runs back-to-front looking for the EOCD signature
/// `0x06054b50`. The first candidate whose declared comment length
/// matches the bytes-after-the-record exactly is accepted.
///
/// # Errors
///
/// - [`ZipError::EocdNotFound`] when `tail` doesn't contain a valid
///   EOCD. Callers can retry with a larger window up to
///   [`MAX_EOCD_TAIL_BYTES`].
/// - [`ZipError::UnsupportedFeature`] when the EOCD's sentinel fields
///   indicate Zip64 (`cd_size`, `cd_offset`, or `cd_entry_count` ==
///   sentinel). Round-one does not implement the Zip64 locator.
/// - [`ZipError::MalformedHeader`] when the EOCD is internally
///   inconsistent (multi-disk, cd_offset past archive end, …).
pub fn find_eocd(tail: &[u8], archive_total_size: u64) -> Result<EndOfCentralDirectory, ZipError> {
    if tail.len() < EOCD_FIXED_LEN {
        return Err(ZipError::EocdNotFound {
            window: tail.len() as u64,
        });
    }
    // Earliest position the EOCD header could start at, given the
    // 22-byte fixed length. Walk backwards from there.
    let last_start = tail.len() - EOCD_FIXED_LEN;

    // The base byte offset within the archive corresponding to
    // `tail[0]`.
    let tail_start_in_archive = archive_total_size.saturating_sub(tail.len() as u64);

    for start in (0..=last_start).rev() {
        if read_u32(&tail[start..start + 4]) != SIGNATURE_EOCD {
            continue;
        }
        // Validate comment_length is consistent with how many bytes
        // remain after the fixed header. A spurious match elsewhere in
        // the archive (data section, comment text, …) usually fails
        // this check.
        let comment_len = read_u16(&tail[start + 20..start + 22]) as usize;
        let expected_total = start + EOCD_FIXED_LEN + comment_len;
        if expected_total != tail.len() {
            continue;
        }
        // Promising. Parse the rest.
        let disk_number = read_u16(&tail[start + 4..start + 6]);
        let cd_start_disk = read_u16(&tail[start + 6..start + 8]);
        let cd_entries_this_disk = read_u16(&tail[start + 8..start + 10]);
        let cd_entries_total = read_u16(&tail[start + 10..start + 12]);
        let cd_size = read_u32(&tail[start + 12..start + 16]);
        let cd_offset = read_u32(&tail[start + 16..start + 20]);

        let eocd_offset = tail_start_in_archive + start as u64;

        if disk_number != 0 || cd_start_disk != 0 {
            return Err(ZipError::UnsupportedFeature {
                feature: "multi-disk archive (split / spanned ZIP)".into(),
            });
        }
        if cd_entries_this_disk != cd_entries_total {
            return Err(ZipError::MalformedHeader {
                archive_offset: eocd_offset,
                reason: format!(
                    "EOCD: cd_entries_this_disk ({cd_entries_this_disk}) != \
                     cd_entries_total ({cd_entries_total})",
                ),
            });
        }
        if cd_entries_total == u16::MAX || cd_size == u32::MAX || cd_offset == u32::MAX {
            return Err(ZipError::UnsupportedFeature {
                feature: "Zip64 (entry count or central-directory size exceeds 32-bit limit)"
                    .into(),
            });
        }
        // CD must lie entirely within the archive and end where the
        // EOCD begins. PKWARE allows extra bytes between CD and EOCD
        // ("archive comment lives elsewhere") only through Zip64; in
        // a non-Zip64 archive the layout is tight.
        let cd_offset_u64 = u64::from(cd_offset);
        let cd_size_u64 = u64::from(cd_size);
        let cd_end =
            cd_offset_u64
                .checked_add(cd_size_u64)
                .ok_or_else(|| ZipError::MalformedHeader {
                    archive_offset: eocd_offset,
                    reason: "EOCD: cd_offset + cd_size overflows u64".into(),
                })?;
        if cd_end > eocd_offset {
            return Err(ZipError::MalformedHeader {
                archive_offset: eocd_offset,
                reason: format!("EOCD: cd ends at {cd_end} but EOCD begins at {eocd_offset}",),
            });
        }
        return Ok(EndOfCentralDirectory {
            eocd_offset,
            cd_entry_count: u32::from(cd_entries_total),
            cd_size: cd_size_u64,
            cd_offset: cd_offset_u64,
        });
    }

    Err(ZipError::EocdNotFound {
        window: tail.len() as u64,
    })
}

/// Parse the entire central directory.
///
/// `cd_bytes` must be exactly the byte range `[cd_offset, cd_offset +
/// cd_size)` from the archive. `cd_offset_in_archive` is that
/// `cd_offset` so the returned [`CentralDirectoryEntry`]s carry
/// archive-absolute offsets in their `cde_offset` field.
/// `expected_count` is the entry count the EOCD recorded; the parser
/// validates the actual count matches.
///
/// # Errors
///
/// Returns [`ZipError::Truncated`] when the buffer ends mid-record,
/// [`ZipError::BadSignature`] if a CDE signature doesn't match, and
/// [`ZipError::UnsupportedFeature`] / [`ZipError::MalformedHeader`]
/// for round-one refusals (Zip64 extras, multi-disk, etc.).
pub fn parse_central_directory(
    cd_bytes: &[u8],
    cd_offset_in_archive: u64,
    expected_count: u32,
) -> Result<Vec<CentralDirectoryEntry>, ZipError> {
    let mut entries = Vec::with_capacity(expected_count as usize);
    let mut cursor = 0usize;

    while cursor < cd_bytes.len() {
        if cd_bytes.len() - cursor < CDE_FIXED_LEN {
            return Err(ZipError::Truncated {
                reason: format!(
                    "central directory ends mid-CDE at offset {} (need {CDE_FIXED_LEN} bytes, \
                     have {})",
                    cursor,
                    cd_bytes.len() - cursor,
                ),
            });
        }
        let header = &cd_bytes[cursor..cursor + CDE_FIXED_LEN];
        let signature = read_u32(&header[0..4]);
        let cde_offset = cd_offset_in_archive + cursor as u64;
        if signature != SIGNATURE_CDE {
            return Err(ZipError::BadSignature {
                archive_offset: cde_offset,
                expected: SIGNATURE_CDE,
                found: signature,
            });
        }
        let _version_made_by = read_u16(&header[4..6]);
        let _version_needed = read_u16(&header[6..8]);
        let gp_flags = GeneralPurposeFlags(read_u16(&header[8..10]));
        let method_code = read_u16(&header[10..12]);
        let _mod_time = read_u16(&header[12..14]);
        let _mod_date = read_u16(&header[14..16]);
        let crc32 = read_u32(&header[16..20]);
        let compressed_size = read_u32(&header[20..24]);
        let uncompressed_size = read_u32(&header[24..28]);
        let filename_length = read_u16(&header[28..30]) as usize;
        let extra_length = read_u16(&header[30..32]) as usize;
        let comment_length = read_u16(&header[32..34]) as usize;
        let disk_start = read_u16(&header[34..36]);
        let _internal_attrs = read_u16(&header[36..38]);
        let _external_attrs = read_u32(&header[38..42]);
        let lfh_offset = read_u32(&header[42..46]);

        if disk_start != 0 {
            return Err(ZipError::UnsupportedFeature {
                feature: format!("multi-disk archive (entry references disk {disk_start} != 0)"),
            });
        }
        if compressed_size == u32::MAX || uncompressed_size == u32::MAX || lfh_offset == u32::MAX {
            return Err(ZipError::UnsupportedFeature {
                feature: "Zip64 (entry size or local-file-header offset exceeds 32-bit limit)"
                    .into(),
            });
        }
        if gp_flags.is_encrypted() {
            return Err(ZipError::UnsupportedFeature {
                feature: "traditional PKWARE encryption (general-purpose flag bit 0)".into(),
            });
        }
        if gp_flags.is_strong_encrypted() {
            return Err(ZipError::UnsupportedFeature {
                feature: "strong encryption (general-purpose flag bit 6, e.g. AES)".into(),
            });
        }

        let body_start = cursor + CDE_FIXED_LEN;
        let body_end = body_start
            .checked_add(filename_length)
            .and_then(|v| v.checked_add(extra_length))
            .and_then(|v| v.checked_add(comment_length))
            .ok_or_else(|| ZipError::MalformedHeader {
                archive_offset: cde_offset,
                reason: "CDE variable-length fields overflow usize".into(),
            })?;
        if body_end > cd_bytes.len() {
            return Err(ZipError::Truncated {
                reason: format!(
                    "CDE at archive offset {cde_offset} declares filename={filename_length} + \
                     extra={extra_length} + comment={comment_length} bytes, but only {} \
                     bytes remain in the central directory",
                    cd_bytes.len() - body_start,
                ),
            });
        }
        let name_bytes = &cd_bytes[body_start..body_start + filename_length];
        let name = std::str::from_utf8(name_bytes)
            .map_err(|e| ZipError::MalformedHeader {
                archive_offset: cde_offset,
                reason: format!("CDE filename is not valid UTF-8: {e}"),
            })?
            .to_string();

        let method = CompressionMethod::from_code(method_code);

        let cde_size = (CDE_FIXED_LEN + filename_length + extra_length + comment_length) as u64;
        entries.push(CentralDirectoryEntry {
            name,
            method,
            flags: gp_flags,
            crc32,
            compressed_size: u64::from(compressed_size),
            uncompressed_size: u64::from(uncompressed_size),
            lfh_offset: u64::from(lfh_offset),
            cde_offset,
            cde_size,
        });

        cursor = body_end;
    }

    if entries.len() != expected_count as usize {
        return Err(ZipError::MalformedHeader {
            archive_offset: cd_offset_in_archive,
            reason: format!(
                "EOCD declared {expected_count} entries, parsed {} from the central directory",
                entries.len(),
            ),
        });
    }
    Ok(entries)
}

impl LocalFileHeader {
    /// Parse a local file header from `bytes`, which begins at
    /// archive offset `lfh_archive_offset` (used purely for diagnostic
    /// context).
    ///
    /// The buffer must contain at least [`LFH_FIXED_LEN`] +
    /// `filename_length` + `extra_length` bytes; truncation surfaces
    /// as [`ZipError::Truncated`] so the caller can fetch a wider
    /// window and retry. The returned record's
    /// [`Self::data_offset_relative`] tells the caller where the
    /// compressed data begins.
    ///
    /// # Errors
    ///
    /// - [`ZipError::BadSignature`] when the four leading bytes are
    ///   not the LFH signature.
    /// - [`ZipError::Truncated`] when the buffer ends inside the
    ///   fixed header, the filename, or the extra field.
    /// - [`ZipError::UnsupportedFeature`] for encryption, Zip64
    ///   sentinels, etc., per the round-one refusal list.
    /// - [`ZipError::MalformedHeader`] when the filename is not valid
    ///   UTF-8.
    pub fn parse(bytes: &[u8], lfh_archive_offset: u64) -> Result<Self, ZipError> {
        if bytes.len() < LFH_FIXED_LEN {
            return Err(ZipError::Truncated {
                reason: format!(
                    "LFH at archive offset {lfh_archive_offset} needs {LFH_FIXED_LEN} bytes, \
                     have {}",
                    bytes.len(),
                ),
            });
        }
        let header = &bytes[..LFH_FIXED_LEN];
        let signature = read_u32(&header[0..4]);
        if signature != SIGNATURE_LFH {
            return Err(ZipError::BadSignature {
                archive_offset: lfh_archive_offset,
                expected: SIGNATURE_LFH,
                found: signature,
            });
        }
        let _version_needed = read_u16(&header[4..6]);
        let gp_flags = GeneralPurposeFlags(read_u16(&header[6..8]));
        let method_code = read_u16(&header[8..10]);
        let _mod_time = read_u16(&header[10..12]);
        let _mod_date = read_u16(&header[12..14]);
        let crc32 = read_u32(&header[14..18]);
        let compressed_size = read_u32(&header[18..22]);
        let uncompressed_size = read_u32(&header[22..26]);
        let filename_length = read_u16(&header[26..28]) as usize;
        let extra_length = read_u16(&header[28..30]) as usize;

        if gp_flags.is_encrypted() {
            return Err(ZipError::UnsupportedFeature {
                feature: "traditional PKWARE encryption (general-purpose flag bit 0)".into(),
            });
        }
        if gp_flags.is_strong_encrypted() {
            return Err(ZipError::UnsupportedFeature {
                feature: "strong encryption (general-purpose flag bit 6, e.g. AES)".into(),
            });
        }
        // Zip64 sentinels in the LFH are only meaningful when the
        // bit-3 data-descriptor flag is unset; with bit 3 set, the
        // LFH's size fields are zero by spec and the CD owns them.
        if !gp_flags.has_data_descriptor()
            && (compressed_size == u32::MAX || uncompressed_size == u32::MAX)
        {
            return Err(ZipError::UnsupportedFeature {
                feature: "Zip64 (LFH size fields use 32-bit sentinel)".into(),
            });
        }

        let body_end = LFH_FIXED_LEN
            .checked_add(filename_length)
            .and_then(|v| v.checked_add(extra_length))
            .ok_or_else(|| ZipError::MalformedHeader {
                archive_offset: lfh_archive_offset,
                reason: "LFH variable-length fields overflow usize".into(),
            })?;
        if bytes.len() < body_end {
            return Err(ZipError::Truncated {
                reason: format!(
                    "LFH at archive offset {lfh_archive_offset} declares filename={filename_length} \
                     + extra={extra_length} bytes, only {} bytes available",
                    bytes.len() - LFH_FIXED_LEN,
                ),
            });
        }
        let name_bytes = &bytes[LFH_FIXED_LEN..LFH_FIXED_LEN + filename_length];
        let name = std::str::from_utf8(name_bytes)
            .map_err(|e| ZipError::MalformedHeader {
                archive_offset: lfh_archive_offset,
                reason: format!("LFH filename is not valid UTF-8: {e}"),
            })?
            .to_string();
        let method = CompressionMethod::from_code(method_code);
        Ok(Self {
            name,
            method,
            flags: gp_flags,
            crc32,
            compressed_size: u64::from(compressed_size),
            uncompressed_size: u64::from(uncompressed_size),
            data_offset_relative: body_end as u64,
        })
    }

    /// Cross-validate this LFH against the central-directory entry
    /// the pipeline matched it to.
    ///
    /// Compression method and filename must match. Sizes and CRC are
    /// allowed to differ when the LFH had the data-descriptor flag
    /// set (in which case its size and CRC fields are zero by spec
    /// and the central directory's values are authoritative).
    ///
    /// # Errors
    ///
    /// Returns [`ZipError::LfhCdMismatch`] naming the field that
    /// disagreed.
    pub fn validate_against(&self, cd: &CentralDirectoryEntry) -> Result<(), ZipError> {
        if self.method.code() != cd.method.code() {
            return Err(ZipError::LfhCdMismatch {
                entry_name: cd.name.clone(),
                field: "compression_method",
                lfh: u64::from(self.method.code()),
                cd: u64::from(cd.method.code()),
            });
        }
        if self.name != cd.name {
            // For the name mismatch, surface "name disagreement" as a
            // dedicated MalformedHeader so the message is readable
            // without losing the structured shape.
            return Err(ZipError::MalformedHeader {
                archive_offset: 0,
                reason: format!(
                    "LFH filename {:?} does not match CDE filename {:?}",
                    self.name, cd.name
                ),
            });
        }
        if !self.flags.has_data_descriptor() {
            if self.compressed_size != cd.compressed_size {
                return Err(ZipError::LfhCdMismatch {
                    entry_name: cd.name.clone(),
                    field: "compressed_size",
                    lfh: self.compressed_size,
                    cd: cd.compressed_size,
                });
            }
            if self.uncompressed_size != cd.uncompressed_size {
                return Err(ZipError::LfhCdMismatch {
                    entry_name: cd.name.clone(),
                    field: "uncompressed_size",
                    lfh: self.uncompressed_size,
                    cd: cd.uncompressed_size,
                });
            }
            if self.crc32 != cd.crc32 {
                return Err(ZipError::LfhCdMismatch {
                    entry_name: cd.name.clone(),
                    field: "crc32",
                    lfh: u64::from(self.crc32),
                    cd: u64::from(cd.crc32),
                });
            }
        }
        Ok(())
    }
}

// ---- low-level wire helpers ------------------------------------------

fn read_u16(bytes: &[u8]) -> u16 {
    // INVARIANT: every caller slices a 2-byte window before calling.
    let mut a = [0u8; 2];
    a.copy_from_slice(&bytes[..2]);
    u16::from_le_bytes(a)
}

fn read_u32(bytes: &[u8]) -> u32 {
    // INVARIANT: every caller slices a 4-byte window before calling.
    let mut a = [0u8; 4];
    a.copy_from_slice(&bytes[..4]);
    u32::from_le_bytes(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tiny in-memory ZIP builder we use across these tests. Mirrors
    /// the test-fixture style used by `sink::tar::test_helpers` —
    /// keeping the corpus inside the test crate avoids any
    /// fixtures/ checked-in churn.
    pub(crate) struct ZipBuilder {
        out: Vec<u8>,
        entries: Vec<CdSpec>,
    }

    pub(crate) struct CdSpec {
        name: String,
        method: u16,
        flags: u16,
        crc32: u32,
        compressed_size: u32,
        uncompressed_size: u32,
        lfh_offset: u32,
    }

    impl ZipBuilder {
        pub(crate) fn new() -> Self {
            Self {
                out: Vec::new(),
                entries: Vec::new(),
            }
        }

        /// Append a STORED entry with the given raw bytes.
        pub(crate) fn add_stored(&mut self, name: &str, data: &[u8]) {
            self.add_entry(name, 0, 0, data, data, /*crc=*/ crc32_ieee(data));
        }

        /// Append a fully-pre-prepared entry: caller supplies the
        /// already-compressed bytes plus the original-size + crc.
        pub(crate) fn add_entry(
            &mut self,
            name: &str,
            method: u16,
            flags: u16,
            compressed: &[u8],
            uncompressed: &[u8],
            crc32: u32,
        ) {
            let lfh_offset = self.out.len() as u32;
            // LFH
            self.out.extend_from_slice(&SIGNATURE_LFH.to_le_bytes());
            self.out.extend_from_slice(&20u16.to_le_bytes()); // version_needed
            self.out.extend_from_slice(&flags.to_le_bytes());
            self.out.extend_from_slice(&method.to_le_bytes());
            self.out.extend_from_slice(&0u16.to_le_bytes()); // mtime
            self.out.extend_from_slice(&0u16.to_le_bytes()); // mdate
                                                             // If data-descriptor flag is set, the LFH's CRC + sizes
                                                             // are zero by spec and the data descriptor follows the
                                                             // compressed bytes. Otherwise they're authoritative
                                                             // (and equal the CD).
            let dd = flags & 0x0008 != 0;
            self.out
                .extend_from_slice(&(if dd { 0 } else { crc32 }).to_le_bytes());
            self.out
                .extend_from_slice(&(if dd { 0 } else { compressed.len() as u32 }).to_le_bytes());
            self.out
                .extend_from_slice(&(if dd { 0 } else { uncompressed.len() as u32 }).to_le_bytes());
            self.out
                .extend_from_slice(&(name.len() as u16).to_le_bytes());
            self.out.extend_from_slice(&0u16.to_le_bytes()); // extra
            self.out.extend_from_slice(name.as_bytes());
            self.out.extend_from_slice(compressed);
            if dd {
                // Optional signature, then crc + sizes.
                self.out
                    .extend_from_slice(&SIGNATURE_DATA_DESCRIPTOR.to_le_bytes());
                self.out.extend_from_slice(&crc32.to_le_bytes());
                self.out
                    .extend_from_slice(&(compressed.len() as u32).to_le_bytes());
                self.out
                    .extend_from_slice(&(uncompressed.len() as u32).to_le_bytes());
            }
            self.entries.push(CdSpec {
                name: name.to_string(),
                method,
                flags,
                crc32,
                compressed_size: compressed.len() as u32,
                uncompressed_size: uncompressed.len() as u32,
                lfh_offset,
            });
        }

        pub(crate) fn finish(mut self) -> Vec<u8> {
            let cd_offset = self.out.len() as u32;
            for spec in &self.entries {
                self.out.extend_from_slice(&SIGNATURE_CDE.to_le_bytes());
                self.out.extend_from_slice(&20u16.to_le_bytes()); // made_by
                self.out.extend_from_slice(&20u16.to_le_bytes()); // needed
                self.out.extend_from_slice(&spec.flags.to_le_bytes());
                self.out.extend_from_slice(&spec.method.to_le_bytes());
                self.out.extend_from_slice(&0u16.to_le_bytes()); // mtime
                self.out.extend_from_slice(&0u16.to_le_bytes()); // mdate
                self.out.extend_from_slice(&spec.crc32.to_le_bytes());
                self.out
                    .extend_from_slice(&spec.compressed_size.to_le_bytes());
                self.out
                    .extend_from_slice(&spec.uncompressed_size.to_le_bytes());
                self.out
                    .extend_from_slice(&(spec.name.len() as u16).to_le_bytes());
                self.out.extend_from_slice(&0u16.to_le_bytes()); // extra
                self.out.extend_from_slice(&0u16.to_le_bytes()); // comment
                self.out.extend_from_slice(&0u16.to_le_bytes()); // disk_start
                self.out.extend_from_slice(&0u16.to_le_bytes()); // internal_attrs
                self.out.extend_from_slice(&0u32.to_le_bytes()); // external_attrs
                self.out.extend_from_slice(&spec.lfh_offset.to_le_bytes());
                self.out.extend_from_slice(spec.name.as_bytes());
            }
            let cd_size = self.out.len() as u32 - cd_offset;
            // EOCD
            self.out.extend_from_slice(&SIGNATURE_EOCD.to_le_bytes());
            self.out.extend_from_slice(&0u16.to_le_bytes()); // disk_number
            self.out.extend_from_slice(&0u16.to_le_bytes()); // cd_start_disk
            self.out
                .extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
            self.out
                .extend_from_slice(&(self.entries.len() as u16).to_le_bytes());
            self.out.extend_from_slice(&cd_size.to_le_bytes());
            self.out.extend_from_slice(&cd_offset.to_le_bytes());
            self.out.extend_from_slice(&0u16.to_le_bytes()); // comment_length
            self.out
        }
    }

    /// Plain CRC-32-IEEE-802.3 (the variant the ZIP format uses).
    /// Hand-rolled to avoid pulling a crate just for tests.
    pub(crate) fn crc32_ieee(data: &[u8]) -> u32 {
        const POLY: u32 = 0xEDB8_8320;
        let mut table = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut j = 0;
            while j < 8 {
                if c & 1 != 0 {
                    c = (c >> 1) ^ POLY;
                } else {
                    c >>= 1;
                }
                j += 1;
            }
            table[i] = c;
            i += 1;
        }
        let mut crc = !0u32;
        for &b in data {
            crc = table[((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8);
        }
        !crc
    }

    #[test]
    fn compression_method_round_trips() {
        for code in [0u16, 8, 93, 1, 14, 99, 12345] {
            assert_eq!(CompressionMethod::from_code(code).code(), code);
        }
        assert_eq!(CompressionMethod::from_code(0), CompressionMethod::Stored);
        assert_eq!(CompressionMethod::from_code(8), CompressionMethod::Deflate);
        assert_eq!(CompressionMethod::from_code(93), CompressionMethod::Zstd);
    }

    #[test]
    fn compression_method_label_includes_code_for_unknown() {
        assert_eq!(CompressionMethod::Stored.label(), "STORED (0)");
        assert!(CompressionMethod::from_code(14).label().contains("LZMA"));
        assert!(CompressionMethod::from_code(99).label().contains("AES"));
        // A method we don't recognize at all still surfaces the code.
        assert!(CompressionMethod::from_code(7777).label().contains("7777"));
    }

    #[test]
    fn general_purpose_flags_decode_relevant_bits() {
        assert!(GeneralPurposeFlags(0x0001).is_encrypted());
        assert!(GeneralPurposeFlags(0x0008).has_data_descriptor());
        assert!(GeneralPurposeFlags(0x0040).is_strong_encrypted());
        assert!(GeneralPurposeFlags(0x0800).is_utf8());
        assert!(!GeneralPurposeFlags(0).is_encrypted());
        assert!(!GeneralPurposeFlags(0).has_data_descriptor());
    }

    #[test]
    fn find_eocd_locates_record_with_zero_comment() {
        let mut b = ZipBuilder::new();
        b.add_stored("a.txt", b"hello");
        let archive = b.finish();
        let total = archive.len() as u64;
        let eocd = find_eocd(&archive, total).expect("eocd");
        assert_eq!(eocd.cd_entry_count, 1);
        // The CD must lie before the EOCD.
        assert!(eocd.cd_offset + eocd.cd_size <= eocd.eocd_offset);
    }

    #[test]
    fn find_eocd_locates_record_with_max_comment() {
        // Build a minimal EOCD with a 1024-byte comment and verify
        // find_eocd ignores byte sequences inside the comment that
        // happen to look like the EOCD signature.
        let mut b = ZipBuilder::new();
        b.add_stored("a.txt", b"x");
        let mut archive = b.finish();
        // Strip the 22-byte EOCD with zero comment that finish()
        // emitted, replace with a hand-built one that has a comment.
        archive.truncate(archive.len() - EOCD_FIXED_LEN);
        // Re-run the builder so we can look up the CD offset/size
        // values that the auto-generated EOCD recorded; we'll splice
        // a hand-crafted EOCD with a comment in their place below.
        let mut b = ZipBuilder::new();
        b.add_stored("a.txt", b"x");
        let archive_no_comment = b.finish();
        let cd_offset = u32::from_le_bytes(
            archive_no_comment[archive_no_comment.len() - 6..archive_no_comment.len() - 2]
                .try_into()
                .unwrap(),
        );
        let cd_size = u32::from_le_bytes(
            archive_no_comment[archive_no_comment.len() - 10..archive_no_comment.len() - 6]
                .try_into()
                .unwrap(),
        );

        // Now re-encode an EOCD with a comment whose bytes include
        // the EOCD signature; the locator must not be tricked by it.
        let mut eocd = Vec::new();
        eocd.extend_from_slice(&SIGNATURE_EOCD.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes()); // disk
        eocd.extend_from_slice(&0u16.to_le_bytes()); // cd_start_disk
        eocd.extend_from_slice(&1u16.to_le_bytes()); // entries_this_disk
        eocd.extend_from_slice(&1u16.to_le_bytes()); // entries_total
        eocd.extend_from_slice(&cd_size.to_le_bytes());
        eocd.extend_from_slice(&cd_offset.to_le_bytes());

        let mut comment = vec![0u8; 1024];
        // Stamp a fake EOCD signature in the comment so the locator
        // would mis-detect it if it didn't validate comment_length.
        comment[100..104].copy_from_slice(&SIGNATURE_EOCD.to_le_bytes());
        // Plausible-but-bogus values for the fake EOCD's fields.
        comment[104..106].copy_from_slice(&0u16.to_le_bytes());
        comment[106..108].copy_from_slice(&0u16.to_le_bytes());
        comment[108..110].copy_from_slice(&1u16.to_le_bytes());
        comment[110..112].copy_from_slice(&1u16.to_le_bytes());
        comment[112..116].copy_from_slice(&0u32.to_le_bytes());
        comment[116..120].copy_from_slice(&0u32.to_le_bytes());
        comment[120..122].copy_from_slice(&0u16.to_le_bytes());

        eocd.extend_from_slice(&(comment.len() as u16).to_le_bytes());
        eocd.extend_from_slice(&comment);

        // Strip the auto-generated EOCD off `archive_no_comment` and
        // append the new one.
        let mut archive = archive_no_comment[..archive_no_comment.len() - EOCD_FIXED_LEN].to_vec();
        archive.extend_from_slice(&eocd);

        let total = archive.len() as u64;
        let eocd = find_eocd(&archive, total).expect("eocd");
        assert_eq!(eocd.cd_entry_count, 1);
    }

    #[test]
    fn find_eocd_returns_eocd_not_found_on_buffer_without_signature() {
        let buf = vec![0u8; 1024];
        match find_eocd(&buf, buf.len() as u64) {
            Err(ZipError::EocdNotFound { window }) => assert_eq!(window, 1024),
            other => panic!("expected EocdNotFound, got {other:?}"),
        }
    }

    #[test]
    fn find_eocd_rejects_zip64_sentinels() {
        // Hand-build an EOCD with cd_entries_total = 0xFFFF.
        let mut buf = Vec::new();
        buf.extend_from_slice(&SIGNATURE_EOCD.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk
        buf.extend_from_slice(&0u16.to_le_bytes()); // cd_start_disk
        buf.extend_from_slice(&u16::MAX.to_le_bytes()); // entries_this_disk
        buf.extend_from_slice(&u16::MAX.to_le_bytes()); // entries_total (sentinel)
        buf.extend_from_slice(&100u32.to_le_bytes()); // cd_size
        buf.extend_from_slice(&0u32.to_le_bytes()); // cd_offset
        buf.extend_from_slice(&0u16.to_le_bytes()); // comment_length
        match find_eocd(&buf, buf.len() as u64) {
            Err(ZipError::UnsupportedFeature { feature }) => assert!(feature.contains("Zip64")),
            other => panic!("expected UnsupportedFeature, got {other:?}"),
        }
    }

    #[test]
    fn find_eocd_rejects_multi_disk() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&SIGNATURE_EOCD.to_le_bytes());
        buf.extend_from_slice(&1u16.to_le_bytes()); // disk = 1
        buf.extend_from_slice(&1u16.to_le_bytes()); // cd_start_disk
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        match find_eocd(&buf, buf.len() as u64) {
            Err(ZipError::UnsupportedFeature { feature }) => {
                assert!(feature.contains("multi-disk"))
            }
            other => panic!("expected UnsupportedFeature, got {other:?}"),
        }
    }

    #[test]
    fn parse_central_directory_round_trips_two_entries() {
        let mut b = ZipBuilder::new();
        b.add_stored("a.txt", b"hello");
        b.add_stored("nested/b.bin", &[0x42u8; 64]);
        let archive = b.finish();

        let total = archive.len() as u64;
        let eocd = find_eocd(&archive, total).expect("eocd");
        let cd_bytes = &archive[eocd.cd_offset as usize..(eocd.cd_offset + eocd.cd_size) as usize];
        let entries =
            parse_central_directory(cd_bytes, eocd.cd_offset, eocd.cd_entry_count).expect("cd");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "a.txt");
        assert_eq!(entries[0].method, CompressionMethod::Stored);
        assert_eq!(entries[0].uncompressed_size, 5);
        assert_eq!(entries[1].name, "nested/b.bin");
        assert_eq!(entries[1].uncompressed_size, 64);
    }

    #[test]
    fn parse_central_directory_rejects_encrypted_entry() {
        let mut b = ZipBuilder::new();
        b.add_entry("secret.bin", 0, 0x0001, b"opaque", b"opaque", 0);
        let archive = b.finish();
        let total = archive.len() as u64;
        let eocd = find_eocd(&archive, total).expect("eocd");
        let cd_bytes = &archive[eocd.cd_offset as usize..(eocd.cd_offset + eocd.cd_size) as usize];
        match parse_central_directory(cd_bytes, eocd.cd_offset, eocd.cd_entry_count) {
            Err(ZipError::UnsupportedFeature { feature }) => assert!(feature.contains("PKWARE")),
            other => panic!("expected UnsupportedFeature, got {other:?}"),
        }
    }

    #[test]
    fn parse_central_directory_rejects_unknown_method_only_at_extract_time() {
        // We *parse* unknown methods successfully — the
        // UnsupportedFeature surfaces when the pipeline tries to
        // dispatch a decoder for the entry. The CDE just preserves
        // the wire code via CompressionMethod::Other(c).
        let mut b = ZipBuilder::new();
        b.add_entry("weird.bin", 12345, 0, b"opaque", b"opaque", 0);
        let archive = b.finish();
        let total = archive.len() as u64;
        let eocd = find_eocd(&archive, total).expect("eocd");
        let cd_bytes = &archive[eocd.cd_offset as usize..(eocd.cd_offset + eocd.cd_size) as usize];
        let entries =
            parse_central_directory(cd_bytes, eocd.cd_offset, eocd.cd_entry_count).expect("cd");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].method, CompressionMethod::Other(12345));
    }

    #[test]
    fn lfh_parse_round_trips_no_data_descriptor() {
        let mut b = ZipBuilder::new();
        b.add_stored("hello.txt", b"hello");
        let archive = b.finish();
        let total = archive.len() as u64;
        let eocd = find_eocd(&archive, total).expect("eocd");
        let cd_bytes = &archive[eocd.cd_offset as usize..(eocd.cd_offset + eocd.cd_size) as usize];
        let entries =
            parse_central_directory(cd_bytes, eocd.cd_offset, eocd.cd_entry_count).expect("cd");
        let cde = &entries[0];

        let lfh = LocalFileHeader::parse(&archive[cde.lfh_offset as usize..], cde.lfh_offset)
            .expect("lfh");
        assert_eq!(lfh.name, "hello.txt");
        assert_eq!(lfh.compressed_size, 5);
        assert_eq!(lfh.uncompressed_size, 5);
        lfh.validate_against(cde).expect("matches");
    }

    #[test]
    fn lfh_validate_detects_method_disagreement() {
        let mut b = ZipBuilder::new();
        b.add_stored("hello.txt", b"hello");
        let archive = b.finish();
        let total = archive.len() as u64;
        let eocd = find_eocd(&archive, total).expect("eocd");
        let cd_bytes = &archive[eocd.cd_offset as usize..(eocd.cd_offset + eocd.cd_size) as usize];
        let entries =
            parse_central_directory(cd_bytes, eocd.cd_offset, eocd.cd_entry_count).expect("cd");
        let cde = &entries[0];

        let mut tampered = archive.clone();
        // Flip the LFH's compression_method field (LFH offset 8..10) to 8 (DEFLATE).
        let m_off = cde.lfh_offset as usize + 8;
        tampered[m_off..m_off + 2].copy_from_slice(&8u16.to_le_bytes());

        let lfh = LocalFileHeader::parse(&tampered[cde.lfh_offset as usize..], cde.lfh_offset)
            .expect("lfh");
        match lfh.validate_against(cde) {
            Err(ZipError::LfhCdMismatch { field, .. }) => {
                assert_eq!(field, "compression_method");
            }
            other => panic!("expected LfhCdMismatch, got {other:?}"),
        }
    }

    #[test]
    fn lfh_parse_truncated_buffer_errors_truncated() {
        let mut b = ZipBuilder::new();
        b.add_stored("hello.txt", b"hello");
        let archive = b.finish();
        let total = archive.len() as u64;
        let eocd = find_eocd(&archive, total).expect("eocd");
        let cd_bytes = &archive[eocd.cd_offset as usize..(eocd.cd_offset + eocd.cd_size) as usize];
        let entries =
            parse_central_directory(cd_bytes, eocd.cd_offset, eocd.cd_entry_count).expect("cd");
        let cde = &entries[0];

        // Hand the parser only the first 20 bytes of the LFH.
        let buf = &archive[cde.lfh_offset as usize..cde.lfh_offset as usize + 20];
        match LocalFileHeader::parse(buf, cde.lfh_offset) {
            Err(ZipError::Truncated { .. }) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn lfh_parse_supports_data_descriptor_flag() {
        // Build an entry with the data-descriptor flag set; the LFH
        // size + crc fields are zero by spec, the descriptor follows
        // the data, and the CD owns the authoritative numbers.
        let mut b = ZipBuilder::new();
        let payload = b"some-bytes-here";
        b.add_entry("dd.txt", 0, 0x0008, payload, payload, crc32_ieee(payload));
        let archive = b.finish();
        let total = archive.len() as u64;
        let eocd = find_eocd(&archive, total).expect("eocd");
        let cd_bytes = &archive[eocd.cd_offset as usize..(eocd.cd_offset + eocd.cd_size) as usize];
        let entries =
            parse_central_directory(cd_bytes, eocd.cd_offset, eocd.cd_entry_count).expect("cd");
        let cde = &entries[0];

        let lfh = LocalFileHeader::parse(&archive[cde.lfh_offset as usize..], cde.lfh_offset)
            .expect("lfh");
        assert!(lfh.flags.has_data_descriptor());
        assert_eq!(lfh.compressed_size, 0);
        assert_eq!(lfh.uncompressed_size, 0);
        assert_eq!(lfh.crc32, 0);
        // validate_against should accept the disagreement because the
        // flag is set; the CD is authoritative.
        lfh.validate_against(cde).expect("dd validation passes");
    }

    #[test]
    fn cde_is_directory_uses_trailing_slash() {
        let mut b = ZipBuilder::new();
        b.add_stored("dir/", b"");
        b.add_stored("dir/file.txt", b"hi");
        let archive = b.finish();
        let total = archive.len() as u64;
        let eocd = find_eocd(&archive, total).expect("eocd");
        let cd_bytes = &archive[eocd.cd_offset as usize..(eocd.cd_offset + eocd.cd_size) as usize];
        let entries =
            parse_central_directory(cd_bytes, eocd.cd_offset, eocd.cd_entry_count).expect("cd");
        assert!(entries[0].is_directory());
        assert!(!entries[1].is_directory());
    }

    #[test]
    fn signature_constants_match_appnote_byte_order() {
        // The APPNOTE quotes signatures as ASCII "PK\x05\x06" etc.;
        // verify the u32 constants match when serialized
        // little-endian.
        assert_eq!(SIGNATURE_LFH.to_le_bytes(), *b"PK\x03\x04");
        assert_eq!(SIGNATURE_CDE.to_le_bytes(), *b"PK\x01\x02");
        assert_eq!(SIGNATURE_EOCD.to_le_bytes(), *b"PK\x05\x06");
        assert_eq!(SIGNATURE_DATA_DESCRIPTOR.to_le_bytes(), *b"PK\x07\x08");
        assert_eq!(SIGNATURE_ZIP64_EOCD.to_le_bytes(), *b"PK\x06\x06");
        assert_eq!(SIGNATURE_ZIP64_EOCD_LOCATOR.to_le_bytes(), *b"PK\x06\x07");
    }
}
