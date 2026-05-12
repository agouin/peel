//! RAR5 wire-format parsers.
//!
//! Hand-rolled per the dependency policy in
//! `docs/ENGINEERING_STANDARDS.md` §2.1 and the audit-trail
//! preference in `docs/PLAN_rar.md` §1. Every parser is pure: input
//! goes in as a byte slice, output comes out as a typed struct, and
//! no IO happens here. Higher layers (the §3 pipeline) drive ranged
//! reads and feed the right bytes to the right parser.
//!
//! # Layout reference (RAR5 only)
//!
//! All multi-byte integers are little-endian. The reference is the
//! "RAR 5.0 archive format" technote (`technote.txt` /
//! <https://www.rarlab.com/technote.htm>); sections this module
//! leans on most:
//!
//! - **Variable length integer** (vint).
//! - **General archive layout**: every block is a generic header
//!   optionally followed by a data area.
//! - **Main archive header** (header type 1).
//! - **File header** (header type 2).
//! - **Service header** (header type 3, skipped in round-one).
//! - **Archive encryption header** (header type 4, refused in
//!   round-one — `RarError::UnsupportedFeature`).
//! - **End of archive header** (header type 5).
//!
//! ```text
//! 8 bytes   RAR5 magic            52 61 72 21 1A 07 01 00
//! ───────── start of first generic header ─────────
//! 4 bytes   Header CRC32          CRC-32-IEEE of [size vint + body]
//! vint      Header size           length of body, in bytes
//! body[Header size]:
//!   vint      Header type
//!   vint      Header flags
//!   [vint]    Extra area size       (only if Header flags bit 0)
//!   [vint]    Data size             (only if Header flags bit 1)
//!   ...       Type-specific fields  (variable length)
//!   [bytes]   Extra area at the end (Extra area size bytes)
//! [Data size bytes following the header]
//! ───────── end of first header ─────────
//! ... more generic headers until type 5 (End of archive) ...
//! ```
//!
//! The CRC32 covers the bytes from the start of the size vint up
//! through the end of the extra area (i.e., everything that comes
//! after the CRC32 field itself, of length `vint_size + body`).
//!
//! # Sentinel rejections
//!
//! Per `docs/PLAN_rar.md` §0, round-one surfaces specific
//! diagnostics for:
//!
//! - **RAR4 magic** at offset 0 (7-byte `Rar!\x1A\x07\x00`):
//!   [`crate::rar::RarError::UnsupportedFormatVersion`].
//! - **Multi-volume** main archive flag (`MHD_VOLUME`):
//!   [`crate::rar::RarError::UnsupportedFeature`] naming the volume
//!   number.
//! - **Encryption** header type (4):
//!   [`crate::rar::RarError::Encryption`] carrying
//!   [`crate::encryption::EncryptionError::UnsupportedCipher`] (peel
//!   parses the encryption header via [`crate::rar::encrypt`] but
//!   does not yet decrypt the subsequent header stream).

use crate::rar::error::RarError;
use crate::zip::crc32;

/// RAR4 magic at offset 0 of every legacy RAR (pre-2013) archive.
/// Detected purely so [`parse_signature`] can surface a precise
/// [`RarError::UnsupportedFormatVersion`] diagnostic instead of a
/// generic [`RarError::BadSignature`]. Round-one of `peel`'s RAR
/// support is RAR5 only.
pub const RAR4_SIGNATURE_MAGIC: [u8; 7] = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];

/// Maximum number of bytes a RAR5 vint can occupy on the wire.
///
/// 64-bit values need at most ⌈64/7⌉ = 10 bytes (nine 7-bit groups
/// plus a tenth byte that must contribute a single bit and clear
/// its continuation flag). Anything longer is malformed.
pub const VINT_MAX_BYTES: usize = 10;

/// Result of decoding a RAR5 vint from the front of a buffer.
///
/// The decoded value plus the number of bytes the codec consumed.
/// Pure value type so parser combinators can pass it around without
/// borrowing.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Vint {
    /// Decoded `u64`.
    pub value: u64,
    /// Number of bytes consumed from the input. `1 ≤ size ≤ 10`.
    pub size: usize,
}

impl Vint {
    /// Decode a vint from the start of `buf`.
    ///
    /// # Errors
    ///
    /// - [`RarError::Truncated`] if `buf` ends before the vint's
    ///   continuation flag clears (the parser needs more bytes).
    /// - [`RarError::CorruptHeader`] (`archive_offset = 0`) if the
    ///   encoded value would overflow `u64` (the 10th byte's high
    ///   bit is still set, or the 10th byte's value exceeds 1).
    pub fn decode(buf: &[u8]) -> Result<Self, RarError> {
        Self::decode_at(buf, 0)
    }

    /// Decode a vint from `buf`, reporting the failing byte offset
    /// as `archive_offset + relative_offset` if the decode aborts.
    ///
    /// Used by the generic-header parser, which has a non-zero
    /// archive offset for everything except the header at the very
    /// start of the archive.
    ///
    /// # Errors
    ///
    /// Same as [`Self::decode`], but [`RarError::CorruptHeader`]'s
    /// `archive_offset` is the supplied `archive_offset`.
    pub fn decode_at(buf: &[u8], archive_offset: u64) -> Result<Self, RarError> {
        let mut value: u64 = 0;
        for i in 0..VINT_MAX_BYTES {
            let byte = *buf.get(i).ok_or_else(|| RarError::Truncated {
                what: format!("vint byte {}", i + 1),
                needed: 1,
            })?;
            let payload = u64::from(byte & 0x7F);
            let shift = (i as u32) * 7;

            // The tenth byte (i == 9) is special. RAR5 caps vints at
            // 10 bytes, so if its continuation flag is still set the
            // input is overlong; if it terminates legally then only
            // payload values 0 or 1 fit in `u64` (shift = 63 lets a
            // single bit survive — bit 63 — and anything else
            // overflows). Check continuation first so the "exceeds
            // 10 bytes" diagnostic wins over "overflow" when both
            // would fire.
            if i == VINT_MAX_BYTES - 1 {
                if byte & 0x80 != 0 {
                    return Err(RarError::CorruptHeader {
                        archive_offset,
                        reason: "vint exceeds 10 bytes (continuation bit set \
                                 on byte 10)"
                            .to_string(),
                    });
                }
                if payload > 1 {
                    return Err(RarError::CorruptHeader {
                        archive_offset,
                        reason: format!(
                            "vint overflow: byte 10 ({:#04x}) would set bits \
                             past u64",
                            byte
                        ),
                    });
                }
            }

            value |= payload << shift;
            if byte & 0x80 == 0 {
                return Ok(Self { value, size: i + 1 });
            }
        }
        // Loop ran the full ten iterations without seeing a clear
        // continuation flag. The final-iteration branch above already
        // surfaces this case; reaching here is unreachable today, but
        // keep a defensive return to anchor the compiler's
        // type-check rather than panic.
        Err(RarError::CorruptHeader {
            archive_offset,
            reason: "vint exceeds 10 bytes (continuation bit set on byte 10)".to_string(),
        })
    }
}

/// RAR5 generic-header type code (header_type vint).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HeaderType {
    /// Main archive header. Carries archive-wide flags (solid,
    /// multi-volume, recovery, locked).
    MainArchive,
    /// File header. One per regular entry.
    File,
    /// Service header. Carries comments / quick-open / recovery
    /// records / similar; round-one skips them.
    Service,
    /// Archive encryption header. Round-one surfaces
    /// [`RarError::UnsupportedFeature`].
    ArchiveEncryption,
    /// End of archive marker.
    EndOfArchive,
    /// Unknown future header type. Whether the parser may skip it
    /// depends on header-flag bit `0x0010` (`SKIP_IF_UNKNOWN`); the
    /// generic-header layer surfaces the wire value so the caller
    /// can decide.
    Other(u64),
}

impl HeaderType {
    /// Decode the wire-level type code.
    #[must_use]
    pub fn from_code(code: u64) -> Self {
        match code {
            1 => Self::MainArchive,
            2 => Self::File,
            3 => Self::Service,
            4 => Self::ArchiveEncryption,
            5 => Self::EndOfArchive,
            other => Self::Other(other),
        }
    }
}

/// Generic-header common-flags bits shared by every header type.
pub mod hdr_flags {
    /// Extra area present at the end of the header body. Width is
    /// then carried by an extra-size vint between the data-size
    /// field and the type-specific fields.
    pub const EXTRA_AREA: u64 = 0x0001;
    /// Data area follows the header; size is carried by a
    /// data-size vint.
    pub const DATA_AREA: u64 = 0x0002;
    /// Block of unknown type may be skipped if this bit is set
    /// (forward-compat).
    pub const SKIP_IF_UNKNOWN: u64 = 0x0004;
    /// Block continues from previous volume.
    pub const SPLIT_BEFORE: u64 = 0x0008;
    /// Block continues into next volume.
    pub const SPLIT_AFTER: u64 = 0x0010;
    /// Block is a child of the previous file block (e.g. attached
    /// service record).
    pub const CHILD_BLOCK: u64 = 0x0020;
    /// Block depends on a preceding file block (e.g. patch).
    pub const INHERITED: u64 = 0x0040;
}

/// Decoded generic header.
///
/// The parser computes byte offsets and sizes; it does **not**
/// retain a slice into the input buffer. Callers index back into the
/// original buffer with `body_offset_in_input` and `body_size` to
/// reach the type-specific fields.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct GenericHeader {
    /// Byte offset of the header within the archive (the offset of
    /// the CRC32 field). Used in error messages.
    pub archive_offset: u64,
    /// CRC32 the header recorded for itself.
    pub recorded_crc32: u32,
    /// CRC32 the parser computed over `[size vint || body]`.
    pub computed_crc32: u32,
    /// Header type after wire decode.
    pub header_type: HeaderType,
    /// Common header flags (`hdr_flags::*`).
    pub header_flags: u64,
    /// Optional extra-area size (only present when
    /// `header_flags & hdr_flags::EXTRA_AREA != 0`).
    pub extra_area_size: Option<u64>,
    /// Optional data-area size (only present when
    /// `header_flags & hdr_flags::DATA_AREA != 0`).
    pub data_size: Option<u64>,
    /// Byte offset, in the input slice, at which the
    /// type-specific-fields region begins. Equals the start of the
    /// header body plus the bytes consumed by header_type +
    /// header_flags + optional extra_area_size + optional data_size.
    pub fields_offset_in_input: usize,
    /// Byte length of the type-specific-fields region. Equals
    /// `body_size - (extra_area_size as usize)` minus the bytes
    /// consumed by header_type + header_flags + extra_area_size +
    /// data_size vints, but precomputed here for the caller's
    /// convenience.
    pub fields_size: usize,
    /// Byte offset, in the input slice, at which the extra area
    /// begins. Only meaningful when `header_flags & EXTRA_AREA != 0`.
    pub extra_offset_in_input: usize,
    /// Byte length of the extra area at the end of the header body.
    /// Mirrors `extra_area_size.unwrap_or(0)`.
    pub extra_size_in_input: usize,
    /// Total bytes consumed from the input by this generic header
    /// alone (CRC32 + size vint + body). Excludes the data area;
    /// add `data_size.unwrap_or(0)` to step over a header *and* its
    /// trailing data.
    pub total_header_bytes: usize,
}

impl GenericHeader {
    /// Convenience: the byte offset, relative to the start of the
    /// archive, at which the data area begins. Returns `None` if no
    /// data area is present.
    #[must_use]
    pub fn data_area_archive_offset(&self) -> Option<u64> {
        if self.data_size.is_some() {
            Some(self.archive_offset + self.total_header_bytes as u64)
        } else {
            None
        }
    }

    /// Total bytes the header *and* its trailing data area occupy in
    /// the archive. Equals `total_header_bytes + data_size.unwrap_or(0)`.
    #[must_use]
    pub fn total_bytes_with_data(&self) -> u64 {
        self.total_header_bytes as u64 + self.data_size.unwrap_or(0)
    }

    /// Whether the header CRC32 the parser computed matches the
    /// CRC32 the header recorded for itself.
    #[must_use]
    pub fn crc32_ok(&self) -> bool {
        self.recorded_crc32 == self.computed_crc32
    }
}

/// Validate the RAR signature at the start of `buf` and return the
/// number of bytes the signature occupies.
///
/// `buf` must start at the very beginning of the archive (byte 0).
/// Returns `8` for a RAR5 magic, surfaces a typed error for RAR4 or
/// a non-RAR signature.
///
/// # Errors
///
/// - [`RarError::Truncated`] if `buf` is shorter than 8 bytes
///   (cannot disambiguate RAR4 vs RAR5 with fewer than that, since
///   the leading 7 bytes match RAR4 exactly).
/// - [`RarError::UnsupportedFormatVersion`] (`major: 4, minor: 0`)
///   if `buf` starts with the RAR4 magic.
/// - [`RarError::BadSignature`] if the leading bytes match neither
///   RAR4 nor RAR5.
pub fn parse_signature(buf: &[u8]) -> Result<usize, RarError> {
    // The first six bytes (`Rar!\x1A\x07`) are common to RAR4 and
    // RAR5; the discriminator lives at offset 6. RAR4's magic is
    // 7 bytes total (last byte `0x00`), RAR5's is 8 bytes
    // (`0x01 0x00`). We need at least 7 bytes to disambiguate.
    if buf.len() < RAR4_SIGNATURE_MAGIC.len() {
        return Err(RarError::Truncated {
            what: "RAR magic (need at least 7 bytes to disambiguate \
                   RAR4 vs RAR5)"
                .to_string(),
            needed: RAR4_SIGNATURE_MAGIC.len() - buf.len(),
        });
    }
    if buf[..RAR4_SIGNATURE_MAGIC.len()] == RAR4_SIGNATURE_MAGIC {
        return Err(RarError::UnsupportedFormatVersion { major: 4, minor: 0 });
    }
    if buf.len() < crate::rar::SIGNATURE_MAGIC.len() {
        return Err(RarError::Truncated {
            what: "RAR5 magic (8 bytes)".to_string(),
            needed: crate::rar::SIGNATURE_MAGIC.len() - buf.len(),
        });
    }
    if buf[..crate::rar::SIGNATURE_MAGIC.len()] == crate::rar::SIGNATURE_MAGIC {
        return Ok(crate::rar::SIGNATURE_MAGIC.len());
    }
    Err(RarError::BadSignature)
}

/// Parse a generic header from `buf`, treating its first byte as
/// living at byte offset `archive_offset` within the archive.
///
/// The returned [`GenericHeader`]'s offsets are relative to `buf`'s
/// start; callers that pass a slice deeper into the archive should
/// add the slice's start offset themselves to translate to absolute
/// archive offsets.
///
/// On success the parser has not advanced into the data area.
/// Callers wanting to skip past the header *and* its data area
/// should advance their cursor by [`GenericHeader::total_bytes_with_data`].
///
/// # Errors
///
/// - [`RarError::Truncated`] if any field falls off the end of `buf`.
/// - [`RarError::CorruptHeader`] for vint overflow, header_size = 0,
///   or extra_area_size + body underflow.
/// - [`RarError::HeaderCrc32Mismatch`] if the computed CRC32 over
///   `[size vint + body]` disagrees with the recorded value.
pub fn parse_generic_header(buf: &[u8], archive_offset: u64) -> Result<GenericHeader, RarError> {
    // CRC32: 4 little-endian bytes.
    if buf.len() < 4 {
        return Err(RarError::Truncated {
            what: "header CRC32 (4 bytes)".to_string(),
            needed: 4 - buf.len(),
        });
    }
    let recorded_crc32 = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);

    // Header size vint: width of the body, in bytes.
    let size_vint = Vint::decode_at(&buf[4..], archive_offset + 4)?;
    if size_vint.value == 0 {
        return Err(RarError::CorruptHeader {
            archive_offset,
            reason: "header size vint = 0; minimum legal header has type+flags".to_string(),
        });
    }
    let body_size: usize = size_vint
        .value
        .try_into()
        .map_err(|_| RarError::CorruptHeader {
            archive_offset,
            reason: format!(
                "header size {} exceeds usize on this platform",
                size_vint.value
            ),
        })?;

    let body_start = 4 + size_vint.size;
    let body_end = body_start
        .checked_add(body_size)
        .ok_or_else(|| RarError::CorruptHeader {
            archive_offset,
            reason: format!("header size {body_size} + crc/size prefix overflows usize"),
        })?;
    if buf.len() < body_end {
        return Err(RarError::Truncated {
            what: format!("header body ({body_size} bytes)"),
            needed: body_end - buf.len(),
        });
    }

    // CRC32 covers everything from the start of the size vint
    // through the end of the body (which already includes the
    // extra area at its tail).
    let computed_crc32 = crc32::ieee(&buf[4..body_end]);

    let body = &buf[body_start..body_end];
    let header_type_vint = Vint::decode_at(body, archive_offset + body_start as u64)?;
    let header_flags_vint = Vint::decode_at(
        &body[header_type_vint.size..],
        archive_offset + (body_start + header_type_vint.size) as u64,
    )?;

    let mut cursor = header_type_vint.size + header_flags_vint.size;
    let extra_area_size = if header_flags_vint.value & hdr_flags::EXTRA_AREA != 0 {
        let v = Vint::decode_at(
            &body[cursor..],
            archive_offset + (body_start + cursor) as u64,
        )?;
        cursor += v.size;
        Some(v.value)
    } else {
        None
    };
    let data_size = if header_flags_vint.value & hdr_flags::DATA_AREA != 0 {
        let v = Vint::decode_at(
            &body[cursor..],
            archive_offset + (body_start + cursor) as u64,
        )?;
        cursor += v.size;
        Some(v.value)
    } else {
        None
    };

    // Sanity: extra area must fit inside the body, and the
    // type-specific region (the gap between the variable-length
    // prefix vints and the trailing extra area) must be
    // non-negative.
    let extra_size_in_input: usize =
        extra_area_size
            .unwrap_or(0)
            .try_into()
            .map_err(|_| RarError::CorruptHeader {
                archive_offset,
                reason: format!(
                    "extra area size {} exceeds usize on this platform",
                    extra_area_size.unwrap_or(0)
                ),
            })?;
    if extra_size_in_input > body_size {
        return Err(RarError::CorruptHeader {
            archive_offset,
            reason: format!(
                "extra area size {extra_size_in_input} exceeds header body \
                 size {body_size}"
            ),
        });
    }
    let fields_offset_in_input = body_start + cursor;
    let trailer_start = body_end - extra_size_in_input;
    if trailer_start < fields_offset_in_input {
        return Err(RarError::CorruptHeader {
            archive_offset,
            reason: format!(
                "extra area size {extra_size_in_input} would overlap \
                 type-specific fields (body has {} bytes after vints, \
                 extra needs {extra_size_in_input})",
                body_size - cursor
            ),
        });
    }
    let fields_size = trailer_start - fields_offset_in_input;

    let header = GenericHeader {
        archive_offset,
        recorded_crc32,
        computed_crc32,
        header_type: HeaderType::from_code(header_type_vint.value),
        header_flags: header_flags_vint.value,
        extra_area_size,
        data_size,
        fields_offset_in_input,
        fields_size,
        extra_offset_in_input: trailer_start,
        extra_size_in_input,
        total_header_bytes: body_end,
    };

    if !header.crc32_ok() {
        return Err(RarError::HeaderCrc32Mismatch {
            archive_offset,
            expected: recorded_crc32,
            computed: computed_crc32,
        });
    }

    Ok(header)
}

/// Bits in the main archive header's `archive_flags` vint.
pub mod arc_flags {
    /// Archive is one volume of a multi-volume set.
    pub const VOLUME: u64 = 0x0001;
    /// Volume number field is present in the header body.
    pub const VOLUME_NUMBER: u64 = 0x0002;
    /// Solid archive: all files share one decompression context.
    pub const SOLID: u64 = 0x0004;
    /// Recovery record is present.
    pub const RECOVERY_RECORD: u64 = 0x0008;
    /// Archive is locked (the locking party intended it not to be
    /// modified). Informational only.
    pub const LOCKED: u64 = 0x0010;
}

/// Decoded archive-wide flags bitfield. Convenience over [`arc_flags`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct ArchiveFlags(pub u64);

impl ArchiveFlags {
    /// `true` iff the archive is one volume of a multi-volume set.
    #[must_use]
    pub fn is_volume(self) -> bool {
        self.0 & arc_flags::VOLUME != 0
    }
    /// `true` iff the volume_number field is present.
    #[must_use]
    pub fn has_volume_number(self) -> bool {
        self.0 & arc_flags::VOLUME_NUMBER != 0
    }
    /// `true` iff the archive is solid.
    #[must_use]
    pub fn is_solid(self) -> bool {
        self.0 & arc_flags::SOLID != 0
    }
    /// `true` iff a recovery record is present.
    #[must_use]
    pub fn has_recovery_record(self) -> bool {
        self.0 & arc_flags::RECOVERY_RECORD != 0
    }
    /// `true` iff the archive carries the "locked" advisory bit.
    #[must_use]
    pub fn is_locked(self) -> bool {
        self.0 & arc_flags::LOCKED != 0
    }
}

/// Decoded main-archive-header (header type 1).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MainArchiveHeader {
    /// Archive-wide flags. See [`ArchiveFlags`].
    pub archive_flags: ArchiveFlags,
    /// Volume number, when [`ArchiveFlags::has_volume_number`].
    pub volume_number: Option<u64>,
}

/// Parse the body of a main-archive header (header type 1).
///
/// `header` must be a [`GenericHeader`] previously returned by
/// [`parse_generic_header`] for this header; `body` is the input
/// slice that was fed to that parser. The function indexes into
/// `body` using the offsets recorded on `header`.
///
/// # Errors
///
/// - [`RarError::CorruptHeader`] if the type-specific-fields region
///   underruns expected vints.
/// - [`RarError::Truncated`] if a vint runs past the fields region.
pub fn parse_main_archive_header(
    header: &GenericHeader,
    buf: &[u8],
) -> Result<MainArchiveHeader, RarError> {
    debug_assert!(matches!(header.header_type, HeaderType::MainArchive));
    let fields =
        &buf[header.fields_offset_in_input..header.fields_offset_in_input + header.fields_size];
    let archive_flags_vint = Vint::decode_at(
        fields,
        header.archive_offset + header.fields_offset_in_input as u64,
    )?;
    let archive_flags = ArchiveFlags(archive_flags_vint.value);
    let volume_number = if archive_flags.has_volume_number() {
        let v = Vint::decode_at(
            &fields[archive_flags_vint.size..],
            header.archive_offset
                + (header.fields_offset_in_input + archive_flags_vint.size) as u64,
        )?;
        Some(v.value)
    } else {
        None
    };
    Ok(MainArchiveHeader {
        archive_flags,
        volume_number,
    })
}

/// Bits in a file header's `file_flags` vint.
pub mod file_flags {
    /// Entry is a directory rather than a regular file.
    pub const DIRECTORY: u64 = 0x0001;
    /// File modification time is recorded as a `u32` Unix time
    /// after the attributes vint.
    pub const TIME_PRESENT: u64 = 0x0002;
    /// Unpacked-data CRC32 is recorded after the optional time.
    pub const CRC32_PRESENT: u64 = 0x0004;
    /// Unpacked size is unknown at archive-creation time (e.g. the
    /// archive was streamed). Round-one rejects this — the §3
    /// pipeline needs the size up front to size sinks.
    pub const UNPACKED_SIZE_UNKNOWN: u64 = 0x0008;
}

/// Decoded file-header file-flags bitfield. Convenience over
/// [`file_flags`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FileFlags(pub u64);

impl FileFlags {
    /// `true` iff the entry is a directory.
    #[must_use]
    pub fn is_directory(self) -> bool {
        self.0 & file_flags::DIRECTORY != 0
    }
    /// `true` iff a `u32` mtime follows the attributes vint.
    #[must_use]
    pub fn has_time(self) -> bool {
        self.0 & file_flags::TIME_PRESENT != 0
    }
    /// `true` iff a `u32` data CRC32 follows the (optional) mtime.
    #[must_use]
    pub fn has_data_crc32(self) -> bool {
        self.0 & file_flags::CRC32_PRESENT != 0
    }
    /// `true` iff the unpacked size is unknown. Round-one rejects.
    #[must_use]
    pub fn is_unpacked_size_unknown(self) -> bool {
        self.0 & file_flags::UNPACKED_SIZE_UNKNOWN != 0
    }
}

/// Decoded compression-information vint from a file header.
///
/// The wire encoding packs algorithm version, solid flag, method,
/// and dictionary-size selector into the low bits of a single vint.
/// Round-one cares about [`Self::method`] and [`Self::is_solid`];
/// callers that want the raw value find it in [`Self::raw`].
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CompressionInfo {
    /// The unmodified vint value.
    pub raw: u64,
}

impl CompressionInfo {
    /// Compression-algorithm version (bits 0..5). The only version
    /// this build understands is `0`.
    #[must_use]
    pub fn version(self) -> u64 {
        self.raw & 0x3F
    }
    /// Per-file solid bit (bit 6). Mirrors the archive-wide
    /// `MHD_SOLID` flag for the entry; archives produced with
    /// `rar a -ma5 -s` set both.
    #[must_use]
    pub fn is_solid(self) -> bool {
        (self.raw >> 6) & 0x1 != 0
    }
    /// Compression-method code (bits 7..9).
    ///
    /// - `0` — STORED (no compression). Round-one §3 supports this.
    /// - `1..=5` — RAR5 standard algorithm at compression levels
    ///   "fastest" through "best". Round-one §4 will support these
    ///   via the hand-rolled decoder in `PLAN_rar5_decoder.md`.
    /// - `6..=7` — reserved by the format spec.
    #[must_use]
    pub fn method(self) -> u64 {
        (self.raw >> 7) & 0x7
    }
    /// Dictionary-size selector (bits 10..13).
    ///
    /// `dict_size_bytes() = 128 KiB << selector`. Selectors `0..=14`
    /// land between 128 KiB and 2 GiB; bits 14..15 carry an
    /// extension introduced in RAR 5.6 that round-one does not yet
    /// fully decode.
    #[must_use]
    pub fn dict_size_selector(self) -> u64 {
        (self.raw >> 10) & 0xF
    }
}

/// Decoded file header (header type 2). Round-one §1 captures the
/// metadata; §3 / §4 add the per-entry extraction loop.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FileHeader {
    /// File flags. See [`FileFlags`].
    pub file_flags: FileFlags,
    /// Decompressed size, in bytes. Round-one rejects entries
    /// whose [`FileFlags::is_unpacked_size_unknown`] is set.
    pub unpacked_size: u64,
    /// Host-OS attribute bits. Interpretation depends on
    /// [`Self::host_os`].
    pub attributes: u64,
    /// Modification time (Unix `time_t`, seconds since the epoch),
    /// when [`FileFlags::has_time`].
    pub mtime: Option<u32>,
    /// CRC32 of the unpacked data, when [`FileFlags::has_data_crc32`].
    pub crc32: Option<u32>,
    /// Decoded compression-info vint.
    pub compression: CompressionInfo,
    /// Host OS code (`0` = Windows, `1` = Unix).
    pub host_os: u64,
    /// Entry name as recorded in the header. UTF-8 only — round-one
    /// rejects names that fail UTF-8 decode with
    /// [`RarError::BadName`]. Path-safety validation (the
    /// `..` / absolute-path / NUL checks) lives in the §3 sink.
    pub name: String,
}

/// Parse the body of a file header (header type 2).
///
/// `header` must be a [`GenericHeader`] previously returned by
/// [`parse_generic_header`] for this header; `buf` is the input
/// slice that was fed to that parser.
///
/// # Errors
///
/// - [`RarError::CorruptHeader`] / [`RarError::Truncated`] for
///   wire-format mishaps inside the header.
/// - [`RarError::BadName`] if the entry name is not valid UTF-8.
/// - [`RarError::UnsupportedFeature`] (`"unknown unpacked size"`)
///   if the unpacked-size-unknown bit is set.
pub fn parse_file_header(header: &GenericHeader, buf: &[u8]) -> Result<FileHeader, RarError> {
    debug_assert!(matches!(header.header_type, HeaderType::File));
    let fields =
        &buf[header.fields_offset_in_input..header.fields_offset_in_input + header.fields_size];
    let mut cursor: usize = 0;

    let file_flags_vint = Vint::decode_at(
        &fields[cursor..],
        header.archive_offset + (header.fields_offset_in_input + cursor) as u64,
    )?;
    cursor += file_flags_vint.size;
    let file_flags = FileFlags(file_flags_vint.value);

    let unpacked_size_vint = Vint::decode_at(
        &fields[cursor..],
        header.archive_offset + (header.fields_offset_in_input + cursor) as u64,
    )?;
    cursor += unpacked_size_vint.size;

    if file_flags.is_unpacked_size_unknown() {
        return Err(RarError::UnsupportedFeature {
            feature: "RAR file with unknown unpacked size (streaming-created \
                      archive)"
                .to_string(),
        });
    }

    let attributes_vint = Vint::decode_at(
        &fields[cursor..],
        header.archive_offset + (header.fields_offset_in_input + cursor) as u64,
    )?;
    cursor += attributes_vint.size;

    let mtime = if file_flags.has_time() {
        if cursor + 4 > fields.len() {
            return Err(RarError::Truncated {
                what: "file header mtime (4 bytes)".to_string(),
                needed: cursor + 4 - fields.len(),
            });
        }
        let t = u32::from_le_bytes([
            fields[cursor],
            fields[cursor + 1],
            fields[cursor + 2],
            fields[cursor + 3],
        ]);
        cursor += 4;
        Some(t)
    } else {
        None
    };

    let crc32 = if file_flags.has_data_crc32() {
        if cursor + 4 > fields.len() {
            return Err(RarError::Truncated {
                what: "file header data-CRC32 (4 bytes)".to_string(),
                needed: cursor + 4 - fields.len(),
            });
        }
        let c = u32::from_le_bytes([
            fields[cursor],
            fields[cursor + 1],
            fields[cursor + 2],
            fields[cursor + 3],
        ]);
        cursor += 4;
        Some(c)
    } else {
        None
    };

    let comp_info_vint = Vint::decode_at(
        &fields[cursor..],
        header.archive_offset + (header.fields_offset_in_input + cursor) as u64,
    )?;
    cursor += comp_info_vint.size;
    let compression = CompressionInfo {
        raw: comp_info_vint.value,
    };

    let host_os_vint = Vint::decode_at(
        &fields[cursor..],
        header.archive_offset + (header.fields_offset_in_input + cursor) as u64,
    )?;
    cursor += host_os_vint.size;

    let name_len_vint = Vint::decode_at(
        &fields[cursor..],
        header.archive_offset + (header.fields_offset_in_input + cursor) as u64,
    )?;
    cursor += name_len_vint.size;
    let name_len: usize = name_len_vint
        .value
        .try_into()
        .map_err(|_| RarError::CorruptHeader {
            archive_offset: header.archive_offset,
            reason: format!(
                "file name length {} exceeds usize on this platform",
                name_len_vint.value
            ),
        })?;
    if cursor + name_len > fields.len() {
        return Err(RarError::Truncated {
            what: format!("file header name ({name_len} bytes)"),
            needed: cursor + name_len - fields.len(),
        });
    }
    let name_bytes = &fields[cursor..cursor + name_len];
    let name = std::str::from_utf8(name_bytes)
        .map_err(|_| RarError::BadName {
            reason: "invalid UTF-8".to_string(),
        })?
        .to_owned();

    Ok(FileHeader {
        file_flags,
        unpacked_size: unpacked_size_vint.value,
        attributes: attributes_vint.value,
        mtime,
        crc32,
        compression,
        host_os: host_os_vint.value,
        name,
    })
}

/// End-of-archive header (header type 5). Carries one bit saying
/// whether a follow-on volume exists.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct EndOfArchiveHeader {
    /// `true` iff the archive is a volume followed by another.
    /// Round-one rejects multi-volume at the main-archive-header
    /// stage, so this is informational by the time we observe it.
    pub more_volumes: bool,
}

/// Parse the body of an end-of-archive header (header type 5).
///
/// # Errors
///
/// - [`RarError::CorruptHeader`] / [`RarError::Truncated`] for vint
///   mishaps.
pub fn parse_end_of_archive_header(
    header: &GenericHeader,
    buf: &[u8],
) -> Result<EndOfArchiveHeader, RarError> {
    debug_assert!(matches!(header.header_type, HeaderType::EndOfArchive));
    if header.fields_size == 0 {
        return Ok(EndOfArchiveHeader {
            more_volumes: false,
        });
    }
    let fields =
        &buf[header.fields_offset_in_input..header.fields_offset_in_input + header.fields_size];
    let flags = Vint::decode_at(
        fields,
        header.archive_offset + header.fields_offset_in_input as u64,
    )?;
    Ok(EndOfArchiveHeader {
        more_volumes: flags.value & 0x0001 != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: encode an unsigned 64-bit integer as a RAR5 vint.
    fn encode_vint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(VINT_MAX_BYTES);
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            if value == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    #[test]
    fn vint_round_trips_boundary_values() {
        for v in [
            0u64,
            1,
            127,
            128,
            255,
            16383,
            16384,
            1 << 14,
            1 << 21,
            1 << 28,
            1 << 35,
            1 << 56,
            1 << 63,
            u64::MAX,
        ] {
            let enc = encode_vint(v);
            let dec = Vint::decode(&enc).expect("vint round-trip");
            assert_eq!(dec.value, v, "wire {enc:02x?} decoded to {}", dec.value);
            assert_eq!(dec.size, enc.len(), "vint size mismatch for {v}");
        }
    }

    #[test]
    fn vint_truncated_on_short_buffer() {
        // 0xFF says "more bytes follow"; one byte alone is truncated.
        let err = Vint::decode(&[0xFF]).unwrap_err();
        assert!(matches!(err, RarError::Truncated { .. }), "got {err:?}");
    }

    #[test]
    fn vint_rejects_overlong_continuation() {
        // 10 bytes, all with continuation bit set, followed by no
        // terminator → must surface CorruptHeader.
        let buf = [0xFFu8; 10];
        let err = Vint::decode(&buf).unwrap_err();
        match err {
            RarError::CorruptHeader { reason, .. } => {
                assert!(reason.contains("10 bytes"), "got {reason}");
            }
            other => panic!("expected CorruptHeader, got {other:?}"),
        }
    }

    #[test]
    fn vint_rejects_overflow_in_tenth_byte() {
        // First nine bytes contribute zero, tenth byte payload is 2
        // (legal payload values: 0 or 1). Tenth byte clears the
        // continuation flag so it terminates cleanly — only the
        // overflow check should fire.
        let mut buf = vec![0x80u8; 9];
        buf.push(0x02);
        let err = Vint::decode(&buf).unwrap_err();
        match err {
            RarError::CorruptHeader { reason, .. } => {
                assert!(reason.contains("overflow"), "got {reason}");
            }
            other => panic!("expected CorruptHeader, got {other:?}"),
        }
    }

    #[test]
    fn parse_signature_accepts_rar5() {
        let bytes = crate::rar::SIGNATURE_MAGIC;
        assert_eq!(parse_signature(&bytes).unwrap(), 8);
    }

    #[test]
    fn parse_signature_rejects_rar4() {
        let err = parse_signature(&RAR4_SIGNATURE_MAGIC).unwrap_err();
        match err {
            RarError::UnsupportedFormatVersion { major, minor } => {
                assert_eq!(major, 4);
                assert_eq!(minor, 0);
            }
            other => panic!("expected UnsupportedFormatVersion, got {other:?}"),
        }
        // The RAR4 magic is only 7 bytes, so we feed a 7-byte
        // buffer here. With an 8th byte that is anything other than
        // 0x01, we should still get UnsupportedFormatVersion (the
        // RAR4 prefix wins). With 0x00 8th byte it remains RAR4.
        let mut buf8 = [0u8; 8];
        buf8[..7].copy_from_slice(&RAR4_SIGNATURE_MAGIC);
        buf8[7] = 0x42;
        let err = parse_signature(&buf8).unwrap_err();
        assert!(matches!(
            err,
            RarError::UnsupportedFormatVersion { major: 4, minor: 0 }
        ));
    }

    #[test]
    fn parse_signature_rejects_garbage() {
        let buf = [0u8; 8];
        let err = parse_signature(&buf).unwrap_err();
        assert!(matches!(err, RarError::BadSignature), "got {err:?}");
    }

    #[test]
    fn parse_signature_truncated() {
        let err = parse_signature(&[0x52, 0x61]).unwrap_err();
        assert!(matches!(err, RarError::Truncated { .. }), "got {err:?}");
    }

    /// Build a valid generic header with the given type, flags, and
    /// optional extra+data sizes plus type-specific bytes. Used by
    /// the parser tests below to round-trip header fixtures without
    /// invoking external tooling.
    fn build_generic_header(
        header_type: u64,
        header_flags: u64,
        type_specific: &[u8],
        extra_area: &[u8],
        data_area_size: Option<u64>,
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&encode_vint(header_type));
        body.extend_from_slice(&encode_vint(header_flags));
        let extra_present = header_flags & hdr_flags::EXTRA_AREA != 0;
        let data_present = header_flags & hdr_flags::DATA_AREA != 0;
        if extra_present {
            body.extend_from_slice(&encode_vint(extra_area.len() as u64));
        }
        if data_present {
            body.extend_from_slice(&encode_vint(data_area_size.unwrap_or(0)));
        }
        body.extend_from_slice(type_specific);
        if extra_present {
            body.extend_from_slice(extra_area);
        }
        let size_vint_bytes = encode_vint(body.len() as u64);
        let mut out = Vec::with_capacity(4 + size_vint_bytes.len() + body.len());
        out.extend_from_slice(&[0u8; 4]); // CRC32 placeholder
        out.extend_from_slice(&size_vint_bytes);
        out.extend_from_slice(&body);
        let crc = crc32::ieee(&out[4..]);
        out[..4].copy_from_slice(&crc.to_le_bytes());
        out
    }

    #[test]
    fn parse_generic_header_round_trips_main_archive() {
        let archive_flags = arc_flags::SOLID;
        let mut type_specific = Vec::new();
        type_specific.extend_from_slice(&encode_vint(archive_flags));
        let bytes = build_generic_header(1, 0, &type_specific, &[], None);
        let header = parse_generic_header(&bytes, 100).unwrap();
        assert_eq!(header.header_type, HeaderType::MainArchive);
        assert_eq!(header.header_flags, 0);
        assert_eq!(header.archive_offset, 100);
        assert!(header.crc32_ok());
        assert_eq!(header.data_size, None);
        let main = parse_main_archive_header(&header, &bytes).unwrap();
        assert!(main.archive_flags.is_solid());
        assert!(!main.archive_flags.is_volume());
        assert_eq!(main.volume_number, None);
    }

    #[test]
    fn parse_generic_header_handles_extra_area() {
        let mut type_specific = Vec::new();
        type_specific.extend_from_slice(&encode_vint(0)); // archive_flags
        let extra = [0xAA, 0xBB, 0xCC, 0xDD];
        let bytes = build_generic_header(1, hdr_flags::EXTRA_AREA, &type_specific, &extra, None);
        let header = parse_generic_header(&bytes, 0).unwrap();
        assert_eq!(header.extra_area_size, Some(extra.len() as u64));
        assert_eq!(header.extra_size_in_input, extra.len());
        assert_eq!(
            &bytes[header.extra_offset_in_input
                ..header.extra_offset_in_input + header.extra_size_in_input],
            &extra
        );
    }

    #[test]
    fn parse_generic_header_detects_crc_mismatch() {
        let mut bytes = build_generic_header(5, 0, &[0x00], &[], None);
        // Flip a byte inside the body (after the CRC32 prefix) to
        // invalidate the recorded CRC.
        let body_byte = bytes.len() - 1;
        bytes[body_byte] ^= 0x01;
        let err = parse_generic_header(&bytes, 0).unwrap_err();
        match err {
            RarError::HeaderCrc32Mismatch {
                archive_offset,
                expected,
                computed,
            } => {
                assert_eq!(archive_offset, 0);
                assert_ne!(expected, computed);
            }
            other => panic!("expected HeaderCrc32Mismatch, got {other:?}"),
        }
    }

    #[test]
    fn parse_file_header_decodes_basic_entry() {
        let unpacked_size: u64 = 1234;
        let attributes: u64 = 0x20;
        let mtime: u32 = 1_700_000_000;
        let data_crc32: u32 = 0xDEAD_BEEF;
        let comp_info: u64 =
            // version 0, solid bit clear, method 0 (STORED), dict selector 0
            0;
        let host_os: u64 = 1; // Unix
        let name = "hello.txt";
        let mut type_specific = Vec::new();
        type_specific.extend_from_slice(&encode_vint(
            file_flags::TIME_PRESENT | file_flags::CRC32_PRESENT,
        ));
        type_specific.extend_from_slice(&encode_vint(unpacked_size));
        type_specific.extend_from_slice(&encode_vint(attributes));
        type_specific.extend_from_slice(&mtime.to_le_bytes());
        type_specific.extend_from_slice(&data_crc32.to_le_bytes());
        type_specific.extend_from_slice(&encode_vint(comp_info));
        type_specific.extend_from_slice(&encode_vint(host_os));
        type_specific.extend_from_slice(&encode_vint(name.len() as u64));
        type_specific.extend_from_slice(name.as_bytes());

        let bytes = build_generic_header(2, 0, &type_specific, &[], None);
        let header = parse_generic_header(&bytes, 0).unwrap();
        assert_eq!(header.header_type, HeaderType::File);
        let file = parse_file_header(&header, &bytes).unwrap();
        assert_eq!(file.unpacked_size, unpacked_size);
        assert_eq!(file.attributes, attributes);
        assert_eq!(file.mtime, Some(mtime));
        assert_eq!(file.crc32, Some(data_crc32));
        assert_eq!(file.compression.method(), 0);
        assert!(!file.compression.is_solid());
        assert_eq!(file.host_os, host_os);
        assert_eq!(file.name, name);
        assert!(!file.file_flags.is_directory());
    }

    #[test]
    fn parse_file_header_rejects_unknown_unpacked_size() {
        let mut type_specific = Vec::new();
        type_specific.extend_from_slice(&encode_vint(file_flags::UNPACKED_SIZE_UNKNOWN));
        type_specific.extend_from_slice(&encode_vint(0)); // unpacked size
        type_specific.extend_from_slice(&encode_vint(0)); // attributes
        type_specific.extend_from_slice(&encode_vint(0)); // compression info
        type_specific.extend_from_slice(&encode_vint(0)); // host os
        type_specific.extend_from_slice(&encode_vint(1)); // name length
        type_specific.push(b'x');
        let bytes = build_generic_header(2, 0, &type_specific, &[], None);
        let header = parse_generic_header(&bytes, 0).unwrap();
        let err = parse_file_header(&header, &bytes).unwrap_err();
        match err {
            RarError::UnsupportedFeature { feature } => {
                assert!(feature.contains("unknown unpacked size"));
            }
            other => panic!("expected UnsupportedFeature, got {other:?}"),
        }
    }

    #[test]
    fn parse_file_header_rejects_invalid_utf8() {
        let mut type_specific = Vec::new();
        type_specific.extend_from_slice(&encode_vint(0)); // file flags
        type_specific.extend_from_slice(&encode_vint(0)); // unpacked size
        type_specific.extend_from_slice(&encode_vint(0)); // attributes
        type_specific.extend_from_slice(&encode_vint(0)); // compression info
        type_specific.extend_from_slice(&encode_vint(0)); // host os
        type_specific.extend_from_slice(&encode_vint(1)); // name length
        type_specific.push(0xFF); // invalid UTF-8 leading byte
        let bytes = build_generic_header(2, 0, &type_specific, &[], None);
        let header = parse_generic_header(&bytes, 0).unwrap();
        let err = parse_file_header(&header, &bytes).unwrap_err();
        match err {
            RarError::BadName { reason } => assert!(reason.contains("UTF-8")),
            other => panic!("expected BadName, got {other:?}"),
        }
    }

    #[test]
    fn parse_end_of_archive_decodes_more_volumes_flag() {
        let mut type_specific = Vec::new();
        type_specific.extend_from_slice(&encode_vint(0x0001));
        let bytes = build_generic_header(5, 0, &type_specific, &[], None);
        let header = parse_generic_header(&bytes, 0).unwrap();
        let eof = parse_end_of_archive_header(&header, &bytes).unwrap();
        assert!(eof.more_volumes);
    }

    #[test]
    fn parse_end_of_archive_with_empty_body() {
        // The minimum legal end-of-archive: type vint + flags vint = 0.
        // A body smaller than 2 bytes underflows the generic-header
        // parser, so feed exactly type + zero flags.
        let bytes = build_generic_header(5, 0, &[], &[], None);
        let header = parse_generic_header(&bytes, 0).unwrap();
        let eof = parse_end_of_archive_header(&header, &bytes).unwrap();
        assert!(!eof.more_volumes);
    }
}
