//! Legacy (RAR3 / RAR4) wire-format parser.
//!
//! Implements `docs/PLAN_rar3.md` §A1 — the hand-rolled header
//! layer for the legacy RAR archive format (WinRAR 1.5–4.x). Sibling
//! of [`crate::rar::format`]; the two share nothing wire-level
//! beyond the leading six magic bytes.
//!
//! # Layout sketch
//!
//! ```text
//! ┌──────── byte 0 ────────┐
//! │ 7-byte signature       │  Rar!\x1A\x07\x00 (the MARK_HEAD block,
//! │                        │  parsed as a fixed magic by [`parse_signature`]).
//! ├────────────────────────┤
//! │ Base block             │  Every header begins with this 7-byte struct:
//! │   head_crc (u16 LE)    │    low 16 bits of CRC-32 IEEE over the bytes
//! │                        │    from head_type onward.
//! │   head_type (u8)       │    0x72..0x7B; see [`BlockType`].
//! │   head_flags (u16 LE)  │    type-specific flags + LONG_BLOCK (0x8000) +
//! │                        │    OLD_NUMBERING (0x4000).
//! │   head_size (u16 LE)   │    total header size including head_crc.
//! ├────────────────────────┤
//! │ Optional add_size      │  u32 LE; present when LONG_BLOCK is set.
//! │   (u32 LE)             │  Size of the data area following the header.
//! ├────────────────────────┤
//! │ Type-specific body     │  MAIN_HEAD / FILE_HEAD / ENDARC_HEAD / …
//! ├────────────────────────┤
//! │ Optional data area     │  Present iff LONG_BLOCK; add_size bytes.
//! └────────────────────────┘
//! ```
//!
//! # Sentinel rejections
//!
//! Per `docs/PLAN_rar3.md` §0 round-one surfaces specific
//! diagnostics for:
//!
//! - **Pre-2.9 compression** (`unp_ver < 29`):
//!   [`crate::rar::RarError::UnsupportedFeature`] naming the version.
//! - **Multi-volume** main archive flag (`MHD_VOLUME`):
//!   [`crate::rar::RarError::UnsupportedFeature`] naming the volume.
//! - **Header / per-file encryption** (`MHD_PASSWORD` / `LHD_PASSWORD`):
//!   [`crate::rar::RarError::UnsupportedFeature`] = `"encryption (legacy)"`.

use crate::rar::error::RarError;
use crate::zip::crc32;

/// Legacy RAR magic at offset 0 of every RAR3/RAR4 archive
/// (`Rar!\x1A\x07\x00`).
///
/// Wire-level the seven bytes are themselves a degenerate
/// `MARK_HEAD` base block: `head_crc = 0x6152`, `head_type = 0x72`,
/// `head_flags = 0x1A21`, `head_size = 0x0007`. The CRC verifies, but
/// nothing in the parser depends on that fact — [`parse_signature`]
/// matches the magic byte-for-byte.
pub const LEGACY_SIGNATURE_MAGIC: [u8; 7] = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00];

/// Minimum supported `unp_ver` value (× 10) for round-one decode.
/// Corresponds to WinRAR 2.9 — the first version of the modern
/// RAR3 algorithm.
pub const MIN_SUPPORTED_UNP_VER: u8 = 29;

/// Maximum supported `unp_ver` value (× 10) for round-one decode.
/// Corresponds to WinRAR 3.6 / 4.x — the last version of the legacy
/// archive format. WinRAR 5.x bumped to a new format with a
/// different magic (see [`crate::rar::SIGNATURE_MAGIC`]) and is
/// handled by the sibling RAR5 path.
pub const MAX_SUPPORTED_UNP_VER: u8 = 36;

/// Method byte for STORED entries — direct byte copy, no
/// compression. `unp_size == pack_size` and the decoder is a plain
/// `memcpy` from packed to unpacked, so the `unp_ver` version gate
/// does not apply.
pub const STORED_METHOD: u8 = 0x30;

/// Length of the fixed base-block header in bytes.
const BASE_BLOCK_LEN: usize = 7;

/// Length of the optional `add_size` field appended to the base
/// block when the `LONG_BLOCK` flag is set.
const ADD_SIZE_LEN: usize = 4;

/// `head_flags` bit set when the header is followed by a data area
/// whose length is recorded by a 4-byte `add_size` field appended
/// to the base block.
const HEAD_FLAG_LONG_BLOCK: u16 = 0x8000;

/// Per-RAR-spec `head_type` byte values for legacy block types.
mod block_codes {
    pub const MARK: u8 = 0x72;
    pub const MAIN: u8 = 0x73;
    pub const FILE: u8 = 0x74;
    pub const COMM: u8 = 0x75;
    pub const AV: u8 = 0x76;
    pub const SUB: u8 = 0x77;
    pub const PROTECT: u8 = 0x78;
    pub const SIGN: u8 = 0x79;
    pub const NEWSUB: u8 = 0x7A;
    pub const ENDARC: u8 = 0x7B;
}

/// Decoded `head_type` byte. Block types not covered by round-one
/// parsing remain typed but their bodies are not parsed; callers
/// step over them by `total_bytes_with_data()`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BlockType {
    /// Signature block (`0x72`). Reachable only from
    /// [`parse_signature`]; [`parse_generic_header`] should never
    /// see it because the signature lives outside the generic-header
    /// stream.
    Mark,
    /// Main archive header (`0x73`).
    Main,
    /// File header (`0x74`).
    File,
    /// Old-style comment header (`0x75`); deprecated, skipped.
    Comment,
    /// Authenticity verification header (`0x76`); deprecated,
    /// skipped.
    AuthenticityVerification,
    /// Old-style subblock (`0x77`); skipped.
    Sub,
    /// Recovery-record header (`0x78`); skipped.
    Protect,
    /// Signature header (`0x79`); skipped.
    Sign,
    /// New-style subblock (`0x7A`); used by modern RAR3 archives for
    /// recovery records, ACLs, EAs, UID/GID. Skipped in round-one.
    NewSub,
    /// End-of-archive marker (`0x7B`).
    EndArchive,
    /// Unknown / future block type. Parser surfaces the wire byte so
    /// callers can decide whether to skip or fail.
    Other(u8),
}

impl BlockType {
    /// Decode the wire-level head_type byte.
    #[must_use]
    pub fn from_code(code: u8) -> Self {
        match code {
            block_codes::MARK => Self::Mark,
            block_codes::MAIN => Self::Main,
            block_codes::FILE => Self::File,
            block_codes::COMM => Self::Comment,
            block_codes::AV => Self::AuthenticityVerification,
            block_codes::SUB => Self::Sub,
            block_codes::PROTECT => Self::Protect,
            block_codes::SIGN => Self::Sign,
            block_codes::NEWSUB => Self::NewSub,
            block_codes::ENDARC => Self::EndArchive,
            other => Self::Other(other),
        }
    }
}

/// Decoded base-block header — the 7-byte struct that prefaces every
/// legacy RAR header (and the optional 4-byte `add_size` extension).
///
/// The parser computes byte offsets and sizes; like [`crate::rar::format::GenericHeader`]
/// it does not retain a slice into the input.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BaseBlock {
    /// Byte offset of the header within the archive (the offset of
    /// the `head_crc` field). Used in error messages and resume.
    pub archive_offset: u64,
    /// CRC-16 the header recorded for itself. Stored as `head_crc`
    /// in the wire format.
    pub recorded_crc16: u16,
    /// CRC-16 the parser computed over `head_size - 2` bytes
    /// starting at `head_type`. Always equals
    /// `(crc32::ieee(...) & 0xffff) as u16`.
    pub computed_crc16: u16,
    /// Block type after wire decode.
    pub block_type: BlockType,
    /// Wire-level head_flags. Type-specific bits live in the low 8;
    /// `0x8000` (`LONG_BLOCK`) and `0x4000` (`OLD_NUMBERING`) are
    /// shared across types.
    pub head_flags: u16,
    /// Total header size in bytes, as recorded by `head_size`.
    /// Includes the `head_crc` prefix and the optional `add_size`
    /// field. `BASE_BLOCK_LEN ≤ head_size`.
    pub head_size: u16,
    /// Optional data-area size. Present iff `head_flags & 0x8000`.
    pub add_size: Option<u32>,
    /// Byte offset, in the input slice, at which the type-specific
    /// fields begin (`BASE_BLOCK_LEN + 4` if `LONG_BLOCK`,
    /// `BASE_BLOCK_LEN` otherwise).
    pub fields_offset_in_input: usize,
    /// Byte length of the type-specific-fields region. Equals
    /// `head_size - fields_offset_in_input`.
    pub fields_size: usize,
}

impl BaseBlock {
    /// Whether the header CRC-16 the parser computed matches the
    /// CRC-16 the header recorded for itself.
    #[must_use]
    pub fn crc16_ok(&self) -> bool {
        self.recorded_crc16 == self.computed_crc16
    }

    /// Total bytes the header *and* its trailing data area occupy
    /// in the archive. Equals `head_size + add_size.unwrap_or(0)`.
    #[must_use]
    pub fn total_bytes_with_data(&self) -> u64 {
        u64::from(self.head_size) + u64::from(self.add_size.unwrap_or(0))
    }

    /// Byte offset, relative to the start of the archive, at which
    /// the data area begins. Returns `None` if no data area is
    /// present.
    #[must_use]
    pub fn data_area_archive_offset(&self) -> Option<u64> {
        self.add_size
            .map(|_| self.archive_offset + u64::from(self.head_size))
    }
}

/// Validate the legacy RAR signature at the start of `buf` and
/// return the number of bytes the signature occupies (always `7`).
///
/// `buf` must start at the very beginning of the archive (byte 0).
///
/// # Errors
///
/// - [`RarError::Truncated`] if `buf` is shorter than 7 bytes.
/// - [`RarError::BadSignature`] if the leading 7 bytes do not
///   match the legacy magic.
pub fn parse_signature(buf: &[u8]) -> Result<usize, RarError> {
    if buf.len() < LEGACY_SIGNATURE_MAGIC.len() {
        return Err(RarError::Truncated {
            what: "legacy RAR magic (7 bytes)".to_string(),
            needed: LEGACY_SIGNATURE_MAGIC.len() - buf.len(),
        });
    }
    if buf[..LEGACY_SIGNATURE_MAGIC.len()] == LEGACY_SIGNATURE_MAGIC {
        Ok(LEGACY_SIGNATURE_MAGIC.len())
    } else {
        Err(RarError::BadSignature)
    }
}

/// Parse a base-block header from `buf`, treating its first byte as
/// living at byte offset `archive_offset` within the archive.
///
/// The returned [`BaseBlock`] has not advanced into the data area;
/// callers wanting to skip past header *and* trailing data should
/// advance their cursor by [`BaseBlock::total_bytes_with_data`].
///
/// # Errors
///
/// - [`RarError::Truncated`] if any field falls off the end of `buf`.
/// - [`RarError::CorruptHeader`] if `head_size < 7` or the LONG_BLOCK
///   flag is set with `head_size < 11`.
/// - [`RarError::HeaderCrc16Mismatch`] if the computed CRC-16
///   disagrees with the recorded value.
pub fn parse_generic_header(buf: &[u8], archive_offset: u64) -> Result<BaseBlock, RarError> {
    if buf.len() < BASE_BLOCK_LEN {
        return Err(RarError::Truncated {
            what: format!("legacy base block ({BASE_BLOCK_LEN} bytes)"),
            needed: BASE_BLOCK_LEN - buf.len(),
        });
    }

    let recorded_crc16 = u16::from_le_bytes([buf[0], buf[1]]);
    let head_type_byte = buf[2];
    let head_flags = u16::from_le_bytes([buf[3], buf[4]]);
    let head_size = u16::from_le_bytes([buf[5], buf[6]]);

    if (head_size as usize) < BASE_BLOCK_LEN {
        return Err(RarError::CorruptHeader {
            archive_offset,
            reason: format!(
                "legacy header size {head_size} < {BASE_BLOCK_LEN} (minimum legal base block)"
            ),
        });
    }

    let has_add_size = (head_flags & HEAD_FLAG_LONG_BLOCK) != 0;
    let fields_offset_in_input = BASE_BLOCK_LEN + if has_add_size { ADD_SIZE_LEN } else { 0 };
    if (head_size as usize) < fields_offset_in_input {
        return Err(RarError::CorruptHeader {
            archive_offset,
            reason: format!(
                "legacy header size {head_size} < {fields_offset_in_input} \
                 (LONG_BLOCK requires room for add_size)"
            ),
        });
    }

    if buf.len() < head_size as usize {
        return Err(RarError::Truncated {
            what: format!("legacy header body ({head_size} bytes)"),
            needed: head_size as usize - buf.len(),
        });
    }

    let add_size = if has_add_size {
        Some(u32::from_le_bytes([buf[7], buf[8], buf[9], buf[10]]))
    } else {
        None
    };

    let crc_body = &buf[2..head_size as usize];
    let computed_crc16 = (crc32::ieee(crc_body) & 0xFFFF) as u16;
    if computed_crc16 != recorded_crc16 {
        return Err(RarError::HeaderCrc16Mismatch {
            archive_offset,
            expected: recorded_crc16,
            computed: computed_crc16,
        });
    }

    Ok(BaseBlock {
        archive_offset,
        recorded_crc16,
        computed_crc16,
        block_type: BlockType::from_code(head_type_byte),
        head_flags,
        head_size,
        add_size,
        fields_offset_in_input,
        fields_size: head_size as usize - fields_offset_in_input,
    })
}

/// Decoded archive-wide flags from `MAIN_HEAD.head_flags`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MainArchiveFlags(pub u16);

impl MainArchiveFlags {
    /// `MHD_VOLUME` — the archive is part of a multi-volume set.
    #[must_use]
    pub fn is_multi_volume(self) -> bool {
        self.0 & 0x0001 != 0
    }
    /// `MHD_LOCK` — the archive is locked (read-only metadata).
    #[must_use]
    pub fn is_locked(self) -> bool {
        self.0 & 0x0004 != 0
    }
    /// `MHD_SOLID` — the archive uses a single shared compression
    /// context across files.
    #[must_use]
    pub fn is_solid(self) -> bool {
        self.0 & 0x0008 != 0
    }
    /// `MHD_NEWNUMBERING` — multi-volume parts use `*.partN.rar`
    /// naming (instead of legacy `*.rNN`).
    #[must_use]
    pub fn uses_new_numbering(self) -> bool {
        self.0 & 0x0010 != 0
    }
    /// `MHD_AV` — authenticity verification block follows.
    #[must_use]
    pub fn has_av(self) -> bool {
        self.0 & 0x0020 != 0
    }
    /// `MHD_PROTECT` — recovery record present.
    #[must_use]
    pub fn has_recovery_record(self) -> bool {
        self.0 & 0x0040 != 0
    }
    /// `MHD_PASSWORD` — header-encryption is in use.
    #[must_use]
    pub fn is_encrypted(self) -> bool {
        self.0 & 0x0080 != 0
    }
    /// `MHD_FIRSTVOLUME` — set on volume 1 of a multi-volume set
    /// (3.0+). Meaningless without `MHD_VOLUME`.
    #[must_use]
    pub fn is_first_volume(self) -> bool {
        self.0 & 0x0100 != 0
    }
}

/// Decoded `MAIN_HEAD` (block type `0x73`).
///
/// Round-one consumes only the flag set; `high_pos_av` and `pos_av`
/// are reserved/legacy fields that nothing in the modern format
/// uses, so the parser reads them only to validate the structure.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MainArchiveHeader {
    /// Decoded archive flags.
    pub archive_flags: MainArchiveFlags,
}

/// Parse a `MAIN_HEAD` body.
///
/// `block` must be a [`BaseBlock`] previously returned by
/// [`parse_generic_header`] for this header; `buf` is the input
/// slice that was fed to that parser.
///
/// # Errors
///
/// - [`RarError::CorruptHeader`] if `block.block_type` is not
///   [`BlockType::Main`] (debug-only sanity check) or if the body
///   is structurally malformed.
/// - [`RarError::UnsupportedFeature`] if `MHD_VOLUME` or
///   `MHD_PASSWORD` is set.
pub fn parse_main_archive_header(
    block: &BaseBlock,
    buf: &[u8],
) -> Result<MainArchiveHeader, RarError> {
    debug_assert!(matches!(block.block_type, BlockType::Main));

    // The fixed body is 6 bytes (high_pos_av u16 + pos_av u32). We
    // do not retain the values — they're reserved in the modern
    // format. The check enforces the minimum size for a well-formed
    // MAIN_HEAD; older archives sometimes carry trailing padding,
    // which we accept and ignore.
    if block.fields_size < 6 {
        return Err(RarError::CorruptHeader {
            archive_offset: block.archive_offset,
            reason: format!(
                "MAIN_HEAD body {} bytes < 6 (high_pos_av + pos_av)",
                block.fields_size
            ),
        });
    }

    let archive_flags = MainArchiveFlags(block.head_flags);

    if archive_flags.is_multi_volume() {
        return Err(RarError::UnsupportedFeature {
            feature: "multi-volume legacy archive".to_string(),
        });
    }
    if archive_flags.is_encrypted() {
        return Err(RarError::UnsupportedFeature {
            feature: "encryption (legacy header)".to_string(),
        });
    }

    // Prevent the `unused` warning on `buf` while keeping the
    // parameter on the signature for future expansion (extra fields
    // when MHD_ENCRYPTVER is set, for example).
    let _ = buf;

    Ok(MainArchiveHeader { archive_flags })
}

/// Decoded per-entry flags from `FILE_HEAD.head_flags`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FileFlags(pub u16);

impl FileFlags {
    /// `LHD_SPLIT_BEFORE` — file continues from previous volume.
    #[must_use]
    pub fn is_split_before(self) -> bool {
        self.0 & 0x0001 != 0
    }
    /// `LHD_SPLIT_AFTER` — file continues into next volume.
    #[must_use]
    pub fn is_split_after(self) -> bool {
        self.0 & 0x0002 != 0
    }
    /// `LHD_PASSWORD` — file is per-entry encrypted.
    #[must_use]
    pub fn is_encrypted(self) -> bool {
        self.0 & 0x0004 != 0
    }
    /// `LHD_SOLID` — file uses the previous file's compression
    /// context (only meaningful with `MHD_SOLID`).
    #[must_use]
    pub fn is_solid(self) -> bool {
        self.0 & 0x0010 != 0
    }
    /// `LHD_LARGE` — packed/unpacked sizes use 64-bit fields.
    #[must_use]
    pub fn has_large_size(self) -> bool {
        self.0 & 0x0100 != 0
    }
    /// `LHD_UNICODE` — name field carries an ASCII name then a
    /// RAR-encoded unicode form.
    #[must_use]
    pub fn has_unicode_name(self) -> bool {
        self.0 & 0x0200 != 0
    }
    /// `LHD_SALT` — 8-byte salt follows the name.
    #[must_use]
    pub fn has_salt(self) -> bool {
        self.0 & 0x0400 != 0
    }
    /// `LHD_VERSION` — file is a versioned entry.
    #[must_use]
    pub fn is_versioned(self) -> bool {
        self.0 & 0x0800 != 0
    }
    /// `LHD_EXTTIME` — extended high-precision time stamps follow
    /// the name (and salt, if any).
    #[must_use]
    pub fn has_ext_time(self) -> bool {
        self.0 & 0x1000 != 0
    }
    /// Window size in bytes from bits 5..7 of head_flags. Returns
    /// `None` if the entry is a directory marker (bits 5..7 = 0b111
    /// = 0xE0).
    #[must_use]
    pub fn dictionary_size(self) -> Option<u32> {
        match (self.0 >> 5) & 0x7 {
            0 => Some(64 * 1024),
            1 => Some(128 * 1024),
            2 => Some(256 * 1024),
            3 => Some(512 * 1024),
            4 => Some(1024 * 1024),
            5 => Some(2 * 1024 * 1024),
            6 => Some(4 * 1024 * 1024),
            7 => None, // LHD_DIRECTORY
            _ => unreachable!(),
        }
    }
    /// `LHD_DIRECTORY` — the entry is a directory marker.
    #[must_use]
    pub fn is_directory(self) -> bool {
        (self.0 >> 5) & 0x7 == 7
    }
}

/// Decoded `FILE_HEAD` (block type `0x74`).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FileHeader {
    /// Per-entry flags.
    pub file_flags: FileFlags,
    /// Compressed (packed) size in bytes. Combines low and optional
    /// high 32 when `LHD_LARGE` is set.
    pub packed_size: u64,
    /// Decompressed (unpacked) size in bytes.
    pub unpacked_size: u64,
    /// Host-OS code recorded in the header.
    /// `0` = MS-DOS, `1` = OS/2, `2` = Win32, `3` = Unix,
    /// `4` = macOS, `5` = BeOS.
    pub host_os: u8,
    /// CRC-32 IEEE of the unpacked file data.
    pub file_crc32: u32,
    /// Modification time in MS-DOS packed format. The pipeline
    /// converts to a Unix timestamp at sink time.
    pub dos_mtime: u32,
    /// Compression-version × 10. Round-one rejects values outside
    /// `[MIN_SUPPORTED_UNP_VER, MAX_SUPPORTED_UNP_VER]` with
    /// [`RarError::UnsupportedFeature`].
    pub unp_ver: u8,
    /// Compression method (`0x30`..`0x35` — `m=0`..`m=5`).
    pub method: u8,
    /// File attribute bits. Interpretation depends on `host_os`.
    pub attributes: u32,
    /// Decoded entry name. `LHD_UNICODE` forms are decoded to UTF-8;
    /// pure-ASCII names (with or without the flag) round-trip
    /// unchanged.
    pub name: String,
}

/// Parse a `FILE_HEAD` body.
///
/// `block` must be a [`BaseBlock`] previously returned by
/// [`parse_generic_header`] for this header; `buf` is the input
/// slice that was fed to that parser.
///
/// # Errors
///
/// - [`RarError::Truncated`] / [`RarError::CorruptHeader`] for
///   wire-format mishaps inside the header.
/// - [`RarError::BadName`] if the entry name fails decoding or
///   path-safety checks.
/// - [`RarError::UnsupportedFeature`] if the entry is encrypted,
///   split across volumes, or uses an out-of-range `unp_ver`.
pub fn parse_file_header(block: &BaseBlock, buf: &[u8]) -> Result<FileHeader, RarError> {
    debug_assert!(matches!(block.block_type, BlockType::File));

    // FILE_HEAD always carries a data area, so LONG_BLOCK must be set.
    let pack_size_low = block.add_size.ok_or_else(|| RarError::CorruptHeader {
        archive_offset: block.archive_offset,
        reason: "FILE_HEAD without LONG_BLOCK (add_size missing)".to_string(),
    })?;

    let fields =
        &buf[block.fields_offset_in_input..block.fields_offset_in_input + block.fields_size];

    // Fixed-layout body. Minimum size 25 bytes:
    //   u32 unp_size_low
    //   u8  host_os
    //   u32 file_crc
    //   u32 ftime
    //   u8  unp_ver
    //   u8  method
    //   u16 name_size
    //   u32 attr
    if fields.len() < 25 {
        return Err(RarError::Truncated {
            what: "FILE_HEAD fixed body (25 bytes)".to_string(),
            needed: 25 - fields.len(),
        });
    }

    let file_flags = FileFlags(block.head_flags);
    if file_flags.is_encrypted() {
        return Err(RarError::UnsupportedFeature {
            feature: "encryption (legacy per-file)".to_string(),
        });
    }
    if file_flags.is_split_before() || file_flags.is_split_after() {
        return Err(RarError::UnsupportedFeature {
            feature: "multi-volume legacy archive (file split)".to_string(),
        });
    }

    let unp_size_low = u32::from_le_bytes([fields[0], fields[1], fields[2], fields[3]]);
    let host_os = fields[4];
    let file_crc32 = u32::from_le_bytes([fields[5], fields[6], fields[7], fields[8]]);
    let dos_mtime = u32::from_le_bytes([fields[9], fields[10], fields[11], fields[12]]);
    let unp_ver = fields[13];
    let method = fields[14];
    let name_size = u16::from_le_bytes([fields[15], fields[16]]) as usize;
    let attributes = u32::from_le_bytes([fields[17], fields[18], fields[19], fields[20]]);

    // Cursor past the fixed prefix.
    let mut cursor = 21;

    let (packed_size, unpacked_size) = if file_flags.has_large_size() {
        if cursor + 8 > fields.len() {
            return Err(RarError::Truncated {
                what: "FILE_HEAD high pack/unp sizes (8 bytes)".to_string(),
                needed: cursor + 8 - fields.len(),
            });
        }
        let high_pack = u32::from_le_bytes([
            fields[cursor],
            fields[cursor + 1],
            fields[cursor + 2],
            fields[cursor + 3],
        ]);
        let high_unp = u32::from_le_bytes([
            fields[cursor + 4],
            fields[cursor + 5],
            fields[cursor + 6],
            fields[cursor + 7],
        ]);
        cursor += 8;
        (
            (u64::from(high_pack) << 32) | u64::from(pack_size_low),
            (u64::from(high_unp) << 32) | u64::from(unp_size_low),
        )
    } else {
        (u64::from(pack_size_low), u64::from(unp_size_low))
    };

    if cursor + name_size > fields.len() {
        return Err(RarError::Truncated {
            what: format!("FILE_HEAD name ({name_size} bytes)"),
            needed: cursor + name_size - fields.len(),
        });
    }
    let name_bytes = &fields[cursor..cursor + name_size];

    // Trailing fields (`LHD_SALT`, `LHD_EXTTIME`, …) live inside
    // `head_size`; the base-block CRC already validated their
    // bytes, and the next call to parse_generic_header starts at
    // `block.archive_offset + block.total_bytes_with_data()`. We
    // do not need their contents in round-one (encrypted entries
    // have been rejected above; ext-time precision is finer than
    // the DOS mtime we keep, but the DOS field is sufficient for
    // the sink).

    // Reject out-of-range compression versions early so the pipeline
    // does not plan a download for an entry it cannot decode. The
    // version gate only applies to compressed methods — STORED
    // (`method == 0x30`) is a direct byte-copy, so `unp_ver` is
    // decorative and we accept any value. Real-world archives (and
    // the registered `rar` encoder when invoked with `-m0`) tag
    // STORED entries `unp_ver = 20` for backward compatibility with
    // pre-2.9 readers; rejecting them would refuse perfectly valid
    // STORED data.
    let name = decode_file_name(name_bytes, file_flags)?;
    if method != STORED_METHOD
        && !(MIN_SUPPORTED_UNP_VER..=MAX_SUPPORTED_UNP_VER).contains(&unp_ver)
    {
        return Err(RarError::UnsupportedFeature {
            feature: format!(
                "legacy RAR compression version {}.{} (unp_ver = {}); round-one supports {}.{}..{}.{} only",
                unp_ver / 10,
                unp_ver % 10,
                unp_ver,
                MIN_SUPPORTED_UNP_VER / 10,
                MIN_SUPPORTED_UNP_VER % 10,
                MAX_SUPPORTED_UNP_VER / 10,
                MAX_SUPPORTED_UNP_VER % 10,
            ),
        });
    }

    Ok(FileHeader {
        file_flags,
        packed_size,
        unpacked_size,
        host_os,
        file_crc32,
        dos_mtime,
        unp_ver,
        method,
        attributes,
        name,
    })
}

/// Decode a legacy `FILE_HEAD.name` field into UTF-8.
///
/// When `LHD_UNICODE` is **not** set, the field is interpreted as
/// raw bytes. Round-one accepts UTF-8 and ASCII-clean Latin-1 (any
/// byte ≤ 0x7F), and rejects anything else with
/// [`RarError::BadName`]. RAR3 archives produced by modern tools
/// always set `LHD_UNICODE` for non-ASCII names.
///
/// When `LHD_UNICODE` **is** set, the field is `<ascii_form>\0<encoded_utf16>`:
/// the leading ASCII run is a fallback used by old readers, and the
/// trailing form is RAR's bespoke UCS-2 encoding (per the format
/// technote / `unrar/encname.cpp`). We decode the UCS-2 form
/// preferentially. If the encoded form is missing (no `\0`
/// separator) we fall back to the leading ASCII run.
fn decode_file_name(buf: &[u8], flags: FileFlags) -> Result<String, RarError> {
    let raw = if !flags.has_unicode_name() {
        decode_ascii_name(buf)?
    } else {
        // Locate the NUL separator. If absent the field is just an
        // ASCII name with the unicode flag erroneously set; accept it.
        let nul = buf.iter().position(|&b| b == 0);
        match nul {
            None => decode_ascii_name(buf)?,
            Some(idx) => {
                let ascii_form = &buf[..idx];
                let encoded = &buf[idx + 1..];
                if encoded.is_empty() {
                    decode_ascii_name(ascii_form)?
                } else {
                    decode_unicode_name(ascii_form, encoded)
                        .or_else(|_| decode_ascii_name(ascii_form))?
                }
            }
        }
    };

    // RAR3's wire format uses DOS path separators ('\\') even when
    // the archive was authored on Unix (`host_os = 3`). The
    // RAR3 technote calls this out and unrar / libarchive both
    // translate to '/' before handing names to the OS. peel
    // mirrors that here so the sink layer can split on '/'
    // unconditionally and nested-directory entries land at the
    // right on-disk paths.
    Ok(raw.replace('\\', "/"))
}

/// Decode an unflagged FILE_HEAD name field. Accepts UTF-8 and
/// ASCII-clean Latin-1; rejects raw Latin-1 (any byte > 0x7F) so
/// callers do not silently mis-decode.
fn decode_ascii_name(buf: &[u8]) -> Result<String, RarError> {
    if buf.is_empty() {
        return Err(RarError::BadName {
            reason: "empty FILE_HEAD name".to_string(),
        });
    }
    if buf.contains(&0) {
        return Err(RarError::BadName {
            reason: "embedded NUL in FILE_HEAD name".to_string(),
        });
    }
    std::str::from_utf8(buf)
        .map(str::to_owned)
        .map_err(|_| RarError::BadName {
            reason: "FILE_HEAD name is not UTF-8 (round-one does not auto-detect non-Unicode \
                     legacy code pages; archives should set LHD_UNICODE for non-ASCII names)"
                .to_string(),
        })
}

/// Decode the bespoke UCS-2 encoding RAR uses when `LHD_UNICODE` is
/// set. Mirrors `unrar/encname.cpp::DecodeName` and libarchive's
/// reference implementation.
///
/// The state machine reads 2-bit groups from a flag byte, refilling
/// every 8 bits, and produces UCS-2 little-endian output. Output is
/// then converted to UTF-8 via [`String::from_utf16`].
fn decode_unicode_name(ascii_form: &[u8], encoded: &[u8]) -> Result<String, RarError> {
    if encoded.is_empty() {
        return Err(RarError::BadName {
            reason: "LHD_UNICODE name has empty encoded form".to_string(),
        });
    }
    let high_byte = u16::from(encoded[0]) << 8;
    let mut pos = 1usize;
    let mut flag_byte: u8 = 0;
    let mut flag_bits: u8 = 0;
    // Cap the output so a malicious archive cannot make us allocate
    // unbounded memory; 16 KiB of UCS-2 == 8 K codepoints == way more
    // than any reasonable file name.
    const MAX_DECODED_CHARS: usize = 8 * 1024;
    let mut out: Vec<u16> = Vec::with_capacity(ascii_form.len().min(64));

    while pos < encoded.len() && out.len() < MAX_DECODED_CHARS {
        if flag_bits == 0 {
            flag_byte = encoded[pos];
            pos += 1;
            flag_bits = 8;
            if pos >= encoded.len() && flag_byte != 0 {
                // Flag byte present but no payload — malformed.
                return Err(RarError::BadName {
                    reason: "LHD_UNICODE name truncated mid-flag".to_string(),
                });
            }
        }
        flag_bits -= 2;
        let mode = (flag_byte >> flag_bits) & 0b11;

        match mode {
            0 => {
                // Literal low byte (high == 0).
                if pos >= encoded.len() {
                    return Err(RarError::BadName {
                        reason: "LHD_UNICODE name truncated (mode 0)".to_string(),
                    });
                }
                out.push(u16::from(encoded[pos]));
                pos += 1;
            }
            1 => {
                // Low byte with shared high byte.
                if pos >= encoded.len() {
                    return Err(RarError::BadName {
                        reason: "LHD_UNICODE name truncated (mode 1)".to_string(),
                    });
                }
                out.push(high_byte | u16::from(encoded[pos]));
                pos += 1;
            }
            2 => {
                // 16-bit literal (low then high).
                if pos + 1 >= encoded.len() {
                    return Err(RarError::BadName {
                        reason: "LHD_UNICODE name truncated (mode 2)".to_string(),
                    });
                }
                let low = u16::from(encoded[pos]);
                let high = u16::from(encoded[pos + 1]);
                out.push((high << 8) | low);
                pos += 2;
            }
            3 => {
                // Run-length form: byte L; if L & 0x80, take 7-bit
                // length+2 + correction byte and emit chars sourced
                // from the ASCII form with a shared high byte; else
                // take length+2 ASCII-form chars verbatim (high == 0).
                if pos >= encoded.len() {
                    return Err(RarError::BadName {
                        reason: "LHD_UNICODE name truncated (mode 3 length)".to_string(),
                    });
                }
                let length_byte = encoded[pos];
                pos += 1;
                if length_byte & 0x80 != 0 {
                    if pos >= encoded.len() {
                        return Err(RarError::BadName {
                            reason: "LHD_UNICODE name truncated (mode 3 correction)".to_string(),
                        });
                    }
                    let correction = encoded[pos];
                    pos += 1;
                    let count = ((length_byte & 0x7F) as usize) + 2;
                    for _ in 0..count {
                        if out.len() >= MAX_DECODED_CHARS {
                            break;
                        }
                        let src = ascii_form.get(out.len()).copied().ok_or_else(|| {
                            RarError::BadName {
                                reason: "LHD_UNICODE name references ASCII byte beyond ASCII run"
                                    .to_string(),
                            }
                        })?;
                        let low = (u16::from(src) + u16::from(correction)) & 0xFF;
                        out.push(high_byte | low);
                    }
                } else {
                    let count = (length_byte as usize) + 2;
                    for _ in 0..count {
                        if out.len() >= MAX_DECODED_CHARS {
                            break;
                        }
                        let src = ascii_form.get(out.len()).copied().ok_or_else(|| {
                            RarError::BadName {
                                reason: "LHD_UNICODE name references ASCII byte beyond ASCII run"
                                    .to_string(),
                            }
                        })?;
                        out.push(u16::from(src));
                    }
                }
            }
            _ => unreachable!(),
        }
    }

    if out.is_empty() {
        return Err(RarError::BadName {
            reason: "LHD_UNICODE name decoded to empty string".to_string(),
        });
    }
    String::from_utf16(&out).map_err(|_| RarError::BadName {
        reason: "LHD_UNICODE name decoded to invalid UTF-16".to_string(),
    })
}

/// Decoded archive-end flags from `ENDARC_HEAD.head_flags`.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct EndarcFlags(pub u16);

impl EndarcFlags {
    /// `EARC_NEXT_VOLUME` — archive continues in next volume.
    #[must_use]
    pub fn has_next_volume(self) -> bool {
        self.0 & 0x0001 != 0
    }
    /// `EARC_DATACRC` — 4-byte archive-data CRC follows the base
    /// block.
    #[must_use]
    pub fn has_data_crc(self) -> bool {
        self.0 & 0x0002 != 0
    }
    /// `EARC_REVSPACE` — 7-byte recovery-space marker present.
    #[must_use]
    pub fn has_recovery_space(self) -> bool {
        self.0 & 0x0004 != 0
    }
    /// `EARC_VOLNUMBER` — 2-byte volume number follows.
    #[must_use]
    pub fn has_volume_number(self) -> bool {
        self.0 & 0x0008 != 0
    }
}

/// Decoded `ENDARC_HEAD` (block type `0x7B`).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct EndarcHeader {
    /// End-of-archive flags.
    pub endarc_flags: EndarcFlags,
}

/// Parse an `ENDARC_HEAD` body.
///
/// # Errors
///
/// [`RarError::CorruptHeader`] only on debug-mismatched block type.
pub fn parse_endarc_header(block: &BaseBlock, buf: &[u8]) -> Result<EndarcHeader, RarError> {
    debug_assert!(matches!(block.block_type, BlockType::EndArchive));
    // Optional fields are inside `head_size` and CRC-validated; we
    // don't need their values for round-one.
    let _ = buf;
    Ok(EndarcHeader {
        endarc_flags: EndarcFlags(block.head_flags),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a base-block header with the given fields and CRC-fix
    /// the `head_crc` slot. Returns the full bytes plus any caller-
    /// supplied trailing data.
    fn build_block(head_type: u8, head_flags: u16, body: &[u8], add_size: Option<u32>) -> Vec<u8> {
        let mut head_flags = head_flags;
        if add_size.is_some() {
            head_flags |= HEAD_FLAG_LONG_BLOCK;
        }
        let header_extra = if add_size.is_some() { 4 } else { 0 };
        let head_size = (BASE_BLOCK_LEN + header_extra + body.len()) as u16;
        let mut bytes = Vec::with_capacity(head_size as usize);
        bytes.extend_from_slice(&[0, 0]); // placeholder for head_crc
        bytes.push(head_type);
        bytes.extend_from_slice(&head_flags.to_le_bytes());
        bytes.extend_from_slice(&head_size.to_le_bytes());
        if let Some(add) = add_size {
            bytes.extend_from_slice(&add.to_le_bytes());
        }
        bytes.extend_from_slice(body);
        let crc16 = (crc32::ieee(&bytes[2..]) & 0xFFFF) as u16;
        bytes[0..2].copy_from_slice(&crc16.to_le_bytes());
        bytes
    }

    #[test]
    fn parse_signature_accepts_legacy_magic() {
        assert_eq!(parse_signature(&LEGACY_SIGNATURE_MAGIC).unwrap(), 7);
    }

    #[test]
    fn parse_signature_rejects_rar5_magic() {
        let rar5 = [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01];
        let err = parse_signature(&rar5).unwrap_err();
        assert!(matches!(err, RarError::BadSignature));
    }

    #[test]
    fn parse_signature_rejects_garbage() {
        assert!(matches!(
            parse_signature(b"hello!!").unwrap_err(),
            RarError::BadSignature
        ));
    }

    #[test]
    fn parse_signature_truncated() {
        let err = parse_signature(&[0x52, 0x61]).unwrap_err();
        assert!(matches!(err, RarError::Truncated { needed: 5, .. }));
    }

    #[test]
    fn parse_generic_header_round_trip_main() {
        // MAIN_HEAD body: 6-byte high_pos_av + pos_av reserved.
        let body = [0u8; 6];
        let bytes = build_block(block_codes::MAIN, 0x0008 /* MHD_SOLID */, &body, None);
        let block = parse_generic_header(&bytes, 100).expect("parses");
        assert_eq!(block.archive_offset, 100);
        assert_eq!(block.block_type, BlockType::Main);
        assert_eq!(block.head_flags, 0x0008);
        assert_eq!(block.head_size as usize, BASE_BLOCK_LEN + 6);
        assert!(block.crc16_ok());
        assert!(block.add_size.is_none());

        let header = parse_main_archive_header(&block, &bytes).expect("main parses");
        assert!(header.archive_flags.is_solid());
        assert!(!header.archive_flags.is_multi_volume());
    }

    #[test]
    fn parse_generic_header_rejects_short_buffer() {
        let buf = [0u8; 4];
        let err = parse_generic_header(&buf, 0).unwrap_err();
        assert!(matches!(err, RarError::Truncated { needed: 3, .. }));
    }

    #[test]
    fn parse_generic_header_rejects_bad_crc() {
        let mut bytes = build_block(block_codes::MAIN, 0, &[0u8; 6], None);
        bytes[2] ^= 0x01; // corrupt head_type, breaking the CRC body.
        let err = parse_generic_header(&bytes, 0).unwrap_err();
        assert!(matches!(err, RarError::HeaderCrc16Mismatch { .. }));
    }

    #[test]
    fn parse_generic_header_long_block_decodes_add_size() {
        let body = [0u8; 25];
        let bytes = build_block(block_codes::FILE, 0, &body, Some(4242));
        let block = parse_generic_header(&bytes, 0).expect("parses");
        assert_eq!(block.add_size, Some(4242));
        assert_eq!(block.block_type, BlockType::File);
        assert_eq!(block.fields_offset_in_input, BASE_BLOCK_LEN + 4);
        assert_eq!(block.fields_size, 25);
        assert_eq!(block.total_bytes_with_data(), block.head_size as u64 + 4242);
    }

    /// Synthesize a FILE_HEAD body for the given parameters, with no
    /// optional fields (no LARGE / SALT / EXTTIME).
    #[allow(clippy::too_many_arguments)]
    fn build_file_head_body(
        unp_size_low: u32,
        host_os: u8,
        crc32_val: u32,
        dos_mtime: u32,
        unp_ver: u8,
        method: u8,
        attr: u32,
        name: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::with_capacity(25 + name.len());
        body.extend_from_slice(&unp_size_low.to_le_bytes());
        body.push(host_os);
        body.extend_from_slice(&crc32_val.to_le_bytes());
        body.extend_from_slice(&dos_mtime.to_le_bytes());
        body.push(unp_ver);
        body.push(method);
        body.extend_from_slice(&(name.len() as u16).to_le_bytes());
        body.extend_from_slice(&attr.to_le_bytes());
        body.extend_from_slice(name);
        body
    }

    #[test]
    fn parse_file_header_basic_ascii() {
        let body = build_file_head_body(
            64,
            3,
            0xDEAD_BEEF,
            0x4949_4949,
            36,
            0x33,
            0o644,
            b"hello.txt",
        );
        let bytes = build_block(block_codes::FILE, 0, &body, Some(32));
        let block = parse_generic_header(&bytes, 0).expect("parses");
        let file = parse_file_header(&block, &bytes).expect("file parses");
        assert_eq!(file.name, "hello.txt");
        assert_eq!(file.packed_size, 32);
        assert_eq!(file.unpacked_size, 64);
        assert_eq!(file.host_os, 3);
        assert_eq!(file.file_crc32, 0xDEAD_BEEF);
        assert_eq!(file.unp_ver, 36);
        assert_eq!(file.method, 0x33);
    }

    #[test]
    fn parse_file_header_rejects_old_unp_ver_for_compressed_method() {
        // Compressed method (0x33 = m=3 Normal) with pre-2.9 unp_ver
        // is rejected — the LZ decoder doesn't support the older
        // stream layout.
        let body = build_file_head_body(0, 0, 0, 0, 20 /* 2.0 */, 0x33, 0, b"old.bin");
        let bytes = build_block(block_codes::FILE, 0, &body, Some(0));
        let block = parse_generic_header(&bytes, 0).expect("parses");
        let err = parse_file_header(&block, &bytes).unwrap_err();
        match err {
            RarError::UnsupportedFeature { feature } => {
                assert!(
                    feature.contains("unp_ver = 20"),
                    "feature should name unp_ver: {feature}"
                );
            }
            other => panic!("expected UnsupportedFeature, got {other:?}"),
        }
    }

    #[test]
    fn parse_file_header_accepts_old_unp_ver_for_stored_method() {
        // STORED (method 0x30) is a `memcpy` — `unp_ver` is
        // decorative. The registered RAR encoder tags `-m0` entries
        // `unp_ver = 20` for backward compatibility with pre-2.9
        // readers, and we accept those.
        let body =
            build_file_head_body(0, 0, 0, 0, 20 /* 2.0 */, STORED_METHOD, 0, b"old.bin");
        let bytes = build_block(block_codes::FILE, 0, &body, Some(0));
        let block = parse_generic_header(&bytes, 0).expect("parses");
        let file = parse_file_header(&block, &bytes).expect("STORED is decode-version-agnostic");
        assert_eq!(file.name, "old.bin");
        assert_eq!(file.method, STORED_METHOD);
        assert_eq!(file.unp_ver, 20);
    }

    #[test]
    fn parse_file_header_rejects_encrypted() {
        let body = build_file_head_body(0, 0, 0, 0, 36, 0x30, 0, b"secret.bin");
        let bytes = build_block(
            block_codes::FILE,
            0x0004, /* LHD_PASSWORD */
            &body,
            Some(0),
        );
        let block = parse_generic_header(&bytes, 0).expect("parses");
        let err = parse_file_header(&block, &bytes).unwrap_err();
        assert!(matches!(
            err,
            RarError::UnsupportedFeature { ref feature } if feature.contains("encryption")
        ));
    }

    #[test]
    fn parse_main_header_rejects_multi_volume() {
        let body = [0u8; 6];
        let bytes = build_block(block_codes::MAIN, 0x0001 /* MHD_VOLUME */, &body, None);
        let block = parse_generic_header(&bytes, 0).expect("parses");
        let err = parse_main_archive_header(&block, &bytes).unwrap_err();
        assert!(matches!(
            err,
            RarError::UnsupportedFeature { ref feature } if feature.contains("multi-volume")
        ));
    }

    #[test]
    fn parse_main_header_rejects_header_encryption() {
        let body = [0u8; 6];
        let bytes = build_block(
            block_codes::MAIN,
            0x0080, /* MHD_PASSWORD */
            &body,
            None,
        );
        let block = parse_generic_header(&bytes, 0).expect("parses");
        let err = parse_main_archive_header(&block, &bytes).unwrap_err();
        assert!(matches!(
            err,
            RarError::UnsupportedFeature { ref feature } if feature.contains("encryption")
        ));
    }

    #[test]
    fn parse_endarc_header_decodes_flags() {
        let bytes = build_block(
            block_codes::ENDARC,
            0x0002, /* EARC_DATACRC */
            &[],
            None,
        );
        let block = parse_generic_header(&bytes, 0).expect("parses");
        let endarc = parse_endarc_header(&block, &bytes).expect("endarc parses");
        assert!(endarc.endarc_flags.has_data_crc());
        assert!(!endarc.endarc_flags.has_next_volume());
    }

    #[test]
    fn unicode_name_decodes_pure_ascii_run() {
        // Encoded form: ascii "hi", NUL, high_byte=0, flag_byte=0x00
        // (mode 0 four times), then 'h','i'. We use literal mode 0 to
        // keep the test independent of run-length quirks.
        let mut name = b"hi".to_vec();
        name.push(0);
        name.push(0); // high_byte = 0
        name.push(0); // flag_byte: four mode-0 groups
        name.extend_from_slice(b"hi");
        let flags = FileFlags(0x0200); // LHD_UNICODE
        let decoded = decode_file_name(&name, flags).unwrap();
        assert_eq!(decoded, "hi");
    }

    #[test]
    fn unicode_name_with_no_separator_falls_back_to_ascii() {
        let flags = FileFlags(0x0200); // LHD_UNICODE but no NUL
        let decoded = decode_file_name(b"plain.txt", flags).unwrap();
        assert_eq!(decoded, "plain.txt");
    }

    #[test]
    fn unflagged_name_rejects_non_utf8() {
        let flags = FileFlags(0);
        let err = decode_file_name(&[0xFF, 0xFE, 0xFD], flags).unwrap_err();
        assert!(matches!(err, RarError::BadName { .. }));
    }

    #[test]
    fn unflagged_name_rejects_embedded_nul() {
        let flags = FileFlags(0);
        let err = decode_file_name(b"foo\0bar", flags).unwrap_err();
        assert!(matches!(err, RarError::BadName { ref reason } if reason.contains("NUL")));
    }
}
