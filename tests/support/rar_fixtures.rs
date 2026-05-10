//! In-memory builder for RAR5 test archives.
//!
//! Mirrors the tar / zip / 7z fixture builders. We synthesize the
//! wire format ourselves (rather than shelling out to a `rar` binary
//! at test time) so the fixtures are reproducible across machines
//! and committed-friendly. The encoding follows the technote at
//! <https://www.rarlab.com/technote.htm>; see `peel::rar::format` for
//! the parser side.
//!
//! Round-one targets fixtures that exercise the §1 walker:
//!
//! - **Non-solid archives** with arbitrary STORED entries.
//! - **Solid archives** (`MHD_SOLID`) — flag-only difference;
//!   round-one fixtures use STORED entries so we don't need a
//!   compressor.
//! - **Multi-volume archives** (`MHD_VOLUME` set + optional volume
//!   number) — the walker rejects with `UnsupportedFeature`.
//! - **Encrypted archives** (header type 4) — the walker rejects.
//! - **RAR4 archives** (different magic, no further structure
//!   needed) — `parse_signature` rejects with
//!   `UnsupportedFormatVersion`.

#![allow(dead_code)] // Different integration tests use different subsets.

use peel::rar::format::{arc_flags, file_flags, hdr_flags, RAR4_SIGNATURE_MAGIC};
use peel::rar::SIGNATURE_MAGIC;

/// Encode a `u64` as a RAR5 vint.
pub fn encode_vint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
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

/// CRC-32-IEEE convenience (matches the polynomial RAR5 uses for
/// header integrity).
pub fn header_crc32(data: &[u8]) -> u32 {
    let mut state: u32 = !0;
    for &b in data {
        state ^= u32::from(b);
        for _ in 0..8 {
            let lsb = state & 1;
            state >>= 1;
            if lsb != 0 {
                state ^= 0xEDB8_8320;
            }
        }
    }
    !state
}

/// Build a generic header on top of the supplied type-specific
/// fields and (optional) extra area / data area. Returns the
/// header bytes only; the caller appends the data-area bytes if
/// `data_area_size` is `Some`.
pub fn build_generic_header(
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
    let crc = header_crc32(&out[4..]);
    out[..4].copy_from_slice(&crc.to_le_bytes());
    out
}

/// Build a main archive header (header type 1) with the given
/// archive-wide flags and (optional) volume number.
pub fn build_main_header(archive_flags: u64, volume_number: Option<u64>) -> Vec<u8> {
    let mut fields = Vec::new();
    fields.extend_from_slice(&encode_vint(archive_flags));
    if archive_flags & arc_flags::VOLUME_NUMBER != 0 {
        fields.extend_from_slice(&encode_vint(volume_number.unwrap_or(0)));
    }
    build_generic_header(1, 0, &fields, &[], None)
}

/// One STORED-method file-header entry. Round-one §1 doesn't extract
/// data; the data area is appended to the archive bytes verbatim
/// (the walker computes per-entry data offsets from the generic
/// header alone).
#[derive(Clone)]
pub struct RarEntrySpec {
    /// Entry name (UTF-8).
    pub name: String,
    /// Pre-encoding payload.
    pub uncompressed: Vec<u8>,
    /// `true` to set the directory bit in `file_flags`.
    pub directory: bool,
    /// `Some(t)` to record a Unix mtime in the file header.
    pub mtime: Option<u32>,
    /// `Some(c)` to record a CRC32 in the file header. The fixture
    /// does **not** validate the CRC against `uncompressed` —
    /// caller-controlled.
    pub data_crc32: Option<u32>,
}

impl RarEntrySpec {
    /// New STORED entry with default flags.
    pub fn stored(name: impl Into<String>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            uncompressed: payload.into(),
            directory: false,
            mtime: None,
            data_crc32: None,
        }
    }
}

/// Build a file-header generic header for the given entry, returning
/// `(header_bytes, data_area_bytes)`. The caller concatenates these
/// onto the archive in order so the walker observes the data area
/// immediately after the header.
pub fn build_file_header(entry: &RarEntrySpec) -> (Vec<u8>, Vec<u8>) {
    let mut flags: u64 = 0;
    if entry.directory {
        flags |= file_flags::DIRECTORY;
    }
    if entry.mtime.is_some() {
        flags |= file_flags::TIME_PRESENT;
    }
    if entry.data_crc32.is_some() {
        flags |= file_flags::CRC32_PRESENT;
    }
    let mut fields = Vec::new();
    fields.extend_from_slice(&encode_vint(flags));
    fields.extend_from_slice(&encode_vint(entry.uncompressed.len() as u64));
    fields.extend_from_slice(&encode_vint(0)); // attributes
    if let Some(t) = entry.mtime {
        fields.extend_from_slice(&t.to_le_bytes());
    }
    if let Some(c) = entry.data_crc32 {
        fields.extend_from_slice(&c.to_le_bytes());
    }
    fields.extend_from_slice(&encode_vint(0)); // compression info: STORED
    fields.extend_from_slice(&encode_vint(1)); // host OS: Unix
    fields.extend_from_slice(&encode_vint(entry.name.len() as u64));
    fields.extend_from_slice(entry.name.as_bytes());

    let header = build_generic_header(
        2,
        hdr_flags::DATA_AREA,
        &fields,
        &[],
        Some(entry.uncompressed.len() as u64),
    );
    (header, entry.uncompressed.clone())
}

/// Build a minimal end-of-archive header (header type 5) with the
/// `more_volumes` flag clear (round-one rejects multi-volume long
/// before we get here, but the marker still terminates the byte
/// stream).
pub fn build_end_of_archive() -> Vec<u8> {
    let fields = encode_vint(0);
    build_generic_header(5, 0, &fields, &[], None)
}

/// Build a complete RAR5 archive: signature + main header (with the
/// supplied flags + volume number) + N file headers + end of
/// archive.
pub fn build_rar5(
    archive_flags: u64,
    volume_number: Option<u64>,
    entries: &[RarEntrySpec],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&SIGNATURE_MAGIC);
    out.extend_from_slice(&build_main_header(archive_flags, volume_number));
    for entry in entries {
        let (header, data) = build_file_header(entry);
        out.extend_from_slice(&header);
        out.extend_from_slice(&data);
    }
    out.extend_from_slice(&build_end_of_archive());
    out
}

/// Build a RAR5 archive with a header-type-4 (archive encryption)
/// header inserted between the main header and the first file
/// header. The encryption header's body is intentionally minimal —
/// the round-one walker rejects on the type code alone, so its
/// contents don't matter.
pub fn build_rar5_encrypted_header(entries: &[RarEntrySpec]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&SIGNATURE_MAGIC);
    out.extend_from_slice(&build_main_header(0, None));
    // Header type 4 with no flags or fields.
    out.extend_from_slice(&build_generic_header(4, 0, &[], &[], None));
    for entry in entries {
        let (header, data) = build_file_header(entry);
        out.extend_from_slice(&header);
        out.extend_from_slice(&data);
    }
    out.extend_from_slice(&build_end_of_archive());
    out
}

/// Build a 7-byte RAR4 magic-only fixture. The walker rejects on
/// the signature alone; nothing further is needed for the test.
pub fn build_rar4_magic_only() -> Vec<u8> {
    RAR4_SIGNATURE_MAGIC.to_vec()
}

// ─────────────────────────────────────────────────────────────────
// Legacy (RAR3 / RAR4) fixture builder
// ─────────────────────────────────────────────────────────────────
//
// The legacy archive format uses fixed-layout little-endian headers
// with a CRC-16 (low 16 of CRC-32 IEEE) prefix. See
// `peel::rar::legacy::format` for the parser side and
// `docs/PLAN_rar3.md` §A1 for the layout.

const LEGACY_HEAD_FLAG_LONG_BLOCK: u16 = 0x8000;
const LEGACY_BASE_BLOCK_LEN: usize = 7;

/// Build a legacy base-block-prefixed header. CRCs the body and
/// returns the wire bytes; the caller appends the data area
/// separately (when `add_size` is `Some(n)`, `n` bytes of data are
/// expected to follow the header in the archive stream).
pub fn build_legacy_block(
    head_type: u8,
    head_flags: u16,
    body: &[u8],
    add_size: Option<u32>,
) -> Vec<u8> {
    let mut head_flags = head_flags;
    if add_size.is_some() {
        head_flags |= LEGACY_HEAD_FLAG_LONG_BLOCK;
    }
    let header_extra = if add_size.is_some() { 4 } else { 0 };
    let head_size = (LEGACY_BASE_BLOCK_LEN + header_extra + body.len()) as u16;
    let mut bytes = Vec::with_capacity(head_size as usize);
    bytes.extend_from_slice(&[0, 0]); // head_crc placeholder
    bytes.push(head_type);
    bytes.extend_from_slice(&head_flags.to_le_bytes());
    bytes.extend_from_slice(&head_size.to_le_bytes());
    if let Some(add) = add_size {
        bytes.extend_from_slice(&add.to_le_bytes());
    }
    bytes.extend_from_slice(body);
    let crc16 = (header_crc32(&bytes[2..]) & 0xFFFF) as u16;
    bytes[..2].copy_from_slice(&crc16.to_le_bytes());
    bytes
}

/// Build a legacy `MAIN_HEAD` (block type `0x73`).
///
/// `archive_flags` is the wire-level flag word (bit 0x0008 = SOLID,
/// 0x0001 = MULTI_VOLUME, etc.). The 6-byte reserved tail
/// (`high_pos_av` + `pos_av`) is zeroed.
pub fn build_legacy_main_header(archive_flags: u16) -> Vec<u8> {
    let body = [0u8; 6];
    build_legacy_block(0x73, archive_flags, &body, None)
}

/// Build a legacy `ENDARC_HEAD` (block type `0x7B`).
pub fn build_legacy_endarc_header() -> Vec<u8> {
    build_legacy_block(0x7B, 0, &[], None)
}

/// Spec for a STORED-method legacy file-header entry.
#[derive(Clone, Debug)]
pub struct LegacyEntrySpec {
    /// Entry name (UTF-8).
    pub name: String,
    /// Pre-encoding payload. STORED means `pack_size == unp_size`.
    pub uncompressed: Vec<u8>,
    /// Compression-version × 10 (e.g. `36` for RAR 3.6 / 4.x).
    /// The legacy parser accepts `[29, 36]`.
    pub unp_ver: u8,
}

impl LegacyEntrySpec {
    /// New STORED entry tagged with `unp_ver = 36` (the RAR 4.x
    /// default).
    pub fn stored(name: impl Into<String>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            uncompressed: payload.into(),
            unp_ver: 36,
        }
    }
}

/// Build a legacy `FILE_HEAD` (block type `0x74`) for a STORED entry,
/// returning `(header_bytes, data_area_bytes)`. The caller
/// concatenates them in order so the walker observes the data area
/// immediately after the header.
pub fn build_legacy_file_header(entry: &LegacyEntrySpec) -> (Vec<u8>, Vec<u8>) {
    let pack_size: u32 = entry.uncompressed.len() as u32;
    let unp_size_low: u32 = pack_size; // STORED
    let host_os: u8 = 3; // Unix
    let file_crc32: u32 = header_crc32(&entry.uncompressed);
    let dos_mtime: u32 = 0x4949_4949; // arbitrary
    let method: u8 = 0x30; // m=0 STORED
    let attr: u32 = 0o644;

    let mut body = Vec::with_capacity(25 + entry.name.len());
    body.extend_from_slice(&unp_size_low.to_le_bytes());
    body.push(host_os);
    body.extend_from_slice(&file_crc32.to_le_bytes());
    body.extend_from_slice(&dos_mtime.to_le_bytes());
    body.push(entry.unp_ver);
    body.push(method);
    body.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
    body.extend_from_slice(&attr.to_le_bytes());
    body.extend_from_slice(entry.name.as_bytes());

    let head_flags: u16 = 0; // no LARGE / UNICODE / SALT / EXTTIME
    let header = build_legacy_block(0x74, head_flags, &body, Some(pack_size));
    (header, entry.uncompressed.clone())
}

/// Build a complete legacy STORED archive: 7-byte magic + MAIN_HEAD
/// (with the supplied flags) + N FILE_HEADs (each followed by data) +
/// ENDARC_HEAD.
pub fn build_legacy_archive(archive_flags: u16, entries: &[LegacyEntrySpec]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&peel::rar::LEGACY_SIGNATURE_MAGIC);
    out.extend_from_slice(&build_legacy_main_header(archive_flags));
    for entry in entries {
        let (header, data) = build_legacy_file_header(entry);
        out.extend_from_slice(&header);
        out.extend_from_slice(&data);
    }
    out.extend_from_slice(&build_legacy_endarc_header());
    out
}
