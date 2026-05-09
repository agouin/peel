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
