//! In-memory builder for ZIP test archives.
//!
//! Mirrors the tar/lz4/xz fixture builders: the integration tests
//! synthesize archives in code rather than checking binary fixtures
//! into the repo. The wire-format details match the PKWARE APPNOTE
//! sections we exercise (`§4.3.6`, `§4.3.12`, `§4.3.16`); see
//! `peel::zip::format` for the parsing side.

#![allow(dead_code)] // Different integration tests use different subsets.

/// PKWARE APPNOTE signatures.
pub const SIGNATURE_LFH: u32 = 0x0403_4b50;
pub const SIGNATURE_CDE: u32 = 0x0201_4b50;
pub const SIGNATURE_EOCD: u32 = 0x0605_4b50;

/// One entry in a synthesized archive.
pub struct ZipEntrySpec {
    /// Filename as recorded in both the local file header and CDE.
    pub name: String,
    /// Compression method code (0 = STORED, 8 = DEFLATE, 93 = zstd).
    pub method: u16,
    /// Pre-encoding payload. The fixture builder compresses it
    /// according to `method` and stamps both the LFH and the CDE
    /// with the resulting compressed/uncompressed sizes and CRC-32.
    pub uncompressed: Vec<u8>,
}

impl ZipEntrySpec {
    /// New STORED entry.
    pub fn stored(name: impl Into<String>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            method: 0,
            uncompressed: payload.into(),
        }
    }

    /// New DEFLATE entry.
    pub fn deflate(name: impl Into<String>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            method: 8,
            uncompressed: payload.into(),
        }
    }

    /// New zstd entry.
    pub fn zstd(name: impl Into<String>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            name: name.into(),
            method: 93,
            uncompressed: payload.into(),
        }
    }

    /// New directory entry (PKWARE convention: trailing slash, zero
    /// uncompressed size, method STORED).
    pub fn directory(name: impl Into<String>) -> Self {
        let mut name: String = name.into();
        if !name.ends_with('/') {
            name.push('/');
        }
        Self {
            name,
            method: 0,
            uncompressed: Vec::new(),
        }
    }
}

/// Build a ZIP archive from `entries`.
///
/// Layout: `[LFH][data] [LFH][data] ... [CDE]+ [EOCD]`. Every entry
/// uses the canonical encoding (no general-purpose flags set, no
/// extra fields, no comments). Suitable for end-to-end coordinator
/// tests.
pub fn build_zip(entries: &[ZipEntrySpec]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd_specs = Vec::new();
    for entry in entries {
        let lfh_offset = out.len() as u32;
        let crc = crc32_ieee(&entry.uncompressed);
        let compressed = match entry.method {
            0 => entry.uncompressed.clone(),
            8 => {
                use std::io::Write as _;
                let mut e =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
                e.write_all(&entry.uncompressed).expect("encode");
                e.finish().expect("finish")
            }
            93 => zstd::encode_all(std::io::Cursor::new(&entry.uncompressed[..]), 3)
                .expect("encode zstd"),
            other => panic!("zip_fixtures: unsupported method {other}"),
        };
        // LFH
        out.extend_from_slice(&SIGNATURE_LFH.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // version_needed
        out.extend_from_slice(&0u16.to_le_bytes()); // gp_flags
        out.extend_from_slice(&entry.method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // mtime
        out.extend_from_slice(&0u16.to_le_bytes()); // mdate
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        out.extend_from_slice(&(entry.uncompressed.len() as u32).to_le_bytes());
        out.extend_from_slice(&(entry.name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra
        out.extend_from_slice(entry.name.as_bytes());
        out.extend_from_slice(&compressed);
        cd_specs.push((
            entry.name.clone(),
            entry.method,
            crc,
            compressed.len() as u32,
            entry.uncompressed.len() as u32,
            lfh_offset,
        ));
    }
    let cd_offset = out.len() as u32;
    for (name, method, crc, csize, usize_, lfh_off) in &cd_specs {
        out.extend_from_slice(&SIGNATURE_CDE.to_le_bytes());
        out.extend_from_slice(&20u16.to_le_bytes()); // made_by
        out.extend_from_slice(&20u16.to_le_bytes()); // needed
        out.extend_from_slice(&0u16.to_le_bytes()); // gp_flags
        out.extend_from_slice(&method.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // mtime
        out.extend_from_slice(&0u16.to_le_bytes()); // mdate
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&csize.to_le_bytes());
        out.extend_from_slice(&usize_.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra
        out.extend_from_slice(&0u16.to_le_bytes()); // comment
        out.extend_from_slice(&0u16.to_le_bytes()); // disk_start
        out.extend_from_slice(&0u16.to_le_bytes()); // internal_attrs
        out.extend_from_slice(&0u32.to_le_bytes()); // external_attrs
        out.extend_from_slice(&lfh_off.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
    }
    let cd_size = out.len() as u32 - cd_offset;
    // EOCD
    out.extend_from_slice(&SIGNATURE_EOCD.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // disk
    out.extend_from_slice(&0u16.to_le_bytes()); // cd_start_disk
    out.extend_from_slice(&(cd_specs.len() as u16).to_le_bytes());
    out.extend_from_slice(&(cd_specs.len() as u16).to_le_bytes());
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment_length
    out
}

/// Plain CRC-32 IEEE 802.3, the variant ZIP records. Hand-rolled
/// to avoid depending on a crate just for tests.
pub fn crc32_ieee(data: &[u8]) -> u32 {
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
