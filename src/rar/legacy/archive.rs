//! Archive-level walker over a legacy (RAR3 / RAR4) byte buffer.
//!
//! Sibling of [`crate::rar::archive`]; see its module docs for the
//! shared design rationale (in-memory walker as the simplest exercise
//! of the wire-format layer; the §A2b pipeline reuses the same
//! per-header parsers but streams ranged downloads on top).
//!
//! The walker enforces `docs/PLAN_rar3.md` §0 round-one rejections:
//!
//! - **Multi-volume** (`MHD_VOLUME` set in `MAIN_HEAD`):
//!   [`crate::rar::RarError::UnsupportedFeature`] = `"multi-volume
//!   legacy archive"`. Surfaced from the type-specific parser, not
//!   here.
//! - **Header / per-file encryption** (`MHD_PASSWORD` /
//!   `LHD_PASSWORD`): same — surfaced from the parsers.
//! - **Pre-2.9 compression versions** (`unp_ver < 29`): surfaced from
//!   [`crate::rar::legacy::format::parse_file_header`] with the
//!   detected version named in the diagnostic.
//! - **Missing end-of-archive marker** —
//!   [`crate::rar::RarError::CorruptHeader`].

use crate::rar::error::RarError;
use crate::rar::legacy::format::{
    parse_endarc_header, parse_file_header, parse_generic_header, parse_main_archive_header,
    parse_signature, BlockType, FileHeader,
};

/// Summary of a legacy archive's metadata after a full walk.
///
/// Counterpart of [`crate::rar::ArchiveSummary`]. The two share the
/// same conceptual surface but carry format-specific flag sets — the
/// types are intentionally disjoint so callers cannot accidentally
/// mix them up.
#[derive(Debug, Clone)]
pub struct LegacyArchiveSummary {
    /// `true` iff `MAIN_HEAD` set `MHD_SOLID`.
    pub solid: bool,
    /// `true` iff `MAIN_HEAD` carried the recovery-record advisory
    /// bit (`MHD_PROTECT`). Round-one ignores the actual recovery
    /// records (they live in `PROTECT_HEAD` / `NEWSUB_HEAD` blocks).
    pub has_recovery_record: bool,
    /// `true` iff the archive is locked (`MHD_LOCK`).
    pub locked: bool,
    /// `true` iff `MAIN_HEAD` set `MHD_AV` (authenticity verification
    /// block follows). Informational; round-one skips AV blocks.
    pub has_authenticity_verification: bool,
    /// `true` iff `ENDARC_HEAD` set `EARC_NEXT_VOLUME`. Informational
    /// only — multi-volume archives are rejected at the main header.
    pub eof_next_volume: bool,
    /// One entry per `FILE_HEAD`. `SUB_HEAD` / `NEWSUB_HEAD` /
    /// `PROTECT_HEAD` / `COMM_HEAD` / `AV_HEAD` / `SIGN_HEAD` are
    /// skipped — round-one does not extract recovery records,
    /// comments, ACLs, or signatures.
    pub entries: Vec<LegacyFileEntry>,
}

/// Per-entry summary captured during a legacy walk.
#[derive(Debug, Clone)]
pub struct LegacyFileEntry {
    /// Decoded `FILE_HEAD` metadata.
    pub header: FileHeader,
    /// Byte offset of the entry's compressed data within the archive
    /// (the offset of the first byte of the data area following the
    /// file header). The §A2b pipeline uses this to schedule a ranged
    /// download for the entry's payload.
    pub data_offset: u64,
}

/// Walk an entire legacy RAR archive in `buf` and produce the
/// [`LegacyArchiveSummary`].
///
/// `buf` must start at byte 0 (the first byte of the legacy magic)
/// and contain the full archive contents through the end-of-archive
/// header.
///
/// # Errors
///
/// - [`RarError::BadSignature`] / [`RarError::Truncated`] from
///   [`parse_signature`].
/// - [`RarError::UnsupportedFeature`] for multi-volume archives,
///   header encryption, per-file encryption, file splits, or
///   compression versions outside `[29, 36]`.
/// - [`RarError::CorruptHeader`] / [`RarError::Truncated`] /
///   [`RarError::HeaderCrc16Mismatch`] from the per-header parsers.
/// - [`RarError::CorruptHeader`] (`reason = "archive ends before
///   ENDARC_HEAD"`) if the byte stream ends before a `0x7B` block is
///   observed.
pub fn walk_archive(buf: &[u8]) -> Result<LegacyArchiveSummary, RarError> {
    let sig_size = parse_signature(buf)?;
    let mut cursor: usize = sig_size;
    let mut summary = LegacyArchiveSummary {
        solid: false,
        has_recovery_record: false,
        locked: false,
        has_authenticity_verification: false,
        eof_next_volume: false,
        entries: Vec::new(),
    };
    let mut saw_main = false;

    loop {
        if cursor >= buf.len() {
            return Err(RarError::CorruptHeader {
                archive_offset: cursor as u64,
                reason: "archive ends before ENDARC_HEAD".to_string(),
            });
        }
        let block = parse_generic_header(&buf[cursor..], cursor as u64)?;
        // The base-block parser returns offsets relative to its own
        // input slice. We translate `fields_offset_in_input` back into
        // `buf` only at use time (see the per-block parsers below).

        match block.block_type {
            BlockType::Mark => {
                // The signature's bytes are themselves a degenerate
                // MARK_HEAD. The walker should never see one inside
                // the generic-header stream because the signature was
                // already consumed above. Surface a precise corruption
                // diagnostic instead of looping.
                return Err(RarError::CorruptHeader {
                    archive_offset: block.archive_offset,
                    reason: "MARK_HEAD encountered after the leading signature".to_string(),
                });
            }
            BlockType::Main => {
                if saw_main {
                    return Err(RarError::CorruptHeader {
                        archive_offset: block.archive_offset,
                        reason: "second MAIN_HEAD encountered".to_string(),
                    });
                }
                saw_main = true;
                let main = parse_main_archive_header(&block, &buf[cursor..])?;
                summary.solid = main.archive_flags.is_solid();
                summary.has_recovery_record = main.archive_flags.has_recovery_record();
                summary.locked = main.archive_flags.is_locked();
                summary.has_authenticity_verification = main.archive_flags.has_av();
            }
            BlockType::File => {
                if !saw_main {
                    return Err(RarError::CorruptHeader {
                        archive_offset: block.archive_offset,
                        reason: "FILE_HEAD encountered before MAIN_HEAD".to_string(),
                    });
                }
                let file = parse_file_header(&block, &buf[cursor..])?;
                let data_offset = (cursor as u64) + u64::from(block.head_size);
                summary.entries.push(LegacyFileEntry {
                    header: file,
                    data_offset,
                });
            }
            BlockType::EndArchive => {
                let end = parse_endarc_header(&block, &buf[cursor..])?;
                summary.eof_next_volume = end.endarc_flags.has_next_volume();
                return Ok(summary);
            }
            // All remaining block types are skipped silently. They
            // carry comments / authenticity / recovery / signatures /
            // sub-blocks (UID/GID/ACL/EA) that round-one does not
            // surface. Their data areas (if any) are accounted for by
            // `block.add_size` and stepped over below.
            BlockType::Comment
            | BlockType::AuthenticityVerification
            | BlockType::Sub
            | BlockType::Protect
            | BlockType::Sign
            | BlockType::NewSub => {}
            BlockType::Other(code) => {
                return Err(RarError::UnsupportedFeature {
                    feature: format!(
                        "unknown legacy RAR block type 0x{code:02x} (no SKIP_IF_UNKNOWN \
                         affordance in legacy format; archive may be corrupt or from a \
                         future spec revision)"
                    ),
                });
            }
        }

        let advance = block.total_bytes_with_data();
        let advance_usize: usize = advance.try_into().map_err(|_| RarError::CorruptHeader {
            archive_offset: block.archive_offset,
            reason: format!("block size {advance} exceeds usize on this platform"),
        })?;
        cursor = cursor
            .checked_add(advance_usize)
            .ok_or_else(|| RarError::CorruptHeader {
                archive_offset: block.archive_offset,
                reason: "block end offset overflows usize".to_string(),
            })?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rar::legacy::format::LEGACY_SIGNATURE_MAGIC;
    use crate::zip::crc32;

    /// Reusable block-builder mirroring the one in
    /// `crate::rar::legacy::format::tests`.
    fn build_block(head_type: u8, head_flags: u16, body: &[u8], add_size: Option<u32>) -> Vec<u8> {
        const HEAD_FLAG_LONG_BLOCK: u16 = 0x8000;
        const BASE_BLOCK_LEN: usize = 7;
        let mut head_flags = head_flags;
        if add_size.is_some() {
            head_flags |= HEAD_FLAG_LONG_BLOCK;
        }
        let header_extra = if add_size.is_some() { 4 } else { 0 };
        let head_size = (BASE_BLOCK_LEN + header_extra + body.len()) as u16;
        let mut bytes = Vec::with_capacity(head_size as usize);
        bytes.extend_from_slice(&[0, 0]);
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

    /// Synthesize a minimal legacy archive: signature + MAIN + a
    /// run of FILEs (each with `pack_size_data` bytes of data) +
    /// ENDARC.
    fn build_archive(main_flags: u16, files: &[(&str, &[u8], u8 /*method*/)]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&LEGACY_SIGNATURE_MAGIC);
        // MAIN_HEAD: 6-byte high_pos_av + pos_av reserved.
        let main_body = [0u8; 6];
        buf.extend_from_slice(&build_block(0x73, main_flags, &main_body, None));
        for (name, data, method) in files {
            let body = build_file_head_body(
                data.len() as u32,
                3, // Unix
                0xDEAD_BEEF,
                0x4949_4949,
                36, // unp_ver = 3.6 / 4.x
                *method,
                0o644,
                name.as_bytes(),
            );
            buf.extend_from_slice(&build_block(0x74, 0, &body, Some(data.len() as u32)));
            buf.extend_from_slice(data);
        }
        // ENDARC_HEAD: empty body.
        buf.extend_from_slice(&build_block(0x7B, 0, &[], None));
        buf
    }

    #[test]
    fn walks_minimal_solid_archive_with_one_stored_entry() {
        let archive = build_archive(0x0008, &[("hello.txt", b"hello world", 0x30)]);
        let summary = walk_archive(&archive).expect("walks");
        assert!(summary.solid);
        assert!(!summary.locked);
        assert_eq!(summary.entries.len(), 1);
        let entry = &summary.entries[0];
        assert_eq!(entry.header.name, "hello.txt");
        assert_eq!(entry.header.method, 0x30);
        assert_eq!(entry.header.unpacked_size, 11);
        assert_eq!(entry.header.packed_size, 11);
    }

    #[test]
    fn walks_multi_entry_archive_and_records_data_offsets() {
        let archive = build_archive(
            0x0000,
            &[
                ("a.txt", b"AAA", 0x33),
                ("b.txt", b"BBBB", 0x33),
                ("c.txt", b"CCCCC", 0x33),
            ],
        );
        let summary = walk_archive(&archive).expect("walks");
        assert!(!summary.solid);
        assert_eq!(summary.entries.len(), 3);
        // Verify the recorded data offsets by reading back from `archive`.
        for (entry, expected) in summary.entries.iter().zip([&b"AAA"[..], b"BBBB", b"CCCCC"]) {
            let start = entry.data_offset as usize;
            let end = start + entry.header.packed_size as usize;
            assert_eq!(&archive[start..end], expected);
        }
    }

    #[test]
    fn rejects_archive_with_multi_volume_main() {
        let archive = build_archive(0x0001 /* MHD_VOLUME */, &[]);
        let err = walk_archive(&archive).unwrap_err();
        assert!(matches!(
            err,
            RarError::UnsupportedFeature { ref feature } if feature.contains("multi-volume")
        ));
    }

    #[test]
    fn rejects_archive_missing_endarc() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&LEGACY_SIGNATURE_MAGIC);
        let main_body = [0u8; 6];
        buf.extend_from_slice(&build_block(0x73, 0, &main_body, None));
        // No ENDARC.
        let err = walk_archive(&buf).unwrap_err();
        assert!(matches!(
            err,
            RarError::CorruptHeader { ref reason, .. } if reason.contains("ENDARC_HEAD")
        ));
    }

    #[test]
    fn rejects_file_before_main() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&LEGACY_SIGNATURE_MAGIC);
        let body = build_file_head_body(0, 3, 0, 0, 36, 0x30, 0, b"early.bin");
        buf.extend_from_slice(&build_block(0x74, 0, &body, Some(0)));
        buf.extend_from_slice(&build_block(0x7B, 0, &[], None));
        let err = walk_archive(&buf).unwrap_err();
        assert!(matches!(
            err,
            RarError::CorruptHeader { ref reason, .. }
                if reason.contains("FILE_HEAD encountered before MAIN_HEAD")
        ));
    }

    #[test]
    fn rejects_unknown_block_type() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&LEGACY_SIGNATURE_MAGIC);
        let main_body = [0u8; 6];
        buf.extend_from_slice(&build_block(0x73, 0, &main_body, None));
        // 0x60 is below the assigned range (0x72..0x7B).
        buf.extend_from_slice(&build_block(0x60, 0, &[0u8; 4], None));
        buf.extend_from_slice(&build_block(0x7B, 0, &[], None));
        let err = walk_archive(&buf).unwrap_err();
        assert!(matches!(
            err,
            RarError::UnsupportedFeature { ref feature }
                if feature.contains("unknown legacy RAR block type")
        ));
    }

    #[test]
    fn skips_subblocks_silently() {
        // Archive with a NEWSUB block (0x7A) between MAIN and FILE.
        let mut buf = Vec::new();
        buf.extend_from_slice(&LEGACY_SIGNATURE_MAGIC);
        let main_body = [0u8; 6];
        buf.extend_from_slice(&build_block(0x73, 0, &main_body, None));
        // NEWSUB: small body, with add_size=0 (no data area).
        let newsub_body = b"some-newsub-payload";
        buf.extend_from_slice(&build_block(0x7A, 0, newsub_body, Some(0)));
        let file_body = build_file_head_body(3, 3, 0, 0, 36, 0x30, 0, b"x.bin");
        buf.extend_from_slice(&build_block(0x74, 0, &file_body, Some(3)));
        buf.extend_from_slice(b"XYZ");
        buf.extend_from_slice(&build_block(0x7B, 0, &[], None));

        let summary = walk_archive(&buf).expect("walks");
        assert_eq!(summary.entries.len(), 1);
        assert_eq!(summary.entries[0].header.name, "x.bin");
    }
}
