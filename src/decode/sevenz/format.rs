//! 7z header / footer wire-format parsers.
//!
//! Hand-rolled per `docs/ENGINEERING_STANDARDS.md` §2.1, the same
//! posture taken for tar (`docs/PLAN.md` §7.3) and zip
//! (`docs/PLAN_v2.md` §5). Every parser is pure: input goes in as
//! a byte slice, output comes out as a typed struct, and no IO
//! happens here. The second-pipeline driver (§8) does the ranged
//! downloads and feeds the right bytes to the right parser.
//!
//! # Phase coverage
//!
//! - **§2** ([`parse_signature_header`]): the fixed 32-byte
//!   `SignatureHeader` + `StartHeader` prefix that begins every
//!   7z archive. Tells us where the trailer is and validates the
//!   archive version.
//!
//! Future phases extend this module with the trailer-side
//! `Header` / `EncodedHeader` / `MainStreamsInfo` / `FilesInfo`
//! parsers (§3) and the `CodersInfo` decoder chain (§4 / §5).

use crate::hash::crc32::ieee as crc32_ieee;
use crate::sevenz::{SevenzError, SIGNATURE_MAGIC};

/// Length, in bytes, of the fixed-size prefix that begins every
/// 7z archive (`SignatureHeader` + `StartHeader`).
///
/// Layout (all multi-byte integers little-endian):
///
/// ```text
///  0   6  Signature             37 7A BC AF 27 1C
///  6   1  ArchiveVersion.major  0x00
///  7   1  ArchiveVersion.minor  0x04
///  8   4  StartHeaderCRC        CRC32 of bytes 12..32
/// 12   8  NextHeaderOffset      u64; relative to byte 32
/// 20   8  NextHeaderSize        u64
/// 28   4  NextHeaderCRC         CRC32 of the trailer bytes
/// ```
pub const SIGNATURE_HEADER_LEN: usize = 32;

/// `ArchiveVersion.major` byte every round-one-supported archive
/// records.
pub const ARCHIVE_VERSION_MAJOR: u8 = 0x00;

/// `ArchiveVersion.minor` byte every round-one-supported archive
/// records. The reference says `0.4` is the only version in the
/// wild; anything else surfaces [`SevenzError::UnsupportedVersion`].
pub const ARCHIVE_VERSION_MINOR: u8 = 0x04;

/// Parsed `SignatureHeader` + `StartHeader`.
///
/// Constructed via [`parse_signature_header`]; the parser
/// validates the magic, the archive version, and the
/// `StartHeaderCRC`, then captures the trailer location for the
/// pipeline driver. The `NextHeaderCRC` is *not* validated here —
/// the trailer bytes it covers are not yet available; it travels
/// alongside the parsed value so §3's `Header` parser can verify
/// the trailer integrity once the bytes are in hand.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct SignatureHeader {
    /// `ArchiveVersion.major` byte. Always [`ARCHIVE_VERSION_MAJOR`]
    /// for archives this build accepts; preserved on the typed
    /// value for diagnostic logging.
    pub archive_version_major: u8,
    /// `ArchiveVersion.minor` byte. Always [`ARCHIVE_VERSION_MINOR`]
    /// for archives this build accepts.
    pub archive_version_minor: u8,
    /// Trailer offset *relative to the byte immediately after the
    /// signature header* — i.e. relative to byte
    /// [`SIGNATURE_HEADER_LEN`] of the archive. To convert to an
    /// absolute archive offset, use [`Self::trailer_archive_offset`].
    pub next_header_offset: u64,
    /// Length, in bytes, of the trailer named by
    /// [`Self::next_header_offset`].
    pub next_header_size: u64,
    /// CRC32 of the trailer bytes. The §3 parser verifies this
    /// once the trailer is in hand.
    pub next_header_crc: u32,
}

impl SignatureHeader {
    /// Absolute archive byte offset where the trailer begins.
    ///
    /// # Errors
    ///
    /// [`SevenzError::CorruptHeader`] if
    /// [`SIGNATURE_HEADER_LEN`] + [`Self::next_header_offset`]
    /// overflows `u64`.
    pub fn trailer_archive_offset(&self) -> Result<u64, SevenzError> {
        (SIGNATURE_HEADER_LEN as u64)
            .checked_add(self.next_header_offset)
            .ok_or_else(|| SevenzError::CorruptHeader {
                reason: "trailer offset overflows u64".into(),
            })
    }

    /// `(start, length)` describing the trailer's location in the
    /// archive, validated against `total_size`.
    ///
    /// `total_size` is the full archive length the caller knows
    /// (e.g. the `Content-Length` of the response). When the
    /// caller does not know the total length yet, use
    /// [`Self::trailer_archive_offset`] alone and skip the bound
    /// check until the length is known.
    ///
    /// # Errors
    ///
    /// [`SevenzError::CorruptHeader`] if the trailer would
    /// overflow `u64` or extend past `total_size`.
    pub fn trailer_range(&self, total_size: u64) -> Result<(u64, u64), SevenzError> {
        let start = self.trailer_archive_offset()?;
        let end =
            start
                .checked_add(self.next_header_size)
                .ok_or_else(|| SevenzError::CorruptHeader {
                    reason: "trailer end overflows u64".into(),
                })?;
        if end > total_size {
            return Err(SevenzError::CorruptHeader {
                reason: format!("trailer end {end} exceeds archive size {total_size}",),
            });
        }
        Ok((start, self.next_header_size))
    }
}

/// Parse the fixed 32-byte signature + start header.
///
/// `buf` must contain at least [`SIGNATURE_HEADER_LEN`] bytes.
///
/// The parser validates, in order:
///
/// 1. The 6-byte signature matches [`SIGNATURE_MAGIC`].
/// 2. `ArchiveVersion.major` / `.minor` are
///    [`ARCHIVE_VERSION_MAJOR`] / [`ARCHIVE_VERSION_MINOR`].
/// 3. `StartHeaderCRC` (a CRC32 over bytes `12..32`) matches the
///    computed CRC. A mismatch signals corruption of the
///    `NextHeaderOffset` / `NextHeaderSize` / `NextHeaderCRC`
///    fields the trailer location depends on.
///
/// # Errors
///
/// - [`SevenzError::Truncated`] if `buf` is shorter than
///   [`SIGNATURE_HEADER_LEN`] bytes.
/// - [`SevenzError::CorruptHeader`] for a magic mismatch or a
///   `StartHeaderCRC` mismatch (the message names which one).
/// - [`SevenzError::UnsupportedVersion`] if the version bytes
///   disagree with the supported `0.4`.
pub fn parse_signature_header(buf: &[u8]) -> Result<SignatureHeader, SevenzError> {
    if buf.len() < SIGNATURE_HEADER_LEN {
        return Err(SevenzError::Truncated {
            what: "signature header".into(),
            needed: SIGNATURE_HEADER_LEN - buf.len(),
        });
    }
    let buf = &buf[..SIGNATURE_HEADER_LEN];

    if buf[0..6] != SIGNATURE_MAGIC {
        return Err(SevenzError::CorruptHeader {
            reason: format!(
                "signature mismatch: expected {:02X?}, found {:02X?}",
                SIGNATURE_MAGIC,
                &buf[0..6]
            ),
        });
    }

    let major = buf[6];
    let minor = buf[7];
    if major != ARCHIVE_VERSION_MAJOR || minor != ARCHIVE_VERSION_MINOR {
        return Err(SevenzError::UnsupportedVersion { major, minor });
    }

    // INVARIANT: try_into on a length-checked slice cannot fail;
    // every from_le_bytes input below is exactly its target size.
    let recorded_crc = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let computed_crc = crc32_ieee(&buf[12..32]);
    if recorded_crc != computed_crc {
        return Err(SevenzError::CorruptHeader {
            reason: format!(
                "start-header CRC32 mismatch: recorded {recorded_crc:#010x}, computed {computed_crc:#010x}",
            ),
        });
    }

    let next_header_offset = u64::from_le_bytes([
        buf[12], buf[13], buf[14], buf[15], buf[16], buf[17], buf[18], buf[19],
    ]);
    let next_header_size = u64::from_le_bytes([
        buf[20], buf[21], buf[22], buf[23], buf[24], buf[25], buf[26], buf[27],
    ]);
    let next_header_crc = u32::from_le_bytes([buf[28], buf[29], buf[30], buf[31]]);

    Ok(SignatureHeader {
        archive_version_major: major,
        archive_version_minor: minor,
        next_header_offset,
        next_header_size,
        next_header_crc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a 32-byte signature header with the requested fields.
    /// Recomputes `StartHeaderCRC` from `next_header_*` so the
    /// "happy path" tests don't have to hand-compute it.
    fn build_signature_header(
        magic: [u8; 6],
        version_major: u8,
        version_minor: u8,
        next_header_offset: u64,
        next_header_size: u64,
        next_header_crc: u32,
    ) -> [u8; SIGNATURE_HEADER_LEN] {
        let mut buf = [0u8; SIGNATURE_HEADER_LEN];
        buf[0..6].copy_from_slice(&magic);
        buf[6] = version_major;
        buf[7] = version_minor;
        buf[12..20].copy_from_slice(&next_header_offset.to_le_bytes());
        buf[20..28].copy_from_slice(&next_header_size.to_le_bytes());
        buf[28..32].copy_from_slice(&next_header_crc.to_le_bytes());
        let crc = crc32_ieee(&buf[12..32]);
        buf[8..12].copy_from_slice(&crc.to_le_bytes());
        buf
    }

    #[test]
    fn parses_valid_signature_header() {
        let buf = build_signature_header(SIGNATURE_MAGIC, 0x00, 0x04, 0x100, 0x42, 0xDEADBEEF);
        let parsed = parse_signature_header(&buf).expect("parses");
        assert_eq!(parsed.archive_version_major, 0x00);
        assert_eq!(parsed.archive_version_minor, 0x04);
        assert_eq!(parsed.next_header_offset, 0x100);
        assert_eq!(parsed.next_header_size, 0x42);
        assert_eq!(parsed.next_header_crc, 0xDEADBEEF);
    }

    #[test]
    fn parser_ignores_bytes_past_signature_header_len() {
        let mut buf = build_signature_header(SIGNATURE_MAGIC, 0x00, 0x04, 0, 0, 0).to_vec();
        buf.extend_from_slice(&[0xAA; 64]);
        let parsed = parse_signature_header(&buf).expect("parses with trailer");
        assert_eq!(parsed.next_header_offset, 0);
    }

    #[test]
    fn rejects_truncated_input() {
        let buf = [0u8; 10];
        match parse_signature_header(&buf) {
            Err(SevenzError::Truncated { what, needed }) => {
                assert!(what.contains("signature header"));
                assert_eq!(needed, SIGNATURE_HEADER_LEN - 10);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn rejects_wrong_magic() {
        let buf = build_signature_header([0xAA; 6], 0x00, 0x04, 0, 0, 0);
        match parse_signature_header(&buf) {
            Err(SevenzError::CorruptHeader { reason }) => {
                assert!(reason.contains("signature"), "got {reason}");
            }
            other => panic!("expected CorruptHeader, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unsupported_archive_version() {
        // ArchiveVersion = 0.5: rejected with the typed UnsupportedVersion error.
        let buf = build_signature_header(SIGNATURE_MAGIC, 0x00, 0x05, 0, 0, 0);
        match parse_signature_header(&buf) {
            Err(SevenzError::UnsupportedVersion { major, minor }) => {
                assert_eq!((major, minor), (0x00, 0x05));
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }

        // ArchiveVersion = 1.0 — same outcome.
        let buf = build_signature_header(SIGNATURE_MAGIC, 0x01, 0x00, 0, 0, 0);
        match parse_signature_header(&buf) {
            Err(SevenzError::UnsupportedVersion { major, minor }) => {
                assert_eq!((major, minor), (0x01, 0x00));
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn rejects_corrupted_start_header_crc() {
        let mut buf = build_signature_header(SIGNATURE_MAGIC, 0x00, 0x04, 0x100, 0x42, 0xCAFE);
        // Flip a bit in the StartHeaderCRC field itself.
        buf[8] ^= 0x01;
        match parse_signature_header(&buf) {
            Err(SevenzError::CorruptHeader { reason }) => {
                assert!(reason.contains("start-header CRC32"), "got {reason}");
            }
            other => panic!("expected CorruptHeader, got {other:?}"),
        }
    }

    #[test]
    fn rejects_when_payload_corrupted_after_crc_was_set() {
        // CRC was computed over the original NextHeaderOffset; we
        // then flip a bit in that field, so the recorded CRC no
        // longer matches the computed CRC over the (now corrupted)
        // payload.
        let mut buf = build_signature_header(SIGNATURE_MAGIC, 0x00, 0x04, 0x100, 0x42, 0xCAFE);
        buf[12] ^= 0x01;
        match parse_signature_header(&buf) {
            Err(SevenzError::CorruptHeader { reason }) => {
                assert!(reason.contains("CRC32"), "got {reason}");
            }
            other => panic!("expected CorruptHeader, got {other:?}"),
        }
    }

    #[test]
    fn trailer_archive_offset_adds_signature_header_len() {
        let h = SignatureHeader {
            archive_version_major: 0,
            archive_version_minor: 4,
            next_header_offset: 1_000,
            next_header_size: 200,
            next_header_crc: 0,
        };
        assert_eq!(h.trailer_archive_offset().unwrap(), 1032);
    }

    #[test]
    fn trailer_archive_offset_rejects_overflow() {
        let h = SignatureHeader {
            archive_version_major: 0,
            archive_version_minor: 4,
            next_header_offset: u64::MAX,
            next_header_size: 0,
            next_header_crc: 0,
        };
        match h.trailer_archive_offset() {
            Err(SevenzError::CorruptHeader { reason }) => {
                assert!(reason.contains("overflows"), "got {reason}");
            }
            other => panic!("expected CorruptHeader, got {other:?}"),
        }
    }

    #[test]
    fn trailer_range_validates_against_total_size() {
        let h = SignatureHeader {
            archive_version_major: 0,
            archive_version_minor: 4,
            next_header_offset: 100,
            next_header_size: 50,
            next_header_crc: 0,
        };
        // Trailer occupies bytes 132..182. total_size of 200 is fine.
        let (start, len) = h.trailer_range(200).expect("fits");
        assert_eq!(start, 132);
        assert_eq!(len, 50);

        // total_size of 150 is too small.
        match h.trailer_range(150) {
            Err(SevenzError::CorruptHeader { reason }) => {
                assert!(reason.contains("exceeds"), "got {reason}");
            }
            other => panic!("expected CorruptHeader, got {other:?}"),
        }
    }

    #[test]
    fn trailer_range_rejects_size_overflow() {
        let h = SignatureHeader {
            archive_version_major: 0,
            archive_version_minor: 4,
            next_header_offset: 0,
            next_header_size: u64::MAX,
            next_header_crc: 0,
        };
        // 32 + 0 = 32; 32 + u64::MAX overflows.
        match h.trailer_range(u64::MAX) {
            Err(SevenzError::CorruptHeader { reason }) => {
                assert!(reason.contains("overflows"), "got {reason}");
            }
            other => panic!("expected CorruptHeader, got {other:?}"),
        }
    }
}
