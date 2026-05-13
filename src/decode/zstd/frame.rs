//! Zstandard frame-header parsing (RFC 8478 §3.1.1.1.1).
//!
//! Pure logic over a `&[u8]` — no IO, no allocation. The
//! [`super::Decoder`] is responsible for pulling bytes into an
//! in-memory buffer before calling into here.
//!
//! Two kinds of frame magic exist in zstd streams:
//!
//! - **Regular frame** — magic `0x28 0xB5 0x2F 0xFD` (LE
//!   `0xFD2FB528`). Carries a header, one or more blocks, and an
//!   optional 4-byte XXH64 content checksum.
//! - **Skippable frame** — magic in `0x184D2A50..=0x184D2A5F`. The
//!   low nibble is producer-defined; the next 4 bytes after the
//!   magic give a little-endian "user data length", and that many
//!   opaque bytes follow. Decoders are required to skip the whole
//!   thing transparently.
//!
//! Round-one limitations match `internal/PLAN_zstd_block_decoder.md` §Scope:
//!
//! - **`windowLog > 27`** (windows above 128 MiB) is rejected at
//!   parse time. Real-world `tar.zst` files don't trip this; the
//!   `--long` mode that does is deferred to a future round.
//! - **Custom dictionaries** (`Dictionary_ID != 0`) are rejected.
//!   `tar.zst` snapshots produced by the standard `zstd` CLI never
//!   carry one.
//!
//! See `internal/PLAN_zstd_block_decoder.md` Appendix A for the Phase 0
//! spike memo that validated this parser shape against the easy
//! single-segment + 8-byte-FCS path.

use super::error::ZstdError;

/// Regular zstd frame magic (`0x28 0xB5 0x2F 0xFD`, little-endian).
///
/// The bytes a `cargo build` zstd archive begins with.
pub const ZSTD_FRAME_MAGIC: u32 = 0xFD2F_B528;

/// Skippable-frame magic range, low-bound (RFC 8478 §3.1.2).
///
/// A magic matches a skippable frame when
/// `magic & SKIPPABLE_MAGIC_MASK == SKIPPABLE_MAGIC_BASE`. The low
/// nibble (`magic & 0x0F`) is producer-defined; decoders must skip
/// regardless of its value.
pub const SKIPPABLE_MAGIC_BASE: u32 = 0x184D_2A50;

/// Skippable-frame magic mask. See [`SKIPPABLE_MAGIC_BASE`].
pub const SKIPPABLE_MAGIC_MASK: u32 = 0xFFFF_FFF0;

/// Largest `windowLog` round-one accepts (128 MiB sliding window).
///
/// Per `internal/PLAN_zstd_block_decoder.md` §Scope, `windowLog > 27`
/// frames (which `zstd --long` can declare on 64-bit hosts up to
/// 31 / 2 GiB) are rejected with a clean error. Caps the
/// resume-blob ceiling in Phase 7 at the same 128 MiB.
pub const MAX_WINDOW_LOG: u32 = 27;

/// Smallest possible regular-frame header length: 4-byte magic +
/// 1-byte FHD only (single-segment, FCS_flag=0, dict_id_flag=0,
/// happens with `zstd --no-check --no-content-size` on a tiny
/// payload — uncommon in the wild but legal).
pub const MIN_FRAME_HEADER_LEN: usize = 5;

/// Largest possible regular-frame header length: magic 4 + FHD 1 +
/// WD 1 + DID 4 + FCS 8 = 18. The streaming decoder allocates a
/// buffer of this size for the FHD-driven tail read; an undersized
/// constant causes an out-of-bounds slice when the producer picks
/// max-width DID + FCS encodings (found by `cargo fuzz` target
/// `frame_boundary`).
pub const MAX_FRAME_HEADER_LEN: usize = 18;

/// What kind of frame a 4-byte magic identifies.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FrameMagic {
    /// A regular zstd frame; full [`FrameHeader`] follows the magic.
    Regular,
    /// A skippable frame; 4-byte little-endian length follows the
    /// magic, then that many opaque user bytes. The low nibble of
    /// the magic is preserved here for diagnostics, though the
    /// decoder ignores it.
    Skippable {
        /// Producer-defined 4-bit value taken from the magic's low
        /// nibble. Typical `zstd` CLI never emits a non-zero value.
        user_low_nibble: u8,
    },
}

/// Classify a 4-byte little-endian magic value.
///
/// Returns `None` if the bytes don't match any recognised zstd
/// frame magic.
#[must_use]
pub fn classify_magic(magic: u32) -> Option<FrameMagic> {
    if magic == ZSTD_FRAME_MAGIC {
        Some(FrameMagic::Regular)
    } else if magic & SKIPPABLE_MAGIC_MASK == SKIPPABLE_MAGIC_BASE {
        Some(FrameMagic::Skippable {
            user_low_nibble: (magic & 0x0F) as u8,
        })
    } else {
        None
    }
}

/// A parsed regular-frame header.
///
/// The numeric fields are interpreted per RFC 8478 §3.1.1.1.1. See
/// [`parse_frame_header`] for the fallible parser.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct FrameHeader {
    /// Frame_Content_Size, if the producer chose to declare it.
    /// `None` when the FCS field is absent (FCS_flag = 0 and
    /// !single_segment).
    pub fcs: Option<u64>,
    /// Effective window size in bytes — the upper bound on the
    /// sliding-window ring buffer the decoder must allocate. For
    /// single-segment frames this equals [`Self::fcs`]; for
    /// non-single-segment frames it's derived from the
    /// Window_Descriptor byte.
    pub window_size: u64,
    /// Dictionary_ID, when the producer used a custom dictionary.
    /// **Always rejected at parse time** in round one (see module
    /// docs); this field would carry the value to a future
    /// dictionary-aware decoder.
    pub dict_id: Option<u32>,
    /// `true` when the frame ends with a 4-byte little-endian
    /// XXH64-low-32-bits content checksum that the decoder must
    /// verify against its accumulated decompressed output.
    pub has_checksum: bool,
    /// Single_Segment_flag — when set, the producer guarantees the
    /// whole frame's decompressed output fits in [`Self::window_size`]
    /// and there is no separate Window_Descriptor byte on the wire.
    pub single_segment: bool,
    /// Number of input bytes the header consumed (magic +
    /// FHD + WD + DID + FCS), so the caller can advance its read
    /// cursor.
    pub header_size: usize,
}

/// Number of header bytes that follow the FHD byte, given the FHD
/// byte alone.
///
/// Lets the streaming decoder pull just-enough bytes for the
/// variable-length header before calling [`parse_frame_header`]
/// (which wants the whole magic + FHD + tail in one slice). The
/// total wire-format header size is `4 (magic) + 1 (FHD) + this`.
#[must_use]
pub fn frame_header_tail_len(fhd: u8) -> usize {
    let dict_id_flag = fhd & 0b11;
    let single_segment = (fhd >> 5) & 1 == 1;
    let fcs_flag = (fhd >> 6) & 0b11;

    let wd_len: usize = usize::from(!single_segment);
    let did_len: usize = match dict_id_flag {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        // INVARIANT: dict_id_flag = fhd & 0b11, so 0..=3 are exhaustive.
        _ => unreachable!("dict_id_flag is 0..=3 by construction"),
    };
    let fcs_len: usize = match fcs_flag {
        0 => usize::from(single_segment),
        1 => 2,
        2 => 4,
        3 => 8,
        // INVARIANT: same exhaustiveness rationale as `did_len`.
        _ => unreachable!("fcs_flag is 0..=3 by construction"),
    };
    wd_len + did_len + fcs_len
}

/// Parse a regular-frame header from `input`, which must begin at
/// the magic.
///
/// # Errors
///
/// - [`ZstdError::UnexpectedEof`] when the slice is shorter than
///   the structurally-required prefix.
/// - [`ZstdError::BadMagic`] when the leading 4 bytes don't match
///   [`ZSTD_FRAME_MAGIC`]. (Skippable-frame magics are rejected
///   here; the caller is expected to dispatch on
///   [`classify_magic`] first.)
/// - [`ZstdError::MalformedFrameHeader`] for spec violations
///   (windowLog < 10, single-segment with no FCS, etc.).
/// - [`ZstdError::UnsupportedFrameFeature`] when the frame
///   declares a non-zero Dictionary_ID or `windowLog > 27`.
pub fn parse_frame_header(input: &[u8]) -> Result<FrameHeader, ZstdError> {
    if input.len() < MIN_FRAME_HEADER_LEN {
        return Err(ZstdError::UnexpectedEof("frame header"));
    }
    let magic = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    if magic != ZSTD_FRAME_MAGIC {
        return Err(ZstdError::BadMagic { magic });
    }
    let fhd = input[4];
    let dict_id_flag = fhd & 0b11;
    let cc_flag = (fhd >> 2) & 1 == 1;
    let reserved_bit = (fhd >> 3) & 1;
    let single_segment = (fhd >> 5) & 1 == 1;
    let fcs_flag = (fhd >> 6) & 0b11;
    if reserved_bit != 0 {
        return Err(ZstdError::MalformedFrameHeader(
            "reserved bit in Frame_Header_Descriptor must be 0",
        ));
    }

    let mut p: usize = 5;

    // Window_Descriptor byte is present iff !single_segment.
    let mut window_log: u32 = 0;
    let mut wd_mantissa: u64 = 0;
    if !single_segment {
        if input.len() <= p {
            return Err(ZstdError::UnexpectedEof("Window_Descriptor"));
        }
        let wd = input[p];
        p += 1;
        let exponent = u32::from((wd >> 3) & 0b11111);
        let mantissa = u64::from(wd & 0b111);
        // RFC 8478 §3.1.1.1.2: Window_Size = (1 + mantissa/8) *
        // 2^(10 + exponent). The +10 is structural, so the wire
        // format cannot encode a window_log below 10. We reject
        // only the upper-bound case (windowLog > 27) per the
        // round-one --long-mode policy.
        window_log = 10 + exponent;
        if window_log > MAX_WINDOW_LOG {
            return Err(ZstdError::UnsupportedFrameFeature(
                "windowLog > 27 (--long mode)",
            ));
        }
        wd_mantissa = mantissa;
    }

    // Dictionary_ID
    let did_len: usize = match dict_id_flag {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        // INVARIANT: `dict_id_flag = fhd & 0b11`, so values 0..=3 are
        // exhaustive — anything else would mean &-with-3 produced a
        // value > 3, which is impossible.
        _ => unreachable!("dict_id_flag is 0..=3 by construction"),
    };
    if input.len() < p + did_len {
        return Err(ZstdError::UnexpectedEof("Dictionary_ID"));
    }
    let dict_id = if did_len == 0 {
        None
    } else {
        let mut v: u64 = 0;
        for i in 0..did_len {
            v |= u64::from(input[p + i]) << (8 * i);
        }
        Some(v as u32)
    };
    p += did_len;
    if dict_id.unwrap_or(0) != 0 {
        return Err(ZstdError::UnsupportedFrameFeature(
            "non-zero Dictionary_ID (custom dictionaries)",
        ));
    }

    // Frame_Content_Size: 0/1/2/4/8 bytes per (fcs_flag, single_segment).
    let fcs_size: usize = match fcs_flag {
        0 => usize::from(single_segment), // 1 if single_segment, else 0
        1 => 2,
        2 => 4,
        3 => 8,
        // INVARIANT: same exhaustiveness rationale as `did_len`.
        _ => unreachable!("fcs_flag is 0..=3 by construction"),
    };
    if input.len() < p + fcs_size {
        return Err(ZstdError::UnexpectedEof("Frame_Content_Size"));
    }
    let fcs = if fcs_size == 0 {
        None
    } else {
        let mut v: u64 = 0;
        for i in 0..fcs_size {
            v |= u64::from(input[p + i]) << (8 * i);
        }
        // Per RFC 8478 §3.1.1.1.4: when fcs_size == 2 the on-wire
        // value is the actual content size minus 256, expanding the
        // single-byte case usefully. Fix it up here so callers see
        // the true byte count.
        if fcs_size == 2 {
            v = v.checked_add(256).ok_or(ZstdError::MalformedFrameHeader(
                "FCS overflow on +256 fixup",
            ))?;
        }
        Some(v)
    };
    p += fcs_size;

    // Window_Size derivation.
    let window_size = if single_segment {
        // RFC 8478 §3.1.1.1.2: for single-segment frames,
        // Window_Size = Frame_Content_Size. FCS is guaranteed
        // present in this case (fcs_size >= 1 above).
        match fcs {
            Some(v) => v,
            None => {
                return Err(ZstdError::MalformedFrameHeader(
                    "single-segment frame without Frame_Content_Size",
                ));
            }
        }
    } else {
        // base = 1 << window_log; add = (base / 8) * mantissa.
        let base = 1u64 << window_log;
        base + (base >> 3) * wd_mantissa
    };

    Ok(FrameHeader {
        fcs,
        window_size,
        dict_id,
        has_checksum: cc_flag,
        single_segment,
        header_size: p,
    })
}

/// Total on-the-wire size of a skippable frame whose magic begins
/// at the start of `input`.
///
/// The size includes the 4-byte magic, the 4-byte length field,
/// and the user-data payload. The caller is expected to have
/// already classified the magic as [`FrameMagic::Skippable`] via
/// [`classify_magic`].
///
/// # Errors
///
/// - [`ZstdError::UnexpectedEof`] when the slice is shorter than
///   the 8-byte (magic + length) prefix.
pub fn parse_skippable_frame_size(input: &[u8]) -> Result<u64, ZstdError> {
    if input.len() < 8 {
        return Err(ZstdError::UnexpectedEof("skippable frame length"));
    }
    let user_size = u32::from_le_bytes([input[4], input[5], input[6], input[7]]) as u64;
    Ok(8 + user_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a single-segment frame header with FCS=8B and no
    /// other optional fields. Mirrors the fixture pattern from the
    /// Phase 0 spike (Appendix A).
    fn ss_fcs8(content_size: u64, has_checksum: bool) -> [u8; 13] {
        let mut out = [0u8; 13];
        out[0..4].copy_from_slice(&ZSTD_FRAME_MAGIC.to_le_bytes());
        let cc_bit = u8::from(has_checksum);
        // FHD: fcs_flag=3 (bits 7:6=11), single_segment=1 (bit 5),
        // cc_flag (bit 2), dict_id_flag=0.
        out[4] = 0b1110_0000 | (cc_bit << 2);
        out[5..13].copy_from_slice(&content_size.to_le_bytes());
        out
    }

    #[test]
    fn classify_regular_magic() {
        assert_eq!(classify_magic(ZSTD_FRAME_MAGIC), Some(FrameMagic::Regular));
    }

    #[test]
    fn classify_skippable_magic_with_user_nibble() {
        assert_eq!(
            classify_magic(0x184D_2A50),
            Some(FrameMagic::Skippable { user_low_nibble: 0 })
        );
        assert_eq!(
            classify_magic(0x184D_2A5F),
            Some(FrameMagic::Skippable {
                user_low_nibble: 0xF
            })
        );
    }

    #[test]
    fn classify_unknown_magic_returns_none() {
        assert_eq!(classify_magic(0xDEAD_BEEF), None);
        // gzip's magic must not match.
        assert_eq!(classify_magic(0x0000_8B1F), None);
    }

    #[test]
    fn parse_single_segment_with_8byte_fcs() {
        let hdr = ss_fcs8(16, false);
        let parsed = parse_frame_header(&hdr).expect("parse");
        assert_eq!(parsed.fcs, Some(16));
        assert_eq!(parsed.window_size, 16);
        assert!(parsed.single_segment);
        assert!(!parsed.has_checksum);
        assert_eq!(parsed.dict_id, None);
        assert_eq!(parsed.header_size, 13);
    }

    #[test]
    fn parse_single_segment_with_checksum_flag() {
        let hdr = ss_fcs8(64, true);
        let parsed = parse_frame_header(&hdr).expect("parse");
        assert!(parsed.has_checksum);
    }

    #[test]
    fn parse_with_window_descriptor_and_2byte_fcs() {
        // FHD: fcs_flag=1 (bits 7:6=01), single_segment=0,
        // cc_flag=0, dict_id_flag=0 -> 0b0100_0000 = 0x40.
        // WD: exponent=10 (windowLog=20), mantissa=0 -> wd = 10 << 3 = 0x50.
        // FCS (2B): on-wire = 1024 - 256 = 768 (0x0300 LE).
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&ZSTD_FRAME_MAGIC.to_le_bytes());
        hdr.push(0x40);
        hdr.push(0x50);
        hdr.extend_from_slice(&768u16.to_le_bytes());
        let parsed = parse_frame_header(&hdr).expect("parse");
        // FCS got the +256 fixup applied.
        assert_eq!(parsed.fcs, Some(1024));
        // window_log=20 -> base=1MiB; mantissa=0 -> add=0.
        assert_eq!(parsed.window_size, 1 << 20);
        assert!(!parsed.single_segment);
        assert_eq!(parsed.header_size, hdr.len());
    }

    #[test]
    fn parse_rejects_bad_magic() {
        let mut buf = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00];
        match parse_frame_header(&buf) {
            Err(ZstdError::BadMagic { magic }) => {
                assert_eq!(magic, 0xEFBE_ADDE);
            }
            other => panic!("expected BadMagic, got {other:?}"),
        }
        // Skippable magic is also rejected by parse_frame_header
        // (caller must dispatch on classify_magic first).
        buf[0..4].copy_from_slice(&SKIPPABLE_MAGIC_BASE.to_le_bytes());
        assert!(matches!(
            parse_frame_header(&buf),
            Err(ZstdError::BadMagic { .. })
        ));
    }

    #[test]
    fn parse_rejects_truncated_header() {
        let hdr = ss_fcs8(0, false);
        // 5 bytes is enough for magic + FHD but not the 8-byte FCS.
        for take in 0..hdr.len() {
            let res = parse_frame_header(&hdr[..take]);
            assert!(res.is_err(), "should fail at {take} bytes: {res:?}");
        }
        assert!(parse_frame_header(&hdr).is_ok());
    }

    #[test]
    fn parse_rejects_reserved_bit_set() {
        let mut hdr = ss_fcs8(0, false);
        hdr[4] |= 1 << 3;
        assert!(matches!(
            parse_frame_header(&hdr),
            Err(ZstdError::MalformedFrameHeader(_))
        ));
    }

    #[test]
    fn parse_accepts_window_log_minimum_of_10() {
        // RFC 8478 §3.1.1.1.2: Window_Size = (1 + mantissa/8) *
        // 2^(10 + exponent), so the smallest valid window_log is
        // 10 (exponent = 0, mantissa = 0).
        // FHD: fcs_flag=0, single_segment=0, dict_id=0 -> 0x00.
        // WD: exponent=0, mantissa=0 -> 0x00.
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&ZSTD_FRAME_MAGIC.to_le_bytes());
        hdr.push(0x00);
        hdr.push(0x00);
        let h = parse_frame_header(&hdr).expect("parse");
        assert_eq!(h.window_size, 1 << 10);
    }

    #[test]
    fn parse_rejects_window_log_above_27() {
        // exponent = 18 -> windowLog = 28 (> 27)
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&ZSTD_FRAME_MAGIC.to_le_bytes());
        hdr.push(0x00);
        hdr.push(18 << 3);
        assert!(matches!(
            parse_frame_header(&hdr),
            Err(ZstdError::UnsupportedFrameFeature(_))
        ));
    }

    #[test]
    fn parse_rejects_non_zero_dict_id() {
        // FHD: dict_id_flag=1 (1B DID), single_segment=1, fcs_flag=3.
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&ZSTD_FRAME_MAGIC.to_le_bytes());
        hdr.push(0b1110_0001);
        hdr.push(0x42); // DID=0x42
        hdr.extend_from_slice(&16u64.to_le_bytes());
        assert!(matches!(
            parse_frame_header(&hdr),
            Err(ZstdError::UnsupportedFrameFeature(_))
        ));
    }

    #[test]
    fn parse_skippable_size_includes_8_byte_prefix() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&SKIPPABLE_MAGIC_BASE.to_le_bytes());
        frame.extend_from_slice(&100u32.to_le_bytes());
        // (no need to actually populate the user data for size parsing)
        assert_eq!(parse_skippable_frame_size(&frame).unwrap(), 108);
    }

    #[test]
    fn parse_skippable_size_rejects_truncated_prefix() {
        for take in 0..8 {
            let buf = vec![0u8; take];
            assert!(parse_skippable_frame_size(&buf).is_err());
        }
    }

    /// Regression test for a fuzz-discovered out-of-bounds slice: the
    /// streaming decoder allocates `[0u8; MAX_FRAME_HEADER_LEN]` and
    /// slices `full[5..5 + frame_header_tail_len(fhd)]` *before*
    /// `parse_frame_header` rejects non-zero dict_id / reserved-bit
    /// FHDs, so the constant must cover every FHD value, not just
    /// the ones the parser accepts. Prior to the fix the constant
    /// was 14 while the actual max (FHD=0xF7: SS+max-DID+max-FCS)
    /// is 18.
    #[test]
    fn max_frame_header_len_covers_every_fhd_tail() {
        let mut worst = 0usize;
        let mut worst_fhd = 0u8;
        for fhd in 0u8..=0xFF {
            let total = 5 + frame_header_tail_len(fhd);
            if total > worst {
                worst = total;
                worst_fhd = fhd;
            }
        }
        assert!(
            worst <= MAX_FRAME_HEADER_LEN,
            "fhd=0x{worst_fhd:02X} needs {worst} header bytes but \
             MAX_FRAME_HEADER_LEN={MAX_FRAME_HEADER_LEN}",
        );
        // Sanity: the worst case should match the documented arithmetic.
        assert_eq!(worst, 18, "RFC 8478 max regular-frame header");
    }

    #[test]
    fn tail_len_matches_parse_for_every_in_scope_fhd() {
        // For every FHD byte that produces a Phase-1-compatible
        // header (no reserved bit set, no dict_id), the streaming
        // tail length must agree with what parse_frame_header
        // actually consumes after the magic + FHD prefix.
        for fhd in 0u8..=0xFF {
            // Skip FHDs we don't support: reserved bit, non-zero
            // dict id (dict_id_flag != 0).
            if (fhd >> 3) & 1 != 0 {
                continue;
            }
            if fhd & 0b11 != 0 {
                // Dict-IDs are tested separately via parse_rejects_*.
                continue;
            }
            let tail = frame_header_tail_len(fhd);
            let mut buf = Vec::with_capacity(5 + tail);
            buf.extend_from_slice(&ZSTD_FRAME_MAGIC.to_le_bytes());
            buf.push(fhd);
            // Need a valid Window_Descriptor when !single_segment:
            // exponent >= 10 and <= 17 (windowLog 20..=27 stays in cap).
            let single_segment = (fhd >> 5) & 1 == 1;
            if !single_segment {
                buf.push(10 << 3); // exponent=10, mantissa=0 -> 1 MiB window
            }
            // Pad rest with zeros — values don't matter for tail-len check.
            buf.resize(5 + tail, 0);
            // Single-segment frames need FCS >= 1 to satisfy the
            // "non-zero window_size for single segment" sanity in
            // some parsers; we don't enforce that, just don't blow up.
            let parsed = parse_frame_header(&buf).expect("parse");
            assert_eq!(parsed.header_size, 5 + tail, "fhd=0x{fhd:02X} tail={tail}",);
        }
    }
}
