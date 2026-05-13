//! 7z wire-format primitive parsers.
//!
//! Reference: 7-Zip's `DOC/7zFormat.txt`. There is no formal RFC;
//! the parsers here are hand-rolled per
//! `internal/ENGINEERING_STANDARDS.md` §2.1, the same posture taken
//! for tar (`internal/PLAN.md` §7.3) and zip (`internal/PLAN_v2.md` §5).
//!
//! Every later phase of `internal/PLAN_7z_support.md` composes these
//! primitives — getting them right once, with property tests,
//! beats catching off-by-ones in §3 / §4.
//!
//! Each parser takes an immutable byte slice and returns the
//! parsed value plus the *unconsumed remainder*. Composing them
//! is a matter of threading the remainder through:
//!
//! ```ignore
//! let (n, rest) = parse_number(input)?;
//! let (bits, rest) = parse_bool_vector(rest, n as usize)?;
//! ```
//!
//! No parser allocates beyond the typed value it returns, and no
//! parser does IO — the second-pipeline driver is responsible for
//! making the bytes available.

use std::path::{Component, Path, PathBuf};

use crate::sevenz::SevenzError;

/// Parse a 7z `Number` (variable-length unsigned 64-bit integer).
///
/// The encoding is documented in `DOC/7zFormat.txt` under
/// `Real_UINT64`: the count of leading 1-bits in the first byte
/// names the number of *additional* little-endian trailing bytes,
/// with any remaining low bits of the first byte (those below the
/// sentinel 0) contributing to the high bits of the result.
///
/// Total encoded length ranges from 1 byte (values < 128) to
/// 9 bytes (values ≥ 2⁵⁶).
///
/// # Errors
///
/// [`SevenzError::Truncated`] if `input` ends before the encoded
/// integer completes.
pub fn parse_number(input: &[u8]) -> Result<(u64, &[u8]), SevenzError> {
    let (&first, mut cursor) = input.split_first().ok_or(SevenzError::Truncated {
        what: "Number first byte".into(),
        needed: 1,
    })?;
    let mut value: u64 = 0;
    let mut mask: u8 = 0x80;
    for i in 0u32..8 {
        if (first & mask) == 0 {
            // Sentinel 0 reached: any remaining low bits of `first`
            // contribute to the high bytes of `value`.
            let high_part = u64::from(first & mask.wrapping_sub(1));
            value |= high_part << (i * 8);
            return Ok((value, cursor));
        }
        let (&b, next) = cursor.split_first().ok_or_else(|| SevenzError::Truncated {
            what: format!("Number trailing byte {} of up to 8", i + 1),
            needed: 1,
        })?;
        value |= u64::from(b) << (i * 8);
        mask >>= 1;
        cursor = next;
    }
    // `first == 0xFF`: 8 trailing bytes, no high contribution.
    Ok((value, cursor))
}

/// Parse a propid byte: a single-byte tag the higher-level header
/// parser switches on.
///
/// The set of meaningful values is documented in
/// `DOC/7zFormat.txt` (e.g. `0x00` = `End`, `0x01` = `Header`,
/// `0x04` = `MainStreamsInfo`, `0x05` = `FilesInfo`,
/// `0x06` = `PackInfo`, `0x17` = `EncodedHeader`); the typed
/// dispatch lives in §3 of `internal/PLAN_7z_support.md`. This
/// primitive only validates that the byte exists.
///
/// # Errors
///
/// [`SevenzError::Truncated`] if `input` is empty.
pub fn parse_propid(input: &[u8]) -> Result<(u8, &[u8]), SevenzError> {
    input
        .split_first()
        .map(|(b, rest)| (*b, rest))
        .ok_or(SevenzError::Truncated {
            what: "propid byte".into(),
            needed: 1,
        })
}

/// Parse a `BoolVector(n)`: a packed bit-string of `n` boolean
/// values stored MSB-first in `ceil(n / 8)` bytes.
///
/// Per `DOC/7zFormat.txt`:
///
/// ```text
/// for (i = 0; i < n; i++) {
///   if (i % 8 == 0) byte = ReadByte();
///   bool[i] = (byte & 0x80) != 0;
///   byte <<= 1;
/// }
/// ```
///
/// `n == 0` is well-formed and consumes zero bytes.
///
/// # Errors
///
/// [`SevenzError::Truncated`] if `input` has fewer than
/// `ceil(n / 8)` bytes.
pub fn parse_bool_vector(input: &[u8], n: usize) -> Result<(Vec<bool>, &[u8]), SevenzError> {
    let bytes_needed = n.div_ceil(8);
    if input.len() < bytes_needed {
        return Err(SevenzError::Truncated {
            what: format!("BoolVector body for {n} bit(s)"),
            needed: bytes_needed - input.len(),
        });
    }
    let (body, rest) = input.split_at(bytes_needed);
    let mut bits = Vec::with_capacity(n);
    let mut byte: u8 = 0;
    for i in 0..n {
        if i & 0x07 == 0 {
            byte = body[i / 8];
        }
        bits.push((byte & 0x80) != 0);
        byte <<= 1;
    }
    Ok((bits, rest))
}

/// Parse an "all-defined-or-explicit" predicate vector of length
/// `n` — the 7z `BitVector` shape used for `is-defined`
/// predicates (e.g. CRCs are present for *some* but not all
/// folders).
///
/// Layout:
///
/// ```text
///   BYTE AllAreDefined;
///   if (AllAreDefined == 0)
///     BoolVector(n);  // packed bits, MSB-first
/// ```
///
/// When `AllAreDefined != 0`, the function returns `vec![true; n]`
/// without consuming any further bytes.
///
/// # Errors
///
/// [`SevenzError::Truncated`] if `input` is too short for the
/// preamble byte or — when the preamble is `0` — for the body.
pub fn parse_bit_vector(input: &[u8], n: usize) -> Result<(Vec<bool>, &[u8]), SevenzError> {
    let (all_defined, rest) = parse_propid(input).map_err(|_| SevenzError::Truncated {
        what: "BitVector AllAreDefined byte".into(),
        needed: 1,
    })?;
    if all_defined != 0 {
        return Ok((vec![true; n], rest));
    }
    parse_bool_vector(rest, n)
}

/// Read one zero-terminated UTF-16LE name and return it as a
/// sanitized [`PathBuf`].
///
/// File names in 7z's `FilesInfo.Names` property are stored as
/// concatenated UTF-16LE strings, each terminated by a `0x0000`
/// code unit. This primitive decodes one such string, advancing
/// the cursor *past* the terminator.
///
/// Sanitization (per `internal/PLAN_7z_support.md` §1.5, mirroring the
/// rules in [`crate::sink`]'s `TarSink` / `ZipSink`):
///
/// - Reject invalid UTF-16LE.
/// - Reject empty names and names that decompose to zero
///   non-trivial path components.
/// - Reject embedded NUL (`'\0'`) in the decoded string.
/// - Reject absolute paths (leading `/` or `\`).
/// - Reject Windows drive-letter prefixes (`X:`).
/// - Split on both `/` and `\` separators; reject any `..`
///   component, any component that does not parse to a single
///   `Component::Normal`, and any path that ends up empty.
///
/// # Errors
///
/// - [`SevenzError::Truncated`] if `input` ends before a `0x0000`
///   terminator is found.
/// - [`SevenzError::BadName`] if the decoded name fails any of
///   the sanitization rules above. The variant's `reason` field
///   carries the specific failure.
pub fn read_name_utf16le_zero_terminated(input: &[u8]) -> Result<(PathBuf, &[u8]), SevenzError> {
    let mut units: Vec<u16> = Vec::new();
    let mut cursor = input;
    let mut idx: u32 = 0;
    loop {
        if cursor.len() < 2 {
            return Err(SevenzError::Truncated {
                what: format!("UTF-16LE name code unit {idx}"),
                needed: 2 - cursor.len(),
            });
        }
        let unit = u16::from_le_bytes([cursor[0], cursor[1]]);
        cursor = &cursor[2..];
        if unit == 0 {
            break;
        }
        units.push(unit);
        idx = idx.saturating_add(1);
    }
    let name = String::from_utf16(&units).map_err(|_| SevenzError::BadName {
        reason: "invalid UTF-16LE".into(),
    })?;
    let path = sanitize_name(&name)?;
    Ok((path, cursor))
}

/// Apply the §1.5 anti-traversal rules to a decoded UTF-16LE
/// string and return a [`PathBuf`] composed of safe components.
///
/// Visible to sibling modules (the §3 `FilesInfo` parser would
/// hand-build a `String` from a different code path if names ever
/// appeared in another property), but not part of the crate's
/// public surface.
fn sanitize_name(name: &str) -> Result<PathBuf, SevenzError> {
    if name.is_empty() {
        return Err(SevenzError::BadName {
            reason: "empty name".into(),
        });
    }
    if name.contains('\0') {
        return Err(SevenzError::BadName {
            reason: "embedded NUL".into(),
        });
    }
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(SevenzError::BadName {
            reason: "absolute path".into(),
        });
    }
    // Drive-letter prefix: any name where the second character is
    // ':' is a Windows-style absolute path (`C:\foo`, `Z:/bar`)
    // and would escape the output dir on a Windows host. The 7z
    // format does not use ':' for any other purpose in names, so
    // a blanket reject is safe.
    if name.len() >= 2 && name.as_bytes().get(1) == Some(&b':') {
        return Err(SevenzError::BadName {
            reason: "drive-letter prefix".into(),
        });
    }
    let mut out = PathBuf::new();
    let mut pushed = 0usize;
    for component in name.split(['/', '\\']) {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            return Err(SevenzError::BadName {
                reason: "path component '..'".into(),
            });
        }
        // Defense in depth: anything other than a single
        // `Component::Normal` from `Path::components()` is
        // rejected. Catches Windows-style oddities a future
        // cross-platform expansion might miss.
        if Path::new(component)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(SevenzError::BadName {
                reason: "non-normal path component".into(),
            });
        }
        out.push(component);
        pushed += 1;
    }
    if pushed == 0 {
        return Err(SevenzError::BadName {
            reason: "empty after sanitization".into(),
        });
    }
    Ok(out)
}

#[cfg(test)]
pub(crate) mod tests_support {
    //! Test-only helpers shared with sibling test modules
    //! (notably `header::tests`, which needs the same
    //! `encode_number` to construct hand-built trailers).

    /// Re-encode `value` to its canonical 7z `Number` byte
    /// sequence. Picks the smallest size that fits.
    ///
    /// Only used by the test suite — production code never
    /// emits a `Number`. Matches
    /// [`super::parse_number`] by construction because both
    /// follow `DOC/7zFormat.txt` directly.
    pub fn encode_number_helper(value: u64) -> Vec<u8> {
        if value < (1u64 << 7) {
            return vec![value as u8];
        }
        for size in 2u32..=8 {
            let bits = 7 * size;
            let max = if bits >= 64 {
                u64::MAX
            } else {
                (1u64 << bits) - 1
            };
            if value <= max {
                let leading_ones = size - 1;
                let header_top = ((1u8 << leading_ones) - 1) << (8 - leading_ones);
                let high_value = value >> (8 * (size as u64 - 1));
                let header = header_top | (high_value as u8);
                let mut out = Vec::with_capacity(size as usize);
                out.push(header);
                for i in 0..(size - 1) {
                    out.push((value >> (8 * i)) as u8);
                }
                return out;
            }
        }
        let mut out = Vec::with_capacity(9);
        out.push(0xFF);
        for i in 0..8 {
            out.push((value >> (8 * i)) as u8);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::encode_number_helper as encode_number;
    use super::*;

    #[test]
    fn parse_number_single_byte_values() {
        for v in [0u64, 1, 0x42, 0x7F] {
            let bytes = encode_number(v);
            assert_eq!(bytes.len(), 1);
            let (decoded, rest) = parse_number(&bytes).expect("parses");
            assert_eq!(decoded, v);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn parse_number_two_byte_boundary() {
        // 0x80 is the smallest value that needs 2 bytes.
        let bytes = encode_number(0x80);
        assert_eq!(bytes, vec![0x80, 0x80]);
        let (decoded, rest) = parse_number(&bytes).expect("parses");
        assert_eq!(decoded, 0x80);
        assert!(rest.is_empty());

        // 0x3FFF is the largest value that fits in 2 bytes.
        let bytes = encode_number(0x3FFF);
        assert_eq!(bytes.len(), 2);
        let (decoded, _) = parse_number(&bytes).expect("parses");
        assert_eq!(decoded, 0x3FFF);
    }

    #[test]
    fn parse_number_three_byte_boundary() {
        // 0x4000 is the smallest value that needs 3 bytes.
        let bytes = encode_number(0x4000);
        assert_eq!(bytes.len(), 3);
        let (decoded, _) = parse_number(&bytes).expect("parses");
        assert_eq!(decoded, 0x4000);
    }

    #[test]
    fn parse_number_handles_eight_byte_form() {
        // Within size=8 capacity (2^56 - 1 max for size 8).
        let v = (1u64 << 49) | 0xCAFE;
        let bytes = encode_number(v);
        assert_eq!(bytes.len(), 8);
        let (decoded, _) = parse_number(&bytes).expect("parses");
        assert_eq!(decoded, v);
    }

    #[test]
    fn parse_number_handles_nine_byte_form() {
        for v in [1u64 << 56, u64::MAX, 0xFFFF_FFFF_FFFF_FFFF] {
            let bytes = encode_number(v);
            assert_eq!(bytes.len(), 9);
            assert_eq!(bytes[0], 0xFF);
            let (decoded, rest) = parse_number(&bytes).expect("parses");
            assert_eq!(decoded, v);
            assert!(rest.is_empty());
        }
    }

    #[test]
    fn parse_number_returns_unconsumed_suffix() {
        let mut bytes = encode_number(0xABCD);
        bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let prefix_len = bytes.len() - 4;
        let (decoded, rest) = parse_number(&bytes).expect("parses");
        assert_eq!(decoded, 0xABCD);
        assert_eq!(rest, &bytes[prefix_len..]);
    }

    #[test]
    fn parse_number_truncated_input_surfaces_typed_error() {
        match parse_number(&[]) {
            Err(SevenzError::Truncated { what, needed }) => {
                assert!(what.contains("Number"));
                assert_eq!(needed, 1);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }

        // Header says 4 trailing bytes but only 2 supplied.
        match parse_number(&[0xE0, 0x01, 0x02]) {
            Err(SevenzError::Truncated { what, needed }) => {
                assert!(what.contains("trailing"), "got {what}");
                assert_eq!(needed, 1);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn parse_number_round_trip_property() {
        // Hand-rolled deterministic property test (proptest is
        // not on the dependency allowlist). Sweeps every byte
        // boundary plus a multiplicative ladder of values.
        let mut samples: Vec<u64> = vec![0, 1, 2, 0x7F, 0x80, 0x81, 0x3FFF, 0x4000];
        for shift in 0..64 {
            let v: u64 = 1u64 << shift;
            samples.push(v);
            samples.push(v.wrapping_sub(1));
            samples.push(v.wrapping_add(1));
        }
        // LCG-derived pseudo-random samples.
        let mut state: u64 = 0xDEAD_BEEF_CAFE_BABE;
        for _ in 0..1000 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            samples.push(state);
        }
        for v in samples {
            let bytes = encode_number(v);
            let (decoded, rest) = parse_number(&bytes).expect("parses");
            assert_eq!(
                decoded, v,
                "round-trip failed for {v:#018x}: encoded {bytes:02X?}"
            );
            assert!(
                rest.is_empty(),
                "leftover bytes for {v:#018x}: encoded {bytes:02X?}"
            );
        }
    }

    #[test]
    fn parse_propid_returns_byte_and_remainder() {
        let (tag, rest) = parse_propid(&[0x17, 0x42, 0xFF]).expect("parses");
        assert_eq!(tag, 0x17);
        assert_eq!(rest, &[0x42, 0xFF]);
    }

    #[test]
    fn parse_propid_rejects_empty_input() {
        match parse_propid(&[]) {
            Err(SevenzError::Truncated { what, needed }) => {
                assert!(what.contains("propid"));
                assert_eq!(needed, 1);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn parse_bool_vector_zero_length_consumes_no_bytes() {
        let input = [0xAB, 0xCD];
        let (bits, rest) = parse_bool_vector(&input, 0).expect("parses");
        assert!(bits.is_empty());
        assert_eq!(rest, &input);
    }

    #[test]
    fn parse_bool_vector_msb_first_within_byte() {
        // 0b10110001 → [true, false, true, true, false, false, false, true]
        let (bits, rest) = parse_bool_vector(&[0b1011_0001], 8).expect("parses");
        assert_eq!(
            bits,
            vec![true, false, true, true, false, false, false, true]
        );
        assert!(rest.is_empty());
    }

    #[test]
    fn parse_bool_vector_partial_final_byte_pads_low_bits() {
        // n=10 needs 2 bytes; only the top 2 bits of byte 1 are
        // consumed. Trailing bits in byte 1 are ignored.
        let (bits, rest) =
            parse_bool_vector(&[0b1100_0000, 0b1000_0000, 0xFF], 10).expect("parses");
        assert_eq!(
            bits,
            vec![true, true, false, false, false, false, false, false, true, false]
        );
        assert_eq!(rest, &[0xFF]);
    }

    #[test]
    fn parse_bool_vector_truncated_input_surfaces_typed_error() {
        match parse_bool_vector(&[0xFF], 9) {
            Err(SevenzError::Truncated { what, needed }) => {
                assert!(what.contains("BoolVector"));
                assert_eq!(needed, 1);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn parse_bit_vector_all_defined_short_circuits() {
        // AllAreDefined = 1 → vec![true; 5], no body byte.
        let (bits, rest) = parse_bit_vector(&[0x01, 0xCC], 5).expect("parses");
        assert_eq!(bits, vec![true; 5]);
        assert_eq!(rest, &[0xCC]);
    }

    #[test]
    fn parse_bit_vector_zero_preamble_reads_packed_body() {
        // AllAreDefined = 0, body 0b1010_0000 → [t,f,t,f,f,f,f,f]
        let (bits, rest) = parse_bit_vector(&[0x00, 0b1010_0000, 0xCC], 4).expect("parses");
        assert_eq!(bits, vec![true, false, true, false]);
        assert_eq!(rest, &[0xCC]);
    }

    #[test]
    fn parse_bit_vector_truncated_input_surfaces_typed_error() {
        match parse_bit_vector(&[], 4) {
            Err(SevenzError::Truncated { what, .. }) => {
                assert!(what.contains("BitVector"));
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
        match parse_bit_vector(&[0x00], 4) {
            Err(SevenzError::Truncated { .. }) => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    /// Encode `text` as zero-terminated UTF-16LE for the name-decoder
    /// tests. Test-only: production never emits.
    fn encode_name(text: &str) -> Vec<u8> {
        let mut out: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        out.extend_from_slice(&[0x00, 0x00]);
        out
    }

    #[test]
    fn read_name_decodes_ascii() {
        let bytes = encode_name("hello.txt");
        let (path, rest) = read_name_utf16le_zero_terminated(&bytes).expect("parses");
        assert_eq!(path, PathBuf::from("hello.txt"));
        assert!(rest.is_empty());
    }

    #[test]
    fn read_name_handles_concatenated_strings() {
        let mut buf = encode_name("a.txt");
        buf.extend_from_slice(&encode_name("b.txt"));
        let (a, rest) = read_name_utf16le_zero_terminated(&buf).expect("parses a");
        assert_eq!(a, PathBuf::from("a.txt"));
        let (b, rest) = read_name_utf16le_zero_terminated(rest).expect("parses b");
        assert_eq!(b, PathBuf::from("b.txt"));
        assert!(rest.is_empty());
    }

    #[test]
    fn read_name_decodes_utf16_surrogate_pair() {
        // U+1F600 GRINNING FACE — encodes as a surrogate pair.
        let bytes = encode_name("smile-\u{1F600}.txt");
        let (path, _) = read_name_utf16le_zero_terminated(&bytes).expect("parses");
        assert_eq!(path, PathBuf::from("smile-\u{1F600}.txt"));
    }

    #[test]
    fn read_name_normalizes_backslash_separators() {
        let bytes = encode_name(r"sub\dir\leaf.txt");
        let (path, _) = read_name_utf16le_zero_terminated(&bytes).expect("parses");
        assert_eq!(path, PathBuf::from("sub").join("dir").join("leaf.txt"));
    }

    #[test]
    fn read_name_normalizes_forward_slash_separators() {
        let bytes = encode_name("sub/dir/leaf.txt");
        let (path, _) = read_name_utf16le_zero_terminated(&bytes).expect("parses");
        assert_eq!(path, PathBuf::from("sub").join("dir").join("leaf.txt"));
    }

    #[test]
    fn read_name_rejects_path_traversal_dotdot() {
        let bytes = encode_name("../etc/passwd");
        match read_name_utf16le_zero_terminated(&bytes) {
            Err(SevenzError::BadName { reason }) => {
                assert!(reason.contains(".."), "got {reason}");
            }
            other => panic!("expected BadName, got {other:?}"),
        }
    }

    #[test]
    fn read_name_rejects_absolute_unix_path() {
        let bytes = encode_name("/etc/passwd");
        match read_name_utf16le_zero_terminated(&bytes) {
            Err(SevenzError::BadName { reason }) => {
                assert!(reason.contains("absolute"), "got {reason}");
            }
            other => panic!("expected BadName, got {other:?}"),
        }
    }

    #[test]
    fn read_name_rejects_absolute_windows_path() {
        let bytes = encode_name(r"\windows\system32\cmd.exe");
        match read_name_utf16le_zero_terminated(&bytes) {
            Err(SevenzError::BadName { reason }) => {
                assert!(reason.contains("absolute"), "got {reason}");
            }
            other => panic!("expected BadName, got {other:?}"),
        }
    }

    #[test]
    fn read_name_rejects_drive_letter_prefix() {
        let bytes = encode_name(r"C:\windows\cmd.exe");
        match read_name_utf16le_zero_terminated(&bytes) {
            Err(SevenzError::BadName { reason }) => {
                assert!(reason.contains("drive-letter"), "got {reason}");
            }
            other => panic!("expected BadName, got {other:?}"),
        }
    }

    #[test]
    fn read_name_rejects_empty_string() {
        let bytes = encode_name("");
        match read_name_utf16le_zero_terminated(&bytes) {
            Err(SevenzError::BadName { reason }) => {
                assert!(reason.contains("empty"), "got {reason}");
            }
            other => panic!("expected BadName, got {other:?}"),
        }
    }

    #[test]
    fn read_name_rejects_only_separators() {
        let bytes = encode_name("///\\\\");
        match read_name_utf16le_zero_terminated(&bytes) {
            Err(SevenzError::BadName { .. }) => {}
            other => panic!("expected BadName, got {other:?}"),
        }
    }

    #[test]
    fn read_name_rejects_invalid_utf16_surrogate() {
        // Lone high surrogate — invalid UTF-16. We hand-build the
        // bytes (the encoder cannot emit this from a Rust `str`).
        let bytes: Vec<u8> = vec![0x00, 0xD8, 0x00, 0x00];
        match read_name_utf16le_zero_terminated(&bytes) {
            Err(SevenzError::BadName { reason }) => {
                assert!(reason.contains("UTF-16"), "got {reason}");
            }
            other => panic!("expected BadName, got {other:?}"),
        }
    }

    #[test]
    fn read_name_truncated_when_no_terminator() {
        // No 0x0000 terminator anywhere in the slice.
        let bytes = b"\x61\x00\x62\x00".to_vec(); // "ab" without NUL
        match read_name_utf16le_zero_terminated(&bytes) {
            Err(SevenzError::Truncated { what, .. }) => {
                assert!(what.contains("UTF-16"), "got {what}");
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn read_name_truncated_on_odd_byte_length() {
        // Single byte before terminator — would-be u16 short.
        let bytes = vec![0x41u8];
        match read_name_utf16le_zero_terminated(&bytes) {
            Err(SevenzError::Truncated { needed, .. }) => {
                assert_eq!(needed, 1);
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }
}
