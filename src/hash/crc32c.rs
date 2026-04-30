//! CRC-32C (Castagnoli) — the variant used as the per-chunk
//! fingerprint by `PLAN_v2.md` §11's mid-flight source-change
//! detector.
//!
//! Hand-rolled per `docs/ENGINEERING_STANDARDS.md` §2.1 (the same
//! reasoning that justifies [`crate::zip::crc32`] applies here): a
//! ~150-line table-driven implementation comfortably exceeds the
//! ~100 MiB/s the §11 hot path needs and avoids dragging in another
//! dependency for one fingerprint.
//!
//! The polynomial is the reflected form `0x82F6_3B78` and the
//! initial / final XOR is `!0u32`. This matches the variant
//! standardized by RFC 3720 (iSCSI) and used by `crc32c`, SSE 4.2's
//! `crc32` instruction, and the Btrfs / ext4 metadata checksum
//! routines. It is **not** the same polynomial as the ZIP / gzip
//! [`crate::zip::crc32`]; the two are intentionally separate because
//! ZIP's wire format pins its CRC variant and §11's per-chunk
//! fingerprint is independent of any wire format.

/// 256-entry lookup table for the byte-at-a-time CRC-32C inner loop.
///
/// `const` so the constant is folded at compile time and we don't
/// pay a one-time initialization cost on the hot path.
const TABLE: [u32; 256] = build_table();

const fn build_table() -> [u32; 256] {
    const POLY: u32 = 0x82F6_3B78;
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut c = i;
        let mut j = 0;
        while j < 8 {
            if c & 1 != 0 {
                c = (c >> 1) ^ POLY;
            } else {
                c >>= 1;
            }
            j += 1;
        }
        table[i as usize] = c;
        i += 1;
    }
    table
}

/// Streaming CRC-32C hasher.
///
/// Construct with [`Self::new`], feed bytes via [`Self::update`],
/// extract the final value with [`Self::finalize`].
#[derive(Debug, Clone, Copy)]
pub struct Crc32c {
    state: u32,
}

impl Default for Crc32c {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32c {
    /// New, empty hasher. Equivalent to [`Self::default`].
    #[must_use]
    pub const fn new() -> Self {
        Self { state: !0u32 }
    }

    /// Feed the next chunk of input into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        let mut state = self.state;
        for &b in data {
            state = TABLE[((state ^ u32::from(b)) & 0xFF) as usize] ^ (state >> 8);
        }
        self.state = state;
    }

    /// Return the final CRC-32C value over all bytes fed so far.
    #[must_use]
    pub fn finalize(self) -> u32 {
        !self.state
    }
}

/// Convenience: full-buffer CRC-32C in one call.
///
/// Equivalent to constructing a [`Crc32c`], feeding `data` through
/// [`Crc32c::update`], and returning [`Crc32c::finalize`].
#[must_use]
pub fn castagnoli(data: &[u8]) -> u32 {
    let mut c = Crc32c::new();
    c.update(data);
    c.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_zero() {
        // CRC-32C of the empty string is 0 by construction (the
        // initial !0 state, finalized via final XOR with !0, yields
        // 0).
        assert_eq!(castagnoli(b""), 0);
    }

    #[test]
    fn check_vector_numeric_run() {
        // Canonical CRC-32C "check" vector from RFC 3720 §B.4:
        // CRC-32C("123456789") = 0xE3069283.
        assert_eq!(castagnoli(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn check_vector_all_zeros() {
        // 32 bytes of zero — RFC 3720 §B.4 lists this as 0x8A9136AA.
        let zeros = [0u8; 32];
        assert_eq!(castagnoli(&zeros), 0x8A91_36AA);
    }

    #[test]
    fn check_vector_all_ones() {
        // 32 bytes of 0xFF — RFC 3720 §B.4 lists this as 0x62A8AB43.
        let ones = [0xFFu8; 32];
        assert_eq!(castagnoli(&ones), 0x62A8_AB43);
    }

    #[test]
    fn check_vector_incrementing() {
        // 32 bytes of 0x00..0x1F — RFC 3720 §B.4 lists this as
        // 0x46DD794E.
        let mut buf = [0u8; 32];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(castagnoli(&buf), 0x46DD_794E);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let payload: Vec<u8> = (0..=255u8).chain(0..=255u8).collect();
        let one_shot = castagnoli(&payload);

        let mut c = Crc32c::new();
        c.update(&payload[..1]);
        c.update(&payload[1..6]);
        c.update(&payload[6..]);
        assert_eq!(c.finalize(), one_shot);
    }

    #[test]
    fn distinct_from_ieee_crc32() {
        // Sanity: the §11 fingerprint must be a different polynomial
        // than ZIP's (ieee 0xEDB88320) so a future refactor that
        // accidentally swaps them produces a loud test failure rather
        // than silent fingerprint drift.
        assert_ne!(
            castagnoli(b"123456789"),
            crate::zip::crc32::ieee(b"123456789"),
        );
    }
}
