//! CRC-32 (IEEE 802.3 / ISO-HDLC) — the variant the .xz Block
//! Check (`Check ID = 0x01`) and many other formats record.
//!
//! Phase 5 of `docs/PLAN_xz_block_decoder.md`. The plan steers
//! Block-Check verification at this module: streaming `update`
//! over decompressed Block bytes, `finalize` at Block end,
//! compare to the read trailer.
//!
//! Hand-rolled per `docs/ENGINEERING_STANDARDS.md` §2.1 ("a
//! 50-line hand-rolled implementation [is preferred over a
//! crate]"). The lookup table is built once at compile time as a
//! `const`; the inner loop is the canonical byte-at-a-time
//! algorithm.
//!
//! The polynomial is the reflected form `0xEDB8_8320` and the
//! initial / final XOR is `!0u32`, matching what `zlib`'s
//! `crc32`, `gzip`, ZIP, and the .xz Block-Check / Stream-Header
//! / Block-Header / Index CRCs all use.
//!
//! # Why a separate module from `crate::zip::crc32`
//!
//! The ZIP path has its own [`crate::zip::crc32::Crc32`] sized
//! and tested for that pipeline's specific resume contract.
//! Round one keeps the two implementations parallel rather than
//! hoisting a shared dependency, on the same "small static-data
//! duplication trumps cross-module coupling" rationale used for
//! [`super::crc32c`] vs the legacy CRC-32. A future cleanup may
//! consolidate them; until then, both modules are tiny enough
//! that the duplication is invisible against the rest of the
//! crate.

/// 256-entry lookup table for the byte-at-a-time CRC-32 inner
/// loop. `const` so the table is folded at compile time; no
/// one-time initialization cost on the hot path.
const TABLE: [u32; 256] = build_table();

const fn build_table() -> [u32; 256] {
    const POLY: u32 = 0xEDB8_8320;
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

/// Streaming CRC-32 hasher.
///
/// Construct with [`Self::new`], feed bytes via [`Self::update`],
/// extract the final CRC with [`Self::finalize`].
#[derive(Debug, Clone, Copy)]
pub struct Crc32 {
    state: u32,
}

impl Default for Crc32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32 {
    /// Fresh, empty hasher. Equivalent to [`Self::default`].
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

    /// Final CRC-32 over all bytes fed so far. Consumes the
    /// hasher; clone first if you need to keep updating.
    #[must_use]
    pub fn finalize(self) -> u32 {
        !self.state
    }

    /// Snapshot the running CRC without consuming the hasher.
    /// Diagnostic and test-only.
    #[must_use]
    pub fn current(&self) -> u32 {
        !self.state
    }
}

/// Convenience: full-buffer CRC-32 in one call.
#[must_use]
pub fn ieee(data: &[u8]) -> u32 {
    let mut c = Crc32::new();
    c.update(data);
    c.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CRC-32 of the empty string is 0 by definition (the
    /// initial `!0u32` state, finalized via final XOR with
    /// `!0u32`, produces 0).
    #[test]
    fn empty_input_is_zero() {
        assert_eq!(ieee(b""), 0);
    }

    /// Canonical CRC-32 "check" vector — `0xCBF43926` for the
    /// ASCII string `"123456789"`.
    #[test]
    fn known_vector_check_string() {
        assert_eq!(ieee(b"123456789"), 0xCBF4_3926);
    }

    /// Reference vector: CRC-32 of `"a"` is `0xE8B7BE43`.
    #[test]
    fn known_vector_single_a() {
        assert_eq!(ieee(b"a"), 0xE8B7_BE43);
    }

    /// Streaming `update` chunked at arbitrary boundaries
    /// produces the same CRC as a single one-shot call.
    #[test]
    fn streaming_matches_one_shot() {
        let payload: Vec<u8> = (0..=255u8).chain(0..=255u8).collect();
        let one_shot = ieee(&payload);
        let mut c = Crc32::new();
        c.update(&payload[..1]);
        c.update(&payload[1..6]);
        c.update(&payload[6..]);
        assert_eq!(c.finalize(), one_shot);
    }

    /// `current()` previews the CRC without consuming the hasher;
    /// continuing to update afterwards continues to be valid.
    #[test]
    fn current_previews_without_consuming() {
        let mut c = Crc32::new();
        c.update(b"abc");
        let preview = c.current();
        assert_eq!(preview, ieee(b"abc"));
        c.update(b"def");
        assert_eq!(c.finalize(), ieee(b"abcdef"));
    }

    /// Cross-check against the parallel ZIP-side implementation
    /// on a few real-world-ish inputs. If either drifts (or we
    /// later consolidate), this guard surfaces directly.
    #[test]
    fn agrees_with_zip_crc32_on_corpus() {
        let inputs: &[&[u8]] = &[
            b"",
            b"a",
            b"abc",
            b"123456789",
            b"the quick brown fox jumps over the lazy dog",
        ];
        for input in inputs {
            assert_eq!(ieee(input), crate::zip::crc32::ieee(input));
        }
    }
}
