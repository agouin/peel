//! CRC-64/XZ (ECMA-182, reflected) — the variant the .xz Block
//! Check uses when `Check ID = 0x04`.
//!
//! Phase 5 of `docs/PLAN_xz_block_decoder.md` calls for "a new
//! small module mirroring the SHA-256 module's style." This
//! module's API shape — `Crc64::new` / `update` / `finalize` —
//! matches [`super::crc32::Crc32`] and [`super::sha256::Sha256`]
//! so the .xz Block-Check verifier can drive whichever variant
//! the Stream Flags name.
//!
//! # Polynomial and parameters
//!
//! - Polynomial (reflected): `0xC96C_5795_D787_0F42`. This is
//!   the reverse of the ECMA-182 generator `0x42F0_E1EB_A9EA_3693`
//!   and is what `xz` / `liblzma` and the canonical "CRC-64/XZ"
//!   alias publish.
//! - Initial / final XOR: `!0u64`. (Same convention as the
//!   reflected CRC-32 above and `liblzma`.)
//! - Reflected input / reflected output: yes.
//!
//! Hand-rolled per `docs/ENGINEERING_STANDARDS.md` §2.1; the
//! lookup table is `const`-folded at compile time. Throughput
//! targets are well below the network bottleneck, so a byte-at-a-
//! time inner loop is plenty.

/// 256-entry lookup table for the byte-at-a-time CRC-64/XZ inner
/// loop. `const` so the table is folded at compile time.
const TABLE: [u64; 256] = build_table();

const fn build_table() -> [u64; 256] {
    const POLY: u64 = 0xC96C_5795_D787_0F42;
    let mut table = [0u64; 256];
    let mut i = 0u64;
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

/// Streaming CRC-64/XZ hasher.
///
/// Construct with [`Self::new`], feed bytes via [`Self::update`],
/// extract the final CRC with [`Self::finalize`]. Mirrors the
/// shape of [`super::crc32::Crc32`] and the SHA-256 hasher.
#[derive(Debug, Clone, Copy)]
pub struct Crc64 {
    state: u64,
}

impl Default for Crc64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc64 {
    /// Fresh, empty hasher. Equivalent to [`Self::default`].
    #[must_use]
    pub const fn new() -> Self {
        Self { state: !0u64 }
    }

    /// Feed the next chunk of input into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        let mut state = self.state;
        for &b in data {
            state = TABLE[((state ^ u64::from(b)) & 0xFF) as usize] ^ (state >> 8);
        }
        self.state = state;
    }

    /// Final CRC-64/XZ over all bytes fed so far.
    #[must_use]
    pub fn finalize(self) -> u64 {
        !self.state
    }

    /// Snapshot the running CRC without consuming the hasher.
    #[must_use]
    pub fn current(&self) -> u64 {
        !self.state
    }

    /// Restore a hasher to a state that, if [`Self::finalize`]
    /// were called immediately, would produce `partial_crc`.
    /// Mirror of [`super::crc32::Crc32::seed`] for the Phase 6
    /// resume blob.
    pub fn seed(&mut self, partial_crc: u64) {
        self.state = !partial_crc;
    }
}

/// Convenience: full-buffer CRC-64/XZ in one call.
#[must_use]
pub fn xz(data: &[u8]) -> u64 {
    let mut c = Crc64::new();
    c.update(data);
    c.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CRC-64/XZ of the empty string is 0 (the initial `!0u64`
    /// state, finalized via final XOR with `!0u64`, produces 0).
    #[test]
    fn empty_input_is_zero() {
        assert_eq!(xz(b""), 0);
    }

    /// Canonical CRC-64/XZ "check" vector — `0x995DC9BBDF1939FA`
    /// for the ASCII string `"123456789"`. This is the
    /// `liblzma` / `crc64fast`-published reference value for the
    /// ECMA-182-reflected polynomial with `init = !0` and
    /// `xorout = !0`. Pin so any drift from the polynomial
    /// transcription surfaces directly.
    #[test]
    fn known_vector_check_string() {
        assert_eq!(xz(b"123456789"), 0x995D_C9BB_DF19_39FA);
    }

    /// Streaming `update` chunked at arbitrary boundaries
    /// produces the same CRC as a single one-shot call.
    #[test]
    fn streaming_matches_one_shot() {
        let payload: Vec<u8> = (0..=255u8).chain(0..=255u8).collect();
        let one_shot = xz(&payload);
        let mut c = Crc64::new();
        c.update(&payload[..1]);
        c.update(&payload[1..6]);
        c.update(&payload[6..]);
        assert_eq!(c.finalize(), one_shot);
    }

    /// `current()` previews without consuming.
    #[test]
    fn current_previews_without_consuming() {
        let mut c = Crc64::new();
        c.update(b"abc");
        let preview = c.current();
        assert_eq!(preview, xz(b"abc"));
        c.update(b"def");
        assert_eq!(c.finalize(), xz(b"abcdef"));
    }
}
