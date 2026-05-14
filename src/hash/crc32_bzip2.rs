//! CRC-32, bzip2 dialect — IEEE 802.3 polynomial in **non-reflected**
//! form, processed MSB-first within each byte, with the standard
//! `init = 0xFFFF_FFFF` / `final XOR = 0xFFFF_FFFF` framing.
//!
//! `internal/PLAN_bz2_support.md` Phase 5. The bzip2 reference
//! (`bzlib_private.h`, `BZ_UPDATE_CRC`) processes input bytes as
//! follows:
//!
//! ```text
//! crc = (crc << 8) ^ BZ2_crc32Table[((crc >> 24) ^ byte) & 0xFF];
//! ```
//!
//! and finalizes with `~crc`. The polynomial is `0x04C11DB7`
//! (non-reflected) — the same numerical polynomial as the gzip /
//! zlib / .xz Block-Check / Castagnoli-non variant, but with the
//! input bit ordering MSB-first instead of LSB-first.
//!
//! # Why a separate module from [`super::crc32`]
//!
//! [`super::crc32`] is the **reflected** form used by gzip / zlib
//! / xz Block-Check (`0xEDB8_8320` polynomial, LSB-first input).
//! The two tables are **not** binary-compatible: feeding the same
//! bytes into both produces different digests. Keeping the modules
//! parallel preserves the call-site clarity ("this is gzip CRC" /
//! "this is bzip2 CRC") and matches the rationale that already
//! splits `crc32` / `crc32c` in this crate.

/// 256-entry lookup table for the byte-at-a-time bzip2 CRC inner
/// loop. `const` so the table is folded at compile time; no
/// one-time initialization cost on the hot path.
const TABLE: [u32; 256] = build_table();

const fn build_table() -> [u32; 256] {
    // Non-reflected polynomial. Each byte slot stores the CRC of
    // the 8-bit value (interpreted MSB-first) under polynomial
    // 0x04C11DB7.
    const POLY: u32 = 0x04C1_1DB7;
    let mut table = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        // Shift the byte into the top of a 32-bit accumulator and
        // run 8 bit-rotations.
        let mut c = i << 24;
        let mut j = 0;
        while j < 8 {
            if c & 0x8000_0000 != 0 {
                c = (c << 1) ^ POLY;
            } else {
                c <<= 1;
            }
            j += 1;
        }
        table[i as usize] = c;
        i += 1;
    }
    table
}

/// Streaming bzip2 CRC-32 hasher.
///
/// Construct with [`Self::new`], feed bytes via [`Self::update`],
/// extract the final CRC with [`Self::finalize`].
#[derive(Debug, Clone, Copy)]
pub struct Crc32Bzip2 {
    state: u32,
}

impl Default for Crc32Bzip2 {
    fn default() -> Self {
        Self::new()
    }
}

impl Crc32Bzip2 {
    /// Fresh hasher pre-seeded with `0xFFFF_FFFF` per the bzip2
    /// reference's `BZ_INITIALISE_CRC` macro.
    #[must_use]
    pub const fn new() -> Self {
        Self { state: 0xFFFF_FFFF }
    }

    /// Feed the next chunk of input into the hasher. Each byte is
    /// processed MSB-first via the precomputed table.
    pub fn update(&mut self, data: &[u8]) {
        let mut state = self.state;
        for &b in data {
            // INVARIANT: `(state >> 24) ^ b` is in 0..=255, fits as
            // a `usize` index into the 256-entry table.
            let idx = ((state >> 24) ^ u32::from(b)) & 0xFF;
            state = (state << 8) ^ TABLE[idx as usize];
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

/// Combine a per-block CRC into a running stream-CRC accumulator
/// the way `libbz2` does: a 1-bit left-rotate of the accumulator
/// followed by XOR with the new block CRC.
///
/// `stream_crc` here is the **already-finalized** running stream
/// value (the value the trailing 32-bit field encodes). Bzip2
/// computes this directly on the post-finalize CRC values rather
/// than on the raw `state` words.
#[must_use]
pub fn combine_stream(stream_crc: u32, block_crc: u32) -> u32 {
    stream_crc.rotate_left(1) ^ block_crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_finalizes_to_zero() {
        // CRC32 of empty input = !0xFFFFFFFF = 0.
        let h = Crc32Bzip2::new();
        assert_eq!(h.finalize(), 0);
    }

    #[test]
    fn hello_newline_matches_bzip2_reference_block_crc() {
        // From a `bzip2 -c` of "hello\n" the block CRC bytes are
        // 0xC1 0xC0 0x80 0xE2 → big-endian u32 = 0xC1C080E2. This
        // is the canonical bzip2-dialect CRC of "hello\n".
        let mut h = Crc32Bzip2::new();
        h.update(b"hello\n");
        assert_eq!(h.finalize(), 0xC1C0_80E2);
    }

    #[test]
    fn update_in_chunks_matches_one_shot() {
        let data: Vec<u8> = (0..255).collect();
        let mut one_shot = Crc32Bzip2::new();
        one_shot.update(&data);
        let one_shot = one_shot.finalize();

        let mut chunked = Crc32Bzip2::new();
        chunked.update(&data[..50]);
        chunked.update(&data[50..200]);
        chunked.update(&data[200..]);
        assert_eq!(chunked.finalize(), one_shot);
    }

    #[test]
    fn combine_stream_uses_rotate_and_xor() {
        // Two simple block CRCs, combined via the bzip2 rule:
        //   stream = ((stream << 1) | (stream >> 31)) ^ block
        // Starting from 0, after one block: rotate(0,1)=0, ^block=block.
        // After second block: rotate(block,1) ^ block2.
        let a = 0xC1C0_80E2u32; // hello\n
        let b = 0xDEAD_BEEFu32;
        let c0 = combine_stream(0, a);
        let c1 = combine_stream(c0, b);
        assert_eq!(c0, a);
        assert_eq!(c1, a.rotate_left(1) ^ b);
    }
}
