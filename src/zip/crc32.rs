//! CRC-32 (IEEE 802.3) — the variant the ZIP format records in every
//! local file header and central directory entry.
//!
//! Hand-rolled per `docs/ENGINEERING_STANDARDS.md` §2.1 ("a 50-line
//! hand-rolled implementation [is preferred over a crate]"). The
//! table is built once at startup; the inner loop is the canonical
//! byte-at-a-time algorithm. We do not need throughput beyond what
//! single-core ~500 MiB/s gives us — the network is the binding
//! constraint.
//!
//! The polynomial is the reflected form `0xEDB8_8320` and the
//! initial / final XOR is `!0u32`, matching what `zlib`'s `crc32`,
//! `gzip`, and ZIP all use.

/// 256-entry lookup table for the byte-at-a-time CRC-32 inner loop.
///
/// `const` so the constant is folded at compile time and we don't
/// pay a one-time initialization cost on the hot path.
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
/// extract the final CRC with [`Self::finalize`]. The state can also
/// be primed mid-stream via [`Self::seed`] so the ZIP pipeline can
/// resume an entry that was partially extracted before a crash —
/// it re-reads the already-written bytes off disk and replays them
/// here rather than serializing the running CRC into the checkpoint.
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

    /// Replace the running state with one that, if [`Self::finalize`]
    /// were called immediately, would produce `partial_crc`. Used by
    /// resume after re-reading the already-extracted prefix.
    pub fn seed(&mut self, partial_crc: u32) {
        self.state = !partial_crc;
    }

    /// Return the final CRC-32 value over all bytes fed so far.
    #[must_use]
    pub fn finalize(self) -> u32 {
        !self.state
    }

    /// Snapshot the running CRC without consuming the hasher. Mostly
    /// useful for diagnostics and tests.
    #[must_use]
    pub fn current(&self) -> u32 {
        !self.state
    }
}

/// Convenience: full-buffer CRC-32 in one call.
///
/// Equivalent to constructing a [`Crc32`], feeding `data` through
/// [`Crc32::update`], and returning [`Crc32::finalize`]. Used by
/// tests and by callers that already have the full byte string.
#[must_use]
pub fn ieee(data: &[u8]) -> u32 {
    let mut c = Crc32::new();
    c.update(data);
    c.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_is_zero() {
        // CRC-32 of the empty string is 0 by definition (the
        // initial !0u32 state, finalized via final XOR with !0u32,
        // produces 0).
        assert_eq!(ieee(b""), 0);
    }

    #[test]
    fn known_vector_a_through_z() {
        // Reference vector: CRC-32 of "abcdefghijklmnopqrstuvwxyz"
        // is 0x4C2750BD per the ZIP/zlib reference implementations.
        assert_eq!(ieee(b"abcdefghijklmnopqrstuvwxyz"), 0x4C2750BD);
    }

    #[test]
    fn known_vector_numeric_run() {
        // Reference vector: CRC-32 of "123456789" is 0xCBF43926
        // (the canonical "check" vector).
        assert_eq!(ieee(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let payload: Vec<u8> = (0..=255u8).chain(0..=255u8).collect();
        let one_shot = ieee(&payload);

        // Feed one byte at a time, then five bytes at a time, then
        // the rest in one chunk — chunking must not change the
        // result.
        let mut c = Crc32::new();
        c.update(&payload[..1]);
        c.update(&payload[1..6]);
        c.update(&payload[6..]);
        assert_eq!(c.finalize(), one_shot);
    }

    #[test]
    fn seed_replays_a_prefix() {
        // Producing the CRC of "abcdef" by computing the prefix CRC
        // separately, seeding a fresh hasher with it, and continuing
        // through "def" yields the same result as a single pass.
        let full = ieee(b"abcdef");
        let prefix = ieee(b"abc");
        let mut resumed = Crc32::new();
        resumed.seed(prefix);
        resumed.update(b"def");
        assert_eq!(resumed.finalize(), full);
    }

    #[test]
    fn current_returns_partial_crc_without_consuming_hasher() {
        let mut c = Crc32::new();
        c.update(b"abc");
        let snap = c.current();
        c.update(b"def");
        let final_value = c.finalize();
        assert_eq!(snap, ieee(b"abc"));
        assert_eq!(final_value, ieee(b"abcdef"));
    }
}
