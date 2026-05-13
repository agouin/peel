//! MSB-first bitstream reader for legacy RAR (RAR3 / RAR4).
//!
//! Sibling of [`crate::decode::rar_native::bits`]: both formats
//! pack bits MSB-first within each byte (the high bit of byte 0
//! is the first bit on the wire), and both back the reader with
//! a 64-bit accumulator over an in-memory byte slice. The reuse-
//! vs-fork decision (`internal/PLAN_rar3.md` §C0) is "fork" — the two
//! readers do not share an implementation, so each can evolve
//! against its own format without dragging the other along.
//!
//! # Where legacy RAR uses the bit reader
//!
//! The LZ path (`unp_ver ∈ [29, 36]`, `method ∈ 0x31..=0x33`)
//! consumes the entry's compressed bytes as a continuous
//! bitstream. The PPMd-II path (`method ∈ 0x34..=0x35`) reads
//! bytes through the [`crate::decode::ppmd2::range_dec::RangeDecoder`]
//! and never touches this module.
//!
//! Inside the LZ path, the bitstream is *not* segmented into
//! byte-aligned blocks. Block boundaries are encoded as a 1-bit
//! `is_ppmd_block` flag at the start of each block, but reaching
//! that flag requires first calling [`BitReader::align_to_byte`]
//! — libarchive's `archive_read_support_format_rar.c` does this
//! at the start of every block via the `rar_br_consume_unaligned_bits`
//! macro (lines 2314..2317 of the reference). The flag itself is
//! the first bit *after* the alignment.
//!
//! # Cursor accounting
//!
//! [`BitReader`] tracks the bit cursor via `bits_consumed`. The
//! [`BitReader::byte_position`] accessor returns
//! `(byte_index, bit_within_byte)` for diagnostic / resume use;
//! §F1's checkpoint blob (when it lands) reconstructs the reader
//! by constructing a fresh one over the bytes starting at
//! `byte_index` and consuming `bit_within_byte` bits.
//!
//! # Read width
//!
//! [`BitReader::read_bits`] / [`BitReader::peek_bits`] /
//! [`BitReader::consume_bits`] each accept up to
//! [`MAX_BITS_PER_READ`] bits per call (32). The legacy RAR
//! algorithm reads ≤ 15 bits at a time for Huffman codes and
//! ≤ 18 bits for the largest distance extra-bits field; 32 is a
//! conservative type-derived ceiling rather than a tight format
//! bound.

use thiserror::Error;

/// Maximum number of bits a single [`BitReader::read_bits`] /
/// [`BitReader::peek_bits`] / [`BitReader::consume_bits`] call may
/// pull at once. The hard ceiling is 32 because the result type is
/// `u32`; the practical ceiling in legacy RAR is far tighter
/// (≤ 15 for Huffman codes, ≤ 18 for the longest distance
/// extra-bits field).
pub const MAX_BITS_PER_READ: u32 = 32;

/// Errors produced by [`BitReader`].
#[derive(Debug, Error)]
pub enum BitReadError {
    /// The bitstream ran out of input before the requested number
    /// of bits could be assembled. Carries the cursor at the
    /// moment the underrun was observed so the upper layer can
    /// include it in the [`crate::rar::RarError::Truncated`] /
    /// `Malformed` message it surfaces.
    #[error(
        "legacy RAR bitstream ran out of input: needed {needed} more bits at \
         byte {byte_index}, bit {bit_off}"
    )]
    Underrun {
        /// Bits the caller still wanted after the accumulator
        /// drained — `n - nbits` at the moment the underrun fired.
        needed: u32,
        /// Byte the cursor was at when the underrun fired.
        byte_index: u64,
        /// Bit-within-byte the cursor was at when the underrun
        /// fired.
        bit_off: u8,
    },
}

/// MSB-first bit reader over a borrowed byte slice.
///
/// Holds a 64-bit accumulator with the next-to-read bit at bit
/// position 63 (the most-significant bit of `acc`). `nbits` is
/// the number of valid bits at the top of `acc`; the low
/// `64 - nbits` bits are zero-padded junk the caller never sees.
///
/// The reader advances forward only. Construct a fresh one for
/// each entry; do not try to rewind it.
pub struct BitReader<'a> {
    /// Borrowed compressed data. Bytes are pulled from `data`
    /// starting at index `next_byte` to refill `acc`.
    data: &'a [u8],
    /// Index of the next byte in `data` to shift into `acc`.
    next_byte: usize,
    /// 64-bit accumulator. Bits `[64 - nbits, 64)` are valid;
    /// the next-to-read bit sits at position 63.
    acc: u64,
    /// Count of valid bits at the top of `acc`. Range `0..=64`.
    nbits: u32,
    /// Total bits consumed since construction. Drives
    /// [`Self::byte_position`] and the §F1 resume snapshot.
    bits_consumed: u64,
}

impl<'a> BitReader<'a> {
    /// Construct a fresh reader over `data`. The accumulator
    /// starts empty — the first [`Self::read_bits`] / [`Self::peek_bits`]
    /// call is what pulls the first byte.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            next_byte: 0,
            acc: 0,
            nbits: 0,
            bits_consumed: 0,
        }
    }

    /// Total bits the reader has consumed since construction.
    #[must_use]
    pub fn bits_consumed(&self) -> u64 {
        self.bits_consumed
    }

    /// Total bits remaining in the bitstream (buffered + still in
    /// the underlying byte slice). Lets the upper layer pre-flight
    /// reads that need to fail closed at end-of-stream rather
    /// than surface an underrun mid-symbol.
    #[must_use]
    pub fn bits_remaining(&self) -> u64 {
        let buffered = u64::from(self.nbits);
        let unread_bytes = (self.data.len() - self.next_byte) as u64;
        buffered.saturating_add(unread_bytes.saturating_mul(8))
    }

    /// Cursor position as `(byte_index, bit_within_byte)`, with
    /// `byte_index * 8 + bit_within_byte == bits_consumed`.
    #[must_use]
    pub fn byte_position(&self) -> (u64, u8) {
        let byte_index = self.bits_consumed / 8;
        let bit_off = (self.bits_consumed % 8) as u8;
        (byte_index, bit_off)
    }

    /// `true` once every bit in the input has been consumed.
    /// Useful for asserting clean termination at end-of-entry.
    #[must_use]
    pub fn is_at_end(&self) -> bool {
        self.nbits == 0 && self.next_byte == self.data.len()
    }

    /// Refill the accumulator until it holds at least `n` bits or
    /// the input runs out. Idempotent if `nbits >= n`. Called
    /// internally by [`Self::read_bits`] / [`Self::peek_bits`];
    /// callers don't normally invoke it.
    fn ensure(&mut self, n: u32) {
        debug_assert!(n <= MAX_BITS_PER_READ);
        while self.nbits + 8 <= 64 && self.next_byte < self.data.len() {
            let byte = u64::from(self.data[self.next_byte]);
            // Place the new byte's 8 bits immediately below the
            // existing valid bits — i.e. at positions
            // [56 - nbits, 64 - nbits). Equivalent to
            // `acc |= byte << (56 - nbits)`.
            self.acc |= byte << (56 - self.nbits);
            self.next_byte += 1;
            self.nbits += 8;
            if self.nbits >= n {
                break;
            }
        }
    }

    /// Look at the next `n` bits without advancing the cursor.
    ///
    /// `n == 0` returns `0` and refills nothing. Otherwise the
    /// accumulator is refilled as needed.
    ///
    /// # Errors
    ///
    /// - [`BitReadError::Underrun`] if fewer than `n` bits remain
    ///   in the bitstream.
    ///
    /// # Panics
    ///
    /// Debug-asserts that `n <= MAX_BITS_PER_READ`.
    pub fn peek_bits(&mut self, n: u32) -> Result<u32, BitReadError> {
        if n == 0 {
            return Ok(0);
        }
        debug_assert!(
            n <= MAX_BITS_PER_READ,
            "peek_bits({n}) exceeds MAX_BITS_PER_READ ({MAX_BITS_PER_READ})"
        );
        self.ensure(n);
        if self.nbits < n {
            let (byte_index, bit_off) = self.byte_position();
            return Err(BitReadError::Underrun {
                needed: n - self.nbits,
                byte_index,
                bit_off,
            });
        }
        Ok((self.acc >> (64 - n)) as u32)
    }

    /// Discard the next `n` bits, advancing the cursor.
    ///
    /// `n == 0` is a no-op. Composing `consume_bits` with a prior
    /// [`Self::peek_bits`] is the canonical "decide based on a
    /// peek, then commit" pattern Huffman decoders need.
    ///
    /// # Errors
    ///
    /// - [`BitReadError::Underrun`] if fewer than `n` bits remain
    ///   in the bitstream.
    ///
    /// # Panics
    ///
    /// Debug-asserts that `n <= MAX_BITS_PER_READ`.
    pub fn consume_bits(&mut self, n: u32) -> Result<(), BitReadError> {
        if n == 0 {
            return Ok(());
        }
        debug_assert!(
            n <= MAX_BITS_PER_READ,
            "consume_bits({n}) exceeds MAX_BITS_PER_READ ({MAX_BITS_PER_READ})"
        );
        self.ensure(n);
        if self.nbits < n {
            let (byte_index, bit_off) = self.byte_position();
            return Err(BitReadError::Underrun {
                needed: n - self.nbits,
                byte_index,
                bit_off,
            });
        }
        // Drop the top n bits. `n == 64` is masked out specially
        // because `u64 << 64` is undefined behaviour in Rust as
        // well as in C, but `MAX_BITS_PER_READ` is 32 so the
        // branch is dead in practice — keep it as a defensive
        // guard in case the cap moves.
        if n == 64 {
            self.acc = 0;
        } else {
            self.acc <<= n;
        }
        self.nbits -= n;
        self.bits_consumed = self.bits_consumed.saturating_add(u64::from(n));
        Ok(())
    }

    /// Read the next `n` bits and advance the cursor in one step.
    ///
    /// Equivalent to `peek_bits(n)? + consume_bits(n)?` but
    /// folds the two ensures and the underrun check into one.
    ///
    /// # Errors
    ///
    /// - [`BitReadError::Underrun`] if fewer than `n` bits remain
    ///   in the bitstream.
    ///
    /// # Panics
    ///
    /// Debug-asserts that `n <= MAX_BITS_PER_READ`.
    pub fn read_bits(&mut self, n: u32) -> Result<u32, BitReadError> {
        if n == 0 {
            return Ok(0);
        }
        debug_assert!(
            n <= MAX_BITS_PER_READ,
            "read_bits({n}) exceeds MAX_BITS_PER_READ ({MAX_BITS_PER_READ})"
        );
        self.ensure(n);
        if self.nbits < n {
            let (byte_index, bit_off) = self.byte_position();
            return Err(BitReadError::Underrun {
                needed: n - self.nbits,
                byte_index,
                bit_off,
            });
        }
        let value = (self.acc >> (64 - n)) as u32;
        self.acc <<= n;
        self.nbits -= n;
        self.bits_consumed = self.bits_consumed.saturating_add(u64::from(n));
        Ok(value)
    }

    /// Skip forward to the next byte boundary. No-op if the
    /// cursor is already byte-aligned.
    ///
    /// Mirrors libarchive's `rar_br_consume_unaligned_bits` macro.
    /// Legacy RAR calls this at the start of every block before
    /// reading the `is_ppmd_block` flag — the first bit of each
    /// block sits on a byte boundary, even if the previous block
    /// ended on a fractional one.
    pub fn align_to_byte(&mut self) {
        let off = (self.bits_consumed % 8) as u32;
        if off == 0 {
            return;
        }
        let to_drop = 8 - off;
        // The bits we're dropping have already been pulled into
        // `acc` (they're the trailing bits of a byte we already
        // shifted in), so this never underruns.
        debug_assert!(self.nbits >= to_drop);
        self.acc <<= to_drop;
        self.nbits -= to_drop;
        self.bits_consumed = self.bits_consumed.saturating_add(u64::from(to_drop));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a sequence of `(value, width)` pairs as an MSB-first
    /// byte stream. Last byte's low bits are zero-padded. Used by
    /// the round-trip and end-of-stream tests to materialise
    /// known-good fixtures without depending on a real archive.
    fn encode_msb(pairs: &[(u32, u32)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut acc: u64 = 0;
        let mut nbits: u32 = 0;
        for &(value, n) in pairs {
            assert!(n <= 32);
            let v = if n == 32 {
                value
            } else {
                value & ((1u32 << n) - 1)
            };
            let shift = 64 - nbits - n;
            acc |= u64::from(v) << shift;
            nbits += n;
            while nbits >= 8 {
                out.push((acc >> 56) as u8);
                acc <<= 8;
                nbits -= 8;
            }
        }
        if nbits > 0 {
            out.push((acc >> 56) as u8);
        }
        out
    }

    #[test]
    fn read_zero_bits_does_not_touch_the_stream() {
        let data = [0xABu8];
        let mut br = BitReader::new(&data);
        assert_eq!(br.read_bits(0).unwrap(), 0);
        assert_eq!(br.bits_consumed(), 0);
        assert_eq!(br.byte_position(), (0, 0));
    }

    #[test]
    fn first_bit_is_high_bit_of_first_byte() {
        // 0xCA = 0b11001010. MSB-first 4+4 = 0xC, 0xA.
        let data = [0xCAu8];
        let mut br = BitReader::new(&data);
        assert_eq!(br.read_bits(4).unwrap(), 0xC);
        assert_eq!(br.read_bits(4).unwrap(), 0xA);
        assert!(br.is_at_end());
    }

    #[test]
    fn reads_span_byte_boundaries() {
        // 0xAB 0xCD = 0b1010_1011 0b1100_1101.
        // 3 → 0b101 = 5, 5 → 0b01011 = 11, 4 → 0xC, 4 → 0xD.
        let data = [0xABu8, 0xCD];
        let mut br = BitReader::new(&data);
        assert_eq!(br.read_bits(3).unwrap(), 0b101);
        assert_eq!(br.read_bits(5).unwrap(), 0b01011);
        assert_eq!(br.read_bits(4).unwrap(), 0xC);
        assert_eq!(br.read_bits(4).unwrap(), 0xD);
        assert!(br.is_at_end());
    }

    #[test]
    fn reads_a_full_32_bit_word_in_one_call() {
        let data = [0xDEu8, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let mut br = BitReader::new(&data);
        assert_eq!(br.read_bits(32).unwrap(), 0xDEAD_BEEF);
        assert_eq!(br.read_bits(16).unwrap(), 0xCAFE);
        assert!(br.is_at_end());
    }

    #[test]
    fn peek_does_not_advance_the_cursor() {
        let data = [0xABu8, 0xCD];
        let mut br = BitReader::new(&data);
        assert_eq!(br.peek_bits(8).unwrap(), 0xAB);
        assert_eq!(br.peek_bits(12).unwrap(), 0xABC);
        assert_eq!(br.bits_consumed(), 0);
        assert_eq!(br.read_bits(8).unwrap(), 0xAB);
        assert_eq!(br.bits_consumed(), 8);
    }

    #[test]
    fn consume_advances_without_yielding_a_value() {
        let data = [0xABu8, 0xCD];
        let mut br = BitReader::new(&data);
        br.consume_bits(4).unwrap();
        assert_eq!(br.read_bits(4).unwrap(), 0xB);
        assert_eq!(br.bits_consumed(), 8);
    }

    #[test]
    fn underrun_reports_remaining_demand_and_cursor() {
        let data = [0xFFu8];
        let mut br = BitReader::new(&data);
        let err = br.read_bits(16).unwrap_err();
        let BitReadError::Underrun {
            needed,
            byte_index,
            bit_off,
        } = err;
        assert_eq!(needed, 8);
        assert_eq!(byte_index, 0);
        assert_eq!(bit_off, 0);
    }

    #[test]
    fn underrun_after_partial_consumption_reports_partial_cursor() {
        let data = [0xABu8, 0xCD];
        let mut br = BitReader::new(&data);
        br.read_bits(12).unwrap();
        let err = br.read_bits(8).unwrap_err();
        let BitReadError::Underrun {
            needed,
            byte_index,
            bit_off,
        } = err;
        assert_eq!(needed, 4);
        assert_eq!(byte_index, 1);
        assert_eq!(bit_off, 4);
    }

    #[test]
    fn align_to_byte_is_idempotent_when_aligned() {
        let data = [0xABu8, 0xCD];
        let mut br = BitReader::new(&data);
        br.read_bits(8).unwrap();
        br.align_to_byte();
        assert_eq!(br.bits_consumed(), 8);
        assert_eq!(br.read_bits(8).unwrap(), 0xCD);
    }

    #[test]
    fn align_to_byte_drops_the_partial_byte() {
        // Read 3 bits, align: the next 5 bits of byte 0 are dropped
        // and the cursor jumps to byte 1.
        let data = [0xABu8, 0xCD];
        let mut br = BitReader::new(&data);
        br.read_bits(3).unwrap();
        br.align_to_byte();
        assert_eq!(br.bits_consumed(), 8);
        assert_eq!(br.read_bits(8).unwrap(), 0xCD);
    }

    /// Mirrors libarchive's block-start sequence: align to byte,
    /// then read the 1-bit `is_ppmd_block` flag. After a fractional
    /// previous block, the flag still has to land on the byte
    /// boundary's high bit. This is the load-bearing reason
    /// [`BitReader::align_to_byte`] exists in this module.
    #[test]
    fn block_start_alignment_then_is_ppmd_flag() {
        // First byte: read 5 bits of "previous block tail", then
        // align. The flag bit is the top bit of byte 1. We stage
        // it as `1` and verify it round-trips.
        let data = [0b1101_1010u8, 0b1000_0000];
        let mut br = BitReader::new(&data);
        br.read_bits(5).unwrap();
        br.align_to_byte();
        assert_eq!(br.byte_position(), (1, 0));
        assert_eq!(br.read_bits(1).unwrap(), 1);
    }

    #[test]
    fn round_trip_random_bit_groups() {
        // 60 widths sweep 1..=31. Encode via the test helper,
        // decode via the production reader, assert each value
        // returns exactly.
        let pairs: Vec<(u32, u32)> = (0..60u32)
            .map(|i| {
                let n = ((i * 9 + 1) % 31) + 1;
                let v = i.wrapping_mul(2_654_435_761) & ((1u32 << n) - 1);
                (v, n)
            })
            .collect();
        let bytes = encode_msb(&pairs);
        let mut br = BitReader::new(&bytes);
        let mut total = 0u64;
        for &(value, n) in &pairs {
            let got = br.read_bits(n).unwrap();
            assert_eq!(got, value, "diverged after {total} bits");
            total += u64::from(n);
        }
        assert_eq!(br.bits_consumed(), total);
    }

    #[test]
    fn byte_position_tracks_a_partial_byte() {
        let data = [0xFFu8; 4];
        let mut br = BitReader::new(&data);
        br.read_bits(11).unwrap();
        assert_eq!(br.byte_position(), (1, 3));
        br.read_bits(5).unwrap();
        assert_eq!(br.byte_position(), (2, 0));
    }

    #[test]
    fn bits_remaining_includes_buffered_and_unread() {
        let data = [0xFFu8; 3];
        let mut br = BitReader::new(&data);
        assert_eq!(br.bits_remaining(), 24);
        br.read_bits(11).unwrap();
        assert_eq!(br.bits_remaining(), 13);
        br.read_bits(13).unwrap();
        assert_eq!(br.bits_remaining(), 0);
        assert!(br.is_at_end());
    }

    #[test]
    fn empty_input_underruns_on_any_nonzero_read() {
        let mut br = BitReader::new(&[]);
        assert!(br.is_at_end());
        assert!(matches!(
            br.read_bits(1),
            Err(BitReadError::Underrun { .. })
        ));
        assert_eq!(br.read_bits(0).unwrap(), 0);
    }

    #[test]
    fn drains_a_three_byte_buffer_through_irregular_reads() {
        let data = [0x12u8, 0x34, 0x56];
        let mut br = BitReader::new(&data);
        for &n in &[1u32, 7, 4, 4, 6, 2] {
            br.read_bits(n).unwrap();
        }
        assert!(br.is_at_end());
        assert_eq!(br.bits_consumed(), 24);
    }

    /// Legacy RAR's longest single field is the ~18-bit distance
    /// extra-bits run; a 16-bit Huffman lookahead is the second-
    /// longest. Exercise both widths at byte-boundary-crossing
    /// offsets to catch a refill-loop off-by-one.
    #[test]
    fn legacy_realistic_widths_cross_byte_boundaries() {
        // Encode: 3-bit prefix, 15-bit Huffman code, 18-bit
        // distance, 1-bit sentinel.
        let pairs = [
            (0b101, 3),
            (0b011_0110_0001_1001, 15),
            (0x2A_3F1, 18),
            (1, 1),
        ];
        let bytes = encode_msb(&pairs);
        let mut br = BitReader::new(&bytes);
        assert_eq!(br.read_bits(3).unwrap(), 0b101);
        assert_eq!(br.read_bits(15).unwrap(), 0b011_0110_0001_1001);
        assert_eq!(br.read_bits(18).unwrap(), 0x2A_3F1);
        assert_eq!(br.read_bits(1).unwrap(), 1);
    }
}
