//! MSB-first bitstream reader over an in-memory byte slice.
//!
//! RAR5's compressed-data stream packs bits **MSB-first** within
//! each byte: the high bit of byte 0 is the first bit on the wire,
//! the low bit of byte 0 is the eighth bit, the high bit of byte 1
//! is the ninth bit, and so on. This is the opposite of DEFLATE's
//! LSB-first packing (see [`crate::decode::deflate_native::bitstream`])
//! and matches the convention RAR5's reference decoder uses.
//!
//! Round-one of `docs/PLAN_rar5_decoder.md` (§A1) ships an
//! in-memory reader: the §3 RAR pipeline materialises an entry's
//! data area in a buffer before invoking the decoder, so we don't
//! need the streaming-source plumbing the DEFLATE / xz / zstd
//! readers carry. If §G later swaps in chunked feeding for
//! memory-bound entries, the streaming variant lands as a sibling
//! type rather than a refit.
//!
//! # Cursor accounting
//!
//! [`BitReader`] tracks the bit cursor (`bits_consumed`) and
//! exposes [`BitReader::byte_position`] returning
//! `(byte_index, bit_off)` where `byte_index` is the byte the
//! cursor is currently sitting in (or just before, when
//! `bit_off == 0`). The §F1 resume snapshot records both fields
//! so a kill mid-bit produces byte-identical output on resume.
//!
//! # Read width
//!
//! [`BitReader::read_bits`] / [`BitReader::peek_bits`] /
//! [`BitReader::consume_bits`] each accept up to
//! [`MAX_BITS_PER_READ`] bits per call (32). The RAR5 algorithm
//! never reads more than ~30 bits at once (largest single field is
//! a match-distance extra-bits run, capped at 30 by the format
//! spec); the cap is a static guard rather than a tight ceiling.

use thiserror::Error;

/// Maximum number of bits a single [`BitReader::read_bits`] /
/// [`BitReader::peek_bits`] / [`BitReader::consume_bits`] call may
/// pull at once. The hard ceiling is 32 because the result type is
/// `u32`; the practical ceiling in RAR5 is far tighter
/// (≤ 16 for Huffman codes, ≤ 30 for distance extra-bits).
pub const MAX_BITS_PER_READ: u32 = 32;

/// Errors produced by [`BitReader`].
#[derive(Debug, Error)]
pub enum BitReadError {
    /// The reader's source ran out of bytes before the requested
    /// number of bits could be assembled. Includes a snapshot of
    /// the cursor at the moment the underrun was observed so the
    /// upper layer can include it in the
    /// [`crate::rar::RarError::Truncated`] message it surfaces.
    #[error(
        "RAR5 bitstream ran out of input: needed {needed} more bits at \
         byte {byte_index}, bit {bit_off}"
    )]
    Underrun {
        /// Bits the caller wanted to read.
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
/// position 63 (the most significant bit of `acc`). `nbits` records
/// how many of the high bits in `acc` are valid data; the low
/// `64 - nbits` bits are zero-padded junk the caller never sees.
///
/// The reader advances forward only — once a bit has been
/// consumed, there's no way back. The §F1 resume path snapshots
/// `bits_consumed` (and the underlying byte slice's offset) and
/// reconstructs the reader by constructing a fresh one over the
/// bytes from that offset.
pub struct BitReader<'a> {
    /// Borrowed input data. Indexed by `next_byte` to refill the
    /// accumulator.
    data: &'a [u8],
    /// Index of the next byte in `data` to shift into `acc`.
    next_byte: usize,
    /// 64-bit bit accumulator. The top `nbits` bits hold valid
    /// data; the next-to-read bit is bit 63.
    acc: u64,
    /// Number of valid bits in `acc`. Range `0..=64`.
    nbits: u32,
    /// Total bits ever consumed from the bitstream. Diagnostic for
    /// error messages and the foundation for §F1's resume snapshot.
    bits_consumed: u64,
}

impl<'a> BitReader<'a> {
    /// Construct a fresh reader over `data`. Does not refill the
    /// accumulator — the first [`Self::read_bits`] / [`Self::ensure`]
    /// call is the first one to touch any bytes.
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

    /// Total bits remaining in the bitstream (data + buffered).
    /// Exposed so upper layers can pre-flight a read that needs
    /// to fail closed at end-of-stream rather than panic on the
    /// underrun.
    #[must_use]
    pub fn bits_remaining(&self) -> u64 {
        let buffered = u64::from(self.nbits);
        let data_bits = ((self.data.len() - self.next_byte) as u64).saturating_mul(8);
        buffered.saturating_add(data_bits)
    }

    /// Cursor position as a `(byte_index, bit_within_byte)` pair.
    /// `byte_index * 8 + bit_within_byte == bits_consumed`.
    #[must_use]
    pub fn byte_position(&self) -> (u64, u8) {
        let byte_index = self.bits_consumed / 8;
        let bit_off = (self.bits_consumed % 8) as u8;
        (byte_index, bit_off)
    }

    /// `true` once every bit in the input has been consumed.
    /// Useful for asserting clean termination at end-of-block.
    #[must_use]
    pub fn is_at_end(&self) -> bool {
        self.nbits == 0 && self.next_byte == self.data.len()
    }

    /// Refill the accumulator until it holds at least `n` bits, or
    /// the input runs out. Idempotent if `nbits >= n`. Used
    /// internally by [`Self::read_bits`] / [`Self::peek_bits`];
    /// callers don't normally invoke it.
    fn ensure(&mut self, n: u32) {
        debug_assert!(n <= MAX_BITS_PER_READ);
        while self.nbits + 8 <= 64 && self.next_byte < self.data.len() {
            // Place the next byte's MSB at bit position
            // (63 - nbits). After this insertion, `nbits` valid
            // bits are at positions [64 - nbits, 64) (high bits),
            // and the new byte's 8 bits sit at the next-lower
            // 8 positions [56 - nbits, 64 - nbits).
            //
            // Equivalently: `acc |= byte << (64 - nbits - 8)`.
            let byte = u64::from(self.data[self.next_byte]);
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
    /// `n == 0` returns `0`. Refills the accumulator as needed.
    ///
    /// # Errors
    ///
    /// - [`BitReadError::Underrun`] if fewer than `n` bits remain
    ///   in the bitstream.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `n > MAX_BITS_PER_READ`.
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
        // Top `n` bits of `acc` hold the value; shift right to
        // align them at bit 0. `n <= 32`, so the cast to `u32` is
        // lossless.
        Ok((self.acc >> (64 - n)) as u32)
    }

    /// Discard the next `n` bits, advancing the cursor.
    ///
    /// `n == 0` is a no-op. Refills the accumulator as needed
    /// (`consume_bits(n)` is logically `let _ = read_bits(n)?` but
    /// without composing the `u32` value).
    ///
    /// # Errors
    ///
    /// - [`BitReadError::Underrun`] if fewer than `n` bits remain
    ///   in the bitstream.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `n > MAX_BITS_PER_READ`.
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
        // Shift the consumed bits off the top.
        if n == 64 {
            self.acc = 0;
        } else {
            self.acc <<= n;
        }
        self.nbits -= n;
        self.bits_consumed = self.bits_consumed.saturating_add(u64::from(n));
        Ok(())
    }

    /// Read the next `n` bits and advance the cursor.
    ///
    /// Equivalent to `peek_bits(n)? + consume_bits(n)?` but cheaper
    /// (one ensure/branch path).
    ///
    /// # Errors
    ///
    /// - [`BitReadError::Underrun`] if fewer than `n` bits remain
    ///   in the bitstream.
    ///
    /// # Panics
    ///
    /// Panics in debug builds if `n > MAX_BITS_PER_READ`.
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

    /// Skip forward to the next byte boundary. No-op if the cursor
    /// is already byte-aligned. Used between RAR5 blocks where the
    /// next block header begins on a byte boundary even if the
    /// previous block ended fractionally.
    ///
    /// # Errors
    ///
    /// Cannot underrun — the alignment skip never asks for more
    /// bits than the accumulator already holds (or zero, when
    /// already aligned).
    pub fn align_to_byte(&mut self) {
        let drop_bits = self.bits_consumed % 8;
        if drop_bits == 0 {
            return;
        }
        let to_drop = 8 - drop_bits as u32;
        // The padding bits are part of the byte we already shifted
        // into `acc`, so this never underruns.
        debug_assert!(self.nbits >= to_drop);
        if to_drop == 64 {
            self.acc = 0;
        } else {
            self.acc <<= to_drop;
        }
        self.nbits -= to_drop;
        self.bits_consumed = self.bits_consumed.saturating_add(u64::from(to_drop));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: encode `(value, n)` pairs into an MSB-first byte
    /// stream. The last byte's low bits are zero-padded.
    fn encode_msb_bits(pairs: &[(u32, u32)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut acc: u64 = 0;
        let mut nbits: u32 = 0;
        for &(value, n) in pairs {
            assert!(n <= 32);
            // Mask the value so encoded bits stay within `n`.
            let v = if n == 32 {
                value
            } else {
                value & ((1u32 << n) - 1)
            };
            // Place the new bits at positions [64 - nbits - n, 64 - nbits).
            let shift = 64 - nbits - n;
            acc |= u64::from(v) << shift;
            nbits += n;
            while nbits >= 8 {
                let top = (acc >> 56) as u8;
                out.push(top);
                acc <<= 8;
                nbits -= 8;
            }
        }
        if nbits > 0 {
            let top = (acc >> 56) as u8;
            out.push(top);
        }
        out
    }

    #[test]
    fn read_bits_zero_is_a_noop() {
        let data = [0xABu8];
        let mut reader = BitReader::new(&data);
        assert_eq!(reader.read_bits(0).unwrap(), 0);
        assert_eq!(reader.bits_consumed(), 0);
        assert_eq!(reader.byte_position(), (0, 0));
    }

    #[test]
    fn read_bits_msb_first_within_byte() {
        // 0xCA = 0b11001010. MSB-first: 4 bits → 0b1100 = 0xC,
        // next 4 → 0b1010 = 0xA.
        let data = [0xCAu8];
        let mut reader = BitReader::new(&data);
        assert_eq!(reader.read_bits(4).unwrap(), 0xC);
        assert_eq!(reader.read_bits(4).unwrap(), 0xA);
        assert!(reader.is_at_end());
    }

    #[test]
    fn read_bits_spans_byte_boundary() {
        // Two bytes: 0xAB 0xCD = 0b10101011_11001101.
        // Read 3 bits → 0b101 = 5; 5 bits → 0b01011 = 11;
        // 4 bits → 0b1100 = 0xC; 4 bits → 0b1101 = 0xD.
        let data = [0xABu8, 0xCD];
        let mut reader = BitReader::new(&data);
        assert_eq!(reader.read_bits(3).unwrap(), 0b101);
        assert_eq!(reader.read_bits(5).unwrap(), 0b01011);
        assert_eq!(reader.read_bits(4).unwrap(), 0xC);
        assert_eq!(reader.read_bits(4).unwrap(), 0xD);
        assert!(reader.is_at_end());
    }

    #[test]
    fn read_bits_can_read_full_32_bits() {
        let data = [0xDEu8, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
        let mut reader = BitReader::new(&data);
        assert_eq!(reader.read_bits(32).unwrap(), 0xDEAD_BEEF);
        assert_eq!(reader.read_bits(16).unwrap(), 0xCAFE);
        assert!(reader.is_at_end());
    }

    #[test]
    fn peek_bits_does_not_advance_cursor() {
        let data = [0xABu8, 0xCD];
        let mut reader = BitReader::new(&data);
        assert_eq!(reader.peek_bits(8).unwrap(), 0xAB);
        assert_eq!(reader.peek_bits(12).unwrap(), 0xABC);
        assert_eq!(reader.bits_consumed(), 0);
        assert_eq!(reader.read_bits(8).unwrap(), 0xAB);
        assert_eq!(reader.bits_consumed(), 8);
    }

    #[test]
    fn consume_bits_advances_without_returning_value() {
        let data = [0xABu8, 0xCD];
        let mut reader = BitReader::new(&data);
        reader.consume_bits(4).unwrap();
        assert_eq!(reader.read_bits(4).unwrap(), 0xB);
        assert_eq!(reader.bits_consumed(), 8);
    }

    #[test]
    fn underrun_surfaces_specific_error_with_cursor() {
        let data = [0xFFu8];
        let mut reader = BitReader::new(&data);
        let err = reader.read_bits(16).unwrap_err();
        match err {
            BitReadError::Underrun {
                needed,
                byte_index,
                bit_off,
            } => {
                assert_eq!(needed, 8);
                assert_eq!(byte_index, 0);
                assert_eq!(bit_off, 0);
            }
        }
    }

    #[test]
    fn underrun_after_partial_consumption_reports_partial_cursor() {
        let data = [0xABu8, 0xCD];
        let mut reader = BitReader::new(&data);
        reader.read_bits(12).unwrap();
        let err = reader.read_bits(8).unwrap_err();
        match err {
            BitReadError::Underrun {
                needed,
                byte_index,
                bit_off,
            } => {
                assert_eq!(needed, 4);
                assert_eq!(byte_index, 1);
                assert_eq!(bit_off, 4);
            }
        }
    }

    #[test]
    fn align_to_byte_is_noop_when_already_aligned() {
        let data = [0xABu8, 0xCD];
        let mut reader = BitReader::new(&data);
        reader.read_bits(8).unwrap();
        reader.align_to_byte();
        assert_eq!(reader.bits_consumed(), 8);
        assert_eq!(reader.read_bits(8).unwrap(), 0xCD);
    }

    #[test]
    fn align_to_byte_skips_padding_bits() {
        // Read 3 bits, then realign: the next 5 bits of byte 0
        // are dropped and reading continues at byte 1.
        let data = [0xABu8, 0xCD];
        let mut reader = BitReader::new(&data);
        reader.read_bits(3).unwrap();
        reader.align_to_byte();
        assert_eq!(reader.bits_consumed(), 8);
        assert_eq!(reader.read_bits(8).unwrap(), 0xCD);
    }

    #[test]
    fn round_trips_random_bit_groups() {
        // 60 random groups summing to ~700 bits. Encode MSB-first
        // via the test helper, decode via the production reader,
        // assert exact recovery.
        let pairs: Vec<(u32, u32)> = (0..60u32)
            .map(|i| {
                let n = ((i * 9 + 1) % 31) + 1; // widths in 1..=31
                let v = i.wrapping_mul(2654435761) & ((1u32 << n) - 1);
                (v, n)
            })
            .collect();
        let bytes = encode_msb_bits(&pairs);
        let mut reader = BitReader::new(&bytes);
        let mut total_bits = 0u64;
        for &(value, n) in &pairs {
            let got = reader.read_bits(n).unwrap();
            assert_eq!(got, value, "after reading {total_bits} bits");
            total_bits += u64::from(n);
        }
        assert_eq!(reader.bits_consumed(), total_bits);
    }

    #[test]
    fn byte_position_tracks_partial_byte() {
        let data = [0xFFu8; 4];
        let mut reader = BitReader::new(&data);
        reader.read_bits(11).unwrap();
        assert_eq!(reader.byte_position(), (1, 3));
        reader.read_bits(5).unwrap();
        assert_eq!(reader.byte_position(), (2, 0));
    }

    #[test]
    fn bits_remaining_reflects_data_plus_accumulator() {
        let data = [0xFFu8; 3];
        let mut reader = BitReader::new(&data);
        assert_eq!(reader.bits_remaining(), 24);
        reader.read_bits(11).unwrap();
        assert_eq!(reader.bits_remaining(), 13);
        reader.read_bits(13).unwrap();
        assert_eq!(reader.bits_remaining(), 0);
        assert!(reader.is_at_end());
    }

    #[test]
    fn empty_input_underruns_immediately() {
        let mut reader = BitReader::new(&[]);
        assert!(reader.is_at_end());
        assert!(matches!(
            reader.read_bits(1),
            Err(BitReadError::Underrun { .. })
        ));
        // Zero-bit read on empty input is fine.
        assert_eq!(reader.read_bits(0).unwrap(), 0);
    }

    #[test]
    fn reads_all_bits_through_a_3_byte_buffer() {
        let data = [0x12u8, 0x34, 0x56];
        let mut reader = BitReader::new(&data);
        // Group sizes summing to 24 bits.
        for &n in &[1u32, 7, 4, 4, 6, 2] {
            reader.read_bits(n).unwrap();
        }
        assert!(reader.is_at_end());
        assert_eq!(reader.bits_consumed(), 24);
    }
}
