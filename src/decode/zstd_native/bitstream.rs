//! Forward and reverse bitstream readers for zstd's compressed
//! sections.
//!
//! Two bit-orderings show up inside a zstd block payload:
//!
//! - A **forward** bitstream is written low-bit-first within each
//!   byte and low-byte-first across bytes (RFC 8478 §4.1's FSE
//!   distribution-table description, and the Huffman weight
//!   description that follows). A 4-bit value `0b1011` written at
//!   the start of a byte appears as `0b00001011` on the wire.
//! - A **reverse** bitstream is the storage format zstd uses for
//!   the per-block FSE / Huffman bit-stream (RFC 8478 §4.1.4). The
//!   encoder writes it right-to-left: bits are emitted to the
//!   high end of the current byte, walking down toward the first
//!   byte. To make the stream length unambiguous despite the
//!   byte-aligned wire format, the encoder sets a single trailing
//!   `1` bit one position past the last data bit; decoders find
//!   that `1` (the highest set bit of the last byte), skip it, and
//!   then read MSB-first across bytes from high index to low.
//!
//! Both readers take a `&[u8]` and never allocate. They report
//! malformed inputs and over-reads as
//! [`ZstdError::MalformedFrameHeader`]-flavoured errors so the
//! decoder layer's existing error mapping carries them through to
//! the trait boundary unchanged.
//!
//! # Why u32 reads
//!
//! Every read site in RFC 8478 reads at most 32 bits in a single
//! call: the largest single field is a 32-bit `Offset_Extra_Bits`
//! pull during sequence decoding. Larger reads can be assembled
//! by the caller from multiple `read` calls. Keeping the API
//! `u32`-typed avoids paying for a 64-bit shift on every call.

use super::error::ZstdError;

/// Maximum number of bits one call to [`ForwardBitReader::read`]
/// or [`ReverseBitReader::read`] can pull. The hard limit is 32
/// because the result type is `u32`; the practical limit in the
/// RFC is even tighter (12 bits for FSE accuracy_log, 11 bits for
/// a single Huffman symbol, ≤ 32 for sequence offset extra-bits).
pub const MAX_BITS_PER_READ: u32 = 32;

/// LSB-first forward bitstream reader.
///
/// `read(n)` returns the next `n` bits from the stream, with the
/// least-significant bit being the bit *closest to the start of
/// the stream* (i.e. the lowest-order bit of the current byte at
/// the current bit offset). Reads that span byte boundaries
/// concatenate naturally — the higher-address bits go into the
/// higher-order positions of the returned `u32`.
#[derive(Debug, Clone)]
pub struct ForwardBitReader<'a> {
    bytes: &'a [u8],
    byte_pos: usize,
    /// Bit offset within `bytes[byte_pos]`; range 0..8. `0` means
    /// the next bit is the LSB of the current byte.
    bit_pos: u8,
}

impl<'a> ForwardBitReader<'a> {
    /// Construct a reader positioned at the first bit of `bytes`.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    /// Bits left in the stream (counts only the bits past the
    /// current cursor).
    #[must_use]
    pub fn bits_remaining(&self) -> usize {
        let total_bits = self.bytes.len().saturating_mul(8);
        let consumed = self.byte_pos.saturating_mul(8) + self.bit_pos as usize;
        total_bits.saturating_sub(consumed)
    }

    /// Index of the current byte (0-based) the reader is consuming
    /// bits from. After a [`Self::align_to_byte`] this points to
    /// the next byte that will yield a bit.
    #[must_use]
    pub fn byte_position(&self) -> usize {
        self.byte_pos
    }

    /// Bit offset within [`Self::byte_position`]'s current byte.
    /// 0 means the next read starts at the LSB.
    #[must_use]
    pub fn bit_position(&self) -> u8 {
        self.bit_pos
    }

    /// Round the cursor up to the next byte boundary.
    ///
    /// Used at the end of FSE-distribution parsing: the spec lets
    /// the bitstream end in the middle of a byte and the rest of
    /// the section starts on the next byte boundary. A no-op when
    /// already aligned.
    pub fn align_to_byte(&mut self) {
        if self.bit_pos != 0 {
            self.byte_pos += 1;
            self.bit_pos = 0;
        }
    }

    /// Read the next `n` bits, returning them as an LSB-aligned
    /// `u32`.
    ///
    /// `n == 0` returns `0` without advancing the cursor.
    ///
    /// # Errors
    ///
    /// - [`ZstdError::MalformedFrameHeader`] when `n >`
    ///   [`MAX_BITS_PER_READ`].
    /// - [`ZstdError::UnexpectedEof`] when fewer than `n` bits
    ///   remain in the stream.
    pub fn read(&mut self, n: u32) -> Result<u32, ZstdError> {
        if n == 0 {
            return Ok(0);
        }
        if n > MAX_BITS_PER_READ {
            return Err(ZstdError::MalformedFrameHeader(
                "forward bit read > 32 bits",
            ));
        }
        if self.bits_remaining() < n as usize {
            return Err(ZstdError::UnexpectedEof("forward bitstream"));
        }
        let mut out: u32 = 0;
        let mut produced: u32 = 0;
        while produced < n {
            let byte = u32::from(self.bytes[self.byte_pos]);
            let avail = 8 - u32::from(self.bit_pos);
            let want = (n - produced).min(avail);
            // Mask off `want` low bits from the shifted byte.
            let mask = if want == 32 {
                u32::MAX
            } else {
                (1u32 << want) - 1
            };
            let chunk = (byte >> u32::from(self.bit_pos)) & mask;
            out |= chunk << produced;
            produced += want;
            self.bit_pos += want as u8;
            if self.bit_pos == 8 {
                self.bit_pos = 0;
                self.byte_pos += 1;
            }
        }
        Ok(out)
    }
}

/// MSB-first reverse bitstream reader (RFC 8478 §4.1.4).
///
/// The wire layout walks bytes high-to-low. Within each byte, bits
/// are read MSB-first. The last byte starts with a single set
/// `1` (the "end-of-stream" sentinel) and any number of leading
/// `0` padding bits above it; the constructor strips both before
/// the first [`Self::read`] call.
#[derive(Debug, Clone)]
pub struct ReverseBitReader<'a> {
    bytes: &'a [u8],
    /// Total bits in `bytes` (always `bytes.len() * 8` — kept as a
    /// field so [`Self::bits_remaining`] is a pure subtraction
    /// without recomputing `len * 8`).
    total_bits: usize,
    /// Bits already consumed counted from the **high end** of the
    /// stream (sentinel + leading-zero padding + every later
    /// `read` call).
    consumed_bits: usize,
}

impl<'a> ReverseBitReader<'a> {
    /// Construct a reader, validating the trailing sentinel.
    ///
    /// # Errors
    ///
    /// - [`ZstdError::MalformedFrameHeader`] when `bytes` is empty
    ///   or the last byte is `0` (no sentinel — the encoder always
    ///   sets at least one bit).
    pub fn new(bytes: &'a [u8]) -> Result<Self, ZstdError> {
        if bytes.is_empty() {
            return Err(ZstdError::MalformedFrameHeader("reverse bitstream: empty"));
        }
        // SAFETY-OF-PARSING: bytes.last() is Some(...) because we
        // just rejected the empty case.
        let last = *bytes.last().expect("non-empty by check above");
        if last == 0 {
            return Err(ZstdError::MalformedFrameHeader(
                "reverse bitstream: missing trailing sentinel bit",
            ));
        }
        // The sentinel is the highest set bit of the last byte.
        // Above it lie 0..7 zero padding bits we discard along
        // with the sentinel itself.
        let leading_zero_pad = last.leading_zeros();
        let total_bits = bytes.len().saturating_mul(8);
        Ok(Self {
            bytes,
            total_bits,
            consumed_bits: leading_zero_pad as usize + 1,
        })
    }

    /// Bits of *payload* (post-sentinel) still available.
    #[must_use]
    pub fn bits_remaining(&self) -> usize {
        self.total_bits.saturating_sub(self.consumed_bits)
    }

    /// Read the next `n` bits MSB-first, returning them as an
    /// LSB-aligned `u32`.
    ///
    /// `n == 0` returns `0` without advancing the cursor.
    ///
    /// # Errors
    ///
    /// - [`ZstdError::MalformedFrameHeader`] when `n >`
    ///   [`MAX_BITS_PER_READ`].
    /// - [`ZstdError::UnexpectedEof`] when fewer than `n` bits
    ///   remain in the stream.
    pub fn read(&mut self, n: u32) -> Result<u32, ZstdError> {
        if n == 0 {
            return Ok(0);
        }
        if n > MAX_BITS_PER_READ {
            return Err(ZstdError::MalformedFrameHeader(
                "reverse bit read > 32 bits",
            ));
        }
        if self.bits_remaining() < n as usize {
            return Err(ZstdError::UnexpectedEof("reverse bitstream"));
        }
        let mut out: u32 = 0;
        for _ in 0..n {
            // Bit index 0 = MSB of last byte.
            // Bit index 7 = LSB of last byte.
            // Bit index 8 = MSB of second-to-last byte.
            // ...
            let bit_index = self.consumed_bits;
            let byte_from_end = bit_index / 8;
            let bit_in_byte_from_msb = (bit_index % 8) as u32;
            // INVARIANT: bits_remaining() check above guarantees
            // bit_index < total_bits, so byte_from_end < bytes.len()
            // and the subtraction is safe.
            let byte_idx = self.bytes.len() - 1 - byte_from_end;
            let bit = (self.bytes[byte_idx] >> (7 - bit_in_byte_from_msb)) & 1;
            out = (out << 1) | u32::from(bit);
            self.consumed_bits += 1;
        }
        Ok(out)
    }

    /// Peek the next `n` bits MSB-first without advancing the
    /// cursor.
    ///
    /// Used by the canonical-Huffman decoder, which peeks
    /// `max_num_bits` to index its decode table, then advances by
    /// the cell's actual `code_length` (which may be shorter).
    ///
    /// # Errors
    ///
    /// Same as [`Self::read`].
    pub fn peek(&mut self, n: u32) -> Result<u32, ZstdError> {
        let saved = self.consumed_bits;
        let result = self.read(n);
        self.consumed_bits = saved;
        result
    }

    /// Advance the cursor by `n` bits without producing a value.
    ///
    /// Convenience over `read(n).map(|_| ())`. The Huffman decoder
    /// pairs this with [`Self::peek`] to consume only the
    /// canonical-code bits a peeked symbol actually used.
    ///
    /// # Errors
    ///
    /// Same as [`Self::read`].
    pub fn advance(&mut self, n: u32) -> Result<(), ZstdError> {
        let _ = self.read(n)?;
        Ok(())
    }

    /// Lenient counterpart to [`Self::read`]: reads the next `n`
    /// bits MSB-first, but returns `0`-padded values for any bits
    /// past the end of the stream instead of failing with
    /// `UnexpectedEof`. The over-read is recorded by advancing
    /// the internal cursor past `total_bits`; callers can detect
    /// it with [`Self::has_leftover`] or [`Self::is_overread`].
    ///
    /// Used by the sequence decoder, where libzstd-encoded
    /// streams are allowed to under-write the very last
    /// sequence's extras and rely on zero-padding for the missing
    /// LSBs (RFC 8478 §4.2.2 / `BIT_DStream_overflow` semantics).
    ///
    /// # Errors
    ///
    /// - [`ZstdError::MalformedFrameHeader`] when `n >`
    ///   [`MAX_BITS_PER_READ`].
    pub fn read_padded(&mut self, n: u32) -> Result<u32, ZstdError> {
        if n == 0 {
            return Ok(0);
        }
        if n > MAX_BITS_PER_READ {
            return Err(ZstdError::MalformedFrameHeader(
                "reverse bit read > 32 bits",
            ));
        }
        let mut out: u32 = 0;
        for _ in 0..n {
            let bit_index = self.consumed_bits;
            let bit = if bit_index < self.total_bits {
                let byte_from_end = bit_index / 8;
                let bit_in_byte_from_msb = (bit_index % 8) as u32;
                // INVARIANT: bit_index < total_bits, so
                // byte_from_end < bytes.len() and the subtraction
                // is safe.
                let byte_idx = self.bytes.len() - 1 - byte_from_end;
                (self.bytes[byte_idx] >> (7 - bit_in_byte_from_msb)) & 1
            } else {
                // Past the end: zero-pad the bit. Cursor still
                // advances so leftover-vs-over-read can be
                // distinguished post-decode.
                0
            };
            out = (out << 1) | u32::from(bit);
            self.consumed_bits += 1;
        }
        Ok(out)
    }

    /// `true` when the cursor has not yet reached the end of the
    /// data bits — i.e. there are bits the caller hasn't
    /// consumed. After a successful decode using
    /// [`Self::read_padded`] this should be `false`; otherwise
    /// the bitstream is over-long (extra bits the encoder
    /// shouldn't have written).
    #[must_use]
    pub fn has_leftover(&self) -> bool {
        self.consumed_bits < self.total_bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- ForwardBitReader -------------------------------------

    #[test]
    fn forward_reads_individual_bits_lsb_first() {
        // 0b1011_0100, low bit is 0, then 0, then 1, then 0, ...
        let bytes = [0b1011_0100u8];
        let mut r = ForwardBitReader::new(&bytes);
        let observed: Vec<u32> = (0..8).map(|_| r.read(1).expect("bit")).collect();
        assert_eq!(observed, vec![0, 0, 1, 0, 1, 1, 0, 1]);
        assert_eq!(r.bits_remaining(), 0);
    }

    #[test]
    fn forward_read_zero_is_noop() {
        let mut r = ForwardBitReader::new(&[0xFF]);
        assert_eq!(r.read(0).expect("zero"), 0);
        assert_eq!(r.bits_remaining(), 8);
        assert_eq!(r.byte_position(), 0);
        assert_eq!(r.bit_position(), 0);
    }

    #[test]
    fn forward_reads_byte_at_a_time() {
        let bytes = [0xAB, 0xCD];
        let mut r = ForwardBitReader::new(&bytes);
        assert_eq!(r.read(8).expect("byte 0"), 0xAB);
        assert_eq!(r.read(8).expect("byte 1"), 0xCD);
        assert_eq!(r.bits_remaining(), 0);
    }

    #[test]
    fn forward_read_spans_byte_boundary() {
        // Bytes 0xAB, 0xCD = LSB-first stream:
        //   byte 0 LSB->MSB: 1 1 0 1 0 1 0 1   (= 0xAB)
        //   byte 1 LSB->MSB: 1 0 1 1 0 0 1 1   (= 0xCD)
        // After consuming 4 bits from byte 0 we're at the high
        // nibble of byte 0 (= 0xA). Reading 8 more bits should
        // give us 0xA from byte 0's high nibble + 0xD from byte 1's
        // low nibble, packed as 0xDA.
        let mut r = ForwardBitReader::new(&[0xAB, 0xCD]);
        assert_eq!(r.read(4).expect("low nibble of byte 0"), 0x0B);
        assert_eq!(r.read(8).expect("8 bits across boundary"), 0xDA);
        assert_eq!(r.read(4).expect("high nibble of byte 1"), 0x0C);
        assert_eq!(r.bits_remaining(), 0);
    }

    #[test]
    fn forward_read_32_bits_full_word() {
        let bytes = [0x78, 0x56, 0x34, 0x12]; // LE encode of 0x12345678
        let mut r = ForwardBitReader::new(&bytes);
        assert_eq!(r.read(32).expect("32"), 0x12345678);
    }

    #[test]
    fn forward_read_more_than_remaining_errors() {
        let mut r = ForwardBitReader::new(&[0xFF]);
        match r.read(9) {
            Err(ZstdError::UnexpectedEof(_)) => {}
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
        // Cursor must be unchanged after an error.
        assert_eq!(r.bits_remaining(), 8);
    }

    #[test]
    fn forward_read_above_max_bits_errors() {
        let mut r = ForwardBitReader::new(&[0xFF; 8]);
        match r.read(33) {
            Err(ZstdError::MalformedFrameHeader(msg)) => {
                assert!(msg.contains("32 bits"), "msg: {msg}");
            }
            other => panic!("expected MalformedFrameHeader, got {other:?}"),
        }
    }

    #[test]
    fn forward_align_to_byte_advances_only_when_unaligned() {
        let mut r = ForwardBitReader::new(&[0x00, 0x00, 0x00]);
        r.align_to_byte();
        assert_eq!(r.byte_position(), 0);
        let _ = r.read(3).unwrap();
        r.align_to_byte();
        assert_eq!(r.byte_position(), 1);
        assert_eq!(r.bit_position(), 0);
        // Rounding twice is idempotent.
        r.align_to_byte();
        assert_eq!(r.byte_position(), 1);
        assert_eq!(r.bit_position(), 0);
    }

    #[test]
    fn forward_bits_remaining_decrements_per_read() {
        let bytes = [0xFF; 4];
        let mut r = ForwardBitReader::new(&bytes);
        assert_eq!(r.bits_remaining(), 32);
        let _ = r.read(7).unwrap();
        assert_eq!(r.bits_remaining(), 25);
        let _ = r.read(20).unwrap();
        assert_eq!(r.bits_remaining(), 5);
        let _ = r.read(5).unwrap();
        assert_eq!(r.bits_remaining(), 0);
    }

    /// Property-style: reading bits one-at-a-time vs. as a
    /// multi-bit chunk produces the same value (when interpreted
    /// LSB-first).
    #[test]
    fn forward_single_bits_vs_chunked_agree() {
        let bytes = [0x12, 0x34, 0x56, 0x78];
        let total_bits = (bytes.len() * 8) as u32;
        for n in 1..=24u32 {
            for start_bit in 0..16u32 {
                if start_bit + n > total_bits {
                    continue;
                }
                let mut r1 = ForwardBitReader::new(&bytes);
                let _ = r1.read(start_bit).unwrap();
                let chunked = r1.read(n).unwrap();

                let mut r2 = ForwardBitReader::new(&bytes);
                let _ = r2.read(start_bit).unwrap();
                let mut acc: u32 = 0;
                for i in 0..n {
                    acc |= r2.read(1).unwrap() << i;
                }
                assert_eq!(
                    chunked, acc,
                    "n={n} start_bit={start_bit} chunked=0x{chunked:X} bit-by-bit=0x{acc:X}",
                );
            }
        }
    }

    // ---- ReverseBitReader -------------------------------------

    #[test]
    fn reverse_empty_input_rejected() {
        match ReverseBitReader::new(&[]) {
            Err(ZstdError::MalformedFrameHeader(_)) => {}
            other => panic!("expected MalformedFrameHeader, got {other:?}"),
        }
    }

    #[test]
    fn reverse_zero_last_byte_rejected() {
        match ReverseBitReader::new(&[0x00]) {
            Err(ZstdError::MalformedFrameHeader(_)) => {}
            other => panic!("expected MalformedFrameHeader, got {other:?}"),
        }
        // Multi-byte zero last-byte also rejected.
        match ReverseBitReader::new(&[0xFF, 0x00]) {
            Err(ZstdError::MalformedFrameHeader(_)) => {}
            other => panic!("expected MalformedFrameHeader, got {other:?}"),
        }
    }

    #[test]
    fn reverse_sentinel_at_msb_leaves_seven_data_bits() {
        // 0x80 = 1000_0000: sentinel at MSB; the seven bits below
        // it are part of the (zero-valued) data payload, not
        // padding.
        let r = ReverseBitReader::new(&[0x80]).expect("ok");
        assert_eq!(r.bits_remaining(), 7);
    }

    #[test]
    fn reverse_sentinel_at_lsb_yields_empty_stream() {
        // 0x01 = 0000_0001: 7 leading zeros (padding) + sentinel
        // at LSB. No data bits remain.
        let r = ReverseBitReader::new(&[0x01]).expect("ok");
        assert_eq!(r.bits_remaining(), 0);
    }

    #[test]
    fn reverse_reads_msb_first_within_byte() {
        // 0xC2 = 1100_0010. Sentinel is the leading 1 (bit 7).
        // Remaining bits in MSB-first order are: 1, 0, 0, 0, 0,
        // 1, 0 — reading single bits should yield exactly that.
        let mut r = ReverseBitReader::new(&[0xC2]).expect("ok");
        let observed: Vec<u32> = (0..7).map(|_| r.read(1).expect("bit")).collect();
        assert_eq!(observed, vec![1, 0, 0, 0, 0, 1, 0]);
        assert_eq!(r.bits_remaining(), 0);
    }

    #[test]
    fn reverse_chunked_read_packs_msb_first() {
        // 0xC5 = 1100_0101. Sentinel is bit 7. Remaining bits
        // MSB-first: 1, 0, 0, 0, 1, 0, 1 -> read(7) yields
        // 0b1000101 = 0x45.
        let mut r = ReverseBitReader::new(&[0xC5]).expect("ok");
        assert_eq!(r.read(7).expect("7"), 0x45);
    }

    #[test]
    fn reverse_read_spans_byte_boundary_high_to_low() {
        // First byte 0xAB = 1010_1011, second byte 0x80 = 1000_0000
        // (sentinel + 7 zero data bits). Total data = 7 + 8 = 15
        // bits. MSB-first across the boundary, the bit sequence is
        // (last-byte-data) 0,0,0,0,0,0,0 | (first-byte) 1,0,1,0,1,0,1,1.
        // - read(7) consumes the last-byte payload (= 0)
        // - read(8) then reads the first byte's 8 bits MSB-first (= 0xAB)
        let mut r = ReverseBitReader::new(&[0xAB, 0x80]).expect("ok");
        assert_eq!(r.bits_remaining(), 15);
        assert_eq!(r.read(7).expect("last-byte payload"), 0);
        assert_eq!(r.read(8).expect("first-byte data"), 0xAB);
        assert_eq!(r.bits_remaining(), 0);
    }

    #[test]
    fn reverse_read_zero_is_noop() {
        // [0x01] has the sentinel at the LSB so no data bits
        // remain — a read(0) on an empty stream is the cleanest
        // way to assert "no-op never advances or errors."
        let mut r = ReverseBitReader::new(&[0x01]).expect("ok");
        assert_eq!(r.bits_remaining(), 0);
        assert_eq!(r.read(0).expect("zero"), 0);
        assert_eq!(r.bits_remaining(), 0);
    }

    #[test]
    fn reverse_read_more_than_remaining_errors() {
        // [0x01] is empty after the sentinel; any non-zero read
        // must surface UnexpectedEof.
        let mut r = ReverseBitReader::new(&[0x01]).expect("ok");
        match r.read(1) {
            Err(ZstdError::UnexpectedEof(_)) => {}
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn reverse_read_above_max_bits_errors() {
        let mut r = ReverseBitReader::new(&[0xFF; 8]).expect("ok");
        match r.read(33) {
            Err(ZstdError::MalformedFrameHeader(msg)) => {
                assert!(msg.contains("32 bits"), "msg: {msg}");
            }
            other => panic!("expected MalformedFrameHeader, got {other:?}"),
        }
    }

    /// The reverse stream's MSB-first bit-by-bit read agrees with
    /// a chunked read of the same width.
    #[test]
    fn reverse_single_bits_vs_chunked_agree() {
        // Last byte 0x80 → sentinel at MSB, so the data payload
        // is 7 + 8*3 = 31 bits.
        let bytes = [0x12, 0x34, 0x56, 0x80];
        let total_data_bits: u32 = {
            // Match the constructor's bookkeeping: total - sentinel - leading-zero-pad.
            let total = (bytes.len() * 8) as u32;
            let last_byte: u8 = *bytes.last().unwrap();
            let pad: u32 = last_byte.leading_zeros();
            total - pad - 1
        };
        for n in 1..=24u32 {
            for start_bit in 0..16u32 {
                if start_bit + n > total_data_bits {
                    continue;
                }
                let mut r1 = ReverseBitReader::new(&bytes).unwrap();
                let _ = r1.read(start_bit).unwrap();
                let chunked = r1.read(n).unwrap();

                let mut r2 = ReverseBitReader::new(&bytes).unwrap();
                let _ = r2.read(start_bit).unwrap();
                let mut acc: u32 = 0;
                for _ in 0..n {
                    acc = (acc << 1) | r2.read(1).unwrap();
                }
                assert_eq!(
                    chunked, acc,
                    "n={n} start_bit={start_bit} chunked=0x{chunked:X} bit-by-bit=0x{acc:X}",
                );
            }
        }
    }
}
