//! Memory-only MSB-first bit reader for RarVM bytecode parsing.
//!
//! Mirrors libarchive's `struct memory_bit_reader` +
//! `membr_bits` + `membr_fill` (`archive_read_support_format_rar.c`
//! lines 252..260 + 3596..3636). The RarVM bytecode payload (the
//! `code` buffer that `read_filter` reads off the wire) is itself
//! a bitstream: parameters such as the program-cache index,
//! block start offset, block length, register mask, register
//! values, embedded-bytecode length, and global-data length are
//! all encoded via the [`next_rarvm_number`] 2-bit-tag width
//! codec; embedded raw bytes are pulled out via repeated
//! `bits(8)` calls. Reads can land at arbitrary bit offsets
//! within the buffer, so a streaming bit reader is unavoidable.
//!
//! Distinct from [`crate::decode::rar_legacy::bits::BitReader`]:
//! the outer reader streams the entry's compressed bytes through
//! a 64-bit accumulator and tracks resume cursors; the memory
//! bit reader is byte-bounded, fail-soft (underrun returns zero
//! and sticks an `at_eof` flag rather than erroring), and exists
//! only for the lifetime of a single declaration parse. The
//! two are unrelated by design; sharing a single reader would
//! conflate the streaming/non-streaming and error/soft-fail
//! contracts that the outer LZ stream and the inner bytecode
//! stream demand.
//!
//! # Soft-fail underrun
//!
//! libarchive's `membr_bits` (line 3617) returns 0 on underrun
//! and sets `br.at_eof`. We do the same. The caller checks
//! [`MemBitReader::at_eof`] after parse completes; libarchive
//! does the same at `parse_filter` line 3371. Modelling underrun
//! as a soft-fail (instead of erroring inline) lets the parser
//! walk through the bytecode tolerantly and surface one clear
//! "malformed bytecode" error at the end, instead of one error
//! per probe.

/// Maximum bits a single [`MemBitReader::bits`] call may pull at
/// once. libarchive's `membr_bits` reads up to 32 bits; we mirror
/// the same hard cap. `MAX_BITS_PER_READ` in the outer
/// [`crate::decode::rar_legacy::bits::BitReader`] uses the same
/// limit — keeping both at 32 means a future cross-format
/// inspection sees a single ceiling.
pub const MEMBR_MAX_BITS_PER_READ: u32 = 32;

/// MSB-first bit reader over a borrowed byte slice, with
/// soft-fail underrun semantics.
///
/// Bytes are shifted into the accumulator at the low end (LSB
/// side); the next-to-read bit is the bit at position
/// `available - 1`. This matches libarchive's `(br->bits >>
/// (br->available -= bits)) & mask` pattern at line 3621.
pub struct MemBitReader<'a> {
    /// Borrowed bytecode payload.
    bytes: &'a [u8],
    /// Index of the next byte to shift into the accumulator.
    offset: usize,
    /// Bit accumulator. Low `available` bits are valid; bits at
    /// position `[available, 64)` are stale carry-over from
    /// earlier shifts.
    bits: u64,
    /// Count of valid bits at the low end of `bits`. Range
    /// `0..=64`.
    available: u32,
    /// Sticky flag: set once a [`Self::bits`] call asks for more
    /// bits than the remaining input + accumulator could supply.
    /// Once set, every subsequent read returns 0. The caller is
    /// expected to inspect this after parsing completes to
    /// decide whether the parse was valid.
    at_eof: bool,
}

impl<'a> MemBitReader<'a> {
    /// Construct a fresh reader over `bytes`. Accumulator starts
    /// empty; first [`Self::bits`] call pulls the first byte.
    #[must_use]
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            bits: 0,
            available: 0,
            at_eof: false,
        }
    }

    /// Construct a reader that starts at `start_offset` bytes
    /// into `bytes`. libarchive's `compile_program` uses this
    /// shape with `start_offset = 1` to skip the XOR-checksum
    /// byte before reading the optional static-data block.
    #[must_use]
    pub fn new_at(bytes: &'a [u8], start_offset: usize) -> Self {
        let clamped = start_offset.min(bytes.len());
        Self {
            bytes,
            offset: clamped,
            bits: 0,
            available: 0,
            at_eof: false,
        }
    }

    /// Pull `n` bits from the stream and advance the cursor.
    ///
    /// `n == 0` is a no-op that returns 0. Returns 0 (and sets
    /// [`Self::at_eof`]) on underrun.
    ///
    /// # Panics
    ///
    /// Debug-asserts that `n <= MEMBR_MAX_BITS_PER_READ`.
    pub fn bits(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        debug_assert!(
            n <= MEMBR_MAX_BITS_PER_READ,
            "MemBitReader::bits({n}) exceeds MEMBR_MAX_BITS_PER_READ ({MEMBR_MAX_BITS_PER_READ})"
        );
        if self.at_eof {
            return 0;
        }
        // Refill from the underlying byte slice until either we
        // have enough bits or the buffer is exhausted. libarchive
        // does the same in `membr_fill` (lines 3624..3636), and
        // tolerates a partial refill so the caller can decide
        // when to stop.
        while self.available < n && self.offset < self.bytes.len() {
            // Shift the new byte's 8 bits into the low end of
            // the accumulator. This places older bits in
            // higher-order positions (towards the MSB) — the
            // MSB-first read at the top of this function then
            // extracts them in the wire's natural order.
            self.bits = (self.bits << 8) | u64::from(self.bytes[self.offset]);
            self.offset += 1;
            self.available += 8;
        }
        if self.available < n {
            // Match libarchive's behaviour: stick a soft-fail
            // flag and return 0 for every subsequent read.
            self.at_eof = true;
            return 0;
        }
        self.available -= n;
        // libarchive: `(br->bits >> (br->available -= bits)) & mask`.
        // `n == 64` would overshift; the debug-assert above
        // forbids it via MEMBR_MAX_BITS_PER_READ = 32, so we
        // can compute `mask` without guarding for `n == 64`.
        let mask: u64 = (1u64 << n) - 1;
        ((self.bits >> self.available) & mask) as u32
    }

    /// `true` once an underrun has been observed. Sticky.
    #[must_use]
    pub fn at_eof(&self) -> bool {
        self.at_eof
    }

    /// Bytes the reader has consumed off the underlying slice
    /// (refilled into the accumulator). Equal to the underlying
    /// slice's length once fully drained. Diagnostic; not used
    /// in parser hot paths.
    #[must_use]
    pub fn byte_offset(&self) -> usize {
        self.offset
    }
}

/// Decode a `next_rarvm_number` value from `br`.
///
/// libarchive's `membr_next_rarvm_number` (lines 3596..3614). A
/// 2-bit tag selects one of four width classes:
///
/// | tag | encoding                                                           |
/// |-----|--------------------------------------------------------------------|
/// | `0` | 4 raw bits → `0..=15`                                              |
/// | `1` | 8 raw bits; if ≥ 16 → that value; else 8-bit prefix `+ extra 4`    |
/// | `2` | 16 raw bits → `0..=65535`                                          |
/// | `3` | 32 raw bits → `0..=u32::MAX`                                       |
///
/// The tag-1 small-value branch maps `val ∈ 0..16` to
/// `0xFFFFFF00 | (val << 4) | extra_4_bits`, which produces a
/// "negative" `i32` value when interpreted as signed — used by
/// the encoder for register-relative offsets that may be
/// negative (the parser reads the result back as `u32` and the
/// register-value path inherits the negative i32 bit pattern).
///
/// Underrun is soft: subsequent reads return 0, and the caller
/// is expected to check [`MemBitReader::at_eof`] after the parse
/// finishes.
#[must_use]
pub fn next_rarvm_number(br: &mut MemBitReader<'_>) -> u32 {
    let tag = br.bits(2);
    match tag {
        0 => br.bits(4),
        1 => {
            let val = br.bits(8);
            if val >= 16 {
                val
            } else {
                0xFFFF_FF00 | (val << 4) | br.bits(4)
            }
        }
        2 => br.bits(16),
        _ => br.bits(32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pack a sequence of `(value, width)` pairs MSB-first into
    /// a byte buffer. Mirrors `BitReader`'s `encode_msb` helper
    /// (`bits.rs` tests) — kept local so the membr tests don't
    /// reach into the outer reader's test module.
    fn pack_msb(pairs: &[(u32, u32)]) -> Vec<u8> {
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
    fn bits_zero_is_a_noop() {
        let mut br = MemBitReader::new(&[0xAB]);
        assert_eq!(br.bits(0), 0);
        assert!(!br.at_eof());
        assert_eq!(br.byte_offset(), 0);
    }

    #[test]
    fn bits_reads_msb_first_across_a_byte_boundary() {
        // 0xAB 0xCD = 0b1010_1011 0b1100_1101.
        let mut br = MemBitReader::new(&[0xAB, 0xCD]);
        assert_eq!(br.bits(3), 0b101);
        assert_eq!(br.bits(5), 0b01011);
        assert_eq!(br.bits(4), 0xC);
        assert_eq!(br.bits(4), 0xD);
        assert!(!br.at_eof());
    }

    #[test]
    fn bits_reads_a_full_32_bit_word_in_one_call() {
        let mut br = MemBitReader::new(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(br.bits(32), 0xDEAD_BEEF);
        assert!(!br.at_eof());
    }

    #[test]
    fn underrun_returns_zero_and_sticks_at_eof() {
        let mut br = MemBitReader::new(&[0xAB]);
        assert_eq!(br.bits(8), 0xAB);
        assert_eq!(br.bits(1), 0);
        assert!(br.at_eof());
        // Subsequent reads also return zero.
        assert_eq!(br.bits(8), 0);
        assert!(br.at_eof());
    }

    #[test]
    fn new_at_skips_the_xor_check_byte() {
        // libarchive's compile_program does `br.offset = 1` to
        // skip bytes[0] (the XOR checksum). After that, the
        // membr reads from byte 1 onwards.
        let mut br = MemBitReader::new_at(&[0xAA, 0xBB, 0xCC], 1);
        assert_eq!(br.bits(8), 0xBB);
        assert_eq!(br.bits(8), 0xCC);
        assert!(!br.at_eof());
        assert_eq!(br.bits(1), 0);
        assert!(br.at_eof());
    }

    #[test]
    fn new_at_clamps_offset_past_end() {
        let mut br = MemBitReader::new_at(&[0xAA, 0xBB], 9);
        assert_eq!(br.bits(1), 0);
        assert!(br.at_eof());
    }

    #[test]
    fn next_rarvm_number_tag_0_returns_4_bits() {
        // Tag 00, value 0b1010 = 10.
        let bytes = pack_msb(&[(0b00, 2), (0b1010, 4)]);
        let mut br = MemBitReader::new(&bytes);
        assert_eq!(next_rarvm_number(&mut br), 10);
    }

    #[test]
    fn next_rarvm_number_tag_1_large_returns_8_bits() {
        // Tag 01, value 0xAB (≥ 16, so no extra 4 bits).
        let bytes = pack_msb(&[(0b01, 2), (0xAB, 8)]);
        let mut br = MemBitReader::new(&bytes);
        assert_eq!(next_rarvm_number(&mut br), 0xAB);
    }

    #[test]
    fn next_rarvm_number_tag_1_small_prepends_negative_bias() {
        // Tag 01, val = 5 (< 16), extra = 0b1010 = 10.
        // → 0xFFFFFF00 | (5 << 4) | 10 = 0xFFFFFF5A.
        let bytes = pack_msb(&[(0b01, 2), (5, 8), (0b1010, 4)]);
        let mut br = MemBitReader::new(&bytes);
        assert_eq!(next_rarvm_number(&mut br), 0xFFFF_FF5A);
    }

    #[test]
    fn next_rarvm_number_tag_2_returns_16_bits() {
        // Tag 10, value 0xCAFE.
        let bytes = pack_msb(&[(0b10, 2), (0xCAFE, 16)]);
        let mut br = MemBitReader::new(&bytes);
        assert_eq!(next_rarvm_number(&mut br), 0xCAFE);
    }

    #[test]
    fn next_rarvm_number_tag_3_returns_32_bits() {
        // Tag 11, value 0xDEADBEEF.
        let bytes = pack_msb(&[(0b11, 2), (0xDEAD_BEEF, 32)]);
        let mut br = MemBitReader::new(&bytes);
        assert_eq!(next_rarvm_number(&mut br), 0xDEAD_BEEF);
    }

    #[test]
    fn next_rarvm_number_propagates_underrun() {
        // Tag 10 (16-bit raw) with only 6 payload bits available:
        // the 16-bit value read underruns and returns 0 directly,
        // without the negative-bias path that tag-1's
        // `val < 16` branch would walk.
        let bytes = pack_msb(&[(0b10, 2), (0, 6)]);
        assert_eq!(bytes.len(), 1);
        let mut br = MemBitReader::new(&bytes);
        let v = next_rarvm_number(&mut br);
        assert!(br.at_eof());
        assert_eq!(v, 0);
    }
}
