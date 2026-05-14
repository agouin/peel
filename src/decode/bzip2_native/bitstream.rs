//! Forward MSB-first bit reader for the hand-rolled bzip2 decoder.
//!
//! Bzip2's wire format packs bits MSB-first within each byte: the
//! high bit of every source byte is the first bit read off the
//! stream, the low bit is the eighth. This is the inverse of
//! deflate's LSB-first ordering (RFC 1951 §3.1.1) — a real shape
//! difference, not a translation bug, and the reason this module
//! cannot share code with [`crate::decode::deflate_native::bitstream`].
//!
//! # Cursor accounting
//!
//! Two cursors live on a [`BitReader`]: the source-byte high-water
//! mark (bytes pulled into the accumulator from the pull-buffer) and
//! the bit cursor (bits consumed by [`BitReader::read_bits`] /
//! [`BitReader::consume_bits`]). [`BitReader::byte_position`] returns
//! `(byte_index, bit_off)` where `byte_index` is the index of the
//! byte the bit cursor is currently inside (or sitting at the start
//! of, when `bit_off == 0`).
//!
//! The decoder's
//! [`crate::decode::StreamingDecoder::bytes_consumed`] reports
//! `byte_index` directly. The byte the bit cursor is fractionally
//! inside is **not** freeable — resume will need to re-read it.
//! Bytes the pull-buffer has fetched ahead of `byte_index` are
//! similarly not yet committed: they're the next thing the bit
//! reader will shift in, and the puncher must not touch them. The
//! contract is identical to deflate-native's, just expressed in MSB
//! ordering.

use std::io::{self, Read};

use super::error::Bzip2Error;

/// Maximum number of bits a single [`BitReader::read_bits`] /
/// [`BitReader::peek_bits`] / [`BitReader::consume_bits`] call may
/// pull at once. Hard ceiling 32 because the result type is `u32`;
/// in bzip2 the largest field the reader needs to pull is the 24-bit
/// `origPtr` and the largest Huffman code is 20 bits.
pub const MAX_BITS_PER_READ: u32 = 32;

/// Internal pull-buffer size. Same rationale as the deflate-native
/// reader: large enough to amortize source `read(2)` calls across
/// 100s of KB of compressed input, small enough to stay in L2 next
/// to the Huffman tables and BWT inverse table.
const PULL_BUF_LEN: usize = 256 * 1024;

/// MSB-first forward bit reader over a streaming [`Read`] source.
///
/// Owns the source (matching the in-tree decoder convention from
/// `xz_native` / `deflate_native` / `zstd`). Pulls bytes greedily
/// into an internal pull-buffer and shifts them into a 64-bit
/// accumulator on demand. `Send` because the source is `Send`, so
/// the reader can be moved to a worker thread.
pub struct BitReader {
    /// Wrapped source, dropped on terminal error or clean source
    /// EOF so further calls cheaply short-circuit and OS resources
    /// are released as soon as possible.
    source: Option<Box<dyn Read + Send>>,
    /// Pull-buffer fed by `source.read`. Bytes are valid in
    /// `pull_buf[pull_pos..pull_filled]`; outside that range the
    /// contents are stale and must not be read.
    pull_buf: Box<[u8]>,
    /// Index of the next byte in `pull_buf` to shift into `acc`.
    pull_pos: usize,
    /// Number of valid bytes in `pull_buf`.
    pull_filled: usize,
    /// Bit accumulator. The unconsumed bits live in the **low**
    /// `nbits` of `acc`, ordered such that the next bit to read is
    /// the bit at position `nbits-1` (i.e. the top of the
    /// unconsumed prefix). This is the MSB-first analogue of the
    /// deflate-native reader's "next bit is bit 0" rule.
    acc: u64,
    /// Number of valid bits in `acc`. Range `0..=64`.
    nbits: u32,
    /// Total bytes ever shifted from `pull_buf` into `acc`. The bit
    /// cursor's byte index is `(bytes_into_acc * 8 - nbits) / 8`.
    bytes_into_acc: u64,
}

impl BitReader {
    /// Construct a [`BitReader`] over `source`.
    ///
    /// Does not pull any bytes from the source.
    #[must_use]
    pub fn new(source: Box<dyn Read + Send>) -> Self {
        Self::new_at(source, 0)
    }

    /// Construct a [`BitReader`] over `source` with the cursor's
    /// byte counter primed to `byte_offset`. The initial cursor
    /// reports as `(byte_offset, 0)`; the first byte the reader
    /// delivers is treated as if it were source byte `byte_offset`.
    /// Used by the resume path (Phase 8) to anchor a resumed
    /// decoder's source-cursor accounting at the saved checkpoint
    /// position.
    #[must_use]
    pub fn new_at(source: Box<dyn Read + Send>, byte_offset: u64) -> Self {
        Self {
            source: Some(source),
            pull_buf: vec![0u8; PULL_BUF_LEN].into_boxed_slice(),
            pull_pos: 0,
            pull_filled: 0,
            acc: 0,
            nbits: 0,
            bytes_into_acc: byte_offset,
        }
    }

    /// Reseat the byte-counter baseline. Equivalent to having
    /// constructed via [`Self::new_at`] with this `byte_offset`.
    /// Only valid before any bits have been consumed.
    pub fn set_byte_offset(&mut self, byte_offset: u64) {
        debug_assert!(
            self.is_untouched(),
            "BitReader::set_byte_offset called after the cursor advanced \
             (nbits={}, pull_pos={}, pull_filled={}, bytes_into_acc={})",
            self.nbits,
            self.pull_pos,
            self.pull_filled,
            self.bytes_into_acc,
        );
        self.bytes_into_acc = byte_offset;
    }

    /// `true` when the cursor is at its post-construction zero state
    /// — no bits buffered, no bytes pulled, no bytes shifted into the
    /// accumulator. Used by the decoder's `set_source_start_offset`
    /// override to distinguish a fresh regular-factory build (safe
    /// to reseat) from a `resume_factory`-built reader that has
    /// already been positioned and may have consumed bits during a
    /// bit-skip dance.
    #[must_use]
    pub fn is_untouched(&self) -> bool {
        self.nbits == 0 && self.pull_pos == self.pull_filled && self.bytes_into_acc == 0
    }

    /// Best-effort: top up the accumulator until it holds at least
    /// `n` valid bits, **or the source is exhausted**. Returns
    /// `Ok(())` either way; the caller is responsible for checking
    /// [`Self::bits_buffered`] before consuming bits.
    ///
    /// # Errors
    ///
    /// Only [`Bzip2Error::SourceIo`] for an underlying `Read::read`
    /// failure (after honoring `Interrupted`). Source EOF surfaces
    /// as `Ok(())` with `bits_buffered() < n`.
    ///
    /// # Panics
    ///
    /// Debug-asserts `n <= MAX_BITS_PER_READ`.
    pub fn ensure(&mut self, n: u32) -> Result<(), Bzip2Error> {
        debug_assert!(
            n <= MAX_BITS_PER_READ,
            "BitReader::ensure: cannot peek more than {MAX_BITS_PER_READ} bits at a time",
        );
        while self.nbits < n {
            if self.pull_pos >= self.pull_filled && !self.refill_pull_buf()? {
                return Ok(());
            }
            let byte = self.pull_buf[self.pull_pos];
            self.pull_pos += 1;
            // MSB-first: shift the accumulator left by 8 and OR the
            // new byte into the low 8 bits. The next bit to read is
            // the highest bit of the (now-extended) unconsumed
            // prefix. INVARIANT: `nbits <= 56` here because we only
            // enter this branch when `nbits < n <= 32`, so adding 8
            // keeps us within the 64-bit accumulator's capacity.
            self.acc = (self.acc << 8) | u64::from(byte);
            self.nbits = self.nbits.saturating_add(8);
            self.bytes_into_acc = self.bytes_into_acc.saturating_add(1);
        }
        Ok(())
    }

    /// Pull more bytes from the source into the pull-buffer. Returns
    /// `Ok(true)` when at least one new byte was buffered,
    /// `Ok(false)` when the source signaled clean EOF.
    fn refill_pull_buf(&mut self) -> Result<bool, Bzip2Error> {
        self.pull_pos = 0;
        self.pull_filled = 0;
        let Some(source) = self.source.as_mut() else {
            return Ok(false);
        };
        loop {
            match source.read(&mut self.pull_buf) {
                Ok(0) => {
                    self.source = None;
                    return Ok(false);
                }
                Ok(n) => {
                    self.pull_filled = n;
                    return Ok(true);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Bzip2Error::SourceIo(e)),
            }
        }
    }

    /// Read the next `n` bits without advancing the cursor.
    ///
    /// The **most-significant** bit of the returned value is the bit
    /// closest to the start of the stream (the MSB of the byte at
    /// `byte_position().0`, when `bit_off == 0`). Reading 8 bits at a
    /// byte boundary returns the byte value verbatim.
    ///
    /// **Short-buffer semantics.** When `nbits < n`, this returns
    /// the available bits in the **low** positions plus implicit
    /// zero-padding in the **high** positions. Callers that need
    /// strict "n bits or error" semantics should use
    /// [`Self::read_bits`] (or check [`Self::bits_buffered`] before
    /// committing to a [`Self::consume_bits`]).
    ///
    /// # Panics
    ///
    /// Debug-asserts `n <= MAX_BITS_PER_READ`.
    #[must_use]
    pub fn peek_bits(&self, n: u32) -> u32 {
        debug_assert!(n <= MAX_BITS_PER_READ);
        if n == 0 {
            return 0;
        }
        if n > self.nbits {
            // Short-buffer: pad the bits we have into the low
            // positions of the result. The unconsumed prefix is
            // `acc & ((1 << nbits) - 1)`; the result is that prefix
            // shifted up so its top aligns with bit `n-1`.
            let avail = if self.nbits == 0 {
                0u64
            } else if self.nbits >= 64 {
                self.acc
            } else {
                self.acc & ((1u64 << self.nbits) - 1)
            };
            // Pad on the right with zeros (the bits we don't have
            // are treated as zero). INVARIANT: `n - self.nbits <= 32`
            // because `n <= 32` and `nbits >= 0`.
            return (avail << (n - self.nbits)) as u32;
        }
        // INVARIANT: `nbits >= n`, so `nbits - n` is non-negative.
        ((self.acc >> (self.nbits - n))
            & if n == 32 {
                u32::MAX as u64
            } else {
                (1u64 << n) - 1
            }) as u32
    }

    /// Advance the cursor by `n` bits without producing a value.
    /// Pairs with [`Self::peek_bits`] to implement the
    /// "peek-then-commit" Huffman-decode pattern.
    ///
    /// # Panics
    ///
    /// Debug-asserts `n <= MAX_BITS_PER_READ` and `nbits >= n`.
    pub fn consume_bits(&mut self, n: u32) {
        debug_assert!(n <= MAX_BITS_PER_READ);
        debug_assert!(
            self.nbits >= n,
            "BitReader::consume_bits({n}) called with only {} bits buffered",
            self.nbits,
        );
        self.nbits -= n;
        // Mask off the high bits we just consumed so a subsequent
        // `(acc << 8) | byte` does not drag stale bits up into a
        // future read window. Equivalent to a logical right-shift in
        // an LSB-first reader; the cost is one mask per consume.
        if self.nbits == 0 {
            self.acc = 0;
        } else if self.nbits < 64 {
            self.acc &= (1u64 << self.nbits) - 1;
        }
        // nbits == 64 is unreachable (we never ensure past 56) but
        // the branch is harmless: the mask would be a no-op.
    }

    /// Read the next `n` bits and advance the cursor — the fallible
    /// `ensure + peek + consume` composition.
    ///
    /// Strict variant: surfaces [`Bzip2Error::UnexpectedEof`] when
    /// the source is exhausted before `n` bits are available.
    ///
    /// Returns the bits as a `u32` with the same bit ordering as
    /// [`Self::peek_bits`]: MSB closest to the start of the stream.
    ///
    /// # Errors
    ///
    /// - [`Bzip2Error::UnexpectedEof`] when fewer than `n` bits are
    ///   available after a best-effort refill.
    /// - [`Bzip2Error::SourceIo`] from the underlying [`Self::ensure`].
    pub fn read_bits(&mut self, n: u32) -> Result<u32, Bzip2Error> {
        self.ensure(n)?;
        if self.nbits < n {
            return Err(Bzip2Error::UnexpectedEof("bit stream"));
        }
        let v = self.peek_bits(n);
        self.consume_bits(n);
        Ok(v)
    }

    /// Read a 32-bit big-endian word from the stream. Equivalent to
    /// four `read_bits(8)` calls — saves spelling them out at the
    /// block-CRC and stream-CRC trailer sites and clarifies intent.
    ///
    /// # Errors
    ///
    /// - [`Bzip2Error::UnexpectedEof`] on truncation.
    /// - [`Bzip2Error::SourceIo`] on IO failure.
    pub fn read_u32_be(&mut self) -> Result<u32, Bzip2Error> {
        // Two 16-bit reads stitched together: we can't satisfy a
        // 32-bit `read_bits(32)` in a single ensure call from a
        // 64-bit accumulator that's already holding non-trivial
        // bits, so do this in two halves to keep within the
        // 32-bit-per-read budget.
        let hi = self.read_bits(16)?;
        let lo = self.read_bits(16)?;
        Ok((hi << 16) | lo)
    }

    /// Source-byte index the bit cursor is currently inside, paired
    /// with the bit offset within that byte.
    ///
    /// The returned `byte_index` is the byte position the
    /// [`crate::decode::StreamingDecoder::bytes_consumed`] floor
    /// should report at the trait boundary: bytes strictly before
    /// this index are fully consumed and safe for the puncher to
    /// release; the byte at `byte_index` is either a clean boundary
    /// (when `bit_off == 0`) or fractionally consumed (when
    /// `bit_off in 1..=7`) and must stay on disk until the cursor
    /// moves through it.
    ///
    /// # Returns
    ///
    /// `(byte_index, bit_off)` where:
    /// - `byte_index` ∈ `0..=bytes_into_acc`.
    /// - `bit_off` ∈ `0..=7`.
    #[must_use]
    pub fn byte_position(&self) -> (u64, u8) {
        let bits_consumed = self.bytes_into_acc.saturating_mul(8) - u64::from(self.nbits);
        let byte_index = bits_consumed / 8;
        // INVARIANT: `bits_consumed % 8 < 8`, fits in `u8`.
        let bit_off = (bits_consumed % 8) as u8;
        (byte_index, bit_off)
    }

    /// Number of bits currently buffered in the accumulator. Mostly
    /// useful for tests that need to assert internal state.
    #[must_use]
    pub fn bits_buffered(&self) -> u32 {
        self.nbits
    }

    /// Discard 0..=7 bits so the next read starts on a byte
    /// boundary. Used between concatenated bzip2 streams in a
    /// multi-stream `.bz2` file: the encoder pads each stream's
    /// last byte with zeros (via `bsFinishWrite`), and the next
    /// stream's header is byte-aligned. Idempotent when already
    /// at a byte boundary.
    pub fn align_to_byte(&mut self) {
        let drop = self.nbits & 7;
        if drop != 0 {
            // INVARIANT: `drop` is in `0..=7`, so it cannot exceed
            // `nbits`.
            self.consume_bits(drop);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    fn reader(bytes: Vec<u8>) -> BitReader {
        BitReader::new(Box::new(Cursor::new(bytes)))
    }

    #[test]
    fn read_bits_byte_at_a_time_msb_first() {
        // 0x4B = 0b0100_1011. MSB-first read order yields:
        //   bit 7: 0   bit 6: 1   bit 5: 0   bit 4: 0
        //   bit 3: 1   bit 2: 0   bit 1: 1   bit 0: 1
        let mut br = reader(vec![0x4B]);
        for &expected in &[0u32, 1, 0, 0, 1, 0, 1, 1] {
            let bit = br.read_bits(1).expect("bit");
            assert_eq!(bit, expected, "next bit");
        }
    }

    #[test]
    fn read_bits_groups_msb_first_within_byte() {
        // 0x4B = 0b0100_1011 read as 3, 2, 3 bits:
        //   top 3 bits = 0b010 = 2
        //   next 2 bits = 0b01 = 1
        //   low 3 bits  = 0b011 = 3
        let mut br = reader(vec![0x4B]);
        assert_eq!(br.read_bits(3).expect("3"), 0b010);
        assert_eq!(br.read_bits(2).expect("2"), 0b01);
        assert_eq!(br.read_bits(3).expect("3"), 0b011);
    }

    #[test]
    fn read_bits_spans_byte_boundary_msb_first() {
        // 0xAB 0xCD as 12-bit MSB-first read:
        //   acc after 2 byte-shifts = 0xABCD
        //   top 12 bits = 0xABC
        let mut br = reader(vec![0xAB, 0xCD]);
        assert_eq!(br.read_bits(12).expect("12"), 0xABC);
        // Remaining 4 bits = low nibble of 0xCD = 0xD.
        assert_eq!(br.read_bits(4).expect("4"), 0xD);
    }

    #[test]
    fn read_bits_can_read_24_bits() {
        // origPtr field is 24 bits — the largest single-read bzip2
        // ever issues. MSB-first byte-by-byte concat:
        //   0x11 0x22 0x33 → top 24 bits = 0x112233
        let mut br = reader(vec![0x11, 0x22, 0x33, 0x44]);
        assert_eq!(br.read_bits(24).expect("24"), 0x0011_2233);
        assert_eq!(br.read_bits(8).expect("8"), 0x44);
    }

    #[test]
    fn read_u32_be_concatenates_four_bytes_msb_first() {
        // 32-bit CRC: 0x11 0x22 0x33 0x44 → 0x1122_3344
        let mut br = reader(vec![0x11, 0x22, 0x33, 0x44]);
        assert_eq!(br.read_u32_be().expect("u32"), 0x1122_3344);
    }

    #[test]
    fn peek_then_consume_pattern_for_huffman() {
        // Simulate Huffman decode: ensure 20 bits (bzip2 max),
        // peek 20, discover actual code is 5 bits, consume 5.
        let mut br = reader(vec![0xAB, 0xCD, 0xEF]);
        br.ensure(20).expect("ensure");
        let look = br.peek_bits(20);
        // 24 bits buffered (3 bytes): top 20 = 0xABCDE.
        assert_eq!(look, 0x0A_BCDE);
        // Top 5 bits = 0b10101 = 21.
        let code_len = 5u32;
        let code = look >> (20 - code_len);
        assert_eq!(code, 0b10101);
        br.consume_bits(code_len);
        // Cursor advanced by exactly 5 bits.
        assert_eq!(br.byte_position(), (0, 5));
    }

    #[test]
    fn byte_position_tracks_partial_byte_consumption() {
        let mut br = reader(vec![0x00, 0x00, 0x00]);
        assert_eq!(br.byte_position(), (0, 0));
        br.read_bits(1).expect("1");
        assert_eq!(br.byte_position(), (0, 1));
        br.read_bits(6).expect("6");
        assert_eq!(br.byte_position(), (0, 7));
        br.read_bits(1).expect("1");
        assert_eq!(br.byte_position(), (1, 0));
        br.read_bits(9).expect("9");
        assert_eq!(br.byte_position(), (2, 1));
    }

    #[test]
    fn unexpected_eof_when_source_runs_out_mid_stream() {
        let mut br = reader(vec![0xFF]);
        br.read_bits(8).expect("byte 0");
        match br.read_bits(1) {
            Err(Bzip2Error::UnexpectedEof(label)) => {
                assert_eq!(label, "bit stream");
            }
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn unexpected_eof_when_source_empty_at_construction() {
        let mut br = reader(Vec::new());
        match br.read_bits(1) {
            Err(Bzip2Error::UnexpectedEof(_)) => {}
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn read_bits_zero_is_a_noop() {
        let mut br = reader(vec![0xFF]);
        let before = br.byte_position();
        let v = br.read_bits(0).expect("zero-bit read");
        assert_eq!(v, 0);
        assert_eq!(br.byte_position(), before);
    }

    #[test]
    fn cursor_floor_under_partial_byte_consumption() {
        // After reading 11 bits (8 + 3) of 3 source bytes, the floor
        // points at byte 1 (the byte the bit cursor is fractionally
        // inside); the puncher can release byte 0 but must keep
        // byte 1.
        let mut br = reader(vec![0xAA, 0xBB, 0xCC]);
        br.read_bits(11).expect("11");
        assert_eq!(br.byte_position(), (1, 3));
    }

    #[test]
    fn source_io_error_propagates_as_typed_variant() {
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::ConnectionAborted, "boom"))
            }
        }
        let mut br = BitReader::new(Box::new(FailingReader));
        match br.read_bits(1) {
            Err(Bzip2Error::SourceIo(e)) => {
                assert_eq!(e.kind(), io::ErrorKind::ConnectionAborted);
            }
            other => panic!("expected SourceIo, got {other:?}"),
        }
    }

    #[test]
    fn interrupted_reads_are_retried_transparently() {
        struct FlakeyReader {
            calls: u32,
            byte: u8,
        }
        impl Read for FlakeyReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.calls += 1;
                if self.calls <= 2 {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "again"));
                }
                buf[0] = self.byte;
                Ok(1)
            }
        }
        let mut br = BitReader::new(Box::new(FlakeyReader {
            calls: 0,
            byte: 0xAA,
        }));
        assert_eq!(br.read_bits(8).expect("retried"), 0xAA);
    }

    #[test]
    fn cursor_advances_across_pull_buffer_refill() {
        let len = PULL_BUF_LEN + 64;
        let bytes: Vec<u8> = (0..len).map(|i| (i & 0xFF) as u8).collect();
        let mut br = reader(bytes.clone());
        for (i, &expected) in bytes.iter().enumerate() {
            let read = br.read_bits(8).expect("byte") as u8;
            assert_eq!(read, expected);
            assert_eq!(br.byte_position(), ((i as u64) + 1, 0));
        }
    }

    #[test]
    fn set_byte_offset_at_construction_reports_offset_in_position() {
        let br = BitReader::new_at(Box::new(Cursor::new(vec![0u8; 16])), 1000);
        assert_eq!(br.byte_position(), (1000, 0));
    }

    #[test]
    fn peek_bits_short_buffer_pads_low_bits_with_available_high_zeros() {
        // Three bits in the buffer (after reading one byte): the
        // accumulator holds nothing. Peeking 5 bits past EOF returns
        // 0 because no bits are available; the implicit padding
        // pushes the "available" zero up.
        let mut br = reader(vec![0x80]);
        br.ensure(8).expect("ensure");
        // top 8 = 0x80.
        let v = br.peek_bits(8);
        assert_eq!(v, 0x80);
        br.consume_bits(8);
        // Now nbits=0. Peeking returns zero-padded.
        assert_eq!(br.peek_bits(4), 0);
    }
}
