//! Forward bit reader for the hand-rolled DEFLATE decoder.
//!
//! RFC 1951 §3.1.1 specifies the deflate stream's bit ordering: bytes
//! are written low-byte first into the stream, and bits within each
//! byte are packed LSB-first. So if a byte's hex value is `0x4B`
//! (`0b01001011`), the first bit read off the stream is bit 0 (the
//! LSB) = `1`, the second is bit 1 = `1`, the third is bit 2 = `0`,
//! and so on.
//!
//! This module provides one type — [`BitReader`] — that owns a
//! `Box<dyn Read + Send>` source and pulls bytes lazily into an
//! internal pull-buffer, then shifts bytes from that buffer into a
//! 64-bit accumulator on demand. Callers read up to 32 bits per
//! call (sufficient for every deflate field — Huffman codes are at
//! most 15 bits, distance extra-bits are at most 13). The reader
//! is the foundation Phases 3 and 4 build on for fixed and dynamic
//! Huffman blocks; Phase 5 wires it into the multi-block stream
//! loop currently driven by direct byte reads in the parent
//! [`super::Decoder`].
//!
//! # Cursor accounting
//!
//! Two cursors live on a [`BitReader`]: the source-byte high-water
//! mark (bytes pulled into the accumulator from the pull-buffer)
//! and the bit cursor (bits consumed by [`BitReader::read_bits`] /
//! [`BitReader::consume_bits`]). [`BitReader::byte_position`]
//! returns `(byte_index, bit_off)` where `byte_index` is the index
//! of the byte the bit cursor is currently inside (or sitting at the
//! start of, when `bit_off == 0`).
//!
//! The convention `docs/PLAN_deflate_block_decoder.md` §Risks 2
//! adopts: the decoder's [`crate::decode::StreamingDecoder::bytes_consumed`]
//! reports `byte_index` directly. The byte the bit cursor is
//! fractionally inside is **not** freeable — resume will need to
//! re-read it. Bytes that the pull-buffer has fetched ahead of
//! `byte_index` are similarly not yet committed: they're the next
//! thing the bit reader will shift in, and the puncher must not
//! touch them.

use std::io::{self, Read};

use super::error::DeflateError;

/// Maximum number of bits a single [`BitReader::read_bits`] /
/// [`BitReader::peek_bits`] / [`BitReader::consume_bits`] call may
/// pull at once. The hard ceiling is 32 because the result type is
/// `u32`; the practical ceiling in RFC 1951 is far tighter (15 bits
/// for a Huffman code, 13 bits for a distance extra-field).
pub const MAX_BITS_PER_READ: u32 = 32;

/// Internal pull-buffer size. Sized for "modest syscall amortization,
/// modest stranded-bytes ceiling": 4 KiB means at most one in-flight
/// chunk's worth of read-ahead beyond the bit cursor, which keeps the
/// gap between [`BitReader::byte_position`] and `source.read`'s
/// high-water mark bounded — important for the puncher floor
/// convention documented at the module level.
const PULL_BUF_LEN: usize = 4096;

/// LSB-first forward bit reader over a streaming [`Read`] source.
///
/// Owns the source (matching the in-tree decoder convention from
/// [`crate::decode::xz_native`] / [`crate::decode::zstd`]). Reads
/// bytes greedily into an internal pull-buffer and shifts them into
/// a 64-bit accumulator on demand. `Send` because the source is
/// `Send`, so the reader can be moved to a worker thread.
pub struct BitReader {
    /// Wrapped source, dropped on terminal error or clean source EOF
    /// so further calls cheaply short-circuit and OS resources are
    /// released as soon as possible.
    source: Option<Box<dyn Read + Send>>,
    /// Pull-buffer fed by `source.read`. Bytes are valid in
    /// `pull_buf[pull_pos..pull_filled]`; outside that range the
    /// contents are stale and must not be read.
    pull_buf: Box<[u8]>,
    /// Index of the next byte in `pull_buf` to shift into `acc`.
    pull_pos: usize,
    /// Number of valid bytes in `pull_buf`.
    pull_filled: usize,
    /// 64-bit bit accumulator. The low `nbits` bits are unconsumed
    /// (next-to-read by `peek_bits` / `consume_bits`).
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
    /// Does not pull any bytes from the source. The first
    /// [`Self::read_bits`] / [`Self::ensure`] call is the first one
    /// that may issue `Read::read`.
    #[must_use]
    pub fn new(source: Box<dyn Read + Send>) -> Self {
        Self {
            source: Some(source),
            pull_buf: vec![0u8; PULL_BUF_LEN].into_boxed_slice(),
            pull_pos: 0,
            pull_filled: 0,
            acc: 0,
            nbits: 0,
            bytes_into_acc: 0,
        }
    }

    /// Top up the accumulator from the pull-buffer (and the source,
    /// if the pull-buffer is empty) until it holds at least `n`
    /// valid bits, or the source is exhausted.
    ///
    /// # Errors
    ///
    /// - [`DeflateError::UnexpectedEof`] when the source delivers
    ///   `Ok(0)` before `n` bits could be assembled.
    /// - [`DeflateError::SourceIo`] for any other `Read::read`
    ///   failure (after honoring `Interrupted`).
    ///
    /// # Panics
    ///
    /// Debug-asserts `n <= MAX_BITS_PER_READ`.
    pub fn ensure(&mut self, n: u32) -> Result<(), DeflateError> {
        debug_assert!(
            n <= MAX_BITS_PER_READ,
            "BitReader::ensure: cannot peek more than {MAX_BITS_PER_READ} bits at a time",
        );
        while self.nbits < n {
            // Refill the pull-buffer from the source if it's empty.
            // Source exhausted and no buffered bytes left = permanent
            // EOF, surface as UnexpectedEof.
            if self.pull_pos >= self.pull_filled && !self.refill_pull_buf()? {
                return Err(DeflateError::UnexpectedEof("bit stream"));
            }
            // Shift one byte from the pull-buffer into the
            // accumulator, low-bytes-first per RFC 1951 §3.1.1.
            // INVARIANT: `nbits <= 56` here because we only enter
            // this branch when `nbits < n <= 32`, so adding 8 keeps
            // us within the 64-bit accumulator's capacity.
            let byte = self.pull_buf[self.pull_pos];
            self.pull_pos += 1;
            self.acc |= u64::from(byte) << self.nbits;
            self.nbits = self.nbits.saturating_add(8);
            self.bytes_into_acc = self.bytes_into_acc.saturating_add(1);
        }
        Ok(())
    }

    /// Pull more bytes from the source into the pull-buffer.
    /// Returns `Ok(true)` when at least one new byte was buffered,
    /// `Ok(false)` when the source signaled clean EOF without
    /// delivering any bytes (and is now dropped). Honors
    /// `Interrupted` per the [`Read`] contract.
    fn refill_pull_buf(&mut self) -> Result<bool, DeflateError> {
        // Reset the cursor — `pull_pos == pull_filled` guarantees the
        // buffer is fully drained at this entry point.
        self.pull_pos = 0;
        self.pull_filled = 0;
        let Some(source) = self.source.as_mut() else {
            return Ok(false);
        };
        loop {
            match source.read(&mut self.pull_buf) {
                Ok(0) => {
                    // Drop the source so future calls short-circuit
                    // and OS resources are released.
                    self.source = None;
                    return Ok(false);
                }
                Ok(n) => {
                    self.pull_filled = n;
                    return Ok(true);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(DeflateError::SourceIo(e)),
            }
        }
    }

    /// Read the next `n` bits without advancing the cursor.
    ///
    /// The least-significant bit of the returned value is the bit
    /// **closest to the start of the stream** (the LSB of the byte
    /// at `byte_position().0`, at offset `byte_position().1`).
    ///
    /// # Panics
    ///
    /// Debug-asserts `n <= MAX_BITS_PER_READ` and `nbits >= n`.
    /// Callers must call [`Self::ensure`] (or [`Self::read_bits`])
    /// before peeking; the typical Huffman-decode pattern is
    /// `ensure(MAX_HUFFMAN_BITS); peek_bits(MAX_HUFFMAN_BITS); consume_bits(actual_code_len)`.
    #[must_use]
    pub fn peek_bits(&self, n: u32) -> u32 {
        debug_assert!(n <= MAX_BITS_PER_READ);
        debug_assert!(
            self.nbits >= n,
            "BitReader::peek_bits({n}) called with only {} bits buffered — caller must ensure first",
            self.nbits,
        );
        let mask = if n == 32 { u32::MAX } else { (1u32 << n) - 1 };
        (self.acc as u32) & mask
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
        self.acc >>= n;
        self.nbits -= n;
    }

    /// Read the next `n` bits and advance the cursor — the
    /// fallible `ensure + peek + consume` composition.
    ///
    /// Returns the bits as a `u32` with the same bit ordering as
    /// [`Self::peek_bits`]: LSB closest to the start of the stream.
    ///
    /// # Errors
    ///
    /// Forwards any error from [`Self::ensure`].
    pub fn read_bits(&mut self, n: u32) -> Result<u32, DeflateError> {
        self.ensure(n)?;
        let v = self.peek_bits(n);
        self.consume_bits(n);
        Ok(v)
    }

    /// Discard the remaining `0..=7` bits of the byte the cursor is
    /// currently inside, so the next read starts on a byte boundary
    /// (RFC 1951 §3.2.4 stored-block alignment). Idempotent when
    /// already at a byte boundary.
    pub fn align_to_byte(&mut self) {
        let drop = self.nbits & 7;
        // INVARIANT: `drop` is in `0..=7`, so it cannot exceed
        // `nbits` and the masking shift below is well-defined.
        if drop != 0 {
            self.acc >>= drop;
            self.nbits -= drop;
        }
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
        // INVARIANT: `bytes_into_acc * 8 >= nbits` because every
        // shift adds 8 bits to the accumulator and consumed bits
        // are <= the total ever shifted in.
        let bits_consumed = self.bytes_into_acc.saturating_mul(8) - u64::from(self.nbits);
        let byte_index = bits_consumed / 8;
        // INVARIANT: `bits_consumed % 8 < 8`, fits in `u8`.
        let bit_off = (bits_consumed % 8) as u8;
        (byte_index, bit_off)
    }

    /// Number of bits currently buffered in the accumulator. Useful
    /// for tests asserting the reader's internal state and for the
    /// Phase 5 wiring's "are we at a clean byte boundary?" check
    /// (the canonical answer is `byte_position().1 == 0`, but
    /// callers that need to gate on "is the accumulator empty?"
    /// can read this directly).
    #[must_use]
    pub fn bits_buffered(&self) -> u32 {
        self.nbits
    }

    /// Read exactly `buf.len()` bytes into `buf`, requiring the bit
    /// cursor to already be byte-aligned (call [`Self::align_to_byte`]
    /// first). Drains the bit accumulator, then the pull-buffer,
    /// then issues `Read::read` calls until satisfied. Far faster
    /// than `read_bits(8)` per byte, used by the stored-block
    /// payload path in [`super::Decoder`].
    ///
    /// # Errors
    ///
    /// - [`DeflateError::UnexpectedEof`] when the source is
    ///   exhausted before `buf.len()` bytes have been delivered.
    /// - [`DeflateError::SourceIo`] for any other `Read::read`
    ///   failure (after honoring `Interrupted`).
    ///
    /// # Panics
    ///
    /// Debug-asserts the bit cursor is byte-aligned. Calling on a
    /// non-aligned cursor would silently corrupt the cursor's bit
    /// offset; the assertion catches the misuse early.
    pub fn read_aligned(&mut self, buf: &mut [u8]) -> Result<(), DeflateError> {
        debug_assert_eq!(
            self.byte_position().1,
            0,
            "BitReader::read_aligned: cursor must be byte-aligned (call align_to_byte first)",
        );
        let mut filled = 0;

        // Phase A: drain the bit accumulator. Aligned cursor →
        // accumulator holds whole bytes (`nbits` is a multiple of 8).
        while filled < buf.len() && self.nbits >= 8 {
            // INVARIANT: `acc & 0xFF` is in 0..=255, fits in `u8`.
            buf[filled] = (self.acc & 0xFF) as u8;
            self.acc >>= 8;
            self.nbits -= 8;
            filled += 1;
        }

        // Phase B: drain the pull-buffer in bulk. Bytes copied
        // directly bypass the accumulator entirely; cursor
        // accounting is preserved by advancing `bytes_into_acc` as
        // if the bytes had been shifted in then immediately
        // consumed (the `bits_consumed = bytes_into_acc * 8 -
        // nbits` formula stays correct).
        while filled < buf.len() && self.pull_pos < self.pull_filled {
            let n = (self.pull_filled - self.pull_pos).min(buf.len() - filled);
            buf[filled..filled + n]
                .copy_from_slice(&self.pull_buf[self.pull_pos..self.pull_pos + n]);
            self.pull_pos += n;
            // INVARIANT: `n <= pull_filled - pull_pos <=
            // PULL_BUF_LEN`, so `as u64` cannot truncate.
            self.bytes_into_acc = self.bytes_into_acc.saturating_add(n as u64);
            filled += n;
        }

        // Phase C: refill from the source until satisfied.
        while filled < buf.len() {
            if !self.refill_pull_buf()? {
                return Err(DeflateError::UnexpectedEof("aligned-byte read"));
            }
            let n = self.pull_filled.min(buf.len() - filled);
            buf[filled..filled + n].copy_from_slice(&self.pull_buf[..n]);
            self.pull_pos = n;
            self.bytes_into_acc = self.bytes_into_acc.saturating_add(n as u64);
            filled += n;
        }

        Ok(())
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
    fn read_bits_byte_at_a_time() {
        // 0x4B = 0b0100_1011 — LSB-first read order yields:
        //   bit 0: 1   bit 1: 1   bit 2: 0   bit 3: 1
        //   bit 4: 0   bit 5: 0   bit 6: 1   bit 7: 0
        let mut br = reader(vec![0x4Bu8]);
        for &expected in &[1u32, 1, 0, 1, 0, 0, 1, 0] {
            let bit = br.read_bits(1).expect("bit");
            assert_eq!(bit, expected);
        }
    }

    #[test]
    fn read_bits_groups_lsb_first_within_byte() {
        // 0x4B = 0b0100_1011 read as 3 bits at a time, then 2, then 3:
        //   bits 0..3 (low 3 bits) = 0b011 = 3
        //   bits 3..5             = 0b01  = 1
        //   bits 5..8 (high 3)    = 0b010 = 2
        let mut br = reader(vec![0x4B]);
        assert_eq!(br.read_bits(3).expect("3"), 0b011);
        assert_eq!(br.read_bits(2).expect("2"), 0b01);
        assert_eq!(br.read_bits(3).expect("3"), 0b010);
    }

    #[test]
    fn read_bits_spans_byte_boundary_lsb_first() {
        // 0xAB 0xCD = bytes [0xAB, 0xCD]. RFC 1951 §3.1.1: bytes are
        // written low-byte-first into the stream. So the bit cursor
        // walks 0xAB low-bit-first first, then 0xCD low-bit-first.
        // 0xAB = 0b1010_1011 (LSB-first: 1,1,0,1,0,1,0,1)
        // 0xCD = 0b1100_1101 (LSB-first: 1,0,1,1,0,0,1,1)
        // Reading 12 bits = bits 0..12 (low 12 of the 16-bit window):
        //   acc = 0xCD << 8 | 0xAB = 0xCDAB
        //   low 12 bits = 0xCDAB & 0xFFF = 0xDAB
        let mut br = reader(vec![0xAB, 0xCD]);
        assert_eq!(br.read_bits(12).expect("12"), 0xDAB);
        // Remaining 4 bits of the original 16-bit window are the
        // high nibble of 0xCD = 0xC.
        assert_eq!(br.read_bits(4).expect("4"), 0xC);
    }

    #[test]
    fn read_bits_can_read_full_32_bits() {
        let mut br = reader(vec![0x12, 0x34, 0x56, 0x78, 0x9A]);
        // 32 bits = first four bytes, low-byte-first:
        //   = (0x78 << 24) | (0x56 << 16) | (0x34 << 8) | 0x12
        //   = 0x7856_3412
        assert_eq!(br.read_bits(32).expect("32"), 0x7856_3412);
        // Fifth byte still readable.
        assert_eq!(br.read_bits(8).expect("8"), 0x9A);
    }

    #[test]
    fn peek_bits_does_not_advance_cursor() {
        let mut br = reader(vec![0xFF, 0x00]);
        br.ensure(8).expect("ensure 8");
        for _ in 0..3 {
            assert_eq!(br.peek_bits(8), 0xFF);
        }
        // Cursor still at byte 0, bit 0.
        assert_eq!(br.byte_position(), (0, 0));
        // After consuming, the next peek sees the second byte.
        br.consume_bits(8);
        br.ensure(8).expect("ensure 8 after consume");
        assert_eq!(br.peek_bits(8), 0x00);
    }

    #[test]
    fn peek_then_consume_partial_pattern_matches_huffman_decode_use() {
        // Simulate a Huffman decode: ensure 15 bits (the deflate
        // max-code-length), peek 15 bits to do a flat-table lookup,
        // discover the actual code is 5 bits long, consume 5 bits,
        // then proceed.
        let mut br = reader(vec![0xAB, 0xCD]);
        br.ensure(15).expect("ensure");
        let look = br.peek_bits(15);
        // Low 5 bits of the look-window are bits 0..5 of byte 0.
        let actual_code_len = 5u32;
        let actual_code = look & ((1u32 << actual_code_len) - 1);
        // 0xAB = 0b1010_1011, low 5 = 0b01011 = 11.
        assert_eq!(actual_code, 11);
        br.consume_bits(actual_code_len);
        // Cursor advanced by exactly 5 bits.
        assert_eq!(br.byte_position(), (0, 5));
    }

    #[test]
    fn align_to_byte_drops_zero_to_seven_bits() {
        let mut br = reader(vec![0x4B, 0x55]);
        // Consume 3 bits — cursor now at byte 0, bit 3.
        br.read_bits(3).expect("3");
        assert_eq!(br.byte_position(), (0, 3));
        // Align should drop the remaining 5 bits of byte 0.
        br.align_to_byte();
        assert_eq!(br.byte_position(), (1, 0));
        // Next read starts at byte 1, bit 0 = LSB of 0x55 = 1.
        assert_eq!(br.read_bits(1).expect("after align"), 1);
    }

    #[test]
    fn align_to_byte_is_noop_when_already_aligned() {
        let mut br = reader(vec![0x4B, 0x55]);
        br.read_bits(8).expect("byte");
        let before = br.byte_position();
        br.align_to_byte();
        let after = br.byte_position();
        assert_eq!(before, after);
        assert_eq!(after, (1, 0));
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
            Err(DeflateError::UnexpectedEof(label)) => {
                assert_eq!(label, "bit stream");
            }
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn unexpected_eof_when_source_empty_at_construction() {
        let mut br = reader(Vec::new());
        match br.read_bits(1) {
            Err(DeflateError::UnexpectedEof(_)) => {}
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn ensure_after_eof_keeps_reporting_eof_idempotently() {
        // Repeated calls after the source has signaled EOF must
        // continue surfacing UnexpectedEof rather than silently
        // returning success or panicking.
        let mut br = reader(vec![0xFF]);
        br.read_bits(8).expect("byte");
        for _ in 0..5 {
            match br.ensure(1) {
                Err(DeflateError::UnexpectedEof(_)) => {}
                other => panic!("expected UnexpectedEof, got {other:?}"),
            }
        }
    }

    #[test]
    fn source_io_error_propagates_as_typed_variant() {
        // A reader that returns a non-Interrupted IO error on the
        // first read must surface as `SourceIo`, preserving the
        // ErrorKind so the boundary translation in
        // `into_decode_error` stays accurate.
        struct FailingReader;
        impl Read for FailingReader {
            fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::new(io::ErrorKind::ConnectionAborted, "boom"))
            }
        }
        let mut br = BitReader::new(Box::new(FailingReader));
        match br.read_bits(1) {
            Err(DeflateError::SourceIo(e)) => {
                assert_eq!(e.kind(), io::ErrorKind::ConnectionAborted);
            }
            other => panic!("expected SourceIo, got {other:?}"),
        }
    }

    #[test]
    fn interrupted_reads_are_retried_transparently() {
        // A reader that fails Interrupted twice then yields a byte
        // must surface a successful read; the bit reader must not
        // expose the Interrupted to the caller.
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
    fn read_bits_zero_is_a_noop() {
        let mut br = reader(vec![0xFF]);
        let before = br.byte_position();
        let v = br.read_bits(0).expect("zero-bit read is allowed");
        assert_eq!(v, 0);
        assert_eq!(br.byte_position(), before);
        // A zero-bit read at EOF also succeeds (no bits required).
        let mut br = reader(Vec::new());
        assert_eq!(br.read_bits(0).expect("zero-bit at EOF"), 0);
    }

    #[test]
    fn bits_buffered_reflects_internal_state() {
        let mut br = reader(vec![0x00, 0x00]);
        assert_eq!(br.bits_buffered(), 0);
        br.ensure(3).expect("ensure 3");
        // After ensure(3) we shift one full byte in (8 bits buffered).
        assert_eq!(br.bits_buffered(), 8);
        br.consume_bits(3);
        assert_eq!(br.bits_buffered(), 5);
        br.ensure(9).expect("ensure 9");
        // Ensure pulls one more byte (5 + 8 = 13 buffered).
        assert_eq!(br.bits_buffered(), 13);
    }

    #[test]
    fn cursor_advances_predictably_across_pull_buffer_refill() {
        // Build a stream longer than `PULL_BUF_LEN` so the bit
        // reader has to refill at least once. Confirm
        // `byte_position` stays accurate across the refill.
        let len = PULL_BUF_LEN + 256;
        let bytes: Vec<u8> = (0..len).map(|i| (i & 0xFF) as u8).collect();
        let mut br = reader(bytes.clone());
        for (i, &expected) in bytes.iter().enumerate() {
            let read = br.read_bits(8).expect("byte") as u8;
            assert_eq!(read, expected);
            assert_eq!(br.byte_position(), ((i as u64) + 1, 0));
        }
        // One more bit past the end is a clean UnexpectedEof.
        match br.read_bits(1) {
            Err(DeflateError::UnexpectedEof(_)) => {}
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn ensure_does_not_overshift_beyond_capacity() {
        // After ensure(32), nbits must be in 32..=64; specifically
        // we never shift in more bytes than fit.
        let mut br = reader(vec![0xAA; 16]);
        br.ensure(32).expect("ensure 32");
        assert!(br.bits_buffered() >= 32);
        assert!(br.bits_buffered() <= 64);
    }

    #[test]
    fn align_to_byte_does_not_affect_byte_position_when_aligned() {
        let mut br = reader(vec![0xFF, 0xFF]);
        br.read_bits(8).expect("byte");
        let before = br.byte_position();
        for _ in 0..3 {
            br.align_to_byte();
            assert_eq!(br.byte_position(), before);
        }
    }

    #[test]
    fn read_aligned_drains_accumulator_then_pull_buffer_then_source() {
        // Stream is large enough to span all three phases of the
        // read_aligned implementation: accumulator drain (after
        // ensure(8) shifts a byte in), pull-buffer drain, and
        // source-side refill (PULL_BUF_LEN forces a refill).
        let len = PULL_BUF_LEN + 256;
        let bytes: Vec<u8> = (0..len).map(|i| (i & 0xFF) as u8).collect();
        let mut br = reader(bytes.clone());
        // Force one byte into the accumulator first.
        br.ensure(1).expect("ensure 1 to seed accumulator");
        assert!(br.bits_buffered() >= 8);
        // We're still byte-aligned (no bits consumed yet).
        assert_eq!(br.byte_position(), (0, 0));
        // Read every byte; the cursor should march byte-by-byte.
        let mut out = vec![0u8; len];
        br.read_aligned(&mut out).expect("read_aligned");
        assert_eq!(out, bytes);
        assert_eq!(br.byte_position(), (len as u64, 0));
    }

    #[test]
    fn read_aligned_short_buffer_round_trips() {
        let bytes = b"hello".to_vec();
        let mut br = reader(bytes.clone());
        let mut out = [0u8; 5];
        br.read_aligned(&mut out).expect("aligned");
        assert_eq!(&out, b"hello");
        assert_eq!(br.byte_position(), (5, 0));
    }

    #[test]
    fn read_aligned_after_some_bit_reads_picks_up_at_byte_boundary() {
        // Read the first byte's worth of bits, align (no-op since
        // already aligned), then read the next 4 bytes via
        // read_aligned.
        let bytes = vec![0xAA, 0x01, 0x02, 0x03, 0x04];
        let mut br = reader(bytes);
        br.read_bits(8).expect("byte 0");
        let mut out = [0u8; 4];
        br.read_aligned(&mut out).expect("aligned 4");
        assert_eq!(&out, &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(br.byte_position(), (5, 0));
    }

    #[test]
    fn read_aligned_after_partial_bit_consumption_realigns_via_align_to_byte() {
        // Reader consumed 3 bits; align_to_byte drops the rest of
        // the byte; read_aligned starts from byte 1.
        let bytes = vec![0x00, 0xAB, 0xCD, 0xEF];
        let mut br = reader(bytes);
        br.read_bits(3).expect("3 bits");
        br.align_to_byte();
        let mut out = [0u8; 3];
        br.read_aligned(&mut out).expect("aligned");
        assert_eq!(&out, &[0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn read_aligned_truncated_source_surfaces_unexpected_eof() {
        let bytes = vec![0x01, 0x02];
        let mut br = reader(bytes);
        let mut out = [0u8; 4];
        match br.read_aligned(&mut out) {
            Err(DeflateError::UnexpectedEof(label)) => {
                assert_eq!(label, "aligned-byte read");
            }
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }

    #[test]
    fn read_aligned_empty_buffer_is_a_noop() {
        let mut br = reader(vec![0x42]);
        let before = br.byte_position();
        br.read_aligned(&mut []).expect("empty");
        assert_eq!(br.byte_position(), before);
    }

    #[test]
    fn cursor_floor_under_partial_byte_consumption_lags_by_one_byte() {
        // The `bytes_consumed` floor convention: the byte the bit
        // cursor is fractionally inside is NOT counted as fully
        // consumed. This pins that contract: after reading 11 bits
        // (8 + 3), `byte_position()` must report (1, 3), meaning
        // the puncher can release byte 0 but must keep byte 1.
        let mut br = reader(vec![0xAA, 0xBB, 0xCC]);
        br.read_bits(11).expect("11");
        assert_eq!(br.byte_position(), (1, 3));
    }
}
