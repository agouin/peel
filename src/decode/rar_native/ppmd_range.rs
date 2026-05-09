//! PPMd-II range decoder ("Ppmd7z" arithmetic coder).
//!
//! RAR5 uses Igor Pavlov's PPMd-II (also known as PPMd7) for the
//! `-ma5 -m5` opt-in alternate compression mode. PPMd-II is an
//! order-N context-mixing predictor on top of a range arithmetic
//! coder; this module implements the bottom layer (the range
//! coder) independent of the model state. Subsequent sub-phases
//! of `docs/PLAN_rar5_decoder.md` §D1 build the suballocator,
//! context tree, and symbol decoder on top.
//!
//! The "z" variant ([`RangeDecoder::init`]) reads 5 bytes:
//! a `0x00` sentinel followed by 4 raw bytes that prime `code`.
//! The sentinel guards against feeding non-PPMd-II data to the
//! decoder — the matching encoder's first emitted byte is always
//! `0x00` because `cache` is initialised to `0` and no carry can
//! occur before the first `Encode` call. Constants and
//! operations match libarchive's bundled `archive_ppmd7.c` (Igor
//! Pavlov, BSD-3) which RAR5's PPM handler in
//! `archive_read_support_format_rar5.c` (Grzegorz Antoniak,
//! BSD 2-Clause) drives directly. See [`NOTICE`](../../../NOTICE)
//! at the repo root for the attribution chain.
//!
//! # Range coder model
//!
//! Carries two 32-bit state words:
//!
//! - **`range`** — width of the current arithmetic interval
//!   (`0 < range ≤ 0xFFFF_FFFF`).
//! - **`code`** — encoded value's offset within the interval
//!   (`0 ≤ code < range`).
//!
//! Each decoded symbol shrinks `range` to `range * size / total`,
//! advances `code` by the decoded symbol's start fraction, then
//! "normalizes": while `range < `[`KTOP`] (`= 1 << 24`), shift
//! both left by 8 bits and refill `code`'s low byte from the byte
//! source.
//!
//! ```text
//!   pre-decode    range               code in [0, range)
//!   --------------|-------------------|---------------------|
//!                 0          start_freq * range_unit       range
//!                            ^-- code lands here for symbol s
//!
//!   post-decode   range *= size       code -= start * range_unit
//!   --------------|---------|
//!                 0       new_range
//!
//!   normalize     range << 8          code = (code << 8) | next_byte
//! ```
//!
//! # Two decoding paths
//!
//! - **Frequency-table decoding** (`get_threshold` + `decode`).
//!   The model presents a sorted list of cumulative frequencies
//!   summing to `total`. The caller asks the decoder for a
//!   threshold in `[0, total)`, scans its table to find the
//!   matching slot, and tells the decoder the slot's `(start,
//!   size)`. PPM context arithmetic uses this path.
//!
//! - **Single-bit decoding** (`decode_bit`). For binary contexts
//!   PPMd uses a 14-bit fixed-point predictor: the caller passes
//!   `size0 ∈ [0, K_BIT_MODEL_TOTAL]` (the predicted "weight" of
//!   the 0 bit out of `1 << 14`) and the decoder returns the
//!   single-bit value. Avoids the divisions of the
//!   frequency-table path.
//!
//! Both paths normalize after they shrink `range`.
//!
//! # Truncation tolerance
//!
//! libarchive's `archive_ppmd7.c` reads bytes through an
//! `IByteIn` callback that returns `0` past end of stream rather
//! than erroring; the model's natural termination (the encoder
//! writes a sentinel symbol) means a well-formed PPM block never
//! reads past the last real byte. We follow that convention:
//! [`ByteIn::read`] returns `0` after the slice is exhausted and
//! sets the latched [`ByteIn::was_truncated`] flag. Upper layers
//! that suspect a malformed archive can call `was_truncated()`
//! after decoding and surface it as a parse error; CRC-based
//! validation downstream catches the rest.
//!
//! # Normalization bound
//!
//! [`RangeDecoder::normalize`] caps the byte-shift loop at
//! [`MAX_NORMALIZE_SHIFTS`] iterations. A well-formed range coder
//! state needs at most 3 shifts to bring `range` back above
//! [`KTOP`]; capping at 4 deadlock-proofs the decoder against
//! malformed model arguments (e.g. `decode(0, 0)` would set
//! `range` to `0` and infinite-loop without the bound). Hitting
//! the cap leaves the decoder in an unrecoverable state but the
//! upper layer's CRC check fires before the garbage propagates.

use thiserror::Error;

/// Threshold the range coder normalizes against. Whenever
/// `range < KTOP`, both `range` and `code` shift left by 8 bits
/// and a new byte is appended to `code`'s low byte.
/// `KTOP = 1 << 24 = 0x0100_0000`.
pub const KTOP: u32 = 1 << 24;

/// Bit-precision of [`RangeDecoder::decode_bit`]'s `size0`
/// predictor. Equal to 14, matching libarchive's
/// `kBitModelTotalBits` (`archive_ppmd7.c`).
pub const K_BIT_MODEL_TOTAL_BITS: u32 = 14;

/// Total used by [`RangeDecoder::decode_bit`]'s `size0`
/// predictor: `1 << K_BIT_MODEL_TOTAL_BITS` = 16384.
pub const K_BIT_MODEL_TOTAL: u32 = 1 << K_BIT_MODEL_TOTAL_BITS;

/// Upper bound on the byte-shift normalization loop. A
/// well-formed range coder needs at most 3 shifts; 4 deadlock-
/// proofs the decoder against malformed model arguments.
pub const MAX_NORMALIZE_SHIFTS: u32 = 4;

/// Errors surfaced by [`RangeDecoder::init`] when the upper layer
/// wants to reject malformed PPM block headers before decoding
/// starts. Decode-time errors travel through
/// [`ByteIn::was_truncated`] instead — the inner methods follow
/// libarchive's "return 0 past end" convention so the model
/// layer can decide whether silent truncation is fatal or
/// merely indicative of a clean encoder termination.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RangeInitError {
    /// The byte source held fewer than [`INIT_BYTES`] bytes when
    /// [`RangeDecoder::init`] tried to prime `code`.
    #[error("PPMd range decoder init needs {needed} bytes; source had {available}")]
    Truncated {
        /// Bytes the init step needed (always [`INIT_BYTES`]).
        needed: usize,
        /// Number of bytes actually available
        /// (`0..=INIT_BYTES - 1`).
        available: usize,
    },
    /// libarchive's `Ppmd7z_RangeDec_Init` requires the very
    /// first wire byte to be `0`. The encoder's `cache` field
    /// initializes to `0` and the first emitted byte is always
    /// `cache + carry = 0`, so any other value flags a malformed
    /// stream (or a non-Ppmd7z encoder).
    #[error("PPMd range decoder init: leading sentinel byte was {got:#04x}, expected 0x00")]
    LeadingByteNotZero {
        /// The non-zero byte the source produced.
        got: u8,
    },
    /// libarchive rejects a primed `code = 0xFFFF_FFFF` because
    /// it cannot represent a value strictly less than `range =
    /// 0xFFFF_FFFF`. Hitting this path implies a corrupt stream.
    #[error("PPMd range decoder init: code 0xFFFFFFFF >= range, refusing to decode")]
    CodeOutOfRange,
}

/// Number of bytes [`RangeDecoder::init`] consumes from the byte
/// source: a 1-byte sentinel (must be `0x00`) followed by 4 raw
/// bytes that prime `code`. Matches libarchive's
/// `Ppmd7z_RangeDec_Init`.
pub const INIT_BYTES: usize = 5;

/// Byte source the [`RangeDecoder`] reads from. Wraps a borrowed
/// byte slice with read-past-end semantics matching libarchive's
/// `archive_ppmd7.c` `IByteIn`: returns `0` for every byte past
/// the end of the slice and sets [`Self::was_truncated`].
#[derive(Debug)]
pub struct ByteIn<'a> {
    data: &'a [u8],
    pos: usize,
    truncated: bool,
}

impl<'a> ByteIn<'a> {
    /// Construct a fresh source over `data`. No bytes are read
    /// until [`Self::read`] is called.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            truncated: false,
        }
    }

    /// Read the next byte. Returns `0` past end of slice and
    /// latches [`Self::was_truncated`] to `true`.
    pub fn read(&mut self) -> u8 {
        if let Some(&b) = self.data.get(self.pos) {
            self.pos += 1;
            b
        } else {
            self.truncated = true;
            0
        }
    }

    /// Number of bytes consumed (capped at the slice length —
    /// past-end reads do not advance the cursor).
    #[must_use]
    pub fn bytes_consumed(&self) -> usize {
        self.pos
    }

    /// Number of bytes still available before truncation kicks
    /// in. `0` once the source is exhausted.
    #[must_use]
    pub fn bytes_remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Total length of the underlying slice. Useful for the
    /// upper layer's diagnostic bookkeeping.
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// `true` if the underlying slice is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// `true` if any [`Self::read`] call returned a synthetic
    /// `0` because the slice was exhausted. Latched: stays
    /// `true` once observed.
    #[must_use]
    pub fn was_truncated(&self) -> bool {
        self.truncated
    }
}

/// PPMd-II range decoder ("Ppmd7z" variant).
///
/// Construct with [`Self::new`], prime with [`Self::init`]
/// (reads [`INIT_BYTES`] bytes from the source: a `0x00` sentinel
/// plus 4 bytes for `code`), then alternate between
/// [`Self::get_threshold`] / [`Self::decode`] and
/// [`Self::decode_bit`] as the model directs. State is just
/// `(range, code)` — the encoder's `low` field has no decode
/// counterpart.
#[derive(Debug, Clone, Copy)]
pub struct RangeDecoder {
    /// Current arithmetic interval width.
    pub range: u32,
    /// Encoded value's offset within the interval.
    pub code: u32,
}

impl Default for RangeDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl RangeDecoder {
    /// Construct a fresh decoder. All decoding methods are
    /// undefined until [`Self::init`] runs; the placeholder
    /// state sets `range` to its post-init value (`0xFFFF_FFFF`)
    /// so a uninitialized-use bug doesn't divide by zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            range: 0xFFFF_FFFF,
            code: 0,
        }
    }

    /// Prime the decoder by reading [`INIT_BYTES`] bytes from
    /// `src`. The first byte is a `0x00` sentinel — libarchive's
    /// `Ppmd7z_RangeDec_Init` rejects any other value because the
    /// matching encoder's first emitted byte (`cache + carry`
    /// with cache initialised to `0` and no carry possible
    /// before the first encode call) is always `0`. The remaining
    /// 4 bytes are read big-endian into `code`. `range` is set to
    /// `0xFFFF_FFFF`.
    ///
    /// # Errors
    ///
    /// - [`RangeInitError::Truncated`] if `src` has fewer than
    ///   [`INIT_BYTES`] bytes available.
    /// - [`RangeInitError::LeadingByteNotZero`] if the sentinel
    ///   byte is non-zero.
    /// - [`RangeInitError::CodeOutOfRange`] if the primed code
    ///   equals `0xFFFF_FFFF` (which would violate the
    ///   `code < range` invariant).
    ///
    /// On any error the decoder's state is reset to the default
    /// `(0xFFFF_FFFF, 0)` position and `src` is left at the
    /// position it had reached when the error fired.
    pub fn init(&mut self, src: &mut ByteIn<'_>) -> Result<(), RangeInitError> {
        let available = src.bytes_remaining();
        if available < INIT_BYTES {
            // Reset to default so the decoder isn't left half-primed.
            self.range = 0xFFFF_FFFF;
            self.code = 0;
            return Err(RangeInitError::Truncated {
                needed: INIT_BYTES,
                available,
            });
        }
        let sentinel = src.read();
        if sentinel != 0 {
            self.range = 0xFFFF_FFFF;
            self.code = 0;
            return Err(RangeInitError::LeadingByteNotZero { got: sentinel });
        }
        self.range = 0xFFFF_FFFF;
        self.code = 0;
        for _ in 0..4 {
            self.code = (self.code << 8) | u32::from(src.read());
        }
        if self.code == 0xFFFF_FFFF {
            // Caller's invariant violated — reset state for
            // diagnostic clarity.
            self.code = 0;
            return Err(RangeInitError::CodeOutOfRange);
        }
        Ok(())
    }

    /// Get the encoded value's threshold within `[0, total)`.
    ///
    /// **Side-effect**: divides `range` by `total` and stores
    /// the quotient back into `range`. The caller must follow up
    /// with [`Self::decode`] to confirm the symbol's `(start,
    /// size)` and re-normalize. libarchive's
    /// `Range_GetThreshold`.
    ///
    /// # Panics
    ///
    /// Debug-asserts `total > 0`. The model layer is responsible
    /// for never passing `total = 0`; in release builds a zero
    /// would divide-by-zero panic.
    pub fn get_threshold(&mut self, total: u32) -> u32 {
        debug_assert!(total > 0, "PPMd range threshold total must be > 0");
        self.range /= total;
        self.code / self.range
    }

    /// Confirm the decoded symbol's `(start, size)` and
    /// normalize. Must follow a [`Self::get_threshold`] call.
    /// libarchive's `Range_Decode`.
    ///
    /// `start` is the cumulative frequency at the symbol's
    /// lower edge and `size` is the symbol's width. Both are in
    /// units of the `total` passed to the preceding
    /// `get_threshold` call.
    pub fn decode(&mut self, src: &mut ByteIn<'_>, start: u32, size: u32) {
        // `start * range` cannot exceed u32 if the caller
        // honored the model's invariants (`start + size ≤
        // total` and `range = old_range / total` after
        // get_threshold). We use wrapping arithmetic anyway so
        // a malformed model can't panic in release.
        self.code = self.code.wrapping_sub(start.wrapping_mul(self.range));
        self.range = self.range.wrapping_mul(size);
        self.normalize(src);
    }

    /// Decode a single bit with the predictor `size0 ∈ [0,
    /// K_BIT_MODEL_TOTAL]`. Returns `0` if the encoded bit was
    /// `0`, else `1`. Mirrors libarchive's `Range_DecodeBit`.
    ///
    /// # Panics
    ///
    /// Debug-asserts `size0 ≤ K_BIT_MODEL_TOTAL`. Out-of-range
    /// values produce nonsense `(code, range)` state without a
    /// panic in release builds, but the model layer should not
    /// emit them.
    pub fn decode_bit(&mut self, src: &mut ByteIn<'_>, size0: u32) -> u32 {
        debug_assert!(
            size0 <= K_BIT_MODEL_TOTAL,
            "PPMd decode_bit size0 = {size0} exceeds K_BIT_MODEL_TOTAL"
        );
        let new_bound = (self.range >> K_BIT_MODEL_TOTAL_BITS).wrapping_mul(size0);
        let bit = if self.code < new_bound {
            self.range = new_bound;
            0
        } else {
            self.code = self.code.wrapping_sub(new_bound);
            self.range = self.range.wrapping_sub(new_bound);
            1
        };
        self.normalize(src);
        bit
    }

    /// Run the byte-shift normalization loop: while
    /// `range < `[`KTOP`], shift both `range` and `code` left by
    /// 8 bits and refill `code`'s low byte from `src`. Capped at
    /// [`MAX_NORMALIZE_SHIFTS`] iterations to deadlock-proof the
    /// decoder against malformed model state (`range = 0`).
    fn normalize(&mut self, src: &mut ByteIn<'_>) {
        let mut iters = 0;
        while self.range < KTOP && iters < MAX_NORMALIZE_SHIFTS {
            self.range <<= 8;
            self.code = (self.code << 8) | u32::from(src.read());
            iters += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-rolled PPMd7z range *encoder* used to produce test
    /// vectors. Mirrors the inverse of [`RangeDecoder`]: every
    /// `encode` / `encode_bit` call emits the wire bytes the
    /// matching decoder method needs to reproduce the input.
    /// Layout matches 7-Zip's `CPpmd7z_RangeEnc` (Igor Pavlov,
    /// BSD-3); `flush` mirrors `Ppmd7z_RangeEnc_FlushData`.
    struct RangeEncoder {
        low: u64,
        range: u32,
        cache_size: u32,
        cache: u8,
        out: Vec<u8>,
    }

    impl RangeEncoder {
        fn new() -> Self {
            Self {
                low: 0,
                range: 0xFFFF_FFFF,
                cache_size: 1,
                cache: 0,
                out: Vec::new(),
            }
        }

        /// 7-Zip's `RangeEnc_ShiftLow` — emits buffered bytes
        /// when the high byte of `low` is no longer ambiguous.
        fn shift_low(&mut self) {
            // Flush condition: either the high byte of `low` is
            // not 0xFF (so future increments to `low` cannot
            // affect already-emitted bytes), or a carry has
            // overflowed bit 32 (so the buffered 0xFF run plus
            // the carry can be emitted).
            if self.low < 0xFF00_0000_u64 || (self.low >> 32) != 0 {
                let mut temp = self.cache;
                let carry = (self.low >> 32) as u8;
                loop {
                    self.out.push(temp.wrapping_add(carry));
                    temp = 0xFF;
                    self.cache_size -= 1;
                    if self.cache_size == 0 {
                        break;
                    }
                }
                self.cache = (self.low >> 24) as u8;
            }
            self.cache_size += 1;
            self.low = (self.low << 8) & 0xFFFF_FFFF;
        }

        /// Inverse of [`RangeDecoder::decode`]. Pushes wire
        /// bytes into the output buffer once `range` shrinks
        /// past [`KTOP`].
        fn encode(&mut self, start: u32, size: u32, total: u32) {
            self.range /= total;
            self.low += u64::from(start) * u64::from(self.range);
            self.range *= size;
            while self.range < KTOP {
                self.range <<= 8;
                self.shift_low();
            }
        }

        /// Inverse of [`RangeDecoder::decode_bit`].
        fn encode_bit(&mut self, size0: u32, symbol: u32) {
            let new_bound = (self.range >> K_BIT_MODEL_TOTAL_BITS) * size0;
            if symbol == 0 {
                self.range = new_bound;
            } else {
                self.low += u64::from(new_bound);
                self.range -= new_bound;
            }
            while self.range < KTOP {
                self.range <<= 8;
                self.shift_low();
            }
        }

        /// Drain the encoder. 7-Zip's `RangeEnc_FlushData` —
        /// 5 trailing `shift_low` calls flush the cached byte
        /// and the `low` accumulator.
        fn flush(mut self) -> Vec<u8> {
            for _ in 0..5 {
                self.shift_low();
            }
            self.out
        }
    }

    #[test]
    fn byte_in_reads_then_truncates() {
        let mut src = ByteIn::new(&[0x12, 0x34]);
        assert_eq!(src.read(), 0x12);
        assert_eq!(src.read(), 0x34);
        assert!(!src.was_truncated());
        assert_eq!(src.bytes_consumed(), 2);
        assert_eq!(src.bytes_remaining(), 0);
        assert_eq!(src.read(), 0); // synthetic zero past end
        assert!(src.was_truncated());
        assert_eq!(src.bytes_consumed(), 2); // not advanced
        assert_eq!(src.read(), 0); // still zero, latched
        assert!(src.was_truncated());
    }

    #[test]
    fn byte_in_empty_slice_truncates_immediately() {
        let mut src = ByteIn::new(&[]);
        assert!(src.is_empty());
        assert_eq!(src.len(), 0);
        assert_eq!(src.read(), 0);
        assert!(src.was_truncated());
    }

    #[test]
    fn init_consumes_sentinel_plus_4_bytes_big_endian() {
        // Sentinel `0x00`, then 4 prime bytes, then a trailing
        // `0x99` we don't expect init to touch.
        let mut src = ByteIn::new(&[0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x99]);
        let mut rd = RangeDecoder::new();
        rd.init(&mut src).expect("INIT_BYTES bytes available");
        assert_eq!(rd.range, 0xFFFF_FFFF);
        assert_eq!(rd.code, 0xDEAD_BEEF);
        assert_eq!(src.bytes_consumed(), INIT_BYTES);
        assert!(!src.was_truncated());
    }

    #[test]
    fn init_rejects_short_source() {
        // 4 bytes is one short of INIT_BYTES; init must reject
        // before consuming anything.
        let mut src = ByteIn::new(&[0x00, 0x01, 0x02, 0x03]);
        let mut rd = RangeDecoder::new();
        let err = rd.init(&mut src).unwrap_err();
        assert_eq!(
            err,
            RangeInitError::Truncated {
                needed: INIT_BYTES,
                available: 4
            }
        );
        // Source untouched on rejection.
        assert_eq!(src.bytes_consumed(), 0);
        assert!(!src.was_truncated());
        // Decoder reset to default so a retry with a fresher
        // source works.
        assert_eq!(rd.range, 0xFFFF_FFFF);
        assert_eq!(rd.code, 0);
    }

    #[test]
    fn init_rejects_nonzero_sentinel() {
        // First byte must be 0x00; libarchive's
        // Ppmd7z_RangeDec_Init rejects anything else.
        let mut src = ByteIn::new(&[0x01, 0xDE, 0xAD, 0xBE, 0xEF]);
        let mut rd = RangeDecoder::new();
        let err = rd.init(&mut src).unwrap_err();
        assert_eq!(err, RangeInitError::LeadingByteNotZero { got: 0x01 });
        // Decoder state reset so a follow-up init works.
        assert_eq!(rd.range, 0xFFFF_FFFF);
        assert_eq!(rd.code, 0);
    }

    #[test]
    fn init_rejects_code_overflow() {
        // Sentinel zero followed by 0xFF * 4 → primed code
        // would equal 0xFFFF_FFFF, violating `code < range`.
        let mut src = ByteIn::new(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF]);
        let mut rd = RangeDecoder::new();
        let err = rd.init(&mut src).unwrap_err();
        assert_eq!(err, RangeInitError::CodeOutOfRange);
        // Decoder state reset.
        assert_eq!(rd.range, 0xFFFF_FFFF);
        assert_eq!(rd.code, 0);
    }

    /// Round-trip a sequence of bytes through the encoder and
    /// decoder using a uniform 256-symbol frequency table
    /// (every byte has start=byte, size=1, total=256).
    #[test]
    fn round_trip_uniform_byte_alphabet() {
        let payload: &[u8] = b"PPMd-II range coder round-trip!";
        let mut enc = RangeEncoder::new();
        for &b in payload {
            enc.encode(u32::from(b), 1, 256);
        }
        let wire = enc.flush();

        let mut src = ByteIn::new(&wire);
        let mut rd = RangeDecoder::new();
        rd.init(&mut src)
            .expect("encoder flush emits ≥ INIT_BYTES bytes");
        let mut decoded = Vec::with_capacity(payload.len());
        for _ in 0..payload.len() {
            let threshold = rd.get_threshold(256);
            // Uniform 256-symbol table: threshold IS the symbol.
            assert!(threshold < 256);
            let symbol = threshold as u8;
            decoded.push(symbol);
            rd.decode(&mut src, u32::from(symbol), 1);
        }
        assert_eq!(decoded.as_slice(), payload);
    }

    /// Round-trip a sequence of binary bits through
    /// `decode_bit` with a fixed mid-range predictor.
    #[test]
    fn round_trip_binary_bits_uniform_predictor() {
        let bits = [0u32, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 1];
        let size0 = K_BIT_MODEL_TOTAL / 2; // unbiased predictor
        let mut enc = RangeEncoder::new();
        for &b in &bits {
            enc.encode_bit(size0, b);
        }
        let wire = enc.flush();

        let mut src = ByteIn::new(&wire);
        let mut rd = RangeDecoder::new();
        rd.init(&mut src)
            .expect("encoder flush emits ≥ INIT_BYTES bytes");
        for &expected in &bits {
            assert_eq!(rd.decode_bit(&mut src, size0), expected);
        }
    }

    /// Heavily biased predictor: every bit predicted 0 with
    /// probability ~0.99. The encoder still emits 5 flush bytes
    /// and the decoder still reproduces the bit stream
    /// faithfully.
    #[test]
    fn round_trip_binary_bits_biased_predictor() {
        let bits = [0u32, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let size0 = K_BIT_MODEL_TOTAL - K_BIT_MODEL_TOTAL / 100;
        let mut enc = RangeEncoder::new();
        for &b in &bits {
            enc.encode_bit(size0, b);
        }
        let wire = enc.flush();

        let mut src = ByteIn::new(&wire);
        let mut rd = RangeDecoder::new();
        rd.init(&mut src)
            .expect("encoder flush emits ≥ INIT_BYTES bytes");
        for &expected in &bits {
            assert_eq!(rd.decode_bit(&mut src, size0), expected);
        }
    }

    /// Mixed traffic: alternate frequency-table symbols and
    /// binary bits, the way the PPM model layer will once §D1.b
    /// lands.
    #[test]
    fn round_trip_mixed_freq_and_bit() {
        // (freq, bit, freq, bit, ...) over a 16-symbol alphabet
        // with uniform freqs.
        let symbols: [u32; 6] = [3, 14, 0, 9, 7, 1];
        let bits = [1u32, 0, 1, 1, 0, 0];
        let size0 = K_BIT_MODEL_TOTAL / 4; // ~25 % zero bias

        let mut enc = RangeEncoder::new();
        for i in 0..symbols.len() {
            enc.encode(symbols[i], 1, 16);
            enc.encode_bit(size0, bits[i]);
        }
        let wire = enc.flush();

        let mut src = ByteIn::new(&wire);
        let mut rd = RangeDecoder::new();
        rd.init(&mut src)
            .expect("encoder flush emits ≥ INIT_BYTES bytes");
        for i in 0..symbols.len() {
            let threshold = rd.get_threshold(16);
            assert_eq!(threshold, symbols[i]);
            rd.decode(&mut src, threshold, 1);
            assert_eq!(rd.decode_bit(&mut src, size0), bits[i]);
        }
    }

    /// `get_threshold` returns values strictly below `total`.
    /// Cross-check across a few `(range, code, total)` triples
    /// the encoder is likely to produce.
    #[test]
    fn get_threshold_is_in_bounds() {
        for total in [2u32, 7, 16, 256, 1023, 65536] {
            // Exercise via a single-symbol round-trip: encode
            // symbol 0 with size 1 / total, the threshold must
            // be 0.
            let mut enc = RangeEncoder::new();
            enc.encode(0, 1, total);
            let wire = enc.flush();
            let mut src = ByteIn::new(&wire);
            let mut rd = RangeDecoder::new();
            rd.init(&mut src).unwrap();
            let t = rd.get_threshold(total);
            assert!(t < total, "threshold {t} not < total {total}");
            assert_eq!(t, 0);
        }
    }

    /// Truncated wire data: the decoder still produces *some*
    /// answer (the model layer's CRC check fires downstream),
    /// and `was_truncated()` flips on so callers can react.
    #[test]
    fn truncated_wire_flips_was_truncated() {
        let payload: &[u8] = b"truncated!";
        let mut enc = RangeEncoder::new();
        for &b in payload {
            enc.encode(u32::from(b), 1, 256);
        }
        let mut wire = enc.flush();
        // Drop everything past the init prime — every
        // subsequent normalize-driven read becomes a synthetic
        // 0.
        wire.truncate(INIT_BYTES);

        let mut src = ByteIn::new(&wire);
        let mut rd = RangeDecoder::new();
        rd.init(&mut src).expect("INIT_BYTES bytes still available");
        assert!(!src.was_truncated());
        // Force at least one normalize cycle so the source goes
        // dry mid-decode.
        let _ = rd.get_threshold(256);
        rd.decode(&mut src, 0, 1);
        assert!(src.was_truncated());
    }

    /// `init` with an empty source rejects without touching
    /// decoder state; the source itself stays unread.
    #[test]
    fn init_with_empty_source_rejects() {
        let mut src = ByteIn::new(&[]);
        let mut rd = RangeDecoder::new();
        let err = rd.init(&mut src).unwrap_err();
        assert_eq!(
            err,
            RangeInitError::Truncated {
                needed: INIT_BYTES,
                available: 0
            }
        );
        assert!(!src.was_truncated());
    }

    /// Sanity-check: `decode_bit(K_BIT_MODEL_TOTAL)` against a
    /// stream that always emits 0 (the encoder's biased path)
    /// reads no extra bytes during normalization for the first
    /// few decodes. Confirms `new_bound = range` short-circuits
    /// the bit-1 branch entirely.
    #[test]
    fn decode_bit_max_size0_picks_zero() {
        let mut enc = RangeEncoder::new();
        enc.encode_bit(K_BIT_MODEL_TOTAL - 1, 0);
        enc.encode_bit(K_BIT_MODEL_TOTAL - 1, 0);
        enc.encode_bit(K_BIT_MODEL_TOTAL - 1, 0);
        let wire = enc.flush();

        let mut src = ByteIn::new(&wire);
        let mut rd = RangeDecoder::new();
        rd.init(&mut src).unwrap();
        assert_eq!(rd.decode_bit(&mut src, K_BIT_MODEL_TOTAL - 1), 0);
        assert_eq!(rd.decode_bit(&mut src, K_BIT_MODEL_TOTAL - 1), 0);
        assert_eq!(rd.decode_bit(&mut src, K_BIT_MODEL_TOTAL - 1), 0);
    }

    /// Default constructor leaves the decoder in a state where
    /// a follow-up `init` call works without manual reset.
    #[test]
    fn default_then_init_round_trips() {
        let mut enc = RangeEncoder::new();
        enc.encode(7, 1, 16);
        let wire = enc.flush();

        let mut src = ByteIn::new(&wire);
        let mut rd = RangeDecoder::default();
        assert_eq!(rd.range, 0xFFFF_FFFF);
        assert_eq!(rd.code, 0);
        rd.init(&mut src).unwrap();
        assert_eq!(rd.get_threshold(16), 7);
    }

    /// Constants match libarchive / 7-Zip exactly.
    #[test]
    fn constants_match_reference() {
        assert_eq!(KTOP, 0x0100_0000);
        assert_eq!(K_BIT_MODEL_TOTAL_BITS, 14);
        assert_eq!(K_BIT_MODEL_TOTAL, 16384);
        assert_eq!(INIT_BYTES, 5);
    }
}
