//! Hand-rolled LZ4 block decoder.
//!
//! [`crate::decode::lz4`] drives the LZ4 Frame Format itself; this
//! module decodes the compressed payload *inside* one block. It
//! replaces the former runtime dependency on
//! `lz4_flex::block::decompress_into`, so the production tree carries
//! no external LZ4 crate (see
//! [`internal/PLAN_lz4_block_decoder.md`](../../../internal/PLAN_lz4_block_decoder.md)).
//! `lz4_flex` remains a dev-dependency, used as the reference
//! implementation in the differential harness
//! `tests/test_lz4_native_diff.rs` and the round-trip checks in this
//! module's unit tests — the same precedent as `flate2` for
//! [`crate::decode::deflate_native`] and `xz2` for the xz decoders.
//!
//! # Block format
//!
//! A block is a sequence of *sequences*. Each sequence is:
//!
//! 1. **Token** (1 byte). High nibble = literal length (`0..=15`), low
//!    nibble = match length (`0..=15`, biased by `+4` — the 4-byte
//!    minimum match LZ4 encodes implicitly).
//! 2. **Literal-length extension**: present only when the high nibble
//!    is `15`. Read bytes, adding each to the length, until a byte
//!    `!= 0xFF` terminates the chain.
//! 3. **Literals**: `literal_length` bytes copied verbatim.
//! 4. **Match offset** (2 bytes, little-endian). A 1-based distance
//!    back into the already-produced output; `0` is invalid.
//! 5. **Match-length extension**: present only when the low nibble is
//!    `15`, same `0xFF`-terminated scheme as the literal length.
//! 6. **Match copy**: `match_length` bytes copied from
//!    `output[pos - offset ..]`, *with overlap* — when
//!    `offset < match_length` the copy reads bytes it has just
//!    written, which is how LZ4 expresses run-length sequences.
//!
//! The final sequence of a block stops right after its literals — it
//! has no offset or match. We detect it structurally: when the input
//! is exactly exhausted after a literal copy, that literal run was the
//! last sequence.
//!
//! # Why no "last 5 bytes are literals" check
//!
//! The spec's end-of-block rules ("the last 5 bytes are literals", "a
//! match must start ≥ 12 bytes before the end") are *encoder*
//! constraints that let the reference decoder use unchecked
//! wide copies on its fast path. A bounds-checked decoder like this
//! one needs neither, and enforcing "last literal run ≥ 5 bytes" would
//! wrongly reject the legal short blocks an encoder emits for tiny
//! incompressible inputs (a 1-byte payload is a single 1-literal
//! sequence). We therefore decode faithfully and reject only genuine
//! safety violations — truncation, output overrun, and bad offsets.
//!
//! [LZ4 Block Format]: https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md

use std::io;

use thiserror::Error;

use crate::decode::DecodeError;

/// The 4-byte minimum match length LZ4 encodes implicitly: a match
/// length nibble of `0` denotes a 4-byte copy.
const MIN_MATCH: usize = 4;

/// The nibble value that signals a length-extension chain follows.
const EXTENSION_MARKER: usize = 15;

/// Errors produced while decoding a single LZ4 block.
///
/// Every variant signals *malformed input* — the decoder is infallible
/// on well-formed blocks (those a conformant encoder emits). They
/// convert to [`DecodeError::Read`] at the frame-decoder boundary via
/// [`BlockDecodeError::into_decode_error`], preserving the specific
/// reason in the message the way the DEFLATE / zstd native decoders do.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlockDecodeError {
    /// The block ended after a match copy without a final literal
    /// sequence (or the input was empty). A well-formed block always
    /// ends with a literal run, so reaching the top of the sequence
    /// loop with no input left means the stream is truncated or
    /// corrupt.
    #[error("lz4 block: truncated — expected a token but input is exhausted")]
    TruncatedToken,

    /// A literal-length extension chain ran past the end of the
    /// compressed input.
    #[error("lz4 block: truncated literal-length extension")]
    TruncatedLiteralLength,

    /// The literal run itself extended past the end of the compressed
    /// input.
    #[error("lz4 block: truncated literal run (wanted {wanted} bytes, {available} available)")]
    TruncatedLiterals {
        /// Literal bytes the token declared.
        wanted: usize,
        /// Compressed-input bytes actually remaining.
        available: usize,
    },

    /// The 2-byte match offset ran past the end of the compressed
    /// input.
    #[error("lz4 block: truncated 2-byte match offset")]
    TruncatedOffset,

    /// A match-length extension chain ran past the end of the
    /// compressed input.
    #[error("lz4 block: truncated match-length extension")]
    TruncatedMatchExtension,

    /// Decoding would write past the end of the caller's output buffer
    /// (sized to the frame's declared block-max). Either the block is
    /// corrupt or it disagrees with the frame header.
    #[error("lz4 block: output overflow (buffer capacity {capacity} bytes)")]
    OutputOverflow {
        /// Capacity of the destination buffer.
        capacity: usize,
    },

    /// A match offset of `0` was decoded. Offsets are 1-based in LZ4;
    /// `0` has no valid interpretation.
    #[error("lz4 block: zero match offset (offsets are 1-based)")]
    OffsetZero,

    /// A match offset pointed before the start of the output produced
    /// so far — the copy source would be out of bounds.
    #[error("lz4 block: match offset {offset} exceeds output produced so far ({produced} bytes)")]
    OffsetOutOfRange {
        /// The offset the sequence declared.
        offset: usize,
        /// Bytes of output produced before the match.
        produced: usize,
    },
}

impl BlockDecodeError {
    /// Convert to the protocol-level [`DecodeError`] used across the
    /// decode stack, tagging it with the source-byte high-water mark.
    ///
    /// `consumed` is the number of *source* bytes the frame decoder had
    /// consumed when it handed us the block, so the resume hint in
    /// [`DecodeError::Read::consumed`] stays accurate.
    #[must_use]
    pub fn into_decode_error(self, consumed: u64) -> DecodeError {
        DecodeError::Read {
            consumed,
            source: io::Error::other(format!("lz4: block decompress: {self}")),
        }
    }
}

/// Decode one LZ4 block.
///
/// `src` is the compressed block payload — no frame header, no block
/// size prefix, no block checksum; the frame decoder strips those.
/// `dst` is the output buffer, sized by the caller to the frame's
/// declared block-max; the decoder rejects any sequence that would
/// overrun it. Returns the number of bytes written to `dst`.
///
/// # Errors
///
/// Returns a [`BlockDecodeError`] if `src` is truncated, declares a
/// match offset that is zero or points before the start of output, or
/// would write more than `dst.len()` bytes.
pub fn decompress_block(src: &[u8], dst: &mut [u8]) -> Result<usize, BlockDecodeError> {
    let mut ip = 0usize; // input (compressed) cursor
    let mut op = 0usize; // output (decompressed) cursor

    loop {
        // 1. Token. A well-formed block always has at least one more
        //    token here: the loop only re-enters after a match copy,
        //    and a match is never the last element of a block.
        let token = *src.get(ip).ok_or(BlockDecodeError::TruncatedToken)?;
        ip += 1;

        // 2. Literal length: high nibble, with a 0xFF-terminated
        //    extension chain when the nibble saturates.
        let mut lit_len = (token >> 4) as usize;
        if lit_len == EXTENSION_MARKER {
            lit_len +=
                read_extension(src, &mut ip).ok_or(BlockDecodeError::TruncatedLiteralLength)?;
        }

        // 3. Copy literals. `src.len() - ip` and `dst.len() - op` are
        //    non-negative: every prior read/write was bounds-checked,
        //    so neither cursor ever passes its buffer end.
        if lit_len > src.len() - ip {
            return Err(BlockDecodeError::TruncatedLiterals {
                wanted: lit_len,
                available: src.len() - ip,
            });
        }
        if lit_len > dst.len() - op {
            return Err(BlockDecodeError::OutputOverflow {
                capacity: dst.len(),
            });
        }
        dst[op..op + lit_len].copy_from_slice(&src[ip..ip + lit_len]);
        ip += lit_len;
        op += lit_len;

        // 4. Last-sequence detection: a block ends right after the
        //    literals of its final sequence.
        if ip == src.len() {
            return Ok(op);
        }

        // 5. Match offset: 2-byte little-endian, 1-based.
        if ip + 2 > src.len() {
            return Err(BlockDecodeError::TruncatedOffset);
        }
        let offset = u16::from_le_bytes([src[ip], src[ip + 1]]) as usize;
        ip += 2;
        if offset == 0 {
            return Err(BlockDecodeError::OffsetZero);
        }
        if offset > op {
            return Err(BlockDecodeError::OffsetOutOfRange {
                offset,
                produced: op,
            });
        }

        // 6. Match length: low nibble + extension, plus the implicit
        //    4-byte minimum match.
        let mut match_len = (token & 0x0F) as usize;
        if match_len == EXTENSION_MARKER {
            match_len +=
                read_extension(src, &mut ip).ok_or(BlockDecodeError::TruncatedMatchExtension)?;
        }
        match_len += MIN_MATCH;

        // 7. Copy match. When the match does not overlap the output
        //    cursor (`offset >= match_len`) a single move suffices —
        //    the source and destination ranges are disjoint, so
        //    `copy_within`'s memmove semantics are correct and fast.
        //    When `offset < match_len` the match reads bytes as they
        //    are produced (LZ4's run-length encoding), which a single
        //    move would mishandle; replicate byte-by-byte instead.
        if match_len > dst.len() - op {
            return Err(BlockDecodeError::OutputOverflow {
                capacity: dst.len(),
            });
        }
        let match_start = op - offset;
        if offset >= match_len {
            dst.copy_within(match_start..match_start + match_len, op);
            op += match_len;
        } else {
            let match_end = op + match_len;
            let mut s = match_start;
            while op < match_end {
                dst[op] = dst[s];
                op += 1;
                s += 1;
            }
        }
    }
}

/// Read a `0xFF`-terminated length-extension chain, advancing `*ip`.
///
/// Returns the summed extension (`0` if the first byte already
/// terminates the chain), or `None` if the input ends mid-chain.
#[inline]
fn read_extension(src: &[u8], ip: &mut usize) -> Option<usize> {
    let mut extra = 0usize;
    loop {
        let b = *src.get(*ip)?;
        *ip += 1;
        extra += b as usize;
        if b != 0xFF {
            return Some(extra);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode into a generously sized buffer and return the written
    /// slice as an owned `Vec` for easy comparison.
    fn decode(src: &[u8], cap: usize) -> Result<Vec<u8>, BlockDecodeError> {
        let mut dst = vec![0u8; cap];
        let n = decompress_block(src, &mut dst)?;
        dst.truncate(n);
        Ok(dst)
    }

    #[test]
    fn all_literals_short_block() {
        // Token 0x50: literal length 5, match nibble unused.
        let src = [0x50, b'h', b'e', b'l', b'l', b'o'];
        assert_eq!(decode(&src, 64).unwrap(), b"hello");
    }

    #[test]
    fn literal_length_extension() {
        // Token 0xF0 + one extension byte 0x00 → literal length 15.
        let mut src = vec![0xF0, 0x00];
        src.extend_from_slice(&(b'a'..=b'o').collect::<Vec<u8>>()); // 15 bytes
        assert_eq!(
            decode(&src, 64).unwrap(),
            (b'a'..=b'o').collect::<Vec<u8>>()
        );
    }

    #[test]
    fn overlap_match_runs_length() {
        // Seq 1: 1 literal 'a', match offset=1 len=7 → eight 'a's.
        // Seq 2 (last): 2 literals "XY".
        // Token 0x13: lit nibble 1, match nibble 3 (→ len 3+4=7).
        let src = [0x13, b'a', 0x01, 0x00, 0x20, b'X', b'Y'];
        assert_eq!(decode(&src, 64).unwrap(), b"aaaaaaaaXY");
    }

    #[test]
    fn non_overlapping_match() {
        // Produce "abcabc..." with a 3-byte offset, 6-byte match.
        // Seq 1: 3 literals "abc", match offset=3 len=6 → "abcabcabc".
        // Token 0x32: lit nibble 3, match nibble 2 (→ len 2+4=6).
        // Seq 2 (last): 1 literal 'Z'.
        let src = [0x32, b'a', b'b', b'c', 0x03, 0x00, 0x10, b'Z'];
        assert_eq!(decode(&src, 64).unwrap(), b"abcabcabcZ");
    }

    #[test]
    fn single_zero_token_yields_empty_output() {
        // A lone 0x00 token: zero literals, immediately the last
        // sequence. Decodes to empty output rather than erroring.
        assert_eq!(decode(&[0x00], 64).unwrap(), b"");
    }

    #[test]
    fn empty_input_is_truncated_token() {
        assert_eq!(decode(&[], 64), Err(BlockDecodeError::TruncatedToken));
    }

    #[test]
    fn block_ending_after_match_is_truncated_token() {
        // Seq with a match but no trailing literal sequence.
        let src = [0x13, b'a', 0x01, 0x00];
        assert_eq!(decode(&src, 64), Err(BlockDecodeError::TruncatedToken));
    }

    #[test]
    fn truncated_literals() {
        // Token wants 5 literals; only 2 bytes follow.
        let src = [0x50, b'h', b'e'];
        assert_eq!(
            decode(&src, 64),
            Err(BlockDecodeError::TruncatedLiterals {
                wanted: 5,
                available: 2,
            })
        );
    }

    #[test]
    fn truncated_literal_length_extension() {
        // Token 0xF0 demands an extension byte that never arrives.
        assert_eq!(
            decode(&[0xF0], 64),
            Err(BlockDecodeError::TruncatedLiteralLength)
        );
    }

    #[test]
    fn truncated_offset() {
        // After the literal there is only one of the two offset bytes.
        let src = [0x13, b'a', 0x01];
        assert_eq!(decode(&src, 64), Err(BlockDecodeError::TruncatedOffset));
    }

    #[test]
    fn truncated_match_extension() {
        // Token 0x1F: match nibble 15 wants an extension byte that
        // never arrives.
        let src = [0x1F, b'a', 0x01, 0x00];
        assert_eq!(
            decode(&src, 64),
            Err(BlockDecodeError::TruncatedMatchExtension)
        );
    }

    #[test]
    fn offset_zero_rejected() {
        let src = [0x13, b'a', 0x00, 0x00];
        assert_eq!(decode(&src, 64), Err(BlockDecodeError::OffsetZero));
    }

    #[test]
    fn offset_out_of_range_rejected() {
        // Only one byte produced, but the offset reaches back five.
        let src = [0x13, b'a', 0x05, 0x00];
        assert_eq!(
            decode(&src, 64),
            Err(BlockDecodeError::OffsetOutOfRange {
                offset: 5,
                produced: 1,
            })
        );
    }

    #[test]
    fn output_overflow_on_literals() {
        // Five literals into a 3-byte buffer.
        let src = [0x50, b'h', b'e', b'l', b'l', b'o'];
        assert_eq!(
            decode(&src, 3),
            Err(BlockDecodeError::OutputOverflow { capacity: 3 })
        );
    }

    #[test]
    fn output_overflow_on_match() {
        // 1 literal + 7-byte match needs 8 bytes; give it 4.
        let src = [0x13, b'a', 0x01, 0x00, 0x20, b'X', b'Y'];
        assert_eq!(
            decode(&src, 4),
            Err(BlockDecodeError::OutputOverflow { capacity: 4 })
        );
    }

    #[test]
    fn into_decode_error_preserves_consumed_and_message() {
        let e = BlockDecodeError::OffsetZero;
        match e.into_decode_error(123) {
            DecodeError::Read { consumed, source } => {
                assert_eq!(consumed, 123);
                assert!(source.to_string().contains("zero match offset"));
            }
            other => panic!("expected Read, got {other:?}"),
        }
    }

    // --- Differential round-trips against the lz4_flex reference -----
    //
    // lz4_flex is a dev-dependency; these guard the happy path against
    // the reference encoder/decoder pair without waiting for the full
    // `tests/test_lz4_native_diff.rs` corpus. Same precedent as the
    // flate2 cross-checks in `deflate_native`.

    fn lz4_flex_roundtrip(payload: &[u8]) {
        let max = lz4_flex::block::get_maximum_output_size(payload.len());
        let mut compressed = vec![0u8; max];
        let n = lz4_flex::block::compress_into(payload, &mut compressed).expect("compress");
        compressed.truncate(n);

        let mut ours = vec![0u8; payload.len()];
        let written = decompress_block(&compressed, &mut ours).expect("decompress");
        ours.truncate(written);
        assert_eq!(
            ours,
            payload,
            "native decode != payload for {} bytes",
            payload.len()
        );
    }

    #[test]
    fn roundtrip_reference_corpus() {
        // Empty payloads are handled at the frame layer and never
        // reach block compression, so the degenerate empty-block
        // encoding is out of scope here (see the `single_zero_token`
        // and `empty_input` unit tests for byte-level behavior).
        lz4_flex_roundtrip(b"a");
        lz4_flex_roundtrip(b"hello, world!");
        lz4_flex_roundtrip(&vec![b'A'; 4096]); // RLE → deep overlap matches
        lz4_flex_roundtrip(
            &std::iter::repeat(b"the quick brown fox ")
                .flatten()
                .copied()
                .take(8192)
                .collect::<Vec<u8>>(),
        );
        // Pseudo-random (mostly literals) via a small LCG.
        let mut state = 0x1234_5678u32;
        let random: Vec<u8> = (0..4096)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 16) as u8
            })
            .collect();
        lz4_flex_roundtrip(&random);
    }
}
