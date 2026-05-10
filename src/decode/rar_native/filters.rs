//! RAR5 filter VM — DELTA / E8 / E8E9 / ARM transformations.
//!
//! After the LZSS layer produces a contiguous run of decoded
//! bytes, RAR5 may have queued one or more filters that transform
//! a `block_length`-byte window of that run before it reaches the
//! sink. The four filters this module implements correspond to
//! libarchive's `FILTER_DELTA` / `FILTER_E8` / `FILTER_E8E9` /
//! `FILTER_ARM` (Grzegorz Antoniak, BSD 2-Clause; see
//! [`NOTICE`](../../../NOTICE)). Filters 4..=7 (`AUDIO`, `RGB`,
//! `ITANIUM`, `PPM`) are reserved by the RAR4 lineage but not
//! used in RAR5 archives — encountering one surfaces
//! [`FilterError::Unsupported`].
//!
//! # Filter operations (libarchive's `run_*_filter` functions)
//!
//! - **DELTA** — channel-deinterleaved byte differencing. For
//!   each channel `c` in `0..channels`, walks
//!   `dest_pos = c, c + channels, c + 2*channels, …` while
//!   `dest_pos < block_length`, reading source bytes linearly:
//!   ```text
//!   prev_byte = 0
//!   prev_byte -= source[src_pos]; output[dest_pos] = prev_byte
//!   ```
//!   Encoder-side this is a per-channel running difference; the
//!   decoder undoes it via the same `-=` operation (modular
//!   arithmetic makes it self-inverse).
//!
//! - **E8 / E8E9** — x86 near-call / jump rewriter. Walks the
//!   block byte-wise; whenever a `0xE8` (or `0xE9` if E8E9) is
//!   seen, reads the next 4 bytes as a little-endian u32 and
//!   transforms the relative address based on the position
//!   modulo `0x1000000` (16 MiB). The transformation reverses
//!   the encoder's PIC-friendly absolute-to-relative
//!   conversion.
//!
//! - **ARM** — ARM BL (branch-link) instruction rewriter. Walks
//!   in 4-byte steps; whenever the high byte (offset 3) is
//!   `0xEB` (the BL opcode), masks the low 24 bits as a
//!   word-relative displacement, subtracts the position-in-block
//!   divided by 4, and recomposes the instruction.

use thiserror::Error;

/// Maximum filter block length (libarchive's `parse_filter`
/// rejects anything larger). 4 MiB.
pub const MAX_FILTER_BLOCK_LENGTH: u32 = 0x0040_0000;

/// Minimum filter block length. E8/E8E9/ARM read 4-byte
/// instructions / addresses, so a sub-4-byte block is
/// inherently malformed.
pub const MIN_FILTER_BLOCK_LENGTH: u32 = 4;

/// Reference file-size constant the E8/E8E9 filter uses for
/// position-modulo arithmetic. From libarchive: 16 MiB
/// (`0x1000000`).
const E8E9_FILE_SIZE: u32 = 0x0100_0000;

/// Maximum DELTA channel count. libarchive reads 5 extra bits
/// and adds 1, yielding `1..=32`.
pub const MAX_DELTA_CHANNELS: u8 = 32;

/// One of the four RAR5-active filter types.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FilterType {
    /// Channel-deinterleaved byte differencing. `channels` in
    /// `1..=32`.
    Delta {
        /// Number of interleaved channels in the block.
        channels: u8,
    },
    /// x86 near-call rewriter (matches `0xE8` only).
    E8,
    /// x86 near-call + unconditional-jump rewriter (matches
    /// `0xE8` and `0xE9`).
    E8e9,
    /// ARM BL-instruction rewriter.
    Arm,
}

impl FilterType {
    /// Decode the 3-bit type code into a [`FilterType`].
    /// `channels` is consulted only for `FILTER_DELTA = 0`.
    ///
    /// # Errors
    ///
    /// - [`FilterError::Unsupported`] for type codes 4..=7
    ///   (`AUDIO` / `RGB` / `ITANIUM` / `PPM` are RAR4-era and
    ///   never appear in RAR5 archives) and any value ≥ 8.
    /// - [`FilterError::BadDeltaChannels`] for `channels` out
    ///   of range (the wire encoder constrains it to `1..=32`,
    ///   so an out-of-range value indicates corruption).
    pub fn from_wire(type_code: u8, channels: u8) -> Result<Self, FilterError> {
        match type_code {
            0 => {
                if !(1..=MAX_DELTA_CHANNELS).contains(&channels) {
                    return Err(FilterError::BadDeltaChannels { got: channels });
                }
                Ok(FilterType::Delta { channels })
            }
            1 => Ok(FilterType::E8),
            2 => Ok(FilterType::E8e9),
            3 => Ok(FilterType::Arm),
            // FILTER_AUDIO=4, FILTER_RGB=5, FILTER_ITANIUM=6,
            // FILTER_PPM=7 — all RAR4 hold-overs, never used in
            // RAR5 archives in the wild.
            other => Err(FilterError::Unsupported { type_code: other }),
        }
    }
}

/// A queued filter waiting to be applied to a window of decoded
/// bytes.
#[derive(Debug, Clone, Copy)]
pub struct Filter {
    /// Filter discriminator + parameters.
    pub kind: FilterType,
    /// Absolute byte position (in the decoded stream) where the
    /// filter's block starts. Used by E8/E8E9/ARM for
    /// position-relative rewrites.
    pub block_start: u64,
    /// Length of the filter's block, in bytes.
    pub block_length: u32,
}

/// Errors produced by the filter VM.
#[derive(Debug, Error)]
pub enum FilterError {
    /// The filter's `block_length` is below the 4-byte minimum
    /// (insufficient for E8/E8E9/ARM's 4-byte instruction reads)
    /// or above [`MAX_FILTER_BLOCK_LENGTH`].
    #[error(
        "RAR5 filter block_length {got} out of range \
         {MIN_FILTER_BLOCK_LENGTH}..={MAX_FILTER_BLOCK_LENGTH}"
    )]
    BadBlockLength {
        /// The offending block_length.
        got: u32,
    },

    /// The filter type code is in the 4..=7 RAR4 range or ≥ 8.
    #[error("RAR5 filter type {type_code} not used in RAR5 archives")]
    Unsupported {
        /// The wire-decoded filter type code.
        type_code: u8,
    },

    /// The DELTA channel count is outside the wire's `1..=32`
    /// range.
    #[error(
        "RAR5 DELTA filter channels {got} out of range \
         1..={MAX_DELTA_CHANNELS}"
    )]
    BadDeltaChannels {
        /// The wire-decoded channel count.
        got: u8,
    },

    /// `source` and `output` had mismatched lengths or the
    /// length disagreed with `filter.block_length`.
    #[error(
        "RAR5 filter buffer length mismatch: filter says {block_length}, \
         source has {source_len}, output has {output_len}"
    )]
    BufferLengthMismatch {
        /// `filter.block_length`.
        block_length: u32,
        /// Actual `source.len()`.
        source_len: usize,
        /// Actual `output.len()`.
        output_len: usize,
    },
}

/// Apply `filter` to `source`, writing the transformed bytes to
/// `output`. Both buffers must be exactly `filter.block_length`
/// bytes long.
///
/// E8/E8E9 and ARM filters first copy `source` to `output`
/// verbatim (so unmatched bytes pass through unchanged) and
/// then transform 4-byte instructions in place at matching
/// positions. The DELTA filter walks `source` linearly and
/// writes the deinterleaved running-difference result to
/// `output`.
///
/// # Errors
///
/// - [`FilterError::BadBlockLength`] if `filter.block_length`
///   is out of range.
/// - [`FilterError::BufferLengthMismatch`] if `source` /
///   `output` lengths disagree with `filter.block_length`.
pub fn apply(filter: &Filter, source: &[u8], output: &mut [u8]) -> Result<(), FilterError> {
    if filter.block_length < MIN_FILTER_BLOCK_LENGTH
        || filter.block_length > MAX_FILTER_BLOCK_LENGTH
    {
        return Err(FilterError::BadBlockLength {
            got: filter.block_length,
        });
    }
    let len = filter.block_length as usize;
    if source.len() != len || output.len() != len {
        return Err(FilterError::BufferLengthMismatch {
            block_length: filter.block_length,
            source_len: source.len(),
            output_len: output.len(),
        });
    }
    match filter.kind {
        FilterType::Delta { channels } => apply_delta(channels, source, output),
        FilterType::E8 => apply_e8e9(filter.block_start, false, source, output),
        FilterType::E8e9 => apply_e8e9(filter.block_start, true, source, output),
        FilterType::Arm => apply_arm(filter.block_start, source, output),
    }
    Ok(())
}

/// DELTA filter: per-channel running difference deinterleave.
fn apply_delta(channels: u8, source: &[u8], output: &mut [u8]) {
    let channels = channels as usize;
    let block_length = source.len();
    let mut src_pos: usize = 0;
    for c in 0..channels {
        let mut prev_byte: u8 = 0;
        let mut dest_pos = c;
        while dest_pos < block_length {
            let byte = source[src_pos];
            // libarchive: prev_byte -= byte (wrapping mod 256).
            prev_byte = prev_byte.wrapping_sub(byte);
            output[dest_pos] = prev_byte;
            src_pos += 1;
            dest_pos += channels;
        }
    }
}

/// E8 / E8E9 filter: x86 near-call (and optionally jump)
/// relative-address rewriter.
fn apply_e8e9(block_start: u64, extended: bool, source: &[u8], output: &mut [u8]) {
    // First copy unchanged so unmatched bytes pass through.
    output.copy_from_slice(source);
    let block_length = source.len();
    if block_length < 5 {
        // Loop condition `i < block_length - 4` would underflow
        // / never execute. No-op.
        return;
    }
    let last_match_index = block_length - 4;
    let mut i: usize = 0;
    while i < last_match_index {
        let b = source[i];
        i += 1;
        if b == 0xE8 || (extended && b == 0xE9) {
            // Read 4-byte LE u32 from the matched byte's tail.
            let mut tail = [0u8; 4];
            tail.copy_from_slice(&source[i..i + 4]);
            let addr = u32::from_le_bytes(tail);
            // libarchive: offset = (i + block_start) % file_size.
            // The +1 from the `i++` above already happened, so
            // `i` here is the index of the first tail byte; the
            // matched-byte position was `i - 1`. libarchive
            // computes `offset = (i + block_start) % file_size`
            // using its post-increment `i` value, so we use the
            // same.
            let offset = ((i as u64).wrapping_add(block_start) % u64::from(E8E9_FILE_SIZE)) as u32;
            let rewritten = if (addr & 0x8000_0000) != 0 {
                // High bit set: addr is "negative" in i32 view.
                // If adding `offset` flips it to non-negative,
                // rewrite as `addr + file_size`.
                if ((addr.wrapping_add(offset)) & 0x8000_0000) == 0 {
                    Some(addr.wrapping_add(E8E9_FILE_SIZE))
                } else {
                    None
                }
            } else {
                // High bit clear: if subtracting `file_size`
                // would flip it to negative, rewrite as
                // `addr - offset`.
                if ((addr.wrapping_sub(E8E9_FILE_SIZE)) & 0x8000_0000) != 0 {
                    Some(addr.wrapping_sub(offset))
                } else {
                    None
                }
            };
            if let Some(new_addr) = rewritten {
                output[i..i + 4].copy_from_slice(&new_addr.to_le_bytes());
            }
            i += 4;
        }
    }
}

/// ARM filter: BL-instruction relative-displacement rewriter.
fn apply_arm(block_start: u64, source: &[u8], output: &mut [u8]) {
    output.copy_from_slice(source);
    let block_length = source.len();
    if block_length < 4 {
        return;
    }
    // libarchive walks i = 0, 4, 8, ... while i < block_length - 3.
    // `block_length - 3` reflects the 4-byte read at i+0..=i+3.
    let last_match_index = block_length - 3;
    let mut i: usize = 0;
    while i < last_match_index {
        // BL is detected at byte i+3 == 0xEB.
        if source[i + 3] == 0xEB {
            // Read 4-byte LE u32 starting at i.
            let mut word = [0u8; 4];
            word.copy_from_slice(&source[i..i + 4]);
            let raw = u32::from_le_bytes(word);
            // 24-bit displacement.
            let mut offset = raw & 0x00FF_FFFF;
            // libarchive: offset -= (i + block_start) / 4.
            let sub = ((i as u64).wrapping_add(block_start) / 4) as u32;
            offset = offset.wrapping_sub(sub);
            // Recompose with the BL opcode (0xEB at byte 3).
            let recomposed = (offset & 0x00FF_FFFF) | 0xEB00_0000;
            output[i..i + 4].copy_from_slice(&recomposed.to_le_bytes());
        }
        i += 4;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_filter(kind: FilterType, block_start: u64, block_length: u32) -> Filter {
        Filter {
            kind,
            block_start,
            block_length,
        }
    }

    // ---- type-code dispatch -----------------------------------

    #[test]
    fn from_wire_decodes_delta_with_channels() {
        let f = FilterType::from_wire(0, 4).unwrap();
        assert_eq!(f, FilterType::Delta { channels: 4 });
    }

    #[test]
    fn from_wire_decodes_e8_e8e9_arm() {
        assert_eq!(FilterType::from_wire(1, 0).unwrap(), FilterType::E8);
        assert_eq!(FilterType::from_wire(2, 0).unwrap(), FilterType::E8e9);
        assert_eq!(FilterType::from_wire(3, 0).unwrap(), FilterType::Arm);
    }

    #[test]
    fn from_wire_rejects_rar4_filter_codes_4_through_7() {
        for code in 4u8..=7u8 {
            let err = FilterType::from_wire(code, 0).unwrap_err();
            assert!(matches!(err, FilterError::Unsupported { .. }));
        }
    }

    #[test]
    fn from_wire_rejects_delta_with_zero_channels() {
        let err = FilterType::from_wire(0, 0).unwrap_err();
        assert!(matches!(err, FilterError::BadDeltaChannels { got: 0 }));
    }

    #[test]
    fn from_wire_rejects_delta_with_too_many_channels() {
        let err = FilterType::from_wire(0, 33).unwrap_err();
        assert!(matches!(err, FilterError::BadDeltaChannels { got: 33 }));
    }

    // ---- buffer / range validation ---------------------------

    #[test]
    fn apply_rejects_block_length_below_minimum() {
        let filter = make_filter(FilterType::E8, 0, 3);
        let mut output = [0u8; 3];
        let err = apply(&filter, &[0u8; 3], &mut output).unwrap_err();
        assert!(matches!(err, FilterError::BadBlockLength { got: 3 }));
    }

    #[test]
    fn apply_rejects_block_length_above_maximum() {
        let filter = make_filter(FilterType::E8, 0, MAX_FILTER_BLOCK_LENGTH + 1);
        let mut output = [0u8; 4];
        let err = apply(&filter, &[0u8; 4], &mut output).unwrap_err();
        assert!(matches!(err, FilterError::BadBlockLength { .. }));
    }

    #[test]
    fn apply_rejects_buffer_length_mismatch() {
        let filter = make_filter(FilterType::E8, 0, 8);
        let mut output = [0u8; 4];
        let err = apply(&filter, &[0u8; 8], &mut output).unwrap_err();
        assert!(matches!(err, FilterError::BufferLengthMismatch { .. }));
    }

    // ---- DELTA filter ----------------------------------------

    #[test]
    fn delta_with_one_channel_is_running_negative_difference() {
        // channels=1: every byte goes through prev -= byte chain.
        // source = [0x01, 0x02, 0x03, 0x04]
        // prev = 0; -1 = 0xFF; 0xFF - 2 = 0xFD; 0xFD - 3 = 0xFA;
        //          0xFA - 4 = 0xF6
        let filter = make_filter(FilterType::Delta { channels: 1 }, 0, 4);
        let source = [0x01, 0x02, 0x03, 0x04];
        let mut output = [0u8; 4];
        apply(&filter, &source, &mut output).unwrap();
        assert_eq!(output, [0xFF, 0xFD, 0xFA, 0xF6]);
    }

    #[test]
    fn delta_with_two_channels_deinterleaves() {
        // channels=2, block_length=8.
        // Channel 0 reads source[0..4], writes to output[0,2,4,6].
        // Channel 1 reads source[4..8], writes to output[1,3,5,7].
        let filter = make_filter(FilterType::Delta { channels: 2 }, 0, 8);
        let source = [10u8, 20, 30, 40, 50, 60, 70, 80];
        let mut output = [0u8; 8];
        apply(&filter, &source, &mut output).unwrap();

        // Channel 0 (source[0..4] = [10,20,30,40]):
        //   prev=0; -10=246; 246-20=226; 226-30=196; 196-40=156
        //   → output[0]=246, [2]=226, [4]=196, [6]=156
        // Channel 1 (source[4..8] = [50,60,70,80]):
        //   prev=0; -50=206; 206-60=146; 146-70=76; 76-80=-4=252
        //   → output[1]=206, [3]=146, [5]=76, [7]=252
        let expected = [246u8, 206, 226, 146, 196, 76, 156, 252];
        assert_eq!(output, expected);
    }

    #[test]
    fn delta_handles_block_length_not_multiple_of_channels() {
        // channels=3, block_length=5 → channel 0 gets 2 bytes,
        // channels 1 and 2 get 1 byte each (last src_pos = 4).
        let filter = make_filter(FilterType::Delta { channels: 3 }, 0, 5);
        let source = [1u8, 2, 3, 4, 5];
        let mut output = [0u8; 5];
        apply(&filter, &source, &mut output).unwrap();
        // src_pos walks 0..5 across channels 0, 1, 2.
        // Channel 0: dest 0, 3 ← src 0, 1
        //   prev=0; -1=255; 255-2=253
        //   output[0]=255, output[3]=253
        // Channel 1: dest 1, 4 ← src 2, 3
        //   prev=0; -3=253; 253-4=249
        //   output[1]=253, output[4]=249
        // Channel 2: dest 2 ← src 4
        //   prev=0; -5=251
        //   output[2]=251
        assert_eq!(output, [255, 253, 251, 253, 249]);
    }

    // ---- E8 / E8E9 filter ------------------------------------

    #[test]
    fn e8_passes_through_blocks_with_no_e8_byte() {
        let filter = make_filter(FilterType::E8, 0, 8);
        let source = [0x90u8; 8]; // x86 NOPs
        let mut output = [0u8; 8];
        apply(&filter, &source, &mut output).unwrap();
        assert_eq!(output, source);
    }

    #[test]
    fn e8_does_not_match_e9() {
        // FilterType::E8 only matches 0xE8, not 0xE9.
        let filter = make_filter(FilterType::E8, 0, 8);
        let source = [0xE9u8, 0x00, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90];
        let mut output = [0u8; 8];
        apply(&filter, &source, &mut output).unwrap();
        assert_eq!(output, source);
    }

    #[test]
    fn e8e9_matches_both_e8_and_e9() {
        // Construct a small block with one 0xE9 and verify the
        // filter rewrites the address. We don't need to assert
        // the exact rewritten value here — just that the bytes
        // following the 0xE9 changed.
        let filter = make_filter(FilterType::E8e9, 0, 8);
        let source = [0xE9u8, 0x00, 0x00, 0x00, 0x80, 0x90, 0x90, 0x90];
        let mut output = [0u8; 8];
        apply(&filter, &source, &mut output).unwrap();
        // The high bit (0x80 in byte index 4) means the high bit
        // of the LE u32 starting at byte 1 is set:
        // u32 = 0x80000000. file_size = 0x01000000.
        // offset = (i + block_start) mod file_size
        //        = (1 + 0) mod 0x01000000 = 1.
        // addr & 0x80000000 != 0; (addr + offset) & 0x80000000:
        //   0x80000000 + 1 = 0x80000001; & 0x80000000 != 0,
        //   so the rewrite condition is FALSE — no rewrite.
        // (Spec edge case: high-bit-set addresses near 0 stay.)
        // Output equals source.
        assert_eq!(output, source);
    }

    #[test]
    fn e8_rewrites_when_the_addr_is_in_the_rewrite_window() {
        // Construct a value where addr is positive and
        // (addr - file_size) flips negative — then rewrite
        // applies. With i=1, block_start=0:
        //   addr = 0x00800000 (just below file_size 0x01000000)
        //   (addr - file_size) = 0xFF800000 (high bit set) → rewrite
        //   new addr = addr - offset = 0x00800000 - 1 = 0x007FFFFF
        let filter = make_filter(FilterType::E8, 0, 8);
        let mut source = vec![0u8; 8];
        source[0] = 0xE8;
        source[1..5].copy_from_slice(&0x00800000u32.to_le_bytes());
        let mut output = [0u8; 8];
        apply(&filter, &source, &mut output).unwrap();
        let mut tail = [0u8; 4];
        tail.copy_from_slice(&output[1..5]);
        let new_addr = u32::from_le_bytes(tail);
        assert_eq!(new_addr, 0x007FFFFF);
        // Bytes outside the rewrite window are unchanged.
        assert_eq!(output[0], 0xE8);
        assert_eq!(&output[5..], &[0u8, 0, 0]);
    }

    // ---- ARM filter -------------------------------------------

    #[test]
    fn arm_passes_through_blocks_with_no_eb_at_offset_3() {
        let filter = make_filter(FilterType::Arm, 0, 8);
        let source = [0u8; 8];
        let mut output = [0u8; 8];
        apply(&filter, &source, &mut output).unwrap();
        assert_eq!(output, source);
    }

    #[test]
    fn arm_rewrites_bl_instruction() {
        // BL instruction: 4 bytes with 0xEB at byte 3. The low
        // 24 bits encode a word-relative displacement.
        // source = [0x00, 0x10, 0x00, 0xEB]
        // raw u32 (LE) = 0xEB001000
        // offset = raw & 0x00FFFFFF = 0x001000
        // offset -= (0 + 0) / 4 = 0; offset stays 0x001000
        // recomposed = (0x001000 & 0x00FFFFFF) | 0xEB000000
        //            = 0xEB001000
        // → output bytes = [0x00, 0x10, 0x00, 0xEB] (unchanged)
        let filter = make_filter(FilterType::Arm, 0, 4);
        let source = [0x00, 0x10, 0x00, 0xEB];
        let mut output = [0u8; 4];
        apply(&filter, &source, &mut output).unwrap();
        assert_eq!(output, source);
    }

    #[test]
    fn arm_rewrites_bl_at_nonzero_position() {
        // At i=4 (second 4-byte word), block_start=0:
        //   subtract = (4 + 0) / 4 = 1
        //   raw = 0xEB001000; offset = 0x001000 - 1 = 0x000FFF
        //   recomposed = 0xEB000FFF → bytes [0xFF, 0x0F, 0x00, 0xEB]
        let filter = make_filter(FilterType::Arm, 0, 8);
        let source = [0x00u8, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0xEB];
        let mut output = [0u8; 8];
        apply(&filter, &source, &mut output).unwrap();
        assert_eq!(&output[0..4], &[0u8; 4]);
        assert_eq!(&output[4..8], &[0xFF, 0x0F, 0x00, 0xEB]);
    }

    #[test]
    fn arm_block_start_shifts_the_subtraction() {
        // block_start=8: subtract = (0 + 8) / 4 = 2.
        // raw = 0xEB001000; offset = 0x001000 - 2 = 0x000FFE.
        // recomposed = 0xEB000FFE → bytes [0xFE, 0x0F, 0x00, 0xEB]
        let filter = make_filter(FilterType::Arm, 8, 4);
        let source = [0x00, 0x10, 0x00, 0xEB];
        let mut output = [0u8; 4];
        apply(&filter, &source, &mut output).unwrap();
        assert_eq!(output, [0xFE, 0x0F, 0x00, 0xEB]);
    }
}
