//! Standard filter set for legacy RAR (RAR3 / RAR4) RarVM.
//!
//! `internal/PLAN_rar3.md` §C2a. WinRAR's RAR3 encoder emits one of
//! five fixed bytecode programs to invoke each of its standard
//! filters (DELTA / E8 / E8E9 / RGB / AUDIO); decoders recognise
//! the program via a 64-bit fingerprint (libarchive's
//! `crc32(bytecode) | (length << 32)` shortcut at
//! `archive_read_support_format_rar.c` lines 3876..3891) and
//! invoke the matching native executor instead of running the
//! bytecode through a VM interpreter.
//!
//! The five fingerprint constants below are taken verbatim from
//! libarchive (Grzegorz Antoniak, BSD 2-Clause; see
//! [`NOTICE`](../../../../NOTICE)). The native executors mirror
//! libarchive's `execute_filter_*` implementations (lines
//! 3690..3870) for DELTA, E8 / E8E9, RGB, and AUDIO.
//!
//! # Why a fingerprint shortcut
//!
//! libarchive's RAR3 implementation does **not** ship a generic
//! VM interpreter; recognising the five standard programs by
//! fingerprint is sufficient for every archive WinRAR actually
//! produces. §C2b adds the generic interpreter for completeness
//! (and to handle malformed-but-non-malicious custom programs
//! the way the spec demands), but the fingerprint shortcut
//! remains the fast path for the overwhelming majority of
//! filter invocations.
//!
//! # CRC32
//!
//! The fingerprint uses CRC-32/ISO-HDLC (reflected polynomial
//! `0xEDB88320`, init `0xFFFFFFFF`, xorout `0xFFFFFFFF`) — the
//! same parameters zlib's `crc32` ships with. We carry a local
//! table-driven implementation rather than reusing the one at
//! [`crate::decode::xz_liblzma::stream::crc32`] to keep the
//! `rar_legacy` module tree self-contained per §C0's
//! sibling-module posture. The table is 1 KiB of `const`
//! storage; the practical cost is nil.

use thiserror::Error;

/// Standard filter discriminator for [`recognize_standard_filter`].
///
/// Each variant corresponds to one of the five WinRAR standard
/// filter programs. The discriminant order matches libarchive's
/// `execute_filter` switch (lines 3878..3886) for ease of
/// cross-referencing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StandardFilter {
    /// DELTA — per-channel running-difference deinterleave.
    /// Register 0 = `num_channels`, register 4 = `length`.
    /// libarchive's `execute_filter_delta`.
    Delta,
    /// E8 — x86 near-call (`0xE8`) absolute → position-relative
    /// rewriter. Register 4 = `length`. libarchive's
    /// `execute_filter_e8` with `e9also = 0`.
    E8,
    /// E8E9 — x86 near-call (`0xE8`) **and** unconditional-jump
    /// (`0xE9`) rewriter. Register 4 = `length`. libarchive's
    /// `execute_filter_e8` with `e9also = 1`.
    E8E9,
    /// RGB — 24-bpp RGB image row predictor. Register 0 =
    /// `stride`, register 1 = `byte_offset`, register 4 =
    /// `block_length`. libarchive's `execute_filter_rgb`.
    Rgb,
    /// AUDIO — per-channel adaptive linear predictor. Register
    /// 0 = `num_channels`, register 4 = `length`. libarchive's
    /// `execute_filter_audio`.
    Audio,
}

/// DELTA filter program fingerprint. libarchive line 3878.
pub const FINGERPRINT_DELTA: u64 = 0x0000_001D_0E06_077D;
/// E8 filter program fingerprint. libarchive line 3880.
pub const FINGERPRINT_E8: u64 = 0x0000_0035_AD57_6887;
/// E8E9 filter program fingerprint. libarchive line 3882.
pub const FINGERPRINT_E8E9: u64 = 0x0000_0039_3CD7_E57E;
/// RGB filter program fingerprint. libarchive line 3884.
pub const FINGERPRINT_RGB: u64 = 0x0000_0095_1C2C_5DC8;
/// AUDIO filter program fingerprint. libarchive line 3886.
pub const FINGERPRINT_AUDIO: u64 = 0x0000_00D8_BC85_E701;

/// Look up a program fingerprint and return the matching
/// [`StandardFilter`], or `None` if the program isn't one of the
/// five standard filters (i.e. it's archive-supplied custom
/// bytecode that §C2b's VM interpreter will need to handle).
#[must_use]
pub fn recognize_standard_filter(fingerprint: u64) -> Option<StandardFilter> {
    match fingerprint {
        FINGERPRINT_DELTA => Some(StandardFilter::Delta),
        FINGERPRINT_E8 => Some(StandardFilter::E8),
        FINGERPRINT_E8E9 => Some(StandardFilter::E8E9),
        FINGERPRINT_RGB => Some(StandardFilter::Rgb),
        FINGERPRINT_AUDIO => Some(StandardFilter::Audio),
        _ => None,
    }
}

/// Compute the libarchive RAR3 program fingerprint:
/// `crc32(bytecode) | ((bytecode.len() as u64) << 32)`.
///
/// libarchive's `compile_program` builds the same value at line
/// 3545 and `execute_filter` switches on it at lines
/// 3878..3886.
#[must_use]
pub fn compute_program_fingerprint(bytecode: &[u8]) -> u64 {
    u64::from(crc32_iso_hdlc(bytecode)) | ((bytecode.len() as u64) << 32)
}

/// Errors surfaced by the standard-filter executors.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum FilterExecError {
    /// DELTA / AUDIO / RGB: the input and output buffers must
    /// have the same length, and that length must match the
    /// filter's `block_length` register. libarchive's
    /// `execute_filter_delta` walks `src` and `dst` pointer-by-
    /// pointer over the same `length`, so a mismatch would
    /// either read past `src` or write past `dst`.
    #[error("legacy RAR VM filter: buffer length mismatch (source {source_len}, dest {dest_len})")]
    BufferLengthMismatch {
        /// `source.len()` at executor entry.
        source_len: usize,
        /// `dest.len()` at executor entry.
        dest_len: usize,
    },

    /// DELTA / AUDIO: the `num_channels` parameter is zero, the
    /// inner channel loop would never run. libarchive's
    /// `execute_filter_delta` silently degenerates here (the
    /// outer `for` loop simply never executes), leaving the
    /// destination uninitialised; we treat the case as
    /// malformed and surface it explicitly.
    #[error("legacy RAR VM filter: num_channels {got} must be >= 1")]
    ZeroNumChannels {
        /// The wire-supplied register value.
        got: u32,
    },

    /// E8 / E8E9: `length <= 4`, no full 5-byte window fits.
    /// libarchive's `execute_filter_e8` rejects on this check at
    /// line 3731.
    #[error("legacy RAR VM filter: E8 block_length {got} must be > 4")]
    E8BlockTooShort {
        /// The wire-supplied register value.
        got: usize,
    },

    /// RGB: stride > block_length, block_length < 3, or
    /// byte_offset > 2. libarchive's `execute_filter_rgb`
    /// rejects on these checks at line 3763.
    #[error(
        "legacy RAR VM filter: RGB parameter out of range (block_length {block_length}, stride {stride}, byte_offset {byte_offset})"
    )]
    RgbBadParams {
        /// `register[4]` (block length).
        block_length: u32,
        /// `register[0]` (stride).
        stride: u32,
        /// `register[1]` (byte offset within stride).
        byte_offset: u32,
    },
}

/// DELTA filter: per-channel running-difference deinterleave.
///
/// libarchive's `execute_filter_delta` (lines 3690..3722). For
/// each channel `c ∈ 0..num_channels`, walks
/// `dest_pos = c, c + num_channels, ...` while
/// `dest_pos < dest.len()`, reading `source[src_pos++]`
/// linearly and writing
/// `lastbyte = dest[dest_pos] = lastbyte - source[src_pos]`
/// (wrapping mod 256).
///
/// Source and destination must be the same length.
///
/// # Errors
///
/// - [`FilterExecError::BufferLengthMismatch`] if
///   `source.len() != dest.len()`.
/// - [`FilterExecError::ZeroNumChannels`] if `num_channels == 0`.
pub fn execute_delta(
    source: &[u8],
    dest: &mut [u8],
    num_channels: u32,
) -> Result<(), FilterExecError> {
    if source.len() != dest.len() {
        return Err(FilterExecError::BufferLengthMismatch {
            source_len: source.len(),
            dest_len: dest.len(),
        });
    }
    if num_channels == 0 {
        return Err(FilterExecError::ZeroNumChannels { got: 0 });
    }
    let length = dest.len();
    let nc = num_channels as usize;
    let mut src_pos: usize = 0;
    for channel in 0..nc {
        let mut lastbyte: u8 = 0;
        let mut dest_pos = channel;
        while dest_pos < length {
            // libarchive: `lastbyte = dst[idx] = lastbyte - *src++`.
            lastbyte = lastbyte.wrapping_sub(source[src_pos]);
            dest[dest_pos] = lastbyte;
            src_pos += 1;
            dest_pos += nc;
        }
    }
    Ok(())
}

/// E8 / E8E9 filter: x86 near-call (and optionally
/// unconditional-jump) absolute → position-relative rewriter.
///
/// libarchive's `execute_filter_e8` (lines 3724..3752). Walks
/// `data` byte-wise; whenever a `0xE8` (or `0xE9` if
/// `e9_also`) is seen, reads the next 4 bytes as a
/// little-endian `i32` absolute address, and rewrites it as
/// `address + filesize` (if `address < 0` and
/// `currpos + address >= 0`) or `address - currpos` (if
/// `address >= 0 && address < filesize`).
///
/// `block_start_pos` is the offset in the global LZ output
/// stream of `data[0]`. libarchive computes the per-byte
/// "current position" as `block_start_pos + i + 1` where `i` is
/// the in-block offset of the matched `0xE8` / `0xE9` byte.
///
/// Transforms `data` in place.
///
/// # Errors
///
/// - [`FilterExecError::E8BlockTooShort`] if `data.len() <= 4`
///   (no full 5-byte window fits).
pub fn execute_e8(
    data: &mut [u8],
    block_start_pos: u64,
    e9_also: bool,
) -> Result<(), FilterExecError> {
    const FILESIZE: u32 = 0x0100_0000;
    let length = data.len();
    if length <= 4 {
        return Err(FilterExecError::E8BlockTooShort { got: length });
    }
    // libarchive: `for (i = 0; i <= length - 5; i++)` — the
    // matched byte is at `i`, the 4-byte address payload is at
    // `i+1..i+5`.
    let last_i = length - 5;
    let mut i: usize = 0;
    while i <= last_i {
        let b = data[i];
        if b == 0xE8 || (e9_also && b == 0xE9) {
            let payload_pos = i + 1;
            let mut tail = [0u8; 4];
            tail.copy_from_slice(&data[payload_pos..payload_pos + 4]);
            let address = u32::from_le_bytes(tail);
            // libarchive: `currpos = (uint32_t)pos + i + 1`.
            // We accept any caller-supplied `block_start_pos`
            // and let the u32 truncation happen explicitly.
            let currpos: u32 = ((block_start_pos as u32).wrapping_add(i as u32)).wrapping_add(1);
            // Signed-view rewrite predicate from libarchive
            // (lines 3740..3743).
            let rewritten = if (address & 0x8000_0000) != 0 {
                // address < 0 (signed). Encoder stored an
                // absolute pointer that, when interpreted as
                // relative-to-currpos, would underflow.
                // Convert back to absolute by adding filesize
                // iff `currpos + address >= 0`, i.e. `currpos
                // >= -address` (unsigned-view: `currpos >=
                // ~address + 1`).
                let neg_address = (!address).wrapping_add(1);
                if currpos >= neg_address {
                    Some(address.wrapping_add(FILESIZE))
                } else {
                    None
                }
            } else if address < FILESIZE {
                // address ≥ 0 and within filesize. The encoder
                // stored an absolute pointer that the decoder
                // converts back to a relative offset.
                Some(address.wrapping_sub(currpos))
            } else {
                None
            };
            if let Some(new_addr) = rewritten {
                data[payload_pos..payload_pos + 4].copy_from_slice(&new_addr.to_le_bytes());
            }
            // libarchive: `i += 4` (plus the loop's `i++`).
            i += 5;
        } else {
            i += 1;
        }
    }
    Ok(())
}

/// RGB filter: 24-bpp RGB image-row predictor.
///
/// libarchive's `execute_filter_rgb` (lines 3754..3803). The
/// first stage runs a 3-pixel-stride median predictor across
/// each of the three colour channels, writing into `dest`. The
/// second stage walks the destination buffer with a
/// `byte_offset`-aligned cursor and adds neighbouring channels
/// together (`dest[i] += dest[i+1]; dest[i+2] += dest[i+1]`)
/// to invert an encoder-side colour-space rotation.
///
/// Source and destination must be the same length, and that
/// length must be at least 3 bytes (one full RGB pixel).
///
/// # Errors
///
/// - [`FilterExecError::BufferLengthMismatch`] if
///   `source.len() != dest.len()`.
/// - [`FilterExecError::RgbBadParams`] if the parameters fail
///   libarchive's `stride > block_length || block_length < 3 ||
///   byte_offset > 2` check.
pub fn execute_rgb(
    source: &[u8],
    dest: &mut [u8],
    stride: u32,
    byte_offset: u32,
) -> Result<(), FilterExecError> {
    if source.len() != dest.len() {
        return Err(FilterExecError::BufferLengthMismatch {
            source_len: source.len(),
            dest_len: dest.len(),
        });
    }
    let block_length_u32 = dest.len() as u32;
    if block_length_u32 < 3 || stride > block_length_u32 || byte_offset > 2 {
        return Err(FilterExecError::RgbBadParams {
            block_length: block_length_u32,
            stride,
            byte_offset,
        });
    }
    let block_length = dest.len();
    let stride_us = stride as usize;
    let byte_offset_us = byte_offset as usize;

    // Stage 1: per-channel predictor.
    // libarchive: `for (i = 0; i < 3; i++) { ... }`.
    let mut src_pos: usize = 0;
    for channel in 0..3usize {
        let mut byte: u8 = 0;
        // `prev` walks one stride behind `dest_pos`; the loop
        // body checks `prev >= dst` (i.e., still inside the
        // dest buffer at offset `dest_pos - stride`) before
        // using it. In our index-based form, that translates to
        // `dest_pos >= stride_us`.
        let mut dest_pos = channel;
        while dest_pos < block_length {
            if dest_pos >= stride_us {
                // libarchive's median predictor: look at the
                // pixel one stride behind (`prev[0]`) and three
                // bytes earlier within that stride
                // (`prev[3]` — i.e. the same colour channel of
                // the previous pixel).
                let prev0_idx = dest_pos - stride_us;
                let prev3_idx = prev0_idx + 3;
                if prev3_idx < block_length {
                    let prev0 = dest[prev0_idx] as i32;
                    let prev3 = dest[prev3_idx] as i32;
                    let byte_i32 = byte as i32;
                    let delta1 = (prev3 - prev0).unsigned_abs();
                    let delta2 = (byte_i32 - prev0).unsigned_abs();
                    let delta3 = ((prev3 - prev0) + (byte_i32 - prev0)).unsigned_abs();
                    if delta1 > delta2 || delta1 > delta3 {
                        byte = if delta2 <= delta3 {
                            dest[prev3_idx]
                        } else {
                            dest[prev0_idx]
                        };
                    }
                }
            }
            byte = byte.wrapping_sub(source[src_pos]);
            dest[dest_pos] = byte;
            src_pos += 1;
            dest_pos += 3;
        }
    }

    // Stage 2: undo the encoder-side colour-space rotation.
    // libarchive: `for (i = byteoffset; i < blocklength - 2; i += 3)
    //   { dst[i] += dst[i+1]; dst[i+2] += dst[i+1]; }`.
    if block_length >= 2 {
        let upper = block_length - 2;
        let mut i = byte_offset_us;
        while i < upper {
            // i + 2 < block_length (since i < upper == block_length - 2).
            let centre = dest[i + 1];
            dest[i] = dest[i].wrapping_add(centre);
            dest[i + 2] = dest[i + 2].wrapping_add(centre);
            i += 3;
        }
    }
    Ok(())
}

/// AUDIO filter: per-channel adaptive linear predictor.
///
/// libarchive's `execute_filter_audio` (lines 3805..3870). Each
/// channel maintains a [`AudioState`] with a 3-weight linear
/// predictor + error-tracking accumulator; the predictor's
/// weights adapt every 32 samples to minimise prediction error.
/// Output bytes are the encoder-supplied deltas added back to
/// the predicted value.
///
/// Source and destination must be the same length.
///
/// # Errors
///
/// - [`FilterExecError::BufferLengthMismatch`] if
///   `source.len() != dest.len()`.
/// - [`FilterExecError::ZeroNumChannels`] if `num_channels == 0`.
pub fn execute_audio(
    source: &[u8],
    dest: &mut [u8],
    num_channels: u32,
) -> Result<(), FilterExecError> {
    if source.len() != dest.len() {
        return Err(FilterExecError::BufferLengthMismatch {
            source_len: source.len(),
            dest_len: dest.len(),
        });
    }
    if num_channels == 0 {
        return Err(FilterExecError::ZeroNumChannels { got: 0 });
    }
    let length = dest.len();
    let nc = num_channels as usize;
    let mut src_pos: usize = 0;
    for channel in 0..nc {
        let mut state = AudioState::default();
        let mut idx = channel;
        while idx < length {
            // Per-sample step. Mirrors libarchive lines
            // 3822..3868. Each step:
            //   1. Read the encoder's delta (signed byte).
            //   2. Shift the delta history.
            //   3. Compute the predicted byte from `lastbyte`
            //      and the weighted delta history.
            //   4. Output `byte = predbyte - delta`; update
            //      `lastdelta`, `lastbyte`, and the error
            //      counters.
            //   5. Every 32 samples, pick the smallest error
            //      bucket and nudge the corresponding weight
            //      one step.
            let delta = source[src_pos] as i8;
            src_pos += 1;
            state.delta_history[2] = state.delta_history[1];
            state.delta_history[1] = i16::from(state.last_delta) - state.delta_history[0];
            state.delta_history[0] = i16::from(state.last_delta);

            let predicted_i32 = (8 * i32::from(state.last_byte))
                .wrapping_add(i32::from(state.weights[0]) * i32::from(state.delta_history[0]))
                .wrapping_add(i32::from(state.weights[1]) * i32::from(state.delta_history[1]))
                .wrapping_add(i32::from(state.weights[2]) * i32::from(state.delta_history[2]));
            let predbyte: u8 = ((predicted_i32 >> 3) & 0xFF) as u8;
            let byte: u8 = predbyte.wrapping_sub(delta as u8);
            let prederror = i32::from(delta) << 3;
            // Error counters (libarchive uses `int`; saturating
            // adds keep us out of overflow trouble on hostile
            // inputs).
            state.error[0] = state.error[0].saturating_add(prederror.unsigned_abs() as i32);
            state.error[1] = state.error[1].saturating_add(
                (prederror - i32::from(state.delta_history[0])).unsigned_abs() as i32,
            );
            state.error[2] = state.error[2].saturating_add(
                (prederror + i32::from(state.delta_history[0])).unsigned_abs() as i32,
            );
            state.error[3] = state.error[3].saturating_add(
                (prederror - i32::from(state.delta_history[1])).unsigned_abs() as i32,
            );
            state.error[4] = state.error[4].saturating_add(
                (prederror + i32::from(state.delta_history[1])).unsigned_abs() as i32,
            );
            state.error[5] = state.error[5].saturating_add(
                (prederror - i32::from(state.delta_history[2])).unsigned_abs() as i32,
            );
            state.error[6] = state.error[6].saturating_add(
                (prederror + i32::from(state.delta_history[2])).unsigned_abs() as i32,
            );
            state.last_delta = (byte.wrapping_sub(state.last_byte)) as i8;
            state.last_byte = byte;
            dest[idx] = byte;

            // libarchive uses `state.count++ & 0x1F` (post-
            // increment): the check fires on the pre-incremented
            // value, so the weight update runs on samples
            // 0, 32, 64, ... within each channel. We mirror the
            // same ordering — capture `fire` before bumping
            // `count`.
            let fire = state.count & 0x1F == 0;
            state.count = state.count.wrapping_add(1);
            if fire {
                // Pick the smallest error bucket (1..=6) and
                // nudge the corresponding weight.
                let mut idx_min: usize = 0;
                for k in 1..7 {
                    if state.error[k] < state.error[idx_min] {
                        idx_min = k;
                    }
                }
                state.error = [0; 7];
                match idx_min {
                    1 if state.weights[0] >= -16 => state.weights[0] -= 1,
                    2 if state.weights[0] < 16 => state.weights[0] += 1,
                    3 if state.weights[1] >= -16 => state.weights[1] -= 1,
                    4 if state.weights[1] < 16 => state.weights[1] += 1,
                    5 if state.weights[2] >= -16 => state.weights[2] -= 1,
                    6 if state.weights[2] < 16 => state.weights[2] += 1,
                    _ => {}
                }
            }
            idx += nc;
        }
    }
    Ok(())
}

/// Per-channel audio predictor state. libarchive's
/// `struct audio_state` (lines 280..288). Three adaptive
/// weights (`-16..=16`), three delta-history slots, last
/// emitted byte, last emitted delta, seven error buckets, and
/// a 5-bit sample counter (top 27 bits unused).
#[derive(Debug, Clone, Copy, Default)]
struct AudioState {
    weights: [i8; 3],
    delta_history: [i16; 3],
    last_delta: i8,
    last_byte: u8,
    error: [i32; 7],
    count: u32,
}

/// CRC-32/ISO-HDLC over `bytes`. Reflected polynomial
/// `0xEDB88320`, init `0xFFFFFFFF`, xorout `0xFFFFFFFF`. Same
/// parameters as zlib's `crc32` — and libarchive's
/// `compile_program` uses zlib's `crc32` directly to compute
/// fingerprints (line 3545).
fn crc32_iso_hdlc(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bytes {
        let idx = ((crc as u8) ^ b) as usize;
        crc = (crc >> 8) ^ CRC32_TABLE[idx];
    }
    crc ^ 0xFFFF_FFFF
}

/// Pre-computed CRC-32/ISO-HDLC byte table.
const CRC32_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0u32;
    while i < 256 {
        let mut c = i;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 == 1 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i as usize] = c;
        i += 1;
    }
    t
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference CRC-32 vectors. Cross-checked against the
    /// existing implementation at
    /// [`crate::decode::xz_liblzma::stream::crc32`] (which
    /// carries its own copies of these vectors and a
    /// known-vector test).
    #[test]
    fn crc32_iso_hdlc_known_vectors() {
        assert_eq!(crc32_iso_hdlc(b""), 0x0000_0000);
        assert_eq!(crc32_iso_hdlc(b"a"), 0xE8B7_BE43);
        assert_eq!(crc32_iso_hdlc(b"123456789"), 0xCBF4_3926);
    }

    /// libarchive's fingerprint formula is the OR of two
    /// adjacent fields, so the easy test is that
    /// `(fp >> 32) as u32 == bytecode.len() as u32` and
    /// `fp as u32 == crc32(bytecode)`.
    #[test]
    fn compute_program_fingerprint_packs_length_above_crc32() {
        let bytes = b"123456789";
        let fp = compute_program_fingerprint(bytes);
        assert_eq!(fp & 0xFFFF_FFFF, u64::from(0xCBF4_3926u32));
        assert_eq!(fp >> 32, bytes.len() as u64);
    }

    #[test]
    fn recognize_standard_filter_matches_each_known_fingerprint() {
        assert_eq!(
            recognize_standard_filter(FINGERPRINT_DELTA),
            Some(StandardFilter::Delta)
        );
        assert_eq!(
            recognize_standard_filter(FINGERPRINT_E8),
            Some(StandardFilter::E8)
        );
        assert_eq!(
            recognize_standard_filter(FINGERPRINT_E8E9),
            Some(StandardFilter::E8E9)
        );
        assert_eq!(
            recognize_standard_filter(FINGERPRINT_RGB),
            Some(StandardFilter::Rgb)
        );
        assert_eq!(
            recognize_standard_filter(FINGERPRINT_AUDIO),
            Some(StandardFilter::Audio)
        );
    }

    #[test]
    fn recognize_standard_filter_returns_none_for_unknown_program() {
        assert_eq!(recognize_standard_filter(0), None);
        assert_eq!(recognize_standard_filter(0xDEAD_BEEF_DEAD_BEEF), None);
    }

    #[test]
    fn execute_delta_single_channel_round_trips_a_running_difference() {
        // Encoder produces a per-channel running difference:
        //   src[i] = byte[i] - byte[i-1] (with byte[-1] = 0)
        // The decoder undoes this with `lastbyte -= src[i]`.
        // Wait — libarchive's decoder is the inverse:
        //   dst[i] = lastbyte = lastbyte - src[i]
        // For round trip, the encoder must be:
        //   src[i] = lastbyte_prev - byte[i], lastbyte_prev = byte[i]
        // Verify with a small fixed-input synthetic.
        let bytes: [u8; 5] = [10, 20, 35, 50, 80];
        // Encode by inverting the decoder.
        let mut encoded = [0u8; 5];
        let mut prev: u8 = 0;
        for (i, &b) in bytes.iter().enumerate() {
            encoded[i] = prev.wrapping_sub(b);
            prev = b;
        }
        // Decode.
        let mut decoded = [0u8; 5];
        execute_delta(&encoded, &mut decoded, 1).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn execute_delta_multichannel_deinterleaves_per_channel() {
        // Two channels interleaved. `bytes` is the original
        // (decoded) data with channel 0 at even indices and
        // channel 1 at odd indices. The encoder writes channel
        // 0 first (all even positions), then channel 1.
        let original: [u8; 6] = [10, 100, 20, 110, 30, 120];
        let mut encoded = [0u8; 6];
        // Channel 0: indices 0, 2, 4 (original: 10, 20, 30).
        let mut prev: u8 = 0;
        for (k, idx) in [0, 2, 4].iter().enumerate() {
            encoded[k] = prev.wrapping_sub(original[*idx]);
            prev = original[*idx];
        }
        // Channel 1: indices 1, 3, 5 (original: 100, 110, 120).
        let mut prev: u8 = 0;
        for (k, idx) in [1, 3, 5].iter().enumerate() {
            encoded[3 + k] = prev.wrapping_sub(original[*idx]);
            prev = original[*idx];
        }
        // Decode.
        let mut decoded = [0u8; 6];
        execute_delta(&encoded, &mut decoded, 2).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn execute_delta_rejects_zero_num_channels() {
        let src = [0u8; 4];
        let mut dst = [0u8; 4];
        let err = execute_delta(&src, &mut dst, 0).expect_err("zero channels rejected");
        assert!(matches!(err, FilterExecError::ZeroNumChannels { got: 0 }));
    }

    #[test]
    fn execute_delta_rejects_buffer_length_mismatch() {
        let src = [0u8; 5];
        let mut dst = [0u8; 4];
        let err = execute_delta(&src, &mut dst, 1).expect_err("length mismatch rejected");
        assert!(matches!(
            err,
            FilterExecError::BufferLengthMismatch {
                source_len: 5,
                dest_len: 4,
            }
        ));
    }

    #[test]
    fn execute_e8_rejects_block_too_short() {
        let mut data = [0u8; 4];
        let err = execute_e8(&mut data, 0, false).expect_err("block too short rejected");
        assert!(matches!(err, FilterExecError::E8BlockTooShort { got: 4 }));
    }

    #[test]
    fn execute_e8_leaves_blocks_without_call_or_jump_alone() {
        let mut data: [u8; 16] = [0x90; 16];
        execute_e8(&mut data, 0x1000, false).unwrap();
        assert_eq!(data, [0x90; 16]);
    }

    #[test]
    fn execute_e8_rewrites_a_call_to_a_relative_offset() {
        // Place 0xE8 at offset 5 followed by absolute address
        // 0x00000010 (16). Block start at LZ position 0. After
        // filter:
        //   currpos = 0 + 5 + 1 = 6.
        //   address = 16 >= 0 && < FILESIZE → rewrite as 16 - 6 = 10.
        let mut data = [0u8; 16];
        data[5] = 0xE8;
        data[6..10].copy_from_slice(&16u32.to_le_bytes());
        execute_e8(&mut data, 0, false).unwrap();
        let new_addr = u32::from_le_bytes(data[6..10].try_into().unwrap());
        assert_eq!(new_addr, 10);
    }

    #[test]
    fn execute_e8_does_not_rewrite_e9_in_e8_only_mode() {
        let mut data = [0u8; 16];
        data[5] = 0xE9;
        data[6..10].copy_from_slice(&16u32.to_le_bytes());
        let unchanged = data;
        execute_e8(&mut data, 0, false).unwrap();
        assert_eq!(data, unchanged);
    }

    #[test]
    fn execute_e8_e9_rewrites_e9_in_e8e9_mode() {
        let mut data = [0u8; 16];
        data[5] = 0xE9;
        data[6..10].copy_from_slice(&16u32.to_le_bytes());
        execute_e8(&mut data, 0, true).unwrap();
        let new_addr = u32::from_le_bytes(data[6..10].try_into().unwrap());
        assert_eq!(new_addr, 10);
    }

    #[test]
    fn execute_e8_skips_payload_after_rewrite() {
        // Two E8 instructions; the second should NOT trigger
        // on the bytes inside the first instruction's 4-byte
        // tail. With first E8 at offset 0, tail at 1..5, and
        // 0xE8 at offset 3 (inside the tail), the filter
        // should skip past 5 bytes and not re-match. We
        // exploit that by placing the second E8 at offset 5
        // (right after the first instruction's tail) and
        // verifying it gets rewritten.
        let mut data = [0u8; 16];
        // First E8 + 4-byte tail.
        data[0] = 0xE8;
        data[1..5].copy_from_slice(&20u32.to_le_bytes());
        // Second E8 right after.
        data[5] = 0xE8;
        data[6..10].copy_from_slice(&40u32.to_le_bytes());
        execute_e8(&mut data, 0, false).unwrap();
        let a0 = u32::from_le_bytes(data[1..5].try_into().unwrap());
        let a1 = u32::from_le_bytes(data[6..10].try_into().unwrap());
        // First: currpos = 0 + 0 + 1 = 1; 20 - 1 = 19.
        assert_eq!(a0, 19);
        // Second: currpos = 0 + 5 + 1 = 6; 40 - 6 = 34.
        assert_eq!(a1, 34);
    }

    #[test]
    fn execute_rgb_rejects_buffer_length_mismatch() {
        let src = [0u8; 6];
        let mut dst = [0u8; 5];
        let err = execute_rgb(&src, &mut dst, 3, 0).expect_err("mismatch rejected");
        assert!(matches!(err, FilterExecError::BufferLengthMismatch { .. }));
    }

    #[test]
    fn execute_rgb_rejects_bad_params() {
        let src = [0u8; 6];
        let mut dst = [0u8; 6];
        // block_length 6 < 3 is false; try stride > length.
        let err = execute_rgb(&src, &mut dst, 9, 0).expect_err("bad stride rejected");
        assert!(matches!(err, FilterExecError::RgbBadParams { .. }));
        // Try byte_offset > 2.
        let err = execute_rgb(&src, &mut dst, 3, 3).expect_err("bad offset rejected");
        assert!(matches!(err, FilterExecError::RgbBadParams { .. }));
        // Block too short.
        let small_src = [0u8; 2];
        let mut small_dst = [0u8; 2];
        let err =
            execute_rgb(&small_src, &mut small_dst, 0, 0).expect_err("block too short rejected");
        assert!(matches!(err, FilterExecError::RgbBadParams { .. }));
    }

    #[test]
    fn execute_rgb_zero_source_produces_stage_two_pattern() {
        // With source = all zeros, stage 1 sets every dest byte
        // to 0 (the predictor's `byte` starts at 0 and `byte -=
        // 0` stays 0). Stage 2 then walks the destination and
        // does `dst[i] += dst[i+1]` / `dst[i+2] += dst[i+1]`,
        // which on all-zeros is also a no-op. So the result is
        // all zeros.
        let src = [0u8; 9];
        let mut dst = [0u8; 9];
        execute_rgb(&src, &mut dst, 3, 0).unwrap();
        assert_eq!(dst, [0u8; 9]);
    }

    #[test]
    fn execute_audio_rejects_zero_num_channels() {
        let src = [0u8; 4];
        let mut dst = [0u8; 4];
        let err = execute_audio(&src, &mut dst, 0).expect_err("zero channels rejected");
        assert!(matches!(err, FilterExecError::ZeroNumChannels { got: 0 }));
    }

    #[test]
    fn execute_audio_zero_source_produces_zero_dest() {
        // With all zeros, predictor stays at 0 forever, weights
        // never update, output is all zeros.
        let src = [0u8; 64];
        let mut dst = [0xFFu8; 64];
        execute_audio(&src, &mut dst, 2).unwrap();
        assert_eq!(dst, [0u8; 64]);
    }
}
