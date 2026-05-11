//! Filter-stack dispatch for legacy RAR (RAR3 / RAR4) RarVM.
//!
//! `docs/PLAN_rar3.md` §C2b. The LZ entry decoder accumulates a
//! queue of [`FilterDeclaration`]s into a [`FilterStack`] as it
//! consumes `symbol 257` filter-decl tokens; once LZ decoding
//! completes (the entry's `unpacked_size` is reached),
//! [`apply_pending_filters_in_place`] runs each pending filter in
//! FIFO order against the LZ output buffer.
//!
//! libarchive's [`run_filters`](https://github.com/libarchive/libarchive)
//! at `archive_read_support_format_rar.c` lines 3425..3522 fires
//! incrementally: when LZ output reaches the next pending
//! filter's block end, that filter runs and its output is emitted
//! to the sink. For round-one §C2b we collapse the whole entry
//! into a single post-decode pass — the corpus has at most three
//! filters per entry and the entries themselves are well under
//! 1 KiB, so the all-at-once shape costs us nothing and keeps
//! the §C2b dispatcher cleanly separable from the §G streaming
//! work that turns the live LZ window into a bounded ring.
//!
//! # In-place vs separate-buffer executors
//!
//! - **E8 / E8E9** transform in place: libarchive's
//!   `execute_filter_e8` operates on `vm->memory[0..length]` and
//!   leaves the result at the same address. We pass the LZ
//!   output buffer's slice directly to [`super::execute_e8`].
//! - **DELTA / RGB / AUDIO** read from `vm->memory[0..length]`
//!   and write to `vm->memory[length..2*length]`. We allocate a
//!   transient destination [`Vec<u8>`] and copy the result back
//!   into the LZ output buffer after the executor returns.
//!
//! # Filter ordering + chaining
//!
//! Filters apply in declaration order (FIFO). Subsequent filters
//! see the *current* buffer state, so a filter whose range
//! overlaps an earlier filter's range sees the earlier filter's
//! output as its input — which is exactly what libarchive's
//! same-`blockstartpos` chain logic (lines 3492..3517) does for
//! filters stacked at the same start. The round-one corpus has
//! no chaining cases, but the in-place ordering is the right
//! shape for when they arrive.

use thiserror::Error;

use super::parse::{FilterDeclaration, FilterStack, ProgramClassification};
use super::standard::{
    execute_audio, execute_delta, execute_e8, execute_rgb, FilterExecError, StandardFilter,
};

/// Errors surfaced by [`apply_pending_filters_in_place`].
#[derive(Debug, Error)]
pub enum DispatchError {
    /// The filter's `block_start + block_length` extends past the
    /// LZ output buffer's length. libarchive's `expand` at
    /// `archive_read_support_format_rar.c` line 3446 guarantees
    /// the LZ has produced enough bytes before the filter fires;
    /// our all-at-once dispatcher relies on the caller to have
    /// produced at least `unpacked_size` bytes of LZ output
    /// before invoking us.
    #[error(
        "legacy RAR VM dispatch: filter block_start={block_start} + block_length={block_length} \
         exceeds LZ output buffer length {output_len}"
    )]
    BlockBeyondOutput {
        /// `filter.block_start`.
        block_start: u64,
        /// `filter.block_length`.
        block_length: u32,
        /// LZ output buffer length at dispatch time.
        output_len: usize,
    },

    /// A pending filter's program wasn't one of the five WinRAR
    /// standard filters (DELTA / E8 / E8E9 / RGB / AUDIO).
    /// libarchive surfaces this case as
    /// `"No support for RAR VM program filter"` (line 3889). A
    /// future §C2-extension will land a full VM interpreter for
    /// archive-supplied bytecode; until then the standard set
    /// covers everything WinRAR's encoder produces in practice.
    #[error(
        "legacy RAR VM dispatch: custom filter bytecode (fingerprint 0x{fingerprint:010X}, \
         {bytecode_len} bytes) not yet supported"
    )]
    UnsupportedCustomFilter {
        /// The program's `crc32 | (len << 32)` fingerprint.
        fingerprint: u64,
        /// The program's bytecode length, in bytes.
        bytecode_len: usize,
    },

    /// The standard-filter executor rejected the filter
    /// parameters. Wraps the source-of-truth
    /// [`FilterExecError`] from [`super::standard`].
    #[error(transparent)]
    Executor(#[from] FilterExecError),
}

/// Run every filter declaration the stack has accumulated against
/// `buffer`, transforming `buffer[start..start+length]` in place
/// for each filter in FIFO order. `buffer` is the LZ output
/// (the raw post-decompression byte stream the encoder asked
/// the decoder to produce); after this function returns, the
/// per-filter ranges contain the filtered emit-stream bytes,
/// and the stack's pending queue is cleared.
///
/// Each filter consumes (and may not preserve) the previous
/// filters' output — filter `i`'s input is read from
/// `buffer` *after* filters `0..i` have run, so a chain of
/// filters at the same `block_start` pipelines as libarchive's
/// `run_filters` chain consumption (lines 3492..3517) does.
///
/// # Errors
///
/// - [`DispatchError::BlockBeyondOutput`] if any filter's
///   `block_start + block_length` extends past `buffer.len()`.
/// - [`DispatchError::UnsupportedCustomFilter`] if the filter's
///   program isn't one of the five WinRAR standard filters.
/// - [`DispatchError::Executor`] wrapping the underlying
///   [`FilterExecError`] from the native executor (parameter
///   range checks).
pub fn apply_pending_filters_in_place(
    stack: &mut FilterStack,
    buffer: &mut [u8],
) -> Result<(), DispatchError> {
    let pending = core::mem::take(&mut stack.pending);
    for filter in &pending {
        let program = &stack.programs[filter.program_index as usize];
        apply_one(filter, program, buffer)?;
    }
    Ok(())
}

/// Apply one filter declaration against `buffer` in place.
/// Helper for [`apply_pending_filters_in_place`]; exposed for
/// tests that exercise individual executors against
/// hand-crafted declarations.
///
/// # Errors
///
/// Same set as [`apply_pending_filters_in_place`].
pub fn apply_one(
    filter: &FilterDeclaration,
    program: &super::parse::Program,
    buffer: &mut [u8],
) -> Result<(), DispatchError> {
    let start = filter.block_start as usize;
    let length = filter.block_length as usize;
    let end = start
        .checked_add(length)
        .ok_or(DispatchError::BlockBeyondOutput {
            block_start: filter.block_start,
            block_length: filter.block_length,
            output_len: buffer.len(),
        })?;
    if end > buffer.len() {
        return Err(DispatchError::BlockBeyondOutput {
            block_start: filter.block_start,
            block_length: filter.block_length,
            output_len: buffer.len(),
        });
    }

    let standard = match program.classification {
        ProgramClassification::Standard(s) => s,
        ProgramClassification::Custom => {
            return Err(DispatchError::UnsupportedCustomFilter {
                fingerprint: program.fingerprint,
                bytecode_len: program.bytecode.len(),
            });
        }
    };

    match standard {
        StandardFilter::E8 => {
            execute_e8(&mut buffer[start..end], filter.block_start, false)?;
        }
        StandardFilter::E8E9 => {
            execute_e8(&mut buffer[start..end], filter.block_start, true)?;
        }
        StandardFilter::Delta => {
            // libarchive: src = vm.memory[0..length],
            //             dst = vm.memory[length..2*length].
            // We materialise dst in a scratch Vec, then copy
            // back over [start..end].
            let mut dst = vec![0u8; length];
            execute_delta(&buffer[start..end], &mut dst, filter.initial_registers[0])?;
            buffer[start..end].copy_from_slice(&dst);
        }
        StandardFilter::Rgb => {
            let mut dst = vec![0u8; length];
            execute_rgb(
                &buffer[start..end],
                &mut dst,
                filter.initial_registers[0],
                filter.initial_registers[1],
            )?;
            buffer[start..end].copy_from_slice(&dst);
        }
        StandardFilter::Audio => {
            let mut dst = vec![0u8; length];
            execute_audio(&buffer[start..end], &mut dst, filter.initial_registers[0])?;
            buffer[start..end].copy_from_slice(&dst);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::rar_legacy::vm::parse::{Program, ProgramClassification};
    use crate::decode::rar_legacy::vm::standard::{
        compute_program_fingerprint, recognize_standard_filter,
    };

    /// Build a `FilterStack` carrying a single fake "standard
    /// filter" pending declaration. The program is synthesised
    /// (no real bytecode); its classification is overridden to
    /// the requested standard filter so we can test the
    /// dispatcher without depending on real fingerprints. The
    /// fingerprint stays at the real value computed from the
    /// empty bytecode for diagnostic completeness.
    fn make_stack_with(
        std_filter: StandardFilter,
        block_start: u64,
        block_length: u32,
        reg0: u32,
        reg1: u32,
    ) -> FilterStack {
        let bytecode = Vec::new();
        let fingerprint = compute_program_fingerprint(&bytecode);
        // Should be `None` since the empty bytecode has a CRC
        // of 0 and no known program has fingerprint 0.
        assert!(recognize_standard_filter(fingerprint).is_none());
        let program = Program {
            bytecode,
            static_data: Vec::new(),
            fingerprint,
            classification: ProgramClassification::Standard(std_filter),
            usage_count: 0,
            old_filter_length: 0,
        };
        let mut initial_registers = [0u32; 8];
        initial_registers[0] = reg0;
        initial_registers[1] = reg1;
        let decl = FilterDeclaration {
            flags: 0,
            program_index: 0,
            block_start,
            block_length,
            initial_registers,
            global_data: Vec::new(),
        };
        FilterStack {
            programs: vec![program],
            last_filter_num: 0,
            pending: vec![decl],
        }
    }

    #[test]
    fn apply_pending_filters_rejects_block_beyond_buffer() {
        let mut stack = make_stack_with(StandardFilter::E8, 100, 200, 0, 0);
        let mut buf = vec![0u8; 50];
        let err =
            apply_pending_filters_in_place(&mut stack, &mut buf).expect_err("beyond rejected");
        assert!(matches!(err, DispatchError::BlockBeyondOutput { .. }));
    }

    #[test]
    fn apply_pending_filters_rejects_custom_bytecode() {
        let mut stack = make_stack_with(StandardFilter::E8, 0, 8, 0, 0);
        stack.programs[0].classification = ProgramClassification::Custom;
        let mut buf = vec![0u8; 8];
        let err =
            apply_pending_filters_in_place(&mut stack, &mut buf).expect_err("custom rejected");
        assert!(matches!(err, DispatchError::UnsupportedCustomFilter { .. }));
    }

    #[test]
    fn apply_pending_filters_runs_e8_in_place_and_clears_pending() {
        // Same shape as the standard.rs `execute_e8_rewrites_a_call_to_a_relative_offset`
        // test: 0xE8 at offset 5, absolute address 16 → relative
        // 16 - 6 = 10.
        let mut stack = make_stack_with(StandardFilter::E8, 0, 16, 0, 0);
        let mut buf = vec![0u8; 16];
        buf[5] = 0xE8;
        buf[6..10].copy_from_slice(&16u32.to_le_bytes());
        apply_pending_filters_in_place(&mut stack, &mut buf).unwrap();
        let rewritten = u32::from_le_bytes(buf[6..10].try_into().unwrap());
        assert_eq!(rewritten, 10);
        assert!(stack.pending.is_empty());
    }

    #[test]
    fn apply_pending_filters_runs_delta_via_destination_copy_back() {
        // Single-channel running difference, same fixture as the
        // standard.rs test: input encodes the running differences,
        // dispatcher applies DELTA in place over `buf[..]`.
        let bytes: [u8; 5] = [10, 20, 35, 50, 80];
        let mut encoded = [0u8; 5];
        let mut prev: u8 = 0;
        for (i, &b) in bytes.iter().enumerate() {
            encoded[i] = prev.wrapping_sub(b);
            prev = b;
        }
        let mut stack = make_stack_with(StandardFilter::Delta, 0, 5, 1, 0);
        let mut buf = encoded.to_vec();
        apply_pending_filters_in_place(&mut stack, &mut buf).unwrap();
        assert_eq!(buf, bytes);
    }

    #[test]
    fn apply_pending_filters_runs_multiple_filters_in_fifo_order() {
        // Two filters at adjacent block ranges, each E8. Verify
        // both run and pending is drained.
        let mut stack = make_stack_with(StandardFilter::E8, 0, 8, 0, 0);
        let second = FilterDeclaration {
            flags: 0,
            program_index: 0,
            block_start: 8,
            block_length: 8,
            initial_registers: [0u32; 8],
            global_data: Vec::new(),
        };
        stack.pending.push(second);
        let mut buf = vec![0u8; 16];
        // No 0xE8/0xE9 bytes → both filters are no-ops in
        // content terms but should still drain the queue.
        apply_pending_filters_in_place(&mut stack, &mut buf).unwrap();
        assert!(stack.pending.is_empty());
    }
}
