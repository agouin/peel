//! Filter declaration parser for legacy RAR (RAR3 / RAR4) RarVM.
//!
//! `docs/PLAN_rar3.md` §C2a. The parser comes in two layers,
//! mirroring libarchive's `read_filter` (lines 3641..3688) and
//! `parse_filter` (lines 3258..3397):
//!
//! - **Wire layer** — [`read_filter_declaration_bytes`] reads the
//!   8-bit flag byte, the 0- / 1- / 2-byte length extension, and
//!   the `length`-byte bytecode payload straight off the LZ
//!   bitstream the LZ dispatcher was last reading. Returns a
//!   [`RawFilterDecl`] (flags + bytecode) for the caller to feed
//!   to the parse layer.
//! - **Parse layer** — [`parse_filter_declaration`] interprets
//!   the bytecode payload against an in-flight [`FilterStack`].
//!   The declaration may either declare a fresh program (with
//!   embedded bytecode + optional static-data blob) or reuse a
//!   previously-declared program by index; the parser handles
//!   both. Returns a [`FilterDeclaration`] carrying the
//!   per-invocation state (program index, block start, block
//!   length, initial registers, global data) that the §C2b
//!   dispatcher will apply.
//!
//! # Why two layers
//!
//! The wire layer's reads come off the outer
//! [`crate::decode::rar_legacy::bits::BitReader`] mid-LZ-block,
//! which means an underrun is a hard error (the LZ stream itself
//! is malformed). The parse layer's reads come off a memory bit
//! reader over the bytecode payload, which uses a soft-fail
//! underrun (sticky `at_eof`) — bytecode payloads may be
//! malformed independently of the surrounding LZ stream, and
//! libarchive treats them as a malformed-archive error rather
//! than a truncation. Keeping the two readers distinct also
//! keeps each layer's resume / diagnostic story local.
//!
//! # What this module does **not** do
//!
//! No filter execution. No filterstart / pending-invocation
//! queue management. Both of those land with §C2b, which is
//! where the live LZ → VM → filtered-output path actually fires.
//! Today the caller (§C1h's [`crate::decode::rar_legacy::entry::decode_entry`])
//! still surfaces a precise unsupported-filter error on
//! [`crate::decode::rar_legacy::lzss::BlockEnd::FilterDecl`]; the
//! parser surface lands here so §C2b has a stable consumer-side
//! API to plumb against.

use thiserror::Error;

use super::membits::{next_rarvm_number, MemBitReader};
use super::standard::{compute_program_fingerprint, recognize_standard_filter, StandardFilter};
use crate::decode::rar_legacy::bits::{BitReadError, BitReader};

/// VM working memory total size, in bytes. libarchive's
/// `VM_MEMORY_SIZE` constant (`archive_read_support_format_rar.c`
/// line 140). The address range `[0, VM_MEMORY_SIZE)` is split
/// into `[0, PROGRAM_WORK_SIZE)` for filter data, then
/// `[PROGRAM_WORK_SIZE, PROGRAM_WORK_SIZE + PROGRAM_SYSTEM_GLOBAL_SIZE)`
/// for VM-managed system globals, then the optional user-global
/// region beyond.
pub const VM_MEMORY_SIZE: u32 = 0x0004_0000;

/// Working-data region size inside [`VM_MEMORY_SIZE`].
/// libarchive's `PROGRAM_WORK_SIZE` (line 142). The actual
/// filter input/output buffer occupies the bottom of this
/// region; standard-filter executors that need a separate
/// destination buffer (DELTA, RGB, AUDIO) split it in half.
pub const PROGRAM_WORK_SIZE: u32 = 0x0003_C000;

/// Combined global-area size (system + user). libarchive's
/// `PROGRAM_GLOBAL_SIZE` (line 143).
pub const PROGRAM_GLOBAL_SIZE: u32 = 0x2000;

/// Address where the VM's system-managed global block lives.
/// libarchive's `PROGRAM_SYSTEM_GLOBAL_ADDRESS` (line 144).
/// Per-filter initial register 3 is set to this address.
pub const PROGRAM_SYSTEM_GLOBAL_ADDRESS: u32 = PROGRAM_WORK_SIZE;

/// Size of the VM's system-managed global block. libarchive's
/// `PROGRAM_SYSTEM_GLOBAL_SIZE` (line 145). The block carries
/// `initialregisters[0..7]`, `blocklength`, the
/// filtered-block-address/length pair, and the program
/// usage-count, all little-endian 32-bit at fixed offsets.
pub const PROGRAM_SYSTEM_GLOBAL_SIZE: u32 = 0x40;

/// Cap on the optional user-supplied global-data section.
/// libarchive's `PROGRAM_USER_GLOBAL_SIZE` (line 147).
/// Declarations with `flags & 0x08` carry a global-data payload;
/// libarchive rejects anything that wouldn't fit in this slot.
pub const PROGRAM_USER_GLOBAL_SIZE: u32 = PROGRAM_GLOBAL_SIZE - PROGRAM_SYSTEM_GLOBAL_SIZE;

/// Same as [`PROGRAM_USER_GLOBAL_SIZE`]. Re-named for the
/// global-data-length check; surfaces the constraint in error
/// messages without confusing the reader about which limit
/// applies where.
pub const MAX_GLOBAL_DATA_LEN: u32 = PROGRAM_USER_GLOBAL_SIZE;

/// Hard cap on an embedded program-bytecode payload. libarchive's
/// `parse_filter` check at line 3337. The encoder couldn't fit a
/// larger bytecode in the wire anyway (the `read_filter` length
/// field caps at 65535), but the parse-layer cap is independent.
pub const MAX_PROGRAM_LENGTH: u32 = 0x0001_0000;

/// Raw on-wire filter declaration: the 8-bit flag byte plus the
/// length-prefixed bytecode payload, exactly as
/// [`read_filter_declaration_bytes`] read them off the LZ bit
/// stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFilterDecl {
    /// 8-bit flag byte. Bits encode (low to high):
    /// - `0..=2` — length-field continuation (initial length =
    ///   `(flags & 7) + 1`; 7 → 1-byte extension, 8 → 2-byte
    ///   extension).
    /// - `3` (`0x08`) — global-data section follows.
    /// - `4` (`0x10`) — register-mask + register values follow.
    /// - `5` (`0x20`) — explicit block-length in the bytecode
    ///   (otherwise reuses the program's `old_filter_length`).
    /// - `6` (`0x40`) — block-start offset is biased by `+ 258`.
    /// - `7` (`0x80`) — program-cache index follows (otherwise
    ///   reuses `last_filter_num`).
    pub flags: u8,
    /// Bytecode payload bytes. `parse_filter_declaration` reads
    /// the encoded parameters from this buffer.
    pub bytecode: Vec<u8>,
}

/// Cached program in a [`FilterStack`].
///
/// Holds the bytecode + parsed static-data section, plus the
/// usage statistics libarchive's `compile_program` maintains.
/// `classification` records whether the program's fingerprint
/// matched one of the five WinRAR standard filters (DELTA / E8 /
/// E8E9 / RGB / AUDIO) or is a custom program that §C2b's VM
/// interpreter will eventually handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Program {
    /// The raw bytecode bytes (including the leading XOR-check
    /// byte at index 0).
    pub bytecode: Vec<u8>,
    /// Optional static-data section parsed out of the bytecode
    /// at compile time. Empty when the bytecode's leading
    /// has-static-data bit (`compile_program` line 3547) is
    /// clear.
    pub static_data: Vec<u8>,
    /// `crc32(bytecode) | (length << 32)`. libarchive's
    /// fingerprint shortcut for recognising standard filters.
    pub fingerprint: u64,
    /// Standard-filter recognition result. `Custom` means the
    /// fingerprint didn't match any of the five known programs
    /// and the VM interpreter (§C2b) would have to run the
    /// bytecode.
    pub classification: ProgramClassification,
    /// Number of times this program has been invoked since it
    /// was declared (or since the last cache clear). libarchive
    /// keeps it for register 5's initial value.
    pub usage_count: u32,
    /// Block length the most-recent invocation carried. When
    /// the next invocation omits its block-length field
    /// (`flags & 0x20 == 0`), the parser reuses this value.
    pub old_filter_length: u32,
}

/// Standard-filter recognition outcome for a [`Program`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramClassification {
    /// Recognised as one of the five WinRAR standard filter
    /// programs. The §C2b dispatcher can route the invocation
    /// to the corresponding native executor in
    /// [`super::standard`] and skip the VM interpreter.
    Standard(StandardFilter),
    /// Not recognised. §C2b's VM interpreter is the only path
    /// today; until that lands, custom programs surface as
    /// `Unsupported` at the entry layer.
    Custom,
}

/// One filter invocation parsed out of a [`RawFilterDecl`].
///
/// The `block_start` field is in the global LZ output stream's
/// coordinate space (libarchive's `blockstartpos`); the §C2b
/// dispatcher uses it to decide when to pause the LZ loop and
/// run the filter. `initial_registers` is the register file
/// state at filter entry, fully populated with libarchive's
/// system defaults (registers 3, 4, 5, 7) and any caller
/// overrides specified by `flags & 0x10`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterDeclaration {
    /// The flag byte from [`RawFilterDecl`], carried verbatim so
    /// §C2b doesn't have to thread it through separately.
    pub flags: u8,
    /// Index into [`FilterStack::programs`] of the program this
    /// invocation runs.
    pub program_index: u32,
    /// Absolute LZ-output position where the filter's input
    /// block starts.
    pub block_start: u64,
    /// Length of the filter's input block, in bytes.
    pub block_length: u32,
    /// Register file at filter entry. Registers 3 / 4 / 5 / 7
    /// are pre-populated with the libarchive defaults
    /// (`PROGRAM_SYSTEM_GLOBAL_ADDRESS` / block length / usage
    /// count / `VM_MEMORY_SIZE`). Registers 0..7 may be
    /// individually overridden by the `flags & 0x10` register-
    /// mask block.
    pub initial_registers: [u32; 8],
    /// Optional global-data block from `flags & 0x08`. Empty
    /// when the bit is clear; libarchive treats the empty case
    /// the same as a zero-length block.
    pub global_data: Vec<u8>,
}

/// Filter-program cache + last-filter cursor. libarchive's
/// `struct rar_filters` minus the pending-invocation queue and
/// `filterstart` (both deferred to §C2b — see the module-level
/// "what this does **not** do" note).
#[derive(Debug, Default)]
pub struct FilterStack {
    /// Cache of declared programs, indexed by declaration
    /// order. libarchive's `filters->progs` linked list; we use
    /// a vector because the index lookups are O(N) regardless.
    pub programs: Vec<Program>,
    /// Most-recent program index referenced by a declaration.
    /// libarchive's `lastfilternum`. When a subsequent
    /// declaration's `flags & 0x80` bit is clear, the parser
    /// reuses this index instead of reading a fresh one off the
    /// bytecode.
    pub last_filter_num: u32,
    /// Filter invocations queued by [`parse_filter_declaration`]
    /// and waiting to be applied to the LZ output buffer by
    /// [`super::dispatch::apply_pending_filters_in_place`].
    /// libarchive maintains the same FIFO queue as
    /// `filters->stack` (lines 268..278 of
    /// `archive_read_support_format_rar.c`); we use a `Vec`
    /// because front-to-back FIFO consumption is the only
    /// operation that hits the queue.
    pub pending: Vec<FilterDeclaration>,
}

impl FilterStack {
    /// Construct an empty stack. Equivalent to
    /// `FilterStack::default()`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Discard every cached program, every pending invocation,
    /// and reset the last-filter cursor. libarchive's behaviour
    /// when the bytecode encodes a `flags & 0x80` cache index of
    /// zero (`parse_filter` lines 3283..3288).
    pub fn clear(&mut self) {
        self.programs.clear();
        self.last_filter_num = 0;
        self.pending.clear();
    }
}

/// Errors surfaced by the wire- and parse-layer entry points.
#[derive(Debug, Error)]
pub enum VmParseError {
    /// The LZ bit stream ran out while
    /// [`read_filter_declaration_bytes`] was reading the
    /// flag-byte / length-extension / bytecode payload.
    /// Wraps the underlying [`BitReadError`] so the caller can
    /// preserve the cursor-at-underrun diagnostic.
    #[error(transparent)]
    Bitstream(#[from] BitReadError),

    /// The wire's length field decoded to zero. Only the
    /// 2-byte-extension branch (`flags & 7 == 7`) can produce
    /// this — every other path's `length` starts at 1 or more.
    /// libarchive happily mallocs a zero-byte buffer here; we
    /// treat it as malformed because a zero-length bytecode can
    /// carry no parameters.
    #[error("legacy RAR VM: filter declaration has zero-length bytecode")]
    ZeroLengthBytecode,

    /// The wire's length field decoded to a value larger than
    /// the 16-bit field can encode. Only the 1-byte-extension
    /// branch (`flags & 7 == 6` → length up to 262) and the
    /// 2-byte-extension branch (length up to 65535) can hit this
    /// in practice; the constant cap is here for symmetry with
    /// the parse-layer's [`MAX_PROGRAM_LENGTH`] cap on embedded
    /// program bytecode.
    #[error("legacy RAR VM: filter declaration length {got} exceeds the {MAX_PROGRAM_LENGTH} cap")]
    DeclarationTooLong {
        /// The decoded wire length.
        got: u32,
    },

    /// The parse layer ran out of bytecode bytes while reading
    /// declaration parameters or an embedded program-bytecode /
    /// global-data section. libarchive surfaces this via the
    /// sticky `at_eof` flag on the memory bit reader (lines
    /// 3371..3375); we mirror that.
    #[error("legacy RAR VM: filter declaration bytecode under-supplied parameters")]
    BytecodeUnderrun,

    /// `flags & 0x80` referenced a program-cache index that is
    /// beyond the current cache size. libarchive's
    /// `if (num > numprogs)` check at line 3292.
    #[error(
        "legacy RAR VM: filter declaration referenced program index {got}, only {programs} declared"
    )]
    ProgramIndexOutOfRange {
        /// Program index requested by the wire (1-based, before
        /// libarchive's `num--` adjustment).
        got: u32,
        /// Programs declared so far.
        programs: u32,
    },

    /// The embedded program-bytecode length field was either 0
    /// or beyond [`MAX_PROGRAM_LENGTH`]. libarchive's
    /// `if (len == 0 || len > 0x10000)` check at line 3337.
    #[error("legacy RAR VM: embedded program length {got} out of range 1..={MAX_PROGRAM_LENGTH}")]
    ProgramLengthOutOfRange {
        /// The wire-decoded program length.
        got: u32,
    },

    /// The embedded program's static-data section claimed a
    /// length beyond [`MAX_PROGRAM_LENGTH`]. libarchive doesn't
    /// explicitly bounds-check this in `compile_program` (lines
    /// 3547..3558) — the memory bit reader's soft-fail just
    /// returns zeros past the buffer end — but a Vec allocation
    /// the size of the wire-encoded `staticdatalen + 1` value
    /// could be massive, so we cap it.
    #[error(
        "legacy RAR VM: program static-data length {got} out of range 1..={MAX_PROGRAM_LENGTH}"
    )]
    ProgramStaticDataTooLong {
        /// The wire-decoded static-data length.
        got: u32,
    },

    /// The embedded program's XOR-checksum byte (the first byte
    /// of the bytecode) didn't match the XOR of the remaining
    /// bytes. libarchive's `compile_program` rejects on this
    /// check (lines 3532..3536).
    #[error(
        "legacy RAR VM: program XOR-checksum mismatch (header byte 0x{expected:02X}, computed 0x{computed:02X})"
    )]
    ProgramChecksumMismatch {
        /// The XOR-checksum byte from the wire (bytecode\[0\]).
        expected: u8,
        /// The XOR of the remaining bytes (`bytecode[1..]`).
        computed: u8,
    },

    /// The optional global-data section's length field decoded
    /// to a value beyond [`MAX_GLOBAL_DATA_LEN`]. libarchive's
    /// `if (globaldatalen > PROGRAM_USER_GLOBAL_SIZE)` check at
    /// line 3362.
    #[error("legacy RAR VM: global-data length {got} exceeds the {MAX_GLOBAL_DATA_LEN} cap")]
    GlobalDataTooLong {
        /// The wire-decoded global-data length.
        got: u32,
    },
}

/// Read a raw filter declaration off the LZ bit stream.
///
/// The LZ dispatcher returns
/// [`crate::decode::rar_legacy::lzss::BlockEnd::FilterDecl`] when it
/// encounters symbol 257 in the main alphabet. The caller is then
/// responsible for calling this function on the same
/// [`BitReader`] to consume the on-wire (flag, length-extension,
/// bytecode) triple. libarchive's `read_filter` at lines
/// 3641..3688.
///
/// Wire layout:
///
/// 1. **Flag byte** (8 bits) — see [`RawFilterDecl::flags`].
/// 2. **Length** — initial value is `(flags & 7) + 1`, range
///    `1..=8`. If it equals 7, a 1-byte extension follows and
///    `length = ext + 7`. If it equals 8, a 2-byte
///    big-endian extension follows and `length = (hi << 8) | lo`.
/// 3. **Bytecode** — `length` raw bytes pulled via 8-bit reads
///    from the same stream.
///
/// # Errors
///
/// - [`VmParseError::Bitstream`] if the LZ bit stream
///   under-supplies any of the above reads.
/// - [`VmParseError::ZeroLengthBytecode`] if the wire's length
///   field decoded to zero (the 2-byte-extension branch's
///   degenerate case).
/// - [`VmParseError::DeclarationTooLong`] if the length field
///   decoded above [`MAX_PROGRAM_LENGTH`]. (Only the 2-byte
///   branch can in principle exceed 65535, and the wire encodes
///   it as a `u16` so this is largely defensive.)
pub fn read_filter_declaration_bytes(
    reader: &mut BitReader<'_>,
) -> Result<RawFilterDecl, VmParseError> {
    let flags = reader.read_bits(8)? as u8;
    let mut length: u32 = (u32::from(flags) & 0x07) + 1;
    if length == 7 {
        let ext = reader.read_bits(8)?;
        length = ext + 7;
    } else if length == 8 {
        let hi = reader.read_bits(8)?;
        let lo = reader.read_bits(8)?;
        length = (hi << 8) | lo;
    }
    if length == 0 {
        return Err(VmParseError::ZeroLengthBytecode);
    }
    if length > MAX_PROGRAM_LENGTH {
        return Err(VmParseError::DeclarationTooLong { got: length });
    }
    let mut bytecode = Vec::with_capacity(length as usize);
    for _ in 0..length {
        bytecode.push(reader.read_bits(8)? as u8);
    }
    Ok(RawFilterDecl { flags, bytecode })
}

/// Parse a [`RawFilterDecl`] into a [`FilterDeclaration`],
/// updating `stack` as needed.
///
/// `lzss_position` is the LZ output position at the moment the
/// declaration fired (i.e. the value
/// [`crate::decode::rar_legacy::lzss::LzDecoder::output_position`]
/// returns when the LZ dispatcher surfaces
/// [`crate::decode::rar_legacy::lzss::BlockEnd::FilterDecl`]).
/// libarchive folds it into the bytecode-encoded `blockstartpos`
/// at line 3306. The §C2b dispatcher needs the absolute LZ
/// coordinate to decide when to pause the LZ loop and apply the
/// filter.
///
/// # Errors
///
/// Every parse-layer variant of [`VmParseError`]. The
/// wire-layer's [`VmParseError::Bitstream`] /
/// [`VmParseError::ZeroLengthBytecode`] /
/// [`VmParseError::DeclarationTooLong`] cannot fire here —
/// those are surfaced only by [`read_filter_declaration_bytes`].
pub fn parse_filter_declaration(
    stack: &mut FilterStack,
    raw: &RawFilterDecl,
    lzss_position: u64,
) -> Result<FilterDeclaration, VmParseError> {
    let mut br = MemBitReader::new(&raw.bytecode);
    let flags = raw.flags;

    let num = if flags & 0x80 != 0 {
        let encoded = next_rarvm_number(&mut br);
        if encoded == 0 {
            stack.clear();
            // After the clear, num == 0 and the program cache
            // is empty: this declaration must include a fresh
            // program bytecode. The `prog_exists` check below
            // handles that by falling into the embedded-program
            // branch.
            0
        } else {
            let one_based = encoded;
            let zero_based = encoded - 1;
            let programs = stack.programs.len() as u32;
            if zero_based > programs {
                return Err(VmParseError::ProgramIndexOutOfRange {
                    got: one_based,
                    programs,
                });
            }
            stack.last_filter_num = zero_based;
            zero_based
        }
    } else {
        stack.last_filter_num
    };

    let prog_exists = (num as usize) < stack.programs.len();
    if prog_exists {
        // libarchive: `if (prog) prog->usagecount++`. The
        // freshly-declared program below inherits the
        // `usage_count = 0` default; the next invocation that
        // references it will bump usagecount to 1, matching
        // libarchive.
        stack.programs[num as usize].usage_count =
            stack.programs[num as usize].usage_count.saturating_add(1);
    }

    let raw_block_start = next_rarvm_number(&mut br);
    let mut block_start = u64::from(raw_block_start).wrapping_add(lzss_position);
    if flags & 0x40 != 0 {
        block_start = block_start.wrapping_add(258);
    }

    let block_length = if flags & 0x20 != 0 {
        next_rarvm_number(&mut br)
    } else if prog_exists {
        stack.programs[num as usize].old_filter_length
    } else {
        0
    };

    let mut initial_registers = [0u32; 8];
    initial_registers[3] = PROGRAM_SYSTEM_GLOBAL_ADDRESS;
    initial_registers[4] = block_length;
    initial_registers[5] = if prog_exists {
        stack.programs[num as usize].usage_count
    } else {
        0
    };
    initial_registers[7] = VM_MEMORY_SIZE;

    if flags & 0x10 != 0 {
        let mask = br.bits(7) as u8;
        for (i, reg) in initial_registers.iter_mut().take(7).enumerate() {
            if mask & (1 << i) != 0 {
                *reg = next_rarvm_number(&mut br);
            }
        }
    }

    if !prog_exists {
        let len = next_rarvm_number(&mut br);
        if len == 0 || len > MAX_PROGRAM_LENGTH {
            return Err(VmParseError::ProgramLengthOutOfRange { got: len });
        }
        let mut prog_bytes = Vec::with_capacity(len as usize);
        for _ in 0..len {
            prog_bytes.push(br.bits(8) as u8);
        }
        let computed_xor = prog_bytes[1..].iter().fold(0u8, |acc, b| acc ^ b);
        let expected_xor = prog_bytes[0];
        if computed_xor != expected_xor {
            return Err(VmParseError::ProgramChecksumMismatch {
                expected: expected_xor,
                computed: computed_xor,
            });
        }
        // The bytecode is itself a bitstream starting one byte
        // past the XOR check. libarchive's `compile_program`
        // (lines 3538..3558) reads an optional has-static-data
        // bit, then if set, a length-prefixed static-data block.
        // Both reads come off a fresh memory bit reader over
        // the bytecode at offset 1.
        let mut prog_br = MemBitReader::new_at(&prog_bytes, 1);
        let static_data = if prog_br.bits(1) == 1 {
            let static_len = next_rarvm_number(&mut prog_br).wrapping_add(1);
            if static_len == 0 || static_len > MAX_PROGRAM_LENGTH {
                return Err(VmParseError::ProgramStaticDataTooLong { got: static_len });
            }
            let mut sd = Vec::with_capacity(static_len as usize);
            for _ in 0..static_len {
                sd.push(prog_br.bits(8) as u8);
            }
            if prog_br.at_eof() {
                return Err(VmParseError::BytecodeUnderrun);
            }
            sd
        } else {
            Vec::new()
        };
        let fingerprint = compute_program_fingerprint(&prog_bytes);
        let classification = match recognize_standard_filter(fingerprint) {
            Some(std) => ProgramClassification::Standard(std),
            None => ProgramClassification::Custom,
        };
        stack.programs.push(Program {
            bytecode: prog_bytes,
            static_data,
            fingerprint,
            classification,
            usage_count: 0,
            old_filter_length: 0,
        });
    }

    let prog_index = num as usize;
    stack.programs[prog_index].old_filter_length = block_length;

    let global_data = if flags & 0x08 != 0 {
        let globaldatalen = next_rarvm_number(&mut br);
        if globaldatalen > MAX_GLOBAL_DATA_LEN {
            return Err(VmParseError::GlobalDataTooLong { got: globaldatalen });
        }
        let mut gd = Vec::with_capacity(globaldatalen as usize);
        for _ in 0..globaldatalen {
            gd.push(br.bits(8) as u8);
        }
        gd
    } else {
        Vec::new()
    };

    if br.at_eof() {
        return Err(VmParseError::BytecodeUnderrun);
    }

    let decl = FilterDeclaration {
        flags,
        program_index: num,
        block_start,
        block_length,
        initial_registers,
        global_data,
    };
    // Mirror libarchive's `parse_filter` lines 3388..3394:
    // queue the invocation FIFO-style on the filter stack so
    // [`super::dispatch::apply_pending_filters_in_place`] can
    // consume it after LZ decoding completes. The caller still
    // receives a copy of the declaration for diagnostics /
    // synchronous inspection (e.g. tests).
    stack.pending.push(decl.clone());
    Ok(decl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::rar_legacy::bits::BitReader;

    /// Pack a sequence of `(value, width)` pairs MSB-first into
    /// a byte buffer. Same shape as the helper in `membits.rs`'
    /// tests; local copy keeps the test modules independent.
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
    fn read_filter_declaration_small_length_inlined_in_flags() {
        // flags = 0x80 | 0x00 | 2 → 3-byte payload (length-1=2 +
        // 1 = 3). Bit 7 set means "program-index follows in
        // bytecode". 3 arbitrary payload bytes follow.
        let mut wire = vec![0x80 | 0x02];
        wire.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        let mut br = BitReader::new(&wire);
        let raw = read_filter_declaration_bytes(&mut br).unwrap();
        assert_eq!(raw.flags, 0x82);
        assert_eq!(raw.bytecode, &[0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn read_filter_declaration_one_byte_length_extension() {
        // flags & 7 == 6 → length = 7. Now wire `7` again to
        // mean length = 7 + 7 = 14.
        let mut wire = vec![0x06, 7];
        for i in 0..14u8 {
            wire.push(i);
        }
        let mut br = BitReader::new(&wire);
        let raw = read_filter_declaration_bytes(&mut br).unwrap();
        assert_eq!(raw.flags, 0x06);
        assert_eq!(raw.bytecode.len(), 14);
        assert_eq!(raw.bytecode[0], 0);
        assert_eq!(raw.bytecode[13], 13);
    }

    #[test]
    fn read_filter_declaration_two_byte_length_extension() {
        // flags & 7 == 7 → length = 8 base; 2-byte big-endian
        // extension: 0x01 0x02 → length = 0x0102 = 258.
        let mut wire = vec![0x07, 0x01, 0x02];
        wire.extend(std::iter::repeat_n(0xDE, 258));
        let mut br = BitReader::new(&wire);
        let raw = read_filter_declaration_bytes(&mut br).unwrap();
        assert_eq!(raw.flags, 0x07);
        assert_eq!(raw.bytecode.len(), 258);
        assert_eq!(raw.bytecode.first(), Some(&0xDE));
        assert_eq!(raw.bytecode.last(), Some(&0xDE));
    }

    #[test]
    fn read_filter_declaration_zero_length_rejected() {
        // flags & 7 == 7 → length = 8; extension 0x00 0x00 →
        // length = 0. We reject as malformed.
        let wire = [0x07, 0x00, 0x00];
        let mut br = BitReader::new(&wire);
        let err = read_filter_declaration_bytes(&mut br).expect_err("zero-length rejected");
        assert!(matches!(err, VmParseError::ZeroLengthBytecode));
    }

    #[test]
    fn read_filter_declaration_propagates_bitstream_underrun() {
        // Single byte for the flags + length-extension claim
        // expects more bytes than exist.
        let wire = [0x06];
        let mut br = BitReader::new(&wire);
        let err = read_filter_declaration_bytes(&mut br).expect_err("underrun");
        assert!(matches!(err, VmParseError::Bitstream(_)));
    }

    /// Build a filter declaration that:
    /// - Uses `flags = 0x80` (program-index in bytecode).
    /// - References program 0 with a fresh bytecode payload
    ///   (`program_index 0 == numprogs`, falls into the new-
    ///   program branch).
    /// - Carries no register-mask, no explicit block-length
    ///   (uses `old_filter_length = 0`), no global-data.
    fn build_new_program_decl(program_bytecode: &[u8]) -> RawFilterDecl {
        // bytecode layout (in the membr stream):
        //   - next_rarvm_number(num)  = 1   (tag 00, value 1)
        //   - next_rarvm_number(start) = 0  (tag 00, value 0)
        //   - next_rarvm_number(len)  = len (tag depends on len)
        //   - then `len` raw program bytecode bytes.
        let mut pairs: Vec<(u32, u32)> = vec![
            (0b00, 2), // num = 1 (one-based, refers to the 0th program slot).
            (1, 4),
            (0b00, 2), // blockstartpos = 0 (4-bit value form).
            (0, 4),
        ];
        // len — for len < 16, tag 0 + 4-bit; for len ≤ 0xFF
        // (and >= 16), tag 1 + 8-bit; …
        let len = program_bytecode.len() as u32;
        if len < 16 {
            pairs.push((0b00, 2));
            pairs.push((len, 4));
        } else if len <= 0xFF {
            pairs.push((0b01, 2));
            pairs.push((len, 8));
        } else if len <= 0xFFFF {
            pairs.push((0b10, 2));
            pairs.push((len, 16));
        } else {
            pairs.push((0b11, 2));
            pairs.push((len, 32));
        }
        for &b in program_bytecode {
            pairs.push((u32::from(b), 8));
        }
        RawFilterDecl {
            flags: 0x80,
            bytecode: pack_msb(&pairs),
        }
    }

    /// XOR-balanced program bytecode: byte 0 is XOR(byte 1..n).
    /// The remaining bytes encode a single has-static-data=0
    /// bit, which the parse layer reads via the bytecode's
    /// inner membr.
    fn xor_balanced_program(payload: &[u8]) -> Vec<u8> {
        let xor = payload.iter().fold(0u8, |acc, &b| acc ^ b);
        let mut out = vec![xor];
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn parse_filter_declaration_accepts_a_well_formed_new_program() {
        // Inner program bytecode: header XOR byte + a single
        // 0x00 payload byte (which the inner membr reads as a
        // `has_static_data = 0` bit followed by padding).
        let prog = xor_balanced_program(&[0x00]);
        let raw = build_new_program_decl(&prog);
        let mut stack = FilterStack::new();
        let decl = parse_filter_declaration(&mut stack, &raw, 100).unwrap();
        assert_eq!(stack.programs.len(), 1);
        assert_eq!(decl.flags, 0x80);
        assert_eq!(decl.program_index, 0);
        assert_eq!(decl.block_start, 100); // 0 + lzss_position
        assert_eq!(decl.block_length, 0); // no explicit length, no prior
        assert_eq!(stack.last_filter_num, 0);
        // Register defaults libarchive populates.
        assert_eq!(decl.initial_registers[3], PROGRAM_SYSTEM_GLOBAL_ADDRESS);
        assert_eq!(decl.initial_registers[4], 0);
        assert_eq!(decl.initial_registers[5], 0);
        assert_eq!(decl.initial_registers[7], VM_MEMORY_SIZE);
        // Custom (no fingerprint match for our synthetic
        // payload).
        assert!(matches!(
            stack.programs[0].classification,
            ProgramClassification::Custom
        ));
    }

    #[test]
    fn parse_filter_declaration_rejects_xor_checksum_mismatch() {
        // Program bytecode whose header byte doesn't XOR the
        // remaining bytes.
        let prog = vec![0xFFu8, 0x01, 0x02];
        let raw = build_new_program_decl(&prog);
        let mut stack = FilterStack::new();
        let err = parse_filter_declaration(&mut stack, &raw, 0).expect_err("xor rejected");
        match err {
            VmParseError::ProgramChecksumMismatch { expected, computed } => {
                assert_eq!(expected, 0xFF);
                assert_eq!(computed, 0x03);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_filter_declaration_rejects_program_length_zero() {
        // Build a declaration with len = 0.
        let pairs: Vec<(u32, u32)> = vec![
            (0b00, 2),
            (1, 4), // num = 1 (new program slot)
            (0b00, 2),
            (0, 4), // blockstart = 0
            (0b00, 2),
            (0, 4), // len = 0 — should be rejected.
        ];
        let raw = RawFilterDecl {
            flags: 0x80,
            bytecode: pack_msb(&pairs),
        };
        let mut stack = FilterStack::new();
        let err = parse_filter_declaration(&mut stack, &raw, 0).expect_err("zero-length rejected");
        assert!(matches!(
            err,
            VmParseError::ProgramLengthOutOfRange { got: 0 }
        ));
    }

    #[test]
    fn parse_filter_declaration_rejects_program_index_past_cache_end() {
        // flags = 0x80, num = 5 (one-based). Cache is empty, so
        // zero_based = 4 > programs (0) → out of range.
        let pairs: Vec<(u32, u32)> = vec![(0b00, 2), (5, 4)];
        let raw = RawFilterDecl {
            flags: 0x80,
            bytecode: pack_msb(&pairs),
        };
        let mut stack = FilterStack::new();
        let err = parse_filter_declaration(&mut stack, &raw, 0).expect_err("out-of-range rejected");
        match err {
            VmParseError::ProgramIndexOutOfRange { got, programs } => {
                assert_eq!(got, 5);
                assert_eq!(programs, 0);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn parse_filter_declaration_zero_num_clears_program_cache() {
        // First declare a program so the cache is non-empty.
        let prog = xor_balanced_program(&[0x00]);
        let raw = build_new_program_decl(&prog);
        let mut stack = FilterStack::new();
        parse_filter_declaration(&mut stack, &raw, 0).unwrap();
        assert_eq!(stack.programs.len(), 1);
        // Now send a declaration with num = 0 (cache clear) +
        // a fresh program.
        let mut pairs: Vec<(u32, u32)> = vec![
            (0b00, 2),
            (0, 4), // num = 0 → clear cache.
            (0b00, 2),
            (0, 4), // blockstart = 0
        ];
        // After clearing, num == 0 falls into the new-program
        // branch (program_index 0 == numprogs == 0).
        let prog2 = xor_balanced_program(&[0x00]);
        let len = prog2.len() as u32;
        if len < 16 {
            pairs.push((0b00, 2));
            pairs.push((len, 4));
        } else {
            pairs.push((0b01, 2));
            pairs.push((len, 8));
        }
        for &b in &prog2 {
            pairs.push((u32::from(b), 8));
        }
        let raw2 = RawFilterDecl {
            flags: 0x80,
            bytecode: pack_msb(&pairs),
        };
        parse_filter_declaration(&mut stack, &raw2, 50).unwrap();
        assert_eq!(stack.programs.len(), 1);
    }

    #[test]
    fn parse_filter_declaration_reuse_path_uses_last_filter_num() {
        // First declare a program with flags = 0x80.
        let prog = xor_balanced_program(&[0x00]);
        let raw = build_new_program_decl(&prog);
        let mut stack = FilterStack::new();
        parse_filter_declaration(&mut stack, &raw, 0).unwrap();
        assert_eq!(stack.last_filter_num, 0);
        // Now a flags == 0 declaration that omits the index
        // (should reuse last_filter_num) and the program already
        // exists in the cache.
        let pairs: Vec<(u32, u32)> = vec![(0b00, 2), (10, 4)];
        let raw2 = RawFilterDecl {
            flags: 0,
            bytecode: pack_msb(&pairs),
        };
        let decl2 = parse_filter_declaration(&mut stack, &raw2, 1000).unwrap();
        assert_eq!(decl2.program_index, 0);
        assert_eq!(decl2.block_start, 10 + 1000);
        // usage_count bumped from 0 to 1 on this reuse.
        assert_eq!(stack.programs[0].usage_count, 1);
        // Register 5 should still reflect the *previous*
        // (pre-bump) usage_count of 0, matching libarchive's
        // `prog->usagecount++` ordering at line 3304 — but
        // libarchive captures `prog->usagecount` *after* the
        // increment for register 5 at line 3320. We do the
        // same.
        assert_eq!(decl2.initial_registers[5], 1);
    }

    #[test]
    fn parse_filter_declaration_block_start_offset_bias() {
        let prog = xor_balanced_program(&[0x00]);
        let raw_template = build_new_program_decl(&prog);
        // Bias the flag byte to include the +258 bit.
        let mut raw = raw_template.clone();
        raw.flags = 0x80 | 0x40;
        let mut stack = FilterStack::new();
        let decl = parse_filter_declaration(&mut stack, &raw, 1000).unwrap();
        assert_eq!(decl.block_start, 1000 + 258);
    }
}
