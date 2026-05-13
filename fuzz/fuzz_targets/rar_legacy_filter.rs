//! Fuzz target: legacy RAR (RAR3 / RAR4) RarVM filter declaration
//! parser + standard-filter dispatcher.
//!
//! `internal/PLAN_rar3.md` §C2c. The §C2a/§C2b parser is the first
//! place in `rar_legacy` where attacker-controlled bytecode
//! (the `symbol 257` filter-declaration payload) feeds a state
//! machine that allocates, validates a fingerprint, and routes
//! to native executors. The standard-filter executors (DELTA /
//! E8 / E8E9 / RGB / AUDIO) take parameters straight off the
//! filter declaration; the RGB and DELTA paths each take a
//! `num_channels` / `stride` value that could be hostile.
//!
//! Coverage:
//!
//! - **Selector `0`** — pure parse path: drive the wire-side
//!   [`read_filter_declaration_bytes`] with random bytes and
//!   pass the result (if any) through
//!   [`parse_filter_declaration`]. Exercises the bit reader's
//!   underrun handling, the bytecode `next_rarvm_number`
//!   decoder, the XOR-checksum check, and every flag-bit branch
//!   of the parser.
//! - **Selector `1`** — parse + classify + dispatch over a
//!   short hostile output buffer: even if the parser accepts a
//!   declaration, the dispatcher's range checks
//!   (`block_start + block_length <= buffer.len()`) must hold,
//!   and the standard-filter executors' parameter validation
//!   (zero channels, RGB bad params, E8 too short) must fire
//!   before any memory access.
//!
//! Required per `internal/ENGINEERING_STANDARDS.md` §5.2 — extends
//! the §C2 deliverable from "decode-only standard filters" to
//! "decode-only standard filters that don't panic on adversarial
//! input". The fuzzer's invariant is **no panics, no
//! out-of-bounds accesses**: every malformed declaration must
//! surface a typed error or be silently skipped.

#![no_main]

use libfuzzer_sys::fuzz_target;
use peel::decode::rar_legacy::bits::BitReader;
use peel::decode::rar_legacy::vm::{
    apply_pending_filters_in_place, parse_filter_declaration, read_filter_declaration_bytes,
    FilterStack,
};

fuzz_target!(|data: &[u8]| {
    let Some((selector, body)) = data.split_first() else {
        return;
    };

    match selector % 2 {
        0 => {
            // Pure parse path. The wire-layer reader pulls
            // (flag, length, bytecode) off the bit stream;
            // the parse-layer interprets the bytecode against
            // a fresh stack.
            let mut br = BitReader::new(body);
            let Ok(raw) = read_filter_declaration_bytes(&mut br) else {
                return;
            };
            let mut stack = FilterStack::new();
            // `lzss_position` is fuzzer-irrelevant for the
            // parse-side invariants; pick 0 to keep the
            // bytecode-encoded block_start values dominant.
            let _ = parse_filter_declaration(&mut stack, &raw, 0);
        }
        _ => {
            // Parse + dispatch. The dispatcher's range checks
            // and the standard-filter executors' parameter
            // validation are the second-line defence the
            // parse-only fuzz target doesn't reach. We cap the
            // output buffer at 4 KiB so the fuzzer can probe
            // the BlockBeyondOutput branch without consuming
            // unbounded memory.
            let mut br = BitReader::new(body);
            let Ok(raw) = read_filter_declaration_bytes(&mut br) else {
                return;
            };
            let mut stack = FilterStack::new();
            if parse_filter_declaration(&mut stack, &raw, 0).is_err() {
                return;
            }
            // Cap pending invocations so the fuzzer can't
            // synthesise a single declaration that asks us to
            // run thousands of filters. Real-archive filter
            // counts per entry are in single digits.
            if stack.pending.len() > 8 {
                return;
            }
            let mut buffer = vec![0u8; 4096];
            let _ = apply_pending_filters_in_place(&mut stack, &mut buffer);
        }
    }
});
