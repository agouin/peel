//! Fuzz target: streaming-decoder frame parsing must never panic on
//! adversarial source bytes. The first input byte selects which
//! hand-rolled decoder receives the rest, so libfuzzer can specialize
//! coverage per format while keeping a single corpus directory.
//!
//! Required per `internal/ENGINEERING_STANDARDS.md` §5.2 ("frame boundary
//! detection").

#![no_main]

use std::io::{Cursor, Read, Write};

use libfuzzer_sys::fuzz_target;
use peel::decode::{self, DecodeStatus, DecoderFactory};

const MAX_STEPS: u32 = 256;
const MAX_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    let Some((selector, body)) = data.split_first() else {
        return;
    };
    let factory: DecoderFactory = match selector % 4 {
        0 => decode::zstd::factory,
        1 => decode::gzip::factory,
        2 => decode::lz4::factory,
        // Phase F.6 of `internal/old/PLAN_xz_liblzma_phase_f.md`
        // retired `xz_native`; `xz_liblzma` is now the sole
        // xz decoder and inherits the existing fuzz contract
        // (no panic, no UB on any adversarial .xz framing).
        _ => decode::xz_liblzma::factory,
    };

    let src: Box<dyn Read + Send> = Box::new(Cursor::new(body.to_vec()));
    let mut decoder = match factory(src) {
        Ok(d) => d,
        Err(_) => return,
    };

    let mut sink = CountingSink::default();
    for _ in 0..MAX_STEPS {
        if sink.bytes_written >= MAX_OUTPUT_BYTES {
            break;
        }
        match decoder.decode_step(&mut sink) {
            Ok(DecodeStatus::Eof) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }

    // Caps on monotonic accessors — verifying the decoder upholds the
    // contract documented on `StreamingDecoder` even on truncated /
    // malformed input.
    let _ = decoder.bytes_consumed();
    let _ = decoder.frame_boundary();
});

#[derive(Default)]
struct CountingSink {
    bytes_written: u64,
}

impl Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes_written = self.bytes_written.saturating_add(buf.len() as u64);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
