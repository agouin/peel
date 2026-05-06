//! Fuzz target: tar header / PAX framing parser.
//!
//! `TarSink::write` is the only public entry into the streaming tar
//! parser; the actual header / checksum / PAX-record code paths are
//! private. To fuzz them we drive the public API: build a sink rooted
//! at a per-iteration tempdir, feed it the fuzzer-supplied bytes, then
//! tear the tempdir down. The tempdir overhead caps fuzz throughput,
//! but every iteration still exercises every framing code path the
//! parser walks (`process_header`, `validate_magic`, `validate_checksum`,
//! `parse_pax_records`, base-256 numeric parsing, …).
//!
//! Required per `docs/ENGINEERING_STANDARDS.md` §5.2 ("frame boundary
//! detection") for the tar format.

#![no_main]

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use libfuzzer_sys::fuzz_target;
use peel::sink::{Sink, TarSink};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fuzz_target!(|data: &[u8]| {
    let root = unique_tempdir();
    if std::fs::create_dir_all(&root).is_err() {
        return;
    }

    let result = (|| {
        let mut sink = TarSink::new(&root)?;
        // The streaming tar parser is required to handle arbitrary
        // chunk boundaries (`Sink::write` doc). One contiguous write
        // is the simplest path; libfuzzer's structural mutations
        // explore the boundary cases through the *content* of `data`
        // rather than its segmentation.
        sink.write(data)?;
        sink.close()
    })();

    // Errors are the expected outcome on adversarial input; the
    // assertion is the implicit "no panic / no abort". Drop the
    // tempdir regardless of result.
    let _ = result;
    let _ = std::fs::remove_dir_all(&root);
});

fn unique_tempdir() -> PathBuf {
    let pid = std::process::id();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("peel_fuzz_tar_{pid}_{n}"))
}
