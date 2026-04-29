//! `cargo run --example decode_demo -- <PATH>`
//!
//! Streams the named file through the registered decoder for its
//! suffix and writes the decompressed bytes to stdout. Doubles as the
//! demo for `docs/PLAN.md` §6 — proves the [`peel::decode`] surface
//! handles multi-frame `.zst` archives end-to-end and reports frame
//! boundaries.
//!
//! Usage:
//!
//! ```text
//! cargo run --example decode_demo -- /path/to/file.zst > /tmp/out.bin
//! ```

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::process::ExitCode;

use peel::decode::{DecodeStatus, DecoderRegistry};

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let Some(path) = args.next() else {
        eprintln!("usage: decode_demo <PATH>");
        return ExitCode::from(2);
    };
    let path: &Path = Path::new(&path);

    if let Err(e) = run(path) {
        eprintln!("error: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

fn run(path: &Path) -> Result<(), String> {
    let registry = DecoderRegistry::with_defaults();
    let factory = registry
        .factory_for_path(path)
        .ok_or_else(|| format!("no decoder registered for {}", path.display()))?;

    let file = File::open(path).map_err(|e| format!("opening {}: {e}", path.display()))?;
    let mut decoder = factory(Box::new(file)).map_err(|e| format!("decoder init: {e}"))?;

    let stdout = io::stdout();
    let mut sink = BufWriter::new(stdout.lock());

    let mut frame_count: u64 = 0;
    let mut last_boundary = None;
    loop {
        let status = decoder
            .decode_step(&mut sink)
            .map_err(|e| format!("decode: {e}"))?;
        let boundary = decoder.frame_boundary();
        if boundary != last_boundary {
            frame_count += 1;
            last_boundary = boundary;
            // Diagnostic to stderr so stdout remains a clean
            // decompressed byte stream — the user can pipe it into
            // another tool, or `> file` to capture it.
            if let Some(off) = boundary {
                eprintln!(
                    "[frame {frame_count}] boundary at source offset {} (consumed {})",
                    off,
                    decoder.bytes_consumed(),
                );
            }
        }
        if status == DecodeStatus::Eof {
            break;
        }
    }

    sink.flush().map_err(|e| format!("flushing stdout: {e}"))?;
    eprintln!(
        "[done] frames={frame_count} consumed={} bytes",
        decoder.bytes_consumed()
    );
    Ok(())
}
