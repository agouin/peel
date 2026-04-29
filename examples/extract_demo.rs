//! `cargo run --example extract_demo -- <PATH> -C <DIR>`
//!
//! Drives [`peel::extractor::Extractor`] end-to-end against a local
//! `.tar.zst` (or any `.zst`) file: decoder + sink + puncher in one
//! loop. Doubles as the demo for `docs/PLAN.md` §8 — the source's
//! on-disk footprint shrinks as decoding advances, and stats are
//! printed on completion.
//!
//! Modes:
//!   --output-dir <DIR> / -C <DIR>   extract a tar archive into <DIR>
//!   --output-file <FILE> / -o <FILE>   stream raw bytes into <FILE>
//!
//! Optional flags:
//!   --punch-threshold <BYTES>  (default 4 MiB; lower = more frequent
//!                              punches, higher = fewer syscalls)
//!
//! Example:
//!   cargo run --release --example extract_demo -- \
//!       /tmp/dataset.tar.zst -C /tmp/dataset.out

#![cfg(unix)]

use std::fs::{self, File, OpenOptions};
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use peel::decode::{DecoderRegistry, StreamingDecoder};
use peel::extractor::{ExtractionStats, Extractor, ExtractorConfig, DEFAULT_PUNCH_THRESHOLD};
use peel::punch::{default_puncher, PunchHole};
use peel::sink::{RawSink, Sink, SinkError, TarSink};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse_args(&args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!(
                "usage: extract_demo <SOURCE.tar.zst> -C <OUTPUT_DIR>\n\
                 usage: extract_demo <SOURCE.zst>     -o <OUTPUT_FILE>\n\
                 optional: --punch-threshold <BYTES>"
            );
            eprintln!("error: {msg}");
            return ExitCode::from(2);
        }
    };

    if let Err(e) = run(parsed) {
        eprintln!("error: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

enum Output {
    Dir(PathBuf),
    File(PathBuf),
}

struct Args {
    source: PathBuf,
    output: Output,
    punch_threshold: u64,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut source: Option<PathBuf> = None;
    let mut out_dir: Option<PathBuf> = None;
    let mut out_file: Option<PathBuf> = None;
    let mut threshold: u64 = DEFAULT_PUNCH_THRESHOLD;

    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "-C" | "--output-dir" => {
                i += 1;
                let v = argv.get(i).ok_or("missing -C value")?;
                out_dir = Some(PathBuf::from(v));
            }
            "-o" | "--output-file" => {
                i += 1;
                let v = argv.get(i).ok_or("missing -o value")?;
                out_file = Some(PathBuf::from(v));
            }
            "--punch-threshold" => {
                i += 1;
                let v = argv.get(i).ok_or("missing --punch-threshold value")?;
                threshold = v
                    .parse()
                    .map_err(|_| format!("--punch-threshold: bad u64 {v:?}"))?;
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown flag {other:?}"));
            }
            _ => {
                if source.is_none() {
                    source = Some(PathBuf::from(&argv[i]));
                } else {
                    return Err(format!("unexpected positional arg {:?}", argv[i]));
                }
            }
        }
        i += 1;
    }
    let source = source.ok_or("source path is required")?;
    let output = match (out_dir, out_file) {
        (Some(_), Some(_)) => return Err("specify exactly one of -C / -o".into()),
        (Some(d), None) => Output::Dir(d),
        (None, Some(f)) => Output::File(f),
        (None, None) => return Err("specify either -C <DIR> or -o <FILE>".into()),
    };
    Ok(Args {
        source,
        output,
        punch_threshold: threshold,
    })
}

fn run(args: Args) -> Result<(), String> {
    let registry = DecoderRegistry::with_defaults();
    let factory = registry.factory_for_path(&args.source).ok_or_else(|| {
        format!(
            "no decoder registered for {} (suffix not in {:?})",
            args.source.display(),
            registry_suffixes(),
        )
    })?;

    // One read-only handle for the decoder, one read-write handle so
    // the puncher has the writable fd it needs.
    let read_handle = File::open(&args.source)
        .map_err(|e| format!("opening {} (read): {e}", args.source.display()))?;
    let rw_handle = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&args.source)
        .map_err(|e| format!("opening {} (read-write): {e}", args.source.display()))?;
    let logical_size = rw_handle
        .metadata()
        .map_err(|e| format!("metadata: {e}"))?
        .len();
    let blocks_before = rw_handle
        .metadata()
        .map_err(|e| format!("metadata: {e}"))?
        .blocks();

    let mut decoder: Box<dyn StreamingDecoder> =
        factory(Box::new(read_handle)).map_err(|e| format!("decoder init: {e}"))?;

    let puncher = default_puncher();
    let cfg = ExtractorConfig {
        punch_threshold: args.punch_threshold,
    };
    let extractor = Extractor::new(cfg);

    eprintln!(
        "[start] source={} ({} bytes), blocks_on_disk={}",
        args.source.display(),
        logical_size,
        blocks_before,
    );
    let started = Instant::now();
    let stats = match args.output {
        Output::Dir(ref d) => {
            fs::create_dir_all(d).map_err(|e| format!("creating {}: {e}", d.display()))?;
            let sink = TarSink::new(d).map_err(sink_err)?;
            run_one(
                &extractor,
                rw_handle.as_fd(),
                &mut *decoder,
                sink,
                &*puncher,
            )?
        }
        Output::File(ref f) => {
            let sink = RawSink::create(f).map_err(sink_err)?;
            run_one(
                &extractor,
                rw_handle.as_fd(),
                &mut *decoder,
                sink,
                &*puncher,
            )?
        }
    };
    let elapsed = started.elapsed();

    let blocks_after = rw_handle
        .metadata()
        .map_err(|e| format!("metadata after: {e}"))?
        .blocks();

    print_stats(&stats, elapsed, blocks_before, blocks_after, logical_size);

    match &args.output {
        Output::Dir(d) => eprintln!("[done] extracted into {}", d.display()),
        Output::File(f) => eprintln!("[done] wrote {}", f.display()),
    }
    Ok(())
}

fn run_one<S: Sink>(
    extractor: &Extractor,
    fd: std::os::fd::BorrowedFd<'_>,
    decoder: &mut dyn StreamingDecoder,
    sink: S,
    puncher: &dyn PunchHole,
) -> Result<ExtractionStats, String> {
    extractor
        .extract(fd, decoder, sink, puncher)
        .map_err(|e| format!("extract: {e}"))
}

fn sink_err(e: SinkError) -> String {
    format!("sink: {e}")
}

fn print_stats(
    stats: &ExtractionStats,
    elapsed: std::time::Duration,
    blocks_before: u64,
    blocks_after: u64,
    logical_size: u64,
) {
    let mib_in = stats.bytes_in as f64 / (1024.0 * 1024.0);
    let mib_out = stats.bytes_out as f64 / (1024.0 * 1024.0);
    let mib_punched = stats.bytes_punched as f64 / (1024.0 * 1024.0);
    let secs = elapsed.as_secs_f64().max(0.001);
    eprintln!(
        "[stats] in={:.2} MiB  out={:.2} MiB  punched={:.2} MiB  in/{:.2}s = {:.2} MiB/s",
        mib_in,
        mib_out,
        mib_punched,
        secs,
        mib_in / secs,
    );
    eprintln!(
        "[stats] frames={} checkpoints={} punch_calls={} punch_unsupported={}",
        stats.frame_boundaries_observed,
        stats.quiescent_checkpoints,
        stats.punch_calls,
        stats.punch_unsupported,
    );
    eprintln!(
        "[stats] decode={:?} write={:?} punch={:?}",
        stats.decode_time, stats.write_time, stats.punch_time,
    );
    let bytes_before = blocks_before.saturating_mul(512);
    let bytes_after = blocks_after.saturating_mul(512);
    eprintln!(
        "[disk]  source logical_size={} bytes; on-disk before≈{} bytes, after≈{} bytes \
         (logical preserved={})",
        logical_size,
        bytes_before,
        bytes_after,
        logical_size, // preserved exactly by the punch contract
    );
}

fn registry_suffixes() -> Vec<&'static str> {
    // Kept in sync with `peel::decode::DecoderRegistry::with_defaults`.
    vec![".zst", ".zstd"]
}
