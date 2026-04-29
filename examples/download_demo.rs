//! `cargo run --example download_demo -- <URL> <output>`
//!
//! Drives `peel::download` end-to-end against a real server: discovery
//! `HEAD`, parallel ranged GETs (or single-stream fallback), sparse-file
//! reassembly. Prints throughput and chunk stats. Doubles as the demo
//! for `docs/PLAN.md` §5.
//!
//! Optional flags:
//!   --workers N       (default 4)
//!   --chunk-size B    (default 4194304 = 4 MiB)
//!
//! Example:
//!   cargo run --release --example download_demo -- \
//!       https://example.com/big.tar.zst /tmp/big.tar.zst.part

use std::io::IsTerminal;
use std::process::ExitCode;
use std::sync::atomic::AtomicU64;
use std::time::Instant;

use peel::bitmap::ChunkBitmap;
use peel::download::{
    chunk_count, discover, run, DownloadInfo, DownloadMode, RetryConfig, SchedulerConfig,
    SparseFile, DEFAULT_CHUNK_SIZE, DEFAULT_WORKERS,
};
use peel::http::{Client, Url};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let parsed = match parse_args(&args) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("usage: download_demo <URL> <OUTPUT> [--workers N] [--chunk-size B]");
            eprintln!("error: {msg}");
            return ExitCode::from(2);
        }
    };

    if let Err(e) = run_demo(parsed) {
        eprintln!("error: {e}");
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}

struct Args {
    url: String,
    output: String,
    workers: u32,
    chunk_size: u64,
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut url: Option<String> = None;
    let mut output: Option<String> = None;
    let mut workers: u32 = DEFAULT_WORKERS;
    let mut chunk_size: u64 = DEFAULT_CHUNK_SIZE;

    let mut i = 0;
    while i < argv.len() {
        match argv[i].as_str() {
            "--workers" => {
                i += 1;
                let v = argv.get(i).ok_or("missing --workers value")?;
                workers = v.parse().map_err(|_| format!("--workers: bad u32 {v:?}"))?;
                if workers == 0 {
                    return Err("--workers must be > 0".into());
                }
            }
            "--chunk-size" => {
                i += 1;
                let v = argv.get(i).ok_or("missing --chunk-size value")?;
                chunk_size = v
                    .parse()
                    .map_err(|_| format!("--chunk-size: bad u64 {v:?}"))?;
                if chunk_size == 0 {
                    return Err("--chunk-size must be > 0".into());
                }
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown flag {other:?}"));
            }
            _ => {
                if url.is_none() {
                    url = Some(argv[i].clone());
                } else if output.is_none() {
                    output = Some(argv[i].clone());
                } else {
                    return Err(format!("unexpected positional arg {:?}", argv[i]));
                }
            }
        }
        i += 1;
    }
    let url = url.ok_or("URL is required")?;
    let output = output.ok_or("OUTPUT path is required")?;
    Ok(Args {
        url,
        output,
        workers,
        chunk_size,
    })
}

fn run_demo(args: Args) -> Result<(), String> {
    let url = Url::parse(&args.url).map_err(|e| format!("parse URL: {e}"))?;
    let client = Client::new().map_err(|e| format!("client init: {e}"))?;

    eprintln!("[discover] HEAD {url}");
    let info: DownloadInfo = discover(&client, &url).map_err(|e| format!("discover: {e}"))?;
    eprintln!(
        "[discover] {} bytes, accept-ranges={}, etag={:?}, last-modified={:?}",
        info.total_size,
        info.accept_ranges,
        info.fingerprint.etag.as_deref().unwrap_or(""),
        info.fingerprint.last_modified.as_deref().unwrap_or(""),
    );

    let total_chunks =
        chunk_count(info.total_size, args.chunk_size).map_err(|e| format!("planning: {e}"))?;
    eprintln!(
        "[plan] chunk_size={} workers={} chunks={}",
        args.chunk_size, args.workers, total_chunks,
    );

    let path = std::path::Path::new(&args.output);
    let sparse =
        SparseFile::open_or_create(path, info.total_size).map_err(|e| format!("sparse: {e}"))?;
    let bitmap = ChunkBitmap::new(total_chunks);
    let cursor = AtomicU64::new(0);

    let cfg = SchedulerConfig {
        chunk_size: args.chunk_size,
        workers: args.workers,
        retry: RetryConfig::default(),
        progress: None,
    };

    let started = Instant::now();
    eprintln!("[run] starting transfer");
    let stats =
        run(&client, &info, &sparse, &bitmap, &cursor, &cfg).map_err(|e| format!("run: {e}"))?;

    let elapsed = started.elapsed();
    let mib = stats.bytes_downloaded as f64 / (1024.0 * 1024.0);
    let secs = elapsed.as_secs_f64().max(0.001);
    let throughput = mib / secs;

    eprintln!(
        "[done] {:.2} MiB in {:.2}s ({:.2} MiB/s)",
        mib, secs, throughput
    );
    eprintln!(
        "[done] mode={:?} chunks_completed={} retries={}",
        stats.mode, stats.chunks_completed, stats.retries,
    );
    if matches!(stats.mode, DownloadMode::Parallel { .. }) && std::io::stderr().is_terminal() {
        eprintln!(
            "[done] (note: file is sparse; size on disk may be lower than {} bytes)",
            info.total_size
        );
    }
    Ok(())
}
