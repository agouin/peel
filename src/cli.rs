//! Command-line argument parsing for the `peel` binary.
//!
//! Kept thin on purpose: the binary entry point in `main.rs` parses
//! arguments, calls into [`crate::coordinator::run`], and formats the
//! result for the terminal. Anything more elaborate (config files,
//! profiles, …) is deferred per `docs/PLAN.md` §10.2 and the
//! "do-not-add-CLI-niceties" rule in `AGENTS.md`.

#![cfg(unix)]

use std::path::PathBuf;
use std::time::Duration;

use clap::{ArgGroup, Parser, ValueEnum};

use crate::coordinator::{CoordinatorConfig, OutputTarget, RunArgs};
use crate::decode::DecoderRegistry;
use crate::download::{RetryConfig, DEFAULT_CHUNK_SIZE, DEFAULT_WORKERS};
use crate::extractor::DEFAULT_PUNCH_THRESHOLD;
use crate::http::Client;
use crate::io_backend::IoBackendChoice;

/// Parsed CLI for the `peel` binary.
#[derive(Debug, Parser)]
#[command(
    name = "peel",
    version,
    about = "Streaming, resumable, space-efficient extractor for compressed archives over HTTP."
)]
#[command(group(
    ArgGroup::new("output")
        .required(true)
        .args(["output_dir", "output_file"]),
))]
#[command(group(
    // The two format-override flags express *different intents*: one
    // names a specific decoder, the other says "trust whichever
    // decoder the magic bytes pick". They cannot both be set at once;
    // the CLI rejects the combination at parse time per `PLAN_v2.md`
    // §1 step 5.
    ArgGroup::new("format-override")
        .args(["forced_format", "force_format_from_magic"]),
))]
pub struct Cli {
    /// Source URL (e.g. https://example.com/dataset.tar.zst).
    pub url: String,

    /// Extract a tar archive into this directory.
    #[arg(short = 'C', long = "output-dir", value_name = "DIR")]
    pub output_dir: Option<PathBuf>,

    /// Stream the decoded bytes verbatim into this file.
    #[arg(short = 'o', long = "output-file", value_name = "FILE")]
    pub output_file: Option<PathBuf>,

    /// Number of parallel download workers.
    #[arg(long = "workers", default_value_t = DEFAULT_WORKERS)]
    pub workers: u32,

    /// Chunk size used to slice the source for ranged downloads.
    ///
    /// This is the bitmap chunk size — the unit of completion
    /// tracked in checkpoints. With adaptive chunk-sizing enabled
    /// (the default), the scheduler may coalesce several
    /// consecutive chunks into a single ranged GET; this flag
    /// continues to set the *bitmap* unit. Passing `--chunk-size`
    /// alongside `--no-adaptive-chunk-size` forces a fixed dispatch
    /// size for the run (`PLAN_v2.md` §8 step 4).
    #[arg(long = "chunk-size", default_value_t = DEFAULT_CHUNK_SIZE)]
    pub chunk_size: u64,

    /// Disable the adaptive chunk-size policy (`PLAN_v2.md` §8).
    ///
    /// When set, the scheduler dispatches one bitmap chunk per
    /// worker task, with no growth or shrink decisions over the
    /// lifetime of the run. The `--chunk-size` value is the
    /// fixed-size dispatch unit. Useful for benchmarking and
    /// reproducible test runs where adaptive behaviour would
    /// change observed throughput.
    #[arg(long = "no-adaptive-chunk-size", default_value_t = false)]
    pub no_adaptive_chunk_size: bool,

    /// Minimum gap between in-loop hole-punch syscalls.
    #[arg(long = "punch-threshold", default_value_t = DEFAULT_PUNCH_THRESHOLD)]
    pub punch_threshold: u64,

    /// Minimum source-byte progress between checkpoint writes.
    #[arg(long = "checkpoint-min-bytes", default_value_t = 8 * 1024 * 1024)]
    pub checkpoint_min_bytes: u64,

    /// Minimum wall-clock interval between checkpoint writes, in
    /// seconds (fractional).
    #[arg(long = "checkpoint-min-secs", default_value_t = 2.0)]
    pub checkpoint_min_secs: f64,

    /// Force a specific decoder by name, bypassing both URL-suffix
    /// and magic-byte detection. Use this when the URL has no
    /// usable suffix (e.g. opaque query-string downloads). Mutually
    /// exclusive with `--force-format-from-magic`.
    #[arg(long = "format", value_name = "NAME")]
    pub forced_format: Option<String>,

    /// When the URL suffix and the source's magic bytes disagree,
    /// trust the magic instead of returning `FormatMismatch`.
    /// Mutually exclusive with `--format`.
    #[arg(long = "force-format-from-magic", default_value_t = false)]
    pub force_format_from_magic: bool,

    /// File-IO backend selection (PLAN_v2.md §7 + §9).
    ///
    /// `auto` (default) prefers `io_uring` on Linux and falls back to
    /// the blocking backend with a warning if the kernel does not
    /// support it. `blocking` forces the pre-§7 `pwrite`/`pread` path
    /// (useful for A/B comparison). `uring` requires `io_uring` and
    /// errors out if it is unavailable. `mmap` selects the §9
    /// memory-mapped sparse-file path: workers `memcpy` into a
    /// `MAP_SHARED` region and the puncher uses
    /// `madvise(MADV_REMOVE)`. Linux-only; sockets continue to use
    /// the blocking backend.
    #[arg(long = "io-backend", value_enum, default_value_t = IoBackendArg::Auto)]
    pub io_backend: IoBackendArg,
}

/// CLI form of [`IoBackendChoice`].
///
/// Kept as a separate type so the [`clap::ValueEnum`] derive does not
/// have to live on the library type. Mapping is mechanical via
/// [`From`].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default, ValueEnum)]
#[value(rename_all = "lower")]
pub enum IoBackendArg {
    /// Auto-detect: try `io_uring` on Linux, fall back to blocking.
    #[default]
    Auto,
    /// Force the blocking `pwrite`/`pread` backend.
    Blocking,
    /// Force the Linux `io_uring` backend.
    Uring,
    /// Force the Linux memory-mapped sparse-file backend.
    Mmap,
}

impl From<IoBackendArg> for IoBackendChoice {
    fn from(arg: IoBackendArg) -> Self {
        match arg {
            IoBackendArg::Auto => Self::Auto,
            IoBackendArg::Blocking => Self::Blocking,
            IoBackendArg::Uring => Self::Uring,
            IoBackendArg::Mmap => Self::Mmap,
        }
    }
}

impl Cli {
    /// Convert the parsed CLI into a [`RunArgs`] ready for
    /// [`crate::coordinator::run`].
    ///
    /// # Errors
    ///
    /// Returns the underlying [`crate::http::ClientError`] if the
    /// HTTP client cannot be constructed.
    pub fn into_run_args(self) -> Result<RunArgs, crate::http::ClientError> {
        let output = match (self.output_dir, self.output_file) {
            (Some(d), None) => OutputTarget::Dir(d),
            (None, Some(f)) => OutputTarget::File(f),
            // The clap ArgGroup guarantees one-of, so these two arms
            // cannot fire in practice; the catch-all keeps the match
            // exhaustive without `unreachable!`.
            _ => OutputTarget::Dir(PathBuf::from(".")),
        };
        let client = Client::new()?;
        Ok(RunArgs {
            url: self.url,
            output,
            config: CoordinatorConfig {
                chunk_size: self.chunk_size,
                adaptive_chunk_size: !self.no_adaptive_chunk_size,
                workers: self.workers,
                retry: RetryConfig::default(),
                punch_threshold: self.punch_threshold,
                checkpoint_min_bytes: self.checkpoint_min_bytes,
                checkpoint_min_interval: Duration::from_secs_f64(self.checkpoint_min_secs.max(0.0)),
                workdir: None,
                reader_poll_interval: Duration::from_millis(5),
                forced_format: self.forced_format,
                force_format_from_magic: self.force_format_from_magic,
                io_backend: self.io_backend.into(),
            },
            client,
            registry: DecoderRegistry::with_defaults(),
            progress: None,
            progress_state: None,
            kill_switch: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_dir_output() {
        let cli = Cli::try_parse_from(["peel", "https://example.com/x.tar.zst", "-C", "/tmp/out"])
            .expect("parse");
        assert!(cli.output_dir.is_some());
        assert!(cli.output_file.is_none());
    }

    #[test]
    fn parses_file_output() {
        let cli = Cli::try_parse_from(["peel", "https://example.com/x.zst", "-o", "/tmp/out.bin"])
            .expect("parse");
        assert!(cli.output_dir.is_none());
        assert!(cli.output_file.is_some());
    }

    #[test]
    fn rejects_both_outputs_simultaneously() {
        let err = Cli::try_parse_from([
            "peel",
            "https://example.com/x.tar.zst",
            "-C",
            "/tmp/d",
            "-o",
            "/tmp/f",
        ])
        .expect_err("must conflict");
        // clap's group conflict reports a helpful kind; we only check
        // that parsing failed rather than couple the test to a kind.
        let _ = err;
    }

    #[test]
    fn rejects_no_output() {
        let err = Cli::try_parse_from(["peel", "https://example.com/x.tar.zst"])
            .expect_err("must require output");
        let _ = err;
    }

    #[test]
    fn parses_forced_format_flag() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x?id=42",
            "-o",
            "/tmp/out.bin",
            "--format",
            "zstd",
        ])
        .expect("parse");
        assert_eq!(cli.forced_format.as_deref(), Some("zstd"));
        assert!(!cli.force_format_from_magic);
    }

    #[test]
    fn parses_force_format_from_magic_flag() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.gz",
            "-o",
            "/tmp/out.bin",
            "--force-format-from-magic",
        ])
        .expect("parse");
        assert!(cli.force_format_from_magic);
        assert!(cli.forced_format.is_none());
    }

    #[test]
    fn parses_io_backend_default_is_auto() {
        let cli = Cli::try_parse_from(["peel", "https://example.com/x.zst", "-o", "/tmp/o"])
            .expect("parse");
        assert_eq!(cli.io_backend, IoBackendArg::Auto);
    }

    #[test]
    fn parses_io_backend_blocking() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.zst",
            "-o",
            "/tmp/o",
            "--io-backend",
            "blocking",
        ])
        .expect("parse");
        assert_eq!(cli.io_backend, IoBackendArg::Blocking);
    }

    #[test]
    fn parses_io_backend_uring() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.zst",
            "-o",
            "/tmp/o",
            "--io-backend",
            "uring",
        ])
        .expect("parse");
        assert_eq!(cli.io_backend, IoBackendArg::Uring);
    }

    #[test]
    fn parses_io_backend_mmap() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.zst",
            "-o",
            "/tmp/o",
            "--io-backend",
            "mmap",
        ])
        .expect("parse");
        assert_eq!(cli.io_backend, IoBackendArg::Mmap);
    }

    #[test]
    fn rejects_unknown_io_backend() {
        let err = Cli::try_parse_from([
            "peel",
            "https://example.com/x.zst",
            "-o",
            "/tmp/o",
            "--io-backend",
            "nonsense",
        ])
        .expect_err("unknown backend");
        let _ = err;
    }

    #[test]
    fn io_backend_arg_maps_to_choice() {
        assert_eq!(
            IoBackendChoice::from(IoBackendArg::Auto),
            IoBackendChoice::Auto
        );
        assert_eq!(
            IoBackendChoice::from(IoBackendArg::Blocking),
            IoBackendChoice::Blocking
        );
        assert_eq!(
            IoBackendChoice::from(IoBackendArg::Uring),
            IoBackendChoice::Uring
        );
        assert_eq!(
            IoBackendChoice::from(IoBackendArg::Mmap),
            IoBackendChoice::Mmap
        );
    }

    #[test]
    fn parses_no_adaptive_chunk_size_default_off() {
        let cli = Cli::try_parse_from(["peel", "https://example.com/x.zst", "-o", "/tmp/o"])
            .expect("parse");
        assert!(!cli.no_adaptive_chunk_size);
    }

    #[test]
    fn parses_no_adaptive_chunk_size_flag() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.zst",
            "-o",
            "/tmp/o",
            "--no-adaptive-chunk-size",
        ])
        .expect("parse");
        assert!(cli.no_adaptive_chunk_size);
    }

    #[test]
    fn no_adaptive_chunk_size_flips_coordinator_field() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.zst",
            "-o",
            "/tmp/o",
            "--no-adaptive-chunk-size",
        ])
        .expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert!(!args.config.adaptive_chunk_size);
    }

    #[test]
    fn default_run_args_have_adaptive_enabled() {
        let cli = Cli::try_parse_from(["peel", "https://example.com/x.zst", "-o", "/tmp/o"])
            .expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert!(args.config.adaptive_chunk_size);
    }

    #[test]
    fn rejects_format_and_force_from_magic_simultaneously() {
        let err = Cli::try_parse_from([
            "peel",
            "https://example.com/x.gz",
            "-o",
            "/tmp/out.bin",
            "--format",
            "zstd",
            "--force-format-from-magic",
        ])
        .expect_err("must conflict");
        let _ = err;
    }
}
