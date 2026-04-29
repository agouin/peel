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

use clap::{ArgGroup, Parser};

use crate::coordinator::{CoordinatorConfig, OutputTarget, RunArgs};
use crate::decode::DecoderRegistry;
use crate::download::{RetryConfig, DEFAULT_CHUNK_SIZE, DEFAULT_WORKERS};
use crate::extractor::DEFAULT_PUNCH_THRESHOLD;
use crate::http::Client;

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
    #[arg(long = "chunk-size", default_value_t = DEFAULT_CHUNK_SIZE)]
    pub chunk_size: u64,

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
                workers: self.workers,
                retry: RetryConfig::default(),
                punch_threshold: self.punch_threshold,
                checkpoint_min_bytes: self.checkpoint_min_bytes,
                checkpoint_min_interval: Duration::from_secs_f64(self.checkpoint_min_secs.max(0.0)),
                workdir: None,
                reader_poll_interval: Duration::from_millis(5),
            },
            client,
            registry: DecoderRegistry::with_defaults(),
            progress: None,
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
}
