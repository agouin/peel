//! Entry point for the `peel` CLI.
//!
//! Parses the command-line via [`peel::cli::Cli`], constructs a
//! [`peel::coordinator::RunArgs`], and runs the pipeline. Progress is
//! formatted as a single redrawn line on a TTY (or one structured log
//! line per checkpoint when stderr is not a terminal — detected via
//! `IsTerminal`). Errors at the binary boundary are wrapped via
//! [`anyhow`] per `docs/ENGINEERING_STANDARDS.md` §3.2.

#![cfg(unix)]
#![warn(unused, clippy::all)]

use std::io::{IsTerminal, Write};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;

use peel::cli::Cli;
use peel::coordinator::{run, ProgressEvent, ProgressFn};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut args = cli
        .into_run_args()
        .context("constructing the HTTP client")?;
    args.progress = Some(make_progress());

    let stats = run(args).context("running peel")?;

    eprintln!(
        "[done] {} bytes downloaded, {} bytes extracted in {:.2}s{}",
        stats.download.bytes_downloaded,
        stats.extraction.bytes_out,
        stats.elapsed.as_secs_f64(),
        if stats.resumed { " (resumed)" } else { "" },
    );
    Ok(())
}

fn make_progress() -> ProgressFn {
    let tty = std::io::stderr().is_terminal();
    let mut last_redraw_at = std::time::Instant::now();
    Box::new(move |event: ProgressEvent<'_>| match event {
        ProgressEvent::Started {
            url,
            total_size,
            resuming,
            total_chunks,
            chunks_resumed,
        } => {
            eprintln!(
                "[start] {} ({} bytes, {} chunks{}{})",
                url,
                total_size,
                total_chunks,
                if resuming { ", resuming" } else { "" },
                if chunks_resumed > 0 {
                    format!(", {chunks_resumed} chunks already complete")
                } else {
                    String::new()
                },
            );
        }
        ProgressEvent::CheckpointWritten {
            source_position,
            bytes_in,
            bytes_out,
        } => {
            let now = std::time::Instant::now();
            // On a TTY, redraw a single status line at most a few times
            // a second. Off-TTY, log every checkpoint.
            if tty && now.duration_since(last_redraw_at) < Duration::from_millis(200) {
                return;
            }
            last_redraw_at = now;
            if tty {
                let mut stderr = std::io::stderr();
                let _ = write!(
                    stderr,
                    "\r[ckpt] src@{source_position} in={bytes_in} out={bytes_out}            ",
                );
                let _ = stderr.flush();
            } else {
                eprintln!("[ckpt] src@{source_position} in={bytes_in} out={bytes_out}",);
            }
        }
        ProgressEvent::Finished {
            download,
            extraction,
        } => {
            if tty {
                let _ = writeln!(std::io::stderr());
            }
            eprintln!(
                "[stats] download chunks={} retries={} mode={:?}",
                download.chunks_completed, download.retries, download.mode,
            );
            eprintln!(
                "[stats] extract bytes_in={} bytes_out={} bytes_punched={} \
                 frames={} checkpoints={}",
                extraction.bytes_in,
                extraction.bytes_out,
                extraction.bytes_punched,
                extraction.frame_boundaries_observed,
                extraction.quiescent_checkpoints,
            );
        }
    })
}
