//! Entry point for the `peel` CLI.
//!
//! Parses the command-line via [`peel::cli::Cli`], constructs a
//! [`peel::coordinator::RunArgs`], and runs the pipeline.
//!
//! Progress is rendered by a [`peel::progress`] renderer thread spawned
//! at the binary boundary: a multi-line ANSI block on a TTY (PLAN_v2.md
//! §6) or one structured `tracing::info!` event per tick when stderr is
//! not a terminal. The renderer reads a shared [`peel::progress::ProgressState`]
//! that the coordinator, download workers, and extractor update directly.
//!
//! Errors at the binary boundary are wrapped via [`anyhow`] per
//! `docs/ENGINEERING_STANDARDS.md` §3.2.

#![cfg(unix)]
#![warn(unused, clippy::all)]

use std::io::IsTerminal;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;

use peel::cli::Cli;
use peel::coordinator::{run, ProgressEvent, ProgressFn};
use peel::progress::{spawn_renderer, LogRenderer, ProgressState, TtyRenderer};

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Pick the progress mode from whether stderr is a real terminal.
    // The TTY path uses hand-rolled ANSI on stderr; the non-TTY path
    // emits `tracing::info!` events that the subscriber below routes
    // back to stderr in human-readable form.
    let stderr_is_tty = std::io::stderr().is_terminal();
    init_tracing(stderr_is_tty);

    let mut args = cli
        .into_run_args()
        .context("constructing the HTTP client")?;
    let state = ProgressState::new();
    args.progress_state = Some(Arc::clone(&state));
    args.progress = Some(make_event_callback());

    // Spawn the renderer thread. TTY mode redraws three lines in place
    // every 100 ms; non-TTY mode emits one structured log line every
    // 2 s so a piped log file remains readable.
    let render_handle = if stderr_is_tty {
        spawn_renderer(
            Arc::clone(&state),
            TtyRenderer::new(std::io::stderr()),
            Duration::from_millis(100),
        )
        .context("spawning the TTY progress renderer")?
    } else {
        spawn_renderer(
            Arc::clone(&state),
            LogRenderer::new(),
            Duration::from_secs(2),
        )
        .context("spawning the log progress renderer")?
    };

    let result = run(args);

    // Tell the renderer to stop, regardless of whether `run` succeeded
    // or errored, so we can join it before exiting `main`.
    state.mark_done();
    let _ = render_handle.join();

    let stats = result.context("running peel")?;

    eprintln!(
        "[done] {} bytes downloaded, {} bytes extracted in {:.2}s{}",
        stats.download.bytes_downloaded,
        stats.extraction.bytes_out,
        stats.elapsed.as_secs_f64(),
        if stats.resumed { " (resumed)" } else { "" },
    );
    Ok(())
}

/// Discrete-event ProgressFn callback. Mostly informational; the
/// renderer thread covers the steady-state UI.
///
/// `Started` and `Finished` are user-facing one-shot events, so they
/// stay on `eprintln!` (CLI user-facing output, per
/// `docs/ENGINEERING_STANDARDS.md` §10's exception). `CheckpointWritten`
/// is high-frequency and would clutter the renderer output, so we
/// drop it on the floor.
fn make_event_callback() -> ProgressFn {
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
        ProgressEvent::CheckpointWritten { .. } => {
            // Per-checkpoint events are noisy on a fast pipeline; the
            // renderer thread shows steady-state progress already.
        }
        ProgressEvent::Finished {
            download,
            extraction,
        } => {
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

/// Configure the global `tracing` subscriber.
///
/// On a TTY we suppress the `peel::progress` target entirely — the
/// TTY renderer is the user's view of that data, and dumping log
/// events to the same stream would corrupt the in-place redraw.
/// Off-TTY we keep the target on so the [`LogRenderer`] events make
/// it to stderr.
fn init_tracing(stderr_is_tty: bool) {
    use tracing_subscriber::fmt;

    let builder = fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_level(true)
        .without_time();

    if stderr_is_tty {
        // Default level INFO but progress events suppressed: the
        // renderer's in-place redraw is the user's progress view.
        // Other targets (warnings, info from other modules) still
        // show.
        let _ = builder.with_max_level(tracing::Level::WARN).try_init();
    } else {
        let _ = builder.with_max_level(tracing::Level::INFO).try_init();
    }
}
