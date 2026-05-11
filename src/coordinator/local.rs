//! Local-file extraction coordinator
//! (`docs/PLAN_local_file_extract.md`).
//!
//! The HTTP-side [`crate::coordinator::run`] is 2.8k lines of
//! download / fingerprint / bandwidth / mirror state machine.
//! Local extraction has none of that: open the file, pick a
//! decoder, wire it to a sink, run the [`crate::extractor::Extractor`]
//! loop. This module keeps the local path next door, sharing
//! sink / decoder / extractor types, so both sides stay readable.
//!
//! The user-facing entry is [`run`]. The CLI's
//! [`crate::cli::Cli::into_dispatch`] hands every flag through;
//! interactive consent (the destructive-mode prompt) is handled
//! at the binary boundary before this function is invoked, so the
//! coordinator cannot tell a `-y` run from a "user typed `y` at
//! the prompt" run.

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use crate::coordinator::{CoordinatorError, OutputTarget, ProgressFn, RunStats};
use crate::decode::DecoderRegistry;
use crate::extractor::DEFAULT_PUNCH_THRESHOLD;
use crate::io_backend::IoBackendChoice;
use crate::progress::ProgressState;

/// Arguments for [`run`] — the local-mode counterpart of
/// [`crate::coordinator::RunArgs`]
/// (`docs/PLAN_local_file_extract.md` §2).
///
/// Fields are deliberately a strict subset of the HTTP-side knobs:
/// no `chunk_size`, no `workers`, no mirror list, no `--sha256`
/// argument, no `Content-Length` discovery. The CLI rejects every
/// HTTP-only flag at parse time so this struct never has to
/// rationalize an unused-but-set knob.
pub struct LocalRunArgs {
    /// Path to the local archive being extracted.
    pub source: PathBuf,
    /// Where the extracted output lands.
    pub output: OutputTarget,
    /// `--format <NAME>` override (bypasses suffix + magic
    /// detection). `None` lets the coordinator detect on its own.
    pub forced_format: Option<String>,
    /// `--force-format-from-magic`: trust magic bytes when they
    /// disagree with the source filename suffix.
    pub force_format_from_magic: bool,
    /// `-k/--keep-archive`. `true` preserves the source archive
    /// across the run (no punching, no deletion); `false` is the
    /// destructive default — the source is punched as the decoder
    /// advances and deleted on clean completion.
    pub keep_archive: bool,
    /// Extractor-side minimum gap between in-loop punch syscalls.
    /// Ignored when [`Self::keep_archive`] is `true`.
    pub punch_threshold: u64,
    /// Minimum source-byte progress between checkpoint writes.
    /// Same meaning as
    /// [`crate::coordinator::CoordinatorConfig::checkpoint_min_bytes`].
    pub checkpoint_min_bytes: u64,
    /// Minimum wall-clock time between checkpoint writes. Same
    /// meaning as
    /// [`crate::coordinator::CoordinatorConfig::checkpoint_min_interval`].
    pub checkpoint_min_interval: Duration,
    /// Override the `.peel.ckpt` location (defaults to a sibling
    /// of the source archive). Mirrors the HTTP-side `--workdir`.
    pub workdir: Option<PathBuf>,
    /// File-IO backend selection (chooses puncher impl in
    /// destructive mode). Same enum as the HTTP-side
    /// `--io-backend`.
    pub io_backend: IoBackendChoice,
    /// Decoder registry. Default is
    /// [`DecoderRegistry::with_defaults`].
    pub registry: DecoderRegistry,
    /// Optional discrete-event progress callback. Library callers
    /// (tests, embedders) pass one; the `peel` binary leaves this
    /// `None` and relies on [`Self::progress_state`].
    pub progress: Option<ProgressFn>,
    /// Optional shared progress state — same shape as
    /// [`crate::coordinator::RunArgs::progress_state`]. Local mode
    /// pumps bytes-decoded into it; the renderer thread reads from
    /// there on its own cadence.
    pub progress_state: Option<Arc<ProgressState>>,
    /// Optional shared kill switch. Flipped by the binary's
    /// SIGINT / SIGTERM handler so the coordinator can exit
    /// gracefully between checkpoints.
    pub kill_switch: Option<Arc<AtomicBool>>,
    /// Optional pre-resolved IO backend. The binary pre-resolves
    /// in `main` so the `io_backend=…` banner is plain stderr
    /// scrollback above the TTY renderer; library callers leave
    /// this `None` and we materialize it from [`Self::io_backend`].
    pub io_backend_resolved: Option<Arc<dyn crate::io_backend::IoBackend>>,
}

impl LocalRunArgs {
    /// Construct a [`LocalRunArgs`] with sensible defaults. Used
    /// by tests and library callers that build the struct without
    /// going through the [`crate::cli::Cli`] surface.
    #[must_use]
    pub fn new(source: PathBuf, output: OutputTarget) -> Self {
        Self {
            source,
            output,
            forced_format: None,
            force_format_from_magic: false,
            keep_archive: false,
            punch_threshold: DEFAULT_PUNCH_THRESHOLD,
            checkpoint_min_bytes: 8 * 1024 * 1024,
            checkpoint_min_interval: Duration::from_secs(2),
            workdir: None,
            io_backend: IoBackendChoice::default(),
            registry: DecoderRegistry::with_defaults(),
            progress: None,
            progress_state: None,
            kill_switch: None,
            io_backend_resolved: None,
        }
    }
}

/// Extract a local archive
/// (`docs/PLAN_local_file_extract.md` §2).
///
/// The current implementation is a placeholder: §1 of the plan
/// lands the CLI / dispatch surface; §2 wires the real
/// open-file / decode-stream / sink pipeline. Until §2 lands every
/// invocation surfaces a typed
/// [`CoordinatorError::LocalNotImplemented`].
///
/// # Errors
///
/// Returns [`CoordinatorError::LocalNotImplemented`] in the
/// placeholder state. Once §2 lands the variant set widens to the
/// same shape as [`crate::coordinator::run`]'s error surface.
pub fn run(_args: LocalRunArgs) -> Result<RunStats, CoordinatorError> {
    Err(CoordinatorError::LocalNotImplemented)
}
