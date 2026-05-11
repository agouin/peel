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
//!
//! # Scope (PLAN_local_file_extract.md §2)
//!
//! This module handles the **streaming-decoder** formats — every
//! container that flows through [`crate::extractor::Extractor`]:
//! `zstd`, `xz`, `lz4`, `gzip`, plus any of those wrapping a tar.
//! ZIP, RAR, and 7z are random-access formats and route through
//! their own per-pipeline orchestrators inside
//! [`crate::coordinator::run`]; those pipelines are tightly
//! coupled to the HTTP-side
//! [`crate::download::BlockingSparseReader`] today, so the local
//! path surfaces [`crate::coordinator::CoordinatorError::NoDecoder`]
//! for those formats with a clear "use the HTTP path for now"
//! message. Re-using their per-entry extractors against a local
//! file is a follow-on item — the plan asserts those entry points
//! exist already, but on inspection they don't yet, and adding
//! them is its own design.

#![cfg(unix)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::coordinator::{CoordinatorError, OutputTarget, ProgressFn, RunStats};
use crate::decode::{DecodeError, DecoderFactory, DecoderRegistry, FormatShape, StreamingDecoder};
use crate::extractor::{
    ExtractionStats, Extractor, ExtractorConfig, ExtractorError, DEFAULT_PUNCH_THRESHOLD,
};
use crate::http::Url;
use crate::io_backend::IoBackendChoice;
use crate::progress::ProgressState;
use crate::punch::{default_puncher, NoopPuncher, PunchHole};
#[cfg(feature = "rar")]
use crate::rar::FORMAT_NAME as RAR_FORMAT_NAME;
use crate::sevenz::FORMAT_NAME as SEVENZ_FORMAT_NAME;
use crate::sink::{RawSink, Sink, TarSink};
use crate::zip::FORMAT_NAME as ZIP_FORMAT_NAME;

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

/// Number of leading bytes peeled off the source file to feed
/// magic-byte detection. Sized to cover every magic signature
/// shipped in the default decoder registry (~263 bytes for the
/// 7z header) with comfortable headroom.
const MAGIC_PROBE_BYTES: usize = 512;

/// Pick a decoder factory for the local source by combining
/// `--format`, the source filename's suffix, and (when both miss
/// or `--force-format-from-magic` is set) the first
/// [`MAGIC_PROBE_BYTES`] of the file's bytes.
///
/// Mirrors the HTTP-side `select_decoder_factory` in
/// [`crate::coordinator`] but reads the prefix from the open file
/// directly rather than waiting for a chunk to arrive in the
/// sparse part-file. The prefix bytes are returned alongside the
/// factory so the caller can prepend them to the decoder's input
/// stream without re-reading from disk.
fn select_local_decoder_factory(
    args: &LocalRunArgs,
    file: &mut File,
) -> Result<(FormatShape, DecoderFactory, Vec<u8>), CoordinatorError> {
    // `--format` short-circuits both suffix and magic detection.
    if let Some(name) = args.forced_format.as_deref() {
        let factory = args.registry.factory_for_format_name(name).ok_or_else(|| {
            CoordinatorError::UnknownFormatName {
                name: name.to_string(),
                available: args
                    .registry
                    .format_names()
                    .into_iter()
                    .map(String::from)
                    .collect(),
            }
        })?;
        // INVARIANT: factory_for_format_name returned Some(_) so
        // shape_for_format_name (same table) cannot miss.
        let shape = args
            .registry
            .shape_for_format_name(name)
            .unwrap_or(FormatShape::Tree);
        // No prefix needed when `--format` skips magic detection;
        // the decoder reads the file from byte 0 directly.
        return Ok((shape, factory, Vec::new()));
    }

    // Peek the prefix for magic detection. Reading is destructive
    // to the file cursor; we seek back to 0 before returning so the
    // caller can hand the file to the decoder unchanged.
    let mut prefix = vec![0u8; MAGIC_PROBE_BYTES];
    file.seek(SeekFrom::Start(0))
        .map_err(|source| CoordinatorError::Io {
            path: args.source.clone(),
            source,
        })?;
    let n = file
        .read(&mut prefix)
        .map_err(|source| CoordinatorError::Io {
            path: args.source.clone(),
            source,
        })?;
    prefix.truncate(n);
    file.seek(SeekFrom::Start(0))
        .map_err(|source| CoordinatorError::Io {
            path: args.source.clone(),
            source,
        })?;

    let basename = args
        .source
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let suffix_lookup = args.registry.lookup_by_name(basename);
    let magic_lookup = args.registry.lookup_by_prefix(&prefix);

    let resolved = match (suffix_lookup, magic_lookup) {
        (Some((shape, s)), Some((_, m))) if std::ptr::fn_addr_eq(s, m) => Some((shape, s)),
        (Some((suffix_shape, s)), Some((magic_shape, m))) => {
            let suffix_name = args.registry.name_for_factory(s).map(String::from);
            let magic_name = args.registry.name_for_factory(m).map(String::from);
            if args.force_format_from_magic {
                tracing::warn!(
                    suffix = %suffix_name.as_deref().unwrap_or("?"),
                    magic = %magic_name.as_deref().unwrap_or("?"),
                    "format-detection conflict; using magic per --force-format-from-magic",
                );
                let _ = suffix_shape;
                Some((magic_shape, m))
            } else {
                return Err(CoordinatorError::FormatMismatch {
                    suffix_format: suffix_name,
                    magic_format: magic_name,
                });
            }
        }
        (Some((shape, s)), None) => Some((shape, s)),
        (None, Some((shape, m))) => Some((shape, m)),
        (None, None) => None,
    };

    let (shape, factory) = resolved.ok_or_else(|| CoordinatorError::NoDecoder {
        filename: basename.to_string(),
    })?;
    Ok((shape, factory, prefix))
}

/// Resolve the [`Url`]-flavored bookkeeping the public
/// [`RunStats`] struct expects, from a local source path.
///
/// `RunStats::final_url` is part of the shared shape between HTTP
/// and local runs; for a local extraction we synthesize a
/// loopback URL whose path component matches the source basename
/// so log lines (`[start]`, `[done]`) carry a useful identifier.
fn local_run_url(source: &Path) -> Url {
    let basename = source.file_name().and_then(|s| s.to_str()).unwrap_or("");
    // `Url::parse` only understands http/https; the synthetic URL
    // is the simplest valid loopback shape. Tests do not assert
    // its content.
    Url::parse(&format!("http://local/{basename}"))
        .unwrap_or_else(|_| Url::parse("http://local/").expect("loopback url parses"))
}

/// Reject the random-access formats — ZIP, RAR, 7z — in local
/// mode for now (`docs/PLAN_local_file_extract.md` §2 step 5).
///
/// The plan asserts these formats have a "fed a local file" entry
/// point; the audit in §3 confirmed they don't yet — every
/// shipping pipeline goes through
/// [`crate::download::BlockingSparseReader`]. Surfacing a
/// dedicated error keeps the failure mode honest and gives a
/// future contributor a clear "follow-on work" hook.
fn reject_random_access_formats(
    factory: DecoderFactory,
    registry: &DecoderRegistry,
) -> Result<(), CoordinatorError> {
    let name = registry.name_for_factory(factory).unwrap_or("?");
    let is_random_access = name == ZIP_FORMAT_NAME || name == SEVENZ_FORMAT_NAME || {
        #[cfg(feature = "rar")]
        {
            name == RAR_FORMAT_NAME
        }
        #[cfg(not(feature = "rar"))]
        {
            false
        }
    };
    if is_random_access {
        return Err(CoordinatorError::NoDecoder {
            filename: format!(
                "{name} (random-access; local-file extraction not yet \
                 supported — re-run against the HTTP source instead)"
            ),
        });
    }
    Ok(())
}

/// Pre-flight check: ensure the source's filesystem supports
/// hole-punching when destructive mode is requested.
///
/// We do *not* call the puncher with a probe at offset 0 — there
/// is no safe probe shape (`length == 0` short-circuits at every
/// in-tree puncher, and a non-zero probe would destroy the
/// archive's first block before extraction even started). Instead,
/// destructive mode relies on the extractor's runtime detection:
/// the first real punch attempt either succeeds (FS supports it)
/// or returns [`crate::punch::PunchError::Unsupported`], in which
/// case the extractor flips
/// [`crate::extractor::ExtractionStats::punch_unsupported`] and
/// runs the rest of the extraction without releasing blocks. The
/// caller of [`run`] inspects that flag after extraction completes
/// and, in destructive mode on an unsupported FS, **preserves the
/// source archive** (it is, by definition, still intact — no
/// successful punch happened) and logs the rationale.
///
/// The plan asked for an upfront probe that errors at the
/// `LocalPunchUnsupported` variant; the runtime-fallback variant
/// preserves the same UX (user gets either a clean
/// destructive run or a clean non-destructive one) without the
/// risk of corrupting bytes during the probe itself.
fn note_destructive_pre_flight() {
    // No-op; documented for future contributors looking for the
    // pre-flight call site. See the comment above for the
    // rationale.
}

/// Run the local-file extraction pipeline
/// (`docs/PLAN_local_file_extract.md` §2).
///
/// # Errors
///
/// Returns the appropriate [`CoordinatorError`] variant on any
/// IO, decoder construction, or extractor failure. The
/// [`CoordinatorError::Aborted`] variant fires when the
/// caller-supplied kill switch trips between checkpoints.
pub fn run(args: LocalRunArgs) -> Result<RunStats, CoordinatorError> {
    let started = Instant::now();
    note_destructive_pre_flight();

    // Open the source with read+write so the puncher can issue
    // `fallocate(PUNCH_HOLE)` against it. Read-only would suffice
    // for the decoder, but the in-loop puncher needs write access
    // to release blocks. With `-k` set the puncher is a no-op and
    // write access is moot, but the cost of opening read+write
    // anyway is one extra `open(2)` flag — not worth the dispatch
    // complexity to special-case.
    let mut source_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&args.source)
        .map_err(|source| CoordinatorError::Io {
            path: args.source.clone(),
            source,
        })?;
    let source_meta = source_file
        .metadata()
        .map_err(|source| CoordinatorError::Io {
            path: args.source.clone(),
            source,
        })?;
    let total_size = source_meta.len();

    let (format_shape, factory, prefix) = select_local_decoder_factory(&args, &mut source_file)?;
    reject_random_access_formats(factory, &args.registry)?;

    // The CLI resolver runs against the source's filename suffix
    // and `--format` overrides only — magic detection happens
    // inside this module. A magic-detected format that flips the
    // shape away from the user's `-o` path is caught here, before
    // any decoder construction or sink open touches the disk.
    crate::coordinator::verify_output_shape_local(format_shape, &args.output)?;

    if let Some(state) = &args.progress_state {
        // Local-mode progress UX (`docs/PLAN_local_file_extract.md` §4):
        // feed the renderer through the same `bytes_downloaded` /
        // `bytes_extracted` channels the HTTP path uses, but skip
        // every `worker_started` / `worker_finished` / `set_total_workers`
        // call — local mode has one logical reader and no chunked
        // download grid to render. The renderer shows "workers 0/0"
        // (harmless) and an ETA driven by the source-read rate
        // alone.
        state.set_total_size(total_size);
        state.mark_started();
    }

    // The decoder reads from the file; the puncher punches the
    // same file. We clone the descriptor so the decoder's
    // sequential Read state (its own file offset) is independent
    // of the puncher's `fd` — punching does not move the file
    // offset, but the borrow checker still wants distinct
    // handles.
    let decoder_file = source_file
        .try_clone()
        .map_err(|source| CoordinatorError::Io {
            path: args.source.clone(),
            source,
        })?;
    let reader: Box<dyn Read + Send> = {
        let mut f = decoder_file;
        // Magic detection consumed `prefix.len()` bytes of the
        // decoder-side file cursor; the post-detection `seek(0)`
        // on `source_file` only moved that handle since each
        // [`File`] clone has its own kernel-tracked offset.
        // Re-seek the decoder clone unconditionally — cheap on a
        // local file and keeps the with-prefix and no-prefix paths
        // identical.
        let _ = prefix;
        f.seek(SeekFrom::Start(0))
            .map_err(|source| CoordinatorError::Io {
                path: args.source.clone(),
                source,
            })?;
        // Wrap the file in a [`ProgressReader`] when a shared
        // [`ProgressState`] is attached: each successful read
        // pumps `add_downloaded` / `set_bytes_decoded_input` so
        // the renderer's existing percent/ETA math has a signal
        // to track (`docs/PLAN_local_file_extract.md` §4). No
        // worker grid is registered, so "workers 0/0" displays
        // unobtrusively next to the progress bar.
        match args.progress_state.clone() {
            Some(state) => Box::new(ProgressReader::new(f, state)),
            None => Box::new(f),
        }
    };

    let mut decoder = factory(reader).map_err(CoordinatorError::Decode)?;
    decoder.set_source_start_offset(0);

    // Puncher selection (`docs/PLAN_local_file_extract.md` §2
    // step 3): `-k` forces a NoopPuncher regardless of
    // `--io-backend`; destructive mode picks the platform default
    // (LinuxPuncher / MacosPuncher / Noop on other OSes).
    let puncher: Box<dyn PunchHole> = if args.keep_archive {
        Box::new(NoopPuncher::new())
    } else {
        default_puncher()
    };

    let effective_punch_threshold = if args.keep_archive {
        u64::MAX
    } else {
        args.punch_threshold
    };
    let extractor_cfg = ExtractorConfig {
        punch_threshold: effective_punch_threshold,
        checkpoint_min_bytes: args.checkpoint_min_bytes,
        checkpoint_min_interval: args.checkpoint_min_interval,
    };
    let mut extractor = Extractor::new(extractor_cfg);
    if let Some(state) = args.progress_state.clone() {
        extractor = extractor.with_progress(state);
    }
    if let Some(flag) = args.kill_switch.clone() {
        extractor = extractor.with_kill_switch(flag);
    }

    // Run the extractor against the source FD + decoder + sink.
    // §5 will replace this with a checkpoint-aware loop that
    // captures `decoder_state` / `sink_state` at every quiescent
    // advance; for §2 we run the extraction straight through and
    // rely on the user re-fetching on crash.
    let stats: ExtractionStats = match &args.output {
        OutputTarget::File(path) => {
            ensure_parent_dir(path)?;
            let sink = RawSink::create(path).map_err(CoordinatorError::Sink)?;
            run_extractor(
                &extractor,
                source_file.as_fd(),
                &mut *decoder,
                sink,
                puncher.as_ref(),
            )?
        }
        OutputTarget::Dir(path) => {
            fs::create_dir_all(path).map_err(|source| CoordinatorError::Io {
                path: path.clone(),
                source,
            })?;
            let sink = TarSink::new(path).map_err(CoordinatorError::Sink)?;
            run_extractor(
                &extractor,
                source_file.as_fd(),
                &mut *decoder,
                sink,
                puncher.as_ref(),
            )?
        }
    };

    // Drop the punching handle (and the decoder's clone) before
    // attempting to delete the source. Holding either across the
    // unlink would prevent immediate space reclamation on macOS
    // (Linux unlinks the inode lazily). The `decoder` value
    // dropped at the end of its enclosing block; `source_file`
    // we drop explicitly here.
    drop(decoder);
    drop(source_file);

    // Destructive-mode cleanup: delete the source on clean
    // completion *unless* the FS refused to punch (in which case
    // the bytes never went anywhere and deleting would be
    // surprising; preserve the source as if `-k` had been set).
    if !args.keep_archive {
        if stats.punch_unsupported {
            tracing::warn!(
                "filesystem does not support FALLOC_FL_PUNCH_HOLE; source archive {} \
                 preserved (extraction succeeded but holes were never punched)",
                args.source.display(),
            );
        } else {
            fs::remove_file(&args.source).map_err(|source| CoordinatorError::Io {
                path: args.source.clone(),
                source,
            })?;
        }
    }

    Ok(RunStats {
        final_url: local_run_url(&args.source),
        total_size,
        resumed: false,
        resume_decoder_position: None,
        resume_used_decoder_state: false,
        download: Default::default(),
        extraction: stats,
        elapsed: started.elapsed(),
    })
}

/// Ensure the parent directory of `path` exists; mirrors the
/// HTTP-side helper of the same shape so a `peel /tmp/foo.tar.zst
/// -o ./fresh/decoded.bin` invocation works even when `./fresh`
/// hasn't been created yet.
fn ensure_parent_dir(path: &Path) -> Result<(), CoordinatorError> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {
            fs::create_dir_all(parent).map_err(|source| CoordinatorError::Io {
                path: parent.to_path_buf(),
                source,
            })
        }
        _ => Ok(()),
    }
}

/// Convert an [`ExtractorError`] into a [`CoordinatorError`]. The
/// kill-switch sentinel string is translated into the typed
/// [`CoordinatorError::Aborted`] so the binary observes the same
/// shape as the HTTP path.
fn coord_err_from_extractor(err: ExtractorError) -> CoordinatorError {
    // The kill-switch sentinel is threaded through the
    // observer's io::Error; in §2 we don't pass an observer so
    // the only kill-switch path is the extractor's own (which
    // also surfaces via `ExtractorError::Observer`). Match the
    // sentinel string explicitly.
    if let ExtractorError::Observer(io_err) = &err {
        if io_err.to_string().contains("peel:kill-switch-tripped") {
            return CoordinatorError::Aborted {
                checkpoints_written: 0,
            };
        }
    }
    if let ExtractorError::Decode(DecodeError::Read { source, .. }) = &err {
        if source.to_string().contains("peel:kill-switch-tripped") {
            return CoordinatorError::Aborted {
                checkpoints_written: 0,
            };
        }
    }
    CoordinatorError::Extractor(err)
}

/// `Read` adapter that pumps two counters on every successful
/// read: `add_downloaded` and `set_bytes_decoded_input`. Used by
/// [`run`] to feed the renderer's percent / ETA math when a
/// shared [`ProgressState`] is attached
/// (`docs/PLAN_local_file_extract.md` §4).
///
/// The HTTP path feeds those counters from two distinct sources
/// (the download scheduler updates `bytes_downloaded`, the
/// decoder's source-read updates `bytes_decoded_input`); local
/// mode has no scheduler, so both counters track the same value
/// — the renderer's lookahead-computed-from-the-two
/// (`bytes_downloaded - bytes_decoded_input`) is always zero,
/// which is correct (there is nothing on disk *ahead* of the
/// decoder).
struct ProgressReader<R: Read> {
    inner: R,
    state: Arc<ProgressState>,
    total_read: u64,
}

impl<R: Read> ProgressReader<R> {
    fn new(inner: R, state: Arc<ProgressState>) -> Self {
        Self {
            inner,
            state,
            total_read: 0,
        }
    }
}

impl<R: Read> Read for ProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            self.total_read = self.total_read.saturating_add(n as u64);
            self.state.add_downloaded(n as u64);
            self.state.set_bytes_decoded_input(self.total_read);
        }
        Ok(n)
    }
}

/// Generic wrapper around [`Extractor::extract`] that maps the
/// extractor's error surface into [`CoordinatorError`].
fn run_extractor<S: Sink>(
    extractor: &Extractor,
    source_fd: std::os::fd::BorrowedFd<'_>,
    decoder: &mut dyn StreamingDecoder,
    sink: S,
    puncher: &dyn PunchHole,
) -> Result<ExtractionStats, CoordinatorError> {
    extractor
        .extract(source_fd, decoder, sink, puncher)
        .map_err(coord_err_from_extractor)
}
