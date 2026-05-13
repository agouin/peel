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
//! This module handles **every** format peel supports. Streaming
//! formats (`zstd`, `xz`, `lz4`, `gzip`, plus any of those wrapping
//! a tar) flow through [`crate::extractor::Extractor`] driven by a
//! plain [`std::fs::File`]. Random-access formats (ZIP, 7z, RAR —
//! both RAR5 and legacy RAR3/RAR4) route through their per-format
//! pipelines from [`crate::download::zip_pipeline`],
//! [`crate::download::sevenz_pipeline`], and
//! [`crate::download::rar_pipeline`]; those pipelines consume a
//! [`crate::download::MultiSparse`] + [`crate::bitmap::ChunkBitmap`]
//! pair, and the local path provides that pair by opening the
//! user's archive read-only via
//! [`crate::download::SparseFile::open_readonly`] and pre-filling
//! the bitmap so every chunk reads "complete" on the first poll.
//! The pipelines run unchanged. Destructive mode (`-d`) is
//! suppressed for random-access formats — their pipelines seek
//! backwards into the archive (zip's central directory at the tail,
//! 7z's trailer, rar's per-entry headers), so a monotonic punch
//! cursor can't be maintained.

#![cfg(unix)]

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use crate::bitmap::ChunkBitmap;
use crate::checkpoint::{Checkpoint, CheckpointError, PartRecord, RunMode, SinkState};
use crate::coordinator::{CoordinatorError, OutputTarget, ProgressFn, RunStats, KILL_SENTINEL};
use crate::decode::{DecodeError, DecoderFactory, DecoderRegistry, FormatShape, StreamingDecoder};
use crate::download::multi_sparse::MultiSparse;
#[cfg(feature = "rar")]
use crate::download::rar_pipeline::{
    RarExtractionStats, RarPipeline, RarPipelineConfig, RarPipelineError, RarResumeState,
};
use crate::download::scheduler::{DownloadStats, SchedulerError};
use crate::download::sevenz_pipeline::{
    SevenzExtractionStats, SevenzPipeline, SevenzPipelineConfig, SevenzPipelineError,
    SevenzPipelineEvent, SevenzResumeState,
};
use crate::download::sparse_file::SparseFile;
use crate::download::zip_pipeline::{
    ZipExtractionStats, ZipPipeline, ZipPipelineConfig, ZipPipelineError, ZipPipelineEvent,
    ZipResumeState,
};
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
#[cfg(feature = "rar")]
use crate::sink::RarSink;
use crate::sink::{RawSink, SevenzSink, Sink, TarSink, ZipSink};
use crate::types::{ByteOffset, ChunkIndex};
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
    /// `-d/--destructive`. `false` (the default) preserves the
    /// source archive across the run — no punching, no deletion.
    /// `true` opts into the disk-pressure contract: the source is
    /// punched as the decoder advances and deleted on clean
    /// completion (`docs/PLAN_local_file_extract.md` §1).
    pub destructive: bool,
    /// Extractor-side minimum gap between in-loop punch syscalls.
    /// Ignored when [`Self::destructive`] is `false`.
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

    /// Password source for encrypted archives
    /// (`docs/PLAN_archive_encryption.md` §1). Mirrors
    /// [`crate::coordinator::CoordinatorConfig::password_source`]
    /// for the local-mode path; the format-specific pipeline calls
    /// [`crate::secret::source::PasswordSource::load`] when it
    /// discovers an encrypted entry.
    pub password_source: Option<crate::secret::source::PasswordSource>,
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
            destructive: false,
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
            password_source: None,
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

/// Identify a random-access format (ZIP, 7z, RAR) by registry name.
///
/// Random-access formats keep their metadata at the end of the
/// archive (zip/7z) or walk a header chain (rar), so they can't
/// flow through the same single-pass streaming decoder the rest of
/// the local-file path uses. They route through their own
/// per-pipeline orchestrators
/// ([`crate::download::ZipPipeline`],
/// [`crate::download::sevenz_pipeline::SevenzPipeline`], and
/// [`crate::download::rar_pipeline::RarPipeline`] under the `rar`
/// feature), driven from [`run_random_access_local`].
///
/// Returns the registry name when the resolved factory is one of
/// the random-access shapes; `None` otherwise.
fn random_access_format_name(
    factory: DecoderFactory,
    registry: &DecoderRegistry,
) -> Option<&'static str> {
    let name = registry.name_for_factory(factory)?;
    if name == ZIP_FORMAT_NAME {
        return Some(ZIP_FORMAT_NAME);
    }
    if name == SEVENZ_FORMAT_NAME {
        return Some(SEVENZ_FORMAT_NAME);
    }
    #[cfg(feature = "rar")]
    if name == RAR_FORMAT_NAME {
        return Some(RAR_FORMAT_NAME);
    }
    None
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

/// Resume planning surface for [`run`]
/// (`docs/PLAN_local_file_extract.md` §5).
///
/// Fresh runs land in [`Self::Fresh`]; runs that found a valid
/// `.peel.ckpt` on disk land in [`Self::Resume`] with the
/// decoder/sink state needed to pick up where the prior run left
/// off. The plan keeps the resume payload tiny on purpose: the
/// existing [`Checkpoint`] format does the heavy lifting (decoder
/// state blob, sink state, source-mtime drift detection); local
/// mode's contribution is the `LocalDestructive` `RunMode` tag
/// plus the `source_mtime` trailer.
#[derive(Debug, Clone)]
enum LocalResumePlan {
    Fresh,
    Resume {
        decoder_position: u64,
        decoder_state: Option<Vec<u8>>,
        sink_state: SinkState,
    },
}

/// Synthetic URL the local-destructive checkpoint stores in its
/// [`Checkpoint::url`] / [`PartRecord::url`] slots
/// (`docs/PLAN_local_file_extract.md` §5). The local-mode resume
/// validator strips the `local://` scheme prefix and compares
/// against the canonicalized source path on disk.
fn local_url_for(path: &Path) -> String {
    let canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    format!("local://{}", canon.display())
}

/// Reverse [`local_url_for`]: extract a [`PathBuf`] from a
/// `local://<path>` URL synthesized by an earlier
/// destructive-mode run.
fn path_from_local_url(url: &str) -> Option<PathBuf> {
    url.strip_prefix("local://").map(PathBuf::from)
}

/// Compute the `.peel.ckpt` path for a local-destructive run
/// (`docs/PLAN_local_file_extract.md` §5). The default is a
/// sibling of the source archive (`<source>.peel.ckpt`); the
/// `--workdir` override moves the file to a user-chosen
/// directory while keeping the basename.
fn local_checkpoint_path(args: &LocalRunArgs) -> PathBuf {
    let basename: OsString = args
        .source
        .file_name()
        .map(OsString::from)
        .unwrap_or_default();
    let mut ckpt_name = basename;
    ckpt_name.push(".peel.ckpt");
    match &args.workdir {
        Some(dir) => dir.join(ckpt_name),
        None => {
            let mut out = args.source.clone();
            out.set_file_name(ckpt_name);
            out
        }
    }
}

/// Read the source archive's `mtime` for the destructive-mode
/// resume validator. Falls back to the system's `UNIX_EPOCH` if
/// the platform doesn't surface `mtime` — the comparison then
/// still works (both runs see the same fallback) but loses the
/// swap-detection guarantee for that platform.
fn source_mtime(meta: &std::fs::Metadata) -> SystemTime {
    meta.modified().unwrap_or(std::time::UNIX_EPOCH)
}

/// Read and validate a prior local-destructive checkpoint, if
/// any. Returns [`LocalResumePlan::Fresh`] when there is nothing
/// to resume (including the `-k`/`--keep-archive` path, which is
/// always fresh per §6) or when the checkpoint is absent;
/// [`LocalResumePlan::Resume`] when a valid checkpoint exists
/// and the source on disk matches its expectations.
///
/// Mismatches (different path, length, mtime, or `RunMode`)
/// surface as a typed [`CoordinatorError::Checkpoint`] /
/// [`CoordinatorError::SourceChanged`] so the user gets a clear
/// "your archive changed, your `.peel.ckpt` is stale, here's
/// what to do" message instead of a silent re-extract producing
/// garbage.
fn read_local_resume_plan(
    args: &LocalRunArgs,
    ckpt_path: &Path,
    source_meta: &std::fs::Metadata,
) -> Result<LocalResumePlan, CoordinatorError> {
    if !args.destructive {
        // §6: non-destructive runs do not read or write
        // `.peel.ckpt`. A stale checkpoint from a prior destructive
        // run is warned about and otherwise ignored.
        if ckpt_path.exists() {
            tracing::warn!(
                "ignoring stale `.peel.ckpt` at {} for non-destructive local run; \
                 delete the file to silence this warning",
                ckpt_path.display(),
            );
        }
        return Ok(LocalResumePlan::Fresh);
    }
    let prior = Checkpoint::read(ckpt_path).map_err(CoordinatorError::Checkpoint)?;
    let Some(prior) = prior else {
        return Ok(LocalResumePlan::Fresh);
    };

    // Mode check: a `.peel.ckpt` from an HTTP run is misleading
    // here and would silently lose progress. Surface the
    // mismatch via the existing `CheckpointError::ModeMismatch`
    // variant — same shape as the HTTP-side mismatch error.
    if prior.mode != RunMode::LocalDestructive {
        return Err(CoordinatorError::Checkpoint(
            CheckpointError::ModeMismatch {
                old: prior.mode,
                new: RunMode::LocalDestructive,
            },
        ));
    }

    // Path drift: a `.peel.ckpt` carried over to a different
    // archive (e.g. user ran peel on `a.tar.zst`, then `mv`'d
    // it to `b.tar.zst` and re-ran) would silently feed the
    // resumed decoder the wrong bytes.
    let expected_path = path_from_local_url(&prior.url).unwrap_or_else(|| args.source.clone());
    let current_canon = args
        .source
        .canonicalize()
        .unwrap_or_else(|_| args.source.clone());
    if expected_path != current_canon {
        return Err(CoordinatorError::Checkpoint(
            CheckpointError::SourceMismatch {
                expected_path: expected_path.clone(),
                reason: format!(
                    "checkpoint refers to {}, current source is {}",
                    expected_path.display(),
                    current_canon.display(),
                ),
            },
        ));
    }

    // Length drift: a truncate or in-place rewrite changes the
    // size and invalidates the punched-blocks topology.
    if prior.total_size != source_meta.len() {
        return Err(CoordinatorError::Checkpoint(
            CheckpointError::SourceMismatch {
                expected_path,
                reason: format!(
                    "checkpoint declares total_size={}, current source has length {}",
                    prior.total_size,
                    source_meta.len(),
                ),
            },
        ));
    }

    // Mtime drift: a same-size swap is the residual case the
    // length check can't catch. `mtime` resolution varies by FS
    // (HFS+ rounds to seconds; APFS and ext4 keep nanoseconds),
    // so exact equality across runs is the right comparison —
    // any in-place edit moves the timestamp.
    let current_mtime = source_mtime(source_meta);
    if let Some(prior_mtime) = prior.source_mtime {
        if prior_mtime != current_mtime {
            return Err(CoordinatorError::Checkpoint(
                CheckpointError::SourceMismatch {
                    expected_path,
                    reason: format!(
                        "source mtime changed: checkpoint={:?}, current={:?}",
                        prior_mtime, current_mtime,
                    ),
                },
            ));
        }
    }

    Ok(LocalResumePlan::Resume {
        decoder_position: prior.decoder_position.get(),
        decoder_state: prior.decoder_state,
        sink_state: prior.sink_state,
    })
}

/// Build a fresh local-destructive [`Checkpoint`] tracking the
/// state surfaced by the extractor's quiescent-advance callback.
///
/// Most fields are uninteresting in local mode — there is no
/// bitmap, no chunk_crc32c, no per-part hashing — so we
/// synthesize the legacy HTTP-shaped fields with empty / zero
/// values. The serializer drops the unused trailers when the
/// values are empty, so the on-disk footprint stays small.
#[allow(clippy::too_many_arguments)]
fn build_local_checkpoint(
    source_path: &Path,
    total_size: u64,
    source_mtime: SystemTime,
    decoder_position: u64,
    sink_state: SinkState,
) -> Checkpoint {
    let url = local_url_for(source_path);
    Checkpoint {
        url: url.clone(),
        etag: None,
        last_modified: None,
        parts: vec![PartRecord {
            url,
            size: total_size,
            etag: None,
            last_modified: None,
            expected_sha256: None,
            volume_role: None,
        }],
        total_size,
        chunk_size: 0,
        decoder_position: ByteOffset::new(decoder_position),
        bitmap_completed: Vec::new(),
        created_at: SystemTime::now(),
        sink_state,
        hash_state: None,
        chunk_crc32c: None,
        decoder_state: None,
        mode: RunMode::LocalDestructive,
        source_mtime: Some(source_mtime),
    }
}

/// Sink-state shape mismatch: the resumed sink expects a Tar
/// state (Dir output) or Raw state (File output); anything else
/// means the checkpoint was written by a different sink type
/// and shouldn't be trusted.
fn check_sink_state_matches_output(
    sink_state: &SinkState,
    output: &OutputTarget,
) -> Result<(), CoordinatorError> {
    let matches = matches!(
        (sink_state, output),
        (SinkState::Raw { .. }, OutputTarget::File(_))
            | (SinkState::Tar { .. }, OutputTarget::Dir(_)),
    );
    if matches {
        return Ok(());
    }
    Err(CoordinatorError::Checkpoint(
        CheckpointError::ModeMismatch {
            old: RunMode::LocalDestructive,
            new: RunMode::LocalDestructive,
        },
    ))
}

/// Run the local-file extraction pipeline
/// (`docs/PLAN_local_file_extract.md` §2 + §5).
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

    // Probe the source read-only first so format detection runs
    // against a handle that doesn't require write permission. The
    // streaming-decoder path re-opens read+write below (the puncher
    // needs it for destructive mode); the random-access path
    // stays read-only the whole way through, so a read-only
    // archive on disk extracts cleanly.
    let mut probe_file = File::open(&args.source).map_err(|source| CoordinatorError::Io {
        path: args.source.clone(),
        source,
    })?;
    let source_meta = probe_file
        .metadata()
        .map_err(|source| CoordinatorError::Io {
            path: args.source.clone(),
            source,
        })?;
    let total_size = source_meta.len();
    let source_mtime_val = source_mtime(&source_meta);
    let ckpt_path = local_checkpoint_path(&args);

    let (format_shape, factory, _prefix) = select_local_decoder_factory(&args, &mut probe_file)?;

    // Random-access formats (zip / 7z / rar) take their own
    // non-destructive path through the existing per-format
    // pipelines — they read the user's archive through a
    // [`SparseFile::open_readonly`] wrapped in a [`MultiSparse`]
    // with a fully-marked [`ChunkBitmap`], so the existing
    // pipelines run unchanged (`docs/PLAN_local_file_extract.md`
    // §2 step 5).
    if let Some(name) = random_access_format_name(factory, &args.registry) {
        drop(probe_file);
        return run_random_access_local(&args, name, total_size, started);
    }

    // Streaming-decoder formats need read+write so the puncher
    // can issue `fallocate(PUNCH_HOLE)` in destructive mode. The
    // open succeeds for any mode-0600 archive; mode-0444 archives
    // can still extract through the random-access path above, but
    // not through this one.
    drop(probe_file);
    let mut source_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&args.source)
        .map_err(|source| CoordinatorError::Io {
            path: args.source.clone(),
            source,
        })?;
    // Re-seek to byte 0 + re-run the prefix probe so the decoder's
    // file handle starts at the same place it would have in the
    // single-open flow. Cheap; the metadata is already cached.
    let _ = select_local_decoder_factory(&args, &mut source_file)?;

    // The CLI resolver runs against the source's filename suffix
    // and `--format` overrides only — magic detection happens
    // inside this module. A magic-detected format that flips the
    // shape away from the user's `-o` path is caught here, before
    // any decoder construction or sink open touches the disk.
    crate::coordinator::verify_output_shape_local(format_shape, &args.output)?;

    // §5: read any prior `.peel.ckpt` and decide whether to
    // resume. The function rejects mismatched / stale checkpoints
    // with a typed error so the user is told *why* resume failed
    // instead of getting a silent re-extract producing garbage.
    let resume_plan = read_local_resume_plan(&args, &ckpt_path, &source_meta)?;
    let (resumed, resume_decoder_position, resume_used_decoder_state) = match &resume_plan {
        LocalResumePlan::Fresh => (false, None, false),
        LocalResumePlan::Resume {
            decoder_position,
            decoder_state,
            sink_state,
        } => {
            check_sink_state_matches_output(sink_state, &args.output)?;
            (true, Some(*decoder_position), decoder_state.is_some())
        }
    };

    if let Some(state) = &args.progress_state {
        // Local-mode progress UX (`docs/PLAN_local_file_extract.md` §4):
        // feed the renderer through the same `bytes_downloaded` /
        // `bytes_extracted` channels the HTTP path uses, but skip
        // every `worker_started` / `worker_finished` / `set_total_workers`
        // call — local mode has one logical reader and no chunked
        // download grid to render. `mark_local` flips the renderer
        // into the local-file shape (drops the download row, the
        // lookahead row, and the workers tally) so the bogus 0/0
        // worker count and duplicated download counters never reach
        // the user.
        state.set_total_size(total_size);
        state.mark_started();
        state.mark_local();
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
    let decoder_start_offset = resume_decoder_position.unwrap_or(0);
    let reader: Box<dyn Read + Send> = {
        let mut f = decoder_file;
        // Magic detection consumed bytes of the decoder-side
        // file cursor; the post-detection `seek(0)` on
        // `source_file` only moved that handle since each
        // [`File`] clone has its own kernel-tracked offset.
        // Re-seek the decoder clone to `decoder_start_offset` —
        // 0 for fresh runs, the resumed-from boundary for
        // resumes.
        f.seek(SeekFrom::Start(decoder_start_offset))
            .map_err(|source| CoordinatorError::Io {
                path: args.source.clone(),
                source,
            })?;
        // Pre-seed the renderer's `bytes_downloaded` counter
        // with the resume offset so the percent stays continuous
        // across kill/restart cycles.
        if let Some(state) = &args.progress_state {
            if decoder_start_offset > 0 {
                state.add_downloaded(decoder_start_offset);
                state.set_bytes_decoded_input(decoder_start_offset);
            }
        }
        match args.progress_state.clone() {
            Some(state) => Box::new(ProgressReader::new(f, state)),
            None => Box::new(f),
        }
    };

    // Decoder construction: use the format's resume factory if a
    // decoder-state blob is present AND the registry knows a
    // resume hook for the format (lz4 / xz_native / zstd today);
    // otherwise the regular factory takes the prefix-stripped
    // file and decodes from the resumed offset.
    let format_name_for_resume = args.registry.name_for_factory(factory).map(String::from);
    let resume_factory = match (resume_plan.clone(), format_name_for_resume.as_deref()) {
        (
            LocalResumePlan::Resume {
                decoder_state: Some(blob),
                decoder_position,
                ..
            },
            Some(name),
        ) => args
            .registry
            .resume_factory_for_name(name)
            .map(|f| (f, blob, decoder_position)),
        _ => None,
    };
    let mut decoder = match resume_factory {
        Some((rf, blob, start_offset)) => {
            rf(reader, &blob, start_offset).map_err(CoordinatorError::Decode)?
        }
        None => factory(reader).map_err(CoordinatorError::Decode)?,
    };
    decoder.set_source_start_offset(decoder_start_offset);

    // Puncher selection (`docs/PLAN_local_file_extract.md` §2
    // step 3): the non-destructive default forces a NoopPuncher
    // regardless of `--io-backend`; `-d/--destructive` picks the
    // platform default (LinuxPuncher / MacosPuncher / Noop on
    // other OSes).
    let puncher: Box<dyn PunchHole> = if args.destructive {
        default_puncher()
    } else {
        Box::new(NoopPuncher::new())
    };

    let effective_punch_threshold = if args.destructive {
        args.punch_threshold
    } else {
        u64::MAX
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

    // Destructive runs persist a `.peel.ckpt` at every
    // quiescent advance. Non-destructive runs skip the observer
    // entirely — there is nothing to recover from since the
    // source is never punched, so a kill mid-run is "restart
    // against the intact source".
    let write_checkpoints = args.destructive;
    let ckpt_writer = if write_checkpoints {
        Some(Arc::new(Mutex::new(LocalCheckpointWriter {
            source_path: args.source.clone(),
            total_size,
            source_mtime: source_mtime_val,
            ckpt_path: ckpt_path.clone(),
            writes: 0,
        })))
    } else {
        None
    };

    // Run the extractor with an observer that persists a
    // `.peel.ckpt` at every persist-eligible quiescent advance
    // (`docs/PLAN_local_file_extract.md` §5). Destructive mode
    // attaches the writer; `-k` mode passes a no-op observer.
    let stats: ExtractionStats = match &args.output {
        OutputTarget::File(path) => {
            ensure_parent_dir(path)?;
            let sink = build_local_raw_sink(path, &resume_plan)?;
            run_extractor_with_ckpt(
                &extractor,
                source_file.as_fd(),
                &mut *decoder,
                sink,
                puncher.as_ref(),
                ckpt_writer.clone(),
            )?
        }
        OutputTarget::Dir(path) => {
            fs::create_dir_all(path).map_err(|source| CoordinatorError::Io {
                path: path.clone(),
                source,
            })?;
            let sink = build_local_tar_sink(path, &resume_plan)?;
            run_extractor_with_ckpt(
                &extractor,
                source_file.as_fd(),
                &mut *decoder,
                sink,
                puncher.as_ref(),
                ckpt_writer.clone(),
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
    // surprising; preserve the source as the non-destructive
    // default would have). The `.peel.ckpt` is removed in both
    // completion branches — the run finished, so there is
    // nothing left to resume.
    if args.destructive {
        let _ = fs::remove_file(&ckpt_path);
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
        resumed,
        resume_decoder_position,
        resume_used_decoder_state,
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

/// Build a [`RawSink`] for the local-mode File-shape output,
/// honoring the resume plan. Fresh runs and resumes from a
/// non-Raw sink state (which is a programmer error caught
/// earlier) construct via [`RawSink::create`]; resumes from a
/// Raw sink state re-open the file at the previously-written
/// offset via [`RawSink::resume`].
fn build_local_raw_sink(path: &Path, plan: &LocalResumePlan) -> Result<RawSink, CoordinatorError> {
    match plan {
        LocalResumePlan::Fresh => RawSink::create(path).map_err(CoordinatorError::Sink),
        LocalResumePlan::Resume {
            sink_state: SinkState::Raw { bytes_written },
            ..
        } => RawSink::resume(path, *bytes_written).map_err(CoordinatorError::Sink),
        // The shape-match check earlier guarantees this is
        // unreachable, but the typed branch makes the panic
        // path local rather than relying on a misleading
        // construct downstream.
        LocalResumePlan::Resume { .. } => Err(CoordinatorError::Checkpoint(
            CheckpointError::ModeMismatch {
                old: RunMode::LocalDestructive,
                new: RunMode::LocalDestructive,
            },
        )),
    }
}

/// Build a [`TarSink`] for the local-mode Dir-shape output,
/// honoring the resume plan. Mirrors the HTTP-side
/// `build_tar_sink`: resumes carrying a v6 `TarSinkState`'s
/// `in_flight` go through [`TarSink::resume`] (mid-member
/// restart); fresh runs and resumes at a coarse member boundary
/// use [`TarSink::new`].
fn build_local_tar_sink(path: &Path, plan: &LocalResumePlan) -> Result<TarSink, CoordinatorError> {
    if let LocalResumePlan::Resume {
        sink_state: SinkState::Tar {
            in_flight: Some(state),
            ..
        },
        ..
    } = plan
    {
        return TarSink::resume(path, state).map_err(CoordinatorError::Sink);
    }
    TarSink::new(path).map_err(CoordinatorError::Sink)
}

/// Persistent state the local-destructive checkpoint observer
/// passes through to every `on_checkpoint` invocation
/// (`docs/PLAN_local_file_extract.md` §5).
///
/// The observer captures one shared `Arc<Mutex<…>>` of this
/// struct rather than threading a pile of small references
/// through the closure — keeps the observer's signature short
/// and lets future per-checkpoint diagnostics land here without
/// touching the closure body.
struct LocalCheckpointWriter {
    source_path: PathBuf,
    total_size: u64,
    source_mtime: SystemTime,
    ckpt_path: PathBuf,
    /// Cumulative count of durable checkpoint writes for this
    /// run. Diagnostic only — used in
    /// [`CoordinatorError::Aborted`]'s `checkpoints_written`
    /// field when the kill switch trips.
    writes: u64,
}

/// Run the extractor and (in destructive mode) persist a
/// `.peel.ckpt` at every persist-eligible quiescent advance.
///
/// The observer borrows the live decoder ref via
/// [`CheckpointInfo`] so the resume blob bytes flow into the
/// `Checkpoint` body buffer with one memcpy
/// (`PLAN_checkpoint_blob_dedup.md` Phase 2). When the writer
/// returns an error, the extractor propagates it as
/// [`ExtractorError::Observer`], which the outer mapper
/// converts to a `CoordinatorError::Checkpoint`.
fn run_extractor_with_ckpt<S: Sink>(
    extractor: &Extractor,
    source_fd: std::os::fd::BorrowedFd<'_>,
    decoder: &mut dyn StreamingDecoder,
    sink: S,
    puncher: &dyn PunchHole,
    writer: Option<Arc<Mutex<LocalCheckpointWriter>>>,
) -> Result<ExtractionStats, CoordinatorError> {
    let writer_for_observer = writer.clone();
    extractor
        .extract_with_callback(source_fd, decoder, sink, puncher, move |info| {
            let Some(w) = writer_for_observer.as_ref() else {
                return Ok(());
            };
            let mut guard = w
                .lock()
                .map_err(|_| std::io::Error::other("local checkpoint writer mutex poisoned"))?;
            // Build a v13 LocalDestructive checkpoint reflecting
            // the extractor's quiescent advance. The decoder's
            // resume blob (if any) flows into the body buffer via
            // `decoder_state_into` — the same one-memcpy path the
            // HTTP coordinator uses
            // (`PLAN_checkpoint_blob_dedup.md` Phase 2).
            let ckpt = build_local_checkpoint(
                &guard.source_path,
                guard.total_size,
                guard.source_mtime,
                info.source_position,
                info.sink_state.clone(),
            );
            ckpt.write_timed_with(&guard.ckpt_path, 0, |body| {
                info.decoder.decoder_state_into(body)
            })
            .map_err(|e| std::io::Error::other(format!("local checkpoint write: {e}")))?;
            guard.writes = guard.writes.saturating_add(1);
            Ok(())
        })
        .map_err(coord_err_from_extractor)
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

/// Chunk size the local random-access driver feeds the pipelines'
/// internal `BoundedSparseReader` / `SparseFileSliceReader`. The
/// bitmap is fully marked from the start, so the actual value
/// only affects the per-read boundary check (the reader bounds
/// its returned slice to one chunk at a time). 4 MiB matches the
/// HTTP-side default; small enough to keep the bitmap allocation
/// tiny (~8 bytes per 32 MiB), large enough to avoid extra
/// boundary loop iterations on big archives.
const LOCAL_RANDOM_ACCESS_CHUNK_SIZE: u64 = 4 * 1024 * 1024;

/// Drive zip / 7z / rar extraction against a local archive
/// (`docs/PLAN_local_file_extract.md` §2 step 5).
///
/// The trick: the existing per-format pipelines all consume a
/// [`MultiSparse`] + [`ChunkBitmap`] pair plus a few coordination
/// signals (`cursor`, `download_done`, `download_outcome`). For a
/// local file every range is always "complete" — we open the
/// archive read-only via [`SparseFile::open_readonly`], wrap it in
/// a one-part [`MultiSparse`], and pre-fill a [`ChunkBitmap`] so
/// every chunk reads "is_complete" on the first poll. The
/// pipelines then run unchanged: their reads dispatch into the
/// kernel `pread` path, their cursor steering becomes a no-op
/// (no workers to steer), and their `wait_for_range` calls return
/// immediately.
///
/// Destructive mode (`-d`) does not apply — random-access
/// pipelines seek backwards into the archive (zip's central
/// directory at the tail, 7z's trailer pointer, rar's per-entry
/// headers), so a monotonically-advancing punch cursor can't be
/// maintained. The plan asks us to warn and proceed
/// non-destructively when `-d` is set on a random-access source;
/// we do exactly that.
fn run_random_access_local(
    args: &LocalRunArgs,
    format_name: &str,
    total_size: u64,
    started: Instant,
) -> Result<RunStats, CoordinatorError> {
    let output_dir = match &args.output {
        OutputTarget::Dir(d) => d.clone(),
        OutputTarget::File(path) => {
            return Err(CoordinatorError::OutputShapeMismatch {
                shape: FormatShape::Tree,
                path: path.clone(),
                detail: format!(
                    "{format_name} produces a directory tree but `-o {}` is a file path. \
                     Pass a directory path (trailing slash optional) instead.",
                    path.display(),
                ),
            })
        }
    };

    if args.destructive {
        tracing::warn!(
            format = format_name,
            source = %args.source.display(),
            "destructive mode does not apply to random-access formats; \
             source will be preserved. Drop `-d` to silence this warning.",
        );
    }

    // Flip the renderer (if any) into the local-file shape before
    // we hand control to the random-access pipeline. The pipelines
    // themselves take `progress_state: None`, so no bytes flow into
    // the shared state from here — but `mark_local` still drops the
    // bogus "download / workers / lookahead" rows the renderer
    // would otherwise paint with zeros.
    if let Some(state) = args.progress_state.as_ref() {
        state.set_total_size(total_size);
        state.mark_started();
        state.mark_local();
    }

    fs::create_dir_all(&output_dir).map_err(|source| CoordinatorError::Io {
        path: output_dir.clone(),
        source,
    })?;

    // Open the user's archive read-only via SparseFile so the
    // existing pipelines accept it through MultiSparse. The
    // read-only flag prevents any accidental write/punch path
    // (the random-access pipelines never call those methods
    // themselves, but the guard catches future regressions).
    let sparse_file =
        SparseFile::open_readonly(&args.source).map_err(CoordinatorError::SparseFile)?;
    let sparse = MultiSparse::from_single(sparse_file);

    // Build a ChunkBitmap that's fully marked from the start so
    // every `is_complete` / `wait_for_range` call inside the
    // pipelines returns immediately.
    let chunk_size = LOCAL_RANDOM_ACCESS_CHUNK_SIZE;
    let num_chunks_u64 = if total_size == 0 {
        1u64
    } else {
        total_size.div_ceil(chunk_size)
    };
    let num_chunks = u32::try_from(num_chunks_u64).map_err(|_| CoordinatorError::Io {
        path: args.source.clone(),
        source: io::Error::other(format!(
            "archive at {} is too large for a {chunk_size}-byte chunk bitmap \
             ({num_chunks_u64} chunks > u32::MAX); split the file or raise \
             LOCAL_RANDOM_ACCESS_CHUNK_SIZE",
            args.source.display(),
        )),
    })?;
    let bitmap = ChunkBitmap::new(num_chunks);
    bitmap.complete_range(ChunkIndex::new(0), ChunkIndex::new(num_chunks));

    // Coordination signals the pipelines borrow. There is no
    // download thread, no scheduler, no progress-side throttle —
    // the cursor never gets read, `download_done` stays `false`
    // for the whole run (the pipelines only consult it on the
    // not-yet-complete path, which we never enter), and the
    // outcome slot is never populated.
    let cursor = Arc::new(AtomicU64::new(0));
    let download_done = Arc::new(AtomicBool::new(false));
    let download_outcome: Arc<Mutex<Option<Result<DownloadStats, SchedulerError>>>> =
        Arc::new(Mutex::new(None));

    let kill_switch = args.kill_switch.as_ref();
    let password_source = args.password_source.as_ref();
    let label = args.source.display().to_string();

    let stats = match format_name {
        ZIP_FORMAT_NAME => run_zip_local(
            &sparse,
            &bitmap,
            &cursor,
            &download_done,
            &download_outcome,
            &output_dir,
            total_size,
            chunk_size,
            kill_switch,
            password_source,
            &label,
        )?,
        SEVENZ_FORMAT_NAME => run_sevenz_local(
            &sparse,
            &bitmap,
            &cursor,
            &download_done,
            &download_outcome,
            &output_dir,
            total_size,
            chunk_size,
            kill_switch,
            password_source,
            &label,
        )?,
        #[cfg(feature = "rar")]
        RAR_FORMAT_NAME => run_rar_local(
            &sparse,
            &bitmap,
            &cursor,
            &download_done,
            &download_outcome,
            &output_dir,
            total_size,
            chunk_size,
            kill_switch,
            password_source,
            &label,
        )?,
        _ => {
            return Err(CoordinatorError::NoDecoder {
                filename: format!("unknown random-access format `{format_name}`"),
            })
        }
    };

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

/// Inner driver: zip pipeline over a local random-access source.
#[allow(clippy::too_many_arguments)]
fn run_zip_local(
    sparse: &MultiSparse,
    bitmap: &ChunkBitmap,
    cursor: &Arc<AtomicU64>,
    download_done: &Arc<AtomicBool>,
    download_outcome: &Arc<Mutex<Option<Result<DownloadStats, SchedulerError>>>>,
    output_dir: &Path,
    total_size: u64,
    chunk_size: u64,
    kill_switch: Option<&Arc<AtomicBool>>,
    password_source: Option<&crate::secret::source::PasswordSource>,
    label: &str,
) -> Result<ExtractionStats, CoordinatorError> {
    let mut sink = ZipSink::new(output_dir).map_err(CoordinatorError::Sink)?;
    let pipeline_cfg = ZipPipelineConfig {
        total_size,
        chunk_size,
        poll_interval: Duration::from_millis(1),
        initial_tail_window: crate::zip::MAX_EOCD_TAIL_BYTES.min(total_size),
    };
    let pipeline = ZipPipeline {
        config: pipeline_cfg,
        sparse,
        bitmap,
        cursor,
        download_done,
        download_outcome,
        progress_state: None,
        password_source,
        password_label: label,
    };
    let puncher = NoopPuncher::new();
    let result = pipeline.run(&mut sink, &puncher, ZipResumeState::default(), |event| {
        if let Some(flag) = kill_switch {
            if flag.load(Ordering::Acquire) {
                return Err(io::Error::other(KILL_SENTINEL));
            }
        }
        match event {
            ZipPipelineEvent::Started { .. }
            | ZipPipelineEvent::EntryFinished { .. }
            | ZipPipelineEvent::InEntryProgress { .. } => Ok(()),
        }
    });
    match result {
        Ok(stats) => {
            sink.close().map_err(CoordinatorError::Sink)?;
            Ok(extraction_stats_from_zip(stats, total_size))
        }
        Err(ZipPipelineError::Aborted(e)) if e.to_string() == KILL_SENTINEL => {
            Err(CoordinatorError::Aborted {
                checkpoints_written: 0,
            })
        }
        Err(other) => Err(CoordinatorError::Zip(other)),
    }
}

/// Inner driver: 7z pipeline over a local random-access source.
#[allow(clippy::too_many_arguments)]
fn run_sevenz_local(
    sparse: &MultiSparse,
    bitmap: &ChunkBitmap,
    cursor: &Arc<AtomicU64>,
    download_done: &Arc<AtomicBool>,
    download_outcome: &Arc<Mutex<Option<Result<DownloadStats, SchedulerError>>>>,
    output_dir: &Path,
    total_size: u64,
    chunk_size: u64,
    kill_switch: Option<&Arc<AtomicBool>>,
    password_source: Option<&crate::secret::source::PasswordSource>,
    label: &str,
) -> Result<ExtractionStats, CoordinatorError> {
    let mut sink = SevenzSink::new(output_dir).map_err(CoordinatorError::Sink)?;
    let pipeline_cfg = SevenzPipelineConfig {
        total_size,
        chunk_size,
        poll_interval: Duration::from_millis(1),
    };
    let pipeline = SevenzPipeline {
        config: pipeline_cfg,
        sparse,
        bitmap,
        cursor,
        download_done,
        download_outcome,
        progress_state: None,
        password_source,
        password_label: label,
    };
    let puncher = NoopPuncher::new();
    let result = pipeline.run(&mut sink, &puncher, SevenzResumeState::default(), |event| {
        if let Some(flag) = kill_switch {
            if flag.load(Ordering::Acquire) {
                return Err(io::Error::other(KILL_SENTINEL));
            }
        }
        match event {
            SevenzPipelineEvent::Started { .. }
            | SevenzPipelineEvent::FolderFinished { .. }
            | SevenzPipelineEvent::Complete { .. } => Ok(()),
        }
    });
    match result {
        Ok(stats) => Ok(extraction_stats_from_sevenz(stats, total_size)),
        Err(SevenzPipelineError::Aborted(e)) if e.to_string() == KILL_SENTINEL => {
            Err(CoordinatorError::Aborted {
                checkpoints_written: 0,
            })
        }
        Err(SevenzPipelineError::Sevenz(e)) | Err(SevenzPipelineError::FolderDecode(e)) => {
            Err(CoordinatorError::Sevenz(e))
        }
        Err(SevenzPipelineError::Sink(e)) => Err(CoordinatorError::Sink(e)),
        Err(SevenzPipelineError::Sparse(e)) => Err(CoordinatorError::SparseFile(e)),
        Err(other) => Err(CoordinatorError::SevenzPipeline(other)),
    }
}

/// Inner driver: RAR pipeline over a local random-access source.
#[cfg(feature = "rar")]
#[allow(clippy::too_many_arguments)]
fn run_rar_local(
    sparse: &MultiSparse,
    bitmap: &ChunkBitmap,
    cursor: &Arc<AtomicU64>,
    download_done: &Arc<AtomicBool>,
    download_outcome: &Arc<Mutex<Option<Result<DownloadStats, SchedulerError>>>>,
    output_dir: &Path,
    total_size: u64,
    chunk_size: u64,
    kill_switch: Option<&Arc<AtomicBool>>,
    password_source: Option<&crate::secret::source::PasswordSource>,
    label: &str,
) -> Result<ExtractionStats, CoordinatorError> {
    let mut sink = RarSink::new(output_dir).map_err(CoordinatorError::Sink)?;
    let pipeline_cfg = RarPipelineConfig {
        total_size,
        chunk_size,
        poll_interval: Duration::from_millis(1),
        initial_header_window: 64 * 1024,
        volume_starts: Vec::new(),
    };
    let pipeline = RarPipeline {
        config: pipeline_cfg,
        sparse,
        bitmap,
        cursor,
        download_done,
        download_outcome,
        progress_state: None,
        password_source,
        password_label: label,
    };
    let puncher = NoopPuncher::new();
    let result = pipeline.run(&mut sink, &puncher, RarResumeState::default(), |event| {
        if let Some(flag) = kill_switch {
            if flag.load(Ordering::Acquire) {
                return Err(io::Error::other(KILL_SENTINEL));
            }
        }
        let _ = event;
        Ok(())
    });
    match result {
        Ok(stats) => Ok(extraction_stats_from_rar(stats, total_size)),
        Err(RarPipelineError::Aborted(e)) if e.to_string() == KILL_SENTINEL => {
            Err(CoordinatorError::Aborted {
                checkpoints_written: 0,
            })
        }
        Err(other) => Err(CoordinatorError::Rar(other)),
    }
}

/// Convert [`ZipExtractionStats`] into the wider
/// [`ExtractionStats`] shape the local runner surfaces. Same
/// mapping the HTTP-side `run_zip` uses, minus the
/// CheckpointObserverStats merge (the local random-access path
/// writes no checkpoints).
fn extraction_stats_from_zip(stats: ZipExtractionStats, total_size: u64) -> ExtractionStats {
    ExtractionStats {
        bytes_in: total_size,
        bytes_out: stats.bytes_written,
        bytes_punched: stats.bytes_punched,
        punch_calls: u64::from(stats.entries_extracted),
        punch_unsupported: false,
        frame_boundaries_observed: u64::from(stats.entries_extracted),
        quiescent_checkpoints: 0,
        decode_time: Duration::default(),
        write_time: Duration::default(),
        punch_time: Duration::default(),
        ..ExtractionStats::default()
    }
}

/// Convert [`SevenzExtractionStats`] into [`ExtractionStats`].
/// Mirrors `extraction_stats_from_sevenz` in
/// [`crate::coordinator`].
fn extraction_stats_from_sevenz(stats: SevenzExtractionStats, total_size: u64) -> ExtractionStats {
    ExtractionStats {
        bytes_in: total_size,
        bytes_out: 0,
        bytes_punched: stats.bytes_punched,
        punch_calls: u64::from(stats.folders_extracted),
        punch_unsupported: false,
        frame_boundaries_observed: u64::from(stats.folders_extracted),
        quiescent_checkpoints: 0,
        decode_time: Duration::default(),
        write_time: Duration::default(),
        punch_time: Duration::default(),
        ..ExtractionStats::default()
    }
}

/// Convert [`RarExtractionStats`] into [`ExtractionStats`].
#[cfg(feature = "rar")]
fn extraction_stats_from_rar(stats: RarExtractionStats, total_size: u64) -> ExtractionStats {
    ExtractionStats {
        bytes_in: total_size,
        bytes_out: stats.bytes_written,
        bytes_punched: stats.bytes_punched,
        punch_calls: u64::from(stats.entries_extracted),
        punch_unsupported: false,
        frame_boundaries_observed: u64::from(stats.entries_extracted),
        quiescent_checkpoints: 0,
        decode_time: Duration::default(),
        write_time: Duration::default(),
        punch_time: Duration::default(),
        ..ExtractionStats::default()
    }
}
