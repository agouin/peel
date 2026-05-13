//! Command-line argument parsing for the `peel` binary.
//!
//! Kept thin on purpose: the binary entry point in `main.rs` parses
//! arguments, calls into [`crate::coordinator::run`], and formats the
//! result for the terminal. Anything more elaborate (config files,
//! profiles, …) is deferred per `docs/PLAN.md` §10.2 and the
//! "do-not-add-CLI-niceties" rule in `AGENTS.md`.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{ArgGroup, Parser, ValueEnum};

use crate::coordinator::local::LocalRunArgs;
use crate::coordinator::{filename_from_url, CoordinatorConfig, OutputTarget, RunArgs};
use crate::decode::{DecoderRegistry, FormatShape};
use crate::download::{
    parse_bandwidth, ParseBandwidthError, RetryConfig, DEFAULT_CHUNK_SIZE, DEFAULT_WORKERS,
};
use crate::extractor::DEFAULT_PUNCH_THRESHOLD;
use crate::hash::sha256::{parse_hex_digest, ParseHexDigestError};
use crate::http::{Client, ClientConfig, HttpVersion, Url, UrlError};
use crate::io_backend::IoBackendChoice;
use crate::secret::source::PasswordSource;

/// Long-form help appendix shown by `peel --help`
/// (`docs/PLAN_multivolume_archives.md` §6 step 3). Documents the
/// three multi-volume filename conventions and the three entry
/// modes (single-seed auto-discovery, explicit positional list,
/// `@manifest` file).
const MULTI_VOLUME_HELP_SECTION: &str = "\
Multi-volume archives:

  peel recognises three multi-volume naming conventions and resolves
  every sibling volume up front (one parallel `HEAD` per volume for
  HTTP seeds):

    RAR5  <base>.part<N>.rar   e.g. backup.part0001.rar
    7z    <base>.7z.<NNN>      e.g. snapshot.7z.001
    ZIP   <base>.z<NN> + <base>.zip   (spanned ZIP: `.zNN` volumes
          plus a mandatory `.zip` final containing the EOCD)

  Three equivalent invocation modes:

    1. Single seed (auto-discovery):
       peel https://h/foo.part0001.rar -o out/
       peel name.7z.001 -o out/

    2. Explicit positional list (volumes must form a contiguous
       numeric sequence; out-of-order entries are rejected):
       peel name.part0001.rar name.part0002.rar name.part0003.rar -o out/

    3. Manifest file (one URL or path per line, blank lines and
       `#` comments ignored):
       peel @volumes.txt -o out/

  `--no-auto-discover` forces single-source semantics on a seed
  whose basename happens to match a multi-volume pattern (useful
  for unrelated `.zip` files or high-latency origins where the
  HEAD probes are not worth it).
";

/// Parsed CLI for the `peel` binary.
#[derive(Debug, Parser)]
#[command(
    name = "peel",
    version,
    about = "Streaming, resumable, space-efficient extractor for compressed archives over HTTP.",
    after_long_help = MULTI_VOLUME_HELP_SECTION,
)]
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
    /// Source URL(s). One URL is the historical single-source case.
    /// Two or more URLs activate the multi-part split-archive path
    /// (`docs/PLAN_multi_url_source.md`): the byte-concatenation of
    /// every URL's body is treated as one logical archive stream,
    /// and the workers fetch all parts in parallel via ranged GETs.
    /// Examples: `peel https://host/x.tar.zst -o out/` or
    /// `peel https://host/x.tar.part0000 https://host/x.tar.part0001 -o out/`.
    #[arg(num_args = 1..)]
    pub urls: Vec<String>,

    /// Output path. Accepts either a directory (for archive formats
    /// that produce a directory tree — tar, zip, 7z, rar, and any
    /// compressed wrapper around tar) or a file (for stream-shaped
    /// formats — raw `.zst`, `.xz`, `.lz4`, `.gz`).
    ///
    /// A trailing slash forces directory semantics; otherwise the
    /// shape is taken from the URL suffix (or `--format`). The
    /// resolver errors at coordinator entry if the shape and the
    /// format disagree (`docs/PLAN_download_modes.md` §1).
    #[arg(short = 'o', long = "output-file", value_name = "PATH")]
    pub output_file: Option<PathBuf>,

    /// Migration stub for the removed `-C/--output-dir` flag.
    /// Hidden from `--help`; any value triggers a hard error pointing
    /// the user at `-o <path>/` (`docs/PLAN_download_modes.md` §1).
    #[arg(short = 'C', long = "output-dir", value_name = "DIR", hide = true)]
    pub output_dir_migration: Option<PathBuf>,

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

    /// Target wall-clock interval between checkpoints, in seconds.
    /// Used to scale the byte floor up at high download rates so the
    /// cadence stays below this target wall-clock interval. `0`
    /// disables rate-aware scaling.
    /// (`PLAN_checkpoint_cadence_throughput.md` Phase 2.)
    #[arg(long = "checkpoint-target-secs", default_value_t = 0.2)]
    pub checkpoint_target_secs: f64,

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
    /// `auto` (default) on Linux selects `mmap` for the sparse part
    /// file (workers `memcpy` into a `MAP_SHARED` region; puncher
    /// uses `madvise(MADV_REMOVE)`) and tries `io_uring` for the HTTP
    /// client's sockets, falling back to the blocking socket backend
    /// with an info log when the kernel rejects ring construction
    /// (e.g. cri-o's default seccomp profile). On non-Linux `auto` is
    /// the blocking backend for both sockets and file IO. `blocking`
    /// forces the pre-§7 `pwrite`/`pread` path everywhere (useful for
    /// A/B comparison). `uring` requires `io_uring` for sockets and
    /// errors out if it is unavailable. `mmap` selects the §9
    /// memory-mapped sparse-file path explicitly with the blocking
    /// socket backend.
    #[arg(long = "io-backend", value_enum, default_value_t = IoBackendArg::Auto)]
    pub io_backend: IoBackendArg,

    /// HTTP version to use for downloads.
    ///
    /// `auto` (default) negotiates between HTTP/1.1 and HTTP/2 via
    /// ALPN over TLS, and uses HTTP/1.1 over plaintext where ALPN
    /// does not apply. `h1` forces HTTP/1.1 only — H2 is not
    /// advertised in ALPN. `h2` forces HTTP/2: over TLS this requires
    /// the origin to negotiate `h2` (the handshake fails otherwise);
    /// over plaintext it forces HTTP/2 prior-knowledge ("h2c") which
    /// only works against servers that explicitly speak it. Most
    /// users want `auto`.
    #[arg(long = "http-version", value_enum, default_value_t = HttpVersionArg::Auto)]
    pub http_version: HttpVersionArg,

    /// SHA-256 digest(s) the source must match. Repeatable.
    ///
    /// Single-URL runs (`PLAN_v2.md` §10): pass `--sha256 <hex>`
    /// once; the coordinator hashes the assembled compressed source
    /// as it streams and aborts at clean completion if the digest
    /// disagrees. The hash state is checkpointed across resumes, so
    /// a `kill -9` and follow-up resume produce a digest
    /// byte-identical to a clean run.
    ///
    /// Multi-URL runs (`docs/PLAN_multi_url_source.md`): pass
    /// `--sha256` either zero times (no verification) or exactly
    /// once per URL, paired by order. The hashes are per-part
    /// digests of each part's bytes — the coordinator verifies each
    /// one at its part-boundary as the decoder advances (planned in
    /// §4 of that doc; phase 3 lands the CLI surface, phase 4 wires
    /// the runtime).
    ///
    /// Streaming pipeline only; `.zip` archives extract per-entry
    /// and integrity checking does not extend to that path in
    /// round-one of `PLAN_v2.md`.
    #[arg(long = "sha256", value_name = "HEX")]
    pub expected_sha256s: Vec<String>,

    /// Additional mirror URL serving the same file
    /// (`PLAN_v2.md` §13). The flag is repeatable; the positional
    /// `url` is the primary, and every `--mirror` is an alternate.
    /// At startup the coordinator runs `HEAD` against every URL in
    /// parallel and drops mirrors whose `Content-Length` (or, when
    /// `--sha256` is unset, `ETag` / `Last-Modified`) does not
    /// agree with the primary. Surviving mirrors are picked from
    /// per ranged GET, biased toward the fastest live one; failures
    /// exclude a mirror for 30 s before it is retried.
    #[arg(long = "mirror", value_name = "URL")]
    pub mirrors: Vec<String>,

    /// Aggregate bandwidth cap (`PLAN_v2.md` §14). Accepts decimal
    /// suffixes (`K`/`M`/`G`/`T`, 1000-based per network
    /// convention) and binary suffixes (`Ki`/`Mi`/`Gi`/`Ti`,
    /// 1024-based). A trailing `B` and `/s` are accepted and
    /// ignored. Examples: `10MB/s`, `1.5GB/s`, `512KiB/s`,
    /// `1000000`. The cap is aggregate across all mirrors, not
    /// per-mirror.
    #[arg(long = "max-bandwidth", value_name = "RATE")]
    pub max_bandwidth: Option<String>,

    /// Cap on the on-disk lookahead — bytes downloaded but not yet
    /// consumed by the decoder. When the gap reaches this value the
    /// download scheduler stops dispatching new chunks until the
    /// decoder catches up, bounding the size of the `.peel.part`
    /// file when the network is faster than the disk. Accepts the
    /// same size syntax as `--max-bandwidth` (e.g. `512MiB`,
    /// `2GB`); pass `none` (or `off` / `disabled`) to disable. The
    /// default (`1GiB`) is high enough that it rarely engages on a
    /// healthy disk and low enough that a slow disk doesn't fill
    /// `/tmp` on a multi-GiB archive.
    #[arg(long = "max-disk-buffer", value_name = "SIZE", default_value = "1GiB")]
    pub max_disk_buffer: String,

    /// Directory for the `.peel.part` and `.peel.ckpt` sidecar files.
    ///
    /// Default places them as siblings of the output (`<output>.peel.part`
    /// / `<output>.peel.ckpt`). Override when the output and the resumable
    /// state should live in different places — for example, extracting
    /// to slow HDD-backed storage while keeping the in-flight compressed
    /// bytes on faster SSD, or pinning the sidecars *inside* a Kubernetes
    /// PersistentVolume mount when the output's parent is on ephemeral
    /// container storage.
    ///
    /// The directory is created if missing. The basenames stay the same
    /// (`<output_name>.peel.part` / `<output_name>.peel.ckpt`); only
    /// their parent directory changes.
    #[arg(long = "workdir", value_name = "DIR")]
    pub workdir: Option<PathBuf>,

    /// Keep the source archive on disk alongside the extracted
    /// output (`docs/PLAN_download_modes.md` §3).
    ///
    /// HTTP-source forms:
    ///   * `-k` / `--keep-archive` (bare) — preserve the archive
    ///     as a sibling of `-o`, named after the URL basename.
    ///   * `-k=<PATH>` / `--keep-archive=<PATH>` — preserve the
    ///     archive at the explicit path. The `=` is required because
    ///     bare `-k` followed by a positional URL is otherwise
    ///     ambiguous.
    ///   * flag absent — default behaviour: the source bytes are
    ///     dropped (sparse hole-punching trims them as the decoder
    ///     advances; the part file is removed on success).
    ///
    /// Local-source mode preserves the source by default, so `-k`
    /// is a harmless no-op there (kept for scripts that pass `-k`
    /// across both HTTP and local sources). Pass `-d/--destructive`
    /// in local mode to opt into hole-punching + delete-on-success.
    /// The `-k=<PATH>` value form is rejected in local mode because
    /// the archive is already at the positional path.
    ///
    /// With `-k` the puncher is forced to no-op and the archive is
    /// preserved at its full `Content-Length` size. Redundant with
    /// `--no-extract` (which already preserves the source); the CLI
    /// logs an info-level note in that case rather than erroring.
    #[arg(
        short = 'k',
        long = "keep-archive",
        value_name = "PATH",
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = ""
    )]
    pub keep_archive: Option<String>,

    /// Skip extraction; download the source bytes verbatim to a
    /// single file (`docs/PLAN_download_modes.md` §2).
    ///
    /// The remote object is fetched in parallel via ranged GETs (the
    /// same scheduler / mirror / resume machinery the extract mode
    /// uses) and renamed into place on success. No decoder runs; no
    /// holes are punched in the sparse file. Useful for arbitrary
    /// remote downloads, non-archive objects (`.deb`, raw binaries,
    /// checksum lists), and for keeping the on-disk archive when you
    /// plan to extract it later with a different tool.
    ///
    /// Mutually exclusive with `--format`,
    /// `--force-format-from-magic`, and `--punch-threshold` (they
    /// are extractor knobs; nothing extracts in this mode). The
    /// `--download-only` alias is provided for users coming from
    /// `aria2c`.
    #[arg(long = "no-extract", alias = "download-only", default_value_t = false)]
    pub no_extract: bool,

    /// Treat unrecognized formats as a hard error
    /// (`docs/PLAN_download_modes.md` §4).
    ///
    /// Default behaviour, when format detection (URL suffix + magic
    /// bytes) cannot identify a registered decoder, is to warn and
    /// fall through to `--no-extract` (the remote object is saved
    /// to disk under its URL basename). `--strict-format` flips this
    /// to an error — useful in CI when an upstream object changing
    /// shape unexpectedly should fail the build instead of producing
    /// a different artifact.
    ///
    /// Incompatible with `--no-extract` (no detection runs when not
    /// extracting); compatible with `-k/--keep-archive`.
    #[arg(long = "strict-format", default_value_t = false)]
    pub strict_format: bool,

    /// Password source for encrypted archives
    /// (`docs/PLAN_archive_encryption.md` §1).
    ///
    /// Accepts one of:
    ///   * `prompt` — read from `/dev/tty` with echo disabled.
    ///     Up to 3 attempts on a wrong password before giving up.
    ///   * `env:NAME` — read from the named environment variable.
    ///   * `file:PATH` — read the first line of the file. Modes
    ///     other than `0600` emit a one-shot warning.
    ///   * `fd:N` — read from file descriptor N (until EOF or
    ///     newline). Compatible with shell process substitution
    ///     (`peel … --password-from fd:3 3< <(pass …)`).
    ///
    /// peel deliberately does not accept the password on the
    /// command line — `argv` is visible to every process on the
    /// host and is the wrong default. Users who really need a
    /// non-interactive single-step invocation can pipe one through
    /// `env:`, `file:`, or `fd:`.
    #[arg(long = "password-from", value_name = "SOURCE")]
    pub password_from: Option<String>,

    /// Skip multi-volume auto-discovery
    /// (`docs/PLAN_multivolume_archives.md` §1 / §6).
    ///
    /// Normally, when the user passes a single positional URL whose
    /// basename matches one of the recognised multi-volume patterns
    /// (`<base>.part<N>.rar`, `<base>.7z.<NNN>`, `<base>.z<NN>` or
    /// `<base>.zip`), peel HEAD-probes the origin to discover the
    /// full ordered volume set before any download starts. The
    /// resolved set is then routed through the multi-part storage
    /// path the same way an explicit positional URL list would be.
    ///
    /// `--no-auto-discover` forces the seed to be treated as a
    /// single-source URL even when its basename matches a
    /// multi-volume pattern. Useful when:
    ///
    /// - The seed's filename matches one of the conventions but is
    ///   not actually a multi-volume archive — e.g. an unrelated
    ///   `.zip` file you do not want peel to probe for `.z01`
    ///   siblings.
    /// - Discovery would fan out to many failed HEAD probes against
    ///   a high-latency origin and the operator already knows the
    ///   seed is a single source.
    ///
    /// Has no effect when the user supplied multiple positional
    /// URLs — that path already opts out of auto-discovery.
    #[arg(long = "no-auto-discover", default_value_t = false)]
    pub no_auto_discover: bool,

    /// Destroy the source archive as extraction proceeds
    /// (`docs/PLAN_local_file_extract.md` §1).
    ///
    /// Local-file mode is non-destructive by default — `peel
    /// abc.tar.xz` extracts into `./abc/` and leaves `abc.tar.xz`
    /// untouched. Passing `-d/--destructive` opts in to the
    /// disk-pressure contract of the HTTP path: the source is
    /// progressively hole-punched as the decoder advances and
    /// deleted on clean completion, freeing the archive's blocks
    /// before the extracted tree is fully written. `-d` overrides
    /// `-k` in local mode (info-logged; non-destructive is the
    /// default so `-k` is already a no-op there).
    ///
    /// HTTP runs are destructive by default already, so `-d` is a
    /// harmless no-op for an HTTP source (info-logged). Passing
    /// `-d` *and* `-k/--keep-archive` together with an HTTP source
    /// is an error — the two intents are contradictory.
    #[arg(short = 'd', long = "destructive", default_value_t = false)]
    pub destructive: bool,
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

/// CLI form of [`HttpVersion`].
///
/// Kept as a separate type so the [`clap::ValueEnum`] derive does not
/// have to live on the library type. Mapping is mechanical via
/// [`From`].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default, ValueEnum)]
#[value(rename_all = "lower")]
pub enum HttpVersionArg {
    /// ALPN-negotiate H1 / H2 over TLS; H1 over plaintext.
    #[default]
    Auto,
    /// Force HTTP/1.1.
    H1,
    /// Force HTTP/2 (prior-knowledge over plaintext).
    H2,
}

impl From<HttpVersionArg> for HttpVersion {
    fn from(arg: HttpVersionArg) -> Self {
        match arg {
            HttpVersionArg::Auto => Self::Auto,
            HttpVersionArg::H1 => Self::Http1Only,
            HttpVersionArg::H2 => Self::Http2Only,
        }
    }
}

/// One-line summary of the resolved [`HttpVersion`].
///
/// Single source of truth for the `http_version=...` banner: emitted
/// via `tracing::info!` on every run, and surfaced via the progress
/// renderer's banner so TTY users — whose INFO output is suppressed
/// to keep the in-place block clean — still see the configuration.
#[must_use]
pub fn http_version_banner(v: HttpVersion) -> &'static str {
    match v {
        HttpVersion::Auto => "http_version=auto (ALPN-negotiated H1/H2)",
        HttpVersion::Http1Only => "http_version=h1 (forced)",
        HttpVersion::Http2Only => "http_version=h2 (forced; h2c prior-knowledge over plaintext)",
    }
}

/// Errors produced by [`Cli::into_run_args`].
///
/// Wraps [`crate::http::ClientError`] (HTTP setup) and adds variants
/// for argument-validation failures the `clap` derive can't express
/// declaratively.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Building the HTTP client failed.
    #[error("HTTP client setup failed")]
    Client(#[from] crate::http::ClientError),

    /// Multi-volume HTTP auto-discovery
    /// (`docs/PLAN_multivolume_archives.md` §1) failed against a
    /// seed URL that matched a multi-volume pattern. Wraps the
    /// per-pattern diagnostic — `MissingVolume`, `FinalVolumeMissing`,
    /// or a `HEAD`-side network error — so the user knows
    /// auto-discovery was attempted (i.e. the seed pattern was
    /// recognised) but the resolved set was incomplete.
    #[error("multi-volume auto-discovery failed")]
    VolumeDiscovery(#[source] crate::multivolume::MvError),

    /// `--sha256 <HEX>` was given but the value did not parse as a
    /// 64-character hex digest.
    #[error("--sha256 value is not a valid SHA-256 digest")]
    InvalidSha256(#[source] ParseHexDigestError),

    /// `--max-bandwidth <RATE>` was given but the value did not
    /// parse as a recognized rate (e.g. `10MB/s`, `1.5GiB`).
    #[error("--max-bandwidth value is not a valid rate")]
    InvalidBandwidth(#[source] ParseBandwidthError),

    /// `--max-disk-buffer <SIZE>` was given but the value did not
    /// parse as a recognized size or one of the disable sentinels.
    #[error("--max-disk-buffer value is not a valid size")]
    InvalidDiskBuffer(#[source] ParseBandwidthError),

    /// `-o/--output-file` was not given and the URL did not parse as
    /// a valid URL — so no default output path could be derived.
    #[error("URL is not valid; pass -o <PATH> explicitly")]
    InvalidUrl(#[source] UrlError),

    /// `-o/--output-file` was not given and the URL has no usable
    /// basename (e.g. it ends in `/`) so no default output path
    /// could be derived.
    #[error("URL has no filename to derive a default output path from; pass -o <PATH> explicitly")]
    NoDefaultOutput,

    /// `-C/--output-dir` was passed. The flag was removed in favour
    /// of a unified `-o <PATH>` (`docs/PLAN_download_modes.md` §1);
    /// the stub exists only to emit a clear migration error.
    #[error(
        "-C/--output-dir was removed; use -o <PATH> instead \
         (a trailing slash on PATH means directory)"
    )]
    OutputDirRemoved,

    /// `--no-extract` was combined with an extractor-only knob
    /// (`--format`, `--force-format-from-magic`, or
    /// `--punch-threshold`) — these are meaningless when no
    /// extractor runs (`docs/PLAN_download_modes.md` §2.1).
    #[error(
        "--no-extract is incompatible with extractor-only flag `{flag}`: \
         no decoder runs in download-only mode"
    )]
    NoExtractConflict {
        /// Name of the conflicting flag.
        flag: &'static str,
    },

    /// `-k=<PATH>` was given but the resolved path already exists
    /// as a directory (`docs/PLAN_download_modes.md` §3.2). A regular
    /// file at the path is accepted — the coordinator overwrites it
    /// with a `tracing::warn!`; a directory would be ambiguous and
    /// is rejected at CLI parse time.
    #[error("--keep-archive path {} exists and is a directory; pass a file path instead", path.display())]
    KeepArchivePathIsDir {
        /// The user-supplied path.
        path: PathBuf,
    },

    /// `-o <PATH>` and the detected format shape disagree
    /// (`docs/PLAN_download_modes.md` §1).
    ///
    /// `shape` is the format's required output shape. For
    /// [`FormatShape::Tree`] the path was an existing regular file;
    /// for [`FormatShape::Stream`] the path was an existing directory
    /// or ended in a trailing slash.
    #[error("output path shape mismatch: {detail}")]
    OutputShapeMismatch {
        /// Shape required by the detected format.
        shape: FormatShape,
        /// The user-supplied path.
        path: PathBuf,
        /// Human-readable explanation of the mismatch (includes path
        /// and detected on-disk shape).
        detail: String,
    },

    /// `--sha256` was given a number of times that does not match
    /// the URL count (`docs/PLAN_multi_url_source.md` §3 step 2).
    /// For a single-URL run, 0 or 1 hash is accepted; for a
    /// multi-URL run, 0 or exactly `urls` hashes is accepted.
    #[error(
        "--sha256 count {hashes} does not match URL count {urls}: \
         pass either no `--sha256` (skip verification) or one per URL"
    )]
    ShaCountMismatch {
        /// How many positional URLs were given.
        urls: usize,
        /// How many `--sha256` flags were given.
        hashes: usize,
    },

    /// The CLI was constructed with zero positional URLs. Cannot be
    /// produced by `clap` parsing (the `#[arg(num_args = 1..)]`
    /// constraint guarantees at least one), but a library caller
    /// that builds a [`Cli`] by hand can hit this — and getting an
    /// explicit error is friendlier than a panic.
    #[error("at least one source URL is required")]
    NoUrls,

    /// `--mirror` was combined with multiple positional URLs. The
    /// `--mirror` flag means "alternate source for the same file"
    /// (a peer of the primary URL); multi-URL means "this archive
    /// is split across N URLs" (a sequence of distinct parts). The
    /// two semantics are mutually exclusive — combining them is
    /// rejected at parse time per `docs/PLAN_multi_url_source.md`
    /// §3 step 3. A future plan may add per-part mirroring.
    #[error(
        "--mirror is incompatible with multi-URL runs: \
         multi-URL treats each positional URL as a distinct part, \
         while --mirror treats the alternates as copies of the same source"
    )]
    MirrorMultipleUrls,

    /// A positional argument was a relative or absolute path but no
    /// regular file exists at it (`docs/PLAN_local_file_extract.md`
    /// §1). Distinct from [`Self::InvalidUrl`]: the input parses as
    /// neither an HTTP URL nor a path to an existing file, and the
    /// "does this file exist" check is the friendlier surface.
    #[error("no such file: {}", path.display())]
    LocalSourceNotFound {
        /// The path the user supplied.
        path: PathBuf,
    },

    /// A positional argument is a path but it resolves to a
    /// non-regular file (a directory, a symlink to a directory, a
    /// socket, etc.). Local mode requires a regular file.
    #[error("{} is not a regular file (local-mode source must be a regular file)", path.display())]
    LocalSourceNotRegularFile {
        /// The path the user supplied.
        path: PathBuf,
    },

    /// The positional arguments mix HTTP URLs and local file paths.
    /// peel rejects the combination at parse time
    /// (`docs/PLAN_local_file_extract.md` §1): resume semantics for
    /// a mixed source list are undefined and the UX gain from
    /// supporting it is nil.
    #[error(
        "cannot mix URL and local-file sources in one run \
         (got both `{url}` and `{path}`)"
    )]
    MixedSources {
        /// One example of an HTTP source from the list.
        url: String,
        /// One example of a local-file source from the list.
        path: PathBuf,
    },

    /// Multiple local-file positional arguments were given. peel
    /// supports exactly one local source today; multi-file local
    /// archives are deferred to the multi-volume plan
    /// (`docs/PLAN_local_file_extract.md` Out-of-scope).
    #[error(
        "local-file mode supports exactly one positional path \
         (got {count}); split-archive local extraction is not yet \
         implemented"
    )]
    LocalMultiSource {
        /// How many local paths the user passed.
        count: usize,
    },

    /// A flag was passed alongside a local-file source but the flag
    /// is HTTP-only (`docs/PLAN_local_file_extract.md` §1 step 2).
    /// All download knobs — `--mirror`, `--sha256`, `--workers`,
    /// `--chunk-size`, `--max-bandwidth`, `--max-disk-buffer`,
    /// `--http-version`, `--no-adaptive-chunk-size`,
    /// `--no-extract`, `--strict-format` — surface this variant.
    #[error(
        "flag `{flag}` does not apply to local-file mode \
         (it controls the HTTP download path)"
    )]
    LocalFlagNotApplicable {
        /// The conflicting flag's user-facing name.
        flag: &'static str,
    },

    /// `-k=<PATH>` was given alongside a local source. In local
    /// mode the archive already lives at the user-supplied
    /// positional path; the `-k <PATH>` value form is rejected per
    /// `docs/PLAN_local_file_extract.md` §1 step 3. Bare `-k` in
    /// local mode is a no-op (local mode preserves the source by
    /// default); pass `-d/--destructive` to hole-punch and delete
    /// the source as extraction proceeds.
    #[error(
        "`-k=<PATH>` does not apply to local-file mode \
         (the archive is already at the positional path; local mode \
         preserves the source by default — pass `-d/--destructive` to \
         opt into hole-punching + delete-on-success)"
    )]
    LocalKeepArchiveWithPath,

    /// `--password-from <SOURCE>` did not parse as a valid source
    /// (`docs/PLAN_archive_encryption.md` §1).
    #[error("--password-from value is not a valid password source")]
    InvalidPasswordSource(#[source] crate::secret::source::PasswordSourceParseError),

    /// Both `-d/--destructive` and `-k/--keep-archive` were passed
    /// alongside an HTTP source. `-d` asks for the downloaded
    /// archive to be hole-punched and deleted on success (the
    /// HTTP-mode default); `-k` asks for it to be preserved. The
    /// two intents are contradictory, so peel rejects the
    /// combination rather than silently picking one. (Local mode
    /// resolves this the other way — `-d` wins and `-k` is
    /// logged as a no-op — because the local-mode default is
    /// non-destructive and `-d` is the explicit opt-in signal.)
    #[error(
        "`-d/--destructive` and `-k/--keep-archive` are contradictory for HTTP sources: \
         drop `-d` (HTTP runs are destructive by default) or drop `-k` (to allow it)"
    )]
    HttpDestructiveConflictsKeepArchive,

    /// A `@<path>` manifest sentinel was passed alongside other
    /// positional URLs (`docs/PLAN_multivolume_archives.md` §6).
    /// The manifest *replaces* the positional list — combining the
    /// two forms is ambiguous (would the manifest entries prepend?
    /// append? overwrite?), so peel refuses to guess.
    #[error(
        "`@<file>` manifest must be the only positional argument; pass either a manifest \
         file or an explicit URL/path list, not both"
    )]
    ManifestPositionalConflict,

    /// Reading a `@<path>` manifest failed
    /// (`docs/PLAN_multivolume_archives.md` §6).
    #[error("failed to read manifest file `{}`", path.display())]
    ManifestReadFailed {
        /// Manifest path passed via `@<path>`.
        path: PathBuf,
        /// Underlying IO error.
        #[source]
        source: std::io::Error,
    },

    /// A `@<path>` manifest contained no non-blank, non-comment
    /// lines (`docs/PLAN_multivolume_archives.md` §6).
    #[error("manifest file `{}` has no URL/path entries", path.display())]
    ManifestEmpty {
        /// Manifest path passed via `@<path>`.
        path: PathBuf,
    },

    /// A positional list of multi-volume names did not form a
    /// contiguous numeric sequence
    /// (`docs/PLAN_multivolume_archives.md` §6). When every
    /// positional source matches a multi-volume convention of the
    /// same format, the volume numbers must walk `1, 2, 3, …` in
    /// the same order the sources are passed; a gap, a duplicate,
    /// or a backwards step rejects the list at parse time.
    #[error(
        "multi-volume positional list is out of order: entry {position} should be \
         volume {expected}, got `{got}`"
    )]
    OutOfOrderVolumeList {
        /// Zero-based index of the first offending positional source.
        position: usize,
        /// Volume number expected at that position (the seed's
        /// volume number `+ position`).
        expected: u32,
        /// Basename / URL of the offending entry as the user wrote
        /// it.
        got: String,
    },
}

/// Compression and archive suffixes stripped when deriving a default
/// output-directory name from a URL basename.
///
/// Applied iteratively (case-insensitive), so `archive.tar.xz` becomes
/// `archive` after `.xz` then `.tar` are stripped. `.tgz` / `.txz` /
/// `.tzst` / `.tbz2` etc. are listed explicitly because they are not a
/// suffix of `.tar` and would otherwise survive a single pass.
const STRIPPABLE_EXTENSIONS: &[&str] = &[
    ".tar", ".tgz", ".tzst", ".txz", ".tlz4", ".tbz2", ".tbz", ".gz", ".zst", ".zstd", ".xz",
    ".lz4", ".bz2", ".zip", ".7z", ".rar",
];

fn strip_archive_extensions(name: &str) -> &str {
    let mut s = name;
    loop {
        let lower = s.to_ascii_lowercase();
        let mut stripped = false;
        for ext in STRIPPABLE_EXTENSIONS {
            if lower.ends_with(ext) && s.len() > ext.len() {
                s = &s[..s.len() - ext.len()];
                stripped = true;
                break;
            }
        }
        if !stripped {
            return s;
        }
    }
}

/// Derive the default output directory when neither `-C` nor `-o` is
/// given: parse the URL, take its basename, strip the multi-volume
/// volume suffix (`docs/PLAN_multivolume_archives.md` §6 — handles
/// `.part<NN>.rar`, `.7z.<NN>`, `.z<NN>`, `.zip`), fall back to the
/// `.partNNNN` byte-concat suffix
/// (`docs/PLAN_multi_url_source.md` §3 step 4) if no volume pattern
/// matched, then strip known compression / archive extensions, and
/// place the result in the current working directory (as a relative
/// path).
fn default_output_dir(url: &str) -> Result<PathBuf, CliError> {
    let parsed = Url::parse(url).map_err(CliError::InvalidUrl)?;
    let name = filename_from_url(&parsed).ok_or(CliError::NoDefaultOutput)?;
    let depart = strip_volume_or_part_suffix(&name);
    let stripped = strip_archive_extensions(depart);
    if stripped.is_empty() {
        return Err(CliError::NoDefaultOutput);
    }
    Ok(PathBuf::from(stripped))
}

/// Strip either a multi-volume volume suffix
/// (`docs/PLAN_multivolume_archives.md` §6 — `.part<NN>.rar`,
/// `.7z.<NN>`, `.z<NN>`, `.zip`) or a byte-concat `.partNNNN`
/// suffix. Used by the output-name derivation so a seed of
/// `foo.7z.001` lands at `./foo/` rather than `./foo.7z.001/`,
/// and `foo.tar.part0000` keeps landing at `./foo/`.
///
/// The multi-volume pattern is checked first because some names
/// (e.g. `foo.tar.part0001.rar`) match both; the volume pattern
/// peels off the `.part0001.rar` suffix in one step while the
/// byte-concat parser would only see `.part0001` if the `.rar`
/// were not at the tail.
fn strip_volume_or_part_suffix(name: &str) -> &str {
    if let Some(parsed) = crate::multivolume::parse_volume_name(name) {
        // For ZIP final volumes (`<base>.zip`) the parsed base is
        // the user-facing identity, which is also what
        // [`strip_archive_extensions`] would have produced from
        // the original name (`.zip` is in `STRIPPABLE_EXTENSIONS`).
        // Either path lands on the same prefix.
        return slice_for_base(name, &parsed.base);
    }
    strip_part_suffix(name)
}

/// Helper for [`strip_volume_or_part_suffix`]: locate the
/// `base` prefix inside `name` and return the corresponding slice
/// from `name` so the result keeps the original casing rather than
/// the lowercased / normalized base returned by [`parse_volume_name`].
fn slice_for_base<'a>(name: &'a str, base: &str) -> &'a str {
    if name.len() >= base.len()
        && name[..base.len()].eq_ignore_ascii_case(base)
        && name.as_bytes()[..base.len()] == *base.as_bytes()
    {
        &name[..base.len()]
    } else if name.len() >= base.len() && name[..base.len()].eq_ignore_ascii_case(base) {
        // Case-folded match but bytes differ (e.g. seed had mixed
        // case for the base portion that parse_volume_name kept).
        &name[..base.len()]
    } else {
        // Defensive: parse_volume_name guarantees `base` is a
        // prefix of the original basename (modulo the suffix it
        // peeled off), so this branch is unreachable in practice.
        name
    }
}

/// If `name` ends in `.partNNNN…` (one or more decimal digits, any
/// length), strip that suffix. Used to turn `pruned.tar.part0000`
/// into `pruned.tar` before the regular extension-strip loop runs.
/// Conservative: requires a leading `.part` and at least one digit;
/// otherwise returns `name` unchanged.
fn strip_part_suffix(name: &str) -> &str {
    let lower = name.to_ascii_lowercase();
    let Some(idx) = lower.rfind(".part") else {
        return name;
    };
    let tail = &name[idx + ".part".len()..];
    if tail.is_empty() || !tail.bytes().all(|b| b.is_ascii_digit()) {
        return name;
    }
    &name[..idx]
}

/// Whether a user-supplied path ends in a directory separator. The
/// CLI uses this as the "user clearly meant a directory" hint for
/// shape resolution (`docs/PLAN_download_modes.md` §1.1).
///
/// peel is unix-only (the binary is `#![cfg(unix)]`), so a trailing
/// `/` is the only separator to check.
fn path_has_trailing_slash(path: &Path) -> bool {
    path.as_os_str()
        .to_str()
        .map(|s| s.ends_with('/'))
        .unwrap_or(false)
}

/// Whether `path` already exists on disk as a regular file. Returns
/// `false` for "does not exist", for a directory, or for any IO
/// error during the stat (callers treat these as "no problem here").
fn path_is_existing_regular_file(path: &Path) -> bool {
    path.metadata().map(|m| m.is_file()).unwrap_or(false)
}

/// Whether `path` already exists on disk as a directory. Returns
/// `false` for "does not exist", for a regular file, or for any IO
/// error during the stat.
fn path_is_existing_dir(path: &Path) -> bool {
    path.metadata().map(|m| m.is_dir()).unwrap_or(false)
}

/// Resolve the user's `-o <PATH>` into an [`OutputTarget`] given the
/// format `shape` dictated by suffix detection (or `--format`).
///
/// Enforces the resolution rules in `docs/PLAN_download_modes.md`
/// §1.1:
///
/// - Tree formats: reject an existing regular file at `path`;
///   accept trailing slash, existing dir, or non-existent path.
/// - Stream formats: reject a trailing slash or an existing
///   directory at `path`; accept existing regular file (caller may
///   warn about overwrite) or non-existent path.
fn build_output_target_explicit(
    path: PathBuf,
    shape: FormatShape,
) -> Result<OutputTarget, CliError> {
    match shape {
        FormatShape::Tree => {
            if path_is_existing_regular_file(&path) {
                return Err(CliError::OutputShapeMismatch {
                    shape,
                    detail: format!(
                        "format produces a directory tree; {} exists and is a regular file. \
                         Remove it, or pass a directory path.",
                        path.display(),
                    ),
                    path,
                });
            }
            Ok(OutputTarget::Dir(path))
        }
        FormatShape::Stream => {
            if path_has_trailing_slash(&path) || path_is_existing_dir(&path) {
                return Err(CliError::OutputShapeMismatch {
                    shape,
                    detail: format!(
                        "format produces a single file; {} is a directory.",
                        path.display(),
                    ),
                    path,
                });
            }
            Ok(OutputTarget::File(path))
        }
    }
}

/// Resolve the user's `-o <PATH>` when the format shape is **not**
/// known at CLI time (no recognized URL suffix, no `--format`).
///
/// Falls back to the path's own shape: trailing slash or existing
/// directory → [`OutputTarget::Dir`]; otherwise [`OutputTarget::File`].
/// The coordinator runs format detection (suffix + magic) after HEAD
/// discovery and re-validates against the resolved shape, surfacing a
/// typed mismatch error before any chunk downloads.
fn build_output_target_unknown_shape(path: PathBuf) -> OutputTarget {
    if path_has_trailing_slash(&path) || path_is_existing_dir(&path) {
        OutputTarget::Dir(path)
    } else {
        OutputTarget::File(path)
    }
}

/// Resolve the format shape for the primary URL using the registry,
/// honoring an explicit `--format` override when set. Returns `None`
/// when neither override nor URL suffix yields a known shape — in
/// which case the resolver falls back to path-shape-hint behaviour.
fn shape_from_url_or_format(
    primary_url: &str,
    registry: &DecoderRegistry,
    forced_format: Option<&str>,
) -> Option<FormatShape> {
    if let Some(name) = forced_format {
        return registry.shape_for_format_name(name);
    }
    let parsed = Url::parse(primary_url).ok()?;
    let basename = filename_from_url(&parsed)?;
    let depart = strip_volume_or_part_suffix(&basename);
    registry.shape_for_name(depart)
}

/// Resolve `-k/--keep-archive` (`docs/PLAN_download_modes.md` §3.2)
/// into the final on-disk path where the source archive will be
/// preserved, or `None` when the flag is absent.
///
/// The flag carries a sentinel empty `PathBuf` when present without
/// a value (the `default_missing_value = ""` form). The bare form
/// derives the path from the URL basename, placed as a sibling of
/// the resolved `-o` output. An explicit `-k=<PATH>` is used
/// verbatim, with one validation: an existing directory at that
/// path is rejected. An existing regular file is accepted; the
/// coordinator overwrites it with a `tracing::warn!` at run time.
fn resolve_keep_archive(
    keep_archive_flag: Option<String>,
    output: &OutputTarget,
    primary_url: &str,
) -> Result<Option<PathBuf>, CliError> {
    let Some(value) = keep_archive_flag else {
        return Ok(None);
    };
    let value = PathBuf::from(value);
    if value.as_os_str().is_empty() {
        // Bare `-k`: derive `<parent-of-output>/<url-basename>` so
        // the archive lands next to the extraction target. Splitting
        // the URL basename through `strip_part_suffix` keeps a
        // multi-URL run from saving `foo.tar.part0000` — the user
        // gets the assembled archive's natural name, not one of the
        // server-side splits.
        let parsed = Url::parse(primary_url).map_err(CliError::InvalidUrl)?;
        let basename = filename_from_url(&parsed).ok_or(CliError::NoDefaultOutput)?;
        let depart = strip_volume_or_part_suffix(&basename);
        if depart.is_empty() {
            return Err(CliError::NoDefaultOutput);
        }
        let parent_path: PathBuf = match output {
            OutputTarget::File(p) | OutputTarget::Dir(p) => p
                .parent()
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(".")),
        };
        Ok(Some(parent_path.join(depart)))
    } else {
        if path_is_existing_dir(&value) {
            return Err(CliError::KeepArchivePathIsDir { path: value });
        }
        Ok(Some(value))
    }
}

/// Derive the default output **file** name when `-o` is not given,
/// preserving the URL's compression / archive suffix. Used by
/// `--no-extract` (`docs/PLAN_download_modes.md` §2.1) where the
/// on-disk bytes are the raw remote object — we want
/// `https://h/foo.tar.zst --no-extract` to land at `./foo.tar.zst`,
/// not `./foo`. Mirrors [`default_output_dir`] but skips the
/// suffix-stripping step.
fn default_output_file_with_suffix(url: &str) -> Result<PathBuf, CliError> {
    let parsed = Url::parse(url).map_err(CliError::InvalidUrl)?;
    let name = filename_from_url(&parsed).ok_or(CliError::NoDefaultOutput)?;
    // Strip the multi-volume volume suffix (multivolume §6) or the
    // byte-concat `.partNNNN` suffix, so the user gets a single
    // output file when downloading split-archive parts or
    // multi-volume seeds. The compression suffix (if any) is
    // intentionally preserved.
    let depart = strip_volume_or_part_suffix(&name);
    if depart.is_empty() {
        return Err(CliError::NoDefaultOutput);
    }
    Ok(PathBuf::from(depart))
}

/// Parse a `--max-disk-buffer` value into `Option<u64>` (bytes).
///
/// The case-insensitive sentinels `none`, `off`, and `disabled` map
/// to `Ok(None)` (throttle disabled). Any other value is delegated
/// to [`parse_bandwidth`], which already accepts the decimal /
/// binary unit suffixes the help text advertises.
fn parse_disk_buffer(input: &str) -> Result<Option<u64>, ParseBandwidthError> {
    let trimmed = input.trim();
    if matches!(
        trimmed.to_ascii_lowercase().as_str(),
        "none" | "off" | "disabled" | "0"
    ) {
        return Ok(None);
    }
    parse_bandwidth(trimmed).map(Some)
}

/// Classification of one positional `<source>` argument
/// (`docs/PLAN_local_file_extract.md` §1 step 1).
///
/// HTTP-shaped strings (anything that [`crate::http::Url::parse`]
/// accepts — `http://...` and `https://...`) take the
/// [`Self::Http`] arm; anything else is treated as a path and the
/// existence check decides whether the binary routes to the
/// local-file extractor or surfaces a "no such file" error before
/// any work begins.
#[derive(Debug, Clone)]
enum SourceClassification {
    /// HTTP / HTTPS URL — eligible for the existing download path.
    Http(String),
    /// Relative or absolute path that exists on disk as a regular
    /// file. Eligible for the local-file extractor.
    Local(PathBuf),
}

/// Classify one positional `<source>` argument
/// (`docs/PLAN_local_file_extract.md` §1 step 1).
///
/// The classifier never does network IO; existence checks on the
/// path are bare `metadata(2)` calls. Heterogeneous lists
/// ([`Self::Http`] + [`Self::Local`]) are detected at the
/// dispatch layer by [`classify_sources`] — this helper is
/// per-argument.
fn classify_source(arg: &str) -> Result<SourceClassification, CliError> {
    match Url::parse(arg) {
        Ok(_) => Ok(SourceClassification::Http(arg.to_string())),
        Err(_) => {
            let path = PathBuf::from(arg);
            let meta = match path.metadata() {
                Ok(m) => m,
                Err(_) => return Err(CliError::LocalSourceNotFound { path }),
            };
            if !meta.is_file() {
                return Err(CliError::LocalSourceNotRegularFile { path });
            }
            Ok(SourceClassification::Local(path))
        }
    }
}

/// Result of a successful multi-volume HTTP discovery pass
/// (`docs/PLAN_multivolume_archives.md` §1).
///
/// Captures the canonical URL list resolved by
/// [`crate::multivolume::discover_http`] reshaped into the
/// `(primary, additional)` split [`RunArgs`] expects:
/// `primary` is volume 1's URL (the discovery walker normalises
/// to start at volume 1 even when the user passed a higher-numbered
/// seed), `additional` is the rest of the volume set in order.
struct ResolvedVolumeSet {
    primary: String,
    additional: Vec<String>,
}

/// Try multi-volume HTTP auto-discovery against `primary_url`.
///
/// Returns:
/// - `Ok(Some(set))` when the seed matched a multi-volume pattern
///   *and* discovery resolved a set of >1 volumes. The caller
///   should switch to `multi_part_storage`-on for the run.
/// - `Ok(None)` when the seed is plainly single-URL — either the
///   string isn't a valid URL (let [`crate::http`] surface that
///   later), or the basename does not match any multi-volume
///   pattern, or discovery returned just a single volume (e.g.
///   `foo.part0001.rar` exists but `foo.part0002.rar` doesn't —
///   discovered as one volume, which is the same as single-URL
///   for the coordinator's purposes).
/// - `Err(CliError::VolumeDiscovery)` when the seed pattern *was*
///   recognised but discovery surfaced a real failure — a missing
///   lower-numbered volume, a missing ZIP final volume, or a HEAD
///   network error. Returning the typed error preserves the
///   operator-facing diagnostic instead of silently swallowing it.
fn resolve_multi_volume_http(
    client: &Client,
    primary_url: &str,
) -> Result<Option<ResolvedVolumeSet>, CliError> {
    use crate::multivolume::{discover_http, parse_volume_name, MvError};

    let Ok(seed) = Url::parse(primary_url) else {
        // Defer URL validation to the downstream HTTP code paths;
        // a malformed URL surfaces there with a clearer message.
        return Ok(None);
    };
    let basename = seed
        .path()
        .rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or("");
    if parse_volume_name(basename).is_none() {
        return Ok(None);
    }
    match discover_http(client, &seed) {
        Ok(urls) => {
            if urls.len() <= 1 {
                // The seed pattern matched but only one volume
                // resolved — treat the same as single-URL so the
                // coordinator's multi-part bookkeeping (per-part
                // sidecars, routing puncher, conflict checks)
                // doesn't kick in for a single sparse file.
                return Ok(None);
            }
            let mut iter = urls.into_iter();
            let primary = iter.next().expect("urls.len() > 1").to_string();
            let additional: Vec<String> = iter.map(|u| u.to_string()).collect();
            Ok(Some(ResolvedVolumeSet {
                primary,
                additional,
            }))
        }
        // `PatternNotRecognised` here is a discovery-time anomaly
        // — `parse_volume_name` already returned `Some` above, so
        // the basename matched. Surface it as a soft skip rather
        // than a hard error to match the "treat unknown patterns
        // as single-URL" rule.
        Err(MvError::PatternNotRecognised { .. }) => Ok(None),
        // A transport-level `HEAD` failure (connection refused,
        // DNS failure, TLS error, …) means the origin is
        // unreachable. We cannot tell from a transport error
        // whether the seed is single-volume or multi-volume, so
        // fall through to the single-URL path and let the
        // coordinator's normal HTTP request surface the
        // underlying network problem with the full retry +
        // mirror plumbing rather than aborting at CLI parse
        // time with a "discovery failed" message that hides the
        // real cause. Specific *protocol-level* failures
        // (`MvError::MissingVolume`, `FinalVolumeMissing`,
        // `UnexpectedStatus`) still propagate — they mean the
        // origin answered, and the answer is incompatible with
        // a multi-volume seed the user clearly intended.
        Err(MvError::Head { .. }) => Ok(None),
        Err(other) => Err(CliError::VolumeDiscovery(other)),
    }
}

/// Top-level entry from [`Cli::into_dispatch`]: a parsed CLI lands
/// in one of two pipelines depending on what the positional
/// `<source>` arguments looked like
/// (`docs/PLAN_local_file_extract.md` §1).
///
/// HTTP / HTTPS arguments produce [`Dispatch::Http`], routed via
/// [`crate::coordinator::run`]. Local file paths produce
/// [`Dispatch::Local`], routed via
/// [`crate::coordinator::local::run`]. The two coordinators share
/// sink / decoder / extractor types but otherwise have no overlap.
pub enum Dispatch {
    /// HTTP / HTTPS run. Same shape as today's binary entry.
    /// Boxed because [`RunArgs`] is several hundred bytes (it
    /// carries config, client, registry, …) — sizing the bare
    /// variant skews the enum.
    Http(Box<RunArgs>),
    /// Local-file run (`docs/PLAN_local_file_extract.md`).
    /// Non-destructive by default: the source archive is left on
    /// disk untouched. Destructive mode (`-d/--destructive`)
    /// hole-punches the source as the decoder advances and
    /// deletes it on success; the dispatch layer encodes that
    /// choice in [`LocalRunArgs::destructive`].
    Local {
        /// Arguments for [`crate::coordinator::local::run`].
        args: Box<LocalRunArgs>,
    },
}

/// Classify every positional argument and reject heterogeneous /
/// invalid lists (`docs/PLAN_local_file_extract.md` §1 step 1).
///
/// Returns a uniform [`Vec<SourceClassification>`] that callers
/// can match against in one pass — every element is the same
/// variant on success.
/// Expand a `@<path>` manifest sentinel in a positional URL list
/// (`docs/PLAN_multivolume_archives.md` §1 step 4 / §6).
///
/// When the only positional argument starts with `@`, the rest is
/// treated as a path to a manifest file containing one URL or
/// local path per line. Blank lines and `#`-prefixed comments are
/// ignored. The expanded list replaces the original.
///
/// Combining `@<file>` with extra positional arguments is rejected
/// — the manifest *is* the positional list, not a prefix or suffix
/// of one.
///
/// Idempotent: a list whose first entry does not start with `@`
/// returns unchanged. Discovery / classification run on the
/// expanded list as if the user had typed it directly, so the
/// downstream code paths (mixed-source detection, sha256-count
/// validation, multi-volume positional sanity check) all apply.
///
/// # Errors
///
/// - [`CliError::ManifestPositionalConflict`] when `@<path>` is
///   paired with extra positional arguments.
/// - [`CliError::ManifestReadFailed`] when the manifest file
///   cannot be opened or read.
/// - [`CliError::ManifestEmpty`] when the manifest contains no
///   non-blank, non-comment lines.
fn expand_manifest_urls(urls: Vec<String>) -> Result<Vec<String>, CliError> {
    let Some(first) = urls.first() else {
        return Ok(urls);
    };
    let Some(rest) = first.strip_prefix('@') else {
        return Ok(urls);
    };
    if urls.len() > 1 {
        return Err(CliError::ManifestPositionalConflict);
    }
    let path = PathBuf::from(rest);
    let body = std::fs::read_to_string(&path).map_err(|source| CliError::ManifestReadFailed {
        path: path.clone(),
        source,
    })?;
    let lines: Vec<String> = body
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_string)
        .collect();
    if lines.is_empty() {
        return Err(CliError::ManifestEmpty { path });
    }
    Ok(lines)
}

/// Validate that a positional list of multi-volume names forms a
/// contiguous numeric sequence
/// (`docs/PLAN_multivolume_archives.md` §6).
///
/// Skipped (returns `Ok(())`) when:
/// - The list has only one entry — no sequence to validate.
/// - Any entry's basename does not match a multi-volume pattern.
///   The byte-concat `.partNNNN` suffix and arbitrary tar parts
///   fall here; the multi-URL plan (`PLAN_multi_url_source.md`)
///   handles ordering for those.
/// - Entries match different formats. The plan does not support
///   mixing formats; if the user wants to interleave a `.7z.001`
///   with a `.part0001.rar` they will surface a format-mismatch
///   downstream at decode time, but the CLI does not need to
///   guess.
///
/// When the list *is* a uniform multi-volume set, every entry's
/// volume number must equal `first.volume + position`. Gaps,
/// duplicates, and backwards steps surface as
/// [`CliError::OutOfOrderVolumeList`].
fn validate_positional_volume_order(args: &[String]) -> Result<(), CliError> {
    if args.len() < 2 {
        return Ok(());
    }
    let parse = |s: &str| -> Option<crate::multivolume::VolumeName> {
        let basename = basename_for_validation(s);
        crate::multivolume::parse_volume_name(basename)
    };
    let Some(first) = parse(&args[0]) else {
        return Ok(());
    };
    // ZIP final-volume seeds (`<base>.zip`) carry `volume == None`;
    // we cannot anchor a numeric sequence on them. The plan models
    // spanned ZIP as `<base>.z01..z<N>` siblings *plus* a single
    // `<base>.zip` final — checking that shape is the discovery
    // walker's job, not the CLI's parse-time sanity check.
    let Some(first_volume) = first.volume else {
        return Ok(());
    };
    for (idx, arg) in args.iter().enumerate().skip(1) {
        let Some(parsed) = parse(arg) else {
            // Mixed multi-volume + non-multi-volume positional list:
            // not a sequence we should validate.
            return Ok(());
        };
        if parsed.kind != first.kind {
            // Mixed formats in the positional list — surfaces
            // downstream; CLI does not adjudicate.
            return Ok(());
        }
        let Some(volume) = parsed.volume else {
            // A `.zip` final mixed with `.zNN` siblings is the one
            // shape that legitimately ends a sequence. The exact
            // placement is the discovery walker's concern; do not
            // reject here.
            return Ok(());
        };
        let expected = first_volume + idx as u32;
        if volume != expected {
            return Err(CliError::OutOfOrderVolumeList {
                position: idx,
                expected,
                got: arg.clone(),
            });
        }
    }
    Ok(())
}

/// Best-effort basename extraction for validation: works on both
/// URLs (split on the last `/`, drop any query) and local paths
/// (last path component). Cheaper than a full `Url::parse` round-
/// trip and tolerant of inputs that are not URLs.
fn basename_for_validation(arg: &str) -> &str {
    let no_query = match arg.find('?') {
        Some(i) => &arg[..i],
        None => arg,
    };
    match no_query.rfind('/') {
        Some(i) => &no_query[i + 1..],
        None => no_query,
    }
}

fn classify_sources(args: &[String]) -> Result<Vec<SourceClassification>, CliError> {
    if args.is_empty() {
        return Err(CliError::NoUrls);
    }
    let classified: Vec<SourceClassification> = args
        .iter()
        .map(|s| classify_source(s))
        .collect::<Result<_, _>>()?;
    // Mixed lists are rejected. We do not have a use case for "two
    // halves of the same archive, one local one remote"; rejecting
    // the combination keeps resume semantics unambiguous.
    let first_http = classified.iter().find_map(|s| match s {
        SourceClassification::Http(u) => Some(u.clone()),
        _ => None,
    });
    let first_local = classified.iter().find_map(|s| match s {
        SourceClassification::Local(p) => Some(p.clone()),
        _ => None,
    });
    if let (Some(url), Some(path)) = (first_http, first_local) {
        return Err(CliError::MixedSources { url, path });
    }
    Ok(classified)
}

/// HTTP-only flags rejected when the positional source is a local
/// path (`docs/PLAN_local_file_extract.md` §1 step 2).
///
/// Returns the user-facing flag name on the first violation so the
/// error message names the specific knob the user tried to use.
fn reject_http_only_flags(cli: &Cli) -> Result<(), CliError> {
    // Order roughly matches the help text so the user sees the
    // earliest violation reported. Each flag's "was set explicitly"
    // detection mirrors the §2 sub-rule the `--no-extract` resolver
    // uses (default-equal values slip through; non-default values
    // surface the error).
    if !cli.mirrors.is_empty() {
        return Err(CliError::LocalFlagNotApplicable { flag: "--mirror" });
    }
    if !cli.expected_sha256s.is_empty() {
        return Err(CliError::LocalFlagNotApplicable { flag: "--sha256" });
    }
    if cli.workers != DEFAULT_WORKERS {
        return Err(CliError::LocalFlagNotApplicable { flag: "--workers" });
    }
    if cli.chunk_size != DEFAULT_CHUNK_SIZE {
        return Err(CliError::LocalFlagNotApplicable {
            flag: "--chunk-size",
        });
    }
    if cli.no_adaptive_chunk_size {
        return Err(CliError::LocalFlagNotApplicable {
            flag: "--no-adaptive-chunk-size",
        });
    }
    if cli.max_bandwidth.is_some() {
        return Err(CliError::LocalFlagNotApplicable {
            flag: "--max-bandwidth",
        });
    }
    // `--max-disk-buffer` has a non-empty default; check against
    // the default literal so a CLI containing the implicit value
    // does not trip the rejection. `clap::ArgMatches::value_source`
    // would be tighter but the [`Parser`] derive does not expose
    // the matches; the literal comparison is good enough.
    if cli.max_disk_buffer != "1GiB" {
        return Err(CliError::LocalFlagNotApplicable {
            flag: "--max-disk-buffer",
        });
    }
    if cli.http_version != HttpVersionArg::default() {
        return Err(CliError::LocalFlagNotApplicable {
            flag: "--http-version",
        });
    }
    if cli.no_extract {
        return Err(CliError::LocalFlagNotApplicable {
            flag: "--no-extract",
        });
    }
    if cli.strict_format {
        return Err(CliError::LocalFlagNotApplicable {
            flag: "--strict-format",
        });
    }
    Ok(())
}

/// Resolve the user's `-o <PATH>` into an [`OutputTarget`] when the
/// source is a local file
/// (`docs/PLAN_local_file_extract.md` §1 step 2).
///
/// Mirrors [`build_output_target_explicit`] /
/// [`build_output_target_unknown_shape`] from the HTTP path: the
/// shape is decided by `--format` (or the source path's suffix
/// fall-through), `-o`'s shape hint disambiguates when the source
/// is opaque, and the explicit-vs-derived branch picks a default
/// when `-o` is absent.
fn build_local_output(
    source: &Path,
    user_output: Option<PathBuf>,
    forced_format: Option<&str>,
    registry: &DecoderRegistry,
) -> Result<OutputTarget, CliError> {
    // Shape resolution: `--format` first, then suffix match on the
    // source filename. We deliberately do *not* peek magic bytes
    // here — magic detection happens inside the coordinator with
    // the file already open. Path-shape hints disambiguate when
    // both lookups miss.
    let shape: Option<FormatShape> = forced_format
        .and_then(|name| registry.shape_for_format_name(name))
        .or_else(|| {
            source
                .file_name()
                .and_then(|s| s.to_str())
                .and_then(|name| registry.shape_for_name(name))
        });
    match (user_output, shape) {
        (Some(path), Some(s)) => build_output_target_explicit(path, s),
        (Some(path), None) => Ok(build_output_target_unknown_shape(path)),
        (None, Some(FormatShape::Stream)) => {
            // Stream-shape default: pop a suffix-stripped basename
            // into CWD. Tar-shape defaults preserve the directory
            // name; stream defaults strip the compression suffix
            // exactly as the HTTP path does
            // (e.g. `foo.zst` → `foo`).
            let basename = source
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or(CliError::NoDefaultOutput)?;
            let stripped = strip_archive_extensions(basename);
            if stripped.is_empty() {
                return Err(CliError::NoDefaultOutput);
            }
            Ok(OutputTarget::File(PathBuf::from(stripped)))
        }
        (None, Some(FormatShape::Tree) | None) => {
            let basename = source
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or(CliError::NoDefaultOutput)?;
            let stripped = strip_archive_extensions(basename);
            if stripped.is_empty() {
                return Err(CliError::NoDefaultOutput);
            }
            Ok(OutputTarget::Dir(PathBuf::from(stripped)))
        }
    }
}

impl Cli {
    /// Convert the parsed CLI into a [`RunArgs`] ready for
    /// [`crate::coordinator::run`].
    ///
    /// # Errors
    ///
    /// Returns [`CliError::Client`] if the HTTP client cannot be
    /// constructed, or [`CliError::InvalidSha256`] if the
    /// `--sha256 <HEX>` argument failed to parse.
    pub fn into_run_args(self) -> Result<RunArgs, CliError> {
        // Hard cutover migration error for the removed `-C` flag
        // (`docs/PLAN_download_modes.md` §1). Surfaces *before* URL
        // and SHA-256 validation so a user passing `-C foo/` doesn't
        // also have to fix other arg shape before seeing the migration
        // hint.
        if self.output_dir_migration.is_some() {
            return Err(CliError::OutputDirRemoved);
        }

        // `--no-extract` is mutually exclusive with extractor-only
        // flags (`docs/PLAN_download_modes.md` §2.1). Detect explicit
        // setting:
        //   * `--format` and `--force-format-from-magic` carry their
        //     own absence sentinel (`None` / `false`) so a default
        //     value cannot be mistaken for an explicit one.
        //   * `--punch-threshold` has a non-trivial default; we
        //     compare against `DEFAULT_PUNCH_THRESHOLD` and only
        //     reject when the user picked a non-default value. A
        //     user passing the exact default explicitly slips past
        //     this check, but that is a degenerate case and the
        //     behavioural outcome (no-op puncher knob) is the same
        //     either way.
        if self.no_extract {
            if self.forced_format.is_some() {
                return Err(CliError::NoExtractConflict { flag: "--format" });
            }
            if self.force_format_from_magic {
                return Err(CliError::NoExtractConflict {
                    flag: "--force-format-from-magic",
                });
            }
            if self.punch_threshold != DEFAULT_PUNCH_THRESHOLD {
                return Err(CliError::NoExtractConflict {
                    flag: "--punch-threshold",
                });
            }
            // §4: `--strict-format` runs detection; nothing to be
            // strict about when extraction is skipped entirely.
            if self.strict_format {
                return Err(CliError::NoExtractConflict {
                    flag: "--strict-format",
                });
            }
        }

        // Manifest expansion (`docs/PLAN_multivolume_archives.md`
        // §1 step 4 / §6): `peel @volumes.txt` is rewritten into
        // the explicit list of URLs / paths from the manifest
        // before anything else runs against `self.urls`. Idempotent
        // — a list whose first entry doesn't start with `@` returns
        // unchanged. Per `PLAN_multivolume_archives.md` §6, a
        // positional list of multi-volume names must form a
        // contiguous numeric sequence; out-of-order or duplicate
        // numbers are rejected here rather than letting the format
        // parser surface a confusing decode-time error.
        let urls = expand_manifest_urls(self.urls)?;
        validate_positional_volume_order(&urls)?;

        // The `num_args = 1..` constraint guarantees at least one
        // URL at parse time; `urls[0]` is the primary part. The
        // explicit fallback below keeps the function defensive
        // against an `into_run_args` caller that constructed `Cli`
        // by hand and skipped clap (the assert path).
        let mut urls_iter = urls.into_iter();
        let primary_url = urls_iter.next().ok_or(CliError::NoUrls)?;
        let additional_urls: Vec<String> = urls_iter.collect();
        let multi_part = !additional_urls.is_empty();

        // §3 step 3: --mirror is for alternates of the same file;
        // multi-URL is for distinct parts of the same archive. The
        // two flags carry different semantics — combining them is a
        // user error, not a runtime warning.
        if multi_part && !self.mirrors.is_empty() {
            return Err(CliError::MirrorMultipleUrls);
        }

        // §3 step 2: validate the --sha256 count against the URL
        // count, then split the parsed digests into the (single,
        // many) shape the `CoordinatorConfig` exposes.
        let parsed_hashes: Vec<[u8; crate::hash::sha256::DIGEST_LEN]> = self
            .expected_sha256s
            .iter()
            .map(|hex| parse_hex_digest(hex).map_err(CliError::InvalidSha256))
            .collect::<Result<_, _>>()?;
        let n_urls = 1 + additional_urls.len();
        let n_hashes = parsed_hashes.len();
        let (expected_sha256, expected_sha256s) = match (multi_part, n_hashes) {
            (false, 0) => (None, Vec::new()),
            (false, 1) => (Some(parsed_hashes[0]), Vec::new()),
            (true, 0) => (None, Vec::new()),
            (true, n) if n == n_urls => (None, parsed_hashes),
            (_, _) => {
                return Err(CliError::ShaCountMismatch {
                    urls: n_urls,
                    hashes: n_hashes,
                })
            }
        };

        // §1 of `docs/PLAN_download_modes.md`: unified `-o <PATH>`
        // resolver. Determine the format shape from the URL suffix
        // (or `--format` override) and pair it with the user's path
        // to produce a typed [`OutputTarget`]. When the shape is
        // unknown at CLI time (URL has no recognized suffix and no
        // `--format` override), fall back to the path's own shape
        // hint; the coordinator catches any post-magic mismatch.
        //
        // §2: `--no-extract` short-circuits format detection — it
        // *always* produces a single file (Stream shape) regardless
        // of the URL suffix, and the default output preserves the
        // compression suffix so `.tar.zst` lands at `.tar.zst`
        // rather than the stripped basename.
        let registry = DecoderRegistry::with_defaults();
        let shape = if self.no_extract {
            Some(FormatShape::Stream)
        } else {
            shape_from_url_or_format(&primary_url, &registry, self.forced_format.as_deref())
        };
        let output = match (self.output_file, shape) {
            (Some(path), Some(s)) => build_output_target_explicit(path, s)?,
            (Some(path), None) => build_output_target_unknown_shape(path),
            (None, Some(FormatShape::Stream)) => {
                // Stream-shaped default. With `--no-extract` the
                // suffix is preserved (§2); without it the default
                // is the stripped basename (the legacy single-`.zst`
                // default name).
                let name = if self.no_extract {
                    default_output_file_with_suffix(&primary_url)?
                } else {
                    default_output_dir(&primary_url)?
                };
                OutputTarget::File(name)
            }
            (None, Some(FormatShape::Tree) | None) => {
                // Tree-shaped default and the unknown-shape default
                // both derive a stripped basename and place it as a
                // directory in CWD — the legacy default. §4 will
                // replace the unknown-shape arm with a clearer
                // "running as --no-extract" fallback.
                OutputTarget::Dir(default_output_dir(&primary_url)?)
            }
        };
        // §3 (`docs/PLAN_download_modes.md`): resolve `-k`/
        // `--keep-archive`. Bare `-k` derives a sibling-of-output
        // path from the URL basename; `-k=<PATH>` uses the explicit
        // path verbatim (validated for "not a directory"). In
        // `--no-extract` mode `-k` is redundant — the source bytes
        // are already preserved as the final output — so log an
        // info notice instead of erroring.
        let keep_archive = resolve_keep_archive(self.keep_archive, &output, &primary_url)?;
        if self.no_extract && keep_archive.is_some() {
            tracing::info!(
                "`-k`/`--keep-archive` is implied by `--no-extract`; no separate archive copy is made"
            );
        }
        // Hide-but-keep semantics: with `--no-extract` the
        // .peel.part *is* the final output and the rename happens
        // unconditionally; passing `keep_archive` through into the
        // coordinator config in that case would cause a second
        // rename attempt against a path the user-supplied flag
        // chose. Strip it to None so the coordinator follows the
        // `--no-extract` codepath cleanly.
        let keep_archive = if self.no_extract { None } else { keep_archive };

        let max_bandwidth_bps = match self.max_bandwidth {
            Some(s) => Some(parse_bandwidth(&s).map_err(CliError::InvalidBandwidth)?),
            None => None,
        };
        let max_disk_buffer =
            parse_disk_buffer(&self.max_disk_buffer).map_err(CliError::InvalidDiskBuffer)?;
        let password_source = self
            .password_from
            .as_deref()
            .map(PasswordSource::parse)
            .transpose()
            .map_err(CliError::InvalidPasswordSource)?;
        let http_version: HttpVersion = self.http_version.into();
        // Log the HTTP version selection at startup. Mirrors the
        // `io_backend=...` line that `crate::io_backend::select_backend`
        // emits, so non-TTY users see the two together in the early
        // subscriber output. With `Auto` the actual H1/H2 outcome is
        // per-origin via ALPN and only known after the first connection.
        // The `peel` binary also surfaces this same string to TTY users
        // via an `eprintln!` before the progress renderer starts (the
        // subscriber suppresses INFO on a TTY); see `http_version_banner`.
        tracing::info!("{}", http_version_banner(http_version));
        let client = Client::with_config(ClientConfig {
            http_version,
            ..ClientConfig::default()
        })?;

        // Multi-volume HTTP auto-discovery
        // (`docs/PLAN_multivolume_archives.md` §1 / §7 Phase 5):
        // when the user passes a single URL whose basename looks
        // like a multi-volume seed (`foo.part0001.rar`,
        // `foo.7z.001`, `foo.z01` / `foo.zip`), HEAD-probe the
        // sibling volumes and flip `multi_part_storage` on so each
        // volume lands in its own `.peel.part.NNN` sidecar.
        //
        // - Auto-discovery is skipped when the user already supplied
        //   additional URLs (they're being explicit).
        // - A seed whose basename doesn't match any pattern (e.g.
        //   `archive.tar.zst`) returns `PatternNotRecognised` and is
        //   silently treated as single-URL — the normal path.
        // - Every *other* discovery error surfaces as
        //   [`CliError::VolumeDiscovery`] so the user knows
        //   auto-discovery was attempted; specifically
        //   `MissingVolume` / `FinalVolumeMissing` mean the seed
        //   pattern *did* match but the resolved set was incomplete.
        let (primary_url, additional_urls, multi_part_storage) =
            if additional_urls.is_empty() && !self.no_auto_discover {
                match resolve_multi_volume_http(&client, &primary_url) {
                    Ok(Some(resolved)) => (resolved.primary, resolved.additional, true),
                    Ok(None) => (primary_url, additional_urls, false),
                    Err(e) => return Err(e),
                }
            } else {
                (primary_url, additional_urls, false)
            };

        Ok(RunArgs {
            url: primary_url,
            additional_urls,
            output,
            config: CoordinatorConfig {
                chunk_size: self.chunk_size,
                adaptive_chunk_size: !self.no_adaptive_chunk_size,
                workers: self.workers,
                retry: RetryConfig::default(),
                punch_threshold: self.punch_threshold,
                checkpoint_min_bytes: self.checkpoint_min_bytes,
                checkpoint_min_interval: Duration::from_secs_f64(self.checkpoint_min_secs.max(0.0)),
                checkpoint_target_interval: Duration::from_secs_f64(
                    self.checkpoint_target_secs.max(0.0),
                ),
                workdir: self.workdir,
                reader_poll_interval: Duration::from_millis(5),
                forced_format: self.forced_format,
                force_format_from_magic: self.force_format_from_magic,
                io_backend: self.io_backend.into(),
                expected_sha256,
                expected_sha256s,
                mirror_urls: self.mirrors,
                max_bandwidth_bps,
                max_disk_buffer,
                no_extract: self.no_extract,
                keep_archive,
                strict_format: self.strict_format,
                password_source,
                multi_part_storage,
            },
            client,
            registry: DecoderRegistry::with_defaults(),
            progress: None,
            progress_state: None,
            kill_switch: None,
            io_backend: None,
        })
    }

    /// Classify the positional sources and dispatch to either the
    /// HTTP coordinator or the local-file extractor
    /// (`docs/PLAN_local_file_extract.md` §1).
    ///
    /// HTTP sources route through [`Self::into_run_args`]; local
    /// sources go through [`Self::into_local_run_args`]. Mixed
    /// lists, non-existent paths, and HTTP-only flags paired with
    /// a local source are rejected at parse time with a typed
    /// [`CliError`] variant naming the specific problem.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::MixedSources`] for heterogeneous source
    /// lists, [`CliError::LocalSourceNotFound`] /
    /// [`CliError::LocalSourceNotRegularFile`] when a positional
    /// argument doesn't parse as a URL and doesn't resolve to a
    /// regular file, [`CliError::LocalFlagNotApplicable`] when an
    /// HTTP-only flag is combined with a local source,
    /// [`CliError::LocalKeepArchiveWithPath`] when `-k=<PATH>` is
    /// used in local mode, or any of the variants
    /// [`Self::into_run_args`] surfaces.
    pub fn into_dispatch(mut self) -> Result<Dispatch, CliError> {
        // Hard cutover migration error for the removed `-C` flag
        // — surfaces *before* source classification so a user who
        // is mixing legacy flags still sees the migration hint
        // first.
        if self.output_dir_migration.is_some() {
            return Err(CliError::OutputDirRemoved);
        }

        // Manifest expansion (`docs/PLAN_multivolume_archives.md`
        // §1 step 4 / §6): `peel @volumes.txt` is rewritten into
        // the explicit list of URLs / paths from the manifest
        // before classification, mirror checking, or downstream
        // discovery. Mutate `self.urls` so the later
        // `into_run_args()` call (HTTP branch) sees the expanded
        // list without re-expanding (which is a no-op since the
        // first entry no longer starts with `@`).
        self.urls = expand_manifest_urls(self.urls)?;
        validate_positional_volume_order(&self.urls)?;

        let classified = classify_sources(&self.urls)?;
        // Disambiguate uniformly. `classify_sources` already
        // rejected mixed lists, so finding any Local element means
        // every element is Local.
        let is_local = classified
            .iter()
            .all(|s| matches!(s, SourceClassification::Local(_)));

        if !is_local {
            // HTTP runs are destructive by default — the
            // downloaded archive's part-file is progressively
            // hole-punched and removed on success. `-d` against
            // an HTTP source therefore restates the default and
            // is a harmless no-op; `-k` is the explicit opt-out.
            // Combining the two is a contradiction we surface as
            // a typed error rather than silently letting one win.
            if self.destructive && self.keep_archive.is_some() {
                return Err(CliError::HttpDestructiveConflictsKeepArchive);
            }
            if self.destructive {
                tracing::info!(
                    "`-d/--destructive` is a no-op for HTTP sources \
                     (the downloaded archive is hole-punched and deleted by default; \
                     pass `-k/--keep-archive` to opt out)",
                );
            }
            return self.into_run_args().map(Box::new).map(Dispatch::Http);
        }

        // Local-file dispatch. Reject all the HTTP-side knobs
        // before touching any IO so the error names the specific
        // flag the user passed instead of failing later with a
        // misleading "decode failed" message.
        reject_http_only_flags(&self)?;

        // Exactly one local source for now. Multi-file local
        // archives are the multi-volume plan's job
        // (`docs/PLAN_local_file_extract.md` Out-of-scope).
        if classified.len() != 1 {
            return Err(CliError::LocalMultiSource {
                count: classified.len(),
            });
        }
        let source = match &classified[0] {
            SourceClassification::Local(p) => p.clone(),
            SourceClassification::Http(_) => unreachable!("filtered above"),
        };

        // Local mode is non-destructive by default
        // (`docs/PLAN_local_file_extract.md` §1). `-d/--destructive`
        // opts into hole-punch + delete-on-success. `-k` is a no-op
        // in local mode (local mode already preserves the source);
        // we still reject the `-k=<PATH>` value form because the
        // archive is already at the positional path.
        match self.keep_archive.as_deref() {
            None | Some("") => {}
            Some(_) => return Err(CliError::LocalKeepArchiveWithPath),
        }
        let destructive = self.destructive;
        if self.keep_archive.is_some() {
            if destructive {
                tracing::info!(
                    "`-d/--destructive` overrides `-k/--keep-archive` in local mode; \
                     running destructively",
                );
            } else {
                tracing::info!(
                    "local mode preserves the source archive by default; \
                     `-k/--keep-archive` is a no-op here (pass `-d/--destructive` \
                     to enable hole-punching + delete-on-success)",
                );
            }
        }

        let registry = DecoderRegistry::with_defaults();
        let output = build_local_output(
            &source,
            self.output_file,
            self.forced_format.as_deref(),
            &registry,
        )?;
        let password_source = self
            .password_from
            .as_deref()
            .map(PasswordSource::parse)
            .transpose()
            .map_err(CliError::InvalidPasswordSource)?;

        let args = LocalRunArgs {
            source,
            output,
            forced_format: self.forced_format,
            force_format_from_magic: self.force_format_from_magic,
            destructive,
            punch_threshold: self.punch_threshold,
            checkpoint_min_bytes: self.checkpoint_min_bytes,
            checkpoint_min_interval: Duration::from_secs_f64(self.checkpoint_min_secs.max(0.0)),
            workdir: self.workdir,
            io_backend: self.io_backend.into(),
            registry,
            progress: None,
            progress_state: None,
            kill_switch: None,
            io_backend_resolved: None,
            password_source,
        };

        Ok(Dispatch::Local {
            args: Box::new(args),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn output_flag_with_tree_format_url_builds_dir_target() {
        // `.tar.zst` suffix → Tree shape; -o builds a Dir target.
        let cli = Cli::try_parse_from(["peel", "https://example.com/x.tar.zst", "-o", "/tmp/out"])
            .expect("parse");
        let args = cli.into_run_args().expect("run args");
        match args.output {
            OutputTarget::Dir(p) => assert_eq!(p, PathBuf::from("/tmp/out")),
            OutputTarget::File(_) => panic!("expected Dir for .tar.zst"),
        }
    }

    #[test]
    fn output_flag_with_stream_format_url_builds_file_target() {
        // Bare `.zst` suffix → Stream shape; -o builds a File target.
        let cli = Cli::try_parse_from(["peel", "https://example.com/x.zst", "-o", "/tmp/out.bin"])
            .expect("parse");
        let args = cli.into_run_args().expect("run args");
        match args.output {
            OutputTarget::File(p) => assert_eq!(p, PathBuf::from("/tmp/out.bin")),
            OutputTarget::Dir(_) => panic!("expected File for bare .zst"),
        }
    }

    #[test]
    fn password_from_absent_yields_none_source() {
        let cli = Cli::try_parse_from(["peel", "https://example.com/x.tar.zst"]).expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert!(args.config.password_source.is_none());
    }

    #[test]
    fn password_from_prompt_parses_into_config() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.tar.zst",
            "--password-from",
            "prompt",
        ])
        .expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert!(matches!(
            args.config.password_source,
            Some(PasswordSource::Prompt)
        ));
    }

    #[test]
    fn password_from_env_parses_into_config() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.tar.zst",
            "--password-from",
            "env:PEEL_PASSWORD",
        ])
        .expect("parse");
        let args = cli.into_run_args().expect("run args");
        match args.config.password_source {
            Some(PasswordSource::Env(name)) => {
                assert_eq!(name, std::ffi::OsString::from("PEEL_PASSWORD"));
            }
            other => panic!("expected Env source, got {other:?}"),
        }
    }

    #[test]
    fn password_from_invalid_value_errors() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.tar.zst",
            "--password-from",
            "stdin",
        ])
        .expect("clap accepts the value");
        let err = cli.into_run_args().err().expect("must error");
        assert!(matches!(err, CliError::InvalidPasswordSource(_)));
    }

    #[test]
    fn no_password_arg_in_help() {
        // peel deliberately does not accept `--password=<value>` in
        // argv. The flag is the source-only form. This test
        // documents that choice: if a `--password` flag is ever
        // added back, this test fails and forces a re-evaluation
        // of the threat-model docs in PLAN_archive_encryption.md.
        let err = Cli::try_parse_from(["peel", "https://example.com/x.tar.zst", "--password", "p"])
            .expect_err("clap should reject --password");
        let msg = format!("{err}");
        assert!(
            msg.contains("unexpected")
                || msg.contains("unrecognized")
                || msg.contains("--password")
        );
    }

    #[test]
    fn dash_c_flag_returns_migration_error() {
        // `-C` is removed; clap accepts it (hidden stub) so we can
        // emit a typed migration error in `into_run_args`.
        let cli = Cli::try_parse_from(["peel", "https://example.com/x.tar.zst", "-C", "/tmp/out"])
            .expect("clap accepts hidden -C stub");
        let err = cli.into_run_args().err().expect("must error");
        assert!(matches!(err, CliError::OutputDirRemoved));
    }

    #[test]
    fn long_output_dir_flag_returns_migration_error() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.tar.zst",
            "--output-dir",
            "/tmp/out",
        ])
        .expect("clap accepts hidden --output-dir stub");
        let err = cli.into_run_args().err().expect("must error");
        assert!(matches!(err, CliError::OutputDirRemoved));
    }

    #[test]
    fn output_flag_with_tree_format_rejects_existing_regular_file() {
        // The user-supplied path exists and is a regular file but the
        // URL is `.tar.zst` (Tree). Reject with a shape mismatch.
        let tmp =
            std::env::temp_dir().join(format!("peel_cli_tree_file_test_{}", std::process::id()));
        std::fs::write(&tmp, b"").expect("create tmp file");
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.tar.zst",
            "-o",
            tmp.to_str().expect("utf8"),
        ])
        .expect("parse");
        let result = cli.into_run_args();
        // Clean up before any assertion so a failure doesn't leave
        // the file behind.
        let _ = std::fs::remove_file(&tmp);
        let err = result.err().expect("must error");
        assert!(matches!(
            err,
            CliError::OutputShapeMismatch {
                shape: FormatShape::Tree,
                ..
            }
        ));
    }

    #[test]
    fn output_flag_with_stream_format_rejects_trailing_slash() {
        let cli = Cli::try_parse_from(["peel", "https://example.com/x.zst", "-o", "/tmp/outdir/"])
            .expect("parse");
        let err = cli.into_run_args().err().expect("must error");
        assert!(matches!(
            err,
            CliError::OutputShapeMismatch {
                shape: FormatShape::Stream,
                ..
            }
        ));
    }

    #[test]
    fn output_flag_with_stream_format_rejects_existing_dir() {
        let tmp =
            std::env::temp_dir().join(format!("peel_cli_stream_dir_test_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).expect("create tmp dir");
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.zst",
            "-o",
            tmp.to_str().expect("utf8"),
        ])
        .expect("parse");
        let result = cli.into_run_args();
        let _ = std::fs::remove_dir_all(&tmp);
        let err = result.err().expect("must error");
        assert!(matches!(
            err,
            CliError::OutputShapeMismatch {
                shape: FormatShape::Stream,
                ..
            }
        ));
    }

    #[test]
    fn no_output_flag_tree_format_defaults_to_dir() {
        // `abcd.tar.xz` → Tree → Dir("abcd") (legacy default).
        let cli = Cli::try_parse_from(["peel", "https://example.com/abcd.tar.xz"]).expect("parse");
        let args = cli.into_run_args().expect("run args");
        match args.output {
            OutputTarget::Dir(p) => assert_eq!(p, PathBuf::from("abcd")),
            OutputTarget::File(_) => panic!("expected Dir target"),
        }
    }

    #[test]
    fn no_output_flag_stream_format_defaults_to_file() {
        // Bare `.zst` → Stream → File("foo") (new in §1).
        let cli = Cli::try_parse_from(["peel", "https://example.com/foo.zst"]).expect("parse");
        let args = cli.into_run_args().expect("run args");
        match args.output {
            OutputTarget::File(p) => assert_eq!(p, PathBuf::from("foo")),
            OutputTarget::Dir(_) => panic!("expected File for bare .zst default"),
        }
    }

    #[test]
    fn no_output_flag_unknown_shape_falls_back_to_dir() {
        // No known archive/compression suffix → unknown shape →
        // legacy Dir default (preserves pre-§1 behaviour).
        let cli = Cli::try_parse_from(["peel", "https://example.com/dataset"]).expect("parse");
        let args = cli.into_run_args().expect("run args");
        match args.output {
            OutputTarget::Dir(p) => assert_eq!(p, PathBuf::from("dataset")),
            OutputTarget::File(_) => panic!("expected Dir target"),
        }
    }

    #[test]
    fn no_output_flag_rejects_url_without_basename() {
        let cli = Cli::try_parse_from(["peel", "https://example.com/"]).expect("parse");
        let err = cli.into_run_args().err().expect("must error");
        assert!(matches!(err, CliError::NoDefaultOutput));
    }

    #[test]
    fn forced_format_drives_shape_resolution() {
        // URL has no recognized suffix but `--format zstd` (Stream)
        // is set → Stream resolver path.
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/opaque",
            "-o",
            "/tmp/decoded.bin",
            "--format",
            "zstd",
        ])
        .expect("parse");
        let args = cli.into_run_args().expect("run args");
        match args.output {
            OutputTarget::File(p) => assert_eq!(p, PathBuf::from("/tmp/decoded.bin")),
            OutputTarget::Dir(_) => panic!("expected File via --format zstd"),
        }
    }

    #[test]
    fn forced_format_with_mismatched_path_errors() {
        // `--format zstd` (Stream) + trailing-slash path → reject.
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/opaque",
            "-o",
            "/tmp/outdir/",
            "--format",
            "zstd",
        ])
        .expect("parse");
        let err = cli.into_run_args().err().expect("must error");
        assert!(matches!(
            err,
            CliError::OutputShapeMismatch {
                shape: FormatShape::Stream,
                ..
            }
        ));
    }

    #[test]
    fn unknown_shape_with_trailing_slash_picks_dir() {
        // URL has no recognized suffix, no `--format`. Path hint
        // (trailing `/`) wins → Dir.
        let cli = Cli::try_parse_from(["peel", "https://example.com/opaque", "-o", "/tmp/outdir/"])
            .expect("parse");
        let args = cli.into_run_args().expect("run args");
        match args.output {
            OutputTarget::Dir(p) => assert_eq!(p, PathBuf::from("/tmp/outdir/")),
            OutputTarget::File(_) => panic!("expected Dir from trailing slash"),
        }
    }

    #[test]
    fn unknown_shape_without_trailing_slash_picks_file() {
        // URL has no recognized suffix, no `--format`. No trailing
        // slash, no existing dir on disk → File (legacy `-o <FILE>`).
        let cli = Cli::try_parse_from(["peel", "https://example.com/opaque", "-o", "/tmp/out.bin"])
            .expect("parse");
        let args = cli.into_run_args().expect("run args");
        match args.output {
            OutputTarget::File(p) => assert_eq!(p, PathBuf::from("/tmp/out.bin")),
            OutputTarget::Dir(_) => panic!("expected File from non-slash path"),
        }
    }

    #[test]
    fn strip_archive_extensions_handles_double_suffix() {
        assert_eq!(strip_archive_extensions("abcd.tar.xz"), "abcd");
        assert_eq!(strip_archive_extensions("abcd.tar.gz"), "abcd");
        assert_eq!(strip_archive_extensions("abcd.tar.zst"), "abcd");
        assert_eq!(strip_archive_extensions("abcd.tgz"), "abcd");
        assert_eq!(strip_archive_extensions("abcd.zip"), "abcd");
        assert_eq!(strip_archive_extensions("abcd.TAR.XZ"), "abcd");
        assert_eq!(strip_archive_extensions("abcd.bin"), "abcd.bin");
        assert_eq!(strip_archive_extensions(".tar"), ".tar");
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
    fn parses_http_version_default_is_auto() {
        let cli = Cli::try_parse_from(["peel", "https://example.com/x.zst", "-o", "/tmp/o"])
            .expect("parse");
        assert_eq!(cli.http_version, HttpVersionArg::Auto);
    }

    #[test]
    fn parses_http_version_h1() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.zst",
            "-o",
            "/tmp/o",
            "--http-version",
            "h1",
        ])
        .expect("parse");
        assert_eq!(cli.http_version, HttpVersionArg::H1);
    }

    #[test]
    fn parses_http_version_h2() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.zst",
            "-o",
            "/tmp/o",
            "--http-version",
            "h2",
        ])
        .expect("parse");
        assert_eq!(cli.http_version, HttpVersionArg::H2);
    }

    #[test]
    fn rejects_unknown_http_version() {
        let err = Cli::try_parse_from([
            "peel",
            "https://example.com/x.zst",
            "-o",
            "/tmp/o",
            "--http-version",
            "h3",
        ])
        .expect_err("unknown http version");
        let _ = err;
    }

    #[test]
    fn http_version_arg_maps_to_library_enum() {
        assert_eq!(HttpVersion::from(HttpVersionArg::Auto), HttpVersion::Auto);
        assert_eq!(
            HttpVersion::from(HttpVersionArg::H1),
            HttpVersion::Http1Only
        );
        assert_eq!(
            HttpVersion::from(HttpVersionArg::H2),
            HttpVersion::Http2Only
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
    fn parses_sha256_hex_into_bytes() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.zst",
            "-o",
            "/tmp/o",
            "--sha256",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ])
        .expect("parse");
        let args = cli.into_run_args().expect("run args");
        let bytes = args.config.expected_sha256.expect("present");
        assert_eq!(bytes[0], 0xBA);
        assert_eq!(bytes[31], 0xAD);
    }

    #[test]
    fn no_sha256_flag_leaves_expected_hash_none() {
        let cli = Cli::try_parse_from(["peel", "https://example.com/x.zst", "-o", "/tmp/o"])
            .expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert!(args.config.expected_sha256.is_none());
    }

    #[test]
    fn rejects_short_sha256_argument() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.zst",
            "-o",
            "/tmp/o",
            "--sha256",
            "abc",
        ])
        .expect("parse");
        let err = cli.into_run_args().err().expect("must error");
        assert!(matches!(err, CliError::InvalidSha256(_)));
    }

    #[test]
    fn rejects_non_hex_sha256_argument() {
        // 64 chars but with a non-hex character.
        let bad: String = "Z".repeat(64);
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.zst",
            "-o",
            "/tmp/o",
            "--sha256",
            &bad,
        ])
        .expect("parse");
        let err = cli.into_run_args().err().expect("must error");
        assert!(matches!(err, CliError::InvalidSha256(_)));
    }

    #[test]
    fn parses_max_bandwidth_into_bytes_per_sec() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.zst",
            "-o",
            "/tmp/o",
            "--max-bandwidth",
            "10MB/s",
        ])
        .expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert_eq!(args.config.max_bandwidth_bps, Some(10_000_000));
    }

    #[test]
    fn parses_max_bandwidth_binary_suffix() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.zst",
            "-o",
            "/tmp/o",
            "--max-bandwidth",
            "1MiB/s",
        ])
        .expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert_eq!(args.config.max_bandwidth_bps, Some(1024 * 1024));
    }

    #[test]
    fn no_max_bandwidth_flag_leaves_limit_none() {
        let cli = Cli::try_parse_from(["peel", "https://example.com/x.zst", "-o", "/tmp/o"])
            .expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert!(args.config.max_bandwidth_bps.is_none());
    }

    #[test]
    fn rejects_unknown_max_bandwidth_unit() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.zst",
            "-o",
            "/tmp/o",
            "--max-bandwidth",
            "10XB/s",
        ])
        .expect("parse");
        let err = cli.into_run_args().err().expect("must error");
        assert!(matches!(err, CliError::InvalidBandwidth(_)));
    }

    #[test]
    fn rejects_zero_max_bandwidth() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.zst",
            "-o",
            "/tmp/o",
            "--max-bandwidth",
            "0",
        ])
        .expect("parse");
        let err = cli.into_run_args().err().expect("must error");
        assert!(matches!(err, CliError::InvalidBandwidth(_)));
    }

    #[test]
    fn parses_max_disk_buffer_default_is_one_gibibyte() {
        let cli = Cli::try_parse_from(["peel", "https://example.com/x.zst", "-o", "/tmp/o"])
            .expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert_eq!(args.config.max_disk_buffer, Some(1 << 30));
    }

    #[test]
    fn parses_max_disk_buffer_explicit_size() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.zst",
            "-o",
            "/tmp/o",
            "--max-disk-buffer",
            "512MiB",
        ])
        .expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert_eq!(args.config.max_disk_buffer, Some(512 * 1024 * 1024));
    }

    #[test]
    fn parses_max_disk_buffer_disable_sentinels() {
        for sentinel in ["none", "off", "disabled", "NONE", "Off", "DISABLED", "0"] {
            let cli = Cli::try_parse_from([
                "peel",
                "https://example.com/x.zst",
                "-o",
                "/tmp/o",
                "--max-disk-buffer",
                sentinel,
            ])
            .unwrap_or_else(|_| panic!("parse failed for sentinel {sentinel:?}"));
            let args = cli
                .into_run_args()
                .unwrap_or_else(|_| panic!("run args for sentinel {sentinel:?}"));
            assert_eq!(
                args.config.max_disk_buffer, None,
                "sentinel {sentinel:?} should disable the throttle",
            );
        }
    }

    #[test]
    fn rejects_unknown_max_disk_buffer_unit() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.zst",
            "-o",
            "/tmp/o",
            "--max-disk-buffer",
            "10XB",
        ])
        .expect("parse");
        let err = cli.into_run_args().err().expect("must error");
        assert!(matches!(err, CliError::InvalidDiskBuffer(_)));
    }

    #[test]
    fn workdir_default_is_none() {
        let cli = Cli::try_parse_from(["peel", "https://example.com/x.zst", "-o", "/tmp/o"])
            .expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert!(args.config.workdir.is_none());
    }

    #[test]
    fn workdir_flag_propagates_to_coordinator_config() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/x.zst",
            "-o",
            "/slow/out.bin",
            "--workdir",
            "/fast/scratch",
        ])
        .expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert_eq!(
            args.config.workdir.as_deref(),
            Some(std::path::Path::new("/fast/scratch"))
        );
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

    // ---- multi-URL (PLAN_multi_url_source.md §3) --------------------

    #[test]
    fn parses_multiple_positional_urls() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://h/p0",
            "https://h/p1",
            "https://h/p2",
            "-o",
            "/tmp/out/",
        ])
        .expect("parse");
        assert_eq!(cli.urls.len(), 3);
        assert_eq!(cli.urls[0], "https://h/p0");
        assert_eq!(cli.urls[2], "https://h/p2");
    }

    #[test]
    fn into_run_args_splits_primary_and_additional_urls() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://h/p0",
            "https://h/p1",
            "https://h/p2",
            "-o",
            "/tmp/out/",
        ])
        .expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert_eq!(args.url, "https://h/p0");
        assert_eq!(
            args.additional_urls,
            vec!["https://h/p1".to_string(), "https://h/p2".into()]
        );
    }

    #[test]
    fn single_url_keeps_additional_urls_empty() {
        let cli =
            Cli::try_parse_from(["peel", "https://h/x.tar.zst", "-o", "/tmp/out/"]).expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert_eq!(args.url, "https://h/x.tar.zst");
        assert!(args.additional_urls.is_empty());
    }

    #[test]
    fn multi_url_pairs_sha256_per_part() {
        // Three URLs and three --sha256 hashes — populates
        // expected_sha256s in URL order, leaves expected_sha256 None.
        let h0 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let h1 = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        let h2 = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
        let cli = Cli::try_parse_from([
            "peel",
            "https://h/p0",
            "https://h/p1",
            "https://h/p2",
            "--sha256",
            h0,
            "--sha256",
            h1,
            "--sha256",
            h2,
            "-o",
            "/tmp/out/",
        ])
        .expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert!(args.config.expected_sha256.is_none());
        assert_eq!(args.config.expected_sha256s.len(), 3);
        assert_eq!(args.config.expected_sha256s[0][0], 0xBA);
        assert_eq!(args.config.expected_sha256s[1][0], 0xB9);
        assert_eq!(args.config.expected_sha256s[2][0], 0x9F);
    }

    #[test]
    fn multi_url_with_no_sha256_is_accepted() {
        let cli = Cli::try_parse_from(["peel", "https://h/p0", "https://h/p1", "-o", "/tmp/out/"])
            .expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert!(args.config.expected_sha256.is_none());
        assert!(args.config.expected_sha256s.is_empty());
    }

    #[test]
    fn rejects_partial_sha256_count_for_multi_url() {
        // 3 URLs + only 2 hashes → ShaCountMismatch.
        let h = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let cli = Cli::try_parse_from([
            "peel",
            "https://h/p0",
            "https://h/p1",
            "https://h/p2",
            "--sha256",
            h,
            "--sha256",
            h,
            "-o",
            "/tmp/out/",
        ])
        .expect("parse");
        let err = cli.into_run_args().err().expect("must error");
        match err {
            CliError::ShaCountMismatch { urls, hashes } => {
                assert_eq!(urls, 3);
                assert_eq!(hashes, 2);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_two_sha256_for_single_url() {
        // Single URL with 2 --sha256 → ShaCountMismatch (not the
        // historical Some(_)/None binary; with multiple hashes the
        // single-URL slot can't represent the user's intent).
        let h = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let cli = Cli::try_parse_from([
            "peel",
            "https://h/x",
            "--sha256",
            h,
            "--sha256",
            h,
            "-o",
            "/tmp/out/",
        ])
        .expect("parse");
        let err = cli.into_run_args().err().expect("must error");
        match err {
            CliError::ShaCountMismatch { urls, hashes } => {
                assert_eq!(urls, 1);
                assert_eq!(hashes, 2);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn rejects_mirror_combined_with_multi_url() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://h/p0",
            "https://h/p1",
            "--mirror",
            "https://m/x",
            "-o",
            "/tmp/out/",
        ])
        .expect("parse");
        let err = cli.into_run_args().err().expect("must error");
        assert!(matches!(err, CliError::MirrorMultipleUrls));
    }

    #[test]
    fn mirror_works_with_single_url() {
        // --mirror is unchanged for the single-URL path.
        let cli = Cli::try_parse_from([
            "peel",
            "https://h/x.tar.zst",
            "--mirror",
            "https://m/x.tar.zst",
            "-o",
            "/tmp/out/",
        ])
        .expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert_eq!(
            args.config.mirror_urls,
            vec!["https://m/x.tar.zst".to_string()]
        );
        assert!(args.additional_urls.is_empty());
    }

    #[test]
    fn default_output_dir_strips_part_suffix() {
        // `pruned.tar.part0000` → strip `.part0000` → `pruned.tar` →
        // strip `.tar` → `pruned`.
        let cli = Cli::try_parse_from([
            "peel",
            "https://h/snap/pruned.tar.part0000",
            "https://h/snap/pruned.tar.part0001",
        ])
        .expect("parse");
        let args = cli.into_run_args().expect("run args");
        match args.output {
            OutputTarget::Dir(p) => assert_eq!(p, PathBuf::from("pruned")),
            OutputTarget::File(_) => panic!("expected Dir target"),
        }
    }

    #[test]
    fn strip_part_suffix_recognizes_part_nnnn() {
        assert_eq!(strip_part_suffix("pruned.tar.part0000"), "pruned.tar");
        assert_eq!(strip_part_suffix("pruned.tar.part12345"), "pruned.tar");
        assert_eq!(strip_part_suffix("PRUNED.TAR.PART0000"), "PRUNED.TAR");
        // Non-part suffixes are left alone.
        assert_eq!(strip_part_suffix("pruned.tar"), "pruned.tar");
        assert_eq!(strip_part_suffix("pruned.partAA"), "pruned.partAA");
        assert_eq!(strip_part_suffix("pruned.part"), "pruned.part");
    }

    #[test]
    fn strip_volume_or_part_handles_multivolume_names() {
        // RAR5 multi-volume: peels the `.part<N>.rar` suffix.
        assert_eq!(strip_volume_or_part_suffix("foo.part0001.rar"), "foo");
        assert_eq!(
            strip_volume_or_part_suffix("dataset.tar.part12.rar"),
            "dataset.tar"
        );
        // 7z multi-volume: peels `.7z.<NNN>`.
        assert_eq!(strip_volume_or_part_suffix("snap.7z.001"), "snap");
        assert_eq!(strip_volume_or_part_suffix("snap.tar.7z.005"), "snap.tar");
        // ZIP spanned: peels `.z<NN>` siblings AND the `.zip` final.
        assert_eq!(strip_volume_or_part_suffix("archive.z01"), "archive");
        assert_eq!(strip_volume_or_part_suffix("archive.zip"), "archive");
        // Byte-concat `.partNNNN` still falls through to the legacy
        // strip when no multi-volume pattern matches.
        assert_eq!(
            strip_volume_or_part_suffix("pruned.tar.part0000"),
            "pruned.tar"
        );
        // Non-matching names pass through.
        assert_eq!(strip_volume_or_part_suffix("foo.tar.zst"), "foo.tar.zst");
    }

    #[test]
    fn default_output_dir_strips_7z_multivolume_suffix() {
        let cli = Cli::try_parse_from(["peel", "https://h/snap/pruned.7z.001"]).expect("parse");
        let args = cli.into_run_args().expect("run args");
        match args.output {
            OutputTarget::Dir(p) => assert_eq!(p, PathBuf::from("pruned")),
            OutputTarget::File(_) => panic!("expected Dir target"),
        }
    }

    #[test]
    fn default_output_dir_strips_rar5_multivolume_suffix() {
        let cli = Cli::try_parse_from(["peel", "https://h/foo.part0001.rar"]).expect("parse");
        let args = cli.into_run_args().expect("run args");
        match args.output {
            OutputTarget::Dir(p) => assert_eq!(p, PathBuf::from("foo")),
            OutputTarget::File(_) => panic!("expected Dir target"),
        }
    }

    #[test]
    fn default_output_dir_strips_zip_spanned_suffix() {
        let cli = Cli::try_parse_from(["peel", "https://h/archive.z01"]).expect("parse");
        let args = cli.into_run_args().expect("run args");
        match args.output {
            OutputTarget::Dir(p) => assert_eq!(p, PathBuf::from("archive")),
            OutputTarget::File(_) => panic!("expected Dir target"),
        }
    }

    // ---- multivolume §6: --no-auto-discover / manifest / order ----------

    #[test]
    fn no_auto_discover_flag_propagates_to_run_args() {
        // `--no-auto-discover` must skip the HTTP `HEAD`-probe walk.
        // We can't easily observe "no HEAD was issued" from
        // [`into_run_args`] without spinning a mock server (covered
        // in an integration test below), but we can assert the flag
        // reaches the parsed struct.
        let cli = Cli::try_parse_from(["peel", "https://h/foo.7z.001", "--no-auto-discover"])
            .expect("parse");
        assert!(cli.no_auto_discover);
    }

    #[test]
    fn manifest_file_expands_positional_urls() {
        // Smoke-test the manifest expansion via the helper; the
        // full into_run_args path exercises the same code on
        // dispatch.
        let dir = std::env::temp_dir().join(format!("peel-manifest-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let manifest = dir.join("vols.txt");
        std::fs::write(
            &manifest,
            "# leading comment\n\
             https://h/foo.part0001.rar\n\
             \n\
             https://h/foo.part0002.rar\n\
             # trailing comment\n\
             https://h/foo.part0003.rar\n",
        )
        .expect("write");
        let arg = format!("@{}", manifest.display());
        let expanded = expand_manifest_urls(vec![arg]).expect("expand");
        assert_eq!(expanded.len(), 3);
        assert_eq!(expanded[0], "https://h/foo.part0001.rar");
        assert_eq!(expanded[2], "https://h/foo.part0003.rar");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manifest_with_extra_positional_args_rejected() {
        let err = expand_manifest_urls(vec![
            "@/tmp/vols.txt".to_string(),
            "https://h/extra.rar".to_string(),
        ])
        .unwrap_err();
        assert!(matches!(err, CliError::ManifestPositionalConflict));
    }

    #[test]
    fn manifest_missing_file_surfaces_typed_error() {
        let err =
            expand_manifest_urls(vec!["@/definitely-not-a-file-94732".to_string()]).unwrap_err();
        assert!(matches!(err, CliError::ManifestReadFailed { .. }));
    }

    #[test]
    fn manifest_empty_file_surfaces_typed_error() {
        let dir = std::env::temp_dir().join(format!("peel-manifest-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let manifest = dir.join("vols.txt");
        std::fs::write(&manifest, "# only comments\n\n").expect("write");
        let arg = format!("@{}", manifest.display());
        let err = expand_manifest_urls(vec![arg]).unwrap_err();
        assert!(matches!(err, CliError::ManifestEmpty { .. }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn positional_volume_list_in_order_accepted() {
        validate_positional_volume_order(&[
            "https://h/foo.part0001.rar".into(),
            "https://h/foo.part0002.rar".into(),
            "https://h/foo.part0003.rar".into(),
        ])
        .expect("contiguous");
    }

    #[test]
    fn positional_volume_list_out_of_order_rejected() {
        let err = validate_positional_volume_order(&[
            "https://h/foo.part0001.rar".into(),
            "https://h/foo.part0003.rar".into(),
            "https://h/foo.part0002.rar".into(),
        ])
        .unwrap_err();
        assert!(matches!(
            err,
            CliError::OutOfOrderVolumeList {
                position: 1,
                expected: 2,
                ..
            }
        ));
    }

    #[test]
    fn positional_volume_list_gap_rejected() {
        let err = validate_positional_volume_order(&[
            "https://h/foo.7z.001".into(),
            "https://h/foo.7z.003".into(),
        ])
        .unwrap_err();
        assert!(matches!(
            err,
            CliError::OutOfOrderVolumeList {
                position: 1,
                expected: 2,
                ..
            }
        ));
    }

    #[test]
    fn positional_volume_list_mixed_with_byte_concat_skips_check() {
        // `.partNNNN` (byte-concat) is *not* a multi-volume name;
        // parse_volume_name returns None for it. Such a list is
        // the multi-URL plan's domain and the volume-order check
        // must not interfere.
        validate_positional_volume_order(&[
            "https://h/pruned.tar.part0000".into(),
            "https://h/pruned.tar.part0001".into(),
        ])
        .expect("ok");
    }

    #[test]
    fn positional_volume_list_zip_final_no_check_anchor() {
        // ZIP final-volume seed has no numeric volume, so we can't
        // anchor a contiguous sequence on it; skipping is the
        // documented behaviour (discovery walker validates shape
        // instead).
        validate_positional_volume_order(&["https://h/foo.zip".into()]).expect("single");
    }

    #[test]
    fn into_dispatch_rejects_out_of_order_positional_list() {
        // End-to-end: a misordered positional list surfaces at
        // CLI dispatch time with the typed error, not after the
        // coordinator has done any IO.
        let cli = Cli::try_parse_from([
            "peel",
            "https://h/foo.part0001.rar",
            "https://h/foo.part0003.rar",
        ])
        .expect("parse");
        let err = cli.into_dispatch().err().expect("must error");
        assert!(matches!(err, CliError::OutOfOrderVolumeList { .. }));
    }

    // ---- §2: --no-extract -----------------------------------------------

    #[test]
    fn no_extract_flag_propagates_to_coordinator_config() {
        let cli = Cli::try_parse_from(["peel", "https://example.com/blob.bin", "--no-extract"])
            .expect("parse");
        assert!(cli.no_extract);
        let args = cli.into_run_args().expect("run args");
        assert!(args.config.no_extract);
    }

    #[test]
    fn download_only_alias_propagates_to_coordinator_config() {
        let cli = Cli::try_parse_from(["peel", "https://example.com/blob.bin", "--download-only"])
            .expect("parse");
        assert!(cli.no_extract);
    }

    #[test]
    fn no_extract_with_format_flag_errors() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/blob",
            "--no-extract",
            "--format",
            "zstd",
        ])
        .expect("parse");
        let err = cli.into_run_args().err().expect("must error");
        assert!(matches!(
            err,
            CliError::NoExtractConflict { flag: "--format" }
        ));
    }

    #[test]
    fn no_extract_with_force_format_from_magic_errors() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/blob",
            "--no-extract",
            "--force-format-from-magic",
        ])
        .expect("parse");
        let err = cli.into_run_args().err().expect("must error");
        assert!(matches!(
            err,
            CliError::NoExtractConflict {
                flag: "--force-format-from-magic"
            }
        ));
    }

    #[test]
    fn no_extract_with_non_default_punch_threshold_errors() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/blob",
            "--no-extract",
            "--punch-threshold",
            "1",
        ])
        .expect("parse");
        let err = cli.into_run_args().err().expect("must error");
        assert!(matches!(
            err,
            CliError::NoExtractConflict {
                flag: "--punch-threshold"
            }
        ));
    }

    #[test]
    fn no_extract_forces_stream_shape_against_url_suffix() {
        // URL says `.tar.zst` (Tree) but `--no-extract` overrides
        // the shape to Stream → the resolver builds an
        // `OutputTarget::File` with the basename + compression
        // suffix preserved.
        let cli = Cli::try_parse_from(["peel", "https://example.com/foo.tar.zst", "--no-extract"])
            .expect("parse");
        let args = cli.into_run_args().expect("run args");
        match args.output {
            OutputTarget::File(p) => assert_eq!(p, PathBuf::from("foo.tar.zst")),
            OutputTarget::Dir(_) => panic!("--no-extract must produce a File target"),
        }
    }

    #[test]
    fn no_extract_with_explicit_output_path_uses_it_verbatim() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/blob.bin",
            "--no-extract",
            "-o",
            "/tmp/local.bin",
        ])
        .expect("parse");
        let args = cli.into_run_args().expect("run args");
        match args.output {
            OutputTarget::File(p) => assert_eq!(p, PathBuf::from("/tmp/local.bin")),
            OutputTarget::Dir(_) => panic!("--no-extract must produce a File target"),
        }
    }

    #[test]
    fn no_extract_with_trailing_slash_output_errors() {
        // `--no-extract` always Stream; trailing slash → reject.
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/blob",
            "--no-extract",
            "-o",
            "/tmp/outdir/",
        ])
        .expect("parse");
        let err = cli.into_run_args().err().expect("must error");
        assert!(matches!(
            err,
            CliError::OutputShapeMismatch {
                shape: FormatShape::Stream,
                ..
            }
        ));
    }

    #[test]
    fn default_output_file_with_suffix_preserves_compression_suffix() {
        // The dedicated helper preserves `.tar.zst` exactly. Used
        // by `--no-extract` so users get the raw remote object on
        // disk under its natural name.
        let p = default_output_file_with_suffix("https://example.com/foo.tar.zst").expect("derive");
        assert_eq!(p, PathBuf::from("foo.tar.zst"));
        let p2 = default_output_file_with_suffix("https://example.com/x.bin").expect("derive");
        assert_eq!(p2, PathBuf::from("x.bin"));
    }

    // ---- §3: -k / --keep-archive ----------------------------------------

    #[test]
    fn bare_keep_archive_flag_sets_default_missing_value() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/foo.tar.zst",
            "-o",
            "/tmp/out/",
            "-k",
        ])
        .expect("parse");
        assert_eq!(cli.keep_archive.as_deref(), Some(""));
        let args = cli.into_run_args().expect("run args");
        assert_eq!(
            args.config.keep_archive.as_deref(),
            Some(Path::new("/tmp/foo.tar.zst")),
        );
    }

    #[test]
    fn keep_archive_with_value_uses_explicit_path() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/foo.tar.zst",
            "-o",
            "/tmp/out/",
            "-k=./archives/foo.zst",
        ])
        .expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert_eq!(
            args.config.keep_archive.as_deref(),
            Some(Path::new("./archives/foo.zst")),
        );
    }

    #[test]
    fn keep_archive_long_form_with_value() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/foo.tar.zst",
            "-o",
            "/tmp/out/",
            "--keep-archive=./archives/foo.zst",
        ])
        .expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert_eq!(
            args.config.keep_archive.as_deref(),
            Some(Path::new("./archives/foo.zst")),
        );
    }

    #[test]
    fn bare_keep_archive_with_file_output_places_archive_in_same_dir() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/foo.zst",
            "-o",
            "/tmp/single.bin",
            "-k",
        ])
        .expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert_eq!(
            args.config.keep_archive.as_deref(),
            Some(Path::new("/tmp/foo.zst")),
        );
    }

    #[test]
    fn bare_keep_archive_without_output_uses_cwd_relative_path() {
        // No `-o` ⇒ the resolver derives `OutputTarget::Dir("foo")`.
        // `Path::new("foo").parent()` is `""` which we coerce to
        // [`PathBuf::new`] (the implicit-CWD case); joining
        // `"foo.tar.zst"` to it yields the bare basename.
        let cli =
            Cli::try_parse_from(["peel", "https://example.com/foo.tar.zst", "-k"]).expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert_eq!(
            args.config.keep_archive.as_deref(),
            Some(Path::new("foo.tar.zst")),
        );
    }

    #[test]
    fn keep_archive_explicit_path_targeting_directory_errors() {
        let tmp =
            std::env::temp_dir().join(format!("peel_keep_archive_dir_test_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).expect("create tmp dir");
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/foo.tar.zst",
            "-o",
            "/tmp/out/",
            &format!("-k={}", tmp.to_str().expect("utf8")),
        ])
        .expect("parse");
        let result = cli.into_run_args();
        let _ = std::fs::remove_dir_all(&tmp);
        let err = result.err().expect("must error");
        assert!(matches!(err, CliError::KeepArchivePathIsDir { .. }));
    }

    // ---- §4: --strict-format --------------------------------------------

    #[test]
    fn strict_format_flag_propagates_to_coordinator_config() {
        let cli =
            Cli::try_parse_from(["peel", "https://example.com/foo.tar.zst", "--strict-format"])
                .expect("parse");
        assert!(cli.strict_format);
        let args = cli.into_run_args().expect("run args");
        assert!(args.config.strict_format);
    }

    #[test]
    fn strict_format_with_no_extract_errors() {
        // `docs/PLAN_download_modes.md` §4: combining
        // `--strict-format` with `--no-extract` is a CLI parse
        // error — detection doesn't run when extraction is
        // skipped, so the strict knob has nothing to be strict
        // about.
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/blob",
            "--no-extract",
            "--strict-format",
        ])
        .expect("parse");
        let err = cli.into_run_args().err().expect("must error");
        assert!(matches!(
            err,
            CliError::NoExtractConflict {
                flag: "--strict-format"
            }
        ));
    }

    #[test]
    fn strict_format_with_keep_archive_is_accepted() {
        // §4: `-k`/`--keep-archive` extracts (with the source
        // preserved), so detection still runs and strict-mode is
        // meaningful.
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/foo.tar.zst",
            "-o",
            "/tmp/out/",
            "-k",
            "--strict-format",
        ])
        .expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert!(args.config.strict_format);
        assert!(args.config.keep_archive.is_some());
    }

    #[test]
    fn keep_archive_with_no_extract_is_silently_dropped() {
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/foo.tar.zst",
            "--no-extract",
            "-k",
        ])
        .expect("parse");
        let args = cli.into_run_args().expect("run args");
        assert!(args.config.no_extract);
        assert!(args.config.keep_archive.is_none());
    }

    // ---- PLAN_local_file_extract.md §1: CLI dispatch -----------------

    /// Helper: create a unique temp regular file and return its path.
    /// Caller is responsible for removing it.
    fn make_local_fixture(label: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "peel_cli_local_{}_{}_{}.bin",
            label,
            std::process::id(),
            line!(),
        ));
        let _ = std::fs::remove_file(&p);
        std::fs::write(&p, b"peel-local-fixture").expect("create local fixture");
        p
    }

    #[test]
    fn classify_source_recognizes_http_url() {
        let s = classify_source("https://example.com/x.tar.zst").expect("classify");
        match s {
            SourceClassification::Http(u) => assert_eq!(u, "https://example.com/x.tar.zst"),
            SourceClassification::Local(_) => panic!("expected Http"),
        }
    }

    #[test]
    fn classify_source_recognizes_existing_path() {
        let p = make_local_fixture("classify_existing");
        let s = classify_source(p.to_str().expect("utf8")).expect("classify");
        let _ = std::fs::remove_file(&p);
        assert!(matches!(s, SourceClassification::Local(_)));
    }

    #[test]
    fn classify_source_rejects_nonexistent_path() {
        let err = classify_source("/definitely/not/a/real/peel/path").expect_err("classify");
        assert!(matches!(err, CliError::LocalSourceNotFound { .. }));
    }

    #[test]
    fn classify_source_rejects_directory() {
        let dir = std::env::temp_dir().join(format!("peel_cli_local_dir_{}", std::process::id(),));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let err = classify_source(dir.to_str().expect("utf8")).expect_err("classify");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(err, CliError::LocalSourceNotRegularFile { .. }));
    }

    #[test]
    fn dispatch_single_url_routes_to_http() {
        let cli = Cli::try_parse_from(["peel", "https://example.com/x.tar.zst", "-o", "/tmp/out/"])
            .expect("parse");
        let dispatch = cli.into_dispatch().expect("dispatch");
        assert!(matches!(dispatch, Dispatch::Http(_)));
    }

    #[test]
    fn dispatch_existing_file_routes_to_local_non_destructive_by_default() {
        let p = make_local_fixture("dispatch_default");
        let cli = Cli::try_parse_from(["peel", p.to_str().expect("utf8")]).expect("parse");
        let dispatch = cli.into_dispatch().expect("dispatch");
        let _ = std::fs::remove_file(&p);
        match dispatch {
            Dispatch::Local { args } => {
                assert!(
                    !args.destructive,
                    "local mode preserves the source by default"
                );
            }
            Dispatch::Http(_) => panic!("expected Local"),
        }
    }

    #[test]
    fn dispatch_existing_file_with_destructive_flag_opts_in() {
        let p = make_local_fixture("dispatch_destructive");
        let cli = Cli::try_parse_from(["peel", p.to_str().expect("utf8"), "-d"]).expect("parse");
        let dispatch = cli.into_dispatch().expect("dispatch");
        let _ = std::fs::remove_file(&p);
        match dispatch {
            Dispatch::Local { args } => {
                assert!(args.destructive, "-d must opt into destructive mode");
            }
            Dispatch::Http(_) => panic!("expected Local"),
        }
    }

    #[test]
    fn dispatch_existing_file_with_keep_archive_is_no_op_in_local_mode() {
        let p = make_local_fixture("dispatch_keep_noop");
        let cli = Cli::try_parse_from(["peel", p.to_str().expect("utf8"), "-k"]).expect("parse");
        let dispatch = cli.into_dispatch().expect("dispatch");
        let _ = std::fs::remove_file(&p);
        match dispatch {
            Dispatch::Local { args } => {
                assert!(
                    !args.destructive,
                    "-k in local mode is a no-op; non-destructive is already the default",
                );
            }
            Dispatch::Http(_) => panic!("expected Local"),
        }
    }

    #[test]
    fn dispatch_nonexistent_path_errors_clearly() {
        let cli = Cli::try_parse_from(["peel", "/definitely/not/here.tar.zst"]).expect("parse");
        let err = cli.into_dispatch().err().expect("must error");
        assert!(matches!(err, CliError::LocalSourceNotFound { .. }));
    }

    #[test]
    fn dispatch_mixing_url_and_path_errors() {
        let p = make_local_fixture("dispatch_mix");
        let cli = Cli::try_parse_from([
            "peel",
            "https://example.com/foo.tar.zst",
            p.to_str().expect("utf8"),
        ])
        .expect("parse");
        let result = cli.into_dispatch();
        let _ = std::fs::remove_file(&p);
        let err = result.err().expect("must error");
        assert!(matches!(err, CliError::MixedSources { .. }));
    }

    #[test]
    fn dispatch_local_rejects_http_only_flags() {
        let p = make_local_fixture("dispatch_workers");
        let cli = Cli::try_parse_from(["peel", p.to_str().expect("utf8"), "--workers", "8"])
            .expect("parse");
        let result = cli.into_dispatch();
        let _ = std::fs::remove_file(&p);
        let err = result.err().expect("must error");
        assert!(matches!(
            err,
            CliError::LocalFlagNotApplicable { flag: "--workers" }
        ));
    }

    #[test]
    fn dispatch_local_rejects_mirror_flag() {
        let p = make_local_fixture("dispatch_mirror");
        let cli =
            Cli::try_parse_from(["peel", p.to_str().expect("utf8"), "--mirror", "https://m/x"])
                .expect("parse");
        let result = cli.into_dispatch();
        let _ = std::fs::remove_file(&p);
        let err = result.err().expect("must error");
        assert!(matches!(
            err,
            CliError::LocalFlagNotApplicable { flag: "--mirror" }
        ));
    }

    #[test]
    fn dispatch_local_rejects_no_extract() {
        let p = make_local_fixture("dispatch_no_extract");
        let cli = Cli::try_parse_from(["peel", p.to_str().expect("utf8"), "--no-extract"])
            .expect("parse");
        let result = cli.into_dispatch();
        let _ = std::fs::remove_file(&p);
        let err = result.err().expect("must error");
        assert!(matches!(
            err,
            CliError::LocalFlagNotApplicable {
                flag: "--no-extract"
            }
        ));
    }

    #[test]
    fn dispatch_local_rejects_keep_archive_with_path() {
        let p = make_local_fixture("dispatch_kpath");
        let cli = Cli::try_parse_from([
            "peel",
            p.to_str().expect("utf8"),
            "-k=/tmp/elsewhere.tar.zst",
        ])
        .expect("parse");
        let result = cli.into_dispatch();
        let _ = std::fs::remove_file(&p);
        let err = result.err().expect("must error");
        assert!(matches!(err, CliError::LocalKeepArchiveWithPath));
    }

    #[test]
    fn dispatch_local_destructive_overrides_keep_archive() {
        // `-d` is the explicit destructive opt-in; `-k` in local
        // mode is a no-op. Combining them is harmless and resolves
        // to destructive (with an info-level log noting `-k` was
        // ignored).
        let p = make_local_fixture("dispatch_dk");
        let cli =
            Cli::try_parse_from(["peel", p.to_str().expect("utf8"), "-d", "-k"]).expect("parse");
        let dispatch = cli.into_dispatch().expect("dispatch");
        let _ = std::fs::remove_file(&p);
        match dispatch {
            Dispatch::Local { args } => {
                assert!(args.destructive, "-d wins over -k in local mode");
            }
            Dispatch::Http(_) => panic!("expected Local"),
        }
    }

    #[test]
    fn dispatch_http_with_destructive_is_no_op() {
        // HTTP runs are destructive by default; `-d` restates the
        // default and is a harmless no-op (logged at info level).
        // The dispatch still produces an Http run.
        let cli =
            Cli::try_parse_from(["peel", "https://example.com/x.tar.zst", "-d"]).expect("parse");
        let dispatch = cli.into_dispatch().expect("dispatch");
        assert!(matches!(dispatch, Dispatch::Http(_)));
    }

    #[test]
    fn dispatch_http_destructive_and_keep_archive_conflict_errors() {
        // `-d` says "destroy the archive" (HTTP default) and `-k`
        // says "preserve it". The two intents are contradictory;
        // peel rejects the combination rather than silently
        // picking one.
        let cli = Cli::try_parse_from(["peel", "https://example.com/x.tar.zst", "-d", "-k"])
            .expect("parse");
        let err = cli.into_dispatch().err().expect("must error");
        assert!(matches!(err, CliError::HttpDestructiveConflictsKeepArchive));
    }

    #[test]
    fn dispatch_local_with_format_overrides_shape_resolution() {
        // The source filename has no recognized suffix; `--format zstd`
        // (Stream) plus an explicit File-shaped `-o` should land in
        // `OutputTarget::File`.
        let p = make_local_fixture("dispatch_format");
        let cli = Cli::try_parse_from([
            "peel",
            p.to_str().expect("utf8"),
            "--format",
            "zstd",
            "-o",
            "/tmp/decoded.bin",
        ])
        .expect("parse");
        let dispatch = cli.into_dispatch().expect("dispatch");
        let _ = std::fs::remove_file(&p);
        match dispatch {
            Dispatch::Local { args, .. } => match &args.output {
                OutputTarget::File(out) => assert_eq!(out, Path::new("/tmp/decoded.bin")),
                OutputTarget::Dir(_) => panic!("expected File"),
            },
            Dispatch::Http(_) => panic!("expected Local"),
        }
    }
}
