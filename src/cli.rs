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

use crate::coordinator::{filename_from_url, CoordinatorConfig, OutputTarget, RunArgs};
use crate::decode::DecoderRegistry;
use crate::download::{
    parse_bandwidth, ParseBandwidthError, RetryConfig, DEFAULT_CHUNK_SIZE, DEFAULT_WORKERS,
};
use crate::extractor::DEFAULT_PUNCH_THRESHOLD;
use crate::hash::sha256::{parse_hex_digest, ParseHexDigestError};
use crate::http::{Client, ClientConfig, HttpVersion, Url, UrlError};
use crate::io_backend::IoBackendChoice;

/// Parsed CLI for the `peel` binary.
#[derive(Debug, Parser)]
#[command(
    name = "peel",
    version,
    about = "Streaming, resumable, space-efficient extractor for compressed archives over HTTP."
)]
#[command(group(
    // Both args are optional; when neither is set, the binary derives
    // a default `OutputTarget::Dir` from the URL basename (with known
    // compression/archive extensions stripped) in the current working
    // directory. The group still rejects setting both at once.
    ArgGroup::new("output")
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
    /// Source URL(s). One URL is the historical single-source case.
    /// Two or more URLs activate the multi-part split-archive path
    /// (`docs/PLAN_multi_url_source.md`): the byte-concatenation of
    /// every URL's body is treated as one logical archive stream,
    /// and the workers fetch all parts in parallel via ranged GETs.
    /// Examples: `peel https://host/x.tar.zst -C out/` or
    /// `peel https://host/x.tar.part0000 https://host/x.tar.part0001 -C out/`.
    #[arg(num_args = 1..)]
    pub urls: Vec<String>,

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

    /// Neither `-C/--output-dir` nor `-o/--output-file` was given,
    /// and the URL did not parse as a valid URL — so no default
    /// output directory could be derived.
    #[error("URL is not valid; pass -C <DIR> or -o <FILE> explicitly")]
    InvalidUrl(#[source] UrlError),

    /// Neither `-C/--output-dir` nor `-o/--output-file` was given,
    /// and the URL has no usable basename (e.g. it ends in `/`) so
    /// no default output directory could be derived.
    #[error("URL has no filename to derive a default output directory from; pass -C <DIR> or -o <FILE> explicitly")]
    NoDefaultOutput,

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
/// given: parse the URL, take its basename, strip the multi-part
/// `.partNNNN` suffix (`docs/PLAN_multi_url_source.md` §3 step 4) if
/// present, then strip known compression / archive extensions, and
/// place the result in the current working directory (as a relative
/// path).
fn default_output_dir(url: &str) -> Result<PathBuf, CliError> {
    let parsed = Url::parse(url).map_err(CliError::InvalidUrl)?;
    let name = filename_from_url(&parsed).ok_or(CliError::NoDefaultOutput)?;
    let depart = strip_part_suffix(&name);
    let stripped = strip_archive_extensions(depart);
    if stripped.is_empty() {
        return Err(CliError::NoDefaultOutput);
    }
    Ok(PathBuf::from(stripped))
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
        // The `num_args = 1..` constraint guarantees at least one
        // URL at parse time; `urls[0]` is the primary part. The
        // explicit fallback below keeps the function defensive
        // against an `into_run_args` caller that constructed `Cli`
        // by hand and skipped clap (the assert path).
        let mut urls_iter = self.urls.into_iter();
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

        let output = match (self.output_dir, self.output_file) {
            (Some(d), None) => OutputTarget::Dir(d),
            (None, Some(f)) => OutputTarget::File(f),
            // §3 step 4: derive the default output dir from the
            // *first* URL's basename, with the multi-part suffix
            // stripped first so `pruned.tar.part0000` becomes
            // `pruned`.
            (None, None) => OutputTarget::Dir(default_output_dir(&primary_url)?),
            // The clap ArgGroup rejects setting both at once at parse
            // time, so this arm cannot fire in practice; the catch-all
            // keeps the match exhaustive without `unreachable!`.
            (Some(d), Some(_)) => OutputTarget::Dir(d),
        };
        let max_bandwidth_bps = match self.max_bandwidth {
            Some(s) => Some(parse_bandwidth(&s).map_err(CliError::InvalidBandwidth)?),
            None => None,
        };
        let max_disk_buffer =
            parse_disk_buffer(&self.max_disk_buffer).map_err(CliError::InvalidDiskBuffer)?;
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
            },
            client,
            registry: DecoderRegistry::with_defaults(),
            progress: None,
            progress_state: None,
            kill_switch: None,
            io_backend: None,
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
    fn no_output_flags_derives_default_dir_from_url() {
        // `abcd.tar.xz` → `$(pwd)/abcd` (relative `PathBuf`).
        let cli = Cli::try_parse_from(["peel", "https://example.com/abcd.tar.xz"]).expect("parse");
        assert!(cli.output_dir.is_none());
        assert!(cli.output_file.is_none());
        let args = cli.into_run_args().expect("run args");
        match args.output {
            OutputTarget::Dir(p) => assert_eq!(p, PathBuf::from("abcd")),
            OutputTarget::File(_) => panic!("expected Dir target"),
        }
    }

    #[test]
    fn no_output_flags_with_unstripped_basename() {
        // No known archive/compression suffix → keep the basename as-is.
        let cli = Cli::try_parse_from(["peel", "https://example.com/dataset"]).expect("parse");
        let args = cli.into_run_args().expect("run args");
        match args.output {
            OutputTarget::Dir(p) => assert_eq!(p, PathBuf::from("dataset")),
            OutputTarget::File(_) => panic!("expected Dir target"),
        }
    }

    #[test]
    fn no_output_flags_rejects_url_without_basename() {
        let cli = Cli::try_parse_from(["peel", "https://example.com/"]).expect("parse");
        let err = cli.into_run_args().err().expect("must error");
        assert!(matches!(err, CliError::NoDefaultOutput));
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
            "-C",
            "/tmp/out",
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
            "-C",
            "/tmp/out",
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
            Cli::try_parse_from(["peel", "https://h/x.tar.zst", "-C", "/tmp/out"]).expect("parse");
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
            "-C",
            "/tmp/out",
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
        let cli = Cli::try_parse_from(["peel", "https://h/p0", "https://h/p1", "-C", "/tmp/out"])
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
            "-C",
            "/tmp/out",
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
            "-C",
            "/tmp/out",
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
            "-C",
            "/tmp/out",
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
            "-C",
            "/tmp/out",
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
}
