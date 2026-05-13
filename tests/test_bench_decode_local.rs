//! Local-only decoder throughput grid: peel vs. the reference CLI.
//!
//! This suite isolates the **decoder** by running both peel and the
//! format-specific reference CLI utility against the same on-disk
//! fixture — no HTTP, no mock server, no parallel ranged GETs. The
//! streaming bench in [`test_bench_streaming.rs`] bakes the HTTP cost
//! into both sides; this one strips it out so the per-format ratios
//! reflect the decoder kernel alone.
//!
//! Plan: [`internal/old/PLAN_decoder_throughput_vs_cli.md`]. This file
//! corresponds to §1 (scaffold), §2 (fixture size sweep), and §3
//! (cold vs. warm cache isolation). §5's "next optimisation queue"
//! summary lands in `internal/bench-results/` after a real grid run on
//! the primary benchmark host — that's an operator task, not
//! something the bench source produces directly.
//!
//! §4 (CI smoke-tier gate) is **intentionally deferred** for now,
//! per the plan's own "optional" qualifier. Rationale: every
//! other per-decoder bench in this repo
//! ([`test_bench_streaming.rs`], [`test_bench_deflate_native.rs`],
//! [`test_bench_xz_liblzma.rs`], [`test_bench_rar_smoke.rs`]) uses
//! the same on-demand pattern — `#[ignore]`'d tests invoked
//! explicitly, results archived under `internal/bench-results/`. A
//! per-PR smoke gate is non-trivial CI infrastructure to add (the
//! plan calls out "the CI overhead is non-trivial and the value is
//! 'catch regressions before they bake in,' which can also be
//! addressed by running the full grid before each release"), and
//! none of the existing bench grids have one. Revisit if regressions
//! actually slip through the release-gate pattern.
//!
//! ## How to run
//!
//! The bench is `#[ignore]`'d so `cargo test` skips it. Invoke
//! explicitly, in `--release`, with `--nocapture` to see the grid:
//!
//! ```text
//! cargo test --release --test test_bench_decode_local -- \
//!     --ignored --nocapture --test-threads=1
//! ```
//!
//! The small + medium tiers run by default. The 1 GiB tier is gated
//! behind the `PEEL_BENCH_LARGE` env var (see §2 of the plan): set
//! it to anything truthy to opt in.
//!
//! ```text
//! PEEL_BENCH_LARGE=1 cargo test --release --test test_bench_decode_local -- \
//!     --ignored --nocapture --test-threads=1
//! ```
//!
//! ## Tool availability
//!
//! Each reference row shells out to a format-specific CLI tool
//! (`zstd`, `xz`, `gzip`, `lz4`, `tar`). Missing tools are reported
//! as `[skip]` rows; the bench never fails on missing tools, so the
//! grid is meaningful on a developer laptop with whatever
//! decompressors happen to be installed.
//!
//! ## Format coverage
//!
//! Every format in [`peel::decode::DecoderRegistry::with_defaults`]
//! that flows through the streaming-decoder path
//! ([`peel::coordinator::local::run`]) gets at least one row:
//! `zstd-raw`, `tar.zst`, `xz-raw`, `tar.xz`, `gz-raw`, `tar.gz`,
//! `lz4-raw`, `tar.lz4`, plain `tar`.
//!
//! The random-access formats (`zip`, `7z`, `rar`) are intentionally
//! skipped here: [`peel::coordinator::local::run`] surfaces a typed
//! error for those today (their per-pipeline orchestrators expect a
//! [`peel::download::BlockingSparseReader`] source), and lifting that
//! restriction is its own design — see the note at the top of
//! `src/coordinator/local.rs`. The streaming bench already covers
//! `zip`, `7z`, and `rar` end-to-end.

#![cfg(unix)]

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime};

#[path = "support/mod.rs"]
mod support;

#[cfg(feature = "rar")]
use support::rar_bench_fixtures::{
    ensure_rar3_stored, ensure_rar5_stored, rar3_encoder_present, rar5_encoder_present, unrar_path,
};
use support::sevenz_fixtures::build_copy_sevenz;
use support::tar_fixtures::build_simple_archive;
use support::zip_fixtures::{build_zip, ZipEntrySpec};

// ---- size tiers -------------------------------------------------------

/// Approximate compressed-size targets per tier (`internal/old/PLAN_decoder_throughput_vs_cli.md` §2).
/// The numbers are *raw* payload sizes; the on-the-wire size after
/// compression varies per format, but the LCG-generated payload is
/// near-incompressible (matching the streaming bench's
/// `random_bytes`) so wall-clock differences track decoder work
/// rather than compression-ratio luck.
#[derive(Copy, Clone)]
struct Tier {
    label: &'static str,
    payload_bytes: usize,
    /// File count for tar-shaped fixtures. Smaller tiers fan out
    /// over fewer files so per-member overhead doesn't dominate the
    /// 10 MiB cell.
    tar_files: usize,
}

/// 10 MiB · 4 files. Fast feedback loop — the whole grid finishes
/// in under 30 s on a developer laptop.
const TIER_SMALL: Tier = Tier {
    label: "10 MiB",
    payload_bytes: 10 * 1024 * 1024,
    tar_files: 4,
};

/// ~100 MiB · 8 files. The "representative" tier; matches the
/// payload size class used by the streaming bench's per-format
/// rows and is where peel-vs-CLI ratios stabilise.
const TIER_MEDIUM: Tier = Tier {
    label: "100 MiB",
    payload_bytes: 100 * 1024 * 1024,
    tar_files: 8,
};

/// 1 GiB · 16 files. Opt-in via `PEEL_BENCH_LARGE=1` (`PLAN_decoder_throughput_vs_cli.md` §2 step 4).
/// Fixtures of this size do not live under `tests/fixtures/`; they
/// are built into a process-unique tempdir and wiped on completion.
const TIER_LARGE: Tier = Tier {
    label: "1 GiB",
    payload_bytes: 1024 * 1024 * 1024,
    tar_files: 16,
};

fn pick_tiers() -> Vec<Tier> {
    let mut tiers = vec![TIER_SMALL, TIER_MEDIUM];
    if std::env::var_os("PEEL_BENCH_LARGE")
        .map(|v| v != *OsStr::new("") && v != *OsStr::new("0"))
        .unwrap_or(false)
    {
        tiers.push(TIER_LARGE);
    }
    tiers
}

// ---- harness helpers --------------------------------------------------

static UNIQ: AtomicU64 = AtomicU64::new(0);

fn unique_dir(label: &str) -> PathBuf {
    let pid = std::process::id();
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("peel_bench_decode_{label}_{pid}_{nanos}_{n}"));
    fs::create_dir_all(&p).expect("create unique_dir");
    p
}

struct CleanupDir(PathBuf);
impl Drop for CleanupDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// True if `name` resolves on `PATH`, or — when it contains a path
/// separator — points at an existing executable file on disk. Same
/// pattern as the streaming bench so a missing reference CLI
/// surfaces as a `[skip]` row, not a test failure. The path-aware
/// branch is used for the licensed `unrar` at
/// `~/Downloads/rar/unrar`, which is typically not on `$PATH`.
fn tool_present(name: &str) -> bool {
    if name.contains('/') {
        return std::path::Path::new(name).is_file();
    }
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {name} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Mostly-incompressible payload generated via an LCG. Matches the
/// streaming bench's `random_bytes` so the two suites compare
/// against the same fixture characteristics — important because the
/// streaming bench's HTTP-side numbers and the decoder-only numbers
/// produced here will land next to each other in the README grid.
fn random_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
    let mut out = Vec::with_capacity(len);
    while out.len() < len {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        out.extend_from_slice(&state.to_le_bytes());
    }
    out.truncate(len);
    out
}

// ---- POSIX shell quoting ---------------------------------------------

/// Single-quote a path for inclusion in a `bash -c` script. Tempdir
/// paths from [`unique_dir`] never contain `'` but the cost of
/// doing it correctly once is small (same helper shape as the
/// streaming bench).
fn shell_quote(path: &Path) -> String {
    let s = path.to_string_lossy();
    let escaped = s.replace('\'', "'\\''");
    format!("'{escaped}'")
}

// ---- codec encoders (in-process) --------------------------------------

fn encode_zstd(payload: &[u8]) -> Vec<u8> {
    zstd::encode_all(payload, 1).expect("encode zstd")
}

fn encode_xz(payload: &[u8]) -> Vec<u8> {
    use xz2::stream::{Action, Check, Status, Stream};
    let mut encoder = Stream::new_easy_encoder(6, Check::Crc64).expect("encoder");
    let mut out: Vec<u8> = Vec::with_capacity(payload.len() / 2 + 256);
    let mut input_pos = 0usize;
    let mut scratch = vec![0u8; 1 << 14];
    loop {
        let action = if input_pos < payload.len() {
            Action::Run
        } else {
            Action::Finish
        };
        let prev_in = encoder.total_in();
        let prev_out = encoder.total_out();
        let res = encoder
            .process(&payload[input_pos..], &mut scratch, action)
            .expect("encode step");
        input_pos += (encoder.total_in() - prev_in) as usize;
        let produced = (encoder.total_out() - prev_out) as usize;
        out.extend_from_slice(&scratch[..produced]);
        if let Status::StreamEnd = res {
            break;
        }
    }
    out
}

fn encode_gzip(payload: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut encoder = GzEncoder::new(
        Vec::with_capacity(payload.len() / 2 + 256),
        Compression::default(),
    );
    encoder.write_all(payload).expect("encode gzip");
    encoder.finish().expect("finish gzip")
}

/// Single-frame, single-block, *uncompressed* LZ4 archive. Same
/// shape produced by the streaming bench; both `peel::decode::lz4`
/// and `lz4 -d` accept it. The wire-size matches the raw payload so
/// the row measures framing/dispatch overhead rather than a
/// compression ratio — that's the point: lz4 is so fast that
/// anything else dominates.
fn encode_lz4_uncompressed_frame(payload: &[u8]) -> Vec<u8> {
    const PRIME32_1: u32 = 0x9E37_79B1;
    const PRIME32_2: u32 = 0x85EB_CA77;
    const PRIME32_3: u32 = 0xC2B2_AE3D;
    const PRIME32_4: u32 = 0x27D4_EB2F;
    const PRIME32_5: u32 = 0x1656_67B1;

    fn read_u32_le(bs: &[u8]) -> u32 {
        u32::from_le_bytes([bs[0], bs[1], bs[2], bs[3]])
    }
    fn round(acc: u32, lane: u32) -> u32 {
        acc.wrapping_add(lane.wrapping_mul(PRIME32_2))
            .rotate_left(13)
            .wrapping_mul(PRIME32_1)
    }
    fn xxh32(input: &[u8]) -> u32 {
        let mut p = 0usize;
        let len = input.len();
        let mut h: u32;
        if len >= 16 {
            let mut v1 = PRIME32_1.wrapping_add(PRIME32_2);
            let mut v2 = PRIME32_2;
            let mut v3 = 0u32;
            let mut v4 = 0u32.wrapping_sub(PRIME32_1);
            let limit = len - 16;
            loop {
                v1 = round(v1, read_u32_le(&input[p..]));
                v2 = round(v2, read_u32_le(&input[p + 4..]));
                v3 = round(v3, read_u32_le(&input[p + 8..]));
                v4 = round(v4, read_u32_le(&input[p + 12..]));
                p += 16;
                if p > limit {
                    break;
                }
            }
            h = v1
                .rotate_left(1)
                .wrapping_add(v2.rotate_left(7))
                .wrapping_add(v3.rotate_left(12))
                .wrapping_add(v4.rotate_left(18));
        } else {
            h = PRIME32_5;
        }
        h = h.wrapping_add(len as u32);
        while p + 4 <= len {
            h = h.wrapping_add(read_u32_le(&input[p..]).wrapping_mul(PRIME32_3));
            h = h.rotate_left(17).wrapping_mul(PRIME32_4);
            p += 4;
        }
        while p < len {
            h = h.wrapping_add(u32::from(input[p]).wrapping_mul(PRIME32_5));
            h = h.rotate_left(11).wrapping_mul(PRIME32_1);
            p += 1;
        }
        h ^= h >> 15;
        h = h.wrapping_mul(PRIME32_2);
        h ^= h >> 13;
        h = h.wrapping_mul(PRIME32_3);
        h ^= h >> 16;
        h
    }

    const BLOCK_MAX: usize = 4 * 1024 * 1024;
    let mut out = Vec::new();
    out.extend_from_slice(&0x184D_2204u32.to_le_bytes());
    let flg: u8 = 0b0110_0000;
    let bd: u8 = 0b0111_0000;
    out.push(flg);
    out.push(bd);
    let hc = ((xxh32(&[flg, bd]) >> 8) & 0xff) as u8;
    out.push(hc);
    for chunk in payload.chunks(BLOCK_MAX) {
        let header = (chunk.len() as u32) | 0x8000_0000;
        out.extend_from_slice(&header.to_le_bytes());
        out.extend_from_slice(chunk);
    }
    out.extend_from_slice(&[0u8; 4]);
    out
}

// ---- fixture builders -------------------------------------------------

/// Build a tar archive whose raw byte total is approximately
/// `payload_bytes`, split across `files` members. The same seed
/// scheme as the streaming bench so [`assert_dir_matches`] can
/// re-derive expected bodies without re-parsing the archive.
fn build_tar_payload(payload_bytes: usize, files: usize) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    let per = payload_bytes / files.max(1);
    let entries: Vec<(String, Vec<u8>)> = (0..files)
        .map(|i| {
            (
                format!("data/file_{i:02}.bin"),
                random_bytes(0xBEEF + i as u64, per),
            )
        })
        .collect();
    let pairs: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    let archive = build_simple_archive(&pairs);
    (archive, entries)
}

fn assert_dir_matches(dir: &Path, entries: &[(String, Vec<u8>)]) {
    for (name, body) in entries {
        let path = dir.join(name);
        let actual = fs::read(&path).expect("read extracted file");
        assert_eq!(actual.len(), body.len(), "size mismatch on {name}");
        assert_eq!(&actual, body, "contents mismatch on {name}");
    }
}

fn assert_file_matches(path: &Path, body: &[u8]) {
    let actual = fs::read(path).expect("read decoded file");
    assert_eq!(actual.len(), body.len(), "raw-decode size mismatch");
    assert_eq!(actual, body, "raw-decode contents mismatch");
}

// ---- CPU-time measurement (getrusage) ---------------------------------

/// `getrusage(2)` wrapper that returns user + system CPU time as a
/// single [`Duration`]. Declared inline because the project's
/// dependency policy bars `libc` (`internal/ENGINEERING_STANDARDS.md`
/// §2.2); same precedent as the `fallocate` / `pwrite` declarations
/// in `src/punch.rs` and `tests/test_punch_race_macos.rs`.
mod rusage {
    use std::time::Duration;

    /// `struct timeval` on Linux: both `tv_sec` and `tv_usec` are
    /// `long` (i64 on every 64-bit Linux target peel supports). The
    /// total `sizeof(struct timeval)` is 16 bytes.
    #[cfg(target_os = "linux")]
    #[repr(C)]
    struct Timeval {
        tv_sec: i64,
        tv_usec: i64,
    }

    /// `struct timeval` on macOS: `tv_sec` is `time_t` (i64) and
    /// `tv_usec` is `__darwin_suseconds_t` (i32). Rust's `#[repr(C)]`
    /// tail-pads to the struct's 8-byte alignment, so
    /// `sizeof(Timeval)` is 16 — matching the kernel ABI exactly.
    #[cfg(target_os = "macos")]
    #[repr(C)]
    struct Timeval {
        tv_sec: i64,
        tv_usec: i32,
    }

    /// `struct rusage` from `<sys/resource.h>`. We only read
    /// `ru_utime` and `ru_stime`; the remaining 14 `long` fields
    /// (`ru_maxrss`, `ru_inblock`, ...) are reserved as opaque
    /// padding so the struct size matches the kernel ABI on both
    /// Linux and macOS (144 bytes on 64-bit targets).
    #[repr(C)]
    struct Rusage {
        ru_utime: Timeval,
        ru_stime: Timeval,
        _rest: [i64; 14],
    }

    extern "C" {
        fn getrusage(who: i32, usage: *mut Rusage) -> i32;
    }

    /// `RUSAGE_SELF` from `<sys/resource.h>`: CPU time consumed by
    /// the calling process (all threads). Used for in-process peel
    /// runs.
    #[allow(dead_code)]
    pub const RUSAGE_SELF: i32 = 0;

    /// `RUSAGE_CHILDREN` (numeric value `-1`): cumulative CPU time
    /// for all *waited-on* descendants of the calling process. Used
    /// to attribute CPU to subprocess pipelines — the kernel rolls
    /// grandchild CPU into a parent's `ru_*time` at `wait4(2)` time,
    /// so a `bash -c "zstd ... | tar ..."` pipeline contributes its
    /// full pipeline-wide CPU to this counter once bash has reaped
    /// its own children.
    pub const RUSAGE_CHILDREN: i32 = -1;

    /// Sample `(user + system)` CPU time for the given `who`.
    /// Returns [`Duration::ZERO`] if the syscall errors (which the
    /// man page only permits for an invalid `who` constant — which
    /// can't happen here since both [`RUSAGE_SELF`] and
    /// [`RUSAGE_CHILDREN`] are spelled out above).
    pub fn sample(who: i32) -> Duration {
        // SAFETY: `Rusage` is `#[repr(C)]` with the ABI-correct
        // size (144 bytes on every 64-bit Unix target peel
        // supports — see the docstrings on `Timeval` and `Rusage`
        // above). Zero-initialising it produces a well-defined
        // value (no `Drop` impls, all primitive integer fields).
        let mut r: Rusage = unsafe { std::mem::zeroed() };
        // SAFETY: `who` is one of the two constants defined in
        // this module (`RUSAGE_SELF` or `RUSAGE_CHILDREN`); the
        // pointer is to a fully-initialised stack local. The
        // kernel writes exactly `sizeof(struct rusage)` bytes,
        // which equals `sizeof(Rusage)` by construction above.
        let rc = unsafe { getrusage(who, &mut r as *mut Rusage) };
        if rc != 0 {
            return Duration::ZERO;
        }
        let u_sec = r.ru_utime.tv_sec.max(0) as u64;
        let u_nsec = (r.ru_utime.tv_usec as i64).max(0) as u32 * 1_000;
        let s_sec = r.ru_stime.tv_sec.max(0) as u64;
        let s_nsec = (r.ru_stime.tv_usec as i64).max(0) as u32 * 1_000;
        Duration::new(u_sec, u_nsec) + Duration::new(s_sec, s_nsec)
    }
}

// ---- peel-local driver ------------------------------------------------

/// Output target for [`run_peel_local`]. Mirrors the streaming bench's
/// shape: file-shape outputs flow through `peel -o <path>` (raw codec
/// targets), tree-shape through `peel -o <path>/` (anything that
/// extracts entries: tar wrappers and the random-access containers).
enum PeelLocalOut {
    File(PathBuf),
    Dir(PathBuf),
}

/// Run the `peel` CLI binary against a local source, timing both
/// wall-clock and child CPU.
///
/// This is the subprocess equivalent of the prior in-process
/// `coordinator::local::run` driver. We spawn the binary because the
/// reference baselines below shell out to `zstd` / `xz` / `unzip` /
/// `7z` / `unrar` — each of which pays the same
/// `fork`/`execve`/`dlopen` cost on every invocation. Measuring peel
/// in-process would hide its own process-startup work (allocator
/// pools, registry init, command-line parsing) behind the test
/// harness's already-warm address space and produce ratios that
/// flatter the in-process API at the expense of the published CLI.
///
/// CPU is sampled via `getrusage(RUSAGE_CHILDREN)` — same primitive
/// the reference pipeline uses — so the wall/CPU columns are
/// directly comparable across rows. We leave `-d` off (the
/// non-destructive default) so the same fixture survives the cold
/// and warm iterations; destructive mode would punch + delete the
/// source mid-bench.
fn run_peel_local(source: &Path, out: PeelLocalOut) -> (Duration, Duration) {
    let exe = env!("CARGO_BIN_EXE_peel");
    let cpu_before = rusage::sample(rusage::RUSAGE_CHILDREN);
    let wall_started = Instant::now();
    let mut cmd = Command::new(exe);
    cmd.arg(source);
    match &out {
        PeelLocalOut::Dir(d) => {
            // Trailing slash forces directory-shape output regardless
            // of suffix detection.
            cmd.arg("-o").arg(format!("{}/", d.display()));
        }
        PeelLocalOut::File(f) => {
            cmd.arg("-o").arg(f);
        }
    }
    let output = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn peel subprocess");
    let wall = wall_started.elapsed();
    let cpu_after = rusage::sample(rusage::RUSAGE_CHILDREN);
    if !output.status.success() {
        panic!(
            "peel subprocess exited {}: stderr=\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    (wall, cpu_after.saturating_sub(cpu_before))
}

// ---- reference-CLI driver ---------------------------------------------

/// Run a `bash -c <pipeline>` reference pipeline. Returns
/// `(wall, cpu)` where `cpu` is the cumulative user+system time of
/// the bash subprocess *and all of its waited descendants* (see the
/// docstring on [`rusage::RUSAGE_CHILDREN`] for why this is sound).
fn run_ref_pipeline(pipeline: &str, src: &Path) -> (Duration, Duration) {
    let cpu_before = rusage::sample(rusage::RUSAGE_CHILDREN);
    let wall_started = Instant::now();
    let output = Command::new("bash")
        .arg("-eu")
        .arg("-o")
        .arg("pipefail")
        .arg("-c")
        .arg(pipeline)
        .env("SRC", src)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn bash for reference pipeline");
    let wall = wall_started.elapsed();
    let cpu_after = rusage::sample(rusage::RUSAGE_CHILDREN);
    if !output.status.success() {
        panic!(
            "reference pipeline exited {}: stderr=\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    (wall, cpu_after.saturating_sub(cpu_before))
}

// ---- format spec ------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq)]
enum Shape {
    /// Single-stream decoder; output is a single file
    /// ([`PeelLocalOut::File`]).
    Raw,
    /// Tar-wrapping decoder; output is a directory tree
    /// ([`PeelLocalOut::Dir`]).
    Tar,
    /// Identity (no compression); output is a directory tree.
    Identity,
    /// Random-access container (zip / 7z / rar). Output is a
    /// directory tree; the encoder takes the named entry list
    /// directly rather than a single byte buffer. Peel's local
    /// path routes these through the per-format pipelines
    /// (`internal/old/PLAN_local_file_extract.md` §2 step 5).
    Container,
}

/// Inputs available to a fixture encoder. Streaming encoders use
/// `raw_payload`; tar-wrapped encoders use `tar_archive` (the same
/// bytes for `Identity`); container encoders use `entries` (and, for
/// cached fixtures like rar5/rar3, `payload_bytes` as the cache key).
struct FixtureInput<'a> {
    raw_payload: &'a [u8],
    tar_archive: &'a [u8],
    entries: &'a [(String, Vec<u8>)],
    /// Cache key for size-indexed fixture caches (rar5/rar3). Only
    /// read when the `rar` feature is on; without it the field
    /// exists so [`build_fixture`] can populate one shape of input
    /// regardless of feature config.
    #[cfg_attr(not(feature = "rar"), allow(dead_code))]
    payload_bytes: usize,
}

type FixtureEncoder = Box<dyn Fn(&FixtureInput<'_>) -> Vec<u8>>;

/// One row in the bench grid. `ref_tools` is the human-readable
/// reference-CLI label printed alongside the row; `ref_required` is
/// the list of tool binaries that must all be on `PATH` for the row
/// to run. `ref_pipeline` is the bash one-liner; it sees `$SRC`
/// (the on-disk fixture path) and `$DST` (a fresh empty directory
/// or output file path; the helper picks based on `shape`) in its
/// environment.
struct FormatSpec {
    label: &'static str,
    shape: Shape,
    ext: &'static str,
    /// Encoder for the on-disk fixture. Receives [`FixtureInput`]
    /// and returns the compressed bytes that will be written to
    /// `<tmp>/<label>.<ext>`. The closure picks which input fields
    /// it needs based on `shape`.
    encode: FixtureEncoder,
    /// Human-readable reference-tool name (e.g. `"zstd|tar"`).
    ref_tools: String,
    /// Tool binaries to probe via `command -v` before running.
    /// Use an absolute path (e.g. for the licensed `unrar`) when
    /// the binary is not on `PATH`; the bench's `tool_present`
    /// helper accepts both.
    ref_required: Vec<String>,
    /// Bash one-liner. `$SRC` is the fixture path; `$DST` is the
    /// destination path (file for `Raw`, directory for
    /// `Tar`/`Identity`/`Container`).
    ref_pipeline: String,
}

/// Build the bench grid format list. Container formats are added
/// dynamically when their fixture-builder dependencies are present
/// (the `rar` Cargo feature for rar5/rar3; the `unrar` binary on
/// PATH or `~/Downloads/rar/unrar`; Docker for the rar3 fixture
/// encoder).
fn formats() -> Vec<FormatSpec> {
    // `mut` only required when the `rar` feature is on; without it
    // the rar5/rar3 push sites are compiled out and the vec is never
    // mutated after construction.
    #[cfg_attr(not(feature = "rar"), allow(unused_mut))]
    let mut v: Vec<FormatSpec> = vec![
        FormatSpec {
            label: "zstd-raw",
            shape: Shape::Raw,
            ext: "zst",
            encode: Box::new(|i| encode_zstd(i.raw_payload)),
            ref_tools: "zstd".into(),
            ref_required: vec!["zstd".into()],
            ref_pipeline: r#"zstd -d -q -f -o "$DST" "$SRC""#.into(),
        },
        FormatSpec {
            label: "tar.zst",
            shape: Shape::Tar,
            ext: "tar.zst",
            encode: Box::new(|i| encode_zstd(i.tar_archive)),
            ref_tools: "zstd|tar".into(),
            ref_required: vec!["zstd".into(), "tar".into()],
            ref_pipeline: r#"zstd -dc -q "$SRC" | tar -xf - -C "$DST""#.into(),
        },
        FormatSpec {
            label: "xz-raw",
            shape: Shape::Raw,
            ext: "xz",
            encode: Box::new(|i| encode_xz(i.raw_payload)),
            ref_tools: "xz".into(),
            ref_required: vec!["xz".into()],
            ref_pipeline: r#"xz -dc -q "$SRC" > "$DST""#.into(),
        },
        FormatSpec {
            label: "tar.xz",
            shape: Shape::Tar,
            ext: "tar.xz",
            encode: Box::new(|i| encode_xz(i.tar_archive)),
            ref_tools: "xz|tar".into(),
            ref_required: vec!["xz".into(), "tar".into()],
            ref_pipeline: r#"xz -dc -q "$SRC" | tar -xf - -C "$DST""#.into(),
        },
        FormatSpec {
            label: "gz-raw",
            shape: Shape::Raw,
            ext: "gz",
            encode: Box::new(|i| encode_gzip(i.raw_payload)),
            ref_tools: "gzip".into(),
            ref_required: vec!["gzip".into()],
            ref_pipeline: r#"gzip -dc -q "$SRC" > "$DST""#.into(),
        },
        FormatSpec {
            label: "tar.gz",
            shape: Shape::Tar,
            ext: "tar.gz",
            encode: Box::new(|i| encode_gzip(i.tar_archive)),
            ref_tools: "gzip|tar".into(),
            ref_required: vec!["gzip".into(), "tar".into()],
            ref_pipeline: r#"gzip -dc -q "$SRC" | tar -xf - -C "$DST""#.into(),
        },
        FormatSpec {
            label: "lz4-raw",
            shape: Shape::Raw,
            ext: "lz4",
            encode: Box::new(|i| encode_lz4_uncompressed_frame(i.raw_payload)),
            ref_tools: "lz4".into(),
            ref_required: vec!["lz4".into()],
            ref_pipeline: r#"lz4 -dc -q "$SRC" > "$DST""#.into(),
        },
        FormatSpec {
            label: "tar.lz4",
            shape: Shape::Tar,
            ext: "tar.lz4",
            encode: Box::new(|i| encode_lz4_uncompressed_frame(i.tar_archive)),
            ref_tools: "lz4|tar".into(),
            ref_required: vec!["lz4".into(), "tar".into()],
            ref_pipeline: r#"lz4 -dc -q "$SRC" | tar -xf - -C "$DST""#.into(),
        },
        FormatSpec {
            label: "tar",
            shape: Shape::Identity,
            ext: "tar",
            encode: Box::new(|i| i.tar_archive.to_vec()),
            ref_tools: "tar".into(),
            ref_required: vec!["tar".into()],
            ref_pipeline: r#"tar -xf "$SRC" -C "$DST""#.into(),
        },
        // ---- random-access containers --------------------------------
        // ZIP. STORED entries — the bench measures the central
        // directory scan + per-entry write loop, not codec work,
        // matching the streaming bench's incompressible-payload
        // shape.
        FormatSpec {
            label: "zip",
            shape: Shape::Container,
            ext: "zip",
            encode: Box::new(|i| {
                let specs: Vec<ZipEntrySpec> = i
                    .entries
                    .iter()
                    .map(|(n, b)| ZipEntrySpec::stored(n.clone(), b.clone()))
                    .collect();
                build_zip(&specs)
            }),
            ref_tools: "unzip".into(),
            ref_required: vec!["unzip".into()],
            ref_pipeline: r#"unzip -q -o "$SRC" -d "$DST""#.into(),
        },
        // 7z, COPY-coded — same rationale as zip.
        FormatSpec {
            label: "7z",
            shape: Shape::Container,
            ext: "7z",
            encode: Box::new(|i| {
                let pairs: Vec<(&str, Vec<u8>)> = i
                    .entries
                    .iter()
                    .map(|(n, b)| (n.as_str(), b.clone()))
                    .collect();
                build_copy_sevenz(&pairs)
            }),
            ref_tools: "7z".into(),
            ref_required: vec!["7z".into()],
            ref_pipeline: r#"7z x -y -bd -bb0 "$SRC" "-o$DST" >/dev/null"#.into(),
        },
    ];

    // RAR rows (gated on the `rar` feature). Fixtures come from
    // the licensed `rar` 7.22 encoder for rar5 and from `rar 5.0.0`
    // (via Docker) for rar3 — matching the streaming bench so the
    // baseline `unrar` decoder sees the same RAR wire bytes both
    // grids feed it. Each row is skipped when its encoder /
    // baseline binary isn't available.
    #[cfg(feature = "rar")]
    {
        if let Some(unrar) = unrar_path() {
            let unrar_quoted = shell_quote(Path::new(&unrar));
            if rar5_encoder_present() {
                let unrar_q = unrar_quoted.clone();
                v.push(FormatSpec {
                    label: "rar5",
                    shape: Shape::Container,
                    ext: "rar",
                    encode: Box::new(|i| ensure_rar5_stored(i.entries, i.payload_bytes)),
                    ref_tools: "unrar".into(),
                    ref_required: vec![unrar.clone()],
                    // Trailing slash on the destination is required
                    // for `unrar x`. Use the resolved binary path so
                    // the licensed `~/Downloads/rar/unrar` works
                    // even when the binary is not on $PATH.
                    ref_pipeline: format!(r#"{unrar} x -inul -y "$SRC" "$DST/""#, unrar = unrar_q,),
                });
            }
            if rar3_encoder_present() {
                v.push(FormatSpec {
                    label: "rar3",
                    shape: Shape::Container,
                    ext: "rar",
                    encode: Box::new(|i| ensure_rar3_stored(i.entries, i.payload_bytes)),
                    ref_tools: "unrar".into(),
                    ref_required: vec![unrar.clone()],
                    ref_pipeline: format!(
                        r#"{unrar} x -inul -y "$SRC" "$DST/""#,
                        unrar = unrar_quoted,
                    ),
                });
            }
        }
    }

    v
}

// ---- grid driver ------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq)]
enum Mode {
    Cold,
    Warm,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Mode::Cold => "cold",
            Mode::Warm => "warm",
        }
    }
}

struct Cell {
    format: String,
    tier: &'static str,
    mode: Mode,
    payload_bytes: u64,
    on_wire_bytes: u64,
    peel_wall: Duration,
    peel_cpu: Duration,
    ref_wall: Duration,
    ref_cpu: Duration,
    ref_tools: String,
}

impl Cell {
    fn ratio(&self) -> f64 {
        let p = self.peel_wall.as_secs_f64();
        let r = self.ref_wall.as_secs_f64();
        if r > 0.0 {
            p / r
        } else {
            0.0
        }
    }

    fn print(&self) {
        println!(
            "[bench] {fmt:<8} {tier:<8} {mode:<4}  payload={mib:6.1} MiB  wire={wire:6.1} MiB  \
             peel={pw:7.3}s cpu={pc:7.3}s  {tools}={rw:7.3}s cpu={rc:7.3}s  ratio={ratio:.2}x",
            fmt = self.format,
            tier = self.tier,
            mode = self.mode.label(),
            mib = (self.payload_bytes as f64) / (1024.0 * 1024.0),
            wire = (self.on_wire_bytes as f64) / (1024.0 * 1024.0),
            pw = self.peel_wall.as_secs_f64(),
            pc = self.peel_cpu.as_secs_f64(),
            tools = self.ref_tools,
            rw = self.ref_wall.as_secs_f64(),
            rc = self.ref_cpu.as_secs_f64(),
            ratio = self.ratio(),
        );
    }
}

fn skip(format: &str, tier: &str, missing: &str) {
    println!("[bench] {format:<8} {tier:<8}  [skip] {missing} not on PATH");
}

/// On-disk fixture for one (format, tier) cell. Built once per
/// cell and reused across cold / warm iterations.
struct Fixture {
    /// Path to the compressed archive on disk.
    source: PathBuf,
    /// Size of the compressed file on disk.
    on_wire_bytes: u64,
    /// Raw decoded bytes — used for `Raw`-shape identity checks.
    payload: Vec<u8>,
    /// Per-file body list — used for `Tar` / `Identity` identity
    /// checks via [`assert_dir_matches`].
    entries: Vec<(String, Vec<u8>)>,
}

/// Build the on-disk fixture for one (format, tier) cell.
fn build_fixture(fmt: &FormatSpec, tier: Tier, dir: &Path) -> Fixture {
    let source = dir.join(format!("fixture.{}", fmt.ext));
    let (raw_payload, entries) = match fmt.shape {
        Shape::Raw => {
            let payload = random_bytes(0xC0FFEE, tier.payload_bytes);
            (payload, Vec::new())
        }
        Shape::Tar | Shape::Identity | Shape::Container => {
            let (archive, entries) = build_tar_payload(tier.payload_bytes, tier.tar_files);
            (archive, entries)
        }
    };
    // For Container formats `raw_payload` is the (unused) tar
    // archive bytes — encoders ignore it; they reach for
    // `entries` instead. The same tar bytes are still useful as
    // the post-decode reference for any future Container row
    // that needs them. `tar_archive` and `raw_payload` differ
    // only for `Raw`-shape rows; for tar-wrapped shapes they
    // alias.
    let tar_archive: &[u8] = match fmt.shape {
        Shape::Raw => &[],
        Shape::Tar | Shape::Identity | Shape::Container => &raw_payload,
    };
    let input = FixtureInput {
        raw_payload: &raw_payload,
        tar_archive,
        entries: &entries,
        payload_bytes: tier.payload_bytes,
    };
    let body = (fmt.encode)(&input);
    fs::write(&source, &body).expect("write fixture");
    Fixture {
        source,
        on_wire_bytes: body.len() as u64,
        payload: raw_payload,
        entries,
    }
}

/// Run one peel iteration. Picks an output target shape from
/// `fmt.shape`, builds a fresh empty destination in `iter_dir`, runs
/// the local coordinator, and asserts the output matches the
/// pre-encoded payload. Returns `(wall, cpu)`.
fn one_peel_iter(
    fmt: &FormatSpec,
    source: &Path,
    payload: &[u8],
    entries: &[(String, Vec<u8>)],
    iter_dir: &Path,
) -> (Duration, Duration) {
    match fmt.shape {
        Shape::Raw => {
            let out = iter_dir.join("decoded.bin");
            let (wall, cpu) = run_peel_local(source, PeelLocalOut::File(out.clone()));
            assert_file_matches(&out, payload);
            (wall, cpu)
        }
        Shape::Tar | Shape::Identity | Shape::Container => {
            let out = iter_dir.join("out");
            fs::create_dir_all(&out).expect("mkdir peel out");
            let (wall, cpu) = run_peel_local(source, PeelLocalOut::Dir(out.clone()));
            assert_dir_matches(&out, entries);
            (wall, cpu)
        }
    }
}

/// Run one reference-CLI iteration. Same shape as
/// [`one_peel_iter`]: builds a fresh destination, runs the bash
/// pipeline, asserts output identity, returns `(wall, cpu)`.
fn one_ref_iter(
    fmt: &FormatSpec,
    source: &Path,
    payload: &[u8],
    entries: &[(String, Vec<u8>)],
    iter_dir: &Path,
) -> (Duration, Duration) {
    let dst: PathBuf;
    let pipeline: String;
    match fmt.shape {
        Shape::Raw => {
            dst = iter_dir.join("decoded.bin");
            pipeline = fmt
                .ref_pipeline
                .replace("\"$DST\"", &shell_quote(&dst))
                .replace("\"$SRC\"", &shell_quote(source));
        }
        Shape::Tar | Shape::Identity | Shape::Container => {
            dst = iter_dir.join("out");
            fs::create_dir_all(&dst).expect("mkdir ref out");
            // Some pipelines (e.g. `7z x -o<DIR>`) embed the
            // destination as a bare-token argument rather than a
            // `"$DST"` placeholder, so we substitute the
            // unquoted form too.
            pipeline = fmt
                .ref_pipeline
                .replace("\"$DST\"", &shell_quote(&dst))
                .replace("$DST", &dst.display().to_string())
                .replace("\"$SRC\"", &shell_quote(source))
                .replace("$SRC", &source.display().to_string());
        }
    }
    let (wall, cpu) = run_ref_pipeline(&pipeline, source);
    match fmt.shape {
        Shape::Raw => assert_file_matches(&dst, payload),
        Shape::Tar | Shape::Identity | Shape::Container => assert_dir_matches(&dst, entries),
    }
    (wall, cpu)
}

/// Run one (format, tier) cell across both Cold and Warm modes,
/// appending to `out`.
///
/// Cold = one fresh run each side. Warm = a throw-away warm-up run
/// followed by the timed run (see
/// `internal/old/PLAN_decoder_throughput_vs_cli.md` §3 step 1; we follow
/// the plan's "run the decoder twice, drop the first" simplification
/// rather than running a full N-sample median, which materially
/// inflates wall-clock cost on the 1 GiB tier with no signal gain
/// at this resolution).
fn run_cell(fmt: &FormatSpec, tier: Tier, out: &mut Vec<Cell>) {
    for tool in &fmt.ref_required {
        if !tool_present(tool) {
            skip(fmt.label, tier.label, tool);
            return;
        }
    }
    let cell_dir = unique_dir(&format!(
        "{}_{}",
        fmt.label.replace('.', "_"),
        tier.label.replace(' ', "")
    ));
    let _g = CleanupDir(cell_dir.clone());
    let fixture = build_fixture(fmt, tier, &cell_dir);

    // Cold: a single fresh run per side.
    let peel_cold_dir = cell_dir.join("peel_cold");
    fs::create_dir_all(&peel_cold_dir).expect("mkdir peel cold");
    let (peel_w_cold, peel_c_cold) = one_peel_iter(
        fmt,
        &fixture.source,
        &fixture.payload,
        &fixture.entries,
        &peel_cold_dir,
    );
    let ref_cold_dir = cell_dir.join("ref_cold");
    fs::create_dir_all(&ref_cold_dir).expect("mkdir ref cold");
    let (ref_w_cold, ref_c_cold) = one_ref_iter(
        fmt,
        &fixture.source,
        &fixture.payload,
        &fixture.entries,
        &ref_cold_dir,
    );
    out.push(Cell {
        format: fmt.label.to_string(),
        tier: tier.label,
        mode: Mode::Cold,
        payload_bytes: fixture.payload.len() as u64,
        on_wire_bytes: fixture.on_wire_bytes,
        peel_wall: peel_w_cold,
        peel_cpu: peel_c_cold,
        ref_wall: ref_w_cold,
        ref_cpu: ref_c_cold,
        ref_tools: fmt.ref_tools.clone(),
    });

    // Warm: discard one warm-up run, then time. The cold runs above
    // *also* primed the OS file cache (we don't flush page cache
    // between cold and warm — that would require root) but the
    // warm-up run additionally exercises peel's allocator pools and
    // the reference CLI's `dlopen`'d codec library on the same
    // process-startup path as the timed iteration.
    let peel_warmup_dir = cell_dir.join("peel_warmup");
    fs::create_dir_all(&peel_warmup_dir).expect("mkdir peel warmup");
    let _ = one_peel_iter(
        fmt,
        &fixture.source,
        &fixture.payload,
        &fixture.entries,
        &peel_warmup_dir,
    );
    let peel_warm_dir = cell_dir.join("peel_warm");
    fs::create_dir_all(&peel_warm_dir).expect("mkdir peel warm");
    let (peel_w_warm, peel_c_warm) = one_peel_iter(
        fmt,
        &fixture.source,
        &fixture.payload,
        &fixture.entries,
        &peel_warm_dir,
    );
    let ref_warmup_dir = cell_dir.join("ref_warmup");
    fs::create_dir_all(&ref_warmup_dir).expect("mkdir ref warmup");
    let _ = one_ref_iter(
        fmt,
        &fixture.source,
        &fixture.payload,
        &fixture.entries,
        &ref_warmup_dir,
    );
    let ref_warm_dir = cell_dir.join("ref_warm");
    fs::create_dir_all(&ref_warm_dir).expect("mkdir ref warm");
    let (ref_w_warm, ref_c_warm) = one_ref_iter(
        fmt,
        &fixture.source,
        &fixture.payload,
        &fixture.entries,
        &ref_warm_dir,
    );
    out.push(Cell {
        format: fmt.label.to_string(),
        tier: tier.label,
        mode: Mode::Warm,
        payload_bytes: fixture.payload.len() as u64,
        on_wire_bytes: fixture.on_wire_bytes,
        peel_wall: peel_w_warm,
        peel_cpu: peel_c_warm,
        ref_wall: ref_w_warm,
        ref_cpu: ref_c_warm,
        ref_tools: fmt.ref_tools.clone(),
    });
}

/// Geometric-mean ratio across `cells`. Plan §1 step 4 calls for a
/// single "are we ahead overall?" number; geometric mean is the
/// right aggregator for ratios because it weights "2x slower" and
/// "2x faster" symmetrically (arithmetic mean would not).
fn geometric_mean(cells: &[&Cell]) -> f64 {
    if cells.is_empty() {
        return 0.0;
    }
    let mut log_sum = 0.0_f64;
    let mut n = 0usize;
    for c in cells {
        let r = c.ratio();
        if r > 0.0 {
            log_sum += r.ln();
            n += 1;
        }
    }
    if n == 0 {
        return 0.0;
    }
    (log_sum / n as f64).exp()
}

/// Print the medium-tier warm-cache summary `internal/old/PLAN_decoder_throughput_vs_cli.md` §5
/// will consume: one line per format, plus a final geometric-mean
/// row. This is the "ranking" deliverable — the row with the
/// highest ratio is the optimisation target.
fn print_summary(cells: &[Cell]) {
    let key_rows: Vec<&Cell> = cells
        .iter()
        .filter(|c| c.tier == TIER_MEDIUM.label && c.mode == Mode::Warm)
        .collect();
    if key_rows.is_empty() {
        return;
    }
    println!("\n[summary] medium-tier, warm-cache — peel/ref wall ratio (lower = peel faster)");
    let mut sorted: Vec<&Cell> = key_rows.to_vec();
    sorted.sort_by(|a, b| {
        a.ratio()
            .partial_cmp(&b.ratio())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    for c in &sorted {
        println!(
            "[summary] {fmt:<8}  ratio={r:.2}x  ({peel:.3}s vs {refw:.3}s {tools})",
            fmt = c.format,
            r = c.ratio(),
            peel = c.peel_wall.as_secs_f64(),
            refw = c.ref_wall.as_secs_f64(),
            tools = c.ref_tools,
        );
    }
    let gm = geometric_mean(&key_rows);
    println!(
        "[summary] geomean   ratio={gm:.2}x  (across {} formats)",
        key_rows.len()
    );
}

// ---- the entry point --------------------------------------------------

#[test]
#[ignore = "benchmark; opt-in via --ignored"]
fn bench_decode_local_grid() {
    print_host_banner();
    let tiers = pick_tiers();
    let format_list = formats();
    warmup_binaries(&format_list);
    let mut cells: Vec<Cell> = Vec::with_capacity(format_list.len() * tiers.len() * 2);
    for &tier in &tiers {
        for fmt in &format_list {
            run_cell(fmt, tier, &mut cells);
        }
    }
    for c in &cells {
        c.print();
    }
    print_summary(&cells);
}

/// Page-cache prime for `peel` and every reference CLI tool the grid
/// will invoke. Without this, the first cell of the first tier
/// (typically `zstd-raw 10 MiB cold`) pays the full dyld + demand-
/// paging cost of first-invocation on this test process — the
/// `peel` binary's text pages, the codec library's initializers,
/// and the reference tool's startup — while every subsequent cold
/// row finds those pages already resident. That outlier dwarfs the
/// 10 MiB row's actual decoder work and produces a wall-clock ratio
/// (32× in early grids) that says nothing about decoder performance.
///
/// One full peel + reference iteration per format on a [`TIER_SMALL`]
/// fixture is sufficient: it exercises every binary the timed grid
/// will load, plus the per-format codec library, and primes the rar
/// fixture caches so the timed pass doesn't pay re-encode cost
/// either. Container rows missing their reference binary (e.g.
/// `unrar`) are skipped — same gating as [`run_cell`].
fn warmup_binaries(formats: &[FormatSpec]) {
    println!("[warmup] priming page cache for peel + reference CLIs ...");
    let warmup_dir = unique_dir("warmup");
    let _g = CleanupDir(warmup_dir.clone());
    for fmt in formats {
        if fmt.ref_required.iter().any(|t| !tool_present(t)) {
            continue;
        }
        let cell_dir = warmup_dir.join(fmt.label.replace('.', "_"));
        fs::create_dir_all(&cell_dir).expect("mkdir warmup cell");
        let fixture = build_fixture(fmt, TIER_SMALL, &cell_dir);
        let peel_dir = cell_dir.join("peel");
        fs::create_dir_all(&peel_dir).expect("mkdir peel warmup");
        let _ = one_peel_iter(
            fmt,
            &fixture.source,
            &fixture.payload,
            &fixture.entries,
            &peel_dir,
        );
        let ref_dir = cell_dir.join("ref");
        fs::create_dir_all(&ref_dir).expect("mkdir ref warmup");
        let _ = one_ref_iter(
            fmt,
            &fixture.source,
            &fixture.payload,
            &fixture.entries,
            &ref_dir,
        );
    }
    println!("[warmup] done");
}

/// One-time banner describing the host so the printed grid is
/// reproducible (`internal/old/PLAN_decoder_throughput_vs_cli.md` §"Hard
/// constraints": "every run records the host CPU, kernel, and tool
/// versions"). Best-effort: missing commands surface as `<unknown>`
/// rather than failing the run.
fn print_host_banner() {
    fn first_line(cmd: &str, args: &[&str]) -> String {
        let out = Command::new(cmd)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();
        match out {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string(),
            _ => "<unknown>".to_string(),
        }
    }
    println!("[host] os={}", std::env::consts::OS);
    println!("[host] arch={}", std::env::consts::ARCH);
    println!("[host] uname={}", first_line("uname", &["-a"]));
    println!("[host] zstd={}", first_line("zstd", &["--version"]));
    println!("[host] xz={}", first_line("xz", &["--version"]));
    println!("[host] gzip={}", first_line("gzip", &["--version"]));
    println!("[host] lz4={}", first_line("lz4", &["--version"]));
    println!("[host] tar={}", first_line("tar", &["--version"]));
    println!(
        "[host] peel={}, profile={}",
        env!("CARGO_PKG_VERSION"),
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
}
