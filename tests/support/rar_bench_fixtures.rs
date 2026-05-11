//! On-demand RAR fixture cache for the streaming-bench grids.
//!
//! Bench cells need archives sized to match the throttled grid's
//! payload column (8 / 32 / 128 / 256 MiB). The hand-rolled fixture
//! builders at [`super::rar_fixtures`] are great for unit-testing
//! parser invariants, but `bench_throttled_download_then_extract_grid`
//! pits `peel` against the third-party `unrar` binary — we want
//! archives produced by the *real* RAR encoder so the baseline
//! extractor isn't decoding a peel-specific dialect of the wire format.
//!
//! Two encoder paths land here:
//!
//! - **RAR5 STORED** (`-m0`): native `rar 7.22` at
//!   `~/Downloads/rar/rar`. Apple Silicon-native; encoding is
//!   disk-IO-bound. STORED is also the only method peel's RAR5
//!   pipeline supports today (the hand-rolled compressed-method
//!   decoder lands per `docs/PLAN_rar5_decoder.md`).
//! - **RAR3 LZ Normal** (`-m3` with `-ma4`): `rar 5.0.0` Linux
//!   x86_64 inside a `linux/amd64` Docker container (Apple Silicon
//!   runs the binary through Rosetta). `rar 7.x` dropped the
//!   `-ma4` switch for RAR3 output, so the older binary is the
//!   only on-hand encoder for the legacy format. `-m3` Normal is
//!   the standard RAR3 packing method; peel's `decode::rar_legacy`
//!   pipeline decodes it end-to-end. The bench payload is
//!   LCG-derived (effectively incompressible) so the on-wire
//!   archive size still tracks each rate column's MiB target.
//!
//! Note: the parser also accepts STORED entries with any
//! `unp_ver` (the version field is decorative for `method =
//! STORED`), but the on-disk cache here is RAR3 LZ-Normal so the
//! bench exercises the actual decode pipeline. Flipping the
//! helper to `-m0` STORED on a future bench refresh just means
//! deleting the cached `rar3_stored_*.rar` files and re-baking
//! with the helper pointed at `-m0`.
//!
//! Encoder output lands in [`fixture_dir()`]
//! (`tests/fixtures/rar_bench/`). The `.gitignore` next to the
//! committed `README.md` keeps the byte content out of source
//! control; on a fresh checkout the first bench run re-bakes
//! whichever cells are missing. Subsequent runs read the cached
//! bytes verbatim.
//!
//! Per [`AGENTS.md`](../../AGENTS.md) §"RAR source policy", the
//! encoder binaries here are opaque tools — neither encoder nor
//! decoder source is consulted by peel's RAR pipeline.

#![allow(dead_code)] // Different integration tests use different subsets.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// On-disk root for cached RAR bench archives.
pub fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar_bench")
}

/// Native RAR 7.22 binary on this machine.
fn native_rar() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME set");
    PathBuf::from(home).join("Downloads/rar/rar")
}

/// RAR 5.0.0 Linux x86_64 tarball used inside the Docker container
/// to encode RAR3 (`-ma4`) archives. RAR 7.x no longer supports
/// `-ma4`, so we fall back to the last public release that does.
fn rarlinux_5_tarball() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME set");
    PathBuf::from(home).join("Downloads/rarlinux-x64-5.0.0.tar.gz")
}

/// Returns the cache path for a `(format, size)` cell.
fn cache_path(format: &str, size_bytes: usize) -> PathBuf {
    let mib = size_bytes / (1024 * 1024);
    fixture_dir().join(format!("{format}_stored_{mib}mib.rar"))
}

/// Materialise `entries` as files under `staging/data/` and return
/// the staging root. Caller cleans up when the encoder is done.
fn stage_entries(staging: &Path, entries: &[(String, Vec<u8>)]) {
    let data_dir = staging.join("data");
    fs::create_dir_all(&data_dir).expect("mkdir staging/data");
    for (name, body) in entries {
        let rel = Path::new(name);
        let path = staging.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("mkdir staging entry parent");
        }
        fs::write(&path, body).expect("write staging entry");
    }
}

/// True if the rar5 encoder is available locally.
pub fn rar5_encoder_present() -> bool {
    native_rar().is_file()
}

/// True if the rar3 encoder path is available: Docker on PATH + the
/// rar 5.0.0 Linux tarball in `~/Downloads`.
pub fn rar3_encoder_present() -> bool {
    if !rarlinux_5_tarball().is_file() {
        return false;
    }
    Command::new("sh")
        .arg("-c")
        .arg("command -v docker >/dev/null 2>&1")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// True if the `unrar` baseline binary is reachable. Probes the
/// caller's PATH first, then the known RAR 7.22 install location.
pub fn unrar_path() -> Option<String> {
    if Command::new("sh")
        .arg("-c")
        .arg("command -v unrar >/dev/null 2>&1")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    {
        return Some("unrar".into());
    }
    let home = std::env::var("HOME").ok()?;
    let p = PathBuf::from(home).join("Downloads/rar/unrar");
    if p.is_file() {
        Some(p.to_string_lossy().into_owned())
    } else {
        None
    }
}

/// Encode (or load from cache) a RAR5 STORED archive holding
/// `entries`. The cache key is the requested `size_bytes`, so cells
/// with the same MiB target reuse the same archive.
pub fn ensure_rar5_stored(entries: &[(String, Vec<u8>)], size_bytes: usize) -> Vec<u8> {
    let path = cache_path("rar5", size_bytes);
    if let Ok(bytes) = fs::read(&path) {
        return bytes;
    }
    fs::create_dir_all(path.parent().expect("fixture dir parent"))
        .expect("mkdir fixture dir");

    let staging = tempdir_under("rar5_stage", size_bytes);
    stage_entries(&staging, entries);

    // Pass each file individually (via shell glob expansion) so the
    // archive does not include a `data/` directory entry. rar tags
    // dir entries with `unp_ver = 20` regardless of `-ma5`/`-ma4`,
    // and peel's RAR3 parser gates `unp_ver < 29`. RAR5 is more
    // permissive but we keep the two encoders symmetric.
    let archive_path = staging.join("bundle.rar");
    let entries_glob = "data/file_*.bin";
    let status = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "{} a -ma5 -m0 -inul -y {} {}",
            native_rar().display(),
            archive_path.display(),
            entries_glob,
        ))
        .current_dir(&staging)
        .status()
        .expect("invoke rar 7.22");
    assert!(status.success(), "rar 7.22 encode failed");

    let bytes = fs::read(&archive_path).expect("read rar5 archive");
    fs::write(&path, &bytes).expect("write rar5 cache");
    let _ = fs::remove_dir_all(&staging);
    bytes
}

/// Encode (or load from cache) a RAR3 STORED archive holding
/// `entries`. Uses `rar 5.0.0` Linux x86_64 via Docker because
/// `rar 7.x` no longer supports `-ma4`.
pub fn ensure_rar3_stored(entries: &[(String, Vec<u8>)], size_bytes: usize) -> Vec<u8> {
    let path = cache_path("rar3", size_bytes);
    if let Ok(bytes) = fs::read(&path) {
        return bytes;
    }
    fs::create_dir_all(path.parent().expect("fixture dir parent"))
        .expect("mkdir fixture dir");

    let staging = tempdir_under("rar3_stage", size_bytes);
    stage_entries(&staging, entries);

    // The Docker invocation extracts the encoder tarball inside the
    // bind-mounted work dir, encodes the archive, and exits. We then
    // copy the resulting `bundle.rar` into the cache.
    // `-ma4` forces RAR3/legacy output; `-m3` is the Normal LZ
    // method — RAR3's standard packing path, which exercises
    // peel's `decode::rar_legacy` LZ + RarVM filter pipeline.
    // Files are listed via glob expansion so the archive carries
    // no `data/` directory entry.
    let script = r#"
set -e
tar -xzf /rar.tgz
./rar/rar a -ma4 -m3 -inul -y bundle.rar data/file_*.bin
"#;
    let status = Command::new("docker")
        .arg("run")
        .arg("--rm")
        .arg("--platform")
        .arg("linux/amd64")
        .arg("-v")
        .arg(format!("{}:/work", staging.display()))
        .arg("-v")
        .arg(format!(
            "{}:/rar.tgz:ro",
            rarlinux_5_tarball().display()
        ))
        .arg("-w")
        .arg("/work")
        .arg("debian:bookworm-slim")
        .arg("bash")
        .arg("-c")
        .arg(script)
        .status()
        .expect("invoke docker");
    assert!(status.success(), "rar 5.0.0 docker encode failed");

    let archive_path = staging.join("bundle.rar");
    let bytes = fs::read(&archive_path).expect("read rar3 archive");
    fs::write(&path, &bytes).expect("write rar3 cache");
    let _ = fs::remove_dir_all(&staging);
    bytes
}

/// `$TMPDIR/<label>-<size>-<pid>-<nanos>` — unique enough for
/// parallel bench cells, deterministic-ish in the cleanup branch.
fn tempdir_under(label: &str, size_bytes: usize) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!(
        "peel-{label}-{size_bytes}-{pid}-{nanos}"
    ));
    fs::create_dir_all(&dir).expect("mkdir tempdir_under");
    dir
}
