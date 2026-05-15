//! Integration tests for [`peel::punch`].
//!
//! On Linux these exercise the real
//! `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)` syscall, on
//! macOS the real `fcntl(F_PUNCHHOLE)` syscall, against a 4 MiB
//! sparse-friendly file in the platform temp directory. If the
//! underlying filesystem doesn't support punching (NFS, FAT, HFS+,
//! certain FUSE mounts), the [`PunchError::Unsupported`] response is
//! treated as a skip rather than a failure.
//!
//! On every other Unix platform [`peel::punch::default_puncher`] returns
//! a [`peel::punch::NoopPuncher`] and the end-to-end flow is reduced to
//! a smoke test that proves the trait dispatch works.

#![cfg(unix)]

use std::fs::OpenOptions;
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use peel::punch::PunchHole;
use peel::punch::{align_down, default_puncher, PunchError};
use peel::types::ByteOffset;

const FOUR_MIB: u64 = 4 * 1024 * 1024;

/// Process-unique counter so concurrent test threads cannot collide on
/// the synthesized temp-file name.
static UNIQ: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(label: &str) -> PathBuf {
    let pid = std::process::id();
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("peel_punch_{label}_{pid}_{nanos}_{n}.bin"))
}

/// Drops cleanly remove the file even when the test panics.
struct CleanupOnDrop(PathBuf);
impl Drop for CleanupOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Create a file at `path` containing `size` bytes of non-zero data and
/// fsync it so the on-disk block count reflects the writes.
fn create_dense_file(path: &Path, size: u64) -> std::fs::File {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .expect("open temp file");
    let chunk = vec![0xAB_u8; 64 * 1024];
    let mut remaining = size;
    while remaining > 0 {
        let n = remaining.min(chunk.len() as u64) as usize;
        file.write_all(&chunk[..n]).expect("write chunk");
        remaining -= n as u64;
    }
    file.sync_all().expect("fsync");
    file
}

#[test]
fn align_down_aligns_to_block_size_hint() {
    let p = default_puncher();
    let block = p.block_size_hint();
    let aligned = align_down(8195, block).expect("non-zero alignment");
    assert_eq!(aligned % block, 0);
    assert!(aligned <= 8195);
}

#[test]
fn default_puncher_round_trips_a_zero_length_punch() {
    // A zero-length punch must succeed everywhere without touching the
    // file. This is the trivial path callers can use to test wiring.
    let path = unique_temp_path("zero_len");
    let _cleanup = CleanupOnDrop(path.clone());
    let file = create_dense_file(&path, 64 * 1024);

    let p = default_puncher();
    p.punch(file.as_fd(), ByteOffset::ZERO, 0)
        .expect("zero-length punch must succeed");

    let meta = file.metadata().expect("metadata");
    assert_eq!(meta.len(), 64 * 1024, "logical size unchanged");
}

#[test]
fn punch_preserves_logical_size_and_never_grows_blocks() {
    // Universal invariant: a punch must never shrink the logical file
    // and must never *increase* the on-disk block count. On Linux+ext4
    // it should also strictly decrease blocks; that stronger assertion
    // lives in the linux-only test below.
    let path = unique_temp_path("preserve_size");
    let _cleanup = CleanupOnDrop(path.clone());
    let file = create_dense_file(&path, FOUR_MIB);

    let blocks_before = file.metadata().expect("metadata").blocks();
    let size_before = file.metadata().expect("metadata").len();
    assert_eq!(size_before, FOUR_MIB);

    let puncher = default_puncher();
    let block = puncher.block_size_hint();
    let offset = align_down(0, block).expect("non-zero alignment");

    match puncher.punch(file.as_fd(), ByteOffset::new(offset), FOUR_MIB) {
        Ok(()) => {
            let meta_after = file.metadata().expect("metadata");
            assert_eq!(meta_after.len(), size_before, "logical size preserved");
            assert!(
                meta_after.blocks() <= blocks_before,
                "blocks must not grow (before={}, after={})",
                blocks_before,
                meta_after.blocks()
            );
        }
        Err(PunchError::Unsupported { .. }) => {
            // The host filesystem can't punch (NFS, FAT, some FUSE
            // mounts). The plan §2.4 specifies this is a skip, not a
            // failure.
        }
        Err(other) => panic!("unexpected punch error: {other}"),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_punch_releases_blocks_when_supported() {
    use peel::punch::LinuxPuncher;

    let path = unique_temp_path("linux_release");
    let _cleanup = CleanupOnDrop(path.clone());
    let file = create_dense_file(&path, FOUR_MIB);

    let blocks_before = file.metadata().expect("metadata").blocks();
    let size_before = file.metadata().expect("metadata").len();

    // Sanity: a freshly-written 4 MiB dense file should hold non-trivial
    // disk blocks. If this fails, the host fs is doing something exotic
    // and the rest of the test is meaningless.
    assert!(
        blocks_before >= FOUR_MIB / 4096,
        "expected dense file to occupy real blocks (got {blocks_before})"
    );

    let puncher = LinuxPuncher::new();
    match puncher.punch(file.as_fd(), ByteOffset::ZERO, FOUR_MIB) {
        Ok(()) => {
            let meta_after = file.metadata().expect("metadata");
            assert_eq!(meta_after.len(), size_before, "logical size preserved");
            assert!(
                meta_after.blocks() < blocks_before,
                "expected block count to decrease (before={}, after={})",
                blocks_before,
                meta_after.blocks()
            );
        }
        Err(PunchError::Unsupported { .. }) => {
            // Acceptable on filesystems that reject the operation.
        }
        Err(other) => panic!("unexpected error from LinuxPuncher: {other}"),
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_puncher_block_size_hint_matches_system_page_size() {
    use peel::punch::LinuxPuncher;
    let hint = LinuxPuncher::new().block_size_hint();
    // The hint must be a power of two ≥ 4 KiB and ≤ 1 MiB. On
    // conventional kernels (most x86_64, aarch64 4k builds) this is
    // 4096; on 16 KiB-page kernels (Apple Silicon Asahi `+16k`,
    // some POWER builds) it is 16384. Anything else would break the
    // extractor's `align_down(quiescent_at, block)` punch-range
    // computation against the kernel's actual alignment rules.
    assert!(hint.is_power_of_two(), "hint {hint} is not a power of two");
    assert!(hint >= 4096, "hint {hint} below 4 KiB minimum");
    assert!(hint <= 1 << 20, "hint {hint} above 1 MiB sanity bound");
    // Cross-check against `sysconf(_SC_PAGESIZE)` via the `getconf`
    // CLI so a future refactor that hard-codes a wrong value (the
    // original 4096) is caught even on 4 KiB-page hosts. Falls back
    // to a no-op assertion if `getconf` is unavailable.
    if let Ok(output) = std::process::Command::new("getconf")
        .arg("PAGESIZE")
        .output()
    {
        if output.status.success() {
            let reported: u64 = String::from_utf8_lossy(&output.stdout)
                .trim()
                .parse()
                .expect("getconf PAGESIZE returned non-integer");
            assert_eq!(
                hint, reported,
                "block_size_hint {hint} disagrees with sysconf(_SC_PAGESIZE) {reported}",
            );
        }
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_punch_releases_blocks_when_supported() {
    use peel::punch::MacosPuncher;

    let path = unique_temp_path("macos_release");
    let _cleanup = CleanupOnDrop(path.clone());
    let file = create_dense_file(&path, FOUR_MIB);

    let blocks_before = file.metadata().expect("metadata").blocks();
    let size_before = file.metadata().expect("metadata").len();

    // Sanity: a freshly-written 4 MiB dense file should hold non-trivial
    // disk blocks. If this fails, the host fs is doing something exotic
    // (a memory-only sandbox, perhaps) and the rest of the test is
    // meaningless.
    assert!(
        blocks_before >= FOUR_MIB / 4096,
        "expected dense file to occupy real blocks (got {blocks_before})"
    );

    let puncher = MacosPuncher::new();
    match puncher.punch(file.as_fd(), ByteOffset::ZERO, FOUR_MIB) {
        Ok(()) => {
            let meta_after = file.metadata().expect("metadata");
            assert_eq!(meta_after.len(), size_before, "logical size preserved");
            assert!(
                meta_after.blocks() < blocks_before,
                "expected block count to decrease (before={}, after={})",
                blocks_before,
                meta_after.blocks()
            );
        }
        Err(PunchError::Unsupported { .. }) => {
            // Acceptable on volumes that reject the operation (HFS+,
            // FAT, network shares, certain FUSE mounts). Modern macOS
            // boots from APFS, so this branch should be rare on CI.
        }
        Err(other) => panic!("unexpected error from MacosPuncher: {other}"),
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_puncher_block_size_hint_is_4096() {
    use peel::punch::MacosPuncher;
    assert_eq!(MacosPuncher::new().block_size_hint(), 4096);
}
