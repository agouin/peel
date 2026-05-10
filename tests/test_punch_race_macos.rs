//! Micro-bench characterizing the macOS `fcntl(F_PUNCHHOLE)` EINVAL race.
//!
//! Reproduces — without the full coordinator/RAR pipeline — the timing
//! window first observed in `tests/test_coordinator_rar.rs::
//! crash_resume_mid_entry_produces_identical_output` after the §F1
//! checkpoint-format change. See `docs/PLAN_macos_puncher_race.md` for
//! the full hypothesis.
//!
//! Two tests:
//!
//! * [`raw_punch_under_pwrite_contention_observed_einvals`] — issues
//!   a raw `fcntl(F_PUNCHHOLE)` against the head of a file while
//!   worker threads `pwrite` across it. Observational: prints the
//!   EINVAL count for the run. On the original M-series hardware the
//!   `tests/test_coordinator_rar.rs::
//!   crash_resume_mid_entry_produces_identical_output` failure is
//!   deterministic, but a tighter standalone harness has been
//!   observed to print 0 EINVAL — APFS only surfaces the race for
//!   particular file-state / scheduler patterns. We therefore do
//!   *not* require EINVAL>0 here; we use this test as a regression
//!   ceiling and to document the pattern.
//!
//! * [`macos_puncher_under_pwrite_contention_never_einvals`] — same
//!   harness, but routed through [`peel::punch::MacosPuncher`]. Once the
//!   fsync-before-punch + bounded-EINVAL-retry hardening lands, this
//!   test reports zero `Unsupported { errno: 22 }` outcomes across the
//!   full iteration count. Asserts strictly.
//!
//! Both tests are gated `#[cfg(target_os = "macos")]` and tagged
//! `#[ignore]`. They depend on real APFS storage (system temp dir),
//! they're noisier than typical unit tests, and they hold real worker
//! threads for ~1 s. Run them with
//! `cargo test --features rar --test test_punch_race_macos -- --ignored`.

#![cfg(target_os = "macos")]

use std::fs::OpenOptions;
use std::os::fd::{AsFd, AsRawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use peel::punch::{MacosPuncher, PunchError, PunchHole};
use peel::types::ByteOffset;

// ---- Shared scaffolding ----------------------------------------------

/// Total file size used by both tests. The failing crash-resume RAR
/// test punches a range that the download workers were actively
/// `pwrite`ing, so the harness lets workers cover the entire file.
const FILE_SIZE: u64 = 8 * 1024 * 1024;
/// Punch range — head half of the file, page-aligned.
const PUNCH_OFFSET: u64 = 4096;
/// Length of each punch. Fully inside the head half.
const PUNCH_LENGTH: u64 = 4 * 1024 * 1024 - 4096;
/// Workers `pwrite` across the full file (head half = punch range,
/// tail half = unrelated). This mirrors the failing test's flow,
/// where download workers' write range overlaps with the punch range.
const PWRITE_BASE: u64 = 0;
/// Upper bound (exclusive) for worker `pwrite`s.
const PWRITE_END: u64 = FILE_SIZE;
/// Worker `pwrite` chunk size. Matches the coordinator's chunk size for
/// the failing crash-resume test.
const PWRITE_CHUNK: usize = 64 * 1024;
/// Number of workers banging on the file. The failing test uses 2.
const WORKERS: usize = 2;
/// Iterations of the main-thread punch loop. Plan target: 1000.
const ITERATIONS: u32 = 1024;

extern "C" {
    /// `ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset)`.
    /// Declared by hand here — the project's dependency policy bars `libc`
    /// (`docs/ENGINEERING_STANDARDS.md` §2.2). Darwin uses 64-bit `off_t`
    /// unconditionally on 64-bit targets.
    fn pwrite(fd: i32, buf: *const u8, count: usize, offset: i64) -> isize;
}

/// Process-unique counter so concurrent `cargo test` threads cannot
/// collide on the synthesized temp-file name.
static UNIQ: AtomicU64 = AtomicU64::new(0);

fn unique_temp_path(label: &str) -> PathBuf {
    let pid = std::process::id();
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("peel_punch_race_{label}_{pid}_{nanos}_{n}.bin"))
}

struct CleanupOnDrop(PathBuf);
impl Drop for CleanupOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Create an 8 MiB file with the head half prewritten (blocks
/// allocated, then synced so they aren't already dirty when the
/// experiment starts). The failing crash-resume test punches a range
/// that the download workers had just `pwrite`-filled, so the file's
/// state at punch time is "blocks exist, possibly dirty pages
/// somewhere", not pure sparse. Prewriting + syncing the punch range
/// gives us the same starting condition.
fn fresh_target_file(label: &str) -> (std::fs::File, CleanupOnDrop) {
    let path = unique_temp_path(label);
    let cleanup = CleanupOnDrop(path.clone());
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .expect("open temp file");
    file.set_len(FILE_SIZE).expect("set_len");

    // Prewrite the punch range so the first punch has real blocks to
    // release. Without this the first iterations would be no-ops on a
    // fully sparse file. Deliberately do NOT fsync — leaving the
    // punch range's pages dirty mirrors the failing test's resume
    // flow, where the download workers had recently `pwrite`-filled
    // the punch range and there's no fsync between the last write
    // and the punch.
    let buf = vec![0xCD_u8; PWRITE_CHUNK];
    let fd = file.as_raw_fd();
    let prewrite_end = PUNCH_OFFSET + PUNCH_LENGTH;
    let mut off = PUNCH_OFFSET;
    while off < prewrite_end {
        let chunk = (prewrite_end - off).min(PWRITE_CHUNK as u64) as usize;
        // SAFETY: `fd` is owned by `file` (alive across this loop).
        // `buf` is a `PWRITE_CHUNK`-byte stack vec, valid for `chunk`
        // bytes (chunk <= PWRITE_CHUNK). `off` is bounded by
        // `prewrite_end` < `i64::MAX`.
        let rc = unsafe {
            pwrite(
                fd,
                buf.as_ptr(),
                chunk,
                i64::try_from(off).expect("offset fits i64"),
            )
        };
        assert!(
            rc >= 0,
            "prewrite failed: {}",
            std::io::Error::last_os_error()
        );
        off += chunk as u64;
    }

    (file, cleanup)
}

/// Spawn `WORKERS` threads that loop `pwrite`ing 64 KiB chunks into the
/// tail half of `file` until `stop` is set. Returns the join handles so
/// the caller can join them after stopping.
fn spawn_pwrite_workers(
    file: &Arc<std::fs::File>,
    stop: Arc<AtomicBool>,
) -> Vec<thread::JoinHandle<u64>> {
    (0..WORKERS)
        .map(|w| {
            let file = Arc::clone(file);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                let buf = vec![0xAB_u8; PWRITE_CHUNK];
                let fd = file.as_raw_fd();
                let mut local_off = PWRITE_BASE + (w as u64) * PWRITE_CHUNK as u64;
                let stride = PWRITE_CHUNK as u64 * WORKERS as u64;
                let mut writes = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    // SAFETY: `fd` is owned by the `Arc<File>`, which the
                    // caller keeps alive for the worker's lifetime. `buf`
                    // is a stack-living `Vec<u8>` of length `PWRITE_CHUNK`,
                    // valid for reads of that many bytes. `local_off`
                    // rolls within `[PWRITE_BASE, PWRITE_END)`, well
                    // below `i64::MAX`.
                    let rc = unsafe {
                        pwrite(
                            fd,
                            buf.as_ptr(),
                            PWRITE_CHUNK,
                            i64::try_from(local_off).expect("offset fits i64"),
                        )
                    };
                    assert!(
                        rc >= 0,
                        "worker pwrite failed: {}",
                        std::io::Error::last_os_error()
                    );
                    writes += 1;
                    local_off += stride;
                    if local_off + PWRITE_CHUNK as u64 > PWRITE_END {
                        local_off = PWRITE_BASE + (w as u64) * PWRITE_CHUNK as u64;
                    }
                }
                writes
            })
        })
        .collect()
}

// ---- Raw-syscall reproducer -----------------------------------------

/// Darwin `fcntl` constants and FFI shim duplicated here so the test
/// can call the syscall without going through `MacosPuncher` (which is
/// what we are about to harden). Keeping the shim local to the test
/// also prevents accidental test-only API surface in `src/punch.rs`.
mod raw {
    pub const F_PUNCHHOLE: i32 = 99;

    #[repr(C)]
    pub struct Fpunchhole {
        pub fp_flags: u32,
        pub fp_offset: i64,
        pub fp_length: i64,
    }

    extern "C" {
        pub fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    }
}

#[test]
#[ignore]
fn raw_punch_under_pwrite_contention_observed_einvals() {
    let (file, _cleanup) = fresh_target_file("raw");
    let file = Arc::new(file);
    let stop = Arc::new(AtomicBool::new(false));
    let workers = spawn_pwrite_workers(&file, Arc::clone(&stop));

    let mut einval_count = 0u32;
    let mut other_err_count = 0u32;
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let mut arg = raw::Fpunchhole {
            fp_flags: 0,
            fp_offset: i64::try_from(PUNCH_OFFSET).expect("offset fits i64"),
            fp_length: i64::try_from(PUNCH_LENGTH).expect("length fits i64"),
        };
        // SAFETY: `file` is kept alive by the Arc. `arg` is a stack-local
        // `#[repr(C)]` value matching Darwin's `fpunchhole_t`. `fcntl`
        // returns an `int`; on error we read `errno` via
        // `std::io::Error::last_os_error`.
        let rc = unsafe {
            raw::fcntl(
                file.as_fd().as_raw_fd(),
                raw::F_PUNCHHOLE,
                &mut arg as *mut raw::Fpunchhole,
            )
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(22) => einval_count += 1,
                _ => other_err_count += 1,
            }
        }
    }
    let elapsed = start.elapsed();
    stop.store(true, Ordering::Release);
    let total_writes: u64 = workers
        .into_iter()
        .map(|j| j.join().expect("worker join"))
        .sum();

    eprintln!(
        "raw fcntl(F_PUNCHHOLE) under pwrite contention: \
         {einval_count}/{ITERATIONS} EINVAL, {other_err_count} other errors, \
         {total_writes} concurrent pwrites, elapsed {:?}",
        elapsed,
    );
    // Observational only — see the module doc comment. The race fires
    // through the full coordinator/RAR pipeline but not through this
    // tighter harness. We still assert that the only error class
    // observed (if any) is EINVAL, since any other error class would
    // mean the harness itself is mis-built.
    assert_eq!(
        other_err_count, 0,
        "unexpected non-EINVAL errors from raw fcntl"
    );
}

// ---- MacosPuncher post-fix verification ------------------------------

#[test]
#[ignore]
fn macos_puncher_under_pwrite_contention_never_einvals() {
    let (file, _cleanup) = fresh_target_file("hardened");
    let file = Arc::new(file);
    let stop = Arc::new(AtomicBool::new(false));
    let workers = spawn_pwrite_workers(&file, Arc::clone(&stop));

    let puncher = MacosPuncher::new();
    let mut unsupported_count = 0u32;
    let mut io_err_count = 0u32;
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        match puncher.punch(file.as_fd(), ByteOffset::new(PUNCH_OFFSET), PUNCH_LENGTH) {
            Ok(()) => {}
            Err(PunchError::Unsupported { .. }) => unsupported_count += 1,
            Err(_) => io_err_count += 1,
        }
    }
    let elapsed = start.elapsed();
    stop.store(true, Ordering::Release);
    let total_writes: u64 = workers
        .into_iter()
        .map(|j| j.join().expect("worker join"))
        .sum();

    eprintln!(
        "MacosPuncher under pwrite contention: \
         {unsupported_count}/{ITERATIONS} Unsupported, {io_err_count} Io errors, \
         {total_writes} concurrent pwrites, elapsed {:?}",
        elapsed,
    );
    assert_eq!(io_err_count, 0, "unexpected Io errors from MacosPuncher");
    assert_eq!(
        unsupported_count, 0,
        "MacosPuncher must not surface EINVAL/ENOTSUP on APFS under pwrite contention; \
         see docs/PLAN_macos_puncher_race.md"
    );
}

// ---- Sanity-check the harness itself --------------------------------

/// Confirms the harness can finish quickly under contention even when
/// every iteration succeeds. Independent of the race; runs by default
/// so a regression in the harness (deadlock, runaway loop) is caught in
/// `cargo test`.
#[test]
fn harness_completes_under_contention() {
    let (file, _cleanup) = fresh_target_file("harness");
    let file = Arc::new(file);
    let stop = Arc::new(AtomicBool::new(false));
    let workers = spawn_pwrite_workers(&file, Arc::clone(&stop));

    let puncher = MacosPuncher::new();
    let _ = puncher.punch(file.as_fd(), ByteOffset::new(PUNCH_OFFSET), PUNCH_LENGTH);
    // Bound the harness to a few hundred ms even if the puncher returns
    // immediately, so we observe at least one worker `pwrite`.
    thread::sleep(Duration::from_millis(50));
    stop.store(true, Ordering::Release);
    let total_writes: u64 = workers
        .into_iter()
        .map(|j| j.join().expect("worker join"))
        .sum();
    assert!(total_writes > 0, "harness produced no concurrent writes");
}
