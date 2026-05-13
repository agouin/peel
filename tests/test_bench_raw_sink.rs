//! Phase 0 anchor bench for [`internal/PLAN_raw_row_throughput.md`].
//!
//! Single-purpose throughput probe for [`peel::sink::RawSink`]. Drives
//! a 256 MiB in-memory payload through the sink one decode-step-sized
//! chunk at a time and prints MiB/s. The bench is parameterised on
//! chunk size so the post-Lever-A comparison (Phase 1) can be made
//! against the same payload size on the same hardware — the relevant
//! gap is per-call syscall pressure, so the chunk size choice drives
//! the result.
//!
//! Two variants run side-by-side. The first variant (the *baseline*)
//! uses today's unbuffered `RawSink`: writes go straight to the
//! underlying `File`, one `write(2)` per call. The second variant
//! (the *post-Lever-A target*) writes go through a 1 MiB
//! `BufWriter<File>` and `flush` on close — what Phase 1 wires into
//! `RawSink` itself. The bench prints both numbers so the same source
//! code shows the expected post-Phase-1 floor and the current ceiling
//! in one run.
//!
//! The bench writes to a real file inside `std::env::temp_dir()`
//! and removes it on drop, so the kernel write-side cost (page-cache
//! copy and dirty-page tracking) is in the measured path. The file
//! is fsync'd once at the end via `close()` so a benchmark that
//! flushes deferred errors at scope exit doesn't get charged
//! differently from one that propagates them inline.
//!
//! # How to run
//!
//! `#[ignore]` so opt-in:
//!
//! ```text
//! cargo test --release --test test_bench_raw_sink -- \
//!     --ignored --nocapture --test-threads=1
//! ```

#![cfg(unix)]

use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use peel::sink::raw::RawSink;
use peel::sink::Sink;

/// Mostly-incompressible LCG payload — same generator the
/// `test_bench_deflate_native.rs` / `test_bench_streaming.rs`
/// fixtures use, so the chunk-write workload's data shape matches
/// the bench grid this plan is moving.
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

fn unique_path(label: &str) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("peel-bench-raw-sink-{label}-{pid}-{nanos}.bin"))
}

fn mibps(bytes: u64, dur: Duration) -> f64 {
    let s = dur.as_secs_f64();
    if s <= 0.0 {
        return 0.0;
    }
    (bytes as f64) / (1024.0 * 1024.0) / s
}

/// Drive `payload` into a [`RawSink`] in `chunk` byte slices. Returns
/// `(bytes_written, elapsed)`.
fn run_raw_sink(payload: &[u8], chunk: usize) -> (u64, Duration) {
    let path = unique_path(&format!("raw-{chunk}"));
    let _cleanup = scopeguard_remove(path.clone());
    let started = Instant::now();
    let mut sink = RawSink::create(&path).expect("create");
    for c in payload.chunks(chunk) {
        sink.write(c).expect("write");
    }
    sink.close().expect("close");
    (payload.len() as u64, started.elapsed())
}

/// Drive `payload` into a `BufWriter<File>` (1 MiB capacity) in `chunk`
/// byte slices. Models the Phase-1 target shape so the same bench
/// surfaces the expected post-A floor.
fn run_bufwriter_1m(payload: &[u8], chunk: usize) -> (u64, Duration) {
    let path = unique_path(&format!("bufw-{chunk}"));
    let _cleanup = scopeguard_remove(path.clone());
    let started = Instant::now();
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .expect("open");
    let mut writer = BufWriter::with_capacity(1 << 20, file);
    for c in payload.chunks(chunk) {
        writer.write_all(c).expect("write");
    }
    writer.flush().expect("flush");
    drop(writer);
    (payload.len() as u64, started.elapsed())
}

/// Drop-guard that deletes the file at `path` when it goes out of
/// scope, so a panicking bench leaves nothing behind.
struct RemoveOnDrop(PathBuf);
impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}
fn scopeguard_remove(path: PathBuf) -> RemoveOnDrop {
    RemoveOnDrop(path)
}

/// Verify the file contents after a run match the source payload.
/// Cheap relative to the timed loop and guards against a sink bug
/// silently dropping bytes during a future refactor.
fn verify_file_matches(path: &std::path::Path, payload: &[u8]) {
    let got = fs::read(path).expect("read back");
    assert_eq!(got.len(), payload.len(), "size mismatch reading back");
    assert!(got == payload, "byte mismatch reading back");
}

fn report(label: &str, bytes: u64, dur: Duration) {
    println!(
        "[bench-raw-sink] {label:<32} bytes={mib:7.1} MiB  time={dur:7.3}s  ({mibps:7.1} MiB/s)",
        mib = (bytes as f64) / (1024.0 * 1024.0),
        dur = dur.as_secs_f64(),
        mibps = mibps(bytes, dur),
    );
}

/// 256 MiB through a `RawSink` with 64 KiB chunks (gzip STORED-block
/// shape) and 128 KiB chunks (zstd Raw_Block shape). Compare to the
/// `BufWriter<File>` 1 MiB variant.
///
/// The decoder's chunk granularity is what drives the bench — at
/// 64 KiB chunks `RawSink::write` issues 4 096 `write(2)` syscalls
/// against the kernel; the 1 MiB-`BufWriter` variant collapses those
/// into 256. The ratio of those two numbers is the lever this plan's
/// Lever A targets.
#[test]
#[ignore = "benchmark; opt-in via --ignored"]
fn bench_raw_sink_write_throughput() {
    const PAYLOAD: usize = 256 * 1024 * 1024;
    let payload = random_bytes(0x000C_0FFE_EBAD_F00D, PAYLOAD);

    for &chunk in &[64 * 1024usize, 128 * 1024] {
        // RawSink (today's shape).
        let path = unique_path(&format!("verify-raw-{chunk}"));
        let cleanup = scopeguard_remove(path.clone());
        let started = Instant::now();
        let mut sink = RawSink::create(&path).expect("create");
        for c in payload.chunks(chunk) {
            sink.write(c).expect("write");
        }
        sink.close().expect("close");
        let dur = started.elapsed();
        verify_file_matches(&path, &payload);
        drop(cleanup);
        report(
            &format!("RawSink chunk={chunk} (today)"),
            PAYLOAD as u64,
            dur,
        );

        // BufWriter<File> 1 MiB (post-A target shape).
        let path = unique_path(&format!("verify-bufw-{chunk}"));
        let cleanup = scopeguard_remove(path.clone());
        let started = Instant::now();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .expect("open");
        let mut writer = BufWriter::with_capacity(1 << 20, file);
        for c in payload.chunks(chunk) {
            writer.write_all(c).expect("write");
        }
        writer.flush().expect("flush");
        drop(writer);
        let dur = started.elapsed();
        verify_file_matches(&path, &payload);
        drop(cleanup);
        report(
            &format!("BufWriter<File> 1MiB chunk={chunk}"),
            PAYLOAD as u64,
            dur,
        );
    }
}

// ---- silence unused-helper warnings on non-bench builds --------------

#[allow(dead_code)]
fn _silence_unused() {
    let _ = (
        random_bytes(0, 0),
        run_raw_sink(&[], 1),
        run_bufwriter_1m(&[], 1),
    );
    let _: fn(&std::path::Path, &[u8]) = verify_file_matches;
    let _: fn(&str, u64, Duration) = report;
    let _: fn(u64, Duration) -> f64 = mibps;
}
