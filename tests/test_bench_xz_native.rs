//! Phase 0 throughput-only benchmark fixture for the hand-rolled
//! xz / LZMA decoder ([`peel::decode::xz_native`]).
//!
//! Phase 0 of `docs/PLAN_xz_throughput.md`. Goal: lock in a baseline
//! decode-only throughput number for the production decoder so each
//! later phase of that plan can record an unambiguous delta in its
//! commit message.
//!
//! # What this measures
//!
//! Decode-only, no network, no sink syscalls beyond a `Vec<u8>::write`.
//! The bench:
//!
//! 1. builds the same 256 MiB tar payload that
//!    [`tests/test_bench_streaming.rs::build_tar_payload`] uses,
//! 2. compresses it with `xz2`'s default-preset (preset 6) easy
//!    encoder — single-threaded, so the resulting stream is
//!    single-Block (the dominant `.tar.xz` shape),
//! 3. runs the resulting bytes through both
//!    [`peel::decode::xz_native::Decoder`] and `xz2::read::XzDecoder`,
//!    writing each into a `Vec<u8>` sink,
//! 4. asserts both decoders emit byte-identical output to the
//!    original payload (correctness gate so a future "fast-path"
//!    regression doesn't silently corrupt),
//! 5. prints a comparison row: payload size, on-wire size,
//!    `peel` MB/s, `xz2` (liblzma) MB/s, ratio.
//!
//! # How to run
//!
//! Both bench tests are `#[ignore]`d. Invoke explicitly, in
//! `--release` (a debug build is so slow the numbers are
//! meaningless):
//!
//! ```text
//! RUSTFLAGS="-C target-cpu=native" \
//!     cargo test --release --test test_bench_xz_native -- \
//!     --ignored --nocapture --test-threads=1
//! ```
//!
//! `target-cpu=native` is recommended so the inner loop sees the
//! same instruction set the developer's profiler does.
//!
//! # Profiling
//!
//! The Phase 0 plan asks for a per-function attribution alongside
//! the absolute MB/s number. Two reasonable paths on the supported
//! developer platforms:
//!
//! ```text
//! # macOS — `samply` records dtrace under the hood and renders a
//! # Firefox profiler view.
//! cargo install samply
//! RUSTFLAGS="-C target-cpu=native -C debuginfo=2" \
//!     cargo test --release --test test_bench_xz_native \
//!     bench_xz_native_tar_xz_64mib_single_block --no-run
//! samply record target/release/deps/test_bench_xz_native-* \
//!     bench_xz_native_tar_xz_64mib_single_block --ignored --nocapture
//!
//! # Linux — `cargo flamegraph` is the equivalent.
//! cargo install flamegraph
//! RUSTFLAGS="-C target-cpu=native -C debuginfo=2" \
//!     cargo flamegraph --release --test test_bench_xz_native -- \
//!     bench_xz_native_tar_xz_64mib_single_block --ignored --nocapture
//! ```
//!
//! Profile the 64 MiB variant rather than 256 MiB — same hot loop,
//! 4× faster turnaround.

#![cfg(unix)]

use std::io::{Cursor, Read};
use std::time::{Duration, Instant};

use peel::decode::xz_native::Decoder;
use peel::decode::{DecodeStatus, StreamingDecoder};

#[path = "support/mod.rs"]
mod support;

use support::tar_fixtures::build_simple_archive;

// ---- payload generation (mirrors test_bench_streaming.rs) ------------

/// Mostly-incompressible LCG-derived bytes — same generator as
/// [`tests/test_bench_streaming.rs::random_bytes`] so this bench's
/// payload is comparable to the bench grid the README publishes.
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

/// Build a tar archive whose raw byte total is approximately
/// `total_bytes`, split across 8 files. Same layout as the bench
/// grid's `build_tar_payload`.
fn build_tar_payload(total_bytes: usize) -> Vec<u8> {
    const FILES: usize = 8;
    let per = total_bytes / FILES;
    let names: Vec<String> = (0..FILES)
        .map(|i| format!("data/file_{i:02}.bin"))
        .collect();
    let bodies: Vec<Vec<u8>> = (0..FILES)
        .map(|i| random_bytes(0xBEEF + i as u64, per))
        .collect();
    let pairs: Vec<(&str, &[u8])> = names
        .iter()
        .zip(bodies.iter())
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    build_simple_archive(&pairs)
}

/// Compress `input` with `xz2` at default preset 6, single-threaded
/// (so the result is single-Block). Mirrors
/// [`tests/test_bench_streaming.rs::encode_xz`].
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

// ---- decode harnesses ------------------------------------------------

/// Drive [`peel::decode::xz_native::Decoder`] over `compressed` until
/// `Eof`, writing into a fresh `Vec<u8>` sink. Returns
/// `(decoded_bytes, elapsed)`.
///
/// `Cursor::new(compressed.to_vec())` clones once so the source slice
/// stays available for the second harness; the clone happens *before*
/// the timer starts, so it's not on the measured path.
fn run_peel(compressed: &[u8]) -> (Vec<u8>, Duration) {
    let source = Cursor::new(compressed.to_vec());
    let mut decoder = Decoder::new(Box::new(source)).expect("construct peel decoder");
    let mut sink: Vec<u8> = Vec::with_capacity(compressed.len() * 2);
    let started = Instant::now();
    loop {
        match decoder.decode_step(&mut sink).expect("decode_step") {
            DecodeStatus::Eof => break,
            DecodeStatus::MoreData => continue,
        }
    }
    let elapsed = started.elapsed();
    (sink, elapsed)
}

/// Drive `xz2`'s liblzma-backed decoder over `compressed` until EOF,
/// reading into a fresh `Vec<u8>`. Returns `(decoded_bytes, elapsed)`.
///
/// Used as a single-threaded reference number so the printed row
/// reads "peel vs liblzma single-thread" — matching the
/// `PLAN_xz_throughput.md` stretch target's framing.
fn run_xz2(compressed: &[u8]) -> (Vec<u8>, Duration) {
    let mut decoder = xz2::read::XzDecoder::new(Cursor::new(compressed.to_vec()));
    let mut sink: Vec<u8> = Vec::with_capacity(compressed.len() * 2);
    let started = Instant::now();
    decoder.read_to_end(&mut sink).expect("xz2 decode");
    let elapsed = started.elapsed();
    (sink, elapsed)
}

// ---- result reporting ------------------------------------------------

fn report(label: &str, payload_bytes: u64, on_wire_bytes: u64, peel: Duration, xz2: Duration) {
    fn mibps(bytes: u64, dur: Duration) -> f64 {
        let s = dur.as_secs_f64();
        if s <= 0.0 {
            return 0.0;
        }
        (bytes as f64) / (1024.0 * 1024.0) / s
    }
    let payload_mib = (payload_bytes as f64) / (1024.0 * 1024.0);
    let wire_mib = (on_wire_bytes as f64) / (1024.0 * 1024.0);
    let peel_mibps = mibps(payload_bytes, peel);
    let xz2_mibps = mibps(payload_bytes, xz2);
    let ratio = if peel_mibps > 0.0 {
        xz2_mibps / peel_mibps
    } else {
        f64::INFINITY
    };
    println!(
        "[bench-xz] {label:<48}  payload={payload_mib:7.1} MiB  wire={wire_mib:7.1} MiB  \
         peel={peel:7.3}s ({pmibs:7.1} MiB/s)  xz2={xz2:7.3}s ({xmibs:7.1} MiB/s)  ratio xz2/peel={ratio:5.2}x",
        peel = peel.as_secs_f64(),
        xz2 = xz2.as_secs_f64(),
        pmibs = peel_mibps,
        xmibs = xz2_mibps,
        ratio = ratio,
    );
}

// ---- benches ---------------------------------------------------------

/// 64 MiB single-Block tar.xz — same fixture size as the
/// `PLAN_xz_block_decoder.md` Phase 0 spike's headline number
/// ("~290 MiB/s on Apple Silicon"). Smaller than the 256 MiB
/// regression-gate fixture; fast enough for profiling iteration.
#[test]
#[ignore = "benchmark; opt-in via --ignored"]
fn bench_xz_native_tar_xz_64mib_single_block() {
    bench_at_size(
        64 * 1024 * 1024,
        "tar.xz · 64 MiB · single-Block · preset 6",
    );
}

/// 128 MiB single-Block tar.xz — matches the `1 Gbps · 128 MiB` cell of
/// the README's `bench_throttled_realistic_grid`. Used by Phase 0 of
/// `docs/PLAN_xz_bench_profile.md` as the "no-pipeline floor": the
/// difference between this elapsed time and the same cell's `decode`
/// column in `diag_tar_xz_breakdown` is the cost of the extractor
/// inner loop and source plumbing on this fixture size.
#[test]
#[ignore = "benchmark; opt-in via --ignored"]
fn bench_xz_native_tar_xz_128mib_single_block() {
    bench_at_size(
        128 * 1024 * 1024,
        "tar.xz · 128 MiB · single-Block · preset 6",
    );
}

/// 256 MiB single-Block tar.xz — the regression-gate fixture
/// referenced by `docs/PLAN_xz_throughput.md` §Targets. Same shape
/// as the 1 Gbps · 128 MiB cell of the README's bench grid scaled
/// up so the wall-clock is resolvable above timing noise.
#[test]
#[ignore = "benchmark; opt-in via --ignored"]
fn bench_xz_native_tar_xz_256mib_single_block() {
    bench_at_size(
        256 * 1024 * 1024,
        "tar.xz · 256 MiB · single-Block · preset 6",
    );
}

/// Profiling helper: encode the 64 MiB fixture once, then drive the
/// peel decoder over it `PEEL_BENCH_ITERS` times (default 10). Use
/// this to keep a `sample` / `dtrace` / `samply` profiler attached
/// to a steady-state decode workload — the one-shot benches above
/// spend the first ~10 s in `xz2`'s encoder, which obscures the
/// decode hot spots.
///
/// ```text
/// # In one shell:
/// PEEL_BENCH_ITERS=20 RUSTFLAGS="-C target-cpu=native" \
///     cargo test --release --test test_bench_xz_native \
///     bench_xz_native_decode_loop_for_profiling -- \
///     --ignored --nocapture --test-threads=1
///
/// # In another shell, attach `sample` to the running PID for the
/// # decode-only window (after the per-test "running 1 test" line
/// # appears).
/// pgrep -f test_bench_xz_native | xargs -I{} sample {} 30 -mayDie
/// ```
#[test]
#[ignore = "profiling helper; opt-in via --ignored"]
fn bench_xz_native_decode_loop_for_profiling() {
    let archive = build_tar_payload(64 * 1024 * 1024);
    let compressed = encode_xz(&archive);
    let iters: u32 = std::env::var("PEEL_BENCH_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    println!("[bench-xz] profiling loop: {iters} iterations of 64 MiB single-Block decode",);
    let started = Instant::now();
    let mut total_bytes: u64 = 0;
    for _ in 0..iters {
        let (out, _) = run_peel(&compressed);
        assert_eq!(
            out.len(),
            archive.len(),
            "iteration emitted wrong byte count"
        );
        total_bytes = total_bytes.saturating_add(out.len() as u64);
    }
    let elapsed = started.elapsed();
    let mibps = (total_bytes as f64) / (1024.0 * 1024.0) / elapsed.as_secs_f64();
    println!(
        "[bench-xz] decode-loop done: total={tot:7.1} MiB  elapsed={el:6.3}s  avg={mibps:7.1} MiB/s",
        tot = (total_bytes as f64) / (1024.0 * 1024.0),
        el = elapsed.as_secs_f64(),
    );
}

fn bench_at_size(payload_bytes: usize, label: &str) {
    let archive = build_tar_payload(payload_bytes);
    let compressed = encode_xz(&archive);

    let (peel_out, peel_elapsed) = run_peel(&compressed);
    assert_eq!(
        peel_out.len(),
        archive.len(),
        "peel decoded length differs from input archive"
    );
    assert_eq!(peel_out, archive, "peel decoded bytes differ from input");

    let (xz2_out, xz2_elapsed) = run_xz2(&compressed);
    assert_eq!(xz2_out, archive, "xz2 decoded bytes differ from input");

    report(
        label,
        archive.len() as u64,
        compressed.len() as u64,
        peel_elapsed,
        xz2_elapsed,
    );
}

// ---- silence unused-helper warnings on non-bench builds --------------

/// `cargo test` without `--ignored` runs no `#[test]` here, but still
/// links the file. The helpers above are unreachable then. Reference
/// them from a `#[test]` that compiles under any flags so the build
/// stays warning-clean. (Mirrors the pattern in
/// `tests/test_bench_streaming.rs`.)
#[allow(dead_code)]
fn _silence_unused() {
    let _ = (random_bytes(0, 0), build_tar_payload(0), encode_xz(&[]));
    let _ = (
        run_peel as fn(&[u8]) -> (Vec<u8>, Duration),
        run_xz2 as fn(&[u8]) -> (Vec<u8>, Duration),
    );
    let _ = report as fn(&str, u64, u64, Duration, Duration);
}
