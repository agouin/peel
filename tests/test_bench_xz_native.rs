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

/// "Log-like" deterministic payload that compresses ~2–3× under
/// LZMA preset 6 — the typical real-world `.tar.xz` shape (kernel
/// sources, distro images, structured ML datasets sit in this range).
///
/// Used by the `compressible_*` benches to exercise the match-copy /
/// dictionary-access paths of the decoder, which see < 1 % of
/// self-time on the LCG-random fixture but become top-3 on real-world
/// archives. See `PLAN_xz_decoder_optimization.md` Phase 0.
///
/// Shape: lines of "timestamp · token · token · …" drawn from a small
/// vocabulary (drives LZMA dictionary matches), peppered with short
/// runs of pure-random bytes (raises the entropy floor so the model
/// emits a realistic mix of literals and matches, not just matches).
fn compressible_bytes(seed: u64, len: usize) -> Vec<u8> {
    static TOKENS: &[&str] = &[
        "INFO",
        "WARN",
        "DEBUG",
        "ERROR",
        "TRACE",
        "FATAL",
        "request",
        "response",
        "handler",
        "worker",
        "queue",
        "scheduler",
        "/api/v1/items",
        "/api/v1/users",
        "/api/v1/orders",
        "/api/v1/sessions",
        "/api/v2/health",
        "/api/v2/metrics",
        "/api/v2/probe",
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "status=200",
        "status=204",
        "status=301",
        "status=404",
        "status=500",
        "host=alpha.internal",
        "host=beta.internal",
        "host=gamma.internal",
        "service=ingest",
        "service=router",
        "service=auth",
        "service=billing",
        "user_id=",
        "request_id=",
        "trace_id=",
        "span_id=",
        "tenant=",
        "method=GET",
        "method=POST",
        "client=mobile",
        "client=web",
        "client=cli",
        "region=us-east-1",
        "region=us-west-2",
        "region=eu-central-1",
        "msg=\"ok\"",
        "msg=\"retry scheduled\"",
        "msg=\"cache miss\"",
        "lat_ms=",
        "bytes=",
        "rows=",
        "qps=",
        "p99=",
    ];

    let mut state = seed ^ 0x9E37_79B9_7F4A_7C15;
    let mut next_u64 = || -> u64 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        state
    };

    let mut out = Vec::with_capacity(len + 256);
    while out.len() < len {
        // Timestamp prefix — most bytes recur; subseconds are random.
        let mins = next_u64() % 60;
        let secs = next_u64() % 60;
        let micros = next_u64() % 1_000_000;
        out.extend_from_slice(
            format!("2026-05-04T12:{mins:02}:{secs:02}.{micros:06}Z ").as_bytes(),
        );

        // 4–7 vocabulary tokens — gives the LZMA dictionary repeating
        // n-grams to match against.
        let n_tokens = 4 + (next_u64() % 4) as usize;
        for i in 0..n_tokens {
            let idx = (next_u64() as usize) % TOKENS.len();
            if i > 0 {
                out.push(b' ');
            }
            out.extend_from_slice(TOKENS[idx].as_bytes());
            // For "key=" tokens, append a numeric tail.
            if TOKENS[idx].ends_with('=') {
                out.extend_from_slice(format!("{}", next_u64() % 1_000_000).as_bytes());
            }
        }

        // High-entropy tail: 48–80 raw random bytes. This is the
        // dominant entropy source. Without it the ratio runs > 6× and
        // over-fits the match path; with it we sit in the realistic
        // 2–3× band. We emit full 8-byte LCG outputs (truncated to
        // the requested length) rather than `(next_u64() & 0xff)` —
        // the low bits of an LCG cycle quickly, so byte-at-a-time
        // truncation produces a stream LZMA can match aggressively.
        out.push(b' ');
        let blob_len = 28 + (next_u64() as usize % 28);
        let mut emitted = 0usize;
        while emitted < blob_len {
            let bytes = next_u64().to_le_bytes();
            let take = (blob_len - emitted).min(8);
            out.extend_from_slice(&bytes[..take]);
            emitted += take;
        }
        out.push(b'\n');
    }
    out.truncate(len);
    out
}

/// Tar archive whose raw bytes are "log-like" structured text that
/// compresses ~2–3× under LZMA. Same 8-file shape as
/// [`build_tar_payload`] so the on-disk footprint, header overhead,
/// and end-of-archive padding are comparable across the two fixtures.
fn build_compressible_tar_payload(total_bytes: usize) -> Vec<u8> {
    const FILES: usize = 8;
    let per = total_bytes / FILES;
    let names: Vec<String> = (0..FILES).map(|i| format!("data/log_{i:02}.txt")).collect();
    let bodies: Vec<Vec<u8>> = (0..FILES)
        .map(|i| compressible_bytes(0xC0DE + i as u64, per))
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

/// CRC-64/XZ throughput over a 1 GiB random buffer.
///
/// Phase 1 of [`docs/PLAN_xz_decoder_optimization.md`]: the
/// decoder-side CRC64 was 7.3 % of decode self-time at slicing-by-1
/// (~1 GB/s). Slicing-by-8 must clear ≥ 4× speedup vs. byte-by-byte
/// on the *same* hardware to gate the phase exit. The bench measures
/// both implementations side-by-side rather than against an absolute
/// GB/s number — the absolute number depends on memory bandwidth /
/// L1 latency of the host, which the plan's "1 GB/s baseline" was
/// estimated against (x86-64); Apple aarch64 numbers differ.
///
/// Allocates 1 GiB; `#[ignore]` so it's opt-in.
#[test]
#[ignore = "benchmark; opt-in via --ignored"]
fn bench_crc64_throughput() {
    use peel::hash::crc64::Crc64;

    const LEN: usize = 1024 * 1024 * 1024; // 1 GiB
    let buf = random_bytes(0xC0FFEE, LEN);

    fn report(label: &str, len: usize, dur: Duration, crc: u64) -> f64 {
        let gibps = (len as f64) / (1024.0 * 1024.0 * 1024.0) / dur.as_secs_f64();
        let gbps = (len as f64) / 1_000_000_000.0 / dur.as_secs_f64();
        println!(
            "[bench-xz] crc64 {label:<20} 1 GiB: {dur:.3}s  ({gibps:.2} GiB/s, {gbps:.2} GB/s)  crc=0x{crc:016x}",
            dur = dur.as_secs_f64(),
        );
        gbps
    }

    // Byte-by-byte reference — measured here so the plan's "≥ 4×"
    // gate is anchored to *this* hardware's slicing-by-1 number, not
    // a generic 1 GB/s assumption.
    fn byte_by_byte(data: &[u8]) -> u64 {
        // Reproduces the pre-Phase-1 inner loop without going through
        // the public API (which now slices-by-8). Same TABLE entries
        // by polynomial; the canonical "123456789" vector pins
        // both this and the production hasher to the same CRC.
        const POLY: u64 = 0xC96C_5795_D787_0F42;
        let mut table = [0u64; 256];
        for (i, slot) in table.iter_mut().enumerate() {
            let mut c = i as u64;
            for _ in 0..8 {
                c = if c & 1 != 0 { (c >> 1) ^ POLY } else { c >> 1 };
            }
            *slot = c;
        }
        let mut state = !0u64;
        for &b in data {
            state = table[((state ^ u64::from(b)) & 0xFF) as usize] ^ (state >> 8);
        }
        !state
    }

    // Warm-up: pages-in the 1 GiB buffer.
    std::hint::black_box(byte_by_byte(&buf));
    let mut warm = Crc64::new();
    warm.update(&buf);
    std::hint::black_box(warm.finalize());

    // Median of 3 timed runs each.
    let mut bb_times = [Duration::default(); 3];
    let mut bb_crc = 0u64;
    for slot in bb_times.iter_mut() {
        let started = Instant::now();
        bb_crc = byte_by_byte(&buf);
        *slot = started.elapsed();
    }
    bb_times.sort();
    let bb_gbps = report("byte-by-byte", LEN, bb_times[1], bb_crc);

    let mut s8_times = [Duration::default(); 3];
    let mut s8_crc = 0u64;
    for slot in s8_times.iter_mut() {
        let mut h = Crc64::new();
        let started = Instant::now();
        h.update(&buf);
        s8_crc = h.finalize();
        *slot = started.elapsed();
    }
    s8_times.sort();
    let s8_gbps = report("slicing-by-16", LEN, s8_times[1], s8_crc);

    assert_eq!(
        bb_crc, s8_crc,
        "byte-by-byte and slicing-by-16 disagree on the same 1 GiB buffer"
    );

    let speedup = s8_gbps / bb_gbps;
    println!(
        "[bench-xz] crc64 speedup vs byte-by-byte: {speedup:.2}× \
         (slicing-by-16 {s8_gbps:.2} GB/s / byte-by-byte {bb_gbps:.2} GB/s)"
    );

    // Phase 1 exit gate: ≥ 4× speedup over byte-by-byte on the same
    // host. The plan denominated this as "≥ 4 GB/s" vs. an assumed
    // ~1 GB/s baseline; phrasing the gate as a ratio makes it
    // hardware-agnostic — what matters is that we cut the absolute
    // CRC64 cost share to ≤ 25 % of decode-time-without-Phase-1.
    let gate = 4.0;
    assert!(
        speedup >= gate,
        "crc64 slicing-by-16 speedup regressed: got {speedup:.2}×, Phase 1 floor is ≥ {gate:.2}×"
    );
}

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

/// 64 MiB compressible-payload sibling. Shape: `build_compressible_tar_payload`.
/// Same Block layout, different per-symbol distribution — the literal hot
/// path is no longer 99 % of self-time, so the match-copy / dict-access /
/// RLE optimizations targeted by Phase 2 of
/// [`docs/PLAN_xz_decoder_optimization.md`] become measurable.
#[test]
#[ignore = "benchmark; opt-in via --ignored"]
fn bench_xz_native_compressible_64mib_single_block() {
    bench_at_size_compressible(
        64 * 1024 * 1024,
        "tar.xz · 64 MiB · single-Block · preset 6 · compressible",
    );
}

/// 128 MiB compressible-payload sibling — matches the
/// `1 Gbps · 128 MiB` cell of the bench grid. The headline number
/// for [`docs/PLAN_xz_decoder_optimization.md`] §Targets.
#[test]
#[ignore = "benchmark; opt-in via --ignored"]
fn bench_xz_native_compressible_128mib_single_block() {
    bench_at_size_compressible(
        128 * 1024 * 1024,
        "tar.xz · 128 MiB · single-Block · preset 6 · compressible",
    );
}

/// 256 MiB compressible-payload sibling — the regression-gate
/// counterpart to `bench_xz_native_tar_xz_256mib_single_block` on the
/// realistic-distribution fixture.
#[test]
#[ignore = "benchmark; opt-in via --ignored"]
fn bench_xz_native_compressible_256mib_single_block() {
    bench_at_size_compressible(
        256 * 1024 * 1024,
        "tar.xz · 256 MiB · single-Block · preset 6 · compressible",
    );
}

/// Sanity-gate: the compressible generator must produce a payload
/// that LZMA preset 6 compresses at a 2.0–4.0× ratio. Outside that
/// band, `bench_xz_native_compressible_*` is no longer measuring a
/// realistic real-world tar.xz shape and the per-symbol attribution
/// stops being representative.
///
/// Cheap to run (no decode), so it runs as a normal `cargo test`
/// gate rather than `#[ignore]`. Keeps the generator from drifting
/// silently.
#[test]
fn compressible_payload_ratio_in_band() {
    let archive = build_compressible_tar_payload(8 * 1024 * 1024);
    let compressed = encode_xz(&archive);
    let ratio = (archive.len() as f64) / (compressed.len() as f64);
    assert!(
        (2.0..=4.0).contains(&ratio),
        "compressible-fixture LZMA ratio drifted: archive={} B, \
         compressed={} B, ratio={:.2}× (expected 2.0–4.0×)",
        archive.len(),
        compressed.len(),
        ratio,
    );
}

/// Microbench: per-call cost of [`StreamingDecoder::decoder_state_into`]
/// on a fully-warmed xz_native decoder. After
/// `PLAN_checkpoint_blob_dedup.md` Phase 2 this is the call the
/// streaming-pipeline observer makes to populate the resume blob
/// bytes inside the `Checkpoint` body buffer with one memcpy
/// (decoder ring → body), so the per-call cost is the load-bearing
/// number for "how much does each persist-eligible advance cost?".
///
/// The bench:
/// 1. encodes a 64 MiB fixture (forces the dict past the 8 MiB cap
///    so `decoder_state_into` actually exercises the full dict
///    memcpy),
/// 2. drives `peel::decode::xz_native::Decoder` until it reaches
///    a snapshotable LZMA2 chunk boundary (where
///    `decoder_state_into` returns `true`),
/// 3. loops `PEEL_DECSTATE_ITERS` calls (default 10000) into a
///    reused `Vec<u8>` so the allocation cost is amortised,
/// 4. asserts the per-call wall-clock is ≤ **2 ms** — the
///    plan's Phase 2 exit-criterion floor.
#[test]
#[ignore = "benchmark; opt-in via --ignored"]
fn bench_xz_native_decoder_state_into_microbench() {
    use peel::decode::xz_native::Decoder;
    use peel::decode::{DecodeStatus, StreamingDecoder};

    let archive = build_tar_payload(64 * 1024 * 1024);
    let compressed = encode_xz(&archive);

    // Warm the decoder up to a snapshotable boundary. Between
    // chunks `decoder_state_into` returns false; we keep stepping
    // until we hit a chunk boundary inside a Block.
    let mut decoder = Decoder::new(Box::new(Cursor::new(compressed.clone()))).expect("decoder");
    let mut sink: Vec<u8> = Vec::with_capacity(compressed.len() * 2);
    let mut probe = Vec::with_capacity(16 * 1024 * 1024);
    let mut warmed_up = false;
    for _ in 0..10_000 {
        match decoder.decode_step(&mut sink).expect("decode_step") {
            DecodeStatus::Eof => break,
            DecodeStatus::MoreData => {}
        }
        probe.clear();
        if decoder.decoder_state_into(&mut probe) {
            warmed_up = true;
            break;
        }
    }
    assert!(
        warmed_up,
        "fixture did not reach a snapshotable LZMA2 chunk boundary; \
         increase warmup iterations or shrink the fixture"
    );
    let blob_size = probe.len();
    println!(
        "[bench-xz] decoder_state_into microbench: warmed up; blob_size = {} bytes \
         (dict at ~8 MiB cap means most of this is the LZMA dict)",
        blob_size
    );

    let iters: u32 = std::env::var("PEEL_DECSTATE_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000);

    // Reuse the same buffer across iterations so allocation
    // doesn't dominate the measurement; clear() preserves the
    // backing capacity.
    let started = Instant::now();
    for _ in 0..iters {
        probe.clear();
        let r = decoder.decoder_state_into(&mut probe);
        debug_assert!(r, "decoder fell off the chunk boundary mid-loop");
    }
    let elapsed = started.elapsed();
    let per_call = elapsed / iters;
    let per_call_ms = per_call.as_secs_f64() * 1_000.0;
    println!(
        "[bench-xz] decoder_state_into microbench: iters={iters} \
         total={total:.3}s  per_call={per_call_ms:.4} ms  blob={blob_size} B",
        total = elapsed.as_secs_f64(),
    );

    // Phase 2 exit criterion: per-call cost ≤ 2 ms (down from
    // ~15.5 ms in Phase 0; ~0.243 ms in Phase 1 already met it).
    // Generous gate so noise on a busy laptop doesn't false-fail
    // CI runs that opt in to the bench.
    let gate_ms = 2.0;
    assert!(
        per_call_ms <= gate_ms,
        "decoder_state_into per-call regressed: got {per_call_ms:.3} ms, \
         Phase 2 floor is ≤ {gate_ms:.3} ms"
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
    decode_loop_for_profiling("64 MiB single-Block · incompressible", &archive);
}

/// Compressible-fixture sibling — same shape as
/// [`bench_xz_native_decode_loop_for_profiling`] but with the
/// realistic `tar.xz` distribution. Use this to attribute
/// match-copy / dict-access / RLE self-time, which sit at < 1 % on
/// the incompressible fixture but become top-3 on real-world archives.
/// See `PLAN_xz_decoder_optimization.md` Phase 0.
#[test]
#[ignore = "profiling helper; opt-in via --ignored"]
fn bench_xz_native_decode_loop_for_profiling_compressible() {
    let archive = build_compressible_tar_payload(64 * 1024 * 1024);
    decode_loop_for_profiling("64 MiB single-Block · compressible", &archive);
}

fn decode_loop_for_profiling(label: &str, archive: &[u8]) {
    let compressed = encode_xz(archive);
    let iters: u32 = std::env::var("PEEL_BENCH_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    println!("[bench-xz] profiling loop ({label}): {iters} iterations");
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
        "[bench-xz] decode-loop done ({label}): total={tot:7.1} MiB  elapsed={el:6.3}s  avg={mibps:7.1} MiB/s",
        tot = (total_bytes as f64) / (1024.0 * 1024.0),
        el = elapsed.as_secs_f64(),
    );
}

fn bench_at_size(payload_bytes: usize, label: &str) {
    let archive = build_tar_payload(payload_bytes);
    bench_archive(&archive, label);
}

fn bench_at_size_compressible(payload_bytes: usize, label: &str) {
    let archive = build_compressible_tar_payload(payload_bytes);
    bench_archive(&archive, label);
}

fn bench_archive(archive: &[u8], label: &str) {
    let compressed = encode_xz(archive);

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
    let _ = (compressible_bytes(0, 0), build_compressible_tar_payload(0));
    let _ = (
        run_peel as fn(&[u8]) -> (Vec<u8>, Duration),
        run_xz2 as fn(&[u8]) -> (Vec<u8>, Duration),
    );
    let _ = report as fn(&str, u64, u64, Duration, Duration);
}
