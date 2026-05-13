//! Integration tests for [`peel::extractor`].
//!
//! These exercise the §8 demo shape end-to-end: a multi-frame zstd
//! stream wrapping a tar archive is decoded, its members extracted to
//! disk via [`peel::sink::TarSink`], and the source's compressed
//! footprint shrinks under [`peel::punch`]. Lower-level unit tests
//! covering the stats, error variants, and stub sinks live alongside
//! the implementation in `src/extractor.rs`.

#![cfg(unix)]

use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::fd::AsFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use peel::decode::{DecoderRegistry, StreamingDecoder};
use peel::extractor::{ExtractionStats, Extractor, ExtractorConfig};
use peel::punch::{default_puncher, NoopPuncher, PunchError, PunchHole};
use peel::sink::{RawSink, TarSink};
use peel::types::ByteOffset;

#[path = "support/mod.rs"]
mod support;

use support::tar_fixtures::build_simple_archive;

static UNIQ: AtomicU64 = AtomicU64::new(0);

/// Synthesize a unique temp path while preserving the supplied
/// `name`'s suffix verbatim — the decoder registry routes by file
/// extension, so the suffix has to land at the end of the path.
fn fresh_path(name: &str) -> PathBuf {
    let pid = std::process::id();
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let prefix = format!("peel_extractor_it_{pid}_{nanos}_{n}_");
    std::env::temp_dir().join(format!("{prefix}{name}"))
}

struct CleanupOnDrop(PathBuf);
impl Drop for CleanupOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Hand-rolled LCG for "random enough" payloads: the integration tests
/// need data that compresses *poorly* so the on-disk footprint of the
/// compressed source is large enough to demonstrate punching shrinks
/// it.
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

/// Encode `payloads` as a sequence of independent zstd frames at level
/// 1 (fast, low-ratio — the tests pick payload entropy themselves).
fn encode_frames(payloads: &[&[u8]]) -> Vec<u8> {
    let mut combined = Vec::new();
    for p in payloads {
        let frame = zstd::encode_all(*p, 1).expect("encode");
        combined.extend_from_slice(&frame);
    }
    combined
}

/// Encode `payload` as a single xz Stream / single Block at the
/// given preset. Used by the Phase 8 hole-punching tests so the
/// archive shape matches what `xz` CLI produces by default — one
/// monolithic Block whose only restart points are the
/// per-LZMA2-chunk boundaries the hand-rolled decoder exposes.
fn xz2_encode_single_block(payload: &[u8], preset: u32) -> Vec<u8> {
    use std::io::Write;
    let mut compressed = Vec::new();
    let mut encoder = xz2::write::XzEncoder::new(&mut compressed, preset);
    encoder.write_all(payload).expect("xz2 encode");
    encoder.finish().expect("xz2 finish");
    compressed
}

/// Encode `payload` as a single-member gzip blob at the default
/// compression level. Used by the Phase 10 hole-punching tests so
/// the archive shape matches what `gzip` / `tar -z` CLI produces
/// by default — one monolithic gzip member whose only restart
/// points are the per-deflate-block boundaries the hand-rolled
/// `crate::decode::deflate_native::gzip` decoder exposes (Phase 7
/// `decoder_state` blob, Phase 8 registry swap).
fn encode_gzip_single_member(payload: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(payload).expect("gzip encode");
    encoder.finish().expect("gzip finish")
}

/// Build LZMA-friendly content of `len` bytes: pseudo-random
/// pseudo-English sentences, varied enough that the decoder
/// cannot collapse the whole input into a single rep match,
/// compressible enough that xz emits real LZMA chunks (not the
/// uncompressed-passthrough chunks it picks for incompressible
/// data — those leave the LZMA model un-allocated, which means
/// the per-LZMA2-chunk `frame_boundary` advance never fires).
/// Mirrors `tests/test_xz_native.rs::build_lzma_friendly_input`.
fn build_lzma_friendly_input(len: usize) -> Vec<u8> {
    let lines: &[&[u8]] = &[
        b"the quick brown fox jumps over the lazy dog ",
        b"alpha bravo charlie delta echo foxtrot golf ",
        b"every good boy deserves favor and this is line ",
        b"the rain in spain falls mainly on the plain ",
        b"to be or not to be that is the question whether ",
        b"in the beginning was the word and the word was with ",
    ];
    let mut out = Vec::with_capacity(len);
    let mut state: u32 = 0x1234_5678;
    while out.len() < len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let line = lines[(state >> 24) as usize % lines.len()];
        out.extend_from_slice(line);
        let digits = state % 1_000_000;
        out.extend_from_slice(format!("{digits:06} ").as_bytes());
    }
    out.truncate(len);
    out
}

/// Build a tar archive carrying `files`, then split it across
/// `frame_count` zstd frames so the extractor observes a real
/// frame-boundary checkpoint discipline rather than just a single
/// terminal boundary.
fn build_multi_frame_zstd_tar(files: &[(&str, &[u8])], frame_count: usize) -> Vec<u8> {
    assert!(frame_count >= 1);
    let archive = build_simple_archive(files);
    let chunk = archive.len().div_ceil(frame_count).max(1);
    let mut frames: Vec<&[u8]> = Vec::new();
    let mut cursor = 0;
    while cursor < archive.len() {
        let end = (cursor + chunk).min(archive.len());
        frames.push(&archive[cursor..end]);
        cursor = end;
    }
    encode_frames(&frames)
}

/// Decode `combined` (a `.tar.zst` payload) into a fresh directory via
/// [`TarSink`] and verify every member lands intact. Asserts the
/// extractor observed at least one frame boundary and one quiescent
/// checkpoint — both the multi-frame and single-frame callers below
/// rely on per-block boundaries firing now that the hand-rolled
/// decoder is the production path.
fn run_zstd_tar_extraction(
    label: &str,
    combined: &[u8],
    files: &[(&str, &[u8])],
) -> ExtractionStats {
    let src = fresh_path(&format!("{label}_src.tar.zst"));
    let dst = fresh_path(&format!("{label}_dst"));
    let _g_src = CleanupOnDrop(src.clone());
    let _g_dst = CleanupOnDrop(dst.clone());
    fs::write(&src, combined).expect("write src");
    fs::create_dir_all(&dst).expect("create dst");

    // Two handles: one read-only that the decoder owns, one read-write
    // for hole-punching the source.
    let read_handle = fs::File::open(&src).expect("open ro");
    let rw_handle = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&src)
        .expect("open rw");

    let registry = DecoderRegistry::with_defaults();
    let factory = registry
        .factory_for_path(&src)
        .expect(".zst factory registered");
    let mut decoder: Box<dyn StreamingDecoder> = factory(Box::new(read_handle)).expect("decoder");

    let sink = TarSink::new(&dst).expect("tar sink");
    let stats = Extractor::with_defaults()
        .extract(rw_handle.as_fd(), &mut *decoder, sink, &NoopPuncher::new())
        .expect("extract");

    assert_eq!(stats.bytes_in, combined.len() as u64);
    assert!(stats.bytes_out > 0);
    assert!(stats.frame_boundaries_observed >= 1);
    assert!(stats.quiescent_checkpoints >= 1);

    for (name, expected) in files {
        let path = dst.join(name);
        let got = fs::read(&path).expect("read extracted file");
        assert_eq!(&got, expected, "contents mismatch for {name}");
    }

    stats
}

/// Run the extractor against a `.tar.zst`-shaped local file and verify
/// every file lands at the right path with the right contents.
#[test]
fn extracts_multi_frame_zstd_tar_into_directory() {
    let files: &[(&str, &[u8])] = &[
        ("alpha.txt", b"alpha contents\n"),
        ("nested/beta.bin", &[0u8, 1, 2, 3, 4, 5, 6, 7]),
        ("nested/deeper/gamma.dat", &b"gamma payload".repeat(513)[..]),
    ];
    let combined = build_multi_frame_zstd_tar(files, 3);
    run_zstd_tar_extraction("multi_frame", &combined, files);
}

/// Single-frame sibling of [`extracts_multi_frame_zstd_tar_into_directory`].
///
/// The default `zstd` CLI emits a single frame for the whole input; per
/// `internal/PLAN_zstd_block_decoder.md` Phase 9, we need an end-to-end
/// `.tar.zst` test that confirms the hand-rolled decoder advances
/// `frame_boundary` *per block* rather than only at end-of-frame.
/// Without per-block advance the extractor would never observe a
/// quiescent checkpoint inside a single-frame archive — exactly the
/// production failure that motivated this plan.
#[test]
fn extracts_single_frame_zstd_tar_into_directory() {
    let files: &[(&str, &[u8])] = &[
        ("alpha.txt", b"alpha contents\n"),
        ("nested/beta.bin", &[0u8, 1, 2, 3, 4, 5, 6, 7]),
        ("nested/deeper/gamma.dat", &b"gamma payload".repeat(513)[..]),
    ];
    let combined = build_multi_frame_zstd_tar(files, 1);
    let stats = run_zstd_tar_extraction("single_frame", &combined, files);

    // Belt-and-braces: a single-frame archive that produces *multiple*
    // quiescent checkpoints can only do so if the decoder is reporting
    // mid-frame block boundaries. The fixture is too small to force
    // multiple zstd blocks deterministically, so we only assert ≥ 1
    // here — the larger random-payload test below pins the multi-block
    // case directly.
    assert!(stats.quiescent_checkpoints >= 1);
}

/// `RawSink` end-to-end: a raw single-stream `.zst` decompressed back
/// to a file is byte-identical to the original payload.
#[test]
fn extracts_zst_to_raw_sink_byte_identical() {
    let payload = random_bytes(0x1234, 256 * 1024);
    let combined = encode_frames(&[&payload, &payload]);

    let src = fresh_path("raw_src.zst");
    let dst = fresh_path("raw_dst.bin");
    let _g_src = CleanupOnDrop(src.clone());
    let _g_dst = CleanupOnDrop(dst.clone());
    fs::write(&src, &combined).expect("write src");

    let read_handle = fs::File::open(&src).expect("ro");
    let rw_handle = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&src)
        .expect("rw");

    let registry = DecoderRegistry::with_defaults();
    let factory = registry.factory_for_path(&src).expect("registered .zst");
    let mut decoder: Box<dyn StreamingDecoder> = factory(Box::new(read_handle)).expect("decoder");

    let sink = RawSink::create(&dst).expect("raw sink");
    let _stats = Extractor::with_defaults()
        .extract(rw_handle.as_fd(), &mut *decoder, sink, &NoopPuncher::new())
        .expect("extract");

    let mut got = Vec::new();
    fs::File::open(&dst)
        .expect("open dst")
        .read_to_end(&mut got)
        .expect("read dst");
    let mut expected = payload.clone();
    expected.extend_from_slice(&payload);
    assert_eq!(got, expected);
}

/// Punching the source with the platform's default puncher must
/// preserve the source's *logical* size and must *never* grow the
/// on-disk block count. On Linux + ext4/xfs/btrfs the block count
/// strictly decreases; on filesystems that report
/// [`PunchError::Unsupported`] we accept the no-shrink path.
#[test]
fn punching_shrinks_or_preserves_source_footprint() {
    // Use random data that doesn't compress so the source has a
    // meaningful block count to begin with — the §8 demo claim is
    // about a multi-MiB archive shrinking, so put a few MiB on disk.
    let frame = random_bytes(0xF00D, 1024 * 1024);
    let combined = encode_frames(&[&frame, &frame, &frame]);
    assert!(
        combined.len() >= 2 * 1024 * 1024,
        "compressed source should be > 2 MiB to make footprint claims meaningful (got {})",
        combined.len(),
    );

    let src = fresh_path("punch_src.zst");
    let dst = fresh_path("punch_dst.bin");
    let _g_src = CleanupOnDrop(src.clone());
    let _g_dst = CleanupOnDrop(dst.clone());
    fs::write(&src, &combined).expect("write src");

    let read_handle = fs::File::open(&src).expect("ro");
    let rw_handle = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&src)
        .expect("rw");
    let logical_size_before = rw_handle.metadata().expect("meta").len();
    let blocks_before = rw_handle.metadata().expect("meta").blocks();

    let registry = DecoderRegistry::with_defaults();
    let factory = registry.factory_for_path(&src).expect(".zst registered");
    let mut decoder: Box<dyn StreamingDecoder> = factory(Box::new(read_handle)).expect("decoder");

    let sink = RawSink::create(&dst).expect("raw sink");
    let puncher = default_puncher();
    // Drive the threshold low so the in-loop punching definitely
    // fires for a multi-MiB source.
    let cfg = ExtractorConfig {
        punch_threshold: 64 * 1024,
        ..ExtractorConfig::default()
    };
    let stats: ExtractionStats = Extractor::new(cfg)
        .extract(rw_handle.as_fd(), &mut *decoder, sink, &*puncher)
        .expect("extract");

    let meta_after = rw_handle.metadata().expect("meta");
    assert_eq!(
        meta_after.len(),
        logical_size_before,
        "logical size must be preserved across punching",
    );
    assert!(
        meta_after.blocks() <= blocks_before,
        "block count must not grow (before={}, after={})",
        blocks_before,
        meta_after.blocks(),
    );

    if !stats.punch_unsupported {
        assert!(
            stats.bytes_punched > 0,
            "supporting fs should have punched at least one block",
        );
        assert!(stats.punch_calls >= 1);
    }
}

/// Wraps any [`PunchHole`] and snapshots the source file's resident
/// block count immediately *before* every punch. The first sample is
/// the file's pre-punch state; every later sample is the high-water
/// mark of the prefix that has been decoded but not yet released.
///
/// Used by [`single_frame_zstd_punches_per_block_bounded_peak`] to
/// prove the §"What this project is" guarantee — "never use more than
/// ~300 MB of disk for the compressed side" — survives even a single
/// monolithic zstd frame, the production failure mode that motivated
/// `internal/PLAN_zstd_block_decoder.md`.
struct PeakSamplingPuncher {
    inner: Box<dyn PunchHole>,
    src_path: PathBuf,
    samples_before_punch: Mutex<Vec<u64>>,
}

impl PeakSamplingPuncher {
    fn new(inner: Box<dyn PunchHole>, src_path: &Path) -> Self {
        Self {
            inner,
            src_path: src_path.to_path_buf(),
            samples_before_punch: Mutex::new(Vec::new()),
        }
    }

    fn samples(&self) -> Vec<u64> {
        self.samples_before_punch.lock().expect("lock").clone()
    }
}

impl PunchHole for PeakSamplingPuncher {
    fn punch(
        &self,
        fd: std::os::fd::BorrowedFd<'_>,
        offset: ByteOffset,
        length: u64,
    ) -> Result<(), PunchError> {
        // Snapshot the file's *physical* size in 512-byte blocks before
        // letting the underlying puncher release anything. The Mutex
        // is uncontended in this single-threaded extractor loop; using
        // it keeps the type `Send + Sync` without unsafe.
        if let Ok(meta) = fs::metadata(&self.src_path) {
            self.samples_before_punch
                .lock()
                .expect("lock")
                .push(meta.blocks());
        }
        self.inner.punch(fd, offset, length)
    }

    fn block_size_hint(&self) -> u64 {
        self.inner.block_size_hint()
    }
}

/// A single-frame `.tar.zst` carrying random (~incompressible) data
/// must still:
///
///   1. drive the puncher (`punch_calls` ≥ 2, `bytes_punched > 0`),
///   2. release most of the compressed source by end-of-extraction,
///   3. show a steady release cadence — the resident-block count
///      strictly decreases across successive punch calls, and the
///      bytes-released-per-call is on the same order as
///      `punch_threshold`. Together these two prove there is no slow
///      leak in `bytes_consumed - last_punched` as the decoder
///      advances through the single frame.
///
/// (1) and (2) are the user-visible Phase 9 fix: before the
/// hand-rolled decoder, single-frame archives skipped per-block
/// boundaries entirely and the puncher never advanced. (3) guards
/// against a regression where a future change keeps punching but the
/// `last_punched` cursor falls farther and farther behind
/// `bytes_consumed` as decoding progresses.
///
/// Note on "peak" framing: the source file is fully written to disk
/// up front (we don't simulate the streaming-download path here), so
/// the resident byte count strictly equals `EOF - last_punched` and
/// the *peak* is trivially the file size. The interesting invariant
/// is the *slope* — that `last_punched` keeps pace with
/// `bytes_consumed` — which is what (3) measures.
#[test]
fn single_frame_zstd_punches_per_block_bounded_peak() {
    // ~16 MiB of random bytes wrapped in a tar archive, then packaged
    // as a *single* zstd frame. The size needs to be well above the
    // punch threshold so we observe many punch calls firing within one
    // frame. Random data so zstd-1 can't compress it away.
    let payload = random_bytes(0xC0FFEE, 16 * 1024 * 1024);
    let files: &[(&str, &[u8])] = &[("blob.bin", &payload[..])];
    let archive = build_simple_archive(files);
    let combined = encode_frames(&[&archive]);
    let combined_len = combined.len() as u64;
    assert!(
        combined_len >= 8 * 1024 * 1024,
        "compressed source needs to be many MiB to make the bounded-peak \
         claim meaningful (got {combined_len})",
    );

    let src = fresh_path("single_frame_punch_src.tar.zst");
    let dst = fresh_path("single_frame_punch_dst");
    let _g_src = CleanupOnDrop(src.clone());
    let _g_dst = CleanupOnDrop(dst.clone());
    fs::write(&src, &combined).expect("write src");
    fs::create_dir_all(&dst).expect("create dst");

    let read_handle = fs::File::open(&src).expect("ro");
    let rw_handle = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&src)
        .expect("rw");
    let blocks_before = rw_handle.metadata().expect("meta").blocks();

    let registry = DecoderRegistry::with_defaults();
    let factory = registry
        .factory_for_path(&src)
        .expect(".zst factory registered");
    let mut decoder: Box<dyn StreamingDecoder> = factory(Box::new(read_handle)).expect("decoder");
    let sink = TarSink::new(&dst).expect("tar sink");

    // A small punch threshold so the puncher fires many times across
    // the single frame; the bounded-peak assertion below expects this
    // value in the bound.
    const PUNCH_THRESHOLD: u64 = 256 * 1024;
    let cfg = ExtractorConfig {
        punch_threshold: PUNCH_THRESHOLD,
        ..ExtractorConfig::default()
    };
    let puncher = PeakSamplingPuncher::new(default_puncher(), &src);

    let stats = Extractor::new(cfg)
        .extract(rw_handle.as_fd(), &mut *decoder, sink, &puncher)
        .expect("extract");

    let extracted = fs::read(dst.join("blob.bin")).expect("read extracted blob");
    assert_eq!(extracted, payload, "extracted payload must match input");

    if stats.punch_unsupported {
        // Filesystem doesn't support hole-punching; the bounded-peak
        // claim is a no-op. The extracted-bytes check above is still
        // load-bearing — it proves the hand-rolled decoder ran.
        return;
    }

    // (1) Puncher fired and released bytes.
    assert!(
        stats.punch_calls >= 2,
        "single-frame archive must trigger multiple per-block punches \
         (calls={}, threshold={PUNCH_THRESHOLD})",
        stats.punch_calls,
    );
    assert!(
        stats.bytes_punched > 0,
        "single-frame archive should have released compressed-side \
         blocks; got bytes_punched=0",
    );
    assert!(stats.frame_boundaries_observed >= 2);

    // (2) End-state: most of the source has been freed.
    let blocks_after = rw_handle.metadata().expect("meta").blocks();
    assert!(
        blocks_after < blocks_before / 4,
        "extraction left {blocks_after} blocks resident (was {blocks_before}); \
         expected the per-block puncher to have freed >75%",
    );

    // (3a) Resident-block count strictly decreases as punches fire —
    //      no regression where the cursor stalls and `last_punched`
    //      stops advancing while `bytes_consumed` keeps moving.
    let samples = puncher.samples();
    assert!(
        samples.len() >= 2,
        "need at least two punch samples to verify cadence (got {})",
        samples.len(),
    );
    for w in samples.windows(2) {
        assert!(
            w[1] < w[0],
            "resident-block count must strictly decrease across punch \
             calls (saw {} -> {} in samples={samples:?})",
            w[0],
            w[1],
        );
    }

    // (3b) Average bytes released per punch is on the order of
    //      `punch_threshold`. Each punch covers
    //      `[last_punched, align_down(quiescent_at, fs_block))`, which
    //      is ≥ `punch_threshold` once the threshold trigger fires.
    //      A regression where punches fire frequently but cover only
    //      a small subset of the unpunched prefix would show a much
    //      larger ratio of `combined_len / bytes_per_call`.
    let bytes_per_call = stats.bytes_punched / stats.punch_calls;
    assert!(
        bytes_per_call >= PUNCH_THRESHOLD / 2,
        "puncher fired too eagerly: bytes_per_call={bytes_per_call}, \
         threshold={PUNCH_THRESHOLD}",
    );
    assert!(
        bytes_per_call <= 8 * PUNCH_THRESHOLD,
        "puncher fell behind the decoder: bytes_per_call={bytes_per_call}, \
         threshold={PUNCH_THRESHOLD}",
    );
}

/// The extractor's stats expose enough plumbing for the §10
/// coordinator to drive a progress UI: at least one of the time fields
/// is non-zero on a non-trivial workload, and the byte counters
/// reconcile with the source/sink lengths.
#[test]
fn stats_account_for_bytes_and_time() {
    let payload = random_bytes(0xACE, 128 * 1024);
    let combined = encode_frames(&[&payload, &payload]);
    let combined_len = combined.len() as u64;

    let src = fresh_path("stats_src.zst");
    let dst = fresh_path("stats_dst.bin");
    let _g_src = CleanupOnDrop(src.clone());
    let _g_dst = CleanupOnDrop(dst.clone());
    fs::write(&src, &combined).expect("write");

    let read_handle = fs::File::open(&src).expect("ro");
    let rw = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&src)
        .expect("rw");
    let factory = DecoderRegistry::with_defaults()
        .factory_for_path(&src)
        .expect("registered");
    let mut decoder: Box<dyn StreamingDecoder> = factory(Box::new(read_handle)).expect("ctor");
    let sink = RawSink::create(&dst).expect("dst");

    let stats = Extractor::with_defaults()
        .extract(rw.as_fd(), &mut *decoder, sink, &NoopPuncher::new())
        .expect("extract");

    assert_eq!(stats.bytes_in, combined_len);
    assert_eq!(stats.bytes_out, (payload.len() * 2) as u64);
    // Decoding a 256 KiB payload through libzstd is not zero-cost: at
    // least one of the disjoint time fields must register. We don't
    // pin a lower bound — wall-clock timers are coarse — only that
    // *some* time was attributed.
    assert!(
        stats.decode_time.as_nanos() > 0
            || stats.write_time.as_nanos() > 0
            || stats.punch_time.as_nanos() > 0,
        "stats={stats:?}"
    );
}

/// A puncher that errors on the very first call (with a non-Unsupported
/// errno) propagates the failure to the caller and stops the
/// extraction. This lives in the integration suite because it
/// exercises the public API surface composed across modules.
#[test]
fn fatal_punch_error_aborts_extraction() {
    struct Boom;
    impl PunchHole for Boom {
        fn punch(
            &self,
            _fd: std::os::fd::BorrowedFd<'_>,
            offset: ByteOffset,
            length: u64,
        ) -> Result<(), PunchError> {
            Err(PunchError::Io {
                offset: offset.get(),
                length,
                source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
            })
        }
        fn block_size_hint(&self) -> u64 {
            4096
        }
    }

    let payload = random_bytes(0xBADD, 256 * 1024);
    let combined = encode_frames(&[&payload, &payload]);

    let src = fresh_path("boom_src.zst");
    let dst = fresh_path("boom_dst.bin");
    let _g_src = CleanupOnDrop(src.clone());
    let _g_dst = CleanupOnDrop(dst.clone());
    fs::write(&src, &combined).expect("write");

    let read_handle = fs::File::open(&src).expect("ro");
    let rw = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&src)
        .expect("rw");
    let factory = DecoderRegistry::with_defaults()
        .factory_for_path(&src)
        .expect("registered");
    let mut decoder: Box<dyn StreamingDecoder> = factory(Box::new(read_handle)).expect("ctor");
    let sink = RawSink::create(&dst).expect("dst");

    let cfg = ExtractorConfig {
        punch_threshold: 4096,
        ..ExtractorConfig::default()
    };
    let result = Extractor::new(cfg).extract(rw.as_fd(), &mut *decoder, sink, &Boom);
    match result {
        Err(peel::extractor::ExtractorError::Punch { .. }) => {}
        other => panic!("expected ExtractorError::Punch, got {other:?}"),
    }
}

/// Single-Block xz sibling of
/// [`extracts_single_frame_zstd_tar_into_directory`]. `xz` CLI
/// at default settings emits a single Block (and a single
/// Stream) for any input that fits in dict_size; per
/// `internal/PLAN_xz_block_decoder.md` Phase 8, this is the shape
/// where the wrapper used to expose only end-of-Stream
/// `frame_boundary` advances and never punch the source mid-
/// extraction. The hand-rolled decoder advances per LZMA2 chunk
/// so the extractor sees multiple quiescent checkpoints inside
/// the single Block.
#[test]
fn extracts_single_block_xz_tar_into_directory() {
    let files: &[(&str, &[u8])] = &[
        ("alpha.txt", b"alpha contents\n"),
        ("nested/beta.bin", &[0u8, 1, 2, 3, 4, 5, 6, 7]),
        ("nested/deeper/gamma.dat", &b"gamma payload".repeat(513)[..]),
    ];
    let archive = build_simple_archive(files);
    let combined = xz2_encode_single_block(&archive, 6);

    let src = fresh_path("single_block_xz_src.tar.xz");
    let dst = fresh_path("single_block_xz_dst");
    let _g_src = CleanupOnDrop(src.clone());
    let _g_dst = CleanupOnDrop(dst.clone());
    fs::write(&src, &combined).expect("write src");
    fs::create_dir_all(&dst).expect("create dst");

    let read_handle = fs::File::open(&src).expect("ro");
    let rw_handle = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&src)
        .expect("rw");

    let registry = DecoderRegistry::with_defaults();
    let factory = registry.factory_for_path(&src).expect(".xz registered");
    let mut decoder: Box<dyn StreamingDecoder> = factory(Box::new(read_handle)).expect("decoder");
    let sink = TarSink::new(&dst).expect("tar sink");
    let stats = Extractor::with_defaults()
        .extract(rw_handle.as_fd(), &mut *decoder, sink, &NoopPuncher::new())
        .expect("extract");

    for (name, expected) in files {
        let path = dst.join(name);
        let got = fs::read(&path).expect("read extracted file");
        assert_eq!(&got, expected, "contents mismatch for {name}");
    }
    assert_eq!(stats.bytes_in, combined.len() as u64);
    assert!(stats.bytes_out > 0);
    // Single-Block streams stamp at least the end-of-Stream
    // frame boundary; the per-LZMA2-chunk-bounded test below
    // pins the multi-chunk case directly.
    assert!(stats.frame_boundaries_observed >= 1);
    assert!(stats.quiescent_checkpoints >= 1);
}

/// A single-Block `.tar.xz` carrying many MiB of LZMA-friendly
/// content must:
///
///   1. drive the puncher (`punch_calls` ≥ 2, `bytes_punched > 0`),
///   2. release most of the compressed source by end-of-extraction,
///   3. show a steady release cadence — the resident-block count
///      strictly decreases across successive punch calls.
///
/// Phase 8 of `internal/PLAN_xz_block_decoder.md` calls this out as
/// the user-visible win: before the hand-rolled decoder, this
/// shape skipped per-block boundaries entirely and the puncher
/// never advanced. Mirrors the zstd analog
/// [`single_frame_zstd_punches_per_block_bounded_peak`] above
/// — same input class (LZMA-friendly text, ~16 MiB), same
/// invariants (`punch_calls`, monotonic-decrease across
/// samples, bounded `bytes_per_call`).
///
/// Note on "peak" framing: the source file is fully written to
/// disk up front (we don't simulate the streaming-download path
/// here), so the resident byte count equals
/// `EOF - last_punched`; the *peak* of that quantity is
/// trivially the file size. The interesting invariant is the
/// *slope* — that `last_punched` keeps pace with
/// `bytes_consumed` — which is what (3) measures.
#[test]
fn single_block_xz_punches_per_chunk_bounded_peak() {
    // ~16 MiB LZMA-friendly content packed into a tar archive.
    // Compressible enough that xz picks LZMA chunks (not the
    // uncompressed-passthrough chunks that would leave the
    // LZMA model un-allocated and silence per-chunk
    // `frame_boundary` advances), big enough that the
    // compressed source is many MiB and the puncher fires
    // multiple times within the single Block.
    let payload = build_lzma_friendly_input(16 * 1024 * 1024);
    let files: &[(&str, &[u8])] = &[("blob.txt", &payload[..])];
    let archive = build_simple_archive(files);
    let combined = xz2_encode_single_block(&archive, 6);
    let combined_len = combined.len() as u64;
    assert!(
        combined_len >= 1024 * 1024,
        "compressed source needs to be many MiB to make the bounded-peak \
         claim meaningful (got {combined_len})",
    );

    let src = fresh_path("single_block_xz_punch_src.tar.xz");
    let dst = fresh_path("single_block_xz_punch_dst");
    let _g_src = CleanupOnDrop(src.clone());
    let _g_dst = CleanupOnDrop(dst.clone());
    fs::write(&src, &combined).expect("write src");
    fs::create_dir_all(&dst).expect("create dst");

    let read_handle = fs::File::open(&src).expect("ro");
    let rw_handle = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&src)
        .expect("rw");
    let blocks_before = rw_handle.metadata().expect("meta").blocks();

    let registry = DecoderRegistry::with_defaults();
    let factory = registry.factory_for_path(&src).expect(".xz registered");
    let mut decoder: Box<dyn StreamingDecoder> = factory(Box::new(read_handle)).expect("decoder");
    let sink = TarSink::new(&dst).expect("tar sink");

    const PUNCH_THRESHOLD: u64 = 256 * 1024;
    let cfg = ExtractorConfig {
        punch_threshold: PUNCH_THRESHOLD,
        ..ExtractorConfig::default()
    };
    let puncher = PeakSamplingPuncher::new(default_puncher(), &src);

    let stats = Extractor::new(cfg)
        .extract(rw_handle.as_fd(), &mut *decoder, sink, &puncher)
        .expect("extract");

    let extracted = fs::read(dst.join("blob.txt")).expect("read extracted blob");
    assert_eq!(extracted, payload, "extracted payload must match input");

    if stats.punch_unsupported {
        return;
    }

    // (1) Puncher fired and released bytes.
    assert!(
        stats.punch_calls >= 2,
        "single-Block xz archive must trigger multiple per-chunk punches \
         (calls={}, threshold={PUNCH_THRESHOLD})",
        stats.punch_calls,
    );
    assert!(
        stats.bytes_punched > 0,
        "single-Block xz archive should have released compressed-side \
         blocks; got bytes_punched=0",
    );
    assert!(stats.frame_boundaries_observed >= 2);

    // (2) End-state: most of the source has been freed.
    let blocks_after = rw_handle.metadata().expect("meta").blocks();
    assert!(
        blocks_after < blocks_before / 4,
        "extraction left {blocks_after} blocks resident (was {blocks_before}); \
         expected the per-chunk puncher to have freed >75%",
    );

    // (3) Resident-block count strictly decreases across punch
    //     samples — guards against a regression where the
    //     puncher fires but `last_punched` stops advancing as
    //     `bytes_consumed` keeps moving.
    let samples = puncher.samples();
    assert!(
        samples.len() >= 2,
        "need at least two punch samples to verify cadence (got {})",
        samples.len(),
    );
    for w in samples.windows(2) {
        assert!(
            w[1] < w[0],
            "resident-block count must strictly decrease across punch \
             calls (saw {} -> {} in samples={samples:?})",
            w[0],
            w[1],
        );
    }

    // Average bytes per call within the same band the zstd
    // analog asserts. Tighter on the upper bound here because
    // xz's LZMA2 chunks are smaller than zstd's blocks at the
    // same compression preset, so each punch covers a smaller
    // span — but it should still be at least the threshold.
    let bytes_per_call = stats.bytes_punched / stats.punch_calls;
    assert!(
        bytes_per_call >= PUNCH_THRESHOLD / 2,
        "puncher fired too eagerly: bytes_per_call={bytes_per_call}, \
         threshold={PUNCH_THRESHOLD}",
    );
    assert!(
        bytes_per_call <= 8 * PUNCH_THRESHOLD,
        "puncher fell behind the decoder: bytes_per_call={bytes_per_call}, \
         threshold={PUNCH_THRESHOLD}",
    );
}

/// Single-member `.tar.gz` decodes byte-identical via the
/// hand-rolled gzip wrapper. Sibling of
/// [`extracts_single_frame_zstd_tar_into_directory`] — pins the
/// Phase 8 registry swap (`crate::decode::gzip` re-exports the
/// hand-rolled `deflate_native::gzip` factory) and the
/// per-deflate-block `frame_boundary` advance through the
/// extractor's quiescent-checkpoint loop. A pre-Phase-8 build
/// would have decoded byte-identically too (the `flate2`-based
/// wrapper produced the same output bytes), but would have
/// observed `quiescent_checkpoints == 1` (only the final
/// member-end boundary). The Phase 10 contract is that
/// intermediate deflate-block boundaries inside the single
/// member fire as quiescent checkpoints — proving the new
/// hand-rolled decoder is the production path.
#[test]
fn extracts_single_member_tar_gz_into_directory() {
    let files: &[(&str, &[u8])] = &[
        ("alpha.txt", b"alpha contents\n"),
        ("nested/beta.bin", &[0u8, 1, 2, 3, 4, 5, 6, 7]),
        ("nested/deeper/gamma.dat", &b"gamma payload".repeat(513)[..]),
    ];
    let archive = build_simple_archive(files);
    let combined = encode_gzip_single_member(&archive);

    let src = fresh_path("single_member_gzip_src.tar.gz");
    let dst = fresh_path("single_member_gzip_dst");
    let _g_src = CleanupOnDrop(src.clone());
    let _g_dst = CleanupOnDrop(dst.clone());
    fs::write(&src, &combined).expect("write src");
    fs::create_dir_all(&dst).expect("create dst");

    let read_handle = fs::File::open(&src).expect("open ro");
    let rw_handle = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&src)
        .expect("open rw");

    let registry = DecoderRegistry::with_defaults();
    let factory = registry
        .factory_for_path(&src)
        .expect(".tar.gz factory registered");
    let mut decoder: Box<dyn StreamingDecoder> = factory(Box::new(read_handle)).expect("decoder");
    let sink = TarSink::new(&dst).expect("tar sink");

    let stats = Extractor::with_defaults()
        .extract(rw_handle.as_fd(), &mut *decoder, sink, &NoopPuncher::new())
        .expect("extract");

    assert_eq!(stats.bytes_in, combined.len() as u64);
    assert!(stats.bytes_out > 0);
    // Per-member granularity stamps at least the end-of-member
    // frame boundary; per-deflate-block (`internal/PLAN_deflate_block_decoder.md`
    // Phase 7) stamps every intermediate block boundary too. The
    // small fixture above doesn't force flate2 into multi-block
    // emission, so we only assert ≥ 1 here — the larger
    // hole-punching test below pins the multi-block case.
    assert!(stats.frame_boundaries_observed >= 1);
    assert!(stats.quiescent_checkpoints >= 1);

    for (name, expected) in files {
        let path = dst.join(name);
        let got = fs::read(&path).expect("read extracted file");
        assert_eq!(&got, expected, "contents mismatch for {name}");
    }
}

/// A single-member `.tar.gz` carrying many MiB of LZMA-friendly
/// content (compressible enough that miniz_oxide emits multiple
/// deflate blocks per member) must:
///
///   1. drive the puncher (`punch_calls` ≥ 2, `bytes_punched > 0`),
///   2. release most of the compressed source by end-of-extraction,
///   3. show a steady release cadence — the resident-block count
///      strictly decreases across successive punch calls.
///
/// Phase 8 / 10 of `internal/PLAN_deflate_block_decoder.md` calls
/// this out as the user-visible win: before the hand-rolled
/// decoder, this shape (a real-world `.tar.gz`) skipped per-block
/// boundaries entirely and the puncher only fired once at
/// end-of-member. Mirrors the zstd analog
/// [`single_frame_zstd_punches_per_block_bounded_peak`] and the
/// xz analog [`single_block_xz_punches_per_chunk_bounded_peak`]
/// — same input class (LZMA-friendly text, ~16 MiB), same
/// invariants. The deflate sliding window is fixed at 32 KiB
/// (vs zstd's `windowLog ≤ 27` and xz's `dict_size ≤ 64 MiB`) so
/// the resident-block bound is structurally tighter, but the
/// per-call shape we assert below matches the other two.
///
/// Note on "peak" framing: same as the zstd / xz analogs — the
/// source file is fully on disk up front, so the resident byte
/// count is `EOF - last_punched`. The interesting invariant is
/// the *slope* — that `last_punched` keeps pace with
/// `bytes_consumed` — which (3) measures.
#[test]
fn single_member_gzip_punches_per_block_bounded_peak() {
    let payload = build_lzma_friendly_input(16 * 1024 * 1024);
    let files: &[(&str, &[u8])] = &[("blob.txt", &payload[..])];
    let archive = build_simple_archive(files);
    let combined = encode_gzip_single_member(&archive);
    let combined_len = combined.len() as u64;
    assert!(
        combined_len >= 1024 * 1024,
        "compressed source needs to be many MiB to make the bounded-peak \
         claim meaningful (got {combined_len})",
    );

    let src = fresh_path("single_member_gzip_punch_src.tar.gz");
    let dst = fresh_path("single_member_gzip_punch_dst");
    let _g_src = CleanupOnDrop(src.clone());
    let _g_dst = CleanupOnDrop(dst.clone());
    fs::write(&src, &combined).expect("write src");
    fs::create_dir_all(&dst).expect("create dst");

    let read_handle = fs::File::open(&src).expect("ro");
    let rw_handle = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&src)
        .expect("rw");
    let blocks_before = rw_handle.metadata().expect("meta").blocks();

    let registry = DecoderRegistry::with_defaults();
    let factory = registry.factory_for_path(&src).expect(".tar.gz registered");
    let mut decoder: Box<dyn StreamingDecoder> = factory(Box::new(read_handle)).expect("decoder");
    let sink = TarSink::new(&dst).expect("tar sink");

    const PUNCH_THRESHOLD: u64 = 256 * 1024;
    let cfg = ExtractorConfig {
        punch_threshold: PUNCH_THRESHOLD,
        ..ExtractorConfig::default()
    };
    let puncher = PeakSamplingPuncher::new(default_puncher(), &src);

    let stats = Extractor::new(cfg)
        .extract(rw_handle.as_fd(), &mut *decoder, sink, &puncher)
        .expect("extract");

    let extracted = fs::read(dst.join("blob.txt")).expect("read extracted blob");
    assert_eq!(extracted, payload, "extracted payload must match input");

    if stats.punch_unsupported {
        return;
    }

    assert!(
        stats.punch_calls >= 2,
        "single-member tar.gz must trigger multiple per-block punches \
         (calls={}, threshold={PUNCH_THRESHOLD})",
        stats.punch_calls,
    );
    assert!(
        stats.bytes_punched > 0,
        "single-member tar.gz should have released compressed-side \
         blocks; got bytes_punched=0",
    );
    assert!(stats.frame_boundaries_observed >= 2);

    let blocks_after = rw_handle.metadata().expect("meta").blocks();
    assert!(
        blocks_after < blocks_before / 4,
        "extraction left {blocks_after} blocks resident (was {blocks_before}); \
         expected the per-deflate-block puncher to have freed >75%",
    );

    let samples = puncher.samples();
    assert!(
        samples.len() >= 2,
        "need at least two punch samples to verify cadence (got {})",
        samples.len(),
    );
    for w in samples.windows(2) {
        assert!(
            w[1] < w[0],
            "resident-block count must strictly decrease across punch \
             calls (saw {} -> {} in samples={samples:?})",
            w[0],
            w[1],
        );
    }

    let bytes_per_call = stats.bytes_punched / stats.punch_calls;
    assert!(
        bytes_per_call >= PUNCH_THRESHOLD / 2,
        "puncher fired too eagerly: bytes_per_call={bytes_per_call}, \
         threshold={PUNCH_THRESHOLD}",
    );
    assert!(
        bytes_per_call <= 8 * PUNCH_THRESHOLD,
        "puncher fell behind the decoder: bytes_per_call={bytes_per_call}, \
         threshold={PUNCH_THRESHOLD}",
    );
}

// ---- Raw-tar resume: decoder_position must equal sink.archive_offset ----
//
// Regression for the multi-URL raw-tar resume corruption (the "malformed
// tar header at archive offset 30749245440" bug). The IdentityDecoder
// used to report `bytes_consumed` / `frame_boundary` as its run-local
// `bytes_copied`. After the saved checkpoint loaded the sink's
// `archive_offset` from the prior run but the freshly-constructed
// decoder restarted at zero, every subsequent quiescent checkpoint
// pinned a small `source_position` against a large `archive_offset`.
// The next resume served bytes from `source_position` (small) while the
// sink expected the file body to continue at `archive_offset` (large) —
// the two cursors talked past each other and the next 512-byte block
// failed the `ustar` magic check at the resume seam.
//
// The fix routes through
// [`peel::decode::StreamingDecoder::set_source_start_offset`]: the
// coordinator calls it once after construction, the IdentityDecoder
// override seeds its `bytes_consumed` counter, and the trait contract on
// `bytes_consumed` / `frame_boundary` (a global source-byte offset, not
// a run-local count) is restored.

/// Extract `archive` with the identity decoder + the supplied tar sink,
/// capturing `(source_position, archive_offset)` from every quiescent
/// checkpoint. Returns the captured pairs along with the final
/// `ExtractionStats`.
fn run_identity_tar_with_checkpoints(
    archive: &[u8],
    start_offset: u64,
    sink: TarSink,
) -> (Vec<(u64, u64)>, ExtractionStats) {
    let captured: Mutex<Vec<(u64, u64)>> = Mutex::new(Vec::new());

    let src_path = fresh_path("identity_resume.tar");
    fs::write(&src_path, archive).expect("write src");
    let _g = CleanupOnDrop(src_path.clone());
    let read_handle = fs::File::open(&src_path).expect("open src");
    let rw_handle = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&src_path)
        .expect("open rw");

    let mut decoder: Box<dyn StreamingDecoder> = Box::new(
        peel::decode::identity::IdentityDecoder::new(Box::new(read_handle)).expect("decoder"),
    );
    decoder.set_source_start_offset(start_offset);

    let stats = Extractor::with_defaults()
        .extract_with_callback(
            rw_handle.as_fd(),
            &mut *decoder,
            sink,
            &NoopPuncher::new(),
            |info| {
                let archive_offset = match &info.sink_state {
                    peel::checkpoint::SinkState::Tar {
                        in_flight: Some(s), ..
                    } => s.archive_offset,
                    peel::checkpoint::SinkState::Tar {
                        in_flight: None, ..
                    } => 0,
                    other => panic!("expected Tar sink state, got {other:?}"),
                };
                captured
                    .lock()
                    .expect("captured lock")
                    .push((info.source_position, archive_offset));
                Ok(())
            },
        )
        .expect("extract");

    (captured.into_inner().expect("captured"), stats)
}

/// The load-bearing assertion: for raw tar (identity decode) every
/// quiescent checkpoint must have `source_position == archive_offset`.
/// Each input byte advances both counters by one, so any drift is the
/// resume bug. Verifies on a fresh run (start_offset = 0), then on a
/// mid-file resumed run (start_offset > 0) — the failure surface that
/// motivated the fix.
#[test]
fn identity_decoder_resume_keeps_decoder_position_equal_to_archive_offset() {
    use peel::sink::Sink;

    // Single member large enough to span multiple `decode_step` calls
    // (the identity decoder's per-step ceiling is 1 MiB) so several
    // quiescent checkpoints fire mid-file. The default
    // `checkpoint_min_bytes` is 0 so each step boundary is a candidate.
    let payload = random_bytes(0xA1B2_C3D4, 4 * 1024 * 1024 + 17);
    let files: &[(&str, &[u8])] = &[("big.bin", &payload)];
    let archive = build_simple_archive(files);

    // Phase 1: fresh run.
    let dst1 = fresh_path("identity_resume_phase1");
    let _g1 = CleanupOnDrop(dst1.clone());
    fs::create_dir_all(&dst1).expect("create dst1");
    let sink1 = TarSink::new(&dst1).expect("sink1");
    let (checkpoints1, stats1) = run_identity_tar_with_checkpoints(&archive, 0, sink1);

    assert!(
        !checkpoints1.is_empty(),
        "fresh run must observe at least one quiescent checkpoint",
    );
    for (i, (pos, archive_off)) in checkpoints1.iter().enumerate() {
        assert_eq!(
            *pos, *archive_off,
            "fresh-run checkpoint #{i}: source_position ({pos}) must equal \
             archive_offset ({archive_off}); identity decoder is 1:1 with \
             the source stream",
        );
    }
    assert_eq!(stats1.bytes_in, archive.len() as u64);
    assert_eq!(
        fs::read(dst1.join("big.bin")).expect("phase1 extracted"),
        payload,
    );

    // Phase 2: pick a mid-file interrupt point and capture a fresh
    // sink_state at that position. The previous extract consumed
    // `sink1`, so we feed a separate sink only the prefix.
    let interrupt_pos = checkpoints1
        .iter()
        .map(|(pos, _)| *pos)
        .find(|pos| *pos > 512 + 1024 && *pos < (archive.len() as u64).saturating_sub(1024))
        .expect("at least one mid-file checkpoint");

    let dst_resume = fresh_path("identity_resume_phase2_resume");
    let _g_resume = CleanupOnDrop(dst_resume.clone());
    fs::create_dir_all(&dst_resume).expect("create dst_resume");
    let mut prefix_sink = TarSink::new(&dst_resume).expect("prefix_sink");
    prefix_sink
        .write(&archive[..interrupt_pos as usize])
        .expect("write prefix");
    let captured_state = prefix_sink.sink_state();
    drop(prefix_sink);

    // Phase 3: build a fresh decoder over the SUFFIX of the archive,
    // seed it with the global start offset, and restore the sink from
    // the captured state. This is what the coordinator does on resume.
    let resumed_in_flight = match &captured_state {
        peel::checkpoint::SinkState::Tar {
            in_flight: Some(s), ..
        } => s.clone(),
        other => panic!("expected mid-flight tar state, got {other:?}"),
    };
    let resumed_sink = TarSink::resume(&dst_resume, &resumed_in_flight).expect("resume sink");

    let suffix = archive[interrupt_pos as usize..].to_vec();
    let (checkpoints3, stats3) =
        run_identity_tar_with_checkpoints(&suffix, interrupt_pos, resumed_sink);

    assert!(
        !checkpoints3.is_empty(),
        "resumed run must observe at least one quiescent checkpoint",
    );
    for (i, (pos, archive_off)) in checkpoints3.iter().enumerate() {
        assert_eq!(
            *pos, *archive_off,
            "resumed-run checkpoint #{i}: source_position ({pos}) must equal \
             archive_offset ({archive_off}); the resumed decoder must \
             report global offsets, not run-local bytes_copied",
        );
        assert!(
            *pos >= interrupt_pos,
            "resumed-run checkpoint #{i}: source_position ({pos}) must be at \
             or past the interrupt point ({interrupt_pos}); a smaller value \
             is the run-local-counter bug",
        );
    }
    // `bytes_in` is the decoder's high-water mark in the global
    // source — start_offset + bytes pulled this run — so a clean
    // resumed extraction lands at `archive.len()`, not `suffix.len()`.
    assert_eq!(stats3.bytes_in, archive.len() as u64);
    let final_offset = checkpoints3.last().expect("at least one").0;
    assert!(
        final_offset >= archive.len() as u64 - 1024,
        "resumed run did not reach near end-of-archive: final \
         source_position={final_offset}, archive_len={}",
        archive.len(),
    );

    // The output file must be byte-identical to the original payload.
    assert_eq!(
        fs::read(dst_resume.join("big.bin")).expect("resumed extracted"),
        payload,
    );
}
