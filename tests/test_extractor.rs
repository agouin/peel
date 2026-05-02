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
/// `docs/PLAN_zstd_block_decoder.md` Phase 9, we need an end-to-end
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
/// `docs/PLAN_zstd_block_decoder.md`.
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
    };
    let result = Extractor::new(cfg).extract(rw.as_fd(), &mut *decoder, sink, &Boom);
    match result {
        Err(peel::extractor::ExtractorError::Punch { .. }) => {}
        other => panic!("expected ExtractorError::Punch, got {other:?}"),
    }
}
