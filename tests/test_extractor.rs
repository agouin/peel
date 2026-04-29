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
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

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

    let src = fresh_path("multi_frame_src.tar.zst");
    let dst = fresh_path("multi_frame_dst");
    let _g_src = CleanupOnDrop(src.clone());
    let _g_dst = CleanupOnDrop(dst.clone());
    fs::write(&src, &combined).expect("write src");
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
