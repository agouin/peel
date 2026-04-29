//! Integration tests for [`peel::download::SparseFile`].
//!
//! The headline test here is the §3 demo from `docs/PLAN.md`: a 1 GiB
//! sparse file, eight worker threads writing 1 MiB chunks at random
//! offsets through the `SparseFile` API, with a [`peel::bitmap::ChunkBitmap`]
//! tracking completion. We check three properties:
//!
//! 1. Every chunk written is later readable with the exact bytes the
//!    worker wrote.
//! 2. The bitmap reflects completions of every chunk and only those
//!    chunks.
//! 3. On a sparse-friendly filesystem the on-disk block count stays
//!    bounded by the data actually written, even though the logical
//!    file is 1 GiB.
//!
//! On filesystems that don't preserve sparseness (FAT, some FUSE
//! mounts) the third assertion is skipped rather than failed, mirroring
//! the policy in `tests/test_punch.rs`.

#![cfg(unix)]

use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

use peel::bitmap::ChunkBitmap;
use peel::download::{SparseFile, SparseFileError};
use peel::types::{ByteOffset, ChunkIndex};

const ONE_MIB: u64 = 1024 * 1024;
const ONE_GIB: u64 = 1024 * ONE_MIB;
const CHUNK_SIZE: u64 = ONE_MIB;
const TOTAL_CHUNKS: u32 = (ONE_GIB / CHUNK_SIZE) as u32; // 1024
const WORKER_COUNT: u32 = 8;

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
    std::env::temp_dir().join(format!("peel_sparse_it_{label}_{pid}_{nanos}_{n}.bin"))
}

struct CleanupOnDrop(PathBuf);
impl Drop for CleanupOnDrop {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Tiny LCG so the test does not depend on a PRNG crate.
struct Lcg(u64);

impl Lcg {
    fn seeded(seed: u64) -> Self {
        Self(seed ^ 0x9E37_79B9_7F4A_7C15)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }
}

/// Deterministic byte pattern keyed by chunk index, so we can verify
/// that reads at offset N return what worker writing chunk N produced.
fn fill_pattern(idx: u32, buf: &mut [u8]) {
    let mut state = u64::from(idx).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xDEAD_BEEF_CAFE_F00D;
    for chunk in buf.chunks_mut(8) {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let bytes = state.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}

/// Pick `WORKER_COUNT` distinct chunk indices in `[0, TOTAL_CHUNKS)`.
fn pick_distinct_chunks(seed: u64) -> Vec<u32> {
    let mut rng = Lcg::seeded(seed);
    let mut picks = Vec::with_capacity(WORKER_COUNT as usize);
    while picks.len() < WORKER_COUNT as usize {
        let cand = (rng.next_u64() % u64::from(TOTAL_CHUNKS)) as u32;
        if !picks.contains(&cand) {
            picks.push(cand);
        }
    }
    picks
}

#[test]
fn round_trip_write_then_read() {
    // The simplest end-to-end path: open a sparse file, write a chunk
    // to it, read it back, content matches.
    let path = unique_temp_path("round_trip");
    let _cleanup = CleanupOnDrop(path.clone());

    let f = SparseFile::open_or_create(&path, 4 * ONE_MIB).expect("open");
    let mut payload = vec![0u8; ONE_MIB as usize];
    fill_pattern(0, &mut payload);

    f.pwrite_at(ByteOffset::new(2 * ONE_MIB), &payload)
        .expect("write");

    let mut readback = vec![0u8; payload.len()];
    f.read_exact_at(ByteOffset::new(2 * ONE_MIB), &mut readback)
        .expect("read");
    assert_eq!(readback, payload);
}

#[test]
fn out_of_bounds_write_is_rejected_without_growing_file() {
    let path = unique_temp_path("oob");
    let _cleanup = CleanupOnDrop(path.clone());
    let f = SparseFile::open_or_create(&path, 1024).expect("open");

    let buf = [0u8; 64];
    let err = f
        .pwrite_at(ByteOffset::new(1000), &buf)
        .expect_err("must reject");
    assert!(matches!(err, SparseFileError::OutOfBounds { .. }));

    let meta = std::fs::metadata(&path).expect("metadata");
    assert_eq!(meta.len(), 1024, "rejected write must not grow the file");
}

#[test]
fn parallel_workers_write_a_sparse_file_and_bitmap_reflects_it() {
    // The §3 demo from docs/PLAN.md: an 8-worker download into a 1 GiB
    // sparse file at random 1 MiB offsets, with a `ChunkBitmap`
    // tracking completion. We verify content correctness, bitmap
    // correctness, and (where the FS supports it) that the on-disk
    // footprint stays close to the data actually written.
    let path = unique_temp_path("parallel_demo");
    let _cleanup = CleanupOnDrop(path.clone());

    let file = Arc::new(SparseFile::open_or_create(&path, ONE_GIB).expect("create 1 GiB"));
    let bitmap = Arc::new(ChunkBitmap::new(TOTAL_CHUNKS));
    let assignments = pick_distinct_chunks(0xCAFE_F00D);
    assert_eq!(assignments.len(), WORKER_COUNT as usize);

    thread::scope(|scope| {
        for &chunk_idx in &assignments {
            let file = Arc::clone(&file);
            let bitmap = Arc::clone(&bitmap);
            scope.spawn(move || {
                let mut payload = vec![0u8; CHUNK_SIZE as usize];
                fill_pattern(chunk_idx, &mut payload);
                let offset = ByteOffset::new(u64::from(chunk_idx) * CHUNK_SIZE);
                file.pwrite_at(offset, &payload).expect("worker write");
                bitmap.mark_complete(ChunkIndex::new(chunk_idx));
            });
        }
    });

    // 1. Bitmap correctness: exactly the assigned chunks are complete.
    assert_eq!(bitmap.count_complete(), u64::from(WORKER_COUNT));
    for i in 0..TOTAL_CHUNKS {
        let expected = assignments.contains(&i);
        assert_eq!(
            bitmap.is_complete(ChunkIndex::new(i)),
            expected,
            "bitmap mismatch at chunk {i}"
        );
    }

    // 2. Content correctness: every assigned chunk reads back exactly
    //    what its worker wrote.
    let mut readback = vec![0u8; CHUNK_SIZE as usize];
    let mut expected = vec![0u8; CHUNK_SIZE as usize];
    for &chunk_idx in &assignments {
        let offset = ByteOffset::new(u64::from(chunk_idx) * CHUNK_SIZE);
        file.read_exact_at(offset, &mut readback).expect("read");
        fill_pattern(chunk_idx, &mut expected);
        assert_eq!(readback, expected, "content mismatch at chunk {chunk_idx}");
    }

    // 3. Sparseness: bytes 0..ONE_GIB are addressable, but on disk we
    //    expect close to WORKER_COUNT * CHUNK_SIZE only. Skip if the
    //    filesystem doesn't preserve sparseness (e.g., FAT, some FUSE
    //    mounts).
    file.sync_all().expect("fsync");
    let meta = std::fs::metadata(&path).expect("metadata");
    assert_eq!(meta.len(), ONE_GIB, "logical size must be 1 GiB");

    let on_disk_bytes = meta.blocks() * 512;
    let logical_bytes = u64::from(WORKER_COUNT) * CHUNK_SIZE;
    let dense_threshold = ONE_GIB / 2;
    if on_disk_bytes >= dense_threshold {
        // Filesystem materialized the holes (or close to it). Treat as
        // a skip — the API contract is still satisfied; the host just
        // cannot demonstrate sparseness.
        return;
    }
    // Allow generous slack for filesystem metadata, journal blocks,
    // and rounding to the FS block size: 4× the logical data is
    // plenty even for ext4 / xfs / apfs / tmpfs with debug overhead.
    let upper_bound = logical_bytes.saturating_mul(4) + 4 * 1024 * 1024;
    assert!(
        on_disk_bytes <= upper_bound,
        "on-disk usage {on_disk_bytes} bytes vastly exceeds logical {logical_bytes} bytes",
    );
}
