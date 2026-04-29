//! Integration tests for [`peel::bitmap::ChunkBitmap`].
//!
//! These exercise the public API across module boundaries and the
//! producer/consumer synchronization edge that workers rely on. Unit
//! tests for the bit-fiddling internals live alongside the
//! implementation in `src/bitmap.rs`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

use peel::bitmap::ChunkBitmap;
use peel::types::ChunkIndex;

#[test]
fn empty_bitmap_reports_no_completions() {
    let b = ChunkBitmap::new(0);
    assert!(b.is_empty());
    assert_eq!(b.len(), 0);
    assert_eq!(b.count_complete(), 0);
    assert_eq!(b.next_incomplete_after(ChunkIndex::ZERO), None);
}

#[test]
fn marks_visible_to_other_threads_with_release_acquire() {
    // The bitmap promises that any write a thread performs before
    // `mark_complete` is observable by another thread that sees the
    // bit set. We model the worker→consumer handoff with a separate
    // payload AtomicU64: the producer stores into it with Relaxed and
    // then marks the bit; the consumer spins on the bit and then
    // checks the payload — if the synchronization edge holds, the
    // payload is observed.
    const TRIALS: usize = 64;
    for trial in 0..TRIALS {
        let bitmap = Arc::new(ChunkBitmap::new(1));
        let payload = Arc::new(AtomicU64::new(0));
        let stamp = (trial as u64) ^ 0xA5A5_A5A5_A5A5_A5A5;

        let bitmap_p = Arc::clone(&bitmap);
        let payload_p = Arc::clone(&payload);
        let producer = thread::spawn(move || {
            payload_p.store(stamp, Ordering::Relaxed);
            bitmap_p.mark_complete(ChunkIndex::ZERO);
        });

        let bitmap_c = Arc::clone(&bitmap);
        let payload_c = Arc::clone(&payload);
        let consumer = thread::spawn(move || loop {
            if bitmap_c.is_complete(ChunkIndex::ZERO) {
                return payload_c.load(Ordering::Relaxed);
            }
            std::thread::yield_now();
        });

        producer.join().expect("producer");
        let observed = consumer.join().expect("consumer");
        assert_eq!(observed, stamp, "trial {trial}");
    }
}

#[test]
fn complete_range_then_iterate_reports_no_gaps() {
    let b = ChunkBitmap::new(257);
    b.complete_range(ChunkIndex::ZERO, ChunkIndex::new(257));
    assert_eq!(b.count_complete(), 257);

    // Walking the bitmap from any starting point yields no incomplete
    // chunks.
    for start in [0u32, 1, 63, 64, 65, 128, 256] {
        assert_eq!(b.next_incomplete_after(ChunkIndex::new(start)), None);
    }
}

#[test]
fn many_workers_partition_a_large_bitmap() {
    // Eight worker threads claim disjoint slices of a 1M-chunk bitmap
    // and concurrently flip every bit. The consumer thread (this one,
    // after join) must see every chunk complete.
    const N: u32 = 1_000_000;
    const WORKERS: u32 = 8;
    let bitmap = Arc::new(ChunkBitmap::new(N));
    let per = N / WORKERS;

    thread::scope(|scope| {
        for w in 0..WORKERS {
            let bitmap = Arc::clone(&bitmap);
            scope.spawn(move || {
                let lo = w * per;
                let hi = if w == WORKERS - 1 { N } else { (w + 1) * per };
                for i in lo..hi {
                    bitmap.mark_complete(ChunkIndex::new(i));
                }
            });
        }
    });

    assert_eq!(bitmap.count_complete(), u64::from(N));
    assert_eq!(bitmap.next_incomplete_after(ChunkIndex::ZERO), None);
}
