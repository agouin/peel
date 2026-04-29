//! End-to-end integration test for [`peel::types`].
//!
//! The unit tests in `src/types.rs` cover the algebra of each type in
//! isolation; this test exercises the *public* surface across types
//! together — chunk → byte range → offset arithmetic — to catch
//! regressions where the types compose poorly.

use peel::types::{ByteOffset, ByteRange, ChunkIndex};

#[test]
fn chunk_iteration_covers_total_size_contiguously() {
    let chunk_size: u64 = 4096;
    let total: u64 = 4096 * 5 + 17; // five full chunks + a partial tail.

    let mut cursor = ByteOffset::ZERO;
    let mut idx = ChunkIndex::ZERO;
    let mut total_bytes = 0u64;

    while let Some(range) = idx.byte_range(chunk_size, total) {
        assert_eq!(range.start(), cursor, "chunks must be contiguous");
        assert!(range.end_exclusive().get() <= total);

        total_bytes += range.len();
        cursor = range.end_exclusive();
        idx = idx.checked_add(1).expect("chunk count fits in u32");
    }

    assert_eq!(cursor, ByteOffset::new(total));
    assert_eq!(total_bytes, total);
    assert_eq!(idx.get(), 6); // 5 full + 1 partial.
}

#[test]
fn byte_range_from_start_len_round_trip() {
    let start = ByteOffset::new(1_000);
    let len: u64 = 200;
    let range = ByteRange::from_start_len(start, len).expect("no overflow");

    assert_eq!(range.start(), start);
    assert_eq!(range.end_exclusive().checked_sub(start), Some(len));
    assert!(range.contains(start));
    assert!(range.contains(start.checked_add(len - 1).unwrap()));
    assert!(!range.contains(start.checked_add(len).unwrap()));
}

#[test]
fn rejecting_a_chunk_past_total_terminates_iteration() {
    // The chunk *after* the last partial chunk must report None, signalling
    // the end of the stream rather than a zero-length range.
    let chunk_size: u64 = 100;
    let total: u64 = 250;

    assert!(ChunkIndex::new(0).byte_range(chunk_size, total).is_some());
    assert!(ChunkIndex::new(1).byte_range(chunk_size, total).is_some());
    assert!(ChunkIndex::new(2).byte_range(chunk_size, total).is_some());
    assert_eq!(ChunkIndex::new(3).byte_range(chunk_size, total), None);
}
