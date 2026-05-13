//! Variable-capacity sliding-window dictionary for RAR5 LZSS.
//!
//! RAR5's LZSS layer copies matches from a back-reference window
//! the encoder filled with previously-emitted bytes. Unlike DEFLATE
//! (fixed 32 KiB) the RAR5 file header declares a per-archive
//! capacity selector, so the dictionary's size is configurable per
//! entry. Round-one of `internal/PLAN_rar5_decoder.md` (§B1) ships the
//! ring buffer; §B2 plugs it into the LZSS dispatcher; §C1's filter
//! VM reads from it via [`Dict::copy_recent_into`]; §F1 serializes
//! the live tail for resume.
//!
//! # Capacity
//!
//! RAR5 archives in the wild use dictionaries up to ~256 MiB; the
//! format spec allows up to 4 GiB. Round-one caps construction at
//! [`MAX_DICT_BYTES`] (256 MiB) so an adversarial header can't
//! force an OOM. The cap lifts once §G profiles real corpora and
//! decides whether the > 256 MiB tail is worth supporting.
//!
//! # Overlap-by-design
//!
//! For `length > distance` the LZSS copy "expands" by reading
//! bytes that were just written this same call. The
//! [`Dict::copy_match`] loop handles this byte-wise — same shape as
//! `decode/deflate_native/window.rs` and
//! `decode/zstd::window`'s `match_copy`. Bulk-copy optimisation
//! for the `length <= distance` branch is filed for §G.

use thiserror::Error;

/// Round-one cap on dictionary size, in bytes. RAR5 archives in
/// the wild rarely exceed ~256 MiB; lifting the cap to the spec's
/// 4 GiB is filed for §G.
pub const MAX_DICT_BYTES: usize = 256 * 1024 * 1024;

/// Errors produced by [`Dict`] operations.
#[derive(Debug, Error)]
pub enum DictError {
    /// Caller asked for a dictionary larger than [`MAX_DICT_BYTES`].
    #[error(
        "RAR5 dict capacity {requested} exceeds MAX_DICT_BYTES \
         ({MAX_DICT_BYTES})"
    )]
    CapacityTooLarge {
        /// Requested capacity in bytes.
        requested: usize,
    },

    /// Caller asked for a zero-byte dictionary. RAR5 capacity
    /// selectors start at 128 KiB; zero would deadlock the LZSS
    /// dispatcher.
    #[error("RAR5 dict capacity must be > 0")]
    CapacityZero,

    /// `copy_match` was passed `distance == 0` or a `distance`
    /// greater than the bytes the dictionary has actually emitted.
    /// Both indicate a malformed bitstream.
    #[error(
        "RAR5 LZSS back-reference underflow: distance {distance}, \
         total_written {available}"
    )]
    BackReferenceUnderflow {
        /// The wire-decoded distance.
        distance: u64,
        /// Bytes the dictionary has emitted so far.
        available: u64,
    },

    /// `distance` exceeded the dictionary's capacity. Even archives
    /// whose LZSS encoder allows a 4 GiB window will refuse a
    /// distance past `capacity` — the bytes that far back have
    /// already wrapped out of the ring.
    #[error(
        "RAR5 LZSS distance {distance} exceeds dict capacity \
         {capacity}"
    )]
    DistanceExceedsCapacity {
        /// The wire-decoded distance.
        distance: u64,
        /// The dictionary's capacity in bytes.
        capacity: u64,
    },

    /// `copy_recent_into` was passed an `out` buffer larger than
    /// `min(capacity, total_written)`. Caller bug — the §C1 filter
    /// VM never asks for more bytes than it has emitted.
    #[error(
        "RAR5 dict recent-window read overruns: requested {requested}, \
         available {available}"
    )]
    RecentWindowOverrun {
        /// Bytes the caller asked for.
        requested: u64,
        /// Bytes actually present in the ring.
        available: u64,
    },
}

/// Bounded ring buffer holding the most-recent decoded bytes.
///
/// Construct with [`Dict::new`] specifying the per-entry capacity
/// (read from the file header). After each [`Self::push_literal`] /
/// [`Self::copy_match`] call, `head` advances modulo `capacity`
/// and `total_written` accumulates; the LZSS dispatcher checks
/// `total_written` to validate that a back-reference distance
/// references a byte that has actually been emitted.
#[derive(Debug)]
pub struct Dict {
    /// Backing storage. Sized to the per-entry capacity. Held as a
    /// `Box<[u8]>` so the [`crate::decode::rar_native`] decoder's
    /// stack footprint stays modest while the ring lives on the
    /// heap.
    buf: Box<[u8]>,
    /// Index in `buf` where the next byte will be written. Wraps
    /// at `capacity`.
    head: usize,
    /// Capacity in bytes (i.e. `buf.len()`). Cached for hot-path
    /// arithmetic.
    capacity: usize,
    /// Total bytes ever written. Used to bounds-check distances
    /// against the "first decoded byte" (the underflow case
    /// surfaced as [`DictError::BackReferenceUnderflow`]).
    total_written: u64,
}

impl Dict {
    /// Construct an empty dictionary of `capacity` bytes.
    ///
    /// # Errors
    ///
    /// - [`DictError::CapacityZero`] if `capacity == 0`.
    /// - [`DictError::CapacityTooLarge`] if `capacity` exceeds
    ///   [`MAX_DICT_BYTES`].
    pub fn new(capacity: usize) -> Result<Self, DictError> {
        if capacity == 0 {
            return Err(DictError::CapacityZero);
        }
        if capacity > MAX_DICT_BYTES {
            return Err(DictError::CapacityTooLarge {
                requested: capacity,
            });
        }
        Ok(Self {
            buf: vec![0u8; capacity].into_boxed_slice(),
            head: 0,
            capacity,
            total_written: 0,
        })
    }

    /// Capacity, in bytes.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Cumulative bytes ever written through [`Self::push_literal`]
    /// / [`Self::copy_match`].
    #[must_use]
    pub fn total_written(&self) -> u64 {
        self.total_written
    }

    /// Bytes currently live in the ring (i.e. recoverable by
    /// [`Self::copy_recent_into`]). Equals
    /// `min(capacity as u64, total_written)`.
    #[must_use]
    pub fn live_bytes(&self) -> u64 {
        u64::min(self.capacity as u64, self.total_written)
    }

    /// Push a literal byte into the dictionary and stage it on
    /// `out` for the sink.
    pub fn push_literal(&mut self, b: u8, out: &mut Vec<u8>) {
        self.buf[self.head] = b;
        self.head += 1;
        if self.head == self.capacity {
            self.head = 0;
        }
        self.total_written = self.total_written.saturating_add(1);
        out.push(b);
    }

    /// Copy `length` bytes from `distance` bytes back, appending
    /// the produced bytes to the dictionary AND to `out`.
    ///
    /// Handles `length > distance` (the LZSS overlap-by-design
    /// case) via a byte-wise loop.
    ///
    /// # Errors
    ///
    /// - [`DictError::BackReferenceUnderflow`] if `distance == 0`
    ///   or `distance > total_written`.
    /// - [`DictError::DistanceExceedsCapacity`] if `distance >
    ///   capacity` (the byte that far back has wrapped out of the
    ///   ring).
    pub fn copy_match(
        &mut self,
        distance: u64,
        length: u64,
        out: &mut Vec<u8>,
    ) -> Result<(), DictError> {
        if distance == 0 {
            return Err(DictError::BackReferenceUnderflow {
                distance,
                available: self.total_written,
            });
        }
        if distance > self.capacity as u64 {
            return Err(DictError::DistanceExceedsCapacity {
                distance,
                capacity: self.capacity as u64,
            });
        }
        if distance > self.total_written {
            return Err(DictError::BackReferenceUnderflow {
                distance,
                available: self.total_written,
            });
        }
        // INVARIANT: `distance <= capacity <= MAX_DICT_BYTES`, so
        // the cast is lossless on every platform peel runs on.
        let distance_usz = distance as usize;
        // Reserve up-front so the inner loop doesn't reallocate.
        let length_usz = usize::try_from(length).unwrap_or(usize::MAX);
        out.reserve(length_usz);
        for _ in 0..length_usz {
            // src = (head - distance) mod capacity, without signed
            // subtraction.
            let src = if distance_usz <= self.head {
                self.head - distance_usz
            } else {
                self.capacity - (distance_usz - self.head)
            };
            let b = self.buf[src];
            out.push(b);
            self.buf[self.head] = b;
            self.head += 1;
            if self.head == self.capacity {
                self.head = 0;
            }
        }
        self.total_written = self.total_written.saturating_add(length);
        Ok(())
    }

    /// Copy the most-recent `len` bytes (in stream order) into
    /// `out`, **without** advancing the dictionary state. Used by
    /// §C1's filter VM, which transforms a dictionary window in
    /// place after the LZSS layer has produced a contiguous run of
    /// output.
    ///
    /// `out` is overwritten with exactly `len` bytes from the
    /// dictionary's live window: the first byte in `out` is the
    /// byte emitted `len` calls ago via `push_literal`/`copy_match`;
    /// the last byte is the byte emitted most recently.
    ///
    /// # Errors
    ///
    /// - [`DictError::RecentWindowOverrun`] if `len` exceeds
    ///   [`Self::live_bytes`] (which is
    ///   `min(capacity, total_written)`).
    pub fn copy_recent_into(&self, out: &mut [u8]) -> Result<(), DictError> {
        let len = out.len() as u64;
        let live = self.live_bytes();
        if len > live {
            return Err(DictError::RecentWindowOverrun {
                requested: len,
                available: live,
            });
        }
        // The most-recent byte sits at `(head - 1) mod capacity`;
        // we want `len` bytes ending there, with `out[len - 1]` =
        // the most-recent byte.
        let len_usz = out.len();
        let start = if len_usz <= self.head {
            self.head - len_usz
        } else {
            self.capacity - (len_usz - self.head)
        };
        if start + len_usz <= self.capacity {
            // Single contiguous slice — no wrap.
            out.copy_from_slice(&self.buf[start..start + len_usz]);
        } else {
            // Wrap: high-half from `[start, capacity)` plus
            // low-half from `[0, head)`.
            let head = (start + len_usz) - self.capacity;
            let high = self.capacity - start;
            out[..high].copy_from_slice(&self.buf[start..]);
            out[high..].copy_from_slice(&self.buf[..head]);
        }
        Ok(())
    }

    /// Snapshot the dictionary's live tail in stream order.
    ///
    /// Append `min(capacity, total_written)` bytes to `out`; the
    /// first byte is the oldest-still-live byte and the last is
    /// the most recently emitted. Used by §F1's resume snapshot.
    ///
    /// Restore via [`Self::restore_from_snapshot`].
    pub fn snapshot_into(&self, out: &mut Vec<u8>) {
        let live = self.live_bytes() as usize;
        if live == 0 {
            return;
        }
        // The same logic as `copy_recent_into` but appending to a
        // `Vec` rather than overwriting an `&mut [u8]`.
        let start = if live <= self.head {
            self.head - live
        } else {
            self.capacity - (live - self.head)
        };
        out.reserve(live);
        if start + live <= self.capacity {
            out.extend_from_slice(&self.buf[start..start + live]);
        } else {
            out.extend_from_slice(&self.buf[start..]);
            let tail = (start + live) - self.capacity;
            out.extend_from_slice(&self.buf[..tail]);
        }
    }

    /// Restore the dictionary from a snapshot taken via
    /// [`Self::snapshot_into`]. `recent` must be ≤ `capacity`
    /// bytes; `total_written` is the cumulative byte count the
    /// resumed dict should report so [`Self::copy_match`]'s
    /// distance-vs-total bounds-check stays correct after resume.
    ///
    /// Does not stage the restored bytes for sink output — the
    /// resumer has already emitted them in the prior run, so
    /// re-emitting would corrupt the user's file.
    ///
    /// # Errors
    ///
    /// - [`DictError::RecentWindowOverrun`] when `recent.len() >
    ///   capacity`.
    pub fn restore_from_snapshot(
        &mut self,
        recent: &[u8],
        total_written: u64,
    ) -> Result<(), DictError> {
        if recent.len() > self.capacity {
            return Err(DictError::RecentWindowOverrun {
                requested: recent.len() as u64,
                available: self.capacity as u64,
            });
        }
        // Clear the buffer to a known state, then write the
        // snapshot bytes contiguously starting at index 0. The
        // resumed `head` points at the byte after the snapshot's
        // last byte (i.e. where the next push will land).
        for slot in &mut self.buf[..] {
            *slot = 0;
        }
        self.buf[..recent.len()].copy_from_slice(recent);
        self.head = recent.len() % self.capacity;
        self.total_written = total_written;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_zero_capacity() {
        let err = Dict::new(0).unwrap_err();
        assert!(matches!(err, DictError::CapacityZero));
    }

    #[test]
    fn new_rejects_oversized_capacity() {
        let err = Dict::new(MAX_DICT_BYTES + 1).unwrap_err();
        assert!(matches!(err, DictError::CapacityTooLarge { .. }));
    }

    #[test]
    fn push_literal_emits_byte_and_advances_head() {
        let mut dict = Dict::new(8).unwrap();
        let mut out = Vec::new();
        dict.push_literal(b'a', &mut out);
        dict.push_literal(b'b', &mut out);
        dict.push_literal(b'c', &mut out);
        assert_eq!(out, b"abc");
        assert_eq!(dict.total_written(), 3);
        assert_eq!(dict.live_bytes(), 3);
    }

    #[test]
    fn copy_match_reproduces_recent_bytes() {
        let mut dict = Dict::new(16).unwrap();
        let mut out = Vec::new();
        for &b in b"abcdef" {
            dict.push_literal(b, &mut out);
        }
        // Copy 3 bytes from 6 bytes back: should copy "abc".
        dict.copy_match(6, 3, &mut out).unwrap();
        assert_eq!(out, b"abcdefabc");
        assert_eq!(dict.total_written(), 9);
    }

    #[test]
    fn copy_match_overlap_by_design_extends_run() {
        // Classic LZSS RLE: distance=1, length=N replicates the
        // last byte N times.
        let mut dict = Dict::new(16).unwrap();
        let mut out = Vec::new();
        dict.push_literal(b'X', &mut out);
        dict.copy_match(1, 5, &mut out).unwrap();
        assert_eq!(out, b"XXXXXX");
        assert_eq!(dict.total_written(), 6);
    }

    #[test]
    fn copy_match_overlap_distance_2_creates_alternating_pattern() {
        // distance=2, length=4 with last two bytes = "ab" produces
        // "abab".
        let mut dict = Dict::new(16).unwrap();
        let mut out = Vec::new();
        dict.push_literal(b'a', &mut out);
        dict.push_literal(b'b', &mut out);
        dict.copy_match(2, 4, &mut out).unwrap();
        assert_eq!(out, b"ababab");
    }

    #[test]
    fn copy_match_rejects_zero_distance() {
        let mut dict = Dict::new(8).unwrap();
        let mut out = Vec::new();
        dict.push_literal(b'a', &mut out);
        let err = dict.copy_match(0, 1, &mut out).unwrap_err();
        assert!(matches!(err, DictError::BackReferenceUnderflow { .. }));
    }

    #[test]
    fn copy_match_rejects_distance_past_total_written() {
        // 3 bytes written; ask for distance 5 → underflow.
        let mut dict = Dict::new(16).unwrap();
        let mut out = Vec::new();
        for &b in b"abc" {
            dict.push_literal(b, &mut out);
        }
        let err = dict.copy_match(5, 1, &mut out).unwrap_err();
        match err {
            DictError::BackReferenceUnderflow {
                distance,
                available,
            } => {
                assert_eq!(distance, 5);
                assert_eq!(available, 3);
            }
            other => panic!("expected BackReferenceUnderflow, got {other:?}"),
        }
    }

    #[test]
    fn copy_match_rejects_distance_past_capacity() {
        let mut dict = Dict::new(8).unwrap();
        let mut out = Vec::new();
        // Fill more than capacity so total_written > capacity.
        for i in 0..20u8 {
            dict.push_literal(b'A' + (i % 26), &mut out);
        }
        // Distance 9 exceeds capacity 8.
        let err = dict.copy_match(9, 1, &mut out).unwrap_err();
        assert!(matches!(err, DictError::DistanceExceedsCapacity { .. }));
    }

    #[test]
    fn ring_wraps_correctly_after_capacity_overflow() {
        // capacity 4; push 6 bytes (wrap once); copy_match should
        // still reach the most-recent bytes.
        let mut dict = Dict::new(4).unwrap();
        let mut out = Vec::new();
        for &b in b"abcdef" {
            dict.push_literal(b, &mut out);
        }
        // After 6 pushes with capacity 4, the ring holds "cdef"
        // (most-recent 4 bytes). copy_match(distance=2, length=2)
        // should copy "ef".
        dict.copy_match(2, 2, &mut out).unwrap();
        assert_eq!(out, b"abcdefef");
    }

    #[test]
    fn copy_recent_into_returns_live_window() {
        let mut dict = Dict::new(8).unwrap();
        let mut out = Vec::new();
        for &b in b"abcdef" {
            dict.push_literal(b, &mut out);
        }
        let mut window = [0u8; 4];
        dict.copy_recent_into(&mut window).unwrap();
        // Most-recent 4 bytes are "cdef".
        assert_eq!(&window, b"cdef");
    }

    #[test]
    fn copy_recent_into_handles_wrap() {
        // capacity 4; fill past capacity so the live window wraps.
        let mut dict = Dict::new(4).unwrap();
        let mut out = Vec::new();
        for &b in b"abcdef" {
            dict.push_literal(b, &mut out);
        }
        // Live window is "cdef" (last 4 bytes), but they're stored
        // wrapped: ring holds [e, f, c, d] with head=2.
        let mut window = [0u8; 4];
        dict.copy_recent_into(&mut window).unwrap();
        assert_eq!(&window, b"cdef");
    }

    #[test]
    fn copy_recent_into_rejects_overrun() {
        let mut dict = Dict::new(8).unwrap();
        let mut out = Vec::new();
        for &b in b"abc" {
            dict.push_literal(b, &mut out);
        }
        // Live = 3; ask for 4.
        let mut window = [0u8; 4];
        let err = dict.copy_recent_into(&mut window).unwrap_err();
        match err {
            DictError::RecentWindowOverrun {
                requested,
                available,
            } => {
                assert_eq!(requested, 4);
                assert_eq!(available, 3);
            }
            other => panic!("expected RecentWindowOverrun, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_round_trips_pre_wrap() {
        let mut dict = Dict::new(16).unwrap();
        let mut out = Vec::new();
        for &b in b"hello" {
            dict.push_literal(b, &mut out);
        }
        let mut snap = Vec::new();
        dict.snapshot_into(&mut snap);
        assert_eq!(snap, b"hello");

        let mut restored = Dict::new(16).unwrap();
        restored.restore_from_snapshot(&snap, 5).unwrap();
        assert_eq!(restored.total_written(), 5);

        // Continue writing: copy_match should reach back into the
        // restored prefix.
        let mut out2 = Vec::new();
        restored.copy_match(5, 5, &mut out2).unwrap();
        assert_eq!(out2, b"hello");
        assert_eq!(restored.total_written(), 10);
    }

    #[test]
    fn snapshot_round_trips_post_wrap() {
        let mut dict = Dict::new(8).unwrap();
        let mut out = Vec::new();
        // Push 12 bytes — the live window holds the last 8.
        for &b in b"abcdefghIJKL" {
            dict.push_literal(b, &mut out);
        }
        assert_eq!(dict.total_written(), 12);
        let mut snap = Vec::new();
        dict.snapshot_into(&mut snap);
        assert_eq!(snap, b"efghIJKL");

        // Restore into a fresh dict.
        let mut restored = Dict::new(8).unwrap();
        restored.restore_from_snapshot(&snap, 12).unwrap();
        assert_eq!(restored.total_written(), 12);

        // Distance-from-most-recent should match the original.
        let mut out2 = Vec::new();
        restored.copy_match(8, 4, &mut out2).unwrap();
        assert_eq!(out2, b"efgh");
    }

    #[test]
    fn snapshot_of_empty_dict_is_empty() {
        let dict = Dict::new(8).unwrap();
        let mut snap = Vec::new();
        dict.snapshot_into(&mut snap);
        assert!(snap.is_empty());
    }

    #[test]
    fn restore_rejects_snapshot_larger_than_capacity() {
        let mut dict = Dict::new(8).unwrap();
        let oversized = [0u8; 16];
        let err = dict.restore_from_snapshot(&oversized, 16).unwrap_err();
        assert!(matches!(err, DictError::RecentWindowOverrun { .. }));
    }

    #[test]
    fn live_bytes_caps_at_capacity() {
        let mut dict = Dict::new(4).unwrap();
        let mut out = Vec::new();
        for &b in b"abcdefghij" {
            dict.push_literal(b, &mut out);
        }
        assert_eq!(dict.total_written(), 10);
        assert_eq!(dict.live_bytes(), 4);
    }
}
