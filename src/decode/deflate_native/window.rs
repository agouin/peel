//! 32 KiB sliding window for back-references (RFC 1951 §3.2.5).
//!
//! A deflate stream's decoded bytes are produced via two operations
//! — append literal bytes, and copy `length` bytes from `distance`
//! bytes back. Both write to the window so subsequent symbols (in
//! this block or any later block) can reference them. RFC 1951
//! caps the back-reference distance at 32 768 bytes, which is also
//! this window's [`MAX_WINDOW_SIZE`] capacity.
//!
//! # Overlap-by-design
//!
//! For `length > distance` (RFC 1951 §3.2.5), the copy "expands"
//! the window using bytes that were just written this same call.
//! The implementation handles this with a byte-wise loop:
//! `dst[head] = src[head - distance]; head++`, repeated `length`
//! times. The loop covers both the overlap and non-overlap cases at
//! the cost of throughput; Phase 11 may optimize the
//! `distance >= length` branch with `slice::copy_within`-style
//! bulk copy.
//!
//! # Streaming output
//!
//! Each `append_byte` / `append_slice` / `match_copy` call also
//! pushes the produced bytes into a caller-supplied `out: &mut
//! Vec<u8>` so the [`super::Decoder`] can flush a contiguous batch
//! to the sink at chunk granularity. This mirrors the
//! `out: &mut Vec<u8>` parameter on [`super::super::zstd::window`]'s
//! `match_copy` and avoids the need for a duplicate
//! "window-vs-staging" buffer.

use super::error::DeflateError;

/// Capacity of the deflate sliding window in bytes. Equals the
/// largest valid distance code (RFC 1951 §3.2.5: distance code 29
/// plus max extra-bits = 24 577 + 8 191 = 32 768).
pub const MAX_WINDOW_SIZE: usize = 32 * 1024;

/// Bounded ring buffer holding the most-recent decoded bytes.
///
/// Construction is infallible (no caller-supplied size — every
/// deflate stream uses the same 32 KiB window). After every
/// `append_*` or `match_copy` call, the head advances by the
/// number of bytes produced and `total_written` accumulates;
/// callers can read `total_written` to validate that a
/// back-reference distance references a byte that has actually
/// been emitted.
#[derive(Debug)]
pub struct RingWindow {
    /// Backing storage. Sized to [`MAX_WINDOW_SIZE`]; allocated as
    /// a `Box<[u8]>` so the [`Decoder`](super::Decoder) struct's
    /// stack footprint stays small while the buffer itself lives
    /// on the heap.
    buf: Box<[u8]>,
    /// Index in `buf` where the next byte will be written. Wraps
    /// around at [`MAX_WINDOW_SIZE`].
    head: usize,
    /// Total bytes ever appended to the window. Used to validate
    /// that a back-reference distance doesn't reach earlier than
    /// the stream's first decoded byte (the "underflow" case the
    /// inner block-decode surfaces as
    /// [`DeflateError::BackReferenceUnderflow`]).
    total_written: u64,
}

impl Default for RingWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl RingWindow {
    /// Construct an empty 32 KiB sliding window.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: vec![0u8; MAX_WINDOW_SIZE].into_boxed_slice(),
            head: 0,
            total_written: 0,
        }
    }

    /// Cumulative bytes ever written through [`Self::append_byte`]
    /// / [`Self::append_slice`] / [`Self::match_copy`]. Used by the
    /// inner block-decode to bounds-check distances.
    #[must_use]
    pub fn total_written(&self) -> u64 {
        self.total_written
    }

    /// Append a single literal byte to the window and stage it for
    /// sink output.
    pub fn append_byte(&mut self, b: u8, out: &mut Vec<u8>) {
        self.buf[self.head] = b;
        self.head += 1;
        if self.head == MAX_WINDOW_SIZE {
            self.head = 0;
        }
        self.total_written = self.total_written.saturating_add(1);
        out.push(b);
    }

    /// Append a contiguous byte slice to the window and stage it
    /// for sink output. When the slice would wrap past the buffer's
    /// end, the write is split into two contiguous slice copies.
    /// No allocation in the window.
    pub fn append_slice(&mut self, bytes: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(bytes);
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let space = MAX_WINDOW_SIZE - self.head;
            let take = remaining.len().min(space);
            self.buf[self.head..self.head + take].copy_from_slice(&remaining[..take]);
            self.head += take;
            if self.head == MAX_WINDOW_SIZE {
                self.head = 0;
            }
            remaining = &remaining[take..];
        }
        // INVARIANT: bytes.len() ≤ usize::MAX (slice invariant), so
        // the cast cannot truncate beyond u64 range on any platform
        // peel runs on.
        self.total_written = self.total_written.saturating_add(bytes.len() as u64);
    }

    /// Copy `length` bytes from `distance` bytes back to the head,
    /// appending the produced bytes to the window AND to `out`.
    ///
    /// Handles `length > distance` (RFC 1951 §3.2.5
    /// overlap-by-design) via a byte-wise loop. The
    /// `length <= distance` case still uses the byte-wise loop for
    /// correctness; bulk-copy optimization is deferred to Phase 11.
    ///
    /// # Errors
    ///
    /// - [`DeflateError::BackReferenceUnderflow`] if `distance == 0`,
    ///   `distance > MAX_WINDOW_SIZE`, or `distance > total_written`
    ///   (the referenced byte hasn't been decoded yet).
    pub fn match_copy(
        &mut self,
        distance: u32,
        length: u32,
        out: &mut Vec<u8>,
    ) -> Result<(), DeflateError> {
        if distance == 0 {
            return Err(DeflateError::BackReferenceUnderflow {
                distance,
                available: self.total_written,
            });
        }
        let distance_usz = distance as usize;
        if distance_usz > MAX_WINDOW_SIZE {
            return Err(DeflateError::BackReferenceUnderflow {
                distance,
                available: self.total_written,
            });
        }
        if u64::from(distance) > self.total_written {
            return Err(DeflateError::BackReferenceUnderflow {
                distance,
                available: self.total_written,
            });
        }
        // Reserve the produced bytes in `out` up-front so the hot
        // loop doesn't reallocate per byte.
        out.reserve(length as usize);
        for _ in 0..length {
            // src = (head - distance) mod MAX_WINDOW_SIZE, computed
            // without signed subtraction.
            let src = if distance_usz <= self.head {
                self.head - distance_usz
            } else {
                MAX_WINDOW_SIZE - (distance_usz - self.head)
            };
            let b = self.buf[src];
            out.push(b);
            self.buf[self.head] = b;
            self.head += 1;
            if self.head == MAX_WINDOW_SIZE {
                self.head = 0;
            }
        }
        self.total_written = self.total_written.saturating_add(u64::from(length));
        Ok(())
    }

    /// Restore the window from a snapshot taken via
    /// [`Self::recent_in_order`]. `recent` must be ≤
    /// [`MAX_WINDOW_SIZE`] bytes; `total_written` is the original
    /// cumulative byte count the resumed window should report
    /// going forward (so [`Self::match_copy`]'s
    /// distance-vs-total bounds-check stays correct after resume).
    ///
    /// Does not stage the restored bytes into any sink — the
    /// resumer has already emitted them in the original run, so
    /// re-emitting would corrupt the user's output.
    pub fn restore_from_snapshot(&mut self, recent: &[u8], total_written: u64) {
        debug_assert!(
            recent.len() <= MAX_WINDOW_SIZE,
            "RingWindow::restore_from_snapshot: snapshot longer than MAX_WINDOW_SIZE",
        );
        // Reset to a known state, then write the snapshot bytes
        // directly into the ring (no `out` staging).
        self.head = 0;
        let mut remaining = recent;
        while !remaining.is_empty() {
            let space = MAX_WINDOW_SIZE - self.head;
            let take = remaining.len().min(space);
            self.buf[self.head..self.head + take].copy_from_slice(&remaining[..take]);
            self.head += take;
            if self.head == MAX_WINDOW_SIZE {
                self.head = 0;
            }
            remaining = &remaining[take..];
        }
        // Override total_written to the resumed cumulative count.
        // Snapshot `recent.len()` may be < total_written for a
        // window that has wrapped at least once, so we can't
        // derive total_written from the snapshot alone.
        self.total_written = total_written;
    }

    /// Snapshot the most-recent `min(MAX_WINDOW_SIZE, total_written)`
    /// bytes of the window in chronological order (oldest first,
    /// newest last).
    ///
    /// Used by the Phase-7 resume blob: the saved bytes are exactly
    /// what a fresh window needs `append_slice`-ed to it to recover
    /// the same logical contents.
    #[must_use]
    pub fn recent_in_order(&self) -> Vec<u8> {
        let len = self.total_written.min(MAX_WINDOW_SIZE as u64) as usize;
        let mut out = Vec::with_capacity(len);
        if len == 0 {
            return out;
        }
        // The most-recent `len` bytes end at `head` (exclusive).
        // Compute the start by going `len` bytes back from `head`,
        // wrapping at the buffer's end.
        let start = if len <= self.head {
            self.head - len
        } else {
            MAX_WINDOW_SIZE - (len - self.head)
        };
        if start + len <= MAX_WINDOW_SIZE {
            out.extend_from_slice(&self.buf[start..start + len]);
        } else {
            // Wraps the ring: tail then head segment.
            let tail = MAX_WINDOW_SIZE - start;
            out.extend_from_slice(&self.buf[start..]);
            out.extend_from_slice(&self.buf[..len - tail]);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_window_is_empty() {
        let w = RingWindow::new();
        assert_eq!(w.total_written(), 0);
        assert!(w.recent_in_order().is_empty());
    }

    #[test]
    fn append_byte_and_match_copy_simple() {
        let mut w = RingWindow::new();
        let mut out = Vec::new();
        for &b in b"ABCDE" {
            w.append_byte(b, &mut out);
        }
        // match_copy distance=2 length=3 — last 2 bytes were "DE",
        // copy 3 bytes from 2 back wraps to "DED".
        w.match_copy(2, 3, &mut out).expect("match");
        assert_eq!(out, b"ABCDEDED");
        assert_eq!(w.total_written(), 8);
    }

    #[test]
    fn append_slice_round_trips() {
        let mut w = RingWindow::new();
        let mut out = Vec::new();
        w.append_slice(b"hello, world", &mut out);
        assert_eq!(out, b"hello, world");
        assert_eq!(w.total_written(), 12);
    }

    #[test]
    fn match_copy_distance_one_length_n_repeats_last_byte() {
        // RFC 1951 §3.2.5 overlap-by-design canonical case: a
        // single-byte literal followed by a `(distance=1,
        // length=N)` match emits `N+1` copies of the literal.
        let mut w = RingWindow::new();
        let mut out = Vec::new();
        w.append_byte(b'a', &mut out);
        w.match_copy(1, 7, &mut out).expect("match");
        assert_eq!(out, b"aaaaaaaa");
        assert_eq!(w.total_written(), 8);
    }

    #[test]
    fn match_copy_overlap_length_greater_than_distance() {
        // distance=3, length=8: literals are "abc", then copy. The
        // first 3 copy bytes are "abc"; the next 3 read from
        // positions just-written (still "abc"); etc.
        let mut w = RingWindow::new();
        let mut out = Vec::new();
        w.append_slice(b"abc", &mut out);
        w.match_copy(3, 8, &mut out).expect("match");
        assert_eq!(out, b"abcabcabcab");
    }

    #[test]
    fn match_copy_underflow_zero_distance() {
        let mut w = RingWindow::new();
        let mut out = Vec::new();
        w.append_byte(b'x', &mut out);
        match w.match_copy(0, 3, &mut out) {
            Err(DeflateError::BackReferenceUnderflow { distance, .. }) => {
                assert_eq!(distance, 0);
            }
            other => panic!("expected BackReferenceUnderflow, got {other:?}"),
        }
    }

    #[test]
    fn match_copy_underflow_distance_too_large() {
        let mut w = RingWindow::new();
        let mut out = Vec::new();
        w.append_byte(b'x', &mut out);
        // Stream has only 1 byte of history.
        match w.match_copy(2, 1, &mut out) {
            Err(DeflateError::BackReferenceUnderflow {
                distance,
                available,
                ..
            }) => {
                assert_eq!(distance, 2);
                assert_eq!(available, 1);
            }
            other => panic!("expected BackReferenceUnderflow, got {other:?}"),
        }
    }

    #[test]
    fn match_copy_underflow_distance_above_window_size() {
        let mut w = RingWindow::new();
        let mut out = Vec::new();
        // Pretend we've written 64 KiB worth (exceeds window).
        for _ in 0..(MAX_WINDOW_SIZE * 2) {
            w.append_byte(0xAB, &mut out);
        }
        // distance > MAX_WINDOW_SIZE is structurally invalid even
        // when total_written far exceeds it.
        let bogus = (MAX_WINDOW_SIZE + 1) as u32;
        match w.match_copy(bogus, 1, &mut out) {
            Err(DeflateError::BackReferenceUnderflow { distance, .. }) => {
                assert_eq!(distance, bogus);
            }
            other => panic!("expected BackReferenceUnderflow, got {other:?}"),
        }
    }

    /// Distance at exactly the window size (32 KiB) must be valid:
    /// it references the very oldest byte still in the ring.
    #[test]
    fn match_copy_max_distance_succeeds() {
        let mut w = RingWindow::new();
        let mut out = Vec::new();
        // Fill the window with a known marker, then 32 KiB of
        // padding, then back-reference at distance MAX_WINDOW_SIZE.
        // Wait: total_written must be ≥ distance, and the marker
        // must be exactly MAX_WINDOW_SIZE bytes back from the
        // current head.
        for _ in 0..(MAX_WINDOW_SIZE - 1) {
            w.append_byte(0xAB, &mut out);
        }
        w.append_byte(0xCD, &mut out);
        // total_written = MAX_WINDOW_SIZE; the byte at distance
        // MAX_WINDOW_SIZE is the very first byte we wrote (0xAB).
        out.clear();
        w.match_copy(MAX_WINDOW_SIZE as u32, 1, &mut out)
            .expect("max-distance match");
        assert_eq!(out, &[0xABu8]);
    }

    #[test]
    fn append_then_wrap_and_match_copy_across_wraparound() {
        // Fill the window past capacity to force the head to wrap.
        // Then issue a back-reference whose source byte is on the
        // far side of the wraparound — exercises the
        // `MAX_WINDOW_SIZE - (distance - head)` branch in
        // match_copy.
        let mut w = RingWindow::new();
        let mut out = Vec::new();
        w.append_byte(b'Z', &mut out); // index 0
        for _ in 0..MAX_WINDOW_SIZE {
            w.append_byte(b'.', &mut out); // pushes 'Z' out of the window slot
        }
        // Now `head` has wrapped to 1 (after MAX_WINDOW_SIZE+1 writes).
        // The byte at distance MAX_WINDOW_SIZE is at index
        // (head - MAX_WINDOW_SIZE) mod MAX_WINDOW_SIZE = (1 - 32768)
        // mod 32768 = 1, which is the byte right after 'Z' (a '.').
        out.clear();
        w.match_copy(MAX_WINDOW_SIZE as u32, 1, &mut out)
            .expect("match across wrap");
        assert_eq!(out, b".");
    }

    #[test]
    fn recent_in_order_returns_chronological_tail() {
        let mut w = RingWindow::new();
        let mut out = Vec::new();
        w.append_slice(b"alpha", &mut out);
        let recent = w.recent_in_order();
        assert_eq!(recent, b"alpha");
    }

    #[test]
    fn recent_in_order_returns_only_window_after_wrap() {
        let mut w = RingWindow::new();
        let mut out = Vec::new();
        // Fill the window past capacity so only the most-recent
        // MAX_WINDOW_SIZE bytes survive.
        for i in 0u32..((MAX_WINDOW_SIZE * 2) as u32) {
            w.append_byte((i & 0xFF) as u8, &mut out);
        }
        let recent = w.recent_in_order();
        assert_eq!(recent.len(), MAX_WINDOW_SIZE);
        // Tail equals the last MAX_WINDOW_SIZE bytes that went in.
        let expected: Vec<u8> = (0u32..((MAX_WINDOW_SIZE * 2) as u32))
            .map(|i| (i & 0xFF) as u8)
            .collect();
        assert_eq!(recent, &expected[expected.len() - MAX_WINDOW_SIZE..]);
    }

    #[test]
    fn recent_in_order_handles_wraparound_split() {
        // Push enough bytes that the chronological tail spans the
        // ring's wrap-around point. Trace `head` after each batch
        // to confirm the recent_in_order assembly stitches the two
        // segments correctly.
        let mut w = RingWindow::new();
        let mut out = Vec::new();
        // First fill: MAX - 1 bytes of 'A'. head ends at MAX-1.
        for _ in 0..(MAX_WINDOW_SIZE - 1) {
            w.append_byte(b'A', &mut out);
        }
        // Then 100 bytes of 'B' — 1 byte fits at MAX-1, 99 wrap to
        // indices 0..99. head ends at 99.
        for _ in 0..100 {
            w.append_byte(b'B', &mut out);
        }
        let recent = w.recent_in_order();
        // The full window holds (MAX - 99) 'A's followed by 100 'B's.
        // Chronologically: A...A B...B (right-to-left tail).
        assert_eq!(recent.len(), MAX_WINDOW_SIZE);
        let last_100_bs = &recent[MAX_WINDOW_SIZE - 100..];
        assert!(last_100_bs.iter().all(|&b| b == b'B'));
        let leading_as = &recent[..MAX_WINDOW_SIZE - 100];
        assert!(leading_as.iter().all(|&b| b == b'A'));
    }
}
