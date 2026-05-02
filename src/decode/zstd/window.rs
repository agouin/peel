//! Sliding-window ring buffer for back-references (RFC 8478
//! §3.1.1.1.4 + §4.1.3).
//!
//! A `Compressed_Block`'s decoded bytes are produced via two
//! operations — append literal bytes, and copy `length` bytes from
//! `offset` bytes back. Both write to the window so future
//! sequences (in this block or later blocks) can reference them.
//!
//! The window's capacity is the frame header's declared
//! `Window_Size`, capped at [`MAX_WINDOW_SIZE`] (128 MiB; matches
//! the Phase-1 frame parser's `windowLog ≤ 27` policy). Once
//! `total_written` exceeds the capacity, the oldest bytes wrap
//! around; an `offset` argument larger than `capacity` is invalid.
//!
//! # Overlap-by-design
//!
//! For `match_length > offset` (RFC 8478 §3.1.1.1.4), the copy
//! "expands" the buffer using bytes that were just written this
//! same call. The implementation handles this with a byte-wise
//! loop: `dst[head] = src[head - offset]; head++`, repeated
//! `length` times. Bulk slice copy is only safe when
//! `offset >= length` (no read/write overlap), so the byte-wise
//! path covers both cases at the cost of throughput. Phase 11 may
//! optimize the non-overlap branch.

use super::error::ZstdError;

/// Largest accepted `Window_Size` (in bytes). RFC 8478 caps
/// `Window_Log` at 27, so 1 << 27 = 128 MiB. Phase 1 enforces
/// this at frame-header parse time; this constant is the same
/// limit expressed for the byte-buffer construction path.
pub const MAX_WINDOW_SIZE: u64 = 1 << 27;

/// A bounded ring buffer holding the most-recent decoded bytes.
///
/// Constructed with the frame's declared `window_size`. After
/// every `append` or `match_copy`, the head advances by the
/// number of bytes produced and `total_written` accumulates;
/// callers can use `total_written` to validate that an offset
/// references a byte that has already been emitted.
#[derive(Debug)]
pub struct SlidingWindow {
    /// Backing storage; size is exactly `capacity`.
    buf: Vec<u8>,
    /// Index in `buf` where the next byte will be written.
    /// Wraps around at `capacity`.
    head: usize,
    /// Total bytes ever appended to the window. Used to validate
    /// that an offset doesn't reach earlier than the frame's
    /// first decoded byte.
    total_written: u64,
    /// Capacity (= the frame's declared `window_size`).
    capacity: usize,
}

impl SlidingWindow {
    /// Construct a window with the declared `window_size`.
    ///
    /// # Errors
    ///
    /// - [`ZstdError::MalformedFrameHeader`] if `window_size`
    ///   is `0` or exceeds [`MAX_WINDOW_SIZE`].
    pub fn new(window_size: u64) -> Result<Self, ZstdError> {
        if window_size == 0 {
            return Err(ZstdError::MalformedFrameHeader(
                "sliding window: window_size = 0",
            ));
        }
        if window_size > MAX_WINDOW_SIZE {
            return Err(ZstdError::MalformedFrameHeader(
                "sliding window: window_size > 128 MiB",
            ));
        }
        // INVARIANT: window_size ≤ MAX_WINDOW_SIZE = 1 << 27, which
        // fits in usize on every platform peel runs on (32-bit and
        // up).
        let capacity = window_size as usize;
        Ok(Self {
            buf: vec![0u8; capacity],
            head: 0,
            total_written: 0,
            capacity,
        })
    }

    /// Capacity of the window (= the frame's `window_size`).
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Total bytes ever written to the window (cumulative across
    /// all `append`/`match_copy` calls).
    #[must_use]
    pub fn total_written(&self) -> u64 {
        self.total_written
    }

    /// Snapshot the most-recent `min(capacity, total_written)` bytes
    /// of the window in chronological order (oldest first, newest
    /// last).
    ///
    /// Used by the Phase-7 resume blob: the saved bytes are exactly
    /// what a fresh window needs `append`-ed to it to recover the
    /// same logical contents.
    #[must_use]
    pub fn recent_in_order(&self) -> Vec<u8> {
        let len = (self.total_written.min(self.capacity as u64)) as usize;
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
            self.capacity - (len - self.head)
        };
        if start + len <= self.capacity {
            out.extend_from_slice(&self.buf[start..start + len]);
        } else {
            // Wraps the ring: tail then head segment.
            let tail = self.capacity - start;
            out.extend_from_slice(&self.buf[start..]);
            out.extend_from_slice(&self.buf[..len - tail]);
        }
        out
    }

    /// Reconstruct a sliding window from a previously captured
    /// snapshot.
    ///
    /// `window_size` is the frame's declared window capacity.
    /// `total_written` is the cumulative byte count the original
    /// window had reached when the snapshot was taken (used only
    /// for match-offset bounds checking after resume — must be
    /// `>= recent.len()`). `recent` is the chronological tail of
    /// the window — the bytes returned by [`Self::recent_in_order`]
    /// — and must be `≤ window_size` bytes long.
    ///
    /// # Errors
    ///
    /// - [`ZstdError::MalformedFrameHeader`] if `window_size` is
    ///   out of range (delegated to [`Self::new`]), if
    ///   `recent.len() > window_size`, or if
    ///   `total_written < recent.len()` (the snapshot can't carry
    ///   more bytes than the window has ever seen).
    pub fn from_snapshot(
        window_size: u64,
        total_written: u64,
        recent: &[u8],
    ) -> Result<Self, ZstdError> {
        let mut window = Self::new(window_size)?;
        if recent.len() as u64 > window_size {
            return Err(ZstdError::MalformedFrameHeader(
                "sliding window resume: snapshot longer than window_size",
            ));
        }
        if total_written < recent.len() as u64 {
            return Err(ZstdError::MalformedFrameHeader(
                "sliding window resume: total_written < snapshot length",
            ));
        }
        window.append(recent);
        // `append` advanced `total_written` by `recent.len()`. Restore
        // the original counter so subsequent match-offset bounds
        // checks reflect the full pre-resume history.
        window.total_written = total_written;
        Ok(window)
    }

    /// Append `bytes` to the window, advancing the head.
    ///
    /// When the slice would wrap past the buffer's end, the write
    /// is split into two contiguous slice copies. No allocation.
    pub fn append(&mut self, bytes: &[u8]) {
        let mut remaining = bytes;
        while !remaining.is_empty() {
            let space = self.capacity - self.head;
            let take = remaining.len().min(space);
            self.buf[self.head..self.head + take].copy_from_slice(&remaining[..take]);
            self.head += take;
            if self.head == self.capacity {
                self.head = 0;
            }
            remaining = &remaining[take..];
        }
        self.total_written = self.total_written.saturating_add(bytes.len() as u64);
    }

    /// Copy `length` bytes from `offset` bytes back to the head,
    /// appending the produced bytes to the window AND to `out`.
    ///
    /// Handles `length > offset` (overlap-by-design) via a
    /// byte-wise loop. The simpler `length <= offset` case still
    /// uses the byte-wise loop for correctness; bulk-copy
    /// optimization is deferred to Phase 11.
    ///
    /// # Errors
    ///
    /// - [`ZstdError::MalformedFrameHeader`] if `offset == 0`,
    ///   `offset > capacity`, or `offset > total_written` (the
    ///   referenced byte hasn't been decoded yet).
    pub fn match_copy(
        &mut self,
        offset: u32,
        length: u32,
        out: &mut Vec<u8>,
    ) -> Result<(), ZstdError> {
        if offset == 0 {
            return Err(ZstdError::MalformedFrameHeader(
                "sliding window: match offset == 0",
            ));
        }
        let offset_usz = offset as usize;
        if offset_usz > self.capacity {
            return Err(ZstdError::MalformedFrameHeader(
                "sliding window: match offset exceeds window size",
            ));
        }
        if u64::from(offset) > self.total_written {
            return Err(ZstdError::MalformedFrameHeader(
                "sliding window: match offset references data not yet decoded",
            ));
        }
        // Reserve the produced bytes in `out` up-front so the
        // hot loop doesn't reallocate per byte.
        out.reserve(length as usize);
        for _ in 0..length {
            // src = (head - offset) mod capacity, computed without
            // signed subtraction: if head >= offset, src = head -
            // offset; else src = capacity - (offset - head).
            let src = if offset_usz <= self.head {
                self.head - offset_usz
            } else {
                self.capacity - (offset_usz - self.head)
            };
            let b = self.buf[src];
            out.push(b);
            self.buf[self.head] = b;
            self.head += 1;
            if self.head == self.capacity {
                self.head = 0;
            }
        }
        self.total_written = self.total_written.saturating_add(u64::from(length));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_zero_window() {
        match SlidingWindow::new(0) {
            Err(ZstdError::MalformedFrameHeader(_)) => {}
            other => panic!("expected malformed, got {other:?}"),
        }
    }

    #[test]
    fn new_rejects_window_above_128mib() {
        match SlidingWindow::new(MAX_WINDOW_SIZE + 1) {
            Err(ZstdError::MalformedFrameHeader(_)) => {}
            other => panic!("expected malformed, got {other:?}"),
        }
    }

    #[test]
    fn append_then_match_copy_simple() {
        // window_size = 16, append "ABCDE", then match_copy
        // offset=2 length=3 -> expect "DED" (last 2 bytes were "DE",
        // copy 3 bytes from 2 back wraps to "DED").
        let mut w = SlidingWindow::new(16).expect("new");
        w.append(b"ABCDE");
        let mut out = Vec::new();
        w.match_copy(2, 3, &mut out).expect("match");
        assert_eq!(out, b"DED");
        assert_eq!(w.total_written(), 8);
    }

    #[test]
    fn match_copy_offset_one_repeats_last_byte() {
        // offset=1, length=N produces N copies of the most-recent
        // byte (overlap-expand case).
        let mut w = SlidingWindow::new(16).expect("new");
        w.append(b"X");
        let mut out = Vec::new();
        w.match_copy(1, 5, &mut out).expect("match");
        assert_eq!(out, b"XXXXX");
        assert_eq!(w.total_written(), 6);
    }

    #[test]
    fn match_copy_overlap_length_greater_than_offset() {
        // offset=3, length=7: starting buffer "abc"; copy 3 back,
        // length 7 -> "abcabcab".. wait let's trace:
        //   step 0: head=3, src=0 -> 'a'. out="a", buf[3]='a', head=4.
        //   step 1: head=4, src=1 -> 'b'. out="ab", buf[4]='b', head=5.
        //   step 2: head=5, src=2 -> 'c'. out="abc", buf[5]='c', head=6.
        //   step 3: head=6, src=3 -> 'a' (just written). out="abca".
        //   step 4: head=7, src=4 -> 'b'. out="abcab".
        //   step 5: head=8, src=5 -> 'c'. out="abcabc".
        //   step 6: head=9, src=6 -> 'a'. out="abcabca".
        let mut w = SlidingWindow::new(16).expect("new");
        w.append(b"abc");
        let mut out = Vec::new();
        w.match_copy(3, 7, &mut out).expect("match");
        assert_eq!(out, b"abcabca");
    }

    #[test]
    fn match_copy_rejects_zero_offset() {
        let mut w = SlidingWindow::new(16).expect("new");
        w.append(b"hello");
        let mut out = Vec::new();
        match w.match_copy(0, 1, &mut out) {
            Err(ZstdError::MalformedFrameHeader(_)) => {}
            other => panic!("expected malformed, got {other:?}"),
        }
    }

    #[test]
    fn match_copy_rejects_offset_above_total_written() {
        let mut w = SlidingWindow::new(16).expect("new");
        w.append(b"ab"); // only 2 bytes decoded
        let mut out = Vec::new();
        match w.match_copy(3, 1, &mut out) {
            Err(ZstdError::MalformedFrameHeader(_)) => {}
            other => panic!("expected malformed, got {other:?}"),
        }
    }

    #[test]
    fn match_copy_rejects_offset_above_capacity() {
        let mut w = SlidingWindow::new(8).expect("new");
        w.append(&[0u8; 100]); // wrap many times; total_written=100
        let mut out = Vec::new();
        match w.match_copy(9, 1, &mut out) {
            Err(ZstdError::MalformedFrameHeader(_)) => {}
            other => panic!("expected malformed, got {other:?}"),
        }
    }

    #[test]
    fn append_wraps_around_ring() {
        // window_size = 4, append "ABCDEFG" (7 bytes). The buffer
        // ends with "DEFG" wrapped: physical buf = ['E', 'F', 'G',
        // 'D'] with head = 3 (cycled past).
        // We can't directly inspect buf, but we can validate
        // behavior through match_copy.
        let mut w = SlidingWindow::new(4).expect("new");
        w.append(b"ABCDEFG"); // total_written = 7
                              // match offset=4, length=4 -> the most-recent 4 bytes,
                              // which are "DEFG".
        let mut out = Vec::new();
        w.match_copy(4, 4, &mut out).expect("match");
        assert_eq!(out, b"DEFG");
    }

    #[test]
    fn match_copy_after_wraparound_reads_correct_byte() {
        // After wraparound, validate that match_copy still
        // resolves the right source byte across the ring boundary.
        let mut w = SlidingWindow::new(4).expect("new");
        w.append(b"ABCD"); // head wraps to 0; buf = "ABCD"
        w.append(b"EFGH"); // head wraps to 0 again; buf = "EFGH"
                           // total_written = 8. match_copy offset=4 length=4 -> "EFGH".
        let mut out = Vec::new();
        w.match_copy(4, 4, &mut out).expect("match");
        assert_eq!(out, b"EFGH");
    }

    #[test]
    fn match_copy_reaches_back_to_first_byte_of_window() {
        // window_size = 8. append 8 bytes "ABCDEFGH". Append more
        // so total_written exceeds capacity. The window now holds
        // the most-recent 8 bytes; offset=8 references 8 bytes
        // back, which is the byte at the OLDEST surviving spot.
        let mut w = SlidingWindow::new(8).expect("new");
        w.append(b"ABCDEFGH"); // head = 0 (wrapped)
        w.append(b"IJKL"); // head = 4. Buffer now: "IJKLEFGH" (logical: EFGHIJKL).
                           // total_written = 12. The most-recent 8 bytes are "EFGHIJKL".
                           // offset = 8 references the byte 8 back from the head — that's
                           // the oldest byte in the current window, which is 'E'.
        let mut out = Vec::new();
        w.match_copy(8, 4, &mut out).expect("match");
        assert_eq!(out, b"EFGH");
    }

    #[test]
    fn append_long_run_works_in_chunks() {
        // append a slice longer than capacity in one call.
        let mut w = SlidingWindow::new(4).expect("new");
        w.append(b"ABCDEFGHIJ"); // 10 bytes; capacity 4
                                 // total_written = 10. The most-recent 4 bytes are "GHIJ".
        let mut out = Vec::new();
        w.match_copy(4, 4, &mut out).expect("match");
        assert_eq!(out, b"GHIJ");
    }

    /// `recent_in_order` returns the chronological tail of the
    /// window, including across a wrap.
    #[test]
    fn recent_in_order_returns_chronological_tail() {
        let mut w = SlidingWindow::new(4).expect("new");
        w.append(b"AB");
        // Sub-capacity: tail is exactly what was appended.
        assert_eq!(w.recent_in_order(), b"AB");
        w.append(b"CDEF"); // total_written = 6 -> wraps once
                           // The most-recent 4 bytes in chronological order are "CDEF".
        assert_eq!(w.recent_in_order(), b"CDEF");
        w.append(b"G");
        // Most-recent 4: "DEFG".
        assert_eq!(w.recent_in_order(), b"DEFG");
    }

    /// Empty window: snapshot is empty.
    #[test]
    fn recent_in_order_on_empty_window() {
        let w = SlidingWindow::new(4).expect("new");
        assert!(w.recent_in_order().is_empty());
    }

    /// `from_snapshot` round-trips: any window can be captured and
    /// rebuilt to one whose `match_copy` outputs match the original's.
    #[test]
    fn from_snapshot_round_trips_match_copy_outputs() {
        let mut original = SlidingWindow::new(8).expect("new");
        original.append(b"ABCDEFGHIJKLMN"); // wraps; total_written = 14
        let recent = original.recent_in_order();
        let total = original.total_written();
        let mut restored = SlidingWindow::from_snapshot(8, total, &recent).expect("restore");
        // Expected bytes: most-recent 8 are "GHIJKLMN".
        let mut expected = Vec::new();
        original
            .match_copy(8, 8, &mut expected)
            .expect("orig match");
        let mut got = Vec::new();
        restored.match_copy(8, 8, &mut got).expect("restored match");
        assert_eq!(got, expected);
    }

    /// `from_snapshot` rejects total_written smaller than the
    /// snapshot length.
    #[test]
    fn from_snapshot_rejects_inconsistent_total_written() {
        let r = SlidingWindow::from_snapshot(8, 1, b"AB");
        assert!(matches!(r, Err(ZstdError::MalformedFrameHeader(_))));
    }

    /// `from_snapshot` rejects snapshot longer than window_size.
    #[test]
    fn from_snapshot_rejects_oversized_snapshot() {
        let r = SlidingWindow::from_snapshot(4, 100, b"ABCDE");
        assert!(matches!(r, Err(ZstdError::MalformedFrameHeader(_))));
    }
}
