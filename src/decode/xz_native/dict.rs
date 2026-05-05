//! LZMA sliding-window dictionary backed by a ring buffer.
//!
//! Phase 4 of `docs/PLAN_xz_block_decoder.md`. Each LZMA Block
//! carries a single dict (sized by the Block Header's `dict_size`
//! property, capped at 64 MiB by `block.rs`); the LZMA inner loop
//! drives it once per emitted byte.
//!
//! The dict serves two operations:
//!
//! - [`LzmaDict::push`]: append one byte (literal output, single-
//!   byte short-rep, or one byte of a match copy).
//! - [`LzmaDict::byte_at`]: peek the byte `n + 1` slots back from
//!   the cursor, used by the matched-literal `match_byte` lookup
//!   and as the per-step source for [`LzmaDict::match_copy`].
//!
//! Plus three accessors that exist for Phase 4's chunk-end
//! validation and Phase 6's resume-snapshot path:
//!
//! - [`LzmaDict::total`]: monotonic byte counter (Phase 4 uses it
//!   as the LZMA "position" feeding the literal-context formula
//!   and `pos_state`).
//! - [`LzmaDict::is_empty`]: whether any bytes have been pushed
//!   since construction or [`LzmaDict::reset`].
//! - [`LzmaDict::recent`]: snapshot the most recent `n` bytes for
//!   a resume blob (Phase 6).
//!
//! # Why a ring buffer
//!
//! `dict_size` is bounded by the Block Header at 64 MiB. We need
//! `byte_at(n)` for `n ∈ [0, dict_size)` with constant-time random
//! access; a ring buffer of size `dict_size` is the obvious shape.
//! Once the dict has been written `dict_size` bytes the oldest
//! byte is overwritten on the next `push`, which matches LZMA's
//! "history of at most `dict_size` bytes" guarantee.
//!
//! # Power-of-two ring
//!
//! Phase 2 of [`docs/PLAN_xz_decoder_optimization.md`] rounded the
//! underlying buffer up to the next power of two. The user-visible
//! [`Self::capacity`] returns this rounded size; back-distances
//! beyond the original `dict_size` are still rejected by
//! [`Self::match_copy`]'s validation. The benefit is that
//! [`Self::byte_at`] / [`Self::push`] / `match_copy` replace
//! `% capacity` with `& (capacity - 1)`, removing a modulo from
//! the per-emitted-byte hot loop. Common preset dict sizes (4 KiB,
//! 64 KiB, 1 MiB, 8 MiB, 64 MiB) are already powers of two, so
//! this only allocates extra bytes for unusual encoder
//! configurations (worst case 2×, bounded at 128 MiB by the
//! `block.rs` 64 MiB cap).
//!
//! # The "before-start" convention
//!
//! Per the LZMA spec, when the decoder asks for a byte before the
//! start of the dictionary (e.g. `byte_at(0)` on an empty dict, or
//! the first matched-literal lookup of a Block) the return is
//! `0x00`. [`LzmaDict::byte_at`] honors this convention so
//! callers don't have to special-case "dict warm-up."

use std::io::Write;

use super::error::XzError;

/// LZMA spec floor on `dict_size`. The encoded property byte
/// 0 maps to 4 KiB; smaller dictionaries are not representable.
/// Honored at construction so `byte_at` modulo arithmetic doesn't
/// have to special-case zero-sized buffers.
pub const MIN_DICT_SIZE: usize = 4096;

/// Sliding-window LZMA dictionary.
///
/// Owns a `Box<[u8]>` of size `max(dict_size, MIN_DICT_SIZE)`
/// rounded up to the next power of two, allocated once at
/// construction. The cursor `head` points at the next position to
/// write; `total` is the monotonic count of bytes pushed since
/// construction or the last [`Self::reset`].
#[derive(Debug)]
pub struct LzmaDict {
    /// Ring buffer holding up to `buf.len()` bytes of history.
    /// `buf.len()` is always a power of two ≥ `MIN_DICT_SIZE`.
    buf: Box<[u8]>,
    /// `buf.len() - 1`. INVARIANT: `buf.len()` is a power of two
    /// so `idx & mask` is equivalent to `idx % buf.len()`.
    mask: usize,
    /// Position in `buf` where the next byte will be written
    /// (`total & mask`).
    head: usize,
    /// Maximum back-distance allowed by [`Self::match_copy`] —
    /// the constructor's `max(dict_size, MIN_DICT_SIZE)`, *before*
    /// the power-of-two rounding that bumped `buf.len()`. The LZMA
    /// spec requires `dist < dict_size`; without this, the
    /// power-of-two extension would silently expose older bytes
    /// than the encoder declared.
    declared_size: usize,
    /// Total bytes pushed since construction or last [`Self::reset`].
    total: u64,
}

impl LzmaDict {
    /// Construct a dict with the given `dict_size` (in bytes).
    /// Sizes below [`MIN_DICT_SIZE`] are rounded up — the LZMA spec
    /// allows the encoder to declare any size ≥ 4 KiB, and we
    /// honor the floor on the *runtime* allocation regardless of
    /// what the chunk declared, so the byte-at modulo math stays
    /// tractable.
    ///
    /// Phase 2 of [`docs/PLAN_xz_decoder_optimization.md`] also
    /// rounds the allocation up to the next power of two so the
    /// inner-loop indexing reduces to a mask. Common encoder
    /// presets (4 KiB / 64 KiB / 1 MiB / 8 MiB / 64 MiB) are
    /// already powers of two; arbitrary values consume up to 2×
    /// their declared size.
    #[must_use]
    pub fn new(dict_size: u32) -> Self {
        let declared_size = std::cmp::max(dict_size as usize, MIN_DICT_SIZE);
        let capacity = declared_size.next_power_of_two();
        // INVARIANT: `declared_size >= MIN_DICT_SIZE >= 4096`, so
        // `next_power_of_two` does not overflow before the
        // `block.rs` 64 MiB cap; cap+1 (worst case) is still well
        // below `usize::MAX`.
        Self {
            buf: vec![0u8; capacity].into_boxed_slice(),
            mask: capacity - 1,
            head: 0,
            declared_size,
            total: 0,
        }
    }

    /// Capacity of the ring buffer in bytes — power-of-two-rounded
    /// from the constructor's `dict_size`. Always ≥ [`MIN_DICT_SIZE`].
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    /// Bytes pushed since construction or the last reset.
    /// Monotonic; saturates at `u64::MAX` (which we will never
    /// reach in practice).
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total
    }

    /// `true` if no bytes have been pushed since construction or
    /// the last reset.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    /// Append a single byte at the cursor.
    ///
    /// Wraps around the ring buffer when `head` reaches the end.
    /// Updates `total` monotonically.
    pub fn push(&mut self, b: u8) {
        // INVARIANT: `self.head < self.buf.len()` is maintained by
        // the mask below; `buf.len()` is a power of two ≥ 4 KiB.
        self.buf[self.head] = b;
        self.head = (self.head + 1) & self.mask;
        self.total = self.total.saturating_add(1);
    }

    /// Peek the byte at offset `n + 1` back from the cursor.
    ///
    /// `byte_at(0)` returns the most recently pushed byte;
    /// `byte_at(k)` returns the byte `k + 1` back.
    ///
    /// Returns `0` if `n + 1 > total` (per the LZMA spec's "before
    /// the start of the dict, the byte is 0" convention) or if `n
    /// >= capacity` (which is a malformed-stream condition the
    /// caller should already have rejected via
    /// [`Self::match_copy`]'s distance check).
    #[must_use]
    pub fn byte_at(&self, n: u32) -> u8 {
        let needed = u64::from(n).saturating_add(1);
        if needed > self.total {
            return 0;
        }
        let n = n as usize;
        if n >= self.buf.len() {
            // Defensive: a caller asked for a distance beyond the
            // ring's capacity. `match_copy` rejects this with a
            // typed error before reaching us; returning 0 here is
            // a fallback for fuzz-style probing.
            return 0;
        }
        // Last-written byte is at `(head - 1) & mask`. Walk back
        // `n` further. The wrapping_sub keeps the math in `usize`
        // — the `& mask` immediately re-bounds it.
        let idx = self.head.wrapping_sub(1).wrapping_sub(n) & self.mask;
        self.buf[idx]
    }

    /// Copy `length` bytes from offset `dist + 1` back to the
    /// cursor. Each byte is appended to the dict (advancing the
    /// cursor) and to `out` so the caller can flush a contiguous
    /// staging region to the sink.
    ///
    /// Handles overlap-by-design: when `length > dist + 1`, each
    /// copied byte becomes part of the dict's history before the
    /// next read, naturally producing the LZMA spec's RLE-like
    /// expansion (e.g. `dist=0, length=4` repeats the last byte
    /// four times).
    ///
    /// Phase 2 of [`docs/PLAN_xz_decoder_optimization.md`]: the
    /// non-overlap branch (`length <= dist + 1`) uses bulk
    /// `copy_within` calls — one when the source range is
    /// contiguous in the ring, two when it wraps. The
    /// `dist == 0` overlap case (single-byte run) is specialized
    /// with `slice::fill`. Other overlap cases (the LZMA RLE
    /// pattern with `dist > 0` and `length > dist + 1`) keep the
    /// byte-by-byte walk — these are rare and bulk-copying them
    /// would require a periodic-pattern fold not worth the code
    /// complexity given the per-symbol attribution.
    ///
    /// # Errors
    ///
    /// - [`XzError::LzmaMatchOutOfRange`] if `dist + 1 > total`
    ///   (back-reference outside available history) or `dist >=
    ///   capacity()` (back-reference past the ring buffer).
    pub fn match_copy(&mut self, dist: u32, length: u32, out: &mut Vec<u8>) -> Result<(), XzError> {
        let needed = u64::from(dist).saturating_add(1);
        if needed > self.total || (dist as usize) >= self.declared_size {
            return Err(XzError::LzmaMatchOutOfRange {
                dist,
                total: self.total,
            });
        }
        let length = length as usize;
        let dist = dist as usize;
        if length == 0 {
            return Ok(());
        }
        // Pre-reserve once.
        out.reserve(length);

        // Source-range overlaps the destination range when
        // `length > dist + 1`. For non-overlap, copy in bulk
        // through `copy_within`. For `dist == 0` (RLE single-byte
        // run), specialize via `slice::fill`. For other overlap
        // shapes, fall back to the byte-by-byte walk.
        if length <= dist + 1 {
            self.bulk_copy_nonoverlap(dist, length, out);
        } else if dist == 0 {
            self.bulk_run_single_byte(length, out);
        } else {
            for _ in 0..length {
                let b = self.byte_at(dist as u32);
                self.push(b);
                out.push(b);
            }
        }
        Ok(())
    }

    /// Bulk match-copy fast path for the non-overlap case
    /// (`length <= dist + 1`). The source range is `length` bytes
    /// starting at `(head - 1 - dist) & mask` (inclusive) and
    /// extending forward. Splits at the ring's wrap point so each
    /// segment is contiguous in `buf`, then re-pushes the same
    /// bytes through the cursor with another contiguous write.
    fn bulk_copy_nonoverlap(&mut self, dist: usize, length: usize, out: &mut Vec<u8>) {
        let cap = self.buf.len();
        // Source's first byte index in the ring.
        let src_start = self.head.wrapping_sub(1).wrapping_sub(dist) & self.mask;
        // Destination's first byte index = current head.
        let dst_start = self.head;

        // Stage the source bytes into `out` first (one or two
        // contiguous spans), then memcpy the same bytes back into
        // the ring at `dst_start` (one or two spans). This keeps
        // the dict consistent with its byte-by-byte fallback even
        // when the source and dest spans both wrap.
        let src_first_run = std::cmp::min(length, cap - src_start);
        out.extend_from_slice(&self.buf[src_start..src_start + src_first_run]);
        if src_first_run < length {
            out.extend_from_slice(&self.buf[..length - src_first_run]);
        }

        // Now write `length` bytes from the just-staged tail of
        // `out` back into the ring at `dst_start`.
        let staged = &out[out.len() - length..];
        let dst_first_run = std::cmp::min(length, cap - dst_start);
        self.buf[dst_start..dst_start + dst_first_run].copy_from_slice(&staged[..dst_first_run]);
        if dst_first_run < length {
            self.buf[..length - dst_first_run].copy_from_slice(&staged[dst_first_run..]);
        }

        self.head = (self.head + length) & self.mask;
        self.total = self.total.saturating_add(length as u64);
    }

    /// Bulk match-copy specialization for `dist == 0` (LZMA RLE
    /// single-byte run): repeat `byte_at(0)` `length` times.
    fn bulk_run_single_byte(&mut self, length: usize, out: &mut Vec<u8>) {
        let cap = self.buf.len();
        // The byte to repeat is the most recently pushed one,
        // sitting at `(head - 1) & mask`. INVARIANT: `total > 0`
        // is guaranteed by `match_copy`'s distance check (which
        // rejects `dist + 1 > total`, i.e. `total == 0` here).
        let byte = self.buf[self.head.wrapping_sub(1) & self.mask];

        let prev_out_len = out.len();
        out.resize(prev_out_len + length, byte);

        // Fill the ring at `head` for `length` bytes, splitting
        // at the wrap point.
        let dst_start = self.head;
        let dst_first_run = std::cmp::min(length, cap - dst_start);
        self.buf[dst_start..dst_start + dst_first_run].fill(byte);
        if dst_first_run < length {
            self.buf[..length - dst_first_run].fill(byte);
        }

        self.head = (self.head + length) & self.mask;
        self.total = self.total.saturating_add(length as u64);
    }

    /// Restore the dict from a chronological byte slice and
    /// declared `total`.
    ///
    /// `bytes` is the most recent up-to-`capacity` bytes of
    /// decompressed output, oldest first; `total` is the absolute
    /// monotonic byte counter the original dict was at when the
    /// snapshot was taken (may exceed `capacity`).
    ///
    /// Used by Phase 6 resume to reconstitute a dict from its
    /// checkpoint blob. The LZMA literal-context formula and
    /// `pos_state` both depend on `total` (not just on the
    /// recent-bytes slice), so we honor the original `total` even
    /// when it exceeds `capacity` — the ring's `head` is
    /// positioned to `total % capacity` and the `bytes` are laid
    /// down such that subsequent `byte_at(0)` returns the last
    /// element of `bytes`.
    ///
    /// # Panics (debug only)
    ///
    /// `bytes.len() <= self.capacity()` and (when `total <
    /// capacity`) `bytes.len() == total as usize`.
    pub fn reload(&mut self, bytes: &[u8], total: u64) {
        debug_assert!(
            bytes.len() <= self.buf.len(),
            "reload bytes longer than capacity"
        );
        let cap = self.buf.len();
        self.total = total;
        self.head = (total & self.mask as u64) as usize;
        if bytes.is_empty() {
            return;
        }
        // The cursor sits at slot `head`; the oldest of `bytes`
        // is at slot `(head - bytes.len()) & mask`. Lay them down
        // in two contiguous slice copies split at the wrap point.
        let start_slot = self.head.wrapping_sub(bytes.len()) & self.mask;
        let first_run = std::cmp::min(bytes.len(), cap - start_slot);
        self.buf[start_slot..start_slot + first_run].copy_from_slice(&bytes[..first_run]);
        if first_run < bytes.len() {
            self.buf[..bytes.len() - first_run].copy_from_slice(&bytes[first_run..]);
        }
    }

    /// Reset the cursor and the byte counter. Used by the LZMA2
    /// chunk dispatcher when a chunk control byte requests a
    /// dictionary reset (mode `0b11`).
    ///
    /// The underlying buffer's bytes are *not* zeroed —
    /// [`Self::byte_at`] honors the "before-start" convention via
    /// the `total` check, so leftover bytes are unreachable.
    pub fn reset(&mut self) {
        self.head = 0;
        self.total = 0;
    }

    /// Number of bytes the next [`Self::recent`] /
    /// [`Self::write_recent_into`] call would emit when asked for
    /// `n` bytes — i.e. `min(n, capacity, total)`.
    #[must_use]
    pub fn recent_len(&self, n: usize) -> usize {
        let avail = std::cmp::min(self.total, self.buf.len() as u64) as usize;
        std::cmp::min(n, avail)
    }

    /// Append the most recent up-to-`n` bytes (capped at
    /// `min(total, capacity)`), in chronological order, into
    /// `out`. The fast-path companion to [`Self::recent`] used by
    /// the resume-blob writer to flow dict bytes straight from the
    /// ring into the `Checkpoint` body buffer with one memcpy.
    /// `PLAN_checkpoint_blob_dedup.md` Phase 2.
    pub fn write_recent_into(&self, n: usize, out: &mut Vec<u8>) {
        let take = self.recent_len(n);
        if take == 0 {
            return;
        }
        let cap = self.buf.len();
        // The most-recent `take` bytes end at `head` (exclusive,
        // since `head` points at the next *write* position). Walk
        // back `take` slots from `head`, wrapping at the buffer
        // start. INVARIANT: `take <= cap`, so `head.wrapping_sub(take)
        // & mask` lands in `[0, cap)`.
        let start = self.head.wrapping_sub(take) & self.mask;
        if start + take <= cap {
            // Contiguous in `buf`: one slice copy.
            out.extend_from_slice(&self.buf[start..start + take]);
        } else {
            // Wraps the ring: tail of the buffer first, then
            // head segment.
            let tail = cap - start;
            out.extend_from_slice(&self.buf[start..]);
            out.extend_from_slice(&self.buf[..take - tail]);
        }
    }

    /// Snapshot the most recent up-to-`n` bytes (capped at
    /// `min(total, capacity)`), in chronological order. Owned-`Vec`
    /// convenience over [`Self::write_recent_into`]; callers on
    /// the hot path should prefer the in-place variant.
    ///
    /// Phase 2 of `docs/PLAN_lazy_decoder_state.md`: implemented
    /// as one or two `extend_from_slice` calls split at the wrap
    /// point (mirroring
    /// [`crate::decode::zstd::window::Window::recent_in_order`]
    /// and
    /// [`crate::decode::deflate_native::window::Window::recent_in_order`]).
    /// The previous byte-by-byte walk through [`Self::byte_at`]
    /// was ~10–20 ms per call at `dict_size = 8 MiB`; the memcpy
    /// version drops that to ~50 µs (memory-bandwidth bound).
    #[must_use]
    pub fn recent(&self, n: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.recent_len(n));
        self.write_recent_into(n, &mut out);
        out
    }

    /// Convenience: append a single byte and write a one-byte
    /// payload to `sink` in the same call. Used by call sites
    /// that don't bother to maintain a staging buffer (e.g. the
    /// uncompressed-chunk path in Phase 1).
    ///
    /// # Errors
    ///
    /// - [`XzError::SinkIo`] if `sink.write_all` fails.
    pub fn push_through(&mut self, b: u8, sink: &mut dyn Write) -> Result<(), XzError> {
        self.push(b);
        sink.write_all(&[b]).map_err(XzError::SinkIo)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a single byte through `push` / `byte_at(0)`.
    #[test]
    fn push_and_byte_at_zero_returns_last_pushed() {
        let mut d = LzmaDict::new(4096);
        assert!(d.is_empty());
        d.push(b'A');
        assert_eq!(d.byte_at(0), b'A');
        assert_eq!(d.total(), 1);
        assert!(!d.is_empty());
        d.push(b'B');
        assert_eq!(d.byte_at(0), b'B');
        assert_eq!(d.byte_at(1), b'A');
        assert_eq!(d.total(), 2);
    }

    /// Before-start convention: `byte_at` returns 0 when asked
    /// for more history than has been pushed.
    #[test]
    fn byte_at_returns_zero_before_start() {
        let d = LzmaDict::new(4096);
        assert_eq!(d.byte_at(0), 0);
        assert_eq!(d.byte_at(100), 0);
        let mut d = LzmaDict::new(4096);
        d.push(b'X');
        assert_eq!(d.byte_at(0), b'X');
        assert_eq!(d.byte_at(1), 0); // only one byte pushed
        assert_eq!(d.byte_at(2), 0);
    }

    /// Ring wraparound: pushing past `capacity` overwrites the
    /// oldest byte and `byte_at(capacity - 1)` reflects the new
    /// last-position byte.
    #[test]
    fn ring_wraps_at_capacity() {
        // Capacity rounds up to MIN_DICT_SIZE (4 KiB).
        let mut d = LzmaDict::new(MIN_DICT_SIZE as u32);
        // Push exactly capacity + 1 distinct values, ending with
        // the byte at index capacity (the wrap point).
        for i in 0..=d.capacity() {
            d.push((i & 0xFF) as u8);
        }
        // The very-most-recent byte is the last-pushed one.
        assert_eq!(d.byte_at(0), (d.capacity() & 0xFF) as u8);
        // Walking `capacity - 1` back lands on the byte that
        // *wrapped*: `head + cap - 1 - (cap - 1) = head`, so we
        // sample buf[head], which is the byte we wrote one
        // wrap-step ago — the byte at index 1 (since we
        // overwrote index 0 with the cap-th byte).
        assert_eq!(d.byte_at(d.capacity() as u32 - 1), 1);
        // Byte beyond capacity falls into the "out of range"
        // path and returns 0.
        assert_eq!(d.byte_at(d.capacity() as u32), 0);
    }

    /// `match_copy` plain-mode (`length <= dist + 1`) copies a
    /// contiguous source region.
    #[test]
    fn match_copy_plain_no_overlap() {
        let mut d = LzmaDict::new(4096);
        for &b in b"ABCDEF" {
            d.push(b);
        }
        let mut out = Vec::new();
        // dist=2 → actual=3, so source is 3 bytes back from
        // cursor. After "ABCDEF", source = "DEF". Copying length=3
        // produces "DEF".
        d.match_copy(2, 3, &mut out).expect("copy");
        assert_eq!(out, b"DEF");
        assert_eq!(d.total(), 9);
        assert_eq!(d.byte_at(0), b'F');
        assert_eq!(d.byte_at(1), b'E');
        assert_eq!(d.byte_at(2), b'D');
    }

    /// `match_copy` overlap-by-design: `dist=0, length=4` repeats
    /// the last byte four times (the LZMA RLE pattern).
    #[test]
    fn match_copy_overlap_rle() {
        let mut d = LzmaDict::new(4096);
        d.push(b'X');
        let mut out = Vec::new();
        d.match_copy(0, 4, &mut out).expect("rle");
        assert_eq!(out, b"XXXX");
        assert_eq!(d.total(), 5);
    }

    /// `match_copy` overlap-by-design with a 2-byte alternation:
    /// `dist=1, length=4` over "AB" produces "ABAB".
    #[test]
    fn match_copy_overlap_alternating() {
        let mut d = LzmaDict::new(4096);
        d.push(b'A');
        d.push(b'B');
        let mut out = Vec::new();
        d.match_copy(1, 4, &mut out).expect("alt");
        assert_eq!(out, b"ABAB");
    }

    /// `match_copy` rejects a distance past available history.
    #[test]
    fn match_copy_rejects_distance_past_history() {
        let mut d = LzmaDict::new(4096);
        d.push(b'A');
        let mut out = Vec::new();
        match d.match_copy(5, 1, &mut out).unwrap_err() {
            XzError::LzmaMatchOutOfRange { dist, total } => {
                assert_eq!(dist, 5);
                assert_eq!(total, 1);
            }
            other => panic!("expected LzmaMatchOutOfRange, got {other:?}"),
        }
    }

    /// `match_copy` rejects a distance ≥ capacity even when
    /// `total` is large enough.
    #[test]
    fn match_copy_rejects_distance_past_capacity() {
        let mut d = LzmaDict::new(MIN_DICT_SIZE as u32);
        // Fill the dict.
        for _ in 0..2 * d.capacity() {
            d.push(b'.');
        }
        // Distance == capacity is past the ring's reach.
        let mut out = Vec::new();
        match d.match_copy(d.capacity() as u32, 1, &mut out).unwrap_err() {
            XzError::LzmaMatchOutOfRange { .. } => {}
            other => panic!("expected LzmaMatchOutOfRange, got {other:?}"),
        }
    }

    /// `recent(n)` returns the most recent `n` bytes
    /// chronologically — last-pushed at the end of the slice.
    #[test]
    fn recent_returns_most_recent_chronologically() {
        let mut d = LzmaDict::new(4096);
        for &b in b"hello, dict" {
            d.push(b);
        }
        // Last 5 bytes of "hello, dict" are " dict" (leading
        // space, then `d-i-c-t`).
        assert_eq!(d.recent(5), b" dict");
        assert_eq!(d.recent(11), b"hello, dict");
        // Asking for more than `total` is capped at `total`.
        assert_eq!(d.recent(20), b"hello, dict");
    }

    /// `reset` returns the dict to empty state.
    #[test]
    fn reset_returns_to_empty() {
        let mut d = LzmaDict::new(4096);
        d.push(b'X');
        d.push(b'Y');
        d.reset();
        assert!(d.is_empty());
        assert_eq!(d.total(), 0);
        assert_eq!(d.byte_at(0), 0);
        // Pushing after reset starts at position 0 again.
        d.push(b'Z');
        assert_eq!(d.byte_at(0), b'Z');
        assert_eq!(d.total(), 1);
    }

    /// `recent` after wraparound still walks the ring correctly.
    #[test]
    fn recent_after_wraparound() {
        let mut d = LzmaDict::new(MIN_DICT_SIZE as u32);
        // Push capacity * 2 bytes; the dict only holds the last
        // `capacity` of them.
        for i in 0..(d.capacity() * 2) {
            d.push((i & 0xFF) as u8);
        }
        let recent = d.recent(d.capacity());
        assert_eq!(recent.len(), d.capacity());
        // The most recent byte is the last-pushed one.
        let cap = d.capacity();
        assert_eq!(recent[cap - 1], ((cap * 2 - 1) & 0xFF) as u8);
        // The oldest byte still in the ring is `cap` bytes back.
        assert_eq!(recent[0], (cap & 0xFF) as u8);
    }

    /// Phase 2 regression gate for `docs/PLAN_lazy_decoder_state.md`:
    /// the memcpy-based [`LzmaDict::recent`] must produce the same
    /// bytes as the byte-by-byte reference at every interesting
    /// `(push_count, n)` cross-product. The reference is kept
    /// inline so a future "let's just use the new one" clean-up
    /// doesn't accidentally drop the diff-test.
    ///
    /// Coverage: empty dict, single-push, half-full, exactly-full
    /// (cap), one-past-full (cap + 1), two-wraps, many-wraps with
    /// odd offset. For each fixture, ask `recent(n)` for n
    /// covering 0, 1, half, cap-1, cap, oversize. A bug in the
    /// wrap-split arithmetic surfaces here as a one-byte
    /// off-by-one and would silently corrupt every resume blob.
    #[test]
    fn recent_matches_byte_by_byte_reference() {
        // Reference: same byte-by-byte walk the original
        // implementation used. Lives in the test module so a
        // future refactor doesn't lose it.
        fn recent_reference(d: &LzmaDict, n: usize) -> Vec<u8> {
            let avail = std::cmp::min(d.total(), d.capacity() as u64) as usize;
            let take = std::cmp::min(n, avail);
            let mut out = Vec::with_capacity(take);
            for i in 0..take {
                let k = (take - 1 - i) as u32;
                out.push(d.byte_at(k));
            }
            out
        }

        let cap = MIN_DICT_SIZE; // 4096
        let push_counts: &[usize] = &[
            0,
            1,
            cap / 2,
            cap - 1,
            cap,
            cap + 1,
            2 * cap,
            5 * cap + 17, // odd offset to force a non-aligned wrap
        ];
        let ns: &[usize] = &[0, 1, cap / 4, cap - 1, cap, 2 * cap, 10_000];
        for &push_count in push_counts {
            let mut d = LzmaDict::new(cap as u32);
            // Distinct byte values per index so a wrong byte
            // shows up at the right position in the assert.
            for i in 0..push_count {
                d.push((i & 0xFF) as u8);
            }
            for &n in ns {
                let memcpy = d.recent(n);
                let walk = recent_reference(&d, n);
                assert_eq!(
                    memcpy, walk,
                    "recent(n={n}) mismatch after {push_count} pushes (cap={cap})",
                );
            }
        }
    }

    /// MIN_DICT_SIZE floor honored even when caller asks for less.
    #[test]
    fn min_dict_size_floor() {
        let d = LzmaDict::new(0);
        assert_eq!(d.capacity(), MIN_DICT_SIZE);
        let d = LzmaDict::new(100);
        assert_eq!(d.capacity(), MIN_DICT_SIZE);
    }

    /// `reload` produces a dict whose `byte_at` and `total`
    /// match the source dict at every back-position.
    #[test]
    fn reload_round_trips_byte_at() {
        let mut original = LzmaDict::new(MIN_DICT_SIZE as u32);
        for &b in b"chronological dict contents" {
            original.push(b);
        }
        let total = original.total();
        let recent = original.recent(total as usize);

        let mut restored = LzmaDict::new(MIN_DICT_SIZE as u32);
        restored.reload(&recent, total);
        assert_eq!(restored.total(), total);
        for n in 0..total as u32 {
            assert_eq!(
                restored.byte_at(n),
                original.byte_at(n),
                "byte_at({n}) mismatch"
            );
        }
    }

    /// Phase 2 of `docs/PLAN_xz_decoder_optimization.md`: the
    /// new bulk `match_copy` paths (non-overlap `copy_within`,
    /// `dist == 0` RLE specialization) must produce byte-identical
    /// output to the byte-by-byte reference across a randomized
    /// fixture corpus. The reference is kept inline so a future
    /// "let's just use the new one" refactor doesn't drop it.
    #[test]
    fn match_copy_matches_byte_by_byte_reference() {
        // Reference: same per-byte loop the pre-Phase-2 implementation
        // used. Note this needs its own dict copy so the original
        // isn't advanced; we run a "shadow" walk through `byte_at`
        // and `push` against a clone of the dict.
        fn match_copy_reference(
            d: &mut LzmaDict,
            dist: u32,
            length: u32,
            out: &mut Vec<u8>,
        ) -> Result<(), XzError> {
            let needed = u64::from(dist).saturating_add(1);
            if needed > d.total() || (dist as usize) >= d.declared_size {
                return Err(XzError::LzmaMatchOutOfRange {
                    dist,
                    total: d.total(),
                });
            }
            out.reserve(length as usize);
            for _ in 0..length {
                let b = d.byte_at(dist);
                d.push(b);
                out.push(b);
            }
            Ok(())
        }

        // Construct two dicts, run the prefix the same way through
        // both (same pushes), then issue `match_copy` to one and
        // the byte-by-byte reference to the other; compare both
        // the emitted bytes and the post-call dict state.
        fn make_dict(dict_size: u32, prefix_len: usize, seed: u64) -> LzmaDict {
            let mut state = seed ^ 0x9E37_79B9_7F4A_7C15_u64;
            let mut d = LzmaDict::new(dict_size);
            for _ in 0..prefix_len {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                d.push((state >> 32) as u8);
            }
            d
        }

        let cap = MIN_DICT_SIZE; // 4096 (also the power-of-two cap)
                                 // Cover: empty (0 prefix; trivially can't match anything),
                                 // single-byte, partial, near-cap, exactly-cap, past-cap,
                                 // multi-wrap.
        let prefix_lens: &[usize] = &[1, 16, 100, cap - 1, cap, cap + 1, 3 * cap + 19];
        // Cover dist: 0 (RLE single-byte), 1 (alternating RLE),
        // small dist, mid, near-cap-1.
        let dists: &[u32] = &[0, 1, 2, 7, 31, 100, (cap as u32) - 1];
        // Cover length: 0, 1, < dist (non-overlap), > dist
        // (overlap RLE-style), much larger than dist.
        let lengths: &[u32] = &[0, 1, 2, 5, 32, 1000, 4096];

        for (k, &prefix_len) in prefix_lens.iter().enumerate() {
            for &dist in dists {
                for &length in lengths {
                    let seed = 0xC0FFEE_u64.wrapping_add((k as u64) * 7919);

                    let mut d_new = make_dict(cap as u32, prefix_len, seed);
                    let mut d_ref = make_dict(cap as u32, prefix_len, seed);
                    let mut out_new = Vec::new();
                    let mut out_ref = Vec::new();

                    let r_new = d_new.match_copy(dist, length, &mut out_new);
                    let r_ref = match_copy_reference(&mut d_ref, dist, length, &mut out_ref);

                    assert_eq!(
                        r_new.is_ok(),
                        r_ref.is_ok(),
                        "match_copy ok/err divergence at prefix={prefix_len}, dist={dist}, length={length}",
                    );
                    if r_new.is_ok() {
                        assert_eq!(
                            out_new, out_ref,
                            "match_copy output mismatch at prefix={prefix_len}, dist={dist}, length={length}",
                        );
                        // The dicts should also agree on every back
                        // position within the ring.
                        assert_eq!(
                            d_new.total(),
                            d_ref.total(),
                            "match_copy total mismatch at prefix={prefix_len}, dist={dist}, length={length}",
                        );
                        for n in 0..(cap as u32 - 1).min(d_new.total() as u32) {
                            assert_eq!(
                                d_new.byte_at(n),
                                d_ref.byte_at(n),
                                "byte_at({n}) mismatch after match_copy(dist={dist}, length={length}, prefix={prefix_len})",
                            );
                        }
                    }
                }
            }
        }
    }

    /// `reload` after wraparound: `total > capacity` is honored
    /// so subsequent `byte_at` returns 0 for distances beyond the
    /// ring (matching the original's behavior).
    #[test]
    fn reload_after_wraparound_keeps_total() {
        let mut original = LzmaDict::new(MIN_DICT_SIZE as u32);
        for i in 0..(MIN_DICT_SIZE as u32 * 2) {
            original.push((i & 0xFF) as u8);
        }
        let total = original.total();
        assert!(total > original.capacity() as u64);
        let recent = original.recent(original.capacity());

        let mut restored = LzmaDict::new(MIN_DICT_SIZE as u32);
        restored.reload(&recent, total);
        assert_eq!(restored.total(), total);
        // Back-distances within the ring are valid.
        for n in 0..original.capacity() as u32 {
            assert_eq!(
                restored.byte_at(n),
                original.byte_at(n),
                "byte_at({n}) mismatch"
            );
        }
        // Pushing more bytes continues coherently — slot `total
        // % capacity` is where the next byte lands; reading
        // back via byte_at(0) should return what we just pushed.
        restored.push(0xAA);
        assert_eq!(restored.byte_at(0), 0xAA);
        assert_eq!(restored.total(), total + 1);
    }
}
