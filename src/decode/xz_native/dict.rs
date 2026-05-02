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
/// Owns a `Box<[u8]>` of size `max(dict_size, MIN_DICT_SIZE)`,
/// allocated once at construction. The cursor `head` points at
/// the next position to write; `total` is the monotonic count of
/// bytes pushed since construction or the last [`Self::reset`].
#[derive(Debug)]
pub struct LzmaDict {
    /// Ring buffer holding up to `buf.len()` bytes of history.
    buf: Box<[u8]>,
    /// Position in `buf` where the next byte will be written
    /// (`total % capacity`).
    head: usize,
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
    #[must_use]
    pub fn new(dict_size: u32) -> Self {
        let capacity = std::cmp::max(dict_size as usize, MIN_DICT_SIZE);
        Self {
            buf: vec![0u8; capacity].into_boxed_slice(),
            head: 0,
            total: 0,
        }
    }

    /// Capacity of the ring buffer in bytes. Always ≥
    /// [`MIN_DICT_SIZE`].
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
        // INVARIANT: `self.head < self.buf.len()` is maintained
        // because we modulo on every advance and the buffer is
        // never empty (`MIN_DICT_SIZE > 0`).
        self.buf[self.head] = b;
        self.head += 1;
        if self.head == self.buf.len() {
            self.head = 0;
        }
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
        // Last-written byte is at `(head + cap - 1) % cap`.
        // Walk back `n` further. INVARIANT:
        // `self.head + cap - 1 - n` is non-negative because
        // `n < cap` and `head >= 0`.
        let cap = self.buf.len();
        let idx = (self.head + cap - 1 - n) % cap;
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
    /// # Errors
    ///
    /// - [`XzError::LzmaMatchOutOfRange`] if `dist + 1 > total`
    ///   (back-reference outside available history) or `dist >=
    ///   capacity()` (back-reference past the ring buffer).
    pub fn match_copy(&mut self, dist: u32, length: u32, out: &mut Vec<u8>) -> Result<(), XzError> {
        let needed = u64::from(dist).saturating_add(1);
        if needed > self.total || (dist as usize) >= self.buf.len() {
            return Err(XzError::LzmaMatchOutOfRange {
                dist,
                total: self.total,
            });
        }
        // Pre-reserve so the inner loop doesn't reallocate per
        // byte; `out` is the chunk's staging buffer.
        out.reserve(length as usize);
        for _ in 0..length {
            let b = self.byte_at(dist);
            self.push(b);
            out.push(b);
        }
        Ok(())
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
        self.head = (total % cap as u64) as usize;
        if bytes.is_empty() {
            return;
        }
        // The cursor sits at slot `head`; the oldest of `bytes`
        // is at slot `(head - bytes.len()) mod cap`. Walk
        // forward `bytes.len()` slots from there.
        let start_slot = (self.head + cap - bytes.len()) % cap;
        for (k, &b) in bytes.iter().enumerate() {
            let slot = (start_slot + k) % cap;
            self.buf[slot] = b;
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

    /// Snapshot the most recent up-to-`n` bytes (capped at
    /// `min(total, capacity)`), in chronological order.
    ///
    /// Used by Phase 6's resume blob: when paused at an LZMA2
    /// chunk boundary, the dict contents up to `dict_size` bytes
    /// (or however many have been pushed, if smaller) are the
    /// minimum state needed to resume byte-identically.
    #[must_use]
    pub fn recent(&self, n: usize) -> Vec<u8> {
        let avail = std::cmp::min(self.total, self.buf.len() as u64) as usize;
        let take = std::cmp::min(n, avail);
        let mut out = Vec::with_capacity(take);
        for i in 0..take {
            // Walk back from `take - 1` slots to `0` slots so the
            // output is chronological.
            // INVARIANT: `take <= avail <= buf.len()`, so the
            // index `take - 1 - i` always fits in u32 because
            // `buf.len() <= u32::MAX`.
            let n = (take - 1 - i) as u32;
            out.push(self.byte_at(n));
        }
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
