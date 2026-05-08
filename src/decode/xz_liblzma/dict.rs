//! Sliding-window dictionary for the liblzma-port decoder.
//!
//! Phase 2 of [`docs/PLAN_xz_liblzma_port.md`](../../../../docs/PLAN_xz_liblzma_port.md).
//! Mirror of liblzma's `lz_decoder.h` `lzma_dict` struct + the
//! inline `dict_get` / `dict_put` / `dict_repeat` / `dict_write`
//! methods.
//!
//! # Why the liblzma shape (vs. the existing `xz_native::dict`)
//!
//! [`super::super::xz_native::dict::LzmaDict`] uses a
//! power-of-two-rounded ring buffer with `mask = capacity - 1`,
//! letting `byte_at` replace `% capacity` with `& mask`. liblzma
//! takes a different approach: the buffer is exactly `dict_size`
//! bytes (no rounding), and `dict_get` uses a conditional offset
//! `(distance < pos ? 0 : size)` to handle wraparound. Both
//! shapes are correct; this port mirrors liblzma's because the
//! Phase 4 bench gate measures whether the **whole liblzma
//! shape** can hit ~1×, and the modular vs. mask choice is one
//! piece of that. The non-power-of-two ring also avoids the
//! up-to-2× memory overhead the existing decoder eats for
//! arbitrary preset sizes (relevant for very large dicts; the
//! production shape caps at 64 MiB and most preset sizes are
//! powers of two anyway).
//!
//! # `unsafe` posture
//!
//! Liberal `unsafe` for the hot-path `dict_get` / `dict_put` and
//! the bulk-copy paths in `dict_repeat` / `dict_write`. Each
//! `unsafe` block carries a `// SAFETY:` proof. liblzma's C code
//! is `dict->buf[dict->pos]` raw-pointer access throughout; we
//! match that.
//!
//! # No mid-decode resume in round one
//!
//! Per [`docs/PLAN_xz_liblzma_port.md`] §Round-one scope, this
//! decoder doesn't snapshot. `pos` only advances; there is no
//! `reload` / `recent` / `write_recent_into` API like the
//! existing decoder has. Phase F adds resume support back if
//! Phase 4's bench gate clears.

use std::ptr;

/// Sliding-window LZMA dictionary.
///
/// Mirror of liblzma's `lzma_dict`:
///
/// ```c
/// typedef struct {
///     uint8_t *buf;
///     size_t pos;
///     size_t full;
///     size_t limit;
///     size_t size;
///     bool need_reset;
/// } lzma_dict;
/// ```
///
/// Constructed with a fixed `dict_size`; the buffer is
/// allocated once at construction. `pos` is the next write
/// index; `full` tracks how much of the buffer holds valid
/// history (used to detect corrupt streams that ask for
/// matches beyond the start). `limit` is the per-call
/// write-stop point — set by the LZMA2 chunk dispatcher
/// (Phase 5) to bound the bytes a single `lzma_decode_port`
/// invocation may produce.
pub struct LzmaDict {
    /// Backing storage. Length is exactly `size` (no
    /// power-of-two rounding).
    buf: Box<[u8]>,
    /// Next write index. Advances by 1 each `dict_put`,
    /// wrapping back to 0 when it reaches `size`.
    pub pos: usize,
    /// Bytes of valid history. Bounded above by `size`. After
    /// the first `size` bytes have been written, `full == size`
    /// permanently (until `reset`).
    pub full: usize,
    /// Per-call write limit. The LZMA2 chunk dispatcher sets
    /// this to bound output for one `lzma_decode_port` call;
    /// `dict_put` returns `true` (signaling full) when
    /// `pos == limit`.
    pub limit: usize,
    /// Total dictionary size in bytes. `buf.len() == size`.
    pub size: usize,
}

impl LzmaDict {
    /// Construct a fresh dict with the given size, allocated
    /// to exactly `size` bytes.
    ///
    /// # Panics (debug)
    ///
    /// `size > 0` — a zero-byte dict has no use case.
    #[must_use]
    pub fn new(size: usize) -> Self {
        debug_assert!(size > 0, "dict_size must be > 0");
        Self {
            buf: vec![0u8; size].into_boxed_slice(),
            pos: 0,
            full: 0,
            limit: 0,
            size,
        }
    }

    /// Reset the cursor + history counter. The buffer's bytes
    /// are not zeroed (the `full` check makes them
    /// unreachable). Mirror of liblzma's `dict_reset` setting
    /// `need_reset = true`; we apply the reset eagerly.
    pub fn reset(&mut self) {
        self.pos = 0;
        self.full = 0;
        // `limit` is intentionally not reset — it's set per-call
        // by the chunk dispatcher and a reset within a chunk
        // shouldn't reach back and clobber the chunk's limit.
    }

    /// Set the per-call write limit. Mirror of liblzma's
    /// inline assignment that happens at the head of
    /// `lzma_decode`'s `dict.limit = ...`.
    #[inline]
    pub fn set_limit(&mut self, limit: usize) {
        debug_assert!(limit <= self.size, "limit exceeds dict size");
        self.limit = limit;
    }

    /// `true` if no bytes have been pushed since construction
    /// or last [`Self::reset`]. Mirror of `dict_is_empty`.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.full == 0
    }

    /// `true` if `distance` is within the available history.
    /// Per the LZMA spec, valid `distance` values are
    /// `0..full`; `distance == 0` means "1 byte back" (the
    /// most-recently-pushed byte). Mirror of
    /// `dict_is_distance_valid`.
    #[inline]
    #[must_use]
    pub fn is_distance_valid(&self, distance: usize) -> bool {
        self.full > distance
    }

    /// Get the byte at offset `distance + 1` back from the
    /// cursor. `distance == 0` returns the most-recently
    /// pushed byte.
    ///
    /// Mirror of liblzma's `dict_get`:
    ///
    /// ```c
    /// return dict->buf[dict->pos - distance - 1
    ///         + (distance < dict->pos ? 0 : dict->size)];
    /// ```
    ///
    /// **Caller contract**: `distance < self.full` must be
    /// established by [`Self::is_distance_valid`] (or by the
    /// LZMA spec's structural guarantee). On a malformed
    /// stream where `distance >= full`, this method may read
    /// stale bytes from the buffer — the caller is
    /// responsible for the spec check.
    #[inline]
    #[must_use]
    pub fn dict_get(&self, distance: u32) -> u8 {
        let distance = distance as usize;
        // INVARIANT: distance < full <= size.
        // Case A: `distance < pos` — wrap-free, source is at
        //   `pos - distance - 1`.
        // Case B: `distance >= pos` — source is in the older
        //   half of the ring at `pos - distance - 1 + size`,
        //   which is `(size + pos - distance - 1)` and lands
        //   in `[pos, size)` since `pos <= distance < size`.
        let offset = if distance < self.pos { 0 } else { self.size };
        let idx = self
            .pos
            .wrapping_sub(distance)
            .wrapping_sub(1)
            .wrapping_add(offset);
        // SAFETY: `idx` lands in `[0, self.size)` by the
        // case analysis above. `buf.len() == size` so the
        // raw-pointer load is in bounds.
        unsafe { *self.buf.as_ptr().add(idx) }
    }

    /// Append one byte at the cursor. Returns `true` if the
    /// dict was already at its `limit` (and the byte was not
    /// written).
    ///
    /// Mirror of liblzma's `dict_put`:
    ///
    /// ```c
    /// if (unlikely(dict->pos == dict->limit)) return true;
    /// dict->buf[dict->pos++] = byte;
    /// if (dict->pos > dict->full) dict->full = dict->pos;
    /// return false;
    /// ```
    #[inline]
    pub fn dict_put(&mut self, byte: u8) -> bool {
        if self.pos == self.limit {
            return true;
        }
        // SAFETY: `pos < limit <= size` from the check above
        // and `set_limit`'s invariant; `buf.len() == size`.
        unsafe {
            *self.buf.as_mut_ptr().add(self.pos) = byte;
        }
        self.pos += 1;
        if self.pos > self.full {
            self.full = self.pos;
        }
        false
    }

    /// Repeat `*len` bytes at `distance` from the history.
    /// Mutates `*len` to the number of bytes that **could not
    /// be written** because the per-call `limit` was reached;
    /// returns `true` when `*len > 0` after the call (i.e.,
    /// the caller should yield to the chunk dispatcher).
    ///
    /// Mirror of liblzma's `dict_repeat` with three cases:
    /// 1. **RLE overlap** (`distance < left`): byte-by-byte
    ///    copy because source and destination overlap and grow
    ///    together (a single byte at distance N gets repeated
    ///    `len/N` times when `len > distance`).
    /// 2. **Simple memcpy** (`distance < pos`): source is in
    ///    `[pos - distance - 1, pos)`, contiguous, and the
    ///    destination `[pos, pos + left)` doesn't overlap.
    ///    Single bulk copy.
    /// 3. **Wrap memcpy** (`distance >= pos`): source wraps
    ///    around the end of the ring; up to two bulk copies.
    ///
    /// **Caller contract**: `is_distance_valid(distance as
    /// usize)` must hold. The LZMA spec's
    /// `LzmaMatchOutOfRange` check is the caller's
    /// responsibility.
    pub fn dict_repeat(&mut self, distance: u32, len: &mut u32) -> bool {
        let dict_avail = self.limit - self.pos;
        let mut left = (*len as usize).min(dict_avail) as u32;
        *len -= left;

        let distance = distance as usize;

        if (distance as u32) < left {
            // Case 1: RLE overlap. Source and target areas
            // overlap and the source grows as we write — this
            // is the LZMA spec's RLE pattern (e.g.
            // `distance=0, len=N` repeats the most-recent byte
            // N times). Must be byte-by-byte.
            //
            // NB: the loop body below is a direct mirror of
            // liblzma's `do { dict->buf[dict->pos] =
            // dict_get(dict, distance); ++dict->pos; } while
            // (--left > 0);` shape.
            while left > 0 {
                let byte = self.dict_get(distance as u32);
                // SAFETY: `pos < limit <= size`. The per-iteration
                // dict_put-style write is bounded by the
                // `pos < limit` invariant maintained by the
                // outer `dict_avail` calculation.
                unsafe {
                    *self.buf.as_mut_ptr().add(self.pos) = byte;
                }
                self.pos += 1;
                left -= 1;
            }
        } else if distance < self.pos {
            // Case 2: simple memcpy. Source `[pos - distance
            // - 1, pos - distance - 1 + left)` doesn't overlap
            // destination `[pos, pos + left)` because
            // `distance >= left` so `pos - distance - 1 +
            // left <= pos`.
            let src = self.pos - distance - 1;
            // SAFETY: src + left <= pos (per the case
            // condition); pos + left <= limit <= size; both
            // ranges are within `buf`. The ranges may be
            // adjacent but not overlap, satisfying
            // `copy_nonoverlapping`.
            unsafe {
                let src_ptr = self.buf.as_ptr().add(src);
                let dst_ptr = self.buf.as_mut_ptr().add(self.pos);
                ptr::copy_nonoverlapping(src_ptr, dst_ptr, left as usize);
            }
            self.pos += left as usize;
        } else {
            // Case 3: wrap memcpy. Source `copy_pos = pos -
            // distance - 1 + size` lands in `[pos, size)`
            // (since `pos <= distance < size`). The first
            // segment is `[copy_pos, size)`; if more bytes
            // are needed, wrap to `[0, ...)`.
            //
            // INVARIANT: case 3 only fires when `full ==
            // size` (the ring has wrapped at least once).
            // Otherwise `distance < full <= pos` would be
            // case 1 or 2.
            debug_assert_eq!(
                self.full, self.size,
                "wrap case requires the dict to have filled at least once",
            );
            let copy_pos = self.pos - distance - 1 + self.size;
            let copy_size = (self.size - copy_pos) as u32;

            if copy_size < left {
                // First segment: `[copy_pos, size)`. May
                // overlap destination if `pos == copy_pos`
                // (impossible here because `pos < copy_pos`
                // by the case condition).
                // SAFETY: `copy_pos + copy_size == size <=
                // buf.len()`; `pos + copy_size <= limit <=
                // size`; the ranges may share a boundary but
                // not overlap interiors when `pos !=
                // copy_pos`. We use `copy` (not
                // `copy_nonoverlapping`) to match liblzma's
                // `memmove` for the first segment.
                unsafe {
                    let src_ptr = self.buf.as_ptr().add(copy_pos);
                    let dst_ptr = self.buf.as_mut_ptr().add(self.pos);
                    ptr::copy(src_ptr, dst_ptr, copy_size as usize);
                }
                self.pos += copy_size as usize;
                let remaining = left - copy_size;
                // Second segment: wrap to `[0, remaining)`.
                // SAFETY: `pos + remaining <= limit <= size`.
                // The ranges `[0, remaining)` and `[pos, pos
                // + remaining)` are disjoint because
                // `remaining <= left <= dict_avail = limit -
                // pos`, i.e., `pos + remaining <= limit <=
                // size` and `remaining < pos` (since `pos
                // > 0` after the first segment write).
                unsafe {
                    let src_ptr = self.buf.as_ptr();
                    let dst_ptr = self.buf.as_mut_ptr().add(self.pos);
                    ptr::copy_nonoverlapping(src_ptr, dst_ptr, remaining as usize);
                }
                self.pos += remaining as usize;
            } else {
                // Single segment, no wrap of the source.
                // SAFETY: same as the if-branch's first
                // segment; using `copy` for the
                // memmove-shape.
                unsafe {
                    let src_ptr = self.buf.as_ptr().add(copy_pos);
                    let dst_ptr = self.buf.as_mut_ptr().add(self.pos);
                    ptr::copy(src_ptr, dst_ptr, left as usize);
                }
                self.pos += left as usize;
            }
        }

        if self.pos > self.full {
            self.full = self.pos;
        }

        *len != 0
    }

    /// Bulk write from an external buffer into the dict.
    /// Mirror of liblzma's `dict_write` — used by the LZMA2
    /// chunk dispatcher (Phase 5) when a chunk-control byte
    /// declares an uncompressed chunk (no LZMA model
    /// involvement).
    ///
    /// `in_pos` advances by the number of bytes copied; `left`
    /// is decremented by the same.
    pub fn dict_write(
        &mut self,
        in_buf: &[u8],
        in_pos: &mut usize,
        in_size: usize,
        left: &mut usize,
    ) {
        // Tighten the input slice if more is available than
        // `*left` permits.
        let effective_in_size = if in_size - *in_pos > *left {
            *in_pos + *left
        } else {
            in_size
        };
        let want = (effective_in_size - *in_pos).min(self.limit - self.pos);
        if want == 0 {
            return;
        }
        // SAFETY: `*in_pos + want <= effective_in_size <=
        // in_buf.len()`; `pos + want <= limit <= size <=
        // buf.len()`; source slice and dict buffer are
        // distinct allocations, so non-overlapping holds.
        unsafe {
            let src_ptr = in_buf.as_ptr().add(*in_pos);
            let dst_ptr = self.buf.as_mut_ptr().add(self.pos);
            ptr::copy_nonoverlapping(src_ptr, dst_ptr, want);
        }
        *in_pos += want;
        self.pos += want;
        *left -= want;
        if self.pos > self.full {
            self.full = self.pos;
        }
    }

    /// Read-only view of the buffer. Used in tests.
    #[cfg(test)]
    #[must_use]
    pub fn buf(&self) -> &[u8] {
        &self.buf
    }
}

impl std::fmt::Debug for LzmaDict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LzmaDict")
            .field("pos", &self.pos)
            .field("full", &self.full)
            .field("limit", &self.limit)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    //! Differential tests against a safe-Rust reference
    //! implementation.
    //!
    //! Strategy: the reference dict uses safe `Vec<u8>` slice
    //! indexing for every operation. The production dict uses
    //! `unsafe` raw-pointer ops. We drive a randomized sequence
    //! of `dict_put` / `dict_get` / `dict_repeat` / `dict_write`
    //! ops against both and assert byte-identical state after
    //! each op. The fixture spans ring-wrap shapes (multi-pass
    //! dicts), the RLE / simple-memcpy / wrap-memcpy three
    //! cases, and the `limit`-saturation early-exit path.
    //!
    //! Per [`docs/PLAN_xz_liblzma_port.md`] Phase 2 exit
    //! criterion: differential corpus byte-identical between
    //! the raw-pointer fast path and the safe reference.

    use super::*;

    /// Reference implementation: safe-Rust slice-indexed
    /// equivalent. Every method has the same semantics as the
    /// production [`LzmaDict`] but uses `&[u8]` / `&mut [u8]`
    /// indexing throughout — no `unsafe`. Slow but obviously
    /// correct.
    struct ReferenceDict {
        buf: Vec<u8>,
        pos: usize,
        full: usize,
        limit: usize,
        size: usize,
    }

    impl ReferenceDict {
        fn new(size: usize) -> Self {
            Self {
                buf: vec![0u8; size],
                pos: 0,
                full: 0,
                limit: 0,
                size,
            }
        }
        fn set_limit(&mut self, limit: usize) {
            self.limit = limit;
        }
        fn dict_get(&self, distance: u32) -> u8 {
            let distance = distance as usize;
            let offset = if distance < self.pos { 0 } else { self.size };
            let idx = self
                .pos
                .wrapping_sub(distance)
                .wrapping_sub(1)
                .wrapping_add(offset);
            self.buf[idx]
        }
        fn dict_put(&mut self, byte: u8) -> bool {
            if self.pos == self.limit {
                return true;
            }
            self.buf[self.pos] = byte;
            self.pos += 1;
            if self.pos > self.full {
                self.full = self.pos;
            }
            false
        }
        fn dict_repeat(&mut self, distance: u32, len: &mut u32) -> bool {
            let dict_avail = self.limit - self.pos;
            let mut left = (*len as usize).min(dict_avail) as u32;
            *len -= left;
            let distance = distance as usize;
            // Single byte-by-byte loop covering all three
            // cases — the reference doesn't bother optimizing.
            while left > 0 {
                let byte = self.dict_get(distance as u32);
                self.buf[self.pos] = byte;
                self.pos += 1;
                left -= 1;
            }
            if self.pos > self.full {
                self.full = self.pos;
            }
            *len != 0
        }
    }

    /// Assert two dicts are in byte-identical state.
    fn assert_state_eq(a: &LzmaDict, b: &ReferenceDict, label: &str) {
        assert_eq!(a.pos, b.pos, "pos diverged at {label}");
        assert_eq!(a.full, b.full, "full diverged at {label}");
        assert_eq!(a.limit, b.limit, "limit diverged at {label}");
        assert_eq!(a.size, b.size, "size diverged at {label}");
        assert_eq!(a.buf(), b.buf.as_slice(), "buf diverged at {label}");
    }

    /// Pre-Phase-1 LCG so tests are deterministic across the
    /// crate. Same state-update math as
    /// `crate::decode::xz_native::test_support`'s LCG.
    fn lcg(seed: u64, n: usize) -> Vec<u8> {
        let mut s = seed ^ 0x9E37_79B9_7F4A_7C15;
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            s = s
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            out.extend_from_slice(&s.to_le_bytes());
        }
        out.truncate(n);
        out
    }

    /// Empty dict: no bytes pushed → distance is invalid for
    /// any value.
    #[test]
    fn empty_dict_invariants() {
        let dict = LzmaDict::new(4096);
        assert!(dict.is_empty());
        assert!(!dict.is_distance_valid(0));
        assert_eq!(dict.pos, 0);
        assert_eq!(dict.full, 0);
    }

    /// Push N bytes, read them back via `dict_get`.
    #[test]
    fn push_and_get_roundtrip() {
        let mut dict = LzmaDict::new(4096);
        dict.set_limit(4096);
        let payload: Vec<u8> = (0..200u32).map(|i| (i & 0xFF) as u8).collect();
        for &b in &payload {
            assert!(!dict.dict_put(b));
        }
        // `dict_get(0)` is the most-recently-pushed byte.
        for i in 0..payload.len() {
            let distance = (payload.len() - 1 - i) as u32;
            assert_eq!(dict.dict_get(distance), payload[i], "i={i}");
        }
    }

    /// `dict_put` returns true once `pos == limit`.
    #[test]
    fn dict_put_full_at_limit() {
        let mut dict = LzmaDict::new(4096);
        dict.set_limit(4);
        assert!(!dict.dict_put(0xAA));
        assert!(!dict.dict_put(0xBB));
        assert!(!dict.dict_put(0xCC));
        assert!(!dict.dict_put(0xDD));
        // Now full.
        assert!(dict.dict_put(0xEE));
        assert_eq!(dict.pos, 4);
    }

    /// RLE overlap case: `distance == 0, len == 8` repeats
    /// the most-recent byte 8 times.
    #[test]
    fn dict_repeat_rle_distance_zero() {
        let mut dict = LzmaDict::new(4096);
        let mut reference = ReferenceDict::new(4096);
        dict.set_limit(4096);
        reference.set_limit(4096);
        dict.dict_put(0x55);
        reference.dict_put(0x55);
        let mut len_a: u32 = 8;
        let mut len_b: u32 = 8;
        let leftover_a = dict.dict_repeat(0, &mut len_a);
        let leftover_b = reference.dict_repeat(0, &mut len_b);
        assert_eq!(leftover_a, leftover_b);
        assert_eq!(len_a, len_b);
        assert_state_eq(&dict, &reference, "RLE distance=0");
        assert!(dict.buf()[0..9].iter().all(|&b| b == 0x55));
    }

    /// Simple memcpy case: `distance >= len`, source within
    /// the existing history, no overlap, no wrap.
    #[test]
    fn dict_repeat_simple_memcpy() {
        let mut dict = LzmaDict::new(4096);
        let mut reference = ReferenceDict::new(4096);
        dict.set_limit(4096);
        reference.set_limit(4096);
        let prefix: Vec<u8> = (0..32u32).map(|i| (i + 1) as u8).collect();
        for &b in &prefix {
            dict.dict_put(b);
            reference.dict_put(b);
        }
        // distance=15, len=10: copy bytes [16, 26) to [32, 42).
        let mut len_a: u32 = 10;
        let mut len_b: u32 = 10;
        let leftover_a = dict.dict_repeat(15, &mut len_a);
        let leftover_b = reference.dict_repeat(15, &mut len_b);
        assert_eq!(leftover_a, leftover_b);
        assert_state_eq(&dict, &reference, "simple memcpy");
    }

    /// Wrap case: dict has wrapped, source range straddles the
    /// ring's end.
    #[test]
    fn dict_repeat_wrap_case() {
        const SIZE: usize = 64;
        let mut dict = LzmaDict::new(SIZE);
        let mut reference = ReferenceDict::new(SIZE);
        dict.set_limit(SIZE);
        reference.set_limit(SIZE);
        // Fill the dict completely so it wraps.
        let payload = lcg(0xC0FFEE, SIZE);
        for &b in &payload {
            dict.dict_put(b);
            reference.dict_put(b);
        }
        assert_eq!(dict.full, SIZE);
        assert_eq!(dict.pos, SIZE);
        // Reset pos to 8 to simulate having wrapped and
        // written 8 more bytes.
        // ... actually `dict_put` would leave pos == size
        // here; the wrap is handled by the next put resetting
        // pos to 0. Let's just push more bytes to wrap.
        dict.set_limit(0);
        reference.set_limit(0);
        // Now `pos == limit`, future dict_put returns true.
        // Reset pos to 0 to simulate liblzma's wrap, then
        // push 8 bytes.
        dict.pos = 0;
        reference.pos = 0;
        dict.set_limit(SIZE);
        reference.set_limit(SIZE);
        let new_bytes: Vec<u8> = (0..8u8).map(|i| 0x80 | i).collect();
        for &b in &new_bytes {
            dict.dict_put(b);
            reference.dict_put(b);
        }
        // Now pos=8, full=size. distance=20, len=10 means:
        //   copy_pos = 8 - 20 - 1 + 64 = 51
        //   first segment = buf[51..61] (10 bytes — fits in
        //   a single chunk since 51+10 < 64).
        let mut len_a: u32 = 10;
        let mut len_b: u32 = 10;
        let leftover_a = dict.dict_repeat(20, &mut len_a);
        let leftover_b = reference.dict_repeat(20, &mut len_b);
        assert_eq!(leftover_a, leftover_b);
        assert_state_eq(&dict, &reference, "wrap simple");

        // Now exercise the two-segment case. distance=4 from
        // pos=18 → copy_pos = 18 - 4 - 1 + 64 = 77, but 77 >
        // 64 so the case is `distance < pos` (case 2). Need
        // distance > pos.
        // Actually we want distance >= pos. pos=18, so
        // distance=20 again → copy_pos = 18 - 20 - 1 + 64 =
        // 61. copy_size = 64 - 61 = 3. Asking for len=8
        // forces the two-segment path.
        let mut len_a: u32 = 8;
        let mut len_b: u32 = 8;
        let leftover_a = dict.dict_repeat(20, &mut len_a);
        let leftover_b = reference.dict_repeat(20, &mut len_b);
        assert_eq!(leftover_a, leftover_b);
        assert_state_eq(&dict, &reference, "wrap two-segment");
    }

    /// Saturation: `dict_repeat` with `len > dict_avail`
    /// writes only `dict_avail` bytes and reports leftover.
    #[test]
    fn dict_repeat_saturates_at_limit() {
        let mut dict = LzmaDict::new(4096);
        dict.set_limit(20);
        for _ in 0..10 {
            dict.dict_put(0xAA);
        }
        let mut len: u32 = 20;
        let leftover = dict.dict_repeat(0, &mut len);
        assert!(leftover);
        assert_eq!(len, 10); // 20 - 10 (dict_avail) = 10 leftover
        assert_eq!(dict.pos, 20);
    }

    /// `dict_write` bulk-copies external bytes into the dict.
    #[test]
    fn dict_write_bulk_copy() {
        let mut dict = LzmaDict::new(4096);
        dict.set_limit(4096);
        let in_buf = lcg(0xDEAD, 100);
        let mut in_pos = 0;
        let mut left: usize = 60;
        dict.dict_write(&in_buf, &mut in_pos, in_buf.len(), &mut left);
        assert_eq!(in_pos, 60);
        assert_eq!(left, 0);
        assert_eq!(dict.pos, 60);
        assert_eq!(&dict.buf()[..60], &in_buf[..60]);
    }

    /// Differential property test: a randomized sequence of
    /// (push, repeat, write) ops produces byte-identical
    /// state across the production and reference dicts.
    #[test]
    fn differential_random_ops() {
        const SIZE: usize = 256;
        const ITERS: usize = 5000;
        let mut dict = LzmaDict::new(SIZE);
        let mut reference = ReferenceDict::new(SIZE);
        dict.set_limit(SIZE);
        reference.set_limit(SIZE);

        let payload = lcg(0xF00D, ITERS * 4);
        let mut pi = 0;
        let mut state: u64 = 0xBEEF;

        for op_i in 0..ITERS {
            // Cycle the limit when the dict fills, simulating
            // liblzma's "wrap to 0, set new limit" at chunk
            // boundaries.
            if dict.pos == dict.limit {
                dict.pos = 0;
                reference.pos = 0;
                dict.set_limit(SIZE);
                reference.set_limit(SIZE);
            }
            state = state
                .wrapping_mul(2862933555777941757)
                .wrapping_add(3037000493);
            let op = state & 0x3;
            match op {
                0 => {
                    // dict_put
                    if pi < payload.len() {
                        let r1 = dict.dict_put(payload[pi]);
                        let r2 = reference.dict_put(payload[pi]);
                        assert_eq!(r1, r2);
                        pi += 1;
                    }
                }
                1 => {
                    // dict_repeat — only if there's history
                    if dict.full > 0 {
                        let dist = ((state >> 8) as u32) % (dict.full.min(64) as u32);
                        let mut len_a = 1 + ((state >> 16) & 0x1F) as u32;
                        let mut len_b = len_a;
                        let r1 = dict.dict_repeat(dist, &mut len_a);
                        let r2 = reference.dict_repeat(dist, &mut len_b);
                        assert_eq!(r1, r2);
                        assert_eq!(len_a, len_b);
                    }
                }
                2 => {
                    // dict_get a random valid distance
                    if dict.full > 0 {
                        let dist = ((state >> 8) as u32) % (dict.full as u32);
                        assert_eq!(
                            dict.dict_get(dist),
                            reference.dict_get(dist),
                            "dict_get diverged at iter {op_i} dist {dist}"
                        );
                    }
                }
                _ => {
                    // dict_write — bulk
                    if pi + 8 < payload.len() {
                        let chunk = ((state >> 8) & 0xF) as usize + 1;
                        let mut local_pos = pi;
                        let in_size = pi + chunk;
                        let mut left_a: usize = chunk;
                        let mut left_b: usize = chunk;
                        // Reference doesn't have dict_write;
                        // emulate via repeated dict_put
                        // against a slice.
                        let snapshot_pi = pi;
                        dict.dict_write(&payload, &mut local_pos, in_size, &mut left_a);
                        let copied = local_pos - snapshot_pi;
                        for k in 0..copied {
                            let stop = reference.dict_put(payload[snapshot_pi + k]);
                            if stop {
                                left_b += copied - k;
                                break;
                            }
                        }
                        let _ = left_b;
                        pi = local_pos;
                    }
                }
            }
            assert_state_eq(&dict, &reference, &format!("iter {op_i} op {op}"));
        }
    }
}
