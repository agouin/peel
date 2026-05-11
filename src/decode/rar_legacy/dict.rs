//! Sliding-window dictionary for the legacy RAR LZ pipeline.
//!
//! Sibling of [`crate::decode::rar_native::dict`]. Both are
//! bounded ring buffers that the LZ dispatcher fills with
//! literal bytes and back-references, and both expose the same
//! "push literal" / "copy a match given a `(distance, length)`
//! pair" API to the upper layer. The two diverge only in
//! capacity bounds and in the prose / cap rationale they ship
//! with — RAR3 caps at 4 MiB (libarchive's `DICTIONARY_MAX_SIZE
//! = 0x400000`); RAR5 reaches ≥ 256 MiB in the wild.
//!
//! # The libarchive reference
//!
//! Equivalent of `archive_read_support_format_rar.c`'s `struct
//! lzss` + `lzss_emit_literal` (line 670) + `lzss_emit_match`
//! (line 677) + `copy_from_lzss_window` (line 3135). The §C1d
//! port keeps the libarchive semantics for the
//! `length > distance` self-overlapping case byte-wise; bulk
//! `memcpy`-style fast-paths for the `length <= distance` case
//! are filed for §G.
//!
//! # Capacity
//!
//! Legacy RAR sizes the dictionary at parse time: libarchive
//! reads `unp_size` from the file header, rounds up to the
//! next power-of-2, and caps at `0x400000` (4 MiB). This
//! module accepts any positive `capacity` ≤
//! [`MAX_DICT_BYTES`]; the actual sizing logic lives in §C1e's
//! `LzDecoder` constructor.
//!
//! # Overlap-by-design
//!
//! For `length > distance` the LZSS copy "expands" by reading
//! bytes that were just written this same call (the classic
//! RLE-via-LZSS trick, e.g. "repeat the previous byte 100
//! times" is encoded as `distance = 1, length = 100`). The
//! [`Dict::copy_match`] loop handles this byte-wise; do not
//! be tempted to swap in a `slice::copy_from_slice` without
//! re-checking the overlap branch.

use thiserror::Error;

/// Round-one cap on dictionary size, in bytes. Matches
/// libarchive's `DICTIONARY_MAX_SIZE` for legacy RAR (4 MiB).
/// Phase G may revisit if the corpus exposes a real need for
/// the spec's slightly higher ceiling on PPMd-mode entries.
pub const MAX_DICT_BYTES: usize = 4 * 1024 * 1024;

/// Errors produced by [`Dict`] operations.
#[derive(Debug, Error)]
pub enum DictError {
    /// Caller asked for a dictionary larger than [`MAX_DICT_BYTES`].
    /// Construction-time guard; the LZ dispatcher's sizing logic
    /// in §C1e clamps `unp_size` to this cap before calling
    /// [`Dict::new`].
    #[error(
        "legacy RAR dict capacity {requested} exceeds MAX_DICT_BYTES \
         ({MAX_DICT_BYTES})"
    )]
    CapacityTooLarge {
        /// Requested capacity in bytes.
        requested: usize,
    },

    /// Caller asked for a zero-byte dictionary. Libarchive
    /// fails out at line 2557 with "Zero window size is invalid";
    /// we surface a typed equivalent.
    #[error("legacy RAR dict capacity must be > 0")]
    CapacityZero,

    /// [`Dict::copy_match`] was passed `distance == 0` or a
    /// distance greater than the bytes the dictionary has
    /// actually emitted. Both indicate a malformed bitstream.
    #[error(
        "legacy RAR LZSS back-reference underflow: distance {distance}, \
         total_written {available}"
    )]
    BackReferenceUnderflow {
        /// The wire-decoded distance.
        distance: u64,
        /// Bytes the dictionary has emitted so far.
        available: u64,
    },

    /// `distance` exceeded the dictionary's capacity. The byte
    /// that far back has wrapped out of the ring; the wire
    /// stream is malformed.
    #[error(
        "legacy RAR LZSS distance {distance} exceeds dict capacity \
         {capacity}"
    )]
    DistanceExceedsCapacity {
        /// The wire-decoded distance.
        distance: u64,
        /// The dictionary's capacity in bytes.
        capacity: u64,
    },

    /// [`Dict::copy_recent_into`] was asked for more bytes than
    /// have ever been written (or than the dict can hold).
    /// Caller bug — the §C2 filter VM never asks for more
    /// bytes than it has staged.
    #[error(
        "legacy RAR dict recent-window read overruns: requested {requested}, \
         available {available}"
    )]
    RecentWindowOverrun {
        /// Bytes the caller asked for.
        requested: u64,
        /// Bytes actually present in the ring (i.e.
        /// `min(capacity, total_written)`).
        available: u64,
    },
}

/// Bounded ring buffer holding the most-recent decoded bytes.
///
/// Construct with [`Dict::new`] specifying the per-entry
/// capacity. After each [`Self::push_literal`] /
/// [`Self::copy_match`] call, `head` advances modulo
/// `capacity` and `total_written` accumulates; the LZ
/// dispatcher uses `total_written` to bounds-check that a
/// back-reference points at a byte the decoder has actually
/// emitted.
#[derive(Debug)]
pub struct Dict {
    /// Backing storage. Sized to the per-entry capacity.
    buf: Box<[u8]>,
    /// Index in `buf` where the next byte will be written.
    /// Wraps at `capacity`.
    head: usize,
    /// Capacity in bytes (i.e. `buf.len()`). Cached for the
    /// hot path.
    capacity: usize,
    /// Total bytes ever written. Used to bounds-check the LZ
    /// dispatcher's distance against the "first decoded byte"
    /// (the back-reference-underflow case).
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

    /// Copy `length` bytes from `distance` bytes back,
    /// appending the produced bytes to the dictionary AND to
    /// `out`.
    ///
    /// Handles `length > distance` (the LZSS overlap-by-design
    /// case used to encode short repeat runs like
    /// `distance = 1, length = N` for "repeat byte N times")
    /// via a byte-wise loop.
    ///
    /// # Errors
    ///
    /// - [`DictError::BackReferenceUnderflow`] if
    ///   `distance == 0` or `distance > total_written`.
    /// - [`DictError::DistanceExceedsCapacity`] if `distance >
    ///   capacity` (the byte that far back has wrapped out of
    ///   the ring).
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
        // INVARIANT: `distance <= capacity <= MAX_DICT_BYTES`,
        // so the cast is lossless.
        let distance_usz = distance as usize;
        let length_usz = usize::try_from(length).unwrap_or(usize::MAX);
        out.reserve(length_usz);
        for _ in 0..length_usz {
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

    /// Copy the most-recent `out.len()` bytes (in stream order)
    /// into `out`, **without** advancing the dictionary state.
    /// Used by §C2's filter VM to pull a window of staged LZ
    /// output for in-place transformation.
    ///
    /// `out[0]` is the byte emitted `out.len()` calls ago via
    /// `push_literal` / `copy_match`; `out[out.len() - 1]` is
    /// the most-recently emitted byte.
    ///
    /// # Errors
    ///
    /// - [`DictError::RecentWindowOverrun`] if `out.len()`
    ///   exceeds [`Self::live_bytes`].
    pub fn copy_recent_into(&self, out: &mut [u8]) -> Result<(), DictError> {
        let len_usz = out.len();
        let len = len_usz as u64;
        let live = self.live_bytes();
        if len > live {
            return Err(DictError::RecentWindowOverrun {
                requested: len,
                available: live,
            });
        }
        // The most-recent byte sits at `(head - 1) mod capacity`;
        // we want `len_usz` bytes ending there.
        let start = if len_usz <= self.head {
            self.head - len_usz
        } else {
            self.capacity - (len_usz - self.head)
        };
        if start + len_usz <= self.capacity {
            out.copy_from_slice(&self.buf[start..start + len_usz]);
        } else {
            // Wrap: high-half from `[start, capacity)`, low-half
            // from `[0, head)`.
            let head = (start + len_usz) - self.capacity;
            let high = self.capacity - start;
            out[..high].copy_from_slice(&self.buf[start..]);
            out[high..].copy_from_slice(&self.buf[..head]);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_capacity_rejects() {
        let err = Dict::new(0).unwrap_err();
        assert!(matches!(err, DictError::CapacityZero));
    }

    #[test]
    fn over_cap_capacity_rejects() {
        let err = Dict::new(MAX_DICT_BYTES + 1).unwrap_err();
        match err {
            DictError::CapacityTooLarge { requested } => {
                assert_eq!(requested, MAX_DICT_BYTES + 1);
            }
            other => panic!("expected CapacityTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn fresh_dict_has_no_live_bytes_and_zero_total() {
        let d = Dict::new(64).unwrap();
        assert_eq!(d.capacity(), 64);
        assert_eq!(d.total_written(), 0);
        assert_eq!(d.live_bytes(), 0);
    }

    #[test]
    fn push_literal_appends_to_out_and_advances_state() {
        let mut d = Dict::new(64).unwrap();
        let mut out = Vec::new();
        d.push_literal(b'A', &mut out);
        d.push_literal(b'B', &mut out);
        d.push_literal(b'C', &mut out);
        assert_eq!(out, b"ABC");
        assert_eq!(d.total_written(), 3);
        assert_eq!(d.live_bytes(), 3);
    }

    #[test]
    fn copy_match_with_distance_greater_than_zero_does_not_overlap() {
        // Seed "ABCDEFGH", then copy_match(distance=4, length=4):
        // pulls bytes at indices 0..4 again → "EFGHABCD".
        let mut d = Dict::new(64).unwrap();
        let mut out = Vec::new();
        for &b in b"ABCDEFGH" {
            d.push_literal(b, &mut out);
        }
        out.clear();
        d.copy_match(4, 4, &mut out).unwrap();
        // After the seed, head = 8. distance = 4 → src = 4, 5, 6, 7
        // → bytes 'E', 'F', 'G', 'H'.
        assert_eq!(out, b"EFGH");
    }

    #[test]
    fn copy_match_with_distance_one_repeats_a_single_byte() {
        // The RLE-via-LZSS trick.
        let mut d = Dict::new(64).unwrap();
        let mut out = Vec::new();
        d.push_literal(b'X', &mut out);
        out.clear();
        d.copy_match(1, 7, &mut out).unwrap();
        assert_eq!(out, b"XXXXXXX");
        assert_eq!(d.total_written(), 8);
    }

    #[test]
    fn copy_match_length_greater_than_distance_expands_correctly() {
        // Seed "AB", then copy_match(distance=2, length=5):
        // pulls 'A', 'B', 'A', 'B', 'A' — overlap-by-design.
        let mut d = Dict::new(64).unwrap();
        let mut out = Vec::new();
        d.push_literal(b'A', &mut out);
        d.push_literal(b'B', &mut out);
        out.clear();
        d.copy_match(2, 5, &mut out).unwrap();
        assert_eq!(out, b"ABABA");
    }

    #[test]
    fn copy_match_zero_distance_errors() {
        let mut d = Dict::new(64).unwrap();
        let mut out = Vec::new();
        d.push_literal(b'A', &mut out);
        let err = d.copy_match(0, 1, &mut out).unwrap_err();
        assert!(matches!(err, DictError::BackReferenceUnderflow { .. }));
    }

    #[test]
    fn copy_match_distance_exceeds_total_written_errors() {
        let mut d = Dict::new(64).unwrap();
        let mut out = Vec::new();
        d.push_literal(b'A', &mut out);
        let err = d.copy_match(2, 1, &mut out).unwrap_err();
        match err {
            DictError::BackReferenceUnderflow {
                distance,
                available,
            } => {
                assert_eq!(distance, 2);
                assert_eq!(available, 1);
            }
            other => panic!("expected BackReferenceUnderflow, got {other:?}"),
        }
    }

    #[test]
    fn copy_match_distance_exceeds_capacity_errors() {
        let mut d = Dict::new(16).unwrap();
        let mut out = Vec::new();
        // Push 32 bytes so total_written > capacity; the
        // distance check fails on capacity first.
        for i in 0..32u8 {
            d.push_literal(i, &mut out);
        }
        let err = d.copy_match(17, 1, &mut out).unwrap_err();
        match err {
            DictError::DistanceExceedsCapacity { distance, capacity } => {
                assert_eq!(distance, 17);
                assert_eq!(capacity, 16);
            }
            other => panic!("expected DistanceExceedsCapacity, got {other:?}"),
        }
    }

    #[test]
    fn copy_match_wraps_around_when_head_passes_capacity() {
        // Capacity 8. Fill it, then copy_match(8, 5) — source
        // straddles the wrap point.
        let mut d = Dict::new(8).unwrap();
        let mut out = Vec::new();
        for &b in b"ABCDEFGH" {
            d.push_literal(b, &mut out);
        }
        // head is now 0. copy_match(8, 5) → src starts 8 back =
        // wraps to position 0 = 'A'; copies 'A','B','C','D','E'.
        out.clear();
        d.copy_match(8, 5, &mut out).unwrap();
        assert_eq!(out, b"ABCDE");
    }

    #[test]
    fn total_written_persists_across_ring_wrap() {
        let mut d = Dict::new(4).unwrap();
        let mut out = Vec::new();
        // Push 10 bytes through a 4-byte ring.
        for b in 0..10u8 {
            d.push_literal(b, &mut out);
        }
        assert_eq!(d.total_written(), 10);
        assert_eq!(d.live_bytes(), 4);
    }

    #[test]
    fn copy_recent_into_returns_last_n_bytes_in_stream_order() {
        let mut d = Dict::new(16).unwrap();
        let mut out = Vec::new();
        for &b in b"ABCDEFGHIJ" {
            d.push_literal(b, &mut out);
        }
        let mut recent = vec![0u8; 4];
        d.copy_recent_into(&mut recent).unwrap();
        // Most-recent 4 bytes: "GHIJ".
        assert_eq!(&recent[..], b"GHIJ");
    }

    #[test]
    fn copy_recent_into_handles_wrap() {
        // Capacity 8, push 12 bytes. live_bytes = 8. Pull last
        // 6 → should include the wrap.
        let mut d = Dict::new(8).unwrap();
        let mut out = Vec::new();
        for &b in b"ABCDEFGHIJKL" {
            d.push_literal(b, &mut out);
        }
        let mut recent = vec![0u8; 6];
        d.copy_recent_into(&mut recent).unwrap();
        // Most-recent 6 of "ABCDEFGHIJKL" = "GHIJKL".
        assert_eq!(&recent[..], b"GHIJKL");
    }

    #[test]
    fn copy_recent_into_overrun_errors() {
        let mut d = Dict::new(64).unwrap();
        let mut out = Vec::new();
        d.push_literal(b'A', &mut out);
        let mut recent = vec![0u8; 10];
        let err = d.copy_recent_into(&mut recent).unwrap_err();
        match err {
            DictError::RecentWindowOverrun {
                requested,
                available,
            } => {
                assert_eq!(requested, 10);
                assert_eq!(available, 1);
            }
            other => panic!("expected RecentWindowOverrun, got {other:?}"),
        }
    }

    #[test]
    fn max_dict_bytes_capacity_constructs() {
        // The cap itself must succeed.
        let d = Dict::new(MAX_DICT_BYTES).unwrap();
        assert_eq!(d.capacity(), MAX_DICT_BYTES);
        assert_eq!(d.total_written(), 0);
    }
}
