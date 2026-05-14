//! Bzip2 RLE1 inverse — the stream-level run-length-encoding stage
//! that runs *between* the BWT-inverse output and the final
//! consumer sink.
//!
//! `internal/PLAN_bz2_support.md` Phase 6. Bzip2's encoder applies
//! RLE1 *before* splitting the input into blocks — every block's
//! BWT-inverse output is therefore a segment of one continuous
//! RLE1-encoded stream, not a self-contained chunk. The decoder
//! must run a stateful RLE1 inverse over the concatenation of
//! every block's BWT-inverse output, with state carried across
//! block boundaries and **reset at stream boundaries** (per the
//! plan and matching the bzip2 reference's multi-stream behavior).
//!
//! # Encoding rule (forward)
//!
//! A run of `len` consecutive identical bytes `b` is encoded as:
//!
//! - `len ≤ 3`: just `len` copies of `b`.
//! - `len ≥ 4`: four copies of `b` followed by a single count
//!   byte `c = len - 4` in `0..=255`; the encoder caps a single
//!   run at 259 (it splits longer runs into multiple
//!   `(4-copies + count)` pairs).
//!
//! # Inverse rule
//!
//! The inverter walks input one byte at a time and tracks
//! `(last_byte, run_count)` with `run_count ∈ 0..=4`:
//!
//! - When `run_count == 0`: this is the first byte of a new run.
//!   Emit it, set `last_byte`, set `run_count = 1`.
//! - When `0 < run_count < 4` and `byte == last_byte`: emit it,
//!   bump `run_count`.
//! - When `0 < run_count < 4` and `byte != last_byte`: emit it,
//!   reset to `run_count = 1`, `last_byte = byte`.
//! - When `run_count == 4`: this byte is the explicit count of
//!   *additional* repeats. Emit `byte` more copies of `last_byte`,
//!   set `run_count = 0`.

use std::io::Write;

use super::error::Bzip2Error;

/// Stream-level RLE1 inverter. Constructed once per stream; carries
/// `(last_byte, run_count)` across block boundaries within the same
/// stream, reset at stream boundaries (which the orchestrating
/// decoder re-constructs the state for).
#[derive(Debug, Clone, Copy, Default)]
pub struct Rle1State {
    /// Last emitted byte (or 0 if `run == 0`, in which case the
    /// value is unused).
    last: u8,
    /// Consecutive-byte count, in `0..=4`. When `run == 4` the next
    /// input byte is the explicit count of additional repeats.
    run: u8,
}

impl Rle1State {
    /// Fresh inverter — equivalent to [`Self::default`].
    #[must_use]
    pub const fn new() -> Self {
        Self { last: 0, run: 0 }
    }

    /// Read-only accessors used by the resume blob.
    #[must_use]
    pub const fn last(&self) -> u8 {
        self.last
    }

    /// Read-only accessor for the run count.
    #[must_use]
    pub const fn run(&self) -> u8 {
        self.run
    }

    /// Restore a previously captured state. Used by the resume
    /// factory in Phase 8.
    pub fn set(&mut self, last: u8, run: u8) -> Result<(), Bzip2Error> {
        if run > 4 {
            return Err(Bzip2Error::ResumeBlob(
                "RLE1 run count > 4 — outside the valid 0..=4 range",
            ));
        }
        self.last = last;
        self.run = run;
        Ok(())
    }

    /// Push one BWT-inverse-output byte through the inverter, emit
    /// zero or more bytes to `sink`.
    ///
    /// # Errors
    ///
    /// Forwards any [`std::io::Error`] surfaced by `sink`, wrapped
    /// in [`Bzip2Error::SinkIo`].
    pub fn feed(&mut self, byte: u8, sink: &mut dyn Write) -> Result<(), Bzip2Error> {
        if self.run == 4 {
            // `byte` is the explicit count of additional repeats.
            // Emit `byte` more copies of `last`, then reset.
            if byte > 0 {
                let buf = [self.last; 1];
                for _ in 0..byte {
                    sink.write_all(&buf).map_err(Bzip2Error::SinkIo)?;
                }
            }
            self.run = 0;
            return Ok(());
        }
        if self.run == 0 {
            // First byte of a new run.
            sink.write_all(&[byte]).map_err(Bzip2Error::SinkIo)?;
            self.last = byte;
            self.run = 1;
            return Ok(());
        }
        // 0 < run < 4 here.
        if byte == self.last {
            sink.write_all(&[byte]).map_err(Bzip2Error::SinkIo)?;
            self.run += 1;
        } else {
            sink.write_all(&[byte]).map_err(Bzip2Error::SinkIo)?;
            self.last = byte;
            self.run = 1;
        }
        Ok(())
    }

    /// Convenience: feed a whole slice through the inverter.
    ///
    /// # Errors
    ///
    /// Forwarded from [`Self::feed`].
    pub fn feed_slice(&mut self, bytes: &[u8], sink: &mut dyn Write) -> Result<(), Bzip2Error> {
        for &b in bytes {
            self.feed(b, sink)?;
        }
        Ok(())
    }

    /// Reset the state to its post-construction zero. Called at
    /// every stream boundary in a multi-stream `.bz2` file.
    pub fn reset(&mut self) {
        self.last = 0;
        self.run = 0;
    }
}

/// Forward RLE1 encoding for testing — the inverse of
/// [`Rle1State::feed`]. Encodes `data` byte-by-byte and returns
/// the encoded byte stream. Used in unit tests to verify round-
/// trips without depending on a real `.bz2` fixture.
#[cfg(test)]
pub fn forward_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut last: u8 = 0;
    let mut run: u32 = 0;
    let flush = |out: &mut Vec<u8>, last: u8, run: u32| {
        let mut remaining = run;
        while remaining > 0 {
            let chunk = remaining.min(259);
            let copies = chunk.min(4);
            for _ in 0..copies {
                out.push(last);
            }
            if chunk >= 4 {
                // INVARIANT: chunk - 4 in 0..=255.
                out.push((chunk - 4) as u8);
            }
            remaining -= chunk;
        }
    };
    for &b in data {
        if run > 0 && b == last {
            run += 1;
            if run == 259 {
                flush(&mut out, last, run);
                run = 0;
            }
        } else {
            if run > 0 {
                flush(&mut out, last, run);
            }
            last = b;
            run = 1;
        }
    }
    if run > 0 {
        flush(&mut out, last, run);
    }
    out
}

/// Convenience for callers that want a single-shot inverse over a
/// known buffer (no streaming). Returns the decoded byte stream.
///
/// # Errors
///
/// Forwarded from [`Rle1State::feed_slice`].
#[cfg(test)]
fn decode_all(encoded: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut state = Rle1State::new();
    let mut out = Vec::with_capacity(encoded.len());
    state.feed_slice(encoded, &mut out).map_err(|e| match e {
        Bzip2Error::SinkIo(io) => io,
        other => std::io::Error::other(other.to_string()),
    })?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_no_runs() {
        let input = b"hello, world\n".to_vec();
        let encoded = forward_encode(&input);
        // No runs of 4: encoding is identical to input.
        assert_eq!(encoded, input);
        let decoded = decode_all(&encoded).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn round_trips_run_of_four() {
        let input = b"aaaa".to_vec();
        let encoded = forward_encode(&input);
        // 4-byte run: "aaaa" + 0.
        assert_eq!(encoded, vec![b'a', b'a', b'a', b'a', 0]);
        let decoded = decode_all(&encoded).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn round_trips_run_of_five() {
        let input = b"aaaaa".to_vec();
        let encoded = forward_encode(&input);
        assert_eq!(encoded, vec![b'a', b'a', b'a', b'a', 1]);
        let decoded = decode_all(&encoded).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn round_trips_long_run_with_split() {
        // 260 'a's: encoded as (4 'a' + 255) + (1 'a').
        let input = vec![b'a'; 260];
        let encoded = forward_encode(&input);
        assert_eq!(encoded.len(), 4 + 1 + 1);
        let decoded = decode_all(&encoded).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn round_trips_runs_with_mixed_breaks() {
        let input = b"aaaabcdaaaaa".to_vec();
        let encoded = forward_encode(&input);
        let decoded = decode_all(&encoded).expect("decode");
        assert_eq!(decoded, input);
    }

    #[test]
    fn streaming_across_artificial_split_matches_one_shot() {
        // Split the encoded stream into two halves; feed each into
        // the inverter; the output should still match the original.
        let input: Vec<u8> = (0..u8::MAX).flat_map(|i| vec![i; 5]).collect();
        let encoded = forward_encode(&input);
        let mid = encoded.len() / 2;

        let mut state = Rle1State::new();
        let mut out: Vec<u8> = Vec::new();
        state.feed_slice(&encoded[..mid], &mut out).expect("first");
        state.feed_slice(&encoded[mid..], &mut out).expect("second");
        assert_eq!(out, input);
    }

    #[test]
    fn streaming_across_run_boundary_is_byte_identical() {
        // 4 a's, then split *right after* the 4th a but BEFORE the
        // count byte. The inverter must remember run=4 across the
        // split and consume the count byte from the second half.
        let input = vec![b'a'; 10];
        let encoded = forward_encode(&input);
        // Encoded: a a a a 6 (5 bytes). Split at offset 4.
        let mut state = Rle1State::new();
        let mut out = Vec::new();
        state.feed_slice(&encoded[..4], &mut out).expect("first");
        // After 4 a's emitted, run = 4 and out has 4 'a's.
        assert_eq!(out.len(), 4);
        assert_eq!(state.run(), 4);
        state.feed_slice(&encoded[4..], &mut out).expect("second");
        assert_eq!(out, input);
    }

    #[test]
    fn reset_clears_state_for_multi_stream_boundary() {
        let mut state = Rle1State::new();
        let mut out = Vec::new();
        state.feed_slice(b"aaaa", &mut out).expect("seed run");
        assert_eq!(state.run(), 4);
        state.reset();
        assert_eq!(state.run(), 0);
        // Next byte starts a fresh run from a fresh state.
        state.feed(b'b', &mut out).expect("post-reset");
        assert_eq!(out, b"aaaab");
    }

    #[test]
    fn set_validates_run_range() {
        let mut state = Rle1State::new();
        match state.set(0, 5) {
            Err(Bzip2Error::ResumeBlob(_)) => {}
            other => panic!("expected ResumeBlob, got {other:?}"),
        }
        state.set(0x42, 3).expect("valid set");
        assert_eq!(state.last(), 0x42);
        assert_eq!(state.run(), 3);
    }
}
