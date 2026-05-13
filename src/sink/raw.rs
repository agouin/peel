//! Single-file output sink.
//!
//! Every byte fed to a [`RawSink`] is written verbatim to one open
//! file at the path the constructor was given. There is no framing
//! and no transformation. Bytes pass through a 1 MiB write-side
//! buffer ([`RAW_SINK_BUF_CAPACITY`]) so the decoder's natural
//! 64-128 KiB output chunks coalesce into one filesystem `write(2)`
//! per buffer flush — see `internal/PLAN_raw_row_throughput.md`
//! Phase 1 for the rationale.
//!
//! The sink reports [`Sink::is_quiescent`] as `true` unconditionally:
//! every byte boundary is a valid checkpoint because there is no
//! parser state to be in the middle of. To pair this with the
//! buffered writes, the sink's [`Sink::flush_durable`] override is
//! called by the extractor before each checkpoint commit so the
//! `bytes_written` field of the persisted [`crate::checkpoint::SinkState`]
//! reflects bytes that have actually reached the kernel.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::sink::{Sink, SinkError};

/// Write-side buffer capacity wrapped around the underlying file.
///
/// 1 MiB matches three things at once:
/// - the streaming decoder's `OUTPUT_CHUNK = 1 MiB` cap, so the
///   buffer holds at most one `decode_step` worth of output before a
///   flush;
/// - the macOS APFS extent granularity (~1 MiB), so the page-cache
///   write boundary aligns with the filesystem's allocation
///   boundary;
/// - the `--max-disk-buffer` default budget the user-named memory
///   ceiling tracks, so the buffer is comfortably inside that budget.
///
/// Selected by `internal/PLAN_raw_row_throughput.md` Phase 1.
pub const RAW_SINK_BUF_CAPACITY: usize = 1 << 20;

/// Streams every byte to a single output file.
///
/// Construct with [`RawSink::create`] (truncating create) or
/// [`RawSink::wrap`] when the caller already holds the [`File`] (used
/// by tests and, in §8, by the resume path that opens an
/// already-extracted prefix in append mode).
#[derive(Debug)]
pub struct RawSink {
    /// Path the sink was constructed from. Used only for diagnostic
    /// messages — the file's identity is the open descriptor.
    path: PathBuf,
    /// 1 MiB write-buffered handle to the output file. `Some` while
    /// the sink is live; taken by [`Sink::close`] to flush and drop
    /// the descriptor.
    file: Option<BufWriter<File>>,
    /// Total bytes successfully accepted by [`Sink::write`] —
    /// initialized to `0` by [`Self::create`] / [`Self::wrap`] and to
    /// the existing offset by [`Self::resume`] so a checkpoint
    /// captured immediately after a resume reflects the correct
    /// already-on-disk byte count.
    ///
    /// This counter is incremented at the [`Sink::write`] call site
    /// (in-buffer), not at the underlying syscall — pair with
    /// [`Sink::flush_durable`] before persisting a checkpoint so
    /// the count published in [`crate::checkpoint::SinkState`] is
    /// known to be on disk rather than in the `BufWriter`.
    bytes_written: u64,
}

impl RawSink {
    /// Create or truncate the file at `path` and wrap it in a
    /// [`RawSink`].
    ///
    /// # Errors
    ///
    /// Returns [`SinkError::Io`] if the file cannot be opened — most
    /// commonly because the parent directory does not exist or the
    /// caller lacks permission.
    pub fn create<P: AsRef<Path>>(path: P) -> Result<Self, SinkError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .map_err(|source| SinkError::Io {
                path: path.clone(),
                source,
            })?;
        Ok(Self::wrap(path, file))
    }

    /// Wrap an already-open [`File`] in a [`RawSink`].
    ///
    /// `path` is recorded only for diagnostics. `bytes_written` is
    /// seeded to `0` — callers that wrap a partially-written file
    /// should use [`Self::resume`] (or set the field afterward via
    /// the resume path) so checkpoint state reflects the on-disk
    /// length.
    #[must_use]
    pub fn wrap(path: PathBuf, file: File) -> Self {
        Self {
            path,
            file: Some(BufWriter::with_capacity(RAW_SINK_BUF_CAPACITY, file)),
            bytes_written: 0,
        }
    }

    /// Open `path` without truncation, seek to `bytes_written`, and
    /// wrap the file in a [`RawSink`] ready to append from there.
    ///
    /// This is the resume entry point used by the §10 coordinator
    /// after a crash: the prior run wrote `bytes_written` decoded
    /// bytes into the file before exiting, the new run constructs a
    /// decoder positioned at the matching frame boundary in the
    /// source, and the two streams meet exactly at `bytes_written`.
    ///
    /// The file is truncated to `bytes_written` so any partial write
    /// past that point (uncommon but possible if the kernel flushed
    /// non-frame-aligned data after the most recent checkpoint) is
    /// discarded before the resumed extraction continues.
    ///
    /// # Errors
    ///
    /// Returns [`SinkError::Io`] if the file cannot be opened, the
    /// seek fails, or the truncation fails.
    pub fn resume<P: AsRef<Path>>(path: P, bytes_written: u64) -> Result<Self, SinkError> {
        let path = path.as_ref().to_path_buf();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| SinkError::Io {
                path: path.clone(),
                source,
            })?;
        file.set_len(bytes_written)
            .map_err(|source| SinkError::Io {
                path: path.clone(),
                source,
            })?;
        file.seek(SeekFrom::Start(bytes_written))
            .map_err(|source| SinkError::Io {
                path: path.clone(),
                source,
            })?;
        let mut sink = Self::wrap(path, file);
        sink.bytes_written = bytes_written;
        Ok(sink)
    }

    /// Return a borrow of the underlying file. Useful for tests that
    /// want to query the descriptor's metadata mid-stream.
    ///
    /// Note that the descriptor's reported length lags
    /// [`Self::bytes_written`] by whatever is currently sitting in
    /// the 1 MiB `BufWriter`; callers that want a flushed-to-disk
    /// view should run [`Sink::flush_durable`] first.
    #[must_use]
    pub fn file(&self) -> Option<&File> {
        self.file.as_ref().map(BufWriter::get_ref)
    }

    /// Return the path the sink was constructed from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Sink for RawSink {
    fn write(&mut self, buf: &[u8]) -> Result<(), SinkError> {
        let path = &self.path;
        let file = self.file.as_mut().ok_or_else(|| SinkError::Io {
            path: path.clone(),
            source: std::io::Error::other("raw sink already closed"),
        })?;
        // `BufWriter::write_all` returns an error inline only when an
        // inner `write(2)` fails *during* the buffered fill (i.e. the
        // buffer was already full and the spilling write to the file
        // surfaced an errno) — every other failure mode parks until
        // the next [`Self::flush_durable`] or [`Sink::close`]. The
        // contract change is intentional and documented at the
        // sink-trait level; the checkpoint observer's
        // `flush_durable` call narrows the deferral window to one
        // checkpoint cadence (~8 MiB on a 1 GiB run, default config).
        file.write_all(buf).map_err(|source| SinkError::Io {
            path: path.clone(),
            source,
        })?;
        self.bytes_written = self.bytes_written.saturating_add(buf.len() as u64);
        Ok(())
    }

    fn is_quiescent(&self) -> bool {
        true
    }

    fn sink_state(&self) -> crate::checkpoint::SinkState {
        crate::checkpoint::SinkState::Raw {
            bytes_written: self.bytes_written,
        }
    }

    /// Drain the 1 MiB write buffer into the underlying file.
    ///
    /// The extractor's checkpoint observer calls this immediately
    /// before [`Sink::sink_state`] is captured, so the
    /// `bytes_written` field of the persisted checkpoint reflects
    /// bytes that have reached the kernel rather than bytes that
    /// are still sitting in this sink's buffer. Without this hook a
    /// `kill -9` between a checkpoint's `fsync` and the next
    /// natural `BufWriter` flush would leave the on-disk file short
    /// of the checkpoint's recorded length, and the resume path
    /// (which `set_len`s to the recorded length) would *grow* the
    /// file with zero bytes rather than truncating — bug.
    fn flush_durable(&mut self) -> Result<(), SinkError> {
        if let Some(file) = self.file.as_mut() {
            file.flush().map_err(|source| SinkError::Io {
                path: self.path.clone(),
                source,
            })?;
        }
        Ok(())
    }

    fn close(mut self) -> Result<(), SinkError> {
        // Take the buffered writer out so a panic between flush and
        // the end of the function still drops the descriptor.
        // `BufWriter::flush` is the call that surfaces any errno
        // parked in the buffer since the last successful flush; we
        // call it explicitly rather than relying on `BufWriter`'s
        // drop impl, since drop's flush failure is silently
        // discarded.
        if let Some(mut file) = self.file.take() {
            file.flush().map_err(|source| SinkError::Io {
                path: self.path.clone(),
                source,
            })?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::io::Read;

    /// Write a couple of buffers, close, and verify the file matches.
    #[test]
    fn raw_sink_writes_and_closes() {
        let tmp = std::env::temp_dir().join(format!(
            "peel-raw-sink-{}-{}.bin",
            std::process::id(),
            line!(),
        ));
        let _ = fs::remove_file(&tmp);

        let mut sink = RawSink::create(&tmp).expect("create");
        sink.write(b"hello, ").expect("write 1");
        sink.write(b"raw sink!").expect("write 2");
        sink.close().expect("close");

        let mut got = Vec::new();
        File::open(&tmp)
            .expect("reopen")
            .read_to_end(&mut got)
            .expect("read");
        assert_eq!(got, b"hello, raw sink!");

        fs::remove_file(&tmp).ok();
    }

    /// `is_quiescent` must hold both before any writes and between any
    /// pair of writes.
    #[test]
    fn raw_sink_is_always_quiescent() {
        let tmp = std::env::temp_dir().join(format!(
            "peel-raw-sink-quiescent-{}-{}.bin",
            std::process::id(),
            line!(),
        ));
        let _ = fs::remove_file(&tmp);

        let mut sink = RawSink::create(&tmp).expect("create");
        assert!(sink.is_quiescent());
        sink.write(b"abc").expect("write");
        assert!(sink.is_quiescent());
        sink.write(b"def").expect("write");
        assert!(sink.is_quiescent());
        sink.close().expect("close");
        fs::remove_file(&tmp).ok();
    }

    /// Opening a path whose parent directory does not exist surfaces
    /// the OS error inside [`SinkError::Io`].
    #[test]
    fn raw_sink_create_failure_reports_path() {
        let bogus = std::path::PathBuf::from("/this/path/does/not/exist/file.bin");
        let err = RawSink::create(&bogus).expect_err("must fail");
        match err {
            SinkError::Io { path, .. } => assert_eq!(path, bogus),
            other => panic!("expected SinkError::Io, got {other:?}"),
        }
    }

    /// Writing to a sink whose file slot has been taken (only
    /// reachable via the public `wrap` + manual close pattern in
    /// internal tests) surfaces [`SinkError::Io`] with a clear
    /// message.
    #[test]
    fn raw_sink_write_after_close_errors() {
        let tmp = std::env::temp_dir().join(format!(
            "peel-raw-sink-after-close-{}-{}.bin",
            std::process::id(),
            line!(),
        ));
        let _ = fs::remove_file(&tmp);

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)
            .expect("open");
        let mut sink = RawSink::wrap(tmp.clone(), file);
        // Manually drain the file slot to exercise the
        // already-closed branch — this mirrors what `close` does and
        // is the only way to hit the error path without UB.
        let _drained = sink.file.take();
        match sink.write(b"x") {
            Err(SinkError::Io { path, .. }) => assert_eq!(path, tmp),
            other => panic!("expected SinkError::Io, got {other:?}"),
        }

        fs::remove_file(&tmp).ok();
    }

    /// `RawSink::resume` opens an existing file at the recorded
    /// position and continues writing without truncating earlier bytes.
    #[test]
    fn raw_sink_resume_preserves_prior_bytes_and_appends() {
        let tmp = std::env::temp_dir().join(format!(
            "peel-raw-sink-resume-{}-{}.bin",
            std::process::id(),
            line!(),
        ));
        let _ = fs::remove_file(&tmp);

        let mut first = RawSink::create(&tmp).expect("create");
        first.write(b"first half;").expect("first write");
        first.close().expect("close first");

        let written = b"first half;".len() as u64;
        let mut second = RawSink::resume(&tmp, written).expect("resume");
        second.write(b"second half").expect("second write");
        second.close().expect("close second");

        let mut got = Vec::new();
        File::open(&tmp)
            .expect("reopen")
            .read_to_end(&mut got)
            .expect("read");
        assert_eq!(got, b"first half;second half");

        fs::remove_file(&tmp).ok();
    }

    /// Resume truncates any post-checkpoint debris that survived a
    /// crash, then continues at the new position.
    #[test]
    fn raw_sink_resume_truncates_past_recorded_position() {
        let tmp = std::env::temp_dir().join(format!(
            "peel-raw-sink-resume-truncate-{}-{}.bin",
            std::process::id(),
            line!(),
        ));
        let _ = fs::remove_file(&tmp);

        // Simulate a prior run that wrote 20 bytes, of which only
        // the first 10 were checkpoint-durable.
        fs::write(&tmp, b"AAAAAAAAAA0123456789").expect("write");
        let mut sink = RawSink::resume(&tmp, 10).expect("resume");
        sink.write(b"BBBBB").expect("append");
        sink.close().expect("close");

        let mut got = Vec::new();
        File::open(&tmp)
            .expect("reopen")
            .read_to_end(&mut got)
            .expect("read");
        assert_eq!(got, b"AAAAAAAAAABBBBB");
        fs::remove_file(&tmp).ok();
    }

    /// Streaming a moderately large payload in many small writes
    /// produces the same bytes on disk as a single bulk write.
    #[test]
    fn raw_sink_streams_arbitrary_chunk_boundaries() {
        let tmp = std::env::temp_dir().join(format!(
            "peel-raw-sink-stream-{}-{}.bin",
            std::process::id(),
            line!(),
        ));
        let _ = fs::remove_file(&tmp);

        let payload: Vec<u8> = (0..4096u32).flat_map(u32::to_le_bytes).collect();

        let mut sink = RawSink::create(&tmp).expect("create");
        // 7 is coprime with 4 (the natural alignment of u32 chunks)
        // so this exercises every byte alignment of a write boundary.
        for chunk in payload.chunks(7) {
            sink.write(chunk).expect("write");
        }
        sink.close().expect("close");

        let mut got = Vec::new();
        File::open(&tmp)
            .expect("reopen")
            .read_to_end(&mut got)
            .expect("read");
        assert_eq!(got, payload);
        fs::remove_file(&tmp).ok();
    }
}
