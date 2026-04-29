//! Single-file output sink.
//!
//! Every byte fed to a [`RawSink`] is written verbatim to one open
//! file at the path the constructor was given. There is no framing,
//! no transformation, and no buffering beyond what the underlying
//! [`std::fs::File`] does. The right choice when the source decodes
//! to a single output stream — a plain `.zst` of one file, a `.gz` of
//! a single tarball that the user wants kept whole, etc.
//!
//! The sink reports [`Sink::is_quiescent`] as `true` unconditionally:
//! every byte boundary is a valid checkpoint because there is no
//! parser state to be in the middle of. The coordinator's checkpoints
//! still need to align with the decoder's frame boundaries, but the
//! sink imposes no extra constraint.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::sink::{Sink, SinkError};

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
    /// The file every byte goes to. `Some` while the sink is live;
    /// taken by [`Sink::close`] to drop and flush the descriptor.
    file: Option<File>,
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
    /// `path` is recorded only for diagnostics.
    #[must_use]
    pub fn wrap(path: PathBuf, file: File) -> Self {
        Self {
            path,
            file: Some(file),
        }
    }

    /// Return a borrow of the underlying file. Useful for tests that
    /// want to query the descriptor's metadata mid-stream.
    #[must_use]
    pub fn file(&self) -> Option<&File> {
        self.file.as_ref()
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
        file.write_all(buf).map_err(|source| SinkError::Io {
            path: path.clone(),
            source,
        })
    }

    fn is_quiescent(&self) -> bool {
        true
    }

    fn close(mut self) -> Result<(), SinkError> {
        // Take the file out so a panic between flush() and the end of
        // the function still drops the descriptor. `flush` on a plain
        // `File` is a no-op; we still call it so any future
        // BufWriter-style wrapper Just Works without revisiting the
        // close discipline here.
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
