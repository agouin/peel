//! Per-file on-disk sink for the 7z pipeline.
//!
//! Implements §7 of `internal/PLAN_7z_support.md`. Mirrors
//! [`crate::sink::zip::ZipSink`]'s shape but is driven by
//! [`crate::decode::sevenz::folder::FolderSink`] (begin /
//! write / end *substream*) rather than the per-entry
//! interface ZIP uses, because 7z's solid-folder model means
//! multiple files share one decoded byte stream.
//!
//! The sink also exposes a [`Self::materialize_empty`] entry
//! point the §8 pipeline calls for `is_directory ||
//! !has_stream` files — those never go through the substream
//! path because the folder decoder never emits bytes for them.
//!
//! Every byte that flows through `write_substream` is hashed
//! into a per-substream CRC32 the
//! [`crate::decode::sevenz::folder::FolderSink::end_substream`]
//! call validates against the value the archive recorded. A
//! mismatch deletes the partially-written file and surfaces a
//! typed [`crate::sink::SinkError`].

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use crate::decode::sevenz::folder::{FolderSink, FolderSinkError};
use crate::decode::sevenz::header::FileRecord;
use crate::sink::SinkError;
// Slicing-by-16 CRC32. See the analogous import in
// `crate::decode::sevenz::folder` for the perf reasoning.
use crate::zip::crc32::Crc32;

/// Streaming destination for a 7z extraction.
///
/// Constructed by [`Self::new`] with a sanitized root and the
/// parsed file list. The §8 pipeline iterates folders in
/// archive order, driving the [`FolderSink`] trait methods for
/// each substream and calling [`Self::materialize_empty`] for
/// directory / zero-byte entries.
pub struct SevenzSink {
    /// Canonicalized extraction root.
    root: PathBuf,
    /// Parsed `FilesInfo` records, one per archive file. `None`
    /// until the §8 pipeline parses the trailer and populates
    /// it via [`Self::set_files`]; the deferred-construction
    /// shape is what enables the streaming overlap with the
    /// download (pre-fetching the trailer in the coordinator
    /// would force workers to fetch the entire archive
    /// front-to-back before the pipeline could start).
    files: Option<Vec<FileRecord>>,
    /// In-flight substream, if any. `None` between substreams
    /// (the moment a checkpoint can capture).
    current: Option<EntryState>,
    /// Sticky failure flag. Once a substream errors, every
    /// subsequent call returns an error too.
    poisoned: bool,
}

/// Mid-substream state.
struct EntryState {
    /// Index into [`SevenzSink::files`].
    file_index: u32,
    /// Resolved on-disk path. Carried for error context.
    path: PathBuf,
    /// File the substream is being written to.
    file: File,
    /// Bytes written into the in-flight file so far.
    bytes_written: u64,
    /// Expected total uncompressed size from the archive.
    expected_size: u64,
    /// Running CRC32 over every byte written.
    crc: Crc32,
}

impl SevenzSink {
    /// Construct a sink that extracts into `root`.
    ///
    /// `root` must already exist; the sink does not create the
    /// extraction root, only entries within it. The file list
    /// is deferred — the pipeline calls [`Self::set_files`]
    /// once the trailer has been parsed.
    ///
    /// # Errors
    ///
    /// [`SinkError::Io`] if `root` cannot be canonicalized.
    pub fn new<P: AsRef<Path>>(root: P) -> Result<Self, SinkError> {
        let root_ref = root.as_ref();
        let canonical = root_ref.canonicalize().map_err(|source| SinkError::Io {
            path: root_ref.to_path_buf(),
            source,
        })?;
        Ok(Self {
            root: canonical,
            files: None,
            current: None,
            poisoned: false,
        })
    }

    /// Install the parsed `FilesInfo` list. The §8 pipeline
    /// calls this exactly once, after parsing the trailer and
    /// before invoking any [`FolderSink`] or
    /// [`Self::materialize_empty`] method. Calling twice on the
    /// same sink is a programmer error and surfaces a sticky
    /// poison.
    pub fn set_files(&mut self, files: Vec<FileRecord>) {
        debug_assert!(self.files.is_none(), "SevenzSink::set_files called twice");
        self.files = Some(files);
    }

    /// Borrow the installed file list. Returns `None` until
    /// [`Self::set_files`] has been called.
    #[must_use]
    pub fn files(&self) -> Option<&[FileRecord]> {
        self.files.as_deref()
    }

    /// Borrow the configured extraction root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether the sink is between substreams.
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        !self.poisoned && self.current.is_none()
    }

    /// Resolve `file_index`'s path against the extraction root,
    /// with the same anti-traversal rules
    /// [`crate::sink::zip::ZipSink::resolve_entry_path`] enforces.
    ///
    /// `FileRecord.name` is already sanitized by the §1 name
    /// parser, but defending-in-depth here catches a class of
    /// bugs where a future code path lands an
    /// un-sanitized [`FileRecord`] in the sink.
    ///
    /// # Errors
    ///
    /// - [`SinkError::PathEscape`] if the resolved path is not
    ///   under [`Self::root`] or contains a non-normal
    ///   component.
    pub fn resolve_file_path(&self, file_index: u32) -> Result<PathBuf, SinkError> {
        let files = self.files.as_ref().ok_or_else(|| SinkError::Io {
            path: self.root.clone(),
            source: std::io::Error::other("SevenzSink::resolve_file_path called before set_files"),
        })?;
        let rec = files
            .get(file_index as usize)
            .ok_or_else(|| SinkError::PathEscape {
                entry: format!("file_index {file_index} out of range"),
                root: self.root.clone(),
            })?;
        // Accumulate Normal components onto the root; reject any
        // that aren't.
        let mut out = self.root.clone();
        let mut pushed = 0usize;
        for component in rec.name.components() {
            match component {
                Component::Normal(name) => {
                    out.push(name);
                    pushed += 1;
                }
                _ => {
                    return Err(SinkError::PathEscape {
                        entry: rec.name.display().to_string(),
                        root: self.root.clone(),
                    });
                }
            }
        }
        if pushed == 0 {
            return Err(SinkError::PathEscape {
                entry: rec.name.display().to_string(),
                root: self.root.clone(),
            });
        }
        Ok(out)
    }

    /// Materialize an empty file or directory entry —
    /// `is_directory || !has_stream` in the FilesInfo. Never
    /// goes through `write_substream`.
    ///
    /// # Errors
    ///
    /// - [`SinkError::PathEscape`] for any path that fails
    ///   anti-traversal.
    /// - [`SinkError::Io`] for filesystem failures.
    pub fn materialize_empty(&mut self, file_index: u32) -> Result<(), SinkError> {
        self.poison_check()?;
        let files = self.files.as_ref().ok_or_else(|| SinkError::Io {
            path: self.root.clone(),
            source: std::io::Error::other("SevenzSink::materialize_empty called before set_files"),
        })?;
        let rec = files
            .get(file_index as usize)
            .ok_or_else(|| SinkError::PathEscape {
                entry: format!("file_index {file_index} out of range"),
                root: self.root.clone(),
            })?;
        let is_directory = rec.is_directory;
        let path = self.resolve_file_path(file_index)?;
        if is_directory {
            return fs::create_dir_all(&path).map_err(|source| SinkError::Io {
                path: path.clone(),
                source,
            });
        }
        // Empty regular file: ensure parent dir exists, create
        // the file zero-sized.
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| SinkError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|source| SinkError::Io {
                path: path.clone(),
                source,
            })?;
        Ok(())
    }

    /// Fail-fast guard: every operation calls this so a poisoned
    /// sink doesn't silently accept further bytes.
    fn poison_check(&self) -> Result<(), SinkError> {
        if self.poisoned {
            return Err(SinkError::Io {
                path: self.root.clone(),
                source: std::io::Error::other("SevenzSink poisoned by prior failure"),
            });
        }
        Ok(())
    }

    /// Mark the sink poisoned, optionally cleaning up the
    /// partially-written current entry first (file deleted).
    fn poison<E>(&mut self, err: E) -> E {
        if let Some(state) = self.current.take() {
            let _ = fs::remove_file(&state.path);
        }
        self.poisoned = true;
        err
    }
}

/// Translate a [`SinkError`] into a [`FolderSinkError`] so the
/// `FolderSink` trait surface stays homogeneous.
fn sink_err_to_folder_err(e: SinkError) -> FolderSinkError {
    match e {
        SinkError::Io { source, .. } => FolderSinkError::Io(source),
        // Path-escape and other parse-time errors map to a
        // generic IO failure for the folder decoder; the §8
        // pipeline catches the original SinkError before
        // dispatching the substream and never reaches here.
        // Any leak surfaces as a generic IO error so the
        // poison cascade still triggers.
        other => FolderSinkError::Io(std::io::Error::other(format!("{other}"))),
    }
}

impl FolderSink for SevenzSink {
    fn begin_substream(
        &mut self,
        _idx: u32,
        file_index: u32,
        expected_size: u64,
    ) -> Result<(), FolderSinkError> {
        self.poison_check().map_err(sink_err_to_folder_err)?;
        if self.current.is_some() {
            return Err(self.poison(FolderSinkError::Io(std::io::Error::other(
                "SevenzSink::begin_substream called while another substream is in flight",
            ))));
        }
        let path = match self.resolve_file_path(file_index) {
            Ok(p) => p,
            Err(e) => return Err(self.poison(sink_err_to_folder_err(e))),
        };
        if let Some(parent) = path.parent() {
            if let Err(source) = fs::create_dir_all(parent) {
                return Err(self.poison(FolderSinkError::Io(source)));
            }
        }
        let file = match OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
        {
            Ok(f) => f,
            Err(source) => return Err(self.poison(FolderSinkError::Io(source))),
        };
        self.current = Some(EntryState {
            file_index,
            path,
            file,
            bytes_written: 0,
            expected_size,
            crc: Crc32::new(),
        });
        Ok(())
    }

    fn write_substream(&mut self, buf: &[u8]) -> Result<(), FolderSinkError> {
        self.poison_check().map_err(sink_err_to_folder_err)?;
        let state = self.current.as_mut().ok_or_else(|| {
            FolderSinkError::Io(std::io::Error::other(
                "SevenzSink::write_substream called with no in-flight substream",
            ))
        })?;
        let projected = state.bytes_written.saturating_add(buf.len() as u64);
        if projected > state.expected_size {
            let err = FolderSinkError::Io(std::io::Error::other(format!(
                "SevenzSink: write would push past expected_size {} (currently \
                 {} written, {} more bytes incoming)",
                state.expected_size,
                state.bytes_written,
                buf.len(),
            )));
            return Err(self.poison(err));
        }
        if let Err(source) = state.file.write_all(buf) {
            return Err(self.poison(FolderSinkError::Io(source)));
        }
        state.crc.update(buf);
        state.bytes_written = projected;
        Ok(())
    }

    fn end_substream(&mut self, expected_crc: Option<u32>) -> Result<(), FolderSinkError> {
        self.poison_check().map_err(sink_err_to_folder_err)?;
        let state = self.current.take().ok_or_else(|| {
            FolderSinkError::Io(std::io::Error::other(
                "SevenzSink::end_substream called with no in-flight substream",
            ))
        })?;
        if state.bytes_written != state.expected_size {
            let path = state.path.clone();
            let _ = fs::remove_file(&path);
            self.poisoned = true;
            return Err(FolderSinkError::Io(std::io::Error::other(format!(
                "SevenzSink: substream for file_index {} ended at {} bytes, expected {}",
                state.file_index, state.bytes_written, state.expected_size,
            ))));
        }
        let computed = state.crc.current();
        if let Some(expected) = expected_crc {
            if computed != expected {
                let _ = fs::remove_file(&state.path);
                self.poisoned = true;
                return Err(FolderSinkError::Crc32Mismatch { expected, computed });
            }
        }
        // No per-substream `sync_all` — that costs ~10 ms each
        // on macOS and stacks up for archives with many small
        // files (the bench grid hit 1 s+ on dozens of entries).
        // [`crate::sink::zip::ZipSink::end_entry`] is similarly
        // sync-free; the §9 checkpoint discipline only needs
        // "all bytes for completed folders are on disk *before*
        // the checkpoint write makes them visible to a future
        // resume," which the upcoming `flush_folder` hook (a
        // `O.32f` follow-up to `internal/PLAN_7z_support.md` §9)
        // handles at folder boundaries via a single batched
        // fsync, not per-substream.
        let _ = state.file;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::decode::sevenz::folder::FolderDecoder;
    use crate::decode::sevenz::header::{Coder, FileRecord, Folder, StreamsInfo, SubStreamsInfo};

    /// Unique-name tempdir helper matching the rest of the
    /// codebase's `tests/` style: `tempfile` is on the allowed
    /// dev-deps list but not yet added to `Cargo.toml`, and the
    /// in-tree integration tests roll their own paths alongside.
    struct TempDirGuard {
        path: PathBuf,
    }

    impl TempDirGuard {
        fn new(label: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let pid = std::process::id();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("peel_sevenz_sink_{label}_{pid}_{nanos}_{n}"));
            std::fs::create_dir_all(&path).expect("create tempdir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn copy_coder() -> Coder {
        Coder {
            id: vec![0x00],
            props: vec![],
            num_in_streams: 1,
            num_out_streams: 1,
        }
    }

    fn file_record(name: &str, has_stream: bool, is_directory: bool) -> FileRecord {
        FileRecord {
            name: PathBuf::from(name),
            attrs: None,
            mtime: None,
            is_directory,
            has_stream,
            is_anti: false,
        }
    }

    #[test]
    fn materialize_empty_creates_file() {
        let dir = TempDirGuard::new("materialize_empty_creates_file");
        let mut sink = SevenzSink::new(dir.path()).expect("sink");
        sink.set_files(vec![file_record("empty.bin", false, false)]);
        sink.materialize_empty(0).expect("materializes");
        let path = dir.path().join("empty.bin");
        let meta = std::fs::metadata(&path).expect("file exists");
        assert_eq!(meta.len(), 0);
    }

    #[test]
    fn materialize_empty_creates_directory() {
        let dir = TempDirGuard::new("materialize_empty_creates_dir");
        let mut sink = SevenzSink::new(dir.path()).expect("sink");
        sink.set_files(vec![file_record("subdir", false, true)]);
        sink.materialize_empty(0).expect("materializes");
        let path = dir.path().join("subdir");
        assert!(path.is_dir());
    }

    #[test]
    fn folder_sink_round_trips_substream_bytes() {
        let dir = TempDirGuard::new("folder_sink_round_trips");
        let payload: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        let files = vec![file_record("hello.bin", true, false)];
        let mut sink = SevenzSink::new(dir.path()).expect("sink");
        sink.set_files(files);

        let folder = Folder {
            coders: vec![copy_coder()],
            bind_pairs: vec![],
            packed_stream_indices: vec![],
            unpack_sizes: vec![payload.len() as u64],
            unpack_crc: None,
        };
        let info = StreamsInfo {
            pack_pos: 0,
            pack_sizes: vec![payload.len() as u64],
            pack_crcs: vec![None],
            folders: vec![folder.clone()],
            sub_streams: SubStreamsInfo {
                num_unpack_streams: vec![1],
                unpack_sizes: vec![payload.len() as u64],
                unpack_crcs: vec![None],
            },
        };

        let mut src = std::io::Cursor::new(payload.clone());
        FolderDecoder::new(&info.folders[0], &info, 0, &[0u32], &mut src)
            .decode(&mut sink)
            .expect("decodes");
        assert!(sink.is_quiescent());

        let written = std::fs::read(dir.path().join("hello.bin")).expect("file readable");
        assert_eq!(written, payload);
    }

    #[test]
    fn folder_sink_validates_per_substream_crc_and_deletes_on_mismatch() {
        let dir = TempDirGuard::new("folder_sink_crc_deletes");
        let payload: Vec<u8> = b"data".to_vec();
        let files = vec![file_record("x.bin", true, false)];
        let mut sink = SevenzSink::new(dir.path()).expect("sink");
        sink.set_files(files);

        let folder = Folder {
            coders: vec![copy_coder()],
            bind_pairs: vec![],
            packed_stream_indices: vec![],
            unpack_sizes: vec![payload.len() as u64],
            unpack_crc: None,
        };
        let info = StreamsInfo {
            pack_pos: 0,
            pack_sizes: vec![payload.len() as u64],
            pack_crcs: vec![None],
            folders: vec![folder.clone()],
            sub_streams: SubStreamsInfo {
                num_unpack_streams: vec![1],
                unpack_sizes: vec![payload.len() as u64],
                unpack_crcs: vec![Some(0xDEAD_BEEF)], // wrong on purpose
            },
        };

        let mut src = std::io::Cursor::new(payload.clone());
        let res =
            FolderDecoder::new(&info.folders[0], &info, 0, &[0u32], &mut src).decode(&mut sink);
        assert!(res.is_err(), "expected CRC failure");
        // Partially-written file should be deleted.
        assert!(
            !dir.path().join("x.bin").exists(),
            "partial file should have been removed"
        );
    }

    #[test]
    fn resolve_file_path_rejects_dotdot_components() {
        let dir = TempDirGuard::new("resolve_dotdot");
        // Construct a FileRecord whose name has a `..`
        // component (bypassing the §1 sanitizer for this
        // defense-in-depth test).
        let mut rec = file_record("safe.bin", true, false);
        rec.name = PathBuf::from("..").join("escape.bin");
        let mut sink = SevenzSink::new(dir.path()).expect("sink");
        sink.set_files(vec![rec]);
        match sink.resolve_file_path(0) {
            Err(SinkError::PathEscape { .. }) => {}
            other => panic!("expected PathEscape, got {other:?}"),
        }
    }

    #[test]
    fn resolve_file_path_rejects_absolute_names() {
        let dir = TempDirGuard::new("resolve_absolute");
        let mut rec = file_record("safe.bin", true, false);
        rec.name = PathBuf::from("/absolute/path");
        let mut sink = SevenzSink::new(dir.path()).expect("sink");
        sink.set_files(vec![rec]);
        match sink.resolve_file_path(0) {
            Err(SinkError::PathEscape { .. }) => {}
            other => panic!("expected PathEscape, got {other:?}"),
        }
    }
}
