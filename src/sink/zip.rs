//! Per-entry on-disk sink for the ZIP pipeline.
//!
//! Streams decoded entry bytes to a directory tree, one entry at a
//! time. Mirrors the path-safety and member-aligned-quiescence
//! semantics of [`crate::sink::tar::TarSink`] but with a different
//! contract — the ZIP pipeline drives the sink explicitly via
//! [`Self::begin_entry`] / [`Self::write_entry`] / [`Self::end_entry`]
//! rather than feeding a single byte stream, because the
//! central-directory-at-the-end format means entries arrive in
//! discrete chunks and we always know each entry's bounds in advance.
//!
//! # Path safety
//!
//! Entry names are resolved purely lexically against the
//! configured root, with the same rules `TarSink` enforces:
//!
//! - absolute paths, empty names, and `..` components are rejected;
//! - NUL bytes in names are rejected;
//! - names that resolve to the root itself are rejected;
//! - the only thing different from `TarSink` is that ZIP encodes
//!   *directory* entries as names ending in `/` with zero
//!   uncompressed size — those are accepted and create the
//!   directory.
//!
//! # Resume
//!
//! Per `docs/PLAN_v2.md` §5 step 7, the checkpoint records
//! `current_entry_offset` for the in-flight entry. The pipeline
//! drives resume by either:
//!
//! - calling [`Self::begin_entry_resume_stored`] for STORED entries,
//!   which truncates the existing on-disk file to `resume_at`,
//!   re-reads the prefix to seed the running CRC-32, and continues
//!   accepting bytes from `resume_at`; or
//! - calling [`Self::begin_entry`] for DEFLATE / zstd entries, which
//!   truncates back to zero — neither codec exposes a serializable
//!   mid-stream state, so we replay the entry from its compressed
//!   start.
//!
//! Either way, the on-disk file ends up byte-identical to a clean run.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use crate::sink::SinkError;
use crate::zip::{Crc32, ZipError};

/// Streaming destination for a ZIP extraction.
///
/// Construct with [`ZipSink::new`]; drive entries via
/// [`Self::begin_entry`] (or [`Self::begin_entry_resume_stored`] on
/// resume), [`Self::write_entry`], and [`Self::end_entry`]. The
/// pipeline is responsible for stitching multiple entries into a
/// single extraction; the sink only owns the per-entry path
/// resolution, the per-entry file handle, and the running CRC-32.
pub struct ZipSink {
    /// Canonicalized extraction root.
    root: PathBuf,
    /// In-flight entry, if any. `None` between entries (the moment a
    /// checkpoint can capture). See [`Self::is_quiescent`].
    current: Option<EntryState>,
    /// Sticky failure flag. Once a write errors, every subsequent
    /// call returns an error too — a partially-written entry is
    /// never silently abandoned.
    poisoned: bool,
}

/// Mid-entry state held by [`ZipSink`].
struct EntryState {
    /// Index of this entry in the central directory's order. The
    /// pipeline uses this to reconcile against `entries_completed`
    /// in [`crate::checkpoint::SinkState::Zip`].
    index: u32,
    /// Resolved on-disk path. Carried for error context only.
    path: PathBuf,
    /// File the entry is being written to.
    file: File,
    /// Bytes successfully written so far. Equal to the on-disk file
    /// size at every safe point.
    bytes_written: u64,
    /// Expected total uncompressed size from the central directory.
    /// The sink rejects writes that would push past this bound.
    expected_size: u64,
    /// Running CRC-32 over every byte we've written (or replayed
    /// from disk on resume).
    crc: Crc32,
    /// Expected CRC-32 from the central directory. Compared at
    /// [`ZipSink::end_entry`].
    expected_crc: u32,
    /// Entry name as recorded in the central directory; carried for
    /// error messages.
    name: String,
}

impl ZipSink {
    /// Construct a sink that extracts into `root`.
    ///
    /// The directory must already exist; we never create the root
    /// itself, only entries within it. Most test paths use
    /// `fs::create_dir_all(&root)` first.
    ///
    /// # Errors
    ///
    /// Returns [`SinkError::Io`] if `root` cannot be canonicalized.
    pub fn new<P: AsRef<Path>>(root: P) -> Result<Self, SinkError> {
        let root = root.as_ref();
        let canonical = root.canonicalize().map_err(|source| SinkError::Io {
            path: root.to_path_buf(),
            source,
        })?;
        Ok(Self {
            root: canonical,
            current: None,
            poisoned: false,
        })
    }

    /// Borrow the configured extraction root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether the sink is between entries.
    ///
    /// `true` when no entry is currently in flight; this is the
    /// moment the coordinator can take a checkpoint that captures
    /// "all entries up to N are durable on disk".
    #[must_use]
    pub fn is_quiescent(&self) -> bool {
        !self.poisoned && self.current.is_none()
    }

    /// Bytes written into the in-flight entry so far. Returns `0`
    /// when no entry is in flight.
    ///
    /// Used by the coordinator to populate
    /// `current_entry_offset` in [`crate::checkpoint::SinkState::Zip`].
    #[must_use]
    pub fn current_entry_offset(&self) -> u64 {
        self.current.as_ref().map_or(0, |e| e.bytes_written)
    }

    /// Index of the entry currently being written. `None` if the
    /// sink is between entries.
    #[must_use]
    pub fn current_entry_index(&self) -> Option<u32> {
        self.current.as_ref().map(|e| e.index)
    }

    /// Resolve `entry_name` to an absolute on-disk path under
    /// [`Self::root`].
    ///
    /// Returns `(resolved_path, is_directory)`. Refuses absolute
    /// paths, `..` components, NUL bytes, empty names, and names
    /// that resolve to the root itself.
    ///
    /// Public so the pipeline can pre-flight the path resolution
    /// before issuing the first ranged GET — surfacing a
    /// path-escape error at plan time is cheaper than after we've
    /// already pulled bytes off the wire.
    ///
    /// # Errors
    ///
    /// Returns [`SinkError::PathEscape`] for any rejected name.
    pub fn resolve_entry_path(&self, entry_name: &str) -> Result<(PathBuf, bool), SinkError> {
        // Trailing-slash names are ZIP's directory-entry
        // convention. Strip the slash for resolution but track that
        // the entry is a directory so the caller can `mkdir -p` it
        // instead of opening a file.
        let (logical, is_directory) = match entry_name.strip_suffix('/') {
            Some(rest) => (rest, true),
            None => (entry_name, false),
        };
        if logical.is_empty() || logical.contains('\0') {
            return Err(SinkError::PathEscape {
                entry: entry_name.to_string(),
                root: self.root.clone(),
            });
        }
        if logical.starts_with('/') {
            return Err(SinkError::PathEscape {
                entry: entry_name.to_string(),
                root: self.root.clone(),
            });
        }
        let mut out = self.root.clone();
        let mut pushed = 0usize;
        for component in logical.split('/') {
            if component.is_empty() || component == "." {
                continue;
            }
            if component == ".." {
                return Err(SinkError::PathEscape {
                    entry: entry_name.to_string(),
                    root: self.root.clone(),
                });
            }
            // Defensive: reject any component that produces
            // anything other than a single Normal component when
            // parsed as a Path. Catches Windows-style backslash
            // separators a future cross-platform expansion might
            // miss.
            if Path::new(component)
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
            {
                return Err(SinkError::PathEscape {
                    entry: entry_name.to_string(),
                    root: self.root.clone(),
                });
            }
            out.push(component);
            pushed += 1;
        }
        if pushed == 0 {
            return Err(SinkError::PathEscape {
                entry: entry_name.to_string(),
                root: self.root.clone(),
            });
        }
        Ok((out, is_directory))
    }

    /// Begin a fresh extraction of an entry.
    ///
    /// Truncates any previously-written content for this entry
    /// (i.e. resume for non-STORED entries restarts from offset 0).
    /// Path safety is enforced via [`Self::resolve_entry_path`].
    /// Directory entries (`name` ends in `/`, `expected_size == 0`)
    /// `mkdir -p` the directory and immediately quiesce — the
    /// caller does not call `write_entry`/`end_entry` for them.
    ///
    /// # Errors
    ///
    /// - [`SinkError::Io`] for filesystem failures.
    /// - [`SinkError::PathEscape`] if the entry name is unsafe.
    /// - [`SinkError::Io`] (sticky-poisoned) if the sink already
    ///   failed.
    pub fn begin_entry(
        &mut self,
        index: u32,
        entry_name: &str,
        expected_size: u64,
        expected_crc: u32,
    ) -> Result<BeginEntryOutcome, SinkError> {
        self.poison_check()?;
        if self.current.is_some() {
            return self.poison_with(SinkError::Io {
                path: self.root.clone(),
                source: std::io::Error::other(
                    "ZipSink::begin_entry called while another entry is in flight",
                ),
            });
        }
        let (path, is_directory) = self.resolve_entry_path(entry_name)?;

        if is_directory {
            fs::create_dir_all(&path).map_err(|source| SinkError::Io {
                path: path.clone(),
                source,
            })?;
            // Directory entries are immediately quiescent — no
            // bytes will follow.
            return Ok(BeginEntryOutcome::Directory { path });
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| SinkError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .map_err(|source| SinkError::Io {
                path: path.clone(),
                source,
            })?;
        self.current = Some(EntryState {
            index,
            path: path.clone(),
            file,
            bytes_written: 0,
            expected_size,
            crc: Crc32::new(),
            expected_crc,
            name: entry_name.to_string(),
        });
        Ok(BeginEntryOutcome::File { path })
    }

    /// Begin a resumed extraction of a STORED entry at `resume_at`
    /// bytes into the entry.
    ///
    /// Truncates the existing on-disk file to `resume_at`, re-reads
    /// those bytes to seed the running CRC, and leaves the sink
    /// ready to accept writes that pick up at `resume_at`. The
    /// underlying file-IO is codec-agnostic — Phase 9b of
    /// `docs/PLAN_deflate_block_decoder.md` swapped DEFLATE / zstd
    /// onto this same path via [`Self::begin_entry_resume`]. The
    /// `_stored` suffix is preserved for compatibility with
    /// pre-Phase-9b callers.
    ///
    /// # Errors
    ///
    /// - [`SinkError::Io`] when the on-disk file cannot be opened
    ///   for read+write, truncated, or re-read.
    /// - [`SinkError::PathEscape`] if the entry name is unsafe.
    pub fn begin_entry_resume(
        &mut self,
        index: u32,
        entry_name: &str,
        expected_size: u64,
        expected_crc: u32,
        resume_at: u64,
    ) -> Result<BeginEntryOutcome, SinkError> {
        // Phase 9b generalised the resume path: STORED, DEFLATE,
        // and zstd entries all use the same file-IO sequence
        // (truncate → replay-CRC → seek). The body is identical
        // to the historical `begin_entry_resume_stored`; the
        // codec-specific bits live in the pipeline's
        // [`crate::zip::decode::decompress_entry_with_resume`].
        self.begin_entry_resume_stored(index, entry_name, expected_size, expected_crc, resume_at)
    }

    /// Pre-Phase-9b spelling of [`Self::begin_entry_resume`] —
    /// retained for tests and for the existing call sites in the
    /// pipeline that pre-date the rename.
    pub fn begin_entry_resume_stored(
        &mut self,
        index: u32,
        entry_name: &str,
        expected_size: u64,
        expected_crc: u32,
        resume_at: u64,
    ) -> Result<BeginEntryOutcome, SinkError> {
        self.poison_check()?;
        if self.current.is_some() {
            return self.poison_with(SinkError::Io {
                path: self.root.clone(),
                source: std::io::Error::other(
                    "ZipSink::begin_entry_resume_stored called while another entry is in flight",
                ),
            });
        }
        let (path, is_directory) = self.resolve_entry_path(entry_name)?;
        if is_directory || resume_at == 0 {
            // Trivial cases — fall through to the fresh path so
            // the directory `mkdir` and the truncate-from-zero
            // logic stay in one place.
            return self.begin_entry(index, entry_name, expected_size, expected_crc);
        }
        if resume_at > expected_size {
            return self.poison_with(SinkError::Io {
                path: path.clone(),
                source: std::io::Error::other(format!(
                    "resume_at ({resume_at}) > expected_size ({expected_size}) for entry {entry_name:?}",
                )),
            });
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| SinkError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
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
        // Truncate to the checkpoint offset, in case the previous
        // run wrote more bytes than the checkpoint captured (e.g.
        // a kill -9 between write and checkpoint flush).
        file.set_len(resume_at).map_err(|source| SinkError::Io {
            path: path.clone(),
            source,
        })?;
        // Replay the prefix to seed the CRC. The IO is sequential,
        // and this is bounded by the entry size which is bounded
        // by the user's archive — no risk of unbounded buffering.
        file.seek(SeekFrom::Start(0))
            .map_err(|source| SinkError::Io {
                path: path.clone(),
                source,
            })?;
        let mut crc = Crc32::new();
        let mut buf = [0u8; 64 * 1024];
        let mut remaining = resume_at;
        while remaining > 0 {
            let want = usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(buf.len());
            let n = file
                .read(&mut buf[..want])
                .map_err(|source| SinkError::Io {
                    path: path.clone(),
                    source,
                })?;
            if n == 0 {
                return self.poison_with(SinkError::Io {
                    path: path.clone(),
                    source: std::io::Error::other(format!(
                        "STORED resume read short: wanted {remaining} more bytes from {entry_name:?}"
                    )),
                });
            }
            crc.update(&buf[..n]);
            remaining -= n as u64;
        }
        // Reposition for append-style writes.
        file.seek(SeekFrom::Start(resume_at))
            .map_err(|source| SinkError::Io {
                path: path.clone(),
                source,
            })?;

        self.current = Some(EntryState {
            index,
            path: path.clone(),
            file,
            bytes_written: resume_at,
            expected_size,
            crc,
            expected_crc,
            name: entry_name.to_string(),
        });
        Ok(BeginEntryOutcome::File { path })
    }

    /// Append `buf` to the in-flight entry.
    ///
    /// Updates the running CRC and bumps `bytes_written`. Refuses
    /// writes that would push past the entry's
    /// `expected_size`.
    ///
    /// # Errors
    ///
    /// - [`SinkError::Io`] for filesystem failures.
    /// - [`SinkError::Io`] (sticky-poisoned) if no entry is in
    ///   flight or if the sink already failed.
    pub fn write_entry(&mut self, buf: &[u8]) -> Result<(), SinkError> {
        self.poison_check()?;
        let entry = match self.current.as_mut() {
            Some(e) => e,
            None => {
                return self.poison_with(SinkError::Io {
                    path: self.root.clone(),
                    source: std::io::Error::other(
                        "ZipSink::write_entry called with no entry in flight",
                    ),
                });
            }
        };
        let want = u64::try_from(buf.len()).unwrap_or(u64::MAX);
        let new_total = entry.bytes_written.saturating_add(want);
        if new_total > entry.expected_size {
            let path = entry.path.clone();
            let name = entry.name.clone();
            let expected = entry.expected_size;
            return self.poison_with(SinkError::Io {
                path,
                source: std::io::Error::other(format!(
                    "entry {name:?} produced more than the {expected} bytes the central \
                     directory declared (would write {new_total})",
                )),
            });
        }
        entry.file.write_all(buf).map_err(|source| {
            let path = entry.path.clone();
            self.poisoned = true;
            SinkError::Io { path, source }
        })?;
        entry.crc.update(buf);
        entry.bytes_written = new_total;
        Ok(())
    }

    /// Finalize the in-flight entry: validate the running CRC
    /// against the declared one, flush, and quiesce.
    ///
    /// # Errors
    ///
    /// - [`SinkError::Io`] for flush failures.
    /// - [`SinkError::Io`] wrapping [`ZipError::Crc32Mismatch`] if
    ///   the running CRC disagrees with the central directory.
    /// - [`SinkError::Io`] (sticky-poisoned) if no entry is in
    ///   flight or if the entry's `bytes_written` does not equal
    ///   `expected_size`.
    pub fn end_entry(&mut self) -> Result<EntryFinalize, SinkError> {
        self.poison_check()?;
        let mut entry = match self.current.take() {
            Some(e) => e,
            None => {
                return self.poison_with(SinkError::Io {
                    path: self.root.clone(),
                    source: std::io::Error::other(
                        "ZipSink::end_entry called with no entry in flight",
                    ),
                });
            }
        };
        if entry.bytes_written != entry.expected_size {
            let bw = entry.bytes_written;
            let exp = entry.expected_size;
            let name = entry.name.clone();
            // Restore the entry into `self.current` before poisoning
            // so a caller debugging via state inspection sees the
            // partial state.
            self.current = Some(entry);
            return self.poison_with(SinkError::Io {
                path: self.root.clone(),
                source: std::io::Error::other(format!(
                    "entry {name:?} closed with {bw} bytes written but central directory \
                     declared {exp}",
                )),
            });
        }
        entry.file.flush().map_err(|source| {
            let path = entry.path.clone();
            self.poisoned = true;
            SinkError::Io { path, source }
        })?;
        let computed = entry.crc.finalize();
        if computed != entry.expected_crc {
            let name = entry.name.clone();
            self.poisoned = true;
            return Err(SinkError::Io {
                path: entry.path.clone(),
                source: std::io::Error::other(
                    ZipError::Crc32Mismatch {
                        entry_name: name,
                        expected: entry.expected_crc,
                        computed,
                    }
                    .to_string(),
                ),
            });
        }
        Ok(EntryFinalize {
            index: entry.index,
            bytes_written: entry.bytes_written,
            crc: computed,
            path: entry.path,
        })
    }

    /// Finalize the sink. Must be called after the last
    /// [`Self::end_entry`].
    ///
    /// # Errors
    ///
    /// Returns [`SinkError::Io`] when the sink is poisoned or an
    /// entry is still in flight.
    pub fn close(self) -> Result<(), SinkError> {
        if self.poisoned {
            return Err(SinkError::Io {
                path: self.root,
                source: std::io::Error::other("ZipSink already failed"),
            });
        }
        if self.current.is_some() {
            return Err(SinkError::Io {
                path: self.root,
                source: std::io::Error::other("ZipSink::close with an entry still in flight"),
            });
        }
        Ok(())
    }

    fn poison_check(&self) -> Result<(), SinkError> {
        if self.poisoned {
            return Err(SinkError::Io {
                path: self.root.clone(),
                source: std::io::Error::other("ZipSink already failed"),
            });
        }
        Ok(())
    }

    fn poison_with<T>(&mut self, err: SinkError) -> Result<T, SinkError> {
        self.poisoned = true;
        Err(err)
    }
}

/// What happened in [`ZipSink::begin_entry`].
///
/// Directory entries don't accept writes; the pipeline checks the
/// outcome and either skips straight to the next entry or starts
/// feeding bytes.
#[derive(Debug, Clone)]
pub enum BeginEntryOutcome {
    /// Entry is a regular file. Writes will land at `path`.
    File {
        /// Resolved on-disk path for the entry.
        path: PathBuf,
    },
    /// Entry is a directory. The directory has been created and the
    /// sink remains quiescent.
    Directory {
        /// Resolved on-disk path for the directory.
        path: PathBuf,
    },
}

/// Information returned from [`ZipSink::end_entry`].
#[derive(Debug, Clone)]
pub struct EntryFinalize {
    /// Index of the entry that was just finalized.
    pub index: u32,
    /// Bytes written for this entry (equal to the entry's
    /// uncompressed size).
    pub bytes_written: u64,
    /// CRC-32 the sink computed and validated against the central
    /// directory.
    pub crc: u32,
    /// Final on-disk path for the entry.
    pub path: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::SystemTime;

    use crate::zip::ieee;

    static UNIQ: AtomicU64 = AtomicU64::new(0);

    fn unique_dir(label: &str) -> PathBuf {
        let pid = std::process::id();
        let n = UNIQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path =
            std::env::temp_dir().join(format!("peel_zipsink_unit_{label}_{pid}_{nanos}_{n}"));
        fs::create_dir_all(&path).expect("mkdir tmp root");
        path
    }

    struct CleanupOnDrop(PathBuf);
    impl Drop for CleanupOnDrop {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn round_trip_single_entry_writes_file_and_validates_crc() {
        let root = unique_dir("single");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = ZipSink::new(&root).expect("new");

        let payload = b"hello, zip world";
        let crc = ieee(payload);
        let outcome = sink
            .begin_entry(0, "greetings.txt", payload.len() as u64, crc)
            .expect("begin");
        assert!(matches!(outcome, BeginEntryOutcome::File { .. }));
        sink.write_entry(payload).expect("write");
        let fin = sink.end_entry().expect("end");
        assert_eq!(fin.bytes_written, payload.len() as u64);
        assert_eq!(fin.crc, crc);
        assert!(sink.is_quiescent());
        sink.close().expect("close");

        let written = fs::read(root.join("greetings.txt")).expect("read");
        assert_eq!(written, payload);
    }

    #[test]
    fn directory_entry_makes_directory_and_stays_quiescent() {
        let root = unique_dir("dir");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = ZipSink::new(&root).expect("new");
        let outcome = sink.begin_entry(0, "nested/dir/", 0, 0).expect("begin");
        assert!(matches!(outcome, BeginEntryOutcome::Directory { .. }));
        assert!(sink.is_quiescent());
        sink.close().expect("close");
        assert!(root.join("nested").join("dir").is_dir());
    }

    #[test]
    fn write_past_expected_size_is_rejected() {
        let root = unique_dir("oversize");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = ZipSink::new(&root).expect("new");
        sink.begin_entry(0, "f.txt", 4, ieee(b"abcd"))
            .expect("begin");
        sink.write_entry(b"abcd").expect("write to bound");
        let err = sink.write_entry(b"!").expect_err("must reject");
        match err {
            SinkError::Io { source, .. } => {
                assert!(source.to_string().contains("more than"));
            }
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn end_entry_rejects_short_write() {
        let root = unique_dir("short");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = ZipSink::new(&root).expect("new");
        sink.begin_entry(0, "f.txt", 8, 0).expect("begin");
        sink.write_entry(b"abc").expect("write 3");
        let err = sink.end_entry().expect_err("short close must fail");
        match err {
            SinkError::Io { source, .. } => {
                assert!(source.to_string().contains("3 bytes"));
            }
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn crc_mismatch_is_reported_with_entry_name() {
        let root = unique_dir("crc");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = ZipSink::new(&root).expect("new");
        let payload = b"abc";
        sink.begin_entry(0, "wrong-crc.txt", payload.len() as u64, 0xDEAD_BEEF)
            .expect("begin");
        sink.write_entry(payload).expect("write");
        let err = sink.end_entry().expect_err("crc mismatch must fail");
        match err {
            SinkError::Io { source, .. } => {
                let msg = source.to_string();
                assert!(msg.contains("wrong-crc.txt"), "msg = {msg}");
                assert!(msg.contains("DEADBEEF") || msg.contains("0xdeadbeef"));
            }
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn path_escape_is_rejected() {
        let root = unique_dir("escape");
        let _g = CleanupOnDrop(root.clone());
        let sink = ZipSink::new(&root).expect("new");
        let cases = [
            "../etc/passwd",
            "/absolute/path",
            "",
            "./..",
            "with\0nul",
            "ok/../escape",
        ];
        for case in cases {
            let err = sink.resolve_entry_path(case).expect_err(case);
            match err {
                SinkError::PathEscape { entry, .. } => assert_eq!(entry, case),
                other => panic!("expected PathEscape for {case:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn resume_stored_truncates_and_reseeds_crc() {
        let root = unique_dir("resume");
        let _g = CleanupOnDrop(root.clone());

        // Pretend a previous run had written 5 bytes of "hello world"
        // before crashing. The on-disk file overshoots (8 bytes),
        // simulating a kill -9 between the last write and the
        // checkpoint flush; resume must truncate back to 5.
        fs::write(root.join("hello.txt"), b"hello___").expect("seed");

        let payload = b"hello world";
        let crc = ieee(payload);
        let mut sink = ZipSink::new(&root).expect("new");
        sink.begin_entry_resume_stored(0, "hello.txt", payload.len() as u64, crc, 5)
            .expect("resume");
        sink.write_entry(b" world").expect("rest");
        let fin = sink.end_entry().expect("end");
        assert_eq!(fin.bytes_written, payload.len() as u64);
        assert_eq!(fin.crc, crc);
        sink.close().expect("close");

        let written = fs::read(root.join("hello.txt")).expect("read");
        assert_eq!(written, payload);
    }

    #[test]
    fn resume_stored_with_zero_offset_falls_through_to_fresh_path() {
        let root = unique_dir("resume0");
        let _g = CleanupOnDrop(root.clone());
        fs::write(root.join("a.bin"), b"junk").expect("seed");
        let payload = b"abcdef";
        let crc = ieee(payload);
        let mut sink = ZipSink::new(&root).expect("new");
        sink.begin_entry_resume_stored(0, "a.bin", payload.len() as u64, crc, 0)
            .expect("resume0");
        sink.write_entry(payload).expect("write");
        sink.end_entry().expect("end");
        sink.close().expect("close");
        assert_eq!(fs::read(root.join("a.bin")).unwrap(), payload);
    }

    #[test]
    fn resume_stored_rejects_resume_past_expected_size() {
        let root = unique_dir("resume-too-far");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = ZipSink::new(&root).expect("new");
        let err = sink
            .begin_entry_resume_stored(0, "f.txt", 5, 0, 6)
            .expect_err("resume past size");
        match err {
            SinkError::Io { source, .. } => {
                assert!(source.to_string().contains("resume_at"));
            }
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn nested_path_creates_parent_directories() {
        let root = unique_dir("nested");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = ZipSink::new(&root).expect("new");
        sink.begin_entry(0, "deep/nested/path/file.txt", 3, ieee(b"abc"))
            .expect("begin");
        sink.write_entry(b"abc").expect("write");
        sink.end_entry().expect("end");
        sink.close().expect("close");
        assert_eq!(
            fs::read(root.join("deep/nested/path/file.txt")).unwrap(),
            b"abc"
        );
    }

    #[test]
    fn close_with_in_flight_entry_errors() {
        let root = unique_dir("close-inflight");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = ZipSink::new(&root).expect("new");
        sink.begin_entry(0, "f.txt", 5, 0).expect("begin");
        let err = sink.close().expect_err("inflight close");
        match err {
            SinkError::Io { source, .. } => {
                assert!(source.to_string().contains("in flight"));
            }
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn current_entry_offset_tracks_writes() {
        let root = unique_dir("offset");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = ZipSink::new(&root).expect("new");
        sink.begin_entry(7, "f.bin", 16, ieee(&[0u8; 16]))
            .expect("begin");
        assert_eq!(sink.current_entry_index(), Some(7));
        assert_eq!(sink.current_entry_offset(), 0);
        sink.write_entry(&[0u8; 4]).expect("w1");
        assert_eq!(sink.current_entry_offset(), 4);
        sink.write_entry(&[0u8; 4]).expect("w2");
        assert_eq!(sink.current_entry_offset(), 8);
        sink.write_entry(&[0u8; 8]).expect("w3");
        sink.end_entry().expect("end");
        assert!(sink.is_quiescent());
        assert_eq!(sink.current_entry_index(), None);
        assert_eq!(sink.current_entry_offset(), 0);
    }
}
