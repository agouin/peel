//! Per-entry on-disk sink for the RAR5 pipeline.
//!
//! Streams decoded entry bytes to a directory tree, one entry at a
//! time. Mirrors [`crate::sink::zip::ZipSink`]'s contract — the §3
//! pipeline drives the sink explicitly via
//! [`Self::begin_entry`] / [`Self::write_entry`] / [`Self::end_entry`]
//! rather than feeding a single byte stream — but with two RAR5
//! specifics:
//!
//! - Per-entry integrity hash is BLAKE2sp (RAR5's standard) plus an
//!   optional CRC-32 (the file header's `data_crc32` field carried
//!   when the `CRC32_PRESENT` flag is set). Either or both are
//!   verified at [`Self::end_entry`].
//! - Round-one §3 extracts STORED (method = 0) entries only; the
//!   sink itself is method-agnostic (it just consumes decompressed
//!   bytes), so the §4 hand-rolled decoder will land the
//!   compressed-method path on top of the same surface.
//!
//! # Path safety
//!
//! Entry names are resolved purely lexically against the configured
//! root, with the same rules `ZipSink` enforces:
//!
//! - absolute paths, empty names, and `..` components are rejected;
//! - NUL bytes in names are rejected;
//! - names that resolve to the root itself are rejected;
//! - directory entries (`file_flags::DIRECTORY` set in the file
//!   header) take an empty data area and `mkdir -p` the directory
//!   instead of opening a file.
//!
//! # Resume
//!
//! Per `internal/PLAN_rar.md` §3 step 4, the checkpoint records
//! `current_entry_offset` for the in-flight entry. The pipeline
//! drives resume by calling [`Self::begin_entry_resume`] which
//! truncates the existing on-disk file to `resume_at`, re-reads the
//! prefix to seed the running BLAKE2sp + CRC-32, and continues
//! accepting bytes from `resume_at`. STORED entries can resume at
//! any byte offset — the codec is a passthrough so the sink's
//! `bytes_written` is the only state that matters.
//!
//! On a clean run the on-disk file ends up byte-identical to a
//! fresh extraction.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use crate::hash::blake2sp::{Blake2sp, DIGEST_LEN as BLAKE2SP_DIGEST_LEN};
use crate::rar::RarError;
use crate::sink::SinkError;
use crate::zip::Crc32;

/// Streaming destination for a RAR5 extraction.
///
/// Construct with [`RarSink::new`]; drive entries via
/// [`Self::begin_entry`] / [`Self::begin_entry_resume`],
/// [`Self::write_entry`], and [`Self::end_entry`]. The pipeline is
/// responsible for stitching multiple entries into a single
/// extraction; the sink owns the per-entry path resolution, the
/// per-entry file handle, and the running hashes.
pub struct RarSink {
    /// Canonicalized extraction root.
    root: PathBuf,
    /// In-flight entry, if any. `None` between entries (the moment
    /// a checkpoint can capture). See [`Self::is_quiescent`].
    current: Option<EntryState>,
    /// Sticky failure flag. Once a write errors, every subsequent
    /// call returns an error too — a partially-written entry is
    /// never silently abandoned.
    poisoned: bool,
}

/// Mid-entry state held by [`RarSink`].
struct EntryState {
    /// Index of this entry in archive order. The pipeline uses
    /// this to reconcile against `entries_completed` in
    /// [`crate::checkpoint::SinkState::Rar`].
    index: u32,
    /// Resolved on-disk path. Carried for error context.
    path: PathBuf,
    /// File the entry is being written to.
    file: File,
    /// Bytes successfully written so far. Equal to the on-disk
    /// file size at every safe point.
    bytes_written: u64,
    /// Expected total uncompressed size from the file header. The
    /// sink rejects writes that would push past this bound.
    expected_size: u64,
    /// Running BLAKE2sp over every byte we've written (or replayed
    /// from disk on resume).
    blake2sp: Blake2sp,
    /// Running CRC-32 over the same bytes. Updated only when the
    /// file header carried a recorded CRC-32 (otherwise the field
    /// is not consulted at end-of-entry; we still maintain it so
    /// resume's prefix replay does not need a special-case skip).
    crc32: Crc32,
    /// Optional CRC-32 the file header recorded for the entry.
    /// `None` when the header's `CRC32_PRESENT` bit is clear.
    expected_crc32: Option<u32>,
    /// Optional BLAKE2sp the file header recorded for the entry.
    /// `None` for round-one §3 — the BLAKE2sp digest lives in the
    /// file-header *extra area* (record type 0x02) which the §1
    /// parser does not yet decode. §3's tests cover the path that
    /// the sink computes a digest and compares against the
    /// caller-supplied expected value when one exists; production
    /// use of expected_blake2sp lands when the §1 parser is
    /// extended to decode the extra-record subtypes (filed as
    /// follow-on `O.RAR.HASH_EXTRA`).
    expected_blake2sp: Option<[u8; BLAKE2SP_DIGEST_LEN]>,
    /// Entry name as recorded in the file header; carried for
    /// error messages.
    name: String,
}

impl RarSink {
    /// Construct a sink that extracts into `root`.
    ///
    /// The directory must already exist; we never create the root
    /// itself, only entries within it. Callers typically
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
    /// Used by the coordinator to populate `current_entry_offset`
    /// in [`crate::checkpoint::SinkState::Rar`].
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
    /// that resolve to the root itself. `is_directory` is forced
    /// `true` when the file header's `DIRECTORY` flag is set, so
    /// the pipeline can `mkdir -p` instead of opening a file.
    ///
    /// Public so the pipeline can pre-flight the path resolution
    /// before issuing the first ranged GET — surfacing a
    /// path-escape error at plan time is cheaper than after we've
    /// already pulled bytes off the wire.
    ///
    /// # Errors
    ///
    /// Returns [`SinkError::PathEscape`] for any rejected name.
    pub fn resolve_entry_path(
        &self,
        entry_name: &str,
        is_directory_flag: bool,
    ) -> Result<(PathBuf, bool), SinkError> {
        if entry_name.is_empty() || entry_name.contains('\0') {
            return Err(SinkError::PathEscape {
                entry: entry_name.to_string(),
                root: self.root.clone(),
            });
        }
        if entry_name.starts_with('/') {
            return Err(SinkError::PathEscape {
                entry: entry_name.to_string(),
                root: self.root.clone(),
            });
        }
        let mut out = self.root.clone();
        let mut pushed = 0usize;
        // RAR5 file names use forward slashes. Strip a trailing
        // slash if present (the §1 parser leaves it intact); we
        // record `is_directory` separately from the slash since
        // RAR5 also encodes directories via the file_flags
        // DIRECTORY bit.
        let logical = entry_name.strip_suffix('/').unwrap_or(entry_name);
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
            // Defensive: reject components that produce anything
            // other than a single Normal Path component (catches
            // Windows-style backslash separators a future
            // cross-platform expansion might otherwise miss).
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
        Ok((out, is_directory_flag))
    }

    /// Begin a fresh extraction of an entry.
    ///
    /// Truncates any previously-written content for this entry.
    /// Path safety is enforced via [`Self::resolve_entry_path`].
    /// Directory entries (`is_directory == true`,
    /// `expected_size == 0`) `mkdir -p` the directory and
    /// immediately quiesce — the caller does not call
    /// `write_entry`/`end_entry` for them.
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
        is_directory: bool,
        expected_size: u64,
        expected_crc32: Option<u32>,
        expected_blake2sp: Option<[u8; BLAKE2SP_DIGEST_LEN]>,
    ) -> Result<BeginEntryOutcome, SinkError> {
        self.poison_check()?;
        if self.current.is_some() {
            return self.poison_with(SinkError::Io {
                path: self.root.clone(),
                source: std::io::Error::other(
                    "RarSink::begin_entry called while another entry is in flight",
                ),
            });
        }
        let (path, treat_as_dir) = self.resolve_entry_path(entry_name, is_directory)?;
        if treat_as_dir {
            fs::create_dir_all(&path).map_err(|source| SinkError::Io {
                path: path.clone(),
                source,
            })?;
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
            blake2sp: Blake2sp::new(),
            crc32: Crc32::new(),
            expected_crc32,
            expected_blake2sp,
            name: entry_name.to_string(),
        });
        Ok(BeginEntryOutcome::File { path })
    }

    /// Begin a resumed extraction of an entry at `resume_at` bytes
    /// into the entry.
    ///
    /// Truncates the existing on-disk file to `resume_at`, re-reads
    /// those bytes to seed the running BLAKE2sp and CRC-32, and
    /// leaves the sink ready to accept writes that pick up at
    /// `resume_at`. Round-one §3 supports STORED entries only,
    /// where the sink's bookkeeping is the entire decoder state;
    /// §4 will add a parallel `begin_entry_resume_compressed`
    /// path that takes a serialized decoder snapshot for the
    /// hand-rolled RAR5 algorithm.
    ///
    /// # Errors
    ///
    /// - [`SinkError::Io`] when the on-disk file cannot be opened
    ///   for read+write, truncated, or re-read.
    /// - [`SinkError::PathEscape`] if the entry name is unsafe.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_entry_resume(
        &mut self,
        index: u32,
        entry_name: &str,
        is_directory: bool,
        expected_size: u64,
        expected_crc32: Option<u32>,
        expected_blake2sp: Option<[u8; BLAKE2SP_DIGEST_LEN]>,
        resume_at: u64,
    ) -> Result<BeginEntryOutcome, SinkError> {
        self.poison_check()?;
        if self.current.is_some() {
            return self.poison_with(SinkError::Io {
                path: self.root.clone(),
                source: std::io::Error::other(
                    "RarSink::begin_entry_resume called while another entry is in flight",
                ),
            });
        }
        let (path, treat_as_dir) = self.resolve_entry_path(entry_name, is_directory)?;
        if treat_as_dir || resume_at == 0 {
            return self.begin_entry(
                index,
                entry_name,
                is_directory,
                expected_size,
                expected_crc32,
                expected_blake2sp,
            );
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
        // Replay the prefix to seed the BLAKE2sp + CRC-32.
        file.seek(SeekFrom::Start(0))
            .map_err(|source| SinkError::Io {
                path: path.clone(),
                source,
            })?;
        let mut blake2sp = Blake2sp::new();
        let mut crc32 = Crc32::new();
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
                        "RAR resume read short: wanted {remaining} more bytes from {entry_name:?}"
                    )),
                });
            }
            blake2sp.update(&buf[..n]);
            crc32.update(&buf[..n]);
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
            blake2sp,
            crc32,
            expected_crc32,
            expected_blake2sp,
            name: entry_name.to_string(),
        });
        Ok(BeginEntryOutcome::File { path })
    }

    /// Append `buf` to the in-flight entry.
    ///
    /// Updates the running BLAKE2sp + CRC-32 and bumps
    /// `bytes_written`. Refuses writes that would push past the
    /// entry's `expected_size`.
    ///
    /// # Errors
    ///
    /// - [`SinkError::Io`] for filesystem failures.
    /// - [`SinkError::Io`] (sticky-poisoned) if no entry is in
    ///   flight, the sink already failed, or the write would
    ///   exceed `expected_size`.
    pub fn write_entry(&mut self, buf: &[u8]) -> Result<(), SinkError> {
        self.poison_check()?;
        let entry = match self.current.as_mut() {
            Some(e) => e,
            None => {
                return self.poison_with(SinkError::Io {
                    path: self.root.clone(),
                    source: std::io::Error::other(
                        "RarSink::write_entry called with no entry in flight",
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
                    "entry {name:?} produced more than the {expected} bytes the file \
                     header declared (would write {new_total})",
                )),
            });
        }
        entry.file.write_all(buf).map_err(|source| {
            let path = entry.path.clone();
            self.poisoned = true;
            SinkError::Io { path, source }
        })?;
        entry.blake2sp.update(buf);
        entry.crc32.update(buf);
        entry.bytes_written = new_total;
        Ok(())
    }

    /// Finalize the in-flight entry: validate the running CRC-32
    /// and (when supplied) BLAKE2sp against the declared values,
    /// flush, and quiesce.
    ///
    /// # Errors
    ///
    /// - [`SinkError::Io`] for flush failures.
    /// - [`SinkError::Io`] wrapping [`RarError::HashMismatch`] if
    ///   either the running CRC-32 or BLAKE2sp disagrees with the
    ///   value the file header recorded.
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
                        "RarSink::end_entry called with no entry in flight",
                    ),
                });
            }
        };
        if entry.bytes_written != entry.expected_size {
            let bw = entry.bytes_written;
            let exp = entry.expected_size;
            let name = entry.name.clone();
            self.current = Some(entry);
            return self.poison_with(SinkError::Io {
                path: self.root.clone(),
                source: std::io::Error::other(format!(
                    "entry {name:?} closed with {bw} bytes written but file header \
                     declared {exp}",
                )),
            });
        }
        entry.file.flush().map_err(|source| {
            let path = entry.path.clone();
            self.poisoned = true;
            SinkError::Io { path, source }
        })?;
        let crc_finalized = entry.crc32.finalize();
        let blake2sp_finalized = entry.blake2sp.finalize();
        if let Some(expected) = entry.expected_crc32 {
            if crc_finalized != expected {
                let name = entry.name.clone();
                self.poisoned = true;
                return Err(SinkError::Io {
                    path: entry.path.clone(),
                    source: std::io::Error::other(
                        RarError::HashMismatch {
                            entry_name: name,
                            hash: "CRC32",
                            expected: format!("{expected:#010x}"),
                            computed: format!("{crc_finalized:#010x}"),
                        }
                        .to_string(),
                    ),
                });
            }
        }
        if let Some(expected) = entry.expected_blake2sp {
            if blake2sp_finalized != expected {
                let name = entry.name.clone();
                self.poisoned = true;
                return Err(SinkError::Io {
                    path: entry.path.clone(),
                    source: std::io::Error::other(
                        RarError::HashMismatch {
                            entry_name: name,
                            hash: "BLAKE2sp",
                            expected: hex_encode(&expected),
                            computed: hex_encode(&blake2sp_finalized),
                        }
                        .to_string(),
                    ),
                });
            }
        }
        Ok(EntryFinalize {
            index: entry.index,
            bytes_written: entry.bytes_written,
            crc32: crc_finalized,
            blake2sp: blake2sp_finalized,
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
                source: std::io::Error::other("RarSink already failed"),
            });
        }
        if self.current.is_some() {
            return Err(SinkError::Io {
                path: self.root,
                source: std::io::Error::other("RarSink::close with an entry still in flight"),
            });
        }
        Ok(())
    }

    fn poison_check(&self) -> Result<(), SinkError> {
        if self.poisoned {
            return Err(SinkError::Io {
                path: self.root.clone(),
                source: std::io::Error::other("RarSink already failed"),
            });
        }
        Ok(())
    }

    fn poison_with<T>(&mut self, err: SinkError) -> Result<T, SinkError> {
        self.poisoned = true;
        Err(err)
    }
}

/// What happened in [`RarSink::begin_entry`].
#[derive(Debug, Clone)]
pub enum BeginEntryOutcome {
    /// Entry is a regular file. Writes will land at `path`.
    File {
        /// Resolved on-disk path for the entry.
        path: PathBuf,
    },
    /// Entry is a directory. The directory has been created and
    /// the sink remains quiescent.
    Directory {
        /// Resolved on-disk path for the directory.
        path: PathBuf,
    },
}

/// Information returned from [`RarSink::end_entry`].
#[derive(Debug, Clone)]
pub struct EntryFinalize {
    /// Index of the entry that was just finalized.
    pub index: u32,
    /// Bytes written for this entry (equal to the entry's
    /// uncompressed size).
    pub bytes_written: u64,
    /// CRC-32 the sink computed (and validated against the file
    /// header when one was supplied).
    pub crc32: u32,
    /// BLAKE2sp the sink computed (and validated against the
    /// expected digest when one was supplied).
    pub blake2sp: [u8; BLAKE2SP_DIGEST_LEN],
    /// Final on-disk path for the entry.
    pub path: PathBuf,
}

/// Lowercase-hex helper for diagnostic messages.
fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::SystemTime;

    use crate::hash::blake2sp;

    static UNIQ: AtomicU64 = AtomicU64::new(0);

    fn unique_dir(label: &str) -> PathBuf {
        let pid = std::process::id();
        let n = UNIQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path =
            std::env::temp_dir().join(format!("peel_rarsink_unit_{label}_{pid}_{nanos}_{n}"));
        fs::create_dir_all(&path).expect("mkdir tmp root");
        path
    }

    struct CleanupOnDrop(PathBuf);
    impl Drop for CleanupOnDrop {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut c = Crc32::new();
        c.update(data);
        c.finalize()
    }

    #[test]
    fn round_trip_single_entry_writes_file_and_validates_hashes() {
        let root = unique_dir("single");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = RarSink::new(&root).expect("new");

        let payload = b"hello, rar world";
        let expected_crc32 = crc32(payload);
        let expected_blake2sp = blake2sp::hash(payload);
        let outcome = sink
            .begin_entry(
                0,
                "greetings.txt",
                false,
                payload.len() as u64,
                Some(expected_crc32),
                Some(expected_blake2sp),
            )
            .expect("begin");
        assert!(matches!(outcome, BeginEntryOutcome::File { .. }));
        sink.write_entry(payload).expect("write");
        let fin = sink.end_entry().expect("end");
        assert_eq!(fin.bytes_written, payload.len() as u64);
        assert_eq!(fin.crc32, expected_crc32);
        assert_eq!(fin.blake2sp, expected_blake2sp);
        assert!(sink.is_quiescent());
        sink.close().expect("close");

        let on_disk = fs::read(root.join("greetings.txt")).expect("read back");
        assert_eq!(on_disk, payload);
    }

    #[test]
    fn directory_entry_creates_dir_and_quiesces() {
        let root = unique_dir("dir");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = RarSink::new(&root).expect("new");
        let outcome = sink
            .begin_entry(0, "subdir", true, 0, None, None)
            .expect("begin");
        match outcome {
            BeginEntryOutcome::Directory { path } => assert!(path.is_dir()),
            other => panic!("expected Directory, got {other:?}"),
        }
        // No write_entry / end_entry call for a directory — the
        // sink stays quiescent.
        assert!(sink.is_quiescent());
        sink.close().expect("close");
    }

    #[test]
    fn nested_path_creates_parent_dirs() {
        let root = unique_dir("nested");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = RarSink::new(&root).expect("new");
        let payload = b"nested";
        sink.begin_entry(0, "a/b/c/note.txt", false, payload.len() as u64, None, None)
            .expect("begin");
        sink.write_entry(payload).expect("write");
        sink.end_entry().expect("end");
        sink.close().expect("close");
        let on_disk =
            fs::read(root.join("a").join("b").join("c").join("note.txt")).expect("read back");
        assert_eq!(on_disk, payload);
    }

    #[test]
    fn rejects_path_traversal() {
        let root = unique_dir("escape");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = RarSink::new(&root).expect("new");
        let err = sink
            .begin_entry(0, "../escape.txt", false, 0, None, None)
            .unwrap_err();
        assert!(matches!(err, SinkError::PathEscape { .. }));
    }

    #[test]
    fn rejects_absolute_path() {
        let root = unique_dir("abs");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = RarSink::new(&root).expect("new");
        let err = sink
            .begin_entry(0, "/etc/passwd", false, 0, None, None)
            .unwrap_err();
        assert!(matches!(err, SinkError::PathEscape { .. }));
    }

    #[test]
    fn rejects_embedded_nul() {
        let root = unique_dir("nul");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = RarSink::new(&root).expect("new");
        let err = sink
            .begin_entry(0, "a\0b", false, 0, None, None)
            .unwrap_err();
        assert!(matches!(err, SinkError::PathEscape { .. }));
    }

    #[test]
    fn rejects_empty_name() {
        let root = unique_dir("empty");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = RarSink::new(&root).expect("new");
        let err = sink.begin_entry(0, "", false, 0, None, None).unwrap_err();
        assert!(matches!(err, SinkError::PathEscape { .. }));
    }

    #[test]
    fn write_past_expected_size_poisons_sink() {
        let root = unique_dir("oversize");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = RarSink::new(&root).expect("new");
        sink.begin_entry(0, "x.bin", false, 4, None, None)
            .expect("begin");
        sink.write_entry(b"abcd").expect("write up to size");
        let err = sink.write_entry(b"e").unwrap_err();
        assert!(matches!(err, SinkError::Io { .. }));
        // Sink stays poisoned for subsequent calls.
        let err2 = sink
            .begin_entry(1, "y.bin", false, 0, None, None)
            .unwrap_err();
        assert!(matches!(err2, SinkError::Io { .. }));
    }

    #[test]
    fn end_entry_with_short_write_poisons_sink() {
        let root = unique_dir("short");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = RarSink::new(&root).expect("new");
        sink.begin_entry(0, "z.bin", false, 8, None, None)
            .expect("begin");
        sink.write_entry(b"abc").expect("partial");
        let err = sink.end_entry().unwrap_err();
        assert!(matches!(err, SinkError::Io { .. }));
    }

    #[test]
    fn crc32_mismatch_surfaces_hash_mismatch_diagnostic() {
        let root = unique_dir("crcmiss");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = RarSink::new(&root).expect("new");
        let payload = b"abcdef";
        let wrong_crc = !crc32(payload);
        sink.begin_entry(
            0,
            "out.bin",
            false,
            payload.len() as u64,
            Some(wrong_crc),
            None,
        )
        .expect("begin");
        sink.write_entry(payload).expect("write");
        let err = sink.end_entry().unwrap_err();
        match err {
            SinkError::Io { source, .. } => {
                let msg = source.to_string();
                assert!(msg.contains("CRC32"), "unexpected: {msg}");
                assert!(msg.contains("expected"), "unexpected: {msg}");
            }
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn blake2sp_mismatch_surfaces_hash_mismatch_diagnostic() {
        let root = unique_dir("b2miss");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = RarSink::new(&root).expect("new");
        let payload = b"abcdef";
        let wrong = [0u8; BLAKE2SP_DIGEST_LEN];
        sink.begin_entry(0, "out.bin", false, payload.len() as u64, None, Some(wrong))
            .expect("begin");
        sink.write_entry(payload).expect("write");
        let err = sink.end_entry().unwrap_err();
        match err {
            SinkError::Io { source, .. } => {
                let msg = source.to_string();
                assert!(msg.contains("BLAKE2sp"), "unexpected: {msg}");
            }
            other => panic!("expected Io, got {other:?}"),
        }
    }

    #[test]
    fn resume_at_seeds_running_hashes_from_on_disk_prefix() {
        let root = unique_dir("resume");
        let _g = CleanupOnDrop(root.clone());
        let payload = b"abcdefghijklmnopqrstuvwxyz0123456789".to_vec();
        let split = 11usize;
        let expected_crc32 = crc32(&payload);
        let expected_blake2sp = blake2sp::hash(&payload);

        // First "run": write the prefix and pretend the process
        // crashes between byte `split` and end-of-entry.
        {
            let mut sink = RarSink::new(&root).expect("new");
            sink.begin_entry(
                0,
                "resume.bin",
                false,
                payload.len() as u64,
                Some(expected_crc32),
                Some(expected_blake2sp),
            )
            .expect("begin");
            sink.write_entry(&payload[..split]).expect("partial");
            // Drop the sink mid-entry — simulates the prior run
            // crashing without calling close.
            drop(sink);
        }

        // Second "run": resume from the saved offset. The sink
        // re-reads bytes [0..split] off disk to seed both hashes,
        // then accepts the suffix.
        {
            let mut sink = RarSink::new(&root).expect("new");
            sink.begin_entry_resume(
                0,
                "resume.bin",
                false,
                payload.len() as u64,
                Some(expected_crc32),
                Some(expected_blake2sp),
                split as u64,
            )
            .expect("resume");
            sink.write_entry(&payload[split..]).expect("suffix");
            let fin = sink.end_entry().expect("end");
            assert_eq!(fin.bytes_written, payload.len() as u64);
            assert_eq!(fin.crc32, expected_crc32);
            assert_eq!(fin.blake2sp, expected_blake2sp);
            sink.close().expect("close");
        }

        let on_disk = fs::read(root.join("resume.bin")).expect("read back");
        assert_eq!(on_disk, payload);
    }
}
