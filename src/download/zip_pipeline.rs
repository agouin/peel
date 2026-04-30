//! Per-entry extraction driver for ZIP archives downloaded via the
//! shared sparse-file pipeline.
//!
//! The streaming pipeline used by zstd / xz / lz4 / tar archives
//! (`docs/PLAN.md` §10) walks the source forward, decoder-driven,
//! punching holes behind a moving cursor. ZIP can't work like that:
//! the central directory lives at the end of the archive, and per-
//! entry compressed payloads live at non-contiguous offsets the CD
//! names. This module is the second pipeline architecture
//! `docs/PLAN_v2.md` §5 calls for.
//!
//! # Workflow
//!
//! 1. Steer the download cursor toward the tail and wait for the
//!    chunks covering at least the last [`MAX_EOCD_TAIL_BYTES`] of
//!    the archive (or the whole archive if it's smaller).
//! 2. Read the tail; locate and parse the EOCD via [`find_eocd`].
//! 3. Wait for the chunks covering the central directory; parse it
//!    via [`parse_central_directory`].
//! 4. For each entry not already in `entries_completed`:
//!    a. Steer the cursor to the entry's local-file-header offset.
//!    b. Wait for the chunks covering the LFH + the entry's
//!    compressed bytes.
//!    c. Parse and validate the LFH against the central-directory
//!    entry.
//!    d. Begin the entry on the [`ZipSink`] (fresh, or
//!    resume-stored when the checkpoint had this entry mid-flight
//!    with method = STORED).
//!    e. Stream the entry's compressed bytes through
//!    [`decompress_entry`] into the sink.
//!    f. End the entry — the sink validates CRC against the CD.
//!    g. Punch the entry's compressed range in the sparse file.
//!    h. Emit a [`ZipPipelineEvent::EntryFinished`] so the
//!    coordinator can write a checkpoint.
//! 5. After the last entry, punch the central directory's range.
//!
//! Hole punching is per-entry rather than continuous, exactly as
//! `docs/PLAN_v2.md` §5 step 6 anticipates: less effective than the
//! streaming pipeline's per-frame discipline, but real for very
//! large entries and graceful elsewhere.

#![cfg(unix)]

use std::collections::HashSet;
use std::io::{self, Read};
use std::os::fd::BorrowedFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use thiserror::Error;

use crate::bitmap::ChunkBitmap;
use crate::download::scheduler::{DownloadStats, SchedulerError};
use crate::download::sparse_file::{SparseFile, SparseFileError};
use crate::punch::{align_down, align_up, PunchError, PunchHole};
use crate::sink::{BeginEntryOutcome, SinkError, ZipSink};
use crate::types::{ByteOffset, ChunkIndex};
use crate::zip::format::LFH_FIXED_LEN;
use crate::zip::{
    decompress_entry, find_eocd, parse_central_directory, CentralDirectoryEntry, EntryDecodeError,
    LocalFileHeader, ZipError, MAX_EOCD_TAIL_BYTES,
};

/// Configuration for a [`ZipPipeline::run`] invocation.
#[derive(Debug, Clone)]
pub struct ZipPipelineConfig {
    /// Total source size in bytes. The pipeline never reads or
    /// writes past this offset.
    pub total_size: u64,
    /// Chunk size the scheduler is using to slice the source.
    pub chunk_size: u64,
    /// Sleep between bitmap polls when waiting for a chunk to land.
    /// Tests use a small value (1–5 ms); production is fine with
    /// the coordinator default.
    pub poll_interval: Duration,
    /// Trailing window the pipeline first waits for so it can locate
    /// the EOCD. Defaults to [`MAX_EOCD_TAIL_BYTES`]; tests may use
    /// a smaller window for archives that fit entirely.
    pub initial_tail_window: u64,
}

impl Default for ZipPipelineConfig {
    fn default() -> Self {
        Self {
            total_size: 0,
            chunk_size: 0,
            poll_interval: Duration::from_millis(5),
            initial_tail_window: MAX_EOCD_TAIL_BYTES,
        }
    }
}

/// Resume state forwarded from a prior checkpoint, mirroring
/// [`crate::checkpoint::SinkState::Zip`].
#[derive(Debug, Clone, Default)]
pub struct ZipResumeState {
    /// Indices of central-directory entries already extracted to
    /// disk before the prior run crashed.
    pub entries_completed: Vec<u32>,
    /// Index of the entry that was in flight when the checkpoint
    /// was written, if any.
    pub current_entry: Option<u32>,
    /// Bytes already written into the in-flight entry.
    pub current_entry_offset: u64,
}

/// Diagnostic events the pipeline emits during a run.
///
/// The coordinator passes through a callback that uses these to
/// drive checkpoint cadence (typically via the same
/// `checkpoint_min_bytes` / `checkpoint_min_interval` policy the
/// streaming pipeline uses).
#[derive(Debug, Clone)]
pub enum ZipPipelineEvent {
    /// The central directory has been parsed; extraction is about
    /// to start.
    Started {
        /// Number of entries the central directory enumerates.
        entry_count: u32,
        /// Indices of entries the resume state already had marked
        /// complete (i.e. extraction will skip them).
        already_complete: Vec<u32>,
    },
    /// One entry just finished extracting cleanly.
    EntryFinished {
        /// Entry's index in central-directory order.
        index: u32,
        /// Entry's filename (as recorded in the central directory).
        name: String,
        /// Uncompressed bytes written for this entry.
        bytes_written: u64,
        /// Source byte range the pipeline punched after this entry.
        bytes_punched: u64,
    },
    /// One entry just had bytes flowed into it. Emitted at most
    /// once per [`ZipPipelineConfig::progress_interval_bytes`] of
    /// extracted output (currently fixed at the COPY_BUFFER_LEN
    /// granularity inside [`decompress_entry`]).
    InEntryProgress {
        /// Entry's index in central-directory order.
        index: u32,
        /// Bytes written so far into the in-flight entry. The
        /// coordinator records this as `current_entry_offset`.
        bytes_written: u64,
    },
}

/// Failure modes for [`ZipPipeline::run`].
#[derive(Debug, Error)]
pub enum ZipPipelineError {
    /// A ZIP wire-format failure surfaced. Wraps any
    /// [`ZipError`] variant; unsupported features carry the same
    /// message the user-facing CLI prints.
    #[error("ZIP format error")]
    Zip(#[source] ZipError),

    /// The decompression dispatcher failed mid-entry.
    #[error("entry decode failed")]
    EntryDecode(#[source] EntryDecodeError),

    /// The sink rejected an operation outside the decode loop
    /// (begin / end of an entry, mkdir of a directory entry,
    /// close).
    #[error("ZIP sink failed")]
    Sink(#[source] SinkError),

    /// Reading from or writing to the sparse file failed.
    #[error("sparse file IO failed")]
    Sparse(#[source] SparseFileError),

    /// Hole punching failed in a way the coordinator should
    /// surface (the [`PunchHole`] trait already swallows
    /// recoverable `Unsupported`; this variant only fires for
    /// unexpected errnos).
    #[error("hole punch failed")]
    Punch(#[source] PunchError),

    /// The download scheduler reported that all chunks are done
    /// but a chunk the pipeline needed never landed. This means
    /// the scheduler errored out and the failure has been ferried
    /// through the shared [`Mutex`].
    #[error("download finished early without delivering chunk {chunk}")]
    DownloadFinishedEarly {
        /// Index of the chunk the pipeline was waiting on.
        chunk: u32,
        /// Detail from the scheduler's stored failure, if any.
        detail: String,
    },

    /// The caller's progress callback returned an error (the §10
    /// kill-switch path uses this to abort cleanly).
    #[error("pipeline aborted by progress callback")]
    Aborted(#[source] io::Error),
}

/// Aggregate stats the pipeline returns on a clean run.
#[derive(Debug, Default, Clone)]
pub struct ZipExtractionStats {
    /// Number of entries extracted (i.e. CD-entry-count minus the
    /// resume-skipped ones).
    pub entries_extracted: u32,
    /// Total uncompressed bytes written across all entries this
    /// run.
    pub bytes_written: u64,
    /// Total source bytes punched (includes per-entry compressed
    /// ranges and the trailing CD region).
    pub bytes_punched: u64,
}

/// References the pipeline borrows for the duration of the call.
pub struct ZipPipeline<'a> {
    /// Configuration knobs.
    pub config: ZipPipelineConfig,
    /// Sparse file the workers are filling.
    pub sparse: &'a SparseFile,
    /// Bitmap recording which chunks are durable on disk.
    pub bitmap: &'a ChunkBitmap,
    /// Steering cursor the scheduler reads. The pipeline writes
    /// "byte offset I'm waiting for" here so worker priority
    /// follows the extraction order.
    pub cursor: &'a Arc<AtomicU64>,
    /// `true` when the download thread has exited (success or
    /// failure). The pipeline reads this so an early scheduler
    /// failure surfaces as [`ZipPipelineError::DownloadFinishedEarly`]
    /// rather than a hang.
    pub download_done: &'a Arc<AtomicBool>,
    /// Optional outcome the download thread stashes here. The
    /// pipeline only reads this on the early-termination path.
    pub download_outcome: &'a Arc<Mutex<Option<Result<DownloadStats, SchedulerError>>>>,
    /// Borrowed file descriptor for hole punching. The pipeline
    /// itself does not write to the sparse file; the workers do.
    pub sparse_fd: BorrowedFd<'a>,
}

impl<'a> ZipPipeline<'a> {
    /// Drive the extraction.
    ///
    /// `sink` is opened (and resumed, if applicable) by the caller
    /// per [`ZipResumeState`]. `puncher` is the
    /// coordinator-supplied [`PunchHole`] (block-aligned;
    /// degrades-gracefully on filesystems without support). The
    /// `callback` fires for each meaningful state change; returning
    /// an error from it aborts the run via [`ZipPipelineError::Aborted`].
    ///
    /// # Errors
    ///
    /// See [`ZipPipelineError`].
    pub fn run<F>(
        &self,
        sink: &mut ZipSink,
        puncher: &dyn PunchHole,
        resume: ZipResumeState,
        mut callback: F,
    ) -> Result<ZipExtractionStats, ZipPipelineError>
    where
        F: FnMut(&ZipPipelineEvent) -> io::Result<()>,
    {
        let mut stats = ZipExtractionStats::default();

        // Step 1: steer the cursor to the trailing region and wait
        // for the chunks covering at least the EOCD's max-size
        // window.
        let initial_window = self.config.initial_tail_window.min(self.config.total_size);
        let trailing_start = self.config.total_size.saturating_sub(initial_window);
        self.cursor.store(trailing_start, Ordering::Release);
        self.wait_for_range(trailing_start, self.config.total_size)?;

        // Step 2: read the tail and locate the EOCD.
        let mut tail = vec![0u8; initial_window as usize];
        self.sparse
            .read_exact_at(ByteOffset::new(trailing_start), &mut tail)
            .map_err(ZipPipelineError::Sparse)?;
        let eocd = find_eocd(&tail, self.config.total_size).map_err(ZipPipelineError::Zip)?;

        // Step 3: wait for the central directory and parse it.
        let cd_end = eocd.cd_offset.checked_add(eocd.cd_size).ok_or_else(|| {
            ZipPipelineError::Zip(ZipError::MalformedHeader {
                archive_offset: eocd.eocd_offset,
                reason: "EOCD: cd_offset + cd_size overflows u64".into(),
            })
        })?;
        self.cursor.store(eocd.cd_offset, Ordering::Release);
        self.wait_for_range(eocd.cd_offset, cd_end)?;
        let mut cd_bytes = vec![0u8; eocd.cd_size as usize];
        self.sparse
            .read_exact_at(ByteOffset::new(eocd.cd_offset), &mut cd_bytes)
            .map_err(ZipPipelineError::Sparse)?;
        let entries = parse_central_directory(&cd_bytes, eocd.cd_offset, eocd.cd_entry_count)
            .map_err(ZipPipelineError::Zip)?;

        // Notify started.
        let already_complete: Vec<u32> = resume.entries_completed.to_vec();
        callback(&ZipPipelineEvent::Started {
            entry_count: eocd.cd_entry_count,
            already_complete: already_complete.clone(),
        })
        .map_err(ZipPipelineError::Aborted)?;

        // Step 4: per-entry extraction.
        let completed_set: HashSet<u32> = resume.entries_completed.iter().copied().collect();
        for (i, entry) in entries.iter().enumerate() {
            let idx = u32::try_from(i).map_err(|_| {
                ZipPipelineError::Zip(ZipError::MalformedHeader {
                    archive_offset: 0,
                    reason: "central directory has more than u32::MAX entries".into(),
                })
            })?;
            if completed_set.contains(&idx) {
                continue;
            }
            let resume_offset = if Some(idx) == resume.current_entry {
                resume.current_entry_offset
            } else {
                0
            };
            let (bytes_written, bytes_punched) =
                self.extract_entry(entry, idx, resume_offset, sink, puncher, &mut callback)?;
            stats.entries_extracted = stats.entries_extracted.saturating_add(1);
            stats.bytes_written = stats.bytes_written.saturating_add(bytes_written);
            stats.bytes_punched = stats.bytes_punched.saturating_add(bytes_punched);
        }

        // Step 5: punch the central directory's range. The EOCD
        // itself is small (≤ 64 KiB+22) so punching it is mostly
        // symbolic, but it costs nothing to try; partial blocks at
        // either edge are skipped via `punch_range`'s inward
        // alignment so a crash before sidecar cleanup leaves the
        // last entry's tail bytes intact for resume.
        let cd_punch_end = self.config.total_size.min(
            eocd.cd_offset
                .saturating_add(eocd.cd_size.saturating_add(initial_window)),
        );
        let punched = self.punch_range(puncher, eocd.cd_offset, cd_punch_end)?;
        stats.bytes_punched = stats.bytes_punched.saturating_add(punched);

        Ok(stats)
    }

    /// Extract one entry; returns `(bytes_written, bytes_punched)`.
    fn extract_entry<F>(
        &self,
        entry: &CentralDirectoryEntry,
        index: u32,
        resume_offset: u64,
        sink: &mut ZipSink,
        puncher: &dyn PunchHole,
        callback: &mut F,
    ) -> Result<(u64, u64), ZipPipelineError>
    where
        F: FnMut(&ZipPipelineEvent) -> io::Result<()>,
    {
        // Directory entries: mkdir -p and we're done. Quietly punch
        // the LFH range (the directory entry itself has zero
        // compressed bytes, but the LFH is still on disk).
        if entry.is_directory() {
            sink.begin_entry(index, &entry.name, 0, entry.crc32)
                .map_err(ZipPipelineError::Sink)?;
            // No begin_entry follow-up needed; directory entries
            // immediately quiesce. Still, we punch the LFH range so
            // the disk usage tracks. We can't compute LFH size
            // without parsing the header — read it.
            self.cursor.store(entry.lfh_offset, Ordering::Release);
            let lfh_size = self.read_and_validate_lfh(entry)?;
            let lfh_end = entry.lfh_offset.saturating_add(lfh_size);
            let punched = self.punch_range(puncher, entry.lfh_offset, lfh_end)?;
            callback(&ZipPipelineEvent::EntryFinished {
                index,
                name: entry.name.clone(),
                bytes_written: 0,
                bytes_punched: punched,
            })
            .map_err(ZipPipelineError::Aborted)?;
            return Ok((0, punched));
        }

        // Regular-file entry.
        self.cursor.store(entry.lfh_offset, Ordering::Release);
        let lfh_size = self.read_and_validate_lfh(entry)?;
        let data_start = entry.lfh_offset.saturating_add(lfh_size);
        let data_end = data_start.saturating_add(entry.compressed_size);
        if data_end > self.config.total_size {
            return Err(ZipPipelineError::Zip(ZipError::MalformedHeader {
                archive_offset: entry.lfh_offset,
                reason: format!(
                    "entry {:?} compressed data ends at {data_end} but total size is {}",
                    entry.name, self.config.total_size,
                ),
            }));
        }
        self.wait_for_range(data_start, data_end)?;

        // Resume-stored is only safe for STORED entries; for
        // DEFLATE/zstd we truncate back to zero (codec state isn't
        // serialized in the checkpoint).
        let outcome =
            if resume_offset > 0 && matches!(entry.method, crate::zip::CompressionMethod::Stored) {
                sink.begin_entry_resume_stored(
                    index,
                    &entry.name,
                    entry.uncompressed_size,
                    entry.crc32,
                    resume_offset,
                )
                .map_err(ZipPipelineError::Sink)?
            } else {
                sink.begin_entry(index, &entry.name, entry.uncompressed_size, entry.crc32)
                    .map_err(ZipPipelineError::Sink)?
            };

        // Stream the entry's compressed bytes through the codec.
        // For STORED resume: skip the bytes already on disk.
        let stream_start = if matches!(outcome, BeginEntryOutcome::Directory { .. }) {
            // Defensive: shouldn't happen — entry.is_directory()
            // returned false. Bail rather than risk silent
            // misclassification.
            return Err(ZipPipelineError::Sink(SinkError::Io {
                path: sink.root().to_path_buf(),
                source: io::Error::other(format!(
                    "non-directory entry {:?} resolved to a directory path",
                    entry.name
                )),
            }));
        } else if matches!(entry.method, crate::zip::CompressionMethod::Stored) && resume_offset > 0
        {
            data_start.saturating_add(resume_offset)
        } else {
            data_start
        };

        let reader = BoundedSparseReader::new(
            self.sparse,
            self.bitmap,
            self.config.chunk_size,
            stream_start,
            data_end,
            self.download_done,
            self.download_outcome,
            self.config.poll_interval,
        );

        decompress_entry(entry.method, reader, sink, &entry.name)
            .map_err(ZipPipelineError::EntryDecode)?;

        let fin = sink.end_entry().map_err(ZipPipelineError::Sink)?;
        // Defensive: the sink already validates against
        // expected_size; this catches a CD/sink contract mismatch.
        debug_assert_eq!(fin.bytes_written, entry.uncompressed_size);

        // Punch [lfh_offset, data_end). The data descriptor (if
        // any, ≤ 16 bytes) lives in the gap before the next
        // entry's LFH; round-one leaves it un-punched because the
        // savings are not worth the extra range arithmetic.
        let punched = self.punch_range(puncher, entry.lfh_offset, data_end)?;

        callback(&ZipPipelineEvent::EntryFinished {
            index,
            name: entry.name.clone(),
            bytes_written: fin.bytes_written,
            bytes_punched: punched,
        })
        .map_err(ZipPipelineError::Aborted)?;

        Ok((fin.bytes_written, punched))
    }

    /// Read the entry's LFH from the sparse file and validate it
    /// against the central-directory entry. Returns the LFH's
    /// total on-wire size (`30 + filename_len + extra_len`).
    fn read_and_validate_lfh(
        &self,
        entry: &CentralDirectoryEntry,
    ) -> Result<u64, ZipPipelineError> {
        // The LFH's filename length lives at offset 26..28 inside
        // the fixed 30-byte header. We can't know the LFH's full
        // size until we read those bytes, so we wait twice: once
        // for the fixed header, then again if the variable region
        // crosses into chunks the first wait didn't cover.
        let fixed_end = entry
            .lfh_offset
            .checked_add(LFH_FIXED_LEN as u64)
            .ok_or_else(|| {
                ZipPipelineError::Zip(ZipError::MalformedHeader {
                    archive_offset: entry.lfh_offset,
                    reason: "LFH offset + fixed header overflows u64".into(),
                })
            })?;
        if fixed_end > self.config.total_size {
            return Err(ZipPipelineError::Zip(ZipError::MalformedHeader {
                archive_offset: entry.lfh_offset,
                reason: format!(
                    "LFH at offset {} extends past archive size {}",
                    entry.lfh_offset, self.config.total_size,
                ),
            }));
        }
        self.wait_for_range(entry.lfh_offset, fixed_end)?;

        // Read the fixed header to discover the variable-length
        // suffix.
        let mut fixed = [0u8; LFH_FIXED_LEN];
        self.sparse
            .read_exact_at(ByteOffset::new(entry.lfh_offset), &mut fixed)
            .map_err(ZipPipelineError::Sparse)?;
        // fields 26..28 = filename_length, 28..30 = extra_length
        let filename_length = u16::from_le_bytes([fixed[26], fixed[27]]) as u64;
        let extra_length = u16::from_le_bytes([fixed[28], fixed[29]]) as u64;
        let lfh_total = (LFH_FIXED_LEN as u64)
            .checked_add(filename_length)
            .and_then(|v| v.checked_add(extra_length))
            .ok_or_else(|| {
                ZipPipelineError::Zip(ZipError::MalformedHeader {
                    archive_offset: entry.lfh_offset,
                    reason: "LFH variable-length fields overflow u64".into(),
                })
            })?;
        let lfh_end = entry.lfh_offset.checked_add(lfh_total).ok_or_else(|| {
            ZipPipelineError::Zip(ZipError::MalformedHeader {
                archive_offset: entry.lfh_offset,
                reason: "LFH offset + total size overflows u64".into(),
            })
        })?;
        if lfh_end > self.config.total_size {
            return Err(ZipPipelineError::Zip(ZipError::MalformedHeader {
                archive_offset: entry.lfh_offset,
                reason: format!(
                    "LFH at offset {} extends past archive size {}",
                    entry.lfh_offset, self.config.total_size,
                ),
            }));
        }
        if lfh_total > LFH_FIXED_LEN as u64 {
            self.wait_for_range(fixed_end, lfh_end)?;
        }

        // Read the full LFH and validate.
        let mut full = vec![0u8; lfh_total as usize];
        self.sparse
            .read_exact_at(ByteOffset::new(entry.lfh_offset), &mut full)
            .map_err(ZipPipelineError::Sparse)?;
        let lfh = LocalFileHeader::parse(&full, entry.lfh_offset).map_err(ZipPipelineError::Zip)?;
        lfh.validate_against(entry).map_err(ZipPipelineError::Zip)?;
        Ok(lfh_total)
    }

    /// Punch the block-aligned interior of `[start, end)` on the
    /// sparse file. Returns the number of bytes actually requested
    /// from the puncher (`0` if the aligned range was empty).
    ///
    /// `start` is rounded **up** and `end` is rounded **down** to
    /// the puncher's `block_size_hint`, so partial blocks at either
    /// edge are left intact. This matters for ZIP: per-entry punch
    /// ranges abut their neighbors at arbitrary offsets, and on
    /// Linux `fallocate(FALLOC_FL_PUNCH_HOLE)` zeroes partial
    /// filesystem blocks at the edges of the requested range. Without
    /// inward alignment we'd silently overwrite the LFH bytes of the
    /// next entry (or the trailing bytes of the previous one),
    /// breaking resume.
    ///
    /// `Unsupported` errors from the puncher are absorbed silently
    /// — the streaming pipeline does the same; on a filesystem
    /// without hole-punching support this is a no-op.
    fn punch_range(
        &self,
        puncher: &dyn PunchHole,
        start: u64,
        end: u64,
    ) -> Result<u64, ZipPipelineError> {
        if end <= start {
            return Ok(0);
        }
        let block = puncher.block_size_hint().max(1);
        let aligned_start = match align_up(start, block) {
            Some(v) => v,
            None => return Ok(0),
        };
        let aligned_end = align_down(end, block).unwrap_or(0);
        if aligned_end <= aligned_start {
            return Ok(0);
        }
        let len = aligned_end - aligned_start;
        match self
            .sparse
            .punch(puncher, ByteOffset::new(aligned_start), len)
        {
            Ok(()) => Ok(len),
            Err(SparseFileError::Punch(source)) => {
                if matches!(source, PunchError::Unsupported { .. }) {
                    Ok(0)
                } else {
                    Err(ZipPipelineError::Punch(source))
                }
            }
            Err(other) => Err(ZipPipelineError::Sparse(other)),
        }
    }

    /// Block until every chunk overlapping `[start, end)` is
    /// present in the bitmap. Returns early with an error if the
    /// download thread reports completion before the chunks land.
    fn wait_for_range(&self, start: u64, end: u64) -> Result<(), ZipPipelineError> {
        if start >= end || self.config.chunk_size == 0 {
            return Ok(());
        }
        // INVARIANT: chunk_size > 0 (checked above).
        let first = start / self.config.chunk_size;
        let last = (end - 1) / self.config.chunk_size;
        for c in first..=last {
            let idx = u32::try_from(c).unwrap_or(u32::MAX);
            let chunk = ChunkIndex::new(idx);
            loop {
                if self.bitmap.is_complete(chunk) {
                    break;
                }
                if self.download_done.load(Ordering::Acquire) {
                    let detail = match self.download_outcome.lock() {
                        Ok(slot) => match &*slot {
                            Some(Err(e)) => format!("{e}"),
                            _ => String::new(),
                        },
                        Err(_) => "download outcome poisoned".into(),
                    };
                    return Err(ZipPipelineError::DownloadFinishedEarly { chunk: idx, detail });
                }
                thread::sleep(self.config.poll_interval);
            }
        }
        Ok(())
    }
}

/// `Read` adapter that reads a fixed `[start, end)` range out of
/// the sparse file, blocking on the bitmap when the chunk it
/// needs has not landed yet.
///
/// Construction does not perform IO; the first `read` call is the
/// first one that may block. The reader returns `Ok(0)` once it
/// has yielded `end - start` bytes.
pub struct BoundedSparseReader<'a> {
    sparse: &'a SparseFile,
    bitmap: &'a ChunkBitmap,
    chunk_size: u64,
    cursor: u64,
    end: u64,
    download_done: &'a Arc<AtomicBool>,
    download_outcome: &'a Arc<Mutex<Option<Result<DownloadStats, SchedulerError>>>>,
    poll_interval: Duration,
}

impl<'a> BoundedSparseReader<'a> {
    /// Wrap `[start, end)` of the sparse file as a `Read` source.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sparse: &'a SparseFile,
        bitmap: &'a ChunkBitmap,
        chunk_size: u64,
        start: u64,
        end: u64,
        download_done: &'a Arc<AtomicBool>,
        download_outcome: &'a Arc<Mutex<Option<Result<DownloadStats, SchedulerError>>>>,
        poll_interval: Duration,
    ) -> Self {
        Self {
            sparse,
            bitmap,
            chunk_size,
            cursor: start,
            end,
            download_done,
            download_outcome,
            poll_interval,
        }
    }
}

impl<'a> Read for BoundedSparseReader<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.cursor >= self.end {
                return Ok(0);
            }
            if self.chunk_size == 0 {
                return Err(io::Error::other("zero chunk_size"));
            }
            let chunk_idx = u32::try_from(self.cursor / self.chunk_size).unwrap_or(u32::MAX);
            if !self.bitmap.is_complete(ChunkIndex::new(chunk_idx)) {
                if self.download_done.load(Ordering::Acquire) {
                    let detail = match self.download_outcome.lock() {
                        Ok(slot) => match &*slot {
                            Some(Err(e)) => format!("download failed: {e}"),
                            _ => format!(
                                "download finished but chunk {chunk_idx} (cursor {}) is not \
                                 complete",
                                self.cursor,
                            ),
                        },
                        Err(_) => "download outcome poisoned".to_string(),
                    };
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, detail));
                }
                thread::sleep(self.poll_interval);
                continue;
            }
            // Bound the read so it doesn't cross chunk boundaries
            // (defensive; the bitmap state may change between this
            // check and the next iteration if we read very large
            // requests and a not-yet-complete chunk is in the
            // middle).
            let chunk_end = u64::from(chunk_idx)
                .saturating_add(1)
                .saturating_mul(self.chunk_size);
            let read_limit = chunk_end.min(self.end);
            let want = read_limit.saturating_sub(self.cursor).min(buf.len() as u64) as usize;
            if want == 0 {
                return Ok(0);
            }
            let n = self
                .sparse
                .read_at(ByteOffset::new(self.cursor), &mut buf[..want])
                .map_err(|e| io::Error::other(format!("sparse read: {e}")))?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("sparse short read at offset {}", self.cursor),
                ));
            }
            self.cursor = self.cursor.saturating_add(n as u64);
            return Ok(n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::error::Error as _;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::SystemTime;

    use crate::bitmap::ChunkBitmap;
    use crate::download::sparse_file::SparseFile;
    use crate::punch::NoopPuncher;
    use crate::types::ChunkIndex;
    use crate::zip::ieee;

    static UNIQ: AtomicU64 = AtomicU64::new(0);

    fn unique_path(label: &str, suffix: &str) -> PathBuf {
        let pid = std::process::id();
        let n = UNIQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "peel_zippipeline_{label}_{pid}_{nanos}_{n}{suffix}",
        ))
    }

    fn unique_dir(label: &str) -> PathBuf {
        let p = unique_path(label, ".dir");
        fs::create_dir_all(&p).expect("mkdir tmp root");
        p
    }

    struct CleanupOnDrop(PathBuf);
    impl Drop for CleanupOnDrop {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
            let _ = fs::remove_file(&self.0);
        }
    }

    /// Build a tiny ZIP in memory with an arbitrary mix of methods.
    fn build_zip(entries: &[(&str, u16, Vec<u8>)]) -> Vec<u8> {
        // Mirrors the test fixture builder in zip::format::tests
        // but kept private to avoid pulling test_helpers into the
        // public API.
        let mut out = Vec::new();
        let mut cd_specs: Vec<(String, u16, u32, u32, u32, u32, u32)> = Vec::new();
        for (name, method, raw) in entries {
            let lfh_offset = out.len() as u32;
            let crc = ieee(raw);
            // For non-STORED: encode appropriately. STORED is just
            // the raw bytes.
            let compressed: Vec<u8> = match *method {
                0 => raw.clone(),
                8 => {
                    let mut e =
                        flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
                    use std::io::Write as _;
                    e.write_all(raw).unwrap();
                    e.finish().unwrap()
                }
                93 => zstd::encode_all(std::io::Cursor::new(raw), 3).unwrap(),
                _ => raw.clone(),
            };
            // LFH
            out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes()); // version_needed
            out.extend_from_slice(&0u16.to_le_bytes()); // gp_flags
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // mtime
            out.extend_from_slice(&0u16.to_le_bytes()); // mdate
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
            out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&compressed);
            cd_specs.push((
                name.to_string(),
                *method,
                crc,
                compressed.len() as u32,
                raw.len() as u32,
                lfh_offset,
                0,
            ));
        }
        let cd_offset = out.len() as u32;
        for (name, method, crc, csize, usize_, lfh_off, _) in &cd_specs {
            out.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            out.extend_from_slice(&20u16.to_le_bytes()); // made_by
            out.extend_from_slice(&20u16.to_le_bytes()); // needed
            out.extend_from_slice(&0u16.to_le_bytes()); // gp_flags
            out.extend_from_slice(&method.to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // mtime
            out.extend_from_slice(&0u16.to_le_bytes()); // mdate
            out.extend_from_slice(&crc.to_le_bytes());
            out.extend_from_slice(&csize.to_le_bytes());
            out.extend_from_slice(&usize_.to_le_bytes());
            out.extend_from_slice(&(name.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u16.to_le_bytes()); // extra
            out.extend_from_slice(&0u16.to_le_bytes()); // comment
            out.extend_from_slice(&0u16.to_le_bytes()); // disk_start
            out.extend_from_slice(&0u16.to_le_bytes()); // internal_attrs
            out.extend_from_slice(&0u32.to_le_bytes()); // external_attrs
            out.extend_from_slice(&lfh_off.to_le_bytes());
            out.extend_from_slice(name.as_bytes());
        }
        let cd_size = out.len() as u32 - cd_offset;
        out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // disk
        out.extend_from_slice(&0u16.to_le_bytes()); // cd_start_disk
        out.extend_from_slice(&(cd_specs.len() as u16).to_le_bytes());
        out.extend_from_slice(&(cd_specs.len() as u16).to_le_bytes());
        out.extend_from_slice(&cd_size.to_le_bytes());
        out.extend_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // comment_length
        out
    }

    type ReadySparse = (
        SparseFile,
        Arc<ChunkBitmap>,
        PathBuf,
        Arc<AtomicBool>,
        Arc<Mutex<Option<Result<DownloadStats, SchedulerError>>>>,
    );

    /// Pre-populate a sparse file with `archive` and mark every
    /// chunk in the bitmap complete; useful for end-to-end pipeline
    /// tests that don't need to exercise the bitmap-wait path.
    fn ready_sparse(archive: &[u8], chunk_size: u64) -> ReadySparse {
        let path = unique_path("sparse", ".part");
        let total = archive.len() as u64;
        let sparse = SparseFile::open_or_create(&path, total).expect("sparse");
        sparse.pwrite_at(ByteOffset::ZERO, archive).expect("seed");
        let chunk_count = if total == 0 {
            0
        } else {
            u32::try_from(total.div_ceil(chunk_size)).expect("u32 chunks")
        };
        let bitmap = Arc::new(ChunkBitmap::new(chunk_count));
        for i in 0..chunk_count {
            bitmap.mark_complete(ChunkIndex::new(i));
        }
        let download_done = Arc::new(AtomicBool::new(true));
        let outcome: Arc<Mutex<Option<Result<DownloadStats, SchedulerError>>>> =
            Arc::new(Mutex::new(Some(Ok(DownloadStats::default()))));
        (sparse, bitmap, path, download_done, outcome)
    }

    #[test]
    fn extracts_three_methods_into_directory() {
        let root = unique_dir("three-methods");
        let _g_root = CleanupOnDrop(root.clone());

        let payload_a = b"hello stored entry".to_vec();
        let payload_b: Vec<u8> = (0..32 * 1024).map(|i| (i % 251) as u8).collect::<Vec<_>>(); // weakly compressible
        let payload_c = b"zstd test payload \xC0\xFF\xEE".repeat(50);

        let archive = build_zip(&[
            ("a.txt", 0, payload_a.clone()),
            ("b.bin", 8, payload_b.clone()),
            ("c.bin", 93, payload_c.clone()),
        ]);

        let (sparse, bitmap, sparse_path, download_done, outcome) = ready_sparse(&archive, 4096);
        let _g_sparse = CleanupOnDrop(sparse_path);

        let cursor = Arc::new(AtomicU64::new(0));
        let pipeline = ZipPipeline {
            config: ZipPipelineConfig {
                total_size: archive.len() as u64,
                chunk_size: 4096,
                poll_interval: Duration::from_millis(1),
                initial_tail_window: MAX_EOCD_TAIL_BYTES,
            },
            sparse: &sparse,
            bitmap: &bitmap,
            cursor: &cursor,
            download_done: &download_done,
            download_outcome: &outcome,
            sparse_fd: sparse.as_fd(),
        };
        let mut sink = ZipSink::new(&root).expect("sink");
        let puncher = NoopPuncher::new();
        let mut events = Vec::new();
        let stats = pipeline
            .run(&mut sink, &puncher, ZipResumeState::default(), |e| {
                events.push(e.clone());
                Ok(())
            })
            .expect("run");
        sink.close().expect("close");

        assert_eq!(stats.entries_extracted, 3);
        assert_eq!(
            stats.bytes_written,
            (payload_a.len() + payload_b.len() + payload_c.len()) as u64,
        );
        assert!(matches!(
            events.first(),
            Some(ZipPipelineEvent::Started { .. })
        ));
        let finished_count = events
            .iter()
            .filter(|e| matches!(e, ZipPipelineEvent::EntryFinished { .. }))
            .count();
        assert_eq!(finished_count, 3);

        assert_eq!(fs::read(root.join("a.txt")).unwrap(), payload_a);
        assert_eq!(fs::read(root.join("b.bin")).unwrap(), payload_b);
        assert_eq!(fs::read(root.join("c.bin")).unwrap(), payload_c);
    }

    #[test]
    fn skips_entries_already_in_resume_state() {
        let root = unique_dir("resume-skip");
        let _g_root = CleanupOnDrop(root.clone());

        let pa = b"first".to_vec();
        let pb = b"second".to_vec();
        let archive = build_zip(&[("a.txt", 0, pa.clone()), ("b.txt", 0, pb.clone())]);

        let (sparse, bitmap, sparse_path, download_done, outcome) = ready_sparse(&archive, 4096);
        let _g_sparse = CleanupOnDrop(sparse_path);

        // Pretend a.txt was already extracted.
        fs::write(root.join("a.txt"), b"--- previously extracted ---").unwrap();

        let cursor = Arc::new(AtomicU64::new(0));
        let pipeline = ZipPipeline {
            config: ZipPipelineConfig {
                total_size: archive.len() as u64,
                chunk_size: 4096,
                poll_interval: Duration::from_millis(1),
                initial_tail_window: MAX_EOCD_TAIL_BYTES,
            },
            sparse: &sparse,
            bitmap: &bitmap,
            cursor: &cursor,
            download_done: &download_done,
            download_outcome: &outcome,
            sparse_fd: sparse.as_fd(),
        };
        let mut sink = ZipSink::new(&root).expect("sink");
        let puncher = NoopPuncher::new();
        let resume = ZipResumeState {
            entries_completed: vec![0],
            current_entry: None,
            current_entry_offset: 0,
        };
        let stats = pipeline
            .run(&mut sink, &puncher, resume, |_| Ok(()))
            .expect("run");
        sink.close().expect("close");
        assert_eq!(stats.entries_extracted, 1);
        // a.txt was skipped — the on-disk content from the
        // pretend-prior-run is preserved.
        assert_eq!(
            fs::read(root.join("a.txt")).unwrap(),
            b"--- previously extracted ---",
        );
        assert_eq!(fs::read(root.join("b.txt")).unwrap(), pb);
    }

    #[test]
    fn resume_stored_mid_entry_picks_up_at_offset() {
        let root = unique_dir("resume-mid");
        let _g_root = CleanupOnDrop(root.clone());

        let payload = b"the quick brown fox jumps over the lazy dog".to_vec();
        let archive = build_zip(&[("doc.txt", 0, payload.clone())]);

        let (sparse, bitmap, sparse_path, download_done, outcome) = ready_sparse(&archive, 4096);
        let _g_sparse = CleanupOnDrop(sparse_path);

        // Pre-write the first 10 bytes to disk so resume_stored can
        // truncate-and-reseed against them.
        fs::write(root.join("doc.txt"), &payload[..10]).unwrap();

        let cursor = Arc::new(AtomicU64::new(0));
        let pipeline = ZipPipeline {
            config: ZipPipelineConfig {
                total_size: archive.len() as u64,
                chunk_size: 4096,
                poll_interval: Duration::from_millis(1),
                initial_tail_window: MAX_EOCD_TAIL_BYTES,
            },
            sparse: &sparse,
            bitmap: &bitmap,
            cursor: &cursor,
            download_done: &download_done,
            download_outcome: &outcome,
            sparse_fd: sparse.as_fd(),
        };
        let mut sink = ZipSink::new(&root).expect("sink");
        let puncher = NoopPuncher::new();
        let resume = ZipResumeState {
            entries_completed: vec![],
            current_entry: Some(0),
            current_entry_offset: 10,
        };
        pipeline
            .run(&mut sink, &puncher, resume, |_| Ok(()))
            .expect("run");
        sink.close().expect("close");
        assert_eq!(fs::read(root.join("doc.txt")).unwrap(), payload);
    }

    #[test]
    fn unsupported_method_surfaces_as_zip_error_with_method_name() {
        let root = unique_dir("unsupported");
        let _g_root = CleanupOnDrop(root.clone());
        let archive = build_zip(&[("weird.bin", 14, b"opaque".to_vec())]);
        let (sparse, bitmap, sparse_path, download_done, outcome) = ready_sparse(&archive, 4096);
        let _g_sparse = CleanupOnDrop(sparse_path);

        let cursor = Arc::new(AtomicU64::new(0));
        let pipeline = ZipPipeline {
            config: ZipPipelineConfig {
                total_size: archive.len() as u64,
                chunk_size: 4096,
                poll_interval: Duration::from_millis(1),
                initial_tail_window: MAX_EOCD_TAIL_BYTES,
            },
            sparse: &sparse,
            bitmap: &bitmap,
            cursor: &cursor,
            download_done: &download_done,
            download_outcome: &outcome,
            sparse_fd: sparse.as_fd(),
        };
        let mut sink = ZipSink::new(&root).expect("sink");
        let puncher = NoopPuncher::new();
        let err = pipeline
            .run(&mut sink, &puncher, ZipResumeState::default(), |_| Ok(()))
            .expect_err("must refuse");
        let msg = err.to_string();
        assert!(msg.contains("decode") || msg.contains("ZIP"), "msg={msg}");
        // The specific method name appears in the chained source.
        let mut chained = err.source();
        while let Some(s) = chained {
            if s.to_string().contains("LZMA") {
                return;
            }
            chained = s.source();
        }
        panic!("expected LZMA in error chain, got {err:?}");
    }

    #[test]
    fn directory_entry_creates_folder() {
        let root = unique_dir("dirent");
        let _g_root = CleanupOnDrop(root.clone());
        let archive = build_zip(&[
            ("subdir/", 0, Vec::new()),
            ("subdir/file.txt", 0, b"hi".to_vec()),
        ]);
        let (sparse, bitmap, sparse_path, download_done, outcome) = ready_sparse(&archive, 4096);
        let _g_sparse = CleanupOnDrop(sparse_path);
        let cursor = Arc::new(AtomicU64::new(0));
        let pipeline = ZipPipeline {
            config: ZipPipelineConfig {
                total_size: archive.len() as u64,
                chunk_size: 4096,
                poll_interval: Duration::from_millis(1),
                initial_tail_window: MAX_EOCD_TAIL_BYTES,
            },
            sparse: &sparse,
            bitmap: &bitmap,
            cursor: &cursor,
            download_done: &download_done,
            download_outcome: &outcome,
            sparse_fd: sparse.as_fd(),
        };
        let mut sink = ZipSink::new(&root).expect("sink");
        let puncher = NoopPuncher::new();
        pipeline
            .run(&mut sink, &puncher, ZipResumeState::default(), |_| Ok(()))
            .expect("run");
        sink.close().expect("close");
        assert!(root.join("subdir").is_dir());
        assert_eq!(fs::read(root.join("subdir/file.txt")).unwrap(), b"hi");
    }

    #[test]
    fn callback_error_aborts_run() {
        let root = unique_dir("abort");
        let _g_root = CleanupOnDrop(root.clone());
        let archive = build_zip(&[
            ("a.txt", 0, b"aaaa".to_vec()),
            ("b.txt", 0, b"bbbb".to_vec()),
        ]);
        let (sparse, bitmap, sparse_path, download_done, outcome) = ready_sparse(&archive, 4096);
        let _g_sparse = CleanupOnDrop(sparse_path);
        let cursor = Arc::new(AtomicU64::new(0));
        let pipeline = ZipPipeline {
            config: ZipPipelineConfig {
                total_size: archive.len() as u64,
                chunk_size: 4096,
                poll_interval: Duration::from_millis(1),
                initial_tail_window: MAX_EOCD_TAIL_BYTES,
            },
            sparse: &sparse,
            bitmap: &bitmap,
            cursor: &cursor,
            download_done: &download_done,
            download_outcome: &outcome,
            sparse_fd: sparse.as_fd(),
        };
        let mut sink = ZipSink::new(&root).expect("sink");
        let puncher = NoopPuncher::new();
        let mut count = 0;
        let err = pipeline
            .run(
                &mut sink,
                &puncher,
                ZipResumeState::default(),
                |_| -> io::Result<()> {
                    count += 1;
                    if count == 2 {
                        Err(io::Error::other("abort!"))
                    } else {
                        Ok(())
                    }
                },
            )
            .expect_err("must abort");
        assert!(matches!(err, ZipPipelineError::Aborted(_)));
    }
}
