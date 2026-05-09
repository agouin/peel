//! Per-folder extraction driver for 7z archives.
//!
//! Implements §8 of `docs/PLAN_7z_support.md`. Sibling to
//! [`super::zip_pipeline`], same shape: bootstrap by reading
//! the (small) trailer region, iterate the parsed folders in
//! archive order, run the §6 folder decoder against the §7
//! sink for each, and punch the source's pack-stream range
//! once a folder lands durably on disk.
//!
//! # Workflow
//!
//! 1. Wait for the first 32 bytes of the archive; parse the
//!    [`SignatureHeader`].
//! 2. Wait for the trailer range the SignatureHeader names;
//!    parse the [`Trailer`]. If it's [`Trailer::Encoded`], run
//!    the embedded folder against an in-memory sink, then
//!    re-parse the decoded bytes via
//!    [`parse_decoded_header`].
//! 3. For each folder *not* already in `resume.folders_completed`:
//!    a. Compute the folder's packed-byte range (relative to
//!    the archive's byte 32).
//!    b. Steer the cursor + wait for the chunks covering that
//!    range.
//!    c. Construct a [`FolderDecoder`] reading from the
//!    sparse file and run it against the sink.
//!    d. Punch the folder's packed range.
//!    e. Emit `FolderFinished` so the coordinator can
//!    checkpoint.
//! 4. Materialize empty / directory files via
//!    [`SevenzSink::materialize_empty`].
//! 5. Punch the trailer range. Emit `Complete`.

#![cfg(unix)]

use std::collections::HashSet;
use std::io;
use std::os::fd::BorrowedFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use thiserror::Error;

use crate::bitmap::ChunkBitmap;
use crate::decode::sevenz::folder::FolderDecoder;
use crate::decode::sevenz::format::{
    parse_signature_header, SignatureHeader, SIGNATURE_HEADER_LEN,
};
use crate::decode::sevenz::header::{
    parse_decoded_header, parse_trailer, Header, StreamsInfo, Trailer,
};
use crate::download::scheduler::{DownloadStats, SchedulerError};
use crate::download::sparse_file::{SparseFile, SparseFileError};
use crate::hash::crc32::ieee as crc32_ieee;
use crate::punch::{align_down, align_up, PunchError, PunchHole};
use crate::sevenz::SevenzError;
use crate::sink::{SevenzSink, SinkError};
use crate::types::{ByteOffset, ChunkIndex};

/// Configuration for a [`SevenzPipeline::run`] invocation.
#[derive(Debug, Clone)]
pub struct SevenzPipelineConfig {
    /// Total source size in bytes.
    pub total_size: u64,
    /// Chunk size the scheduler is using.
    pub chunk_size: u64,
    /// Sleep between bitmap polls.
    pub poll_interval: Duration,
}

impl Default for SevenzPipelineConfig {
    fn default() -> Self {
        Self {
            total_size: 0,
            chunk_size: 0,
            poll_interval: Duration::from_millis(5),
        }
    }
}

/// Resume state forwarded from a prior checkpoint, mirroring
/// [`crate::checkpoint::SinkState::Sevenz`] (added in §9).
#[derive(Debug, Clone, Default)]
pub struct SevenzResumeState {
    /// Indices of folders already extracted to disk before the
    /// prior run crashed.
    pub folders_completed: Vec<u32>,
    /// Index of the folder that was in flight when the
    /// checkpoint was written, if any. Round-one resume
    /// restarts that folder from byte 0; mid-folder resume is
    /// `O.32c`.
    pub current_folder: Option<u32>,
}

/// Diagnostic events the pipeline emits.
#[derive(Debug, Clone)]
pub enum SevenzPipelineEvent {
    /// The trailer has been parsed; extraction is about to start.
    Started {
        /// Number of folders the archive declares.
        folder_count: u32,
        /// Indices of folders the resume state already had
        /// marked complete (i.e. extraction will skip them).
        already_complete: Vec<u32>,
    },
    /// One folder finished extracting cleanly.
    FolderFinished {
        /// Folder index in archive order.
        index: u32,
        /// Bytes punched from the source for this folder.
        bytes_punched: u64,
    },
    /// Extraction is fully done.
    Complete {
        /// Total bytes punched across all folders + the
        /// trailer.
        bytes_punched: u64,
    },
}

/// Failure modes for [`SevenzPipeline::run`].
#[derive(Debug, Error)]
pub enum SevenzPipelineError {
    /// A 7z wire-format failure surfaced.
    #[error("7z format error")]
    Sevenz(#[source] SevenzError),

    /// The folder decoder or coder dispatch failed mid-folder.
    #[error("folder decode failed")]
    FolderDecode(#[source] SevenzError),

    /// The sink rejected an operation.
    #[error("sink failed")]
    Sink(#[source] SinkError),

    /// Reading from or writing to the sparse file failed.
    #[error("sparse file IO failed")]
    Sparse(#[source] SparseFileError),

    /// Hole punching failed.
    #[error("hole punch failed")]
    Punch(#[source] PunchError),

    /// The download scheduler reported all chunks done but a
    /// chunk the pipeline needed never landed.
    #[error("download finished early without delivering chunk {chunk}")]
    DownloadFinishedEarly {
        /// Index of the chunk the pipeline was waiting on.
        chunk: u32,
        /// Detail from the scheduler's stored failure, if any.
        detail: String,
    },

    /// The caller's progress callback returned an error.
    #[error("pipeline aborted by progress callback")]
    Aborted(#[source] io::Error),

    /// An expected trailer CRC32 disagreed with the bytes the
    /// pipeline read. Distinct variant so the user-facing
    /// diagnostic can name the trailer specifically (a
    /// CorruptHeader variant from the parser would be a less
    /// helpful "corrupt header somewhere" message).
    #[error(
        "trailer CRC32 mismatch: SignatureHeader recorded \
         {expected:#010x}, computed {computed:#010x}"
    )]
    TrailerCrcMismatch {
        /// CRC32 the SignatureHeader recorded.
        expected: u32,
        /// CRC32 computed over the trailer bytes.
        computed: u32,
    },
}

/// Aggregate stats returned on a clean run.
#[derive(Debug, Default, Clone)]
pub struct SevenzExtractionStats {
    /// Number of folders extracted this run (excludes resume-
    /// skipped ones).
    pub folders_extracted: u32,
    /// Total source bytes punched.
    pub bytes_punched: u64,
}

/// References the pipeline borrows for the duration of the call.
pub struct SevenzPipeline<'a> {
    /// Configuration knobs.
    pub config: SevenzPipelineConfig,
    /// Sparse file the workers are filling.
    pub sparse: &'a SparseFile,
    /// Bitmap recording which chunks are durable.
    pub bitmap: &'a ChunkBitmap,
    /// Steering cursor. Workers preferentially dispatch chunks
    /// at-or-past this byte offset. The pipeline steers it to
    /// the trailer first (so the small metadata region lands
    /// quickly), then to the start of pack data, and finally
    /// the [`crate::progress::ProgressState`] thread keeps it
    /// in sync with extraction progress via the streaming
    /// reader's per-`read` updates.
    pub cursor: &'a Arc<AtomicU64>,
    /// `true` once the download thread has exited.
    pub download_done: &'a Arc<AtomicBool>,
    /// Optional outcome the download thread stashes here.
    pub download_outcome: &'a Arc<Mutex<Option<Result<DownloadStats, SchedulerError>>>>,
    /// Borrowed file descriptor for hole punching.
    pub sparse_fd: BorrowedFd<'a>,
    /// Shared progress state. The streaming reader publishes
    /// `bytes_decoded_input` on each pread so the scheduler's
    /// `max_disk_buffer` throttle measures real lookahead. When
    /// `None`, the throttle is effectively disabled (zero
    /// lookahead) and the pipeline runs without bound — useful
    /// for tests but never the production path.
    pub progress_state: Option<&'a Arc<crate::progress::ProgressState>>,
}

impl SevenzPipeline<'_> {
    /// Drive the extraction.
    ///
    /// # Errors
    ///
    /// See [`SevenzPipelineError`].
    pub fn run<F>(
        &self,
        sink: &mut SevenzSink,
        puncher: &dyn PunchHole,
        resume: SevenzResumeState,
        mut callback: F,
    ) -> Result<SevenzExtractionStats, SevenzPipelineError>
    where
        F: FnMut(&SevenzPipelineEvent) -> io::Result<()>,
    {
        let mut stats = SevenzExtractionStats::default();

        // Step 1: signature header.
        self.cursor.store(0, Ordering::Release);
        self.wait_for_range(0, SIGNATURE_HEADER_LEN as u64)?;
        let mut sig_buf = [0u8; SIGNATURE_HEADER_LEN];
        self.sparse
            .read_exact_at(ByteOffset::ZERO, &mut sig_buf)
            .map_err(SevenzPipelineError::Sparse)?;
        let signature = parse_signature_header(&sig_buf).map_err(SevenzPipelineError::Sevenz)?;

        // Step 2: trailer.
        let (trailer_start, trailer_len) = signature
            .trailer_range(self.config.total_size)
            .map_err(SevenzPipelineError::Sevenz)?;
        let trailer_end = trailer_start.saturating_add(trailer_len);
        // Steer worker priority to the trailer and *exempt the
        // trailer fetch from the cap*. The trailer is small in
        // a plain-Header archive (KB to a few MB) but an
        // EncodedHeader's compressed trailer can easily exceed
        // a tightly-configured `max_disk_buffer`. Forcing it
        // through the cap would deadlock: workers can't
        // dispatch enough chunks to land the whole trailer,
        // the trailer parse can't run, the per-folder reader
        // can't start, and the cap never releases. Exempting
        // is the right move — the trailer is a fixed metadata
        // region, not bulk pack data, and once it's parsed
        // we re-anchor the cap to the pack-data origin so the
        // *folder* extraction respects the cap.
        //
        // Implementation: temporarily advance
        // `bytes_decoded_input` to `total_size`. The cap reads
        // `bytes_downloaded - bytes_decoded_input`; when
        // `bytes_decoded_input >= bytes_downloaded` the
        // saturating-sub yields 0 and the cap never fires.
        // After the trailer parse, the per-folder
        // [`SparseFileSliceReader`] resets the anchor to its
        // folder's start.
        self.cursor.store(trailer_start, Ordering::Release);
        if let Some(p) = self.progress_state {
            p.set_bytes_decoded_input(self.config.total_size);
        }
        self.wait_for_range(trailer_start, trailer_end)?;

        let mut trailer_bytes = vec![0u8; trailer_len as usize];
        self.sparse
            .read_exact_at(ByteOffset::new(trailer_start), &mut trailer_bytes)
            .map_err(SevenzPipelineError::Sparse)?;

        // Verify trailer CRC32 against SignatureHeader's record.
        let computed_crc = crc32_ieee(&trailer_bytes);
        if computed_crc != signature.next_header_crc {
            return Err(SevenzPipelineError::TrailerCrcMismatch {
                expected: signature.next_header_crc,
                computed: computed_crc,
            });
        }

        let header = self.parse_full_header(&signature, &trailer_bytes)?;

        // Install the parsed file list on the sink. The
        // coordinator constructs the sink with no files (since
        // the trailer hadn't been parsed yet); we hand it over
        // here so begin_substream / materialize_empty can
        // resolve paths. Constructing the sink later, after
        // trailer parse, would force the coordinator to wait
        // for trailer chunks to land before workers had any
        // priority signal — which serializes the download
        // (workers walk byte 0 → end) ahead of any extraction
        // and kills the streaming overlap. Doing it here lets
        // workers prioritize the trailer (per cursor steering
        // above) AND the early pack data in parallel.
        sink.set_files(header.files.clone());

        let folder_count = header
            .main_streams
            .as_ref()
            .map(|s| s.folders.len() as u32)
            .unwrap_or(0);
        callback(&SevenzPipelineEvent::Started {
            folder_count,
            already_complete: resume.folders_completed.clone(),
        })
        .map_err(SevenzPipelineError::Aborted)?;

        // Step 3: per-folder extraction.
        let completed_set: HashSet<u32> = resume.folders_completed.iter().copied().collect();
        if let Some(streams) = header.main_streams.as_ref() {
            let pack_origin = SIGNATURE_HEADER_LEN as u64;
            let pack_section_start =
                pack_origin.checked_add(streams.pack_pos).ok_or_else(|| {
                    SevenzPipelineError::Sevenz(SevenzError::CorruptHeader {
                        reason: "pack_pos overflows when added to signature header length".into(),
                    })
                })?;

            // Compute (start, end) of each folder's packed range.
            let mut packed_starts: Vec<u64> = Vec::with_capacity(streams.folders.len());
            let mut acc = pack_section_start;
            for (i, _folder) in streams.folders.iter().enumerate() {
                packed_starts.push(acc);
                let pack_size = streams.pack_sizes.get(i).copied().ok_or_else(|| {
                    SevenzPipelineError::Sevenz(SevenzError::CorruptHeader {
                        reason: format!("pack_sizes missing entry for folder {i}"),
                    })
                })?;
                acc = acc.checked_add(pack_size).ok_or_else(|| {
                    SevenzPipelineError::Sevenz(SevenzError::CorruptHeader {
                        reason: format!("pack offset overflows at folder {i}"),
                    })
                })?;
            }

            for (i, _folder) in streams.folders.iter().enumerate() {
                let idx = u32::try_from(i).map_err(|_| {
                    SevenzPipelineError::Sevenz(SevenzError::CorruptHeader {
                        reason: "folder index exceeds u32".into(),
                    })
                })?;
                if completed_set.contains(&idx) {
                    continue;
                }
                let start = packed_starts[i];
                let pack_size = streams.pack_sizes[i];
                let end = start.checked_add(pack_size).ok_or_else(|| {
                    SevenzPipelineError::Sevenz(SevenzError::CorruptHeader {
                        reason: format!("folder {i} pack end overflows"),
                    })
                })?;
                if end > self.config.total_size {
                    return Err(SevenzPipelineError::Sevenz(SevenzError::CorruptHeader {
                        reason: format!(
                            "folder {i} pack end {end} > total_size {}",
                            self.config.total_size,
                        ),
                    }));
                }
                // Stream the packed bytes straight from the
                // sparse file via a chunk-blocking pread
                // adapter. The reader publishes its position
                // to `self.cursor` on every `read`, so the
                // scheduler's `max_disk_buffer` throttle
                // sees decoder progress and releases new
                // dispatches as old chunks are consumed. This
                // is what gives the 7z pipeline an
                // extract-while-downloading overlap *and*
                // bounds the on-disk footprint regardless of
                // archive size — both prerequisites for
                // resuming a multi-GiB extraction without
                // re-downloading the prefix.
                let mut packed_reader = SparseFileSliceReader::new(
                    self.sparse,
                    self.bitmap,
                    self.config.chunk_size,
                    self.download_done,
                    self.config.poll_interval,
                    self.cursor,
                    self.progress_state,
                    start,
                    pack_size,
                );
                let file_indices = header.folder_to_files.get(i).cloned().unwrap_or_default();
                let decoder = FolderDecoder::new(
                    &streams.folders[i],
                    streams,
                    idx,
                    &file_indices,
                    &mut packed_reader,
                );
                decoder
                    .decode(sink)
                    .map_err(SevenzPipelineError::FolderDecode)?;

                // Punch the folder's packed range (block-aligned
                // inward).
                let punched = self.punch_range(puncher, start, end)?;
                stats.bytes_punched = stats.bytes_punched.saturating_add(punched);
                stats.folders_extracted = stats.folders_extracted.saturating_add(1);
                callback(&SevenzPipelineEvent::FolderFinished {
                    index: idx,
                    bytes_punched: punched,
                })
                .map_err(SevenzPipelineError::Aborted)?;
            }
        }

        // Step 4: empty / directory files.
        for (i, rec) in header.files.iter().enumerate() {
            if rec.is_directory || !rec.has_stream {
                let idx = u32::try_from(i).map_err(|_| {
                    SevenzPipelineError::Sevenz(SevenzError::CorruptHeader {
                        reason: "file index exceeds u32".into(),
                    })
                })?;
                sink.materialize_empty(idx)
                    .map_err(SevenzPipelineError::Sink)?;
            }
        }

        // Step 5: punch the trailer range. Also the SignatureHeader
        // (the first 32 bytes) gets punched here for symmetry.
        let trailer_punched = self.punch_range(puncher, trailer_start, trailer_end)?;
        stats.bytes_punched = stats.bytes_punched.saturating_add(trailer_punched);
        let header_punched = self.punch_range(puncher, 0, SIGNATURE_HEADER_LEN as u64)?;
        stats.bytes_punched = stats.bytes_punched.saturating_add(header_punched);

        callback(&SevenzPipelineEvent::Complete {
            bytes_punched: stats.bytes_punched,
        })
        .map_err(SevenzPipelineError::Aborted)?;

        Ok(stats)
    }

    /// Parse the trailer, decoding an embedded `EncodedHeader`
    /// folder if present.
    fn parse_full_header(
        &self,
        signature: &SignatureHeader,
        trailer_bytes: &[u8],
    ) -> Result<Header, SevenzPipelineError> {
        match parse_trailer(trailer_bytes).map_err(SevenzPipelineError::Sevenz)? {
            Trailer::Plain(h) => Ok(h),
            Trailer::Encoded { streams_info } => {
                self.decode_embedded_header(signature, &streams_info)
            }
        }
    }

    /// Run the (single-folder) packed range named by an
    /// `EncodedHeader`'s embedded `StreamsInfo`, then re-parse
    /// the decoded bytes as a plain Header.
    fn decode_embedded_header(
        &self,
        _signature: &SignatureHeader,
        streams: &StreamsInfo,
    ) -> Result<Header, SevenzPipelineError> {
        if streams.folders.len() != 1 {
            return Err(SevenzPipelineError::Sevenz(SevenzError::CorruptHeader {
                reason: format!(
                    "EncodedHeader expected 1 folder, got {}",
                    streams.folders.len()
                ),
            }));
        }
        let pack_origin = SIGNATURE_HEADER_LEN as u64;
        let inner_start = pack_origin.checked_add(streams.pack_pos).ok_or_else(|| {
            SevenzPipelineError::Sevenz(SevenzError::CorruptHeader {
                reason: "EncodedHeader pack_pos overflows".into(),
            })
        })?;
        let inner_size = *streams.pack_sizes.first().ok_or_else(|| {
            SevenzPipelineError::Sevenz(SevenzError::CorruptHeader {
                reason: "EncodedHeader has zero pack streams".into(),
            })
        })?;
        let inner_end = inner_start.checked_add(inner_size).ok_or_else(|| {
            SevenzPipelineError::Sevenz(SevenzError::CorruptHeader {
                reason: "EncodedHeader pack end overflows".into(),
            })
        })?;
        if inner_end > self.config.total_size {
            return Err(SevenzPipelineError::Sevenz(SevenzError::CorruptHeader {
                reason: format!(
                    "EncodedHeader pack end {inner_end} > total_size {}",
                    self.config.total_size
                ),
            }));
        }
        // The EncodedHeader's folder is small (a compressed
        // copy of the trailer); stream it via the same slice
        // reader the main folder loop uses. The reader seeds
        // the pipeline cursor at `inner_start` so workers
        // prioritize the embedded-folder chunks immediately.
        let mut packed_reader = SparseFileSliceReader::new(
            self.sparse,
            self.bitmap,
            self.config.chunk_size,
            self.download_done,
            self.config.poll_interval,
            self.cursor,
            self.progress_state,
            inner_start,
            inner_size,
        );

        // Run the embedded folder decoder against an in-memory
        // sink that just collects bytes.
        let mut collector = HeaderCollectorSink::default();
        FolderDecoder::new(
            &streams.folders[0],
            streams,
            0,
            &[u32::MAX], // dummy file index (not used by collector)
            &mut packed_reader,
        )
        .decode(&mut collector)
        .map_err(SevenzPipelineError::FolderDecode)?;

        parse_decoded_header(&collector.bytes).map_err(SevenzPipelineError::Sevenz)
    }

    /// Block until every chunk covering `[start, end)` is
    /// marked complete in the bitmap.
    fn wait_for_range(&self, start: u64, end: u64) -> Result<(), SevenzPipelineError> {
        if end <= start {
            return Ok(());
        }
        let chunk_size = self.config.chunk_size;
        if chunk_size == 0 {
            return Err(SevenzPipelineError::Sevenz(SevenzError::CorruptHeader {
                reason: "pipeline configured with chunk_size = 0".into(),
            }));
        }
        let first_chunk = start / chunk_size;
        let last_chunk = (end - 1) / chunk_size;
        for c in first_chunk..=last_chunk {
            let idx = u32::try_from(c).map_err(|_| {
                SevenzPipelineError::Sevenz(SevenzError::CorruptHeader {
                    reason: format!("chunk index {c} exceeds u32"),
                })
            })?;
            loop {
                if self.bitmap.is_complete(ChunkIndex::new(idx)) {
                    break;
                }
                if self.download_done.load(Ordering::Acquire)
                    && !self.bitmap.is_complete(ChunkIndex::new(idx))
                {
                    let detail = self
                        .download_outcome
                        .lock()
                        .ok()
                        .and_then(|g| {
                            g.as_ref().map(|r| match r {
                                Ok(_) => "ok".to_string(),
                                Err(e) => format!("{e}"),
                            })
                        })
                        .unwrap_or_else(|| "unknown".into());
                    return Err(SevenzPipelineError::DownloadFinishedEarly { chunk: idx, detail });
                }
                thread::sleep(self.config.poll_interval);
            }
        }
        Ok(())
    }

    /// Punch `[start, end)` (block-aligned inward) and return
    /// the byte count that landed. `Unsupported` errors from
    /// the puncher are absorbed silently — same posture as
    /// [`super::zip_pipeline`].
    fn punch_range(
        &self,
        puncher: &dyn PunchHole,
        start: u64,
        end: u64,
    ) -> Result<u64, SevenzPipelineError> {
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
                    Err(SevenzPipelineError::Punch(source))
                }
            }
            Err(other) => Err(SevenzPipelineError::Sparse(other)),
        }
    }
}

/// `Read` adapter over a fixed-length range of a `SparseFile`,
/// blocking per-chunk on the [`ChunkBitmap`] so the
/// [`FolderDecoder`] can stream bytes from the front of a
/// folder while workers are still fetching chunks at the back.
///
/// This is the key to extract-while-downloading for 7z. A naive
/// pread-only reader (the predecessor of this type) silently
/// returns sparse-zeros for chunks that haven't landed yet,
/// which the §8 pipeline guarded against by waiting for the
/// entire pack range up front — but that wait *serialized* the
/// decode behind the download. Polling the bitmap per chunk
/// inside `read` means the decoder gets bytes as soon as each
/// chunk lands; the wire and the decoder run concurrently.
///
/// `download_done` is consulted on every poll iteration so a
/// scheduler failure surfaces as a typed read error instead of
/// hanging.
struct SparseFileSliceReader<'a> {
    sparse: &'a SparseFile,
    bitmap: &'a ChunkBitmap,
    chunk_size: u64,
    download_done: &'a Arc<AtomicBool>,
    poll_interval: Duration,
    /// Worker-priority cursor. `read` publishes the new
    /// position here so the scheduler steers fetches around
    /// the chunk that the decoder is about to consume.
    pipeline_cursor: &'a Arc<AtomicU64>,
    /// Optional [`crate::progress::ProgressState`]. The reader
    /// publishes `bytes_decoded_input` on every successful
    /// `read`. Together with the scheduler's `max_disk_buffer`
    /// cap, that bounds `bytes_downloaded - bytes_decoded_input`
    /// to the cap value — i.e., bounds the on-disk-but-not-
    /// extracted footprint to the cap regardless of archive
    /// size.
    progress: Option<&'a Arc<crate::progress::ProgressState>>,
    cursor: u64,
    end: u64,
}

impl<'a> SparseFileSliceReader<'a> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        sparse: &'a SparseFile,
        bitmap: &'a ChunkBitmap,
        chunk_size: u64,
        download_done: &'a Arc<AtomicBool>,
        poll_interval: Duration,
        pipeline_cursor: &'a Arc<AtomicU64>,
        progress: Option<&'a Arc<crate::progress::ProgressState>>,
        start: u64,
        len: u64,
    ) -> Self {
        // Seed both the priority cursor (steering) and the
        // decoded-input counter (cap) at the folder's start.
        // The `bytes_decoded_input` jump matters: between
        // folders, the bytes between this folder's start and
        // the previous folder's end are already-extracted (or
        // skipped on resume), so the lookahead is "downloaded
        // beyond *this* folder's start", not "downloaded total".
        pipeline_cursor.store(start, Ordering::Release);
        if let Some(p) = progress {
            p.set_bytes_decoded_input(start);
        }
        Self {
            sparse,
            bitmap,
            chunk_size,
            download_done,
            poll_interval,
            pipeline_cursor,
            progress,
            cursor: start,
            end: start.saturating_add(len),
        }
    }
}

impl io::Read for SparseFileSliceReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.end.saturating_sub(self.cursor);
        if remaining == 0 || buf.is_empty() {
            return Ok(0);
        }

        // Block until the chunk holding `self.cursor` is durable
        // on disk. Cap each `pread` at the chunk boundary so we
        // never read across a not-yet-complete chunk.
        let chunk_idx_u64 = self.cursor / self.chunk_size.max(1);
        let chunk_idx = u32::try_from(chunk_idx_u64).map_err(|_| {
            io::Error::other(format!(
                "chunk index {chunk_idx_u64} exceeds u32 in SparseFileSliceReader",
            ))
        })?;
        loop {
            if self.bitmap.is_complete(ChunkIndex::new(chunk_idx)) {
                break;
            }
            if self.download_done.load(Ordering::Acquire)
                && !self.bitmap.is_complete(ChunkIndex::new(chunk_idx))
            {
                return Err(io::Error::other(format!(
                    "download finished without delivering chunk {chunk_idx}",
                )));
            }
            std::thread::sleep(self.poll_interval);
        }

        let chunk_end = (chunk_idx_u64 + 1) * self.chunk_size.max(1);
        let chunk_end = chunk_end.min(self.end);
        let max_take = (chunk_end - self.cursor).min(buf.len() as u64) as usize;
        self.sparse
            .read_exact_at(ByteOffset::new(self.cursor), &mut buf[..max_take])
            .map_err(io::Error::other)?;
        self.cursor += max_take as u64;
        // Publish the new decoder position. The priority
        // cursor steers worker dispatch toward the chunk we
        // need next; `bytes_decoded_input` shrinks the
        // lookahead the cap measures, releasing dispatch as
        // the decoder drains chunks.
        self.pipeline_cursor.store(self.cursor, Ordering::Release);
        if let Some(p) = self.progress {
            p.set_bytes_decoded_input(self.cursor);
        }
        Ok(max_take)
    }
}

/// `FolderSink` impl that collects all decoded bytes into a
/// `Vec<u8>`. Used for the EncodedHeader path where the
/// decoded bytes ARE the plain Header to parse next.
#[derive(Default)]
struct HeaderCollectorSink {
    bytes: Vec<u8>,
}

impl crate::decode::sevenz::folder::FolderSink for HeaderCollectorSink {
    fn begin_substream(
        &mut self,
        _idx: u32,
        _file_index: u32,
        expected_size: u64,
    ) -> Result<(), crate::decode::sevenz::folder::FolderSinkError> {
        self.bytes.reserve(expected_size as usize);
        Ok(())
    }

    fn write_substream(
        &mut self,
        buf: &[u8],
    ) -> Result<(), crate::decode::sevenz::folder::FolderSinkError> {
        self.bytes.extend_from_slice(buf);
        Ok(())
    }

    fn end_substream(
        &mut self,
        _expected_crc: Option<u32>,
    ) -> Result<(), crate::decode::sevenz::folder::FolderSinkError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU64;
    use std::time::SystemTime;

    use crate::bitmap::ChunkBitmap;
    use crate::download::sparse_file::SparseFile;
    use crate::punch::NoopPuncher;

    static UNIQ: AtomicU64 = AtomicU64::new(0);

    fn unique_path(label: &str, suffix: &str) -> PathBuf {
        let pid = std::process::id();
        let n = UNIQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "peel_sevenzpipeline_{label}_{pid}_{nanos}_{n}{suffix}",
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

    type ReadySparse = (
        SparseFile,
        Arc<ChunkBitmap>,
        PathBuf,
        Arc<AtomicBool>,
        Arc<Mutex<Option<Result<DownloadStats, SchedulerError>>>>,
    );

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

    /// Encode `value` to the 7z `Number` format. Mirrors the
    /// helper used in the §3 tests.
    fn encode_number(value: u64) -> Vec<u8> {
        if value < (1u64 << 7) {
            return vec![value as u8];
        }
        for size in 2u32..=8 {
            let bits = 7 * size;
            let max = if bits >= 64 {
                u64::MAX
            } else {
                (1u64 << bits) - 1
            };
            if value <= max {
                let leading_ones = size - 1;
                let header_top = ((1u8 << leading_ones) - 1) << (8 - leading_ones);
                let high_value = value >> (8 * (size as u64 - 1));
                let header = header_top | (high_value as u8);
                let mut out = Vec::with_capacity(size as usize);
                out.push(header);
                for i in 0..(size - 1) {
                    out.push((value >> (8 * i)) as u8);
                }
                return out;
            }
        }
        let mut out = Vec::with_capacity(9);
        out.push(0xFF);
        for i in 0..8 {
            out.push((value >> (8 * i)) as u8);
        }
        out
    }

    /// Build a complete 7z archive with one folder, COPY coder,
    /// containing the named files (their concatenated bytes form
    /// the packed stream).
    ///
    /// `files` is a list of `(name, payload)` pairs.
    fn build_copy_sevenz(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
        use crate::decode::sevenz::header::nid;

        // Concatenated packed bytes (all files' raw bytes).
        let pack_bytes: Vec<u8> = files.iter().flat_map(|(_, p)| p.clone()).collect();
        let pack_size = pack_bytes.len() as u64;
        let primary_unpack_size = pack_size;

        // Trailer: Header (0x01) + MainStreamsInfo + FilesInfo + End
        let mut trailer = vec![nid::HEADER];

        // MainStreamsInfo
        trailer.push(nid::MAIN_STREAMS_INFO);
        // PackInfo
        trailer.push(nid::PACK_INFO);
        trailer.extend(encode_number(0)); // pack_pos
        trailer.extend(encode_number(1)); // num_pack_streams
        trailer.push(nid::SIZE);
        trailer.extend(encode_number(pack_size));
        trailer.push(nid::END);

        // UnPackInfo
        trailer.push(nid::UNPACK_INFO);
        trailer.push(nid::FOLDER);
        trailer.extend(encode_number(1)); // NumFolders
        trailer.push(0x00); // External=0
        trailer.extend(encode_number(1)); // NumCoders
        trailer.push(0x01); // flags: idSize=1, simple
        trailer.push(0x00); // codec id COPY
                            // No bind pairs (NumOutStreams - 1 = 0)
                            // No PackedStreamIndices (NumPackedStreams = 1)
        trailer.push(nid::CODERS_UNPACK_SIZE);
        trailer.extend(encode_number(primary_unpack_size));
        trailer.push(nid::END);

        // SubStreamsInfo
        trailer.push(nid::SUBSTREAMS_INFO);
        trailer.push(nid::NUM_UNPACK_STREAM);
        trailer.extend(encode_number(files.len() as u64));
        trailer.push(nid::SIZE);
        // For NumSubstreams - 1 of them, encode the size.
        for (_, payload) in &files[..files.len() - 1] {
            trailer.extend(encode_number(payload.len() as u64));
        }
        // The last is implied = primary_unpack_size - sum of others.
        trailer.push(nid::END);

        // StreamsInfo End
        trailer.push(nid::END);

        // FilesInfo
        trailer.push(nid::FILES_INFO);
        trailer.extend(encode_number(files.len() as u64));
        trailer.push(nid::NAME);
        let mut name_body = vec![0x00u8]; // external = 0
        for (name, _) in files {
            for u in name.encode_utf16() {
                name_body.extend_from_slice(&u.to_le_bytes());
            }
            name_body.extend_from_slice(&[0x00, 0x00]);
        }
        trailer.extend(encode_number(name_body.len() as u64));
        trailer.extend(name_body);
        trailer.push(nid::END);

        // Header End
        trailer.push(nid::END);

        // Build SignatureHeader (32 bytes) + pack data + trailer.
        let trailer_offset = pack_size; // relative to byte 32
        let trailer_len = trailer.len() as u64;
        let trailer_crc = crc32_ieee(&trailer);

        let mut start_header_body = Vec::with_capacity(20);
        start_header_body.extend(trailer_offset.to_le_bytes());
        start_header_body.extend(trailer_len.to_le_bytes());
        start_header_body.extend(trailer_crc.to_le_bytes());
        let start_header_crc = crc32_ieee(&start_header_body);

        let mut archive = Vec::with_capacity(32 + pack_bytes.len() + trailer.len());
        archive.extend_from_slice(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]); // magic
        archive.push(0x00); // ArchiveVersion.major
        archive.push(0x04); // ArchiveVersion.minor
        archive.extend_from_slice(&start_header_crc.to_le_bytes());
        archive.extend(start_header_body);
        archive.extend(pack_bytes);
        archive.extend(trailer);
        archive
    }

    #[test]
    fn pipeline_extracts_two_copy_files_into_directory() {
        let root = unique_dir("two-copy");
        let _g_root = CleanupOnDrop(root.clone());

        let payload_a: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        let payload_b: Vec<u8> = (200..400u32).map(|i| i as u8).collect();
        let archive =
            build_copy_sevenz(&[("a.bin", payload_a.clone()), ("b.bin", payload_b.clone())]);

        let chunk_size: u64 = 64;
        let (sparse, bitmap, sparse_path, done, outcome) = ready_sparse(&archive, chunk_size);
        let _g_sparse = CleanupOnDrop(sparse_path.clone());
        let cursor = Arc::new(AtomicU64::new(0));

        // The pipeline now installs the file list on the sink
        // after parsing the trailer; tests just hand it an
        // empty sink and let `pipeline.run` populate it.
        let mut sink = SevenzSink::new(&root).expect("sink");

        let pipeline = SevenzPipeline {
            config: SevenzPipelineConfig {
                total_size: archive.len() as u64,
                chunk_size,
                poll_interval: Duration::from_millis(1),
            },
            sparse: &sparse,
            bitmap: &bitmap,
            cursor: &cursor,
            download_done: &done,
            download_outcome: &outcome,
            sparse_fd: sparse.as_fd(),
            progress_state: None,
        };
        let puncher = NoopPuncher::new();
        let stats = pipeline
            .run(
                &mut sink,
                &puncher,
                SevenzResumeState::default(),
                |_| Ok(()),
            )
            .expect("runs");
        assert_eq!(stats.folders_extracted, 1);

        let read_a = std::fs::read(root.join("a.bin")).expect("a.bin");
        assert_eq!(read_a, payload_a);
        let read_b = std::fs::read(root.join("b.bin")).expect("b.bin");
        assert_eq!(read_b, payload_b);
        // The sink received the file list from the pipeline.
        assert!(sink.files().is_some());
    }
}
