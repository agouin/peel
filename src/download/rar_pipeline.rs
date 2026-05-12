//! Per-entry extraction driver for RAR5 archives downloaded via
//! the shared sparse-file pipeline.
//!
//! Mirrors the second-pipeline architecture used by ZIP and 7z
//! (`docs/PLAN_v2.md` §5 / `docs/PLAN_7z_support.md` §8 /
//! `docs/PLAN_rar.md` §3) but with RAR5's simpler layout: the
//! archive header is at offset 0 and per-entry data immediately
//! follows each file header. There is no central-directory
//! trailing-fetch dance — we walk forward, header by header, from
//! offset 0 to the end-of-archive marker.
//!
//! Round-one §3 ships STORED-method (`compression method = 0`)
//! extraction. The hand-rolled RAR5 decoder lands in §4 via
//! `docs/PLAN_rar5_decoder.md` and plugs into the same per-entry
//! flow described below.
//!
//! # Workflow
//!
//! 1. Wait for the chunk(s) covering the magic at offset 0 and
//!    validate it ([`crate::rar::format::parse_signature`]).
//! 2. Walk generic headers from offset 8:
//!    - Wait for an estimated header-window's worth of chunks.
//!    - Parse one generic header. On `Truncated` widen the window
//!      and retry until either the header parses or the window
//!      reaches the archive's end.
//!    - Dispatch on the header type:
//!      * **MainArchive** — capture archive-wide flags. Reject
//!        multi-volume.
//!      * **File** — record the entry's metadata for the entry
//!        loop. Reject compression methods other than STORED.
//!      * **Service** — skip past the data area.
//!      * **ArchiveEncryption** — refuse with
//!        [`crate::rar::RarError::UnsupportedFeature`].
//!      * **EndOfArchive** — terminate the walk.
//!    - Advance the cursor past header + data area.
//! 3. For each `File` entry not already in `entries_completed`:
//!    a. Steer the cursor to the entry's data offset.
//!    b. Wait for the chunks covering the entry's data range.
//!    c. Begin (or resume) the entry on the [`crate::sink::RarSink`].
//!    d. Stream the entry's bytes through the sink's
//!    `write_entry` (round-one §3: STORED — pure copy from
//!    sparse file to sink with running BLAKE2sp + CRC-32).
//!    e. End the entry — sink validates hashes against the file
//!    header.
//!    f. Punch the entry's data range.
//!    g. Emit a [`RarPipelineEvent::EntryFinished`] so the
//!    coordinator can write a checkpoint.
//! 4. After the last entry, punch the trailing region (header +
//!    end-of-archive bytes the entries didn't cover).

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
use crate::decode::rar_legacy::RarLegacyStreamDecoder;
use crate::decode::rar_native::dict::MAX_DICT_BYTES;
use crate::decode::rar_native::RarStreamDecoder;
use crate::decode::{DecodeError, DecodeStatus, StreamingDecoder};
use crate::download::scheduler::{DownloadStats, SchedulerError};
use crate::download::sparse_file::{SparseFile, SparseFileError};
use crate::encryption::EncryptionError;
use crate::punch::{align_down, align_up, PunchError, PunchHole};
use crate::rar::archive::FileEntry;
use crate::rar::encrypt::ArchiveEncryptionHeader;
use crate::rar::format::{
    parse_end_of_archive_header, parse_file_header, parse_generic_header,
    parse_main_archive_header, HeaderType,
};
use crate::rar::legacy::format::{
    parse_endarc_header as parse_legacy_endarc_header,
    parse_file_header as parse_legacy_file_header,
    parse_generic_header as parse_legacy_generic_header,
    parse_main_archive_header as parse_legacy_main_archive_header, BlockType,
};
use crate::rar::{
    detect_signature, RarError, SignatureKind, LEGACY_SIGNATURE_MAGIC, SIGNATURE_MAGIC,
};
use crate::sink::rar::{BeginEntryOutcome, EntryFinalize, RarSink};
use crate::sink::SinkError;
use crate::types::{ByteOffset, ChunkIndex};

/// Configuration for a [`RarPipeline::run`] invocation.
#[derive(Debug, Clone)]
pub struct RarPipelineConfig {
    /// Total source size in bytes. The pipeline never reads past
    /// this offset.
    pub total_size: u64,
    /// Chunk size the scheduler is using to slice the source.
    pub chunk_size: u64,
    /// Sleep between bitmap polls when waiting for a chunk to
    /// land. Tests use a small value (1–5 ms); production uses the
    /// coordinator default.
    pub poll_interval: Duration,
    /// Initial header-window size. The pipeline doubles this as
    /// needed when a header's `Truncated` parser surfaces a
    /// "needed N more bytes" hint. Defaults to 64 KiB which is
    /// large enough for the common case (RAR5 file headers tend
    /// to be a few hundred bytes including the file name).
    pub initial_header_window: u64,
}

impl Default for RarPipelineConfig {
    fn default() -> Self {
        Self {
            total_size: 0,
            chunk_size: 0,
            poll_interval: Duration::from_millis(5),
            initial_header_window: 64 * 1024,
        }
    }
}

/// Resume state forwarded from a prior checkpoint, mirroring
/// [`crate::checkpoint::SinkState::Rar`].
#[derive(Debug, Clone, Default)]
pub struct RarResumeState {
    /// Indices of entries already extracted to disk before the
    /// prior run crashed.
    pub entries_completed: Vec<u32>,
    /// Index of the entry that was in flight when the checkpoint
    /// was written, if any.
    pub current_entry: Option<u32>,
    /// Bytes already written into the in-flight entry.
    pub current_entry_offset: u64,
    /// Opaque [`crate::decode::rar_native::RarStreamDecoder`]
    /// snapshot for compressed (`method >= 1`) entries
    /// (`PLAN_rar5_decoder.md` §F1). `None` for STORED entries
    /// or for v10-and-earlier checkpoints — the pipeline falls
    /// back to "restart entry from byte 0" in that case.
    pub current_entry_decoder_state: Option<Vec<u8>>,
}

/// Diagnostic events the pipeline emits during a run.
///
/// The coordinator's progress callback uses these to throttle the
/// checkpoint cadence (same shape as [`ZipPipelineEvent`]).
#[derive(Debug, Clone)]
pub enum RarPipelineEvent {
    /// The archive header walk finished; entry extraction is
    /// about to start.
    Started {
        /// Total file-header entries the walk discovered (after
        /// service / encryption / end-of-archive headers were
        /// filtered).
        entry_count: u32,
        /// Indices of entries the resume state already had marked
        /// complete (extraction will skip them).
        already_complete: Vec<u32>,
        /// Whether the main archive header carried `MHD_SOLID`.
        /// Round-one §3 supports STORED entries only, so the flag
        /// is informational; §4 will switch to single-stream
        /// sequential decode when set.
        solid: bool,
    },
    /// One STORED entry just had bytes flowed into it. Emitted
    /// on a mid-entry boundary so the coordinator can capture
    /// `current_entry_offset` for resume.
    InEntryProgress {
        /// Entry's index in archive order.
        index: u32,
        /// Bytes written so far into the in-flight entry.
        bytes_written: u64,
    },
    /// One compressed entry (`compression.method() >= 1`) just
    /// had bytes flowed into it. Emitted on a mid-entry boundary
    /// so the coordinator can capture `current_entry_offset`
    /// **and** the [`crate::decode::rar_native::RarStreamDecoder`]
    /// snapshot needed to resume byte-identically. Distinct from
    /// [`Self::InEntryProgress`] so the STORED event shape stays
    /// stable across the §F1 transition (its serialized
    /// representation is monitored by tight timing-sensitive
    /// crash-resume tests).
    InEntryProgressCompressed {
        /// Entry's index in archive order.
        index: u32,
        /// Bytes written so far into the in-flight entry.
        bytes_written: u64,
        /// Opaque snapshot of the in-flight RAR5 decoder
        /// (`PLAN_rar5_decoder.md` §F1). `None` when the
        /// decoder has not yet reached a snapshotable boundary
        /// inside the entry; otherwise `Some(blob)` carries the
        /// `RarStreamDecoder::decoder_state_into` output the
        /// coordinator persists into the checkpoint's
        /// `current_entry_decoder_state` field.
        decoder_state: Option<Vec<u8>>,
    },
    /// One entry just finished extracting cleanly.
    EntryFinished {
        /// Entry's index in archive order.
        index: u32,
        /// Entry's filename (as recorded in the file header).
        name: String,
        /// Uncompressed bytes written for this entry.
        bytes_written: u64,
        /// Source byte range the pipeline punched after this
        /// entry's data area.
        bytes_punched: u64,
    },
}

/// Failure modes for [`RarPipeline::run`].
#[derive(Debug, Error)]
pub enum RarPipelineError {
    /// A RAR wire-format failure surfaced. Wraps any [`RarError`]
    /// variant; unsupported features carry the same message the
    /// user-facing CLI prints.
    #[error("RAR format error")]
    Rar(#[source] RarError),

    /// The sink rejected an operation outside the decode loop
    /// (begin / end of an entry, mkdir of a directory entry,
    /// close).
    #[error("RAR sink failed")]
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

    /// The caller's progress callback returned an error (the
    /// kill-switch path uses this to abort cleanly).
    #[error("pipeline aborted by progress callback")]
    Aborted(#[source] io::Error),
}

/// Aggregate stats the pipeline returns on a clean run.
#[derive(Debug, Default, Clone)]
pub struct RarExtractionStats {
    /// Number of entries extracted (i.e. file-header count minus
    /// the resume-skipped ones).
    pub entries_extracted: u32,
    /// Total uncompressed bytes written across all entries this
    /// run.
    pub bytes_written: u64,
    /// Total source bytes punched (per-entry data ranges + the
    /// trailing region).
    pub bytes_punched: u64,
}

/// Per-entry record the legacy walker hands to the legacy
/// extractor. Distinct from [`crate::rar::archive::FileEntry`] (the
/// RAR5 walker's record) because the legacy file header carries a
/// different field set: CRC-32 is unconditionally present (no
/// `Option<u32>`), there is no BLAKE2sp slot, and the
/// dictionary-size / compression-info vint shape is RAR5-only.
#[derive(Debug, Clone)]
struct LegacyEntryRecord {
    /// Entry name decoded from the legacy file header (UTF-8, with
    /// `LHD_UNICODE` UCS-2 forms already converted).
    name: String,
    /// `true` for directory marker entries (`LHD_WINDOW` field set
    /// to 0xE0). Their data area is always zero bytes.
    is_directory: bool,
    /// Decompressed size in bytes (legacy `unp_size` low + optional
    /// high32 when `LHD_LARGE`).
    unpacked_size: u64,
    /// Wire-format CRC-32 IEEE of the unpacked payload. Always
    /// present in legacy file headers — the sink validates it on
    /// `end_entry`.
    expected_crc32: u32,
    /// Byte offset of the entry's compressed data within the
    /// archive (the offset of the first byte of the data area
    /// following the file header).
    data_offset: u64,
    /// Compressed-data length in bytes (legacy `pack_size` low +
    /// optional high32 when `LHD_LARGE`). For STORED entries this
    /// equals [`Self::unpacked_size`].
    packed_size: u64,
    /// Compression-method byte from the file header
    /// (`0x30..=0x35`). `0x30` is STORED — the §A2b fast-path
    /// extractor handles those; `0x31..=0x35` route through the
    /// [`RarLegacyStreamDecoder`] (§E1).
    method: u8,
    /// Per-entry LZ sliding-window capacity, derived from the
    /// file header's `LHD_WINDOW` selector. Zero for STORED
    /// directory markers (where the selector reads as `0b111`);
    /// the directory branch never consults this field.
    dict_capacity: usize,
}

/// Per-entry extraction driver.
pub struct RarPipeline<'a> {
    /// Configuration knobs.
    pub config: RarPipelineConfig,
    /// Sparse file the workers are filling.
    pub sparse: &'a SparseFile,
    /// Bitmap recording which chunks are durable on disk.
    pub bitmap: &'a ChunkBitmap,
    /// Steering cursor the scheduler reads. The pipeline writes
    /// "byte offset I'm waiting for" here so worker priority
    /// follows the extraction order.
    pub cursor: &'a Arc<AtomicU64>,
    /// `true` when the download thread has exited (success or
    /// failure). Reading this lets us surface a scheduler failure
    /// as [`RarPipelineError::DownloadFinishedEarly`] rather than
    /// a hang.
    pub download_done: &'a Arc<AtomicBool>,
    /// Optional scheduler outcome stashed by the download thread.
    pub download_outcome: &'a Arc<Mutex<Option<Result<DownloadStats, SchedulerError>>>>,
    /// Borrowed file descriptor for hole punching. The pipeline
    /// itself does not write to the sparse file; the workers do.
    pub sparse_fd: BorrowedFd<'a>,
    /// Shared progress state (`bytes_decoded_input` is published
    /// per-pread so the scheduler's `max_disk_buffer` throttle
    /// can bound the on-disk-but-not-yet-extracted footprint).
    /// `None` is supported for tests but is never the production
    /// path.
    pub progress_state: Option<&'a Arc<crate::progress::ProgressState>>,
}

impl<'a> RarPipeline<'a> {
    /// Drive the extraction.
    ///
    /// `sink` is opened by the caller; resume is reflected via
    /// `resume.current_entry` / `resume.current_entry_offset`.
    /// `puncher` is the coordinator-supplied [`PunchHole`].
    /// `callback` fires for each meaningful state change.
    ///
    /// # Errors
    ///
    /// See [`RarPipelineError`].
    pub fn run<F>(
        &self,
        sink: &mut RarSink,
        puncher: &dyn PunchHole,
        resume: RarResumeState,
        mut callback: F,
    ) -> Result<RarExtractionStats, RarPipelineError>
    where
        F: FnMut(&RarPipelineEvent) -> io::Result<()>,
    {
        let mut stats = RarExtractionStats::default();

        // Step 1: wait for the magic and dispatch on the format.
        // The RAR5 magic is 8 bytes; the legacy (RAR3 / RAR4) magic
        // is 7. We fetch the longer of the two so a single read
        // serves both branches (`detect_signature` reads only what
        // it needs and ignores any trailing byte for the legacy
        // case).
        self.cursor.store(0, Ordering::Release);
        if let Some(p) = self.progress_state {
            p.set_bytes_decoded_input(0);
        }
        self.wait_for_range(0, SIGNATURE_MAGIC.len() as u64)?;
        let mut sig_buf = [0u8; SIGNATURE_MAGIC.len()];
        self.sparse
            .read_exact_at(ByteOffset::new(0), &mut sig_buf)
            .map_err(RarPipelineError::Sparse)?;
        let (kind, sig_len) = detect_signature(&sig_buf).map_err(RarPipelineError::Rar)?;
        let sig_size = sig_len as u64;
        if matches!(kind, SignatureKind::Legacy) {
            // Hand off to the legacy walker. `docs/PLAN_rar3.md`
            // §A2b: round-one supports STORED-method (`m=0`) legacy
            // entries end-to-end; `m≥1` surfaces a precise
            // `UnsupportedFeature` naming the version + method, and
            // the decoder generations land in §B / §C.
            return self.run_legacy(sig_size, sink, puncher, resume, stats, callback);
        }
        debug_assert_eq!(sig_size, SIGNATURE_MAGIC.len() as u64);
        // Suppress dead_code on the legacy magic re-export when it
        // is reached only via the dispatcher above (the import
        // makes the symbol available for future inline checks).
        let _ = LEGACY_SIGNATURE_MAGIC;

        // Step 2: walk headers from offset `sig_size`. Capture
        // the main archive header's flags and the per-file
        // entries; reject the round-one out-of-scope features.
        let mut cursor: u64 = sig_size;
        let mut entries: Vec<FileEntry> = Vec::new();
        let mut solid = false;
        let mut saw_main = false;
        loop {
            if cursor >= self.config.total_size {
                return Err(RarPipelineError::Rar(RarError::CorruptHeader {
                    archive_offset: cursor,
                    reason: "archive ends before end-of-archive marker".to_string(),
                }));
            }
            let (header_buf, header_buf_start) = self.read_header_window(cursor)?;
            let header =
                parse_generic_header(&header_buf[(cursor - header_buf_start) as usize..], cursor)
                    .map_err(RarPipelineError::Rar)?;
            // Re-slice so per-header parsers see byte 0 = start of
            // their own header.
            let local_buf = &header_buf[(cursor - header_buf_start) as usize..];
            match header.header_type {
                HeaderType::MainArchive => {
                    if saw_main {
                        return Err(RarPipelineError::Rar(RarError::CorruptHeader {
                            archive_offset: header.archive_offset,
                            reason: "second main archive header encountered".to_string(),
                        }));
                    }
                    saw_main = true;
                    let main = parse_main_archive_header(&header, local_buf)
                        .map_err(RarPipelineError::Rar)?;
                    if main.archive_flags.is_volume() {
                        let label = match main.volume_number {
                            Some(n) => format!("multi-volume archive (volume {n})"),
                            None => "multi-volume archive".to_string(),
                        };
                        return Err(RarPipelineError::Rar(RarError::UnsupportedFeature {
                            feature: label,
                        }));
                    }
                    solid = main.archive_flags.is_solid();
                }
                HeaderType::File => {
                    let file =
                        parse_file_header(&header, local_buf).map_err(RarPipelineError::Rar)?;
                    let method = file.compression.method();
                    if method > 5 {
                        // 6 / 7 are reserved by the format spec; rejecting
                        // here surfaces a precise diagnostic rather than
                        // letting the decoder failure mode leak.
                        return Err(RarPipelineError::Rar(RarError::UnsupportedFeature {
                            feature: format!(
                                "compression method {method} (reserved by \
                                 RAR5 spec for future use)"
                            ),
                        }));
                    }
                    let packed_size = header.data_size.unwrap_or(0);
                    let data_offset = cursor + header.total_header_bytes as u64;
                    entries.push(FileEntry {
                        header: file,
                        data_offset,
                        packed_size,
                    });
                }
                HeaderType::Service => {
                    // Skip past header + data area.
                }
                HeaderType::ArchiveEncryption => {
                    // Parse the encryption header for diagnostic
                    // detail, then surface the unified
                    // [`EncryptionError`]. The encryption header
                    // parser validates the spec-defined fields
                    // (version, kdf_count cap, salt length); a
                    // malformed header surfaces a RarError variant
                    // before the user even sees the encryption
                    // refusal, which is more useful.
                    // Full archive-header decryption support is
                    // tracked in `docs/PLAN_archive_encryption.md` §4
                    // — the encryption primitives module
                    // [`crate::rar::encrypt`] lands the parsers + KDF
                    // groundwork; the walker-side header-stream
                    // wrapping is invasive enough that it stays in a
                    // follow-on commit.
                    let fields = &local_buf[header.fields_offset_in_input
                        ..header.fields_offset_in_input + header.fields_size];
                    let _enc = ArchiveEncryptionHeader::parse(fields)
                        .map_err(RarError::from)
                        .map_err(RarPipelineError::Rar)?;
                    return Err(RarPipelineError::Rar(RarError::Encryption(
                        EncryptionError::UnsupportedCipher {
                            detail: "archive-header encryption (RAR5 AES-256-CBC, encryption \
                                     header type 4) — peel parses the encryption header but \
                                     does not yet decrypt the subsequent header stream"
                                .to_string(),
                        },
                    )));
                }
                HeaderType::EndOfArchive => {
                    let _eof = parse_end_of_archive_header(&header, local_buf)
                        .map_err(RarPipelineError::Rar)?;
                    cursor = cursor.saturating_add(header.total_bytes_with_data());
                    break;
                }
                HeaderType::Other(code) => {
                    if header.header_flags & crate::rar::format::hdr_flags::SKIP_IF_UNKNOWN == 0 {
                        return Err(RarPipelineError::Rar(RarError::UnsupportedFeature {
                            feature: format!(
                                "unknown RAR header type {code} without \
                                 SKIP_IF_UNKNOWN flag"
                            ),
                        }));
                    }
                }
            }
            cursor = cursor.saturating_add(header.total_bytes_with_data());
        }
        let trailer_end = cursor;

        let entry_count = u32::try_from(entries.len()).map_err(|_| {
            RarPipelineError::Rar(RarError::CorruptHeader {
                archive_offset: 0,
                reason: "archive has more than u32::MAX entries".to_string(),
            })
        })?;

        let already_complete: Vec<u32> = resume.entries_completed.to_vec();
        callback(&RarPipelineEvent::Started {
            entry_count,
            already_complete: already_complete.clone(),
            solid,
        })
        .map_err(RarPipelineError::Aborted)?;

        // Step 3: per-entry extraction in archive order.
        let completed_set: HashSet<u32> = resume.entries_completed.iter().copied().collect();
        for (idx, entry) in entries.iter().enumerate() {
            let idx = idx as u32;
            if completed_set.contains(&idx) {
                continue;
            }
            let resume_offset = if Some(idx) == resume.current_entry {
                resume.current_entry_offset
            } else {
                0
            };
            // §F1 dispatch: a compressed entry whose checkpoint
            // carried a saved [`RarStreamDecoder`] snapshot
            // routes through the dedicated resume helper. Every
            // other case (STORED, fresh-start compressed,
            // legacy-checkpoint compressed) goes through the
            // unchanged [`Self::extract_entry`] so the STORED
            // hot path's calling convention stays byte-identical
            // to round-one §3 (a tight crash-resume test is
            // sensitive to its event timing).
            let resume_blob: Option<&[u8]> =
                if Some(idx) == resume.current_entry && entry.header.compression.method() != 0 {
                    resume.current_entry_decoder_state.as_deref()
                } else {
                    None
                };
            let (bytes_written, bytes_punched) = match resume_blob {
                Some(blob) => self.extract_compressed_entry_with_resume(
                    idx,
                    entry,
                    resume_offset,
                    blob,
                    sink,
                    puncher,
                    &mut callback,
                )?,
                None => {
                    self.extract_entry(idx, entry, resume_offset, sink, puncher, &mut callback)?
                }
            };
            stats.entries_extracted = stats.entries_extracted.saturating_add(1);
            stats.bytes_written = stats.bytes_written.saturating_add(bytes_written);
            stats.bytes_punched = stats.bytes_punched.saturating_add(bytes_punched);
        }

        // Step 4: punch the trailing region (the bytes after the
        // last entry's data area through end-of-archive). Same
        // best-effort discipline as `zip_pipeline::punch_range`:
        // partial blocks at either edge are skipped via inward
        // alignment.
        if trailer_end < self.config.total_size {
            let punched = self.punch_range(puncher, trailer_end, self.config.total_size)?;
            stats.bytes_punched = stats.bytes_punched.saturating_add(punched);
        }
        // Also punch the leading region (signature + main + service
        // headers) — they're tiny but punching them costs nothing.
        if let Some(first_entry) = entries.first() {
            if first_entry.data_offset > 0 {
                let punched = self.punch_range(puncher, 0, first_entry.data_offset)?;
                stats.bytes_punched = stats.bytes_punched.saturating_add(punched);
            }
        } else if trailer_end > 0 {
            // No entries; punch the whole archive (header + EOA).
            let punched = self.punch_range(puncher, 0, trailer_end)?;
            stats.bytes_punched = stats.bytes_punched.saturating_add(punched);
        }

        Ok(stats)
    }

    fn extract_entry<F>(
        &self,
        idx: u32,
        entry: &FileEntry,
        resume_offset: u64,
        sink: &mut RarSink,
        puncher: &dyn PunchHole,
        callback: &mut F,
    ) -> Result<(u64, u64), RarPipelineError>
    where
        F: FnMut(&RarPipelineEvent) -> io::Result<()>,
    {
        let data_offset = entry.data_offset;
        let packed_size = entry.packed_size;
        let data_end = data_offset.checked_add(packed_size).ok_or_else(|| {
            RarPipelineError::Rar(RarError::CorruptHeader {
                archive_offset: data_offset,
                reason: "entry data range overflows u64".to_string(),
            })
        })?;

        // Steer the scheduler toward this entry's range.
        self.cursor.store(data_offset, Ordering::Release);
        if let Some(p) = self.progress_state {
            p.set_bytes_decoded_input(data_offset);
        }
        self.wait_for_range(data_offset, data_end)?;

        // STORED entries always resume from the byte-offset alone
        // (the sink's prefix-replay seeds the running hashes, and
        // there's no decoder state to migrate). Compressed
        // entries always restart from byte 0 in this code path —
        // the §F1 decoder-state-aware dispatch lives in
        // [`Self::extract_compressed_entry_with_resume`] and is
        // selected by `run` ahead of `extract_entry` for `method
        // != 0` entries with a saved decoder-state blob.
        let method = entry.header.compression.method();
        let effective_resume_offset = if method == 0 { resume_offset } else { 0 };

        let begin_outcome = if effective_resume_offset > 0 {
            sink.begin_entry_resume(
                idx,
                &entry.header.name,
                entry.header.file_flags.is_directory(),
                entry.header.unpacked_size,
                entry.header.crc32,
                None, // BLAKE2sp from extra-record subtypes lands in a follow-on
                effective_resume_offset,
            )
        } else {
            sink.begin_entry(
                idx,
                &entry.header.name,
                entry.header.file_flags.is_directory(),
                entry.header.unpacked_size,
                entry.header.crc32,
                None,
            )
        }
        .map_err(RarPipelineError::Sink)?;

        if matches!(begin_outcome, BeginEntryOutcome::Directory { .. }) {
            // Directory entry: data area is zero bytes (RAR5 directories
            // don't carry payload). Verified at parse time. Punch
            // anything that managed to reserve space (defensive — usually
            // packed_size == 0).
            let punched = if packed_size > 0 {
                self.punch_range(puncher, data_offset, data_end)?
            } else {
                0
            };
            callback(&RarPipelineEvent::EntryFinished {
                index: idx,
                name: entry.header.name.clone(),
                bytes_written: 0,
                bytes_punched: punched,
            })
            .map_err(RarPipelineError::Aborted)?;
            return Ok((0, punched));
        }

        if method == 0 {
            // Stream the entry's data bytes from the sparse file
            // into the sink. STORED is a passthrough so
            // packed_size == unpacked_size; we copy directly.
            // Resume picks up at the sink's `resume_offset` without
            // re-reading the prefix from the source — the sink
            // already replayed the on-disk file to seed its hashes.
            let copy_start = data_offset.saturating_add(effective_resume_offset);
            let mut cursor_in_entry = copy_start;
            let mut buf = vec![0u8; 64 * 1024];
            while cursor_in_entry < data_end {
                let want = (data_end - cursor_in_entry).min(buf.len() as u64) as usize;
                self.sparse
                    .read_exact_at(ByteOffset::new(cursor_in_entry), &mut buf[..want])
                    .map_err(RarPipelineError::Sparse)?;
                sink.write_entry(&buf[..want])
                    .map_err(RarPipelineError::Sink)?;
                cursor_in_entry = cursor_in_entry.saturating_add(want as u64);
                if let Some(p) = self.progress_state {
                    p.set_bytes_decoded_input(cursor_in_entry);
                }
                callback(&RarPipelineEvent::InEntryProgress {
                    index: idx,
                    bytes_written: sink.current_entry_offset(),
                })
                .map_err(RarPipelineError::Aborted)?;
            }
        } else {
            self.decompress_entry_to_sink(
                idx,
                entry,
                data_offset,
                data_end,
                0,    // no §F1 mid-entry resume on this path
                None, // §F1 dispatch lives in `extract_compressed_entry_with_resume`
                sink,
                callback,
            )?;
        }

        let _finalize: EntryFinalize = sink.end_entry().map_err(RarPipelineError::Sink)?;

        let punched = self.punch_range(puncher, data_offset, data_end)?;
        callback(&RarPipelineEvent::EntryFinished {
            index: idx,
            name: entry.header.name.clone(),
            bytes_written: entry.header.unpacked_size,
            bytes_punched: punched,
        })
        .map_err(RarPipelineError::Aborted)?;

        Ok((entry.header.unpacked_size, punched))
    }

    /// §F1 mid-entry-resume dispatch for compressed entries.
    /// Mirrors the structure of [`Self::extract_entry`] but uses
    /// [`RarSink::begin_entry_resume`] to seed the running hashes
    /// from the on-disk prefix and seeds the
    /// [`RarStreamDecoder`] from the saved snapshot. STORED
    /// entries never reach this path — `run` dispatches them
    /// through the unmodified [`Self::extract_entry`] so the
    /// crash-resume test's tight event timing stays unchanged.
    #[allow(clippy::too_many_arguments)]
    fn extract_compressed_entry_with_resume<F>(
        &self,
        idx: u32,
        entry: &FileEntry,
        resume_offset: u64,
        resume_decoder_state: &[u8],
        sink: &mut RarSink,
        puncher: &dyn PunchHole,
        callback: &mut F,
    ) -> Result<(u64, u64), RarPipelineError>
    where
        F: FnMut(&RarPipelineEvent) -> io::Result<()>,
    {
        let data_offset = entry.data_offset;
        let packed_size = entry.packed_size;
        let data_end = data_offset.checked_add(packed_size).ok_or_else(|| {
            RarPipelineError::Rar(RarError::CorruptHeader {
                archive_offset: data_offset,
                reason: "entry data range overflows u64".to_string(),
            })
        })?;

        self.cursor.store(data_offset, Ordering::Release);
        if let Some(p) = self.progress_state {
            p.set_bytes_decoded_input(data_offset);
        }
        self.wait_for_range(data_offset, data_end)?;

        let begin_outcome = sink
            .begin_entry_resume(
                idx,
                &entry.header.name,
                entry.header.file_flags.is_directory(),
                entry.header.unpacked_size,
                entry.header.crc32,
                None,
                resume_offset,
            )
            .map_err(RarPipelineError::Sink)?;

        if matches!(begin_outcome, BeginEntryOutcome::Directory { .. }) {
            // A directory-flagged entry with a decoder-state blob
            // is a malformed checkpoint, but we treat it the same
            // way the non-resume path does (mkdir + 0-byte data
            // area) so the resumed extraction can still complete.
            let punched = if packed_size > 0 {
                self.punch_range(puncher, data_offset, data_end)?
            } else {
                0
            };
            callback(&RarPipelineEvent::EntryFinished {
                index: idx,
                name: entry.header.name.clone(),
                bytes_written: 0,
                bytes_punched: punched,
            })
            .map_err(RarPipelineError::Aborted)?;
            return Ok((0, punched));
        }

        self.decompress_entry_to_sink(
            idx,
            entry,
            data_offset,
            data_end,
            resume_offset,
            Some(resume_decoder_state),
            sink,
            callback,
        )?;

        let _finalize: EntryFinalize = sink.end_entry().map_err(RarPipelineError::Sink)?;

        let punched = self.punch_range(puncher, data_offset, data_end)?;
        callback(&RarPipelineEvent::EntryFinished {
            index: idx,
            name: entry.header.name.clone(),
            bytes_written: entry.header.unpacked_size,
            bytes_punched: punched,
        })
        .map_err(RarPipelineError::Aborted)?;

        Ok((entry.header.unpacked_size, punched))
    }

    /// Standard-RAR5 (`compression.method() >= 1`) dispatch: build
    /// a [`RarStreamDecoder`] over the entry's compressed bytes
    /// and drive it until clean EOF. Decoded bytes flow through a
    /// staging buffer into the sink so the in-flight resume
    /// bookkeeping (`current_entry_offset`) stays the
    /// post-decompression byte count the §3 sink was built for.
    ///
    /// Round-one §E1 buffers the entry's full compressed
    /// `packed_size` into memory before constructing the decoder
    /// (mirrors the zip / 7z pipelines' compressed-entry path).
    /// The cost is bounded by the file header's `packed_size`;
    /// `O.RAR.STREAMING_DECOMPRESS` will lift this to a
    /// chunk-by-chunk reader once the decoder has stabilised
    /// against a real corpus.
    ///
    /// Round-one §F1 wires resume: `resume_offset > 0` means the
    /// sink already replayed the on-disk prefix to seed its hashes
    /// and the decoder must come up at the same LZSS-output
    /// position — the matching `resume_decoder_state` blob carries
    /// the dictionary + Huffman + filter-queue state needed to
    /// produce byte-identical output from the source-byte cursor
    /// `resume_decoder_state` was captured at.
    #[allow(clippy::too_many_arguments)]
    fn decompress_entry_to_sink<F>(
        &self,
        idx: u32,
        entry: &FileEntry,
        data_offset: u64,
        data_end: u64,
        resume_offset: u64,
        resume_decoder_state: Option<&[u8]>,
        sink: &mut RarSink,
        callback: &mut F,
    ) -> Result<(), RarPipelineError>
    where
        F: FnMut(&RarPipelineEvent) -> io::Result<()>,
    {
        let packed_size = data_end.saturating_sub(data_offset);
        let mut compressed = vec![
            0u8;
            usize::try_from(packed_size).map_err(|_| {
                RarPipelineError::Rar(RarError::CorruptHeader {
                    archive_offset: data_offset,
                    reason: format!("packed_size {packed_size} exceeds usize on this platform"),
                })
            })?
        ];
        if !compressed.is_empty() {
            self.sparse
                .read_exact_at(ByteOffset::new(data_offset), &mut compressed)
                .map_err(RarPipelineError::Sparse)?;
        }

        let dict_capacity = dict_capacity_for(&entry.header.compression).map_err(|e| {
            RarPipelineError::Rar(RarError::UnsupportedFeature {
                feature: format!("RAR5 dictionary size: {e}"),
            })
        })?;

        let mut decoder = if let Some(blob) = resume_decoder_state {
            // §F1 resume: the blob captured the source-byte cursor
            // it was taken at. We slice the in-memory compressed
            // bytes from that cursor so the decoder's source picks
            // up exactly where the prior run paused.
            let cursor =
                RarStreamDecoder::source_cursor_from_blob(blob).map_err(decode_err_to_rar)?;
            if cursor > packed_size {
                return Err(RarPipelineError::Rar(RarError::CorruptHeader {
                    archive_offset: data_offset,
                    reason: format!(
                        "RAR5 resume blob source cursor {cursor} exceeds packed_size {packed_size}"
                    ),
                }));
            }
            let cursor_usz = cursor as usize;
            let tail = compressed.split_off(cursor_usz);
            let src: Box<dyn std::io::Read + Send> = Box::new(std::io::Cursor::new(tail));
            RarStreamDecoder::resume(src, dict_capacity, blob).map_err(decode_err_to_rar)?
        } else {
            // Fresh-or-restart-from-zero: the §E1 path. The sink
            // is at byte 0 (the caller forced `effective_resume_offset
            // = 0` when no blob is available), so the LZSS layer
            // also starts from a clean slate.
            debug_assert_eq!(resume_offset, 0);
            let src: Box<dyn std::io::Read + Send> = Box::new(std::io::Cursor::new(compressed));
            RarStreamDecoder::new(src, dict_capacity).map_err(decode_err_to_rar)?
        };

        let mut staging: Vec<u8> = Vec::with_capacity(64 * 1024);
        loop {
            let status = decoder
                .decode_step(&mut staging)
                .map_err(decode_err_to_rar)?;
            if !staging.is_empty() {
                sink.write_entry(&staging).map_err(RarPipelineError::Sink)?;
                staging.clear();
                let blob = decoder.decoder_state();
                callback(&RarPipelineEvent::InEntryProgressCompressed {
                    index: idx,
                    bytes_written: sink.current_entry_offset(),
                    decoder_state: blob,
                })
                .map_err(RarPipelineError::Aborted)?;
            }
            if matches!(status, DecodeStatus::Eof) {
                break;
            }
        }
        // Decoder consumed every compressed byte; nudge the
        // progress meter so the scheduler's max_disk_buffer
        // throttle treats the entry's source range as released.
        if let Some(p) = self.progress_state {
            p.set_bytes_decoded_input(data_end);
        }
        Ok(())
    }

    /// Drive the extraction of a legacy (RAR3 / RAR4) archive.
    ///
    /// Mirrors [`Self::run`] in shape but uses the legacy header
    /// parsers from [`crate::rar::legacy::format`]. Round-one
    /// (`docs/PLAN_rar3.md` §A2b) supports STORED-method (`m=0`,
    /// wire byte `0x30`) entries end-to-end; compressed methods
    /// surface a precise [`RarError::UnsupportedFeature`] naming
    /// the version + method byte and the decoder lands in
    /// §B / §C.
    ///
    /// The signature has already been validated by the caller;
    /// `sig_size` is the number of bytes the magic occupied
    /// (`7` for the legacy format).
    fn run_legacy<F>(
        &self,
        sig_size: u64,
        sink: &mut RarSink,
        puncher: &dyn PunchHole,
        resume: RarResumeState,
        mut stats: RarExtractionStats,
        mut callback: F,
    ) -> Result<RarExtractionStats, RarPipelineError>
    where
        F: FnMut(&RarPipelineEvent) -> io::Result<()>,
    {
        let mut cursor: u64 = sig_size;
        let mut entries: Vec<LegacyEntryRecord> = Vec::new();
        let mut solid = false;
        let mut saw_main = false;
        loop {
            if cursor >= self.config.total_size {
                return Err(RarPipelineError::Rar(RarError::CorruptHeader {
                    archive_offset: cursor,
                    reason: "legacy archive ends before ENDARC_HEAD".to_string(),
                }));
            }
            let (header_buf, header_buf_start) = self.read_legacy_header_window(cursor)?;
            let local_buf = &header_buf[(cursor - header_buf_start) as usize..];
            let block =
                parse_legacy_generic_header(local_buf, cursor).map_err(RarPipelineError::Rar)?;
            match block.block_type {
                BlockType::Mark => {
                    return Err(RarPipelineError::Rar(RarError::CorruptHeader {
                        archive_offset: block.archive_offset,
                        reason: "MARK_HEAD encountered after the leading signature".to_string(),
                    }));
                }
                BlockType::Main => {
                    if saw_main {
                        return Err(RarPipelineError::Rar(RarError::CorruptHeader {
                            archive_offset: block.archive_offset,
                            reason: "second MAIN_HEAD encountered".to_string(),
                        }));
                    }
                    saw_main = true;
                    let main = parse_legacy_main_archive_header(&block, local_buf)
                        .map_err(RarPipelineError::Rar)?;
                    solid = main.archive_flags.is_solid();
                }
                BlockType::File => {
                    if !saw_main {
                        return Err(RarPipelineError::Rar(RarError::CorruptHeader {
                            archive_offset: block.archive_offset,
                            reason: "FILE_HEAD encountered before MAIN_HEAD".to_string(),
                        }));
                    }
                    let file = parse_legacy_file_header(&block, local_buf)
                        .map_err(RarPipelineError::Rar)?;
                    // Round-one §A2b shipped STORED only; §E1 wires
                    // the §B/§C decoder behind a streaming adapter
                    // ([`RarLegacyStreamDecoder`]) so compressed
                    // entries (m=1..=5, on-disk method bytes
                    // 0x31..=0x35) now extract end-to-end. Method
                    // bytes outside the supported 0x30..=0x35 range
                    // still surface a precise diagnostic.
                    const LEGACY_METHOD_STORED: u8 = 0x30;
                    if !(0x30..=0x35).contains(&file.method) {
                        return Err(RarPipelineError::Rar(RarError::UnsupportedFeature {
                            feature: format!(
                                "legacy RAR compression method 0x{:02x} (m={}, unp_ver={}.{}); \
                                 only m=0..=5 (wire bytes 0x30..=0x35) are supported",
                                file.method,
                                file.method.wrapping_sub(LEGACY_METHOD_STORED),
                                file.unp_ver / 10,
                                file.unp_ver % 10,
                            ),
                        }));
                    }
                    let data_offset = cursor + u64::from(block.head_size);
                    let packed_size = u64::from(block.add_size.unwrap_or(0));
                    // Directory markers (LHD_WINDOW == 0xE0) carry
                    // no payload — `dictionary_size()` returns None
                    // for them; the per-entry extractor never
                    // consults `dict_capacity` on that branch.
                    let dict_capacity = file
                        .file_flags
                        .dictionary_size()
                        .map(|v| v as usize)
                        .unwrap_or(0);
                    entries.push(LegacyEntryRecord {
                        name: file.name.clone(),
                        is_directory: file.file_flags.is_directory(),
                        unpacked_size: file.unpacked_size,
                        expected_crc32: file.file_crc32,
                        data_offset,
                        packed_size,
                        method: file.method,
                        dict_capacity,
                    });
                }
                BlockType::EndArchive => {
                    let _end = parse_legacy_endarc_header(&block, local_buf)
                        .map_err(RarPipelineError::Rar)?;
                    cursor = cursor.saturating_add(block.total_bytes_with_data());
                    break;
                }
                BlockType::Comment
                | BlockType::AuthenticityVerification
                | BlockType::Sub
                | BlockType::Protect
                | BlockType::Sign
                | BlockType::NewSub => {
                    // Skipped silently — round-one does not surface
                    // comments / AV / recovery / signatures / ACL
                    // records.
                }
                BlockType::Other(code) => {
                    return Err(RarPipelineError::Rar(RarError::UnsupportedFeature {
                        feature: format!(
                            "unknown legacy RAR block type 0x{code:02x} (no SKIP_IF_UNKNOWN \
                             affordance in legacy format)"
                        ),
                    }));
                }
            }
            cursor = cursor.saturating_add(block.total_bytes_with_data());
        }
        let trailer_end = cursor;

        let entry_count = u32::try_from(entries.len()).map_err(|_| {
            RarPipelineError::Rar(RarError::CorruptHeader {
                archive_offset: 0,
                reason: "legacy archive has more than u32::MAX entries".to_string(),
            })
        })?;

        let already_complete: Vec<u32> = resume.entries_completed.to_vec();
        callback(&RarPipelineEvent::Started {
            entry_count,
            already_complete: already_complete.clone(),
            solid,
        })
        .map_err(RarPipelineError::Aborted)?;

        // Per-entry STORED extraction.
        let completed_set: HashSet<u32> = resume.entries_completed.iter().copied().collect();
        for (idx, entry) in entries.iter().enumerate() {
            let idx = idx as u32;
            if completed_set.contains(&idx) {
                continue;
            }
            let resume_offset = if Some(idx) == resume.current_entry {
                resume.current_entry_offset
            } else {
                0
            };
            // §F1 dispatch: a compressed legacy entry whose
            // checkpoint carried a saved decoder-state blob
            // routes through the resume path. STORED entries
            // always resume by offset alone (sink prefix-replay
            // seeds the running hash); compressed entries with
            // no blob restart from byte 0. Mirror of the RAR5
            // pipeline's §F1 dispatch shape.
            let resume_blob: Option<&[u8]> =
                if Some(idx) == resume.current_entry && entry.method != 0x30 {
                    resume.current_entry_decoder_state.as_deref()
                } else {
                    None
                };
            let (bytes_written, bytes_punched) = if entry.method == 0x30 {
                self.extract_legacy_entry(idx, entry, resume_offset, sink, puncher, &mut callback)?
            } else {
                self.extract_legacy_compressed_entry(
                    idx,
                    entry,
                    resume_offset,
                    resume_blob,
                    sink,
                    puncher,
                    &mut callback,
                )?
            };
            stats.entries_extracted = stats.entries_extracted.saturating_add(1);
            stats.bytes_written = stats.bytes_written.saturating_add(bytes_written);
            stats.bytes_punched = stats.bytes_punched.saturating_add(bytes_punched);
        }

        // Trailing + leading punch, identical to the RAR5 path.
        if trailer_end < self.config.total_size {
            let punched = self.punch_range(puncher, trailer_end, self.config.total_size)?;
            stats.bytes_punched = stats.bytes_punched.saturating_add(punched);
        }
        if let Some(first_entry) = entries.first() {
            if first_entry.data_offset > 0 {
                let punched = self.punch_range(puncher, 0, first_entry.data_offset)?;
                stats.bytes_punched = stats.bytes_punched.saturating_add(punched);
            }
        } else if trailer_end > 0 {
            let punched = self.punch_range(puncher, 0, trailer_end)?;
            stats.bytes_punched = stats.bytes_punched.saturating_add(punched);
        }

        Ok(stats)
    }

    /// STORED-method per-entry extractor for legacy archives.
    ///
    /// Mirrors the STORED arm of [`Self::extract_entry`] but uses
    /// the legacy entry record (no BLAKE2sp slot — legacy file
    /// headers carry CRC-32 only). Compressed entries are rejected
    /// at walk time in [`Self::run_legacy`], so this function is
    /// never called for `method != 0x30`.
    fn extract_legacy_entry<F>(
        &self,
        idx: u32,
        entry: &LegacyEntryRecord,
        resume_offset: u64,
        sink: &mut RarSink,
        puncher: &dyn PunchHole,
        callback: &mut F,
    ) -> Result<(u64, u64), RarPipelineError>
    where
        F: FnMut(&RarPipelineEvent) -> io::Result<()>,
    {
        let data_offset = entry.data_offset;
        let packed_size = entry.packed_size;
        let data_end = data_offset.checked_add(packed_size).ok_or_else(|| {
            RarPipelineError::Rar(RarError::CorruptHeader {
                archive_offset: data_offset,
                reason: "legacy entry data range overflows u64".to_string(),
            })
        })?;

        self.cursor.store(data_offset, Ordering::Release);
        if let Some(p) = self.progress_state {
            p.set_bytes_decoded_input(data_offset);
        }
        self.wait_for_range(data_offset, data_end)?;

        let begin_outcome = if resume_offset > 0 {
            sink.begin_entry_resume(
                idx,
                &entry.name,
                entry.is_directory,
                entry.unpacked_size,
                Some(entry.expected_crc32),
                None, // legacy FILE_HEAD has no BLAKE2sp slot
                resume_offset,
            )
        } else {
            sink.begin_entry(
                idx,
                &entry.name,
                entry.is_directory,
                entry.unpacked_size,
                Some(entry.expected_crc32),
                None,
            )
        }
        .map_err(RarPipelineError::Sink)?;

        if matches!(begin_outcome, BeginEntryOutcome::Directory { .. }) {
            let punched = if packed_size > 0 {
                self.punch_range(puncher, data_offset, data_end)?
            } else {
                0
            };
            callback(&RarPipelineEvent::EntryFinished {
                index: idx,
                name: entry.name.clone(),
                bytes_written: 0,
                bytes_punched: punched,
            })
            .map_err(RarPipelineError::Aborted)?;
            return Ok((0, punched));
        }

        let copy_start = data_offset.saturating_add(resume_offset);
        let mut cursor_in_entry = copy_start;
        let mut buf = vec![0u8; 64 * 1024];
        while cursor_in_entry < data_end {
            let want = (data_end - cursor_in_entry).min(buf.len() as u64) as usize;
            self.sparse
                .read_exact_at(ByteOffset::new(cursor_in_entry), &mut buf[..want])
                .map_err(RarPipelineError::Sparse)?;
            sink.write_entry(&buf[..want])
                .map_err(RarPipelineError::Sink)?;
            cursor_in_entry = cursor_in_entry.saturating_add(want as u64);
            if let Some(p) = self.progress_state {
                p.set_bytes_decoded_input(cursor_in_entry);
            }
            callback(&RarPipelineEvent::InEntryProgress {
                index: idx,
                bytes_written: sink.current_entry_offset(),
            })
            .map_err(RarPipelineError::Aborted)?;
        }

        let _finalize: EntryFinalize = sink.end_entry().map_err(RarPipelineError::Sink)?;

        let punched = self.punch_range(puncher, data_offset, data_end)?;
        callback(&RarPipelineEvent::EntryFinished {
            index: idx,
            name: entry.name.clone(),
            bytes_written: entry.unpacked_size,
            bytes_punched: punched,
        })
        .map_err(RarPipelineError::Aborted)?;

        Ok((entry.unpacked_size, punched))
    }

    /// Compressed-method (`m=1..=5`, on-disk method `0x31..=0x35`)
    /// per-entry extractor for legacy archives.
    ///
    /// Mirrors the structure of [`Self::decompress_entry_to_sink`]
    /// (the RAR5 compressed path) but uses
    /// [`RarLegacyStreamDecoder`] (`docs/PLAN_rar3.md` §E1) over the
    /// in-memory compressed payload. Round-one buffers the entry's
    /// full `packed_size` before constructing the decoder; Phase G
    /// (`O.RAR.STREAMING_DECOMPRESS`) lifts this to a chunk-by-
    /// chunk reader once the §C decoder primitives have stabilised
    /// against a real corpus.
    ///
    /// `resume_decoder_state` carries the saved
    /// [`RarLegacyStreamDecoder`] snapshot blob when this entry was
    /// in flight at the previous checkpoint (`docs/PLAN_rar3.md`
    /// §F1). When `Some`, the sink uses `begin_entry_resume` to
    /// replay the on-disk prefix and seed its running CRC, and
    /// the decoder is constructed via [`RarLegacyStreamDecoder::resume`]
    /// so the suffix emitted matches the original run byte-for-byte.
    /// When `None`, the entry restarts from byte 0 (the §E1
    /// fallback).
    #[allow(clippy::too_many_arguments)]
    fn extract_legacy_compressed_entry<F>(
        &self,
        idx: u32,
        entry: &LegacyEntryRecord,
        resume_offset: u64,
        resume_decoder_state: Option<&[u8]>,
        sink: &mut RarSink,
        puncher: &dyn PunchHole,
        callback: &mut F,
    ) -> Result<(u64, u64), RarPipelineError>
    where
        F: FnMut(&RarPipelineEvent) -> io::Result<()>,
    {
        let data_offset = entry.data_offset;
        let packed_size = entry.packed_size;
        let data_end = data_offset.checked_add(packed_size).ok_or_else(|| {
            RarPipelineError::Rar(RarError::CorruptHeader {
                archive_offset: data_offset,
                reason: "legacy entry data range overflows u64".to_string(),
            })
        })?;

        self.cursor.store(data_offset, Ordering::Release);
        if let Some(p) = self.progress_state {
            p.set_bytes_decoded_input(data_offset);
        }
        self.wait_for_range(data_offset, data_end)?;

        // §F1 resume: seed the sink's running CRC from the
        // already-written on-disk prefix when a decoder-state blob
        // is available. The blob's `decoded_pos` and the sink's
        // `resume_offset` agree by construction — they both track
        // "bytes already emitted to the sink at the moment of the
        // last checkpoint". Without a blob, restart fresh.
        let begin_outcome = if resume_decoder_state.is_some() && resume_offset > 0 {
            sink.begin_entry_resume(
                idx,
                &entry.name,
                entry.is_directory,
                entry.unpacked_size,
                Some(entry.expected_crc32),
                None,
                resume_offset,
            )
            .map_err(RarPipelineError::Sink)?
        } else {
            sink.begin_entry(
                idx,
                &entry.name,
                entry.is_directory,
                entry.unpacked_size,
                Some(entry.expected_crc32),
                None, // legacy FILE_HEAD has no BLAKE2sp slot
            )
            .map_err(RarPipelineError::Sink)?
        };

        if matches!(begin_outcome, BeginEntryOutcome::Directory { .. }) {
            // Directory marker: a compressed-method byte on a
            // directory entry is unusual but valid (packed_size is
            // zero either way). Punch defensively and emit the
            // finished event.
            let punched = if packed_size > 0 {
                self.punch_range(puncher, data_offset, data_end)?
            } else {
                0
            };
            callback(&RarPipelineEvent::EntryFinished {
                index: idx,
                name: entry.name.clone(),
                bytes_written: 0,
                bytes_punched: punched,
            })
            .map_err(RarPipelineError::Aborted)?;
            return Ok((0, punched));
        }

        // Buffer the entry's compressed bytes from the sparse file.
        let mut compressed = vec![
            0u8;
            usize::try_from(packed_size).map_err(|_| {
                RarPipelineError::Rar(RarError::CorruptHeader {
                    archive_offset: data_offset,
                    reason: format!("packed_size {packed_size} exceeds usize on this platform"),
                })
            })?
        ];
        if !compressed.is_empty() {
            self.sparse
                .read_exact_at(ByteOffset::new(data_offset), &mut compressed)
                .map_err(RarPipelineError::Sparse)?;
        }

        let mut decoder = if let Some(blob) = resume_decoder_state {
            // §F1 resume: the blob carries the snapshot taken at
            // the previous checkpoint. `source_cursor_from_blob`
            // is always 0 for the legacy decoder (round-one
            // re-buffers the full payload to deterministically
            // re-run [`decode_payload`]), but we honour the
            // pipeline's standard "slice from cursor" shape for
            // symmetry with the RAR5 path.
            let cursor =
                RarLegacyStreamDecoder::source_cursor_from_blob(blob).map_err(decode_err_to_rar)?;
            if cursor > packed_size {
                return Err(RarPipelineError::Rar(RarError::CorruptHeader {
                    archive_offset: data_offset,
                    reason: format!(
                        "legacy RAR resume blob source cursor {cursor} exceeds \
                         packed_size {packed_size}"
                    ),
                }));
            }
            let cursor_usz = cursor as usize;
            let tail = compressed.split_off(cursor_usz);
            let src: Box<dyn std::io::Read + Send> = Box::new(std::io::Cursor::new(tail));
            RarLegacyStreamDecoder::resume(
                src,
                packed_size,
                entry.unpacked_size,
                entry.method,
                entry.dict_capacity,
                blob,
            )
            .map_err(decode_err_to_rar)?
        } else {
            debug_assert_eq!(resume_offset, 0);
            let src: Box<dyn std::io::Read + Send> = Box::new(std::io::Cursor::new(compressed));
            RarLegacyStreamDecoder::new(
                src,
                packed_size,
                entry.unpacked_size,
                entry.method,
                entry.dict_capacity,
            )
            .map_err(decode_err_to_rar)?
        };

        let mut staging: Vec<u8> = Vec::with_capacity(64 * 1024);
        loop {
            let status = decoder
                .decode_step(&mut staging)
                .map_err(decode_err_to_rar)?;
            if !staging.is_empty() {
                sink.write_entry(&staging).map_err(RarPipelineError::Sink)?;
                staging.clear();
                let blob = decoder.decoder_state();
                callback(&RarPipelineEvent::InEntryProgressCompressed {
                    index: idx,
                    bytes_written: sink.current_entry_offset(),
                    decoder_state: blob,
                })
                .map_err(RarPipelineError::Aborted)?;
            }
            if matches!(status, DecodeStatus::Eof) {
                break;
            }
        }
        if let Some(p) = self.progress_state {
            p.set_bytes_decoded_input(data_end);
        }

        let _finalize: EntryFinalize = sink.end_entry().map_err(RarPipelineError::Sink)?;

        let punched = self.punch_range(puncher, data_offset, data_end)?;
        callback(&RarPipelineEvent::EntryFinished {
            index: idx,
            name: entry.name.clone(),
            bytes_written: entry.unpacked_size,
            bytes_punched: punched,
        })
        .map_err(RarPipelineError::Aborted)?;

        Ok((entry.unpacked_size, punched))
    }

    /// Ensure the chunks covering `[start, start + initial_window)`
    /// (clamped to `total_size`) have landed and return a buffer
    /// holding those bytes. The buffer's start offset is `start`
    /// itself; the caller indexes into it with `byte - start`.
    ///
    /// The window grows on retry when the parser surfaces
    /// `Truncated` (handled at the call site).
    fn read_header_window(&self, start: u64) -> Result<(Vec<u8>, u64), RarPipelineError> {
        let mut window = self.config.initial_header_window.max(64);
        loop {
            let end = (start.saturating_add(window)).min(self.config.total_size);
            self.cursor.store(start, Ordering::Release);
            if let Some(p) = self.progress_state {
                p.set_bytes_decoded_input(start);
            }
            self.wait_for_range(start, end)?;
            let mut buf = vec![0u8; (end - start) as usize];
            self.sparse
                .read_exact_at(ByteOffset::new(start), &mut buf)
                .map_err(RarPipelineError::Sparse)?;
            // Try to parse a generic header; if it surfaces
            // Truncated, double the window and retry. Cap at the
            // archive's remaining length — beyond that the input
            // is genuinely malformed.
            match parse_generic_header(&buf, start) {
                Ok(_) => return Ok((buf, start)),
                Err(RarError::Truncated { needed, .. }) => {
                    if end == self.config.total_size {
                        return Err(RarPipelineError::Rar(RarError::Truncated {
                            what: format!(
                                "header at archive offset {start} \
                                 exceeds remaining archive size"
                            ),
                            needed,
                        }));
                    }
                    window = window
                        .saturating_mul(2)
                        .max(needed as u64 + 64)
                        .min(self.config.total_size - start);
                }
                Err(other) => return Err(RarPipelineError::Rar(other)),
            }
        }
    }

    /// Same shape as [`Self::read_header_window`] but probes with
    /// the legacy (RAR3/RAR4) header parser. Used by the
    /// [`Self::run_legacy`] walker; kept distinct from the RAR5
    /// helper so a single archive's wire format never crosses
    /// parsers mid-walk.
    fn read_legacy_header_window(&self, start: u64) -> Result<(Vec<u8>, u64), RarPipelineError> {
        let mut window = self.config.initial_header_window.max(64);
        loop {
            let end = (start.saturating_add(window)).min(self.config.total_size);
            self.cursor.store(start, Ordering::Release);
            if let Some(p) = self.progress_state {
                p.set_bytes_decoded_input(start);
            }
            self.wait_for_range(start, end)?;
            let mut buf = vec![0u8; (end - start) as usize];
            self.sparse
                .read_exact_at(ByteOffset::new(start), &mut buf)
                .map_err(RarPipelineError::Sparse)?;
            match parse_legacy_generic_header(&buf, start) {
                Ok(_) => return Ok((buf, start)),
                Err(RarError::Truncated { needed, .. }) => {
                    if end == self.config.total_size {
                        return Err(RarPipelineError::Rar(RarError::Truncated {
                            what: format!(
                                "legacy header at archive offset {start} \
                                 exceeds remaining archive size"
                            ),
                            needed,
                        }));
                    }
                    window = window
                        .saturating_mul(2)
                        .max(needed as u64 + 64)
                        .min(self.config.total_size - start);
                }
                Err(other) => return Err(RarPipelineError::Rar(other)),
            }
        }
    }

    /// Block until every chunk overlapping `[start, end)` is in
    /// the bitmap. Returns early if the download thread reports
    /// completion before the chunks land.
    fn wait_for_range(&self, start: u64, end: u64) -> Result<(), RarPipelineError> {
        if start >= end || self.config.chunk_size == 0 {
            return Ok(());
        }
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
                    return Err(RarPipelineError::DownloadFinishedEarly { chunk: idx, detail });
                }
                thread::sleep(self.config.poll_interval);
            }
        }
        Ok(())
    }

    /// Punch the inward-aligned block-sized hole within
    /// `[start, end)`. Partial blocks at either edge are skipped
    /// (the §10 puncher's `align_up`/`align_down` semantics) so
    /// the leading + trailing edges of each entry's range stay
    /// covered until the sidecar deletion proves the run is done.
    fn punch_range(
        &self,
        puncher: &dyn PunchHole,
        start: u64,
        end: u64,
    ) -> Result<u64, RarPipelineError> {
        if start >= end {
            return Ok(0);
        }
        let block = puncher.block_size_hint().max(1);
        // Inward-align: a partial leading or trailing block stays
        // covered until the sidecar deletion proves the run is done.
        let aligned_start = match align_up(start, block) {
            Some(v) => v,
            None => return Ok(0),
        };
        let aligned_end = match align_down(end, block) {
            Some(v) => v,
            None => return Ok(0),
        };
        if aligned_start >= aligned_end {
            return Ok(0);
        }
        let len = aligned_end - aligned_start;
        puncher
            .punch(self.sparse_fd, ByteOffset::new(aligned_start), len)
            .map_err(RarPipelineError::Punch)?;
        Ok(len)
    }
}

/// Translate an entry's `CompressionInfo` into the LZSS
/// dictionary capacity (in bytes). The wire selector encodes
/// `dict_size_bytes = 128 KiB << selector`; we cap at
/// [`MAX_DICT_BYTES`] (256 MiB — the round-one cap from
/// `PLAN_rar5_decoder.md` §B1) and surface a precise diagnostic
/// for selectors that overflow.
fn dict_capacity_for(compression: &crate::rar::format::CompressionInfo) -> Result<usize, String> {
    let selector = compression.dict_size_selector();
    if selector > 14 {
        return Err(format!(
            "selector {selector} exceeds RAR5 spec maximum (14)"
        ));
    }
    let bytes = (128u64 * 1024)
        .checked_shl(
            u32::try_from(selector)
                .map_err(|_| format!("selector {selector} does not fit in u32"))?,
        )
        .ok_or_else(|| format!("selector {selector} overflows the u64 dict size"))?;
    let usz = usize::try_from(bytes)
        .map_err(|_| format!("dict size {bytes} bytes exceeds usize on this platform"))?;
    if usz > MAX_DICT_BYTES {
        return Err(format!(
            "dict size {usz} bytes exceeds round-one cap of {MAX_DICT_BYTES} bytes \
             (selector {selector})"
        ));
    }
    Ok(usz)
}

/// Translate a [`DecodeError`] from the hand-rolled RAR5 decoder
/// into a [`RarPipelineError`]. Read / format errors fold into
/// the pipeline's `Rar` arm wrapping a synthetic
/// [`RarError::CorruptHeader`]; sink-side write errors funnel
/// through `Sink` (the streaming decoder writes into our staging
/// `Vec<u8>` whose `write_all` is infallible, so this branch is
/// only reached on a programming error and is mapped defensively).
fn decode_err_to_rar(e: DecodeError) -> RarPipelineError {
    match e {
        DecodeError::Read { source, .. }
        | DecodeError::Construct(source)
        | DecodeError::Write(source) => RarPipelineError::Rar(RarError::CorruptHeader {
            archive_offset: 0,
            reason: format!("RAR5 stream decoder: {source}"),
        }),
        DecodeError::ResumeMismatch { expected, actual } => {
            RarPipelineError::Rar(RarError::CorruptHeader {
                archive_offset: 0,
                reason: format!(
                    "RAR5 stream decoder resume seam mismatch: expected {expected}, got {actual}"
                ),
            })
        }
    }
}
