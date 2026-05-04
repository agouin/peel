//! Crash-safe checkpoint persistence for resumable extractions.
//!
//! A [`Checkpoint`] captures everything the §10 coordinator needs to
//! pick a download + extraction back up after a `kill -9`: which source
//! was being fetched (URL + ETag/Last-Modified), how the source is
//! sliced (`total_size`, `chunk_size`), the lock-free completion bitmap
//! the workers had populated, the decoder cursor, and a sink-specific
//! [`SinkState`] blob describing how far into extraction we'd gotten.
//!
//! # File layout
//!
//! Checkpoints are not JSON. The format is a tiny custom binary frame
//! so we can verify framing, version, and integrity in three reads
//! without dragging in a serialization crate. All multi-byte integers
//! are little-endian.
//!
//! ```text
//! [ Header — 28 bytes, fixed                                       ]
//!   8 B  magic                  = "peelckpt"
//!   4 B  format_version (u32)
//!   8 B  body_length    (u64)
//!   8 B  body_checksum  (u64)   // FNV-1a-64 over the body bytes
//! [ Body — body_length bytes, length-prefixed fields per version ]
//!   u32 url_len + url utf8 bytes
//!   u8  etag_present + (u32 len + etag utf8 bytes)?
//!   u8  last_modified_present + (u32 len + last_modified utf8 bytes)?
//!   u64 total_size
//!   u64 chunk_size
//!   u64 decoder_position
//!   u32 bitmap_len + bitmap bytes
//!   i64 created_at_unix_secs
//!   u32 created_at_nanos
//!   u8  sink_state_tag
//!     tag 0 (Raw):  u64 bytes_written
//!     tag 1 (Tar):  u32 count, then count × (u32 len + utf8 bytes)
//!     tag 2 (Zip, v2+):
//!                  u32 entries_completed.len, then count × u32 index
//!                  u8  current_entry.is_some
//!                  if some: u32 current_entry_index
//!                  u64 current_entry_offset
//!   u8  hash_state_present (v3+ only)
//!     if 1: SERIALIZED_LEN bytes of `hash::sha256::Sha256` state
//!   u8  chunk_crc32c_present (v4+ only)
//!     if 1: u32 count, then count × u32 CRC-32C values
//! ```
//!
//! # Forward compatibility
//!
//! Adding fields is allowed at the **end** of the body in a future
//! `format_version`. Older readers that encounter a higher version
//! number than they understand fail with
//! [`CheckpointError::UnsupportedVersion`] rather than silently dropping
//! the unknown trailing data. Newer readers that encounter an older
//! version dispatch on the version number and parse the v1 layout.
//!
//! # Atomic writes
//!
//! [`Checkpoint::write`] writes to `<path>.tmp`, `fsync`s the data and
//! then the parent directory, and finally `rename(2)`s `<path>.tmp` over
//! `<path>`. On every supported filesystem `rename` is atomic, so a
//! crash at any point leaves either the previous `<path>` intact or the
//! new one in place — never a torn write. A stray `<path>.tmp` from a
//! crashed previous run is overwritten by the next `write` and ignored
//! by [`Checkpoint::read`].
//!
//! # Examples
//!
//! ```no_run
//! use peel::checkpoint::{Checkpoint, SinkState};
//! use peel::types::ByteOffset;
//!
//! let ckpt = Checkpoint {
//!     url: "https://example.com/dataset.tar.zst".into(),
//!     etag: Some("\"abc123\"".into()),
//!     last_modified: None,
//!     total_size: 10 * 1024 * 1024,
//!     chunk_size: 4 * 1024 * 1024,
//!     decoder_position: ByteOffset::new(2 * 1024 * 1024),
//!     bitmap_completed: vec![0xFF, 0x0F],
//!     created_at: std::time::SystemTime::now(),
//!     sink_state: SinkState::Tar {
//!         members_completed: vec!["root/a.txt".into()],
//!         in_flight: None,
//!     },
//!     hash_state: None,
//!     chunk_crc32c: None,
//!     decoder_state: None,
//! };
//! ckpt.write(std::path::Path::new("/tmp/peel-demo.ckpt"))?;
//! # Ok::<(), peel::checkpoint::CheckpointError>(())
//! ```

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use thiserror::Error;

use crate::types::ByteOffset;

/// Magic bytes at the start of every checkpoint file.
///
/// Eight bytes of ASCII so a `head -c 8 file.ckpt` is human-readable
/// without a hex dump.
pub const MAGIC: [u8; 8] = *b"peelckpt";

/// The format version this build writes and is the highest version it
/// can read. Future builds bump this when the body layout changes.
///
/// History:
///
/// - **v1** — `Raw` and `Tar` sink states.
/// - **v2** — adds the `Zip` sink state for per-entry ZIP extraction
///   (`docs/PLAN_v2.md` §5). The body layout is otherwise unchanged;
///   v2 readers parse v1 files transparently.
/// - **v3** — appends an optional [`Checkpoint::hash_state`] field
///   carrying the serialized SHA-256 state used by `--sha256`
///   integrity verification (`docs/PLAN_v2.md` §10). v3 readers
///   parse v1 / v2 files transparently with `hash_state = None`.
/// - **v4** — appends an optional [`Checkpoint::chunk_crc32c`]
///   per-chunk fingerprint vector for `PLAN_v2.md` §11's mid-flight
///   source-change detector. v4 readers parse v1 / v2 / v3 files
///   transparently with `chunk_crc32c = None`.
/// - **v5** — appends an optional opaque [`Checkpoint::decoder_state`]
///   blob for `OPTIMIZATIONS.md` O.7b's mid-frame lz4 resume. The
///   blob is decoder-private — checkpoint code only carries it
///   verbatim. Length is capped at [`MAX_DECODER_STATE_LEN`] on
///   decode to bound allocation. v5 readers parse v1 / v2 / v3 / v4
///   files transparently with `decoder_state = None`. Older binaries
///   refuse v5 files with [`CheckpointError::UnsupportedVersion`].
/// - **v6** — extends [`SinkState::Tar`] with optional `in_flight`
///   parser state so a kill at any block boundary (not just between
///   tar members) is resumable. Supports the
///   `OPTIMIZATIONS.md`-tracked Polkachu shape where alignment
///   between LZ4 block boundaries and tar member boundaries is
///   essentially never satisfied. v6 readers parse v1 / v2 / v3 /
///   v4 / v5 files transparently with `in_flight = None`. Older
///   binaries refuse v6 with [`CheckpointError::UnsupportedVersion`].
/// - **v7** — extends [`SinkState::Zip`] with an optional opaque
///   `current_entry_decoder_state` blob carrying the in-flight zip
///   entry's codec state (`docs/PLAN_deflate_block_decoder.md`
///   Phase 9b). v7 readers parse v1..=v6 files transparently
///   with `current_entry_decoder_state = None` (which fall through
///   to the existing per-entry "restart from byte 0" path for
///   DEFLATE / zstd entries). Older binaries refuse v7 with
///   [`CheckpointError::UnsupportedVersion`].
pub const FORMAT_VERSION: u32 = 7;

/// Fixed-size header length, in bytes.
const HEADER_LEN: usize = 8 + 4 + 8 + 8;

/// Tag for [`SinkState::Raw`] in the on-disk format.
const SINK_TAG_RAW: u8 = 0;
/// Tag for [`SinkState::Tar`] in the on-disk format.
const SINK_TAG_TAR: u8 = 1;
/// Tag for [`SinkState::Zip`] in the on-disk format. Added in v2 of
/// the checkpoint layout.
const SINK_TAG_ZIP: u8 = 2;

/// Maximum length of the v5 [`Checkpoint::decoder_state`] blob.
///
/// Sized to accommodate the hand-rolled zstd decoder's resume blob
/// (`docs/PLAN_zstd_block_decoder.md` Phase 7), which carries a
/// sliding-window snapshot of up to `MAX_WINDOW_SIZE` (128 MiB at
/// `windowLog = 27`) plus ~10 KiB of metadata. The lz4 blob is on
/// the order of 50 bytes; the upper bound is a zstd-only concern.
/// [`MAX_BODY_LEN`] (1 GiB) still bounds the worst-case allocation
/// a hostile checkpoint can trigger before
/// [`Checkpoint::deserialize`] checks the body checksum.
pub const MAX_DECODER_STATE_LEN: u32 = (1 << 27) + 32 * 1024;

/// Errors produced by [`Checkpoint::read`] / [`Checkpoint::write`] and
/// the in-memory [`Checkpoint::deserialize`] / [`Checkpoint::serialize`]
/// helpers.
///
/// Variants are specific so callers can decide what to log vs. retry
/// vs. surface as a hard failure. Per `docs/ENGINEERING_BEST_PRACTICES`
/// §3.1 every variant carries enough structured context that the
/// `Display` message alone is debuggable.
#[derive(Debug, Error)]
pub enum CheckpointError {
    /// A filesystem syscall failed.
    #[error("io error operating on {path}")]
    Io {
        /// Path involved in the failing call.
        path: PathBuf,
        /// The underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The first eight bytes of the file did not match [`MAGIC`].
    #[error("not a peel checkpoint (magic was {found:02X?})")]
    BadMagic {
        /// The eight bytes the reader actually saw.
        found: [u8; 8],
    },

    /// The file declares a `format_version` newer than this build can
    /// parse. Per §9.4 the older binary refuses to guess at the new
    /// layout and surfaces this so the caller can surface a clean
    /// upgrade-required message.
    #[error("checkpoint format version {found} is newer than supported max {supported_max}")]
    UnsupportedVersion {
        /// The version recorded in the file header.
        found: u32,
        /// The highest version this build understands.
        supported_max: u32,
    },

    /// The file's framing is internally consistent (magic, version) but
    /// the body length is shorter than the version's minimum, or
    /// truncated mid-field.
    #[error("checkpoint is truncated or malformed: {reason}")]
    Truncated {
        /// Human-readable detail naming which field overran.
        reason: String,
    },

    /// The body checksum recorded in the header does not match the
    /// computed checksum of the body bytes — the file has been
    /// corrupted on disk or in transit.
    #[error(
        "checkpoint body checksum mismatch (header {expected:#018x}, computed {computed:#018x})"
    )]
    BodyChecksumMismatch {
        /// Checksum the header recorded.
        expected: u64,
        /// Checksum we computed over the body bytes we read.
        computed: u64,
    },

    /// A `Vec<u8>`-prefixed UTF-8 field failed to decode.
    #[error("checkpoint field {field} is not valid utf-8")]
    InvalidUtf8 {
        /// Name of the field that failed to decode.
        field: &'static str,
        /// Underlying conversion error.
        #[source]
        source: std::string::FromUtf8Error,
    },

    /// A discriminant byte (`SinkState` tag) had an unknown value.
    #[error("checkpoint field {field} has unknown enum tag {tag}")]
    InvalidEnumTag {
        /// Name of the field whose tag was unknown.
        field: &'static str,
        /// The unknown tag value.
        tag: u8,
    },

    /// A boolean-coded presence byte (etag / last-modified) was neither
    /// `0` nor `1`.
    #[error("checkpoint field {field} presence byte {value} is not a valid boolean")]
    InvalidPresence {
        /// Name of the field whose presence byte was invalid.
        field: &'static str,
        /// The byte we observed.
        value: u8,
    },

    /// The file declares a `body_length` that exceeds the configured
    /// safety cap. Defensive against pathological inputs.
    #[error("checkpoint body length {found} exceeds safety cap {cap}")]
    BodyTooLarge {
        /// The declared body length.
        found: u64,
        /// The configured cap.
        cap: u64,
    },
}

/// In-flight [`crate::sink::TarSink`] parser state captured at a
/// checkpoint, mirroring the live `TarSink::State` enum in a form that
/// can be (de)serialized.
///
/// Stored inside [`SinkState::Tar`]'s `in_flight` field so a kill
/// mid-member is resumable without requiring decoder block boundaries
/// to coincide with tar member boundaries (a rare alignment for
/// real-world `tar.lz4` archives like Polkachu's chain snapshots).
///
/// Deserialization rejects out-of-range fields (e.g. `header_filled >
/// 512`, `padding > 511`) so a corrupt checkpoint can't drive the
/// resumed sink into UB-adjacent states.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TarSinkState {
    /// Cumulative archive bytes the sink has consumed at the
    /// checkpoint moment. Diagnostic only; the resumed sink rebuilds
    /// its own counter from `state` and the resumed decoder's output.
    pub archive_offset: u64,
    /// Number of *consecutive* trailing zero blocks the sink has
    /// observed leading up to the checkpoint. Tar uses two zero
    /// blocks as the end-of-archive marker.
    pub zero_blocks_seen: u8,
    /// PAX `path=` override applying to the next non-PAX entry, if
    /// any was buffered when the checkpoint fired.
    pub pending_path: Option<String>,
    /// PAX `size=` override applying to the next non-PAX entry, if
    /// any.
    pub pending_size: Option<u64>,
    /// The parser's driving state.
    pub state: TarMemberState,
}

/// Serializable companion of `crate::sink::tar::State`.
///
/// `Header` carries the partial 512-byte buffer accumulated so far so
/// resume picks up reading the rest of it. `File` carries the path,
/// remaining payload bytes, and remaining padding bytes — the resumed
/// sink reopens the file at offset `total_size - remaining` and
/// continues. `PaxData` and `LongName` carry their accumulator
/// buffers. `Finished` is the terminal state.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TarMemberState {
    /// Buffering bytes toward the next 512-byte tar header. `filled`
    /// is in `0..=512`; `buf` carries exactly the bytes received so
    /// far (length == `filled`; the rest of the 512-byte block is
    /// not stored).
    Header {
        /// Bytes already received toward the header.
        filled: u32,
        /// The bytes received so far (length == `filled`).
        buf: Vec<u8>,
    },
    /// Mid-payload write to a regular file. The resumed sink reopens
    /// `path` (relative to the extraction root), seeks to the
    /// already-written offset, and continues.
    File {
        /// Bytes of file payload still to receive.
        remaining: u64,
        /// Bytes of trailing zero padding still to consume.
        padding: u32,
        /// Output path the sink is writing into, relative to the
        /// extraction root.
        path: String,
        /// Original payload size declared by the tar header, used to
        /// derive the resumed file's seek offset
        /// (`total_size - remaining`).
        total_size: u64,
    },
    /// Mid-PAX-extended-header read.
    PaxData {
        /// Bytes of PAX body still to receive.
        remaining: u64,
        /// Bytes of trailing zero padding still to consume.
        padding: u32,
        /// Accumulator for the PAX entry data so far.
        buf: Vec<u8>,
    },
    /// Mid-GNU-long-name read.
    LongName {
        /// Bytes of body still to receive.
        remaining: u64,
        /// Bytes of trailing zero padding still to consume.
        padding: u32,
        /// Accumulator for the long path so far.
        buf: Vec<u8>,
        /// `true` for 'K' (long link target, discarded), `false` for
        /// 'L' (long path, applied to the next entry).
        is_link: bool,
    },
    /// End-of-archive marker observed; further bytes are an error.
    Finished,
}

/// Maximum buffered data the v6 [`TarSinkState`] decoder will trust
/// before [`Checkpoint::deserialize`] rejects with
/// [`CheckpointError::Truncated`]. Bounds the allocation a hostile
/// blob can trigger before the body checksum kicks in.
const MAX_TAR_BUFFER_LEN: u32 = 16 * 1024;

/// Tag for [`TarMemberState::Header`].
const TAR_TAG_HEADER: u8 = 0;
/// Tag for [`TarMemberState::File`].
const TAR_TAG_FILE: u8 = 1;
/// Tag for [`TarMemberState::PaxData`].
const TAR_TAG_PAX: u8 = 2;
/// Tag for [`TarMemberState::LongName`].
const TAR_TAG_LONGNAME: u8 = 3;
/// Tag for [`TarMemberState::Finished`].
const TAR_TAG_FINISHED: u8 = 4;

/// Sink-specific extraction state opaque to everything but the sink.
///
/// `Raw` and `Tar` are the two MVP sinks (see [`crate::sink`]); each
/// carries the minimum state required to skip already-extracted output
/// on resume:
///
/// - [`SinkState::Raw`] records bytes already written to the single
///   output file, so resume seeks past them rather than redoing them.
/// - [`SinkState::Tar`] records the in-flight parser state so resume
///   picks up exactly where the killed run left off — including in
///   the middle of a multi-MB tar member, which is the common case
///   for archives whose decoder block boundaries don't align with
///   tar-member boundaries.
///
/// The §10 coordinator captures the appropriate variant whenever the
/// extractor reports a checkpoint.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SinkState {
    /// State for [`crate::sink::RawSink`].
    Raw {
        /// Total bytes successfully written to the output file at the
        /// checkpoint moment. Resume seeks past `bytes_written` and
        /// continues writing from there.
        bytes_written: u64,
    },

    /// State for [`crate::sink::TarSink`].
    Tar {
        /// Tar member names already extracted at the checkpoint moment.
        /// Vestigial: the streaming pipeline does not re-present prior
        /// members on resume (the resumed decoder produces only the
        /// archive suffix), so this list is empty in v6 producers and
        /// is preserved only for v5-and-earlier on-disk compatibility.
        members_completed: Vec<String>,
        /// In-flight tar parser state, captured at the checkpoint
        /// moment. `Some(...)` whenever the sink was mid-member (or
        /// mid-header / mid-PAX / mid-LongName); `None` only when the
        /// sink had just finished a member and was quiescent or fully
        /// finished. The resumed sink restores this state directly
        /// instead of starting from scratch — necessary for archive
        /// shapes (e.g. Polkachu's single-frame `tar.lz4`) where
        /// alignment between decoder block boundaries and tar member
        /// boundaries is rare. Added in checkpoint format v6; older
        /// readers see `None`.
        in_flight: Option<TarSinkState>,
    },

    /// State for [`crate::sink::ZipSink`].
    ///
    /// ZIP archives are extracted per-entry in central-directory
    /// order. The checkpoint records which entries are durable on
    /// disk via `entries_completed`, and (when a crash interrupts an
    /// entry) the in-flight entry index plus the byte offset within
    /// it. STORED entries resume from `current_entry_offset`;
    /// DEFLATE / zstd entries resume from `current_entry_offset` *and*
    /// the codec's `current_entry_decoder_state` blob (Phase 9b of
    /// `docs/PLAN_deflate_block_decoder.md`). When the blob is
    /// `None` for a DEFLATE / zstd entry — either because the
    /// checkpoint was captured at byte 0 or the v6 reader couldn't
    /// see it — the pipeline falls back to "restart entry from byte
    /// 0", matching the pre-Phase-9b behaviour.
    Zip {
        /// Indices (within the central directory) of entries that
        /// finished extracting before this checkpoint was written.
        /// Ordered, deduplicated in the producer; the on-disk form
        /// trusts the producer rather than re-checking on read.
        entries_completed: Vec<u32>,
        /// Index of the entry that was in flight when the checkpoint
        /// was written, if any. `None` means the sink was quiescent.
        current_entry: Option<u32>,
        /// Bytes already written into the in-flight entry. `0` when
        /// `current_entry` is `None`.
        current_entry_offset: u64,
        /// Opaque decoder-state blob captured at the most recent
        /// in-entry checkpoint. `None` when the in-flight entry is
        /// at byte 0, when the entry uses STORED (no codec state),
        /// or when the checkpoint was written by a pre-v7 binary.
        /// Added in checkpoint format v7; v6 readers see `None` and
        /// fall through to the per-entry "restart from byte 0" path.
        current_entry_decoder_state: Option<Vec<u8>>,
    },
}

/// On-disk checkpoint of a download+extraction in progress.
///
/// All fields are owned values — there are no borrows so the struct is
/// `Send` and the coordinator can shuttle it between threads.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Checkpoint {
    /// The URL the download is fetching from. Stored verbatim so the
    /// resume path can compare against the URL the user passed on the
    /// CLI.
    pub url: String,
    /// `ETag` recorded at the initial `HEAD` time, if the server sent
    /// one.
    pub etag: Option<String>,
    /// `Last-Modified` recorded at the initial `HEAD` time, if the
    /// server sent one.
    pub last_modified: Option<String>,
    /// Total source size in bytes (from `Content-Length`).
    pub total_size: u64,
    /// Chunk size the scheduler used to slice the source.
    pub chunk_size: u64,
    /// Most recent decoder cursor durably reachable from this
    /// checkpoint. Resume rewinds the decoder to this position.
    pub decoder_position: ByteOffset,
    /// Serialized chunk completion bitmap as raw bytes. The
    /// coordinator reconstructs a [`crate::bitmap::ChunkBitmap`] from
    /// these bytes plus `total_size / chunk_size`.
    pub bitmap_completed: Vec<u8>,
    /// Wall-clock time the checkpoint was written. Diagnostic only —
    /// the resume path uses ETag/Last-Modified to validate freshness.
    pub created_at: SystemTime,
    /// Sink-specific state captured at the same instant the checkpoint
    /// was taken.
    pub sink_state: SinkState,
    /// Serialized SHA-256 state when integrity tracking is on
    /// (`docs/PLAN_v2.md` §10), or `None` when the run is not
    /// verifying a `--sha256` digest.
    ///
    /// The bytes are exactly the output of
    /// [`crate::hash::sha256::Sha256::serialize`] and are restored
    /// with [`crate::hash::sha256::Sha256::deserialize`] on resume.
    /// Added in checkpoint format v3; older readers see `None`.
    pub hash_state: Option<[u8; crate::hash::sha256::SERIALIZED_LEN]>,
    /// Per-bitmap-chunk CRC-32C fingerprints (`PLAN_v2.md` §11)
    /// captured by the download workers, or `None` when the §11
    /// drift detector is off (or the checkpoint predates v4).
    ///
    /// Length, when `Some`, equals the chunk count implied by
    /// `total_size / chunk_size`. Workers populate the slot for
    /// each completed chunk as they record CRCs; an unset slot
    /// (chunk not yet downloaded) holds `0`. Coordinator's resume
    /// path uses the populated slots to verify the source has not
    /// changed since the checkpoint was written.
    pub chunk_crc32c: Option<Vec<u32>>,
    /// Opaque per-decoder resume state captured by the extractor at
    /// the same step the boundary advanced
    /// (`docs/OPTIMIZATIONS.md` §O.7b). Today this is populated by
    /// `lz4` for mid-frame block boundaries; every other in-tree
    /// decoder reports `None`. The bytes are decoder-private — the
    /// checkpoint format treats the blob as opaque and only enforces
    /// the [`MAX_DECODER_STATE_LEN`] length cap on decode. Added in
    /// checkpoint format v5; older readers see `None`.
    pub decoder_state: Option<Vec<u8>>,
}

/// Maximum body length [`Checkpoint::deserialize`] will trust before
/// returning [`CheckpointError::BodyTooLarge`]. Defensive: the bitmap
/// scales linearly with the chunk count, so for `u32::MAX` chunks
/// that's ~512 MiB; we leave headroom and cap at 1 GiB.
pub const MAX_BODY_LEN: u64 = 1 << 30;

impl Checkpoint {
    /// Serialize the checkpoint to its on-disk binary representation.
    ///
    /// This is the in-memory companion to [`Self::write`]. Tests round
    /// trip through this pair without touching the filesystem.
    #[must_use]
    pub fn serialize(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(self.estimated_body_size());
        write_string(&mut body, &self.url);
        write_optional_string(&mut body, self.etag.as_deref());
        write_optional_string(&mut body, self.last_modified.as_deref());
        write_u64(&mut body, self.total_size);
        write_u64(&mut body, self.chunk_size);
        write_u64(&mut body, self.decoder_position.get());
        write_byte_array(&mut body, &self.bitmap_completed);

        let (secs, nanos) = encode_system_time(self.created_at);
        write_i64(&mut body, secs);
        write_u32(&mut body, nanos);

        match &self.sink_state {
            SinkState::Raw { bytes_written } => {
                body.push(SINK_TAG_RAW);
                write_u64(&mut body, *bytes_written);
            }
            SinkState::Tar {
                members_completed,
                in_flight,
            } => {
                body.push(SINK_TAG_TAR);
                // u32::try_from is the right boundary check; in practice the
                // checkpoint is bounded long before this could overflow.
                let count = u32::try_from(members_completed.len()).unwrap_or(u32::MAX);
                write_u32(&mut body, count);
                for name in members_completed.iter().take(count as usize) {
                    write_string(&mut body, name);
                }
                // v6: optional in-flight tar parser state.
                match in_flight {
                    Some(s) => {
                        body.push(1);
                        write_tar_sink_state(&mut body, s);
                    }
                    None => body.push(0),
                }
            }
            SinkState::Zip {
                entries_completed,
                current_entry,
                current_entry_offset,
                current_entry_decoder_state,
            } => {
                body.push(SINK_TAG_ZIP);
                let count = u32::try_from(entries_completed.len()).unwrap_or(u32::MAX);
                write_u32(&mut body, count);
                for idx in entries_completed.iter().take(count as usize) {
                    write_u32(&mut body, *idx);
                }
                match current_entry {
                    Some(idx) => {
                        body.push(1);
                        write_u32(&mut body, *idx);
                    }
                    None => body.push(0),
                }
                write_u64(&mut body, *current_entry_offset);
                // v7: optional in-flight codec state blob. v6
                // readers stop at the previous field and see the
                // blob as absent, which matches the field's default.
                match current_entry_decoder_state {
                    Some(blob) => {
                        body.push(1);
                        let len = u32::try_from(blob.len()).unwrap_or(u32::MAX);
                        write_u32(&mut body, len);
                        body.extend_from_slice(&blob[..len as usize]);
                    }
                    None => body.push(0),
                }
            }
        }

        match &self.hash_state {
            Some(bytes) => {
                body.push(1);
                body.extend_from_slice(bytes);
            }
            None => body.push(0),
        }

        match &self.chunk_crc32c {
            Some(crcs) => {
                body.push(1);
                let count = u32::try_from(crcs.len()).unwrap_or(u32::MAX);
                write_u32(&mut body, count);
                for crc in crcs.iter().take(count as usize) {
                    write_u32(&mut body, *crc);
                }
            }
            None => body.push(0),
        }

        match &self.decoder_state {
            Some(blob) => {
                body.push(1);
                // The encode side enforces the same cap the decode
                // side enforces; longer blobs would round-trip but
                // the cap on read would reject them, which would be
                // confusing.
                let len = u32::try_from(blob.len())
                    .unwrap_or(u32::MAX)
                    .min(MAX_DECODER_STATE_LEN);
                write_u32(&mut body, len);
                body.extend_from_slice(&blob[..len as usize]);
            }
            None => body.push(0),
        }

        let body_len = body.len() as u64;
        let body_checksum = fnv1a64(&body);

        let mut buf = Vec::with_capacity(HEADER_LEN + body.len());
        buf.extend_from_slice(&MAGIC);
        write_u32(&mut buf, FORMAT_VERSION);
        write_u64(&mut buf, body_len);
        write_u64(&mut buf, body_checksum);
        buf.extend_from_slice(&body);
        buf
    }

    /// Parse a checkpoint from its on-disk binary representation.
    ///
    /// # Errors
    ///
    /// Returns the appropriate [`CheckpointError`] variant on any
    /// framing, version, checksum, or field-decode failure. The
    /// function never panics on adversarial input.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, CheckpointError> {
        if bytes.len() < HEADER_LEN {
            return Err(CheckpointError::Truncated {
                reason: format!(
                    "expected at least {HEADER_LEN}-byte header, got {}",
                    bytes.len(),
                ),
            });
        }

        let mut found_magic = [0u8; 8];
        found_magic.copy_from_slice(&bytes[0..8]);
        if found_magic != MAGIC {
            return Err(CheckpointError::BadMagic { found: found_magic });
        }

        let format_version = read_u32(&bytes[8..12]);
        if format_version > FORMAT_VERSION {
            return Err(CheckpointError::UnsupportedVersion {
                found: format_version,
                supported_max: FORMAT_VERSION,
            });
        }

        let body_len = read_u64(&bytes[12..20]);
        if body_len > MAX_BODY_LEN {
            return Err(CheckpointError::BodyTooLarge {
                found: body_len,
                cap: MAX_BODY_LEN,
            });
        }
        let body_checksum_header = read_u64(&bytes[20..28]);

        let body_start = HEADER_LEN;
        let body_end = body_start
            .checked_add(
                usize::try_from(body_len).map_err(|_| CheckpointError::Truncated {
                    reason: format!("body_length {body_len} does not fit in usize"),
                })?,
            )
            .ok_or_else(|| CheckpointError::Truncated {
                reason: format!("header + body length {body_len} overflows"),
            })?;
        if bytes.len() < body_end {
            return Err(CheckpointError::Truncated {
                reason: format!(
                    "body declared {body_len} bytes, file has {} after header",
                    bytes.len().saturating_sub(body_start),
                ),
            });
        }
        let body = &bytes[body_start..body_end];

        let computed = fnv1a64(body);
        if computed != body_checksum_header {
            return Err(CheckpointError::BodyChecksumMismatch {
                expected: body_checksum_header,
                computed,
            });
        }

        // v1 and v2 share the same body layout up to the sink tag;
        // v2 adds [`SINK_TAG_ZIP`] as an accepted tag value. v3
        // appends a single trailing `hash_state` field after the
        // sink-state body. v4 appends a `chunk_crc32c` trailer after
        // that. v5 appends an opaque `decoder_state` blob after that.
        // v6 extends `SinkState::Tar` with an optional `in_flight`
        // parser-state field. The `decode_body` helper takes the
        // version so it can decide whether to read each trailer;
        // future versions that *change* the layout will branch
        // here.
        debug_assert!(matches!(format_version, 1..=7));
        Self::decode_body(body, format_version)
    }

    /// Decode the body layout. v1 / v2 / v3 share the same prefix;
    /// v3 appends an optional `hash_state` blob after `sink_state`,
    /// v4 appends a `chunk_crc32c` trailer, v5 appends an opaque
    /// `decoder_state` blob; v6 extends `SinkState::Tar` with an
    /// optional `in_flight` parser-state trailer.
    fn decode_body(body: &[u8], format_version: u32) -> Result<Self, CheckpointError> {
        let mut cursor = Cursor::new(body);
        let url = cursor.read_string("url")?;
        let etag = cursor.read_optional_string("etag")?;
        let last_modified = cursor.read_optional_string("last_modified")?;
        let total_size = cursor.read_u64("total_size")?;
        let chunk_size = cursor.read_u64("chunk_size")?;
        let decoder_position = cursor.read_u64("decoder_position")?;
        let bitmap_completed = cursor.read_byte_array("bitmap_completed")?;
        let secs = cursor.read_i64("created_at_unix_secs")?;
        let nanos = cursor.read_u32("created_at_nanos")?;
        let created_at = decode_system_time(secs, nanos);

        let sink_tag = cursor.read_u8("sink_state_tag")?;
        let sink_state = match sink_tag {
            SINK_TAG_RAW => SinkState::Raw {
                bytes_written: cursor.read_u64("sink.raw.bytes_written")?,
            },
            SINK_TAG_TAR => {
                let count = cursor.read_u32("sink.tar.members_completed.len")?;
                let mut members = Vec::with_capacity(count as usize);
                for i in 0..count {
                    // Use the index in the field tag so a malformed
                    // entry's position is in the error message.
                    let label_owned = format!("sink.tar.members_completed[{i}]");
                    let s = cursor.read_string_dyn(&label_owned)?;
                    members.push(s);
                }
                let in_flight = if format_version >= 6 {
                    let presence = cursor.read_u8("sink.tar.in_flight.is_some")?;
                    match presence {
                        0 => None,
                        1 => Some(read_tar_sink_state(&mut cursor)?),
                        other => {
                            return Err(CheckpointError::InvalidPresence {
                                field: "sink.tar.in_flight",
                                value: other,
                            });
                        }
                    }
                } else {
                    None
                };
                SinkState::Tar {
                    members_completed: members,
                    in_flight,
                }
            }
            SINK_TAG_ZIP => {
                let count = cursor.read_u32("sink.zip.entries_completed.len")?;
                let mut entries = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    entries.push(cursor.read_u32("sink.zip.entries_completed[i]")?);
                }
                let current_present = cursor.read_u8("sink.zip.current_entry.is_some")?;
                let current_entry = match current_present {
                    0 => None,
                    1 => Some(cursor.read_u32("sink.zip.current_entry")?),
                    other => {
                        return Err(CheckpointError::InvalidPresence {
                            field: "sink.zip.current_entry",
                            value: other,
                        });
                    }
                };
                let current_entry_offset = cursor.read_u64("sink.zip.current_entry_offset")?;
                // v7: optional in-flight codec state blob. v6 and
                // earlier files have no further bytes here; the
                // remaining body (hash_state / chunk_crc32c /
                // decoder_state) reads correctly because each of
                // those fields is its own length-prefixed
                // optional field.
                let current_entry_decoder_state = if format_version >= 7 {
                    let presence =
                        cursor.read_u8("sink.zip.current_entry_decoder_state.is_some")?;
                    match presence {
                        0 => None,
                        1 => {
                            let len =
                                cursor.read_u32("sink.zip.current_entry_decoder_state.len")?;
                            // Bound the allocation; reuse the same
                            // ceiling as `Checkpoint::decoder_state`
                            // since the deflate / gzip / zstd-in-zip
                            // resume blobs all stay well under it.
                            if len > MAX_DECODER_STATE_LEN {
                                return Err(CheckpointError::Truncated {
                                    reason: format!(
                                        "sink.zip.current_entry_decoder_state length {len} \
                                         exceeds cap {MAX_DECODER_STATE_LEN}",
                                    ),
                                });
                            }
                            let bytes = cursor.require(
                                len as usize,
                                "sink.zip.current_entry_decoder_state.bytes",
                            )?;
                            Some(bytes.to_vec())
                        }
                        other => {
                            return Err(CheckpointError::InvalidPresence {
                                field: "sink.zip.current_entry_decoder_state",
                                value: other,
                            });
                        }
                    }
                } else {
                    None
                };
                SinkState::Zip {
                    entries_completed: entries,
                    current_entry,
                    current_entry_offset,
                    current_entry_decoder_state,
                }
            }
            other => {
                return Err(CheckpointError::InvalidEnumTag {
                    field: "sink_state_tag",
                    tag: other,
                });
            }
        };

        let hash_state = if format_version >= 3 {
            let presence = cursor.read_u8("hash_state.is_some")?;
            match presence {
                0 => None,
                1 => {
                    let bytes =
                        cursor.require(crate::hash::sha256::SERIALIZED_LEN, "hash_state.bytes")?;
                    let mut buf = [0u8; crate::hash::sha256::SERIALIZED_LEN];
                    buf.copy_from_slice(bytes);
                    Some(buf)
                }
                other => {
                    return Err(CheckpointError::InvalidPresence {
                        field: "hash_state",
                        value: other,
                    });
                }
            }
        } else {
            None
        };

        let chunk_crc32c = if format_version >= 4 {
            let presence = cursor.read_u8("chunk_crc32c.is_some")?;
            match presence {
                0 => None,
                1 => {
                    let count = cursor.read_u32("chunk_crc32c.len")?;
                    let mut crcs = Vec::with_capacity(count as usize);
                    for _ in 0..count {
                        crcs.push(cursor.read_u32("chunk_crc32c[i]")?);
                    }
                    Some(crcs)
                }
                other => {
                    return Err(CheckpointError::InvalidPresence {
                        field: "chunk_crc32c",
                        value: other,
                    });
                }
            }
        } else {
            None
        };

        let decoder_state = if format_version >= 5 {
            let presence = cursor.read_u8("decoder_state.is_some")?;
            match presence {
                0 => None,
                1 => {
                    let len = cursor.read_u32("decoder_state.len")?;
                    if len > MAX_DECODER_STATE_LEN {
                        return Err(CheckpointError::Truncated {
                            reason: format!(
                                "decoder_state length {len} exceeds cap {MAX_DECODER_STATE_LEN}",
                            ),
                        });
                    }
                    let bytes = cursor.require(len as usize, "decoder_state.bytes")?;
                    Some(bytes.to_vec())
                }
                other => {
                    return Err(CheckpointError::InvalidPresence {
                        field: "decoder_state",
                        value: other,
                    });
                }
            }
        } else {
            None
        };

        if cursor.remaining() != 0 {
            return Err(CheckpointError::Truncated {
                reason: format!(
                    "{} trailing bytes after final field in v{format_version} body",
                    cursor.remaining(),
                ),
            });
        }

        Ok(Self {
            url,
            etag,
            last_modified,
            total_size,
            chunk_size,
            decoder_position: ByteOffset::new(decoder_position),
            bitmap_completed,
            created_at,
            sink_state,
            hash_state,
            chunk_crc32c,
            decoder_state,
        })
    }

    /// Atomically write the checkpoint to `path`.
    ///
    /// Writes to `<path>.tmp` first, `fsync`s the data and the parent
    /// directory, then `rename(2)`s `<path>.tmp` over `<path>`. A crash
    /// at any point leaves either the previous `<path>` intact or the
    /// new one in place; readers never observe a partial write.
    ///
    /// # Errors
    ///
    /// Returns [`CheckpointError::Io`] for any failing syscall, with
    /// `path` set to the file involved (the temp file or the parent
    /// directory, as appropriate).
    pub fn write(&self, path: &Path) -> Result<(), CheckpointError> {
        let bytes = self.serialize();
        let tmp_path = tmp_path_for(path);

        // Open the temp file: create or truncate so a stale .tmp from
        // a previous crash is overwritten cleanly.
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp_path)
            .map_err(|source| CheckpointError::Io {
                path: tmp_path.clone(),
                source,
            })?;

        file.write_all(&bytes)
            .map_err(|source| CheckpointError::Io {
                path: tmp_path.clone(),
                source,
            })?;
        file.sync_all().map_err(|source| CheckpointError::Io {
            path: tmp_path.clone(),
            source,
        })?;
        // Drop the file handle before renaming. On POSIX the rename
        // works either way, but closing first matches the canonical
        // sequence and keeps the resource lifetime obvious.
        drop(file);

        fs::rename(&tmp_path, path).map_err(|source| CheckpointError::Io {
            path: path.to_path_buf(),
            source,
        })?;

        // Best-effort fsync of the parent directory so the rename is
        // also durable. Filesystems differ on whether this is required
        // — ext4 with `data=ordered`, xfs, etc. — and on platforms
        // where opening a directory for fsync is unsupported (Windows)
        // we skip silently. A failure here is non-fatal: the data is
        // durable; only the directory entry's flush is at stake.
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                if let Ok(dir) = File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }

        Ok(())
    }

    /// Read a checkpoint from `path` if one exists.
    ///
    /// Returns `Ok(None)` if `path` does not exist (the common
    /// first-run case). Returns `Ok(Some(_))` on a valid checkpoint.
    /// Returns the appropriate [`CheckpointError`] on any other
    /// failure — including a corrupt or truncated checkpoint, which
    /// the §10 coordinator surfaces to the user rather than silently
    /// discarding.
    ///
    /// # Errors
    ///
    /// See [`CheckpointError`].
    pub fn read(path: &Path) -> Result<Option<Self>, CheckpointError> {
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(CheckpointError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|source| CheckpointError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        Self::deserialize(&bytes).map(Some)
    }

    fn estimated_body_size(&self) -> usize {
        // Rough ceiling so the Vec only grows once for typical inputs.
        // Bitmap dominates; everything else is bounded by short strings.
        4 + self.url.len()
            + 1
            + 4
            + self.etag.as_ref().map_or(0, String::len)
            + 1
            + 4
            + self.last_modified.as_ref().map_or(0, String::len)
            + 8
            + 8
            + 8
            + 4
            + self.bitmap_completed.len()
            + 8
            + 4
            + 1
            + 32
            + 1
            + self
                .hash_state
                .as_ref()
                .map_or(0, |_| crate::hash::sha256::SERIALIZED_LEN)
            + 1
            + self.chunk_crc32c.as_ref().map_or(0, |c| 4 + c.len() * 4)
            + 1
            + self.decoder_state.as_ref().map_or(0, |b| 4 + b.len())
    }
}

/// Compute `<path>.tmp` for the atomic-write dance. Public so tests
/// and callers (like §10's coordinator) can clean up stale temp files.
#[must_use]
pub fn tmp_path_for(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    PathBuf::from(name)
}

// -- internal serializer helpers --------------------------------------

fn write_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_i64(buf: &mut Vec<u8>, v: i64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_string(buf: &mut Vec<u8>, s: &str) {
    write_byte_array(buf, s.as_bytes());
}

fn write_byte_array(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    write_u32(buf, len);
    buf.extend_from_slice(&bytes[..len as usize]);
}

fn write_optional_string(buf: &mut Vec<u8>, s: Option<&str>) {
    match s {
        Some(value) => {
            buf.push(1);
            write_string(buf, value);
        }
        None => buf.push(0),
    }
}

fn write_tar_sink_state(buf: &mut Vec<u8>, s: &TarSinkState) {
    write_u64(buf, s.archive_offset);
    buf.push(s.zero_blocks_seen);
    write_optional_string(buf, s.pending_path.as_deref());
    match s.pending_size {
        Some(v) => {
            buf.push(1);
            write_u64(buf, v);
        }
        None => buf.push(0),
    }
    write_tar_member_state(buf, &s.state);
}

fn write_tar_member_state(buf: &mut Vec<u8>, m: &TarMemberState) {
    match m {
        TarMemberState::Header { filled, buf: hdr } => {
            buf.push(TAR_TAG_HEADER);
            write_u32(buf, *filled);
            write_byte_array(buf, hdr);
        }
        TarMemberState::File {
            remaining,
            padding,
            path,
            total_size,
        } => {
            buf.push(TAR_TAG_FILE);
            write_u64(buf, *remaining);
            write_u32(buf, *padding);
            write_string(buf, path);
            write_u64(buf, *total_size);
        }
        TarMemberState::PaxData {
            remaining,
            padding,
            buf: body,
        } => {
            buf.push(TAR_TAG_PAX);
            write_u64(buf, *remaining);
            write_u32(buf, *padding);
            write_byte_array(buf, body);
        }
        TarMemberState::LongName {
            remaining,
            padding,
            buf: body,
            is_link,
        } => {
            buf.push(TAR_TAG_LONGNAME);
            write_u64(buf, *remaining);
            write_u32(buf, *padding);
            write_byte_array(buf, body);
            buf.push(u8::from(*is_link));
        }
        TarMemberState::Finished => {
            buf.push(TAR_TAG_FINISHED);
        }
    }
}

fn read_u32(bytes: &[u8]) -> u32 {
    // INVARIANT: caller slices a 4-byte window before calling.
    let mut a = [0u8; 4];
    a.copy_from_slice(&bytes[..4]);
    u32::from_le_bytes(a)
}

fn read_u64(bytes: &[u8]) -> u64 {
    // INVARIANT: caller slices an 8-byte window before calling.
    let mut a = [0u8; 8];
    a.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(a)
}

/// Forward-only cursor used while decoding the body. Keeping the
/// reader in a struct lets the per-field `read_*` helpers attach the
/// failing field name to a `Truncated` error.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn require(&mut self, n: usize, field: &str) -> Result<&'a [u8], CheckpointError> {
        if self.remaining() < n {
            return Err(CheckpointError::Truncated {
                reason: format!(
                    "field {field}: needed {n} bytes, only {} available",
                    self.remaining(),
                ),
            });
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, CheckpointError> {
        Ok(self.require(1, field)?[0])
    }

    fn read_u32(&mut self, field: &'static str) -> Result<u32, CheckpointError> {
        Ok(read_u32(self.require(4, field)?))
    }

    fn read_u64(&mut self, field: &'static str) -> Result<u64, CheckpointError> {
        Ok(read_u64(self.require(8, field)?))
    }

    fn read_i64(&mut self, field: &'static str) -> Result<i64, CheckpointError> {
        let bytes = self.require(8, field)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(bytes);
        Ok(i64::from_le_bytes(a))
    }

    fn read_byte_array(&mut self, field: &'static str) -> Result<Vec<u8>, CheckpointError> {
        let len = self.read_u32(field)? as usize;
        let bytes = self.require(len, field)?;
        Ok(bytes.to_vec())
    }

    fn read_string(&mut self, field: &'static str) -> Result<String, CheckpointError> {
        let bytes = self.read_byte_array(field)?;
        String::from_utf8(bytes).map_err(|source| CheckpointError::InvalidUtf8 { field, source })
    }

    /// Like [`Self::read_string`] but takes a runtime-allocated label so
    /// indexed-field error messages can report the index.
    fn read_string_dyn(&mut self, field: &str) -> Result<String, CheckpointError> {
        let len = {
            // Reuse the static-label path for the length read; the
            // composite label only matters when we hit utf-8 issues.
            let len_label: &'static str = "string-len";
            self.read_u32(len_label)? as usize
        };
        let bytes = self.require(len, "string-bytes")?.to_vec();
        String::from_utf8(bytes).map_err(|source| {
            // Promote the dynamic label to a leaked &'static str. We
            // only do this on the error path, and the leak is bounded
            // by the malformed-checkpoint failure: the binary is about
            // to exit with the error.
            let leaked: &'static str = Box::leak(field.to_string().into_boxed_str());
            CheckpointError::InvalidUtf8 {
                field: leaked,
                source,
            }
        })
    }

    fn read_optional_string(
        &mut self,
        field: &'static str,
    ) -> Result<Option<String>, CheckpointError> {
        let presence = self.read_u8(field)?;
        match presence {
            0 => Ok(None),
            1 => self.read_string(field).map(Some),
            other => Err(CheckpointError::InvalidPresence {
                field,
                value: other,
            }),
        }
    }

    fn read_byte_array_capped(
        &mut self,
        field: &'static str,
        cap: u32,
    ) -> Result<Vec<u8>, CheckpointError> {
        let len = self.read_u32(field)?;
        if len > cap {
            return Err(CheckpointError::Truncated {
                reason: format!("{field} length {len} exceeds cap {cap}"),
            });
        }
        let bytes = self.require(len as usize, field)?;
        Ok(bytes.to_vec())
    }
}

fn read_tar_sink_state(cursor: &mut Cursor<'_>) -> Result<TarSinkState, CheckpointError> {
    let archive_offset = cursor.read_u64("sink.tar.in_flight.archive_offset")?;
    let zero_blocks_seen = cursor.read_u8("sink.tar.in_flight.zero_blocks_seen")?;
    let pending_path = cursor.read_optional_string("sink.tar.in_flight.pending_path")?;
    let pending_size = match cursor.read_u8("sink.tar.in_flight.pending_size.is_some")? {
        0 => None,
        1 => Some(cursor.read_u64("sink.tar.in_flight.pending_size.value")?),
        other => {
            return Err(CheckpointError::InvalidPresence {
                field: "sink.tar.in_flight.pending_size",
                value: other,
            });
        }
    };
    let state = read_tar_member_state(cursor)?;
    Ok(TarSinkState {
        archive_offset,
        zero_blocks_seen,
        pending_path,
        pending_size,
        state,
    })
}

fn read_tar_member_state(cursor: &mut Cursor<'_>) -> Result<TarMemberState, CheckpointError> {
    let tag = cursor.read_u8("sink.tar.in_flight.state_tag")?;
    match tag {
        TAR_TAG_HEADER => {
            let filled = cursor.read_u32("sink.tar.in_flight.header.filled")?;
            if filled > 512 {
                return Err(CheckpointError::Truncated {
                    reason: format!("tar header filled {filled} exceeds 512"),
                });
            }
            let buf = cursor.read_byte_array_capped("sink.tar.in_flight.header.buf", 512)?;
            if (buf.len() as u32) != filled {
                return Err(CheckpointError::Truncated {
                    reason: format!(
                        "tar header buf length {} does not match filled {filled}",
                        buf.len(),
                    ),
                });
            }
            Ok(TarMemberState::Header { filled, buf })
        }
        TAR_TAG_FILE => {
            let remaining = cursor.read_u64("sink.tar.in_flight.file.remaining")?;
            let padding = cursor.read_u32("sink.tar.in_flight.file.padding")?;
            if padding >= 512 {
                return Err(CheckpointError::Truncated {
                    reason: format!("tar file padding {padding} ≥ 512"),
                });
            }
            let path = cursor.read_string("sink.tar.in_flight.file.path")?;
            let total_size = cursor.read_u64("sink.tar.in_flight.file.total_size")?;
            if remaining > total_size {
                return Err(CheckpointError::Truncated {
                    reason: format!(
                        "tar file remaining {remaining} exceeds total_size {total_size}",
                    ),
                });
            }
            Ok(TarMemberState::File {
                remaining,
                padding,
                path,
                total_size,
            })
        }
        TAR_TAG_PAX => {
            let remaining = cursor.read_u64("sink.tar.in_flight.pax.remaining")?;
            let padding = cursor.read_u32("sink.tar.in_flight.pax.padding")?;
            if padding >= 512 {
                return Err(CheckpointError::Truncated {
                    reason: format!("tar pax padding {padding} ≥ 512"),
                });
            }
            let buf =
                cursor.read_byte_array_capped("sink.tar.in_flight.pax.buf", MAX_TAR_BUFFER_LEN)?;
            Ok(TarMemberState::PaxData {
                remaining,
                padding,
                buf,
            })
        }
        TAR_TAG_LONGNAME => {
            let remaining = cursor.read_u64("sink.tar.in_flight.longname.remaining")?;
            let padding = cursor.read_u32("sink.tar.in_flight.longname.padding")?;
            if padding >= 512 {
                return Err(CheckpointError::Truncated {
                    reason: format!("tar longname padding {padding} ≥ 512"),
                });
            }
            let buf = cursor
                .read_byte_array_capped("sink.tar.in_flight.longname.buf", MAX_TAR_BUFFER_LEN)?;
            let is_link = match cursor.read_u8("sink.tar.in_flight.longname.is_link")? {
                0 => false,
                1 => true,
                other => {
                    return Err(CheckpointError::InvalidPresence {
                        field: "sink.tar.in_flight.longname.is_link",
                        value: other,
                    });
                }
            };
            Ok(TarMemberState::LongName {
                remaining,
                padding,
                buf,
                is_link,
            })
        }
        TAR_TAG_FINISHED => Ok(TarMemberState::Finished),
        other => Err(CheckpointError::InvalidEnumTag {
            field: "sink.tar.in_flight.state_tag",
            tag: other,
        }),
    }
}

/// 64-bit FNV-1a hash. Hand-rolled because the dependency policy
/// (`docs/ENGINEERING_STANDARDS.md` §2) says "anything we can write in
/// 50 lines should be written, not depended on" and a checksum used
/// only for tamper detection on a tiny file does not justify a crate.
///
/// We are not using FNV-1a as a cryptographic hash; collisions on
/// adversarial input are possible. The threat model is corrupted
/// disk blocks, partial writes, and accidental modification — all of
/// which FNV-1a detects with overwhelming probability for a body
/// bounded by [`MAX_BODY_LEN`].
fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xCBF2_9CE4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01B3;
    let mut hash = OFFSET;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Encode `t` as `(secs_since_epoch, nanos)`. Times before `UNIX_EPOCH`
/// produce a negative `secs`.
fn encode_system_time(t: SystemTime) -> (i64, u32) {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (
            i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            d.subsec_nanos(),
        ),
        Err(e) => {
            let d = e.duration();
            // Pre-epoch: store a negative seconds value with positive
            // sub-second remainder, matching the BSD `timespec` shape.
            let secs = i64::try_from(d.as_secs())
                .unwrap_or(i64::MAX)
                .saturating_neg();
            (secs, d.subsec_nanos())
        }
    }
}

/// Decode `(secs, nanos)` back into a [`SystemTime`]. Saturates to
/// [`UNIX_EPOCH`] on negative seconds rather than returning an error;
/// the timestamp is diagnostic only and a "before-epoch" round-trip
/// is not load-bearing for resume.
fn decode_system_time(secs: i64, nanos: u32) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH
            .checked_add(Duration::new(secs as u64, nanos))
            .unwrap_or(UNIX_EPOCH)
    } else {
        let abs = secs.unsigned_abs();
        UNIX_EPOCH
            .checked_sub(Duration::new(abs, nanos))
            .unwrap_or(UNIX_EPOCH)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static UNIQ: AtomicU64 = AtomicU64::new(0);

    fn unique_temp(label: &str) -> PathBuf {
        let pid = std::process::id();
        let n = UNIQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("peel_checkpoint_unit_{label}_{pid}_{nanos}_{n}"))
    }

    struct CleanupOnDrop(PathBuf);
    impl Drop for CleanupOnDrop {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
            let tmp = tmp_path_for(&self.0);
            let _ = fs::remove_file(&tmp);
        }
    }

    fn sample_raw() -> Checkpoint {
        Checkpoint {
            url: "https://example.com/file.zst".into(),
            etag: Some("\"v1\"".into()),
            last_modified: None,
            total_size: 1_048_576,
            chunk_size: 65_536,
            decoder_position: ByteOffset::new(32_768),
            bitmap_completed: vec![0xFFu8; 16],
            created_at: UNIX_EPOCH + Duration::new(1_700_000_000, 12_345),
            sink_state: SinkState::Raw {
                bytes_written: 4096,
            },
            hash_state: None,
            chunk_crc32c: None,
            decoder_state: None,
        }
    }

    fn sample_tar() -> Checkpoint {
        Checkpoint {
            url: "http://localhost:8080/data.tar.zst".into(),
            etag: None,
            last_modified: Some("Wed, 21 Oct 2026 07:28:00 GMT".into()),
            total_size: u64::MAX / 2,
            chunk_size: 4 * 1024 * 1024,
            decoder_position: ByteOffset::new(8 * 1024 * 1024),
            bitmap_completed: (0u8..=255).collect(),
            created_at: SystemTime::now(),
            sink_state: SinkState::Tar {
                members_completed: vec![
                    "root/a.txt".into(),
                    "root/sub/b.bin".into(),
                    "root/empty/".into(),
                ],
                in_flight: None,
            },
            hash_state: None,
            chunk_crc32c: None,
            decoder_state: None,
        }
    }

    // ---- magic / framing ---------------------------------------------

    #[test]
    fn header_layout_starts_with_magic_and_version() {
        let bytes = sample_raw().serialize();
        assert_eq!(&bytes[0..8], &MAGIC);
        let version = read_u32(&bytes[8..12]);
        assert_eq!(version, FORMAT_VERSION);
    }

    #[test]
    fn header_records_body_length_and_checksum() {
        let bytes = sample_raw().serialize();
        let body_len = read_u64(&bytes[12..20]) as usize;
        let body_checksum = read_u64(&bytes[20..28]);
        assert_eq!(bytes.len(), HEADER_LEN + body_len);
        assert_eq!(fnv1a64(&bytes[HEADER_LEN..]), body_checksum);
    }

    // ---- round-trip --------------------------------------------------

    #[test]
    fn round_trip_raw_sink() {
        let original = sample_raw();
        let bytes = original.serialize();
        let parsed = Checkpoint::deserialize(&bytes).expect("decode");
        assert_eq!(parsed, original);
    }

    #[test]
    fn round_trip_tar_sink() {
        let original = sample_tar();
        let bytes = original.serialize();
        let parsed = Checkpoint::deserialize(&bytes).expect("decode");
        assert_eq!(parsed, original);
    }

    fn sample_zip(current: Option<u32>, current_offset: u64) -> Checkpoint {
        Checkpoint {
            url: "https://example.com/archive.zip".into(),
            etag: Some("\"v9\"".into()),
            last_modified: None,
            total_size: 9_876_543,
            chunk_size: 4 * 1024 * 1024,
            decoder_position: ByteOffset::new(0),
            bitmap_completed: vec![0xCC; 8],
            created_at: UNIX_EPOCH + Duration::new(1_700_000_000, 0),
            sink_state: SinkState::Zip {
                entries_completed: vec![0, 1, 2, 5, 7],
                current_entry: current,
                current_entry_offset: current_offset,
                current_entry_decoder_state: None,
            },
            hash_state: None,
            chunk_crc32c: None,
            decoder_state: None,
        }
    }

    #[test]
    fn round_trip_zip_sink_quiescent() {
        let original = sample_zip(None, 0);
        let bytes = original.serialize();
        let parsed = Checkpoint::deserialize(&bytes).expect("decode");
        assert_eq!(parsed, original);
    }

    #[test]
    fn round_trip_zip_sink_mid_entry() {
        let original = sample_zip(Some(8), 1_234_567);
        let bytes = original.serialize();
        let parsed = Checkpoint::deserialize(&bytes).expect("decode");
        assert_eq!(parsed, original);
    }

    #[test]
    fn round_trip_zip_sink_no_completed_entries() {
        // Edge case: zero completed entries with a current_entry
        // mid-flight. Exercises the empty-vec encoding.
        let mut ckpt = sample_zip(Some(0), 100);
        if let SinkState::Zip {
            entries_completed, ..
        } = &mut ckpt.sink_state
        {
            entries_completed.clear();
        }
        let parsed = Checkpoint::deserialize(&ckpt.serialize()).expect("decode");
        assert_eq!(parsed, ckpt);
    }

    #[test]
    fn checkpoint_format_version_is_seven() {
        // Sanity: PLAN_v2 §10 step 4 (v3), §11 step 1 (v4),
        // OPTIMIZATIONS.md §O.7b (v5), the tar mid-member resume
        // work (v6), and `docs/PLAN_deflate_block_decoder.md`
        // Phase 9b's zip per-entry decoder-state field (v7) each
        // bumped this when an optional trailer landed. If a
        // future change resets it, this guards against silently
        // dropping the upgrade-required signal older readers
        // depend on.
        assert_eq!(FORMAT_VERSION, 7);
    }

    fn build_legacy_body_raw_sink() -> Vec<u8> {
        // Hand-build the v1 / v2 body for a `Raw`-sink checkpoint
        // — same layout as v3 *minus* the trailing hash_state byte.
        let mut body = Vec::new();
        write_string(&mut body, "https://example.com/file.zst");
        write_optional_string(&mut body, Some("\"v1\""));
        write_optional_string(&mut body, None);
        write_u64(&mut body, 1_048_576);
        write_u64(&mut body, 65_536);
        write_u64(&mut body, 32_768);
        write_byte_array(&mut body, &[0xFFu8; 16]);
        write_i64(&mut body, 1_700_000_000);
        write_u32(&mut body, 12_345);
        body.push(SINK_TAG_RAW);
        write_u64(&mut body, 4096);
        body
    }

    fn frame_legacy_body(body: &[u8], version: u32) -> Vec<u8> {
        let body_len = body.len() as u64;
        let body_checksum = fnv1a64(body);
        let mut buf = Vec::with_capacity(HEADER_LEN + body.len());
        buf.extend_from_slice(&MAGIC);
        write_u32(&mut buf, version);
        write_u64(&mut buf, body_len);
        write_u64(&mut buf, body_checksum);
        buf.extend_from_slice(body);
        buf
    }

    #[test]
    fn v1_checkpoint_bytes_still_parse_after_version_bump() {
        // Construct a literal v1 wire image and verify the v3 reader
        // parses it transparently (with `hash_state = None`).
        let body = build_legacy_body_raw_sink();
        let bytes = frame_legacy_body(&body, 1);
        let parsed = Checkpoint::deserialize(&bytes).expect("v1 still parses");
        assert_eq!(parsed.url, "https://example.com/file.zst");
        assert_eq!(parsed.etag.as_deref(), Some("\"v1\""));
        assert_eq!(parsed.total_size, 1_048_576);
        assert!(parsed.hash_state.is_none());
    }

    #[test]
    fn v2_checkpoint_bytes_still_parse_after_version_bump() {
        // Same shape — a v2 file that predates the hash_state
        // trailer must still load with `hash_state = None`.
        let body = build_legacy_body_raw_sink();
        let bytes = frame_legacy_body(&body, 2);
        let parsed = Checkpoint::deserialize(&bytes).expect("v2 still parses");
        assert!(parsed.hash_state.is_none());
    }

    #[test]
    fn v3_checkpoint_bytes_still_parse_after_v5_bump() {
        // A v3 file (raw sink, hash_state = None) must still load
        // under the v5 reader with both `chunk_crc32c` and
        // `decoder_state` defaulted to `None`.
        let mut body = build_legacy_body_raw_sink();
        body.push(0); // hash_state = None
        let bytes = frame_legacy_body(&body, 3);
        let parsed = Checkpoint::deserialize(&bytes).expect("v3 still parses");
        assert!(parsed.hash_state.is_none());
        assert!(parsed.chunk_crc32c.is_none());
        assert!(parsed.decoder_state.is_none());
    }

    #[test]
    fn v4_checkpoint_bytes_still_parse_after_v5_bump() {
        // A v4 file (raw sink, hash_state and chunk_crc32c both
        // None) must still load under the v5 reader with
        // `decoder_state = None`.
        let mut body = build_legacy_body_raw_sink();
        body.push(0); // hash_state = None
        body.push(0); // chunk_crc32c = None
        let bytes = frame_legacy_body(&body, 4);
        let parsed = Checkpoint::deserialize(&bytes).expect("v4 still parses");
        assert!(parsed.hash_state.is_none());
        assert!(parsed.chunk_crc32c.is_none());
        assert!(parsed.decoder_state.is_none());
    }

    #[test]
    fn v5_checkpoint_bytes_still_parse_after_v6_bump() {
        // A v5 file (raw sink, all trailing optionals = None) must
        // still load under the v6 reader. The Tar in_flight field
        // is v6-only so a Raw v5 file doesn't exercise it; we test
        // it separately below with a hand-built v5 Tar body.
        let mut body = build_legacy_body_raw_sink();
        body.push(0); // hash_state
        body.push(0); // chunk_crc32c
        body.push(0); // decoder_state (v5)
        let bytes = frame_legacy_body(&body, 5);
        let parsed = Checkpoint::deserialize(&bytes).expect("v5 still parses");
        assert!(parsed.decoder_state.is_none());
    }

    #[test]
    fn v5_tar_body_parses_with_in_flight_none() {
        // Hand-build a v5 Tar body (no in_flight trailer) and
        // verify the v6 reader fills `in_flight: None`.
        let mut body = Vec::new();
        write_string(&mut body, "https://example.com/x.tar.zst");
        write_optional_string(&mut body, None);
        write_optional_string(&mut body, None);
        write_u64(&mut body, 1024);
        write_u64(&mut body, 64);
        write_u64(&mut body, 0);
        write_byte_array(&mut body, &[0xFFu8; 4]);
        write_i64(&mut body, 1_700_000_000);
        write_u32(&mut body, 0);
        body.push(SINK_TAG_TAR);
        write_u32(&mut body, 0); // members_completed empty
        body.push(0); // hash_state
        body.push(0); // chunk_crc32c
        body.push(0); // decoder_state

        let bytes = frame_legacy_body(&body, 5);
        let parsed = Checkpoint::deserialize(&bytes).expect("v5 tar parses");
        match parsed.sink_state {
            SinkState::Tar { in_flight, .. } => assert!(in_flight.is_none()),
            other => panic!("expected Tar, got {other:?}"),
        }
    }

    #[test]
    fn v6_zip_body_parses_with_decoder_state_none() {
        // Hand-build a v6 Zip body (with current_entry mid-flight,
        // no v7 decoder-state trailer) and verify the v7 reader
        // fills `current_entry_decoder_state: None`. Pins
        // backward-compat for the Phase-9b format bump.
        let mut body = Vec::new();
        write_string(&mut body, "https://example.com/x.zip");
        write_optional_string(&mut body, None);
        write_optional_string(&mut body, None);
        write_u64(&mut body, 1024);
        write_u64(&mut body, 64);
        write_u64(&mut body, 0);
        write_byte_array(&mut body, &[0xFFu8; 4]);
        write_i64(&mut body, 1_700_000_000);
        write_u32(&mut body, 0);
        body.push(SINK_TAG_ZIP);
        // entries_completed = [0, 1]
        write_u32(&mut body, 2);
        write_u32(&mut body, 0);
        write_u32(&mut body, 1);
        // current_entry = Some(2)
        body.push(1);
        write_u32(&mut body, 2);
        // current_entry_offset = 12_345
        write_u64(&mut body, 12_345);
        // v6 ends here for Zip (no v7 decoder_state trailer).
        // Trailing v3 / v4 / v5 optionals.
        body.push(0); // hash_state
        body.push(0); // chunk_crc32c
        body.push(0); // checkpoint-level decoder_state

        let bytes = frame_legacy_body(&body, 6);
        let parsed = Checkpoint::deserialize(&bytes).expect("v6 zip parses under v7 reader");
        match parsed.sink_state {
            SinkState::Zip {
                current_entry,
                current_entry_offset,
                current_entry_decoder_state,
                ..
            } => {
                assert_eq!(current_entry, Some(2));
                assert_eq!(current_entry_offset, 12_345);
                assert!(
                    current_entry_decoder_state.is_none(),
                    "v6 readers shouldn't conjure a decoder-state blob"
                );
            }
            other => panic!("expected Zip, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_tar_in_flight_file_state() {
        // Capture-mid-file is the load-bearing v6 case. The
        // resumed sink reopens the path at offset
        // `total_size - remaining` and continues; the on-disk
        // serialization round-trips exactly.
        let mut ckpt = sample_tar();
        match &mut ckpt.sink_state {
            SinkState::Tar { in_flight, .. } => {
                *in_flight = Some(TarSinkState {
                    archive_offset: 1_234_567,
                    zero_blocks_seen: 0,
                    pending_path: Some("pax-overrides-this-name".into()),
                    pending_size: Some(987_654_321),
                    state: TarMemberState::File {
                        remaining: 100_000,
                        padding: 384,
                        path: "deep/nested/file.bin".into(),
                        total_size: 500_000,
                    },
                });
            }
            _ => panic!("sample_tar should produce Tar"),
        }
        let parsed = Checkpoint::deserialize(&ckpt.serialize()).expect("decode");
        assert_eq!(parsed, ckpt);
    }

    #[test]
    fn round_trip_tar_in_flight_pax_state() {
        let mut ckpt = sample_tar();
        match &mut ckpt.sink_state {
            SinkState::Tar { in_flight, .. } => {
                *in_flight = Some(TarSinkState {
                    archive_offset: 42,
                    zero_blocks_seen: 0,
                    pending_path: None,
                    pending_size: None,
                    state: TarMemberState::PaxData {
                        remaining: 256,
                        padding: 256,
                        buf: b"path=overlong/path.bin\nsize=12345\n".to_vec(),
                    },
                });
            }
            _ => panic!("sample_tar should produce Tar"),
        }
        let parsed = Checkpoint::deserialize(&ckpt.serialize()).expect("decode");
        assert_eq!(parsed, ckpt);
    }

    #[test]
    fn deserialize_rejects_tar_header_filled_over_512() {
        let mut ckpt = sample_tar();
        match &mut ckpt.sink_state {
            SinkState::Tar { in_flight, .. } => {
                *in_flight = Some(TarSinkState {
                    archive_offset: 0,
                    zero_blocks_seen: 0,
                    pending_path: None,
                    pending_size: None,
                    state: TarMemberState::Header {
                        filled: 0,
                        buf: Vec::new(),
                    },
                });
            }
            _ => panic!(),
        }
        let mut bytes = ckpt.serialize();
        // Find the `filled` field: it is the u32 immediately after
        // the in-flight presence byte. Trick is finding that byte —
        // serialize layout is deterministic but long; cheaper to
        // re-serialize with filled = 1024 directly. Construct a
        // poisoned blob via deserialize → mutate → reserialize is
        // also OK; do it inline.
        // We poke the SinkState::Tar::in_flight `filled` field by
        // searching for the magic 0u32 that should be `filled` = 0.
        // Since the body precedes it with a Header tag (0x00) and
        // the serialized layout has many zero bytes, just use a
        // structured re-serialization instead.
        let _ = &mut bytes;
        // Simpler: directly serialize a poisoned blob via the
        // helper with filled = 1024 (out of range).
        let mut body = Vec::new();
        write_tar_member_state(
            &mut body,
            &TarMemberState::Header {
                filled: 1024, // > 512: must be rejected
                buf: vec![0u8; 0],
            },
        );
        // Try to deserialize that one-off blob.
        let mut cursor = Cursor::new(&body);
        match read_tar_member_state(&mut cursor) {
            Err(CheckpointError::Truncated { reason }) => {
                assert!(reason.contains("filled"), "reason: {reason}");
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_with_hash_state_present() {
        let mut state = crate::hash::sha256::Sha256::new();
        state.update(b"hello world");
        let serialized = state.serialize();
        let mut ckpt = sample_raw();
        ckpt.hash_state = Some(serialized);

        let parsed = Checkpoint::deserialize(&ckpt.serialize()).expect("decode");
        assert_eq!(parsed, ckpt);
        let bytes = parsed.hash_state.expect("present");
        assert_eq!(bytes, serialized);
    }

    #[test]
    fn rejects_invalid_hash_state_presence_byte() {
        // Build a valid v5 body with all trailing flags absent
        // (hash_state at -3, chunk_crc32c at -2, decoder_state at
        // -1) and poke the hash_state byte specifically.
        let mut bytes = sample_raw().serialize();
        let hash_state_byte = bytes.len() - 3;
        bytes[hash_state_byte] = 7;
        // Recompute the body checksum so the integrity check
        // doesn't fire first.
        let body_start = HEADER_LEN;
        let new_checksum = fnv1a64(&bytes[body_start..]);
        bytes[20..28].copy_from_slice(&new_checksum.to_le_bytes());

        match Checkpoint::deserialize(&bytes).unwrap_err() {
            CheckpointError::InvalidPresence { value, field } => {
                assert_eq!(value, 7);
                assert_eq!(field, "hash_state");
            }
            other => panic!("expected InvalidPresence(hash_state), got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_chunk_crc32c_presence_byte() {
        // Build a valid v5 body and poke the chunk_crc32c presence
        // byte (offset -2; decoder_state lives at -1) to an
        // out-of-range value.
        let mut bytes = sample_raw().serialize();
        let crc_byte = bytes.len() - 2;
        bytes[crc_byte] = 5;
        let body_start = HEADER_LEN;
        let new_checksum = fnv1a64(&bytes[body_start..]);
        bytes[20..28].copy_from_slice(&new_checksum.to_le_bytes());

        match Checkpoint::deserialize(&bytes).unwrap_err() {
            CheckpointError::InvalidPresence { value, field } => {
                assert_eq!(value, 5);
                assert_eq!(field, "chunk_crc32c");
            }
            other => panic!("expected InvalidPresence(chunk_crc32c), got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_decoder_state_presence_byte() {
        // Poke the trailing decoder_state presence byte (offset -1)
        // to an out-of-range value; recompute the checksum so
        // integrity doesn't fire first.
        let mut bytes = sample_raw().serialize();
        let last = bytes.len() - 1;
        bytes[last] = 9;
        let body_start = HEADER_LEN;
        let new_checksum = fnv1a64(&bytes[body_start..]);
        bytes[20..28].copy_from_slice(&new_checksum.to_le_bytes());

        match Checkpoint::deserialize(&bytes).unwrap_err() {
            CheckpointError::InvalidPresence { value, field } => {
                assert_eq!(value, 9);
                assert_eq!(field, "decoder_state");
            }
            other => panic!("expected InvalidPresence(decoder_state), got {other:?}"),
        }
    }

    #[test]
    fn round_trip_with_decoder_state_present() {
        let mut ckpt = sample_raw();
        ckpt.decoder_state = Some(vec![0xDE, 0xAD, 0xBE, 0xEF, 0x42, 0x00, 0x01]);
        let parsed = Checkpoint::deserialize(&ckpt.serialize()).expect("decode");
        assert_eq!(parsed, ckpt);
    }

    #[test]
    fn rejects_decoder_state_blob_over_cap() {
        // Hand-build a v5 body that declares a decoder_state length
        // exceeding MAX_DECODER_STATE_LEN. The deserializer must
        // surface a Truncated error before allocating the blob.
        let mut bytes = sample_raw().serialize();
        // Strip the trailing `decoder_state = None` byte (0x00) and
        // replace it with `presence = 1` + `len = MAX + 1`.
        bytes.truncate(bytes.len() - 1);
        bytes.push(1u8);
        let len = MAX_DECODER_STATE_LEN + 1;
        bytes.extend_from_slice(&len.to_le_bytes());
        // Update body_len in the header; recompute the checksum.
        let new_body_len = (bytes.len() - HEADER_LEN) as u64;
        bytes[12..20].copy_from_slice(&new_body_len.to_le_bytes());
        let body_start = HEADER_LEN;
        let new_checksum = fnv1a64(&bytes[body_start..]);
        bytes[20..28].copy_from_slice(&new_checksum.to_le_bytes());

        match Checkpoint::deserialize(&bytes).unwrap_err() {
            CheckpointError::Truncated { reason } => {
                assert!(
                    reason.contains("decoder_state length"),
                    "unexpected reason: {reason}",
                );
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_with_chunk_crc32c_present() {
        let mut ckpt = sample_raw();
        ckpt.chunk_crc32c = Some(vec![0xDEAD_BEEF, 0xCAFE_F00D, 0x1234_5678]);
        let parsed = Checkpoint::deserialize(&ckpt.serialize()).expect("decode");
        assert_eq!(parsed, ckpt);
    }

    #[test]
    fn round_trip_with_unicode_strings() {
        let mut ckpt = sample_raw();
        ckpt.url = "https://例え.test/データ.zst".into();
        ckpt.etag = Some("\"日本語✓\"".into());
        let parsed = Checkpoint::deserialize(&ckpt.serialize()).expect("decode");
        assert_eq!(parsed, ckpt);
    }

    #[test]
    fn round_trip_empty_strings_and_bitmap() {
        let ckpt = Checkpoint {
            url: String::new(),
            etag: Some(String::new()),
            last_modified: Some(String::new()),
            total_size: 0,
            chunk_size: 0,
            decoder_position: ByteOffset::ZERO,
            bitmap_completed: Vec::new(),
            created_at: UNIX_EPOCH,
            sink_state: SinkState::Tar {
                members_completed: Vec::new(),
                in_flight: None,
            },
            hash_state: None,
            chunk_crc32c: None,
            decoder_state: None,
        };
        let parsed = Checkpoint::deserialize(&ckpt.serialize()).expect("decode");
        assert_eq!(parsed, ckpt);
    }

    // ---- error paths -------------------------------------------------

    #[test]
    fn rejects_short_buffer() {
        match Checkpoint::deserialize(&[]).unwrap_err() {
            CheckpointError::Truncated { .. } => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = sample_raw().serialize();
        bytes[0..8].copy_from_slice(b"notpeel!");
        match Checkpoint::deserialize(&bytes).unwrap_err() {
            CheckpointError::BadMagic { found } => assert_eq!(&found, b"notpeel!"),
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn rejects_newer_format_version() {
        let mut bytes = sample_raw().serialize();
        // Bump the version field to one beyond what we support.
        let newer = (FORMAT_VERSION + 7).to_le_bytes();
        bytes[8..12].copy_from_slice(&newer);
        // The body checksum is now over a body that no longer matches
        // the version, but the version check fires first.
        match Checkpoint::deserialize(&bytes).unwrap_err() {
            CheckpointError::UnsupportedVersion {
                found,
                supported_max,
            } => {
                assert_eq!(found, FORMAT_VERSION + 7);
                assert_eq!(supported_max, FORMAT_VERSION);
            }
            other => panic!("expected UnsupportedVersion, got {other:?}"),
        }
    }

    #[test]
    fn rejects_corrupted_body_via_checksum() {
        let mut bytes = sample_raw().serialize();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        match Checkpoint::deserialize(&bytes).unwrap_err() {
            CheckpointError::BodyChecksumMismatch { .. } => {}
            other => panic!("expected BodyChecksumMismatch, got {other:?}"),
        }
    }

    #[test]
    fn rejects_truncated_body() {
        let bytes = sample_raw().serialize();
        // Drop the last few bytes; deserialize must report the body
        // is shorter than the header claimed.
        let truncated = &bytes[..bytes.len() - 4];
        match Checkpoint::deserialize(truncated).unwrap_err() {
            CheckpointError::Truncated { .. } => {}
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn rejects_oversize_body_length_field() {
        // Synthesize a header that claims an absurd body length.
        let mut bytes = vec![0u8; HEADER_LEN];
        bytes[0..8].copy_from_slice(&MAGIC);
        bytes[8..12].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        bytes[12..20].copy_from_slice(&(MAX_BODY_LEN + 1).to_le_bytes());
        // checksum field can be anything; the cap check fires first.
        match Checkpoint::deserialize(&bytes).unwrap_err() {
            CheckpointError::BodyTooLarge { found, cap } => {
                assert_eq!(found, MAX_BODY_LEN + 1);
                assert_eq!(cap, MAX_BODY_LEN);
            }
            other => panic!("expected BodyTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_sink_tag() {
        // Build a body that has every field up to a bogus sink tag,
        // then re-frame.
        let mut body = Vec::new();
        write_string(&mut body, "u");
        write_optional_string(&mut body, None);
        write_optional_string(&mut body, None);
        write_u64(&mut body, 0);
        write_u64(&mut body, 0);
        write_u64(&mut body, 0);
        write_byte_array(&mut body, &[]);
        write_i64(&mut body, 0);
        write_u32(&mut body, 0);
        body.push(0xFE); // unknown tag

        let body_len = body.len() as u64;
        let body_checksum = fnv1a64(&body);

        let mut buf = Vec::with_capacity(HEADER_LEN + body.len());
        buf.extend_from_slice(&MAGIC);
        write_u32(&mut buf, FORMAT_VERSION);
        write_u64(&mut buf, body_len);
        write_u64(&mut buf, body_checksum);
        buf.extend_from_slice(&body);

        match Checkpoint::deserialize(&buf).unwrap_err() {
            CheckpointError::InvalidEnumTag { tag, .. } => assert_eq!(tag, 0xFE),
            other => panic!("expected InvalidEnumTag, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_presence_byte() {
        // url = "u", etag presence = 5 (invalid).
        let mut body = Vec::new();
        write_string(&mut body, "u");
        body.push(5);

        let body_len = body.len() as u64;
        let body_checksum = fnv1a64(&body);

        let mut buf = Vec::with_capacity(HEADER_LEN + body.len());
        buf.extend_from_slice(&MAGIC);
        write_u32(&mut buf, FORMAT_VERSION);
        write_u64(&mut buf, body_len);
        write_u64(&mut buf, body_checksum);
        buf.extend_from_slice(&body);

        match Checkpoint::deserialize(&buf).unwrap_err() {
            CheckpointError::InvalidPresence { value, .. } => assert_eq!(value, 5),
            other => panic!("expected InvalidPresence, got {other:?}"),
        }
    }

    #[test]
    fn rejects_trailing_bytes_in_body() {
        let mut bytes = sample_raw().serialize();
        // Append one extra byte in the body and update length+checksum
        // so that only the trailing-bytes guard fires.
        let body_start = HEADER_LEN;
        let mut body = bytes[body_start..].to_vec();
        body.push(0xAA);
        let new_len = body.len() as u64;
        let new_checksum = fnv1a64(&body);
        bytes.truncate(body_start);
        bytes.extend_from_slice(&body);
        bytes[12..20].copy_from_slice(&new_len.to_le_bytes());
        bytes[20..28].copy_from_slice(&new_checksum.to_le_bytes());

        match Checkpoint::deserialize(&bytes).unwrap_err() {
            CheckpointError::Truncated { reason } => {
                assert!(reason.contains("trailing"), "unexpected reason: {reason}");
            }
            other => panic!("expected Truncated, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_utf8() {
        // url declared as 2 bytes of invalid UTF-8 (0xFF 0xFF).
        let mut body = Vec::new();
        write_u32(&mut body, 2);
        body.extend_from_slice(&[0xFF, 0xFF]);
        // Pad the rest of v1 with valid zero defaults.
        write_optional_string(&mut body, None);
        write_optional_string(&mut body, None);
        write_u64(&mut body, 0);
        write_u64(&mut body, 0);
        write_u64(&mut body, 0);
        write_byte_array(&mut body, &[]);
        write_i64(&mut body, 0);
        write_u32(&mut body, 0);
        body.push(SINK_TAG_RAW);
        write_u64(&mut body, 0);

        let body_len = body.len() as u64;
        let body_checksum = fnv1a64(&body);

        let mut buf = Vec::with_capacity(HEADER_LEN + body.len());
        buf.extend_from_slice(&MAGIC);
        write_u32(&mut buf, FORMAT_VERSION);
        write_u64(&mut buf, body_len);
        write_u64(&mut buf, body_checksum);
        buf.extend_from_slice(&body);

        match Checkpoint::deserialize(&buf).unwrap_err() {
            CheckpointError::InvalidUtf8 { field, .. } => assert_eq!(field, "url"),
            other => panic!("expected InvalidUtf8, got {other:?}"),
        }
    }

    // ---- atomic write/read ------------------------------------------

    #[test]
    fn write_then_read_round_trips_via_disk() {
        let path = unique_temp("roundtrip");
        let _g = CleanupOnDrop(path.clone());
        let original = sample_tar();

        original.write(&path).expect("write");
        let parsed = Checkpoint::read(&path).expect("read").expect("present");
        assert_eq!(parsed, original);

        // Tmp file must not linger after a successful rename.
        assert!(!tmp_path_for(&path).exists(), "tmp file lingered");
    }

    #[test]
    fn read_returns_none_when_path_missing() {
        let path = unique_temp("missing");
        // No CleanupOnDrop — file does not exist.
        let parsed = Checkpoint::read(&path).expect("read");
        assert!(parsed.is_none());
    }

    #[test]
    fn write_overwrites_existing_checkpoint_atomically() {
        let path = unique_temp("overwrite");
        let _g = CleanupOnDrop(path.clone());
        let first = sample_raw();
        first.write(&path).expect("first write");

        let second = sample_tar();
        second.write(&path).expect("second write");

        let parsed = Checkpoint::read(&path).expect("read").expect("present");
        assert_eq!(parsed, second);
    }

    #[test]
    fn stale_tmp_file_is_overwritten_by_next_write() {
        // Simulate a crashed previous run: a partial .tmp on disk and
        // no .ckpt yet. The next write must succeed.
        let path = unique_temp("stale-tmp");
        let _g = CleanupOnDrop(path.clone());
        let tmp = tmp_path_for(&path);
        fs::write(&tmp, b"\xDE\xAD\xBE\xEF garbage from crashed run").unwrap();

        let ckpt = sample_raw();
        ckpt.write(&path).expect("write");
        let parsed = Checkpoint::read(&path).expect("read").expect("present");
        assert_eq!(parsed, ckpt);
        assert!(!tmp.exists(), "tmp survived overwrite");
    }

    #[test]
    fn read_propagates_corrupt_files_as_typed_error() {
        let path = unique_temp("corrupt");
        let _g = CleanupOnDrop(path.clone());
        // Write a valid-looking but corrupted checkpoint: flip one byte
        // in the body.
        let mut bytes = sample_raw().serialize();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x80;
        fs::write(&path, &bytes).unwrap();

        match Checkpoint::read(&path).unwrap_err() {
            CheckpointError::BodyChecksumMismatch { .. } => {}
            other => panic!("expected BodyChecksumMismatch, got {other:?}"),
        }
    }

    // ---- property-style: random round-trips --------------------------

    /// Tiny LCG (matches the pattern used elsewhere in the crate; keeps
    /// the dependency tree free of a PRNG crate).
    struct Lcg(u64);

    impl Lcg {
        fn seeded(seed: u64) -> Self {
            Self(seed ^ 0x9E37_79B9_7F4A_7C15)
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            self.0
        }
        fn next_u32(&mut self) -> u32 {
            (self.next_u64() >> 32) as u32
        }
        fn next_bool(&mut self) -> bool {
            self.next_u64() & 1 == 1
        }
    }

    fn random_string(rng: &mut Lcg, max_len: usize) -> String {
        let len = (rng.next_u32() as usize) % (max_len + 1);
        let mut s = String::with_capacity(len);
        while s.len() < len {
            // Stay inside ASCII to keep the generator simple; we have a
            // dedicated unicode test for non-ASCII.
            let c = (rng.next_u64() % 94 + 33) as u8 as char;
            s.push(c);
        }
        s
    }

    fn random_bytes(rng: &mut Lcg, max_len: usize) -> Vec<u8> {
        let len = (rng.next_u32() as usize) % (max_len + 1);
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            out.extend_from_slice(&rng.next_u64().to_le_bytes());
        }
        out.truncate(len);
        out
    }

    #[test]
    fn property_round_trip_random_checkpoints() {
        let mut rng = Lcg::seeded(0xC0DE_C0DE);
        for _ in 0..256 {
            let url = random_string(&mut rng, 128);
            let etag = if rng.next_bool() {
                Some(random_string(&mut rng, 32))
            } else {
                None
            };
            let last_modified = if rng.next_bool() {
                Some(random_string(&mut rng, 32))
            } else {
                None
            };
            let total_size = rng.next_u64();
            let chunk_size = rng.next_u64();
            let decoder_position = ByteOffset::new(rng.next_u64());
            let bitmap_completed = random_bytes(&mut rng, 1024);
            let created_at = UNIX_EPOCH + Duration::new(rng.next_u64() % 4_000_000_000, 12_345);

            let sink_state = match rng.next_u32() % 3 {
                0 => SinkState::Raw {
                    bytes_written: rng.next_u64(),
                },
                1 => {
                    let n = (rng.next_u32() as usize) % 8;
                    let members = (0..n).map(|_| random_string(&mut rng, 64)).collect();
                    // Property test exercises both `in_flight =
                    // None` (the v6 quiescent path) and a few
                    // hand-built non-trivial states; structured
                    // round-trip tests below cover File / PaxData /
                    // LongName variants directly.
                    let in_flight = if rng.next_bool() {
                        let archive_offset = rng.next_u64();
                        let zero_blocks_seen = (rng.next_u32() & 0xFF) as u8;
                        let pending_path = if rng.next_bool() {
                            Some(random_string(&mut rng, 32))
                        } else {
                            None
                        };
                        let pending_size = if rng.next_bool() {
                            Some(rng.next_u64())
                        } else {
                            None
                        };
                        let header_buf = random_bytes(&mut rng, 512);
                        // `filled == buf.len()` is the deserialize
                        // invariant; bind them together here.
                        Some(TarSinkState {
                            archive_offset,
                            zero_blocks_seen,
                            pending_path,
                            pending_size,
                            state: TarMemberState::Header {
                                filled: header_buf.len() as u32,
                                buf: header_buf,
                            },
                        })
                    } else {
                        None
                    };
                    SinkState::Tar {
                        members_completed: members,
                        in_flight,
                    }
                }
                _ => {
                    let count = (rng.next_u32() as usize) % 16;
                    let entries = (0..count).map(|_| rng.next_u32()).collect();
                    let current = if rng.next_bool() {
                        Some(rng.next_u32())
                    } else {
                        None
                    };
                    let blob_present = rng.next_u32() & 1 == 0;
                    let current_entry_decoder_state = if blob_present {
                        let len = (rng.next_u32() % 64) as usize;
                        let mut blob = Vec::with_capacity(len);
                        for _ in 0..len {
                            blob.push((rng.next_u32() & 0xFF) as u8);
                        }
                        Some(blob)
                    } else {
                        None
                    };
                    SinkState::Zip {
                        entries_completed: entries,
                        current_entry: current,
                        current_entry_offset: rng.next_u64(),
                        current_entry_decoder_state,
                    }
                }
            };

            // Half the trials carry a populated hash_state to
            // exercise the v3 trailer; the other half exercise the
            // hash_state=None path that v1 / v2 also produce.
            let hash_state = if rng.next_bool() {
                let mut state = crate::hash::sha256::Sha256::new();
                state.update(&random_bytes(&mut rng, 256));
                Some(state.serialize())
            } else {
                None
            };

            // Half the trials carry a §11 chunk-CRC32C vector to
            // exercise the v4 trailer; the other half leave it
            // unset so v3-shape inputs round-trip too.
            let chunk_crc32c = if rng.next_bool() {
                let n = (rng.next_u32() as usize) % 16;
                Some((0..n).map(|_| rng.next_u32()).collect())
            } else {
                None
            };

            // Half the trials carry an opaque v5 `decoder_state`
            // blob (size up to 64 bytes) to exercise the trailer;
            // the other half leave it unset.
            let decoder_state = if rng.next_bool() {
                let n = (rng.next_u32() as usize) % 64;
                Some(random_bytes(&mut rng, n))
            } else {
                None
            };

            let ckpt = Checkpoint {
                url,
                etag,
                last_modified,
                total_size,
                chunk_size,
                decoder_position,
                bitmap_completed,
                created_at,
                sink_state,
                hash_state,
                chunk_crc32c,
                decoder_state,
            };
            let parsed = Checkpoint::deserialize(&ckpt.serialize()).expect("decode");
            assert_eq!(parsed, ckpt);
        }
    }

    // ---- helpers ----------------------------------------------------

    #[test]
    fn fnv1a64_known_vector() {
        // Reference: 64-bit FNV-1a of the empty string is the offset
        // basis itself, and of "foobar" matches the canonical vector.
        assert_eq!(fnv1a64(b""), 0xCBF2_9CE4_8422_2325);
        assert_eq!(fnv1a64(b"foobar"), 0x85944171_F73967E8);
    }

    #[test]
    fn tmp_path_for_appends_dot_tmp() {
        assert_eq!(
            tmp_path_for(Path::new("/var/tmp/foo.ckpt")),
            PathBuf::from("/var/tmp/foo.ckpt.tmp"),
        );
        assert_eq!(
            tmp_path_for(Path::new("relative/name")),
            PathBuf::from("relative/name.tmp"),
        );
    }

    #[test]
    fn encode_decode_system_time_round_trips_post_epoch() {
        let original = UNIX_EPOCH + Duration::new(1_700_000_000, 654_321);
        let (s, n) = encode_system_time(original);
        assert_eq!(decode_system_time(s, n), original);
    }

    #[test]
    fn encode_decode_system_time_handles_epoch_boundary() {
        let (s, n) = encode_system_time(UNIX_EPOCH);
        assert_eq!(s, 0);
        assert_eq!(n, 0);
        assert_eq!(decode_system_time(0, 0), UNIX_EPOCH);
    }
}
