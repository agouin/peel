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
//!     sink_state: SinkState::Tar { members_completed: vec!["root/a.txt".into()] },
//!     hash_state: None,
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
pub const FORMAT_VERSION: u32 = 3;

/// Fixed-size header length, in bytes.
const HEADER_LEN: usize = 8 + 4 + 8 + 8;

/// Tag for [`SinkState::Raw`] in the on-disk format.
const SINK_TAG_RAW: u8 = 0;
/// Tag for [`SinkState::Tar`] in the on-disk format.
const SINK_TAG_TAR: u8 = 1;
/// Tag for [`SinkState::Zip`] in the on-disk format. Added in v2 of
/// the checkpoint layout.
const SINK_TAG_ZIP: u8 = 2;

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

/// Sink-specific extraction state opaque to everything but the sink.
///
/// `Raw` and `Tar` are the two MVP sinks (see [`crate::sink`]); each
/// carries the minimum state required to skip already-extracted output
/// on resume:
///
/// - [`SinkState::Raw`] records bytes already written to the single
///   output file, so resume seeks past them rather than redoing them.
/// - [`SinkState::Tar`] records the names of members already extracted,
///   so resume's parser ignores re-presented members. (Tar entry order
///   in the archive is well-defined, but recording names lets us be
///   robust to *any* legitimate emission order.)
///
/// The §10 coordinator captures the appropriate variant whenever the
/// extractor reports a quiescent checkpoint.
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
        /// Names are the post-PAX path the extractor wrote (relative to
        /// the extraction root) and are stored in extraction order.
        members_completed: Vec<String>,
    },

    /// State for [`crate::sink::ZipSink`].
    ///
    /// ZIP archives are extracted per-entry in central-directory
    /// order. The checkpoint records which entries are durable on
    /// disk via `entries_completed`, and (when a crash interrupts an
    /// entry) the in-flight entry index plus the byte offset within
    /// it. STORED entries can resume from `current_entry_offset`;
    /// DEFLATE / zstd entries truncate back to zero on resume because
    /// neither codec exposes a serializable mid-stream state. See
    /// `docs/PLAN_v2.md` §5 step 7.
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
            SinkState::Tar { members_completed } => {
                body.push(SINK_TAG_TAR);
                // u32::try_from is the right boundary check; in practice the
                // checkpoint is bounded long before this could overflow.
                let count = u32::try_from(members_completed.len()).unwrap_or(u32::MAX);
                write_u32(&mut body, count);
                for name in members_completed.iter().take(count as usize) {
                    write_string(&mut body, name);
                }
            }
            SinkState::Zip {
                entries_completed,
                current_entry,
                current_entry_offset,
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
            }
        }

        match &self.hash_state {
            Some(bytes) => {
                body.push(1);
                body.extend_from_slice(bytes);
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
        // sink-state body. The `decode_body` helper takes the
        // version so it can decide whether to read that trailer;
        // future versions that *change* the layout will branch
        // here.
        debug_assert!(matches!(format_version, 1..=3));
        Self::decode_body(body, format_version)
    }

    /// Decode the body layout. v1 / v2 / v3 share the same prefix;
    /// v3 appends an optional `hash_state` blob after `sink_state`.
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
                SinkState::Tar {
                    members_completed: members,
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
                SinkState::Zip {
                    entries_completed: entries,
                    current_entry,
                    current_entry_offset,
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
            },
            hash_state: None,
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
            },
            hash_state: None,
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
    fn checkpoint_format_version_is_three() {
        // Sanity: PLAN_v2 §10 step 4 calls for bumping the version
        // when the optional `hash_state` trailer lands. If a future
        // change resets it, this guards against silently dropping
        // the upgrade-required signal v1 / v2 readers depend on.
        assert_eq!(FORMAT_VERSION, 3);
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
        // Build a valid v3 body, then poke the trailing presence
        // byte to an out-of-range value (only 0/1 are valid).
        let mut bytes = sample_raw().serialize();
        let last = bytes.len() - 1;
        // The last body byte is the hash_state presence (None=0).
        bytes[last] = 7;
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
            },
            hash_state: None,
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
                    SinkState::Tar {
                        members_completed: members,
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
                    SinkState::Zip {
                        entries_completed: entries,
                        current_entry: current,
                        current_entry_offset: rng.next_u64(),
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
