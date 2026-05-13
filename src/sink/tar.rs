//! Streaming tar extractor sink.
//!
//! Hand-rolled rather than wrapping the upstream `tar` crate so the
//! parser state can be (de)serialized into a checkpoint and resumed
//! from any byte boundary — the v6 [`crate::checkpoint::SinkState::Tar`]
//! `in_flight` trailer carries the full parser state and
//! [`TarSink::resume`] reconstructs it. Earlier rounds of the project
//! relied on the [`Sink::is_quiescent`] contract being "true only
//! between members"; with mid-member resume support the sink is
//! resumable from anywhere and `is_quiescent` is `true` whenever the
//! sink is healthy. The format is small and the parser is the kind
//! of code we want to be able to audit byte-for-byte.
//!
//! # Format support
//!
//! - **USTAR (POSIX.1-1988)** headers (`ustar\0` + `00` magic) and
//!   **old-GNU** headers (`ustar  \0` magic). The two layouts are
//!   byte-for-byte compatible apart from those eight magic/version
//!   bytes; the typeflag dispatch picks up the format-specific
//!   extensions ('L' / 'K').
//! - **PAX (POSIX.1-2001) extended headers** (typeflag `x`) for the
//!   `path` and `size` keys. `path` lifts the 100/255-byte length
//!   limit; `size` lifts the 8 GiB octal-encoded limit and is the
//!   mechanism §7.4 names for "ustar size limits" handling.
//! - **GNU base-256 (binary) numeric encoding** in the size field.
//!   GNU tar (the default in most distros) switches the size field
//!   from octal ASCII to a big-endian unsigned integer with the high
//!   bit of the first byte set whenever the value exceeds the
//!   8 GiB octal limit, instead of (or in addition to) emitting a
//!   PAX `size=` record. Chain-state snapshots that contain
//!   individual files ≥ 8 GiB rely on this.
//! - **GNU long-name extensions** (typeflag `L`) for entries whose
//!   path exceeds the 100/255-byte ustar limits. The bytes following
//!   the `L` header are read as a NUL-terminated path and applied
//!   to the next entry, matching what GNU `tar` does on extract.
//!   `K` (long link target) is consumed and discarded — peel does
//!   not extract symlinks today.
//! - **Regular files** (`0`, `\0`) and **directories** (`5`).
//!
//! Everything else — symlinks (`2`), hard links (`1`), device nodes
//! (`3`/`4`), FIFOs (`6`), PAX global headers (`g`) — is rejected
//! with [`SinkError::UnsupportedEntry`]. `internal/PLAN.md` §7 explicitly
//! defers these and `OPTIMIZATIONS.md` tracks them.
//!
//! # Path safety
//!
//! Entry names are resolved purely lexically against
//! [`TarSink::new`]'s root. The resolver rejects:
//!
//! - Absolute paths (`/etc/passwd`).
//! - Any component equal to `..`.
//! - Empty entry names.
//! - Entry names containing NUL bytes.
//!
//! There is no attempt to canonicalize through the filesystem; we never
//! create symlinks, so a lexical guarantee is a complete one. This
//! deliberately rejects archives whose entries cancel out a `..` later
//! — a stricter posture than `bsdtar` and the right default for the
//! MVP.
//!
//! # Streaming guarantees
//!
//! [`Sink::write`] accepts arbitrary chunk boundaries: feeding the same
//! archive byte-by-byte produces the same on-disk output as feeding it
//! all at once. The parser maintains a single 512-byte header buffer
//! and a per-entry data cursor, both of which advance independently of
//! the call boundaries.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use crate::sink::{Sink, SinkError};

/// Tar block size. Headers are exactly one block; file data is padded
/// up to the next block boundary.
const BLOCK: usize = 512;

/// Stream into a directory tree on disk, member by member.
///
/// Construct with [`TarSink::new`]; feed the archive bytes via
/// [`Sink::write`]; finalize with [`Sink::close`]. The sink reports
/// [`Sink::is_quiescent`] as `true` only between members so the
/// coordinator can take checkpoints at restart-safe boundaries.
pub struct TarSink {
    /// Extraction root. Every successfully written file's path lies
    /// inside this directory.
    root: PathBuf,
    /// Driving state machine — see [`State`].
    state: State,
    /// Total bytes consumed from the archive so far. Used in error
    /// messages to point the user at the failing record.
    archive_offset: u64,
    /// Number of *consecutive* zero blocks observed. Two of them mark
    /// the end of the archive.
    zero_blocks_seen: u8,
    /// PAX `path=` override applying to the next non-PAX entry.
    pending_path: Option<String>,
    /// PAX `size=` override applying to the next non-PAX entry.
    pending_size: Option<u64>,
    /// Sticky failure flag. Once a write errors, every subsequent
    /// write returns an error too — partial extraction is never silently
    /// continued.
    poisoned: bool,
}

/// Parser state machine.
///
/// Transitions:
/// ```text
/// Header(filled<512) ──bytes──▶ Header(filled+=)
/// Header(filled==512) ──parse──▶ {Header,File,PaxData,Finished}
/// File(remaining>0) ──bytes──▶ File(remaining-=)
/// File(remaining==0, padding>0) ──bytes──▶ File(padding-=)
/// File(remaining==0, padding==0) ──▶ Header(0)
/// PaxData ── analogous, then applies overrides and ──▶ Header(0)
/// Finished ── trailing bytes are an error
/// ```
enum State {
    /// Filling a 512-byte header buffer.
    Header {
        /// Number of bytes received toward the next header. `0..=BLOCK`.
        filled: usize,
        /// The header buffer itself. Boxed so the `State` enum stays
        /// small (the variant is only ~24 bytes instead of ~520).
        buf: Box<[u8; BLOCK]>,
    },
    /// Writing a regular file's body to disk, then skipping its
    /// 512-byte block padding.
    File {
        /// Bytes of file data still to receive.
        remaining: u64,
        /// Bytes of trailing zero padding still to consume.
        padding: u16,
        /// The file we are writing into.
        file: File,
        /// Resolved on-disk path; carried for error context only.
        path: PathBuf,
        /// Total payload size declared by the tar header. Used by
        /// the checkpoint snapshotter to derive how many bytes have
        /// already been written (`total_size - remaining`); not
        /// otherwise consulted by the live parser.
        total_size: u64,
    },
    /// Collecting a PAX 'x' extended header's body into a buffer.
    PaxData {
        /// Bytes of PAX body still to receive.
        remaining: u64,
        /// Bytes of trailing zero padding still to consume.
        padding: u16,
        /// Accumulator for the entry data; drained on completion.
        buf: Vec<u8>,
    },
    /// Collecting a GNU long-name ('L') or long-link ('K') extension.
    /// The body is a NUL-terminated path that overrides the *next*
    /// entry's name field. 'K' (long link target) is consumed and
    /// discarded — peel does not extract symlinks today.
    LongName {
        /// Bytes of body still to receive.
        remaining: u64,
        /// Bytes of trailing zero padding still to consume.
        padding: u16,
        /// Accumulator for the long path; empty for 'K' since we drop
        /// the bytes inline rather than allocate.
        buf: Vec<u8>,
        /// `true` for 'K' (long link target, discarded), `false` for
        /// 'L' (long path, applied to the next entry).
        is_link: bool,
    },
    /// End-of-archive marker observed; further bytes other than zeros
    /// are an error.
    Finished,
}

impl TarSink {
    /// Construct a sink that extracts into `root`.
    ///
    /// The directory must already exist; we never create the root
    /// itself, only entries within it. Most test paths use
    /// `fs::create_dir_all(&root)` first.
    ///
    /// # Errors
    ///
    /// Returns [`SinkError::Io`] if `root` cannot be canonicalized
    /// (does not exist, permission denied, …). Canonicalizing once
    /// up-front means later path-escape checks compare absolute paths
    /// rather than relative-vs-relative segments.
    pub fn new<P: AsRef<Path>>(root: P) -> Result<Self, SinkError> {
        let root = root.as_ref();
        let canonical = root.canonicalize().map_err(|source| SinkError::Io {
            path: root.to_path_buf(),
            source,
        })?;
        Ok(Self {
            root: canonical,
            state: State::Header {
                filled: 0,
                buf: Box::new([0u8; BLOCK]),
            },
            archive_offset: 0,
            zero_blocks_seen: 0,
            pending_path: None,
            pending_size: None,
            poisoned: false,
        })
    }

    /// Construct a [`TarSink`] pre-seeded from a previously captured
    /// [`crate::checkpoint::TarSinkState`].
    ///
    /// `state` was produced by [`Sink::sink_state`] on the prior
    /// (killed) run's sink, and the on-disk extraction is whatever
    /// the killed run had durably written before the checkpoint
    /// fired. The resume path:
    ///
    /// 1. Canonicalizes `root` (the same way [`Self::new`] does).
    /// 2. For [`crate::checkpoint::TarMemberState::File`]: opens
    ///    the recorded path under `root`, truncates it to
    ///    `total_size - remaining` (so any torn write past the
    ///    checkpoint is discarded), and seeks to that offset.
    ///    Restores the live `State::File` ready to receive the
    ///    payload's continuation.
    /// 3. For other variants: rebuilds the `State` enum directly
    ///    from the saved fields.
    ///
    /// # Errors
    ///
    /// Returns [`SinkError::Io`] if `root` can't be canonicalized
    /// or the in-flight file can't be reopened at the recorded
    /// offset; [`SinkError::PathEscape`] if the recorded file path
    /// lies outside `root`.
    pub fn resume<P: AsRef<Path>>(
        root: P,
        state: &crate::checkpoint::TarSinkState,
    ) -> Result<Self, SinkError> {
        use crate::checkpoint::TarMemberState;

        let root_ref = root.as_ref();
        let canonical_root = root_ref.canonicalize().map_err(|source| SinkError::Io {
            path: root_ref.to_path_buf(),
            source,
        })?;

        let live_state = match &state.state {
            TarMemberState::Header { filled, buf: saved } => {
                if *filled > BLOCK as u32 || saved.len() != *filled as usize {
                    return Err(SinkError::Io {
                        path: canonical_root.clone(),
                        source: std::io::Error::other(format!(
                            "resume: header filled={filled} buf.len()={}",
                            saved.len(),
                        )),
                    });
                }
                let mut buf = Box::new([0u8; BLOCK]);
                buf[..saved.len()].copy_from_slice(saved);
                State::Header {
                    filled: *filled as usize,
                    buf,
                }
            }
            TarMemberState::File {
                remaining,
                padding,
                path,
                total_size,
            } => {
                if *remaining > *total_size {
                    return Err(SinkError::Io {
                        path: canonical_root.clone(),
                        source: std::io::Error::other(format!(
                            "resume: file remaining {remaining} > total_size {total_size}",
                        )),
                    });
                }
                let path_buf = PathBuf::from(path);
                if !path_buf.starts_with(&canonical_root) {
                    return Err(SinkError::PathEscape {
                        entry: path.clone(),
                        root: canonical_root.clone(),
                    });
                }
                let already_written = total_size.saturating_sub(*remaining);
                let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .truncate(false)
                    .open(&path_buf)
                    .map_err(|source| SinkError::Io {
                        path: path_buf.clone(),
                        source,
                    })?;
                // Truncate any tail past the checkpoint, then seek
                // to the resume position. The truncate-then-seek
                // shape mirrors `RawSink::resume`.
                file.set_len(already_written)
                    .map_err(|source| SinkError::Io {
                        path: path_buf.clone(),
                        source,
                    })?;
                use std::io::{Seek, SeekFrom};
                file.seek(SeekFrom::Start(already_written))
                    .map_err(|source| SinkError::Io {
                        path: path_buf.clone(),
                        source,
                    })?;
                State::File {
                    remaining: *remaining,
                    padding: u16::try_from(*padding).map_err(|_| SinkError::Io {
                        path: path_buf.clone(),
                        source: std::io::Error::other(format!(
                            "resume: file padding {padding} ≥ 65536",
                        )),
                    })?,
                    file,
                    path: path_buf,
                    total_size: *total_size,
                }
            }
            TarMemberState::PaxData {
                remaining,
                padding,
                buf,
            } => State::PaxData {
                remaining: *remaining,
                padding: u16::try_from(*padding).map_err(|_| SinkError::Io {
                    path: canonical_root.clone(),
                    source: std::io::Error::other(
                        format!("resume: pax padding {padding} ≥ 65536",),
                    ),
                })?,
                buf: buf.clone(),
            },
            TarMemberState::LongName {
                remaining,
                padding,
                buf,
                is_link,
            } => State::LongName {
                remaining: *remaining,
                padding: u16::try_from(*padding).map_err(|_| SinkError::Io {
                    path: canonical_root.clone(),
                    source: std::io::Error::other(format!(
                        "resume: longname padding {padding} ≥ 65536",
                    )),
                })?,
                buf: buf.clone(),
                is_link: *is_link,
            },
            TarMemberState::Finished => State::Finished,
        };

        Ok(Self {
            root: canonical_root,
            state: live_state,
            archive_offset: state.archive_offset,
            zero_blocks_seen: state.zero_blocks_seen,
            pending_path: state.pending_path.clone(),
            pending_size: state.pending_size,
            poisoned: false,
        })
    }

    /// Borrow the configured extraction root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Feed bytes through the parser without the poisoning bookkeeping.
    /// All public entry points wrap this in the sticky-failure check.
    fn write_inner(&mut self, mut input: &[u8]) -> Result<(), SinkError> {
        while !input.is_empty() {
            // We only step as much as one state arm can consume; the
            // outer loop re-enters with the remainder so a long input
            // can cross arbitrarily many state transitions in one call.
            let consumed = match &mut self.state {
                State::Header { filled, buf } => {
                    let want = BLOCK - *filled;
                    let take = input.len().min(want);
                    buf[*filled..*filled + take].copy_from_slice(&input[..take]);
                    *filled += take;
                    if *filled == BLOCK {
                        // The buffer is complete — process it. We
                        // can't keep `filled`/`buf` borrowed across the
                        // call, so move the buffer out, drop the
                        // borrow, then transition. The state will be
                        // overwritten before the function returns.
                        let header_buf = std::mem::replace(buf, Box::new([0u8; BLOCK]));
                        *filled = 0;
                        self.process_header(*header_buf)?;
                    }
                    take
                }
                State::File {
                    remaining,
                    padding,
                    file,
                    path,
                    total_size: _,
                } => {
                    if *remaining > 0 {
                        let want = usize::try_from(*remaining)
                            .unwrap_or(usize::MAX)
                            .min(input.len());
                        file.write_all(&input[..want])
                            .map_err(|source| SinkError::Io {
                                path: path.clone(),
                                source,
                            })?;
                        *remaining -= want as u64;
                        // Transition immediately when both data and
                        // padding are exhausted. Without this guard,
                        // a file whose size is an exact multiple of
                        // 512 (so `padding == 0`) would loop into the
                        // "both zero" arm below, return 0 consumed,
                        // and trip the outer no-progress check.
                        if *remaining == 0 && *padding == 0 {
                            self.finish_file_state();
                        }
                        want
                    } else if *padding > 0 {
                        let want = usize::from(*padding).min(input.len());
                        // The padding is supposed to be zero bytes; we
                        // do not enforce that — real-world archives
                        // produced by `gnu tar` zero them out, but the
                        // spec only says "padding to a 512-byte
                        // boundary" and we are forgiving.
                        *padding -= want as u16;
                        if *padding == 0 {
                            self.finish_file_state();
                        }
                        want
                    } else {
                        // Both zero — should have transitioned out
                        // already.
                        self.finish_file_state();
                        0
                    }
                }
                State::PaxData {
                    remaining,
                    padding,
                    buf,
                } => {
                    if *remaining > 0 {
                        let want = usize::try_from(*remaining)
                            .unwrap_or(usize::MAX)
                            .min(input.len());
                        buf.extend_from_slice(&input[..want]);
                        *remaining -= want as u64;
                        // Same alignment-fix rationale as the File
                        // arm: a PAX header whose size is a multiple
                        // of 512 would otherwise stall the parser.
                        if *remaining == 0 && *padding == 0 {
                            self.finish_pax_state()?;
                        }
                        want
                    } else if *padding > 0 {
                        let want = usize::from(*padding).min(input.len());
                        *padding -= want as u16;
                        if *padding == 0 {
                            self.finish_pax_state()?;
                        }
                        want
                    } else {
                        self.finish_pax_state()?;
                        0
                    }
                }
                State::LongName {
                    remaining,
                    padding,
                    buf,
                    is_link,
                } => {
                    if *remaining > 0 {
                        let want = usize::try_from(*remaining)
                            .unwrap_or(usize::MAX)
                            .min(input.len());
                        // 'L' captures the path; 'K' discards inline
                        // so an oversized link target cannot grow the
                        // buffer unbounded.
                        if !*is_link {
                            buf.extend_from_slice(&input[..want]);
                        }
                        *remaining -= want as u64;
                        if *remaining == 0 && *padding == 0 {
                            self.finish_long_name_state()?;
                        }
                        want
                    } else if *padding > 0 {
                        let want = usize::from(*padding).min(input.len());
                        *padding -= want as u16;
                        if *padding == 0 {
                            self.finish_long_name_state()?;
                        }
                        want
                    } else {
                        self.finish_long_name_state()?;
                        0
                    }
                }
                State::Finished => {
                    // After the end-of-archive marker, we tolerate
                    // additional zero bytes (real-world archives often
                    // pad to a 10 KiB block) but reject anything else.
                    let nz = input.iter().position(|&b| b != 0).unwrap_or(input.len());
                    if nz < input.len() {
                        return Err(SinkError::TrailingData {
                            archive_offset: self.archive_offset + nz as u64,
                        });
                    }
                    nz
                }
            };
            self.archive_offset += consumed as u64;
            input = &input[consumed..];
            // Defensive: a state transition that consumes zero bytes
            // and does not change state would loop forever. The arms
            // above either consume or transition; the only place that
            // can return 0 is the Finished arm with empty `input`,
            // which is exited by the outer while.
            if consumed == 0 && !input.is_empty() {
                return Err(SinkError::MalformedHeader {
                    archive_offset: self.archive_offset,
                    reason: "parser made no progress (internal invariant)".into(),
                });
            }
        }
        Ok(())
    }

    /// Process a fully-buffered 512-byte header.
    fn process_header(&mut self, header: [u8; BLOCK]) -> Result<(), SinkError> {
        if header.iter().all(|&b| b == 0) {
            self.zero_blocks_seen = self.zero_blocks_seen.saturating_add(1);
            if self.zero_blocks_seen >= 2 {
                self.state = State::Finished;
            }
            // Single zero block: we stay in Header, waiting to see if
            // the second one follows.
            return Ok(());
        }
        self.zero_blocks_seen = 0;

        let header_offset = self
            .archive_offset
            .checked_sub(BLOCK as u64 - 1)
            .map_or(self.archive_offset, |o| o.saturating_sub(1));
        // The header occupies [header_offset, header_offset+512); the
        // saturating arithmetic keeps the diagnostic value sane even on
        // pathological offsets.

        validate_magic(&header, header_offset)?;
        validate_checksum(&header, header_offset)?;

        let parsed = ParsedHeader::from_bytes(&header, header_offset)?;
        let type_flag = parsed.type_flag;
        let raw_size = parsed.size;

        // PAX overrides are applied on top of the parsed header so the
        // actual on-disk size and name reflect the override-not-the-
        // raw-header.
        let entry_size = self.pending_size.take().unwrap_or(raw_size);
        let entry_name = match self.pending_path.take() {
            Some(p) => p,
            None => parsed.combined_name()?,
        };

        match type_flag {
            // Regular file. '\0' is the historical encoding, '0' the
            // POSIX one; both mean the same thing. '7' (contiguous
            // file) is treated identically — the distinction is
            // semantic-free on every modern filesystem.
            0 | b'0' | b'7' => {
                let path = self.resolve_entry_path(&entry_name)?;
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
                let padding = padding_for(entry_size);
                self.state = if entry_size == 0 && padding == 0 {
                    // Zero-length file with no padding to skip;
                    // transition straight back to Header.
                    drop(file);
                    State::Header {
                        filled: 0,
                        buf: Box::new([0u8; BLOCK]),
                    }
                } else {
                    State::File {
                        remaining: entry_size,
                        padding,
                        file,
                        path,
                        total_size: entry_size,
                    }
                };
                Ok(())
            }
            // Directory.
            b'5' => {
                let path = self.resolve_entry_path(&entry_name)?;
                fs::create_dir_all(&path).map_err(|source| SinkError::Io {
                    path: path.clone(),
                    source,
                })?;
                // Directory entries should declare size=0; some
                // archives in the wild ignore that. We honor whatever
                // the header (or PAX) said and skip that many bytes
                // before resuming.
                let padding = padding_for(entry_size);
                self.state = if entry_size == 0 && padding == 0 {
                    State::Header {
                        filled: 0,
                        buf: Box::new([0u8; BLOCK]),
                    }
                } else {
                    State::PaxData {
                        // Reuse the PaxData state as a "skip these
                        // bytes" buffer for non-zero-size directory
                        // entries; we discard the bytes by checking
                        // the buf len in finish_pax_state but it is
                        // simpler to just throw away the bytes inline.
                        // Use a dedicated skip path:
                        remaining: entry_size,
                        padding,
                        // An empty Vec means "discard incoming bytes";
                        // see finish_pax_state for the cap.
                        buf: Vec::new(),
                    }
                };
                Ok(())
            }
            // PAX extended header for the next entry. Body is a
            // sequence of `<len> <key>=<value>\n` records we'll parse
            // in finish_pax_state.
            b'x' => {
                let padding = padding_for(entry_size);
                self.state = if entry_size == 0 && padding == 0 {
                    State::Header {
                        filled: 0,
                        buf: Box::new([0u8; BLOCK]),
                    }
                } else {
                    State::PaxData {
                        remaining: entry_size,
                        padding,
                        // We pre-allocate the exact size — bounded
                        // small in practice (a few KiB at most).
                        buf: Vec::with_capacity(usize::try_from(entry_size).unwrap_or(0)),
                    }
                };
                Ok(())
            }
            // GNU long-name ('L') / long-link ('K') extensions. The
            // header's "./@LongLink" name is ignored; the body holds
            // the real path. 'L' overrides the next entry's name; 'K'
            // is discarded because peel does not extract symlinks.
            // Pre-cap the allocation so a hostile archive can't ask
            // us to reserve gigabytes of memory.
            b'L' | b'K' => {
                let is_link = type_flag == b'K';
                let padding = padding_for(entry_size);
                self.state = if entry_size == 0 && padding == 0 {
                    State::Header {
                        filled: 0,
                        buf: Box::new([0u8; BLOCK]),
                    }
                } else {
                    let cap_hint = usize::try_from(entry_size)
                        .unwrap_or(usize::MAX)
                        .min(64 * 1024);
                    State::LongName {
                        remaining: entry_size,
                        padding,
                        buf: if is_link {
                            Vec::new()
                        } else {
                            Vec::with_capacity(cap_hint)
                        },
                        is_link,
                    }
                };
                Ok(())
            }
            other => Err(SinkError::UnsupportedEntry {
                type_flag: other,
                entry: entry_name,
            }),
        }
    }

    fn finish_file_state(&mut self) {
        // Drop the file, transition home.
        self.state = State::Header {
            filled: 0,
            buf: Box::new([0u8; BLOCK]),
        };
    }

    fn finish_long_name_state(&mut self) -> Result<(), SinkError> {
        let State::LongName {
            remaining: _,
            padding: _,
            buf,
            is_link,
        } = std::mem::replace(
            &mut self.state,
            State::Header {
                filled: 0,
                buf: Box::new([0u8; BLOCK]),
            },
        )
        else {
            // INVARIANT: only called from within the LongName arm.
            return Ok(());
        };
        if is_link {
            // 'K' bytes were never buffered; nothing to do.
            return Ok(());
        }
        // GNU stores the path NUL-terminated and pads to a 512-byte
        // boundary with zeros. Trim at the first NUL so the override
        // we apply matches what `tar` itself would.
        let trimmed = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        let bytes = &buf[..trimmed];
        let path = std::str::from_utf8(bytes).map_err(|_| SinkError::MalformedHeader {
            archive_offset: self.archive_offset,
            reason: "GNU long-name payload is not valid UTF-8".into(),
        })?;
        // PAX 'path=' takes precedence if both extensions are present
        // for the same entry — PAX is the modern spec and any archive
        // emitting both is signaling the PAX value as authoritative.
        if self.pending_path.is_none() {
            self.pending_path = Some(path.to_string());
        }
        Ok(())
    }

    fn finish_pax_state(&mut self) -> Result<(), SinkError> {
        let State::PaxData {
            remaining: _,
            padding: _,
            buf,
        } = std::mem::replace(
            &mut self.state,
            State::Header {
                filled: 0,
                buf: Box::new([0u8; BLOCK]),
            },
        )
        else {
            // INVARIANT: only called from within the PaxData arm.
            return Ok(());
        };
        if !buf.is_empty() {
            let records = parse_pax_records(&buf, self.archive_offset)?;
            for (key, value) in records {
                match key.as_str() {
                    "path" => self.pending_path = Some(value),
                    "size" => {
                        self.pending_size =
                            Some(value.parse::<u64>().map_err(|_| SinkError::MalformedPax {
                                archive_offset: self.archive_offset,
                                reason: format!("size value {value:?} is not a u64"),
                            })?);
                    }
                    _ => {
                        // Unknown keys are silently ignored — PAX
                        // requires that an extractor not break on
                        // unknown extensions.
                    }
                }
            }
        }
        Ok(())
    }

    /// Resolve an entry name to an absolute path under `self.root`,
    /// rejecting anything that escapes.
    ///
    /// Tar archives in the wild commonly include a self-referential
    /// directory entry like `./` (or just `.`) representing the
    /// archive root itself — `bsdtar` and GNU `tar` both emit it on
    /// `tar cf out.tar ./`. Those entries resolve to `self.root` and
    /// are extracted as a no-op `mkdir -p` of the (already-existing)
    /// output directory. Treating that as a path-escape would refuse
    /// every Arbitrum snapshot and many real-world tarballs; accept
    /// it instead.
    fn resolve_entry_path(&self, entry: &str) -> Result<PathBuf, SinkError> {
        if entry.is_empty() || entry.contains('\0') {
            return Err(SinkError::PathEscape {
                entry: entry.to_string(),
                root: self.root.clone(),
            });
        }
        if entry.starts_with('/') {
            return Err(SinkError::PathEscape {
                entry: entry.to_string(),
                root: self.root.clone(),
            });
        }
        let mut out = self.root.clone();
        for component in entry.split('/') {
            if component.is_empty() || component == "." {
                continue;
            }
            if component == ".." {
                return Err(SinkError::PathEscape {
                    entry: entry.to_string(),
                    root: self.root.clone(),
                });
            }
            // Reject any component containing a path separator — on
            // Unix this is just a NUL guard (already checked) and
            // the std `PathBuf::push` already documents it as an
            // append. We do an extra check for robustness against any
            // future cross-platform expansion.
            if Path::new(component)
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
            {
                return Err(SinkError::PathEscape {
                    entry: entry.to_string(),
                    root: self.root.clone(),
                });
            }
            out.push(component);
        }
        // Empty resolved path means the entry was `.`, `./`, or
        // similar — that's the archive root itself. Return
        // `self.root`; the caller's `create_dir_all` is a no-op
        // because the root already exists. A file entry whose name
        // resolves to the root (vanishingly rare; would have to be
        // `./` with type-flag `0`) would fail at `OpenOptions::write`
        // with a clean "Is a directory" IO error — matched behaviour
        // is fine.
        Ok(out)
    }
}

impl Sink for TarSink {
    fn write(&mut self, buf: &[u8]) -> Result<(), SinkError> {
        if self.poisoned {
            return Err(SinkError::Io {
                path: self.root.clone(),
                source: std::io::Error::other("tar sink already failed"),
            });
        }
        match self.write_inner(buf) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.poisoned = true;
                Err(e)
            }
        }
    }

    fn is_quiescent(&self) -> bool {
        // Every byte boundary is a checkpoint-safe restart point now
        // that [`Self::sink_state`] captures the live parser state
        // and [`Self::resume`] consumes it. Poisoned sinks stay
        // non-quiescent so a checkpoint observed after a sink
        // failure isn't written.
        !self.poisoned
    }

    fn sink_state(&self) -> crate::checkpoint::SinkState {
        use crate::checkpoint::{TarMemberState, TarSinkState};
        let path_to_string = |p: &Path| p.to_string_lossy().into_owned();
        let parser_state = match &self.state {
            State::Header { filled, buf } => TarMemberState::Header {
                filled: *filled as u32,
                buf: buf[..*filled].to_vec(),
            },
            State::File {
                remaining,
                padding,
                path,
                total_size,
                ..
            } => TarMemberState::File {
                remaining: *remaining,
                padding: u32::from(*padding),
                path: path_to_string(path),
                total_size: *total_size,
            },
            State::PaxData {
                remaining,
                padding,
                buf,
            } => TarMemberState::PaxData {
                remaining: *remaining,
                padding: u32::from(*padding),
                buf: buf.clone(),
            },
            State::LongName {
                remaining,
                padding,
                buf,
                is_link,
            } => TarMemberState::LongName {
                remaining: *remaining,
                padding: u32::from(*padding),
                buf: buf.clone(),
                is_link: *is_link,
            },
            State::Finished => TarMemberState::Finished,
        };
        crate::checkpoint::SinkState::Tar {
            members_completed: Vec::new(),
            in_flight: Some(TarSinkState {
                archive_offset: self.archive_offset,
                zero_blocks_seen: self.zero_blocks_seen,
                pending_path: self.pending_path.clone(),
                pending_size: self.pending_size,
                state: parser_state,
            }),
        }
    }

    fn close(self) -> Result<(), SinkError> {
        if self.poisoned {
            return Err(SinkError::Io {
                path: self.root.clone(),
                source: std::io::Error::other("tar sink already failed"),
            });
        }
        match self.state {
            State::Finished => Ok(()),
            // Single trailing zero block before EOF is unusual but the
            // archive is still self-consistent (no half-entry); treat
            // it the same as a clean finish so we tolerate sources
            // that omit the second zero block. The `Header { filled:
            // 0 }` case is the same.
            State::Header { filled: 0, .. } if self.zero_blocks_seen <= 1 => {
                if self.zero_blocks_seen == 0 {
                    // No end-of-archive marker at all. Most archives
                    // we'll see do include it; the absence of even one
                    // zero block is suspicious enough to flag.
                    Err(SinkError::UnexpectedEof {
                        archive_offset: self.archive_offset,
                        bytes_remaining: BLOCK as u64,
                    })
                } else {
                    Ok(())
                }
            }
            State::Header { filled, .. } => Err(SinkError::UnexpectedEof {
                archive_offset: self.archive_offset,
                bytes_remaining: (BLOCK - filled) as u64,
            }),
            State::File {
                remaining, padding, ..
            } => Err(SinkError::UnexpectedEof {
                archive_offset: self.archive_offset,
                bytes_remaining: remaining + u64::from(padding),
            }),
            State::PaxData {
                remaining, padding, ..
            } => Err(SinkError::UnexpectedEof {
                archive_offset: self.archive_offset,
                bytes_remaining: remaining + u64::from(padding),
            }),
            State::LongName {
                remaining, padding, ..
            } => Err(SinkError::UnexpectedEof {
                archive_offset: self.archive_offset,
                bytes_remaining: remaining + u64::from(padding),
            }),
        }
    }
}

/// Magic + version for the ustar variants we accept.
fn validate_magic(header: &[u8; BLOCK], offset: u64) -> Result<(), SinkError> {
    // Two variants found in the wild:
    //   POSIX/USTAR (POSIX.1-1988): "ustar\0" + "00"
    //   Old-GNU (GNU tar default): "ustar  \0" — five chars, two
    //     spaces, NUL, occupying the same eight bytes. The header
    //     layout is otherwise byte-for-byte compatible; the
    //     differences live in the typeflag dispatch ('L' / 'K').
    let magic = &header[257..265];
    if magic == b"ustar\x0000" || magic == b"ustar  \x00" {
        Ok(())
    } else {
        Err(SinkError::MalformedHeader {
            archive_offset: offset,
            reason: format!(
                "magic/version is {magic:?}, expected POSIX 'ustar\\0'+'00' \
                 or old-GNU 'ustar  \\0'"
            ),
        })
    }
}

fn validate_checksum(header: &[u8; BLOCK], offset: u64) -> Result<(), SinkError> {
    let recorded = parse_octal(&header[148..156]).ok_or_else(|| SinkError::MalformedHeader {
        archive_offset: offset,
        reason: "chksum field is not a valid octal value".into(),
    })?;
    let computed: u32 = header
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                0x20u32
            } else {
                u32::from(b)
            }
        })
        .sum();
    let recorded_u32 = u32::try_from(recorded).map_err(|_| SinkError::MalformedHeader {
        archive_offset: offset,
        reason: format!("chksum value {recorded} does not fit u32"),
    })?;
    if recorded_u32 == computed {
        Ok(())
    } else {
        Err(SinkError::BadChecksum {
            archive_offset: offset,
            expected: recorded_u32,
            computed,
        })
    }
}

/// Result of parsing a 512-byte header into its semantic fields.
struct ParsedHeader<'h> {
    name: &'h [u8],
    prefix: &'h [u8],
    size: u64,
    type_flag: u8,
    archive_offset: u64,
}

impl<'h> ParsedHeader<'h> {
    fn from_bytes(header: &'h [u8; BLOCK], archive_offset: u64) -> Result<Self, SinkError> {
        let name = trim_nul(&header[..100]);
        // The size field is octal in plain ustar but GNU tar switches
        // to base-256 binary (high bit of the first byte set) when the
        // value won't fit the 11 octal digits + terminator — i.e. for
        // any entry ≥ 8 GiB. Multi-TB chain snapshots routinely hit
        // this, so we honor both encodings.
        let size = parse_numeric(&header[124..136]).ok_or_else(|| SinkError::MalformedHeader {
            archive_offset,
            reason: "size field is not a valid octal or base-256 value".into(),
        })?;
        let type_flag = header[156];
        let prefix = trim_nul(&header[345..500]);
        Ok(Self {
            name,
            prefix,
            size,
            type_flag,
            archive_offset,
        })
    }

    fn combined_name(&self) -> Result<String, SinkError> {
        let name = std::str::from_utf8(self.name).map_err(|e| SinkError::MalformedHeader {
            archive_offset: self.archive_offset,
            reason: format!("name is not valid UTF-8: {e}"),
        })?;
        if self.prefix.is_empty() {
            return Ok(name.to_string());
        }
        let prefix = std::str::from_utf8(self.prefix).map_err(|e| SinkError::MalformedHeader {
            archive_offset: self.archive_offset,
            reason: format!("prefix is not valid UTF-8: {e}"),
        })?;
        Ok(format!("{prefix}/{name}"))
    }
}

/// PAX records map keys to values. We care about `path` and `size`;
/// callers iterate the returned vec rather than indexing because the
/// spec allows the same key to appear multiple times (last write
/// wins).
fn parse_pax_records(data: &[u8], archive_offset: u64) -> Result<Vec<(String, String)>, SinkError> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < data.len() {
        // <length> <key>=<value>\n
        let space = data[cursor..]
            .iter()
            .position(|&b| b == b' ')
            .ok_or_else(|| SinkError::MalformedPax {
                archive_offset,
                reason: "missing space between length and key".into(),
            })?;
        let len_str = std::str::from_utf8(&data[cursor..cursor + space]).map_err(|e| {
            SinkError::MalformedPax {
                archive_offset,
                reason: format!("length prefix is not UTF-8: {e}"),
            }
        })?;
        let entry_len = len_str
            .parse::<usize>()
            .map_err(|_| SinkError::MalformedPax {
                archive_offset,
                reason: format!("length prefix {len_str:?} is not a decimal integer"),
            })?;
        if entry_len < space + 2 {
            // Need at least "<n> =\n" — the smallest legal entry has
            // a 1-char key and 0-char value.
            return Err(SinkError::MalformedPax {
                archive_offset,
                reason: format!("entry length {entry_len} too small to be valid"),
            });
        }
        let entry_end = cursor
            .checked_add(entry_len)
            .ok_or_else(|| SinkError::MalformedPax {
                archive_offset,
                reason: "entry length overflowed usize".into(),
            })?;
        if entry_end > data.len() {
            return Err(SinkError::MalformedPax {
                archive_offset,
                reason: format!(
                    "entry length {entry_len} exceeds remaining buffer ({} bytes left)",
                    data.len() - cursor,
                ),
            });
        }
        // Skip past the length and the space.
        let body_start = cursor + space + 1;
        let body_end = entry_end
            .checked_sub(1)
            .ok_or_else(|| SinkError::MalformedPax {
                archive_offset,
                reason: "entry too short for trailing newline".into(),
            })?;
        if data[body_end] != b'\n' {
            return Err(SinkError::MalformedPax {
                archive_offset,
                reason: "entry does not end with newline".into(),
            });
        }
        let body = &data[body_start..body_end];
        let eq = body
            .iter()
            .position(|&b| b == b'=')
            .ok_or_else(|| SinkError::MalformedPax {
                archive_offset,
                reason: "entry body lacks '='".into(),
            })?;
        let key = std::str::from_utf8(&body[..eq])
            .map_err(|e| SinkError::MalformedPax {
                archive_offset,
                reason: format!("key is not UTF-8: {e}"),
            })?
            .to_string();
        let value = std::str::from_utf8(&body[eq + 1..])
            .map_err(|e| SinkError::MalformedPax {
                archive_offset,
                reason: format!("value is not UTF-8: {e}"),
            })?
            .to_string();
        out.push((key, value));
        cursor = entry_end;
    }
    Ok(out)
}

/// Trim trailing NUL bytes from a fixed-size header field. Tar header
/// fields are NUL-terminated within their fixed width; everything
/// after the first NUL is "padding".
fn trim_nul(field: &[u8]) -> &[u8] {
    match field.iter().position(|&b| b == 0) {
        Some(i) => &field[..i],
        None => field,
    }
}

/// Parse a tar header numeric field, honoring the GNU base-256 binary
/// extension. If the high bit of the first byte is set, the field is
/// a big-endian unsigned integer (with the flag bit masked off the
/// first byte) rather than an octal ASCII string. GNU tar emits this
/// for size/mtime values that don't fit the 11 octal-digit form —
/// notably any file ≥ 8 GiB. Otherwise we fall through to [`parse_octal`].
///
/// Returns `None` if the field is the rare two's-complement-negative
/// form (first byte `0xff`) — tar size/uid/etc. fields are non-negative
/// — or if the magnitude overflows `u64`.
fn parse_numeric(field: &[u8]) -> Option<u64> {
    match field.first() {
        Some(&first) if first & 0x80 != 0 => {
            // 0x40 bit set on top of the flag bit means the value is
            // two's-complement negative; not used for tar sizes.
            if first & 0x40 != 0 {
                return None;
            }
            let mut acc: u64 = u64::from(first & 0x7f);
            for &b in &field[1..] {
                // If the high byte of `acc` is non-zero we'd lose bits
                // shifting it up, meaning the value exceeds u64::MAX.
                if acc & 0xff00_0000_0000_0000 != 0 {
                    return None;
                }
                acc = (acc << 8) | u64::from(b);
            }
            Some(acc)
        }
        _ => parse_octal(field),
    }
}

/// Parse a tar header numeric field as octal. Tar fields may be
/// padded with leading spaces, leading NULs, or trailing spaces/NULs;
/// libarchive even allows a few non-octal-alphabet bytes in the wild.
/// We accept `0-7`, leading/trailing whitespace, and trailing NULs.
fn parse_octal(field: &[u8]) -> Option<u64> {
    let mut start = 0;
    while start < field.len() && (field[start] == b' ' || field[start] == 0) {
        start += 1;
    }
    let mut end = field.len();
    while end > start && (field[end - 1] == b' ' || field[end - 1] == 0) {
        end -= 1;
    }
    if start == end {
        return Some(0);
    }
    let mut acc: u64 = 0;
    for &b in &field[start..end] {
        if !(b'0'..=b'7').contains(&b) {
            return None;
        }
        acc = acc.checked_mul(8)?;
        acc = acc.checked_add(u64::from(b - b'0'))?;
    }
    Some(acc)
}

/// Bytes of zero padding required after a body of `size` bytes to land
/// on the next 512-byte block.
fn padding_for(size: u64) -> u16 {
    let r = (size % BLOCK as u64) as u16;
    if r == 0 {
        0
    } else {
        BLOCK as u16 - r
    }
}

/// Test-only helpers for synthesizing USTAR/PAX bytes.
///
/// Lives behind `#[cfg(test)]` so it is excluded from release builds
/// and integration tests; integration tests duplicate the small
/// fixture builder in `tests/support/tar_fixtures.rs` so `cargo
/// llvm-cov` does not see two compilations of the same code.
#[cfg(test)]
#[allow(dead_code)] // Different unit tests use different subsets.
mod test_helpers {
    use super::BLOCK;

    /// Build a USTAR header with the given fields. `name` is split
    /// into prefix/name automatically up to the 155+100-byte limit.
    pub fn build_header(name: &str, size: u64, type_flag: u8) -> [u8; BLOCK] {
        let mut h = [0u8; BLOCK];
        // Split name across prefix (155) + name (100).
        let bytes = name.as_bytes();
        let (prefix, leaf): (&[u8], &[u8]) = if bytes.len() <= 100 {
            (&[], bytes)
        } else {
            // Find the last '/' within the first 155 bytes such that
            // the leaf fits in 100. This mirrors what `tar` does.
            let split = bytes[..155.min(bytes.len())]
                .iter()
                .rposition(|&b| b == b'/')
                .unwrap_or(0);
            (&bytes[..split], &bytes[split + 1..])
        };
        h[..leaf.len()].copy_from_slice(leaf);
        h[345..345 + prefix.len()].copy_from_slice(prefix);
        // Mode 0644 for files, 0755 for dirs (cosmetic — modes are
        // not applied by MVP).
        let mode = if type_flag == b'5' {
            b"0000755"
        } else {
            b"0000644"
        };
        h[100..107].copy_from_slice(mode);
        // uid/gid 0
        h[108..115].copy_from_slice(b"0000000");
        h[116..123].copy_from_slice(b"0000000");
        // size in octal, NUL-terminated to 12 bytes
        let size_str = format!("{size:011o}");
        h[124..124 + size_str.len()].copy_from_slice(size_str.as_bytes());
        // mtime
        h[136..147].copy_from_slice(b"00000000000");
        // typeflag
        h[156] = type_flag;
        // magic + version
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        // checksum: temporarily fill with spaces, sum, write octal
        h[148..156].fill(b' ');
        let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
        // 6 octal digits + NUL + space, classic tar form.
        let chk = format!("{sum:06o}\0 ");
        h[148..148 + chk.len()].copy_from_slice(chk.as_bytes());
        h
    }

    /// Build a PAX 'x' extended header body for the given key/value
    /// pairs. Each record is encoded as `<len> <key>=<value>\n`.
    pub fn build_pax_body(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::new();
        for (k, v) in pairs {
            // The length itself includes its own digit count plus the
            // space, the key, the '=', the value, and the trailing
            // newline. We solve the fixed point by trying digit counts
            // ascending from 1.
            let suffix_len = k.len() + v.len() + 3; // " " "=" "\n"
            for digits in 1..=20usize {
                let total = digits + suffix_len;
                let candidate = format!("{total}");
                if candidate.len() == digits {
                    out.extend_from_slice(candidate.as_bytes());
                    out.push(b' ');
                    out.extend_from_slice(k.as_bytes());
                    out.push(b'=');
                    out.extend_from_slice(v.as_bytes());
                    out.push(b'\n');
                    break;
                }
            }
        }
        out
    }

    /// Pad `body` up to the next 512-byte block with zero bytes.
    pub fn pad_block(body: &[u8]) -> Vec<u8> {
        let mut out = body.to_vec();
        let rem = out.len() % BLOCK;
        if rem != 0 {
            out.resize(out.len() + (BLOCK - rem), 0);
        }
        out
    }

    /// Append the two-zero-block end-of-archive marker.
    pub fn end_of_archive() -> Vec<u8> {
        vec![0u8; BLOCK * 2]
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use super::*;

    /// Minimal sanity check on the PAX parser: a single `path` record
    /// round-trips.
    #[test]
    fn pax_records_parse_single_path() {
        // "29 path=long/name/here.txt\n" — len includes the digits.
        let body = build_pax_body(&[("path", "long/name/here.txt")]);
        let records = parse_pax_records(&body, 0).expect("parse");
        assert_eq!(records, vec![("path".into(), "long/name/here.txt".into())]);
    }

    /// PAX `size` value can exceed the 8 GiB ustar octal limit. This
    /// is the §7.4 "ustar size limits" test: the parser correctly
    /// extracts a `size=10000000000` (10 GB) override without ever
    /// allocating the file's worth of memory.
    #[test]
    fn pax_records_size_can_exceed_ustar_octal_limit() {
        let body = build_pax_body(&[("size", "10000000000")]);
        let records = parse_pax_records(&body, 0).expect("parse");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "size");
        let n: u64 = records[0].1.parse().expect("u64");
        assert!(n > (1u64 << 33), "10 GB should exceed 8 GiB ustar limit");
    }

    /// Multiple records in one PAX body parse in order.
    #[test]
    fn pax_records_parse_multiple() {
        let body = build_pax_body(&[("path", "a/b"), ("size", "42")]);
        let records = parse_pax_records(&body, 0).expect("parse");
        assert_eq!(records.len(), 2);
        assert_eq!(records[0], ("path".into(), "a/b".into()));
        assert_eq!(records[1], ("size".into(), "42".into()));
    }

    /// A truncated PAX entry surfaces a [`SinkError::MalformedPax`].
    #[test]
    fn pax_records_truncated_errors() {
        // Length advertises 30 bytes but we provide only 5.
        let body = b"30 pa";
        match parse_pax_records(body, 1024) {
            Err(SinkError::MalformedPax { archive_offset, .. }) => assert_eq!(archive_offset, 1024),
            other => panic!("expected MalformedPax, got {other:?}"),
        }
    }

    /// Octal parsing accepts leading/trailing space and NUL padding
    /// and rejects non-octal bytes.
    #[test]
    fn parse_octal_accepts_field_padding() {
        assert_eq!(parse_octal(b"0000644 \0"), Some(0o644));
        assert_eq!(parse_octal(b"  10\0\0\0"), Some(0o10));
        assert_eq!(parse_octal(b"\0\0\0\0"), Some(0));
        assert_eq!(parse_octal(b"        "), Some(0));
    }

    #[test]
    fn parse_octal_rejects_non_digit() {
        assert_eq!(parse_octal(b"08\0"), None);
        assert_eq!(parse_octal(b"abc\0"), None);
    }

    /// `parse_numeric` falls through to octal parsing for the common
    /// case so existing fields keep working unchanged.
    #[test]
    fn parse_numeric_falls_through_to_octal() {
        assert_eq!(parse_numeric(b"0000644 \0"), Some(0o644));
        assert_eq!(parse_numeric(b"\0\0\0\0"), Some(0));
        assert_eq!(parse_numeric(b"08\0"), None);
    }

    /// GNU base-256: high bit of the first byte signals binary
    /// encoding. The remainder is a big-endian u64 — used for sizes
    /// that can't fit 11 octal digits.
    #[test]
    fn parse_numeric_decodes_gnu_base256() {
        // 12-byte size field encoding 0x0000_0001_0000_0000 (4 GiB)
        // — picked above the 8-decimal-digit boundary so the bytes
        // exercise the multi-byte shift loop.
        let mut field = [0u8; 12];
        field[0] = 0x80;
        field[7] = 0x01;
        assert_eq!(parse_numeric(&field), Some(0x1_0000_0000));

        // 10 GiB — what a "files larger than the octal cap" snapshot
        // produces in the wild.
        let mut field = [0u8; 12];
        field[0] = 0x80;
        let v: u64 = 10 * 1024 * 1024 * 1024;
        for (i, b) in v.to_be_bytes().iter().enumerate() {
            field[4 + i] = *b;
        }
        assert_eq!(parse_numeric(&field), Some(v));
    }

    /// Two's-complement-negative encoding (first byte `0xff`) is not
    /// used for non-negative tar fields and we explicitly reject it
    /// rather than silently sign-extending.
    #[test]
    fn parse_numeric_rejects_negative_base256() {
        let mut field = [0u8; 12];
        field[0] = 0xff;
        field[11] = 0x01;
        assert_eq!(parse_numeric(&field), None);
    }

    /// Values whose magnitude exceeds u64 — the field is 12 bytes so
    /// it can encode up to 256^11 — surface as `None` rather than
    /// wrapping silently.
    #[test]
    fn parse_numeric_rejects_overflow() {
        let mut field = [0u8; 12];
        field[0] = 0x80;
        field[1] = 0x01; // sets bit 64 of the result; overflows u64.
        assert_eq!(parse_numeric(&field), None);
    }

    /// End-to-end: a header whose size field uses GNU base-256
    /// parses through `ParsedHeader::from_bytes` (with checksum) the
    /// same way it would if the size were small enough for octal.
    /// This is the exact regression that surfaced as
    /// `malformed tar header at archive offset 1536: size field is
    /// not a valid octal value` on multi-TB chain snapshots.
    #[test]
    fn parsed_header_accepts_gnu_base256_size() {
        let huge: u64 = 12 * 1024 * 1024 * 1024; // 12 GiB > 8 GiB octal cap.
        let mut h = build_header("big.bin", 0, b'0');
        // Overwrite the size field with the base-256 form. Every byte
        // of the field participates in the checksum, so we have to
        // re-compute it after patching.
        h[124..136].fill(0);
        h[124] = 0x80;
        for (i, b) in huge.to_be_bytes().iter().enumerate() {
            h[128 + i] = *b;
        }
        // Re-run the checksum dance from `build_header`: spaces in the
        // chksum slot, sum, then write 6 octal digits + NUL + space.
        h[148..156].fill(b' ');
        let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
        let chk = format!("{sum:06o}\0 ");
        h[148..148 + chk.len()].copy_from_slice(chk.as_bytes());

        validate_checksum(&h, 0).expect("checksum must validate");
        let parsed = ParsedHeader::from_bytes(&h, 0).expect("size must parse");
        assert_eq!(parsed.size, huge);
    }

    #[test]
    fn padding_for_lands_on_block_boundary() {
        assert_eq!(padding_for(0), 0);
        assert_eq!(padding_for(1), 511);
        assert_eq!(padding_for(511), 1);
        assert_eq!(padding_for(512), 0);
        assert_eq!(padding_for(513), 511);
    }

    #[test]
    fn trim_nul_strips_trailing_nuls() {
        assert_eq!(trim_nul(b"hello\0\0\0"), b"hello");
        assert_eq!(trim_nul(b"\0\0"), b"" as &[u8]);
        assert_eq!(trim_nul(b"no_nul"), b"no_nul");
    }

    /// `validate_magic` rejects a header without the POSIX ustar
    /// signature.
    #[test]
    fn magic_rejects_non_ustar() {
        let mut h = [0u8; BLOCK];
        h[257..263].copy_from_slice(b"PADDED");
        match validate_magic(&h, 0) {
            Err(SinkError::MalformedHeader { .. }) => {}
            other => panic!("expected MalformedHeader, got {other:?}"),
        }
    }

    /// Old-GNU magic ("ustar  \0") is accepted; this is what the
    /// stock `gnu tar` CLI emits and what most cosmos / polkachu-style
    /// snapshot archives use.
    #[test]
    fn magic_accepts_old_gnu() {
        let mut h = [0u8; BLOCK];
        h[257..265].copy_from_slice(b"ustar  \x00");
        validate_magic(&h, 0).expect("old-GNU magic must validate");
    }

    /// A header built by `build_header` round-trips through
    /// `validate_checksum`.
    #[test]
    fn checksum_round_trip() {
        let h = build_header("hello.txt", 5, b'0');
        validate_checksum(&h, 0).expect("our own header should verify");
    }

    /// Tampering with a header byte trips the checksum check.
    #[test]
    fn checksum_detects_tampering() {
        let mut h = build_header("hello.txt", 5, b'0');
        h[10] ^= 0x80; // flip a bit in the name
        match validate_checksum(&h, 0) {
            Err(SinkError::BadChecksum { .. }) => {}
            other => panic!("expected BadChecksum, got {other:?}"),
        }
    }
}
