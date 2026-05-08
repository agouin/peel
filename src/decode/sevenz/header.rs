//! 7z trailer parser: `Header` / `EncodedHeader` / `StreamsInfo`
//! / `FilesInfo`.
//!
//! Implements §3 of `docs/PLAN_7z_support.md`. The trailer the
//! [`super::format::SignatureHeader`] points at is decoded into
//! the typed [`Trailer`] / [`Header`] / [`StreamsInfo`] /
//! [`FileRecord`] tree the §8 pipeline operates on.
//!
//! Two entry points cover the two trailer shapes:
//!
//! - [`parse_trailer`] reads the outermost trailer and returns
//!   [`Trailer::Plain`] (a fully decoded [`Header`]) or
//!   [`Trailer::Encoded`] (a [`StreamsInfo`] describing where the
//!   real header lives, packed bytes the caller must run through
//!   the §6 folder decoder before re-entering with
//!   [`parse_decoded_header`]).
//! - [`parse_decoded_header`] parses the bytes produced by
//!   decoding an `EncodedHeader`'s folder. It rejects nested
//!   encoded headers (the format admits the recursion in
//!   principle but no real archive nests).
//!
//! Round-one rejects, with [`SevenzError::UnsupportedFeature`]
//! naming the specific feature:
//!
//! - `AdditionalStreamsInfo` (`0x03`) — uncommon and not on the
//!   round-one feature list.
//! - `Anti = true` flagged files.
//! - `kStartPos` (`0x18`) per-file property — rare and unsupported.
//! - Coders flagged as `IsComplex` (multi-input/-output, e.g. BCJ2)
//!   or `IsAlternative`.
//! - Folders with non-linear bind-pair graphs (round-one only
//!   accepts the linear chain shape, validated structurally).
//! - External `Folder` lists (the `External = 1` branch of
//!   `kFolder`).
//! - External name / time / attribute property bodies.
//! - Encrypted EncodedHeaders (rejected at the
//!   §6 / §4 dispatch layer once the coder id is decoded; this
//!   parser surfaces the EncodedHeader's `StreamsInfo` and lets
//!   the caller make the call).
//!
//! All multi-byte integers in the `7zFormat.txt` reference are
//! variable-length [`super::number::parse_number`] values
//! (commonly notated `UINT64` in the reference). The exception
//! is recorded CRC32 values, which are raw 4-byte little-endian.

use std::path::PathBuf;

use crate::sevenz::SevenzError;

use super::number::{
    parse_bool_vector, parse_number, parse_propid, read_name_utf16le_zero_terminated,
};

/// 7z trailer property IDs (`NID` constants in
/// `DOC/7zFormat.txt`). Only the values round-one references are
/// named; unknown propids are skipped via the size-prefixed
/// FilesInfo body or surfaced as `CorruptHeader` outside FilesInfo.
pub mod nid {
    /// Sentinel terminating a propid sequence.
    pub const END: u8 = 0x00;
    /// Top-level `Header` marker — `Trailer::Plain` shape.
    pub const HEADER: u8 = 0x01;
    /// `ArchiveProperties` block — round-one accepts and skips.
    pub const ARCHIVE_PROPERTIES: u8 = 0x02;
    /// `AdditionalStreamsInfo` — round-one rejects.
    pub const ADDITIONAL_STREAMS_INFO: u8 = 0x03;
    /// `MainStreamsInfo` propid inside the top-level Header.
    pub const MAIN_STREAMS_INFO: u8 = 0x04;
    /// `FilesInfo` propid inside the top-level Header.
    pub const FILES_INFO: u8 = 0x05;
    /// `PackInfo` propid inside `StreamsInfo`.
    pub const PACK_INFO: u8 = 0x06;
    /// `UnPackInfo` propid inside `StreamsInfo`.
    pub const UNPACK_INFO: u8 = 0x07;
    /// `SubStreamsInfo` propid inside `StreamsInfo`.
    pub const SUBSTREAMS_INFO: u8 = 0x08;
    /// `Size` propid (PackSizes inside PackInfo, etc.).
    pub const SIZE: u8 = 0x09;
    /// `CRC` propid (PackStreamDigests inside PackInfo, etc.).
    pub const CRC: u8 = 0x0A;
    /// `Folder` propid inside `UnPackInfo`.
    pub const FOLDER: u8 = 0x0B;
    /// `CodersUnPackSize` propid inside `UnPackInfo`.
    pub const CODERS_UNPACK_SIZE: u8 = 0x0C;
    /// `NumUnPackStream` propid inside `SubStreamsInfo`.
    pub const NUM_UNPACK_STREAM: u8 = 0x0D;
    /// `EmptyStream` per-file flag vector.
    pub const EMPTY_STREAM: u8 = 0x0E;
    /// `EmptyFile` per-empty-stream flag vector.
    pub const EMPTY_FILE: u8 = 0x0F;
    /// `Anti` per-empty-stream flag vector — round-one rejects.
    pub const ANTI: u8 = 0x10;
    /// `Name` per-file property (UTF-16LE concatenation).
    pub const NAME: u8 = 0x11;
    /// `CTime` per-file property — round-one accepts and skips.
    pub const CTIME: u8 = 0x12;
    /// `ATime` per-file property — round-one accepts and skips.
    pub const ATIME: u8 = 0x13;
    /// `MTime` per-file property — round-one decodes.
    pub const MTIME: u8 = 0x14;
    /// `WinAttributes` per-file property — round-one decodes.
    pub const WIN_ATTRIBUTES: u8 = 0x15;
    /// Deprecated `Comment` propid.
    pub const COMMENT: u8 = 0x16;
    /// `EncodedHeader` top-level marker — `Trailer::Encoded` shape.
    pub const ENCODED_HEADER: u8 = 0x17;
    /// `StartPos` per-file property — round-one rejects.
    pub const START_POS: u8 = 0x18;
    /// `Dummy` padding property — round-one accepts and skips.
    pub const DUMMY: u8 = 0x19;
}

/// Outcome of [`parse_trailer`]: either a fully decoded
/// [`Header`] (plain trailer) or a [`StreamsInfo`] describing
/// where the *real* header is packed (encoded trailer).
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Trailer {
    /// Plain header: parser saw `kHeader` (0x01) and decoded
    /// the rest end-to-end.
    Plain(Header),
    /// Encoded header: parser saw `kEncodedHeader` (0x17). The
    /// caller runs the §6 folder decoder against the
    /// [`Self::Encoded::streams_info`] folder, then re-enters
    /// [`parse_decoded_header`] on the decoded bytes.
    Encoded {
        /// The embedded `StreamsInfo` describing how the
        /// trailer is packed.
        streams_info: StreamsInfo,
    },
}

/// Fully decoded plain header.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct Header {
    /// `MainStreamsInfo` (NID 0x04) block, if present. An archive
    /// with no stream-bearing files can omit it.
    pub main_streams: Option<StreamsInfo>,
    /// `FilesInfo` (NID 0x05) block, if present. Archives with
    /// empty file lists can omit it.
    pub files: Vec<FileRecord>,
    /// Mapping from folder index to the `files` indices that
    /// take their bytes from that folder, in substream order.
    /// Built at parse time from `main_streams.sub_streams` +
    /// `files`. Length equals
    /// `main_streams.as_ref().map(|s| s.folders.len()).unwrap_or(0)`.
    pub folder_to_files: Vec<Vec<u32>>,
}

/// `StreamsInfo` block — used as both `MainStreamsInfo` (top-
/// level archive layout) and the embedded body of an
/// `EncodedHeader`.
///
/// Layout:
///
/// ```text
///   PackInfo   (optional; required if any folder takes data)
///   UnPackInfo (optional; required if PackInfo is present)
///   SubStreamsInfo (optional; defaults to one substream per folder)
///   End (0x00)
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct StreamsInfo {
    /// Absolute byte offset (relative to the byte immediately
    /// after the [`super::format::SIGNATURE_HEADER_LEN`] prefix)
    /// where the packed data section begins.
    pub pack_pos: u64,
    /// Sizes of each consecutive packed stream, in archive order.
    pub pack_sizes: Vec<u64>,
    /// Per-pack-stream CRC32, where present. `None` slots mean
    /// the archive did not record a CRC for that pack stream.
    pub pack_crcs: Vec<Option<u32>>,
    /// Folder definitions, one per folder. Each describes its
    /// coder chain and unpack sizes.
    pub folders: Vec<Folder>,
    /// Substream-level information mapping folders → output
    /// substreams (= files, in the §3 sense). Always populated
    /// even if `SubStreamsInfo` is absent in the wire — defaults
    /// to one substream per folder.
    pub sub_streams: SubStreamsInfo,
}

/// One folder: a linear chain of coders that consumes one
/// packed stream and produces one decoded stream of bytes.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct Folder {
    /// Coders in chain order. Round-one accepts only
    /// 1-input/1-output coders and a linear bind structure.
    pub coders: Vec<Coder>,
    /// Bind pairs encoding the coder graph. Round-one validates
    /// these as linear (`out_index = i, in_index = i + 1` for
    /// `i = 0..coders.len() - 1`).
    pub bind_pairs: Vec<BindPair>,
    /// Indices into the folder's input streams that correspond
    /// to packed (i.e. consumed-from-the-archive) streams.
    /// Round-one accepts only one packed stream per folder; the
    /// list is empty when the wire format omits it (the
    /// single-packed-stream-default case).
    pub packed_stream_indices: Vec<u32>,
    /// Per-output-stream uncompressed sizes, indexed in the
    /// flattened `coders[i].num_out_streams` order. The
    /// "primary" output (the folder's final decoded stream) is
    /// the last one not consumed by any bind pair as an input
    /// — for a linear chain this is the last coder's output.
    pub unpack_sizes: Vec<u64>,
    /// CRC32 of the final decoded folder output, if recorded.
    pub unpack_crc: Option<u32>,
}

impl Folder {
    /// Return the index into [`Self::unpack_sizes`] that names
    /// the folder's *primary* (final) output stream — the one
    /// the substream decoder consumes.
    ///
    /// For a linear N-coder chain, the primary output is at
    /// index `N - 1`: every other output is the source of a
    /// bind pair, and the primary is the only one not
    /// consumed.
    ///
    /// # Errors
    ///
    /// [`SevenzError::CorruptHeader`] if the folder has zero
    /// coders or the bind structure is degenerate.
    pub fn primary_unpack_size(&self) -> Result<u64, SevenzError> {
        let primary_idx = self.primary_output_index()?;
        self.unpack_sizes
            .get(primary_idx as usize)
            .copied()
            .ok_or_else(|| SevenzError::CorruptHeader {
                reason: format!(
                    "folder primary output index {primary_idx} out of range \
                     (unpack_sizes.len() = {})",
                    self.unpack_sizes.len(),
                ),
            })
    }

    /// Index, into the flattened output-stream space, of the
    /// folder's primary output (the one not consumed by any
    /// bind pair as an input).
    ///
    /// # Errors
    ///
    /// [`SevenzError::CorruptHeader`] if no such index exists
    /// or there are multiple candidates (indicates a non-
    /// linear graph that round-one shouldn't have accepted).
    pub fn primary_output_index(&self) -> Result<u32, SevenzError> {
        if self.coders.is_empty() {
            return Err(SevenzError::CorruptHeader {
                reason: "folder has no coders".into(),
            });
        }
        let total_out: u32 = self.coders.iter().map(|c| c.num_out_streams).sum::<u32>();
        let consumed: std::collections::BTreeSet<u32> =
            self.bind_pairs.iter().map(|b| b.out_index).collect();
        let mut primary: Option<u32> = None;
        for idx in 0..total_out {
            if consumed.contains(&idx) {
                continue;
            }
            if let Some(prev) = primary {
                return Err(SevenzError::CorruptHeader {
                    reason: format!(
                        "folder has multiple unbound output streams \
                         (already saw {prev}, also {idx})",
                    ),
                });
            }
            primary = Some(idx);
        }
        primary.ok_or_else(|| SevenzError::CorruptHeader {
            reason: "folder has no unbound output stream".into(),
        })
    }
}

/// One coder inside a [`Folder`]. The id, props, and stream
/// counts are passed to the §4 coder-registry dispatch.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Coder {
    /// Codec id bytes verbatim. Length is 1..=15 (encoded as a
    /// 4-bit `idSize` field in the wire flags). Round-one
    /// dispatches the supported set: `[0x00]` (COPY), `[0x21]`
    /// (LZMA2), `[0x03, 0x01, 0x01]` (LZMA),
    /// `[0x04, 0x01, 0x08]` (DEFLATE).
    pub id: Vec<u8>,
    /// Coder-specific properties bytes (e.g. LZMA's 5-byte
    /// `(properties, dict_size)` blob, LZMA2's 1-byte
    /// `dictSize` field). Empty when the coder declared no
    /// `HasAttribs` flag.
    pub props: Vec<u8>,
    /// Number of input streams this coder consumes. `1` for
    /// every round-one-supported coder (`IsComplex` is
    /// rejected at parse time).
    pub num_in_streams: u32,
    /// Number of output streams this coder produces. `1` for
    /// every round-one-supported coder.
    pub num_out_streams: u32,
}

/// One bind-pair: input stream `in_index` consumes the bytes
/// produced by output stream `out_index`. Indices are into the
/// flattened per-folder stream space (concatenation of
/// `coders[i].num_in_streams` / `num_out_streams`).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct BindPair {
    /// Index in the folder's flattened input-stream space.
    pub in_index: u32,
    /// Index in the folder's flattened output-stream space.
    pub out_index: u32,
}

/// Substream-level layout: how each folder's primary output
/// stream is partitioned among files.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct SubStreamsInfo {
    /// Number of substreams per folder, in folder order.
    /// Length equals `folders.len()` after the parser
    /// canonicalizes (filling default 1 for absent
    /// `SubStreamsInfo`).
    pub num_unpack_streams: Vec<u32>,
    /// Per-substream uncompressed sizes, in the flattened
    /// per-folder substream order. Length equals
    /// `sum(num_unpack_streams)`.
    pub unpack_sizes: Vec<u64>,
    /// Per-substream CRC32, where present.
    pub unpack_crcs: Vec<Option<u32>>,
}

/// One file (or directory, or empty file) the archive
/// contains.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FileRecord {
    /// Sanitized output path (per `super::number` §1.5 rules).
    pub name: PathBuf,
    /// Windows attributes word, when the archive recorded one.
    pub attrs: Option<u32>,
    /// Last-modified time, when the archive recorded one. The
    /// value is the raw 7z `FILETIME` (100-ns intervals since
    /// 1601-01-01 UTC); the §7 sink converts to platform-
    /// native time when writing.
    pub mtime: Option<i64>,
    /// `true` for entries whose `EmptyStream` flag is set and
    /// whose `EmptyFile` flag is clear — i.e. directory
    /// entries, materialized as `mkdir -p` by the §7 sink.
    pub is_directory: bool,
    /// `true` iff the file consumes bytes from a folder. When
    /// `false` the file is either an empty regular file or a
    /// directory entry; either way the §7 sink does not call
    /// `FolderSink::write` for it.
    pub has_stream: bool,
    /// `true` iff the archive flagged this entry as
    /// "anti-file" (a delete-on-extract marker). Round-one
    /// rejects archives containing any anti-file at parse
    /// time, so this field is always `false` on a successful
    /// parse and exists for diagnostic completeness.
    pub is_anti: bool,
}

/// Parse the outermost trailer.
///
/// `buf` must contain the entire trailer (the §2 parser tells
/// you exactly how many bytes that is). The parser dispatches
/// on the first byte:
///
/// - `0x01` (`kHeader`): decode the rest into [`Header`]
///   ([`Trailer::Plain`]).
/// - `0x17` (`kEncodedHeader`): decode the embedded
///   `StreamsInfo` and return it ([`Trailer::Encoded`]). The
///   caller runs the §6 folder decoder, then calls
///   [`parse_decoded_header`] on the decoded bytes.
///
/// # Errors
///
/// - [`SevenzError::Truncated`] if the buffer ends mid-field.
/// - [`SevenzError::CorruptHeader`] for an unexpected first
///   byte or any inconsistency surfaced by the parsers below.
/// - [`SevenzError::UnsupportedFeature`] for any deferred
///   feature; the variant's `feature` field carries the
///   specific name.
/// - [`SevenzError::BadName`] for a name that fails §1.5
///   sanitization.
pub fn parse_trailer(buf: &[u8]) -> Result<Trailer, SevenzError> {
    let (tag, rest) = parse_propid(buf)?;
    match tag {
        nid::HEADER => {
            let (header, _) = parse_header_body(rest)?;
            Ok(Trailer::Plain(header))
        }
        nid::ENCODED_HEADER => {
            let (streams_info, _) = parse_streams_info(rest)?;
            Ok(Trailer::Encoded { streams_info })
        }
        other => Err(SevenzError::CorruptHeader {
            reason: format!(
                "expected trailer to begin with kHeader (0x01) or \
                 kEncodedHeader (0x17), found {other:#04x}",
            ),
        }),
    }
}

/// Parse the bytes produced by decoding an
/// [`Trailer::Encoded`]'s folder. Rejects nested encoded
/// headers (a real archive never nests).
///
/// # Errors
///
/// Same as [`parse_trailer`], plus
/// [`SevenzError::UnsupportedFeature`] for nested encoded
/// headers.
pub fn parse_decoded_header(buf: &[u8]) -> Result<Header, SevenzError> {
    let (tag, rest) = parse_propid(buf)?;
    match tag {
        nid::HEADER => {
            let (header, _) = parse_header_body(rest)?;
            Ok(header)
        }
        nid::ENCODED_HEADER => Err(SevenzError::UnsupportedFeature {
            feature: "nested encoded headers".into(),
        }),
        other => Err(SevenzError::CorruptHeader {
            reason: format!(
                "expected decoded header to begin with kHeader (0x01), \
                 found {other:#04x}",
            ),
        }),
    }
}

/// Parse the body of a top-level `kHeader` (the propid has
/// already been consumed). Returns the decoded [`Header`]
/// plus the unconsumed remainder (typically empty).
fn parse_header_body(input: &[u8]) -> Result<(Header, &[u8]), SevenzError> {
    let mut cursor = input;
    let mut main_streams: Option<StreamsInfo> = None;
    let mut files: Vec<FileRecord> = Vec::new();
    let mut sub_streams_for_mapping: Option<SubStreamsInfo> = None;
    loop {
        let (tag, rest) = parse_propid(cursor)?;
        cursor = rest;
        match tag {
            nid::END => break,
            nid::ARCHIVE_PROPERTIES => {
                // Round-one accepts and skips: read body until kEnd,
                // discarding properties.
                cursor = skip_archive_properties(cursor)?;
            }
            nid::ADDITIONAL_STREAMS_INFO => {
                return Err(SevenzError::UnsupportedFeature {
                    feature: "AdditionalStreamsInfo (NID 0x03)".into(),
                });
            }
            nid::MAIN_STREAMS_INFO => {
                let (info, rest2) = parse_streams_info(cursor)?;
                cursor = rest2;
                sub_streams_for_mapping = Some(info.sub_streams.clone());
                main_streams = Some(info);
            }
            nid::FILES_INFO => {
                let (parsed_files, rest2) = parse_files_info(cursor)?;
                cursor = rest2;
                files = parsed_files;
            }
            other => {
                return Err(SevenzError::CorruptHeader {
                    reason: format!("unexpected propid {other:#04x} inside top-level Header",),
                });
            }
        }
    }

    let folder_to_files = build_folder_to_files_mapping(
        main_streams.as_ref(),
        &files,
        sub_streams_for_mapping.as_ref(),
    )?;

    Ok((
        Header {
            main_streams,
            files,
            folder_to_files,
        },
        cursor,
    ))
}

/// Skip an `ArchiveProperties` block: a sequence of
/// `(propid, size, body)` triples terminated by `propid == 0x00`.
fn skip_archive_properties(mut cursor: &[u8]) -> Result<&[u8], SevenzError> {
    loop {
        let (tag, rest) = parse_propid(cursor)?;
        cursor = rest;
        if tag == nid::END {
            return Ok(cursor);
        }
        let (size, rest) = parse_number(cursor)?;
        let size = usize::try_from(size).map_err(|_| SevenzError::CorruptHeader {
            reason: "ArchiveProperties property size exceeds usize".into(),
        })?;
        if rest.len() < size {
            return Err(SevenzError::Truncated {
                what: "ArchiveProperties body".into(),
                needed: size - rest.len(),
            });
        }
        cursor = &rest[size..];
    }
}

/// Parse a `StreamsInfo` block (the body — caller has already
/// consumed the leading propid, e.g. `kMainStreamsInfo`).
///
/// Returns the canonicalized [`StreamsInfo`] plus the
/// unconsumed remainder. "Canonicalized" means
/// `sub_streams.num_unpack_streams.len() == folders.len()`
/// even when `SubStreamsInfo` was absent.
pub fn parse_streams_info(input: &[u8]) -> Result<(StreamsInfo, &[u8]), SevenzError> {
    let mut cursor = input;
    let mut info = StreamsInfo::default();
    let mut have_pack_info = false;
    let mut have_unpack_info = false;
    let mut have_sub_streams_info = false;
    loop {
        let (tag, rest) = parse_propid(cursor)?;
        cursor = rest;
        match tag {
            nid::END => break,
            nid::PACK_INFO => {
                if have_pack_info {
                    return Err(SevenzError::CorruptHeader {
                        reason: "duplicate PackInfo".into(),
                    });
                }
                cursor = parse_pack_info(cursor, &mut info)?;
                have_pack_info = true;
            }
            nid::UNPACK_INFO => {
                if have_unpack_info {
                    return Err(SevenzError::CorruptHeader {
                        reason: "duplicate UnPackInfo".into(),
                    });
                }
                cursor = parse_unpack_info(cursor, &mut info)?;
                have_unpack_info = true;
            }
            nid::SUBSTREAMS_INFO => {
                if have_sub_streams_info {
                    return Err(SevenzError::CorruptHeader {
                        reason: "duplicate SubStreamsInfo".into(),
                    });
                }
                cursor = parse_substreams_info(cursor, &mut info)?;
                have_sub_streams_info = true;
            }
            other => {
                return Err(SevenzError::CorruptHeader {
                    reason: format!("unexpected propid {other:#04x} inside StreamsInfo",),
                });
            }
        }
    }

    // Canonicalize: every folder produces at least one substream.
    // Default to one substream per folder, with size = the
    // folder's primary output size and CRC = the folder's
    // unpack_crc, if SubStreamsInfo was absent.
    if !have_sub_streams_info && !info.folders.is_empty() {
        info.sub_streams.num_unpack_streams = vec![1; info.folders.len()];
        info.sub_streams.unpack_sizes = info
            .folders
            .iter()
            .map(Folder::primary_unpack_size)
            .collect::<Result<Vec<_>, _>>()?;
        info.sub_streams.unpack_crcs = info.folders.iter().map(|f| f.unpack_crc).collect();
    }

    Ok((info, cursor))
}

/// Parse a `PackInfo` block (caller has consumed the
/// `kPackInfo` propid). Mutates `info.pack_pos`,
/// `info.pack_sizes`, and `info.pack_crcs`.
fn parse_pack_info<'a>(input: &'a [u8], info: &mut StreamsInfo) -> Result<&'a [u8], SevenzError> {
    let (pack_pos, rest) = parse_number(input)?;
    let (num_pack_streams, mut cursor) = parse_number(rest)?;
    let num_pack_streams =
        usize::try_from(num_pack_streams).map_err(|_| SevenzError::CorruptHeader {
            reason: "NumPackStreams exceeds usize".into(),
        })?;
    info.pack_pos = pack_pos;

    loop {
        let (tag, rest) = parse_propid(cursor)?;
        cursor = rest;
        match tag {
            nid::END => break,
            nid::SIZE => {
                let mut sizes = Vec::with_capacity(num_pack_streams);
                for _ in 0..num_pack_streams {
                    let (s, rest) = parse_number(cursor)?;
                    cursor = rest;
                    sizes.push(s);
                }
                info.pack_sizes = sizes;
            }
            nid::CRC => {
                let (crcs, rest) = parse_optional_crc_vec(cursor, num_pack_streams)?;
                cursor = rest;
                info.pack_crcs = crcs;
            }
            other => {
                return Err(SevenzError::CorruptHeader {
                    reason: format!("unexpected propid {other:#04x} inside PackInfo",),
                });
            }
        }
    }

    if info.pack_sizes.len() != num_pack_streams {
        return Err(SevenzError::CorruptHeader {
            reason: format!(
                "PackInfo declared {num_pack_streams} pack streams but \
                 produced {} sizes",
                info.pack_sizes.len(),
            ),
        });
    }
    if info.pack_crcs.is_empty() {
        info.pack_crcs = vec![None; num_pack_streams];
    }
    Ok(cursor)
}

/// Parse an `UnPackInfo` block (caller has consumed the
/// `kUnPackInfo` propid). Mutates `info.folders`.
fn parse_unpack_info<'a>(input: &'a [u8], info: &mut StreamsInfo) -> Result<&'a [u8], SevenzError> {
    let mut cursor = input;
    let (folder_tag, rest) = parse_propid(cursor)?;
    cursor = rest;
    if folder_tag != nid::FOLDER {
        return Err(SevenzError::CorruptHeader {
            reason: format!("expected kFolder (0x0B) inside UnPackInfo, found {folder_tag:#04x}",),
        });
    }

    let (num_folders, rest) = parse_number(cursor)?;
    let num_folders = usize::try_from(num_folders).map_err(|_| SevenzError::CorruptHeader {
        reason: "NumFolders exceeds usize".into(),
    })?;
    cursor = rest;

    let (external, rest) = parse_propid(cursor)?;
    cursor = rest;
    if external != 0 {
        return Err(SevenzError::UnsupportedFeature {
            feature: "external folder list (UnPackInfo External=1)".into(),
        });
    }

    let mut folders = Vec::with_capacity(num_folders);
    for _ in 0..num_folders {
        let (folder, rest) = parse_folder_definition(cursor)?;
        cursor = rest;
        folders.push(folder);
    }

    // CodersUnPackSize: per-output-stream sizes, flattened across all coders.
    let (coder_unpack_size_tag, rest) = parse_propid(cursor)?;
    cursor = rest;
    if coder_unpack_size_tag != nid::CODERS_UNPACK_SIZE {
        return Err(SevenzError::CorruptHeader {
            reason: format!(
                "expected kCodersUnPackSize (0x0C) after Folders, \
                 found {coder_unpack_size_tag:#04x}",
            ),
        });
    }
    for folder in &mut folders {
        let total_out: u32 = folder.coders.iter().map(|c| c.num_out_streams).sum();
        let mut sizes = Vec::with_capacity(total_out as usize);
        for _ in 0..total_out {
            let (s, rest) = parse_number(cursor)?;
            cursor = rest;
            sizes.push(s);
        }
        folder.unpack_sizes = sizes;
    }

    // Optional CRCs + End.
    loop {
        let (tag, rest) = parse_propid(cursor)?;
        cursor = rest;
        match tag {
            nid::END => break,
            nid::CRC => {
                let (crcs, rest) = parse_optional_crc_vec(cursor, num_folders)?;
                cursor = rest;
                for (folder, crc) in folders.iter_mut().zip(crcs) {
                    folder.unpack_crc = crc;
                }
            }
            other => {
                return Err(SevenzError::CorruptHeader {
                    reason: format!(
                        "unexpected propid {other:#04x} inside UnPackInfo \
                         after CodersUnPackSize",
                    ),
                });
            }
        }
    }

    info.folders = folders;
    Ok(cursor)
}

/// Parse one `Folder` (a CodersInfo block describing a coder
/// chain plus its bind / pack-stream-index plumbing).
fn parse_folder_definition(input: &[u8]) -> Result<(Folder, &[u8]), SevenzError> {
    let (num_coders, mut cursor) = parse_number(input)?;
    let num_coders = usize::try_from(num_coders).map_err(|_| SevenzError::CorruptHeader {
        reason: "NumCoders exceeds usize".into(),
    })?;
    if num_coders == 0 {
        return Err(SevenzError::CorruptHeader {
            reason: "folder has zero coders".into(),
        });
    }

    let mut coders = Vec::with_capacity(num_coders);
    for _ in 0..num_coders {
        let (coder, rest) = parse_one_coder(cursor)?;
        cursor = rest;
        coders.push(coder);
    }

    let total_in: u32 = coders.iter().map(|c| c.num_in_streams).sum();
    let total_out: u32 = coders.iter().map(|c| c.num_out_streams).sum();
    let num_bind_pairs = total_out
        .checked_sub(1)
        .ok_or_else(|| SevenzError::CorruptHeader {
            reason: "folder has zero output streams".into(),
        })?;

    let mut bind_pairs = Vec::with_capacity(num_bind_pairs as usize);
    for _ in 0..num_bind_pairs {
        let (in_index, rest) = parse_number(cursor)?;
        cursor = rest;
        let (out_index, rest) = parse_number(cursor)?;
        cursor = rest;
        let in_index = u32::try_from(in_index).map_err(|_| SevenzError::CorruptHeader {
            reason: "BindPair InIndex exceeds u32".into(),
        })?;
        let out_index = u32::try_from(out_index).map_err(|_| SevenzError::CorruptHeader {
            reason: "BindPair OutIndex exceeds u32".into(),
        })?;
        if in_index >= total_in {
            return Err(SevenzError::CorruptHeader {
                reason: format!("BindPair InIndex {in_index} >= total_in {total_in}",),
            });
        }
        if out_index >= total_out {
            return Err(SevenzError::CorruptHeader {
                reason: format!("BindPair OutIndex {out_index} >= total_out {total_out}",),
            });
        }
        bind_pairs.push(BindPair {
            in_index,
            out_index,
        });
    }

    let num_packed_streams =
        total_in
            .checked_sub(num_bind_pairs)
            .ok_or_else(|| SevenzError::CorruptHeader {
                reason: format!("total_in {total_in} < num_bind_pairs {num_bind_pairs}",),
            })?;
    let packed_stream_indices: Vec<u32> = Vec::new();
    if num_packed_streams != 1 {
        if num_packed_streams == 0 {
            return Err(SevenzError::CorruptHeader {
                reason: "folder has zero packed input streams".into(),
            });
        }
        // Round-one rejects multi-packed-stream folders (they
        // arise only from non-linear graphs we already reject).
        return Err(SevenzError::UnsupportedFeature {
            feature: format!(
                "folder with {num_packed_streams} packed input streams \
                 (round-one supports linear single-packed chains only)",
            ),
        });
    }
    // Validate bind-pair structure: linear chain only.
    validate_linear_bind_pairs(&coders, &bind_pairs)?;

    Ok((
        Folder {
            coders,
            bind_pairs,
            packed_stream_indices,
            unpack_sizes: Vec::new(),
            unpack_crc: None,
        },
        cursor,
    ))
}

/// Verify `bind_pairs` form a linear chain over `coders`:
/// each coder is 1-in/1-out, and the pairs collectively assign
/// `out_index = i` to `in_index = i + 1` for `i = 0..coders.len()-1`.
///
/// Round-one's coders are all simple (1-in 1-out) by the
/// rejection in [`parse_one_coder`], so this also serves as an
/// existence proof that the runtime can decode the chain by
/// running coders in order.
fn validate_linear_bind_pairs(
    coders: &[Coder],
    bind_pairs: &[BindPair],
) -> Result<(), SevenzError> {
    for (i, c) in coders.iter().enumerate() {
        if c.num_in_streams != 1 || c.num_out_streams != 1 {
            return Err(SevenzError::UnsupportedFeature {
                feature: format!(
                    "non-linear coder graph: coder {i} has \
                     {} input(s) and {} output(s)",
                    c.num_in_streams, c.num_out_streams,
                ),
            });
        }
    }
    if bind_pairs.len() + 1 != coders.len() {
        return Err(SevenzError::CorruptHeader {
            reason: format!(
                "expected {} bind pairs for linear chain of {} coders, \
                 got {}",
                coders.len() - 1,
                coders.len(),
                bind_pairs.len(),
            ),
        });
    }
    // Build a map: out_index → in_index. Validate each pairing
    // respects the linear order (out i feeds in i+1).
    let mut map = std::collections::BTreeMap::new();
    for bp in bind_pairs {
        if map.insert(bp.out_index, bp.in_index).is_some() {
            return Err(SevenzError::CorruptHeader {
                reason: format!("duplicate bind pair on out_index {}", bp.out_index),
            });
        }
    }
    for i in 0..(coders.len() as u32 - 1) {
        let want_in = i + 1;
        match map.get(&i) {
            Some(&got) if got == want_in => {}
            Some(&got) => {
                return Err(SevenzError::UnsupportedFeature {
                    feature: format!(
                        "non-linear coder graph: out {i} bound to in {got}, \
                         expected in {want_in}",
                    ),
                });
            }
            None => {
                return Err(SevenzError::CorruptHeader {
                    reason: format!("missing bind pair for out_index {i}"),
                });
            }
        }
    }
    Ok(())
}

/// Parse one coder definition inside a Folder block.
fn parse_one_coder(input: &[u8]) -> Result<(Coder, &[u8]), SevenzError> {
    let (flags, rest) = parse_propid(input).map_err(|_| SevenzError::Truncated {
        what: "coder flags byte".into(),
        needed: 1,
    })?;
    let codec_id_size = (flags & 0x0F) as usize;
    let is_complex = (flags & 0x10) != 0;
    let has_attribs = (flags & 0x20) != 0;
    let is_alternative = (flags & 0x80) != 0;
    if is_alternative {
        return Err(SevenzError::UnsupportedFeature {
            feature: "alternative coder method (flag 0x80)".into(),
        });
    }
    if codec_id_size == 0 || codec_id_size > 15 {
        return Err(SevenzError::CorruptHeader {
            reason: format!("coder id size {codec_id_size} out of range 1..=15",),
        });
    }
    if rest.len() < codec_id_size {
        return Err(SevenzError::Truncated {
            what: format!("coder id ({codec_id_size} bytes)"),
            needed: codec_id_size - rest.len(),
        });
    }
    let (id_bytes, mut cursor) = rest.split_at(codec_id_size);

    let (num_in, num_out) = if is_complex {
        // Round-one rejects every multi-input / multi-output
        // coder: BCJ2 etc. The wire then carries
        // `(NumInStreams, NumOutStreams)` Numbers we have to
        // step past before surfacing the error so the rest of
        // the buffer stays positioned on a valid propid (this
        // matters because the parser is sometimes invoked on
        // archives we'd like to enumerate even if we can't
        // extract). Read but discard.
        let (n_in, rest) = parse_number(cursor)?;
        let (n_out, rest) = parse_number(rest)?;
        let _ = (cursor, rest);
        return Err(SevenzError::UnsupportedFeature {
            feature: format!("complex coder ({n_in} input(s), {n_out} output(s))",),
        });
    } else {
        (1u32, 1u32)
    };

    let props = if has_attribs {
        let (size, rest) = parse_number(cursor)?;
        let size = usize::try_from(size).map_err(|_| SevenzError::CorruptHeader {
            reason: "coder properties size exceeds usize".into(),
        })?;
        if rest.len() < size {
            return Err(SevenzError::Truncated {
                what: "coder properties body".into(),
                needed: size - rest.len(),
            });
        }
        let (body, rest) = rest.split_at(size);
        cursor = rest;
        body.to_vec()
    } else {
        Vec::new()
    };

    Ok((
        Coder {
            id: id_bytes.to_vec(),
            props,
            num_in_streams: num_in,
            num_out_streams: num_out,
        },
        cursor,
    ))
}

/// Parse `SubStreamsInfo` (caller has consumed the `kSubStreamsInfo`
/// propid). Populates `info.sub_streams`.
fn parse_substreams_info<'a>(
    input: &'a [u8],
    info: &mut StreamsInfo,
) -> Result<&'a [u8], SevenzError> {
    let folder_count = info.folders.len();
    let mut cursor = input;
    let mut num_unpack_streams: Vec<u32> = vec![1; folder_count];
    let mut explicit_substream_sizes: Vec<u64> = Vec::new();
    let mut explicit_substream_crcs: Vec<Option<u32>> = Vec::new();
    let mut have_size = false;
    let mut have_crc = false;
    loop {
        let (tag, rest) = parse_propid(cursor)?;
        cursor = rest;
        match tag {
            nid::END => break,
            nid::NUM_UNPACK_STREAM => {
                let mut counts = Vec::with_capacity(folder_count);
                for _ in 0..folder_count {
                    let (n, rest) = parse_number(cursor)?;
                    cursor = rest;
                    let n = u32::try_from(n).map_err(|_| SevenzError::CorruptHeader {
                        reason: "SubStreamsInfo NumUnpackStream exceeds u32".into(),
                    })?;
                    counts.push(n);
                }
                num_unpack_streams = counts;
            }
            nid::SIZE => {
                // Per spec: for each folder with N substreams, only
                // the first N-1 sizes are recorded; the last is
                // implied (= folder.primary_unpack_size - sum of
                // listed sizes).
                let mut sizes = Vec::new();
                for (folder_idx, &count) in num_unpack_streams.iter().enumerate() {
                    if count == 0 {
                        continue;
                    }
                    let mut sum = 0u64;
                    for _ in 0..count.saturating_sub(1) {
                        let (s, rest) = parse_number(cursor)?;
                        cursor = rest;
                        sum = sum
                            .checked_add(s)
                            .ok_or_else(|| SevenzError::CorruptHeader {
                                reason: format!(
                                    "substream size sum overflows u64 in folder {folder_idx}",
                                ),
                            })?;
                        sizes.push(s);
                    }
                    if count >= 1 {
                        let folder = info.folders.get(folder_idx).ok_or_else(|| {
                            SevenzError::CorruptHeader {
                                reason: format!(
                                    "SubStreamsInfo references folder {folder_idx} \
                                     but only {} folders parsed",
                                    info.folders.len(),
                                ),
                            }
                        })?;
                        let primary = folder.primary_unpack_size()?;
                        let last =
                            primary
                                .checked_sub(sum)
                                .ok_or_else(|| SevenzError::CorruptHeader {
                                    reason: format!(
                                        "substream sizes sum {sum} > folder {folder_idx} \
                                     primary unpack size {primary}",
                                    ),
                                })?;
                        sizes.push(last);
                    }
                }
                explicit_substream_sizes = sizes;
                have_size = true;
            }
            nid::CRC => {
                let total_substreams: u64 = num_unpack_streams.iter().map(|&n| n as u64).sum();
                let total_substreams =
                    usize::try_from(total_substreams).map_err(|_| SevenzError::CorruptHeader {
                        reason: "total substream count exceeds usize".into(),
                    })?;
                let (crcs, rest) = parse_optional_crc_vec(cursor, total_substreams)?;
                cursor = rest;
                explicit_substream_crcs = crcs;
                have_crc = true;
            }
            other => {
                return Err(SevenzError::CorruptHeader {
                    reason: format!("unexpected propid {other:#04x} inside SubStreamsInfo",),
                });
            }
        }
    }

    let total_substreams: u64 = num_unpack_streams.iter().map(|&n| n as u64).sum();
    let total_substreams =
        usize::try_from(total_substreams).map_err(|_| SevenzError::CorruptHeader {
            reason: "total substream count exceeds usize".into(),
        })?;

    // If sizes weren't explicit and any folder has >1 substream,
    // the file is malformed — single-substream folders default
    // to `primary_unpack_size` for that folder.
    let unpack_sizes = if have_size {
        if explicit_substream_sizes.len() != total_substreams {
            return Err(SevenzError::CorruptHeader {
                reason: format!(
                    "SubStreamsInfo Size produced {} entries but expected {}",
                    explicit_substream_sizes.len(),
                    total_substreams,
                ),
            });
        }
        explicit_substream_sizes
    } else {
        let mut sizes = Vec::with_capacity(total_substreams);
        for (folder_idx, &count) in num_unpack_streams.iter().enumerate() {
            if count == 0 {
                continue;
            }
            if count != 1 {
                return Err(SevenzError::CorruptHeader {
                    reason: format!(
                        "SubStreamsInfo missing Size property but folder \
                         {folder_idx} has {count} substreams",
                    ),
                });
            }
            let folder = &info.folders[folder_idx];
            sizes.push(folder.primary_unpack_size()?);
        }
        sizes
    };

    let unpack_crcs = if have_crc {
        if explicit_substream_crcs.len() != total_substreams {
            return Err(SevenzError::CorruptHeader {
                reason: format!(
                    "SubStreamsInfo CRC produced {} entries but expected {}",
                    explicit_substream_crcs.len(),
                    total_substreams,
                ),
            });
        }
        explicit_substream_crcs
    } else {
        // Fall back to per-folder unpack_crc when each folder has
        // exactly one substream (the only case where the mapping
        // is unambiguous); otherwise None.
        let mut crcs = Vec::with_capacity(total_substreams);
        for (folder_idx, &count) in num_unpack_streams.iter().enumerate() {
            if count == 1 {
                crcs.push(info.folders[folder_idx].unpack_crc);
            } else {
                for _ in 0..count {
                    crcs.push(None);
                }
            }
        }
        crcs
    };

    info.sub_streams = SubStreamsInfo {
        num_unpack_streams,
        unpack_sizes,
        unpack_crcs,
    };
    Ok(cursor)
}

/// Parse an optional-CRC vector. The wire form is `kCRC` already
/// consumed by the caller; here we read the
/// `BitVector(n) Defined; UINT32 CRCs[popcount(Defined)]`
/// payload and return `Vec<Option<u32>>` of length `n`.
fn parse_optional_crc_vec(
    input: &[u8],
    n: usize,
) -> Result<(Vec<Option<u32>>, &[u8]), SevenzError> {
    let (all_defined, rest) = parse_propid(input)?;
    let (defined, mut cursor) = if all_defined != 0 {
        (vec![true; n], rest)
    } else {
        parse_bool_vector(rest, n)?
    };
    let mut out = Vec::with_capacity(n);
    for present in defined {
        if present {
            if cursor.len() < 4 {
                return Err(SevenzError::Truncated {
                    what: "CRC32 word".into(),
                    needed: 4 - cursor.len(),
                });
            }
            let crc = u32::from_le_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
            cursor = &cursor[4..];
            out.push(Some(crc));
        } else {
            out.push(None);
        }
    }
    Ok((out, cursor))
}

/// Parse a `FilesInfo` block (caller has consumed the
/// `kFilesInfo` propid).
fn parse_files_info(input: &[u8]) -> Result<(Vec<FileRecord>, &[u8]), SevenzError> {
    let (num_files, mut cursor) = parse_number(input)?;
    let num_files = usize::try_from(num_files).map_err(|_| SevenzError::CorruptHeader {
        reason: "NumFiles exceeds usize".into(),
    })?;

    // Initialize records with placeholders; Names / MTimes /
    // attrs / flags fold in over the property loop below.
    let mut records: Vec<FileRecord> = (0..num_files)
        .map(|_| FileRecord {
            name: PathBuf::new(),
            attrs: None,
            mtime: None,
            is_directory: false,
            has_stream: true,
            is_anti: false,
        })
        .collect();
    let mut have_name = false;
    let mut empty_stream: Option<Vec<bool>> = None;
    let mut empty_file: Option<Vec<bool>> = None;
    let mut anti: Option<Vec<bool>> = None;

    loop {
        let (tag, rest) = parse_propid(cursor)?;
        cursor = rest;
        if tag == nid::END {
            break;
        }
        let (size, rest) = parse_number(cursor)?;
        let size = usize::try_from(size).map_err(|_| SevenzError::CorruptHeader {
            reason: "FilesInfo property size exceeds usize".into(),
        })?;
        if rest.len() < size {
            return Err(SevenzError::Truncated {
                what: format!("FilesInfo property {tag:#04x} body"),
                needed: size - rest.len(),
            });
        }
        let (body, rest) = rest.split_at(size);
        cursor = rest;
        match tag {
            nid::EMPTY_STREAM => {
                let (vec, _) = parse_bool_vector(body, num_files)?;
                empty_stream = Some(vec);
            }
            nid::EMPTY_FILE => {
                let n_empty = empty_stream
                    .as_ref()
                    .map(|v| v.iter().filter(|&&b| b).count());
                let n_empty = n_empty.ok_or_else(|| SevenzError::CorruptHeader {
                    reason: "EmptyFile property without preceding EmptyStream".into(),
                })?;
                let (vec, _) = parse_bool_vector(body, n_empty)?;
                empty_file = Some(vec);
            }
            nid::ANTI => {
                let n_empty = empty_stream
                    .as_ref()
                    .map(|v| v.iter().filter(|&&b| b).count());
                let n_empty = n_empty.ok_or_else(|| SevenzError::CorruptHeader {
                    reason: "Anti property without preceding EmptyStream".into(),
                })?;
                let (vec, _) = parse_bool_vector(body, n_empty)?;
                anti = Some(vec);
            }
            nid::NAME => {
                parse_names_property(body, &mut records)?;
                have_name = true;
            }
            nid::MTIME => {
                parse_optional_i64_property(body, num_files, |rec, v| rec.mtime = v, &mut records)?;
            }
            nid::WIN_ATTRIBUTES => {
                parse_optional_u32_property(body, num_files, |rec, v| rec.attrs = v, &mut records)?;
            }
            nid::CTIME | nid::ATIME | nid::COMMENT | nid::DUMMY => {
                // Round-one accepts and skips: body already
                // sliced off via `size`.
            }
            nid::START_POS => {
                return Err(SevenzError::UnsupportedFeature {
                    feature: "kStartPos per-file property".into(),
                });
            }
            other => {
                // Unknown propids are skipped by Size; this matches
                // 7z's forward-compat stance.
                let _ = other;
            }
        }
    }

    if !have_name && num_files > 0 {
        return Err(SevenzError::CorruptHeader {
            reason: "FilesInfo missing Name property".into(),
        });
    }

    // Fold EmptyStream / EmptyFile / Anti into per-file flags.
    if let Some(es) = empty_stream {
        if es.len() != num_files {
            return Err(SevenzError::CorruptHeader {
                reason: format!("EmptyStream length {} != NumFiles {num_files}", es.len(),),
            });
        }
        let mut empty_idx = 0usize;
        for (i, is_empty) in es.iter().enumerate() {
            if *is_empty {
                records[i].has_stream = false;
                let is_dir = empty_file.as_ref().map(|ef| !ef[empty_idx]).unwrap_or(true);
                records[i].is_directory = is_dir;
                if let Some(a) = anti.as_ref() {
                    if a[empty_idx] {
                        return Err(SevenzError::UnsupportedFeature {
                            feature: format!("anti-file at index {i} ({:?})", records[i].name),
                        });
                    }
                }
                empty_idx += 1;
            }
        }
    }

    Ok((records, cursor))
}

/// Decode the body of a `kName` property (one
/// `external` byte followed by concatenated zero-terminated
/// UTF-16LE names).
fn parse_names_property(body: &[u8], records: &mut [FileRecord]) -> Result<(), SevenzError> {
    let (external, mut cursor) = parse_propid(body).map_err(|_| SevenzError::Truncated {
        what: "Names external flag".into(),
        needed: 1,
    })?;
    if external != 0 {
        return Err(SevenzError::UnsupportedFeature {
            feature: "external Names property body".into(),
        });
    }
    for rec in records.iter_mut() {
        let (path, rest) = read_name_utf16le_zero_terminated(cursor)?;
        cursor = rest;
        rec.name = path;
    }
    if !cursor.is_empty() {
        return Err(SevenzError::CorruptHeader {
            reason: format!(
                "Names property had {} trailing byte(s) past last name terminator",
                cursor.len(),
            ),
        });
    }
    Ok(())
}

/// Decode one of the `(AllAreDefined; external; values)`-shaped
/// per-file properties (`kMTime`, etc.) into `FileRecord` fields,
/// reading 8-byte little-endian values.
fn parse_optional_i64_property(
    body: &[u8],
    num_files: usize,
    mut set: impl FnMut(&mut FileRecord, Option<i64>),
    records: &mut [FileRecord],
) -> Result<(), SevenzError> {
    let (defined, cursor) = parse_optional_predicate_preamble(body, num_files)?;
    let (external, mut cursor) = parse_propid(cursor).map_err(|_| SevenzError::Truncated {
        what: "i64 property external flag".into(),
        needed: 1,
    })?;
    if external != 0 {
        return Err(SevenzError::UnsupportedFeature {
            feature: "external i64 property body".into(),
        });
    }
    for (i, &is_defined) in defined.iter().enumerate() {
        if is_defined {
            if cursor.len() < 8 {
                return Err(SevenzError::Truncated {
                    what: "i64 property value".into(),
                    needed: 8 - cursor.len(),
                });
            }
            let value = i64::from_le_bytes([
                cursor[0], cursor[1], cursor[2], cursor[3], cursor[4], cursor[5], cursor[6],
                cursor[7],
            ]);
            cursor = &cursor[8..];
            set(&mut records[i], Some(value));
        } else {
            set(&mut records[i], None);
        }
    }
    if !cursor.is_empty() {
        return Err(SevenzError::CorruptHeader {
            reason: format!("i64 property body had {} trailing byte(s)", cursor.len(),),
        });
    }
    Ok(())
}

/// Like [`parse_optional_i64_property`] but reads 4-byte LE u32
/// values. Used for `kWinAttributes`.
fn parse_optional_u32_property(
    body: &[u8],
    num_files: usize,
    mut set: impl FnMut(&mut FileRecord, Option<u32>),
    records: &mut [FileRecord],
) -> Result<(), SevenzError> {
    let (defined, cursor) = parse_optional_predicate_preamble(body, num_files)?;
    let (external, mut cursor) = parse_propid(cursor).map_err(|_| SevenzError::Truncated {
        what: "u32 property external flag".into(),
        needed: 1,
    })?;
    if external != 0 {
        return Err(SevenzError::UnsupportedFeature {
            feature: "external u32 property body".into(),
        });
    }
    for (i, &is_defined) in defined.iter().enumerate() {
        if is_defined {
            if cursor.len() < 4 {
                return Err(SevenzError::Truncated {
                    what: "u32 property value".into(),
                    needed: 4 - cursor.len(),
                });
            }
            let value = u32::from_le_bytes([cursor[0], cursor[1], cursor[2], cursor[3]]);
            cursor = &cursor[4..];
            set(&mut records[i], Some(value));
        } else {
            set(&mut records[i], None);
        }
    }
    if !cursor.is_empty() {
        return Err(SevenzError::CorruptHeader {
            reason: format!("u32 property body had {} trailing byte(s)", cursor.len(),),
        });
    }
    Ok(())
}

/// Parse the `(AllAreDefined; if 0: BoolVector(n))` preamble
/// shared by `kMTime` / `kWinAttributes` / etc.
fn parse_optional_predicate_preamble(
    input: &[u8],
    n: usize,
) -> Result<(Vec<bool>, &[u8]), SevenzError> {
    let (all_defined, rest) = parse_propid(input).map_err(|_| SevenzError::Truncated {
        what: "predicate preamble AllAreDefined byte".into(),
        needed: 1,
    })?;
    if all_defined != 0 {
        Ok((vec![true; n], rest))
    } else {
        parse_bool_vector(rest, n)
    }
}

/// Build the `folder_to_files` mapping per the spec: walk
/// `FilesInfo` in order, skipping `is_directory || !has_stream`
/// entries; assign each remaining file to the next folder slot
/// based on `SubStreamsInfo.num_unpack_streams`.
fn build_folder_to_files_mapping(
    main: Option<&StreamsInfo>,
    files: &[FileRecord],
    sub_streams: Option<&SubStreamsInfo>,
) -> Result<Vec<Vec<u32>>, SevenzError> {
    let Some(main) = main else {
        return Ok(Vec::new());
    };
    let counts = sub_streams
        .map(|s| s.num_unpack_streams.clone())
        .unwrap_or_else(|| vec![1u32; main.folders.len()]);
    if counts.len() != main.folders.len() {
        return Err(SevenzError::CorruptHeader {
            reason: format!(
                "SubStreamsInfo.num_unpack_streams.len() = {}, expected {}",
                counts.len(),
                main.folders.len(),
            ),
        });
    }

    // Stream-bearing files in order.
    let stream_bearing_indices: Vec<u32> = files
        .iter()
        .enumerate()
        .filter_map(|(i, rec)| {
            if rec.has_stream && !rec.is_directory {
                u32::try_from(i).ok()
            } else {
                None
            }
        })
        .collect();

    let total_substreams: u64 = counts.iter().map(|&n| n as u64).sum();
    if total_substreams != stream_bearing_indices.len() as u64 {
        return Err(SevenzError::CorruptHeader {
            reason: format!(
                "stream-bearing file count {} != SubStreamsInfo total {}",
                stream_bearing_indices.len(),
                total_substreams,
            ),
        });
    }

    let mut out = Vec::with_capacity(main.folders.len());
    let mut cursor = 0usize;
    for &count in &counts {
        let take = count as usize;
        let slice = &stream_bearing_indices[cursor..cursor + take];
        out.push(slice.to_vec());
        cursor += take;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::super::number::tests_support::encode_number_helper as encode_number;
    use super::*;

    /// Encode a single `kCRC` body: optional preamble (AllAreDefined =
    /// 0, then bit-vector of length n) plus N raw u32 LE CRC values
    /// for the defined ones. `defined.len()` must equal `n`.
    fn encode_optional_crc_body(defined: &[bool], crcs: &[u32]) -> Vec<u8> {
        let n = defined.len();
        let bytes_needed = n.div_ceil(8);
        let mut bv = vec![0u8; bytes_needed];
        for (i, &b) in defined.iter().enumerate() {
            if b {
                bv[i / 8] |= 0x80 >> (i % 8);
            }
        }
        let mut out = vec![0x00u8]; // AllAreDefined = 0
        out.extend(bv);
        let mut crc_iter = crcs.iter();
        for &is_def in defined {
            if is_def {
                let crc = crc_iter.next().expect("not enough CRCs");
                out.extend_from_slice(&crc.to_le_bytes());
            }
        }
        out
    }

    /// Build a single-folder StreamsInfo body (everything *after*
    /// the `kMainStreamsInfo` propid). The folder declares one
    /// COPY-coder, one packed stream, one unpack size.
    fn build_single_folder_streams_info(
        pack_pos: u64,
        pack_size: u64,
        unpack_size: u64,
        unpack_crc: Option<u32>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        // PackInfo
        out.push(nid::PACK_INFO);
        out.extend(encode_number(pack_pos));
        out.extend(encode_number(1)); // NumPackStreams
        out.push(nid::SIZE);
        out.extend(encode_number(pack_size));
        out.push(nid::END);

        // UnPackInfo
        out.push(nid::UNPACK_INFO);
        out.push(nid::FOLDER);
        out.extend(encode_number(1)); // NumFolders
        out.push(0x00); // External
                        // Folder: 1 coder, 1 in, 1 out, no bind pairs.
        out.extend(encode_number(1)); // NumCoders
                                      // Coder: flags = 0x01 (idSize=1, simple, no attribs)
        out.push(0x01);
        out.push(0x00); // codec id = COPY
                        // No NumInStreams/OutStreams (simple), no props.
                        // No bind pairs (NumBindPairs = NumOutStreams - 1 = 0)
                        // No PackedStreamIndices (NumPackedStreams = 1, the wire
                        // format omits the list).

        out.push(nid::CODERS_UNPACK_SIZE);
        out.extend(encode_number(unpack_size));
        if let Some(crc) = unpack_crc {
            out.push(nid::CRC);
            out.extend(encode_optional_crc_body(&[true], &[crc]));
        }
        out.push(nid::END);

        // SubStreamsInfo: omitted (defaults to 1 substream per folder).

        // StreamsInfo End
        out.push(nid::END);
        out
    }

    /// Build a complete plain-Header trailer: kHeader + the
    /// MainStreamsInfo + a FilesInfo declaring `names.len()`
    /// regular files and assigning them all to one folder.
    fn build_plain_header(
        pack_pos: u64,
        pack_size: u64,
        unpack_size: u64,
        names: &[&str],
    ) -> Vec<u8> {
        let mut out = vec![nid::HEADER];
        out.push(nid::MAIN_STREAMS_INFO);
        out.extend(build_single_folder_streams_info(
            pack_pos,
            pack_size,
            unpack_size,
            None,
        ));

        // FilesInfo
        out.push(nid::FILES_INFO);
        out.extend(encode_number(names.len() as u64));
        // kName property
        out.push(nid::NAME);
        let mut name_body = Vec::new();
        name_body.push(0x00); // external
        for n in names {
            for u in n.encode_utf16() {
                name_body.extend_from_slice(&u.to_le_bytes());
            }
            name_body.extend_from_slice(&[0x00, 0x00]);
        }
        out.extend(encode_number(name_body.len() as u64));
        out.extend(name_body);
        out.push(nid::END); // FilesInfo end

        out.push(nid::END); // Header end
        out
    }

    #[test]
    fn parse_trailer_plain_single_file_folder() {
        let trailer = build_plain_header(0x100, 50, 100, &["hello.txt"]);
        let parsed = parse_trailer(&trailer).expect("parses");
        let header = match parsed {
            Trailer::Plain(h) => h,
            other => panic!("expected Plain, got {other:?}"),
        };
        let main = header.main_streams.as_ref().expect("main streams present");
        assert_eq!(main.pack_pos, 0x100);
        assert_eq!(main.pack_sizes, vec![50]);
        assert_eq!(main.folders.len(), 1);
        let folder = &main.folders[0];
        assert_eq!(folder.coders.len(), 1);
        assert_eq!(folder.coders[0].id, vec![0x00]);
        assert_eq!(folder.unpack_sizes, vec![100]);
        assert!(folder.bind_pairs.is_empty());
        assert_eq!(header.files.len(), 1);
        assert_eq!(header.files[0].name, PathBuf::from("hello.txt"));
        assert!(header.files[0].has_stream);
        assert!(!header.files[0].is_directory);
        assert_eq!(header.folder_to_files, vec![vec![0]]);
    }

    #[test]
    fn parse_trailer_rejects_unknown_first_byte() {
        match parse_trailer(&[0x42]) {
            Err(SevenzError::CorruptHeader { reason }) => {
                assert!(reason.contains("kHeader"), "got {reason}");
            }
            other => panic!("expected CorruptHeader, got {other:?}"),
        }
    }

    #[test]
    fn parse_trailer_encoded_returns_streams_info_for_caller() {
        let mut trailer = vec![nid::ENCODED_HEADER];
        trailer.extend(build_single_folder_streams_info(0x10, 30, 40, Some(0xCAFE)));
        let parsed = parse_trailer(&trailer).expect("parses");
        let streams = match parsed {
            Trailer::Encoded { streams_info } => streams_info,
            other => panic!("expected Encoded, got {other:?}"),
        };
        assert_eq!(streams.pack_pos, 0x10);
        assert_eq!(streams.pack_sizes, vec![30]);
        assert_eq!(streams.folders[0].unpack_crc, Some(0xCAFE));
    }

    #[test]
    fn parse_decoded_header_rejects_nested_encoded() {
        let mut trailer = vec![nid::ENCODED_HEADER];
        trailer.extend(build_single_folder_streams_info(0x10, 30, 40, None));
        match parse_decoded_header(&trailer) {
            Err(SevenzError::UnsupportedFeature { feature }) => {
                assert!(feature.contains("nested"), "got {feature}");
            }
            other => panic!("expected UnsupportedFeature, got {other:?}"),
        }
    }

    #[test]
    fn parse_trailer_rejects_additional_streams_info() {
        let mut trailer = vec![nid::HEADER, nid::ADDITIONAL_STREAMS_INFO];
        trailer.push(nid::END); // body never gets read
        match parse_trailer(&trailer) {
            Err(SevenzError::UnsupportedFeature { feature }) => {
                assert!(feature.contains("Additional"), "got {feature}");
            }
            other => panic!("expected UnsupportedFeature, got {other:?}"),
        }
    }

    #[test]
    fn parse_trailer_rejects_anti_files() {
        // Build a trailer with one file, EmptyStream=true,
        // EmptyFile=false (so it's a directory candidate),
        // Anti=true.
        let mut out = vec![nid::HEADER];
        out.push(nid::MAIN_STREAMS_INFO);
        out.extend(build_single_folder_streams_info(0x10, 1, 1, None));

        out.push(nid::FILES_INFO);
        out.extend(encode_number(2));

        // EmptyStream property: 2-bit BoolVector with file 0 empty, file 1 not.
        out.push(nid::EMPTY_STREAM);
        let body = vec![0b1000_0000];
        out.extend(encode_number(body.len() as u64));
        out.extend(body);

        // EmptyFile: 1-bit BoolVector, file 0 is empty-file=false (=> is_directory).
        out.push(nid::EMPTY_FILE);
        let body = vec![0b0000_0000]; // bit 0 = false → is_directory
        out.extend(encode_number(body.len() as u64));
        out.extend(body);

        // Anti: 1-bit, file 0 anti=true.
        out.push(nid::ANTI);
        let body = vec![0b1000_0000]; // bit 0 = true → anti
        out.extend(encode_number(body.len() as u64));
        out.extend(body);

        // Names: 2 names.
        out.push(nid::NAME);
        let mut name_body = vec![0x00];
        for n in ["dir/", "real.txt"] {
            for u in n.encode_utf16() {
                name_body.extend_from_slice(&u.to_le_bytes());
            }
            name_body.extend_from_slice(&[0x00, 0x00]);
        }
        out.extend(encode_number(name_body.len() as u64));
        out.extend(name_body);

        out.push(nid::END);
        out.push(nid::END);

        match parse_trailer(&out) {
            Err(SevenzError::UnsupportedFeature { feature }) => {
                assert!(feature.contains("anti-file"), "got {feature}");
            }
            other => panic!("expected UnsupportedFeature, got {other:?}"),
        }
    }

    #[test]
    fn parse_trailer_handles_empty_directory_entries() {
        let mut out = vec![nid::HEADER];
        out.push(nid::MAIN_STREAMS_INFO);
        out.extend(build_single_folder_streams_info(0x10, 5, 5, None));

        out.push(nid::FILES_INFO);
        out.extend(encode_number(2));

        // EmptyStream: file 0 empty (dir), file 1 not.
        out.push(nid::EMPTY_STREAM);
        let body = vec![0b1000_0000];
        out.extend(encode_number(body.len() as u64));
        out.extend(body);

        // EmptyFile: 1-bit, value false → is_directory = true.
        out.push(nid::EMPTY_FILE);
        let body = vec![0b0000_0000];
        out.extend(encode_number(body.len() as u64));
        out.extend(body);

        // Names
        out.push(nid::NAME);
        let mut name_body = vec![0x00];
        for n in ["mydir", "leaf.txt"] {
            for u in n.encode_utf16() {
                name_body.extend_from_slice(&u.to_le_bytes());
            }
            name_body.extend_from_slice(&[0x00, 0x00]);
        }
        out.extend(encode_number(name_body.len() as u64));
        out.extend(name_body);

        out.push(nid::END);
        out.push(nid::END);

        let parsed = parse_trailer(&out).expect("parses");
        let header = match parsed {
            Trailer::Plain(h) => h,
            other => panic!("expected Plain, got {other:?}"),
        };
        assert!(header.files[0].is_directory);
        assert!(!header.files[0].has_stream);
        assert!(!header.files[1].is_directory);
        assert!(header.files[1].has_stream);
        // Only the stream-bearing file maps to the folder.
        assert_eq!(header.folder_to_files, vec![vec![1]]);
    }

    #[test]
    fn parse_trailer_carries_per_folder_unpack_crc() {
        let mut trailer = vec![nid::HEADER, nid::MAIN_STREAMS_INFO];
        trailer.extend(build_single_folder_streams_info(
            0x10,
            5,
            5,
            Some(0xDEADBEEF),
        ));
        trailer.push(nid::FILES_INFO);
        trailer.extend(encode_number(1));
        trailer.push(nid::NAME);
        let mut name_body = vec![0x00];
        for u in "f.txt".encode_utf16() {
            name_body.extend_from_slice(&u.to_le_bytes());
        }
        name_body.extend_from_slice(&[0x00, 0x00]);
        trailer.extend(encode_number(name_body.len() as u64));
        trailer.extend(name_body);
        trailer.push(nid::END);
        trailer.push(nid::END);

        let parsed = parse_trailer(&trailer).expect("parses");
        let header = match parsed {
            Trailer::Plain(h) => h,
            other => panic!("expected Plain, got {other:?}"),
        };
        let main = header.main_streams.unwrap();
        assert_eq!(main.folders[0].unpack_crc, Some(0xDEADBEEF));
        assert_eq!(main.sub_streams.unpack_crcs, vec![Some(0xDEADBEEF)]);
    }

    #[test]
    fn folder_primary_output_index_is_last_for_linear_chain() {
        let folder = Folder {
            coders: vec![
                Coder {
                    id: vec![0x21],
                    props: vec![],
                    num_in_streams: 1,
                    num_out_streams: 1,
                },
                Coder {
                    id: vec![0x21],
                    props: vec![],
                    num_in_streams: 1,
                    num_out_streams: 1,
                },
            ],
            bind_pairs: vec![BindPair {
                in_index: 1,
                out_index: 0,
            }],
            packed_stream_indices: vec![],
            unpack_sizes: vec![100, 200],
            unpack_crc: None,
        };
        assert_eq!(folder.primary_output_index().unwrap(), 1);
        assert_eq!(folder.primary_unpack_size().unwrap(), 200);
    }

    #[test]
    fn parse_folder_rejects_complex_coder() {
        // Build a folder with one coder marked as `IsComplex`
        // (flags bit 0x10).
        let mut buf = Vec::new();
        buf.extend(encode_number(1)); // NumCoders
        buf.push(0x11); // flags: idSize=1, IsComplex=1
        buf.push(0x00); // codec id
        buf.extend(encode_number(2)); // NumInStreams
        buf.extend(encode_number(2)); // NumOutStreams
        match parse_folder_definition(&buf) {
            Err(SevenzError::UnsupportedFeature { feature }) => {
                assert!(feature.contains("complex"), "got {feature}");
            }
            other => panic!("expected UnsupportedFeature, got {other:?}"),
        }
    }

    #[test]
    fn parse_folder_rejects_alternative_method() {
        let mut buf = Vec::new();
        buf.extend(encode_number(1));
        buf.push(0x81); // flags: idSize=1, IsAlternative=1
        buf.push(0x00);
        match parse_folder_definition(&buf) {
            Err(SevenzError::UnsupportedFeature { feature }) => {
                assert!(feature.contains("alternative"), "got {feature}");
            }
            other => panic!("expected UnsupportedFeature, got {other:?}"),
        }
    }
}
