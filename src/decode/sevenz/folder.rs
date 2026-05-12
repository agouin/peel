//! Single-folder streaming decoder.
//!
//! Implements §6 of `docs/PLAN_7z_support.md`. Given a parsed
//! [`super::header::Folder`] (linear coder chain) and the
//! folder's packed bytes, [`FolderDecoder::decode`] runs the
//! chain and feeds the decoded substream bytes into a
//! [`FolderSink`] in substream order, with substream CRCs
//! validated at each boundary and the folder-wide CRC validated
//! at end-of-folder.
//!
//! Round-one streaming policy:
//!
//! - **One coder**: `source → coder → splitter → sink` runs as
//!   a streaming pipeline. The coder writes into the splitter
//!   directly; per-call memory is bounded by the coder's own
//!   buffer (e.g. 64 KiB for LZMA2 chunks).
//! - **Two or more coders**: each intermediate stage produces
//!   a `Vec<u8>` of bounded size (`folder.unpack_sizes[i]`).
//!   The final stage streams to the splitter. Round-one
//!   exercises this path almost exclusively for
//!   `EncodedHeader` decoding (where the buffers are tiny);
//!   "real" 1-coder folders dominate everything else.

use std::io::{self, Cursor, Read, Write};

use thiserror::Error;

// Use the slicing-by-16 CRC32 from `zip::crc32`, not the
// byte-at-a-time `hash::crc32::Crc32`. The folder-wide CRC
// runs over every decoded byte; on a 256 MiB folder the
// difference between ~500 MB/s and ~5 GB/s is ~450 ms of
// wall-clock at 10 Gbps × 256 MiB.
use crate::encryption::EncryptionError;
use crate::secret::Password;
use crate::sevenz::SevenzError;
use crate::zip::crc32::Crc32;

use super::coders::{dispatch, CoderError, CoderId};
use super::header::{Folder, StreamsInfo};

/// Sink that consumes the decoded output of a [`FolderDecoder`],
/// split into substreams.
///
/// The decoder calls these methods in the order:
/// `begin_substream(0, …)` →
/// (`write(…)` …) →
/// `end_substream(…)` →
/// `begin_substream(1, …)` →
/// (`write(…)` …) →
/// `end_substream(…)` →
/// … (one per substream).
///
/// `end_substream` carries the per-substream CRC32 the archive
/// recorded (or `None` if absent); the §7 sink validates and
/// surfaces a typed error on mismatch.
pub trait FolderSink {
    /// Begin substream `idx` (0-based within the folder).
    /// `expected_size` is the substream's uncompressed byte
    /// count.
    ///
    /// `file_index` is the parent archive's
    /// [`super::header::Header::files`] index this substream's
    /// bytes are owed to (equivalent to
    /// `header.folder_to_files[folder_idx][idx]`).
    ///
    /// # Errors
    ///
    /// Implementation-defined; the §7 sink surfaces filesystem
    /// failures and path-escape errors here.
    fn begin_substream(
        &mut self,
        idx: u32,
        file_index: u32,
        expected_size: u64,
    ) -> Result<(), FolderSinkError>;

    /// Append decoded bytes to the currently-open substream.
    ///
    /// # Errors
    ///
    /// Implementation-defined.
    fn write_substream(&mut self, buf: &[u8]) -> Result<(), FolderSinkError>;

    /// Close the currently-open substream.
    ///
    /// `expected_crc` is the CRC32 the archive recorded for
    /// this substream (or `None` if absent). The sink is the
    /// authoritative validator: it owns the running hasher and
    /// surfaces a typed mismatch error.
    ///
    /// # Errors
    ///
    /// Implementation-defined.
    fn end_substream(&mut self, expected_crc: Option<u32>) -> Result<(), FolderSinkError>;
}

/// Errors a [`FolderSink`] can surface.
///
/// Wraps [`std::io::Error`] for IO failures and carries a
/// typed CRC-mismatch variant the §7 sink converts to its
/// own error shape.
#[derive(Debug, Error)]
pub enum FolderSinkError {
    /// Underlying IO failure (filesystem, path escape, …).
    #[error("folder sink IO failure")]
    Io(#[from] io::Error),

    /// Per-substream CRC32 mismatch. Surfaced by the sink's
    /// `end_substream` impl; the decoder does not pre-compute
    /// this — the sink owns the running hasher because it
    /// also owns the final on-disk truth.
    #[error("substream CRC32 mismatch: expected {expected:#010x}, computed {computed:#010x}")]
    Crc32Mismatch {
        /// CRC32 the archive recorded.
        expected: u32,
        /// CRC32 the sink computed over the bytes it received.
        computed: u32,
    },
}

/// Streaming decoder for one [`Folder`].
///
/// Borrows the packed-bytes source via `&mut dyn Read`. The
/// borrowed shape lets the §8 pipeline stream straight from the
/// sparse file (no intermediate `Vec<u8>` of the whole packed
/// range) — which is the difference between ~250 ms and ~10 ms
/// of overhead on a 256 MiB single-folder COPY archive.
pub struct FolderDecoder<'a> {
    folder: &'a Folder,
    streams_info: &'a StreamsInfo,
    folder_idx: u32,
    file_indices_for_folder: &'a [u32],
    packed_bytes: &'a mut dyn Read,
    password: Option<&'a Password>,
}

impl<'a> FolderDecoder<'a> {
    /// Build a decoder for `folder` (index `folder_idx` inside
    /// `streams_info.folders`) reading from `packed_bytes`.
    ///
    /// `file_indices_for_folder` is
    /// `header.folder_to_files[folder_idx]` — the parent
    /// archive's file indices that consume substreams from
    /// this folder, in substream order. The §8 pipeline
    /// computes this; tests can pass an empty slice if the
    /// caller doesn't care about file-index forwarding.
    pub fn new(
        folder: &'a Folder,
        streams_info: &'a StreamsInfo,
        folder_idx: u32,
        file_indices_for_folder: &'a [u32],
        packed_bytes: &'a mut dyn Read,
    ) -> Self {
        Self::with_password(
            folder,
            streams_info,
            folder_idx,
            file_indices_for_folder,
            packed_bytes,
            None,
        )
    }

    /// Same as [`Self::new`] but threads a password through to
    /// the AES coder dispatch. `None` is acceptable for archives
    /// without encrypted folders; an encrypted folder seen with
    /// `password == None` surfaces
    /// [`EncryptionError::PasswordMissing`] before any decode
    /// work begins.
    pub fn with_password(
        folder: &'a Folder,
        streams_info: &'a StreamsInfo,
        folder_idx: u32,
        file_indices_for_folder: &'a [u32],
        packed_bytes: &'a mut dyn Read,
        password: Option<&'a Password>,
    ) -> Self {
        Self {
            folder,
            streams_info,
            folder_idx,
            file_indices_for_folder,
            packed_bytes,
            password,
        }
    }

    /// `true` iff the folder's coder chain contains the
    /// AES-256-CBC encryption coder. Used by the §8 pipeline to
    /// decide whether to load a password before invoking decode,
    /// and by the splitter to translate post-decrypt CRC32
    /// mismatches into [`EncryptionError::PasswordIncorrect`].
    #[must_use]
    pub fn folder_is_encrypted(folder: &Folder) -> bool {
        folder
            .coders
            .iter()
            .any(|c| matches!(CoderId::from_bytes(&c.id), CoderId::Aes256Cbc))
    }

    /// Drive the coder chain to completion, splitting the final
    /// decoded byte stream into substreams via `sink`.
    ///
    /// # Errors
    ///
    /// - [`SevenzError::CorruptHeader`] for any structural
    ///   inconsistency the §3 parser missed (e.g. mismatched
    ///   substream metadata).
    /// - [`SevenzError::UnsupportedFeature`] surfaced by
    ///   [`super::coders::dispatch`].
    /// - Any `io::Error` from the source surfaces as
    ///   [`SevenzError::CorruptHeader`] with a "coder IO"
    ///   message — the §6 abstraction is "bytes flow" so the
    ///   distinction between "source ran dry" and "wire is
    ///   malformed" is collapsed at this boundary; the §8
    ///   pipeline wraps this in a richer `pipeline::Error`
    ///   that distinguishes them.
    pub fn decode(self, sink: &mut dyn FolderSink) -> Result<(), SevenzError> {
        let folder_idx_us = self.folder_idx as usize;
        let counts = &self.streams_info.sub_streams.num_unpack_streams;
        if counts.len() != self.streams_info.folders.len() {
            return Err(SevenzError::CorruptHeader {
                reason: format!(
                    "SubStreamsInfo.num_unpack_streams.len() = {}, \
                     expected {}",
                    counts.len(),
                    self.streams_info.folders.len(),
                ),
            });
        }
        let count = counts[folder_idx_us] as usize;
        if count == 0 {
            // Folders with zero substreams are well-formed in
            // principle but have no useful work to do — the
            // §7 sink doesn't open any files.
            return Ok(());
        }
        let start: usize = counts.iter().take(folder_idx_us).map(|&n| n as usize).sum();
        let end = start + count;
        let substream_sizes = &self.streams_info.sub_streams.unpack_sizes[start..end];
        let substream_crcs = &self.streams_info.sub_streams.unpack_crcs[start..end];

        // File-index forwarding: the §8 pipeline supplies one
        // entry per substream in this folder. Tests that pass
        // an empty slice get sentinel `u32::MAX` indices.
        let mut file_indices: Vec<u32> = self.file_indices_for_folder.to_vec();
        if file_indices.is_empty() {
            file_indices = vec![u32::MAX; count];
        }
        if file_indices.len() != count {
            return Err(SevenzError::CorruptHeader {
                reason: format!(
                    "file_indices_for_folder.len() = {} but folder \
                     has {count} substreams",
                    file_indices.len(),
                ),
            });
        }

        let primary_size = self.folder.primary_unpack_size()?;
        let total_substream_size: u64 = substream_sizes.iter().sum();
        if total_substream_size != primary_size {
            return Err(SevenzError::CorruptHeader {
                reason: format!(
                    "folder {folder_idx_us} substream sizes sum {total_substream_size} \
                     != primary unpack size {primary_size}",
                ),
            });
        }

        let is_encrypted = Self::folder_is_encrypted(self.folder);
        let mut splitter = SubstreamSplitter::new(
            sink,
            substream_sizes,
            substream_crcs,
            &file_indices,
            self.folder.unpack_crc,
            is_encrypted,
        );
        splitter.begin_first()?;

        let coder_count = self.folder.coders.len();
        if coder_count == 0 {
            return Err(SevenzError::CorruptHeader {
                reason: "folder has zero coders".into(),
            });
        }

        // Run the chain. The first coder reads from
        // `self.packed_bytes` (a borrowed `&mut dyn Read`,
        // typically over the sparse file). Intermediate stages
        // produce a `Vec<u8>` and the next coder reads from a
        // `Cursor` over it. The last coder streams directly
        // into the splitter — both paths unify when
        // `coder_count == 1`, which skips the buffered loop
        // entirely.
        let mut intermediate: Option<Cursor<Vec<u8>>> = None;
        if coder_count > 1 {
            for (i, coder) in self.folder.coders[..coder_count - 1].iter().enumerate() {
                let coder_size = self.folder.unpack_sizes.get(i).copied().ok_or_else(|| {
                    SevenzError::CorruptHeader {
                        reason: format!("folder unpack_sizes missing entry for coder {i}"),
                    }
                })?;
                let mut coder_impl = dispatch(coder, self.password).map_err(coder_err_to_sevenz)?;
                let mut buf: Vec<u8> = Vec::with_capacity(coder_size as usize);
                let res = match intermediate.as_mut() {
                    None => coder_impl.decode_one_block(self.packed_bytes, &mut buf, coder_size),
                    Some(cur) => coder_impl.decode_one_block(cur, &mut buf, coder_size),
                };
                res.map_err(coder_err_to_sevenz)?;
                intermediate = Some(Cursor::new(buf));
            }
        }
        let last_idx = coder_count - 1;
        let last_coder = &self.folder.coders[last_idx];
        let last_size = if coder_count == 1 {
            primary_size
        } else {
            self.folder
                .unpack_sizes
                .get(last_idx)
                .copied()
                .ok_or_else(|| SevenzError::CorruptHeader {
                    reason: format!("folder unpack_sizes missing entry for last coder {last_idx}",),
                })?
        };
        let mut last_impl = dispatch(last_coder, self.password).map_err(coder_err_to_sevenz)?;
        let res = match intermediate.as_mut() {
            None => last_impl.decode_one_block(self.packed_bytes, &mut splitter, last_size),
            Some(cur) => last_impl.decode_one_block(cur, &mut splitter, last_size),
        };
        res.map_err(coder_err_to_sevenz)?;

        splitter.finish_last_substream()?;
        splitter.validate_folder_crc()?;
        Ok(())
    }
}

/// Translate a [`CoderError`] into a [`SevenzError`].
fn coder_err_to_sevenz(e: CoderError) -> SevenzError {
    match e {
        CoderError::UnsupportedFeature { feature } => SevenzError::UnsupportedFeature { feature },
        CoderError::BadProps { coder, reason } => SevenzError::CorruptHeader {
            reason: format!("{coder} coder props rejected: {reason}"),
        },
        CoderError::UnpackSizeMismatch {
            coder,
            expected,
            got,
        } => SevenzError::CorruptHeader {
            reason: format!("{coder} coder unpack size mismatch: expected {expected}, got {got}",),
        },
        CoderError::Decode { coder, source } => SevenzError::CorruptHeader {
            reason: format!("{coder} coder decode failure: {source}"),
        },
        CoderError::Io(source) => {
            // The splitter's `Write` impl funnels post-decrypt CRC
            // mismatches through this path tagged with
            // `ENCRYPTED_CRC_MISMATCH_SENTINEL`. Catch the sentinel
            // here and rewrite back into the unified
            // [`EncryptionError::PasswordIncorrect`] surface.
            if source.to_string().contains(ENCRYPTED_CRC_MISMATCH_SENTINEL) {
                SevenzError::Encryption(EncryptionError::PasswordIncorrect)
            } else {
                SevenzError::CorruptHeader {
                    reason: format!("coder IO failure: {source}"),
                }
            }
        }
        // Encryption coder surfaces directly through the unified
        // SevenzError::Encryption variant
        // (`docs/PLAN_archive_encryption.md` §5 / §6) — the shared
        // EncryptionError type makes ZIP / RAR / 7z encryption
        // refusals match on the same shape.
        CoderError::Encryption(inner) => SevenzError::Encryption(inner),
    }
}

/// `Write` adapter that splits incoming bytes into substreams,
/// running per-substream and folder-wide CRC32s as it goes.
struct SubstreamSplitter<'a> {
    sink: &'a mut dyn FolderSink,
    substream_sizes: &'a [u64],
    substream_crcs: &'a [Option<u32>],
    file_indices: &'a [u32],
    folder_unpack_crc: Option<u32>,
    /// When `true`, post-decrypt CRC mismatches surface as
    /// [`EncryptionError::PasswordIncorrect`] (the user is much
    /// more likely to have typed the wrong password than to be
    /// looking at a corrupted archive that *also* happens to be
    /// encrypted). 7z has no integrity tag on its encryption
    /// layer, so the substream CRC32 is the only signal we have.
    encrypted: bool,

    current_substream: usize,
    bytes_in_current_substream: u64,
    folder_crc: Crc32,
    started: bool,
    finished: bool,
}

impl<'a> SubstreamSplitter<'a> {
    fn new(
        sink: &'a mut dyn FolderSink,
        substream_sizes: &'a [u64],
        substream_crcs: &'a [Option<u32>],
        file_indices: &'a [u32],
        folder_unpack_crc: Option<u32>,
        encrypted: bool,
    ) -> Self {
        Self {
            sink,
            substream_sizes,
            substream_crcs,
            file_indices,
            folder_unpack_crc,
            encrypted,
            current_substream: 0,
            bytes_in_current_substream: 0,
            folder_crc: Crc32::new(),
            started: false,
            finished: false,
        }
    }

    /// Open the first substream. Called by [`FolderDecoder::decode`]
    /// before any coder runs.
    fn begin_first(&mut self) -> Result<(), SevenzError> {
        debug_assert!(!self.started, "begin_first called twice");
        self.started = true;
        self.sink
            .begin_substream(0, self.file_indices[0], self.substream_sizes[0])
            .map_err(folder_sink_err_to_sevenz)
    }

    /// Close the final substream. Called once the coder chain
    /// has reported all bytes.
    fn finish_last_substream(&mut self) -> Result<(), SevenzError> {
        if self.finished {
            return Ok(());
        }
        if self.current_substream >= self.substream_sizes.len() {
            self.finished = true;
            return Ok(());
        }
        let expected = self.substream_sizes[self.current_substream];
        if self.bytes_in_current_substream != expected {
            return Err(SevenzError::CorruptHeader {
                reason: format!(
                    "substream {} ended at {} bytes, expected {expected}",
                    self.current_substream, self.bytes_in_current_substream,
                ),
            });
        }
        let crc = self.substream_crcs[self.current_substream];
        self.sink
            .end_substream(crc)
            .map_err(folder_sink_err_to_sevenz)?;
        self.current_substream += 1;
        self.finished = true;
        Ok(())
    }

    /// Validate the folder-wide CRC after all bytes have been
    /// written.
    fn validate_folder_crc(&self) -> Result<(), SevenzError> {
        if let Some(expected) = self.folder_unpack_crc {
            let computed = self.folder_crc.current();
            if computed != expected {
                if self.encrypted {
                    return Err(SevenzError::Encryption(EncryptionError::PasswordIncorrect));
                }
                return Err(SevenzError::CorruptHeader {
                    reason: format!(
                        "folder CRC32 mismatch: expected {expected:#010x}, \
                         computed {computed:#010x}",
                    ),
                });
            }
        }
        Ok(())
    }
}

impl Write for SubstreamSplitter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.started {
            return Err(io::Error::other(
                "SubstreamSplitter received bytes before begin_first",
            ));
        }
        let mut consumed = 0usize;
        while consumed < buf.len() {
            if self.current_substream >= self.substream_sizes.len() {
                return Err(io::Error::other(format!(
                    "FolderDecoder produced {} extra bytes past last substream",
                    buf.len() - consumed,
                )));
            }
            let target_size = self.substream_sizes[self.current_substream];
            let remaining = target_size - self.bytes_in_current_substream;
            let take = ((buf.len() - consumed) as u64).min(remaining) as usize;
            let slice = &buf[consumed..consumed + take];
            self.sink
                .write_substream(slice)
                .map_err(|e| substream_sink_err_to_io(e, self.encrypted))?;
            self.folder_crc.update(slice);
            self.bytes_in_current_substream += take as u64;
            consumed += take;
            if self.bytes_in_current_substream == target_size {
                let crc = self.substream_crcs[self.current_substream];
                self.sink
                    .end_substream(crc)
                    .map_err(|e| substream_sink_err_to_io(e, self.encrypted))?;
                self.current_substream += 1;
                self.bytes_in_current_substream = 0;
                if self.current_substream < self.substream_sizes.len() {
                    self.sink
                        .begin_substream(
                            self.current_substream as u32,
                            self.file_indices[self.current_substream],
                            self.substream_sizes[self.current_substream],
                        )
                        .map_err(|e| substream_sink_err_to_io(e, self.encrypted))?;
                }
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Sentinel string the splitter inserts into [`io::Error`] when a
/// substream CRC mismatch happens inside an encrypted folder. The
/// `coder_err_to_sevenz` translator at the [`FolderDecoder::decode`]
/// boundary catches this sentinel and rewrites the error into
/// [`SevenzError::Encryption(EncryptionError::PasswordIncorrect)`].
///
/// Carried through `io::Error` rather than a typed channel because
/// the splitter is plugged into a `Write` chain (whose only error
/// type *is* `io::Error`); we don't have a typed back-channel and
/// don't want to widen the `CoderImpl` trait for a single edge case.
const ENCRYPTED_CRC_MISMATCH_SENTINEL: &str = "peel:7z:encrypted-folder-crc-mismatch";

/// Translate a [`FolderSinkError`] into an [`io::Error`] suitable for
/// returning from the splitter's `Write` impl. CRC mismatches in
/// encrypted folders carry the sentinel so the decode-level
/// translator can rewrite them into [`EncryptionError::PasswordIncorrect`].
fn substream_sink_err_to_io(e: FolderSinkError, encrypted: bool) -> io::Error {
    match e {
        FolderSinkError::Crc32Mismatch { .. } if encrypted => {
            io::Error::other(ENCRYPTED_CRC_MISMATCH_SENTINEL)
        }
        other => io::Error::other(other),
    }
}

/// Translate a [`FolderSinkError`] into a [`SevenzError`].
fn folder_sink_err_to_sevenz(e: FolderSinkError) -> SevenzError {
    match e {
        FolderSinkError::Io(source) => SevenzError::CorruptHeader {
            reason: format!("folder sink IO: {source}"),
        },
        FolderSinkError::Crc32Mismatch { expected, computed } => SevenzError::CorruptHeader {
            reason: format!(
                "substream CRC32 mismatch: expected {expected:#010x}, \
                 computed {computed:#010x}",
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::decode::sevenz::header::{BindPair, Coder, Folder, StreamsInfo, SubStreamsInfo};

    /// In-memory `FolderSink` that captures each substream's
    /// bytes into a `Vec<u8>` and validates the recorded CRC
    /// (when provided) using `crate::hash::crc32`.
    struct VecSink {
        substreams: Vec<Vec<u8>>,
        current: Option<Vec<u8>>,
        running_crc: Crc32,
    }

    impl VecSink {
        fn new() -> Self {
            Self {
                substreams: Vec::new(),
                current: None,
                running_crc: Crc32::new(),
            }
        }
    }

    impl FolderSink for VecSink {
        fn begin_substream(
            &mut self,
            idx: u32,
            _file_index: u32,
            _expected_size: u64,
        ) -> Result<(), FolderSinkError> {
            assert_eq!(idx as usize, self.substreams.len());
            self.current = Some(Vec::new());
            self.running_crc = Crc32::new();
            Ok(())
        }

        fn write_substream(&mut self, buf: &[u8]) -> Result<(), FolderSinkError> {
            self.running_crc.update(buf);
            self.current.as_mut().unwrap().extend_from_slice(buf);
            Ok(())
        }

        fn end_substream(&mut self, expected_crc: Option<u32>) -> Result<(), FolderSinkError> {
            let bytes = self.current.take().unwrap();
            let computed = self.running_crc.current();
            if let Some(expected) = expected_crc {
                if expected != computed {
                    return Err(FolderSinkError::Crc32Mismatch { expected, computed });
                }
            }
            self.substreams.push(bytes);
            Ok(())
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

    #[test]
    fn folder_decoder_round_trips_single_copy_substream() {
        let payload: Vec<u8> = (0..1024u32).map(|i| i as u8).collect();
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

        let mut sink = VecSink::new();
        let mut src = Cursor::new(payload.clone());
        FolderDecoder::new(&info.folders[0], &info, 0, &[42u32], &mut src)
            .decode(&mut sink)
            .expect("decodes");
        assert_eq!(sink.substreams.len(), 1);
        assert_eq!(sink.substreams[0], payload);
    }

    #[test]
    fn folder_decoder_splits_two_substreams_at_size_boundary() {
        let payload: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
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
                num_unpack_streams: vec![2],
                unpack_sizes: vec![400, 600],
                unpack_crcs: vec![None, None],
            },
        };

        let mut sink = VecSink::new();
        let mut src = Cursor::new(payload.clone());
        FolderDecoder::new(&info.folders[0], &info, 0, &[10u32, 20u32], &mut src)
            .decode(&mut sink)
            .expect("decodes");
        assert_eq!(sink.substreams.len(), 2);
        assert_eq!(sink.substreams[0], payload[..400]);
        assert_eq!(sink.substreams[1], payload[400..]);
    }

    #[test]
    fn folder_decoder_validates_folder_unpack_crc() {
        let payload: Vec<u8> = b"the quick brown fox".to_vec();
        let crc = crate::hash::crc32::ieee(&payload);
        let folder = Folder {
            coders: vec![copy_coder()],
            bind_pairs: vec![],
            packed_stream_indices: vec![],
            unpack_sizes: vec![payload.len() as u64],
            unpack_crc: Some(crc),
        };
        let info = StreamsInfo {
            pack_pos: 0,
            pack_sizes: vec![payload.len() as u64],
            pack_crcs: vec![None],
            folders: vec![folder.clone()],
            sub_streams: SubStreamsInfo {
                num_unpack_streams: vec![1],
                unpack_sizes: vec![payload.len() as u64],
                unpack_crcs: vec![Some(crc)],
            },
        };

        let mut sink = VecSink::new();
        let mut src = Cursor::new(payload.clone());
        FolderDecoder::new(&info.folders[0], &info, 0, &[1u32], &mut src)
            .decode(&mut sink)
            .expect("decodes");
        assert_eq!(sink.substreams[0], payload);
    }

    #[test]
    fn folder_decoder_rejects_bad_folder_unpack_crc() {
        let payload: Vec<u8> = b"the quick brown fox".to_vec();
        let folder = Folder {
            coders: vec![copy_coder()],
            bind_pairs: vec![],
            packed_stream_indices: vec![],
            unpack_sizes: vec![payload.len() as u64],
            unpack_crc: Some(0xDEADBEEF), // wrong on purpose
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

        let mut sink = VecSink::new();
        let mut src = Cursor::new(payload);
        match FolderDecoder::new(&info.folders[0], &info, 0, &[1u32], &mut src).decode(&mut sink) {
            Err(SevenzError::CorruptHeader { reason }) => {
                assert!(reason.contains("folder CRC32"), "got {reason}");
            }
            Ok(_) => panic!("expected CorruptHeader, got Ok"),
            Err(other) => panic!("expected CorruptHeader, got {other:?}"),
        }
    }

    #[test]
    fn folder_decoder_rejects_substream_crc_mismatch_via_sink() {
        let payload: Vec<u8> = b"data".to_vec();
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
                unpack_crcs: vec![Some(0xDEADBEEF)],
            },
        };

        let mut sink = VecSink::new();
        let mut src = Cursor::new(payload);
        match FolderDecoder::new(&info.folders[0], &info, 0, &[1u32], &mut src).decode(&mut sink) {
            Err(SevenzError::CorruptHeader { reason }) => {
                assert!(reason.contains("CRC32"), "got {reason}");
            }
            Ok(_) => panic!("expected CorruptHeader, got Ok"),
            Err(other) => panic!("expected CorruptHeader, got {other:?}"),
        }
    }

    #[test]
    fn folder_decoder_buffered_two_coder_chain_runs_through() {
        // Build a 2-coder chain: COPY → COPY (linear).
        // Logically a no-op but exercises the buffered path.
        let payload: Vec<u8> = b"chain".to_vec();
        let folder = Folder {
            coders: vec![copy_coder(), copy_coder()],
            bind_pairs: vec![BindPair {
                in_index: 1,
                out_index: 0,
            }],
            packed_stream_indices: vec![],
            unpack_sizes: vec![payload.len() as u64, payload.len() as u64],
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

        let mut sink = VecSink::new();
        let mut src = Cursor::new(payload.clone());
        FolderDecoder::new(&info.folders[0], &info, 0, &[7u32], &mut src)
            .decode(&mut sink)
            .expect("decodes");
        assert_eq!(sink.substreams[0], payload);
    }

    /// Build an AES-256-CBC props blob: byte0 = 0xC0|power,
    /// byte1 = 0xFF (salt nibble 15+carry 1 = 16, iv nibble 15+
    /// carry 1 = 16), then 16 salt bytes, then 16 IV bytes.
    fn aes_props(power: u8, salt: &[u8; 16], iv: &[u8; 16]) -> Vec<u8> {
        let mut p = Vec::with_capacity(2 + 16 + 16);
        p.push(0xC0 | (power & 0x3F));
        p.push(0xFF);
        p.extend_from_slice(salt);
        p.extend_from_slice(iv);
        p
    }

    fn encrypt_aes256_cbc(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
        use crate::crypto::aes::{Aes256, AesBlockCipher};
        let cipher = Aes256::new(key);
        let mut padded = plaintext.to_vec();
        let pad = (16 - (padded.len() % 16)) % 16;
        padded.extend(std::iter::repeat_n(0u8, pad));
        let mut prev = *iv;
        let mut out = padded.clone();
        for chunk in out.chunks_exact_mut(16) {
            for (b, p) in chunk.iter_mut().zip(prev.iter()) {
                *b ^= *p;
            }
            let block: &mut [u8; 16] = chunk.try_into().unwrap();
            cipher.encrypt_block(block);
            prev.copy_from_slice(block);
        }
        out
    }

    #[test]
    fn folder_decoder_round_trips_single_aes_substream() {
        use crate::crypto::sevenz_kdf::{password_to_utf16le, sevenz_derive_key};
        use crate::secret::Password;

        // 96 bytes (6 blocks) — plenty to exercise multi-block CBC.
        let payload: Vec<u8> = (0..96u32).map(|i| (i * 5) as u8).collect();
        let salt = [0x11u8; 16];
        let iv = [0x22u8; 16];
        let power: u8 = 6;
        let pw_bytes = b"hunter2".to_vec();
        let key = sevenz_derive_key(
            &password_to_utf16le(std::str::from_utf8(&pw_bytes).unwrap()),
            &salt,
            power,
        );
        let mut key32 = [0u8; 32];
        key32.copy_from_slice(&key);
        let ciphertext = encrypt_aes256_cbc(&key32, &iv, &payload);

        let aes_coder = Coder {
            id: vec![0x06, 0xF1, 0x07, 0x01],
            props: aes_props(power, &salt, &iv),
            num_in_streams: 1,
            num_out_streams: 1,
        };
        let folder = Folder {
            coders: vec![aes_coder],
            bind_pairs: vec![],
            packed_stream_indices: vec![],
            unpack_sizes: vec![payload.len() as u64],
            unpack_crc: Some(crate::hash::crc32::ieee(&payload)),
        };
        let info = StreamsInfo {
            pack_pos: 0,
            pack_sizes: vec![ciphertext.len() as u64],
            pack_crcs: vec![None],
            folders: vec![folder.clone()],
            sub_streams: SubStreamsInfo {
                num_unpack_streams: vec![1],
                unpack_sizes: vec![payload.len() as u64],
                unpack_crcs: vec![Some(crate::hash::crc32::ieee(&payload))],
            },
        };

        let pw = Password::new(pw_bytes);
        let mut sink = VecSink::new();
        let mut src = Cursor::new(ciphertext);
        FolderDecoder::with_password(&info.folders[0], &info, 0, &[1u32], &mut src, Some(&pw))
            .decode(&mut sink)
            .expect("decrypts and decodes");
        assert_eq!(sink.substreams.len(), 1);
        assert_eq!(sink.substreams[0], payload);
    }

    #[test]
    fn folder_decoder_wrong_password_surfaces_password_incorrect() {
        // Same setup as the round-trip test but feed a wrong
        // password. Wrong password → garbage plaintext → CRC
        // mismatch → translated to PasswordIncorrect because
        // the folder is encrypted.
        use crate::crypto::sevenz_kdf::{password_to_utf16le, sevenz_derive_key};
        use crate::secret::Password;

        let payload: Vec<u8> = (0..64u32).map(|i| i as u8).collect();
        let salt = [0xAAu8; 16];
        let iv = [0xBBu8; 16];
        let power: u8 = 4;
        let real_pw = b"correct horse";
        let key = sevenz_derive_key(
            &password_to_utf16le(std::str::from_utf8(real_pw).unwrap()),
            &salt,
            power,
        );
        let mut key32 = [0u8; 32];
        key32.copy_from_slice(&key);
        let ciphertext = encrypt_aes256_cbc(&key32, &iv, &payload);
        let crc = crate::hash::crc32::ieee(&payload);

        let aes_coder = Coder {
            id: vec![0x06, 0xF1, 0x07, 0x01],
            props: aes_props(power, &salt, &iv),
            num_in_streams: 1,
            num_out_streams: 1,
        };
        let folder = Folder {
            coders: vec![aes_coder],
            bind_pairs: vec![],
            packed_stream_indices: vec![],
            unpack_sizes: vec![payload.len() as u64],
            unpack_crc: Some(crc),
        };
        let info = StreamsInfo {
            pack_pos: 0,
            pack_sizes: vec![ciphertext.len() as u64],
            pack_crcs: vec![None],
            folders: vec![folder.clone()],
            sub_streams: SubStreamsInfo {
                num_unpack_streams: vec![1],
                unpack_sizes: vec![payload.len() as u64],
                unpack_crcs: vec![Some(crc)],
            },
        };

        let wrong = Password::new(b"wrong password".to_vec());
        let mut sink = VecSink::new();
        let mut src = Cursor::new(ciphertext);
        match FolderDecoder::with_password(
            &info.folders[0],
            &info,
            0,
            &[1u32],
            &mut src,
            Some(&wrong),
        )
        .decode(&mut sink)
        {
            Err(SevenzError::Encryption(EncryptionError::PasswordIncorrect)) => {}
            Ok(_) => panic!("expected PasswordIncorrect, got Ok"),
            Err(other) => panic!("expected PasswordIncorrect, got {other:?}"),
        }
    }

    #[test]
    fn folder_decoder_missing_password_surfaces_password_missing() {
        // An encrypted folder without a password threaded in
        // must surface PasswordMissing at dispatch time, before
        // any bytes flow.
        let salt = [0x00u8; 16];
        let iv = [0x00u8; 16];
        let aes_coder = Coder {
            id: vec![0x06, 0xF1, 0x07, 0x01],
            props: aes_props(0, &salt, &iv),
            num_in_streams: 1,
            num_out_streams: 1,
        };
        let folder = Folder {
            coders: vec![aes_coder],
            bind_pairs: vec![],
            packed_stream_indices: vec![],
            unpack_sizes: vec![16],
            unpack_crc: None,
        };
        let info = StreamsInfo {
            pack_pos: 0,
            pack_sizes: vec![16],
            pack_crcs: vec![None],
            folders: vec![folder.clone()],
            sub_streams: SubStreamsInfo {
                num_unpack_streams: vec![1],
                unpack_sizes: vec![16],
                unpack_crcs: vec![None],
            },
        };

        let mut sink = VecSink::new();
        let mut src = Cursor::new(vec![0u8; 16]);
        match FolderDecoder::new(&info.folders[0], &info, 0, &[1u32], &mut src).decode(&mut sink) {
            Err(SevenzError::Encryption(EncryptionError::PasswordMissing)) => {}
            Ok(_) => panic!("expected PasswordMissing, got Ok"),
            Err(other) => panic!("expected PasswordMissing, got {other:?}"),
        }
    }

    #[test]
    fn folder_is_encrypted_reflects_aes_coder_presence() {
        let plain = Folder {
            coders: vec![copy_coder()],
            bind_pairs: vec![],
            packed_stream_indices: vec![],
            unpack_sizes: vec![0],
            unpack_crc: None,
        };
        assert!(!FolderDecoder::folder_is_encrypted(&plain));
        let encrypted = Folder {
            coders: vec![Coder {
                id: vec![0x06, 0xF1, 0x07, 0x01],
                props: vec![0x00],
                num_in_streams: 1,
                num_out_streams: 1,
            }],
            bind_pairs: vec![],
            packed_stream_indices: vec![],
            unpack_sizes: vec![0],
            unpack_crc: None,
        };
        assert!(FolderDecoder::folder_is_encrypted(&encrypted));
    }
}
