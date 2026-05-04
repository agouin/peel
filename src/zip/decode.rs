//! Per-entry decoder dispatcher for the ZIP pipeline.
//!
//! Round-one supports three compression methods (`docs/PLAN_v2.md`
//! §5):
//!
//! - **STORED (0)** — passthrough; bytes flow from source to sink
//!   verbatim.
//! - **DEFLATE (8)** — RFC 1951 raw deflate via the hand-rolled
//!   [`crate::decode::deflate_native::Decoder`]. Phase 9a of
//!   `docs/PLAN_deflate_block_decoder.md` swapped this off
//!   `flate2`'s `miniz_oxide` backend; the entry's compressed
//!   bytes are buffered into an owned [`std::io::Cursor`] before
//!   handoff so the existing `'static`-source decoder API works
//!   unchanged. Memory peak per call = entry's `compressed_size`
//!   from the central directory; Phase 11 may stream this for the
//!   pathologically-large-entry case.
//! - **zstd (93)** — via the existing `zstd` crate binding, the
//!   same backend [`crate::decode::zstd`] uses. Per the APPNOTE,
//!   ZIP-zstd entries are wrapped in a single zstd frame.
//!
//! Any other compression method surfaces as
//! [`ZipError::UnsupportedFeature`] naming the method (e.g.
//! "DEFLATE64 (9)", "BZIP2 (12)", …) so the user sees a precise
//! refusal, not a generic parse failure.
//!
//! # Streaming
//!
//! [`decompress_entry`] is one-shot: it consumes the bounded `Read`
//! source from start to end, feeding decoded bytes through
//! [`ZipSink::write_entry`] in fixed-size chunks. The buffer is
//! [`COPY_BUFFER_LEN`] bytes — large enough that per-call syscall
//! overhead is amortized, small enough that even gigabyte-scale
//! entries do not balloon resident memory. The caller is
//! responsible for bounding the source (typically with
//! [`std::io::Read::take`]) so the codec doesn't read past the
//! entry's compressed-size declaration.
//!
//! # Errors
//!
//! Failures are surfaced as [`EntryDecodeError`]:
//!
//! - source-read failures and codec-format failures map to
//!   [`EntryDecodeError::Read`];
//! - sink failures (filesystem, CRC mismatch via the sink's
//!   end-of-entry check) map to [`EntryDecodeError::Sink`];
//! - unsupported methods map to [`EntryDecodeError::Zip`] with the
//!   inner [`ZipError::UnsupportedFeature`].

use std::io::{Cursor, Read};

use thiserror::Error;

use crate::decode::{deflate_native, DecodeError, DecodeStatus, StreamingDecoder};
use crate::sink::{SinkError, ZipSink};
use crate::zip::format::CompressionMethod;
use crate::zip::ZipError;

/// Buffer size used by [`decompress_entry`]'s copy loop. Sized to
/// the same scale the streaming decoders in [`crate::decode`] use so
/// the kernel-syscall amortization story matches.
pub const COPY_BUFFER_LEN: usize = 64 * 1024;

/// Composite error type returned by [`decompress_entry`].
///
/// Discriminating between source / codec failure (`Read`) and sink
/// failure (`Sink`) is load-bearing for the pipeline's retry policy:
/// a transient source error is recoverable by re-reading the entry's
/// chunks; a sink error usually means a filesystem problem the user
/// has to address.
#[derive(Debug, Error)]
pub enum EntryDecodeError {
    /// Reading from the source or interpreting compressed bytes
    /// failed. The codec's [`std::io::Error`]s funnel through here
    /// — Phase 9a swapped DEFLATE off `flate2` onto the hand-rolled
    /// [`crate::decode::deflate_native::Decoder`], whose format
    /// violations (`MalformedHuffman`, `BackReferenceUnderflow`,
    /// etc.) surface as [`std::io::ErrorKind::Other`] with a
    /// human-readable message preserved through the wrapped
    /// [`std::io::Error`].
    #[error("failed to read or decompress entry {entry_name:?}")]
    Read {
        /// Entry name from the central directory.
        entry_name: String,
        /// The underlying error, preserved for `Error::source`.
        #[source]
        source: std::io::Error,
    },

    /// Writing decoded bytes to the sink failed.
    #[error("sink rejected decoded bytes for entry {entry_name:?}")]
    Sink {
        /// Entry name from the central directory.
        entry_name: String,
        /// The underlying sink error.
        #[source]
        source: SinkError,
    },

    /// Wraps a [`ZipError`] surfaced before any IO ran (most
    /// commonly [`ZipError::UnsupportedFeature`] when an entry
    /// declares a compression method round-one does not implement).
    #[error(transparent)]
    Zip(#[from] ZipError),
}

/// Resume context carried through [`decompress_entry`] for
/// codec-aware mid-entry resume.
///
/// `blob` is the opaque decoder-state blob captured by a previous
/// run's mid-entry checkpoint
/// (`SinkState::Zip::current_entry_decoder_state`). `compressed`
/// must already be positioned at `source_byte_offset` within the
/// entry's compressed payload — typically the caller has done
/// `entry_reader.take(compressed_size - source_byte_offset)`
/// after seeking past the prefix.
#[derive(Debug)]
pub struct DecompressResume<'a> {
    /// Opaque codec-resume blob.
    pub blob: &'a [u8],
    /// Byte offset within the entry's compressed payload where
    /// `compressed` starts delivering bytes.
    pub source_byte_offset: u64,
}

/// Per-progress hook fired periodically inside
/// [`decompress_entry`]'s decode loop. Receives the cumulative
/// bytes written into the sink for the in-flight entry plus the
/// codec's most-recent snapshotable state (when one is
/// available). Returning `Err` aborts the decode with
/// [`EntryDecodeError::Read`] carrying the IO error.
pub type InEntryProgressCallback<'a> =
    &'a mut dyn FnMut(u64, Option<Vec<u8>>) -> std::io::Result<()>;

/// Decompress one entry's compressed bytes into the sink.
///
/// `compressed` is a `Read` that yields exactly the entry's
/// compressed payload — typically `entry_reader.take(compressed_size)`
/// constructed by the caller. `sink` must already have an entry in
/// flight (via [`ZipSink::begin_entry`] or
/// [`ZipSink::begin_entry_resume`]). On return the entry's
/// bytes have been fully fed into the sink and the caller can
/// [`ZipSink::end_entry`] to validate the CRC.
///
/// # Errors
///
/// See [`EntryDecodeError`].
pub fn decompress_entry<R: Read>(
    method: CompressionMethod,
    compressed: R,
    sink: &mut ZipSink,
    entry_name: &str,
) -> Result<u64, EntryDecodeError> {
    decompress_entry_with_resume(method, compressed, sink, entry_name, None, &mut |_, _| {
        Ok(())
    })
}

/// Like [`decompress_entry`] but additionally:
///
/// - Honors `resume` (when `Some`) by constructing the codec
///   from the captured state blob via the codec's
///   `resume_factory`. The caller must have already positioned
///   `compressed` at `resume.source_byte_offset` and called
///   [`ZipSink::begin_entry_resume`] so the sink picks up at the
///   matching output offset.
/// - Fires `progress` periodically inside the decode loop with
///   the cumulative bytes-written-this-entry and (when the codec
///   supports mid-entry resume) the latest decoder-state blob.
///   Returning `Err` from the callback aborts the decode with
///   [`EntryDecodeError::Read`] carrying the IO error.
///
/// Used by the zip pipeline's
/// [`crate::download::zip_pipeline::ZipPipeline::run`] to thread
/// Phase 9b's `current_entry_decoder_state` through.
pub fn decompress_entry_with_resume<R: Read>(
    method: CompressionMethod,
    compressed: R,
    sink: &mut ZipSink,
    entry_name: &str,
    resume: Option<DecompressResume<'_>>,
    progress: InEntryProgressCallback<'_>,
) -> Result<u64, EntryDecodeError> {
    match method {
        CompressionMethod::Stored => {
            copy_into_sink_with_progress(compressed, sink, entry_name, progress)
        }
        CompressionMethod::Deflate => {
            decompress_deflate_entry_with_resume(compressed, sink, entry_name, resume, progress)
        }
        CompressionMethod::Zstd => {
            decompress_zstd_entry_with_resume(compressed, sink, entry_name, resume, progress)
        }
        CompressionMethod::Other(_) => Err(EntryDecodeError::Zip(ZipError::UnsupportedFeature {
            feature: format!(
                "{label} (entry {entry_name:?})",
                label = method.label(),
                entry_name = entry_name,
            ),
        })),
    }
}

/// Decode one DEFLATE-compressed entry through the hand-rolled
/// [`deflate_native::Decoder`].
///
/// When `resume` is `Some`, the decoder is reconstructed via
/// [`deflate_native::resume_factory`] from the captured blob, the
/// sliding window is pre-seeded, and the bit cursor is advanced
/// to the saved `(byte, bit)` position. When `resume` is `None`,
/// a fresh decoder reads from byte 0.
///
/// Reads the (remaining) compressed bytes off `compressed` into
/// an owned [`Cursor`] so the decoder's `'static`-source API
/// works unchanged, then drives the
/// [`StreamingDecoder::decode_step`] loop, copying decompressed
/// bytes into the sink in [`COPY_BUFFER_LEN`]-bounded batches.
/// `progress` fires after each `decode_step` with the cumulative
/// bytes-written-this-entry and the codec's
/// [`StreamingDecoder::decoder_state`] blob (when available).
///
/// Memory peak per call is the entry's *remaining* compressed size
/// (compressed_size minus `resume.source_byte_offset`); Phase 11
/// of `docs/PLAN_deflate_block_decoder.md` may swap this for a
/// streaming variant once real-world archives need it.
fn decompress_deflate_entry_with_resume<R: Read>(
    mut compressed: R,
    sink: &mut ZipSink,
    entry_name: &str,
    resume: Option<DecompressResume<'_>>,
    progress: InEntryProgressCallback<'_>,
) -> Result<u64, EntryDecodeError> {
    // Buffer the entry's (remaining) compressed bytes into memory.
    // The caller's bounded source caps this at the central
    // directory's `compressed_size` (or its remainder past the
    // resume point).
    let mut compressed_buf = Vec::new();
    compressed
        .read_to_end(&mut compressed_buf)
        .map_err(|source| EntryDecodeError::Read {
            entry_name: entry_name.to_string(),
            source,
        })?;
    let cursor: Box<dyn Read + Send> = Box::new(Cursor::new(compressed_buf));

    // Construct fresh-or-resumed decoder.
    let mut decoder: Box<dyn StreamingDecoder> = if let Some(r) = resume.as_ref() {
        deflate_native::resume_factory(cursor, r.blob, r.source_byte_offset).map_err(|e| {
            let source = decode_err_to_io(e);
            EntryDecodeError::Read {
                entry_name: entry_name.to_string(),
                source,
            }
        })?
    } else {
        deflate_native::factory(cursor).map_err(|e| {
            let source = decode_err_to_io(e);
            EntryDecodeError::Read {
                entry_name: entry_name.to_string(),
                source,
            }
        })?
    };

    drive_streaming_decoder(decoder.as_mut(), sink, entry_name, progress)
}

/// Decode one zstd-compressed entry through the hand-rolled
/// [`crate::decode::zstd::Decoder`] when a resume blob is
/// supplied; otherwise fall back to the upstream `zstd` crate
/// binding (matching the pre-Phase-9b behaviour for fresh
/// entries — Phase 11 may unify both paths once the hand-rolled
/// decoder's throughput matches `zstd`'s for short single-frame
/// inputs).
fn decompress_zstd_entry_with_resume<R: Read>(
    mut compressed: R,
    sink: &mut ZipSink,
    entry_name: &str,
    resume: Option<DecompressResume<'_>>,
    progress: InEntryProgressCallback<'_>,
) -> Result<u64, EntryDecodeError> {
    if let Some(r) = resume {
        // Buffer remaining compressed bytes for the resume path —
        // the resume_factory's `Box<dyn Read + Send>` source
        // demands `'static`. Memory cost mirrors the deflate
        // case above.
        let mut compressed_buf = Vec::new();
        compressed
            .read_to_end(&mut compressed_buf)
            .map_err(|source| EntryDecodeError::Read {
                entry_name: entry_name.to_string(),
                source,
            })?;
        let cursor: Box<dyn Read + Send> = Box::new(Cursor::new(compressed_buf));
        let mut decoder = crate::decode::zstd::resume_factory(cursor, r.blob, r.source_byte_offset)
            .map_err(|e| {
                let source = decode_err_to_io(e);
                EntryDecodeError::Read {
                    entry_name: entry_name.to_string(),
                    source,
                }
            })?;
        drive_streaming_decoder(decoder.as_mut(), sink, entry_name, progress)
    } else {
        // Fresh entry: stream through the upstream zstd binding,
        // matching the pre-Phase-9b path. The progress callback
        // still fires after each chunk, just without a
        // decoder_state blob (the upstream binding doesn't expose
        // mid-stream state; only the hand-rolled decoder does).
        let decoder = zstd::stream::read::Decoder::new(compressed).map_err(|source| {
            EntryDecodeError::Read {
                entry_name: entry_name.to_string(),
                source,
            }
        })?;
        copy_into_sink_with_progress(decoder, sink, entry_name, progress)
    }
}

/// Drive a [`StreamingDecoder`] until clean EOF, writing each
/// step's output to `sink` and firing `progress` with the
/// cumulative bytes-written-this-entry and the codec's resume
/// blob (when one is available). Shared by the deflate path and
/// the zstd-with-resume path.
fn drive_streaming_decoder(
    decoder: &mut dyn StreamingDecoder,
    sink: &mut ZipSink,
    entry_name: &str,
    progress: InEntryProgressCallback<'_>,
) -> Result<u64, EntryDecodeError> {
    let mut staging: Vec<u8> = Vec::with_capacity(COPY_BUFFER_LEN);
    let mut total: u64 = 0;
    loop {
        let status = decoder.decode_step(&mut staging).map_err(|e| {
            let source = decode_err_to_io(e);
            EntryDecodeError::Read {
                entry_name: entry_name.to_string(),
                source,
            }
        })?;
        if !staging.is_empty() {
            sink.write_entry(&staging)
                .map_err(|source| EntryDecodeError::Sink {
                    entry_name: entry_name.to_string(),
                    source,
                })?;
            total = total.saturating_add(staging.len() as u64);
            staging.clear();
        }
        // Pull a snapshotable resume blob if the codec exposes
        // one at this step (returns `None` mid-block / at EOF for
        // hand-rolled decoders that only checkpoint at boundaries).
        let blob = decoder.decoder_state();
        progress(total, blob).map_err(|source| EntryDecodeError::Read {
            entry_name: entry_name.to_string(),
            source,
        })?;
        if matches!(status, DecodeStatus::Eof) {
            break;
        }
    }
    Ok(total)
}

/// Translate a [`DecodeError`] from the hand-rolled deflate
/// decoder into an [`std::io::Error`] so the callers'
/// [`EntryDecodeError::Read`] / [`EntryDecodeError::Sink`]
/// discrimination stays clean. Source / format errors funnel
/// through `Read`; sink errors funnel through the
/// `EntryDecodeError::Sink` arm at the call site (the decoder's
/// internal sink path can't surface here because we pass it a
/// `Vec<u8>` whose `write_all` is infallible).
fn decode_err_to_io(e: DecodeError) -> std::io::Error {
    match e {
        DecodeError::Read { source, .. } => source,
        DecodeError::Write(source) => source,
        DecodeError::Construct(source) => source,
        DecodeError::ResumeMismatch { expected, actual } => std::io::Error::other(format!(
            "deflate resume seam mismatch: expected {expected}, actual {actual}"
        )),
    }
}

/// Copy `src` to `sink` in fixed-size chunks until EOF, firing
/// `progress` after each chunk write. STORED entries (and the
/// upstream-zstd fresh path) use this — neither has a
/// snapshotable codec state, so the `decoder_state` argument to
/// `progress` is always `None`.
fn copy_into_sink_with_progress<R: Read>(
    mut src: R,
    sink: &mut ZipSink,
    entry_name: &str,
    progress: InEntryProgressCallback<'_>,
) -> Result<u64, EntryDecodeError> {
    let mut buf = vec![0u8; COPY_BUFFER_LEN];
    let mut total: u64 = 0;
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(source) => {
                return Err(EntryDecodeError::Read {
                    entry_name: entry_name.to_string(),
                    source,
                });
            }
        };
        sink.write_entry(&buf[..n])
            .map_err(|source| EntryDecodeError::Sink {
                entry_name: entry_name.to_string(),
                source,
            })?;
        total += n as u64;
        progress(total, None).map_err(|source| EntryDecodeError::Read {
            entry_name: entry_name.to_string(),
            source,
        })?;
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
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
            std::env::temp_dir().join(format!("peel_zipdecode_unit_{label}_{pid}_{nanos}_{n}"));
        fs::create_dir_all(&path).expect("mkdir tmp root");
        path
    }

    struct CleanupOnDrop(PathBuf);
    impl Drop for CleanupOnDrop {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// Encode `data` to raw DEFLATE (no zlib header), the wire form
    /// ZIP entries use.
    fn deflate_raw(data: &[u8]) -> Vec<u8> {
        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(data).expect("encode");
        encoder.finish().expect("finish")
    }

    fn zstd_encode(data: &[u8]) -> Vec<u8> {
        zstd::encode_all(std::io::Cursor::new(data), 3).expect("zstd encode")
    }

    #[test]
    fn stored_round_trips_short_buffer() {
        let root = unique_dir("stored-short");
        let _g = CleanupOnDrop(root.clone());
        let payload = b"hello, stored entry";
        let crc = ieee(payload);

        let mut sink = ZipSink::new(&root).expect("sink");
        sink.begin_entry(0, "hello.txt", payload.len() as u64, crc)
            .expect("begin");
        let n = decompress_entry(
            CompressionMethod::Stored,
            std::io::Cursor::new(payload),
            &mut sink,
            "hello.txt",
        )
        .expect("decompress");
        assert_eq!(n, payload.len() as u64);
        sink.end_entry().expect("end");
        sink.close().expect("close");
        assert_eq!(fs::read(root.join("hello.txt")).unwrap(), payload);
    }

    #[test]
    fn deflate_round_trips_random_payload() {
        let root = unique_dir("deflate");
        let _g = CleanupOnDrop(root.clone());
        // A non-trivially compressible payload: 64 KiB of repeating
        // text plus some literal noise so DEFLATE actually does work
        // and the test exercises non-trivial codec output.
        let mut payload = Vec::with_capacity(64 * 1024);
        while payload.len() < 64 * 1024 {
            payload.extend_from_slice(b"the quick brown fox jumps over the lazy dog. ");
        }
        payload.truncate(64 * 1024);
        let crc = ieee(&payload);

        let compressed = deflate_raw(&payload);
        // Non-trivial check that DEFLATE actually shrunk something.
        assert!(compressed.len() < payload.len());

        let mut sink = ZipSink::new(&root).expect("sink");
        sink.begin_entry(0, "compressible.txt", payload.len() as u64, crc)
            .expect("begin");
        let n = decompress_entry(
            CompressionMethod::Deflate,
            std::io::Cursor::new(compressed),
            &mut sink,
            "compressible.txt",
        )
        .expect("decompress");
        assert_eq!(n, payload.len() as u64);
        sink.end_entry().expect("end");
        sink.close().expect("close");
        assert_eq!(fs::read(root.join("compressible.txt")).unwrap(), payload);
    }

    #[test]
    fn zstd_round_trips_short_buffer() {
        let root = unique_dir("zstd");
        let _g = CleanupOnDrop(root.clone());
        let payload = b"abcdef".repeat(128);
        let crc = ieee(&payload);
        let compressed = zstd_encode(&payload);

        let mut sink = ZipSink::new(&root).expect("sink");
        sink.begin_entry(0, "z.bin", payload.len() as u64, crc)
            .expect("begin");
        let n = decompress_entry(
            CompressionMethod::Zstd,
            std::io::Cursor::new(compressed),
            &mut sink,
            "z.bin",
        )
        .expect("decompress");
        assert_eq!(n, payload.len() as u64);
        sink.end_entry().expect("end");
        sink.close().expect("close");
        assert_eq!(fs::read(root.join("z.bin")).unwrap(), payload);
    }

    #[test]
    fn unsupported_method_surfaces_feature_message_with_name() {
        let root = unique_dir("unsupported");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = ZipSink::new(&root).expect("sink");
        sink.begin_entry(0, "x.bin", 0, 0).expect("begin");
        let err = decompress_entry(
            CompressionMethod::Other(14),
            std::io::Cursor::new(b""),
            &mut sink,
            "x.bin",
        )
        .expect_err("must refuse");
        let msg = err.to_string();
        assert!(msg.contains("LZMA"), "msg = {msg}");
        // Don't `end_entry` on a refused entry; the sink stays in
        // its mid-entry state but the caller gets the typed error.
    }

    #[test]
    fn corrupt_deflate_payload_surfaces_read_error() {
        let root = unique_dir("bad-deflate");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = ZipSink::new(&root).expect("sink");
        sink.begin_entry(0, "broken.bin", 100, 0).expect("begin");
        // Garbage that is not valid DEFLATE.
        let garbage = vec![0xFFu8; 64];
        let err = decompress_entry(
            CompressionMethod::Deflate,
            std::io::Cursor::new(garbage),
            &mut sink,
            "broken.bin",
        )
        .expect_err("must reject");
        match err {
            EntryDecodeError::Read { entry_name, .. } => assert_eq!(entry_name, "broken.bin"),
            other => panic!("expected Read, got {other:?}"),
        }
    }

    #[test]
    fn stored_writing_past_size_surfaces_sink_error() {
        // Sink declares 4 bytes; STORED reader gives 8. The sink
        // rejects the second 4 bytes, which is reported as
        // EntryDecodeError::Sink.
        let root = unique_dir("oversize");
        let _g = CleanupOnDrop(root.clone());
        let mut sink = ZipSink::new(&root).expect("sink");
        sink.begin_entry(0, "f.bin", 4, 0).expect("begin");
        let err = decompress_entry(
            CompressionMethod::Stored,
            std::io::Cursor::new(b"abcdefgh"),
            &mut sink,
            "f.bin",
        )
        .expect_err("must reject");
        assert!(matches!(err, EntryDecodeError::Sink { .. }));
    }
}
