//! 7z coder registry: dispatch from parsed
//! [`super::header::Coder`] to a runtime [`CoderImpl`].
//!
//! Implements §4 of `docs/PLAN_7z_support.md` (COPY + DEFLATE)
//! and provides the dispatch surface §5 plugs LZMA / LZMA2 into.
//!
//! The `CoderImpl` trait is object-safe (`&mut dyn Read` source,
//! `&mut dyn Write` sink) so the §6 folder decoder can keep a
//! chain of coders in a `Vec<Box<dyn CoderImpl>>` and run them
//! in order. The borrowed-source shape lets the COPY hot path
//! stream straight from the sparse file (no 256 MiB intermediate
//! `Vec`) — that pull was the dominant cost in the §10 round-one
//! 4× wall-clock gap at 10 Gbps × 256 MiB. DEFLATE wraps the
//! borrowed reader in a small `unsafe` lifetime-extension
//! adapter to satisfy
//! [`crate::decode::deflate_native::Decoder::new`]'s owned-source
//! constructor; the wrapper is constructed and dropped inside
//! the same `decode_one_block` call, so the borrow it holds is
//! valid for the whole decoder lifetime.
//!
//! # Round-one coder set
//!
//! - `[0x00]`             → COPY (this module).
//! - `[0x04, 0x01, 0x08]` → DEFLATE (raw, no zlib / gzip
//!   framing). Wraps the in-tree
//!   [`crate::decode::deflate_native::Decoder`].
//! - `[0x03, 0x01, 0x01]` → LZMA  (round-one, plumbed in §5).
//! - `[0x21]`             → LZMA2 (round-one, plumbed in §5).
//!
//! Anything else surfaces a typed
//! [`CoderError::UnsupportedFeature`] naming the id in hex.

use std::io::{self, Read, Write};

use thiserror::Error;

use crate::decode::deflate_native::Decoder as DeflateDecoder;
use crate::decode::xz_liblzma::raw::{decode_lzma1_raw, decode_lzma2_raw};
use crate::decode::{DecodeStatus, StreamingDecoder};

use super::header::Coder;

/// Canonical 7z coder ids the registry understands.
///
/// Each variant carries the "kind" of coder — the runtime
/// [`CoderImpl`] dispatched against the variant is what does
/// the decoding work. Holding the id as an enum (rather than a
/// raw `Vec<u8>`) keeps the §3 → §4 → §5 plumbing readable: the
/// parsed `Folder` says `coders[i].id == CoderId::Lzma2` and
/// the dispatcher knows what to do.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CoderId {
    /// `[0x00]` — store-as-is (no compression).
    Copy,
    /// `[0x04, 0x01, 0x08]` — raw DEFLATE.
    Deflate,
    /// `[0x03, 0x01, 0x01]` — LZMA (with its
    /// 5-byte `(properties, dict_size_le32)` prop blob).
    Lzma,
    /// `[0x21]` — LZMA2 (with its 1-byte `dictSize` prop).
    Lzma2,
    /// Anything else. Carries the raw id for use in error
    /// messages.
    Unsupported(Vec<u8>),
}

impl CoderId {
    /// Map raw id bytes from
    /// [`super::header::Coder::id`] to the typed variant.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        match bytes {
            [0x00] => Self::Copy,
            [0x04, 0x01, 0x08] => Self::Deflate,
            [0x03, 0x01, 0x01] => Self::Lzma,
            [0x21] => Self::Lzma2,
            _ => Self::Unsupported(bytes.to_vec()),
        }
    }

    /// Render the id as a colon-separated hex string for use in
    /// error messages and logs (e.g. `"04:02:02"` for BZIP2).
    /// Stable across builds; the diagnostic output is what
    /// users see when they hit an unsupported coder.
    #[must_use]
    pub fn hex_repr(&self) -> String {
        let bytes = match self {
            Self::Copy => &[0x00u8][..],
            Self::Deflate => &[0x04u8, 0x01, 0x08][..],
            Self::Lzma => &[0x03u8, 0x01, 0x01][..],
            Self::Lzma2 => &[0x21u8][..],
            Self::Unsupported(b) => b.as_slice(),
        };
        bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    }
}

/// Errors a [`CoderImpl`] can surface.
///
/// Distinct from [`super::SevenzError`] (the parser-side error
/// type) because the runtime decoder makes a different set of
/// promises: it can produce [`Self::Io`] when the source / sink
/// fails, whereas the parser cannot. The §6 folder decoder
/// converts via `?`.
#[derive(Debug, Error)]
pub enum CoderError {
    /// The decoded output's byte count disagreed with the size
    /// the archive declared in `CodersUnPackSize`.
    #[error(
        "{coder} unpack size mismatch: expected {expected} bytes, \
         decoder produced {got}"
    )]
    UnpackSizeMismatch {
        /// Human-readable coder name (`"copy"`, `"deflate"`, …).
        coder: &'static str,
        /// Bytes the archive said the coder would produce.
        expected: u64,
        /// Bytes the coder actually wrote to its sink.
        got: u64,
    },

    /// The coder's properties blob was malformed (wrong length
    /// for the coder, reserved bits set, etc.).
    #[error("{coder} properties rejected: {reason}")]
    BadProps {
        /// Human-readable coder name.
        coder: &'static str,
        /// Specific reason — e.g. `"LZMA props must be 5 bytes,
        /// got 3"`.
        reason: String,
    },

    /// The inner format-specific decoder reported a failure.
    /// `coder` names which one; the wrapped IO error carries
    /// the underlying message.
    #[error("{coder} decode failure")]
    Decode {
        /// Human-readable coder name.
        coder: &'static str,
        /// Underlying error from the format-specific decoder.
        #[source]
        source: io::Error,
    },

    /// Reading from the source or writing to the sink failed.
    #[error("coder IO failure")]
    Io(#[from] io::Error),

    /// The archive uses a coder id this build does not
    /// implement.
    ///
    /// `feature` is human-readable and includes the coder's
    /// hex id (e.g. `"coder id 04:02:02 (BZIP2)"`).
    #[error("unsupported coder: {feature}")]
    UnsupportedFeature {
        /// Human-readable feature name.
        feature: String,
    },
}

/// Runtime decoder for one [`Coder`] inside a [`super::header::Folder`].
///
/// Round-one's contract is "decode the entire stream in one
/// call" (`decode_one_block` produces the full per-coder
/// output); per-block streaming inside a folder is filed as
/// `O.32c` in `OPTIMIZATIONS.md` and shares its design with
/// `xz_liblzma::resume`.
pub trait CoderImpl: Send {
    /// Drain `src` of the coder's input bytes and write the
    /// decoded output to `dst`, validating against
    /// `expected_unpack_size`.
    ///
    /// `src` is exhausted (read until EOF) — the §6 folder
    /// decoder positions a `Read` adapter so EOF aligns with
    /// the end of this coder's packed-stream slice. Ownership
    /// is transferred so format-specific decoders that take
    /// `Box<dyn Read + Send>` (e.g.
    /// [`crate::decode::deflate_native::Decoder::new`]) can be
    /// driven without lifetime gymnastics.
    ///
    /// # Errors
    ///
    /// - [`CoderError::Io`] for raw read/write failures.
    /// - [`CoderError::Decode`] for format-specific errors the
    ///   inner decoder surfaces.
    /// - [`CoderError::UnpackSizeMismatch`] when the decoder
    ///   produces fewer or more bytes than declared.
    fn decode_one_block(
        &mut self,
        src: &mut dyn Read,
        dst: &mut dyn Write,
        expected_unpack_size: u64,
    ) -> Result<(), CoderError>;

    /// Human-readable name (`"copy"`, `"deflate"`, …) used in
    /// log lines and error messages.
    fn name(&self) -> &'static str;
}

/// Resolve a parsed [`Coder`] to its runtime [`CoderImpl`].
///
/// # Errors
///
/// [`CoderError::UnsupportedFeature`] if the coder's id does
/// not match any registered runtime.
/// [`CoderError::BadProps`] if the props blob size disagrees
/// with the coder's expectations.
pub fn dispatch(coder: &Coder) -> Result<Box<dyn CoderImpl>, CoderError> {
    let id = CoderId::from_bytes(&coder.id);
    match id {
        CoderId::Copy => {
            if !coder.props.is_empty() {
                return Err(CoderError::BadProps {
                    coder: "copy",
                    reason: format!("expected 0 prop bytes, got {}", coder.props.len()),
                });
            }
            Ok(Box::new(CopyCoder))
        }
        CoderId::Deflate => {
            if !coder.props.is_empty() {
                return Err(CoderError::BadProps {
                    coder: "deflate",
                    reason: format!("expected 0 prop bytes, got {}", coder.props.len()),
                });
            }
            Ok(Box::new(DeflateCoder))
        }
        CoderId::Lzma => {
            if coder.props.len() != 5 {
                return Err(CoderError::BadProps {
                    coder: "lzma",
                    reason: format!("LZMA props must be 5 bytes, got {}", coder.props.len()),
                });
            }
            let mut props = [0u8; 5];
            props.copy_from_slice(&coder.props);
            Ok(Box::new(LzmaCoder { props }))
        }
        CoderId::Lzma2 => {
            if coder.props.len() != 1 {
                return Err(CoderError::BadProps {
                    coder: "lzma2",
                    reason: format!("LZMA2 props must be 1 byte, got {}", coder.props.len()),
                });
            }
            Ok(Box::new(Lzma2Coder {
                props_byte: coder.props[0],
            }))
        }
        CoderId::Unsupported(_) => Err(CoderError::UnsupportedFeature {
            feature: format!("coder id {}", id.hex_repr()),
        }),
    }
}

/// COPY coder: pass bytes through unchanged.
struct CopyCoder;

impl CoderImpl for CopyCoder {
    fn decode_one_block(
        &mut self,
        src: &mut dyn Read,
        dst: &mut dyn Write,
        expected_unpack_size: u64,
    ) -> Result<(), CoderError> {
        // `io::copy`'s default 8 KiB stack buffer would issue
        // ~32 K preads for a 256 MiB folder, each one going
        // through the streaming reader's bitmap-poll path; the
        // syscall + atomic-load tax is non-trivial at high
        // bandwidth. A 256 KiB buffer issues ~1 K preads
        // instead, which the kernel's readahead absorbs
        // cheaply, and keeps the bitmap-check rate down to
        // once per ~64 KiB of pread (well under any chunk
        // size) — so the streaming-overlap behaviour the
        // smaller buffer provided is preserved.
        const COPY_BUF_BYTES: usize = 256 * 1024;
        let mut buf = vec![0u8; COPY_BUF_BYTES];
        let mut copied: u64 = 0;
        loop {
            let n = src.read(&mut buf).map_err(CoderError::Io)?;
            if n == 0 {
                break;
            }
            dst.write_all(&buf[..n]).map_err(CoderError::Io)?;
            copied = copied.saturating_add(n as u64);
        }
        if copied != expected_unpack_size {
            return Err(CoderError::UnpackSizeMismatch {
                coder: "copy",
                expected: expected_unpack_size,
                got: copied,
            });
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "copy"
    }
}

/// Raw-DEFLATE coder: wraps
/// [`crate::decode::deflate_native::Decoder`] driven through
/// its [`StreamingDecoder`] interface.
struct DeflateCoder;

impl CoderImpl for DeflateCoder {
    fn decode_one_block(
        &mut self,
        src: &mut dyn Read,
        dst: &mut dyn Write,
        expected_unpack_size: u64,
    ) -> Result<(), CoderError> {
        // [`DeflateDecoder::new`] takes `Box<dyn Read + Send +
        // 'static>`. Wrap the borrowed `src` in a tiny adapter
        // that lifetime-extends the borrow; the adapter is
        // owned by the [`DeflateDecoder`] which is dropped
        // before this function returns, so the borrow it holds
        // is valid for the entire decoder lifetime.
        let owned: Box<dyn Read + Send> = Box::new(BorrowedReadAdapter::new(src));
        let mut decoder = DeflateDecoder::new(owned).map_err(map_decode_err)?;
        let mut counting = CountingWriter {
            inner: dst,
            count: 0,
        };
        while let DecodeStatus::MoreData =
            decoder.decode_step(&mut counting).map_err(map_decode_err)?
        {}
        if counting.count != expected_unpack_size {
            return Err(CoderError::UnpackSizeMismatch {
                coder: "deflate",
                expected: expected_unpack_size,
                got: counting.count,
            });
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "deflate"
    }
}

/// Owned `Read + Send + 'static` adapter that delegates to a
/// borrowed `&mut dyn Read`.
///
/// Used by [`DeflateCoder`] to feed
/// [`crate::decode::deflate_native::Decoder::new`] (which takes
/// an owned `Box<dyn Read + Send>`) without an intermediate
/// `Vec<u8>` slurp of the entire packed stream.
///
/// # Safety
///
/// The struct holds a raw pointer to a `dyn Read` whose
/// referent is bounded by the calling stack frame. Constructing
/// it requires a `&mut dyn Read` (so the borrow is alive at
/// construction); the only consumer
/// ([`DeflateCoder::decode_one_block`]) keeps the adapter
/// inside a `DeflateDecoder` that is created *and* consumed
/// inside the same function, so the adapter never outlives the
/// borrow.
///
/// `Send` is sound because the entire lifecycle stays on a
/// single thread (the §6 folder decoder calls
/// `decode_one_block` synchronously); the `Send` claim only
/// satisfies the `Box<dyn Read + Send>` bound the
/// `DeflateDecoder` constructor wants.
struct BorrowedReadAdapter {
    inner: std::ptr::NonNull<dyn Read + 'static>,
}

impl BorrowedReadAdapter {
    /// Wrap the borrowed reader. The caller must ensure the
    /// adapter is dropped before `inner`'s borrow expires;
    /// inside [`DeflateCoder::decode_one_block`] this is
    /// guaranteed by the `DeflateDecoder` drop ordering.
    fn new(inner: &mut dyn Read) -> Self {
        // SAFETY: we lifetime-extend `inner`'s borrow to
        // `'static` solely to satisfy the
        // `Box<dyn Read + Send>` (= `+ 'static`) bound on
        // [`crate::decode::deflate_native::Decoder::new`]. The
        // type-level safety doc on [`Self`] guarantees the
        // adapter never outlives the real borrow — it is
        // constructed and dropped inside the same
        // `decode_one_block` call. NonNull::new_unchecked is
        // sound because `inner` is a live mutable reference.
        let static_ptr: *mut (dyn Read + 'static) =
            unsafe { std::mem::transmute::<*mut dyn Read, *mut (dyn Read + 'static)>(inner) };
        let ptr = unsafe { std::ptr::NonNull::new_unchecked(static_ptr) };
        Self { inner: ptr }
    }
}

// SAFETY: the adapter is single-threaded by construction (see
// the type's `# Safety` doc) — the `Send` claim is what the
// `Box<dyn Read + Send>` bound on `DeflateDecoder::new`
// demands, not an assertion that real cross-thread movement
// happens.
unsafe impl Send for BorrowedReadAdapter {}

impl Read for BorrowedReadAdapter {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // SAFETY: `self.inner` was constructed from a
        // `&mut dyn Read` in `BorrowedReadAdapter::new`. Per
        // the type-level safety doc, the adapter never
        // outlives that borrow, and we are the unique holder
        // of the pointer (the adapter owns it; no clones).
        // Re-materializing as `&mut *` is therefore unique.
        let r = unsafe { self.inner.as_mut() };
        r.read(buf)
    }
}

/// LZMA1 coder. Slurps the source into a buffer (the per-
/// coder packed-stream slice is bounded by the §3 parser) and
/// runs the raw LZMA1 driver from
/// [`crate::decode::xz_liblzma::raw::decode_lzma1_raw`].
struct LzmaCoder {
    props: [u8; 5],
}

impl CoderImpl for LzmaCoder {
    fn decode_one_block(
        &mut self,
        src: &mut dyn Read,
        dst: &mut dyn Write,
        expected_unpack_size: u64,
    ) -> Result<(), CoderError> {
        let mut buf = Vec::new();
        src.read_to_end(&mut buf)?;
        decode_lzma1_raw(&self.props, &buf, dst, expected_unpack_size).map_err(|e| {
            CoderError::Decode {
                coder: "lzma",
                source: io::Error::other(format!("{e}")),
            }
        })
    }

    fn name(&self) -> &'static str {
        "lzma"
    }
}

/// LZMA2 coder. Same shape as [`LzmaCoder`]: buffer the
/// packed-stream slice, run
/// [`crate::decode::xz_liblzma::raw::decode_lzma2_raw`].
struct Lzma2Coder {
    props_byte: u8,
}

impl CoderImpl for Lzma2Coder {
    fn decode_one_block(
        &mut self,
        src: &mut dyn Read,
        dst: &mut dyn Write,
        expected_unpack_size: u64,
    ) -> Result<(), CoderError> {
        let mut buf = Vec::new();
        src.read_to_end(&mut buf)?;
        decode_lzma2_raw(self.props_byte, &buf, dst, expected_unpack_size).map_err(|e| {
            CoderError::Decode {
                coder: "lzma2",
                source: io::Error::other(format!("{e}")),
            }
        })
    }

    fn name(&self) -> &'static str {
        "lzma2"
    }
}

/// Convert a [`crate::decode::DecodeError`] from the deflate
/// backend to our [`CoderError::Decode`] shape, preserving the
/// underlying [`std::io::Error`] so callers can match on its
/// kind.
fn map_decode_err(e: crate::decode::DecodeError) -> CoderError {
    match e {
        crate::decode::DecodeError::Read { source, .. }
        | crate::decode::DecodeError::Write(source)
        | crate::decode::DecodeError::Construct(source) => CoderError::Decode {
            coder: "deflate",
            source,
        },
        crate::decode::DecodeError::ResumeMismatch { .. } => CoderError::Decode {
            coder: "deflate",
            source: io::Error::other("deflate resume mismatch (not used by 7z runtime)"),
        },
    }
}

/// `Write` shim that counts the bytes flowing through to the
/// inner sink. Used to validate `decode_one_block`'s
/// `expected_unpack_size` invariant.
struct CountingWriter<'a> {
    inner: &'a mut dyn Write,
    count: u64,
}

impl Write for CountingWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count = self.count.saturating_add(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::decode::sevenz::header::{BindPair, Coder};

    fn fake_coder(id: &[u8], props: &[u8]) -> Coder {
        Coder {
            id: id.to_vec(),
            props: props.to_vec(),
            num_in_streams: 1,
            num_out_streams: 1,
        }
    }

    #[test]
    fn coder_id_from_bytes_recognizes_round_one_set() {
        assert_eq!(CoderId::from_bytes(&[0x00]), CoderId::Copy);
        assert_eq!(CoderId::from_bytes(&[0x04, 0x01, 0x08]), CoderId::Deflate);
        assert_eq!(CoderId::from_bytes(&[0x03, 0x01, 0x01]), CoderId::Lzma);
        assert_eq!(CoderId::from_bytes(&[0x21]), CoderId::Lzma2);
        assert_eq!(
            CoderId::from_bytes(&[0x04, 0x02, 0x02]),
            CoderId::Unsupported(vec![0x04, 0x02, 0x02])
        );
    }

    #[test]
    fn coder_id_hex_repr_is_colon_separated() {
        assert_eq!(CoderId::Copy.hex_repr(), "00");
        assert_eq!(CoderId::Deflate.hex_repr(), "04:01:08");
        assert_eq!(CoderId::Lzma.hex_repr(), "03:01:01");
        assert_eq!(CoderId::Lzma2.hex_repr(), "21");
        assert_eq!(
            CoderId::Unsupported(vec![0x04, 0x02, 0x02]).hex_repr(),
            "04:02:02",
        );
    }

    /// `dispatch` returns `Box<dyn CoderImpl>`, which has no
    /// `Debug` impl; using `.expect()` directly would leak that
    /// requirement to the test result type. Wrap with a tiny
    /// helper that panics on `Err` without printing the boxed
    /// trait object.
    fn dispatched(coder: &Coder) -> Box<dyn CoderImpl> {
        match dispatch(coder) {
            Ok(c) => c,
            Err(e) => panic!("dispatch failed: {e:?}"),
        }
    }

    #[test]
    fn dispatch_copy_round_trips_bytes() {
        let mut coder = dispatched(&fake_coder(&[0x00], &[]));
        let payload: Vec<u8> = (0..200u32).map(|i| i as u8).collect();
        let mut src = std::io::Cursor::new(payload.clone());
        let mut dst = Vec::new();
        coder
            .decode_one_block(&mut src, &mut dst, payload.len() as u64)
            .expect("decodes");
        assert_eq!(dst, payload);
    }

    #[test]
    fn dispatch_copy_rejects_size_mismatch() {
        let mut coder = dispatched(&fake_coder(&[0x00], &[]));
        let payload: Vec<u8> = (0..100u32).map(|i| i as u8).collect();
        let mut src = std::io::Cursor::new(payload.clone());
        let mut dst = Vec::new();
        match coder.decode_one_block(&mut src, &mut dst, payload.len() as u64 + 5) {
            Err(CoderError::UnpackSizeMismatch {
                coder,
                expected,
                got,
            }) => {
                assert_eq!(coder, "copy");
                assert_eq!(expected, payload.len() as u64 + 5);
                assert_eq!(got, payload.len() as u64);
            }
            Ok(_) => panic!("expected UnpackSizeMismatch, got Ok"),
            Err(other) => panic!("expected UnpackSizeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_copy_rejects_props() {
        match dispatch(&fake_coder(&[0x00], &[0xAA])) {
            Err(CoderError::BadProps { coder, reason }) => {
                assert_eq!(coder, "copy");
                assert!(reason.contains("0 prop"), "got {reason}");
            }
            Ok(_) => panic!("expected BadProps, got Ok"),
            Err(other) => panic!("expected BadProps, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_deflate_round_trips_through_native_backend() {
        // Reference-encode some plaintext with `flate2`'s
        // raw-DEFLATE writer (the dev-dependency the
        // `deflate_native` differential corpus already uses)
        // and decode through our coder.
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write as _;

        let plaintext: Vec<u8> = b"hello hello hello, this is a test of deflate decoding"
            .iter()
            .copied()
            .cycle()
            .take(8192)
            .collect();
        let mut encoded = Vec::new();
        {
            let mut enc = DeflateEncoder::new(&mut encoded, Compression::default());
            enc.write_all(&plaintext).expect("encodes");
            enc.finish().expect("finishes");
        }

        let mut coder = dispatched(&fake_coder(&[0x04, 0x01, 0x08], &[]));
        let mut src = std::io::Cursor::new(encoded);
        let mut dst = Vec::new();
        coder
            .decode_one_block(&mut src, &mut dst, plaintext.len() as u64)
            .expect("decodes");
        assert_eq!(dst, plaintext);
    }

    #[test]
    fn dispatch_deflate_rejects_size_mismatch() {
        use flate2::write::DeflateEncoder;
        use flate2::Compression;
        use std::io::Write as _;

        let plaintext = b"short";
        let mut encoded = Vec::new();
        {
            let mut enc = DeflateEncoder::new(&mut encoded, Compression::default());
            enc.write_all(plaintext).expect("encodes");
            enc.finish().expect("finishes");
        }

        let mut coder = dispatched(&fake_coder(&[0x04, 0x01, 0x08], &[]));
        let mut src = std::io::Cursor::new(encoded);
        let mut dst = Vec::new();
        match coder.decode_one_block(&mut src, &mut dst, 999) {
            Err(CoderError::UnpackSizeMismatch { coder, .. }) => assert_eq!(coder, "deflate"),
            Ok(_) => panic!("expected UnpackSizeMismatch, got Ok"),
            Err(other) => panic!("expected UnpackSizeMismatch, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_lzma_rejects_wrong_props_length() {
        match dispatch(&fake_coder(&[0x03, 0x01, 0x01], &[0; 3])) {
            Err(CoderError::BadProps { coder, reason }) => {
                assert_eq!(coder, "lzma");
                assert!(reason.contains("5 bytes"), "got {reason}");
            }
            Ok(_) => panic!("expected BadProps, got Ok"),
            Err(other) => panic!("expected BadProps, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_lzma2_rejects_wrong_props_length() {
        match dispatch(&fake_coder(&[0x21], &[0; 3])) {
            Err(CoderError::BadProps { coder, reason }) => {
                assert_eq!(coder, "lzma2");
                assert!(reason.contains("1 byte"), "got {reason}");
            }
            Ok(_) => panic!("expected BadProps, got Ok"),
            Err(other) => panic!("expected BadProps, got {other:?}"),
        }
    }

    #[test]
    fn dispatch_lzma_round_trips_through_xz_liblzma_backend() {
        // Use xz2's LZMA1 (.lzma) encoder as a reference; the
        // dev-dependency the existing xz_liblzma differential
        // suite already uses. Strip the 13-byte .lzma header
        // (5-byte props + 8-byte size) and feed the rest
        // through our LzmaCoder.
        use xz2::stream::{Action, LzmaOptions, Stream};

        let plaintext: Vec<u8> = b"the quick brown fox jumps over the lazy dog "
            .iter()
            .copied()
            .cycle()
            .take(4096)
            .collect();
        let opts = LzmaOptions::new_preset(6).expect("opts");
        let mut enc = Stream::new_lzma_encoder(&opts).expect("encoder");
        let mut encoded = Vec::with_capacity(plaintext.len());
        let _ = enc
            .process_vec(&plaintext, &mut encoded, Action::Finish)
            .expect("encode");
        // Drain.
        loop {
            let pre = enc.total_out();
            let _ = enc
                .process_vec(&[], &mut encoded, Action::Finish)
                .expect("flush");
            if enc.total_out() == pre {
                break;
            }
        }
        assert!(encoded.len() > 13, "lzma container is at least 13 bytes");
        let mut props = [0u8; 5];
        props.copy_from_slice(&encoded[0..5]);
        let payload = encoded[13..].to_vec();

        let mut coder = dispatched(&fake_coder(&[0x03, 0x01, 0x01], &props));
        let mut src = std::io::Cursor::new(payload);
        let mut dst = Vec::new();
        coder
            .decode_one_block(&mut src, &mut dst, plaintext.len() as u64)
            .expect("decodes");
        assert_eq!(dst, plaintext);
    }

    #[test]
    fn dispatch_lzma2_round_trips_uncompressed_chunks() {
        // Hand-build an LZMA2 stream of all-uncompressed chunks
        // and run it through Lzma2Coder. This validates the
        // dispatch + buffering path without leaning on xz2.
        let plaintext: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
        let mut encoded = Vec::new();
        // First chunk: control 0x01 (uncompressed, dict reset),
        // then 16-bit (size - 1) BE, then payload.
        encoded.push(0x01);
        let size_field = (plaintext.len() - 1) as u16;
        encoded.push((size_field >> 8) as u8);
        encoded.push((size_field & 0xFF) as u8);
        encoded.extend_from_slice(&plaintext);
        encoded.push(0x00); // EndOfStream

        // Props byte 0 → dict_size = 4 KiB (smallest LZMA2 dict).
        let mut coder = dispatched(&fake_coder(&[0x21], &[0]));
        let mut src = std::io::Cursor::new(encoded);
        let mut dst = Vec::new();
        coder
            .decode_one_block(&mut src, &mut dst, plaintext.len() as u64)
            .expect("decodes");
        assert_eq!(dst, plaintext);
    }

    #[test]
    fn dispatch_unknown_id_is_unsupported() {
        match dispatch(&fake_coder(&[0x04, 0x02, 0x02], &[])) {
            Err(CoderError::UnsupportedFeature { feature }) => {
                assert!(feature.contains("04:02:02"), "got {feature}");
            }
            Ok(_) => panic!("expected UnsupportedFeature, got Ok"),
            Err(other) => panic!("expected UnsupportedFeature, got {other:?}"),
        }
    }

    #[test]
    fn bind_pair_struct_hosts_indices() {
        // Cheap smoke test that the §3 BindPair re-export
        // remains in scope (so future phases that build coder
        // chains in tests don't have to re-import).
        let bp = BindPair {
            in_index: 1,
            out_index: 0,
        };
        assert_eq!((bp.in_index, bp.out_index), (1, 0));
    }
}
