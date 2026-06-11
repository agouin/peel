//! Streaming decoders for compressed source streams.
//!
//! A decoder consumes bytes from an opaque [`std::io::Read`] source — in
//! production this is the partial sparse file the download workers are
//! filling — and writes the decompressed output into a sink that
//! implements [`std::io::Write`]. The protocol that ties extraction
//! together is small and deliberately format-agnostic:
//!
//! - [`StreamingDecoder::decode_step`] performs *bounded* work each call
//!   so the extractor can interleave hole-punching with decoding rather
//!   than blocking until EOF.
//! - [`StreamingDecoder::bytes_consumed`] is a conservative high-water
//!   mark in the source: every byte before that offset has already been
//!   processed and will never be re-read. This is the input the puncher
//!   trims behind, so under-reporting is safe but over-reporting is
//!   catastrophic.
//! - [`StreamingDecoder::frame_boundary`] returns the offset *immediately
//!   after* the most recently completed frame, when the underlying format
//!   admits the notion. The coordinator uses this to align checkpoints
//!   with format-level restart points: resuming from a frame boundary
//!   produces byte-identical output to a clean run.
//!
//! Concrete implementations live in submodules:
//!
//! - [`zstd`] — hand-rolled pure-Rust zstd decoder
//!   (`internal/PLAN_zstd_block_decoder.md`) with per-block mid-frame
//!   restart points.
//! - [`identity`] — passthrough decoder for archive formats that have
//!   no compression layer (uncompressed `.tar`).
//! - [`xz`] — re-export of [`xz_native`], the hand-rolled pure-
//!   Rust xz / LZMA decoder (`internal/PLAN_xz_block_decoder.md`)
//!   with per-LZMA2-chunk mid-Block restart points.
//! - [`xz_native`] — implementation of the hand-rolled xz
//!   decoder. The `xz` re-export is the public surface; only
//!   tests reach into `xz_native::*` directly.
//! - [`lz4`] — hand-rolls the LZ4 Frame Format, decodes each block
//!   through [`lz4_native`], and exposes per-block frame boundaries
//!   (`internal/PLAN_v2.md` §4 / `internal/PLAN_lz4_block_decoder.md`).
//! - [`lz4_native`] — the hand-rolled LZ4 block decoder [`lz4`] feeds
//!   each compressed block into; replaces the former `lz4_flex`
//!   runtime dependency.
//!
//! Future formats (`gzip`, anything that fits the protocol) are added
//! here following the same shape.
//!
//! # Source ownership
//!
//! Unlike the Python prototype — where the source was re-bound on every
//! call to give the codec a fresh file handle — every in-tree decoder
//! takes ownership of its input at construction and keeps it for its
//! lifetime. This is a deliberate deviation from the trait sketch in
//! `internal/PLAN.md` §6.1; the contract the *extractor* relies on
//! (bounded steps, monotone `bytes_consumed`, optional
//! `frame_boundary`) is unchanged.
//!
//! # Registry
//!
//! [`DecoderRegistry`] maps formats to factory functions through three
//! parallel lookups: file-name **suffix**, magic-byte **prefix**, and
//! human-readable **format name** (used by `--format <name>`). Suffix
//! and magic lookups both follow a longest-match-wins rule so
//! `.tar.zst` shadows `.zst` and a more specific magic shadows a less
//! specific one. [`DecoderRegistry::with_defaults`] returns a registry
//! pre-populated with every decoder this crate ships.

use std::io::{Read, Write};
use std::path::Path;

use thiserror::Error;

use crate::types::ByteOffset;

// Tar (identity / passthrough) is the always-on substrate: no
// compression layer, no dependencies, tiny. Every other format
// is gated behind its `peel` Cargo feature; with the feature
// disabled the registry registers a diagnostic stub against the
// format's suffix + magic so the user sees a precise "compiled
// without `<feature>` feature" message instead of the generic
// "unknown format". See `internal/PLAN_rar.md` §0.5 for the
// original rationale (which now applies uniformly).
pub mod identity;

#[cfg(feature = "gzip")]
pub mod gzip;
#[cfg(feature = "lz4")]
pub mod lz4;
#[cfg(feature = "sevenz")]
pub mod sevenz;
#[cfg(feature = "xz")]
pub mod xz;
#[cfg(feature = "xz")]
pub mod xz_liblzma;
#[cfg(feature = "zstd")]
pub mod zstd;

// Hand-rolled DEFLATE decoder (`internal/PLAN_deflate_block_decoder.md`).
// Gated under the `gzip` feature: standalone `.gz` / `.tar.gz`
// extraction is the externally visible consumer, and the `zip`
// and `sevenz` container features pull in `gzip` so their
// DEFLATE entry / coder paths compile alongside.
#[cfg(feature = "gzip")]
pub mod deflate_native;

// Hand-rolled bzip2 decoder (`internal/PLAN_bz2_support.md`).
#[cfg(feature = "bzip2")]
pub mod bzip2_native;

// Hand-rolled LZ4 block decoder (`internal/PLAN_lz4_block_decoder.md`).
// `decode::lz4` drives the LZ4 Frame Format and feeds each block's
// compressed payload here, replacing the former `lz4_flex` runtime dep.
#[cfg(feature = "lz4")]
pub mod lz4_native;

// Hand-rolled RAR5 decoder (`internal/PLAN_rar5_decoder.md`). Gated
// behind the `rar` Cargo feature alongside the rest of the RAR5
// module tree (`internal/PLAN_rar.md` §0.5). Phase A1 ships the
// MSB-first bitstream reader; subsequent phases land the Huffman /
// LZSS / filter VM / PPMd-II layers and the integration trait.
#[cfg(feature = "rar")]
pub mod rar_native;

// Hand-rolled PPMd-II decoder (`internal/PLAN_rar3.md` §B). Sibling of
// `rar_native` so it can be reused by the legacy RAR decoder
// (§B's first consumer), by hypothetical PPMd-encoded RAR5
// archives (`O.RAR.PPM5` follow-on), and by 7z's PPMd-II method.
// Round-one ships the range coder (§B0); subsequent phases land
// the sub-allocator, context tree, and the symbol-decode loop.
#[cfg(feature = "rar")]
pub mod ppmd2;

// Hand-rolled legacy RAR (RAR3 / RAR4) decompression pipeline
// (`internal/PLAN_rar3.md` §C). Sibling of `rar_native` and `ppmd2`;
// the §A2b pipeline dispatches here on the legacy signature.
// §C0 scaffolds the module entry; subsequent sub-phases land the
// bitstream / Huffman / dictionary / LZ block dispatcher / RarVM
// layers and the PPMd-II bridge for `m=4` / `m=5` entries.
#[cfg(feature = "rar")]
pub mod rar_legacy;

/// Status returned by [`StreamingDecoder::decode_step`].
///
/// Does not indicate whether *any* output was produced this step;
/// implementations may legitimately make progress on the input without
/// emitting decoded bytes (for example, while consuming a frame header).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DecodeStatus {
    /// The decoder believes more input remains and the caller should
    /// keep stepping.
    MoreData,
    /// The decoder has cleanly finished the source. Subsequent calls to
    /// [`StreamingDecoder::decode_step`] will keep returning `Eof`
    /// without further side effects.
    Eof,
}

/// Errors produced by streaming decoders and their factories.
///
/// The variants are deliberately specific: the coordinator distinguishes
/// "the source stream was malformed" from "the sink rejected a write"
/// when deciding whether to surface a transient retry or a hard failure.
#[derive(Debug, Error)]
pub enum DecodeError {
    /// Reading from the source or interpreting its bytes failed.
    ///
    /// In-tree decoders surface both true IO failures (errno from the
    /// file descriptor) and format violations (corrupt frame header,
    /// bad checksum, truncated input) as [`std::io::Error`]. The kinds
    /// we observe in practice are [`std::io::ErrorKind::UnexpectedEof`]
    /// for truncation and [`std::io::ErrorKind::Other`] for
    /// format-decoder-reported failures (the wrapped message names the
    /// reason); anything else is an underlying IO error from the source.
    #[error("decoder failed after consuming {consumed} bytes from source")]
    Read {
        /// Number of source bytes the decoder had consumed when the
        /// error surfaced. Useful for log correlation and resume hints.
        consumed: u64,
        /// The underlying error preserved for [`std::error::Error::source`].
        #[source]
        source: std::io::Error,
    },

    /// The decoder's sink rejected a write.
    #[error("sink write failed during decode")]
    Write(#[source] std::io::Error),

    /// Constructing the decoder failed before any bytes were consumed.
    /// This is its own variant because `consumed = 0` would otherwise be
    /// indistinguishable from a corrupt first frame.
    #[error("decoder construction failed")]
    Construct(#[source] std::io::Error),

    /// `PLAN_responsiveness.md` §3.2: a saved decoder-state blob was
    /// supplied with a `start_offset` that disagrees with the source
    /// cursor the blob captured. Surfacing this as its own variant
    /// (rather than as a downstream `block size too large` /
    /// `bad magic` error from the codec internals) gives the
    /// coordinator a clean signal that the failure is at the resume
    /// seam itself: either the saved cursor was wrong when the blob
    /// was written, the source bytes shifted between runs, or the
    /// caller seeded the wrong offset.
    #[error(
        "decoder resume seam mismatch: blob captured cursor {expected} \
         but resume() was seeded with cursor {actual}"
    )]
    ResumeMismatch {
        /// Cursor the saved blob says it was captured at.
        expected: u64,
        /// Cursor the caller seeded the resumed decoder with.
        actual: u64,
    },
}

/// A forward-only decoder over a compressed byte stream.
///
/// Implementations are `Send` so the extractor can run them on a
/// dedicated worker thread without `Arc<Mutex<…>>` plumbing.
pub trait StreamingDecoder: Send {
    /// Pull bounded input from the source and push decoded output to
    /// `sink`.
    ///
    /// Implementations should bound the work performed per call (the
    /// in-tree zstd implementation reads at most one ~1 MiB output
    /// chunk) so the coordinator can interleave hole-punching and
    /// checkpoint writes with decoding.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::Read`] if the source surfaces an IO or
    /// format error, [`DecodeError::Write`] if writing to `sink` fails,
    /// or [`DecodeError::Construct`] only on the very first call when
    /// the underlying decoder reported a setup failure that was
    /// deferred from the constructor.
    fn decode_step(&mut self, sink: &mut dyn Write) -> Result<DecodeStatus, DecodeError>;

    /// Conservative high-water mark in the source.
    ///
    /// Every byte before the returned offset has already been processed
    /// by the decoder and will never be re-read. Punching the source up
    /// to this offset is therefore safe; punching past it is not.
    /// Implementations must return values that are monotonically
    /// non-decreasing across the lifetime of the decoder.
    fn bytes_consumed(&self) -> ByteOffset;

    /// Offset immediately after the most recently completed frame, if
    /// the format admits the notion.
    ///
    /// Returns `None` until the first frame completes, then transitions
    /// monotonically as later frame boundaries are observed.
    /// Implementations guarantee that decoding from any returned offset,
    /// **paired with the [`Self::decoder_state`] snapshot taken in the
    /// same step**, produces an output that, when concatenated to the
    /// output already emitted, equals a fresh decode of the full
    /// source. When `decoder_state()` returns `None` at the same step,
    /// the offset alone is restartable via the format's normal factory
    /// (the contract every in-tree decoder upholds today *except* at
    /// `lz4` and `zstd` mid-frame block boundaries, which require the
    /// `decoder_state` blob).
    fn frame_boundary(&self) -> Option<ByteOffset>;

    /// Append the resume blob's bytes directly to `out` and return
    /// `true` when this boundary needs more than the offset alone
    /// to resume cleanly, or `false` when the offset alone
    /// suffices (and `out` was left untouched).
    ///
    /// Returning `false` is the default for end-of-frame boundaries
    /// in every container format we ship (zstd frame end, xz Stream
    /// end, gzip member end, lz4 frame EndMark): a freshly
    /// constructed decoder reading the source from `frame_boundary`
    /// onward produces byte-identical output to a clean run.
    ///
    /// Returning `true` covers mid-frame boundaries (today `lz4`,
    /// `zstd`, `xz_native`, and the resume-equipped `deflate_native`
    /// path). The bytes appended to `out` are opaque to the rest of
    /// the crate; only the originating decoder module knows the
    /// layout.
    ///
    /// The "into" shape lets the caller (the extractor's checkpoint
    /// observer) thread the blob bytes straight into the
    /// `Checkpoint` body buffer with one memcpy instead of the
    /// previous decoder→Vec→clone→extend chain.
    /// `PLAN_checkpoint_blob_dedup.md` Phase 2.
    fn decoder_state_into(&self, out: &mut Vec<u8>) -> bool {
        let _ = out;
        false
    }

    /// Owned-`Vec` convenience over [`Self::decoder_state_into`].
    ///
    /// Returns `Some(blob)` when the boundary is restart-safe only
    /// if the resuming decoder is seeded with the captured state,
    /// `None` otherwise. Allocates a fresh `Vec`; callers on the
    /// hot path should prefer [`Self::decoder_state_into`].
    fn decoder_state(&self) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(self.decoder_state_size_hint());
        if self.decoder_state_into(&mut out) {
            Some(out)
        } else {
            None
        }
    }

    /// Upper bound on the next [`Self::decoder_state_into`] call's
    /// payload size, in bytes. Lets callers (the streaming-pipeline
    /// observer in particular) pre-reserve capacity on the
    /// `Checkpoint` body buffer so the closure call does not pay
    /// amortized-doubling memcpies as the Vec grows from 0 to
    /// ~9 MiB on `tar.xz` preset 6. The default `0` is safe for
    /// formats whose blob is small (lz4: ~120 B fixed; zstd /
    /// deflate-native: ≤ 64 KiB) — the resulting Vec growth from
    /// the body's pre-decoder_state floor (~bitmap + sink_state)
    /// up to that small cap is one cheap doubling. xz_native
    /// overrides this to return the dict's `recent_len(capacity)`
    /// plus a small overhead.
    /// `PLAN_checkpoint_blob_dedup.md` Phase 2.
    fn decoder_state_size_hint(&self) -> usize {
        0
    }

    /// Inform the decoder of the source-byte offset at which `src`
    /// will deliver its first byte. Called once by the coordinator
    /// immediately after construction.
    ///
    /// The contract on [`Self::bytes_consumed`] / [`Self::frame_boundary`]
    /// is that they return *global* source-stream offsets — the
    /// high-water mark in the underlying source, not the count of
    /// bytes pulled by this decoder instance. For fresh runs the
    /// source starts at 0 and the two coincide; for runs resumed from
    /// a saved [`crate::checkpoint::Checkpoint::decoder_position`], the
    /// source is positioned at that offset and the decoder's internal
    /// run-local counter must be seeded with it so the global property
    /// is preserved.
    ///
    /// Resume factories ([`DecoderResumeFactory`]) already seed
    /// `bytes_consumed` to `start_offset` at construction; the
    /// override on those decoders is idempotent (calling with the same
    /// offset is a no-op). Decoders constructed via the regular
    /// [`DecoderFactory`] start with `bytes_consumed = 0` and rely on
    /// this hook to align with the source.
    ///
    /// The default no-op is safe only for decoders whose
    /// `bytes_consumed` is naturally zero-relative (i.e. no resume
    /// support and the source is always fresh). All in-tree decoders
    /// override.
    fn set_source_start_offset(&mut self, offset: u64) {
        let _ = offset;
    }
}

/// Type-erased function that constructs a decoder from a source.
///
/// Factories are plain function pointers so the registry stays
/// allocation-free and trivially `Send + Sync`. Implementations should
/// preserve the `consumed = 0` contract on [`DecodeError::Construct`]
/// — i.e., not pull any bytes from the source before reporting
/// construction failure.
pub type DecoderFactory =
    fn(Box<dyn Read + Send>) -> Result<Box<dyn StreamingDecoder>, DecodeError>;

/// Sibling of [`DecoderFactory`] for the resume path: builds a decoder
/// pre-seeded from a previously captured [`StreamingDecoder::decoder_state`]
/// blob.
///
/// `start_offset` is the source byte offset at which the source will
/// deliver its first byte (the saved checkpoint's `decoder_position`).
/// The resume factory must seed `bytes_consumed` to that offset so the
/// decoder's high-water mark stays consistent across the boundary.
///
/// Only formats whose [`StreamingDecoder::decoder_state`] returns
/// `Some(...)` need register a resume factory; for the others the
/// regular [`DecoderFactory`] reading from the saved offset suffices.
pub type DecoderResumeFactory =
    fn(Box<dyn Read + Send>, &[u8], u64) -> Result<Box<dyn StreamingDecoder>, DecodeError>;

/// Diagnostic-stub factories registered when a per-format Cargo
/// feature is disabled.
///
/// Each function shares the [`DecoderFactory`] signature and
/// always fails [`DecodeError::Construct`] with a message naming
/// the missing feature and the rebuild command. The intent — same
/// as `crate::rar::streaming_factory_placeholder` under the
/// disabled-`rar` branch — is that the registry still owns the
/// format's suffix + magic so suffix / magic / `--format <name>`
/// detection resolves the format, and the user sees a precise
/// "compiled without `<feature>` feature" diagnostic instead of
/// the generic "unknown format" error.
///
/// `bzip2` / `gzip` / `lz4` / `xz` / `zstd` are codec stubs that
/// stand in for the real per-codec factory. The `zip` and
/// `sevenz` container stubs live alongside the rest of their
/// always-exported scaffolding in `crate::zip::streaming_factory_placeholder`
/// and `crate::sevenz::streaming_factory_placeholder` so the
/// pipeline-dispatch sentinel and the disabled-feature
/// diagnostic share one entry point.
mod disabled {
    #[allow(unused_imports)]
    use super::{DecodeError, StreamingDecoder};
    #[allow(unused_imports)]
    use std::io::Read;

    macro_rules! disabled_factory {
        ($name:ident, $format:literal, $feature:literal) => {
            #[cfg(not(feature = $feature))]
            pub fn $name(
                _src: Box<dyn Read + Send>,
            ) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
                Err(DecodeError::Construct(std::io::Error::other(concat!(
                    "this build of `peel` was compiled without the `",
                    $feature,
                    "` feature; rebuild with default features (or `--features ",
                    $feature,
                    "`) to extract ",
                    $format,
                    " archives",
                ))))
            }
        };
    }

    disabled_factory!(zstd_factory, "zstd (.zst / .tar.zst)", "zstd");
    disabled_factory!(xz_factory, "xz / lzma (.xz / .tar.xz)", "xz");
    disabled_factory!(lz4_factory, "LZ4 (.lz4 / .tar.lz4)", "lz4");
    disabled_factory!(gzip_factory, "gzip (.gz / .tar.gz)", "gzip");
    disabled_factory!(bzip2_factory, "bzip2 (.bz2 / .tar.bz2)", "bzip2");
}

/// Shape of the output a format produces, used by the CLI's unified
/// `-o` resolver (`internal/PLAN_download_modes.md` §1) to validate a
/// user-supplied output path against the format dictated by either
/// the URL suffix or the magic bytes.
///
/// - [`FormatShape::Tree`]: the decoded stream is a directory tree
///   (tar, zip, 7z, rar, or any compressed wrapper around tar —
///   `.tar.zst`, `.tar.xz`, etc.). The CLI requires `-o` to resolve
///   to a directory.
/// - [`FormatShape::Stream`]: the decoded stream is a single byte
///   stream with no archive layer (raw `.zst`, `.xz`, `.lz4`, `.gz`).
///   The CLI requires `-o` to resolve to a file.
///
/// Shape is attached **per suffix entry** so the same factory can
/// serve both shapes: `.zst` registers as Stream and `.tar.zst` as
/// Tree, both pointing at the same zstd factory. For magic
/// detection — which sees only the format-level prefix and cannot
/// peek through a compression layer to a tar header — the registered
/// magic carries the format's default shape (Stream for compression
/// codecs, Tree for tar / zip / 7z / rar).
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum FormatShape {
    /// Decoded stream produces a directory tree.
    Tree,
    /// Decoded stream produces a single byte stream.
    Stream,
}

/// A fixed byte sequence at a known offset that uniquely identifies a
/// compressed-archive format.
///
/// Most container formats begin with a magic at offset 0 (zstd, gzip,
/// xz, lz4, zip's local file header); tar lives at offset 257 inside
/// the first 512-byte header block. The registry uses these signatures
/// to identify a format from a downloaded prefix when the URL's suffix
/// is unhelpful (e.g. `https://example.com/download?id=42`) or
/// contradicts the bytes.
#[derive(Debug, Clone, Copy)]
pub struct MagicSignature {
    /// Offset, in bytes, where the signature begins in the source.
    pub offset: u16,
    /// The exact bytes that must appear at `offset`.
    pub bytes: &'static [u8],
}

impl MagicSignature {
    /// Smallest prefix length that fully covers this signature.
    ///
    /// A caller that has read fewer bytes than this cannot evaluate
    /// the signature one way or the other.
    #[must_use]
    pub fn window_required(&self) -> usize {
        self.offset as usize + self.bytes.len()
    }

    /// Whether `prefix` matches this signature.
    ///
    /// Returns `false` if `prefix` is shorter than [`Self::window_required`].
    #[must_use]
    pub fn matches(&self, prefix: &[u8]) -> bool {
        let end = self.window_required();
        prefix.len() >= end && &prefix[self.offset as usize..end] == self.bytes
    }
}

/// Three-way lookup from URL suffix, magic-byte prefix, or
/// human-readable format name to [`DecoderFactory`] callbacks.
///
/// Suffix and magic lookups both follow a longest-match-wins rule:
/// when a name matches multiple registered suffixes the longest
/// suffix wins (so `.tar.zst` shadows `.zst`); when a prefix matches
/// multiple registered magics the longest magic wins. Format-name
/// lookups are exact-match.
///
/// All string comparisons are case-insensitive on the file-name
/// portion of the path / on the format name.
#[derive(Default, Clone)]
pub struct DecoderRegistry {
    /// Each entry is `(lowercased_suffix, shape, factory)`. Order is
    /// the insertion order; lookup linearly searches for the longest
    /// match. At plan-§6 scale (a handful of suffixes), the linear
    /// scan is faster than any lookup structure that requires hashing.
    /// `shape` is the [`FormatShape`] dictated by the suffix — the
    /// same factory may register under two suffixes with different
    /// shapes (e.g. zstd's `.zst` → Stream and `.tar.zst` → Tree);
    /// shape lookup follows the same longest-match-wins rule as
    /// factory lookup so `.tar.zst` shadows `.zst`.
    suffix_entries: Vec<(String, FormatShape, DecoderFactory)>,
    /// Each entry is `(magic_signature, shape, factory)`. Same
    /// linear-scan rationale as `suffix_entries`. `shape` is the
    /// format's default — magic detection sees only the outer
    /// compression layer and cannot peek through to a tar header, so
    /// compression codecs register their magic as
    /// [`FormatShape::Stream`] while archive containers (tar, zip,
    /// 7z, rar) register theirs as [`FormatShape::Tree`].
    magic_entries: Vec<(MagicSignature, FormatShape, DecoderFactory)>,
    /// Each entry is `(lowercased_name, default_shape, factory)`.
    /// Used by the `--format <name>` CLI override path. `default_shape`
    /// is the shape implied when the user passes only a format name
    /// and no path-shape hint; the resolver may still let a
    /// trailing-slash `-o` path override this for codecs whose
    /// factory works in either shape.
    name_entries: Vec<(String, FormatShape, DecoderFactory)>,
    /// Optional resume-factory companion to `name_entries`. Only
    /// populated for formats whose
    /// [`StreamingDecoder::decoder_state`] returns `Some(...)`
    /// (today: `lz4` and `zstd` mid-frame block boundaries).
    /// Coordinator looks up the resume factory by format name when a
    /// checkpoint carries a `decoder_state` blob; absence means the
    /// regular `factory` is sufficient.
    name_resume_entries: Vec<(String, DecoderResumeFactory)>,
}

impl DecoderRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a registry populated with every decoder shipped by this
    /// crate.
    ///
    /// Currently registers:
    ///
    /// - `"zstd"` — `.zst` / `.zstd` suffixes; magic `28 B5 2F FD` at
    ///   offset 0.
    /// - `"tar"` — `.tar` suffix; POSIX ustar magic `"ustar\0"` and
    ///   legacy old-GNU magic `"ustar  \0"`, both at offset 257
    ///   (inside the first 512-byte tar header block). The decoder is
    ///   the identity passthrough — uncompressed tar streams hand
    ///   their bytes straight through to [`crate::sink::TarSink`].
    /// - `"xz"` — `.xz` / `.tar.xz` suffixes; magic
    ///   `FD 37 7A 58 5A 00` at offset 0. Round-one frame granularity
    ///   is per-`Stream` (see `internal/PLAN_v2.md` §3); the resulting
    ///   decoder hands its bytes straight through to either
    ///   [`crate::sink::RawSink`] (`.xz`) or [`crate::sink::TarSink`]
    ///   (`.tar.xz`) like every other compressed format.
    /// - `"lz4"` — `.lz4` / `.tar.lz4` suffixes; magic
    ///   `04 22 4D 18` at offset 0. Round-one supports
    ///   block-independent frames only (the lz4 CLI's default); see
    ///   [`lz4::Lz4Decoder`] for the full feature matrix.
    /// - `"gzip"` — `.gz` / `.tar.gz` suffixes; magic `1F 8B` at
    ///   offset 0. Frame granularity is per-member (each gzip member
    ///   ends with its own CRC32 + ISIZE trailer and is an
    ///   independent restart point).
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut r = Self::new();
        // Compression codecs default to FormatShape::Stream — their
        // magic identifies the codec, not whether the decoded bytes
        // happen to be tar. The `.tar.<x>` suffix entries are
        // registered as FormatShape::Tree so the unified-`-o`
        // resolver (`internal/PLAN_download_modes.md` §1) demands a
        // directory output for those URLs without needing to peek
        // through the codec.
        // Each compression codec is gated by its per-format Cargo
        // feature; when the feature is off we still register the
        // suffix + magic but point them at a diagnostic stub from
        // [`disabled`] so the user sees a precise
        // "compiled without `<feature>` feature" message instead of
        // the generic "unknown format". See `internal/PLAN_rar.md`
        // §0.5 for the original rationale.
        //
        // The resume-factory companions only register when the
        // matching codec is on — there is nothing to resume against
        // when the codec itself is a stub.
        #[cfg(feature = "zstd")]
        let zstd_factory = zstd::factory;
        #[cfg(not(feature = "zstd"))]
        let zstd_factory = disabled::zstd_factory;
        r.register_format(
            "zstd",
            FormatShape::Stream,
            &[
                (".zst", FormatShape::Stream),
                (".zstd", FormatShape::Stream),
                (".tar.zst", FormatShape::Tree),
                (".tar.zstd", FormatShape::Tree),
            ],
            &[MagicSignature {
                offset: 0,
                bytes: &[0x28, 0xB5, 0x2F, 0xFD],
            }],
            zstd_factory,
        );
        r.register_format(
            "tar",
            FormatShape::Tree,
            &[(".tar", FormatShape::Tree)],
            &[
                MagicSignature {
                    offset: 257,
                    bytes: b"ustar\0",
                },
                MagicSignature {
                    offset: 257,
                    bytes: b"ustar  \0",
                },
            ],
            identity::factory,
        );
        #[cfg(feature = "xz")]
        let xz_factory = xz::factory;
        #[cfg(not(feature = "xz"))]
        let xz_factory = disabled::xz_factory;
        r.register_format(
            "xz",
            FormatShape::Stream,
            &[(".xz", FormatShape::Stream), (".tar.xz", FormatShape::Tree)],
            &[MagicSignature {
                offset: 0,
                bytes: &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],
            }],
            xz_factory,
        );
        #[cfg(feature = "lz4")]
        let lz4_factory = lz4::factory;
        #[cfg(not(feature = "lz4"))]
        let lz4_factory = disabled::lz4_factory;
        r.register_format(
            "lz4",
            FormatShape::Stream,
            &[
                (".lz4", FormatShape::Stream),
                (".tar.lz4", FormatShape::Tree),
            ],
            &[MagicSignature {
                offset: 0,
                bytes: &[0x04, 0x22, 0x4D, 0x18],
            }],
            lz4_factory,
        );
        // Mid-frame resume hook: lz4 (per-block), zstd (per-block
        // inside a frame), xz (per-LZMA2-chunk inside a Block,
        // since Phase 7 of `internal/PLAN_xz_block_decoder.md` swapped
        // the wrapper out for the hand-rolled decoder), and gzip
        // (per-deflate-block inside a member, since Phase 8 of
        // `internal/PLAN_deflate_block_decoder.md` swapped the
        // `flate2`-based wrapper for the hand-rolled
        // [`deflate_native::gzip`] backend) all stamp
        // `frame_boundary` at points where a fresh decoder cannot
        // pick up from the source offset alone — the captured
        // `decoder_state` blob carries the sliding-window /
        // repeat-offset / probability-table / running-CRC state
        // needed to produce byte-identical output past the
        // boundary. identity (tar) restarts cleanly from
        // `frame_boundary` and so does not need this hook.
        #[cfg(feature = "lz4")]
        r.register_resume_factory("lz4", lz4::resume_factory);
        #[cfg(feature = "zstd")]
        r.register_resume_factory("zstd", zstd::resume_factory);
        #[cfg(feature = "xz")]
        r.register_resume_factory("xz", xz::resume_factory);
        #[cfg(feature = "gzip")]
        r.register_resume_factory("gzip", gzip::resume_factory);
        #[cfg(feature = "gzip")]
        let gzip_factory = gzip::factory;
        #[cfg(not(feature = "gzip"))]
        let gzip_factory = disabled::gzip_factory;
        r.register_format(
            "gzip",
            FormatShape::Stream,
            &[(".gz", FormatShape::Stream), (".tar.gz", FormatShape::Tree)],
            &[MagicSignature {
                offset: 0,
                bytes: &[0x1F, 0x8B],
            }],
            gzip_factory,
        );
        // bzip2 (`internal/PLAN_bz2_support.md`). The 3-byte magic
        // `42 5A 68` (`BZh`) is shared by every bzip2 stream; the
        // level byte that follows (`'1'..='9'`) is validated by the
        // decoder constructor on the first `decode_step` rather than
        // baked into the registered magic (the alternative of
        // registering nine variants of the magic would add no
        // discrimination beyond what the decoder does anyway).
        // Round-one ships only the standalone format; the zip-method-
        // 12 + 7z-coder-0x040202 integrations are tracked in
        // `OPTIMIZATIONS.md §O.8b` / §O.32e.
        #[cfg(feature = "bzip2")]
        let bzip2_factory = bzip2_native::factory;
        #[cfg(not(feature = "bzip2"))]
        let bzip2_factory = disabled::bzip2_factory;
        r.register_format(
            "bzip2",
            FormatShape::Stream,
            &[
                (".bz2", FormatShape::Stream),
                (".tar.bz2", FormatShape::Tree),
                (".tbz2", FormatShape::Tree),
                (".tbz", FormatShape::Tree),
            ],
            &[MagicSignature {
                offset: 0,
                bytes: &[0x42, 0x5A, 0x68],
            }],
            bzip2_factory,
        );
        #[cfg(feature = "bzip2")]
        r.register_resume_factory("bzip2", bzip2_native::resume::resume_factory);
        // ZIP doesn't use the streaming-decoder loop — see
        // `internal/PLAN_v2.md` §5 and `crate::zip::streaming_factory_placeholder`.
        // The registry entry exists so suffix / magic / format-name
        // detection (and the --format / --force-format-from-magic
        // CLI overrides) resolve `.zip` archives the same way the
        // streaming formats do; the coordinator looks up the
        // resolved factory's name and, when it matches
        // [`crate::zip::FORMAT_NAME`], dispatches to the ZIP
        // pipeline instead of invoking the factory.
        //
        // Two magic signatures registered: `PK\x03\x04` (the local
        // file header that begins every non-empty zip) and
        // `PK\x05\x06` (the EOCD-only encoding of an empty zip).
        // Zip64-only archives that begin with `PK\x06\x06` are not
        // auto-detected by magic but still extract via the URL
        // suffix or `--format zip`.
        r.register_format(
            crate::zip::FORMAT_NAME,
            FormatShape::Tree,
            &[(".zip", FormatShape::Tree)],
            &[
                MagicSignature {
                    offset: 0,
                    bytes: &[0x50, 0x4B, 0x03, 0x04],
                },
                MagicSignature {
                    offset: 0,
                    bytes: &[0x50, 0x4B, 0x05, 0x06],
                },
            ],
            crate::zip::streaming_factory_placeholder,
        );
        // 7z (`internal/PLAN_7z_support.md` §10). Same pattern as
        // ZIP — the coordinator dispatches to
        // `crate::download::sevenz_pipeline` before the factory
        // is invoked. Magic is the 6-byte `7z¼¯' \x1c`
        // signature at offset 0; suffixes register both `.7z`
        // and `.tar.7z` (the latter is rare in the wild but
        // exists; round-one routes both through the same
        // pipeline and the user runs `tar` on the decoded tree
        // themselves).
        r.register_format(
            crate::sevenz::FORMAT_NAME,
            FormatShape::Tree,
            &[(".7z", FormatShape::Tree), (".tar.7z", FormatShape::Tree)],
            &[MagicSignature {
                offset: 0,
                bytes: &crate::sevenz::SIGNATURE_MAGIC,
            }],
            crate::sevenz::streaming_factory_placeholder,
        );
        // RAR (`internal/PLAN_rar.md` §1 + `internal/PLAN_rar3.md` §A2b).
        // Same shape as ZIP / 7z — the coordinator dispatches to
        // `crate::download::rar_pipeline` before the factory is
        // invoked. Two magics are registered:
        //   * 8-byte `Rar!\x1A\x07\x01\x00` (RAR5)
        //   * 7-byte `Rar!\x1A\x07\x00`     (legacy RAR3 / RAR4)
        // The pipeline's `detect_signature` dispatches between them
        // post-fetch. When the `rar` Cargo feature is disabled the
        // registered factory still owns the `.rar` suffix and both
        // magics but emits a "compiled without `rar` feature"
        // diagnostic.
        #[cfg(feature = "rar")]
        let rar_magics: &[MagicSignature] = &[
            MagicSignature {
                offset: 0,
                bytes: &crate::rar::SIGNATURE_MAGIC,
            },
            MagicSignature {
                offset: 0,
                bytes: &crate::rar::LEGACY_SIGNATURE_MAGIC,
            },
        ];
        #[cfg(not(feature = "rar"))]
        let rar_magics: &[MagicSignature] = &[MagicSignature {
            offset: 0,
            bytes: &crate::rar::SIGNATURE_MAGIC,
        }];
        r.register_format(
            crate::rar::FORMAT_NAME,
            FormatShape::Tree,
            &[(".rar", FormatShape::Tree)],
            rar_magics,
            crate::rar::streaming_factory_placeholder,
        );
        r
    }

    /// Register `factory` to handle paths whose lowercased file name
    /// ends in `suffix`, with `shape` describing whether the suffix
    /// implies a tree-bearing or stream-shaped output.
    ///
    /// Re-registering the same suffix replaces the prior factory and
    /// shape.
    pub fn register(&mut self, suffix: &str, shape: FormatShape, factory: DecoderFactory) {
        let key = suffix.to_ascii_lowercase();
        if let Some(slot) = self.suffix_entries.iter_mut().find(|(s, _, _)| *s == key) {
            slot.1 = shape;
            slot.2 = factory;
        } else {
            self.suffix_entries.push((key, shape, factory));
        }
    }

    /// Register `factory` to handle sources whose first bytes match
    /// `magic`, with `shape` describing the format's default output
    /// shape (Stream for compression codecs, Tree for archive
    /// containers).
    ///
    /// Re-registering the same magic (same offset and same bytes)
    /// replaces the prior factory and shape.
    pub fn register_magic(
        &mut self,
        magic: MagicSignature,
        shape: FormatShape,
        factory: DecoderFactory,
    ) {
        if let Some(slot) = self
            .magic_entries
            .iter_mut()
            .find(|(m, _, _)| m.offset == magic.offset && m.bytes == magic.bytes)
        {
            slot.1 = shape;
            slot.2 = factory;
        } else {
            self.magic_entries.push((magic, shape, factory));
        }
    }

    /// Register `factory` under a human-readable format `name` for
    /// `--format <name>` lookups, with `default_shape` describing the
    /// shape implied when the user passes only a format name.
    ///
    /// Re-registering the same name (case-insensitively) replaces the
    /// prior factory and shape.
    pub fn register_name(
        &mut self,
        name: &str,
        default_shape: FormatShape,
        factory: DecoderFactory,
    ) {
        let key = name.to_ascii_lowercase();
        if let Some(slot) = self.name_entries.iter_mut().find(|(n, _, _)| *n == key) {
            slot.1 = default_shape;
            slot.2 = factory;
        } else {
            self.name_entries.push((key, default_shape, factory));
        }
    }

    /// Convenience: register `factory` against a format name, a list
    /// of `(suffix, shape)` entries, and a list of magic signatures
    /// in one call.
    ///
    /// `name_shape` is the format's default shape (used by the
    /// `--format <name>` override). Each suffix carries its own
    /// shape — the same factory can handle both shapes (e.g. zstd
    /// registers `.zst` as [`FormatShape::Stream`] and `.tar.zst` as
    /// [`FormatShape::Tree`]). All registered magics inherit
    /// `name_shape` because magic detection cannot distinguish a tar
    /// wrapper from a bare stream.
    ///
    /// Each individual registration follows the same replacement
    /// semantics as the targeted single-purpose method.
    pub fn register_format(
        &mut self,
        name: &str,
        name_shape: FormatShape,
        suffixes: &[(&str, FormatShape)],
        magics: &[MagicSignature],
        factory: DecoderFactory,
    ) {
        self.register_name(name, name_shape, factory);
        for (s, shape) in suffixes {
            self.register(s, *shape, factory);
        }
        for m in magics {
            self.register_magic(*m, name_shape, factory);
        }
    }

    /// Register `factory` as the resume entry-point for the format
    /// registered under `name`.
    ///
    /// Only required for formats whose
    /// [`StreamingDecoder::decoder_state`] returns `Some(...)`.
    /// Coordinator code consults this map when a checkpoint carries
    /// a `decoder_state` blob and the run is resuming; absence falls
    /// back to the regular [`Self::factory_for_format_name`] path,
    /// which is correct for every format whose frame boundaries are
    /// restartable from the offset alone.
    ///
    /// Re-registering the same name (case-insensitively) replaces
    /// the prior resume factory.
    pub fn register_resume_factory(&mut self, name: &str, factory: DecoderResumeFactory) {
        let key = name.to_ascii_lowercase();
        if let Some(slot) = self.name_resume_entries.iter_mut().find(|(n, _)| *n == key) {
            slot.1 = factory;
        } else {
            self.name_resume_entries.push((key, factory));
        }
    }

    /// Look up the resume factory registered against `name`, case-
    /// insensitively, if any.
    #[must_use]
    pub fn resume_factory_for_name(&self, name: &str) -> Option<DecoderResumeFactory> {
        let lower = name.to_ascii_lowercase();
        self.name_resume_entries
            .iter()
            .find(|(n, _)| n == &lower)
            .map(|(_, f)| *f)
    }

    /// Return the longest-matching factory for `path`'s file name, if any.
    #[must_use]
    pub fn factory_for_path(&self, path: &Path) -> Option<DecoderFactory> {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())?
            .to_ascii_lowercase();
        self.factory_for_name(&name)
    }

    /// Return the longest-matching factory for the given file name.
    ///
    /// `name` is matched against suffixes case-insensitively.
    #[must_use]
    pub fn factory_for_name(&self, name: &str) -> Option<DecoderFactory> {
        self.suffix_match(name).map(|(_, _, factory)| factory)
    }

    /// Return the longest-matching `(shape, factory)` pair for the
    /// given file name, or `None` if no suffix matches.
    ///
    /// `name` is matched against suffixes case-insensitively. Shape
    /// is taken from the same longest-match entry so a `.tar.zst`
    /// lookup yields [`FormatShape::Tree`] while a `.zst` lookup
    /// yields [`FormatShape::Stream`] even though both resolve to
    /// the zstd factory.
    #[must_use]
    pub fn lookup_by_name(&self, name: &str) -> Option<(FormatShape, DecoderFactory)> {
        self.suffix_match(name)
            .map(|(_, shape, factory)| (shape, factory))
    }

    fn suffix_match(&self, name: &str) -> Option<(&str, FormatShape, DecoderFactory)> {
        let lower = name.to_ascii_lowercase();
        self.suffix_entries
            .iter()
            .filter(|(suffix, _, _)| lower.ends_with(suffix.as_str()))
            .max_by_key(|(suffix, _, _)| suffix.len())
            .map(|(suffix, shape, factory)| (suffix.as_str(), *shape, *factory))
    }

    /// Return the [`FormatShape`] dictated by the longest-matching
    /// suffix for `name`, if any.
    #[must_use]
    pub fn shape_for_name(&self, name: &str) -> Option<FormatShape> {
        self.suffix_match(name).map(|(_, shape, _)| shape)
    }

    /// Return the longest-matching factory for `prefix`, if any of the
    /// registered magics match.
    ///
    /// "Longest" is measured in [`MagicSignature::bytes`] length so
    /// more specific signatures shadow less specific ones (the same
    /// rule as suffix lookup, in spirit).
    #[must_use]
    pub fn factory_for_prefix(&self, prefix: &[u8]) -> Option<DecoderFactory> {
        self.magic_match(prefix).map(|(_, _, factory)| factory)
    }

    /// Return the longest-matching `(shape, factory)` pair for
    /// `prefix`, or `None` if no registered magic matches.
    #[must_use]
    pub fn lookup_by_prefix(&self, prefix: &[u8]) -> Option<(FormatShape, DecoderFactory)> {
        self.magic_match(prefix)
            .map(|(_, shape, factory)| (shape, factory))
    }

    fn magic_match(&self, prefix: &[u8]) -> Option<(&MagicSignature, FormatShape, DecoderFactory)> {
        self.magic_entries
            .iter()
            .filter(|(magic, _, _)| magic.matches(prefix))
            .max_by_key(|(magic, _, _)| magic.bytes.len())
            .map(|(magic, shape, factory)| (magic, *shape, *factory))
    }

    /// Return the factory registered against the given format `name`,
    /// case-insensitively, if any.
    ///
    /// Used by the `--format <name>` CLI override that bypasses both
    /// suffix and magic detection.
    #[must_use]
    pub fn factory_for_format_name(&self, name: &str) -> Option<DecoderFactory> {
        let lower = name.to_ascii_lowercase();
        self.name_entries
            .iter()
            .find(|(n, _, _)| n == &lower)
            .map(|(_, _, factory)| *factory)
    }

    /// Return the default [`FormatShape`] for the given format
    /// `name`, case-insensitively, if any.
    ///
    /// Used by the `--format <name>` CLI override path to validate a
    /// user-supplied `-o` against the chosen format's default shape.
    #[must_use]
    pub fn shape_for_format_name(&self, name: &str) -> Option<FormatShape> {
        let lower = name.to_ascii_lowercase();
        self.name_entries
            .iter()
            .find(|(n, _, _)| n == &lower)
            .map(|(_, shape, _)| *shape)
    }

    /// Largest prefix window any registered magic requires.
    ///
    /// The coordinator uses this to decide how many bytes to wait for
    /// before sniffing — every registered signature can be evaluated
    /// once a buffer of this length has been read.
    #[must_use]
    pub fn max_magic_window(&self) -> usize {
        self.magic_entries
            .iter()
            .map(|(m, _, _)| m.window_required())
            .max()
            .unwrap_or(0)
    }

    /// List of registered format names, in registration order. Used
    /// by error messages that want to suggest valid `--format` values.
    #[must_use]
    pub fn format_names(&self) -> Vec<&str> {
        self.name_entries
            .iter()
            .map(|(n, _, _)| n.as_str())
            .collect()
    }

    /// Reverse-lookup: the registered name (if any) for a given
    /// factory, used to render human-readable diagnostics about
    /// detection mismatches.
    #[must_use]
    pub fn name_for_factory(&self, factory: DecoderFactory) -> Option<&str> {
        self.name_entries
            .iter()
            .find(|(_, _, f)| std::ptr::fn_addr_eq(*f, factory))
            .map(|(n, _, _)| n.as_str())
    }

    /// Number of registered suffixes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.suffix_entries.len()
    }

    /// True if the registry has no registered suffixes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.suffix_entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Cursor;

    /// Minimal decoder used to verify registry plumbing without pulling
    /// in zstd-specific concerns.
    struct StubDecoder;
    impl StreamingDecoder for StubDecoder {
        fn decode_step(&mut self, _sink: &mut dyn Write) -> Result<DecodeStatus, DecodeError> {
            Ok(DecodeStatus::Eof)
        }
        fn bytes_consumed(&self) -> ByteOffset {
            ByteOffset::ZERO
        }
        fn frame_boundary(&self) -> Option<ByteOffset> {
            None
        }
    }

    fn stub_factory(_src: Box<dyn Read + Send>) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
        Ok(Box::new(StubDecoder))
    }

    fn other_factory(_src: Box<dyn Read + Send>) -> Result<Box<dyn StreamingDecoder>, DecodeError> {
        Ok(Box::new(StubDecoder))
    }

    #[test]
    fn registry_starts_empty_by_default() {
        let r = DecoderRegistry::new();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn registry_with_defaults_has_zstd_entries() {
        let r = DecoderRegistry::with_defaults();
        assert!(!r.is_empty());
        assert!(r.factory_for_name("dataset.zst").is_some());
        assert!(r.factory_for_name("dataset.zstd").is_some());
        // `.tar` is also registered now (PLAN_v2 §2). A suffix that no
        // shipping decoder owns still misses.
        assert!(r.factory_for_name("dataset.tar").is_some());
        // `.xz` and `.tar.xz` registered as of PLAN_v2 §3.
        assert!(r.factory_for_name("dataset.xz").is_some());
        assert!(r.factory_for_name("dataset.tar.xz").is_some());
        // `.lz4` and `.tar.lz4` registered as of PLAN_v2 §4.
        assert!(r.factory_for_name("dataset.lz4").is_some());
        assert!(r.factory_for_name("dataset.tar.lz4").is_some());
        // `.zip` registered as of PLAN_v2 §5 (factory is the
        // sentinel `streaming_factory_placeholder` — the coordinator
        // dispatches to the ZIP pipeline before invoking it).
        assert!(r.factory_for_name("release.zip").is_some());
        // `.gz` and `.tar.gz` registered alongside the other
        // streaming formats.
        assert!(r.factory_for_name("dataset.gz").is_some());
        assert!(r.factory_for_name("dataset.tar.gz").is_some());
        // `.bz2` / `.tar.bz2` / `.tbz2` / `.tbz` registered as of
        // `internal/PLAN_bz2_support.md` Phase 9.
        assert!(r.factory_for_name("dataset.bz2").is_some());
        assert!(r.factory_for_name("dataset.tar.bz2").is_some());
        assert!(r.factory_for_name("dataset.tbz2").is_some());
        assert!(r.factory_for_name("dataset.tbz").is_some());
        // A suffix that no shipping decoder owns still misses.
        assert!(r.factory_for_name("dataset.unknownfmt").is_none());
    }

    #[test]
    fn registry_lookup_is_case_insensitive() {
        let r = DecoderRegistry::with_defaults();
        assert!(r.factory_for_name("DATASET.ZST").is_some());
        assert!(r.factory_for_name("Dataset.ZsT").is_some());
    }

    #[test]
    fn registry_re_registering_replaces_factory() {
        let mut r = DecoderRegistry::new();
        r.register(".bin", FormatShape::Stream, stub_factory);
        r.register(".bin", FormatShape::Stream, other_factory);
        assert_eq!(r.len(), 1);
        // We can't compare fn pointers reliably across compilation
        // units, but we can call through and confirm a factory exists.
        let f = r.factory_for_name("a.bin").expect("registered");
        let _decoder = f(Box::new(Cursor::new(Vec::<u8>::new()))).expect("constructs");
    }

    #[test]
    fn registry_longest_suffix_wins() {
        let mut r = DecoderRegistry::new();
        r.register(".zst", FormatShape::Stream, stub_factory);
        r.register(".tar.zst", FormatShape::Tree, other_factory);

        // We rely on fn-pointer identity within the same crate, which
        // is well-defined for non-generic free functions.
        let zst = r.factory_for_name("plain.zst").expect("matches .zst");
        let tar = r
            .factory_for_name("bundle.tar.zst")
            .expect("matches .tar.zst");
        assert!(std::ptr::fn_addr_eq(zst, stub_factory as DecoderFactory));
        assert!(std::ptr::fn_addr_eq(tar, other_factory as DecoderFactory));
        // Shape lookup uses the same longest-match rule.
        assert_eq!(r.shape_for_name("plain.zst"), Some(FormatShape::Stream));
        assert_eq!(r.shape_for_name("bundle.tar.zst"), Some(FormatShape::Tree));
    }

    #[test]
    fn registry_lookup_misses_when_no_suffix_matches() {
        let r = DecoderRegistry::with_defaults();
        assert!(r.factory_for_name("plain.txt").is_none());
        assert!(r.factory_for_name("noextension").is_none());
    }

    #[test]
    fn registry_factory_for_path_uses_basename_only() {
        let r = DecoderRegistry::with_defaults();
        let path = std::path::Path::new("/some/dir/archive.zst");
        assert!(r.factory_for_path(path).is_some());

        // A directory ending in a known suffix must not match: paths
        // without a file name are not matchable.
        let bare = std::path::Path::new("/");
        assert!(r.factory_for_path(bare).is_none());
    }

    #[test]
    fn magic_signature_matches_only_with_full_window() {
        let zstd_magic = MagicSignature {
            offset: 0,
            bytes: &[0x28, 0xB5, 0x2F, 0xFD],
        };
        assert_eq!(zstd_magic.window_required(), 4);
        assert!(!zstd_magic.matches(&[]));
        assert!(!zstd_magic.matches(&[0x28, 0xB5, 0x2F]));
        assert!(zstd_magic.matches(&[0x28, 0xB5, 0x2F, 0xFD]));
        assert!(zstd_magic.matches(&[0x28, 0xB5, 0x2F, 0xFD, 0xAA]));
        assert!(!zstd_magic.matches(&[0x1F, 0x8B, 0x00, 0x00]));
    }

    #[test]
    fn magic_signature_with_offset_skips_leading_bytes() {
        // Tar's `ustar\0` lives at offset 257 inside the first 512-byte
        // header block. A short prefix can't satisfy it; a long-enough
        // prefix with the right pattern can.
        let tar_magic = MagicSignature {
            offset: 257,
            bytes: b"ustar\0",
        };
        assert_eq!(tar_magic.window_required(), 263);
        assert!(!tar_magic.matches(&[0u8; 100]));
        let mut block = vec![0u8; 512];
        block[257..263].copy_from_slice(b"ustar\0");
        assert!(tar_magic.matches(&block));
    }

    #[test]
    fn registry_with_defaults_registers_zstd_magic_and_format_name() {
        let r = DecoderRegistry::with_defaults();
        let prefix = [0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00];
        assert!(r.factory_for_prefix(&prefix).is_some());
        // gzip's `1F 8B` magic now resolves to the gzip factory.
        assert!(r.factory_for_prefix(&[0x1F, 0x8B, 0x00, 0x00]).is_some());
        assert!(r.factory_for_format_name("zstd").is_some());
        assert!(r.factory_for_format_name("ZSTD").is_some());
        assert!(r.factory_for_format_name("gzip").is_some());
        // `bzip2` registered as of `internal/PLAN_bz2_support.md`
        // Phase 9; magic `42 5A 68` resolves to bzip2 too.
        assert!(r.factory_for_format_name("bzip2").is_some());
        assert!(r.factory_for_prefix(&[0x42, 0x5A, 0x68, 0x39]).is_some());
        // A format name no shipping decoder owns still misses.
        assert!(r.factory_for_format_name("nonexistent_format").is_none());
    }

    #[test]
    fn registry_factory_for_prefix_picks_longest_magic() {
        // Two stub formats that share the same prefix start; the longer
        // (more specific) signature should win.
        let mut r = DecoderRegistry::new();
        r.register_magic(
            MagicSignature {
                offset: 0,
                bytes: &[0xAA, 0xBB],
            },
            FormatShape::Stream,
            stub_factory,
        );
        r.register_magic(
            MagicSignature {
                offset: 0,
                bytes: &[0xAA, 0xBB, 0xCC, 0xDD],
            },
            FormatShape::Stream,
            other_factory,
        );

        let chosen = r
            .factory_for_prefix(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE])
            .expect("longer matches");
        assert!(std::ptr::fn_addr_eq(
            chosen,
            other_factory as DecoderFactory
        ));

        // A prefix that only satisfies the shorter signature falls back
        // to the shorter factory.
        let chosen = r
            .factory_for_prefix(&[0xAA, 0xBB, 0x00])
            .expect("shorter matches");
        assert!(std::ptr::fn_addr_eq(chosen, stub_factory as DecoderFactory));
    }

    #[test]
    fn registry_re_registering_magic_replaces_factory() {
        let magic = MagicSignature {
            offset: 0,
            bytes: &[0x01, 0x02, 0x03],
        };
        let mut r = DecoderRegistry::new();
        r.register_magic(magic, FormatShape::Stream, stub_factory);
        r.register_magic(magic, FormatShape::Stream, other_factory);
        let chosen = r
            .factory_for_prefix(&[0x01, 0x02, 0x03, 0x04])
            .expect("registered");
        assert!(std::ptr::fn_addr_eq(
            chosen,
            other_factory as DecoderFactory
        ));
        // No accidental duplicate left in the magic vector.
        assert_eq!(r.magic_entries.len(), 1);
    }

    #[test]
    fn registry_max_magic_window_picks_largest_offset_plus_len() {
        let mut r = DecoderRegistry::new();
        r.register_magic(
            MagicSignature {
                offset: 0,
                bytes: &[0xAA; 4],
            },
            FormatShape::Stream,
            stub_factory,
        );
        assert_eq!(r.max_magic_window(), 4);
        r.register_magic(
            MagicSignature {
                offset: 257,
                bytes: b"ustar\0",
            },
            FormatShape::Tree,
            other_factory,
        );
        assert_eq!(r.max_magic_window(), 263);
    }

    #[test]
    fn registry_max_magic_window_is_zero_when_no_magic_registered() {
        let r = DecoderRegistry::new();
        assert_eq!(r.max_magic_window(), 0);
    }

    #[test]
    fn registry_register_format_populates_all_three_maps() {
        let mut r = DecoderRegistry::new();
        r.register_format(
            "stub",
            FormatShape::Stream,
            &[(".stub", FormatShape::Stream), (".s2", FormatShape::Stream)],
            &[MagicSignature {
                offset: 0,
                bytes: &[0xDE, 0xAD],
            }],
            stub_factory,
        );
        assert!(r.factory_for_format_name("stub").is_some());
        assert!(r.factory_for_format_name("STUB").is_some());
        assert!(r.factory_for_name("a.stub").is_some());
        assert!(r.factory_for_name("a.s2").is_some());
        assert!(r.factory_for_prefix(&[0xDE, 0xAD, 0x00]).is_some());
        // Shape lookup mirrors the per-entry shape passed at registration.
        assert_eq!(r.shape_for_name("a.stub"), Some(FormatShape::Stream));
        assert_eq!(r.shape_for_format_name("stub"), Some(FormatShape::Stream));
    }

    #[test]
    fn registry_with_defaults_assigns_shape_per_suffix() {
        // The same compression factory registers under both a
        // stream-shaped suffix (e.g. `.zst`) and a tree-shaped wrapper
        // suffix (e.g. `.tar.zst`); shape lookup respects the
        // longest-match-wins rule even when the factory is identical.
        let r = DecoderRegistry::with_defaults();
        assert_eq!(r.shape_for_name("foo.zst"), Some(FormatShape::Stream));
        assert_eq!(r.shape_for_name("foo.tar.zst"), Some(FormatShape::Tree));
        assert_eq!(r.shape_for_name("foo.xz"), Some(FormatShape::Stream));
        assert_eq!(r.shape_for_name("foo.tar.xz"), Some(FormatShape::Tree));
        assert_eq!(r.shape_for_name("foo.gz"), Some(FormatShape::Stream));
        assert_eq!(r.shape_for_name("foo.tar.gz"), Some(FormatShape::Tree));
        assert_eq!(r.shape_for_name("foo.lz4"), Some(FormatShape::Stream));
        assert_eq!(r.shape_for_name("foo.tar.lz4"), Some(FormatShape::Tree));
        // bzip2: same Stream / Tree split as the other compression
        // codecs (`internal/PLAN_bz2_support.md` Phase 9).
        assert_eq!(r.shape_for_name("foo.bz2"), Some(FormatShape::Stream));
        assert_eq!(r.shape_for_name("foo.tar.bz2"), Some(FormatShape::Tree));
        assert_eq!(r.shape_for_name("foo.tbz2"), Some(FormatShape::Tree));
        assert_eq!(r.shape_for_name("foo.tbz"), Some(FormatShape::Tree));
        // Archive containers register as Tree at every suffix.
        assert_eq!(r.shape_for_name("foo.tar"), Some(FormatShape::Tree));
        assert_eq!(r.shape_for_name("foo.zip"), Some(FormatShape::Tree));
        assert_eq!(r.shape_for_name("foo.7z"), Some(FormatShape::Tree));
        assert_eq!(r.shape_for_name("foo.rar"), Some(FormatShape::Tree));
        // Unknown suffix → no shape.
        assert_eq!(r.shape_for_name("foo.bin"), None);
    }

    #[test]
    fn registry_with_defaults_format_name_shape_defaults() {
        // `--format <name>` looks up the format's default shape; the
        // resolver pairs it with the user's -o path to validate.
        let r = DecoderRegistry::with_defaults();
        assert_eq!(r.shape_for_format_name("zstd"), Some(FormatShape::Stream));
        assert_eq!(r.shape_for_format_name("xz"), Some(FormatShape::Stream));
        assert_eq!(r.shape_for_format_name("lz4"), Some(FormatShape::Stream));
        assert_eq!(r.shape_for_format_name("gzip"), Some(FormatShape::Stream));
        assert_eq!(r.shape_for_format_name("tar"), Some(FormatShape::Tree));
        assert_eq!(r.shape_for_format_name("zip"), Some(FormatShape::Tree));
        assert_eq!(r.shape_for_format_name("7z"), Some(FormatShape::Tree));
        // Case-insensitive.
        assert_eq!(r.shape_for_format_name("ZSTD"), Some(FormatShape::Stream));
        // `bzip2` registered as of `internal/PLAN_bz2_support.md`
        // Phase 9 with `Stream` as the default shape.
        assert_eq!(r.shape_for_format_name("bzip2"), Some(FormatShape::Stream));
        // Unknown name → None.
        assert_eq!(r.shape_for_format_name("nonexistent_format"), None);
    }

    #[test]
    fn registry_name_for_factory_round_trips() {
        let r = DecoderRegistry::with_defaults();
        let zstd_factory = r.factory_for_format_name("zstd").expect("registered");
        assert_eq!(r.name_for_factory(zstd_factory), Some("zstd"));
    }

    #[test]
    fn registry_format_names_returns_registered_names() {
        let r = DecoderRegistry::with_defaults();
        let names = r.format_names();
        assert!(names.contains(&"zstd"));
        assert!(names.contains(&"tar"));
        assert!(names.contains(&"xz"));
        assert!(names.contains(&"lz4"));
        assert!(names.contains(&"zip"));
        assert!(names.contains(&"7z"));
        assert!(names.contains(&"bzip2"));
    }

    #[test]
    fn registry_with_defaults_registers_sevenz_suffix_and_magic() {
        let r = DecoderRegistry::with_defaults();
        // Suffix lookup, including the longer `.tar.7z` shadow.
        assert!(r.factory_for_name("dataset.7z").is_some());
        assert!(r.factory_for_name("dataset.tar.7z").is_some());
        // Magic detection on the canonical 7z signature.
        let prefix = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04];
        let by_magic = r.factory_for_prefix(&prefix).expect("7z magic registered");
        assert_eq!(r.name_for_factory(by_magic), Some("7z"));
        // Format-name override path.
        let by_name = r.factory_for_format_name("7z").expect("name registered");
        assert!(std::ptr::fn_addr_eq(
            by_name,
            crate::sevenz::streaming_factory_placeholder as DecoderFactory,
        ));
    }

    #[cfg(feature = "lz4")]
    #[test]
    fn registry_with_defaults_registers_lz4_suffix_and_magic() {
        let r = DecoderRegistry::with_defaults();

        let plain = r.factory_for_name("archive.lz4").expect(".lz4 registered");
        let tarred = r
            .factory_for_name("archive.tar.lz4")
            .expect(".tar.lz4 registered");
        assert!(std::ptr::fn_addr_eq(plain, lz4::factory as DecoderFactory));
        assert!(std::ptr::fn_addr_eq(tarred, lz4::factory as DecoderFactory));

        let prefix = [0x04, 0x22, 0x4D, 0x18, 0x00, 0x00, 0x00, 0x00];
        let by_magic = r.factory_for_prefix(&prefix).expect("lz4 magic registered");
        assert_eq!(r.name_for_factory(by_magic), Some("lz4"));

        let by_name = r.factory_for_format_name("lz4").expect("name registered");
        assert!(std::ptr::fn_addr_eq(
            by_name,
            lz4::factory as DecoderFactory
        ));
    }

    #[cfg(all(
        feature = "lz4",
        feature = "zstd",
        feature = "xz",
        feature = "gzip",
        feature = "bzip2",
    ))]
    #[test]
    fn registry_with_defaults_registers_resume_factories_for_lz4_zstd_xz_and_gzip() {
        // lz4 (per-block mid-frame), zstd (per-block mid-frame),
        // xz (per-LZMA2-chunk inside a Block, since Phase 7 of
        // `internal/PLAN_xz_block_decoder.md` swapped the wrapper out
        // for the hand-rolled decoder), and gzip (per-deflate-block
        // inside a member, since Phase 8 of
        // `internal/PLAN_deflate_block_decoder.md` swapped the
        // `flate2`-based wrapper for the hand-rolled
        // [`deflate_native::gzip`] backend) all stamp
        // `frame_boundary` at points whose `decoder_state` blob
        // is required to resume byte-identically. Other formats
        // fall through to the generic `factory(source)` path.
        let r = DecoderRegistry::with_defaults();
        let lz4_resume = r
            .resume_factory_for_name("lz4")
            .expect("lz4 resume registered");
        assert!(std::ptr::fn_addr_eq(
            lz4_resume,
            lz4::resume_factory as DecoderResumeFactory,
        ));
        let zstd_resume = r
            .resume_factory_for_name("zstd")
            .expect("zstd resume registered");
        assert!(std::ptr::fn_addr_eq(
            zstd_resume,
            zstd::resume_factory as DecoderResumeFactory,
        ));
        let xz_resume = r
            .resume_factory_for_name("xz")
            .expect("xz resume registered");
        assert!(std::ptr::fn_addr_eq(
            xz_resume,
            xz::resume_factory as DecoderResumeFactory,
        ));
        let gzip_resume = r
            .resume_factory_for_name("gzip")
            .expect("gzip resume registered");
        assert!(std::ptr::fn_addr_eq(
            gzip_resume,
            gzip::resume_factory as DecoderResumeFactory,
        ));
        let bzip2_resume = r
            .resume_factory_for_name("bzip2")
            .expect("bzip2 resume registered");
        assert!(std::ptr::fn_addr_eq(
            bzip2_resume,
            bzip2_native::resume::resume_factory as DecoderResumeFactory,
        ));
        // Case-insensitive lookup matches the rest of the registry.
        assert!(r.resume_factory_for_name("LZ4").is_some());
        assert!(r.resume_factory_for_name("ZSTD").is_some());
        assert!(r.resume_factory_for_name("XZ").is_some());
        assert!(r.resume_factory_for_name("GZIP").is_some());
        assert!(r.resume_factory_for_name("BZIP2").is_some());

        // identity (tar) and zip restart cleanly from
        // `frame_boundary` and don't need a resume factory.
        for name in ["tar", "zip"] {
            assert!(
                r.resume_factory_for_name(name).is_none(),
                "{name} unexpectedly has a resume factory",
            );
        }
    }

    #[cfg(feature = "xz")]
    #[test]
    fn registry_with_defaults_registers_xz_suffix_and_magic() {
        let r = DecoderRegistry::with_defaults();

        // Suffix lookup, including the longer `.tar.xz` shadowing
        // `.xz`. Both register the same factory, so the assertion is
        // about hit-vs-miss, not factory identity.
        let plain = r.factory_for_name("archive.xz").expect(".xz registered");
        let tarred = r
            .factory_for_name("archive.tar.xz")
            .expect(".tar.xz registered");
        assert!(std::ptr::fn_addr_eq(plain, xz::factory as DecoderFactory));
        assert!(std::ptr::fn_addr_eq(tarred, xz::factory as DecoderFactory));

        // Magic detection on a real xz prefix.
        let prefix = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00, 0x00];
        let by_magic = r.factory_for_prefix(&prefix).expect("xz magic registered");
        assert_eq!(r.name_for_factory(by_magic), Some("xz"));

        // Format-name override path.
        let by_name = r.factory_for_format_name("xz").expect("name registered");
        assert!(std::ptr::fn_addr_eq(by_name, xz::factory as DecoderFactory));

        // Window must accommodate the 6-byte xz magic at offset 0
        // (and the 263-byte tar window already pushed it higher).
        assert!(r.max_magic_window() >= 6);
    }

    #[test]
    fn registry_with_defaults_registers_tar_suffix_and_magics() {
        let r = DecoderRegistry::with_defaults();

        // Suffix lookup.
        assert!(r.factory_for_name("archive.tar").is_some());

        // POSIX ustar magic at offset 257 inside a 512-byte header.
        let mut posix = vec![0u8; 512];
        posix[257..263].copy_from_slice(b"ustar\0");
        posix[263..265].copy_from_slice(b"00");
        let posix_factory = r.factory_for_prefix(&posix).expect("posix matches");
        assert_eq!(r.name_for_factory(posix_factory), Some("tar"));

        // Legacy old-GNU magic at offset 257 — the registry recognizes
        // it as tar even though the parser ultimately rejects it; the
        // user should see a sink-level "malformed header" rather than
        // a registry-level "no decoder".
        let mut old_gnu = vec![0u8; 512];
        old_gnu[257..265].copy_from_slice(b"ustar  \0");
        let old_gnu_factory = r.factory_for_prefix(&old_gnu).expect("old gnu matches");
        assert_eq!(r.name_for_factory(old_gnu_factory), Some("tar"));

        // The format-name lookup picks up the same factory.
        assert!(r.factory_for_format_name("tar").is_some());

        // Magic-window must be ≥ 265 bytes to cover both signatures.
        assert!(r.max_magic_window() >= 265);
    }

    #[test]
    fn registry_with_defaults_tar_does_not_match_random_bytes() {
        // A 512-byte block with no tar magic at 257 should miss.
        let r = DecoderRegistry::with_defaults();
        let buf = vec![0u8; 512];
        assert!(r.factory_for_prefix(&buf).is_none());
    }
}
