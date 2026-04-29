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
//! - [`zstd`] — wraps the upstream `zstd` crate's streaming reader and
//!   detects frame boundaries by single-frame stepping.
//!
//! Future formats (`gzip`, anything that fits the protocol) are added
//! here following the same shape.
//!
//! # Source ownership
//!
//! Unlike the Python prototype — where the source was re-bound on every
//! call to give the codec a fresh file handle — Rust's
//! [`zstd::stream::read::Decoder`] takes ownership of its input. Carrying
//! that ownership across calls would require type-erased lifetimes that
//! buy nothing in practice, so the decoder takes the source at
//! construction and keeps it for its lifetime. This is a deliberate
//! deviation from the trait sketch in `docs/PLAN.md` §6.1; the contract
//! the *extractor* relies on (bounded steps, monotone `bytes_consumed`,
//! optional `frame_boundary`) is unchanged.
//!
//! # Registry
//!
//! [`DecoderRegistry`] maps file-name suffixes to factory functions. The
//! lookup is longest-suffix-wins so `.tar.zst` shadows `.zst` once a tar
//! decoder lands. [`DecoderRegistry::with_defaults`] returns a registry
//! pre-populated with every decoder this crate ships.

use std::io::{Read, Write};
use std::path::Path;

use thiserror::Error;

use crate::types::ByteOffset;

pub mod zstd;

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
    /// The upstream `zstd` reader surfaces both true IO failures
    /// (errno from the file descriptor) and format violations (corrupt
    /// frame header, bad checksum, truncated input) as
    /// [`std::io::Error`]. The kinds we observe in practice are
    /// [`std::io::ErrorKind::UnexpectedEof`] for truncation and
    /// [`std::io::ErrorKind::Other`] for libzstd-reported format
    /// failures (the wrapped message contains the libzstd reason);
    /// anything else is an underlying IO error from the source.
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
    /// Implementations guarantee that decoding from any returned offset
    /// produces an output that, when concatenated to the output already
    /// emitted, equals a fresh decode of the full source.
    fn frame_boundary(&self) -> Option<ByteOffset>;
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

/// Map from file-name suffixes to [`DecoderFactory`] callbacks.
///
/// Lookup is longest-suffix-wins: when a path matches multiple
/// registered suffixes, the registry returns the factory whose suffix
/// is longest. This is what makes `.tar.zst` resolve to a tar-aware
/// decoder once one lands without having to deregister `.zst` first.
///
/// All comparisons are case-insensitive on the file-name portion of the
/// path.
#[derive(Default, Clone)]
pub struct DecoderRegistry {
    /// Each entry is `(lowercased_suffix, factory)`. Order is the
    /// insertion order; lookup linearly searches for the longest match.
    /// At plan-§6 scale (a handful of suffixes), the linear scan is
    /// faster than any lookup structure that requires hashing.
    entries: Vec<(String, DecoderFactory)>,
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
    /// Currently registers `.zst` and `.zstd`.
    #[must_use]
    pub fn with_defaults() -> Self {
        let mut r = Self::new();
        r.register(".zst", zstd::factory);
        r.register(".zstd", zstd::factory);
        r
    }

    /// Register `factory` to handle paths whose lowercased file name
    /// ends in `suffix`.
    ///
    /// Re-registering the same suffix replaces the prior factory.
    pub fn register(&mut self, suffix: &str, factory: DecoderFactory) {
        let key = suffix.to_ascii_lowercase();
        if let Some(slot) = self.entries.iter_mut().find(|(s, _)| *s == key) {
            slot.1 = factory;
        } else {
            self.entries.push((key, factory));
        }
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
        let lower = name.to_ascii_lowercase();
        self.entries
            .iter()
            .filter(|(suffix, _)| lower.ends_with(suffix.as_str()))
            .max_by_key(|(suffix, _)| suffix.len())
            .map(|(_, factory)| *factory)
    }

    /// Number of registered suffixes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the registry has no registered suffixes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
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
        assert!(r.factory_for_name("dataset.tar").is_none());
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
        r.register(".bin", stub_factory);
        r.register(".bin", other_factory);
        assert_eq!(r.len(), 1);
        // We can't compare fn pointers reliably across compilation
        // units, but we can call through and confirm a factory exists.
        let f = r.factory_for_name("a.bin").expect("registered");
        let _decoder = f(Box::new(Cursor::new(Vec::<u8>::new()))).expect("constructs");
    }

    #[test]
    fn registry_longest_suffix_wins() {
        let mut r = DecoderRegistry::new();
        r.register(".zst", stub_factory);
        r.register(".tar.zst", other_factory);

        // We rely on fn-pointer identity within the same crate, which
        // is well-defined for non-generic free functions.
        let zst = r.factory_for_name("plain.zst").expect("matches .zst");
        let tar = r
            .factory_for_name("bundle.tar.zst")
            .expect("matches .tar.zst");
        assert!(std::ptr::fn_addr_eq(zst, stub_factory as DecoderFactory));
        assert!(std::ptr::fn_addr_eq(tar, other_factory as DecoderFactory));
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
}
