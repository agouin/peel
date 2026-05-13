//! Multi-volume archive discovery
//! (`internal/PLAN_multivolume_archives.md` §1).
//!
//! Given a single seed source — a URL or a local file path — resolve
//! the full ordered set of sibling volumes for one of three
//! multi-volume archive formats:
//!
//! | Format | Naming convention                                |
//! |--------|--------------------------------------------------|
//! | RAR5   | `<base>.part<NN>.rar` (variable-width zero-pad)  |
//! | 7z     | `<base>.7z.<NN>` (≥ 3-digit zero-pad)            |
//! | ZIP    | `<base>.z<NN>` siblings + `<base>.zip` (final)   |
//!
//! Discovery is the seam between "user passed one filename" and
//! "the decoder needs the whole logical volume stream." It runs
//! before any decoder is constructed, so the user gets early,
//! format-specific errors about missing volumes rather than a
//! generic corruption signal halfway through the run.
//!
//! # Modes
//!
//! - **Local**: pattern-match the seed's basename, probe each
//!   sibling path via `metadata(2)`. End of sequence is the first
//!   `ENOENT`.
//! - **HTTP**: pattern-match the seed URL's path basename, probe
//!   each sibling URL with a `HEAD` request. End of sequence is the
//!   first 404 (other non-2xx statuses surface as errors).
//!
//! Both modes refuse to mix transports — the per-format functions
//! take either a path or a URL, never both. A heterogeneous list is
//! rejected one layer up in the CLI dispatch (the same place
//! [`crate::cli`] already rejects URL + path combinations).
//!
//! # Out of scope (this module)
//!
//! - Per-volume signed URLs whose query string differs across
//!   siblings. The HTTP discovery resolves siblings relative to the
//!   seed URL's path, dropping any query string; users with signed
//!   URLs must supply every volume explicitly on the CLI rather than
//!   relying on auto-discovery.
//! - SFX (self-extracting) prefixes around the first RAR5 volume.
//!   Surfaces upstream as `PatternNotRecognised`.
//! - Reading volumes whose basename pattern does not match the
//!   conventions in the table above; users with non-conforming
//!   filenames pass every volume explicitly.

#![cfg(unix)]

use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::http::{Client, ClientError, Url, UrlError};

/// Multi-volume archive format detected from the seed source's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeKind {
    /// RAR5 multi-volume: `<base>.part<NNNN>.rar`. The width is the
    /// number of digits the seed used (rar produces a width that
    /// scales with the volume count: `partN.rar` for fewer than 10
    /// volumes, `part0001.rar` for 4-digit sets, …).
    Rar5,
    /// 7z multi-volume: `<base>.7z.<NNN>`. The reference CLI always
    /// uses ≥ 3-digit zero-padding.
    SevenZ,
    /// ZIP spanned archive: `<base>.z<NN>` for the leading volumes
    /// (numbered, 2-digit-wide in 7z's reference output) and
    /// `<base>.zip` for the final volume (which holds the EOCD and
    /// the central directory).
    Zip,
}

impl VolumeKind {
    /// Render the kind in user-facing diagnostic strings.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            VolumeKind::Rar5 => "rar5",
            VolumeKind::SevenZ => "7z",
            VolumeKind::Zip => "zip",
        }
    }
}

impl std::fmt::Display for VolumeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parsed multi-volume archive name.
///
/// Carries the *non*-volume portion of the basename (`base`), the
/// detected format, and (for numbered volumes) the volume number
/// plus the zero-pad width the seed used. The ZIP final volume
/// (`<base>.zip`) is signalled by `volume == None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeName {
    /// The portion of the basename before the format-specific
    /// suffix. For `foo.part0003.rar` this is `"foo"`; for
    /// `pruned.tar.7z.012` it is `"pruned.tar"`; for
    /// `archive.zip` it is `"archive"`.
    pub base: String,
    /// The detected format.
    pub kind: VolumeKind,
    /// Numeric volume index parsed from the seed. `None` for the
    /// ZIP final volume (`.zip`); always `Some` for RAR5 / 7z and
    /// for ZIP `.zNN` siblings.
    pub volume: Option<u32>,
    /// Width of the zero-padding the seed used (digit count). For
    /// `part0003.rar` this is `4`; for `7z.012` it is `3`. Zero for
    /// the ZIP final volume.
    pub width: usize,
}

/// Errors surfaced by the discovery functions.
#[derive(Debug, Error)]
pub enum MvError {
    /// The seed's basename did not match any recognised
    /// multi-volume naming pattern.
    #[error(
        "source `{seed}` does not match any multi-volume naming pattern \
         (rar5: `.part<N>.rar`; 7z: `.7z.<NNN>`; zip: `.z<NN>` or final `.zip`)"
    )]
    PatternNotRecognised {
        /// User-visible rendering of the offending source (filename
        /// for local mode, full URL for HTTP mode).
        seed: String,
    },
    /// A volume in `[1, seed.volume]` was missing from the
    /// filesystem / origin. The seed itself exists (the caller
    /// supplied it) but at least one lower-numbered volume does
    /// not.
    #[error(
        "{kind} volume {missing} is missing — discovery walked forward from 1 \
         and stopped before reaching the seed's volume number"
    )]
    MissingVolume {
        /// Format the missing volume belongs to.
        kind: VolumeKind,
        /// Volume index that was not present on disk / origin.
        missing: u32,
    },
    /// ZIP-specific: the trailing `<base>.zip` (which carries the
    /// central directory and EOCD) was not found.
    #[error("ZIP final volume `{path}` is missing — spanned ZIP requires the final `.zip`")]
    FinalVolumeMissing {
        /// Rendering of the missing final volume's name / URL.
        path: String,
    },
    /// HTTP HEAD failed at the transport layer for one of the
    /// probed sibling URLs.
    #[error("HEAD `{url}` failed: {source}")]
    Head {
        /// The URL whose HEAD failed.
        url: String,
        /// Underlying transport error.
        #[source]
        source: ClientError,
    },
    /// HTTP HEAD returned a status that was neither 2xx (success,
    /// volume exists) nor 404 (end of sequence). Examples: 401,
    /// 403, 500.
    #[error("HEAD `{url}` returned unexpected status {status}")]
    UnexpectedStatus {
        /// The URL whose HEAD returned the unexpected status.
        url: String,
        /// HTTP status code returned.
        status: u16,
    },
    /// Local-mode `metadata(2)` failed for a reason other than
    /// `ENOENT` (which marks end-of-sequence).
    #[error("failed to inspect `{path}`: {source}")]
    Io {
        /// Path that could not be inspected.
        path: PathBuf,
        /// Underlying `io::Error`.
        #[source]
        source: std::io::Error,
    },
    /// Discovery walked forward past the safety cap without seeing
    /// a 404 / `ENOENT`. Surfaces when the origin is misconfigured
    /// (always returns 2xx) or the user pointed peel at a
    /// pathologically large volume set; the cap protects against an
    /// infinite probe loop.
    #[error(
        "{kind} discovery exceeded {cap} volumes without observing a missing volume — \
         the origin / filesystem may be misconfigured (every probed sibling returned success)"
    )]
    DiscoveryExceededCap {
        /// Format whose discovery exceeded the cap.
        kind: VolumeKind,
        /// Maximum volume count discovery is willing to walk.
        cap: u32,
    },
    /// A sibling URL constructed from the seed could not be parsed
    /// back into a [`Url`]. Realistically unreachable — the URL
    /// crate's [`Url::join`] returns this for malformed input and
    /// we feed it only basenames we just generated — but surfaced
    /// cleanly rather than panicking.
    #[error("could not construct sibling URL for `{name}`: {source}")]
    BadSiblingUrl {
        /// Sibling basename we tried to attach.
        name: String,
        /// Underlying URL parser error.
        #[source]
        source: UrlError,
    },
}

/// Parse a basename into its volume-name parts, if it matches any
/// recognised multi-volume convention.
///
/// Returns `None` for names that do not match (e.g. `archive.tar.zst`,
/// `foo.rar` with no `.partNN` segment). Matching is case-insensitive
/// on the format suffix (`.RAR`, `.Rar`, `.rar` all accepted).
#[must_use]
pub fn parse_volume_name(basename: &str) -> Option<VolumeName> {
    if let Some(vn) = parse_rar5(basename) {
        return Some(vn);
    }
    if let Some(vn) = parse_7z(basename) {
        return Some(vn);
    }
    if let Some(vn) = parse_zip(basename) {
        return Some(vn);
    }
    None
}

/// Render a numbered volume basename in the same style as the seed.
///
/// Pairs with [`parse_volume_name`]: round-tripping a parsed name
/// through [`format_volume_name`] yields the same basename (modulo
/// case folding on the suffix).
///
/// For [`VolumeKind::Zip`] this always renders a numbered `.zNN`
/// sibling; the final `.zip` volume goes through
/// [`format_zip_final`].
#[must_use]
pub fn format_volume_name(base: &str, kind: VolumeKind, volume: u32, width: usize) -> String {
    let num = format!("{volume:0width$}", width = width.max(1));
    match kind {
        VolumeKind::Rar5 => format!("{base}.part{num}.rar"),
        VolumeKind::SevenZ => format!("{base}.7z.{num}"),
        VolumeKind::Zip => format!("{base}.z{num}"),
    }
}

/// Render the final-volume basename for a spanned ZIP set
/// (`<base>.zip`). Has no analogue for RAR5 / 7z.
#[must_use]
pub fn format_zip_final(base: &str) -> String {
    format!("{base}.zip")
}

/// Maximum volume count any discovery walk will probe before
/// surfacing [`MvError::DiscoveryExceededCap`]. The real-world
/// upper bound for a multi-volume archive is well below this
/// (rar's `-v` per-volume size is typically MiB-to-GiB; a 100k-
/// volume archive would imply a ridiculously small volume size).
/// The cap exists to protect against an origin that returns 2xx
/// for *every* probed sibling — e.g. test mocks that don't model
/// 404 — so a misconfigured server cannot pin discovery in an
/// infinite loop.
pub const DISCOVERY_VOLUME_CAP: u32 = 9_999;

/// Discover the full ordered set of volume paths from a local-mode
/// seed.
///
/// The seed must be an existing regular file; the caller has
/// already validated this (the CLI's [`SourceClassification::Local`]
/// arm rejects non-existent paths before reaching discovery).
///
/// Returns a single-element vector when the seed turns out to be
/// non-multi-volume (e.g. plain `archive.zip` with no `.z01`
/// sibling). Higher layers can treat that case as the legacy
/// single-source path with no further branching.
///
/// # Errors
///
/// - [`MvError::PatternNotRecognised`] if the basename does not
///   match any of the supported conventions.
/// - [`MvError::MissingVolume`] if discovery walked forward from
///   volume 1 and stopped before reaching the seed's recorded
///   volume number (i.e. a lower-numbered volume is absent).
/// - [`MvError::FinalVolumeMissing`] for spanned ZIP where the
///   trailing `.zip` was not found.
/// - [`MvError::Io`] for any non-`ENOENT` `metadata(2)` failure.
pub fn discover_local(seed: &Path) -> Result<Vec<PathBuf>, MvError> {
    let basename = path_basename(seed);
    let parsed = parse_volume_name(basename).ok_or_else(|| MvError::PatternNotRecognised {
        seed: seed.display().to_string(),
    })?;
    let parent = seed
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);

    match parsed.kind {
        VolumeKind::Rar5 | VolumeKind::SevenZ => {
            let seed_volume = parsed.volume.unwrap_or(1);
            let volumes = walk_forward_local(
                &parent,
                &parsed.base,
                parsed.kind,
                parsed.width,
                seed_volume,
            )?;
            Ok(volumes)
        }
        VolumeKind::Zip => discover_zip_local(&parent, parsed, seed),
    }
}

/// Discover the full ordered set of volume URLs from an HTTP-mode
/// seed.
///
/// The `client` is used to issue `HEAD` requests against each
/// candidate sibling URL. End-of-sequence is the first 404; any
/// other non-2xx surfaces as [`MvError::UnexpectedStatus`].
///
/// Returns a single-element vector if the seed turns out to be
/// non-multi-volume after probing — see [`discover_local`].
///
/// # Errors
///
/// - [`MvError::PatternNotRecognised`] if the seed URL's path
///   basename does not match any recognised pattern.
/// - [`MvError::MissingVolume`] if a lower-numbered volume is
///   absent from the origin.
/// - [`MvError::FinalVolumeMissing`] for spanned ZIP where the
///   trailing `.zip` returned 404.
/// - [`MvError::Head`] / [`MvError::UnexpectedStatus`] for any
///   per-volume HEAD failure other than 404.
/// - [`MvError::BadSiblingUrl`] if the constructed sibling URL was
///   rejected by [`Url::join`] (realistically unreachable).
pub fn discover_http(client: &Client, seed: &Url) -> Result<Vec<Url>, MvError> {
    let basename = url_basename(seed);
    let parsed = parse_volume_name(basename).ok_or_else(|| MvError::PatternNotRecognised {
        seed: seed.to_string(),
    })?;

    match parsed.kind {
        VolumeKind::Rar5 | VolumeKind::SevenZ => {
            let seed_volume = parsed.volume.unwrap_or(1);
            walk_forward_http(
                client,
                seed,
                &parsed.base,
                parsed.kind,
                parsed.width,
                seed_volume,
            )
        }
        VolumeKind::Zip => discover_zip_http(client, seed, parsed),
    }
}

// ---- pattern parsers --------------------------------------------------

/// Parse a RAR5 multi-volume basename: `<base>.part<digits>.rar`.
fn parse_rar5(basename: &str) -> Option<VolumeName> {
    // Strip the `.rar` (case-insensitive) suffix first; what
    // remains must end in `.part<digits>` (case-insensitive `.part`).
    let head = strip_suffix_ci(basename, ".rar")?;
    let dot_part = rfind_ascii_ci(head, ".part")?;
    let (base_part, num_part) = head.split_at(dot_part);
    let num_str = &num_part[".part".len()..];
    if num_str.is_empty() || !num_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let volume: u32 = num_str.parse().ok()?;
    Some(VolumeName {
        base: base_part.to_string(),
        kind: VolumeKind::Rar5,
        volume: Some(volume),
        width: num_str.len(),
    })
}

/// Right-most occurrence of `needle` in `haystack`, matching
/// ASCII bytes case-insensitively. Returns the byte offset of the
/// match's start, or `None` if no match exists. `needle` must be
/// ASCII; on non-ASCII input the match is undefined (we only call
/// this with ASCII literals).
fn rfind_ascii_ci(haystack: &str, needle: &str) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    let last_start = h.len() - n.len();
    let mut i = last_start + 1;
    while i > 0 {
        i -= 1;
        if h[i..i + n.len()].eq_ignore_ascii_case(n) {
            return Some(i);
        }
    }
    None
}

/// Parse a 7z multi-volume basename: `<base>.7z.<digits>`.
fn parse_7z(basename: &str) -> Option<VolumeName> {
    let last_dot = basename.rfind('.')?;
    let (head, num_dot) = basename.split_at(last_dot);
    let num_str = &num_dot[1..];
    if num_str.is_empty() || !num_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let base = strip_suffix_ci(head, ".7z")?;
    let volume: u32 = num_str.parse().ok()?;
    Some(VolumeName {
        base: base.to_string(),
        kind: VolumeKind::SevenZ,
        volume: Some(volume),
        width: num_str.len(),
    })
}

/// Parse a ZIP spanned-archive basename: `<base>.z<digits>` or
/// `<base>.zip`.
fn parse_zip(basename: &str) -> Option<VolumeName> {
    if let Some(base) = strip_suffix_ci(basename, ".zip") {
        return Some(VolumeName {
            base: base.to_string(),
            kind: VolumeKind::Zip,
            volume: None,
            width: 0,
        });
    }
    // `.zNN` sibling: ASCII `z` (case-insensitive) followed by
    // digits.
    let last_dot = basename.rfind('.')?;
    let suffix = &basename[last_dot + 1..];
    let bytes = suffix.as_bytes();
    if bytes.is_empty() || !(bytes[0] == b'z' || bytes[0] == b'Z') {
        return None;
    }
    let num_str = &suffix[1..];
    if num_str.is_empty() || !num_str.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let volume: u32 = num_str.parse().ok()?;
    let base = &basename[..last_dot];
    Some(VolumeName {
        base: base.to_string(),
        kind: VolumeKind::Zip,
        volume: Some(volume),
        width: num_str.len(),
    })
}

/// Case-insensitive suffix strip. Returns the prefix on match.
fn strip_suffix_ci<'a>(input: &'a str, suffix: &str) -> Option<&'a str> {
    if input.len() < suffix.len() {
        return None;
    }
    let split = input.len() - suffix.len();
    let (head, tail) = input.split_at(split);
    if tail.eq_ignore_ascii_case(suffix) {
        Some(head)
    } else {
        None
    }
}

// ---- local-mode discovery --------------------------------------------

/// Walk forward over numbered volumes (`{base}.part{N}.rar` or
/// `{base}.7z.{N}`) until the first `ENOENT`. Verify the seed's
/// volume number is in `[1, last_found]`. Capped at
/// [`DISCOVERY_VOLUME_CAP`] to bound the worst case when every
/// probed path appears to exist.
fn walk_forward_local(
    parent: &Path,
    base: &str,
    kind: VolumeKind,
    width: usize,
    seed_volume: u32,
) -> Result<Vec<PathBuf>, MvError> {
    debug_assert!(matches!(kind, VolumeKind::Rar5 | VolumeKind::SevenZ));
    let mut volumes = Vec::new();
    for n in 1..=DISCOVERY_VOLUME_CAP {
        let name = format_volume_name(base, kind, n, width);
        let path = parent.join(&name);
        match path.metadata() {
            Ok(_) => volumes.push(path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if seed_volume == 0 || (seed_volume as usize) > volumes.len() {
                    return Err(MvError::MissingVolume {
                        kind,
                        missing: seed_volume,
                    });
                }
                return Ok(volumes);
            }
            Err(source) => return Err(MvError::Io { path, source }),
        }
    }
    Err(MvError::DiscoveryExceededCap {
        kind,
        cap: DISCOVERY_VOLUME_CAP,
    })
}

/// Spanned-ZIP local discovery.
///
/// The seed may be either a `.zNN` sibling or the final `.zip`.
/// Iterates `.z01..z<N>` until the first `ENOENT`, then probes
/// `<base>.zip`. The final `.zip` is mandatory (that's where the
/// EOCD lives). The returned vector is `[z01, z02, …, zN, zip]` —
/// the order the decoder consumes them.
///
/// A bare `<base>.zip` with no `.z01` sibling is treated as a
/// non-multi-volume zip and surfaces as a single-element vector;
/// the caller (or the format detector) can fall through to the
/// single-source path.
fn discover_zip_local(
    parent: &Path,
    parsed: VolumeName,
    seed: &Path,
) -> Result<Vec<PathBuf>, MvError> {
    let width = if parsed.width == 0 { 2 } else { parsed.width };
    let mut volumes = Vec::new();
    let mut hit_cap = true;
    for n in 1..=DISCOVERY_VOLUME_CAP {
        let name = format_volume_name(&parsed.base, VolumeKind::Zip, n, width);
        let path = parent.join(&name);
        match path.metadata() {
            Ok(_) => volumes.push(path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                hit_cap = false;
                break;
            }
            Err(source) => return Err(MvError::Io { path, source }),
        }
    }
    if hit_cap {
        return Err(MvError::DiscoveryExceededCap {
            kind: VolumeKind::Zip,
            cap: DISCOVERY_VOLUME_CAP,
        });
    }
    let final_name = format_zip_final(&parsed.base);
    let final_path = parent.join(&final_name);
    let final_exists = match final_path.metadata() {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(source) => {
            return Err(MvError::Io {
                path: final_path,
                source,
            })
        }
    };
    if volumes.is_empty() {
        // No `.zNN` siblings: this is a single-volume zip. Return
        // the seed as-is (whether the seed is `.zip` or a stray
        // `.zNN` that has no companions).
        if final_exists {
            return Ok(vec![final_path]);
        }
        // Seed was a `.zNN` sibling with no `.zip` neighbour.
        return Err(MvError::FinalVolumeMissing {
            path: final_path.display().to_string(),
        });
    }
    if !final_exists {
        return Err(MvError::FinalVolumeMissing {
            path: final_path.display().to_string(),
        });
    }
    // Sanity: the seed must be one of the discovered files.
    let seed_canonical = parent.join(path_basename(seed));
    let seed_in_set = volumes.iter().any(|p| p == &seed_canonical) || seed_canonical == final_path;
    if !seed_in_set {
        let seed_volume = parsed.volume.unwrap_or(0);
        return Err(MvError::MissingVolume {
            kind: VolumeKind::Zip,
            missing: seed_volume,
        });
    }
    volumes.push(final_path);
    Ok(volumes)
}

// ---- HTTP-mode discovery ---------------------------------------------

/// HEAD a candidate volume URL. Returns `Some(url)` on 2xx, `None`
/// on 404 (end of sequence), or [`MvError::UnexpectedStatus`] for
/// anything else.
fn head_volume(client: &Client, url: &Url) -> Result<Option<Url>, MvError> {
    let head = client.head(url).map_err(|source| MvError::Head {
        url: url.to_string(),
        source,
    })?;
    if head.status.is_success() {
        Ok(Some(head.final_url))
    } else if head.status.code == 404 {
        Ok(None)
    } else {
        Err(MvError::UnexpectedStatus {
            url: url.to_string(),
            status: head.status.code,
        })
    }
}

/// HTTP version of [`walk_forward_local`]. Capped at
/// [`DISCOVERY_VOLUME_CAP`]: an origin that returns 2xx for every
/// probed sibling (a misconfigured mock or a captive-portal style
/// 200) surfaces [`MvError::DiscoveryExceededCap`] rather than
/// spinning forever.
fn walk_forward_http(
    client: &Client,
    seed: &Url,
    base: &str,
    kind: VolumeKind,
    width: usize,
    seed_volume: u32,
) -> Result<Vec<Url>, MvError> {
    debug_assert!(matches!(kind, VolumeKind::Rar5 | VolumeKind::SevenZ));
    let mut volumes = Vec::new();
    for n in 1..=DISCOVERY_VOLUME_CAP {
        let name = format_volume_name(base, kind, n, width);
        let candidate = seed.join(&name).map_err(|source| MvError::BadSiblingUrl {
            name: name.clone(),
            source,
        })?;
        match head_volume(client, &candidate)? {
            Some(final_url) => volumes.push(final_url),
            None => {
                if seed_volume == 0 || (seed_volume as usize) > volumes.len() {
                    return Err(MvError::MissingVolume {
                        kind,
                        missing: seed_volume,
                    });
                }
                return Ok(volumes);
            }
        }
    }
    Err(MvError::DiscoveryExceededCap {
        kind,
        cap: DISCOVERY_VOLUME_CAP,
    })
}

/// HTTP version of [`discover_zip_local`].
fn discover_zip_http(client: &Client, seed: &Url, parsed: VolumeName) -> Result<Vec<Url>, MvError> {
    let width = if parsed.width == 0 { 2 } else { parsed.width };
    let mut volumes = Vec::new();
    let mut hit_cap = true;
    for n in 1..=DISCOVERY_VOLUME_CAP {
        let name = format_volume_name(&parsed.base, VolumeKind::Zip, n, width);
        let candidate = seed.join(&name).map_err(|source| MvError::BadSiblingUrl {
            name: name.clone(),
            source,
        })?;
        match head_volume(client, &candidate)? {
            Some(final_url) => volumes.push(final_url),
            None => {
                hit_cap = false;
                break;
            }
        }
    }
    if hit_cap {
        return Err(MvError::DiscoveryExceededCap {
            kind: VolumeKind::Zip,
            cap: DISCOVERY_VOLUME_CAP,
        });
    }
    let final_name = format_zip_final(&parsed.base);
    let final_candidate = seed
        .join(&final_name)
        .map_err(|source| MvError::BadSiblingUrl {
            name: final_name.clone(),
            source,
        })?;
    let final_url = head_volume(client, &final_candidate)?;
    if volumes.is_empty() {
        if let Some(u) = final_url {
            return Ok(vec![u]);
        }
        return Err(MvError::FinalVolumeMissing {
            path: final_candidate.to_string(),
        });
    }
    let Some(final_url) = final_url else {
        return Err(MvError::FinalVolumeMissing {
            path: final_candidate.to_string(),
        });
    };
    volumes.push(final_url);
    Ok(volumes)
}

// ---- name helpers ----------------------------------------------------

/// Extract a basename from a `&Path`. Defaults to the empty string
/// if the path has no final component (a vacuous "." for an empty
/// path makes the downstream pattern parsers cleanly miss).
fn path_basename(p: &Path) -> &str {
    p.file_name().and_then(|s| s.to_str()).unwrap_or("")
}

/// Extract a basename from a [`Url`]'s path, dropping any query
/// string. The returned slice borrows from the URL's stored path.
///
/// Re-exported under a name explicit about its purpose for callers
/// outside this module who need to feed [`parse_volume_name`] from
/// a [`Url`] without re-implementing the path-to-basename slice.
#[must_use]
pub fn url_basename_for_discovery(url: &Url) -> &str {
    url_basename(url)
}

/// Extract a basename from a [`Url`]'s path, dropping any query
/// string.
fn url_basename(url: &Url) -> &str {
    let path = url.path();
    let no_query = match path.find('?') {
        Some(i) => &path[..i],
        None => path,
    };
    match no_query.rfind('/') {
        Some(i) => &no_query[i + 1..],
        None => no_query,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- pattern parsing ---------------------------------------------

    #[test]
    fn parse_rar5_four_digit() {
        let v = parse_volume_name("foo.part0001.rar").expect("matches");
        assert_eq!(v.base, "foo");
        assert_eq!(v.kind, VolumeKind::Rar5);
        assert_eq!(v.volume, Some(1));
        assert_eq!(v.width, 4);
    }

    #[test]
    fn parse_rar5_two_digit() {
        let v = parse_volume_name("snapshot.tar.part12.rar").expect("matches");
        assert_eq!(v.base, "snapshot.tar");
        assert_eq!(v.kind, VolumeKind::Rar5);
        assert_eq!(v.volume, Some(12));
        assert_eq!(v.width, 2);
    }

    #[test]
    fn parse_rar5_single_digit() {
        let v = parse_volume_name("foo.part3.rar").expect("matches");
        assert_eq!(v.volume, Some(3));
        assert_eq!(v.width, 1);
    }

    #[test]
    fn parse_rar5_case_insensitive_suffix() {
        let v = parse_volume_name("Foo.PART0007.RAR").expect("matches");
        assert_eq!(v.base, "Foo");
        assert_eq!(v.volume, Some(7));
    }

    #[test]
    fn parse_rar5_plain_rar_does_not_match() {
        assert!(parse_volume_name("foo.rar").is_none());
        assert!(parse_volume_name("foo.partABC.rar").is_none());
    }

    #[test]
    fn parse_7z_three_digit() {
        let v = parse_volume_name("foo.7z.001").expect("matches");
        assert_eq!(v.base, "foo");
        assert_eq!(v.kind, VolumeKind::SevenZ);
        assert_eq!(v.volume, Some(1));
        assert_eq!(v.width, 3);
    }

    #[test]
    fn parse_7z_high_volume() {
        let v = parse_volume_name("backup.tar.7z.0123").expect("matches");
        assert_eq!(v.base, "backup.tar");
        assert_eq!(v.volume, Some(123));
        assert_eq!(v.width, 4);
    }

    #[test]
    fn parse_7z_plain_does_not_match() {
        assert!(parse_volume_name("foo.7z").is_none());
        assert!(parse_volume_name("foo.tar.zst").is_none());
    }

    #[test]
    fn parse_zip_final() {
        let v = parse_volume_name("archive.zip").expect("matches");
        assert_eq!(v.base, "archive");
        assert_eq!(v.kind, VolumeKind::Zip);
        assert_eq!(v.volume, None);
    }

    #[test]
    fn parse_zip_numbered() {
        let v = parse_volume_name("archive.z01").expect("matches");
        assert_eq!(v.base, "archive");
        assert_eq!(v.kind, VolumeKind::Zip);
        assert_eq!(v.volume, Some(1));
        assert_eq!(v.width, 2);
    }

    #[test]
    fn parse_zip_numbered_three_digit() {
        let v = parse_volume_name("set.z105").expect("matches");
        assert_eq!(v.volume, Some(105));
        assert_eq!(v.width, 3);
    }

    #[test]
    fn parse_zip_case_insensitive_zip_suffix() {
        let v = parse_volume_name("Archive.ZIP").expect("matches");
        assert_eq!(v.base, "Archive");
        assert_eq!(v.volume, None);
    }

    #[test]
    fn format_round_trips_through_parse() {
        let inputs = [
            ("foo", VolumeKind::Rar5, 1u32, 4usize),
            ("bar.tar", VolumeKind::Rar5, 12, 2),
            ("foo", VolumeKind::SevenZ, 7, 3),
            ("foo", VolumeKind::Zip, 1, 2),
        ];
        for (base, kind, vol, width) in inputs {
            let name = format_volume_name(base, kind, vol, width);
            let parsed = parse_volume_name(&name).expect("round-trips");
            assert_eq!(parsed.base, base);
            assert_eq!(parsed.kind, kind);
            assert_eq!(parsed.volume, Some(vol));
            assert_eq!(parsed.width, width);
        }
    }

    // ---- local discovery --------------------------------------------

    use std::fs;
    use tempdir::tempdir;

    // We sit on top of `tempfile` via the existing test infra; if a
    // crate-local helper exists prefer it, but a bare std::env temp
    // directory keeps the test simple and avoids adding a dep.
    mod tempdir {
        use std::fs;
        use std::path::PathBuf;
        use std::sync::atomic::{AtomicU64, Ordering};
        use std::time::{SystemTime, UNIX_EPOCH};

        pub fn tempdir() -> TempDir {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!("peel-mv-{pid}-{nanos}-{n}"));
            fs::create_dir_all(&path).expect("create temp dir");
            TempDir { path }
        }

        pub struct TempDir {
            path: PathBuf,
        }
        impl TempDir {
            pub fn path(&self) -> &std::path::Path {
                &self.path
            }
        }
        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.path);
            }
        }
    }

    fn touch(p: &std::path::Path) {
        fs::write(p, b"").expect("touch");
    }

    #[test]
    fn discover_local_rar5_three_volumes_seed_first() {
        let td = tempdir();
        let root = td.path();
        for n in 1..=3u32 {
            touch(&root.join(format!("multi.part{n:04}.rar")));
        }
        let got = discover_local(&root.join("multi.part0001.rar")).expect("ok");
        let want: Vec<_> = (1..=3)
            .map(|n| root.join(format!("multi.part{n:04}.rar")))
            .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn discover_local_rar5_seed_in_middle_walks_from_one() {
        let td = tempdir();
        let root = td.path();
        for n in 1..=5u32 {
            touch(&root.join(format!("x.part{n:04}.rar")));
        }
        let got = discover_local(&root.join("x.part0003.rar")).expect("ok");
        assert_eq!(got.len(), 5);
        assert_eq!(got[0], root.join("x.part0001.rar"));
        assert_eq!(got[4], root.join("x.part0005.rar"));
    }

    #[test]
    fn discover_local_rar5_missing_lower_volume_errors() {
        let td = tempdir();
        let root = td.path();
        // Only volumes 2 and 3 exist; user passes 3 as the seed.
        for n in 2..=3u32 {
            touch(&root.join(format!("y.part{n:04}.rar")));
        }
        let err = discover_local(&root.join("y.part0003.rar")).unwrap_err();
        assert!(matches!(
            err,
            MvError::MissingVolume {
                kind: VolumeKind::Rar5,
                ..
            }
        ));
    }

    #[test]
    fn discover_local_7z_three_volumes() {
        let td = tempdir();
        let root = td.path();
        for n in 1..=3u32 {
            touch(&root.join(format!("z.7z.{n:03}")));
        }
        let got = discover_local(&root.join("z.7z.001")).expect("ok");
        let want: Vec<_> = (1..=3).map(|n| root.join(format!("z.7z.{n:03}"))).collect();
        assert_eq!(got, want);
    }

    #[test]
    fn discover_local_zip_spanned() {
        let td = tempdir();
        let root = td.path();
        for n in 1..=2u32 {
            touch(&root.join(format!("multi.z{n:02}")));
        }
        touch(&root.join("multi.zip"));
        let got = discover_local(&root.join("multi.z01")).expect("ok");
        let want = vec![
            root.join("multi.z01"),
            root.join("multi.z02"),
            root.join("multi.zip"),
        ];
        assert_eq!(got, want);
    }

    #[test]
    fn discover_local_zip_seed_is_final_volume() {
        let td = tempdir();
        let root = td.path();
        for n in 1..=2u32 {
            touch(&root.join(format!("m.z{n:02}")));
        }
        touch(&root.join("m.zip"));
        let got = discover_local(&root.join("m.zip")).expect("ok");
        assert_eq!(got.len(), 3);
        assert_eq!(got.last().unwrap(), &root.join("m.zip"));
    }

    #[test]
    fn discover_local_zip_single_volume_falls_through() {
        let td = tempdir();
        let root = td.path();
        touch(&root.join("solo.zip"));
        let got = discover_local(&root.join("solo.zip")).expect("ok");
        assert_eq!(got, vec![root.join("solo.zip")]);
    }

    #[test]
    fn discover_local_zip_missing_final_errors() {
        let td = tempdir();
        let root = td.path();
        for n in 1..=2u32 {
            touch(&root.join(format!("partial.z{n:02}")));
        }
        // No partial.zip.
        let err = discover_local(&root.join("partial.z01")).unwrap_err();
        assert!(matches!(err, MvError::FinalVolumeMissing { .. }));
    }

    #[test]
    fn discover_local_pattern_not_recognised() {
        let td = tempdir();
        let root = td.path();
        let p = root.join("archive.tar.zst");
        touch(&p);
        let err = discover_local(&p).unwrap_err();
        assert!(matches!(err, MvError::PatternNotRecognised { .. }));
    }

    // ---- helpers ----------------------------------------------------

    #[test]
    fn url_basename_drops_query() {
        let url =
            Url::parse("https://host.example/path/foo.part0001.rar?signature=xyz").expect("parses");
        assert_eq!(url_basename(&url), "foo.part0001.rar");
    }

    #[test]
    fn path_basename_extracts_name() {
        let p = Path::new("/tmp/dir/foo.part0001.rar");
        assert_eq!(path_basename(p), "foo.part0001.rar");
    }
}
