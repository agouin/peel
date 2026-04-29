//! Error-handling conventions for the `pux` library.
//!
//! `pux` deliberately does **not** define a single crate-wide `Error`
//! enum. Each module owns its own typed error built with
//! [`thiserror::Error`]. Merging a download error and a checkpoint error
//! into one variant set dilutes the diagnostics and tempts callers into
//! generic `match _ => ...` arms; keeping them separate forces every error
//! site to be specific.
//!
//! This module is documentation, not code. The pattern below is the one
//! every other module in the crate is expected to follow.
//!
//! # The pattern
//!
//! ```
//! use std::path::PathBuf;
//! use thiserror::Error;
//!
//! /// Errors produced by the (hypothetical) widget subsystem.
//! #[derive(Debug, Error)]
//! pub enum WidgetError {
//!     /// A configuration value failed validation.
//!     #[error("widget {name}: invalid {field}: {reason}")]
//!     InvalidConfig {
//!         /// The widget that failed to validate.
//!         name: String,
//!         /// The misconfigured field.
//!         field: &'static str,
//!         /// Human-readable explanation of why it was rejected.
//!         reason: String,
//!     },
//!
//!     /// The widget store on disk was unreadable.
//!     #[error("widget {name}: io error reading {path}")]
//!     Io {
//!         /// The widget being operated on.
//!         name: String,
//!         /// The on-disk path involved.
//!         path: PathBuf,
//!         /// The underlying IO error, preserved for `Error::source()`.
//!         #[source]
//!         source: std::io::Error,
//!     },
//! }
//! ```
//!
//! # Conventions
//!
//! - **Variants are specific.** `InvalidConfig`, not `BadInput`. The
//!   variant name should tell the reader what failed without reading the
//!   message.
//! - **Messages are diagnosable.** They name the resource (path, URL,
//!   chunk index, byte offset), not just the class of failure. A user
//!   pasting the message into a bug report should give enough context to
//!   investigate.
//! - **Underlying errors are preserved with `#[source]`**, not flattened
//!   into the message. The `Display` chain walks down naturally and the
//!   original `errno` (or upstream type) is recoverable via
//!   [`std::error::Error::source`].
//! - **Use `#[from]` sparingly.** Only when a conversion is genuinely
//!   unambiguous (one variant, one source type). Otherwise wrap explicitly
//!   so the conversion site is greppable.
//! - **Library code never returns `Box<dyn Error>` or `String`.**
//! - **`anyhow` is reserved for the binary boundary** (see
//!   [`crate`] docs). Library APIs return their typed error.
//!
//! # Why no crate-wide `Error`?
//!
//! At first glance a crate-wide `Error` enum is convenient: callers can
//! `match` once and handle anything. In practice the variants of a
//! download error (`SourceChanged`, `RangeUnsupported`) and the variants
//! of a checkpoint error (`CorruptCheckpoint`, `IncompatibleVersion`) do
//! not belong to the same vocabulary. Merging them produces a sprawling
//! enum whose variants are mostly irrelevant at any one call site, and
//! whose `Display` impl ends up generic ("checkpoint or download failed")
//! to keep the message coherent. We prefer many small, specific error
//! types and explicit conversions at module boundaries.
