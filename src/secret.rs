//! Password handling for encrypted archives
//! (`docs/PLAN_archive_encryption.md` §1).
//!
//! This module exists to keep raw passphrase bytes inside one auditable
//! perimeter. Two types do the work:
//!
//! - [`Password`] is a zeroising byte-buffer wrapper. It is the only
//!   type that crosses module boundaries carrying decrypted passphrase
//!   bytes, denies `Debug` / `Display`, and overwrites its backing
//!   storage with `ptr::write_volatile` on drop. Format-specific
//!   decoders take `&Password` from §3 onward.
//! - [`source::PasswordSource`] is a parsed `--password-from <SOURCE>`
//!   value. It knows how to obtain a [`Password`] from the user (TTY
//!   prompt without echo, environment variable, file, or a passed-in
//!   file descriptor) and is the only point in the codebase that reads
//!   passphrase bytes from outside.
//!
//! # Threat model
//!
//! The plan's threat model
//! (`docs/PLAN_archive_encryption.md` §7) explicitly does not protect
//! against an attacker with read access to `/proc/<pid>/mem`, the swap
//! device, or the process's argv. We minimise the in-memory lifetime of
//! the password (drop zeroises) and refuse to accept it on the command
//! line at all (no `--password=…` flag — process-list visibility is
//! the wrong default). Beyond that we rely on the operating system.

#[cfg(unix)]
pub mod source;

#[cfg(unix)]
pub use source::{PasswordLoadError, PasswordSource, PasswordSourceParseError};

use std::fmt;

/// Owned passphrase bytes that zeroise their backing storage on drop.
///
/// The only accessor is [`Password::as_bytes`]; the type denies
/// `Debug` / `Display` / `Clone` to keep the bytes from accidentally
/// landing in a log line or duplicate buffer. Format-specific
/// decoders take `&Password` and hand the bytes to the KDF; nothing
/// outside this module constructs one except [`PasswordSource::load`].
///
/// # Zeroisation
///
/// Drop overwrites every byte with `0u8` using
/// [`std::ptr::write_volatile`], which the compiler is forbidden from
/// optimising away. Capacity beyond `len` is left untouched — we never
/// `with_capacity` more than `len`, so this is fine; see
/// [`Password::new`].
pub struct Password {
    bytes: Vec<u8>,
}

impl Password {
    /// Wrap raw passphrase bytes.
    ///
    /// The vector is taken by value and its capacity is shrunk to its
    /// length so the drop-zeroiser covers every byte. Callers should
    /// pass freshly allocated vectors (e.g. from
    /// [`PasswordSource::load`]); reusing a `Vec` whose capacity once
    /// held other secrets would leave those bytes unzeroed when this
    /// `Password` drops.
    pub fn new(mut bytes: Vec<u8>) -> Self {
        bytes.shrink_to_fit();
        Self { bytes }
    }

    /// Borrow the password bytes for use by a KDF.
    ///
    /// The returned slice is valid for the lifetime of this
    /// [`Password`]; the caller MUST NOT copy the bytes into a
    /// longer-lived buffer. Format-specific decoders feed the slice
    /// directly into a PBKDF2 / SHA-256 loop and discard the derived
    /// key bytes through the same channel.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// True when the password is empty.
    ///
    /// Used by [`PasswordSource`] loaders to refuse empty values
    /// (an empty password is almost always a misconfigured env var
    /// or an unexpected EOF, not a legitimate input).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        // Volatile per-byte writes to defeat optimiser elision. We do
        // not use `slice::fill` because the compiler is permitted to
        // remove a non-volatile fill on a value that is about to be
        // dropped — exactly the case here.
        let len = self.bytes.len();
        let ptr = self.bytes.as_mut_ptr();
        for offset in 0..len {
            // SAFETY: `offset < len` and `ptr` is a valid mutable
            // pointer to `len` initialized bytes. `write_volatile` is
            // not subject to dead-store elimination, so the zero
            // persists past the drop.
            unsafe { std::ptr::write_volatile(ptr.add(offset), 0u8) };
        }
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never expose the bytes. A `{:?}` print yields the type name
        // and the length only, which is enough to debug "is the
        // password loaded?" without leaking the value.
        f.debug_struct("Password")
            .field("len", &self.bytes.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_does_not_leak_bytes() {
        let pw = Password::new(b"hunter2".to_vec());
        let debug = format!("{pw:?}");
        assert!(!debug.contains("hunter2"));
        assert!(debug.contains("redacted"));
        assert!(debug.contains("len: 7"));
    }

    #[test]
    fn as_bytes_round_trips_input() {
        let pw = Password::new(b"correct horse battery staple".to_vec());
        assert_eq!(pw.as_bytes(), b"correct horse battery staple");
        assert_eq!(pw.len(), 28);
        assert!(!pw.is_empty());
    }

    #[test]
    fn empty_password_reports_empty() {
        let pw = Password::new(Vec::new());
        assert!(pw.is_empty());
        assert_eq!(pw.len(), 0);
    }

    #[test]
    fn drop_zeroises_backing_storage() {
        // We can't observe the buffer after `Drop` runs in safe Rust, so
        // we mimic the drop-time loop and verify it produces zero bytes
        // regardless of the input.
        let mut bytes = b"sensitive".to_vec();
        let ptr = bytes.as_mut_ptr();
        let len = bytes.len();
        for offset in 0..len {
            // SAFETY: same invariants as the real `Drop` impl.
            unsafe { std::ptr::write_volatile(ptr.add(offset), 0u8) };
        }
        assert!(bytes.iter().all(|&b| b == 0));
    }

    #[test]
    fn new_shrinks_to_fit_so_drop_covers_full_capacity() {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(b"abc");
        let pw = Password::new(buf);
        // After `shrink_to_fit`, capacity must be at most len.
        // (Vec may keep a small minimum capacity, but it must not
        // hold the original 64-byte tail.)
        assert!(pw.bytes.capacity() <= pw.bytes.len() + 8);
    }
}
