//! Shared scratch-directory helpers for integration tests.
//!
//! Several integration tests grew their own private copies of the same
//! `unique_dir` / `CleanupDir` pair; the CLI subprocess tests
//! (`tests/test_cli_*.rs`) collapse those into one source of truth so
//! the harness in [`super::peel_cli`] does not have to re-derive a
//! tempdir convention per file.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

static UNIQ: AtomicU64 = AtomicU64::new(0);

/// Create a fresh, unique directory under the system tempdir and
/// return it. The name embeds pid + monotonic counter + wall-clock
/// nanoseconds so concurrent test binaries never collide.
pub fn unique_dir(label: &str) -> PathBuf {
    let pid = std::process::id();
    let n = UNIQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let p = std::env::temp_dir().join(format!("peel_cli_{label}_{pid}_{nanos}_{n}"));
    fs::create_dir_all(&p).expect("create unique_dir");
    p
}

/// RAII guard that recursively removes its directory on `Drop`.
pub struct CleanupDir(pub PathBuf);

impl Drop for CleanupDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
