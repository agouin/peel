//! Subprocess harness for end-to-end CLI tests.
//!
//! Spawns the real `peel` binary (resolved through Cargo's
//! `CARGO_BIN_EXE_peel` env var, set by the test runner) so the argv →
//! [`peel::coordinator::CoordinatorConfig`] wiring, the exit-code
//! contract documented in `internal/ENCRYPTION.md`, and the user-facing
//! stderr shape are all under test — not just the in-process API
//! exercised by `tests/test_coordinator_*.rs`.
//!
//! The harness deliberately keeps the dependency footprint to
//! `std::process::Command` — `assert_cmd` would be ergonomic but
//! introduces a new vetted crate for a use case the existing bench
//! tests already cover with `Command::output()` (see
//! [`tests/test_bench_streaming.rs`] §`run_peel_subprocess`). The
//! dependency policy in `internal/ENGINEERING_STANDARDS.md` §2.2 prefers
//! reusing the std-lib primitive when adequate.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Builder around [`Command`] that resolves the `peel` binary path
/// once and forwards `arg` / `env` mutations through to the underlying
/// command. Construct with [`peel_cmd`] for a fresh, environment-clean
/// invocation.
pub struct PeelCmd {
    cmd: Command,
}

/// Captured outcome of a [`PeelCmd::run`].
///
/// `code` is the process's exit code; `-1` represents "terminated by a
/// signal" (matches [`std::process::ExitStatus::code`] returning
/// `None`). The encryption-error contract in `internal/ENCRYPTION.md`
/// §Exit-codes guarantees `4` for `PasswordIncorrect`/`PasswordMissing`
/// and `0` for clean success; everything else surfaces as `1`.
pub struct PeelOutput {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl PeelOutput {
    /// Stderr as a lossy UTF-8 string for `assert!`-style diagnostics.
    pub fn stderr_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.stderr)
    }

    /// Stdout as a lossy UTF-8 string.
    pub fn stdout_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.stdout)
    }
}

/// Construct a fresh [`PeelCmd`] pointing at the test-built `peel`
/// binary. Cargo sets `CARGO_BIN_EXE_peel` to the absolute path of
/// the binary built for the current test target.
pub fn peel_cmd() -> PeelCmd {
    let exe = env!("CARGO_BIN_EXE_peel");
    let cmd = Command::new(exe);
    PeelCmd { cmd }
}

impl PeelCmd {
    pub fn arg<S: AsRef<std::ffi::OsStr>>(mut self, a: S) -> Self {
        self.cmd.arg(a);
        self
    }

    pub fn args<I, S>(mut self, a: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.cmd.args(a);
        self
    }

    pub fn env(mut self, k: &str, v: &str) -> Self {
        self.cmd.env(k, v);
        self
    }

    pub fn env_remove(mut self, k: &str) -> Self {
        self.cmd.env_remove(k);
        self
    }

    /// Append `-o <dir>/` so peel resolves the output as a tree-shape
    /// target regardless of suffix detection. Matches the convention
    /// used by [`tests/test_bench_streaming.rs`] `run_peel_subprocess`
    /// — the trailing slash is what the CLI's
    /// `output_shape_from_path` consults
    /// ([src/cli.rs](../../src/cli.rs) §`ends_with('/')`).
    pub fn out_dir(self, d: &Path) -> Self {
        self.arg("-o").arg(format!("{}/", d.display()))
    }

    /// Append `-o <path>` for stream-shape outputs (raw `.gz` / `.zst`
    /// / `.xz` / `.lz4`).
    pub fn out_file(self, p: &Path) -> Self {
        self.arg("-o").arg(p)
    }

    /// Spawn the subprocess, drain stdout/stderr, and return the
    /// captured outcome. `stdin` is wired to `/dev/null` so a stray
    /// `prompt`-mode password source cannot wedge the test on a
    /// terminal read.
    ///
    /// Blocks until the child exits. Does not panic on non-zero exit;
    /// the caller asserts on `code` and inspects stderr.
    pub fn run(mut self) -> PeelOutput {
        self.cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = self.cmd.output().expect("spawn peel subprocess");
        PeelOutput {
            code: out.status.code().unwrap_or(-1),
            stdout: out.stdout,
            stderr: out.stderr,
        }
    }
}

/// Write `bytes` to `<dir>/<name>` with mode 0600 and return the path.
///
/// `--password-from file:<path>` warns when the file's mode is not
/// 0600 (see [src/secret/source.rs](../../src/secret/source.rs)), so
/// the fixture matches the documented quiet path: no spurious warning
/// in stderr that an assertion might trip on.
pub fn write_password_file(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, bytes).expect("write password file");
    let mut perms = std::fs::metadata(&path)
        .expect("stat password file")
        .permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&path, perms).expect("chmod 0600");
    path
}

/// Walk `dir` and assert it contains exactly the supplied
/// `(relpath, body)` pairs — no missing entries, no extras.
///
/// Catches two failure modes the in-process coordinator tests do
/// *not*: an extractor that silently writes a sidecar the caller did
/// not expect (e.g. a stray `.peel.part` left behind on success), and
/// a CLI flag that quietly emits a parallel artifact (e.g.
/// `--keep-archive` plus an extraction tree where one path was
/// supposed to subsume the other). Caller passes `expected` in any
/// order; comparison is order-independent.
pub fn assert_tree_exactly(dir: &Path, expected: &[(&str, &[u8])]) {
    let mut got = walk_files(dir);
    got.sort_by(|a, b| a.0.cmp(&b.0));
    let mut want: Vec<(String, Vec<u8>)> = expected
        .iter()
        .map(|(p, b)| ((*p).to_string(), (*b).to_vec()))
        .collect();
    want.sort_by(|a, b| a.0.cmp(&b.0));

    let got_names: Vec<&str> = got.iter().map(|(n, _)| n.as_str()).collect();
    let want_names: Vec<&str> = want.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        got_names,
        want_names,
        "tree mismatch under {}: got {got_names:?}, want {want_names:?}",
        dir.display()
    );
    for ((g_name, g_body), (w_name, w_body)) in got.iter().zip(want.iter()) {
        assert_eq!(g_name, w_name);
        assert_eq!(
            g_body.len(),
            w_body.len(),
            "size mismatch on {g_name}: got {} bytes, want {} bytes",
            g_body.len(),
            w_body.len()
        );
        assert_eq!(g_body, w_body, "body mismatch on {g_name}");
    }
}

/// Recursively collect `(relative_path, bytes)` for every regular
/// file under `root`. Directories are descended; symlinks are not
/// followed (none of the supported formats produce symlinks the
/// existing in-process tests are expected to extract, so descending
/// them would only introduce platform-specific noise).
fn walk_files(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(root: &Path, cur: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let Ok(entries) = std::fs::read_dir(cur) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let ft = match entry.file_type() {
                Ok(ft) => ft,
                Err(_) => continue,
            };
            if ft.is_dir() {
                walk(root, &path, out);
            } else if ft.is_file() {
                let rel = path
                    .strip_prefix(root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .into_owned();
                let body = std::fs::read(&path).unwrap_or_default();
                out.push((rel, body));
            }
        }
    }
    let mut out = Vec::new();
    walk(root, root, &mut out);
    out
}
