//! Parsing and loading of `--password-from <SOURCE>`
//! (`internal/PLAN_archive_encryption.md` §1).
//!
//! [`PasswordSource`] is the parsed form of the user's
//! `--password-from` argument. The CLI parses the source once at
//! startup; format-specific decoders later call
//! [`PasswordSource::load`] when an encrypted entry is encountered.
//!
//! The four sources are deliberately limited: anything the user could
//! pipe in via `argv` (the absent `--password=…` flag) leaks to every
//! process on the host through `/proc/<pid>/cmdline`. Instead the
//! supported sources are:
//!
//! - `prompt` — TTY input with echo disabled, opened on `/dev/tty`
//!   (never `stdin`, because `stdin` may carry archive data in some
//!   future streaming mode and conflating the two is a footgun).
//! - `env:NAME` — the named environment variable, with a single
//!   trailing newline stripped.
//! - `file:PATH` — the first line of the file. Non-`0600` modes get
//!   a one-shot warning but do not abort.
//! - `fd:N` — the given file descriptor (duped, so we never close
//!   the original). One-shot, until EOF or newline. Pairs with shell
//!   process substitution: `peel … --password-from fd:3 3< <(pass …)`.

//! # Cross-platform notes
//!
//! `PLAN_v3_windows.md` §3 lifts the file-level `#![cfg(unix)]` so
//! [`PasswordSource`] and the env/file loaders work on Windows too.
//! The `fd:N` source is Unix-only (Windows `HANDLE`s are not small
//! integers; the parser rejects `fd:N` with
//! [`PasswordSourceParseError::UnsupportedOnPlatform`]). The TTY
//! prompt's `SetConsoleMode` Windows implementation lands in §6;
//! until then `Prompt` on Windows returns a clean
//! [`PasswordLoadError::PlatformUnsupported`] error.

use std::ffi::OsString;
use std::fs::File;
#[cfg(unix)]
use std::io::Write;
use std::io::{self, Read};
#[cfg(unix)]
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::ffi::c_int;

use thiserror::Error;

use super::Password;

/// Where the password for an encrypted archive comes from.
///
/// Parsed once at CLI time via [`PasswordSource::parse`]; consumed
/// by [`PasswordSource::load`] when a format-specific decoder
/// discovers an encrypted entry. Multiple loads against the same
/// source are supported on [`PasswordSource::Prompt`] (retry on
/// wrong password); non-interactive sources fail-fast after the
/// first attempt by convention — see
/// [`PasswordSource::is_interactive`].
#[derive(Debug, Clone)]
pub enum PasswordSource {
    /// Read from `/dev/tty` with echo disabled on Unix; from
    /// `CONIN$` with `ENABLE_ECHO_INPUT` cleared on Windows
    /// (`PLAN_v3_windows.md` §6).
    Prompt,
    /// Read from the named environment variable.
    Env(OsString),
    /// Read the first line of the file at the given path.
    File(PathBuf),
    /// Read from the given file descriptor (duped before reading
    /// so the caller's fd remains open). Unix-only: Windows
    /// `HANDLE`s are not small integers and the `fd:N` shell idiom
    /// (`peel … --password-from fd:3 3< <(pass …)`) has no direct
    /// Windows analog. On Windows the parser rejects `fd:N` with
    /// [`PasswordSourceParseError::UnsupportedOnPlatform`].
    #[cfg(unix)]
    Fd(RawFd),
}

/// Errors from parsing a `--password-from <SOURCE>` argument.
#[derive(Debug, Error)]
pub enum PasswordSourceParseError {
    /// The argument did not match any known shape
    /// (`prompt`, `env:NAME`, `file:PATH`, `fd:N`).
    #[error(
        "unrecognized password source {input:?}; expected one of \
         `prompt`, `env:NAME`, `file:PATH`, `fd:N`"
    )]
    UnknownScheme {
        /// The verbatim user input.
        input: String,
    },

    /// `env:NAME` was passed with an empty `NAME`.
    #[error("--password-from env:<NAME> requires a non-empty NAME")]
    EmptyEnvName,

    /// `file:PATH` was passed with an empty `PATH`.
    #[error("--password-from file:<PATH> requires a non-empty PATH")]
    EmptyFilePath,

    /// `fd:N` carried a value that could not be parsed as a
    /// non-negative integer.
    #[error("--password-from fd:<N> requires a non-negative integer, got {value:?}")]
    InvalidFd {
        /// The substring that failed to parse.
        value: String,
    },

    /// A syntactically valid source variant is not supported on this
    /// platform. Today the only case is `fd:N` on Windows — Windows
    /// `HANDLE`s are not numeric file descriptors and shell
    /// process-substitution (`<(pass …)`) is a Unix idiom.
    #[error("--password-from {scheme} is not supported on this platform")]
    UnsupportedOnPlatform {
        /// The source scheme (e.g. `"fd:N"`).
        scheme: &'static str,
    },
}

/// Errors from loading a password via [`PasswordSource::load`].
#[derive(Debug, Error)]
pub enum PasswordLoadError {
    /// Opening `/dev/tty` failed (no controlling terminal, etc.).
    #[error("opening /dev/tty for password prompt: {source}")]
    TtyOpen {
        /// Underlying `io::Error`.
        #[source]
        source: io::Error,
    },

    /// Writing the prompt banner to `/dev/tty` failed.
    #[error("writing password prompt to /dev/tty: {source}")]
    TtyWrite {
        /// Underlying `io::Error`.
        #[source]
        source: io::Error,
    },

    /// `tcgetattr` / `tcsetattr` failed while toggling echo.
    #[error("configuring terminal for password input (errno {errno})")]
    TermiosFailure {
        /// The errno reported by `tcgetattr` / `tcsetattr`.
        errno: i32,
    },

    /// `GetConsoleMode` / `SetConsoleMode` failed while toggling
    /// `ENABLE_ECHO_INPUT` on the Windows console handle.
    /// (`PLAN_v3_windows.md` §6.)
    #[error("configuring Windows console for password input: {source}")]
    ConsoleModeFailure {
        /// The underlying `io::Error` (carries the Win32 last-error
        /// code via `io::Error::raw_os_error`).
        #[source]
        source: io::Error,
    },

    /// Reading the password line itself failed.
    #[error("reading password from {source_label}: {source}")]
    Read {
        /// Human-readable identifier of the source (`/dev/tty`,
        /// `env:PEEL_PASSWORD`, `file:/path`, `fd:3`).
        source_label: String,
        /// Underlying `io::Error`.
        #[source]
        source: io::Error,
    },

    /// The named environment variable was not set.
    #[error("environment variable {name:?} is not set (--password-from env:{name})")]
    EnvNotSet {
        /// The variable name the user passed.
        name: String,
    },

    /// The loaded password was empty after stripping the line ending.
    /// Empty passwords are almost always a misconfiguration (an empty
    /// env var, an EOF on the fd, an empty file) rather than a
    /// legitimate input.
    #[error("password from {source_label} was empty")]
    Empty {
        /// Human-readable identifier of the source.
        source_label: String,
    },

    /// Could not read the file's metadata while checking its mode.
    #[error("stat({path:?}) for password file mode check: {source}")]
    FileMetadata {
        /// The path that failed to stat.
        path: PathBuf,
        /// Underlying `io::Error`.
        #[source]
        source: io::Error,
    },

    /// The requested loader is not implemented on this platform yet.
    /// Today this fires only on Windows for [`PasswordSource::Prompt`]
    /// pending `PLAN_v3_windows.md` §6 (the Windows `SetConsoleMode`
    /// echo-off implementation). Use `--password-from env:NAME` or
    /// `--password-from file:PATH` as the workaround.
    #[error("--password-from {source_kind} is not yet implemented on this platform")]
    PlatformUnsupported {
        /// Short label of the source variant (e.g. `"prompt"`).
        source_kind: &'static str,
    },
}

impl PasswordSource {
    /// Parse a `--password-from` argument.
    ///
    /// # Errors
    /// Returns [`PasswordSourceParseError`] when the input does not
    /// match `prompt`, `env:NAME`, `file:PATH`, or `fd:N`.
    pub fn parse(input: &str) -> Result<Self, PasswordSourceParseError> {
        if input == "prompt" {
            return Ok(Self::Prompt);
        }
        if let Some(rest) = input.strip_prefix("env:") {
            if rest.is_empty() {
                return Err(PasswordSourceParseError::EmptyEnvName);
            }
            return Ok(Self::Env(OsString::from(rest)));
        }
        if let Some(rest) = input.strip_prefix("file:") {
            if rest.is_empty() {
                return Err(PasswordSourceParseError::EmptyFilePath);
            }
            return Ok(Self::File(PathBuf::from(rest)));
        }
        if let Some(rest) = input.strip_prefix("fd:") {
            // Validate the numeric shape on every platform so the
            // diagnostic is consistent (`InvalidFd` for bad digits,
            // `UnsupportedOnPlatform` for "Windows doesn't do fd:N").
            #[cfg(unix)]
            {
                let fd: c_int = rest
                    .parse()
                    .map_err(|_| PasswordSourceParseError::InvalidFd {
                        value: rest.to_string(),
                    })?;
                if fd < 0 {
                    return Err(PasswordSourceParseError::InvalidFd {
                        value: rest.to_string(),
                    });
                }
                return Ok(Self::Fd(fd));
            }
            #[cfg(not(unix))]
            {
                let _ = rest;
                return Err(PasswordSourceParseError::UnsupportedOnPlatform { scheme: "fd:N" });
            }
        }
        Err(PasswordSourceParseError::UnknownScheme {
            input: input.to_string(),
        })
    }

    /// True when the source is interactive (re-loading prompts the
    /// user again). Non-interactive sources just return the same
    /// bytes on every call, so the caller should only retry on
    /// interactive sources.
    #[must_use]
    pub fn is_interactive(&self) -> bool {
        matches!(self, Self::Prompt)
    }

    /// Human-readable identifier for diagnostics (does not include
    /// the password itself).
    #[must_use]
    pub fn label(&self) -> String {
        match self {
            #[cfg(unix)]
            Self::Prompt => "/dev/tty".to_string(),
            #[cfg(not(unix))]
            Self::Prompt => "console".to_string(),
            Self::Env(name) => format!("env:{}", name.to_string_lossy()),
            Self::File(path) => format!("file:{}", path.display()),
            #[cfg(unix)]
            Self::Fd(fd) => format!("fd:{fd}"),
        }
    }

    /// Load a password from this source.
    ///
    /// `prompt_message` is shown to the user on interactive sources
    /// (e.g. the archive name plus, on retries, a "wrong password"
    /// banner). Ignored for the non-interactive sources.
    ///
    /// # Errors
    /// Returns [`PasswordLoadError`] for IO failures, missing env
    /// vars, empty values, and termios errors.
    pub fn load(&self, prompt_message: &str) -> Result<Password, PasswordLoadError> {
        match self {
            #[cfg(unix)]
            Self::Prompt => prompt_password_tty(prompt_message),
            #[cfg(windows)]
            Self::Prompt => prompt_password_console(prompt_message),
            #[cfg(not(any(unix, windows)))]
            Self::Prompt => {
                let _ = prompt_message;
                Err(PasswordLoadError::PlatformUnsupported {
                    source_kind: "prompt",
                })
            }
            Self::Env(name) => load_from_env(name),
            Self::File(path) => load_from_file(path),
            #[cfg(unix)]
            Self::Fd(fd) => load_from_fd(*fd),
        }
    }
}

fn load_from_env(name: &std::ffi::OsStr) -> Result<Password, PasswordLoadError> {
    let label = format!("env:{}", name.to_string_lossy());
    let value = std::env::var_os(name).ok_or_else(|| PasswordLoadError::EnvNotSet {
        name: name.to_string_lossy().into_owned(),
    })?;
    let raw = os_str_to_bytes(&value);
    let bytes = strip_trailing_eol(&raw);
    if bytes.is_empty() {
        return Err(PasswordLoadError::Empty {
            source_label: label,
        });
    }
    Ok(Password::new(bytes.to_vec()))
}

/// Encode an [`OsStr`] as bytes for password-loading.
///
/// On Unix the byte sequence is the kernel-native representation
/// returned by [`std::os::unix::ffi::OsStrExt::as_bytes`]; non-UTF-8
/// sequences round-trip exactly. On Windows the underlying value is
/// WTF-16 and we encode through `to_string_lossy()` — non-decodable
/// half-surrogates become U+FFFD. Real-world passwords are valid
/// UTF-8 / UTF-16, so the lossy edge case is academic; the
/// alternative (refusing non-UTF-8 input) would surprise users with
/// otherwise-valid passwords containing high-codepoint characters.
fn os_str_to_bytes(s: &std::ffi::OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        s.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        s.to_string_lossy().into_owned().into_bytes()
    }
}

fn load_from_file(path: &Path) -> Result<Password, PasswordLoadError> {
    let label = format!("file:{}", path.display());
    let meta = std::fs::metadata(path).map_err(|source| PasswordLoadError::FileMetadata {
        path: path.to_path_buf(),
        source,
    })?;
    // POSIX mode bits don't exist on Windows (NTFS uses ACLs); the
    // pre-2026-05-15 0600-recommendation warning is therefore
    // skipped on Windows. A `Get-Acl` / `icacls`-based equivalent
    // is filed as a round-two follow-on (see `PLAN_v3_windows.md`
    // §11 round-two list); for now the file's ACL is the user's
    // responsibility on Windows.
    #[cfg(unix)]
    {
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            tracing::warn!(
                path = %path.display(),
                mode = format!("{mode:04o}"),
                "password file is readable by users beyond the owner; \
                 recommended mode is 0600",
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
    }
    let mut file = File::open(path).map_err(|source| PasswordLoadError::Read {
        source_label: label.clone(),
        source,
    })?;
    let bytes = read_password_line(&mut file, &label)?;
    Ok(Password::new(bytes))
}

#[cfg(unix)]
fn load_from_fd(fd: RawFd) -> Result<Password, PasswordLoadError> {
    let label = format!("fd:{fd}");
    // SAFETY: we trust the caller's claim that `fd` is a valid open
    // descriptor — this is a CLI argument the user supplied and the
    // shell handed us. We use `BorrowedFd::borrow_raw` to wrap it
    // without taking ownership, then duplicate so the read-side
    // `File` we create can be dropped (and its dup closed) without
    // closing the caller's original fd.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let owned = borrowed
        .try_clone_to_owned()
        .map_err(|source| PasswordLoadError::Read {
            source_label: label.clone(),
            source,
        })?;
    let mut file = File::from(owned);
    let bytes = read_password_line(&mut file, &label)?;
    Ok(Password::new(bytes))
}

/// Read bytes until '\n' or EOF. Strips a trailing CR, errors on
/// empty input. Used for the file / fd / TTY sources; the env source
/// uses [`strip_trailing_eol`] directly because the variable is
/// already in memory.
pub(crate) fn read_password_line<R: Read>(
    reader: &mut R,
    source_label: &str,
) -> Result<Vec<u8>, PasswordLoadError> {
    // Cap at a generous-but-bounded ceiling so a misconfigured fd
    // can't OOM us. 1 MiB is well past any plausible passphrase.
    const MAX: usize = 1 << 20;
    let mut buf = Vec::with_capacity(64);
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                buf.push(byte[0]);
                if buf.len() >= MAX {
                    return Err(PasswordLoadError::Read {
                        source_label: source_label.to_string(),
                        source: io::Error::new(
                            io::ErrorKind::InvalidData,
                            "password exceeds 1 MiB",
                        ),
                    });
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(source) => {
                return Err(PasswordLoadError::Read {
                    source_label: source_label.to_string(),
                    source,
                });
            }
        }
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    if buf.is_empty() {
        return Err(PasswordLoadError::Empty {
            source_label: source_label.to_string(),
        });
    }
    Ok(buf)
}

/// Strip a single trailing `\n` (or `\r\n`) from a byte slice.
///
/// A bare trailing `\r` is preserved — it is not a line terminator on
/// any platform we care about and may be intentional payload.
fn strip_trailing_eol(bytes: &[u8]) -> &[u8] {
    if let Some(rest) = bytes.strip_suffix(b"\r\n") {
        return rest;
    }
    if let Some(rest) = bytes.strip_suffix(b"\n") {
        return rest;
    }
    bytes
}

// --- TTY password prompt ---------------------------------------------------
//
// The Unix-only block below talks directly to termios via
// `tcgetattr` / `tcsetattr` on `/dev/tty`. The Windows analogue
// (`SetConsoleMode` against `CONIN$` with `ENABLE_ECHO_INPUT`
// cleared) lands in `PLAN_v3_windows.md` §6; until then the
// `Prompt` variant on Windows returns
// `PasswordLoadError::PlatformUnsupported`.

#[cfg(unix)]
/// Bit in `termios::c_lflag` that gates echoing of typed characters.
/// Same numeric value on Linux and macOS.
const ECHO: TcFlag = 0o0000010;

#[cfg(unix)]
/// `tcsetattr` action: drain output, flush input, then apply.
/// Same numeric value on Linux and macOS.
const TCSAFLUSH: c_int = 2;

#[cfg(target_os = "linux")]
type TcFlag = u32;
#[cfg(target_os = "linux")]
type Speed = u32;
#[cfg(target_os = "linux")]
const NCCS: usize = 32;

#[cfg(target_os = "macos")]
type TcFlag = u64;
#[cfg(target_os = "macos")]
type Speed = u64;
#[cfg(target_os = "macos")]
const NCCS: usize = 20;

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
type TcFlag = u32;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
type Speed = u32;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
const NCCS: usize = 32;

/// Layout-compatible mirror of `struct termios`.
///
/// Linux and macOS both place `c_lflag` at the 4th `tcflag_t`-sized
/// slot; the rest of the layout differs in `NCCS` and trailing
/// speed fields. Each platform's `tcflag_t` is also a different
/// width (u32 on Linux, u64 on macOS). The platform-specific
/// `cfg`s above keep this struct binary-compatible with the host's
/// libc `termios`.
#[cfg(unix)]
#[repr(C)]
#[derive(Copy, Clone)]
struct Termios {
    c_iflag: TcFlag,
    c_oflag: TcFlag,
    c_cflag: TcFlag,
    c_lflag: TcFlag,
    #[cfg(target_os = "linux")]
    c_line: u8,
    c_cc: [u8; NCCS],
    c_ispeed: Speed,
    c_ospeed: Speed,
}

#[cfg(unix)]
extern "C" {
    fn tcgetattr(fd: c_int, termios_p: *mut Termios) -> c_int;
    fn tcsetattr(fd: c_int, optional_actions: c_int, termios_p: *const Termios) -> c_int;
}

#[cfg(unix)]
fn errno() -> i32 {
    // SAFETY: `__errno_location` (glibc/musl) and `__error` (macOS)
    // return a thread-local pointer to the integer errno. We
    // dereference it once and copy the value out — no aliasing or
    // lifetime concerns.
    unsafe {
        #[cfg(target_os = "linux")]
        {
            extern "C" {
                fn __errno_location() -> *mut c_int;
            }
            *__errno_location()
        }
        #[cfg(target_os = "macos")]
        {
            extern "C" {
                fn __error() -> *mut c_int;
            }
            *__error()
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        {
            0
        }
    }
}

/// Disables echo on `fd` for the lifetime of the guard. On drop the
/// guard restores the saved termios — covering normal completion
/// and Rust panic-unwinds. An abrupt process death (`SIGKILL`)
/// skips the restore, but in that case the kernel teardown drops
/// the controlling-terminal association anyway and the next shell
/// re-initialises termios on its own prompt.
#[cfg(unix)]
struct NoEchoGuard {
    fd: RawFd,
    saved: Termios,
}

#[cfg(unix)]
impl NoEchoGuard {
    fn install(fd: RawFd) -> Result<Self, PasswordLoadError> {
        let mut saved = blank_termios();
        // SAFETY: `tcgetattr` writes a `struct termios` into the
        // pointer; our `Termios` matches the host libc's layout
        // (see the `#[cfg]` blocks above). `fd` is a valid open
        // descriptor (the caller just opened `/dev/tty`).
        let rc = unsafe { tcgetattr(fd, &mut saved) };
        if rc != 0 {
            return Err(PasswordLoadError::TermiosFailure { errno: errno() });
        }
        let mut modified = saved;
        modified.c_lflag &= !ECHO;
        // SAFETY: `tcsetattr` reads from the pointer; same layout
        // guarantee as above. `TCSAFLUSH` is the documented
        // numeric value on both platforms.
        let rc = unsafe { tcsetattr(fd, TCSAFLUSH, &modified) };
        if rc != 0 {
            return Err(PasswordLoadError::TermiosFailure { errno: errno() });
        }
        Ok(Self { fd, saved })
    }
}

#[cfg(unix)]
impl Drop for NoEchoGuard {
    fn drop(&mut self) {
        // SAFETY: `self.saved` was populated by an earlier
        // successful `tcgetattr`; `self.fd` was valid then and we
        // hold the guard until drop, so it's still valid. We
        // ignore the return value because there's nothing
        // sensible to do on failure inside `Drop`.
        unsafe {
            tcsetattr(self.fd, TCSAFLUSH, &self.saved);
        }
    }
}

#[cfg(unix)]
fn blank_termios() -> Termios {
    Termios {
        c_iflag: 0,
        c_oflag: 0,
        c_cflag: 0,
        c_lflag: 0,
        #[cfg(target_os = "linux")]
        c_line: 0,
        c_cc: [0u8; NCCS],
        c_ispeed: 0,
        c_ospeed: 0,
    }
}

#[cfg(unix)]
fn prompt_password_tty(prompt_message: &str) -> Result<Password, PasswordLoadError> {
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|source| PasswordLoadError::TtyOpen { source })?;
    let fd = tty.as_raw_fd();

    tty.write_all(prompt_message.as_bytes())
        .map_err(|source| PasswordLoadError::TtyWrite { source })?;
    tty.flush().ok();

    let _guard = NoEchoGuard::install(fd)?;
    let bytes = read_password_line(&mut tty, "/dev/tty")?;
    // The user's typed newline was consumed by `read_password_line`
    // but never echoed; we still want to advance the cursor so
    // subsequent output doesn't appear on the prompt line.
    tty.write_all(b"\n").ok();
    Ok(Password::new(bytes))
}

// --- Windows console password prompt --------------------------------
//
// Windows analog of `prompt_password_tty`. Opens the console input
// (`CONIN$`) and console output (`CONOUT$`) device pair, writes the
// prompt to the output stream, and disables `ENABLE_ECHO_INPUT` on
// the input stream for the duration of the read via
// `NoEchoGuardWindows`. The guard restores the previous console mode
// on `Drop` — covering normal completion and Rust panic-unwinds.
// Abrupt termination (`TerminateProcess` / `ExitProcess` from a
// console-ctrl handler) skips the restore; that's the same Unix
// posture (a `SIGKILL` skips `tcsetattr`) and the OS resets the
// console mode on the next shell prompt anyway.
//
// `CONIN$` / `CONOUT$` are special filenames the Win32 layer routes
// to the process's attached console regardless of stdin/stdout
// redirection — equivalent to Unix's `/dev/tty`. We open them via
// the high-level `std::fs::OpenOptions` API so error reporting goes
// through `io::Error` consistently with the rest of the codebase.
// (`PLAN_v3_windows.md` §6.)
#[cfg(windows)]
fn prompt_password_console(prompt_message: &str) -> Result<Password, PasswordLoadError> {
    use std::io::Write as _;

    let mut conin = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("CONIN$")
        .map_err(|source| PasswordLoadError::TtyOpen { source })?;
    let mut conout = std::fs::OpenOptions::new()
        .write(true)
        .open("CONOUT$")
        .map_err(|source| PasswordLoadError::TtyOpen { source })?;

    conout
        .write_all(prompt_message.as_bytes())
        .map_err(|source| PasswordLoadError::TtyWrite { source })?;
    conout.flush().ok();

    let _guard = NoEchoGuardWindows::install(&conin)?;
    let bytes = read_password_line(&mut conin, "CONIN$")?;

    // Mirror the Unix path's trailing newline so subsequent output
    // doesn't land on top of the prompt line.
    conout.write_all(b"\r\n").ok();
    Ok(Password::new(bytes))
}

/// `ENABLE_ECHO_INPUT` from `<wincon.h>`. Numeric value is part of
/// the stable console-mode ABI. Declared locally rather than pulled
/// from `windows-sys`'s `Win32_System_Console` constants list so
/// the import surface stays minimal — same precedent as
/// `punch::macos::F_PUNCHHOLE`.
#[cfg(windows)]
const ENABLE_ECHO_INPUT: u32 = 0x0004;

/// Disables `ENABLE_ECHO_INPUT` on a Windows console handle for the
/// guard's lifetime, restoring the saved console mode on `Drop`.
#[cfg(windows)]
struct NoEchoGuardWindows {
    handle: std::os::windows::io::RawHandle,
    saved_mode: u32,
}

#[cfg(windows)]
impl NoEchoGuardWindows {
    fn install(conin: &File) -> Result<Self, PasswordLoadError> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Console::{GetConsoleMode, SetConsoleMode};

        let handle = conin.as_raw_handle();
        let mut saved_mode: u32 = 0;
        // SAFETY: `conin` is borrowed for the duration of this call,
        // so the raw handle is valid. `GetConsoleMode` writes a
        // `u32` through the pointer on success.
        let rc = unsafe { GetConsoleMode(handle as _, &mut saved_mode) };
        if rc == 0 {
            return Err(PasswordLoadError::ConsoleModeFailure {
                source: io::Error::last_os_error(),
            });
        }
        let new_mode = saved_mode & !ENABLE_ECHO_INPUT;
        // SAFETY: same handle-lifetime argument; `SetConsoleMode`
        // takes a `u32` mode by value.
        let rc = unsafe { SetConsoleMode(handle as _, new_mode) };
        if rc == 0 {
            return Err(PasswordLoadError::ConsoleModeFailure {
                source: io::Error::last_os_error(),
            });
        }
        Ok(Self { handle, saved_mode })
    }
}

#[cfg(windows)]
impl Drop for NoEchoGuardWindows {
    fn drop(&mut self) {
        use windows_sys::Win32::System::Console::SetConsoleMode;
        // SAFETY: `self.handle` was valid when the guard was
        // installed and the guard is dropped before the `File` is
        // closed (the `File` outlives `_guard` in
        // `prompt_password_console`'s caller). We ignore the return
        // value because there's nothing sensible to do on failure
        // inside `Drop`.
        unsafe {
            SetConsoleMode(self.handle as _, self.saved_mode);
        }
    }
}

// The existing test module assumes a Unix-only build: it uses
// `RawFd`, `pipe(2)`, the termios machinery, and tests the
// `Fd(RawFd)` variant. `PLAN_v3_windows.md` §3 lifts the file-level
// `cfg(unix)`, so the parse tests *could* run cross-platform, but
// splitting them out is a §6 task (paired with adding Windows-side
// `SetConsoleMode` echo-off tests). Until then the existing tests
// stay Unix-only; cross-platform parse coverage is exercised
// indirectly via `cli` tests.
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn parse_prompt() {
        let s = PasswordSource::parse("prompt").unwrap();
        assert!(matches!(s, PasswordSource::Prompt));
        assert!(s.is_interactive());
    }

    #[test]
    fn parse_env() {
        let s = PasswordSource::parse("env:PEEL_PW").unwrap();
        match s {
            PasswordSource::Env(name) => assert_eq!(name, OsString::from("PEEL_PW")),
            other => panic!("expected Env, got {other:?}"),
        }
    }

    #[test]
    fn parse_env_empty_name_rejected() {
        let err = PasswordSource::parse("env:").unwrap_err();
        assert!(matches!(err, PasswordSourceParseError::EmptyEnvName));
    }

    #[test]
    fn parse_file() {
        let s = PasswordSource::parse("file:/tmp/pw").unwrap();
        match s {
            PasswordSource::File(p) => assert_eq!(p, PathBuf::from("/tmp/pw")),
            other => panic!("expected File, got {other:?}"),
        }
    }

    #[test]
    fn parse_file_empty_path_rejected() {
        let err = PasswordSource::parse("file:").unwrap_err();
        assert!(matches!(err, PasswordSourceParseError::EmptyFilePath));
    }

    #[test]
    fn parse_fd() {
        let s = PasswordSource::parse("fd:7").unwrap();
        match s {
            PasswordSource::Fd(n) => assert_eq!(n, 7),
            other => panic!("expected Fd, got {other:?}"),
        }
    }

    #[test]
    fn parse_fd_negative_rejected() {
        let err = PasswordSource::parse("fd:-1").unwrap_err();
        assert!(matches!(err, PasswordSourceParseError::InvalidFd { .. }));
    }

    #[test]
    fn parse_fd_non_numeric_rejected() {
        let err = PasswordSource::parse("fd:abc").unwrap_err();
        assert!(matches!(err, PasswordSourceParseError::InvalidFd { .. }));
    }

    #[test]
    fn parse_unknown_scheme() {
        let err = PasswordSource::parse("stdin").unwrap_err();
        assert!(matches!(
            err,
            PasswordSourceParseError::UnknownScheme { .. }
        ));
    }

    #[test]
    fn is_interactive_only_for_prompt() {
        assert!(PasswordSource::Prompt.is_interactive());
        assert!(!PasswordSource::Env(OsString::from("X")).is_interactive());
        assert!(!PasswordSource::File(PathBuf::from("/x")).is_interactive());
        assert!(!PasswordSource::Fd(3).is_interactive());
    }

    #[test]
    fn label_does_not_leak_value() {
        // No source carries password bytes themselves; the label is
        // safe to log.
        assert_eq!(PasswordSource::Prompt.label(), "/dev/tty");
        assert_eq!(PasswordSource::Env(OsString::from("PW")).label(), "env:PW");
        assert_eq!(
            PasswordSource::File(PathBuf::from("/tmp/pw")).label(),
            "file:/tmp/pw"
        );
        assert_eq!(PasswordSource::Fd(5).label(), "fd:5");
    }

    #[test]
    fn read_line_strips_lf() {
        let mut c = Cursor::new(b"hunter2\n".to_vec());
        let bytes = read_password_line(&mut c, "test").unwrap();
        assert_eq!(bytes, b"hunter2");
    }

    #[test]
    fn read_line_strips_crlf() {
        let mut c = Cursor::new(b"hunter2\r\n".to_vec());
        let bytes = read_password_line(&mut c, "test").unwrap();
        assert_eq!(bytes, b"hunter2");
    }

    #[test]
    fn read_line_eof_without_newline() {
        let mut c = Cursor::new(b"hunter2".to_vec());
        let bytes = read_password_line(&mut c, "test").unwrap();
        assert_eq!(bytes, b"hunter2");
    }

    #[test]
    fn read_line_empty_errors() {
        let mut c = Cursor::new(b"\n".to_vec());
        let err = read_password_line(&mut c, "test").unwrap_err();
        assert!(matches!(err, PasswordLoadError::Empty { .. }));
    }

    #[test]
    fn read_line_eof_immediate_errors() {
        let mut c = Cursor::new(Vec::<u8>::new());
        let err = read_password_line(&mut c, "test").unwrap_err();
        assert!(matches!(err, PasswordLoadError::Empty { .. }));
    }

    #[test]
    fn read_line_caps_at_1_mib() {
        let mut data = vec![b'a'; (1 << 20) + 10];
        data.push(b'\n');
        let mut c = Cursor::new(data);
        let err = read_password_line(&mut c, "test").unwrap_err();
        assert!(matches!(err, PasswordLoadError::Read { .. }));
    }

    #[test]
    fn strip_eol_handles_lf_crlf_and_bare() {
        assert_eq!(strip_trailing_eol(b"abc"), b"abc");
        assert_eq!(strip_trailing_eol(b"abc\n"), b"abc");
        assert_eq!(strip_trailing_eol(b"abc\r\n"), b"abc");
        assert_eq!(strip_trailing_eol(b"abc\r"), b"abc\r"); // bare CR untouched
        assert_eq!(strip_trailing_eol(b""), b"");
    }

    #[test]
    fn load_env_reads_value() {
        // Use a per-test variable so we don't race with other tests.
        let name = "PEEL_TEST_PASSWORD_LOAD_ENV";
        // SAFETY: we set then read; this is the documented one-thread
        // contract of `std::env::set_var`. The cargo test runner can
        // execute tests in parallel, but each one uses a unique
        // variable name so concurrent set/unset is fine for *other*
        // variables.
        unsafe {
            std::env::set_var(name, "hunter2");
        }
        let src = PasswordSource::Env(OsString::from(name));
        let pw = src.load("prompt-unused").unwrap();
        assert_eq!(pw.as_bytes(), b"hunter2");
        unsafe {
            std::env::remove_var(name);
        }
    }

    #[test]
    fn load_env_missing_errors() {
        let name = "PEEL_TEST_PASSWORD_LOAD_ENV_MISSING";
        unsafe {
            std::env::remove_var(name);
        }
        let src = PasswordSource::Env(OsString::from(name));
        let err = src.load("p").unwrap_err();
        assert!(matches!(err, PasswordLoadError::EnvNotSet { .. }));
    }

    #[test]
    fn load_env_strips_trailing_lf() {
        let name = "PEEL_TEST_PASSWORD_LOAD_ENV_LF";
        unsafe {
            std::env::set_var(name, "hunter2\n");
        }
        let src = PasswordSource::Env(OsString::from(name));
        let pw = src.load("p").unwrap();
        assert_eq!(pw.as_bytes(), b"hunter2");
        unsafe {
            std::env::remove_var(name);
        }
    }

    #[test]
    fn load_env_empty_errors() {
        let name = "PEEL_TEST_PASSWORD_LOAD_ENV_EMPTY";
        unsafe {
            std::env::set_var(name, "");
        }
        let src = PasswordSource::Env(OsString::from(name));
        let err = src.load("p").unwrap_err();
        assert!(matches!(err, PasswordLoadError::Empty { .. }));
        unsafe {
            std::env::remove_var(name);
        }
    }

    #[test]
    fn load_file_reads_first_line() {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = TempDirGuard::new("file_first_line");
        let path = dir.path().join("pw");
        {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .mode(0o600)
                .open(&path)
                .unwrap();
            f.write_all(b"hunter2\nignored second line\n").unwrap();
        }
        let pw = PasswordSource::File(path).load("p").unwrap();
        assert_eq!(pw.as_bytes(), b"hunter2");
    }

    #[test]
    fn load_file_missing_errors() {
        let dir = TempDirGuard::new("file_missing");
        let path = dir.path().join("nope");
        let err = PasswordSource::File(path).load("p").unwrap_err();
        assert!(matches!(err, PasswordLoadError::FileMetadata { .. }));
    }

    #[test]
    fn load_file_empty_errors() {
        let dir = TempDirGuard::new("file_empty");
        let path = dir.path().join("empty");
        std::fs::File::create(&path).unwrap();
        let err = PasswordSource::File(path).load("p").unwrap_err();
        assert!(matches!(err, PasswordLoadError::Empty { .. }));
    }

    #[test]
    fn load_fd_reads_from_pipe() {
        // Create a pipe via pipe(2). Write a password into the
        // write end; load() the read end via Fd.
        let (read_fd, write_fd) = make_pipe();
        // Write the password to the write end and close it so the
        // reader sees EOF.
        {
            // SAFETY: we own write_fd here, having just created it.
            let mut writer = unsafe { File::from(std::os::fd::OwnedFd::from_raw_fd(write_fd)) };
            writer.write_all(b"hunter2\n").unwrap();
            // File drop closes the fd.
        }
        let pw = PasswordSource::Fd(read_fd).load("p").unwrap();
        assert_eq!(pw.as_bytes(), b"hunter2");
        // We didn't own read_fd via the load (it duped); close it now.
        // SAFETY: the load duplicated read_fd and closed the dup; the
        // original is still open and we own it for this scope.
        unsafe {
            let _ = std::os::fd::OwnedFd::from_raw_fd(read_fd);
        }
    }

    #[test]
    fn load_fd_eof_errors() {
        let (read_fd, write_fd) = make_pipe();
        // Close write end immediately so the read sees EOF.
        // SAFETY: we own write_fd here.
        unsafe {
            drop(std::os::fd::OwnedFd::from_raw_fd(write_fd));
        }
        let err = PasswordSource::Fd(read_fd).load("p").unwrap_err();
        assert!(matches!(err, PasswordLoadError::Empty { .. }));
        // SAFETY: we still own read_fd.
        unsafe {
            drop(std::os::fd::OwnedFd::from_raw_fd(read_fd));
        }
    }

    use std::os::fd::FromRawFd;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Unique-name tempdir helper matching the in-tree style
    /// (`src/sink/sevenz.rs` carries the same pattern). `tempfile`
    /// is on the allowlist as a dev-dep but not added to
    /// `Cargo.toml`; the existing convention is to roll the few
    /// lines needed here rather than pull the dependency for
    /// trivial tests.
    struct TempDirGuard {
        path: PathBuf,
    }

    impl TempDirGuard {
        fn new(label: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let pid = std::process::id();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!("peel_secret_{label}_{pid}_{nanos}_{n}"));
            std::fs::create_dir_all(&path).expect("create tempdir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// Test helper: create a pipe via the libc `pipe` syscall.
    /// Returns (read_fd, write_fd) on success; panics on failure.
    fn make_pipe() -> (RawFd, RawFd) {
        extern "C" {
            fn pipe(fds: *mut RawFd) -> c_int;
        }
        let mut fds = [-1, -1];
        // SAFETY: `pipe` writes two file descriptors into the
        // 2-element buffer; we provide a stack array of that size.
        let rc = unsafe { pipe(fds.as_mut_ptr()) };
        assert_eq!(rc, 0, "pipe(2) failed (errno {})", errno());
        (fds[0], fds[1])
    }
}
