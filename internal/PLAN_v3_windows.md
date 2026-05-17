## Plan: peel Windows support

> **Status: drafted 2026-05-15, not yet started.** Successor plan covering
> `OPTIMIZATIONS.md` `O.15` (Windows sparse files + `FSCTL_SET_ZERO_DATA`).
> Promoted *deliberately* per the rule at the top of `OPTIMIZATIONS.md`.
> Do not pull other items from `OPTIMIZATIONS.md` while this plan is in
> flight — finish a phase, demo it, then move on.

The end state: `peel` is a first-class Windows citizen. The north-star
command from `PLAN.md` works on `x86_64-pc-windows-msvc`, including
crash-resume and NTFS hole-punching. Linux and macOS behavior is
unchanged.

The same sequencing discipline as `PLAN.md` / `PLAN_v2.md` applies: each
phase ends with a runnable demo, and §N+1 does not begin until §N's demo
passes.

---

## Hard constraints

- **Existing platforms must not regress.** Every phase below adds or
  abstracts code; nothing in this plan removes a Linux or macOS code
  path. The crash-test harness, `cargo clippy --all-targets
  --all-features -- -D warnings`, and `cargo test --all-features` stay
  green on Linux and macOS at every commit.
- **One new dependency: `windows-sys`.** Phase 0 amends
  `ENGINEERING_STANDARDS.md` §2.2 to allow it (Microsoft-maintained,
  no transitive deps, the canonical Win32 binding crate). No other
  Windows-specific crates land in this plan; everything else is direct
  `extern "system"` declarations or the equivalent through
  `windows-sys`. `windows-sys` is gated as a Windows-target dependency
  in `Cargo.toml` so non-Windows builds do not change their dependency
  closure.
- **No async runtime.** `tokio` stays confined to `http::client` per
  `ENGINEERING_STANDARDS.md` §2.5; no Windows code in this plan reaches
  for `async`.
- **Backwards-compatible checkpoints.** Checkpoint format does not
  change in this plan. A `.peel.ckpt` written on Linux must resume on
  Windows and vice versa (modulo path differences in the saved sink
  state, which is already kept platform-portable via `Vec<u8>` blobs).
- **No symlink / permission semantics regressions on Unix.** The
  existing `sink/tar.rs` does not extract symlinks and does not set
  POSIX modes (`OPTIMIZATIONS.md` `O.23`, `O.25` — deferred). This
  plan preserves that behavior on every platform; Windows extraction
  has the same surface area, no more, no less.

## What this plan deliberately does not include

- Windows-specific extras beyond the parity bar: ACLs, NTFS alternate
  data streams, junctions, reparse points, code-page conversions of
  archive entry names, `\\?\` long-path opt-in. All of these are
  filed as round-two follow-ons in §11 below.
- macOS-only or Linux-only optimization items still listed in
  `OPTIMIZATIONS.md`. They remain deferred.
- A Windows `io_uring`-style backend. `IoBackendChoice::Uring` and
  `IoBackendChoice::Mmap` stay Linux-only; on Windows they error
  exactly the way `Uring` errors on macOS today.
- Daemon / library mode (`O.16`), HTTP/3 (`O.17`), pluggable
  destinations (`O.18`). Out of scope.

---

## Phase 0 — Cross-cutting prerequisites

### §0.1 Dependency-policy amendment

**What**: amend `internal/ENGINEERING_STANDARDS.md` §2.2 to add
`windows-sys` to the allowlist. The new row reads, in the same style
as `io-uring`:

| Crate          | Role                                        | Notes                                |
|----------------|---------------------------------------------|--------------------------------------|
| `windows-sys`  | Microsoft-maintained Win32 bindings         | Windows only; declared in `[target.'cfg(windows)'.dependencies]` to keep non-Windows builds unchanged; `PLAN_v3_windows.md` §0.1 |

**Why**: Hand-rolling `extern "system"` declarations for the dozens of
Win32 surfaces we touch (`DeviceIoControl`, `FSCTL_SET_SPARSE`,
`FSCTL_SET_ZERO_DATA`, `FILE_ZERO_DATA_INFORMATION`,
`SetConsoleCtrlHandler`, `GetConsoleMode` / `SetConsoleMode`,
`GetStdHandle`, `WriteFile` with `OVERLAPPED`, `FlushFileBuffers`,
`CreateFileW` with UTF-16 paths, `FILE_STANDARD_INFORMATION`) is
realistic for one or two surfaces (the way `punch.rs::macos` declares
`fcntl`) but error-prone at the scale of a full port. `windows-sys` is
Microsoft-maintained, has zero transitive dependencies, and is the
canonical Win32 binding crate. The exception is the same shape as
`rustls` (TLS) and `io-uring` (Linux-only): a load-bearing OS surface
where hand-rolling is not a reasonable use of human time.

**Sketch**:

1. Edit `internal/ENGINEERING_STANDARDS.md` §2.2 to add the row.
2. Edit `Cargo.toml`:
   ```toml
   [target.'cfg(windows)'.dependencies]
   windows-sys = { version = "0.59", features = [
       "Win32_Foundation",
       "Win32_Storage_FileSystem",
       "Win32_System_IO",
       "Win32_System_Console",
       "Win32_System_Threading",
       "Win32_Security",
   ] }
   ```
   Exact feature list is finalized in later phases; this is the
   anchor.
3. Update `internal/PLAN.md`'s "Linux first" note and
   `OPTIMIZATIONS.md`'s `O.15` entry to point at this plan.

**Demo**: `cargo build --target x86_64-pc-windows-msvc` produces a
binary that builds the `windows-sys` crate. (No semantic change yet —
this is only the dependency landing.)

---

### §0.2 Portable file-handle abstraction

**What**: introduce a portable handle wrapper used by every trait that
currently takes `BorrowedFd<'_>`.

**Why now**: today `PunchHole::punch`, every method on `IoBackend`,
and `SparseFile::punch` take `BorrowedFd<'_>` directly. That type is
Unix-only by definition. Without an abstraction here, every Windows
phase below would carry its own ad-hoc `#[cfg]` arm at every call
site.

**Sketch**:

1. Add `src/os_fd.rs` exporting:
   ```rust
   #[cfg(unix)]
   pub type OsFd<'a> = std::os::fd::BorrowedFd<'a>;
   #[cfg(windows)]
   pub type OsFd<'a> = std::os::windows::io::BorrowedHandle<'a>;
   ```
   plus a small `AsOsFd` trait re-exporting `AsFd` on Unix and
   `AsHandle` on Windows. Both backing types are already in `std`;
   `OsFd<'_>` is `Copy + Send + Sync` on both platforms.
2. Replace `BorrowedFd<'_>` with `OsFd<'_>` in every trait
   signature: `PunchHole::punch`, `IoBackend::pwrite_all_at`,
   `IoBackend::pread_at`, `IoBackend::pread_exact_at`,
   `IoBackend::sync_all`, `IoBackend::order_writes`,
   `crate::io_backend::order_writes_blocking`,
   `SparseFile::punch`, every Linux/macOS impl. Unix call sites stay
   unchanged (just an alias swap); the macro at the top of each
   `#![cfg(unix)]` module still keeps the bodies Unix-only.
3. Re-export `AsOsFd` from `lib.rs`. The two existing Linux/macOS
   puncher impls keep their `extern "C"` and `as_raw_fd()` internals;
   the trait surface is the only thing that changes.

**Demo**: every existing test on Linux + macOS still passes after
the type alias swap. `cargo clippy --all-targets --all-features --
-D warnings` clean on both platforms.

---

### §0.3 CI matrix

**What**: add `windows-2022` to `.github/workflows/ci.yml`. Gate the
io_uring-specific tests on Linux only (they already are; this is just
confirming the matrix split).

The Windows job lands incrementally. Until §3 ungates the consumer
modules, `http::response::BodyReader::{empty,streaming}` and
`BodyState::{Empty,Streaming}` are unreachable on Windows and trip
`#[warn(unused)]`; AGENTS.md forbids `#[allow(dead_code)]` to silence
warnings, and §3 is the real fix. So:

- **Land §0.3**: `cargo fmt --check` + `cargo build --no-default-features`
  + `cargo build` (default features). No clippy yet, no test run yet.
  Demos that the matrix entry plumbing works.
- **Promote in §2** (`io_backend` Windows blocking impl): add
  `cargo test --lib` so the unit tests for the bits that already
  compile run on Windows.
- **Promote in §3** (gate lift): turn on `cargo clippy --all-targets
  -- -D warnings`. With the gates lifted the dead-code warnings are
  resolved by use, and the gate matches the project standard.
- **Promote in §4** (real puncher): add `cargo test --all-features`
  (default features only — `system-libs` enables `zstd-sys`'s
  `pkg-config` probe which has no Windows analog in CI without
  custom vcpkg setup, filed as `O.WIN.PKGCFG` round-two follow-on).

Crash tests stay Linux-only until §10 promotes the harness.

**Demo**: a green CI run on Windows for an empty no-op PR that
touches only the workflow file. (`fmt + build` only; clippy and test
expand in §2/§3/§4 as written above.)

---

## Phase A — Make the binary build on Windows

The five phases in this block lift the `#![cfg(unix)]` gates one
subsystem at a time. By the end of Phase A, `peel.exe` exists and
runs — with `NoopPuncher`, so the source file is held on disk for the
full extraction. Phase B is where the real puncher lands.

### §1. Punch trait portability + Windows `NoopPuncher` path

**What**: remove `#![cfg(unix)]` from `src/punch.rs`. The trait body,
`NoopPuncher`, `align_down`, `align_up`, and `PunchError` compile on
every platform. The Linux and macOS impls stay in their existing
`#[cfg(target_os = …)]` modules. `default_puncher()` on Windows
returns `NoopPuncher` (Phase 4 swaps in `WindowsPuncher`).

**Sketch**:

1. Replace `#![cfg(unix)]` at the top of `punch.rs` with module-level
   `#[cfg(target_os = "linux")]` / `#[cfg(target_os = "macos")]` on
   the two impl modules. Trait + Noop + align helpers compile
   everywhere.
2. `default_puncher()` grows a `#[cfg(target_os = "windows")]` arm
   returning `Box::new(NoopPuncher::new())`.
3. Pull `MmapHandle` and `for_mmap` behind `#[cfg(target_os =
   "linux")]` if they aren't already; verify on macOS first.
4. Doc updates: §Other platforms note becomes "Windows uses
   `WindowsPuncher` in §4 below; until then the default is
   `NoopPuncher`."

**Demo**: `cargo build --target x86_64-pc-windows-msvc -p peel-rs
--lib` builds `punch.rs` on Windows. Trait + `NoopPuncher` +
alignment unit tests pass on Windows.

---

### §2. `IoBackend` Windows blocking impl

**What**: remove `#![cfg(unix)]` from `src/io_backend.rs`. Provide a
Windows `BlockingBackend` impl. `IoBackendChoice::{Uring, Mmap}`
error on Windows the same way `Uring` errors on macOS today.

**Sketch**:

1. Lift `#![cfg(unix)]` and switch the trait to use `OsFd<'_>` (§0.2).
2. Windows `BlockingBackend` methods:
   - `pwrite_all_at` / `pread_at` / `pread_exact_at`: wrap the borrowed
     handle in a `ManuallyDrop<File>` via `File::from_raw_handle` (mirrors
     the Unix `with_file` pattern) and call
     `std::os::windows::fs::FileExt::seek_write` / `seek_read`. Both have
     the same "does not advance the kernel-side position" semantics as
     POSIX `pwrite`/`pread` and are safe to call concurrently from
     multiple threads against the same handle.
   - `sync_all`: `FlushFileBuffers(handle)` via `windows-sys`. Same
     contract as `File::sync_all` (which calls `FlushFileBuffers`
     under the hood).
   - `order_writes`: same as `sync_all` on Windows. NTFS does not
     expose a cheaper barrier primitive analogous to `fdatasync` /
     `F_BARRIERFSYNC`; the checkpoint write path simply pays the
     full sync cost on Windows. Documented in the impl.
   - `connect`: `TcpStream::connect_timeout` + `set_read_timeout` /
     `set_write_timeout` / `set_nodelay` — identical to the Unix
     impl, no `#[cfg]` needed.
3. `select_mmap_socket` and `select_uring` on Windows error with the
   same shape they do on macOS today (`io::Error::other(...)`
   naming Linux as the only supported platform).
4. `select_auto` on Windows returns the blocking backend with a
   "io_backend=blocking (uring is Linux-only)" label — same as
   macOS.

**Demo**: every cross-platform test in `io_backend::tests` (excluding
the existing `select_uring_errors_on_non_linux` test, which becomes
`select_uring_errors_off_linux`) passes on Windows. A new
Windows-only test confirms `FlushFileBuffers` succeeds on a freshly
truncated file.

---

### §3. `SparseFile` + downstream gate lift

**What**: lift `#![cfg(unix)]` from `src/download/sparse_file.rs`,
`src/download.rs` and the entire `src/download/*` tree (except the
Linux-only `mmap_region.rs` and `chunk_policy.rs`'s `unix` bits if
any), `src/extractor.rs`, `src/coordinator.rs`, `src/coordinator/`,
`src/multivolume.rs`, `src/cli.rs`. After this phase the library
half compiles on Windows.

**Sketch**:

1. Switch every `BorrowedFd<'_>` in these files to `OsFd<'_>`
   (mechanical sweep). `AsFd` callers become `AsOsFd`.
2. `SparseFile::open_or_create` calls
   `DeviceIoControl(handle, FSCTL_SET_SPARSE, …)` immediately after
   creating the file on Windows. Without this, NTFS treats every
   subsequent write as a normal allocation — even before any
   punching happens we want the holes (the file is created with the
   target size via `set_len`, which zero-extends; the
   `FSCTL_SET_SPARSE` tells NTFS to keep those zero pages
   unallocated).
3. `mmap_region` stays `#[cfg(target_os = "linux")]`. Every
   `SparseFile::open_or_create_mmap` call site is already gated on
   the `Mmap` choice failing on non-Linux per §2 above.
4. Multivolume / chunk-policy / rate-limit etc. should drop their
   `#![cfg(unix)]` and just work — they're pure Rust on top of the
   abstractions above.
5. `cli.rs` drops `#![cfg(unix)]`. Any `--io-backend` parsing that
   referenced Linux-only choices in help text adds a Windows note.

**Demo**: `cargo build --target x86_64-pc-windows-msvc -p peel-rs
--lib` builds the entire library. The cross-platform tests in
`download::*` (those not gated on io_uring or mmap) pass on
Windows.

---

### §4. NTFS hole-punching puncher (`WindowsPuncher`)

**What**: real Windows analog of `LinuxPuncher` / `MacosPuncher`.
Calls `DeviceIoControl(FSCTL_SET_ZERO_DATA, …)` with a
`FILE_ZERO_DATA_INFORMATION` argument struct.

**Sketch**:

1. New module `mod windows` inside `src/punch.rs`:
   ```rust
   #[repr(C)]
   struct FileZeroDataInformation {
       file_offset: i64,
       beyond_final_zero: i64,
   }
   ```
   Plus a hand-typed `pub struct WindowsPuncher;` (zero-sized) with
   the trait impl.
2. `punch` body: `DeviceIoControl(handle, FSCTL_SET_ZERO_DATA,
   &arg, size, null, 0, &bytes_returned, null)`. NTFS requires the
   file have the sparse attribute set (done in §3); non-NTFS volumes
   and network mounts return `ERROR_INVALID_FUNCTION` (1),
   `ERROR_NOT_SUPPORTED` (50), or `ERROR_INVALID_PARAMETER` (87),
   all mapped to `PunchError::Unsupported`. Other Win32 error codes
   surface as `PunchError::Io` via
   `io::Error::from_raw_os_error(…)`.
3. `block_size_hint` returns 4096. The actual NTFS cluster size
   varies (`FSUTIL fsinfo ntfsinfo C:` reports it); we accept 4096
   as a safe lower bound and revisit if a profile shows it
   load-bearing (filed as a follow-on).
4. `default_puncher()` on Windows now returns
   `Box::new(WindowsPuncher::new())`.
5. Integration test: create a sparse file, write 16 MiB, punch the
   first 8 MiB, verify the on-disk allocation dropped via
   `GetFileInformationByHandleEx` with
   `FileStandardInfo`/`AllocationSize` (or
   `GetCompressedFileSize`). Same shape as the
   `linux_puncher_actually_releases_blocks` test.

**Demo**: a 100 MiB sparse file shrinks to ~0 on-disk allocation
after a full-range punch, while `len()` stays at 100 MiB. On a
FAT32 USB stick the test verifies a graceful `Unsupported` and
continues.

---

### §5. Signal handling parity in `main.rs`

**What**: lift `#![cfg(unix)]` from `src/main.rs`. Provide a Windows
signal-handler equivalent that flips the same kill switch the Unix
path flips today.

**Sketch**:

1. Move the existing Unix `signal(2)` FFI into
   `mod unix_signals { #[cfg(unix)] ... }`. Move the
   `install_signal_handlers` / `shutdown_handler` / `signal_name`
   functions behind `#[cfg(unix)]`.
2. New `mod windows_signals { #[cfg(windows)] ... }`:
   - `extern "system" fn console_ctrl_handler(ctrl_type: u32) ->
     BOOL` calls into a counterpart of `shutdown_handler` that
     does the same atomic count + kill-switch flip + best-effort
     `WriteFile` to stderr. The second delivery calls `ExitProcess`
     (Windows analog of `_exit`). Async-signal-safe constraints are
     looser on Windows — the handler runs on a dedicated worker
     thread, not the main thread — but we keep the no-allocation /
     no-formatting discipline anyway since it's cheap.
   - `install_signal_handlers` calls `SetConsoleCtrlHandler(Some(
     console_ctrl_handler), TRUE)`. We register for `CTRL_C_EVENT`,
     `CTRL_BREAK_EVENT`, and `CTRL_CLOSE_EVENT`; the latter is the
     console-window close (the user clicking the X), which has a
     ~5 second timeout before Windows kills the process. Our
     graceful watchdog (`install_graceful_watchdog`) already
     handles the timeout escalation; we just have to make sure
     `cleanup_done` flips before the watchdog deadline.
   - The graceful-deadline watchdog stays unchanged (it's pure
     Rust + `std::thread::sleep`).
3. Exit-code convention on Windows: keep `128 + 2 = 130` for
   `CTRL_C_EVENT` (matches the conventional Unix code so scripts
   still recognize it). `CTRL_BREAK_EVENT` → 131. `CTRL_CLOSE_EVENT`
   → 130 (we treat it as "user wants out, treat as Ctrl+C"). The
   `_exit`-equivalent is `ExitProcess(exit_code)`. The fall-through
   `signal_name` returns the same `"SIGINT"` / `"SIGTERM"` labels
   on Unix; on Windows we use `"CTRL_C"` / `"CTRL_BREAK"` /
   `"CTRL_CLOSE"` for the `[abort]` line.
4. Document the CTRL_CLOSE_EVENT 5-second hard timeout in the
   handler doc comment so a future reader knows why the watchdog
   exists.

**Demo**: a Windows integration test that spawns `peel.exe` against
a local fixture and sends `CTRL_C_EVENT` via
`GenerateConsoleCtrlEvent` — verifies the process exits with code
130, the `.peel.part` / `.peel.ckpt` files exist on disk, and a
follow-up run resumes byte-identically.

---

## Phase B — Parity polish

### §6. Password-prompt parity in `secret/source.rs`

**What**: implement the Windows analog of the termios echo-disable
guard.

**Sketch**:

1. Pull the existing termios path behind `#[cfg(unix)]`.
2. New `#[cfg(windows)]` `prompt_password_tty`:
   - Open `CONIN$` for read/write via `File::open`/`OpenOptions`
     (kernel-level "console input"). Fallback: stdin if `CONIN$`
     fails (matches the Unix fallback shape).
   - `GetConsoleMode(handle, &mut mode)`; save the mode; call
     `SetConsoleMode(handle, mode & !ENABLE_ECHO_INPUT)`.
   - Drop guard restores the saved mode.
   - Read the password line. CRLF (Windows line endings on console
     input) is trimmed.
3. The `PasswordLoadError::TermiosFailure { errno }` variant grows
   a Windows arm or we rename to `ConsoleModeFailure { os_error
   }` — variant naming finalized at implementation time.

**Demo**: a Windows-host test (gated on a real console available, or
mocked) that asserts the prompt path runs without echo. The
encryption end-to-end test (`tests/test_archive_encryption.rs`)
runs on Windows.

---

### §7. ANSI on Windows in `progress.rs`

**What**: enable ANSI sequence processing on the Windows stderr
console so the TTY renderer's redraws work.

**Sketch**:

1. At `TtyRenderer::new`, call (Windows only)
   `SetConsoleMode(stderr, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING
   | DISABLE_NEWLINE_AUTO_RETURN)`. If `SetConsoleMode` fails
   (Windows 8 / Server 2012 R2 — released 2013, still in some LTS
   environments), the renderer can't safely draw ANSI; the binary
   should fall back to the log renderer. To enforce this, the
   renderer-selection logic in `main.rs` calls a new helper
   `peel::progress::tty_supports_ansi()` that returns `false` when
   the mode-set fails on Windows; if `false`, `main` uses
   `LogRenderer` instead. On Unix the helper always returns `true`
   (modern Unix terminals support ANSI; the renderer never tried to
   verify before).
2. Restore the saved console mode on drop, the same way the
   password-prompt guard does — otherwise a `Ctrl+C` mid-redraw
   leaves the terminal with the wrong mode.
3. Document in the renderer module that Windows 10 1607+ is
   required for the TTY redraw; older Windows falls back to the
   structured-log path.

**Demo**: a screenshot from Windows Terminal showing a clean
progress redraw during a real download. On older Windows the
fallback log renderer is exercised by a test that mocks the
mode-set failure.

---

### §8. Path safety in `sink/tar.rs`

**What**: extend the existing path-escape rejection in `TarSink` to
cover NTFS reserved characters and reserved names, so a malicious
archive cannot create a file the OS later misinterprets.

**Sketch**:

1. After the existing absolute-path / `..`-traversal checks, on
   Windows additionally reject entry names containing:
   - Reserved characters `< > : " | ? *` and ASCII controls `\x00-
     \x1F`.
   - Backslashes (tar uses `/` exclusively; a `\\` in an entry name
     on Windows would form a directory boundary).
   - Trailing `.` or trailing space on any path component.
   - Reserved DOS names (case-insensitively): `CON`, `PRN`, `AUX`,
     `NUL`, `COM0` – `COM9`, `LPT0` – `LPT9`, with or without an
     extension.
2. Reject via the existing `TarError::UnsafePath` shape; add a
   `reason: &'static str` field if it doesn't already have one so
   we can distinguish "absolute path" from "reserved character"
   etc. in the diagnostic.
3. The check runs on every platform when reading a tar — a
   `:`-containing entry is unsafe on Windows, and we'd rather
   refuse it everywhere than have the same archive succeed on
   Linux and fail on Windows. (Inverse-friendly: an archive that
   extracts cleanly on Windows always extracts cleanly on Unix.)
4. Symlinks remain dropped (matches existing behavior; `O.25`
   deferred).

**Demo**: new tests in `sink/tar.rs::tests` covering each rejection
class. The existing path-escape tests continue to pass on every
platform.

---

### §9. Atomic checkpoint rename

**What**: confirm `checkpoint.rs`'s `write-to-tmp-then-rename` works
on Windows without code changes, or add the minimal Windows wiring
if it doesn't.

**Sketch**:

1. Inspect: `std::fs::rename` on Windows fails by default if the
   destination exists. Linux/macOS's behavior is replace-by-default.
2. If the existing code uses plain `fs::rename`, switch to
   `MoveFileExW(src, dst, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`
   on Windows via a small platform-specific helper in
   `checkpoint.rs`. (The crate-level rule says no `std::fs::rename`
   for atomic publish on Windows.) On Unix the existing
   `fs::rename` stays.
3. `MOVEFILE_WRITE_THROUGH` makes the rename itself durable; the
   parent-directory `fsync` the Unix path does for the rename
   doesn't have a direct Windows equivalent, so the write-through
   flag is how we get the equivalent guarantee.
4. Audit any other rename in the codebase (the final
   `*.peel.part` → `output` rename; any temp-file path) for the
   same gotcha.

**Demo**: a Windows crash-resume test that kills the process
between `.tmp` write and rename, then verifies the prior `.ckpt`
is still intact on resume. Already exists on Unix
(`checkpoint::tests::partial_write_recovery`); promote to Windows.

---

## Phase C — Wrap-up

### §10. Windows crash-test job

**What**: extend the crash-test harness to run on Windows. The
existing harness (Linux-only, `tests/test_crash_resume.rs` etc.)
spawns `peel`, kills it, and verifies the resumed run produces
byte-identical output. On Windows the "kill" primitive is
`TerminateProcess` (`kill -9` equivalent) — same harness shape,
different syscall.

**Sketch**:

1. Factor the existing harness's "kill the child process" call
   behind a `#[cfg]` switch: Unix uses `signal::kill` /
   `Pid::kill`; Windows uses `TerminateProcess(handle, 1)`.
2. Run the crash-test grid against `peel.exe` on the Windows CI
   job. Start with a smaller iteration count (10 random kill
   points instead of 100) so the job stays under 10 minutes.
3. Land the grid-extension and the harness commit together.

**Demo**: 10 random `TerminateProcess` points against a
`tar.zst` extraction all produce byte-identical output on resume.

---

### §11. Documentation + status updates

**What**: every doc that says "Linux first" or "macOS / Linux only"
updates. Status transitions land in this phase.

**Sketch**:

1. `CLAUDE.md`: the project description gains "Windows support
   (NTFS sparse + FSCTL_SET_ZERO_DATA) shipped in `PLAN_v3_windows.md`".
2. `internal/PLAN.md`: the §2 hard-constraints note about Windows
   being deferred updates to "Windows supports the full pipeline
   via `WindowsPuncher` (see `PLAN_v3_windows.md`)".
3. `internal/OPTIMIZATIONS.md`: mark `O.15` delivered with a
   "**Status: delivered in `PLAN_v3_windows.md` §4 (date)**"
   header, mirroring the `O.14` macOS-puncher entry.
4. `docs/src/` mdBook pages: add a Windows section to the
   "Supported platforms" page; update the install instructions to
   include `winget install peel` (or the equivalent — packaging
   path is `PLAN_packaging.md`'s lane, may be deferred).
5. README: claim Windows support in the badge / supported
   platforms list.
6. `release.yml`: confirm `x86_64-pc-windows-msvc` is built and
   the `peel.exe` is uploaded as a release asset. If not, add it.

**Demo**: the north-star command from the top of `PLAN.md` runs
end-to-end on a Windows 11 machine, including a `Ctrl-C` mid-flight
and a clean resume. Recorded in the commit message that closes
this plan.

---

## Round-two follow-ons (filed pre-emptively)

These are deliberately out of scope for this plan and will be filed
in `OPTIMIZATIONS.md` once the plan lands. They are listed here so
future-me sees the deferred items as a parking lot, not as gaps
that should be filled in this round.

- **`O.WIN.LONGPATH`**: opt-in long-path support via `\\?\` prefix.
  Default Windows max path is 260; `\\?\` lifts it to ~32 K but
  requires UTF-16 paths through every API and breaks some
  third-party tooling. Promote when a real archive trips the 260
  limit.
- **`O.WIN.JUNCTIONS`**: junction / reparse-point handling at
  extraction time. Today's tar parser doesn't extract symlinks at
  all (`O.25`); Windows-side parity is part of that follow-on, not
  this plan.
- **`O.WIN.SCHED_PRIORITY`**: `SetThreadPriority` on download
  workers when the system reports the disk as busy. Mirrors a
  hypothetical Linux `ioprio_set` follow-on; only worth doing if
  profiling shows a benefit.
- **`O.WIN.CLUSTER_SIZE`**: query NTFS cluster size via
  `GetDiskFreeSpaceW` and use it as the `block_size_hint` instead
  of the hard-coded 4 KiB. Only useful on volumes formatted with
  non-default cluster sizes.
- **`O.WIN.ALTSTREAMS`**: NTFS alternate data streams in the
  extracted output (`file.txt:Zone.Identifier` etc.). Rare in
  practice; out of scope for parity.

---

## Risk register

1. **NTFS cluster alignment.** If the cluster size is 64 KiB (common
   on large volumes formatted for backups), our 4 KiB block hint is
   under-sized and `FSCTL_SET_ZERO_DATA` will silently retain the
   tail of each punched range. Mitigation: `O.WIN.CLUSTER_SIZE`
   above; or accept the slight over-retention as a correctness-safe
   degradation (no data loss, just less hole punching).
2. **`CTRL_CLOSE_EVENT` 5-second timeout.** When the user closes the
   console window, Windows gives us ~5 s before unconditionally
   terminating the process. Our graceful watchdog's default deadline
   is 30 s (`DEFAULT_GRACEFUL_DEADLINE`). Mitigation: the watchdog
   detects the close-event flow specifically and shrinks its own
   deadline to 3 s in that case, leaving 2 s headroom for the OS
   teardown. Implementation lives in §5.
3. **`MoveFileExW` is not atomic across all NTFS configurations.**
   On some network mounts the rename can briefly leave the
   destination missing. Mitigation: keep both `*.peel.ckpt` and
   `*.peel.ckpt.tmp` on disk after the rename so a resume can fall
   back to the `.tmp` if the `.ckpt` is observed missing. (Same
   recovery shape as the existing Unix path.)
4. **`windows-sys` MSRV.** `windows-sys` 0.59 requires Rust 1.71+;
   our MSRV in `Cargo.toml` is 1.85 today, so this is comfortably
   in range. Future `windows-sys` releases that raise the floor
   require the same deliberation as any other MSRV bump.
5. **CI minute cost.** Adding a `windows-2022` matrix entry roughly
   doubles the per-PR CI minute cost on every job. Mitigation: the
   Windows job runs only `fmt + clippy + cargo test
   --all-features` initially; the crash-test grid (§10) is the
   expensive one and lives behind a `-- --ignored` flag run only
   on the main branch.

---

## What "Windows support done" means

All of the following are true:

1. `cargo build --target x86_64-pc-windows-msvc` produces a
   `peel.exe` that runs the north-star command end-to-end.
2. A `Ctrl-C` mid-flight on Windows produces a graceful abort with
   exit code 130, leaving `.peel.part` and `.peel.ckpt` on disk;
   re-running resumes byte-identically.
3. NTFS sparse file + `FSCTL_SET_ZERO_DATA` actually reduces the
   on-disk footprint of the compressed source during extraction
   (verified via `GetFileInformationByHandleEx`).
4. CI matrix is green on `ubuntu-latest`, `macos-latest`, and
   `windows-2022` for `fmt + clippy + cargo test --all-features`.
   The Windows crash-test job is green on a 10-iteration grid.
5. `OPTIMIZATIONS.md` `O.15` is marked delivered with a back-pointer
   to this plan.
