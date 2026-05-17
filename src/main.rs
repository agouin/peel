//! Entry point for the `peel` CLI.
//!
//! Parses the command-line via [`peel::cli::Cli`], constructs a
//! [`peel::coordinator::RunArgs`], and runs the pipeline.
//!
//! Progress is rendered by a [`peel::progress`] renderer thread spawned
//! at the binary boundary: a multi-line ANSI block on a TTY (PLAN_v2.md
//! §6) or one structured `tracing::info!` event per tick when stderr is
//! not a terminal. The renderer reads a shared [`peel::progress::ProgressState`]
//! that the coordinator, download workers, and extractor update directly.
//!
//! Errors at the binary boundary are wrapped via [`anyhow`] per
//! `internal/ENGINEERING_STANDARDS.md` §3.2.

#![warn(unused, clippy::all)]

fn main() -> anyhow::Result<()> {
    app_main::main()
}

// The body of the binary, kept in a private module so the file's
// top-level `fn main` is a single thin shim. `PLAN_v3_windows.md` §5
// makes `app_main` cross-platform — the only platform-specific bits
// are the signal-handler installation and the async-signal-safe
// stderr-write / process-exit helpers, all behind `cfg` inside
// `mod signals` below.
mod app_main {

    use std::error::Error as StdError;
    use std::io::IsTerminal;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use anyhow::{Context, Result};
    use clap::Parser;

    use peel::cli::{http_version_banner, Cli, Dispatch};
    use peel::coordinator::local::{run as run_local, LocalRunArgs};
    use peel::coordinator::{run, CoordinatorError, ProgressEvent, ProgressFn, RunArgs, RunStats};
    use peel::decode::DecoderRegistry;
    use peel::download::{SchedulerError, WorkerError};
    use peel::encryption::EncryptionError;
    use peel::progress::{format_eta, spawn_renderer, LogRenderer, ProgressState, TtyRenderer};

    /// Synthetic signal numbers we report through the `[abort]` line
    /// and the conventional `128 + signum` exit code. On Unix these
    /// are the real signal values (`SIGINT = 2`, `SIGTERM = 15`,
    /// `SIGHUP = 1`); the Windows console-ctrl handler translates the
    /// platform-native `CTRL_*_EVENT` values into the same set so
    /// shell scripts see the familiar "130" / "143" / "129" exit
    /// codes (`PLAN_v3_windows.md` §5).
    const SIGHUP: i32 = 1;
    const SIGINT: i32 = 2;
    const SIGQUIT_OR_BREAK: i32 = 3;
    const SIGTERM: i32 = 15;

    /// First-signal notice (TTY variant). The leading `\r\x1b[K` returns
    /// to column 0 and clears the current line so the message lands cleanly
    /// even if the TTY progress renderer has just drawn there; the trailing
    /// newline pushes the renderer's next tick down by one row instead of
    /// overwriting our text in place.
    const SHUTDOWN_GRACEFUL_MSG_TTY: &[u8] =
        b"\r\x1b[KShutdown request received, performing graceful shutdown...\n";
    /// First-signal notice (non-TTY variant). No ANSI escapes — kubelet's
    /// log capture stores them verbatim and downstream log viewers (Loki,
    /// Stackdriver, plain `kubectl logs -f`) display them as garbage. This
    /// is the form an operator sees in `kubectl logs` after `kubectl delete
    /// pod`.
    const SHUTDOWN_GRACEFUL_MSG_PLAIN: &[u8] =
        b"Shutdown request received, performing graceful shutdown...\n";
    /// Second-signal notice (TTY variant). Printed immediately before `_exit`.
    const FORCEFUL_MSG_TTY: &[u8] =
        b"\r\x1b[KSecond shutdown signal received, forcing immediate exit\n";
    /// Second-signal notice (non-TTY variant).
    const FORCEFUL_MSG_PLAIN: &[u8] = b"Second shutdown signal received, forcing immediate exit\n";
    /// Watchdog-fired notice (TTY variant). Printed immediately before the
    /// watchdog thread `_exit`s once `GRACEFUL_DEADLINE` elapses without
    /// `run` returning.
    const WATCHDOG_MSG_TTY: &[u8] =
        b"\r\x1b[KGraceful shutdown deadline elapsed, forcing immediate exit\n";
    /// Watchdog-fired notice (non-TTY variant).
    const WATCHDOG_MSG_PLAIN: &[u8] =
        b"Graceful shutdown deadline elapsed, forcing immediate exit\n";

    /// Hard upper bound on the wait between the first shutdown signal and
    /// the process exiting. Belt-and-suspenders for any kill-switch poll
    /// site we missed: even if the run is fully stuck and never observes
    /// the flag, the watchdog `_exit`s at the deadline. 30 s is well under
    /// the typical Kubernetes `terminationGracePeriodSeconds` (60–120 s),
    /// so a checkpoint-during-graceful path that *is* making progress
    /// still has time to land. Override via
    /// `PEEL_GRACEFUL_DEADLINE_SECS` (positive integer).
    const DEFAULT_GRACEFUL_DEADLINE: Duration = Duration::from_secs(30);

    /// Pointer to the kill-switch [`AtomicBool`] handed to
    /// [`peel::coordinator::run`] via [`peel::coordinator::RunArgs::kill_switch`].
    /// The signal handler reads this with one async-signal-safe atomic
    /// load and stores `true` into the pointee; `main` keeps the owning
    /// [`Arc`] alive until process exit so the dereference is always
    /// valid.
    static SHUTDOWN_PTR: AtomicPtr<AtomicBool> = AtomicPtr::new(ptr::null_mut());

    /// Set by `main` before installing handlers so the signal handler can
    /// pick the TTY-vs-non-TTY message variant. Reading an `AtomicBool`
    /// is async-signal-safe.
    static STDERR_IS_TTY: AtomicBool = AtomicBool::new(false);

    /// Number of shutdown signals delivered so far. The first delivery
    /// flips the kill switch (graceful: finish or skip the current
    /// checkpoint, then return [`CoordinatorError::Aborted`]); a second
    /// delivery short-circuits to `_exit(128 + signum)` so an unresponsive
    /// graceful path can always be escaped.
    static SIGNAL_COUNT: AtomicI32 = AtomicI32::new(0);

    /// Signal number of the *first* shutdown signal we received. `main`
    /// reads it after [`run`] returns [`CoordinatorError::Aborted`] so the
    /// process exit status follows the conventional `128 + signum` shape
    /// (130 for SIGINT, 143 for SIGTERM).
    static FIRST_SIGNAL: AtomicI32 = AtomicI32::new(0);

    /// Shared body of the shutdown handler. Called from the Unix
    /// signal handler (`extern "C" fn(i32)`) and from the Windows
    /// console-ctrl handler (`extern "system" fn(u32) -> BOOL`), both
    /// defined in `signals::imp`. **Async-signal-safe operations
    /// only:** atomic loads/stores, raw stderr writes of static byte
    /// slices, and (on the second signal) `_exit` / `ExitProcess`.
    /// No allocation, no formatting, no locking, no `Arc` ref-count
    /// traffic.
    fn dispatch_shutdown(sig: i32) {
        // The previous count tells us whether this is the first delivery
        // (count == 0 → graceful) or a follow-up (count >= 1 → forceful).
        // Doing this `fetch_add` first means a second signal that arrives
        // mid-handler still observes "this is the second one" and takes
        // the immediate-exit branch.
        if SIGNAL_COUNT.fetch_add(1, Ordering::AcqRel) == 0 {
            // First delivery: graceful path. Record the signal number so
            // `main` can pick the conventional `128 + signum` exit code,
            // flip the kill switch the coordinator polls between
            // checkpoints, and emit a one-line notice so an interactive
            // operator knows their Ctrl-C registered.
            FIRST_SIGNAL.store(sig, Ordering::Release);

            let ptr = SHUTDOWN_PTR.load(Ordering::Acquire);
            if !ptr.is_null() {
                // SAFETY: `SHUTDOWN_PTR` is set in
                // `install_signal_handlers` from `Arc::as_ptr` on a
                // heap `AtomicBool`. `main` holds the owning `Arc`
                // until the process exits (either via normal return
                // or the immediate-exit below), so the pointee
                // outlives every signal delivery. `AtomicBool::store`
                // is async-signal-safe.
                unsafe { (*ptr).store(true, Ordering::Release) };
            }

            let msg: &[u8] = if STDERR_IS_TTY.load(Ordering::Acquire) {
                SHUTDOWN_GRACEFUL_MSG_TTY
            } else {
                SHUTDOWN_GRACEFUL_MSG_PLAIN
            };
            signals::write_stderr_static(msg);
        } else {
            // Second (or later) delivery: drop the polite path. Best-effort
            // notice, then immediate exit.
            let msg: &[u8] = if STDERR_IS_TTY.load(Ordering::Acquire) {
                FORCEFUL_MSG_TTY
            } else {
                FORCEFUL_MSG_PLAIN
            };
            signals::write_stderr_static(msg);
            signals::proc_exit(128 + sig);
        }
    }

    /// Install platform-specific signal handlers that flip `kill` on
    /// first delivery and call `signals::proc_exit(128 + signum)` on
    /// the second.
    ///
    /// Must be called before any thread that holds the `Arc` is
    /// spawned. `main` calls it from the single-threaded prelude, so
    /// the `SHUTDOWN_PTR` store is happens-before any subsequent
    /// thread spawn and the handler observes a valid pointer from
    /// the first delivery.
    fn install_signal_handlers(kill: &Arc<AtomicBool>) -> Result<()> {
        SHUTDOWN_PTR.store(Arc::as_ptr(kill) as *mut AtomicBool, Ordering::Release);
        signals::imp::install_platform_handlers()
    }

    /// Human-readable name for the synthetic signal number reported
    /// through the `[abort]` line. The Unix path passes the real
    /// signal value; the Windows path maps `CTRL_*_EVENT` onto these
    /// same numbers so the diagnostic vocabulary is portable.
    fn signal_name(sig: i32) -> &'static str {
        match sig {
            SIGHUP => "SIGHUP",
            SIGINT => "SIGINT",
            SIGQUIT_OR_BREAK => {
                // Unix: SIGQUIT (3). Windows: synthetic mapping of
                // `CTRL_BREAK_EVENT`. Same exit-code convention.
                if cfg!(windows) {
                    "CTRL_BREAK"
                } else {
                    "SIGQUIT"
                }
            }
            SIGTERM => "SIGTERM",
            _ => "signal",
        }
    }

    mod signals {
        use std::sync::atomic::Ordering;

        // Re-exports so the cfg-internal impl can reach the parent's
        // dispatch entry point. The inner `imp` module is the only
        // platform-specific bit; everything else in this module is
        // portable.
        use super::dispatch_shutdown;
        use super::{
            FIRST_SIGNAL, SIGNAL_COUNT, STDERR_IS_TTY, WATCHDOG_MSG_PLAIN, WATCHDOG_MSG_TTY,
        };

        /// Best-effort async-signal-safe write of a `'static` byte
        /// slice to stderr. The return value (bytes written, if
        /// any) is discarded because there is no useful recovery
        /// from a partial / failed stderr write inside a signal
        /// handler.
        pub(super) fn write_stderr_static(bytes: &[u8]) {
            imp::write_stderr_static(bytes)
        }

        /// Immediate process exit with `code`. On Unix this is
        /// `_exit(2)`; on Windows it is `ExitProcess`. Both are the
        /// textbook "exit from a signal / console-ctrl handler"
        /// primitive on their platform.
        pub(super) fn proc_exit(code: i32) -> ! {
            imp::proc_exit(code)
        }

        /// Fire the watchdog's "deadline elapsed" exit path. The
        /// watchdog runs in a regular thread (not a signal handler),
        /// but we route through the same async-signal-safe write +
        /// exit primitives so the abort line is byte-for-byte
        /// identical to the in-handler messages.
        pub(super) fn watchdog_force_exit() -> ! {
            let msg: &[u8] = if STDERR_IS_TTY.load(Ordering::Acquire) {
                WATCHDOG_MSG_TTY
            } else {
                WATCHDOG_MSG_PLAIN
            };
            write_stderr_static(msg);
            let sig = FIRST_SIGNAL.load(Ordering::Acquire);
            let _ = SIGNAL_COUNT.fetch_add(1, Ordering::AcqRel);
            proc_exit(128 + sig)
        }

        #[cfg(unix)]
        pub(super) mod imp {
            //! Unix signal-handler installation via `signal(2)`.
            //!
            //! POSIX deprecates `signal(2)` in favor of
            //! `sigaction(2)`, but `struct sigaction`'s field order,
            //! `sigset_t` size, and `sa_restorer` presence vary
            //! across glibc / musl / macOS — a portable FFI
            //! declaration would need three different `#[repr(C)]`
            //! shapes plus `cfg` arms. `signal()` has a uniform
            //! signature, and on every libc we target it installs a
            //! persistent BSD-semantic handler with `SA_RESTART`.
            //! That is exactly what we want here: in-flight
            //! `read`/`write` syscalls that get interrupted simply
            //! retry instead of returning `EINTR`, so the
            //! download/extract loop is unaffected up to the next
            //! checkpoint where the kill switch is observed.
            use anyhow::{Context, Result};

            use super::super::{SIGINT, SIGTERM};

            const SIG_ERR: usize = usize::MAX;
            const STDERR_FD: i32 = 2;

            extern "C" {
                fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
                fn _exit(status: i32) -> !;
                fn write(fd: i32, buf: *const u8, count: usize) -> isize;
            }

            extern "C" fn handler(sig: i32) {
                super::dispatch_shutdown(sig);
            }

            pub(in super::super) fn install_platform_handlers() -> Result<()> {
                for sig in [SIGINT, SIGTERM] {
                    // SAFETY: `signal(2)` takes a signal number and a
                    // function pointer with `extern "C" fn(i32)` ABI,
                    // which matches `handler`. The handler only
                    // performs async-signal-safe work.
                    let prev = unsafe { signal(sig, handler) };
                    if prev == SIG_ERR {
                        return Err(std::io::Error::last_os_error())
                            .with_context(|| format!("installing handler for signal {sig}"));
                    }
                }
                Ok(())
            }

            pub(super) fn write_stderr_static(bytes: &[u8]) {
                // SAFETY: `write(2)` with a `'static` byte slice is
                // async-signal-safe. We discard the return value.
                unsafe { write(STDERR_FD, bytes.as_ptr(), bytes.len()) };
            }

            pub(super) fn proc_exit(code: i32) -> ! {
                // SAFETY: `_exit(2)` is the textbook async-signal-safe
                // exit call; calling it from a signal handler is its
                // intended use.
                unsafe { _exit(code) }
            }
        }

        #[cfg(windows)]
        pub(super) mod imp {
            //! Windows console-ctrl handler installation via
            //! `SetConsoleCtrlHandler` (`PLAN_v3_windows.md` §5).
            //!
            //! Windows does not have Unix-style asynchronous signals
            //! delivered to the main thread; instead the OS spawns a
            //! dedicated worker thread to call our registered handler.
            //! Async-signal-safety is therefore not strictly required
            //! (the handler is not interrupting arbitrary code), but
            //! we keep the no-allocation / no-formatting discipline so
            //! the body is interchangeable with the Unix one.
            //!
            //! Specifically: `CTRL_CLOSE_EVENT` (the console window's
            //! X button) gives the process ~5 seconds before Windows
            //! unconditionally terminates it. The graceful watchdog's
            //! default deadline is 30 s; on `CTRL_CLOSE_EVENT` the
            //! watchdog has no chance of firing first, so we rely on
            //! the kill switch being observed quickly enough that the
            //! checkpoint write completes before the OS pulls the
            //! plug. The shutdown-message bytes still land via
            //! `WriteFile`.
            use anyhow::{Context, Result};
            use windows_sys::Win32::Foundation::BOOL;
            use windows_sys::Win32::Storage::FileSystem::WriteFile;
            use windows_sys::Win32::System::Console::{
                GetStdHandle, SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT,
                CTRL_C_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT, STD_ERROR_HANDLE,
            };
            use windows_sys::Win32::System::Threading::ExitProcess;

            use super::super::{SIGHUP, SIGINT, SIGQUIT_OR_BREAK, SIGTERM};

            extern "system" fn handler(ctrl_type: u32) -> BOOL {
                // Map Windows console-ctrl event codes to the same
                // synthetic signal numbers the Unix path uses so the
                // `[abort]` line and the `128 + signum` exit code are
                // portable. `CTRL_CLOSE_EVENT` (window-close X) and
                // `CTRL_LOGOFF_EVENT` / `CTRL_SHUTDOWN_EVENT` (user
                // session ending) all get the SIGHUP convention used
                // for "controlling terminal disappeared".
                let sig = match ctrl_type {
                    CTRL_C_EVENT => SIGINT,
                    CTRL_BREAK_EVENT => SIGQUIT_OR_BREAK,
                    CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => SIGHUP,
                    _ => return 0, // FALSE: not handled; let the next handler in the chain decide
                };
                super::dispatch_shutdown(sig);
                if matches!(
                    ctrl_type,
                    CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT
                ) {
                    // Windows hard-terminates the process ~5 s after
                    // we return TRUE on a close/logoff/shutdown.
                    // We're already at the second-signal threshold
                    // (the OS won't give us a chance for a "graceful
                    // then forceful" two-step), so finish the
                    // forceful path inline so the abort line lands
                    // before the OS kills us.
                    let _ = SIGTERM; // keep the import live regardless of cfg arm
                    proc_exit(128 + sig);
                }
                1 // TRUE: handled
            }

            pub(in super::super) fn install_platform_handlers() -> Result<()> {
                // SAFETY: `SetConsoleCtrlHandler(Some(handler), TRUE)`
                // takes an `extern "system" fn(u32) -> BOOL` pointer
                // with no extra-state contract beyond async-thread
                // safety, which `handler` satisfies. Returns
                // non-zero on success.
                let rc = unsafe { SetConsoleCtrlHandler(Some(handler), 1) };
                if rc == 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("installing Windows console-ctrl handler");
                }
                Ok(())
            }

            pub(super) fn write_stderr_static(bytes: &[u8]) {
                // SAFETY: `GetStdHandle(STD_ERROR_HANDLE)` returns
                // the process-wide stderr handle; the value is valid
                // until process exit. `WriteFile` against a console
                // or file handle with a `'static` buffer and the
                // matching length is safe to call from any thread,
                // including the console-ctrl handler thread.
                let h = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
                if h.is_null() {
                    return;
                }
                let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
                let mut written: u32 = 0;
                unsafe {
                    WriteFile(h, bytes.as_ptr(), len, &mut written, std::ptr::null_mut());
                }
            }

            pub(super) fn proc_exit(code: i32) -> ! {
                // `ExitProcess` is the Windows analog of `_exit(2)`:
                // a clean, immediate process exit that runs no
                // destructors. `code` is `u32` on Windows; the
                // conventional `128 + signum` we pass is always
                // positive and fits in `i32`, so the
                // bit-equivalent `as u32` cast is lossless.
                // (`i32::cast_unsigned` would be cleaner but is
                // 1.87+ and our MSRV is 1.85.)
                #[allow(clippy::cast_sign_loss)]
                let exit_code = code as u32;
                // SAFETY: terminates the process; non-returning.
                unsafe { ExitProcess(exit_code) }
            }
        }
    }

    /// Read `PEEL_GRACEFUL_DEADLINE_SECS` (positive integer) and fall back
    /// to [`DEFAULT_GRACEFUL_DEADLINE`] otherwise.
    fn graceful_deadline_from_env() -> Duration {
        std::env::var("PEEL_GRACEFUL_DEADLINE_SECS")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|n| *n > 0)
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_GRACEFUL_DEADLINE)
    }

    /// Spawn the graceful-deadline watchdog (`PLAN_responsiveness.md`
    /// §2.4).
    ///
    /// The thread polls [`SIGNAL_COUNT`] every 100 ms while the run is
    /// healthy. Once a shutdown signal lands, it sleeps `deadline` and —
    /// if `cleanup_done` is still `false` — emits an `[abort]` line and
    /// `_exit`s the process. `main` flips `cleanup_done` immediately
    /// before returning so a clean exit before the deadline cancels the
    /// watchdog. The thread is detached: there is no join path.
    ///
    /// This guards against any kill-switch poll site we missed (or that
    /// hangs in non-cooperative work like a CPU-bound third-party
    /// codec). Pods that take >30 s to terminate are themselves a
    /// production problem in Kubernetes, so capping the graceful path is
    /// healthy.
    fn install_graceful_watchdog(deadline: Duration, cleanup_done: Arc<AtomicBool>) {
        let _ = std::thread::Builder::new()
            .name("peel-graceful-watchdog".into())
            .spawn(move || {
                // Phase 1: idle until either cleanup signals "we're done"
                // (no signal arrived; the run finished cleanly) or a
                // shutdown signal lands.
                loop {
                    std::thread::sleep(Duration::from_millis(100));
                    if cleanup_done.load(Ordering::Acquire) {
                        return;
                    }
                    if SIGNAL_COUNT.load(Ordering::Acquire) > 0 {
                        break;
                    }
                }
                // Phase 2: graceful deadline. The signal handler has
                // already flipped the kill switch and printed the
                // "initiating graceful shutdown" notice; we wait the
                // configured deadline for the run to wind down.
                let started = std::time::Instant::now();
                while started.elapsed() < deadline {
                    std::thread::sleep(Duration::from_millis(100));
                    if cleanup_done.load(Ordering::Acquire) {
                        return;
                    }
                }
                // Phase 3: deadline elapsed. The run is genuinely
                // stuck. The helper emits the same byte-for-byte
                // abort line the in-handler path would, then
                // unconditionally exits via the platform's immediate-
                // exit primitive (`_exit(2)` on Unix, `ExitProcess`
                // on Windows).
                signals::watchdog_force_exit();
            })
            .expect("spawn graceful watchdog");
    }

    /// Walk an [`anyhow::Error`]'s source chain looking for an
    /// [`EncryptionError`] variant that should map to exit code 4.
    ///
    /// Returns `true` for [`EncryptionError::PasswordIncorrect`] and
    /// [`EncryptionError::PasswordMissing`] — both indicate the user
    /// can retry with a different / supplied password and we want
    /// scripts to distinguish that from the generic "extraction
    /// failed" code 1.
    ///
    /// Implements the exit-code routing described in
    /// `internal/PLAN_archive_encryption.md` §6.
    fn password_exit_code_required(err: &anyhow::Error) -> bool {
        let mut current: &(dyn StdError + 'static) = err.as_ref();
        loop {
            if let Some(enc) = current.downcast_ref::<EncryptionError>() {
                return matches!(
                    enc,
                    EncryptionError::PasswordIncorrect | EncryptionError::PasswordMissing,
                );
            }
            match current.source() {
                Some(next) => current = next,
                None => return false,
            }
        }
    }

    pub fn main() -> Result<()> {
        let cli = Cli::parse();

        // Pick the progress mode from whether stderr is a real
        // terminal AND can accept ANSI escapes. The TTY path uses
        // hand-rolled ANSI on stderr; the non-TTY path emits
        // `tracing::info!` events that the subscriber below routes
        // back to stderr in human-readable form. On Windows 10 1607+
        // `tty_supports_ansi` enables virtual-terminal processing on
        // the console handle as a side effect; on pre-1607 Windows
        // (or any platform where `SetConsoleMode` rejects the
        // VT bit) the helper returns `false` and we drop to the
        // log renderer rather than emitting literal escape codes
        // (`PLAN_v3_windows.md` §7).
        let stderr_is_tty = std::io::stderr().is_terminal() && peel::progress::tty_supports_ansi();
        // Publish the TTY status so the signal handler picks the right
        // message variant — kubelet log capture stores ANSI escapes
        // verbatim, so the non-TTY path needs a clean message.
        STDERR_IS_TTY.store(stderr_is_tty, Ordering::Release);
        init_tracing(stderr_is_tty);

        // Install SIGINT/SIGTERM handlers as early as possible — before
        // any worker threads exist — so a signal arriving during setup is
        // observed by the kill switch the coordinator polls between
        // checkpoints. As PID 1 in a Kubernetes pod the kernel applies no
        // default disposition for these signals, so without this the
        // process would silently ignore SIGTERM and only exit on the
        // kubelet's escalation to SIGKILL after the grace period elapses.
        let kill_switch = Arc::new(AtomicBool::new(false));
        install_signal_handlers(&kill_switch).context("installing signal handlers")?;

        // §2.4: arm the graceful watchdog. The thread is detached and
        // cancels itself when `cleanup_done` flips to `true` (set right
        // before `main` returns); if the deadline elapses first, it
        // `_exit`s with the conventional `128 + signum` code so an
        // unresponsive graceful path can't hold the pod hostage.
        let cleanup_done = Arc::new(AtomicBool::new(false));
        install_graceful_watchdog(graceful_deadline_from_env(), Arc::clone(&cleanup_done));

        // Capture the http_version label before consuming `cli`. Both
        // banners (http_version and io_backend) are printed below as plain
        // stderr scrollback ABOVE the TTY renderer's redraw region — the
        // renderer's cursor-up math can't reach into scrollback, so the
        // banners are immune to corruption from later redraws. On non-TTY
        // we leave them to the `tracing::info!` calls inside
        // `into_run_args` and `select_backend` (the subscriber is at INFO
        // level there).
        let http_banner = http_version_banner(cli.http_version.into());
        let dispatch = cli.into_dispatch().context("parsing CLI arguments")?;

        // Local-file mode (`internal/old/PLAN_local_file_extract.md`) skips
        // every HTTP-side knob — no scheduler retries, no
        // multi-attempt rebuild, no mirror state. Handle it before
        // setting up the HTTP-flavored renderer scaffolding.
        if let Dispatch::Local { args: local_args } = dispatch {
            return run_local_dispatch(*local_args, stderr_is_tty, &kill_switch, cleanup_done);
        }
        let mut args = match dispatch {
            Dispatch::Http(args) => *args,
            Dispatch::Local { .. } => unreachable!("filtered above"),
        };

        // Resolve the IO backend in main (rather than letting
        // `coordinator::run` do it) so we can print the `io_backend=…`
        // label as scrollback BEFORE spawning the renderer. Coordinator
        // accepts the resolved backend via `RunArgs::io_backend` and
        // skips its own resolution step.
        let (io_backend, io_backend_label) =
            peel::io_backend::select_backend(args.config.io_backend, args.config.workers)
                .context("resolving the IO backend")?;
        args.io_backend = Some(io_backend);

        if stderr_is_tty {
            eprintln!("{http_banner}");
            eprintln!("{io_backend_label}");
        }

        let state = ProgressState::new();

        // Capture the cloneable bits of `args` so the outer-loop retry path
        // can rebuild a fresh `RunArgs` per attempt. `RunArgs` itself is
        // not `Clone` (the boxed `ProgressFn` and the `Arc<dyn IoBackend>`
        // are not trivially cloneable as a unit), but every field we need
        // is independently cloneable; we just have to assemble them.
        let url = args.url.clone();
        let additional_urls = args.additional_urls.clone();
        let output = args.output.clone();
        let coord_config = args.config.clone();
        let client = args.client.clone();
        // INVARIANT: we set `args.io_backend = Some(io_backend)` above.
        let io_backend_arc = args.io_backend.clone().expect("io_backend was set above");

        let make_args = || RunArgs {
            url: url.clone(),
            additional_urls: additional_urls.clone(),
            output: output.clone(),
            config: coord_config.clone(),
            client: client.clone(),
            registry: DecoderRegistry::with_defaults(),
            progress: Some(make_event_callback(stderr_is_tty)),
            progress_state: Some(Arc::clone(&state)),
            kill_switch: Some(Arc::clone(&kill_switch)),
            io_backend: Some(Arc::clone(&io_backend_arc)),
        };

        args.progress_state = Some(Arc::clone(&state));
        args.progress = Some(make_event_callback(stderr_is_tty));
        args.kill_switch = Some(Arc::clone(&kill_switch));

        // Spawn the renderer thread. TTY mode redraws three lines in place
        // every 100 ms; non-TTY mode emits one structured log line every
        // 2 s so a piped log file remains readable.
        let render_handle = if stderr_is_tty {
            spawn_renderer(
                Arc::clone(&state),
                TtyRenderer::new(std::io::stderr()),
                Duration::from_millis(100),
                Some(Arc::clone(&kill_switch)),
            )
            .context("spawning the TTY progress renderer")?
        } else {
            spawn_renderer(
                Arc::clone(&state),
                LogRenderer::new(),
                Duration::from_secs(2),
                Some(Arc::clone(&kill_switch)),
            )
            .context("spawning the log progress renderer")?
        };

        let result = run_with_outer_retry(args, &make_args, &state, &kill_switch, stderr_is_tty);

        // Tell the renderer to stop, regardless of whether `run` succeeded
        // or errored, so we can join it before exiting `main`.
        state.mark_done();
        let _ = render_handle.join();

        // §2.4: stand down the graceful watchdog now that the run is fully
        // wrapped up — including the renderer thread join. If a SIGTERM
        // arrives between this store and process exit it has nothing left
        // to interrupt; the watchdog is no longer needed.
        cleanup_done.store(true, Ordering::Release);

        let stats = match result {
            Ok(stats) => stats,
            Err(CoordinatorError::Aborted {
                checkpoints_written,
            }) => {
                // Graceful abort triggered by a SIGINT/SIGTERM landing in
                // `shutdown_handler`. The most recent `.peel.part` and
                // `.peel.ckpt` are durable on disk; the next invocation
                // resumes from there. Exit with the conventional
                // `128 + signum` status (130 for SIGINT, 143 for SIGTERM)
                // so kubelet / shells see the expected code.
                let sig = FIRST_SIGNAL.load(Ordering::Acquire);
                eprintln!(
                    "[abort] {} received, exited after {} checkpoints \
                 (.peel.part / .peel.ckpt left for resume)",
                    signal_name(sig),
                    checkpoints_written,
                );
                std::process::exit(128 + sig);
            }
            Err(other) => {
                let wrapped = anyhow::Error::from(other).context("running peel");
                // §6 of `internal/PLAN_archive_encryption.md`: surface a
                // wrong-password / missing-password failure as exit code
                // 4 so scripts can distinguish it from the generic
                // "extraction failed" code 1. The error chain may wrap
                // the `EncryptionError` several layers deep
                // (CoordinatorError → ZipPipelineError → ZipError →
                // EncryptionError, etc.), so we walk the
                // `Error::source` chain.
                if password_exit_code_required(&wrapped) {
                    eprintln!("[error] {wrapped:#}");
                    cleanup_done.store(true, Ordering::Release);
                    std::process::exit(4);
                }
                return Err(wrapped);
            }
        };

        eprintln!(
            "[done] {} bytes downloaded, {} bytes extracted in {:.2}s{}",
            stats.download.bytes_downloaded,
            stats.extraction.bytes_out,
            stats.elapsed.as_secs_f64(),
            if stats.resumed { " (resumed)" } else { "" },
        );
        eprintln!(
            "[stats] download chunks={} retries={} mode={:?}",
            stats.download.chunks_completed, stats.download.retries, stats.download.mode,
        );
        eprintln!(
            "[stats] extract bytes_in={} bytes_out={} bytes_punched={} \
         frames={} checkpoints={}",
            stats.extraction.bytes_in,
            stats.extraction.bytes_out,
            stats.extraction.bytes_punched,
            stats.extraction.frame_boundaries_observed,
            stats.extraction.quiescent_checkpoints,
        );
        // Render the cumulative wall-clock with the same human shape
        // the progress renderer uses for ETA (e.g. `2m14s`, `1h7m3s`)
        // so the final summary is at-a-glance readable even for
        // resumed runs whose total spans hours or days. The value is
        // sourced from `RunStats::elapsed`, which the coordinator
        // populates as `prior_elapsed + started.elapsed()` — the
        // accumulator survives crash-resumes via the checkpoint's v15
        // trailer.
        eprintln!("[stats] total_time={}", format_eta(Some(stats.elapsed)));
        Ok(())
    }

    /// Drive the local-file extractor
    /// (`internal/old/PLAN_local_file_extract.md`). Mirrors the HTTP path's
    /// renderer / IO-backend / kill-switch wiring but skips the
    /// download-side retry loop entirely: a local extraction either
    /// completes or surfaces a clean error.
    ///
    /// Local mode is non-destructive by default — the source archive
    /// is preserved on disk. `-d/--destructive` opts into hole-punching
    /// the source as the decoder advances and deleting it on clean
    /// completion; the choice is encoded in [`LocalRunArgs::destructive`]
    /// before this function is called, so there is nothing left to
    /// prompt or confirm here.
    fn run_local_dispatch(
        mut args: LocalRunArgs,
        stderr_is_tty: bool,
        kill_switch: &Arc<AtomicBool>,
        cleanup_done: Arc<AtomicBool>,
    ) -> Result<()> {
        // Resolve the IO backend in `main` so the `io_backend=…`
        // banner is plain stderr scrollback ABOVE the renderer's
        // redraw region (mirroring the HTTP path). Local mode passes
        // workers=1 because there is one logical reader and no
        // download-worker grid.
        let (io_backend, io_backend_label) = peel::io_backend::select_backend(args.io_backend, 1)
            .context("resolving the IO backend")?;
        args.io_backend_resolved = Some(io_backend);

        if stderr_is_tty {
            eprintln!("{io_backend_label}");
        }

        let state = ProgressState::new();
        args.progress_state = Some(Arc::clone(&state));
        args.progress = Some(make_event_callback(stderr_is_tty));
        args.kill_switch = Some(Arc::clone(kill_switch));

        let render_handle = if stderr_is_tty {
            spawn_renderer(
                Arc::clone(&state),
                TtyRenderer::new(std::io::stderr()),
                Duration::from_millis(100),
                Some(Arc::clone(kill_switch)),
            )
            .context("spawning the TTY progress renderer")?
        } else {
            spawn_renderer(
                Arc::clone(&state),
                LogRenderer::new(),
                Duration::from_secs(2),
                Some(Arc::clone(kill_switch)),
            )
            .context("spawning the log progress renderer")?
        };

        let result = run_local(args);

        state.mark_done();
        let _ = render_handle.join();
        cleanup_done.store(true, Ordering::Release);

        let stats = match result {
            Ok(stats) => stats,
            Err(CoordinatorError::Aborted {
                checkpoints_written,
            }) => {
                let sig = FIRST_SIGNAL.load(Ordering::Acquire);
                eprintln!(
                    "[abort] {} received, exited after {} checkpoints \
                 (.peel.ckpt left for resume)",
                    signal_name(sig),
                    checkpoints_written,
                );
                std::process::exit(128 + sig);
            }
            Err(other) => {
                let wrapped = anyhow::Error::from(other).context("running peel");
                if password_exit_code_required(&wrapped) {
                    eprintln!("[error] {wrapped:#}");
                    std::process::exit(4);
                }
                return Err(wrapped);
            }
        };

        eprintln!(
            "[done] {} bytes extracted in {:.2}s{}",
            stats.extraction.bytes_out,
            stats.elapsed.as_secs_f64(),
            if stats.resumed { " (resumed)" } else { "" },
        );
        eprintln!(
            "[stats] extract bytes_in={} bytes_out={} bytes_punched={} \
         frames={} checkpoints={}",
            stats.extraction.bytes_in,
            stats.extraction.bytes_out,
            stats.extraction.bytes_punched,
            stats.extraction.frame_boundaries_observed,
            stats.extraction.quiescent_checkpoints,
        );
        // Cumulative wall-clock across every run that contributed —
        // see the HTTP path's identical line for the rationale.
        eprintln!("[stats] total_time={}", format_eta(Some(stats.elapsed)));
        Ok(())
    }

    /// Discrete-event ProgressFn callback. Mostly informational; the
    /// renderer thread covers the steady-state UI.
    ///
    /// On a TTY this is intentionally a near-no-op: any concurrent
    /// `eprintln!` while the renderer is mid-redraw lands inside its
    /// 3-line region and corrupts the cursor-up math (a long URL in the
    /// `[start]` line, for example, can wrap across 2 visual rows on an
    /// 80-col terminal — the renderer's next tick then undershoots the
    /// cursor-up and the previous tick's body lines stick around as
    /// duplicates above the new draw). The `[done]`/`[stats]` summary
    /// runs after the renderer has joined, so it's safe.
    ///
    /// Off-TTY (the [`LogRenderer`] path) the redraw concern doesn't
    /// apply, so we keep the discrete `[start]`/`[stats]` lines for log
    /// readers.
    fn make_event_callback(stderr_is_tty: bool) -> ProgressFn {
        Box::new(move |event: ProgressEvent<'_>| {
            if stderr_is_tty {
                return;
            }
            match event {
                ProgressEvent::Started {
                    url,
                    total_size,
                    resuming,
                    total_chunks,
                    chunks_resumed,
                } => {
                    eprintln!(
                        "[start] {} ({} bytes, {} chunks{}{})",
                        url,
                        total_size,
                        total_chunks,
                        if resuming { ", resuming" } else { "" },
                        if chunks_resumed > 0 {
                            format!(", {chunks_resumed} chunks already complete")
                        } else {
                            String::new()
                        },
                    );
                }
                ProgressEvent::CheckpointWritten { .. } => {
                    // Per-checkpoint events are noisy on a fast pipeline; the
                    // renderer thread shows steady-state progress already.
                }
                ProgressEvent::Finished {
                    download,
                    extraction,
                } => {
                    eprintln!(
                        "[stats] download chunks={} retries={} mode={:?}",
                        download.chunks_completed, download.retries, download.mode,
                    );
                    eprintln!(
                        "[stats] extract bytes_in={} bytes_out={} bytes_punched={} \
                     frames={} checkpoints={}",
                        extraction.bytes_in,
                        extraction.bytes_out,
                        extraction.bytes_punched,
                        extraction.frame_boundaries_observed,
                        extraction.quiescent_checkpoints,
                    );
                }
            }
        })
    }

    /// Configure the global `tracing` subscriber.
    ///
    /// On a TTY we suppress the `peel::progress` target entirely — the
    /// TTY renderer is the user's view of that data, and dumping log
    /// events to the same stream would corrupt the in-place redraw.
    /// Off-TTY we keep the target on so the [`LogRenderer`] events make
    /// it to stderr.
    fn init_tracing(stderr_is_tty: bool) {
        use tracing_subscriber::fmt;

        let builder = fmt()
            .with_writer(std::io::stderr)
            .with_target(false)
            .with_level(true)
            .without_time();

        if stderr_is_tty {
            // Default level INFO but progress events suppressed: the
            // renderer's in-place redraw is the user's progress view.
            // Other targets (warnings, info from other modules) still
            // show.
            let _ = builder.with_max_level(tracing::Level::WARN).try_init();
        } else {
            let _ = builder.with_max_level(tracing::Level::INFO).try_init();
        }
    }

    /// Default number of additional `run` attempts after the first one
    /// fails with a transient error. Override via `PEEL_OUTER_RETRIES`.
    const DEFAULT_OUTER_RETRIES: u32 = 5;
    /// Initial delay between the first failure and its retry. Doubles up
    /// to [`OUTER_RETRY_MAX_BACKOFF`].
    const OUTER_RETRY_INITIAL_BACKOFF: Duration = Duration::from_secs(5);
    /// Cap on the exponential backoff between retry attempts. The user
    /// already endured a multi-minute failure window before reaching this
    /// path, so a one-minute ceiling is plenty — anything longer just
    /// stretches the operator's pager without improving recovery odds.
    const OUTER_RETRY_MAX_BACKOFF: Duration = Duration::from_secs(60);

    /// Read `PEEL_OUTER_RETRIES` (non-negative integer) and fall back to
    /// [`DEFAULT_OUTER_RETRIES`]. `0` disables the outer-loop retry
    /// entirely (one attempt, no restarts).
    fn outer_retries_from_env() -> u32 {
        std::env::var("PEEL_OUTER_RETRIES")
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(DEFAULT_OUTER_RETRIES)
    }

    /// Drive [`run`] in an outer retry loop: on a transient failure (a
    /// download-side error whose root `WorkerError` / `SchedulerError`
    /// reports `is_retryable`), wait, reset the shared progress counters,
    /// rebuild a fresh `RunArgs` (fresh HTTP `Client` connection pool,
    /// fresh `ProgressFn`), and call [`run`] again. The checkpoint and
    /// part-file on disk make the next attempt resume losslessly from
    /// where the failed one left off.
    ///
    /// Non-retryable errors (`Aborted`, `SourceChanged*`, format-detection
    /// conflicts, sparse-file IO, integrity mismatches, …) bypass the
    /// retry path and surface immediately.
    ///
    /// `kill_switch` is polled both before each retry and during the
    /// backoff sleep so a SIGINT/SIGTERM during the wait window terminates
    /// promptly instead of waiting out the full backoff.
    fn run_with_outer_retry(
        initial: RunArgs,
        rebuild_args: &dyn Fn() -> RunArgs,
        state: &Arc<ProgressState>,
        kill_switch: &Arc<AtomicBool>,
        stderr_is_tty: bool,
    ) -> Result<RunStats, CoordinatorError> {
        let max_retries = outer_retries_from_env();
        let mut args = initial;
        let mut backoff = OUTER_RETRY_INITIAL_BACKOFF;
        let mut attempt: u32 = 1;
        loop {
            match run(args) {
                Ok(stats) => return Ok(stats),
                Err(err) => {
                    let exhausted = attempt > max_retries;
                    let killed = kill_switch.load(Ordering::Acquire);
                    if exhausted || killed || !is_retryable_run_error(&err) {
                        return Err(err);
                    }
                    emit_retry_notice(&err, attempt, max_retries, backoff, stderr_is_tty);
                    if !sleep_with_kill_switch(backoff, kill_switch) {
                        return Err(err);
                    }
                    state.reset_for_retry();
                    attempt = attempt.saturating_add(1);
                    backoff = backoff.saturating_mul(2).min(OUTER_RETRY_MAX_BACKOFF);
                    args = rebuild_args();
                }
            }
        }
    }

    /// Walk the `Error::source` chain looking for a typed `SchedulerError`
    /// or `WorkerError` and ask it whether the underlying failure is
    /// transient. We look at both because the actual root cause can land
    /// at either layer depending on which path failed: scheduler-level for
    /// failures the scheduler synthesizes itself (e.g. `SingleStream`),
    /// worker-level for failures the per-chunk loop bubbles up.
    ///
    /// `Aborted` short-circuits to `false` because that variant means the
    /// kill switch tripped — retrying would re-enter the same shutdown.
    fn is_retryable_run_error(err: &CoordinatorError) -> bool {
        if matches!(err, CoordinatorError::Aborted { .. }) {
            return false;
        }
        let mut cursor: &(dyn StdError + 'static) = err;
        loop {
            if let Some(s) = cursor.downcast_ref::<SchedulerError>() {
                return scheduler_err_is_retryable(s);
            }
            if let Some(w) = cursor.downcast_ref::<WorkerError>() {
                return w.is_retryable();
            }
            match cursor.source() {
                Some(src) => cursor = src,
                None => return false,
            }
        }
    }

    /// Map a [`SchedulerError`] to "transient enough that a fresh `run`
    /// from checkpoint might succeed". The conservative default for
    /// unknown variants is `false`: prefer surfacing a real error than
    /// burning retry budget on something that won't fix itself.
    fn scheduler_err_is_retryable(s: &SchedulerError) -> bool {
        match s {
            SchedulerError::Head { source, .. } => source.is_retryable(),
            SchedulerError::ChunkFailed { source, .. } => source.is_retryable(),
            SchedulerError::SingleStream { source, .. } => source.is_retryable(),
            SchedulerError::SingleStreamBodyLength { .. } => true,
            SchedulerError::BodyIo { .. } => true,
            SchedulerError::SourceChangedDuringDownload { .. } => false,
            SchedulerError::SparseFile { .. } => false,
            SchedulerError::WorkersExhausted { .. } => false,
            SchedulerError::MissingContentLength { .. }
            | SchedulerError::BitmapLengthMismatch { .. }
            | SchedulerError::InvalidChunkSize
            | SchedulerError::InvalidWorkerCount
            | SchedulerError::TooManyChunks { .. }
            | SchedulerError::MultiPart(_) => false,
        }
    }

    /// Emit a one-line `[retry]` notice describing the failure and the
    /// upcoming wait. Mirrors the existing `[start]` / `[done]` /
    /// `[abort]` line shapes so log parsers see a consistent prefix.
    fn emit_retry_notice(
        err: &CoordinatorError,
        attempt: u32,
        max_retries: u32,
        backoff: Duration,
        stderr_is_tty: bool,
    ) {
        let total_attempts = max_retries.saturating_add(1);
        let msg = format!(
            "[retry] attempt {attempt}/{total_attempts} failed ({err:#}); \
         restarting from checkpoint in {:.1}s",
            backoff.as_secs_f64(),
        );
        if stderr_is_tty {
            eprintln!("{msg}");
        } else {
            tracing::warn!("{msg}");
        }
    }

    /// Sleep up to `dur`, polling `kill_switch` every 100 ms. Returns
    /// `false` if a kill signal landed during the wait (so the caller can
    /// surface the original error instead of looping into another
    /// attempt), `true` if the full duration elapsed cleanly.
    fn sleep_with_kill_switch(dur: Duration, kill: &AtomicBool) -> bool {
        if dur.is_zero() {
            return !kill.load(Ordering::Acquire);
        }
        let deadline = Instant::now() + dur;
        let step = Duration::from_millis(100);
        loop {
            if kill.load(Ordering::Acquire) {
                return false;
            }
            let now = Instant::now();
            if now >= deadline {
                return true;
            }
            let remaining = deadline - now;
            thread::sleep(step.min(remaining));
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use peel::download::WorkerError;
        use peel::http::{ClientError, Method};
        use peel::types::ChunkIndex;

        fn transport_worker_error() -> WorkerError {
            WorkerError::Transport {
                chunk: ChunkIndex::ZERO,
                source: ClientError::Transport {
                    host: "example.test".into(),
                    port: 443,
                    detail: "connection reset".into(),
                },
            }
        }

        #[test]
        fn aborted_is_not_retryable() {
            let err = CoordinatorError::Aborted {
                checkpoints_written: 7,
            };
            assert!(!is_retryable_run_error(&err));
        }

        #[test]
        fn scheduler_chunk_failed_with_transport_is_retryable() {
            let err = CoordinatorError::Scheduler(SchedulerError::ChunkFailed {
                chunk: ChunkIndex::new(294),
                attempts: 5,
                source: transport_worker_error(),
            });
            assert!(is_retryable_run_error(&err));
        }

        #[test]
        fn scheduler_chunk_failed_with_terminal_worker_error_is_not_retryable() {
            let err = CoordinatorError::Scheduler(SchedulerError::ChunkFailed {
                chunk: ChunkIndex::new(0),
                attempts: 1,
                source: WorkerError::SourceChanged {
                    chunk: ChunkIndex::ZERO,
                    expected_etag: Some("\"abc\"".into()),
                    actual_etag: Some("\"def\"".into()),
                    expected_last_modified: None,
                    actual_last_modified: None,
                },
            });
            assert!(!is_retryable_run_error(&err));
        }

        #[test]
        fn extractor_wrapping_retryable_scheduler_error_is_retryable() {
            // The realistic path from the bug report: a download-side
            // failure wrapped in DecodeError::Read inside ExtractorError
            // inside CoordinatorError::Extractor. The retry detector must
            // walk the source chain to find the SchedulerError/WorkerError.
            use peel::decode::DecodeError;
            use peel::extractor::ExtractorError;
            use std::io;

            let scheduler_err = SchedulerError::ChunkFailed {
                chunk: ChunkIndex::new(294),
                attempts: 5,
                source: transport_worker_error(),
            };
            let io_err = io::Error::other(scheduler_err);
            let decode_err = DecodeError::Read {
                consumed: 1_231_172_260,
                source: io_err,
            };
            let extractor_err = ExtractorError::Decode(decode_err);
            let coord_err = CoordinatorError::Extractor(extractor_err);
            assert!(is_retryable_run_error(&coord_err));
        }

        #[test]
        fn scheduler_head_404_is_not_retryable() {
            // A 404 from HEAD / range-probe discovery is terminal — the
            // URL is wrong. Retrying just walks the full backoff
            // schedule before surfacing the same error, leaving the
            // user staring at a blank progress UI.
            let err = CoordinatorError::Scheduler(SchedulerError::Head {
                url: "https://example.test/missing.tar.lz4".into(),
                source: ClientError::UnexpectedStatus {
                    method: Method::Get,
                    url: "https://example.test/missing.tar.lz4".into(),
                    status: 404,
                },
            });
            assert!(!is_retryable_run_error(&err));
        }

        #[test]
        fn scheduler_head_5xx_is_retryable() {
            // A 503 from HEAD is transient (server overload / gateway
            // hiccup) and should ride the retry path.
            let err = CoordinatorError::Scheduler(SchedulerError::Head {
                url: "https://example.test/snap.tar.lz4".into(),
                source: ClientError::UnexpectedStatus {
                    method: Method::Head,
                    url: "https://example.test/snap.tar.lz4".into(),
                    status: 503,
                },
            });
            assert!(is_retryable_run_error(&err));
        }

        #[test]
        fn scheduler_head_transport_is_retryable() {
            let err = CoordinatorError::Scheduler(SchedulerError::Head {
                url: "https://example.test/snap.tar.lz4".into(),
                source: ClientError::Transport {
                    host: "example.test".into(),
                    port: 443,
                    detail: "connection reset".into(),
                },
            });
            assert!(is_retryable_run_error(&err));
        }

        #[test]
        fn extractor_unrelated_to_download_is_not_retryable() {
            // A sink-side failure (e.g. tar write IO) has no
            // SchedulerError/WorkerError in its source chain — it should
            // not trigger an outer-loop retry, since restarting won't
            // address a stuck local disk.
            use peel::decode::DecodeError;
            use peel::extractor::ExtractorError;
            use std::io;
            let decode_err =
                DecodeError::Write(io::Error::other("sink write failed for unrelated reasons"));
            let coord_err = CoordinatorError::Extractor(ExtractorError::Decode(decode_err));
            assert!(!is_retryable_run_error(&coord_err));
        }

        #[test]
        fn sleep_returns_false_when_kill_set_immediately() {
            let kill = AtomicBool::new(true);
            let elapsed = std::time::Instant::now();
            assert!(!sleep_with_kill_switch(Duration::from_secs(60), &kill));
            // Should return promptly (well under the 60s budget).
            assert!(elapsed.elapsed() < Duration::from_secs(1));
        }

        #[test]
        fn sleep_returns_true_after_full_duration() {
            let kill = AtomicBool::new(false);
            let started = std::time::Instant::now();
            assert!(sleep_with_kill_switch(Duration::from_millis(150), &kill));
            assert!(started.elapsed() >= Duration::from_millis(140));
        }

        #[test]
        fn outer_retries_env_overrides_default() {
            let prev = std::env::var("PEEL_OUTER_RETRIES").ok();
            std::env::set_var("PEEL_OUTER_RETRIES", "0");
            assert_eq!(outer_retries_from_env(), 0);
            std::env::set_var("PEEL_OUTER_RETRIES", "12");
            assert_eq!(outer_retries_from_env(), 12);
            match prev {
                Some(v) => std::env::set_var("PEEL_OUTER_RETRIES", v),
                None => std::env::remove_var("PEEL_OUTER_RETRIES"),
            }
        }
    }
} // end mod app_main
