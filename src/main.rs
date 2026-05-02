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
//! `docs/ENGINEERING_STANDARDS.md` §3.2.

#![cfg(unix)]
#![warn(unused, clippy::all)]

use std::io::IsTerminal;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicPtr, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;

use peel::cli::{http_version_banner, Cli};
use peel::coordinator::{run, CoordinatorError, ProgressEvent, ProgressFn};
use peel::progress::{spawn_renderer, LogRenderer, ProgressState, TtyRenderer};

/// SIGINT — `Ctrl-C` from an interactive shell.
const SIGINT: i32 = 2;
/// SIGTERM — what kubelet sends at the start of a pod's grace period
/// before escalating to SIGKILL after `terminationGracePeriodSeconds`.
const SIGTERM: i32 = 15;
/// `SIG_ERR` is `(sighandler_t)-1`. `signal(2)` returns this on
/// failure; we compare the pointer-sized return value against
/// `usize::MAX` (the unsigned representation of `-1` on every Unix
/// target Rust supports).
const SIG_ERR: usize = usize::MAX;

extern "C" {
    /// `sighandler_t signal(int signum, sighandler_t handler);`
    ///
    /// POSIX deprecates `signal(2)` in favor of `sigaction(2)`, but
    /// `struct sigaction`'s field order, `sigset_t` size, and
    /// `sa_restorer` presence vary across glibc / musl / macOS — a
    /// portable FFI declaration would need three different `#[repr(C)]`
    /// shapes plus `cfg` arms. `signal()` has a uniform signature, and
    /// on every libc we target it installs a persistent BSD-semantic
    /// handler with `SA_RESTART`. That is exactly what we want here:
    /// in-flight `read`/`write` syscalls that get interrupted simply
    /// retry instead of returning `EINTR`, so the download/extract
    /// loop is unaffected up to the next checkpoint where the kill
    /// switch is observed.
    fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
    /// `void _exit(int status) __attribute__((noreturn));`
    ///
    /// Async-signal-safe immediate-exit syscall wrapper. We invoke
    /// this on the *second* shutdown signal so the operator can always
    /// escalate past a graceful path that's not progressing.
    fn _exit(status: i32) -> !;
    /// `ssize_t write(int fd, const void *buf, size_t count);`
    ///
    /// Async-signal-safe direct write syscall wrapper. We use this
    /// (rather than `eprintln!`) to emit the "graceful shutdown" /
    /// "forcing exit" notices from the signal handler — `eprintln!`
    /// would lock stderr and call into the formatting machinery,
    /// neither of which is signal-safe.
    fn write(fd: i32, buf: *const u8, count: usize) -> isize;
}

/// `STDERR_FILENO` — fixed by POSIX to be `2`.
const STDERR_FD: i32 = 2;

/// First-signal notice for SIGINT (interactive Ctrl-C). The leading
/// `\r\x1b[K` returns to column 0 and clears the current line so the
/// message lands cleanly even if the TTY progress renderer has just
/// drawn there; the trailing newline pushes the renderer's next tick
/// down by one row instead of overwriting our text in place.
const SIGINT_GRACEFUL_MSG: &[u8] =
    b"\r\x1b[K[abort] SIGINT received, initiating graceful shutdown \
      (press Ctrl+C again for forceful shutdown)\n";
/// First-signal notice for SIGTERM. Same shape as `SIGINT_GRACEFUL_MSG`
/// but worded for non-interactive contexts (kubelet, `kill <pid>`),
/// where "Ctrl+C again" doesn't apply.
const SIGTERM_GRACEFUL_MSG: &[u8] =
    b"\r\x1b[K[abort] SIGTERM received, initiating graceful shutdown \
      (send another signal for forceful shutdown)\n";
/// Second-signal notice. Printed immediately before `_exit`.
const FORCEFUL_MSG: &[u8] = b"\r\x1b[K[abort] second signal received, forcing immediate exit\n";

/// Pointer to the kill-switch [`AtomicBool`] handed to
/// [`peel::coordinator::run`] via [`peel::coordinator::RunArgs::kill_switch`].
/// The signal handler reads this with one async-signal-safe atomic
/// load and stores `true` into the pointee; `main` keeps the owning
/// [`Arc`] alive until process exit so the dereference is always
/// valid.
static SHUTDOWN_PTR: AtomicPtr<AtomicBool> = AtomicPtr::new(ptr::null_mut());

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

/// Signal handler. **Async-signal-safe operations only:** atomic
/// loads/stores, raw `write(2)` of static byte slices, and (on the
/// second signal) `_exit`. No allocation, no formatting, no locking,
/// no `Arc` ref-count traffic.
extern "C" fn shutdown_handler(sig: i32) {
    // The previous count tells us whether this is the first delivery
    // (count == 0 → graceful) or a follow-up (count >= 1 → forceful).
    // Doing this `fetch_add` first means a second signal that arrives
    // mid-handler still observes "this is the second one" and takes
    // the `_exit` branch.
    if SIGNAL_COUNT.fetch_add(1, Ordering::AcqRel) == 0 {
        // First delivery: graceful path. Record the signal number so
        // `main` can pick the conventional `128 + signum` exit code,
        // flip the kill switch the coordinator polls between
        // checkpoints, and emit a one-line notice so an interactive
        // operator knows their Ctrl-C registered.
        FIRST_SIGNAL.store(sig, Ordering::Release);

        let ptr = SHUTDOWN_PTR.load(Ordering::Acquire);
        if !ptr.is_null() {
            // SAFETY: `SHUTDOWN_PTR` is set in `install_signal_handlers`
            // from `Arc::as_ptr` on a heap `AtomicBool`. `main` holds
            // the owning `Arc` until the process exits (either via
            // normal return or `_exit` below), so the pointee outlives
            // every signal delivery. `AtomicBool::store` is
            // async-signal-safe.
            unsafe { (*ptr).store(true, Ordering::Release) };
        }

        let msg: &[u8] = if sig == SIGINT {
            SIGINT_GRACEFUL_MSG
        } else {
            SIGTERM_GRACEFUL_MSG
        };
        // SAFETY: `write(2)` with a `'static` byte slice is
        // async-signal-safe. We discard the return value because there
        // is no useful recovery from a partial / failed stderr write
        // inside a signal handler.
        unsafe { write(STDERR_FD, msg.as_ptr(), msg.len()) };
    } else {
        // Second (or later) delivery: drop the polite path. Best-effort
        // notice, then immediate exit.
        // SAFETY: same reasoning as the graceful-path `write` above.
        unsafe { write(STDERR_FD, FORCEFUL_MSG.as_ptr(), FORCEFUL_MSG.len()) };
        // SAFETY: `_exit(2)` is the textbook async-signal-safe exit
        // call; calling it from a signal handler is its intended use.
        unsafe { _exit(128 + sig) };
    }
}

/// Install [`shutdown_handler`] for SIGINT and SIGTERM and publish the
/// kill-switch pointer the handler will store into.
///
/// Must be called before any thread that holds the `Arc` is spawned.
/// `main` calls it from the single-threaded prelude, so the
/// `SHUTDOWN_PTR` store is happens-before any subsequent thread spawn
/// and the handler observes a valid pointer from the first delivery.
fn install_signal_handlers(kill: &Arc<AtomicBool>) -> Result<()> {
    SHUTDOWN_PTR.store(Arc::as_ptr(kill) as *mut AtomicBool, Ordering::Release);
    for sig in [SIGINT, SIGTERM] {
        // SAFETY: `signal(2)` takes a signal number and a function
        // pointer with `extern "C" fn(i32)` ABI, which matches
        // `shutdown_handler`. The handler only performs
        // async-signal-safe work.
        let prev = unsafe { signal(sig, shutdown_handler) };
        if prev == SIG_ERR {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("installing handler for signal {sig}"));
        }
    }
    Ok(())
}

/// Human-readable name for the signal numbers we install handlers
/// for. Used only in the `[abort]` stderr line.
fn signal_name(sig: i32) -> &'static str {
    match sig {
        SIGINT => "SIGINT",
        SIGTERM => "SIGTERM",
        _ => "signal",
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Pick the progress mode from whether stderr is a real terminal.
    // The TTY path uses hand-rolled ANSI on stderr; the non-TTY path
    // emits `tracing::info!` events that the subscriber below routes
    // back to stderr in human-readable form.
    let stderr_is_tty = std::io::stderr().is_terminal();
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

    // Capture the http_version label before consuming `cli`. Both
    // banners (http_version and io_backend) are printed below as plain
    // stderr scrollback ABOVE the TTY renderer's redraw region — the
    // renderer's cursor-up math can't reach into scrollback, so the
    // banners are immune to corruption from later redraws. On non-TTY
    // we leave them to the `tracing::info!` calls inside
    // `into_run_args` and `select_backend` (the subscriber is at INFO
    // level there).
    let http_banner = http_version_banner(cli.http_version.into());
    let mut args = cli
        .into_run_args()
        .context("constructing the HTTP client")?;

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
        )
        .context("spawning the TTY progress renderer")?
    } else {
        spawn_renderer(
            Arc::clone(&state),
            LogRenderer::new(),
            Duration::from_secs(2),
        )
        .context("spawning the log progress renderer")?
    };

    let result = run(args);

    // Tell the renderer to stop, regardless of whether `run` succeeded
    // or errored, so we can join it before exiting `main`.
    state.mark_done();
    let _ = render_handle.join();

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
        Err(other) => return Err(anyhow::Error::from(other).context("running peel")),
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
