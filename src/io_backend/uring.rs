//! Linux `io_uring` file-IO backend (PLAN_v2.md §7.2).
//!
//! On a kernel new enough to support `io_uring` (5.6+), this backend
//! batches the download workers' `pwrite` / `pread` / `fsync`
//! submissions through a single ring on a dedicated IO thread. The
//! aggregate kernel-syscall count drops from
//! `O(workers * chunks_per_worker)` to `O(submit_batches)` — at N=64
//! workers the difference shows up cleanly on a localhost mock.
//!
//! # Threading
//!
//! Workers call into [`UringBackend`] like they call into any
//! [`crate::io_backend::IoBackend`]: each call is synchronous. Under
//! the hood the call hands an [`OpRequest`] to a bounded
//! [`mpsc::sync_channel`] and blocks on the per-op
//! [`Completion`]. The dedicated IO thread owns the [`IoUring`]
//! handle, drains the channel, pushes SQEs, and completes ops as CQEs
//! arrive.
//!
//! `submit_with_args` (or `submit_and_wait` on the kernel-disagrees
//! fallback) is the only sync primitive used; no async runtime is
//! involved (PLAN_v2.md §7's hard rule). The IO thread bounds its
//! wait via a kernel-side timespec so it wakes at least once per
//! watchdog cadence even when no CQE arrives — see
//! `PLAN_decoder_freeze.md` §2.4a.
//!
//! # Capability probe
//!
//! [`UringBackend::probe`] tries the default ring depth, falls back to
//! a smaller one if `RLIMIT_MEMLOCK` rejects the larger allocation,
//! and returns `None` (with a `tracing::warn!` line) if the kernel has
//! no usable `io_uring` at all. Callers fall back to the blocking
//! backend on `None`.

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use io_uring::{opcode, squeue, types, IoUring};

use super::{IoBackend, NetStream, SocketConfig};

/// User-data tag bit set on the LinkTimeout SQE that pairs with each
/// timed socket op. The IO thread's CQE drain checks this bit and
/// silently discards the timeout CQE; only the main op's CQE
/// (`user_data` without the tag) drives a [`Completion`].
const TIMEOUT_TAG: u64 = 1u64 << 63;

/// Default ring depth.
///
/// Sized so that 64 workers can keep the ring busy with several
/// in-flight ops each before the SQ saturates and the IO thread has
/// to submit. Must be a power of two per the `io_uring` ABI.
pub const DEFAULT_RING_DEPTH: u32 = 256;

/// Minimum ring depth probed at startup if [`DEFAULT_RING_DEPTH`]
/// fails (typically due to `RLIMIT_MEMLOCK`). Must be a power of two.
pub const MIN_RING_DEPTH: u32 = 8;

/// Linux `RLIMIT_NOFILE` resource id.
///
/// Hard-coded so we do not pull in `libc` as a direct runtime
/// dependency for a single integer constant. Stable across the
/// architectures the standards doc cares about (x86_64 and aarch64
/// Linux).
const RLIMIT_NOFILE: i32 = 7;

/// Default age threshold for the per-op in-flight watchdog
/// (`PLAN_decoder_freeze.md` §2.1). Any op whose CQE has not
/// arrived within this window emits one `tracing::warn!` per
/// warn-interval, identifying the op that the IO thread is
/// stuck waiting on.
///
/// Matches `progress::DEFAULT_STALL_WARN_INTERVAL` (30 s) so the
/// uring-side warning composes with the renderer-side
/// "pipeline frozen" warning: a freeze surfaces both signals
/// inside the same wall-clock window. Override via
/// `PEEL_URING_INFLIGHT_WARN_SECS`.
const DEFAULT_INFLIGHT_WARN: Duration = Duration::from_secs(30);

/// Linux `ETIME` (timer expired) errno. The kernel returns this from
/// `io_uring_enter` when a `submit_with_args` timespec elapses
/// before the requested number of completions arrive — *not* a
/// failure mode, just "no CQE in this window, try again."
///
/// Hard-coded to keep us off `libc` per the policy in `RLIMIT_NOFILE`'s
/// comment.
const ETIME: i32 = 62;

/// Lower / upper bound on the IO thread's wait cadence
/// (`PLAN_decoder_freeze.md` §2.4a). The thread wakes at least every
/// `inflight_warn / 4`, clamped to `[1s, 5s]`, so the §2.1 walker has
/// a chance to fire even when no CQE ever arrives. Without this, a
/// kernel-level CQE drop wedges `submit_with_args` indefinitely and
/// the walker line is unreachable — exactly the silence we observed
/// in the snapshot-restore freeze.
const WALKER_WAKE_FLOOR: Duration = Duration::from_secs(1);
const WALKER_WAKE_CEIL: Duration = Duration::from_secs(5);

/// Compute the IO thread's bounded-wait cadence from the configured
/// in-flight warn threshold. Aims for roughly four wake-ups per
/// warn-interval — frequent enough that a stuck op is identified
/// inside the same `inflight_warn` window the operator already knows,
/// rare enough that a healthy idle ring does not burn syscalls.
fn walker_wake_period(inflight_warn: Duration) -> Duration {
    let quarter = inflight_warn / 4;
    quarter.clamp(WALKER_WAKE_FLOOR, WALKER_WAKE_CEIL)
}

/// Read `PEEL_URING_INFLIGHT_WARN_SECS` (positive integer
/// seconds) and fall back to [`DEFAULT_INFLIGHT_WARN`]. `0` or
/// any other invalid value disables the env override; the default
/// applies. There is no way to disable the watchdog entirely
/// today — the warning is cheap and silent under healthy
/// operation.
fn inflight_warn_from_env() -> Duration {
    std::env::var("PEEL_URING_INFLIGHT_WARN_SECS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|n| *n > 0)
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_INFLIGHT_WARN)
}

/// IO-thread loop result reported back to the constructor.
///
/// Wraps the underlying [`io::Error`] from the kernel rejecting the
/// ring construction (`ENOSYS`, `EPERM`, `ENOMEM`, etc.). Wrapping
/// keeps the trait surface narrow — callers branch on
/// [`UringBackend::probe`] returning `None` rather than inspecting
/// errno.
#[derive(Debug)]
pub struct UringInitError {
    /// Underlying OS error from `IoUring::new` or thread spawning.
    pub source: io::Error,
}

impl std::fmt::Display for UringInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "io_uring init failed: {}", self.source)
    }
}

impl std::error::Error for UringInitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// io_uring-backed implementation of [`IoBackend`].
///
/// Construction spawns the dedicated IO thread; drop tears it down by
/// closing the submission channel and joining the thread. Callers
/// share the backend through `Arc<dyn IoBackend>` like any other
/// implementation.
pub struct UringBackend {
    tx: Option<mpsc::SyncSender<OpRequest>>,
    join: Mutex<Option<JoinHandle<()>>>,
    depth: u32,
}

impl std::fmt::Debug for UringBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UringBackend")
            .field("depth", &self.depth)
            .finish()
    }
}

impl UringBackend {
    /// Construct a backend with the given ring depth.
    ///
    /// Spawns the dedicated IO thread on success. Returns
    /// [`UringInitError`] if the kernel rejects the ring construction
    /// (no `io_uring` support, `RLIMIT_MEMLOCK` too low for `depth`,
    /// seccomp policy blocking the syscall, …) or if the IO thread
    /// fails to spawn.
    ///
    /// # Errors
    ///
    /// See above.
    pub fn try_new(depth: u32) -> Result<Self, UringInitError> {
        let ring = IoUring::new(depth).map_err(|source| UringInitError { source })?;
        let cap = depth.max(1) as usize;
        let (tx, rx) = mpsc::sync_channel::<OpRequest>(cap);
        let depth_for_thread = depth;
        let handle = thread::Builder::new()
            .name("peel-io-uring".into())
            .spawn(move || io_thread_loop(ring, rx, depth_for_thread))
            .map_err(|e| UringInitError {
                source: io::Error::other(e),
            })?;
        Ok(Self {
            tx: Some(tx),
            join: Mutex::new(Some(handle)),
            depth,
        })
    }

    /// Probe the kernel for usable `io_uring`.
    ///
    /// Tries [`DEFAULT_RING_DEPTH`] first, then [`MIN_RING_DEPTH`] if
    /// the larger ring is rejected (typically `RLIMIT_MEMLOCK`).
    /// Returns `None` if both fail; the caller (the §7.3 selection
    /// logic) falls back to the blocking backend on `None`.
    ///
    /// `workers` is consulted for an `RLIMIT_NOFILE` warning only —
    /// the file-descriptor limit does not gate ring creation.
    #[must_use]
    pub fn probe(workers: u32) -> Option<Self> {
        check_rlimit_nofile(workers);
        match Self::try_new(DEFAULT_RING_DEPTH) {
            Ok(b) => return Some(b),
            Err(e) => {
                tracing::debug!(
                    "io_uring depth {DEFAULT_RING_DEPTH} rejected: {}; trying {MIN_RING_DEPTH}",
                    e.source
                );
            }
        }
        match Self::try_new(MIN_RING_DEPTH) {
            Ok(b) => {
                tracing::warn!(
                    "io_uring depth reduced to {MIN_RING_DEPTH}; \
                     RLIMIT_MEMLOCK is too low for the default depth ({DEFAULT_RING_DEPTH}). \
                     Run `ulimit -l` to inspect; raising the limit lets peel batch more SQEs."
                );
                Some(b)
            }
            Err(e) => {
                tracing::warn!("io_uring unavailable: {}; using blocking IO", e.source);
                None
            }
        }
    }

    /// The configured ring depth. Useful for diagnostic logging only.
    #[must_use]
    pub fn ring_depth(&self) -> u32 {
        self.depth
    }

    fn dispatch(&self, req: OpRequest) -> io::Result<()> {
        let tx = self
            .tx
            .as_ref()
            .ok_or_else(|| io::Error::other("uring backend has been dropped; cannot dispatch"))?;
        tx.send(req)
            .map_err(|_| io::Error::other("uring io thread exited; cannot dispatch"))
    }

    fn tx_clone(&self) -> io::Result<mpsc::SyncSender<OpRequest>> {
        self.tx
            .as_ref()
            .cloned()
            .ok_or_else(|| io::Error::other("uring backend has been dropped"))
    }
}

impl Drop for UringBackend {
    fn drop(&mut self) {
        // Drop the sender first; that closes the channel and signals
        // the IO thread to drain in-flight ops and exit. Then join.
        self.tx = None;
        if let Ok(mut g) = self.join.lock() {
            if let Some(h) = g.take() {
                let _ = h.join();
            }
        }
    }
}

impl IoBackend for UringBackend {
    fn name(&self) -> &'static str {
        "uring"
    }

    fn pwrite_all_at(&self, fd: BorrowedFd<'_>, offset: u64, buf: &[u8]) -> io::Result<()> {
        let completion = Arc::new(Completion::new());
        let req = OpRequest {
            kind: OpKind::WriteAll,
            fd: fd.as_raw_fd(),
            base_offset: offset,
            // Cast away const for storage. The IO thread only treats
            // this as `*const u8` when building Write SQEs.
            ptr: buf.as_ptr() as *mut u8,
            total_len: buf.len(),
            timeout_ns: 0,
            completion: Arc::clone(&completion),
        };
        self.dispatch(req)?;
        completion.wait().map(|_| ())
    }

    fn pread_at(&self, fd: BorrowedFd<'_>, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let completion = Arc::new(Completion::new());
        let req = OpRequest {
            kind: OpKind::ReadShort,
            fd: fd.as_raw_fd(),
            base_offset: offset,
            ptr: buf.as_mut_ptr(),
            total_len: buf.len(),
            timeout_ns: 0,
            completion: Arc::clone(&completion),
        };
        self.dispatch(req)?;
        completion.wait()
    }

    fn pread_exact_at(&self, fd: BorrowedFd<'_>, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        let completion = Arc::new(Completion::new());
        let req = OpRequest {
            kind: OpKind::ReadExact,
            fd: fd.as_raw_fd(),
            base_offset: offset,
            ptr: buf.as_mut_ptr(),
            total_len: buf.len(),
            timeout_ns: 0,
            completion: Arc::clone(&completion),
        };
        self.dispatch(req)?;
        completion.wait().map(|_| ())
    }

    fn sync_all(&self, fd: BorrowedFd<'_>) -> io::Result<()> {
        let completion = Arc::new(Completion::new());
        let req = OpRequest {
            kind: OpKind::Fsync,
            fd: fd.as_raw_fd(),
            base_offset: 0,
            ptr: std::ptr::null_mut(),
            total_len: 0,
            timeout_ns: 0,
            completion: Arc::clone(&completion),
        };
        self.dispatch(req)?;
        completion.wait().map(|_| ())
    }

    fn connect(&self, addr: SocketAddr, config: &SocketConfig) -> io::Result<Box<dyn NetStream>> {
        // We use std's `TcpStream::connect_timeout` for the actual
        // three-way handshake — it is a one-shot per connection, not
        // on the hot per-byte path, and re-implementing it via
        // io_uring's Connect SQE buys nothing in the workloads §7b
        // targets. After the handshake, we strip the file descriptor
        // out of the `TcpStream` and wrap it in [`UringSocket`] so
        // every subsequent read/write goes through the ring.
        //
        // SO_RCVTIMEO / SO_SNDTIMEO would not apply here: per the
        // io_uring kernel docs, those socket-level timeouts are
        // *ignored* by io_uring's Recv/Send. Per-op cancellation is
        // handled instead by linked LinkTimeout SQEs that
        // [`UringSocket`] attaches based on the supplied
        // [`SocketConfig`].
        let tcp = TcpStream::connect_timeout(&addr, config.connect_timeout)?;
        tcp.set_nodelay(config.nodelay)?;
        let owned: OwnedFd = tcp.into();
        let sender = self.tx_clone()?;
        Ok(Box::new(UringSocket::new(
            owned,
            sender,
            config.read_timeout,
            config.write_timeout,
        )))
    }
}

/// `Read + Write` adapter that routes every byte through the shared
/// io_uring submission ring.
///
/// The adapter holds an [`OwnedFd`] for the connected socket and a
/// clone of the IO-thread submission channel. Each `read` / `write`
/// call dispatches a [`OpKind::SocketRecv`] / [`OpKind::SocketSend`]
/// op with the configured per-op timeout (enforced by a linked
/// LinkTimeout SQE). On cancellation the kernel returns
/// `-ECANCELED`, which the IO thread maps to
/// [`io::ErrorKind::TimedOut`]; rustls and the hand-rolled HTTP
/// client see standard [`io::Error`]s either way.
///
/// The fd is owned: dropping the socket closes it, which by the time
/// `Drop` runs has no in-flight uring op against it (every
/// `read`/`write` is synchronous from the caller's POV, so the last
/// kernel access has already returned).
pub struct UringSocket {
    fd: OwnedFd,
    sender: mpsc::SyncSender<OpRequest>,
    read_timeout: Option<Duration>,
    write_timeout: Option<Duration>,
}

impl UringSocket {
    fn new(
        fd: OwnedFd,
        sender: mpsc::SyncSender<OpRequest>,
        read_timeout: Option<Duration>,
        write_timeout: Option<Duration>,
    ) -> Self {
        Self {
            fd,
            sender,
            read_timeout,
            write_timeout,
        }
    }

    fn submit(
        &self,
        kind: OpKind,
        ptr: *mut u8,
        len: usize,
        timeout: Option<Duration>,
    ) -> io::Result<usize> {
        let completion = Arc::new(Completion::new());
        let timeout_ns = timeout
            .and_then(|d| u64::try_from(d.as_nanos()).ok())
            .unwrap_or(0);
        let req = OpRequest {
            kind,
            fd: self.fd.as_raw_fd(),
            base_offset: 0,
            ptr,
            total_len: len,
            timeout_ns,
            completion: Arc::clone(&completion),
        };
        self.sender
            .send(req)
            .map_err(|_| io::Error::other("uring io thread exited; socket op failed"))?;
        completion.wait()
    }
}

impl std::fmt::Debug for UringSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UringSocket")
            .field("fd", &self.fd.as_raw_fd())
            .field("read_timeout", &self.read_timeout)
            .field("write_timeout", &self.write_timeout)
            .finish()
    }
}

impl Read for UringSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.submit(
            OpKind::SocketRecv,
            buf.as_mut_ptr(),
            buf.len(),
            self.read_timeout,
        )
    }
}

impl Write for UringSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.submit(
            OpKind::SocketSend,
            buf.as_ptr() as *mut u8,
            buf.len(),
            self.write_timeout,
        )
    }

    fn flush(&mut self) -> io::Result<()> {
        // Sockets do not buffer userspace writes here; the kernel's
        // send buffer is flushed by the OS on its own schedule.
        Ok(())
    }
}

/// What kind of IO an [`OpRequest`] performs.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum OpKind {
    /// File: write the full buffer; resubmit on partial completions.
    WriteAll,
    /// File: read up to `total_len` bytes; complete on first CQE
    /// (short reads OK).
    ReadShort,
    /// File: read exactly `total_len` bytes; resubmit on partial;
    /// report `UnexpectedEof` if the kernel returns 0 before
    /// completing.
    ReadExact,
    /// File: `fsync` the fd. `ptr` and `total_len` are unused.
    Fsync,
    /// Socket: receive up to `total_len` bytes; complete on first
    /// CQE. Returns 0 on remote close (mirrors `read(2)` semantics).
    /// The optional [`OpRequest::timeout_ns`] is enforced via a
    /// linked LinkTimeout SQE; on timeout the kernel cancels the
    /// recv and the CQE returns `-ECANCELED`, which the handler maps
    /// to [`io::ErrorKind::TimedOut`].
    SocketRecv,
    /// Socket: send up to `total_len` bytes; complete on first CQE.
    /// Same timeout semantics as [`OpKind::SocketRecv`].
    SocketSend,
}

impl OpKind {
    fn supports_timeout(self) -> bool {
        matches!(self, Self::SocketRecv | Self::SocketSend)
    }
}

/// One request handed from a worker to the IO thread.
///
/// `ptr` is a raw pointer into the caller's stack buffer. The calling
/// thread blocks on [`Completion`] until the IO thread fires it, which
/// guarantees the buffer outlives every kernel access. The
/// `unsafe impl Send` below is sound under that contract.
struct OpRequest {
    kind: OpKind,
    fd: RawFd,
    base_offset: u64,
    ptr: *mut u8,
    total_len: usize,
    /// Per-op timeout in nanoseconds for [`OpKind::SocketRecv`] /
    /// [`OpKind::SocketSend`]. `0` disables the linked timeout. File
    /// ops ignore this field.
    timeout_ns: u64,
    completion: Arc<Completion>,
}

// SAFETY: The contract for sending `OpRequest` across thread
// boundaries is that the buffer at `(ptr, total_len)` outlives the
// completion notification. The trait methods above arrange this by
// blocking the calling thread on `Completion::wait` until the IO
// thread completes the op; at that point no more kernel access
// occurs. The IO thread itself never dereferences `ptr` from Rust
// code — it hands it to the kernel via SQE submission and then awaits
// the matching CQE.
unsafe impl Send for OpRequest {}

/// IO-thread side state for one in-flight op.
///
/// Identical fields to [`OpRequest`] minus the kind handling, plus a
/// `bytes_done` counter for the WriteAll / ReadExact resubmit path
/// and the optional `timeout_ts` Box that keeps the LinkTimeout's
/// timespec alive for the duration of the operation.
struct InFlight {
    kind: OpKind,
    fd: RawFd,
    base_offset: u64,
    ptr: *mut u8,
    total_len: usize,
    bytes_done: usize,
    completion: Arc<Completion>,
    /// Heap-allocated [`types::Timespec`] kept alive while the linked
    /// timeout SQE is in flight. The kernel reads the timespec via the
    /// pointer carried in the LinkTimeout SQE; the Box ensures a
    /// stable address until the op's CQE arrives. `None` for ops
    /// without a linked timeout.
    ///
    /// The field is never read from Rust code — its purpose is the
    /// `Box`'s drop ordering. Clippy's `dead_code` lint does not see
    /// the kernel-side reference and would flag the field
    /// otherwise.
    #[allow(dead_code)]
    timeout_ts: Option<Box<types::Timespec>>,
    /// Wall-clock time the op was first inserted into the tracker.
    /// Used by the §2.1 watchdog to detect ops whose CQE has not
    /// arrived in `PEEL_URING_INFLIGHT_WARN_SECS`. Reset to the
    /// resume time when a partial WriteAll/ReadExact resubmits, so
    /// the watchdog only complains about a single submission's age
    /// — not the cumulative time across resubmits.
    submitted_at: Instant,
    /// Most recent wall-clock time the watchdog warned about this op.
    /// Used to rate-limit the warning to one line per warn-interval
    /// per op, matching the stall detector's discipline at
    /// [`crate::progress::StallDetector`]. `None` until the first
    /// warning fires.
    last_warned_at: Option<Instant>,
}

impl InFlight {
    fn from_request(
        req: OpRequest,
        timeout_ts: Option<Box<types::Timespec>>,
        now: Instant,
    ) -> Self {
        Self {
            kind: req.kind,
            fd: req.fd,
            base_offset: req.base_offset,
            ptr: req.ptr,
            total_len: req.total_len,
            bytes_done: 0,
            completion: req.completion,
            timeout_ts,
            submitted_at: now,
            last_warned_at: None,
        }
    }

    fn complete(&self, result: io::Result<usize>) {
        self.completion.set(result);
    }
}

// SAFETY: see `unsafe impl Send for OpRequest` — the IO thread holds
// the only `InFlight` for each id and never sees concurrent access
// from any other thread. The raw pointer is dereferenced only by the
// kernel during SQE submission, never from Rust code.
unsafe impl Send for InFlight {}

/// One-shot completion notifier.
///
/// The calling thread builds it, hands an [`Arc`] clone to the IO
/// thread inside the [`OpRequest`], and parks on
/// [`Self::wait`]. The IO thread calls [`Self::set`] from its CQE
/// handler to release the worker.
struct Completion {
    state: Mutex<Option<io::Result<usize>>>,
    cv: Condvar,
}

impl Completion {
    fn new() -> Self {
        Self {
            state: Mutex::new(None),
            cv: Condvar::new(),
        }
    }

    fn wait(&self) -> io::Result<usize> {
        // INVARIANT: the lock is held only for short, panic-free
        // sections inside this module; treating poisoning as a hard
        // error matches the standards doc's "no surprise panics"
        // policy.
        let mut g = match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        loop {
            if let Some(r) = g.take() {
                return r;
            }
            g = match self.cv.wait(g) {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
    }

    fn set(&self, result: io::Result<usize>) {
        let g = self.state.lock();
        let mut g = match g {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Only the first set wins; later writes (e.g., from a
        // teardown drain) are dropped.
        if g.is_none() {
            *g = Some(result);
        }
        self.cv.notify_all();
    }
}

/// IO-thread state, kept inside a struct so the [`Drop`] impl drains
/// in-flight ops on every exit path (clean or panicking) and unblocks
/// any worker waiting on a completion.
struct InFlightTracker {
    map: HashMap<u64, InFlight>,
}

impl InFlightTracker {
    fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
        }
    }
}

impl Drop for InFlightTracker {
    fn drop(&mut self) {
        for (_, ifl) in self.map.drain() {
            ifl.complete(Err(io::Error::other(
                "uring io thread terminated before op completed",
            )));
        }
    }
}

/// The dedicated IO thread's main loop.
///
/// Owns the [`IoUring`] handle, drains [`OpRequest`]s from `rx`, pushes
/// SQEs, and routes CQEs back to their completion notifiers. Exits
/// when `rx` closes and every in-flight op has resolved.
///
/// The in-flight cap is `depth / 2` (rounded up) so that every
/// in-flight op may consume up to two SQE slots — one for the
/// operation itself and one for the linked timeout used by socket
/// ops. File ops only use one slot; the cap stays the same in both
/// cases, which keeps the bookkeeping simple at the cost of halving
/// the maximum file-IO concurrency. With a default depth of 256, the
/// cap is 128, which is well above any realistic worker count.
fn io_thread_loop(mut ring: IoUring, rx: mpsc::Receiver<OpRequest>, depth: u32) {
    let inflight_cap = ((depth as usize) / 2).max(1);
    let mut tracker = InFlightTracker::new(inflight_cap);
    let mut next_id: u64 = 0;
    let mut sender_open = true;
    // §2.1 (PLAN_decoder_freeze.md): cache the warn threshold once.
    // The env var is read at process start before any worker submits,
    // and re-reading it per loop iteration would just be syscall noise.
    let inflight_warn = inflight_warn_from_env();
    // §2.4a: bound the wait so the walker runs even when no CQE
    // arrives. The Timespec must outlive every `submit_with_args`
    // call that references it; constructing once and reusing matches
    // the kernel's expectation (the pointer is read each call).
    let walker_period = walker_wake_period(inflight_warn);
    let walker_ts = types::Timespec::from(walker_period);
    let submit_args = types::SubmitArgs::new().timespec(&walker_ts);

    'main: loop {
        // Drain new submissions until the in-flight cap is hit or the
        // channel is empty. If we have nothing in flight we block on
        // `recv` so the thread sleeps cleanly.
        loop {
            if tracker.map.len() >= inflight_cap {
                break;
            }
            if tracker.map.is_empty() && sender_open {
                match rx.recv() {
                    Ok(req) => {
                        let id = next_id & !TIMEOUT_TAG;
                        match push_initial(&mut ring, id, &req) {
                            Ok(timeout_ts) => {
                                next_id = next_id.wrapping_add(1);
                                tracker.map.insert(
                                    id,
                                    InFlight::from_request(req, timeout_ts, Instant::now()),
                                );
                            }
                            Err(()) => {
                                req.completion.set(Err(io::Error::other(
                                    "uring SQ overflow on initial push",
                                )));
                            }
                        }
                    }
                    Err(_) => {
                        sender_open = false;
                        break;
                    }
                }
            } else {
                match rx.try_recv() {
                    Ok(req) => {
                        let id = next_id & !TIMEOUT_TAG;
                        match push_initial(&mut ring, id, &req) {
                            Ok(timeout_ts) => {
                                next_id = next_id.wrapping_add(1);
                                tracker.map.insert(
                                    id,
                                    InFlight::from_request(req, timeout_ts, Instant::now()),
                                );
                            }
                            Err(()) => {
                                req.completion.set(Err(io::Error::other(
                                    "uring SQ overflow on initial push",
                                )));
                            }
                        }
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        sender_open = false;
                        break;
                    }
                }
            }
        }

        if tracker.map.is_empty() {
            if !sender_open {
                break 'main;
            }
            continue;
        }

        // §2.4a: submit + wait with a kernel-side timespec. Returns
        // promptly with `Ok(_)` when a CQE is queued, or with
        // `Err(ETIME)` when `walker_period` elapses without one. The
        // ETIME path is *not* a failure — we drop through to the
        // walker so a stuck op gets its diagnostic line, then loop
        // and re-arm the wait. Any other error is treated as before:
        // drain every in-flight with the error and tear down.
        match ring.submitter().submit_with_args(1, &submit_args) {
            Ok(_) => {}
            Err(e) if e.raw_os_error() == Some(ETIME) => {
                // No CQE arrived within walker_period. Continue to
                // the walker; in-flight ops remain in the kernel.
            }
            Err(e) => {
                let kind = e.kind();
                let msg = format!("uring submit_with_args failed: {e}");
                tracker.map.drain().for_each(|(_, ifl)| {
                    ifl.complete(Err(io::Error::new(kind, msg.clone())));
                });
                break 'main;
            }
        }

        // Drain CQEs.
        loop {
            let next = ring.completion().next();
            let cqe = match next {
                Some(c) => c,
                None => break,
            };
            handle_cqe(&mut ring, &mut tracker, cqe.user_data(), cqe.result());
        }

        // §2.1 watchdog: any op still in flight with an age past
        // `inflight_warn` gets a one-line warning, rate-limited to
        // one entry per warn-interval per op. Cheap (a HashMap walk
        // and an Instant compare per entry) — runs at most once per
        // CQE batch, which is bounded by the in-flight cap.
        warn_long_inflight(&mut tracker, Instant::now(), inflight_warn);
    }
    // tracker drops on return: drains any leftover in-flight ops
    // with a "io thread terminated" error so workers do not deadlock.
}

/// Walk every in-flight op and emit one `tracing::warn!` line per op
/// whose CQE has not arrived in `warn_after`. Returns the number of
/// warnings emitted on this pass — the IO thread does not consume
/// the count, but tests use it to assert the rate-limit behavior
/// without having to install a tracing subscriber.
///
/// Rate-limited via each op's `last_warned_at` field: an op already
/// warned about within the last `warn_after` window is silently
/// skipped. The first warning fires as soon as `age >= warn_after`;
/// subsequent warnings fire `warn_after`-spaced thereafter for as
/// long as the op stays stuck.
fn warn_long_inflight(tracker: &mut InFlightTracker, now: Instant, warn_after: Duration) -> usize {
    let mut warned = 0usize;
    for ifl in tracker.map.values_mut() {
        let age = now.saturating_duration_since(ifl.submitted_at);
        if age < warn_after {
            continue;
        }
        if let Some(prev) = ifl.last_warned_at {
            if now.saturating_duration_since(prev) < warn_after {
                continue;
            }
        }
        let age_secs = age.as_secs();
        tracing::warn!(
            target: "peel::io_uring",
            kind = ?ifl.kind,
            fd = ifl.fd,
            base_offset = ifl.base_offset,
            total_len = ifl.total_len,
            bytes_done = ifl.bytes_done,
            age_secs,
            "io_uring op stalled: no CQE in {age_secs}s",
        );
        ifl.last_warned_at = Some(now);
        warned = warned.saturating_add(1);
    }
    warned
}

/// Push the initial SQE(s) for a fresh request.
///
/// Returns the boxed [`types::Timespec`] that must outlive the
/// LinkTimeout SQE, or `None` if the op did not need a linked
/// timeout. Returns `Err(())` if the submission queue rejected the
/// push; the caller is expected to keep the in-flight cap below the
/// SQ capacity so this does not happen in practice.
fn push_initial(
    ring: &mut IoUring,
    id: u64,
    req: &OpRequest,
) -> Result<Option<Box<types::Timespec>>, ()> {
    let timeout_ts = if req.kind.supports_timeout() && req.timeout_ns > 0 {
        Some(Box::new(types::Timespec::from(Duration::from_nanos(
            req.timeout_ns,
        ))))
    } else {
        None
    };
    let pushed = push_sqe(
        ring,
        id,
        req.kind,
        req.fd,
        req.base_offset,
        req.ptr,
        req.total_len,
        timeout_ts.as_deref(),
    );
    if !pushed {
        return Err(());
    }
    Ok(timeout_ts)
}

/// Push the resume SQE for a partially-completed WriteAll / ReadExact.
///
/// File ops never carry a linked timeout, so this is a single-SQE
/// push.
fn push_resume(ring: &mut IoUring, id: u64, ifl: &InFlight) -> bool {
    let off = ifl.base_offset.saturating_add(ifl.bytes_done as u64);
    // SAFETY: `bytes_done < total_len` is checked by the caller; the
    // original buffer is at least `total_len` bytes long, so adding
    // `bytes_done` stays within the same allocation.
    let ptr = unsafe { ifl.ptr.add(ifl.bytes_done) };
    let remaining = ifl.total_len - ifl.bytes_done;
    push_sqe(ring, id, ifl.kind, ifl.fd, off, ptr, remaining, None)
}

/// Push the op's SQE, plus a linked LinkTimeout SQE if `timeout_ts`
/// is `Some`.
///
/// When `timeout_ts` is supplied, the main op's SQE is given the
/// `IO_LINK` flag so the LinkTimeout that follows applies to it. The
/// timeout's user_data has the [`TIMEOUT_TAG`] bit set; the CQE
/// drain ignores those entries.
#[allow(clippy::too_many_arguments)]
fn push_sqe(
    ring: &mut IoUring,
    id: u64,
    kind: OpKind,
    fd: RawFd,
    offset: u64,
    ptr: *mut u8,
    len: usize,
    timeout_ts: Option<&types::Timespec>,
) -> bool {
    let len_u32 = u32::try_from(len).unwrap_or(u32::MAX);
    let mut entry = match kind {
        OpKind::WriteAll => opcode::Write::new(types::Fd(fd), ptr.cast::<u8>(), len_u32)
            .offset(offset)
            .build(),
        OpKind::ReadShort | OpKind::ReadExact => opcode::Read::new(types::Fd(fd), ptr, len_u32)
            .offset(offset)
            .build(),
        OpKind::Fsync => opcode::Fsync::new(types::Fd(fd)).build(),
        OpKind::SocketRecv => opcode::Recv::new(types::Fd(fd), ptr, len_u32).build(),
        OpKind::SocketSend => opcode::Send::new(types::Fd(fd), ptr.cast::<u8>(), len_u32).build(),
    };
    if timeout_ts.is_some() {
        entry = entry.flags(squeue::Flags::IO_LINK);
    }
    entry = entry.user_data(id);

    let mut sq = ring.submission();
    // SAFETY: The buffer pointed at by `ptr` is valid for `len`
    // bytes for the duration of this submission. The calling thread
    // owns the buffer and is blocked on the matching `Completion`,
    // so the buffer cannot be deallocated or aliased until after the
    // CQE is drained. The fd is borrowed for the call's duration via
    // the `BorrowedFd<'_>` argument on the trait method, or via the
    // [`UringSocket`]'s `OwnedFd` (which lives as long as the socket
    // is borrowed for the read/write call).
    let result = unsafe { sq.push(&entry) };
    if result.is_err() {
        sq.sync();
        return false;
    }

    if let Some(ts) = timeout_ts {
        let timeout_entry = opcode::LinkTimeout::new(ts as *const types::Timespec)
            .build()
            .user_data(id | TIMEOUT_TAG);
        // SAFETY: `ts` points into a `Box<Timespec>` that the caller
        // (the IO thread, via [`InFlight::timeout_ts`]) keeps alive
        // until the main op's CQE is drained. The kernel only reads
        // the timespec while the LinkTimeout SQE is live, which ends
        // when the main op completes; both events happen before the
        // InFlight's Drop runs.
        let r = unsafe { sq.push(&timeout_entry) };
        if r.is_err() {
            // Bail: with the in-flight cap at depth/2, this should
            // be unreachable. Sync what we have so the partial push
            // is observable to the kernel.
            sq.sync();
            return false;
        }
    }

    sq.sync();
    true
}

fn handle_cqe(ring: &mut IoUring, tracker: &mut InFlightTracker, id: u64, res: i32) {
    // CQEs from the LinkTimeout sidecar carry the [`TIMEOUT_TAG`]
    // bit. They mean "the timeout finished doing its job"; the main
    // op's CQE (with the bit clear) is what drives the [`Completion`].
    if id & TIMEOUT_TAG != 0 {
        return;
    }

    let mut ifl = match tracker.map.remove(&id) {
        Some(i) => i,
        None => return,
    };

    if res < 0 {
        // Linked timeouts cancel the main op with `-ECANCELED`. For
        // socket ops that's the user-facing TimedOut error; for
        // anything else propagate the raw OS error verbatim.
        const ECANCELED: i32 = 125;
        let err = if -res == ECANCELED && ifl.kind.supports_timeout() {
            io::Error::from(io::ErrorKind::TimedOut)
        } else {
            io::Error::from_raw_os_error(-res)
        };
        ifl.complete(Err(err));
        return;
    }

    let bytes = res as usize;
    let new_total = ifl.bytes_done.saturating_add(bytes);
    ifl.bytes_done = new_total;

    match ifl.kind {
        OpKind::Fsync => ifl.complete(Ok(0)),
        OpKind::ReadShort => ifl.complete(Ok(bytes)),
        OpKind::SocketRecv | OpKind::SocketSend => {
            // Socket ops complete on the first CQE — short reads and
            // short writes are valid in the network world. The
            // caller (the [`UringSocket`] adapter) returns whatever
            // the kernel delivered and the higher layer (HTTP body
            // reader, rustls, …) loops if it needs more bytes.
            ifl.complete(Ok(bytes));
        }
        OpKind::WriteAll | OpKind::ReadExact => {
            if ifl.bytes_done >= ifl.total_len {
                ifl.complete(Ok(ifl.bytes_done));
                return;
            }
            if bytes == 0 {
                let err = match ifl.kind {
                    OpKind::ReadExact => io::Error::from(io::ErrorKind::UnexpectedEof),
                    OpKind::WriteAll => io::Error::from(io::ErrorKind::WriteZero),
                    _ => io::Error::other("uring partial completion with zero bytes"),
                };
                ifl.complete(Err(err));
                return;
            }
            if !push_resume(ring, id, &ifl) {
                ifl.complete(Err(io::Error::other("uring SQ full on resume push")));
                return;
            }
            // Reset the §2.1 watchdog timestamps so the warn path
            // measures only this resubmit's age, not the cumulative
            // time across earlier partials. A genuinely stuck op will
            // re-cross the threshold inside its single submission;
            // we do not want a series of healthy resubmits to summed-
            // age into a false alarm.
            ifl.submitted_at = Instant::now();
            ifl.last_warned_at = None;
            tracker.map.insert(id, ifl);
        }
    }
}

/// Warn if `RLIMIT_NOFILE` is below the threshold required for the
/// configured worker count.
fn check_rlimit_nofile(workers: u32) {
    let target = u64::from(workers).saturating_mul(2);
    let mut rl = ffi::Rlimit { cur: 0, max: 0 };
    // SAFETY: `getrlimit` reads `resource` by value and writes the
    // `rlim` struct out-parameter. We pass a properly initialized
    // pointer into a local struct; the call returns 0 on success or
    // -1 with errno set. Either way the pointer's lifetime brackets
    // the call.
    let rc = unsafe { ffi::getrlimit(RLIMIT_NOFILE, &mut rl as *mut _) };
    if rc != 0 {
        // Could not query — silently skip the warning.
        return;
    }
    if rl.cur < target {
        tracing::warn!(
            "RLIMIT_NOFILE soft limit is {}; recommend at least {} for {} workers \
             (run `ulimit -n {}`)",
            rl.cur,
            target,
            workers,
            target,
        );
    }
}

mod ffi {
    /// Mirrors `struct rlimit` from `<sys/resource.h>` on 64-bit
    /// Linux glibc/musl. Both `rlim_t` fields are unsigned 64-bit
    /// integers on every architecture peel runs on.
    #[repr(C)]
    pub struct Rlimit {
        pub cur: u64,
        pub max: u64,
    }

    extern "C" {
        /// `int getrlimit(int resource, struct rlimit *rlim);`
        pub fn getrlimit(resource: i32, rlim: *mut Rlimit) -> i32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom};
    use std::os::fd::AsFd;
    use std::sync::atomic::{AtomicU64, Ordering};

    static UNIQ: AtomicU64 = AtomicU64::new(0);

    fn unique_temp_path(label: &str) -> std::path::PathBuf {
        let pid = std::process::id();
        let n = UNIQ.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("peel_uring_{label}_{pid}_{nanos}_{n}.bin"))
    }

    struct CleanupOnDrop(std::path::PathBuf);
    impl Drop for CleanupOnDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    fn open_temp(label: &str, len: u64) -> (std::fs::File, CleanupOnDrop) {
        let path = unique_temp_path(label);
        let cleanup = CleanupOnDrop(path.clone());
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .expect("open temp");
        file.set_len(len).expect("set_len");
        (file, cleanup)
    }

    /// Skip helper: probes a small ring; returns None if the runner
    /// kernel does not support `io_uring`.
    fn try_backend() -> Option<UringBackend> {
        UringBackend::try_new(MIN_RING_DEPTH).ok()
    }

    #[test]
    fn name_is_uring() {
        let Some(backend) = try_backend() else {
            eprintln!("skipping: io_uring unavailable on this kernel");
            return;
        };
        assert_eq!(backend.name(), "uring");
    }

    #[test]
    fn write_then_read_round_trips() {
        let Some(backend) = try_backend() else {
            return;
        };
        let (mut file, _cleanup) = open_temp("rw", 1024);
        let payload: Vec<u8> = (0u8..64).collect();
        backend
            .pwrite_all_at(file.as_fd(), 100, &payload)
            .expect("pwrite");
        backend.sync_all(file.as_fd()).expect("sync_all");
        // Read back via the std API to verify the bytes landed.
        file.seek(SeekFrom::Start(100)).expect("seek");
        let mut got = vec![0u8; 64];
        file.read_exact(&mut got).expect("read");
        assert_eq!(got, payload);

        // Also read back through the backend.
        let mut got2 = vec![0u8; 64];
        backend
            .pread_exact_at(file.as_fd(), 100, &mut got2)
            .expect("pread_exact");
        assert_eq!(got2, payload);
    }

    #[test]
    fn pread_short_at_eof() {
        let Some(backend) = try_backend() else {
            return;
        };
        let (file, _cleanup) = open_temp("short", 32);
        let mut got = vec![0u8; 64];
        let n = backend.pread_at(file.as_fd(), 16, &mut got).expect("pread");
        assert_eq!(n, 16);
    }

    #[test]
    fn pread_exact_eof_errors() {
        let Some(backend) = try_backend() else {
            return;
        };
        let (file, _cleanup) = open_temp("exact_eof", 32);
        let mut got = vec![0u8; 64];
        let err = backend
            .pread_exact_at(file.as_fd(), 16, &mut got)
            .expect_err("expected EOF");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn drop_unblocks_pending_workers() {
        // Build a backend with depth 1, drop it, ensure no leak. We
        // can't easily provoke a worker block here without a slow
        // device, but the drop path itself exercises the
        // teardown-then-join sequence.
        let Some(backend) = try_backend() else {
            return;
        };
        drop(backend);
    }

    /// Exercise a partial-completion resubmit by writing more bytes
    /// than the kernel typically delivers in one go. Most filesystems
    /// short-circuit pwrite into a single SQE completion, but this
    /// test still verifies the WriteAll path drives `bytes_done`
    /// forward.
    #[test]
    fn write_all_handles_large_buffers() {
        let Some(backend) = try_backend() else {
            return;
        };
        const SIZE: usize = 4 * 1024 * 1024;
        let (file, _cleanup) = open_temp("large", SIZE as u64);
        let payload = vec![0xA5u8; SIZE];
        backend
            .pwrite_all_at(file.as_fd(), 0, &payload)
            .expect("pwrite");
        let mut got = vec![0u8; SIZE];
        backend
            .pread_exact_at(file.as_fd(), 0, &mut got)
            .expect("pread_exact");
        assert_eq!(got, payload);
    }

    /// Smoke test: drive a few thousand sequential writes through the
    /// ring to exercise the SQ <-> CQE drain cadence.
    #[test]
    fn sequential_writes_drive_through() {
        let Some(backend) = try_backend() else {
            return;
        };
        let total = 4096usize;
        let chunk = 32usize;
        let (file, _cleanup) = open_temp("seq", (total * chunk) as u64);
        let mut buf = vec![0u8; chunk];
        for i in 0..total {
            buf.iter_mut()
                .enumerate()
                .for_each(|(j, b)| *b = ((i + j) & 0xff) as u8);
            backend
                .pwrite_all_at(file.as_fd(), (i * chunk) as u64, &buf)
                .expect("pwrite");
        }
        backend.sync_all(file.as_fd()).expect("sync");
    }

    #[test]
    fn rlimit_nofile_check_does_not_panic() {
        // The check should never panic regardless of the host's
        // ulimit. We don't assert any tracing output here; we just
        // exercise the path.
        check_rlimit_nofile(1);
        check_rlimit_nofile(64);
        check_rlimit_nofile(0);
    }

    /// Sanity: probe is callable without panicking; the returned
    /// option's discriminant depends on the runner.
    #[test]
    fn probe_is_idempotent() {
        let _ = UringBackend::probe(8);
        let _ = UringBackend::probe(64);
    }

    /// Connect through the uring backend to a localhost echo server,
    /// round-trip a small payload via UringSocket's Read+Write impl.
    #[test]
    fn socket_round_trip_against_loopback() {
        use std::net::TcpListener;

        let Some(backend) = try_backend() else {
            return;
        };

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().expect("accept");
            let mut buf = [0u8; 5];
            std::io::Read::read_exact(&mut s, &mut buf).expect("server read");
            assert_eq!(&buf, b"PING!");
            std::io::Write::write_all(&mut s, b"PONG!").expect("server write");
        });

        let cfg = SocketConfig::default();
        let mut stream = backend.connect(addr, &cfg).expect("connect");
        std::io::Write::write_all(&mut stream, b"PING!").expect("client write");
        let mut got = [0u8; 5];
        std::io::Read::read_exact(&mut stream, &mut got).expect("client read");
        assert_eq!(&got, b"PONG!");
        server.join().expect("server thread");
    }

    /// Recv times out via the linked LinkTimeout SQE when the peer
    /// never sends data.
    #[test]
    fn socket_recv_timeout_fires() {
        use std::net::TcpListener;

        let Some(backend) = try_backend() else {
            return;
        };

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        // Server accepts the connection but never writes. Hold the
        // accepted socket alive until the client's recv times out.
        let (sender_done, receiver_done) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (_s, _) = listener.accept().expect("accept");
            // Park until the client signals it observed the timeout.
            let _ = receiver_done.recv();
        });

        let cfg = SocketConfig {
            connect_timeout: Duration::from_secs(2),
            read_timeout: Some(Duration::from_millis(100)),
            write_timeout: Some(Duration::from_secs(1)),
            nodelay: true,
        };
        let mut stream = backend.connect(addr, &cfg).expect("connect");

        let mut buf = [0u8; 64];
        let started = std::time::Instant::now();
        let err = std::io::Read::read(&mut stream, &mut buf).expect_err("expected TimedOut");
        let elapsed = started.elapsed();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "got {err:?}");
        // Bound the timeout's wall clock somewhere reasonable: the
        // configured 100 ms ± a fudge factor for scheduling.
        assert!(
            elapsed >= Duration::from_millis(50),
            "fired too quickly: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "fired too slowly: {elapsed:?}"
        );

        let _ = sender_done.send(());
        server.join().expect("server thread");
    }

    /// Disconnected peer surfaces as Ok(0) on read.
    #[test]
    fn socket_recv_returns_zero_on_remote_close() {
        use std::net::TcpListener;

        let Some(backend) = try_backend() else {
            return;
        };

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let server = std::thread::spawn(move || {
            let (s, _) = listener.accept().expect("accept");
            drop(s); // close immediately
        });

        let cfg = SocketConfig {
            connect_timeout: Duration::from_secs(2),
            read_timeout: Some(Duration::from_secs(2)),
            write_timeout: Some(Duration::from_secs(2)),
            nodelay: true,
        };
        let mut stream = backend.connect(addr, &cfg).expect("connect");
        let mut buf = [0u8; 16];
        let n = std::io::Read::read(&mut stream, &mut buf).expect("read");
        assert_eq!(n, 0);
        server.join().expect("server thread");
    }

    // ---- §2.1 watchdog -------------------------------------------------

    /// Construct a synthetic [`InFlight`] entry far enough away from
    /// the live ring path to test [`warn_long_inflight`] in isolation.
    /// The entry will never fire its [`Completion`] — the test controls
    /// the lifecycle and drops the tracker before any wait could occur.
    fn fake_inflight(submitted_at: Instant) -> InFlight {
        InFlight {
            kind: OpKind::ReadShort,
            fd: -1,
            base_offset: 0,
            ptr: std::ptr::null_mut(),
            total_len: 0,
            bytes_done: 0,
            completion: Arc::new(Completion::new()),
            timeout_ts: None,
            submitted_at,
            last_warned_at: None,
        }
    }

    /// Stale entries past the threshold get warned exactly once per
    /// pass; fresh entries are silent. Mirrors the §2.1 demo: a 60-s-
    /// old op at a 30-s threshold fires; a 5-s-old one does not.
    #[test]
    fn warn_long_inflight_warns_only_stale_entries() {
        let mut tracker = InFlightTracker::new(8);
        let now = Instant::now();
        let warn_after = Duration::from_secs(30);
        tracker
            .map
            .insert(1, fake_inflight(now - Duration::from_secs(60)));
        tracker
            .map
            .insert(2, fake_inflight(now - Duration::from_secs(5)));

        let warned = warn_long_inflight(&mut tracker, now, warn_after);
        assert_eq!(warned, 1);

        // The stale entry has its rate-limit watermark set; the fresh
        // one is untouched.
        assert!(tracker
            .map
            .get(&1)
            .expect("present")
            .last_warned_at
            .is_some());
        assert!(tracker
            .map
            .get(&2)
            .expect("present")
            .last_warned_at
            .is_none());
    }

    /// Re-running the walker inside the same warn window does not
    /// re-warn for the same op — the rate-limit field gates it.
    #[test]
    fn warn_long_inflight_rate_limits_within_window() {
        let mut tracker = InFlightTracker::new(8);
        let t0 = Instant::now();
        let warn_after = Duration::from_secs(30);
        tracker
            .map
            .insert(1, fake_inflight(t0 - Duration::from_secs(60)));

        let first = warn_long_inflight(&mut tracker, t0, warn_after);
        assert_eq!(first, 1);

        // Another walker pass 5 s later: still inside the rate-limit
        // window; no second warning.
        let second = warn_long_inflight(&mut tracker, t0 + Duration::from_secs(5), warn_after);
        assert_eq!(second, 0);

        // After a full warn_after has elapsed since the first warning,
        // the next pass fires again — a stuck op produces one entry
        // per warn-interval, not one per CQE drain.
        let third = warn_long_inflight(&mut tracker, t0 + Duration::from_secs(35), warn_after);
        assert_eq!(third, 1);
    }

    /// Ops that complete (and are removed from the tracker) cannot
    /// fire spurious warnings on later passes.
    #[test]
    fn warn_long_inflight_ignores_completed_ops() {
        let mut tracker = InFlightTracker::new(8);
        let now = Instant::now();
        let warn_after = Duration::from_secs(30);
        tracker
            .map
            .insert(1, fake_inflight(now - Duration::from_secs(60)));
        // Simulate the CQE drain removing the entry before the walker
        // runs.
        tracker.map.remove(&1);

        let warned = warn_long_inflight(&mut tracker, now, warn_after);
        assert_eq!(warned, 0);
    }

    /// §2.4a: the walker wakes at least every quarter of the warn
    /// threshold, clamped to `[1s, 5s]`. The bounds matter: too
    /// short and we burn syscalls on a healthy idle ring; too long
    /// and a stuck op stays invisible past the operator-set warning
    /// interval.
    #[test]
    fn walker_wake_period_clamps() {
        // Default 30s warn → 7.5s, clamped down to 5s ceiling.
        assert_eq!(
            walker_wake_period(Duration::from_secs(30)),
            Duration::from_secs(5),
        );
        // 8s warn → 2s, inside the band.
        assert_eq!(
            walker_wake_period(Duration::from_secs(8)),
            Duration::from_secs(2),
        );
        // 2s warn → 0.5s, clamped up to 1s floor.
        assert_eq!(
            walker_wake_period(Duration::from_secs(2)),
            Duration::from_secs(1),
        );
        // Tiny warn → still 1s floor.
        assert_eq!(
            walker_wake_period(Duration::from_millis(100)),
            Duration::from_secs(1),
        );
        // Huge warn (2 minutes) → 30s, clamped to 5s ceiling.
        assert_eq!(
            walker_wake_period(Duration::from_secs(120)),
            Duration::from_secs(5),
        );
    }

    /// `PEEL_URING_INFLIGHT_WARN_SECS` overrides the default; an
    /// invalid or zero value falls back. Mirrors the env-override
    /// pattern in `progress::StallDetector::from_env`.
    #[test]
    fn inflight_warn_env_override() {
        let prev = std::env::var("PEEL_URING_INFLIGHT_WARN_SECS").ok();
        std::env::set_var("PEEL_URING_INFLIGHT_WARN_SECS", "5");
        assert_eq!(inflight_warn_from_env(), Duration::from_secs(5));
        std::env::set_var("PEEL_URING_INFLIGHT_WARN_SECS", "0");
        assert_eq!(inflight_warn_from_env(), DEFAULT_INFLIGHT_WARN);
        std::env::set_var("PEEL_URING_INFLIGHT_WARN_SECS", "not-a-number");
        assert_eq!(inflight_warn_from_env(), DEFAULT_INFLIGHT_WARN);
        std::env::remove_var("PEEL_URING_INFLIGHT_WARN_SECS");
        assert_eq!(inflight_warn_from_env(), DEFAULT_INFLIGHT_WARN);
        match prev {
            Some(v) => std::env::set_var("PEEL_URING_INFLIGHT_WARN_SECS", v),
            None => std::env::remove_var("PEEL_URING_INFLIGHT_WARN_SECS"),
        }
    }
}
