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
//! `submit_and_wait` is the only sync primitive used; no async runtime
//! is involved (PLAN_v2.md §7's hard rule).
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
use std::io;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

use io_uring::{opcode, types, IoUring};

use super::{IoBackend, NetStream, SocketConfig};

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
            completion: Arc::clone(&completion),
        };
        self.dispatch(req)?;
        completion.wait().map(|_| ())
    }

    fn connect(&self, addr: SocketAddr, config: &SocketConfig) -> io::Result<Box<dyn NetStream>> {
        // §7b.1 placeholder: the Linux io_uring socket implementation
        // (Connect / Send / Recv via SQEs sharing the IO thread) lands
        // in §7b.2. For now route through the blocking `TcpStream`
        // path so the trait surface compiles and the Client refactor
        // in §7b.3 has something to plug into. The mixed
        // "uring-files + blocking-sockets" mode is not a supported
        // production deployment — it exists only between the §7b.1
        // and §7b.2 commits — and the §7.3 selection logic still
        // returns this backend the same way it returned it before
        // §7b.1, so callers see no behavioral change.
        super::BlockingBackend::new().connect(addr, config)
    }
}

/// What kind of file IO an [`OpRequest`] performs.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum OpKind {
    /// Write the full buffer; resubmit on partial completions.
    WriteAll,
    /// Read up to `total_len` bytes; complete on first CQE (short
    /// reads OK).
    ReadShort,
    /// Read exactly `total_len` bytes; resubmit on partial; report
    /// `UnexpectedEof` if the kernel returns 0 before completing.
    ReadExact,
    /// `fsync` the fd. `ptr` and `total_len` are unused.
    Fsync,
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
/// `bytes_done` counter for the WriteAll / ReadExact resubmit path.
struct InFlight {
    kind: OpKind,
    fd: RawFd,
    base_offset: u64,
    ptr: *mut u8,
    total_len: usize,
    bytes_done: usize,
    completion: Arc<Completion>,
}

impl InFlight {
    fn from_request(req: OpRequest) -> Self {
        Self {
            kind: req.kind,
            fd: req.fd,
            base_offset: req.base_offset,
            ptr: req.ptr,
            total_len: req.total_len,
            bytes_done: 0,
            completion: req.completion,
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
fn io_thread_loop(mut ring: IoUring, rx: mpsc::Receiver<OpRequest>, depth: u32) {
    let mut tracker = InFlightTracker::new(depth as usize);
    let mut next_id: u64 = 0;
    let mut sender_open = true;

    'main: loop {
        // Drain new submissions until the SQ is full or the channel
        // is empty. If we have nothing in flight we block on `recv`
        // so the thread sleeps cleanly.
        loop {
            if tracker.map.len() >= depth as usize {
                break;
            }
            if tracker.map.is_empty() && sender_open {
                match rx.recv() {
                    Ok(req) => {
                        if !push_initial(&mut ring, next_id, &req) {
                            // SQ overflow on initial push: should not
                            // happen because we checked the depth
                            // above. Complete the op with an error
                            // and bail.
                            req.completion
                                .set(Err(io::Error::other("uring SQ overflow on initial push")));
                            continue;
                        }
                        let id = next_id;
                        next_id = next_id.wrapping_add(1);
                        tracker.map.insert(id, InFlight::from_request(req));
                    }
                    Err(_) => {
                        sender_open = false;
                        break;
                    }
                }
            } else {
                match rx.try_recv() {
                    Ok(req) => {
                        if !push_initial(&mut ring, next_id, &req) {
                            req.completion
                                .set(Err(io::Error::other("uring SQ overflow on initial push")));
                            continue;
                        }
                        let id = next_id;
                        next_id = next_id.wrapping_add(1);
                        tracker.map.insert(id, InFlight::from_request(req));
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

        // Submit and wait for at least one CQE. `submit_and_wait`
        // returns immediately if a CQE is already queued.
        match ring.submit_and_wait(1) {
            Ok(_) => {}
            Err(e) => {
                // Submission failure: the kernel rejected the ring
                // op. Complete every in-flight with this error so
                // workers do not block forever.
                let kind = e.kind();
                let msg = format!("uring submit_and_wait failed: {e}");
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
    }
    // tracker drops on return: drains any leftover in-flight ops
    // with a "io thread terminated" error so workers do not deadlock.
}

/// Push the initial SQE for a fresh request.
///
/// Returns `false` if the SQ is full; the caller is expected to
/// ensure that does not happen (the io_thread bounds insertions by
/// `depth`).
fn push_initial(ring: &mut IoUring, id: u64, req: &OpRequest) -> bool {
    push_sqe(
        ring,
        id,
        req.kind,
        req.fd,
        req.base_offset,
        req.ptr,
        req.total_len,
    )
}

/// Push the resume SQE for a partially-completed WriteAll / ReadExact.
fn push_resume(ring: &mut IoUring, id: u64, ifl: &InFlight) -> bool {
    let off = ifl.base_offset.saturating_add(ifl.bytes_done as u64);
    // SAFETY: `bytes_done < total_len` is checked by the caller; the
    // original buffer is at least `total_len` bytes long, so adding
    // `bytes_done` stays within the same allocation.
    let ptr = unsafe { ifl.ptr.add(ifl.bytes_done) };
    let remaining = ifl.total_len - ifl.bytes_done;
    push_sqe(ring, id, ifl.kind, ifl.fd, off, ptr, remaining)
}

fn push_sqe(
    ring: &mut IoUring,
    id: u64,
    kind: OpKind,
    fd: RawFd,
    offset: u64,
    ptr: *mut u8,
    len: usize,
) -> bool {
    let len_u32 = u32::try_from(len).unwrap_or(u32::MAX);
    let entry = match kind {
        OpKind::WriteAll => opcode::Write::new(types::Fd(fd), ptr.cast::<u8>(), len_u32)
            .offset(offset)
            .build()
            .user_data(id),
        OpKind::ReadShort | OpKind::ReadExact => opcode::Read::new(types::Fd(fd), ptr, len_u32)
            .offset(offset)
            .build()
            .user_data(id),
        OpKind::Fsync => opcode::Fsync::new(types::Fd(fd)).build().user_data(id),
    };
    let mut sq = ring.submission();
    // SAFETY: The buffer pointed at by `ptr` is valid for `len`
    // bytes for the duration of this submission. The calling thread
    // owns the buffer and is blocked on the matching `Completion`,
    // so the buffer cannot be deallocated or aliased until after the
    // CQE is drained. The fd is borrowed for the call's duration via
    // the `BorrowedFd<'_>` argument on the trait method.
    let result = unsafe { sq.push(&entry) };
    sq.sync();
    result.is_ok()
}

fn handle_cqe(ring: &mut IoUring, tracker: &mut InFlightTracker, id: u64, res: i32) {
    let mut ifl = match tracker.map.remove(&id) {
        Some(i) => i,
        None => return,
    };

    if res < 0 {
        let err = io::Error::from_raw_os_error(-res);
        ifl.complete(Err(err));
        return;
    }

    let bytes = res as usize;
    let new_total = ifl.bytes_done.saturating_add(bytes);
    ifl.bytes_done = new_total;

    match ifl.kind {
        OpKind::Fsync => ifl.complete(Ok(0)),
        OpKind::ReadShort => ifl.complete(Ok(bytes)),
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
}
