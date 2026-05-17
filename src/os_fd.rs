//! Portable borrowed-handle alias used by the [`crate::punch::PunchHole`]
//! and [`crate::io_backend::IoBackend`] trait surfaces.
//!
//! `peel` needs to hand a single borrowed reference to an open file
//! across two trait boundaries: the puncher (`fallocate(PUNCH_HOLE)`
//! on Linux, `fcntl(F_PUNCHHOLE)` on macOS,
//! `DeviceIoControl(FSCTL_SET_ZERO_DATA)` on Windows) and the IO
//! backend (`pwrite`/`pread` / `FlushFileBuffers`). On Unix that
//! reference is [`std::os::fd::BorrowedFd`]; on Windows it is
//! [`std::os::windows::io::BorrowedHandle`]. The two types are
//! shaped the same — `Copy + Send + Sync`, no destructor, lifetime
//! ties them to an open OS handle — but they live behind different
//! `cfg`s in `std` because the underlying OS objects are distinct.
//!
//! [`OsFd`] is a single name for either. Trait signatures that
//! today take `BorrowedFd<'_>` switch to `OsFd<'_>`; on Unix the
//! alias resolves to `BorrowedFd<'_>` so every existing `as_fd()`
//! call site keeps compiling unchanged, and on Windows the same
//! alias resolves to `BorrowedHandle<'_>` so future Windows impls
//! (per `PLAN_v3_windows.md` §§1–4) can plug in without a second
//! trait flavor.
//!
//! [`AsOsFd`] is the corresponding "anything that can hand out an
//! [`OsFd`]" trait. It is a single-method portable mirror of
//! [`std::os::fd::AsFd`] / [`std::os::windows::io::AsHandle`]; the
//! blanket impl below means every standard `File`, `Arc<File>`, and
//! socket implements it for free. Call sites that today write
//! `file.as_fd()` can switch to `file.as_os_fd()` to opt into the
//! portable name; existing Unix-only sites that intentionally name
//! `BorrowedFd` keep working because `OsFd<'_> = BorrowedFd<'_>` on
//! Unix.

#![cfg(any(unix, windows))]

/// Borrowed reference to an OS file handle, portable across Unix and
/// Windows.
///
/// `Copy + Send + Sync` on every supported platform. The lifetime
/// `'a` is the borrow of the underlying owned handle (an open
/// `File`, `TcpStream`, etc.); the borrow does not own the handle
/// and dropping it does not close anything.
#[cfg(unix)]
pub type OsFd<'a> = std::os::fd::BorrowedFd<'a>;

/// Borrowed reference to an OS file handle, portable across Unix and
/// Windows.
///
/// `Copy + Send + Sync` on every supported platform. The lifetime
/// `'a` is the borrow of the underlying owned handle (an open
/// `File`, `TcpStream`, etc.); the borrow does not own the handle
/// and dropping it does not close anything.
#[cfg(windows)]
pub type OsFd<'a> = std::os::windows::io::BorrowedHandle<'a>;

/// Anything that can hand out an [`OsFd`] borrowed reference.
///
/// Single-method portable mirror of [`std::os::fd::AsFd`] /
/// [`std::os::windows::io::AsHandle`]. The blanket impl in this
/// module means every standard `File`, `Arc<File>`, etc. implements
/// `AsOsFd` for free.
pub trait AsOsFd {
    /// Return a borrowed [`OsFd`] reference whose lifetime is tied
    /// to `self`.
    fn as_os_fd(&self) -> OsFd<'_>;
}

#[cfg(unix)]
impl<T: std::os::fd::AsFd + ?Sized> AsOsFd for T {
    fn as_os_fd(&self) -> OsFd<'_> {
        self.as_fd()
    }
}

#[cfg(windows)]
impl<T: std::os::windows::io::AsHandle + ?Sized> AsOsFd for T {
    fn as_os_fd(&self) -> OsFd<'_> {
        self.as_handle()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_fd_round_trip_through_file() {
        // SAFETY-equivalent: on every platform, a freshly opened
        // stdout handle is valid for the duration of the test.
        // `as_os_fd` borrows it for that duration; the test does
        // not store the borrow past the parent's lifetime.
        let out = std::io::stdout();
        let fd = out.as_os_fd();
        // The Debug impls of both `BorrowedFd` and `BorrowedHandle`
        // print the underlying numeric handle, so this round-trip
        // is sufficient as a smoke test that the alias resolves and
        // the blanket impl applies.
        let s = format!("{fd:?}");
        assert!(!s.is_empty());
    }

    #[test]
    fn os_fd_is_copy_send_sync() {
        // Compile-time check: if these `fn` declarations type-check,
        // the alias has the marker traits the trait-bounds in
        // `IoBackend` / `PunchHole` rely on.
        fn assert_copy<T: Copy>() {}
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_copy::<OsFd<'static>>();
        assert_send::<OsFd<'static>>();
        assert_sync::<OsFd<'static>>();
    }
}
