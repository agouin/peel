"""Cross-platform hole punching.

Linux: fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)
macOS: fcntl(F_PUNCHHOLE)
Windows: FSCTL_SET_ZERO_DATA on a sparse file
Fallback: no-op (extraction still works, just doesn't save space)

The punch interface is deliberately tiny: punch(fd, offset, length).
Callers handle alignment.
"""
from __future__ import annotations

import os
import sys
import ctypes
import ctypes.util
from typing import Protocol


class Puncher(Protocol):
    """Releases disk blocks for a byte range of an open file."""

    def punch(self, fd: int, offset: int, length: int) -> None: ...

    @property
    def block_size_hint(self) -> int:
        """Filesystem-block alignment expected by this puncher (bytes)."""
        ...


class _NoopPuncher:
    """Used when no native hole-punching is available. Extraction still works,
    it just won't reclaim space until the source file is deleted."""

    block_size_hint = 4096

    def punch(self, fd: int, offset: int, length: int) -> None:
        return


class _LinuxPuncher:
    """fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE).

    Works on ext4, xfs, btrfs, tmpfs, f2fs. Range must be aligned to the
    filesystem block size (usually 4096). The file's logical size is
    preserved; only the underlying blocks are released.
    """

    FALLOC_FL_KEEP_SIZE = 0x01
    FALLOC_FL_PUNCH_HOLE = 0x02

    def __init__(self) -> None:
        # fallocate is exposed via os.posix_fallocate but only with mode=0.
        # We need the mode flags, so go straight to libc.
        libc_name = ctypes.util.find_library("c") or "libc.so.6"
        self._libc = ctypes.CDLL(libc_name, use_errno=True)
        self._fallocate = self._libc.fallocate
        self._fallocate.argtypes = [
            ctypes.c_int,      # fd
            ctypes.c_int,      # mode
            ctypes.c_longlong, # offset (off_t)
            ctypes.c_longlong, # len    (off_t)
        ]
        self._fallocate.restype = ctypes.c_int

    block_size_hint = 4096

    def punch(self, fd: int, offset: int, length: int) -> None:
        if length <= 0:
            return
        mode = self.FALLOC_FL_PUNCH_HOLE | self.FALLOC_FL_KEEP_SIZE
        rc = self._fallocate(fd, mode, offset, length)
        if rc != 0:
            err = ctypes.get_errno()
            # ENOTSUP/EOPNOTSUPP: filesystem doesn't support punching
            # (NFS, some FUSE mounts, FAT, certain overlay/tmpfs setups).
            # Treat as a soft failure — extraction can still proceed.
            import errno
            if err in (errno.EOPNOTSUPP, errno.ENOTSUP, errno.EINVAL):
                raise _PunchUnsupported()
            raise OSError(err, os.strerror(err),
                          f"fallocate(PUNCH_HOLE, off={offset}, len={length})")


class _PunchUnsupported(Exception):
    """Raised when the underlying FS rejects the punch op. Caller should
    swap to a noop puncher and continue."""


class _MacPuncher:
    """fcntl(F_PUNCHHOLE) on APFS. Requires struct fpunchhole."""

    F_PUNCHHOLE = 99

    class _FPunchhole(ctypes.Structure):
        _fields_ = [
            ("fp_flags", ctypes.c_uint),
            ("reserved", ctypes.c_uint),
            ("fp_offset", ctypes.c_longlong),
            ("fp_length", ctypes.c_longlong),
        ]

    block_size_hint = 4096

    def __init__(self) -> None:
        libc_name = ctypes.util.find_library("c") or "libSystem.dylib"
        self._libc = ctypes.CDLL(libc_name, use_errno=True)
        self._fcntl = self._libc.fcntl

    def punch(self, fd: int, offset: int, length: int) -> None:
        if length <= 0:
            return
        arg = self._FPunchhole(0, 0, offset, length)
        rc = self._fcntl(fd, self.F_PUNCHHOLE, ctypes.byref(arg))
        if rc != 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err),
                          f"F_PUNCHHOLE(off={offset}, len={length})")


def get_puncher() -> Puncher:
    """Return the best puncher available on this platform."""
    if sys.platform.startswith("linux"):
        try:
            return _LinuxPuncher()
        except (OSError, AttributeError):
            pass
    elif sys.platform == "darwin":
        try:
            return _MacPuncher()
        except (OSError, AttributeError):
            pass
    # Windows FSCTL_SET_ZERO_DATA omitted for brevity; would go here.
    return _NoopPuncher()


def get_fs_block_size(path: str) -> int:
    """Get the filesystem block size for the volume containing path.
    Falls back to 4096 if unavailable. Used for alignment."""
    try:
        st = os.statvfs(path)
        return st.f_bsize or 4096
    except (OSError, AttributeError):
        return 4096


def align_down(value: int, alignment: int) -> int:
    return (value // alignment) * alignment
