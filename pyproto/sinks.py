"""Sinks consume decoded bytes and write them somewhere useful.

Two sinks ship by default:
  - RawFileSink: dumps the decoded byte stream to a single output file.
    Use for foo.zst -> foo.
  - TarStreamingSink: feeds the decoded byte stream into a tar extractor
    on the fly, never materializing the .tar on disk. Use for foo.tar.zst.

Both implement the same Sink protocol. Add new ones (cpio, ar, custom
container formats) by following the same shape.
"""
from __future__ import annotations

import io
import os
import tarfile
import threading
from typing import Protocol, Optional


class Sink(Protocol):
    def write(self, data: bytes) -> None: ...
    def close(self) -> None: ...


class RawFileSink:
    """Writes the decoded stream to a single output file."""

    def __init__(self, output_path: str):
        self._fp = open(output_path, "wb")

    def write(self, data: bytes) -> None:
        self._fp.write(data)

    def close(self) -> None:
        self._fp.close()


class TarStreamingSink:
    """Pipes decoded bytes into tarfile.open(mode='r|') on a background thread.

    'r|' mode is tar's streaming reader — it never seeks, so it composes
    cleanly with our forward-only decode. We use an os.pipe() to bridge
    the decoder thread (writes) and the tar thread (reads).
    """

    def __init__(self, output_dir: str):
        self._output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        r_fd, w_fd = os.pipe()
        # Generous buffer reduces context-switch thrash. On Linux you can also
        # fcntl(F_SETPIPE_SZ) to grow this beyond the default 64 KiB.
        self._writer = os.fdopen(w_fd, "wb", buffering=1 << 16)
        self._reader_fd = r_fd

        self._error: Optional[BaseException] = None
        self._thread = threading.Thread(
            target=self._extract_loop, name="tar-extract", daemon=True
        )
        self._thread.start()

    def _extract_loop(self) -> None:
        try:
            with os.fdopen(self._reader_fd, "rb") as r:
                with tarfile.open(fileobj=r, mode="r|") as tf:
                    for member in tf:
                        # Defensive extraction: refuse paths escaping the
                        # output dir. Python 3.12+ has filter='data' built in.
                        if _is_unsafe_path(member.name, self._output_dir):
                            continue
                        tf.extract(member, self._output_dir,
                                   set_attrs=False)
        except BaseException as e:
            self._error = e

    def write(self, data: bytes) -> None:
        if self._error:
            raise self._error
        self._writer.write(data)

    def close(self) -> None:
        try:
            self._writer.close()  # signals EOF to the tar reader
        except BrokenPipeError:
            pass
        self._thread.join()
        if self._error:
            raise self._error


def _is_unsafe_path(name: str, base: str) -> bool:
    target = os.path.realpath(os.path.join(base, name))
    base_real = os.path.realpath(base)
    return not (target == base_real or target.startswith(base_real + os.sep))
