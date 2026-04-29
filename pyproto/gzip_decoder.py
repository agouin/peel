"""Gzip streaming decoder. Mirrors the zstd one — the only differences are
the codec object and the read-size defaults."""
from __future__ import annotations

import gzip
from typing import BinaryIO, Callable

from . import register_decoder


_OUTPUT_CHUNK = 1 << 20


class GzipDecoder:
    def __init__(self) -> None:
        self._gz = None
        self._counting = None

    def _ensure(self, src: BinaryIO):
        if self._gz is None:
            self._counting = _CountingReader(src)
            self._gz = gzip.GzipFile(fileobj=self._counting, mode="rb")
        return self._gz

    def decode_step(self, src: BinaryIO, sink: Callable[[bytes], None]) -> bool:
        gz = self._ensure(src)
        chunk = gz.read(_OUTPUT_CHUNK)
        if not chunk:
            return False
        sink(chunk)
        return True

    def bytes_consumed(self) -> int:
        return self._counting.position if self._counting else 0

    def close(self) -> None:
        if self._gz is not None:
            self._gz.close()
            self._gz = None


class _CountingReader:
    def __init__(self, inner: BinaryIO):
        self._inner = inner
        self.position = 0

    def read(self, n: int = -1) -> bytes:
        data = self._inner.read(n)
        self.position += len(data)
        return data

    def readable(self) -> bool:
        return True


register_decoder(".gz", GzipDecoder)
register_decoder(".gzip", GzipDecoder)
