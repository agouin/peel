"""Zstd streaming decoder.

Wraps zstandard.ZstdDecompressor's stream_reader. The crucial property:
zstd is a forward-only stream codec, so once the decoder has pulled a byte
out of the source, it never looks back at it.

We track bytes_consumed by counting bytes we've actually handed to the
decompressor's input feeder. zstandard buffers internally, but it copies
input into its own buffer before returning, so anything we've passed in
is fair game to punch.
"""
from __future__ import annotations

from typing import BinaryIO, Callable

import zstandard as zstd

from . import register_decoder


# Tunables. Larger chunks = fewer syscalls but coarser punching granularity.
_INPUT_CHUNK = 1 << 20   # 1 MiB read per step
_OUTPUT_CHUNK = 1 << 20  # 1 MiB output buffer


class ZstdDecoder:
    def __init__(self) -> None:
        # max_window_size guards against malicious archives demanding huge RAM.
        # 256 MiB is generous for typical archives; tune for your threat model.
        self._dctx = zstd.ZstdDecompressor(max_window_size=256 << 20)
        self._reader = None      # ZstdDecompressionReader, lazy
        self._consumed = 0       # bytes pulled from src

    def _ensure_reader(self, src: BinaryIO):
        if self._reader is None:
            # Wrap src in a counting adapter so we know exactly how many bytes
            # the decompressor has pulled.
            self._counting = _CountingReader(src)
            self._reader = self._dctx.stream_reader(
                self._counting,
                read_size=_INPUT_CHUNK,
                closefd=False,
            )
        return self._reader

    def decode_step(self, src: BinaryIO, sink: Callable[[bytes], None]) -> bool:
        reader = self._ensure_reader(src)
        chunk = reader.read(_OUTPUT_CHUNK)
        if not chunk:
            self._consumed = self._counting.position
            return False
        sink(chunk)
        self._consumed = self._counting.position
        return True

    def bytes_consumed(self) -> int:
        return self._consumed

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()
            self._reader = None


class _CountingReader:
    """File-like wrapper that tracks bytes read. Used so we can ask the
    decompressor 'how far into the source have you read?' without trusting
    its internal accounting (which varies between codec libraries)."""

    def __init__(self, inner: BinaryIO):
        self._inner = inner
        self.position = 0

    def read(self, n: int = -1) -> bytes:
        data = self._inner.read(n)
        self.position += len(data)
        return data

    def readable(self) -> bool:
        return True


register_decoder(".zst", ZstdDecoder)
register_decoder(".zstd", ZstdDecoder)
