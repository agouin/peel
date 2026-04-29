"""Core extraction loop. Format-agnostic.

The dance:
    1. Open source RDWR.
    2. Loop:
         a. decoder.decode_step(src, sink)        -> may write output
         b. consumed = decoder.bytes_consumed()
         c. If consumed - last_punched > threshold, punch the gap.
    3. On clean EOF, optionally truncate or unlink the source.

Safety properties:
    - We always punch *behind* the decoder by at least one FS block
      (safety_margin), never up to or past the live read cursor.
    - Punch offsets and lengths are aligned down to the FS block size;
      sub-block tails are left in place until the next punch advances past them.
    - If the decoder raises, we stop punching. The source is left in a
      partially-holed state but its logical contents (in the unholed regions)
      are unchanged, so a future tool could in principle resume — though
      none of these formats actually support that without a manifest.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from .decoders import StreamingDecoder
from .sinks import Sink
from .punch import (
    Puncher,
    get_puncher,
    get_fs_block_size,
    align_down,
    _PunchUnsupported,
    _NoopPuncher,
)


class ExtractionError(Exception):
    pass


@dataclass
class ExtractStats:
    bytes_in: int = 0
    bytes_out: int = 0
    bytes_punched: int = 0
    punch_calls: int = 0


class PunchingExtractor:
    def __init__(
        self,
        *,
        puncher: Optional[Puncher] = None,
        # Don't punch within this many bytes of the read cursor.
        safety_margin: int = 64 * 1024,
        # Minimum gap between successive punches. Keeps syscall count down.
        punch_threshold: int = 4 * 1024 * 1024,
        # If True, unlink the source file once extraction succeeds.
        unlink_on_success: bool = False,
    ):
        self._puncher = puncher or get_puncher()
        self._safety_margin = safety_margin
        self._punch_threshold = punch_threshold
        self._unlink_on_success = unlink_on_success

    def extract(
        self,
        source_path: str,
        decoder: StreamingDecoder,
        sink: Sink,
    ) -> ExtractStats:
        stats = ExtractStats()
        fs_block = get_fs_block_size(source_path)
        block = max(fs_block, self._puncher.block_size_hint)

        fd = os.open(source_path, os.O_RDWR)
        try:
            src = os.fdopen(fd, "rb", buffering=0, closefd=False)
            last_punched = 0

            while True:
                try:
                    more = decoder.decode_step(src, _CountingSink(sink, stats))
                except Exception as e:
                    raise ExtractionError(f"decode failed: {e}") from e

                consumed = decoder.bytes_consumed()
                stats.bytes_in = consumed

                # Safe-to-punch: behind decoder by safety_margin, FS-aligned.
                punch_to = align_down(
                    max(0, consumed - self._safety_margin), block
                )
                gap = punch_to - last_punched
                if gap >= self._punch_threshold:
                    try:
                        self._puncher.punch(fd, last_punched, gap)
                        if not isinstance(self._puncher, _NoopPuncher):
                            stats.bytes_punched += gap
                            stats.punch_calls += 1
                    except _PunchUnsupported:
                        self._puncher = _NoopPuncher()
                    last_punched = punch_to

                if not more:
                    break

            # Final punch sweep: release everything up to the consumed mark.
            consumed = decoder.bytes_consumed()
            final_to = align_down(consumed, block)
            tail = final_to - last_punched
            if tail > 0:
                try:
                    self._puncher.punch(fd, last_punched, tail)
                    if not isinstance(self._puncher, _NoopPuncher):
                        stats.bytes_punched += tail
                        stats.punch_calls += 1
                except _PunchUnsupported:
                    pass

        finally:
            try:
                decoder.close()
            except Exception:
                pass
            try:
                sink.close()
            except Exception:
                pass
            os.close(fd)

        if self._unlink_on_success:
            os.unlink(source_path)

        return stats


class _CountingSink:
    """Wraps a Sink to tally output bytes for stats. Cheap pass-through."""

    __slots__ = ("_sink", "_stats")

    def __init__(self, sink: Sink, stats: ExtractStats):
        self._sink = sink
        self._stats = stats

    def __call__(self, data: bytes) -> None:
        self._sink.write(data)
        self._stats.bytes_out += len(data)
