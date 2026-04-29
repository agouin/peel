"""Streaming decoder protocol.

A decoder consumes bytes from an input file and writes decoded bytes to an
output sink. The contract that makes destructive extraction possible:

    `bytes_consumed()` reports an offset in the *source* file such that
    no future call to `decode_step()` will read bytes before that offset.

That number is the high-water mark we can safely punch up to. All the
format-specific knowledge lives behind this interface; the core extractor
stays format-agnostic.
"""
from __future__ import annotations

from typing import Protocol, BinaryIO, Callable, Optional
import os


class StreamingDecoder(Protocol):
    """Forward-only decoder over a file-like input."""

    def decode_step(self, src: BinaryIO, sink: Callable[[bytes], None]) -> bool:
        """Pull some input from src, push decoded bytes to sink.

        Returns True if more data may be available, False if the stream
        is fully consumed. May make zero, one, or many sink() calls per
        step. Should bound work per call (~1 MiB of input is reasonable)
        so the extractor can punch holes at regular intervals.
        """
        ...

    def bytes_consumed(self) -> int:
        """High-water mark in src (bytes) that the decoder will never reread.

        This MUST be conservative. If unsure whether a byte will be reread,
        report a smaller number. Punching past this offset corrupts state.
        """
        ...

    def close(self) -> None:
        """Release any decoder-held resources."""
        ...


# --- registry ---------------------------------------------------------------

DecoderFactory = Callable[[], StreamingDecoder]
_REGISTRY: dict[str, DecoderFactory] = {}


def register_decoder(suffix: str, factory: DecoderFactory) -> None:
    """Register a decoder factory for a file suffix (e.g. '.zst', '.tar.zst').

    Longer suffixes win during lookup, so '.tar.zst' takes precedence
    over '.zst'.
    """
    _REGISTRY[suffix.lower()] = factory


def get_decoder_for_path(path: str) -> Optional[StreamingDecoder]:
    """Find a registered decoder for the given path by suffix.

    Returns a fresh decoder instance, or None if no decoder matches.
    """
    name = os.path.basename(path).lower()
    matches = [s for s in _REGISTRY if name.endswith(s)]
    if not matches:
        return None
    best = max(matches, key=len)
    return _REGISTRY[best]()
