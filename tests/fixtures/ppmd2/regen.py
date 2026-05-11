#!/usr/bin/env python3
"""Regenerate the PPMd-II differential corpus from 7z PPMd output.

This script is the *only* path that writes the case_*.bin fixtures
under this directory. Don't hand-edit those files — re-run this
script when you want to refresh the corpus.

Inputs:  the curated (payload, order, mem_mb) cases below.
Outputs: tests/fixtures/ppmd2/case_NNN_<slug>.bin — a tight binary
         envelope holding the plaintext, the 7z-PPMd byte stream
         extracted verbatim from the .7z archive, and the order /
         mem-size parameters Model::new needs.

7z's PPMd uses Igor Pavlov's PPMd7 (the LZMA SDK variant), which is
the same range-coder variant our hand-rolled Model::decode_symbol
targets today. That's why we use 7z here instead of `rar a -m5`:
modern rar 7.x dropped legacy-archive creation entirely (no -ma3
flag), and the RAR-variant range coder is deferred to Phase C
(PLAN_rar3.md). When Phase C lands and we have RAR3 block parsing,
a sibling corpus of rar-produced fixtures becomes possible.

Fixture wire format (little-endian throughout):
    [0..4]    b"PPM2"           magic
    [4]       u8   order
    [5]       u8   reserved (0)
    [6..10]   u32  mem_bytes      (extracted from 7z's PPMd properties)
    [10..14]  u32  plaintext_len
    [14..18]  u32  ppmd_len
    [18..18+plaintext_len]   plaintext
    [18+plaintext_len..18+plaintext_len+ppmd_len]  ppmd byte stream

Note on `mem_bytes`: the value 7z stores in the archive header is
the *bytes* parameter the encoder used, not what we requested on the
command line — p7zip 17.05's PPMd parser silently overrides the
`mem` switch and emits a fixed default (typically 64 KB), so we
extract the canonical value from the 7z archive's PPMd method
properties and pass *that* to the decoder. Mismatched arenas trigger
divergent model restarts on long streams.
"""

import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEVENZ = shutil.which("7z") or shutil.which("7za")
if SEVENZ is None:
    sys.exit("7z (or 7za) not found on PATH; install p7zip and retry")

# 7z's SignatureHeader is a fixed 32-byte prefix; nextHeaderOffset
# at bytes [12..20] is the size of the packed-data region that
# immediately follows. For a single-file PPMd-only archive that
# packed region is the PPMd byte stream verbatim.
SEVENZ_HEADER_LEN = 32
NEXT_HEADER_OFFSET_FIELD = (12, 20)


def extract_ppmd_stream(archive_bytes: bytes) -> bytes:
    sig = archive_bytes[:6]
    if sig != b"7z\xbc\xaf\x27\x1c":
        raise ValueError(f"not a 7z archive (sig={sig!r})")
    lo, hi = NEXT_HEADER_OFFSET_FIELD
    next_header_offset = struct.unpack("<Q", archive_bytes[lo:hi])[0]
    end = SEVENZ_HEADER_LEN + next_header_offset
    stream = archive_bytes[SEVENZ_HEADER_LEN:end]
    if not stream or stream[0] != 0x00:
        raise ValueError(
            f"packed PPMd stream does not start with 0x00 leader "
            f"(first byte = 0x{stream[0]:02x}); 7z may have used "
            f"unexpected framing"
        )
    return stream


# PPMd method ID per the 7z reference (Igor Pavlov's "7zFormat.txt"):
# the three-byte sequence below identifies the PPMd coder; immediately
# after the method ID the header carries a one-byte property length
# (= 5) and 5 property bytes: order (u8) + mem_size_bytes (u32 LE).
PPMD_METHOD_ID = bytes.fromhex("030401")


def extract_ppmd_props(archive_bytes: bytes) -> tuple[int, int]:
    """Return `(order, mem_bytes)` from the 7z archive's PPMd
    method properties."""
    sig_off = archive_bytes.find(PPMD_METHOD_ID, SEVENZ_HEADER_LEN)
    if sig_off < 0:
        raise ValueError("PPMd method id (03 04 01) not found in 7z header")
    props_len = archive_bytes[sig_off + 3]
    if props_len != 5:
        raise ValueError(
            f"unexpected PPMd property length {props_len} (want 5)"
        )
    order = archive_bytes[sig_off + 4]
    mem_bytes = struct.unpack("<I", archive_bytes[sig_off + 5 : sig_off + 9])[0]
    return order, mem_bytes


def compress(payload: bytes, order: int, mem_mb: int) -> tuple[bytes, int, int]:
    """Round-trip `payload` through 7z PPMd; return `(ppmd_stream,
    order_used, mem_bytes_used)`. The `order` and `mem_mb` arguments
    are what we *request* on the 7z command line; the values 7z
    actually used (as recorded in the .7z header) are returned so
    the fixture matches the encoder's view of the model."""
    with tempfile.TemporaryDirectory(prefix="ppmd2_regen_") as td:
        td = Path(td)
        plain = td / "p.bin"
        archive = td / "a.7z"
        plain.write_bytes(payload)
        cmd = [
            SEVENZ,
            "a",
            f"-m0=PPMd:o{order}:mem{mem_mb}m",
            "-mx=0",  # we don't care about non-PPMd-method tuning
            str(archive),
            str(plain),
        ]
        result = subprocess.run(cmd, capture_output=True, cwd=td)
        if result.returncode != 0:
            sys.exit(
                f"7z failed (rc={result.returncode}):\n"
                f"stdout: {result.stdout.decode(errors='replace')}\n"
                f"stderr: {result.stderr.decode(errors='replace')}"
            )
        archive_bytes = archive.read_bytes()
    order_used, mem_bytes_used = extract_ppmd_props(archive_bytes)
    stream = extract_ppmd_stream(archive_bytes)
    return stream, order_used, mem_bytes_used


def write_fixture(
    path: Path, payload: bytes, order: int, mem_bytes: int, ppmd: bytes
) -> None:
    if len(payload) > 0xFFFF_FFFF or len(ppmd) > 0xFFFF_FFFF:
        raise ValueError("fixture overflows u32 length field")
    if not (2 <= order <= 32):
        raise ValueError(f"order {order} out of 7z PPMd range [2, 32]")
    if mem_bytes < 2048 or mem_bytes > 0xFFFF_FFFF - 36:
        raise ValueError(f"mem_bytes {mem_bytes} out of PPMd7 range")
    body = b"".join([
        b"PPM2",
        struct.pack("<BB", order, 0),  # second byte reserved for alignment
        struct.pack("<III", mem_bytes, len(payload), len(ppmd)),
        payload,
        ppmd,
    ])
    path.write_bytes(body)


# ── Payloads ─────────────────────────────────────────────────────

LOREM = (
    b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. "
    b"Vestibulum tincidunt sapien id velit pulvinar, eu lacinia "
    b"justo dapibus. Cras sed velit non urna porta tempor. Sed "
    b"non posuere ipsum. Donec eu metus ut ipsum porta euismod. "
    b"Pellentesque habitant morbi tristique senectus et netus et "
    b"malesuada fames ac turpis egestas. Mauris ut nibh nec leo "
    b"dictum tristique. Quisque non sapien nec libero porta porta. "
)


def english_4kb() -> bytes:
    # Repeating a small paragraph saturates around order ~4. Good
    # stress for the model's frequency tracking.
    out = bytearray()
    while len(out) < 4096:
        out.extend(LOREM)
    return bytes(out[:4096])


def lcg_bytes(n: int, seed: int = 0xC0FFEE) -> bytes:
    # Stable LCG so fixtures regenerate identically across machines.
    out = bytearray(n)
    state = seed & 0xFFFFFFFF
    for i in range(n):
        state = (state * 1103515245 + 12345) & 0xFFFFFFFF
        out[i] = (state >> 16) & 0xFF
    return bytes(out)


def period_cyclic(period: int, n: int) -> bytes:
    return bytes((i % period) for i in range(n))


PAYLOADS: list[tuple[str, bytes]] = [
    ("hello_world", b"Hello, World!\nHello, World!\nHello, World!\n"),
    ("alphabet_256", bytes(range(256))),
    ("lorem_1kb", (LOREM * ((1024 // len(LOREM)) + 1))[:1024]),
    ("english_4kb", english_4kb()),
    ("zeros_1kb", b"\x00" * 1024),
    ("zeros_16kb", b"\x00" * 16384),
    ("lcg_1kb", lcg_bytes(1024)),
    ("lcg_16kb", lcg_bytes(16384)),
    ("period27_1kb", b"X" * 27 * 38),  # 1026 ≈ 1 KB of X repeated
    ("cyclic_256", period_cyclic(256, 1024)),
]

# (order, mem_mb) pairs. Span the full order range PPMd7 accepts
# (2..=32) and a few mem_mb values that exercise both compact and
# generous arenas.
CONFIGS: list[tuple[int, int]] = [
    (2, 1),
    (4, 4),
    (8, 16),
    (16, 32),
    (32, 64),
]


def main() -> int:
    # Wipe any stale case_*.bin so renamed cases don't linger.
    for stale in HERE.glob("case_*.bin"):
        stale.unlink()

    case_no = 0
    for payload_name, payload in PAYLOADS:
        for req_order, req_mb in CONFIGS:
            case_no += 1
            slug = f"case_{case_no:03d}_o{req_order:02d}_m{req_mb:02d}_{payload_name}"
            out_path = HERE / f"{slug}.bin"
            ppmd, order_used, mem_bytes = compress(payload, req_order, req_mb)
            write_fixture(out_path, payload, order_used, mem_bytes, ppmd)
            print(
                f"{slug}: payload={len(payload)} B  ppmd={len(ppmd)} B  "
                f"req=o{req_order}/mem{req_mb}m  used=o{order_used}/0x{mem_bytes:08x}"
            )
    print(f"\nWrote {case_no} fixtures to {HERE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
