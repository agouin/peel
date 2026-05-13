# How it works

This page describes the internal architecture. The
[Quick start](./quick-start.md) is sufficient for basic use. This
material covers why disk usage stays bounded, how resume converges to
a byte-identical output, and what happens on the wire.

## The three components

A `peel` run for an HTTP source has three loosely-coupled stages, each
running concurrently:

```text
   +-------------+      +----------+      +----------+
   |  download   | ---> | part-file| ---> | decoder  | ---> output tree
   |  workers    |      | (sparse) |      | + sink   |
   +-------------+      +----------+      +----------+
        |                    ^                  |
        |                    |                  v
        |              +-----------+      +-----------+
        +----------->  | scheduler |      |  puncher  |
                       | + bitmap  |      | (releases |
                       +-----------+      |  blocks)  |
                                          +-----------+
```

1. **Download workers** fetch ranges of the source object in parallel via
   ranged GETs. Each worker writes its bytes into the sparse `.peel.part`
   file at the byte offset the scheduler assigned it.
2. **The decoder** walks the part-file from offset 0, consuming whatever
   the workers have already written, blocking briefly when it gets ahead
   of them.
3. **The puncher** trails the decoder. As the decoder advances past a
   chunk boundary, `fallocate(PUNCH_HOLE)` (Linux) or
   `madvise(MADV_REMOVE)` (Linux, mmap backend) or `F_PUNCHHOLE`
   (macOS) releases the blocks underneath that range back to the
   filesystem.

At any instant the part-file's *logical* size is the full archive,
but its *physical* size on disk is roughly the gap between the slowest
worker and the decoder. This is the **lookahead window**, capped by
`--max-disk-buffer` (default 1 GiB).

## The bitmap and the checkpoint

Two pieces of state make resume work:

**A chunk bitmap.** The source is divided into fixed-size chunks
(`--chunk-size`, default 4 MiB). A bit per chunk records "this chunk's
bytes have been fetched and written." The scheduler hands out the next
unset bit to whichever worker is free.

**A checkpoint sidecar.** `peel` writes `<output>.peel.ckpt` next to
the part-file at quiescent points: boundaries the decoder can resume
from byte-identically. These are frame-aligned (per zstd block, per
LZMA2 chunk, per deflate block, per 7z folder, per RAR entry, etc.),
so the next run reads the checkpoint, knows the decoder state, and
picks up at exactly the byte that was in flight.

A checkpoint write is atomic: `peel` writes to a `.tmp` file,
`fsync`s it, and renames it over the previous checkpoint. A crash
during the write loses at most the in-flight checkpoint, not the
previous one.

## Streaming `.zip`, `.7z`, and `.rar` over HTTP

ZIP and 7z put their index at the **end** of the archive: the ZIP
central directory after every entry, the 7z trailer at the bottom of
the SignatureHeader's pointer chain. `unrar` does not depend on a
tail-anchored index, but the `unrar` binary requires `lseek` on its
input regardless. None of `curl | unzip`, `curl | 7z x`, or
`curl | unrar x` will start producing output until the entire archive
has been buffered somewhere.

`peel` does not buffer the whole archive. It issues a small ranged
GET to fetch the tail (zip central directory or 7z trailer) up front,
parses it, then dispatches entry-sized GETs in parallel. Entries are
written to the sink as soon as their bytes arrive while the rest of
the archive is still in flight. The same hole-punching and resume
guarantees as the streaming `.tar.*` family apply.

For RAR, the format's per-file headers are already laid out at the
start of each file's data area, so `peel` walks them in stream order.
No tail probe is needed.

## Resume after `kill -9`

The output is byte-identical to a clean run if `peel` is re-invoked
with the same arguments after any failure. The mechanism:

1. Workers write to the part-file with `pwrite` (or `mmap` memcpy
   under the §9 backend). The kernel page-caches the write.
2. The bitmap is updated only after a chunk has been written and
   `fsync`'d back into the part-file (configurable via
   `--checkpoint-min-bytes` / `--checkpoint-min-secs`).
3. The checkpoint sidecar captures the decoder's frame-aligned state
   *plus* the bitmap *plus* the streaming SHA-256 state (if
   `--sha256` is set).
4. A `kill -9` between bitmap updates leaves the part-file with
   bytes that haven't been marked yet. Per-chunk **CRC32C
   fingerprints** in the bitmap detect those bytes on resume; they
   are re-fetched.
5. The decoder resumes from the checkpoint's frame boundary, not
   from the start. Per-format details: zstd resumes per block,
   xz per LZMA2 chunk, gzip per deflate block (with a 32 KiB
   sliding-window snapshot), tar per member, zip per entry plus
   intra-entry (per deflate block / per zstd block), 7z per
   folder, rar per entry plus intra-entry (via the §F1 checkpoint
   blob that snapshots the LZ dictionary and filter cache).

The crash-test harness runs 100 random kill points per format and
asserts the post-resume output bytes match a clean run, every time.

## Bounded disk usage

The compressed side of the pipeline runs as a **sliding window**:

```text
                    decoder pointer
                          v
   [hole-punched][......in-flight......][unfetched]
                          ^                  ^
                       worker N         worker N+M
```

The window's *width* is the gap between the slowest active worker
and the decoder. Two knobs bound it:

- **`--max-disk-buffer`** (default 1 GiB): when the gap reaches this
  many bytes, the scheduler stops dispatching new chunks until the
  decoder catches up. The default rarely engages on a healthy disk
  and bounds disaster on a slow one.
- **`--punch-threshold`** (default 4 MiB): minimum gap between
  in-loop hole-punch syscalls. Smaller values yield a tighter
  physical-disk footprint; larger values yield fewer syscalls per
  second. Tune downward to enforce a hard ceiling on physical disk;
  upward if the filesystem's punch-hole implementation is slow.

For `--no-extract` runs the puncher is bypassed and the part-file
grows to the full archive size. Otherwise the part-file's physical
size tracks the in-flight window, typically a few hundred MiB on a
healthy network.

## What runs where on Linux

`--io-backend auto` (default) runs probes at startup and picks the
fastest path the kernel allows:

- **mmap sparse-file** for the part-file: workers `memcpy` into a
  `MAP_SHARED` region; the puncher uses `madvise(MADV_REMOVE)`. This
  removes a syscall per chunk write at high parallelism.
- **`io_uring`** for the HTTP client's sockets: TCP `connect`, `send`,
  and `recv` are submitted to a single ring on a dedicated IO thread,
  with linked `LinkTimeout` SQEs for prompt cancellation. `rustls`
  rides on top unchanged.

If a probe fails (kernel < 5.6, `RLIMIT_MEMLOCK` too low, seccomp
blocking, filesystem rejecting `MADV_REMOVE`), `peel` logs one
`warn!` and falls back to the blocking `pwrite` / `pread` backend.
Force a specific path with `--io-backend [auto|blocking|uring|mmap]`.
See [Performance and tuning](./performance.md).

## Further reading

- [Checkpoint and resume](./checkpoint-resume.md): contents of the
  `.peel.ckpt` sidecar, write cadence, and inspection.
- [Performance and tuning](./performance.md): every knob with a
  measured tradeoff.
- [Supported formats](./formats.md): the per-format detection,
  resume, and encryption matrix.
