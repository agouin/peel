# Checkpoint and resume

`peel` survives any failure short of disk corruption (dropped TCP,
`kill -9`, OOM kill, pod restart, power loss) and resumes
byte-identical to a clean run. This page describes the on-disk
layout, the write cadence, and how to interpret the sidecar files.

## The two sidecar files

When `peel` extracts `<output>` from an HTTP source, two sidecar
files appear next to the output during the run:

| File | What it holds |
| --- | --- |
| `<output>.peel.part` | The sparse compressed bytes (the part-file). Hole-punched as the decoder advances; physical size is the lookahead window. |
| `<output>.peel.ckpt` | Frame-aligned decoder state, chunk bitmap, and optional SHA-256 state, written atomically. |

On clean completion, both files are unlinked.

On failure or interruption, both files are left on disk. Re-running
the same command picks them up and resumes from the checkpoint.

The `--workdir <DIR>` flag relocates both files. Their basenames stay
the same (`<output_name>.peel.part` / `<output_name>.peel.ckpt`);
only the parent directory changes.

## When checkpoints are written

A checkpoint write is triggered when all of these are true:

1. `--checkpoint-min-bytes` bytes of source progress have accumulated
   since the last checkpoint (default 8 MiB).
2. `--checkpoint-min-secs` seconds have elapsed since the last
   checkpoint (default 2 s).
3. The decoder is at a frame-aligned boundary (per zstd block, per
   LZMA2 chunk, per deflate block, per tar member, per 7z folder,
   per RAR entry, per ZIP entry / intra-entry boundary).

The byte floor is scaled up at high download rates so the cadence
stays below `--checkpoint-target-secs` (default 0.2 s) wall-clock.
Pass `--checkpoint-target-secs 0` to disable rate-aware scaling.

The combination keeps checkpoint cadence steady (~5 / sec) on a fast
network without burning CPU on filesystems where `fsync` is slow,
and falls back to the byte floor on a slow network.

## How a write is atomic

A checkpoint write is never a partial overwrite:

1. Serialise the checkpoint blob to `<output>.peel.ckpt.tmp`.
2. `fsync` it.
3. `rename` it over `<output>.peel.ckpt`.
4. `fsync` the parent directory.

A crash during the write loses at most the in-flight checkpoint,
not the previous one. The next run reads the previous checkpoint and
resumes there.

## What's in the checkpoint

The on-disk format is versioned (current version 7). The blob holds:

- Source identity: `Content-Length`, `ETag`, `Last-Modified`, and
  the per-mirror metadata. Detects upstream drift (the source
  changing during a run).
- Chunk bitmap and CRC32C fingerprints: which chunks are complete.
  The per-chunk fingerprint catches partial writes that were not
  yet marked.
- Decoder state: per-format frame-aligned snapshot. For zstd, the
  inter-block state. For xz, the LZMA2 inter-chunk state. For gzip,
  a 32 KiB sliding-window snapshot plus the running CRC32 / ISIZE.
  For RAR, the §F1 blob capturing the LZ dictionary state and
  filter program cache.
- Sink state: per-entry write progress for tar / zip / 7z / rar
  per-entry sinks.
- Streaming SHA-256 state: if `--sha256` is set, the SHA-256
  intermediate `state` words are checkpointed so the resumed digest
  is byte-identical to `sha256sum` over the original file.

## Resume guarantees

The output is byte-identical to a clean run if and only if:

1. The source bytes at the same URL have not changed (ETag /
   Last-Modified verification catches this).
2. The same `peel` version (or a forward-compatible one) is used to
   resume.
3. The output directory has not been tampered with between runs.
   `peel` does not re-verify extracted files on resume; it trusts
   the checkpoint's record of what was written.

If the source has changed mid-run, `peel`'s per-chunk CRC32C
fingerprints catch the drift: a chunk's fingerprint at re-fetch
time disagrees with what was checkpointed. `peel` aborts the resume
with a specific "source changed during run" error rather than
silently writing wrong bytes.

If the `peel` version changed and the checkpoint format is
incompatible, the resume aborts at parse time. Re-run with the same
version, or delete the sidecars (`rm <output>.peel.part
<output>.peel.ckpt`) to start from scratch.

## Resuming a run

There is no separate "resume" flag. Re-invoke the same command:

```sh
peel https://example.com/dataset.tar.zst -o ./out/
# Ctrl-C / kill -9 / network drop happens at 50% through.
# Sidecars remain on disk.

peel https://example.com/dataset.tar.zst -o ./out/
# Picks up at the last checkpoint, finishes the rest.
```

For multi-volume or multi-part runs, pass the same URL list / `@file`
and the same `-o`. The checkpoint records the assembled source's
identity, so partial progress across multiple URLs is preserved.

## Crash-test coverage

The crash-test harness in `tests/test_crash_resume.rs` runs 100
random kill points per format and asserts that the post-resume
output bytes are byte-identical to a clean run, every time. This
verifies the byte-identical guarantee.

## Inspecting a checkpoint

The checkpoint blob is not human-readable. Its presence on disk is
inspectable:

```sh
$ ls -la ./out.peel.part ./out.peel.ckpt
-rw-r--r--  1 ag  staff  10737418240 May 13 14:22 ./out.peel.part   # logical size
-rw-r--r--  1 ag  staff       274432 May 13 14:22 ./out.peel.ckpt

# Physical size: what is actually on disk, after hole-punching
$ du -h ./out.peel.part
123M    ./out.peel.part
```

`du -h` reports the physical size, which is the in-flight window.
The logical size (`ls -la`) is the full archive length.

`RUST_LOG=debug peel …` logs checkpoint writes as they happen:

```text
DEBUG checkpoint write: bytes_since_last=8.0MiB seconds_since_last=2.1
DEBUG checkpoint write: bytes_since_last=8.0MiB seconds_since_last=2.0
```

## Tuning checkpoint cadence

The defaults work well across the bench grid. Reasons to tune:

| Goal | Flag | Direction |
| --- | --- | --- |
| Fewer `fsync`s on slow disks | `--checkpoint-min-bytes` | Larger (e.g. 64 MiB) |
| Tighter resume granularity for very long runs | `--checkpoint-min-secs` | Smaller (e.g. 1 s) |
| Steady cadence under highly variable network | `--checkpoint-target-secs` | Smaller (e.g. 0.1 s) |
| Disable rate-aware scaling for reproducibility | `--checkpoint-target-secs` | `0` |

A more aggressive cadence trades extra `fsync` syscalls for
finer-grained resume: less work lost on a `kill -9`, more CPU and
IO during normal operation.

## When resume can't help

A few scenarios fall outside the byte-identical-resume guarantee:

- The source disappeared between runs. Sidecars stay on disk until
  removed; the next run fails at the HEAD probe with a clear error.
- The output directory was partially modified by hand. `peel` does
  not re-verify already-extracted files. If this is suspected,
  delete the output and the sidecars and start over.
- The checkpoint format is from an incompatible `peel` version.
  Delete the `.peel.ckpt` to start fresh from the part-file (the
  part-file's chunks are still individually verifiable via the
  inline fingerprints), or delete both sidecars to start completely
  from scratch.
- Non-destructive local extraction. `peel ./file.tar.zst` (no `-d`)
  is a one-pass run with no checkpoint. The source remains intact
  on kill, so re-run.
