# peel

> Streaming, resumable, space-efficient extractor for compressed archives over
> HTTP, and for local archive files on disk.

```sh
peel https://example.com/dataset.tar.zst
```

`peel` is a Rust CLI that downloads, decompresses, and extracts an archive in
a single pass. It resumes exactly where it left off after a dropped
connection, `kill -9`, OOM kill, or power loss. The compressed bytes never
fully land on disk: as the decoder consumes the prefix, the download buffer
underneath is hole-punched out. The archive and the extracted tree never
coexist at full size.

## What it solves

- **Disk pressure.** Pulling a 40 GB `.tar.zst` should not require 80 GB free.
  Peak disk usage is roughly `extracted_size + a few hundred MB`, not
  `compressed_size + extracted_size`.
- **Flaky networks.** A dropped connection mid-download is the default case,
  not the edge case. `peel` resumes at the byte that was in flight.
- **`kill -9` and pod restarts.** Frame-aligned checkpoints (atomic
  `write+fsync+rename`) plus per-chunk fingerprints ensure a hard kill
  mid-extraction resumes exactly where it left off, byte-identical to a
  clean run.
- **Streaming `.zip`, `.7z`, `.rar` over HTTP.** `curl | unzip` does not
  work: the ZIP central directory lives at the end of the file, the 7z
  trailer pointer sits at the end of the file, and `unrar` requires
  `lseek` on its input. `peel` issues a ranged GET for the central
  directory or trailer first (zip, 7z), or walks the RAR header chain in
  stream order (rar), then streams entries to disk as soon as their bytes
  arrive.

## Format coverage at a glance

| Family | Formats |
| --- | --- |
| Plain | `.tar` |
| Streaming codecs | `.zst` / `.tar.zst` · `.xz` / `.tar.xz` · `.lz4` / `.tar.lz4` · `.gz` / `.tar.gz` |
| Random-access archives | `.zip` · `.7z` · `.rar` (RAR5 + legacy RAR3/RAR4) |

Encrypted archives are supported for zip (WinZip-AES, ZipCrypto), 7z
(AES-256-CBC), and rar5 (AES-256-CBC, both archive-header and per-file).
See [Encrypted archives](./encryption.md).

The full per-format matrix (magic-byte detection, resume granularity,
encryption) is on the [Supported formats](./formats.md) page.

## Distinguishing features

1. **Hole-punched compressed buffer.** Parallel ranged HTTP downloads feed a
   sparse part-file. The decoder consumes the prefix while workers continue
   to fetch the suffix, and finished bytes are released back to the
   filesystem as the decoder advances. Peak compressed-side disk usage is
   the download window (approximately `--max-disk-buffer`), not the archive
   size.

2. **Frame-aligned, byte-identical resume.** A `kill -9` anywhere in the
   pipeline leaves a `.peel.ckpt` next to the part file. Re-running the
   same command picks up exactly at the checkpointed frame. The final
   output is byte-identical to a clean run. The crash-test harness runs
   100 random kill points per format and asserts that property every time.

3. **One command for HTTP and local.** A URL argument triggers parallel
   ranged GETs and streaming extract. A local file argument runs the same
   hand-rolled decoders against the file on disk: non-destructive by
   default, with hole-punching enabled via `-d`.

## Where to next

- Getting started: [Installation](./installation.md) and
  [Quick start](./quick-start.md).
- Full flag listing: [CLI reference](./cli-reference.md).
- Specific features: [Multi-volume archives](./multi-volume.md),
  [Encrypted archives](./encryption.md),
  [Performance and tuning](./performance.md),
  [Checkpoint and resume](./checkpoint-resume.md).
- Pipeline integration: the [worked examples](./examples/kubernetes.md)
  cover Kubernetes init containers, CI runners, and an Arbitrum snapshot
  bundle.
