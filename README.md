# peel

**Sick of downloading an archive just to extract it and delete it?**
**Tired of provisioning disk for *both* the compressed file and the
extracted contents — only to throw ~half of it away?**

`peel` downloads, decompresses, and extracts in a single pass. The
compressed bytes never fully land on disk: as the decoder consumes them,
the download buffer is hole-punched out from underneath. Your archive
and your extracted tree never coexist at full size, the pipeline
survives `kill -9`, and resumption is byte-identical to a clean run.

```
peel https://example.com/dataset.tar.zst -C ./out
```

## What you get

- **Streaming, hole-punched extraction.** Parallel ranged HTTP downloads
  feed a sparse part-file; the decoder consumes the prefix while
  workers continue to fetch the suffix; finished bytes are released back
  to the filesystem as the decoder advances. Peak compressed-side disk
  is ~the download window, not the archive size.
- **Multi-format.** `.tar`, `.tar.zst`/`.zst`, `.tar.xz`/`.xz`,
  `.tar.lz4`/`.lz4`, `.tar.gz`/`.gz`, and `.zip` (STORED + DEFLATE +
  zstd entries).
  Format detection is suffix-first with magic-byte fallback; mismatches
  fail closed unless you opt in with `--force-format-from-magic` or
  pin a decoder with `--format <name>`.
- **Resumable by construction.** Frame-aligned checkpoints (atomic
  `write+fsync+rename`) plus per-chunk fingerprints. A `kill -9`
  mid-extraction resumes exactly where it left off. The crash-test
  harness runs 100 random kill points per format and asserts
  byte-identical output every time.
- **Single-pass integrity.** `--sha256 <hex>` streams a hand-rolled,
  resumable SHA-256 over the source bytes. The hash state is
  checkpointed alongside everything else, so a resumed run produces a
  digest byte-identical to `sha256sum` on the original file.
- **Mid-flight drift detection.** Per-chunk CRC32C fingerprints catch
  source changes during a run and on resume; strong/weak ETag handling
  layered on top.
- **Multi-mirror.** Repeat `--mirror <URL>` to download from several
  sources at once. The scheduler verifies size/ETag/hash agreement at
  startup, biases work toward the fastest live mirror, and excludes
  failing mirrors with backoff instead of failing the whole run.
- **Bandwidth limiting.** `--max-bandwidth 50MB/s` (decimal or `MiB`
  binary suffixes) caps aggregate throughput across all workers and
  mirrors via a shared token bucket.

## Performance, on Linux

- **`io_uring` end-to-end.** The default backend submits the parallel
  `pwrite`/`pread`/`fsync` syscalls *and* the download workers' TCP
  `connect`/`send`/`recv` through a single ring on a dedicated IO
  thread. `rustls` rides on top unchanged; per-op timeouts are linked
  `LinkTimeout` SQEs so cancellations are prompt without polling.
- **Memory-mapped sparse file.** Workers `memcpy` into a `MAP_SHARED`
  region; `madvise(MADV_REMOVE)` releases pages as the decoder
  advances. This is the default file-IO path on Linux and removes a
  syscall per chunk write at high parallelism.
- **Adaptive chunk-sizing.** A scheduler watches per-GET latency and
  retry rate and grows or shrinks how many bitmap chunks coalesce into
  a single ranged GET (1 MiB floor, 64 MiB cap, 30 s hysteresis).
  Bitmap unit and dispatch unit are decoupled, so checkpoints stay
  fine-grained while the wire-level request size scales with the
  network.
- **Graceful fallbacks.** Every Linux fast path probes at startup and
  logs a single `warn!` if it has to step down (kernel < 5.6,
  `RLIMIT_MEMLOCK` too low, seccomp blocking, filesystem rejecting
  `MADV_REMOVE`/`PUNCH_HOLE`). Pick the path explicitly with
  `--io-backend [auto|blocking|uring|mmap]` (default: `auto`).
- **Live progress.** A redrawn three-line block shows download/extract
  rates, ETA, active workers, and on-disk source footprint. Falls back
  to periodic `tracing::info!` lines on a non-TTY without any extra
  flag.

## Why you want this

**Local workstations.** Pulling a 40 GB `.tar.zst` dataset shouldn't
require 80 GB free. With `peel`, peak disk usage is roughly
`extracted_size + a few hundred MB` — not `compressed_size +
extracted_size`.

**Kubernetes / PVCs.** Loading a database snapshot, ML model bundle, or
seed dataset into a PersistentVolumeClaim is the canonical case. The
naive approach forces you to size the PVC for `archive + extracted`,
then shrink it (or live with the waste) once extraction finishes. PVCs
don't shrink gracefully, so in practice you over-provision forever.
`peel` lets you size the PVC for the **extracted** contents plus a
small download window — which is what you actually need to keep around.
Drop it into an `initContainer` and the volume is ready by the time
your workload starts.

**CI runners and ephemeral disks.** Same story: bounded disk, resumable
on flaky networks, no scratch space gymnastics.

## Usage

```sh
# Stream a tar archive into a directory
peel https://example.com/linux-6.x.tar.xz -C ./linux

# Bare compressed file → single output file
peel https://example.com/model.bin.zst -o ./model.bin

# Verify an expected hash, cap bandwidth, fan out across mirrors
peel https://primary.example.com/dataset.tar.zst \
  --mirror https://eu.mirror.example.com/dataset.tar.zst \
  --mirror https://us.mirror.example.com/dataset.tar.zst \
  --sha256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad \
  --max-bandwidth 50MB/s \
  -C ./out

# URL has no useful suffix? Pin the decoder.
peel "https://example.com/download?id=42" --format zstd -o ./out.bin

# A/B against the pre-uring path
peel https://example.com/dataset.tar.zst --io-backend blocking -C ./out
```

| Flag | Default | Notes |
| --- | --- | --- |
| `-C, --output-dir <DIR>` | — | Extract a tar/zip archive into `DIR`. Mutually exclusive with `-o`. |
| `-o, --output-file <FILE>` | — | Stream the decoded bytes verbatim into `FILE`. |
| `--workers <N>` | 8 | Parallel download workers. |
| `--chunk-size <BYTES>` | 4 MiB | Bitmap unit. With adaptive sizing, dispatch may coalesce several. |
| `--no-adaptive-chunk-size` | off | Lock dispatch to the bitmap unit. |
| `--io-backend <auto\|blocking\|uring\|mmap>` | `auto` | Linux: `auto` ≈ `mmap` for files + `uring` for sockets. |
| `--format <NAME>` | — | Force a decoder, bypassing suffix and magic detection. |
| `--force-format-from-magic` | off | Trust magic bytes when they disagree with the URL suffix. |
| `--sha256 <HEX>` | — | Verify the assembled compressed source against this 64-hex digest. |
| `--mirror <URL>` (repeatable) | — | Additional source URLs for the same file. |
| `--max-bandwidth <RATE>` | — | Aggregate cap; `K`/`M`/`G` (decimal) or `Ki`/`Mi`/`Gi` (binary). |
| `--punch-threshold <BYTES>` | tuned | Minimum gap between in-loop hole-punch syscalls. |
| `--checkpoint-min-bytes <BYTES>` | 8 MiB | Minimum source progress between checkpoint writes. |
| `--checkpoint-min-secs <SECS>` | 2 | Minimum wall-clock interval between checkpoint writes. |

`peel --help` for the full list and exact defaults.

## Status

MVP complete (2026-04-29). PLAN_v2 round one — multi-format support,
io_uring file + network, adaptive chunk-sizing, mmap sparse file,
SHA-256 integrity with resumable hashing, multi-mirror, bandwidth
limiting, the progress UI — has landed on top. Active work moves back
to [`docs/OPTIMIZATIONS.md`](docs/OPTIMIZATIONS.md) for round two
planning.

| | Streaming | Frame-granular resume | Magic-byte detect |
| --- | --- | --- | --- |
| `.tar` (uncompressed) | ✓ | per tar member | ✓ (offset 257) |
| `.zst` / `.tar.zst` | ✓ | per zstd frame | ✓ |
| `.xz` / `.tar.xz` | ✓ | per xz Stream¹ | ✓ |
| `.lz4` / `.tar.lz4` | ✓ | per lz4 block | ✓ |
| `.gz` / `.tar.gz` | ✓ | per gzip member | ✓ |
| `.zip` | per-entry² | per entry | ✓ |

¹ Default-encoded `.tar.xz` is single-Block; per-Block granularity is
filed as `O.6b` for a future round.
² ZIP uses a separate per-entry pipeline because of the
central-directory-at-the-end layout. STORED + DEFLATE + zstd entries
in round one; AES, Zip64, multi-disk filed as `O.8b`.

## For contributors and AI agents

Start with [`CLAUDE.md`](CLAUDE.md) (or [`AGENTS.md`](AGENTS.md) — both
point at the same docs). The full doc set:

- [`CLAUDE.md`](CLAUDE.md) — entry point, house rules summary
- [`AGENTS.md`](AGENTS.md) — workflow rules for coding agents
- [`docs/PLAN.md`](docs/PLAN.md) — sequenced MVP plan (complete; kept
  as historical record)
- [`docs/PLAN_v2.md`](docs/PLAN_v2.md) — round-one post-MVP plan
  (complete)
- [`docs/ENGINEERING_STANDARDS.md`](docs/ENGINEERING_STANDARDS.md) —
  non-negotiable rules
- [`docs/ENGINEERING_BEST_PRACTICES.md`](docs/ENGINEERING_BEST_PRACTICES.md)
  — idiomatic patterns
- [`docs/OPTIMIZATIONS.md`](docs/OPTIMIZATIONS.md) — backlog;
  promotions require a successor plan before implementation

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms
or conditions.
