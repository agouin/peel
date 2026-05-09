# peel

**Sick of downloading an archive just to extract it and delete it?**
**Tired of provisioning disk for *both* the compressed file and the
extracted contents — only to throw ~half of it away?**
**Tired of restarting a half-finished multi-gigabyte download from
scratch every time the connection drops or the process gets killed?**

`peel` downloads, decompresses, and extracts in a single pass — and
resumes exactly where it left off after any interruption: dropped
connection, `kill -9`, power loss, OOM. The compressed bytes never
fully land on disk: as the decoder consumes them, the download buffer
is hole-punched out from underneath. Your archive and your extracted
tree never coexist at full size, and a resumed run produces output
byte-identical to a clean run.

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
  `.tar.lz4`/`.lz4`, `.tar.gz`/`.gz`, `.zip` (STORED + DEFLATE +
  zstd entries), `.7z` (COPY + DEFLATE + LZMA + LZMA2 coders;
  plain and unencrypted-encoded headers; single-volume), and
  `.rar` (RAR5; STORED entries today via the `rar` Cargo feature
  on by default — non-encrypted, single-volume only; the
  hand-rolled compressed-method decoder lands per
  `docs/PLAN_rar5_decoder.md`). Format detection is suffix-first
  with magic-byte fallback; mismatches fail closed unless you opt
  in with `--force-format-from-magic` or pin a decoder with
  `--format <name>`. Build with `cargo build --no-default-features`
  (or any subset that excludes `rar`) to drop the RAR5 module
  entirely; `.rar` URLs then surface a precise "compiled without
  the `rar` feature" diagnostic instead of "unknown format".
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

**Streaming `.zip` and `.7z` over HTTP at all.** `curl | unzip` and
`curl | 7z x` don't work: the ZIP central directory lives at the
end of the file, and the 7z SignatureHeader points at a trailer at
the end of the file — so a stdin-only decoder has to buffer the
entire archive before it can decode the first byte. The canonical
workaround (download fully, then extract, then delete) defeats the
whole point of streaming. `peel` uses a ranged GET to fetch the
central directory / trailer first, then streams entries (zip) or
folders (7z) in order while the rest of the archive is still
arriving — same hole-punching, same resume guarantees as the tar
formats.

## Benchmarks: peel vs `curl | <decompressor> | tar`

The fair worry is "doesn't all that machinery — parallel ranged GETs,
sparse part-file, frame-aligned checkpoints, hole-punching — make
`peel` slower than just `curl | zstd -d | tar -xf -`?" No. The decoder
side is faster than the wire side, so the structural overhead
disappears into the network wait, and `peel` actually wins by a small
margin from ranged-GET parallelism — across every codec the grid
covers, including `tar.xz`.

Both sides share the same rate cap (`peel --max-bandwidth`,
`curl --limit-rate`). Payload size scales per row so wire-time stays
in the 0.2–7 s range (long enough to drown out connection setup,
short enough that the whole grid finishes in ~6 minutes). 4 workers,
blocking IO backend, in-process mock server on loopback. Apple M4
Max / macOS 26.3, two consecutive runs averaged (variance ≤ 5 %).
Reproduce with:

```sh
cargo test --release --test test_bench_streaming \
  bench_throttled_realistic_grid -- --ignored --nocapture --test-threads=1
```

### Wall-clock ratio: `peel` ÷ `curl | tool`

Lower is better; **bold** = `peel` is faster than the shell pipe.

| Format | 10 Mbps · 8 MiB | 100 Mbps · 32 MiB | 1 Gbps · 128 MiB | 10 Gbps · 256 MiB |
| --- | --- | --- | --- | --- |
| `tar` | 1.07× | **0.94×** | **0.79×** | **0.90×** |
| `tar.zst` | 1.08× | **0.94×** | **0.79×** | **0.93×** |
| `tar.gz`¹ | 1.14× | **0.94×** | **0.79×** | 1.05× |
| `tar.gz·m`² | 1.08× | **0.95×** | **0.79×** | **0.97×** |
| `tar.lz4` | 1.09× | **0.94×** | **0.78×** | **0.91×** |
| `tar.xz` | 1.04× | **0.99×** | 1.03× | **0.97×** |

¹ Single-member gzip — the default-`gzip` / `tar -z` shape.
² Multi-member gzip (~32 MiB members) — the `pigz` / `gzip a b > c.gz`
shape. Same baseline pipe (`gzip -d` handles concatenated members per
RFC 1952 §2.2).

Absolute wall-clock for the 10 Gbps · 256 MiB column, for scale:
`tar` 0.22 s vs 0.24 s · `tar.zst` 0.22 s vs 0.23 s · `tar.lz4`
0.22 s vs 0.24 s · `tar.gz` 0.27 s vs 0.24 s · `tar.gz·m` 0.25 s vs
0.24 s · `tar.xz` 5.68 s vs 5.85 s.

### Reading the grid

At 100 Mbps and up, `peel` ties or beats the system pipeline across
every codec. Four parallel ranged GETs put more bandwidth in flight
than curl's single TCP connection, and that win more than pays for the
part-file double-hop and checkpoint syncs.

The 10 Mbps row is the one place the parallel-GET shape costs more
than it earns. With 8 MiB of payload, ranged-GET parallelism has
nothing to amortize over: as the body finishes, workers idle out one
by one and the last worker drains the token bucket alone, so the
trailing edge runs below the cap. Add post-wire finalization (final
checkpoint, manifest, sink fsync) and `peel` lands ~500 ms over the
6.7 s wire-time floor; `curl --limit-rate` lands within ~40 ms of it.
The gap is widest in codecs (`tar`, `tar.lz4`) whose baseline decoder
is too cheap to soak it up, and disappears in `tar.xz` / `tar.gz`
where the baseline's slower decoder absorbs most of it.

## Benchmarks: peel vs `curl -O && <extract> && rm`

The streaming-pipe baseline above is a fair head-to-head for the
`tar.*` family — the user has the option of `curl … | tool | tar`.
For `.zip` and `.7z` they don't: the ZIP central directory and the
7z trailer pointer both live at the *end* of the archive, so a
stdin-only decoder has to buffer the whole file before it can decode
the first byte. The canonical user-typed workflow for those formats
collapses to:

```sh
curl -O https://example.com/dataset.zip
unzip dataset.zip -d ./out
rm dataset.zip
```

`peel` collapses that three-step sequence into one. A ranged GET
fetches the central directory / trailer first, then entries (zip)
or folders (7z) stream into the sink while the rest of the archive
is still arriving — the compressed bytes never fully land on disk.
For tar.{zst,xz,gz,lz4} the same happens, just against a `tar.*`
baseline that *also* has to wait for `curl` to finish before
extracting.

Same machinery as the streaming grid; same rate × payload cells.
The baseline is `curl --limit-rate <R> -o <file> $URL && <extract
<file> into dir> && rm <file>`. p7zip 17.05 (Homebrew) for `7z`;
everything else as in the streaming grid. Two consecutive runs
averaged. Reproduce with:

```sh
cargo test --release --test test_bench_streaming \
  bench_throttled_download_then_extract_grid -- --ignored --nocapture --test-threads=1
```

### Wall-clock ratio: `peel` ÷ `curl -O && <extract> && rm`

Lower is better; **bold** = `peel` is faster than the
download-then-extract sequence.

| Format | 10 Mbps · 8 MiB | 100 Mbps · 32 MiB | 1 Gbps · 128 MiB | 10 Gbps · 256 MiB |
| --- | --- | --- | --- | --- |
| `tar` | 1.11× | **0.93×** | **0.74×** | **0.70×** |
| `tar.zst` | 1.11× | **0.93×** | **0.72×** | **0.54×** |
| `tar.gz` | 1.13× | **0.92×** | **0.71×** | **0.62×** |
| `tar.lz4` | 1.08× | **0.93×** | **0.72×** | **0.59×** |
| `tar.xz` | 1.06× | **0.83×** | **0.78×** | **0.96×** |
| `zip` | 1.08× | **0.90×** | **0.58×** | **0.24×** |
| `7z` | 1.06× | **0.93×** | **0.78×** | 1.04× |

### Reading the grid

For tar.* rows at 100 Mbps and up, peel's wall-clock is roughly the
wire-time — decode runs in parallel with the download. The baseline's
is `wire-time + extract-time + rm`. peel saves the trailing extract
phase outright, and the savings widen with bandwidth: at 1 Gbps and
above the baseline eats half a second to over a second of trailing
wall-clock that peel never spends. `tar.xz` shows the slow-decode
story most cleanly — at 100 Mbps peel is **0.82×** the baseline
because xz decode runs during the in-flight download instead of after
it.

The 10 Mbps row trails the baseline by 4–13% for the same reason as
the streaming grid above: 8 MiB is too small for parallel ranged GETs
to amortize, so trailing-edge drain plus post-wire finalization land
peel ~300–500 ms over the wire-time floor.

`zip` is the headline. There is no streaming-pipe baseline for
`.zip`, so this grid is the only fair head-to-head. At 1 Gbps ×
128 MiB peel finishes in roughly half the baseline's wall-clock;
at 10 Gbps × 256 MiB it's a 4× speedup. peel writes each entry to
its final path as soon as the entry's bytes arrive, while the
baseline is structurally barred from starting `unzip` until `curl`
finishes.

`7z` supports the same single-pass shape: peel beats the
baseline at every bandwidth from 100 Mbps through 1 Gbps and
ties at 10 Gbps. The 10 Gbps cell is essentially a draw because
the 256 MiB archive fits inside a sub-300 ms wire window — once
wire-time drops below ~300 ms the per-archive overhead of any
extraction tool dominates, and `curl -O && 7z x && rm` and peel
both finish within ~10 ms of each other.

### When to reach for `peel`

`peel` is the right choice in every case the bench grids cover —
it ties or beats `curl | tool | tar` across the streaming grid,
and against `curl -O && <extract> && rm` it widens the gap on
every cell where the wire-time is non-trivial. On top of the
wall-clock numbers you get the full feature set:

- Disk for `archive_size + extracted_size` doesn't fit — PVCs,
  ephemeral runners, TB-scale datasets — only `peel` keeps the
  compressed side bounded via `fallocate(PUNCH_HOLE)`.
- A `kill -9`, network drop, or pod restart shouldn't cost you the
  run — frame-aligned checkpoints resume exactly where they left off.
- `--sha256` verified inline, `--mirror` fan-out across sources, and
  `--max-bandwidth` capping are first-class.
- `.zip` and `.7z` over HTTP without ever materializing the full
  archive on disk — a single-pass streaming workflow that simply
  doesn't exist with `curl + unzip` or `curl + 7z`.

## Usage

```sh
# Stream a tar archive into a directory
peel https://example.com/linux-6.x.tar.xz -C ./linux

# No -C / -o? Default extract dir is the URL basename with known
# archive/compression suffixes stripped, in the current working
# directory: this lands the contents in ./linux-6.x
peel https://example.com/linux-6.x.tar.xz

# Bare compressed file → single output file
peel https://example.com/model.bin.zst -o ./model.bin

# Verify an expected hash, cap bandwidth, fan out across mirrors
peel https://primary.example.com/dataset.tar.zst \
  --mirror https://eu.mirror.example.com/dataset.tar.zst \
  --mirror https://us.mirror.example.com/dataset.tar.zst \
  --sha256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad \
  --max-bandwidth 50MB/s \
  -C ./out

# Multi-part split archive: concatenated parts form one logical
# stream. Pass each part as a positional URL; --sha256 is repeatable
# and pairs with the URLs by order. Workers fetch every part in
# parallel via ranged GETs, the same way `aria2c -Z` would, but
# stream into the decoder so the compressed bytes never fully land
# on disk. Used in production against Arbitrum snapshot bundles
# (see scripts/arb-snapshot.sh).
peel \
  https://snapshot.arbitrum.io/nova/2026-04-26-7efe0f23/pruned.tar.part0000 \
  https://snapshot.arbitrum.io/nova/2026-04-26-7efe0f23/pruned.tar.part0001 \
  --sha256 0a8de6e83fd8ba040fd052fd8d4fd0e009a9736ace5cb32bb2abd4ac6a61725d \
  --sha256 1bcf4d2e9aa01ff5...                                              \
  -C ./nova-out

# URL has no useful suffix? Pin the decoder.
peel "https://example.com/download?id=42" --format zstd -o ./out.bin

# A/B against the pre-uring path
peel https://example.com/dataset.tar.zst --io-backend blocking -C ./out
```

| Flag | Default | Notes |
| --- | --- | --- |
| `-C, --output-dir <DIR>` | URL basename, suffixes stripped | Extract a tar/zip archive into `DIR`. When neither `-C` nor `-o` is given, defaults to `$(pwd)/<basename>` with known archive/compression extensions stripped (`abcd.tar.xz` → `./abcd`). Mutually exclusive with `-o`. |
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
| `.zst` / `.tar.zst` | ✓ | per zstd block | ✓ |
| `.xz` / `.tar.xz` | ✓ | per LZMA2 chunk | ✓ |
| `.lz4` / `.tar.lz4` | ✓ | per lz4 block | ✓ |
| `.gz` / `.tar.gz` | ✓ | per deflate block¹ | ✓ |
| `.zip` | per-entry² | per entry + intra-entry³ | ✓ |
| `.7z` | per-folder⁴ | per folder⁴ | ✓ |

¹ Hand-rolled RFC 1951 inflate with a 32 KiB sliding-window snapshot
plus running CRC32/ISIZE persisted in the checkpoint, so a `kill -9`
mid-member resumes byte-identically without re-decoding the member from
its start. `flate2` is a dev-dependency only (used in the differential
test harness), not a runtime dependency.
² ZIP uses a separate per-entry pipeline because of the
central-directory-at-the-end layout. STORED + DEFLATE + zstd entries
in round one; AES, Zip64, multi-disk filed as `O.8b`.
³ STORED entries resume byte-granular; DEFLATE entries resume per
deflate block via the same 32 KiB-window snapshot used for `.gz`; zstd
entries resume per zstd block. Encoded into the checkpoint format
(version 7) under each in-progress entry.
⁴ 7z uses a separate per-folder pipeline (the "second-pipeline"
driver from `docs/PLAN_7z_support.md` §8) because of the
SignatureHeader → trailer-pointer layout. Round one: COPY, DEFLATE,
LZMA, and LZMA2 coders; plain `Header` and unencrypted
`EncodedHeader`; single-volume archives only. Resume granularity is
one folder at a time — a `kill -9` mid-folder restarts that folder
from the start of its packed range; per-coder intra-folder resume,
BCJ filters, AES, and multi-volume archives are queued.

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
