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
peel https://example.com/dataset.tar.zst -o ./out/
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
  `.rar` — both **RAR5** (STORED + the standard RAR5 algorithm
  at compression methods 1..5, end-to-end through the hand-rolled
  `decode::rar_native` LZSS pipeline plus the RAR-VM standard
  filters per `docs/PLAN_rar5_decoder.md`) and **legacy
  RAR3/RAR4** (STORED + LZ-Normal entries through the hand-rolled
  `decode::rar_legacy` pipeline, with RarVM standard filters —
  E8, E8E9, Delta, RGB, Audio — dispatched per entry).
  Both gated by the `rar` Cargo feature on by default;
  non-encrypted, single-volume only. Format detection is
  suffix-first with magic-byte fallback; mismatches fail closed
  unless you opt in with `--force-format-from-magic` or pin a
  decoder with `--format <name>`. Build with
  `cargo build --no-default-features` (or any subset that excludes
  `rar`) to drop the RAR module entirely; `.rar` URLs then surface
  a precise "compiled without the `rar` feature" diagnostic instead
  of "unknown format".
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

**Streaming `.zip`, `.7z`, and `.rar` over HTTP at all.**
`curl | unzip`, `curl | 7z x`, and `curl | unrar x` don't work:
the ZIP central directory lives at the end of the file, the 7z
SignatureHeader points at a trailer at the end of the file, and
`unrar` requires `lseek` on its input regardless of where the RAR
metadata sits — so a stdin-only decoder either has to buffer the
entire archive before decoding or just refuses to start. The
canonical workaround (download fully, then extract, then delete)
defeats the whole point of streaming. `peel` uses a ranged GET
to fetch the central directory / trailer first (zip / 7z) or
walks the RAR header chain in stream order (rar5 + legacy
rar3/rar4), then streams entries (zip, rar) or folders (7z) as
soon as their bytes arrive while the rest of the archive is
still in flight — same hole-punching, same resume guarantees as
the tar formats.

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
fetches the central directory / trailer first (zip, 7z) or walks
the RAR header chain in stream order (rar5 + legacy rar3/rar4),
then entries (zip, rar) or folders (7z) stream into the sink while
the rest of the archive is still arriving — the compressed bytes
never fully land on disk. For tar.{zst,xz,gz,lz4} the same happens,
just against a `tar.*` baseline that *also* has to wait for `curl`
to finish before extracting.

Same machinery as the streaming grid; same rate × payload cells.
The baseline is `curl --limit-rate <R> -o <file> $URL && <extract
<file> into dir> && rm <file>`. p7zip 17.05 (Homebrew) for `7z`;
RARLAB `unrar 7.22` (license-purchased copy) for `rar5` / `rar3`,
which `peel` uses as a third-party benchmark baseline only — never
as an implementation reference (see "RAR provenance" below).
Everything else as in the streaming grid. Two consecutive runs
averaged. The `rar` rows use archives produced by RARLAB's real
encoder (`rar 7.22` for RAR5 STORED, `rar 5.0.0` Linux x86_64 in a
`linux/amd64` Docker container for RAR3 LZ-Normal) and cached
under `tests/fixtures/rar_bench/`; the first run bakes them, every
subsequent run reuses the cache. Reproduce with:

```sh
cargo test --release --test test_bench_streaming \
  bench_throttled_download_then_extract_grid \
  --features rar -- --ignored --nocapture --test-threads=1
```

### Wall-clock ratio: `peel` ÷ `curl -O && <extract> && rm`

Lower is better; **bold** = `peel` is faster than the
download-then-extract sequence.

| Format | 10 Mbps · 8 MiB | 100 Mbps · 32 MiB | 1 Gbps · 128 MiB | 10 Gbps · 256 MiB |
| --- | --- | --- | --- | --- |
| `tar` | 1.02× | **0.93×** | **0.73×** | **0.76×** |
| `tar.zst` | 1.01× | **0.93×** | **0.72×** | **0.57×** |
| `tar.gz` | 1.11× | **0.93×** | **0.72×** | **0.62×** |
| `tar.lz4` | 1.05× | **0.93×** | **0.72×** | **0.59×** |
| `tar.xz` | 1.03× | **0.83×** | **0.77×** | **0.97×** |
| `zip` | 1.06× | **0.90×** | **0.58×** | **0.24×** |
| `7z` | 1.02× | **0.93×** | **0.75×** | **0.74×** |
| `rar5` | 1.07× | **0.95×** | **0.93×** | 2.43× |
| `rar3` | 1.06× | **0.96×** | **0.99×** | 1.30× |

### Reading the grid

For tar.* rows at 100 Mbps and up, peel's wall-clock is roughly the
wire-time — decode runs in parallel with the download. The baseline's
is `wire-time + extract-time + rm`. peel saves the trailing extract
phase outright, and the savings widen with bandwidth: at 1 Gbps and
above the baseline eats half a second to over a second of trailing
wall-clock that peel never spends. `tar.xz` shows the slow-decode
story most cleanly — at 100 Mbps peel is **0.83×** the baseline
because xz decode runs during the in-flight download instead of after
it.

The 10 Mbps row sits within 1–11% of the baseline for the same
reason as the streaming grid above: 8 MiB is too small for parallel
ranged GETs to amortize, so trailing-edge drain plus post-wire
finalization land peel up to ~500 ms over the wire-time floor.

`zip` is the headline. There is no streaming-pipe baseline for
`.zip`, so this grid is the only fair head-to-head. At 1 Gbps ×
128 MiB peel finishes in roughly half the baseline's wall-clock;
at 10 Gbps × 256 MiB it's a 4× speedup. peel writes each entry to
its final path as soon as the entry's bytes arrive, while the
baseline is structurally barred from starting `unzip` until `curl`
finishes.

`7z` supports the same single-pass shape: peel beats the
baseline at every bandwidth from 100 Mbps through 10 Gbps. At
10 Gbps × 256 MiB the COPY-coded archive's 256 MiB fits inside a
sub-300 ms wire window, so the gap narrows to **0.74×** — peel
still wins because writing each folder's bytes to the final path
during the in-flight window beats running `7z x` over the full
archive after `curl` finishes, even when both are very fast.

`rar5` and `rar3` are the new entries. `unrar` requires a
seekable file (the binary `lseek`s its input regardless of
where the metadata sits), so a streaming-pipe baseline doesn't
exist for them either — this grid is the only fair head-to-head.
peel ties or beats the baseline at every cell from 10 Mbps
through 1 Gbps for both formats. The 10 Gbps × 256 MiB cell is
the one place `unrar` wins outright: at that scale the wire
window collapses to ~0.21 s and the per-entry extraction cost
dominates, where RARLAB's mature implementation has the edge over
the freshly-landed pipelines (RAR5 STORED in
[`docs/PLAN_rar.md`](docs/PLAN_rar.md) §3 and RAR3 LZ-Normal in
[`docs/PLAN_rar3.md`](docs/PLAN_rar3.md) Phases B–C). The RAR3
row is also doing real decode work both sides — `-m3` packs the
incompressible bench payload through full LZ + RarVM filters,
not COPY — so its wall-clock floor (~1.8 s) is much higher than
the other formats. peel's parallel-GET-plus-stream shape pays
for itself everywhere the wire-time is non-trivial, which covers
every real production scenario. (Both rar rows skip rather than
fail when `unrar` is missing from `PATH`.)

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
- `.zip`, `.7z`, and `.rar` (RAR5 + legacy RAR3/RAR4) over HTTP
  without ever materializing the full archive on disk — a
  single-pass streaming workflow that simply doesn't exist with
  `curl + unzip`, `curl + 7z`, or `curl + unrar`.

## Usage

> **Migration (2026-05):** `-C/--output-dir` was removed. The single
> `-o/--output-file` flag now accepts either a file or a directory
> path; a trailing `/` (or an existing directory at the path) means
> "directory output." Replace `-C foo/` with `-o foo/`. Passing
> `-C` produces a hard error pointing at the new flag.

```sh
# Stream a tar archive into a directory (trailing slash forces dir)
peel https://example.com/linux-6.x.tar.xz -o ./linux/

# No -o? Default extract dir is the URL basename with known
# archive/compression suffixes stripped, in the current working
# directory: this lands the contents in ./linux-6.x
peel https://example.com/linux-6.x.tar.xz

# Bare compressed file → single output file
peel https://example.com/model.bin.zst -o ./model.bin

# Download-only: parallel ranged GETs (like aria2c) with no
# extraction. The remote object lands at <basename> verbatim.
peel https://example.com/big.deb --no-extract

# Extract AND keep the source archive on disk. Sibling-of-`-o` by
# default; `-k=<path>` for an explicit location.
peel https://example.com/dataset.tar.zst -o ./out/ -k

# Verify an expected hash, cap bandwidth, fan out across mirrors
peel https://primary.example.com/dataset.tar.zst \
  --mirror https://eu.mirror.example.com/dataset.tar.zst \
  --mirror https://us.mirror.example.com/dataset.tar.zst \
  --sha256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad \
  --max-bandwidth 50MB/s \
  -o ./out/

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
  -o ./nova-out/

# URL has no useful suffix? Pin the decoder.
peel "https://example.com/download?id=42" --format zstd -o ./out.bin

# A/B against the pre-uring path
peel https://example.com/dataset.tar.zst --io-backend blocking -o ./out/
```

### Download modes

peel runs in one of three modes, all selected at the CLI. Format
detection (suffix → magic) decides the output shape for the
default mode; `--no-extract` and `-k`/`--keep-archive` are explicit
mode flags.

| Flag | Download | Extract | Hole-punch source | Source on disk at exit |
| --- | --- | --- | --- | --- |
| (default) | yes | yes | yes | deleted |
| `-k` (bare) | yes | yes | **no** | preserved as sibling of `-o` |
| `-k=<PATH>` | yes | yes | **no** | preserved at `<PATH>` |
| `--no-extract` | yes | no | n/a | preserved at `-o` |

If format detection misses, peel warns and runs as `--no-extract`
by default — the remote object is saved to disk under its URL
basename. Pass `--strict-format` to make that case a hard error
instead (useful in CI when an upstream object changing shape
should fail the build).

| Flag | Default | Notes |
| --- | --- | --- |
| `-o, --output-file <PATH>` | URL basename, suffixes stripped | Output path. Directory for tree-shaped formats (tar / zip / 7z / rar / any `.tar.<x>` wrapper); file for stream-shaped formats (raw `.zst`, `.xz`, `.lz4`, `.gz`). A trailing slash forces directory semantics. |
| `--no-extract` (alias: `--download-only`) | off | Skip extraction; download the source bytes verbatim. |
| `-k, --keep-archive[=<PATH>]` | off | Extract AND keep the source archive on disk. Bare `-k` places the archive as a sibling of `-o`; `-k=<PATH>` is explicit. |
| `--strict-format` | off | Treat unrecognized formats as a hard error rather than falling back to download-only. |
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

### Local-file extraction

Point peel at a path on disk and it skips the HTTP machinery
entirely — no scheduler, no mirrors, no chunk bitmap — and runs
the same decoder / sink / extractor stack against the local
file. Use it when you already have the archive on disk and want
peel's hand-rolled decoders instead of `tar -I zstd -xf` /
`unzip` / `7z x`:

```sh
# Destructive by default: hole-punches the source as the
# decoder advances; deletes it on clean completion. A TTY
# user is prompted before this begins; non-TTY runs must
# pass -y or -k explicitly.
peel /tmp/dataset.tar.zst -o ./out/

# Skip the prompt non-interactively.
peel /tmp/dataset.tar.zst -o ./out/ -y

# Preserve the source archive (non-destructive). The same `-k`
# flag the HTTP path uses; in local mode it always means "keep
# the existing file untouched."
peel /tmp/dataset.tar.zst -o ./out/ -k
```

| Flag | Local-mode behaviour |
| --- | --- |
| (default, TTY) | destructive — prompt for confirmation, hole-punch the source, delete on completion |
| (default, non-TTY) | hard error at parse time; pass `-y` or `-k` |
| `-y` / `--yes` | bypass the prompt; destructive mode proceeds |
| `-k` / `--keep-archive` | preserve the source archive; no punching, no deletion |
| `--format <NAME>` | force a decoder (same semantics as HTTP mode) |
| `--workdir <DIR>` | place the `.peel.ckpt` sidecar here instead of next to the source |
| `--io-backend ...` | selects the puncher implementation (`auto` / `blocking` / `mmap`) |
| `--punch-threshold` | minimum gap between in-loop punch syscalls in destructive mode |

Resume-after-crash is supported in destructive mode: peel writes
a `.peel.ckpt` next to the source after each quiescent decoder
boundary, and a `kill -9` mid-run followed by a re-invocation
with the same arguments converges to the same final output tree
as a clean single run. `-k` runs are one-pass — no `.peel.ckpt`
is written, and a kill mid-run just means re-run from scratch
against the still-intact source.

A few HTTP-only flags are rejected at parse time in local mode
(`--mirror`, `--sha256`, `--workers`, `--chunk-size`,
`--no-adaptive-chunk-size`, `--max-bandwidth`, `--max-disk-buffer`,
`--http-version`, `--no-extract`, `--strict-format`). ZIP / RAR /
7z local-file extraction is not yet supported in this release —
the per-format pipelines are tightly coupled to the HTTP-side
sparse reader today; use the HTTP path or extract those archives
with their native tools until the local entry points land. Every
streaming format (`.tar.zst`, `.tar.xz`, `.tar.lz4`, `.tar.gz`,
raw `.zst` / `.xz` / `.lz4` / `.gz`, plain uncompressed `.tar`)
works through the local pipeline today.

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
| `.rar` (RAR5) | per-entry⁵ | per entry + intra-entry⁶ | ✓ |
| `.rar` (RAR3/RAR4 legacy) | per-entry⁷ | per entry + intra-entry⁷ | ✓ |

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
⁵ RAR5 walks file headers in stream order (no tail-anchored index
like zip / 7z), so peel streams entries to their final paths as
each entry's data area arrives. STORED method plus the standard
RAR5 algorithm (compression methods 1..5) both ship via the
hand-rolled `decode::rar_native` LZSS + RAR-VM filter pipeline
per `docs/PLAN_rar5_decoder.md`. Non-encrypted, single-volume
only; SFX, AES, and the rarely-used RAR-VM custom-filter slot
(`O.RAR.CUSTOMFILTER`) are queued.
⁶ Mid-entry resume via the §F1 checkpoint blob: a `kill -9` mid-RAR5
file restarts the in-flight entry from the snapshot, not from its
start. Multi-block lookahead state is captured in the blob so resume
is byte-identical.
⁷ Legacy RAR3/RAR4 uses the hand-rolled `decode::rar_legacy` LZ
pipeline plus the RarVM standard-filter dispatcher (E8, E8E9, Delta,
RGB, Audio) per `docs/PLAN_rar3.md`. STORED + LZ Normal (`-m3`) in
round one; the mid-entry checkpoint blob (`PLAN_rar3.md` §F1)
captures the LZ dictionary state and filter program cache so
resume is byte-identical. PPMd-II and other filters are queued.

## RAR provenance

`peel`'s RAR3 and RAR5 decoders are clean-room implementations.
RARLAB's `unrar` source has not been consulted at any point.
`libarchive`'s RAR readers (LGPL-2.1, OSI-licensed) are referenced
as an external spec where the RAR wire format requires one — read,
not vendored or linked.

Test fixtures are produced with a license-purchased copy of
RARLAB's `rar` encoder. The `unrar` binary is not linked,
vendored, or used as an implementation reference; it appears in
the RAR benchmark grid as a third-party point of comparison only.

`peel` is licensed `MIT OR Apache-2.0`. The unRAR license is
non-OSI and GPL-incompatible, so a clean-room derivation is the
only way to ship a RAR decoder without inheriting that constraint.
All future RAR work in this repo must continue the same practice —
see [`AGENTS.md`](AGENTS.md).

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
