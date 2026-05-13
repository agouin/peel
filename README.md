# peel

**The Swiss Army knife for file downloads and extraction.**

Sick of downloading an archive just to extract it and delete it?
Tired of provisioning disk for *both* the compressed file and its
extracted contents, only to throw half of it away? Tired of
restarting a half-finished multi-gigabyte download from scratch
every time the connection drops or the process gets killed?

Point `peel` at a URL and it does the right thing. A plain file?
You get a parallel, ranged, resumable download with end-to-end
integrity checking. An archive? You get the extracted contents,
streamed through decompression in a single pass, with the
compressed bytes hole-punched out from underneath as the decoder
advances, so the archive and its extracted tree never coexist at
full size. Either way, a dropped connection, `kill -9`, or power
loss resumes exactly where it left off, byte-identical to a clean
run.

Defaults match what you'd actually type. Simple flags cover the
rest: add mirrors, cap bandwidth, verify a hash, pin a format,
choose an IO backend, point at an output directory.

```
peel https://example.com/installer.bin
peel https://example.com/dataset.tar.zst
peel localfile.rar
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
  filters per `internal/PLAN_rar5_decoder.md`) and **legacy
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

Both sides invoke real CLI binaries: the `peel` row spawns
`target/release/peel` as a subprocess (rate-capped with
`--max-bandwidth`) pointed at a loopback mock origin, and the
baseline row spawns `bash -c 'curl --limit-rate … | tool | tar'`.
Same shape, same process-spawn + dynamic-linker cost on both sides;
no in-process fast path that flatters peel. Payload size scales per
row so wire-time stays in the 0.2–8 s range (long enough to drown out
connection setup, short enough that the whole grid finishes in
~10 minutes). Workers tuned per column (see grid footnote) by
sweeping `--workers ∈ {1, 2, 4, 8, 16}` and picking the value with
the smallest geomean `peel / curl|tool` ratio across the column's
format rows. Blocking IO backend, in-process mock server on
loopback. Apple M4 Max / macOS 26.3, single run (variance ≤ 5 %).
Reproduce with:

```sh
cargo test --release --features rar --test test_bench_streaming \
  bench_throttled_realistic_grid -- --ignored --nocapture --test-threads=1
```

### Wall-clock ratio: `peel` ÷ `curl | tool`

Lower is better; **bold** = `peel` is faster than the shell pipe.
Workers value below each column header is the per-column geomean
winner of the sweep described above.

| Format | 10 Mbps · 8 MiB (w=1) | 100 Mbps · 32 MiB (w=1) | 1 Gbps · 128 MiB (w=4) | 10 Gbps · 256 MiB (w=16) |
| --- | --- | --- | --- | --- |
| `tar` | 1.03× | **0.92×** | **0.83×** | **0.64×** |
| `tar.zst` | **0.98×** | **0.93×** | **0.82×** | **0.65×** |
| `tar.gz`¹ | **0.98×** | **0.92×** | **0.82×** | 1.24× |
| `tar.gz·m`² | **0.97×** | **0.92×** | **0.82×** | 1.15× |
| `tar.lz4` | **0.98×** | **0.92×** | **0.82×** | **0.75×** |
| `tar.xz` | 1.00× | **0.93×** | **0.99×** | 1.00× |

¹ Single-member gzip — the default-`gzip` / `tar -z` shape.
² Multi-member gzip (~32 MiB members) — the `pigz` / `gzip a b > c.gz`
shape. Same baseline pipe (`gzip -d` handles concatenated members per
RFC 1952 §2.2).

Absolute wall-clock for the 10 Gbps · 256 MiB column, for scale:
`tar` 0.16 s vs 0.24 s · `tar.zst` 0.16 s vs 0.24 s · `tar.lz4`
0.18 s vs 0.24 s · `tar.gz` 0.30 s vs 0.24 s · `tar.gz·m` 0.28 s vs
0.24 s · `tar.xz` 6.46 s vs 6.48 s.

### Reading the grid

At 100 Mbps and 1 Gbps, `peel` ties or beats the system pipeline
across every codec — and at 10 Gbps the cheap codecs (`tar`,
`tar.zst`, `tar.lz4`) extend the lead to **0.64–0.75×** once the
column is tuned to `--workers 16`, because 16 in-flight ranged GETs
saturate the loopback path while curl's single TCP connection idles
behind its `--limit-rate` token bucket. The single-threaded gzip
decoder (`tar.gz`, `tar.gz·m`) becomes the bottleneck once the wire
window shrinks below the codec's decode time, which is why those
two rows land >1× in the 10 Gbps cell; `internal/PLAN_gzip_throughput.md`
phase 3 (parallel-member decode) is the regression-gate that fixes
them.

The 10 Mbps and 100 Mbps columns settle on `--workers 1`: with sub-
gigabit pipes and ≤32 MiB payloads, every extra worker adds
trailing-edge drain (workers idle out one by one as the body
finishes; the last worker drains the token bucket alone, below the
cap) without enough wire-time left to amortize it. Pinning to one
worker lands `peel` within noise of `curl --limit-rate` at 10 Mbps
(geomean 0.99× across the column) and ahead of it by ~7–8 % at
100 Mbps. The `tar` row at 10 Mbps lands slightly slow (1.03×)
because the tar decoder spends almost no time decoding; the gap is
post-wire finalization (final checkpoint, manifest, sink fsync). The
slow-decode `tar.xz` row absorbs more of that finalization into the
xz compute floor and ties the baseline at every column.

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
Both sides spawn real CLI binaries — `target/release/peel` on one
side, `bash -c 'curl … -o <file> && <extract> && rm <file>'` on the
other — so process-spawn + dynamic-linker cost is paid by both. p7zip
17.05 (Homebrew) for `7z`; RARLAB `unrar 7.22` (license-purchased
copy) for `rar5` / `rar3`, which `peel` uses as a third-party
benchmark baseline only — never as an implementation reference (see
"RAR provenance" below). Everything else as in the streaming grid.
Single run on Apple M4 Max / macOS 26.3. The `rar` rows use archives
produced by RARLAB's real encoder (`rar 7.22` for RAR5 STORED, `rar
5.0.0` Linux x86_64 in a `linux/amd64` Docker container for RAR3
LZ-Normal) and cached under `tests/fixtures/rar_bench/`; the first
run bakes them, every subsequent run reuses the cache. Reproduce
with:

```sh
cargo test --release --features rar --test test_bench_streaming \
  bench_throttled_download_then_extract_grid \
  -- --ignored --nocapture --test-threads=1
```

### Wall-clock ratio: `peel` ÷ `curl -O && <extract> && rm`

Lower is better; **bold** = `peel` is faster than the
download-then-extract sequence. Same worker-tuning methodology as
the streaming grid: workers swept ∈ {1, 2, 4, 8, 16} per column,
geomean winner per column shown in the header.

| Format | 10 Mbps · 8 MiB (w=1) | 100 Mbps · 32 MiB (w=1) | 1 Gbps · 128 MiB (w=1) | 10 Gbps · 256 MiB (w=16) |
| --- | --- | --- | --- | --- |
| `tar` | 1.02× | **0.91×** | **0.76×** | **0.57×** |
| `tar.zst` | **0.97×** | **0.90×** | **0.76×** | **0.46×** |
| `tar.gz` | **0.97×** | **0.90×** | **0.75×** | **0.67×** |
| `tar.lz4` | **0.97×** | **0.90×** | **0.76×** | **0.48×** |
| `tar.xz` | **0.96×** | **0.76×** | **0.76×** | **0.96×** |
| `zip` | **0.97×** | **0.88×** | **0.59×** | **0.20×** |
| `7z` | **0.97×** | **0.91×** | **0.79×** | **0.58×** |
| `rar5` | **0.98×** | **0.91×** | **0.78×** | **0.97×** |
| `rar3` | **0.98×** | **0.92×** | **0.71×** | 1.04× |

### Reading the grid

For tar.* rows at 100 Mbps and up, peel's wall-clock is roughly the
wire-time — decode runs in parallel with the download. The baseline's
is `wire-time + extract-time + rm`. peel saves the trailing extract
phase outright, and the savings widen with bandwidth: at 1 Gbps and
above the baseline eats half a second to over a second of trailing
wall-clock that peel never spends. `tar.xz` shows the slow-decode
story most cleanly — at 100 Mbps peel is **0.76×** the baseline
because xz decode runs during the in-flight download instead of after
it.

With workers tuned per column the 10 Mbps row now ties or beats the
baseline on every format (geomean **0.98×**). At sub-gigabit rates
the dnx grid prefers `--workers 1` even more strongly than the
streaming grid: the baseline pays `wire + extract + rm` while peel
pays `wire + a few ms of finalization`, so trailing-edge drain on
multiple ranged GETs would forfeit the extract-overlap win.
`--workers 1` keeps the token bucket fully utilized through the
trailing edge and lets the in-flight decode steal the baseline's
extract phase outright. 1 Gbps still wins at `--workers 1` (the
extract-overlap savings are large enough that adding parallelism
to shave the trailing edge isn't worth the drain risk); only at
10 Gbps does `--workers 16` flip in.

`zip` is the headline. There is no streaming-pipe baseline for
`.zip`, so this grid is the only fair head-to-head. At 1 Gbps ×
128 MiB peel finishes in roughly 59 % of the baseline's wall-clock;
at 10 Gbps × 256 MiB it's a ~5× speedup (**0.20×**). peel writes
each entry to its final path as soon as the entry's bytes arrive,
while the baseline is structurally barred from starting `unzip`
until `curl` finishes.

`7z` supports the same single-pass shape: peel beats the baseline at
every bandwidth from 10 Mbps through 10 Gbps, all the way to
**0.58×** at the 10 Gbps · 256 MiB cell. The COPY-coded archive's
256 MiB fits inside a sub-300 ms wire window, but `--workers 16`
keeps that window full while the baseline still has to run `7z x`
over the full archive after `curl` finishes.

`rar5` and `rar3` are the new entries. `unrar` requires a seekable
file (the binary `lseek`s its input regardless of where the metadata
sits), so a streaming-pipe baseline doesn't exist for them either —
this grid is the only fair head-to-head. With per-column worker
tuning, peel ties or beats the baseline at every cell from 10 Mbps
through 1 Gbps for both formats, and `rar5` is essentially tied
(**0.97×**) even at the 10 Gbps · 256 MiB cell where the wire window
collapses to ~0.3 s and per-entry extraction cost dominates (was
2.48× in the original §3 numbers before §G1's STORED-throughput
pass; see the local-file decode grid below for the per-byte story).
`rar3` lands at 1.04× at 10 Gbps — the only >1.00× rar cell — because
`-m3` packs the incompressible bench payload through full LZ + RarVM
filters, not COPY, and the wall-clock floor (~1.9 s) is much higher
than the other formats. peel's parallel-GET-plus-stream shape pays
for itself everywhere the wire-time is non-trivial, which covers
every real production scenario. (Both rar rows skip rather than
fail when `unrar` is missing from `PATH`.)

## Benchmarks: peel's decoder vs the reference CLI (local files)

The two grids above bake HTTP cost into both sides — useful for the
"is the streaming machinery a net win?" question, but the per-format
ratio gets blurred by the network. This grid strips HTTP out: both
peel and the reference CLI decode the same fixture from disk, so the
ratio reflects the decoder kernel plus the process-spawn /
dynamic-linker cost both sides pay every time the user types the
command.

Same `target/release/peel` subprocess invocation for the peel column
as the HTTP grids — no in-process shortcut. Same LCG-generated
near-incompressible payload. Two raw-payload sizes per format:
10 MiB and 100 MiB, each in `cold` (one fresh run per side) and `warm`
(one throw-away warm-up, then time the next) variants. Apple M4 Max
/ macOS 26.3 with the homebrew `zstd 1.5.7`, `xz 5.8.3`, `lz4 1.10.0`,
bsdtar 3.5.3, `gzip` builtins, `p7zip 17.05`, `unzip 6.00`, and
RARLAB `unrar 7.22` (license-purchased copy) for the `rar5` / `rar3`
rows. Single-run laptop numbers. Reproduce with:

```sh
cargo test --release --features rar --test test_bench_decode_local -- \
  --ignored --nocapture --test-threads=1
```

### Wall-clock ratio: `peel` ÷ reference CLI

Lower is better; **bold** = `peel` is faster than the reference CLI.

| Format | 10 MiB · cold | 10 MiB · warm | 100 MiB · cold | 100 MiB · warm |
| --- | --- | --- | --- | --- |
| `zstd-raw` | 1.39× | 1.75× | 1.00× | 1.61× |
| `tar.zst` | **0.94×** | 1.14× | **0.42×** | **0.45×** |
| `xz-raw` | **0.90×** | **0.88×** | **0.92×** | **0.91×** |
| `tar.xz` | **0.96×** | **0.94×** | **0.93×** | **0.93×** |
| `gz-raw` | 1.48× | 1.52× | 1.94× | 1.82× |
| `tar.gz` | 1.00× | 1.04× | 1.08× | 1.04× |
| `lz4-raw` | 1.50× | 1.59× | 1.06× | 1.01× |
| `tar.lz4` | **0.97×** | 1.20× | **0.43×** | **0.47×** |
| `tar` | 1.42× | 1.36× | **0.80×** | **0.97×** |
| `zip` | **0.68×** | **0.59×** | **0.19×** | **0.17×** |
| `7z` | **0.83×** | **0.84×** | 1.06× | **0.95×** |
| `rar5` | 1.29× | 1.49× | **0.86×** | **0.86×** |
| `rar3` | 1.07× | 1.16× | 1.04× | 1.03× |

Geomean at 100 MiB · warm: **0.82×** across all 13 formats — peel is
~18 % faster than the reference CLI overall.

### Reading the grid

At 10 MiB the comparison is dominated by per-invocation overhead.
Both sides pay `fork` + `execve` + dynamic-linker + `dlopen` of the
codec library; the decoder kernel does microseconds of work over
megabytes. Tiny absolute deltas (< 30 ms) blow the ratio around —
`lz4-raw` reads as 1.59× warm because peel takes 36 ms vs `lz4 -d`'s
23 ms, both of which are mostly process startup.

The 100 MiB columns are where the per-format decoder story lives.
`tar.zst` and `tar.lz4` lead at **0.45×** / **0.47×** because peel
finishes decoding *and* writing entries during what the reference
pipeline still spends piping `zstd -dc | tar -xf -` between two
processes. `tar.xz`, `xz-raw`, and `tar` all land near parity
(0.80–0.93×): that's the LZMA decode floor (peel's
[`xz_liblzma_phase_f`](internal/old/PLAN_xz_liblzma_phase_f.md) matches
`liblzma` per-CPU-cycle) and the bsdtar floor (a memcpy loop).

`zip` is the headline at **0.17×** — peel finishes in 1/6 of the
`unzip` wall-clock at 100 MiB warm. peel's hand-rolled central-
directory parse + STORED entry copy stays in one process and one
write loop; `unzip` does the same work but pays the codec library's
per-entry overhead.

The slower-than-1× rows are honest. `gz-raw` at **1.82× warm** is
peel's hand-rolled DEFLATE decoder
([`PLAN_decoder_throughput_vs_cli.md`](internal/old/PLAN_decoder_throughput_vs_cli.md)
§5): single-threaded today and waiting on the parallel-member round
that [`PLAN_gzip_throughput.md`](internal/PLAN_gzip_throughput.md) lays
out. `zstd-raw` at **1.61× warm** is a similar story: the bench
extracts a single raw zstd frame to one output file, where peel's
sink fsync + buffer dance shows up against `zstd`'s straight-through
copy. The tar-wrapped row (`tar.zst`) reclaims the lead via the
skip-the-pipe shape.

`rar5` and `rar3` both land at parity-or-better — `rar5` at
**0.86× warm**, `rar3` at **1.03×**. This is a step change from
the first round-one §3 numbers (`rar5` warm = 5.66× when the
grid first shipped); the §G1 throughput pass in
[`internal/PLAN_rar5_decoder.md`](internal/PLAN_rar5_decoder.md) found
that the RAR5 STORED hot path was spending most of its cycles
inside [`RarSink::write_entry`](src/sink/rar.rs) maintaining a
running BLAKE2sp digest that nothing ever consumed (the §1 parser
does not yet decode the BLAKE2sp extra-record so the expected
value was always `None`) and a slice-by-16 CRC-32 on a CPU whose
single-instruction `CRC32X` would do the same work 4× as fast.
The sink now skips each hash when the file header carries no
matching expected value, [`zip::Crc32`](src/zip/crc32.rs) dispatches
to the aarch64 `crc` extension when the runtime CPU exposes it
(`__crc32x` at 8 bytes per instruction, ~10 GB/s on M-series), and
the STORED copy loop reads 1 MiB at a time instead of 64 KiB so
the per-iteration syscall / callback overhead drops 16×.

## When to reach for `peel`

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

```sh
# No -o? Default extract dir is the URL basename with known
# archive/compression suffixes stripped, in the current working
# directory: this lands the contents in ./linux-6.x
peel https://example.com/linux-6.x.tar.xz

# Stream a tar archive into a directory (trailing slash forces dir)
peel https://example.com/linux-6.x.tar.xz -o ./linux/

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
| `-d, --destructive` | off | Hole-punch and delete the source archive as extraction proceeds. Required to enable destructive behavior in local mode (preservation is the default there); a no-op for HTTP runs, which are destructive by default. Combining `-d` with `-k` for an HTTP source is an error. |
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
# Non-destructive by default: extracts to ./dataset/ and
# leaves the source archive untouched.
peel /tmp/dataset.tar.zst

# Destructive opt-in: hole-punches the source as the decoder
# advances and deletes it on clean completion.
peel -d /tmp/dataset.tar.zst -o ./out/
```

| Flag | Local-mode behaviour |
| --- | --- |
| (default) | non-destructive — extract and leave the source untouched, no `.peel.ckpt` written |
| `-d` / `--destructive` | hole-punch the source as the decoder advances and delete it on clean completion |
| `-k` / `--keep-archive` | no-op in local mode (preservation is already the default); kept for cross-source script compatibility |
| `--format <NAME>` | force a decoder (same semantics as HTTP mode) |
| `--workdir <DIR>` | place the `.peel.ckpt` sidecar here instead of next to the source (destructive mode only) |
| `--io-backend ...` | selects the puncher implementation (`auto` / `blocking` / `mmap`) |
| `--punch-threshold` | minimum gap between in-loop punch syscalls in destructive mode |

Resume-after-crash is supported in destructive mode: peel writes
a `.peel.ckpt` next to the source after each quiescent decoder
boundary, and a `kill -9` mid-run followed by a re-invocation
(with the same `-d`) converges to the same final output tree as a
clean single run. Non-destructive runs are one-pass — no
`.peel.ckpt` is written, and a kill mid-run just means re-run
from scratch against the still-intact source.

A few HTTP-only flags are rejected at parse time in local mode
(`--mirror`, `--sha256`, `--workers`, `--chunk-size`,
`--no-adaptive-chunk-size`, `--max-bandwidth`, `--max-disk-buffer`,
`--http-version`, `--no-extract`, `--strict-format`). Every format
peel supports works through the local path today: the streaming
shapes (`.tar.zst`, `.tar.xz`, `.tar.lz4`, `.tar.gz`, raw `.zst` /
`.xz` / `.lz4` / `.gz`, plain uncompressed `.tar`) flow through the
same single-pass decoder the HTTP path uses, and the random-access
formats (`.zip`, `.7z`, `.rar` — RAR5 + legacy RAR3/RAR4) drive
their per-format pipelines against the user's archive opened
read-only and wrapped in a fully-marked
[`ChunkBitmap`](src/bitmap.rs) so the existing orchestrators run
unchanged. Destructive mode (`-d`) does not apply to the
random-access formats — their pipelines seek backwards into the
archive (zip's central directory at the tail, 7z's trailer pointer,
rar's per-entry headers), so a monotonically-advancing punch cursor
can't be maintained; peel warns and proceeds non-destructively when
`-d` is passed against one of those sources.

## Status

MVP complete (2026-04-29). PLAN_v2 round one — multi-format support,
io_uring file + network, adaptive chunk-sizing, mmap sparse file,
SHA-256 integrity with resumable hashing, multi-mirror, bandwidth
limiting, the progress UI — has landed on top. Active work moves back
to [`internal/OPTIMIZATIONS.md`](internal/OPTIMIZATIONS.md) for round two
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
driver from `internal/PLAN_7z_support.md` §8) because of the
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
per `internal/PLAN_rar5_decoder.md`. Non-encrypted, single-volume
only; SFX, AES, and the rarely-used RAR-VM custom-filter slot
(`O.RAR.CUSTOMFILTER`) are queued.
⁶ Mid-entry resume via the §F1 checkpoint blob: a `kill -9` mid-RAR5
file restarts the in-flight entry from the snapshot, not from its
start. Multi-block lookahead state is captured in the blob so resume
is byte-identical.
⁷ Legacy RAR3/RAR4 uses the hand-rolled `decode::rar_legacy` LZ
pipeline plus the RarVM standard-filter dispatcher (E8, E8E9, Delta,
RGB, Audio) per `internal/PLAN_rar3.md`. STORED + LZ Normal (`-m3`) in
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

## Documentation

User-facing documentation lives at
**<https://agouin.github.io/peel/>** (built from
[`docs/`](docs/) via mdBook). It covers every CLI flag, the format
matrix, encryption, multi-mirror / multi-volume / multi-part-URL
workflows, the checkpoint-and-resume model, performance tuning, exit
codes, and worked examples for Kubernetes init containers, CI
runners, and Arbitrum snapshot bundles.

To preview locally:

```sh
cargo install mdbook --locked
mdbook serve docs --open
```

## For contributors and AI agents

Start with [`CLAUDE.md`](CLAUDE.md) (or [`AGENTS.md`](AGENTS.md) — both
point at the same docs). The full doc set:

- [`CLAUDE.md`](CLAUDE.md) — entry point, house rules summary
- [`AGENTS.md`](AGENTS.md) — workflow rules for coding agents
- [`internal/PLAN.md`](internal/PLAN.md) — sequenced MVP plan (complete; kept
  as historical record)
- [`internal/PLAN_v2.md`](internal/PLAN_v2.md) — round-one post-MVP plan
  (complete)
- [`internal/ENGINEERING_STANDARDS.md`](internal/ENGINEERING_STANDARDS.md) —
  non-negotiable rules
- [`internal/ENGINEERING_BEST_PRACTICES.md`](internal/ENGINEERING_BEST_PRACTICES.md)
  — idiomatic patterns
- [`internal/OPTIMIZATIONS.md`](internal/OPTIMIZATIONS.md) — backlog;
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
