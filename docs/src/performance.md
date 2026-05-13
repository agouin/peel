# Performance and tuning

`peel`'s defaults target a laptop-class machine on a healthy network and
land within ~6% of the system tools across the
[bench grid in the project README](https://github.com/agouin/peel#benchmarks-peels-decoder-vs-the-reference-cli-local-files).
Outside that envelope (extremely high bandwidth, severe memory pressure,
picky filesystems, locked-down kernels), the following knobs matter.

## File-IO backend

### `--io-backend <auto|blocking|uring|mmap>`

The part-file is written from many workers concurrently, then read
linearly by the decoder, then hole-punched. Three backends implement
this differently:

| Backend | Workers write via | Puncher | Sockets |
| --- | --- | --- | --- |
| `blocking` | `pwrite(2)` | `fallocate(PUNCH_HOLE)` / `F_PUNCHHOLE` | Blocking BSD sockets |
| `mmap` (Linux only) | `memcpy` into `MAP_SHARED` | `madvise(MADV_REMOVE)` | Blocking BSD sockets |
| `uring` (Linux only) | `pwrite` SQE on the ring | `fallocate(PUNCH_HOLE)` SQE | TCP `connect` / `send` / `recv` on the ring |
| `auto` (default) | Probes each at startup | | |

#### What `auto` picks

On Linux, `auto` selects:

- **`mmap` for the part-file** if the filesystem supports
  `MADV_REMOVE` (probed at startup with a small test mapping). All
  major Linux filesystems do. The probe fails on some unusual mounts
  (for example, `tmpfs` does not accept `MADV_REMOVE` and falls back
  cleanly).
- **`io_uring` for the HTTP client's sockets** if `io_uring_setup`
  succeeds. Falls back to blocking sockets with one `info!` log if
  the kernel rejects ring construction (kernel < 5.6, seccomp
  blocking such as cri-o's default profile under Kubernetes, or
  `RLIMIT_MEMLOCK` too low).

On non-Linux platforms (macOS, BSD), `auto` selects the blocking
backend for both sockets and file IO. No `io_uring` equivalent exists.
Mmap with hole-punching works but does not beat the blocking path by
enough to default to it.

#### When to override

- **A/B benchmarking.** `--io-backend blocking` forces the pre-`io_uring`
  path everywhere. Useful for measuring the speedup the fast paths
  contribute on a given network.
- **Hard requirement on `io_uring`.** `--io-backend uring` errors out
  if the kernel cannot construct a ring. Suitable for CI verification
  that the fast path is actually in use.
- **Hard requirement on `mmap`.** `--io-backend mmap` selects the
  mmap part-file path explicitly with the blocking socket backend.
  Same memcpy-into-the-mapping shape, but no `io_uring` for sockets.

#### Confirming what got selected

```sh
RUST_LOG=info peel <URL> -o ./out/ 2>&1 | grep 'selected'
# selected file IO backend = mmap
# selected socket backend = io_uring
```

## HTTP version

### `--http-version <auto|h1|h2>`

| Value | Behaviour |
| --- | --- |
| `auto` (default) | ALPN-negotiate H1 / H2 over TLS; H1 over plaintext |
| `h1` | Force HTTP/1.1 |
| `h2` | Force HTTP/2 (prior-knowledge `h2c` over plaintext) |

#### When to override

- **Suspected H2 misbehaviour.** Some origins (and some middleboxes,
  typically corporate proxies) handle ranged GETs better on H1 than on
  H2. Force `--http-version h1` to test.
- **Origin only speaks `h2c`.** Plaintext H2 does not ALPN-negotiate
  and must be selected explicitly.
- **Origin negotiation fails.** TLS handshakes that succeed but
  negotiate something `peel` cannot use surface as a clear error with
  the negotiated protocol name.

## Bandwidth and disk caps

### `--max-bandwidth <RATE>`

Aggregate token-bucket cap across **all workers and mirrors**.
Accepts decimal (`K`, `M`, `G`, `T`, 1000-based) or binary (`Ki`, `Mi`,
`Gi`, `Ti`) suffixes. Trailing `B` and `/s` are accepted and ignored.

```sh
peel <URL> --max-bandwidth 50MB/s   -o ./out/    # 50 megabytes/s, decimal
peel <URL> --max-bandwidth 512MiB/s -o ./out/    # 512 mebibytes/s, binary
peel <URL> --max-bandwidth 1000000  -o ./out/    # 1 million bytes/s
```

The cap is **aggregate**, not per-mirror: `--max-bandwidth 50MB/s`
with three mirrors caps the total at 50 MB/s, not 150 MB/s.

When to use it:

- Polite scraping of a public mirror.
- Co-tenant workloads where `peel` must not saturate the pipe.
- Reproducible benchmarks needing a deterministic wire-time floor.

### `--max-disk-buffer <SIZE>`

Cap on the **on-disk lookahead**: bytes downloaded but not yet
consumed by the decoder. When the gap reaches this value, the
scheduler stops dispatching new chunks until the decoder catches up.

```sh
peel <URL> --max-disk-buffer 256MiB -o ./out/    # tighter cap for memory-constrained env
peel <URL> --max-disk-buffer none   -o ./out/    # disable
```

Default `1GiB`. The default rarely engages on a healthy disk and
bounds the part-file's physical size on a slow one.

When to lower it:

- Containers with a hard ephemeral-disk quota (Kubernetes pods with
  small `emptyDir`, CI runners with capped tmpfs).
- A network much faster than the disk (10 Gbps NIC and a spinning
  disk output target) where the part-file must not balloon before
  the decoder catches up.

When to raise it (or disable):

- Decoder is the bottleneck and network bursts should be absorbed
  fully into the buffer.
- Very fast disk with a slow or bursty network where pre-buffering
  wins.

## Worker count

### `--workers <N>`

Default `4`. The scheduler will not dispatch more than this many
concurrent ranged GETs against the primary or any mirror.

Tuning matrix:

| Symptom | Direction |
| --- | --- |
| Wire under-utilised, origin far away (high RTT) | **Raise**: more workers in flight overlap the RTT |
| Origin returns 429 / 503 under load | **Lower**: back off the per-origin parallelism |
| Per-worker throughput collapses with more workers | **Lower**: local CPU or NIC is the bottleneck |
| Memory pressure from many in-flight buffers | **Lower**: each worker holds its in-flight chunk |

The default `4` suits a laptop-class machine on a healthy network. On
a high-spec server pulling from a far CDN, 8–16 is often faster. On a
constrained client, 2 can win.

## Chunk-size tuning

### `--chunk-size <BYTES>` + `--no-adaptive-chunk-size`

The **bitmap chunk size** is the unit of completion tracked in
checkpoints (default 4 MiB). It is also the smallest possible ranged
GET.

With **adaptive sizing** (the default), the scheduler watches
per-GET latency and retry rate and may **coalesce** several
consecutive bitmap chunks into a single ranged GET:

- 1 MiB floor, 64 MiB cap.
- 30 s hysteresis: the scheduler waits before reacting to transient
  changes.
- Bitmap unit and dispatch unit are **decoupled**. Checkpoints stay
  fine-grained while the wire-level request size scales with the
  network.

Pass `--no-adaptive-chunk-size` to lock dispatch to the bitmap unit.
The scheduler then dispatches exactly one bitmap chunk per worker
task, with no growth or shrink decisions over the lifetime of the
run. Useful for **benchmarking** and **reproducible test runs**.

## Puncher and checkpoint cadence

### `--punch-threshold <BYTES>`

Minimum gap between in-loop hole-punch syscalls (default 4 MiB).

- **Smaller**: tighter physical-disk footprint, more syscalls.
- **Larger**: fewer syscalls, larger transient physical footprint.

Tune downward for a hard ceiling on physical disk usage. Tune upward
if the filesystem's punch-hole implementation is slow (some
network-attached storage backends have noticeable per-punch cost).

### `--checkpoint-min-bytes` / `--checkpoint-min-secs` / `--checkpoint-target-secs`

See [Checkpoint and resume](./checkpoint-resume.md#tuning-checkpoint-cadence)
for the full discussion of these.

Defaults: 8 MiB, 2 s, 0.2 s target. Raise the `min-bytes` floor when
the filesystem has slow `fsync` and it dominates wall-clock. Lower it
for tighter resume granularity on very long runs.

## Workdir placement

### `--workdir <DIR>`

Place the `.peel.part` and `.peel.ckpt` sidecars in a separate
directory from the output.

Use cases:

- **Slow output disk, fast scratch disk.** Extract onto slow
  HDD-backed `/data`, keep the in-flight part-file on fast NVMe at
  `/var/cache/peel`:

  ```sh
  peel <URL> -o /data/out/ --workdir /var/cache/peel/
  ```

- **Persistent Kubernetes PVC, ephemeral container scratch.** Output
  goes onto the PVC mount, sidecars onto the container's ephemeral
  scratch. Resume across pod restarts uses the PVC's data and the
  ephemeral checkpoint as a fast-path optimisation. After a pod
  restart, delete the ephemeral checkpoint and `peel` re-derives
  state from the part-file's bytes.

- **Read-only output filesystem.** Output is a read-only mount where
  only the extracted contents are needed. Sidecars go to a writable
  scratch dir.

The directory is created if missing. Basenames stay the same
(`<output_name>.peel.part`, `<output_name>.peel.ckpt`). Only the
parent directory changes.

## Progress and logging

`peel` emits a live three-line block on a TTY:

```text
download: 412.3 MiB / 1.2 GiB (33.7%) @ 187 MB/s  (4 workers, 312 MiB on disk)
extract : 387.1 MiB / 1.2 GiB (31.8%) @ 178 MB/s
eta     : 4.6s
```

On a **non-TTY** (CI logs, redirected output), the progress UI falls
back to periodic `tracing::info!` lines. No extra flag is needed.

`RUST_LOG=<level>` controls verbosity:

- `RUST_LOG=warn`: only warnings and errors. The default when
  `RUST_LOG` is unset is `info`.
- `RUST_LOG=info`: startup banners (selected backend, discovered
  volumes, mirror probes, checkpoint cadence summaries).
- `RUST_LOG=debug`: per-chunk dispatch, per-checkpoint writes,
  per-mirror selection decisions.

```sh
RUST_LOG=debug peel <URL> -o ./out/ 2>peel-debug.log
```

## A typical tuning workflow

1. Run with defaults. Inspect the progress UI's download rate and
   "on disk" footprint.
2. If the download rate is **far below** what the network should
   support, raise `--workers` (try 8, then 16).
3. If the rate is fine but the **physical disk footprint** is
   uncomfortable, lower `--max-disk-buffer` and `--punch-threshold`.
4. If `fsync` dominates CPU on a slow disk, raise
   `--checkpoint-min-bytes` (try 64 MiB).
5. Fallback warnings from `--io-backend auto` are expected on most
   non-Linux or restricted-kernel hosts. Verify with `RUST_LOG=info`
   that the blocking backend is selected, then check throughput
   before concluding the fallback matters.
