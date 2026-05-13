# Multi-mirror downloads

`peel` can fetch a single file from several origins in parallel,
biasing the work toward whichever mirror is fastest and excluding
mirrors that fail. The positional `URL` is the **primary**. Every
`--mirror <URL>` is an **alternate**.

## Usage

```sh
peel https://primary.example.com/dataset.tar.zst \
  --mirror https://eu.mirror.example.com/dataset.tar.zst \
  --mirror https://us.mirror.example.com/dataset.tar.zst \
  -o ./out/
```

`--mirror` is repeatable with no fixed upper bound. Returns diminish
once the mirror count exceeds the network's ability to keep more
than a few worker connections busy.

## Startup validation

Before any data download, `peel` runs a parallel `HEAD` against
**every** URL (primary and each mirror) and compares:

1. **`Content-Length`**: the byte size of the source must agree
   across all mirrors.
2. **`ETag` / `Last-Modified`**: if `--sha256` is unset, these serve
   as a secondary identity signal. Mismatched ETags indicate the
   mirrors are serving different files.
3. **`Accept-Ranges: bytes`**: required for the mirror to be useful.
   Mirrors without ranged-GET support are dropped with a warning.

Any mirror that fails these checks is excluded for the run. Surviving
mirrors are selected per ranged GET, biased toward the fastest live
mirror.

If the **primary** fails validation, the run aborts unless
`--sha256` is set. With the hash as the source of truth, `peel`
proceeds against the agreeing mirrors.

## Scheduler behaviour

For each pending ranged GET:

- The scheduler picks among healthy mirrors using a smoothed
  per-mirror throughput estimate.
- A mirror that fails a request (5xx, connection reset, timeout) is
  **excluded for 30 seconds** before being retried.
- The exclusion is logged at `warn!`. The retry is logged at `info!`.
- If **all** mirrors are excluded simultaneously, the scheduler
  back-pressures the workers until one returns.

A flapping mirror takes itself out of rotation rather than failing
the whole run, providing graceful degradation.

## Combining with other features

### With `--sha256`

When `--sha256` is set, the hash is the source of truth. `peel`
trusts agreeing mirrors even when their `Last-Modified` headers
disagree (CDN edge timing, mirror re-uploads). A wrong-hash mirror
fails validation later. A right-hash mirror is accepted even if its
metadata is slightly different.

```sh
peel https://primary.example.com/dataset.tar.zst \
  --mirror https://eu.mirror.example.com/dataset.tar.zst \
  --mirror https://us.mirror.example.com/dataset.tar.zst \
  --sha256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad \
  -o ./out/
```

### With `--max-bandwidth`

The cap is **aggregate** across all mirrors via a single token
bucket. `--max-bandwidth 50MB/s` against 3 mirrors caps the total at
50 MB/s, not 150 MB/s. This matches the intent when the cap exists
to be polite to the caller's network or to the mirrors collectively.

### With `--workers`

`--workers <N>` is the total in-flight request count across all
mirrors, not per-mirror. With 4 workers and 3 mirrors, ~4 concurrent
requests are in flight at any time, drawn from whichever mirrors are
fastest at the moment.

## What `--mirror` is not

- **Failover only.** `peel` does not sequentially try mirror 1, then
  mirror 2 on failure. It uses all of them in parallel by default.
- **A way to download from sharded URLs.** When the URLs serve
  different bytes (different parts of one logical file), use
  [Multi-part URLs](./multi-part-urls.md).
- **A way to download a multi-volume archive.** For
  `name.part0001.rar` + `name.part0002.rar` (each volume is its own
  file), use [Multi-volume archives](./multi-volume.md). `--mirror`
  applies only when **the same file** is reachable at multiple URLs.

## Diagnostics

| Log line | Meaning |
| --- | --- |
| `mirror https://… dropped at startup: Content-Length mismatch` | Mirror's reported size disagrees with the primary |
| `mirror https://… dropped: no Accept-Ranges: bytes` | Mirror does not support ranged GETs and cannot be used for parallel download |
| `mirror https://… excluded for 30s after status=502` | Transient failure; mirror will be retried |
| `all mirrors excluded; back-pressuring` | All sources are down simultaneously; the scheduler waits |
| `primary failed validation; using N agreeing mirror(s)` | The primary's size/etag didn't match; mirrors did. Requires `--sha256` |
