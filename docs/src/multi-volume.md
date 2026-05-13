# Multi-volume archives

Some archive formats support **splitting one logical archive across
multiple physical files** with format-aware metadata in each volume.
`peel` recognises three multi-volume naming conventions and resolves
every sibling volume up front (one parallel `HEAD` per volume for
HTTP seeds).

Archives split at the HTTP layer (raw `.partNNNN` files that
concatenate into a logical archive) are handled by
[Multi-part URLs](./multi-part-urls.md) instead.

## Supported conventions

| Format | Pattern | Example |
| --- | --- | --- |
| **RAR5** | `<base>.part<N>.rar` | `backup.part0001.rar`, `backup.part0002.rar`, … |
| **7z** | `<base>.7z.<NNN>` | `snapshot.7z.001`, `snapshot.7z.002`, … |
| **ZIP (spanned)** | `<base>.z<NN>` + `<base>.zip` | `data.z01`, `data.z02`, …, `data.zip` |

For spanned ZIP, the `<base>.zip` final volume is mandatory: it
contains the End-of-Central-Directory record. The `.zNN` files hold
the entry data.

## Three ways to invoke

### 1. Single seed with auto-discovery (default)

Pass any volume whose basename matches a recognised pattern and
`peel` discovers the full ordered set:

```sh
peel https://host/backup.part0001.rar -o ./out/
peel https://host/snapshot.7z.001 -o ./out/
peel ./data.z01 -o ./out/                          # local works too
```

At startup, `peel`:

1. Recognises the pattern from the basename.
2. Probes the origin for siblings via `HEAD` against
   `backup.part0002.rar`, `backup.part0003.rar`, and so on, until
   two consecutive HEADs return 404.
3. Reports the resolved volume count in the progress UI.
4. Routes downloads through the multi-volume storage path.

Discovery is **parallel**: every probe runs concurrently against the
origin, so resolution costs one round-trip of wall-clock time
regardless of the volume count.

### 2. Explicit positional list

Pass every volume URL as a positional argument. Useful when
auto-discovery does not fit (volumes hosted on different origins, or
numbering that is not contiguous from `0001`):

```sh
peel \
  https://host/backup.part0001.rar \
  https://host/backup.part0002.rar \
  https://host/backup.part0003.rar \
  -o ./out/
```

The volume basenames must form a **contiguous numeric sequence**;
out-of-order or non-contiguous entries (`part0001`, `part0003`) are
rejected at parse time with a specific error.

### 3. Manifest file

Pass `@file.txt` (one URL or path per line; blank lines and `#`
comments ignored):

```text
# volumes.txt
https://host/backup.part0001.rar
https://host/backup.part0002.rar
https://host/backup.part0003.rar
```

```sh
peel @volumes.txt -o ./out/
```

Useful when the volume list is long or generated programmatically.

## Disabling auto-discovery

`--no-auto-discover` forces single-source semantics on a seed whose
basename happens to match a multi-volume pattern:

```sh
# Just download the one .zip file, don't probe for .z01 siblings.
peel https://host/data.zip --no-extract --no-auto-discover
```

When to use it:

- The seed's filename matches one of the conventions but is **not**
  actually a multi-volume archive (for example, an unrelated `.zip`
  file that should not be HEAD-probed for `.z01` siblings).
- Discovery would fan out to many failed HEAD probes against a
  high-latency origin and the seed is known to be a single source.

The flag has no effect when multiple positional URLs are supplied:
that path already opts out of auto-discovery.

## How it interacts with the streaming pipeline

A multi-volume archive is internally a single logical archive: the
[scheduler](./how-it-works.md), the bitmap, the checkpoint, and the
decoder all see one contiguous source. Each volume contributes its
bytes to the byte-concatenated logical stream.

That means:

- **Resume** works across volumes. A `kill -9` while volume 7 of 12
  is in flight is safe: the next run picks up exactly where the
  decoder was.
- **Hole-punching** applies to each volume's `.peel.part` shard as
  the decoder advances past it. The compressed-side disk footprint
  stays bounded the same way as a single-URL run.
- **Mirror fan-out** (`--mirror`) is currently single-URL only.
  Multi-volume archives are fetched from their primary URLs. Mirror
  support across the volume set is a planned addition.
- **`--sha256`** is single-hash-per-URL on multi-URL runs, so a
  multi-volume archive expects a hash per volume.

## Listing the resolved volumes

Run with `RUST_LOG=info` to see the discovered set before any
downloads start:

```sh
RUST_LOG=info peel https://host/backup.part0001.rar -o ./out/ 2>&1 | head -20
```

Look for the `discovered N volumes` line and the per-volume sizes.

## Diagnostics

| Error | Cause | Fix |
| --- | --- | --- |
| `multi-volume volumes not contiguous` | Explicit list skips a number | Add the missing volume or renumber |
| `multi-volume probe returned mixed Content-Length` | Origin serving inconsistent volumes | Investigate origin; check for partial uploads |
| `spanned zip requires .zip final volume` | Passed `.z01..z09` without `.zip` | Add the `.zip` final volume to the list |
| `cannot mix multi-volume conventions` | `.part0001.rar` + `.7z.001` in one list | One archive per invocation |
