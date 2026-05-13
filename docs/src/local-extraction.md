# Local-file extraction

When passed a path on disk, `peel` skips the HTTP machinery entirely
(no scheduler, no mirrors, no chunk bitmap) and runs the same
decoder / sink / extractor stack against the local file.

Use this mode when the archive is already on disk and `peel`'s
decoders are preferred over `tar -I zstd -xf`, `unzip`, `7z x`, or
`unrar x`.

## Usage

```sh
# Non-destructive (default): extracts to ./dataset/ and leaves
# /tmp/dataset.tar.zst untouched.
peel /tmp/dataset.tar.zst

# Explicit output directory.
peel /tmp/dataset.tar.zst -o ./out/

# Destructive opt-in: hole-punch the source as the decoder advances,
# delete it on clean completion.
peel -d /tmp/dataset.tar.zst -o ./out/
```

`peel` recognises a local path by the absence of an `http://` or
`https://` scheme. Relative paths are resolved against the current
working directory.

## Modes

| Flag | Behaviour |
| --- | --- |
| (default) | Non-destructive: extract and leave the source untouched, no `.peel.ckpt` written |
| `-d` / `--destructive` | Hole-punch the source as the decoder advances and delete it on clean completion |
| `-k` / `--keep-archive` | No-op in local mode (preservation is already the default); kept for cross-source script compatibility |
| `--format <NAME>` | Force a decoder (same semantics as HTTP mode) |
| `--workdir <DIR>` | Place the `.peel.ckpt` sidecar here instead of next to the source (destructive mode only) |
| `--io-backend …` | Selects the puncher implementation (`auto` / `blocking` / `mmap`) |
| `--punch-threshold` | Minimum gap between in-loop punch syscalls in destructive mode |

## Resume

**Destructive mode** writes a `.peel.ckpt` next to the source after
each quiescent decoder boundary. A `kill -9` mid-run followed by a
re-invocation (with the same `-d`) converges to the same final
output tree as a clean single run.

**Non-destructive mode** is **one-pass**: no `.peel.ckpt` is
written. A kill mid-run requires re-running from scratch against
the still-intact source.

## Format coverage

Every format `peel` supports works through the local path:

- **Streaming shapes** (`.tar.zst`, `.tar.xz`, `.tar.lz4`, `.tar.gz`,
  raw `.zst` / `.xz` / `.lz4` / `.gz`, plain uncompressed `.tar`)
  flow through the same single-pass decoder the HTTP path uses.
- **Random-access shapes** (`.zip`, `.7z`, `.rar`: RAR5 plus legacy
  RAR3/RAR4) drive their per-format pipelines against the source
  archive opened read-only and wrapped in a fully-marked chunk
  bitmap, so the existing orchestrators run unchanged.

Destructive mode (`-d`) **does not apply** to the random-access
formats. Their pipelines seek backwards into the archive (zip's
central directory at the tail, 7z's trailer pointer, rar's per-entry
headers), so a monotonically-advancing punch cursor cannot be
maintained. `peel` warns and proceeds non-destructively when `-d` is
passed against one of those sources.

## Flags rejected in local mode

A few HTTP-only flags are rejected at parse time when `peel` detects
a local-path positional argument:

- `--mirror`
- `--sha256`
- `--workers`
- `--chunk-size`
- `--no-adaptive-chunk-size`
- `--max-bandwidth`
- `--max-disk-buffer`
- `--http-version`
- `--no-extract`
- `--strict-format`

If any of those flags are required, the run belongs on the HTTP
path: pass a `file:///…` URL or upload to localhost.

## When to use local mode

The HTTP path uses the same decoders. The choice depends on whether
the bytes are already on disk.

- **Already on disk**: local mode is faster (no syscall overhead
  from the HTTP client), simpler, and supports destructive
  hole-punching via `-d` when disk pressure is the goal.
- **Must be downloaded**: HTTP mode does it in one pass. A separate
  download then local-extract pipeline adds a full disk round-trip.

The [bench grid in the project README](https://github.com/agouin/peel#benchmarks-peels-decoder-vs-the-reference-cli-local-files)
compares `peel` against the system tools (`tar -I zstd -xf …`,
`unzip`, `7z x`, `unrar x`) for local-file decode and covers the
per-format performance characteristics.

## Examples

```sh
# Extract a .tar.zst from disk, default output dir is ./dataset/
peel /tmp/dataset.tar.zst

# Extract a .zip with one specific decoder, output to ./out/
peel ./archive.zip --format zip -o ./out/

# Free disk as the extraction proceeds (destructive); fail if the
# decoder gets stuck.
peel -d /var/snapshots/big.tar.xz -o /data/snapshot/

# Keep checkpoint state on fast NVMe, write output to slow HDD.
peel -d /data/big.tar.zst -o /mnt/slow/out/ --workdir /var/cache/peel/
```
