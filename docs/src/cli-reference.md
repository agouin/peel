# CLI reference

```text
peel [OPTIONS] [URLS]...
```

`peel --help` prints the same content with full details and the exact
default values for the current build. This page covers every flag,
grouped by function, with design notes and constraints.

The full alphabetical list, with one-liners, appears at the bottom under
[Flag summary](#flag-summary).

## Positional arguments

### `[URLS]...`

One or more source URLs or local file paths.

- **One URL**: the single-source case. Example:
  `peel https://host/x.tar.zst -o ./out/`.
- **Two or more URLs**: activates the
  [multi-part split-archive](./multi-part-urls.md) path. The
  byte-concatenation of every URL's body is treated as one logical
  archive stream. Workers fetch all parts in parallel via ranged GETs.
- **A single local path** (no `http://` or `https://` scheme):
  activates [local-file extraction](./local-extraction.md). The same
  decoders run without HTTP machinery.
- **`@file.txt`** (single arg): read URLs and paths from `file.txt`,
  one per line. Blank lines and `#` comments are ignored. Suitable for
  [multi-volume](./multi-volume.md) manifests stored next to the
  archive.

## Output and destination

### `-o, --output <PATH>`

Destination for the extracted contents. Accepts a directory for
archive formats that produce a tree (`tar`, `zip`, `7z`, `rar`, and any
compressed wrapper around tar), or a file for stream-shaped formats
(raw `.zst`, `.xz`, `.lz4`, `.gz`).

- A **trailing slash** forces directory semantics.
  `peel x.zst -o ./out/` errors at parse time because `.zst` is a
  single-file output shape.
- **No `-o`**: defaults to the URL basename with archive and
  compression suffixes stripped, in the current working directory.
  `peel https://host/linux-6.x.tar.xz` extracts into `./linux-6.x/`.
- The resolver errors at coordinator entry if the explicit shape
  (trailing slash, file path) disagrees with the detected format.

See [Output path resolution](./output-paths.md) for the full table of
URL → output mappings.

### `--workdir <DIR>`

Directory for the `.peel.part` and `.peel.ckpt` sidecar files.

By default these are placed as siblings of the output
(`<output>.peel.part` and `<output>.peel.ckpt`). Override when the
extracted output and the in-flight state should live on different
disks. Examples: extracting onto slow HDD-backed storage while
keeping the part-file on a fast NVMe, or pinning the sidecars
*inside* a Kubernetes PVC mount when the output's parent is on
ephemeral container storage.

The directory is created if missing. The basenames stay the same;
only their parent directory changes.

## Download mode

`peel` runs in one of three modes (default, `-k`, `--no-extract`),
plus a destructive opt-in for local-file runs. See
[Download modes](./download-modes.md) for the full mode table.

### `-k, --keep-archive[=<PATH>]`

Extract **and** keep the source archive on disk. The puncher is
forced to no-op so the archive's bytes are preserved at their full
`Content-Length`.

- `-k` or `--keep-archive` (bare): preserve the archive as a sibling
  of `-o`, named after the URL basename.
- `-k=<PATH>` or `--keep-archive=<PATH>`: explicit path. The `=` is
  **required** because bare `-k` followed by a positional URL is
  otherwise ambiguous.
- Flag absent: default behaviour. The source bytes are dropped.
  Hole-punching trims them and the part-file is removed on success.

`-k` is a no-op in local mode (preservation is the default there)
and incompatible with `-d/--destructive` for HTTP sources.

### `--no-extract` (alias: `--download-only`)

Skip extraction. Download the source bytes verbatim to a single
file. The remote object is fetched in parallel via ranged GETs, using
the same scheduler, mirror, resume, and SHA-256 machinery as extract
mode, and is renamed into place on success. No decoder runs and no
holes are punched.

Suitable for arbitrary non-archive downloads, for keeping an archive
to extract later with a different tool, or as a parallel-ranged-GET
replacement for `aria2c`.

Mutually exclusive with `--format`, `--force-format-from-magic`, and
`--punch-threshold`. These are extractor knobs and nothing extracts in
this mode.

### `-d, --destructive`

Opt in to destructive extraction in local-file mode: hole-punch the
source as the decoder advances, then delete on clean completion.
Required because local mode is non-destructive by default.

For HTTP sources `-d` is a no-op. The HTTP path is destructive by
default. Combining `-d` with `-k` for an HTTP source is an error.

### `--strict-format`

Make format-detection failure a hard error instead of falling
through to `--no-extract`.

Default behaviour: if neither the URL suffix nor the magic bytes
identify a registered decoder, `peel` warns and saves the remote
object under its URL basename. `--strict-format` flips that to a
fatal error. Useful in CI when an upstream object changing shape
unexpectedly should fail the build instead of producing a different
artifact.

Incompatible with `--no-extract`. No detection runs when nothing is
being extracted.

## Format selection

`peel` detects the archive shape from the URL suffix first, then
falls back to a magic-byte read of the first ~8 bytes of the source.
A mismatch between the suffix and the magic fails closed unless
overridden.

### `--format <NAME>`

Force a specific decoder, bypassing both URL-suffix and magic-byte
detection. Required when the URL has no usable suffix (for example,
an opaque query-string download). Valid names: `tar`, `zstd`, `xz`,
`lz4`, `gzip`, `zip`, `7z`, `rar`.

Mutually exclusive with `--force-format-from-magic`.

### `--force-format-from-magic`

When the URL suffix and the source's magic bytes disagree, trust the
magic instead of returning `FormatMismatch`.

Mutually exclusive with `--format`.

## Network

### `--workers <N>`

Number of parallel ranged-GET workers. Default `4`. The scheduler
will not dispatch more concurrent requests than this against the
primary or any mirror.

Raise on a high-latency, high-bandwidth link (origin in another
region) where individual GETs leave the pipe under-utilised. Lower on
a single-machine, single-NIC link if the workers saturate the kernel's
network stack and per-worker throughput collapses.

### `--mirror <URL>` (repeatable)

Additional source URL serving the same file. The positional `URL` is
the primary; every `--mirror` is an alternate.

At startup, `peel` runs a parallel `HEAD` against every URL and drops
any mirror whose `Content-Length` (or `ETag` and `Last-Modified`, when
`--sha256` is unset) disagrees with the primary. Surviving mirrors are
picked from per ranged GET, biased toward the fastest live one.
Failures exclude a mirror for 30 s before retry.

See [Multi-mirror downloads](./multi-mirror.md).

### `--max-bandwidth <RATE>`

Aggregate bandwidth cap across all workers and mirrors via a shared
token bucket. Accepts:

- Decimal suffixes (1000-based, network convention): `K`, `M`, `G`, `T`.
- Binary suffixes (1024-based): `Ki`, `Mi`, `Gi`, `Ti`.
- A trailing `B` and `/s` are accepted and ignored.

Examples: `10MB/s`, `1.5GB/s`, `512KiB/s`, `1000000`.

The cap is **aggregate**, not per-mirror.

### `--max-disk-buffer <SIZE>`

Cap on the on-disk lookahead: bytes downloaded but not yet consumed
by the decoder. When the gap reaches this value, the scheduler stops
dispatching new chunks until the decoder catches up, bounding the
size of the `.peel.part` file when the network is faster than the
disk.

Accepts the same size syntax as `--max-bandwidth`. Pass `none`,
`off`, or `disabled` to remove the cap. Default `1GiB`.

### `--http-version <auto|h1|h2>`

HTTP version to use for downloads.

- `auto` (default): ALPN-negotiate between H1 and H2 over TLS, H1
  over plaintext.
- `h1`: force HTTP/1.1.
- `h2`: force HTTP/2. Over TLS, the origin must negotiate `h2` or the
  handshake fails. Over plaintext this forces HTTP/2 prior-knowledge
  ("h2c"), which only works against servers that explicitly speak it.

`auto` is the default.

### `--no-auto-discover`

Skip [multi-volume](./multi-volume.md) auto-discovery.

When the positional URL matches a multi-volume pattern
(`<base>.part<N>.rar`, `<base>.7z.<NNN>`, `<base>.z<NN>` and
`<base>.zip`), `peel` HEAD-probes the origin to discover the full
ordered volume set before any download starts. This flag forces the
seed to be treated as a single-source URL even when its basename
matches a multi-volume pattern.

Applicable when:

- The seed's filename matches one of the conventions but is not
  actually a multi-volume archive.
- Discovery would fan out to many failed HEAD probes against a
  high-latency origin and the seed is known to be a single source.

No effect when multiple positional URLs are supplied. That path
already opts out of auto-discovery.

## Integrity

### `--sha256 <HEX>` (repeatable)

SHA-256 digest the assembled compressed source must match. Repeatable.

- **Single-URL runs**: pass once. `peel` streams a hand-rolled,
  resumable SHA-256 over the source bytes as they arrive and aborts
  at clean completion if the digest disagrees. The hash state is
  checkpointed across resumes, so a resumed run produces a digest
  byte-identical to `sha256sum` on the original file.
- **Multi-URL runs**: pass zero times (no verification) or exactly
  once per URL, paired by order. Hashes are per-part digests of each
  part's bytes; verified at part-boundaries as the decoder advances.

See [Integrity verification](./integrity.md). Hashing happens on the
streaming pipeline. `.zip` archives extract per-entry and integrity
checking does not extend to that path in the current release.

## Encryption

### `--password-from <SOURCE>`

Password source for [encrypted archives](./encryption.md). Accepts:

- `prompt`: read from `/dev/tty` with echo disabled. Up to 3 attempts
  on a wrong password before exit code 4.
- `env:NAME`: read from the named environment variable.
- `file:PATH`: read the first line of the file. Modes other than
  `0600` emit a one-shot warning.
- `fd:N`: read from file descriptor `N` (one-shot, until EOF or
  newline). Compatible with `peel … --password-from fd:3 3< <(pass …)`.

`peel` does **not** accept a `--password=<value>` flag. `argv` is
visible to every process on the host.

## Tuning knobs

These have measured defaults that work well across the bench grid.
See [Performance and tuning](./performance.md) before changing them
in production.

### `--chunk-size <BYTES>`

Bitmap chunk size: the unit of completion tracked in checkpoints.
Default 4 MiB.

With adaptive chunk-sizing enabled (the default), the scheduler may
coalesce several consecutive bitmap chunks into a single ranged GET;
this flag continues to set the *bitmap* unit. Pair with
`--no-adaptive-chunk-size` to force a fixed dispatch size.

### `--no-adaptive-chunk-size`

Disable the adaptive chunk-size policy. The scheduler dispatches
exactly one bitmap chunk per worker, with no growth/shrink decisions
over the lifetime of the run. Useful for benchmarking and reproducible
test runs.

### `--punch-threshold <BYTES>`

Minimum gap between in-loop hole-punch syscalls. Default 4 MiB.

Smaller values yield a tighter physical-disk footprint; larger values
yield fewer syscalls per second. Tune downward to enforce a hard
ceiling on physical disk; upward if the filesystem's punch-hole
implementation is slow.

### `--checkpoint-min-bytes <BYTES>`

Minimum source-byte progress between checkpoint writes. Default 8 MiB.

### `--checkpoint-min-secs <SECS>`

Minimum wall-clock interval between checkpoint writes (fractional).
Default 2 s.

### `--checkpoint-target-secs <SECS>`

Target wall-clock interval between checkpoints. Used to scale the
byte floor up at high download rates so the cadence stays below this
target. `0` disables rate-aware scaling. Default 0.2 s.

### `--io-backend <auto|blocking|uring|mmap>`

File-IO backend selection.

- `auto` (default): on Linux, `mmap` for the sparse part file plus
  `io_uring` for sockets, with graceful fallback. On non-Linux, the
  blocking backend for both.
- `blocking`: force the pre-`io_uring` `pwrite` / `pread` path
  everywhere. Used for A/B comparison.
- `uring`: require `io_uring` for sockets; error out if unavailable.
- `mmap`: force the memory-mapped sparse-file path explicitly, with
  the blocking socket backend.

See [Performance and tuning](./performance.md) for what each path
does and when to pick it.

## Help and version

### `-h, --help`

Print full help. `-h` prints a one-line summary per flag; `--help`
prints the full description.

### `-V, --version`

Print the version.

## Flag summary

| Flag | Purpose | Default |
| --- | --- | --- |
| `-o, --output <PATH>` | Output path | URL basename, suffixes stripped |
| `--workdir <DIR>` | Sidecar (`.peel.part` / `.peel.ckpt`) location | Sibling of output |
| `-k, --keep-archive[=<PATH>]` | Extract AND keep the source | off |
| `--no-extract` | Download without extracting | off |
| `-d, --destructive` | Hole-punch + delete source (local mode) | off |
| `--strict-format` | Unrecognised format → error | off |
| `--format <NAME>` | Force a decoder | none |
| `--force-format-from-magic` | Trust magic over URL suffix | off |
| `--workers <N>` | Parallel GETs | 4 |
| `--mirror <URL>` (repeat) | Additional source URLs | none |
| `--max-bandwidth <RATE>` | Aggregate token-bucket cap | none |
| `--max-disk-buffer <SIZE>` | Lookahead window cap | 1 GiB |
| `--http-version <auto\|h1\|h2>` | HTTP version | auto |
| `--no-auto-discover` | Skip multi-volume HEAD probes | off |
| `--sha256 <HEX>` (repeat) | Verify hash | none |
| `--password-from <SOURCE>` | Password source | none |
| `--chunk-size <BYTES>` | Bitmap unit | 4 MiB |
| `--no-adaptive-chunk-size` | Fixed dispatch size | off |
| `--punch-threshold <BYTES>` | Min gap between punches | 4 MiB |
| `--checkpoint-min-bytes <BYTES>` | Min progress between checkpoints | 8 MiB |
| `--checkpoint-min-secs <SECS>` | Min interval between checkpoints | 2 s |
| `--checkpoint-target-secs <SECS>` | Target interval (rate-aware) | 0.2 s |
| `--io-backend <NAME>` | File-IO backend | auto |
| `-h, --help` | Print help | none |
| `-V, --version` | Print version | none |
