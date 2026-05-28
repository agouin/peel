# Download modes

`peel` runs in one of three modes for HTTP sources, plus a destructive
opt-in for local-file sources. The mode is selected by flag at the CLI;
format detection (URL suffix → magic bytes) decides the output shape
for the default mode.

## Mode summary (HTTP source)

| Flag | Download | Extract | Hole-punch source | Source on disk at exit |
| --- | --- | --- | --- | --- |
| (default) | yes | yes | yes | deleted |
| `-k` (bare) | yes | yes | **no** | preserved as sibling of `-o` |
| `-k=<PATH>` | yes | yes | **no** | preserved at `<PATH>` |
| `--no-extract` | yes | no | n/a | preserved at `-o` |

If format detection fails, `peel` warns and runs as `--no-extract`
by default: the remote object is saved to disk under its URL
basename. Pass `--strict-format` to make that case a hard error
instead. Useful in CI when an upstream object changing shape should
fail the build rather than produce a different artifact.

## Default mode: extract and destroy

```sh
peel https://example.com/dataset.tar.zst -o ./out/
```

Behaviour:

- Parallel ranged GETs feed `<output>.peel.part` (sparse).
- The decoder consumes the prefix while workers fetch the suffix.
- `fallocate(PUNCH_HOLE)` / `madvise(MADV_REMOVE)` releases blocks
  of the part-file as the decoder advances past them.
- On clean completion, the part-file (now mostly holes) is unlinked
  and the checkpoint sidecar (`<output>.peel.ckpt`) is removed.
- On `kill -9` or crash, the part-file and the checkpoint sidecar
  are left on disk. Re-running the same command resumes
  byte-identically.

Peak compressed-side disk: roughly `--max-disk-buffer` (default 1 GiB).
Peak total disk: `extracted_size + lookahead_window`.

> **Range-less servers.** The compressed-side cap above assumes the
> server honors `Range` requests. If it doesn't, `peel` falls back to a
> single streaming GET. Streaming formats (`.tar.zst`, `.tar.gz`, …)
> still hole-punch behind the decoder, but a random-access archive
> (`.zip`, `.7z`, `.rar`) can only be extracted once its trailer /
> central directory arrives — i.e. after the whole archive has been
> downloaded — so `--max-disk-buffer` cannot be honored and peak
> compressed-side disk equals the full archive size. `peel` logs a
> warning when this applies. (Hole-punching still reclaims blocks as
> entries extract, so peak total disk stays near the larger of the two
> sides, not their sum.)
>
> **No `Content-Length`.** If a range-less server also omits
> `Content-Length` (chunked transfer-encoding, HTTP/2, or HTTP/1.1
> connection-close framing), `peel` streams the body to EOF, learning
> the size as it goes. Streaming formats decode as bytes arrive;
> random-access archives are downloaded in full first, then extracted.
> Such runs cannot resume (the size isn't known and the server can't be
> ranged) and write no checkpoint. Truncation of a chunked / HTTP-2
> body is detected as a transfer error; an HTTP/1.1 close-delimited body
> that is cut short can't be distinguished from a complete one, so pass
> `--sha256` if you need that guarantee.

## `-k` / `--keep-archive`: extract and keep the archive

```sh
peel https://example.com/dataset.tar.zst -o ./out/ -k
peel https://example.com/dataset.tar.zst -o ./out/ -k=./preserved/dataset.tar.zst
```

Behaviour:

- Same parallel download and streaming extract as default mode.
- **The puncher is forced to no-op.** The part-file grows to the
  full `Content-Length` of the source.
- On clean completion, the part-file is renamed to its final
  archive path:
  - Bare `-k` → sibling of `-o`, named after the URL basename.
  - `-k=<PATH>` → explicit path. The `=` is **required**, since
    bare `-k` followed by a positional URL is otherwise ambiguous.

Peak disk: `extracted_size + compressed_size`. Use this mode when the
archive must remain on disk afterward (for example, to upload it
elsewhere, to extract it again with a different tool, or to keep as
a backup).

`-k` is redundant with `--no-extract` (which already preserves the
source). The CLI logs an info-level note rather than erroring.

## `--no-extract`: download only, parallel-GET aria2c-style

```sh
peel https://example.com/big.deb --no-extract
peel https://example.com/big.deb --download-only        # alias
```

Behaviour:

- Parallel ranged GETs feed `<output>.peel.part`.
- **No decoder runs.** **No holes are punched.**
- On clean completion, `<output>.peel.part` is renamed to its final
  path (the URL basename when `-o` is unset).
- Resume on `kill -9` or network drop works the same way as extract
  mode: the chunk bitmap, ETag handling, and SHA-256 hashing all
  apply.

Suitable for:

- Arbitrary remote downloads that are not archives: `.deb` packages,
  raw binaries, checksum files, ML weight files.
- Keeping the archive on disk to extract later with a different tool.
- Using `peel` as a parallel ranged-GET replacement for `aria2c`,
  `axel`, or `wget -c`, with the same scheduler, mirror fan-out,
  SHA-256 verification, and checkpointed resume.

Mutually exclusive with `--format`, `--force-format-from-magic`, and
`--punch-threshold`. Those are extractor knobs and nothing extracts
in this mode.

## `-d` / `--destructive`: opt in to destructive local-file extraction

```sh
peel /tmp/dataset.tar.zst                # non-destructive (default for local)
peel /tmp/dataset.tar.zst -d -o ./out/   # destructive: hole-punch + delete on success
```

[Local-file extraction](./local-extraction.md) is **non-destructive
by default**. `peel abc.tar.xz` extracts into `./abc/` and leaves
`abc.tar.xz` untouched. `-d` opts in to the disk-pressure contract
of the HTTP path: the source is progressively hole-punched as the
decoder advances and deleted on clean completion, freeing the
archive's blocks before the extracted tree is fully written.

For an **HTTP source**, `-d` is a harmless no-op (HTTP runs are
destructive by default), and `peel` logs an info-level note.
Combining `-d` with `-k/--keep-archive` for an HTTP source is an
**error**: the two intents contradict.

`-d` does not apply to the random-access formats (`.zip`, `.7z`,
`.rar`) in local mode. Their pipelines seek backwards into the
archive (zip central directory at the tail, 7z trailer pointer,
rar per-entry headers), so a monotonically-advancing punch cursor
cannot be maintained. `peel` warns and proceeds non-destructively
when `-d` is passed against one of those sources.

## Strict mode

```sh
peel --strict-format <URL> -o <PATH>
```

When the URL suffix and the magic-byte read both fail to identify a
registered decoder, the default behaviour is a warning and a
fall-through to `--no-extract`. `--strict-format` turns that case
into a hard error.

Use this in CI when an upstream object changing shape unexpectedly
(`.tar.zst` → `.tar.gz`, or a maintainer's CDN serving a different
file under the same URL) should fail the build rather than produce
a different artifact. Incompatible with `--no-extract` (no detection
runs when nothing is being extracted). Compatible with `-k`.

## Putting it together

| Goal | Command |
| --- | --- |
| Extract and discard the archive | `peel <URL> -o ./out/` |
| Extract and keep the archive | `peel <URL> -o ./out/ -k` |
| Just download (no extract) | `peel <URL> --no-extract` |
| Extract a local file, preserve source | `peel ./archive.tar.zst -o ./out/` |
| Extract a local file, free disk as you go | `peel ./archive.tar.zst -o ./out/ -d` |
| Verify hash, cap bandwidth, fan out across mirrors | see [Multi-mirror downloads](./multi-mirror.md) |
| Fail CI on format drift | `peel <URL> -o ./out/ --strict-format` |
