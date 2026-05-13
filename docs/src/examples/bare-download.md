# Bare downloader (aria2c replacement)

`peel --no-extract` is a parallel-ranged-GET downloader with mirror
fan-out, SHA-256 verification, and resume. It covers the same surface
as `aria2c`, minus the extract step.

## The basic case

```sh
peel https://example.com/big-file.iso --no-extract
```

Behavior:

- Issues 4 parallel ranged GETs against the URL.
- Writes the bytes to `<basename>.peel.part` (sparse).
- On clean completion, renames to the final filename (`big-file.iso`).

The bytes never pass through a decoder. No hole-punching occurs,
since no decoder advances the puncher. The part-file grows to the
full `Content-Length`.

`--download-only` is an alias for callers who prefer aria2c-style
naming.

## With explicit output path

```sh
peel https://example.com/big-file.iso --no-extract -o /downloads/
peel https://example.com/big-file.iso --no-extract -o /downloads/renamed.iso
```

Same semantics as extract mode: a trailing slash makes `-o` a
directory, otherwise it is the final file path.

## With hash verification

```sh
peel https://example.com/big-file.iso \
  --no-extract \
  --sha256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

The SHA-256 is checked against the downloaded bytes. This is the
same hash that `sha256sum big-file.iso` would produce after the
download finishes, without the separate hash step.

## With mirror fan-out

```sh
peel https://primary.example.com/big-file.iso \
  --mirror https://eu.mirror.example.com/big-file.iso \
  --mirror https://us.mirror.example.com/big-file.iso \
  --sha256 ba7816bf... \
  --no-extract
```

All [Multi-mirror downloads](../multi-mirror.md) machinery applies:
parallel HEAD validation at startup, per-mirror health tracking, 30s
exclusion on failure, aggregate bandwidth cap.

## With bandwidth cap

```sh
peel https://example.com/big-file.iso \
  --no-extract \
  --max-bandwidth 10MB/s
```

Useful when:

- Downloading on a shared link where saturating the pipe is disruptive.
- Cron-scheduled downloads that should run at steady-state rather
  than burst-and-idle.

## With resume across kills

`--no-extract` has the same resume guarantee as extract mode.
Ctrl-C / `kill -9` / network drop / OOM:

```sh
peel https://example.com/big-file.iso --no-extract
# ... interrupted at 40% ...

peel https://example.com/big-file.iso --no-extract
# Picks up where it left off, completes the rest.
```

The sidecars (`big-file.iso.peel.part` and `big-file.iso.peel.ckpt`)
stay on disk between runs.

## Choosing `peel --no-extract` over `aria2c`

| Need | Tool |
| --- | --- |
| Parallel ranged GETs | both |
| Resume on `kill -9` | both |
| Multiple URLs treated as one logical file | both (`aria2c -Z`, `peel`'s multi-part URL path) |
| Multiple URLs serving the **same** file (mirror fan-out) | both |
| SHA-256 verification | both |
| Hand-rolled, vetted single-binary install | `peel` |
| Out-of-band integration with a streaming extract step | only `peel` (toggling `--no-extract` switches to default extract mode) |
| Bittorrent / Metalink / multi-protocol | only `aria2c` |
| Browser-style cookie handling, OAuth, etc. | only `aria2c` |

`peel --no-extract` applies when callers want **the
streaming/resumable/parallel guarantee** without a separate
extract step. For a plain download (no archive) where the eventual
extract is not a concern, it offers aria2c-level UX in one binary.

## A typical script

```sh
#!/usr/bin/env bash
set -euo pipefail

URL=https://example.com/big-file.iso
SHA256=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
OUT=/downloads/big-file.iso

peel "$URL" \
  --no-extract \
  --sha256 "$SHA256" \
  --max-bandwidth 50MB/s \
  -o "$OUT"

echo "Downloaded and verified: $OUT"
```

Re-running this script after any failure resumes from the last
checkpoint. Re-running it after a clean completion is a no-op
(the file is already at `$OUT`, the sidecars are gone, and the next
invocation downloads from scratch because there is no checkpoint to
resume from).

For **"only download if not already present"** semantics, wrap with
a check:

```sh
if [ ! -s "$OUT" ]; then
  peel "$URL" --no-extract --sha256 "$SHA256" -o "$OUT"
fi
```

(The `-s` test checks for non-empty, which catches both "missing"
and "empty partial".)

## Non-goals

- **Torrent client.** No DHT, no peers.
- **Protocol-coercing tool.** HTTP / HTTPS only.
- **Auth-aware downloader.** No OAuth flow, no browser-cookie
  import. For URLs that require auth, pre-sign or pass a custom
  `Authorization` header via a reverse proxy. `peel` honours
  `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` env vars.
