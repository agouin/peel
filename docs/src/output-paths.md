# Output path resolution

`-o <PATH>` accepts either a **directory** (for archive formats that
produce a tree) or a **file** (for stream-shaped formats). When `-o`
is omitted, `peel` derives a default from the URL basename.

## The two output shapes

| Shape | When | Default `-o` |
| --- | --- | --- |
| **Directory** (tree-shaped) | `tar`, `zip`, `7z`, `rar`, and any `.tar.<x>` wrapper | URL basename with archive / compression suffixes stripped |
| **File** (stream-shaped) | Raw `.zst`, `.xz`, `.lz4`, `.gz` (no inner tar) | URL basename with the compression suffix stripped |

If the explicit `-o` does not match the detected format's shape,
`peel` errors at coordinator entry. There is no silent fixup.

## Examples

```sh
# Tar wrapper → directory. Trailing slash is optional but explicit.
peel https://example.com/linux-6.x.tar.xz                  # → ./linux-6.x/
peel https://example.com/linux-6.x.tar.xz -o ./linux/      # → ./linux/
peel https://example.com/linux-6.x.tar.xz -o ./linux       # → ./linux/  (no trailing slash, still a dir)

# Raw compressed → single file.
peel https://example.com/model.bin.zst                     # → ./model.bin
peel https://example.com/model.bin.zst -o ./weights.bin    # → ./weights.bin

# ZIP / 7z / RAR → directory.
peel https://example.com/data.zip                          # → ./data/
peel https://example.com/snapshot.7z -o ./snap/            # → ./snap/
peel https://example.com/backup.part0001.rar -o ./out/     # → ./out/  (multi-volume auto-discovered)

# Trailing slash forces directory semantics. Useful when the URL has
# no suffix and a tree output is required for `--format zip`.
peel "https://host/dl?id=42" --format zip -o ./out/
```

## How the basename is computed

1. Strip the URL's query string and fragment.
2. Take the last path component.
3. Strip suffixes in order until a non-archive / non-compression
   suffix remains:
   - `.tar` strips `.tar`.
   - `.zst` / `.xz` / `.lz4` / `.gz` strip the compression suffix.
   - `.tar.zst` etc. strip both.
   - `.zip` / `.7z` / `.rar` strip the archive suffix.

Examples:

| URL basename | Default output |
| --- | --- |
| `linux-6.x.tar.xz` | `linux-6.x/` |
| `model.bin.zst` | `model.bin` |
| `data.tar` | `data/` |
| `dataset.zip` | `dataset/` |
| `snapshot.7z` | `snapshot/` |
| `backup.part0001.rar` | `backup/` |

## When the URL has no useful suffix

Opaque query-string downloads (`?id=42`, `?download_token=…`) defeat
the suffix-based default. Two options:

```sh
# 1. Pin the decoder explicitly.
peel "https://host/dl?id=42" --format zstd -o ./out.bin

# 2. Force trust in magic-byte detection. A small initial GET reads
#    the magic, and the resolver picks the decoder from there.
peel "https://host/dl?id=42" --force-format-from-magic -o ./out.bin
```

`--format` is more deterministic than relying on magic. Prefer it
whenever the format is known ahead of time.

## Conflict resolution

| Situation | Behaviour |
| --- | --- |
| `-o` is a file path, format is tree-shaped (e.g. `tar.zst`) | Error at coordinator entry: shape mismatch |
| `-o` ends in `/`, format is stream-shaped (e.g. raw `.zst`) | Error at coordinator entry: shape mismatch |
| `-o` is a directory that exists and is non-empty (tar / zip / 7z / rar) | `peel` writes into it; pre-existing files are overwritten when an archive entry has the same path |
| `-o` is a file path that exists (stream-shaped output) | Overwritten |
| `-o`'s parent directory does not exist | Created if a single parent component is missing; otherwise error |

## Where the sidecars live

The `.peel.part` and `.peel.ckpt` sidecar files live next to the
**output** by default:

- `-o ./out/` → `./out.peel.part`, `./out.peel.ckpt`
- `-o ./out.bin` → `./out.bin.peel.part`, `./out.bin.peel.ckpt`

Override with `--workdir <DIR>` when the output and the in-flight
state should live on different disks:

```sh
# Extract onto slow HDD-backed /data, keep the in-flight state on
# fast NVMe at /var/cache/peel.
peel https://host/dataset.tar.zst -o /data/out/ --workdir /var/cache/peel/
```

The directory is created if missing. The basenames stay the same
(`<output_name>.peel.part` / `<output_name>.peel.ckpt`); only the
parent directory changes.
