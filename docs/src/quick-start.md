# Quick start

Five things `peel` does, in five copy-pasteable commands.

## 1. Extract a tarball over HTTP

```sh
peel https://example.com/linux-6.x.tar.xz
```

Without `-o`, the default extract directory is the URL basename with
archive and compression suffixes stripped, in the current working
directory. The example above lands the kernel sources in `./linux-6.x/`.

To set an explicit path, a trailing slash forces directory semantics
(useful when the URL has no recognisable suffix):

```sh
peel https://example.com/linux-6.x.tar.xz -o ./linux/
```

## 2. Extract a bare compressed file

For stream-shaped formats (raw `.zst` / `.xz` / `.lz4` / `.gz`) the output
is a single file, not a directory:

```sh
peel https://example.com/model.bin.zst -o ./model.bin
```

## 3. Download without extracting

Skip the decoder and write the bytes verbatim into a single file using
parallel ranged GETs. The same scheduler, mirror, and resume machinery
used by extract mode applies.

```sh
peel https://example.com/big.deb --no-extract
```

`--download-only` is an alias provided for compatibility with `aria2c`.

## 4. Extract a `.zip`, `.7z`, or `.rar` over HTTP

These formats place their index at the *end* of the file
(`curl | unzip` does not work; see [How it works](./how-it-works.md)).
`peel` fetches the central directory or trailer first via a ranged GET,
then streams entries to disk as they arrive:

```sh
peel https://example.com/dataset.zip   -o ./out/
peel https://example.com/snapshot.7z   -o ./out/
peel https://example.com/backup.rar    -o ./out/
```

For a password-protected archive, see [Encrypted archives](./encryption.md):

```sh
peel https://example.com/secret.zip -o ./out/ --password-from prompt
```

## 5. Extract a local file

For an archive already on disk, skip the HTTP machinery and run the same
decoders against the local file. Non-destructive by default:

```sh
peel /tmp/dataset.tar.zst                # extracts to ./dataset/, archive untouched
peel /tmp/dataset.tar.zst -o ./out/      # explicit output dir
peel -d /tmp/dataset.tar.zst -o ./out/   # destructive: hole-punch and delete on success
```

See [Local-file extraction](./local-extraction.md) for the full mode table.

## Default behaviour

Every command above runs with these guarantees, without any extra flag:

- **Parallel ranged GETs.** Default 4 workers, tunable with `--workers`.
- **Streaming decompression** that overlaps with the download. Peak disk
  for the compressed side is the lookahead window, not the archive size.
- **Hole-punched compressed buffer.** `fallocate(PUNCH_HOLE)` and
  `madvise(MADV_REMOVE)` release blocks of the part-file as the decoder
  advances past them.
- **Frame-aligned resume.** A `kill -9` mid-run leaves a `.peel.ckpt`
  next to the part-file. Re-running the same command resumes.
- **Live progress UI.** Three-line block on TTY (download, extract, ETA,
  active workers, on-disk source footprint). Falls back to
  `tracing::info!` lines on a non-TTY without any extra flag.

## Where to go next

- Hash verification, bandwidth caps, or mirrors:
  [Integrity verification](./integrity.md) and
  [Multi-mirror downloads](./multi-mirror.md).
- Multi-volume archives (`name.part0001.rar`, `name.7z.001`, spanned
  ZIP): [Multi-volume archives](./multi-volume.md).
- Archives split across several URLs as `.part0000` / `.part0001`:
  [Multi-part URLs](./multi-part-urls.md).
- High-bandwidth or memory-constrained runs:
  [Performance and tuning](./performance.md) covers `--io-backend`,
  `--http-version`, `--max-bandwidth`, `--max-disk-buffer`, `--workdir`.
- Full flag listing: [CLI reference](./cli-reference.md).
