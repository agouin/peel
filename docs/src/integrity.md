# Integrity verification

`peel` provides two integrity mechanisms layered on top of the
streaming pipeline:

1. **`--sha256 <HEX>`**: end-to-end source verification against the
   exact bytes produced by `sha256sum` over the original archive.
2. **Per-chunk CRC32C fingerprints**: automatic drift detection
   inside the chunk bitmap, catching a source that changes mid-run
   or on resume.

The second mechanism is enabled by default. The first is opt-in via
the `--sha256` flag.

## `--sha256`: end-to-end source verification

Pass the expected digest of the **compressed source bytes**, the value
`sha256sum dataset.tar.zst` would print over the original archive
(not over the extracted contents):

```sh
peel https://example.com/dataset.tar.zst \
  --sha256 ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad \
  -o ./out/
```

Behaviour:

- `peel` streams a resumable SHA-256 over the source bytes as they
  arrive.
- On clean completion, the digest is compared. A mismatch aborts the
  run with a specific error and exit code 1.
- The hash state is **checkpointed** alongside everything else, so a
  resumed run produces a digest **byte-identical** to `sha256sum` on
  the original file.

The digest is 64 hex characters. Mixed case is accepted; whitespace
is not.

### Relationship to TLS

TLS protects against in-flight tampering. It does **not** protect
against:

- The origin serving a corrupted file.
- A CDN mirror serving a stale or wrong file.
- A `--mirror` URL pointing at a subtly different object.
- A mid-flight transmission glitch that survives TLS framing (rare
  but observed).

`--sha256` enforces a published-by-the-source contract (the project
declares "this archive's hash is X") end-to-end.

### Multi-URL runs

For [multi-part URLs](./multi-part-urls.md) and
[multi-volume archives](./multi-volume.md), `--sha256` is repeatable.
Pass **zero** flags (no verification) or **exactly one** `--sha256`
per URL, paired by order:

```sh
peel \
  https://host/dataset.tar.part0000 \
  https://host/dataset.tar.part0001 \
  --sha256 0a8de6e83fd8ba040fd052fd8d4fd0e009a9736ace5cb32bb2abd4ac6a61725d \
  --sha256 1bcf4d2e9aa01ff5...                                              \
  -o ./out/
```

Each part's hash is verified at its part-boundary as the decoder
advances. A wrong number of `--sha256` flags (1 hash for 2 URLs, 3
hashes for 2 URLs) is rejected at parse time.

### Scope and limits

- `--sha256` covers the **streaming pipeline**: anything that goes
  through the `.tar.*` / raw codec / `.7z` path.
- `.zip` archives extract per-entry and integrity checking does not
  extend to the streaming-source path in the current release. Each
  ZIP entry's own CRC32 (in the central directory) is still
  verified per-entry.
- For `.rar` and `.7z`, the format's per-entry integrity check (RAR's
  BLAKE2sp / CRC32, 7z's per-substream CRC32) is verified independently
  and on top of `--sha256`.

## CRC32C fingerprints: automatic drift detection

Every bitmap chunk (default 4 MiB) has a CRC32C fingerprint stored
in the checkpoint. Two scenarios where this matters:

### Mid-run source drift

If the source changes during a long run (someone re-uploaded the
file, or a CDN edge invalidated and re-pulled a different version),
a worker fetching a later chunk receives bytes that disagree with
those of an earlier worker. The fingerprint comparison catches this
case: `peel` aborts with a "source changed during run" error rather
than producing wrong output.

### Resume after a kill

On `kill -9`, the part-file may contain bytes for chunks that were
not yet marked complete in the bitmap. On resume, `peel`:

1. Reads the bitmap to find which chunks are complete.
2. Re-verifies the fingerprint against the bytes on disk for any
   chunk near a recent bitmap update.
3. Marks the chunk complete if the fingerprint matches, or re-fetches
   it otherwise.

This procedure makes a `kill -9` mid-write safe. Bytes that landed on
disk are reused when correct and refetched when not.

## ETag / Last-Modified handling

When `--sha256` is **not** set, `peel` uses `ETag` and `Last-Modified`
as secondary identity signals:

- **At startup**, the HEAD probe records the ETag and Last-Modified.
- **On resume**, the ETag and Last-Modified are re-checked. A change
  indicates the source changed and the resume aborts.
- For [multi-mirror](./multi-mirror.md) runs, mirrors with disagreeing
  ETags are dropped at startup (unless `--sha256` is set, in which
  case the hash is the source of truth).

Strong ETags are honoured strictly. Weak ETags (`W/"…"`) are treated
as best-effort, since they may legitimately differ across CDN edges
for the same file. A weak-ETag mismatch is logged but does not fail
the run.

## Reading a hash from a file

`peel` does not provide a `--sha256-file` flag. Use shell substitution:

```sh
# Bash, zsh:
peel "$URL" --sha256 "$(awk '{print $1}' dataset.tar.zst.sha256)" -o ./out/

# With process substitution:
peel "$URL" --sha256 $(< checksum.txt) -o ./out/
```

A future `--sha256-file <PATH>` flag is under consideration. Shell
substitution is the recommended path in the interim.

## Failure modes

| Error message | Cause | Action |
| --- | --- | --- |
| `digest mismatch` | `--sha256` value disagrees with what was streamed | Check the source against the published hash; the file may have been re-uploaded |
| `source changed during run` | CRC32C fingerprint disagrees between chunks | Re-run; the source is unstable |
| `ETag mismatch on resume` | The source's ETag changed since the run started | Delete the sidecars and start fresh, or pass `--sha256` to trust the hash instead |
| `multi-URL sha256 count mismatch` | Wrong number of `--sha256` for the URL count | Pass exactly one per URL, or none |
