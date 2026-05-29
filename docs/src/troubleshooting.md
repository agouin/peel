# Troubleshooting

Symptoms, likely causes, and verification steps. For problems not
listed here, see [Exit codes](./exit-codes.md) for the error code
key and [FAQ](./faq.md) for design-rationale questions.

## "No space left on device"

The extraction filled the output filesystem. Two causes:

1. **The extracted tree is genuinely bigger than the free space.**
   Check the archive's expected uncompressed size (most formats
   report it in their metadata, and `peel` logs it on the progress
   UI's first line). If that exceeds free space, more disk is
   required: the sliding window only bounds the *compressed* side.

2. **The part-file's lookahead window grew faster than the decoder
   consumed it.** Lower `--max-disk-buffer` (default 1 GiB) so the
   scheduler back-pressures sooner:

   ```sh
   peel <URL> --max-disk-buffer 128MiB -o ./out/
   ```

   Then confirm hole-punching is working (see the next section).

## "Hole-punching seems disabled / part-file is huge"

Check the part-file's **physical** size (`du -h`) versus its
**logical** size (`ls -la`):

```sh
$ ls -la out.peel.part out.peel.ckpt
-rw-r--r--  ...  10737418240 ... out.peel.part   # 10 GiB logical
$ du -h out.peel.part
182M    out.peel.part                           # 182 MiB physical (healthy)
```

If `du` is close to `ls`, hole-punching is not trimming. Possible
causes:

- **`-k/--keep-archive` is set.** The puncher is intentionally
  disabled. Remove `-k` if archive preservation is not required.
- **`--no-extract` is set.** Nothing decodes, so nothing punches.
  Expected for `--no-extract`: the bytes are kept verbatim.
- **The filesystem does not support punch-hole.** Some unusual
  mounts and old kernels reject it. `peel` logs a `warn!` at
  startup when the probe fails:

  ```text
  WARN  filesystem rejected MADV_REMOVE probe, falling back to fallocate(PUNCH_HOLE)
  WARN  filesystem rejected fallocate(PUNCH_HOLE) probe, source bytes will not be released
  ```

  Move the workdir to a filesystem that supports it
  (`--workdir /var/tmp/peel`), or accept the larger transient
  footprint.

## "`io_uring` fallback warning"

On Linux, one of these messages may appear:

```text
WARN  io_uring_setup failed (errno=1 EPERM), falling back to blocking sockets
WARN  io_uring not available (kernel < 5.6), falling back to blocking sockets
WARN  RLIMIT_MEMLOCK too low for io_uring (need at least N KiB), falling back to blocking sockets
```

These are informational, not errors. `peel` falls back to the
blocking backend and continues. The fallback path is the same code
every non-Linux build uses; results are correct either way.

To force `io_uring` and fail-fast when it is not available:

```sh
peel <URL> --io-backend uring -o ./out/
```

Common causes:

- **Seccomp profile blocks the syscalls.** `cri-o`'s default profile
  is the most common case under Kubernetes. Add `io_uring_*` to the
  allowed syscalls or accept the fallback.
- **Kernel too old.** Minimum 5.6 for the SQEs `peel` uses. In
  practice 5.10+ is more reliable.
- **`RLIMIT_MEMLOCK` too low.** Container default may be 16 KiB,
  while `io_uring` rings need a few MiB. Raise the limit
  (`ulimit -l unlimited` in the container spec) or accept the
  fallback.

## "Wrong digest at completion"

```text
error: digest mismatch
  expected: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
  got:      e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

The streamed bytes did not hash to the value asserted by `--sha256`.
Possibilities:

1. **The source moved or was re-uploaded.** Re-download a small
   sample (`curl --range 0-1023 $URL | sha256sum`) and compare
   against what the publisher currently advertises.
2. **Wrong hash supplied.** Double-check the hash source.
3. **A `--mirror` is serving subtly different bytes.** Remove
   mirrors one at a time to identify the culprit. `peel` drops
   misbehaving mirrors at the HEAD validation step, but some forms
   of subtle corruption only show up post-decoder.

## "Source changed during run"

```text
error: source changed during run
  chunk 1247 fingerprint mismatch: stored=…, refetched=…
```

The CRC32C fingerprint of a chunk does not agree across fetches.
The source bytes changed between when one worker fetched the chunk
and when another did. Causes:

- **CDN-edge cache drift.** Common with mirror infrastructure that
  is mid-rollout. Wait for propagation, then re-run.
- **Origin re-uploaded the file.** Check the upstream publishing
  timeline.
- **Network corruption.** Rare with TLS, but observed on some
  middlebox-heavy paths. Repeat the run; the second attempt usually
  succeeds.

Delete the `.peel.ckpt` to start fresh from the part-file's bytes
(which `peel` re-verifies chunk-by-chunk), or delete both sidecars
to start completely from scratch.

## "ETag mismatch on resume"

```text
error: source identity changed since last run
  ETag at startup: "8b1a9953c4611296a827abf8c47804d7"
  ETag now:        "65a8e27d8879283831b664bd8b7f0ad4"
```

The source's ETag (or `Last-Modified`) changed between the start of
the run and the resume. `peel` aborts rather than silently mixing
bytes from two different versions of the file.

Two fixes:

1. **Delete the sidecars and start from scratch.** The bytes
   already on disk belong to the previous version and are not
   useful.
2. **Pass `--sha256` of the *new* version.** With `--sha256` set,
   the hash is the source of truth, and agreeing mirrors are trusted
   regardless of ETag drift.

## "Multi-volume probe returned 404s"

```text
warn: multi-volume probe: backup.part0005.rar returned 404, stopping at 4 volumes
```

This is **normal**: auto-discovery stops at the first missing
volume. The reported count is what `peel` will fetch.

If more volumes are expected than the probe found:

- The volumes may be on a different host or path.
- The numbering may have a gap.
- The volumes may use a different convention than the seed implies.

Use the explicit positional list or an `@manifest.txt` file instead.

## "TLS / certificate error connecting to host"

```text
error: hyper transport error to "host":443: client error (Connect)
```

The server's TLS certificate could not be verified against the system
trust store — it may be self-signed, expired, issued for a different
hostname, or signed by a CA `peel` doesn't trust.

The right fix is almost always to make the certificate trustworthy:
install the issuing CA into your system trust store, or renew/reissue
the server's certificate.

If you understand the risk and are talking to a host you control or
trust on an otherwise secure network, `--insecure` skips certificate
verification (like `curl -k`). See
[`--insecure`](./cli-reference.md#--insecure) — it disables MITM
protection, so it is a last resort, not a default.

## "Wrong format detected"

```text
error: format mismatch: URL suffix says .tar.zst, magic bytes are 0x1f 0x8b (gzip)
       pass --force-format-from-magic to trust magic, or --format <NAME> to pin
```

The URL suffix and the magic bytes disagree. Three options:

1. **Trust the magic** when the file is known to match its bytes:
   `--force-format-from-magic`.
2. **Pin the decoder** when the expected format is known:
   `--format zstd` (or whichever).
3. **Investigate the source.** The file may have been re-encoded
   without renaming, or the URL is genuinely serving the wrong file.

## "Permission denied" writing the output

The output's parent directory is not writable for the user running
`peel`. The error message names the path:

```text
error: cannot create output directory ./out/: Permission denied (os error 13)
```

`peel` does **not** elevate privileges. Run as a user with write
permission on the output path, or use `--workdir` to relocate only
the sidecars to a writable location while writing the final
extracted tree to a location the user owns.

## "Output file already exists" (or seems to)

`peel` overwrites the extracted output:

- For **tree-shaped** outputs (tar, zip, 7z, rar), existing files at
  paths matching an archive entry are overwritten. Existing files at
  paths *not* in the archive are left alone.
- For **stream-shaped** outputs (raw `.zst`, `.xz`, `.lz4`, `.gz`),
  the output file is overwritten unconditionally.

For a non-destructive run, point `-o` at a fresh directory.

## "I want to interrupt and resume later"

Press **Ctrl-C** (or send SIGTERM). `peel` traps the signal, flushes
the in-flight checkpoint, and exits with code 130 (SIGINT) or 143
(SIGTERM). The sidecars stay on disk. Re-run the exact same command
to resume.

`kill -9` (SIGKILL) is also safe. `peel` is designed so that even
an ungraceful kill leaves the part-file's bytes and the last
checkpoint in a consistent state, and the next run reconciles.

## "Where do the logs go?"

`stderr`. The progress UI block goes to stderr as well, redrawn in
place on a TTY. To capture:

```sh
peel <URL> -o ./out/ 2>peel.log                    # only log
peel <URL> -o ./out/ 2> >(tee peel.log >&2)        # log and show
RUST_LOG=debug peel <URL> -o ./out/ 2>peel.log     # verbose
```

## "Live progress UI shows wrong percentage"

The percentage is `streamed_bytes / Content-Length`. Two pitfalls:

- For [multi-part URLs](./multi-part-urls.md), the denominator is
  the sum of all parts' `Content-Length` values (accurate).
- For a server that does not return `Content-Length` but does support
  ranges, `peel` recovers the size from a ranged probe, so the
  percentage stays accurate.
- For a server that returns neither `Content-Length` nor range support
  (rare; chunked or connection-close responses, mostly badly-configured
  proxies), the total size isn't known until the transfer finishes, so
  `peel` streams to EOF and reports bytes transferred without a
  percentage.

## Getting better diagnostics

Always run with `RUST_LOG=info` (or `RUST_LOG=debug`) when filing a
bug report:

```sh
RUST_LOG=debug peel <URL> -o ./out/ 2>peel-debug.log
```

The first few lines list the selected backends, the discovered
volumes and mirrors, and the format detection result. Misbehaviour
typically shows up there.
