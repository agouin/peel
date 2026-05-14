# FAQ

Design-rationale notes and answers to common "why does `peel` do X"
questions.

## No `--password=<value>` flag

`argv` is visible to every process on the host via `ps`,
`/proc/<pid>/cmdline`, and `Get-Process -IncludeUserName`. A
passphrase on the command line is read by:

- Any unprivileged process on the host (until the process exits).
- Anything that scrapes process listings: monitoring agents, shell
  history collectors, exit-code-replaying scripts.
- Container observability tools that log process state on crash.

`--password-from` keeps the passphrase out of `argv`. `env:NAME`,
`file:PATH`, and `fd:N` integrate with non-interactive workflows.
For a single-line non-interactive invocation,
`PEEL_PW=… peel … --password-from env:PEEL_PW` is two characters
longer than `--password=…` and avoids the visibility problem.

## Why `.bz2` support was added in round two

Round one shipped without `.bz2` on the basis that bzip2 is a slow,
single-threaded codec superseded by xz (better ratio) and zstd
(faster). That priors-only argument held until a real corpus
arrived as `.tar.bz2` and `bunzip2 | peel /dev/stdin` discarded the
streaming + resume properties `peel` exists to deliver — the source
side's on-disk footprint went unbounded across the workaround pipe,
and a mid-extraction `kill -9` restarted the whole thing.

`.bz2`, `.tar.bz2`, `.tbz2`, and `.tbz` are now first-class formats.
The pipeline matches the other compressed `.tar.*` codecs: parallel
ranged HTTP downloads, in-flight streaming decompression,
`fallocate(PUNCH_HOLE)` reclaim of the compressed source as the
decoder advances, and per-block frame-aligned checkpointing so a
crash mid-extraction resumes exactly where it left off. See
`internal/PLAN_bz2_support.md` for the engineering plan and
trade-offs (randomised blocks, mid-block resume, parallel block
decoding) deferred from this round.

## No raw `lzma` support (only `xz`)

XZ is the modern container format wrapping LZMA2. Raw `.lzma`
(without the XZ headers) was the LZMA1 era's format and is rare in
modern publishing. `peel`'s decoder is per-cycle equivalent to
`liblzma` on the XZ path. Adding the raw LZMA1 framing is in the
backlog but does not fit the streaming-from-HTTP workflow `peel`
targets.

## No nested archive handling

Each invocation of `peel` extracts one archive. Chain invocations
for a nested archive:

```sh
peel https://host/outer.tar.zst -o ./outer/
peel ./outer/inner.zip -o ./final/                   # local mode
```

Nested-archive auto-detection adds an order-of-magnitude of
complexity (filesystem walking, recursion limits, archive bombs) for
no compelling user-facing win.

## Reason for `--no-extract`

Three things `peel --no-extract` provides that plain `curl` does
not:

1. **Parallel ranged GETs**, like `aria2c`. `curl` has `--parallel`
   but it parallelises over many URLs, not over ranges of one URL.
2. **Resume after `kill -9`**, with checkpointed state. `curl -C -`
   resumes a single in-flight transfer and does not survive a kill
   that lost the file descriptor.
3. **Mirror fan-out and SHA-256 verification.** `--mirror`'s
   per-mirror health tracking and aggregate token-bucket bandwidth
   cap are built in.

Use `curl` for one-off "download this one file fast". Use
`peel --no-extract` for parallel-GET, resume, mirror failover, or
hash verification (the full `aria2c` use case).

## `--mirror` failover is parallel, not sequential

Modern CDN topologies are mostly symmetric: any mirror should serve
any byte. Parallel scheduling across mirrors gives the aggregate
bandwidth of all of them. Sequential failover wastes that.

When a mirror starts failing, the scheduler excludes it for 30 s and
rebalances. The exclusion is logged for debugging which mirror went
out of rotation.

For true sequential failover (mirror 2 used only if mirror 1 is
totally unreachable), wrap with shell logic:

```sh
peel "$PRIMARY"  -o ./out/ ||
peel "$BACKUP_1" -o ./out/ ||
peel "$BACKUP_2" -o ./out/
```

## Corporate proxy support

`peel` honours the standard `HTTP_PROXY`, `HTTPS_PROXY`, and
`NO_PROXY` environment variables for outbound requests, plus
`SSL_CERT_FILE` for trust-store overrides.

For TLS errors with a corporate CA, point `SSL_CERT_FILE` at the
bundle that includes it:

```sh
SSL_CERT_FILE=/etc/ssl/certs/corp-bundle.pem peel <URL> -o ./out/
```

H2 through a corporate proxy is the most fragile combination.
`--http-version h1` is the usual workaround when an H2-aware proxy
is doing something subtle wrong.

## No Homebrew formula

The crates.io publish is the primary distribution path. The GitHub
release attachments cover platforms where `cargo install` is not
convenient. A Homebrew formula is on the wish list but not yet in
place. PRs welcome at <https://github.com/agouin/peel>.

## Windows support

Not officially supported. The blocking backend and the codec
machinery are platform-neutral and should work, but:

- `io_uring` is Linux-only.
- `mmap` with `MADV_REMOVE` is Linux-only.
- The progress UI's terminal handling is tested on TTYs that behave
  like xterm. `cmd.exe` is not in the test grid.
- `--password-from prompt` reads `/dev/tty`, which does not exist on
  Windows.

WSL2 is a reasonable workaround and provides the full Linux path.
Native Windows support is open for contribution.

## Large on-disk part-file logical size

The part-file is **sparse**. The logical size is the full archive
length (`ls -la` shows the full size), while the **physical** size
on disk is the in-flight window (`du -h` shows actual usage):

```sh
$ ls -la out.peel.part
-rw-r--r--  ...  10737418240 ... out.peel.part   # 10 GiB logical
$ du -h out.peel.part
182M    out.peel.part                           # 182 MiB physical
```

Tools that ignore sparse files (some backup tools, some `tar`
implementations) see the logical size. The actual disk usage is the
physical size.

## Choosing `--max-disk-buffer`

Default 1 GiB rarely engages on a healthy disk. Tune it when:

- A hard ceiling on transient disk usage is required (CI runner
  with small `/tmp`).
- The network is much faster than the disk and the lookahead grows
  unboundedly before the decoder catches up.

Common values: 256 MiB on memory-constrained or disk-constrained
containers, default 1 GiB on a laptop or server, disable
(`--max-disk-buffer none`) on a high-bandwidth host where the
network burst should be absorbed fully into the buffer.

## Bench grid platform

The README's bench grid is single-machine, single-run on an Apple M4
Max. macOS was chosen because:

1. The reference CLIs (`zstd`, `xz`, `lz4`, `gzip`, `7z`, `unzip`,
   `unrar`) are all available as Homebrew packages with stable
   versions.
2. `peel`'s `blocking` backend is in use (no `io_uring` on macOS),
   so the grid measures the codec story alone. Linux-specific fast
   paths (mmap, io_uring) provide additional gains on top.

A Linux grid with the io_uring backend is in
[`internal/bench-results/`](https://github.com/agouin/peel/tree/main/internal/bench-results).

## Licensing

MIT OR Apache-2.0, at the user's option. The full text is at
[LICENSE-MIT](https://github.com/agouin/peel/blob/main/LICENSE-MIT)
and
[LICENSE-APACHE](https://github.com/agouin/peel/blob/main/LICENSE-APACHE).

The RAR3 and RAR5 decoders are **clean-room** implementations.
RARLAB's `unrar` source has not been consulted at any point. See
[Supported formats §RAR provenance](./formats.md#rar-provenance).

## Filing bugs or feature requests

GitHub Issues: <https://github.com/agouin/peel/issues>. Include the
output of `peel --version`, the command that was run, and (if
applicable) a `RUST_LOG=debug` log.
