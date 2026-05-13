# Exit codes

`peel` uses a small, stable set of exit codes so wrapper scripts can
distinguish failure modes without parsing stderr.

| Code | Meaning |
| --- | --- |
| `0` | Extraction completed successfully |
| `1` | Generic extraction or I/O failure (everything not covered below) |
| `2` | CLI argument parse error (clap-handled; not user-distinct) |
| `4` | `PasswordIncorrect` or `PasswordMissing` anywhere in the error chain |
| `128 + signum` | Graceful shutdown after a signal (130 = SIGINT, 143 = SIGTERM); sidecars left on disk for resume |

## Code 0

The extracted output is complete and, if `--sha256` was set, matches
the expected hash. The `.peel.part` and `.peel.ckpt` sidecars have
been unlinked.

In `-k` and `--keep-archive` mode, the source archive is at its final
location.

In `--no-extract` mode, the downloaded source bytes are at `-o`, or at
the URL basename if `-o` was omitted.

## Code 1

Something else went wrong: disk full, network exhausted retries, the
source disappeared mid-run, the checkpoint format is incompatible,
format detection failed under `--strict-format`, or the SHA-256 digest
did not match.

The error message on stderr identifies the cause. Examples:

| Error message | Cause |
| --- | --- |
| `No space left on device` | Output filesystem full |
| `digest mismatch: expected …, got …` | `--sha256` value disagrees with the streamed bytes |
| `source changed during run` | Per-chunk CRC32C fingerprint disagrees on resume |
| `format detection failed, --strict-format set` | `--strict-format` is on and neither URL suffix nor magic identifies a registered decoder |
| `mirror https://… : 502 Bad Gateway` (after retries) | All mirrors exhausted |
| `checkpoint format version 6 not compatible with this peel build (current: 7)` | Older sidecar; delete it or use a compatible `peel` version |

The sidecars (`.peel.part`, `.peel.ckpt`) are left in place on a
code-1 exit so that a follow-up run can either resume (if the cause
was transient) or be cleaned up explicitly.

## Code 4

A password issue: the wrong password was supplied, no password was
supplied for an encrypted archive, or `--password-from prompt`
exhausted its 3 retries.

This is a separate code so that scripts can **re-prompt** without
conflating it with a genuine extraction failure. A retry loop:

```sh
while true; do
  peel "$URL" --password-from prompt -o ./out/ && break
  rc=$?
  if [ "$rc" != "4" ]; then
    echo "peel failed with code $rc (not a password issue)" >&2
    exit "$rc"
  fi
  echo "wrong password, retry" >&2
done
```

See [Encrypted archives](./encryption.md) for the full encryption
discussion.

## Codes 130 and 143 (signal exits)

`peel` traps SIGINT (Ctrl-C) and SIGTERM and exits with
`128 + signum` (130 for SIGINT, 143 for SIGTERM). On graceful
shutdown:

- The current checkpoint is flushed and `fsync`'d.
- The `.peel.part` and `.peel.ckpt` sidecars are **left on disk**.
- Re-running the same command resumes from the last checkpoint.

`SIGKILL` (`kill -9`) does **not** get a graceful shutdown. The
process dies immediately. An ungraceful kill is still safe to resume
from: the last completed checkpoint is on disk, the per-chunk
fingerprints catch the in-flight chunk's partial bytes, and the next
run reconciles.

## Code 2 (clap parse error)

CLI argument parsing errors (unrecognised flag, conflicting flags,
wrong value type) come from `clap` and exit code 2. The error
message names the offending argument:

```text
error: the argument '--no-extract' cannot be used with '--format <NAME>'

Usage: peel --no-extract [URLS]...

For more information, try '--help'.
```

This is not user-distinct. It follows the standard `clap` convention
and matches `cargo`, `rustup`, and most modern Rust CLIs.

## Scripting against the codes

A common pattern distinguishes "user error" (retry with different
inputs), "transient error" (retry with the same inputs), and "give
up":

```sh
#!/usr/bin/env bash
set -u

URL=$1
OUT=$2

peel "$URL" -o "$OUT" --password-from env:PEEL_PW
rc=$?

case "$rc" in
  0)
    echo "ok"; exit 0 ;;
  4)
    echo "wrong password: set PEEL_PW correctly and retry"; exit 4 ;;
  130|143)
    echo "interrupted; re-run to resume"; exit "$rc" ;;
  *)
    echo "peel failed; sidecars at ${OUT}.peel.part / ${OUT}.peel.ckpt"; exit "$rc" ;;
esac
```

On `kill -9`, `peel` does not get to set an exit code. The parent
sees `137` (`128 + 9`), which `peel` itself never produces. That
state is still resumable: the next run picks up the sidecars.
