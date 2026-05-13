# Encrypted archives

`peel` decrypts encrypted ZIP, 7z, and RAR5 archives. It never
encrypts. Re-encrypting an extracted stream to a different password
is out of scope; pipe to `7z` or `zip` for that.

The password is supplied via `--password-from <SOURCE>` and never
appears on the command line. `argv` is visible to every process on
the host and is the wrong default for a passphrase.

## Supported schemes at a glance

| Format | Scheme | KDF | Authenticated |
| --- | --- | --- | --- |
| zip | WinZip-AES (AE-1 / AE-2; AES-128/192/256-CTR) | PBKDF2-HMAC-SHA1, 1000 iterations | HMAC-SHA1-80 trailer |
| zip | PKWARE traditional "ZipCrypto" (CRC32-keyed PRGA) | password-derived 12-byte header | none (CRC32 of plaintext)¹ |
| rar5 | AES-256-CBC, archive-header encryption (type 4) | PBKDF2-HMAC-SHA256, `2^(kdf_count+15)` iterations | optional `pswcheck` |
| rar5 | AES-256-CBC, per-file encryption (extra record 1) | same as above (per-record salt / IV / `kdf_count`) | optional `pswcheck` |
| 7z | AES-256-CBC (coder id `06:F1:07:01`) | bespoke SHA-256 "round-tower" KDF | none (CRC32 of plaintext) |

¹ ZipCrypto is insecure: published 1994, broken under known-plaintext
attack. Supported only for compatibility with archives that already use it.

## Supplying a password

### `--password-from <SOURCE>`

| Source | Use it when | Notes |
| --- | --- | --- |
| `prompt` | Interactive terminal | Reads `/dev/tty` directly (so a piped stdin carrying archive data can't accidentally answer). Echo disabled. Up to 3 retries on wrong password. |
| `env:NAME` | CI / scripted runs | Reads the named environment variable. Strips a trailing newline; empty values are refused. |
| `file:PATH` | Long-lived credential files | Reads the first line of `PATH`. Modes other than `0600` emit a one-shot warning. |
| `fd:N` | Process substitution / `pass` integration | Reads from file descriptor `N` (until EOF or newline). `peel … --password-from fd:3 3< <(pass …)`. |

### Absence of `--password=<value>`

Process-list visibility (`ps aux`, `/proc/<pid>/cmdline`,
`Get-Process -IncludeUserName`) is the wrong default for a
passphrase. Every other source above keeps the password out of
`argv`. For a one-step non-interactive invocation, wrap with
`env:NAME`:

```sh
PEEL_PW="$(cat ~/.peel-passwords/dataset)" \
  peel "$URL" --password-from env:PEEL_PW -o ./out/
unset PEEL_PW
```

## Examples

### Interactive prompt

```sh
peel https://example.com/secret.zip -o ./out/ --password-from prompt
```

The prompt reads `/dev/tty`. Three failed attempts trigger exit
code 4.

### From an environment variable

```sh
PEEL_PW='hunter2' peel "$URL" --password-from env:PEEL_PW -o ./out/
```

### From a file

```sh
echo 'hunter2' > /root/.peel-pw
chmod 0600 /root/.peel-pw

peel "$URL" --password-from file:/root/.peel-pw -o ./out/
```

The `0600` chmod silences the mode warning.

### From an fd via process substitution

```sh
peel "$URL" --password-from fd:3 3< <(pass show archives/dataset) -o ./out/
```

Integrate with `pass`, `gopass`, `1password-cli`, or any other
passphrase manager that writes to stdout by piping its output into
an fd `peel` reads.

## RAR5 specifics

RAR5 has two independent encryption layers. An archive may use
either, both, or neither.

### Archive-header encryption (HEAD_CRYPT)

When present, every header after `HEAD_CRYPT` is AES-256-CBC
encrypted under a per-archive key. Each encrypted header is prefixed
by its own 16-byte IV and padded to a 16-byte boundary.

Data areas are not encrypted by this layer. They pass through
cleartext (or under per-file encryption, below). `peel`'s walker
switches into encrypted-header mode after parsing `HEAD_CRYPT`.

### Per-file data encryption (extra record type 1)

Each file header may carry an encryption record with its own salt,
IV, `kdf_count`, and optional `pswcheck`. When present, the file's
data area is AES-256-CBC encrypted under a per-file key.

Both layers share a single password (resolved once per archive). The
`kdf_count` byte is capped at the spec maximum of 24
(= `2^39` iterations) before key derivation runs.

When a checkpoint resumes a partially-extracted run, encrypted entries
restart from byte 0 on the in-flight entry. The CBC chain state
cannot yet be migrated across a checkpoint snapshot. The sink replays
the on-disk prefix to seed its hashes, so the user-visible bytes
remain byte-identical to a clean run.

## 7z specifics

7z has a single encryption shape: an AES-256-CBC coder (id
`06:F1:07:01`) at the front of a folder's coder chain.

The coder props blob encodes:

- `numCyclesPower` (low 6 bits of byte 0): the SHA-256 round-tower
  KDF runs `2^power` rounds.
- Optional salt (up to 16 bytes) and IV (up to 16 bytes), present
  when the high bits of byte 0 are set.

The KDF derives a 32-byte AES-256 key by hashing
`salt || password_utf16le || round_counter_le` for each of the
`2^power` rounds. The on-disk IV is zero-padded to 16 bytes if shorter.

7z has no in-archive password verifier (unlike RAR5's optional
`pswcheck` or ZIP-AES's 2-byte PBKDF2 verifier). The first
correctness signal is the per-substream CRC32 inside the decoded
plaintext. Under a wrong password the plaintext is random and the
CRC32 mismatches with overwhelming probability. `peel` translates
that into `EncryptionError::PasswordIncorrect` when it knows the
folder is encrypted.

All folders in an archive share one password (loaded lazily on the
first encrypted folder), matching 7-Zip's own behaviour. Resume
restarts the in-flight folder from byte 0, the same constraint as
RAR5's per-file encryption, for the same reason (CBC chain state).

## Exit code 4

Password-related failures use a dedicated exit code so scripts can
distinguish them from generic extraction failures:

- `0`: extraction completed.
- `1`: generic extraction or I/O failure.
- `4`: `PasswordIncorrect` or `PasswordMissing` anywhere in the
  error chain.
- `128 + signum`: graceful shutdown after SIGINT (130) or SIGTERM
  (143). The `.peel.part` / `.peel.ckpt` sidecars are left on disk;
  re-running resumes.

A retry loop on wrong password looks like:

```sh
while true; do
  peel "$URL" --password-from prompt -o ./out/ && break
  rc=$?
  if [ "$rc" != "4" ]; then
    echo "peel failed with code $rc (not a password issue)"; exit "$rc"
  fi
  echo "wrong password, retry"
done
```

## Threat model

`peel` decrypts. It does not authenticate the user. It has no
support for hardware tokens, smart cards, GPG-encrypted passphrases,
or biometric unlock. The user supplies a passphrase via one of the
`--password-from` sources; everything beyond that is the operating
system's responsibility.

`peel` does not protect against an attacker with:

- Read access to the process's address space (`/proc/<pid>/mem` on
  Linux, `vmmap` on macOS). The internal `Password` wrapper zeroises
  its backing storage on drop, but a snapshot taken during key
  derivation will see the cleartext.
- Read access to the swap device. If the machine swaps
  mid-extraction the passphrase may be written to disk. Disable
  swap for the workload if this matters.
- Read access to `argv`, which is precisely why `--password=<value>`
  does not exist.
- Precise micro-architectural timing side-channels (Spectre-class,
  cache-timing on a co-located VM). Tag comparisons go through a
  length-stable `ct_eq` function, but the underlying AES / HMAC
  primitives are not cycle-constant.

`peel` does apply the following discipline:

- Every cryptographic primitive ships with a differential test suite
  cross-checking against a reference upstream crate (`sha1`, `hmac`,
  `pbkdf2`, `sha2`, `aes`, `ctr`, `cbc`). The runtime binary links
  none of these.
- Tag and verifier comparisons route through `crypto::ct_eq`.
- Password bytes never travel through any code path that prints
  `Debug`. The `Password` type explicitly redacts.
- All KDF iteration counts come from the archive's header. `peel`
  does not guess a sensible default.

## Out of scope, permanently

- Re-encrypting on the fly. `peel` never encrypts. "Decrypt this
  remote archive and re-encrypt to a different password" is not a
  `peel` job.
- Password-protected gzip / xz / lz4 / zstd. None of these formats
  has a native encryption layer; the convention "GPG-encrypted
  tarball" is a separate pipeline.
- ZIP central-directory encryption (PKWARE strong-encryption spec,
  general-purpose flag bit 6). Used by approximately one product
  outside enterprise contexts. Surfaces as
  `unsupported feature: PKWARE strong encryption`.
- Hardware-accelerated AES (AES-NI). Software AES first; a
  runtime-probed AES-NI path may land later behind a feature flag.

## Verifying the primitives

Every primitive ships with a differential test suite that runs
≥ 1000 random inputs through both `peel`'s implementation and the
upstream reference crate, asserting byte-identical output. The corpus
also includes known-answer vectors from the format specs themselves
(FIPS 197 for AES, RFC 3174 for SHA-1, NIST SP 800-132 for PBKDF2).

```sh
cargo test --tests test_crypto_diff
```

The reference crates pinned in `[dev-dependencies]` are `sha1`,
`hmac`, `pbkdf2`, `aes`, `ctr`, `cbc`, `sha2`, `blake2`. The runtime
binary links none of these.
