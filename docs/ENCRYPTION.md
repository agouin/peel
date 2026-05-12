# Encryption

This document is the user-facing summary of which encrypted-archive
schemes peel can decrypt, which it refuses (and why), and the threat
model the implementation is engineered against. The implementation
plan lives in [`PLAN_archive_encryption.md`](PLAN_archive_encryption.md);
this file is the shipping-feature surface.

## Supported schemes

| Format | Scheme | KDF | Authenticated | Status |
|--------|--------|-----|---------------|--------|
| zip | WinZip-AES (AE-1 / AE-2; AES-128/192/256-CTR) | PBKDF2-HMAC-SHA1, 1000 iterations | HMAC-SHA1-80 trailer | shipping (§3) |
| zip | PKWARE traditional "ZipCrypto" (CRC32-keyed PRGA) | password-derived 12-byte header | none (CRC32 of plaintext) | shipping (§3b) — *insecure* |
| rar5 | AES-256-CBC, archive-header encryption (type 4) | PBKDF2-HMAC-SHA256 with `iterations = 1 << (kdf_count + 15)` | optional pswcheck (8-byte truncated HMAC-SHA256) | **not yet** (§4 lays the parser groundwork; decryption pending) |
| rar5 | AES-256-CBC, per-file encryption (extra record 1) | same as above | optional pswcheck (8-byte truncated) | **not yet** (§4) |
| 7z | AES-256-CBC (coder id `06:F1:07:01`) | bespoke SHA-256 "round-tower" KDF (`crate::crypto::sevenz_kdf`) | none (CRC32 of plaintext) | **not yet** (§5 wires recognition + error surface; decryption pending) |

The "**not yet**" rows surface a clean
[`EncryptionError::UnsupportedCipher`](../src/encryption.rs) at the
binary boundary with a precise detail message; the same shape and exit
code (4) the shipping ZIP paths use. Scripts that catch encrypted
archives can match on the error chain regardless of format.

## Supplying a password

Every encrypted path consumes a password via the
[`--password-from <SOURCE>`](../src/cli.rs) flag added in
[`PLAN_archive_encryption.md`](PLAN_archive_encryption.md) §1. Four
sources are supported:

- `prompt` — reads `/dev/tty` directly (never stdin, so a piped stdin
  carrying archive data cannot accidentally answer the prompt). Echo
  is disabled while reading. Up to 3 attempts on a wrong password
  before peel exits with code 4.
- `env:NAME` — reads the named environment variable. Strips a trailing
  newline; empty values are refused.
- `file:PATH` — reads the first line of `PATH`. peel emits a warning
  when the file's mode is not `0600`.
- `fd:N` — reads from file descriptor `N` (one-shot, until EOF or
  newline). Compatible with shell `< <(…)` redirections.

peel deliberately does **not** accept a `--password=<value>` flag.
Process-list visibility (`ps`, `/proc/<pid>/cmdline`) is the wrong
default for a passphrase; users who really want this can wrap with
`env:NAME PEEL_PW=… peel … --password-from env:PEEL_PW`.

Exit codes:

- `0` — extraction completed.
- `1` — generic extraction or I/O failure (anything not below).
- `4` — `EncryptionError::PasswordIncorrect` or
  `EncryptionError::PasswordMissing` anywhere in the error chain.
  Scripts that want to re-prompt distinguish password issues from
  archive corruption by checking this code.
- `128 + signum` — graceful shutdown after SIGINT (130) or SIGTERM
  (143). The `.peel.part` / `.peel.ckpt` sidecars are left on disk;
  re-running resumes.

## Threat model

peel **decrypts**. It does not authenticate the user; it has no
support for hardware tokens, smart cards, GPG-encrypted passphrases,
or biometric unlock. The user supplies a passphrase via one of the
[`--password-from`](#supplying-a-password) sources; everything beyond
that is the operating system's responsibility.

peel does **not** protect against an attacker with:

- read access to the process's address space (`/proc/<pid>/mem` on
  Linux, `vmmap` on macOS). The
  [`Password`](../src/secret.rs) wrapper zeroises its backing
  storage on drop via `ptr::write_volatile`, but a snapshot taken
  while the key derivation is in flight will see the cleartext.
- read access to the swap device. If the machine swaps mid-extraction
  the passphrase may be written to disk.
- read access to `argv` (which is precisely why `--password=<value>`
  does not exist).
- a precise micro-architectural timing side-channel (Spectre-class,
  cache-timing on a co-located VM). Tag comparisons go through
  [`crypto::ct_eq`](../src/crypto.rs) which is constant-time
  relative to the *length* of its inputs; that defends against the
  byte-walking class of timing attack but does not defend against
  attackers measuring cycle-level timing of the underlying AES /
  HMAC primitives.

peel **does** apply the following discipline:

- Every cryptographic primitive in [`src/crypto/`](../src/crypto.rs)
  is differentially cross-checked against a reference upstream crate
  pinned in `[dev-dependencies]` (`sha1`, `hmac`, `pbkdf2`, `sha2`,
  `aes`, `ctr`, `cbc`). The runtime binary does not link any of these
  crates; the reference implementations exist only so a reviewer can
  reproduce the corpus.
- Tag / verifier comparisons route through `crypto::ct_eq`. Password
  bytes never travel through any code path that prints `Debug`
  (the `Password` type explicitly redacts).
- All KDF iteration counts come from the archive's header; peel does
  not "guess" a sensible default. RAR5's `kdf_count` byte is capped
  at the spec maximum of 24 (= 2^39 iterations) before key
  derivation runs.

## Out of scope — permanently

- **Re-encrypting on the fly.** peel never encrypts. "Decrypt this
  remote archive and re-encrypt to a different password locally" is
  not a peel job; pipe to `7z` / `zip` if you need that.
- **Password-protected gzip / xz / lz4 / zstd.** None of these formats
  has a native encryption layer; the convention "GPG-encrypted
  tarball" is a separate pipeline.
- **ZIP central-directory encryption** (PKWARE strong-encryption
  spec, general-purpose flag bit 6). Used by approximately one
  product (SecureZIP) outside specific enterprise contexts. peel
  surfaces it as `ZipError::UnsupportedFeature { feature: "PKWARE
  strong encryption" }`.
- **Hardware-accelerated AES (AES-NI).** Software AES first; if
  benchmarks justify it later, a runtime-probed AES-NI path lives
  behind a feature flag. The plan deliberately keeps the production
  binary single-implementation.

## Verifying primitives

Every primitive in [`src/crypto/`](../src/crypto.rs) ships with a
differential test suite that runs ≥ 1000 random inputs through both
peel's implementation and the upstream reference crate, asserting
byte-identical output. The corpus also includes the known-answer
vectors from the format specs themselves (FIPS 197 for AES, RFC 3174
for SHA-1, NIST SP 800-132 for PBKDF2). To reproduce:

```sh
cargo test --tests test_crypto_diff
```

The reference crates this test pins against are listed in
[`Cargo.toml`](../Cargo.toml) under `[dev-dependencies]`: `sha1`,
`hmac`, `pbkdf2`, `aes`, `ctr`, `cbc`. The runtime binary links **none**
of these.

## See also

- [`PLAN_archive_encryption.md`](PLAN_archive_encryption.md) — the
  implementation plan this feature traces against.
- [`ENGINEERING_STANDARDS.md`](ENGINEERING_STANDARDS.md) §Dependency
  Policy — the "std-first, vetted-crates second, novel-deps almost
  never" rule that motivates the hand-rolled crypto module.
- [`src/encryption.rs`](../src/encryption.rs) — the shared
  `EncryptionError` enum.
- [`src/secret.rs`](../src/secret.rs) — the `Password` zeroising
  wrapper and `--password-from` parser.
