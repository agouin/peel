# Plan: password-protected archives (zip, rar5, 7z)

> **Status: scoped, not started (2026-05-11).** Today every encrypted
> entry surfaces as `RarError::UnsupportedFeature` /
> `ZipError::UnsupportedFeature` /
> `SevenZError::UnsupportedFeature` with a clear message — a
> deliberate "fail loudly" choice during the MVP. This plan turns
> those refusals into actual decryption support for the three
> formats users hit in the wild. The streaming-compression formats
> (gzip, xz, lz4, zstd, tar) have no native password support and
> are out of scope.

## Motivation

Encrypted archives are common in three real-world places peel is
already aimed at:

1. **Vendor / partner deliverables** — datasets shared via password-
   protected zip or 7z is a corporate-IT default.
2. **Personal backups** — rar5 with archive encryption is a popular
   "ship a drive somewhere" format on Windows.
3. **CTFs / forensic artefacts** — usually 7z or rar5, often with
   non-trivial KDF parameters.

In all three cases the user knows the password and just wants peel
to do the same thing it does for unencrypted archives. Today they
get told "feature not supported"; that is the right error message
but it caps peel's usefulness short of parity.

## Scope by format

| Format | Encryption scheme(s) | KDF | Auth |
|--------|---------------------|-----|------|
| zip — ZipCrypto | RC4-variant (PKWARE 1989) | password-derived 12-byte header | none (CRC32 check only) |
| zip — AES (WinZip) | AES-128/192/256-CTR | PBKDF2-HMAC-SHA1, 1000 iterations | HMAC-SHA1-80 (truncated) |
| rar5 | AES-256-CTR | PBKDF2-HMAC-SHA256, configurable iterations | optional CHECK record (HMAC-SHA256) |
| 7z | AES-256-CBC | SHA-256 round-tower KDF | none (CRC32 of plaintext) |

All four cases are well-specified; the format implementations
already parse the metadata that signals encryption (see the
`is_encrypted` checks linked above). What's missing is the
decryption coder itself + key-derivation + password-source CLI.

## Hard constraints

- Std-first crypto. We already have hand-rolled SHA-256
  (`src/hash/sha256.rs`) and BLAKE2sp (`src/hash/`). We add:
  hand-rolled AES-128/192/256, HMAC-SHA1, HMAC-SHA256, PBKDF2. No
  new dependencies. Crypto crates are not pre-approved in
  `ENGINEERING_STANDARDS.md` §2 and adding `aes`, `pbkdf2`, `hmac`,
  `sha1` would be a meaningful audit-surface bump. Cross-checked
  against the existing `dev-dependencies` (`sha2`, `blake2`)
  pattern: reference impls in `dev-dependencies`, production
  binary links nothing.
- Constant-time comparisons for HMAC checks and password
  verification. Side-channel discipline is already implicit in our
  hash modules; codify it for the AES/HMAC paths.
- Passwords stay in memory only as long as needed. Read into a
  `secrecy`-style wrapper (hand-rolled — see std-first rule) that
  zeroises on drop. No CLI-arg leakage in `argv`.
- No KDF "convenience" defaults. The format dictates iterations
  and salt; we don't second-guess.
- Encryption is **read-only**. peel never encrypts. The "create an
  encrypted archive" feature is out of scope, permanently.

## Out of scope

- Re-encrypting on the fly (e.g. "decrypt this remote archive and
  re-encrypt to a different password locally"). Not a peel job.
- Password-protected gzip / xz / lz4 / zstd. None of these formats
  have a native encryption layer; the convention "gpg-encrypted
  tarball" is a separate pipeline that we don't try to subsume.
- ZIP traditional PKWARE encryption (the original "ZipCrypto"
  scheme). Insecure, deprecated, and rare in modern outputs. We
  acknowledge it but defer; the rate of real-world `.zip` archives
  using it is low and they're trivially crackable for the user
  who needs them. Revisit if a real consumer surfaces. (Strong
  candidate to ship anyway because it's tiny — see §1 for the
  reversal.)
- ZIP central-directory encryption (PKWARE strong encryption
  spec). Used by exactly nobody outside SecureZIP; out of scope
  unless an actual user shows up.
- Hardware-accelerated AES (AES-NI). Software AES first; if
  benchmarks justify it, route to AES-NI through a runtime probe
  later — separate plan.

---

## §1. Password-source CLI surface

**What**: how the user supplies a password.

**Why first**: all four format-specific paths share this; getting
it right once avoids re-litigating the UX.

**Sketch**:

1. New CLI flag `--password-from <SOURCE>` accepting:
   - `prompt` (default if any entry is encrypted): read once from
     `/dev/tty` (never from stdin, since stdin may carry archive
     data), no echo. Same machinery as `sudo`. Reuse rather than
     reimplement: peel today does not have prompt code, so this is
     ~30 LOC behind an abstraction trait.
   - `env:NAME`: read from the named environment variable. Strip
     trailing newline, error on empty.
   - `file:PATH`: read from a file (first line, newline stripped).
     File mode must be `0600` or peel emits a warning.
   - `fd:N`: read from the given file descriptor (one-shot, as
     many bytes as available until EOF or newline). Compatible
     with shell `< <(…)` redirections.
2. **No `--password=foo` flag in `argv`.** Process-list visibility
   is the wrong default; users who really want it can still pass
   `--password-from env:PEEL_PASSWORD PEEL_PASSWORD=foo peel …`.
   This decision is documented in `--help` so the user understands
   why the flag they're looking for isn't there.
3. Multiple passwords per run: an encrypted archive uses one
   password. If the user supplies a wrong password, peel surfaces
   that distinctly from "archive corrupt" — and asks again on the
   prompt source, up to 3 attempts. Non-prompt sources fail-fast
   after 1 attempt.
4. `Password` wrapper type in `src/secret.rs` (new module):
   `Vec<u8>` that zeroises on drop, denies `Debug` formatting, and
   exposes a single `as_bytes(&self) -> &[u8]` accessor. Hand-roll
   the zeroise — `std::ptr::write_volatile` per byte, no
   `zeroize` crate.

**Demo**: `peel encrypted.zip -C out/` prompts for a password,
extracts on success; `peel encrypted.zip -C out/ --password-from
env:PW PW=test` extracts non-interactively; wrong password produces
`PasswordIncorrect` error distinguishable from `ArchiveCorrupt`.

---

## §2. Crypto primitives module

**What**: pure-Rust AES, HMAC, PBKDF2, with cross-checks against
reference crates in `dev-dependencies` only.

**Why now**: every format depends on this. Building it once,
shared across zip/rar/7z, beats three near-copies.

**Sketch**:

1. New crate path: `src/crypto/`. Modules:
   - `aes.rs`: AES-128/192/256 ECB primitive (the building block).
     Constant-time implementation; the differential test suite
     uses the `aes` crate at `dev-dependencies` only.
   - `aes_modes.rs`: CTR and CBC modes layered on the ECB
     primitive. CTR uses big-endian counter increments
     (matches zip-AES and rar5; 7z's CBC uses a 16-byte IV from
     the archive's per-folder metadata).
   - `hmac.rs`: generic HMAC<H>, instantiated as
     `Hmac<Sha1>` and `Hmac<Sha256>`. The output truncation for
     zip-AES (10 bytes of 20) is at the call site, not in the HMAC
     itself.
   - `sha1.rs`: hand-rolled SHA-1 (yes, even though SHA-1 is
     broken — zip-AES uses it in PBKDF2 and HMAC; the format
     spec calls for it). Cross-check against `sha1` crate in
     `dev-dependencies`.
   - `pbkdf2.rs`: generic PBKDF2<Hmac>. The iteration count is a
     parameter; per-format defaults live in the format's parser
     (rar5 iterations come from the archive header; zip-AES is
     a fixed 1000; 7z uses a non-PBKDF2 round-tower).
   - `sevenz_kdf.rs`: 7z's bespoke KDF — the round-tower scheme
     defined in `7zFormat.txt`. It uses `power` (number of rounds
     = 2^power) and a salt, hashed into SHA-256 sequentially.
     Not PBKDF2; one module for one use site.
2. Differential test corpus: for each primitive, encode 1 000+
   random inputs through both peel's impl and the reference crate
   from `dev-dependencies`, assert byte-identical output. Pattern
   lifted from the existing
   [`test_xz_native.rs`](../tests/test_xz_native.rs) cross-check.
3. Constant-time discipline: all key comparison and tag
   verification goes through one helper
   `crypto::ct_eq(&[u8], &[u8]) -> bool` with a comment explaining
   the timing-attack threat model.
4. No multi-threading inside the crypto code. CTR mode is
   parallelisable but we don't pursue it in this plan; the
   per-frame parallel decode plan from `OPTIMIZATIONS.md` is a
   different axis.

**Demo**: `cargo test --test test_crypto_diff` exercises 1 000
random vectors per primitive against the reference impls;
known-answer tests from the format specs land as fixed-input
asserts.

---

## §3. ZIP-AES decryption

**What**: WinZip-AES (compression method 99, the AE-1/AE-2
"strong" encryption that's actually deployed). PKWARE traditional
encryption (`is_encrypted` bit 0) is also handled because it's
~50 LOC after AES is in place.

**Why before rar5 / 7z**: ZIP is the most common encrypted-archive
format users ask about, and the AES wiring is the simplest of the
three (no header encryption, no key cache, no archive-level
encryption blob — just a per-entry transform).

**Sketch**:

1. `src/zip/format.rs`: the entry parser already detects encryption
   bits. Today it errors; instead, when AES (method 99) is set,
   parse the AES extra field (header ID `0x9901`):
   - 2 bytes: AES extra field version (`0x0001` or `0x0002`).
   - 2 bytes: vendor ID (`"AE"`).
   - 1 byte: AES strength (`0x01` = AES-128, `0x02` = AES-192,
     `0x03` = AES-256).
   - 2 bytes: actual compression method (replaces method 99 for
     decoding).
2. `src/zip/decode.rs`: when an entry is encrypted, wrap the
   `Read` chain:
   ```
   raw_entry_bytes → AesCtrReader → decompressor → output
   ```
   `AesCtrReader` consumes the entry's salt (8/12/16 bytes
   depending on strength), the 2-byte password-verification value,
   and the trailing 10-byte HMAC-SHA1-80. Verifies the password
   against the verification value; verifies the HMAC at EOF.
   Mismatch → `PasswordIncorrect` or `IntegrityCheckFailed`.
3. PBKDF2-HMAC-SHA1 with 1000 iterations to derive a key block of
   `keysize + keysize + 2` bytes: AES key, HMAC key, password
   verification value.
4. Local-header-only ZIPs (the streaming case, no central
   directory yet) cannot verify the HMAC until they've consumed
   the entry; same constraint as the existing CRC32 check —
   surface mismatch as a clean error after the last byte.
5. Tests: round-trip fixtures generated via `unzip`/`zip` and
   `7z a -p`. KAT vectors from the WinZip spec.

**Demo**: `peel encrypted.zip -p prompt -C out/` extracts
correctly; tampered HMAC trailer fails with
`IntegrityCheckFailed`; wrong password fails with
`PasswordIncorrect` before any decompression starts.

---

## §3b. ZIP ZipCrypto (PKWARE traditional encryption)

**What**: the original ZIP encryption: three 32-bit keys, RC4-ish
PRGA driven by CRC32. Insecure, but ubiquitous in legacy archives.

**Why opportunistic**: implementation is ~150 LOC; we already
have CRC32. Including it here costs almost nothing once the
ZIP-AES plumbing is in place.

**Sketch**:

1. `src/zip/encrypt_legacy.rs`: PKWARE keystream generator. The
   first 12 bytes of each entry are the encryption header; the
   last byte must equal the high byte of the CRC32 of the
   plaintext (which we know from the entry's central-directory
   record).
2. Wire it as another `Read` adapter, peer of `AesCtrReader`.
3. Tests: round-trip fixtures generated via `zip -e`.
4. **Caveat banner**: when a ZipCrypto entry is encountered, emit
   a one-shot `tracing::warn!` at info level: "this archive uses
   the legacy ZIP encryption from 1989, which provides no real
   confidentiality." We extract it; we tell the user it isn't
   secret.

**Demo**: `peel zipcrypto.zip -p prompt -C out/` extracts; warning
appears once.

---

## §4. RAR5 archive + file encryption (**shipped**)

**Status: shipping (2026-05-12).** Both encryption layers extract
end-to-end; integration coverage in `tests/test_coordinator_rar.rs`
exercises round-trip extraction, wrong-password (→
`PasswordIncorrect`), and missing-password (→ `PasswordMissing`) for
each layer.

**What**: rar5's AES-256-CBC encryption (the spec table earlier in
this doc mistakenly listed it as CTR — the wire format is CBC), both
at the file level (per-entry) and at the archive-header level (every
header after HEAD_CRYPT is encrypted).

**Why now**: rar5 already has the deepest decoder work in peel;
keeping it at feature parity matters.

**Sketch**:

1. `src/rar/header.rs` (the existing parser): when an archive-
   encryption header (type 4) is present, the body cannot be
   parsed without first deriving the archive key from the
   password and decrypting the rest of the file headers. Today
   this is the `feature: "encryption (header)"` error
   (`src/rar/archive.rs:162`).
2. Key derivation: PBKDF2-HMAC-SHA256 with `iterations =
   1 << (kdf_count + 15)` (per the rar5 spec; `kdf_count` is in
   the encryption header, capped at 24 = 2^39 iterations which is
   absurd but valid). Salt + initial vector come from the
   encryption header.
3. CTR mode with the 16-byte block IV. After each file, the IV
   resets per entry (each file's encryption block carries its own
   IV).
4. Password verification: the encryption header includes an
   optional CHECK value — a truncated HMAC-SHA256 of a known
   constant. Verify before reading any encrypted bytes. If the
   archive doesn't carry CHECK (older rar5), we cannot tell good
   from bad password before decompression fails; surface as
   "password may be incorrect, or archive corrupt."
5. File encryption block (header type 6, the file-level
   encryption record that precedes each encrypted file's data) is
   parsed the same way; per-file IVs are XORed into the archive
   key to form the per-file key.
6. Tests: fixtures generated with `rar` (the WinRAR Linux CLI) at
   multiple iteration counts.

**Demo**: `peel encrypted.rar -C out/` extracts; tampered file
data surfaces the existing rar5 BLAKE2sp integrity error;
encryption-header tampering surfaces `PasswordIncorrect` (when
CHECK is present) or `IntegrityCheckFailed` (when it isn't).

---

## §5. 7z AES-256-CBC decryption (**shipped**)

**Status: shipping (2026-05-12).** The AES coder dispatch, KDF,
CBC decryption, and post-decrypt CRC32 → `PasswordIncorrect`
translation all land end-to-end. Integration coverage in
`tests/test_coordinator_sevenz.rs` exercises round-trip
extraction, wrong-password (→ `PasswordIncorrect`), and
missing-password (→ `PasswordMissing`). Spec compliance is
verified against a real `7z a -mx0 -p<pw>` fixture as a one-off
cross-check (not committed to CI to avoid the host-binary
dependency).

**What**: 7z's per-folder AES coder (coder ID `06 F1 07 01`).

**Why now**: completes the trio. 7z's KDF is the only bespoke
piece (the rest is AES-CBC, which §2 already provides).

**Sketch**:

1. `src/sevenz/codec.rs` (or wherever the coder dispatch lives):
   today the AES coder ID is rejected as "AES-256 encryption".
   Replace with construction of a `Sevenz256Cbc` filter chain
   element.
2. Filter chain wiring: 7z lists coders per folder, possibly
   chained (encryption + LZMA2 + delta, etc.). The encryption
   coder consumes a 1-byte "properties" header encoding `power`
   (key-strengthening rounds = 2^power) and 0–32 bytes of salt +
   0–16 bytes of IV. Decode this, run §2's `sevenz_kdf` to derive
   the 32-byte AES key, then chain CBC under whichever coder
   comes next.
3. Password verification: 7z has no integrity tag on encrypted
   content; the post-decryption CRC32 is the only check. Wrong
   password produces a CRC mismatch on the first entry that
   completes. Surface as "password may be incorrect, or archive
   corrupt" — same UX as legacy rar5.
4. Tests: fixtures generated with `7z a -p` at various iteration
   counts and IV lengths.

**Demo**: `peel encrypted.7z -C out/` extracts a multi-entry
archive; mid-archive password mismatch is detected at the first
CRC32 check, not silently in extracted garbage.

---

## §6. Error surface unification

**What**: a single `EncryptionError` enum used by all three
formats, mapped onto their respective top-level error types.

**Sketch**:

```rust
pub enum EncryptionError {
    PasswordIncorrect,
    PasswordMissing,                // archive needs one, user didn't supply
    IntegrityCheckFailed,           // tag/HMAC mismatch with correct password
    UnsupportedKdf { detail: String },
    UnsupportedCipher { detail: String },
}
```

Each format's existing error type gains an
`Encryption(EncryptionError)` variant. The CLI binary maps
`PasswordIncorrect` to exit code 4 (new, distinguishable from
generic "extraction failed" code 1).

**Demo**: a smoke test that wrong-passwords every format
produces consistent error messages and the right exit codes.

---

## §7. Documentation + threat-model note

**What**: a short doc explaining what peel does and doesn't
guarantee on the cryptographic side.

**Sketch**:

1. `docs/ENCRYPTION.md`: list of supported schemes (§3–§5),
   explicit non-support for ZIP central-directory encryption and
   anything not in the §-table.
2. Threat model: peel decrypts; it does not authenticate the user
   (no support for hardware tokens, smart cards, GPG-encrypted
   passphrases, etc.). It does not protect against an attacker
   with read access to `argv`, `/proc/<pid>/mem`, or the swap
   device; password lifetimes are minimised but Rust cannot
   prevent OS-level capture.
3. Audit pointer: every primitive in `src/crypto/` is
   cross-checked against the reference crate it shadows. The
   reference crates are listed in the README so a reviewer can
   reproduce the differential corpus.
4. Add ENCRYPTION.md to the list at the top of `CLAUDE.md` once it
   exists.

**Demo**: the doc exists, is consistent with what the code does,
and the differential cross-check tests are listed.

---

## What "feature done" means

1. Encrypted fixtures (one per scheme: zip-AES-128/192/256,
   zipcrypto, rar5 with and without CHECK, 7z at multiple powers)
   round-trip extract identically under peel and the reference
   CLI.
2. Wrong password produces `PasswordIncorrect` for schemes that
   carry a verifier; for schemes that don't, the first integrity
   check surfaces it with a clear "may be wrong password" message.
3. `--password-from prompt` works on a real TTY and exits cleanly
   on Ctrl-C without leaking the password (or partial password)
   to the next process.
4. The `Password` wrapper zeroises on drop, denies `Debug`, and is
   the only type that crosses module boundaries with raw
   passphrase bytes.
5. Coverage thresholds in `ENGINEERING_STANDARDS.md` §5.1 hold for
   every new module under `src/crypto/`, `src/secret.rs`, and the
   modified format modules.
6. `docs/ENCRYPTION.md` exists and is linked from `CLAUDE.md`.
