# Supported formats

Every format `peel` decodes is hand-rolled or wraps a vetted upstream
crate. The binary does not shell out to `tar`, `unzip`, `7z`, or
`unrar`. See [How it works](./how-it-works.md) for the architecture.

## Detection

`peel` resolves the archive shape with a two-step fallback:

1. **URL-suffix.** The last component of the URL is matched against a
   list of known suffixes (`.tar`, `.tar.zst`, `.zst`, `.tar.xz`,
   `.xz`, `.tar.lz4`, `.lz4`, `.tar.gz`, `.gz`, `.zip`, `.7z`, `.rar`).
2. **Magic-byte fallback.** If the suffix doesn't match, `peel`
   issues a tiny initial GET for the first ~16 bytes of the source
   and matches the magic.

A mismatch between suffix and magic (for example, a URL ending in
`.tar.zst` but bytes starting with the gzip magic `0x1f8b`) fails
closed. Override with one of:

- `--force-format-from-magic`: trust the magic, ignore the suffix.
- `--format <NAME>`: bypass detection entirely.

If neither suffix nor magic matches a registered decoder, the default
behaviour is to warn once and fall through to `--no-extract`. The
remote object is saved under its URL basename. `--strict-format`
converts that warning to a fatal error.

## Format matrix

| Format | Streaming | Resume granularity | Encryption | Multi-volume |
| --- | --- | --- | --- | --- |
| `.tar` (uncompressed) | ✓ | per tar member | n/a | n/a |
| `.zst` / `.tar.zst` | ✓ | per zstd block | n/a | n/a |
| `.xz` / `.tar.xz` | ✓ | per LZMA2 chunk | n/a | n/a |
| `.lz4` / `.tar.lz4` | ✓ | per lz4 block | n/a | n/a |
| `.gz` / `.tar.gz` | ✓ | per deflate block¹ | n/a | n/a |
| `.bz2` / `.tar.bz2` / `.tbz2` / `.tbz` | ✓ | per bzip2 block | n/a | n/a |
| `.zip` | per-entry² | per entry + intra-entry³ | WinZip-AES, ZipCrypto | spanned ZIP (`.zNN` + `.zip`) |
| `.7z` | per-folder⁴ | per folder | AES-256-CBC (SHA-256 KDF) | `.7z.001`/`.002`/… |
| `.rar` (RAR5) | per-entry⁵ | per entry + intra-entry⁶ | AES-256-CBC (header + per-file) | `.part0001.rar`/… |
| `.rar` (RAR3/RAR4 legacy) | per-entry⁷ | per entry + intra-entry⁷ | queued | RAR3 multi-volume queued |

Footnotes below.

## Streaming codecs (`.tar.*`, raw codecs)

### `.tar` (uncompressed)

Plain POSIX tar. `peel` recognises `ustar` (`0x75 0x73 0x74 0x61 0x72`
at offset 257) and emits each entry to its final path as the member
header arrives. Hard links, symlinks, and long-name extensions are
all supported.

### `.zst` / `.tar.zst`

Streaming Zstandard. The decoder is hand-rolled in
`src/decode/zstd/`. Resume is per-block: the checkpoint snapshots
the decoder state at every zstd block boundary, so a `kill -9`
mid-archive picks up at the next block.

The `zstd` crate in `[dependencies]` exists for decoding zstd-coded
ZIP entries only. The streaming `.tar.zst` / `.zst` path is
hand-rolled.

### `.xz` / `.tar.xz`

Streaming XZ (LZMA2). The hand-rolled decoder in
`src/decode/xz_liblzma/` is per-cycle-equivalent to `liblzma` (see
the bench grid in the project README). Resume is per LZMA2 chunk.

### `.lz4` / `.tar.lz4`

Streaming LZ4 Frame Format. Frame parsing is hand-rolled; the inner
block-layer decompression uses the `lz4_flex` crate's
`block::decompress_into` API. Resume is per lz4 block.

### `.gz` / `.tar.gz`

Streaming gzip with hand-rolled RFC 1951 DEFLATE. The 32 KiB sliding
window and the running CRC32 / ISIZE are persisted in the checkpoint,
so a `kill -9` mid-member resumes byte-identically without
re-decoding the member from its start.

Multi-member gzip (the `pigz` / `gzip a b > c.gz` shape) is
handled per RFC 1952 §2.2: concatenated members are decoded in
sequence and emitted as one logical stream.

¹ `flate2` is a `[dev-dependencies]` only (used in the differential
test harness to cross-check the hand-rolled decoder); the runtime
binary does not link `flate2`.

### `.bz2` / `.tar.bz2` / `.tbz2` / `.tbz`

Streaming bzip2 with hand-rolled MSB-first Huffman / MTF / RLE2 /
BWT / RLE1 layers. Each block (≤ 900 KB uncompressed at `-9`, with
a 48-bit `pi` BCD sync header `0x314159265359` per the bzip2 wire
format) is an independent restart point; the per-block resume blob
is ~25 bytes (bit cursor + running stream CRC + cross-block RLE1
state + stream level). The decoder rejects the legacy bzip2 0.9.0
"randomised block" flag with a specific diagnostic; modern encoders
have not emitted that flag since 1.0.0 in 1999.

Multi-stream `.bz2` files (the `cat a.bz2 b.bz2 > c.bz2` shape) are
handled by aligning to the next byte boundary after each stream's
combined CRC and re-entering the per-block loop with a fresh RLE1
state.

`peel` does not link `libbz2`; the decoder is pure Rust.

## Random-access archives

### `.zip`

ZIP uses a separate per-entry pipeline because of its
central-directory-at-the-end layout. On startup, `peel` issues a
small ranged GET for the End-of-Central-Directory record, walks the
central directory, then dispatches per-entry GETs in parallel.
Entries are written to their final paths as their bytes arrive.

Supported coders in entries:

- STORED (uncompressed)
- DEFLATE (RFC 1951; same hand-rolled decoder as `.gz`)
- zstd entries (via the `zstd` crate's streaming reader API)

Encryption: WinZip-AES (AE-1 and AE-2 forms, AES-128/192/256-CTR
with PBKDF2-HMAC-SHA1 key derivation and an HMAC-SHA1-80 trailer);
PKWARE traditional "ZipCrypto" (CRC32-keyed PRGA, insecure but
supported for compatibility). PKWARE strong-encryption
(central-directory encryption, general-purpose flag bit 6) is not
supported and surfaces as a clear error.

Zip64, multi-disk / spanned archives (other than the simple
`.zNN` + `.zip` form), and AES with non-standard parameters are
not yet supported. Such archives fail with a specific
"`unsupported feature`" error rather than producing wrong output.

² Per-entry streaming: each entry's bytes are written to its final
path as soon as they arrive, while the rest of the archive is still
in flight.

³ STORED entries resume byte-granular. DEFLATE entries resume per
deflate block via the 32 KiB-window snapshot. zstd entries resume
per zstd block. All encoded into the checkpoint format (version 7)
under each in-progress entry.

### `.7z`

7z uses a separate per-folder pipeline because of its
SignatureHeader → trailer-pointer layout. `peel` reads the
SignatureHeader at offset 0, follows the pointer to fetch the
trailer, parses the streams metadata, and dispatches per-folder
GETs.

Supported coders:

- COPY (no compression)
- DEFLATE
- LZMA
- LZMA2

Header forms: plain `Header` and unencrypted `EncodedHeader` (the
trailer compresses metadata with an unencrypted coder chain).
Encryption ships for AES-256-CBC under the
[7z KDF](./encryption.md#7z) (`crate::crypto::sevenz_kdf`).

The current release is single-volume only; multi-volume `.7z.001`
support is planned. BCJ filters (x86, ARM, and other preprocessor
filters) and per-coder intra-folder resume are queued.

⁴ Resume granularity is one folder at a time. A `kill -9` mid-folder
restarts that folder from the start of its packed range. Per-coder
intra-folder resume, BCJ filters, AES with non-default parameters,
and multi-volume archives are queued.

### `.rar` (RAR5)

RAR5 walks file headers in stream order with no tail-anchored index
like zip or 7z, so `peel` streams entries to their final paths as
each entry's data area arrives.

Supported coders (compression methods):

- STORED (method 0)
- Standard RAR5 algorithm (methods 1–5) via the hand-rolled
  `decode::rar_native` LZSS pipeline plus the RAR-VM standard filters
  (E8, E8E9, Delta, RGB, Audio).

Encryption: AES-256-CBC for both archive-header encryption
(HEAD_CRYPT, header type 4) and per-file data encryption (extra
record type 1), with PBKDF2-HMAC-SHA256 key derivation. Optional
`pswcheck` verifier supported. See [Encrypted archives](./encryption.md).

Multi-volume archives in the `<base>.part<N>.rar` form are
supported via the [multi-volume](./multi-volume.md) path:
auto-discovery, explicit positional list, or manifest file.

The previous "non-encrypted, single-volume only" restriction no
longer applies. Encryption ships, multi-volume ships. SFX archives
and the rarely-used RAR-VM custom-filter slot
(`O.RAR.CUSTOMFILTER`) remain queued.

⁵ Per-entry streaming with the §F1 checkpoint blob capturing the LZ
dictionary state and filter program cache so resume is byte-identical.

⁶ Mid-entry resume: a `kill -9` mid-RAR5 file restarts the in-flight
entry from the snapshot, not from its start. Multi-block lookahead
state is captured in the blob.

### `.rar` (RAR3 / RAR4 legacy)

Legacy RAR3 / RAR4 archives use the hand-rolled `decode::rar_legacy`
LZ pipeline plus the RarVM standard-filter dispatcher (E8, E8E9,
Delta, RGB, Audio).

Supported coders:

- STORED
- LZ Normal (`-m3` from the `rar` encoder)

The mid-entry checkpoint blob (`PLAN_rar3.md` §F1) captures the LZ
dictionary state and filter program cache.

PPMd-II and other less-common filters and coders are queued.
Encryption for legacy RAR3 archives is queued.

⁷ Same per-entry-plus-intra-entry resume model as RAR5; the LZ
pipeline is different (hand-rolled `decode::rar_legacy`) but the
checkpoint semantics are identical.

## RAR provenance

`peel`'s RAR3 and RAR5 decoders are clean-room implementations.
RARLAB's `unrar` source has not been consulted at any point.
`libarchive`'s RAR readers (LGPL-2.1, OSI-licensed) are referenced
as an external spec where the RAR wire format requires one. They
are read, not vendored or linked.

Test fixtures are produced with a license-purchased copy of
RARLAB's `rar` encoder. The `unrar` binary is not linked, vendored,
or used as an implementation reference; it appears in the RAR
benchmark grid as a third-party point of comparison only.

`peel` is licensed `MIT OR Apache-2.0`. The unRAR license is non-OSI
and GPL-incompatible, so a clean-room derivation is the only way to
ship a RAR decoder without inheriting that constraint.

## Disabling the RAR module

To produce a smaller binary without `.rar` support, build without
the `rar` feature:

```sh
cargo install peel-rs --locked --no-default-features
```

The crate still registers `.rar` and the RAR5 magic against a
diagnostic-only factory, so the user sees a precise `compiled
without the 'rar' feature` error rather than `unknown format`.

## What's not (yet) supported

The following are not in the current release:

- `.lzma` (raw LZMA1, no XZ container): not registered.
- PKWARE strong encryption: clear error.
- ZIP64 multi-disk: clear error (regular Zip64 is supported).
- GPG-encrypted tarballs: out of scope. This is a separate pipeline
  that `peel` does not wrap.
- 7z BCJ filters, AES with non-default coder placement, multi-volume
  `.7z.001`: clear error.
- RAR self-extracting (SFX) archives: clear error.
