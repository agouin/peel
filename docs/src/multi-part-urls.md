# Multi-part URLs

Some publishers split a large archive into multiple files at the **HTTP
layer**, serving separate URLs for `name.tar.part0000`,
`name.tar.part0001`, and so on. The byte-concatenation of every part's
body forms the logical archive. `peel` handles this case by accepting
**two or more positional URLs**.

This case differs from [multi-volume archives](./multi-volume.md). The
format's own splitting (RAR `.partNNN.rar`, 7z `.7z.NNN`, spanned ZIP
`.zNN`) stores format-aware metadata in each volume. Multi-part URLs
carry no such metadata: they are a byte-stream served across multiple
URLs.

## Usage

```sh
peel \
  https://snapshot.example.com/dataset.tar.part0000 \
  https://snapshot.example.com/dataset.tar.part0001 \
  https://snapshot.example.com/dataset.tar.part0002 \
  -o ./out/
```

Behaviour:

- At startup, `peel` issues a parallel `HEAD` against every URL and
  reads its `Content-Length`.
- The full assembled length is `sum(Content-Length)` of the parts.
- Workers fetch every part in parallel via ranged GETs (the same
  approach as `aria2c -Z`), but the bytes stream into a **single**
  logical part file and a **single** decoder.
- The decoder sees the byte-concatenation of every part's body, in
  order.

The compressed bytes never fully land on disk. The hole-punching and
resume guarantees of a single-URL run apply.

## Verifying integrity per part

`--sha256` is repeatable. With two or more URLs, either form is valid:

- **Zero** `--sha256` flags: no verification.
- **Exactly one `--sha256` per URL**, paired by order. Each part's
  hash is verified at its part-boundary as the decoder advances.

```sh
peel \
  https://snapshot.example.com/dataset.tar.part0000 \
  https://snapshot.example.com/dataset.tar.part0001 \
  --sha256 0a8de6e83fd8ba040fd052fd8d4fd0e009a9736ace5cb32bb2abd4ac6a61725d \
  --sha256 1bcf4d2e9aa01ff5...                                              \
  -o ./out/
```

A wrong number of `--sha256` flags (1 for 2 URLs, 3 for 2 URLs) is
rejected at parse time.

## A real example: Arbitrum snapshot bundles

This mode is used in production against
[Arbitrum snapshot bundles](./examples/arbitrum-snapshot.md). The
nova snapshot, for example, is published as `pruned.tar.part0000`
through `pruned.tar.partNNNN` with a per-part SHA-256 list:

```sh
peel \
  https://snapshot.arbitrum.io/nova/2026-04-26-7efe0f23/pruned.tar.part0000 \
  https://snapshot.arbitrum.io/nova/2026-04-26-7efe0f23/pruned.tar.part0001 \
  https://snapshot.arbitrum.io/nova/2026-04-26-7efe0f23/pruned.tar.part0002 \
  --sha256 0a8de6e83fd8ba040fd052fd8d4fd0e009a9736ace5cb32bb2abd4ac6a61725d \
  --sha256 1bcf4d2e9aa01ff5e8aa72a2ab39310af020bdb6f76d6f7c75c7c14ade38c6ce \
  --sha256 c40bf8a2cb9d9a90e4c80a5b7c6e9c5d3b8a2e1f9d4a6c1b7e2f8d3a5c0b9e1f0 \
  -o ./nova-out/
```

The convenience script
[`scripts/arb-snapshot.sh`](https://github.com/agouin/peel/blob/main/scripts/arb-snapshot.sh)
wraps the URL list / hash list discovery against the Arbitrum
manifest.

## Reading URLs from a file

When the part list is large (tens or hundreds of URLs), pass it as
`@file.txt` instead of inlining it:

```text
# urls.txt: blank lines and "#" comments are skipped
https://snapshot.example.com/dataset.tar.part0000
https://snapshot.example.com/dataset.tar.part0001
https://snapshot.example.com/dataset.tar.part0002
```

```sh
peel @urls.txt -o ./out/
```

`@file.txt` is also used for [multi-volume manifests](./multi-volume.md).

## Differences from multi-volume archives

| | Multi-part URLs | Multi-volume archives |
| --- | --- | --- |
| **Detection** | Caller passes ≥ 2 URLs | One URL whose basename matches a known volume pattern, auto-discovered |
| **Format metadata** | None; bytes concatenate raw | Each volume carries format-aware headers |
| **Order matters** | Yes; caller specifies | Yes; discovered from volume numbering |
| **Use cases** | Large `.tar.*` published in chunks (Arbitrum snapshots) | RAR `.partNNN.rar`, 7z `.7z.NNN`, spanned ZIP |
| **Override** | Pass `@file.txt` for many parts | `--no-auto-discover` forces single-source |

To distinguish the two cases, inspect the URL suffixes. URLs ending
in `.partNNNN` (numbered, no archive extension) or `.tar.partNNN`
(numbered after a tar extension) are multi-part URLs. URLs ending in
`.part0001.rar`, `.7z.001`, or `.z01` are multi-volume archives.
