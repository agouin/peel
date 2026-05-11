# `tests/fixtures/rar_bench/`

Cache of pre-baked RAR archives used by the bench
[`bench_throttled_download_then_extract_grid`](../../test_bench_streaming.rs)
when measuring `peel` against `curl -O && unrar x && rm`.

The archives themselves are `*.rar` blobs sized to match the grid's
8 / 32 / 128 / 256 MiB payload cells. They are **not committed** —
the `.gitignore` next to this README keeps the byte content out of
the tree. On first bench run the helper at
[`tests/support/rar_bench_fixtures.rs`](../../support/rar_bench_fixtures.rs)
re-bakes whichever cells are missing.

## Why a cache (not in-test assembly)

The hand-rolled fixture builders at `tests/support/rar_fixtures.rs`
synthesize RAR wire bytes directly. That's fine for unit tests of
the walker / parser, but a benchmark grid wants archives produced by
the *real* RAR encoder so the third-party `unrar` baseline isn't
extracting some peel-specific dialect.

The registered RAR encoder we have on hand is RAR 7.22 for macOS
(`~/Downloads/rar/rar`). RAR 7.x emits RAR5 only — the `-ma4`
switch for RAR3 / legacy output was dropped at RAR 7.0. So:

- **RAR5 STORED (`-m0`)**: encoded by native `rar 7.22` at bench
  time. Fast (native ARM, milliseconds even at 256 MiB).
  STORED is also the only method peel's RAR5 pipeline supports
  today.
- **RAR3 LZ Normal (`-m3` with `-ma4`)**: encoded by `rar 5.0.0`
  Linux x86_64 (from `~/Downloads/rarlinux-x64-5.0.0.tar.gz`)
  inside a `linux/amd64` Docker container. Apple Silicon runs the
  binary through Rosetta — slow but tractable for the four bench
  cells. `-m3` Normal is RAR3's standard packing path; the bench
  exercises peel's `decode::rar_legacy` LZ + RarVM filter
  pipeline. The bench payload is LCG-derived and effectively
  incompressible, so wire size still tracks each rate column's
  MiB target.

  peel's parser also accepts RAR3 STORED entries (`-m0` tags
  them `unp_ver = 20` for pre-2.9 compatibility; the version
  field is decorative for STORED). Flipping the helper to `-m0`
  on a future bench refresh just means deleting the cached
  `rar3_stored_*.rar` files and re-running.

## Cache layout

```
tests/fixtures/rar_bench/
├── .gitignore             # *.rar and *.bin (this README is committed)
├── README.md              # this file
├── rar5_stored_8mib.rar
├── rar5_stored_32mib.rar
├── rar5_stored_128mib.rar
├── rar5_stored_256mib.rar
├── rar3_stored_8mib.rar
├── rar3_stored_32mib.rar
├── rar3_stored_128mib.rar
└── rar3_stored_256mib.rar
```

Each archive holds eight `data/file_NN.bin` entries
(deterministic, LCG-derived) totalling the cache key's MiB target —
the same payload shape every other format in the grid uses.

## Rebuilding

Delete the cell you want to rebake; the next bench run regenerates
it. To wipe the lot:

```sh
rm -f tests/fixtures/rar_bench/*.rar
```

## Provenance

Per [`AGENTS.md`](../../../AGENTS.md) §"RAR source policy", the
encoder binaries are license-purchased copies used as opaque
tools for fixture generation. `unrar` appears only in the
benchmark grid as a third-party baseline; neither encoder nor
decoder source is consulted by the `peel` RAR decoder.
