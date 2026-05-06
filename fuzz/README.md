# peel fuzz harness

`cargo-fuzz` targets for the parser/decoder surfaces required by
[`docs/ENGINEERING_STANDARDS.md`](../docs/ENGINEERING_STANDARDS.md) §5.2.

## Targets

| Target                     | What it fuzzes                                                 |
|----------------------------|----------------------------------------------------------------|
| `checkpoint_deserialize`   | `Checkpoint::deserialize` (round-trips through `serialize`)    |
| `http_response_parsing`    | `parse_content_range`, `Url::parse`, `Url::join`               |
| `frame_boundary`           | `zstd` / `xz_native` / `gzip` / `lz4` streaming-decoder framing |
| `zip_format`               | `find_eocd`, `parse_central_directory`, `LocalFileHeader::parse` |
| `tar_sink`                 | Tar header / PAX / checksum parsing through `TarSink::write`   |

## Running locally

`cargo-fuzz` requires a nightly toolchain (libFuzzer's instrumentation
flags are nightly-only). Install once, then run a target:

```sh
cargo install cargo-fuzz
cd fuzz
cargo +nightly fuzz run checkpoint_deserialize
cargo +nightly fuzz run http_response_parsing
cargo +nightly fuzz run frame_boundary
```

Each invocation runs until you Ctrl-C or the fuzzer finds a crash.
Pass `-- -max_total_time=300` (libFuzzer flag) for a fixed budget.

## Corpus / seeds layout

- `seeds/<target>/` — hand-curated, version-controlled starter inputs.
- `corpus/<target>/` — the live corpus libFuzzer reads and writes.
  Gitignored; populate it from `seeds/` before a run:

  ```sh
  mkdir -p corpus/http_response_parsing
  cp -r seeds/http_response_parsing/. corpus/http_response_parsing/
  cargo +nightly fuzz run http_response_parsing
  ```

Binary targets (`checkpoint_deserialize`, `frame_boundary`) ship without
checked-in seeds; the format magics gate enough coverage that libFuzzer
discovers structured inputs quickly. To seed them from the existing unit
tests, dump bytes from a known-good test fixture into `corpus/<target>/`
— any `cargo test` in the parent crate that prints serialized bytes
works.

## Crashes

When libFuzzer finds an input that triggers a panic or sanitizer
report, it writes the offending bytes to `artifacts/<target>/`. Reproduce
deterministically with:

```sh
cargo +nightly fuzz run <target> artifacts/<target>/<crash-file>
```

## CI

Scheduled fuzzing runs in [`.github/workflows/fuzz.yml`](../.github/workflows/fuzz.yml).
Each target gets a fixed time budget per run; any crash fails the
workflow and uploads the crash artifact.
