# PPMd-II differential corpus

Reference vectors that drive `src/decode/ppmd2/model.rs`'s §B3
differential test against an externally-built PPMd encoder. Each
`case_NNN_*.bin` is a tight binary envelope holding one
`(plaintext, PPMd byte stream, order, mem_mb)` tuple; the test feeds
the stream through `RangeDecoder` + `Model::decode_symbol` for
`plaintext.len()` iterations and byte-compares the output to the
recorded plaintext.

## Why 7z, not `rar a -m5`

`internal/PLAN_rar3.md` §B3 originally pitched "encode with `rar a -m5`,
decode with the §B2 model". Two facts force a different reference:

1. **`rar 7.x` dropped legacy-archive creation.** There is no
   `-ma3` switch and `m<0..5>` is now a RAR5-only compression
   level. We have no path to a RAR3-format archive from a modern
   rar binary.
2. **The §B2 model uses the 7z-variant range coder.** The
   RAR-variant range coder is deferred to Phase C of
   `PLAN_rar3.md`. Feeding bytes from a RAR3 PPMd block into
   today's `RangeDecoder` would test the wrong wire format.

7z PPMd is Igor Pavlov's PPMd7 (the LZMA SDK variant) — exactly the
algorithm + range-coder variant our model targets. When Phase C
lands and the RAR-variant decoder + RAR3 LZ block parser are in
the tree, a sibling corpus generated from actual `.rar` archives
becomes possible; that work is gated on Phase C and out of scope
here.

## Fixture wire format

Little-endian throughout:

| offset    | size              | field                  |
| --------- | ----------------- | ---------------------- |
| `0..4`    | `4`               | magic `b"PPM2"`        |
| `4`       | `u8`              | `order`                |
| `5`       | `u8`              | reserved (always `0`)  |
| `6..10`   | `u32`             | `mem_bytes`            |
| `10..14`  | `u32`             | `plaintext_len`        |
| `14..18`  | `u32`             | `ppmd_len`             |
| `18..`    | `plaintext_len`   | plaintext bytes        |
| trailing  | `ppmd_len`        | PPMd stream            |

The PPMd byte stream starts with the standard PPMd7 5-byte init
prefix (`0x00` leader + 4 BE bytes of `code`); `RangeDecoder::new`
consumes those before the first `decode_symbol` call.

**`mem_bytes` is the value 7z actually used**, not what we requested
on the command line. p7zip 17.05's `-m0=PPMd:mem=<N>m` parser
silently overrides our request and emits a fixed default (typically
64 KiB / `0x10000`); regen.py reads the canonical `mem_size_bytes`
straight out of the .7z archive's PPMd method properties so the
decoder sees the same arena the encoder used. The model restarts
when `text >= units_start`, so a mismatch between encoder and
decoder arena sizes silently desynchronises on streams long enough
to grow the text region — which is exactly how high-order corpus
cases failed before this was tightened.

PPMd7 caps `order` at 32 and `mem_bytes` between `MIN_MEM_SIZE`
(2 KiB) and `MAX_MEM_SIZE` (≈ 4 GiB − 36 bytes); the corpus stays
well inside that.

## Regenerating

```sh
./tests/fixtures/ppmd2/regen.py
```

`regen.py` is the **only** path that writes `case_*.bin`. It wipes
any stale `case_*.bin` before re-emitting, so renaming or dropping a
case in the script will not leave orphan files behind. Requires
`7z` (or `7za`) from p7zip on `PATH`; no Python deps beyond stdlib.

## Corpus shape

10 payloads × 5 `(order, mem_mb)` configurations = 50 cases:

- **Payloads**: tiny ASCII, alphabet, lorem (1 KB), English (4 KB),
  all-zeros (1 KB & 16 KB), LCG pseudorandom (1 KB & 16 KB),
  period-27 'X' run (1 KB), period-256 cyclic (1 KB).
- **`(order, mem_mb)`**: `(2, 1)`, `(4, 4)`, `(8, 16)`, `(16, 32)`,
  `(32, 64)` — sweeps the model's order axis from minimum to the
  PPMd7 maximum and exercises arenas from 1 MiB to 64 MiB.

If a case fails, the test surfaces the fixture's filename so the
break-point is obvious without rerunning the script.
