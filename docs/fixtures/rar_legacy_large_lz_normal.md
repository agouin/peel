# Fixture: `tests/fixtures/rar_legacy/large_lz_normal.{rar,bin}`

Reproducibility recipe for the §F1 Goldilocks crash-resume fixture
(`docs/PLAN_rar3.md` §F1, `tests/test_coordinator_rar3.rs`).

## What it is

- **`large_lz_normal.bin`** — 262,144 bytes (256 KiB) of
  deterministic, semi-compressible bytes. LCG-derived in 64 ×
  4 KiB aligned subblocks; predictable but with enough entropy
  per subblock that `rar -m3` compresses it to ~800 bytes
  rather than a pathological 1:1 ratio.
- **`large_lz_normal.rar`** — encoder output (RAR4 / legacy
  format, LZ method 3). Single entry named `payload.bin`.

The decoded size (256 KiB) exceeds the streaming adapter's
64 KiB `STREAM_CHUNK_BYTES`, so the live `decode_step` loop
takes multiple drain steps. That makes the fixture
**Goldilocks-sized** for the coordinator-level crash-resume
test: `checkpoint_min_bytes = 1` lands a mid-entry
`CheckpointWritten` before the entry finishes, the kill-switch
fires, and the resumed run picks the entry up via the §F1
snapshot blob.

## How to regenerate

### Step 1 — synthesise the payload

```python
# gen_payload.py
out = bytearray()
state = 0x9E3779B97F4A7C15
for block in range(64):  # 64 * 4 KiB = 256 KiB
    seed = state ^ block
    s = seed
    for i in range(4096):
        s = (s * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        out.append(s & 0xFF)
open("payload.bin", "wb").write(bytes(out))
```

`python3 gen_payload.py` → 262,144-byte `payload.bin`.

### Step 2 — encode via `rar 5.0.0` Linux x86_64

`rar 7.x` no longer accepts the `-ma4` switch (RAR4 output was
dropped from rar 6+). `rar 5.0.0` is the most recent public
RARLAB release whose `-ma4` still works. Extract
`rarlinux-x64-5.0.0.tar.gz` into a working directory and run
via Docker (Linux x86_64 emulation on Apple Silicon works
through Rosetta):

```bash
docker run --rm --platform linux/amd64 \
  -v "$PWD:/work" -w /work \
  debian:bookworm-slim \
  ./rar/rar a -ma4 -m3 large_lz_normal.rar payload.bin
```

- `-ma4` forces the legacy (RAR3/RAR4) file format. Without
  this `rar 5.0.0` would default to `-ma5` (RAR5).
- `-m3` is the "Normal" compression level (the default).
  Empirically yields a single-block LZ stream for a 256 KiB
  semi-compressible input.

### Step 3 — commit the pair

Drop both files into `tests/fixtures/rar_legacy/` and confirm
the round-trip via:

```bash
cargo test --features rar --lib \
  decode::rar_legacy::stream::tests::streams_large_lz_normal_entry_round_trips
```

## License + provenance note

`rar 5.0.0` is a proprietary trial binary; the encoder output
itself is not copyrightable and the input is wholly synthetic
(LCG-derived from a public constant). Both files are
redistributable as test data alongside the rest of the
`rar_legacy/` corpus, which already includes `rar 3.93`-encoded
fixtures under the same posture.
