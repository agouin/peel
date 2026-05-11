# Legacy RAR (RAR3 / RAR4) corpus

Real-archive fixtures for the §C1g PPMd-entry path's end-to-
end cross-check. The compressed entry inside each `.rar` file
is a single `is_ppmd_block = 1` block (the WinRAR `-m5` encoder
picked PPMd over LZSS for the 12-byte text payload — see the
§C1e₂ corpus-inspection note in `docs/PLAN_rar3.md`).

## Files

- **`testfile.rar3.rar`** (98 bytes) — non-solid archive,
  single entry `testfile.txt`, PPMd-mode with 128 KiB dict.
- **`testfile.rar3.solid.rar`** (98 bytes) — solid archive,
  same entry, PPMd-mode with 1 MiB dict (`MHD_SOLID` set in
  main header).
- **`testfile.rar3.txt`** (12 bytes) — expected plaintext
  for both single-entry archives: `"Testing 123\n"`.
- **`testfile.rar3.cbr`** (381 bytes) — non-solid multi-entry
  archive (the §A's "Comic Book RAR" convention is just a
  RAR archive renamed `.cbr`). Two entries:
  - `testfile.jpg` (220 bytes uncompressed, PPMd, 128 KiB dict).
  - `testfile.png` (87 bytes uncompressed, PPMd, 128 KiB dict).
- **`testfile.cbr.jpg`** (220 bytes) — expected unpacked
  content of the `testfile.jpg` entry inside
  `testfile.rar3.cbr`. Minimal 2×2 JFIF JPEG.
- **`testfile.cbr.png`** (87 bytes) — expected unpacked
  content of the `testfile.png` entry inside
  `testfile.rar3.cbr`. Minimal 2×2 8-bit colormap PNG.

## Source + license

Both `.rar` files are taken verbatim from
[ssokolow/rar-test-files](https://github.com/ssokolow/rar-test-files)
at commit `master`. The upstream license is **CC0** — the
files were created from scratch with minimally-novel content
specifically to be redistributable as test data.
`testfile.rar3.txt` is the obvious round-trip output and is
re-typed here (12 bytes; no copyright concerns).

## LZ + standard-filter archives (§C2b corpus)

The four `filter_*` pairs below land for §C2b's filter-pipeline
validation. The ssokolow corpus is all PPMd-mode short-text
payloads, so it doesn't exercise the LZ + RarVM-filter path the
encoder picks for larger / typed content. The §C2b corpus is
self-generated against `rar 3.93` (Linux x86_64, RARLAB public
release, March 2010) under Docker `linux/amd64` emulation, with
each filter forced via the corresponding
`-mc[param]<Module>+` switch documented in `rar.txt` of the
RAR 3.93 distribution.

Each archive's compressed entry is **pure LZ** (no PPMd
sub-blocks) — the encoder was told `-mcT-` to disable the text
(PPMd) module alongside the filter-forcing switch. Without that,
`rar 3.93` at `-m5` produces a hybrid: a first LZ block
containing just the filter declaration, followed by a PPMd
block carrying the actual data, with the filter post-applied
to the shared LZ/PPMd window. Cross-mode hybrid is its own
flavour of complexity (§C2b explicitly defers it as
`CrossModeNotSupported`), so the corpus stays on the pure-LZ
shape the dispatcher round-one handles. The plaintext is the
same synthetic input the encoder consumed, re-decoded
byte-for-byte by the bundled `rar 7.22` (`-p -inul`) as the
reference.

- **`filter_e8.rar`** (264 bytes) + **`filter_e8.bin`**
  (512 bytes) — synthetic PE/x86 binary, 24 alternating
  `0xE8`/`0xE9` instructions interspersed with NOPs. Encoder
  forced to E8 filter via `-m5 -mcT- -mcE+`. Single LZ block,
  one filter declaration: standard E8
  (fingerprint `0x35AD576887`), block 512 bytes at output
  position 0.
- **`filter_rgb.rar`** (405 bytes) + **`filter_rgb.bin`**
  (270 bytes) — synthetic 24-bpp BMP, 12×6 pixels with a
  per-channel gradient. Encoder forced to RGB filter via
  `-m5 -mcT- -mcC+`. Two LZ blocks (the first declares the
  filter, the second carries the tail of the encoded data,
  ending at the entry's unpacked size); one filter
  declaration: standard RGB (fingerprint `0x951C2C5DC8`),
  block 270 bytes, stride 153.
- **`filter_audio.rar`** (885 bytes) + **`filter_audio.bin`**
  (556 bytes) — synthetic 16-bit stereo PCM WAV, 128 samples
  of correlated sine waves. Encoder forced to AUDIO filter
  via `-m5 -mcT- -mc2A+` (2 channels). Three LZ blocks (the
  encoder split the data across multiple block-boundaries),
  one filter declaration: standard AUDIO
  (fingerprint `0xD8BC85E701`), block 556 bytes, 2 channels.
- **`filter_delta.rar`** (153 bytes) + **`filter_delta.bin`**
  (512 bytes) — synthetic 4-channel structured records (32
  records × 4 little-endian `u32` fields). Encoder forced to
  DELTA filter via `-m5 -mcT- -mc4D+` (4 channels). Single
  LZ block, one filter declaration: standard DELTA
  (fingerprint `0x1D0E06077D`), block 512 bytes, 4 channels.
- **`filter_multi.rar`** (397 bytes) + **`filter_multi.bin`**
  (4096 bytes) — synthetic 4 KiB PE/x86 binary, alternating
  `0xE8`/`0xE9`/`0xCC` instructions. Encoder forced to E8
  filter via `-m5 -mcT- -mcE+`. The encoder's auto-mode
  heuristic splits the entry into **three filter
  declarations** in one LZ block:
  - filter 1 (flags=`0xA6`): standard E8, declares a new
    program slot 0, explicit `block_length=256` at
    `block_start=0`.
  - filter 2 (flags=`0xB6`): standard DELTA, declares a new
    program slot 1, explicit `block_length=3584` at
    `block_start=256`, with the `flags & 0x10` register-mask
    payload carrying the channel count register.
  - filter 3 (flags=`0xC2`): re-uses cached program slot 0
    (E8) — `flags & 0x80` SET (index in bytecode) +
    `flags & 0x40` SET (`block_start` biased by `+258`) +
    `flags & 0x20` CLEAR (implicit `block_length` reused
    from the program's `old_filter_length = 256`).
  Exercises the dispatcher's FIFO drain, register-mask
  parsing, +258 block-start bias, and `old_filter_length`
  reuse — none of which the single-filter fixtures hit.
  Confirmed byte-identical between `rar 3.93` and
  `rar 5.0.0` at the same input + switches; we ship the
  3.93-encoded archive for corpus consistency.

All four `filter_*` `.bin` files are wholly synthetic
(no copyrightable content) and CC0-equivalent. The matching
`filter_*` `.rar` archives are encoder output over the
synthetic inputs and inherit the same status.

`rar 3.93` is the last public RAR release whose macOS / Linux
binaries are still readily available; later 4.x / 5.x / 6.x
versions emit RAR3 archives too (until RAR 7.0 dropped
`-ma3`), but `rar 3.93` is the version the §C2b corpus uses
for reproducibility — see `docs/PLAN_rar3.md` §C2b for the
exact encode recipe and Docker `linux/amd64` invocation.

The fifth WinRAR standard filter (`E8E9` — same algorithm as
`E8` but also matching `0xE9` near-jumps in addition to `0xE8`
near-calls, libarchive fingerprint `0x393CD7E57E`) doesn't
have a dedicated `-mc` switch in `rar 3.93`; the encoder
chose pure-`E8` for every x86-like input we tried. The
`execute_e8` executor takes an `e9_also: bool` parameter and
the `E8E9` codepath is covered by the synthetic-input unit
tests in
[`vm/standard.rs`](../../../src/decode/rar_legacy/vm/standard.rs).
