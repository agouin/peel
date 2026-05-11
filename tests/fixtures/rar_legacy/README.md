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
  for both archives: `"Testing 123\n"`.

## Source + license

Both `.rar` files are taken verbatim from
[ssokolow/rar-test-files](https://github.com/ssokolow/rar-test-files)
at commit `master`. The upstream license is **CC0** — the
files were created from scratch with minimally-novel content
specifically to be redistributable as test data.
`testfile.rar3.txt` is the obvious round-trip output and is
re-typed here (12 bytes; no copyright concerns).

## Why no LZ-mode archives

The §C1e₂ commit (`541c1ee`) records the discovery: every
RAR3 archive in the ssokolow corpus (and every RAR3 archive
modern `rar 7.x` can produce — it dropped legacy-archive
creation entirely) uses PPMd for compressed entries. A
synthetic LZ-only RAR3 archive builder is filed as a §G
fuzz-seed candidate; the §C1e₁ dispatcher's synthetic-fixture
coverage stands as the LZ path's primary validation today.
