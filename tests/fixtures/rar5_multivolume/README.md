# RAR5 multi-volume test fixtures

Real RAR5 multi-volume archives produced by WinRAR (`rar` 7.22) for
`internal/PLAN_multivolume_archives.md` §2.

## Layout

- `multi.part1.rar` (16 384 B) — volume 1 of 3 in a STORED-method
  (`-m0`), 16 KiB-per-volume (`-v16k`) set produced from two source
  files:

  - `small.txt` — `b"Hello from multivol\n" * 50` (1 000 B). Fits
    entirely in volume 1.
  - `big.bin` — `b"X" * 35000`. Spans volumes 1→2→3 (carries the
    RAR5 `FHD_SPLIT_AFTER` flag in volumes 1 and 2; `FHD_SPLIT_BEFORE`
    in volumes 2 and 3).

- `multi.part2.rar` (16 384 B) — volume 2.
- `multi.part3.rar` (3 596 B) — volume 3 (trailing volume; carries the
  `FHD_SPLIT_BEFORE`-only continuation of `big.bin` plus the
  `EndArchive` marker).

The expected plaintext payloads are reconstructed in test code so they
don't need to be committed alongside the archives.

## Regenerate

```sh
cd /tmp && rm -rf rar5mv && mkdir rar5mv && cd rar5mv
python3 -c 'import sys; sys.stdout.buffer.write(b"Hello from multivol\n" * 50)' > small.txt
python3 -c 'import sys; sys.stdout.buffer.write(b"X" * 35000)' > big.bin
rar a -ma5 -m0 -v16k -tsm- -tsa- -tsc- -ep multi.rar small.txt big.bin
```
