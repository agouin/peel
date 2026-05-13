# RAR5 test fixtures

These archives come from
[ssokolow/rar-test-files](https://github.com/ssokolow/rar-test-files)
under the [CC0 public-domain dedication](http://creativecommons.org/publicdomain/zero/1.0/).
The author waived all copyright and related rights worldwide; the
archives in that repo are deliberately tiny and trivially novel so
they're safe to redistribute.

## Layout

- `testfile.rar5.solid.rar` (97 B) — single-entry RAR5 archive in
  solid mode, compression method 5 ("best"), payload
  `Testing 123\n`. Drives `PLAN_rar5_decoder.md` §F1's snapshot
  round-trip test in [`tests/test_rar_decoder_resume.rs`](../../test_rar_decoder_resume.rs)
  and [`src/decode/rar_native/stream.rs`](../../../src/decode/rar_native/stream.rs)'s
  unit tests.

- `multi_block_p27.rar` (2.9 KB) — non-solid RAR5 archive,
  compression method 5, payload `b'X' * 27 * 2_500_000` (67.5 MB
  of period-27 repetition). The smallest known archive whose
  compressed output spans two RAR5 blocks (block 0 has
  `is_last_block=False`); pins the multi-block decode-gap
  regression in
  [`tests/test_rar_decoder_resume.rs`](../../test_rar_decoder_resume.rs)
  via an `#[ignore]`'d test that activates when the gap is
  closed. Source / fix plan:
  [`internal/PLAN_rar5_multi_block_decode.md`](../../../internal/PLAN_rar5_multi_block_decode.md).
  Regenerate with
  `python3 -c 'import sys; sys.stdout.buffer.write(b"X"*27*2_500_000)' > p27-fails.txt && rar a -ma5 -m5 -tsm- -tsa- -tsc- -ep multi_block_p27.rar p27-fails.txt`.
