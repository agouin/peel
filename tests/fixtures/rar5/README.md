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
