# PLAN — Hand-rolled xz block decoder for mid-Block resume + per-chunk puncher

**Status**: proposed (2026-05-01).
**Owner**: TBD.
**Supersedes**: `OPTIMIZATIONS.md` §O.6b — promotes that deferred item
to a real plan.

## Why we're doing this

Today the xz path wraps `xz2::stream::Stream`
(`src/decode/xz.rs:101-127`). Its only exposed restart-safe boundary
is "between xz Streams": `Status::StreamEnd` (`src/decode/xz.rs:293`)
records a frame boundary and the wrapper either chains a fresh Stream
or transitions to `Done`.

The default `xz` CLI emits **a single Stream containing a single
Block** for the entire input, identical in shape to default `zstd`'s
"one frame per file" emission. For a single-Block archive:

- `frame_boundary()` returns `None` until end-of-stream.
- The extractor's checkpoint observer never fires.
- The puncher never advances; **no source bytes are ever freed**.
- A `kill -9` mid-extraction restarts from byte 0.

This is the same failure mode the zstd plan
(`docs/PLAN_zstd_block_decoder.md`) addressed, with the same root
cause: liblzma exposes no per-chunk hook and `xz2` does not surface
mid-Block state.

Three approaches were considered (mirrors zstd's triage):

- **A. Re-decompress the prefix on resume.** Fixes resume but defeats
  per-chunk hole-punching, because punching past the Block start
  makes the prefix unrecoverable. Disk-frugality regresses for any
  multi-GiB single-Block `.tar.xz`.
- **B. Per-Block / per-Stream only.** Doesn't help single-Block
  archives — the dominant shape.
- **C. Hand-roll the LZMA2 / LZMA decoder.** Per-LZMA2-chunk restart
  points; puncher fires at every chunk boundary; mid-Block is a
  first-class citizen.

We pick **C**, on the same load-bearing-property argument as the zstd
plan: per-format puncher coverage is the project's value proposition
(`CLAUDE.md` §"What this project is": "never use more than ~300 MB of
disk for the compressed side"), and the round-one MVP regresses it
for the dominant archive shape.

This is a multi-week project. Phasing is structured so each phase
ends in a runnable, tested artifact and integrates with the existing
`StreamingDecoder` trait at recognized milestones.

## Scope

### In scope (round one)

- Pure-Rust **decoder** for xz Streams produced by the standard `xz`
  CLI at default settings (preset 6) and any preset whose dictionary
  size ≤ 64 MiB.
- Stream framing: Stream Header, Block Header(s), Index, Stream
  Footer per the [.xz file format].
- Filter chain: **LZMA2 only** as the last (and typically sole)
  filter. BCJ pre-filters are deferred.
- All LZMA2 chunk types: uncompressed (with/without dict reset),
  LZMA (with/without state/dict reset), end-of-stream marker.
- LZMA probability model: literal contexts (`lc`/`lp`/`pb`),
  match/rep state machine, length decoders, distance decoders,
  alignment-bit reverse decoder.
- Range coder reader (the LZMA equivalent of zstd's bitstream
  readers).
- Stream-level integrity: `Check` types `None`, `CRC32`, `CRC64`,
  `SHA-256`. Index parsing for cross-validation.
- **Mid-Block `decoder_state()` blob** captured at LZMA2 chunk
  boundaries: dictionary snapshot, LZMA state probability tables,
  repeat-distance slots (`rep0..rep3`), `state` (the 12-state
  machine), filter parameters (`lc`, `lp`, `pb`, `dict_size`),
  Block-level running Check, accumulated `Compressed_Size` /
  `Uncompressed_Size` for Index validation. Capped at ≤ 64 MiB +
  small constant.
- **`resume_factory`** that reconstructs a decoder from the blob
  and resumes byte-identically with the original sink.
- **Per-LZMA2-chunk `frame_boundary()` advance** so the existing
  extractor checkpoint cadence and puncher fire every chunk
  boundary.

### Deferred (out of round one)

- **BCJ pre-filters** (x86, ARM, ARM64, IA-64, PowerPC, SPARC,
  RISC-V). Reject Block Headers whose filter chain contains a
  non-LZMA2 filter with a clean `DecodeError::Read` naming the
  unsupported feature (mirrors lz4's linked-block stance,
  `src/decode/lz4.rs:782-789`). Real-world `.tar.xz` archives almost
  never use BCJ; if a use case appears, add per-filter state to the
  resume blob.
- **`dict_size > 64 MiB`** (preset 7+ can declare up to 1.5 GiB,
  spec allows up to 4 GiB). Reject with a clean error to keep the
  resume-blob ceiling at ~64 MiB. Mirrors zstd's `windowLog > 27`
  rejection.
- **Encoder.** We never emit xz; only decompress.
- **Multi-Block Streams.** Promote to first-class once the MVP
  ships; until then, multi-Block files fall back to per-Block (not
  per-chunk) granularity through the same machinery, which is a
  strict improvement over today's per-Stream.
- **Stream Padding** (zero-byte alignment between concatenated
  Streams). Rejected today (`src/decode/xz.rs:51-58`); stays
  rejected.
- **Differential fuzz harness against `xz2` at fuzz scale.**
  Smoke-level differential is in Phase 5; fuzz is a follow-on.

### Non-goals

- Beating liblzma on throughput. It's a 20+-year-old hand-tuned C
  library; a clean-room Rust decoder will be slower. Target is
  "fast enough not to be the bottleneck against 1 Gb/s download" —
  roughly **100 MB/s** sustained on commodity hardware. xz decode
  is intrinsically slower than zstd, so the bar is lower than
  zstd's 200 MB/s. If we land below 50 MB/s we revisit before
  Phase 4.

## Reference material

- **The .xz File Format Specification v1.1.0**
  ([tukaani.org/xz/xz-file-format.txt](https://tukaani.org/xz/xz-file-format.txt)).
  Authoritative wire format.
- **LZMA specification** (Igor Pavlov, included in the LZMA SDK as
  `lzma-specification.txt`). Authoritative for the inner compressed
  payload.
- **`xz` / `liblzma` source** as a cross-reference, specifically
  `src/liblzma/lzma/lzma_decoder.c` and
  `src/liblzma/lzma/lzma2_decoder.c`. Read for cross-checks, not
  for copy-paste — license is BSD-0 / public domain but we want a
  clean-room Rust implementation per
  `ENGINEERING_STANDARDS.md` §2.
- **`lzma-rs`** (pure-Rust LZMA decoder on crates.io). Useful for
  cross-checking edge cases during development; **not** a runtime
  dependency.

## Phasing

Each phase is a separate commit (or small commit chain) with its own
tests. Phases ship in order — no parallel work on later phases while
earlier ones are unstable.

### Phase 0 — Spike (1–3 days, throwaway)

Goal: derisk the range coder + LZMA probability model before
committing to the module layout. Pick three xz reference vectors
(tiny, medium, with checksum) and write a single-file decoder that
parses Stream/Block headers, walks LZMA2 chunks, and decodes them.
Don't worry about `decoder_state` or trait integration yet. Output:
a one-page memo appended to this doc as Appendix A.

**Exit criteria**: three reference vectors decode byte-identical to
`xz`. Time-boxed at 3 days; surface blockers before continuing.

### Phase 1 — Module skeleton, Stream/Block parsers, uncompressed chunks (1 week)

- New module `src/decode/xz_native/` with submodules `stream.rs`
  (Stream Header + Footer + Index), `block.rs` (Block Header +
  LZMA2 chunk header), `error.rs` (`thiserror`-based local error
  type that maps cleanly to `DecodeError`).
- The existing `src/decode/xz.rs` wrapper stays in place as the
  default-registered factory; this phase adds the new module
  *behind* it, gated by build cfg `peel_xz_native` so we can
  develop without breaking `cargo test`.
- Public surface: `Decoder::new(src) -> Self` and a single
  `decode_step(&mut self, sink: &mut dyn Write) -> Result<...>`
  that handles `Initial -> InStream -> InBlock { ctx } -> Done`.
- LZMA2 chunk types implemented: uncompressed-with-reset,
  uncompressed-no-reset, end-of-stream. LZMA chunks return
  `DecodeError::Read("LZMA chunk decoding not yet implemented")`
  until Phase 4.
- Filter chain validation: reject anything other than `[LZMA2]`.
  Reject `dict_size > 64 MiB`.

**Tests**: bytes-in/bytes-out byte-identical for fixtures encoded
with `xz --lzma2=preset=0` on inputs that compress as uncompressed
chunks.

**Exit criteria**: `cargo test --features peel_xz_native` passes;
the module compiles cleanly with `clippy -- -D warnings`.

### Phase 2 — Range coder reader (3 days)

The xz analogue of zstd's bitstream readers. Foundation for
Phases 3 and 4.

- `range_coder.rs`: `RangeDecoder` over a `&[u8]` slice (no I/O;
  the slice is the already-buffered LZMA2 chunk payload).
  Implements `decode_bit(prob: &mut u16) -> u8` and
  `decode_direct_bits(n) -> u32` per the LZMA spec's range-coder
  section.
- Pure logic, no allocation. Heavily unit-tested against
  hand-built bit patterns and cross-checked against `lzma-rs`'s
  range coder on identical inputs.

**Exit criteria**: tests pass; clippy clean.

### Phase 3 — LZMA probability tables & state machine (1.5 weeks)

The first big load-bearing piece. Equivalent to zstd's Phase 3
(Huffman + literals).

- `lzma_state.rs`: the 12-state machine (`STATE_LIT_LIT`,
  `STATE_LIT_MATCH`, `STATE_LIT_REP`, …, `STATE_NONLIT_MATCH`,
  `STATE_NONLIT_REP`). Transition tables transcribed from the
  LZMA spec as `const` arrays.
- `probs.rs`: probability table allocation sized to `lc`/`lp`/`pb`.
  ~16 KiB total at default presets; `Box<[u16]>` for cache
  friendliness.
- Literal decoder: context-dependent literal probability lookup
  (`lc` previous-byte bits, `lp` position bits) plus the
  post-match literal-with-matched-byte path.
- Length decoder: `LengthDecoder` shared between match-length and
  rep-match-length contexts (low-2 / mid-3 / high-8 trees per the
  spec).
- Distance decoder: slot decoder + direct-bit middle slots +
  reverse aligned-tree decoder for the bottom 4 bits.

**Tests**:

- Property: round-trip arbitrary `&[u8]` payloads through `xz
  --check=none` and verify byte-identical decode.
- Differential: cross-check 50 random fixtures against `xz2`'s
  `Stream::process`.

**Exit criteria**: literals + lengths + distances decode correctly
under hand-built test vectors covering the full state machine.

### Phase 4 — LZMA2 chunk decode & sliding window output (2 weeks)

The other big load-bearing piece. Equivalent to zstd's Phase 4 + 5
(FSE + sequences + window).

- `lzma2.rs`: full LZMA2 chunk-header decoder. Resolves the five
  chunk control-byte ranges per spec (uncompressed, LZMA with
  various reset modes, end-of-stream). Drives a fresh
  `RangeDecoder` per chunk (range coder state does **not** carry
  across chunks — this is what makes per-chunk boundaries clean
  restart points).
- `dict.rs`: ring-buffer dictionary sized to `dict_size`, capped
  at 64 MiB. Provides:
  - `append_byte(u8)` for literal output
  - `match_copy(distance: u32, length: u32)` for back-references
    (handles overlap-by-design when `length > distance`)
  - `recent(&self, n: usize) -> &[u8]` for the snapshot path in
    Phase 6
- `Decoder::decode_chunk(...)`: drive the LZMA inner loop until
  the chunk's declared `Uncompressed_Size` is reached or
  `Compressed_Size` is consumed, whichever comes first.
  Cross-validate at chunk end.
- Wire `LZMA chunk` into Phase 1's state machine: parse chunk
  header, decode chunk, write to sink and append to dictionary.

**Tests**:

- Differential: 100 random fixtures through `xz2` vs the new
  decoder, byte-identical.
- Hand-built rep-distance test exercising `rep0..rep3` slot
  rotation.
- LZMA2 chunk-type matrix: every legal control byte exercised at
  least once.

**Exit criteria**: the test corpus from `test_extractor.rs`
decodes through the new path with `--features peel_xz_native`.

### Phase 5 — Frame-level integration & validation (3 days)

- `Check` verification: `None` / `CRC32` (existing
  `src/hash/crc32.rs`, if present; otherwise a small new module
  mirroring SHA-256's shape) / `CRC64` / `SHA-256`
  (`src/hash/sha256.rs`). Compute over decompressed Block output;
  compare to the trailing Check field per the .xz file-format
  spec.
- Stream Index parse: enumerate Block records, cross-check
  `Compressed_Size`, `Uncompressed_Size`.
- Stream Footer validation: backward-size, flags consistency.
- Reject: BCJ filters in chain, `dict_size > 64 MiB`, multi-Block
  (round one — Phase 9 promotes), Stream Padding (continues
  today's behavior).
- New small module `src/hash/crc64.rs` mirroring the SHA-256
  module's style.

**Tests**: corrupted-Check, undersized declared sizes, oversized
dict declaration, BCJ-in-chain — all surface clean errors.

**Exit criteria**: differential against `xz2` clean across 500
random fixtures.

### Phase 6 — Decoder state serialization (1 week)

Now the lz4/zstd-shaped resume support.

- `resume.rs`: `XzResumeState` struct. Layout:

  ```text
   4 B  magic = b"XDR1"
   1 B  format_version (1)
   8 B  dict_size (u64 LE)
   N B  dict contents (dict_size bytes; the most recent dict_size
          bytes of decompressed output ending at decoder_position)
   1 B  lc (0..=8)
   1 B  lp (0..=4)
   1 B  pb (0..=4)
   1 B  state (0..=11)
   4*4 B rep0..rep3 (u32 LE x 4)
   2*N B prob tables (u16 LE; size = 0x1000 +
          literal_states * 0x300 + aux tables — fixed once
          lc/lp/pb known)
   1 B  Check_Type (matches Stream flags)
   N B  in-progress Check state (CRC32: 4B, CRC64: 8B,
          SHA-256: 32B)
   8 B  block_uncompressed_so_far (u64 LE)
   8 B  block_compressed_so_far (u64 LE; for Index cross-check)
   8 B  block_start_offset (u64 LE — for diagnostic only)
  ```

  Total size is bounded by `dict_size + ~20 KiB` — at
  `dict_size=64 MiB` that's 64 MiB + change. Smaller dictionaries
  produce proportionally smaller blobs.
- The probability-table serialization is *internal* to our
  decoder; versioned by the blob's `format_version`. Format bumps
  are fine.
- `Decoder::resume(src, blob, start_offset)`: deserialize, hydrate
  dict + probs + state + repeats + running Check, set internal
  `bytes_consumed = start_offset` and `last_frame_boundary =
  Some(start_offset)`. Mirror lz4's resume contract:
  `src/decode/lz4.rs:269-301`.
- `decoder_state()`: return `Some(blob)` only when paused at an
  LZMA2 chunk boundary inside a Block; `None` between
  Blocks/Streams or mid-chunk (mirrors `Lz4Decoder::between_blocks`
  and the zstd analogue).

**Tests**:

- Round-trip: capture state at every chunk boundary in a 10-chunk
  Block, resume from each, verify byte-identical output for the
  suffix.
- Property: random Blocks, random kill points at chunk boundaries,
  byte-identical resume.

**Exit criteria**: the lz4-style
`frame_boundary_property_is_a_valid_restart_point` test
(`src/decode/xz.rs:725`) ports cleanly to the new decoder and
passes.

### Phase 7 — Wire into the registry & extractor (3 days)

- Move the new `Decoder` behind `crate::decode::xz::XzDecoder`
  (replace the wrapper). The factory shape stays the same; only
  the implementation swaps. Drop the `peel_xz_native` cfg — this
  is now the production path.
- Register the resume_factory in `src/decode.rs`:

  ```rust
  r.register_resume_factory("xz", xz::resume_factory);
  ```

- Update the registry comment that today excludes xz from the
  resume-factory set.
- Coordinator changes (`src/coordinator.rs:868-884`): none — the
  resume_factory match arm already handles this case identically
  to lz4 and zstd.

**Tests**: existing tests pass under the swapped-in decoder.

**Exit criteria**: the `xz2` crate is no longer a *runtime*
dependency for our decode path. (It can remain a dev-dependency
for differential tests.)

### Phase 8 — Hole-punching coverage for single-Block xz (2 days)

Mostly a test-only phase that confirms Phase 7 worked.

- Add an integration test that decodes a 256 MiB single-Block
  `.tar.xz` and asserts:
  - `bytes_punched > 0`
  - `punch_calls > 0`
  - peak on-disk block count of the source file stays under
    `2 * dict_size + chunk_size` (small constant, no slow leak).
- Update `tests/test_extractor.rs` to add a single-Block xz
  sibling alongside the existing fixtures.

**Exit criteria**: the single-Block failure mode (no punching, no
checkpointing) is demonstrably fixed at smaller scale, mirroring
Phase 9 of the zstd plan.

### Phase 9 — Crash-resume integration tests (1 week)

Mirror the existing lz4/zstd crash tests
(`tests/test_coordinator_crash.rs`).

- Build a single-Block `tar.xz` with several tar members of
  awkward sizes (so LZMA2 chunk boundaries and tar-member
  boundaries rarely coincide).
- Run the coordinator under a kill-after-N-bytes harness; restart;
  verify final output is byte-identical to a clean run.
- Property test: vary `xz` preset, member sizes, and kill points.

**Exit criteria**: 100 randomized crash-resume runs are
byte-identical.

### Phase 10 — Optional follow-ons (deferred)

These all live in `OPTIMIZATIONS.md` after this plan ships:

- BCJ pre-filter support (x86 + ARM64 are highest-value; their
  state is small — a few bytes of address tracking — and adds
  modestly to the resume blob).
- Multi-Block per-Block boundaries (real Block-level granularity
  for `pixz` / `xz -T` output).
- `dict_size > 64 MiB` for archives that need a larger sliding
  window.
- Differential fuzz harness with `cargo-fuzz` and a real-world
  corpus.
- SIMD fast-paths in the LZMA inner loop.

## Risks & open questions

1. **Throughput.** A clean-room pure-Rust LZMA decoder will be
   slower than liblzma; pure-Rust implementations typically land at
   50–100 MB/s. If we land below 50 MB/s sustained, the
   user-perceived extract phase regresses noticeably. Mitigation:
   Phase 0 spike must benchmark against liblzma; if catastrophically
   slower (< 30 MB/s) we revisit before Phase 4.
2. **Dictionary blob.** A 64 MiB checkpoint blob written every
   chunk boundary is a lot of disk I/O. xz's default LZMA2 chunk
   size is ~64 KiB, so a 1 GiB Block has ~16k chunks. Same
   mitigation menu as zstd Phase 7: dedupe against the previously-
   written blob (only persist diffs from the last checkpoint), or
   accept that checkpoints fire less often (every Nth chunk).
   Decide during Phase 6.
3. **Endianness / portability.** xz is little-endian on the wire.
   We target LE hosts only, matching the zstd plan and the io_uring
   path. Document the assumption.
4. **License / clean-room.** `.xz` spec + LZMA SDK spec +
   clean-room implementation. Don't read `liblzma`'s C
   line-by-line for copying patterns; refer to the specs, then
   implement, then cross-check. This is the normal clean-room
   discipline already used for the zstd plan.
5. **`tracing` instrumentation.** Decode is hot-loop; instrument
   sparingly. Only at Stream/Block-header parse and at the
   `decode_step` boundary.
6. **Probability-table size with extreme `lc`/`lp`/`pb`.** Worst
   case is `lc=8, lp=4, pb=4`, blowing the literal table to
   ~2 MiB. Default presets use `lc=3, lp=0, pb=2` (~6 KiB), so
   this is a long-tail concern; cap at the spec-max and document.

## Acceptance criteria for the whole plan

- ✅ Single-Block `tar.xz` (any size, any preset ≤ 64 MiB dict)
  extracts with the puncher firing every LZMA2 chunk boundary.
- ✅ A `kill -9` mid-extraction at any chunk boundary resumes
  byte-identical to a clean run.
- ✅ The `xz2` crate is removed from the runtime dependency tree.
  (Confirms our hand-rolled path is what's actually decompressing.)
- ✅ `cargo test`, `cargo clippy -- -D warnings`,
  `cargo fmt --check` all green.
- ✅ Differential test passes against a curated corpus of 1000+
  xz fixtures.
- ✅ Throughput within 4× of liblzma on a representative `tar.xz`
  archive (looser than zstd's 3× because pure-Rust LZMA decoders
  are systematically further behind their C counterparts than
  pure-Rust zstd is behind libzstd).

## Estimated total effort

Roughly **5–7 weeks of focused work** for one engineer, distributed
across the phases above — same envelope as the zstd plan. Phase 3
(LZMA probability model + state machine) and Phase 4 (LZMA2 chunks
+ window) are the heaviest single phases. Phase 0's spike result
will tighten this estimate.

[.xz file format]: https://tukaani.org/xz/xz-file-format.txt
