# PLAN — Hand-rolled zstd block decoder for mid-frame resume + per-block puncher

**Status**: proposed (2026-05-01).
**Owner**: TBD.
**Supersedes**: nothing yet — this is additive to `PLAN_v2.md`.

## Why we're doing this

Today the zstd path uses the `zstd` crate (libzstd binding). Its only
public surface for restart-safe boundaries is "between zstd frames":
[`StreamingDecoder::frame_boundary`](../src/decode/zstd.rs) advances
only when `Decoder::single_frame()` returns `Ok(0)`. For
multi-frame archives (`pzstd`, concatenated `cat a.zst b.zst`) that
fires often enough that resume and per-block hole-punching both work
— and the existing tests deliberately use multi-frame fixtures
(`tests/test_extractor.rs::build_multi_frame_zstd_tar`).

The default `zstd` CLI emits **a single frame for the entire input**.
For a single-frame archive:

- `frame_boundary()` returns `None` until end-of-stream.
- The extractor's checkpoint observer
  (`src/extractor.rs:385-407`) only fires when `boundary_advanced`,
  so **no checkpoint is ever written**.
- `last_quiescent_at` stays at 0, so the puncher
  (`src/extractor.rs:415-424`) never advances and **no source bytes
  are ever freed**.
- A `kill -9` mid-extraction restarts from byte 0.

This was observed in production: a 3.7 TiB `tar.zst` download stalled
at 380 GiB compressed, restart began at 0%, and inspection of the
checkpoint directory found no checkpoint had ever been written.

Three approaches were considered; details in the original triage
thread (worktree `worktree-zstd-resume`):

- **A. xz-style fast-skip on resume** (re-decompress the prefix on
  restart, no re-download). Fixes resume but **does not enable
  per-block hole-punching** within a frame, because punching past the
  frame's start makes fast-skip impossible. Disk-frugality regresses
  for any multi-GiB single-frame archive, which is the common case.
- **B. Frame-boundary only.** Doesn't help single-frame archives —
  the case that motivated this plan.
- **C. Hand-roll the zstd block decoder.** Per-block restart points
  in the source. The puncher fires every block; resume carries a
  small (≤ window_size of decompressed bytes plus a few KiB of
  decoder state) blob; mid-frame is a first-class citizen.

We're picking **C**. Per-format puncher coverage is a load-bearing
property of the project's value proposition (`CLAUDE.md` §"What this
project is": "never use more than ~300 MB of disk for the compressed
side"). A and B both compromise that for the most common shape of
real-world zstd archives.

This is a multi-week project. The phasing below is structured so each
phase ends in a runnable, tested artifact and integrates with the
existing `StreamingDecoder` trait at recognized milestones.

## Scope

### In scope (round one)

- Pure-Rust zstd **decoder** for frames produced by the standard
  `zstd` CLI at default settings (`-3`), and any compression level
  the upstream tool emits as long as `windowLog ≤ 27` (128 MiB
  sliding window cap).
- All four block types: `Raw_Block`, `RLE_Block`, `Compressed_Block`,
  reserved (rejected).
- All literal section types: `Raw_Literals_Block`, `RLE_Literals_Block`,
  `Compressed_Literals_Block`, `Treeless_Literals_Block`.
- All sequence FSE modes for each of LL/ML/OF: `Predefined_Mode`,
  `RLE_Mode`, `FSE_Compressed_Mode`, `Repeat_Mode`.
- Skippable frames (magics `184D2A50`–`184D2A5F`) — already handled
  generically by the existing wrapper, but the new decoder must
  also recognize them.
- Frame header decoding: `Frame_Content_Size`, `Window_Descriptor`,
  `Dictionary_ID` (rejected if non-zero — see deferred), checksum
  flag (XXH64 over decompressed output).
- **Mid-frame `decoder_state()` blob** with sliding window snapshot,
  repeat offsets, prior Huffman tree (for `Treeless_Literals_Block`
  reuse), prior FSE distribution tables (for `Repeat_Mode` reuse),
  block-position metadata. Capped at ≤ 128 MiB + small constant.
- **`resume_factory`** that reconstructs a decoder from the blob and
  resumes byte-identically with the original sink.
- **Per-block `frame_boundary()` advance** so the existing extractor
  checkpoint cadence and puncher fire every block boundary.

### Deferred (out of round one)

- **Custom dictionaries** (zstd's `Dictionary_ID` set). Reject at
  frame-header parse time with a clean `DecodeError::Read` naming
  the unsupported feature (mirrors the lz4 linked-block stance,
  `src/decode/lz4.rs:782-789`). Real-world `tar.zst` dataset
  archives don't use custom dictionaries.
- **`windowLog > 27`** (windows > 128 MiB). zstd's `--long` mode
  can declare windows up to 27 (128 MiB) on 32-bit and 31 (2 GiB)
  on 64-bit; we cap at 27 to keep the resume-blob ceiling at 128
  MiB. Reject `> 27` with a clean error.
- **Encoder**. We never emit zstd; we only decompress.
- **Seekable format** (`zstd` `--seekable`). Different framing; not
  produced by default `zstd`.
- **Differential testing against `zstd` crate at fuzz scale.** A
  smoke-level differential is in Phase 6; a fuzz harness with a
  curated seed corpus is its own follow-up.

### Non-goals

- Beating libzstd on throughput. Libzstd is a 10+-year-old
  hand-tuned C library; we will be slower. Target is "fast enough
  not to be the bottleneck against 1 Gb/s download" — roughly 200
  MB/s sustained on commodity hardware. If we land below that we
  ship anyway and improve in a follow-on; the resume + puncher
  property is the value, not the throughput.

## Reference material

- **RFC 8478** ([Zstandard Compression and the application/zstd Media
  Type](https://datatracker.ietf.org/doc/html/rfc8478)). The
  authoritative wire-format spec.
- **Zstd source** as a reference implementation, specifically
  `lib/decompress/zstd_decompress_block.c` and
  `lib/decompress/huf_decompress.c`. Read for cross-checks, not for
  copy-paste — license is BSD/GPL dual but we want a clean-room
  Rust implementation to keep the dependency tree clean per
  `ENGINEERING_STANDARDS.md` §2.
- **`ruzstd`** (pure-Rust zstd decoder on crates.io). Useful for
  cross-checking edge cases during development; **not** a runtime
  dependency (would require allowlist approval and adds 10k+ LOC of
  surface area we don't control).

## Phasing

Each phase is a separate commit (or small commit chain) with its
own tests. Phases ship in order — no parallel work on later phases
while earlier ones are unstable, because the trait/blob/wire-format
surfaces tighten as we go.

### Phase 0 — Spike (1–3 days, throwaway)

Goal: derisk FSE and Huffman before committing to the full module
layout. Pick three `zstd` reference vectors (tiny, medium, with
checksum) and write a single-file decoder that parses the frame
header, walks blocks, and successfully decodes them. Don't worry
about `decoder_state` or trait integration yet. Output: a one-page
"yes this is feasible in our codebase style and the cost estimate
holds" memo, or "no, here are the rocks we hit, here's the revised
plan". The throwaway code is not committed; the memo gets appended
to this doc as an appendix.

**Exit criteria**: three reference vectors decode byte-identical
to libzstd. Time-boxed at 3 days; if blocked, surface the blocker
before continuing.

### Phase 1 — Module skeleton, frame parser, raw/RLE blocks (1 week)

Land the on-disk module layout that the rest of the phases fill in:

- New module `src/decode/zstd_native/` with submodules
  `frame.rs` (frame header parser), `block.rs` (block header
  parser, raw + RLE bodies), `error.rs` (`thiserror`-based local
  error type that maps cleanly to `DecodeError`).
- The existing `src/decode/zstd.rs` wrapper stays put as the
  default-registered factory; this phase adds the new module
  *behind* it, gated by a build cfg `peel_zstd_native` so we can
  develop without breaking `cargo test`.
- Public surface: `Decoder::new(src) -> Self` and a single
  `decode_step(&mut self, sink: &mut dyn Write) -> Result<...>`
  that handles the `Initial -> InFrame { ctx } -> Done` state
  machine for raw and RLE blocks only. Compressed blocks return
  `DecodeError::Read("compressed block decoding not yet
  implemented")` until Phase 5.
- Skippable frames handled (delegate to the same logic the lz4
  decoder uses; consider extracting a shared helper).

**Tests**: bytes-in/bytes-out byte-identical for fixtures
generated with `zstd --no-compression-trail` and `zstd -1` on
all-zero inputs (which encode as RLE).

**Exit criteria**: `cargo test --features peel_zstd_native` passes;
the module compiles cleanly with `clippy -- -D warnings`.

### Phase 2 — Bitstream readers (3 days)

zstd uses both forward (LE) and reverse (LE, bit-stuffed) bitstreams
inside compressed sections. Foundation for Phases 3 and 4.

- `bitstream.rs`: `ForwardBitReader` and `ReverseBitReader`. Both
  read from a `&[u8]` slice (no I/O); the slice is the already-
  buffered block payload. Unit tests cover RFC 8478 §4.1.4 bit-stuff
  semantics, multi-byte reads, EOF behavior.
- These types are pure logic, no allocation. Heavily unit-tested
  against hand-built bit patterns.

**Exit criteria**: tests pass; clippy clean.

### Phase 3 — Huffman decoder & literals section (1.5 weeks)

The first big load-bearing piece. Implements RFC 8478 §4.2.1.

- `huffman.rs`: weight-table parser, Huffman table builder
  (max 11 bits / 2048-entry decode table; we don't need
  X2/X4 fast-path tables in round one — straight bit-by-bit
  is acceptable for our throughput target).
- `literals.rs`: parses the literals-section header for all
  four block types. Decodes raw/rle directly; for compressed
  treeful, builds a tree from the inline weight section then
  decodes; for compressed treeless, reuses the tree from the
  decoder's `prev_huffman` slot.
- Multi-stream decode (4-stream parallel literals, where the
  header carries 6 bytes of stream sizes) — done sequentially
  for round one; parallel decode is an optional Phase 11
  optimization.

**Tests**:

- Property: round-trip arbitrary `&[u8]` literals through `zstd
  --content-only` (synthetic frames carrying just a literals
  section) and verify byte-identical decode.
- Differential: cross-check 50 random fixtures against the
  `zstd` crate's `decode_all`.

**Exit criteria**: all four literal block types decode correctly;
treeless reuse works across two consecutive blocks.

### Phase 4 — FSE decoder & sequences section (2 weeks)

The other big load-bearing piece. RFC 8478 §4.1.4, §4.2.2.

- `fse.rs`: FSE distribution-table decoder (the "normalized
  counts" probability table parser), state-table builder, sequence
  symbol decoder. Three independent FSE tables per block — for
  literal lengths (LL), match lengths (ML), and offsets (OF).
- `sequences.rs`: parses the sequences-section header (number of
  sequences, FSE compression modes for each of LL/ML/OF).
  Resolves each table per its mode (`Predefined_Mode`,
  `RLE_Mode`, `FSE_Compressed_Mode`, `Repeat_Mode`). Decodes
  the sequence stream into a `Vec<Sequence { literals_length,
  match_length, offset_code }>`.
- Predefined distribution tables come straight from RFC 8478
  appendix tables; transcribe them as `const` arrays with a
  property test confirming they match libzstd's expectations on
  one fixture per table.

**Tests**:

- Property: random sequences round-tripped through libzstd
  decode byte-identical via our path.
- Repeat-mode test: two blocks where the second declares
  `Repeat_Mode` for all three FSE tables.

**Exit criteria**: arbitrary block-of-sequences decodes to the
same symbol stream libzstd does.

### Phase 5 — Sequence execution & sliding window (1 week)

This is where decoded sequences become decompressed bytes.

- `window.rs`: a ring buffer sized to `window_size` declared in the
  frame header, capped at 128 MiB. Provides:
  - `append(&mut self, &[u8])` for literal copy
  - `match_copy(&mut self, offset: u32, length: u32)` for back-
    references (handles overlap-by-design — match length can
    exceed offset, RFC 8478 §3.1.1.1.4)
  - `recent(&self, n: usize) -> &[u8]` for the snapshot path in
    Phase 7
- `sequences.rs::execute(...)`: walk the sequence list, applying
  literals from the literals buffer and matches against the
  window. Tracks the three repeat offsets per RFC 8478 §3.1.1.5.
- Wire `Compressed_Block` into Phase 1's `decode_step` state
  machine: parse literals, parse sequences, execute, write to
  sink and append to window.

**Tests**:

- Differential: 100 random fixtures through `zstd` crate vs our
  decoder, byte-identical.
- Hand-built repeat-offset test: a frame that exercises all
  three repeat slots and the `OF == 0/1/2/3` mapping.

**Exit criteria**: the test corpus from `test_extractor.rs`
decodes through the new path with `--features peel_zstd_native`.

### Phase 6 — Frame-level integration & validation (3 days)

- XXH64 content checksum (already implemented in
  `src/hash/sha256.rs` — XXH64 is different; a small new
  `src/hash/xxh64.rs` mirroring the SHA-256 module's style is
  needed). Compute over decompressed bytes; compare to the
  trailing 4-byte truncation if `Content_Checksum_Flag` is set.
- `Frame_Content_Size` cross-check at frame end.
- `Dictionary_ID` non-zero rejection.
- `windowLog > 27` rejection.

**Tests**: corrupted-checksum frame, undersized declared content
size, oversized window declaration — all surface clean errors.

**Exit criteria**: differential against `zstd` crate clean across
500 random fixtures.

### Phase 7 — Decoder state serialization (1 week)

Now the lz4-shaped resume support.

- `resume.rs`: `ZstdResumeState` struct mirroring the captured
  invariants. Layout:

  ```text
   4 B  magic = b"ZDR1"
   1 B  format_version (1)
   8 B  window_size (u64 LE)
   N B  window contents (window_size bytes; the most recent
          window_size bytes of decompressed output ending at
          decoder_position)
   3*4 B repeat_offsets (u32 LE x 3)
   1 B  has_prev_huffman (0/1)
   N B  prev_huffman serialized (only when has_prev_huffman)
   1 B  has_prev_fse_ll (0/1)
   N B  prev_fse_ll distribution serialized
   ... (same for ml, of)
   8 B  bytes_decompressed_in_frame (u64 LE)
   8 B  frame_start_offset (u64 LE — for diagnostic only)
  ```

  Total size is bounded by `window_size + ~10 KiB` — at
  `windowLog=27` that's 128 MiB + change. Smaller window
  archives produce proportionally smaller blobs.
- The Huffman/FSE serialization formats are *internal* — they
  capture our decoder's table representation. Versioned by the
  blob's `format_version`; format bumps are fine.
- `Decoder::resume(src, blob, start_offset)`: deserialize, hydrate
  window + repeat offsets + reuse-mode tables, set internal
  `bytes_consumed = start_offset` and `last_frame_boundary =
  Some(start_offset)`. Mirror lz4's resume contract:
  `src/decode/lz4.rs:269-301`.
- `decoder_state()`: return `Some(blob)` only when paused at a
  block boundary inside a frame; `None` between frames or
  mid-block (mirrors `Lz4Decoder::between_blocks`).

**Tests**:

- Round-trip: capture state at every block boundary in a
  10-block frame, resume from each, verify byte-identical
  output for the suffix.
- Property: random frames, random kill points, byte-identical
  resume.

**Exit criteria**: the lz4-style `frame_boundary_property_is_a_valid_restart_point`
test (`src/decode/zstd.rs:576`) ports cleanly to the new decoder
and passes.

### Phase 8 — Wire into the registry & extractor (3 days)

- Move the new `Decoder` behind `crate::decode::zstd::ZstdDecoder`
  (replace the wrapper). The factory shape stays the same; only
  the implementation swaps. Drop the `peel_zstd_native` cfg —
  this is now the production path.
- Register the resume_factory in `src/decode.rs:372`-style:

  ```rust
  r.register_resume_factory("zstd", zstd::resume_factory);
  ```

- Update the comment in `src/decode.rs:369-372` (currently says
  "Other in-tree formats today restart cleanly from their
  `frame_boundary` offset and don't need this hook" — that's no
  longer true once this lands).
- Coordinator changes (`src/coordinator.rs:868-884`): none —
  the resume_factory match arm already handles this case
  identically to lz4.

**Tests**: existing tests pass under the swapped-in decoder.

**Exit criteria**: the `zstd` crate is no longer a *runtime*
dependency for our decode path. (It can remain a dev-dependency
for differential tests.)

### Phase 9 — Hole-punching coverage for single-frame zstd (2 days)

This is mostly a test-only phase that confirms Phase 8 worked.

- Add an integration test that decodes a 256 MiB single-frame
  `.tar.zst` and asserts:
  - `bytes_punched > 0`
  - `punch_calls > 0`
  - peak on-disk block count of the source file stays under
    `2 * window_size + chunk_size` (small constant, no slow
    leak).
- Update `tests/test_extractor.rs::extracts_multi_frame_zstd_tar_into_directory`
  to add a single-frame sibling.

**Exit criteria**: the user's reported failure mode (3.7 TiB
single-frame `tar.zst` not punching, not checkpointing) is
demonstrably fixed at smaller scale.

### Phase 10 — Crash-resume integration tests (1 week)

Mirror the existing lz4 crash test
(`tests/test_coordinator_crash.rs::tar_lz4_with_misaligned_member_sizes_resumes_byte_identically`,
commit `34975da`). The shape:

- Build a single-frame `tar.zst` with several tar members of
  awkward sizes (so block boundaries and tar-member boundaries
  rarely coincide).
- Run the coordinator under a kill-after-N-bytes harness; restart;
  verify final output is byte-identical to a clean run.
- Property test: vary frame compression level, member sizes, and
  kill points.

**Exit criteria**: 100 randomized crash-resume runs are byte-
identical.

### Phase 11 — Optional follow-ons (deferred)

These all live in `OPTIMIZATIONS.md` after this plan ships:

- Multi-stream parallel literals decode (Phase 3 single-stream is
  fine for round one).
- Huffman X2 fast-path table for ≥ 11-bit symbols.
- SIMD fast-path for sequence execution.
- Custom-dictionary support.
- `windowLog > 27` for `--long` archives larger than 128 MiB
  context.
- Differential fuzz harness with `cargo-fuzz` and a real-world
  corpus.

## Risks & open questions

1. **Throughput.** A clean-room pure-Rust decoder will be slower
   than libzstd. If we land at < 100 MB/s sustained, the
   user-perceived extract phase regresses. Mitigation: Phase 0
   spike must benchmark against libzstd; if we're catastrophically
   slower (< 50 MB/s) we revisit before Phase 5.
2. **Window-size blob.** A 128 MiB checkpoint blob written every
   block boundary is a lot of disk I/O. We may need to dedupe
   against the previously-written blob (only persist diffs from
   the last checkpoint), or accept that checkpoints fire less
   often (every Nth block). Decide during Phase 7.
3. **Endianness / portability.** zstd is little-endian on the
   wire. We're targeting LE hosts for now (the io_uring path
   already requires Linux x86_64/aarch64). Document the
   assumption.
4. **License.** RFC 8478 + clean-room implementation. Don't read
   `lib/decompress/*.c` line-by-line for copying patterns; refer
   to the RFC, then implement, then cross-check. This is the
   normal clean-room discipline.
5. **`tracing` instrumentation.** Decode is hot-loop; instrument
   sparingly. Only at frame-header parse and at the
   `decode_step` boundary.

## Acceptance criteria for the whole plan

- ✅ Single-frame `tar.zst` (any size, any zstd CLI level) extracts
  with the puncher firing every block boundary.
- ✅ A `kill -9` mid-extraction at any block boundary resumes
  byte-identical to a clean run.
- ✅ The `zstd` crate is removed from the runtime dependency tree.
  (Confirms our hand-rolled path is what's actually decompressing.)
- ✅ `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`
  all green.
- ✅ Differential test passes against a curated corpus of 1000+
  zstd fixtures.
- ✅ Throughput within 3× of libzstd on a representative
  `tar.zst` archive.

## Estimated total effort

Roughly **5–7 weeks of focused work** for one engineer, distributed
across the phases above. Phase 4 (FSE) and Phase 7 (decoder_state
serialization) are the heaviest single phases. Phase 0's spike
result will tighten this estimate.
