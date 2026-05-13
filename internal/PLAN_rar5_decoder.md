## Plan: hand-rolled RAR5 decoder

> **Status: §A1, §A2, §B1, §B2, §C1, §E1, §F1 landed
> (drafted 2026-05-09, round-one shipped through 2026-05-11).**
> The `method >= 1` dispatch in
> [`rar_pipeline::extract_entry`](../src/download/rar_pipeline.rs)
> now drives [`RarStreamDecoder`](../src/decode/rar_native/stream.rs);
> the §3 STORED-only rejection has been removed. The mid-entry
> checkpoint blob (§F1) is wired through `Checkpoint` format v11 and
> the crash-resume integration test covers compressed entries
> end-to-end including the multi-block lookahead path (see
> [`PLAN_rar5_multi_block_decode.md`](PLAN_rar5_multi_block_decode.md),
> resolved 2026-05-10).
>
> **Open**: §C2 (custom-filter bytecode) — deferred to
> `O.RAR.CUSTOMFILTER`. §G1 (throughput) — not started; the
> bench grid in the README currently exercises STORED-method
> archives only, so the compressed-method hot-path profile that
> §G1 calls for has not yet been collected.
>
> **Sequencing.** §1+§2+§3 of `internal/PLAN_rar.md` were on `main`
> before §A1 began; the decoder plugs into the same `RarSink` /
> `rar_pipeline` surfaces those phases shipped.

**Supersedes**: nothing — this is additive to `internal/PLAN_rar.md` §4.

## Why we're hand-rolling this

§0.1 of `internal/PLAN_rar.md` rejected the `unrar` C++ FFI on
licensing grounds: the unRAR license is non-OSI and
GPL-incompatible, and `peel` is licensed `MIT OR Apache-2.0`.
Mainstream Rust BLAKE2sp / RAR5 ref crates don't help —
`blake2 = "0.10"` dropped the parallel variants and the
pure-Rust RAR ports examined on crates.io 2026-05 covered RAR5
minimally or not at all.

Hand-rolling is comparable in scope to
`internal/PLAN_zstd_block_decoder.md` (10 phases, ~12 weeks) but
materially harder: the RAR5 wire format is author-provided by
RARLAB rather than IETF-standardized, the corpus of public test
vectors is smaller, and the algorithm has more moving parts
(LZSS + filter VM + adaptive Huffman re-coding per block).

The cost is the price of staying fully OSI-licensed.

## Hard constraints (carried forward from `PLAN_rar.md`)

- Std-first; allowlist-only. No new runtime dependencies. The
  reference implementation we cross-check against in tests can
  shell out to the locally-installed `unrar` binary at
  `[dev-dependencies]`-only scope (mirroring the precedent set
  by `xz2` for the XZ plan and `flate2` for DEFLATE), but the
  runtime binary must not link any RAR-licensed code.
- No async runtime.
- Linux-first; macOS works via the existing `MacosPuncher`.
- Backwards-compatible checkpoints. Each phase that introduces
  new resume state bumps `Checkpoint::format_version` per
  `PLAN.md` §9.2.
- Hand-rolled wire-format parsing. Every layer (bitstream
  reader, Huffman tables, LZSS dictionary, filter VM) is
  hand-rolled. No transitive linking against RAR-licensed C
  code.

## What this plan deliberately does not include

- Compression — `peel` is decompression-only. The `unrar`
  license restriction we sidestepped by hand-rolling forbids
  using its source to build a *compressor*; we never wanted to
  build one anyway.
- RAR4 (legacy). Out of scope per `PLAN_rar.md` "What this plan
  deliberately does not include". RAR4 archives surface
  `RarError::UnsupportedFormatVersion` at parse time and never
  reach the decoder.
- Encryption (`O.RAR.ENC` follow-on). The decoder ships unencrypted-only.
- Multi-volume (`O.RAR.MV`).
- SFX archives (`O.RAR.SFX`).
- PPMd-II / PPM compression. RAR4 supported a PPM mode; RAR5
  dropped it. libarchive's RAR5 decoder
  (`archive_read_support_format_rar5.c`) lists method values
  STORE..BEST and never invokes its bundled PPMd7 functions for
  RAR5 entries; the `FILTER_PPM` filter slot is explicitly
  marked "not used in RARv5". Hypothetical PPMd-encoded entries
  surface as `RarError::UnsupportedMethod` at parse time.

---

## Phase A — Bitstream and Huffman scaffolding

### §A1. Bitstream reader

**What**: hand-rolled MSB-first bitstream reader over the entry's
data area. Lives in `src/decode/rar_native/bits.rs`.

**Why first**: every layer above (Huffman, LZSS, filter VM)
reads bits and groups of bits from the same stream; getting the
bitstream wrong corrupts everything else. Validates the
foundation cheaply.

**Sketch**.

1. `BitReader<'a>` over `&'a [u8]`: `read_bits(n: u8) -> u32`,
   `peek_bits(n: u8) -> u32`, `consume(n: u8)`,
   `align_to_byte()`. MSB-first (RAR5 convention), fast path
   over a `u32` accumulator that refills lazily.
2. Position tracking in *bits* (not bytes) so the decoder can
   record exact restart points later.
3. Tests: round-trip random bit sequences, alignment-padding
   semantics, end-of-buffer rejection.

**Demo**: `cargo test decode::rar_native::bits` passes including
a property test that round-trips `Vec<(u8, u32)>` through the
encoder + decoder and recovers the original groups.

---

### §A2. Huffman decoder

**What**: canonical Huffman code-table reader and decoder, as
RAR5 uses for literals + match lengths + match distances. Lives
in `src/decode/rar_native/huffman.rs`.

**Sketch**.

1. Code-length table parser per the RAR5 algorithm (the table
   is itself Huffman-encoded; we need a small inner decoder to
   bootstrap).
2. Lookup-table-backed canonical Huffman decoder
   (256-entry root + per-leaf overflow chains). Same shape as
   `decode/deflate_native/huffman.rs`.
3. Tests: round-trip random byte sequences encoded with
   `flate2`'s reference Huffman + verify our decoder recovers
   the bytes; rejection of malformed code-length tables.

**Demo**: `cargo test decode::rar_native::huffman` passes.

---

## Phase B — LZSS

### §B1. Sliding-window dictionary

**What**: ring-buffered dictionary the LZSS layer copies matches
from. Lives in `src/decode/rar_native/dict.rs`.

**Sketch**.

1. `Dict { buf: Box<[u8]>, head: usize, capacity: usize }` —
   fixed-capacity ring buffer up to 4 GiB (RAR5's max
   dictionary size).
2. `push_literal(b)`, `copy_match(distance, length)`,
   `recent_window(start, len)` for the filter VM.
3. Resume snapshot: serialize the live tail of the buffer up to
   `min(head, capacity)` plus the metadata. Same shape as
   `xz_native::dict::Dict::serialize`.
4. Tests: round-trip serialization, copy-overlap semantics
   (`distance < length`, the LZSS-specific RLE pattern), wrap
   handling at `capacity` boundary.

**Demo**: `cargo test decode::rar_native::dict` passes.

---

### §B2. Block-level LZSS dispatcher

**What**: per-block decoder that consumes Huffman codes and
populates the dictionary. Lives in
`src/decode/rar_native/lzss.rs`.

**Sketch**.

1. `decode_block(reader, dict, sink)` — drives the literal /
   short-match / long-match dispatch using the per-block
   Huffman tables from §A2.
2. Block-end detection (the literal-table's end-of-block
   marker) so the upper layer can re-read fresh tables.
3. Tests: differential against a small corpus of single-block
   RAR5 archives produced by `rar a -m1` against fixed
   payloads. Cross-check the dictionary state against the
   `unrar` binary's debug output where feasible.

**Demo**: `cargo test decode::rar_native::lzss` passes for at
least one curated single-entry archive < 1 MiB.

---

## Phase C — Filters

### §C1. RAR-VM bytecode interpreter

**What**: small bytecode VM for the post-decompression filters
RAR5 supports (e8/e9/itanium/rgb/audio/delta + custom). Lives
in `src/decode/rar_native/filter_vm.rs`.

**Sketch**.

1. Decode the static filter set RAR5 ships (per the technote).
   The "custom" filter slot is rare in practice and lands as a
   §C2 follow-up.
2. Apply filters to dictionary windows after the LZSS layer
   produces a contiguous run.
3. Tests: round-trip e8/e9 transformations against a curated
   corpus of executable fixtures (a tiny ELF/Mach-O blob is
   enough); RGB transformation against a small bitmap.

**Demo**: `cargo test decode::rar_native::filter_vm` passes.

---

### §C2. Custom-filter bytecode

**Deferred**. RAR5 archives in the wild rarely use the custom
filter slot — `rar a` does not emit it by default. Filed as a
follow-on in `OPTIMIZATIONS.md` (`O.RAR.CUSTOMFILTER`).

---

## Phase E — Integration

### §E1. `StreamingDecoder` wiring

**What**: `RarStreamDecoder` that owns the bitstream + dict +
filter VM and exposes the [`crate::decode::StreamingDecoder`]
trait so the §3 pipeline can replace its STORED-only check
with a fully-method-aware dispatcher. Lives in
`src/decode/rar_native/mod.rs`.

**Sketch**.

1. `RarStreamDecoder { bits, dict, vm, ... }` —
   per-entry instance.
2. `decode_step(sink)` — bounded work per call, same contract
   as every other decoder.
3. Wire into `rar_pipeline::extract_entry` so `method != 0`
   entries dispatch through the decoder rather than the
   passthrough copy path.
4. Tests: differential round-trip 100+ archives across a
   curated + random corpus, byte-comparing against `unrar`-
   produced expected outputs (committed as `*.expected.bin`
   alongside the fixture archives in `tests/fixtures/rar5/`).

**Demo**: full RAR5 round-trip against a multi-MB archive
downloaded over the mock server.

---

## Phase F — Resume

### §F1. Mid-entry checkpoint blob

**What**: serializable decoder snapshot so a `kill -9`
mid-entry resumes byte-identical. Lives next to §B1's dict
snapshot but takes the bitstream + Huffman + VM state into
account.

**Sketch**.

1. `RarStreamDecoder::serialize() -> Vec<u8>` — wire-format-
   stable blob covering every field.
2. `RarStreamDecoder::deserialize(&[u8])` — round-trip.
3. Bump `Checkpoint::format_version` (v11) and add an optional
   `current_entry_decoder_state` field to `SinkState::Rar`
   (`PLAN_rar.md` §3 had reserved this slot).
4. Tests: crash-test round-trip — kill mid-entry at random bit
   offsets and verify the resumed extraction is byte-identical
   for 100+ trials.

**Demo**: the `tests/test_coordinator_rar.rs` crash-test now
also covers compressed entries.

**Postmortem note** (2026-05-10): landing §F1 surfaced a latent
struct-layout bug in `MacosPuncher` — small code-gen changes from
F1 left nonzero garbage in the `fpunchhole_t` struct's
previously-implicit padding bytes, and APFS rejects the call
with `EINVAL` when `reserved != 0`. The bug was not in F1; it
had been latent since `MacosPuncher` shipped. Full investigation
in [`PLAN_macos_puncher_race.md`](PLAN_macos_puncher_race.md).
The crash-resume test now passes 100/100 on macOS arm64 in both
debug and release.

**Postmortem note** (2026-05-11): wiring the
`crash_resume_mid_compressed_entry_produces_identical_output`
integration test (the multi-block sibling of the original §F1
coverage) surfaced a real bug in the snapshot serializer. After
each non-last block, `RarStreamDecoder::read_block` pulls
`BLOCK_LOOKAHEAD_BYTES = 4` past the block end into `prepend_buf`
so the LZSS dispatcher's symbol peek can read across the seam.
The snapshot serialized `src_consumed` verbatim and the resume
factory cleared `prepend_buf`, so the resumed decoder's source
delivered bytes starting **past** the next block's prologue —
the next `read_block` call read garbage. Fix: serialize
`src_consumed - prepend_buf.len()` (the "logical" source cursor)
so the resumed decoder's fresh `src` re-delivers those 4
lookahead bytes as the next block's prologue. Byte-equivalent to
the original lookahead-replay state; avoids serializing the
lookahead bytes themselves. No-op on single-block snapshots
(prepend_buf is always empty there), so the existing
`snapshot_resume_round_trips_at_every_step` test stays green
without changes. The new integration test pins the multi-block
resume path against the curated `multi_block_p27.rar` fixture
(67.5 MB decoded, 2.8 KB compressed — Goldilocks for the tight
checkpoint cadence).

---

## Phase G — Throughput

### §G1. Profiling + targeted hot paths

**What**: `O.7b`-style optimisations after correctness lands.
Bit-table lookups, fast-path literal runs, branchless filter
dispatches. Lives entirely under `src/decode/rar_native/`;
no new files outside that tree.

**Why last**: round-one of the hand-roll prioritises
correctness; throughput is a second pass once the differential
corpus is large enough to be a reliable benchmark.

**Demo**: bench-grid run shows decode throughput within 2× of
the `unrar` C++ reference on the curated corpus.

---

## What "the hand-rolled RAR5 decoder is done" means

All of the following are true:

1. Each phase's demo has been recorded and reviewed.
2. The crash-test harness covers compressed entries in both
   solid and non-solid modes; resumes still produce
   byte-identical output.
3. `OPTIMIZATIONS.md` follow-ons have been amended with the
   leftover items (`O.RAR.CUSTOMFILTER`, etc.).
4. The §3 pipeline's "compression method != 0" rejection has
   been deleted; round-one §4's hand-rolled decoder handles
   methods 1..5.
5. README format-matrix entry for `.rar` no longer carries the
   "STORED only" caveat.
6. CI gates remain green; coverage thresholds (80 % overall,
   95 % on critical paths) hold across the new modules.

## Schedule guidance

Phases are sequenced; do them in order, do each phase
completely. Phase A → B → C → E is the critical path for
"general-purpose RAR5 extraction". Phase F (resume) can land
any time after §E. Phase G (throughput) is optional for the
milestone but expected before the matrix loses its "RAR5 only"
caveat.

## Filed follow-ons (added to `OPTIMIZATIONS.md` after §G ships)

- **`O.RAR.CUSTOMFILTER`** — RAR-VM custom filter slot
  (§C2's deferred follow-up).
- **`O.RAR.MULTITHREAD`** — multi-threaded decode for solid
  archives. Tricky because solid mode shares one
  decompression context across entries, but per-block
  parallel decode within a single entry is plausible after
  §G profiles the hot paths.
