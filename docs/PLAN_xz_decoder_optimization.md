# PLAN — Close the gap to liblzma in `xz_native` after pipeline fixes

**Status**: proposed (2026-05-04). Not started.
**Owner**: TBD.
**Sequenced after**: [`PLAN_checkpoint_blob_dedup.md`](PLAN_checkpoint_blob_dedup.md)
and the bench cadence audit. Those land first; this plan
re-baselines on the post-pipeline state and goes after the
remaining decoder gap.
**Supersedes**: portions of
[`PLAN_xz_throughput.md`](PLAN_xz_throughput.md). That plan's
Phase 0 attribution is reused as a starting point; its Phase 1
shipped as a structural cleanup with 0 % gain (Appendix C); its
Phases 2–6 were filed as deprioritized pending a re-profile.
This plan re-profiles, retires the phases that profiling shows
aren't load-bearing, and promotes the ones that are.
**Related plans**:

- [`PLAN_xz_bench_profile.md`](PLAN_xz_bench_profile.md) — the
  end-to-end bench attribution. Phase 1 closed the pipeline-side
  gap; the residual **after** pipeline fixes lands is decoder-only.
- [`PLAN_xz_parallel_block_decode.md`](PLAN_xz_parallel_block_decode.md)
  — orthogonal lever. Multi-Block decode is the only way to
  *exceed* liblzma single-thread on a multi-Block fixture. This
  plan races liblzma single-thread on the single-Block fixture;
  the two stack.
- [`PLAN_xz_block_decoder.md`](PLAN_xz_block_decoder.md) — the
  parent decoder plan. §Acceptance set "within 4× of liblzma" as
  the ship bar; we cleared it. This plan tightens the bar.

## Why we're doing this

Once [`PLAN_checkpoint_blob_dedup.md`](PLAN_checkpoint_blob_dedup.md)
and the bench cadence audit ship, the bench grid's
`tar.xz · 1 Gbps · 128 MiB` cell looks like:

| Component                                | Time   | Source                                                    |
|------------------------------------------|-------:|-----------------------------------------------------------|
| LZMA decode                              | 4.08 s | `bench_xz_native_tar_xz_128mib_single_block` 31.4 MiB/s   |
| Checkpoint cost (post-dedup, prod cadence)| ~0.40 s | dedup plan's projection                                  |
| Wire (overlapped with decode)            |  0.0 s | 1 Gbps · 109 MiB compressed = 0.87 s, fully overlapped    |
| Other pipeline (write, punch, etc.)      |  0.05 s | well-characterized                                        |
| **Total**                                | **~4.5 s** |                                                       |
| `curl \| xz -d \| tar -x` reference     | 2.65 s | liblzma at 51.5 MiB/s, 128 MiB / 51.5 ≈ 2.48 s decode + 0.17 s misc |
| **Projected ratio**                      | **~1.70×** |                                                       |

The pipeline plans get the bench from today's 2.40× to ~1.67×.
**The remaining ~0.67× is decoder gap.** `peel xz_native`
decodes at 31.4 MiB/s; liblzma decodes the same fixture at
51.5 MiB/s (~64 % of liblzma). Closing the decoder gap is the
only way to bring the bench grid's single-Block tar.xz row near
1× (and the only way to *exceed* liblzma when paired with the
parallel-Block plan on multi-Block fixtures).

`PLAN_xz_throughput.md` Phase 0 already characterized where
decode time goes — but the Phase 0 fixture was incompressible
(LCG-random tar payload) and Phase 1 (the obvious lever, infallible
inner loop primitives) shipped with 0 % gain. Two reasons to
re-profile rather than restart from that plan's hypothesis:

1. **The fixture is wrong for real-world tar.xz.** Phase 0's LCG
   payload makes the model emit ~99 % literals. The match-copy /
   dictionary-access / RLE paths see < 1 % of self-time on that
   fixture but are dominant on real `.tar.xz` (kernel sources,
   distro images, ML datasets). Optimization plans aimed at the
   real-world distribution will get drowned out by the literal
   hot path on Phase 0's fixture; we need a compressible
   counter-fixture.
2. **The pipeline residual masked decoder-side opportunities.**
   Phase 0b's profile saw 8.9 s decode + 95 s overlap; the
   95 s pipeline term made any decoder-side improvement
   indistinguishable from noise. Post-pipeline-fix the decoder
   *is* the bottleneck, so the same `samply` / `dtrace` profile
   will be sharper.

## Hypothesis

The decoder gap to liblzma decomposes into terms in (probable)
descending order:

1. **CRC64 hashing of the output stream** runs byte-by-byte at
   ~1 GB/s on M4 Max. Phase 0 measured 5.9 % of decode time
   ([PLAN_xz_throughput.md:550](PLAN_xz_throughput.md#L550)).
   Implementation at
   [crc64.rs:75-81](../src/hash/crc64.rs#L75-L81) is slicing-by-1.
   Slicing-by-8 / slicing-by-16 yields ~4× speedup; PCLMUL on
   x86-64 yields another order of magnitude; ARM64 has PMULL
   for the same shape. **Estimated gain: 4–6 % of decode time.**
2. **The literal decode hot loop** (probs::decode_literal) is
   71 % of decode self-time on Phase 0's fixture (8 sequential
   bit-tree decode steps per output byte). Each step is:
   `decode_bit(prob_slot)` → multiply, branch, range-update,
   prob-update. liblzma's hand-tuned C inner loop does the same
   ops but presumably with better register allocation, branch
   layout, and prefetching. **Estimated gain: 5–15 %** if we can
   match liblzma's inner-loop structure (table-driven literal
   decode is the speculative ceiling, ~30 %+).
3. **Probability table layout & bounds checks.** Each
   `probs.X[idx]` is a slice access through a `Box<[u16]>`. LLVM
   can elide some bounds checks when it sees the chunk-start
   length validation, but the `Box` indirection inhibits more
   aggressive elision. Restructuring the prob tables as a single
   contiguous array with offset-based access could let LLVM see
   through the indirection. **Estimated gain: 2–5 %.**
4. **Range coder normalize().** Currently does a `pos < bytes.len()`
   bounds check inside `normalize()` even though the call site
   guarantees the bound. Phase 1 of `PLAN_xz_throughput.md`
   tried to make `decode_bit` infallible and got 0 %, suggesting
   LLVM was already eliding this. But profiling under
   `-C target-cpu=native` may show different behavior on Apple
   M4 vs the Phase 1 hardware. **Estimated gain: 0–3 %.**
5. **Match-copy and dictionary access.** ~0.5 % on Phase 0's
   incompressible fixture; **expected to be 10–30 % on a
   compressible fixture** (where the LZMA model emits matches
   instead of literals). The byte-by-byte `match_copy` walk +
   modulo arithmetic in `byte_at` are the candidate inefficiencies.
   Plan's hypothesis from `PLAN_xz_throughput.md` Phases 2 + 3
   (power-of-two ring rounding to elide modulo, bulk
   `copy_within` for non-overlapping matches) stays valid here
   but is now a top-3 candidate on the right fixture.
6. **Data-dependent branches in the inner loop.** LZMA's
   range coder has heavily input-dependent branches; M4 Max's
   branch predictor handles them well but not perfectly. Branch
   layout (`#[cold]` / `#[likely]` annotations, restructuring
   the loop to bias toward the more frequent path) could yield
   **1–3 %**. Diminishing returns past Phases 1–5.

(1)–(2) are cross-fixture wins. (5) is the load-bearing term on
the workloads where peel's resume / multi-mirror story actually
matters (large compressible archives, e.g. ML model bundles,
kernel sources). (3)–(4)–(6) are smaller but compound.

A realistic stack of (1)+(2)+(3)+(5) lands at **80–90 % of
liblzma single-thread** on Apple M4 Max. (5) alone could push
the compressible-fixture number above the bench's
incompressible-fixture number. Beyond 90 % requires research-grade
work (table-driven literal decode, hand-rolled SIMD).

## Scope

### In scope (round one)

- **Re-profile on both the incompressible (current) and a new
  compressible fixture.** A 256 MiB realistic `.tar.xz` corpus —
  e.g. a Linux kernel source tarball or a synthetic compressible
  payload (text + structured binary) that produces a 2–4×
  compression ratio. The compressible profile dictates the
  Phase ordering for items (2), (3), (5).
- **Hardware-accelerated CRC64.** Slicing-by-N first (portable,
  no `unsafe`, no SIMD intrinsics crate). Hardware-specific path
  (PCLMUL on x86-64, PMULL on aarch64) gated behind `cfg`. The
  cross-format CRC32 / CRC32C in `peel`'s hash module is in the
  same shape; this plan addresses xz-specific CRC64 only, but
  files an `OPTIMIZATIONS.md` follow-on for the cross-format
  case.
- **Literal decode hot loop.** Audit liblzma's `lzma_decoder.c`
  hot loop and adopt structural patterns (loop unrolling, branch
  layout, register hints) without copy-pasting code. The
  clean-room policy from `PLAN_xz_block_decoder.md` stays in
  effect; reference is for *behavior at branches*, not source.
- **Probability table layout.** Audit whether the current
  `Box<[u16]>` per category can be merged into a single
  contiguous `Vec<u16>` with category offsets, and whether that
  unlocks LLVM bounds-check elision. Microbench any change.
- **Range coder normalize() and bytes-buffer access.** Re-test
  `Phase 1` of `PLAN_xz_throughput.md`'s premise *under
  `-C target-cpu=native`* on M4 Max — that plan was tested on
  default codegen and found 0 % gain. Different result on aarch64
  with native instructions wouldn't be surprising.
- **Match-copy bulk path.** When source and destination ranges
  in the dict don't overlap (the dominant shape on real-world
  matches), use `slice::copy_within` instead of byte-by-byte.
  When they do overlap (LZMA's RLE-mode), specialize the common
  `dist == 0` (single-byte run) case.
- **Dict access modulo elision.** Round the dict ring's
  underlying buffer up to the next power of two; replace
  `% cap` with `& (cap - 1)`. Same shape as Phase 2 of
  `PLAN_xz_throughput.md`. The user-visible `dict_size` cap
  stays the same; we may allocate up to 2× internally for
  non-power-of-two presets.
- **`unsafe` admitted only when a microbench proves ≥ 5 % gain
  on the regression fixture.** Each block carries a `// SAFETY:`
  proof. Exact policy from `PLAN_xz_throughput.md` §Scope.
- **Cross-format regression check.** Re-run
  `bench_throttled_realistic_grid` and
  `bench_xz_native_tar_xz_*` after each phase; numbers go in the
  commit message.

### Out of scope

- **Multi-Block parallel decode.** Filed as
  [`PLAN_xz_parallel_block_decode.md`](PLAN_xz_parallel_block_decode.md);
  this plan is single-thread only.
- **liblzma FFI.** Violates the std-lib-first dependency policy
  ([`ENGINEERING_STANDARDS.md`](ENGINEERING_STANDARDS.md)) and
  defeats the clean-room goal.
- **Table-driven literal decode.** This is the speculative
  ceiling — pre-compute a transition table for the 8-bit literal
  walk and dispatch a byte via a single load. Estimated 30 %+
  gain *if* it works, but it's a multi-week algorithmic rewrite.
  **Filed as a follow-on plan if the realistic stack lands short
  of the stretch target.**
- **SIMD literal decode.** LZMA's bit-tree decode has
  data-dependencies that prevent straightforward vectorization
  (the next bit's prob slot depends on the previous bit's
  result). Speculative parallel decode could work but is
  research-grade. **Filed as follow-on.**
- **Encoder.** Same as
  [`PLAN_xz_block_decoder.md`](PLAN_xz_block_decoder.md) —
  `peel` never emits xz.
- **Fixture changes for `bench_throttled_realistic_grid`.** That
  bench's fixture stays as-is; we add a *new* compressible
  fixture for *decoder-only* benches. The end-to-end bench
  cadence and shape are owned by other plans.

### Non-goals

- **Beating liblzma in single-thread on Apple Silicon.** liblzma
  has 20+ years of hand-tuning; clean-room Rust without the
  research-grade items (table-driven, SIMD) is not expected to
  match it on a single thread, much less beat it. The plan's
  primary target is **80 % of liblzma**; stretch is **95 %**.
- **Microbenchmark wins that don't carry to the bench grid.**
  Every phase's exit criterion includes a re-run of
  `bench_throttled_realistic_grid` at 1 Gbps · 128 MiB and a
  re-run of `bench_xz_native_tar_xz_*`. A phase that wins
  microbench but doesn't move the bench grid does not exit.
- **Bit-identical resume blob output.** The resume blob format
  stays bit-identical to today's; the plan does not touch
  [`xz_native::resume`](../src/decode/xz_native/resume.rs). The
  per-LZMA2-chunk `frame_boundary` advance is preserved.

## Targets

Targets are deltas against the post-pipeline-plans baseline (i.e.
*after* `PLAN_checkpoint_blob_dedup.md` lands and the bench cadence
audit completes). Not against today's numbers.

- **Decoder-only throughput** on
  `bench_xz_native_tar_xz_128mib_single_block`:
  - Today: 31.4 MiB/s (61 % of liblzma's 51.5 MiB/s).
  - **Primary target**: ≥ **41 MiB/s** (≥ 80 % of liblzma; ~30 %
    speedup over today).
  - **Stretch target**: ≥ **48 MiB/s** (≥ 95 % of liblzma).
- **Compressible-fixture decoder throughput** (new fixture, see
  Phase 0):
  - Baseline established in Phase 0.
  - **Primary target**: ≥ 80 % of liblzma's number on the same
    fixture.
- **`bench_throttled_realistic_grid` `tar.xz` row** — projected
  given the assumed pipeline floor:
  - At Phase 1 (CRC64): ratio ≤ **1.62×** at 1 Gbps · 128 MiB.
  - At Phase 4 (literal + probs + matches stack): ratio ≤
    **1.30×**.
  - At stretch (matching liblzma): ratio ≤ **1.05×**.
  - **Below 1×** is **not achievable** by single-thread decoder
    optimizations on this fixture; that's the parallel-Block
    plan's job.
- **Cross-fixture regression**: Phase 0's incompressible fixture
  must not regress more than 5 % at any phase. The optimization
  for compressible workloads must not pessimize the
  incompressible case.
- **Differential corpus byte-identical to `xz2`** — every phase.
  100-fixture randomized differential corpus from
  [`PLAN_xz_block_decoder.md`](PLAN_xz_block_decoder.md) Phase 9.
- **Crash-resume harness byte-identical** — every phase.
  [`tests/test_coordinator_crash.rs`](../tests/test_coordinator_crash.rs)
  100 randomized kill points.
- **`unsafe` discipline preserved** — every block carries
  `// SAFETY:` and is justified by ≥ 5 % microbench improvement.

## Approach

### Re-shaped phase ordering

The original `PLAN_xz_throughput.md` ordered phases by *expected
hypothesis impact*. This plan orders by *measured impact* against
both the incompressible and a new compressible fixture. The
phases are rotations / promotions of the original list:

| Original plan | This plan | Change                                        |
|---------------|-----------|-----------------------------------------------|
| Phase 1: range coder | Phase 4 (low priority) | Already 0 % gain; demoted             |
| Phase 2: dict access | Phase 5 (compressible-only) | Demoted, fixture-gated         |
| Phase 3: bulk match copy | Phase 5 (compressible-only) | Demoted, fixture-gated     |
| Phase 4: literal fast path | Phase 3 | Promoted (84 % of self-time)              |
| Phase 5: chunk staging | retired | Phase 0 measured 0.05 % — non-event     |
| Phase 6: probs BCE | Phase 4 | Renumbered                                |
| (new) CRC64 | Phase 1 | Promoted from `PLAN_xz_throughput.md` Appendix A item 5 (5.9 % of decode) |
| Phase 7: validate | Phase 6 (validate) | Renumbered                       |

### What "going after liblzma" means structurally

`liblzma`'s `lzma_decoder.c` does the same algorithm as our
`xz_native::lzma2`. The wins in 20 years of tuning are:

1. **Inner loop register pressure.** liblzma's hot loop hand-codes
   register usage so the LZMA model state (`range`, `code`, the
   active prob slot pointer, the symbol cursor) stays in
   registers across the bit-tree walk. Rust's auto-codegen does
   well but not as well; LLVM may spill / reload across
   `decode_bit` calls. Mitigation: aggressive `#[inline(always)]`
   on the bit-decode helper, structural fusion of `normalize()`
   into `decode_bit()` so the codegen sees the whole flow.
2. **Branch layout.** liblzma uses GCC `__builtin_expect` to bias
   the branch predictor's static prediction toward the
   bit-zero path of literal decode (which is the more frequent
   on most data). Rust has `core::intrinsics::likely` /
   `unlikely` (nightly) and `core::hint::cold_path`; portable
   via `#[cold]` on rare paths.
3. **Buffer access elision.** liblzma reads from a `*const uint8_t *`
   pointer and trusts the input length validated at chunk start.
   Our `RangeDecoder` validates length at construction
   ([range_coder.rs:200](../src/decode/xz_native/range_coder.rs#L200))
   so the same elision is *available* — the question is whether
   LLVM sees it. `cargo asm` on `normalize` before/after a
   given commit is the verification.
4. **CRC64 algorithm.** liblzma uses slicing-by-4 by default
   ([liblzma's `crc64_table.c`](https://github.com/tukaani-project/xz/blob/master/src/liblzma/check/crc64_table.c)),
   plus PCLMUL on x86-64 (`crc64_x86.S`), plus ARMv8 PMULL on
   aarch64. Our slicing-by-1 is the easy 4× win.

This plan's commits are clean-room Rust adaptations of the
*shapes* (not the source code) — same legal posture as the
original `PLAN_xz_block_decoder.md`.

### Profile workflow

The plan's "measured impact" gating depends on a profile
workflow that anyone on the team can reproduce. Document it in
[`tests/test_bench_xz_native.rs`](../tests/test_bench_xz_native.rs)'s
module docs as an addendum:

- **Apple M4 Max**: `samply record --rate 4000 -- target/release/deps/test_bench_xz_native-*
  bench_xz_native_decode_loop_for_profiling --ignored --nocapture`.
  Open the resulting profile in
  [Firefox Profiler](https://profiler.firefox.com/).
- **Linux x86-64**: `perf record -F 4000 -g -- target/release/deps/test_bench_xz_native-*
  bench_xz_native_decode_loop_for_profiling --ignored --nocapture`,
  then `perf script | inferno-flamegraph > flame.svg`.
- **Detailed counters** (Linux only):
  `perf stat -e instructions,branches,branch-misses,L1-dcache-load-misses,LLC-load-misses
  -- target/release/deps/test_bench_xz_native-* bench_xz_native_decode_loop_for_profiling
  --ignored --nocapture`. Branch miss rate and IPC are the
  diagnostic signal for whether (2) and (6) are load-bearing.

Each phase's commit message names the exact profile fixture
(incompressible / compressible), the percentage moves of the
top-5 self-time symbols, and the IPC / branch-miss-rate delta
where available.

## Phasing

Each phase ends green on `cargo test`,
`cargo clippy -- -D warnings`, `cargo fmt --check`, and the
crash-resume + differential corpora. Each phase's commit message
records the bench grid `tar.xz` ratio delta and the decoder-only
MiB/s delta on both fixtures.

### Phase 0 — Re-baseline post-pipeline (2 days)

- Confirm `PLAN_checkpoint_blob_dedup.md` and the bench cadence
  audit have shipped (this plan is gated on them landing first).
- Re-run `bench_xz_native_tar_xz_*` on M4 Max + at least one
  Linux x86-64 host. Record the post-pipeline-fix decoder-only
  baseline. (Should be unchanged from today's 31.4 MiB/s on the
  128 MiB fixture; pipeline plans don't touch the decoder.)
- Re-run `bench_throttled_realistic_grid` and capture the
  post-pipeline tar.xz ratios. These are the "before" numbers
  for this plan's commits.
- **Add a compressible-fixture sibling** to
  [`tests/test_bench_xz_native.rs`](../tests/test_bench_xz_native.rs):
  - `bench_xz_native_compressible_128mib_single_block` — same
    shape as today's bench but with a structured payload that
    produces a 2–4× compression ratio. Two choices:
    - (a) A bundled fixture: a small embedded snapshot of a real
      compressible blob (e.g., a tarred subset of Cargo's git
      checkout, ~64 MiB on disk). Cleanest signal but ships
      bytes in the repo.
    - (b) A synthetic generator: text-like patterns +
      structured binary that compresses representatively. No
      repo bytes; reproducible. Probably the right choice.
  - Pick (b) unless (a) shows materially different per-symbol
    distribution.
- Re-profile with `samply` (M4) and `perf` (Linux) on both
  fixtures. Top-5 self-time symbols + IPC + branch-miss-rate.
- Document baselines in this plan's Appendix A.

**Exit criterion**:
- Post-pipeline baseline recorded; all subsequent phases use it
  as the reference.
- Compressible fixture in tree; differential corpus extended to
  cover it (the new fixture must round-trip byte-identical to
  `xz2`).
- Per-symbol attribution table in Appendix A for both fixtures.

### Phase 1 — CRC64 slicing-by-N (3 days)

- Replace the byte-by-byte loop in
  [`crc64.rs:75-81`](../src/hash/crc64.rs#L75-L81) with
  slicing-by-8 (process 8 bytes per iteration via 8 lookup
  tables). Same shape as
  [Intel's slicing-by-N paper](https://www.researchgate.net/publication/4334341_Fast_CRC_computation_for_genericpolynomials_using_PCLMULQDQ_instruction).
  Pure Rust, no `unsafe`, portable.
- Add a microbench
  `bench_crc64_throughput` to
  [`tests/test_bench_xz_native.rs`](../tests/test_bench_xz_native.rs)
  that times CRC64 over a 1 GiB random buffer. Today: ~1 GB/s.
  Target: ≥ 4 GB/s (slicing-by-8) or ≥ 8 GB/s (slicing-by-16).
- Differential test against the existing slicing-by-1 (the new
  implementation must produce byte-identical CRCs across a
  randomized fixture corpus).
- Optional sub-phase 1b — hardware CRC64 on x86-64 via PCLMUL.
  Gated behind `target_arch = "x86_64"` and a feature flag if
  needed. Must keep the slicing-by-N fallback. Microbench must
  show ≥ 5× over slicing-by-N to justify `unsafe` for the
  intrinsic; otherwise file as follow-on.
- Optional sub-phase 1c — ARM64 PMULL on Apple Silicon.
  `aarch64_target_feature(enable = "aes")` (PMULL is in the
  AES extension on aarch64). Same gating as 1b.

**Exit criterion**:
- CRC64 microbench shows ≥ 4× over today.
- Phase 0's `bench_xz_native_tar_xz_*` decoder-only number
  improves by ≥ 4 % (5.9 % of decode at 4× = 4.5 % gain).
- Differential corpus byte-identical.
- `bench_throttled_realistic_grid` `tar.xz` ratio drops by ≥
  0.04 (e.g. 1.67× → ≤ 1.63×).

### Phase 2 — Match copy + dict access (compressible-fixture-driven; 3–4 days)

- This phase is gated on Phase 0's *compressible* profile
  showing match_copy / byte_at as ≥ 10 % of self-time. (On the
  incompressible fixture, both are < 1 %; the phase wouldn't
  pay back there.) If the compressible profile shows otherwise,
  *swap this phase with Phase 3*; profile-led ordering is the
  whole point.
- **Bulk match copy.** In
  [`LzmaDict::match_copy`](../src/decode/xz_native/dict.rs):
  branch on whether source and dest ranges overlap inside the
  ring (i.e., `length > dist + 1`).
  - When they don't overlap: one `copy_within` (or
    `ptr::copy_nonoverlapping` with `// SAFETY:` proof). The
    typical no-overlap case is the dominant shape on
    compressible payloads.
  - When the source range wraps the ring's end: split into two
    `copy_within` calls.
  - When they overlap (LZMA RLE): keep byte-by-byte, but
    specialize `dist == 0` (single-byte run) using
    `slice::fill`.
- **Power-of-two ring rounding.** Round
  [`LzmaDict`](../src/decode/xz_native/dict.rs)'s underlying
  buffer up to the next power of two. Replace `% cap` in
  `byte_at` and `push` with `& (cap - 1)`. The user-visible
  `dict_size` cap stays the same; we may allocate up to 2×
  internally for non-power-of-two presets (worst case 128 MiB
  at preset 9; bounded). Document the assumption in
  `dict.rs`'s module docs.
- **Specialize `prev_byte` lookup.** The literal hot path calls
  `byte_at(0)` to fetch the previous byte; that byte is in
  scope from the most recent `push`. Stash it in a local
  variable to avoid the dict access entirely.

**Exit criterion**:
- Compressible-fixture decoder MiB/s improves by ≥ 8 %.
- Incompressible fixture MiB/s does not regress > 2 % (this
  phase doesn't touch the literal hot path; ≤ 2 % is noise).
- Differential corpus byte-identical on both fixtures.
- Crash-resume green.

### Phase 3 — Literal decode hot loop (5–7 days)

- This is the load-bearing phase. 71 % of self-time on Phase 0's
  fixture, ~50 %+ on a typical compressible fixture (literals
  still dominate in absolute count even when matches grow).
- Audit
  [`probs::decode_literal`](../src/decode/xz_native/probs.rs#L505)
  against liblzma's
  [`lzma_decoder.c`'s LITERAL macro](https://github.com/tukaani-project/xz/blob/master/src/liblzma/lzma/lzma_decoder.c)
  (clean-room: read for *what branches and unrolls liblzma
  does at this level*, not source).
- **Unroll the 8-bit walk** explicitly. LLVM may already do this
  on some platforms; `cargo asm` confirms. If unrolled, leave
  alone; if not, write the explicit 8-step body. Both arms of
  the matched-vs-plain split.
- **Cache the active prob slot pointer.** Today the index into
  `context: &mut [u16]` is recomputed per bit
  ([probs.rs:547](../src/decode/xz_native/probs.rs#L547)). The
  index *is* `symbol`, but `symbol` updates per bit too; this
  is structural. Verify with `cargo asm` whether the bounds
  check is being elided per iteration; if not, hoist a
  `let context_ptr = context.as_mut_ptr();` and use
  `unsafe { &mut *context_ptr.add(idx) }` with `// SAFETY:`
  proof of `idx < LITERAL_CODER_SIZE` from the symbol invariants.
- **Branch layout for the matched path.** The matched path
  (`!is_literal_state`) is taken when the prior position is a
  match-end; on highly compressible data this is ~20–40 % of
  the time. On the incompressible fixture it's near 0 %.
  Profile both. Use `core::hint::cold_path` (or
  `core::intrinsics::cold` on nightly) for the rarer branch.
- **Inline `RangeDecoder::decode_bit` and `normalize`** more
  aggressively. The `#[inline]` annotations are present but
  may not be `#[inline(always)]`. Switch and microbench.

**Exit criterion**:
- Both fixtures' decoder MiB/s improve by ≥ 8 %.
- IPC on Linux x86-64 improves by ≥ 0.05 (a quarter-instruction
  per cycle on the inner loop).
- Differential corpus byte-identical.
- The asm dump of `decode_literal` (committed to `docs/profiles/`
  as a regression artifact) shows no `panic_bounds_check` calls
  in the inner loop.

### Phase 4 — Range coder + probability tables (4 days)

- **Probability table layout.** Audit
  [`LzmaProbs`](../src/decode/xz_native/probs.rs)'s field
  shape: today each category is its own `Box<[u16]>`. Switch
  to a single contiguous `Vec<u16>` with category offsets
  (`is_match: usize, is_rep: usize, …`). This lets LLVM see
  through one indirection layer; bounds checks on the inner
  category accesses become checks on the single backing store.
  Microbench the change.
- **Range coder normalize().** Re-test the `Phase 1 of
  PLAN_xz_throughput.md` premise on M4 Max under
  `-C target-cpu=native`. The original plan tested on default
  codegen; aarch64 with native flags may produce different
  inner-loop code. If `cargo asm` shows the bounds check is
  still emitted, eliminate it via the chunk-start length proof
  (with `// SAFETY:` justification).
- **Inline `bit_tree_decode` + `bit_tree_reverse_decode`** into
  the same translation unit as `decode_bit`. They are tiny;
  cross-function inlining hasn't always fired in the past.
  `#[inline(always)]` if needed.

**Exit criterion**:
- Both fixtures' decoder MiB/s improve by ≥ 3 %.
- Asm dump of `decode_chunk`'s inner loop shows no
  `panic_bounds_check` and no spill/reload of the LZMA model
  state across `decode_bit` calls (regression artifact).
- Differential corpus byte-identical.

### Phase 5 — Reserved for the second-largest item that surfaced (2–4 days)

- Phase 0's profile may surface an item not in the hypothesis
  list. Phase 5 is the catch-all for the second-largest
  unattributed term, gated on Phase 0–4 results.
- Likely candidates:
  - Cache layout / memory placement of probs vs dict.
  - Branch-prediction misses on a specific distance/length
    decode path.
  - A specific liblzma optimization the audit revealed.
- This phase's scope is decided after Phase 0 completes.

**Exit criterion**:
- Whatever phase 5 ends up being: ≥ 5 % gain on the relevant
  fixture, no regression on the other.

### Phase 6 — Validate against the targets (2 days)

- Re-run `bench_throttled_realistic_grid` and
  `bench_xz_native_tar_xz_*` on M4 Max + Linux x86-64.
- Confirm primary target (≥ 80 % of liblzma) on both fixtures
  on both platforms.
- Refresh README's bench grid `tar.xz` row with the new
  numbers.
- Refresh README's "Reading the grid" prose: the xz-row caveat
  shrinks proportionally to the new ratio.
- Update
  [`PLAN_xz_block_decoder.md`](PLAN_xz_block_decoder.md) Phase 0
  spike memo's "production" line with the new measured number.
- File follow-on items in `OPTIMIZATIONS.md`:
  - Table-driven literal decode (research-grade; ~30 %+
    speculative gain).
  - Hand-rolled SIMD for literal decode (research-grade).
  - Hardware CRC64 across formats (currently filed for xz only).

**Exit criterion**:
- Primary target met on both platforms.
- README updated.
- Follow-on plans filed.
- All tests green.

## Risks

1. **Realistic stack lands short of 80 %.** Phases 1–5 collectively
   win 10–25 % is the rough estimate; the spread is wide because
   compressible-fixture-vs-incompressible-fixture ordering matters.
   If the stack lands at 70 %, Phase 6 either re-bases the target
   or promotes a follow-on. **Mitigation**: explicit phase exit
   criteria; a phase that doesn't pay back is reverted before
   the chain proceeds.
2. **`unsafe` discipline.** The plan admits `unsafe` for
   bounds-check elision when a microbench proves ≥ 5 % gain. The
   risk is "one block bleeds into a culture of skipping bounds
   checks." **Mitigation**: each block carries `// SAFETY:` AND a
   commit-message microbench number AND a code review by a second
   pair of eyes — the same discipline that keeps the io_uring
   backend's `unsafe` from metastasizing.
3. **Phase 1 PCLMUL / PMULL delivery on hardware.** Hardware CRC64
   intrinsics need `cfg`-gated `#[target_feature]`. ABI-correct
   intrinsic use requires careful `unsafe` proofs. **Mitigation**:
   1b/1c are *optional* sub-phases; the slicing-by-N portable
   path is the load-bearing commit. Hardware paths only ship if
   they're easy *and* clearly profitable.
4. **Apple-vs-x86 divergence.** A win on M4 Max may not carry
   to AVX2 / AVX-512 hosts and vice versa. **Mitigation**:
   Phase 0 baselines on at least one of each; reject any phase
   whose change regresses one arch even if it wins on the other.
5. **Compressible fixture choice biases the rest of the plan.**
   If we pick a fixture that's "too compressible" (e.g.,
   highly-redundant text), the match-heavy phases over-fit. If
   we pick "too incompressible" (LCG-random), the literal phases
   over-fit. **Mitigation**: target a 2–3× compression ratio,
   which is the typical real-world `.tar.xz` shape. Document the
   choice rationale in Phase 0's commit.
6. **Chasing micro-wins past the 80 % bar produces diminishing
   returns and complexity creep.** The stretch target (≥ 95 %)
   is genuinely speculative; any phase that proposes a > 200 LoC
   addition for < 3 % gain should be rejected and filed as a
   research follow-on. **Mitigation**: explicit "is this phase
   paying back?" checkpoint at the end of each commit.
7. **The bench grid ratio doesn't move proportionally.** If
   decoder-only MiB/s jumps 30 % but the bench grid only moves
   15 %, there's residual pipeline cost we missed. **Mitigation**:
   Phase 6's re-validation catches this and triggers a
   follow-on `PLAN_xz_bench_profile.md` Phase 2 (sample profiler)
   to find the new bottleneck.

## Acceptance criteria

- ✅ `bench_xz_native_tar_xz_128mib_single_block`: peel ≥ 41 MiB/s
  (≥ 80 % of liblzma) on Apple M4 Max and modern x86-64.
- ✅ `bench_xz_native_compressible_128mib_single_block` (new):
  peel ≥ 80 % of liblzma on the same fixture.
- ✅ `bench_throttled_realistic_grid` `tar.xz` row at
  1 Gbps · 128 MiB: ratio ≤ **1.30×** (post-pipeline + this plan).
- ✅ Cross-fixture regression: incompressible fixture does not
  regress > 5 % at any phase.
- ✅ Differential corpus byte-identical to `xz2` for both
  fixtures, every phase.
- ✅ Crash-resume harness: 100 random kill points, byte-identical
  output, every phase.
- ✅ Per-LZMA2-chunk `frame_boundary` advance and resume blob
  bit-identical to today.
- ✅ Every `unsafe` block carries `// SAFETY:` + microbench
  justification of ≥ 5 % gain.
- ✅ `cargo test`, `cargo clippy -- -D warnings`,
  `cargo fmt --check` all green.
- ✅ README's xz-row prose updated.
- ✅ At least one (and at most three) follow-on plan stubs
  filed in `OPTIMIZATIONS.md`.

## Estimated total effort

Roughly **3–4 weeks** for one engineer:

- Phase 0: 2 days (re-baseline + new fixture + initial profile).
- Phase 1: 3 days (CRC64 slicing-by-N; optional 1b/1c hardware
  paths).
- Phase 2: 3–4 days (match copy + dict access; gated on
  compressible-fixture profile).
- Phase 3: 5–7 days (literal decode hot loop; the load-bearing
  phase).
- Phase 4: 4 days (range coder + probs tables).
- Phase 5: 2–4 days (catch-all for surfaced item).
- Phase 6: 2 days (validate, document, file follow-ons).

Phase 3 is the largest single piece. Phases 2 and 4 are
microbench-gated; either could shrink if profiling shows the
hypothesis isn't load-bearing on this hardware.

## Combined gain projection (with sibling plans)

What the bench grid's `tar.xz · 1 Gbps · 128 MiB` cell looks like
across the plan stack:

| Configuration                                            | total  | ratio  | notes                                                              |
|----------------------------------------------------------|-------:|-------:|--------------------------------------------------------------------|
| Today                                                    | 6.35 s | 2.40×  | `PLAN_xz_bench_profile.md` Phase 0 baseline                        |
| + checkpoint blob dedup                                  | ~5.5 s | ~2.07× | Saves ~14 ms × 189 ckpts ≈ 2.6 s; 50 ms cadence still in effect    |
| + bench cadence audit (50 ms → 2 s)                      | ~4.5 s | ~1.70× | Saves ~163 fewer ckpts × 14 ms ≈ 2.3 s                             |
| **+ this plan, primary (≥ 80 % of liblzma)**             |~3.6 s  |~1.36×  | Decode 4.08 s → 3.12 s                                             |
| + this plan, stretch (≥ 95 % of liblzma)                 |~3.05 s |~1.15×  | Decode 4.08 s → 2.69 s                                             |
| + parallel-Block decode (4 workers, multi-Block fixture) |~1.4 s  |**~0.50×** | Decode further 2.69 → ~0.68 s; multi-Block fixture only         |

The 1× line is touched (just barely) at the stretch target on
the single-Block fixture, but reliably crossed only with
multi-Block parallelism. The decoder optimization plan's job is
to **make the floor low enough that parallel decode can be a
2–3× win** rather than a 4–6× win — and to bring the
single-Block fixture from "2.4× behind" to "essentially even."

## Reference material

- [`PLAN_xz_throughput.md`](PLAN_xz_throughput.md) — the parent
  plan. Phase 0 / 0b appendices have the per-symbol
  attribution this plan reuses; Phase 1's appendix documents
  why the obvious `Result`-removal lever didn't work.
- [`PLAN_xz_block_decoder.md`](PLAN_xz_block_decoder.md) — the
  decoder's parent plan. §Acceptance set "within 4× of liblzma"
  as the original ship bar.
- [`PLAN_xz_bench_profile.md`](PLAN_xz_bench_profile.md) — the
  pipeline diagnosis. Phase 1 closed the pipeline-side gap; this
  plan picks up where pipeline ends and decoder begins.
- liblzma's `lzma_decoder.c`
  ([source](https://github.com/tukaani-project/xz/blob/master/src/liblzma/lzma/lzma_decoder.c))
  — clean-room reference for "what does the canonical decoder
  do at this branch", consulted for *behavior at branches* per
  the project's clean-room policy (no source copy).
- liblzma's `crc64_table.c`
  ([source](https://github.com/tukaani-project/xz/blob/master/src/liblzma/check/crc64_table.c))
  — slicing-by-4 reference for Phase 1.
- The .xz file-format spec
  ([tukaani.org/xz/xz-file-format.txt](https://tukaani.org/xz/xz-file-format.txt))
  — referenced for cross-checking that fast-paths preserve
  semantics; no wire-format changes here.
- [`tests/test_bench_xz_native.rs`](../tests/test_bench_xz_native.rs)
  — the regression gate; this plan's commits each name a delta
  vs the Phase 0 baseline recorded here.
- [`tests/test_xz_native.rs`](../tests/test_xz_native.rs) — the
  differential corpus; every phase must be byte-identical to
  `xz2` across this corpus.
- [`tests/test_coordinator_crash.rs`](../tests/test_coordinator_crash.rs)
  — the crash-resume harness; every phase 100/100 byte-identical.

## Appendix A — Results

### Phase 0 baseline (post-pipeline-fix, 2026-05-04)

Captured on Apple M4 Max (`darwin 25.3.0`, `RUSTFLAGS="-C
target-cpu=native -C debuginfo=2"`, `--release`). Linux x86-64
row pending — filed as a Phase 0 follow-up; the M4 row is the
load-bearing reference for subsequent phases.

#### Decoder-only MiB/s — Apple M4 Max

| Fixture                                          | peel MiB/s | xz2 MiB/s | xz2/peel | peel/xz2 |
|--------------------------------------------------|-----------:|----------:|---------:|---------:|
| 64 MiB · single-Block · preset 6 · LCG           |       33.0 |      54.1 |    1.64× |    61.0% |
| 128 MiB · single-Block · preset 6 · LCG          |       32.6 |      53.0 |    1.62× |    61.5% |
| 256 MiB · single-Block · preset 6 · LCG          |       28.2 |      45.1 |    1.60× |    62.5% |
| 64 MiB · single-Block · preset 6 · compressible  |       49.7 |      75.8 |    1.52× |    65.6% |
| 128 MiB · single-Block · preset 6 · compressible |       50.7 |      78.3 |    1.54× |    64.7% |
| 256 MiB · single-Block · preset 6 · compressible |       49.3 |      76.5 |    1.55× |    64.5% |

Compressible fixture's xz-encoded compression ratio ≈ 2.22×
(128 MiB → 57.7 MiB on wire; same number across all three sizes).
Inside the 2–4× design band gated by
[`compressible_payload_ratio_in_band`](../tests/test_bench_xz_native.rs).

**Cross-fixture observations**:
- Both decoders are ~50 % faster on the compressible fixture
  (peel 50.7 MiB/s vs 32.6 MiB/s; xz2 78.3 MiB/s vs 53.0 MiB/s).
  Match-output mode emits multiple bytes per range-coder step;
  literal mode emits one. Compressible inputs spend more time in
  match-output → higher throughput.
- The peel/liblzma gap is *narrower* on compressible (64.7 % vs
  61.5 % at 128 MiB). Inverting the plan's hypothesis: the *literal*
  hot loop has more headroom than match-copy on this hardware,
  not the other way around. Phase 3 (literal decode) is even more
  load-bearing than the plan's hypothesis assumed.

#### Bench grid `tar.xz` baseline — Apple M4 Max

| Cell                       | peel  | curl\|xz\|tar | ratio  |
|----------------------------|------:|--------------:|-------:|
| 10 Mbps · 8 MiB · tar.xz   | 7.126 |         6.377 |  1.12× |
| 100 Mbps · 32 MiB · tar.xz | 2.616 |         2.520 |  1.04× |
| 1 Gbps · 128 MiB · tar.xz  | 4.334 |         2.661 |  1.63× |
| 10 Gbps · 256 MiB · tar.xz | 9.796 |         6.032 |  1.62× |

Headline cell `1 Gbps · 128 MiB`: **1.63×**, slightly better than
the plan's projected 1.67× post-pipeline floor. This is the "before"
number for Phase 1's exit criterion (≤ 1.62×, 0.04 drop) and Phase 4's
(≤ 1.30×).

#### Per-symbol attribution (incompressible fixture, 30 s `sample`)

`sample(1)` on M4 Max attached to `bench_xz_native_decode_loop_for_profiling`
mid-iteration; 1 ms sample interval; total decoder-thread samples =
2088. (Main thread spent the entire window in `semaphore_wait_trap`
and is excluded from the percentages.)

| Symbol                                              | samples | self % | notes                                                |
|-----------------------------------------------------|--------:|-------:|------------------------------------------------------|
| `xz_native::probs::decode_literal`                  |    1755 |  84.0% | the literal hot loop; corroborates Phase 0 of `PLAN_xz_throughput.md` (71 %) and bumps it higher on M4 |
| `xz_native::check::BlockCheckHasher::update` (CRC64)|     152 |   7.3% | byte-by-byte slicing-by-1; Phase 1 target            |
| `xz_native::lzma2::Lzma2State::decode_chunk`        |     151 |   7.2% | range-coder dispatch + chunk framing                 |
| `decode_step` (extractor harness)                   |      12 |   0.6% | not load-bearing                                     |
| `xz_native::probs::decode_length`                   |      12 |   0.6% | matches' length decode; rare on this fixture         |
| `xz_native::dict::LzmaDict::match_copy`             |       6 |   0.3% | < 1 %, as Phase 0 of the parent plan reported        |

**Cumulative**: top three sum to 98.5 %; everything else is noise.

#### Per-symbol attribution (compressible fixture, 25 s `sample`)

`sample(1)` on M4 Max attached to `bench_xz_native_decode_loop_for_profiling_compressible`;
1 ms interval; total decoder-thread samples = 21624.

| Symbol                                              | samples | self % | notes                                                                                |
|-----------------------------------------------------|--------:|-------:|--------------------------------------------------------------------------------------|
| `xz_native::probs::decode_literal`                  |   15073 |  69.7% | still the largest term — the plan's hypothesis (~50 %+ on compressible) was conservative |
| `xz_native::check::BlockCheckHasher::update` (CRC64)|    1929 |   8.9% | per-output-byte work, slightly higher cost-share than incompressible because output bytes/sec is higher |
| `xz_native::probs::decode_distance`                 |    1503 |   7.0% | **invisible on incompressible (< 0.1 %); newly load-bearing here** — see Phase 5 candidate |
| `xz_native::lzma2::Lzma2State::decode_chunk`        |    1450 |   6.7% | range coder + dispatch                                                               |
| `xz_native::probs::decode_length`                   |     755 |   3.5% | ~6× the incompressible share (matches ⇒ length encodes)                              |
| `xz_native::dict::LzmaDict::match_copy`             |     737 |   3.4% | ~10× the incompressible share, as the plan hypothesized; smaller absolute number than the 10–30 % hypothesis |
| `_platform_memmove`                                 |     177 |   0.8% | tail of `match_copy`'s bulk-copy path (already uses `copy_within` for the non-overlap case) |

**Cumulative**: top four sum to 92.3 %; top six sum to 99.2 %.

**Surprises vs. the plan's hypothesis** (each one updates the
phasing, but doesn't invalidate the plan):

1. `decode_distance` was not on the hypothesis list at all and
   is now the **third-largest term on compressible** (7.0 %).
   It's a textbook Phase 5 catch-all candidate. The function
   does a 6-bit `bit_tree_reverse_decode` for short distances
   and direct-bit decoding for long ones; same shape as
   `decode_literal`'s inner loop, so wins from Phase 3 may
   compound here.
2. `match_copy` lands at 3.4 % on compressible, not the
   hypothesized 10–30 %. Reading
   [`dict.rs`](../src/decode/xz_native/dict.rs), the non-overlap
   path is already a `copy_within` call (Phase 2's main lever
   is partially shipped). The remaining work is the overlap /
   RLE specialization and the power-of-two ring rounding. Phase
   2's exit-criterion floor (≥ 8 % gain) needs revisiting in
   light of this; the available budget is closer to ≤ 5 %.
3. `decode_literal` is *bigger* than the plan thought (84 % on
   incompressible, plan hypothesized 71 %; 70 % on compressible,
   plan hypothesized 50 %). Promotes Phase 3 even further as the
   single load-bearing phase.

#### Phase ordering revision in light of Phase 0

The plan's Phase 5 (catch-all) slot is now tentatively claimed by
`decode_distance`. The plan's Phase 2 (match copy + dict) needs
its exit-criterion floor reduced from 8 % to 5 % given the
already-shipped `copy_within` work. Both updates land in the
respective phase commits; this Phase 0 commit only records the
findings.

### Phase 1 results (CRC64) (TBD)

| Fixture | peel before | peel after | Δ % | bench grid ratio |
|---------|------------:|-----------:|----:|-----------------:|

### Phase 2 results (match copy + dict) (TBD)

### Phase 3 results (literal decode) (TBD)

### Phase 4 results (range coder + probs) (TBD)

### Phase 5 results (catch-all) (TBD)

### Phase 6 final bench grid (TBD)

| Format   | 10 Mbps · 8 MiB | 100 Mbps · 32 MiB | 1 Gbps · 128 MiB | 10 Gbps · 256 MiB |
|----------|----------------:|------------------:|-----------------:|------------------:|
| `tar.xz` |                 |                   |                  |                   |
