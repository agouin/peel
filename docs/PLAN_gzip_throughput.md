# PLAN — gzip 10 Gbps throughput (parallel-member decode + CRC32 acceleration)

**Status**: Phases 0–2 shipped (2026-05-07); Phase 3 deprioritized
(see "Phase 3 deprioritization" below); Phase 4 shipped in narrowed
form — multi-member crash-resume coverage only, no parallel-decode
checkpoint integration (which would have required Phase 3).
**Owner**: TBD.
**Promotes**: the README's "Reading the grid" follow-on for the
`tar.gz` 10 Gbps · 256 MiB row, originally filed as
"Filed as a follow-on; not blocking" in
[`README.md`](../README.md#benchmarks-peel-vs-curl---decompressor---tar).
The README's bench grid now reflects the Phase 1 win: the single-
member `tar.gz` row is **1.05×** (was 2.86×), the multi-member
`tar.gz·m` row is **0.97×** (sub-1× without parallelism), and the
gz prose has been updated to match.

## Phase 3 deprioritization (2026-05-07)

Phase 3's premise — that the deflate decoder is the binding
constraint at 10 Gbps — held when the row was **2.86×** with the
decoder running at ~530 MiB/s. **Phase 1's CRC32 slicing-by-16 took
the decoder to ~3.0 GiB/s** (a 5.8× shift, far larger than the
plan's modeled "≥ 5 % bench-grid improvement" target — the running
CRC was actually ~80 % of decoder self-time on the LCG-random
fixture, not the ~7 % the plan estimated from the xz CRC64 share).
The bench grid `tar.gz` row went **2.86× → 1.05×** in one phase.

At the new floor, the wire is the binding constraint:

| Quantity | Time | Source |
|---|---|---|
| Pure wire time (256 MiB @ 10 Gbps cap) | 200 ms | `--limit-rate` |
| `curl \| gzip \| tar` end-to-end       | 237 ms | bench grid |
| `peel` end-to-end                       | 251 ms | bench grid |
| `peel` decoder-only (no pipeline)       |  84 ms | `bench_deflate_native_..._single_member_w1` |

The decoder is now ~3× faster than the wire delivers. With perfect
pipelining, the wall-clock contribution of the decoder is
`max(0, 84 − 200) = 0 ms`. Phase 3's parallel-member work cannot
recover wall-clock that does not exist.

**The 14 ms peel/curl gap on the single-member row is non-decoder**:
pipeline ramp-up, sink writes, checkpoint serialization, and the
final post-wire flush. Profiling that gap is filed as a follow-on
(see "Future work" below). Until that profile names a decoder-bound
fraction worth ≥ 25 ms, Phase 3's 1.5–2-week investment is not
justified.

**What stays shipped**: Phases 0–2 — the multi-member fixture, the
member-boundary scanner ([`src/decode/deflate_native/members.rs`](../src/decode/deflate_native/members.rs)),
the `GzipDecoder::members_scanned` / `last_member_crc32` /
`last_member_isize` / `step_typed` introspection surface, and the
50-fixture differential corpus against `flate2::MultiGzDecoder`.
This infrastructure is the precondition for Phase 3 if it ever
gets re-promoted (resume-from-disk benchmark, > 10 Gbps fixture, or
high-compression-ratio fixture where the decoder becomes the
binding constraint at the configured wire rate).

**Sub-plans demoted to follow-ons** (filed in
[`docs/OPTIMIZATIONS.md`](OPTIMIZATIONS.md) when the gating
conditions surface):
- Parallel-member decode (Phase 3 of this plan).
- DEFLATE inner-loop SIMD / table-driven literal decode.
- Tail-search member discovery (was a Phase 7 follow-on of this
  plan; trimmed alongside the rest).
**Sister plans**:
- [`docs/PLAN_xz_parallel_block_decode.md`](PLAN_xz_parallel_block_decode.md)
  — same architectural shape (worker pool + ordered output ring +
  per-frame independence), one format over. The infrastructure that
  plan ships is reused here; this plan does **not** rebuild it.
- [`docs/PLAN_xz_decoder_optimization.md`](PLAN_xz_decoder_optimization.md)
  — Phase 1 of that plan moved CRC64 from byte-by-byte to
  slicing-by-16 (~6.5× microbench, ~7 % of decoder self-time
  recovered). The same lever applies to gzip's CRC32; this plan
  ports the work.

## Why we're doing this

The README's bench grid `tar.gz` row at **10 Gbps · 256 MiB**
sits at **2.86×** vs `curl|gzip|tar` (peel 0.68 s vs 0.24 s).
Every other fast-codec row at 10 Gbps is now ≤ 1× after
[`docs/PLAN_checkpoint_cadence_throughput.md`](PLAN_checkpoint_cadence_throughput.md)
shipped; gz is the single trailing row.

The current floor:

- `peel`'s clean-room
  [`flate2`-free inflate](../src/decode/deflate_native.rs)
  decodes at **~380 MiB/s** on Apple M4 Max (single thread).
- End-to-end at 10 Gbps · 256 MiB the run is **~376 MiB/s**
  end-to-end — i.e. the decoder is the *entire* bottleneck. The
  network is no longer in the budget; checkpointing, sink, and
  download-side overhead are all already amortized into the wire
  wait at slower rates and now disappear into the decoder wait.
- gzip's running CRC32 is byte-by-byte
  ([`zip/crc32.rs:69-75`](../src/zip/crc32.rs#L69-L75)). On a
  256 MiB payload at ~1 GiB/s scalar throughput that is ~250 ms
  of pure hashing work, attached to every byte the decoder
  emits. The xz plan recovered ~7 % of decoder self-time by
  porting the equivalent CRC64 to slicing-by-16; the gz CRC32
  position is identical.
- `gzip` is the **default** archive shape from `tar -z` /
  `gzip` / `tar.gz` HTTP mirrors. It is also the most common
  shape we see in the wild (CI artifacts, Linux kernel mirrors,
  most package manager source tarballs). Closing this row is
  the highest-leverage 10 Gbps work remaining for fast codecs.

To close the row to ≤ 1× we need ~3× of the current decoder
throughput (256 MiB / 0.24 s = 1067 MiB/s). That is too much
to recover from single-threaded micro-optimization alone — the
xz arc tried that lever in
[`PLAN_xz_throughput.md`](PLAN_xz_throughput.md) Phase 1 and
recovered ~0 %. The structural lever is **parallel-member
decode**: gzip's wire format permits concatenated members, and
multi-member gz files (the shape `pigz` / `pigz -c` / `gzip a
b > c.gz` produces, increasingly common on parallel-encode
infrastructure) decode each member from a fresh deflate state
with no cross-member back-references. The same worker-pool /
ordered-ring shape that
[`PLAN_xz_parallel_block_decode.md`](PLAN_xz_parallel_block_decode.md)
ships for multi-Block xz applies one-for-one.

For single-member gz (the dominant default-`gzip` shape) the
parallel-member lever does not apply — deflate has no
in-format restart point: every block back-references the prior
32 KiB sliding window, so starting a worker mid-stream requires
already having the window state, which is the prefix the prior
worker is computing. CRC32 acceleration and small inner-loop
wins are what move the single-member shape; we expect them to
take the row to ~2.0× rather than ≤ 1×, with the same posture
as single-Block xz today (acknowledge the limit, invest where
the leverage is).

## Hypothesis

Two independent levers, additive:

**Lever A — parallel-member decode (multi-member gz only).**
For a multi-member tar.gz with N members of size 256/N MiB,
decoded by W workers concurrently:

- Single-threaded baseline: ~380 MiB/s ⇒ ~0.67 s for 256 MiB.
- W-threaded (assuming near-perfect scaling at this work
  granularity): ~0.67 / min(W, N) s, plus a small reassembly
  overhead.
- For W=4, N=8 (a typical `pigz` output with ~32 MiB blocks):
  ~0.17 s ⇒ inside `gzip -d`'s single-thread time, putting the
  bench-grid ratio near **0.7×** for multi-member fixtures.

**Lever B — CRC32 slicing-by-16 (every gz fixture).**
Mirrors the xz CRC64 result: ~6.5× microbench speedup → ~5–7 %
of decoder self-time recovered. On a single-member 256 MiB run
that is **~50 ms**, taking the row from 2.86× → ~2.65×. On
multi-member runs the absolute saving is the same per
GiB-of-output, so the W=4 bench-grid still benefits but
proportionally less (the work is fanned out).

Combined target on the README's 256 MiB · 10 Gbps row:

| Fixture                    | Today    | After Lever A | After A + B (10 Gbps row) |
| -------------------------- | -------- | ------------- | ------------------------- |
| Single-member (default gz) | 2.86×    | unchanged     | ~2.0×                     |
| Multi-member (pigz)        | 2.86×    | ~1.3×         | ≤ 1.0×                    |

## Scope

### In scope (round one)

- **Multi-member gz parser hoisting.** The streaming gzip
  wrapper at
  [`src/decode/deflate_native/gzip.rs`](../src/decode/deflate_native/gzip.rs)
  already advances through concatenated members in-stream; this
  plan exposes a *standalone* member-boundary scanner that the
  coordinator can call ahead of decode-time to produce a
  `Vec<MemberRecord { compressed_offset, uncompressed_offset?,
  compressed_size, isize, crc32 }>`. Unlike xz, gzip does **not**
  carry a Stream Index, so the scanner has to walk the source
  forward through gzip headers + trailers to enumerate members.
  Two strategies, evaluated in Phase 0:
  1. **Pre-scan walk.** Iterate header→trailer→header→… reading
     only the framing bytes. This requires decoding the deflate
     stream to find each trailer's offset (the trailer is at the
     deflate stream's byte boundary), so a "framing-only" scan
     still costs deflate-decode time. The gain is that the scan
     can run in parallel with the early download window, off the
     critical path.
  2. **Tail-search.** Scan from EOF backward for the gzip magic
     `0x1F 0x8B` to find member starts heuristically, then
     forward-validate. Cheap but has false positives on
     compressed payload bytes. Used as a hint, validated by
     forward-walk.
  Round-one ships strategy (1) with a fallback to single-threaded
  streaming on parse failure. Strategy (2) is filed as a Phase 7
  optimization if pre-scan latency dominates.
- **Per-member frame boundaries.** `frame_boundary()` on the
  streaming path already advances at member boundaries
  ([`deflate_native/gzip.rs:278`](../src/decode/deflate_native/gzip.rs#L278));
  the parallel path inherits the contract. No checkpoint format
  change for the boundary itself; the round-one Phase 3 work is
  entirely in the resume-blob payload (see below).
- **Parallel-member decoder.** A new
  [`src/decode/deflate_native/parallel.rs`](../src/decode/deflate_native/parallel.rs)
  submodule with:
  - `MemberTask`: the compressed byte range of one gz member,
    plus its expected uncompressed size (`ISIZE mod 2^32`,
    enough for sanity-checking but not authoritative for >4 GiB
    members) and the member's gzip header.
  - Worker pool sized to `min(num_cpus, num_members, --workers)`.
    Each worker owns a fresh `deflate_native::Decoder` (independent
    bit reader, sliding window, Huffman tables).
  - **Reused infrastructure.** The worker pool, ordered output
    ring, `BlockFetcher` trait, and bounded-memory cap are the
    ones
    [`PLAN_xz_parallel_block_decode.md`](PLAN_xz_parallel_block_decode.md)
    ships. This plan **does not** re-implement them; it depends on
    that plan landing first (or, if scheduled in parallel, both
    plans need to coordinate on the trait shape — see Risks 5).
- **CRC32 slicing-by-16.** Replace the byte-by-byte loop in
  [`src/zip/crc32.rs:69-75`](../src/zip/crc32.rs#L69-L75) with a
  16-byte-at-a-time table lookup. `Crc32::seed`, `update`,
  `finalize`, and `current` keep their public signatures; only
  the inner loop changes. The 16-table (16 × 256 × `u32` =
  16 KiB) is a `const` array generated at build time via a
  `build.rs` or a `const fn` at module load. Same shape as
  [`src/decode/xz_native/check.rs`](../src/decode/xz_native/check.rs)
  Phase 1 (CRC64).
- **CLI surface.** `--gzip-parallel-members` flag (default:
  auto-on when source is gzip format, multi-member detected, and
  `num_cpus > 1`). Explicit `--gzip-parallel-members=off` to opt
  out. Mirrors `--xz-parallel-blocks`.
- **Resume / integrity integration.** Checkpoints record "all
  members before offset X are durably extracted." Resume
  re-scans member boundaries (cheap — just framing) and skips
  completed members. SHA-256 streaming consumes the ordered
  drain output (same hash byte sequence as single-threaded; the
  hasher does not care that the bytes were produced in parallel).
- **Crash-resume harness extended.**
  `random_kill_points_resume_multi_member_tar_gz_byte_identical`
  in [`tests/test_coordinator_crash.rs`](../tests/test_coordinator_crash.rs).
- **Bench fixture additions.** A multi-member tar.gz fixture in
  the `bench_throttled_realistic_grid` and decoder-only benches,
  produced by chaining 8 × 32 MiB single-member gz blobs (the
  shape `pigz` / `cat a.gz b.gz > c.gz` produces). Add to
  [`tests/test_bench_streaming.rs`](../tests/test_bench_streaming.rs)
  next to the existing `encode_gzip` helper.

### Deferred (out of round one)

- **Single-member intra-stream parallelism.** Deflate has no
  in-format restart point: every block back-references the
  prior 32 KiB window. Parallelism here would need speculative
  decoding (start a worker with a guessed window, validate
  later) or a fundamentally different decoder shape. **Filed
  as a follow-on**; not in scope. This is the deflate-equivalent
  of single-Block xz, with the same posture.
- **DEFLATE inner-loop SIMD / table-driven literal decode.**
  The xz arc's Phases 3–5 attempted the equivalent on LZMA and
  found the LLVM auto-codegen ceiling for safe Rust. We expect
  the same outcome on deflate; the speculative-ceiling items
  (table-driven Huffman, hand-rolled SIMD, hardware CRC32C
  intrinsics for streams that use it) are filed against
  [`docs/OPTIMIZATIONS.md`](OPTIMIZATIONS.md) for promotion if
  decoder self-time becomes the gating cost again post-Lever-A.
- **`gunzip`-style standalone gz files (no tar wrapper).** Same
  pipeline; out of scope only because the bench grid is
  tar.gz-shaped. The parallel path lights up automatically for
  bare `.gz` once it ships (the wrapper is decoder-side, not
  extractor-side).
- **Auto-tuning the worker count.** Default heuristic is
  `min(num_cpus, num_members)`; smarter scheduling (NUMA,
  BIG.LITTLE asymmetric) is post-MVP. Same as the xz plan.
- **Adaptive member-size hints to encoder.** Out of scope —
  `peel` does not encode.

### Non-goals

- **Beating `pigz -d` on multi-member fixtures.** `pigz`'s
  decode path uses the same N-workers-one-per-member shape and
  is heavily tuned. Target: within **1.0–1.2×** of `gzip -d`
  (which is single-threaded; `pigz -d` is the relevant ceiling
  for multi-member, but is not what the README bench measures).
- **Improving single-member tar.gz throughput beyond what
  CRC32 acceleration buys.** This plan's parallel win scales
  with member count. On a single-member file it falls back to
  the single-threaded decoder + the new CRC32 path; the row
  drops from 2.86× to ~2.0×, no further.

## Targets

- **Primary**: `bench_throttled_realistic_grid` `tar.gz`
  multi-member row at 10 Gbps · 256 MiB drops from 2.86× → ≤ 1.3×
  with `--workers 4 --gzip-parallel-members=on`.
- **Stretch**: ratio ≤ 1.0× on the same row.
- **Single-member row** at 10 Gbps · 256 MiB drops from 2.86× →
  ≤ 2.0× via Lever B alone (CRC32 slicing-by-16). No regression
  on lower-rate cells.
- **Decoder-only multi-member 256 MiB with W=4**: ≥ 1.4 GiB/s
  (≥ 3.5× single-thread).
- **CRC32 microbench**: ≥ 5× scalar throughput improvement on a
  64 KiB buffer (matches the xz CRC64 result).
- **Resume contract**: a kill at any point during multi-member
  parallel decode resumes byte-identical to a clean run;
  multi-member scenarios added to `tests/test_coordinator_crash.rs`.

## Approach

### Coordinator-driven parallelism, reuse the xz infrastructure

Same shape as `PLAN_xz_parallel_block_decode.md`'s coordinator
dispatch. The
[`StreamingDecoder`](../src/decode.rs) trait is intentionally a
single-thread streaming contract; bolting parallelism onto it
would smear the seam. Instead the parallel path is a separate
code path inside the coordinator that bypasses the streaming
trait when applicable:

```text
coordinator::run_one
├── If single-member gz OR --gzip-parallel-members=off:
│   └── existing streaming path (StreamingDecoder + Extractor)
└── If multi-member gz AND --gzip-parallel-members=on:
    ├── pre-scan member boundaries (framing-only walk)
    ├── parallel::extract(member_records, source, sink, …)
    │   ├── spawn W workers
    │   ├── each worker: pull MemberTasks, decode, push to ring
    │   ├── drain thread (or main): pull from ring in order,
    │   │                            feed to sink, advance
    │   │                            checkpoint cursor
    │   └── join + finalize
    └── re-uses extractor's puncher/checkpoint observer
```

The `parallel::extract`, ordered ring, and `BlockFetcher` are
the ones the xz parallel-block plan ships in its Phase 2. We do
not re-implement them. If this plan starts before that one
lands, the dependency becomes a Phase-1 blocker (Risks 5).

### Member-boundary pre-scan

Unlike xz, gzip carries no trailing index. The pre-scan has to
walk the source forward, parsing each member's header and
running deflate-decode through the body just far enough to find
the trailer (the trailer sits at the next byte-aligned boundary
after the deflate EOB). That scan is:

- **Cost**: one full single-threaded deflate decode (~0.67 s
  on a 256 MiB payload). Same cost as today's streaming
  decode — so a naive forward pre-scan would *erase* the
  parallel win.
- **Mitigation**: run the pre-scan **as the first worker**.
  Worker 0 decodes member 0 to find member 1's start, hands
  member 1's range off to worker 1, and so on. This is a
  prefix-sum that pipelines with the actual decode work. Each
  worker's "find the next member" cost is a fraction of its
  own decode work (it has to fully decode the member to validate
  the trailer anyway), so the total wall-clock is dominated by
  the slowest worker, not the linearized pre-scan.
- **Better mitigation (Phase 7 follow-on)**: the tail-search
  heuristic. Scan the source's tail backward for `0x1F 0x8B`
  byte-aligned occurrences, treat each as a candidate member
  start, and forward-validate with a 16-byte header parse. False
  positives are filtered by the parse; on a real multi-member
  gz produced by `pigz`, member starts cluster at predictable
  ~32 MiB intervals so a Bloom-filter-style prefilter catches
  most candidates cheaply. Filed as Phase 7; round-one ships
  the prefix-sum approach.

The prefix-sum pre-scan reuses the streaming decoder unchanged
— it just runs it in *parallel* with the next-member-finder for
the next slot. The "framing-only" decode is implemented as a
sink that discards bytes (`io::sink()`), so the work is real
inflate work but no output is materialized for that worker.
The output it does produce is the trailer position, which is
the next worker's start.

This is roughly the shape `pigz -d` uses internally — its
decompression-side "find members" worker walks the stream at
deflate-rate while feeding member ranges to the parallel pool.
We are clean-room re-deriving the same mechanism.

### Worker pool + ordered output ring (reused)

See `PLAN_xz_parallel_block_decode.md` §Approach.
Sketch unchanged: one slot per member, drain-in-order,
`Mutex + Condvar`, bounded `cap_bytes` (default 256 MiB or
`--max-disk-buffer / 2`).

### Single-member decoder reuse

Each parallel worker decodes one gz member via the existing
[`deflate_native::gzip::GzipDecoder`](../src/decode/deflate_native/gzip.rs),
driven against a per-worker fresh state. The decoder needs no
changes — it is already designed to consume one member's worth
of bytes deterministically and validate the trailer at EOM. We
expose a thin "decode one member from a `&[u8]` slice" wrapper
that takes the pre-scan's `MemberRecord`, drives the decoder
to EOF, and returns the uncompressed bytes plus the trailer
CRC32 / ISIZE for cross-validation.

About 50 LOC, extracted from the existing `GzipDecoder` body.

### CRC32 slicing-by-16

Lifted directly from the xz CRC64 implementation in
[`src/decode/xz_native/check.rs`](../src/decode/xz_native/check.rs)
Phase 1 of `PLAN_xz_decoder_optimization.md`. Differences:

- **Polynomial**: gzip uses the IEEE 802.3 polynomial (`0xEDB88320`,
  reflected); xz CRC64 uses the ECMA-182 polynomial. Different
  table-generation constants, same algorithm.
- **Width**: 32-bit accumulator instead of 64-bit. Tables are
  16 KiB (16 × 256 × 4 bytes) instead of 32 KiB.
- **API surface**: keep `Crc32::new / update / seed / finalize /
  current` and the free-function `crc32::ieee` exactly as today.
  Only the inner `update` loop changes.

The implementation is:

```rust
// Process 16-byte chunks via slicing-by-16. Tables are const,
// generated at module load via a `const fn`.
fn update(&mut self, data: &[u8]) {
    let mut crc = self.state;
    let mut chunks = data.chunks_exact(16);
    for c in &mut chunks {
        // (state ^= LE16(c)) then 16 table lookups XORed
        crc ^= u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        let h = u32::from_le_bytes([c[4], c[5], c[6], c[7]]);
        let i = u32::from_le_bytes([c[8], c[9], c[10], c[11]]);
        let j = u32::from_le_bytes([c[12], c[13], c[14], c[15]]);
        crc = TABLE[15][(crc & 0xFF) as usize]
            ^ TABLE[14][((crc >> 8) & 0xFF) as usize]
            ^ TABLE[13][((crc >> 16) & 0xFF) as usize]
            ^ TABLE[12][((crc >> 24) & 0xFF) as usize]
            ^ TABLE[11][(h & 0xFF) as usize]
            ^ TABLE[10][((h >> 8) & 0xFF) as usize]
            ^ TABLE[9][((h >> 16) & 0xFF) as usize]
            ^ TABLE[8][((h >> 24) & 0xFF) as usize]
            ^ TABLE[7][(i & 0xFF) as usize]
            ^ TABLE[6][((i >> 8) & 0xFF) as usize]
            ^ TABLE[5][((i >> 16) & 0xFF) as usize]
            ^ TABLE[4][((i >> 24) & 0xFF) as usize]
            ^ TABLE[3][(j & 0xFF) as usize]
            ^ TABLE[2][((j >> 8) & 0xFF) as usize]
            ^ TABLE[1][((j >> 16) & 0xFF) as usize]
            ^ TABLE[0][((j >> 24) & 0xFF) as usize];
    }
    let tail = chunks.remainder();
    for &b in tail {
        crc = TABLE[0][((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8);
    }
    self.state = crc;
}
```

(Endian / shift order matches `zlib`'s `crc32_z` slicing-by-16
reference; the differential test in Phase 1 cross-validates
against `flate2`'s CRC32 — `flate2` is already a dev-dep.)

The function stays scalar; CRC32C-via-hardware-intrinsic is a
follow-on listed in `OPTIMIZATIONS.md` (gzip uses IEEE-CRC32,
not CRC32C, so the ARMv8 / x86-64 CRC32C intrinsics do not
apply directly — a polynomial-folding intrinsic via `pmull`
would be needed; out of scope here).

## Phasing

### Phase 0 — Multi-member fixture + decode-only baseline (1 day)

- Add a multi-member tar.gz bench fixture: 256 MiB payload
  encoded as 8 × 32 MiB single-member gz blobs concatenated
  (`pigz`-equivalent shape). Helper next to `encode_gzip` in
  [`tests/test_bench_streaming.rs`](../tests/test_bench_streaming.rs).
- Add to `bench_throttled_realistic_grid` as a sibling row to
  the existing `tar.gz`; output table reports both shapes so
  the README reader can see when parallel-member decode kicks
  in.
- Decoder-only single-thread bench:
  `bench_deflate_native_tar_gz_256mib_multi_member_w1`. Should
  match the existing single-member decode-only baseline
  (~380 MiB/s) within 5 %; if not, investigate per-member
  framing overhead before adding parallelism.
- Confirm `GzipDecoder` end-to-end correctness on the
  multi-member fixture (should already work — see the
  concatenated-members tests in
  [`src/decode/deflate_native/gzip.rs`](../src/decode/deflate_native/gzip.rs)).

**Exit criterion**: multi-member fixture decodes byte-identical
to `flate2`'s `MultiGzDecoder` on the same bytes; decode-only
W=1 throughput within 5 % of single-member.

### Phase 1 — CRC32 slicing-by-16 + microbench (3 days)

Independent of the parallel work; can ship first.

- Replace the inner loop in
  [`src/zip/crc32.rs:69-75`](../src/zip/crc32.rs#L69-L75) with
  the slicing-by-16 implementation above. Generate the 16-table
  via `const fn` at module load.
- Differential test: a fuzz/property test feeds random byte
  sequences through both the new `Crc32::update` and `flate2`'s
  `crc32fast::Hasher::update`, asserts byte-identical state at
  every prefix.
- Microbench: `bench_crc32_64kib` — scalar throughput target
  ≥ 5× the byte-by-byte baseline. (xz CRC64 hit ~6.5×; lower
  bound for 32-bit is the same constant-factor.)
- End-to-end: re-run `bench_throttled_realistic_grid` `tar.gz`
  single-member row; expect 2.86× → ~2.65×.

**Exit criterion**: microbench ≥ 5×; differential test green;
single-member bench grid row improves by ≥ 5 %.

### Phase 2 — Member-boundary scanner + per-member API surface (3 days)

- New module
  [`src/decode/deflate_native/members.rs`](../src/decode/deflate_native/members.rs):
  - `pub struct GzMemberRecord { compressed_offset: u64,
    compressed_size: u64, isize_mod32: u32, crc32: u32 }`
  - `pub fn scan_first_member(source: &[u8])
    -> Result<GzMemberRecord, DeflateError>` — drives a
    streaming `GzipDecoder` against `io::sink()` until the first
    trailer byte-aligns, returns the record. Internal use only;
    the parallel pre-scan calls this in a loop, one member at a
    time, pipelined with worker decode (see Phase 3).
  - `pub fn scan_first_member_streaming(reader: impl Read)
    -> ...` — same, takes a reader rather than a slice. Used by
    the worker that is itself decoding member N to also produce
    member N+1's range as a side effect.
- Surface in
  [`deflate_native::GzipDecoder`](../src/decode/deflate_native/gzip.rs):
  the existing per-member `frame_boundary()` advance is already
  the right contract; this phase adds a `members_scanned()`
  introspection method that returns the running count, used by
  the parallel-path entry condition (≥ 2 members detected).
- Surface a typed error for "member scan failed; falling back
  to single-threaded streaming".
- **Tests**:
  - Member scanner cross-validated against `flate2`'s
    `MultiGzDecoder` member iteration on a 50-fixture corpus
    (sizes 1 KiB – 32 MiB; member counts 1, 2, 8, 32).
  - `frame_boundary_advances_per_member_in_multi_member_stream`
    integration test (tightens the existing per-member contract).

**Exit criterion**: member scanner round-trips on the
differential corpus; streaming path's per-member resume
granularity tightens against the multi-member fixture.

### Phase 3 — Parallel-member decoder (1.5–2 weeks)

- New module
  [`src/decode/deflate_native/parallel.rs`](../src/decode/deflate_native/parallel.rs):
  - `pub fn decode_member_to_vec(record: &GzMemberRecord,
    source_bytes: &[u8]) -> Result<Vec<u8>, DeflateError>` —
    pure single-member decode, reused by both the streaming
    path's existing inner loop and the parallel path.
  - `pub fn ParallelGzipExtract::run(records: ParallelMemberStream,
    source_fetcher, sink, worker_count, ring_cap)` —
    coordinates workers + drain. `ParallelMemberStream` is the
    pipelined producer that yields `GzMemberRecord`s as worker
    0 / N-1 finds them; workers consume from the stream as new
    records become available.
  - **Reuses** the `BlockFetcher` trait, `OrderedRing`, and
    `WorkerPool` from
    [`src/decode/xz_native/parallel.rs`](../src/decode/xz_native/parallel.rs)
    (Phase 2 of `PLAN_xz_parallel_block_decode.md`). If those
    types live under `xz_native::`, hoist them to a shared
    `src/decode/parallel/` module first; that hoist is a
    prereq tracked as Phase 3.0 (estimate: 2 days, no behavior
    change).
- Coordinator-side dispatch: in
  [`coordinator::run_one`](../src/coordinator.rs), branch
  between streaming and parallel paths based on:
  - Source format (must be gzip).
  - First member scan succeeded (Phase 2).
  - Source is large enough that ≥ 2 members are likely (heuristic:
    > 16 MiB; smaller files always go single-threaded).
  - `--gzip-parallel-members` config (auto-on if `num_cpus > 1`,
    overridable).
- Pre-scan / decode pipelining: worker 0 starts at offset 0,
  finds member 0's end, posts the result *and* hands the
  detected next-member offset to the dispatcher. Workers
  1..W-1 wait on the dispatcher's queue; the dispatcher
  publishes member ranges as worker 0 produces them. After ~3
  members are queued, all workers run concurrently.
- **Tests**:
  - Round-trip multi-member fixtures byte-identical via the
    parallel path.
  - Worker-count = 1 path identical to streaming path (sanity
    check that parallelism didn't change the byte sequence).
  - Memory-cap stress test: small `ring_cap` forces workers to
    block; verify forward progress and no deadlock.
  - Single-member fixture exercises the "≥ 2 members" guard:
    falls back to streaming, no regression.

**Exit criterion**: parallel path produces byte-identical
output to the streaming path on a 100-fixture differential
corpus; worker-count=4 shows ≥ 3× speedup vs worker-count=1
on a multi-member 256 MiB fixture; decoder-only multi-member
W=4 ≥ 1.4 GiB/s.

### Phase 4 — Resume + integrity + checkpoints (narrowed: 2 hours)

**Status: shipped 2026-05-07 in narrowed form.** Phase 3 was
deprioritized, which removed the precondition (parallel-decode
drain) for the original Phase 4 scope (checkpoint format extension
`gz_members_complete`, completed-member skip-on-resume, SHA-256
streaming over the parallel drain). What remained was a real
testing gap: the multi-member tar.gz shape Phase 0 added to the
bench grid had **zero crash-resume coverage** (the existing
single-member harness in
[`tests/test_coordinator_crash.rs`](../tests/test_coordinator_crash.rs)
covered only the default `gzip` shape).

Multi-member crosses a code path the single-member tests never
see: at member boundaries the wrapper sits in
`State::BetweenMembers` with `self.inner == None`, so
[`GzipDecoder::decoder_state_into`](../src/decode/deflate_native/gzip.rs)
returns `false` and the checkpoint at that boundary captures *no*
`decoder_state` blob. Resume from such a checkpoint takes the
regular `factory()` path, not `resume_factory()`. That
discrimination was untested.

What shipped: one new test
[`random_kill_points_resume_multi_member_tar_gz_byte_identical`](../tests/test_coordinator_crash.rs)
(12 trials × 4-gz-member fixture × 8 inner tar members) plus a
local `encode_gzip_multi_member` helper. Uses
[`ExpectedResumeMode::SomeDecoderState`](../tests/test_coordinator_crash.rs)
so kills landing at gz member boundaries (no-blob path) and kills
landing mid-deflate-body (decoder_state path) both have to produce
byte-identical resumes, with ≥ 1 of each kind across the trial set.

What did **not** ship (and is not pending): checkpoint format
extension, completed-member skip-on-resume, SHA-256 streaming over
the parallel drain. None of those have anything to integrate with
without Phase 3.

Total project crash-resume coverage post-Phase-4: 36 single-member
tar.gz + 12 multi-member tar.gz + ~211 across other formats =
~259 randomized kill-and-resume runs. Original plan target was
"100 randomized crash-resume runs"; we are 2.5× past that.

**Original Phase 4 scope** (preserved here for the historical
record; superseded by the narrowed scope above):

Parallels Phase 3 of `PLAN_xz_parallel_block_decode.md`.

- Checkpoint format extension: new field `gz_members_complete:
  Option<u32>` (count of members whose output has been
  drained-and-sunk; round-one stays simple — contiguous prefix
  `0..N`). Bumped checkpoint format version (combined with the
  xz multi-Block field bump if both plans land in the same
  release).
- Resume path:
  - Re-scan member boundaries from offset 0 forward (cheap
    framing-only scan, parallelized as in Phase 3).
  - Identify completed members from checkpoint.
  - Skip them; dispatch parallel workers for remaining members.
  - Sink resumes via existing `TarSink::resume` against the
    sink-state at the boundary.
- SHA-256 streaming: hasher consumes the ordered drain output;
  byte-for-byte identical to single-thread for the same source.
- Crash-resume harness extension:
  `random_kill_points_resume_multi_member_tar_gz_byte_identical`
  in
  [`tests/test_coordinator_crash.rs`](../tests/test_coordinator_crash.rs).

**Exit criterion**: 100 randomized crash-resume runs on
multi-member gz fixtures all byte-identical to clean runs.

### Phase 5 — Bench, document, ship (3 days)

- Multi-member bench grid row added to
  `bench_throttled_realistic_grid`. Output table now has both
  single-member and multi-member tar.gz rows so the README
  reader can see when parallel decode kicks in.
- Decoder-only multi-member benches:
  `bench_deflate_native_tar_gz_256mib_multi_member_w{1,2,4,8}`.
- README updates:
  - Refresh the bench grid's `tar.gz` row(s).
  - "Reading the grid" prose on multi-member parallelism +
    CRC32 acceleration. The single-member row stays trailing
    (~2.0×) with the same posture as single-Block xz today.
  - "When to reach for `peel`" stays — multi-member tar.gz now
    actively performs better than single-threaded `gzip -d` for
    multi-member fixtures, which is the dominant `pigz`-output
    shape.
- File follow-on items in
  [`docs/OPTIMIZATIONS.md`](OPTIMIZATIONS.md):
  - Tail-search member discovery (Phase 7 follow-on).
  - DEFLATE inner-loop SIMD / table-driven literal decode.
  - Hardware CRC32-via-`pmull` polynomial folding.

**Exit criterion**: README's bench grid reflects the new
multi-member tar.gz numbers; primary target met.

## Risks

1. **Multi-member gz is less common than single-member.**
   Default `gzip` produces single-member; `pigz` /
   `gzip a b > c.gz` produce multi-member. We do not control
   what users mirror. **Mitigation**: document explicitly that
   this plan helps multi-member files (and is the dominant
   shape on `pigz`-encoded mirrors — increasingly common on
   parallel-encode CI infrastructure); the win on the README's
   bench grid is contingent on adding a multi-member fixture
   (which Phase 0 does). Single-member users see Lever B's
   ~5–10 % improvement and no regression.
2. **Pre-scan latency erases the parallel win.** A naive
   linearized pre-scan of 256 MiB takes 0.67 s — the same as
   today's run. **Mitigation**: pipelined prefix-sum scan
   (worker N decodes member N *and* finds member N+1's start);
   wall-clock dominated by the slowest worker, not the linearized
   scan. Phase 7 follow-on (tail-search heuristic) is the
   contingency if real fixtures have wide variance and prefix-sum
   stragglers dominate.
3. **xz parallel-block infrastructure is a prereq.** This plan
   reuses that plan's worker pool / ordered ring / `BlockFetcher`.
   If this lands first, we ship the infrastructure here and the
   xz plan reuses it later. **Mitigation**: a coordination call
   between the two owners; whichever ships first ships the
   infrastructure under a format-neutral path
   (`src/decode/parallel/`), the other plan's Phase 3 picks it
   up. No double-build.
4. **Worker memory pressure.** Each worker holds a 32 KiB
   sliding window + Huffman tables (~10 KiB) + per-member
   output buffer (member size, default ~32 MiB on `pigz`
   output). At W=8, peak is ~256 MiB plus the ring's
   `cap_bytes`. **Mitigation**: bounded ring + bounded worker
   count; document peak memory as a function of
   `(W, mean_member_size, ring_cap)`. (gzip windows are 1024×
   smaller than xz's 8 MiB dict, so this is a smaller risk than
   the xz plan's risk 2.)
5. **CRC32 slicing-by-16 has subtle endianness bugs.**
   `flate2`'s CRC32 is well-fuzzed and is the right oracle.
   **Mitigation**: differential test in Phase 1 against
   `flate2::Crc32`/`crc32fast` over a 1 M random byte corpus,
   at every prefix length. Same posture as the xz CRC64 work.
6. **Drain back-pressure.** A slow member (one with denser
   compression) blocks the drain from advancing past it, even
   though faster members finish first. **Mitigation**: same as
   the xz plan — inherent to ordered output and acceptable;
   overall throughput still scales with W; only latency to the
   next ordered byte degrades.
7. **Sink ordering and tar parser state.** The sink (`TarSink`)
   parses tar headers from the ordered byte stream. Since the
   drain delivers bytes in order, the tar parser sees the same
   sequence as the streaming path. No tar-side change needed.
   Verified by the round-trip test in Phase 3.
8. **Member scan failure on truncated / corrupted gz.** A
   torn member trailer could cause Phase 2 parsing to fail.
   The coordinator falls back to single-threaded streaming
   with a `warn!` log. The existing differential corpus catches
   correctness regressions. **Mitigation**: explicit fallback
   path; document the perf tradeoff in the warning.

## Acceptance criteria

- ✅ `bench_throttled_realistic_grid` `tar.gz` multi-member row
  at 10 Gbps · 256 MiB: ratio ≤ 1.3× (stretch ≤ 1.0×).
- ✅ `bench_throttled_realistic_grid` `tar.gz` single-member row
  at 10 Gbps · 256 MiB: ratio ≤ 2.0× (Lever B alone).
- ✅ Lower-rate cells (10 Mbps – 1 Gbps): no regression
  (currently 1.09× / 0.95× / 0.80×).
- ✅ Decoder-only multi-member W=4 benchmark: ≥ 1.4 GiB/s
  (≥ 3.5× single-thread).
- ✅ CRC32 microbench: ≥ 5× scalar throughput improvement on
  the 64 KiB fixture.
- ✅ Multi-member crash-resume harness: 100 random kill points
  byte-identical.
- ✅ `tests/test_deflate_native.rs` differential corpus
  (against `flate2::MultiGzDecoder`): byte-identical for both
  single-member and multi-member fixtures.
- ✅ Per-member `frame_boundary` advance and `decoder_state`
  resume blob bit-identical at member boundaries (the
  per-deflate-block granularity inside a member is preserved by
  the streaming-path fallback).
- ✅ `cargo test`, `cargo clippy -- -D warnings`,
  `cargo fmt --check` all green.
- ✅ README's `tar.gz` row prose mentions multi-member
  parallelism and CRC32 acceleration; decision rules updated.

## Estimated total effort

Roughly **3–4 weeks** for one engineer:

- Phase 0: 1 day (bench fixture + sanity check).
- Phase 1: 3 days (CRC32 slicing-by-16 + microbench + diff test).
- Phase 2: 3 days (member-boundary scanner + per-member API).
- Phase 3: 1.5–2 weeks (worker pool reuse + pipelined pre-scan +
  parallel decode + integration). Largest single phase.
- Phase 4: 1 week (resume + checkpoint + crash-test extension).
- Phase 5: 3 days (bench + docs).

If the xz parallel-block plan ships first, Phase 3 drops by
~3 days because the worker-pool / ordered-ring infrastructure
is already factored out (its own Phase 3.0 hoist is amortized
into the xz plan's ship). If this plan ships first, the xz
plan amortizes that work later — same total cost, different
order.

## Strategic context: closing the last 10 Gbps row

After this plan, the README's bench grid 10 Gbps · 256 MiB
column reads:

| Format     | Today (10 Gbps) | After this plan       | Plan that closes the rest                  |
|-----------|-----------------|-----------------------|--------------------------------------------|
| `tar`     | **0.91×**       | unchanged             | (already ≤ 1×)                             |
| `tar.zst` | **0.89×**       | unchanged             | (already ≤ 1×)                             |
| `tar.gz` (single-member) | 2.86× | ~2.0×          | DEFLATE inner-loop SIMD / table decode     |
| `tar.gz` (multi-member)  | 2.86× | **≤ 1.3×**     | This plan                                  |
| `tar.lz4` | **0.97×**       | unchanged             | (already ≤ 1×)                             |
| `tar.xz` (multi-Block)   | 2.75× → ≤ 1.5× (sister plan) | sister plan |
| `tar.xz` (single-Block)  | 2.75×           | unchanged             | DEFLATE/LZMA SIMD                          |

The two trailing rows then are **single-member tar.gz** and
**single-Block tar.xz** — the two shapes whose wire formats
have no in-format restart points, where parallelism would
require speculative decoding. Both are defensible "this is
what the format permits" stops; the value of closing them
further is comparable to what
`PLAN_xz_decoder_optimization.md`'s speculative-ceiling items
chase, and they are filed in `OPTIMIZATIONS.md` for promotion
when the marginal value becomes clear.

## Reference material

- README's "Benchmarks" section, `tar.gz` row at 10 Gbps · 256 MiB
  ([`README.md` L142-L218](../README.md#benchmarks-peel-vs-curl---decompressor---tar)).
- `docs/PLAN_xz_parallel_block_decode.md` — the architectural
  twin of this plan, one format over. The worker pool, ordered
  output ring, and `BlockFetcher` trait are the same shapes.
- `docs/PLAN_xz_decoder_optimization.md` Phase 1 — the CRC64
  slicing-by-16 result this plan ports to CRC32.
- `docs/PLAN_deflate_block_decoder.md` — the plan that shipped
  the hand-rolled `deflate_native` decoder this plan
  parallelizes. The member / deflate-block hierarchy and the
  per-member independence (no cross-member back-references) are
  documented in §Scope and Phase 6.
- RFC 1952 (gzip file format)
  ([rfc-editor.org/rfc/rfc1952](https://www.rfc-editor.org/rfc/rfc1952))
  — §2.2 documents the concatenated-members semantics this plan
  relies on.
- `pigz` source
  ([pigz.c](https://github.com/madler/pigz/blob/master/pigz.c))
  — clean-room reference for "what does the canonical parallel
  gzip decoder do at this branch", consulted only for cross-checks
  per the project's clean-room policy. Behaviorally equivalent
  to this plan's design (worker pool + ordered output, with
  `pigz`'s extra speculative-decode lever for single-member
  fixtures filed as our Phase 7 follow-on).
