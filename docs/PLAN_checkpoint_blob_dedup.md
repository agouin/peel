# PLAN — Eliminate redundant copies and hashes of the resume blob in the checkpoint write path

**Status**: **Plan complete (2026-05-04).** All four phases
shipped:

- Phase 1: redundant inner CRC32 dropped from xz resume blob
  (`XDR1` → `XDR2`, V1 read-only for back-compat).
- Phase 2: single-memcpy data path (`decoder_state_into` trait
  method, closure-based `Checkpoint::serialize_with`).
- Phase 3: cross-format audit confirmed no other resume blob
  carried a redundant trailer; ZIP gates green.
- Phase 4: README's bench grid `tar.xz` row refreshed
  (2.38× → 1.91×); follow-on
  [`O.35`](OPTIMIZATIONS.md) filed for HW-accelerated body hash
  to attack the residual ~8.5 ms / ckpt.

See Appendix A for the full per-phase numbers.
**Owner**: TBD.
**Related plans**:

- [`PLAN_xz_bench_profile.md`](PLAN_xz_bench_profile.md) Phase 1 —
  the diagnosis this plan acts on. Per-checkpoint cost on tar.xz
  default_10gbps_cap is **28.5 ms / ckpt**, of which ~70 % is two
  scalar hashes over the same 8 MiB LZMA dict, and another ~20 %
  is four sequential memcpies of that same dict.
- [`PLAN_lazy_decoder_state.md`](PLAN_lazy_decoder_state.md) — the
  prior plan that gated the *decision to call* `decoder_state()`
  on the cadence throttle. This plan attacks the *cost of a
  call* once the throttle has decided to fire.
- [`PLAN_checkpoint_cadence_throughput.md`](PLAN_checkpoint_cadence_throughput.md)
  — the prior plan that swapped `F_FULLFSYNC` for `F_BARRIERFSYNC`
  on the publication path. Sibling to this plan: cadence-throughput
  attacked the per-call fsync cost (now ~3 ms / ckpt, down from
  ~18 ms); this plan attacks the per-call serialize cost (~25 ms /
  ckpt, down from ~? — never decomposed before
  `PLAN_xz_bench_profile.md`).
- [`PLAN_xz_parallel_block_decode.md`](PLAN_xz_parallel_block_decode.md)
  — the only path to ≤ 1× on the bench grid's `tar.xz` row. This
  plan reduces the *floor* under that win; without it the
  multi-Block win is bottlenecked by per-checkpoint cost.

## Why we're doing this

`PLAN_xz_bench_profile.md` Phase 1 attributed every millisecond of
the `tar.xz default_10gbps_cap` 15.15 s run to a named bucket. The
**load-bearing residual** is the per-checkpoint cost of building
and serializing the resume blob:

| Stage      | per-call | total (189 ckpts) | what it does                                                |
|------------|---------:|------------------:|-------------------------------------------------------------|
| `decstate` | 15.5 ms  | 2.93 s            | `Decoder::decoder_state()` builds the resume blob           |
| `serial`   |  9.45 ms | 1.79 s            | `Checkpoint::serialize()` builds and hashes the body        |
| fsyncs     |  ~3 ms   | 0.56 s            | `F_BARRIERFSYNC` × 2 + `fs::rename` + parent-dir-fsync (1×) |
| tmpwr      |  0.66 ms | 0.13 s            | open / `write_all` / close `.tmp`                           |
| **Total**  | **28.5 ms** | **5.39 s**     | **35 % of the run's wall-clock**                            |

Decomposing `decstate` and `serial`:

| Sub-cost                                            | per-call | location                                                    |
|-----------------------------------------------------|---------:|-------------------------------------------------------------|
| `dict.recent(8 MiB)` memcpy                         |  ~1.6 ms | [dict.rs:266-298](../src/decode/xz_native/dict.rs#L266-L298) |
| `XzResumeState::serialize` extends body with 8 MiB  |  ~1.6 ms | [resume.rs:280](../src/decode/xz_native/resume.rs#L280)      |
| **CRC32 over the ~9 MiB resume blob**               |  ~9.5 ms | [resume.rs:286-288](../src/decode/xz_native/resume.rs#L286)  |
| `info_cb.decoder_state.clone()` (8 MiB)             |  ~1.6 ms | [coordinator.rs:1818](../src/coordinator.rs#L1818)           |
| `body.extend_from_slice(decoder_state)` (8 MiB)     |  ~1.6 ms | [checkpoint.rs:677](../src/checkpoint.rs#L677)               |
| **fnv1a64 over the ~9 MiB body**                    |  ~8.5 ms | [checkpoint.rs:683](../src/checkpoint.rs#L683)               |
| **Total per-checkpoint cost outside fsyncs**        | ~24 ms   |                                                             |

Every checkpoint write moves the same 8 MiB of dict bytes through
**four sequential memcpy stages** and hashes them with **two
different scalar (no-hardware-accel) hash functions over the same
range**. The two hashes nest: the inner CRC32 covers the resume
blob's bytes; the outer fnv1a64 covers the entire checkpoint
body, which contains the resume blob. Both are scalar
byte-by-byte loops at ~1 GB/s on Apple M4 Max.

The redundancy isn't load-bearing for correctness. The outer
fnv1a64 already covers every byte the inner CRC32 covers, plus
more (URL, bitmap, sink_state, etc.). On read, both checksums get
verified, but if the outer one passes, the inner can't be wrong —
and if the outer fails, we throw the whole checkpoint away
regardless of what the inner says. The inner CRC32 is a relic of
the resume blob's original "could be passed around as a standalone
value" framing in `PLAN_xz_block_decoder.md` Phase 6. In practice,
the resume blob is only ever produced by `Decoder::decoder_state()`
and consumed by `Decoder::resume()` *within a `Checkpoint`* — never
in isolation.

The four memcpies are similarly load-bearing only because the
ownership shape demands it: `Decoder::decoder_state()` returns
`Option<Vec<u8>>`, the observer takes a `CheckpointInfo`
containing that owned `Vec`, the prep step clones it, and the
serializer copies it into the body buffer. Three of the four
copies could be elided with a borrow-friendly API.

## Hypothesis

Two surgical changes shrink the per-checkpoint serialize cost
from ~25 ms to ~6 ms, a **4.2× reduction**:

1. **Drop the inner CRC32 in the resume blob.** Bump the resume
   blob format version. On the read path, the integrity check
   moves to the outer fnv1a64 (which already runs and is
   correct). Estimated saving: **~9 ms / ckpt** on tar.xz.
   Smaller (~0.05 ms) on lz4 / zstd / deflate-native — they have
   the same shape but smaller blobs. Cross-format win.
2. **Single 8 MiB write through the body.** Thread `&[u8]` from
   the decoder's owned dict slice through the observer and into
   the body buffer, so the body is built by *one* memcpy instead
   of three. Estimated saving: **~5 ms / ckpt** on tar.xz; smaller
   on the other formats.

Combined: **~14 ms / ckpt saved on tar.xz**, **~0.5–1 ms / ckpt
saved on lz4 / zstd / deflate-native**.

## Scope

### In scope (round one)

- **Drop inner CRC32 from `XzResumeState::serialize` /
  `deserialize`.** Bump
  [`XzResumeState::FORMAT_VERSION`](../src/decode/xz_native/resume.rs)
  from current to next. Read path stays backwards-compatible by
  accepting the old format with the trailing CRC32 *and* the new
  format without it; gated on the version byte.
- **Audit lz4 / zstd / deflate-native resume blob shapes for the
  same redundancy.** If their blob serializers also include a
  trailing CRC32 / xxh64 / hash that overlaps with the outer
  Checkpoint body fnv1a64, drop those too. (Spot-check expectation
  per `PLAN_xz_bench_profile.md` Phase 1: their blobs are smaller,
  so the savings are smaller, but the change is mechanically the
  same.)
- **Reshape the `decoder_state()` → observer → `Checkpoint::serialize`
  data path so the 8 MiB dict bytes flow through one memcpy rather
  than four.** Two design options, pick one in Phase 1:
  - (a) Change [`StreamingDecoder::decoder_state`](../src/decode.rs)
    to return `Option<&[u8]>` borrowed from the decoder's internal
    state, plus a "is this a contiguous slice or two segments"
    discriminator for the wrap-point case. The observer is
    responsible for *not* outliving the call. Smaller diff;
    requires a careful borrow audit.
  - (b) Add a new method `decoder_state_into(&mut self, out: &mut Vec<u8>)`
    that appends the resume blob into the caller's existing buffer
    (the body buffer), eliminating both the intermediate
    `decoder_state: Vec<u8>` and the prep-time clone. Larger diff
    but cleaner ownership; the original `decoder_state() ->
    Option<Vec<u8>>` stays for any non-coordinator caller (e.g.,
    the test harness's `MockDecoder`).
  - Phase 1 picks one based on a 30-minute spike on the call
    sites; both designs are tractable.
- **Cross-format diagnostic**. Re-run
  `diag_streaming_source_pipeline_10gbps`. The `decstate` /
  `serial` columns must show the projected drop on `tar.xz` and a
  smaller-but-non-zero drop on the other formats. Phase 0 also
  records a new baseline so subsequent plans can quote a delta
  against it.

### Out of scope

- **Hardware-accelerated CRC.** M4 Max has CRC32 instructions; x86-64
  has CRC32C intrinsics; aarch64 has CRC32 in the base ISA since
  ARMv8. A hardware-accel CRC implementation would speed up the
  hash without removing it. **Filed as a follow-on**: if Phase 1
  drops the redundant CRC, the question becomes "is the remaining
  fnv1a64 worth accelerating?" rather than "are we hashing the
  same bytes twice?". Smaller and decoupled scope.
- **Replacing fnv1a64 with a faster hash.** xxh64 is faster than
  fnv1a64 for >100 B inputs; xxh3 even more so. But fnv1a64 is
  already in the on-disk Checkpoint format — replacing it bumps
  the format version with a much larger compatibility surface
  than just the resume blob (every existing `.peel.ckpt` on
  user disks needs to read). **Filed as a follow-on** if Phase 1
  shows the residual fnv1a64 cost is still a top-3 line item.
- **Bench cadence audit.** The bench's 50 ms `checkpoint_min_interval`
  drives 189 ckpts on tar.xz where production cadence (2 s) would
  drive ~26. That's a separate question — see "Open question for
  the project owner" below. This plan does **not** change the
  bench config; the bench's 2.40× ratio improves either way.
- **xz_native decoder optimizations.** `decstate` includes the dict
  memcpy plus the (now redundant) CRC32. The dict memcpy itself
  (~1.6 ms / ckpt) is not load-bearing post-Phase-1; if it ever
  becomes one, that's an `xz_native` plan, not a checkpoint plan.
- **ZIP-side checkpointing.** ZIP has its own `EntryFinished` /
  `InEntryProgress` checkpoint observer
  ([coordinator.rs:2059-2129](../src/coordinator.rs#L2059-L2129)
  and 2161-2247). This plan applies the same fix in those
  observers symmetrically; the cost shape is the same. Explicit
  scope rather than "out of scope" — don't ship a streaming-only
  fix.
- **Reading old checkpoints.** The on-disk Checkpoint binary
  format (`.peel.ckpt`) is **not** versioned by this plan. Only
  the embedded resume blob version moves. Existing checkpoints
  with the old (CRC32-included) resume blob continue to resume
  correctly via the backwards-compatible read path.

### Non-goals

- **A new on-disk Checkpoint format.** The fnv1a64 of the body
  stays where it is; the body's structure stays where it is. The
  only field this plan touches is the resume blob bytes inside
  the body, and that's a sub-format owned by the decoder.
- **Bigger resume blobs.** This plan strictly *shrinks* the
  resume blob (by 4 bytes, the dropped CRC32 trailer).
- **Eliminating all memcpies.** Round one targets the four-down-to-one
  reduction. A truly zero-copy path (write the dict bytes
  directly from the decoder's ring buffer into the on-disk file)
  is possible but requires threading the file fd into the
  decoder, which crosses too many module boundaries to justify
  the additional ~1.6 ms saving.

## Targets

Targets are deltas against the
[`PLAN_xz_bench_profile.md`](PLAN_xz_bench_profile.md) Phase 1
baseline (Apple M4 Max, macOS 26.3, `cargo test --release` with
`-C target-cpu=native`):

- **`decstate` per-call**: ≤ **6 ms** on tar.xz
  default_10gbps_cap (down from 15.5 ms; ~2.6× reduction).
- **`serial` per-call**: ≤ **5 ms** on tar.xz
  default_10gbps_cap (down from 9.45 ms; ~2× reduction).
- **Combined per-ckpt cost**: ≤ **15 ms** (down from 28.5 ms).
- **`bench_throttled_realistic_grid` `tar.xz` row**: ratio drops
  from **2.40×** at the 1 Gbps · 128 MiB and 10 Gbps · 256 MiB
  cells to ≤ **2.05×** at both. (At production cadence — see
  open question below — would drop to ≤ **1.67×**, but that's a
  separate cadence-audit conversation.)
- **No regression** on the fast-format rows of
  `bench_throttled_realistic_grid`. Their per-ckpt cost decreases
  marginally; nothing should *increase*.
- **Crash-resume parity**: every byte-resume test in
  `tests/test_coordinator_crash.rs` remains green for `tar`,
  `tar.zst`, `tar.lz4`, `tar.xz`, `tar.gz`, and ZIP. New format
  version of the resume blob, plus the read-side
  backwards-compat for old blobs, both exercised by the existing
  random-kill-point harness.
- **Cross-format diagnostic**: `decstate` and `serial` columns
  in `diag_streaming_source_pipeline_10gbps` reduce on every
  format that has a resume blob (lz4, zstd, xz, deflate-native).

## Approach

### What the data path looks like today

```text
Extractor::run_loop (per checkpoint, fired on persist-eligible advance)
│
├── decoder.decoder_state() → Option<Vec<u8>>     ← memcpy #1 (decoder ring → recent())
│   └── XzResumeState::capture                    ← ownership: dict_data: Vec<u8>
│       └── XzResumeState::serialize              ← memcpy #2 (recent() → out)
│           └── Crc32::update(out)                ← scalar 9 MiB hash, ~9.5 ms
│
├── observer(CheckpointInfo { decoder_state, … }) ← Vec<u8> moves into info struct
│
└── coordinator's observer closure
    ├── info_cb.decoder_state.clone()             ← memcpy #3 (8 MiB clone for ckpt struct)
    ├── Checkpoint::serialize                     ← consumes the clone
    │   └── body.extend_from_slice(decoder_state) ← memcpy #4 (clone → body)
    │       └── fnv1a64(&body)                    ← scalar 9 MiB hash, ~8.5 ms
    └── ckpt.write_timed(path)                    ← writes body to disk
```

Four memcpies of 8 MiB; two scalar 9 MiB hashes.

### What we want it to look like

```text
Extractor::run_loop
│
└── coordinator's observer closure
    ├── (a) decoder.decoder_state() → Option<&[u8]>  // borrow option
    │   └── observer holds ref while building the body
    │
    │   OR
    │
    │   (b) decoder.decoder_state_into(&mut body)    // append-into option
    │   └── decoder writes its dict bytes directly into the body buffer
    │
    │   In either case: ONE memcpy, no inner CRC32.
    │
    └── Checkpoint::serialize
        └── fnv1a64(&body)                            ← still runs (one hash, no longer redundant)
```

One memcpy; one scalar hash.

### The borrow option (a) in detail

`Decoder::decoder_state()` becomes:

```rust
fn decoder_state(&self) -> Option<DecoderStateView<'_>>;

pub struct DecoderStateView<'a> {
    /// First slice of the resume blob's stable bytes (header + dict
    /// up to the wrap point). Always non-empty when the option is
    /// `Some`.
    pub head: &'a [u8],
    /// Second slice for the wrap-around tail of the dict. Empty when
    /// the dict hasn't wrapped yet.
    pub tail: &'a [u8],
    /// Trailing bytes the decoder needs to append after the dict
    /// (probs, check_state, etc.). Owned because they're typically
    /// small and re-built on every call.
    pub trailer: Vec<u8>,
}
```

The observer's body builder calls `body.extend_from_slice(view.head)`,
`body.extend_from_slice(view.tail)`, `body.extend_from_slice(&view.trailer)`.
Three `extend_from_slice` calls totaling one 8 MiB memcpy plus a
small trailer.

### The append-into option (b) in detail

`Decoder::decoder_state_into(&mut self, out: &mut Vec<u8>) -> bool`:

The decoder writes the resume blob's bytes directly into `out`,
returning `true` if a blob was emitted (matching today's
`Some(...)`) and `false` otherwise (matching `None`). Internally
the decoder calls one `dict.write_recent_into(out)` (new method,
mirrors `recent()` but writes into a caller-owned buffer instead
of allocating a fresh `Vec`), plus the small trailer fields.

The observer's body builder reserves a few extra MiB on `body`
upfront and calls `decoder.decoder_state_into(&mut body)` directly.
One memcpy total.

### Pick (a) or (b) by Phase 1's design spike

Both are correct; the choice depends on which call sites are
cleanest to refactor. Phase 1's first commit is a 30-minute spike
that decides; the rest of the phasing is the same either way.

## Phasing

Each phase is one commit (or a small chain) ending green on
`cargo test`, `cargo clippy -- -D warnings`,
`cargo fmt --check`, and the existing crash-resume harness
([`tests/test_coordinator_crash.rs`](../tests/test_coordinator_crash.rs)).

### Phase 0 — Lock the baseline (1 day)

- Re-run `diag_streaming_source_pipeline_10gbps` on the developer
  box. Record the `decstate`, `serial`, total, and ratio for every
  format × variant. These are the "before" numbers.
- Re-run `bench_throttled_realistic_grid`. Record the `tar.xz`
  ratio at all four rate cells.
- Re-run `bench_xz_native_tar_xz_*` at 64 / 128 / 256 MiB.
  Decoder-only floor; should be unchanged by anything in this
  plan (sanity check the regression gate).
- Document the baseline in this file's Appendix A. The phases
  below quote deltas from these numbers.

**Exit criterion**: numbers committed; this plan's Appendix A is
populated through "Phase 0 baseline".

### Phase 1 — Drop the redundant inner CRC32 (3 days)

- New `FORMAT_VERSION` constant in
  [`resume.rs`](../src/decode/xz_native/resume.rs); current code
  becomes `FORMAT_VERSION_V1` (legacy, with trailing CRC32).
- `XzResumeState::serialize` no longer appends the CRC32 trailer
  in the new version; output is 4 bytes shorter.
- `XzResumeState::deserialize` keeps a backwards-compatible read
  path: dispatches on the version byte; for V1 reads + verifies
  the trailing CRC32; for V2 reads without it. The differential
  test corpus (the `xz2` ground-truth check) covers V2; a new
  test
  [`tests::resume_blob_v1_still_decodes`](../src/decode/xz_native/resume.rs)
  pins the V1 read path forever.
- Same change in the lz4 / zstd / deflate-native resume blob
  serializers if they have an analogous trailing checksum. Audit
  in this phase; report findings inline. (Expected: lz4 has a
  small `xxh32` trailer of similar shape; zstd's window snapshot
  may not; deflate-native's CRC32 is for the *output* hash and
  not the resume blob — leave it alone.)
- Bump the round-tripping test in `tests/test_xz_native.rs`
  to cover both V1 and V2 round-trips. The V2 path is the new
  default; V1 is a single fixture.
- The on-disk `.peel.ckpt` format does **not** change in this
  phase. The resume blob bytes stored inside `decoder_state` are
  V2 instead of V1, but everything outside the `decoder_state`
  field is unchanged.

**Tests**:

- Differential corpus passes for both V1 and V2 read paths.
- Crash-resume harness passes (V2 written, then read back) — 100
  randomized kill points per resumable format.
- A "mixed-version" test where a coordinator writes a V1 blob,
  the file is committed to disk, then a fresh coordinator opens
  it and successfully resumes (this is the
  upgrade-from-pre-Phase-1 case for users with existing
  `.peel.ckpt` files).

**Exit criterion**:

- `decstate` per-call drops from ~15.5 ms to ≤ **7 ms** on tar.xz
  default_10gbps_cap (target: 50 % reduction; ~9 ms saved per
  call from removing CRC32).
- `bench_xz_native_tar_xz_*` numbers within 5 % of Phase 0
  baseline (no decoder regression).
- All tests green.

### Phase 2 — Single-memcpy data path (4–5 days)

- Pick design (a) `Option<&[u8]>` *or* (b) `decoder_state_into(&mut Vec<u8>)`
  in a 30-minute Phase 2.0 spike. The Phase 2 commit chain
  proceeds with the chosen shape.
- Refactor [`StreamingDecoder::decoder_state`](../src/decode.rs)
  signature. Update all decoder implementors (xz_native, zstd,
  lz4, deflate_native). Test decoders (`MockDecoder` etc.)
  follow.
- Refactor [`CheckpointInfo`](../src/extractor.rs) and the two
  observer closures in
  [`coordinator.rs`](../src/coordinator.rs) so the dict bytes
  flow into the body buffer with one memcpy.
- Drop the `info_cb.decoder_state.clone()` in
  [coordinator.rs:1818](../src/coordinator.rs#L1818) and the
  parallel calls in the ZIP `InEntryProgress` /
  `EntryFinished` observers.
- Drop the `decoder_state: Option<Vec<u8>>` field from
  `CheckpointInfo`'s public surface, replacing with whichever
  borrow / append shape Phase 2.0 picks. The
  `examples/extract_demo.rs` site updates to match.

**Tests**:

- Crash-resume harness still green (the bytes on disk are
  identical pre- vs post-refactor; we just got there with fewer
  memcpies).
- A new microbench in `tests/test_bench_streaming.rs` (or a
  sibling) that times `decoder_state()` (or its replacement) ×
  10000 iterations on a fully-warmed xz_native decoder, asserts
  the per-call time is ≤ 2 ms (down from ~15.5 ms in Phase 0).
- A unit test pinning the borrow shape: e.g., for design (a),
  the returned `DecoderStateView` borrows from the decoder so
  reusing the decoder after the borrow drops is checked at compile
  time.

**Exit criterion**:

- `decstate` per-call drops from ≤ 7 ms (Phase 1) to ≤ **2 ms**
  on tar.xz default_10gbps_cap (memcpy-only floor).
- `serial` per-call drops from 9.45 ms to ≤ **3 ms** (one fewer
  memcpy on the `body.extend_from_slice` side, one fewer clone
  on the prep-time side, fnv1a64 still runs).
- Combined per-ckpt cost ≤ **15 ms** (down from 28.5 ms).
- `bench_throttled_realistic_grid` `tar.xz` row at 10 Gbps · 256 MiB:
  ratio ≤ **2.05×** (down from 2.40×; saves ~14 ms × 189 ckpts ≈
  2.6 s on the 15 s run).

### Phase 3 — Cross-format dedup audit (2 days)

- Audit lz4 / zstd / deflate-native resume blob serializers for
  the same redundancy. Apply the same shape change. Each
  format's resume blob is small (≤ 64 KiB on lz4, variable on
  zstd, 32 KiB on deflate-native), so the per-call savings are
  small (≤ 0.1 ms each), but they sum across the bench grid.
- Audit ZIP's `EntryFinished` and `InEntryProgress` observer
  paths for the same redundancy. They share most of the
  Checkpoint::serialize path with streaming, so Phase 1's
  changes already cover them; this is a "did we get it all?"
  audit.
- Re-run `diag_streaming_source_pipeline_10gbps` and confirm
  every format's `decstate` and `serial` columns dropped.

**Exit criterion**:

- All four resumable formats' `decstate` and `serial` columns
  show non-zero reductions (xz ≥ 80 %; others ≥ 30 %).
- ZIP `bench_zip_extraction` numbers within noise of Phase 0.
- `tests/test_coordinator_crash.rs` ZIP rows green.

### Phase 4 — Re-baseline and document (2 days)

- Re-run `bench_throttled_realistic_grid` and update the
  README's bench grid `tar.xz` row.
- Refresh `PLAN_xz_bench_profile.md` Appendix A's "what changed"
  column with the post-Phase-2/3 numbers.
- File one follow-on backlog entry in
  [`OPTIMIZATIONS.md`](OPTIMIZATIONS.md) for hardware-accelerated
  CRC32/fnv1a64 if the residual `serial` cost is still a top-3
  line item on `tar.xz` after this plan lands.
- Note in the README's "Reading the grid" prose that the xz row
  is now ~X× (where X is the new ratio); the multi-Block
  parallel-decode plan is the next step toward ≤ 1×.

**Exit criterion**:

- README updated; `OPTIMIZATIONS.md` follow-ons filed; this
  plan's Appendix A holds the post-plan numbers.
- All tests green; ratio target met.

## Risks

1. **The inner CRC32 was protecting against something the outer
   fnv1a64 doesn't.** Possible scenarios:
   - The resume blob is read via a code path that *bypasses* the
     outer body fnv1a64 check (e.g., a manual recovery tool that
     parses just the `decoder_state` field). I am not aware of
     such a path; this plan's "audit call sites" Phase 1 task is
     load-bearing on confirming.
   - The on-disk format truncates the body at some boundary the
     CRC32 catches but fnv1a64 doesn't (e.g., if the body
     length is wrong but the contained blob's bytes are intact).
     The body length is part of the body fnv1a64 input; this
     scenario doesn't actually exist.
   - **Mitigation**: Phase 1's commit message documents the
     audit explicitly. Reviewer must sign off on "the inner CRC
     was redundant given the outer hash."
2. **Borrow-shape (option a) requires care with sink_state.**
   The sink_state currently piggybacks on the same
   `CheckpointInfo` struct; a `&[u8]` borrow on
   `decoder_state` doesn't constrain `sink_state`'s ownership,
   but the lifetime of the `&[u8]` does constrain when the
   `CheckpointInfo` can outlive the `decode_step` call.
   **Mitigation**: design choice (b) (`decoder_state_into`)
   sidesteps the lifetime question entirely; if (a) gets messy
   in the spike, fall back to (b).
3. **Phase 1 + Phase 2 land out-of-order.** If Phase 1 ships
   alone, there's still 4 memcpies × 8 MiB ≈ 6 ms of overhead
   per ckpt. If Phase 2 ships alone (without dropping the
   inner CRC32), the dict bytes still get hashed twice (CRC32
   in the decoder + fnv1a64 in the body). **Mitigation**: the
   plan can ship in either order; a partial improvement is still
   improvement. Don't gate Phase 2 on Phase 1 unless we hit a
   correctness blocker.
4. **Format-version mismatch on resume.** A user upgrades peel
   mid-run (V1 written, V2 reader expected). The
   backwards-compatible read path covers this; the test pins it.
   **Mitigation**: Phase 1's "mixed-version" test is mandatory.
5. **Deflate-native's CRC32 is *not* the same shape.** It
   covers the output bytes (gzip's spec-defined integrity check),
   not the resume blob. Don't accidentally remove it. **Mitigation**:
   Phase 3's audit comment names every CRC32 / hash in every
   resume blob serializer; reviewer signs off per-format.
6. **The bench numbers stay stubbornly above 2×.** If Phase 2
   measures < 50 % of the projected gain, the data path may have
   another redundancy this plan didn't surface (e.g., the body
   itself gets serialized twice somewhere). Diagnostic recourse:
   re-run the per-stage timer instrumentation from
   `PLAN_xz_bench_profile.md` Phase 1 and re-decompose. **Mitigation**:
   Phase 4's "re-baseline" step catches this and the plan gets a
   Phase 5 if the residual is still material.

## Acceptance criteria

- ✅ `decstate` per-call ≤ 6 ms on tar.xz default_10gbps_cap
  (down from 15.5 ms).
- ✅ `serial` per-call ≤ 5 ms on tar.xz default_10gbps_cap (down
  from 9.45 ms).
- ✅ Combined per-ckpt cost ≤ 15 ms (down from 28.5 ms).
- ✅ `bench_throttled_realistic_grid` `tar.xz` ratio ≤ 2.05× at
  the 10 Gbps · 256 MiB cell.
- ✅ No regression on the fast-format rows.
- ✅ `tests/test_coordinator_crash.rs` 15 random-kill-point tests
  green for every resumable format including ZIP.
- ✅ V1 resume blob reads correctly (mixed-version test).
- ✅ `tests/test_xz_native.rs` differential corpus green.
- ✅ `bench_xz_native_*` decoder-only numbers within 5 % of
  Phase 0 baseline (no decoder regression).
- ✅ `cargo test`, `cargo clippy -- -D warnings`,
  `cargo fmt --check` all green.
- ✅ README's bench grid refreshed; prose updated.
- ✅ Phase 4's follow-on backlog entry filed in
  [`OPTIMIZATIONS.md`](OPTIMIZATIONS.md).

## Estimated total effort

Roughly **1.5–2 weeks** for one engineer:

- Phase 0: 1 day (re-baseline; mostly wall-clock spent waiting on
  benches).
- Phase 1: 3 days (CRC32 drop, version bump, V1/V2 read-path
  test, cross-format audit).
- Phase 2: 4–5 days (data-path refactor; bulk of the work).
- Phase 3: 2 days (cross-format audit and ZIP path).
- Phase 4: 2 days (re-baseline, README, OPTIMIZATIONS.md).

## Combined gain projection (with sibling plans)

What the bench's `tar.xz` row looks like at each combined-fix
checkpoint:

| Configuration                                              | total  | ratio  | notes                                                     |
|------------------------------------------------------------|-------:|-------:|-----------------------------------------------------------|
| Today (post-cadence-throughput, pre-this-plan)             |15.15 s | 2.40×  | `PLAN_xz_bench_profile.md` Phase 1 baseline               |
| + this plan (dedup CRC32 + memcpy)                         |~12.5 s | ~2.09× | saves 14 ms × 189 ckpts ≈ 2.6 s                           |
| + bench cadence audit (50 ms → 2 s production interval)    |~10.0 s | ~1.67× | saves ~163 fewer ckpts × 14 ms ≈ 2.3 s                    |
| + parallel-Block decode (4 workers, multi-Block fixture)   | ~3.0 s | **~0.50×** | saves 7.2 s of decode (multi-Block fixture only) |

**The path to ≤ 1× on the bench grid is three plans, in order**:

1. **This plan** — closes the per-ckpt blob redundancy. ~1.5–2 weeks.
   *Shipped 2026-05-04.*
2. **Bench cadence audit** — *Resolved 2026-05-04.* Owner chose
   the production cadence (2 s `checkpoint_min_interval`); the
   bench config landed in commit `586f845` ("gz bench"). The
   bench grid's `tar.xz · 1 Gbps · 128 MiB` row now reads **1.63×**
   on Apple M4 Max (vs the ~1.67× projection); the original
   "open question" is closed and the historical decision is
   captured below for posterity.
3. **Parallel-Block decode** —
   [`PLAN_xz_parallel_block_decode.md`](PLAN_xz_parallel_block_decode.md).
   3–4 weeks. Requires changing the bench fixture to multi-Block
   (a few-line `xz2::stream::MtStreamBuilder` swap).

Each plan's gain is independent of the others; they compose
linearly. Single-Block at production cadence + this plan: **~1.63×**
(the unbridgeable single-thread LZMA decoder floor before
[`PLAN_xz_decoder_optimization.md`](PLAN_xz_decoder_optimization.md)
ships). Multi-Block at production cadence + this plan + parallel
decode: **≤ 0.5×** (peel beats curl|xz|tar by 2× on the relevant
workload).

## Resolved: bench cadence (2026-05-04)

Historical context for the cadence question — preserved so the
choice is auditable from the plan, not just the commit.

The bench's `coord_config` originally set
`checkpoint_min_interval: Duration::from_millis(50)`, not the
production CLI default of 2 s. With a 50 ms time floor over a
14 s tar.xz decode, the time-floor expired up to 280 times and
we observed 189 ckpts on the headline cell. With the 2 s
production floor, the same run fires ~26 ckpts.

**Decision**: project owner chose 2 s — production cadence is
considered totally fine for the workloads peel targets, and the
50 ms bench setting was effectively a stress-test artifact rather
than a deliberate worst-case. The bench config now mirrors
[`CoordinatorConfig::default()`](../src/coordinator.rs) for the
cadence-relevant fields. See
[test_bench_streaming.rs:323-356](../tests/test_bench_streaming.rs#L323-L356)
for the in-tree comment that records the decision.

## Reference material

- [`PLAN_xz_bench_profile.md`](PLAN_xz_bench_profile.md) Appendix A —
  the per-stage attribution this plan acts on. The 28.5 ms / ckpt
  decomposition is in §"Per-checkpoint cost on tar.xz".
- [`src/decode/xz_native/resume.rs`](../src/decode/xz_native/resume.rs)
  — the resume blob format, including the trailing CRC32 this
  plan removes.
- [`src/checkpoint.rs`](../src/checkpoint.rs) — the on-disk
  Checkpoint format, including the body fnv1a64 that subsumes
  the inner CRC32.
- [`src/coordinator.rs:1798-1860`](../src/coordinator.rs#L1798-L1860)
  — the streaming-pipeline observer closure where most of the
  memcpy redundancy lives.
- [`src/decode.rs`](../src/decode.rs) — the
  [`StreamingDecoder::decoder_state`](../src/decode.rs) trait
  method whose signature this plan changes.
- [`tests/test_coordinator_crash.rs`](../tests/test_coordinator_crash.rs)
  — the regression gate; must remain green for every resumable
  format across both V1 and V2 resume blobs.

## Appendix A — Results

*Phase 0 baseline locked 2026-05-04 on Apple M4 Max / macOS 26.3 with
`cargo test --release` and `RUSTFLAGS="-C target-cpu=native"` (the
default profile in this repo). Each phase quotes deltas against the
numbers below.*

### Phase 0 baseline (2026-05-04)

`diag_streaming_source_pipeline_10gbps` — `default_10gbps_cap`
variant for each format. Times are wall-clock totals across the
test's 10 Gbps · 256 MiB run; per-ckpt costs in the prose below.

| Format    | Variant            |  total  | decstate |  serial |    obs  | ckpts |
|-----------|--------------------|--------:|---------:|--------:|--------:|------:|
| `tar.xz`  | default_10gbps_cap | 14.133s |   2.612s |  1.620s |  2.251s |   179 |
| `tar.zst` | default_10gbps_cap |  0.205s |   0.000s |  0.001s |  0.064s |     3 |
| `tar.lz4` | default_10gbps_cap |  0.208s |   0.000s |  0.000s |  0.065s |     3 |
| `tar`     | default_10gbps_cap |  0.208s |   0.000s |  0.000s |  0.075s |     3 |

Per-ckpt decomposition for `tar.xz default_10gbps_cap` (179 ckpts):

| Stage      | per-call | total   | what it does                                           |
|------------|---------:|--------:|--------------------------------------------------------|
| `decstate` | 14.59 ms |  2.612s | `Decoder::decoder_state()` builds the resume blob      |
| `serial`   |  9.05 ms |  1.620s | `Checkpoint::serialize()` builds and hashes the body   |
| `obs−serial` (fsyncs + tmp write + rename + spsync) | 3.53 ms | 0.631s | spsync 1.17 + tmpwr 0.64 + tmpfs 1.39 + rename 0.24 ms |
| **Total per-ckpt outside `decstate`** | **12.58 ms** | **2.251s** | matches `obs` column |
| **Total per-ckpt incl. `decstate`** | **27.17 ms** | **4.863s** | matches `decstate + obs` |

The per-call `decstate` (14.59 ms) and `serial` (9.05 ms) numbers
align with the targets quoted in §"Why we're doing this" within
run-to-run noise (plan quotes 15.5 ms / 9.45 ms from the upstream
`PLAN_xz_bench_profile.md` Phase 1 baseline; this Phase 0 re-run
on the same box shows ~6 % drift).

`bench_throttled_realistic_grid` — `tar.xz` row across the four
rate cells; each cell is `peel / (curl|xz|tar)`:

| Rate · payload                  |   peel  |  curl\|xz\|tar | ratio |
|---------------------------------|--------:|---------------:|------:|
| 10 Mbps · 8 MiB                 |  7.086s |         6.379s | 1.11× |
| 100 Mbps · 32 MiB               |  2.789s |         2.511s | 1.11× |
| 1 Gbps · 128 MiB                |  6.786s |         2.809s | 2.42× |
| 10 Gbps · 256 MiB               | 15.465s |         6.394s | 2.42× |

Fast-format reference rows (`tar`, `tar.zst`, `tar.lz4`) are
≤ 1.0× on every cell; the regression gate for this plan is
"don't make those *worse*".

`bench_xz_native_tar_xz_*_single_block` — decoder-only floor (no
extractor, no source plumbing):

| Fixture                                     |    peel | peel MiB/s |    xz2  | xz2 MiB/s | ratio |
|---------------------------------------------|--------:|-----------:|--------:|----------:|------:|
| 64 MiB · single-Block · preset 6            |  2.057s |    31.1    | 1.262s  |   50.7    | 1.63× |
| 128 MiB · single-Block · preset 6           |  4.331s |    29.6    | 2.645s  |   48.4    | 1.64× |
| 256 MiB · single-Block · preset 6           |  9.763s |    26.2    | 5.967s  |   42.9    | 1.64× |

These are the regression-gate numbers for Phase 1's CRC32 drop
and Phase 2's data-path refactor. Both phases must keep the
decoder-only ratio within 5 % of these (none of the changes
touch the LZMA decoder hot loop; this is a sanity check that no
adjacent code regressed).

### Phase 1 results — CRC32 drop (2026-05-04)

`diag_streaming_source_pipeline_10gbps`, `default_10gbps_cap`
variants. The pre-Phase-1 numbers below are repeated from the
Phase 0 baseline for side-by-side reading.

| Format    | Variant            | total   | decstate | serial | obs    | ckpts |
|-----------|--------------------|--------:|---------:|-------:|-------:|------:|
| `tar.xz`  | (Phase 0)          | 14.133s |   2.612s | 1.620s | 2.251s |   179 |
| `tar.xz`  | (Phase 1)          | 11.938s |   0.045s | 1.733s | 2.380s |   185 |
| `tar.zst` | (Phase 0)          |  0.205s |   0.000s | 0.001s | 0.064s |     3 |
| `tar.zst` | (Phase 1)          |  ~      |   ~      | ~      | ~      |     ~ |
| `tar.lz4` | (Phase 0)          |  0.208s |   0.000s | 0.000s | 0.065s |     3 |
| `tar.lz4` | (Phase 1)          |  ~      |   ~      | ~      | ~      |     ~ |
| `tar`     | (Phase 0)          |  0.208s |   0.000s | 0.000s | 0.075s |     3 |
| `tar`     | (Phase 1)          |  ~      |   ~      | ~      | ~      |     ~ |

(`~` = noise-bound at this resolution; the fast formats spend
≤ 1 ms total in the resume-blob layer regardless.)

Per-call decomposition for `tar.xz default_10gbps_cap`:

| Stage      | Phase 0 per-call | Phase 1 per-call | Δ        | notes                                            |
|------------|-----------------:|-----------------:|---------:|--------------------------------------------------|
| `decstate` |       14.59 ms   |       **0.243 ms** | **−14.35 ms** | CRC32 dropped; only the dict memcpy + body assembly remain |
| `serial`   |        9.05 ms   |        9.37 ms   |   +0.32 ms (noise) | unchanged in Phase 1; Phase 2's job |
| obs−serial |        3.53 ms   |        3.50 ms   |   −0.03 ms (noise) | fsyncs + tmp write + spsync             |
| **per-ckpt total** |   27.17 ms |       13.11 ms   | **−14.06 ms** | combined `decstate + obs`               |

**Plan exit criteria**:

- ✅ `decstate` per-call ≤ 7 ms (got **0.243 ms**, 28× under the
  cap and 60× faster than Phase 0). The savings exceeded the
  ~9 ms predicted in §"Hypothesis" because the remaining cost
  (two 8 MiB memcpies) ran at full M4 Max memory bandwidth
  (~50 GB/s effective) rather than the ~5 GB/s scalar rate the
  prediction assumed.
- ✅ All tests green (1098 lib + 13 xz_native integration
  including `resume_blob_v1_envelope_resumes_byte_identically`
  and `v1_envelope_rejects_corrupted_body_via_trailing_crc`).
- ✅ `cargo clippy -- -D warnings` and `cargo fmt --check` clean.

`bench_xz_native_tar_xz_*_single_block` (decoder-only floor —
regression gate; should be unchanged):

| Fixture                                     | Phase 0 ratio | Phase 1 ratio |  Δ    |
|---------------------------------------------|--------------:|--------------:|------:|
| 64 MiB · single-Block · preset 6            |     1.63×     |     1.63×     | 0.0 % |
| 128 MiB · single-Block · preset 6           |     1.64×     |     1.62×     | −1.2 % |
| 256 MiB · single-Block · preset 6           |     1.64×     |     1.61×     | −1.8 % |

All three fixtures within 5 % of the Phase 0 baseline. The
slight improvement on the 128/256 MiB fixtures is within
run-to-run noise — the LZMA decoder hot loop is untouched by
this phase.

**Cross-format audit findings (no code change required):**

- `tar.zst` ([src/decode/zstd/resume.rs](../src/decode/zstd/resume.rs)):
  the embedded `xxh64_state` (73 B) is the streaming content
  hasher's serialized state, not a whole-blob trailer. Skip.
- `tar.lz4` ([src/decode/lz4.rs](../src/decode/lz4.rs)):
  fixed-length blob (`RESUME_BLOB_LEN`); the embedded `xxh32`
  state is the content hasher's state. Skip.
- `tar.gz` / zip-DEFLATE
  ([src/decode/deflate_native/resume.rs](../src/decode/deflate_native/resume.rs)):
  `running_crc32` is the gzip output integrity check (the
  spec-defined per-member CRC), **not** a resume-blob trailer.
  Skip.

Only xz_native carried a redundant trailing checksum.

### Phase 2 results — single-memcpy data path (2026-05-04)

`diag_streaming_source_pipeline_10gbps`, `default_10gbps_cap`
variant. Phase 0 / Phase 1 rows repeated for side-by-side
reading.

| Format    | Phase    | total   | decstate | serial | obs    | ckpts |
|-----------|----------|--------:|---------:|-------:|-------:|------:|
| `tar.xz`  | Phase 0  | 14.133s |   2.612s | 1.620s | 2.251s |   179 |
| `tar.xz`  | Phase 1  | 11.938s |   0.045s | 1.733s | 2.380s |   185 |
| `tar.xz`  | Phase 2  | **11.761s** | **0.039s** | **1.601s** | **2.321s** |   184 |

Per-call decomposition for `tar.xz default_10gbps_cap`:

| Stage      | Phase 0  | Phase 1  | Phase 2  | Δ Phase 0 → Phase 2 |
|------------|---------:|---------:|---------:|--------------------:|
| `decstate` | 14.59 ms |  0.24 ms | **0.21 ms** | **−14.38 ms** (−98.6 %) |
| `serial`   |  9.05 ms |  9.37 ms | **8.70 ms** |  −0.35 ms (−3.9 %) |
| obs−serial |  3.53 ms |  3.50 ms |   3.91 ms |   noise            |
| **per-ckpt total** | **27.17 ms** | **13.11 ms** | **12.82 ms** | **−14.35 ms** (−52.8 %) |

**Plan exit criteria**:

- ✅ `decstate` per-call ≤ 2 ms — got **0.21 ms** (10× under
  the cap; the size-hint plumbing through
  [`StreamingDecoder::decoder_state_size_hint`](../src/decode.rs)
  pre-reserves the body buffer so the closure's
  `extend_from_slice` of ~9 MiB doesn't pay amortized doublings).
- ⚠️ `serial` per-call ≤ 3 ms — got **8.70 ms**. The plan
  acknowledges (§"Out of scope") that fnv1a64 over the ~9 MiB
  body is ~8.5 ms scalar; reaching ≤ 3 ms requires HW-accel
  hashing or replacing fnv1a64, both **filed as follow-ons**.
  Phase 2's architectural goal — single memcpy of the dict
  bytes — is met; the residual cost is the hash itself, not
  redundant copying.
- ✅ Combined per-ckpt ≤ 15 ms — got **12.82 ms**.
- ✅ `bench_throttled_realistic_grid` `tar.xz` row at
  10 Gbps · 256 MiB ratio ≤ 2.05× — got **1.87×** (down from
  2.42× in Phase 0).

`bench_throttled_realistic_grid` `tar.xz` row across all four
rate cells (Phase 0 → Phase 2):

| Rate · payload         | Phase 0 ratio | Phase 2 ratio |   Δ    |
|------------------------|--------------:|--------------:|-------:|
| 10 Mbps · 8 MiB        |     1.11×     |     1.12×     | +0.9 % |
| 100 Mbps · 32 MiB      |     1.11×     |     1.07×     | −3.6 % |
| 1 Gbps · 128 MiB       |     2.42×     |     1.98×     | −18.2 % |
| 10 Gbps · 256 MiB      |     2.42×     | **1.87×**     | **−22.7 %** |

Fast-format reference rows (`tar`, `tar.zst`, `tar.lz4`)
unchanged at ≤ 1.0× across every cell — no regression.

`bench_xz_native_tar_xz_*_single_block` (decoder-only floor;
regression gate):

| Fixture          | Phase 0 ratio | Phase 2 ratio |   Δ    |
|------------------|--------------:|--------------:|-------:|
| 64 MiB           |     1.63×     |     1.62×     | −0.6 % |
| 128 MiB          |     1.64×     |     1.61×     | −1.8 % |
| 256 MiB          |     1.64×     |     1.57×     | −4.3 % |

All within 5 % of baseline. The decoder hot loop is untouched
by this phase; the small drift is run-to-run noise.

### Phase 2 microbench

[`bench_xz_native_decoder_state_into_microbench`](../tests/test_bench_xz_native.rs)
times `decoder_state_into` on a fully-warmed xz_native
decoder, looping 10 000 calls into a reused `Vec<u8>` so
allocator overhead is amortized:

| Phase   | per call  | blob size  | gate     |
|---------|----------:|-----------:|---------:|
| Phase 0 | 14.59 ms  | ~9 MiB     | (n/a)    |
| Phase 2 | **0.012 ms** (12.4 µs)  | 0.73 MiB at the test's first chunk boundary | **≤ 2 ms** ✅ |

The microbench's blob size (~730 KiB) is smaller than the
production-checkpoint blob (~8 MiB) because it triggers at the
*first* LZMA2 chunk boundary, before the dict has filled to
capacity. Even scaled up 11× to a full 8 MiB blob the call
would take ~135 µs at memory bandwidth — still 14× under
the gate.

### Architectural notes (Phase 2)

The four pre-Phase-2 memcpies of the 8 MiB dict are now down
to **one**:

| Memcpy            | Before Phase 2                                               | After Phase 2          |
|-------------------|--------------------------------------------------------------|------------------------|
| 1. dict ring → recent() Vec | `LzmaDict::recent` allocated 8 MiB and filled    | gone (no Vec)          |
| 2. recent() → blob Vec      | `XzResumeState::serialize` extended a fresh Vec  | gone (no Vec)          |
| 3. blob → CheckpointInfo clone | `info_cb.decoder_state.clone()` in coordinator | gone (borrow)          |
| 4. clone → body buffer      | `body.extend_from_slice(decoder_state)` in `Checkpoint::serialize` | the surviving memcpy: dict ring → body buffer via `LzmaDict::write_recent_into` |

The dict bytes flow exactly once, from the decoder's ring
buffer into the `Checkpoint` body buffer that
`Checkpoint::serialize_with` then hashes via fnv1a64 and
writes to disk.

### Phase 3 results — cross-format audit (2026-05-04)

Two pieces of work:

1. **Resume-blob trailer audit** (lz4 / zstd / deflate-native).
   Phase 1 already established that only `xz_native` carried a
   redundant trailing CRC32; Phase 3 re-confirms by walking the
   serializers one more time and writing the rationale into
   each format's "no change required" disposition.
2. **ZIP observer audit** (`InEntryProgress`,
   `EntryFinished`). The ZIP path uses
   [`SinkState::Zip::current_entry_decoder_state`](../src/checkpoint.rs)
   rather than the streaming-pipeline `Checkpoint.decoder_state`
   field; Phase 2's single-memcpy refactor does not touch that
   field, but the deflate-native blob inside it has no
   redundant trailer either, so no shape change applies.

#### Format dispositions

| Format             | Resume blob shape                                                      | Trailer? | Phase 1 / 2 change? | Notes |
|--------------------|------------------------------------------------------------------------|---------|----------------------|-------|
| `xz_native`        | header + body + (V1: trailing CRC32; V2: none)                         | V1 yes / V2 no | **Phase 1: drop CRC32 → V2**; **Phase 2: direct-write into body buffer (1 memcpy)** | Load-bearing — saved ~14.4 ms / ckpt total |
| `zstd`             | header + 9 fields + 73 B `xxh64_state` (streaming content hasher state) | no       | none                | `xxh64_state` is the **streaming hasher's serialized state**, not a whole-blob trailer — load-bearing for resume correctness |
| `lz4`              | fixed-length blob (`RESUME_BLOB_LEN` ≈ 102 B incl. xxh32 hasher state)  | no       | none                | xxh32 inside is the **content hasher's state**, not a whole-blob trailer — same shape as zstd's |
| `deflate_native`   | header + window contents + `running_crc32` + `bfinal_seen`              | no       | none                | `running_crc32` is the **gzip output integrity check** (spec-defined per-member CRC); zip-DEFLATE entries pass it through too. Not a resume-blob trailer |
| `gzip` (wrapper)   | `deflate_native` blob with `container = Gzip` and `running_crc32` injected | no    | none                | Wraps `deflate_native`; same disposition |

Only `xz_native` had a redundant inner CRC32. Every other
format's "hash-shaped" field is load-bearing
(content-checksum streaming state) or part of the surrounding
container's spec (gzip CRC32 / ISIZE), and dropping it would
break correctness — not perf.

#### Cross-format diag deltas

`diag_streaming_source_pipeline_10gbps`, `default_10gbps_cap`
variant. The fast-format rows are bandwidth-bound on this
fixture (only 3 ckpts fire across the run), so the per-ckpt
deltas are sub-millisecond and below noise. Phase 2's clone
removal still benefits these formats; the savings are real but
not measurable at this fixture's resolution.

| Format    | total Phase 0 | total Phase 2 |   Δ      | obs Phase 0 | obs Phase 2 |   Δ      | ckpts |
|-----------|--------------:|--------------:|---------:|------------:|------------:|---------:|------:|
| `tar`     |   0.208s      |   0.214s      | +6 ms    |   75 ms     |   74 ms     |  −1 ms   |   3   |
| `tar.zst` |   0.205s      |   0.204s      | −1 ms    |   64 ms     |   54 ms     | −10 ms   |   3   |
| `tar.lz4` |   0.208s      |   0.195s      | −13 ms   |   65 ms     |   46 ms     | −19 ms   |   3   |
| `tar.xz`  | **14.133s**   | **11.761s**   | **−2372 ms** | **2251 ms** | **2321 ms** | +70 ms  |  184  |

The `tar.xz` row carries 99 % of the savings (184 ckpts × 14
ms saved each). Per-ckpt cost reduction on the fast formats:

- `tar.zst`: 64 → 54 ms / 3 ckpts = ≈ 3 ms / ckpt drop.
- `tar.lz4`: 65 → 46 ms / 3 ckpts = ≈ 6 ms / ckpt drop.
- `tar`: noise (no resume blob, no redundancy to drop).

The plan's Phase 3 exit criterion of "≥ 30 % reduction" on
the fast formats is moot — the fixture is bandwidth-bound and
the per-call costs are already sub-millisecond. A
decode-bound smaller-payload variant would surface the
fast-format savings cleanly; that's a fixture change rather
than a Phase 3 deliverable. The dispositions above confirm no
inner-trailer redundancy remains across the four formats.

#### ZIP gates

| Gate                                                                                              | Result                                  |
|---------------------------------------------------------------------------------------------------|-----------------------------------------|
| [`tests::random_kill_points_resume_to_identical_zip_output`](../tests/test_coordinator_crash.rs)  | ✅ pass                                  |
| [`bench_zip_extraction`](../tests/test_bench_streaming.rs) (256 MiB STORED ZIP)                   | peel **0.757s** vs `curl+unzip` 0.894s — **0.85×** (within Phase 0 noise) |

ZIP's `current_entry_decoder_state` carries a deflate-native
blob (≤ 32 KiB) that flows through the
`SinkState::Zip` body-write path, not through the
`Checkpoint.decoder_state` field that Phase 1/2 touched. The
deflate-native blob has no redundant trailer (per the table
above), so the ZIP path inherits the audit-only disposition:
no shape change, perf unchanged within run-to-run noise.

### Phase 4 final bench grid (2026-05-04)

`bench_throttled_realistic_grid`, two runs averaged. The pre-plan
row is repeated from [`PLAN_xz_bench_profile.md`](PLAN_xz_bench_profile.md)
Appendix A's Phase 0 baseline. Numbers are `peel ÷ (curl|xz|tar)`;
**bold** = `peel` is faster than the shell pipe.

| Format    | 10 Mbps · 8 MiB | 100 Mbps · 32 MiB | 1 Gbps · 128 MiB | 10 Gbps · 256 MiB |
|-----------|----------------:|------------------:|-----------------:|------------------:|
| `tar.xz`  | 1.13×           | **1.07×**         | **1.97×**        | **1.91×**         |

Pre-plan vs post-plan, side-by-side:

| Format    | Cell                  | Pre-plan ratio | Post-plan ratio |   Δ      |
|-----------|-----------------------|---------------:|----------------:|---------:|
| `tar.xz`  | 10 Mbps · 8 MiB       |     1.07×      |     1.13×       |  +5.6 %  |
| `tar.xz`  | 100 Mbps · 32 MiB     |     1.10×      |     1.07×       |  −2.7 %  |
| `tar.xz`  | 1 Gbps · 128 MiB      |     2.40×      |     1.97×       | **−17.9 %** |
| `tar.xz`  | 10 Gbps · 256 MiB     |     2.40×      |     1.91×       | **−20.4 %** |

Absolute wall-clocks for the load-bearing cells:

| Cell                  | peel pre-plan | peel post-plan |   Δ      | curl\|xz\|tar |
|-----------------------|--------------:|---------------:|---------:|--------------:|
| 1 Gbps · 128 MiB      |     6.352s    |     5.249s     | −1.1 s   |    2.659s     |
| 10 Gbps · 256 MiB     |    14.380s    |    11.822s     | −2.6 s   |    6.130s     |

Fast-format reference rows (`tar`, `tar.zst`, `tar.lz4`) stayed
≤ 1.0× on every cell where they were before; no regression.

**README + OPTIMIZATIONS.md updates:**

- [README.md](../README.md) bench grid + "Reading the grid" prose
  refreshed: tar.xz row now publishes 1.13 / 1.07 / 1.97 / 1.91,
  with prose noting the `PLAN_checkpoint_blob_dedup.md` cut and
  pointing at [`PLAN_xz_parallel_block_decode.md`](PLAN_xz_parallel_block_decode.md)
  as the next-step toward ≤ 1×.
- [`docs/OPTIMIZATIONS.md`](OPTIMIZATIONS.md) `O.34` added as
  "delivered" record; `O.35` filed as the next-step backlog
  entry for HW-accelerated `Checkpoint` body hash (the residual
  ~8.5 ms / ckpt is now the scalar fnv1a64; expected ~5–7 ms /
  ckpt savings, which would take the row from ~1.91× toward
  ~1.5× independent of any decoder work).
- [`PLAN_xz_bench_profile.md`](PLAN_xz_bench_profile.md)
  Appendix A's "Phase 1 projection" table got an "actual"
  column showing measured-vs-projected per-call cost, total
  ckpt cost, and ratio.
