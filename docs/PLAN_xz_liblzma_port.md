# PLAN — Clean-room Rust port of liblzma's decoder, structurally faithful

**Status**: proposed (2026-05-07). Not started.
**Owner**: TBD.
**Sequenced after**:
[`PLAN_xz_liblzma_deep_dive.md`](PLAN_xz_liblzma_deep_dive.md) —
that plan's Phase A documented liblzma's inner-loop shape;
Phase C tested whether a safe-Rust LocalRc reshape of the
existing `xz_native` decoder could close the gap and **found
it could not**: LLVM kept materializing the LocalRc on the
stack frame because `decode_chunk`'s overall live state was
too high. Phase C's diagnosis: closing the 1.5× gap in
Rust requires either a structural rewrite that liblzma
itself uses, or research-grade work.

This plan is the **structural rewrite**. We port liblzma's
decoder shape into a new module — clean-room (read-for-shape,
no source copy), liberal `unsafe` budget, no checkpoint
support — to test whether Rust + LLVM can reach liblzma's
~1× when the surrounding code shape matches liblzma's. If it
works, Phase F adds checkpoint support back; if it doesn't,
we close the deep-dive plan and ship the existing
`xz_native` as the production path.

**Sibling plan**:
[`PLAN_xz_decoder_optimization.md`](PLAN_xz_decoder_optimization.md) —
the predecessor plan whose Phase 2 is the as-shipped
production decoder (~1.48× LCG / ~1.31× compressible at
128 MiB). This plan does **not** modify that decoder; it
builds an experimental sibling.

## Why we're doing this

The existing `xz_native` decoder's structural constraint is
**checkpoint compatibility**:
- Each LZMA2 chunk gets a fresh `RangeDecoder` over its
  pre-buffered `Compressed_Size` bytes. The rc state is
  intentionally *not* threaded across chunks.
- Dict + probs + LZMA-state-machine state are snapshotable
  at chunk boundaries (this is what `frame_boundary` is).
- `decode_chunk`'s body is responsible for one chunk's
  worth of work, with the chunk dispatcher (`block.rs`)
  driving the loop.

This shape is checkpoint-friendly but **performance-hostile**:
`decode_chunk` carries a lot of live state (chunk dispatch
context, dict, probs, staging, plus the rc fields), and
LLVM's register allocator can't keep all of it in registers
on Apple aarch64. Phase C of the deep-dive plan
demonstrated this empirically — moving rc fields from a
heap struct to a stack-local struct produced ~0 % gain
because the spills moved one form of L1-resident memory to
another.

liblzma's design is the inverse:
- `lzma_decode` is a giant single function that runs until
  it exhausts a Block's worth of input *or* output.
- Resume happens **inside the inner loop** via a
  per-bit-decode `case`-labeled state machine and
  `coder->sequence` (the per-bit position cursor).
- The chunk dispatcher (`lzma2_decoder.c`) feeds bytes into
  `lzma_decode` and collects bytes out via the dict; it does
  not own the rc state.
- The hot loop sees only its own state plus the dict
  pointer — minimal register pressure.

This plan ports liblzma's design into Rust, **without
checkpoint support for round one**. The user's framing:
"see if we can get same perf, then add checkpoints if it
seems worth it." The clear two-phase decision is the right
shape — Phase C just demonstrated that pursuing checkpoint
*and* perf simultaneously is hostile.

## Hypothesis

Three structural levers compound:

1. **Single-function dispatch loop**. With `lzma_decode_port`
   as the only function holding rc/dict/state in scope, LLVM
   has the entire Block's decode in one body. Register pressure
   drops to roughly liblzma's: ~10–14 live values
   (range, code, in_pos, out_pos, prob_base, symbol, plus the
   dict's pos/buf/size, plus rep0..rep3 + state). M4 has 31
   GP registers; this is well within budget. **Estimated
   gain: 30–50 % of decoder-only throughput** if LLVM follows
   the same allocation pattern as GCC/Clang on the C source.

2. **`unsafe` raw-pointer prob access**. liblzma's `probs[idx]`
   is a `uint16_t *`; ours uses `&mut [u16]` slice indexing
   with the bounds check that LLVM may or may not elide. With
   liberal `unsafe` we can use `probability *prob = base.add(idx);`
   directly — no fat pointer, no panic_bounds_check potential.
   **Estimated gain: 5–10 %**.

3. **Macro-based bit-decode primitives** as `macro_rules!`
   expansions. liblzma's `rc_normalize`, `rc_if_0`,
   `rc_update_0`, `rc_update_1`, `rc_bit`, `rc_bit_case`
   macros expand at the call site so the compiler sees one
   straight-line body per literal byte. Rust can do exactly
   the same with `macro_rules!`. **Estimated gain: 0–5 %**
   above (1) + (2) — the bigger function-shape changes will
   carry most of this.

(1)+(2)+(3) stack to land within **5 % of liblzma** on
both fixtures, the user's stated success gate. If (1) alone
is the load-bearing piece, (2) and (3) are polish; if (1)
lands at, say, 20 % gain, we're at ~80 % of liblzma which
is the previous plan's primary target — useful but not
"closer to 1×."

The honest pre-implementation projection: **70 % chance we
hit ≤ 1.10× on both fixtures; 40 % chance we hit ≤ 1.05×**.
Phase C's surprise (the spills don't compress to register
moves just by relocating them) should lower confidence in
"it'll just work" hypotheses, but the function-shape change
is structurally larger than what Phase C tried.

## Scope

### In scope (round one)

- **A new module at `src/decode/xz_liblzma/`**, parallel to
  `src/decode/xz_native/`. Contents:
  - `mod.rs` — public crate surface
  - `decoder.rs` — `lzma_decode_port`-equivalent (the
    giant function) + `Lzma1Decoder` state struct
  - `range_coder.rs` — rc state + `macro_rules!` for
    `rc_normalize` / `rc_if_0` / `rc_update_0` /
    `rc_update_1` / `rc_bit` / `rc_bit_case` /
    `rc_direct`
  - `dict.rs` — sliding-window dict (its own struct,
    not coupled to the decoder state)
  - `lzma2.rs` — LZMA2 chunk dispatcher
  - `block.rs` — Block header parser + Block-Check
    integration
  - `stream.rs` — Stream Header + Stream Footer + Index
    parser
  - `check.rs` — None / CRC32 / CRC64 / SHA256 stream-check
    dispatch (re-uses `peel::hash` modules)
  - `error.rs` — typed errors
- **Liberal `unsafe`**: `unsafe` blocks admitted wherever
  liblzma uses raw pointers. Each block carries a `// SAFETY:`
  proof block with the invariants the caller and callee rely
  on, **but the strict ≥ 5 % microbench gate from the
  predecessor plan is dropped**: parity-with-liblzma is the
  goal, and liblzma uses raw pointers throughout. The audit
  surface grows commensurately and the plan owns that.
- **Clean-room discipline preserved**: liblzma's source is
  read for *behavior at branches*, not copied. The macro
  expansion shape is the load-bearing structural element;
  faithful behavioral equivalence is required, source
  duplication is not. Same legal posture as the existing
  decoder.
- **Public API surface**: a `peel::decode::xz_liblzma::Decoder`
  type that implements `peel::decode::StreamingDecoder` (for
  the bench harness). No checkpoint support — the
  `decoder_state_into` / `frame_boundary_offset` methods
  return values that signal "this decoder does not snapshot."
  This is fine for the bench grid; it would block production
  integration until Phase F adds checkpoint support back.
- **Differential test against `xz2`**: the new decoder must
  produce byte-identical output to liblzma across the
  existing 100-fixture corpus and the compressible-fixture
  corpus from `PLAN_xz_decoder_optimization.md`. Plus:
  the new decoder must produce byte-identical output to
  the existing `xz_native` decoder. Both gates are tested
  in `tests/test_xz_liblzma_diff.rs`.
- **No checkpoint support** in round one.
  `xz_liblzma::Decoder` is "decode the whole Block in one
  call (or stream input chunk-by-chunk via the public Read
  shape)"; mid-Block resume is filed as Phase F if the
  bench grid says it's worth integrating.
- **No fuzz target additions for round one** — the
  differential corpus + the existing fuzz coverage of the
  old decoder is the safety net. New fuzz targets file as
  a Phase F follow-on.

### Out of scope

- **Encoder**. Same as predecessor — `peel` never emits xz.
- **Mid-Block resume / checkpoints**. Filed as Phase F.
  Implementing them in this plan defeats the hypothesis.
- **Hardware CRC64 (PMULL/PCLMUL)**. Phase B of the deep-dive
  plan was deferred and is similarly deferred here. The new
  port uses the existing `peel::hash::crc64` (slicing-by-16),
  same as the production decoder. PMULL/PCLMUL is filed as
  a follow-on regardless of whether this plan ships.
- **Multi-Block parallel decode**. Filed as
  [`PLAN_xz_parallel_block_decode.md`](PLAN_xz_parallel_block_decode.md);
  orthogonal lever, single-thread-only here.
- **Modifying the existing `xz_native` decoder**. The new
  module is parallel; the old module stays as the
  shipped-in-production path until/unless Phase F decides
  to migrate.
- **Linux x86-64 perf validation in this plan's main body**.
  Project default-target is M4 Max; cross-arch is filed as
  a Phase F TODO (same as the deep-dive plan's Phase F TODO).

### Non-goals

- **Beating liblzma**. Stretch is **≤ 1.05× on both fixtures**;
  primary target is **≤ 1.10×**. Beating liblzma single-thread
  on Apple Silicon is genuinely speculative and not the point
  of this exercise.
- **API ergonomics parity with the existing decoder**. The
  new module is an experiment first, integration target
  second. Round-one API can be ugly if it makes the perf
  measurable.
- **Bit-identical resume blob output**. No resume blob exists
  in round one.

## Targets

- **Decoder-only throughput** on
  `bench_xz_native_tar_xz_128mib_single_block` (extended to
  drive the new decoder via a sibling bench
  `bench_xz_liblzma_tar_xz_128mib_single_block`):
  - Today's existing decoder: 35.9 MiB/s (calm) / 67.7 % of
    xz2 (53.0 MiB/s).
  - **Primary target**: peel ≥ **48 MiB/s** (≥ 90 % of xz2);
    ratio ≤ 1.10×.
  - **Stretch target**: peel ≥ **50 MiB/s** (≥ 95 % of xz2);
    ratio ≤ 1.05×.
- **Compressible 128 MiB**:
  - Today's existing decoder: 59.7 MiB/s / 76.2 % of xz2
    (78.3 MiB/s).
  - **Primary target**: peel ≥ **70 MiB/s** (≥ 90 % of xz2);
    ratio ≤ 1.10×.
  - **Stretch target**: peel ≥ **74 MiB/s** (≥ 95 % of xz2);
    ratio ≤ 1.05×.
- **Both fixtures must independently clear the gate**.
  Diverging — one fixture at 1.05× and the other at 1.30× —
  is a phase-blocking smell.
- **Differential corpus byte-identical to `xz2`** — every
  phase that touches the inner loop. 100-fixture corpus
  reused; new fixtures added if a structural fold (e.g.,
  sequence-state coroutine resume) opens new paths.
- **Cross-validation against the existing `xz_native`** — the
  new decoder must produce byte-identical output to the old
  one across the 100-fixture corpus, every phase. Catches
  any drift in the LZMA spec interpretation that's identical
  but wrong in both directions.
- **`unsafe` discipline**: SAFETY: comments required per
  block; reviewer ack required; **no microbench-gain gate**
  (the gate is "the port matches liblzma," which is itself
  the perf-justification for the policy relaxation).

## Approach

### Inner-first phasing

Phase C of the deep-dive plan was a 28-minute experiment
that came back as a no-op. The lesson: **don't write the
framing code before you've confirmed the inner loop hits
the perf you need**. This plan adopts the same posture —
build the smallest possible artifact that lets us run the
hot loop, bench it against liblzma, and decide whether the
rest of the port is worth writing.

The structural ordering:

1. **Phase 1**: Range coder + probs primitives (no I/O,
   no chunk framing). The macros expand correctly; round-trip
   tests pass against a hand-written test encoder.
2. **Phase 2**: Sliding-window dict (no I/O, isolated
   correctness via fixture-driven tests).
3. **Phase 3**: `lzma_decode_port` — the giant function.
   Drives Phase 1 + Phase 2 against pre-buffered
   compressed bytes. **No LZMA2 chunk framing yet** — the
   bench at this phase decodes one giant pre-extracted
   LZMA stream, fed all at once.
4. **Phase 4**: **Bench gate**. Run the hot loop against
   pre-extracted LZMA fixtures (extracted from real
   `.tar.xz` files via the existing `xz_native::lzma2`
   chunk-dispatcher being told to dump its compressed
   payload to a side channel). Measure peel-port MiB/s,
   compare to xz2 MiB/s on the same input. **If we don't
   clear ≤ 1.10× on both fixtures, the plan stops here**
   and we close out with "the inner loop alone wasn't
   enough; closer-to-1× is gated on something we haven't
   tested yet, file as a research follow-on."
5. **Phase 5**: LZMA2 chunk dispatcher. Drives `lzma_decode_port`
   chunk-by-chunk against a real `.tar.xz` Block's
   chunk-control-byte sequence.
6. **Phase 6**: Block + Stream parser + check hashing. The
   public `xz_liblzma::Decoder` type emerges here.
7. **Phase 7**: Differential test pass. 100-fixture corpus
   byte-identical to `xz2`. The new decoder also matches the
   existing `xz_native`.
8. **Phase 8**: Bench grid integration. The new decoder is
   driven via the bench harness for the `tar.xz · 1 Gbps ·
   128 MiB` cell; the headline ratio number is the
   integration-vs-shelf decision input.
9. **Phase 9**: Decision. Either:
   - **Integrate**: file follow-on to add checkpoint support
     (Phase F), then migrate `peel`'s xz path from
     `xz_native` to `xz_liblzma`.
   - **Shelf**: keep `xz_liblzma` as a benchmarking
     reference; no production integration. Close out
     `PLAN_xz_liblzma_deep_dive.md` with this plan's
     numbers as the structural ceiling under a strict
     safe-Rust posture.

### "As close as possible to liblzma" — what that means

Concretely, the structural shapes we mirror:

| liblzma | Rust port |
|---|---|
| `typedef enum { SEQ_NORMALIZE, SEQ_IS_MATCH, ... }` | `enum Sequence { ... }` with `#[repr(u8)]` |
| `lzma_lzma1_decoder { rc, state, rep0..3, probs, sequence, symbol, limit, offset, len }` | `pub struct Lzma1Decoder { ... }` with field-by-field correspondence |
| `rc_to_local(coder->rc, *in_pos);` | `let (mut range, mut code, mut in_pos) = (coder.rc.range, coder.rc.code, *in_pos);` |
| `#define rc_normalize(seq) do { if (rc.range < RC_TOP_VALUE) { ... if (unlikely(rc_in_pos == in_size)) { coder->sequence = seq; goto out; } ... } } while (0)` | `macro_rules! rc_normalize { ($seq:expr) => { ... } }` with `break 'main_loop` standing in for `goto out` |
| `case SEQ_LITERAL0: ... rc_bit_case(probs[symbol], , , SEQ_LITERAL0);` | `Sequence::Literal0 => { rc_bit_case!(...); }` arm in a `loop { match coder.sequence { ... } }` body |
| `probability literal[LITERAL_CODERS_MAX][LITERAL_CODER_SIZE];` | `pub literal: [[u16; LITERAL_CODER_SIZE]; LITERAL_CODERS_MAX]` (fixed-size; ≤16 KiB worst case) |
| `dict_get(&dict, n)` / `dict_put(&dict, byte)` / `dict_repeat(&dict, dist, &len)` | `dict.get(n)` / `dict.put(b)` / `dict.repeat(dist, &mut len)` (raw-pointer-backed) |

Where Rust's safety model differs irreconcilably from C's,
the port will use `unsafe` blocks with SAFETY: proofs. The
two big places this happens:

1. **Probability slot pointer**. liblzma's `probability *probs;`
   is a raw pointer that's reseated per literal byte to point
   at the relevant context's slab. Ours becomes a `*mut u16`
   with a SAFETY proof that the offset is within
   `LITERAL_CODER_SIZE` for any in-flight `symbol`.
2. **Dict pointer-and-length**. liblzma uses a `lzma_dict`
   struct with `uint8_t *buf`, `size_t pos`, `size_t full`,
   `size_t limit`, `size_t size`. Ours uses raw-pointer
   indexing for the hot path, with SAFETY proofs from the
   chunk-end length validation and the spec's
   `dist < dict_size` check.

### Crate structure (round one)

```
src/decode/xz_liblzma/
├── mod.rs              ; public crate API (pub use Decoder)
├── decoder.rs          ; lzma_decode_port + Lzma1Decoder struct
├── range_coder.rs      ; rc state + macro_rules! primitives
├── dict.rs             ; sliding-window dict
├── lzma2.rs            ; LZMA2 chunk dispatcher
├── block.rs            ; Block header parser, Block-Check integration
├── stream.rs           ; Stream Header + Footer + Index
├── check.rs            ; check-hash dispatcher (calls peel::hash::*)
├── error.rs            ; typed errors (XzPortError)
└── tests/              ; module-internal #[cfg(test)] tests
```

External tests:
```
tests/
├── test_xz_liblzma_diff.rs      ; differential corpus vs xz2 + xz_native
├── test_bench_xz_liblzma.rs     ; sibling to test_bench_xz_native.rs
└── ...                          ; existing tests untouched
```

### Macro-based primitives — Rust shape

The `range_coder.rs` macros are the load-bearing structural
element. Sketch:

```rust
macro_rules! rc_normalize {
    ($range:ident, $code:ident, $in_pos:ident, $bytes:expr, $seq:expr, $coder:expr) => {{
        if $range < RC_TOP_VALUE {
            if $in_pos >= $bytes.len() {
                $coder.sequence = $seq;
                break 'decoder_loop;  // stand-in for "goto out"
            }
            $range <<= 8;
            $code = ($code << 8) | $bytes[$in_pos] as u32;
            $in_pos += 1;
        }
    }}
}

macro_rules! rc_if_0 {
    ($range:ident, $code:ident, $in_pos:ident, $bytes:expr, $bound:ident, $prob:expr, $seq:expr, $coder:expr, $body0:block else $body1:block) => {{
        rc_normalize!($range, $code, $in_pos, $bytes, $seq, $coder);
        $bound = ($range >> RC_BIT_MODEL_TOTAL_BITS) * (*$prob as u32);
        if $code < $bound {
            $bound = $bound;  // satisfy the "rc_bound is in-scope downstream" idiom
            $body0
        } else {
            $body1
        }
    }}
}
```

The "everything is a hygienic-macro identifier" pattern is
what lets the compiler keep `range`, `code`, `in_pos` in
function-local registers across hundreds of expansion sites.
Rust's `macro_rules!` hygiene is powerful enough for this;
no `proc_macro` is needed.

### "goto out" in Rust

liblzma's `goto out` is the function-exit on input
underflow. Rust has no `goto`, but `break 'label` from a
labeled `loop {}` block reaches an outer-scope code section
in the same way. Sketch:

```rust
fn lzma_decode_port(coder: &mut Lzma1Decoder, dict: &mut LzmaDict, bytes: &[u8], in_pos: &mut usize) -> XzPortResult<()> {
    let mut range = coder.rc.range;
    let mut code = coder.rc.code;
    let mut local_in_pos = *in_pos;
    let mut bound: u32;
    
    'decoder_loop: loop {
        match coder.sequence {
            Sequence::Normalize | Sequence::IsMatch => {
                rc_if_0!(range, code, local_in_pos, bytes, bound, 
                         &mut coder.probs.is_match[/*...*/],
                         Sequence::IsMatch, coder,
                         { /* literal path */ } else { /* match path */ });
                // ... etc
            }
            Sequence::Literal0 => { /* etc */ }
            // ... 30-ish sequence states
        }
    }
    
    // out: equivalent
    coder.rc.range = range;
    coder.rc.code = code;
    *in_pos = local_in_pos;
    Ok(())
}
```

### Phase 4's bench — the gating measurement

Phase 4 is the load-bearing decision point. Its bench must
isolate the inner loop from chunk dispatch, parser overhead,
and check hashing — otherwise we can't tell whether the inner
loop hits parity even if other layers don't.

The Phase 4 bench:
1. Take the existing 128 MiB LCG / 128 MiB compressible
   `.tar.xz` fixtures.
2. Use the **existing** `xz_native::lzma2::Lzma2State` as a
   "framing extractor" — its `decode_chunk` accepts a
   pre-buffered chunk's compressed payload and runs the
   inner loop. Modify it (locally for the bench, not in the
   shipped path) to dump each chunk's compressed payload + a
   prelude of (lc, lp, pb, dict_size, initial_state_snapshot)
   to a temp file.
3. Drive the new `lzma_decode_port` against the same
   pre-extracted bytes, with a fresh dict + freshly-init
   probs per chunk.
4. Compare wall-clock against `xz2` doing the same — `xz2`
   exposes `XzDecoder` over a `Read`, so feed it the same
   real `.tar.xz` and the relevant Block's slice.

Variant: skip the chunk extraction entirely and just decode
the whole `.tar.xz` Block via `lzma2_decoder_port` (Phase 5);
the only difference is whether we've written the chunk
dispatcher yet. **If Phase 5 lands quickly** (it's small),
we may skip the Phase 4 mock and bench against the real
chunk-dispatch shape.

## Phasing

Each phase ends green on `cargo test`,
`cargo clippy --tests --release -- -D warnings`,
`cargo fmt --check`. The differential corpus and bench
gates are phase-specific.

### Phase 1 — Range coder + probs primitives (3–5 days human; ~1–2h agent)

- `src/decode/xz_liblzma/range_coder.rs`:
  - `RangeDecoder` struct (mirror of `lzma_range_decoder`):
    `range: u32`, `code: u32`, `init_bytes_left: u8`.
  - `rc_to_local!` / `rc_from_local!` macros.
  - `rc_normalize!` / `rc_if_0!` / `rc_update_0!` /
    `rc_update_1!` / `rc_bit!` / `rc_bit_case!` /
    `rc_direct!` macros.
  - `rc_read_init` helper for the 5-byte init prefix.
- `src/decode/xz_liblzma/decoder.rs` (skeleton):
  - `Lzma1Decoder` struct (mirror of `lzma_lzma1_decoder`):
    rc, state, rep0..rep3, probs, sequence, symbol, limit,
    offset, len.
  - `Sequence` enum with all the `SEQ_*` values from
    liblzma's `lzma_decoder.c:208-266` (~30 variants).
  - `LzmaProbs` (mirror of liblzma's struct shape):
    fixed-size arrays for is_match, is_rep_g0/1/2,
    is_rep0_long, dist_special, dist_align, len_decoder,
    rep_len_decoder, dist_slot. The `literal` table is
    also fixed-size at the spec maximum (`(1 << 4) * 0x300`
    `u16`s = 24 KiB), then the active `(lc, lp)` selects a
    sub-region.
- Round-trip tests: encode a few hundred bits via the
  existing `TestRangeEncoder` (the `xz_native` test
  helper), decode via the new macros, assert byte-identical
  prob-slot evolution. Same pattern as
  [`xz_native::range_coder::tests`](../src/decode/xz_native/range_coder.rs).
- **No microbench at this phase** — the macros aren't
  meaningfully exercised without the inner loop.

**Exit criterion**:
- Round-trip tests pass: 64-bit / 30-bit direct / mixed
  bit-tree fixtures match the existing `xz_native`
  reference.
- `cargo clippy` clean.
- `cargo asm` of a stand-in test driver shows the macros
  expand to the expected aarch64 shape (no
  `panic_bounds_check`, no struct-field stores in the bit
  decode body).

### Phase 2 — Sliding-window dict (2–3 days human; ~30 min agent)

- `src/decode/xz_liblzma/dict.rs`:
  - `LzmaDict` struct: `buf: Box<[u8]>`, `pos: usize`,
    `full: usize`, `limit: usize`, `size: usize`. Same
    shape as liblzma's `lzma_dict`.
  - `dict_get` / `dict_put` / `dict_repeat` methods,
    raw-pointer-backed. `dict_repeat` is the
    match-copy fast path.
  - SAFETY proofs on every `unsafe` block.
- Differential test: build a fixture set of (push, repeat,
  get) sequences; the new dict's behavior is byte-identical
  to a reference implementation that uses safe slice
  indexing. The reference is checked into the test module.
- No mid-decode resume support — `dict.pos` never moves
  backwards; checkpoint comes in Phase F.

**Exit criterion**:
- Differential test corpus byte-identical between the
  raw-pointer fast path and the safe-Rust reference.
- `cargo clippy` clean (every `unsafe` block carries
  SAFETY:).

### Phase 3 — `lzma_decode_port` skeleton (4–6 days human; ~1.5h agent)

- `src/decode/xz_liblzma/decoder.rs`:
  - The giant `lzma_decode_port` function. Mirror
    of liblzma's `lzma_decode` body. Sequence enum +
    `loop { match coder.sequence { ... } }`.
  - All the `case SEQ_*:` arms, each transcribed from
    liblzma's `lzma_decoder.c` per the project's
    clean-room policy.
  - `unsafe` blocks carry SAFETY: + the structural
    invariant.
  - The `out:` equivalent (post-loop block) writes back
    `range`, `code`, `in_pos` to the `Lzma1Decoder`
    state.
- Driven by a Phase 3 unit test that constructs a
  `Lzma1Decoder`, feeds it pre-extracted LZMA-stream
  bytes (one full Block's payload, no LZMA2 framing),
  and asserts byte-identical output vs the existing
  `xz_native` decoder over the same bytes.
- **No LZMA2 chunk dispatch yet** — the test fixture is
  a single chunk's worth of LZMA payload, manually
  framed.

**Exit criterion**:
- Round-trip on at least 5 hand-constructed LZMA payloads
  spanning literal-only, match-only, RLE, mixed-state
  shapes.
- `cargo asm` of `lzma_decode_port` shows:
  - `range` / `code` / `in_pos` in registers across the
    inner loop body (no `[sp, ...]` stores in the
    matched-literal walk).
  - The literal hot loop has 8 explicit `case` arms
    (`Literal0` ... `Literal7`) that each compile to
    ~12 instructions.
- Differential test against `xz_native` byte-identical
  on the 5 fixtures.

### Phase 4 — **GATING BENCH** (1 day; bench-bound)

This phase is the load-bearing decision point. **If the
bench numbers don't clear ≤ 1.10× on both fixtures, the
plan stops** and we report findings.

- `tests/test_bench_xz_liblzma.rs`:
  - `bench_xz_liblzma_inner_loop_lcg` — drives `lzma_decode_port`
    against a 128 MiB LCG payload's pre-extracted Block
    bytes. Reports peel MiB/s + xz2 MiB/s + ratio.
  - `bench_xz_liblzma_inner_loop_compressible` — same for
    compressible fixture.
  - Both `#[ignore]`d; opt-in via `--ignored`.
- Run each 3 times for thermal stability; median is the
  reported number.
- **Exit decision**:
  - **Both fixtures ≤ 1.10×**: proceed to Phase 5. Plan is
    on track for primary target.
  - **Both fixtures ≤ 1.05×**: plan is on track for stretch.
  - **Either fixture > 1.10×**: stop the plan. Document
    findings in this plan's Appendix A. Either:
    - The structural rewrite hits the same ceiling Phase C
      did, in which case we've established the
      architectural gap is deeper than rewrite-scoped
      changes can close.
    - There's a specific identifiable lever we missed,
      which becomes a new Phase 4.5 to try before stopping.

**Phase 4's expected outcome**: 60–70 % chance both fixtures
hit ≤ 1.10×; 30–40 % chance one or both come in higher.
The "stop the plan" branch is the scientifically interesting
result regardless — it tells us the existing `xz_native` is
at LLVM/Apple aarch64's structural ceiling and further work
must go through other levers (parallel decode, table-driven,
SIMD).

### Phase 5 — LZMA2 chunk dispatcher (3 days human; ~45 min agent)

Skipped if Phase 4 stopped the plan.

- `src/decode/xz_liblzma/lzma2.rs`:
  - `Lzma2Decoder` struct + state machine (mirror of
    liblzma's `lzma2_decoder.c`).
  - Chunk-control-byte parser:
    - `0x00`: end of LZMA2 stream
    - `0x01`: uncompressed chunk, dict reset
    - `0x02`: uncompressed chunk, no dict reset
    - `0x80..=0xFF`: LZMA chunk with various reset modes
  - Drives `lzma_decode_port` against each LZMA chunk's
    compressed payload.
  - Calls `LzmaProbs` reset functions per chunk-control
    request.

**Exit criterion**:
- Differential test corpus expanded — at least 5 multi-chunk
  fixtures, all byte-identical to `xz_native`.

### Phase 6 — Block + Stream parser + check hashing (3 days human; ~45 min agent)

- `src/decode/xz_liblzma/block.rs`: Block header parser (mirror
  of `block_header_decoder.c`).
- `src/decode/xz_liblzma/stream.rs`: Stream Header + Footer +
  Index parser (mirror of `stream_decoder.c`).
- `src/decode/xz_liblzma/check.rs`: dispatches None / CRC32 /
  CRC64 / SHA256 against the existing `peel::hash::*` modules
  (no separate implementations).
- Public API: `xz_liblzma::Decoder` type implementing
  `peel::decode::StreamingDecoder` (the same trait
  `xz_native::Decoder` implements). The
  `decoder_state_into` method returns `false` (this decoder
  doesn't snapshot); `frame_boundary_offset` returns `None`.

**Exit criterion**:
- Public `Decoder::new(&mut dyn Read)` accepts the same
  byte stream the existing `xz_native::Decoder` does.
- Differential corpus byte-identical across the 100-fixture
  suite vs `xz2` and vs `xz_native`.

### Phase 7 — Differential test pass (1 day)

- `tests/test_xz_liblzma_diff.rs`:
  - The full 100-fixture differential corpus from
    `PLAN_xz_block_decoder.md` Phase 9.
  - The compressible-fixture extension from
    `PLAN_xz_decoder_optimization.md` Phase 0.
  - Cross-validation against both `xz2` and `xz_native`.
- 1-hour fuzz on the new `lzma_decode_port` (existing fuzz
  targets retargeted to the new decoder for a single
  overnight run).

**Exit criterion**:
- 100-fixture corpus byte-identical (every fixture, every
  preset) vs both `xz2` and `xz_native`.
- 1-hour fuzz passes (no panics, no `unsafe` UB detected
  via Miri at fuzz-corpus replay).

### Phase 8 — Bench grid integration (1 day)

- Extend `bench_throttled_realistic_grid` to drive the new
  decoder for the `tar.xz` row alongside the existing path
  (toggleable via env var or `--features=xz-liblzma`).
- Capture `tar.xz · 1 Gbps · 128 MiB` ratio under both
  decoders.

**Exit criterion**:
- Bench grid `tar.xz` row reported under both decoders.
- The headline ratio is the integration-vs-shelf decision
  input.

### Phase 9 — Decision

Two outcomes, gated on the bench grid + Phase 4 numbers:

1. **Integrate**: file follow-on plan
   `PLAN_xz_liblzma_checkpoint.md` to add per-LZMA2-chunk
   resume support to the new decoder. Once that lands,
   migrate `peel::decode::xz` from `xz_native` to
   `xz_liblzma` (or alias one to the other, depending on
   API parity). Close this plan with the migration commit.

2. **Shelf**: keep `xz_liblzma` in the source tree as a
   benchmarking reference, **not** wired into production.
   The README's bench row stays at the existing decoder's
   number. Close this plan with a finding: "the structural
   port reached X % of liblzma; the remaining gap is gated
   on Y; further work as a research item."

The user's framing was clear: integrate if perf is worth
it, otherwise the experiment is the deliverable. This plan
preserves both outcomes.

## Risks

1. **Phase 4 lands at the same ceiling as Phase C**.
   Possible: the LLVM aarch64 register allocator may behave
   the same way for a giant single function as it does for
   the existing `decode_chunk`; the structural rewrite
   doesn't help. **Mitigation**: Phase 4 is the explicit
   stop-the-plan point. If it stops, the artifact is the
   "structural rewrite alone isn't enough" finding, which
   is itself useful.
2. **`unsafe` audit surface explodes**. The liberal
   `unsafe` policy admits raw pointers in the hot path;
   reviewer fatigue is a real risk. **Mitigation**: every
   `unsafe` block carries SAFETY: + the structural
   invariant; the new module's `unsafe` count is reported
   in Phase 9's commit message. Code-review passes for the
   port can be batched per phase.
3. **Differential vs `xz_native` finds we've been wrong all
   along**. The 100-fixture corpus has been our only
   correctness gate; the new port adds a second
   independent reference. If the new port is byte-identical
   to `xz2` but *not* to `xz_native`, the existing decoder
   has a (corner-case) bug. **Mitigation**: explicit
   three-way compare in Phase 7. A discrepancy is a bug
   report against `xz_native`, not a phase blocker for the
   new port; we file it and continue.
4. **Phase 4's "extract per-chunk LZMA bytes" instrumentation
   is more work than it sounds**. The `xz_native::lzma2`
   module doesn't currently expose the raw chunk-payload
   bytes. **Mitigation**: skip Phase 4 if Phase 5 is
   tractable; bench against the full chunk-dispatch shape
   instead.
5. **Time-spent vs. value**. The full plan is ~3 weeks
   human time, ~5 hours agent time at the calibration we
   measured during Phase C. **Mitigation**: Phase 4's
   stop-the-plan gate caps the downside. If the inner loop
   doesn't deliver, we don't write Phases 5–8.
6. **Maintenance cost of two decoders**. If the port ships
   as a sibling, future work has to update both.
   **Mitigation**: Phase 9's "shelf" outcome is acceptable
   for the experimental case; the production path stays on
   `xz_native`. Phase 9's "integrate" outcome involves a
   migration commit that retires `xz_native`.
7. **The "no checkpoint" qualifier is load-bearing for
   integration**. Adding checkpoint support back may force
   architectural compromises that re-introduce the
   register-pressure problem. **Mitigation**: Phase F
   (checkpoint integration) is a separate plan; if it
   forces compromises that regress the parity number, we
   re-evaluate at that time. Round-one perf is the bench
   for "is this port worth pursuing."

## Acceptance criteria (round one)

- ✅ `bench_xz_liblzma_inner_loop_lcg` (or its post-Phase-5
  full-stream sibling): ratio ≤ **1.10×** vs `xz2`; stretch
  ≤ 1.05×.
- ✅ `bench_xz_liblzma_inner_loop_compressible`: same gate.
- ✅ Differential corpus byte-identical vs `xz2` and vs
  `xz_native`. 100 fixtures × all presets.
- ✅ `cargo test`, `cargo clippy --tests --release -- -D warnings`,
  `cargo fmt --check` all green.
- ✅ Every `unsafe` block carries a SAFETY: comment.
- ✅ The new module is the public path **only if** Phase 9
  decides to integrate; otherwise it's experimental and
  not exposed via `lib.rs`.
- ✅ Phase 9 decision recorded: integrate or shelf, with
  rationale.

## Estimated total effort

Calibrated against the Phase C data point (28 minutes
agent time vs 5–7 days plan estimate ≈ 80–100× speedup).
Same calibration applied here:

| Phase | Human estimate | Agent estimate (calibrated) |
|---|---|---|
| 1: range coder + probs | 3–5 days | ~1.5h |
| 2: dict | 2–3 days | ~30 min |
| 3: lzma_decode_port | 4–6 days | ~1.5h |
| 4: gating bench | 1 day | ~30 min |
| 5: LZMA2 dispatcher | 3 days | ~45 min |
| 6: Block + Stream + Check | 3 days | ~45 min |
| 7: differential test pass | 1 day | ~20 min |
| 8: bench grid integration | 1 day | ~20 min |
| 9: decision + write-up | 0.5 day | ~15 min |
| **Totals (Phases 1–9)** | **~3 weeks** | **~6 hours** |

Phase-3's `lzma_decode_port` is the largest single piece;
its bench-bound wall-clock is the actual rate-limit (the
benches at Phase 4 and Phase 8 each cost ~30s × 6 runs
= ~3 min each).

**The plan's actual time-to-decision** (Phases 1–4) is
~4 hours agent time. After Phase 4 we either stop or
continue; the continue-path adds ~2 hours.

## Combined gain projection

What the bench grid's `tar.xz · 1 Gbps · 128 MiB` cell
looks like across the plan stack:

| Configuration | total | ratio | notes |
|---|---:|---:|---|
| Today (post Phase 2 of decoder-opt; Phase C reverted) | ~4.2 s | 1.53× | Shipped state |
| + this plan, primary (≤ 1.10× single-Block) | ~3.1 s | ~1.20× | xz_liblzma chosen for production via Phase F |
| + this plan, stretch (≤ 1.05×) | ~2.95 s | ~1.10× | xz_liblzma + Phase B (HW CRC64) on top |
| + parallel-Block decode (4 workers, multi-Block fixture) | ~1.2 s | **~0.45×** | Crosses 1×; multi-Block fixture only |

Single-Block ratios touch 1× only at the stretch target;
crossing 1× requires multi-Block parallelism. This plan's
job is to bring the single-Block fixture from 1.53× to
near-1.10×, restoring the parallel-decode plan's 2–3×
projection from the current 4–6×.

## Reference material

- [`PLAN_xz_liblzma_deep_dive.md`](PLAN_xz_liblzma_deep_dive.md)
  — the deep-dive plan whose Phase A documented liblzma's
  inner loop and Phase C demonstrated the structural
  ceiling. Appendix B's diagnosis is the input to this
  plan's hypothesis.
- [`PLAN_xz_decoder_optimization.md`](PLAN_xz_decoder_optimization.md)
  — predecessor plan whose Phase 2 is the as-shipped
  baseline.
- [`docs/profiles/liblzma_vs_peel_inner_loop.md`](profiles/liblzma_vs_peel_inner_loop.md)
  — Phase A's deliverable; documents the structural shapes
  this plan ports.
- liblzma sources (vendored via `lzma-sys 0.1.20` at
  `~/.cargo/registry/src/index.crates.io-*/lzma-sys-0.1.20/xz-5.2/`):
  - `lzma/lzma_decoder.c` — main decoder; ~1064 lines
  - `lzma/lzma2_decoder.c` — LZMA2 chunk dispatcher; ~310 lines
  - `lz/lz_decoder.c` / `.h` — sliding-window dict; ~545 lines
  - `common/block_decoder.c` / `block_header_decoder.c` —
    ~381 lines combined
  - `common/stream_decoder.c` — ~467 lines
  - `rangecoder/range_decoder.h` — the macros; 185 lines
- Total ~3000 lines of C source to port, structurally;
  in practice the Rust port will be a similar line count.
- [`tests/test_xz_native.rs`](../tests/test_xz_native.rs)
  — the differential corpus; gets a sibling
  `tests/test_xz_liblzma_diff.rs` in Phase 7.
- [`tests/test_bench_xz_native.rs`](../tests/test_bench_xz_native.rs)
  — the bench harness; gets a sibling
  `tests/test_bench_xz_liblzma.rs` at Phase 4.
- The `xz` file-format spec
  ([tukaani.org/xz/xz-file-format.txt](https://tukaani.org/xz/xz-file-format.txt))
  — referenced for Block / Stream framing.

## Appendix A — Phase 4 results (TBD)

To be populated by Phase 4. Same shape as the deep-dive
plan's Appendix B: bench numbers, asm artifacts, and the
exit-decision rationale.

## Appendix B — Phase 9 decision (TBD)

To be populated by Phase 9. One of:
- **Integrate**: the post-Phase-9 numbers + the migration
  commit hash + the Phase F follow-on plan link.
- **Shelf**: the post-Phase-9 numbers + the rationale +
  the research follow-on filed in `OPTIMIZATIONS.md`.
