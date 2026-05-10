# PLAN — Harden the macOS puncher against APFS `fcntl(F_PUNCHHOLE)` EINVAL

**Status**: resolved 2026-05-10. **Root cause was not a race.**
**Triggered by**: `rar5 phase f1` (commit `958a8de`). The §F1
checkpoint-format change surfaced a latent struct-layout bug in
[`MacosPuncher`](../src/punch.rs).
**Related plans / docs**:

- [`PLAN_rar5_decoder.md`](PLAN_rar5_decoder.md) §F1 — the
  trigger; the §F1 commit message documents the regression.
- [`PLAN_v2.md`](PLAN_v2.md) §12 — original `MacosPuncher`
  rationale.

## TL;DR — what was actually wrong

`MacosPuncher::punch` declared `fpunchhole_t` with **three** fields
(`fp_flags`, `fp_offset`, `fp_length`) and relied on `#[repr(C)]` to
insert the natural 4-byte pad between `fp_flags` and `fp_offset`.
The Darwin SDK (`/Library/Developer/CommandLineTools/SDKs/.../sys/fcntl.h`)
declares **four** fields, with an explicit `unsigned int reserved`
where Rust's compiler had been inserting padding:

```c
typedef struct fpunchhole {
    unsigned int fp_flags;   /* unused */
    unsigned int reserved;   /* (to maintain 8-byte alignment) */
    off_t        fp_offset;  /* IN: start of the region */
    off_t        fp_length;  /* IN: size of the region */
} fpunchhole_t;
```

The kernel `copyin()`s all 24 bytes and the APFS validator rejects
the call with `EINVAL` when `reserved != 0`, even though the SDK
header marks the field "for alignment". The Rust constructor

```rust
let mut arg = Fpunchhole { fp_flags: 0, fp_offset, fp_length };
```

leaves the 4-byte padding **uninitialized** — it's whatever stack
slot bytes happened to be there. In debug builds the slot was
typically zero (so the test passed). In release builds the optimizer
reused dirty slots and the bytes were nonzero — every per-entry punch
came back as `Punch(Unsupported { errno: 22 })`.

The fix was a one-line struct change: declare `reserved: u32` and
initialize it to zero. Both debug and release builds now pass the
crash-resume test 100/100 times.

This is **our bug**, not an Apple bug. No Feedback Assistant report
needed.

## How we got there

The §F1 commit added an optional `current_entry_decoder_state:
Option<Vec<u8>>` field to the `SinkState::Rar` checkpoint variant
and a corresponding event-handler arm in the coordinator's RAR
observer. That changed enough of the layout/code-gen around the
puncher's call site that the previously-zero stack-slot bytes
became nonzero — a classic "uninitialized memory bug latent for
years, surfaced by an unrelated change" pattern.

### What threw us off the scent (and is documented for posterity)

1. **The error code was `EINVAL`.** The original
   `MacosPuncher::punch` mapped `EINVAL` to
   `PunchError::Unsupported`, treating it as the "filesystem
   doesn't support punching" signal. APFS *does* support
   punching — it was rejecting our argument as malformed.

2. **It only fired in release mode after F1.** Debug builds
   zero-fill stack slots more aggressively and tests always
   passed there. The first investigative pass kept running in
   debug, where every fix appeared to work.

3. **Adding any instrumentation made the test pass.** `eprintln!`,
   file-logging, even an extra fcntl probe — all of these
   shifted code-gen enough to leave zeros in the padding bytes.
   This looked exactly like a timing race ("the eprintln slows
   things down enough"), so the original draft of this plan
   hypothesized worker-pwrite contention and proposed an
   `fsync` + retry fix.

4. **A "fresh fd" punch succeeded while the original fd's
   punch failed.** When the puncher opened a new fd by path
   (`F_GETPATH` + `open`) and tried the same `F_PUNCHHOLE`
   args, it returned 0 and actually freed blocks (verified via
   `st_blocks`). This looked like per-fd kernel state and led
   to ~an hour of investigation into Darwin's `FNOCACHE`,
   `F_BARRIERFSYNC`, and per-vnode caches. The actual
   explanation is mundane: the fresh-fd codepath used a
   *different* stack frame, and that frame's padding bytes
   were zero. The original-fd codepath kept failing not
   because the fd was special, but because the same stack
   slot was being reused with the same nonzero garbage.

5. **A pure-C reproducer "didn't reproduce" until I noticed
   I'd written the aggregate initializer wrong.** A first-pass
   C reproducer used the SDK struct (4 fields) with
   `{0, 4096, OFFSET}` (3 values). C's positional initializer
   put `4096` into `reserved` and `OFFSET` into `fp_offset`,
   leaving `fp_length = 0`. That returned EINVAL too — same
   *symptom*, different *cause*. Confusing both error sources
   together delayed pinpointing the layout issue. The lesson:
   when reproducing a kernel-syscall bug across languages, use
   **named field initializers** in both, every time.

The smoking-gun probe is preserved in the test helper's
characterization comment in [`tests/test_punch_race_macos.rs`](../tests/test_punch_race_macos.rs).
The probe instrumentation that revealed the per-fd disparity
(`PROBE orig_flags=0x10002 fresh_flags=0x2`) initially looked
like Apple had set a magic FNOCACHE-equivalent bit on the
ftruncate'd fd; the bit turned out to be `FFCNTL_INTERNAL`-
adjacent and unrelated to the EINVAL.

## Phases (revised)

### §A — Resolve the struct layout

**What**: declare `reserved: u32` explicitly between `fp_flags`
and `fp_offset` in `Fpunchhole`, and initialize it to `0` at
every call site (there is one).

**Sketch**:

```rust
#[repr(C)]
struct Fpunchhole {
    fp_flags: u32,
    reserved: u32, // explicit; was implicit padding under repr(C)
    fp_offset: i64,
    fp_length: i64,
}

let mut arg = Fpunchhole {
    fp_flags: 0,
    reserved: 0,
    fp_offset: i_offset,
    fp_length: i_length,
};
```

**Demo**:

- `tests/test_coordinator_rar.rs::
  crash_resume_mid_entry_produces_identical_output` passes 100/100
  in **both** debug and release on macOS arm64.
- `tests/test_punch_race_macos.rs` reports zero
  `Unsupported { errno: 22 }` outcomes from `MacosPuncher`
  through 1024 iterations under live `pwrite` contention.
- Linux and other Unix targets are unchanged.

**Status**: ✅ landed.

### §B — Keep the focused micro-bench

**What**: keep [`tests/test_punch_race_macos.rs`](../tests/test_punch_race_macos.rs)
as-is. The "MacosPuncher under pwrite contention" test now
serves as a regression test for the layout: any future puncher
change that re-introduces uninitialized bytes (including a
naive port to a different platform's struct) will surface in
that test by failing the strict `Unsupported == 0` assertion.

The companion "raw fcntl, observational" test stays as a
documentation artifact — it prints the count of EINVALs from
the raw-fcntl path so a future investigator has a quick smoke
test for "is `F_PUNCHHOLE` even working on this Mac?".

**Status**: ✅ landed.

### §C — Re-enable the §F1 compressed-entry sibling test

**What**: add a `crash_resume_mid_compressed_entry_produces_identical_output`
sibling so the §F1 decoder-state-aware resume path is also
exercised end-to-end (matching `PLAN_rar5_decoder.md` §F1's
"Demo" intent).

**Status**: ⚠️ deferred. A scaffolded version of the sibling
test was written against a curated 6 MiB method-5 fixture
(`tests/fixtures/rar5/multi_entry.rar`). The puncher fix
worked correctly; the test failed because the round-one §F1
`RarStreamDecoder` rejects the fixture's bitstream with
`"RAR5 Huffman decode underran the bitstream"` at archive
offset 0 — i.e., the decoder doesn't yet cover the Huffman
shapes real-world RAR5 archives use.

The smaller curated fixture (`testfile.rar5.solid.rar`,
12-byte payload) is the only known-good compressed input
today, and its payload is too small for
`coord_config(checkpoint_min_bytes = 1)` to land a mid-entry
`CheckpointWritten` before the entry finishes (the test
collapses to a clean-run round-trip, not a crash-resume).
The 6 MiB fixture has been removed from the tree pending
decoder coverage.

Closing out the §F1 demo therefore needs either:
1. broader §F2+ decoder coverage, after which any real-world
   RAR5 archive drives the test directly; or
2. a hand-encoded "Goldilocks" fixture (large enough for
   mid-entry checkpointing, simple enough for the round-one
   decoder) — which needs an external encoder we don't have
   on the dependency allowlist (`rar` is commercial and not
   installed; 7z's RAR5 encoder is `E_NOTIMPL`).

The deferral, scaffolding pointer, and exit conditions are
all noted inline at the test site in
[`tests/test_coordinator_rar.rs`](../tests/test_coordinator_rar.rs)
so a future contributor revisiting §F2 finds the context.

### §D — Cross-references

**What**:

1. ✅ [`PLAN_v2.md`](PLAN_v2.md) §12 now carries an
   "Implementation note" pointing here so future readers
   wondering why we mirror Darwin's struct verbatim
   (including the explicit `reserved` field) find this
   story.
2. ✅ [`PLAN_rar5_decoder.md`](PLAN_rar5_decoder.md) §F1
   now carries a "Postmortem note" linking here so the next
   reader knows F1 wasn't the bug — F1 was the trigger that
   surfaced an uninitialized-memory bug latent in
   `MacosPuncher` since it shipped.
3. **No** `OPTIMIZATIONS.md` entry: the fix is a structural
   correctness change, not a performance tradeoff.

**Status**: ✅ landed.

## What the original plan got wrong

For honesty, the discarded hypotheses (preserved here for
future contributors who may chase similar symptoms):

- ❌ "APFS `F_PUNCHHOLE` returns EINVAL when there are
  pending dirty pages elsewhere in the file." False — APFS
  does not validate that. Plain `fsync`/`F_FULLFSYNC` calls
  before the punch had no effect on the actual bug.
- ❌ "The 2 ms `thread::sleep` before each punch fixes it
  deterministically." Misleading: the sleep changed code-gen
  layout, which incidentally zeroed the padding bytes. Sleeps
  inside the puncher's retry loop did not fix it because they
  did not change the padding.
- ❌ "The `0x10000` bit on the fd's `F_GETFL` output is
  `FNOCACHE` and that's what's blocking the punch." The bit
  is set by `ftruncate(2)`, but it's an internal `FFCNTL`
  bookkeeping flag, not `FNOCACHE` (FNOCACHE = `0x40000` per
  empirical probe in the macOS 26.4 SDK). The bit had nothing
  to do with the EINVAL; the per-fd disparity was an artifact
  of which stack frame the syscall was made from.

## Hard constraints (carried forward)

- `MacosPuncher` stays std-lib-only (no new runtime deps).
- `EOPNOTSUPP` / `ENOTSUP` continue to surface as
  `PunchError::Unsupported` so the coordinator's downgrade
  path stays intact.
- `EINVAL` continues to map to `PunchError::Unsupported` —
  with the layout fix in place, EINVAL now indicates a
  genuinely unsupported filesystem rather than our own
  malformed argument. (If it ever fires on APFS again, that
  *would* be an Apple bug; the place to look first is whether
  `Fpunchhole`'s field set still matches the SDK header.)
