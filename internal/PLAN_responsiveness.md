# Plan: signal responsiveness + stall observability

> **Status:** drafted 2026-05-02 in response to two bugs observed in the
> snapshot-restore pod (4 TiB `.tar.zst` over R2):
>
> 1. **SIGTERM is ignored** — `kubectl delete pod` hangs through the
>    full grace period; only `--force` releases the pod. After kill,
>    resume succeeds.
> 2. **Download stalls silently** — after resume the download runs at
>    ~50 MiB/s for ~20 s, then drops to 0 B/s with `bottleneck=disk`
>    and `workers 0/4`, while `extract … @ 0 B/s` the entire time. No
>    error is logged.
>
> **Update 2026-05-02 (later that day).** The third resume of the
> same pod failed loudly with:
>
> ```
> decoder failed after consuming 431903887362 bytes from source
> zstd: block size 1277792 exceeds RFC 8478 cap of 131072 bytes
> ```
>
> That offset is **55,815 bytes past** the resume cursor
> (`decoder_position=431903831547`, chunk index 103228). So the
> "silent stall" of bug 2 is almost certainly the *prelude* to the
> same corruption — the decoder hit malformed bytes, spun without
> reading enough source to advance past the bad block, and only on
> the next resume (at a slightly different offset) surfaced the
> typed `DecodeError`. That reframes the work: bug 1 is real and
> still needs Phase 2; bug 2 is a **source-data integrity bug that
> looked like a stall because we couldn't see far enough into the
> pipeline**. Phase 3 below is rewritten around that hypothesis.
>
> Both bugs trace to the same observability gap: long-running loops
> in the coordinator never poll the kill switch and never publish
> enough internal state for an operator (or this plan's author) to
> tell *why* progress stopped. This plan closes that gap, then
> uses the new signal — plus the typed error we now have — to
> root-cause the corruption.

The same sequencing discipline as `PLAN.md` / `PLAN_v2.md` applies:
each phase ends with a runnable demo, and §N+1 does not begin until
§N's demo passes. Standards (`internal/ENGINEERING_STANDARDS.md`) and
agent rules (`AGENTS.md`) are unchanged.

---

## Symptom analysis (what the logs tell us)

Key excerpts (timestamps elided):

```
[resume] checkpoint at /db/db.peel.ckpt
         decoder_position=431901149742 chunks=102974/976640
[start]  ... (4096322190237 bytes, 976640 chunks, resuming,
              102974 chunks already complete)
progress: 10.5%  download 402.3 GiB / 3.7 TiB @ 201.1 GiB/s
                 extract  746.0 GiB / unknown @ 373.0 GiB/s
                 workers 4/4  ETA 16s  bottleneck=net
progress: 10.6%  download 402.7 GiB / 3.7 TiB @ 52.1 MiB/s
                 extract  746.0 GiB / unknown @ 0 B/s
                 workers 4/4  ETA 18h37m
progress: 10.6%  download 403.2 GiB / 3.7 TiB @ 43.6 MiB/s
                 extract  746.0 GiB / unknown @ 0 B/s
                 workers 0/4  ETA 22h14m  bottleneck=disk
progress: 10.6%  download 403.2 GiB / 3.7 TiB @ 0 B/s
                 extract  746.0 GiB / unknown @ 0 B/s
                 workers 0/4  ETA --     bottleneck=disk   (forever)
```

Reading the sequence:

- The first `201.1 GiB/s` row is a startup artefact. On resume the
  coordinator pre-credits `bytes_downloaded` and `bytes_extracted`
  with the resumed counts at
  [coordinator.rs:728](src/coordinator.rs#L728) and
  [coordinator.rs:750](src/coordinator.rs#L750); the rate window
  treats that step as deliveries inside one tick. Cosmetic, not the
  cause.
- Real download then runs at ~50 MiB/s with all four workers active.
  `bytes_extracted` does **not** advance during this window — extract
  is at 746.0 GiB the whole time.
- After ~1 GiB of fresh download (402.3 GiB → 403.2 GiB), workers
  drop to 0/4 and `bottleneck=disk` appears. That is the configured
  `max_disk_buffer = 1 GiB` cap kicking in
  ([scheduler.rs:1168](src/download/scheduler.rs#L1168),
  [coordinator.rs:224](src/coordinator.rs#L224)): when
  `bytes_downloaded - bytes_decoded_input ≥ 1 GiB`, the scheduler
  stops dispatching.
- After throttle engages, **neither side advances**. `bytes_extracted`
  never moves; therefore `bytes_decoded_input` (set by
  `BlockingSparseReader::read` at
  [coordinator.rs:2189](src/coordinator.rs#L2189)) almost certainly
  never moves either; therefore the gap never shrinks; therefore the
  throttle never releases. Stable deadlock.
- During that deadlock SIGTERM is delivered. The handler at
  [main.rs:118](src/main.rs#L118) flips the `kill_switch` atomic, but
  the only sites that observe it
  ([coordinator.rs:1393](src/coordinator.rs#L1393),
  [coordinator.rs:1560](src/coordinator.rs#L1560)) live inside the
  checkpoint-observer closure, which is only called when the
  extractor reports a *quiescent frame boundary*. The extractor is
  blocked, so the observer never fires, so the kill switch is never
  read. Process stays alive until kubelet escalates to SIGKILL.
- After force-delete, the `.peel.ckpt` and `.peel.part` from the last
  observer firing are still durable on disk, so resume picks up. The
  user is then back in the same race a few seconds later — confirming
  the bug is reproducible.
- **The third resume surfaced `zstd: block size 1277792 exceeds RFC
  8478 cap of 131072 bytes` at consumed-offset 431,903,887,362** —
  resume cursor 431,903,831,547 plus 55,815 bytes. The ~55 KiB the
  decoder *did* consume after resume must therefore have been
  enough to read into a malformed block header but not enough to
  reach the next quiescent boundary. The earlier silent stalls
  were the same bad bytes hit in a slightly different state: the
  decoder kept calling `Read::read` on the source but couldn't
  produce output, so `bytes_decoded_input` advanced (slowly) but
  `bytes_extracted` did not, lookahead grew to `max_disk_buffer`,
  and the throttle locked the pipeline. The fact that each resume
  picked up a *slightly* different cursor (102974 → 103228) means
  some forward progress did land between checkpoints, but the
  underlying bad-byte region is reachable from each.

So the bug catalog is actually three things, not two:

- **Decoder hits bad source bytes** ⇒ surfaces as either a typed
  `DecodeError` (sometimes) or as a silent spin (when the decoder
  reads garbage that *looks* parseable but yields no output). This
  is the real bug — the corruption itself.
- **The spin variant is invisible** because the renderer doesn't
  expose `bytes_decoded_input` or the lookahead. Phase 1 fixes
  that — and would have let us see the error class on day one.
- **The kill switch is unreachable from inside the spin**, so the
  pod can't be told to stop politely. Phase 2 fixes that.

Phase 3 is then targeted at the corruption itself, with a much
narrower hypothesis space than "something stalls."

---

## Hard constraints (carried forward)

- Std-first; no new dependencies without explicit approval per
  `ENGINEERING_STANDARDS.md` §2. Everything below is achievable with
  what's already on the allowlist.
- No async runtime. Signal responsiveness is purely cooperative
  polling of `Arc<AtomicBool>` flags from existing threads.
- Backwards-compatible checkpoints. Nothing in this plan grows the
  `Checkpoint` schema, so `format_version` does not change.
- No new public CLI flags unless a phase calls one out and gets
  approval first.

---

## Phase 1 — surface the missing signals

We cannot diagnose the stall (or verify any fix) without a few
data points the renderer doesn't currently expose. This phase is
**read-only with respect to behavior** — it only adds visibility.

### §1.1 Render the lookahead and disk-buffer cap

**What.** Add a fourth counter to the TTY and log renderer:

```
lookahead 996.4 MiB / 1.0 GiB cap   decoded_in 402.4 GiB
```

`lookahead = bytes_downloaded - bytes_decoded_input` (already
computed by `ProgressState::lookahead_bytes` at
[progress.rs:177](src/progress.rs#L177)). The cap is already
published via `set_max_disk_buffer` at
[progress.rs:161](src/progress.rs#L161); the snapshot exposes it.

`decoded_in` is the running compressed-byte cursor — printing it
makes "is the decoder reading?" answerable from the log alone.
Today the user sees `extract … @ 0 B/s` and cannot tell whether
the decoder is reading source bytes (and just not producing
output yet) or wedged.

**Why first.** Every later phase justifies itself by what this
counter shows. If `decoded_in` does not advance during the stall
window, the decoder is stuck. If it advances slowly, the sink is
stuck. If it advances at the download rate, we have a different
bug entirely. We need this in the log before we touch anything.

**Demo.** Re-run the snapshot-restore pod with the new build.
Capture the log lines around the stall. Note whether `decoded_in`
is increasing, flat, or jittery. Attach the log to the §3 root-cause
ticket.

### §1.2 Heartbeat log when the renderer detects no progress

**What.** Inside the renderer tick (already running on its own
thread at 100 ms / 2 s cadence — see
[main.rs:253](src/main.rs#L253)), add a small state machine: if
*all three* of `bytes_downloaded`, `bytes_decoded_input`, and
`bytes_extracted` have not advanced for `STALL_WARN_INTERVAL`
(suggest 30 s; configurable via env, no CLI flag yet), emit a
single `tracing::warn!` line per warn-interval naming the
suspected stuck component:

- `download stalled, decoder at byte X (delta 0 in 30s)` if
  `bytes_decoded_input` is the one that hasn't moved while the
  scheduler is throttled.
- `extractor stalled, decoder consumed +Y bytes but sink wrote 0
  in 30s` if the decoder *is* reading but the sink is not
  producing.
- `pipeline frozen, no counters advanced in 30s` if both are
  flat.

The renderer already has the snapshot history (`rate_dl`,
`rate_ex` ring buffers in `progress.rs`); reuse them rather than
adding new buffers. Keep the warn rate-limited (one per
`STALL_WARN_INTERVAL`, not one per tick).

**Why.** Today the operator has to compare two log lines five
seconds apart and notice that `746.0 GiB` is identical — the
software should say so. In Kubernetes this also makes the
condition machine-readable for an alert.

**Demo.** Unit test that drives a `ProgressState` whose
`bytes_decoded_input` doesn't move for 35 s and asserts exactly
one warn line is captured. (Use `tracing-test` if it's already a
dev-dep, otherwise a small `tracing::Subscriber` impl in the
test module — no new deps.)

### §1.3 Per-component instrumented spans

**What.** Add `tracing::debug_span!` (gated behind `RUST_LOG=peel=debug`)
around the four call sites that can wedge:

- `BlockingSparseReader::read` poll loop
  ([coordinator.rs:2129](src/coordinator.rs#L2129))
- the decoder's `decode_step` call from `extractor.rs::run_loop`
  ([extractor.rs:354](src/extractor.rs#L354))
- the sink write inside `SinkAdapter::write` (find via grep:
  `impl Write for SinkAdapter`)
- the punch syscall in `Extractor::maybe_punch`

Each span carries the local cursor / counter. With `RUST_LOG`
enabled and the §1.2 stall warning firing, the operator can pick
the matching span and see which one was last entered.

**Why now.** This is cheap (`debug` level is compiled in but
filtered out by default) and makes §3's root-cause work
mechanical.

**Demo.** A test run with `RUST_LOG=peel=debug` against a small
`.tar.zst` shows all four spans firing on a normal extraction;
no behavior regression at `RUST_LOG=info` (the default).

---

## Phase 2 — make the kill switch actually observable

The signal handler already does the right thing. The bug is that
nothing reads its flag during a stall.

### §2.1 Poll the kill switch from `BlockingSparseReader::read`

**What.** Inside the `loop` at
[coordinator.rs:2131](src/coordinator.rs#L2131), check the kill
switch (a) immediately on entry and (b) before each
`thread::sleep(self.poll_interval)`. On observed kill, return
`io::Error::other(KILL_SENTINEL)` — same sentinel string used by
the checkpoint observer at
[coordinator.rs:1395](src/coordinator.rs#L1395) — so
`run_one`'s outer `match` already maps it to
`CoordinatorError::Aborted`.

Plumb a `Option<Arc<AtomicBool>>` field into
`BlockingSparseReader` alongside `progress_state` (an additional
`with_kill_switch` builder method, mirroring `with_progress` at
[coordinator.rs:2119](src/coordinator.rs#L2119)). Wire it from
the existing `kill_switch.as_ref()` plumbing in
[coordinator.rs:907](src/coordinator.rs#L907) and below.

**Why.** This is *the* fix for the hung-pod case. Even if the
decoder is wedged inside a long internal computation, it almost
always reads source bytes between work units; a kill check at the
read boundary will trip on the first of those reads. For the
fully-frozen case (decoder spinning without reading) we still
need §2.2.

**Demo.** Integration test: spawn `coordinator::run` against a
fixture archive whose download pauses at chunk N (use the
existing test harness in `tests/test_coordinator_crash.rs` as a
template). After the run is wedged in the read poll loop for ≥1 s,
flip the kill switch from the test thread. Assert the run returns
`CoordinatorError::Aborted` within the next `reader_poll_interval`
(5 ms × small constant).

### §2.2 Poll the kill switch from `sniff_prefix`

Same shape as §2.1, applied to the loop at
[coordinator.rs:2326](src/coordinator.rs#L2326). Sniff happens
once at startup, but if chunk 0 is slow to arrive (cold connect,
TLS handshake hiccup) a SIGTERM during sniff has the same hang
the user reported. Cheap to fix at the same time.

### §2.3 Poll the kill switch from the inner extractor loop

**What.** In `Extractor::run_loop` at
[extractor.rs:348](src/extractor.rs#L348), check the kill switch
once per loop iteration (top of the loop, before `decode_step`).
This requires extending `Extractor` with an optional kill-switch
the same way it already carries an optional `ProgressState`
([extractor.rs:213](src/extractor.rs#L213)). Tripping returns
`ExtractorError::Observer` carrying the sentinel.

**Why.** §2.1 catches stalls that read source bytes; §2.3 catches
the pathological case where the decoder makes one CPU-bound
iteration that doesn't touch the source (e.g., a zstd block whose
literals are entirely in-window). One extra atomic load per
`decode_step` is well below noise.

**Demo.** Unit test: a `StreamingDecoder` mock that returns
`DecodeStatus::More` indefinitely without reading. Without the
kill-switch poll the test deadlocks (run with
`#[should_panic(expected = "deadlock")]` plus a timeout
helper); with the poll, flipping the flag returns `Aborted`
within one iteration.

### §2.4 Bound the graceful path

**What.** In `main.rs`, after the first signal flips the switch,
arm a watchdog thread that calls `_exit(128 + sig)` if
`run` has not returned within `GRACEFUL_DEADLINE` (suggest 30 s).
This is a belt-and-suspenders for any kill-switch poll site we
*didn't* think of: the user gets graceful behaviour when it's
working and a hard bound on how long they wait when it isn't.

The current code already escalates on a *second* signal
([main.rs:153](src/main.rs#L153)); the watchdog gives the same
guarantee without requiring a second `kubectl delete pod`.

**Why.** Pods that take >30 s to terminate are themselves a
production problem (Kubernetes considers them stuck). 30 s is well
under the typical 60–120 s `terminationGracePeriodSeconds`, so
checkpoint-during-graceful still has time to land if the run is
genuinely making progress.

**Demo.** Integration test that installs a panicking-on-second-poll
mock and asserts the watchdog fires within ~30 s.

---

## Phase 3 — root-cause the source-byte corruption

The third-resume error narrows §3 dramatically. We are no longer
looking at "something is stalling somewhere"; we have a specific
typed assertion firing at a specific source offset. The
investigation is a sequence of *integrity checks* that each
isolate one possible cause.

The error site itself is
[decode/zstd/block.rs](src/decode/zstd/block.rs) (search for the
`exceeds RFC 8478 cap` literal). When that fires, the bytes the
decoder just read at offset `431,903,887,362` parsed as a
`Compressed_Block` header whose 21-bit size field decoded to
`1,277,792`. RFC 8478 §3.1.1.2 caps it at `min(Window_Size,
128 KiB)`. Either:

- **(a)** the bytes on disk at that offset don't match what R2
  served (corruption between download and read), or
- **(b)** the bytes on disk *do* match R2 but the decoder is
  parsing them at the wrong offset (resume seam misalignment), or
- **(c)** R2 itself served different bytes for the same range
  across the run's lifetime (object change / cache split).

Phase 3 walks down that list. Each step is cheap and rules out
one cause cleanly.

### §3.1 Audit the resume cursor's relationship to the bitmap

**What.** Add a debug-only one-shot self-check on resume that
verifies, for the chunk containing `decoder_position`:

1. The chunk is marked complete in the loaded bitmap.
2. The chunk has a recorded CRC-32C fingerprint
   ([download/chunk_fingerprints.rs](src/download/chunk_fingerprints.rs)).
3. Re-CRC the on-disk bytes for that chunk and compare against
   the stored fingerprint.

If (3) mismatches we have on-disk corruption, full stop — go to
§3.3. If it matches we have either resume-seam misalignment or
upstream drift; continue to §3.2.

The §11 resume probe ([coordinator.rs:703](src/coordinator.rs#L703))
already re-fetches *one random complete chunk* and compares. It
does *not* check the chunk that holds the cursor — and that's
exactly the chunk most likely to be the suspect. Extending the
probe to always include `chunk_idx(decoder_position)` is a
one-liner.

**Demo.** Force-corrupt one byte in the resume chunk of a fixture
`.peel.part` and confirm the new probe rejects with
`SourceChangedSinceCheckpoint` (or a new
`PartFileCorrupted`-flavoured error) within the first second of
the run.

### §3.2 Audit the decoder_state resume seam

**What.** When the checkpoint stores a non-empty
`decoder_state` blob, the resume path at
[coordinator.rs:969](src/coordinator.rs#L969) calls the registry's
`resume_factory` (zstd's lives in
[decode/zstd/resume.rs](src/decode/zstd/resume.rs)) with the
blob and `start_offset = decoder_position`. The decoder is
expected to consume the *exact* source bytes that the original
run consumed at that offset and produce byte-identical output.

Two failure modes are worth instrumenting before changing
anything:

1. **Off-by-one on the source cursor at resume.** If the seed
   offset disagrees with the source reader's start by even one
   byte, the very next block-header parse will read garbage. Add
   an assertion at `resume()` entry that the supplied
   `start_offset` equals what the stored blob *expects* — and
   wire that back to a typed `DecodeError::ResumeMismatch` rather
   than letting it surface as a "block size too large" further
   downstream.
2. **State-blob version drift.** If a previous run wrote a v5
   blob and a newer binary reads it expecting a different layout,
   the decoder will mis-restore. The blob is opaque to
   `Checkpoint`, so this isn't policed today.
   `decode/zstd/resume.rs` should embed a magic/version prefix
   and reject reads that don't match.

If the corruption only reproduces across a binary upgrade, this
is the cause; otherwise rule it out.

**Demo.** Property test that takes any fixture archive, runs it
to a checkpoint, simulates a SIGKILL, resumes from the saved
state, and asserts the resumed run's output equals the
single-shot output byte-for-byte. Run with
`PEEL_FUZZ_RESUME_SEEDS=200` (env-gated; default off in CI).

### §3.3 Audit the worker write/sync ordering

**What.** A chunk worker writes the body via the
sparse-file `pwrite_at` ([download/sparse_file.rs](src/download/sparse_file.rs))
and reports completion. The scheduler then marks the chunk in
`bitmap` ([scheduler.rs:1043](src/download/scheduler.rs#L1043))
and records its CRC. The checkpoint observer later calls
`sparse.sync_all()` ([coordinator.rs:1404](src/coordinator.rs#L1404))
**before** writing the checkpoint, so anything in the snapshot
bitmap should be durable. Verify each link of that chain:

1. Does `pwrite_at` actually flush the page cache, or does it
   need an explicit `fdatasync` per chunk for the io_uring
   backend? See [io_backend/uring.rs](src/io_backend/uring.rs).
   A bug here would explain why the bytes near the cursor (the
   *latest* writes before the SIGKILL) are corrupted.
2. Is there any window where `bitmap.complete_range` runs before
   `pwrite_at` returns? Read the worker's completion path end to
   end and write the ordering down in a comment if it turns out
   to be correct.
3. Does the in-flight CRC match the on-disk CRC? Add a debug
   assertion that re-reads each chunk before marking complete and
   verifies. This is expensive but bounded; gate it on
   `RUST_LOG=peel::download=trace` or a `PEEL_VERIFY_CHUNKS=1`
   env var so it's available for the next pod incident without
   shipping it on by default.

**Demo.** A test that fault-injects a "pwrite reports success but
last 4 KiB is zeros" scenario and confirms the §3.3 guard
catches it before the chunk is marked complete in the bitmap.

### §3.4 Add a "verify-on-resume" mode

**What.** Add an opt-in `--verify-on-resume` CLI flag (off by
default; this is per-AGENTS.md "ask before adding flags" so the
flag itself needs sign-off) that, when set, walks the resumed
bitmap and re-CRCs every chunk against the stored fingerprints.
Slower startup, but turns "is the part file corrupted?" from a
debugging exercise into a one-flag answer. For the
snapshot-restore pod with a 4 TiB archive this is hours of disk
read at startup, so it must remain opt-in.

**Why.** Even after §3.1–§3.3 fix the immediate cause, this gives
operators a recovery path on the next time something weird
happens — which, given the size of these archives, will be a
matter of when not if.

### §3.5 Reproducer + fix

Once one of §3.1–§3.3 has identified the cause, build a small
local reproducer (a few-GiB `.tar.zst`, fault-injected
appropriately) and the fix. Resist the urge to "fix" speculatively
before then — the cost of iterating against the 4 TiB R2 archive
is high, and a wrong patch will stall on the same byte under
slightly different conditions.

### §3.6 Document the integrity contract

Whatever the root cause, end the phase by writing a short
"Integrity invariants" section in `coordinator.rs`'s module docs
covering:

- What it means for a chunk to be in `bitmap` (durable on disk
  with bytes matching its fingerprint, after the most recent
  `sync_all`).
- What `decoder_position` guarantees about the chunk that
  contains it.
- What happens to the bitmap and `.peel.part` after a SIGKILL.
- The `max_disk_buffer` math: what `bytes_downloaded -
  bytes_decoded_input` means in steady state vs. immediately
  after resume (this is silent and easy to get wrong today, which
  is why I had to derive it from the log to write this plan).

---

## What is *not* in this plan

- Replacing the disk-buffer throttle with a smarter scheduler, or
  removing it. The throttle is doing its job (bounding the on-disk
  footprint); the bug is downstream.
- Switching from `signal(2)` + `AtomicBool` to a self-pipe / signalfd.
  The current setup is fine once §2 lands.
- Auto-resume on stall (the run kills itself and re-execs). That's
  a band-aid, and it would mask whichever root cause §3 will find.
- Anything from `OPTIMIZATIONS.md` or `PLAN_v2.md` §A/§B that hasn't
  already shipped. Those plans stand.

---

## Phase ordering and "done" criteria

```
§1.1 ─┬─► §1.2 ─► §1.3
      │
§2.1 ─┴─► §2.2 ─► §2.3 ─► §2.4
                                   ↓
                                  §3.1 ─► §3.2 ─► §3.3
```

§1 and §2 can land in parallel (they touch different files). §3
strictly follows.

"Round done" means:

- A snapshot-restore pod hit by SIGTERM exits in <30 s, every time.
- A stalled run logs a structured warning naming the stuck
  component within 30 s of the stall, **and** prints the
  decoder's source cursor on every progress tick so a corrupted
  region is immediately visible.
- The reproducer from §3.5 runs to completion under the fix.
- A re-run of the snapshot-restore pod against the same R2 URL
  either completes or fails with a typed
  `PartFileCorrupted` / `SourceChangedSinceCheckpoint` /
  `ResumeMismatch` error within seconds of resume — never silent.
- All `cargo test`, `cargo clippy -- -D warnings`, and the
  `--ignored` long-running tests pass on the same commit.
