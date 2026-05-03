# Plan: diagnose and address decoder/sink freeze

> **Status:** drafted 2026-05-02 in response to a fresh occurrence of
> the decoder/sink freeze in the snapshot-restore pod (4 TiB
> `.tar.zst` over R2).
>
> This is a *follow-on* to `PLAN_responsiveness.md` Phase 3. Phase 1 of
> that plan landed the lookahead/`decoded_in` counters and the stall
> heartbeat; Phase 2 made the kill switch reachable from inside the
> read poll. Phase 3 closed the corruption gap that produced the
> earlier silent stalls. The freeze documented here is **a different
> failure mode** that the new instrumentation surfaced but did not
> resolve, and it points at the IO layer rather than the source bytes.

The same sequencing discipline as `PLAN.md` / `PLAN_v2.md` /
`PLAN_responsiveness.md` applies: each phase ends with a runnable
demo, and §N+1 does not begin until §N's demo passes. Standards
(`ENGINEERING_STANDARDS.md`) and agent rules (`AGENTS.md`) are
unchanged.

---

## Symptom analysis

Key excerpts from the captured run (timestamps elided):

```
progress: 12.5% download 477.0 GiB @ 48.0 MiB/s extract 885.3 GiB @ 76.7 MiB/s
         lookahead 1.1 GiB / 1.0 GiB cap  decoded_in 475.5 GiB
         workers 0/4  bottleneck=disk
...
WARN pipeline frozen, no counters advanced in 30s
     decoder at byte 511130468352, sink at byte 951714971648
```

After this point `bytes_downloaded`, `bytes_decoded_input`, and
`bytes_extracted` are all flat forever and the run never recovers
on its own. SIGTERM brings it down promptly (Phase 2 of
`PLAN_responsiveness.md` is doing its job); restarting from the
durable checkpoint resumes at the same byte position and runs
cleanly.

Reading the sequence:

- **Lookahead grows under `bottleneck=net`** during the steady-state
  window before the freeze. By definition, lookahead growing means
  the download rate (compressed bytes/s into the part file) exceeds
  the decoder consumption rate (compressed bytes/s out of the part
  file). The classifier disagrees because it compares download rate
  against the *uncompressed* extract rate scaled by an
  `extracted_estimate / total_size` ratio that defaults to `1.0`
  when the extracted size is unknown
  ([progress.rs:487](src/progress.rs#L487)). The classifier is
  lying: the decoder is the slow side.
- **Decoder and sink freeze at the same instant.** This is consistent
  with a single-threaded blocker inside `decode_step`
  ([extractor.rs:437](src/extractor.rs#L437)): if the decoder is
  parked inside a source `pread` or a sink `write_all`, no further
  bytes flow through *either* counter. The two counters look
  independent in the renderer; they are not.
- **All file/network IO funnels through one io_uring ring.** Part-file
  pwrite (workers), part-file pread (decoder via
  `BlockingSparseReader` →
  `sparse.read_at` →
  `backend.pread_at`,
  [sparse_file.rs:449](src/download/sparse_file.rs#L449)),
  HTTP socket recv/send
  ([uring.rs:285-310](src/io_backend/uring.rs#L285-L310)) — all
  share one `mpsc::sync_channel(depth)` and one IO thread
  ([uring.rs:128-137](src/io_backend/uring.rs#L128-L137)). The tar
  sink is the only IO path that bypasses io_uring
  ([sink/tar.rs:406](src/sink/tar.rs#L406) — direct
  `std::fs::File::write_all`).
- **A fresh process resumes cleanly** at the same byte offset that
  the wedged process never advanced past. That rules out
  on-disk corruption (cf. `PLAN_responsiveness.md` Phase 3) and
  points at in-memory state — most likely io_uring tracker /
  completion bookkeeping, since `Drop` of the `UringBackend` drains
  in-flight ops ([uring.rs:605-613](src/io_backend/uring.rs#L605-L613))
  and a restart guarantees a fresh ring.

So the working hypothesis is: **a `pread_at` against the part file
never gets its CQE delivered (or its completion notification never
fires), the decoder is parked inside `BlockingSparseReader::read`
forever, and what the operator sees as "decoder + sink froze
together" is one site (the pread) starving both counters.** The
hypothesis is not yet proven — we have no in-flight-age data and
no `decode_step`-duration data. The plan below is structured around
**proving or disproving the hypothesis with cheap instrumentation
first**, then acting on what the instrumentation shows.

---

## Hard constraints (carried forward)

- Std-first; no new dependencies without explicit approval per
  `ENGINEERING_STANDARDS.md` §2. Everything below is achievable
  with what is already on the allowlist.
- No async runtime. The IO thread loop is the only thread that
  needs added bookkeeping; it stays single-threaded.
- Backwards-compatible checkpoints. Nothing here grows the
  `Checkpoint` schema; `format_version` does not change.
- No new public CLI flags unless a phase calls one out and gets
  approval first. Diagnostic knobs go through env vars (matching
  the existing `PEEL_STALL_WARN_INTERVAL_SECS` pattern).

---

## Phase 1 — fix the bottleneck classifier

The `bottleneck=net` label was actively misleading during the
window before the freeze. Until we trust the badge, every later
phase has to second-guess "was that really the bottleneck the
classifier said it was?" Fix this first, both because it is
small and because it gives every subsequent debugging session a
faithful one-glance signal.

### §1.1 Compare compressed-side rates instead of mixing units

**What.** `classify_bottleneck` at
[progress.rs:487](src/progress.rs#L487) currently compares
`dl_rate` (compressed bytes/s) against
`ex_rate / ratio` where `ratio = extracted_estimate /
total_size` falls back to `1.0` if either is unknown. The fallback
is wrong for any compressed format and especially wrong for `.zst`
(typical 2× ratio) or anything denser. The faithful comparison
is "compressed bytes flowing into the part file" vs "compressed
bytes flowing out of the part file" — i.e., `bytes_downloaded`
rate vs `bytes_decoded_input` rate. Both are already published on
`ProgressState`; the snapshot already carries `bytes_decoded_input`.

Rework the classifier so:

- The disk-throttle short-circuit at
  [progress.rs:492](src/progress.rs#L492) stays — `disk_bound`
  remains the highest-priority signal.
- Otherwise, compare `dl_rate` against the *decoded-input* rate.
  We need a `RateBuffer` for `bytes_decoded_input` alongside the
  existing two. Wire it through `TtyRenderer` and `JsonRenderer`
  the same way the download/extract rate buffers are wired.
- Keep the 10% deadband and the "neither side has enough samples
  yet → `None`" case.

The extract rate stays in the *display* (it is what the operator
actually wants to see for ETA on the user-facing side), but it
no longer drives the badge.

**Why first.** The freeze investigation has us reading the badge
on every renderer tick. With the current logic, "lookahead growing
while the badge says `net`" is an internal contradiction we have
to mentally correct for. After this phase the badge means what it
says.

**Tests.**
- Unit test in `progress.rs`: snapshot with `bytes_downloaded`
  rate 80 MiB/s and `bytes_decoded_input` rate 40 MiB/s →
  `Bottleneck::Disk`. Reverse → `Bottleneck::Network`. Within 10%
  → `None`.
- Unit test: `disk_bound = true` always wins, regardless of rates.
- Update any existing tests that fed `ex_rate` into
  `classify_bottleneck` to use the new signature.

**Demo.** Run the snapshot-restore pod with the new build.
Capture log lines from the steady-state window before the freeze.
Verify the badge reads `disk` (or `None`) when `lookahead` is
trending up, and `net` only when `decoded_in` is keeping up
with `download`.

---

## Phase 2 — prove or disprove the io_uring stall hypothesis

We do not have direct evidence that a CQE is being lost. Before
we touch the IO backend or the extractor for any kind of
fix-or-restart, add the two cheap signals that would localise
the wedge to a specific layer. Both are pure observability —
no behavioural change.

### §2.1 Per-op in-flight age warning in the io_uring thread

**What.** In `io_thread_loop`
([uring.rs:628](src/io_backend/uring.rs#L628)), give every
`InFlight` a `submitted_at: Instant`. After each
`submit_and_wait` returns and the CQE drain finishes, walk
`tracker.map` and log a `tracing::warn!` for any in-flight whose
age exceeds `PEEL_URING_INFLIGHT_WARN_SECS` (default 30 s,
matching `STALL_WARN_INTERVAL`). Rate-limit one warn per op per
warn-interval — same one-line-per-window discipline the stall
detector uses
([progress.rs:843](src/progress.rs#L843)). The warn line carries
`OpKind`, `fd`, `base_offset`, `total_len`, `bytes_done`, and
the age in seconds.

**Why.** If the freeze is "a CQE was lost," this fires within
one warn-interval and tells us which op (and on which fd) is
stuck. If it does *not* fire across a freeze, the IO thread is
draining CQEs fine and the wedge is elsewhere.

**Tests.**
- Unit test the age-walk logic in isolation: feed a synthetic
  `InFlightTracker` with one entry whose `submitted_at` is
  60 s old and another at 5 s; assert the walker yields exactly
  the first.
- Existing io_uring tests should be untouched by adding a field
  and a periodic walk; verify the integration tests under
  `tests/` still pass.

**Demo.** Reproduce the freeze (or wait for the next one). Confirm
the `WARN io_uring op stalled …` line fires within 30 s of the
existing `pipeline frozen` line, and identifies an op against the
part-file fd. If it does not fire, document that and proceed to
§2.2 — the wedge is not the ring.

### §2.2 `decode_step` duration watchdog in the extractor

**What.** Wrap each `decode_step` call in `Extractor::run_loop`
([extractor.rs:437](src/extractor.rs#L437)) with a "started at"
`Instant`. Before re-entering the loop body for the next call,
if the *previous* step took more than
`PEEL_DECODE_STEP_WARN_SECS` (default 30 s), emit one
`tracing::warn!` with `bytes_consumed`, `bytes_out`, the elapsed
duration, and a hint at the inner state if cheap to expose
(e.g., the decoder's `bytes_consumed` delta — was the step
reading source, producing output, or neither?).

This is a *post-hoc* watchdog, not a preemption — we cannot
unblock a step from a thread we do not own. It is just enough
to answer "where in the loop is the run wedged?": if the warn
fires on the freeze, the wedge is inside `decode_step`. If it
*never* fires (because `decode_step` keeps returning), the
wedge is somewhere else (sink? checkpoint observer? puncher?).

**Why.** Pinpoints which call site stalls without needing a
pstack on a wedged production pod. Composes cleanly with §2.1:
together they say "the step is wedged inside an io_uring op
older than N seconds against fd F at offset O" — a complete
diagnosis from logs alone.

**Tests.**
- Unit test in `extractor.rs`: a `StreamingDecoder` impl that
  sleeps 200 ms inside `decode_step`; with a 100 ms watchdog
  threshold, assert exactly one warn fires per step.
- Verify the watchdog does not fire on healthy steps (existing
  integration tests under `tests/`).

**Demo.** Reproduce. Confirm the `WARN decode_step exceeded
N s` line fires once per warn-interval during the freeze and
gives us `bytes_consumed`/`bytes_out` deltas. Cross-reference
with the §2.1 line.

### §2.3 Decision point — what does the data say?

This is not code; it is the gate that decides what Phase 3 looks
like.

After §2.1 + §2.2 land and we capture one freeze with both
warnings, **stop and read the data** before writing more code.

The branches:

- **Both warnings fire and §2.1 names a part-file pread.** The
  hypothesis is confirmed. Phase 3 becomes "make the io_uring
  layer survive a lost completion" — see §3a sketch below.
- **§2.2 fires but §2.1 does not.** The wedge is inside
  `decode_step` but not in the IO backend. Most likely candidates
  are the tar sink (`std::fs::File::write_all` at
  [sink/tar.rs:406](src/sink/tar.rs#L406) — kernel page-cache
  pressure, ENOSPC retry, fsync inside another fd) or a
  CPU-bound spin in the zstd decoder. Phase 3 becomes "narrow it
  further with sink-side timing."
- **Neither warning fires but the renderer still reports the
  freeze.** The wedge is between `decode_step` calls — the
  observer closure, the puncher, or the renderer's own state.
  Phase 3 becomes "instrument those sites." Lower probability,
  but possible.

**Demo.** Write up the captured warnings (one or two log
excerpts, no more) into a follow-up note appended to this plan.
Pick a Phase 3 branch and proceed.

---

## Phase 3a — survive a lost io_uring completion *(conditional on §2.3)*

Sketch only. Do not start until §2.3 selects this branch.

The current `Completion::wait`
([uring.rs:555](src/io_backend/uring.rs#L555)) is an unbounded
condvar wait. There is no per-op timeout for file ops
(`timeout_ns = 0` in the file paths at
[uring.rs:225-265](src/io_backend/uring.rs#L225-L265)) — the
linked-timeout machinery only kicks in for sockets. If a CQE for
a file op is dropped, the calling thread waits forever and the
ring's in-flight slot is never released.

Two ways to address this, in increasing order of invasiveness:

1. **Timed `wait`s for file ops.** Add a `wait_timeout` to
   `Completion` and use it from the file-IO entry points with a
   generous bound (e.g., 60 s) — far longer than any healthy
   `pread`/`pwrite` against a local fs would ever take, but
   short enough to surface the bug as a typed error instead of
   a deadlock. The error path turns into a typed
   `BackendError::CompletionTimeout` that the worker /
   `BlockingSparseReader` returns as an `io::Error`. Workers
   already retry transient IO via the existing retry config; the
   reader path needs to fail loudly so the outer-retry loop
   restarts the run.
2. **Add LinkTimeouts to file ops.** Mirror what sockets already
   do: every file op submits with `IO_LINK + LinkTimeout`. The
   kernel cancels the op with `-ECANCELED` if the timeout fires
   and we get a CQE back through the existing handler. Heavier
   plumbing than (1) but solves the failure at its source — the
   tracker entry is removed by the kernel's CQE.

(1) is the smaller change and probably the right starting point;
(2) is a defensible follow-on if the operations team would
prefer kernel-level enforcement. Either way the concrete fix
shape lives in §2.3's note, not here.

---

## Phase 3b — surface a wedged extractor as a retry trigger *(conditional on §2.3)*

Sketch only. Do not start until §2.3 selects this branch.

If the wedge is somewhere we cannot easily un-wedge (e.g., a
genuinely stuck `write_all` on a backing filesystem we do not
control), the right answer is the auto-restart originally
proposed: **after `StallDetector::tick` returns
`Warned(PipelineFrozen)` for `RESTART_AFTER_STALL_WINDOWS` (≥ 2)
consecutive windows, trip the run-wide kill switch with a typed
`CoordinatorError::PipelineFrozen`**. The outer-retry loop in
`run_with_outer_retry`
([main.rs:604](src/main.rs#L604)) restarts from checkpoint —
exactly what the operator does manually today.

Two design points worth flagging now so the implementation goes
smoothly when we get here:

- **Classify `PipelineFrozen` as retryable.** The
  `is_retryable_run_error` matcher at
  [main.rs:646](src/main.rs#L646) currently walks for
  `SchedulerError`/`WorkerError`. Add a top-level branch for the
  new variant.
- **Bound the consecutive-window count.** A single 30 s warning
  is too aggressive (some legitimately long writes happen), but
  more than 2 windows means we waste minutes on every restart.
  Suggest `RESTART_AFTER_STALL_WINDOWS = 2` (≈ 60 s of frozen
  state) with an env override for tuning.

---

## What is *not* in this plan

- **Bypassing io_uring for the part-file path.** The hypothesis is
  not yet confirmed; falling back to the blocking backend
  permanently would lose the §7.2 throughput win. If §2.3
  selects Phase 3a, the fix is *inside* the io_uring layer.
- **Replacing the tar sink's direct `write_all` with io_uring.**
  Out of scope. If §2.3 implicates the sink, the fix is timing
  and observability around the existing call site, not a wholesale
  IO-backend swap.
- **CLI flags for the new diagnostics.** Env vars match what
  Phase 1.2 of `PLAN_responsiveness.md` already established.
  Promotion to flags is a separate plan if the operations team
  asks for it.
- **Changes to the `Checkpoint` schema.** None needed; the durable
  state already lets a fresh process resume losslessly.

---

## Phase ordering and "done" criteria

| Phase | Done when                                                                 |
|-------|---------------------------------------------------------------------------|
| 1     | Classifier badge agrees with the lookahead trend in the steady-state log; new unit tests pass. |
| 2.1   | Per-op in-flight warn line fires in a synthetic test and in production at the next freeze. |
| 2.2   | `decode_step` watchdog warn line fires in a synthetic test and at the next freeze. |
| 2.3   | Captured production freeze has been triaged into one of the three branches; the chosen branch is appended to this plan as a follow-up note. |
| 3a/3b | Per the branch selected in §2.3.                                          |

Do not start §2.3's chosen branch (3a or 3b) without that
follow-up note in this file. The whole point of Phase 2 is to
**not** burn implementation effort on a hypothesis we have not
verified.
