# PLAN — Close the bench-grid raw rows by buffering the sink/source boundary

**Status**: Phases 0, 1, 2, 4 shipped (2026-05-13). Phase 3 skipped
— the Phase 0 anchor bench measured `Xxh64::update` at ~23 GiB/s on
M4 Max (vs. the plan narrative's ~3 GB/s estimate), so the Phase 3
SWAR work was filed against
[`internal/OPTIMIZATIONS.md`](OPTIMIZATIONS.md#orawxxh64swar-xxh64-swar--simd-update-loop)
instead of pursued. Bench grid (median-of-5, log at
`internal/bench-results/decode-local-grid-mac-m4max-2026-05-13-post-raw-medians.txt`)
confirms `gz-raw` 100 MiB · warm 1.82× → **1.45×** (peel wall
77 ms → 60 ms) and `zstd-raw` 100 MiB · warm 1.61× → **1.28×**
(peel wall 63 ms → 38 ms). Peel CPU on both rows is at parity with
the reference CLI; the residual ratio gap is peel's ~30 ms
subprocess startup vs the reference's ~14 ms — outside this plan's
scope. The `tar.gz` 100 MiB · warm row got the same source-side
buffering for free, dropping 1.04× → 0.81×.
**Owner**: TBD.
**Promotes**: the README bench grid's `gz-raw` and `zstd-raw`
100 MiB · warm rows (1.82× and 1.61× today) and the surrounding
prose at [`README.md` L427-L436](../README.md#reading-the-grid).
**Sister plans**:
- [`internal/PLAN_gzip_throughput.md`](PLAN_gzip_throughput.md) — chased
  the same `tar.gz` row at 10 Gbps via DEFLATE-side levers
  (CRC32 slicing-by-16 shipped; parallel-member decode and DEFLATE
  inner-loop SIMD deferred). This plan attacks the **other half** of
  the gap that plan named: the per-byte framework overhead that sits
  on top of the decoder kernel. Acts before any further decoder
  micro-optimization because the profile says the decoder is **not**
  the bottleneck on the bench payload (incompressible LCG-random →
  DEFLATE STORED blocks → no Huffman inner loop runs).
- [`internal/old/PLAN_raw_tar_throughput.md`](old/PLAN_raw_tar_throughput.md)
  — characterized the same per-byte overhead for the 10 Gbps `tar`
  row over the network. Different code path (download + part-file
  double-hop) but the same diagnostic shape: the decoder is cheap;
  the framework is what costs.

## Why we're doing this

The decode-local bench grid
([`internal/bench-results/decode-local-grid-mac-m4max-2026-05-12-cli-subprocess.log`](bench-results/decode-local-grid-mac-m4max-2026-05-12-cli-subprocess.log))
100 MiB · warm cells:

| row        | peel wall | peel cpu | ref wall | ref cpu | ratio |
| ---------- | --------: | -------: | -------: | ------: | ----: |
| `gz-raw`   |    0.077s |   0.067s |   0.043s |  0.028s | **1.80×** |
| `tar.gz`   |    0.086s |   0.067s |   0.073s |  0.078s | 1.17× |
| `zstd-raw` |    0.063s |   0.021s |   0.036s |  0.025s | **1.61×** |
| `tar.zst`  |    0.036s |   0.022s |   0.074s |  0.086s | 0.49× |

Two facts to notice:

1. **peel's CPU is the same for each codec regardless of shape**
   (gz: 67 ms either way; zstd: 21 ms either way). peel does the
   same decode work in both rows. The ratio inversion between raw
   and tar shapes is a *denominator* effect — `gzip > file` is
   28 ms of system-CPU; `gzip | tar` is 78 ms because the pipe + tar
   process pays its own overhead. The tar rows look great because
   the reference is slower, not because peel is faster.
2. **The slow raw rows are not codec-bound.** A `samply` profile
   of `peel fixture.gz -o out.bin` on a 1 GiB LCG-random fixture
   (8 iterations, 4 kHz sampling) attributes self-time as:

   | self time | symbol |
   | -------: | --- |
   | **36.9 %** | `write` (libsystem_kernel.dylib) |
   | **26.1 %** | `read`  (libsystem_kernel.dylib) |
   | 18.6 % | `std::io::Write::write_all` (mod.rs:1877 — the loop around `write()`) |
   | 7.2 % | `_platform_memmove` |
   | ~5.8 % | DEFLATE inner loop + window append |

   The DEFLATE decoder itself is **~6 %** of self-time on the bench
   payload. The remaining ~94 % is syscalls, the wrappers around
   syscalls, and `memmove`. This is the worst-case shape for the
   current architecture: incompressible payload → DEFLATE
   STORED-only stream → each `decode_step` reads a 64 KiB block
   header + payload from the source and writes 64 KiB to the sink,
   1 GiB / 64 KiB = ~16 384 round trips, with the source-side
   `BitReader` pull buffer **fixed at 4 KiB**
   ([`deflate_native/bitstream.rs:57`](../src/decode/deflate_native/bitstream.rs#L57))
   so the *source* side gets re-`read()`-ed 16× more often than
   the sink gets written.

   Same shape for zstd-raw (1 GiB zstd-1 of random data, 16
   iterations, profile at
   `/tmp/peel-prof/zst_profile.json.gz`):

   | self time | symbol |
   | -------: | --- |
   | **43.2 %** | `write` (libsystem_kernel.dylib) |
   | **22.0 %** | `read`  (libsystem_kernel.dylib) |
   | 7.3 % | `_platform_memmove` |
   | **~14 %** | `peel::hash::xxh64::Xxh64::update` (sum of leaf samples) |
   | ~7.8 % | zstd window append |

   The zstd decoder itself barely registers (raw blocks copy-through);
   `xxh64::update` for the optional content checksum is the second
   biggest userspace consumer.

3. **What does *not* show up.** The DEFLATE CRC32 path
   (already slicing-by-16 from
   [`PLAN_gzip_throughput.md`](PLAN_gzip_throughput.md) Phase 1) is
   under the noise floor in both profiles. CRC is no longer
   load-bearing on these payloads.

The diagnosis is unambiguous: **the raw rows are dominated by
small-granularity syscall traffic at the sink and source seams.**
Closing them is a buffering problem, not a decoder problem.

## Hypothesis

Three independent levers, additive, in expected-impact order.

**Lever A — buffer sink writes on `RawSink`.**
[`src/sink/raw.rs:142-155`](../src/sink/raw.rs#L142-L155) is
unbuffered: every `decode_step` slice that lands in `RawSink::write`
becomes one `File::write_all` → one `write()` syscall. The DEFLATE
decoder hands the sink up to 64 KiB at a time (STORED block max,
per RFC 1951 §3.2.4 = `u16::MAX`); zstd hands up to 128 KiB at a
time (`BLOCK_MAX_SIZE`,
[`src/decode/zstd/block.rs:40`](../src/decode/zstd/block.rs#L40)).
Wrapping the underlying `File` in a 1 MiB `BufWriter` collapses
~16 writes into one for the gz row, ~8 into one for the zstd row.
On the profile that should drop the write-leaf share from ~37 %
to ~3 % and the `write_all`-wrapper share to near zero.

**Modeled impact:** the dominant per-byte cost on the bench
payload at the M4 Max page-cache write boundary is ~8 µs per
64 KiB `write(2)` (measured: 36.9 % of 480 ms × 8 iterations / 16 384
calls ≈ 9 µs/call). 1 MiB chunks cut the syscall count 16× while
the per-call cost rises sub-linearly (page-cache writes are
dominated by the kernel-side `memcpy` proportional to the
chunk length). Net: ~30 % wall-time saved on `gz-raw`,
~35 % on `zstd-raw`.

**Lever B — enlarge `deflate_native::bitstream::PULL_BUF_LEN`.**
[`src/decode/deflate_native/bitstream.rs:57`](../src/decode/deflate_native/bitstream.rs#L57)
sets the pull buffer to **4 KiB**. Every refill is one source
`read()`. On a 1 GiB STORED-heavy stream that is **~262 K
syscalls**. Bump to 256 KiB (a single VM page table entry on
ARM64 / a typical filesystem readahead unit) → 64× fewer refill
syscalls. On the profile that should drop the read-leaf share
from ~26 % to ~0.5 %. The 256 KiB buffer is ~6× the size of
the DEFLATE 32 KiB sliding window, so it cannot intermittently
fight cache lines with the window or the Huffman tables; same
posture as the xz Phase 1 buffer sizing landed in
[`PLAN_xz_throughput.md`](old/PLAN_xz_throughput.md).

The same lever applies to the zstd source-read path
([`src/decode/zstd.rs:189-211`](../src/decode/zstd.rs#L189-L211) —
`read_exact_into` issues one `read()` per field, including the
3-byte block header). Wrapping the source `Read` in a
`BufReader<R>` at the coordinator seam
([`src/coordinator/local.rs:740-765`](../src/coordinator/local.rs#L740-L765)
— between `ProgressReader` and the decoder) collapses the
header + payload reads into one syscall per refill, mirroring
Lever B for any non-DEFLATE codec that doesn't pull-buffer
internally (zstd, lz4, xz).

**Lever C — drop `xxh64` from the leaf on zstd-raw.**
The 14 %-of-self-time on `xxh64::update` is the optional content
checksum verification path. Two narrowly-scoped options:

- **C.1** Vectorize `Xxh64::update` (`src/hash/xxh64.rs`) using
  the 8-byte block scalar already present + a 32-byte block
  SWAR / AArch64 `uadalp` variant. Reference xxhash's SIMD path
  hits ~10 GB/s on M-series; current scalar is ~3 GB/s. ~3×
  microbench win, ~10 % wall-time saved on `zstd-raw`.
- **C.2** Skip `Xxh64::update` when the frame header carries no
  content-checksum bit
  ([RFC 8478 §3.1.1.1.1 `Content_Checksum_flag`](https://www.rfc-editor.org/rfc/rfc8478#section-3.1.1.1.1)).
  zstd at level 1 from the system `zstd` CLI **sets** the
  checksum bit by default, so this lever is conditional —
  archives that opt out get the win for free; archives that
  opt in still pay. Filed as the cheaper-to-implement
  baseline; C.1 is the actual lever.

C is the smaller lever and is the only one that touches the
zstd code path differently than gzip — A and B together should
take both rows close to their targets without C.

## Targets

- `gz-raw` 100 MiB · warm: **1.80× → ≤ 1.30×** (peel 77 ms →
  ≤ 56 ms vs `gzip` 43 ms).
- `zstd-raw` 100 MiB · warm: **1.61× → ≤ 1.30×** (peel 63 ms →
  ≤ 47 ms vs `zstd` 36 ms; warm-cell noise band on this row is
  ~10 ms based on the cold-vs-warm spread of 0.039–0.063 s, so
  the published number may bounce inside ≤ 1.20×–≤ 1.40×).
- `tar.gz` and `tar.zst` rows: **no regression** (they share the
  same sink-write path through `TarSink`; the change must keep
  the existing 0.49× / 1.17× cells).
- Lower-tier `gz-raw` / `zstd-raw` 10 MiB cells: no regression.
  These are dominated by process startup, not codec work; a
  larger BufWriter must not amortize badly enough to add
  measurable startup overhead.
- Decoder-only `bench_deflate_native_*` microbenches: no
  regression. The buffer change is on the sink/source side; the
  decoder kernel is untouched.

## Scope

### In scope (round one)

- **`RawSink` write buffering.**
  Wrap the inner `File` in `BufWriter<File>` with a 1 MiB
  capacity. `RawSink::write` forwards to `BufWriter::write_all`;
  `RawSink::close` calls `BufWriter::flush` before dropping the
  inner file. A new `RawSink::flush_for_checkpoint` method (or
  reuse of the existing `Sink::close` discipline — see Risks 1)
  flushes the buffer **before** every checkpoint commit so a
  `kill -9` between checkpoint and post-checkpoint write
  cannot lose buffered bytes. Wire the flush into the extractor's
  `on_checkpoint` hook
  ([`src/extractor.rs:823`](../src/extractor.rs#L823)).
- **DEFLATE pull-buffer bump.** Raise
  `PULL_BUF_LEN` from `4096` to `262144` in
  [`src/decode/deflate_native/bitstream.rs:57`](../src/decode/deflate_native/bitstream.rs#L57).
  The buffer is a `Box<[u8]>`, fixed-size; the field's only
  external invariants are `pull_pos <= pull_filled <=
  PULL_BUF_LEN`, all of which a numeric bump preserves.
  Resume-blob compatibility is preserved (the blob carries
  `acc`, `nbits`, `bytes_into_acc`, not the buffer contents
  — see `src/decode/deflate_native/resume.rs`).
- **Coordinator-side source `BufReader`.** Wrap the decoder's
  source `Read` in a 256 KiB `BufReader<R>` between the
  existing `ProgressReader` and the decoder factory in
  [`src/coordinator/local.rs:740-765`](../src/coordinator/local.rs#L740-L765).
  This benefits every format that doesn't pull-buffer
  internally (zstd, lz4, xz, gzip-when-fed-through-the-Read-API).
  The DEFLATE Lever B above is the per-format companion that
  also fixes the case where the decoder is used outside the
  coordinator (microbench, direct API).
- **`xxh64::update` SWAR.** Rewrite the inner loop of
  [`src/hash/xxh64.rs`](../src/hash/xxh64.rs)
  `Xxh64::update` to process 32-byte (4-lane) blocks via
  unrolled scalar multiply-add (matches xxhash's `XXH64_round`
  on the four parallel accumulators). No `unsafe`; LLVM
  auto-vectorizes the unrolled 4-lane form on AArch64 to
  `mul.4d` + `add.4d`. Differential test against
  `twox-hash`'s `XxHash64` over a 1 M random byte corpus at
  every prefix length; microbench target ≥ 3× scalar
  throughput on a 64 KiB buffer.
- **Bench grid refresh.** Re-run
  `bench_decode_local_grid` and update both the bench log
  and the README's "Wall-clock ratio" table.

### Deferred (out of round one)

- **`TarSink` write buffering.** `TarSink` already writes
  per-entry; the per-write granularity is whatever the
  decoder hands it. Profile post-A to see whether the
  same lever applies to `tar.gz` / `tar.zst` rows; if so,
  promote in round two. Out of scope only because the
  raw rows are the named gap.
- **`zstd::Decoder` internal pull buffer.** zstd reads via
  `read_exact_into` against the (now-buffered, post-B)
  source `Read`. An internal buffer is redundant once the
  coordinator wraps the source in a `BufReader`. Filed as
  contingent on a profile showing the wrapper isn't enough.
- **`Xxh64` skip when frame opts out of content checksum.**
  See Lever C.2 above. The default zstd CLI sets the
  checksum bit so the bench grid does not exercise the
  opt-out; promote only if a real corpus surfaces.
- **`io_uring` for the local raw path.** Linux-only; raw
  rows on macOS are the named gap. The blocking `pwrite`
  path is what the profile measures. Filed against
  [`internal/OPTIMIZATIONS.md`](OPTIMIZATIONS.md) if Linux
  raw rows show the same shape after A/B/C.
- **`splice(2)` / `copy_file_range(2)`-style zero-copy.**
  Both require source and destination to be on the same
  filesystem and require kernel support not available on
  the macOS bench host. Out of scope; same posture as
  [`PLAN_raw_tar_throughput.md`](old/PLAN_raw_tar_throughput.md)
  §Deferred.
- **`Write::write_vectored`.** A scatter-gather write could
  pass the decoder's window and the new bytes in one
  `writev(2)`. The DEFLATE path already coalesces into
  `decoded_buf` before flushing, so the gain is only the
  syscall count, which is the same as a `BufWriter` flush.
  Out of scope.

### Non-goals

- **Beating system `gzip` / `zstd` at codec throughput on
  compressible payloads.** The bench's incompressible payload
  is the worst case for syscall pressure; a compressible
  payload shifts the cost back into the decoder kernel.
  This plan does not chase that case. The `PLAN_gzip_throughput.md`
  §"Sub-plans demoted to follow-ons" DEFLATE-SIMD work is the
  right doc for that gap.
- **Resume-blob format changes.** The buffer sizing changes
  are runtime-only; no on-disk format change.
- **CLI surface changes.** All flags stay; defaults shift on
  the buffer sizes. No new flag to control the buffer (it's
  an implementation detail; expose later if a real workload
  asks for it).

## Approach

### Lever A — `RawSink` write buffering

```rust
// src/sink/raw.rs (sketch)
use std::io::{BufWriter, Write};

pub struct RawSink {
    path: PathBuf,
    file: Option<BufWriter<File>>,   // was: Option<File>
    bytes_written: u64,
}

impl Sink for RawSink {
    fn write(&mut self, buf: &[u8]) -> Result<(), SinkError> {
        let file = self.file.as_mut().ok_or_else(/* … */)?;
        file.write_all(buf).map_err(/* … */)?;
        self.bytes_written = self.bytes_written.saturating_add(buf.len() as u64);
        Ok(())
    }

    fn is_quiescent(&self) -> bool { true }
    // …

    fn close(mut self) -> Result<(), SinkError> {
        if let Some(mut bw) = self.file.take() {
            bw.flush()?;                  // surfaces deferred write errors
            bw.into_inner()?.sync_all()?; // optional fsync — match existing
        }
        Ok(())
    }
}
```

The capacity is a `const RAW_SINK_BUF: usize = 1 << 20` at the
top of the file. 1 MiB matches:

- The decoder's `OUTPUT_CHUNK = 1 MiB` cap (so the buffer
  holds one decode step's worth of output before flushing).
- The macOS APFS extent granularity (typical 1 MiB).
- The `--max-disk-buffer` default (so the buffer never bloats
  beyond the user-named memory budget).

**Checkpoint-time flush.** The current `RawSink::is_quiescent`
returns `true` unconditionally — every byte boundary is a valid
checkpoint because there's no parser state. With a `BufWriter`
in the way, "quiescent" still holds *for the parser*, but the
on-disk byte count lags the buffer. Two options, evaluated in
Phase 1:

1. **Flush on every checkpoint commit.** Add a
   `Sink::flush_durable` method (default: no-op; `RawSink`
   overrides to call `BufWriter::flush`) and have the
   extractor's checkpoint observer call it before
   `SinkState::Raw { bytes_written }` is serialized. Cost:
   one extra `flush` per checkpoint (~128 checkpoints/GiB,
   i.e. ~1 / 8 MiB) — adds one `write(2)` per 8 MiB of
   buffered output. Marginal.
2. **Track `bytes_durably_written` separately.** `RawSink`
   tracks `bytes_written` (in-flight including the buffer)
   and `bytes_durably_written` (post-flush). Checkpoint
   serializes the durable count; resume rewinds to it
   and truncates the file. Cost: more invariant juggling;
   no extra syscall.

Option 1 is the round-one default — simpler, one new method,
one extra syscall per ~8 MiB of output. Option 2 is filed as
a follow-on if the extra flush shows up in the post-A profile.

### Lever B — DEFLATE pull-buffer bump + coordinator BufReader

The deflate change is a single-line `const` bump in
[`src/decode/deflate_native/bitstream.rs:57`](../src/decode/deflate_native/bitstream.rs#L57).
The coordinator-side `BufReader` wrap goes between
`ProgressReader` and the decoder factory at
[`src/coordinator/local.rs:765`](../src/coordinator/local.rs#L765):

```rust
let reader: Box<dyn Read + Send> = {
    // … existing seek + ProgressReader wrap …
    let base = match args.progress_state.clone() {
        Some(state) => Box::new(ProgressReader::new(f, state)) as Box<dyn Read + Send>,
        None => Box::new(f),
    };
    // Wrap in a 256 KiB BufReader so codecs that pull bytes
    // via `Read::read` (zstd, lz4, xz) don't issue one
    // syscall per record/field. DEFLATE has its own
    // PULL_BUF_LEN buffer (raised in this plan) and is
    // not the binding consumer of this wrapper.
    Box::new(BufReader::with_capacity(256 * 1024, base))
};
```

The wrapper is type-erased as `Box<dyn Read + Send>` like
the existing reader so the decoder factory's signature does
not change.

**Resume contract.** The `BufReader` is constructed fresh
per coordinator entry (whether clean or resumed), so the
internal buffer state never appears in a checkpoint. The
underlying `File` was already `seek`-ed to
`decoder_start_offset` before the wrap, so the
`BufReader`'s reads start at the correct source offset.

**Why not 1 MiB on the source side?**
The `decode_step` flow for zstd reads up to 128 KiB at a
time (one Raw block); for DEFLATE the streaming pull is
4 KiB at a time (today, 256 KiB after this plan). A 256 KiB
coordinator-side buffer:

- Holds one zstd block + a handful of headers
- Is small enough that the buffer's `memcpy` cost on
  refill amortizes well against the syscall it saves
- Keeps the per-coordinator memory cost bounded
  (`--workers` doesn't multiply this; the local path is
  single-threaded)

Phase 0 sweeps 64 KiB / 128 KiB / 256 KiB / 1 MiB to lock
the chosen value to data.

### Lever C — `Xxh64::update` SWAR

```rust
// src/hash/xxh64.rs (sketch, replacing the inner u64 loop)
fn update(&mut self, mut data: &[u8]) {
    // Drain into stripe buffer until 32-byte aligned, as today.
    // Then process 32-byte stripes 4-lane parallel:
    let mut a = self.a;
    let mut b = self.b;
    let mut c = self.c;
    let mut d = self.d;
    while data.len() >= 32 {
        let chunk = &data[..32];
        let l0 = u64::from_le_bytes(chunk[ 0.. 8].try_into().unwrap());
        let l1 = u64::from_le_bytes(chunk[ 8..16].try_into().unwrap());
        let l2 = u64::from_le_bytes(chunk[16..24].try_into().unwrap());
        let l3 = u64::from_le_bytes(chunk[24..32].try_into().unwrap());
        a = round(a, l0);
        b = round(b, l1);
        c = round(c, l2);
        d = round(d, l3);
        data = &data[32..];
    }
    self.a = a; self.b = b; self.c = c; self.d = d;
    // tail bytes: same as today.
}
```

The four-lane `round` calls are independent; LLVM
auto-vectorizes the unrolled form on AArch64 to NEON.
No `unsafe`. Differential test against `twox-hash::XxHash64`
across the 1 M random-byte corpus at every prefix length
(the same property test shape as
[`PLAN_xz_decoder_optimization.md`](PLAN_xz_decoder_optimization.md)
Phase 1's CRC64 diff). Phase 3 only ships if Phase 2's
bench grid has not closed the `zstd-raw` row to ≤ 1.3×.

## Phasing

### Phase 0 — Anchor benches (1 day)

- Add a microbench
  `bench_raw_sink_write_throughput` in
  [`tests/test_bench_streaming.rs`](../tests/test_bench_streaming.rs)
  (or a new `tests/test_bench_raw_sink.rs`): drives a 256 MiB
  in-memory byte stream through `RawSink` (and a
  `BufWriter`-wrapped variant for the post-A comparison),
  reports MiB/s.
- Add a microbench `bench_xxh64_64kib` in
  [`tests/test_bench_hash.rs`](../tests/test_bench_hash.rs):
  scalar throughput baseline at the 64 KiB working-set size
  the zstd path hits.
- Sweep `PULL_BUF_LEN` candidates (`4`, `64`, `256`, `1024` KiB)
  via a feature-gated microbench
  `bench_deflate_native_stored_throughput` and pin the chosen
  value to data.

**Exit criterion**: anchor numbers recorded in
`internal/bench-results/raw-row-baseline-<date>.log`.

### Phase 1 — `RawSink` BufWriter + checkpoint flush (3 days)

- Implement the `RawSink` change above with the
  `Sink::flush_durable` default + `RawSink` override.
- Wire `flush_durable` into the extractor's checkpoint
  observer at
  [`src/extractor.rs:771-825`](../src/extractor.rs#L771-L825).
- Crash-test extension: add a flavor of
  `tests/test_coordinator_crash.rs` that kills the process
  immediately *after* a checkpoint commit, verifies that
  the resumed run starts from `bytes_written` recorded in
  the checkpoint and produces byte-identical output.
- Re-run `bench_decode_local_grid` and confirm
  `gz-raw` / `zstd-raw` rows move; record the post-A
  numbers.

**Exit criterion**: `gz-raw` 100 MiB warm ≤ 1.55×;
`zstd-raw` 100 MiB warm ≤ 1.40×; no regression on
`tar.gz` / `tar.zst`; crash-resume harness green.

### Phase 2 — DEFLATE pull-buffer + coordinator BufReader (3 days)

- Bump
  [`src/decode/deflate_native/bitstream.rs:57`](../src/decode/deflate_native/bitstream.rs#L57)
  `PULL_BUF_LEN` from `4096` to `262144`.
- Wrap the source `Read` in a 256 KiB `BufReader<R>` at
  [`src/coordinator/local.rs:765`](../src/coordinator/local.rs#L765).
- Verify the existing
  `tests/test_deflate_native.rs` differential corpus stays
  byte-identical against `flate2::MultiGzDecoder`
  (the Phase 2 buffer change is internal; the public
  contract is unchanged).
- Re-run `bench_decode_local_grid` and confirm the
  remainder of the gap closes.

**Exit criterion**: `gz-raw` 100 MiB warm ≤ 1.30×;
`zstd-raw` 100 MiB warm ≤ 1.30× (with the warm-cell
noise band the row may publish at 1.20×–1.40×); no
regression on any other row.

### Phase 3 — `Xxh64` SWAR (gate: Phase 2 did not close zstd-raw) (2 days)

- Implement the SWAR loop as above.
- Differential test against `twox-hash::XxHash64`.
- Microbench: ≥ 3× scalar throughput on 64 KiB.
- Re-run `bench_decode_local_grid`.

**Exit criterion**: `zstd-raw` 100 MiB warm ≤ 1.30×.
If Phase 2 already met the criterion, **skip Phase 3**
and file the SWAR work as a follow-on against
[`internal/OPTIMIZATIONS.md`](OPTIMIZATIONS.md) (promote
when a profile on a real corpus shows `xxh64::update`
load-bearing again).

### Phase 4 — Bench + docs (1 day)

- Run `bench_decode_local_grid` and
  `bench_throttled_realistic_grid` (the latter to catch
  any 10 Gbps regressions).
- Update
  [`internal/bench-results/decode-local-grid-mac-m4max-<date>-post-raw.log`](bench-results/)
  and overwrite the README's "Wall-clock ratio" table
  with the new numbers.
- Update README prose at
  [`README.md` L427-L436](../README.md#reading-the-grid)
  — the "honest" raw-row commentary moves to a smaller
  gap or disappears, depending on where the rows land.
- Update
  [`internal/PLAN_gzip_throughput.md`](PLAN_gzip_throughput.md)
  §"Phase 3 deprioritization" with a forward reference
  to this plan as the lever that closed the remaining
  decode-local raw gap.

**Exit criterion**: README's bench grid reflects the
new numbers; primary targets met; no `bench_throttled_realistic_grid`
regression.

## Risks

1. **`BufWriter` defers `write` errors past the
   call site.** A failed write inside the buffer
   surfaces at the next `flush` / `close`. The current
   `Sink::write` contract is "errors propagate at the
   write that caused them". The `BufWriter` wrap weakens
   this to "errors propagate at the next flush or close",
   which means a checkpoint commit may surface a write
   error that logically belongs to bytes written several
   blocks earlier. **Mitigation**: the `flush_durable`
   call on every checkpoint commit narrows the window;
   any write-error blast radius is bounded to the
   checkpoint cadence (~8 MiB of output on a 1 GiB run).
   This matches `TarSink`'s existing posture (it batches
   per-entry, surfaces errors at entry close); no new
   contract is being broken, just a new code path.
2. **Checkpoint cadence inflation.** If the
   `flush_durable` call dominates checkpoint cost, the
   net throughput could regress on small files. The
   bench-grid 10 MiB rows are the canary. **Mitigation**:
   Phase 0 microbench measures `BufWriter::flush` cost;
   the post-Phase-1 grid run validates the 10 MiB rows.
   If a regression appears, gate the flush on
   `buffered_bytes > 0`.
3. **`PULL_BUF_LEN = 256 KiB` adds memory per
   `BitReader` instance.** The deflate decoder
   instantiates one `BitReader` per stream. Bare gz files
   instantiate one decoder; multi-member tar.gz
   instantiates one per active worker (post the
   `PLAN_gzip_throughput.md` Phase 3 work, which is
   deferred — so today, still one). Peak memory uplift:
   252 KiB per coordinator run. Within the
   `--max-disk-buffer` budget by an order of magnitude.
4. **256 KiB `BufReader` on the coordinator's source
   path may steal cache lines from the decoder's
   working set.** The DEFLATE 32 KiB sliding window +
   16 KiB CRC32 table + 4 KiB Huffman tables are the
   hot footprint. M-series L1d is 192 KiB; L2 is much
   larger. A 256 KiB buffer fits comfortably in L2 and
   does not displace the L1 footprint. **Mitigation**:
   Phase 2 grid run is the verifier; if a regression
   appears, drop to 128 KiB.
5. **`Xxh64` SWAR LLVM auto-vectorization may not fire.**
   The xz arc's
   [`PLAN_xz_decoder_optimization.md`](PLAN_xz_decoder_optimization.md)
   Phases 3–5 documented the same risk and found the
   LLVM ceiling for safe Rust. **Mitigation**: Phase 3
   is gated on Phase 2 missing its target; if SWAR
   doesn't auto-vectorize, the lever is filed against
   OPTIMIZATIONS.md with a note that hardware-specific
   intrinsics would be required.
6. **Profile noise on the warm cells.** The 100 MiB
   warm cells have a ~10 ms variance band (the
   cold-vs-warm spread on `zstd-raw` is 0.039–0.063 s,
   for example). A single-run grid result can land
   inside the band by luck. **Mitigation**: each grid
   refresh runs the cell three times and reports the
   median; if the median is at the noise boundary,
   re-run with `--test-threads=1` on an otherwise idle
   machine. Same posture as
   [`PLAN_xz_throughput.md`](old/PLAN_xz_throughput.md)
   Phase 1 used.
7. **Implication for the `tar.gz` row at 10 Gbps.**
   That row sits at 1.05× today
   ([`README.md` row 10 Gbps · 256 MiB](../README.md#benchmarks-peel-vs-curl---decompressor---tar)).
   The Lever A change applies to `RawSink` only;
   `TarSink` is untouched. The Lever B changes apply
   to every codec, so the 10 Gbps `tar.gz` row will
   see a *small* improvement (the source-side
   buffering removes some of the 14 ms peel/curl gap
   that `PLAN_gzip_throughput.md` §"Phase 3
   deprioritization" filed as a follow-on). Phase 4
   bench includes the streaming grid to make this
   delta visible; no regression is the firm criterion.

## Acceptance criteria

- ✅ `bench_decode_local_grid` `gz-raw` 100 MiB · warm:
  ratio ≤ 1.30× (target 1.80× → 1.30×).
- ✅ `bench_decode_local_grid` `zstd-raw` 100 MiB · warm:
  ratio ≤ 1.30× (target 1.61× → 1.30×).
- ✅ `bench_decode_local_grid` other rows: no regression
  vs the 2026-05-12 baseline within 5 %.
- ✅ `bench_throttled_realistic_grid` rows: no regression
  vs the 2026-05-12 baseline within 5 %.
- ✅ Crash-resume harness: new
  `kill_after_checkpoint_resumes_byte_identical_raw_sink`
  variant green across 100 random trials.
- ✅ `tests/test_deflate_native.rs` differential corpus:
  byte-identical against `flate2::MultiGzDecoder` for
  the existing fixtures (Phase 2 buffer change is
  internal-only).
- ✅ `cargo test`, `cargo clippy -- -D warnings`,
  `cargo fmt --check` all green.
- ✅ README's "Wall-clock ratio" table reflects the new
  `gz-raw` / `zstd-raw` ratios; the "Reading the grid"
  prose at L427-L436 updates the raw-row commentary to
  match the new numbers (the "honest" framing shifts to
  whatever the residual gap is — likely ≤ 1.30× and
  attributable to the codec floor below the syscall
  floor, not to syscall overhead).
- ✅ Followup items filed in
  [`internal/OPTIMIZATIONS.md`](OPTIMIZATIONS.md):
  TarSink write buffering (gate: profile after A shows it
  load-bearing); Xxh64 SWAR (if Phase 3 didn't ship);
  `splice(2)` / `copy_file_range(2)` zero-copy (Linux
  raw rows).

## Estimated total effort

Roughly **1.5–2 weeks** for one engineer:

- Phase 0: 1 day (anchor microbenches).
- Phase 1: 3 days (`RawSink` BufWriter + checkpoint
  flush + crash-resume).
- Phase 2: 3 days (pull-buffer bump + coordinator
  BufReader + differential test).
- Phase 3: 2 days (only if Phase 2 missed the
  `zstd-raw` target).
- Phase 4: 1 day (bench + README + plan cross-references).

## Reference material

- `/tmp/peel-prof/gz_profile.json.gz` —
  `samply` profile, 8 iterations × 1 GiB LCG-random
  gz fixture, M4 Max, 4 kHz sampling. Source of the
  37 % `write` / 26 % `read` self-time numbers above.
  *Local, not checked in.*
- `/tmp/peel-prof/zst_profile.json.gz` —
  zstd equivalent, 16 iterations × 1 GiB zstd-1 random
  fixture. Source of the 43 % `write` / 22 % `read` /
  14 % `xxh64` numbers above.
- README "Reading the grid"
  ([`README.md` L427-L436](../README.md#reading-the-grid))
  — the prose this plan rewrites.
- [`internal/PLAN_gzip_throughput.md`](PLAN_gzip_throughput.md)
  §"Sub-plans demoted to follow-ons" — the DEFLATE
  SIMD / table-driven literal decode follow-on, the
  *next* lever after this plan if a *compressible*
  payload corpus surfaces a decoder-bound gap.
- [`internal/old/PLAN_raw_tar_throughput.md`](old/PLAN_raw_tar_throughput.md)
  — sibling analysis for the 10 Gbps `tar` row;
  identifies the same pattern at a different point on
  the pipeline.
