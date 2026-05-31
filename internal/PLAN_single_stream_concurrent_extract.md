# Plan: stream-extract concurrently in single-stream (range-less) downloads

> **Status:** **CONFIRMED & FIXED (2026-05-30).** The root-cause
> hypothesis below was verified against the source and the fix landed via
> **Option A** (drive the known-size single-stream reader off a
> sequential write frontier instead of the 4 MiB chunk bitmap). Summary
> of the change:
>
> - `SchedulerConfig` gained an optional `write_frontier:
>   Option<Arc<AtomicU64>>`; `run_single_stream` stores the durable byte
>   offset there (`Release`) after each `pwrite_at`.
> - `BlockingSparseReader` gained `with_write_frontier` + a
>   `read_sequential` path (modelled on `read_unknown`) that gates
>   byte-availability on that frontier; the coordinator wires it for
>   `info.size_known && !info.accept_ranges`. The chunk bitmap is still
>   maintained for resume/accounting.
> - `sniff_prefix` learned the same frontier gate, so format detection
>   no longer stalls on the post-download chunk mark for archives ≤
>   `chunk_size`.
> - `run_single_stream` now also honours `max_disk_buffer` by pausing
>   the socket read (TCP backpressure) when the on-disk lookahead is at
>   the cap — single-stream previously ignored the cap entirely, so the
>   gating fix alone would not have bounded peak disk on a fast network.
> - Regression coverage: `blocking_reader_sequential_*` unit tests and
>   `single_stream_publishes_sequential_write_frontier` integration test;
>   verified end-to-end against a throttled range-less `Content-Length`
>   server (a 48 MiB `.tar.zst` extracted concurrently with `decoded_in`
>   tracking the download and lookahead held ~113 KiB under a 4 MiB cap).
>   The **random-access exception** is intact: zip/7z/rar use their own
>   pipelines, never the frontier reader.
>
> Original report follows. Drafted 2026-05-30 from a downstream
> consumer that embeds peel as a library and fetches every artifact as a
> `tar.zst` through `coordinator::run`. While building a live download
> UI on top of peel we measured that, for a range-less HTTP source, peel
> defers *all* extraction until the download finishes — even though the
> archive is a streaming format. This doc lays out the evidence and a
> root-cause hypothesis with code pointers so a peel agent can confirm,
> decide the fix, and open an issue. Line numbers are as of this date;
> re-locate before editing.

A peel maintainer (Andrew) confirmed the intended contract:
**streaming formats should download and extract concurrently
(honouring `max_disk_buffer`) regardless of whether the server supports
HTTP range requests or even sends `Content-Length`.** The only formats
that may legitimately require a fully-downloaded archive before
extraction are **random-access** ones (zip / 7z / rar) when the server
is range-less. `tar.zst` is a streaming format, so the behaviour below
is a bug, not by-design.

---

## Symptom

The consumer fetches a `tar.zst` (registered as `FormatShape::Tree`)
over a loopback HTTP server that sends `Content-Length` but does **not**
advertise `Accept-Ranges` → peel runs `DownloadMode::SingleStream`.

Per-tick `ProgressState` snapshot for one artifact (~1.7 MiB `tar.zst`,
network throttled so the download takes ~2.1 s), captured from the
consumer side via `state.snapshot()`:

```
dl=65536     ex=0  decin=0      total=Some(1760153)   disk_bound=false
dl=557056    ex=0  decin=0      total=Some(1760153)   disk_bound=false
dl=1081344   ex=0  decin=0      total=Some(1760153)   disk_bound=false
dl=1605632   ex=0  decin=0      total=Some(1760153)   disk_bound=false   (download ~done)
RunStats: mode=SingleStream elapsed=2.156s download.elapsed=2.114s
          extraction.decode_time=37ms write_time=0.6ms
          source_wait_time=0ns source_wait_count=0
          bytes_in=1760153 bytes_out=1763840
```

`bytes_decoded_input` and `bytes_extracted` stay at **0 for the entire
download**, then the archive extracts in a single ~37 ms burst *after*
the download completes. `source_wait_time` is 0 because by the time the
reader runs, every byte is already on disk — it never blocks.

The same shape held across 8/8 artifacts (0.5–2.6 MiB each), all
`SingleStream`.

## Why it matters

1. **Defeats the streaming premise** for range-less sources: peak disk
   footprint is the whole archive, and wall-clock is
   `download + extract` instead of `max(download, extract)`. For large
   archives over a range-less mirror this is the difference peel exists
   to avoid.
2. **Breaks the live bottleneck indicator.** `classify_bottleneck`
   (`src/progress.rs`) compares `dl_rate` vs `decoded_in_rate`. With
   `bytes_decoded_input` pinned at 0 through the download, `decoded_in_rate`
   is 0, so the `if dl <= 0.0 || di <= 0.0 { return None }` guard fires
   and the indicator reads "no bottleneck" for the whole transfer, then
   flickers `Network` only during the post-download drain. (The
   imbalance semantics of `classify_bottleneck` are otherwise considered
   correct/intended — this item is strictly the `decin=0` side effect,
   not a request to change the classifier.)

## Root-cause hypothesis (confirm)

The single-stream **known-size** reader gates on the **chunk bitmap**,
whose completion granularity is `DEFAULT_CHUNK_SIZE = 4 MiB`
(`src/download/scheduler.rs:63`):

- `run_single_stream` marks bitmap chunks only as it crosses a
  `chunk_size` boundary (`src/download/scheduler.rs:1730-1739`), and
  marks the trailing partial chunk **after the download loop**
  (`:1745-1751`).
- For any archive `total_size <= chunk_size` (4 MiB), there is exactly
  one bitmap chunk and the boundary at `:1734` is never crossed, so the
  only completion is the post-loop `mark_complete` at `:1748` — i.e.
  the chunk flips to complete only once `download_done` is set.
- `BlockingSparseReader::read` (the known-size path) blocks on
  `self.bitmap.is_complete(chunk_idx)` (`src/coordinator.rs:4751`) and
  only advances the cursor / publishes `bytes_decoded_input` once that
  bit is set. So the decoder cannot start until the whole file is down.
- For archives larger than 4 MiB the decoder *does* advance, but always
  trails by up to a full `chunk_size`, and the final chunk is always
  marked post-loop — so the tail always extracts after download.

Contrast the **unknown-size** path (range-less *and* no
`Content-Length`, "issue #8"): `run_single_stream_unknown`
(`src/download/scheduler.rs:1773`) touches no bitmap, and
`BlockingSparseReader::read_unknown` (`src/coordinator.rs:4631`) gates on
the sparse file's live high-water (`MultiSparse::total_size()`),
advancing byte-by-byte as `pwrite_at` extends it. **That path already
extracts concurrently** — which is why the maintainer's "even without
`Content-Length`" expectation already holds, while the *known-size*
single-stream path (the more common one) does not.

So the fix is essentially: make known-size single-stream gate on the
sequential write frontier the way the unknown-size path already does,
instead of the coarse 4 MiB bitmap.

## Proposed direction (for the evaluator to weigh)

Single-stream is strictly sequential (one body, writing `0..total` in
order), so a byte-granular high-water frontier is exactly correct and
the bitmap's chunk granularity is unnecessary coarseness here.

**Option A (preferred): drive the known-size single-stream reader off
the high-water, like the unknown-size path.** Either route the reader
through the `read_unknown` frontier logic when the active download mode
is single-stream, or have `run_single_stream` publish a byte-level
"durable frontier" the reader consults. Keep the chunk bitmap for
resume/accounting, but don't make extraction wait on it. The
unknown-size path is the working template.

**Option B: finer bitmap completion in `run_single_stream`.** Mark
partial progress within the current chunk so the reader can advance
mid-chunk. More invasive to the bitmap's "a set bit means the whole
chunk is durable" invariant; likely worse than A.

Either way, preserve:
- `max_disk_buffer` throttling (the reader's cursor still feeds the
  lookahead/`bytes_decoded_input` the scheduler throttles against).
- The **random-access exception**: zip / 7z / rar over a range-less
  source must still fully download first. Gate the concurrent-extract
  behaviour on the format being streaming (the registry/`FormatShape`
  already distinguishes a streamable tree/stream from a random-access
  container — confirm the right predicate).
- Resume semantics: single-stream "can't resume mid-file" (re-fetches
  from 0); that's unchanged.

## Verification

1. **Reproduce:** fetch a streaming archive (`.tar.zst`) over a
   range-less server that *does* send `Content-Length`. A small loopback
   HTTP server that sends `Content-Length`, omits `Accept-Ranges`,
   ignores `Range` (always replies `200`), and throttles bandwidth
   reproduces it directly. (`python -m http.server` honours `Range`, so
   to force single-stream either strip range support or use a server
   that lacks it.) Snapshot `ProgressState` on a timer and confirm
   `bytes_decoded_input` / `bytes_extracted` stay 0 until `download_done`.
2. **After the fix:** the same timeline should show `decin`/`ex`
   climbing *during* the download (trailing `dl` by no more than
   `max_disk_buffer`), `source_wait_time > 0` (the reader now genuinely
   waits on the network), and `decode_time` spread across the transfer
   rather than a terminal burst.
3. **Regression guard:** a zip/7z over a range-less source must still
   defer extraction (random-access exception intact). Parallel
   ranged-GET mode (`run_parallel`) already completes chunks
   incrementally — confirm it's unaffected.

## Open questions

- Exact predicate for "streaming vs random-access" at the point the
  reader chooses its gating strategy — is `FormatShape` / the decoder
  registry the right signal, or is there an existing
  "requires-full-download" flag?
- Does the known-size single-stream path want to *become* the
  high-water path wholesale (size known only used for the EOF check), or
  keep the bitmap for accounting while reading off the frontier?
- Any checkpoint/resume coupling to the bitmap that Option A would need
  to keep intact.

## Provenance

Found via a downstream library consumer that calls
`peel::coordinator::run` with `OutputTarget::Dir`, `expected_sha256`
set, and a default `CoordinatorConfig` (so `max_disk_buffer = 1 GiB`),
with the archive registered as a tar+zstd `FormatShape::Tree`. That
consumer's UI works around the gap by classifying its bottleneck from
`download.elapsed` vs total `elapsed` rather than the live
`decoded_input` signal.
