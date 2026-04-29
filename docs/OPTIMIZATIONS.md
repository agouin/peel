# Optimizations & Future Work

> **Status: post-MVP work is now active (2026-04-29).** The MVP in `PLAN.md`
> has shipped (phases 1–10 complete). Items in this file are now eligible
> for prioritization, but the rule still stands: **promotion from this file
> to active work happens through deliberate human review**, not by an agent
> deciding "while I'm here…" When an item is selected, it should be lifted
> into a successor plan (a new sequenced doc, same discipline as the
> original `PLAN.md`) before implementation begins.

This file started as a **wishlist of things explicitly deferred** during
MVP. Now that the MVP is complete, it serves as the input queue for the
next planning round.

The point of having this file is twofold:

1. To capture good ideas so they're not lost.
2. To give agents an explicit "not until it's been planned" list so
   post-MVP work stays scoped to what was actually agreed.

Each item below has: what it is, why we deferred it, and a sketch of how
it would be approached if/when prioritized.

---

## Performance

### O.1 Adaptive chunk size

**What**: tune chunk size during download based on observed throughput
and connection RTT, instead of a fixed 4 MiB.

**Why deferred**: 4 MiB is a known-good value for typical CDN setups;
optimizing further is premature without real-world telemetry.

**Sketch**: track per-worker chunk completion times; when all workers
consistently complete chunks in <1s, double chunk size up to a cap (say
64 MiB); when latency spikes or we see frequent retries, halve.

---

### O.2 io_uring for downloads and writes

**What**: replace blocking `read`/`pwrite` with `io_uring` submission
queues for higher throughput at high IO concurrency.

**Why deferred**: blocking IO with a small thread pool is more than
fast enough for network-bound work; `io_uring` adds Linux-only
complexity for marginal gains in our use case.

**Sketch**: introduce a Linux-specific IO backend behind a trait; keep
the portable blocking backend as default. Likely needs `tokio-uring` or
similar — adding async runtime complexity that the MVP avoids.

---

### O.3 Memory-mapped sparse file

**What**: `mmap` the partial download file so workers write into memory
and the kernel handles flushing.

**Why deferred**: makes hole-punching coordination harder (need to
`madvise(MADV_REMOVE)` instead of `fallocate`), and `pwrite` is already
fast. Real benefit only at very high concurrency.

**Sketch**: investigate `MADV_REMOVE` semantics, build a parallel
mmap-based sparse-file backend, benchmark against pwrite at various
chunk counts.

---

### O.4 Parallel decoding within a frame

**What**: for zstd archives with very large frames, decode independent
sub-blocks in parallel.

**Why deferred**: requires per-format work, marginal benefit unless
producers happen to use large frames, and most modern zstd-compressed
archives use many small frames already (which we exploit naturally
via worker priority steering).

**Sketch**: would need to parse zstd block headers ourselves to
identify independent blocks; not exposed by the upstream `zstd` crate.

---

### O.5 NUMA-aware worker placement

**What**: pin workers to NUMA nodes to keep download buffers local.

**Why deferred**: only relevant on multi-socket servers; we are a CLI
utility for end-user machines first.

---

## Format support

### O.6 xz / LZMA decoder

**Status: delivered in `PLAN_v2.md` §3 (2026-04-29).** Round-one ships
per-`Stream` frame granularity via `xz2`'s raw `Stream::process` API;
see [`src/decode/xz.rs`](../src/decode/xz.rs). Default-encoded
`.tar.xz` files are single-Block (and therefore single-Stream from the
format's point of view) — no implementation can checkpoint within
those, because the file itself does not contain a usable restart
point. Per-Block granularity for multi-Block / multi-Stream files
(which would help multi-threaded encoder output, `xz --keep` concat
output, etc.) is filed below as `O.6b`.

---

### O.6b xz per-Block frame boundaries (round-two follow-on)

**What**: parse xz's Block headers and Stream Index to expose
per-Block frame boundaries within a single Stream, instead of only
the per-Stream boundary `PLAN_v2.md` §3 settled for.

**Why deferred**: only matters for multi-Block xz files (multi-threaded
encoder output via `pixz` / `xz -T`, deliberately split corpora) and
for multi-Stream files (`xz --keep` concat). The dominant `.tar.xz`
shape — single-Block, single-Stream — cannot be checkpointed
within-Block by *any* implementation; the format itself does not
contain a restart point. Round-one's per-Stream MVP covers the case
where it matters in practice.

**Sketch**: parse the Stream Index at the tail of each Stream (it
enumerates Blocks with their compressed/uncompressed sizes). Drive
`xz2::stream::Stream::new_stream_decoder` per-Block by re-instantiating
at known Block boundaries. Surface each Block boundary through
`StreamingDecoder::frame_boundary` exactly the way per-Stream is
surfaced today. Promote when real users hit the slow-resume cost.

---

### O.7 lz4 decoder

**What**: support `.tar.lz4`.

**Why deferred**: lz4 is rare in published archives; not a common
real-world target.

---

### O.8 zip support

**What**: stream-extract `.zip` archives.

**Why deferred**: zip's central-directory-at-the-end design is
fundamentally hostile to streaming and to prefix-truncation. Would
require downloading the central directory first (the last few KB),
then doing per-entry ranged GETs — a different pipeline architecture
entirely. Worth it if the use case demands it; out of scope otherwise.

---

### O.9 Native peel container format

**What**: design a new archive format optimized end-to-end for our
pipeline (per-block compression, embedded sync markers, validated
prefix truncation, optional manifest sidecar).

**Why deferred**: the existing `tar.zst` workflow covers most needs.
Designing a new format adoption-ready (and actually adopted) is a
much larger project.

**Sketch**: see the design notes in the Python prototype's predecessor
discussions. Block layout: `[magic][len][type][crc32][payload][pad]`.
Block types: archive header, file header, file data, file end, archive
end, sync marker.

---

## Reliability

### O.10 Multi-mirror downloads

**What**: accept multiple URLs for the same file (with the same hash);
download chunks from whichever mirror responds fastest.

**Why deferred**: not in MVP; common in package managers but not
universally needed for arbitrary archive downloads.

**Sketch**: scheduler accepts `Vec<Url>`, runs HEAD against each in
parallel to verify size + ETag/checksum, then dispatches chunk
requests to the fastest-responding mirror with fallback on failure.

---

### O.11 Bandwidth limiting

**What**: `--max-bandwidth 10MB/s` flag.

**Why deferred**: easy to add but not load-bearing for MVP.

**Sketch**: token-bucket rate limiter shared across workers; each
worker `acquire()`s tokens equal to bytes-about-to-be-read before
issuing each socket read.

---

### O.12 Resume across version changes

**What**: when the binary version changes between an interrupted run
and the resume, attempt to migrate the checkpoint format.

**Why deferred**: MVP just refuses to resume across format-version
changes and starts over; that's safe and simple.

**Sketch**: a versioned migration table (`v1 → v2 → v3 ...`) in
`checkpoint.rs`. Adds maintenance burden; only worth it once we have
real users with real interrupted downloads.

---

### O.13 Integrity verification

**What**: `--sha256 abc...` flag verifies the assembled compressed
file's hash against an expected value before extraction.

**Why deferred**: useful but orthogonal to the core resumable-extraction
loop. ETag already gives us "did the source change during download";
this would add "is the result what was expected" on top.

**Sketch**: maintain a streaming SHA-256 hasher fed by the extractor's
input stream; check at completion. Resume needs to handle this:
either start over (safe) or store the partial hasher state in the
checkpoint (complex; SHA-256 state is small but the API isn't built
for serialization).

---

## Operational features

### O.14 macOS `F_PUNCHHOLE` puncher

**What**: implement the `PunchHole` trait for macOS.

**Why deferred**: MVP is Linux-first. The trait abstraction means
adding macOS is purely additive.

**Sketch**: `fcntl(fd, F_PUNCHHOLE, &fpunchhole_arg)` — already
sketched in the Python prototype. APFS supports it.

---

### O.15 Windows sparse file + `FSCTL_SET_ZERO_DATA`

**What**: NTFS equivalent of hole punching.

**Why deferred**: same reason as O.14; orders of magnitude more work
to also port the rest of the toolchain (fallocate/sparse file
semantics, signal handling).

---

### O.16 Daemon / library mode

**What**: expose `peel` as a library callable from other Rust
binaries, or as a long-running daemon with an IPC interface.

**Why deferred**: the MVP is a CLI. The internal API is shaped to
allow this later (every module is a library; the binary is a thin
shell), but the public library API isn't a commitment we want to
make until the internal one stabilizes.

---

### O.17 HTTP/2 and HTTP/3

**What**: upgrade the hand-rolled HTTP client beyond HTTP/1.1.

**Why deferred**: HTTP/1.1 with parallel connections is sufficient
for ranged downloads. HTTP/2 multiplexing would let us use one
connection but doesn't speed things up versus N parallel HTTP/1.1
connections in our use case. HTTP/3 (QUIC) is a much larger lift
and not a clear win for bulk transfer.

**Sketch**: out of scope for "hand-rolled"; if pursued, this is
where we'd revisit the dependency policy and consider `hyper` or
`reqwest`.

---

### O.18 Pluggable destination

**What**: write extracted output to S3, GCS, etc., not just local
disk.

**Why deferred**: nice-to-have, big surface area, requires those
SDKs (which conflict with our dependency policy). Likely better
served by piping to a separate uploader tool.

---

### O.19 Progress UI improvements

**What**: TUI with multiple progress bars (per worker), bandwidth
graphs, ETA, etc.

**Why deferred**: a single redrawn line is enough for MVP. Going
further means a `crossterm`/`ratatui` dependency.

---

## Testing & QA

### O.20 Continuous fuzzing

**What**: long-running fuzz jobs in CI for the HTTP parser, decoder
wrappers, checkpoint format.

**Why deferred**: short fuzz runs in PR CI cover the basics; sustained
fuzzing is a post-MVP investment in coverage.

**Sketch**: OSS-Fuzz integration if/when this becomes a published
crate.

---

### O.21 Real-world archive corpus tests

**What**: weekly CI job that downloads N real-world `.tar.zst`
archives (Linux distro images, open dataset releases, container
images) and verifies extraction works.

**Why deferred**: bandwidth and storage costs in CI; the local
synthetic corpus catches most issues.

---

### O.22 Differential testing against reference tools

**What**: extract every test archive with both peel and `tar -xzf`
(or equivalent), diff the outputs.

**Why deferred**: unit tests already verify content correctness;
diff-against-tar would catch metadata bugs (modes, mtimes, xattrs)
that the MVP explicitly defers.

---

## Metadata & semantics

### O.23 File modes, ownership, mtimes

**What**: preserve POSIX permissions, ownership, modification times
on extracted files.

**Why deferred**: explicit MVP exclusion. Most users care about
contents; metadata can be added without touching the streaming
infrastructure.

**Sketch**: `tar::Header` already has the data; just call
`std::os::unix::fs::PermissionsExt::set_mode` and `utime` after
extraction. Ownership requires root or `CAP_CHOWN`; behavior should
match `tar`'s `--no-same-owner` default.

---

### O.24 Extended attributes, ACLs, SELinux contexts

**What**: preserve xattrs/ACLs/etc.

**Why deferred**: niche, platform-specific. Defer until requested.

---

### O.25 Symbolic and hard link handling

**What**: correctly recreate symlinks and hardlinks from tar.

**Why deferred**: the MVP's tar parser will handle regular files only.
Adding link handling is straightforward but expands the path-safety
surface area significantly (symlink-target traversal is a classic
attack vector).

---

## When to revisit this list

**This is the moment.** The MVP shipped on 2026-04-29 and we're now in the
post-MVP phase. Look at this list and ask:

1. What did real users actually need that we deferred?
2. What did we discover during MVP work that changed our priors?
3. Which items are dependencies of others?

Then a *new* `PLAN.md` (or `PLAN_v2.md`) gets written with a focused
slice of these promoted to scope, in dependency order, with the same
discipline as the original MVP plan. Don't try to "knock out a few
optimizations" outside of that process.
