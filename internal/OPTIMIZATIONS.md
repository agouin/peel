# Optimizations & Future Work

> **Status: zstd block decoder plan shipped (2026-05-01).** The MVP in
> `PLAN.md` landed 2026-04-29 (phases 1–10); round one of `PLAN_v2.md`
> followed on top (2026-04-30), delivering `O.1`, `O.2`, `O.3`, `O.6`,
> `O.7`, `O.8`, `O.10`, `O.11`, `O.13`, `O.14`, and `O.19`; and the
> `PLAN_zstd_block_decoder.md` plan landed 2026-05-01 (phases 1–10),
> replacing the `zstd` crate with a hand-rolled `decode/zstd_native/`
> module that surfaces per-block frame boundaries and a sliding-window
> resume blob. That plan's Phase 11 follow-ons are filed below as `O.26`
> through `O.31`. Delivered entries are annotated **"delivered in
> PLAN_v2 §<phase>"** (or, where applicable, the zstd plan) and kept as
> historical record — do not re-pull them. The remaining items are
> eligible for prioritization, but the rule still stands: **promotion
> from this file to active work happens through deliberate human
> review**, not by an agent deciding "while I'm here…" When an item is
> selected, it should be lifted into a successor plan (a new sequenced
> doc, same discipline as the original `PLAN.md`) before implementation
> begins.

This file started as a **wishlist of things explicitly deferred** during
MVP. With round one of `PLAN_v2.md` now shipped on top of the MVP, it
serves as the input queue for the next planning round.

The point of having this file is twofold:

1. To capture good ideas so they're not lost.
2. To give agents an explicit "not until it's been planned" list so
   post-MVP work stays scoped to what was actually agreed.

Each item below has: what it is, why we deferred it, and a sketch of how
it would be approached if/when prioritized.

---

## Performance

### O.1 Adaptive chunk size

**Status: delivered in `PLAN_v2.md` §8 (2026-04-29).** The bitmap chunk
size — the on-disk planning unit and the value persisted in the
checkpoint — is fixed for the lifetime of a run. The new
[`ChunkSizePolicy`](../src/download/chunk_policy.rs) instead controls
the **dispatch size**, i.e. the number of contiguous bitmap chunks
the scheduler coalesces into a single ranged GET. The policy grows
the dispatch size (doubling, capped at 64 MiB) when all recent
samples completed in under 1 s and there are at least 2× workers
chunks remaining, and shrinks it (halving, floored at the larger of
1 MiB and the bitmap chunk size) when p95 latency exceeds 5 s or the
recent retry rate exceeds 10 %. A 30 s hysteresis prevents
oscillation. Adaptive sizing is on by default; `--no-adaptive-chunk-size`
disables it without changing the default starting size, and
`--chunk-size <N>` continues to set the bitmap chunk size for runs
that want a fixed unit.

---

### O.2 io_uring for downloads and writes

**Status: delivered in `PLAN_v2.md` §7 + §7b (2026-04-29).** Both halves
of the IO path now route through the [`IoBackend`](../src/io_backend.rs)
trait. `UringBackend` (Linux-only, gated on a runtime capability probe)
submits the parallel `pwrite`/`pread`/`fsync` SQEs *and* the download
workers' TCP `connect`/`send`/`recv` SQEs through a single ring on a
dedicated IO thread; per-op timeouts are linked `LinkTimeout` SQEs so
worker cancellation is prompt without polling. `rustls` rides on top
unchanged because [`UringSocket`](../src/io_backend/uring.rs) implements
`std::io::{Read, Write}`. No async runtime was added — the IO thread
uses `Submitter::submit_and_wait` and workers block on per-op
completion notifiers. The probe falls back cleanly (with a `warn!`
naming the cause) when the kernel rejects ring construction (kernel
< 5.6, `RLIMIT_MEMLOCK` too low, seccomp blocking); `--io-backend
[auto|blocking|uring|mmap]` lets a user pin a path explicitly.

---

### O.3 Memory-mapped sparse file

**Status: delivered in `PLAN_v2.md` §9 (2026-04-29).** Linux-only mmap
storage backend for `SparseFile`, selected via `--io-backend mmap`.
Workers `memcpy` into a `MAP_SHARED` region; `sync_all` translates to
`msync(MS_ASYNC)`; the matching puncher (constructed via
`SparseFile::make_mmap_puncher`) issues `madvise(MADV_REMOVE)` against
the mapping. The `LinuxPuncher::for_mmap` constructor pairs the
fallocate-mode puncher with an mmap-mode sibling, sharing the same
`PunchHole` trait surface; `EOPNOTSUPP`/`EINVAL`/`ENOSYS` returns
graceful `PunchError::Unsupported` (mirroring the fallocate path).
Sockets continue to use the blocking backend in mmap mode — only the
sparse file's storage changes. Default backend remains
`pwrite`/`pread` until the mmap path has been benchmarked in
production.

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

### O.26 zstd multi-stream parallel literals decode

**What**: decode the 4-stream parallel literals format (used by zstd
when the literals section's compressed size warrants it) in parallel
across threads, instead of the sequential walk
[`src/decode/zstd_native/literals.rs`](../src/decode/zstd_native/literals.rs)
ships in round one.

**Why deferred**: sequential decode hit the `PLAN_zstd_block_decoder.md`
throughput target (within 3× of libzstd on a representative
`tar.zst`). Parallelizing is a fixed 4× ceiling on one hot loop and
adds thread-coordination machinery; only worth it if profiling shows
literals as the bottleneck.

**Sketch**: the literals header carries three `u16` stream sizes (the
fourth is derived from the total). After Huffman-table construction
(which is shared and immutable for the block), spawn a job per stream
into a small pool and concatenate the four output slices on join.
No synchronization beyond the join — the table is read-only.

---

### O.27 zstd Huffman X2 fast-path table

**What**: build libzstd's two-symbols-per-step Huffman decode table
(`HUF_DTableX2`) for high-`tableLog` codes, halving the per-symbol
overhead in the literals decode loop.

**Why deferred**: the round-one decoder in
[`src/decode/zstd_native/huffman.rs`](../src/decode/zstd_native/huffman.rs)
walks one symbol per bitstream lookup against a single 2048-entry
table — adequate for the throughput target. X2 is an additive boost
on a fraction of total runtime, not a blocker.

**Sketch**: build the X2 table alongside the X1 table when `tableLog ≥
11`; alternate-symbol entries point at a "consume the next bits and
then this second symbol" tail. The format is a libzstd implementation
detail (not in RFC 8478), so the design is "infer the contract from
libzstd's documentation, implement clean-room" — the same discipline
the rest of `zstd_native` was built under.

---

### O.28 zstd SIMD fast-path for sequence execution

**What**: SIMD-accelerate the inner loop of the sliding window's
`match_copy` for long matches with offsets ≥ 16, where vectorized
copies dominate the scalar 8-byte-word path.

**Why deferred**: the scalar implementation in
[`src/decode/zstd_native/window.rs`](../src/decode/zstd_native/window.rs)
handles overlap-by-design correctness and hits the throughput target.
SIMD is purely a throughput improvement and fragments the
implementation across architectures.

**Sketch**: in `match_copy`, branch on `offset >= 16 && remaining >=
16` and fall into a `_mm_storeu_si128` path on x86-64 / `vst1q_u8` on
aarch64; keep the scalar path as the fallback. Gate behind the same
`#[cfg]` shape the io_uring backend uses for its platform set.

---

### O.RAW.TARBUF TarSink write buffering

**Filed 2026-05-13 from
[`internal/PLAN_raw_row_throughput.md`](PLAN_raw_row_throughput.md)
§Deferred.**

**What**: wrap `TarSink`'s per-entry output file in a `BufWriter`
the same way Phase 1 of `PLAN_raw_row_throughput.md` wrapped
`RawSink`. The tar-sink writes per entry today, so a many-small-files
archive pays the same per-entry `write(2)` granularity that
`RawSink` paid before the wrap; a `BufWriter` collapses each entry's
writes into one or two syscalls.

**Why deferred**: the raw rows were the named gap; the `tar.gz` /
`tar.zst` rows the plan checked for "no regression" already sit at
**0.82×** / **0.52×** without this change. Promote only after a
profile on a many-small-files corpus shows per-entry sink writes
load-bearing again.

---

### O.RAW.XXH64SWAR Xxh64 SWAR / SIMD update loop

**Filed 2026-05-13 from
[`internal/PLAN_raw_row_throughput.md`](PLAN_raw_row_throughput.md)
Phase 3 (skipped).**

**What**: rewrite `Xxh64::update`'s four-lane stripe processor with
explicit SWAR / NEON intrinsics to push past LLVM auto-vectorization's
ceiling on `process_stripe`.

**Why deferred**: the Phase 0 anchor bench
([`tests/test_bench_hash.rs`](../tests/test_bench_hash.rs)) measured
peel's existing scalar `Xxh64` at **~23 GiB/s** on M4 Max — well above
the plan narrative's "current scalar ~3 GB/s" estimate that motivated
Phase 3 in the first place. LLVM is already auto-vectorizing the
unrolled four-lane loop. A 3× speedup over 24 GiB/s would land at
72 GiB/s, which is above realistic memory bandwidth on this
microarchitecture. Promote only if a profile on a different host or a
different workload (e.g., x86-64 / AMD Zen, or a sparse-fill payload
that fits the L1) shows `xxh64::update` load-bearing again.

---

### O.RAW.LINUXIOURING io_uring blocking-write zero-copy on the local raw path

**Filed 2026-05-13 from
[`internal/PLAN_raw_row_throughput.md`](PLAN_raw_row_throughput.md)
§Deferred.**

**What**: on Linux, replace the blocking `pwrite` path the `RawSink`
`BufWriter` ultimately calls with io_uring `IORING_OP_WRITE` submissions
fed off the decoder's output ring, so the syscall round-trip drops
out of the bench-grid wall time entirely.

**Why deferred**: macOS raw rows were the named gap; Phase 1's
1 MiB `BufWriter` plus Phase 2's source-side buffering already
collapsed the syscall pressure that profiled as the per-row floor.
Promote only after a Linux raw-row bench shows the blocking `pwrite`
path is still the binding constraint on that platform — the same
`splice(2)` / `copy_file_range(2)` posture this plan's §Deferred
section captured.

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

**Status: delivered in `PLAN_v2.md` §4 (2026-04-29).** Round-one
parses the [LZ4 Frame Format] header ourselves and feeds individual
blocks through `lz4_flex::block::decompress_into`; see
[`src/decode/lz4.rs`](../src/decode/lz4.rs). Frame boundaries are
surfaced at end-of-frame only — the only positions where a freshly
constructed decoder can correctly continue, since per-frame state
(block-max-size, checksum flags, …) is not serialized into the
checkpoint today. Per-block (within-frame) checkpoint granularity is
filed below as `O.7b`.

[LZ4 Frame Format]: https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md

---

### O.7b lz4 per-block frame boundaries

**Status: delivered (2026-04-30).** `frame_boundary()` now advances
on every successful block decode inside an LZ4 frame, paired with a
`decoder_state()` blob that carries the per-frame parameters
([`FrameContext`]: `block_max_size`, checksum flags, optional
content size, `bytes_decompressed`, and the running XXH32 content
hasher). The checkpoint format bumped to v5 with an opaque
[`Checkpoint::decoder_state`] field; older binaries refuse v5 with
[`CheckpointError::UnsupportedVersion`]. The decoder registry gains
a parallel `DecoderResumeFactory` hook (registered for `lz4` only);
the coordinator dispatches via the registry when a checkpoint
carries a blob, falling through to the regular factory otherwise.

A single-frame `.tar.lz4` whose archive has many tar members
(e.g. Polkachu's chain snapshots) now produces a checkpoint at
every block-boundary that aligns with a tar-member boundary,
instead of zero checkpoints across the entire run. A `kill -9`
mid-extraction loses at most one block's worth of decoded output
(64 KiB to 4 MiB depending on the producer's block-max-size).

[`Checkpoint`]: ../src/checkpoint.rs
[`Checkpoint::decoder_state`]: ../src/checkpoint.rs
[`CheckpointError::UnsupportedVersion`]: ../src/checkpoint.rs
[`FrameContext`]: ../src/decode/lz4.rs

---

### O.8 zip support

**Status: delivered in `PLAN_v2.md` §5 (2026-04-29).** Round-one
ships a second pipeline architecture in
[`src/download/zip_pipeline.rs`](../src/download/zip_pipeline.rs)
that drives extraction in central-directory order: the trailing
EOCD is fetched first, the central directory is parsed, and each
entry's compressed bytes are streamed through STORED / DEFLATE /
zstd into a per-entry [`ZipSink`](../src/sink/zip.rs) with the
same path-safety rules as `TarSink`. Hole punching is per-entry
(less effective than the streaming pipeline's per-frame discipline
but real for very large entries). Resume preserves
`entries_completed` plus the in-flight entry's index/offset; STORED
entries resume mid-entry, DEFLATE/zstd restart the entry from its
compressed start. Out-of-scope features (Zip64, encryption,
multi-disk, methods other than 0/8/93) surface as
`ZipError::UnsupportedFeature` with the specific feature named —
filed below as `O.8b`.

---

### O.8b zip extended-feature support (round-two follow-on)

**What**: features round-one of `PLAN_v2.md` §5 deliberately
deferred:

- **Zip64**: archives ≥ 4 GiB or with ≥ 65535 entries (sentinel
  `0xFFFF_FFFF` / `0xFFFF` in the EOCD or a CDE).
- **Traditional PKWARE encryption** and **AES / strong encryption**
  (general-purpose flag bits 0 and 6).
- **Multi-disk / spanned archives** (`disk_start != 0`).
- **DEFLATE64**, **BZIP2**, **LZMA-in-zip**, **PPMD**, **AES-99
  marker**, and any other compression method beyond STORED, DEFLATE,
  and zstd.
- **Self-extractor stubs**: data prepended to the LFH signature.

**Why deferred**: real-world zip archives users will actually run
`peel` against (GitHub release artifacts, npm tarballs published as
.zip, JDK distributions) almost never use any of these features.
Each one expands the audit surface, the dependency tree (AES needs
crypto), or both. Round-one refuses cleanly with
`ZipError::UnsupportedFeature` naming the specific feature so
users see "AES encryption is not supported", not "malformed
header".

**Sketch**: Zip64 needs a parallel parser path that reads the
Zip64 EOCD locator (`0x07064b50`) and EOCD record (`0x06064b50`)
ahead of the legacy EOCD. Encryption needs a dependency on a
crypto crate (and a careful look at what we want to support —
traditional PKWARE is cryptographically broken). DEFLATE64 likely
ships as a flate2 feature flag. Self-extractor stub support is
mostly a parser change to scan further back from the file end for
the EOCD signature. Promote when a real corpus exists where the
deferred features actually matter.

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

### O.29 zstd custom-dictionary support

**What**: decode zstd frames whose `Frame_Header_Descriptor` declares a
non-zero `Dictionary_ID`, including loading the dictionary's
literals/match tables and prior FSE distributions.

**Why deferred**:
[`src/decode/zstd_native/frame.rs`](../src/decode/zstd_native/frame.rs)
rejects non-zero `Dictionary_ID` cleanly, per the round-one scope.
Real-world `.tar.zst` archives don't use custom dictionaries (a niche
feature for repository-level deduplication, e.g. zstd-trained npm
packing); adds significant surface (dictionary file format,
table-pre-population semantics) for a use case our users haven't
asked for.

**Sketch**: implement the [`Dictionary_Format`] parser; pre-populate
the decoder's `prev_huffman` / `prev_fse_*` / repeat-offset slots from
the dictionary at frame start. Surface `--zstd-dict <path>` on the CLI
to load a single dictionary, or read from a known well-known location.

[`Dictionary_Format`]: https://datatracker.ietf.org/doc/html/rfc8478#section-5

---

### O.30 zstd `windowLog > 27` for `--long` archives

**What**: decode zstd frames with `windowLog > 27` (windows larger
than 128 MiB), which `zstd --long=N` produces with `N` up to 31
(2 GiB on 64-bit hosts).

**Why deferred**: the 128 MiB cap was chosen so the resume blob
(window contents + small constant) stays bounded — see
`PLAN_zstd_block_decoder.md` §Risks #2. Lifting the cap means
multi-GiB resume blobs, which interacts poorly with checkpoint-write
cost. Real-world `tar.zst` corpora don't use `--long > 27`; promoting
this should pair with a checkpoint-blob diffing scheme so the on-disk
cost of every-block checkpoints stays reasonable.

**Sketch**: lift the cap in
[`src/decode/zstd_native/frame.rs`](../src/decode/zstd_native/frame.rs)
behind a delta-encoded resume blob: only persist the slice of the
window that changed since the previous checkpoint, plus a back-
reference to the prior blob. Or trade granularity — write checkpoints
every Nth block, with N scaled by window size — and accept that resume
loses up to N blocks of work.

---

## Reliability

### O.10 Multi-mirror downloads

**Status: delivered in `PLAN_v2.md` §13 (2026-04-30).** `--mirror <URL>`
is repeatable; the positional URL is the primary, every `--mirror` is
an alternate. At startup the coordinator runs `HEAD` against every URL
in parallel and drops any whose `Content-Length` (or, when `--sha256`
is unset, `ETag` / `Last-Modified`) disagrees with the primary. The
scheduler picks per ranged GET, biased toward the fastest live mirror
via per-mirror health (success rate, latency p95); a failing mirror
is excluded for 30 s before being retried instead of failing the run.
`--sha256` cross-checks every mirror against the same expected digest;
the §11 CRC32C drift detection runs across mirrors as well as across
resume.

---

### O.11 Bandwidth limiting

**Status: delivered in `PLAN_v2.md` §14 (2026-04-30).** `--max-bandwidth
<RATE>` accepts decimal (`K`/`M`/`G`/`T`, 1000-based per network
convention) and binary (`Ki`/`Mi`/`Gi`/`Ti`) suffixes; trailing `B`
and `/s` are accepted and ignored. The cap is **aggregate** across all
workers and (per §13) all mirrors via a shared token-bucket rate
limiter — bytes are tokens, refill rate is the configured limit,
bucket capacity is `max(1 MiB, rate × 250 ms)` to absorb bursts.
Workers acquire tokens *before* dispatching each socket read, so the
limiter sits above the IO backend and applies uniformly to both the
blocking and uring paths.

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

**Status: delivered in `PLAN_v2.md` §10 (2026-04-30); extended by §11
(mid-flight drift detection).** `--sha256 <HEX>` verifies the
assembled compressed source against the expected 64-hex digest. The
implementation is a hand-rolled, resumable SHA-256
([`src/hash/sha256.rs`](../src/hash/sha256.rs)); the running state is
serialized into the checkpoint at every quiescent frame boundary so a
resumed run produces a digest byte-identical to a clean run (and to
`sha256sum` on the original compressed file). Tests cross-check
against the `sha2` dev-dependency and the NIST FIPS 180-4 vectors.
A mismatch raises `IntegrityError::HashMismatch` with an exit code
distinct from generic IO failure. Streaming pipeline only — `.zip`
archives extract per-entry and integrity checking does not extend to
that path in round-one (filed implicitly under `O.8b` if needed).
**§11** layers per-chunk CRC32C fingerprints on top: every Nth chunk
(default `N = 32`) is re-fetched as a probe and aborts with
`SourceChangedDuringDownload` on mismatch; resume probes a random
already-complete chunk against the live source and aborts with
`SourceChangedSinceCheckpoint` on mismatch. ETag handling was
tightened in the same phase to honor strong/weak distinctions and
Last-Modified.

---

## Operational features

### O.14 macOS `F_PUNCHHOLE` puncher

**Status: delivered in `PLAN_v2.md` §12 (2026-04-30).**
[`MacosPuncher`](../src/punch.rs) calls `fcntl(fd, F_PUNCHHOLE,
&fpunchhole_arg)` directly via `libc`, with the same
`ENOTSUP`/`EINVAL` graceful-degrade path as `LinuxPuncher`.
`default_puncher()` selects the right implementation by
`cfg(target_os)`, so the macOS build links the macOS puncher and the
blocking IO backend (the io_uring path stays Linux-only). On-disk
source footprint shrinks during extraction on APFS the same way it
does on ext4.

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

**Status: HTTP/2 delivered (2026-04-30).** The hand-rolled HTTP/1.1
implementation was replaced with `hyper` + `hyper-util` +
`hyper-rustls`, ALPN-negotiating between H1 and H2 per origin. A
current-thread `tokio` runtime is owned by `http::Client` and confined
to it; the rest of the codebase remains synchronous. See
`ENGINEERING_STANDARDS.md` §2.3 / §2.5 for the policy text and
`src/http/client.rs` for the implementation. The H1 throughput
argument from the deferred sketch still holds — H2 is on by default
because hyper does both, not because we expect a speedup over N
parallel ranged H1 streams; it exists so origins that only speak H2
work without extra config.

**HTTP/3 (QUIC)** remains deferred: a much larger lift, no clear win
for bulk transfer over a single ranged TCP fan-out, and would require
a QUIC stack on top of the current TLS dependency.

---

### O.18 Pluggable destination

**What**: write extracted output to S3, GCS, etc., not just local
disk.

**Why deferred**: nice-to-have, big surface area, requires those
SDKs (which conflict with our dependency policy). Likely better
served by piping to a separate uploader tool.

---

### O.19 Progress UI improvements

**Status: delivered in `PLAN_v2.md` §6 (2026-04-30).** No new TUI
dependency. [`progress.rs`](../src/progress.rs) renders a redrawn
multi-line block with hand-rolled ANSI (`\x1b7`/`\x1b8` save/restore,
`\x1b[K` erase-to-EOL): percent complete, compressed bytes
downloaded / total, decompressed bytes written, download rate
(rolling 5 s), disk write rate (rolling 5 s), ETA (whichever rate is
the bottleneck), and active worker count. `IsTerminal` switches the
non-TTY path to periodic `tracing::info!` lines. The `ProgressState`
ring buffer added here is the same one the §8 adaptive chunk-size
policy and the §13 multi-mirror health tracker hang off of, so future
phases extend it instead of building parallel state.

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

### O.32 Barrier-style checkpoint publication

**Status: delivered in `PLAN_checkpoint_cadence_throughput.md` Phase 1
(2026-05-04).** The per-checkpoint `SparseFile::sync_all` and `.tmp`
file `File::sync_all` were two `F_FULLFSYNC` calls on macOS (~9 ms
and ~5 ms respectively); plus a parent-directory `sync_all` on every
write. Replaced with [`SparseFile::order_writes`](../src/download/sparse_file.rs)
and a tmp-file barrier path in [`Checkpoint::write_timed`](../src/checkpoint.rs):
macOS uses `fcntl(F_BARRIERFSYNC)`, Linux uses `fdatasync(2)`, other
Unix falls back to full `sync_all`. The barrier guarantees that
pre-barrier writes hit stable storage *no later than* the subsequent
`rename`, which is exactly what publication needs (resume contract:
"if the renamed `.peel.ckpt` is observed by a future run, every page
the bitmap claims durable is at least as durable as the checkpoint").
Parent-directory `fsync` only fires when the rename creates a new
entry. Fast-row 10 Gbps `Pwrite` improved 75–84 %; observer-time
fsync subtotal dropped 81–85 %.

---

### O.33 Rate-aware checkpoint cadence floor

**Status: delivered in `PLAN_checkpoint_cadence_throughput.md` Phase 2
(2026-05-04).** Pre-Phase-2, the cadence throttle used a fixed
`checkpoint_min_bytes = 8 MiB` floor. At 10 Gbps that floor clears
every ~6 ms, so the bench produced 32 checkpoints in a 0.7 s run —
faster than the OS could durably publish them. The new
[`CoordinatorConfig::checkpoint_target_interval`](../src/coordinator.rs)
(default 200 ms) scales the live floor with realized download
throughput: `live_floor = max(configured_floor, realized_bps × target_interval)`.
At 10 Gbps the realized term raises the floor to ~250 MB and the
bench drops to 2–3 checkpoints (10–16× reduction). At low rates the
configured floor still wins (cadence is rate-invariant under everyday
WAN). `checkpoint_min_interval` (`2 s` default) remains the upper
bound on resume granularity regardless. Combined with `O.32`, the
fast-codec rows on the README grid dropped from a 3× peel:`curl|tar`
ratio at 10 Gbps to **<1×** — peel now beats `curl | tool` across the
whole 10 Mbps – 10 Gbps range for streaming codecs.

---

### O.34 Resume-blob dedup + single-memcpy checkpoint write

**Status: delivered in `PLAN_checkpoint_blob_dedup.md` Phases 1–3
(2026-05-04).** Per-checkpoint cost on `tar.xz default_10gbps_cap`
was 28.5 ms / ckpt pre-plan, broken down as ~15.5 ms in
`Decoder::decoder_state()` (8 MiB dict memcpy + scalar CRC32 over the
whole resume blob) plus ~9.5 ms in `Checkpoint::serialize` (8 MiB
dict body-extend + scalar fnv1a64 over the body). Two fixes:

1. **Drop the redundant inner CRC32** from the xz resume blob's
   trailer. The surrounding `Checkpoint` body's outer fnv1a64 already
   covered every byte the inner CRC32 covered (plus URL, bitmap,
   sink_state). New format version `XDR2` writes without the trailer;
   `XDR1` is read-only for back-compat. Cross-format audit confirmed
   only xz_native carried a redundant trailer (zstd's `xxh64_state`,
   lz4's xxh32, deflate-native's `running_crc32` are all load-bearing
   format state, not whole-blob trailers). [`src/decode/xz_native/resume.rs`](../src/decode/xz_native/resume.rs).
2. **Single-memcpy data path.** Replaced the
   `Decoder::decoder_state(&self) -> Option<Vec<u8>>` trait method
   with `decoder_state_into(&self, &mut Vec<u8>) -> bool` plus a
   `decoder_state_size_hint`. `CheckpointInfo` now carries
   `decoder: &dyn StreamingDecoder` (borrow); the streaming-pipeline
   observer calls `Checkpoint::write_timed_with(path, hint, |body| info_cb.decoder.decoder_state_into(body))`,
   which threads the dict bytes from the LZMA decoder's ring buffer
   directly into the `Checkpoint` body buffer. Four pre-plan memcpies
   (ring → recent() Vec → blob Vec → CheckpointInfo clone → body)
   collapse to **one** (ring → body). [`src/decode.rs`](../src/decode.rs),
   [`src/checkpoint.rs`](../src/checkpoint.rs),
   [`src/extractor.rs`](../src/extractor.rs),
   [`src/coordinator.rs`](../src/coordinator.rs).

Result on the README's bench grid `tar.xz` row: **2.38× → 1.91×** at
1 Gbps · 128 MiB and 10 Gbps · 256 MiB. Per-checkpoint cost on
`tar.xz default_10gbps_cap` dropped from 28.5 ms to 12.8 ms (-55 %).
The decoder-only floor (`bench_xz_native_*`) and fast-format rows
were untouched; ZIP crash-resume harness and `bench_zip_extraction`
green.

---

### O.35 Hardware-accelerated `Checkpoint` body hash

**What**: replace the scalar fnv1a64 over the `Checkpoint` body
([`src/checkpoint.rs`](../src/checkpoint.rs)) with a hardware-
accelerated CRC32C (or xxh3) when the target CPU exposes the
relevant intrinsic.

**Why deferred**: post-`O.34`, the residual per-checkpoint cost on
`tar.xz default_10gbps_cap` is **8.7 ms / ckpt**, of which ~8.5 ms is
the scalar fnv1a64 over the ~9 MiB body (LZMA dict + URL + bitmap +
sink_state). On a 184-checkpoint run that's 1.6 s of wall-clock —
the single-largest line item left in the
`bench_throttled_realistic_grid` `tar.xz` row. M4 Max has CRC32C in
the base ISA; x86-64 has CRC32C intrinsics; aarch64 added CRC32 in
ARMv8. A SIMD xxh3 implementation would be even faster but adds an
algorithm we don't already ship.

**Why this is a separate plan from `O.34`**: changing the body hash
from fnv1a64 to anything else bumps the `Checkpoint` on-disk format
version. That has a wider compatibility surface than the resume blob
inside it (every existing `.peel.ckpt` on user disks must be readable
under the new version), and warrants its own PLAN doc. The right
shape is probably "write old + new in parallel for one release, then
flip the writer".

**Sketch**: pick the algorithm based on a bench against the existing
fnv1a64 on a 9 MiB body fixture. Add a `Checkpoint::FORMAT_VERSION`
bump from `7` to `8`; the deserializer dispatches on the new version
and uses the new hash, keeping the v7 path for back-compat. The
`Checkpoint::write_timed_with` and `serialize_with` shapes
(`O.34`-shipped) are already the right surface for a one-line
algorithm swap. **Expected savings**: ~5–7 ms / ckpt on
`tar.xz default_10gbps_cap`, taking the row from ~1.91× toward
~1.5× independent of any decoder work. Smaller and decoupled scope
from `PLAN_xz_parallel_block_decode.md`'s ≤ 1× target.

---

### O.31 zstd differential fuzz harness

**What**: a `cargo-fuzz` target driving the
[`zstd_native`](../src/decode/zstd_native/) decoder against a curated
corpus of real-world `.tar.zst` fixtures, cross-checked byte-identical
against libzstd.

**Why deferred**: `PLAN_zstd_block_decoder.md` Phase 6 ships a
500-fixture differential against the `zstd` crate as a
dev-dependency, which catches the obvious shapes. Sustained fuzzing
is a separate investment — corpus curation, CI cycles, triage
workflow. Same posture as `O.20`, and ideally promoted alongside it
so the harness wires both targets in one go.

**Sketch**: a `fuzz_targets/zstd_decode.rs` that takes arbitrary bytes,
runs them through both `zstd_native::Decoder` and `zstd::stream::
Decoder`, asserts the outputs match (or both error). Seed corpus
from real `.tar.zst` archives plus the existing Phase 6 fixtures. If
this lands as part of an OSS-Fuzz integration (per `O.20`), the same
infrastructure covers both.

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

## RAR5 follow-ons (filed 2026-05-09 from `internal/PLAN_rar.md`)

These items were filed when `internal/PLAN_rar.md` §§1–3 landed
(STORED-method extraction). The hand-rolled standard-RAR5 decoder
that unblocks the rest is itself a multi-phase sub-plan
(`internal/PLAN_rar5_decoder.md`); promote items here as that plan
makes them tractable.

### O.RAR.MV Multi-volume RAR archives

**What**: extract `archive.part01.rar` … `archive.partNN.rar`
without first concatenating the volumes locally.

**Why deferred**: the §1 walker rejects multi-volume archives
with a precise `RarError::UnsupportedFeature` naming the
detected volume number, and the §3 pipeline never reaches the
data area. Round-one is single-volume only. Adding multi-volume
needs either a CLI affordance for naming the parts (`peel
arch.part01.rar --rar-volumes 'arch.part??.rar'`) or
URL-pattern detection.

### O.RAR.ENC RAR5 encryption

**What**: AES-256 header-encryption and per-file encryption with
a passphrase prompt.

**Why deferred**: round-one rejects encryption headers with
`UnsupportedFeature { feature: "encryption (header)" }`.
Implementing the AES path is straightforward (the existing TLS
stack already pulls `ring`), but the passphrase-prompt UX, the
key-derivation parameters (PBKDF2-SHA256), and the key-cache
semantics warrant their own design pass.

### O.RAR.SFX Self-extracting archives

**What**: detect the RAR5 magic past offset 0 (typical SFX
archives prepend an executable preamble) by scanning the first
N bytes — same logic as `find_eocd` in `src/zip/format.rs`.

**Why deferred**: round-one's magic-byte detector deliberately
scans only offset 0 (`PLAN_rar.md` §0.3). SFX users today must
pass `--format rar` or strip the preamble themselves.

### O.RAR.RECOVERY Reed-Solomon recovery records

**What**: validate (and offer to repair) corrupted entries
using RAR5's optional Reed-Solomon recovery records.

**Why deferred**: recovery records ride in service headers
(type 3) which round-one's pipeline skips. Parsing them is
straightforward; the repair logic and the on-disk fallback
ergonomics need more thought.

### O.RAR.HASH_EXTRA File-header BLAKE2sp digest from extra-record

**What**: decode the `BLAKE2sp` digest that lives in the
file-header extra area (record type `0x02`) and feed it to the
sink as the per-entry expected-hash. Today the sink computes
the running BLAKE2sp internally but only validates against an
expected digest when one is plumbed through; the §1 parser
does not yet decode extra-record subtypes.

**Why deferred**: round-one §3 captures the field-direct
`data_crc32` path (file-flags bit 2). The extra-record path
adds wider parser surface and richer extras (encryption salt,
high-precision time, redirect). Filed so the sink stays
forward-compatible: when the parser surfaces an
`expected_blake2sp`, the sink already validates it.

### O.RAR.CUSTOMFILTER RAR-VM custom filter slot

**What**: support archive-defined filters (the RAR5 spec lets
the encoder ship a custom bytecode filter).

**Why deferred**: see `internal/PLAN_rar5_decoder.md` §C2. `rar a`
does not emit custom filters by default, so the corpus is
small. Files alongside the §C/§D lift.

### O.RAR.PPMD_RESUME Mid-entry resume across PPMd-II / LZSS

**What**: serialize the PPMd-II range-coder state in the
mid-entry decoder snapshot so resume across a PPMd-II block
boundary produces byte-identical output.

**Why deferred**: see `internal/PLAN_rar5_decoder.md` §F1. The LZSS
case is straightforward; PPMd-II's context-model state is
larger and more error-prone to serialize.

### O.RAR.MULTITHREAD Multi-threaded RAR5 decode

**What**: parallel decode within a single entry (or across
non-solid entries) to reduce wall-clock for big archives.

**Why deferred**: §G of `internal/PLAN_rar5_decoder.md` profiles
the hot paths first; promote this only if profiling shows the
single-threaded decode bound.

### O.RAR4 RAR4 legacy format

**What**: support the pre-2013 RAR4 format alongside RAR5.

**Why deferred**: the RAR4 format and its compression methods
are wholly different from RAR5 — supporting both doubles the
scope without doubling the value (the corpus has been migrating
to RAR5 for a decade). Lower priority than `O.RAR.ENC` /
`O.RAR.MV`. Round-one rejects with a precise
`RarError::UnsupportedFormatVersion { major: 4, minor: 0 }` so
the diagnostic is specific.

---

## When to revisit this list

**This is the moment, again.** The MVP shipped 2026-04-29, round
one of `PLAN_v2.md` shipped on top of it (§§6, 7, 7b, 8–14
delivered), and the `PLAN_zstd_block_decoder.md` plan shipped
2026-05-01 (phases 1–10). What's left here splits cleanly into four
buckets:

- **Round-two follow-ons filed during round one** — `O.6b` (xz
  per-Block boundaries), `O.8b` (zip Zip64/AES/extra-method support).
  (`O.7b` was filed during round one and delivered immediately
  after.) These are concrete candidates because the round-one phases
  that filed them named the exact corpora and motivations that would
  justify promoting them.
- **zstd round-two follow-ons** — `O.26`–`O.28` (perf: multi-stream
  literals, Huffman X2, sequence-execution SIMD), `O.29`–`O.30`
  (format: custom dictionaries, `windowLog > 27`), `O.31` (fuzz
  harness). Promote a perf item only if profiling on a real corpus
  shows the relevant hot loop dominating; promote a format item only
  if a real archive trips the round-one rejection path.
- **Performance items still deferred** — `O.4` (parallel zstd block
  decoding), `O.5` (NUMA placement). Both remain niche; promote only
  if profiling on a real corpus shows them load-bearing.
- **Operational and metadata items** — `O.9` (native peel container
  format), `O.12` (resume across version changes), `O.15`–`O.18`
  (Windows, daemon/library mode, HTTP/2/3, pluggable destinations),
  `O.20`–`O.25` (continuous fuzzing, real-world corpus tests,
  differential testing, file modes, xattrs, links). Larger surface,
  larger commitment; pick deliberately.

Look at this list and ask:

1. What did real users actually need that we deferred?
2. What did we discover during round one that changed our priors?
3. Which items are dependencies of others?

Then a *new* successor plan (`PLAN_v3.md` or similar) gets written
with a focused slice of these promoted to scope, in dependency order,
with the same discipline as `PLAN.md` and `PLAN_v2.md`. Don't try to
"knock out a few optimizations" outside of that process.
