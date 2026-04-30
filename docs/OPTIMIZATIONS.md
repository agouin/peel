# Optimizations & Future Work

> **Status: PLAN_v2 round one shipped (2026-04-30).** The MVP in `PLAN.md`
> landed 2026-04-29 (phases 1–10), and round one of `PLAN_v2.md` followed
> immediately on top, delivering `O.1`, `O.2`, `O.3`, `O.6`, `O.7`, `O.8`,
> `O.10`, `O.11`, `O.13`, `O.14`, and `O.19`. Their entries below are
> annotated **"delivered in PLAN_v2 §<phase>"** and kept as historical
> record — do not re-pull them. The remaining items are eligible for
> prioritization, but the rule still stands: **promotion from this file
> to active work happens through deliberate human review**, not by an agent
> deciding "while I'm here…" When an item is selected, it should be lifted
> into a successor plan (a new sequenced doc, same discipline as the
> original `PLAN.md`) before implementation begins.

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

### O.7b lz4 per-block frame boundaries (round-two follow-on)

**What**: surface *per-block* frame boundaries inside a single LZ4
frame, instead of only the end-of-frame boundary `PLAN_v2.md` §4
settled for. Today a single-frame `.tar.lz4` admits no within-source
restart point and resumes re-decode the whole frame — for a typical
single-block-per-tar-member encoding this is fine, but a producer
that emits one big multi-megablock frame pays the full re-decode cost
on resume.

**Why deferred**: round-one would need to extend the [`Checkpoint`]
format with a serialized [`FrameContext`] (`block_max_size`,
checksum flags, optional content size, the running content hash, …)
so a freshly constructed decoder restarted at a mid-frame block
boundary could continue. That's a `format_version` bump and a wider
diff than the round-one slot wants. Promote when a real corpus
exists where the slow-resume cost matters.

**Sketch**: extend `checkpoint::SinkState` (or a new sibling) with
the per-frame parameters captured by `parse_frame_header`. On resume,
seed the decoder's `State::InFrame { ctx }` from the checkpoint
instead of starting in `BetweenFrames`. Surface every post-block
offset through `frame_boundary` once that contract is genuine.

[`Checkpoint`]: ../src/checkpoint.rs
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

**This is the moment, again.** The MVP shipped 2026-04-29 and round
one of `PLAN_v2.md` shipped on top of it (§§6, 7, 7b, 8–14
delivered). What's left here splits cleanly into three buckets:

- **Round-two follow-ons filed during round one** — `O.6b` (xz
  per-Block boundaries), `O.7b` (lz4 per-block boundaries), `O.8b`
  (zip Zip64/AES/extra-method support). These are the most concrete
  candidates because the round-one phases that filed them named the
  exact corpora and motivations that would justify promoting them.
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
