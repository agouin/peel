## Plan: peel post-MVP, round one

> **Status: drafted 2026-04-29, not yet started.** This is the successor
> plan to `PLAN.md` and supersedes the "promotion happens through a new
> sequenced doc" requirement at the top of `OPTIMIZATIONS.md`. Items here
> were promoted *deliberately* from `OPTIMIZATIONS.md`; the rest of that
> file remains deferred. Do not pull from `OPTIMIZATIONS.md` while this
> plan is in flight — finish a phase, demo it, then move on.

This plan covers two rounds of work, in order:

1. **Format support** — broaden the set of archives `peel` can extract.
2. **Pipeline & UX improvements** — make the existing extraction loop
   faster, more observable, and more robust under real-world conditions.

The same sequencing discipline as `PLAN.md` applies: each phase ends with
a runnable demo, and §N+1 does not begin until §N's demo passes.

---

## Hard constraints (carried forward from `PLAN.md`)

- Std-first; the `ENGINEERING_STANDARDS.md` §2 allowlist still rules.
  Several phases in this plan call out crates that are *not* on the
  allowlist — those calls are flagged as "needs approval before
  Cargo.toml lands" and require an explicit decision before
  implementation begins.
- No async runtime. The io_uring phase (§9) is the most likely place
  for a slip; it must use direct syscalls or a sync wrapper, not a new
  reactor.
- Linux-first. Phases that add macOS- or Windows-specific code are
  additive behind the existing `PunchHole` trait pattern.
- Hand-rolled HTTP/1.1 stays hand-rolled. Multi-mirror (§16) and
  bandwidth limiting (§17) extend the existing client; they do not
  introduce `hyper`/`reqwest`.
- Backwards-compatible checkpoints. Any phase that grows the
  checkpoint format bumps `format_version` and provides a clean
  rejection path for older readers (per `checkpoint.rs` §9.2 of
  `PLAN.md`). Migration tables are still out of scope (`O.12`).

## What this plan deliberately does not include

- Items `O.4` (parallel zstd block decoding), `O.5` (NUMA placement),
  `O.9` (native peel container format), `O.12` (resume across version
  changes), `O.15` (Windows support), `O.16` (daemon / library mode),
  `O.17` (HTTP/2 / HTTP/3), `O.18` (pluggable destination), and
  `O.20`–`O.25` (continuous fuzzing, real-world corpus tests,
  differential testing, file modes, xattrs, links). Those stay in
  `OPTIMIZATIONS.md` for a future planning round.
- Format detection by content sniffing of *every* byte: we sniff the
  magic-byte prefix only, not arbitrary content. Heuristic auto-detect
  beyond magic bytes is out of scope.

---

## Phase A — Format support

The format-support phases share one cross-cutting prerequisite: today
the [`DecoderRegistry`](../src/decode.rs) keys decoder factories on
file-name suffixes only. Each new format extends *both* the suffix map
and a new magic-byte map. §1 lays the groundwork; §2–§5 each register
their format on both maps.

### §1. Magic-byte format detection

**What**: extend `DecoderRegistry` so that, in addition to the existing
suffix lookup, it can identify a format from the first ≤ 1 KiB of the
source. Use it as a fallback (or override) when the URL's suffix is
ambiguous, missing, or contradicts the bytes.

**Why now**: every later format-support phase needs to plug into this.
Doing it once, well, and refactoring zstd/gzip behind it costs less
than retrofitting four formats later.

**Sketch**:

1. Add `MagicSignature { offset: u16, bytes: &'static [u8] }` and a
   parallel `magics: Vec<(MagicSignature, DecoderFactory)>` to the
   registry. Most formats live at offset 0; tar lives at offset 257.
2. Add `factory_for_prefix(&[u8]) -> Option<DecoderFactory>` —
   longest-match wins, same rule as suffix lookup.
3. Coordinator change: after the first `CHUNK_SIZE`-or-`max_magic_window`
   bytes are downloaded (whichever is smaller), call
   `factory_for_prefix` if `factory_for_path` returned `None` *or* if
   the resolved factories disagree. Disagreement aborts with a clean
   `FormatMismatch` error rather than silently picking one — the user
   intent (URL suffix) and the file content (magic) disagree, and we
   refuse to guess.
4. Retrofit `.zst`/`.zstd` and `.gz` registrations to also publish
   their magic signatures (zstd: `28 B5 2F FD` at 0; gzip: `1F 8B` at 0).
5. CLI flags for the disagreement / unknown cases:
   - `--format <name>` forces a specific decoder, bypassing both
     suffix and magic detection (e.g., for URLs like
     `https://example.com/download?id=42` where the suffix is
     unhelpful).
   - `--force-format-from-magic` opts in to "trust the magic when
     suffix and magic disagree" — same workflow without having to
     name the format. Mutually exclusive with `--format` (clap
     `ArgGroup`).
   Both default off; the bare `peel <url>` path keeps the hard-error
   behavior so silent format swaps cannot happen by accident.

**Demo**: a test that points the coordinator at four local files —
`x.zst`, `x.bin` (zstd content, no suffix), `x.gz` (zstd content,
*wrong magic vs. suffix*), and the same wrong-suffix case with
`--force-format-from-magic` — and verifies: (1) suffix path works,
(2) magic-only path works when no suffix is registered,
(3) suffix/magic mismatch without override aborts cleanly with
`FormatMismatch`, (4) the same mismatch *with* override extracts
correctly and emits a `warn!` recording which signal won.

---

### §2. Uncompressed `.tar` support

**What**: extract uncompressed tar archives streamed over HTTP.

**Why now**: it's the simplest new format (no decompression layer),
exercises the §1 magic-byte path (tar's `ustar` magic is at offset
257, the only registered format that doesn't live at 0), and shakes
out any "decoder == identity" assumptions in the extractor that the
zstd-only MVP lets through.

**Sketch**:

1. New `decode/identity.rs`: a `StreamingDecoder` that owns its source
   and copies bytes verbatim into the sink in bounded chunks (matches
   the ~1 MiB step size the zstd impl uses). `bytes_consumed()` equals
   bytes written so far. `frame_boundary()` returns `Some(bytes_consumed)`
   on every step — the whole stream is one big restart-aligned region,
   so the existing checkpoint cadence policy still works without
   special-casing.
2. Register `.tar` (suffix) and the `ustar\0` / `ustar  \0` magic at
   offset 257 (read window must be ≥ 265 bytes).
3. The extractor's existing `TarSink` already handles the byte stream;
   no change needed there.
4. CLI: `peel https://example.com/dataset.tar -C ./out` should work
   without any new flag.
5. Edge cases worth testing explicitly: archives < 1 KiB (the magic
   window is bigger than the file); archives where the first member is
   a PAX/GNU extended header (offset 257 still ustar but the parser
   needs to traverse the extension); empty archives (two zero blocks
   only).

**Demo**: north-star use case but against a `.tar` URL; crash-test
harness covers it.

---

### §3. xz / LZMA support (`O.6`)

**What**: support `.tar.xz` and bare `.xz` archives.

**Why now**: `tar.xz` is the dominant format for several large public
datasets (some Wikipedia dumps, several Linux distro source tarballs)
that users will hit before they hit `.tar.lz4` or `.zip`.

**Dependency**: `xz2` (bindings to upstream `liblzma`). **Approved
2026-04-29** and added to `ENGINEERING_STANDARDS.md` §2.2. The
pure-Rust alternative `lzma-rs` was considered and rejected (less
battle-tested, performance gap, similar block-introspection
weakness).

**Sketch**:

1. `decode/xz.rs`: streaming wrapper around `xz2::stream::Stream` (the
   raw-API layer, not `XzDecoder`'s `Read` adapter — we want explicit
   step boundaries, same shape as the zstd implementation).
2. **Frame boundaries**: xz Streams contain Blocks; resume to a Block
   start is correct. The pragmatic MVP-of-xz approach is to treat the
   *whole* xz Stream as one frame for checkpointing — i.e.,
   `frame_boundary()` returns `None` until the Stream ends, then
   returns the post-Stream offset. That means resume across crash-mid-xz
   re-decompresses from the Stream start (we still don't re-download),
   which is acceptable because xz decompression is much faster than xz
   network downloads and dataset-scale users are network-bound.
   Smarter block-boundary detection is a follow-on (filed below).
3. Register `.xz`, `.tar.xz`, and the magic `FD 37 7A 58 5A 00` at
   offset 0.
4. `decoder_position` semantics: continues to be the source-stream
   offset, which is *Stream-byte* progress — coarse for xz but
   correct.
5. Multi-Stream xz files (`xz --keep` concat output): the wrapper
   loops `Stream::new_stream_decoder` per Stream and exposes each
   Stream-end as a frame boundary.

**Decision (2026-04-29)**: round-one ships per-Stream granularity. The
limitation is real for default-encoded `.tar.xz` (which is most of
them, and which is single-Block — meaning *no implementation* can
checkpoint within the file; the format itself does not contain a
restart point). Per-Block granularity helps only the multi-threaded /
concatenated case. File a per-Block follow-on as `O.6b` in
`OPTIMIZATIONS.md` once §3 lands; promote it deliberately if real
users hit the slow-resume cost.

**Demo**: `peel https://.../linux-6.x.tar.xz -C ./linux` extracts
correctly; crash-test harness covers `.tar.xz`.

---

### §4. lz4 support (`O.7`)

**What**: support `.tar.lz4` and bare `.lz4` archives in the
[LZ4 Frame Format] (RFC-style spec at github.com/lz4/lz4/blob/dev/doc).

[LZ4 Frame Format]: https://github.com/lz4/lz4/blob/dev/doc/lz4_Frame_format.md

**Why now**: not because lz4 is widely used in published archives —
it isn't (per `O.7`) — but because lz4 frames have *clean*, cheap
block boundaries (every block carries a 4-byte length prefix), so it
gives us a second post-MVP format with better checkpoint granularity
than xz, which is useful for testing the §1 magic-byte path against
something that isn't ustar-at-257.

**Dependency**: `lz4_flex` (pure Rust, no C dep, MIT/Apache).
**Approved 2026-04-29** and added to `ENGINEERING_STANDARDS.md`
§2.2. The C-binding alternative `lz4` was considered and rejected
(extra build-time complexity for no functional gain in our use
case).

**Sketch**:

1. `decode/lz4.rs`: streaming wrapper that parses the Frame Format
   header itself (it's small — magic + flags + content size + HC) and
   feeds blocks one at a time through `lz4_flex::block::decompress_into`.
   This avoids relying on whatever streaming API the crate exposes for
   its frame layer (which has been less stable than the block layer).
2. Frame boundaries: every decoded block ends at a known source
   offset; `frame_boundary()` returns the post-block offset on every
   step.
3. Register `.lz4`, `.tar.lz4`, magic `04 22 4D 18` at offset 0.
   (Skippable frames `184D2A50`–`184D2A5F` are also valid prefixes —
   skip them transparently before locating the real frame.)
4. Content-checksum and block-checksum flags: validate when present;
   surface a `DecodeError::Read` on mismatch with offset context.

**Demo**: round-trip a 100 MB synthetic file through `lz4` and `peel`,
verify byte-identical extraction; crash-test covers `.tar.lz4`.

---

### §5. zip support (`O.8`)

**What**: stream-extract `.zip` archives.

**Why now and why last**: zip's central-directory-at-the-end design is
fundamentally hostile to the §6.x streaming pipeline. This phase is
deliberately the largest in Phase A because it is essentially a
*second pipeline architecture*. We do it last in this plan so all the
other format-support work — and the §1 magic-byte detection — is
already in place to fall back on.

**Dependency**: none. The CD parser and per-entry header parser are
hand-rolled, matching the precedent set by tar in `PLAN.md` §7.3.
The PKWARE APPNOTE is the spec. DEFLATE comes from existing
`flate2`; STORED is a passthrough; zstd comes from the existing
decoder.

**Round-one scope (locked 2026-04-29)**: STORED + DEFLATE + zstd
entries. AES / password-protected entries, Zip64 end-of-central-
directory locator, multi-disk archives, and any other PKWARE
extensions are out of scope and will be filed as `O.8b` in
`OPTIMIZATIONS.md` after §5 lands. Encountering an unsupported
method or feature returns a clean `ZipError::UnsupportedFeature`
naming the specific feature, not a generic parse failure — the user
should see "AES encryption is not supported", not "malformed
header".

**Sketch**:

1. New `download/zip_pipeline.rs` (separate from the streaming
   pipeline): the URL is opened with `HEAD`; a small ranged GET fetches
   the trailing `ZIP_END_OF_CENTRAL_DIRECTORY` (variable-size, but
   bounded by 64 KiB + comment) — typically the last 64 KiB suffices,
   with a fallback to a larger window if the comment overflows.
2. Parse the central directory into a list of entries with
   `(name, method, compressed_size, uncompressed_size, local_header_offset, crc32)`.
3. For each entry, issue a ranged GET for the local file header +
   compressed data. The download scheduler is reused but with a
   *per-entry* chunk plan rather than a global one — workers are
   assigned to entries, not to byte chunks of one big file.
4. Decompress per-entry using either an identity passthrough
   (`STORED`), DEFLATE (existing `flate2`), or zstd (we already have
   the decoder). Other methods return `ZipError::UnsupportedFeature`
   with the method name surfaced.
5. Sink: existing `TarSink` is replaced with a new `ZipSink` that
   handles per-entry path safety (same anti-traversal rules as
   `TarSink`) and writes one entry at a time.
6. Hole-punching: less effective for zip because we hole-punch
   per-entry rather than continuously. Still useful for very large
   single entries; degrades gracefully.
7. Checkpoint format gains a `ZipState { entries_completed: Vec<u32>,
   current_entry: Option<u32>, current_entry_offset: u64 }`.

**Demo**: `peel https://.../release.zip -C ./out` extracts a real
multi-MB zip (e.g., a GitHub release artifact). Crash mid-entry
resumes correctly. Crash mid-CD-fetch falls back to retrying the CD.

---

## Phase B — Pipeline & UX improvements

After Phase A lands, `peel` handles a much wider input set. Phase B
makes the *extraction loop itself* better — observability, throughput,
robustness — without expanding the format set further.

### §6. Progress UI

**What**: replace the single redrawn line with a multi-field progress
display that shows, at minimum:

- Percent complete (overall — see "what does percent mean").
- Compressed bytes downloaded out of total.
- Decompressed bytes written out of *estimated* total (we do not
  always know decompressed size; use the actual value for tar /
  uncompressed total when known; otherwise show "extracted: 156 MiB,
  unknown total").
- Download rate (rolling 5 s average).
- Disk write rate (rolling 5 s average).
- ETA to completion (whichever of the two rates is the bottleneck).
- Active worker count (currently doing IO, not just spawned).

**Why now**: comes first in Phase B because most of the later phases
add new state we'll want to surface. Doing the renderer once now —
with a rate-tracking primitive that later phases plug into — costs
less than rebuilding the renderer four times.

**No new TUI dependency.** `crossterm`/`ratatui` are not on the
allowlist and the requirement does not justify them. We render with
hand-rolled ANSI: cursor save/restore (`\x1b7`/`\x1b8`), erase-to-EOL
(`\x1b[K`), and `\r` for line returns. Three lines of output, redrawn
in place. On a non-TTY `stdout` (detected via `IsTerminal`), fall back
to periodic structured log lines instead.

**Sketch**:

1. `progress.rs`: a `ProgressState` struct holding atomics
   (`bytes_downloaded`, `bytes_extracted`, `total_size`,
   `active_workers`) and a small ring buffer for rate computation.
2. `ProgressRenderer` trait with two implementations: `TtyRenderer`
   (the multi-line redrawn block) and `LogRenderer` (writes
   `tracing::info!` lines at a configurable interval). The coordinator
   already accepts a `progress: Option<...>` callback; expose
   `ProgressState` and let the renderer choose.
3. ETA: `min(remaining_to_download / rate_dl, remaining_to_extract /
   rate_ex)` — whichever bottleneck dominates. Display `--:--` until
   we have ≥ 5 s of rate data.
4. "Percent complete" heuristic: if the decoder reports a known
   uncompressed total, use extraction progress; otherwise use download
   progress. Document the choice next to the field so users aren't
   surprised when a `.tar.zst` shows download-percent.
5. Worker activity tracking: download workers `fetch_add`/`fetch_sub`
   on `active_workers` around their per-chunk read loops.

**Demo**: against a 1 GiB `.tar.zst`, the progress block redraws
smoothly without flicker, all six fields populate, ETA converges to a
sensible number, the non-TTY fallback logs every 2 s.

---

### §7. io_uring backend — file IO (`O.2`, file-IO half)

**What**: replace blocking `pwrite_at` / `pread_at` on the sparse
file with `io_uring` submission queues on Linux when the kernel
supports it, with a safe automatic fallback to the existing blocking
path when it doesn't.

**Scope split (added 2026-04-29).** §7 covers *file IO only*
(`pwrite_at` / `pread_at`). The download path's TCP `connect` /
`send` / `recv` are the subject of §7b, which builds on §7's trait,
IO thread, and capability probe. Splitting the work keeps each diff
focused and lets the file-IO half land and bake before we touch the
hand-rolled HTTP client + rustls byte transport. Together §7 and §7b
deliver `O.2` from `OPTIMIZATIONS.md`.

**Why now**: it sits behind §8 (adaptive chunk size — adaptive sizing
makes more sense once IO concurrency can actually scale) and §9 (mmap
sparse file — io_uring registered buffers compose with mmap'd
regions). Doing io_uring before either of those is a forcing function
to keep the IO abstraction clean.

**Dependency**: `io-uring` (the `tokio-rs/io-uring` crate; raw
bindings, no async runtime). **Approved 2026-04-29** and added to
`ENGINEERING_STANDARDS.md` §2.2.

**Hard rule for this phase: no async runtime.** We use `io-uring`'s
sync API (`Submitter::submit_and_wait`) on a dedicated IO thread.
Anything that asks us to add `tokio` is rejected.

**Sketch**:

1. New `IoBackend` trait wrapping the file-IO operations the sparse
   file currently calls directly: `pwrite_at`, `pread_at`, plus
   `sync_all`. Default implementation is the existing blocking path;
   `UringBackend` is a Linux-only implementation gated on
   `#[cfg(target_os = "linux")]`. The trait is shaped to grow the
   socket operations §7b introduces without breaking either backend.
2. Capability probe at startup: open a ring with
   `IoUring::new(MIN_DEPTH)`. If construction fails (kernel too old,
   container without uring, seccomp blocking), log a `warn!` to
   stderr ("io_uring unavailable: <reason>; using blocking IO") and
   fall back. If `RLIMIT_MEMLOCK` is below the threshold required for
   our default ring depth, log a `warn!` and reduce ring depth (still
   uring, just smaller).
3. ulimit checks: `RLIMIT_NOFILE` should be ≥ workers × 2; below
   that, log a `warn!` with the recommended `ulimit -n` value.
4. Submission strategy: workers post `write` SQEs into a per-worker
   ring slot, then drain CQEs in batches. The IO thread owns the
   ring; workers communicate with it via a bounded channel of
   submission requests.
5. Tests: `IoBackend`-level unit tests stub both impls; integration
   tests run end-to-end on a real ring (gated behind a `linux-uring`
   feature flag in CI so non-Linux runners skip).

**Demo**: download of a 5 GiB file completes with measurable
throughput improvement on a localhost mock under high parallelism
(N=64 workers). Flag `--io-backend blocking` forces the old path for
A/B comparison. Falls back cleanly on a kernel < 5.6 and prints the
expected stderr warning.

---

### §7b. io_uring backend — network IO (`O.2`, network-IO half)

> **Status: drafted 2026-04-29, not yet started.** Added to the plan
> after §7 was scoped down to file IO. §7b assumes §7's trait, IO
> thread, capability probe, and `--io-backend` CLI flag are already
> in tree.

**What**: extend the [`IoBackend`] trait from §7 to cover the
download workers' network IO — TCP `connect`, `send`, `recv` — via
`io_uring`, sharing the dedicated IO thread and capability probe with
the file-IO path. `rustls` continues to drive the TLS state machine;
the uring path swaps the byte transport beneath it.

**Why now**: §7 establishes the trait, the IO thread, the bounded
submission channel, and the capability probe. Doing the network half
in a separate phase keeps each diff focused, lets the file-IO half
ship and bake before we touch the wire path, and lets us A/B the two
halves independently against the same demo (the §7 demo runs with
network blocking; this phase's demo runs with both halves on uring).

**Dependency**: no new crate. Uses the same `io-uring` dependency
approved in §7.

**Hard rule for this phase: still no async runtime.** Each socket
operation submits an SQE on the per-process IO thread and the calling
worker thread blocks on a per-op completion notifier. The ring
batches across workers — one ring, N workers — but each individual
`Read::read` / `Write::write` call is synchronous from the worker's
point of view, so `rustls` and the hand-rolled HTTP client work
unchanged.

**Sketch**:

1. `IoBackend` (introduced in §7) gains three methods: `connect(addr:
   SocketAddr) -> io::Result<UringSocket>`, plus `send` and `recv`
   operating on a backend-owned socket handle. Returning a typed
   handle (rather than a raw `RawFd`) keeps the ownership story
   crisp: the backend owns the socket lifecycle, the caller borrows a
   `Read + Write` adapter.
2. `UringSocket` is a thin wrapper around the kernel-side socket plus
   a back-reference to the `IoBackend`. It implements `std::io::Read`
   and `std::io::Write` by submitting `recv` / `send` SQEs and waiting
   on the per-op completion. This is the surface
   `rustls::StreamOwned` plugs into in place of `TcpStream`.
3. `http::client::Client` gains a backend handle (`Arc<dyn
   IoBackend>`), defaulting to the blocking backend it has today.
   Connect / send / recv go through the backend; the rest of the
   client (request framing, response parsing, redirects, pool) is
   unchanged.
4. TLS: `rustls::StreamOwned<ClientConnection, UringSocket>` Just
   Works because `UringSocket: Read + Write`. We do not interpose
   below the TLS state machine — the rustls / `webpki-roots` exception
   in `ENGINEERING_STANDARDS.md` §2.4 covers the unchanged bits.
5. Worker `cancel` flag: a worker that's blocked inside a uring `recv`
   completion wait must respond to cancellation. Either (a) submit the
   `recv` SQE with a linked timeout SQE and re-check `cancel` on
   timeout, or (b) submit a uring `cancel` SQE from the scheduler when
   it flips the flag. (a) is simpler; pick that and document the
   worst-case latency (1× timeout) in the trait's contract.
6. Capability is shared with §7's probe. A `--io-backend uring`
   selection that hits a kernel without ring support falls back to
   *both* halves blocking, with the same `warn!` line. There is no
   "uring file IO + blocking sockets" mixed mode — the trait stays
   coherent across halves.
7. Tests: a localhost mock server (reusing the existing test harness)
   plus the same crash-test path with the uring backend forced. Run
   the property-style "identical extraction output across backends
   for a fixed seed" test from §7 against the network half too.

**Demo**: the §7 demo, repeated under simulated network latency
(`tc qdisc add dev lo root netem delay 50ms` on Linux runners). At
N=64 workers and 50 ms RTT, the blocking-sockets variant pays a
context switch per recv; the uring variant batches recvs across
workers and finishes faster. The exact speedup is hardware- and
kernel-dependent; the demo bar is "uring is not slower than blocking
on the same workload, and is meaningfully faster at high parallelism
+ high RTT."

---

### §8. Adaptive chunk size (`O.1`)

**What**: tune chunk size during download based on observed throughput
and connection RTT, instead of the fixed 4 MiB.

**Why now**: §7 makes chunk size matter more (deep IO queues benefit
from larger units; shallow queues from smaller). Without io_uring, any
adaptive policy hits the blocking-IO ceiling first.

**Sketch**:

1. Track per-worker chunk completion times in a small ring buffer
   (already added to `ProgressState` in §6 — reuse it).
2. Policy:
   - When all workers consistently complete chunks in < 1 s and the
     bitmap reports ≥ 2 × workers chunks remaining, double chunk size
     up to a 64 MiB cap.
   - When latency spikes (p95 > 5 s) or retry rate exceeds 10 %,
     halve down to a 1 MiB floor.
   - Hysteresis: do not size-change more than once every 30 s.
3. The bitmap and checkpoint format encode chunk size; resume must
   honor the size that was active when the checkpoint was written
   (do not re-plan). New chunks added past the checkpoint can use the
   new size — but the simpler implementation just freezes chunk size
   at the size present at first checkpoint and doesn't re-tune across
   resumes. Document the limitation.
4. CLI: `--chunk-size <N>` continues to *force* a specific size
   (disabling adaptive); `--no-adaptive-chunk-size` disables adaptive
   behavior while keeping the default starting size.

**Demo**: against a localhost mock that throttles per-connection,
chunk size grows when bandwidth is plentiful and shrinks when the
mock injects 503s; logged size changes match the policy.

---

### §9. Memory-mapped sparse file (`O.3`)

**What**: `mmap` the partial download file so workers write into
memory and the kernel handles flushing; replace `fallocate(PUNCH_HOLE)`
with `madvise(MADV_REMOVE)` for hole release.

**Why now**: real benefit appears only at high IO concurrency (per
`O.3`), which §7 + §8 together unlock. This is also the phase where
we revisit the puncher abstraction — `MADV_REMOVE` semantics differ
from `fallocate` and the existing trait shouldn't have to lie about
that.

**Sketch**:

1. New `MmapSparseFile` alongside `SparseFile`. Selection is via
   config (`coordinator.rs`), not auto-detection — we don't want a
   silent backend switch.
2. New `Puncher::madv_remove(addr, len)` variant. The existing
   `LinuxPuncher` gains a `for_mmap()` constructor that issues
   `madvise(MADV_REMOVE)` instead of `fallocate(FALLOC_FL_PUNCH_HOLE |
   FALLOC_FL_KEEP_SIZE)`. Filesystem support varies (tmpfs and ext4
   support MADV_REMOVE; some others don't); fallback semantics
   mirror the existing ENOTSUP path.
3. Worker write path becomes a memcpy into the mapped region. We
   still flush via `msync(MS_ASYNC)` at frame boundaries to bound the
   dirty-page window the kernel is holding.
4. **Safety**: each `mmap` call lives in an `unsafe` block with a
   `// SAFETY:` comment documenting alignment, length, and lifetime.
   The exposed surface is `safe`. New unsafe code requires human
   review before merging (per standards doc §4).
5. CLI: `--io-backend mmap` selects this path; default stays blocking
   pwrite for now until §9 has been benchmarked in production.
6. Tests: parallel-write correctness, sparseness verification after
   `MADV_REMOVE`, behavior on filesystems that reject `MADV_REMOVE`
   (the test runs on tmpfs which supports it; assertion-skip on FS
   that doesn't).

**Demo**: 1 GiB synthetic download, 16 workers, both backends — same
extraction result, mmap backend's `time` shows lower kernel CPU.

---

### §10. Integrity verification (`O.13`)

**What**: `--sha256 <hex>` flag verifies the assembled compressed
file's hash. Hash is updated incrementally as bytes are consumed by
the decoder; verification runs at clean completion. A mismatch is a
hard error: extraction completed but the source did not match the
expected hash.

**Why now**: independent of §6–§9 in scope, but it benefits from §6's
`ProgressState` (the running hash makes a nice progress field).

**Implementation**: hand-rolled SHA-256 (~150 LOC, FIPS 180-4
reference). Standards doc §2.1 already nudges toward hand-rolling
trivial primitives; the deciding factor here is that resumable
hashing requires serializable internal state, and the `sha2` crate
does not expose it without unsafe transmute against private fields.
Pure-Rust SHA-256 measures 300–500 MiB/s on a single core, well
above the network-bound ceiling we operate under, so the asm /
AVX2 acceleration `sha2` would give us is irrelevant. `sha2` is
added as a **dev-dependency only** (`[dev-dependencies]` in
`Cargo.toml`) so unit tests can cross-check our implementation
against a known-correct reference; the runtime binary does not
link it.

**Sketch**:

1. New `hash/sha256.rs`: `Sha256 { state: [u32; 8], buffer: [u8;
   64], buffer_len: u8, bytes_processed: u64 }`. Public API mirrors
   the familiar shape: `new() -> Self`, `update(&mut self, &[u8])`,
   `finalize(self) -> [u8; 32]`. The serialized form is the struct
   layout above (113 bytes; padded to 120 for alignment), with a
   stable wire format independent of struct layout.
2. Wire the hasher into the source-byte path inside the extractor —
   every byte that flows through `decode_step`'s source `Read` is
   forwarded to the hasher. The hasher does not participate in the
   punching critical path; it processes bytes *before* they're
   punched.
3. CLI: `--sha256 <hex>` (64-hex-char). On clean completion, finalize
   the hasher and compare; mismatch returns a new
   `IntegrityError::HashMismatch { expected, got }`. Friendly
   message in `main.rs` ("the file you got is not the file you
   expected; this usually means the source changed during download
   or the expected hash is for a different file").
4. **Resume semantics — supported**. The `Checkpoint` struct gains a
   `hash_state: Option<Sha256State>` field, written atomically with
   the rest of the checkpoint at every quiescent frame boundary
   (same `write_temp` + `fsync` + `rename` discipline as today; no
   new atomicity machinery). The invariant: at any frame boundary,
   the saved hash state is the SHA-256 of source bytes
   `0..decoder_position`. On resume, deserialize the state and
   continue feeding bytes from the resume cursor. The whole-file
   hash at clean completion equals the SHA-256 of the original
   compressed source — byte-identical to `sha256sum` on the source
   file. Bumps `format_version`.
5. Tests:
   - NIST FIPS 180-4 test vectors (byte-string and bit-string
     varieties) for raw correctness.
   - `proptest`-driven 1000 random inputs, cross-checked against
     `sha2::Sha256` (dev-dependency) — catches divergence the NIST
     vectors miss.
   - Round-trip: serialize the state mid-stream, deserialize, feed
     the remaining bytes; resulting digest must equal the digest of
     the same input fed in one pass.
   - Per-byte-boundary: feed N random inputs split at every possible
     boundary, all yield the same digest (chunking-invariance).

**Demo**: `peel --sha256 abc... URL` succeeds for a correct hash and
fails cleanly for an incorrect one with an exit code distinct from
generic IO failure (per `cli.rs` exit-code conventions). A
mid-download `kill -9` followed by resume produces a digest equal to
a clean-run digest (verified by the crash-test harness, extended to
cover this).

---

### §11. Mid-flight source-change detection (extension of §10)

**What**: tighten the existing ETag/Last-Modified guard (`PLAN.md`
§5.3) and extend it to detect source drift in cases where ETag is
weak, missing, or wrong. Build on the streaming hasher from §10.

**Why now**: §10 added a per-byte hasher; with very little additional
work we get a much stronger drift detector than ETag. Doing it in a
separate phase keeps §10's diff small and the contract clear — §10
is "did we get what we expected?", §11 is "did the bytes we already
have remain consistent with the bytes still coming?".

**Sketch**:

1. Per-chunk fingerprints: as each chunk is downloaded, compute a
   small fingerprint (CRC32C is cheap and good enough — `O(1) MiB/s`
   on a single core). Persist the per-chunk fingerprints in the
   bitmap structure, expanded to `Vec<(chunk_state, crc32c)>`. Bumps
   `format_version`.
2. **Resume verification**: on resume, before accepting any persisted
   chunk as complete, re-fetch a small overlap probe (a single byte
   range from a random already-complete chunk) and recompute its
   CRC32C. Mismatch ⇒ `SourceChangedSinceCheckpoint`, abort and force
   a clean restart.
3. **Mid-flight verification**: every `N`th chunk (configurable;
   default `N = 32`) is re-requested as a probe by a different
   worker; re-fetched bytes must match the original CRC32C. Mismatch
   ⇒ `SourceChangedDuringDownload`, abort.
4. CRC32C implementation: hand-rolled (`O(150 LOC)`, table-driven).
   No new dependency. Standards doc §2.1 prefers this for trivial
   primitives.
5. Tighten ETag check: today the response is validated against the
   ETag captured at HEAD. Add Last-Modified comparison and a
   strong/weak ETag distinction (weak ETags can change without a
   content change; treat as advisory only).

**Demo**: a mock server that swaps the file under us mid-download
triggers `SourceChangedDuringDownload` within at most `N` chunks. A
mock that returns a different file on resume triggers
`SourceChangedSinceCheckpoint` on the very first probe.

---

### §12. macOS `F_PUNCHHOLE` puncher (`O.14`)

**What**: implement the `PunchHole` trait for macOS (APFS supports
`F_PUNCHHOLE`).

**Why now**: independent of §6–§11. We do it in this position so
multi-mirror and bandwidth limiting (which are independent of the OS)
follow it; macOS users have something to test the streaming pipeline
with sooner.

**Sketch**:

1. `MacosPuncher` calling `fcntl(fd, F_PUNCHHOLE, &fpunchhole_arg)`
   per the existing Python prototype reference. Direct `libc::fcntl`
   call; `F_PUNCHHOLE` constant is `99` on macOS but we look it up
   via `libc` to avoid hard-coding.
2. Same ENOTSUP/EINVAL graceful-degrade pattern as `LinuxPuncher`.
3. `default_puncher()` selects by `cfg(target_os)`.
4. Tests: integration test that exercises the macOS puncher on APFS
   (`tempfile` + `statx`-equivalent — macOS uses `fstat` and reports
   `st_blocks` like Linux). Skip on Linux runners.
5. Unblock the rest of the binary on macOS: §7 (io_uring) is Linux-
   only and remains so; the macOS build uses the blocking backend
   and the macOS puncher.

**Demo**: full extraction round-trip on a macOS runner; on-disk
source footprint shrinks during extraction same as on Linux.

**Implementation note** (added 2026-05-10): the `Fpunchhole`
struct must mirror Darwin's `fpunchhole_t` **including the
`reserved: u32` field** between `fp_flags` and `fp_offset`. APFS's
kernel-side validator rejects `F_PUNCHHOLE` with `EINVAL` if that
field reads as nonzero, even though the SDK header marks it "for
alignment". Relying on `#[repr(C)]` to insert the padding leaves
the bytes uninitialized, which is a bug — see
[`PLAN_macos_puncher_race.md`](PLAN_macos_puncher_race.md) for the
investigation.

---

### §13. Multi-mirror downloads (`O.10`)

**What**: accept multiple URLs for the same file (with the same
expected hash); download chunks from whichever mirror responds
fastest, fall back on per-mirror failure.

**Why now**: builds cleanly on §10 (we already have a hash to verify
the resulting file regardless of mirror), §11 (we already verify
cross-chunk consistency), and §8 (per-mirror chunk-size adaptation
falls out of the same machinery). Doing multi-mirror without those
would mean re-deriving consistency invariants twice.

**Sketch**:

1. CLI: `--mirror URL` repeatable; the positional `url` becomes the
   primary mirror.
2. Scheduler: on `start`, run `HEAD` against every mirror in
   parallel, verify size + ETag agreement (or hash agreement if
   `--sha256` is set; ETag-disagreeing mirrors are dropped with a
   `warn!`). At least one mirror must agree with the primary.
3. Worker assignment: each worker picks the fastest-responding live
   mirror for each new chunk request, tracks per-mirror health
   (success rate, latency p95), and avoids mirrors with elevated
   failure rates for a backoff window.
4. Per-mirror failure ⇒ that mirror is excluded for `30 s` and
   another mirror is used; if all mirrors are excluded, the
   scheduler stalls until one's backoff expires (don't fail the
   whole download just because every mirror has had one transient
   failure).
5. Per-chunk consistency with §11's CRC32C still applies — but now
   between mirrors as well as across resume.

**Demo**: two mock servers, one fast and one slow; chunks
preferentially route to the fast one; killing the fast mirror
mid-download routes the rest to the slow one and the download
completes.

---

### §14. Bandwidth limiting (`O.11`)

**What**: `--max-bandwidth <RATE>` flag (e.g., `10MB/s`, `1.5GB/s`).

**Why now**: small phase; depends on nothing except the existing
download path. Last in Phase B because it's the most "operational
nicety" of the bunch.

**Sketch**:

1. `download/rate_limit.rs`: a token-bucket rate limiter shared
   across workers via `Arc`. Tokens are bytes; refill rate is the
   configured limit; bucket capacity is `max(1 MiB, rate × 250 ms)`
   to absorb bursts.
2. Each worker calls `acquire(bytes_about_to_read).wait()` before
   each socket `recv`; the limiter blocks the calling thread (sync
   `Condvar`) until tokens are available.
3. CLI: `--max-bandwidth` parses standard suffixes (`K`/`M`/`G` =
   1000-based per network convention; `Ki`/`Mi`/`Gi` = 1024-based).
4. Interaction with §7 (io_uring): the limiter sits *above* the IO
   backend — workers acquire tokens, then dispatch through whatever
   backend is configured. Same limiter works for both.
5. Interaction with §13 (multi-mirror): the limit is *aggregate*
   across all mirrors, not per-mirror. Document this.

**Demo**: a 1 GiB download with `--max-bandwidth 10MB/s` completes
in ≈ 100 s, with download rate (from §6's progress UI) hovering at
the configured limit ± 5 %. Removing the flag uses full bandwidth.

---

## What "round one done" means

All of the following are true:

1. Each phase's demo has been recorded (screen capture or
   reproducible test) and reviewed.
2. The crash-test harness (the random `kill -9` test from `PLAN.md`
   §10) has been extended to cover every new format and every new
   IO backend variant. Resumes still produce byte-identical output.
3. CI gates listed in `ENGINEERING_STANDARDS.md` §CI remain green;
   coverage thresholds (80 % overall, 95 % on critical paths)
   continue to hold across the new modules.
4. `OPTIMIZATIONS.md` has been amended to mark items `O.1`, `O.2`
   (delivered jointly by §7 + §7b), `O.3`, `O.6`, `O.7`, `O.8`,
   `O.10`, `O.11`, `O.13`, `O.14`, `O.19` as "delivered in PLAN_v2
   §<phase>"; the rest stay deferred for a future round.
5. README has been updated with the new format coverage matrix and
   the new flags.

## Schedule guidance

There is still no schedule. The plan is sequenced; do it in order, do
each phase completely. Phase A's five phases are gating dependencies
for one another (§1 first; §5 last). Phase B's ten phases (§6, §7,
§7b, §8–§14) are loosely dependent in the order written and should
not be parallelized across sessions; in particular §7b builds on §7
and must not start until §7 has landed and demoed.

## Decisions resolved before §1 begins

Resolved 2026-04-29 (this section is the audit trail; the
substantive change lands in the relevant phase above):

1. **Crate approvals.** `xz2` (§3), `lz4_flex` (§4), `io-uring`
   (§7) approved and added to `ENGINEERING_STANDARDS.md` §2.2.
   `sha2` was *not* approved as a runtime dependency; §10 hand-rolls
   SHA-256 to make resumable hashing tractable, and `sha2` is added
   as a `dev-dependency` only for cross-checking the hand-rolled
   implementation in tests.
2. **Magic-byte / suffix disagreement.** Hard error by default
   (`FormatMismatch`); `--force-format-from-magic` opts in to
   trusting the magic, and `--format <name>` forces a specific
   decoder regardless of either signal. The two override flags are
   mutually exclusive.
3. **Resume + integrity verification.** Resume preserves SHA-256
   state. The `Checkpoint` format gains a `hash_state` field
   serialized atomically with the rest of the checkpoint; the
   resumed run produces a digest byte-identical to a clean run.
   Hand-rolling SHA-256 (#1) is what makes this clean.
4. **xz frame granularity.** Per-Stream for round-one. Per-Block is
   filed as `O.6b` in `OPTIMIZATIONS.md` after §3 lands. The
   limitation is real but mostly affects multi-threaded /
   concatenated xz files, which are the minority of published
   `.tar.xz`; default-encoded xz is single-Block and *no*
   implementation can checkpoint within it.
5. **Zip scope.** STORED + DEFLATE + zstd entries for round-one.
   AES / password-protected entries, Zip64, multi-disk, and other
   PKWARE extensions are filed as `O.8b` after §5 lands.

When §3 / §5 land they should append the corresponding `O.6b` /
`O.8b` entries to `OPTIMIZATIONS.md` before the phase is marked
done.
