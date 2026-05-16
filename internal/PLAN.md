# Plan: peel MVP

> **Status: MVP complete (2026-04-29).** All ten sequenced phases below have
> landed (see `git log` — `phase 1` through `phase 10`). Active work has
> moved to `OPTIMIZATIONS.md`; this document is retained as the historical
> record of how the MVP was scoped and built. Do not start new MVP work from
> this file — promote items from `OPTIMIZATIONS.md` into a successor plan
> instead (see "When to revisit this list" in that doc).

This is the **MVP**. Things explicitly *out* of scope for the MVP are listed
in `OPTIMIZATIONS.md`. Don't pull from that list during MVP work.

## North-star use case

```
$ peel https://example.com/dataset.tar.zst -C ./out
[downloading] 234.5 MiB / 1.2 GiB  ▓▓▓░░░░░  19.5%  (4 workers, 38 MiB/s)
[extracting]  119 files, 156.2 MiB written
[disk]        compressed on-disk: 84 MiB (of 234.5 MiB downloaded)
```

If killed (`kill -9`) at any point and re-run, it picks up where it left off
and produces byte-identical output to a clean run.

## Hard constraints reminder

- Std-first; vetted crates from the allowlist only (see
  `ENGINEERING_STANDARDS.md` §2).
- No async runtime in MVP; threads + sync primitives only.
- Hand-rolled HTTP/1.1 client over `std::net` + `rustls`.
- Linux first (`fallocate(PUNCH_HOLE)`); puncher trait abstracts the OS so
  macOS/Windows can be added later without core changes. macOS shipped in
  `PLAN_v2.md` §12; Windows (`FSCTL_SET_SPARSE` + `FSCTL_SET_ZERO_DATA`)
  is in flight under `PLAN_v3_windows.md`.

## Module map

This is the target structure at MVP completion. Modules are introduced in
the order below; each one is fully tested before the next begins.

```
src/
  lib.rs                       // pub re-exports + crate-level docs
  main.rs                      // CLI binary
  cli.rs                       // arg parsing (clap derive)
  error.rs                     // top-level Error type (rare; usually module-local)
  types.rs                     // ByteOffset, ChunkIndex, ByteRange, etc. newtypes

  punch.rs                     // PunchHole trait + Linux/noop impls
  bitmap.rs                    // chunk completion bitmap (atomic-bit-set)
  checkpoint.rs                // atomic write/read, ETag verification

  http/
    mod.rs (i.e. http.rs)      // public surface
    client.rs                  // hand-rolled HTTP/1.1 over rustls
    request.rs, response.rs    // wire-format parsing
    range.rs                   // Range/Content-Range header handling

  download/
    scheduler.rs               // chunk planning, worker dispatch, retries
    worker.rs                  // single-worker download loop
    sparse_file.rs             // safe wrapper for the partial output file

  decode/
    mod.rs                     // StreamingDecoder trait + registry
    zstd.rs                    // zstd decoder w/ frame boundary detection
    gzip.rs                    // gzip decoder (member-boundary checkpoints)

  sink/
    mod.rs                     // Sink trait
    raw.rs                     // single-file output
    tar.rs                     // streaming tar extractor

  extractor.rs                 // the coordinator: ties decoder+sink+puncher

  coordinator.rs               // top-level: download + extractor + checkpoint
```

## Sequenced implementation

Each section ends with a **demo** — something runnable that proves the section
works. Sections build on each other; do not start §N+1 until §N's demo passes.

### §1. Foundations

Establish the baseline so everything that follows compiles, tests, and lints.

1.1. Project scaffolding: `Cargo.toml`, `rust-toolchain.toml`, `deny.toml`,
     `.gitignore`, basic CI config (GitHub Actions).
1.2. `types.rs`: `ByteOffset`, `ChunkIndex`, `ByteRange { start, end_exclusive }`,
     with `Display`, `Debug`, ordering, arithmetic methods (`checked_add`,
     `len`, `contains`, etc.). Property tests for arithmetic.
1.3. `error.rs`: define the top-level error pattern. Each module will have its
     own typed error; this file documents the convention.
1.4. `lib.rs` skeleton with module declarations, `#![deny(missing_docs)]`,
     `#![warn(unused, clippy::all)]`.

**Demo**: `cargo build && cargo test && cargo clippy -- -D warnings` clean.

---

### §2. Hole punching

Port the design from the Python prototype (py_proto/). This is small but load-bearing.

2.1. `punch.rs`: `PunchHole` trait with `punch(fd, offset, len)` and
     `block_size_hint()`. `LinuxPuncher` calls `libc::fallocate` directly
     (no extra crate; we already have `libc` transitively, but if we don't,
     wrap the syscall manually). `NoopPuncher` for fallback.
2.2. Detect ENOTSUP/EOPNOTSUPP/EINVAL and downgrade gracefully. Same logic
     as the Python prototype.
2.3. Helper: `align_down(value, block_size)`. Tested.
2.4. Tests: integration test that creates a sparse file on tmpfs/ext4,
     punches a range, verifies `st_blocks` decreased while `st_size`
     held steady. Skip the assertion when running on an unsupported FS,
     don't fail.

**Demo**: A `cargo test` that on a supporting filesystem demonstrates a
4 MB file shrinking to ~0 disk usage after a punch, with logical size
preserved.

---

### §3. Sparse file & bitmap

The substrate the download workers write into.

3.1. `bitmap.rs`: `ChunkBitmap` backed by a `Vec<AtomicU64>`. Operations:
     `mark_complete(idx)`, `is_complete(idx)`, `complete_range(start, end)`,
     `next_incomplete_after(idx)`, `count_complete()`. All lock-free.
     Property tests for bit-manipulation correctness.
3.2. `download/sparse_file.rs`: `SparseFile` wraps an `std::fs::File` opened
     `O_RDWR | O_CREAT`, tracks total size, exposes `pwrite_at(offset, buf)`
     using `FileExt::write_all_at`, and `read_at`. Owns the file descriptor;
     punching is done via the `PunchHole` trait passed in.
3.3. Tests: round-trip writes from multiple threads, verify sparseness.

**Demo**: A test that creates a 1 GB sparse file, has 8 threads write
random 1 MB chunks at random offsets, verifies the bitmap reflects
completions, verifies file content matches expected, verifies on-disk
size is approximately 8 MB (when on a sparse-friendly FS).

---

### §4. HTTP client

The piece most tempting to outsource. Don't. Scope: HTTP/1.1, plaintext +
TLS via `rustls`, `HEAD` + `GET` with `Range` header, follow redirects (3xx)
up to a small limit, parse `Content-Length`, `Content-Range`, `ETag`,
`Accept-Ranges`, `Last-Modified`.

4.1. `http/request.rs`: `Request` builder, serialization to wire bytes.
4.2. `http/response.rs`: streaming response parser — read status line,
     headers, then leave the caller a `Read` over the body. Support
     `Content-Length`-delimited and `chunked` transfer encoding.
4.3. `http/range.rs`: `ByteRange ⇄ Range: bytes=a-b` header, parse
     `Content-Range: bytes a-b/total`.
4.4. `http/client.rs`: `Client` struct holding connection pool keyed by
     `(host, port, scheme)`, with a small idle-connection cache.
     Implements `head()`, `get_range()`, `get_full()`. TLS connections
     wrap `TcpStream` in `rustls::StreamOwned`.
4.5. Test infrastructure: `tests/support/mock_server.rs` — a real
     `TcpListener` + tiny handler that supports our subset of HTTP and
     can be configured to inject failures (early disconnect, slow
     response, wrong ETag, etc.).
4.6. Tests: every header parser is property-tested. Every response shape
     (200, 206, 301, 404, 503, partial body, chunked, oversized header)
     has an integration test against the mock server. Fuzz target for
     response parser.

**Demo**: `cargo run --example http_demo -- https://...` fetches a file,
prints headers + body length. Same against a localhost mock with TLS.

---

### §5. Download scheduler

Orchestrate workers downloading chunks into the sparse file.

5.1. `download/scheduler.rs`:
     - On `start(url)`: HEAD to get `Content-Length`, `Accept-Ranges`,
       `ETag`. If ranges unsupported, fall back to single-stream mode.
     - Plan chunks: divide total size into `CHUNK_SIZE` (default 4 MiB)
       pieces, build initial bitmap.
     - Spawn N workers via `thread::scope`. Workers pull chunk indices
       from a `mpsc::SyncSender`; on success, mark bitmap; on failure,
       report to scheduler for retry/backoff.
     - **Priority**: workers prefer chunks closest to the decoder
       cursor (passed in via an `Arc<AtomicU64>` the decoder updates).
       This is the difference between a pleasantly streaming pipeline
       and a stalled decoder.
5.2. `download/worker.rs`: takes a `Client`, a chunk assignment, writes
     to the sparse file via `SparseFile::pwrite_at`, retries on
     transient errors with exponential backoff.
5.3. ETag/Last-Modified verification on every range response — if the
     server's identifier changed mid-download, abort with
     `SourceChanged` error.
5.4. Tests: against the mock server, exercise: parallel downloads,
     retry on 503, abort on ETag change, single-stream fallback,
     priority steering. Crash test: kill the scheduler thread mid-flight,
     verify bitmap state is consistent with what's actually on disk.

**Demo**: `peel-download URL output.bin` (a temporary debug binary)
downloads a multi-hundred-MB file with 4 workers, prints throughput,
result is byte-identical to the source.

---

### §6. Decoder protocol & zstd

Ports the Python prototype, with the addition of frame-boundary detection.

6.1. `decode/mod.rs`: `StreamingDecoder` trait:
     ```rust
     trait StreamingDecoder {
         fn decode_step(&mut self, src: &mut dyn Read, sink: &mut dyn Sink)
             -> Result<DecodeStatus, DecodeError>;
         fn bytes_consumed(&self) -> ByteOffset;
         fn frame_boundary(&self) -> Option<ByteOffset>;
     }
     enum DecodeStatus { MoreData, Eof }
     ```
     The `frame_boundary()` returns `Some(offset)` only when the decoder
     has *just* completed a frame and the next byte starts a new frame.
6.2. `decode/zstd.rs`: thin wrapper over the `zstd` crate's streaming
     reader. We also peek for the zstd frame magic (`0x28 0xB5 0x2F 0xFD`)
     to detect frame boundaries — the upstream crate doesn't expose this
     directly. Approach: maintain our own counted-input wrapper, after
     each decode call ask the zstd reader for its remaining unread bytes
     and check whether we just finished a frame.
6.3. Decoder registry by file suffix, per the Python design.
6.4. Tests: round-trip arbitrary data through encode/decode, verify
     `bytes_consumed` is monotonic and bounded by actual reads,
     property test that `frame_boundary` only ever returns offsets
     that are valid restart points (verified by trying to decode from
     that offset).

**Demo**: `peel-decode foo.zst > foo` works on multi-frame zstd
files; tests confirm frame boundaries.

---

### §7. Sinks

7.1. `sink/mod.rs`: `Sink` trait with `write(&mut self, &[u8]) -> Result`,
     `close(self) -> Result`, and crucially `is_quiescent(&self) -> bool`
     — true when the sink is between extraction units and could be
     checkpointed (e.g., between tar members).
7.2. `sink/raw.rs`: writes to a single output file. Always quiescent.
7.3. `sink/tar.rs`: streaming tar parser (we hand-roll it; tar is a
     simple format and we want frame/member alignment for checkpointing).
     Parses header blocks, validates checksums, extracts files into the
     output directory, refuses path-escape attempts. `is_quiescent()` is
     true between members.
7.4. Tests: tar fixtures generated in code (build a tar in memory with
     several files, feed it byte-by-byte to verify the streaming parser
     handles arbitrary chunk boundaries), path-escape tests
     (`../../etc/passwd` rejected), large-file (>8 GB, ustar size limits)
     handling.

**Demo**: pipe a `.tar` to `peel-extract -C out/`, verify all files
extracted with correct contents and modes (modes deferred to
`OPTIMIZATIONS.md`; MVP just gets contents right).

---

### §8. Extractor (decoder + sink + puncher)

8.1. `extractor.rs`: the loop from the Python prototype, in Rust:
     ```
     while decode_step != Eof:
         if decoder.frame_boundary().is_some() && sink.is_quiescent():
             record extractor_position
         maybe punch behind extractor_position
     ```
     Punches only behind the most recent quiescent point. This is the
     *checkpoint-safe* punching discipline (different from naive
     read-ahead punching).
8.2. Stats: bytes in/out/punched, punch-call count, time spent in
     decode vs. write vs. punch.
8.3. Tests: extract a multi-frame zstd → tar archive end-to-end from a
     local file (no network yet); verify outputs match reference and
     on-disk source footprint shrinks.

**Demo**: `peel-extract local.tar.zst -C out/` produces correct
extraction with shrinking source footprint.

---

### §9. Checkpointing

The piece that makes resume work.

9.1. `checkpoint.rs`: `Checkpoint` struct with:
     - URL, ETag, total_size, chunk_size
     - `decoder_position: ByteOffset`
     - `bitmap_completed: Vec<u8>` (serialized chunk bitmap)
     - `extraction_state: SinkState` (sink-specific opaque blob;
       for raw it's just `bytes_written`, for tar it's
       `members_completed: Vec<String>`)
     - `format_version: u32`, `created_at: SystemTime`
9.2. Serialization: a simple custom binary format (header magic +
     length-prefixed fields). Not JSON; we want this to be tiny and
     forward-compatible with explicit version handling.
9.3. Atomic write: write to `<path>.ckpt.tmp`, `fsync`, `rename` over
     `<path>.ckpt`. Read on resume; verify `format_version` and
     compute a checksum over the body.
9.4. Tests: round-trip property tests, partial-write recovery
     (corrupt the `.tmp`, ensure resume falls back to either the prior
     `.ckpt` or a clean restart), forward-compatibility tests
     (older code reading newer file fails cleanly with a clear error).

**Demo**: a test that writes a checkpoint, kills the process between
write and rename, and verifies the existing `.ckpt` is intact.

---

### §10. Coordinator (the whole thing)

Wires download + extractor + checkpoint into one resumable pipeline.

10.1. `coordinator.rs`:
      - Open or create sparse file at `<output>.peel.part`.
      - Open or create `<output>.peel.ckpt`.
      - If checkpoint exists and ETag matches server, resume: load
        bitmap, seek decoder to `decoder_position`, restore sink state.
      - Spawn download scheduler thread; spawn extractor thread.
      - Coordinator main loop: wait for extractor to report a quiescent
        frame boundary; write checkpoint; punch source up to checkpoint
        position; repeat.
      - On clean completion: delete `.part` and `.ckpt`, optionally
        rename outputs to final paths.
      - On error or signal (SIGINT/SIGTERM): write a final checkpoint
        and exit cleanly.
10.2. CLI integration: `cli.rs` parses args, constructs coordinator,
      runs it, formats progress on a single redrawn line on a TTY or
      structured logs otherwise.
10.3. Tests:
      - Happy path: full download + extraction.
      - Resume: kill at random points, verify resume produces byte-
        identical output. This is the **crash test harness** — a test
        that runs the binary 100 times with random `kill -9` points
        and asserts identical output every time.
      - ETag mismatch on resume: fails cleanly.
      - Disk full mid-extraction: fails cleanly with a useful error.

**Demo (the actual MVP)**: the north-star use case at the top of this
file works end-to-end, including being killed and resumed.

---

## What "MVP done" means

All of the following are true:

1. The north-star command works against a real-world `.tar.zst` (e.g.,
   a Linux distro container image, an open-source dataset).
2. Crash test harness passes: 100 random kill points, all produce
   byte-identical output on resume.
3. On-disk footprint of the compressed source stays bounded by the
   download window even for multi-GB archives.
4. CI is green on the gates listed in `ENGINEERING_STANDARDS.md` §CI.
5. Coverage ≥ 80% overall, ≥ 95% on the critical-path modules listed in
   `ENGINEERING_STANDARDS.md` §5.1.
6. Docs: every public item has a doc comment; the README has a
   complete usage example and a section explaining the architecture
   linked to `PLAN.md`.

After MVP, work moves to `OPTIMIZATIONS.md`. **As of 2026-04-29, the MVP
criteria above are satisfied and that transition is now in effect.**

## Schedule guidance

There is no schedule. The plan is sequenced; do it in order, do each
section completely. Trying to parallelize sections (e.g., "I'll work on
HTTP while waiting for review on punching") tends to produce code that
doesn't fit together; resist.
