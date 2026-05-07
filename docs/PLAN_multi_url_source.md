# Plan: multi-URL source (split-archive parts)

> **Status: drafted 2026-05-06, not yet started.** Scoped against `PLAN_v2.md`
> as a post-MVP feature that does not depend on, and is not depended on by,
> any of the in-flight phases there. Land it on top of whatever the active
> branch is at start-of-work.

`peel` today consumes one URL whose body is the entire archive. This plan
adds support for a different real-world layout: **N URLs whose
byte-concatenation is one logical archive stream**, with per-part SHA-256
verification, parallel downloads across all parts, and byte-identical
crash-resume.

The motivating case is the Arbitrum snapshot service:

```
peel \
  https://snapshot.arbitrum.io/arb1/2026-05-01-ddbe8e46/pruned.tar.part0000 \
  https://snapshot.arbitrum.io/arb1/2026-05-01-ddbe8e46/pruned.tar.part0001 \
  https://snapshot.arbitrum.io/arb1/2026-05-01-ddbe8e46/pruned.tar.part0002 \
  https://snapshot.arbitrum.io/arb1/2026-05-01-ddbe8e46/pruned.tar.part0003 \
  https://snapshot.arbitrum.io/arb1/2026-05-01-ddbe8e46/pruned.tar.part0004 \
  --sha256 0a8de6e83fd8ba040fd052fd8d4fd0e009a9736ace5cb32bb2abd4ac6a61725d \
  --sha256 1bcf4d2e9aa01ff5...                                              \
  --sha256 7e2a3140be11e00b...                                              \
  --sha256 c084221d099b4a44...                                              \
  --sha256 39b1...                                                          \
  -C ./out
```

Concatenating the parts yields one `.tar`. Five parts × ~500 GiB → ~2.5 TiB
of `pruned.tar`. The whole pipeline (bitmap, decoder cursor, hole-punching,
checkpoint) stays single-stream; only the *source* gains a layer that maps
a global byte offset to `(part_index, in-part offset)` and dispatches the
ranged GET to the right per-part URL.

## Why one logical stream (not N sequential downloads)

Two reasons:

1. **Parallelism.** The whole point of the Arb / aria2 layout is that the
   five parts can be fetched concurrently. A sequential model would
   serialise the network and miss most of the throughput.
2. **No code rewrite.** The existing scheduler / bitmap / decoder /
   checkpoint pipeline is already global-offset based; with `total_size =
   sum(part_sizes)` the bitmap, decoder cursor, hole-punching, and
   checkpoint all keep working unchanged. The only new code is the offset-
   to-part router.

## Hard constraints (carried forward from `PLAN_v2.md`)

- Std-first; no new crates. SHA-256 already in-tree (`src/hash/sha256.rs`).
- No async runtime. Threaded scheduler stays threaded.
- Checkpoint format bumps `FORMAT_VERSION` from 7 → 8 with a clean
  rejection path for older readers (`src/checkpoint.rs:148`).
- Hand-rolled HTTP/1.1 stays. Per-part HEADs reuse the existing client.

## Out of scope (this plan)

- A peel-native or third-party manifest format (Metalink, JSON, etc.).
  Defer until a second consumer exists. The Arb snapshot-explorer index
  API does not expose per-snapshot endpoints; users obtain the part list
  externally and pass URLs on the CLI. (Future work: an Arb adapter.)
- Per-part *mirrors* (each part has alternate sources). The existing
  `--mirror` flag treats mirrors as alternates of the *same* whole file
  and is incompatible with the multi-URL semantics; using both at once
  is rejected at parse time.
- `xxhash` verification. The Arb manifest exposes both; we use `sha256`
  only because peel already speaks it.
- Auto-discovery of part lists by URL pattern (e.g. `…part{0000..NNNN}`).

---

## §1. Source abstraction (`MultiPartSource`)

**What**: a small layer that owns the part list and exposes the global-
offset interface the scheduler uses today.

**Why now**: every later phase plugs into this. Doing it once,
keeping the existing single-URL path as the `parts.len() == 1` case,
costs less than threading a second code path through the scheduler.

**Sketch**:

1. New module `src/download/multi_url.rs`. Types:
   ```rust
   pub struct PartDescriptor {
       pub url: Url,
       pub size: u64,
       pub fingerprint: SourceFingerprint,
       pub expected_sha256: Option<[u8; 32]>,
   }
   pub struct MultiPartSource {
       parts: Vec<PartDescriptor>,
       prefix_sums: Vec<u64>, // prefix_sums[i] = sum(sizes[0..i])
       total_size: u64,
   }
   impl MultiPartSource {
       pub fn locate(&self, global_offset: u64) -> (usize, u64) { ... }
       pub fn part_url(&self, idx: usize) -> &Url { ... }
       pub fn dispatch_range(&self, range: ByteRange)
           -> impl Iterator<Item = (usize, ByteRange)> { ... }
   }
   ```
   `dispatch_range` splits a global ranged GET that spans a part boundary
   into one ranged GET per part. In practice the scheduler already
   dispatches in `chunk_size`-sized units (default 4 MiB) and we align
   part boundaries with chunk boundaries (see §2), so spans are rare.
2. Generalise `DownloadInfo` (`src/download/scheduler.rs:263`) to embed
   a `MultiPartSource` instead of a single `url: Url` + `total_size: u64`.
   Single-URL constructions wrap a one-element source.
3. Generalise `discover()` (`src/download/scheduler.rs:463`) to
   `discover_multi(&Client, &[Url])` performing parallel HEADs (one per
   part), validating `Accept-Ranges: bytes` on every part, summing
   `Content-Length` into `total_size`, and storing per-part
   `SourceFingerprint`. ETag agreement is *not* required across parts —
   parts are distinct objects with their own ETags.
4. Update worker dispatch (`src/download/scheduler.rs:1559-1563`) to ask
   `MultiPartSource::locate()` for the part URL given the chunk's start
   byte, then build the part-relative `Range` header.
5. The pre-existing `--mirror` machinery (`src/download/mirrors.rs`) stays
   intact for the single-URL case. `MultiPartSource` and `MirrorSet` are
   mutually exclusive at config time.

**Demo**: `cargo test` exercising a unit test that builds a 3-part source
from `MockServer` instances of differing sizes, verifies `locate()` for
boundary offsets, and runs an end-to-end download where workers serve
chunks 0…N from the correct part URLs.

---

## §2. Chunk / part boundary alignment

**What**: ensure bitmap chunks never span a part boundary.

**Why**: if a chunk straddles two parts, a worker would have to issue
two ranged GETs to two different URLs to satisfy one bitmap unit, which
breaks the "one chunk = one HTTP transaction" invariant the scheduler
relies on (and double-counts on retries).

**Sketch**:

1. Round each part's effective range up so subsequent parts start on a
   bitmap-chunk boundary. There are two equivalent options; we pick the
   second:

   a. Pad the bitmap with "synthetic complete" bits at part boundaries
      (zero-cost on disk, trivial logic, but pollutes the bitmap
      semantically).

   b. Shrink the chunk size so it divides every part size. Compute
      `gcd(chunk_size, all part sizes)` at startup; if the result is
      below a floor (e.g. 256 KiB) reject the configuration with a clear
      error explaining how to align the parts. In practice Arb parts are
      `512 GiB` and the default chunk size is `4 MiB`, so `gcd = 4 MiB`
      already.

2. The scheduler already supports adaptive chunk sizing (`PLAN_v2.md` §8);
   adaptive coalescing must respect part boundaries — never issue a
   single GET that crosses one. Add a part-aware splitter at the
   `dispatch_range` seam.

**Demo**: unit test for boundary cases (chunk_size that doesn't divide a
part size triggers the rejection error; chunk_size that does works
end-to-end).

---

## §3. CLI surface

**What**: positional URLs (any number ≥ 1) plus a repeatable `--sha256`.

**Sketch**:

1. `src/cli.rs`: change `pub url: String` to
   `pub urls: Vec<String>` with `#[arg(num_args = 1..)]` and
   `value_name = "URL"`. The first URL keeps the existing single-URL
   semantics; passing multiple activates the multi-part path.
2. Change `pub expected_sha256: Option<String>` to
   `pub expected_sha256s: Vec<String>` (repeatable). Validation rules:
   - If empty: no verification (today's behaviour with no `--sha256`).
   - If `urls.len() == 1`: 0 or 1 hashes accepted (today's behaviour).
   - If `urls.len() > 1`: 0 hashes (no verification) or exactly
     `urls.len()` hashes (one per part, paired by order). Anything else
     is a `CliError::ShaCountMismatch`.
3. Reject the combination `--mirror` + multiple positional URLs with a
   clear error. (`--mirror` semantics — alternates of the same file —
   are incompatible with split-source semantics; revisit if a future
   plan brings per-part mirroring.)
4. Default output-directory derivation (`default_output_dir` in
   `src/cli.rs:365`) reads from the *first* URL's basename, then strips
   the `.partNNNN` suffix before going through the existing
   `STRIPPABLE_EXTENSIONS` loop. So `…/pruned.tar.part0000` →
   `pruned`.

**Demo**: `cargo test` parses N-URL invocations, validates count
constraints, and emits the expected `RunArgs`.

---

## §4. Per-part rolling SHA-256

**What**: extend the existing `HashingReader` (`src/hash.rs:146`) so a
mismatch fails the run *at the part boundary that produced it*, not at
end-of-stream.

**Why**: Arb part 4 is hours of decode behind part 0. We want the bad-byte
signal early. The existing `HashingReader` already feeds bytes
sequentially as the decoder consumes them — that's the natural place to
notice a part-end.

**Sketch**:

1. Replace `HashingReader`'s single `Sha256` with a state machine:
   ```rust
   struct PartHashes {
       active: Sha256,                    // hasher for the active part
       active_part_idx: usize,
       part_boundaries: Vec<u64>,         // prefix sums (== part end offsets)
       expected: Vec<Option<[u8; 32]>>,   // per-part expectations
   }
   ```
   On each `update(bytes)` at logical offset `off`:
   - Feed bytes into `active`.
   - If `off + bytes.len()` reaches `part_boundaries[active_part_idx]`,
     finalize `active`, compare against `expected[active_part_idx]`
     (if `Some`), advance the index, reset `active = Sha256::new()`.
   - On mismatch: return `HashError::PartMismatch { idx, expected,
     actual }`. The coordinator surfaces it as `SourceChanged`.
2. Checkpoint serialisation (`snapshot_hash_state` in
   `src/coordinator.rs:2672`) stores `(active_part_idx, active.serialize())`
   instead of just `active.serialize()`. Resume reconstructs the state
   machine: parts before `active_part_idx` are already verified, the
   active hasher continues from its serialised state.
3. Single-URL path (no multi-part): one part, one optional expected
   hash, behaviour byte-identical to today.

**Demo**: an integration test that constructs a 3-part source where part
1's bytes are corrupted on the wire; assert the run fails after part 1
finishes (not after part 2 or part 3 has started decoding).

---

## §5. Checkpoint format bump (v7 → v8)

**What**: store the part list in the checkpoint so resume can verify the
user re-passed the same source.

**Sketch**:

1. `src/checkpoint.rs`: bump `FORMAT_VERSION: u32 = 8`.
2. New on-disk shape (length-prefixed parts vec):
   ```
   v8 body =
     existing v7 fields, except `url: String` → `parts: Vec<PartRecord>`
     PartRecord = { url: String, size: u64, fingerprint: SourceFingerprint,
                    expected_sha256: Option<[u8; 32]> }
     hash_state: Option<(active_part_idx: u32, sha256_serialized: [u8;
       SERIALIZED_LEN])>
   ```
3. Reading a v7 checkpoint: lift `url` into `parts[0]` synthetically
   (single-part vector), keep going. No migration of v6 or earlier.
4. On resume: re-pass `--url` arguments → confirm:
   - `urls.len()` matches `parts.len()`.
   - Each URL string matches (allow user to substitute a CDN swap by
     comparing fingerprints; if `expected_sha256` was set, any
     fingerprint drift on a *finished* part aborts).
   - `expected_sha256s` (if any) match what's in the checkpoint.
   Any mismatch → `CheckpointError::SourceChanged` with a message
   explaining which part disagreed.
5. Test matrix already exercised for v7 (round-trip, partial-write,
   corrupt-`.tmp`, forward-compat) extends to multi-part fixtures.

**Demo**: kill the binary mid-flight on a 3-part download, re-run, verify
byte-identical output. Same crash-test harness as `PLAN.md` §10.3.

---

## §6. End-to-end: real Arb snapshot

**What**: confirm the whole pipeline against the smallest Arb snapshot.

**Sketch**:

1. `nova` chain currently ships a 2-part Pruned snapshot — the smallest
   `isLatest && isFinished` snapshot in the index. Use that for the
   first end-to-end run on a workstation; do not put a multi-TiB
   download into CI.
2. Manual demo command:
   ```
   curl -s https://snapshot-explorer.arbitrum.io/api/snapshots \
     | jq '.data[] | select(.name=="nova") | .snapshots[] | select(.isLatest and .isFinished)' \
     # → produces the part keys + per-part sha256s
   peel <part0-url> <part1-url> --sha256 <h0> --sha256 <h1> -C ./nova-out
   ```
3. Acceptance: bytes extracted match `aria2c -Z … && tar -xf …`
   on the same source (compare directory hashes). Source on-disk
   footprint stays bounded by `--max-disk-buffer` (default 1 GiB).

**Demo (the actual feature)**: the manual command above completes
successfully on a workstation with `--max-disk-buffer 4GiB` and the
extracted `nova-out/` matches a reference extract.

---

## What "feature done" means

1. The end-to-end demo passes against the real Arb `nova` snapshot.
2. All existing single-URL tests pass with no behavioural change
   (regression budget: 0).
3. Crash-test harness (`PLAN.md` §10.3) extended to a 3-part fixture
   passes 100/100 random-kill points.
4. Coverage thresholds in `ENGINEERING_STANDARDS.md` §5.1 hold for
   `multi_url.rs`, the modified scheduler paths, and the v8 checkpoint
   path.
5. README gains a "split sources" section and a multi-URL example.
