# PLAN — `.bz2` / `.tar.bz2` support (hand-rolled bzip2 decoder)

**Status**: proposed (2026-05-13).
**Owner**: TBD.
**Supersedes**: nothing — additive to `PLAN_v2.md`. Reverses the
"deliberately out of round-one scope" stance in
[`docs/src/faq.md` §"No `.bz2` support"](../docs/src/faq.md) and the
"not registered; surfaces as `unknown format`" line in
[`docs/src/formats.md`](../docs/src/formats.md). Both doc edits are
phase deliverables, not prerequisites.

## Why we're doing this

Round-one of `PLAN_v2.md` argued bzip2 out of scope on the basis that
modern publishing pipelines have moved to `xz` (better ratio) and
`zstd` (faster), and that real-world `.tar.bz2` is a legacy shape. That
priors-only argument held until **<corpus / user name TBD>** asked us
to extract `<dataset>`, which ships as `.tar.bz2` and is large enough
that `bunzip2 | peel /dev/stdin` (the FAQ's workaround) discards the
exact property the project exists to deliver: the source's compressed
on-disk footprint is unbounded across the workaround pipe, and a
mid-extraction `kill -9` restarts the whole thing.

The workaround also fails for the multi-mirror (§13 of `PLAN_v2.md`)
and checksum-verified (`--sha256`, §10) paths — both expect `peel` to
own the source-byte side end-to-end. We cannot keep them coherent
while telling users to terminate the source pipe at `bunzip2`.

What changed since 2026-04-29 (round-one freeze):

1. The hand-rolled-decoder pattern is now established by three
   shipped plans (`PLAN_zstd_block_decoder.md`,
   `PLAN_xz_block_decoder.md`, `PLAN_deflate_block_decoder.md`). The
   per-format hand-roll cost has dropped because the skeleton — bit
   reader, registry plumbing, decoder-state blob, resume factory,
   crash-test harness — is recognized infrastructure now, not novel
   scaffolding.
2. `OPTIMIZATIONS.md` §O.32e ("bzip2 + PPMd coders for both 7z and
   standalone use") sits as a deferred 7z follow-on. Doing the
   standalone bzip2 decoder now unblocks O.32e at zero additional
   cost (the 7z `BZip2` method ID `0x04 02 02` plugs the same
   decoder into the 7z folder pipeline; no new decompression
   primitive needed).
3. The format is unusually friendly to our pipeline. Bzip2 blocks
   (≤ 900 KB uncompressed each) are **independently decodable** — a
   48-bit sync header `0x314159265359` (π in BCD) prefixes every
   block and the block CRC sits right after it. Per-block frame
   boundaries fall out of the wire format without any
   archaeology, and the `decoder_state` blob is **~20 bytes** —
   roughly 1700× smaller than the deflate plan's 34 KiB ceiling and
   six orders of magnitude below the zstd plan's 128 MiB cap.

This is **not** an argument for parity with `tar`/`bsdtar` on every
legacy codec — see Deferred. It's a targeted promotion driven by a
real corpus and a clean fit with the existing pipeline.

## Scope

### In scope (round one)

- Pure-Rust **bzip2 decoder** covering bzip2 ≥ 1.0.0 streams as
  produced by `bzip2`, `pbzip2`, `lbzip2`, and `7z -m0=BZip2`. The
  wire format is fixed by the original `bzip2` reference
  implementation (Julian Seward, 1996–2010) and has not changed
  since 1.0.0.
- All five canonical block sizes (`-1` … `-9`, i.e. 100 KB through
  900 KB max block size, encoded in the stream-header `level` byte).
- The full pipeline in inverse order (RFC-equivalent references in
  the "Reference material" section):
  - Bit-level forward stream reader (**MSB-first** byte order — the
    inverse of deflate's LSB-first; this is a real shape difference,
    not a translation bug).
  - Stream header (`BZh<level>`), per-block magic
    (`0x314159265359`), end-of-stream marker (`0x177245385090`), and
    32-bit stream CRC trailer.
  - Per-block 32-bit CRC, randomised-block flag (rejected — see
    Deferred), 24-bit `origPtr` (BWT origin pointer), 16/256-bit
    symbol-used bitmap, 3-bit selector count, delta-encoded Huffman
    selector ranking, 2-6 Huffman tables with canonical-code
    construction.
  - **MTF + RLE2 inverse** (RUNA/RUNB run-length variant operating
    on the MTF index alphabet; bzip2's contribution is fusing these
    two stages in the bit stream).
  - **MTF inverse** producing the BWT-permuted byte stream.
  - **BWT inverse** via the `T[i] = L[i] | (rank(L,i) << 8)`
    inverse-permutation table — O(N) memory at block-size scale
    (≤ ~3.6 MiB for `-9` after fusing).
  - **RLE1 inverse** applied to the concatenated post-BWT byte
    stream of all blocks (RLE1 is a **stream-level** stage in
    bzip2, not per-block — see Phase 6 notes).
- **CRC32 (bzip2 dialect)**. Bzip2 uses the IEEE 802.3 polynomial
  but with **reversed input** and no final XOR — the table is *not*
  binary-compatible with the gzip/zip table at
  [`src/zip/crc32.rs`](../src/zip/crc32.rs). New module
  `crate::hash::crc32_bzip2` (mirrors the file/module layout that
  shipped in Phase 8 of `PLAN_deflate_block_decoder.md`). Cross-
  checked against `bzip2 --test` output during development.
- **Mid-stream `decoder_state()` blob** captured at per-block
  boundaries. Contents:
  - source bit cursor `(byte_offset, bit_offset_in_byte)` —
    bzip2 blocks are bit-aligned, not byte-aligned, so we cannot
    treat the post-block byte position as the resume point;
  - running stream-CRC32 value (4 bytes);
  - RLE1 carry-over state (last byte + run-count-so-far, ≤ 5
    bytes) so the cross-block RLE1 inverse resumes byte-identically.
  - Total ≤ **24 bytes**. The blob is tiny because every block-
    internal state (BWT inverse table, MTF table, Huffman tables)
    is fresh per block by spec.
- **`resume_factory`** that reconstructs a decoder from the blob
  and resumes byte-identically into the original sink. Mirrors the
  lz4 / zstd / xz_native / deflate_native contracts.
- **Per-block `frame_boundary()` advance** so the existing
  extractor checkpoint cadence and puncher fire every block (every
  ≤ 900 KB uncompressed, every ~50–250 KB compressed at typical
  ratios). This is the property the round-one no-bz2 stance traded
  away by directing users at `bunzip2`; getting it back is the
  whole point of the phase.
- **Registry wiring** for the streaming pipeline: format name
  `"bzip2"`, suffixes `.bz2` (Stream), `.tar.bz2` (Tree), `.tbz2`
  (Tree), `.tbz` (Tree), magic `42 5A 68 [31..39]` at offset 0
  (`'B' 'Z' 'h' <level>`). All four `.t*` suffixes already live in
  `STRIPPABLE_EXTENSIONS` (`src/cli.rs:790`) — this plan flips them
  from "stripped from output-name derivation" to "actually
  extractable", with no CLI change required.
- **Doc reversal**. The FAQ entry "No `.bz2` support" is removed,
  the formats.md "not registered; surfaces as `unknown format`"
  line is removed, the format-coverage matrix gets a new row, and
  the FAQ acquires a small note explaining the decision change for
  anyone arriving from a stale link.
- **Crash-test harness extension**. The existing random-`kill -9`
  harness (`PLAN.md` §10) gains a `.tar.bz2` fixture and asserts
  byte-identical resume across kills, same shape as it does today
  for `.tar.zst` / `.tar.xz` / `.tar.gz`.

### Deferred (out of round one)

- **Randomised blocks** (bzip2 0.9.0 legacy flag, the 1-bit
  `randomised` field set after the block-CRC). 0.9.5 (1999) replaced
  the heuristic with a deterministic worst-case selector and has not
  emitted the flag since. Real-world prevalence in the modern corpus
  is essentially zero (`bzip2 -1 -k` from 1.0+ never sets it; only a
  vanishing population of pre-1999 archives do). Round one **rejects
  the block** with `DecodeError::Read` carrying a precise
  "randomised block (bzip2 0.9.0 legacy) is not supported" message
  so the diagnostic is specific. If a real archive trips it, file
  the unrandomise stage as a follow-on; it is ~150 LOC and a small
  per-symbol postprocess (not in the BWT critical path).
- **Mid-block resume** (resume points *between symbols inside* a
  single bzip2 block). The block design — Huffman → MTF → BWT — is
  fundamentally not mid-resumable: the BWT inverse permutation is
  a single monolithic operation against the whole block, and the
  RLE1 inverse only runs after the entire block decompresses. There
  is no implementable mid-block restart point; this is a wire-
  format property, not a code limitation. Per-block frame
  boundaries are the finest granularity bzip2 admits, and at ≤ 900
  KB they are already finer than our 8 MiB checkpoint cadence
  floor.
- **Encoder.** We never emit bzip2; only decompress. No `bzip2`
  fixtures are produced by `peel` itself in tests — fixtures are
  produced offline by the upstream `bzip2` CLI and checked in (the
  same pattern `tar.zst` / `tar.xz` fixtures already follow).
- **7z `BZip2` coder integration.** O.32e in `OPTIMIZATIONS.md`.
  This plan ships the standalone decoder; wiring it into the 7z
  folder pipeline (method ID `0x04 02 02`) is a small follow-on
  (~80 LOC, well-contained in `crate::sevenz::folder`). Filed as
  Phase 12 of this plan but split out behind an explicit "stop
  here" gate so we can demo the streaming-pipeline value before
  taking on 7z's folder-resume model.
- **Multi-stream `.bz2` files** (concatenated streams, the
  bzip2-equivalent of multi-member gzip or multi-Stream xz). The
  bzip2 1.0 CLI accepts these on read (the stream loop is part of
  the reference); this plan supports them too because the cost is
  trivial — the multi-block loop already restarts on the
  `BZh<level>` magic. Calling it out so the test harness covers
  it.
- **Differential fuzz harness against `bzip2-rs` at fuzz scale.**
  Smoke-level differential is in Phase 5; fuzz-scale differential
  is a follow-on (mirrors the precedent set by zstd / xz / deflate).

### Non-goals

- **Beating libbz2 on throughput.** Reference `libbz2` decodes at
  ~70 MB/s on commodity hardware (BWT inverse is the bottleneck;
  bzip2 was designed for the late-1990s memory hierarchy and has
  not aged into modern caches well). Target for the hand-rolled
  decoder is "fast enough not to be the bottleneck against a 1 Gb/s
  download": ~50 MB/s sustained, single-core. This is below libbz2
  but above the network ceiling for any realistic single-host
  download. If we land below 30 MB/s sustained we revisit before
  Phase 6 — bzip2 is the slowest format we will ship and there is
  no point shipping it slower than the network anchor it's
  unblocking.
- **Parallel block decoding** (the `pbzip2` shape). Each block is
  independent, so this is a real opportunity; the round-one
  decoder is single-threaded for the same reason every other
  decoder in the tree is single-threaded (the project's
  parallelism budget is download workers, not decode). File a
  follow-on if profiling on a real corpus shows decode-bound
  behavior dominating extraction time.
- **`bzip2-1.0.6` security CVE recovery paths.** CVE-2016-3189 and
  similar trigger only on malformed inputs; we surface them as
  `DecodeError::Read` with offset context, the same way we handle
  any other format violation. We do not attempt to "recover" past
  a corrupt block — that would diverge from the reference and
  break the "byte-identical output to a clean run" invariant.

## Reference material

- **Bzip2 1.0.6 source** (Julian Seward, Mark Wielaard, Micah
  Snyder; LBZIP2 / pbzip2 forks). The 1.0.6 reference is the
  authoritative wire format; later forks fix CVEs but do not
  change the format. Read `decompress.c` end-to-end before
  starting Phase 0 — it is dense but compact.
  ([`https://sourceware.org/git/bzip2.git`](https://sourceware.org/git/bzip2.git))
- **"A Block-sorting Lossless Data Compression Algorithm"**
  (Burrows & Wheeler, 1994). The BWT is the only non-obvious
  component of bzip2; this is the paper.
  ([`https://www.hpl.hp.com/techreports/Compaq-DEC/SRC-RR-124.pdf`](https://www.hpl.hp.com/techreports/Compaq-DEC/SRC-RR-124.pdf))
- **"Manber-Myers suffix arrays / inverse BWT in O(N) time"**
  references. The inverse-permutation `T[i] = L[i] | (rank(L,i) <<
  8)` trick is older than bzip2; the libbz2 implementation is the
  reference we cross-check.
- **`bzip2-rs`** (pure-Rust bzip2 decoder by `paolobarbolini`,
  MIT/Apache). Useful for cross-checking edge cases during
  development; **not** a runtime dependency we keep — same posture
  as `miniz_oxide` for deflate. Cross-check at smoke scale only;
  the upstream reference is `libbz2`.
- **PKWARE APPNOTE.TXT §4.4.5.12** — confirms zip's `BZIP2`
  compression method (12) uses the bzip2 stream format directly,
  no extra framing. Out of scope for this plan (zip-bzip2 entries
  are not on the round-one zip method list per `PLAN_v2.md` §5),
  but a 50-LOC follow-on once the decoder lands. Filed as
  `O.8b`-companion.
- **7z `BZip2` coder ID `0x04 02 02`** (7-Zip source, `CPP/7zip/
  Compress/Bzip2Decoder.cpp`). Per-folder integration model
  documented in `PLAN_7z_support.md` §"Coders"; this plan files
  the integration as Phase 12.

## Phasing

Each phase is a separate commit (or small commit chain) with its
own tests. Phases ship in order — no parallel work on later phases
while earlier ones are unstable. The phasing structure deliberately
mirrors `PLAN_deflate_block_decoder.md` (same author conventions,
same review style).

### Phase 0 — Spike (2 days, throwaway)

Goal: derisk the bit reader (MSB-first), the canonical-Huffman
construction (bzip2's canonical-code rules diverge subtly from
deflate's — bit-length ordering then symbol-order rather than the
deflate convention), and the BWT inverse permutation against a
known vector before committing to module layout. Pick three
reference vectors:

1. A trivial single-block bz2 file (`bzip2 -1` of a 16-byte input)
2. A medium multi-block file (`bzip2 -1` of a 500 KB input — block
   size 100 KB forces ≥ 5 blocks)
3. A `-9` single-block file with high-entropy contents (forces
   dynamic-Huffman paths to exercise the full selector machinery).

Write a single-file decoder that walks blocks and decodes them
byte-identically to `bzip2 -d`. Don't worry about
`decoder_state` or trait integration yet. Output: a one-page memo
appended to this doc as Appendix A.

**Exit criteria**: three reference vectors decode byte-identical
to `bzip2 -d`. Time-boxed at 2 days; surface blockers before
continuing. If BWT inverse cost exceeds the time-box estimate by
more than 50 %, escalate before starting Phase 5.

### Phase 1 — Module skeleton & MSB-first bit reader (3 days)

- New module `src/decode/bzip2_native/` with submodules
  `bitstream.rs`, `error.rs` (`thiserror`-based local error type
  that maps cleanly to `DecodeError`), `mod.rs` (public surface
  stub).
- `bitstream.rs`: `BitReader` over an internal buffer fed by an
  underlying `Read`. Bzip2 byte order is **MSB-first** (RFC-style:
  the high bit of each byte is the first bit read). Provides:
  - `peek_bits(n) -> u32` (without advancing — for Huffman decode
    lookups and the 48-bit block-magic match)
  - `consume_bits(n)` (advance by `n` bits)
  - `read_bits(n) -> u32` (peek + consume; the common case; `n ≤
    24` is the documented contract — Huffman codes are at most 20
    bits, the BWT origin pointer is 24 bits)
  - `read_u32_be() -> u32` (32-bit CRC reads; saves us spelling
    out four `read_bits(8)` calls and clarifies intent)
  - `byte_position() -> (u64, u8)`: source-byte high-water mark
    and bit offset within the current byte. **The decoder's
    `bytes_consumed` reports the floor**: bytes the decoder has
    fully consumed and that the bit cursor has moved past. The
    byte that the bit cursor is fractionally inside is *not*
    freeable — resume will need to re-read it. (Same contract as
    the deflate plan's bit reader; the documentation is reused
    verbatim by `pub use` of the contract notes.)
- Pure logic, no allocation beyond the input buffer. Heavily
  unit-tested against hand-built bit patterns; cross-checked
  against `bzip2-rs` `BitReader` on identical inputs (smoke level,
  dev-dep only).
- The existing `src/decode/` registry stays in place; this phase
  adds the new module *behind* a build cfg `peel_bzip2_native` so
  we can develop without breaking `cargo test` until the wire-up
  in Phase 9.

**Exit criteria**: `cargo test --features peel_bzip2_native`
passes; the module compiles cleanly with `clippy -- -D warnings`.

### Phase 2 — Stream and block framing (3 days)

The "outer envelope" pass. Walks the stream header → per-block
magic loop → EOS marker → stream-CRC trailer without yet decoding
block contents.

- `stream.rs`: stream-header parser (`BZh<level>` with `level ∈
  '1'..='9'`); the level byte gates `max_block_size` (100 KB ×
  level). Validate magic; reject `BZh0` (legacy "marker" stream,
  not seen in the wild and not produced by any modern encoder).
- `block.rs`: block-magic parser — read 48 bits, compare against
  `0x314159265359` (compressed-block-start) and
  `0x177245385090` (end-of-stream). The 48-bit match is bit-
  aligned, not byte-aligned, so it goes through `read_bits(24)`
  twice rather than a byte-level memcmp.
- Per-block header fields up to but **not** including the
  Huffman-coded body: 32-bit block CRC, 1-bit randomised flag
  (rejected with `DecodeError::Read` per Deferred), 24-bit
  `origPtr`, 16-bit "symbols used" row-map, then 16-bit columns
  for each populated row (the standard sparse-symbol-set encoding).
- After the EOS marker: 32-bit combined-stream CRC. Validate
  against the running stream-CRC accumulator — at Phase 2 the
  accumulator is hard-coded zero and CRC validation is a no-op;
  Phase 6 wires the real CRC.
- Multi-stream loop: after a stream's EOS+CRC the reader looks for
  another `BZh<level>` magic; on match it loops, on EOF it
  terminates cleanly.

**Tests**: framing-only vectors. Hand-craft a stream with no
blocks (just header + EOS + CRC, which `bzip2` never emits but
which our parser must reject cleanly — there is no valid "empty
stream" in bzip2). Hand-craft a stream with three trivially-
small blocks and verify the framing pass walks them without
decoding bodies.

**Exit criteria**: framing parser walks every fixture without
panic; clippy clean.

### Phase 3 — Huffman tables & selectors (5 days)

The largest sub-pass — bzip2's Huffman layer is the densest part
of the wire format.

- `huffman.rs`: canonical Huffman table builder
  `build_table(code_lengths) -> DecodeTable` that produces a flat
  lookup table keyed by `peek_bits(MAX_CODE_BITS)` for fast O(1)
  decode. Max code length in bzip2 is 20 bits (vs. deflate's 15);
  the table is `1 << 20 = 1_048_576` entries × 4 bytes
  (`(symbol, length)` packed) = 4 MiB worst case **per table**.
  Bzip2 packs **2–6 tables per block** with a selector ranking
  choosing between them every 50 symbols (a "group"); we
  allocate the tables once per block and reuse them across
  groups. The 4 MiB peak is real but transient — it is freed at
  the block boundary.
- *Optimisation note (deferred to Phase 11)*: bzip2 tables are
  sparse — only `nSymbols` of the 1M slots are populated. A
  two-level lookup (8-bit primary, residual-bits secondary)
  would shrink working set to ~1 KB/table at a small per-symbol
  cost. Phase 11 measures and decides; round one accepts the
  4 MiB transient for clarity.
- `selectors.rs`: the per-block selector ranking. Reads
  `numSelectors` (3 bits → numSelectorsHi, 12 bits → numSelectors)
  delta-coded selectors-of-MTF-rank into a `Vec<u8>` of group →
  table indices.
- Wire `huffman.rs` + `selectors.rs` into the Phase 2 block-
  header pass; emit a sequence of decoded symbols (MTF indices
  + RUNA/RUNB + EOB) into a temporary `Vec<u16>`. The
  MTF → BWT → RLE1 inverse stages land in Phases 4 and 5.

**Tests**:
- Hand-crafted canonical-Huffman fixtures with known code-length
  vectors; decode to expected symbols.
- Selector-decoding fixtures with 1, 2, 6 tables and 1, 18, 18000
  selectors (the upper bound is 18 002 groups at 900 KB ÷ 50).
- Differential against `bzip2-rs` huffman decode on the spike
  vectors from Phase 0.

**Exit criteria**: every fixture decodes to byte-identical
symbol stream; clippy clean.

### Phase 4 — MTF & RLE2 inverse (3 days)

The fused Move-To-Front + run-length-2 layer that bzip2 applies
between Huffman and BWT. RUNA / RUNB symbols encode run lengths
in a base-2 representation that decodes into "repeat the
zero-index byte N times"; all other symbols are MTF indices into
a 256-byte alphabet maintained per block.

- `mtf.rs`: `MtfState { table: [u8; 256], len: u8 }`. The MTF
  alphabet is initialised from the block-header "symbols used"
  set (not from 0..256) — this is a real bzip2 quirk that costs
  an hour to debug if missed. Provides `pop(rank: u8) -> u8` and
  `init(used_symbols: &[u8])`.
- `rle2.rs`: the RUNA/RUNB → zero-run expansion. RUNA = bit 0,
  RUNB = bit 1, accumulated MSB-first into a run-length-1 count
  (note: RLE2's run encoding is over the **MTF index 0** symbol;
  the actual byte emitted after MTF inverse is whatever the MTF
  state at index 0 currently points to).
- Wire into Phase 3's symbol stream → produce the post-MTF
  byte stream (the BWT-permuted byte sequence).

**Tests**:
- MTF fixtures with hand-crafted symbol sets — exercise the
  symbols-used-bitmap initialisation specifically.
- RLE2 fixtures: zero-run lengths 1, 2, 3, 7, 50, 10_000.
  Validate against `bzip2-rs` smoke vectors.

**Exit criteria**: byte-identical MTF/RLE2 output for all
fixtures; clippy clean.

### Phase 5 — BWT inverse & block CRC (5 days)

The performance-critical block pass. The BWT inverse is the only
bzip2 stage that allocates per-byte working memory at block-size
scale.

- `bwt.rs`: inverse-permutation table construction. Given the
  block's "last column" `L` (the MTF-decoded bytes) and the
  origin pointer `origPtr`, build `T[i] = L[i] | (rank(L, i) <<
  8)` and walk it `origPtr → T[origPtr] >> 8 → …` to emit the
  original block in forward order. Memory is `4 × block_size`
  bytes — up to ~3.6 MiB for `-9`. The walk is the hot path; it
  is a single counted loop with one indexed load per byte.
- `crc32_bzip2.rs` (in `src/hash/`): bzip2's CRC32 dialect.
  IEEE 802.3 polynomial, **reversed input** (bits of each byte
  are processed MSB-first, equivalent to a standard CRC32 over
  bit-reversed bytes), **no final XOR**. The table is built by
  the standard `(c << 1) ^ (poly & ((c & 0x80) >> 7).wrapping_neg())`
  pattern; 256-entry, 1 KiB. Cross-checked against `bzip2 --test`
  CRC output during dev. Note: this is a different table from
  `src/zip/crc32.rs` — do **not** re-export from there. Add a
  module-level comment naming the divergence and pointing to
  this doc.
- Per-block CRC validation: compute the bzip2 CRC over the
  RLE1-encoded block bytes (the input to the per-block CRC is
  the *pre*-RLE1 byte stream, i.e. the BWT inverse output —
  named `blockCRC` in `libbz2`). Mismatch ⇒ `DecodeError::Read`
  with offset context.
- Stream CRC accumulator: `streamCRC = ((streamCRC << 1) |
  (streamCRC >> 31)) ^ blockCRC` (the bzip2-specific rotate-and-
  XOR combiner). Validated at EOS against the trailing 32-bit
  stream CRC.

**Tests**:
- BWT-only fixtures: hand-craft a 4-byte block, verify forward
  walk produces the expected output.
- Round-trip fixtures: BWT-encode → BWT-decode on random inputs,
  byte-identical.
- CRC fixtures: NIST-style test vectors derived from running
  `bzip2 -c < input | xxd` for several inputs; cross-checked
  against `bzip2 --test`.
- Block CRC mismatch test: corrupt one byte of the block body in
  a fixture, verify the decoder fails with a precise
  "block CRC mismatch" diagnostic and not a generic parse error.

**Exit criteria**: full per-block decode pipeline (Phases 2–5)
produces byte-identical output to `bzip2 -d` on the Phase 0
spike vectors; clippy clean.

### Phase 6 — RLE1 inverse & multi-block stream (3 days)

The final inverse stage. RLE1 is applied **at the stream level**,
not per block — bzip2 encodes the input through RLE1 *before*
splitting into blocks, so the inverse must run after every
block's BWT output has been emitted, with state carried across
block boundaries.

- `rle1.rs`: forward-only state machine. Reads one byte at a time
  from the BWT output stream; when four identical bytes in a row
  appear, the *fifth* byte is the explicit count (0–255) of
  additional repeats. State: `last: u8, run: u8` (`run` counts how
  many identical bytes have been seen in a row, 0..=4; ≥ 4 means
  the next byte is a count).
- Wire RLE1 inverse downstream of Phases 2–5's per-block emit
  loop — same `dyn Write` sink the rest of the decoder writes to.
- Multi-stream `.bz2` files: when EOS+CRC is consumed, the
  outer loop looks for another `BZh<level>` magic; on match,
  re-enter the per-block loop with a *fresh* RLE1 state
  (per-stream, not per-file — see notes below). The bzip2 CLI
  reads multi-stream files by treating each stream's output as
  separate and concatenating: RLE1 state resets at the stream
  boundary, not the block boundary. This is a real correctness
  point — getting it wrong silently corrupts the output by one
  byte at multi-stream concatenation points.

**Tests**:
- Hand-crafted RLE1 sequences: `[a, a, a, a, 0]` decodes to
  `[a, a, a, a]`; `[a, a, a, a, 7]` decodes to 11× `a`.
- Cross-block RLE1: construct a multi-block fixture where a run
  straddles a block boundary; verify state carries correctly.
- Multi-stream RLE1: construct a two-stream `.bz2` (`cat a.bz2
  b.bz2 > c.bz2`) where the boundary would mis-decode if state
  carried across streams; verify clean re-init.

**Exit criteria**: end-to-end decode (`Read .bz2` source → byte-
identical `Write` sink) on the Phase 0 fixtures and on a 100
MB synthetic corpus; clippy clean.

### Phase 7 — `StreamingDecoder` trait integration (3 days)

Wire the assembled decoder into the project's trait surface.

- `mod.rs` (replacing the Phase 1 stub): `Bzip2Decoder` struct
  implementing `StreamingDecoder`. Internal state machine:
  `Initial → StreamHeader → BlockMagic → BlockHeader → BlockBody
  → BlockTrailer → StreamTrailer → MultiStreamProbe → Done`.
- `decode_step` is bounded — one block per call, matching the
  ~1 MiB step bound the other decoders honor. On a 900 KB block
  this produces up to ~900 KB of decoded output per step, which
  is consistent with what xz_native delivers on a `-6` Block.
- `bytes_consumed` returns the bit-cursor floor (Phase 1
  contract); `frame_boundary` returns `Some(post_block_offset)`
  on transition from `BlockTrailer → BlockMagic`/`StreamTrailer`
  and from `StreamTrailer → MultiStreamProbe`.
- `set_source_start_offset` seeds the bit-cursor base for the
  resume path (Phase 8 consumer).

**Tests**: existing decoder-trait property tests (the ones that
zstd / xz / deflate already pass) instantiated against
`Bzip2Decoder`. No new test infra.

**Exit criteria**: trait-level property tests pass on the
synthetic corpus; clippy clean.

### Phase 8 — `decoder_state` blob & resume factory (4 days)

The resume-seam phase. Mirrors Phase 7 of
`PLAN_deflate_block_decoder.md` and Phase 8 of
`PLAN_zstd_block_decoder.md`.

- Define the resume blob layout (stable wire format, independent
  of struct layout):

  ```text
  magic:        4 bytes   "PB2R" (peel bzip2 resume)
  version:      1 byte    0x01
  bit_cursor:   9 bytes   u64 byte_offset, u8 bit_offset_in_byte
  stream_crc:   4 bytes   u32 running stream CRC accumulator
  rle1_last:    1 byte    last emitted byte (or 0 if run=0)
  rle1_run:     1 byte    run count so far (0..=4)
  reserved:     4 bytes   zero, for future expansion
  TOTAL:       24 bytes
  ```

  The blob is captured at every frame boundary (Phase 7); the
  observer in the streaming-pipeline coordinator writes it
  through `decoder_state_into(&mut Vec<u8>)` per the
  `PLAN_checkpoint_blob_dedup.md` Phase 2 contract.
  `decoder_state_size_hint` returns `24`.
- `resume_factory`: builds a `Bzip2Decoder` from the blob and a
  source positioned at the cursor's byte offset. The decoder is
  seeded into the `BlockMagic` state with the bit cursor
  positioned mid-byte if necessary, the stream-CRC accumulator
  pre-loaded, and the RLE1 state pre-loaded. `decode_step`
  produces byte-identical output to a clean run from byte 0.
- The frame-boundary always falls *between* blocks, so by
  construction the BWT table, MTF state, and Huffman tables are
  all freshly allocated at resume — no per-block state to
  serialize.

**Tests**:
- Round-trip: serialize state mid-stream, deserialize, feed
  remaining source bytes; output byte-identical to a clean run.
- Cross-boundary: every block boundary in a 10-block fixture is
  a valid resume point; resume from each one produces byte-
  identical output.
- Resume mismatch: feed a `start_offset` that disagrees with the
  blob's captured cursor; verify `DecodeError::ResumeMismatch`
  surfaces (the existing `PLAN_responsiveness.md` §3.2 contract).
- Multi-stream resume: resume across a stream boundary; verify
  RLE1 state correctly resets at the stream-magic transition.

**Exit criteria**: resume tests pass; clippy clean.

### Phase 9 — Registry & coordinator wiring (3 days)

The "ship it" phase. Behind the `peel_bzip2_native` cfg up to
this point; this phase drops the cfg and turns bzip2 on by
default.

- `src/decode.rs` registration in `DecoderRegistry::with_defaults`:
  - Format name `"bzip2"` (default shape `Stream`).
  - Suffixes: `.bz2` (Stream), `.tar.bz2` (Tree), `.tbz2` (Tree),
    `.tbz` (Tree).
  - Magic `42 5A 68` (`'B' 'Z' 'h'`) at offset 0 — the level
    byte is variable (`'1'..='9'`) so the registered magic is
    three bytes; the level byte is validated by the decoder
    constructor on the first `decode_step`. (Alternative: register
    nine variants of the magic, one per level. The single 3-byte
    magic is simpler and the level check is unavoidable inside
    the decoder anyway.)
  - Resume factory: `bzip2::resume_factory`.
- `src/cli.rs`: the `STRIPPABLE_EXTENSIONS` list already includes
  `.tbz2`, `.tbz`, `.bz2` — no change needed there. The four
  suffixes now resolve to a decoder instead of falling through
  to `unknown format`.
- `docs/src/faq.md`: remove the "No `.bz2` support" section
  (lines 23–32); replace with a short "Why bz2 support was added
  in <version>" note pointing back at this plan.
- `docs/src/formats.md`: remove the `.bz2` / `.tar.bz2` row from
  the "What's not (yet) supported" list (line 248); add bzip2 to
  the supported-formats matrix earlier in the page.
- `README.md`: update the format-coverage matrix; add `.tar.bz2`
  to the bench grid (median-of-5, per the recent README update).
- Drop the `peel_bzip2_native` cfg and the gated tests; the
  module is now first-class.

**Tests**: every `registry_with_defaults_*` test in
`src/decode.rs` that today asserts bzip2 is **not** registered
(lines 1010, 1111, 1263) gets flipped to assert that it **is**.
End-to-end test: extract a real `.tar.bz2` fixture into a temp
directory, verify file contents byte-identical to `bzip2 -d |
tar -x` output on the same fixture.

**Exit criteria**: every existing test passes (no regressions);
new tests pass; clippy clean; docs build (`mdbook build docs`)
clean.

### Phase 10 — Hole-punching coverage demo (2 days)

The "value delivered" phase. Mirrors Phase 10 of the deflate
plan and Phase 9 of the zstd plan.

- Add a `.tar.bz2` fixture to `internal/fixtures/` that is large
  enough (≥ 256 MiB compressed) to exercise the puncher
  meaningfully — at typical bzip2 ratios this is a ~1 GiB
  uncompressed tarball with ≥ 300 blocks.
- Demo script that runs `peel -C ./out fixture.tar.bz2` against
  a localhost mock server and observes:
  - Per-block frame boundaries fire every ≤ 900 KB of
    compressed source.
  - The puncher advances every block; peak on-disk source
    footprint stays bounded by the download window (target:
    ≤ 16 MiB, consistent with the other formats).
  - A mid-extraction `kill -9` followed by resume produces a
    byte-identical output tree.

**Exit criteria**: demo passes; the recorded on-disk source
peak is documented in `internal/bench-results/`.

### Phase 11 — Crash-resume integration tests (1 week)

Extend the random-`kill -9` harness (`PLAN.md` §10) to cover
`.tar.bz2`.

- New fixture: `tar.bz2` archive with ≥ 100 blocks (a corpus of
  small files compressed together; reuse the `.tar.gz` /
  `.tar.zst` crash-test fixture generator with a `bzip2` step
  substituted for the compression).
- 100 random kill points across the extraction; every run must
  produce a byte-identical output tree on resume.
- Repeat for a multi-stream `.bz2` fixture (`cat a.bz2 b.bz2 >
  c.bz2`) to exercise the stream-boundary RLE1 reset under
  random kill.

**Exit criteria**: 100/100 kills produce byte-identical output;
no flakes across three consecutive harness runs.

### Phase 12 (gated) — 7z `BZip2` coder integration

> **Status**: gated on Phase 11 ship. Do not start until the
> standalone decoder has been in main for ≥ 2 weeks and has not
> required revert / hotfix.

Wires the `Bzip2Decoder` into the 7z folder pipeline as the
`BZip2` coder (method ID `0x04 02 02`). This delivers half of
`OPTIMIZATIONS.md` §O.32e; the PPMd half stays deferred.

- `src/sevenz/folder.rs`: dispatch on coder ID `0x04 02 02` →
  `Bzip2Decoder::new(source)`. The 7z folder pipeline already
  threads a `Box<dyn StreamingDecoder>` per coder; no new trait
  surface.
- Folder-level resume: per-coder `decoder_state` blob storage
  already exists in `SinkState::SevenZ` (added in `PLAN_7z_support.md`
  Phase 8); the blob carries through unchanged.
- Update `OPTIMIZATIONS.md` §O.32e: mark "bzip2 half delivered
  in PLAN_bz2_support §12; PPMd half remains deferred".

**Tests**: round-trip a `.7z` archive compressed with
`-m0=BZip2` (created offline with `7z`) and verify byte-identical
extraction.

**Exit criteria**: 7z `.7z -m0=BZip2` fixture extracts byte-
identical to `7z x` output; clippy clean.

## Decisions to resolve before Phase 1

Resolve these in a small commit at the head of the Phase 1
commit chain so the audit trail is in tree, not just in this
plan:

1. **Module path**. Pick one of:
   - `src/decode/bzip2_native/` (matches `xz_native`, `deflate_native`
     precedent — **recommended**)
   - `src/decode/bzip2/` (matches `lz4`, `zstd` precedent for non-
     name-conflicting decoders)
   The two-tier precedent exists because xz / deflate started life
   as upstream-crate wrappers and the `_native` suffix marked the
   hand-rolled replacement during the transition. Bzip2 has no
   prior wrapper; the `_native` suffix is therefore *technically*
   unnecessary. Recommended anyway for symmetry with the most
   recent format additions and to leave room if a future plan
   ever wraps `bzip2-rs` for benchmarking-cross-check purposes.

2. **Feature gate**. Do we ship behind a Cargo feature
   (`bzip2`, default-on) the way `rar` is gated, or unconditionally
   compiled in? Recommended: **unconditional** for round one.
   The 4 MiB transient Huffman-table allocation is the only real
   binary-size cost; the decoder itself is ~3 KLOC of pure logic
   with no transitive deps. Compare `rar`, which is gated because
   it adds ~12 KLOC and pulls in PPMd-II.

3. **Doc reversal sequencing**. Drop the FAQ "No `.bz2` support"
   section in Phase 9 (same commit as the registry wire-up), or
   in a separate commit between Phase 9 and Phase 10? Recommended:
   **same commit**. The FAQ promise diverges from the registry
   the moment Phase 9 lands; splitting them creates a window
   where the doc lies.

4. **Bench corpus**. The README's "bench grid: median-of-5"
   needs a `.tar.bz2` row. Pick the corpus once and document it
   in the bench-results dir alongside the existing `tar.zst` /
   `tar.xz` corpora. Recommended: the **Linux 3.0 tarball**
   (`linux-3.0.tar.bz2`, ~75 MiB compressed, public, stable
   URL). The same corpus is used by `xz`'s own benchmarking
   suite; reusing it lets reviewers cross-reference against
   published xz/bz2 ratio comparisons.

## What "ship" means

All of the following are true:

1. `peel https://.../<corpus>.tar.bz2 -C ./out` extracts byte-
   identical to `bzip2 -d | tar -x` on the same source.
2. The crash-test harness (Phase 11) passes 100/100 kills across
   three consecutive runs.
3. Per-block hole-punching coverage matches the other formats:
   peak on-disk source footprint ≤ 16 MiB on the Phase 10 demo
   corpus.
4. CI gates listed in `ENGINEERING_STANDARDS.md` §CI remain green;
   coverage thresholds (80 % overall, 95 % on critical paths) hold
   for the new module tree.
5. Docs (`mdbook build docs`) build clean; the FAQ no longer
   claims bzip2 is unsupported; the format-coverage matrix
   includes the new row; README bench grid includes the new row.
6. `OPTIMIZATIONS.md` §O.32e is updated to mark the bzip2 half
   delivered (Phase 12) if Phase 12 ships, or annotated "unblocked
   pending integration" if Phase 12 is held.

## Schedule guidance

There is no schedule. The plan is sequenced; do it in order, do
each phase completely. Phases 0–6 are gating dependencies for one
another (the decoder must work end-to-end before it can be wired
up). Phases 7–9 are also sequential (trait integration → resume
seam → registry). Phase 10 and Phase 11 can be parallelized only
if two reviewers are available and the harness fixture in 11
does not depend on the bench corpus in 10 (they don't share, so
parallel is fine). Phase 12 is gated as noted.

## Appendix A — Spike findings folded into the plan

Phases 1–11 landed in one execution sweep; the discrete Phase 0
spike was folded into the Phase 1 skeleton commit. The plan held
up well, with three wrinkles worth pinning here for future
reference (one bug class, one prose error, one debug-mode-only
performance issue):

1. **BWT walk direction.** The plan's prose described the LF-side
   formulation `T[i] = L[i] | (LF(i) << 8)`, which walks the
   *original sequence in reverse* from `origPtr`. The first
   in-place implementation matched the prose, ran clean against
   the round-trip property tests, and produced reversed output on
   real `.bz2` fixtures. The decoder now uses the FL form
   `T[LF(i)] = (i << 8) | L[i]` — same memory, same one-load-per-
   byte walk, but emits forward. See `src/decode/bzip2_native/bwt.rs`
   for the cross-reference and the in-test forward BWT used to
   verify the inverse.

2. **Per-block CRC scope.** The plan stated the per-block CRC is
   "computed over the BWT inverse output (the pre-RLE1 byte
   stream)". The bzip2 reference (`bzlib_private.h` /
   `BZ_FINALISE_CRC`) actually computes it over the
   **RLE1-expanded** byte stream — i.e. the bytes the decoder
   ultimately emits for the block, *not* the BWT-inverse output.
   The two diverge whenever any run ≥ 4 exists in the original
   input. `src/decode/bzip2_native.rs::process_block` now stages
   the RLE1 output to a per-block buffer, hashes that, and
   compares to the block-header CRC.

3. **Multi-stream byte alignment.** The plan's multi-stream loop
   describes "on EOS+CRC, look for another `BZh<level>` magic". The
   bzip2 encoder's `bsFinishWrite` pads each stream's last byte
   with zeros, and the next concatenated stream begins at the next
   byte boundary; without an explicit `align_to_byte()` between
   streams the decoder reads the padding bits as part of the next
   stream's magic and surfaces a 1-bit-shifted "bad magic"
   diagnostic. `bitstream::BitReader::align_to_byte` was added for
   this; the `AwaitingMultiStreamProbe` arm calls it before
   probing.

Performance: the BWT-inverse table fit the plan's ~3.6 MiB
estimate at level 9 (`4 × block_size` bytes), and the Huffman flat
table sized at `1 << observed_max_len` rather than the worst-case
`1 << 20` keeps a typical block at ≤ 512 KiB per group. The MTF
inverse's O(rank) per-byte shift is the debug-build hotspot — a
500 KB random-bytes round-trip takes ~30 s in `cargo test`
(unoptimised) but ~0.5 s in `cargo test --release`. Phase 11
crash-resume tests run in release for that reason; the unit-test
ceilings (`round_trips_120kb_forces_multiple_blocks_at_level_1`,
`resume_blob_round_trips_at_every_block_boundary`) are sized so
the debug-build pass stays under a couple of seconds.

The 7z `BZip2` coder integration (Phase 12, gated) was *not*
landed in this sweep — held per the plan's "≥ 2 weeks soak"
gate.
