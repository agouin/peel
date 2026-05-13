# PLAN — Hand-rolled DEFLATE block decoder for mid-stream resume

**Status**: proposed (2026-05-03).
**Owner**: TBD.
**Supersedes**: nothing — additive to `PLAN_v2.md`. Promotes the deferred
"gzip / zip-DEFLATE mid-stream checkpoint" gap surfaced in the
2026-05-03 autoresume audit.

## Why we're doing this

Today the gzip path wraps `flate2::bufread::GzDecoder`
([`src/decode/gzip.rs:228-336`](../src/decode/gzip.rs#L228-L336)) and
the zip path wraps `flate2::read::DeflateDecoder`
([`src/zip/decode.rs:118`](../src/zip/decode.rs#L118)). `flate2` (with
`rust_backend`, i.e. `miniz_oxide`) decodes correctly but exposes no
mid-stream restart hook. The only restart-safe boundaries we can
currently surface are:

- **gzip**: end-of-member ([`gzip.rs:258-265`](../src/decode/gzip.rs#L258-L265)).
- **zip-DEFLATE**: end-of-entry. Mid-entry resume is downgraded to
  "restart the entry from byte 0"
  ([`zip_pipeline.rs:393-410`](../src/download/zip_pipeline.rs#L393-L410)).

The dominant real-world shapes are exactly the worst case for both:

- A `.tar.gz` is almost always a **single gzip member** wrapping the
  whole tarball — no member boundaries before EOF, so
  `frame_boundary()` returns `None` for the entire run, the
  checkpoint observer never fires, the puncher never advances, and a
  `kill -9` mid-extraction restarts from byte 0.
- A `.zip` with a single big DEFLATE entry (a JDK distribution, a
  game asset bundle) has the same property at the entry level.

Decode-from-zero on resume gets us about **1 GiB/7 s** at miniz_oxide
throughput. The autoresume target is ≤ 1 minute, so we miss it once
the compressed payload exceeds ~9 GiB. This is the same failure mode
the zstd plan fixed for `.tar.zst` (`internal/PLAN_zstd_block_decoder.md`)
and the xz plan fixed for `.tar.xz`
(`internal/PLAN_xz_block_decoder.md`). Same root cause: the upstream
library exposes no mid-stream hook; the on-wire format itself
*does* have a usable restart point (the deflate-block boundary,
RFC 1951 §3.2.3) but it is not surfaced through any C-shim API we
can call into.

Three approaches were considered (mirrors zstd / xz triage):

- **A. Re-decompress the prefix on resume.** Fixes resume but
  prevents per-deflate-block hole-punching: punching past the gzip
  member start makes fast-skip impossible. Disk-frugality regresses
  for any multi-GiB single-member `.tar.gz` — the dominant shape.
- **B. Per-member only (status quo).** Doesn't help the
  one-member-per-archive case.
- **C. Hand-roll inflate.** Per-deflate-block restart points;
  puncher fires every block; resume carries a small (32 KiB sliding
  window + a few hundred bytes of decoder state) blob; mid-stream
  is a first-class citizen for both gzip and zip-DEFLATE.

We pick **C**, on the same load-bearing-property argument as the
zstd and xz plans: per-format puncher coverage is the project's
value proposition (`CLAUDE.md` §"What this project is": "never use
more than ~300 MB of disk for the compressed side"), and round-one
regresses it for the dominant gzip / zip-DEFLATE archive shape.

This is a multi-week project. Phasing is structured so each phase
ends in a runnable, tested artifact and integrates with the existing
`StreamingDecoder` trait at recognized milestones.

## Scope

### In scope (round one)

- Pure-Rust **inflate decoder** for raw DEFLATE streams produced by
  any standard encoder (gzip CLI, `pigz`, libdeflate, miniz_oxide,
  zlib at any compression level).
- All three deflate block types (RFC 1951 §3.2.3): `BTYPE=00`
  (stored, byte-aligned uncompressed run), `BTYPE=01` (fixed
  Huffman, RFC 1951 §3.2.6 precomputed tables), `BTYPE=10` (dynamic
  Huffman, RFC 1951 §3.2.7 with HLIT / HDIST / HCLEN code-length
  preamble). `BTYPE=11` rejected as reserved.
- LZ77 back-reference resolution with overlap-by-design (RFC 1951
  §3.2.5: match length up to 258 bytes, distance up to 32 768).
- 32 KiB sliding window with ring-buffer storage; wrap-around
  match copy.
- Bit-level forward bitstream reader (LSB-first byte order,
  LSB-first bit order within each byte per RFC 1951 §3.1.1).
- **gzip framing** (RFC 1952): magic, flags (FTEXT, FHCRC, FEXTRA,
  FNAME, FCOMMENT bits), MTIME / XFL / OS, optional CRC16 of
  header, member trailer (CRC32 of uncompressed bytes + ISIZE
  mod 2^32), concatenated members.
- **CRC32 (IEEE 802.3 polynomial)** computed over decompressed
  bytes during decode. Reuses the table already shipping at
  [`src/zip/crc32.rs`](../src/zip/crc32.rs) — same polynomial as
  gzip and zip-DEFLATE. `pub use` it from the new module rather
  than re-deriving the table.
- **Mid-stream `decoder_state()` blob** captured at deflate-block
  boundaries: 32 KiB sliding-window snapshot, source bit cursor
  (`(byte_offset, bit_offset_in_byte)`), running gzip framing
  state (current member's CRC32 + ISIZE counter, member-header
  parser progress if straddling), block-level metadata
  (`BFINAL_seen`). Capped at **34 KiB + small constant** —
  ~3700× smaller than the zstd plan's 128 MiB ceiling.
- **`resume_factory`** that reconstructs a decoder from the blob
  and resumes byte-identically with the original sink. Mirrors
  lz4 / zstd / xz contracts.
- **Per-deflate-block `frame_boundary()` advance** so the existing
  extractor checkpoint cadence and puncher fire every block
  boundary.
- **ZIP-DEFLATE integration**: wire the new decoder into
  [`src/zip/decode.rs::decompress_entry`](../src/zip/decode.rs)
  for `CompressionMethod::Deflate`, *and* extend
  [`ZipResumeState`](../src/download/zip_pipeline.rs) /
  [`SinkState::Zip`](../src/checkpoint.rs) with an optional
  per-entry `decoder_state` blob so DEFLATE entries resume
  mid-entry instead of restarting from byte 0.
- **ZIP-zstd resume plumbing** (small companion change). The
  existing zstd `decoder_state` infra already produces blobs at
  the streaming-pipeline boundary; the zip pipeline today
  discards them. Threading the blob through `extract_entry` is
  a pure-plumbing follow-on that costs ~50 LOC and removes a
  parallel "we'll fix this when we fix DEFLATE" footnote in
  `OPTIMIZATIONS.md`.

### Deferred (out of round one)

- **Mid-deflate-block resume** (resume points *between symbols
  inside* a single dynamic-Huffman block). Block boundaries are
  every 32–64 KiB of compressed data at typical encoder defaults;
  per-block coverage is far finer than the existing 8 MiB
  checkpoint cadence floor needs. Mid-block requires capturing
  Huffman-table state, partial code-in-flight, and the LZ77
  state machine — much larger blob, much more code surface, no
  measurable user-facing improvement.
- **Encoder.** We never emit gzip / zip; only decompress. The
  existing `flate2::write::GzEncoder` / `DeflateEncoder` usage
  in tests stays put.
- **zlib framing** (RFC 1950: 2-byte header + 4-byte Adler-32
  trailer). Not currently produced by any source we extract;
  add a clean rejection if a `.zlib` source ever appears. (gzip
  and zip-DEFLATE both use raw deflate, not zlib-framed.)
- **Differential fuzz harness against `flate2` / `miniz_oxide`
  at fuzz scale.** Smoke-level differential is in Phase 5; fuzz
  is a follow-on (mirrors the precedent set by zstd / xz).
- **AES / encrypted zip-DEFLATE entries.** Already filed under
  `OPTIMIZATIONS.md` §O.8b; orthogonal to this plan.

### Non-goals

- Beating miniz_oxide on throughput. miniz_oxide is the de-facto
  pure-Rust inflate baseline at ~250 MB/s decode on commodity
  hardware. A clean-room hand-rolled decoder will be slower at
  first; target is "fast enough not to be the bottleneck against
  1 Gb/s download" — roughly **150 MB/s** sustained on commodity
  hardware. This is below miniz_oxide but above the network
  ceiling for any realistic single-host download. If we land
  below 80 MB/s sustained we revisit before Phase 6.

## Reference material

- **RFC 1951** — DEFLATE Compressed Data Format (lossless).
  Authoritative wire format for the inflate stream.
  ([`https://www.rfc-editor.org/rfc/rfc1951`](https://www.rfc-editor.org/rfc/rfc1951))
- **RFC 1952** — GZIP file format. Authoritative wire format for
  the gzip member envelope.
  ([`https://www.rfc-editor.org/rfc/rfc1952`](https://www.rfc-editor.org/rfc/rfc1952))
- **RFC 1950** — ZLIB Compressed Data Format. Read for cross-
  reference; not implemented in round one (see Deferred).
- **PKWARE APPNOTE.TXT** — confirms zip-DEFLATE entries use raw
  deflate (no zlib header / trailer) inside the LFH-bracketed
  payload. The CRC32 is recorded in the central directory (or the
  trailing data descriptor when GP-flag bit 3 is set), not in the
  deflate stream itself.
- **`miniz_oxide`** (pure-Rust inflate, the `flate2`
  `rust_backend`). Useful for cross-checking edge cases during
  development; **not** a runtime dependency we keep — Phase 8
  drops it from the runtime dep tree the same way Phases 7-8 of
  the xz / zstd plans did for `xz2` and `zstd`.
- **`zlib`** / **`libdeflate`** as encoder reference
  implementations. Read for cross-checks, not for copy-paste —
  clean-room Rust per `ENGINEERING_STANDARDS.md` §2 (same
  discipline as zstd / xz).

## Phasing

Each phase is a separate commit (or small commit chain) with its own
tests. Phases ship in order — no parallel work on later phases while
earlier ones are unstable.

### Phase 0 — Spike (1–2 days, throwaway)

Goal: derisk the bit reader, dynamic-Huffman code-length-codes
preamble, and 32 KiB sliding-window match-copy before committing
to module layout. Pick three reference vectors (tiny stored block,
medium fixed-Huffman, large dynamic-Huffman) and write a single-
file decoder that walks deflate blocks and decodes them. Don't
worry about `decoder_state` or trait integration yet. Output: a
one-page memo appended to this doc as Appendix A.

**Exit criteria**: three reference vectors decode byte-identical
to `gunzip` / `unzip`. Time-boxed at 2 days; surface blockers
before continuing.

### Phase 1 — Module skeleton, stored blocks (BTYPE=00) (3 days)

- New module `src/decode/deflate_native/` with submodules
  `block.rs` (block-header parser + `BTYPE=00` body),
  `error.rs` (`thiserror`-based local error type that maps
  cleanly to `DecodeError`).
- The existing `src/decode/gzip.rs` wrapper stays in place as
  the default-registered factory; this phase adds the new
  module *behind* it, gated by build cfg `peel_deflate_native`
  so we can develop without breaking `cargo test`.
- Public surface: `Decoder::new(src) -> Self` and a single
  `decode_step(&mut self, sink: &mut dyn Write) -> Result<...>`
  that handles the `Initial -> InBlock { ctx } -> Done` state
  machine for stored blocks only. Fixed and dynamic blocks
  return `DecodeError::Read("dynamic/fixed Huffman block decoding
  not yet implemented")` until Phases 3 and 4.

**Tests**: bytes-in/bytes-out byte-identical for hand-built
fixtures consisting of `BTYPE=00` blocks only (a stored-only
deflate stream is `gzip --rsyncable`-uncomon but trivially
constructible).

**Exit criteria**: `cargo test --features peel_deflate_native`
passes; the module compiles cleanly with `clippy -- -D warnings`.

### Phase 2 — Bit reader (2 days)

The deflate analogue of zstd's `bitstream.rs` and xz's
`range_coder.rs`. Foundation for Phases 3 and 4.

- `bitstream.rs`: `BitReader` over an internal buffer fed by an
  underlying `Read`. RFC 1951 §3.1.1 byte order is LSB-first;
  bits within a byte are packed LSB-first. Provides:
  - `peek_bits(n) -> u32` (without advancing — for Huffman
    decode lookups)
  - `consume_bits(n)` (advance by `n` bits)
  - `read_bits(n) -> u32` (peek + consume; the common case)
  - `align_to_byte()` (RFC 1951 §3.2.4: stored blocks are
    byte-aligned; the reader skips the remaining 0–7 bits of
    the current byte)
  - `byte_position() -> (u64, u8)`: source-byte high-water
    mark and bit offset within the current byte. **The
    decoder's `bytes_consumed` reports the floor**: bytes the
    decoder has fully consumed and that the bit cursor has
    moved past. The byte that the bit cursor is fractionally
    inside is *not* freeable — resume will need to re-read it.
- Pure logic, no allocation beyond the input buffer. Heavily
  unit-tested against hand-built bit patterns; cross-checked
  against `miniz_oxide`'s `read_bits` on identical inputs.

**Exit criteria**: tests pass; clippy clean.

### Phase 3 — Fixed-Huffman blocks (BTYPE=01) (3 days)

The smaller of the two Huffman block types — uses RFC 1951
§3.2.6's precomputed tables, no per-block table construction.

- `huffman.rs`: canonical Huffman table builder
  (`build_table(code_lengths) -> DecodeTable`) that produces a
  flat lookup table keyed by `peek_bits(MAX_CODE_BITS)` for
  fast O(1) decode. Max code length in deflate is 15 bits, so
  the table is `1 << 15 = 32768` entries × 2 bytes (code +
  length) = 64 KiB worst case. For round one this is allocated
  per-block; Phase 11 may revisit with a two-level table for
  cache friendliness.
- The fixed-Huffman literal/length and distance tables are
  precomputed `const` arrays transcribed from RFC 1951 §3.2.6.
  Lit/length: 288 codes; distance: 32 codes (only 30 used).
- Match-length / distance code post-decoding: the lit/length
  symbol decodes to a base length + extra bits (RFC 1951
  §3.2.5 Tables); same for distance codes. Two small `const`
  lookup tables per RFC.
- Wire `BTYPE=01` into Phase 1's state machine: read symbols,
  dispatch to `append_byte` or `match_copy` against the window.
  (Window itself lands in Phase 5 — for now use a flat
  `Vec<u8>` to keep Phase 3 testable in isolation.)

**Tests**:

- Property: random `&[u8]` payloads round-tripped through
  `flate2::write::DeflateEncoder` at level 1 (which prefers
  fixed Huffman for short inputs) and decoded byte-identical
  by our path.
- Hand-built test for the lit/length code-256 (end-of-block)
  and the distance-code edge cases (codes 0..3 = literal
  distances 1..4 with no extra bits).

**Exit criteria**: 50 random fixed-Huffman fixtures decode
byte-identical to `flate2`.

### Phase 4 — Dynamic-Huffman blocks (BTYPE=10) (1.5 weeks)

The largest single piece. RFC 1951 §3.2.7's code-length-codes
preamble is the deflate equivalent of zstd's FSE distribution
parser — pointy and easy to get subtly wrong.

- Parse `HLIT` (5 bits, 257..286 lit/length codes), `HDIST`
  (5 bits, 1..32 distance codes), `HCLEN` (4 bits, 4..19
  code-length-code lengths). Read `HCLEN + 4` 3-bit code
  lengths in the permuted order
  `[16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2,
    14, 1, 15]`.
- Build the code-length-code Huffman table (max code length 7).
- Decode the lit/length and distance code-length sequences,
  applying RLE codes 16 (repeat last 3+`extra_2_bits` times),
  17 (zero 3+`extra_3_bits` times), 18 (zero
  11+`extra_7_bits` times). Bounds-check that the total decoded
  count == `HLIT + HDIST + 258`.
- Build the lit/length and distance Huffman tables from the
  decoded lengths.
- Decode the block body using the new tables (same path as
  Phase 3's fixed-Huffman body, just different tables).

**Tests**:

- Differential: 100 random fixtures through `miniz_oxide` vs
  the new decoder, byte-identical.
- Hand-built test exercising RLE codes 16/17/18 in the
  code-length sequence (force-construct a fixture using
  zlib's `deflateInit2` at level 9 on a payload that triggers
  long zero runs in the distance-code-length table).
- Edge case: HCLEN = 4 (minimum), HLIT = 257 (only literal 0
  used + EOB), HDIST = 1 (single distance code).

**Exit criteria**: 500 random dynamic-Huffman fixtures decode
byte-identical to `flate2`.

### Phase 5 — Sliding window & multi-block stream (3 days)

This is where decoded symbols become decompressed bytes that
can feed the next block's matches.

- `window.rs`: ring buffer sized to 32 KiB (deflate's max).
  Provides:
  - `append_byte(u8)` for literal output
  - `match_copy(distance: u32, length: u32)` for back-
    references (handles overlap-by-design: when
    `length > distance`, the early bytes of the copy are read
    as soon as they're appended — RFC 1951 §3.2.5)
  - `recent(&self, n: usize) -> &[u8]` for the snapshot path
    in Phase 7
- Block iteration: the outer state machine reads `BFINAL`
  (1 bit) and `BTYPE` (2 bits) per block, dispatches to the
  per-type body, then loops until `BFINAL=1` and that block
  ends. EOF after the last block is **bit-aligned** — the
  remaining bits of the final byte are discarded, the underlying
  reader's byte cursor advances to the next byte, and (in gzip
  framing) the trailer parser takes over.

**Tests**:

- Random multi-block fixtures (encoded with deflate at varying
  levels) decode byte-identical to `flate2`.
- A fixture that crosses block boundaries with a back-reference
  whose distance reaches into the previous block.

**Exit criteria**: the test corpus from `tests/test_extractor.rs`'s
gzip / zip fixtures decodes through the new path with
`--features peel_deflate_native`.

### Phase 6 — gzip framing wrapper & CRC32 / ISIZE validation (3 days)

- `src/decode/deflate_native/gzip.rs`: RFC 1952 framing parser.
  Member header (10 fixed bytes + optional FEXTRA / FNAME /
  FCOMMENT / FHCRC), member trailer (CRC32 + ISIZE), member
  chaining (concatenated members are valid gzip).
- Compute CRC32-IEEE incrementally over decompressed bytes
  using the existing [`src/zip/crc32.rs`](../src/zip/crc32.rs)
  table. Compare to the trailing CRC32 in the member trailer;
  surface mismatches as a clean `DecodeError::Read` naming the
  member offset.
- ISIZE is the low-32-bits of the uncompressed size; compare
  modulo 2^32 (gzip allows decompressed sizes ≥ 4 GiB; ISIZE
  wraps).
- Behaviour-preserving: this module reproduces every observable
  property of the existing
  [`gzip.rs`](../src/decode/gzip.rs) wrapper — multi-member
  decode, per-member `frame_boundary()`, monotone
  `bytes_consumed()` — under the same trait contract.

**Tests**:

- Port every test in
  [`src/decode/gzip.rs`](../src/decode/gzip.rs) (single member,
  multi-member, monotone bytes_consumed, truncated stream,
  failing sink, etc.) to the new module.
- Corrupted trailer: flip a CRC32 byte, confirm clean
  `DecodeError::Read`.
- Corrupted ISIZE: same.
- Cross-member boundary: the `last_frame_boundary` advance
  still fires per-member (i.e. the new wrapper's per-block
  granularity is *strictly finer* than the existing
  per-member granularity, never coarser).

**Exit criteria**: every test in `src/decode/gzip.rs` passes
under the swapped-in decoder.

### Phase 7 — Decoder state serialization (1 week)

Now the lz4 / zstd / xz-shaped resume support.

- `resume.rs`: `DflResumeState` struct. Layout:

  ```text
   4 B   magic = b"DDR1"
   1 B   format_version (1)
   1 B   container (0 = raw deflate, 1 = gzip, 2 = zip-DEFLATE)
   1 B   bit_offset_in_first_byte (0..=7)
   8 B   source_byte_position (u64 LE; equals
           `decoder_position` in the checkpoint, i.e. the
           first byte the resumed reader will deliver)
  32768 B window contents (the most recent 32 KiB of
           decompressed output ending at decoder_position;
           shorter if the decoder hasn't yet emitted 32 KiB)
   2 B   window_filled (u16 LE; ≤ 32768)
   8 B   bytes_decompressed_in_member (u64 LE; for ISIZE
           cross-check on the gzip path, for the per-entry
           offset on the zip-DEFLATE path)
   4 B   running_crc32 (u32 LE; gzip + zip-DEFLATE; 0 for
           raw deflate)
   1 B   bfinal_seen (0 if the *next* block to read is
           non-final; 1 if `BFINAL=1` was the last block we
           started — i.e. the decoder is mid-final-block at
           checkpoint time, and resume must continue that
           same final block instead of treating the stream as
           ended)
   ── gzip-only suffix (omitted on container=0/2) ──
   N B   in-flight gzip member-header parser state (variable;
           ≤ 64 B). Members straddle checkpoints rarely (only
           when a member ends at exactly the checkpoint), but
           encoding this keeps resume correct in that edge.
  ```

  Total worst-case size: **~33 KiB** — three orders of
  magnitude smaller than the zstd plan's 128 MiB ceiling. The
  per-checkpoint write cost is negligible against the existing
  8 MiB cadence floor (~0.4 % overhead).
- The window snapshot is *internal* to our decoder — versioned
  by the blob's `format_version`. Format bumps are fine.
- `Decoder::resume(src, blob, start_offset)`: deserialize,
  hydrate window + CRC + bit-offset + member state, set
  internal `bytes_consumed = start_offset` and
  `last_frame_boundary = Some(start_offset)`. Mirror lz4's
  resume contract:
  [`src/decode/lz4.rs:269-301`](../src/decode/lz4.rs#L269-L301).
- `decoder_state()`: return `Some(blob)` only when paused at a
  deflate-block boundary (i.e. just after `BFINAL`/`BTYPE`-aligned
  EOB or just before the next `BFINAL` bit); `None` mid-block
  or between gzip members where the existing per-member
  boundary semantics are sufficient (mirrors
  `Lz4Decoder::between_blocks` and the zstd analogue).

**Tests**:

- Round-trip: capture state at every block boundary in a
  10-block gzip member, resume from each, verify byte-identical
  output for the suffix.
- Property: random gzip streams, random kill points at block
  boundaries, byte-identical resume.
- Bit-cursor edge case: kill point where the next block's
  `BFINAL` bit lives in the same byte as the previous block's
  EOB code. Resume must read that byte again, not skip it.

**Exit criteria**: an analogue of
[`src/decode/lz4.rs`'s `frame_boundary_property_is_a_valid_restart_point`](../src/decode/lz4.rs)
ports cleanly to the new decoder and passes.

### Phase 8 — Wire into the registry & extractor (3 days)

- Move the new gzip wrapper behind
  [`crate::decode::gzip::GzipDecoder`](../src/decode/gzip.rs)
  (replace the current `flate2`-based wrapper). The factory
  shape stays the same; only the implementation swaps. Drop
  the `peel_deflate_native` cfg — this is now the production
  path.
- Register the resume_factory in
  [`src/decode.rs`](../src/decode.rs):

  ```rust
  r.register_resume_factory("gzip", gzip::resume_factory);
  ```

- Update the registry comment that today excludes gzip from
  the resume-factory set
  ([`src/decode.rs:393-403`](../src/decode.rs#L393-L403)).
- Coordinator changes
  ([`src/coordinator.rs`](../src/coordinator.rs)): none — the
  resume_factory match arm already handles this case
  identically to lz4 / zstd / xz.

**Tests**: existing tests pass under the swapped-in decoder.

**Exit criteria**: `flate2` is no longer a *runtime* dependency
of the streaming-pipeline gzip path. (It can remain a
dev-dependency for differential tests, and **stays** as a
runtime dependency for the zip-DEFLATE path until Phase 9
swaps that too.)

### Phase 9 — ZIP-DEFLATE & ZIP-zstd resume integration (1 week)

This is where the second user-facing payoff lands: zip archives
with big DEFLATE entries (or big zstd entries) gain mid-entry
resume.

#### 9a — ZIP-DEFLATE swap (3 days)

- Wire the new decoder into
  [`src/zip/decode.rs::decompress_entry`](../src/zip/decode.rs)
  for `CompressionMethod::Deflate`. The CRC32 is recorded in
  the central directory (or the trailing data descriptor); the
  zip pipeline already reads the CD entry's CRC, so the new
  decoder just needs to compute the running CRC and the
  pipeline compares at end-of-entry.
- Drop `flate2` from the runtime dependency tree once both
  surfaces (gzip + zip-DEFLATE) are off it.

#### 9b — ZIP per-entry decoder_state plumbing (4 days)

- Extend [`ZipResumeState`](../src/download/zip_pipeline.rs)
  with a new field:

  ```rust
  /// Opaque per-entry decoder state captured at the most
  /// recent in-entry checkpoint. None if the in-flight entry
  /// is at byte 0, or if the entry uses STORED (which
  /// resumes per-byte without a blob) or an unsupported
  /// codec.
  pub current_entry_decoder_state: Option<Vec<u8>>,
  ```

- Extend [`SinkState::Zip`](../src/checkpoint.rs) with the
  same field. This is a **checkpoint format v7 bump** — the
  existing v6 readers see `None` for the new field; older
  binaries refuse v7 with `CheckpointError::UnsupportedVersion`.
- Update
  [`zip_pipeline.rs::extract_entry`](../src/download/zip_pipeline.rs)
  to:
  - Pass the blob into the codec at entry start (when present
    and the entry's compressed format matches what the blob
    captured).
  - Capture the codec's `decoder_state()` periodically and
    surface it through a new `ZipPipelineEvent::InEntryProgress`
    variant carrying the blob. The coordinator's
    `ZipPipelineEvent` handler stores the blob alongside the
    existing `current_entry_offset` field.
  - On `BeginEntryOutcome` mismatch (e.g. blob says DEFLATE
    but the entry now reads as STORED — should not happen if
    fingerprints validated, but defend anyway), discard the
    blob and restart the entry from byte 0 with a `tracing::warn!`.
- Wire `extract_entry` for `CompressionMethod::Zstd` to use
  the existing
  [`zstd::resume_factory`](../src/decode/zstd.rs)
  via the same plumbing — the only zip-side change is the
  blob threading; the decoder is already production-ready.

**Tests**:

- Build a 256 MiB single-entry DEFLATE zip; kill-after-N-bytes
  harness; verify byte-identical resume for 100 random kill
  points.
- Mixed-method zip: STORED + DEFLATE + zstd entries
  interleaved; checkpoints after each entry plus mid-entry for
  the DEFLATE / zstd entries; verify resume picks up from the
  in-flight entry's mid-point, not from its start.
- Format-bump test: an old v6 checkpoint resumes cleanly under
  the new code with `current_entry_decoder_state = None`.

**Exit criteria**: zip-DEFLATE entries no longer regress to
"restart entry from byte 0" on mid-entry kill.
[`OPTIMIZATIONS.md`](OPTIMIZATIONS.md) §O.8's "DEFLATE/zstd
restart the entry from its compressed start" footnote becomes
historical.

### Phase 10 — Hole-punching coverage for single-member gzip (2 days)

Mostly a test-only phase that confirms Phases 7 + 8 worked.

- Add an integration test that decodes a 256 MiB single-member
  `.tar.gz` and asserts:
  - `bytes_punched > 0`
  - `punch_calls > 0`
  - peak on-disk block count of the source file stays under
    `2 * 32 KiB + chunk_size` (small constant, no slow leak —
    the deflate window is fixed at 32 KiB so this bound is
    far tighter than xz / zstd's).
- Update [`tests/test_extractor.rs`](../tests/test_extractor.rs)
  to add a single-member `.tar.gz` sibling alongside the
  existing fixtures.

**Exit criteria**: the single-member failure mode (no
punching, no checkpointing for a 1-member-archive tar.gz) is
demonstrably fixed at smaller scale, mirroring Phase 9 of the
zstd plan and Phase 8 of the xz plan.

### Phase 11 — Crash-resume integration tests (1 week)

Mirror the existing lz4 / zstd / xz crash tests
([`tests/test_coordinator_crash.rs`](../tests/test_coordinator_crash.rs)).

- Build a single-member `tar.gz` with several tar members of
  awkward sizes (so deflate-block boundaries and tar-member
  boundaries rarely coincide).
- Run the coordinator under a kill-after-N-bytes harness;
  restart; verify final output is byte-identical to a clean
  run.
- Property test: vary `gzip --best` vs `gzip --fast`, member
  sizes, and kill points.
- Repeat for a single-entry zip-DEFLATE archive (Phase 9
  payoff regression test).

**Exit criteria**: 100 randomized crash-resume runs are
byte-identical for both gzip and zip-DEFLATE shapes.

### Phase 12 — Optional follow-ons (deferred)

These all live in `OPTIMIZATIONS.md` after this plan ships:

- **Mid-block resume** (resume points inside a single
  dynamic-Huffman block). Only worth it if real users hit
  >256 KiB single deflate blocks regularly.
- **Two-level Huffman decode tables** for cache friendliness
  (root level 8–10 bits, secondary tables for the long-tail
  of 11–15 bit codes). Latency improvement, not correctness.
- **SIMD-accelerated match-copy** (overlap-aware `memcpy`
  variant). Throughput win on large back-references; no
  resume implication.
- **zlib (RFC 1950) framing** if a `.zlib` source ever appears
  (e.g. PNG IDAT extraction outside the project's current
  scope).
- **Differential fuzz harness with `cargo-fuzz`** and a
  curated corpus of real-world `.tar.gz` / `.zip` fixtures.

## Risks & open questions

1. **Throughput.** A clean-room pure-Rust inflate decoder will
   typically land at 100–200 MB/s on a first cut. miniz_oxide
   sits around 250 MB/s after a decade of tuning. If we land
   below 80 MB/s sustained, the user-perceived extract phase
   regresses noticeably for fast-disk users. Mitigation:
   Phase 0 spike must benchmark against miniz_oxide; if
   catastrophically slower (< 50 MB/s) revisit Phase 3's
   table-build strategy before Phase 4.
2. **Bit-cursor / byte-cursor mismatch.** Unlike zstd / xz / lz4
   (all byte-aligned at frame boundaries), deflate-block
   boundaries can land at any of the 8 bit positions in a byte.
   The `decoder_position` field in
   [`Checkpoint`](../src/checkpoint.rs) is byte-aligned by
   design (it must be: the puncher operates in filesystem
   blocks). The convention this plan adopts:
   `decoder_position` reports the **byte the bit cursor lives
   in** (i.e. `floor(bit_cursor / 8)`); the resume blob's
   `bit_offset_in_first_byte` carries the missing 0–7 bits.
   `bytes_consumed` reports the same byte. This means the
   puncher can **never punch the byte the bit cursor is in**,
   only the bytes strictly before it. Document loudly in
   Phase 7's resume-blob comment block.
3. **CRC32 cumulative state.** Trivial — single `u32`, no
   nontrivial state. Same for ISIZE. The risk surface is
   smaller than zstd's XXH64 streaming state by a comfortable
   margin.
4. **Window-size blob.** 32 KiB written every block boundary
   is ~0.4 % overhead against the 8 MiB cadence floor. No
   dedup needed; no "every Nth block" throttle needed. The
   simplest possible policy works.
5. **Endianness / portability.** Deflate is bit-packed, not
   byte-endian-sensitive at the bit level, but multi-byte
   integers in the gzip framing and zip framing are LE.
   Document the LE-host assumption (matches zstd / xz / lz4 /
   io_uring path).
6. **Checkpoint format bump (v6 → v7).** Phase 9b carries a
   format-version bump for the new
   `current_entry_decoder_state` field. Older binaries refuse
   v7 cleanly (the existing `UnsupportedVersion` path).
   Document the bump in
   [`src/checkpoint.rs`](../src/checkpoint.rs)'s version table
   comment block, mirroring the v4 → v5 bump's pattern.
7. **License / clean-room.** RFC 1951 + RFC 1952 +
   clean-room implementation. Don't read `miniz_oxide` /
   `zlib` / `libdeflate` source line-by-line for copying
   patterns; refer to the RFCs, then implement, then
   cross-check. This is the normal clean-room discipline
   already used for the zstd / xz plans.
8. **`tracing` instrumentation.** Decode is hot-loop;
   instrument sparingly. Only at gzip-member-header parse,
   block-header parse, and `decode_step` boundary.
9. **flate2 in dev-dependencies.** Phase 8 / 9a drop `flate2`
   from runtime deps. It stays as a `dev-dependencies` entry
   for the differential tests in Phase 4 and 5 (mirrors how
   the zstd plan kept the `zstd` crate as a dev-dependency).

## Acceptance criteria for the whole plan

- ✅ Single-member `.tar.gz` (any size, any gzip CLI level)
  extracts with the puncher firing every deflate-block
  boundary.
- ✅ Single-entry DEFLATE `.zip` (any size) resumes mid-entry
  on kill instead of restarting the entry from byte 0.
- ✅ A `kill -9` mid-extraction at any deflate-block boundary
  resumes byte-identical to a clean run for both gzip and
  zip-DEFLATE shapes.
- ✅ A 10 GiB single-member `.tar.gz` resumes within 1 minute
  of where the killed run was, satisfying the autoresume
  target this plan was scoped to address.
- ✅ `flate2` is removed from the runtime dependency tree.
  (Confirms our hand-rolled path is what's actually
  decompressing.)
- ✅ ZIP-zstd entries also resume mid-entry (Phase 9b
  payoff — the existing zstd resume infra is wired through to
  the zip pipeline).
- ✅ `cargo test`, `cargo clippy -- -D warnings`,
  `cargo fmt --check` all green.
- ✅ Differential test passes against a curated corpus of
  1000+ gzip / zip-DEFLATE fixtures.
- ✅ Throughput within 2× of miniz_oxide on a representative
  `tar.gz` archive. (Tighter than zstd's 3× / xz's 4× because
  deflate is the simplest of the three formats and pure-Rust
  baselines are competitive.)

## Estimated total effort

Roughly **4–5 weeks of focused work** for one engineer,
distributed across the phases above. Smaller envelope than the
zstd plan (5–7 weeks) and the xz plan (5–7 weeks) for two
reasons: (a) deflate is the simplest of the three on-wire
formats — no FSE, no LZMA range coder, no probability model;
(b) the resume blob is fixed at 32 KiB rather than
`window_size`-dependent, so Phase 7 is mechanically simpler.
Phase 4 (dynamic-Huffman code-length-codes) and Phase 9b (zip
plumbing + checkpoint format bump) are the heaviest single
phases. Phase 0's spike result will tighten this estimate.

[RFC 1951]: https://www.rfc-editor.org/rfc/rfc1951
[RFC 1952]: https://www.rfc-editor.org/rfc/rfc1952

## Appendix A — Phase 0 spike memo (2026-05-03)

**Verdict**: feasible. Recommend proceeding to Phase 1. Cost estimate
unchanged.

**Spike scope.** Single-file Rust binary at `/tmp/deflate-spike/`
(~440 LOC of decoder + ~420 LOC of harness/fixtures/benchmarks,
throwaway, dependency-free). Generates four reference vectors —
hand-built BTYPE=00 stored block, Apple `gzip -1` on a 16-byte
all-`a` payload (BTYPE=01 fixed Huffman + a length-15 distance-1
back-reference), Apple `gzip -1` on 131 bytes of mixed text (BTYPE=10
dynamic Huffman), and Apple `gzip -9` on a 256 KiB pseudorandomly-
mixed payload (BTYPE=10 dynamic Huffman across one large block) —
plus a fifth multi-member case (concatenated `gzip -1` outputs) to
validate gzip member chaining. All five decode **byte-identical** to
`gunzip -c`.

**What was validated end-to-end.**

- *Bit reader* (RFC 1951 §3.1.1). LSB-first byte order, LSB-first
  bit-within-byte order, with a 64-bit refill buffer and a
  byte-aligned `align_to_byte()` for stored-block transitions. The
  `cursor() -> (byte_pos, bit_off)` accessor — load-bearing for the
  decoder_state blob's bit cursor in Phase 7 — accounts for buffered-
  but-unconsumed bits correctly: `byte_pos = src_pos -
  ceil(nbits/8)`, `bit_off = (8 - nbits & 7) % 8`. The 8-byte gzip
  trailer reads cleanly after every fixture (proves the bit cursor
  rounds up to the byte boundary correctly when the deflate stream
  ends mid-byte).
- *Block walker.* `BFINAL` (1 bit) + `BTYPE` (2 bits) per block,
  loop until `BFINAL=1`. Multi-block in a single member (the 256 KiB
  fixture observed only one block at `gzip -9`, but the multi-member
  test exercised back-to-back inflate cycles).
- *BTYPE=00 stored block* (§3.2.4): `align_to_byte`, then 4 raw
  bytes `(LEN_lo, LEN_hi, NLEN_lo, NLEN_hi)` with `LEN ^ 0xFFFF ==
  NLEN` invariant check, then `LEN` literal bytes copied through.
- *BTYPE=01 fixed Huffman* (§3.2.6). Lit/length codes 0..143 = 8
  bits, 144..255 = 9, 256..279 = 7, 280..287 = 8; distance codes all
  5 bits. Built via the same canonical-Huffman table builder as
  dynamic blocks, transcribed from RFC 1951's procedure verbatim.
- *BTYPE=10 dynamic Huffman* (§3.2.7). Full preamble: `HLIT` (5 bits,
  +257), `HDIST` (5 bits, +1), `HCLEN` (4 bits, +4), then `HCLEN+4`
  3-bit code lengths in the permuted order
  `[16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]`.
  Code-length-code Huffman built, then the lit/length and distance
  code-length sequences decoded with RLE codes 16 / 17 / 18
  (repeat-prev-3+2bits / zero-3+3bits / zero-11+7bits) all
  exercised on the 131-byte and 256 KiB fixtures.
- *Canonical Huffman table builder.* RFC 1951 §3.2.2 procedure
  (count → next_code → assign), into a flat `1 << max_len` lookup
  table indexed by `peek_bits(max_len)` (`max_len ≤ 15`). Every
  canonical code is bit-reversed before being installed, because
  the deflate stream reads bits LSB-first while canonical Huffman
  codes are MSB-first; this is the single most easily-bungled piece
  of inflate and the spike got it right via the explicit
  `bit_reverse` helper.
- *LZ77 sliding-window match-copy* (§3.2.5). Length codes 257..285
  → base length 3..258 + 0..5 extra bits; distance codes 0..29 →
  base distance 1..24577 + 0..13 extra bits. **Overlap-by-design**
  works: the 16-byte all-`a` fixture decodes via a length-15
  distance-1 match (one literal `a` then "copy 15 bytes from 1
  behind, where each byte you read was just produced") with no
  special-casing — a byte-by-byte loop reading from `out[len -
  distance]` while pushing to `out` does the right thing because
  the read index never catches up to the write index. The
  256 KiB fixture exercises distances large enough to reach the
  10–13-bit-extra distance-code range.
- *gzip framing* (RFC 1952). Header parser handles all five FLG
  bits (FTEXT / FHCRC / FEXTRA / FNAME / FCOMMENT) — only FNAME
  was triggered by Apple gzip without `-n`, but the parser path is
  the same for every flag and the spike's `-n` fixtures avoid
  filename injection. Trailer: `CRC32(decompressed) == recorded`
  and `len(decompressed) mod 2^32 == ISIZE` both verified for
  every fixture. Multi-member chaining (concatenated members)
  works without intermediate state, because each member's deflate
  stream ends at the bit-cursor position before the trailer, then
  the next member's header parser picks up after the 8-byte
  trailer.
- *CRC32-IEEE* (table-driven, reflected polynomial 0xEDB8_8320,
  produced via a `const fn` table builder so the lookup table is
  baked into `.rodata`). Cross-checks byte-identical against every
  fixture's recorded trailer CRC.
- *Throughput sanity check* (Apple Silicon, M-series, single
  thread, 8 MiB plaintext → `gzip -6` → spike decode):

  | payload                     | ratio | spike       | gunzip      | ratio |
  |-----------------------------|-------|-------------|-------------|-------|
  | redundant text (8 MiB)      | 343×  | **448 MiB/s** | 1397 MiB/s  | 3.1×  |
  | low-redundancy text (8 MiB) | 1.3×  | **228 MiB/s** | 344 MiB/s   | 1.5×  |

  The low-redundancy number is the realistic worst case (most
  symbols are literal Huffman decodes rather than back-reference
  memcpy). 228 MiB/s is **2.85× the plan's 80 MiB/s alarm
  threshold** and comfortably above the 150 MiB/s "comfortable"
  target (Risks §1). The spike is unoptimized — per-block table
  allocation (`Vec<HuffEntry>` rebuilt on every dynamic block,
  `Vec<u8>` for the sliding window with no ring-buffer
  trimming) and no inner-loop tightening — so the production
  decoder should land at least as well, likely meaningfully
  better with table reuse and a 32 KiB ring window.

**What was NOT validated, and why.**

- *Apple gzip emits BTYPE=01 only at very small input sizes*
  (`-1` on ≤ ~30 bytes). Larger inputs at every level go straight
  to BTYPE=10. The spike's small fixture (`gzip -1` on 16 bytes
  of `aaa...`) exercises BTYPE=01 with one back-reference; broader
  fixed-Huffman coverage (multiple back-references, distance codes
  beyond 0..3, length codes with extra bits) wasn't exercised at
  the spike scale and is a Phase 3 concern. Hand-building a richer
  fixed-Huffman fixture is straightforward (the canonical fixed
  tables are short) and is the right Phase 3 test pattern.
- *FHCRC, FEXTRA, FCOMMENT bits in gzip header.* Code path is
  written and tested via inspection, but no fixture exercises them
  end-to-end — Apple gzip's `-n` flag suppresses everything except
  the fixed 10-byte header. Phase 6 should add hand-built fixtures
  with each flag set (the parser is sequential — `if flg & FEXTRA
  { skip 2 + xlen }`, `if flg & FNAME { skip until NUL }`, etc. —
  so the test surface is 4 small additions to Phase 6's test
  module).
- *Decoder state at every block boundary across an 8 KiB-block
  multi-block stream.* The spike's `cursor()` accessor was
  validated only at end-of-stream (where it must point at the
  byte after the last byte the bit reader fully consumed, modulo
  alignment). Phase 7's resume-blob round-trip tests will need
  fixtures with multiple blocks per member (typical for `gzip
  --rsyncable` or producers like `pigz`) so the bit-cursor
  capture-and-replay is exercised at every boundary, not only
  the final one. Apple gzip in single-threaded mode appears to
  emit one block per member at every level (256 KiB into one
  block at `-9`), which understates the typical real-world block
  count — `pigz -p4` or `gzip` from GNU coreutils on heterogeneous
  input emit far more.
- *BTYPE=11 reserved rejection.* Spike panics; production code
  should surface a clean `DecodeError::Read` naming the offset.
- *Distance code 30/31 reserved rejection.* Same — spike asserts
  `< 30` on the index; production code should surface a typed
  error.
- *Truncated stream.* No fixture; relies on Rust's `&[u8]` bounds
  checks panicking. Production code surfaces `DecodeError::Read`
  with `UnexpectedEof` exactly as the existing gzip / zstd / xz
  paths do — the path the spike takes (panic on out-of-bounds)
  is wrong for production but doesn't change the cost estimate.
- *Differential at fuzz scale.* The spike differential is
  `gunzip -c` on five hand-picked fixtures plus 8 MiB benchmark
  payloads. Phase 4 / 5's "100 / 500 random fixtures" differential
  against `flate2` is a follow-on, not a Phase 0 deliverable.

**Cost-estimate sanity check.** Spike LOC vs plan effort estimates:

| Plan phase | Spike-equivalent surface                                    | Spike LOC | Plan estimate |
|------------|-------------------------------------------------------------|-----------|---------------|
| Phase 1    | gzip-level state machine + BTYPE=00 stored block            | ~70       | 3 days        |
| Phase 2    | bit reader (forward, LSB-first, with cursor accessor)       | ~80       | 2 days        |
| Phase 3    | canonical Huffman builder + fixed-Huffman tables            | ~120      | 3 days        |
| Phase 4    | dynamic-Huffman preamble (HLIT/HDIST/HCLEN + RLE 16/17/18)  | ~80       | 1.5 weeks     |
| Phase 5    | sliding window + LZ77 overlap-aware copy + multi-block loop | ~50       | 3 days        |
| Phase 6    | gzip framing + CRC32 + ISIZE                                | ~80       | 3 days        |

The spike was written in one focused half-day. The Phase 1 + 2 + 3
+ 5 + 6 surfaces (~400 LOC) line up with the plan's cumulative
~2.5 weeks of effort for the same surfaces — proportional to the
existing spike-vs-estimate ratios in the zstd and xz Appendix A
memos, allowing for production-quality testing, error-type
plumbing, trait integration, and the StreamingDecoder /
DecoderResumeFactory contract code the spike doesn't write. Phase
4's plan estimate (1.5 weeks) is the conspicuous outlier — only
~80 LOC in the spike — but that surface includes the
code-length-codes preamble, which is the deflate equivalent of
zstd's FSE distribution parser, with the same "easy to get subtly
wrong" reputation. The plan's outsized allocation for Phase 4 is
right; do not adjust it. Phase 7 (decoder_state) and Phase 9b
(zip plumbing + checkpoint format bump) are not represented in
the spike at all and remain the heaviest single phases.

**Open questions surfaced.**

1. *Per-block table allocation cost.* The spike rebuilds a fresh
   `Vec<HuffEntry>` for every block (lit/length and distance both,
   plus the code-length-code table for dynamic blocks). For an
   archive with thousands of blocks that's thousands of
   `Vec::with_capacity` + populate + drop cycles. Phase 3 should
   pre-allocate a single set of `Box<[HuffEntry]>` buffers as
   fields on the decoder struct and rebuild in place. This is a
   Phase 3 implementation note, not a plan-level concern, but
   worth flagging because the spike's 228 MiB/s low-redundancy
   number is partially allocation-bound.
2. *Bit-reverse helper hot path.* `bit_reverse(canonical, len)`
   is called once per **populated symbol** when building each
   Huffman table — i.e. potentially hundreds of calls per block
   for a typical dynamic block. The spike implementation is a
   naive bit-by-bit loop. Phase 3 should either inline a
   constant-time 16-bit reverse (e.g. the standard
   `(x & 0xAA55) | ...` cascade) or precompute a 256-byte table
   and reverse in two lookups. Same scale of optimization as
   zstd's bitstream readers; not a correctness issue.
3. *Distance code 30/31 reserved.* Round-one rejects them, but
   the rejection is via `assert!`; Phase 5 should route through
   `DecodeError::Read` with a structured error variant. Same
   note for `BTYPE=11`.
4. *FHCRC validation.* Spike skips the 2-byte CRC16 (gzip
   header CRC) without verification. Phase 6 should *verify*
   when the bit is set, mirroring how the existing
   [`gzip.rs`](../src/decode/gzip.rs) wrapper relies on
   `flate2`'s default behaviour (which validates internally).
5. *Multi-member checkpoint blob shape.* The plan's blob layout
   carries `bytes_decompressed_in_member` for ISIZE cross-check
   and gzip-level CRC32. When a checkpoint lands at a
   member-boundary (the previous member is closed, the next one
   has yet to be parsed), the captured state has a clean reset
   for both fields. The spike confirms the boundary semantics
   (members are byte-aligned, member-end is a clean restart
   point) but Phase 7 will need to encode "between members"
   versus "mid-member at a deflate-block boundary" as two
   distinct blob states. The plan's `container` byte and the
   gzip-only suffix already permit this — Phase 7 just has to
   wire it explicitly.
6. *Apple gzip block density.* Apple gzip emits one deflate block
   per member at every level on the fixtures used; this is a
   weaker block-density signal than expected and will understate
   the per-block puncher cadence in the integration tests. Phase
   10 / 11 should explicitly use `pigz -p4` or `gzip` from GNU
   coreutils (via Homebrew) to get a more representative
   multi-block stream for the puncher-coverage test. Note this in
   the Phase 10 fixture-generation comments.

**Recommendation.** Proceed to Phase 1. Drop the spike code
(throwaway per the plan); carry forward only the bug-spotting
notes above into Phase 1 / 3 / 6 commit messages and the
allocation / bit-reverse optimizations into Phase 3's
implementation comments.

