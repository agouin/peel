## Plan: legacy RAR (RAR3 / RAR4) archive support

> **Status: drafted 2026-05-10, Phases A + B landed, Phase C started.**
> §0 resolved 2026-05-10.
> **§A1 (6c96328) + §A2a (38ff665) + §A2b (cc60bf8)** complete:
> STORED-method legacy archives extract end-to-end. **§B0 (e730509)**
> lands the PPMd-II range coder under `src/decode/ppmd2/` —
> round-tripped against a test-only sister encoder across uniform /
> skewed / adaptive-binary distributions. **§B1 (62bc41c)** lands
> the PPMd-II suballocator alongside it: 38 freelist size classes,
> two-direction unit region, GlueCount-driven coalescing.
> **§B2a (c5119cc) + §B2b (f3a73b6) + §B2c (f3d1226)** land the
> model: context tree, decode loop, update path, sister encoder,
> and 21 round-trip / edge-case tests across the full order range
> (2..=64), session restart, and small-arena exhaustion. **§B3
> (2e4648e)** lands 50 differential reference vectors from
> 7z-PPMd output and the two model-layer fixes that corpus surfaced.
> **§C0 (fadba5b)** opened Phase C: the original §C1 / §C2 split
> is too coarse — same lesson §B taught — so it landed the
> sub-phasing (§C0..§C2c, 12 commits total), scaffolded
> `src/decode/rar_legacy/` behind the existing `rar` Cargo feature,
> and locked the differential-test corpus strategy. The licensed
> RAR 7.22 binary at `~/Downloads/rar/` is decode-only for the
> legacy format (7.x dropped the `-ma3` switch and emits RAR5
> exclusively) — fixtures come from the CC0 corpus at
> [`ssokolow/rar-test-files`](https://github.com/ssokolow/rar-test-files)
> with the bundled `unrar` as the reference-decoder side.
> **§C1a (e96f842)** landed the MSB-first bitstream reader at
> [`src/decode/rar_legacy/bits.rs`](../src/decode/rar_legacy/bits.rs),
> sibling of [`crate::decode::rar_native::bits`]; 17 unit tests
> cover zero-bit reads, byte-spanning reads, 32-bit reads, peek vs.
> consume, partial-cursor underrun reporting, byte alignment at
> block boundaries (the load-bearing libarchive-equivalent path),
> a 60-group random round trip, and legacy-realistic 15-bit
> Huffman / 18-bit distance-extra-bits widths at byte-boundary-
> crossing offsets. **§C1b (2be01b6)** landed the canonical
> Huffman builder at
> [`src/decode/rar_legacy/huffman.rs`](../src/decode/rar_legacy/huffman.rs)
> (15-bit max code, flat-lookup table sized `1 << max_len`, same
> shape as the `rar_native::huffman` sibling) plus the per-block
> bootstrap at
> [`src/decode/rar_legacy/bootstrap.rs`](../src/decode/rar_legacy/bootstrap.rs)
> (the 20-entry precode parser, the 404-entry main-length parser
> with the delta-from-previous-block trick and the libarchive
> repeat-last / zero-run opcode set, and the four-sub-tree
> extractor). 24 unit tests across the two modules.
> **§C1c (721ce9c)** landed the per-block prologue parser at
> [`src/decode/rar_legacy/block_header.rs`](../src/decode/rar_legacy/block_header.rs)
> — byte-aligns, reads `is_ppmd_block`, then either runs the §C1b
> chain (LZ mode) or decodes the 7-bit `ppmd_flags` plus its
> conditional dict / max-order / init-escape payload (PPMd
> mode). 11 unit tests covering the LZ `keep_old_tables` reset
> and retain paths, the four PPMd flag combinations
> (none / `0x20` / `0x40` / both), max-order remapping above 16,
> the `max_order == 1` rejection, byte-alignment from an
> off-aligned cursor, and truncated-prologue underrun.
> **§C1d (this commit)** lands the sliding-window ring buffer at
> [`src/decode/rar_legacy/dict.rs`](../src/decode/rar_legacy/dict.rs)
> (4 MiB cap, overlap-by-design `copy_match` for the `length >
> distance` self-extending RLE-via-LZSS case, `copy_recent_into`
> for the §C2 filter VM) and the 4-slot LRU at
> [`src/decode/rar_legacy/dist_cache.rs`](../src/decode/rar_legacy/dist_cache.rs)
> (push / touch matching libarchive's `oldoffset[]` semantics
> from `archive_read_support_format_rar.c` lines 3030..3115).
> 25 unit tests across the two files; lib-test count now 1585.
> This plan resolves follow-on `O.RAR4` from `docs/PLAN_rar.md`. It
> is a sibling sub-plan to `docs/PLAN_rar5_decoder.md` — additive to
> `docs/PLAN_rar.md`, not a supersession.
>
> **Sequencing.** `PLAN_rar.md` §1–§4 plus `PLAN_rar5_decoder.md`
> Phases A–E must be on `main` first. The hand-rolled RAR5 decoder
> establishes the bitstream / Huffman / dictionary / RarVM / sink
> patterns this plan re-uses; landing legacy support before that
> stabilises forces double rework.

**Supersedes**: nothing — additive to `PLAN_rar.md` (§"Filed
follow-ons" → `O.RAR4`).

---

## A note on names

"RAR3" and "RAR4" refer to the same on-disk archive format. RARLAB's
own technote calls it the *RAR 4.x archive format* (because WinRAR
4.x was the last program version to ship it as default), but the
algorithm crystallised in WinRAR 2.9/3.0 and is colloquially called
"RAR3" by most third-party readers. The user-facing CLI surface and
this plan use **legacy RAR** for the format as a whole; the codebase
keeps the existing `RAR4_*` constants in [src/rar/format.rs](src/rar/format.rs)
because that matches RARLAB's nomenclature and is already wired into
the diagnostic path. The 7-byte signature `Rar!\x1A\x07\x00` is the
sole on-the-wire discriminator from RAR5 (`Rar!\x1A\x07\x01\x00`).

---

## Why we're hand-rolling this

`PLAN_rar5_decoder.md` rejected the `unrar` C++ FFI on licensing
grounds (non-OSI, GPL-incompatible) for RAR5. Every reason there
applies identically here. There is additionally **no acceptable
pure-Rust legacy RAR decoder**: the few candidates on crates.io
(`unrar_rs`, `unrar-rust`, `compress-tools` via libarchive) either
shell out to unrar, link libarchive (LGPL), or implement only the
RAR5 path. The only OSI-licensed reference for the legacy algorithm
is libarchive's `archive_read_support_format_rar.c`, which is
LGPL-2.1 and read-as-reference but not link-as-dependency.

Hand-rolling is **larger in scope than the RAR5 hand-roll**:

- RAR5 has one compression algorithm. Legacy RAR has *four*
  generations (1.x, 2.0, 2.6, 2.9/3.0/4.x) and the first three are
  not subsets of the fourth.
- Legacy RAR 2.9+ uses **PPMd-II**, which RAR5 dropped. PPMd-II is
  ~6 kLOC of C in unrar, the densest single algorithm in the RAR
  source tree, and shares no code with the RAR5 hand-roll.
- The RarVM filter interpreter exists in both, but legacy archives
  may carry **archive-defined RarVM bytecode** (a custom filter
  compiled from program text and stored in the archive). RAR5 ships
  a fixed standard set, so `PLAN_rar5_decoder.md` deferred the custom
  slot (`O.RAR.CUSTOMFILTER`). For legacy we cannot defer it — real
  archives use it.

The cost is the price of staying fully OSI-licensed.

---

## Hard constraints (carried forward)

- Std-first; allowlist-only. No new runtime dependencies. The
  reference cross-check binary is `unrar` (or `bsdtar` against
  libarchive) at `[dev-dependencies]`-only scope, mirroring
  `PLAN_rar5_decoder.md`.
- No async runtime.
- Linux-first; macOS works via the existing `MacosPuncher`.
- Backwards-compatible checkpoints. Phases that introduce new
  resume state bump `Checkpoint::format_version` per `PLAN.md` §9.2.
- Hand-rolled wire-format parsing. CRC16 lookup table is hand-rolled
  the same way `crate::zip::crc32` is.
- The RAR5 path stays untouched. Legacy support is dispatched off
  the signature byte at offset 6 and lives in a sibling tree under
  `src/rar/legacy/` and `src/decode/rar_legacy/`. No
  reaching-across between the two.

---

## What this plan deliberately does not include

- **Compression.** Decompression-only, same as everywhere else in
  `peel`.
- **Encryption.** `O.RAR.ENC` covers RAR5 and (as a co-resolved
  follow-on) legacy. Encrypted legacy archives surface
  `RarError::UnsupportedFeature { feature: "encryption (legacy)" }`.
- **Multi-volume.** `O.RAR.MV` covers both formats. A legacy
  multi-volume archive surfaces the existing diagnostic with the
  detected part number.
- **SFX.** `O.RAR.SFX` covers both.
- **Recovery records.** Skipped silently; `O.RAR.RECOVERY` is
  format-agnostic.
- **RAR 1.3 / 1.5 archives.** These pre-date the LZSS+Huffman
  redesign (1.5 is the earliest with a fixed magic; 1.3 has no
  magic). Surface `RarError::UnsupportedFeature` with the detected
  `unp_ver`. Filed as `O.RAR.LEGACY15` follow-on; the corpus is
  effectively zero-modern.

---

## §0. Decisions to resolve before §A begins

> **§0 resolved 2026-05-10.** All four decisions resolved by the
> project owner on the recommended path. Resolutions recorded inline
> at the end of each sub-section in a `**Resolution.**` block.
> Headline outcomes: round-one covers RAR 2.9–4.x only (§0.1);
> `rar_pipeline` is shared across formats with signature dispatch
> (§0.2); the RarVM custom-filter slot ships on day one (§0.3);
> PPMd-II lives in `src/decode/ppmd2/` as a standalone module (§0.4).

### §0.1 Compression-version coverage

**Question.** Which legacy compression generations does round-one
support, given they are not subsets of each other?

**Options.**

1. **Comprehensive (2.0 + 2.6 + 2.9–4.x).** All three generations.
   Three independent decoders. Largest scope; aligns with "full
   compatibility" framing.
2. **2.9–4.x only.** Cover the algorithm shipped 2003-onward (the
   one almost every public archive uses). Pre-2.9 archives surface a
   precise diagnostic naming the version. Smallest scope that is
   still useful in the wild.
3. **2.6 + 2.9–4.x.** Skip 2.0. 2.6's multimedia / audio modes are
   rare; 2.9's PPMd path is the bulk of work either way.

**Recommendation.** Option 2 first, with §F below adding 2.6 (and
optionally 2.0) only if a real-archive failure surfaces. Rationale:
the corpus that actually breaks `peel` today is overwhelmingly
2.9–4.x. Doing all three up front triples test corpus, fuzz seeds,
and conformance work for a rapidly shrinking long tail.

**Resolution (2026-05-10).** Option 2. Round-one decodes
`unp_ver` ∈ \[29, 36] only (the WinRAR 2.9 / 3.x / 4.x algorithm
family — they share a single decoder). `unp_ver < 29` surfaces
`RarError::UnsupportedFeature { feature: "legacy RAR ≤ 2.6
compression (unp_ver = N)" }` at parse time. 2.0 / 2.6 are filed as
the conditional Phase D below. RAR 1.x stays excluded
(`O.RAR.LEGACY15`).

### §0.2 Solid-mode decoder lifetime

**Question.** Solid legacy archives share **one** LZ+PPMd context
across multiple files. The RAR5 §3 pipeline already has a
single-stream sequential path for solid mode; does the legacy path
re-use it, or fork?

**Options.**

1. **Re-use.** `crate::download::rar_pipeline` learns to dispatch
   on signature and selects between `RarStreamDecoder` (RAR5) and
   `RarLegacyStreamDecoder` (this plan). The serial-solid driver
   is generic over the trait.
2. **Fork.** A sibling `rar_legacy_pipeline` mod with its own
   solid-mode driver.

**Recommendation.** Option 1. The pipeline is the part of `peel`
that is *not* format-specific (it does ranged HTTP, punch holes,
checkpoint). Forking it would be a regression.

**Resolution (2026-05-10).** Option 1. `crate::download::rar_pipeline`
gains signature-dispatched walking; the serial-solid driver
becomes generic over `StreamingDecoder`. The legacy walker is a
sibling type implementing the same archive-walk trait the RAR5
walker exposes (the trait is introduced in §A2 of this plan).

### §0.3 RarVM custom-filter slot

**Question.** Legacy archives in the wild use the custom filter
slot. Do we ship the VM hot-path on day one, or stub it and surface
`UnsupportedFeature` until §C2 lands?

**Options.**

1. **Ship on day one.** §C in this plan covers the standard set
   *and* the VM interpreter. Larger Phase C, single delivery.
2. **Stub then ship.** §C1 covers the standard set; §C2 lands the
   VM interpreter as a follow-up. Real archives may surface
   `UnsupportedFeature` in the gap.

**Recommendation.** Option 1. Unlike RAR5 where the custom slot
is rare, the legacy corpus uses it heavily for recompressed
multimedia. A "stubbed" round-one would not extract real archives.

**Resolution (2026-05-10).** Option 1. The standard set and the
custom-bytecode interpreter ship together in §C2. The interpreter
must reject every malformed memory access without UB or abort —
the historical CVE record on this code path is long and unforgiving.

### §0.4 PPMd-II separability

**Question.** Is PPMd-II implemented as a standalone module that
could be reused if PPMd-encoded RAR5 archives ever surface (none
exist today, but the spec slot is reserved)?

**Recommendation.** Yes — implement PPMd-II under
`src/decode/ppmd2/` (sibling of `src/decode/rar_native/`), with the
legacy decoder being its first consumer. This costs nothing extra
and keeps the door open for `O.RAR.PPM5` (PPMd in RAR5) and for the
PPMd-II variant some 7z archives use, which today fall under
`crate::sevenz::UnsupportedMethod`.

**Resolution (2026-05-10).** Yes. PPMd-II lives at
`src/decode/ppmd2/` with the legacy decoder its first consumer.
The module exposes a small surface (`Decoder::new(params)`,
`Decoder::decode_symbol(reader)`, snapshot/restore) that
`crate::sevenz` and a hypothetical `O.RAR.PPM5` consumer can wire
into without modification.

---

## Phase A — Format layer

### §A1. Legacy header parser ✅ (commit 6c96328)

**What**: hand-rolled parser for the legacy fixed-layout headers,
sibling of [src/rar/format.rs](src/rar/format.rs). Lives at
`src/rar/legacy/format.rs` (new submodule
`src/rar/legacy/mod.rs`).

**Sketch**.

1. CRC16 (CCITT, polynomial 0xA001 reversed — the same one unrar
   uses) as a 256-entry table in `src/rar/legacy/crc16.rs`.
2. Generic header struct: `head_crc: u16`, `head_type: u8`,
   `head_flags: u16`, `head_size: u16`, optional `add_size: u32`
   (when `LONG_BLOCK` flag set). All little-endian, fixed offsets.
3. Block-type-specific parsers for `MAIN_HEAD` (0x73),
   `FILE_HEAD` (0x74), `ENDARC_HEAD` (0x7B). Skip
   `COMM_HEAD` (0x75), `AV_HEAD` (0x76), `SUB_HEAD` (0x77),
   `PROTECT_HEAD` (0x78), `SIGN_HEAD` (0x79), `NEWSUB_HEAD` (0x7A)
   by `head_size + add_size`.
4. FILE_HEAD decodes: `pack_size`, `unp_size` (+ high32 if
   `LARGE` flag), `host_os`, `file_crc` (CRC32 over uncompressed
   bytes), `ftime` (DOS), `unp_ver` (compression-version × 10),
   `method` (0x30..0x35), `name_size`, `attr`, optional `unicode_name`.
5. Reject (`UnsupportedFeature`) per §0.1 outcome — pre-2.9 archives
   carry `unp_ver < 29`.

**Tests**: parse known fixtures emitted by `rar a -m1`, `rar a -m3`,
`rar a -ma3 -m5` (legacy-format flag). Round-trip CRC16 against a
small payload. Reject malformed CRC, malformed flags.

**Demo**: `cargo test rar::legacy::format` passes; `peel` shows a
useful summary for a STORED legacy archive (next phase makes it
extract).

---

### §A2. Pipeline dispatch

Split into two sub-steps during implementation: §A2a lands the
structural pieces in isolation; §A2b ports the (~1 kLOC) RAR5
pipeline. Splitting keeps each diff reviewable.

#### §A2a. Signature dispatch + legacy walker ✅ (commit 38ff665)

**What landed**: top-level [`SignatureKind`](../src/rar.rs)
enum + `detect_signature` in `crate::rar`, and
`crate::rar::legacy::archive::{walk_archive, LegacyArchiveSummary,
LegacyFileEntry}` mirroring the RAR5 walker. The walker enforces
`§0` rejections at parse time (multi-volume, encryption,
pre-2.9 `unp_ver`) and skips comments / AV / sub-blocks /
recovery records silently.

13 unit tests cover dispatcher truncation/garbage paths and walker
happy-path / multi-entry / ordering / unknown-block cases.

**Deliberately not in scope of §A2a**:

- The existing `crate::rar::format::parse_signature` still rejects
  the legacy magic with `UnsupportedFormatVersion`. The RAR5
  pipeline (`crate::download::rar_pipeline`) still calls that
  function. Net effect: legacy archives still fail with the
  pre-existing diagnostic when `peel` actually runs against one.
  §A2b unblocks that.
- No streaming-decoder factory changes — `streaming_factory_placeholder`
  is unaffected, RAR5 callers see no semantic change.

#### §A2b. Pipeline integration ✅ (commit cc60bf8)

**What landed**: the pipeline reads the magic, calls
`crate::rar::detect_signature`, and routes legacy archives
through new `run_legacy` / `extract_legacy_entry` methods on
`RarPipeline`. The legacy path mirrors the STORED arm of the RAR5
extractor and reuses the format-agnostic primitives (sparse file,
`wait_for_range`, `punch_range`, sink begin/write/end). A sibling
`read_legacy_header_window` handles the truncated-header retry.
`LEGACY_SIGNATURE_MAGIC` is registered in
[`DecoderRegistry::with_defaults`](../src/decode.rs) so legacy
archives reach the pipeline by magic-sniff.

**What turned out NOT to need changing** (vs. the original
sketch):

- **Sink stays as-is.** `RarSink::begin_entry` already accepts
  `Option<u32>` CRC-32 and `Option<[u8; 32]>` BLAKE2sp; the legacy
  path passes `Some(file_crc32)` + `None`. The ad-hoc `EntryHashSpec`
  enum the original sketch proposed is unnecessary.
- **Checkpoint stays as-is.** STORED legacy entries reuse the
  same `SinkState::Rar` shape — there's no decoder snapshot, so
  the `current_entry_decoder_state` slot stays `None` and the
  format version is still v10. The bump that the sketch
  anticipated will land with §F1 (mid-entry compressed legacy
  resume).
- **Compressed methods rejected at walk time** with
  `RarError::UnsupportedFeature` naming `unp_ver`/`method` byte;
  `m=0` is the only method the §A2b dispatch accepts.

**Tests**: 3 mock-server integration tests in
[tests/test_coordinator_rar3.rs](../tests/test_coordinator_rar3.rs) —
3-file STORED round-trip, `MHD_SOLID` flag variant, compressed
rejection. **1622 tests pass total.**

**Deliberately NOT in §A2b**: crash-resume parity for legacy
STORED. The crash-test harness in `test_coordinator_rar.rs` is
RAR5-specific and tightly timed; rather than thread two formats
through it, the legacy crash-resume scenario will land alongside
§F1 when checkpoint discriminator shape is known.

---

## Phase B — PPMd-II

> **Phase B sub-phasing** (resolved during §B0 implementation,
> further refined during §B2 implementation): the original
> "§B1. PPMd-II model" item turned out to be too coarse — the model
> decomposes into weakly-coupled layers that should land separately
> so each one's acceptance criteria are real.
>
> - **§B0** ✅ (commit e730509) — range coder. Bit-level entropy
>   primitive. Self-contained, round-trippable against a sister
>   encoder.
> - **§B1** ✅ (commit 62bc41c) — suballocator. The custom slab
>   allocator the PPMd model uses for its variable-order context
>   tree. 12-byte units, 38 freelist size classes, GlueCount-driven
>   compaction.
> - **§B2** — context tree + symbol-decode loop. Bulk of the
>   algorithm; consumes both §B0 and §B1. Further sub-split into
>   §B2a (model foundation, init/restart, SEE table seeding),
>   §B2b (decode loop, update_model, create_successors, rescale,
>   sister encoder, round-trip tests), and §B2c (edge-case stress).
> - **§B2a** ✅ (commit c5119cc) — model foundation + alloc.rs
>   split fix.
> - **§B2b** ✅ (commit f3a73b6) — decode loop + update model.
> - **§B2c** ✅ (commit f3d1226) — edge-case stress.
> - **§B3** ✅ (this commit) — 50 differential reference vectors
>   sourced from 7z-PPMd output, two model-layer fixes the corpus
>   surfaced, and a regen script that pins the encoder's actual
>   `mem_size_bytes` so the decoder shares the encoder's restart
>   schedule.

### §B1. PPMd-II suballocator ✅ (commit 62bc41c)

**What landed**: hand-rolled port of the LZMA SDK Ppmd7 allocator
at [src/decode/ppmd2/alloc.rs](../src/decode/ppmd2/alloc.rs). One
contiguous arena (`Box<[u8]>`) with three regions — a 4-byte
alignment pad reserving the `Ref(0)` null sentinel, a text region
the model layer will populate in §B2, and a unit region split
between `lo_unit` (grows up, multi-unit allocs) and `hi_unit`
(grows down, one-unit context allocs). 38 freelist size classes
quantised by the PPMd7 step rule (`step = i >= 12 ? 4 : (i >> 2) +
1`); lookup tables are computed at compile time. The rare-alloc
path scans larger size classes for a block to split, falls back to
lowering `units_start`, and triggers `glue_free_blocks` when
`glue_count` decays to zero (insertion-sort by address, merge
physically-adjacent runs, redistribute with `> 128`-unit splits).

**Public surface** (consumed by §B2):

- `Allocator::new(arena_bytes)`, `Allocator::restart()`.
- `alloc_units(indx) -> Option<Ref>`, `alloc_context() -> Option<Ref>`,
  `free_units(ptr, indx)`, `shrink_units(ptr, old, new) -> Ref`.
- `slot(ptr, indx) -> &[u8]` / `slot_mut`, plus 1-unit
  `context_slot` variants.
- `glue_free_blocks()` (called automatically; exposed for tests).
- `Allocator::units_to_indx` / `Allocator::indx_to_units` lookup
  helpers.

**What turned out NOT to need** (vs. the original sketch):

- **No `Stamp` field in free nodes.** The LZMA SDK reserves the
  first u32 of a free node for an integrity marker, but our glue
  walks the freelists themselves rather than scanning the arena
  linearly — the marker carries no information the freelist heads
  don't already.
- **No text-region API.** The plan's "text grows from the bottom"
  story is real, but round-one keeps `text` pinned at
  `align_offset`. The §B2 model layer is the first consumer that
  needs to write byte-stream history, and the API shape (per-byte
  bump? per-context buffered? boundary check) reads better when
  the model is in scope.

**Tests**: 23 unit tests in
[src/decode/ppmd2/alloc.rs](../src/decode/ppmd2/alloc.rs) cover
the freelist round-trip across all 38 size classes, LIFO ordering,
shrink in-place vs. via the target freelist, split-block remainder
placement (exact-fit + inexact), the rare-path larger-bucket steal
and the `units_start` fallback, and glue's adjacency /
non-adjacency / oversize-split behaviour. **1470 lib tests pass
total** (was 1447 at §B0).

**Demo**: `cargo test decode::ppmd2::alloc` passes; the allocator
round-trips arbitrary alloc / free / shrink / glue sequences.

### §B2. PPMd-II context tree + symbol-decode loop ✅ (commits c5119cc + f3a73b6 + f3d1226)

**What landed**: hand-rolled PPMd-II model at
[src/decode/ppmd2/model.rs](../src/decode/ppmd2/model.rs).
Faithful port of libarchive `archive_ppmd7.c` (itself a public-
domain redistribution of the LZMA SDK Ppmd7). Sits on top of §B0's
range coder and §B1's suballocator without modifying either's
public surface (one `pub(super)` visibility bump on `Ref::new`).

**Public surface** (consumed by §C / pipeline integration):

- `Model::new(arena_bytes, max_order) -> Result<Model, ModelError>`
  / `Model::restart()` — construct and reset.
- `Model::decode_symbol(&mut RangeDecoder<'_>) -> Result<u8, DecodeError>`
  — decode one byte; mutates model state via internal
  `update_model` / `update1` / `update1_0` / `update2` / `update_bin`.
- `Model::allocator()` / `Model::max_order()` — read-only accessors
  for integration code.
- `ModelError` (`BadOrder`, `ArenaTooSmall`, `ArenaTooLarge`, `Alloc`).
- `DecodeError` (`Range`, `EndMarker`, `Malformed`).
- `MIN_ORDER = 2`, `MAX_ORDER = 64`, `MIN_MEM_SIZE = 2048`,
  `MAX_MEM_SIZE ≈ 4 GiB - 36`.

The model is range-coder-variant-agnostic — it calls
`RangeDecoder::get_threshold` + `decode` exclusively, never the
`decode_bit` shortcut. Binary contexts go through the n-ary path
with `total = PPMD_BIN_SCALE (= 1 << 14)`, mirroring libarchive's
`Range_DecodeBit_RAR`. Swapping in a RAR-variant range coder
(needed by the real legacy pipeline, deferred to Phase C) reuses
the same model verbatim.

**What turned out NOT to need** (vs. the original sketch):

- **No new text-region API on `Allocator` for §B2c.** §B2a added
  the four-method text-region surface (`write_text_byte` /
  `dec_text` / `read_byte` / `text` / `units_start`) that the
  model layer needed. The "shape stays open" note from §B1 resolved
  cleanly — per-byte writes, no buffering, boundary check is the
  model's responsibility after each `write_text_byte`.
- **No separate `State` / `Context` typed wrappers.** The on-disk
  layouts live as byte offsets the typed accessors
  (`ctx_num_stats`, `state_symbol`, etc.) read and write through.
  Adding a typed wrapper layer would have meant either a parallel
  representation (cache invalidation hazard) or `Ref<State>`-style
  phantom-typed offsets (no real safety win on `u32` offsets).
- **No RAR-variant range coder yet.** The 7z range coder from §B0
  is correct for the model's round-trip tests (encoder and decoder
  use the same arithmetic). The RAR variant is needed for actual
  legacy RAR archive bytes and lands with §C2 / pipeline integration.

**What §B2 had to fix from §B1**:

- **alloc.rs initial unit/text split was inverted.** §B1 carved
  1/8 of the arena into the unit region and 7/8 into text; the
  canonical LZMA SDK Ppmd7 layout is 7/8 unit / 1/8 text. With
  the inverted ratio, the model's initial 129-unit allocation
  (root context + 128-unit state array) would have failed on any
  arena below ~16 KiB even though `PPMD7_MIN_MEM_SIZE` is 2 KiB.
  §B2a fixed it and added regression tests.

**Tests**: 33 unit + round-trip + edge-case tests across §B2a/b/c.

- §B2a (12 tests): `Model::new` rejection paths, `restart()`
  invariants, root-context layout, BinSumm / See / DummySee
  table seeding.
- §B2b (9 tests): single-byte, repeated-byte (binary path),
  alternating (swap + rescale), short / long ASCII at orders 4
  and 8, LCG pseudorandom 1 KiB, 256-symbol permutation, all-zero
  run, MIN_MEM_SIZE / MIN_ORDER corner.
- §B2c (12 tests): every supported order (2..=64), two-session
  restart, 32 KiB long stream, internal-restart-on-small-arena
  (the load-bearing exhaustion case), cyclic 256-byte permutation,
  MAX_ORDER on compressible input, decoder-side init-time and
  mid-stream truncation surfacing typed `DecodeError::Range`,
  accessor smoke tests.

**1507 lib tests pass total** (was 1470 at §B1, +37 from §B2 net of
the 16 alloc tests added in §B2a that test the text-region API and
the canonical 7/8 split).

**Demo**: `cargo test decode::ppmd2` runs all 69 module tests in
≈0.25 s debug / ≈0.04 s release. `cargo test --release
--all-features` clean. The model end-to-end round-trips arbitrary
byte streams through the encode → decode pipeline.

**Reference.** libarchive's `archive_ppmd7.c` / `archive_ppmd7_private.h`
(BSD-2-Clause, in turn redistributing Igor Pavlov's public-domain
LZMA SDK Ppmd7 code, in turn based on Dmitry Shkarin's PPMd var.H).
The libarchive distribution was the porting source-of-truth
because (a) it's the cleanest BSD-2-Clause form of the algorithm,
and (b) it ships both the 7z and RAR range-coder variants behind
one decode_symbol — useful when the RAR variant lands in Phase C.

### §B3. Differential cross-check ✅

**What landed**: 50 reference vectors at
[tests/fixtures/ppmd2/](../tests/fixtures/ppmd2/), each containing a
plaintext, the PPMd byte stream 7zip produced when encoding it, and
the encoder's `(order, mem_size_bytes)` tuple. The new
`differential_7z_tests::corpus_decodes_byte_for_byte` in
[src/decode/ppmd2/model.rs](../src/decode/ppmd2/model.rs) constructs
a [`Model`](../src/decode/ppmd2/model.rs) per fixture and asserts
byte-perfect decode.

**Why 7z PPMd, not `rar a -m5`**: the original sketch was no longer
buildable. Modern `rar 7.x` dropped legacy-archive creation outright
— there is no `-ma3` switch, no compatible `m<level>` mapping —
so there is no path to a fresh RAR3-format archive from the
licensed binary at `~/Downloads/rar/`. The §B2 model also still
sits on the 7z-variant range coder; the RAR-variant decoder is
deferred to Phase C. 7z PPMd uses the identical PPMd-II model and
the 7z-variant range coder this module already targets, so it is
the cleanest external reference today. When Phase C lands the
RAR-variant range coder + RAR3 LZ-block parser, a sibling corpus of
`rar`-produced fixtures is a natural addition.

**Two model bugs the corpus surfaced**:

1. **Binary-context decode used the n-ary path**. The model called
   `RangeDecoder::get_threshold(BIN_SCALE) + decode(start, size)`
   for both the bit-0 (hit) and bit-1 (escape) branches of a
   1-state context. libarchive's `Range_DecodeBit_7z` is **not**
   equivalent to this on the bit-1 branch: it computes
   `range -= bound` directly, preserving the low 14 bits of
   `range`, while the n-ary path computes
   `range = (range >> 14) * (BIN_SCALE - prob)` and throws them
   away. The bit streams agree on bit-0 and diverge on every bit-1
   (escape). The fix adds [`RangeDecoder::decode_bit_ppmd7`](../src/decode/ppmd2/range_dec.rs)
   plus the matching `RangeEncoder::encode_bit_ppmd7` and wires the
   model's BIN path through them. The earlier doc note that "the
   model is range-coder-variant-agnostic" was wrong about the
   binary primitive — the 7z variant has a dedicated bit method
   that has to be honoured.
2. **`init_esc` was indexed with the pre-update probability**.
   libarchive updates the binary-SEE probability via
   `PPMD_UPDATE_PROB_1` and then indexes `K_EXP_ESCAPE[*prob >> 10]`
   with the *post-update* value. The Rust code captured `prob` into
   a local before the update, then indexed with that stale local —
   one-bucket-low on most escapes. Drift accumulated through
   `update_model`'s 1-state→multi-state promotion (which uses
   `init_esc` to seed the new `SummFreq`) and silently desynced the
   model.

**Fixture-pipeline fix**: 7zip's command-line parser silently
overrides `m0=PPMd:mem=<N>m` on the version installed via Homebrew
(p7zip 17.05) and uses a fixed default — for our requests it
always emitted `mem_size_bytes = 0x10000` (64 KiB), regardless of
whether we asked for 1 MiB or 64 MiB. The decoder restarts on
`text >= units_start`, which is sized off `mem_size_bytes`; if we
passed the *requested* megabytes to the decoder it would never
restart while the encoder did, and the model state diverged on any
stream long enough to grow the text region. Streams short enough to
fit before the encoder's restart still decoded — which is why the
five high-order failures clustered on the longest payloads. The fix
is in regen.py: it now reads the PPMd method properties straight
out of the 7z archive header (method ID `03 04 01` + length-5
properties; `bytes[1..5]` are the canonical `mem_size_bytes` as
LE-u32) and serialises that value into each fixture so the decoder
shares the encoder's arena. Fixture wire format gained a `u32`
`mem_bytes` field; the prior `u8 mem_mb` was both insufficient
(64 KiB doesn't fit a MiB-granularity field) and unreliable.

**What `corpus_decodes_byte_for_byte` covers**:

- 10 payloads × 5 `(order, mem_mb)` configurations = 50 cases.
- Payloads sweep highly-compressible (zeros, period-27), modestly
  compressible (ASCII, lorem, English), and high-entropy (LCG
  pseudorandom). Sizes from 42 B to 16 KiB.
- Orders 2, 4, 8, 16, 32 (the PPMd7 maximum); mem requests 1 / 4 /
  16 / 32 / 64 MiB — all of which p7zip 17.05 collapses to 64 KiB
  in the encoded stream, as recorded.

**Lib-test count**: 1508 passes (was 1507 at §B2c — net +1 for
`corpus_decodes_byte_for_byte`; the diagnostic scaffolding that
narrowed down the two bugs was deleted before commit, so no other
test count changes).

**Demo**: `cargo test --features rar decode::ppmd2` runs all 70
ppmd2 module tests including the new corpus in <1 s.

**Reference harness**: while triaging the bugs above, a libarchive-
based standalone decoder was useful for printing observable model
state at every decoded byte and diff'ing it against our Rust
trace. That harness lives outside the tree (in `/tmp/refdec/`) and
is not committed, but its strategy — copy `archive_ppmd7.c`
verbatim + stub `archive_read_private.h` + small `main.c` that
parses our fixture format and dumps per-byte state — is
reproducible if a future bug needs the same level of triage.

---

## Phase C — Legacy LZ + RarVM

> **Phase C sub-phasing** (resolved in §C0): the original "§C1.
> Sliding window + Huffman tables" + "§C2. RarVM interpreter" split
> is too coarse — same lesson §B taught when "§B1. PPMd-II model"
> decomposed into §B0/§B1/§B2a/§B2b/§B2c/§B3. The pieces below are
> weakly coupled enough to land separately, each with its own
> demo / passing tests:
>
> - **§C0** ✅ (fadba5b) — sub-phasing + scaffolding.
> - **§C1a** ✅ (e96f842) — bitstream reader (MSB-first, with
>   `align_to_byte` for block-start alignment per libarchive's
>   `rar_br_consume_unaligned_bits`).
> - **§C1b** ✅ (2be01b6) — canonical Huffman builder
>   (`HuffmanCode`, flat-lookup table, 15-bit max) + per-block
>   bootstrap (20-entry precode → 404 main-table lengths → four
>   sub-trees of size 299 / 60 / 17 / 28).
> - **§C1c** ✅ (721ce9c) — block-prologue parser at
>   [`block_header`](../src/decode/rar_legacy/block_header.rs):
>   byte-align + `is_ppmd_block` flag + branch into LZ
>   (`keep_old_tables` + §C1b chain) or PPMd (7-bit ppmd_flags +
>   conditional dict / init-escape / max-order payload).
> - **§C1d** ✅ (this commit) —
>   [`dict`](../src/decode/rar_legacy/dict.rs) (sliding-window
>   ring buffer, 4 MiB cap, overlap-by-design `copy_match` +
>   `copy_recent_into` for the §C2 filter VM) and
>   [`dist_cache`](../src/decode/rar_legacy/dist_cache.rs)
>   (4-slot LRU of recent match offsets for symbols 259..=262 /
>   263..=298).
> - **§C1e** — LZ block dispatcher (`m=1..m=3`), differential
>   round-trip against the ssokolow corpus + curated single-entry
>   m=3 archives.
> - **§C1f** — RAR-variant range coder added to
>   [`src/decode/ppmd2/range_dec.rs`](../src/decode/ppmd2/range_dec.rs).
>   Small follow-on to §B0 — the model layer §B2 left "swap in a
>   RAR-variant range coder when the legacy pipeline needs it" as a
>   note. §C1f cashes that note in.
> - **§C1g** — PPMd entry path (`m=4`/`m=5`): wire
>   `crate::decode::ppmd2::Model` through the legacy per-entry
>   pipeline using the §C1f range coder.
> - **§C1h** — solid-mode driver + multi-block continuation across
>   entries.
> - **§C2a** — RarVM bytecode parser + standard filter set
>   (e8/e9/itanium/rgb/audio/delta) via the `VM_STANDARD_FILTERS`
>   shortcut encoding.
> - **§C2b** — VM interpreter for archive-supplied bytecode with
>   strict per-reference bounds-checking (no UB / abort on
>   malformed programs).
> - **§C2c** — fuzz harness + custom-filter differential corpus.

### §C0. Sub-phasing + module scaffolding ✅ (this commit)

**What landed**:

1. The Phase C sub-phasing block above, decided during §C0
   implementation. §C0 itself is the smallest non-trivial Phase C
   landing — a plan-doc update plus the new module entry — so the
   sub-phasing for the *rest* of Phase C is the actual deliverable.
2. New module entry [`src/decode/rar_legacy.rs`](../src/decode/rar_legacy.rs)
   gated behind the existing `rar` Cargo feature flag (same flag
   the §A2 archive walker and §B PPMd-II module use; no new
   feature surface). Sibling of [`src/decode/rar_native`](../src/decode/rar_native)
   and [`src/decode/ppmd2`](../src/decode/ppmd2). Submodules land
   one per sub-phase from §C1a onward; the entry file documents
   the module structure and routes the §0.2 / §A2 dispatch target
   for legacy compressed methods.
3. Wired into [`src/decode.rs`](../src/decode.rs) alongside
   `rar_native` and `ppmd2`, behind the same `cfg(feature = "rar")`
   gate.

**Reuse-vs-fork decision (locked here)**: legacy primitives live
as **sibling modules** in `src/decode/rar_legacy/`, not as
re-exports from `src/decode/rar_native/`. The two formats share
the same MSB-first bitstream convention and a 4-deep distance
cache in spirit, but the practical details differ — RAR3's
bitstream has different block-boundary alignment, RAR3's Huffman
ships four trees vs. RAR5's three with different max code lengths,
and RAR3's dictionary is fixed-4-MiB vs. RAR5's variable. Sharing
code-the-types-don't-fit produces leaky generics and version skew
between two algorithms that are not actually one algorithm. If
post-§C2 review surfaces real duplication we want to factor out,
that factoring lands as a separate clean-up commit.

**Corpus strategy (locked here)**: the §B3 commit recorded that
modern `rar 7.x` (the bundled `~/Downloads/rar/rar`, RAR 7.22) no
longer creates legacy archives — the `-ma3` switch was removed in
the 7.x line and the help text confirms only `-m<0..5>` exists for
compression level, with no archive-format selector. The licensed
binary is therefore decode-only for the legacy format. Phase C
fixtures come from:

1. [`ssokolow/rar-test-files`](https://github.com/ssokolow/rar-test-files)
   — CC0-licensed minimal RAR3 / CBR archives, 98 B – ~1 KiB each.
   Suitable for direct commit under
   [`tests/fixtures/rar_legacy/`](../tests/fixtures/) per §A2's
   precedent.
2. The bundled `unrar` (RAR 7.22, license at
   `~/Downloads/rar/license.txt`) as the reference-decoder side.
   Same role libarchive played for §B3's bug triage: extract each
   fixture with `unrar`, capture the expected plaintext, then
   differential against our decoder's output byte-for-byte.
3. Self-generated **structural** fixtures (hand-rolled in-test) for
   §C1a–§C1d unit tests, mirroring how §B0 round-tripped its range
   coder against a sister encoder before any real-archive bytes
   appeared.

Real-archive RAR3 generation is left as a `dev` tool task in §C1e:
if the §C0 corpus shape leaves gaps the ssokolow files don't fill
(e.g. specific filter combinations, large dictionary edge cases),
sourcing an older `rar 3.x` / `rar 5.x` Linux binary from RARLAB's
public archives covers them, but we don't pull that lever before
§C1e demonstrates it's needed.

**What §C0 deliberately is NOT**:

- No actual decoder code. Submodules under `src/decode/rar_legacy/`
  land one per sub-phase from §C1a forward.
- No `StreamingDecoder` factory changes. The pipeline still rejects
  `unp_ver ∈ [29, 36]` + `method ∈ 1..5` entries at walk time per
  §A2b until §C1e's dispatcher is in place.
- No `RangeDecoder` variant addition to `ppmd2/range_dec.rs`. That
  lands with §C1f, alongside the consumer that exercises it.

**Tests**: `cargo build --features rar` builds clean — the new
module is wired but exposes no public surface yet. Lib-test
count unchanged at 1508.

**Demo**: `git ls-files src/decode/rar_legacy*` shows the entry
file; `cargo test --features rar` is green.

---

### §C1. Legacy LZ pipeline

§C1a–§C1h land the bitstream / Huffman / dict / dispatcher /
PPMd-bridge / solid-mode pieces in turn per the sub-phasing block
above. Each sub-section ships with the demo / tests its predecessor
left a TODO for.

**Notes vs. RAR5** (carried forward from the original §C1 sketch):

- Same MSB-first bitstream convention, but RAR3 aligns to a byte
  boundary at block start and only there; RAR5 has tighter
  per-meta-tree alignment that doesn't apply.
- Four Huffman trees per block (literals 299, distances 60,
  lower-distance bits 17, repeats 28) vs. RAR5's three.
- Distance cache (`oldDist`) is 4-deep, same as RAR5, but RAR3
  pushes / promotes on different symbol numbers.

#### §C1a. Bitstream reader ✅ (this commit)

**What landed**: hand-rolled MSB-first bit reader at
[`src/decode/rar_legacy/bits.rs`](../src/decode/rar_legacy/bits.rs).
Sibling of [`crate::decode::rar_native::bits`] per the §C0 reuse-
vs-fork decision: both formats pack MSB-first, but the two readers
do not share an implementation so each can evolve against its own
format. The shape mirrors `rar_native`'s — 64-bit accumulator with
the next-to-read bit at position 63, `next_byte` cursor over the
borrowed byte slice, `bits_consumed` counter for diagnostics and
the §F1 resume snapshot — but the prose, error type, and test
fixtures are independently considered.

**Public surface** (consumed by §C1b onwards):

- `BitReader::new(data) -> Self`, `BitReader::bits_consumed()`,
  `bits_remaining()`, `byte_position()`, `is_at_end()`.
- `peek_bits(n) -> Result<u32, _>` and the matching
  `consume_bits(n)` — the canonical "decide based on a peek, then
  commit" pattern Huffman decoders need.
- `read_bits(n) -> Result<u32, _>` — folded peek+consume for the
  common single-shot read.
- `align_to_byte()` — skips to the next byte boundary. Mirrors
  libarchive's `rar_br_consume_unaligned_bits` macro. RAR3 calls
  this at the start of every block before reading the
  `is_ppmd_block` flag (libarchive `archive_read_support_format_rar.c`
  lines 2314..2317); §C1c's block-header parser is the first
  in-tree caller.
- `BitReadError::Underrun { needed, byte_index, bit_off }` —
  carries the cursor at the moment of underrun so the upper layer
  can include it in the eventual
  [`crate::rar::RarError::Truncated`] / `Malformed` message.

**What turned out NOT to need** (vs. the §C0 sketch):

- **No `read_bits_forced` (tail-zero-padding) primitive.** The
  §C0 plan flagged libarchive's `rar_br_bits_forced` macro as a
  candidate for the legacy reader — it pads the high bits of the
  result with zeros when the cache underruns, used at end-of-
  stream so a Huffman peek that overshoots can still return a
  prefix. The §C1a posture is "make the caller pre-flight reads
  via `bits_remaining` and surface underrun explicitly", same as
  the RAR5 sibling. If §C1b's Huffman decoder turns out to need
  the forced-padding behaviour for end-of-block lookahead, it
  lands as a sibling method then. The §C1a tests show the upper
  layer can already handle end-of-stream cleanly via
  `is_at_end`.
- **No streaming-source plumbing.** Same call as §A1 of
  `PLAN_rar5_decoder.md`: the §3 RAR pipeline materialises an
  entry's data area in a buffer before invoking the decoder, so
  the bit reader takes `&[u8]` and never touches IO. Phase G
  may swap in a chunked-feeding variant for memory-bound entries;
  it lands as a sibling type, not a refit.

**What §C1a confirmed about the RAR3 bitstream** (resolves the
§C0-deferred "alignment rules" hedge):

- **MSB-first within each byte**, same as RAR5.
- **No automatic byte alignment between blocks** — the bitstream
  is fundamentally continuous. The `align_to_byte` call at block
  start is *explicit* (libarchive does it via the
  `rar_br_consume_unaligned_bits` macro before reading the
  `is_ppmd_block` flag); the reader does not byte-align on its
  own.
- **Cache layout differs from libarchive's, semantics don't.**
  Libarchive's `cache_buffer` keeps the next-to-read bit at
  position `cache_avail - 1` (bottom-aligned cache, grow upward,
  consume by decrementing `cache_avail`); our `acc` keeps it at
  position 63 (top-aligned cache, grow downward, consume by left-
  shifting). Both materialise the same MSB-first stream; the
  `align_to_byte` operation drops `bits_consumed % 8 == 0`-aligned
  bits either way.

**Tests**: 17 unit tests covering zero-bit reads, single-byte
splits, byte-spanning reads, 32-bit single-shot reads, peek vs.
consume, partial-cursor underrun reporting, byte alignment at
block boundaries (the load-bearing libarchive-equivalent test),
a 60-group random round trip with widths in `1..=31`, and
legacy-realistic 15-bit Huffman + 18-bit distance-extra-bits
widths at byte-boundary-crossing offsets. **1525 lib tests pass
total** (was 1508 at §C0, +17 from §C1a).

**Demo**: `cargo test --features rar decode::rar_legacy::bits`
runs all 17 tests in <50 ms debug / <10 ms release.

#### §C1b. Canonical Huffman + per-block bootstrap ✅ (this commit)

**What landed**:

1. [`src/decode/rar_legacy/huffman.rs`](../src/decode/rar_legacy/huffman.rs)
   — `HuffmanCode` builder + decoder. Same shape as the
   `rar_native::huffman` sibling: MSB-first canonical codes
   stored as a flat lookup table sized `1 << max_len`, queried
   via [`super::bits::BitReader::peek_bits`] + `consume_bits`.
   15-bit max code length (libarchive's `MAX_SYMBOL_LENGTH`);
   worst-case table 128 KiB per code, 512 KiB for the four-tree
   block, negligible against the 4 MiB sliding-window dictionary
   §C1d will land.
2. [`src/decode/rar_legacy/bootstrap.rs`](../src/decode/rar_legacy/bootstrap.rs)
   — the three layers libarchive's `parse_codes` interleaves:
   `read_precode_lengths` (20 × 4-bit literals with the `0xF` +
   zerocount escape), `read_main_lengths` (404 entries decoded
   via the precode with delta-mod-16 + repeat-last + zero-run
   opcodes), and `build_main_tables` (slice the 404-entry buffer
   into the four canonical sub-trees: `main` 299, `offset` 60,
   `low_offset` 17, `length` 28).

**Public surface** (consumed by §C1c onwards):

- `huffman::HuffmanCode` + `HuffmanCode::build(&[u8]) -> Result<…>`
  + `HuffmanCode::decode(&mut BitReader) -> Result<u16, …>` +
  `HuffmanCode::bits()` + `HuffmanCode::is_populated()`.
- `huffman::HuffmanError` (`CodeLengthTooLarge`, `OverSubscribed`,
  `MissingPrefix`, `Underrun`).
- `bootstrap::{MAIN_CODE_SIZE, OFFSET_CODE_SIZE, LOW_OFFSET_CODE_SIZE,
  LENGTH_CODE_SIZE, MAIN_TABLE_TOTAL, PRECODE_SIZE}` — the libarchive-
  matching constants.
- `bootstrap::MainTables { main, offset, low_offset, length }`.
- `bootstrap::read_precode_lengths(reader) -> Result<[u8; 20], …>`.
- `bootstrap::read_main_lengths(reader, precode, &mut [u8; 404])
  -> Result<(), …>`. Note: the caller owns the per-entry buffer
  across blocks and decides whether to memset-to-zero (when
  `keep_old_tables` is false) or retain the previous block's
  values (when true). This matches libarchive's lengthtable
  semantics and is what enables the delta-from-previous-block
  encoding.
- `bootstrap::build_main_tables(&[u8; 404]) -> Result<MainTables, …>`.
- `bootstrap::BootstrapError` (`Underrun`, `HuffmanBuild`,
  `RepeatLastAtStart`, `InvalidPrecodeSymbol`).

**What turned out NOT to need** (vs. the §C0 sketch):

- **No fallback decode tree.** Libarchive's `huffman_code` mixes
  a flat lookup table (sized `min(max_len, 10)`) with a tree
  walked when codes exceed the table size. The rar_native
  sibling uses a single flat-lookup table at `max_len` width and
  pays the 128 KiB / code worst case for simpler / faster decode.
  §C1b inherits that posture; the worst case fits in L2 and is
  ~4 × what rar_native pays in a single block. §G may revisit if
  profiling shows it matters.
- **No precode "fast path" for libarchive's `Range_DecodeBit_RAR`
  variant.** That's the RAR-variant range coder §C1f lands; the
  bootstrap's precode goes through the same canonical Huffman
  primitive as the main code.
- **No explicit Kraft-equality enforcement.** A canonical code
  with `Σ 2^(-len) < 1` is *under-subscribed* — some prefixes
  don't map to any symbol — but that's not malformed per se
  (libarchive accepts them). The decoder surfaces
  `HuffmanError::MissingPrefix` when an under-subscribed alphabet
  is hit at decode time; the builder only rejects over-
  subscription, where the canonical-code accumulator overflows
  `1 << max_len`.

**Tests**: 24 unit tests across the two new files.

- `huffman.rs` (10 tests): empty alphabet, single-symbol
  alphabet, two-symbol equal-length codes, a six-symbol
  hand-checked canonical round trip, over-subscription
  rejection, code-length-too-large rejection, under-subscription
  decode-time `MissingPrefix`, mid-symbol underrun surfacing,
  200-symbol mixed-length-alphabet LCG-shuffled round trip, and
  the max-code-length-15 alphabet building cleanly.
- `bootstrap.rs` (14 tests): twenty literal precode lengths
  round-trip, `0xF` + zerocount-0 literal-15 path, `0xF` +
  zerocount-5 zero-run path, end-of-buffer truncation of an
  oversized zero run, precode-side underrun, delta-mod-16 update
  semantics across 404 entries, opcode-16 small repeat-last,
  opcodes-18/19 zero-runs, opcode-16 + opcode-17 at index 0
  errors, the delta `(15 + 1) & 15 = 0` wrap, `build_main_tables`
  slicing into four canonical codes with mixed populated /
  empty sub-trees, `build_main_tables` surfacing
  `HuffmanError::OverSubscribed` through the wrapped error type,
  and an end-to-end "encode precode + main stream → decode
  precode + main stream → build sub-tables" round trip.

**1549 lib tests pass total** (was 1525 at §C1a, +24 from §C1b).

**Demo**: `cargo test --features rar decode::rar_legacy` runs
all 41 rar_legacy module tests (17 from §C1a + 24 from §C1b) in
<10 ms release.

#### §C1c. Block-prologue parser ✅ (this commit)

**What landed**:
[`src/decode/rar_legacy/block_header.rs`](../src/decode/rar_legacy/block_header.rs)
— the thin parsing wrapper around §C1a + §C1b that decodes one
block's prologue and surfaces the LZ-vs-PPMd discriminant plus
each branch's payload. Mirrors libarchive's `parse_codes` head
(lines 2301..2417 of the reference): byte-align, read 1-bit
`is_ppmd_block` flag, and then either:

- **LZ** — read 1-bit `keep_old_tables`, conditionally zero the
  persistent length buffer, and chain into §C1b's three stages.
  Returns a `BlockPrologue::Lz { tables, kept_old_tables }`.
- **PPMd** — read 7-bit `ppmd_flags`, conditionally read an
  8-bit `dict_byte` (gated by `flags & 0x20`) and an 8-bit
  `init_esc` byte (gated by `flags & 0x40`), and decode the
  max-order from `(flags & 0x1F) + 1` with the
  `> 16 → 16 + (raw - 16) * 3` remap. Returns a
  `BlockPrologue::Ppmd { restart, dictionary_size, max_order,
  init_esc }`.

**Public surface** (consumed by §C1e and §C1g):

- `BlockPrologue` enum with the two variants above.
- `BlockHeaderError` (`Underrun`, `Bootstrap`, `PpmdMaxOrderTooSmall`).
- `parse_block_prologue(&mut BitReader, &mut [u8; 404])
  -> Result<BlockPrologue, BlockHeaderError>` — the single
  public entry-point.

**What turned out NOT to need** (vs. the §C0 sketch):

- **No PPMd context allocation.** The original §C0 thinking
  pictured the prologue parser owning the PPMd init dance.
  §C1g's caller-owned `PpmdSession` is the cleaner home for
  context allocation, range-decoder restart, and the
  "first-block has-no-prior-context" check — keeping the
  prologue parser pure-parsing means §C1c is testable without
  pulling in §B's `Model` / `RangeDecoder`. The
  `Ppmd { restart, dictionary_size, max_order, init_esc }`
  surface is exactly the state §C1g needs to decide what to do.
- **No `BlockPrologue::Empty` variant for end-of-entry.** End-
  of-entry is signalled inside the LZ block dispatcher (a
  specific main-code symbol exits the block loop, and the
  pipeline decides whether more blocks follow); the prologue
  parser is unconditional — every call reads at least the
  is_ppmd bit and one path's payload.

**Tests**: 11 unit tests at
[`src/decode/rar_legacy/block_header.rs`](../src/decode/rar_legacy/block_header.rs).

- PPMd: minimal-no-flags, restart with dict + low max-order,
  restart with high max-order (the `(32 - 16) * 3 + 16 = 64`
  remap), restart with `max_order == 1` error, init-escape-only
  flag, and both-flags wire-format order (is_ppmd → flags →
  dict → init-escape).
- LZ: `keep_old_tables == 0` zeros a pre-seeded length buffer
  before applying deltas, `keep_old_tables == 1` preserves the
  buffer before deltas, and the returned `MainTables` are
  whatever §C1b builds (an all-zero block yields four empty
  alphabets, which is fine).
- Cross-cutting: the prologue byte-aligns from an off-aligned
  cursor before reading its first bit, and a truncated input
  surfaces `Underrun` cleanly.

**1560 lib tests pass total** (was 1549 at §C1b, +11 from §C1c).

**Demo**: `cargo test --features rar
decode::rar_legacy::block_header` runs all 11 tests in <10 ms
release. The decoder now reads "what kind of block is this and
what does it carry" end-to-end from a raw bitstream — the
remaining §C1d / §C1e plumbing makes the four trees actually
produce LZ output.

#### §C1d. Sliding-window dictionary + dist-cache LRU ✅ (this commit)

**What landed**: two sibling files at
[`src/decode/rar_legacy/dict.rs`](../src/decode/rar_legacy/dict.rs)
and
[`src/decode/rar_legacy/dist_cache.rs`](../src/decode/rar_legacy/dist_cache.rs)
— the state §C1e's per-symbol dispatcher mutates as it emits
output. Both are forks of their `rar_native` counterparts per
§C0's reuse-vs-fork posture; the RAR3 versions cap the dict at
4 MiB (libarchive's `DICTIONARY_MAX_SIZE`), carry their own
error type / wire references / test fixtures, and are free to
evolve against legacy-only changes without touching `rar_native`.

**Public surface** (consumed by §C1e):

- `dict::Dict::new(capacity) -> Result<Self, DictError>`
  rejecting zero and over-cap. `capacity()` / `total_written()`
  / `live_bytes()` accessors.
- `dict::Dict::push_literal(b, &mut Vec<u8>)` — write to ring
  and stage to the output sink in one call.
- `dict::Dict::copy_match(distance, length, &mut Vec<u8>)` —
  byte-wise back-reference copy that handles `length > distance`
  overlap (the RLE-via-LZSS trick).
- `dict::Dict::copy_recent_into(&mut [u8])` — pull the last
  `out.len()` bytes in stream order without advancing the
  dictionary; §C2's filter VM is the eventual consumer.
- `dict::DictError` (`CapacityZero`, `CapacityTooLarge`,
  `BackReferenceUnderflow`, `DistanceExceedsCapacity`,
  `RecentWindowOverrun`) — all the failure modes a malformed
  bitstream can trigger plus the construction-time guards.
- `dist_cache::DistCache::{new, from_slots, slots, peek, push,
  touch}` — push for fresh-match symbols (263..=298), touch for
  cached-distance symbols (259..=262 via `idx = symbol - 259`).
- `dist_cache::DIST_CACHE_SLOTS = 4` constant.

**What turned out NOT to need** (vs. the §C0 sketch):

- **No `last_offset` / `last_length` fields here.** Symbol 258
  ("repeat last match") uses the dispatcher's most-recently-
  emitted `(offset, length)` pair, which lives outside the
  cache. The §C1e `LzDecoder` owns those as plain fields; the
  cache stays the pure 4-slot LRU.
- **No power-of-2 capacity requirement.** Libarchive sizes the
  buffer at `rar_fls(unp_size) << 1` (power-of-2 up to 4 MiB),
  but the ring math uses `head + 1; if head == cap { head = 0 }`
  rather than `mask`-AND, so any positive capacity ≤ 4 MiB
  works. §C1e's sizing logic will produce power-of-2 capacities
  to match libarchive; §C1d just trusts the caller.
- **No live-tail snapshot for §F1 yet.** rar_native's `Dict`
  has a `snapshot_live_tail` for resume; the legacy `Dict`
  punts that to §F1's plan-resolution block. PPMd-mode entries
  also need to serialise the arena, so the snapshot surface is
  better decided once both consumers are in scope.

**Tests**: 25 unit tests across the two files.

- `dict.rs` (16 tests): zero-capacity / over-cap construction
  errors, fresh-dict accessors, push-literal round trip,
  copy_match non-overlap / distance-1 RLE / overlap-by-design,
  zero-distance error, distance > total_written error,
  distance > capacity error, the ring wrap when `head` passes
  capacity, `total_written` persisting across multiple wraps,
  `copy_recent_into` straight / wrapped / overrun, and the
  `MAX_DICT_BYTES` (4 MiB) cap constructing cleanly.
- `dist_cache.rs` (9 tests): zero-construction, push promote /
  shift / overflow at slot 3, touch(0..=3) covering all four
  shift patterns, a libarchive-combined push-and-touch sequence
  modeling `271, 259, 271, 261`, and `from_slots` round trip.

**1585 lib tests pass total** (was 1560 at §C1c, +25 from §C1d).

**Demo**: `cargo test --features rar decode::rar_legacy::dict
decode::rar_legacy::dist_cache` runs all 25 tests in <10 ms
release. The decoder now has every primitive §C1e will need to
emit per-symbol output: the bit reader (§C1a) reads the block,
the precode + main-length parser (§C1b) builds the four
Huffman codes, the block-prologue (§C1c) chooses LZ vs PPMd
and applies the keep-old-tables logic, and §C1d's `Dict` +
`DistCache` hold the LZ state the dispatcher mutates.

---

### §C2. RarVM (filter pipeline)

§C2a–§C2c land bytecode parser / interpreter / fuzz harness per
the sub-phasing block above. The original §C2 sketch carries
forward:

1. Decode the standard filter set (e8/e9/itanium/rgb/audio/delta)
   plus the `VM_STANDARD_FILTERS` shortcuts the encoder uses to
   compress them.
2. Compile archive-supplied bytecode to an internal opcode list at
   filter-registration time; interpret per-block.
3. Strict bounds-checking on every memory reference (the
   real-world VM has been the source of half a dozen unrar CVEs;
   our interpreter must reject out-of-range memory access without
   relying on UB or aborts).

A curated corpus of archives that exercise the standard filters
plus at least three real-world archives that ship custom filter
programs is committed alongside §C2c; the §C0 corpus decision
above sources these from RARLAB public test sets if the ssokolow
files don't include filter-using archives.

---

## Phase D — Older generations (only if §0.1 picks Option 1 or 3)

### §D1. RAR 2.0 / 2.6 algorithm

**Conditional.** Only landed if §0.1 expanded scope beyond 2.9+.
Otherwise this section is the rejection diagnostic in §A1.

**What**: classic LZSS + Huffman, with 2.6's multimedia (PPMII
predecessor — distinct from PPMd-II) and audio compression modes.

**Sketch.** Self-contained module
`src/decode/rar_legacy/v26.rs`. No code shared with §C — different
table layout, different distance encoding, different filter set.

---

## Phase E — Integration

### §E1. `StreamingDecoder` wiring + format-mismatch path

**What**: `RarLegacyStreamDecoder` exposing the
[`crate::decode::StreamingDecoder`](src/decode.rs) trait. The
pipeline learns to dispatch on the §A2 enum.

**Sketch**.

1. Per-entry decoder selects the right inner driver based on
   `unp_ver` / `method`.
2. `decode_step(sink)` keeps the bounded-work contract.
3. `archive::walk_archive` returns `ArchiveSummary` populated for
   legacy archives the same as RAR5, including solid-mode flag.

**Tests**: differential round-trip 100+ legacy archives across the
`rar3` and `rar4` corpora committed to `tests/fixtures/rar_legacy/`,
byte-comparing against `unrar`-produced expected outputs.

**Demo**: full legacy round-trip against a multi-MB archive
downloaded via the mock server.

---

## Phase F — Resume

### §F1. Mid-entry checkpoint blob (legacy)

**What**: serialisable decoder snapshot for legacy entries. Same
shape as `PLAN_rar5_decoder.md` §F1, with PPMd-II model state
serialised in addition to the LZ dict.

**Sketch**.

1. PPMd-II model state is *not* trivially serialisable —
   sub-allocator pointers, context tree. Two options: (a) snapshot
   the entire allocator arena (large but mechanical), (b) replay
   from the previous block boundary (small but slow). Probably (a)
   bounded by a `--max-resume-state` knob.
2. Bump `Checkpoint::format_version` (next free slot after the
   RAR5 §F1 bump).
3. Crash-test parity with `tests/test_coordinator_rar.rs`.

**Demo**: crash-resume harness covers compressed legacy entries.

---

## Phase G — Throughput

### §G1. Profiling + targeted hot paths

**What**: same shape as `PLAN_rar5_decoder.md` §G1 — profile-guided
optimisation in `src/decode/rar_legacy/` and `src/decode/ppmd2/`,
no new files outside those trees.

**Why last**: PPMd in particular has a cache-locality knob
(sub-allocator layout) that is best tuned with real profiles, not
guesses.

**Demo**: bench-grid run shows decode throughput within 2× of the
`unrar` C++ reference on the curated legacy corpus.

---

## What "legacy RAR support is done" means

1. Each phase's demo has been recorded and reviewed.
2. The crash-test harness covers compressed legacy entries,
   solid and non-solid; resumes still produce byte-identical
   output.
3. `RarError::UnsupportedFormatVersion` is reachable only for the
   formats out of scope per §0.1 (and `RAR 1.x` per the deliberate
   exclusion).
4. README format-matrix entry for `.rar` adds "legacy (RAR3/RAR4)"
   alongside RAR5, with footnotes for any §0.1-deferred generations.
5. CI gates remain green; coverage thresholds (80 % overall, 95 %
   on critical paths) hold across the new modules.
6. `OPTIMIZATIONS.md` `O.RAR4` entry is removed; any
   §0.1-deferred sub-items are filed as new follow-ons
   (`O.RAR.LEGACY15`, etc.).

## Schedule guidance

Phases are sequenced; do them in order, do each phase completely.
A → B → C → E is the critical path. Phase D is conditional on
§0.1. Phase F (resume) can land any time after §E. Phase G
(throughput) is optional for the milestone but expected before the
matrix loses any "RAR5-only" caveat.

§A is a natural "land partial" checkpoint: §A1 + §A2 ship a binary
that extracts STORED legacy archives and surfaces precise
diagnostics for everything else. If §0 takes a while to resolve,
this subset is shippable on its own and adds value.

## Filed follow-ons (added to `OPTIMIZATIONS.md` after §G ships)

- **`O.RAR.LEGACY15`** — RAR 1.x archives. Corpus is effectively
  zero; defer indefinitely.
- **`O.RAR.PPM5`** — hypothetical PPMd-encoded RAR5 entries
  (the spec reserves the slot; no encoder emits them today).
  Reuses `src/decode/ppmd2/` from §B1.
