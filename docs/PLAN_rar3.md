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
> **§C1d (3e159f2)** landed the sliding-window ring buffer at
> [`src/decode/rar_legacy/dict.rs`](../src/decode/rar_legacy/dict.rs)
> (4 MiB cap, overlap-by-design `copy_match` for the `length >
> distance` self-extending RLE-via-LZSS case, `copy_recent_into`
> for the §C2 filter VM) and the 4-slot LRU at
> [`src/decode/rar_legacy/dist_cache.rs`](../src/decode/rar_legacy/dist_cache.rs)
> (push / touch matching libarchive's `oldoffset[]` semantics
> from `archive_read_support_format_rar.c` lines 3030..3115).
> 25 unit tests across the two files.
> **§C1e₁ (80f2f9c)** landed the per-symbol LZ dispatcher at
> [`src/decode/rar_legacy/lzss.rs`](../src/decode/rar_legacy/lzss.rs)
> — wires §C1a–d into `LzDecoder::decode_block`, ports the
> libarchive `expand` function's symbol dispatch (literals,
> block-end, filter-decl, repeat-last, cached-distance,
> short-distance, full-match-small + full-match-large with the
> low-offset code + repeat sentinel), and exits cleanly on
> symbol 256 / 257 via a typed `BlockEnd` enum. 13 unit tests
> with synthetic fixtures covering every dispatch branch.
> **§C1e₂ (541c1ee, plan-doc only)** recorded what corpus
> inspection turned up: every compressed entry in the ssokolow
> CC0 archives is `is_ppmd_block = 1` (the encoder picked PPMd
> for the `-m5` short-text payloads), so the LZ-only
> cross-check originally pitched for §C1e₂ can't run today.
> Cross-check defers to §C1g; the corpus is the PPMd cross-
> check target there.
> **§C1f (5976588)** landed the RAR-variant of the PPMd
> range coder in
> [`src/decode/ppmd2/range_dec.rs`](../src/decode/ppmd2/range_dec.rs).
> `RangeCoderVariant { Sevenz, Rar }` discriminator; new
> `new_rar(src)` constructor reads a 4-byte init prefix with no
> leading marker (vs 7z's 5-byte `0x00`-prefixed init) and sets
> `bottom = 0x8000`; `decode` branches between
> `Code -= start*Range` (7z, libarchive `Range_Decode_7z`) and
> `Low += start*Range` (RAR, libarchive `Range_Decode_RAR`);
> `normalize` uses the unified carry-handling loop from
> libarchive's `Range_Normalize`; `decode_bit_ppmd7` renamed to
> `decode_bit_bin` with an internal variant branch (7z keeps
> the `Range_DecodeBit_7z` dedicated math; RAR uses
> `get_threshold + decode` matching `Range_DecodeBit_RAR`).
> The model layer's 4 binary-context call sites rename to
> `decode_bit_bin` / `encode_bit_bin`; the §B PPMd round-trip
> and differential-corpus tests all pass unchanged. 5 new
> RAR-init / structural tests.
> **§C1g (863ea77)** landed the per-entry PPMd decoder at
> [`src/decode/rar_legacy/ppmd_entry.rs`](../src/decode/rar_legacy/ppmd_entry.rs)
> — `PpmdSession` owns the model + dict + escape-byte state
> and implements libarchive's `read_data_compressed`
> dispatch loop (lines 2158..=2238). The first end-to-end
> legacy RAR archive decode landed alongside: the ssokolow
> single-entry archives decode to `"Testing 123\n"` through
> `walk_archive → BitReader → parse_block_prologue →
> RangeDecoder::new_rar → PpmdSession::decode_block`.
> **§C1h (f9db3a9)** lands the per-entry front-door at
> [`src/decode/rar_legacy/entry.rs`](../src/decode/rar_legacy/entry.rs):
> `decode_entry(archive_bytes, &LegacyFileEntry) -> Vec<u8>`
> wraps STORED / LZ / PPMd dispatch behind one function, with
> precise errors for the multi-block-within-entry / cross-
> mode / solid-mode cases the corpus doesn't exercise. The
> ssokolow `testfile.rar3.cbr` (multi-entry, 220-byte JPEG +
> 87-byte PNG, both PPMd) decodes both entries byte-perfectly
> against the bundled `unrar`'s extraction. 3 new lib-test
> entries + 2 new integration tests; lib-test count now 1614,
> integration-test count now 6.
> **§C2a (prior commit)** landed the RarVM filter-declaration
> parser + standard filter set at
> [`src/decode/rar_legacy/vm/`](../src/decode/rar_legacy/vm.rs).
> Three submodules: `vm::membits` (memory-only MSB-first bit
> reader + `next_rarvm_number` codec), `vm::parse`
> (`read_filter_declaration_bytes` + `FilterStack` + `Program`
> + `parse_filter_declaration` for the eight flag bits
> + XOR-checksum + optional static-data section, mirroring
> libarchive's `parse_filter` at lines 3258..3397), and
> `vm::standard` (DELTA / E8 / E8E9 / RGB / AUDIO recognition
> via libarchive's `crc32 | length << 32` fingerprint shortcut
> + native executors mirroring `execute_filter_*`).
> **§C2b + §C2c (this commit)** finishes Phase C: live filter-
> pipeline wiring through
> [`entry::decode_entry`](../src/decode/rar_legacy/entry.rs)
> via the new
> [`vm::dispatch`](../src/decode/rar_legacy/vm/dispatch.rs)
> submodule, multi-block LZ decode (both `BlockEnd::NextBlock`
> and `BlockEnd::EntryDone` treated as "block done; re-parse
> if `output.len() < unpacked_size`"), and `FilterStack`'s
> `pending` queue draining at entry end. The §C2b corpus is
> four self-encoded LZ-only filter fixtures at
> `tests/fixtures/rar_legacy/filter_*.rar` — encoded against
> `rar 3.93` (Linux x86_64, RARLAB public release) under
> Docker `linux/amd64` with `-mcT-` (disable PPMd) and
> `-mcX+` (force one standard filter); all four decode
> byte-identical to `rar 7.22`'s reference extraction.
> Audio-executor off-by-one bug found + fixed during
> integration: libarchive's `count++ & 0x1F` post-increment
> fires the weight update on samples 0/32/64/…; our initial
> pre-increment off-by-one fired on 32/64/… and the audio
> fixture drifted progressively through the adaptive
> predictor. §C2c adds a parser+dispatcher fuzz target at
> [`fuzz/fuzz_targets/rar_legacy_filter.rs`](../fuzz/fuzz_targets/rar_legacy_filter.rs).
> The custom-bytecode VM interpreter (the original §C2b
> sketch's "interpreter for archive-supplied bytecode")
> moves to a post-MVP follow-on §C2-extension, gated on a
> clean-room reference becoming available — unrar is
> off-limits per `AGENTS.md`, and libarchive doesn't ship
> one (stops at the fingerprint shortcut). Lib-test count
> grows from 1657 to 1662; integration-test files grow from
> 1 to 2 (six PPMd tests + five filter tests = 11 `rar_legacy`
> integration tests). The fifth filter fixture
> (`filter_multi`) exercises a three-filter declaration
> shape with register-mask, block-start bias, and
> program-cache reuse — none of which the single-filter
> fixtures hit.
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
> - **§C1d** ✅ (3e159f2) —
>   [`dict`](../src/decode/rar_legacy/dict.rs) (sliding-window
>   ring buffer, 4 MiB cap, overlap-by-design `copy_match` +
>   `copy_recent_into` for the §C2 filter VM) and
>   [`dist_cache`](../src/decode/rar_legacy/dist_cache.rs)
>   (4-slot LRU of recent match offsets for symbols 259..=262 /
>   263..=298).
> - **§C1e₁** ✅ (80f2f9c) — per-symbol LZ dispatcher at
>   [`lzss`](../src/decode/rar_legacy/lzss.rs). Wires §C1a–d
>   together into `LzDecoder::decode_block`, with libarchive's
>   `lengthbases` / `lengthbits` / `offsetbases` / `offsetbits`
>   / `shortbases` / `shortbits` const tables inlined. Returns
>   a `BlockEnd::{NextBlock, EntryDone, FilterDecl}` enum so
>   the upper layer (§C1h / §C2) can decide what to do.
> - **§C1e₂** ✅ (541c1ee, plan-doc only) — corpus inspection:
>   every compressed entry in
>   [ssokolow/rar-test-files](https://github.com/ssokolow/rar-test-files)
>   starts with `is_ppmd_block = 1` (the encoder picks PPMd
>   for `-m5` short-text payloads). The real-archive cross-
>   check therefore can't validate the LZ path; it moves to
>   §C1g, where PPMd lands and the ssokolow corpus actually
>   decodes. The synthetic-fixture coverage in §C1e₁ is the LZ
>   path's primary validation until then.
> - **§C1f** ✅ (5976588) — RAR-variant range coder added
>   to [`src/decode/ppmd2/range_dec.rs`](../src/decode/ppmd2/range_dec.rs).
>   `RangeCoderVariant { Sevenz, Rar }` discriminator; new
>   `new_rar(src)` constructor (4-byte init, no leading marker,
>   `bottom = 0x8000`); `decode` branches between
>   `Code -= start*Range` (7z) and `Low += start*Range` (RAR);
>   `normalize` uses the unified libarchive carry-handling loop
>   (the underflow-recovery branch is dead in 7z mode but
>   reachable in RAR); `decode_bit_ppmd7` renamed to
>   `decode_bit_bin` with an internal variant branch — 7z keeps
>   `Range_DecodeBit_7z` math; RAR uses `get_threshold +
>   decode` matching `Range_DecodeBit_RAR`. Model layer is
>   variant-agnostic (4 call-site renames; no behaviour
>   change for 7z).
> - **§C1g** ✅ (863ea77) — PPMd entry path. New
>   [`ppmd_entry`](../src/decode/rar_legacy/ppmd_entry.rs)
>   module: `PpmdSession` wraps
>   [`Model`](../src/decode/ppmd2/model.rs) +
>   [`Dict`](../src/decode/rar_legacy/dict.rs) + escape-byte
>   state for per-entry PPMd decoding. Implements libarchive's
>   `read_data_compressed` (lines 2158..2238) dispatch:
>   literal-vs-escape, EOD marker (code 2), new-table (code 0,
>   surfaced for §C1h), large LZ match (code 4), short LZ match
>   (code 5), escape-of-escape literals. **First end-to-end
>   legacy RAR archive decode landed here**: the ssokolow
>   single-entry archives decode to the expected 12-byte
>   plaintext through the full stack `walk_archive → BitReader →
>   parse_block_prologue → RangeDecoder::new_rar →
>   PpmdSession::decode_block`.
> - **§C1h** ✅ (this commit) — per-entry front-door
>   [`entry`](../src/decode/rar_legacy/entry.rs):
>   `decode_entry(archive_bytes, &LegacyFileEntry) -> Vec<u8>`
>   wraps STORED / LZ / PPMd dispatch behind one function and
>   adds multi-entry support. The ssokolow `testfile.rar3.cbr`
>   (multi-entry: 220-byte JPEG + 87-byte PNG, both PPMd)
>   decodes both entries byte-perfectly. Solid-mode (cross-
>   entry state) + multi-block-within-entry are surfaced as
>   precise errors today; the corpus doesn't exercise them.
> - **§C2a** ✅ (this commit) — RarVM filter-declaration parser
>   + standard filter set
>   ([`vm`](../src/decode/rar_legacy/vm.rs)). Three submodules:
>   [`vm::membits`](../src/decode/rar_legacy/vm/membits.rs)
>   (memory-only MSB-first bit reader + `next_rarvm_number`
>   2-bit-tag width codec, libarchive lines 3596..3622);
>   [`vm::parse`](../src/decode/rar_legacy/vm/parse.rs)
>   (`read_filter_declaration_bytes` for the on-wire (flags +
>   length-extension + bytecode) triple, mirroring libarchive's
>   `read_filter` at lines 3641..3688; `FilterStack` + `Program`
>   types holding the per-declaration program cache; and
>   `parse_filter_declaration` for the bytecode-internal
>   parameter parse mirroring libarchive's `parse_filter` at
>   lines 3258..3397, including XOR-checksum validation, optional
>   static-data section, and the register-mask / global-data flag
>   bits);
>   [`vm::standard`](../src/decode/rar_legacy/vm/standard.rs)
>   (the five WinRAR standard filter programs — DELTA / E8 /
>   E8E9 / RGB / AUDIO — recognised by libarchive's
>   `crc32(bytecode) | (length << 32)` fingerprint shortcut at
>   lines 3876..3891, plus native executors mirroring
>   `execute_filter_*` at lines 3690..3870). Note: §C0's
>   sub-phasing block mentioned "itanium" — that's an RAR5-era
>   standard filter handled by
>   [`rar_native::filters`](../src/decode/rar_native/filters.rs);
>   the five WinRAR RAR3 standard filters are
>   DELTA / E8 / E8E9 / RGB / AUDIO per libarchive's
>   `execute_filter` switch.
> - **§C2b** ✅ (this commit) — live filter-pipeline wiring
>   through
>   [`entry::decode_entry`](../src/decode/rar_legacy/entry.rs)
>   for the four standard filter kinds the corpus exercises
>   (DELTA / E8 / RGB / AUDIO).
>   [`vm::dispatch`](../src/decode/rar_legacy/vm/dispatch.rs):
>   `apply_pending_filters_in_place(stack, buffer)` walks the
>   FIFO pending queue, copies each filter's
>   `[block_start, block_start + block_length)` slice through
>   the matching native executor, and writes the filtered bytes
>   back over the LZ output in place. Custom (non-standard)
>   bytecode surfaces `DispatchError::UnsupportedCustomFilter`
>   with the program's CRC fingerprint + length —
>   `docs/PLAN_rar3.md` §C2-extension owns the future VM
>   interpreter for that path, gated on a clean-room reference
>   becoming available.
>   [`entry::decode_lz_entry`](../src/decode/rar_legacy/entry.rs)
>   moved from "single-block, no filter" to
>   "multi-block + filter-decl handling":
>   `BlockEnd::NextBlock` and `BlockEnd::EntryDone` are now
>   both treated as "this block done; re-parse the next
>   prologue and continue if `output.len() < unpacked_size`"
>   (matching libarchive's `start_new_table`-and-`parse_codes`
>   pattern); `BlockEnd::FilterDecl` reads the inline
>   declaration off the bit stream and queues it on the
>   filter stack, continuing the same block. Filter
>   application runs at entry end. Corpus: four self-encoded
>   pure-LZ archives at `tests/fixtures/rar_legacy/filter_*.rar`
>   (one per standard filter type, see the fixtures README for
>   the `rar 3.93 -m5 -mcT- -mcX+` recipe under Docker
>   `linux/amd64`). All four decode byte-identical to
>   `rar 7.22`'s reference extraction.
>   Audio-filter bug found + fixed: libarchive's
>   `state.count++ & 0x1F` is post-increment, so the weight
>   update fires at samples 0/32/64/…; our initial pre-
>   increment off-by-one fired at 32/64/… and the audio
>   fixture drifted progressively through the predictor's
>   adaptive weights. Fixed at
>   [`vm/standard.rs:audio fire-flag`](../src/decode/rar_legacy/vm/standard.rs).
> - **§C2c** ✅ (this commit) — fuzz harness for the §C2a
>   parser + §C2b dispatcher at
>   [`fuzz/fuzz_targets/rar_legacy_filter.rs`](../fuzz/fuzz_targets/rar_legacy_filter.rs).
>   Two selector branches: pure parse (drive the wire-side
>   reader + parse-side bytecode decoder over fuzzer-supplied
>   bytes) and parse+dispatch (also run the standard-filter
>   executors over a capped 4 KiB output buffer, exercising
>   the dispatcher's `BlockBeyondOutput` /
>   `UnsupportedCustomFilter` / executor-parameter-validation
>   branches). Approved per
>   `docs/ENGINEERING_STANDARDS.md` §5.2 ("Fuzz tests"); the
>   `rar_legacy_filter` target is the third format-parser fuzz
>   target alongside `zip_format` and `tar_sink`.
>   Custom-bytecode VM interpreter (the original §C2b
>   sketch's "interpreter for archive-supplied bytecode")
>   moves to a post-§C2 follow-on, **§C2-extension**: gated
>   on a clean-room reference becoming available (unrar is
>   off-limits per `AGENTS.md`; libarchive's RAR3
>   implementation doesn't ship one — it stops at the
>   fingerprint-match shortcut). Today's dispatcher rejects
>   custom bytecode with a precise error.

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

#### §C1e₁. Per-symbol LZ dispatcher ✅ (this commit)

**Sub-split decision** (resolved during §C1e implementation):
the original §C1 sketch put "LZ block dispatcher (m=1..m=3),
differential round-trip against the ssokolow corpus + curated
single-entry m=3 archives" all in one commit. The dispatcher
itself is large (~370 LOC + ~530 LOC of tests) and worth
shipping with its own demo (synthetic-fixture tests covering
every main-code branch). Real-archive cross-check needs a
fixture-vendor step (commit small CC0 archives from
ssokolow/rar-test-files into `tests/fixtures/rar_legacy/`)
plus a streaming-entry driver that knows how to find the
compressed payload inside a legacy archive — that lives in
§C1e₂.

**What landed**: per-symbol dispatch at
[`src/decode/rar_legacy/lzss.rs`](../src/decode/rar_legacy/lzss.rs).
Port of libarchive's `expand` function (lines 2906..3132 of
`archive_read_support_format_rar.c`) — the six-branch main-code
dispatch loop with the six constant tables inlined as Rust
`const [u32; N]`:

- Symbols `0..=255` — literal byte. `Dict::push_literal`.
- Symbol `256` — block end. Read 1-bit `new_file` flag; return
  `BlockEnd::NextBlock` if cleared (another block follows in
  this entry) or `BlockEnd::EntryDone` if set
  (libarchive's `start_new_table = 1`).
- Symbol `257` — filter declaration. Return
  `BlockEnd::FilterDecl`; §C2 reads the filter program in.
- Symbol `258` — repeat last `(offset, length)`. Skipped
  silently if no prior match has been emitted in this entry
  (libarchive's `if (lastlength == 0) continue`).
- Symbols `259..=262` — cached-distance: `DistCache::touch`
  + length-code decode + `Dict::copy_match`.
- Symbols `263..=270` — short-distance match (fixed length 2):
  `SHORT_BASES[i] + 1` + `SHORT_BITS[i]` extra bits;
  `DistCache::push` the new offset.
- Symbols `271..=298` — full match: length from
  `LENGTH_BASES[symbol-271] + 3` + extras, offset from the
  offset code (`OFFSET_BASES` + `OFFSET_BITS`), with the
  large-distance low-offset code + 15-repeat sentinel path for
  offset symbols ≥ 10. Distance-above-`0x2000` / -`0x40000`
  length bumps applied.

**Public surface** (consumed by §C1e₂ / §C1h):

- `LzDecoder::new(dict_capacity) -> Result<Self, DictError>`.
- `LzDecoder::decode_block(reader, tables, out) ->
  Result<BlockEnd, LzError>` — runs the dispatcher until a
  block-terminating symbol.
- `LzDecoder::output_position() -> u64`,
  `LzDecoder::dict() -> &Dict` — diagnostic accessors.
- `BlockEnd { NextBlock, EntryDone, FilterDecl }`.
- `LzError { Underrun, Huffman, Dict, InvalidSymbol }` — the
  four classes of malformed-bitstream / dispatcher-error
  surfaces.

**What turned out NOT to need landing**:

- **No per-symbol step API.** The original sketch considered
  a `decode_one_symbol` for finer control (e.g. byte-budget
  enforcement, profiling-friendly tracing). The §C1e₁ posture
  is "run the tight loop until block end" — the dispatcher's
  hot path stays inside one function, no per-symbol callout.
  If §F1's resume needs finer granularity, add it then.
- **No filter-application logic.** Symbol 257 surfaces as
  `BlockEnd::FilterDecl` and the dispatcher exits; reading
  the filter's bytecode + applying the filter is §C2's job.
  The dispatcher does not advance the bit cursor past the
  symbol-257 codeword — the next call into §C2's filter
  reader picks up exactly where §C1e₁ left off.
- **No special handling of `unp_size` truncation.** Libarchive
  exits the dispatch loop when `lzss_position(&lzss) >= *end`
  (i.e. the entry's reported uncompressed size has been
  emitted). §C1e₁'s caller is responsible for that — the
  dispatcher just decodes whatever the bitstream tells it
  until a block-terminating symbol. §C1e₂ wraps this with an
  output-size guard.

**Tests**: 13 unit tests, all with synthetic in-test fixtures
(canonical-code helper + MSB-first packer; no real-archive
bytes yet — those land with §C1e₂).

- Literal run + block-end with new_file=1 → entry done.
- Block-end with new_file=0 → `NextBlock`.
- Filter-decl exit.
- Short-distance symbol 263 (distance 1, length 2).
- Short-distance symbol 264 (distance 5 from `SHORT_BASES[1]
  + extras = 0`).
- Cached-distance symbol 259 touching slot 0 after a prior
  short-distance push.
- Repeat-last symbol 258 after an emitted match.
- Symbol 258 at block start (no prior match) → skipped
  silently.
- Full-match symbol 271 small distance, no length bumps.
- Full-match symbol 271 with offset symbol 26 → distance 8193
  → `0x2000` length bump applies (len = 3 + 1 = 4).
- Full-match with low-offset code symbol 16 (repeat
  sentinel) — exercises the `num_low_offset_repeats = 15`
  path and the subsequent repeat consumption.
- Truncated bitstream surfaces typed `Underrun` (via the
  inner Huffman decode).
- Malformed back-reference (distance before any literal
  emitted) surfaces typed `Dict(BackReferenceUnderflow)`.

**1598 lib tests pass total** (was 1585 at §C1d, +13 from
§C1e₁).

**Demo**: `cargo test --features rar decode::rar_legacy::lzss`
runs all 13 tests in <10 ms release. The full LZ stack — from
raw bits to emitted output — now round-trips synthetic
fixtures cleanly.

#### §C1e₂. Corpus inspection (plan-doc revision) ✅ (this commit)

**What landed**: this sub-section + the routing decision below.
No code changes; the §C1e₁ dispatcher's synthetic-fixture
coverage stands as the LZ path's primary validation.

**Finding**. The §C0 plan locked the corpus strategy as "CC0
archives from [ssokolow/rar-test-files](https://github.com/ssokolow/rar-test-files)
+ bundled `unrar` as reference-decoder side". When §C1e₂
started, the first step was to inspect each candidate archive
to confirm which compression path it would exercise. The
result was uniform: every compressed entry in the ssokolow
corpus is PPMd, not LZ.

- `testfile.rar3.rar` (98 B) — `testfile.txt` entry's first
  compressed-data byte is `0xA7 = 0b1010_0111`; first bit
  (MSB) = 1 = `is_ppmd_block`.
- `testfile.rar3.solid.rar` (98 B) — same.
- `testfile.rar3.av.rar` (327 B) — same.
- `testfile.rar3.rr.rar` (666 B) — same.
- `testfile.rar3.locked.rar` (98 B) — same.
- `testfile.rar3.cbr` (381 B) — both `testfile.jpg` and
  `testfile.png` entries first byte `0xE7 = 0b1110_0111`,
  bit 1 = `is_ppmd_block`.

This is consistent with the WinRAR encoder's normal behaviour:
`-m5` (maximum compression) lets it pick PPMd over LZSS for
short text and already-entropy-rich payloads (the ssokolow
archives' `testfile.txt` is 12 bytes; `testfile.jpg` is a
220-byte JPEG; `testfile.png` is 87 bytes of pre-compressed
PNG).

**Routing decision**. The real-archive cross-check moves to
§C1g (PPMd entry path). At that point the ssokolow corpus is
the natural validation target — every entry decodes through
the PPMd path, and the bundled `unrar` at
`~/Downloads/rar/unrar` produces the expected plaintext.

§C1e₁'s synthetic-fixture coverage remains the LZ path's
primary validation until a real LZ-mode RAR3 archive surfaces
(filed as a §G concern; the corpus shape we can actually
acquire today is what the encoder chose to emit, and that's
PPMd). Building a synthetic RAR3-LZ archive in test code
(precode + main-length encoder + Huffman packer wrapped in
the archive container) is filed as a candidate for §G's
fuzz-seed work — it doesn't add over-and-above value to
§C1e₁'s direct LZ-stack tests today.

**What didn't change**: no source files, no lib test count.
1598 lib tests still pass; this is a plan-doc-only commit.

#### §C1f. RAR-variant range coder ✅ (this commit)

**What landed**: the RAR variant of the PPMd range coder at
[`src/decode/ppmd2/range_dec.rs`](../src/decode/ppmd2/range_dec.rs).
Round-one §B0 landed the 7z variant; §B2 noted "swap in a
RAR-variant range coder when the legacy pipeline needs it"
as deferred to Phase C. §C1f cashes that note in.

Mirrors libarchive's `archive_ppmd7.c` (lines 750..862),
where both variants are implemented side-by-side:

- `Ppmd_RangeDec_Init` — common init that reads 4 BE bytes
  into `Code`.
- `Ppmd7z_RangeDec_Init` (7z) — reads one extra byte (the
  leading marker, must be `0x00`) before calling common init.
- `PpmdRAR_RangeDec_Init` (RAR) — calls common init, then sets
  `Bottom = 0x8000`.
- `Range_Decode_7z` — `Code -= start * Range`.
- `Range_Decode_RAR` — `Low += start * Range`.
- `Range_Normalize` — single function, parametrised by
  `Bottom`. In 7z mode (`Low = 0, Bottom = 0`) the carry check
  `(Low ^ Low+Range) >= TOP_VALUE` reduces to `Range >=
  TOP_VALUE`; in RAR mode the carry check is real and the
  `Range < Bottom` underflow-recovery branch becomes
  reachable.
- `Range_DecodeBit_7z` — dedicated `(range >> 14) * prob`
  binary primitive; the 7z model's binary contexts go
  through this.
- `Range_DecodeBit_RAR` — `get_threshold(PPMD_BIN_SCALE) +
  decode(0, prob)` / `decode(prob, PPMD_BIN_SCALE - prob)`;
  the n-ary primitive does the work, not a dedicated fast
  path. The 7z encoder's binary symbol is NOT compatible
  with the RAR decoder's binary primitive and vice versa.

**Public surface changes**:

- `RangeCoderVariant { Sevenz, Rar }` enum.
- `RangeDecoder::new_rar(src) -> Result<Self, _>` constructor.
- `RangeDecoder::variant() -> RangeCoderVariant` accessor.
- `decode_bit_ppmd7` **renamed** to `decode_bit_bin` (internal
  variant branch). Same applies to the test-only
  `RangeEncoder::encode_bit_ppmd7` → `encode_bit_bin`.
- `RangeDecoder` gains `low: u32` and `bottom: u32` fields
  (always 0 in 7z mode; `low` accumulates and `bottom =
  0x8000` in RAR mode).
- `get_threshold` returns `(code.wrapping_sub(low)) / range`
  (in 7z mode `low = 0` so this is unchanged).
- `decode` branches on variant: `code -= start * range` (7z)
  vs `low += start * range` (RAR).
- `normalize` adopts the unified libarchive carry-handling
  loop; the 7z behavior is preserved exactly (the underflow-
  recovery branch is unreachable when `bottom = 0`).

**Model-layer call-site changes**: `decode_bit_bin` /
`encode_bit_bin` rename at 3 sites in
[`src/decode/ppmd2/model.rs`](../src/decode/ppmd2/model.rs)
(one decode, two encode). No semantic change for the 7z
variant; the model becomes variant-agnostic — the range
decoder's internal `variant` field drives the binary-primitive
dispatch.

**What turned out NOT to need landing**:

- **No RAR-variant test encoder.** §C1f's validation is via
  init / structural tests and the existing §B 7z round-trip
  + differential-corpus tests (which still pass unchanged
  across the rename). Functional cross-check of the RAR-
  variant decode loop is via real archives in §C1g — the
  ssokolow corpus's `is_ppmd_block = 1` payloads exercise the
  RAR-variant math end-to-end. Writing a RAR-variant test
  encoder (porting LZMA SDK's `Range_EncodeBit_RAR` plus the
  carry-handling renormalize) is deferred until a concrete
  test need shows up; the §B PPMd model layer already
  rigorously exercises every code path on the 7z side, and
  the variant branch is small enough that real-archive
  validation in §C1g is the right next checkpoint.
- **No `decode_bit_ppmd7` compatibility alias.** The rename is
  hard; the method only existed since §B3 and only had two
  external callers (in this crate). Clean rename keeps the
  naming honest about what the primitive does.

**Tests**: 5 new tests at
[`src/decode/ppmd2/range_dec.rs`](../src/decode/ppmd2/range_dec.rs):

- `new_rar_reads_four_bytes_with_no_marker` — init prefix
  shape; `variant() == Rar`; `bottom == 0x8000`;
  `code = BE(first 4 bytes)`.
- `new_rar_rejects_truncated_init` — `src.len() < 4` surfaces
  `Truncated` (4-byte prefix label).
- `new_rar_does_not_check_leading_byte` — `BadLeader` is
  7z-only; RAR accepts any first byte as code-seed material.
- `rar_decode_updates_low_not_code` — shape test confirming
  the `decode` variant branch was taken (low advanced).
- `rar_decode_smoke_tests_normalize_loop` — drives 40 n-ary
  decodes against zero-padded input, exercising the unified
  normalize loop without expecting specific values (full
  functional cross-check defers to §C1g).

The pre-existing §B0 / §B1 / §B2 / §B3 7z tests all pass
unchanged: 60+ ppmd2 module tests including the 50-vector
differential corpus and the 33 model edge-case tests.

**1603 lib tests pass total** (was 1598 at §C1e₂, +5 from
§C1f's RAR-init / structural tests).

**Demo**: `cargo test --features rar decode::ppmd2` runs all
75 ppmd2 module tests in <1 s release. The range decoder is
now wired for both 7z and RAR; §C1g plumbs the legacy LZ
pipeline's PPMd-mode entries through a `RangeDecoder::new_rar
→ Model::decode_symbol` chain.

#### §C1g. PPMd entry path ✅ (863ea77)

**What landed**: the per-entry PPMd dispatcher at
[`src/decode/rar_legacy/ppmd_entry.rs`](../src/decode/rar_legacy/ppmd_entry.rs).
`PpmdSession` owns the per-entry state — an `Option<Model>`
(allocated on the first `restart = true` prologue), a
`Dict` sized from the file header's declared dictionary
capacity, and the current `ppmd_escape` byte. Implements
libarchive's `read_data_compressed` (lines 2158..2238)
dispatch loop:

- `sym != ppmd_escape` — literal byte; `Dict::push_literal`.
- `sym == ppmd_escape` — read a sub-code:
  - `code 0` — new table. Returns `BlockEnd::NewTable`; the
    §C1h multi-block driver re-parses a prologue.
  - `code 2` — EOD marker. Returns `BlockEnd::EndOfData`.
  - `code 3` — filter declaration. Returns
    `Err(UnsupportedFilter)` until §C2 lands.
  - `code 4` — large LZ match: 3-byte BE offset + 1-byte
    length. `Dict::copy_match(offset + 2, length + 32)`.
  - `code 5` — short LZ match: 1-byte length.
    `Dict::copy_match(1, length + 4)`.
  - other `code` — escape-of-escape literal (`ppmd_escape`
    byte itself).

`Model::set_init_esc` accessor added so the
prologue-driven `init_esc` byte seeds the model's escape-
probability state before the first symbol decode.

**Public surface**:

- `PpmdSession::new(dict_capacity)`.
- `PpmdSession::apply_prologue(&BlockPrologue)` — branches
  on `restart`: allocates a fresh model when `true`; errors
  with `NoPriorContext` when `false` and no prior context
  exists; seeds `ppmd_escape` from `init_esc` or defaults to
  `2`.
- `PpmdSession::decode_block(&mut RangeDecoder, &mut Vec<u8>,
  unpacked_size: u64) -> Result<PpmdBlockEnd, _>` — runs the
  dispatch loop until `output_position >= unpacked_size` or a
  block-terminating escape.
- `PpmdBlockEnd::{SizeReached, NewTable, EndOfData}`.
- `PpmdEntryError::{Range, Model, ModelInit, Dict,
  NoPriorContext, RestartPayloadMissing, UnsupportedFilter}`.
- `DEFAULT_PPMD_ESCAPE = 2` constant (matches libarchive
  line 2344).

**First end-to-end demo**:
[`tests/test_rar_legacy_ppmd.rs`](../tests/test_rar_legacy_ppmd.rs)
decodes two real CC0 archives from
[ssokolow/rar-test-files](https://github.com/ssokolow/rar-test-files)
through the full stack:

1. `crate::rar::legacy::walk_archive` — header parse (§A2).
2. `crate::decode::rar_legacy::bits::BitReader` over the
   entry's compressed payload (§C1a).
3. `crate::decode::rar_legacy::block_header::parse_block_prologue`
   — `is_ppmd_block = 1` recognised; `ppmd_flags` /
   `dictionary_size` / `max_order` / `init_esc` returned
   (§C1c).
4. `crate::decode::ppmd2::range_dec::RangeDecoder::new_rar`
   over the post-prologue byte-aligned tail (§C1f).
5. `PpmdSession::apply_prologue` + `decode_block` — emits
   12 bytes of `"Testing 123\n"` per entry.

Both `testfile.rar3.rar` (non-solid, 128 KiB dict) and
`testfile.rar3.solid.rar` (solid, 1 MiB dict) cross-check
byte-perfectly against the expected plaintext from the
bundled `unrar` (RAR 7.22 at `~/Downloads/rar/unrar`).

**What turned out NOT to need landing**:

- **No shared `Dict` between LZ and PPMd within an entry.**
  Libarchive shares one LZSS window across LZ and PPMd
  blocks within a single entry (e.g. "code 0 → new table"
  can transition modes). The ssokolow corpus has one PPMd
  block per entry, so `PpmdSession` owns its own dict and
  doesn't share with `LzDecoder`. The cross-mode case is
  filed for §C1h's multi-block driver, which will refactor
  to a shared owner when a real archive surfaces that
  needs it.
- **No `Model::restart()` between RAR-mode blocks.** The
  RAR-variant range coder is re-initialised every block via
  `RangeDecoder::new_rar` against the next 4 bytes
  (libarchive's `PpmdRAR_RangeDec_Init` is called per
  block), but the PPMd MODEL state carries over when
  `restart = false`. `apply_prologue` matches this by NOT
  calling `model.restart()` in the `restart = false` path.
- **No CRC32 verification yet.** The file header carries a
  CRC32 of the unpacked content; checking it lives at the
  pipeline integration boundary (which lands in §C1h or
  the rar_pipeline plumbing).

**Tests**: 8 unit tests in `ppmd_entry.rs` covering the
session lifecycle (uninitialised state, zero-cap rejection,
restart + init_esc plumbing, no-prior-context errors,
missing-payload errors, no-restart-after-restart escape-byte
update) + 4 integration tests in
[`tests/test_rar_legacy_ppmd.rs`](../tests/test_rar_legacy_ppmd.rs)
exercising the real-corpus decode + metadata-walk checks.

**1611 lib tests + 4 integration tests pass** (was 1603 lib
tests at §C1f, +8 from §C1g's `ppmd_entry` unit tests; the
4 new integration tests live in their own binary and aren't
counted in the lib total).

**Demo**: `cargo test --features rar test_rar_legacy_ppmd`
decodes both ssokolow fixtures end-to-end in <100 ms.

**Files added / modified**:

- `src/decode/ppmd2/model.rs` — new `Model::set_init_esc`
  setter.
- `src/decode/rar_legacy/ppmd_entry.rs` (new) — the dispatcher.
- `src/decode/rar_legacy.rs` — wired in `pub mod ppmd_entry`.
- `tests/fixtures/rar_legacy/testfile.rar3.rar` (new, CC0,
  98 bytes).
- `tests/fixtures/rar_legacy/testfile.rar3.solid.rar` (new,
  CC0, 98 bytes).
- `tests/fixtures/rar_legacy/testfile.rar3.txt` (new, 12
  bytes — expected plaintext).
- `tests/fixtures/rar_legacy/README.md` (new — CC0
  attribution + corpus posture).
- `tests/test_rar_legacy_ppmd.rs` (new — the integration
  test).

#### §C1h. Per-entry front-door + multi-entry decode ✅ (this commit)

**What landed**: per-entry decoder API at
[`src/decode/rar_legacy/entry.rs`](../src/decode/rar_legacy/entry.rs)
that wraps STORED / LZ-mode / PPMd-mode dispatch behind one
function. The §C1g integration test refactors to use it; the
ssokolow `testfile.rar3.cbr` (multi-entry, both PPMd) gets a
new cross-check that decodes both `testfile.jpg` (220 B JPEG)
and `testfile.png` (87 B PNG) byte-perfectly through the
front-door.

**Public surface**:

- `decode_entry(archive_bytes: &[u8], entry: &LegacyFileEntry)
  -> Result<Vec<u8>, LegacyEntryError>` — dispatches:
  - `method == 0x30` (STORED) → byte copy.
  - `method ∈ 0x31..=0x35` (compressed) → parse the first
    block prologue; route to `LzDecoder` or `PpmdSession`;
    decode through one block; truncate to `unpacked_size`.
  - `method` outside the above → `UnsupportedMethod`.
- `LegacyEntryError` with 11 variants covering wire-level
  faults, dispatcher faults, and the explicit
  "not-yet-supported" cases the corpus doesn't exercise:
  - `BlockHeader`, `Ppmd`, `Lz`, `Dict`, `Range` — wrapped
    sub-decoder faults.
  - `DataAreaOverrun` — `data_offset + packed_size >
    archive.len()`.
  - `DirectoryEntry` — directory marker (the file-flags
    dict-size selector reads as `0b111`).
  - `UnsupportedMethod { method }` — method byte outside the
    `0x30..=0x35` range.
  - `PostPrologueUnaligned` — post-prologue cursor not on a
    byte boundary (programmer error in §C1c).
  - `MultiBlockNotSupported` — encoder emits a block
    continuation (LZ `NextBlock` or PPMd `NewTable`) the
    round-one corpus doesn't exercise.
  - `CrossModeNotSupported` — LZ↔PPMd block transition
    within an entry (needs shared dict; §G follow-on).
  - `SizeShortfall` — decoded fewer bytes than the header
    declared.
  - `UnsupportedFilter` — LZ `BlockEnd::FilterDecl` from the
    block dispatcher (defers to §C2).

**Multi-entry support**: the §C1g test changed from a hand-
rolled per-entry decode helper to a generic `decode_all_entries`
loop using `decode_entry`. The ssokolow cbr — 2 entries, both
PPMd-mode with 128 KiB dicts — decodes both `testfile.jpg`
(220 B) and `testfile.png` (87 B) to byte-identical output
matching the bundled `unrar`'s extraction. The decoder uses
the per-entry `data_offset` + `packed_size` from the §A2
walker; non-solid means each entry is independently decodable.

**What turned out NOT to need landing** (vs. the original
§C1h sketch):

- **No cross-entry shared state for solid archives.** The
  ssokolow `testfile.rar3.solid.rar` fixture has only one
  entry, so non-solid logic decodes it correctly. Multi-
  entry solid archives need cross-entry dict + PPMd-model
  carry-over, but we don't have such a fixture in the
  corpus today. Filed as a §G follow-on alongside synthetic
  LZ-mode archive generation. The walker (§A2) already
  surfaces the `MHD_SOLID` flag in `LegacyArchiveSummary`,
  so the integration step is wiring (not new decoder code).
- **No multi-block-within-entry loop.** The block-end
  outcomes that surface for continuation (`BlockEnd::NextBlock`
  / `PpmdBlockEnd::NewTable`) are translated to
  `LegacyEntryError::MultiBlockNotSupported` rather than
  parsing a follow-on prologue. The §C1d `Dict` and §C1g
  `PpmdSession` both carry per-call state correctly, so
  wiring this is a loop refactor when a multi-block fixture
  surfaces.
- **No CRC32 verification.** The file header carries
  `file_crc32`; comparing it against a running CRC32 over
  decoded bytes is the natural pipeline-integration step.
  Today's integration tests assert against expected-byte
  fixtures, which is a stronger check than CRC32 anyway —
  CRC32 verification gets added when the `rar_pipeline`
  plumbing routes through `decode_entry`.

**Tests**: 3 new lib-tests in
[`src/decode/rar_legacy/entry.rs`](../src/decode/rar_legacy/entry.rs)
(round-trip via the front-door, data-area-overrun on a
truncated slice, method-byte rejection) + 2 new
integration tests in
[`tests/test_rar_legacy_ppmd.rs`](../tests/test_rar_legacy_ppmd.rs)
(cbr multi-entry decode + cbr-not-solid metadata check).
The §C1g integration tests refactor to use `decode_entry`;
all 6 now go through the same front-door.

**1614 lib tests + 6 integration tests pass** (was 1611 lib +
4 integration at §C1g; +3 lib + 2 integration from §C1h).

**Demo**: `cargo test --features rar test_rar_legacy_ppmd`
runs all 6 integration tests (3 single-entry + 1 multi-entry
+ 2 metadata) in <100 ms.

**Files added / modified**:

- `src/decode/rar_legacy/entry.rs` (new) — `decode_entry` +
  `LegacyEntryError`.
- `src/decode/rar_legacy.rs` — wired in `pub mod entry`.
- `tests/fixtures/rar_legacy/testfile.rar3.cbr` (new, CC0,
  381 bytes — non-solid 2-entry archive).
- `tests/fixtures/rar_legacy/testfile.cbr.jpg` (new, CC0,
  220 bytes — expected JPEG output).
- `tests/fixtures/rar_legacy/testfile.cbr.png` (new, CC0,
  87 bytes — expected PNG output).
- `tests/fixtures/rar_legacy/README.md` — extended with the
  cbr entry.
- `tests/test_rar_legacy_ppmd.rs` — refactored to use
  `decode_entry`; +2 new tests for cbr.

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

#### §C2a. Filter-declaration parser + standard filter set ✅ (this commit)

**What landed**: the [`vm`](../src/decode/rar_legacy/vm.rs)
sub-module tree under `src/decode/rar_legacy/`. Three submodules
mirroring the layout libarchive's
`archive_read_support_format_rar.c` carries out:

1. [`vm::membits`](../src/decode/rar_legacy/vm/membits.rs) —
   memory-only MSB-first bit reader (`MemBitReader`) over a
   borrowed byte slice with soft-fail underrun (sticky `at_eof`
   flag; reads past end-of-buffer return 0 rather than erroring,
   matching libarchive's `membr_bits` at line 3617). The
   `next_rarvm_number` codec at libarchive lines 3596..3614
   decodes the 2-bit-tag width-encoded integer the bytecode-
   internal stream uses for register values, block start
   offsets, block lengths, program lengths, and global-data
   lengths.
2. [`vm::parse`](../src/decode/rar_legacy/vm/parse.rs) —
   `read_filter_declaration_bytes` reads the on-wire
   `(flags, length-extension, bytecode)` triple straight off the
   outer [`bits::BitReader`](../src/decode/rar_legacy/bits.rs)
   (libarchive's `read_filter` at lines 3641..3688), with
   precise underrun / zero-length / over-cap diagnostics.
   `FilterStack` + `Program` + `ProgramClassification` types
   hold the per-archive program cache (libarchive's
   `struct rar_filters`'s `progs` linked list +
   `lastfilternum`, minus the pending-invocation queue and
   `filterstart` that §C2b will add). `parse_filter_declaration`
   interprets the bytecode payload against the stack
   (libarchive's `parse_filter` at lines 3258..3397), handles
   the eight flag bits (program-cache index, block-start +258
   bias, explicit block length, register-mask + overrides,
   embedded program bytecode with XOR-checksum validation +
   optional static-data section, global-data section), and
   returns a `FilterDeclaration` for §C2b's dispatcher.
3. [`vm::standard`](../src/decode/rar_legacy/vm/standard.rs) —
   the five WinRAR standard filter programs
   (DELTA / E8 / E8E9 / RGB / AUDIO) recognised by libarchive's
   `crc32(bytecode) | (length << 32)` fingerprint shortcut
   (libarchive's `execute_filter` switch at lines 3876..3891).
   The five fingerprint constants are taken verbatim from
   libarchive; the native executors (`execute_delta`,
   `execute_e8`, `execute_rgb`, `execute_audio`) mirror
   `execute_filter_*` at lines 3690..3870, with explicit
   parameter bounds checks (zero-channel rejection, E8 block-
   too-short, RGB stride/byte-offset/block-length bounds, buffer
   length agreement). The CRC-32/ISO-HDLC implementation is
   local (1 KiB const table) to keep `rar_legacy` self-contained
   per §C0's sibling-module posture; there's an existing
   `crc32` at
   [`xz_liblzma::stream`](../src/decode/xz_liblzma/stream.rs)
   but the duplication preserves the format-tree boundary.

**Reuse-vs-fork note (carried forward from §C0)**: the standard
filter set has a near-cousin in
[`rar_native::filters`](../src/decode/rar_native/filters.rs)
(DELTA / E8 / E8E9 / ARM for RAR5). The two formats share
algorithm names but the per-format math differs — DELTA in RAR3
writes to a separate destination buffer where RAR5 deinterleaves
in place; RAR3's E8 uses
`address < 0 ? address + filesize : address - currpos` where
RAR5 uses a sign-flip predicate; RAR3 ships RGB / AUDIO that
RAR5 doesn't, and RAR5 ships ARM that RAR3 doesn't. Sharing
code would just hide the divergence; the modules stay sibling
forks.

**Corpus note**: §C2a does **not** wire the parser through
[`entry::decode_entry`](../src/decode/rar_legacy/entry.rs).
The §C1e₂ corpus inspection established that every entry in the
ssokolow round-one corpus is PPMd-mode (`is_ppmd_block = 1`),
and the bundled `rar 7.22` no longer creates legacy archives.
Filter-using fixtures therefore have to be sourced separately,
and lighting the wire on the live decode path before we have one
to round-trip against would be untestable. §C2b sources a
filter-using corpus first (likely from RARLAB's public test
archives, per §C0's corpus strategy), then lands both the live
LZ → VM → filtered-output dispatcher and the custom-bytecode
interpreter at once. §C2a's deliverable is the parser surface
(testable in isolation) plus the standard-filter executors
(round-trip-testable with synthetic input).

**§C2a deliberately is NOT**:

- No live wiring through `entry::decode_entry`. The LZ
  dispatcher still returns `BlockEnd::FilterDecl` and the entry
  layer still surfaces `LegacyEntryError::UnsupportedFilter` —
  one variant pinned by the single-`UnsupportedFilter` test in
  [`entry.rs`](../src/decode/rar_legacy/entry.rs).
- No VM bytecode interpreter for custom programs. §C2b. The
  parser correctly classifies a non-standard program as
  `ProgramClassification::Custom`, but invoking such a program
  has no implementation yet.
- No pending-filter queue / filterstart tracking on
  `FilterStack`. §C2b's deliverable, since both are dispatcher
  state.

**Tests**: 43 new unit tests across
[`vm/membits.rs`](../src/decode/rar_legacy/vm/membits.rs) (12 —
bit-read MSB-first across byte boundaries, full 32-bit reads,
`new_at` offset, soft-fail underrun stickiness,
`next_rarvm_number` tag-0/1/2/3 cases, tag-1 negative-bias path,
tag-1 large branch, underrun propagation),
[`vm/parse.rs`](../src/decode/rar_legacy/vm/parse.rs) (11 —
wire-side `read_filter_declaration_bytes` for the 3-byte / 1-byte
/ 2-byte length-extension cases, zero-length rejection,
bitstream-underrun propagation, parse-side full new-program
happy path, XOR mismatch, program-length zero, program-index
past cache, num=0 cache clear, last-filter-num reuse path,
+258 block-start bias), and
[`vm/standard.rs`](../src/decode/rar_legacy/vm/standard.rs) (20 —
CRC-32 known vectors, fingerprint packing, recognition for each
of the five known + unknown fingerprints, DELTA single- /
multi-channel round-trips, all four executors' rejection paths
for zero channels / buffer-length mismatch / E8-too-short /
RGB-bad-params, E8 + E8E9 absolute-to-relative rewrite,
post-rewrite payload skip, RGB / AUDIO zero-source identity).
All 43 pass; full suite stays at 1657 green
(`cargo test --features rar --lib`).

**Demo**: `cargo test --features rar --lib decode::rar_legacy::vm`
runs the 43-test vm sub-suite. `cargo clippy --features rar
--all-targets -- -D warnings` is clean. The next sub-phase
(§C2b) extends `FilterStack` with the pending-invocation queue
+ `filterstart`, lands the VM interpreter for custom bytecode,
and wires the live dispatcher through `entry::decode_entry`.

#### §C2b. Live filter-pipeline wiring + standard filter dispatch ✅ (this commit)

**What landed**:

1. [`vm::dispatch`](../src/decode/rar_legacy/vm/dispatch.rs) —
   new submodule.
   `apply_pending_filters_in_place(stack, buffer)` walks the
   filter stack's FIFO pending queue, copies each filter's
   `[block_start, block_start + block_length)` slice from the
   LZ output buffer through the matching native executor in
   [`vm::standard`](../src/decode/rar_legacy/vm/standard.rs),
   and writes filtered bytes back over the slice. For DELTA /
   RGB / AUDIO (which libarchive's `execute_filter_*` runs
   into a separate destination half of VM memory), we allocate
   a transient `Vec<u8>` per filter; for E8 / E8E9 (in-place
   transforms) we pass the buffer slice directly. `DispatchError`
   covers `BlockBeyondOutput` (range past `buffer.len()`),
   `UnsupportedCustomFilter` (program isn't one of the five
   standard fingerprints), and `Executor(FilterExecError)`
   (parameter validation: zero channels, E8 block-too-short,
   RGB bad params).
2. [`vm::parse::FilterStack`](../src/decode/rar_legacy/vm/parse.rs)
   gained a `pending: Vec<FilterDeclaration>` field;
   `parse_filter_declaration` now both returns the decoded
   `FilterDeclaration` *and* pushes a clone onto
   `stack.pending`, matching libarchive's `parse_filter` queue
   append at lines 3388..3394. `FilterStack::clear` also drains
   the pending queue alongside the program cache.
3. [`entry::decode_lz_entry`](../src/decode/rar_legacy/entry.rs)
   re-shaped from "single-block, no filter" to
   "multi-block + filter-decl driver":
   - `BlockEnd::EntryDone` and `BlockEnd::NextBlock` are now
     treated identically as "block done; if `output.len() <
     unpacked_size`, re-parse the next prologue and continue".
     This matches libarchive's `start_new_table`-and-
     `parse_codes` pattern (lines 2918..2935) where the
     bit-after-symbol-256 only controls *when* the next
     prologue's tables get loaded.
   - `BlockEnd::FilterDecl` calls
     [`read_filter_declaration_bytes`](../src/decode/rar_legacy/vm/parse.rs)
     to consume the flags + length-extension + bytecode payload
     off the same LZ bit stream, then
     [`parse_filter_declaration`](../src/decode/rar_legacy/vm/parse.rs)
     to enqueue the invocation. The LZ block continues with the
     next symbol after the inline payload.
   - At entry end, `apply_pending_filters_in_place` runs every
     queued filter against the LZ output before truncating to
     `unpacked_size`.
   - `BlockEnd::EntryDone` / `NextBlock` landing on a PPMd
     prologue still surfaces `CrossModeNotSupported` (the
     hybrid LZ-decl + PPMd-data shape that `rar 3.93 -m5`
     emits when PPMd is enabled is documented in the fixtures
     README and deferred — the §C2b corpus avoids it via
     `-mcT-`).
4. New error variants: `LegacyEntryError::FilterParse` (wraps
   `VmParseError`) and `LegacyEntryError::FilterDispatch`
   (wraps `DispatchError`). The old `UnsupportedFilter`
   variant + its single test in
   [`entry.rs`](../src/decode/rar_legacy/entry.rs) are removed
   — they're unreachable now that the dispatcher handles every
   filter declaration the corpus produces.

**Audio-executor bug found + fixed**: integration testing
caught a drift in [`vm/standard.rs`'s
`execute_audio`](../src/decode/rar_legacy/vm/standard.rs).
libarchive's
`if (!(state.count++ & 0x1F))` (line 3846) is **post-
increment**: the check evaluates `count & 0x1F` *before*
bumping, so the weight-update path fires on samples
0 / 32 / 64 / … within each channel. Our initial pre-
increment shape fired on 32 / 64 / 96 / … and the audio
filter's adaptive weights diverged progressively across the
sample stream. Fixed by capturing `let fire = state.count &
0x1F == 0` before the `state.count += 1` bump.

**Corpus**: four pure-LZ + single-filter fixtures committed
to [`tests/fixtures/rar_legacy/filter_*.rar`](../tests/fixtures/rar_legacy/),
each paired with the synthetic input the encoder consumed
(`filter_*.bin`):

- `filter_e8.rar` (264 B) + `filter_e8.bin` (512 B) — E8
  filter, synthetic PE/x86 binary with `0xE8`/`0xE9`
  instructions.
- `filter_rgb.rar` (405 B) + `filter_rgb.bin` (270 B) — RGB
  filter, 12×6 24-bpp BMP with per-channel gradient.
- `filter_audio.rar` (885 B) + `filter_audio.bin` (556 B) —
  AUDIO filter, 128-sample stereo PCM sine wave.
- `filter_delta.rar` (153 B) + `filter_delta.bin` (512 B) —
  DELTA filter, 32 records × 4 LE-u32 fields.
- `filter_multi.rar` (397 B) + `filter_multi.bin` (4096 B) —
  synthetic 4 KiB PE/x86 binary that the encoder's auto-mode
  heuristic splits into **three filter declarations** in a
  single LZ block: E8 (new program 0, `flags=0xA6`, len 256
  @ start 0), DELTA (new program 1, `flags=0xB6` with
  register-mask, len 3584 @ start 256), and an E8 reuse of
  program 0 (`flags=0xC2`, `+258` block-start bias,
  implicit-len from `old_filter_length`). Exercises FIFO
  drain across multiple filters, the `flags & 0x10`
  register-mask path, the `flags & 0x40` block-start bias
  path, and the `!(flags & 0x20)` implicit-length /
  program-cache reuse path — none of which the
  single-filter fixtures hit. `rar 3.93` and `rar 5.0.0`
  emit byte-identical archives for this input at the same
  switches.

The encode recipe (Docker `linux/amd64` + `rar 3.93` +
`-m5 -mcT- -mcX+`) is documented in
[`tests/fixtures/rar_legacy/README.md`](../tests/fixtures/rar_legacy/README.md).
`rar 3.93` is the last RARLAB public release whose Linux
x86_64 binary is still readily available; later 4.x / 5.x /
6.x versions also support `-ma3` (RAR3 format) but `rar 3.93`
suffices for round-one coverage. The fifth WinRAR standard
filter (E8E9 — same algorithm as E8 plus matching `0xE9`)
isn't exercised in the live corpus because `rar 3.93`'s
encoder picks pure-E8 for x86 inputs; the `execute_e8`
executor takes an `e9_also: bool` parameter and the
E8E9 codepath is covered by the synthetic unit tests in
[`vm/standard.rs`](../src/decode/rar_legacy/vm/standard.rs).

**What §C2b deliberately is NOT**:

- No VM interpreter for archive-supplied (non-standard)
  bytecode. The §C2-extension follow-on (see below) owns
  that, gated on a clean-room reference becoming available.
  libarchive's RAR3 implementation stops at the
  fingerprint-match shortcut and rejects custom programs
  with `"No support for RAR VM program filter"`; our
  `UnsupportedCustomFilter` dispatch error mirrors that.
- No PPMd / LZ cross-mode within an entry. The hybrid shape
  `rar 3.93 -m5` produces (LZ block declaring filter +
  PPMd block carrying data) requires a shared dict between
  the two decoders. Deferred to §G.

**Tests**: 5 new integration tests at
[`tests/test_rar_legacy_filters.rs`](../tests/test_rar_legacy_filters.rs):
one per single-filter fixture (E8 / RGB / AUDIO / DELTA) plus
the multi-filter fixture above; each `decode_entry`'s the
corresponding fixture and asserts byte-identical output.
5 new lib-test entries in `vm/dispatch.rs` (range-check
rejection, custom-bytecode rejection, in-place E8,
separate-buffer DELTA, multi-filter FIFO drain). Full
lib-test count grows from 1657 to 1662; integration-test
files grow from 1 to 2; integration test count for
`rar_legacy` grows from 6 to 11.

**Demo**: `cargo test --features rar --test test_rar_legacy_filters`
runs the 4 filter-corpus tests against the four standard-
filter executors, all green. `cargo clippy --features rar
--all-targets -- -D warnings` is clean.

#### §C2c. Parser fuzz harness ✅ (this commit)

**What landed**: new fuzz target at
[`fuzz/fuzz_targets/rar_legacy_filter.rs`](../fuzz/fuzz_targets/rar_legacy_filter.rs).
Two selector branches:

1. **Pure parse** — drive
   [`read_filter_declaration_bytes`](../src/decode/rar_legacy/vm/parse.rs)
   on fuzzer-supplied bytes; on success, push the result
   through
   [`parse_filter_declaration`](../src/decode/rar_legacy/vm/parse.rs)
   against a fresh `FilterStack`. Exercises the bit reader's
   underrun handling, the bytecode `next_rarvm_number`
   decoder, the XOR-checksum check, and every flag-bit branch
   of the parser.
2. **Parse + dispatch** — also runs
   [`apply_pending_filters_in_place`](../src/decode/rar_legacy/vm/dispatch.rs)
   over a capped 4 KiB output buffer. Exercises the
   dispatcher's range-check, the standard-filter-vs-custom
   classification, and the native executors' parameter
   validation (zero channels, RGB bad params, E8 too short).

Invariant: **no panics, no out-of-bounds accesses**. Every
malformed declaration must surface a typed error or be
silently skipped. `[[bin]]` entry added to
[`fuzz/Cargo.toml`](../fuzz/Cargo.toml); the `rar` feature
is now enabled on the fuzz crate's `peel-rs` dep so the
target compiles. Approved per
`docs/ENGINEERING_STANDARDS.md` §5.2; this is the third
format-parser fuzz target alongside `zip_format` and
`tar_sink`.

**Demo**: `cd fuzz && cargo check --bin rar_legacy_filter`
builds the target. A 5-minute fuzz run is the standing
acceptance criterion (`cargo +nightly fuzz run
rar_legacy_filter -- -max_total_time=300`) — left to the
maintainer to invoke ad-hoc per `AGENTS.md` §Fuzzing.

#### §C2-extension. Custom-bytecode VM interpreter (post-MVP follow-on)

**Why deferred**: the original §C2b sketch called for a full
VM interpreter for archive-supplied (non-standard) bytecode.
Implementing one cleanly requires a reference for the
RarVM's opcode set + instruction-encoding wire format; the
two reference sources available are:

- **unrar** — off-limits per `AGENTS.md` §Approved
  References. The RarVM opcode tables in `rarvm.cpp` are
  the canonical source.
- **libarchive** — only ships the fingerprint-match
  shortcut (line 3878..3891 of
  `archive_read_support_format_rar.c`), not a generic
  interpreter. Custom bytecode hits `"No support for RAR VM
  program filter"` at line 3889.

In practice the standard-filter shortcut handles every
archive WinRAR's encoder produces (libarchive ships
production decoders on this basis), so the missing
interpreter only matters for adversarial archives or
unusual encoder configurations. Today the §C2b dispatcher
rejects custom bytecode with `UnsupportedCustomFilter`
carrying the program's CRC fingerprint + length, matching
libarchive's posture exactly. The §C2-extension follow-on
lands when a clean-room reference becomes available; until
then the §C2c fuzz target validates that custom-bytecode
rejection is panic-free.

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

### §E1. `StreamingDecoder` wiring + format-mismatch path ✅ (this commit)

**What landed**: new
[`RarLegacyStreamDecoder`](../src/decode/rar_legacy/stream.rs)
adapter implementing
[`crate::decode::StreamingDecoder`](../src/decode.rs). The §A2b
pipeline ([`run_legacy`](../src/download/rar_pipeline.rs)) now
dispatches compressed entries (`m=1..=5`, on-disk method bytes
`0x31..=0x35`) through this adapter; STORED entries
(`method == 0x30`) stay on the existing byte-copy fast path.

**Shape**.

1. Per-entry record (`LegacyEntryRecord` in
   [`src/download/rar_pipeline.rs`](../src/download/rar_pipeline.rs))
   carries `method` + `dict_capacity`; the per-entry loop branches
   on `method == 0x30` to pick STORED vs. the new
   [`extract_legacy_compressed_entry`](../src/download/rar_pipeline.rs)
   path.
2. [`decode_payload`](../src/decode/rar_legacy/entry.rs) is the
   new public helper inside `entry.rs` that takes the dispatch
   primitives `(compressed, method, dict_capacity,
   unpacked_size)` directly so the stream decoder doesn't need
   to thread a `LegacyFileEntry` through (it operates on bytes
   pulled from a `Read` source, not on an archive slice).
3. Round-one buffers the entry's full `packed_size` into memory
   before constructing the decoder (mirrors the zip / 7z / RAR5
   §E1 posture). The first
   [`StreamingDecoder::decode_step`](../src/decode.rs) call
   pulls the source, runs `decode_payload`, and stages the
   decoded `Vec<u8>`; subsequent calls drain it to the sink in
   64 KiB chunks. `decoder_state` returns `None` and
   `frame_boundary` returns `None` — Phase F (§F1) adds the
   snapshot blob.
4. `archive::walk_archive` already returned a populated
   `LegacyArchiveSummary` with the solid-mode flag from §A2;
   §E1 carries that flag through the pipeline event stream
   unchanged.

**Tests**:

- Unit tests in
  [`src/decode/rar_legacy/stream.rs`](../src/decode/rar_legacy/stream.rs)
  cover the PPMd-mode `testfile.rar3.rar` corpus entry, the
  LZ + E8 standard-filter `filter_e8.rar` corpus entry, the
  `bytes_consumed` / `set_source_start_offset` contract, the
  cap rejections, and the source short-read path.
- Integration test
  `round_trip_compressed_legacy_archive_with_e8_filter` in
  [`tests/test_coordinator_rar3.rs`](../tests/test_coordinator_rar3.rs)
  drives `filter_e8.rar` end-to-end through the mock-server +
  ranged-download + sparse-file pipeline and asserts
  byte-identical output against the curated `.bin` reference.
- The pre-§E1 `rejects_compressed_legacy_archive_with_specific_diagnostic`
  test was replaced by two follow-ons: a positive coordinator
  test exercises the decoder dispatch, and
  `malformed_compressed_legacy_payload_surfaces_decoder_diagnostic`
  guards the precise-error contract on malformed payloads
  (`"legacy RAR decode failed"` surfaces through the
  CoordinatorError chain). `rejects_legacy_archive_with_unknown_method_byte`
  keeps walker-level coverage for method bytes outside
  `0x30..=0x35`.
- Wider differential round-trip across the full corpus is
  blocked on building out the corpus itself (the existing
  fixtures cover the standard-filter set); fold-in lands as
  follow-on fixture work rather than a §E1 blocker.

**Demo**: `cargo test --features rar
--test test_coordinator_rar3 round_trip_compressed_legacy_archive_with_e8_filter`
extracts a compressed legacy archive via the mock-server
pipeline and byte-compares against the reference plaintext.

---

## Phase F — Resume

### §F1. Mid-entry checkpoint blob (legacy) ✅ (this commit)

**What landed**: `RarLegacyStreamDecoder` now exposes a
deterministic snapshot blob so a `kill -9` mid-compressed-entry
resumes byte-identical. The §E1 buffer-then-stream shape made
this much smaller than the §F1 plan originally sketched: because
[`decode_payload`](../src/decode/rar_legacy/entry.rs) is
deterministic in `(compressed, method, dict_capacity,
unpacked_size)`, the snapshot only needs to record the per-entry
header fields plus `decoded_pos` (how many output bytes had been
emitted at the snapshot moment). On resume,
[`RarLegacyStreamDecoder::resume`](../src/decode/rar_legacy/stream.rs)
re-runs the synchronous decode against the same compressed
payload — yielding the same `decoded` buffer — and skips ahead
to the saved `decoded_pos` before emitting the suffix.

The sketch's "snapshot the PPMd suballocator" / "replay from the
previous block" options drop out of consideration entirely: the
round-one decoder already re-runs end-to-end on every entry, so
the cheap thing is to reuse that determinism and keep the
snapshot tiny (49 bytes fixed). When Phase G lifts the
buffer-then-stream into a block-by-block driver
(`O.RAR.STREAMING_DECOMPRESS`), §F1's wire layout will need to
extend — at that point we revisit option (a) vs (b) with real
performance numbers.

**Shape**.

1. New module-private `SNAPSHOT_MAGIC` (`b"RR3S"`) +
   `SNAPSHOT_VERSION` (1) tag the blob so a stray RAR5 snapshot
   (`b"RR5S"`) can't be mis-routed into the legacy resume path.
2. [`RarLegacyStreamDecoder::serialize_into`](../src/decode/rar_legacy/stream.rs)
   writes a 49-byte fixed-layout blob: magic + version +
   `src_start_offset` + `packed_size` + `unpacked_size` + `method` +
   `dict_capacity` + `decoded_pos`.
   [`Self::resume`](../src/decode/rar_legacy/stream.rs) is the
   inverse — it cross-checks every per-entry field against the
   caller's file-header values and refuses on any disagreement,
   then drives `buffer_and_decode()` and seeks to the saved
   `decoded_pos`.
3. `StreamingDecoder::decoder_state_into` returns `true` only
   between drain steps (after `buffer_and_decode()` has run and
   before `eof_emitted` latches); `frame_boundary` becomes
   `Some(src_start_offset + packed_size)` over the same window.
   `source_cursor_from_blob` always reports `0` — the resuming
   decoder needs the full entry payload to rebuild the decoded
   buffer, not a tail-only slice. The pipeline's
   `compressed.split_off(0)` slicing handles that as a no-op.
4. [`Checkpoint::FORMAT_VERSION`](../src/checkpoint.rs) stays at
   v11. The §E1 RAR5 path already cut the
   `current_entry_decoder_state` slot in `SinkState::Rar`; the
   legacy blob just rides the same opaque-byte channel. The §F1
   plan asked for a fresh format-version bump but the checkpoint
   layer treats the blob as opaque bytes, and the leading magic
   already disambiguates legacy vs RAR5 snapshots, so the v11
   bump suffices for both.
5. [`extract_legacy_compressed_entry`](../src/download/rar_pipeline.rs)
   grew `resume_offset` + `resume_decoder_state` parameters and a
   dispatch on `resume_decoder_state.is_some() && resume_offset
   > 0` to pick `begin_entry_resume` vs `begin_entry`. The
   per-entry decoder construction also branches: with a blob it
   goes through `RarLegacyStreamDecoder::resume`; without one it
   stays on `RarLegacyStreamDecoder::new`. The `run_legacy`
   dispatcher mirrors the §F1 RAR5 dispatch shape, including the
   "blob is only honoured for the current_entry" guard.

**Tests**:

- 19 unit tests in
  [`src/decode/rar_legacy/stream.rs`](../src/decode/rar_legacy/stream.rs)
  cover the snapshot/resume contract. The headline test is
  `synthetic_blob_resume_round_trips_at_every_decoded_pos` which
  builds a snapshot blob for every `decoded_pos` in
  `0..filter_e8.bin.len()` (512 boundaries) and verifies the
  prefix + resumed suffix equals the reference plaintext byte
  for byte. The unit-test approach side-steps the in-tree
  fixture limitation: every legacy fixture decodes to ≤4 KiB,
  which is below the streaming adapter's 64 KiB drain chunk, so
  the live `decode_step` loop never exposes a mid-drain snapshot
  through the public `decoder_state` path. Going through a
  hand-built blob lets us cover the same code paths the live
  decoder would hit at larger fixture sizes. Companion tests
  exercise: header-field mismatch rejections (method,
  `dict_capacity`, `packed_size`, `decoded_pos` past
  `unpacked_size`), magic / version / truncation diagnostics,
  the `source_cursor_from_blob` zero contract, and serialize →
  resume → serialize round-trip lossless-ness.
- [`tests/test_coordinator_rar3.rs::crash_resume_mid_entry_produces_identical_output`](../tests/test_coordinator_rar3.rs)
  drives a 4 MiB single-entry STORED legacy archive through the
  full coordinator pipeline. STORED goes through
  `extract_legacy_entry` (not the §F1 snapshot path) but the
  test pins the `entries_completed` / `current_entry_offset`
  checkpoint machinery for legacy archives across the §E1 / §F1
  pipeline reshuffle.
- [`tests/test_coordinator_rar3.rs::crash_resume_mid_compressed_entry_produces_identical_output`](../tests/test_coordinator_rar3.rs)
  is the headline §F1 end-to-end crash-resume. Uses the new
  Goldilocks fixture
  [`large_lz_normal.rar`](../tests/fixtures/rar_legacy/large_lz_normal.rar)
  (256 KiB decoded, ~800 B compressed, `rar 5.0.0 -ma4 -m3`).
  Decoded size exceeds the streaming adapter's
  `STREAM_CHUNK_BYTES` so the live `decode_step` loop takes
  multiple drain steps and the tight `checkpoint_min_bytes = 1`
  config lands a mid-entry `CheckpointWritten` well before EOF.
  See
  [`docs/fixtures/rar_legacy_large_lz_normal.md`](fixtures/rar_legacy_large_lz_normal.md)
  for the re-encode recipe.

**Demo**: `cargo test --features rar --lib
decode::rar_legacy::stream` exercises the snapshot/resume
contract end-to-end (20 unit tests including the Goldilocks
fixture round-trip); `cargo test --features rar --test
test_coordinator_rar3 crash_resume_mid_compressed_entry_produces_identical_output`
drives the legacy compressed crash-resume through the full
coordinator pipeline.

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
