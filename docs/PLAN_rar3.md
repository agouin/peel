## Plan: legacy RAR (RAR3 / RAR4) archive support

> **Status: drafted 2026-05-10, partially landed.** §0 resolved
> 2026-05-10. **§A1 landed (commit 6c96328).** **§A2a landed (commit
> 38ff665)** — signature dispatch + sibling archive walker. §A2b
> (pipeline integration) is the next checkpoint. This plan resolves
> follow-on `O.RAR4` from `docs/PLAN_rar.md`. It is a sibling
> sub-plan to `docs/PLAN_rar5_decoder.md` — additive to
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

#### §A2b. Pipeline integration (next)

**What**: refactor `crate::download::rar_pipeline` to dispatch on
`SignatureKind` and route legacy archives through a sibling walker
+ STORED extraction path. Per §0.2 the serial-solid driver and the
sparse-file/punch/checkpoint plumbing are shared; the format
delta is in the walker, the per-entry sink expectations
(BLAKE2sp vs. CRC-32-only), and the `SinkState::Rar` checkpoint
shape.

**Sketch**.

1. Replace the pipeline's `parse_signature` call with
   `crate::rar::detect_signature`. Add a `SignatureKind`-keyed
   branch.
2. Generalise `crate::sink::rar::RarSink` so per-entry hashes are
   driven by what the file header actually carries (RAR5: BLAKE2sp +
   optional CRC-32; legacy: CRC-32 only — no BLAKE2sp slot in
   FILE_HEAD). The cleanest factoring is an `EntryHashSpec` enum
   the walker hands the sink at `begin_entry` time.
3. Reject `method != 0x30` (i.e. anything other than STORED) at
   the legacy dispatch site with `RarError::UnsupportedFeature`
   naming the method byte. `m=0` STORED extraction works
   end-to-end via the existing copy-from-sparse-file path.
4. `Checkpoint::format_version` bumps; `SinkState::Rar` grows a
   discriminator so a resumed legacy extraction does not get
   handed to the RAR5 walker. `PLAN_rar.md` §3 reserved this
   slot.

**Tests**: integration test extracting a curated STORED legacy
archive end-to-end via the mock server. Crash-test parity
(kill mid-entry) for STORED legacy.

**Demo**: `peel http://mock/legacy_stored.rar` produces correct
contents. The `--format rar` override goes through the legacy
walker when the bytes start with the legacy magic.

---

## Phase B — PPMd-II

### §B1. PPMd-II model

**What**: hand-rolled PPMd-II decoder. Lives at
`src/decode/ppmd2/` per §0.4. New crate-internal module.

**Sketch**.

1. Bit-level range coder (PPM uses range coding, not Huffman).
2. Context tree + suffix links. Order-N modelling with escape
   probabilities.
3. State-machine decode loop: `decode_symbol(ctx) -> u8`.
4. Initialisation parameters: order, sub-allocator size, restart
   policy. Legacy RAR sets all three at the start of each
   `m=4`/`m=5` block.

**Reference.** libarchive's `archive_read_support_format_rar.c`
PPMd code, plus Shkarin's original PPMd-II paper. `7zip`'s
`PPMd7Decoder.c` is closely related and is the cleaner read.

**Tests**: differential — encode a small payload with `rar a -m5`,
decode with our PPMd, byte-compare. ~50 fixture vectors.

**Demo**: `cargo test decode::ppmd2` passes including a corpus of
~50 reference vectors.

---

## Phase C — Legacy LZ + RarVM

### §C1. Sliding window + Huffman tables

**What**: bitstream + dictionary + Huffman dispatcher specific to
legacy 2.9+. Lives at `src/decode/rar_legacy/`.

**Notes vs. RAR5.**

- Same bitstream contract — re-use `decode::rar_native::bits` if it
  is generic enough, otherwise lift it. (Likely a sibling copy:
  legacy uses MSB-first too but with different alignment rules at
  block boundaries.)
- Different code-length tables: 4 trees per block (literals,
  distances, lower-distance bits, repeat-codes) vs. RAR5's 3.
- Distance cache (`oldDist`) is 4-deep, same as RAR5.

**Tests**: differential against `rar a -m3` archives, ≤ 1 MiB.

**Demo**: `cargo test decode::rar_legacy::lzss` passes for at least
one curated single-entry m=3 archive.

---

### §C2. RarVM interpreter (with custom-filter support)

**What**: bytecode VM for archive-defined filter programs. Lives
at `src/decode/rar_legacy/vm.rs`.

**Sketch**.

1. Decode the standard filter set (e8/e9/itanium/rgb/audio/delta)
   plus the `VM_STANDARD_FILTERS` shortcuts the encoder uses to
   compress them.
2. Compile archive-supplied bytecode to an internal opcode list at
   filter-registration time; interpret per-block.
3. Strict bounds-checking on every memory reference (the
   real-world VM has been the source of half a dozen unrar CVEs;
   our interpreter must reject out-of-range memory access without
   relying on UB or aborts).

**Tests**: a curated corpus of archives that exercise the standard
filters plus at least three real-world archives that ship custom
filter programs (we will need to find and commit these — the
`rarlab` test suite is a starting point).

**Demo**: `cargo test decode::rar_legacy::vm` passes including
filter-program differential cases.

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
