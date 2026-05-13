## Plan: RAR archive support

> **Status: drafted 2026-05-04, not yet started.** This plan adds a
> sixth archive format alongside the streaming formats (zstd, gzip,
> xz, lz4), the identity tar pass-through, and the ZIP pipeline. It
> follows the same sequencing discipline as `PLAN.md` and `PLAN_v2.md`:
> each phase ends with a runnable demo, and §N+1 does not begin until
> §N's demo passes. Promotion to active work requires deliberate human
> review of the §0 decisions below — do not start §1 until those are
> resolved.

RAR is qualitatively different from every format `peel` supports
today. The header layout is friendly to streaming, but the archive's
two most common real-world uses — **solid mode** (multiple files share
one compression context) and **multi-volume** (the bytestream is split
across separate URLs, e.g. `archive.part01.rar` … `archive.partNN.rar`)
— each break a different load-bearing assumption in the existing
pipeline. The plan below confronts those head-on rather than burying
them.

It also makes a **dependency call** that is the largest deviation from
`ENGINEERING_STANDARDS.md` §2 in the project's history: there is no
acceptable pure-Rust RAR5 decompressor today, and hand-rolling one is
multi-month work in dense PPMd-II + LZSS + filter-bytecode territory.
The plan treats round-one as a "framing layer + vetted decoder
dependency" pairing, mirroring the precedent set by `xz2` (round one
via crate, round two via `PLAN_xz_block_decoder.md` hand-roll). That
pairing has explicit gates — see §0.

---

## Hard constraints (carried forward)

- Std-first; allowlist-only. The new RAR decoder dependency is **not**
  approved at the time of writing — see §0.1.
- No async runtime. RAR's pipeline reuses the same `IoBackend` trait,
  blocking-IO worker pool, and bounded channels every other format
  uses.
- Linux-first; macOS works via the existing `MacosPuncher`. No new OS
  surface.
- Backwards-compatible checkpoints. The new `RarState` field bumps
  `Checkpoint::format_version` and provides a clean rejection path for
  older readers (per `PLAN.md` §9.2).
- Hand-rolled wire-format parsing. The header layer (archive header,
  per-file headers, end-of-archive marker, multi-volume linkage) is
  hand-rolled in the same shape as `src/zip/format.rs` and
  `src/sink/tar.rs`. Only the *decompression* step delegates to a
  dependency, and only in round one.

## What this plan deliberately does not include

- **RAR4** (legacy, pre-2013). The RAR4 format and its compression
  methods are wholly different from RAR5; supporting both doubles the
  scope without doubling the value (the corpus has been migrating to
  RAR5 for over a decade). Round-one targets RAR5 only. RAR4 archives
  return a clear `RarError::UnsupportedFormatVersion { major, minor }`
  rather than a generic parse failure. RAR4 support is filed as a
  follow-on — see "Filed follow-ons" at the bottom.
- **Encryption** (header encryption and per-file encryption). Out of
  scope for round one. Encountering an encrypted archive returns
  `RarError::UnsupportedFeature { feature: "encryption" }`.
- **Multi-volume archives.** Out of scope for round one; encountering
  one returns `RarError::UnsupportedFeature { feature: "multi-volume" }`
  with a hint pointing at the follow-on tracking issue. The header
  parser does decode the multi-volume flags so the diagnostic can name
  the part number it saw.
- **Recovery records (Reed-Solomon).** Skipped silently if present —
  we don't need them to decompress, and validating them is a separate
  feature filed as a follow-on.
- **Self-extracting archives (SFX).** RAR archives wrapped in an
  executable prefix: out of scope for round one. The magic-byte
  detector in §1 *does not* scan past offset 0 looking for the
  signature; SFX users need `--format rar` or a non-SFX archive.
- **Compression methods other than RAR5's standard.** RAR5 has one
  standard method (called "the RAR algorithm" in the format spec —
  it's a custom LZSS variant with optional PPMd-II contexts and
  e8/e9/itanium/rgb/audio/delta filters). Method 0 (STORED) is
  trivially supported as a passthrough. Round-one supports method 0
  and the standard RAR5 algorithm; nothing else.

---

## §0. Decisions to resolve before §1 begins

This section is the audit trail for the five gating decisions. **None
of §1 may begin until these are resolved and the resolutions are
recorded inline below.**

> **§0 resolved 2026-05-09.** All five decisions resolved by the
> project owner. Resolutions recorded inline at the end of each
> sub-section in a `**Resolution.**` block. The headline change vs.
> the provisional resolutions: §0.1 lands on Option 3 (hand-roll), not
> Option 1 (`unrar` crate). §4's scope grows accordingly and is
> spun out into its own `PLAN_rar5_decoder.md` sub-plan (see §4).
> §0.2–§0.5 land as drafted, with §0.5's rationale updated since the
> licensing pressure evaporated alongside §0.1.

### §0.1 Decompressor dependency

**Question.** Round-one RAR5 decompression: vetted FFI dependency, or
hand-roll?

**Options considered.**

1. **`unrar` crate (FFI to RARLAB's unrar source).** The de facto
   reference. Wraps the unrar source distributed by RARLAB.
   - **License.** "unRAR license": free to use for decompression;
     forbids using the source to create a RAR-compatible
     *compressor*. `peel` is decompression-only, so the substantive
     restriction does not bind us. The license is **not OSI-approved**
     and is **not GPL-compatible**; this is the most consequential
     point — `peel` has no upstream license declaration of its own
     today, but a future relicense to GPL would have to drop this
     dependency. Documenting the constraint in the README and
     `ENGINEERING_STANDARDS.md` is a hard prerequisite, not a
     nice-to-have.
   - **Build.** Compiles the unrar C++ source via `cc`; adds a C++
     toolchain to the build prereqs (we already have a C toolchain
     for `xz2` / `flate2 (rust_backend = false)` / etc., but C++ is
     net-new).
   - **API shape.** Exposes a `OpenArchive` / `read_header` / `process`
     loop that maps cleanly onto `StreamingDecoder::decode_step`. The
     tricky bit is that the upstream library wants a `Read + Seek`
     source for some operations (specifically the multi-volume
     transition); we restrict to single-volume in round one which
     sidesteps that.
   - **Maturity.** Crate downloads moderate; upstream RARLAB source is
     under continuous maintenance.

2. **Pure-Rust crates** (`unrar_rs`, `unrar-rust`, etc., as found on
   crates.io 2026-05). All examined are incomplete reimplementations
   covering RAR4 partially, RAR5 minimally or not at all, and not
   actively maintained. **Not viable for round one.**

3. **Hand-roll the RAR5 decoder.** ~5000–8000 LOC of dense LZSS +
   PPMd-II + filter-bytecode interpretation. Comparable in scope to
   `PLAN_zstd_block_decoder.md` (which delivered hand-rolled zstd in
   ten phases) but materially harder because the format spec is
   author-provided (not an IETF RFC) and several details are
   under-specified. Realistic effort: 2–4 months of focused work.

**Provisional resolution (to be confirmed before §1).** Option 1
(`unrar` crate) for round one, **conditional on**:

- Explicit human approval to add `unrar` (and its transitive `cc`
  build-dep) to `ENGINEERING_STANDARDS.md` §2.2, with a row that
  documents the unRAR-license constraint and names this plan.
- A new follow-on filed in `OPTIMIZATIONS.md` for hand-rolling RAR5,
  modeled on `PLAN_zstd_block_decoder.md`. The follow-on does not
  block round-one shipping; it sets up the round-two replacement
  trajectory the same way `xz2` was eventually displaced.
- A README addendum disclosing the unRAR-license constraint. Users who
  need a fully OSI-licensed binary build it without the `rar` feature
  flag (see §0.5).

**If approval is denied**, the plan reverts to Option 3 (hand-roll)
and grows accordingly. Do not silently swap to Option 2 — the
pure-Rust crates examined are not adequate.

**Resolution (2026-05-09).** Option 3: hand-roll RAR5. The unRAR
license restriction (non-OSI, GPL-incompatible) was rejected as a
permanent dependency on a project licensed `MIT OR Apache-2.0`. The
hand-roll cost (~5000–8000 LOC, 2–4 months of focused work modeled on
`PLAN_zstd_block_decoder.md`) is accepted as the price of staying
fully OSI. Concrete consequences:

- No new runtime dependency lands for RAR support. `Cargo.toml` is
  unchanged for §1–§3.
- §4's sketch (built around an `unrar` wrapper) is invalidated. §4
  is spun out into a new sibling sub-plan
  `internal/PLAN_rar5_decoder.md` modeled on
  `PLAN_zstd_block_decoder.md` and `PLAN_xz_block_decoder.md` —
  multi-phase, each phase with its own demo, with the same
  differential-test discipline (encode fixtures with a known-correct
  external reference at `[dev-dependencies]`-only scope, decode with
  ours, byte-compare).
- §1+§2+§3 ship the hand-rolled framing layer, BLAKE2sp, and
  STORED-method extraction without waiting on the §4 sub-plan.
- The `O.RAR.HANDROLL` follow-on listed at the bottom of this plan
  is no longer a follow-on — it *is* §4. The follow-ons list is
  updated accordingly when §5 lands.

### §0.2 Solid-mode policy

**Question.** Solid-mode RAR archives compress all files together as
one continuous bytestream. To decompress file N you must have
decompressed files 0..N first. This is fundamentally incompatible with
the per-entry parallelism the ZIP pipeline (`src/download/zip_pipeline.rs`)
uses. What does round-one do when it encounters one?

**Options considered.**

1. **Refuse with `UnsupportedFeature`.** Cleanest rule, smallest
   round-one diff. The user has to extract solid archives with `unrar`
   or 7z. Unattractive because solid archives are common in the wild
   (default for many RAR producers).
2. **Single-stream sequential mode.** Detect solid mode at archive-open
   time; switch the pipeline from per-entry parallel extraction to a
   single-worker linear read. Slow (no parallelism) but correct, and
   the network download itself is still parallel via the existing
   chunked sparse-file path — only the *decode* step serializes.
3. **Per-file parallelism with redundant decompression.** Decompress
   from the start of the solid block once per worker. Wastes CPU
   linearly with worker count; not worth implementing.

**Provisional resolution.** Option 2. Detect solid mode at archive-open
time; if set, the pipeline serializes the decode step but continues to
parallelize the download. Surface `solid: bool` in the progress UI so
the user understands why CPU stays at one core. This is an additive
mode, not a separate pipeline — the same `RarPipeline` handles both
with a `solid_mode: bool` flag.

**Resolution (2026-05-09).** Locked in as drafted.

### §0.3 Magic-byte detection scope

**Question.** RAR5's magic is `52 61 72 21 1A 07 01 00` at offset 0
(8 bytes). RAR4's magic is `52 61 72 21 1A 07 00` at offset 0 (7
bytes). Self-extracting RAR archives prepend an executable to the
magic. What does the magic-byte detector in `decode::DecoderRegistry`
register?

**Provisional resolution.**

- Register the RAR5 magic at offset 0. RAR5 archives autodetect.
- Do **not** register the RAR4 magic. RAR4 is out of scope; URLs with
  `.rar` suffix that contain RAR4 bytes go through the suffix path,
  hit the factory, and return `RarError::UnsupportedFormatVersion`
  with a clear message. (Registering the RAR4 magic and then
  immediately rejecting it would be worse — the user would see
  "format detected: rar" followed by "format unsupported", which is
  confusing.)
- Do **not** scan past offset 0 for the magic. SFX archives require
  the user to pass `--format rar` (which already exists from
  `PLAN_v2.md` §1).

**Resolution (2026-05-09).** Locked in as drafted.

### §0.4 Multi-volume URL convention

**Question.** Multi-volume is out of scope for round one (see "What
this plan deliberately does not include"). When the user has multi-
volume archives at `archive.part01.rar` … `archive.partNN.rar`, what
should the round-one error say?

**Provisional resolution.** The header parser checks the
`MHD_VOLUME` archive header flag (the bit RAR5 calls
`MHD_FLAGS::VOLUME`). When set, return
`RarError::UnsupportedFeature { feature: "multi-volume archive (volume N of unknown total)" }`,
including the volume number from the `volume_number` field of the
multi-volume extra-header record when present. The CLI surfaces a
follow-on hint: "multi-volume support is filed as a follow-on; for
now, concatenate the volumes locally and pass the result via
`file://` or run `unrar` first." This avoids a generic parse failure
on a feature we deliberately deferred.

**Resolution (2026-05-09).** Locked in as drafted. The CLI hint's
"or run `unrar` first" suggestion stays — that refers to the user's
locally-installed `unrar` binary, not a `peel` runtime dependency.

### §0.5 Build flag for RAR feature

**Question.** Given the unRAR-license constraint (§0.1), users who need
a fully OSI-licensed `peel` build (e.g. for repackaging in a Linux
distro that requires it) must be able to build without the `unrar`
dependency.

**Provisional resolution.** Gate RAR support behind a Cargo feature
flag `rar`, **on by default**. Building with
`--no-default-features` (or `--features <subset>` excluding `rar`)
produces a binary that:

- Does not link `unrar`.
- Does not compile `src/decode/rar.rs` or `src/download/rar_pipeline.rs`.
- Returns `RarError::FeatureDisabled` from the registry factory if a
  RAR archive is encountered (so the user gets a clean error, not a
  decoder-not-found panic).
- Continues to register `.rar` suffix and the RAR5 magic in the
  registry, so the diagnostic is "this build was compiled without RAR
  support; install the standard `peel` build or rebuild with
  `--features rar`" rather than "unknown format".

This mirrors how `flate2` projects expose `rust_backend` vs
`zlib-ng-compat` features, and how Rust distro packagers can opt out
of non-OSI bits without forking.

**Resolution (2026-05-09).** Locked in as drafted, with **rationale
updated**. The original justification (OSI-licensing escape hatch
for the `unrar` dependency) no longer applies — §0.1 resolved to
hand-roll, so the entire RAR module is OSI-clean. The feature flag
is retained for two narrower reasons:

1. **Compile-time opt-out for binary size.** The hand-rolled RAR5
   decoder lands as several thousand LOC of LZSS + PPMd-II + filter
   bytecode. Users who never extract `.rar` archives can shave that
   from their binary by building `--no-default-features` (or
   `--features` excluding `rar`).
2. **Modular gating for the §4 rollout.** The decoder lands in
   phases via `PLAN_rar5_decoder.md`. A feature flag lets the
   incremental landings stay behind a flag if a phase is partial,
   without holding up the rest of the binary.

The error variant name changes from `RarError::FeatureDisabled` to
`RarError::CrateFeatureDisabled` to make clear it's a build-time
opt-out, not a runtime configuration. Diagnostic message becomes:
"this build of `peel` was compiled without the `rar` feature;
rebuild with default features (or `--features rar`) to extract RAR
archives."

---

## Phase A — Format support

### §1. Wire-format scaffolding

**What**: hand-rolled parsers for the RAR5 archive header, generic
header layout, end-of-archive marker, and the per-file header. No
decompression yet. Lives in `src/rar/format.rs`, the same shape as
`src/zip/format.rs`.

**Why first**: the parser is small, self-contained, and validates the
§0 decisions cheaply — solid-mode detection, multi-volume detection,
RAR4 rejection, and unsupported-feature surfacing all live here. We
get to a working "open archive, list entries, refuse the unsupported
ones cleanly" milestone before we touch decompression.

**Sketch**.

1. New `src/rar/` module mirroring `src/zip/`'s layout: `format.rs`
   (parsers), `crc32.rs` (RAR5 actually uses CRC-32 of the IEEE
   polynomial for headers and BLAKE2sp for file data — so this module
   re-exports `crate::zip::crc32::ieee` for headers and gains a
   BLAKE2sp impl in §2), and a top-level `mod.rs` with the pub re-exports.
2. Headers are length-prefixed and have a uniform shape:
   `[size:vint] [type:vint] [flags:vint] [type-specific fields]`. The
   varint encoding (RAR5 calls them "vint") is the standard 7-bit-
   per-byte continuation, max 10 bytes (since the max payload is
   `u64`). Hand-rolled: ~30 LOC.
3. Header types we parse: `MAIN_ARCHIVE_HEADER` (1),
   `FILE_HEADER` (2), `SERVICE_HEADER` (3, skipped), `END_OF_ARCHIVE`
   (5). Encryption header type (4) → `UnsupportedFeature`.
4. Detect and surface: solid-mode flag (in main archive header
   `MHD_SOLID`), multi-volume flag (`MHD_VOLUME`), file-header flags
   (encrypted, version, has-extra-area, splits-before/after, is-dir).
5. The end-of-archive header carries a `EAH_MORE_VOLUMES` flag — when
   set, the archive continues in another volume; in round one, we've
   already failed at the `MHD_VOLUME` check, so this is informational.
6. Tests:
   - Hand-built fixtures: a 3-file non-solid RAR5 archive built with
     `rar a -ma5` (or equivalent), parsed byte-by-byte; assertions
     against expected entry list, sizes, methods.
   - A 3-file *solid* archive (`rar a -ma5 -s`); parser flags solid
     mode but does not refuse.
   - A multi-volume archive (`rar a -ma5 -v100k`); parser returns
     `UnsupportedFeature` naming the volume number.
   - An encrypted archive (`rar a -ma5 -hp`); parser returns
     `UnsupportedFeature { "encryption (header)" }`.
   - A RAR4 archive (truncated to magic only is enough); parser
     returns `UnsupportedFormatVersion { major: 4, minor: 0 }`.
   - Property tests on the vint codec for round-trip and overlong-
     encoding rejection.

**Demo**: a `rar-list` debug binary (or `cargo run --example
rar_list`) that takes a local RAR5 file and prints the entry list,
the solid flag, and any unsupported-feature diagnostic — same shape
as `unzip -l` minus the dates. No decompression involved.

---

### §2. Hash primitives

**What**: hand-roll BLAKE2sp (the RAR5 file-data integrity hash) in
`src/hash/blake2sp.rs`, alongside the existing `sha256.rs`.

**Why now**: RAR5 file integrity uses BLAKE2sp (parallel BLAKE2s, 8
lanes), not CRC-32 like ZIP and not SHA-256 like the `--sha256` flag.
We need it before §3 can validate decompressed entry data. Doing it
now in a separate phase keeps the §3 diff focused on framing +
decompressor wiring.

**Sketch**.

1. `BLAKE2sp` per RFC 7693 §B (BLAKE2sp: parallel BLAKE2s with 8
   lanes, fanout=8, depth=2, leaf_length=0). The eight leaf BLAKE2s
   instances each consume every 8th 64-byte block; the root BLAKE2s
   consumes the leaves' digests. Pure scalar implementation; ~250 LOC.
2. Same shape as `Sha256`: `new()`, `update(&[u8])`, `finalize() ->
   [u8; 32]`. No incremental-resume requirement — RAR5 BLAKE2sp is
   computed once per file entry, and round-one entries are not
   resumable mid-entry (see §4 for why).
3. Tests:
   - The BLAKE2sp test vectors from RFC 7693 §B.
   - Per-byte-boundary chunking-invariance (same shape as the
     `Sha256` tests).
   - Cross-check against a known-correct external reference (the
     `blake2` crate is added as a `dev-dependency` for cross-checking
     only, mirroring the `sha2` precedent in `PLAN_v2.md` §10).

**Demo**: `cargo test hash::blake2sp` passes including the RFC
vectors and the dev-dep cross-check.

---

### §3. STORED method (no compression)

**What**: extract method-0 RAR5 entries — uncompressed, byte-identical
copy from archive bytes to output file. Validates the §1 framing layer
end-to-end without depending on the decompressor (whose approval is
still gated by §0.1).

**Why now**: lets us land most of the pipeline plumbing
(`src/download/rar_pipeline.rs`, `src/sink/rar.rs`, the checkpoint
state field, the CLI integration, the §0.5 feature gate) without
waiting on the decompressor decision. If §0.1 is still under review
when §1+§2+§3 land, we still ship a useful subset (peel can extract
RAR archives that happen to use method 0 — uncommon in the wild but
it exercises the full pipeline).

**Sketch**.

1. New `src/sink/rar.rs`: a per-entry sink with the same path-safety
   rules as `src/sink/tar.rs` (refuse `..` traversal, refuse absolute
   paths, refuse symlinks pointing outside the extraction root).
2. New `src/download/rar_pipeline.rs`: shaped like
   `src/download/zip_pipeline.rs`, but without the central-directory
   trailing-fetch dance — RAR's archive header is at offset 0, so the
   pipeline reads the archive header inline as the download begins.
   The download itself uses the existing chunked sparse-file path;
   the pipeline drives header-by-header advancement through the
   already-downloaded prefix.
3. Per-entry flow for method 0: compute the entry's compressed range
   `[file_data_start, file_data_start + packed_size)` from the file
   header, wait for that range to be downloaded (the priority-steered
   scheduler handles this), then copy the bytes into the sink while
   feeding them through the BLAKE2sp hasher. Compare hash to the
   header's recorded value at end-of-entry; mismatch ⇒
   `RarError::HashMismatch`.
4. Checkpoint format gains `RarState { entries_completed: Vec<u32>,
   current_entry: Option<u32>, current_entry_offset: u64,
   current_entry_blake2sp_state: Option<Blake2spState> }`. The
   `current_entry_*` fields support resume mid-entry for method 0
   (BLAKE2sp's parallel structure makes incremental serialization
   harder than SHA-256's; for round one we serialize the eight leaf
   states and the root state, accepting the larger-than-SHA-256 blob
   size). Bumps `format_version`.
5. CLI integration: same as ZIP — the coordinator detects the
   resolved factory's name matches `crate::rar::FORMAT_NAME` and
   dispatches to `rar_pipeline::run` instead of the streaming-decoder
   loop.
6. Tests: round-trip a 3-file method-0 archive built with
   `rar a -m0`; verify byte-identical output. Crash-test mid-entry
   and verify resume produces byte-identical output.

**Demo**: `peel ./fixture-stored.rar -C ./out` extracts a 3-file
method-0 archive, including hash validation. Crash-test passes.

---

### §4. RAR5 standard compression method

**What**: extract entries compressed with the standard RAR5 algorithm.
This is where the §0.1 decompressor decision lands.

**Sketch (assuming §0.1 resolves to `unrar` crate)**.

1. New `src/decode/rar.rs`: streaming wrapper over `unrar`'s
   archive-iteration API. Same `StreamingDecoder` shape as
   `decode/zstd.rs` (round-one, pre-`zstd_native`): owns the source,
   decompresses one entry's worth of data per `decode_step`, surfaces
   `frame_boundary()` at end-of-entry only.
2. `frame_boundary()` semantics: returns `Some(decompressed_offset)`
   only at end-of-entry. Mid-entry is **not** a restart point in
   round one; resume mid-entry re-decompresses the entry from the
   start. (Acceptable because round-one is non-streaming-prefix —
   the entry's compressed bytes are already downloaded in their
   entirety before decompression begins.) `O.6b`-style per-block
   resume inside the RAR algorithm is filed as a follow-on.
3. Solid-mode wiring: when the archive is solid, the pipeline opens
   one decompressor for the whole archive and feeds it sequentially.
   The single-worker decode constraint from §0.2 lives here.
4. Filter handling: RAR5's standard algorithm includes filters
   (e8/e9/itanium/rgb/audio/delta) that transform decompressed bytes
   for specific data types (executables, PNG/RGB, audio). The `unrar`
   crate handles filters internally; `peel` does not need to
   implement them.
5. CRC / hash checking: every entry's decompressed bytes flow through
   BLAKE2sp; mismatch ⇒ `RarError::HashMismatch`. The crate also
   computes its own CRC; we re-check ours independently because
   crate-provided integrity is not a substitute for our own
   verification path (same discipline as the SHA-256 verify in
   `PLAN_v2.md` §10).
6. Tests:
   - Round-trip 3-file non-solid archive (`rar a -ma5`); byte-
     identical extraction.
   - Round-trip 3-file solid archive (`rar a -ma5 -s`); same.
   - Round-trip a single-entry archive containing a >1 MiB random
     file; verify BLAKE2sp matches.
   - Crash-test against both solid and non-solid fixtures; resume
     produces byte-identical output (re-decompresses the in-progress
     entry from the start).

**Demo**: `peel https://.../release.rar -C ./out` against a real
multi-MB RAR5 archive (a SourceForge or HuggingFace mirror is the
likely test target — RAR5 is still common in older dataset releases
and Windows-source distributions).

---

## Phase B — Polish

### §5. Format-coverage README and matrix update

**What**: update the README's format-support matrix (added in
`PLAN_v2.md` "round one done"), document the `--no-default-features`
build (§0.5), and document the unRAR-license constraint (§0.1).

**Why now**: the format matrix is the user-visible end of every Phase
A landing. Doing it as the last step of the RAR plan keeps the README
in sync with the binary's actual capabilities.

**Sketch**.

1. README: add `.rar` to the format matrix with caveats columns —
   "single-volume only", "non-encrypted only", "RAR5 only".
2. README: a new "License notes" subsection covering the `unrar`
   dependency. The substantive point is that the `peel` source is
   under whatever license the project chooses, but the *default
   binary build* links `unrar` (under the unRAR license, which is
   not OSI-approved); users who need a fully OSI binary build with
   `--no-default-features --features <set without rar>`.
3. `ENGINEERING_STANDARDS.md` §2.2: append the `unrar` row to the
   allowlist with the same notes pattern (`PLAN_rar.md` §0.1).
4. `OPTIMIZATIONS.md`: append the follow-ons listed below.

**Demo**: `cargo build --no-default-features` produces a binary that
extracts every other format and returns `RarError::FeatureDisabled`
on `.rar`; `cargo build` (default features) extracts RAR. Both binary
sizes are recorded in the README for transparency.

---

## What "RAR support done" means

All of the following are true:

1. Each phase's demo has been recorded and reviewed.
2. The crash-test harness has been extended to cover RAR5 in both
   solid and non-solid modes; resumes still produce byte-identical
   output.
3. `OPTIMIZATIONS.md` has been amended with the four follow-ons
   listed below.
4. `ENGINEERING_STANDARDS.md` §2.2 lists `unrar` with the unRAR-license
   note.
5. README format matrix includes `.rar` with the round-one caveats.
6. CI gates remain green; coverage thresholds (80 % overall, 95 % on
   critical paths) hold across the new modules. The §0.5 feature-flag
   variant is built (and its tests run) in a separate CI job.

## Filed follow-ons (added to `OPTIMIZATIONS.md` after this plan lands)

- **`O.RAR.MV`** — multi-volume RAR archives. Requires either a CLI
  affordance for naming the parts (`peel arch.part01.rar
  --rar-volumes 'arch.part??.rar'`) or pattern-matching the URL.
- **`O.RAR.ENC`** — RAR5 header and per-file encryption (AES-256).
  Requires a passphrase-prompt path in the CLI.
- **`O.RAR.SFX`** — self-extracting archives. Detect the RAR5 magic
  past offset 0 by scanning the first N bytes; same logic as
  `find_eocd` in `src/zip/format.rs`.
- **`O.RAR.HANDROLL`** — replace the `unrar` dependency with a
  hand-rolled RAR5 decoder, modeled on `PLAN_zstd_block_decoder.md`
  and `PLAN_xz_block_decoder.md`. Resolves the OSI-licensing concern
  permanently and unlocks per-block resume semantics inside an entry.
- **`O.RAR.RECOVERY`** — Reed-Solomon recovery records. Validate
  when present; offer to repair detected corruption.
- **`O.RAR4`** — RAR4 legacy format support. Lower priority; corpus
  is shrinking.

## Schedule guidance

There is no schedule. Phases are sequenced; do them in order, do each
phase completely. §0 is gating — none of §1+ may begin until all five
§0 decisions are resolved with their resolutions recorded inline.

§3 is the natural "land a partial result if §0.1 is still in review"
checkpoint: §1 + §2 + §3 ship a binary that extracts STORED-method
RAR5 archives without any new dependency. If §0.1 takes longer than
expected to resolve, this subset can land first and the §4 dependency
can be added later without rework.
