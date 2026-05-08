# Plan: 7z archive support

> **Status: drafted 2026-05-04, not yet started.** This is a successor
> plan in the lineage of `PLAN.md` → `PLAN_v2.md` →
> `PLAN_zstd_block_decoder.md` → `PLAN_xz_block_decoder.md`. It promotes
> 7z support — *not* on any prior plan, *not* in `OPTIMIZATIONS.md` —
> deliberately, because the existing format set
> (`tar`/`tar.zst`/`tar.gz`/`tar.xz`/`tar.lz4`/`zip`) leaves a real gap:
> the dominant Windows-world archive format and a non-trivial fraction
> of public-dataset releases. As with prior plans, sequencing is
> mandatory: each phase ends with a runnable demo, and §N+1 does not
> begin until §N's demo passes.

7z is the closest architectural sibling to ZIP among the formats `peel`
already supports — metadata lives at the tail, the streaming pipeline
(`PLAN.md` §10) cannot be used directly, and a separate
"second-pipeline" driver (`PLAN_v2.md` §5) is the right shape. It also
inherits ZIP's "many compression methods, scope what we ship"
discipline.

7z is, however, *not* a clone of ZIP:

- **Solid compression.** A 7z `Folder` groups multiple files into one
  decoded stream — you cannot extract file *k* without first decoding
  files `0..k` in that folder. Hole punching becomes per-folder rather
  than per-entry, and mid-folder resume is fundamentally harder than
  mid-entry resume in ZIP (which round-one defers).
- **Coder chains.** Each Folder declares a chain of coders (LZMA →
  BCJ → ...), with bind pairs wiring outputs to inputs. The full
  graph supports filters and multi-input coders we will not ship in
  round-one.
- **Compressed headers.** The header at the tail is *itself* commonly
  a compressed (single-folder) stream ("EncodedHeader"). Parsing the
  archive metadata requires running the folder decoder on the trailer
  before any data is touched.
- **No formal RFC.** The reference is 7-Zip's `DOC/7zFormat.txt` plus
  the 7-Zip / p7zip source. Hand-rolling per
  `ENGINEERING_STANDARDS.md` §2.1 is the same posture taken for tar
  (`PLAN.md` §7.3) and zip (`PLAN_v2.md` §5).

`peel` already has the LZMA/LZMA2 implementation 7z needs, sitting in
[`src/decode/xz_native/`](../src/decode/xz_native/). 7z's most common
coder chain (`LZMA2` alone or `LZMA` alone, no filters) maps directly
onto that module once the xz framing is peeled off. That reuse is the
keystone that makes round-one tractable.

---

## Hard constraints (carried forward)

- Std-first; vetted crates from the `ENGINEERING_STANDARDS.md` §2
  allowlist only. Round-one introduces **no new dependency** — every
  decoder we need (LZMA, LZMA2, DEFLATE, COPY) is already in tree.
- No async runtime. The 7z pipeline runs on the existing IO thread and
  scheduler (same posture as `download/zip_pipeline.rs`).
- Linux-first. macOS works through the same blocking IO path that
  `PLAN_v2.md` §12 already wired up.
- Hand-rolled wire-format parsers. The 7z header is a tagged
  variable-length structure with several integer encodings (`Number`,
  `BoolVector`, `BitVector`); a nibble-tag-driven parser is small,
  auditable, and matches the precedent for tar / zip.
- Backwards-compatible checkpoints. The phases below add an opaque
  `SinkState::Sevenz { … }` variant to the checkpoint format and bump
  `format_version`. Older readers reject the new version cleanly per
  `checkpoint.rs` §9.2 of `PLAN.md`.

## What round-one deliberately does *not* include

These are filed for `O.32x` follow-ons in `OPTIMIZATIONS.md` once §10
lands. Encountering any of them returns a clean
`SevenzError::UnsupportedFeature` naming the specific feature — the
user sees "BCJ filter not supported" or "AES-256 encryption not
supported", not a generic parse error.

- **Encryption** (coder id `06 F1 07 01`, AES-256 + SHA-256 password
  derivation), and the encrypted-header variant (`Header.Encrypted`).
- **Filters**: BCJ (`03 03 01 03`), BCJ2 (`03 03 01 1B`), Delta
  (`03`), ARM / ARMT / IA64 / SPARC / PPC. Filter chains are a real
  fraction of `.7z` archives in the wild but each is a small encoder
  plus a decoder, and shipping them all in round-one bloats audit
  surface.
- **BZIP2** (id `04 02 02`) and **PPMd** (id `03 04 01`) coders.
  We have no in-tree decoder for either; bzip2 is a candidate for a
  future plan, PPMd is much rarer and not worth the implementation
  cost for our use case.
- **Multi-volume archives** (`.7z.001`, `.7z.002`, …): require
  cross-URL chunk planning the multi-mirror code is *not* a fit for
  (mirrors are alternates of one file; volumes are distinct files
  that must be concatenated). Filed as `O.32d`.
- **Anti-files** (the `Anti` flag in `FilesInfo`), hard/symlinks
  (parallels `O.25` for tar).
- **Mid-folder resume**. A solid folder is a single LZMA/LZMA2
  stream; resuming mid-stream requires serializing the
  decoder state the same way `xz_native::resume` does for xz Block
  resume. Round-one restarts the in-progress folder from its start
  on resume; filed as `O.32c` (depends on `xz_native::resume`'s
  design and reuses its sliding-window snapshot shape).
- **Multiple-input coders** (i.e. Folders with bind-pair graphs that
  aren't a simple linear chain). The 7z format admits a DAG; round-
  one parses and accepts only a linear chain (`InStreams[i] →
  Coder[i] → InStreams[i+1]`). Non-linear chains return
  `UnsupportedFeature`.

## Module map (target)

```
src/
  decode/
    sevenz/
      mod.rs           (i.e. sevenz.rs)  // public surface
      format.rs        // header/footer wire-format parsers (no IO)
      number.rs        // 7z's variable-length integer encoding
      coders.rs        // coder-chain registry, dispatch to LZMA/LZMA2/DEFLATE/COPY
      folder.rs        // single-folder streaming decoder protocol
      lzma_raw.rs      // raw-LZMA / raw-LZMA2 entry points reused from xz_native
  download/
    sevenz_pipeline.rs // second-pipeline driver, parallel to zip_pipeline.rs
  sink/
    sevenz.rs          // SevenzSink, parallel to sink/zip.rs
  sevenz/              // crate-level wire-format types re-exported
    mod.rs (sevenz.rs)
    error.rs
```

---

## §1. Variable-length integer + bit-vector parsers

**What**: implement the small primitive parsers 7z's wire format leans
on — every other parser in this plan composes them.

**Why first**: every later phase touches them; getting them right
once, with property tests, beats catching off-by-ones in §3 / §4.

**Sketch**:

1. `Number` — 7z's variable-length unsigned integer encoding (also
   called "7-bit encoded" but with a header-byte twist: the count of
   leading 1-bits in the first byte tells you how many *additional*
   little-endian bytes follow, with the remaining bits of the header
   contributing to the high bits when the count is `< 7`). Range:
   `0..2^64 - 1`. Reference: `DOC/7zFormat.txt` "Real_UINT64".
2. `BoolVector(n)` — `ceil(n / 8)` bytes, MSB-first within each byte.
3. `BitVector(n)` — same encoding as `BoolVector` but used for
   "is-defined" predicates (e.g. CRCs are present for *some* but not
   all folders).
4. `propid` byte — single-byte tag (`0x01` = Header, `0x04` =
   MainStreamsInfo, `0x06` = PackInfo, …). Each parser switches on
   the tag and dispatches to the next-level parser.
5. `read_name_utf16le_zero_terminated` — file names in 7z are stored
   as zero-terminated UTF-16LE concatenated; round-one decodes via
   `String::from_utf16` and rejects names containing `..`, `/`-on-
   Windows-paths-with-drive-letters, NUL embedded mid-name, and any
   byte that would let a path escape the output dir (same anti-
   traversal rules as `TarSink` / `ZipSink`).

**Demo**: a `cargo test` module driving the four parsers against
hand-constructed byte sequences plus a `proptest` round-trip against
a small encoder we write in the test module (encode `u64` →
`Number`, decode, assert equal). No 7z-specific code runs yet.

---

## §2. SignatureHeader + StartHeader parser

**What**: parse the fixed 32-byte prefix of every 7z archive.

**Why now**: it tells us where the trailer is, which §3 needs.

**Sketch**:

1. Layout (all little-endian):
   ```text
    0   6  Signature           37 7A BC AF 27 1C
    6   1  ArchiveVersion.major  0x00
    7   1  ArchiveVersion.minor  0x04
    8   4  StartHeaderCRC      (CRC32 of bytes 12..32)
   12   8  NextHeaderOffset    (u64; relative to byte 32)
   20   8  NextHeaderSize      (u64)
   28   4  NextHeaderCRC       (CRC32 of the trailer bytes)
   ```
2. Reject ArchiveVersion ≠ `0x00 0x04` with
   `SevenzError::UnsupportedVersion { major, minor }`. The format has
   no other version in the wild but the field is checked for forward-
   compat.
3. Validate StartHeaderCRC. Mismatch ⇒
   `SevenzError::CorruptHeader { reason: "start-header CRC32" }`.
4. Trailer location: `(32 + NextHeaderOffset, NextHeaderSize)`. Sanity-
   check `32 + NextHeaderOffset + NextHeaderSize ≤ total_size` and
   surface `SevenzError::CorruptHeader` on overflow / past-EOF.
5. Reuse the existing CRC32 implementation in
   [`src/zip/crc32.rs`](../src/zip/crc32.rs) — same polynomial,
   already audited.

**Demo**: a unit test against a hand-built signature header and
against the first 32 bytes of a real `.7z` fixture. Reject a
corrupted-CRC version and a `version=0x05` version with the right
typed errors.

---

## §3. Header / EncodedHeader parser

**What**: decode the trailer the §2 parser pointed us at into a
typed `Header` structure: `MainStreamsInfo` (PackInfo + CodersInfo +
SubStreamsInfo) + `FilesInfo`.

**Why now**: the rest of the plan operates on this typed structure.
The pipeline (§7) cannot plan downloads or hole-punches without it.

**Sketch**:

1. The trailer is *either* a `Header` (id `0x01`) *or* an
   `EncodedHeader` (id `0x17`) followed by a `StreamsInfo` for the
   real header.
2. **Plain Header path**: parse propids in order
   `MainStreamsInfo (0x04)` → `FilesInfo (0x05)` → `End (0x00)`.
   `ArchiveProperties (0x02)` and `AdditionalStreamsInfo (0x03)` are
   uncommon; round-one accepts the former (skips its body) and
   rejects the latter (`UnsupportedFeature: "additional streams"`).
3. **EncodedHeader path**: parse the embedded `StreamsInfo`, run
   §6's folder decoder on the (small) packed bytes, then re-enter
   the parser at step (2) on the decoded buffer. Reject when the
   embedded folder has more than one coder *and* one of those coders
   is encryption (`UnsupportedFeature: "encrypted header"`).
4. **MainStreamsInfo** parses to:
   ```rust
   struct MainStreamsInfo {
       pack_pos: u64,                    // relative to byte 32
       pack_sizes: Vec<u64>,
       pack_crcs: Option<Vec<Option<u32>>>,
       folders: Vec<Folder>,             // CodersInfo
       sub_streams: SubStreamsInfo,      // mapping folders → files
   }
   struct Folder {
       coders: Vec<Coder>,               // linear chain only in round-one
       bind_pairs: Vec<BindPair>,        // validated linear in round-one
       packed_stream_indices: Vec<u32>,
       unpack_sizes: Vec<u64>,           // one per output stream
       unpack_crc: Option<u32>,
   }
   struct Coder {
       id: CoderId,                      // see §4 registry
       props: Vec<u8>,                   // coder-specific init bytes
       num_in_streams: u32,
       num_out_streams: u32,
   }
   ```
5. **FilesInfo** parses to a list of:
   ```rust
   struct FileRecord {
       name: PathBuf,                    // sanitized (§1.5 rules)
       attrs: Option<u32>,
       mtime: Option<i64>,
       is_directory: bool,
       has_stream: bool,                 // false ⇒ empty file or anti-file
       is_anti: bool,
   }
   ```
   The bit-vectors `EmptyStream`, `EmptyFile`, `Anti` are decoded
   with the §1.3 helper and folded into the per-file flags.
   Round-one rejects `Anti = true` with
   `UnsupportedFeature: "anti-file"`; directory entries (no stream,
   non-empty? — see `DOC/7zFormat.txt`) are honored as `mkdir -p`.
6. **Substream-to-file mapping**: `SubStreamsInfo.NumUnPackStreams[]`
   gives the number of files per folder; iterate `FilesInfo`
   skipping `is_directory || !has_stream` entries and assign each
   non-empty stream-bearing file to the next folder slot. The
   resulting `Vec<FolderToFiles>` is the input the pipeline §7 plans
   downloads from.

**Demo**: parse the trailer of three real fixtures (a single-file
LZMA2 7z, a multi-file LZMA 7z, a 7z with EncodedHeader). For each,
print the resulting `Vec<FolderToFiles>` and verify it matches
`7z l <fixture>` listing. Reject an encrypted fixture with the
documented typed error.

---

## §4. Coder registry + COPY / DEFLATE coders

**What**: introduce the dispatch surface `Coder.id → CoderImpl` that
§5 / §6 use, and ship the two coders that don't need any
LZMA-specific work.

**Why now**: lets us land §3 → §4 → §5 with the cheapest two coders
first, deferring the LZMA reuse refactor (§5) to its own phase.

**Sketch**:

1. `coders.rs`:
   ```rust
   enum CoderId {
       Copy,             // 00
       Deflate,          // 04 01 08
       Lzma,             // 03 01 01
       Lzma2,            // 21
       Unsupported(Vec<u8>),
   }
   trait CoderImpl {
       fn decode_one_block(&mut self,
                           src: &mut impl Read,
                           dst: &mut impl Write,
                           expected_unpack_size: u64) -> Result<(), CoderError>;
   }
   ```
   Round-one's `decode_one_block` is the single per-folder call that
   produces the entire decoded stream; per-block streaming inside a
   folder is filed as `O.32c` (the same follow-on as mid-folder
   resume — they share the LZMA-state-snapshot machinery).
2. `CopyCoder` — `io::copy` with the byte counter checked against
   `expected_unpack_size`. Reject mismatch with
   `CoderError::UnpackSizeMismatch { coder: "copy", expected, got }`.
3. `DeflateCoder` — wraps the existing
   [`decode/deflate_native`](../src/decode/deflate_native/) raw-
   DEFLATE entry point (no zlib / gzip framing). 7z DEFLATE coders
   feed raw DEFLATE streams.
4. Lookup is by exact-match on `Coder.id` bytes; an unknown id
   surfaces `UnsupportedFeature` with the id rendered as hex.

**Demo**: round-trip a `.7z` produced with `7z a -mx=0 …` (STORED /
copy) through §3 + §4 in a unit test, verify decoded bytes match
the original files. Repeat for `7z a -m0=Deflate …`.

---

## §5. LZMA / LZMA2 coder reuse from `xz_native`

**What**: add raw-LZMA and raw-LZMA2 entry points to the
`xz_native` module and wire them into `coders.rs` as
`LzmaCoder` / `Lzma2Coder`.

**Why now**: this is the keystone — the most common coder by far in
real `.7z` archives. Doing it as its own phase keeps the diff that
touches `xz_native` separable from the new code in `decode/sevenz/`.

**Sketch**:

1. The existing `xz_native::lzma2` parser expects the xz Block
   framing around an LZMA2 payload. 7z hands us a raw LZMA2 stream
   plus a one-byte property (`dictSize` encoded as in xz). Refactor:
   - Promote `xz_native::lzma2::decode_chunked` (or the equivalent
     that already operates on raw LZMA2 chunks) to a `pub(crate)`
     function: `decode_lzma2_raw(props: u8, src, dst,
     expected_size) -> Result<(), Lzma2Error>`.
   - Keep the existing xz Block path calling through that helper.
2. Same shape for raw LZMA: 7z's coder.props is the 5-byte
   `(properties, dict_size_le32)` blob LZMA1 has used since 1999.
   Promote a `decode_lzma1_raw(props: &[u8; 5], src, dst,
   expected_size) -> Result<(), LzmaError>` that wraps the LZMA
   range-coder loop already in
   [`src/decode/xz_native/lzma_state.rs`](../src/decode/xz_native/lzma_state.rs)
   without the xz Block scaffolding.
3. In `decode/sevenz/lzma_raw.rs`: thin wrappers that adapt the
   above to the `CoderImpl` trait surface (§4.1) and validate
   `coder.props.len()` (5 for LZMA, 1 for LZMA2; reject otherwise).
4. **No new state-machine code** — every new line in this phase is
   either a rename, a new `pub(crate)` declaration, or trivial glue.
   The audit posture is "shrink the surface area, don't grow it."
5. Tests: differential against the `xz2` dev-dependency's raw-
   LZMA / raw-LZMA2 mode for ~1000 random inputs (same shape as the
   `xz_native` differential corpus). Plus a real-fixture round-trip
   on a `7z a -m0=LZMA2 …` archive and a `7z a -m0=LZMA …` archive.

**Demo**: §3 + §4 (with §5's coders registered) extracts a real
`linux-source.tar.7z` (or equivalent) end-to-end *in a single
process*, no pipeline yet — a `peel-7z-decode <fixture> -C ./out`
debug binary. Output is byte-identical to `7z x` on the same
fixture.

---

## §6. Folder decoder

**What**: tie §4 + §5 together into a `Folder::decode_into(sink)`
entry point: given a `Folder` (linear coder chain + packed-stream
slice), produce its decoded byte stream into a sink.

**Why now**: this is the atomic unit §7's pipeline schedules around
— it's also the unit hole-punching is keyed to.

**Sketch**:

1. `folder.rs`:
   ```rust
   pub struct FolderDecoder<'a> { … }
   impl<'a> FolderDecoder<'a> {
       pub fn new(folder: &'a Folder, packed: &'a [PackedStreamSlice])
           -> Result<Self, SevenzError>;
       pub fn decode(self, sink: &mut dyn FolderSink) -> Result<(), SevenzError>;
   }
   trait FolderSink {
       fn begin_substream(&mut self, idx: u32, expected_size: u64)
           -> Result<(), SinkError>;
       fn write(&mut self, buf: &[u8]) -> Result<(), SinkError>;
       fn end_substream(&mut self, crc: Option<u32>)
           -> Result<(), SinkError>;
   }
   ```
2. **Linear chain enforcement**: validate `bind_pairs` match
   `(coders[i].out_streams[0], coders[i+1].in_streams[0])` for `i =
   0..coders.len()-1`. Anything else surfaces
   `UnsupportedFeature: "non-linear coder chain"`.
3. Coder pipelining: round-one decodes the chain by buffering each
   stage's output in a `Vec<u8>` of bounded size (`unpack_size` of
   the stage's output, which the header makes known up front). The
   in-tree usage is "1 coder ⇒ no buffer, source-to-sink streaming";
   "≥ 2 coders" goes through buffers. With round-one rejecting all
   filters, the ≥ 2 path is in practice only exercised by the
   EncodedHeader case, where the buffers are tiny.
4. **CRC validation**: if `folder.unpack_crc` is set, hash the final
   output stream and validate at end-of-folder. Mismatch ⇒
   `CoderError::FolderCrcMismatch`.
5. **Substream split**: the `FolderSink` interface takes the
   per-substream sizes from `SubStreamsInfo` and forwards bytes to
   the right substream in order. Per-substream CRCs (when present)
   are validated in `end_substream`.

**Demo**: same fixture as §5's demo, but driving the folder decoder
through a `Vec`-backed `FolderSink` and asserting per-substream
sizes / CRCs match the central directory. Reject a fixture with two
coders chained as a non-linear graph (build one with `7z a -m0=...`
explicitly if needed).

---

## §7. SevenzSink (file output)

**What**: the `FolderSink` implementation that materializes
substreams into actual files on disk, with the same path-safety
discipline `TarSink` and `ZipSink` already follow.

**Why now**: trivial, but separates the on-disk concern from the
in-memory folder decoder.

**Sketch**:

1. `sink/sevenz.rs`:
   ```rust
   pub struct SevenzSink { … }
   impl SevenzSink {
       pub fn new(out_dir: PathBuf, files: Vec<FileRecord>) -> Self;
       pub fn begin_file(&mut self, file_idx: u32) -> io::Result<…>;
       pub fn end_file(&mut self) -> io::Result<()>;
   }
   impl FolderSink for SevenzSink { … }
   ```
2. Path safety: copy the `ZipSink::sanitize_path` helper verbatim
   (anti-traversal: reject any component equal to `..`, any absolute
   path, any path containing a NUL or a `\` on Unix, any path that,
   after `path.components()` resolution, escapes `out_dir`). The
   §1.5 name decoder already guards the upstream side.
3. Empty-file / directory entries (`!has_stream`) materialize
   directly without ever going through `FolderSink::write`.
4. CRC mismatch on `end_substream` deletes the partially-written
   file and surfaces `SinkError::Crc { path, expected, got }`.

**Demo**: extracting a small `.7z` end-to-end from a local file
through §3 + §6 + §7 produces a directory tree byte-identical to
`7z x`.

---

## §8. Pipeline (`download/sevenz_pipeline.rs`)

**What**: the second-pipeline driver — the 7z analogue of
[`src/download/zip_pipeline.rs`](../src/download/zip_pipeline.rs).
Steers downloads, runs the folder decoder, hole-punches between
folders, emits checkpoint events.

**Why now**: this is where everything converges. Doing it before §6
+ §7 means stubbing the folder decoder; doing it after means we
already have a tested decoder to plug in.

**Sketch**:

1. **Bootstrap (parallel to ZIP's EOCD fetch)**:
   - Steer the cursor to the first 32 bytes of the archive *and*
     the trailer range named by the SignatureHeader. The trailer is
     usually small (≤ a few MiB even for large archives — only
     metadata).
   - Parse the SignatureHeader (§2). Wait for the trailer chunks.
     Run §3 to materialize the typed `Header`.
2. **Folder iteration**: for each folder *not* already in
   `folders_completed`:
   - Compute the folder's packed-byte range:
     `[32 + pack_pos + sum(pack_sizes[..first_idx]),
       … + pack_sizes[first_idx..first_idx + folder.packed_count])`.
   - Steer the cursor and wait for those chunks.
   - Build a `PackedStreamSlice` for each input. Run §6's
     `FolderDecoder` into the §7 `SevenzSink`.
   - Punch the folder's packed range in the sparse file (`align_up`
     / `align_down` to puncher block size, same as zip).
   - Emit `SevenzPipelineEvent::FolderFinished` so the coordinator
     can write a checkpoint.
3. **End-of-archive**: punch the trailer range. Punch any
   straggling holes between folders (the data section is usually
   contiguous, but EncodedHeaders sometimes leave a gap). Emit
   `SevenzPipelineEvent::Complete`.
4. **Empty / directory files**: materialized at iteration time
   without touching the download — the `FilesInfo` list alone is
   enough.
5. **Cursor steering policy**: same posture as
   `zip_pipeline::run` — bias the scheduler toward "the chunk the
   pipeline is waiting on right now" via the existing
   `Arc<AtomicU64>` priority cursor.

**Demo**: `peel https://.../linux-6.x.tar.7z -C ./linux` extracts
correctly, hole-punching the archive to ~one folder's worth of
packed bytes at a time. Compare on-disk footprint to a control run
with punching disabled — should differ by GiB on a multi-GiB
fixture.

---

## §9. Resume + checkpoint integration

**What**: persist enough state in the checkpoint that an
interrupted 7z extraction resumes byte-identical. Round-one resume
granularity is **one folder** — the in-progress folder restarts
from the start of its packed range.

**Why now**: requires §8's `SevenzPipelineEvent` stream, but is its
own diff worth keeping separate from the pipeline phase to keep
review surface manageable.

**Sketch**:

1. `checkpoint.rs`: extend `SinkState`:
   ```rust
   pub enum SinkState {
       Raw { bytes_written: u64 },
       Tar { … },
       Zip { … },
       Sevenz {
           folders_completed: Vec<u32>,
           current_folder: Option<u32>,
       },
   }
   ```
   Bump `format_version`. `current_folder` is `Some` when a folder
   was started (i.e. its packed range was hole-punched-pending) but
   not finished — the resume restarts that folder.
2. Resume loads `folders_completed`, asks the pipeline to skip
   those, and re-enters the iteration loop. Empty / directory files
   are re-materialized iff their `file_idx` falls into a folder we
   re-extract — the §7 sink's `begin_file` is idempotent on
   identical contents (matches `ZipSink`'s STORED-resume rule).
3. **Hash state (§10 of `PLAN_v2.md` integration)**: the SHA-256 of
   the *compressed source* runs across the entire archive bytes,
   independent of folder boundaries; resume continues feeding bytes
   into the hasher from the cursor as today.
4. **Crash test harness**: extend the existing 100-random-kill-
   points harness to cover `.7z` archives. For round-one this means
   "resume produces a byte-identical output tree", not "resume
   re-uses prior decoded folder bytes" — the latter is `O.32c`.
5. Reject older binaries reading the new `format_version` cleanly
   (`CheckpointError::UnsupportedVersion`) — same discipline as
   every prior plan that bumped the version.

**Demo**: kill a 7z extraction at a random byte offset; resume
produces byte-identical output. Repeat 100 times across multiple
fixtures (LZMA2, LZMA, multi-folder, EncodedHeader); all pass.

---

## §10. CLI integration + format detection

**What**: register `.7z` everywhere `peel` recognizes formats; ship
the round-one as an officially supported format.

**Why last**: this is the phase that exposes 7z to users. Doing it
last means the prior phases have been demoed in isolation already.

**Sketch**:

1. `decode.rs` → `DecoderRegistry::with_defaults`:
   - Suffix: `.7z` (and `.tar.7z`, though it's vanishingly rare —
     7z archives almost always already contain the file tree
     directly).
   - Magic: `37 7A BC AF 27 1C` at offset 0.
   - Format name: `"7z"` for the `--format <name>` override.
   - Factory: routes to the §8 pipeline rather than the streaming
     decoder. The registry already returns a `DecoderFactory` *or*
     `PipelineFactory` discriminated union (the same plumbing zip
     uses); 7z plugs in on the pipeline side.
2. `coordinator.rs`: extend the format-router that already
   distinguishes "streaming pipeline" vs "zip pipeline" to add the
   "7z pipeline" arm. The coordinator's job is unchanged: pick a
   pipeline, hand it the scheduler + sparse file + sink.
3. `main.rs`: no flag changes. `peel https://.../foo.7z -C ./out`
   works automatically.
4. `README.md`: add 7z to the format coverage matrix; document the
   round-one limitation list (no encryption, no filters, no
   bzip2/PPMd, no multi-volume, no mid-folder resume) so users know
   what to expect.
5. Append the round-one follow-on entries to `OPTIMIZATIONS.md`:
   - `O.32a` — 7z encryption (AES-256, password-derived).
   - `O.32b` — 7z BCJ / Delta / arch filters.
   - `O.32c` — 7z mid-folder resume + intra-folder bounded steps
     (depends on `xz_native`'s LZMA-state snapshot machinery).
   - `O.32d` — 7z multi-volume archives (`.7z.001`).
   - `O.32e` — bzip2 + PPMd coders for both 7z and standalone use.

**Demo (the round-one milestone)**:
```
$ peel https://example.com/dataset.7z -C ./out
[downloading]  234.5 MiB / 1.2 GiB  ▓▓▓░░░░░  19.5%  (4 workers, 38 MiB/s)
[extracting]   119 files, 156.2 MiB written     (folder 7 / 12)
[disk]         compressed on-disk: 84 MiB (of 234.5 MiB downloaded)
```
…with a `kill -9` at any point and a clean resume to byte-
identical output. The same north-star use case `PLAN.md` set for
`.tar.zst`, now for `.7z`.

---

## What "round-one done" means

All of the following are true:

1. Each phase's demo has been recorded (screen capture or
   reproducible test) and reviewed.
2. The crash-test harness covers `.7z` (LZMA2, LZMA, multi-folder,
   EncodedHeader) at 100 random kill points; resumes produce byte-
   identical output.
3. Differential corpus: ≥ 50 real-world `.7z` fixtures
   (Linux-distro source tarballs republished as `.7z`, public-
   dataset `.7z` releases, GitHub-release artifacts) extract byte-
   identically against `7z x`.
4. Encountering any deferred feature returns the right typed
   `UnsupportedFeature` error with the specific feature named.
5. CI gates listed in `ENGINEERING_STANDARDS.md` §CI remain green;
   coverage thresholds (80 % overall, 95 % on critical paths) hold
   across the new modules.
6. README updated with format coverage, limitations, and a 7z
   example.
7. `OPTIMIZATIONS.md` gains `O.32a` through `O.32e` so a future
   round can promote them deliberately.

## Decisions to resolve before §1 begins

These are the calls that need a deliberate yes/no before the first
diff lands. None of them are flagged as research — every one has a
default that the corresponding phase will assume unless someone
overrides it before §1.

1. **No new dependency.** §5 reuses `xz_native`; §4 reuses
   `deflate_native` and the existing CRC32 helper. Adopting a
   `sevenz`-flavored crate (e.g. `sevenz-rust`) is *not* on the
   table — same posture as the zip / xz / lz4 phases. Default:
   confirmed, hand-rolled.
2. **Mid-folder resume.** Round-one restarts the in-progress
   folder; mid-folder resume is `O.32c`. The cost of round-one's
   choice is "kill mid-folder ⇒ re-decompress that one folder on
   resume"; for a multi-folder `.7z` (the common shape) this is
   bounded and acceptable. Default: confirmed.
3. **Coder set.** COPY + DEFLATE + LZMA + LZMA2. BZIP2 is
   conspicuously absent; if we hit a real fixture it's needed for,
   bzip2 promotes via `O.32e`. Default: confirmed, ship without
   bzip2.
4. **EncodedHeader support.** Yes — round-one supports the
   unencrypted variant because it's near-universal in real `.7z`
   archives (anything `7z a` produces by default uses one). The
   *encrypted* EncodedHeader variant is rejected as part of the
   encryption deferral. Default: confirmed.
5. **`.tar.7z` vs `.7z` of a tree.** The dominant convention is
   `.7z` containing the file tree directly. `.tar.7z` does exist
   but is rare; round-one accepts both suffixes and routes them
   through the §8 pipeline regardless. The pipeline produces the
   decoded file tree; if that tree happens to be a single `.tar`,
   the user runs `tar` themselves (no auto-chained-format
   handling). Default: confirmed.

## Schedule guidance

There is still no schedule. The plan is sequenced; do it in order,
do each phase completely. §1 → §10 are gating dependencies for one
another in the order written. In particular:

- §3 cannot demo without §2.
- §6 cannot demo without §4 and §5.
- §8 cannot demo without §6 and §7.
- §9 cannot demo without §8.
- §10 cannot demo without §9.

Resist the temptation to parallelize across sessions. The 7z spec
has enough quirks that a half-finished §3 leaking assumptions into
§4 will cost more debugging time than the parallelism saves.
