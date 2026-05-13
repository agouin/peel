# Plan: multi-volume archive support (rar5, 7z, zip)

> **Status: scoped, not started (2026-05-11).** peel already handles
> the multi-URL case where N URLs byte-concatenate into one logical
> stream (see [`PLAN_multi_url_source.md`](PLAN_multi_url_source.md)).
> That's not the same as multi-volume archives, where each volume is
> a self-contained file with its own headers and the entries can
> *span* volume boundaries. Raw tar split-volume already works
> because tar is a stream; the work here is rar5 / 7z / zip, where
> the format itself encodes the multi-volume relationship.

## What "multi-volume" actually means per format

| Format | File naming | Header layout | Cross-volume entries |
|--------|-------------|---------------|----------------------|
| rar5   | `name.part0001.rar`, `name.part0002.rar`, … | Each volume has its own main+end headers; `MHD_VOLUME` flag set; volume number in main header | Yes — `FHD_SPLIT_BEFORE`/`FHD_SPLIT_AFTER` flags mark continuing files |
| 7z     | `name.7z.001`, `name.7z.002`, … | Only the **last** volume has the EOS/header data; earlier volumes are raw streamed payload | Yes — the compressed stream spans all volumes; folders/packs reference into a logical concatenation |
| zip    | `name.z01`, `name.z02`, …, `name.zip` | Central directory only in the last volume (`name.zip`); each volume starts with `0x08074B50` "spanning marker" | Yes — local file headers can split across volumes (rare in modern outputs but allowed) |
| tar (split) | Operator's choice (`.part-aa`, `.part-ab`, …) | None — pure byte split | N/A — tar is a stream, the "split" is just concatenation |

Today peel's rar5 path rejects `MHD_VOLUME` archives with
`UnsupportedFeature` (`src/rar/archive.rs:125-128`). 7z and zip
multi-volume aren't even detected — the format parsers see "this
file ends mid-stream" and report it as corruption. The multi-URL
source path
([`PLAN_multi_url_source.md`](PLAN_multi_url_source.md)) handles
the *byte-concat-equals-tar* case only.

## Motivation

Multi-volume archives turn up in three places that peel is
already pointed at:

1. **Backup imports** — both rar5 and 7z multi-volume are common
   when shipping data on physical media sized to fit in (e.g.)
   25 GiB chunks.
2. **Game / community distributions** — `.partN.rar` is the
   archetype.
3. **CDN constraints** — split `.7z.NNN` is the workaround for
   per-object upload size limits on legacy hosts.

The user wants `peel name.part0001.rar -C out/` (or just `peel
name.7z.001 -C out/`) to find the other volumes and extract the
whole thing, the same way `unrar x name.part0001.rar` does today.

## Hard constraints

- Reuse the existing `MultiPartSource` from
  [`PLAN_multi_url_source.md`](PLAN_multi_url_source.md). A
  multi-volume archive is structurally a `MultiPartSource` where
  the parts are the volumes; the only twist is the format-aware
  parser that knows the parts are *not* a byte-concatenation
  (rar5 main headers in volume N+1 are not part of the logical
  decode stream; they're metadata).
- No new HTTP plumbing. Volume URL discovery is a pre-flight
  step that resolves a single URL or path into the full list,
  then hands off to existing code.
- Volume order is **rigid**. If the user supplies `part0003.rar`
  first, we either error (and tell them how to glob) or auto-
  discover the full set by URL pattern. We do not attempt to
  reorder a heterogeneous list.
- Reads only. peel never *creates* multi-volume archives.

## Out of scope

- Heterogeneous-source mixes (volume 1 on disk, volume 2 over
  HTTP). The discovery path picks one transport per archive.
- Mid-archive volume replacement (e.g. retry volume 3 from a
  different URL while volumes 1, 2, 4 stream in parallel). The
  existing `--mirror` machinery solves the closest analogue and
  is per-archive, not per-volume.
- Self-extracting volume detection (SFX `.exe` prefixes around the
  first volume). Out of scope for round one; surfaces as
  "unrecognised prefix" and the user strips it.
- ZIP multi-volume "open volume by volume" UX (the WinZip "insert
  next disk" flow). We resolve the full set up front.

---

## §1. Volume-set discovery

**What**: given a single URL or path, find the full ordered set
of volume URLs/paths.

**Why first**: every other phase depends on the resolved list.
Discovery is also the place where the user gets their first
clear "this is multi-volume" signal, so we need its error
messages to be helpful.

**Sketch**:

1. New module `src/multivolume.rs`. One function per format:
   ```rust
   pub fn discover_rar5(seed: &Source) -> Result<Vec<Source>, MvError>;
   pub fn discover_7z(seed:  &Source) -> Result<Vec<Source>, MvError>;
   pub fn discover_zip(seed: &Source) -> Result<Vec<Source>, MvError>;
   ```
   Where `Source` is either `Url` or `PathBuf` (see
   [`PLAN_local_file_extract.md`](PLAN_local_file_extract.md)).
2. **Pattern matching**:
   - rar5: `(.*)\.part(\d+)\.rar$` (case-insensitive). Iterate
     `1..=N` until the next number doesn't resolve (HEAD 404 or
     `ENOENT`). Tolerate gaps in numbering with a clear error
     ("found part0001, part0003 — part0002 missing").
   - 7z: `(.*)\.7z\.(\d+)$`. Same iteration.
   - zip: `(.*)\.z(\d+)$` for the leading volumes (numbered),
     plus `(.*)\.zip$` for the final volume. The final volume is
     mandatory — that's where the central directory lives.
3. **HEAD-time validation**: for HTTP sources, every volume
   gets a HEAD to confirm 200, capture `Content-Length`,
   `ETag`/`Last-Modified`. Same shape as
   [`PLAN_multi_url_source.md`](PLAN_multi_url_source.md) §1.
4. **No URL pattern? Look for sibling explicit list**: the user
   can supply a manifest list (`peel @volumes.txt` — one
   URL/path per line) to side-step discovery. Or pass all volumes
   as positional args (we accept this and rely on the format
   parser to confirm the order matches the volume-number
   metadata; reject on mismatch).
5. Error type `MvError` with variants `MissingVolume(n)`,
   `OutOfOrder`, `MixedTransports`, `PatternNotRecognised`,
   `FinalVolumeMissing` (zip-specific).

**Demo**: `peel test.part0001.rar -C out/` finds parts 0001–0005
on the same path/host and runs through the existing rar5 pipeline
with the full set.

---

## §2. rar5 multi-volume decode

**What**: stitch the rar5 logical stream across volumes.

**Why first among the three formats**: rar5 already has the most
multi-volume metadata machinery in place. The flags are parsed
(`FHD_SPLIT_BEFORE`, `FHD_SPLIT_AFTER` per `src/rar/format.rs:222-224`),
the volume number is captured. The implementation is mostly
"don't reject, then handle the cross-volume continuation logic."

**Sketch**:

1. `src/rar/archive.rs:125`: remove the `UnsupportedFeature` for
   `MHD_VOLUME`. Replace with: open the next volume from the
   resolved set when an EOF-with-`more_volumes` end marker is
   hit (the flag is already captured on `EndArchive` —
   `src/rar/archive.rs:167`).
2. **Volume transition**:
   - At the end of the active volume, drop the volume's main
     header context and open the next.
   - The next volume starts with its own RAR signature + main
     archive header; both are *not* part of the logical stream.
     Skip past them (existing parser already does this for the
     first volume).
3. **Files spanning volumes**: when a file's `FHD_SPLIT_AFTER`
   flag is set, the decoder doesn't reach EOF on that file's
   data — it switches to the next volume's first file (which has
   `FHD_SPLIT_BEFORE`) and continues from where it left off.
   - Cross-check: the spanning file's name in volume N must match
     the spanning file's name in volume N+1 (the rar5 spec
     requires this; if it doesn't match, error).
   - The decoder context (LZ / PPMd state) carries across; the
     existing rar5 decoder reads from a logical byte stream that
     is already abstracted over the source — we just feed it the
     concatenation of volume payloads, with the metadata bytes
     in each volume skipped.
4. **BLAKE2sp digest**: the per-file digest covers the full
   reconstructed file, not the per-volume slice. This already
   works as long as the decoder sees the full plaintext.
5. **Multi-URL source plumbing**: the resolved volume list is
   handed to `MultiPartSource` with one tweak — each part has a
   "header prefix size" that the *decoder* skips. The
   download/bitmap/checkpoint layer treats every byte as a byte;
   only the format parser knows about the skip.
6. Tests: fixtures generated with `rar a -v25M` (WinRAR linux);
   round-trip extract under peel and `unrar` and assert
   byte-identical output. Include a fixture with a 10 MiB file
   that spans three volumes.

**Demo**: `peel multi.part0001.rar -C out/` extracts a 5-volume
fixture with a file that crosses every volume boundary; output
matches `unrar x multi.part0001.rar` bytewise.

---

## §3. 7z multi-volume decode

**What**: 7z's "earlier volumes are raw, last volume has the
metadata" layout.

**Sketch**:

1. 7z's `name.7z.NNN` files are a pure byte split — the logical
   `.7z` file is `cat name.7z.001 name.7z.002 … name.7z.NNN`.
   Crucially, the SignatureHeader is at the start of `001`, but
   the EndHeader (which points to the StreamsInfo metadata) is
   in `NNN`, with the StreamsInfo body itself sitting somewhere
   in the middle of the concatenation, addressed by absolute
   offset.
2. This is the easy case: it maps directly onto
   `MultiPartSource` from
   [`PLAN_multi_url_source.md`](PLAN_multi_url_source.md). The
   7z parser sees one logical stream. No per-volume header skip
   is needed because the volumes are a literal byte-split.
3. Discovery (§1) resolves `name.7z.001` → `[001, 002, …, NNN]`,
   constructs a `MultiPartSource` with each part's
   `Content-Length` and ETag, and the existing 7z pipeline runs
   unchanged.
4. **Edge case**: the user passes `name.7z.005` first. Detect
   this (the file starts with random payload bytes, no 7z
   signature), walk backwards to find `001`, error if missing.
   Or accept it and document the seed-must-be-first requirement.
   Pick one in the implementation review.
5. Tests: fixtures generated with `7z a -v25m`; round-trip
   identical to `7z x name.7z.001`.

**Demo**: `peel multi.7z.001 -C out/` extracts a 5-volume fixture
where the metadata lives in `.005` and the largest entry spans
volumes 002–004.

---

## §4. zip multi-volume decode

**What**: spanned `.zip` (`name.z01`, `name.z02`, …, `name.zip`).

**Why last**: this is the rarest of the three in modern use, but
the format is fully specified in APPNOTE.TXT §8. The trickiest
piece is that the spanning signature `0x08074B50` may appear at
volume starts, and the central directory + EOCD live only in the
final `.zip` volume.

**Sketch**:

1. Discovery (§1) resolves the volume set. The final volume is
   the `.zip` (no number); earlier volumes are `.z01..z<N>`.
2. The zip parser starts from the **end** — it reads the EOCD
   from the last volume to find the central directory. The CD
   entries each carry the disk number that holds the local file
   header. We read CD first, then dispatch per-entry to the
   right volume's offset.
3. This is fundamentally a random-access scheme. peel's existing
   zip pipeline is already random-access (it does not use the
   streaming `StreamingDecoder` trait — see the
   `streaming_factory_placeholder` comment in `src/decode.rs:530-536`).
   The change is plumbing per-entry offsets through
   `MultiPartSource` rather than a single source.
4. Entries that span volumes: cd entry says volume 3 offset
   `X`; the local file header is at `(3, X)`; the entry data
   continues until volume 4 ends or the compressed size is
   exhausted. The decoder's `Read` adapter is fed
   `MultiPartSource::reader_at(...).take(compressed_size)`.
5. Tests: fixtures from `7z a -v25m archive.zip ...` (which
   produces a spanned zip when the format is zip + volume size
   set); cross-check against `unzip`.

**Demo**: `peel multi.z01 -C out/` extracts a 5-volume spanned
zip; `peel multi.zip -C out/` (final volume seed) does the
same — both invocations should work.

---

## §5. Checkpoint format bump

**Status (2026-05-12):** the format bump itself has landed.
`FORMAT_VERSION` is v14; `PartRecord` carries an
`Option<VolumeRole>` that round-trips through the on-disk
layout, with a byte-identical fallback for runs whose parts are
all `None`. The resume-side enforcement (steps 3 and 4 below)
remains future work, gated on §1's discovery and §2/§3/§4's
per-format decoders.

**What**: extend the checkpoint to remember the volume set.

**Why now**: the existing v8 checkpoint already carries a
`Vec<PartRecord>` (see `PLAN_multi_url_source.md` §5). Multi-
volume archives reuse that vector with one twist: a
`volume_role: enum { Rar5Volume, SevenZVolume,
ZipSpannedVolume }` tag so a resume can verify the volume set's
shape matches. The original sketch listed a fourth `LinearByte`
variant; the implementation collapses that into the
`Option`-`None` arm because `Option<VolumeRole>` already
encodes "no multi-volume role" without redundancy.

**Sketch**:

1. ✅ **Bumped `FORMAT_VERSION` to 14.** A new
   `FORMAT_VERSION_MULTIVOLUME = 14` constant names the floor;
   `Checkpoint::required_format_version` returns 14 only when at
   least one part has `Some(volume_role)`. Runs whose parts are
   all `None` keep writing the pre-v14 layout byte-identically
   so existing crash-resume tests do not see a sidecar-size
   drift.
2. ✅ **Each `PartRecord` gains an `Option<VolumeRole>` field.**
   `None` is the linear byte-concat shape (single-URL,
   multi-URL split-byte, and every pre-v14 checkpoint). The
   three concrete variants are `Rar5Volume`, `SevenZVolume`,
   and `ZipSpannedVolume`.
   - **Wire format:** at v14+ each `PartRecord` appends a
     presence byte after `expected_sha256`. When the presence
     byte is `1`, a one-byte tag follows
     (`0 = Rar5Volume`, `1 = SevenZVolume`,
     `2 = ZipSpannedVolume`). The trailer is written for *every*
     part once the writer commits to the v14 layout — the read
     loop has a fixed shape, with no per-part dispatch. A mixed
     vec (some `Some`, some `None`) is legal and round-trips
     verbatim.
   - **Forward-compat:** v13-and-earlier checkpoints decode with
     every part's `volume_role` defaulting to `None`. Older
     binaries reading a v14 checkpoint surface
     `CheckpointError::UnsupportedVersion`.
3. **On resume: shape match enforced.** *(Pending.)* The
   coordinator's resume validator will fail with a typed error
   when the discovered volume set's roles disagree with the
   recorded set (e.g. a checkpoint that recorded `Rar5Volume`
   parts resumed against a `.7z.NNN` set). This wires into the
   §1 discovery output once it lands.
4. **Mid-flight kill across a volume boundary.** *(Pending.)*
   Existing per-part SHA-256 still verifies each volume
   independently as it completes; the decoder context (LZ
   window, etc.) is captured in the same `decoder_state` blob
   the streaming formats already use. rar5's decoder state
   across a volume boundary needs a one-line confirmation test
   that the existing blob captures everything (LZ window +
   PPMd model + repeat offsets); if not, that's a follow-up
   before §2 is done.

**Demo (pending §2..§4):** kill mid-decode at a volume
boundary, restart, verify byte-identical output. Same
crash-test harness as `PLAN.md` §10.3, extended to multi-volume
fixtures.

---

## §6. CLI surface

**What**: the user types one of these and peel does the right
thing:

```
peel name.part0001.rar -C out/                    # rar5 multi-volume
peel https://host/name.part0001.rar -C out/       # rar5 multi-volume over HTTP
peel name.7z.001 -C out/                          # 7z multi-volume
peel name.zip -C out/                             # spanned zip (final volume seed)
peel @volumes.txt -C out/                         # explicit list
peel name.part0001.rar name.part0002.rar ... -C out/  # positional list
```

**Sketch**:

1. CLI accepts a single seed or an explicit set. Auto-discovery
   (§1) runs only when one source is supplied.
2. `--no-auto-discover` flag forces the user to supply the full
   list; useful for non-conforming filename patterns or when
   discovery would fan out to too many failed HEAD probes.
3. Help text: a "Multi-volume archives" section calling out the
   three filename conventions.

**Demo**: each of the seven invocation forms in the table works
end-to-end on a fixture and produces the same output tree.

---

## §7. Interaction with parallel downloads

**What**: each volume can be downloaded in parallel chunks the
same way a single archive is today. Volumes themselves can also
be downloaded in parallel — both layers compose.

**Sketch**:

1. The existing `MultiPartSource` already supports parallel
   chunks across parts (see `PLAN_multi_url_source.md` §2). For
   multi-volume archives the only new constraint is that the
   **decoder** consumes volumes sequentially — but the
   **download** can race ahead. The disk-buffer cap
   (`--max-disk-buffer`) gates how far ahead.
2. Decoder cursor steering (`PLAN.md` §5.1) gives priority to
   chunks the decoder needs next, which is the chunks at the
   current logical-offset position. The existing logic works
   unchanged because logical offset already maps via prefix sums
   to `(volume_idx, in-volume offset)`.
3. **Hole punching** works across volumes the same way it works
   today across a single sparse file — except multi-volume runs
   have *multiple* `.part` files. The puncher's per-file
   block-size and per-file cursor need to be tracked separately.
   This is the only real implementation surprise in the plan;
   anticipate it.

**Demo**: a 5-volume archive downloads with 4 parallel workers
chasing the decoder cursor across volume boundaries; on-disk
footprint stays bounded; aborted run resumes cleanly.

---

## What "feature done" means

1. All three formats extract multi-volume fixtures byte-identical
   to the reference CLI:
   - rar5 vs. `unrar`
   - 7z vs. `7z x`
   - zip vs. `unzip` (when the format is `7z a -v ... -tzip`)
2. Auto-discovery resolves the volume set from any seed, errors
   clearly on gaps, refuses out-of-order positional lists.
3. Crash-resume on a multi-volume run produces byte-identical
   output (same 100/100 standard as `PLAN.md` §10.3).
4. The on-disk footprint of the source volumes stays bounded by
   `--max-disk-buffer` even though there are multiple `.part`
   files.
5. Coverage thresholds in `ENGINEERING_STANDARDS.md` §5.1 hold
   for `src/multivolume.rs`, the modified rar/7z/zip pipelines,
   and the bumped checkpoint reader.
6. README has a "multi-volume archives" section with one example
   per format and one explicit-list example.
