# Plan: download modes (`--no-extract`, `--keep-archive`, unknown formats)

> **Status: scoped, not started (2026-05-11).** A set of CLI surface
> changes that all touch the same coordinator seam — "what do we do
> with the bytes we just downloaded?" — plus a prerequisite CLI
> simplification that collapses `-C`/`-o` into a unified `-o`.
> Grouped into one plan because the implementation overlaps and the
> UX needs to be consistent. After this lands, peel covers the
> parallel-ranged-HTTP-download case (the part of aria2c that
> matters here — not BitTorrent, metalink, or magnet links) on top
> of its existing extract-only role.

## Motivation

Today peel runs one pipeline: **download → in-flight decode →
extract → hole-punch the source as the decoder advances → delete
the source on success**. That's the right default for the
north-star use case (a huge `.tar.zst` you only want extracted). It
is the wrong default for:

1. **You just want the file.** The remote object is a `.deb`, a
   raw binary, a checksum-list — not an archive. You want aria2c's
   "parallel ranged downloads with checkpoint/resume," nothing more.
2. **You want both extracted contents *and* the archive.** Maybe the
   archive will be re-extracted later by a different tool; maybe it's
   a release artifact that needs to land on a mirror.
3. **You want to download an archive but extract it yourself** (e.g.
   into a non-`std` tool, or because peel's extractor doesn't yet
   support a feature you need — encryption, multi-volume — that the
   archive happens to use).

The plumbing for all three already exists in pieces. This plan ties
them together into three explicit, named modes with clear precedence
when they're combined.

## The three modes

The table below applies to **HTTP sources**. Local-file sources use
the same `-k/--keep-archive` flag with the same semantics
("preserve source, no punching, no deletion") but a different
default; see [`PLAN_local_file_extract.md`](PLAN_local_file_extract.md)
for the local-mode prompt, `-y`, and non-TTY rules.

| Flag | Download | Extract | Hole-punch source | Source on disk at exit |
|------|----------|---------|-------------------|------------------------|
| (default) | yes | yes | yes | deleted |
| `-k` (bare) | yes | yes | **no** | preserved as sibling of `-o` |
| `-k <path>` | yes | yes | **no** | preserved at `<path>` |
| `--no-extract` | yes | no | n/a | preserved at `-o` |

Mutual exclusion (NEW errors introduced by this plan, not
"existing" — needs fresh clap rules):

- `--no-extract` + `-o <dir>/` → error (no tree to put in a dir).
- `--no-extract` + `--format`/`--force-format-from-magic`/
  `--punch-threshold` → error (extractor knobs; nothing extracts).
- `--no-extract` + `--strict-format` → error (no detection runs).
- `-C/--output-dir` → migration error pointing to `-o` (see §1).

Combining `--no-extract` and `-k` is **not** an error — `-k` is
just redundant (`--no-extract` already preserves the source).
Emit `tracing::info`, not a warning.

Unknown-format behaviour (see §4) is a different axis: it
determines which mode the binary *defaults to* when format
detection fails.

## Hard constraints

- No new download orchestration. The existing
  scheduler / `MultiPartSource` / bitmap / checkpoint stack is
  reused identically; the only thing that changes is what runs
  after `download::run` returns (or runs alongside it for
  `--keep-archive`).
- Checkpoint format compatibility: `--no-extract` and
  `--keep-archive` both still write a checkpoint after each chunk
  batch (so a kill mid-download still resumes). The on-disk format
  gains one new field, `mode: RunMode` (enum; see §5), so a
  resume with a different mode than the original run errors out
  cleanly rather than corrupting state.
- Hole-punching is **always opt-out for `-k`/`--keep-archive`**:
  when the user asks for the archive on disk, we will not punch
  holes in it mid-extraction, period.
- `-C/--output-dir` is **removed** as part of this plan; `-o` is
  the unified output path. See §1 for the resolution rules and the
  hard-cutover error message.

## Out of scope

- Re-downloading on top of an existing `--keep-archive` output. If
  the user passes the same URL to a directory that already contains
  the archive, peel still creates `<output>.peel.part` and checks
  the existing `.ckpt`; this is the existing resume logic and
  doesn't need anything new.
- An automatic "guess the right mode" mode. Modes are explicit
  flags; defaults are explained in `--help` and the README.
- An async tee that writes the decoded bytes to one consumer and
  the compressed bytes to another consumer in lock-step. Today the
  decoder reads from the sparse file via `pread`; in
  `--keep-archive` it keeps doing exactly that, and the puncher is
  the *only* thing that goes away. No new IO topology.

---

## §1. Prerequisite: collapse `-C`/`-o` into a unified `-o`

**What**: remove `-C/--output-dir`. The single `-o/--output-file`
flag accepts either a file path or a directory path; the format
determines which shape is expected, and a trailing `/` (or an
existing-directory check) disambiguates when the format alone
isn't enough.

**Why first**: `--no-extract` (§2) and `--keep-archive` (§3) both
talk about "where things land on disk." A clean answer requires
one unambiguous output flag. The collapse also removes the existing
`-C`/`-o` mutex, which was always a proxy for "the format dictates
output shape" — better to encode that constraint directly.

**Resolution rules** for `-o <path>`:

1. **Tree-bearing formats** (tar, zip, rar, 7z, anything wrapped
   over tar — `.tar.zst`, `.tar.xz`, etc.):
   - `<path>` must resolve to a directory.
   - Accepted: a trailing `/`, OR an existing directory, OR a
     non-existent path (in which case peel creates the directory).
   - Rejected: an existing regular file at `<path>` — error:
     "format produces a directory tree; `<path>` exists and is a
     regular file. Remove it, or pass a directory path."
2. **Stream-shaped formats** (raw/identity, single-frame `.zst`,
   `.xz`, `.lz4`, `.gz` with no inner tar):
   - `<path>` must resolve to a file.
   - Accepted: a path that does not exist, OR an existing regular
     file (overwritten with a `tracing::warn!`).
   - Rejected: an existing directory at `<path>`, OR a path ending
     in `/` — error: "format produces a single file; `<path>` is a
     directory."
3. **`-o` omitted**: derive from URL basename using the existing
   `default_output_dir`/`default_output_file` logic, with the
   format-shape rule applied: tree formats default to a directory
   named after the URL's stripped basename; stream formats default
   to a file named after the URL basename (with compression suffix
   preserved iff `--no-extract`).
4. **`-o -`** (single dash) is **reserved** but not implemented in
   this plan — stdin/stdout streaming is its own design problem
   (no progress bar, no resume).

**Hard cutover for `-C`**: remove the flag from clap entirely. A
user passing `-C` (or `--output-dir`) gets clap's standard
"unexpected argument" error. To make the migration discoverable,
register a hidden clap arg `-C/--output-dir` that takes any value
and **always errors** with a custom message:

```
error: -C/--output-dir was removed in peel <version>.
       use -o <path>/ instead (trailing slash means directory).
       see CHANGELOG.md for the migration note.
```

No deprecation period, no warning-then-error grace window. peel is
pre-1.0; the surface is allowed to move.

**Sketch**:

1. `src/cli.rs`:
   - Remove `pub output_dir: Option<PathBuf>` and the `args(["output_dir", "output_file"]).multiple(false)` mutex.
   - Repurpose `pub output_file: Option<PathBuf>` to mean
     "user-supplied output path, any shape."
   - Add the `-C/--output-dir` migration-error stub described above.
   - Replace `OutputTarget::File`/`OutputTarget::Dir` resolution
     (today in `src/cli.rs:515-522`) with a single resolver that
     takes `(user_path: Option<PathBuf>, format_shape: FormatShape)`
     and returns `OutputTarget`.
2. `src/decode/registry.rs` (or wherever formats are registered):
   each registered decoder factory exposes a `FormatShape` enum
   (`Tree | Stream`). The resolver in §1 reads this to apply the
   right rules.
3. Affected docs: `README.md`, `--help` text, and the local-extract
   plan (which currently references `-C` in examples — those need
   to be rewritten as `-o <dir>/`).

**Demo**:

- `peel https://h/foo.tar.zst -o out/` → tree at `out/`.
- `peel https://h/foo.bin -o ./foo.bin` → file at `./foo.bin`.
- `peel https://h/foo.tar.zst -o ./foo.bin` → error (tree format,
  file-shaped path).
- `peel https://h/foo.bin -o ./outdir/` → error (stream format,
  directory-shaped path).
- `peel https://h/foo.tar.zst -C out/` → migration error pointing
  to `-o out/`.

---

## §2. `--no-extract`

**What**: skip the extractor entirely. Output the downloaded bytes
to a file (`-o`) or to a default-named file in CWD.

**Why second**: smallest change after the §1 prerequisite. Also
gives us a story for §4 (unknown-format) — the unknown-format
fallback is "do whatever `--no-extract` does."

**Sketch**:

1. `src/cli.rs`: add `pub no_extract: bool` flag (also exposed as
   `--download-only` alias for users coming from aria2c). Validation
   (NEW errors, not "existing" — these mutexes need fresh clap
   rules):
   - With `--format`, `--force-format-from-magic`, or
     `--punch-threshold`: error. These are all extractor knobs;
     nothing extracts in this mode.
   - With `--strict-format` (see §4): error at parse time —
     "`--strict-format` has no effect with `--no-extract` (no
     format detection runs when not extracting)." Per user
     decision; keeps the mental model clean.
   - With `-o <dir>/` or `-o <existing-dir>`: error per §1 rules
     — `--no-extract` always produces a single file.
   - Without `-o`: derive an output path from the URL basename,
     **with the compression suffix preserved** (`default_output_file`
     for stream-shape outputs already keeps it; per §1 the resolver
     selects this path based on the resolved `FormatShape::Stream`).
   - `--sha256` **stays meaningful** — verifying the downloaded
     bytes is exactly the same operation whether or not we extract
     them. No special-casing needed.
2. `src/coordinator.rs`: in `run`, after `download::run` completes,
   branch on `no_extract`:
   - True: rename `<output>.peel.part` → `<output>` (final name).
     Discard the bitmap and `.ckpt`. Done.
   - False: existing extractor pipeline.
3. While download is running with `--no-extract`, **no extractor
   thread is spawned**. The decoder cursor `AtomicU64` is replaced
   by a dummy cursor pinned to `0` — the scheduler's priority
   steering then dispatches chunks in natural order, which is the
   right behaviour for a sequential output file.
4. Hole-punching is disabled in this mode (no decoder means no
   advancing cursor). The `.peel.part` file uses the **existing**
   sparse-creation behavior from `download::run` — verify in
   review; if the current implementation pre-fallocates the full
   size, that's a separate (small) fix in this same PR. The plan
   does not change allocation behaviour for `--no-extract`, it
   just disables the puncher.
5. Checkpoint compatibility: see §5. `--no-extract` writes a
   checkpoint with `mode: NoExtract`; resume verifies the mode
   matches.

**Demo**: `peel https://host/blob.bin --no-extract` downloads a
500 MB file in parallel, kills mid-flight, resumes, completes;
output matches a reference `curl` download bytewise.

---

## §3. `-k`/`--keep-archive`

**What**: extract AND keep the source archive on disk. Optional
value form `-k <path>` lets the user choose where the preserved
archive lands; bare `-k` defaults to the sibling-of-`-o`
convention.

**Why now**: with `--no-extract` and unified `-o` shipped, this is
a small delta — the same "preserve the source file" path, run
alongside the existing extractor pipeline, with hole-punching
disabled.

**Sketch**:

1. `src/cli.rs`: add `pub keep_archive: KeepArchive` (custom type)
   with short alias `-k`. The flag is **value-optional** via clap's
   `num_args = 0..=1`:
   - `-k` (bare) → `KeepArchive::Yes(None)`.
   - `-k <path>` → `KeepArchive::Yes(Some(path))`.
   - flag absent → `KeepArchive::No`.

   Grammar safety: clap parses `-k` followed by a positional
   (the URL) as bare `-k` + URL, not `-k=URL`, because the URL
   isn't a value of `-k` unless attached as `-k=<url>` or
   immediately after `-k`. The plan needs a CLI test that pins
   this:
   - `peel -k https://h/foo.tar.zst` → bare `-k`, URL positional.
   - `peel -k ./archives/foo.zst https://h/foo.tar.zst` → `-k`
     with path, URL positional. **Caveat**: clap may eagerly
     consume the path as `-k`'s value. If grammar conflicts arise,
     fall back to: require `-k=<path>` for the value form, bare
     `-k` for the default. Pick this at implementation time after
     a quick clap experiment.

   Validation:
   - With `--no-extract`: `-k` is redundant — `--no-extract`
     preserves the source bytes by definition. Do **not** error;
     emit a `tracing::info` ("`-k` is implied by `--no-extract`").
   - In local-file mode (see
     [`PLAN_local_file_extract.md`](PLAN_local_file_extract.md)),
     `-k/--keep-archive` is the **opt-out** for destructive default
     behaviour: same flag, same shape, applied to the user-supplied
     local file instead of the downloaded part-file. The bare `-k`
     vs. `-k <path>` distinction does not apply to local mode (the
     archive is already at the user-supplied path).
   - Combining `-k` with `-y/--yes` is fine in local mode (`-k`
     wins; the prompt is moot). `-y` has no effect for HTTP
     sources.
2. **Archive path resolution** (HTTP mode):
   - `-k <path>` explicit → use `<path>` verbatim (parent must
     exist; if `<path>` exists as a regular file, overwrite with a
     `tracing::warn!`; if it exists as a directory, error).
   - `-k` bare → derive from URL basename, placed as a sibling of
     `-o`:
     - `-o ./out/`           → archive at `./foo.tar.zst`
     - `-o ./extract/out/`   → archive at `./extract/foo.tar.zst`
     - `-o ./single.bin`     → archive at `./<url-basename>` in
                               the same directory as `single.bin`
   - `-o` omitted (default output): archive at
     `./<url-basename>` in CWD.
3. `src/coordinator.rs`:
   - Construct a `NoopPuncher` regardless of the `--io-backend`
     choice. (Earlier drafts mentioned a `KeepArchivePuncher`
     newtype for stats clarity — drop that; `NoopPuncher` is fine.)
   - Set the extractor's `punch_threshold` to `u64::MAX` so the
     extractor never even *attempts* a punch — cheaper than
     relying on the puncher's `Unsupported` return.
   - On successful completion, rename `<output>.peel.part` →
     resolved archive path (per §3.2). Don't delete the source.
     The `.ckpt` is cleared.
   - mmap mode: the rename works regardless of `--io-backend`
     (Linux holds the inode, not the path; macOS likewise). No
     special handling needed; add one rename-while-mapped test for
     confidence.
   - Sink-state checkpointing already exists at
     [src/checkpoint.rs:381](src/checkpoint.rs#L381) (`TarSinkState`,
     `TarMemberState`). `-k` reuses it without change; a mid-
     extraction kill resumes from the next tar-member boundary.
4. Disk-buffer behaviour: `--max-disk-buffer` is **ignored** in
   `-k` mode. Without a release mechanism, enforcing it as
   backpressure would stall the download forever once the cap is
   reached (decoder lags, no blocks freed, no progress). Emit a
   warning at start if the flag was passed **explicitly** (detect
   via clap's `ArgMatches::value_source() == CommandLine` —
   *not* via the parsed `Option<u64>` being `Some`, since the
   default is also `Some`). Don't error; the user may be reusing a
   preset.
5. Checkpoint: see §5. `-k` writes `mode: KeepArchive`.

**Demo**: `peel https://host/foo.tar.zst -o out/ -k` produces both
`out/` (extracted) and `./foo.tar.zst` (preserved source) at
completion. Kill mid-extraction, restart, both side-effects
converge to the same final state. Disk-usage assertion: the
source's on-disk footprint equals `Content-Length` at completion
(no holes). Second demo: `peel https://host/foo.tar.zst -o out/ -k
./archives/foo.tar.zst` puts the archive at the explicit path.

---

## §4. Unknown-format handling

**What**: when format detection fails, the binary today aborts. With
`--no-extract` available, we have a useful fallback: download to a
file and let the user sort it out.

**Why this completes the picture**: a user who points peel at a
non-archive URL today gets a confusing "unknown format" error after
the download has happened. With this change, the same invocation
either (a) shows a clear warning and proceeds in download-only mode,
or (b) errors out asking the user to explicitly choose, depending on
how loud we want to be.

**Sketch**:

1. Format detection runs as today (suffix → magic). On miss:
   - **Default behaviour**: log a `tracing::warn!`:
     "no decoder registered for this source; running as
     --no-extract. Pass --no-extract to silence this warning, or
     --format <name> if you know the format." Continue in
     download-only mode. **No-op pipeline change**: this is the same
     code path as §2.
   - **`--strict-format` flag (opt-in)**: error and exit on
     unknown-format detection. For users in CI who want to be told
     when a remote object changed shape unexpectedly. Rejected at
     CLI parse time when combined with `--no-extract` (no detection
     runs in that mode; see §2). Allowed with `-k/--keep-archive`
     (detection still runs in `-k` mode).
2. Format detection happens at HEAD time in HTTP mode (peek the
   first 512 bytes via a `Range: bytes=0-511` GET before scheduling
   the full download). This is a small extension to the existing
   `discover()` path — fetch the prefix when neither the suffix nor
   any caller-provided override resolves to a registered factory.
   In local-file mode (see [`PLAN_local_file_extract.md`](PLAN_local_file_extract.md))
   the prefix is free to peek.

   **Mirror semantics**: when multiple mirrors are configured (via
   `discover_with_mirrors`, [coordinator.rs:827](src/coordinator.rs#L827)),
   the prefix probe goes to the **primary URL only**. Mirrors are
   assumed byte-identical by definition; cross-mirror prefix
   disagreement would already be a fingerprint mismatch caught by
   existing discovery logic.
3. **Edge case**: server doesn't support Range. The prefix-probe
   issues a full GET, reads the first 512 bytes, drops the
   connection. The download then proceeds via the single-stream
   fallback (see [`PLAN_no_range_fallback.md`](PLAN_no_range_fallback.md))
   and re-fetches the body from byte 0. Two GETs of the prefix;
   one full body. Acceptable cost, behind a clear warning.

   **Dependency**: this edge case requires
   [`PLAN_no_range_fallback.md`](PLAN_no_range_fallback.md) to be
   landed. If that plan isn't shipped before §4, peel treats a
   Range-incapable server + unknown format as a hard error at HEAD
   time (same UX as `--strict-format`). Document this gap in
   `--help`.
4. `--format <name>` continues to bypass detection entirely, in
   both modes. `--force-format-from-magic` keeps a real role under
   the new default: detection considers magic only when suffix
   *misses*, so the flag is still needed for the "suffix is
   misleading (mislabeled `.tar.gz` that's actually `.tar.zst`),
   force magic to win" use case. Drop the "redundant" framing;
   the docstring should explain the override-suffix-with-magic
   semantics.

**Demo**:
- `peel https://host/foo.bin` (no archive) → downloads to
  `./foo.bin`, prints a warning, no extraction attempted.
- `peel https://host/foo.bin --strict-format` → errors at HEAD time,
  no full download.
- `peel https://host/foo.bin --no-extract --strict-format` →
  CLI parse error per §2.
- `peel https://host/foo.tar.zst --no-extract` → downloads to
  `./foo.tar.zst`, no warning (explicit intent).
- `peel https://host/foo.tar.zst -k -o out/` → both source and
  tree on disk.

---

## §5. Checkpoint format bump

**What**: encode the chosen mode in the checkpoint so a resume can
detect drift.

**Why now**: §2 and §3 both want this; doing it once with both
modes in mind avoids a second bump.

**Sketch**:

1. `src/checkpoint.rs`: bump `FORMAT_VERSION` from the current 11
   ([checkpoint.rs:198](src/checkpoint.rs#L198)) to **12**. Add a
   `mode: RunMode` enum field (`Extract`, `NoExtract`,
   `KeepArchive`, `LocalDestructive` — the last is consumed by
   [`PLAN_local_file_extract.md`](PLAN_local_file_extract.md) §5
   and shares the same bump so we don't need two version
   transitions).

   Implementation note: `LocalDestructive` could equivalently be
   modeled as `Extract` plus a `source: SourceKind` sibling field.
   The data needed for resume is the same. Author's call at
   implementation time; either is fine.
2. On resume:
   - Checkpoint's `mode == CLI's mode`: proceed as today.
   - Mismatch: `CheckpointError::ModeMismatch { old: …, new: … }`
     with a clear suggestion ("restart with the matching flag, or
     delete `<output>.peel.ckpt` to start over").
3. Multi-mode resume drift is **not** supported. We do not silently
   re-derive what's already on disk; if the user wanted a different
   mode they should have asked for one from the start.
4. Reading older checkpoints: the previous-version reader path
   already exists for prior version transitions; apply the same
   forward-compat discipline (versions ≤11 decode as
   `mode: Extract` synthetically). Verify the
   `PLAN_multi_url_source.md` reference at implementation time —
   it may be stale (this plan was drafted when `FORMAT_VERSION`
   was lower).

**Demo**: round-trip property test, mismatch test, forward-compat
test (v11 file decoded by v12 reader as `mode: Extract`; v12 file
rejected cleanly by a v11 reader).

---

## §6. CLI help & README

**What**: one combined section that documents the modes together,
with a short table like the one at the top of this plan. Also
documents the `-C` removal.

**Why now**: the modes are easier to explain together than apart.
The user mental model is "what does peel do with the archive after
the download?" — answering that question once, in one place, beats
three scattered paragraphs.

**Sketch**:

1. README: new "Download modes" section. Include the table. Include
   one example invocation per mode. Link to the resume semantics.
   Add a "Migration: `-C` was removed" callout near the top of the
   CLI section.
2. `--help` output for the flags cross-references siblings
   ("see `--keep-archive` for the variant that also extracts";
   `-o` help text mentions trailing-slash semantics).
3. CHANGELOG.md entry documents the `-C` removal with the
   migration command (`-C foo/` → `-o foo/`).

**Demo**: the doctest at the top of the README runs each example
against a mock server and asserts the expected on-disk state.
Markdown code blocks in the README are real doctests via the
existing `mdbook-runnable`-style harness (or, if no such harness
exists today, they're prose-only with an integration test in
`tests/cli/` covering the same scenarios — verify at
implementation time).

---

## What "feature done" means

1. All four CLI changes (unified `-o`, `--no-extract`, `-k`,
   `--strict-format`) work end-to-end, including resume after
   `kill -9` at random points.
2. The mode table at the top of this doc matches the binary's
   behaviour exactly. CI gate: a smoke test enumerates all four
   rows of the table and asserts the post-conditions.
3. The unknown-format default behaviour is *visible* (warning on
   stderr, mentioned in `--help`) and easily silenced
   (`--no-extract` or `--format`).
4. **Unified `-o` enforcement is tight**: invalid path-shape
   combinations (tree format + file path, stream format + dir
   path) error at coordinator entry, not partway through the
   download.
5. **`-C` migration error** fires for any `-C` / `--output-dir`
   invocation with a clear suggestion of the equivalent `-o`
   form.
6. Checkpoint v12 round-trips, refuses cross-mode resume with a
   clear error, and decodes v11 files synthetically as
   `mode: Extract`.
7. No behavioural change in the default extract mode (regression
   budget: 0 bytes diff in the extracted tree for any existing
   test fixture).
8. README documents the modes in one section with the table, and
   has a top-of-CLI-section `-C` migration callout.
