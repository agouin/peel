# CLAUDE.md

This file is read by Claude Code at the start of every session. Its job is to
**point you at the right docs**, not to repeat them.

## What this project is

`peel` is a Rust CLI utility for **streaming, resumable, space-efficient
extraction of compressed archives downloaded over HTTP**. It combines:

- Parallel ranged HTTP downloads (like aria2c)
- In-flight streaming decompression (decoder consumes prefix while download
  continues at suffix)
- `fallocate(PUNCH_HOLE)` to release blocks of the compressed file as the
  decoder advances past them
- Frame-aligned checkpointing so a `kill -9` mid-extraction can resume
  exactly where it left off

The end result: download a 10 GB `.tar.zst`, get the extracted contents, never
use more than ~300 MB of disk for the compressed side, and survive crashes.

## Read these before writing code

In this order. Don't skip.

1. **`docs/PLAN.md`** — what we're building, in what order. The MVP scope is
   deliberately tight; resist scope creep.
2. **`docs/ENGINEERING_STANDARDS.md`** — non-negotiable rules: dependency
   policy, error handling, unsafe code, formatting, testing thresholds.
3. **`docs/ENGINEERING_BEST_PRACTICES.md`** — idiomatic Rust patterns,
   module structure, concurrency style, what "good" looks like in this repo.
4. **`AGENTS.md`** — workflow rules for AI coding agents (commit hygiene,
   what to do when stuck, when to ask vs. when to act).
5. **`docs/OPTIMIZATIONS.md`** — explicitly **out of scope** for now. Read
   only so you don't accidentally implement something from this list and
   bloat the MVP.

## House rules summary

These are the points most likely to catch you out. Full rationale in the
standards docs.

- **Std-lib first, vetted crates second, novel deps almost never.** See
  `ENGINEERING_STANDARDS.md` §Dependency Policy for the allowlist and the
  approval process.
- **No `unwrap()` or `expect()` in non-test code** unless accompanied by a
  `// SAFETY:` or `// INVARIANT:` comment proving it cannot panic.
- **No `unsafe` without an `// SAFETY:` block** explaining every invariant
  the caller and callee rely on.
- **Errors are typed.** `thiserror` for library errors, `anyhow` only at the
  binary boundary. Never `Box<dyn Error>` in library code.
- **Tests live next to code** (`#[cfg(test)] mod tests`), integration tests
  in `tests/`. Coverage thresholds in `ENGINEERING_STANDARDS.md`.
- **Format with `cargo fmt`, lint with `cargo clippy -- -D warnings`** before
  every commit. CI enforces both.

## When in doubt

If a question is answered by one of the docs above, follow the doc. If two
docs disagree, the standards doc wins; flag the inconsistency in your reply
so a human can fix it. If no doc covers your question, **ask before
implementing** — see `AGENTS.md` §Asking vs. Acting.
