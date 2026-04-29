# AGENTS.md

Workflow rules for AI coding agents (Claude Code, Cursor, Aider, etc.) working
in this repo. These are about *process*, not code style — for code style see
`docs/ENGINEERING_STANDARDS.md` and `docs/ENGINEERING_BEST_PRACTICES.md`.

## Before you start a task

1. Read the section of `docs/PLAN.md` that covers what you're about to do.
   Don't work ahead — the plan is sequenced for a reason (earlier modules
   are dependencies of later ones, and earlier modules are easier to verify
   in isolation).
2. Re-read `docs/ENGINEERING_STANDARDS.md` if it's been more than a few
   tasks since you last did. The dependency policy in particular is easy
   to forget.
3. Check the existing code for prior art. If a similar pattern already
   exists in the repo, follow it. Consistency beats cleverness.

## Asking vs. acting

**Act without asking** when:
- The task is mechanical (rename, refactor with no semantic change, fix a
  clippy warning, add a missing test).
- The plan or standards docs unambiguously specify what to do.
- You're exploring with read-only tools (running `cargo check`, reading
  files, running tests).

**Ask before acting** when:
- The task requires adding a new dependency. (Standards doc requires
  human approval; do not skip this.)
- The task seems to require `unsafe` code. Propose the design first.
- You discover a discrepancy between the plan and what the code needs.
  Don't silently "fix" the plan; flag it.
- You're about to make a change >300 lines or touching >5 files in one
  commit. Propose the breakdown first.
- The user's request seems to conflict with a standards doc rule. Ask
  which wins; don't guess.

**Never do without asking**:
- Add a runtime dependency not on the allowlist.
- Introduce `async` runtimes other than the one chosen in the plan.
- Reformat or "clean up" files unrelated to your task.
- Commit changes to `docs/PLAN.md` or `docs/ENGINEERING_STANDARDS.md`.
  These are human-curated.

## Commit hygiene

- **One logical change per commit.** "Add ranged downloader + add tests for
  it" is one commit. "Add ranged downloader + refactor error types" is two.
- Commit message format: imperative subject ≤72 chars, blank line, body
  explaining *why* (not *what* — the diff shows what). Reference the plan
  section when relevant: `Implements PLAN.md §3.2`.
- Run `cargo fmt && cargo clippy -- -D warnings && cargo test` before every
  commit. If any of those fail, the commit is not ready.
- Never commit `target/`, `.env`, or files in `.gitignore`. Never commit
  generated test fixtures larger than a few KB; generate them in the test.

## When you get stuck

Stuck = you've tried two reasonable approaches and neither works, OR you're
about to do something that contradicts a standards doc rule, OR you're
guessing at API behavior.

Do **not**:
- Add `#[allow(dead_code)]` or `#[allow(clippy::...)]` to make warnings go
  away. Fix the underlying issue or ask.
- Add a dependency to "make it work" (see Dependency Policy).
- Stub out functionality with `todo!()` and pretend the task is done.
  `todo!()` is fine as a *deliberate* placeholder when the plan says
  "implement this in the next task," but call it out in your response.
- Disable failing tests. If a test is wrong, fix the test. If the code is
  wrong, fix the code. If you can't tell which, ask.

Do:
- Summarize what you've tried and what failed.
- Quote the relevant docs sections that constrain the solution.
- Propose 2-3 paths forward with tradeoffs.
- Wait for direction.

## Working with the test suite

- Tests are not optional. Every public function gets a unit test; every
  module gets at least one integration test exercising its public API.
- A bug fix without a regression test reproducing the bug is incomplete.
- If the existing tests don't catch a class of bugs you're worried about,
  add property tests or fuzz targets. See `ENGINEERING_BEST_PRACTICES.md`
  §Testing for the patterns we use.
- `cargo test` must pass on every commit. `cargo test --release` and any
  `--ignored` long-running tests must pass before merging a plan section.

## Communicating with the human

- When you finish a task, summarize: what you did, what you tested, what
  you didn't do that someone might expect you to have done, and what
  should happen next per the plan.
- Don't editorialize the codebase ("this code is messy"). If you have
  concerns, file them as tracked TODOs with rationale.
- If you discover the plan is wrong or incomplete, say so explicitly and
  propose a revision. Don't quietly diverge from it.

## Things that are NOT your job

- Choosing the project's overall architecture. The plan defines it.
- Deciding which optimizations to pursue. `OPTIMIZATIONS.md` is a deferred
  list, not a TODO list.
- Adding "nice to have" CLI flags, logging verbosity levels, config file
  formats, etc. unless the plan or the user asks for them.
- Migrating to newer/shinier crates without a documented reason.

The point of these rules is to keep the project on track and the codebase
coherent across many sessions. When you follow them, the human reviewing
your output spends time on actual decisions instead of cleanup.
