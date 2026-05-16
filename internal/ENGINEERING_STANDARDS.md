# Engineering Standards

These are **non-negotiable rules** for code in this repository. Violations
should be caught in review (or by CI, where possible). For *style* and
*pattern* guidance — the softer "what does idiomatic look like" — see
`ENGINEERING_BEST_PRACTICES.md`.

If you propose to violate a rule here, the burden of proof is on you, and the
violation must be approved by a human and documented in the code with a
comment explaining why.

---

## 1. Toolchain & Edition

- **Rust edition: 2021** (until we explicitly migrate to 2024).
- **MSRV (minimum supported Rust version): stable - 2 releases.** Use
  `rust-toolchain.toml` to pin. Bump deliberately, not incidentally.
- **Format with `cargo fmt`** using the default rustfmt config. No
  `.rustfmt.toml` overrides without discussion.
- **Lint with `cargo clippy --all-targets --all-features -- -D warnings`.**
  CI fails on any clippy warning. Don't `#[allow]` your way out; fix the
  code or, if the lint is genuinely wrong for our case, `#[allow]` at the
  narrowest possible scope with a comment explaining why.

---

## 2. Dependency Policy

This is the rule most likely to be tempting to bend. Don't.

### 2.1 The bias is toward std

Before reaching for a crate, ask: can `std` do this? Can a 50-line
hand-rolled implementation do this? If yes, prefer that. We are building a
systems utility; surface area in the dependency tree is a liability.

### 2.2 Allowlist

Crates pre-approved for use, with the role they fill:

| Crate          | Role                                        | Notes                                |
|----------------|---------------------------------------------|--------------------------------------|
| `zstd`         | zstd compression/decompression              | Bindings to upstream libzstd         |
| `flate2`       | gzip/deflate                                | Use the `rust_backend` feature       |
| `xz2`          | xz / LZMA decompression                     | Bindings to upstream liblzma; `PLAN_v2.md` §3 |
| `lz4_flex`     | lz4 frame decompression                     | Pure Rust; `PLAN_v2.md` §4           |
| `io-uring`     | io_uring submission/completion API          | Linux only; sync API only — no async runtime; `PLAN_v2.md` §7 |
| `windows-sys`  | Microsoft-maintained Win32 bindings         | Windows only; declared in `[target.'cfg(windows)'.dependencies]` so non-Windows builds are unchanged; load-bearing for `FSCTL_SET_SPARSE`/`FSCTL_SET_ZERO_DATA`, `SetConsoleCtrlHandler`, console-mode and rename primitives; `PLAN_v3_windows.md` §0.1 |
| `thiserror`    | Library error type derivation               | Library code only                    |
| `anyhow`       | Application error type                      | Binary/CLI boundary only             |
| `clap`         | CLI argument parsing                        | Use `derive` feature                 |
| `tracing`      | Structured logging                          | Replace `println!` debugging         |
| `tracing-subscriber` | Tracing setup at binary boundary       | Binary only                          |
| `hyper`        | HTTP/1.1 + HTTP/2 protocol implementation   | Confined to `http::client`; see §2.3 |
| `hyper-util`   | hyper connector + legacy pooled client      | Confined to `http::client`; see §2.3 |
| `hyper-rustls` | rustls TLS connector for hyper, with ALPN   | Confined to `http::client`; see §2.3 / §2.4 |
| `http`         | hyper's request/response/header types       | Confined to `http::client`           |
| `http-body-util` | body adapters (`BodyExt::frame`, `Empty`) | Confined to `http::client`           |
| `bytes`        | hyper's body byte buffer type               | Confined to `http::client`           |
| `tokio`        | current-thread runtime owned by `http::Client` | `rt`, `net`, `time`, `macros` features only; see §2.5 |
| `tempfile`     | Test scratch files                          | Dev-dependency only                  |
| `sha2`         | SHA-256 reference for cross-checking tests  | Dev-dependency only — runtime SHA-256 is hand-rolled in `hash/sha256.rs`; `PLAN_v2.md` §10 |

`h2` arrives transitively via `hyper`'s `http2` feature; it is not a
direct dependency and does not need its own row.

That's the list. **Anything not on this list requires human approval before
adding to `Cargo.toml`.** Approval criteria:

1. Does std or an existing dependency cover this? If yes, no.
2. Is the crate maintained, audited, and widely used? (Rough proxies:
   >1M downloads/month, recent commits, multiple maintainers.)
3. Does it pull in a large transitive tree? Run `cargo tree` and look.
4. Is the role it fills truly load-bearing (compression algorithm, OS
   bindings) or just convenience (a slightly nicer API)?

The only acceptable reason to add a dependency is "we genuinely cannot
write this ourselves at acceptable quality." Convenience is not a reason.

### 2.3 HTTP client: hyper-based, ALPN-negotiated H1/H2

The HTTP client is built on `hyper` + `hyper-util` + `hyper-rustls`, with
ALPN auto-negotiating between HTTP/1.1 and HTTP/2 per origin. We
deliberately do **not** depend on higher-level wrappers (`reqwest`,
`ureq`, etc.) — `hyper-util`'s `legacy::Client` is the highest level we
build on; everything above it (redirect handling, the
`HEAD`/`get_full`/`get_range` shape, `UnexpectedStatus` checks, the
`Read`-shaped body adapter that callers actually consume) stays in
`http::client` so the wire-level behavior we depend on remains
auditable.

The `hyper` family is confined to the `http::client` module. Code outside
that module does not import `hyper`, `http`, `bytes`, or `tokio`; it
sees the same sync `Client` / `Response` / `BodyReader<R: Read>` shape
as before, and that boundary is enforced by review.

**Historical note.** Before 2026-04-30 we maintained a hand-rolled
HTTP/1.1 implementation over `std::net::TcpStream` + `rustls`. It was
replaced in order to add HTTP/2 support without writing a second wire
format by hand; see `OPTIMIZATIONS.md §O.17`.

### 2.4 TLS exception

`rustls` + `webpki-roots` is approved for TLS, because writing a TLS stack
is not a reasonable use of human time and is genuinely dangerous to get
wrong. This is the one place we accept a large dependency for safety
reasons.

### 2.5 Async runtime

The codebase is **synchronous**. Worker-pool concurrency uses
`std::thread` and `std::sync` primitives. Modules outside `http::client`
do not use `async fn`, do not import `tokio`, and do not see `Future`
types in their public APIs.

The single exception is `http::client`, which owns a current-thread
`tokio::runtime::Runtime` purely as plumbing for `hyper`. The runtime is
constructed inside `Client`, never escapes it, and every public method
on `Client` is a synchronous `fn` that `block_on`s internally. Callers
remain blocking-IO consumers reading a `BodyReader<R: Read>`. The tokio
features enabled (`rt`, `net`, `time`, `macros`) are the minimum hyper
needs; we do not enable `rt-multi-thread`.

Any proposal to broaden tokio's footprint beyond this confinement is a
standards change and must be amended here, not done piecewise.

---

## 3. Error Handling

### 3.1 Library code

- Define a typed error per module using `thiserror`. Errors should carry
  enough context that the message alone is debuggable (paths, offsets,
  underlying errno, etc.).
- Never return `Box<dyn Error>` from a library function.
- Never return `String` as an error type.
- Use `#[from]` sparingly — only when the conversion is genuinely
  unambiguous. Otherwise wrap explicitly so the error path is greppable.

### 3.2 Binary code

- The binary entry point (`main.rs`) returns `anyhow::Result<()>`.
- Use `anyhow::Context` (`.context("opening source file")?`) liberally to
  add a trail of where errors occurred.

### 3.3 Panics

- `unwrap()` and `expect()` are **forbidden in non-test code** unless
  immediately preceded by a comment of the form:

  ```rust
  // INVARIANT: <reason this cannot panic>
  let x = foo.unwrap();
  ```

  or for true safety invariants:

  ```rust
  // SAFETY: <invariant>
  let x = unsafe { ... };
  ```

- `panic!()`, `unreachable!()`, and `todo!()` are likewise forbidden in
  shipping code paths. `unreachable!()` may appear with the same comment
  discipline as `unwrap()`. `todo!()` is acceptable only as a deliberate
  placeholder during multi-commit work, and must be removed before the
  containing task is marked done.
- Integer overflow: use `checked_*`, `saturating_*`, or `wrapping_*` —
  whichever is *semantically correct* for the operation. Never rely on
  release-mode wrapping by accident. For arithmetic on byte offsets and
  sizes, `checked_*` is almost always right.

---

## 4. Unsafe Code

- All `unsafe` blocks require an `// SAFETY:` comment immediately above,
  enumerating every invariant relied on.
- Prefer `safe` wrappers over scattered `unsafe`. If `unsafe` is needed
  for FFI or a syscall, wrap it in a `safe` function with documented
  preconditions, and put the `unsafe` inside.
- New `unsafe` code requires human review before merging. Do not slip
  `unsafe` into a large diff hoping no one notices.

---

## 5. Testing

### 5.1 Coverage requirements

- **Every public function in a library module has at least one unit test.**
- **Every module has at least one integration test** in `tests/` exercising
  its public API end-to-end.
- **Every bug fix includes a regression test** that fails before the fix
  and passes after.
- **Coverage target: 80% line coverage** for library code, measured by
  `cargo llvm-cov`. Below 80% blocks merge of a plan section.
- **Critical paths** (checkpoint serialization, frame boundary detection,
  hole punching, range request reassembly) target **95%+** and have
  property tests, not just example-based tests.

### 5.2 Test categories we use

- **Unit tests** (`#[cfg(test)] mod tests`): fast, narrow, no IO beyond
  `tempfile`. Run on every commit.
- **Integration tests** (`tests/`): exercise public API across module
  boundaries. May use `tempfile`, may bind to localhost, may use real
  compression libraries. Run on every commit.
- **Property tests** (`proptest` or hand-rolled): for code where the input
  space is large and adversarial — checkpoint serialization round-trips,
  range coalescing, bitmap operations.
- **Fuzz tests** (`cargo fuzz`): for parsers and decoders we touch, even
  when we're using a battle-tested upstream library, because *our framing*
  around it is new code. Required for: HTTP response parsing, checkpoint
  file parsing, frame boundary detection.
- **Crash tests**: for the resume path specifically. A test harness that
  spawns the utility, kills it at random points, and verifies that
  resuming produces byte-identical output to a clean run. This is a
  category we own and maintain; see PLAN §5.

### 5.3 What good tests look like

- A test name describes the behavior, not the function. Good:
  `resume_after_crash_mid_frame_produces_identical_output`. Bad:
  `test_resume`.
- Each test asserts one behavior. If you have ten asserts, you probably
  have ten tests.
- Tests do not depend on each other or on execution order. No shared
  global state. No "set up fixture in test A, read it in test B."
- Tests do not rely on network access except for tests explicitly marked
  `#[ignore]` and run in a separate CI lane. The HTTP client is tested
  against a local server we spin up in the test process.

---

## 6. Concurrency

- **No data races.** Rust's type system enforces this for safe code; if
  you reach for `unsafe` to bypass it, see §4.
- **Lock ordering**: when multiple locks must be held, document the order
  in a comment at each acquisition site. Lock ordering bugs are the
  hardest to find; make them grep-able.
- **No `Mutex<T>` where `Atomic*` will do.** Atomics are cheaper and
  harder to misuse.
- **No `Arc<Mutex<T>>` shared across many threads as the default pattern.**
  Prefer message-passing (`std::sync::mpsc` or a hand-rolled bounded
  channel) when threads need to coordinate. Shared mutable state is a
  last resort.
- **Channels have bounded capacity.** Unbounded channels are how memory
  leaks become OOMs.

---

## 7. Performance & Allocations

- **Avoid allocation in hot loops.** The download → punch → checkpoint
  loop runs frequently; preallocate buffers, reuse them.
- **Don't `.clone()` casually.** Each clone is a deliberate decision
  reviewers can question.
- **Don't `.to_string()` to "make types match."** Fix the types.
- **Benchmarks for performance-sensitive code** use `cargo bench` (criterion
  is allowed for this purpose only, as a dev-dependency). Performance
  claims in commits or comments must be backed by benchmark output.

---

## 8. Documentation

- **Every public item has a doc comment.** Modules, types, functions,
  fields, variants. `#![deny(missing_docs)]` is set on the library crate.
- **Doc comments include an example** for non-trivial public functions,
  enforced by `cargo test --doc`.
- **`# Errors` and `# Panics` sections** on functions that can do either,
  describing under what conditions.
- **`# Safety` section** on every `unsafe fn`.

---

## 9. File Layout & Naming

- Snake_case file and module names. No `mod.rs` files; use the
  `name.rs` + `name/` directory pattern instead.
- One primary type per file. Helper types may live alongside if they're
  truly subordinate.
- Tests for `foo.rs` live in a `mod tests` at the bottom of `foo.rs`.
- Integration tests in `tests/` are named `test_<area>.rs`.

---

## 10. Logging

- Use `tracing` with structured fields. Never `println!` or `eprintln!`
  for diagnostic output (CLI user-facing output is fine via `println!`
  in `main.rs` and friends).
- Log levels: `error` = the operation failed and we're returning an
  error; `warn` = something recoverable happened the user should know
  about; `info` = normal milestone events (download started, extraction
  complete); `debug` = per-chunk progress, useful for diagnosis;
  `trace` = per-syscall, off by default even at `--verbose`.
- No PII or secrets in logs. URLs are fine; auth tokens, headers
  containing credentials, and request bodies are not.

---

## CI gates

A pull request is not mergeable unless all of these pass:

1. `cargo fmt --check`
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo test --all-features`
4. `cargo test --release --all-features` (catches release-mode-only bugs)
5. `cargo test --doc`
6. `cargo llvm-cov --fail-under-lines 80`
7. `cargo deny check` (license + advisory audit; config in `deny.toml`)
8. The crash-test suite for any change touching download, decoder, or
   checkpoint code.

If a gate is genuinely wrong for a particular change, ask before
disabling it.
