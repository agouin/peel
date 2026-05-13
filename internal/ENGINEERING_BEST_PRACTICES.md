# Engineering Best Practices

This document is the *softer* counterpart to `ENGINEERING_STANDARDS.md`. The
standards doc is a list of rules; this one is a guide to what idiomatic,
maintainable code looks like in this repo. Treat it as strong default
guidance — deviate when you have a real reason, document the deviation.

---

## 1. Idiomatic Rust in this codebase

### 1.1 Prefer iterators to indexed loops

```rust
// Good
let total: u64 = chunks.iter().map(|c| c.len as u64).sum();

// Avoid
let mut total = 0u64;
for i in 0..chunks.len() {
    total += chunks[i].len as u64;
}
```

The exception: when index arithmetic carries semantic weight (e.g., "chunk
index N corresponds to byte offset N * CHUNK_SIZE in the source file"),
indexing makes that relationship visible and is preferred.

### 1.2 Use newtypes for unit-bearing primitives

Byte offsets, chunk indices, frame numbers, file sizes — these all look
like `u64` to the compiler, but they are not interchangeable. Wrap them:

```rust
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct ByteOffset(pub u64);

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct ChunkIndex(pub u32);
```

Yes, this is verbose. Yes, it catches a class of bugs (passing a chunk
index where an offset was expected) at compile time that would otherwise
take hours to track down at runtime. Worth it.

### 1.3 Make illegal states unrepresentable

If a `DownloadState` can only be `Pending`, `InFlight { worker_id }`, or
`Complete { etag }`, model it as an enum, not as three optional fields on
a struct. The compiler will then enforce that you handle every case.

### 1.4 `Result` and `?` everywhere

Don't write functions that "can't fail" if there's any IO, parsing,
arithmetic on untrusted input, or syscall involved. Return `Result`,
propagate with `?`, let the caller decide.

### 1.5 Borrowing over ownership

Default function signatures take `&T` or `&mut T`, not `T`. Take ownership
only when you genuinely need to store, move, or drop the value. This makes
the API more flexible and avoids unnecessary clones.

### 1.6 `&str` over `&String`, `&[T]` over `&Vec<T>`

The slice forms are strictly more general. Use them in function signatures
unless you specifically need to mutate the underlying container.

### 1.7 `impl Trait` for return types when the concrete type is an
implementation detail

```rust
// Good - caller doesn't care about the concrete iterator type
fn pending_chunks(&self) -> impl Iterator<Item = ChunkIndex> + '_ {
    self.chunks.iter().filter(|c| c.is_pending()).map(|c| c.index)
}
```

But return concrete types from public API where the type *is* part of the
contract.

---

## 2. Module structure

### 2.1 One concept per module

A module owns one concept and the types/functions that directly support it.
If a module has two unrelated public types, it's two modules.

### 2.2 Public surface is small and deliberate

The default visibility is private. Promote to `pub(crate)` when another
module in the crate needs it. Promote to `pub` only when external users
of the library need it. Each `pub` item is a commitment.

### 2.3 The `mod.rs`-free layout

Use `foo.rs` + `foo/` directory rather than `foo/mod.rs`. The IDE
experience is better and the parent module's contents are easier to
locate.

```
src/
  download.rs           // pub mod download; declarations
  download/
    scheduler.rs
    worker.rs
    bitmap.rs
```

### 2.4 Re-export at module roots, not from `lib.rs`

`lib.rs` declares the top-level modules. Each module's root file
re-exports what it wants visible. Don't pile re-exports in `lib.rs`.

---

## 3. Error design

### 3.1 Errors are documentation

A good error type tells you (a) what failed, (b) what we were trying to
do, (c) how to remediate. Bad: `IoError`. Good:

```rust
#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    #[error("server returned {status} for range request {range:?} of {url}")]
    UnexpectedStatus { url: String, range: ByteRange, status: u16 },

    #[error("server does not support range requests (no Accept-Ranges: bytes for {url})")]
    RangesUnsupported { url: String },

    #[error("source changed during download (etag was {expected}, now {actual})")]
    SourceChanged { expected: String, actual: String },

    // ... etc
}
```

The variants are specific. The messages are diagnosable. The structured
fields are queryable in tests.

### 3.2 Don't lose context when wrapping

If you wrap a lower-level error, preserve it via `#[source]`:

```rust
#[error("failed to write chunk {index} to {path}")]
ChunkWriteFailed {
    index: ChunkIndex,
    path: PathBuf,
    #[source]
    source: std::io::Error,
}
```

The `Display` chain then walks down naturally, and the original errno is
recoverable via `error.source()`.

### 3.3 At the binary boundary, add context with `anyhow`

```rust
fn run(args: Args) -> anyhow::Result<()> {
    let downloader = Downloader::new(&args.url)
        .context("creating downloader")?;
    downloader.download()
        .with_context(|| format!("downloading {}", args.url))?;
    Ok(())
}
```

The user sees a chain like:
```
Error: downloading https://example.com/foo.tar.zst
Caused by:
    0: requesting range 1048576-2097151
    1: connection reset by peer (os error 104)
```

That's diagnosable. A bare `Error: connection reset by peer` is not.

---

## 4. Concurrency style

### 4.1 Threads have names and roles

```rust
std::thread::Builder::new()
    .name("download-worker-3".into())
    .spawn(move || worker.run())?;
```

When a thread panics or shows up in a backtrace, the name tells you
immediately what it was doing.

### 4.2 Channels for fan-out, shared state for read-mostly data

The download scheduler hands out chunk assignments to workers via a
channel. The completion bitmap is read-mostly (workers update one bit on
completion; the decoder polls the whole structure) and lives behind a
`RwLock` or, better, an `AtomicU64`-based bitmap.

### 4.3 Use scoped threads

`std::thread::scope` removes whole categories of `'static` lifetime
acrobatics and `Arc` boxing. Use it whenever the threads' lifetimes are
bounded by a single function.

### 4.4 Bounded everything

Every channel has a capacity. Every queue has a maximum length. Every
buffer pool has a fixed size. Unbounded resources are a recipe for
unexpected memory usage under load.

### 4.5 Shutdown is part of the design

Every thread has a defined way to be told "stop, the operation is being
cancelled or has failed elsewhere." Usually this is a `CancellationToken`
(an `Arc<AtomicBool>` we check at safe points) or closing a channel. Don't
write threads that can only stop by completing their work.

---

## 5. Testing patterns

### 5.1 Arrange-Act-Assert, with whitespace

```rust
#[test]
fn bitmap_marks_chunk_complete() {
    // Arrange
    let mut bitmap = ChunkBitmap::new(100);

    // Act
    bitmap.mark_complete(ChunkIndex(42));

    // Assert
    assert!(bitmap.is_complete(ChunkIndex(42)));
    assert!(!bitmap.is_complete(ChunkIndex(41)));
}
```

The blank lines aren't decorative; they make the structure scannable.

### 5.2 Test fixtures in code, not on disk

Tests that need a compressed archive build it in the test:

```rust
fn build_test_archive() -> Vec<u8> {
    let raw = b"hello world".repeat(10_000);
    zstd::encode_all(&raw[..], 3).unwrap()
}
```

This keeps the repo small and the test self-documenting. The exception is
when you're explicitly testing handling of a *specific* malformed file
discovered in the wild — keep that fixture under `tests/fixtures/` with a
README explaining where it came from.

### 5.3 Property tests for invariants

For any function with non-trivial input space, ask: what's the invariant?
Then write a property test:

```rust
proptest! {
    #[test]
    fn checkpoint_roundtrips(state in any::<CheckpointState>()) {
        let bytes = state.encode();
        let decoded = CheckpointState::decode(&bytes).unwrap();
        prop_assert_eq!(state, decoded);
    }
}
```

The point isn't to find specific bugs; it's to encode the invariant in
machine-checkable form so future refactors can't break it silently.

### 5.4 Test the failure paths

For every error variant a function can return, there's a test that
provokes that variant. If you can't construct a test that triggers a
particular error, that error variant is probably dead code or
unreachable, and should be removed or its unreachability documented.

### 5.5 Local HTTP server for download tests

We spin up a `std::net::TcpListener` on `127.0.0.1:0` (auto-assigned
port) inside tests, run a tiny request handler that supports just enough
HTTP for our needs (HEAD, GET with `Range`, ETag echo, configurable
failure modes), and point the downloader at it. This lets us test:

- Range requests work
- Server changes mid-download (different ETag) is detected
- Server returns 503 mid-download is handled
- Connection drops mid-chunk are retried
- Slow servers don't deadlock the worker pool

All without network flakiness. The mock server is its own module under
`tests/support/`.

---

## 6. Documentation patterns

### 6.1 The doc comment formula

```rust
/// One-line summary, ending in a period.
///
/// Optional longer paragraph explaining context, motivation, or
/// non-obvious behavior. Reference related items with [`Self::other`]
/// or [`other_module::Type`].
///
/// # Errors
/// Returns [`MyError::Foo`] if X. Returns [`MyError::Bar`] if Y.
///
/// # Panics
/// Panics if `chunk_size == 0`.
///
/// # Examples
/// ```
/// # use peel::ChunkBitmap;
/// let mut b = ChunkBitmap::new(10);
/// b.mark_complete(ChunkIndex(3));
/// assert!(b.is_complete(ChunkIndex(3)));
/// ```
pub fn mark_complete(&mut self, index: ChunkIndex) { ... }
```

### 6.2 Module-level docs

Every module starts with `//!` describing what the module is *for* and
how its pieces fit together. A new contributor reading `download.rs`
should understand the design from the top of the file alone.

### 6.3 Comment the *why*

Code shows what; comments explain why. Especially:

```rust
// We punch the source file at frame boundaries, not continuously,
// because anything we punch is unrecoverable. Punching only behind
// the most recent durable checkpoint means a crash here loses at
// most one frame of work.
self.puncher.punch(fd, last_punched, gap)?;
```

That comment will save someone an hour of "why isn't this more
aggressive?" thinking, two years from now.

---

## 7. CLI ergonomics

### 7.1 The CLI is for humans first

- Default output is concise: progress to stderr, paths to stdout.
- `-v` raises log level; `-vv` raises further. `--quiet` silences all
  but errors.
- Errors print the chain, not just the top. Use the `anyhow` Display
  format that `{:#}` gives you.
- Long-running operations show progress. Silence is anxiety-inducing.

### 7.2 But scriptable too

- Exit codes are meaningful: 0 success, 1 generic failure, 2 invalid
  usage, others reserved.
- `--json` gives machine-readable progress and result on stdout.
- No interactive prompts in non-tty mode. Detect with `IsTerminal`.

### 7.3 Resume must be obvious

If a user runs the same command twice and a checkpoint exists, we resume
by default and tell them we're doing so. `--no-resume` to opt out.
`--restart` to wipe the checkpoint and start over.

---

## 8. What "done" looks like

A task is done when:

1. The code does what the plan section described.
2. Tests pass: unit, integration, doc, and any relevant property/fuzz
   targets touched by the change.
3. `cargo fmt && cargo clippy -- -D warnings` are clean.
4. New public items have doc comments.
5. The change is covered by a test that would fail without it.
6. Logs at `info` level tell the story of what the code did.
7. The commit message references the plan section and explains why.

Not before all six.
