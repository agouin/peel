# Installation

`peel` is a single statically-linked binary. It has no runtime dependencies
beyond a working `libc`, and on Linux a 5.6+ kernel for the `io_uring`
fast paths. Older kernels fall back automatically.

## From source (Cargo)

The currently-supported route. The crate name on crates.io is `peel-rs`.
The installed binary is `peel`.

```sh
cargo install peel-rs --locked
```

The MSRV is pinned in [`rust-toolchain.toml`](https://github.com/agouin/peel/blob/main/rust-toolchain.toml);
a recent stable Rust (1.93+) is sufficient.

### Building from a checkout

```sh
git clone https://github.com/agouin/peel
cd peel
cargo build --release
./target/release/peel --help
```

### Cargo features

| Feature | Default | What it enables |
| --- | --- | --- |
| `rar` | **on** | RAR5 and legacy RAR3/RAR4 decoders. When disabled, the binary still registers `.rar` against a diagnostic-only factory so the user sees `compiled without the 'rar' feature` instead of `unknown format`. |

To drop the RAR module entirely (shrinks the binary; useful when `.rar`
inputs are not expected):

```sh
cargo install peel-rs --locked --no-default-features
```

## From a release binary

Pre-built binaries for Linux (x86_64, aarch64) and macOS (x86_64, aarch64)
are attached to every GitHub release:

<https://github.com/agouin/peel/releases>

```sh
# Linux x86_64 example. Substitute your platform's triple.
curl -L https://github.com/agouin/peel/releases/latest/download/peel-x86_64-unknown-linux-gnu.tar.gz \
  | tar -xz -C /usr/local/bin peel
peel --version
```

## Docker

```sh
docker run --rm -v "$PWD/out:/out" ghcr.io/agouin/peel \
  https://example.com/dataset.tar.zst -o /out/
```

The image is a `FROM scratch` build with the static `peel` binary plus a
recent CA bundle (no shell, no package manager). See the
[Kubernetes init container](./examples/kubernetes.md) example for usage
inside a Pod.

## Verifying the install

```sh
peel --version
peel --help | head
```

To confirm which file-IO backend `peel` selects at runtime on Linux, run
any command with `RUST_LOG=info` and look for the
`selected file IO backend = …` line:

```sh
RUST_LOG=info peel https://example.com/x.tar.zst -o ./out/ 2>&1 | head -5
```

See [Performance and tuning](./performance.md) for what each backend means.
