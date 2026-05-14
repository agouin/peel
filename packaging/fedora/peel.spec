# peel.spec — Fedora / EPEL package for peel
#
# This spec drives both the COPR (community repo) build and the
# future official-Fedora-repo build. See packaging/fedora/README.md
# for the publication flow and internal/PLAN_packaging.md §1 for the
# overall plan.
#
# Crate / binary name split: the crate is `peel-rs` on crates.io
# (the `peel` name was already taken before this project started)
# but the binary, man page, and Fedora package name are all `peel`.
# See internal/PLAN_packaging.md §0.1.

Name:           peel
Version:        0.5.0
Release:        1%{?dist}
Summary:        Streaming, resumable, space-efficient HTTP archive extractor

License:        MIT OR Apache-2.0
URL:            https://github.com/agouin/peel

# Source0 is the upstream source tree at the matching git tag —
# GitHub's auto-generated archive. The directory inside the tarball
# is `peel-<version>` (no `v` prefix), which %%autosetup consumes
# below.
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz#/%{name}-%{version}.tar.gz
# Source1 is the pre-vendored crates dir produced by
# `release.yml`'s "Vendor dependencies" step. Fedora build chroots
# are network-isolated (mock), so cargo must resolve every dep
# locally. The tarball expands to `peel-v<version>-vendored/`
# containing `vendor/` and `cargo-vendor-config.toml`. See
# `internal/PLAN_packaging.md` §0.3.
Source1:        %{url}/releases/download/v%{version}/%{name}-v%{version}-vendored.tar.gz

# Toolchain. Fedora 42+ ships rust >= 1.84; older releases need
# `rust-toolset` (which tracks current stable). The MSRV declared
# in Cargo.toml is 1.85 — see `internal/PLAN_packaging.md` §0.6.
BuildRequires:  rust >= 1.85
BuildRequires:  cargo
# `--features system-libs` routes zstd-sys to pkg-config so we
# link against the distro's libzstd.so.1 instead of vendoring the
# C source. See Cargo.toml [features] and PLAN_packaging.md §0.4.
BuildRequires:  pkgconfig(libzstd)

# Restricted to the architectures we exercise in CI (`release.yml`).
# Fedora's %%{rust_arches} would also include i686, ppc64le, s390x,
# riscv64; expand the set when we have CI coverage to back it up.
ExclusiveArch:  x86_64 aarch64

# Rust source files use `#![...]` inner attributes ("inner doc /
# inner crate attributes") that look like malformed shebangs to
# rpm's `brp-mangle-shebangs` — it treats every line starting with
# `#!` as a shebang and rejects anything that doesn't begin
# `#!/`. Exclude `.rs` files so the inner-attribute lines pass
# through to the debug-source subpackage unchanged. Canonical
# Fedora Rust packaging idiom.
%global __brp_mangle_shebangs_exclude_from ^.*\.rs$

%description
peel downloads compressed archives over HTTP and streams them through
decompression in a single pass, hole-punching the compressed bytes from
disk as the decoder advances. A SIGKILL mid-extraction resumes exactly
where it left off, byte-identical to a clean run.

Supports tar / tar.zst / tar.xz / tar.lz4 / tar.gz / tar.bz2 / zip /
7z / rar (rar5 + rar3/rar4), plus the raw single-stream forms of those
codecs.

%prep
%autosetup -n %{name}-%{version}
# Drop the pre-vendored crates tree next to the source. The
# `--strip-components=1` removes the `peel-v<version>-vendored/`
# outer directory so `vendor/` lands directly in the source root.
tar -xzf %{SOURCE1} --strip-components=1
# Point cargo at the vendored copy. The `cargo-vendor-config.toml`
# that ships in the vendored tarball is the snippet cargo-vendor
# prints to stdout — exactly the `[source.crates-io] /
# [source.vendored-sources]` directives we need.
mkdir -p .cargo
mv cargo-vendor-config.toml .cargo/config.toml

%build
# `--locked` rejects any drift between Cargo.lock and the vendored
# tree. `--features system-libs` swaps zstd-sys's vendored C source
# for the system libzstd. RUSTFLAGS / RUSTC are left at Fedora's
# defaults so the spec stays compatible with `rust-toolset` macros
# if the build env opts into them.
cargo build --frozen --release --features system-libs --bin peel
# Man page is arch-independent troff; one invocation per build is
# fine — see `src/bin/peel-mangen.rs` and PLAN_packaging.md §0.2.
# The `man-page` feature pulls in the optional `clap_mangen` dep so
# the `peel-mangen` bin can compile; it stays off in default builds.
cargo build --frozen --release --features system-libs,man-page --bin peel-mangen
target/release/peel-mangen target/man/peel.1

%install
install -D -m0755 target/release/peel %{buildroot}%{_bindir}/peel
install -D -m0644 target/man/peel.1   %{buildroot}%{_mandir}/man1/peel.1

%check
cargo test --frozen --release --features system-libs

%files
# %%license puts these under `/usr/share/licenses/peel/` on
# Fedora 30+; %%doc puts README under `/usr/share/doc/peel/`.
%license LICENSE-MIT LICENSE-APACHE NOTICE
%doc README.md
%{_bindir}/peel
%{_mandir}/man1/peel.1*

%changelog
* Thu May 14 2026 Andrew Gouin <andrew@gouin.io> - 0.5.0-1
- Initial Fedora packaging.
