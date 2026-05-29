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

# Allow packagers to skip the heavy %%check step with
# `--without check` (e.g. `rpmbuild -bb --without check`). The
# main CI workflow already runs `cargo test` on every push, so
# repeating it here is duplicative; the option exists for local
# rebuilds and for matrix branches where the dev-deps (`xz2` →
# `lzma-sys`) would otherwise pull in extra C build deps.
%bcond_without check

Name:           peel
Version:        0.7.3
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
# Source2 ships a per-package rpmlint config that filters the
# domain-term spelling false-positives (`resumable`, `zst`, `xz`,
# `gz`, `rar`) that the default Fedora dictionary raises against
# Summary / %%description.
#
# rpmlint 2.x auto-discovers `*.rpmlintrc` in the same directory
# as the target rpm — but ONLY when exactly one rpm file is
# passed on the command line (see `_load_rpmlintrc` in
# rpmlint/lint.py). For SRPM lint this works (one .src.rpm next
# to `peel.rpmlintrc`), but for the built-RPM set (peel +
# peel-debuginfo + peel-debugsource) you must pass it
# explicitly:
#   rpmlint -r packaging/fedora/peel.rpmlintrc <rpms...>
# See `packaging/fedora/peel.rpmlintrc` for the filter regex
# and rationale.
Source2:        peel.rpmlintrc

# Toolchain. `rust >= 1.85` matches the MSRV in Cargo.toml; the
# `cargo-rpm-macros` package pulls in current-stable rust + cargo
# automatically (Fedora 44 ships 1.95). Pinning the floor here
# documents the MSRV for the spec; EPEL builds that lag behind
# 1.85 will fail this check cleanly. See PLAN_packaging.md §0.6.
#
# cargo-rpm-macros (>= 24) provides %%cargo_prep / %%cargo_build /
# %%cargo_test, which apply Fedora's hardening RUSTFLAGS, an
# offline-cargo-config, and the standard rust build profile.
BuildRequires:  rust >= 1.85
BuildRequires:  cargo-rpm-macros >= 24

# `--features system-libs` routes zstd-sys to pkg-config so we
# link against the distro's libzstd.so.1 instead of vendoring the
# C source. See Cargo.toml [features] and PLAN_packaging.md §0.4.
BuildRequires:  pkgconfig(libzstd)

# `%%check` builds dev-deps (`xz2` → `lzma-sys`, plus `cc`-using
# build scripts elsewhere). The runtime binary doesn't link
# liblzma — peel's xz path is a hand-rolled decoder
# (`internal/PLAN_xz_block_decoder.md` §7) — but the test build
# needs the system liblzma headers and a C compiler.
%if %{with check}
BuildRequires:  gcc
BuildRequires:  xz-devel
%endif

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
# Drop the pre-vendored crates tree alongside the source. The
# `--strip-components=1` removes the `peel-v<version>-vendored/`
# outer directory so `vendor/` lands directly in the source root —
# which is where %%cargo_prep's `-v` flag expects it.
tar -xzf %{SOURCE1} --strip-components=1
# The vendor tarball ships a redundant `cargo-vendor-config.toml`
# (what `cargo vendor` prints to stdout). %%cargo_prep -v writes
# its own structurally-equivalent `[source.vendored-sources]` /
# `[source.crates-io]` directives, so drop the shipped one.
rm -f cargo-vendor-config.toml
# %%cargo_prep -v vendor: write `.cargo/config.toml` pointing at
# the local vendor dir, set `[net] offline = true`, keep
# Cargo.lock (the `-v` branch preserves it; the no-args branch
# would delete it). %%cargo_build / %%cargo_test downstream pick
# up this config automatically.
%cargo_prep -v vendor

%build
# %%cargo_build applies Fedora's hardening RUSTFLAGS (relro/now
# linker flags, frame pointers, debuginfo, package-note
# annotation, --cap-lints=warn) and builds with `--profile rpm`
# (inherits from `release`). The `-f system-libs` flag swaps
# zstd-sys's bundled C source for the system libzstd. `--locked`
# enforces Cargo.lock parity with the vendor dir; `--offline` is
# already set globally by %%cargo_prep.
%cargo_build -f system-libs -- --locked --bin peel
# Man page is arch-independent troff; one invocation per build is
# fine — see `src/bin/peel-mangen.rs` and PLAN_packaging.md §0.2.
# The `man-page` feature pulls in the optional `clap_mangen` dep
# so the `peel-mangen` bin can compile; the binary is invoked
# below to render `peel.1` and is then discarded — only the
# runtime `peel` binary ships.
%cargo_build -f system-libs,man-page -- --locked --bin peel-mangen
mkdir -p target/man
target/release/peel-mangen target/man/peel.1

%install
install -D -m0755 target/release/peel %{buildroot}%{_bindir}/peel
install -D -m0644 target/man/peel.1   %{buildroot}%{_mandir}/man1/peel.1

%if %{with check}
%check
# %%cargo_test runs `cargo test --profile rpm --no-fail-fast`
# with the same hardening flags. Same `-f system-libs` so the
# test build matches the runtime binary's link surface.
%cargo_test -f system-libs -- --locked
%endif

%files
# %%license puts these under `/usr/share/licenses/peel/` on
# Fedora 30+; %%doc puts README under `/usr/share/doc/peel/`.
%license LICENSE-MIT LICENSE-APACHE NOTICE
%doc README.md
%{_bindir}/peel
%{_mandir}/man1/peel.1*

%changelog
* Fri May 29 2026 Andrew Gouin <andrew@gouin.io> - 0.7.3-1
- Release v0.7.3.

* Thu May 28 2026 Andrew Gouin <andrew@gouin.io> - 0.7.2-1
- Release v0.7.2.

* Tue May 19 2026 Andrew Gouin <andrew@gouin.io> - 0.7.1-1
- Release v0.7.1.

* Tue May 19 2026 Andrew Gouin <andrew@gouin.io> - 0.7.0-1
- Release v0.7.0.

* Sat May 16 2026 Andrew Gouin <andrew@gouin.io> - 0.6.14-1
- Release v0.6.14.

* Sat May 16 2026 Andrew Gouin <andrew@gouin.io> - 0.6.13-1
- Release v0.6.13.

* Fri May 15 2026 Andrew Gouin <andrew@gouin.io> - 0.6.12-1
- Update to 0.6.12.
- Switch to cargo-rpm-macros idiom (%%cargo_prep -v, %%cargo_build,
  %%cargo_test) so Fedora hardening RUSTFLAGS apply.
- Add `%%bcond_without check` so packagers can skip `cargo test`
  without `--nocheck`.

* Thu May 14 2026 Andrew Gouin <andrew@gouin.io> - 0.5.0-1
- Initial Fedora packaging.
