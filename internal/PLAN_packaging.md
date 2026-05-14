# PLAN_packaging.md — distro packaging for `peel`

Goal: ship `peel` through the native package manager on Fedora,
Ubuntu, Debian, Arch, and Alpine, so users can `dnf install peel`,
`apt install peel`, `pacman -S peel`, `apk add peel` without
touching `cargo install` or curling a tarball.

This plan covers crate / source preparation that's common to every
distro, then one section per distro with the specific submission path,
file layout, and friction points. A phasing recommendation at the end
suggests the order to attack them in (quick wins first).

---

## §0 Prerequisites (do these once, they unblock everything else)

These are shared inputs every distro packager will need. Do them
before opening any of the distro-specific tracks below.

### §0.1 Document the crate / binary name split

The `Cargo.toml` ships the crate as `peel-rs` and the binary as
`peel`. The `peel` crate name on crates.io is already taken by an
unrelated existing crate (not a binary tool like this one), so the
split is **permanent** — there is no rename path. Distro packages
ship as `peel` (binary name wins). Every spec / PKGBUILD /
APKBUILD / `debian/control` needs a one-line comment noting that
the upstream source on crates.io is `peel-rs-<version>.crate`
but the installed binary, man page, and package name are `peel`.

The `Source0:` / `Source:` URLs in each spec point at the GitHub
release tarball (which is named `peel-<version>.tar.gz` per
§release.yml), not crates.io, so this is mostly a comment-level
clarification — only matters if a packager wonders why `cargo
search peel` returns the wrong thing.

### §0.2 Generate a man page with `clap_mangen`

`clap` already owns the CLI surface. Add `clap_mangen` as a
**build-script** dependency (so the runtime binary is unchanged —
no new dep in the link graph) and emit `target/man/peel.1` during
`cargo build`. Concrete steps:

1. Add `[build-dependencies] clap_mangen = "0.2"` and `clap =
   { version = "4", features = ["derive"] }` to `Cargo.toml`.
2. Extract the `Cli` struct definition from `src/main.rs` (or
   wherever it lives) into a small module that both `main.rs` and
   `build.rs` can import. Easiest: put it in `src/cli.rs` and
   declare `mod cli;` in both `main.rs` and via `build.rs`'s
   `path = "src/cli.rs"; #[path = ...] mod cli;` trick. If that
   gets ugly, the fallback is to have `build.rs` define a
   minimal mirror of the `clap::Command` (lower fidelity but
   stable).
3. `build.rs` runs `clap::CommandFactory::command()`, hands it to
   `clap_mangen::Man::new(...).render(&mut writer)`, writes
   `target/man/peel.1`. Also write a `target/man/peel.1.gz` for
   distros that want it compressed.
4. CI: add a step to `ci.yml` that asserts `target/man/peel.1`
   exists after a release build, so regressions show up before
   tagging.

Pre-approval: `clap_mangen` is maintained by the clap-rs org, MIT
or Apache-2.0, no transitive C deps. Treat as pre-approved under
the `clap` umbrella in `ENGINEERING_STANDARDS.md` §2.2 (worth a
one-line note in that doc).

### §0.3 Vendor dependencies for offline / sandboxed builds

Most distro build environments (Fedora mock, Debian sbuild, Alpine
abuild) are **network-isolated**. Cargo can't fetch from crates.io
during the build. Two options:

- **`cargo vendor`** into `vendor/` and commit it to a `packaging`
  branch (or generate at release time and bundle into the
  source tarball). Pros: one tarball builds everywhere. Cons:
  ~50–100 MB added to the source artifact.
- **Per-distro vendoring** done by the packager at build time
  (e.g. Fedora's `cargo-c` / `rust2rpm` helpers, Debian's `debcargo`
  per-crate model). More distro-idiomatic but more work per distro.

Recommended: produce a `peel-<version>-vendored.tar.gz` in the
existing `release.yml` GitHub Actions workflow, alongside the
binary tarballs. Each distro's source package downloads that as
its upstream tarball.

### §0.4 Add a `system-libs` Cargo feature for shared `libzstd`

The `zstd` crate currently statically links libzstd via `zstd-sys`
(vendored C source). Most distros require shared linking against
system `libzstd` so security updates flow without rebuilding every
consumer.

Add a `system-libs` Cargo feature that forwards to `zstd-sys`'s
`pkg-config` feature. Concrete shape in `Cargo.toml`:

```toml
[features]
default = ["rar"]
rar = []
system-libs = ["zstd/pkg-config"]
```

(`zstd` re-exports `zstd-sys`'s features, so `zstd/pkg-config`
is the path. Confirm the exact feature name in the version of
`zstd` we pin — recent versions expose it as `pkg-config`.)

Default builds (the crates.io release, the GitHub-released
binaries, `cargo install peel-rs`) stay vendored / statically
linked — no behavior change for existing users. Distro packages
build with `--features system-libs` and `BuildRequires:
pkgconfig(libzstd)` (or distro equivalent), and a runtime
`Depends: libzstd1` (or equivalent shared-library package).

The other compression deps (`lz4_flex`, hand-rolled xz / zstd /
deflate / bz2 / rar / gzip) are pure-Rust — no system-libs
question for them, no further feature flags needed.

### §0.5 LICENSE files in the install layout

Every distro expects `/usr/share/doc/peel/` (or `/usr/share/licenses/peel/`
on Arch) to contain `LICENSE-MIT`, `LICENSE-APACHE`, and `NOTICE`.
These exist at the repo root — confirm `cargo package` puts them in
the `.crate` tarball (it does by default for `LICENSE*` patterns).

### §0.6 MSRV floor

Current state: `rust-toolchain.toml` pins the dev/build toolchain
to 1.95.0, `Cargo.toml` declares `rust-version = "1.93"`. Distros
shipping older rustc:

| Distro / channel             | rustc shipped (as of 2026-05) |
| ---------------------------- | ----------------------------- |
| Debian trixie (stable)       | ~1.78                         |
| Ubuntu 24.04 LTS (noble)     | 1.75                          |
| Ubuntu 24.10 / 25.04         | ~1.81 / ~1.84                 |
| Fedora 41                    | ~1.81                         |
| Fedora 42                    | 1.84+                         |
| Alpine 3.21                  | ~1.81                         |
| Alpine edge                  | current stable                |
| Arch                         | current stable                |
| EPEL 10                      | ~1.79 via `rust-toolset`      |

A declared MSRV of 1.93 excludes every current LTS / stable
release. The original target was 1.78 (Debian trixie). The audit
below shows what's actually reachable.

#### Audit results (run 2026-05-14)

Method: `cargo +<rustc> check --all-features --locked
--ignore-rust-version` against the current `Cargo.lock`, on
aarch64-apple-darwin.

| rustc  | Result                                                         |
| ------ | -------------------------------------------------------------- |
| 1.95.0 | clean (current stable)                                         |
| 1.87.0 | **clean — zero code changes needed**                           |
| 1.85.0 | 10 errors, all `u*::is_multiple_of` (stabilized 1.87)          |
| 1.78.0 | manifest parse fails — `clap_lex 1.1.0` requires edition 2024  |

The 1.85 errors are all the same shape:
`x.is_multiple_of(N)` (used in
[bzip2_native/{selectors,body,huffman,block}.rs](../src/decode/bzip2_native/),
[ppmd2/alloc.rs:872](../src/decode/ppmd2/alloc.rs#L872),
[rar_pipeline.rs:1403](../src/download/rar_pipeline.rs#L1403),
[scheduler.rs:1637](../src/download/scheduler.rs#L1637), and
[tests/test_bench_hash.rs:124](../tests/test_bench_hash.rs#L124)).
Mechanical rewrite to `x % N == 0`. After applying the rewrite,
1.85 builds clean (verified during audit by sed-patching all 10
call sites and re-running `cargo +1.85.0 check`).

The 1.78 failure is **load-bearing**: even with our code at
1.78-compatible shape, edition-2024 has spread through the
transitive dep tree. Confirmed in audit:

- `clap 4.6.1` → `clap_lex 1.1.0` (edition 2024). Manifest
  parse fails before any compilation.
- Pinning `clap` to `4.5.40` downgrades `clap_lex` to `0.7.7`
  (edition 2021), but then `hyper 1.9` → `h2 0.4.13` →
  `indexmap 2.14` → `hashbrown 0.17.0` (edition 2024) fails
  next.

The pattern is unambiguous: the Rust ecosystem is migrating to
edition 2024 (stabilized in cargo 1.85). Holding the dep tree at
pre-edition-2024 versions would require permanent pins on `clap`,
`hashbrown`, `indexmap`, and almost certainly more — freezing
security updates on each. Not a sustainable position.

#### Decision: target MSRV 1.85

Rationale:

- **1.87 is "free"** (zero code changes) but signals nothing
  about MSRV discipline — distros and downstream consumers can't
  tell whether the 1.87 floor is incidental or load-bearing.
- **1.85 costs 10 mechanical rewrites** and gives us a real
  declared floor enforced by CI. 1.85 is the cheapest point above
  the edition-2024 cargo gate, so any future rustc bump becomes a
  deliberate choice rather than a transitive accident.
- **1.78 is not realistically reachable** without permanently
  pinning much of the HTTP / async / indexing dep tree to old
  versions.

Distro impact at MSRV 1.85 (compared to the original 1.78 target):

| Distro                | Archive rustc | 1.85 status                  |
| --------------------- | ------------- | ---------------------------- |
| Arch                  | current       | OK                           |
| Alpine edge           | current       | OK                           |
| Alpine 3.22+ (TBD)    | ~1.85+ likely | OK (when released)           |
| Alpine 3.21           | ~1.81         | blocked — testing branch +   |
|                       |               | rustup-in-build, or wait     |
| Fedora 42             | 1.84+         | borderline — needs 1.85+     |
| Fedora 41             | ~1.81         | needs `rust-toolset` bump    |
| Debian sid            | rolling       | OK                           |
| Debian trixie         | ~1.78         | **blocked** — sid only       |
| Ubuntu 25.10+         | 1.86+         | OK                           |
| Ubuntu 24.04..25.04   | 1.75..1.84    | **blocked from archive** —   |
|                       |               | PPA with rustup-in-build     |

So MSRV 1.85 means:
- Arch and Alpine edge install cleanly today.
- Fedora COPR (§1.1) and Ubuntu PPA (§2.1) work today — both can
  pull a newer rustc into the build env.
- The Debian / Fedora / Alpine **main archive** paths wait for
  the next archive rustc bump in each distro — typically 6–12
  months for trixie's first point release with newer rustc, or
  the next stable cycle.

The Ubuntu LTS 24.04 main-archive path is closed regardless of
our MSRV choice (1.75 is below even what a zero-edition-2024
codebase buys us, since edition-2024-gated deps still trip cargo).

#### Phase 0 work list

1. Update `Cargo.toml`: `rust-version = "1.85"`.
2. Rewrite the 10 `is_multiple_of` call sites listed above to
   `% == 0`. Single mechanical commit.
3. Add a `ci.yml` job: `cargo +1.85 check --all-features
   --locked` so MSRV regressions fail CI. Use the
   `dtolnay/rust-toolchain@1.85` setup-action.
4. Leave `rust-toolchain.toml` pinned at current stable
   (1.95.0) — that's the dev-experience pin; MSRV is the
   declared floor, not the dev floor. A short comment in
   `Cargo.toml` next to `rust-version` should note this
   distinction.
5. If a distro maintainer later asks for a lower floor, revisit
   — but expect to push back, citing the edition-2024 cascade.

---

## §1 Fedora

**Target**: `dnf install peel` on Fedora 41+ and EPEL 10.
**Submission path**: COPR first (fast), official Fedora repos second.

### §1.1 Phase A — COPR (community / personal repo)

COPR is Fedora's PPA equivalent: a build farm + repo hosting service
for community packages. Zero review process, ships in a day.

1. Sign up at `copr.fedorainfracloud.org` with a FAS account.
2. Create a `peel` project, enable Fedora 41 / 42 / rawhide and EPEL 10
   x86_64 + aarch64 chroots.
3. Write `peel.spec` (see §1.3) and a `peel-<version>.src.rpm`.
   Use `rpkg` or `fedpkg --dist=fedora-41 srpm`.
4. Upload the `.src.rpm` via the COPR web UI or `copr-cli build peel
   peel-<version>.src.rpm`.
5. Users add the repo with `dnf copr enable agouin/peel` and
   `dnf install peel`.

Friction: low. This is the recommended first step — gets real users
running it from `dnf` in a week, validates the spec file before
the official-repo review.

### §1.2 Phase B — Official Fedora repository

Fedora's Rust packaging guidelines historically required
**every transitive dep be its own RPM** (`rust-thiserror`,
`rust-clap`, etc.). For a crate with ~25 transitive deps this is
weeks of work and a maintenance tax forever.

The 2024 guideline update softened this for "leaf application"
crates (binary-only, no library consumers): they may ship
vendored. `peel` qualifies — the `peel` library crate is internal,
not published for external consumers.

Steps:
1. Read the current Fedora Rust Packaging Guidelines
   (docs.fedoraproject.org/en-US/packaging-guidelines/Rust/).
2. Run `rust2rpm peel-rs` against the published crate to get a
   starter spec. Adjust to use the vendored tarball from §0.3.
3. File a package review bug on `bugzilla.redhat.com` against
   `Package Review` component. Title: `Review Request: peel —
   streaming HTTP archive extractor`.
4. Find a sponsor (someone in the `packager` group). Post in
   `#fedora-rust:matrix.org` or the `devel@lists.fedoraproject.org`
   list once the review ticket is up.
5. After approval, request the dist-git repo, push the spec, and
   submit Bodhi updates for each release.

### §1.3 `peel.spec` skeleton

```spec
Name:           peel
Version:        0.5.0
Release:        1%{?dist}
Summary:        Streaming, resumable, space-efficient HTTP archive extractor

# crates.io ships as `peel-rs`; binary and Fedora package are `peel`.
# See internal/PLAN_packaging.md §0.1.
License:        MIT OR Apache-2.0
URL:            https://github.com/agouin/peel
Source0:        https://github.com/agouin/peel/releases/download/v%{version}/peel-%{version}.tar.gz
Source1:        https://github.com/agouin/peel/releases/download/v%{version}/peel-%{version}-vendored.tar.gz

BuildRequires:  rust >= 1.93
BuildRequires:  cargo
BuildRequires:  pkgconfig(libzstd)
# §0.4: system-libs feature routes zstd-sys to pkg-config.

ExclusiveArch:  %{rust_arches}

%description
peel downloads compressed archives over HTTP and streams them through
decompression in a single pass, hole-punching the compressed bytes from
disk as the decoder advances. A `kill -9` mid-extraction resumes
exactly where it left off.

%prep
%autosetup -n peel-%{version}
tar -xzf %{SOURCE1}
mkdir -p .cargo
cat > .cargo/config.toml <<EOF
[source.crates-io]
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "vendor"
EOF

%build
ZSTD_SYS_USE_PKG_CONFIG=1 \
cargo build --release --locked --features system-libs --bin peel

%install
install -Dm0755 target/release/peel %{buildroot}%{_bindir}/peel
install -Dm0644 target/man/peel.1 %{buildroot}%{_mandir}/man1/peel.1
install -Dm0644 LICENSE-MIT      %{buildroot}%{_docdir}/peel/LICENSE-MIT
install -Dm0644 LICENSE-APACHE   %{buildroot}%{_docdir}/peel/LICENSE-APACHE
install -Dm0644 NOTICE           %{buildroot}%{_docdir}/peel/NOTICE
install -Dm0644 README.md        %{buildroot}%{_docdir}/peel/README.md

%files
%license LICENSE-MIT LICENSE-APACHE NOTICE
%doc README.md
%{_bindir}/peel
%{_mandir}/man1/peel.1*

%changelog
* <date> Andrew Gouin <andrew@gouin.io> - 0.5.0-1
- Initial Fedora packaging.
```

### §1.4 Risks / open questions for Fedora

- **Rust MSRV vs. Fedora rustc**. Resolved by §0.6 (target floor
  1.85). Fedora's `rust-toolset` macros support flexibly pulling
  a newer rustc into a build root, so the COPR path (§1.1) works
  immediately by setting `BuildRequires: rust >= 1.85` and
  relying on `rust-toolset`. The main-archive path (§1.2) is
  gated on Fedora's archive rustc reaching 1.85 — Fedora 42
  (1.84+) is right on the line; Fedora 43+ should be fine.
  EPEL 10 builds via `rust-toolset` which tracks current stable,
  so EPEL is unaffected.
- **The `io-uring` dep is Linux-only**. Already gated in
  `Cargo.toml` via `[target.'cfg(target_os = "linux")']`. Confirm
  the `rust_arches` macro doesn't include any non-Linux target.
- **Bundled-libraries exception**. The vendored-deps tarball means
  filing a `bundled(crate(thiserror))`, `bundled(crate(clap))`, …
  list in the spec. `rust2rpm` generates this list automatically.

---

## §2 Ubuntu

**Target**: `apt install peel` on Ubuntu 24.04+ (noble) and
later LTS releases.
**Submission path**: Launchpad PPA first, official archive second.

### §2.1 Phase A — Launchpad PPA

Launchpad PPAs are Ubuntu's COPR equivalent: a build farm + repo
service maintained by Canonical. Fast, zero review.

1. Create a Launchpad account and an OpenPGP key. Upload the key to
   `keyserver.ubuntu.com` and to Launchpad.
2. Create a PPA: `ppa:agouin/peel`.
3. Build the source package locally (see §2.3) and push with
   `dput ppa:agouin/peel peel_<version>-1ppa1_source.changes`.
4. Launchpad builds binaries for amd64 + arm64 across all enabled
   Ubuntu series. Users add it with `add-apt-repository
   ppa:agouin/peel && apt install peel`.

Friction: low. Same recommendation as Fedora — do this first.

### §2.2 Phase B — Official Ubuntu archive (via Debian)

Ubuntu auto-syncs from Debian unstable each release cycle. The
correct path is **not** to package directly into Ubuntu, but to get
into Debian (§3) and let the sync pick it up.

If a faster path is needed (e.g. for the next LTS cut-off), file a
sync request via `requestsync` against `ubuntu-motu` once the
Debian package exists, asking them to pull it forward into the
in-development Ubuntu series before the auto-sync cycle.

### §2.3 Debian source package layout (works for §2 and §3)

```
peel-0.5.0/
├── debian/
│   ├── changelog
│   ├── control
│   ├── copyright
│   ├── rules
│   ├── source/
│   │   └── format         # "3.0 (quilt)"
│   ├── peel.manpages      # "target/man/peel.1"
│   └── peel.docs          # "README.md NOTICE"
├── vendor/                # from §0.3
└── (cargo source tree)
```

Key file: `debian/control`:

```
Source: peel
Section: utils
Priority: optional
Maintainer: Andrew Gouin <andrew@gouin.io>
Build-Depends:
 debhelper-compat (= 13),
 rustc (>= 1.93),
 cargo,
 libzstd-dev,
 pkg-config
Standards-Version: 4.7.0
Homepage: https://github.com/agouin/peel
Rules-Requires-Root: no

Package: peel
Architecture: any-amd64 any-arm64
Depends: ${shlibs:Depends}, ${misc:Depends}
Description: streaming, resumable, space-efficient HTTP archive extractor
 peel downloads compressed archives over HTTP and streams them through
 decompression in a single pass, hole-punching the compressed bytes from
 disk as the decoder advances. A SIGKILL mid-extraction resumes exactly
 where it left off.
```

`debian/rules`:

```make
#!/usr/bin/make -f
export ZSTD_SYS_USE_PKG_CONFIG=1
export CARGO_HOME=$(CURDIR)/.cargo
export RUSTFLAGS=

%:
	dh $@

override_dh_auto_configure:
	mkdir -p .cargo
	printf '[source.crates-io]\nreplace-with = "vendored-sources"\n[source.vendored-sources]\ndirectory = "vendor"\n' > .cargo/config.toml

override_dh_auto_build:
	cargo build --release --locked --features system-libs --bin peel

override_dh_auto_install:
	install -Dm0755 target/release/peel debian/peel/usr/bin/peel
	install -Dm0644 target/man/peel.1 debian/peel/usr/share/man/man1/peel.1

override_dh_auto_test:
	cargo test --release --locked --features system-libs
```

Build with `dpkg-buildpackage -S -sa` for the PPA source upload, or
`-b` for a local `.deb`.

### §2.4 Phase C — quick win: `cargo-deb` artifact on GitHub Releases

Independent of the PPA path: add a `cargo-deb` step to the existing
`release.yml`. `cargo-deb` reads `[package.metadata.deb]` from
`Cargo.toml` and emits a usable `peel_<version>_amd64.deb` per
build. Users on any Debian-family distro can
`dpkg -i ./peel_<version>_amd64.deb` directly. This is **not** an
apt-repo-managed install, so security updates don't flow, but it's
~30 lines of YAML and one new dev-dep, and it gets us a downloadable
`.deb` immediately. Recommended as a same-day deliverable.

### §2.5 Risks / open questions for Ubuntu

- **Rust MSRV vs. Ubuntu archive rustc**. Per §0.6 (target floor
  1.85), the **main archive** path is blocked for every Ubuntu
  release through 25.04 (archive rustc ranges 1.75 → 1.84,
  all < 1.85). Ubuntu 25.10+ should ship rustc 1.86+ and works.
  The PPA path (§2.1) can install a newer rustc via `rustup` in
  the build script — acceptable for a PPA, not for the main
  archive. Practical plan: ship 24.04 / 24.10 / 25.04 via PPA
  only; the next LTS (26.04) gets the official-archive path
  once the Debian sync lands (§2.2) and trixie's rustc bumps to
  ≥ 1.85.

---

## §3 Debian

**Target**: `apt install peel` on Debian bookworm / trixie / sid.
**Submission path**: ITP → debcargo / sponsored upload → main archive.

### §3.1 The Debian Rust packaging model

Debian's Rust team historically packaged **every transitive dep** as
`librust-foo-dev`. `debcargo` automates this from `Cargo.toml`. The
team's policy on application crates is more flexible than it used to
be — for a binary-only "leaf" application like `peel`, you may
**ship vendored** with explicit `Built-Using:` entries listing the
bundled crates. Confirm current policy with the
`pkg-rust-maintainers` team on `#debian-rust:oftc.net` or the
`pkg-rust-maintainers@alioth-lists.debian.net` list **before**
starting work.

### §3.2 Path A — full unbundled (`debcargo`)

Heavy. Each transitive crate becomes a `librust-foo-dev` package
that goes through NEW queue review. ~25 deps × NEW queue latency
(weeks each) = months of calendar time. Only attempt if the Debian
Rust team won't accept vendored.

### §3.3 Path B — vendored leaf application (`dh-cargo` + vendor)

Use the §2.3 source-package layout. Add `Built-Using:` listing the
vendored crates (generate from `cargo metadata`).

### §3.4 Submission process (either path)

1. **ITP bug**: file `Intent To Package` against `wnpp` on
   bugs.debian.org. Title: `ITP: peel -- streaming, resumable HTTP
   archive extractor`. Cite homepage, license, language, brief
   description. This claims the name and signals intent.
2. **Find a sponsor**. New Debian maintainers don't have upload
   rights. Post the source package on `mentors.debian.net` and ask
   on `debian-mentors@lists.debian.org` for a sponsor. Or contact a
   Debian Rust team member directly (they sometimes adopt
   well-prepared application packages).
3. **Sponsor uploads to NEW**. Reviewers check license, copyright,
   lintian output, debian/copyright accuracy, source-format
   correctness. Address feedback. Typical: 2–6 weeks in NEW.
4. **Once in unstable**, the package migrates to testing after 5–10
   days assuming no RC bugs. From testing it goes into the next
   Debian stable release.
5. **Ubuntu auto-sync** picks it up for the next Ubuntu series
   (closes §2.2).

### §3.5 Risks / open questions for Debian

- **The Debian Rust team is the gatekeeper**. Their current
  application-crate policy is the make-or-break factor. Email them
  first; structure the package to match what they ask for.
- **Rust MSRV vs. trixie**. Per §0.6 (target floor 1.85), trixie's
  archive rustc (~1.78) is below the floor. The package lands in
  `sid` (which tracks newer rustc) but **won't migrate to the next
  Debian stable** until trixie's first point release bumps rustc to
  ≥ 1.85, or until the next stable cycle (trixie+1). This is the
  load-bearing distro-coverage cost of MSRV 1.85; see §0.6 audit
  results for why a lower floor isn't reachable.
- **Reproducible builds**. Debian's reproducible-builds tracker
  will flag any non-determinism. Strip `RUSTFLAGS` and avoid
  embedding build paths via `--remap-path-prefix`.

---

## §4 Arch Linux

**Target**: `pacman -S peel` (eventually); `paru -S peel` /
`yay -S peel` immediately via AUR.
**Submission path**: AUR first, `extra` repo later if there's
sustained demand.

### §4.1 Phase A — AUR (Arch User Repository)

The AUR is a git-based collection of `PKGBUILD` files. Anyone with
an account can publish. Three flavors of the package are
conventional for Rust binaries:

- **`peel`** — builds from the latest release tarball / crates.io.
  Canonical entry point.
- **`peel-git`** — builds from `main`. For users who want HEAD.
- **`peel-bin`** — extracts the prebuilt binary from GitHub
  Releases. Skips local compilation; fastest install.

Recommended: ship `peel` and `peel-bin` initially. Skip `peel-git`
unless someone asks for it.

### §4.2 `PKGBUILD` for the source package

```bash
# Maintainer: Andrew Gouin <andrew@gouin.io>
pkgname=peel
pkgver=0.5.0
pkgrel=1
pkgdesc="Streaming, resumable, space-efficient HTTP archive extractor"
arch=('x86_64' 'aarch64')
url="https://github.com/agouin/peel"
license=('MIT' 'Apache-2.0')
depends=('zstd')
makedepends=('rust' 'cargo' 'pkgconf')
source=("https://github.com/agouin/peel/releases/download/v${pkgver}/peel-${pkgver}.tar.gz")
sha256sums=('SKIP')  # replace with actual hash; gh release SHA256SUMS has it

prepare() {
    cd "peel-${pkgver}"
    export RUSTUP_TOOLCHAIN=stable
    cargo fetch --locked --target "$(rustc -vV | sed -n 's/host: //p')"
}

build() {
    cd "peel-${pkgver}"
    export RUSTUP_TOOLCHAIN=stable
    export CARGO_TARGET_DIR=target
    export ZSTD_SYS_USE_PKG_CONFIG=1
    cargo build --frozen --release --features system-libs --bin peel
}

check() {
    cd "peel-${pkgver}"
    export RUSTUP_TOOLCHAIN=stable
    cargo test --frozen --release --features system-libs
}

package() {
    cd "peel-${pkgver}"
    install -Dm0755 target/release/peel "${pkgdir}/usr/bin/peel"
    install -Dm0644 target/man/peel.1 "${pkgdir}/usr/share/man/man1/peel.1"
    install -Dm0644 LICENSE-MIT "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE-MIT"
    install -Dm0644 LICENSE-APACHE "${pkgdir}/usr/share/licenses/${pkgname}/LICENSE-APACHE"
    install -Dm0644 NOTICE "${pkgdir}/usr/share/licenses/${pkgname}/NOTICE"
}
```

### §4.3 `PKGBUILD` for `peel-bin`

Strips out `cargo`, downloads the `peel-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz`
artifact from §release.yml, and installs the binary directly.
~20 lines total. Add `provides=('peel')` and
`conflicts=('peel')` so the two AUR entries are mutually exclusive.

### §4.4 Submission process for AUR

1. Generate `.SRCINFO` with `makepkg --printsrcinfo > .SRCINFO`.
2. Create the AUR repo: `git clone ssh://aur@aur.archlinux.org/peel.git`.
3. Commit `PKGBUILD` + `.SRCINFO`, push.
4. Each new release: bump `pkgver`, refresh `sha256sums`, regenerate
   `.SRCINFO`, commit, push. Automatable from `release.yml`.

### §4.5 Phase B — promotion to `extra`

Once the AUR package has sustained votes / users (loose threshold —
"a Trusted User notices and offers"), a TU can adopt it into the
`extra` repository so it's installable with plain `pacman` without
AUR helpers. No formal application — usually happens via
`#archlinux-tu:libera.chat` after sustained interest. Don't plan
around this; treat as bonus.

### §4.6 Risks / open questions for Arch

- **Rust toolchain in `[extra]`**. Arch ships current stable, so
  MSRV is a non-issue regardless of where §0.6 lands. Lowest-
  friction distro in this plan.
- **Multi-arch**. AUR supports both `x86_64` and `aarch64` via the
  same PKGBUILD. The arm64 builders are community-run; `peel-bin`
  needs separate `source_aarch64=()` / `sha256sums_aarch64=()`
  arrays pointing at the arm64 release artifact.

---

## §5 Alpine

**Target**: `apk add peel` on Alpine 3.20+ and edge.
**Submission path**: `aports` MR against the testing repo →
promotion to community.

### §5.1 The aports model

Alpine packages live in a single monorepo: `gitlab.alpinelinux.org/
alpine/aports`. Each package is a directory under `main/`,
`community/`, or `testing/` containing an `APKBUILD` script plus
optional patches and init scripts. Submission is a merge request
against the `testing/` directory; after a probation period a
package gets promoted to `community/`.

### §5.2 `APKBUILD`

```sh
# Contributor: Andrew Gouin <andrew@gouin.io>
# Maintainer: Andrew Gouin <andrew@gouin.io>
pkgname=peel
pkgver=0.5.0
pkgrel=0
pkgdesc="Streaming, resumable, space-efficient HTTP archive extractor"
url="https://github.com/agouin/peel"
arch="x86_64 aarch64"
license="MIT OR Apache-2.0"
makedepends="cargo rust zstd-dev pkgconf"
source="$pkgname-$pkgver.tar.gz::https://github.com/agouin/peel/archive/v$pkgver.tar.gz"

prepare() {
    default_prepare
    cargo fetch --target="$CTARGET" --locked
}

build() {
    export ZSTD_SYS_USE_PKG_CONFIG=1
    cargo build --release --frozen --features system-libs --bin peel
}

check() {
    cargo test --release --frozen --features system-libs
}

package() {
    install -Dm755 target/release/peel "$pkgdir"/usr/bin/peel
    install -Dm644 target/man/peel.1 "$pkgdir"/usr/share/man/man1/peel.1
    install -Dm644 LICENSE-MIT "$pkgdir"/usr/share/licenses/$pkgname/LICENSE-MIT
    install -Dm644 LICENSE-APACHE "$pkgdir"/usr/share/licenses/$pkgname/LICENSE-APACHE
    install -Dm644 NOTICE "$pkgdir"/usr/share/licenses/$pkgname/NOTICE
}

sha512sums="<filled in by abuild-keygen / abuild checksum>"
```

### §5.3 Submission process for Alpine

1. **Get an Alpine developer account** at
   `gitlab.alpinelinux.org`. Read `docs.alpinelinux.org/
   developer-handbook/`.
2. **Set up the build env**: install `alpine-sdk`, run
   `abuild-keygen -a -i -n`.
3. **Fork aports**, branch `testing/peel`, create
   `testing/peel/APKBUILD`. Build locally with `abuild -r`.
4. **Verify with `apkbuild-lint` and `apkbuild-shellcheck`**.
   Alpine's CI runs both.
5. **Open MR**: title `testing/peel: new aport`. CI builds for
   x86_64, aarch64, armv7, ppc64le, s390x, riscv64. Be prepared to
   skip arches if io-uring's `cfg(target_os = "linux")` gating
   plus rustc support don't cover all of them — set `arch="x86_64
   aarch64"` to start.
6. **After merge**, the package builds in `testing/` for a few
   weeks. Once stable, propose promotion to `community/` via a
   second MR moving the directory.

### §5.4 Risks / open questions for Alpine

- **musl libc**. The release artifact `peel-*-x86_64-unknown-linux-musl.tar.gz`
  is the right reference for testing; the apk build itself
  builds from source against musl, but having a known-good musl
  binary helps debug build issues.
- **Rust MSRV vs. Alpine archive rustc**. Per §0.6 (target floor
  1.85), Alpine 3.21's archive rustc (~1.81) is below the floor.
  Submit to `testing/` against edge first (current stable, OK).
  Promotion to `community/` and inclusion in the next 3.x release
  is gated on that release shipping rustc ≥ 1.85 — likely 3.22 or
  3.23 depending on Alpine's rustc bump cadence. For 3.21 users we
  can ship via a side aports overlay with `rustup`-in-build, but
  the canonical answer is "wait for 3.22+".
- **`io-uring` on musl**. The `io-uring` crate compiles fine on
  musl in theory, but our CI doesn't exercise it on Alpine. Add
  an Alpine job to `ci.yml` before submitting — surprises here
  block the MR.
- **Static linking**. Alpine traditionally prefers `-static`
  binaries. The `system-libs` route conflicts with this — there's
  a tension between "use system libzstd" (Alpine maintainer
  preference for security updates) and "static binary"
  (Alpine cultural preference for minimal closures). The
  `community/` reviewer will decide; defer to them.

---

## §6 Phasing and order of execution

The recommended order maximizes time-to-first-user-install.
Each phase is independent — finish phase 1 across all distros
before starting phase 2.

### Phase 1 (this sprint, days, not weeks)

Same-day or near-same-day deliverables. No reviews, no gatekeepers.

1. **§0.6** MSRV audit. Determine the actual floor before anything
   else — every distro decision in Phase 2 depends on it. Land the
   `Cargo.toml` `rust-version` bump and the CI MSRV-check job.
2. **§0.2** generate `peel.1` via `clap_mangen` build script.
3. **§0.3** add `vendored-sources.tar.gz` to `release.yml` outputs.
4. **§0.4** add the `system-libs` Cargo feature.
5. **§2.4** add `cargo-deb` to `release.yml` → ship `.deb` on every
   release.
6. **§4.1** publish `peel-bin` and `peel` to AUR.
7. **§1.1** publish to Fedora COPR.
8. **§2.1** publish to Launchpad PPA.

After Phase 1: Arch users have `paru -S peel`; Fedora users have
a one-line `dnf copr enable` command; Ubuntu users have a PPA;
Debian-family users have a downloadable `.deb`. Zero distro
review queues touched.

### Phase 2 (weeks to months)

Real distro reviews. Each is independent.

8. **§5** Alpine aports MR → `testing/peel` → `community/peel`.
9. **§3** Debian ITP + sponsor + NEW queue.
10. **§1.2** Fedora package review + Bodhi.

### Phase 3 (passive / opportunistic)

11. **§2.2** Ubuntu auto-sync from Debian (happens for free after §3).
12. **§4.5** Arch promotion to `extra` (happens organically if §4.1
    gets traction).

### Out of scope for this plan

- macOS Homebrew (separate, lower friction, address after Linux).
- Nix / NixOS (separate model; flake or nixpkgs PR).
- Snap / Flatpak (sandboxing model is awkward for a tool that needs
  to write to arbitrary user paths and call `fallocate`).
- Windows package managers (winget, scoop, chocolatey) — `peel`'s
  Linux-specific features (`fallocate(PUNCH_HOLE)`, io-uring) don't
  apply, so Windows packaging waits on a Windows port.

---

## §7 Maintenance burden after launch

Each release (`vX.Y.Z` git tag) needs to fan out to every
distro that's accepted us. The cost per distro per release:

| Distro    | Per-release action                              | Automatable? |
| --------- | ----------------------------------------------- | ------------ |
| AUR       | bump `pkgver` + `sha256sums`, regenerate `.SRCINFO`, `git push` | Yes — `release.yml` step |
| COPR      | upload new `.src.rpm` via `copr-cli`            | Yes — `release.yml` step |
| Launchpad | `dput` new source package                       | Yes — `release.yml` step (needs PGP key in CI secret) |
| Fedora    | `fedpkg import` + Bodhi update                  | Partial — Bodhi step is manual |
| Debian    | new upload via sponsor                          | No — sponsor in the loop each time |
| Alpine    | bump `pkgver` + `sha512sums`, MR against aports | Partial — needs Alpine CI build to land MR |

Automate the AUR / COPR / Launchpad steps in `release.yml` so they
fan out on tag push. The other three stay manual.
