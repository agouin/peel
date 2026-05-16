# Fedora / EPEL packaging for `peel`

This directory holds [`peel.spec`](peel.spec) — the canonical Fedora
RPM spec for `peel`. The same file feeds:

- **COPR builds** (community repo, fastest path to users) — see §1
- **Official Fedora repo** (requires package review + sponsor) — see §2

Both paths consume the GitHub-released `peel-<version>.tar.gz`
(auto-generated source archive) plus the
`peel-v<version>-vendored.tar.gz` produced by
[release.yml](../../.github/workflows/release.yml). See
[`internal/PLAN_packaging.md`](../../internal/PLAN_packaging.md) §1
for the broader plan.

## §1 COPR publication (Phase A, days not weeks)

1. **Get a FAS account** at `accounts.fedoraproject.org`.
2. **Create a COPR project** at `copr.fedorainfracloud.org`. Enable
   the chroots you want to ship for (Fedora 42 / 43 / 44 / rawhide,
   EPEL 10 — both `x86_64` and `aarch64`). Fedora 42+ ships
   `cargo-rpm-macros` and a `rust` package new enough to satisfy
   the spec's `BuildRequires: rust >= 1.85`, so no extra chroot
   configuration is needed. Older chroots (Fedora 41, EPEL 9) lag
   the MSRV and aren't supported.
3. **Build a source RPM locally** (or let COPR build from a git
   ref):

   ```bash
   # On a Fedora host or in a fedora:latest container:
   dnf install rpm-build rpmlint
   # Produce a source RPM from the spec + the two Source tarballs.
   rpmbuild -bs packaging/fedora/peel.spec
   # Result: ~/rpmbuild/SRPMS/peel-<version>-1.fcXX.src.rpm
   ```

4. **Upload the SRPM**:

   ```bash
   copr-cli build <copr-username>/peel \
       ~/rpmbuild/SRPMS/peel-<version>-1.fcXX.src.rpm
   ```

   Or upload via the web UI.

5. **Users install** with:

   ```bash
   dnf copr enable <copr-username>/peel
   dnf install peel
   ```

## §2 Official Fedora repo (Phase B, weeks)

Heavier — requires package review + sponsor. Steps:

1. **File a package review bug** on `bugzilla.redhat.com` against
   `Package Review`. Title:
   `Review Request: peel — streaming HTTP archive extractor`.
   Attach the spec and an SRPM URL.
2. **Find a sponsor** in the `packager` group. Ask on
   `#fedora-rust:matrix.org` or `devel@lists.fedoraproject.org`
   once the review ticket is up.
3. **Address review feedback** until the ticket is approved.
4. **Request the dist-git repo**, push the spec, and submit Bodhi
   updates for each release.

See the Fedora Rust Packaging Guidelines at
<https://docs.fedoraproject.org/en-US/packaging-guidelines/Rust/>
for what reviewers look for. The vendored-leaf-application path
(which this spec uses) is the simpler route now that the
guidelines allow it; the older every-crate-is-a-package path is a
much heavier lift.

## §3 Per-release update flow

1. Bump `Version:` in [peel.spec](peel.spec).
2. Add a new `%changelog` entry at the top with today's date,
   matching the RPM changelog format
   (`* DOW MMM DD YYYY Name <email> - version-release`).
3. Confirm `release.yml` has produced both the source tarball
   (Source0) and the vendored-deps tarball (Source1) for the new
   tag — both must be downloadable from the GitHub release page.
4. Rebuild the SRPM and upload to COPR (or push to dist-git for
   official-repo). The Bodhi update flow handles per-release
   testing → stable promotion.

## §4 Local validation in a container

`rpmbuild` is Linux-only. Validate the spec from a Fedora
container. **macOS hosts** require two tar-time guards: cargo
vendor's tarball must drop `com.apple.provenance` xattrs, and
the rpmbuild's BUILD/RPMS dirs must not be bind-mounted from the
host (Docker-for-Mac's filesystem bridge materialises AppleDouble
files inside the container view, which trips lzma-sys's C build
during `%check`).

```bash
mkdir -p /tmp/peel-rpm-staging/SOURCES /tmp/peel-rpm-staging/SPECS

# Source0: github-style archive of the working tree.
git archive --prefix=peel-<version>/ HEAD \
    -o /tmp/peel-rpm-staging/SOURCES/peel-<version>.tar.gz

# Source1: vendored deps. On macOS, the COPYFILE_DISABLE +
# --no-mac-metadata flags strip the `com.apple.provenance` xattr
# that GNU tar otherwise extracts as `._*` AppleDouble files
# (which the lzma-sys C build then tries to compile). On Linux
# hosts both flags are no-ops / unsupported by GNU tar — drop them.
mkdir -p /tmp/peel-vendor-stage/peel-v<version>-vendored
( cd /tmp/peel-vendor-stage \
    && cargo vendor --locked --versioned-dirs vendor \
        --manifest-path /path/to/peel/Cargo.toml \
        > peel-v<version>-vendored/cargo-vendor-config.toml \
    && mv vendor peel-v<version>-vendored/vendor \
    && COPYFILE_DISABLE=true tar --no-mac-metadata \
        -czf /tmp/peel-rpm-staging/SOURCES/peel-v<version>-vendored.tar.gz \
        peel-v<version>-vendored )

cp packaging/fedora/peel.spec /tmp/peel-rpm-staging/SPECS/

# Run the build inside the container's own filesystem (only mount
# SOURCES + SPECS read-only). `cargo-rpm-macros` pulls in `cargo`
# + `rust` (1.95+ on Fedora 44) and provides the %%cargo_prep /
# %%cargo_build macros the spec uses for hardening RUSTFLAGS.
# `--without check` flips the spec's `%bcond_without check` so the
# heavy dev-dep build chain (xz2 → lzma-sys) doesn't run.
docker run --rm --platform linux/<arch> \
    -v /tmp/peel-rpm-staging/SOURCES:/sources:ro \
    -v /tmp/peel-rpm-staging/SPECS:/specs:ro \
    fedora:latest bash -c '
        dnf -y install rpm-build rpmlint cargo-rpm-macros \
            pkgconf-pkg-config libzstd-devel gcc tar > /dev/null
        mkdir -p /root/rpmbuild/SOURCES /root/rpmbuild/SPECS
        cp /sources/* /root/rpmbuild/SOURCES/
        cp /specs/* /root/rpmbuild/SPECS/
        # Build SRPM + binary RPMs (skip %check; ci.yml already runs cargo test).
        rpmbuild -bs --without check /root/rpmbuild/SPECS/peel.spec
        rpmbuild -bb --without check /root/rpmbuild/SPECS/peel.spec
        # Lint with the bundled rpmlintrc so the five domain-term
        # spelling false-positives stay filtered. The SRPM auto-
        # discovers `peel.rpmlintrc` from its own SOURCES dir;
        # the built-RPM set needs `-r` because rpmlint disables
        # auto-discovery when more than one rpm is passed at once.
        cp /sources/peel.rpmlintrc /root/rpmbuild/SRPMS/
        rpmlint /root/rpmbuild/SRPMS/peel-*.src.rpm
        rpmlint -r /sources/peel.rpmlintrc /root/rpmbuild/RPMS/*/peel-*.rpm
        find /root/rpmbuild/RPMS -name "*.rpm"
    '
```

Expected output: three RPMs (main + `peel-debuginfo` +
`peel-debugsource`), zero rpmlint errors or warnings on either
the SRPM or the built set, and the main RPM's `rpm -qlp`
listing of `/usr/bin/peel`, `/usr/share/man/man1/peel.1.gz`,
and `/usr/share/licenses/peel/{LICENSE-MIT,LICENSE-APACHE,NOTICE}`.

To run `%check` locally, add `xz-devel` to the dnf install line
and drop `--without check`. The dev-dep `xz2` crate
(`tests/test_xz_native.rs`) links against system liblzma during
the test build — the runtime `peel` binary does not.

## §5 What's been validated

The spec was end-to-end-tested in a `fedora:latest` (Fedora 44 at
validation time, rustc 1.95.0, cargo-rpm-macros 28.4) container
on aarch64. The full build via `cargo-rpm-macros` produced:

```
peel-0.6.12-1.fc44.aarch64.rpm           (main, ~5 MB)
peel-debuginfo-0.6.12-1.fc44.aarch64.rpm (debug symbols)
peel-debugsource-0.6.12-1.fc44.aarch64.rpm (source for symbols)
```

Verified on the produced binary: PIE executable, `BIND_NOW` +
full relro, frame pointers preserved, Fedora's `.note.package`
build-flags fingerprint emitted. `NEEDED libzstd.so.1` confirms
`-f system-libs` correctly routes to pkg-config.

rpmlint findings: zero errors and zero warnings on the SRPM
(auto-discovers the bundled `peel.rpmlintrc`) and on the built
set when invoked as `rpmlint -r packaging/fedora/peel.rpmlintrc
peel-*.rpm`. The rpmlintrc filters the five domain-term
spelling false-positives (`resumable`, `zst`, `xz`, `gz`, `rar`)
that the default Fedora dictionary raises against Summary /
%%description; see the file header for the per-term rationale.
