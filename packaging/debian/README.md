# Debian / Ubuntu source packaging for `peel`

This directory is the canonical `debian/` tree for `peel`. The same
files drive:

- **Launchpad PPA builds** for Ubuntu (Phase A, fastest)
- **Official Debian archive** uploads (Phase B, requires sponsor)

Ubuntu users that just want a `.deb` without a PPA can also use the
GitHub-released `peel_<version>_<arch>.deb` from
[release.yml](../../.github/workflows/release.yml), which is produced
by `cargo-deb` from `[package.metadata.deb]` in `Cargo.toml`. The PPA
path here is for `apt`-managed installs with automatic security
update flow.

See [`internal/PLAN_packaging.md`](../../internal/PLAN_packaging.md) §2
(PPA) and §3 (Debian archive) for the broader plan.

## §1 Why this lives under `packaging/debian/` and not `/debian/`

The conventional Debian layout puts `debian/` at the repo root, but
that location is reserved for the actual build (the source tree is
the one `dpkg-buildpackage` consumes, and it expects `debian/` next
to upstream files). Keeping our canonical copy under
`packaging/debian/` and copying it into place at build time means:

- The repo root stays clean for non-Debian builds (cargo, AUR,
  Fedora) that don't need a `debian/` dir.
- The packaging artifacts for every distro live together under
  `packaging/`.

The cost is one `cp -r packaging/debian/ debian/` before the
`dpkg-buildpackage` invocation — captured in the build scripts
below.

## §2 What's in here

| File              | Purpose                                                             |
| ----------------- | ------------------------------------------------------------------- |
| `control`         | Package metadata (Source, Build-Depends, runtime Depends, …)        |
| `changelog`       | Version history in Debian's strict per-line format                  |
| `copyright`       | Machine-readable license metadata for the source tree               |
| `rules`           | Build orchestration (makefile-driven by `debhelper`)                |
| `source/format`   | `3.0 (quilt)` — modern Debian source package format                 |

## §3 Phase A — Launchpad PPA

The PPA path lets us ship today without waiting on Debian sponsorship.
Launchpad's build farm runs each new tag's source package against
every Ubuntu series we enable.

1. **Create the PPA** at `launchpad.net` — `ppa:agouin/peel` is the
   conventional name.
2. **Upload an OpenPGP key** to `keyserver.ubuntu.com` and to
   Launchpad; Launchpad uses your key to verify uploaded source
   packages.
3. **Stage and build** the source package locally (see §5).
4. **Push to the PPA** with `dput`:

   ```bash
   dput ppa:agouin/peel \
       peel_<version>-1ppa1_source.changes
   ```

5. **Users install** with:

   ```bash
   sudo add-apt-repository ppa:agouin/peel
   sudo apt update && sudo apt install peel
   ```

Friction: low. The first upload takes 5–10 minutes after `dput`
before the PPA's build farm finishes. Per-release uploads are a
single `dput` after bumping `debian/changelog`.

## §4 Phase B — Official Debian archive

Heavier — requires ITP + sponsor + NEW queue. Detailed flow in
`internal/PLAN_packaging.md` §3. Summary:

1. **File an ITP** (`Intent To Package`) bug on `bugs.debian.org`
   against `wnpp`. Subject:
   `ITP: peel -- streaming HTTP archive extractor`.
2. **Find a sponsor** in the Debian Rust team or via
   `mentors.debian.net`.
3. **Sponsor uploads** the source package to Debian unstable's NEW
   queue. Reviewers check license, copyright, lintian output.
4. **Once in unstable**, the package migrates to testing after 5–10
   days and to stable on the next release cycle. Ubuntu's
   auto-sync flow then picks it up.

## §5 Per-release update flow

1. Bump `debian/changelog` with a new entry. Use `dch -i`
   (interactive) or:

   ```
   peel (<new-version>-1) unstable; urgency=medium

     * <human-readable change>

    -- Andrew Gouin <andrew@gouin.io>  <RFC822-formatted date>
   ```

2. Confirm `release.yml` has produced both the source tarball
   (Source0) and the vendored-deps tarball (Source1) for the new
   tag.
3. Rebuild the source package (§6) and `dput` to the PPA, or hand
   off to a sponsor for the Debian archive path.

## §6 Local validation in a container

`dpkg-buildpackage` is Linux-only. Validate from a Debian
container. Note the same `COPYFILE_DISABLE` + `--no-mac-metadata`
guards that the Fedora flow needs (see
`packaging/fedora/README.md` §4) — macOS-produced vendored
tarballs otherwise smuggle `com.apple.provenance` xattrs through
to the build chroot.

```bash
ver=0.5.0
work=/tmp/peel-deb-staging

# Stage the upstream source as `peel_<version>.orig.tar.gz`. The
# orig tarball includes the vendored crates so the build chroot
# doesn't need network access — same shape Debian's lintian-clean
# Rust-leaf-application packages use.
mkdir -p "${work}"
rm -rf "${work}/peel-${ver}"
git archive --prefix=peel-${ver}/ HEAD | tar -x -C "${work}"

# Extract the vendored tarball into the source tree. The tarball
# expands to `peel-v<version>-vendored/{vendor, cargo-vendor-config.toml}`
# — pull both up into the source root via --strip-components=1.
tar -xzf /path/to/peel-v${ver}-vendored.tar.gz -C "${work}/peel-${ver}" \
    --strip-components=1

# Copy our canonical debian/ tree into the source root.
cp -r packaging/debian "${work}/peel-${ver}/debian"

# Build the orig tarball (without debian/).
( cd "${work}" && \
    COPYFILE_DISABLE=true tar --no-mac-metadata --exclude='peel-${ver}/debian' \
        -czf "peel_${ver}.orig.tar.gz" "peel-${ver}/" )

# Run dpkg-buildpackage inside a Debian container.
docker run --rm --platform linux/<arch> \
    -v "${work}":/work:rw \
    debian:trixie bash -c '
        set -ex
        apt-get update -qq
        apt-get install -y --no-install-recommends \
            build-essential debhelper devscripts dpkg-dev fakeroot \
            rustc cargo libzstd-dev pkg-config ca-certificates curl \
            > /dev/null
        # If archive rustc < 1.85, install a newer toolchain via
        # rustup (PPA convention; Debian archive uploads cannot do
        # this — they need the archive rustc to be >= 1.85).
        if [ "$(rustc -V | awk \"{print \\$2}\")" \"<\" "1.85" ]; then
            curl -fsSL https://sh.rustup.rs | sh -s -- -y \
                --default-toolchain 1.95.0 --profile minimal
            . "$HOME/.cargo/env"
        fi
        cd /work/peel-0.5.0
        dpkg-buildpackage -us -uc -b
        ls /work/*.deb
        dpkg-deb -I /work/peel_*.deb
        dpkg-deb -c /work/peel_*.deb
    '
```

Expected output: a `peel_0.5.0-1_<arch>.deb` (~5 MB) with
`/usr/bin/peel`, `/usr/share/man/man1/peel.1.gz`, and the
licenses under `/usr/share/doc/peel/`. Lintian warnings about
`bad-distribution-in-changes-file` and `vendored-rust-crates` are
expected for a non-archive build.
