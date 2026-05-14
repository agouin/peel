# AUR packaging for `peel`

This directory is the canonical source for the two AUR packages
shipped for `peel`:

- [`peel`](peel/PKGBUILD) — builds from the upstream source tarball
  (`https://github.com/agouin/peel/archive/v<version>.tar.gz`).
  Links against Arch's system `libzstd` via the `system-libs`
  Cargo feature so security updates flow without rebuilding the
  package.
- [`peel-bin`](peel-bin/PKGBUILD) — installs the prebuilt binary
  from the corresponding GitHub release tarball. No compile, much
  faster install. Mostly statically linked (vendored libzstd, ring's
  bundled libcrypto), so it only depends on `glibc` and `gcc-libs`.

The two packages declare `provides=('peel')` and `conflicts=`
each other so users pick one or the other.

## First-time publication

The AUR is a separate Git repo per package, hosted at
`ssh://aur@aur.archlinux.org/<pkgname>.git`. To publish:

1. Have an AUR account at `aur.archlinux.org` with your SSH key
   uploaded.
2. For each package:

   ```bash
   git clone ssh://aur@aur.archlinux.org/peel.git aur-peel
   cp packaging/aur/peel/PKGBUILD aur-peel/
   cd aur-peel
   makepkg --printsrcinfo > .SRCINFO
   git add PKGBUILD .SRCINFO
   git commit -m "Initial import: peel <version>"
   git push
   ```

   And separately for `peel-bin`:

   ```bash
   git clone ssh://aur@aur.archlinux.org/peel-bin.git aur-peel-bin
   cp packaging/aur/peel-bin/PKGBUILD aur-peel-bin/
   cd aur-peel-bin
   makepkg --printsrcinfo > .SRCINFO
   git add PKGBUILD .SRCINFO
   git commit -m "Initial import: peel-bin <version>"
   git push
   ```

3. The package appears on `aur.archlinux.org/packages/<pkgname>`
   within a minute or so. Users install with `paru -S peel` or
   `yay -S peel-bin`.

## Per-release update flow

When a new upstream `v<version>` tag is released:

1. Bump `pkgver` in both PKGBUILDs.
2. Fill in `sha256sums` (currently `'SKIP'`) with the real
   values:
   - For `peel`: `curl -sL https://github.com/agouin/peel/archive/v<version>.tar.gz | sha256sum`
   - For `peel-bin`: extract from the release's `SHA256SUMS` file.
3. Regenerate `.SRCINFO` (`makepkg --printsrcinfo > .SRCINFO`)
   and push each AUR repo.

The PLAN suggests this could be automated in `release.yml` on tag
push (`internal/PLAN_packaging.md` §7). Defer that until we've
actually published the AUR packages once by hand and confirmed
they work end-to-end.

## Verifying a PKGBUILD locally (on an Arch host)

```bash
cd packaging/aur/peel
makepkg --syncdeps --rmdeps --noconfirm
namcap PKGBUILD
namcap *.pkg.tar.zst
```

`namcap` flags packaging issues that `shellcheck` doesn't catch
(missing/unused deps, missing license file references, etc.).
It's Arch-only and isn't installed via Homebrew.
