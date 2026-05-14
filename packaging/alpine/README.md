# Alpine packaging for `peel`

This directory holds [`APKBUILD`](APKBUILD) — the canonical Alpine
build recipe for `peel`. It drives:

- **Per-release `.apk` builds** shipped as GitHub release assets
  (the `package-alpine` job in
  [release.yml](../../.github/workflows/release.yml) runs `abuild`
  against this file in an `alpine:latest` container, fanned across
  `x86_64` and `aarch64`).
- **Future `aports` submission**, which is the path to
  `apk add peel` from the official Alpine repos. See
  [`internal/PLAN_packaging.md`](../../internal/PLAN_packaging.md) §5.

## Why this lives here, not under `/`

Alpine's `aports` is a monorepo of `APKBUILD` files; submission is a
merge request that drops `APKBUILD` into `testing/peel/`. Our copy
is the canonical "what we'd submit" version. The MR flow uses
`cp packaging/alpine/APKBUILD /path/to/aports/testing/peel/` plus
the standard `abuild checksum` to refresh sha512s.

## §1 What's in here

| File        | Purpose                                                |
| ----------- | ------------------------------------------------------ |
| `APKBUILD`  | Package recipe (source URLs, deps, build/package fns)  |
| `README.md` | This file                                              |

The package ships:

- `/usr/bin/peel` — the binary
- `peel-doc` subpackage — man page (gzipped by abuild) + license
  files. Alpine convention puts these in a separate subpackage so
  the runtime package stays minimal.

## §2 Source layout

`APKBUILD`'s `source=` line references two upstream URLs:

- `peel-<version>.tar.gz` — the GitHub auto-generated source archive
- `peel-v<version>-vendored.tar.gz` — the vendored crates tarball
  produced by `release.yml`'s `vendor` job. Required because aports
  builds run in a network-isolated chroot, so cargo can't fetch
  from crates.io.

`sha512sums` is `SKIP` for both in the committed `APKBUILD`. The
[release.yml `package-alpine` job](../../.github/workflows/release.yml)
patches them in at build time with the real digests; for an `aports`
MR, run `abuild checksum` after dropping the file into
`testing/peel/`.

## §3 Per-release update flow

1. Bump `pkgver=` in [APKBUILD](APKBUILD).
2. (Optional) bump `pkgrel=` if the package shape changed but
   `pkgver` didn't.
3. CI: `release.yml`'s `package-alpine` job computes the real sha512
   from the just-built source + vendored tarballs, patches the
   APKBUILD, and runs `abuild -r`. Nothing manual here.
4. aports MR (if applicable): copy the patched APKBUILD to
   `testing/peel/APKBUILD`, run `abuild checksum`, open the MR.

## §4 Local validation in a container

`abuild` is Alpine-specific. Validate the APKBUILD from an Alpine
container — the same flow `release.yml` runs:

```bash
ver=0.5.0
work=/tmp/peel-apk-staging
mkdir -p "${work}/distfiles"

# Source0: github-style archive of the working tree.
git archive --prefix="peel-${ver}/" HEAD \
    -o "${work}/distfiles/peel-${ver}.tar.gz"

# Source1: vendored crates. On macOS, the COPYFILE_DISABLE +
# --no-mac-metadata flags strip `com.apple.provenance` xattrs that
# GNU tar otherwise extracts as `._*` AppleDouble files (which
# lzma-sys's C build would try to compile during cargo build);
# on Linux these flags are no-ops / unsupported by GNU tar.
mkdir -p /tmp/peel-vendor-stage/peel-v${ver}-vendored
( cd /tmp/peel-vendor-stage \
    && cargo vendor --locked --versioned-dirs vendor \
        --manifest-path /path/to/peel/Cargo.toml \
        > peel-v${ver}-vendored/cargo-vendor-config.toml \
    && mv vendor peel-v${ver}-vendored/vendor \
    && COPYFILE_DISABLE=true tar --no-mac-metadata \
        -czf "${work}/distfiles/peel-v${ver}-vendored.tar.gz" \
        peel-v${ver}-vendored )

# Compute real sha512 and patch APKBUILD.
SHA1=$(sha512sum "${work}/distfiles/peel-${ver}.tar.gz" | awk '{print $1}')
SHA2=$(sha512sum "${work}/distfiles/peel-v${ver}-vendored.tar.gz" | awk '{print $1}')
cp packaging/alpine/APKBUILD "${work}/APKBUILD"
python3 -c "
import re
content = open('${work}/APKBUILD').read()
block = 'sha512sums=\"\\n${SHA1}  peel-${ver}.tar.gz\\n${SHA2}  peel-v${ver}-vendored.tar.gz\\n\"'
content = re.sub(r'sha512sums=\"[^\"]*\"', block, content, count=1, flags=re.DOTALL)
open('${work}/APKBUILD', 'w').write(content)
"

# Run abuild inside Alpine. Mount the work dir at /work and run the
# build as a non-root `builder` user (abuild refuses root).
docker run --rm --platform linux/<your-arch> \
    -v "${work}":/work:rw \
    alpine:latest sh -c '
        apk add --no-cache alpine-sdk build-base abuild cargo rust \
            zstd-dev pkgconf coreutils
        addgroup -S builder; adduser -S -G builder builder
        addgroup builder abuild
        su builder -c "abuild-keygen -a -n"
        cp /home/builder/.abuild/*.rsa.pub /etc/apk/keys/

        # Pre-populate the distfiles cache so abuild uses our local
        # files instead of fetching from upstream (which would 404 for
        # the vendored tarball on the first release).
        mkdir -p /var/cache/distfiles
        cp /work/distfiles/* /var/cache/distfiles/

        mkdir -p /tmp/build
        cp /work/APKBUILD /tmp/build/
        chown -R builder:builder /tmp/build

        su builder -c "cd /tmp/build && REPODEST=/tmp/packages abuild -r -F"
        find /tmp/packages -name peel-\*.apk
    '
```

Expected output: two `.apk` files (main + `-doc`), depends correctly
resolved to `so:libc.musl-*.so.1, so:libgcc_s.so.1, so:libzstd.so.1`
(proving the `system-libs` Cargo feature is doing the right thing).
