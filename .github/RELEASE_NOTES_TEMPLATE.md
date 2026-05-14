## Install

Pick the matching path for your OS. All artifacts are signed by GitHub's
release infrastructure and checksummed in `SHA256SUMS`.

### Debian / Ubuntu (`.deb`)

```bash
arch=$(dpkg --print-architecture)
curl -fsSLO https://github.com/agouin/peel/releases/download/${TAG}/peel_${VERSION}-1_${arch}.deb
sudo dpkg -i peel_${VERSION}-1_${arch}.deb
```

### Fedora / RHEL / CentOS Stream / Rocky / Alma (`.rpm`)

The Fedora release suffix (`.fcXX.`) tracks whatever Fedora the build host
ran, so the exact filename varies between releases. Easiest path with the
`gh` CLI:

```bash
gh release download ${TAG} -R agouin/peel -p "peel-*.fc*.$(uname -m).rpm"
sudo rpm -i peel-*.fc*.$(uname -m).rpm
```

Or grab the matching file directly from the [release page](https://github.com/agouin/peel/releases/tag/${TAG}).

### Arch Linux (`.pkg.tar.zst`)

```bash
curl -fsSLO https://github.com/agouin/peel/releases/download/${TAG}/peel-${VERSION}-1-x86_64.pkg.tar.zst
sudo pacman -U peel-${VERSION}-1-x86_64.pkg.tar.zst
```

Arch Linux ARM users: install via the AUR (`paru -S peel-bin`) instead;
the official Arch distribution is x86_64-only.

### Alpine Linux (`.apk`)

```bash
arch=$(apk --print-arch)
curl -fsSLO https://github.com/agouin/peel/releases/download/${TAG}/peel-${VERSION}-r0.apk
sudo apk add --allow-untrusted peel-${VERSION}-r0.apk
```

`--allow-untrusted` is required because the per-release `.apk` is signed
with an ephemeral CI key, not Alpine's distribution keyring. The future
aports-published version will install with plain `apk add peel`.

### Linux (any other distro — static musl binary)

```bash
arch=$(uname -m)
curl -fsSLo /tmp/peel.tar.gz \
    https://github.com/agouin/peel/releases/download/${TAG}/peel-${TAG}-${arch}-unknown-linux-musl.tar.gz
tar -xzf /tmp/peel.tar.gz -C /tmp
sudo install -m0755 /tmp/peel-${TAG}-${arch}-unknown-linux-musl/peel /usr/local/bin/peel
```

Replace `-musl` with `-gnu` if you'd prefer glibc dynamic linking and
your distro is glibc-based.

### macOS (Apple Silicon)

```bash
curl -fsSLo /tmp/peel.tar.gz \
    https://github.com/agouin/peel/releases/download/${TAG}/peel-${TAG}-aarch64-apple-darwin.tar.gz
tar -xzf /tmp/peel.tar.gz -C /tmp
sudo install -m0755 /tmp/peel-${TAG}-aarch64-apple-darwin/peel /usr/local/bin/peel
```

### Verify integrity (optional, all OSes)

```bash
gh release download ${TAG} -R agouin/peel -p 'SHA256SUMS'
gh release download ${TAG} -R agouin/peel -p '<file-you-downloaded>'
shasum -c SHA256SUMS --ignore-missing
```

---
