# syntax=docker/dockerfile:1.7

# Multi-arch image for `peel`. The builder stage is pinned to BUILDPLATFORM
# so it always runs natively on the host runner; cross-arch outputs are
# produced by Rust + a matching `gcc-<triple>` cross toolchain rather than
# by emulating the target under QEMU.
#
# Drives `linux/amd64` and `linux/arm64`. Other platforms fail fast.

ARG RUST_VERSION=1.95.0
ARG DEBIAN_RELEASE=trixie

FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-slim-${DEBIAN_RELEASE} AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM

WORKDIR /src

# Resolve TARGETPLATFORM -> Rust triple + matching C cross toolchain.
# zstd-sys / lzma-sys / ring are all cc-rs based, so they pick up
# `CC_<triple>` and the cargo `LINKER` env vars we export below.
# When BUILDPLATFORM == TARGETPLATFORM we use the image's native gcc;
# otherwise we install the matching cross-gcc (which pulls in the
# matching cross binutils, including the `<triple>-strip` we need
# to strip a foreign-arch binary on the host).
RUN <<'EOF' bash
set -euo pipefail
case "${TARGETPLATFORM}" in
  linux/amd64)
    triple=x86_64-unknown-linux-gnu
    cross_pkg=gcc-x86-64-linux-gnu
    cc=x86_64-linux-gnu-gcc
    ;;
  linux/arm64)
    triple=aarch64-unknown-linux-gnu
    cross_pkg=gcc-aarch64-linux-gnu
    cc=aarch64-linux-gnu-gcc
    ;;
  *)
    echo "unsupported TARGETPLATFORM: ${TARGETPLATFORM}" >&2
    exit 1
    ;;
esac

if [[ "${TARGETPLATFORM}" != "${BUILDPLATFORM}" ]]; then
  apt-get update
  apt-get install -y --no-install-recommends "${cross_pkg}"
  rm -rf /var/lib/apt/lists/*
fi

mkdir -p /etc/peel-build
{
  echo "TRIPLE=${triple}"
  echo "CC=${cc}"
} > /etc/peel-build/env
EOF

RUN . /etc/peel-build/env && rustup target add "${TRIPLE}"

COPY . .

# Cross-compile peel. Cargo registry / git caches are arch-agnostic and
# shared across builds; the build target dir isn't cached here because
# we want the output layer to be the source of truth for what gets
# copied into the runtime image.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    <<'EOF' bash
set -euo pipefail
. /etc/peel-build/env
upper=$(echo "${TRIPLE}" | tr 'a-z-' 'A-Z_')
export "CC_${TRIPLE//-/_}=${CC}"
export "CARGO_TARGET_${upper}_LINKER=${CC}"

cargo build --release --locked --target "${TRIPLE}" --bin peel

bin="target/${TRIPLE}/release/peel"
if [[ "${TARGETPLATFORM}" == "${BUILDPLATFORM}" ]]; then
  strip "${bin}"
else
  "${CC%-gcc}-strip" "${bin}"
fi
install -Dm0755 "${bin}" /out/peel
EOF


FROM debian:${DEBIAN_RELEASE}-slim AS runtime

# `ca-certificates` is required so rustls's webpki-roots resolution can
# validate TLS chains against the system trust store at runtime.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/peel /usr/local/bin/peel

ENTRYPOINT ["/usr/local/bin/peel"]
