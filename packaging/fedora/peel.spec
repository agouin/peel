Name:           peel
Version:        0.7.9
Release:        1%{?dist}
Summary:        Streaming, resumable, space-efficient HTTP archive extractor

License:        MIT OR Apache-2.0
URL:            https://github.com/agouin/peel
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz#/%{name}-%{version}.tar.gz
Source1:        peel.rpmlintrc

BuildRequires:  rust >= 1.85
BuildRequires:  cargo-rpm-macros >= 24

BuildRequires:  (crate(thiserror/default) >= 2.0.0 with crate(thiserror/default) < 3.0.0~)
BuildRequires:  (crate(rustls/std) >= 0.23.0 with crate(rustls/std) < 0.24.0~)
BuildRequires:  (crate(rustls/ring) >= 0.23.0 with crate(rustls/ring) < 0.24.0~)
BuildRequires:  (crate(rustls/tls12) >= 0.23.0 with crate(rustls/tls12) < 0.24.0~)
BuildRequires:  (crate(webpki-roots/default) >= 0.26.0 with crate(webpki-roots/default) < 0.27.0~)
BuildRequires:  (crate(zstd) >= 0.13.0 with crate(zstd) < 0.14.0~)
BuildRequires:  (crate(clap/default) >= 4.0.0 with crate(clap/default) < 5.0.0~)
BuildRequires:  (crate(clap/derive) >= 4.0.0 with crate(clap/derive) < 5.0.0~)
BuildRequires:  (crate(clap_mangen/default) >= 0.2.0 with crate(clap_mangen/default) < 0.3.0~)
BuildRequires:  (crate(anyhow/default) >= 1.0.0 with crate(anyhow/default) < 2.0.0~)
BuildRequires:  (crate(tracing/std) >= 0.1.0 with crate(tracing/std) < 0.2.0~)
BuildRequires:  (crate(tracing-subscriber/fmt) >= 0.3.0 with crate(tracing-subscriber/fmt) < 0.4.0~)
BuildRequires:  (crate(tracing-subscriber/ansi) >= 0.3.0 with crate(tracing-subscriber/ansi) < 0.4.0~)
BuildRequires:  (crate(hyper/client) >= 1.0.0 with crate(hyper/client) < 2.0.0~)
BuildRequires:  (crate(hyper/http1) >= 1.0.0 with crate(hyper/http1) < 2.0.0~)
BuildRequires:  (crate(hyper/http2) >= 1.0.0 with crate(hyper/http2) < 2.0.0~)
BuildRequires:  (crate(hyper-util/client) >= 0.1.0 with crate(hyper-util/client) < 0.2.0~)
BuildRequires:  (crate(hyper-util/client-legacy) >= 0.1.0 with crate(hyper-util/client-legacy) < 0.2.0~)
BuildRequires:  (crate(hyper-util/http1) >= 0.1.0 with crate(hyper-util/http1) < 0.2.0~)
BuildRequires:  (crate(hyper-util/http2) >= 0.1.0 with crate(hyper-util/http2) < 0.2.0~)
BuildRequires:  (crate(hyper-util/tokio) >= 0.1.0 with crate(hyper-util/tokio) < 0.2.0~)
BuildRequires:  (crate(hyper-rustls/http1) >= 0.27.0 with crate(hyper-rustls/http1) < 0.28.0~)
BuildRequires:  (crate(hyper-rustls/http2) >= 0.27.0 with crate(hyper-rustls/http2) < 0.28.0~)
BuildRequires:  (crate(hyper-rustls/ring) >= 0.27.0 with crate(hyper-rustls/ring) < 0.28.0~)
BuildRequires:  (crate(hyper-rustls/tls12) >= 0.27.0 with crate(hyper-rustls/tls12) < 0.28.0~)
BuildRequires:  (crate(http/std) >= 1.0.0 with crate(http/std) < 2.0.0~)
BuildRequires:  (crate(http-body) >= 1.0.0 with crate(http-body) < 2.0.0~)
BuildRequires:  (crate(http-body-util) >= 0.1.0 with crate(http-body-util) < 0.2.0~)
BuildRequires:  (crate(bytes/std) >= 1.0.0 with crate(bytes/std) < 2.0.0~)
BuildRequires:  (crate(tokio/rt) >= 1.0.0 with crate(tokio/rt) < 2.0.0~)
BuildRequires:  (crate(tokio/net) >= 1.0.0 with crate(tokio/net) < 2.0.0~)
BuildRequires:  (crate(tokio/time) >= 1.0.0 with crate(tokio/time) < 2.0.0~)
BuildRequires:  (crate(tokio/macros) >= 1.0.0 with crate(tokio/macros) < 2.0.0~)
BuildRequires:  (crate(tokio/sync) >= 1.0.0 with crate(tokio/sync) < 2.0.0~)
BuildRequires:  (crate(io-uring) >= 0.6.0 with crate(io-uring) < 0.7.0~)

# Rust inner attributes (`#![...]`) look like malformed shebangs to
# brp-mangle-shebangs; exclude .rs from the check.
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
# windows-sys is a Windows-only cfg-gated dep (rust-windows-sys is not
# packaged in Fedora). Cargo's resolver inspects every target block
# regardless of host target, so strip the block before %cargo_prep runs.
sed -i "/^\[target\.'cfg(windows)'\.dependencies\]$/,/^] }$/d" Cargo.toml
%cargo_prep

%build
%cargo_build -- --bin peel
%cargo_build -f man-page -- --bin peel-mangen
mkdir -p target/man
target/release/peel-mangen target/man/peel.1

%install
install -D -m0755 target/release/peel %{buildroot}%{_bindir}/peel
install -D -m0644 target/man/peel.1   %{buildroot}%{_mandir}/man1/peel.1

%files
%license LICENSE-MIT LICENSE-APACHE NOTICE
%doc README.md
%{_bindir}/peel
%{_mandir}/man1/peel.1*

%changelog
* Fri Jun 12 2026 Andrew Gouin <andrew@gouin.io> - 0.7.9-1
- Initial Fedora package.
