Name:           peel
Version:        0.7.11
Release:        %autorelease
Summary:        Streaming, resumable, space-efficient HTTP archive extractor

SourceLicense:  MIT OR Apache-2.0
# Statically linked crate licenses: AND of `%%cargo_license_summary
# -f system-libs`; per-crate breakdown ships in LICENSE.dependencies.
License:        %{shrink:
    (Apache-2.0 AND ISC AND (MIT OR Apache-2.0)) AND
    (Apache-2.0 OR ISC OR MIT) AND
    (Apache-2.0 OR MIT) AND
    BSD-3-Clause AND
    CDLA-Permissive-2.0 AND
    ISC AND
    MIT AND
    (MIT OR Apache-2.0)
}
URL:            https://github.com/agouin/peel
Source0:        %{url}/archive/v%{version}/%{name}-%{version}.tar.gz
Source1:        peel.rpmlintrc

BuildRequires:  cargo-rpm-macros >= 24
# system-libs links Fedora's libzstd instead of the vendored C copy.
BuildRequires:  pkgconfig(libzstd)

%description
peel downloads compressed archives over HTTP and streams them through
decompression in a single pass, hole-punching the compressed bytes from
disk as the decoder advances. A SIGKILL mid-extraction resumes exactly
where it left off, byte-identical to a clean run.

Supports tar / tar.zst / tar.xz / tar.lz4 / tar.gz / tar.bz2 / zip /
7z / rar (rar5 + rar3/rar4), plus the raw single-stream forms of those
codecs.

%prep
%autosetup -n %{name}-%{version} -p1
# windows-sys is Windows-only and unpackaged in Fedora; drop its target block.
sed -i "/^\[target\.'cfg(windows)'\.dependencies\]$/,/^] }$/d" Cargo.toml
%cargo_prep

%generate_buildrequires
# Cover every feature any %%cargo_build below enables (man-page pulls
# clap_mangen; system-libs pulls the pkg-config path for libzstd).
%cargo_generate_buildrequires -f man-page,system-libs

%build
%cargo_build -f system-libs -- --bin peel
%cargo_build -f man-page,system-libs -- --bin peel-mangen
%{cargo_license_summary -f system-libs}
%{cargo_license -f system-libs} > LICENSE.dependencies
mkdir -p target/man
target/rpm/peel-mangen target/man/peel.1

%install
install -Dpm0755 target/rpm/peel -t %{buildroot}%{_bindir}
install -Dpm0644 target/man/peel.1 -t %{buildroot}%{_mandir}/man1

%files
%license LICENSE-MIT LICENSE-APACHE NOTICE
%license LICENSE.dependencies
%doc README.md
%{_bindir}/peel
%{_mandir}/man1/peel.1*

%changelog
%autochangelog
