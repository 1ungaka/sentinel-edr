# RPM packaging for CAU EDR (Fedora / RHEL / openSUSE family).
#
# Builds offline from the release source tarball and its committed vendor/
# tree, exactly like the Debian package and the Arch PKGBUILD: no module is
# downloaded at build time. The install steps are the Makefile's own targets,
# so the three packagings cannot drift apart on what they ship.
#
# Build:
#   rpmbuild -ba packaging/rpm/cau.spec \
#       --define "cau_version 0.1.0" \
#       --define "_sourcedir /path/holding/cau-0.1.0.tar.gz"
#
# The source is the fixed-bytes tarball the release job publishes
# (cau-<version>.tar.gz, top-level directory cau-<version>/), not GitHub's
# generated archive, whose bytes are not stable.

%{!?cau_version: %global cau_version 0.1.0}

Name:           cau
Version:        %{cau_version}
Release:        1%{?dist}
Summary:        Transparent open-source malware detection engine
License:        MIT
URL:            https://github.com/s-b-repo/cau
Source0:        https://github.com/s-b-repo/cau/releases/download/v%{version}/cau-%{version}.tar.gz

BuildRequires:  golang >= 1.24
BuildRequires:  yara-devel >= 4.3
BuildRequires:  pkgconf-pkg-config
BuildRequires:  gcc
BuildRequires:  make
BuildRequires:  systemd-rpm-macros
Requires(pre):  shadow-utils

# The binaries are built by the Go toolchain with its own flags; rpm's debug
# package extraction does not understand them.
%global debug_package %{nil}

%description
CAU is a malware detection and triage engine written in Go. Its detectors
read every file once; every finding is explained with a labelled class and a
MITRE ATT&CK technique, and every report is machine-readable with CI-friendly
exit codes. It scans files and directories, inspects the live process table,
reads the boot chain and UEFI firmware images, and gates detection changes
against a measured evaluation baseline. YARA matching runs in-process through
libyara.

Detection and on-host response are complete in this package and unmetered.

%prep
%autosetup -n cau-%{version}

%build
# -mod=vendor and GOFLAGS keep the build offline; GOPROXY=off makes any
# attempt to reach the network a build failure rather than a silent fetch.
export GOPROXY=off GOFLAGS=-mod=vendor CGO_ENABLED=1
%make_build build build-mcp VERSION=%{version}

%install
export GOPROXY=off GOFLAGS=-mod=vendor CGO_ENABLED=1
make install install-systemd install-logrotate install-config \
    PREFIX=%{_prefix} DESTDIR=%{buildroot} VERSION=%{version}

%check
# The packaged binary must at least identify itself and find its resources.
%{buildroot}%{_bindir}/cau version
%{buildroot}%{_bindir}/cau scan --quiet \
    --db %{buildroot}%{_datadir}/cau/signatures/hashes.txt \
    --rules %{buildroot}%{_datadir}/cau/rules LICENSE

%pre
# The unprivileged user the optional systemd units run as. Harmless if the
# units are never enabled.
getent group cau >/dev/null || groupadd -r cau
getent passwd cau >/dev/null || \
    useradd -r -g cau -d /var/lib/cau -s /sbin/nologin -c "CAU EDR" cau
exit 0

%post
# The units are installed and never enabled or started by the package: a
# scanner that starts walking the filesystem at install time is a surprise.
%systemd_post cau-scan.timer cau-daemon.service cau-defend.service cau-update.timer

%preun
%systemd_preun cau-scan.timer cau-daemon.service cau-defend.service cau-update.timer

%postun
%systemd_postun_with_restart cau-daemon.service cau-defend.service

%files
%license %{_datadir}/licenses/cau/LICENSE
%doc %{_datadir}/doc/cau/README.md
%doc %{_datadir}/doc/cau/CHANGELOG.md
%{_bindir}/cau
%{_bindir}/cau-mcp
%dir %{_datadir}/cau
%{_datadir}/cau/rules
%{_datadir}/cau/signatures
%{_mandir}/man1/cau.1*
%{_mandir}/man1/cau-mcp.1*
%{_datadir}/bash-completion/completions/cau
%{_datadir}/zsh/site-functions/_cau
%{_datadir}/fish/vendor_completions.d/cau.fish
%{_prefix}/lib/systemd/system/cau-daemon.service
%{_prefix}/lib/systemd/system/cau-defend.service
%{_prefix}/lib/systemd/system/cau-scan.service
%{_prefix}/lib/systemd/system/cau-scan.timer
%{_prefix}/lib/systemd/system/cau-update.service
%{_prefix}/lib/systemd/system/cau-update.timer
%dir %{_sysconfdir}/cau
%config(noreplace) %{_sysconfdir}/cau/cau.conf
%config(noreplace) %{_sysconfdir}/logrotate.d/cau

%changelog
* Fri Nov 06 2026 Stephan Botes <stephanbotes0@gmail.com> - 0.1.0-1
- Initial RPM packaging.
