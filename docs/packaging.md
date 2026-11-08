# Packaging and distribution

CAU ships as source and as distro packages for Debian, Kali Linux and Arch
Linux. Every package is built and *tested* by CI: a package that installs but
cannot detect a known sample fails the pipeline. This document is the maintainer
guide; the user-facing instructions live in [installation.md](installation.md).

## What CI does

`make ci` is the engine gate (lint, tests, race, rules lint, coverage gate, eval
baseline). `.github/workflows/package.yml` is the packaging gate, on every push,
every pull request and every tag. The `pull_request` trigger is a
`paths-ignore` list, so a change confined to Markdown, wiki or docs gets no
runner time; packaging, scripts and `debian/` changes run the gate. Each job carries a
bounded runtime:

| Job | Container | Builds | Then |
|---|---|---|---|
| `Debian (.deb, x86_64)` / `Debian (.deb, arm64)` | `debian:trixie` | source + binary `.deb` (the source package is built from the tag tarball) | `dpkg -i`, then `scripts/package-smoke.sh` |
| `Kali Linux (.deb, x86_64)` / `Kali Linux (.deb, arm64)` | `kalilinux/kali-rolling:latest` | binary `.deb` | `apt install ./*.deb`, then smoke test |
| `Arch Linux (.pkg.tar.zst, x86_64)` / `Arch Linux (.pkg.tar.zst, arm64)` | `archlinux:latest` / `menci/archlinuxarm:latest` | `.pkg.tar.zst` from the `PKGBUILD`, with the current checkout staged as source | `pacman -U`, then smoke test |

Both architectures are built natively, not cross-compiled: the arm64 jobs run
on an arm64 runner (`ubuntu-24.04-arm`), so the cgo binding to libyara is
compiled, not translated, and the package is the one an arm64 user actually
gets. `arch=('x86_64' 'aarch64')` in the PKGBUILD is the declaration of that,
and `.SRCINFO` carries both entries.

Nothing here publishes: each leg uploads its package as a workflow artifact and
nothing else. The release job in `.github/workflows/ci.yml` is the single
publisher. On a `v*` tag it waits for this workflow's run for the same commit,
downloads the six package artifacts into its own `dist/` and only then signs
`SHA256SUMS`, so the signed manifest covers the `.deb`, the Kali `.deb` and the
`.pkg.tar.zst` next to the source tarball, the binaries and the signed update
bundle; one `action-gh-release` step then publishes `dist/` in full, and a leg
that failed to build fails the release instead of shipping a package no digest
authenticates. The checkout is full-depth, so `git describe` stamps the tag
version into a package instead of a commit sha.

`scripts/package-smoke.sh` is distro-agnostic and asserts the behaviour a user
buys the package for:

- the malicious smoke sample is caught **with zero flags** (exit 1), the benign
  one stays clean (exit 0), and the JSON verdict names itself malicious;
- the man pages, both shell completions, the license, the YARA rules, the
  signature database and the scheduled-scan unit are installed;
- the version stamped into the binary is the release version, not `dev`;
- `cau selftest` still fails closed (exit 3) rather than trusting unrecorded
  content;
- SARIF output is SARIF 2.1.0, so a CI consumer can parse it.

## Debian and Kali Linux

The package is in `debian/` and is deliberately simple: it is not built with
`dh-golang`, because the cgo dependency on libyara and the Go modules that are
not packaged in Debian (`go-yara`, `ssdeep`, `tlsh`) make a vendored,
Makefile-driven build the path with the fewest moving parts.

**The vendored Go module tree is committed.** That is what makes an offline build
possible on buildds and in a container, and `debian/rules` sets
`GOFLAGS=-mod=vendor` and `GOPROXY=off` so a missing `vendor/` fails loudly
instead of silently trying to fetch. Refresh it with `go mod vendor` and commit
the result.

```sh
# from a clean checkout
sudo apt install build-essential debhelper golang-go libyara-dev pkg-config
dpkg-buildpackage -us -uc        # source + binary, unsigned
sudo apt install ../cau_*_amd64.deb
```

| Path | Content |
|---|---|
| `/usr/bin/cau`, `/usr/bin/cau-mcp` | the scanner and the MCP server |
| `/usr/share/cau/rules/*.yar`, `/usr/share/cau/signatures/*.txt` | bundled detection content |
| `/usr/share/man/man1/cau.1`, `cau-mcp.1` | man pages |
| `/usr/share/{bash,zsh,fish}/completions/...` | completions, all three shells |
| `/usr/lib/systemd/system/cau-{daemon,scan}.service`, `cau-scan.timer` | optional scheduled-scan units |
| `/usr/share/doc/cau/`, `/usr/share/licenses/cau/LICENSE` | docs and license |

Runtime behaviour worth knowing before you ship an update:

- `debian/cau.postinst` creates the unprivileged system user `cau` that the
  units run as. On `remove`, the user stays (a reinstall must keep the uid the
  quarantine vault was written with); `purge` removes it.
- The units are installed but never enabled or started: a security scanner that
  starts walking the filesystem at install time is a surprise, not a feature.
  `systemctl enable --now cau-scan.timer` is the operator's decision.
- `debian/watch` resolves the upstream tarball from `v*` tags on GitHub, so
  `uscan` and `git-import-orig` find new versions with no manual edit.
- Signature database updates are separate from the package: `cau update` pulls
  a signed bundle (or the operator replaces
  `/usr/share/cau/signatures/hashes.txt` by hand), so detection content can move
  faster than a distro package.

Kali Linux is Debian-derived, so the same `.deb` installs there; the CI job runs
the build and the smoke test on `kalilinux/kali-rolling` to prove it rather than
assume it.

## Arch Linux

`packaging/arch/PKGBUILD` and `packaging/arch/.SRCINFO` build the same install
from the same Makefile targets:

```sh
cd packaging/arch
makepkg -s --noconfirm       # build and install missing deps
sudo pacman -U ./cau-*.pkg.tar.zst
```

Notes:

- The build uses the committed `vendor/` tree with `GOFLAGS=-mod=vendor` and
  `GOPROXY=off` in both build and install phases, so an AUR build never reaches
  the module proxy. `GOTOOLCHAIN=local` requires a sufficiently new installed Go
  compiler rather than allowing an automatic toolchain download.
- Both binaries use the Makefile's `-trimpath -buildmode=pie` flags, matching
  the Debian build's reproducibility and executable hardening settings.
- `VERSION=${pkgver}` is passed to `make install` because a release tarball has
  no `.git` directory: without it the binary is re-stamped `dev`.
- `packaging/cau.sysusers` must be tracked in git: the `package()` step installs
  it from the extracted source tree (the tarball excludes `packaging/arch` but
  keeps the rest of `packaging/`), and an untracked copy is a package with no
  `sysusers.d` snippet, so `systemctl enable cau-scan.timer` fails until the
  operator creates the `cau` account by hand.
- `cau` and `cau-edr` are both free in the AUR, Arch official has no `cau`
  package, and Debian has no source package by that name, so there is nothing to
  conflict with.

### Submitting to the AUR

```sh
git clone ssh://aur@aur.archlinux.org/cau.git cau-aur
cp packaging/arch/PKGBUILD packaging/arch/.SRCINFO cau-aur/
cd cau-aur
updpkgsums                 # fill in the tarball checksums
makepkg --printsrcinfo > .SRCINFO
git add PKGBUILD .SRCINFO
git commit -m "cau 0.1.0-1: initial release"
git push
```

The `.SRCINFO` must stay in sync with the `PKGBUILD`; CI compares it with
`makepkg --printsrcinfo` before building, so regenerate it before every push.
CI uses a staged copy of the recipe with a locally generated, checksummed
archive of the current checkout. The committed release source URL and checksum
remain the ones used by AUR users.

## The signed apt repository

A `.deb` that users fetch one at a time from a releases page is a fallback, not
a distribution channel. `scripts/apt-repo.sh` turns the CI `.deb` artifacts into
a signed repository that can be hosted statically:

```sh
# on a workstation with the CAU release GPG key
gpg --armor --export <key-id> > pubkey.asc
scripts/apt-repo.sh --suite stable --signing-key <key-id> --out /srv/repo dist/
rsync -av /srv/repo/ <static-host>:/repo/
```

It is built on the tools every Debian system already has (`dpkg-scanpackages`,
`gzip`, `gpg`) so it runs without aptly or reprepro, signs `Release` into both
`InRelease` and a detached `Release.gpg`, and prints the `sources.list` stanza
clients need. Publish next to it as `pubkey.asc` so clients can be pinned on it:

```
curl -fsSL https://<host>/pubkey.asc | sudo tee /usr/share/keyrings/cau.asc
echo 'deb [signed-by=/usr/share/keyrings/cau.asc] https://<host> stable main' \
    | sudo tee /etc/apt/sources.list.d/cau.list
sudo apt update && sudo apt install cau
```

Pinning the key with `signed-by` matters more than honouring every repository
key globally, and it is what lets the repository also serve Kali users, which
are Debian-based, without a second one.

## Releases

1. Update `CHANGELOG.md` and move the entry out of `Unreleased`.
2. Bump `pkgver` in `packaging/arch/PKGBUILD`, then run `updpkgsums` and
   `makepkg --printsrcinfo` there.
3. Bump `debian/changelog` to the same upstream version with a `-1` Debian
   revision; `debian/rules` derives the binary's version from it.
4. Commit, then `git tag -a vX.Y.Z -m '...'` and `git push origin main --tags`.
   Cut the tag once, after the tree is final: the `PKGBUILD` checksum is a
   function of the tag's bytes, so moving a tag invalidates it (this cost a
   green Debian and Kali a red Arch).
5. The `release` job in `ci.yml` publishes the packages and the source tarball
   as one release: it stages this workflow's artifacts for the commit into
   `dist/` before it signs `SHA256SUMS`, then uploads `dist/` in full. Run
   `scripts/apt-repo.sh` over the downloaded artifacts and republish the
   repository.

### The source tarball is a release asset, on purpose

The release job builds it with `git archive` (pathspec-excluding the distro
packaging, a fixed mtime, sorted names, zeroed owner/group, `gzip -n`), and the
`PKGBUILD` source URL points at that asset. GitHub's `/archive/<ref>/...tar.gz`
URLs are regenerated per request and are **not** byte-stable: the checksum
recorded from one fetch is not the bytes the next fetcher downloads, which is
exactly how the Arch build broke while the tree was unchanged. A fixed asset
gives the `PKGBUILD`, the Debian `.orig` tarball and `uscan` something they can
pin.

The packaging is excluded from the archive so that the checksum is a function of
the tagged *source* alone: editing `packaging/arch/PKGBUILD` or `debian/`
neither changes the tarball nor invalidates the recorded hash. The exclusion is
done with a pathspec, never with `.gitattributes` `export-ignore`, because
GitHub's codeload archive respects that attribute and `actions/checkout`
downloads the archive rather than cloning — marking `debian/` export-ignore
removes `debian/` from every CI checkout.

## What is not automated yet

- **Kali Linux repository.** Kali packages are built from Kali's own
  repositories. The `.deb` installs on Kali unchanged; landing it in Kali's repos
  is a submission to Kali's packaging queue, not a change to this code.
- **RPM is a spec, not a pipeline.** `packaging/rpm/cau.spec` builds offline
  from the release tarball and `vendor/` with the same Makefile install targets
  as the Debian and Arch packages, and its `%check` runs the packaged binary.
  It has been built with `rpmbuild --nodeps` on a Debian-family host only: no
  CI job builds it and it has not been installed on Fedora, RHEL or openSUSE,
  where the build dependencies (`golang`, `yara-devel`) and the systemd
  scriptlet macros resolve for real. Build it with
  `rpmbuild -ba packaging/rpm/cau.spec --define "cau_version <version>" --define "_sourcedir <dir holding cau-<version>.tar.gz>"`.
- **No Homebrew core.** The macOS path stays build-from-source
  ([installation.md](installation.md)).
- **arm64 user-space libraries.** The arm64 package is built on an arm64 runner
  against that image's libyara, so it links only what the image provides. A
  distro that ships an older libyara than the base image would need a rebuild
  there; the same is true of every package here, and `dpkg` states the
  dependency.
