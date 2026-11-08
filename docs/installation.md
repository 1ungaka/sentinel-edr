# Installation

## Requirements

| Dependency | Version | Why |
|---|---|---|
| Go | 1.24 or newer | the engine is a single Go module |
| libyara with headers | 4.3 or newer | YARA runs in-process through [go-yara](https://github.com/hillu/go-yara); the `yara` binary is not needed |
| pkg-config | any | go-yara locates libyara through it |
| a C compiler | any | cgo, for the libyara binding |

Supported targets are Linux and macOS. Windows builds work with a libyara
installation that pkg-config can find, but are not exercised by CI.

```sh
# Debian / Ubuntu / Kali
sudo apt install golang-go libyara-dev pkg-config build-essential
# Fedora
sudo dnf install golang yara-devel pkgconf-pkg-config gcc
# Arch Linux
sudo pacman -S --needed base-devel go yara pkgconf
# macOS
brew install go yara pkg-config
```

## Build from source

```sh
git clone https://github.com/s-b-repo/cau.git cau
cd cau
make build          # -> ./cau
./cau version
```

`make build` stamps the version from `git describe`. The plain `go build .`
also works and produces a binary that reports `0.1.0-dev`.

### User-local toolchain

If Go or libyara are installed under your home directory rather than
system-wide, `scripts/dev-env.sh` exports `PATH`, `PKG_CONFIG_PATH`,
`LD_LIBRARY_PATH` and `CGO_ENABLED=1` for a layout of `~/.local/go` and
`~/.local/yara`:

```sh
source scripts/dev-env.sh
make build
```

The build fails with `package yara was not found in the pkg-config search
path` when pkg-config cannot see libyara; the script, or an exported
`PKG_CONFIG_PATH`, is the fix.

## Install

```sh
sudo make install                      # PREFIX=/usr/local by default
make install PREFIX=$HOME/.local       # no root
```

This installs:

| Path | Content |
|---|---|
| `$PREFIX/bin/cau` | the binary |
| `$PREFIX/bin/cau-mcp` | the MCP server |
| `$PREFIX/share/cau/rules/*.yar` | the bundled YARA rules |
| `$PREFIX/share/cau/signatures/hashes.txt` | the hash signature database |
| `$PREFIX/share/cau/signatures/fuzzy.txt` | the fuzzy-hash database (empty on purpose, see [Detection content](detection-content.md)) |
| `$PREFIX/share/man/man1/cau*.1` | the man pages |
| `$PREFIX/share/licenses/cau/LICENSE` | the license |
| `$PREFIX/share/doc/cau/` | this documentation, the README and the changelog |
| `$PREFIX/share/bash-completion/completions/cau` | bash completion |
| `$PREFIX/share/zsh/site-functions/_cau` | zsh completion |
| `$PREFIX/share/fish/vendor_completions.d/cau.fish` | fish completion |

Print a completion script instead of installing it:

```sh
cau completion bash   > /etc/bash_completion.d/cau
cau completion zsh    > /usr/share/zsh/site-functions/_cau
cau completion fish   > /usr/share/fish/vendor_completions.d/cau.fish
```

The optional scheduled-scan units are not installed by default:

```sh
sudo make install-systemd PREFIX=/usr
sudo systemd-sysusers /usr/lib/sysusers.d/cau.conf  # create the service account
sudo make install-config                # /etc/cau/cau.conf, the agent's configuration
sudo make install-logrotate             # /etc/logrotate.d/cau, for cau-defend's log
```

`cau defend` runs as `cau-defend.service`. It reads `/etc/cau/cau.conf`, and a flag
on the command line wins over the file. It defends by default, so set
`report-only = true` to watch a host first. That setting is only as safe as the file
it sits in: a cau.conf the agent refuses or cannot parse leaves it on its built-in
defaults, and those act rather than failing closed into report-only. A host that must
never act should put `--report-only` on the unit's ExecStart line instead, because
the command line wins over the file. Both packages install the configuration
and the rotation policy as conffiles, so local edits survive an upgrade.

## Packages

The fastest supported install path. Every package is built, installed and
smoke-tested by CI on Debian, Kali Linux and Arch Linux — the CI job scans a
known-malicious sample with the installed binary before it publishes anything
(see [packaging.md](packaging.md) for the maintainer detail).

### Debian and Kali Linux

```sh
# GitHub release assets: cau_<version>-1_amd64.deb
sudo apt install ./cau_<version>-1_amd64.deb
```

Or add the signed repository once, and take updates through apt:

```sh
curl -fsSL https://<host>/pubkey.asc | sudo tee /usr/share/keyrings/cau.asc
echo 'deb [signed-by=/usr/share/keyrings/cau.asc] https://<host> stable main' \
    | sudo tee /etc/apt/sources.list.d/cau.list
sudo apt update && sudo apt install cau
```

The package installs `cau` and `cau-mcp` into `/usr/bin`, the YARA rules and
signature databases into `/usr/share/cau`, man pages, and shell completions for
bash, zsh and fish. A systemd timer (`cau-scan.timer`) ships with it but is not
enabled: `sudo systemctl enable --now cau-scan.timer` starts scheduled scanning.
Detections are content, not just the binary — update them with `cau update`.

Build the package from source yourself:

```sh
sudo apt install build-essential debhelper golang-go libyara-dev pkg-config
dpkg-buildpackage -us -uc          # needs a checkout with vendor/ committed
sudo apt install ../cau_*_amd64.deb
```

### Arch Linux

```sh
# from a checkout of this repository
cd packaging/arch && makepkg -si
# or, once published, from the AUR
yay -S cau
```

The `PKGBUILD` downloads the checksummed source asset for its `pkgver`; running
it from a checkout still builds that release. It builds from the vendored module
tree without contacting the Go module proxy or downloading a toolchain, and
stamps `pkgver` into both binaries. CI separately stages the current checkout
as a source archive so every change is packaged and tested before release. The packaged
systemd units run as the unprivileged `cau` user, so the package ships a
`sysusers.d` snippet that creates that system account (no home, no login shell)
at install time; on a host without systemd-sysusers, create it yourself with
`useradd --system --no-create-home --shell /usr/sbin/nologin cau` before
enabling any unit.

### What the package does not do for you

`cau selftest` refuses to trust content it cannot verify and exits 3 until an
integrity manifest has been recorded with `cau selftest --record`. That is the
documented behaviour, not a broken install: the manifest that ships in a
release is the one `cau selftest` verifies against.

## Release tarballs

The first tag, `v0.1.0`, was cut on 2026-11-02. Every `v*` tag triggers the CI
release job, which builds `cau-<tag>-linux-amd64.tar.gz` with the rules and
signatures and attaches it to the GitHub release together with `SHA256SUMS`,
the `cau_<version>-1_amd64.deb`, the `cau-kali_<version>-1_amd64.deb` and the
`cau-<version>-1-x86_64.pkg.tar.zst` — the packaging workflow builds those
packages, the release job downloads their artifacts and publishes them itself,
so a release carries them next to the source tarball and the signed update
bundle (the maintainer checklist is in [packaging.md](packaging.md)). Download
them from [the v0.1.0 release](https://github.com/s-b-repo/cau/releases/tag/v0.1.0),
or build from source.

### Which release assets are authenticated

`SHA256SUMS` is signed with the release key, and `cau verify-self` checks a
binary against it, but it only covers what the release job staged into its own
`dist/` before signing: the source tarball `cau-<tag>-linux-amd64.tar.gz`, the
binaries `cau-<tag>-linux-amd64` and `cau-<tag>-linux-arm64`, the update bundle
(`hashes.txt`, `manifest.json`, `manifest.json.sig`), the integrity baseline
`integrity.json`, the pinned public key `release-pubkey.hex` and the distro
packages built for the tag. Those are the assets a signed digest exists for, so
they are the ones that can be verified offline:

```sh
cau verify-self --from dist --pubkey release-pubkey.hex --name cau-v0.1.0-linux-amd64
```

The `.deb` and `.pkg.tar.zst` packages reach that `dist/` before the manifest is
signed: the release job waits for the packaging workflow's run, downloads its
artifacts and publishes them itself. Their digests are therefore in the signed
`SHA256SUMS` too, and a package can be checked the way any other asset is —
against the signed manifest, not against the page it was downloaded from:

```sh
# in a directory holding SHA256SUMS, SHA256SUMS.sig and the downloaded package
sha256sum --check --ignore-missing SHA256SUMS
```

Building the package from the signed source tarball yourself
(`dpkg-buildpackage -us -uc`, `makepkg -si`) remains an equally verifiable
alternative.

## Resource discovery

The binary looks for its signature database, rules directory and fuzzy
database in this order and uses the first that exists:

1. the flag (`--db`, `--rules`, `--fuzzy-db`)
2. the environment (`CAU_SIGNATURES`, `CAU_RULES`, `CAU_FUZZY`)
3. next to the binary (`<dir of cau>/signatures/hashes.txt`, `<dir of cau>/rules`)
4. the share directory relative to the binary (`<dir of cau>/../share/cau/...`)
5. `/usr/local/share/cau` and `/usr/share/cau`
6. the current working directory

When nothing is found, the error lists every path that was tried. A missing
signature database is fatal; missing rules or a missing fuzzy database turn
that detector off with a message on stderr, because the README advertising a
feature that silently did not run was one of the bugs this fork fixed.

## Verify the installation

```sh
cau scan --file corpus/smoke/malicious/mimikatz_strings.bin --db corpus/smoke/hashes.txt
echo "exit $?"          # 1: a YARA rule matched
make eval               # validate the smoke corpus, run it, gate against the baseline
```
