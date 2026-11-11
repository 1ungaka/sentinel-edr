# Installation

## From source

Requires Go (see `go.mod`) and libyara with its development headers.

```sh
sudo apt-get install -y libyara-dev yara pkg-config   # Debian/Kali/Ubuntu
git clone https://github.com/1ungaka/sentinel-edr.git
cd cau
make build            # produces ./cau
./cau version
```

The signature database, YARA rules and fuzzy database are discovered next to the
binary, under `<prefix>/share/cau`, `/usr/share/cau`, or the working directory;
override with `--db` / `--rules` / `--fuzzy-db` or `CAU_SIGNATURES` / `CAU_RULES`
/ `CAU_FUZZY`.

## From a signed release

Releases are signed. **Verify before you run** — see
[Updates and Self-Verification](Updates-and-Self-Verification):

```sh
# download the release assets, including SHA256SUMS and SHA256SUMS.sig, then:
cau verify-self --from . --pubkey release-pubkey.hex --name cau-vX.Y.Z-linux-amd64
```

A release that cannot verify itself against the signed `SHA256SUMS` should not be
trusted. The CI release job itself self-verifies before publishing, so a broken
or unsigned build never ships.
