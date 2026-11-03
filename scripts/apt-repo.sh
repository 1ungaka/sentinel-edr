#!/bin/sh
# apt-repo.sh — build a signed APT repository from the .deb artifacts CI
# produced, ready to be hosted statically (GitHub Pages, S3, a web server).
#
# The repository is deliberately dependency-free: it uses the tools that ship
# with every Debian and Kali installation (dpkg-scanpackages, gzip, gpg), so it
# runs on a maintainer workstation or in a small container without aptly or
# reprepro. See docs/packaging.md for hosting and pinning instructions.
#
# Usage:
#   scripts/apt-repo.sh [options] <directory-of-.deb-files>
#
# Options:
#   --suite NAME          repository suite, also the codename (default: stable)
#   --component NAME       pool component (default: main)
#   --architectures LIST   architecture list (default: detected from the .debs)
#   --signing-key KEYID    GPG key id used to sign Release (optional; without
#                          it the repository is built unsigned and warned about,
#                          which apt will refuse to use until you sign it)
#   --out PATH             repository root (default: ./aptrepo)
#   --help                 print this help and exit
set -eu

suite=stable
component=main
architectures=
signkey=
out=aptrepo

usage() {
    sed -n '3,25p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --suite)          suite=${2:?--suite needs a value}; shift 2 ;;
        --component)      component=${2:?--component needs a value}; shift 2 ;;
        --architectures)  architectures=${2:?--architectures needs a value}; shift 2 ;;
        --signing-key)    signkey=${2:?--signing-key needs a key id}; shift 2 ;;
        --out)            out=${2:?--out needs a path}; shift 2 ;;
        --help|-h)        usage; exit 0 ;;
        -*)               echo "unknown option: $1" >&2; usage; exit 2 ;;
        *)                break ;;
    esac
done

if [ $# -ne 1 ]; then
    usage >&2
    exit 2
fi
indir=$(CDPATH= cd -- "$1" && pwd)

for tool in dpkg-scanpackages gzip; do
    command -v "$tool" >/dev/null 2>&1 || { echo "required tool missing: $tool" >&2; exit 1; }
done
if [ -n "$signkey" ]; then
    command -v gpg >/dev/null 2>&1 || { echo "--signing-key needs gpg" >&2; exit 1; }
    gpg --list-secret-keys "$signkey" >/dev/null 2>&1 || {
        echo "the signing key $signkey is not in the secret keyring of this user" >&2
        exit 1
    }
fi

[ -d "$indir" ] || { echo "not a directory: $indir" >&2; exit 1; }
debs=$(find "$indir" -maxdepth 1 -name '*.deb' | sort)
[ -n "$debs" ] || { echo "no .deb files in $indir" >&2; exit 1; }

# Architecture list is taken from the artifacts when not given, so an arm64
# build drop needs no extra arguments.
if [ -z "$architectures" ]; then
    architectures=$(
        for d in $debs; do dpkg-deb --field "$d" Architecture; done | sort -u | tr '\n' ' '
    )
fi

pool="$out/pool/$suite/$component"
dist="$out/dists/$suite"

echo "== staging $(find "$indir" -maxdepth 1 -name '*.deb' | wc -l) package(s) into $pool"
rm -rf "$out"
mkdir -p "$pool"
# shellcheck disable=SC2086
for d in $debs; do cp -p "$d" "$pool/"; done

for arch in $architectures; do
    binary="$dist/$component/binary-$arch"
    mkdir -p "$binary"
    # -m (multiversion) keeps older cau versions in the index during an upgrade
    # window, which is what a user with a pinned version needs.
    (cd "$out" && dpkg-scanpackages --multiversion "pool/$suite/$component") > "$binary/Packages"
    gzip -9n -c "$binary/Packages" > "$binary/Packages.gz"
    echo "   $arch: $(grep -c '^Package:' "$binary/Packages") package(s)"
done

echo "== writing Release"
release="$dist/Release"
{
    printf 'Origin: CAU\n'
    printf 'Label: cau\n'
    printf 'Suite: %s\n' "$suite"
    printf 'Codename: %s\n' "$suite"
    printf 'Architectures: %s\n' "$architectures"
    printf 'Components: %s\n' "$component"
    printf 'Description: CAU EDR packages (%s)\n' "$suite"
    printf 'Date: %s\n' "$(date -Ru)"
    # The index checksums apt verifies before it trusts anything in this
    # repository; every listed file gets its MD5Sum, SHA1 and SHA256.
    for sum in MD5Sum SHA1 SHA256; do
        case "$sum" in
            MD5Sum)  cmd="md5sum" ;;
            SHA1)    cmd="sha1sum" ;;
            SHA256)  cmd="sha256sum" ;;
        esac
        printf '%s:\n' "$sum"
        for arch in $architectures; do
            for f in Packages Packages.gz; do
                file="$component/binary-$arch/$f"
                [ -f "$dist/$file" ] || continue
                hash=$($cmd "$dist/$file" | cut -d' ' -f1)
                size=$(wc -c < "$dist/$file")
                printf ' %s %8d %s\n' "$hash" "$size" "$file"
            done
        done
    done
} > "$release"

if [ -n "$signkey" ]; then
    echo "== signing with GPG key $signkey"
    # InRelease is the signed index modern apt looks for; Release.gpg is the
    # detached signature older clients still use.
    rm -f "$dist/InRelease" "$dist/Release.gpg"
    gpg --batch --yes --default-key "$signkey" --clearsign -o "$dist/InRelease" "$release"
    gpg --batch --yes --default-key "$signkey" --detach-sign --armor \
        -o "$dist/Release.gpg" "$release"
else
    echo "WARNING: not signed. Clients must then trust the repository with"
    echo "         'trusted=yes', or you sign it later with --signing-key."
fi

cat <<EOF

Repository written to $out

Host it on any static origin, e.g. GitHub Pages (see docs/packaging.md):

  suite $suite, components $component, architectures $architectures

Install from it:

  curl -fsSL <host>/pubkey.asc | sudo tee /usr/share/keyrings/cau.asc
  echo 'deb [signed-by=/usr/share/keyrings/cau.asc] <host> $suite $component' \\
    | sudo tee /etc/apt/sources.list.d/cau.list
  sudo apt update && sudo apt install cau

EOF
