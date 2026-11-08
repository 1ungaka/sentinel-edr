#!/bin/sh
# Regression checks for source selection and release artifact preservation.
set -eu
scripts=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

mkdir -p "$work/repo/packaging/arch" "$work/repo/packaging/systemd" \
    "$work/repo/debian" "$work/repo/.github"
cd "$work/repo"
git init -q
git config user.name pipeline-test
git config user.email pipeline-test@example.invalid
printf 'current source\n' > Makefile
printf 'installed service\n' > packaging/systemd/cau.service
printf 'checksum recipe\n' > packaging/arch/PKGBUILD
printf 'debian metadata\n' > debian/control
printf 'workflow\n' > .github/test.yml
git add .
git commit -qm fixture
"$scripts/source-archive.sh" 1.2.3 "$work/a.tar.gz"
"$scripts/source-archive.sh" 1.2.3 "$work/b.tar.gz"
cmp "$work/a.tar.gz" "$work/b.tar.gz"
tar -tzf "$work/a.tar.gz" > "$work/members"
grep -qx 'cau-1.2.3/Makefile' "$work/members"
grep -qx 'cau-1.2.3/packaging/systemd/cau.service' "$work/members"
if grep -Eq '/(arch|debian|\.github)/' "$work/members"; then
    echo 'source archive includes excluded metadata' >&2; exit 1
fi
# A packaging-only commit must not change the archive bytes the AUR pins.
printf 'changed recipe\n' > packaging/arch/PKGBUILD
git add .
git commit -qm packaging-only
"$scripts/source-archive.sh" 1.2.3 "$work/c.tar.gz"
cmp "$work/a.tar.gz" "$work/c.tar.gz"
# The current checkout, rather than a previous release, supplies the source.
printf 'improved current source\n' > Makefile
git add .
git commit -qm source-change
"$scripts/source-archive.sh" 1.2.3 "$work/current.tar.gz"
if cmp -s "$work/a.tar.gz" "$work/current.tar.gz"; then
    echo 'source archive ignored the source change' >&2; exit 1
fi
if "$scripts/source-archive.sh" 1.2.3 "$work/bad.tar.gz" missing-ref 2>/dev/null; then
    echo 'source archive accepted a missing ref' >&2; exit 1
fi
[ ! -e "$work/bad.tar.gz" ]

artifacts="$work/artifacts"
for arch in amd64 arm64; do
    for distro in debian-trixie kali-rolling; do
        mkdir -p "$artifacts/cau-${distro}-${arch}"
        printf '%s/%s\n' "$distro" "$arch" > "$artifacts/cau-${distro}-${arch}/cau_1.2.3-1_${arch}.deb"
    done
done
for pair in amd64:x86_64 arm64:aarch64; do
    mkdir -p "$artifacts/cau-archlinux-${pair%:*}"
    printf 'Arch/%s\n' "${pair#*:}" > "$artifacts/cau-archlinux-${pair%:*}/cau-1.2.3-1-${pair#*:}.pkg.tar.zst"
    printf 'debug\n' > "$artifacts/cau-archlinux-${pair%:*}/cau-debug-1.2.3-1-${pair#*:}.pkg.tar.zst"
done
"$scripts/stage-release-packages.sh" "$artifacts" "$work/dist"
[ "$(find "$work/dist" -type f | wc -l)" -eq 8 ]
for arch in amd64 arm64; do
    cmp "$artifacts/cau-debian-trixie-${arch}/cau_1.2.3-1_${arch}.deb" "$work/dist/cau_1.2.3-1_${arch}.deb"
    cmp "$artifacts/cau-kali-rolling-${arch}/cau_1.2.3-1_${arch}.deb" "$work/dist/cau-kali_1.2.3-1_${arch}.deb"
done
# Neither a successful Debian leg nor a debug package can mask a missing leg.
mv "$artifacts/cau-kali-rolling-arm64" "$work/missing-kali"
if "$scripts/stage-release-packages.sh" "$artifacts" "$work/missing-kali-dist" 2>/dev/null; then
    echo 'release staging accepted a missing Kali package' >&2; exit 1
fi
mv "$work/missing-kali" "$artifacts/cau-kali-rolling-arm64"
mv "$artifacts/cau-archlinux-arm64/cau-1.2.3-1-aarch64.pkg.tar.zst" "$work/missing-arch"
if "$scripts/stage-release-packages.sh" "$artifacts" "$work/missing-arch-dist" 2>/dev/null; then
    echo 'release staging accepted a debug package in place of the main package' >&2; exit 1
fi
mv "$work/missing-arch" "$artifacts/cau-archlinux-arm64/cau-1.2.3-1-aarch64.pkg.tar.zst"
cp "$artifacts/cau-debian-trixie-amd64/cau_1.2.3-1_amd64.deb" "$artifacts/cau-debian-trixie-amd64/cau_1.2.4-1_amd64.deb"
if "$scripts/stage-release-packages.sh" "$artifacts" "$work/ambiguous-dist" 2>/dev/null; then
    echo 'release staging accepted ambiguous package versions' >&2; exit 1
fi
echo 'pipeline regressions: passed'
