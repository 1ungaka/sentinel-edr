#!/bin/sh
# Stage every native package without letting equal Debian/Kali names overwrite.
# Usage: stage-release-packages.sh ARTIFACT_ROOT DIST
set -eu
[ "$#" -eq 2 ] || { echo "usage: $0 ARTIFACT_ROOT DIST" >&2; exit 2; }
artifacts=$1
dist=$2
mkdir -p "$dist"

for arch in amd64 arm64; do
    for distro in debian-trixie kali-rolling; do
        set -- "$artifacts/cau-${distro}-${arch}"/cau_*_"${arch}".deb
        [ "$#" -eq 1 ] && [ -f "$1" ] || {
            echo "expected exactly one ${distro}/${arch} package" >&2; exit 1;
        }
        name=$(basename "$1")
        if [ "$distro" = kali-rolling ]; then name="cau-kali_${name#cau_}"; fi
        [ ! -e "$dist/$name" ] || { echo "duplicate release asset: $name" >&2; exit 1; }
        cp "$1" "$dist/$name"
    done
done
for pair in amd64:x86_64 arm64:aarch64; do
    runner_arch=${pair%:*}
    package_arch=${pair#*:}
    # Debug packages are useful CI artifacts, but the release requires the main
    # package. Reject a missing or ambiguous main package rather than signing it.
    # The compression is the recipe's choice (PKGEXT), but a builder whose
    # configuration says otherwise still produces a package, so both are taken.
    set -- "$artifacts/cau-archlinux-${runner_arch}"/cau-[0-9]*-"${package_arch}".pkg.tar.zst
    if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
        set -- "$artifacts/cau-archlinux-${runner_arch}"/cau-[0-9]*-"${package_arch}".pkg.tar.xz
    fi
    [ "$#" -eq 1 ] && [ -f "$1" ] || {
        echo "expected exactly one Arch/${package_arch} package" >&2; exit 1;
    }
    name=$(basename "$1")
    [ ! -e "$dist/$name" ] || { echo "duplicate release asset: $name" >&2; exit 1; }
    cp "$1" "$dist/$name"
    # Keep optional debug packages as release assets too, when makepkg emits
    # them. Their absence does not excuse a missing main package above.
    for debug in "$artifacts/cau-archlinux-${runner_arch}"/cau-debug-*-"${package_arch}".pkg.tar.zst \
                  "$artifacts/cau-archlinux-${runner_arch}"/cau-debug-*-"${package_arch}".pkg.tar.xz; do
        [ -f "$debug" ] || continue
        name=$(basename "$debug")
        [ ! -e "$dist/$name" ] || { echo "duplicate release asset: $name" >&2; exit 1; }
        cp "$debug" "$dist/$name"
    done
done
