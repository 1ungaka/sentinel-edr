#!/usr/bin/env bash
# Build the current checkout with makepkg, without changing the release recipe.
# Usage from anywhere in the checkout: scripts/build-arch-package.sh [-si ...]
set -euo pipefail

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$here/.." && pwd)
command -v makepkg >/dev/null || {
    echo 'makepkg is required; run this helper on Arch Linux with base-devel installed' >&2
    exit 1
}
if [ "$(id -u)" -eq 0 ]; then
    echo 'makepkg must run as an ordinary user; use -s/-i for dependency installation' >&2
    exit 1
fi

# Packages survive removal of the temporary build tree and appear in the
# caller's directory (or the PKGDEST the caller explicitly selected).
export PKGDEST=${PKGDEST:-$PWD}
mkdir -p "$PKGDEST"
PKGDEST=$(CDPATH= cd -- "$PKGDEST" && pwd)
export PKGDEST
stage=$(mktemp -d "${TMPDIR:-/tmp}/cau-arch.XXXXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM

pkgver=$(bash -c 'source "$1"; printf "%s" "$pkgver"' _ "$repo/packaging/arch/PKGBUILD")
archive="cau-${pkgver}.tar.gz"
cd "$repo"
"$here/source-archive.sh" "$pkgver" "$stage/$archive" --worktree
cp packaging/arch/PKGBUILD "$stage/PKGBUILD"
checksum=$(sha256sum "$stage/$archive")
checksum=${checksum%% *}
printf '\nsource=("%s")\nsha256sums=("%s")\n' "$archive" "$checksum" >> "$stage/PKGBUILD"

cd "$stage"
export SRCDEST=$stage
makepkg "$@"
