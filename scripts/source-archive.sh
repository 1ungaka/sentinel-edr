#!/usr/bin/env bash
# Build the same fixed-byte source archive for releases and the packaging gate.
# Usage: source-archive.sh VERSION OUTPUT [GIT_REF|--worktree]
set -euo pipefail

[ "$#" -ge 2 ] && [ "$#" -le 3 ] || {
    echo "usage: $0 VERSION OUTPUT [GIT_REF|--worktree]" >&2
    exit 2
}
version=$1
output=$2
ref=${3:-HEAD}
case "$version" in
    ''|*[!0-9A-Za-z._+-]*) echo "invalid source version: $version" >&2; exit 2 ;;
esac

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
# Keep packaging/systemd and the shared configuration: make install needs them.
# The Arch recipe hashes this archive, so exclude it to avoid a checksum cycle.
if [ "$ref" = --worktree ]; then
    # A local build must include edits and new source files, while leaving
    # ignored build products and nested working copies out of its archive.
    # A NUL-delimited manifest handles spaces and newlines in source paths.
    git ls-files -z --cached --others --exclude-standard --deduplicate -- . \
        ':(exclude)packaging/arch' ':(exclude)debian' ':(exclude).github' |
        while IFS= read -r -d '' source_file; do
            if [ -f "$source_file" ] || [ -L "$source_file" ]; then
                printf '%s\0' "$source_file"
            fi
        done > "$stage/paths"
    mkdir "$stage/cau-${version}"
    tar --null --verbatim-files-from --no-recursion -T "$stage/paths" \
        -cf "$stage/source.tar"
    tar -xf "$stage/source.tar" -C "$stage/cau-${version}"
else
    git archive --format=tar --prefix="cau-${version}/" "$ref" -- . \
        ':(exclude)packaging/arch' ':(exclude)debian' ':(exclude).github' > "$stage/source.tar"
    tar -xf "$stage/source.tar" -C "$stage"
fi
tar --sort=name --mtime='@1735689600' --owner=0 --group=0 \
    --numeric-owner --format=gnu -C "$stage" -cf "$stage/normalized.tar" "cau-${version}"
gzip -9n < "$stage/normalized.tar" > "$output"
