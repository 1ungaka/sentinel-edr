#!/usr/bin/env bash
# Render the release notes for a version from the CHANGELOG.
#
# Usage: release-notes.sh VERSION OUTPUT
#
# The changelog is the release notes: it is the document the project already
# keeps, and a second copy of it in the release body would be a second thing to
# keep in step. GitHub's own generator cannot be used for it — it looks for
# headings of the form "## 1.2.3" and this changelog writes "## [0.3.0] -
# 2026-11-11", so every release published so far carried nothing but a link
# to the comparison.
#
# The notes carry what an operator needs and not only what changed:
#
#   * the version, the date and the comparison with the last release,
#   * the changelog section for this version, verbatim,
#   * how to check what was downloaded.
set -euo pipefail

[ "$#" -eq 2 ] || {
    echo "usage: $0 VERSION OUTPUT" >&2
    exit 2
}
version=$1
output=$2
changelog=${CHANGELOG:-CHANGELOG.md}

[ -f "$changelog" ] || {
    echo "release-notes: no changelog at $changelog" >&2
    exit 1
}

# The section for this version: from its heading to the next heading of the
# same level. Both spellings the changelog has used are accepted ("## [0.3.0] -
# 2026-11-11" and "## 0.1.0 - 2026-11-02").
section=$(awk -v want="$version" '
    BEGIN { in_section = 0 }
    /^## / {
        # The heading names the version, with or without brackets, and may
        # carry a date after it.
        line = $0
        gsub(/^## +/, "", line)
        gsub(/\[/, "", line); gsub(/\]/, "", line)
        split(line, parts, /[ \t-]+/)
        name = parts[1]
        if (in_section) { exit }
        if (name == want) { in_section = 1; next }
        next
    }
    in_section { print }
' "$changelog" | sed '/./,$!d')

# A beta has no section of its own: it is the work that has not been released
# yet, which is what the changelog still calls Unreleased. Its notes are that
# section, and saying so is better than an empty release.
unreleased=false
if [ -z "$(printf '%s' "$section" | tr -d '[:space:]')" ]; then
    section=$(awk '
        BEGIN { in_section = 0 }
        /^## / {
            if (in_section) { exit }
            line = $0
            gsub(/^## +/, "", line)
            gsub(/\[/, "", line); gsub(/\]/, "", line)
            if (line ~ /^[Uu]nreleased/) { in_section = 1 }
            next
        }
        in_section { print }
    ' "$changelog" | sed '/./,$!d')
    unreleased=true
fi

if [ -z "$(printf '%s' "$section" | tr -d '[:space:]')" ]; then
    case "$version" in
        *-*)
            echo "release-notes: the changelog's Unreleased section is empty, so there is nothing to say about $version; write the notes before cutting a pre-release" >&2
            ;;
        *)
            echo "release-notes: $changelog has no section for $version" >&2
            ;;
    esac
    exit 1
fi

# The date the section carries, if it has one.
date=$(awk -v want="$version" '
    /^## / {
        line = $0
        gsub(/^## +/, "", line)
        gsub(/\[/, "", line); gsub(/\]/, "", line)
        split(line, parts, /[ \t-]+/)
        if (parts[1] == want) {
            # The date is whatever follows the version.
            rest = line
            sub(/^[^ \t-]+[ \t-]*/, "", rest)
            gsub(/^[ \t-]+|[ \t-]+$/, "", rest)
            print rest
            exit
        }
    }
' "$changelog")

{
    echo "# CAU EDR ${version}"
    echo
    if [ -n "$date" ]; then
        echo "Released ${date}."
    elif [ "$unreleased" = true ]; then
        echo "A pre-release: this is the work that has not been released yet."
    fi
    echo
    echo "The engine is one binary; the kernel sensor that guards the host from"
    echo "the inside is a separate project ([cau-kernel](https://github.com/s-b-repo/cau-kernel))."
    echo
    printf '%s\n' "$section"
    echo
    echo "## Checking what you downloaded"
    echo
    if [ "${RELEASE_SIGNED:-0}" = "1" ]; then
        echo "Every asset in this release is listed in \`SHA256SUMS\`, which is"
        echo "signed with the release key: the signature is checked before the"
        echo "digests are."
    else
        echo "Every asset in this release is listed in \`SHA256SUMS\`. **This"
        echo "release was published without the release key**, so the manifest is"
        echo "a plain list of digests: it says what the assets are, and it does"
        echo "not say who vouched for them. Check the digests against the"
        echo "release page, and treat a release published without the key as"
        echo "one without a signature."
    fi
    echo
    echo '```'
    echo "sha256sum --ignore-missing -c SHA256SUMS"
    echo '```'
    echo
    echo "The engine checks itself against that manifest: \`cau verify-self --from .\`"
    echo "recomputes the running binary's digest and compares it with the signed"
    echo "one, so a tampered download is refused rather than run."
    echo
    echo "Full changelog: [CHANGELOG.md](https://github.com/1ungaka/sentinel-edr/blob/main/CHANGELOG.md)."
    echo "Comparison with the previous release: <https://github.com/1ungaka/sentinel-edr/compare/v${version}%5E...v${version}>."
} > "$output"

echo "release-notes: wrote $output ($(wc -l < "$output") lines)"
