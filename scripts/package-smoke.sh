#!/bin/sh
# package-smoke.sh — prove that the package this container just built actually
# detects malware once installed.
#
# A package that builds is not the same as a package that works. This asserts
# the verdicts (malicious sample caught with zero flags, benign sample clean),
# the packaged content, the man pages, the completions and the fail-closed
# selftest, on whichever distribution installed it.
#
# Usage: run from the repository checkout of the workflow, e.g.
#   scripts/package-smoke.sh          # inside the container job
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$here/.." && pwd)

# root is where the package claims to be installed: "/" in a container, or a
# DESTDIR-style staging directory when the packaging is checked by hand.
root=${INSTALL_ROOT:-/}
bin="$root/usr/bin"
share="$root/usr/share"

malicious="$repo/corpus/smoke/malicious/mimikatz_strings.bin"
benign="$repo/corpus/smoke/benign/hello_elf.bin"
[ -f "$malicious" ] || { echo "corpus missing: $malicious" >&2; exit 1; }
[ -f "$benign" ] || { echo "corpus missing: $benign" >&2; exit 1; }

fail() { echo "FAIL: $*" >&2; exit 1; }

# Run everything from a neutral directory: the packaged binary must find its
# signature database and rules through its own install prefix, not through the
# working directory this script was invoked from.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

echo "== package contents =="
# What a distribution extracts is not what the package contains: Arch container
# images ship /etc/pacman.conf with NoExtract for usr/share/man and usr/share/doc,
# so the man pages exist in the package and never on the disk. The package's own
# file list is therefore the authority for those trees, and the filesystem for
# everything else.
list=$(
    if command -v dpkg-query >/dev/null 2>&1 &&
       dpkg-query -W -f='${Status}' cau 2>/dev/null | grep -q '^install ok installed'; then
        dpkg -L cau
    elif command -v pacman >/dev/null 2>&1 && pacman -Q cau >/dev/null 2>&1; then
        pacman -Ql cau | sed 's/^[^ ]* //'
    fi | sed 's|^/||'
)

# has <path under the filesystem root>: on disk, on disk compressed (Arch gzips
# man pages, Debian compresses some docs at postinst), or in the package's own
# file list.
has() {
    for cand in "$root/$1" "$root/$1.gz"; do
        [ -e "$cand" ] && return 0
    done
    if [ -n "$list" ]; then
        # The package list carries the form the packager built: uncompressed on
        # Debian, .gz on Arch (makepkg compresses man and info pages).
        printf '%s\n' "$list" | grep -qx -- "$1" && return 0
        printf '%s\n' "$list" | grep -qx -- "$1.gz" && return 0
    fi
    return 1
}

has "usr/bin/cau"                    || fail "missing $bin/cau"
has "usr/bin/cau-mcp"                || fail "missing $bin/cau-mcp"
ls "$share/cau/rules/"*.yar >/dev/null 2>&1 || fail "no YARA rules in $share/cau/rules"
[ -s "$share/cau/signatures/hashes.txt" ] || fail "missing or empty hash database"
has "usr/share/licenses/cau/LICENSE"     || fail "missing license"
for m in cau.1 cau-mcp.1; do
    has "usr/share/man/man1/$m" || fail "missing man page $m"
done
has "usr/share/bash-completion/completions/cau" || fail "missing bash completion"
has "usr/share/zsh/site-functions/_cau"         || fail "missing zsh completion"
has "usr/share/fish/vendor_completions.d/cau.fish" || fail "missing fish completion"
has "usr/lib/systemd/system/cau-scan.timer"     || fail "missing the scheduled-scan unit"
echo "   ok"

echo "== version =="
ver=$("$bin/cau" version) || fail "cau version failed"
echo "   $ver"
case "$ver" in *dev*) fail "the package was built without its version stamped: $ver" ;; esac

echo "== command surface =="
"$bin/cau" --help >/dev/null 2>&1 || fail "cau --help failed"
"$bin/cau" completion bash | grep -q 'quarantine' \
    || fail "the embedded bash completion does not mention the commands"
"$bin/cau" completion zsh | grep -q '_cau' || fail "zsh completion is broken"
"$bin/cau" rules lint >/dev/null 2>&1 || fail "cau rules lint failed"
echo "   ok"

echo "== malicious sample, zero flags =="
out=$("$bin/cau" scan --file "$malicious" 2>&1) && code=0 || code=$?
[ "$code" -eq 1 ] || fail "expected exit 1 for a malicious sample, got $code"
printf '%s\n' "$out" | grep -q 'malicious' || fail "the text report does not say malicious"
json=$("$bin/cau" scan --file "$malicious" --format json 2>/dev/null) || true
printf '%s\n' "$json" | grep -q '"verdict":"malicious"' || fail "JSON verdict is not malicious"
printf '%s\n' "$json" | grep -q '"exit_code":1' || fail "JSON exit_code is not 1"
printf '%s\n' "$json" | grep -q 'explanation' || fail "the explained verdict is missing from JSON"
"$bin/cau" scan --file "$malicious" --format sarif 2>/dev/null |
    grep -q '"version":"2.1.0"' || fail "SARIF output is not SARIF 2.1.0"
echo "   detected, with the verdict explained"

echo "== benign sample =="
"$bin/cau" scan --file "$benign" >/dev/null 2>&1 || fail "benign sample did not scan clean"
json=$("$bin/cau" scan --file "$benign" --format json 2>/dev/null) || true
printf '%s\n' "$json" | grep -q '"verdict":"clean"' || fail "benign sample is not clean"
echo "   clean"

echo "== selftest fails closed =="
if "$bin/cau" selftest >/dev/null 2>&1; then
    fail "selftest passed: it must require a recorded manifest and fail closed"
else
    code=$?
    [ "$code" -eq 3 ] || fail "selftest exited $code, want 3 (fail closed)"
fi
echo "   exit 3, refuses to trust unrecorded content"

echo
echo "package smoke: all checks passed on $(uname -s)/$(uname -m)"
