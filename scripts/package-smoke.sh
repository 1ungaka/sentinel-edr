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
prefix=${PREFIX:-/usr}

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
[ -x "$prefix/bin/cau" ] || fail "missing $prefix/bin/cau"
[ -x "$prefix/bin/cau-mcp" ] || fail "missing $prefix/bin/cau-mcp"
ls "$prefix/share/cau/rules/"*.yar >/dev/null 2>&1 || fail "no YARA rules in $prefix/share/cau/rules"
[ -s "$prefix/share/cau/signatures/hashes.txt" ] || fail "missing or empty hash database"
[ -s "$prefix/share/licenses/cau/LICENSE" ] || fail "missing license"
for m in cau.1 cau-mcp.1; do
    # Arch compresses man pages; Debian does so in the postinst step. Accept both.
    ls "$prefix/share/man/man1/$m" >/dev/null 2>&1 ||
        ls "$prefix/share/man/man1/$m.gz" >/dev/null 2>&1 ||
        fail "missing man page $m"
done
ls "$prefix/share/bash-completion/completions/cau" >/dev/null 2>&1 || fail "missing bash completion"
ls "$prefix/share/zsh/site-functions/_cau" >/dev/null 2>&1 || fail "missing zsh completion"
ls "$prefix/share/fish/vendor_completions.d/cau.fish" >/dev/null 2>&1 || fail "missing fish completion"
[ -f "$prefix/lib/systemd/system/cau-scan.timer" ] || fail "missing the scheduled-scan unit"
echo "   ok"

echo "== version =="
ver=$("$prefix/bin/cau" version) || fail "cau version failed"
echo "   $ver"
case "$ver" in *dev*) fail "the package was built without its version stamped: $ver" ;; esac

echo "== command surface =="
"$prefix/bin/cau" --help >/dev/null 2>&1 || fail "cau --help failed"
"$prefix/bin/cau" completion bash | grep -q 'quarantine' \
    || fail "the embedded bash completion does not mention the commands"
"$prefix/bin/cau" completion zsh | grep -q '_cau' || fail "zsh completion is broken"
"$prefix/bin/cau" rules lint >/dev/null 2>&1 || fail "cau rules lint failed"
echo "   ok"

echo "== malicious sample, zero flags =="
out=$("$prefix/bin/cau" scan --file "$malicious" 2>&1) && code=0 || code=$?
[ "$code" -eq 1 ] || fail "expected exit 1 for a malicious sample, got $code"
printf '%s\n' "$out" | grep -q 'malicious' || fail "the text report does not say malicious"
json=$("$prefix/bin/cau" scan --file "$malicious" --format json 2>/dev/null) || true
printf '%s\n' "$json" | grep -q '"verdict":"malicious"' || fail "JSON verdict is not malicious"
printf '%s\n' "$json" | grep -q '"exit_code":1' || fail "JSON exit_code is not 1"
printf '%s\n' "$json" | grep -q 'explanation' || fail "the explained verdict is missing from JSON"
"$prefix/bin/cau" scan --file "$malicious" --format sarif 2>/dev/null |
    grep -q '"version":"2.1.0"' || fail "SARIF output is not SARIF 2.1.0"
echo "   detected, with the verdict explained"

echo "== benign sample =="
"$prefix/bin/cau" scan --file "$benign" >/dev/null 2>&1 || fail "benign sample did not scan clean"
json=$("$prefix/bin/cau" scan --file "$benign" --format json 2>/dev/null) || true
printf '%s\n' "$json" | grep -q '"verdict":"clean"' || fail "benign sample is not clean"
echo "   clean"

echo "== selftest fails closed =="
if "$prefix/bin/cau" selftest >/dev/null 2>&1; then
    fail "selftest passed: it must require a recorded manifest and fail closed"
else
    code=$?
    [ "$code" -eq 3 ] || fail "selftest exited $code, want 3 (fail closed)"
fi
echo "   exit 3, refuses to trust unrecorded content"

echo
echo "package smoke: all checks passed on $(uname -s)/$(uname -m)"
