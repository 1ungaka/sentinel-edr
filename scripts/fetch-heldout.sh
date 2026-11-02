#!/usr/bin/env bash
#
# fetch-heldout.sh — download the sample bytes for the held-out recall corpus.
#
# The hashes and their intel live in the ENCRYPTED database managed by
# `cau heldout` (corpus/heldout/hashes.db). This script asks that tool for a
# manifest, downloads each sample from MalwareBazaar (abuse.ch) BY HASH,
# verifies the SHA-256, stores it non-executable under samples/, and writes a
# live manifest.json containing only the samples it fetched and verified. No
# plaintext hash list ever touches disk; live malware never enters git.
#
# This is OPT-IN. It is never run by CI and downloads real malware — run it
# only on a machine you intend to analyse malware on, ideally an isolated VM.
#
# Usage:
#   CAU_HELDOUT_KEY=... MB_API_KEY=... scripts/fetch-heldout.sh [--limit N] [--family F]
#
# Requires: cau (built), curl, jq, unzip, sha256sum.
#   CAU_HELDOUT_KEY  passphrase for the encrypted hash database
#   MB_API_KEY       MalwareBazaar auth key (free from https://auth.abuse.ch)
# MalwareBazaar ships samples in a zip encrypted with the password "infected".
#
# Populate the database first with:  cau heldout pull --source full

set -euo pipefail

MB_API="${MB_API:-https://mb-api.abuse.ch/api/v1/}"
ZIP_PW="infected"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_dir="$here/corpus/heldout"
samples_dir="$out_dir/samples"
live_manifest="$out_dir/manifest.json"
db="$out_dir/hashes.db"
cau_bin="${CAU_BIN:-$here/cau}"

# Pass-through selectors to `cau heldout manifest` are not supported directly;
# the manifest reflects the whole database. Subset by pulling with --family or
# by curating the database. (--limit/--family here are accepted for symmetry
# and applied to the fetch loop.)
limit=0
family=""
while [ $# -gt 0 ]; do
  case "$1" in
    --limit) limit="$2"; shift 2 ;;
    --family) family="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

for tool in curl jq unzip sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || { echo "need $tool on PATH" >&2; exit 1; }
done
[ -x "$cau_bin" ] || { echo "need the cau binary (set CAU_BIN or run 'go build -o cau .')" >&2; exit 1; }
[ -f "$db" ] || { echo "no encrypted database at $db; run 'cau heldout pull' first" >&2; exit 1; }
if [ -z "${CAU_HELDOUT_KEY:-}" ]; then
  echo "set CAU_HELDOUT_KEY (passphrase for $db)" >&2
  exit 1
fi
if [ -z "${MB_API_KEY:-}" ]; then
  echo "set MB_API_KEY (free from https://auth.abuse.ch)" >&2
  exit 1
fi

# Decrypt the database into a source manifest (in memory, then a temp file).
src_manifest="$(mktemp)"
mkdir -p "$samples_dir"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp" "$src_manifest"' EXIT
"$cau_bin" heldout manifest --db "$db" --root "$samples_dir" > "$src_manifest"

is_hex64() { [[ "$1" =~ ^[0-9a-fA-F]{64}$ ]]; }

# Pull (id, sha256, family, path) rows from the source manifest, honouring an
# optional family filter and limit.
mapfile -t rows < <(jq -r --arg fam "$family" '
    .samples[] | select($fam=="" or (.family|ascii_downcase)==($fam|ascii_downcase))
    | [.id, .sha256, .family, .path] | @tsv' "$src_manifest")

fetched=()   # id<TAB>sha256<TAB>path for each verified sample
skipped=0
failed=0

for row in "${rows[@]}"; do
  IFS=$'\t' read -r id sha family path <<<"$row"
  sha="$(echo "$sha" | tr '[:upper:]' '[:lower:]')"

  if [ "$limit" -gt 0 ] && [ "${#fetched[@]}" -ge "$limit" ]; then
    break
  fi
  if ! is_hex64 "$sha"; then
    echo "skip  $id: sha256 is not 64 hex chars" >&2
    skipped=$((skipped + 1))
    continue
  fi

  dest="$samples_dir/$path"
  if [ -f "$dest" ] && [ "$(sha256sum "$dest" | cut -d' ' -f1)" = "$sha" ]; then
    echo "have  $id ($sha)"
    fetched+=("$id"$'\t'"$sha"$'\t'"$path")
    continue
  fi

  echo "fetch $id ($sha)"
  zip="$tmp/$sha.zip"
  if ! curl -fsS -H "Auth-Key: $MB_API_KEY" \
        -d "query=get_file&sha256_hash=$sha" "$MB_API" -o "$zip"; then
    echo "fail  $id: download error" >&2
    failed=$((failed + 1))
    continue
  fi
  # A hash miss returns a tiny JSON body, not a zip.
  if file "$zip" 2>/dev/null | grep -qvi 'zip archive'; then
    echo "fail  $id: not found on MalwareBazaar (query_status: $(jq -r '.query_status // "?"' "$zip" 2>/dev/null))" >&2
    failed=$((failed + 1))
    continue
  fi

  unzip -P "$ZIP_PW" -o -j "$zip" -d "$tmp/extract-$sha" >/dev/null
  got="$(find "$tmp/extract-$sha" -type f | head -1)"
  [ -n "$got" ] || { echo "fail  $id: empty archive" >&2; failed=$((failed + 1)); continue; }

  actual="$(sha256sum "$got" | cut -d' ' -f1)"
  if [ "$actual" != "$sha" ]; then
    echo "fail  $id: hash mismatch (got $actual)" >&2
    failed=$((failed + 1))
    continue
  fi

  mkdir -p "$(dirname "$dest")"
  cp "$got" "$dest"
  chmod 0444 "$dest"   # non-executable on disk
  fetched+=("$id"$'\t'"$sha"$'\t'"$path")
done

# Emit a live manifest containing only the verified samples, carrying each
# sample's full record from the source manifest.
n="${#fetched[@]}"
ids_json='[]'
if [ "$n" -gt 0 ]; then
  ids_json="$(printf '%s\0' "${fetched[@]}" \
    | jq -Rs '[ splits("\u0000") | select(length>0) | split("\t")[0] ]')"
fi
jq --argjson ids "$ids_json" '
    .description = "Held-out recall corpus (live). Generated by scripts/fetch-heldout.sh; do not commit."
    | .samples = [ .samples[] | select(.id as $i | $ids | index($i)) ]
  ' "$src_manifest" > "$live_manifest"
echo
echo "fetched $n sample(s), skipped $skipped placeholder(s), $failed failure(s)"
echo "live manifest: $live_manifest"
[ "$n" -gt 0 ] && echo "measure recall: make eval-recall"
exit 0
