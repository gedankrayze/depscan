#!/usr/bin/env bash
set -euo pipefail

artifact_dir=${1:?usage: verify-release-assets.sh ARTIFACT-DIR ASSET-CONTRACT}
asset_contract=${2:?usage: verify-release-assets.sh ARTIFACT-DIR ASSET-CONTRACT}

if [[ ! -d "$artifact_dir" ]]; then
  echo "release artifact directory does not exist: $artifact_dir" >&2
  exit 1
fi
if [[ ! -f "$asset_contract" ]]; then
  echo "release asset contract does not exist: $asset_contract" >&2
  exit 1
fi

artifact_dir=$(cd -- "$artifact_dir" && pwd -P)
asset_contract=$(cd -- "$(dirname -- "$asset_contract")" && pwd -P)/$(basename -- "$asset_contract")
scratch=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/depscan-release-assets.XXXXXX")
cleanup() {
  rm -rf -- "$scratch"
}
trap cleanup EXIT

expected_assets="$scratch/expected-assets.txt"
actual_assets="$scratch/actual-assets.txt"
paired_names="$scratch/paired-names.txt"
aggregate_names="$scratch/aggregate-names.txt"

LC_ALL=C sort -u "$asset_contract" > "$expected_assets"
if ! cmp -s "$asset_contract" "$expected_assets" \
  || [[ $(wc -l < "$expected_assets") -ne 16 ]]; then
  echo "release asset contract must contain 16 sorted unique filenames" >&2
  exit 1
fi
if find "$artifact_dir" -mindepth 1 -maxdepth 1 ! -type f -print -quit | grep -q .; then
  echo "release artifact directory contains an unexpected non-file entry" >&2
  find "$artifact_dir" -mindepth 1 -maxdepth 1 ! -type f -print >&2
  exit 1
fi
find "$artifact_dir" -mindepth 1 -maxdepth 1 -type f -exec basename {} \; \
  | LC_ALL=C sort -u > "$actual_assets"
if ! diff -u "$expected_assets" "$actual_assets"; then
  echo "release artifact directory differs from the reviewed 16-file contract" >&2
  exit 1
fi

shopt -s nullglob
checksum_files=("$artifact_dir"/*.sha256)
if [[ ${#checksum_files[@]} -ne 7 ]]; then
  echo "release must contain exactly seven paired checksum records" >&2
  exit 1
fi
: > "$paired_names"
for checksum_path in "${checksum_files[@]}"; do
  checksum_file=$(basename -- "$checksum_path")
  payload=${checksum_file%.sha256}
  if [[ $(awk 'NF { count++ } END { print count + 0 }' "$checksum_path") -ne 1 ]]; then
    echo "paired checksum must contain one nonblank record: $checksum_file" >&2
    exit 1
  fi
  record=$(awk 'NF { print; exit }' "$checksum_path")
  read -r expected name unexpected <<< "$record"
  name=${name#\*}
  if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]] \
    || [[ -n "${unexpected:-}" ]] \
    || [[ "$name" != "$payload" ]] \
    || [[ ! -f "$artifact_dir/$name" ]]; then
    echo "paired checksum is malformed or names the wrong payload: $checksum_file" >&2
    exit 1
  fi
  actual=$(sha256sum "$artifact_dir/$name" | awk '{ print $1 }')
  if [[ "$actual" != "$expected" ]]; then
    echo "paired checksum mismatch for $name" >&2
    exit 1
  fi
  printf '%s\n' "$name" >> "$paired_names"
done
LC_ALL=C sort -u -o "$paired_names" "$paired_names"
if [[ $(wc -l < "$paired_names") -ne 7 ]]; then
  echo "paired checksums must name seven distinct payloads" >&2
  exit 1
fi

if [[ $(awk 'NF { count++ } END { print count + 0 }' "$artifact_dir/sha256.sum") -ne 7 ]]; then
  echo "aggregate checksum must contain exactly seven nonblank records" >&2
  exit 1
fi
: > "$aggregate_names"
while IFS= read -r record; do
  read -r expected name unexpected <<< "$record"
  name=${name#\*}
  if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]] \
    || [[ -n "${unexpected:-}" ]] \
    || [[ ! -f "$artifact_dir/$name" ]]; then
    echo "aggregate checksum contains a malformed record" >&2
    exit 1
  fi
  actual=$(sha256sum "$artifact_dir/$name" | awk '{ print $1 }')
  if [[ "$actual" != "$expected" ]]; then
    echo "aggregate checksum mismatch for $name" >&2
    exit 1
  fi
  printf '%s\n' "$name" >> "$aggregate_names"
done < <(awk 'NF { print }' "$artifact_dir/sha256.sum")
LC_ALL=C sort -u -o "$aggregate_names" "$aggregate_names"
if ! diff -u "$paired_names" "$aggregate_names"; then
  echo "aggregate checksum names differ from the seven paired payloads" >&2
  exit 1
fi

echo "release asset inventory and checksum contract verified"
