#!/usr/bin/env bash
set -euo pipefail

cargo_bin=${CARGO_BIN:-cargo}
root=$(git rev-parse --show-toplevel)
cd "$root"

if [[ ${CARGO_NET_OFFLINE:-false} == true ]]; then
  echo 'Dependency freshness requires an online registry and advisory check' >&2
  exit 1
fi
if ! command -v "$cargo_bin" >/dev/null 2>&1; then
  echo 'Cargo and cargo-edit (cargo upgrade) are required for dependency freshness' >&2
  exit 1
fi

# --locked makes a proposed change an error; neither command rewrites the candidate.
# Do not combine update with --dry-run: Cargo then exits zero for a stale lockfile.
# Include incompatible stable requirements rather than checking only Cargo.lock.
"$cargo_bin" upgrade --manifest-path "$root/Cargo.toml" \
  --incompatible allow --locked
"$cargo_bin" update --manifest-path "$root/Cargo.toml" --locked
"$cargo_bin" audit --file "$root/Cargo.lock" --deny warnings
printf 'Dependency freshness passed: stable requirements, compatible lockfile, fresh audit\n'
