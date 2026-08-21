#!/usr/bin/env bash
set -euo pipefail

ci_workflow=.github/workflows/ci.yml
static_workflow=.github/workflows/static-linux.yml
release_workflow=.github/workflows/release.yml

for workflow in "$ci_workflow" "$static_workflow" "$release_workflow"; do
  if [[ ! -f "$workflow" ]]; then
    echo "missing workflow: $workflow" >&2
    exit 1
  fi
done

if ! grep -Fq '    branches: [main]' "$ci_workflow" ||
  ! grep -Fq '    branches: [main]' "$static_workflow"; then
  echo "CI and Static Linux push runs must target protected main only" >&2
  exit 1
fi
if grep -Eq 'branches:.*develop' "$ci_workflow" "$static_workflow"; then
  echo "develop pushes must rely on the canonical pull-request run" >&2
  exit 1
fi

expected_ci_concurrency=$'concurrency:\n  group: ci-${{ github.event.pull_request.number || github.ref }}\n  cancel-in-progress: true'
actual_ci_concurrency=$(sed -n '/^concurrency:$/,/^$/p' "$ci_workflow" | sed '/^$/d')
if [[ "$actual_ci_concurrency" != "$expected_ci_concurrency" ]]; then
  echo "CI must cancel superseded runs for the same PR or ref" >&2
  exit 1
fi

expected_static_concurrency=$'concurrency:\n  group: static-linux-${{ github.event.pull_request.number || github.ref }}\n  cancel-in-progress: true'
actual_static_concurrency=$(sed -n '/^concurrency:$/,/^$/p' "$static_workflow" | sed '/^$/d')
if [[ "$actual_static_concurrency" != "$expected_static_concurrency" ]]; then
  echo "Static Linux must cancel superseded runs for the same PR or ref" >&2
  exit 1
fi

for release_path in \
  "      - '.github/workflows/release.yml'" \
  "      - 'Cargo.toml'" \
  "      - 'action.yml'" \
  "      - 'crates/*/Cargo.toml'" \
  "      - 'rust-toolchain.toml'" \
  "      - 'scripts/verify-release-workflow.sh'"; do
  if ! grep -Fqx "$release_path" "$release_workflow"; then
    echo "release pull-request path contract is missing: $release_path" >&2
    exit 1
  fi
done

for static_path in \
  "      - '.github/workflows/static-linux.yml'" \
  "      - 'Cargo.toml'" \
  "      - 'crates/**'" \
  "      - 'scripts/verify-static-linux.sh'"; do
  if [[ $(grep -Fxc "$static_path" "$static_workflow") -ne 2 ]]; then
    echo "static workflow path contract must cover PR and main push: $static_path" >&2
    exit 1
  fi
done

printf 'CI policy verified: canonical PR evidence and path-scoped heavy workflows\n'
