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

# A toolchain bump must land in rust-toolchain.toml and every workflow pin together. Version
# comments on the pinned dtolnay/rust-toolchain commits are the human-auditable half of each
# pin; requiring them to match the toolchain channel (or the MSRV for the dedicated MSRV job)
# turns a missed workflow into a failure instead of silent drift.
toolchain_channel=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)
msrv=$(sed -n 's/^rust-version = "\(.*\)"$/\1/p' Cargo.toml)
if [[ -z "$toolchain_channel" || -z "$msrv" ]]; then
  echo "cannot determine the toolchain channel or MSRV" >&2
  exit 1
fi
toolchain_pins=$(grep -rn "dtolnay/rust-toolchain@" .github/workflows/ || true)
if [[ -z "$toolchain_pins" ]]; then
  echo "no pinned dtolnay/rust-toolchain uses found" >&2
  exit 1
fi
stray_toolchains=$(grep -vE "# (${toolchain_channel}|${msrv})$" <<<"$toolchain_pins" || true)
if [[ -n "$stray_toolchains" ]]; then
  echo "workflow toolchain pins disagree with rust-toolchain.toml (${toolchain_channel}) or the MSRV (${msrv}):" >&2
  echo "$stray_toolchains" >&2
  exit 1
fi

printf 'CI policy verified: canonical PR evidence, path-scoped heavy workflows, and consistent toolchain pins\n'
