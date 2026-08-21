#!/usr/bin/env bash
set -euo pipefail

mode=${1:-full}

usage() {
  cat <<'EOF'
Usage: scripts/dev-gate.sh [quick|full|release]

  quick    Architecture, formatting, compilation, and patch hygiene.
  full     Quick structural gates plus strict Clippy, tests, and repository verifiers.
  release  Full gates plus publishable workspace packaging and a release CLI build.
EOF
}

run() {
  printf '\n==> %s\n' "$*"
  "$@"
}

quick_gates() {
  run bash scripts/check-rust-architecture.sh
  run bash scripts/verify-agent-automation.sh
  run bash scripts/verify-ci-policy.sh
  run cargo fmt --all -- --check
  run cargo check --workspace --all-targets --locked
  run git diff --check
}

full_gates() {
  run bash scripts/check-rust-architecture.sh
  run bash scripts/verify-agent-automation.sh
  run bash scripts/verify-ci-policy.sh
  run cargo fmt --all -- --check
  run cargo clippy --all-targets -- -D warnings
  run cargo test --workspace --all-targets --locked
  run bash scripts/verify-github-action.sh
  run bash scripts/verify-release-workflow.sh
  run git diff --check
}

case "$mode" in
  quick)
    quick_gates
    ;;
  full)
    full_gates
    ;;
  release)
    full_gates
    run cargo package --workspace --allow-dirty --locked
    run cargo build --release --locked -p depscan-cli
    ;;
  -h | --help | help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
