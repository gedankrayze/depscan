#!/usr/bin/env bash
set -euo pipefail

required_files=(
  Cargo.toml
  README.md
  action.yml
  scripts/github-action/install-depscan.sh
  scripts/github-action/install-depscan.ps1
  scripts/github-action/run-depscan.mjs
)
for required_file in "${required_files[@]}"; do
  if [[ ! -f "$required_file" ]]; then
    echo "missing GitHub Action support file: $required_file" >&2
    exit 1
  fi
done

workspace_version=$(
  awk '
    /^\[workspace\.package\]$/ { in_workspace_package = 1; next }
    /^\[/ { in_workspace_package = 0 }
    in_workspace_package && /^version = "/ {
      value = $0
      sub(/^version = "/, "", value)
      sub(/".*$/, "", value)
      print value
      exit
    }
  ' Cargo.toml
)
action_version=$(
  awk '
    /^  version:$/ { in_version = 1; next }
    in_version && /^    default: / {
      value = $0
      sub(/^    default: /, "", value)
      gsub(/^"|"$/, "", value)
      print value
      exit
    }
    in_version && /^  [A-Za-z0-9_-]+:$/ { exit }
  ' action.yml
)

if [[ -z "$workspace_version" || "$action_version" != "v$workspace_version" ]]; then
  echo "action default $action_version does not match workspace version v$workspace_version" >&2
  exit 1
fi
grep -Fq "uses: gedankrayze/depscan@v$workspace_version" README.md
grep -Fq "version: v$workspace_version" README.md

if grep -Eq '^[[:space:]]+run:.*[$][{][{][[:space:]]*inputs\.' action.yml; then
  echo "action inputs must enter fixed environment variables, not shell source" >&2
  exit 1
fi
if grep -Eq '(^|[^A-Za-z])(eval|Invoke-Expression)([^A-Za-z]|$)' \
  scripts/github-action/install-depscan.sh \
  scripts/github-action/install-depscan.ps1 \
  scripts/github-action/run-depscan.mjs; then
  echo "GitHub Action support scripts must not evaluate generated command text" >&2
  exit 1
fi
grep -Fq 'shell: false' scripts/github-action/run-depscan.mjs

bash -n scripts/github-action/install-depscan.sh
node --check scripts/github-action/run-depscan.mjs

echo "GitHub Action version and invocation contract verified"
