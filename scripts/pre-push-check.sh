#!/usr/bin/env bash
set -euo pipefail

gh_bin=${GH_BIN:-gh}
if ! command -v "$gh_bin" >/dev/null 2>&1; then
  echo "GitHub CLI is required for the pre-push incoming-PR check" >&2
  exit 1
fi

if ! repository=$(
  "$gh_bin" repo view --json nameWithOwner --jq '.nameWithOwner'
); then
  echo "unable to resolve the GitHub repository; authenticate gh before pushing" >&2
  exit 1
fi

if ! incoming=$(
  "$gh_bin" pr list \
    --repo "$repository" \
    --state open \
    --limit 1000 \
    --json number,title,author,headRefName,baseRefName,url \
    --jq '.[]
      | select(.headRefName != "develop" or .baseRefName != "main")
      | [
          ("#" + (.number | tostring)),
          (.baseRefName + " <- " + .headRefName),
          (.author.login // "unknown"),
          .title,
          .url
        ]
      | @tsv'
); then
  echo "unable to inspect incoming pull requests; refusing to proceed toward a push" >&2
  exit 1
fi

if [[ -n "$incoming" ]]; then
  echo "incoming pull requests must be processed before pushing:" >&2
  printf '%s\n' "$incoming" >&2
  echo "use the depscan-pr-triage skill, then rerun this check" >&2
  exit 1
fi

printf 'Pre-push PR check passed for %s: no incoming pull requests\n' "$repository"
