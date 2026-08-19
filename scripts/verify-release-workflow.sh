#!/usr/bin/env bash
set -euo pipefail

release_workflow=.github/workflows/release.yml
quality_workflow=.github/workflows/release-quality.yml
installer_action=.github/actions/install-cargo-dist/action.yml
installer_unix=.github/actions/install-cargo-dist/install-cargo-dist.sh
installer_windows=.github/actions/install-cargo-dist/install-cargo-dist.ps1

for required_file in \
  "$release_workflow" \
  "$quality_workflow" \
  "$installer_action" \
  "$installer_unix" \
  "$installer_windows"; do
  if [[ ! -f "$required_file" ]]; then
    echo "missing release support file: $required_file" >&2
    exit 1
  fi
done

unpinned_actions=$(
  grep -hE '^[[:space:]-]*uses:' "$release_workflow" "$quality_workflow" \
    | grep -vE 'uses:[[:space:]]+\./' \
    | grep -vE '@[0-9a-f]{40}([[:space:]]|$)' \
    || true
)
if [[ -n "$unpinned_actions" ]]; then
  echo "release workflows contain unpinned actions:" >&2
  echo "$unpinned_actions" >&2
  exit 1
fi

root_permissions=$(sed -n '/^permissions:$/,/^$/p' "$release_workflow" | sed '/^$/d')
expected_root_permissions=$'permissions:\n  "contents": "read"'
if [[ "$root_permissions" != "$expected_root_permissions" ]]; then
  echo "release workflow root permissions must be exactly contents: read" >&2
  exit 1
fi
quality_permissions=$(sed -n '/^permissions:$/,/^$/p' "$quality_workflow" | sed '/^$/d')
if [[ "$quality_permissions" != "$expected_root_permissions" ]]; then
  echo "release quality workflow permissions must be exactly contents: read" >&2
  exit 1
fi

write_permission_count=$(grep -Fc '"contents": "write"' "$release_workflow")
if [[ "$write_permission_count" -ne 1 ]]; then
  echo "release workflow must grant contents: write to exactly one job" >&2
  exit 1
fi

host_job=$(sed -n '/^  host:/,/^  announce:/p' "$release_workflow")
for permission in '"attestations": "write"' '"contents": "write"' '"id-token": "write"'; do
  if [[ $(grep -Fc "$permission" "$release_workflow") -ne 1 ]] || ! grep -Fq "$permission" <<<"$host_job"; then
    echo "only the host job may receive $permission" >&2
    exit 1
  fi
done
if [[ $(grep -Ec '^[[:space:]]+"[^"]+": "write"$' "$release_workflow") -ne 3 ]]; then
  echo "release workflow contains an unexpected write permission" >&2
  exit 1
fi

if grep -Eq '(curl|wget|irm|Invoke-WebRequest).*[|][[:space:]]*(sh|bash|iex|Invoke-Expression)' \
  "$release_workflow" "$quality_workflow" "$installer_action" "$installer_unix" "$installer_windows"; then
  echo "release bootstrap must never pipe downloaded content into an interpreter" >&2
  exit 1
fi
for forbidden in \
  'matrix.install_dist' \
  'matrix.dist_args' \
  'matrix.packages_install' \
  'tag-flag' \
  'cargo-dist-cache' \
  'sh.rustup.rs' \
  'win.rustup.rs'; do
  if grep -Fq "$forbidden" "$release_workflow"; then
    echo "release workflow contains forbidden dynamic bootstrap: $forbidden" >&2
    exit 1
  fi
done
if grep -Eq '^[[:space:]]*(dist|gh)[^#]*[$][{][{]' "$release_workflow"; then
  echo "release commands must not interpolate GitHub expressions into shell source" >&2
  exit 1
fi
# shellcheck disable=SC2016
grep -Fq '[[ ! "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]' "$release_workflow"
if [[ $(grep -Fc 'uses: ./.github/actions/install-cargo-dist' "$release_workflow") -ne 4 ]]; then
  echo "every cargo-dist release phase must use the checked-in installer" >&2
  exit 1
fi
# The literal templates prove that the scripts combine only the reviewed version and asset names.
# shellcheck disable=SC2016
grep -Fq 'https://github.com/axodotdev/cargo-dist/releases/download/v${version}/${asset}' "$installer_unix"
# shellcheck disable=SC2016
grep -Fq 'https://github.com/axodotdev/cargo-dist/releases/download/v$version/$asset' "$installer_windows"
for expected_sha256 in \
  aa343b2ff78ec2981f17a65140250c5ad6062c74072163f68c5c2686d94763a7 \
  d29bcffeb3f8b0c517b4ce0dd2470926ed5cb0bb29d78c6bdd5f88d76ee14a6a \
  6243464a8389e006b9256ee548bc795638f1a17113c1b6669c0e05ce89fd05c5 \
  26e845cabff12a92911ce960af73a86c8f9b2b2d9072b01dfe5b662acf044fa3 \
  eb52f9fae0d0506774e9f1801c1168f87fa2c87a45e2d64d3ae7c89401929946; do
  if ! grep -Fq "$expected_sha256" "$installer_unix" "$installer_windows"; then
    echo "missing reviewed cargo-dist checksum: $expected_sha256" >&2
    exit 1
  fi
done
grep -Fq '      - custom-release-quality' "$release_workflow"
host_needs=$(sed -n '/^  host:/,/^[[:space:]]*if:/p' "$release_workflow")
grep -Fq '      - custom-release-quality' <<<"$host_needs"
grep -Fq "needs.custom-release-quality.result == 'success'" <<<"$host_job"
if grep -Fq 'secrets: inherit' "$release_workflow"; then
  echo "release quality workflow must not inherit repository secrets" >&2
  exit 1
fi
if [[ $(grep -Fc 'uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6' "$release_workflow") -ne 1 ]]; then
  echo "release workflow must use the pinned attestation action exactly once" >&2
  exit 1
fi
grep -Fq 'uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6' <<<"$host_job"
grep -Fq '            artifacts/*' <<<"$host_job"

echo "release workflow pins, verified bootstrap, and permissions verified"
