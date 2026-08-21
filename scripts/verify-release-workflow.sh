#!/usr/bin/env bash
set -euo pipefail

release_workflow=.github/workflows/release.yml
quality_workflow=.github/workflows/release-quality.yml
acceptance_workflow=.github/workflows/release-acceptance.yml
ci_workflow=.github/workflows/ci.yml
asset_contract=.github/release-assets.txt
asset_verifier=scripts/verify-release-assets.sh
static_verifier=scripts/verify-static-linux.sh
architecture_verifier=scripts/check-rust-architecture.sh
installer_action=.github/actions/install-cargo-dist/action.yml
installer_unix=.github/actions/install-cargo-dist/install-cargo-dist.sh
installer_windows=.github/actions/install-cargo-dist/install-cargo-dist.ps1
workspace_manifest=Cargo.toml

for required_file in \
  "$release_workflow" \
  "$quality_workflow" \
  "$acceptance_workflow" \
  "$ci_workflow" \
  "$asset_contract" \
  "$asset_verifier" \
  "$static_verifier" \
  "$architecture_verifier" \
  "$installer_action" \
  "$installer_unix" \
  "$installer_windows" \
  "$workspace_manifest"; do
  if [[ ! -f "$required_file" ]]; then
    echo "missing release support file: $required_file" >&2
    exit 1
  fi
done

if [[ $(grep -Fc 'run: bash scripts/check-rust-architecture.sh' "$ci_workflow") -ne 1 ]] ||
  [[ $(grep -Fc 'run: bash scripts/check-rust-architecture.sh' "$quality_workflow") -ne 1 ]]; then
  echo "CI and release quality must enforce the Rust architecture check exactly once" >&2
  exit 1
fi

unpinned_actions=$(
  grep -hE '^[[:space:]-]*uses:' "$release_workflow" "$quality_workflow" "$acceptance_workflow" \
    | grep -vE 'uses:[[:space:]]+\./' \
    | grep -vE '@[0-9a-f]{40}([[:space:]]|$)' \
    || true
)
if [[ -n "$unpinned_actions" ]]; then
  echo "release workflows contain unpinned actions:" >&2
  echo "$unpinned_actions" >&2
  exit 1
fi
release_action_uses=$(
  grep -hE '^[[:space:]-]*uses:[[:space:]]+[^.]' "$release_workflow" "$quality_workflow"
)
for expected in \
  'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1:6' \
  'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a:4' \
  'actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c:4' \
  'actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6:1'; do
  action_ref=${expected%:*}
  expected_count=${expected##*:}
  if [[ $(grep -Fc "$action_ref" <<<"$release_action_uses") -ne "$expected_count" ]]; then
    echo "release workflows do not match reviewed action pin/count: $expected" >&2
    exit 1
  fi
  metadata_line=\"${action_ref%@*}\"' = "'${action_ref#*@}'"'
  if ! grep -Fq "$metadata_line" "$workspace_manifest"; then
    echo "release workflow pin is not recorded in cargo-dist metadata: $action_ref" >&2
    exit 1
  fi
done
if [[ $(wc -l <<<"$release_action_uses") -ne 15 ]]; then
  echo "release workflows contain an unexpected external action" >&2
  exit 1
fi

root_permissions=$(sed -n '/^permissions:$/,/^$/p' "$release_workflow" | sed '/^$/d')
expected_root_permissions=$'permissions:\n  "contents": "read"'
if [[ "$root_permissions" != "$expected_root_permissions" ]]; then
  echo "release workflow root permissions must be exactly contents: read" >&2
  exit 1
fi
expected_release_concurrency=$'concurrency:\n  group: release-${{ github.ref }}\n  cancel-in-progress: false'
release_concurrency=$(sed -n '/^concurrency:$/,/^$/p' "$release_workflow" | sed '/^$/d')
if [[ "$release_concurrency" != "$expected_release_concurrency" ]]; then
  echo "release workflow must serialize each tag without cancellation" >&2
  exit 1
fi
quality_permissions=$(sed -n '/^permissions:$/,/^$/p' "$quality_workflow" | sed '/^$/d')
if [[ "$quality_permissions" != "$expected_root_permissions" ]]; then
  echo "release quality workflow permissions must be exactly contents: read" >&2
  exit 1
fi
acceptance_permissions=$(sed -n '/^permissions:$/,/^$/p' "$acceptance_workflow" | sed '/^$/d')
expected_acceptance_permissions=$'permissions:\n  contents: read\n  attestations: read'
if [[ "$acceptance_permissions" != "$expected_acceptance_permissions" ]]; then
  echo "release acceptance permissions must be exactly contents and attestations read" >&2
  exit 1
fi

inline_permissions=$(
  grep -hE "^[[:space:]]*['\"]?permissions['\"]?:[[:space:]]+[^#[:space:]].*$" \
    "$release_workflow" "$quality_workflow" "$acceptance_workflow" \
    || true
)
if [[ -n "$inline_permissions" ]]; then
  echo "release workflows must use auditable block-style permission mappings" >&2
  printf '%s\n' "$inline_permissions" >&2
  exit 1
fi
write_permissions=$(
  grep -hE "^[[:space:]]+['\"]?[A-Za-z0-9_-]+['\"]?:[[:space:]]+['\"]?write['\"]?[[:space:]]*(#.*)?$" \
    "$release_workflow" "$quality_workflow" "$acceptance_workflow" \
    | sed -E "s/^[[:space:]]+['\"]?([A-Za-z0-9_-]+)['\"]?:[[:space:]]+['\"]?write['\"]?[[:space:]]*(#.*)?$/\1/" \
    | LC_ALL=C sort
)
expected_write_permissions=$'attestations\ncontents\nid-token'
if [[ "$write_permissions" != "$expected_write_permissions" ]]; then
  echo "release workflows contain an unexpected quoted or unquoted write permission" >&2
  printf '%s\n' "$write_permissions" >&2
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
if [[ $(grep -Fc '          fetch-depth: 0' "$release_workflow") -ne 1 ]]; then
  echo "release plan checkout must fetch full history exactly once" >&2
  exit 1
fi
# shellcheck disable=SC2016
grep -Fq '[[ "$release_commit" != "$main_commit" ]]' "$release_workflow"
# shellcheck disable=SC2016
grep -Fq 'release-commit: ${{ steps.release-boundary.outputs.commit }}' "$release_workflow"
# shellcheck disable=SC2016
grep -Fq 'RELEASE_COMMIT: "${{ needs.plan.outputs.release-commit }}"' "$release_workflow"
# shellcheck disable=SC2016
if grep -Fq 'RELEASE_COMMIT: "${{ github.sha }}"' "$release_workflow"; then
  echo "release host must use the plan's peeled release commit, not the event object" >&2
  exit 1
fi
grep -Fq 'installers = ["shell", "msi"]' "$workspace_manifest"
# shellcheck disable=SC2016
grep -Fq '$sourceBinary = Join-Path $downloadDir "dist.exe"' "$installer_windows"
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
grep -Fq 'plan_manifest=artifacts/plan-dist-manifest.json' <<<"$host_job"
grep -Fq 'rm -f artifacts/*-dist-manifest.json artifacts/dist-manifest.json' <<<"$host_job"
grep -Fq 'cargo-dist plan differs from the checked-in release asset contract' <<<"$host_job"
grep -Fq 'scripts/verify-release-assets.sh artifacts .github/release-assets.txt' <<<"$host_job"
grep -Fq 'release_args=(--draft --verify-tag' <<<"$host_job"
# shellcheck disable=SC2016
grep -Fq 'git ls-remote origin "refs/tags/$RELEASE_TAG^{}"' <<<"$host_job"
if [[ $(grep -Fxc '          verify_remote_tag' <<<"$host_job") -ne 2 ]]; then
  echo "release host must revalidate the remote tag before draft creation and publication" >&2
  exit 1
fi
# shellcheck disable=SC2016
grep -Fq 'gh release edit "$RELEASE_TAG" --draft=false' <<<"$host_job"

if [[ $(grep -Fc '          - target:' "$acceptance_workflow") -ne 5 ]] \
  || [[ $(grep -Fc '            runner:' "$acceptance_workflow") -ne 5 ]] \
  || [[ $(grep -Fc '            asset:' "$acceptance_workflow") -ne 5 ]]; then
  echo "release acceptance must contain exactly five runner and archive mappings" >&2
  exit 1
fi
for mapping in \
  $'          - target: x86_64-unknown-linux-musl\n            runner: ubuntu-22.04\n            asset: depscan-cli-x86_64-unknown-linux-musl.tar.xz' \
  $'          - target: aarch64-unknown-linux-musl\n            runner: ubuntu-22.04-arm\n            asset: depscan-cli-aarch64-unknown-linux-musl.tar.xz' \
  $'          - target: x86_64-apple-darwin\n            runner: macos-15-intel\n            asset: depscan-cli-x86_64-apple-darwin.tar.xz' \
  $'          - target: aarch64-apple-darwin\n            runner: macos-15\n            asset: depscan-cli-aarch64-apple-darwin.tar.xz' \
  $'          - target: x86_64-pc-windows-msvc\n            runner: windows-2022\n            asset: depscan-cli-x86_64-pc-windows-msvc.zip'; do
  if ! grep -Fq "$mapping" "$acceptance_workflow"; then
    echo "release acceptance target/runner/archive mapping changed" >&2
    exit 1
  fi
done
grep -Fq '          ref: v2.0.0' "$acceptance_workflow"
grep -Fq '          persist-credentials: false' "$acceptance_workflow"
# shellcheck disable=SC2016
grep -Fq '[[ "$GITHUB_REF" != "refs/tags/$RELEASE_TAG" ]]' "$acceptance_workflow"
grep -Fq '            --signer-workflow github.com/gedankrayze/depscan/.github/workflows/release.yml' "$acceptance_workflow"
# shellcheck disable=SC2016
grep -Fq '            --source-ref "refs/tags/$RELEASE_TAG"' "$acceptance_workflow"
# shellcheck disable=SC2016
grep -Fq '            --source-digest "$RELEASE_COMMIT"' "$acceptance_workflow"
grep -Fq '            --deny-self-hosted-runners' "$acceptance_workflow"
grep -Fq 'published release inventory differs from the reviewed 16-file contract' "$acceptance_workflow"
# shellcheck disable=SC2016
grep -Fq 'scripts/verify-release-assets.sh "$artifact_dir" .github/release-assets.txt' "$acceptance_workflow"
if [[ $(grep -Fc 'gh attestation verify' "$acceptance_workflow") -ne 3 ]]; then
  echo "release acceptance must verify the full inventory plus Unix and Windows archives" >&2
  exit 1
fi
if [[ $(grep -Fc 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' "$acceptance_workflow") -ne 2 ]]; then
  echo "release acceptance must use the reviewed checkout v7 pin exactly twice" >&2
  exit 1
fi
if [[ $(grep -Fc 'uses: ./release-source' "$acceptance_workflow") -ne 1 ]] \
  || grep -Eq '^[[:space:]]+binary:' "$acceptance_workflow" \
  || grep -Fq 'uses: gedankrayze/depscan@' "$acceptance_workflow"; then
  echo "release acceptance must use the immutable local tag checkout once without a binary override" >&2
  exit 1
fi
grep -Fq '          version: v2.0.0' "$acceptance_workflow"
# shellcheck disable=SC2016
grep -Fq '          output: ${{ runner.temp }}/depscan-published-action-summary.txt' "$acceptance_workflow"
grep -Fq '          offline: "true"' "$acceptance_workflow"
# shellcheck disable=SC2016
grep -Fq 'if ! cmp -s "$DEPSCAN_ACTION_INSTALLED_BINARY" "$ACCEPTANCE_BINARY"; then' "$acceptance_workflow"
# shellcheck disable=SC2016
grep -Fq '$actionHash = (Get-FileHash -LiteralPath $env:DEPSCAN_ACTION_INSTALLED_BINARY -Algorithm SHA256).Hash' "$acceptance_workflow"
# shellcheck disable=SC2016
grep -Fq '[[ "$($DEPSCAN_ACTION_INSTALLED_BINARY --version)" != "depscan ${RELEASE_TAG#v}" ]]' "$acceptance_workflow"
# shellcheck disable=SC2016
grep -Fq '$version.Trim() -ne "depscan $($env:RELEASE_TAG.Substring(1))"' "$acceptance_workflow"
# shellcheck disable=SC2016
grep -Fq '$version = (& $env:DEPSCAN_ACTION_INSTALLED_BINARY --version) -join "`n"' "$acceptance_workflow"
# shellcheck disable=SC2016
grep -Fq '[[ "$action_summary" != "$EXPECTED_OFFLINE_SUMMARY" ]]' "$acceptance_workflow"
# shellcheck disable=SC2016
grep -Fq '$actionSummary -ne $env:EXPECTED_OFFLINE_SUMMARY' "$acceptance_workflow"
# shellcheck disable=SC2016
grep -Fq '$archiveHash = (Get-FileHash -LiteralPath $env:ACCEPTANCE_BINARY -Algorithm SHA256).Hash' "$acceptance_workflow"
# shellcheck disable=SC2016
grep -Fq 'if ($actionHash -ne $archiveHash) {' "$acceptance_workflow"
if [[ $(grep -Fc 'continue-on-error: true' "$acceptance_workflow") -ne 2 ]]; then
  echo "release acceptance must exercise provider failure on Unix and Windows" >&2
  exit 1
fi
grep -Fq 'id: provider_failure_unix' "$acceptance_workflow"
grep -Fq 'id: provider_failure_windows' "$acceptance_workflow"
# shellcheck disable=SC2016
grep -Fq '[[ "$exit_code" -ne 30 ]]' "$acceptance_workflow"
# shellcheck disable=SC2016
grep -Fq '$exitCode -ne 30' "$acceptance_workflow"
# shellcheck disable=SC2016
grep -Fq '$PSNativeCommandUseErrorActionPreference = $false' "$acceptance_workflow"
grep -Fq 'steps.provider_failure_unix.outcome' "$acceptance_workflow"
grep -Fq 'steps.provider_failure_windows.outcome' "$acceptance_workflow"
if [[ $(grep -Fc 'provider hard failure' "$acceptance_workflow") -ne 2 ]]; then
  echo "release acceptance must bind both provider-failure probes to the typed diagnostic" >&2
  exit 1
fi
# shellcheck disable=SC2016
grep -Fq 'release-source/scripts/verify-static-linux.sh "$ACCEPTANCE_BINARY"' "$acceptance_workflow"
# shellcheck disable=SC2016
grep -Fq 'docker build --network none --tag "$image" "$smoke_root"' "$acceptance_workflow"
if [[ $(grep -Fc "            'FROM scratch'" "$acceptance_workflow") -ne 1 ]]; then
  echo "release acceptance must build exactly one literal scratch image" >&2
  exit 1
fi
if [[ $(grep -Fc 'docker run --rm --network none --read-only' "$acceptance_workflow") -ne 3 ]]; then
  echo "release acceptance must run Linux version, help, and scan inside read-only networkless scratch" >&2
  exit 1
fi
# shellcheck disable=SC2016
grep -Fq -- '--mount "type=bind,source=$DEPSCAN_CACHE_DIR,target=/cache,readonly"' "$acceptance_workflow"
# shellcheck disable=SC2016
grep -Fq -- '--mount "type=bind,source=$GITHUB_WORKSPACE/release-source/fixtures/e2e/cargo,target=/project,readonly"' "$acceptance_workflow"
grep -Fq 'EXPECTED_OFFLINE_SUMMARY: "depscan: 4 packages | 0 vulns | 0 withdrawn | 0 outdated (0 major, 0 yanked) | 0 suppressed | 0 expired ignores | 3 soft failures"' "$acceptance_workflow"
# shellcheck disable=SC2016
if [[ $(grep -Fc '[[ "$summary" != "$EXPECTED_OFFLINE_SUMMARY" ]]' "$acceptance_workflow") -ne 2 ]]; then
  echo "release acceptance must enforce the exact Unix fixture summary twice" >&2
  exit 1
fi
# shellcheck disable=SC2016
if [[ $(grep -Fc 'if ($summaryText -ne $env:EXPECTED_OFFLINE_SUMMARY)' "$acceptance_workflow") -ne 1 ]]; then
  echo "release acceptance must enforce the exact Windows fixture summary" >&2
  exit 1
fi
if [[ $(wc -l < "$asset_contract") -ne 16 ]] \
  || ! cmp -s "$asset_contract" <(LC_ALL=C sort -u "$asset_contract") \
  || grep -Fq 'depscan-cli.rb' "$asset_contract" \
  || grep -Fq 'dist-manifest.json' "$asset_contract"; then
  echo "checked-in release asset contract is not the reviewed sorted 16-file set" >&2
  exit 1
fi

shellcheck "$asset_verifier"
shellcheck "$static_verifier"

echo "release workflow pins, verified bootstrap, and permissions verified"
