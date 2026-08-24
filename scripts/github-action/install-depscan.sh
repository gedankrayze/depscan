#!/usr/bin/env bash
set -euo pipefail

version=${DEPSCAN_ACTION_VERSION:-}
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "version must be an exact depscan release tag such as v2.0.1" >&2
  exit 1
fi

case "${RUNNER_OS:-}/${RUNNER_ARCH:-}" in
  Linux/X64)
    target=x86_64-unknown-linux-musl
    ;;
  Linux/ARM64)
    target=aarch64-unknown-linux-musl
    ;;
  macOS/X64)
    target=x86_64-apple-darwin
    ;;
  macOS/ARM64)
    target=aarch64-apple-darwin
    ;;
  *)
    echo "unsupported depscan runner: ${RUNNER_OS:-unset}/${RUNNER_ARCH:-unset}" >&2
    exit 1
    ;;
esac

: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_ENV:?GITHUB_ENV is required}"

asset="depscan-cli-${target}.tar.xz"
checksum_asset="${asset}.sha256"
release_base="https://github.com/gedankrayze/depscan/releases/download/${version}"
download_dir=$(mktemp -d "${RUNNER_TEMP%/}/depscan-action-download.XXXXXX")
install_dir=$(mktemp -d "${RUNNER_TEMP%/}/depscan-action-bin.XXXXXX")
cleanup() {
  rm -rf -- "$download_dir"
}
trap cleanup EXIT

archive="$download_dir/$asset"
checksum_file="$download_dir/$checksum_asset"
for release_asset in "$asset" "$checksum_asset"; do
  curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
    --retry 3 --retry-connrefused \
    --output "$download_dir/$release_asset" "$release_base/$release_asset"
done

if [[ $(awk 'NF { count++ } END { print count + 0 }' "$checksum_file") -ne 1 ]]; then
  echo "release checksum file must contain exactly one nonblank record" >&2
  exit 1
fi
checksum_line=$(awk 'NF { print; exit }' "$checksum_file")
read -r expected_sha256 checksum_name unexpected_field <<< "$checksum_line"
if [[ ! "$expected_sha256" =~ ^[0-9a-f]{64}$ || -n "${unexpected_field:-}" ]]; then
  echo "release checksum file has an invalid record" >&2
  exit 1
fi
checksum_name=${checksum_name#\*}
if [[ "$checksum_name" != "$asset" ]]; then
  echo "release checksum names $checksum_name instead of $asset" >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  actual_sha256=$(sha256sum "$archive" | awk '{print $1}')
else
  actual_sha256=$(shasum -a 256 "$archive" | awk '{print $1}')
fi
if [[ "$actual_sha256" != "$expected_sha256" ]]; then
  echo "depscan checksum mismatch for $asset" >&2
  echo "expected: $expected_sha256" >&2
  echo "actual:   $actual_sha256" >&2
  exit 1
fi

tar -xJf "$archive" -C "$download_dir"
source_binary="$download_dir/${asset%.tar.xz}/depscan"
if [[ ! -f "$source_binary" ]]; then
  echo "verified depscan archive did not contain the expected executable" >&2
  exit 1
fi
install -m 0755 "$source_binary" "$install_dir/depscan"
installed_binary="$(cd -- "$install_dir" && pwd -P)/depscan"

installed_version=$("$installed_binary" --version)
if [[ "$installed_version" != "depscan ${version#v}" ]]; then
  echo "downloaded binary does not match release $version: $installed_version" >&2
  exit 1
fi
printf 'DEPSCAN_ACTION_INSTALLED_BINARY=%s\n' "$installed_binary" >> "$GITHUB_ENV"
