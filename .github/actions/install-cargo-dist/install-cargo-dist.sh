#!/usr/bin/env bash
set -euo pipefail

version=0.32.0

case "${RUNNER_OS:-}/${RUNNER_ARCH:-}" in
  Linux/X64)
    asset=cargo-dist-x86_64-unknown-linux-gnu.tar.xz
    expected_sha256=eb52f9fae0d0506774e9f1801c1168f87fa2c87a45e2d64d3ae7c89401929946
    ;;
  Linux/ARM64)
    asset=cargo-dist-aarch64-unknown-linux-gnu.tar.xz
    expected_sha256=d29bcffeb3f8b0c517b4ce0dd2470926ed5cb0bb29d78c6bdd5f88d76ee14a6a
    ;;
  macOS/X64)
    asset=cargo-dist-x86_64-apple-darwin.tar.xz
    expected_sha256=6243464a8389e006b9256ee548bc795638f1a17113c1b6669c0e05ce89fd05c5
    ;;
  macOS/ARM64)
    asset=cargo-dist-aarch64-apple-darwin.tar.xz
    expected_sha256=aa343b2ff78ec2981f17a65140250c5ad6062c74072163f68c5c2686d94763a7
    ;;
  *)
    echo "unsupported cargo-dist runner: ${RUNNER_OS:-unset}/${RUNNER_ARCH:-unset}" >&2
    exit 1
    ;;
esac

: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_PATH:?GITHUB_PATH is required}"

download_dir=$(mktemp -d "${RUNNER_TEMP%/}/depscan-cargo-dist-download.XXXXXX")
install_dir=$(mktemp -d "${RUNNER_TEMP%/}/depscan-cargo-dist-bin.XXXXXX")
cleanup() {
  rm -rf -- "$download_dir"
}
trap cleanup EXIT

archive="$download_dir/$asset"
url="https://github.com/axodotdev/cargo-dist/releases/download/v${version}/${asset}"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  --retry 3 --retry-connrefused --output "$archive" "$url"

if command -v sha256sum >/dev/null 2>&1; then
  actual_sha256=$(sha256sum "$archive" | awk '{print $1}')
else
  actual_sha256=$(shasum -a 256 "$archive" | awk '{print $1}')
fi
if [[ "$actual_sha256" != "$expected_sha256" ]]; then
  echo "cargo-dist checksum mismatch for $asset" >&2
  echo "expected: $expected_sha256" >&2
  echo "actual:   $actual_sha256" >&2
  exit 1
fi

tar -xJf "$archive" -C "$download_dir"
source_binary="$download_dir/${asset%.tar.xz}/dist"
if [[ ! -f "$source_binary" ]]; then
  echo "verified cargo-dist archive did not contain the expected executable" >&2
  exit 1
fi
install -m 0755 "$source_binary" "$install_dir/dist"

installed_version=$("$install_dir/dist" --version)
if [[ "$installed_version" != "cargo-dist $version" ]]; then
  echo "unexpected cargo-dist version: $installed_version" >&2
  exit 1
fi
printf '%s\n' "$install_dir" >> "$GITHUB_PATH"
