#!/usr/bin/env bash
set -euo pipefail

version=0.34.0

case "${RUNNER_OS:-}/${RUNNER_ARCH:-}" in
  Linux/X64)
    asset=cargo-dist-x86_64-unknown-linux-gnu.tar.xz
    expected_sha256=7fee44ff3ff71ed0064b32d4ec62fee6b58bd37c5887b12a86aedddc5af0c7b5
    ;;
  Linux/ARM64)
    asset=cargo-dist-aarch64-unknown-linux-gnu.tar.xz
    expected_sha256=58efb33edf01342875bfd0c3ce2befa9d73075579ca1b3e5dd75b98c88f92e83
    ;;
  macOS/X64)
    asset=cargo-dist-x86_64-apple-darwin.tar.xz
    expected_sha256=6aa89bb1e7c18f51ae8b148ce2fc6ab00ac46ed8173d4f2ed9afa12101218773
    ;;
  macOS/ARM64)
    asset=cargo-dist-aarch64-apple-darwin.tar.xz
    expected_sha256=d1eec30e63eed23e5a5bd48fe96eae314799811bffca254ec1d2264638ba1890
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
