#!/usr/bin/env sh
set -eu

binary=${1:?"usage: verify-static-linux.sh PATH-TO-DEPSCAN"}

if [ ! -f "$binary" ] || [ ! -x "$binary" ]; then
  printf 'expected an executable regular file: %s\n' "$binary" >&2
  exit 1
fi

file_output=$(file "$binary")
case "$file_output" in
  *ELF*"statically linked"* | *ELF*"static-pie linked"*) ;;
  *)
    printf 'expected a statically linked ELF binary, got: %s\n' "$file_output" >&2
    exit 1
    ;;
esac

dynamic_output=$(readelf -d "$binary" 2>&1)
if printf '%s\n' "$dynamic_output" | grep -q '(NEEDED)'; then
  printf 'binary has dynamic-library requirements:\n%s\n' "$dynamic_output" >&2
  exit 1
fi

version_output=$($binary --version)
case "$version_output" in
  "depscan "*) ;;
  *)
    printf 'unexpected version output: %s\n' "$version_output" >&2
    exit 1
    ;;
esac

$binary --help >/dev/null
printf '%s\n' "$file_output"
printf '%s\n' "$version_output"
