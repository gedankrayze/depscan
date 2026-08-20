#!/usr/bin/env bash
set -euo pipefail

source_root=${1:-crates}
max_lines=${RUST_MAX_LINES:-400}

if [[ ! -d "$source_root" ]]; then
  echo "Rust source root does not exist: $source_root" >&2
  exit 1
fi
if [[ ! "$max_lines" =~ ^[1-9][0-9]*$ ]]; then
  echo "RUST_MAX_LINES must be a positive integer, got: $max_lines" >&2
  exit 1
fi

violations=0
file_count=0
while IFS= read -r -d '' source_file; do
  ((file_count += 1))
  line_count=$(awk 'END { print NR }' "$source_file")
  if ((line_count > max_lines)); then
    printf '%s has %d lines; maximum is %d\n' "$source_file" "$line_count" "$max_lines" >&2
    violations=1
  fi

  case "$source_file" in
    */tests.rs | */tests/*.rs) ;;
    *)
      if grep -Eq '^[[:space:]]*#\[(tokio::)?test([^]]*)?\]' "$source_file"; then
        echo "$source_file contains tests outside a dedicated tests module" >&2
        violations=1
      fi
      ;;
  esac
done < <(find "$source_root" -type f -name '*.rs' -print0)

if ((file_count == 0)); then
  echo "no Rust source files found below $source_root" >&2
  exit 1
fi
if ((violations != 0)); then
  exit 1
fi

printf 'Rust architecture check passed: %d files, maximum %d lines, tests isolated\n' \
  "$file_count" "$max_lines"
