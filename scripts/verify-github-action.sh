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
grep -Fq 'path.resolve(binaryInput)' scripts/github-action/run-depscan.mjs
grep -Fq 'path.isAbsolute(binary)' scripts/github-action/run-depscan.mjs
for installer in \
  scripts/github-action/install-depscan.sh \
  scripts/github-action/install-depscan.ps1; do
  grep -Fq 'GITHUB_ENV' "$installer"
  grep -Fq 'DEPSCAN_ACTION_INSTALLED_BINARY=' "$installer"
  if grep -Fq 'GITHUB_PATH' "$installer"; then
    echo "installers must hand off the verified binary identity directly, not through PATH" >&2
    exit 1
  fi
done
# shellcheck disable=SC2016
grep -Fq '$sourceBinary = Join-Path $downloadDir "depscan.exe"' \
  scripts/github-action/install-depscan.ps1
# shellcheck disable=SC2016
if grep -Fq 'depscan-cli-$target/depscan.exe' scripts/github-action/install-depscan.ps1; then
  echo "Windows action installer must use cargo-dist's flat ZIP layout" >&2
  exit 1
fi
grep -Fq 'setting("DEPSCAN_ACTION_INSTALLED_BINARY")' \
  scripts/github-action/run-depscan.mjs
if grep -Eq "['\"]depscan(\\.exe)?['\"]" scripts/github-action/run-depscan.mjs; then
  echo "action runner must not contain a bare depscan executable fallback" >&2
  exit 1
fi

bash -n scripts/github-action/install-depscan.sh
node --check scripts/github-action/run-depscan.mjs

runner_script="$PWD/scripts/github-action/run-depscan.mjs"
probe_root=$(mktemp -d "${TMPDIR:-/tmp}/depscan-action-probe.XXXXXX")
cleanup_action_probe() {
  rm -rf -- "$probe_root"
}
trap cleanup_action_probe EXIT

make_probe_binary() {
  local binary_path=$1
  mkdir -p -- "$(dirname -- "$binary_path")"
  cat > "$binary_path" <<'PROBE'
#!/usr/bin/env bash
set -euo pipefail
printf 'started\n' > "${DEPSCAN_PROBE_MARKER:?}"
printf '%s\n' "$@" > "${DEPSCAN_PROBE_CAPTURE:?}"
exit "${DEPSCAN_PROBE_EXIT:-0}"
PROBE
  chmod 0755 "$binary_path"
}

trusted_binary="$probe_root/trusted bin/depscan-verified"
override_binary="$probe_root/override bin/depscan-local"
decoy_directory="$probe_root/decoy cwd"
decoy_binary="$decoy_directory/depscan"
decoy_marker="$probe_root/decoy-started"
make_probe_binary "$trusted_binary"
make_probe_binary "$override_binary"
mkdir -p -- "$decoy_directory"
cat > "$decoy_binary" <<'DECOY'
#!/usr/bin/env bash
set -euo pipefail
printf 'started\n' > "${DEPSCAN_PROBE_DECOY_MARKER:?}"
exit 97
DECOY
chmod 0755 "$decoy_binary"

injected_marker="$probe_root/injected"
scan_path="$probe_root/project path;literal-\$(touch $injected_marker)"
output_path="$probe_root/report path;literal-\$(touch $injected_marker)"

run_driver() {
  local binary_input=$1
  local installed_binary=$2
  local format=$3
  local capture=$4
  local marker=$5
  local child_exit=$6
  env \
    DEPSCAN_ACTION_BINARY="$binary_input" \
    DEPSCAN_ACTION_INSTALLED_BINARY="$installed_binary" \
    DEPSCAN_ACTION_PATH_INPUT="$scan_path" \
    DEPSCAN_ACTION_ECOSYSTEM=npm \
    DEPSCAN_ACTION_FORMAT="$format" \
    DEPSCAN_ACTION_OUTPUT="$output_path" \
    DEPSCAN_ACTION_FAIL_ON=high \
    DEPSCAN_ACTION_FAIL_ON_OUTDATED=minor \
    DEPSCAN_ACTION_OFFLINE=true \
    DEPSCAN_ACTION_NO_CACHE=false \
    DEPSCAN_ACTION_NO_DEV=true \
    DEPSCAN_ACTION_DIRECT_ONLY=true \
    DEPSCAN_ACTION_INCLUDE_WITHDRAWN=true \
    DEPSCAN_PROBE_CAPTURE="$capture" \
    DEPSCAN_PROBE_MARKER="$marker" \
    DEPSCAN_PROBE_EXIT="$child_exit" \
    DEPSCAN_PROBE_DECOY_MARKER="$decoy_marker" \
    node "$runner_script"
}

expected_args="$probe_root/expected.args"
printf '%s\n' \
  scan \
  --ecosystem npm \
  --format markdown \
  --output "$output_path" \
  --fail-on high \
  --fail-on-outdated minor \
  --offline \
  --no-dev \
  --direct-only \
  --include-withdrawn \
  -- "$scan_path" > "$expected_args"

installed_capture="$probe_root/installed.args"
installed_marker="$probe_root/installed-started"
PATH="$decoy_directory:$PATH" \
  run_driver "" "$trusted_binary" markdown "$installed_capture" "$installed_marker" 0
diff -u "$expected_args" "$installed_capture"
test -f "$installed_marker"
test ! -e "$decoy_marker"
test ! -e "$injected_marker"

override_capture="$probe_root/override.args"
override_marker="$probe_root/override-started"
(
  cd "$probe_root"
  run_driver \
    "override bin/depscan-local" \
    "$decoy_binary" \
    markdown \
    "$override_capture" \
    "$override_marker" \
    0
)
diff -u "$expected_args" "$override_capture"
test -f "$override_marker"
test ! -e "$decoy_marker"

relative_capture="$probe_root/relative.args"
relative_marker="$probe_root/relative-started"
set +e
run_driver \
  "" \
  depscan \
  json \
  "$relative_capture" \
  "$relative_marker" \
  0 > "$probe_root/relative.stdout" 2> "$probe_root/relative.stderr"
relative_status=$?
set -e
test "$relative_status" -eq 10
grep -Fq 'installed depscan binary path must be a non-empty absolute path' \
  "$probe_root/relative.stderr"
test ! -e "$relative_capture"
test ! -e "$relative_marker"

invalid_capture="$probe_root/invalid.args"
invalid_marker="$probe_root/invalid-started"
set +e
run_driver \
  "" \
  "$trusted_binary" \
  invalid \
  "$invalid_capture" \
  "$invalid_marker" \
  0 > "$probe_root/invalid.stdout" 2> "$probe_root/invalid.stderr"
invalid_status=$?
set -e
test "$invalid_status" -eq 10
grep -Fq 'DEPSCAN_ACTION_FORMAT must be one of' "$probe_root/invalid.stderr"
test ! -e "$invalid_capture"
test ! -e "$invalid_marker"

exit_capture="$probe_root/exit.args"
exit_marker="$probe_root/exit-started"
set +e
run_driver \
  "" \
  "$trusted_binary" \
  json \
  "$exit_capture" \
  "$exit_marker" \
  1 > "$probe_root/exit.stdout" 2> "$probe_root/exit.stderr"
child_status=$?
set -e
test "$child_status" -eq 1
test -f "$exit_capture"
test -f "$exit_marker"

echo "GitHub Action version, exact binary identity, and invocation contract verified"
