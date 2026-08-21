#!/usr/bin/env bash
set -euo pipefail

required_files=(
  AGENTS.md
  .codex/hooks.json
  .codex/hooks/repository_guard.py
  .codex/hooks/session_context.py
  .agents/skills/depscan-change/SKILL.md
  .agents/skills/depscan-pr-triage/SKILL.md
  .agents/skills/depscan-release/SKILL.md
  scripts/dev-gate.sh
  scripts/verify-ci-policy.sh
)
for required_file in "${required_files[@]}"; do
  if [[ ! -f "$required_file" ]]; then
    echo "missing agent automation file: $required_file" >&2
    exit 1
  fi
done

python3 -m json.tool .codex/hooks.json >/dev/null
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s .codex/hooks/tests
bash -n scripts/dev-gate.sh

python3 - .agents/skills/*/SKILL.md <<'PY'
import pathlib
import sys

expected = {
    "depscan-change",
    "depscan-pr-triage",
    "depscan-release",
}
found = set()
for argument in sys.argv[1:]:
    path = pathlib.Path(argument)
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        raise SystemExit(f"invalid skill frontmatter: {path}")
    frontmatter = text.split("---\n", 2)[1]
    fields = {}
    for line in frontmatter.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            raise SystemExit(f"invalid skill frontmatter line in {path}: {line}")
        fields[key.strip()] = value.strip()
    if set(fields) != {"name", "description"} or not fields["description"]:
        raise SystemExit(f"skill needs only non-empty name and description fields: {path}")
    if fields["name"] != path.parent.name:
        raise SystemExit(f"skill name does not match its directory: {path}")
    found.add(fields["name"])
if found != expected:
    raise SystemExit(f"unexpected project skills: {sorted(found)}")
PY

grep -Fq 'cargo clippy --all-targets -- -D warnings' AGENTS.md
grep -Fq 'delete the merged local ticket branch' AGENTS.md
grep -Fq 'delete that merged local branch' .agents/skills/depscan-change/SKILL.md
grep -Fq '"matcher": "^Bash$"' .codex/hooks.json
grep -Fq '"matcher": "^(startup|resume|clear|compact)$"' .codex/hooks.json
if [[ $(grep -Fc '"commandWindows":' .codex/hooks.json) -ne 2 ]]; then
  echo "both project hooks need an explicit Windows command" >&2
  exit 1
fi

printf 'Agent automation check passed: %d skills and tested project hooks\n' 3
