#!/usr/bin/env python3
"""Provide concise, local-only DepScan context when a Codex session starts."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


def git(root: Path, *arguments: str) -> str | None:
    result = subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def context(root: Path) -> str:
    branch = git(root, "branch", "--show-current") or "detached HEAD"
    changes = git(root, "status", "--porcelain")
    dirty_count = len(changes.splitlines()) if changes else 0
    divergence = git(root, "rev-list", "--left-right", "--count", "origin/main...HEAD")
    if divergence:
        behind, ahead = divergence.split(maxsplit=1)
        relation = f"origin/main: behind {behind}, ahead {ahead}"
    else:
        relation = "origin/main divergence unavailable without fetching"

    return (
        f"DepScan repository context: branch {branch}; {dirty_count} changed worktree entries; {relation}. "
        "Read AGENTS.md. Use the matching .agents/skills workflow and scripts/dev-gate.sh. "
        "Do not commit, push, merge, tag, publish, or change remote settings without explicit permission."
    )


def main() -> int:
    root_text = git(Path.cwd(), "rev-parse", "--show-toplevel")
    if root_text is None:
        return 0
    output = {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": context(Path(root_text)),
        }
    }
    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
