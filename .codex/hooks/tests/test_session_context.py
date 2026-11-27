from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HOOK = Path(__file__).parents[1] / "session_context.py"
SPEC = importlib.util.spec_from_file_location("session_context", HOOK)
assert SPEC is not None and SPEC.loader is not None
session_context = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(session_context)


class SessionContextTests(unittest.TestCase):
    def test_startup_installs_exclusions_and_keeps_hook_output_valid(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            source = HOOK.parents[2]
            shutil.copy2(source / ".gitignore", root / ".gitignore")
            (root / "scripts").mkdir()
            shutil.copy2(source / "scripts/setup-project.py", root / "scripts/setup-project.py")
            result = subprocess.run(
                [sys.executable, str(HOOK)], cwd=root, check=True, capture_output=True, text=True,
            )
            output = json.loads(result.stdout)["hookSpecificOutput"]
            self.assertEqual(output["hookEventName"], "SessionStart")
            self.assertNotIn("setup failed", output["additionalContext"])
            self.assertIn(b"**/target/", (root / ".git/info/exclude").read_bytes())

    def test_startup_reports_setup_failure_in_context(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "--quiet", str(root)], check=True)
            result = subprocess.run(
                [sys.executable, str(HOOK)], cwd=root, check=True, capture_output=True, text=True,
            )
            output = json.loads(result.stdout)["hookSpecificOutput"]
            self.assertIn("Snapshot exclusion setup failed", output["additionalContext"])
            self.assertIn("python3 scripts/setup-project.py", output["additionalContext"])

    def test_reports_branch_dirty_count_and_gate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-b", "ticket/test"], cwd=root, check=True, capture_output=True)
            subprocess.run(["git", "config", "user.name", "DepScan Test"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            (root / "tracked.txt").write_text("tracked\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-m", "test"], cwd=root, check=True, capture_output=True)
            (root / "untracked.txt").write_text("changed\n", encoding="utf-8")

            rendered = session_context.context(root)

            self.assertIn("branch ticket/test", rendered)
            self.assertIn("1 changed worktree entries", rendered)
            self.assertIn("scripts/dev-gate.sh", rendered)


if __name__ == "__main__":
    unittest.main()
