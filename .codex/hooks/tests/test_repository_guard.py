from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


HOOK = Path(__file__).parents[1] / "repository_guard.py"
SPEC = importlib.util.spec_from_file_location("repository_guard", HOOK)
assert SPEC is not None and SPEC.loader is not None
repository_guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(repository_guard)


class RepositoryGuardTests(unittest.TestCase):
    def test_allows_normal_development_commands(self) -> None:
        for command in (
            "git status --short",
            "git push origin develop",
            "git push origin ticket/agent-automation",
            "git push main",
            "git tag v1.3.0",
            "echo git push origin main",
            "cargo test --workspace --all-targets --locked",
        ):
            with self.subTest(command=command):
                self.assertIsNone(repository_guard.denial_reason(command))

    def test_denies_direct_main_pushes(self) -> None:
        for command in (
            "git push origin main",
            "git push origin HEAD:main",
            "git push origin HEAD:refs/heads/main",
            "echo ready && git push origin refs/heads/main",
        ):
            with self.subTest(command=command):
                self.assertIn("never push directly to main", repository_guard.denial_reason(command))

    def test_denies_force_pushes(self) -> None:
        for command in (
            "git push --force origin develop",
            "git push origin --force-with-lease ticket/change",
            "git push origin --force-with-lease=abc ticket/change",
            "git push -f origin ticket/change",
        ):
            with self.subTest(command=command):
                self.assertIn("Force-pushing", repository_guard.denial_reason(command))

    def test_denies_release_tag_deletion_or_movement(self) -> None:
        for command in (
            "git tag -d v1.2.0",
            "git tag --force v1.2.0 HEAD",
            "git push --delete origin v1.2.0",
            "git push origin :refs/tags/v1.2.0",
        ):
            with self.subTest(command=command):
                self.assertIsNotNone(repository_guard.denial_reason(command))

    def test_cli_emits_the_documented_denial_shape(self) -> None:
        result = subprocess.run(
            [sys.executable, str(HOOK)],
            input=json.dumps({"tool_input": {"command": "git push origin main"}}),
            check=True,
            capture_output=True,
            text=True,
        )

        output = json.loads(result.stdout)
        hook_output = output["hookSpecificOutput"]
        self.assertEqual(hook_output["hookEventName"], "PreToolUse")
        self.assertEqual(hook_output["permissionDecision"], "deny")

    def test_cli_is_silent_for_an_allowed_command(self) -> None:
        result = subprocess.run(
            [sys.executable, str(HOOK)],
            input=json.dumps({"tool_input": {"command": "git push origin develop"}}),
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
