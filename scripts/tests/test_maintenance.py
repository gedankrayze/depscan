from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
class MaintenanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.log = self.directory / "calls.jsonl"
        self.cargo = self.directory / "cargo-stub"
        self.cargo.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "with open(os.environ['STUB_LOG'], 'a', encoding='utf-8') as stream:\n"
            "    stream.write(json.dumps(sys.argv[1:]) + '\\n')\n"
            "sys.exit(42 if sys.argv[1] == os.environ.get('STUB_FAIL') else 0)\n",
            encoding="utf-8",
        )
        self.cargo.chmod(0o755)
        self.environment = {
            **os.environ,
            "CARGO_BIN": str(self.cargo),
            "CARGO_NET_OFFLINE": "false",
            "STUB_LOG": str(self.log),
        }

    def run_check(self, script: str = "check-dependency-freshness.sh") -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", str(ROOT / "scripts" / script)], cwd=ROOT,
            env=self.environment, text=True, capture_output=True, check=False,
        )

    def calls(self) -> list[list[str]]:
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_freshness_checks_stable_manifests_full_lock_and_fresh_advisories(self) -> None:
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls(), [
            ["upgrade", "--manifest-path", str(ROOT / "Cargo.toml"), "--incompatible", "allow", "--locked"],
            ["update", "--manifest-path", str(ROOT / "Cargo.toml"), "--locked"],
            ["audit", "--file", str(ROOT / "Cargo.lock"), "--deny", "warnings"],
        ])

    def test_a_failed_or_outdated_check_stops_the_push_preflight(self) -> None:
        for index, command in enumerate(("upgrade", "update", "audit"), start=1):
            with self.subTest(command=command):
                self.log.unlink(missing_ok=True)
                self.environment["STUB_FAIL"] = command
                result = self.run_check()
                self.assertEqual(result.returncode, 42)
                self.assertEqual(len(self.calls()), index)

    def test_offline_freshness_is_rejected(self) -> None:
        self.environment["CARGO_NET_OFFLINE"] = "true"
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("online", result.stderr)
        self.assertEqual(self.calls(), [])

    def gh_stub(self, incoming: str, fail: bool = False) -> None:
        gh = self.directory / "gh-stub"
        gh.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            f"sys.exit(23) if {fail!r} else None\n"
            "if sys.argv[1:3] == ['repo', 'view']:\n"
            "    print('gedankrayze/depscan')\n"
            "elif sys.argv[1:3] == ['pr', 'list']:\n"
            f"    print({incoming!r}, end='')\n"
            "else:\n"
            "    sys.exit(2)\n", encoding="utf-8",
        )
        gh.chmod(0o755)
        self.environment["GH_BIN"] = str(gh)

    def test_incoming_pr_check_precedes_dependency_freshness(self) -> None:
        self.gh_stub("#74 incoming dependency update\n")
        result = self.run_check("pre-push-check.sh")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("incoming pull requests", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_empty_incoming_queue_runs_all_freshness_checks(self) -> None:
        self.gh_stub("")
        result = self.run_check("pre-push-check.sh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(self.calls()), 3)

    def test_github_failure_is_not_treated_as_an_empty_queue(self) -> None:
        self.gh_stub("", fail=True)
        self.assertNotEqual(self.run_check("pre-push-check.sh").returncode, 0)
        self.assertEqual(self.calls(), [])



if __name__ == "__main__":
    unittest.main()
