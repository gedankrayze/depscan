from __future__ import annotations

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("issue_size", ROOT / "scripts/check-issue-size.py")
assert SPEC is not None and SPEC.loader is not None
issue_size = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(issue_size)


class IssueSizeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)

    def test_issue_word_cap_is_a_soft_boundary(self) -> None:
        short = self.directory / "DS-001.md"
        long = self.directory / "DS-002.md"
        short.write_text("word " * 500, encoding="utf-8")
        long.write_text("word " * 501, encoding="utf-8")
        self.assertEqual(issue_size.oversized([short, long]), [(long, 501)])
        result = subprocess.run(
            ["python3", str(ROOT / "scripts/check-issue-size.py"), str(long)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("WARNING", result.stdout)


if __name__ == "__main__":
    unittest.main()
