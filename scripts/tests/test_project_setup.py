from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/setup-project.py"
SPEC = importlib.util.spec_from_file_location("project_setup", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
project_setup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(project_setup)


class ProjectSetupTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="depscan setup ")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.root = self.directory / "source"
        self.root.mkdir()
        self.git(self.root, "init", "--quiet", "-b", "main")
        self.git(self.root, "config", "user.name", "DepScan Test")
        self.git(self.root, "config", "user.email", "test@example.invalid")
        shutil.copy2(ROOT / ".gitignore", self.root / ".gitignore")
        (self.root / "scripts").mkdir()
        shutil.copy2(SCRIPT, self.root / "scripts/setup-project.py")
        (self.root / "source.rs").write_text("// source fixture\n", encoding="utf-8")
        self.git(self.root, "add", ".")
        self.git(self.root, "-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture")

    def git(self, root: Path, *arguments: str, env: dict[str, str] | None = None) -> str:
        return subprocess.check_output(["git", *arguments], cwd=root, env=env, text=True)

    def test_fresh_clone_setup_protects_snapshots_without_gitignore(self) -> None:
        clone = self.directory / "fresh clone"
        self.git(self.directory, "clone", "--quiet", str(self.root), str(clone))
        (clone / "src").mkdir()
        result = subprocess.run(
            [sys.executable, str(clone / "scripts/setup-project.py")], cwd=clone / "src",
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        (clone / ".gitignore").unlink()
        artifacts = ["target/debug/build.rlib", "crates/example/target/release/app", "app.pdb", "old.rs.bk"]
        for name in artifacts + ["new-source.rs"]:
            path = clone / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture\n", encoding="utf-8")
        index_before = (clone / ".git/index").read_bytes()
        env = {**os.environ, "GIT_INDEX_FILE": str(clone / ".git/snapshot-index")}
        self.git(clone, "read-tree", "--empty", env=env)
        self.git(clone, "add", "-A", env=env)
        tree = self.git(clone, "write-tree", env=env).strip()
        paths = self.git(clone, "ls-tree", "-r", "--name-only", tree).splitlines()
        self.assertIn("new-source.rs", paths)
        self.assertTrue(set(artifacts).isdisjoint(paths), paths)
        self.assertEqual((clone / ".git/index").read_bytes(), index_before)

    def test_preserves_existing_bytes_and_is_idempotent(self) -> None:
        exclude = self.root / ".git/info/exclude"
        existing = b"# User exclusions\r\nprivate-data/\r\n!keep-this.txt"
        exclude.write_bytes(existing)
        project_setup.install(self.root)
        contents = exclude.read_bytes()
        self.assertTrue(contents.startswith(existing + b"\n"))
        timestamp = exclude.stat().st_mtime_ns
        project_setup.install(self.root)
        self.assertEqual(exclude.read_bytes(), contents)
        self.assertEqual(exclude.stat().st_mtime_ns, timestamp)

    def test_reuses_exclusions_installed_before_project_setup_existed(self) -> None:
        exclude = self.root / ".git/info/exclude"
        existing = b"# Original local protection\n/target/\n**/target/\n**/*.rs.bk\n*.pdb\n"
        exclude.write_bytes(existing)
        project_setup.install(self.root)
        self.assertEqual(exclude.read_bytes(), existing)

    def test_linked_worktree_uses_common_repository_exclusions(self) -> None:
        worktree = self.directory / "linked worktree"
        self.git(self.root, "worktree", "add", "--quiet", "--detach", str(worktree), "HEAD")
        self.assertTrue((worktree / ".git").is_file())
        exclude = project_setup.install(worktree)
        self.assertEqual(exclude.resolve(), (self.root / ".git/info/exclude").resolve())
        self.assertEqual(self.git(worktree, "check-ignore", "target/debug/probe").strip(), "target/debug/probe")

    def test_existing_lock_is_preserved_and_no_changes_are_lost(self) -> None:
        exclude = self.root / ".git/info/exclude"
        before = exclude.read_bytes()
        lock = exclude.with_name("exclude.lock")
        lock.write_bytes(b"another writer")
        with self.assertRaises(FileExistsError):
            project_setup.install(self.root)
        self.assertEqual(exclude.read_bytes(), before)
        self.assertEqual(lock.read_bytes(), b"another writer")

    def test_missing_pattern_section_fails_without_editing_exclusions(self) -> None:
        exclude = self.root / ".git/info/exclude"
        before = exclude.read_bytes()
        (self.root / ".gitignore").write_text("target/\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            project_setup.install(self.root)
        self.assertEqual(exclude.read_bytes(), before)

    def test_missing_local_exclusion_file_is_created(self) -> None:
        exclude = self.root / ".git/info/exclude"
        exclude.unlink()
        project_setup.install(self.root)
        self.assertIn(b"**/target/", exclude.read_bytes())
        self.assertFalse(exclude.with_name("exclude.lock").exists())

    @unittest.skipIf(os.name == "nt", "creating a symlink may require Windows elevation")
    def test_symlinked_exclusions_do_not_modify_an_external_file(self) -> None:
        exclude = self.root / ".git/info/exclude"
        external = self.directory / "personal-exclusions"
        external.write_bytes(b"private-data/\n")
        exclude.unlink()
        exclude.symlink_to(external)
        with self.assertRaises(ValueError):
            project_setup.install(self.root)
        self.assertEqual(external.read_bytes(), b"private-data/\n")


if __name__ == "__main__":
    unittest.main()
