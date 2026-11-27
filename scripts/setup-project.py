#!/usr/bin/env python3
"""Install branch-independent local snapshot exclusions from the project ignore file."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


BEGIN = "# BEGIN DepScan build artifacts"
END = "# END DepScan build artifacts"


def build_patterns(root: Path) -> list[bytes]:
    lines = (root / ".gitignore").read_text(encoding="utf-8").splitlines()
    if lines.count(BEGIN) != 1 or lines.count(END) != 1:
        raise ValueError(".gitignore needs one marked DepScan build artifact section")
    start, end = lines.index(BEGIN), lines.index(END)
    patterns = [
        line.encode("utf-8") for line in lines[start + 1:end]
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if end <= start or not patterns:
        raise ValueError(".gitignore build artifact section must contain patterns")
    return patterns


def git(root: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", "--no-optional-locks", "-C", str(root), *arguments],
        text=True, stderr=subprocess.PIPE,
    ).strip()


def install(root: Path) -> Path:
    root = root.resolve()
    patterns = build_patterns(root)
    if Path(git(root, "rev-parse", "--show-toplevel")).resolve() != root:
        raise ValueError("project setup must belong to the repository root")
    common = Path(git(root, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    exclude = common / "info/exclude"
    if exclude.is_symlink() or exclude.parent.is_symlink():
        raise ValueError("local Git exclusion file and its parent must not be symlinks")
    exclude.parent.mkdir(parents=True, exist_ok=True)
    lock = exclude.with_name(exclude.name + ".lock")
    stream = lock.open("xb")
    try:
        with stream:
            original = exclude.read_bytes() if exclude.exists() else b""
            existing = set(original.splitlines())
            missing = [pattern for pattern in patterns if pattern not in existing]
            if not missing:
                return exclude
            separator = b"\n" if original and not original.endswith(b"\n") else b""
            stream.write(
                original + separator + b"\n# DepScan build artifact snapshot exclusions\n"
                + b"\n".join(missing) + b"\n"
            )
            mode = exclude.stat().st_mode & 0o777 if exclude.exists() else 0o644
            os.chmod(lock, mode)
        os.replace(lock, exclude)
    finally:
        lock.unlink(missing_ok=True)
    return exclude


def main() -> int:
    try:
        install(Path(__file__).resolve().parents[1])
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Project setup failed: {error}", file=sys.stderr)
        return 1
    print("Project build artifact snapshot exclusions ready.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
