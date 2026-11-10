#!/usr/bin/env python3
"""Warn about issue records exceeding the 500-word documentation soft cap."""

from __future__ import annotations

import argparse
from pathlib import Path


SOFT_CAP = 500
ROOT = Path(__file__).resolve().parents[1]


def word_count(text: str) -> int:
    return len(text.split())


def oversized(paths: list[Path]) -> list[tuple[Path, int]]:
    return [(path, count) for path in paths if (count := word_count(path.read_text(encoding="utf-8"))) > SOFT_CAP]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path)
    arguments = parser.parse_args()
    paths = arguments.paths or sorted((ROOT / "docs/issues").glob("DS-*.md"))
    findings = oversized(paths)
    for path, count in findings:
        print(f"WARNING: {path}: {count} words (soft cap {SOFT_CAP}); link detailed evidence")
    print(f"Issue size check: {len(paths)} records, {len(findings)} soft-cap warnings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
