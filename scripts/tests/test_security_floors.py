from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class SecurityFloorTests(unittest.TestCase):
    def test_tls_and_runtime_floors_reach_production_consumers(self) -> None:
        manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
        provider = (ROOT / "crates/depscan-providers/Cargo.toml").read_text(encoding="utf-8")
        production = provider.split("[dependencies]", 1)[1].split("[dev-dependencies]", 1)[0]
        for name, minimum in {"rustls": (0, 23, 46), "webpki": (0, 103, 16), "tokio": (1, 54, 1)}.items():
            with self.subTest(dependency=name):
                match = re.search(rf'^{name}\s*=\s*\{{[^\n]*version\s*=\s*"(\d+)\.(\d+)\.(\d+)"', manifest, re.MULTILINE)
                self.assertIsNotNone(match)
                assert match is not None
                self.assertGreaterEqual(tuple(map(int, match.groups())), minimum)
                self.assertRegex(production, rf'(?m)^{name}\.workspace\s*=\s*true$')


if __name__ == "__main__":
    unittest.main()
