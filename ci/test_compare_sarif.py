#!/usr/bin/env python3
"""Small contract test for cross-platform SARIF comparison."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "ci" / "compare-sarif.py"


def log() -> dict:
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {"name": "rbx-heal", "version": "test", "rules": []}
                },
                "results": [],
            }
        ],
    }


class SarifCompareTests(unittest.TestCase):
    def test_clean_logs_compare_deterministically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            windows = root / "windows.sarif"
            ubuntu = root / "ubuntu.sarif"
            output = root / "compare.json"
            windows.write_text(json.dumps(log(), indent=2), encoding="utf-8")
            ubuntu.write_text(json.dumps(log(), separators=(",", ":")), encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--windows",
                    str(windows),
                    "--ubuntu",
                    str(ubuntu),
                    "--output",
                    str(output),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(output.read_text())["result_count"], 0)


if __name__ == "__main__":
    unittest.main()
