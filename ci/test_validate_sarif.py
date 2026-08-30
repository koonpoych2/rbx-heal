#!/usr/bin/env python3
"""Tests for the SARIF upload/privacy validator."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "ci" / "validate-sarif.py"


def clean_document() -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "rbx-heal",
                        "version": "0.10.0-rc.3",
                        "rules": [],
                    }
                },
                "results": [],
            }
        ],
    }


class SarifValidatorTests(unittest.TestCase):
    def invoke(self, document: dict, expected: int | None = None) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.sarif"
            path.write_text(json.dumps(document), encoding="utf-8")
            command = [sys.executable, str(SCRIPT), str(path)]
            if expected is not None:
                command.extend(["--expect-results", str(expected)])
            return subprocess.run(command, text=True, capture_output=True, check=False)

    def test_clean_upload_document_passes(self) -> None:
        self.assertEqual(self.invoke(clean_document(), expected=0).returncode, 0)

    def test_source_snippet_and_absolute_uri_fail_closed(self) -> None:
        document = clean_document()
        document["runs"][0]["results"] = [
            {
                "ruleId": "RBX-TASK-001",
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "C:/checkout/src/file.luau"}
                        }
                    }
                ],
                "properties": {"snippet": {"text": "wait(0)"}},
            }
        ]
        self.assertNotEqual(self.invoke(document).returncode, 0)

    def test_result_count_is_enforced(self) -> None:
        document = clean_document()
        document["runs"][0]["results"] = [{}]
        self.assertNotEqual(self.invoke(document, expected=0).returncode, 0)


if __name__ == "__main__":
    unittest.main()
