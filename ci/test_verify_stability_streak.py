#!/usr/bin/env python3
"""Contract tests for the offline stable qualification verifier."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from datetime import date, timedelta
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "ci" / "verify-stability-streak.py"
TAG = "v0.10.0-rc.3"
COMMIT = "a" * 40


class StabilityVerifierTests(unittest.TestCase):
    def invoke(self, runs: list[dict], evidence: list[dict]) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runs_path = root / "runs.json"
            evidence_dir = root / "evidence"
            output = root / "qualification.json"
            evidence_dir.mkdir()
            runs_path.write_text(json.dumps(runs), encoding="utf-8")
            for index, record in enumerate(evidence):
                (evidence_dir / f"{index:02d}.json").write_text(
                    json.dumps(record), encoding="utf-8"
                )
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--runs",
                    str(runs_path),
                    "--evidence-dir",
                    str(evidence_dir),
                    "--candidate-tag",
                    TAG,
                    "--candidate-commit",
                    COMMIT,
                    "--required-runs",
                    "7",
                    "--output",
                    str(output),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            if result.returncode == 0:
                self.assertTrue(output.is_file())
                parsed = json.loads(output.read_text(encoding="utf-8"))
                self.assertEqual(parsed["kind"], "StableQualificationV1")
                self.assertEqual(parsed["candidate_tag"], TAG)
                self.assertEqual(len(parsed["runs"]), 7)
            return result

    def records(self, count: int = 7) -> tuple[list[dict], list[dict]]:
        runs = []
        evidence = []
        for index in range(count):
            run_id = 1000 + index
            timestamp = f"2026-08-{20 + index:02d}T03:17:00Z"
            runs.append(
                {
                    "id": run_id,
                    "event": "schedule",
                    "status": "completed",
                    "conclusion": "success",
                "run_attempt": 1,
                "created_at": timestamp,
                "html_url": f"https://github.com/example/runs/{run_id}",
                "head_sha": COMMIT,
                }
            )
            evidence.append(
                {
                    "schema_version": 1,
                    "kind": "StableQualificationRunV1",
                    "candidate_tag": TAG,
                    "candidate_commit": COMMIT,
                    "run_id": run_id,
                    "run_attempt": 1,
                    "created_at_utc": timestamp,
                    "event": "schedule",
                    "status": "passed",
                    "gates": {"quality": "passed"},
                }
            )
        return runs, evidence

    def test_seven_consecutive_days_pass(self) -> None:
        runs, evidence = self.records()
        self.assertEqual(self.invoke(runs, evidence).returncode, 0)

    def test_six_days_and_gap_fail(self) -> None:
        runs, evidence = self.records(6)
        self.assertNotEqual(self.invoke(runs, evidence).returncode, 0)
        runs, evidence = self.records()
        runs[3]["created_at"] = "2026-08-30T03:17:00Z"
        self.assertNotEqual(self.invoke(runs, evidence).returncode, 0)

    def test_rerun_and_failed_run_fail_closed(self) -> None:
        runs, evidence = self.records()
        runs[0]["run_attempt"] = 2
        self.assertNotEqual(self.invoke(runs, evidence).returncode, 0)
        runs, evidence = self.records()
        runs[0]["conclusion"] = "cancelled"
        self.assertNotEqual(self.invoke(runs, evidence).returncode, 0)

    def test_interspersed_duplicate_is_not_hidden_by_latest_slice(self) -> None:
        runs, evidence = self.records()
        runs.append(
            {
                "id": 2000,
                "event": "schedule",
                "status": "completed",
                "conclusion": "failure",
                "run_attempt": 1,
                "created_at": "2026-08-20T01:00:00Z",
            }
        )
        self.assertNotEqual(self.invoke(runs, evidence).returncode, 0)

    def test_candidate_identity_mismatch_fails_closed(self) -> None:
        runs, evidence = self.records()
        evidence[0]["candidate_commit"] = "b" * 40
        self.assertNotEqual(self.invoke(runs, evidence).returncode, 0)

    def test_run_metadata_commit_mismatch_fails_closed(self) -> None:
        runs, evidence = self.records()
        runs[0]["head_sha"] = "b" * 40
        self.assertNotEqual(self.invoke(runs, evidence).returncode, 0)

    def test_missing_artifact_does_not_replace_existing_output(self) -> None:
        runs, evidence = self.records()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runs_path = root / "runs.json"
            evidence_dir = root / "evidence"
            output = root / "qualification.json"
            evidence_dir.mkdir()
            runs_path.write_text(json.dumps(runs), encoding="utf-8")
            for index, record in enumerate(evidence[:-1]):
                (evidence_dir / f"{index:02d}.json").write_text(
                    json.dumps(record), encoding="utf-8"
                )
            output.write_text("keep this proof", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--runs",
                    str(runs_path),
                    "--evidence-dir",
                    str(evidence_dir),
                    "--candidate-tag",
                    TAG,
                    "--candidate-commit",
                    COMMIT,
                    "--required-runs",
                    "7",
                    "--output",
                    str(output),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.read_text(encoding="utf-8"), "keep this proof")

    def test_unknown_evidence_field_fails_closed(self) -> None:
        runs, evidence = self.records()
        evidence[0]["private_source_excerpt"] = "must never be accepted"
        self.assertNotEqual(self.invoke(runs, evidence).returncode, 0)

    def test_input_order_does_not_change_output(self) -> None:
        runs, evidence = self.records()
        first = self.invoke(runs, evidence)
        self.assertEqual(first.returncode, 0)
        runs.reverse()
        evidence.reverse()
        second = self.invoke(runs, evidence)
        self.assertEqual(second.returncode, 0)

    def test_older_history_does_not_break_latest_streak(self) -> None:
        runs, evidence = self.records()
        runs.insert(
            0,
            {
                "id": 999,
                "event": "schedule",
                "status": "completed",
                "conclusion": "success",
                "run_attempt": 1,
                "created_at": "2026-08-19T03:17:00Z",
            },
        )
        evidence.insert(
            0,
            {
                "schema_version": 1,
                "kind": "StableQualificationRunV1",
                "candidate_tag": TAG,
                "candidate_commit": COMMIT,
                "run_id": 999,
                "run_attempt": 1,
                "created_at_utc": "2026-08-19T03:17:00Z",
                "event": "schedule",
                "status": "passed",
                "gates": {"quality": "passed"},
            },
        )
        self.assertEqual(self.invoke(runs, evidence).returncode, 0)


if __name__ == "__main__":
    unittest.main()
