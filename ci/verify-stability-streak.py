#!/usr/bin/env python3
"""Fail-closed verifier for the 0.10.0 stable qualification streak.

The input is deliberately split into GitHub run metadata and the
metadata-only StableQualificationRunV1 artifacts produced by scheduled CI.
This tool is offline: it never calls GitHub and never reads source files.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, NoReturn


SCHEMA_VERSION = 1
RUN_KIND = "StableQualificationRunV1"
OUTPUT_KIND = "StableQualificationV1"
TAG_RE = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+-rc\.[0-9]+$")
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
RUN_KEYS = {
    "schema_version",
    "kind",
    "candidate_tag",
    "candidate_commit",
    "run_id",
    "run_attempt",
    "created_at_utc",
    "event",
    "status",
    "gates",
}
REQUIRED_RUN_KEYS = {
    "schema_version",
    "kind",
    "candidate_tag",
    "candidate_commit",
    "run_id",
    "run_attempt",
    "created_at_utc",
    "event",
    "status",
    "gates",
}


class ValidationError(ValueError):
    """An input violated the qualification contract."""


def fail(message: str) -> "NoReturn":
    raise ValidationError(message)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"invalid JSON in {path}: {exc}")


def parse_utc(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        fail(f"{field} must be an RFC3339 UTC timestamp")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        fail(f"{field} is not an RFC3339 timestamp")
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        fail(f"{field} must use UTC")
    return parsed.astimezone(timezone.utc)


def validate_identity(tag: Any, commit: Any) -> tuple[str, str]:
    if not isinstance(tag, str) or not TAG_RE.fullmatch(tag):
        fail("candidate_tag is not a prerelease tag")
    if not isinstance(commit, str) or not SHA_RE.fullmatch(commit):
        fail("candidate_commit must be a 40-character hexadecimal SHA")
    return tag, commit.lower()


def normalize_run_id(value: Any) -> int:
    if isinstance(value, bool):
        fail("run_id must be a positive integer")
    if isinstance(value, int):
        run_id = value
    elif isinstance(value, str) and value.strip().isdigit():
        run_id = int(value.strip())
    else:
        fail("run_id must be a positive integer")
    if run_id <= 0:
        fail("run_id must be a positive integer")
    if isinstance(value, str) and str(run_id) != value.strip():
        # String IDs are accepted only when they contain their canonical
        # decimal representation. This prevents two records for one run.
        fail("run_id must be a positive integer")
    return run_id


def validate_evidence(value: Any, path: Path, tag: str, commit: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{path}: evidence must be an object")
    unknown = set(value) - RUN_KEYS
    missing = REQUIRED_RUN_KEYS - set(value)
    if unknown:
        fail(f"{path}: unknown evidence fields: {', '.join(sorted(unknown))}")
    if missing:
        fail(f"{path}: missing evidence fields: {', '.join(sorted(missing))}")
    if value["schema_version"] != SCHEMA_VERSION or value["kind"] != RUN_KIND:
        fail(f"{path}: unsupported evidence schema or kind")
    evidence_tag, evidence_commit = validate_identity(
        value["candidate_tag"], value["candidate_commit"]
    )
    if evidence_tag != tag or evidence_commit != commit:
        fail(f"{path}: candidate identity mismatch")
    run_id = normalize_run_id(value["run_id"])
    attempt = value["run_attempt"]
    if isinstance(attempt, bool) or not isinstance(attempt, int) or attempt != 1:
        fail(f"{path}: run_attempt must be 1")
    if value["event"] != "schedule" or value["status"] != "passed":
        fail(f"{path}: evidence is not a successful scheduled run")
    if not isinstance(value["gates"], dict) or not value["gates"]:
        fail(f"{path}: gates must be a non-empty object")
    if any(not isinstance(name, str) or not name for name in value["gates"]):
        fail(f"{path}: gate names must be non-empty strings")
    if any(status != "passed" for status in value["gates"].values()):
        fail(f"{path}: every gate must be passed")
    timestamp = parse_utc(value["created_at_utc"], f"{path}: created_at_utc")
    result = {
        "schema_version": 1,
        "kind": RUN_KIND,
        "candidate_tag": evidence_tag,
        "candidate_commit": evidence_commit,
        "run_id": run_id,
        "run_attempt": 1,
        "created_at_utc": timestamp.isoformat().replace("+00:00", "Z"),
        "event": "schedule",
        "status": "passed",
        "gates": {name: "passed" for name in sorted(value["gates"])},
    }
    result["_date"] = timestamp.date()
    return result


def run_records(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        # GitHub's API uses ``workflow_runs`` while local fixtures commonly
        # use ``runs``.  Treat an explicitly null first key as absent rather
        # than silently discarding a valid fallback array.
        container = value
        value = container.get("workflow_runs")
        if value is None:
            value = container.get("runs")
    if not isinstance(value, list) or not value:
        fail("--runs must contain a non-empty array or workflow_runs array")
    records: list[dict[str, Any]] = []
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            fail(f"run metadata entry {index} is not an object")
        event = raw.get("event")
        if event != "schedule":
            continue
        status = raw.get("status")
        conclusion = raw.get("conclusion")
        if "run_attempt" in raw:
            attempt = raw["run_attempt"]
        elif "attempt" in raw:
            attempt = raw["attempt"]
        else:
            fail(f"scheduled run {raw.get('id', index)} is missing its attempt")
        run_id_value = raw.get("id") if raw.get("id") is not None else raw.get("databaseId")
        run_id = normalize_run_id(run_id_value)
        if "head_sha" in raw:
            head_sha_value = raw["head_sha"]
        else:
            head_sha_value = raw.get("headSha")
        head_sha = None
        if head_sha_value is not None:
            if not isinstance(head_sha_value, str) or not SHA_RE.fullmatch(head_sha_value):
                fail(f"run {run_id}: head_sha must be a 40-character hexadecimal SHA")
            head_sha = head_sha_value.lower()
        timestamp_value = (
            raw.get("created_at")
            or raw.get("createdAt")
            or raw.get("created_at_utc")
        )
        timestamp = parse_utc(timestamp_value, f"run {run_id}: created_at")
        records.append(
            {
                "run_id": run_id,
                "run_attempt": 1,
                "created_at_utc": timestamp.isoformat().replace("+00:00", "Z"),
                "_date": timestamp.date(),
                "_valid": status == "completed" and conclusion == "success" and attempt == 1,
                "_head_sha": head_sha,
                "_status": status,
                "_conclusion": conclusion,
                "_attempt": attempt,
            }
        )
    if not records:
        fail("no scheduled runs were supplied")
    return records


def load_evidence(directory: Path, tag: str, commit: str) -> dict[int, dict[str, Any]]:
    if not directory.is_dir():
        fail(f"evidence directory does not exist: {directory}")
    paths = sorted(path for path in directory.rglob("*.json") if path.is_file())
    if not paths:
        fail("no qualification evidence artifacts were supplied")
    evidence: dict[int, dict[str, Any]] = {}
    for path in paths:
        raw = read_json(path)
        if isinstance(raw, list):
            values = raw
        elif isinstance(raw, dict) and isinstance(raw.get("runs"), list):
            unknown = set(raw) - {"runs"}
            if unknown:
                fail(
                    f"{path}: unknown aggregate evidence fields: {', '.join(sorted(unknown))}"
                )
            values = raw["runs"]
        else:
            values = [raw]
        for index, value in enumerate(values):
            record_path = path if len(values) == 1 else Path(f"{path}#{index}")
            record = validate_evidence(value, record_path, tag, commit)
            run_id = record["run_id"]
            if run_id in evidence:
                fail(f"duplicate evidence for run {run_id}")
            evidence[run_id] = record
    return evidence


def verify(args: argparse.Namespace) -> dict[str, Any]:
    tag, commit = validate_identity(args.candidate_tag, args.candidate_commit)
    if not isinstance(args.required_runs, int) or args.required_runs < 1:
        fail("required-runs must be positive")
    runs = run_records(read_json(args.runs))
    evidence = load_evidence(args.evidence_dir, tag, commit)
    by_id = {record["run_id"]: record for record in runs}
    if len(by_id) != len(runs):
        fail("duplicate scheduled run IDs")
    runs.sort(key=lambda item: (item["_date"], item["created_at_utc"], item["run_id"]), reverse=True)
    selected = runs[: args.required_runs]
    if len(selected) != args.required_runs:
        fail(
            f"expected exactly {args.required_runs} successful scheduled runs, got {len(selected)}"
        )
    for item in selected:
        if not item["_valid"]:
            fail(
                f"scheduled run {item['run_id']} is not a successful first-attempt run"
            )
        if item["_head_sha"] is not None and item["_head_sha"] != commit:
            fail(f"scheduled run {item['run_id']} does not point at the candidate commit")
    # The selected records must be the complete history for their UTC date
    # window.  Otherwise an older duplicate (for example a failed rerun on a
    # day whose successful record sorts first) could be hidden by the
    # ``latest N`` slice while the reported streak still appeared green.
    selected_dates = [item["_date"] for item in selected]
    if selected_dates:
        first_date = min(selected_dates)
        last_date = max(selected_dates)
        window = [
            item for item in runs if first_date <= item["_date"] <= last_date
        ]
        if len(window) != args.required_runs:
            fail(
                "scheduled run window contains duplicate or interspersed records"
            )
        if any(not item["_valid"] for item in window):
            fail("scheduled run window contains a failed, cancelled, or rerun record")
        if any(
            item["_head_sha"] is not None and item["_head_sha"] != commit
            for item in window
        ):
            fail("scheduled run window contains a different candidate commit")
    selected_ids = {item["run_id"] for item in selected}
    missing = sorted(selected_ids - set(evidence))
    if missing:
        fail(f"missing evidence for scheduled run(s): {', '.join(map(str, missing))}")
    extra = sorted(set(evidence) - set(by_id))
    if extra:
        fail(f"evidence references unknown run(s): {', '.join(map(str, extra))}")
    joined = []
    for run_id in selected_ids:
        metadata = by_id[run_id]
        item = evidence[run_id]
        if item["_date"] != metadata["_date"]:
            fail(f"run {run_id}: metadata/evidence UTC date mismatch")
        if item["run_attempt"] != metadata["run_attempt"]:
            fail(f"run {run_id}: attempt mismatch")
        joined.append(item)
    joined.sort(key=lambda item: (item["_date"], item["run_id"]))
    dates = [item["_date"] for item in joined]
    if len(set(dates)) != len(dates):
        fail("scheduled qualification dates must be unique")
    for previous, current in zip(dates, dates[1:]):
        if current != previous + timedelta(days=1):
            fail("scheduled qualification dates must be consecutive UTC days")
    # A record for every scheduled run in the supplied window is required;
    # callers cannot hide a failed/cancelled run between two green days.
    output_runs = []
    for item in joined:
        row = {key: value for key, value in item.items() if not key.startswith("_")}
        output_runs.append(row)
    return {
        "schema_version": 1,
        "kind": OUTPUT_KIND,
        "candidate_tag": tag,
        "candidate_commit": commit,
        "required_scheduled_runs": args.required_runs,
        "qualified": True,
        "status": "qualified",
        "utc_dates": [item.isoformat() for item in dates],
        "runs": output_runs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=Path, required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    parser.add_argument("--candidate-tag", required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument(
        "--required-runs",
        "--required-scheduled-runs",
        dest="required_runs",
        type=int,
        default=7,
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(args)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.output.with_name(f".{args.output.name}.tmp")
        temporary.write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        temporary.replace(args.output)
        return 0
    except ValidationError as exc:
        print(f"stability verification failed: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"stability verification failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
