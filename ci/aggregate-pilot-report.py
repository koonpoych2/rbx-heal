#!/usr/bin/env python3
"""Create a privacy-safe release quality report from public-v1 pilot JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def load(path: Path) -> dict:
    report = json.loads(path.read_text(encoding="utf-8-sig"))
    if report.get("schema_version") != 1 or report.get("suite") != "public-v1":
        raise SystemExit(f"invalid pilot report: {path.name}")
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("reports", nargs="+", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    reports = [load(path) for path in sorted(args.reports)]
    if not reports or not all(report.get("official_gate_complete") for report in reports):
        raise SystemExit("public-v1 official gate is incomplete")
    first = reports[0]
    cases = []
    for case in sorted(first.get("cases", []), key=lambda item: item["id"]):
        cases.append(
            {
                "id": case["id"],
                "repository": case["repository"],
                "commit": case["commit"],
                "license": case["license"],
                "files_scanned": case["files_scanned"],
                "findings": case["findings"],
                "parse_errors": case["parse_errors"],
                "rule_counts": case["rule_counts"],
                "duration_ms": case["duration_ms"],
                "source_unchanged": case["source_unchanged"],
                "official_gate_complete": case["official_gate_complete"],
                "expectations_passed": case["expectations_passed"],
                "tool_versions": case["tool_versions"],
                "verification": [
                    {"name": step["name"], "status": step["status"]}
                    for step in case["verification"]
                ],
            }
        )
    output = {
        "schema_version": 1,
        "product": "rbx-heal",
        "version": args.version,
        "suite": "public-v1",
        "platform_reports": len(reports),
        "cases": cases,
        "total_findings": first["total_findings"],
        "total_reviewed": first["total_reviewed"],
        "total_unreviewed": first["total_unreviewed"],
        "official_gate_complete": True,
        "source_unchanged": first["source_unchanged"],
        "expectations_passed": first["expectations_passed"],
        "action_lock": "ci/actions.lock.json",
        "rust_toolchain": "1.85.0",
    }
    args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
