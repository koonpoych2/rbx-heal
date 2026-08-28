#!/usr/bin/env python3
"""Compare the deterministic, privacy-safe fields of two SARIF logs."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"invalid SARIF {path}: {exc}") from exc
    if not isinstance(value, dict) or value.get("version") != "2.1.0":
        raise SystemExit(f"invalid SARIF version in {path}")
    return value


def deterministic(value: dict[str, Any], path: Path) -> dict[str, Any]:
    runs = value.get("runs")
    if not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], dict):
        raise SystemExit(f"SARIF must contain exactly one run: {path}")
    run = runs[0]
    tool = run.get("tool")
    driver = tool.get("driver") if isinstance(tool, dict) else None
    results = run.get("results")
    rules = driver.get("rules") if isinstance(driver, dict) else None
    if not isinstance(driver, dict) or not isinstance(results, list) or not isinstance(rules, list):
        raise SystemExit(f"SARIF has an invalid tool/results shape: {path}")
    for result in results:
        if not isinstance(result, dict):
            raise SystemExit(f"SARIF result is not an object: {path}")
        for location in result.get("locations", []):
            if not isinstance(location, dict):
                raise SystemExit(f"SARIF location is not an object: {path}")
            physical = location.get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {}) if isinstance(physical, dict) else {}
            uri = artifact.get("uri") if isinstance(artifact, dict) else None
            if isinstance(uri, str) and (
                uri.startswith(("/", "\\", "file:"))
                or re.match(r"^[A-Za-z]:[\\/]", uri)
            ):
                raise SystemExit(f"SARIF contains an absolute URI: {path}")
    return {
        "version": value["version"],
        "driver": {
            "name": driver.get("name"),
            "version": driver.get("version"),
            "rules": rules,
        },
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--windows", type=Path, required=True)
    parser.add_argument("--ubuntu", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    left = deterministic(load(args.windows), args.windows)
    right = deterministic(load(args.ubuntu), args.ubuntu)
    if left != right:
        raise SystemExit("SARIF deterministic fields differ across operating systems")
    output = {
        "schema_version": 1,
        "fields_match": True,
        "result_count": len(left["results"]),
        "rule_count": len(left["driver"]["rules"]),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
