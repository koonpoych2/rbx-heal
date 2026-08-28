#!/usr/bin/env python3
"""Validate the privacy and shape contract for an rbx-heal SARIF log.

The upload job intentionally sends a clean smoke report.  This validator is
kept dependency-free so it can run on both hosted runners before the SARIF
upload action is invoked.  It rejects source-bearing SARIF fields and paths
that could identify a runner or local checkout.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, NoReturn


ABSOLUTE_URI = re.compile(
    r"^(?:file:|[A-Za-z]:[\\/]|[\\/]{2}|[\\/])", re.IGNORECASE
)
ABSOLUTE_PATH_TEXT = re.compile(
    r"(?:^|[\s(])(?:[A-Za-z]:[\\/]|[\\/]{2}|[\\/](?:home|Users|runner|tmp|var)/|file:)",
    re.IGNORECASE,
)
SOURCE_KEYS = {
    "artifactContent",
    "snippet",
    "sourceContent",
    "sourceText",
    "sourceExcerpt",
    "source_excerpt",
    "source_excerpt_text",
    "source_content",
    "source_text",
    "contents",
    "source",
}


class SarifError(ValueError):
    """A SARIF document violated the upload contract."""


def fail(message: str) -> NoReturn:
    raise SarifError(message)


def read(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"invalid SARIF {path}: {exc}")
    if not isinstance(value, dict):
        fail("SARIF root must be an object")
    return value


def walk(value: Any, location: str = "root") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in SOURCE_KEYS:
                fail(f"source-bearing SARIF field is not allowed: {location}.{key}")
            child_location = f"{location}.{key}"
            if key == "uri" and isinstance(child, str) and ABSOLUTE_URI.match(child):
                fail(f"absolute SARIF URI is not allowed: {child_location}")
            walk(child, child_location)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            walk(child, f"{location}[{index}]")
    elif isinstance(value, str):
        if "GITHUB_WORKSPACE" in value or ABSOLUTE_PATH_TEXT.search(value):
            fail(f"absolute path text is not allowed: {location}")


def validate(document: dict[str, Any], expected_results: int | None) -> None:
    if document.get("version") != "2.1.0":
        fail("SARIF version must be 2.1.0")
    runs = document.get("runs")
    if not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], dict):
        fail("SARIF must contain exactly one run")
    run = runs[0]
    tool = run.get("tool")
    driver = tool.get("driver") if isinstance(tool, dict) else None
    if not isinstance(driver, dict):
        fail("SARIF run is missing tool.driver")
    rules = driver.get("rules")
    results = run.get("results")
    if not isinstance(rules, list) or not isinstance(results, list):
        fail("SARIF tool.driver.rules and run.results must be arrays")
    if expected_results is not None and len(results) != expected_results:
        fail(f"expected {expected_results} SARIF result(s), got {len(results)}")
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict) or not isinstance(rule.get("id"), str):
            fail(f"SARIF rule {index} is malformed")
    walk(document)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("sarif", type=Path)
    parser.add_argument("--expect-results", type=int)
    args = parser.parse_args()
    try:
        if args.expect_results is not None and args.expect_results < 0:
            fail("--expect-results must be non-negative")
        validate(read(args.sarif), args.expect_results)
    except SarifError as exc:
        print(f"SARIF validation failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
