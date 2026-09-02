#!/usr/bin/env python3
"""Measure H7 detection rate over the checked-in adversarial fixtures.

The fixture suite is an independently labelled ground-truth set: positive
cases name rules that must be emitted, while negative cases name rules that
must not be emitted.  This is a detection-rate canary, not ecosystem recall;
the real-plugin precision measurement remains in ``run-corpus.py`` and its
human disposition ledger.

Usage:
  scripts/measure-ground-truth.py [--manifest PATH] [--binary PATH]
                                  [--output PATH]
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from bounded_process import run_bounded  # noqa: E402


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = ROOT / "fixtures/corpus/expectations/ground-truth.json"
DEFAULT_BINARY = ROOT / "target/debug/omasafe-cli"


def scan(binary, fixture_path):
    with tempfile.TemporaryDirectory(prefix="omasafe-ground-truth-xdg-") as xdg:
        environment = {
            **os.environ,
            "HOME": xdg,
            "XDG_CONFIG_HOME": f"{xdg}/config",
            "XDG_STATE_HOME": f"{xdg}/state",
            "XDG_CACHE_HOME": f"{xdg}/cache",
        }
        result = run_bounded(
            [str(binary), "scan-plugin", "--path", str(fixture_path), "--format", "json"],
            env=environment,
            timeout=120,
        )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(stderr[:400] or f"exit {result.returncode}")
    document = json.loads(result.stdout.decode("utf-8", errors="replace"))
    findings = document["result"]["analysis"].get("findings", [])
    return sorted({finding["rule_id"] for finding in findings})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--binary", default=str(DEFAULT_BINARY))
    parser.add_argument("--output")
    arguments = parser.parse_args()

    manifest_path = Path(arguments.manifest).resolve()
    binary = Path(arguments.binary).resolve()
    if not binary.exists():
        subprocess.run(
            ["cargo", "build", "--quiet", "-p", "omasafe-cli", "--features", "qml-parser"],
            cwd=ROOT,
            check=True,
        )
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = json.load(handle)
    if manifest.get("schemaVersion") != 1 or not isinstance(manifest.get("fixtures"), list):
        raise SystemExit("ground-truth manifest must have schemaVersion 1 and a fixtures list")

    per_rule = {}
    fixture_results = []
    errors = []
    for case in manifest["fixtures"]:
        case_id = case["id"]
        fixture_path = (ROOT / case["path"]).resolve()
        expected = sorted(set(case.get("expectedRules", [])))
        forbidden = sorted(set(case.get("forbiddenRules", [])))
        try:
            detected = scan(binary, fixture_path)
            missing = sorted(set(expected) - set(detected))
            forbidden_hits = sorted(set(forbidden) & set(detected))
        except (OSError, RuntimeError, json.JSONDecodeError, KeyError) as error:
            detected, missing, forbidden_hits = [], expected, forbidden
            errors.append({"id": case_id, "error": str(error)[:400]})
        fixture_results.append(
            {
                "id": case_id,
                "path": case["path"],
                "expectedRules": expected,
                "detectedRules": detected,
                "missingRules": missing,
                "forbiddenHits": forbidden_hits,
                "passed": not missing and not forbidden_hits,
            }
        )
        for rule_id in expected:
            stats = per_rule.setdefault(
                rule_id,
                {"expected": 0, "detected": 0, "missed": 0, "negativeCases": 0, "negativeViolations": 0},
            )
            stats["expected"] += 1
            if rule_id in detected:
                stats["detected"] += 1
            else:
                stats["missed"] += 1
        for rule_id in forbidden:
            stats = per_rule.setdefault(
                rule_id,
                {"expected": 0, "detected": 0, "missed": 0, "negativeCases": 0, "negativeViolations": 0},
            )
            stats["negativeCases"] += 1
            if rule_id in detected:
                stats["negativeViolations"] += 1

    for stats in per_rule.values():
        stats["detectionRate"] = (
            stats["detected"] / stats["expected"] if stats["expected"] else None
        )
    failed = [case["id"] for case in fixture_results if not case["passed"]]
    report = {
        "reportVersion": 1,
        "suite": "h7-ground-truth",
        "manifest": str(manifest_path.relative_to(ROOT))
        if manifest_path.is_relative_to(ROOT)
        else str(manifest_path),
        "fixtures": fixture_results,
        "perRule": dict(sorted(per_rule.items())),
        "failedFixtures": failed,
        "errors": errors,
        "passed": not failed and not errors,
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        Path(arguments.output).write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
