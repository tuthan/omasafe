#!/usr/bin/env python3
"""Append current per-projection review-compatibility declarations.

The caller must supply the review metadata. This tool computes identities and
affected rows from the four parser builds; it never invents a maintainer
approval or rewrites existing declaration history.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
from copy import deepcopy
from datetime import date
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DECLARATION_PATH = ROOT / "crates" / "omasafe-analyzer" / "review-compatibility.json"
CHECKER_PATH = ROOT / "scripts" / "check-analysis-semantics.py"
SPEC = importlib.util.spec_from_file_location("check_analysis_semantics", CHECKER_PATH)
CHECKER = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(CHECKER)

PROJECTIONS = {
    "qml-python": ("qml-parser", "python-parser"),
    "qml-only": ("qml-parser",),
    "python-only": ("python-parser",),
    "lexical-only": (),
}


def current_result(features):
    command = ["cargo", "run", "--quiet", "-p", "omasafe-cli", "--no-default-features"]
    if features:
        command.extend(["--features", ",".join(features)])
    command.extend(["--", "rules", "list", "--format", "json"])
    completed = subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
    return json.loads(completed.stdout)["result"]


def build_declaration(result, projection, baseline, reviewer, review_date, rationale):
    policy = result["policy_identity"]
    semantics = result["rule_semantics"]
    digests = {rule_id: row["digest"] for rule_id, row in semantics.items()}
    revisions = {
        rule_id: row["identity"]["review_revision"] for rule_id, row in semantics.items()
    }
    changed = sorted(
        rule_id
        for rule_id in digests
        if baseline is None
        or digests[rule_id] != baseline["rule_semantic_digests"].get(rule_id)
        or revisions[rule_id] != baseline["rule_review_revisions"].get(rule_id)
    )
    declaration = {
        "affected_rule_ids": changed,
        "baseline_declaration_id": baseline["id"] if baseline else None,
        "classification": "semantic-change" if changed or baseline is None else "review-compatible",
        "date": review_date,
        "detector_logic_fingerprint": policy["detector_logic_fingerprint"],
        "feature_projection": projection,
        "id": "",
        "rationale": rationale,
        "reviewer": reviewer,
        "rule_review_revisions": revisions,
        "rule_semantic_digests": digests,
        "semantic_catalog_digest": policy["rule_semantics_catalog_digest"],
    }
    declaration["id"] = CHECKER.declaration_digest(declaration)
    return declaration


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reviewer", required=True)
    parser.add_argument("--date", required=True, help="ISO review date")
    parser.add_argument("--rationale", required=True)
    args = parser.parse_args()
    if not args.reviewer.strip() or not args.rationale.strip():
        parser.error("--reviewer and --rationale must be non-empty")
    try:
        date.fromisoformat(args.date)
    except ValueError as error:
        parser.error(f"--date must be ISO YYYY-MM-DD: {error}")

    document = json.loads(DECLARATION_PATH.read_text(encoding="utf-8"))
    declarations = document["declarations"]
    latest = {}
    for declaration in declarations:
        latest[declaration["feature_projection"]] = declaration

    appended = []
    for projection, features in PROJECTIONS.items():
        result = current_result(features)
        declaration = build_declaration(
            result,
            projection,
            latest.get(projection),
            args.reviewer,
            args.date,
            args.rationale,
        )
        if not any(item.get("id") == declaration["id"] for item in declarations):
            declarations.append(declaration)
            appended.append(declaration)
        latest[projection] = declaration

    rule_ids = set(appended[0]["rule_semantic_digests"]) if appended else set(
        declarations[0]["rule_semantic_digests"]
    )
    validation_error = CHECKER.validate_document(document, rule_ids)
    if validation_error:
        raise SystemExit(f"refreshed declarations failed validation: {validation_error}")
    DECLARATION_PATH.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(f"appended {len(appended)} declaration(s) for {len(PROJECTIONS)} projections")
    for declaration in appended:
        print(f"{declaration['feature_projection']}: {declaration['id']}")


if __name__ == "__main__":
    main()
