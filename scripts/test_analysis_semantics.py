#!/usr/bin/env python3
"""Focused self-tests for review-compatibility declaration validation."""

import importlib.util
import json
import sys
from copy import deepcopy
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "check-analysis-semantics.py"
SPEC = importlib.util.spec_from_file_location("check_analysis_semantics", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


def check(name, condition):
    if not condition:
        raise AssertionError(name)
    print(f"ok   {name}")


def relabel(declaration):
    declaration["id"] = MODULE.declaration_digest(declaration)
    return declaration


def main():
    path = ROOT / "crates" / "omasafe-analyzer" / "review-compatibility.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    rule_ids = set(document["declarations"][0]["rule_semantic_digests"])
    check("checked-in declarations have valid shape", MODULE.validate_document(document, rule_ids) is None)

    bad_id = deepcopy(document)
    bad_id["declarations"][0]["id"] = "0" * 64
    check("tampered declaration ID is rejected", MODULE.validate_document(bad_id, rule_ids) is not None)

    bad_map = deepcopy(document)
    bad_map["declarations"][0]["rule_semantic_digests"]["oma.retired.rule"] = "0" * 64
    bad_map["declarations"][0]["rule_review_revisions"]["oma.retired.rule"] = 1
    relabel(bad_map["declarations"][0])
    check("unknown map rows are rejected", MODULE.validate_document(bad_map, rule_ids) is not None)

    bad_lineage = deepcopy(document)
    bad_lineage["declarations"][0]["baseline_declaration_id"] = "missing"
    relabel(bad_lineage["declarations"][0])
    check("unknown baseline is rejected", MODULE.validate_document(bad_lineage, rule_ids) is not None)

    baseline = document["declarations"][0]
    affected = next(iter(rule_ids))
    missing_bump = deepcopy(baseline)
    missing_bump["baseline_declaration_id"] = baseline["id"]
    missing_bump["classification"] = "semantic-change"
    missing_bump["affected_rule_ids"] = [affected]
    missing_bump["rule_semantic_digests"][affected] = "f" * 64
    missing_bump["semantic_catalog_digest"] = MODULE.semantic_catalog_digest(missing_bump["rule_semantic_digests"])
    relabel(missing_bump)
    no_bump = deepcopy(document)
    no_bump["declarations"].append(missing_bump)
    check("affected semantic row needs a revision bump", MODULE.validate_document(no_bump, rule_ids) is not None)

    changed = deepcopy(baseline)
    changed["baseline_declaration_id"] = baseline["id"]
    changed["classification"] = "semantic-change"
    changed["affected_rule_ids"] = [affected]
    changed["rule_semantic_digests"][affected] = "f" * 64
    changed["rule_review_revisions"][affected] += 1
    changed["semantic_catalog_digest"] = MODULE.semantic_catalog_digest(changed["rule_semantic_digests"])
    relabel(changed)
    valid_change = deepcopy(document)
    valid_change["declarations"].append(changed)
    check("changed and unaffected rows are compared independently", MODULE.validate_document(valid_change, rule_ids) is None)

    print("all analysis semantic self-tests passed")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, json.JSONDecodeError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        raise SystemExit(1)
