#!/usr/bin/env python3
"""Validate the checked-in v0.2.5 review-compatibility declarations."""

from __future__ import annotations

import json
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path


SCHEMA = "omasafe.review-compatibility.v1"
PROJECTIONS = {"qml-python", "qml-only", "python-only", "lexical-only"}
HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def error(message):
    """Return a stable validation error instead of silently accepting a row."""
    return message


def declaration_digest(declaration):
    canonical = dict(declaration)
    canonical.pop("id", None)
    material = ("omasafe:review-compatibility:v1\0" + canonical_json(canonical)).encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def _valid_rule_maps(declaration, rule_ids):
    digests = declaration.get("rule_semantic_digests")
    revisions = declaration.get("rule_review_revisions")
    if not isinstance(digests, dict) or not isinstance(revisions, dict):
        return error("semantic and revision maps must be objects")
    if set(digests) != set(revisions):
        return error("semantic and revision maps must have identical keys")
    if rule_ids is not None and set(digests) != set(rule_ids):
        return error("semantic and revision maps must cover the current rule catalog")
    for rule_id, digest in digests.items():
        if not isinstance(rule_id, str) or not rule_id.startswith("oma."):
            return error(f"invalid rule id in semantic map: {rule_id!r}")
        if not isinstance(digest, str) or not HEX_DIGEST.fullmatch(digest):
            return error(f"invalid semantic digest for {rule_id}")
        revision = revisions[rule_id]
        if type(revision) is not int or revision < 1:
            return error(f"invalid review revision for {rule_id}")
    if not digests:
        return error("semantic maps cannot be empty")
    if declaration.get("semantic_catalog_digest") != semantic_catalog_digest(digests):
        return error("semantic catalog digest does not match its rule map")
    return None


def validate_document(document, rule_ids=None):
    """Validate declaration shape, canonical IDs, lineage, and row changes.

    ``rule_ids`` is supplied from the current CLI catalog in the release gate.
    Keeping it optional makes this validator useful in isolated unit tests while
    still allowing the gate to reject retired/unknown rows in stored history.
    """
    if not isinstance(document, dict) or document.get("schema") != SCHEMA:
        return error("unsupported semantic declaration schema")
    declarations = document.get("declarations")
    if not isinstance(declarations, list) or not declarations:
        return error("semantic declarations are empty")

    by_id = {}
    for declaration in declarations:
        if not isinstance(declaration, dict):
            return error("semantic declaration is not an object")
        identifier = declaration.get("id")
        if not isinstance(identifier, str) or not HEX_DIGEST.fullmatch(identifier):
            return error("semantic declaration IDs must be lowercase SHA-256 digests")
        if identifier in by_id:
            return error(f"duplicate semantic declaration ID: {identifier}")
        by_id[identifier] = declaration
        if declaration_digest(declaration) != identifier:
            return error(f"{identifier} is not its canonical declaration digest")
        if declaration.get("feature_projection") not in PROJECTIONS:
            return error(f"invalid feature projection for {identifier}")
        if declaration.get("classification") not in {"semantic-change", "review-compatible"}:
            return error(f"invalid classification for {identifier}")
        for key in (
            "feature_projection",
            "affected_rule_ids",
            "rule_semantic_digests",
            "rule_review_revisions",
            "reviewer",
            "date",
            "rationale",
        ):
            if key not in declaration:
                return error(f"{identifier} is missing {key}")
        for key in ("detector_logic_fingerprint", "semantic_catalog_digest"):
            if not isinstance(declaration.get(key), str) or not HEX_DIGEST.fullmatch(declaration[key]):
                return error(f"{identifier} must declare a lowercase {key}")
        map_error = _valid_rule_maps(declaration, rule_ids)
        if map_error:
            return error(f"{identifier}: {map_error}")
        affected = declaration.get("affected_rule_ids")
        if not isinstance(affected, list) or any(
            not isinstance(rule_id, str) or rule_id not in declaration["rule_semantic_digests"]
            for rule_id in affected
        ):
            return error(f"invalid affected rule list for {identifier}")
        if len(affected) != len(set(affected)):
            return error(f"affected rule list has duplicates for {identifier}")
        if any(not isinstance(declaration.get(key), str) or not declaration[key].strip() for key in ("reviewer", "date", "rationale")):
            return error(f"{identifier} has empty review metadata")

    if set(declaration["feature_projection"] for declaration in declarations) != PROJECTIONS:
        return error("semantic declarations must cover all parser projections")

    def lineage_has_cycle(identifier):
        seen = set()
        cursor = identifier
        while cursor is not None:
            if cursor in seen:
                return True
            seen.add(cursor)
            current = by_id.get(cursor)
            if current is None:
                return False
            cursor = current.get("baseline_declaration_id")
        return False

    for identifier, declaration in by_id.items():
        baseline_id = declaration.get("baseline_declaration_id")
        if baseline_id is None:
            if declaration["classification"] == "review-compatible":
                return error(f"review-compatible declaration {identifier} needs a baseline")
            if not declaration["affected_rule_ids"]:
                return error(f"bootstrap semantic declaration {identifier} needs affected rules")
            continue
        if not isinstance(baseline_id, str) or baseline_id not in by_id:
            return error(f"{identifier} points to an unknown baseline")
        if baseline_id == identifier or lineage_has_cycle(identifier):
            return error(f"cyclic semantic declaration baseline at {identifier}")
        baseline = by_id[baseline_id]
        if baseline["feature_projection"] != declaration["feature_projection"]:
            return error(f"baseline projection mismatch for {identifier}")
        if declaration["classification"] == "review-compatible":
            if declaration["affected_rule_ids"]:
                return error(f"review-compatible declaration {identifier} names affected rules")
            if declaration["rule_semantic_digests"] != baseline["rule_semantic_digests"] or declaration["rule_review_revisions"] != baseline["rule_review_revisions"]:
                return error(f"review-compatible declaration {identifier} changes a semantic row")
        else:
            affected = set(declaration["affected_rule_ids"])
            if not affected:
                return error(f"semantic-change declaration {identifier} needs affected rules")
            for rule_id, digest in declaration["rule_semantic_digests"].items():
                baseline_digest = baseline["rule_semantic_digests"].get(rule_id)
                revision = declaration["rule_review_revisions"].get(rule_id)
                baseline_revision = baseline["rule_review_revisions"].get(rule_id)
                if baseline_digest is None or baseline_revision is None:
                    return error(f"baseline map is incomplete for {identifier}: {rule_id}")
                if rule_id in affected:
                    if digest == baseline_digest or revision <= baseline_revision:
                        return error(f"affected rule {rule_id} was not changed and revised in {identifier}")
                elif digest != baseline_digest or revision != baseline_revision:
                    return error(f"unaffected rule {rule_id} changed in {identifier}")
    return None


def semantic_catalog_digest(digests):
    return hashlib.sha256(canonical_json(digests).encode("utf-8")).hexdigest()


def main() -> int:
    path = Path(__file__).resolve().parents[1] / "crates/omasafe-analyzer/review-compatibility.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"semantic declarations unreadable: {error}", file=sys.stderr)
        return 1
    cli = Path(os.environ.get("OMASAFE_CLI", str(Path(__file__).resolve().parents[1] / "target/debug/omasafe-cli")))
    if not cli.is_file():
        print(f"current CLI build not found at {cli}; build omasafe-cli before this check", file=sys.stderr)
        return 1
    try:
        completed = subprocess.run(
            [str(cli), "rules", "list", "--format", "json"],
            check=True,
            capture_output=True,
            text=True,
        )
        current = json.loads(completed.stdout)["result"]
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError, KeyError) as error:
        print(f"unable to inspect current analyzer semantics: {error}", file=sys.stderr)
        return 1
    if not isinstance(current, dict):
        print("current analyzer result is malformed", file=sys.stderr)
        return 1
    current_rules = current.get("rules")
    if not isinstance(current_rules, list) or any(not isinstance(rule, dict) for rule in current_rules):
        print("current analyzer rule catalog is malformed", file=sys.stderr)
        return 1
    current_rule_values = [rule.get("id") for rule in current_rules]
    if any(not isinstance(rule_id, str) or not rule_id.startswith("oma.") for rule_id in current_rule_values):
        print("current analyzer rule catalog has invalid IDs", file=sys.stderr)
        return 1
    current_rule_ids = set(current_rule_values)
    if len(current_rule_ids) != len(current_rules):
        print("current analyzer rule catalog has invalid or duplicate IDs", file=sys.stderr)
        return 1
    validation_error = validate_document(document, current_rule_ids)
    if validation_error:
        print(f"semantic declaration invalid: {validation_error}", file=sys.stderr)
        return 1
    declarations = document["declarations"]
    by_id = {declaration["id"]: declaration for declaration in declarations}
    policy = current.get("policy_identity", {})
    current_id = policy.get("review_compatibility_declaration_id")
    current_semantics = current.get("rule_semantics", {})
    if not isinstance(current_semantics, dict):
        print("current analyzer semantic map is malformed", file=sys.stderr)
        return 1
    current_digests = {}
    current_revisions = {}
    for rule_id, item in current_semantics.items():
        if not isinstance(item, dict) or not isinstance(item.get("digest"), str) or not HEX_DIGEST.fullmatch(item["digest"]):
            print(f"current analyzer semantic row is malformed: {rule_id}", file=sys.stderr)
            return 1
        identity = item.get("identity")
        if not isinstance(identity, dict) or type(identity.get("review_revision")) is not int or identity["review_revision"] < 1:
            print(f"current analyzer semantic revision is malformed: {rule_id}", file=sys.stderr)
            return 1
        current_digests[rule_id] = item["digest"]
        current_revisions[rule_id] = identity["review_revision"]
    if set(current_digests) != current_rule_ids:
        print("current analyzer semantic map does not cover the rule catalog", file=sys.stderr)
        return 1
    if not current_id or current_id not in by_id:
        print("current build is not covered by a declared compatibility identity", file=sys.stderr)
        return 1
    declaration = by_id[current_id]
    qml_enabled = str(policy.get("parser_versions", {}).get("qml", "")).startswith("tree-sitter")
    python_enabled = str(policy.get("parser_versions", {}).get("python", "")).startswith("tree-sitter")
    projection = {
        (True, True): "qml-python",
        (True, False): "qml-only",
        (False, True): "python-only",
        (False, False): "lexical-only",
    }[(qml_enabled, python_enabled)]
    if declaration["feature_projection"] != projection:
        print(f"current declaration projection mismatch: {projection}", file=sys.stderr)
        return 1
    if not isinstance(policy.get("detector_logic_fingerprint"), str) or not HEX_DIGEST.fullmatch(policy["detector_logic_fingerprint"]):
        print("current policy has no valid detector identity", file=sys.stderr)
        return 1
    if declaration["detector_logic_fingerprint"] != policy.get("detector_logic_fingerprint") or declaration["semantic_catalog_digest"] != policy.get("rule_semantics_catalog_digest"):
        print("current detector or semantic catalog is not declared", file=sys.stderr)
        return 1
    if declaration["rule_semantic_digests"] != current_digests:
        print("current rule semantic map is not declared", file=sys.stderr)
        return 1
    if declaration["rule_review_revisions"] != current_revisions:
        print("current rule review revisions are not declared", file=sys.stderr)
        return 1
    if policy.get("rule_semantics_catalog_digest") != semantic_catalog_digest(current_digests):
        print("current semantic catalog digest is not canonical", file=sys.stderr)
        return 1
    print(f"semantic declaration check passed: {len(declarations)} declaration(s); current build {current_id}")
    return 0


def canonical_json(value):
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(key, ensure_ascii=False) + ":" + canonical_json(value[key]) for key in sorted(value)) + "}"
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


if __name__ == "__main__":
    raise SystemExit(main())
