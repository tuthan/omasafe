"""Shared primitives for the S6 corpus tooling.

Both runners (run-corpus.py, validator-parity.py) import this module so
selection, plugin-directory resolution, and ledger parsing can never drift
apart. Kept dependency-free on purpose.
"""

import json
import os
import subprocess
from pathlib import Path

# Inventory-level limitations that mean the scanner saw less than the whole
# repository. Any of these degrades a result to INCOMPLETE — coverage loss
# must never pass a gate as a clean zero-findings scan.
MATERIAL_LIMITATIONS = frozenset(
    {
        "time_budget_exhausted",
        "tree_depth_limit_exceeded",
        "directory_entry_limit_exceeded",
        "file_limit_exceeded",
        "aggregate_byte_limit_reached",
        "unreadable_file",
        "read_error",
        "metadata_unavailable",
    }
)

VALID_DISPOSITIONS = frozenset({"true-positive", "false-positive"})
LEDGER_V2_SCHEMA_VERSION = 2


def _valid_hex(value, lengths):
    return (
        isinstance(value, str)
        and len(value) in lengths
        and all(char in "0123456789abcdefABCDEF" for char in value)
    )


def sample_plugins(plugins, count):
    """Deterministic evenly spaced subset over the sorted plugin-id order."""
    ordered = sorted(plugins, key=lambda item: item["pluginId"])
    total = len(ordered)
    count = min(count, total)
    if count <= 0:
        return []
    return [ordered[(index * total) // count] for index in range(count)]


def resolve_plugin_dir(repo_dir, plugin):
    """Directory whose manifest.json declares this plugin id.

    Uses the recorded manifestPath when present, otherwise discovers within
    depth two. Returns None when nothing matches — callers must count that
    INCOMPLETE, never as agreement or a clean scan.
    """
    recorded = plugin.get("manifestPath")
    candidates = []
    if recorded:
        candidates.append(repo_dir / recorded)
    candidates.extend([repo_dir, *sorted(repo_dir.glob("*/")), *sorted(repo_dir.glob("*/*/"))])
    seen = set()
    for candidate in candidates:
        candidate = candidate.parent if candidate.name == "manifest.json" else candidate
        if candidate in seen or not candidate.is_dir():
            continue
        seen.add(candidate)
        manifest = candidate / "manifest.json"
        if not manifest.is_file():
            continue
        try:
            document = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if document.get("id") == plugin["pluginId"]:
            return candidate
    return None


def load_ledger(path):
    """Last record per key wins; records are append-only.

    Raises ValueError with the offending line on schema violations so a
    malformed ledger can never silently reclassify results.
    """
    ledger = {}
    path = Path(path)
    if not path.exists():
        return ledger
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                if record.get("schema_version") == LEDGER_V2_SCHEMA_VERSION:
                    raise ValueError(
                        "occurrence ledger records require load_occurrence_ledger()"
                    )
                commit = record["commit"]
                disposition = record["disposition"]
                plugin_id = record["plugin_id"]
                rule_id = record["rule_id"]
                note = record["note"]
            except (json.JSONDecodeError, KeyError) as error:
                raise ValueError(f"ledger line {number}: malformed record: {error}") from error
            if not _valid_hex(commit, (40, 64)):
                raise ValueError(f"ledger line {number}: commit is not 40/64-hex: {commit!r}")
            if disposition not in VALID_DISPOSITIONS:
                raise ValueError(
                    f"ledger line {number}: disposition must be one of "
                    f"{sorted(VALID_DISPOSITIONS)}, got {disposition!r}"
                )
            if not isinstance(note, str) or not note.strip():
                raise ValueError(f"ledger line {number}: a human note is required")
            ledger[(plugin_id, commit, rule_id)] = disposition
    return ledger


def load_occurrence_ledger(path):
    """Load append-only v2 labels keyed by exact finding occurrence.

    The legacy rule-only ledger is intentionally kept separate: a v1 label
    must never fan out to every occurrence of a rule. Last record wins for the
    full compatibility key, while the producer/declaration digests remain in
    the returned audit record.
    """
    ledger = {}
    path = Path(path)
    if not path.exists():
        return ledger
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                schema_version = record["schema_version"]
                plugin_id = record["plugin_id"]
                commit = record["commit"]
                rule_id = record["rule_id"]
                occurrence_id = record["occurrence_id"]
                semantic_digest = record["rule_semantic_identity_digest"]
                policy_digest = record["observed_policy_identity_digest"]
                declaration_id = record["review_compatibility_declaration_id"]
                disposition = record["disposition"]
                note = record["note"]
            except (json.JSONDecodeError, KeyError, TypeError) as error:
                raise ValueError(f"ledger v2 line {number}: malformed record: {error}") from error
            if schema_version != LEDGER_V2_SCHEMA_VERSION:
                raise ValueError(f"ledger v2 line {number}: schema_version must be 2")
            if not isinstance(plugin_id, str) or not plugin_id.strip():
                raise ValueError(f"ledger v2 line {number}: plugin_id is required")
            if not _valid_hex(commit, (40, 64)):
                raise ValueError(f"ledger v2 line {number}: commit is not 40/64-hex")
            if not isinstance(rule_id, str) or not rule_id.strip():
                raise ValueError(f"ledger v2 line {number}: rule_id is required")
            if not _valid_hex(occurrence_id, (64,)):
                raise ValueError(f"ledger v2 line {number}: occurrence_id is not SHA-256")
            if not _valid_hex(semantic_digest, (64,)):
                raise ValueError(
                    f"ledger v2 line {number}: rule_semantic_identity_digest is not SHA-256"
                )
            if not _valid_hex(policy_digest, (64,)):
                raise ValueError(
                    f"ledger v2 line {number}: observed_policy_identity_digest is not SHA-256"
                )
            if declaration_id is not None and (
                not isinstance(declaration_id, str) or not declaration_id.strip()
            ):
                raise ValueError(f"ledger v2 line {number}: invalid declaration id")
            if disposition not in VALID_DISPOSITIONS:
                raise ValueError(
                    f"ledger v2 line {number}: disposition must be one of "
                    f"{sorted(VALID_DISPOSITIONS)}"
                )
            if not isinstance(note, str) or not note.strip():
                raise ValueError(f"ledger v2 line {number}: a human note is required")
            key = (plugin_id, commit, rule_id, occurrence_id, semantic_digest)
            ledger[key] = record
    return ledger


def run_git(arguments, cwd, timeout=900):
    """Bounded git execution: returns stdout or raises RuntimeError."""
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={
                **os.environ,
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_SYSTEM": "/dev/null",
                "GIT_TERMINAL_PROMPT": "0",
            },
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"git {' '.join(arguments)}: timed out") from error
    if result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(arguments)}: {result.stderr.strip()[:350] or 'failed'}"
        )
    return result.stdout.strip()
