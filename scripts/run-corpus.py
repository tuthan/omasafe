#!/usr/bin/env python3
"""Run the pinned S6 corpus through OmaSafe and classify every result.

Clones pinned commits into a disposable cache (never committed), runs
`omasafe-cli scan-plugin` per plugin with an isolated XDG environment so
local suppressions or cached snapshots cannot influence corpus results,
classifies each finding against the expectation ledger, and publishes
per-rule true-positive/false-positive/untriaged counts. Coverage loss,
unclonable repositories, and undiscoverable manifests are INCOMPLETE —
never clean. The cache is verified against the pin (HEAD equality AND a
clean worktree) before every scan; anything else is re-cloned.

PR mode (--sample N) takes a deterministic evenly spaced subset sorted by
id; nightly/release mode (--full) takes everything. The release gate
(--gate-high) fails on any known high-severity false positive or any
untriaged high-severity result — genuine high findings are expected.

Usage:
  scripts/run-corpus.py --manifest fixtures/corpus/manifest.json \
      (--sample N | --full) [--gate-high] [--output report.json]
      [--cache DIR] [--bin PATH]
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from corpus_common import (  # noqa: E402
    MATERIAL_LIMITATIONS,
    load_ledger,
    resolve_plugin_dir,
    run_git,
    sample_plugins,
)
from bounded_process import run_bounded  # noqa: E402

HIGH_SEVERITIES = {"high", "critical"}
SCAN_TIMEOUT_SECONDS = float(os.environ.get("OMASAFE_CORPUS_SCAN_TIMEOUT_SECONDS", "60"))
SCAN_MEMORY_LIMIT_BYTES = int(
    os.environ.get("OMASAFE_CORPUS_SCAN_MEMORY_MB", "768")
) * 1024 * 1024
SCAN_OUTPUT_LIMIT_BYTES = int(
    os.environ.get("OMASAFE_CORPUS_SCAN_OUTPUT_MB", "4")
) * 1024 * 1024


def log(message):
    print(f"[corpus] {message}", flush=True)


def clone_pinned(repository, commit, destination):
    """Fetch exactly one pinned commit; returns None on success or a reason.

    A cache entry is trusted only when HEAD matches the pin AND the worktree
    is pristine: tracked-file edits, untracked additions, or index changes
    from any earlier run force a fresh clone, so the scanner can never read
    poisoned bytes under a valid-looking HEAD.
    """
    if destination.exists():
        try:
            head = run_git(["rev-parse", "HEAD"], cwd=destination)
            dirty = run_git(["status", "--porcelain"], cwd=destination)
        except RuntimeError:
            head, dirty = None, "reset"
        if head == commit and not dirty:
            return None
        shutil.rmtree(destination, ignore_errors=True)
    destination.mkdir(parents=True)
    try:
        run_git(["init", "--quiet", destination.name], cwd=destination.parent)
        run_git(["remote", "add", "origin", repository], cwd=destination)
        run_git(
            ["-c", "protocol.version=2", "fetch", "--quiet", "--depth", "1",
             "origin", commit],
            cwd=destination,
        )
        run_git(["checkout", "--quiet", "--detach", commit], cwd=destination)
    except RuntimeError as error:
        return str(error)
    # Post-checkout verification of the same invariants.
    try:
        head = run_git(["rev-parse", "HEAD"], cwd=destination)
        dirty = run_git(["status", "--porcelain"], cwd=destination)
    except RuntimeError as error:
        return str(error)
    if head != commit or dirty:
        return "cache verification failed after checkout"
    return None


def run_scan(bin_path, plugin_dir):
    """scan-plugin under an isolated XDG environment.

    Returns (findings, material_loss_reasons): any inventory-level coverage
    limitation outside the benign set, or truncated entries, means the scan
    saw less than the repository and the caller must count INCOMPLETE.
    """
    with tempfile.TemporaryDirectory(prefix="omasafe-corpus-xdg-") as xdg:
        environment = {
            **os.environ,
            "HOME": xdg,
            "XDG_CONFIG_HOME": f"{xdg}/config",
            "XDG_STATE_HOME": f"{xdg}/state",
            "XDG_CACHE_HOME": f"{xdg}/cache",
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        }
        result = run_bounded(
            [str(bin_path), "scan-plugin", "--path", str(plugin_dir), "--format", "json"],
            env=environment,
            timeout=SCAN_TIMEOUT_SECONDS,
            max_output_bytes=SCAN_OUTPUT_LIMIT_BYTES,
            memory_limit_bytes=SCAN_MEMORY_LIMIT_BYTES,
            cpu_limit_seconds=max(1, int(SCAN_TIMEOUT_SECONDS)),
        )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"scan-plugin failed: {stderr[:400]}")
    stdout = result.stdout.decode("utf-8", errors="replace")
    report = json.loads(stdout)
    analysis = report["result"]["analysis"]
    inventory_section = report["result"]["payload_inventory"]
    loss = [
        limitation
        for limitation in inventory_section.get("limitations", [])
        if limitation in MATERIAL_LIMITATIONS
    ]
    states = inventory_section.get("coverage_states", {})
    if states.get("truncated", 0) or states.get("skipped", 0):
        loss.append("entries_truncated_or_skipped")
    return analysis["findings"], loss


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sample", type=int)
    group.add_argument("--full", action="store_true")
    parser.add_argument("--gate-high", action="store_true")
    parser.add_argument("--output")
    parser.add_argument("--cache", default=os.environ.get("OMASAFE_CORPUS_CACHE"))
    parser.add_argument("--ledger", default=None)
    parser.add_argument("--bin", default="target/debug/omasafe-cli")
    arguments = parser.parse_args()

    if arguments.sample is not None and arguments.sample <= 0:
        parser.error("--sample must be a positive count")

    with open(arguments.manifest, encoding="utf-8") as handle:
        manifest = json.load(handle)
    plugins = manifest["plugins"]
    mode = "full"
    if arguments.sample is not None:
        plugins = sample_plugins(plugins, arguments.sample)
        mode = f"sample:{arguments.sample}"

    ledger_default = (
        Path(arguments.manifest).parent / "expectations" / "dispositions.jsonl"
    )
    ledger = load_ledger(arguments.ledger or ledger_default)

    cache_root = Path(arguments.cache or tempfile.mkdtemp(prefix="omasafe-corpus-cache-"))
    cache_root.mkdir(parents=True, exist_ok=True)
    bin_path = Path(arguments.bin).resolve()
    if not bin_path.exists():
        log(f"building {bin_path}")
        subprocess.run(
            ["cargo", "build", "--quiet", "--bin", "omasafe-cli", "--features", "qml-parser"],
            check=True,
        )

    per_rule = {}
    totals = {"true_positive": 0, "false_positive": 0, "untriaged": 0}
    incomplete = []
    gate_failures = []
    scanned = 0

    for plugin in plugins:
        plugin_id = plugin["pluginId"]
        commit = plugin["upstreamObservedCommit"]
        digest = hashlib.sha256(plugin_id.encode()).hexdigest()
        repo_dir = cache_root / digest
        log(f"{plugin_id} @ {commit[:12]}")
        failure = clone_pinned(plugin["repository"], commit, repo_dir)
        if failure is not None:
            log(f"  INCOMPLETE (clone): {failure}")
            incomplete.append({"pluginId": plugin_id, "reason": failure})
            continue
        # Same resolution contract as the parity runner: recorded path when
        # usable, depth<=2 id discovery otherwise, incomplete when nothing
        # matches.
        plugin_dir = resolve_plugin_dir(repo_dir, plugin)
        if plugin_dir is None:
            reason = "no manifest.json declares this plugin id within depth 2"
            log(f"  INCOMPLETE: {reason}")
            incomplete.append({"pluginId": plugin_id, "reason": reason})
            continue
        try:
            findings, loss = run_scan(bin_path, plugin_dir)
        except (RuntimeError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
            log(f"  INCOMPLETE: analysis failed: {error}")
            incomplete.append({"pluginId": plugin_id, "reason": str(error)[:400]})
            continue
        if loss:
            reason = "; ".join(sorted(set(loss)))
            log(f"  INCOMPLETE: coverage loss: {reason}")
            incomplete.append({"pluginId": plugin_id, "reason": f"coverage loss: {reason}"})
            continue
        scanned += 1
        for finding in findings:
            rule_id = finding.get("rule_id", "<unknown>")
            severity = finding.get("severity", "info")
            disposition = ledger.get((plugin_id, commit, rule_id), "untriaged")
            bucket = {
                "true-positive": "true_positive",
                "false-positive": "false_positive",
            }.get(disposition, "untriaged")
            rule_stats = per_rule.setdefault(
                rule_id, {"true_positive": 0, "false_positive": 0, "untriaged": 0}
            )
            rule_stats[bucket] += 1
            totals[bucket] += 1
            if (
                arguments.gate_high
                and severity in HIGH_SEVERITIES
                and bucket in ("false_positive", "untriaged")
            ):
                gate_failures.append(
                    {
                        "pluginId": plugin_id,
                        "ruleId": rule_id,
                        "severity": severity,
                        "bucket": bucket,
                    }
                )

    report = {
        "reportVersion": 1,
        "mode": mode,
        "catalogCommit": manifest["source"]["repositoryCommit"],
        "recordedOmarchyVersion": manifest.get("recordedOmarchyVersion"),
        "selectedPlugins": len(plugins),
        "scanned": scanned,
        "incompleteRepositories": incomplete,
        "totals": totals,
        "perRule": dict(sorted(per_rule.items())),
    }
    # Precision is defined only for emitted results with a completed human
    # disposition.  A null value is deliberate: zero triaged observations are
    # not zero-percent precision, and must not accidentally admit a rule to a
    # hardened blocking set.
    blocking_eligible = []
    for rule_id, stats in report["perRule"].items():
        triaged = stats["true_positive"] + stats["false_positive"]
        stats["triaged"] = triaged
        stats["precision"] = (
            stats["true_positive"] / triaged if triaged else None
        )
        if triaged and stats["false_positive"] == 0 and stats["untriaged"] == 0:
            blocking_eligible.append(rule_id)
    report["precisionThreshold"] = 1.0
    report["blockingEligible"] = sorted(blocking_eligible)
    output = json.dumps(report, indent=2, sort_keys=True)
    if arguments.output:
        Path(arguments.output).write_text(output + "\n", encoding="utf-8")
        log(f"report written to {arguments.output}")
    print(output)

    log(
        "totals: tp={true_positive} fp={false_positive} untriaged={untriaged} "
        "incomplete={count}".format(count=len(incomplete), **totals)
    )
    if arguments.gate_high:
        if gate_failures:
            log("GATE FAILED: unaccounted high-severity results:")
            for failure in gate_failures:
                log(f"  {failure['pluginId']} {failure['ruleId']} -> {failure['bucket']}")
            return 1
        log("GATE PASSED: no known or untriaged high-severity corpus results.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
