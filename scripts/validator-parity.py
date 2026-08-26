#!/usr/bin/env python3
"""Validator parity canary (S6 / M5): OmaSafe manifest checks vs native.

Runs both `omarchy plugin validate` and OmaSafe's mirror over the pinned
corpus clones and compares verdicts. Verdicts are three-state — `valid`,
`invalid`, `error` — and only identical valid/invalid labels count as
agreement: timeouts, spawn failures, and unexpected exits are errors, and
any error is a disagreement (never silent agreement). Disagreement fails
the build for the recorded Omarchy version. A missing or newer/unverified
runtime degrades validator coverage VISIBLY instead of silently passing.
Repositories without a discoverable manifest, or whose cache does not
verify against the pin, are incomplete.

Usage:
  scripts/validator-parity.py --manifest fixtures/corpus/manifest.json \
      --cache DIR (--sample N | --full) [--output report.json]
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from corpus_common import resolve_plugin_dir, run_git, sample_plugins  # noqa: E402


def log(message):
    print(f"[parity] {message}", flush=True)


def omarchy_version():
    try:
        result = subprocess.run(
            ["omarchy", "version"], capture_output=True, text=True, timeout=30
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    # e.g. "4.0.1-1" or "omarchy 4.0.1"
    for token in result.stdout.split():
        if token[0:1].isdigit():
            return token.split("-")[0]
    return None


def ensure_validator_bin():
    env_path = os.environ.get("OMASAFE_VALIDATE_BIN")
    if env_path:
        path = Path(env_path)
        if path.exists():
            return path
        raise SystemExit(f"OMASAFE_VALIDATE_BIN points at a missing file: {env_path}")
    target = Path("target/debug/examples/validate-manifest")
    if not target.exists():
        log("building validate-manifest example")
        subprocess.run(
            [
                "cargo", "build", "--quiet",
                "-p", "omasafe-marketplace", "--example", "validate-manifest",
            ],
            check=True,
        )
    return target


def verdict(command):
    """Three-state verdict: valid / invalid / error. Only the first two are
    evaluation results; anything else (timeout, spawn failure, unexpected
    exit code or signal) is an error and can never count as agreement."""
    label = "error"
    detail = ""
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as error:
        detail = str(error)[:200]
        return (label, detail)
    if result.returncode == 0:
        label = "valid"
    elif result.returncode == 1:
        label = "invalid"
    else:
        detail = f"exit {result.returncode}: {result.stderr.strip()[:180]}"
    return (label, detail)


def cache_verifies(repo_dir, commit):
    """Independent pin verification for reused cache entries."""
    try:
        head = run_git(["rev-parse", "HEAD"], cwd=repo_dir)
        dirty = run_git(["status", "--porcelain"], cwd=repo_dir)
    except RuntimeError:
        return False
    return head == commit and not dirty


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sample", type=int)
    group.add_argument("--full", action="store_true")
    parser.add_argument("--cache", required=True)
    parser.add_argument("--output")
    arguments = parser.parse_args()
    if arguments.sample is not None and arguments.sample <= 0:
        parser.error("--sample must be a positive count")

    with open(arguments.manifest, encoding="utf-8") as handle:
        manifest = json.load(handle)
    recorded = manifest.get("recordedOmarchyVersion")

    runtime = omarchy_version()
    if runtime is None:
        report = {
            "reportVersion": 1,
            "status": "degraded",
            "reason": "native omarchy validator is not available on this runner",
            "recordedOmarchyVersion": recorded,
            "runtimeOmarchyVersion": None,
            "compared": 0,
            "disagreements": [],
            "incomplete": 0,
        }
    elif recorded is None or runtime != recorded:
        report = {
            "reportVersion": 1,
            "status": "degraded",
            "reason": (
                f"runtime Omarchy {runtime} is not the recorded version {recorded}; "
                "validator coverage degrades until the recording is re-verified"
            ),
            "recordedOmarchyVersion": recorded,
            "runtimeOmarchyVersion": runtime,
            "compared": 0,
            "disagreements": [],
            "incomplete": 0,
        }
    else:
        ours = ensure_validator_bin()
        disagreements = []
        incomplete = 0
        compared = 0
        plugins = manifest["plugins"]
        if arguments.sample is not None:
            plugins = sample_plugins(plugins, arguments.sample)
        for plugin in plugins:
            plugin_id = plugin["pluginId"]
            digest = hashlib.sha256(plugin_id.encode()).hexdigest()
            repo_dir = Path(arguments.cache) / digest
            if not repo_dir.exists() or not cache_verifies(repo_dir, plugin["upstreamObservedCommit"]):
                incomplete += 1
                continue
            target = resolve_plugin_dir(repo_dir, plugin)
            if target is None:
                incomplete += 1
                continue
            native = verdict(["omarchy", "plugin", "validate", str(target)])
            mirror = verdict([str(ours), str(target)])
            compared += 1
            if native[0] == "error" or mirror[0] == "error" or native[0] != mirror[0]:
                disagreements.append(
                    {
                        "pluginId": plugin_id,
                        "native": native,
                        "mirror": mirror,
                    }
                )
                log(f"DISAGREEMENT {plugin_id}: native={native[0]} mirror={mirror[0]}")
        report = {
            "reportVersion": 1,
            "status": "compared",
            "recordedOmarchyVersion": recorded,
            "runtimeOmarchyVersion": runtime,
            "compared": compared,
            "disagreements": disagreements,
            "incomplete": incomplete,
        }

    output = json.dumps(report, indent=2, sort_keys=True)
    if arguments.output:
        Path(arguments.output).write_text(output + "\n", encoding="utf-8")
        log(f"report written to {arguments.output}")
    print(output)

    if report["status"] == "degraded":
        # Visible degradation is a successful canary run by design; the
        # report makes the reduced coverage impossible to miss.
        log(f"VALIDATOR COVERAGE DEGRADED: {report['reason']}")
        return 0
    if report["disagreements"]:
        log(f"GATE FAILED: {len(report['disagreements'])} verdict disagreements.")
        return 1
    log(f"parity ok: {report['compared']} compared, {report['incomplete']} incomplete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
