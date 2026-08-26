#!/usr/bin/env python3
"""Validator parity canary (S6 / M5): OmaSafe manifest checks vs native.

Runs both `omarchy plugin validate` and OmaSafe's mirror over the pinned
corpus clones and fails the build on verdict disagreement for the recorded
Omarchy version. A missing or newer/unverified runtime Omarchy degrades
validator coverage VISIBLY — the report says so — instead of silently
passing. Repositories without a discoverable manifest count incomplete,
never as agreement.

Usage:
  scripts/validator-parity.py --manifest fixtures/corpus/manifest.json \
      --cache DIR [--output report.json] [--limit N]
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path


def sample_plugins(plugins, count):
    """Identical deterministic sampling to run-corpus.py so both runners
    always evaluate the same PR subset."""
    ordered = sorted(plugins, key=lambda item: item["pluginId"])
    total = len(ordered)
    count = min(count, total)
    if count == 0:
        return []
    return [ordered[(index * total) // count] for index in range(count)]


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
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as error:
        return ("error", str(error)[:200])
    return ("pass" if result.returncode == 0 else "fail", result.stderr.strip()[:200])


def discover_manifest_dir(repo_dir, plugin_id):
    """Depth<=2 directory whose manifest.json declares this plugin id."""
    candidates = [repo_dir, *sorted(repo_dir.glob("*/")), *sorted(repo_dir.glob("*/*/"))]
    for candidate in candidates:
        manifest = candidate / "manifest.json"
        if not manifest.is_file():
            continue
        try:
            document = json.loads(manifest.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if document.get("id") == plugin_id:
            return candidate
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--cache", required=True)
    parser.add_argument("--output")
    parser.add_argument("--sample", type=int)
    arguments = parser.parse_args()

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
        if arguments.sample:
            plugins = sample_plugins(plugins, arguments.sample)
        for plugin in plugins:
            plugin_id = plugin["pluginId"]
            digest = hashlib.sha256(plugin_id.encode()).hexdigest()
            repo_dir = Path(arguments.cache) / digest
            if not repo_dir.exists():
                # The corpus runner owns cloning; missing clone = incomplete.
                incomplete += 1
                continue
            target = repo_dir
            if plugin["manifestPath"] is None:
                discovered = discover_manifest_dir(repo_dir, plugin_id)
                if discovered is None:
                    incomplete += 1
                    continue
                target = discovered
            native = verdict(["omarchy", "plugin", "validate", str(target)])
            mirror = verdict([str(ours), str(target)])
            compared += 1
            if native[0] != mirror[0]:
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
