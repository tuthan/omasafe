#!/usr/bin/env python3
"""Self-tests for the S6 corpus tooling (run with python3, exit 0/1).

Covers the invariants the runners depend on: deterministic sampling shared
by both scripts, plugin-directory resolution (recorded path and depth-2
discovery), ledger schema validation, and byte-stable manifest generation
on a synthetic catalog including duplicate ids and malformed metadata.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from corpus_common import load_ledger, resolve_plugin_dir, sample_plugins  # noqa: E402
from bounded_process import run_bounded  # noqa: E402

ROOT = Path(__file__).parent.parent
FAILURES = []


def check(name, condition, detail=""):
    if condition:
        print(f"ok   {name}")
    else:
        print(f"FAIL {name} {detail}")
        FAILURES.append(name)


def synthetic_catalog(path, count=8):
    entries = []
    for index in range(count):
        entries.append(
            {
                "id": f"io.test.plugin{index:02d}",
                "sourceType": "community",
                "repo": f"https://github.com/test/plugin{index:02d}",
                "upstreamObservedCommit": f"{index:06x}" + "a" * 34,
                "repositoryLayout": "root-plugin",
                "kind": "Bar widget",
                "status": "Available",
                "installAvailable": True,
            }
        )
    # A duplicate id must not survive into the manifest twice.
    entries.append(dict(entries[0], repo="https://github.com/test/duplicate"))
    # Builtins and invalid commits are excluded.
    entries.append({"id": "omarchy.builtin", "sourceType": "builtin"})
    entries.append(
        {
            "id": "io.test.nopin",
            "sourceType": "community",
            "repo": "https://github.com/test/nopin",
            "upstreamObservedCommit": "not-a-commit",
        }
    )
    path.write_text(json.dumps({"entries": entries}), encoding="utf-8")


def main():
    plugins = [
        {"pluginId": f"id{i:02d}", "manifestPath": "manifest.json"} for i in range(100)
    ]
    first = [item["pluginId"] for item in sample_plugins(plugins, 12)]
    second = [item["pluginId"] for item in sample_plugins(plugins, 12)]
    check("sampling is deterministic", first == second)
    check("sample size is exact", len(first) == 12, str(len(first)))
    check("sample is sorted by id", first == sorted(first))

    # Both runner scripts share one sampler implementation.
    parity_source = (ROOT / "scripts" / "validator-parity.py").read_text(encoding="utf-8")
    runner_source = (ROOT / "scripts" / "run-corpus.py").read_text(encoding="utf-8")
    ground_truth_source = (ROOT / "scripts" / "measure-ground-truth.py").read_text(
        encoding="utf-8"
    )
    check(
        "both runners import the shared sampler",
        "from corpus_common import" in parity_source
        and "sample_plugins" in parity_source
        and "from corpus_common import" in runner_source,
    )
    check(
        "corpus reports precision and blocking eligibility",
        '"blockingEligible"' in runner_source
        and '"precision"' in runner_source
        and '"triaged"' in runner_source,
    )
    check(
        "corpus scans use process bounds",
        "run_bounded" in runner_source
        and "SCAN_MEMORY_LIMIT_BYTES" in runner_source
        and "SCAN_TIMEOUT_SECONDS" in runner_source,
    )
    check(
        "all CLI test runners use process bounds",
        "run_bounded" in parity_source and "run_bounded" in ground_truth_source,
    )

    parity_invocations = []
    workflows = ROOT / ".github" / "workflows"
    for workflow in sorted(workflows.glob("*.y*ml")):
        lines = workflow.read_text(encoding="utf-8").splitlines()
        for index, line in enumerate(lines):
            if "python3 scripts/validator-parity.py" not in line:
                continue
            invocation = [line]
            cursor = index
            while invocation[-1].rstrip().endswith("\\") and cursor + 1 < len(lines):
                cursor += 1
                invocation.append(lines[cursor])
            parity_invocations.append((workflow.name, "\n".join(invocation)))
    check(
        "validator parity workflows choose exactly one corpus mode",
        bool(parity_invocations)
        and all(
            sum(f"--{mode}" in invocation for mode in ("sample", "full")) == 1
            for _, invocation in parity_invocations
        ),
        str([name for name, _ in parity_invocations]),
    )

    bounded = run_bounded(
        [sys.executable, "-c", "print('x' * 256)"],
        timeout=5,
        max_output_bytes=64,
        memory_limit_bytes=None,
    )
    check("bounded runner caps retained output", len(bounded.stdout) <= 64)
    try:
        run_bounded(
            [sys.executable, "-c", "import time; time.sleep(5)"],
            timeout=0.1,
            memory_limit_bytes=None,
        )
    except subprocess.TimeoutExpired:
        check("bounded runner stops timed-out children", True)
    else:
        check("bounded runner stops timed-out children", False)

    ground_truth = json.loads(
        (ROOT / "fixtures" / "corpus" / "expectations" / "ground-truth.json").read_text(
            encoding="utf-8"
        )
    )
    check(
        "ground-truth manifest is versioned and non-empty",
        ground_truth.get("schemaVersion") == 1
        and isinstance(ground_truth.get("fixtures"), list)
        and bool(ground_truth["fixtures"]),
    )
    check(
        "ground-truth cases declare positive or negative rules",
        all(
            isinstance(case.get("expectedRules"), list)
            or isinstance(case.get("forbiddenRules"), list)
            for case in ground_truth["fixtures"]
        ),
    )
    case_ids = [case.get("id") for case in ground_truth["fixtures"]]
    check(
        "ground-truth case ids are unique",
        all(isinstance(case_id, str) and case_id for case_id in case_ids)
        and len(case_ids) == len(set(case_ids)),
    )

    h8b_admission = json.loads(
        (ROOT / "docs" / "reports" / "h8b-blocking-admission.json").read_text(
            encoding="utf-8"
        )
    )
    ledger_count = len(
        load_ledger(ROOT / "fixtures" / "corpus" / "expectations" / "dispositions.jsonl")
    )
    check(
        "H8b admission report is evidence-gated",
        h8b_admission.get("schemaVersion") == 1
        and h8b_admission.get("precisionThreshold") == 1.0
        and h8b_admission.get("fixtureDetectionThreshold") == 1.0
        and h8b_admission.get("triagedDispositionCount") == ledger_count
        and ledger_count > 0
        and h8b_admission.get("groundTruth", {}).get("passed") is True
        and h8b_admission.get("blockingEligible") == []
        and h8b_admission.get("blockingRuleFamilies") == [],
    )

    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        # Recorded-path resolution.
        plugin = {"pluginId": "io.test.a", "manifestPath": "manifest.json"}
        (base / "repo-a").mkdir()
        (base / "repo-a" / "manifest.json").write_text('{"id":"io.test.a"}')
        check(
            "resolves recorded root path",
            resolve_plugin_dir(base / "repo-a", plugin) == base / "repo-a",
        )
        # Depth-2 discovery when no path is recorded.
        nested = base / "repo-b" / "plugins" / "sub"
        nested.mkdir(parents=True)
        (nested / "manifest.json").write_text('{"id":"io.test.b"}')
        found = resolve_plugin_dir(base / "repo-b", {"pluginId": "io.test.b", "manifestPath": None})
        check("discovers nested manifest", found == nested, str(found))
        # No match anywhere is None (callers count incomplete).
        check(
            "missing id resolves to None",
            resolve_plugin_dir(base / "repo-b", {"pluginId": "io.other", "manifestPath": None}) is None,
        )

        # Ledger validation.
        ledger_path = base / "d.jsonl"
        good = (
            '{"plugin_id":"p","commit":"' + "b" * 40 + '","rule_id":"r",'
            '"disposition":"true-positive","note":"reviewed"}\n'
        )
        ledger_path.write_text(good)
        check("valid ledger loads", load_ledger(ledger_path) != {})
        for bad in [
            '{"plugin_id":"p","commit":"short","rule_id":"r","disposition":"true-positive","note":"n"}',
            '{"plugin_id":"p","commit":"' + "b" * 40 + '","rule_id":"r","disposition":"maybe","note":"n"}',
            '{"plugin_id":"p","commit":"' + "b" * 40 + '","rule_id":"r","disposition":"true-positive"}',
            "{ not json",
        ]:
            ledger_path.write_text(good + bad + "\n")
            try:
                load_ledger(ledger_path)
                check(f"rejects {bad[:50]}", False)
            except ValueError:
                check(f"rejects {bad[:44]}...", True)

    # Generator determinism and exclusion rules on a synthetic catalog.
    with tempfile.TemporaryDirectory() as temp:
        catalog = Path(temp) / "catalog.json"
        meta = Path(temp) / "meta.json"
        synthetic_catalog(catalog)
        meta.write_text(
            json.dumps(
                {
                    "repository_commit": "964dc08df2a3450578727b665908272cd3a277e5",
                    "retrieved_at": "2026-08-25T03:27:21Z",
                    "file_digest": None,
                    "repository_url": "https://example.test/catalog",
                }
            )
        )
        outputs = []
        for run in range(2):
            output = Path(temp) / f"manifest-{run}.json"
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "generate-corpus-manifest.py"),
                    str(catalog),
                    str(meta),
                    str(output),
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                check(f"generator run {run}", False, result.stderr)
                break
            outputs.append(output.read_bytes())
        if len(outputs) == 2:
            check("generator is byte-stable", outputs[0] == outputs[1])
            document = json.loads(outputs[0])
            ids = [item["pluginId"] for item in document["plugins"]]
            check("duplicate id appears once", len(ids) == len(set(ids)), str(ids))
            check("excludes builtins and unpinned", all(i.startswith("io.test.plugin") for i in ids), str(ids))
            check("records provenance commit",
                  document["source"]["repositoryCommit"] == "964dc08df2a3450578727b665908272cd3a277e5")

        # Digest mismatch between meta and catalog must be rejected.
        meta.write_text(json.dumps({**json.loads(meta.read_text()), "file_digest": "deadbeef"}))
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "generate-corpus-manifest.py"),
             str(catalog), str(meta), str(Path(temp) / "m3.json")],
            capture_output=True, text=True,
        )
        check("digest mismatch rejected", result.returncode != 0)

    if FAILURES:
        print(f"\n{len(FAILURES)} failure(s)")
        return 1
    print("\nall corpus tooling self-tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
