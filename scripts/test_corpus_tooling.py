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
    check(
        "both runners import the shared sampler",
        "from corpus_common import" in parity_source
        and "sample_plugins" in parity_source
        and "from corpus_common import" in runner_source,
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
