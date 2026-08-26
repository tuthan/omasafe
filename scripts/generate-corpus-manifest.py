#!/usr/bin/env python3
"""Generate the pinned S6 corpus manifest from the frozen marketplace catalog.

Every community plugin with an https repository and a valid hexadecimal
`upstreamObservedCommit` is pinned: plugin id, repository, commit, layout,
manifest path (root-plugin layouts; null otherwise — the runner discovers),
and expected availability. No plugin content is committed anywhere; CI clones
pinned commits into a disposable cache. The manifest records the frozen-catalog
provenance so the exact selection can be reproduced, and live-catalog refresh
is never PR input — regenerating requires an explicit run against a new frozen
snapshot.

Usage:
  scripts/generate-corpus-manifest.py <catalog.json> <catalog.meta.json> \
      <output.json>
"""

import hashlib
import json
import sys


def valid_commit(value):
    return (
        isinstance(value, str)
        and len(value) in (40, 64)
        and all(c in "0123456789abcdefABCDEF" for c in value)
    )


def manifest_path_for(entry):
    # root-plugin repositories keep manifest.json at their root. Monorepo and
    # suite layouts hold several plugins under subdirectories with no catalog
    # recorded path; the runner discovers per plugin and counts discovery
    # failure as incomplete, never clean.
    if entry.get("repositoryLayout") == "root-plugin":
        return "manifest.json"
    return None


def main():
    if len(sys.argv) != 4:
        print(__doc__)
        return 2
    catalog_path, meta_path, output_path = sys.argv[1:4]

    with open(catalog_path, "rb") as handle:
        raw = handle.read()
    digest = hashlib.sha256(raw).hexdigest()
    document = json.loads(raw)
    entries = document.get("entries") or document.get("plugins") or []
    with open(meta_path, encoding="utf-8") as handle:
        meta = json.load(handle)

    picked = []
    for entry in entries:
        if entry.get("sourceType") not in (None, "community"):
            continue
        repo = entry.get("repo", "")
        if not str(repo).startswith("https://"):
            continue
        if not valid_commit(entry.get("upstreamObservedCommit")):
            continue
        picked.append(
            {
                "pluginId": entry["id"],
                "repository": repo,
                "upstreamObservedCommit": entry["upstreamObservedCommit"],
                "repositoryLayout": entry.get("repositoryLayout"),
                "manifestPath": manifest_path_for(entry),
                "kind": entry.get("kind"),
                "status": entry.get("status"),
                "expectedAvailable": entry.get("installAvailable") is True,
            }
        )
    picked.sort(key=lambda item: item["pluginId"])

    manifest = {
        "manifestVersion": 1,
        "selectionRule": (
            "candidates = community entries with https repo and valid "
            "upstreamObservedCommit; all candidates are pinned, sorted by "
            "plugin id. PR runners sample deterministically from this file; "
            "nightly and pre-release runs take the full corpus."
        ),
        "source": {
            "catalogFileSha256": digest,
            "catalogEntryCount": len(entries),
            "repositoryCommit": meta.get("repository_commit"),
            "repositoryUrl": meta.get("repository_url"),
            "retrievedAt": meta.get("retrieved_at"),
            "fileDigest": meta.get("file_digest"),
        },
        "recordedOmarchyVersion": "4.0.1",
        "plugins": picked,
    }
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(
        f"pinned {len(picked)} of {len(entries)} catalog entries "
        f"(catalog commit {meta.get('repository_commit')})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
