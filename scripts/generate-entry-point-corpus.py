#!/usr/bin/env python3
"""Generate the pinned entry-point corpus manifest for parser measurement.

Selection is deterministic: candidates are catalog entries with an https
repository URL and a valid hexadecimal `upstreamObservedCommit`, sorted by
plugin id, then sampled at evenly spaced indices. The manifest records the
frozen-catalog provenance so the exact selection can be reproduced.

Usage:
  scripts/generate-entry-point-corpus.py <catalog.json> <catalog.meta.json> \
      <output.json> [count]
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


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    catalog_path, meta_path, output_path = sys.argv[1:4]
    count = int(sys.argv[4]) if len(sys.argv) > 4 else 50

    with open(catalog_path, "rb") as handle:
        raw = handle.read()
    digest = hashlib.sha256(raw).hexdigest()
    document = json.loads(raw)
    entries = document.get("entries") or document.get("plugins") or []
    with open(meta_path, encoding="utf-8") as handle:
        meta = json.load(handle)

    candidates = [
        entry
        for entry in entries
        if str(entry.get("repo", "")).startswith("https://")
        and valid_commit(entry.get("upstreamObservedCommit"))
    ]
    candidates.sort(key=lambda entry: entry["id"])
    total = len(candidates)

    # Stratify proportionally across repositoryLayout buckets, then take an
    # evenly spaced sample within each bucket. Keeps the mix of plugin shapes
    # representative while staying fully deterministic.
    buckets = {}
    for entry in candidates:
        buckets.setdefault(entry.get("repositoryLayout"), []).append(entry)

    picked = []
    seen = set()
    layouts = sorted(buckets, key=lambda layout: (buckets[layout][0]["id"], layout))
    remaining = count
    allocated = []
    for position, layout in enumerate(layouts):
        size = len(buckets[layout])
        share = size * count // total
        if position == len(layouts) - 1:
            share = remaining
        else:
            remaining -= share
        allocated.append((layout, min(share, size)))
    for layout, share in allocated:
        bucket = buckets[layout]
        if share == 0:
            continue
        size = len(bucket)
        for index in range(share):
            position = (index * size) // share
            entry = bucket[position]
            if entry["id"] not in seen:
                seen.add(entry["id"])
                picked.append(
                    {
                        "id": entry["id"],
                        "repo": entry["repo"],
                        "upstreamObservedCommit": entry["upstreamObservedCommit"],
                        "repositoryLayout": layout,
                        "kind": entry.get("kind"),
                    }
                )
    picked.sort(key=lambda entry: entry["id"])

    manifest = {
        "manifestVersion": 1,
        "selectionRule": (
            f"candidates = entries with https repo and valid upstreamObservedCommit; "
            f"grouped by repositoryLayout; proportional allocation across layout "
            f"buckets; evenly spaced sample of {count} from {total}; result sorted by id"
        ),
        "source": {
            "catalogRepository": meta["repository_url"],
            "catalogCommit": meta["repository_commit"],
            "catalogFileDigest": digest,
            "retrievedAt": meta["retrieved_at"],
        },
        "plugins": picked,
    }
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    layouts = {}
    for plugin in picked:
        layouts[plugin["repositoryLayout"]] = layouts.get(plugin["repositoryLayout"], 0) + 1
    print(f"wrote {len(picked)} plugins to {output_path} (layouts: {layouts})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
