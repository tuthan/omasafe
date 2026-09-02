#!/usr/bin/env bash
#
# Recompute the supply-chain figures shown in the "Why" band of site/index.html.
#
# Both sources are mutable and regenerated continuously upstream, so every number
# is attributed to a snapshot date on the page. Re-run this before a site refresh,
# copy the values into site/index.html, and move the snapshot dates with them.
#
# Sources:
#   - Omarchy plugin catalog: https://plugins.omarchy.org/catalog.json
#       (the site is a client-rendered SPA; the real catalog is this JSON, not the
#        rendered HTML, so a plain page fetch reports zero plugins.)
#   - Arch User Repository:   https://aur.archlinux.org/packages-meta-ext-v1.json.gz
#
# Usage: scripts/site-stats.sh
#
set -euo pipefail

CATALOG_URL="https://plugins.omarchy.org/catalog.json"
AUR_URL="https://aur.archlinux.org/packages-meta-ext-v1.json.gz"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "Fetching Omarchy plugin catalog ..." >&2
curl -fsSL --max-time 120 "$CATALOG_URL" -o "$work/catalog.json"
echo "Fetching AUR metadata ..." >&2
curl -fsSL --max-time 120 "$AUR_URL" -o "$work/aur.json.gz"

python3 - "$work/catalog.json" "$work/aur.json.gz" <<'PY'
import sys, json, gzip, datetime

catalog_path, aur_path = sys.argv[1], sys.argv[2]

# --- Omarchy plugin marketplace -------------------------------------------
cat = json.load(open(catalog_path))
plugins   = cat["plugins"]
community = [p for p in plugins if p.get("sourceType") == "community"]
builtin   = [p for p in plugins if p.get("sourceType") == "builtin" or p.get("builtIn")]

total_listings  = len(plugins)
comm_unverified = sum(1 for p in community if p.get("verificationStatus") == "unverified")
# "upstream moved past the listing-validated commit": the exact commit the
# marketplace validated at listing time no longer matches what upstream now serves.
comm_drifted = sum(
    1 for p in community
    if p.get("upstreamObservedCommit")
    and p.get("listingValidatedCommit")
    and p["upstreamObservedCommit"] != p["listingValidatedCommit"]
)
cat_date = cat.get("generatedAt", "?")[:10]

# --- Arch User Repository -------------------------------------------------
aur = json.load(gzip.open(aur_path))
now = datetime.datetime.now(datetime.timezone.utc).timestamp()
aur_total    = len(aur)
aur_zerovote = sum(1 for p in aur if (p.get("NumVotes") or 0) == 0)
aur_recent   = sum(1 for p in aur if (p.get("LastModified") or 0) >= now - 30 * 86400)
aur_ood      = sum(1 for p in aur if p.get("OutOfDate"))
aur_date = datetime.date.today().isoformat()

def line(label, value):
    print(f"  {label:<46} {value:>10,}")

print(f"\nOmarchy plugin marketplace   (snapshot {cat_date})")
line("total listings", total_listings)
line("  community", len(community))
line("  built-in", len(builtin))
line("community listings unverified", comm_unverified)
line("upstream commit != listing-validated commit", comm_drifted)

print(f"\nArch User Repository         (snapshot {aur_date})")
line("total packages", aur_total)
line("with zero community votes", aur_zerovote)
line("changed in the last 30 days", aur_recent)
line("flagged out-of-date", aur_ood)

print("\nLanding-page values for site/index.html (.stats band):")
print(f"  marketplace : {total_listings} / {comm_unverified} / {comm_drifted}   (note date {cat_date})")
print(f"  aur         : {aur_total} / {aur_zerovote} / {aur_recent}   (note date {aur_date})")
print()
PY
