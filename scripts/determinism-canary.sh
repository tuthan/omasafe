#!/usr/bin/env bash
# S5 determinism canary: unchanged source identity and policy identity must
# yield identical analysis output across repeated runs. Any divergence fails
# the build with preserved reproduction inputs.
#
# The comparison covers the full `result.analysis` section (fingerprint,
# normalized results, capabilities, edges, limitations) — not the report
# envelope, which legitimately carries a generation timestamp.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fixture="$root/fixtures/canary"
target_dir="${CARGO_TARGET_DIR:-$root/target}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cargo build --quiet --manifest-path "$root/Cargo.toml" --bin omasafe-cli
bin="$target_dir/debug/omasafe-cli"

run_report() {
    local home="$1" out="$2"
    mkdir -p "$home"
    HOME="$home" \
    XDG_CONFIG_HOME="$home/config" \
    XDG_STATE_HOME="$home/state" \
    XDG_CACHE_HOME="$home/cache" \
        "$bin" scan-plugin --path "$fixture" --format json >"$out"
}

for attempt in 1 2; do
    run_report "$work/home-$attempt" "$work/report-$attempt.json"
done

if ! python3 - "$work/report-1.json" "$work/report-2.json" <<'EOF'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    first = json.load(handle)["result"]["analysis"]
with open(sys.argv[2], encoding="utf-8") as handle:
    second = json.load(handle)["result"]["analysis"]
sys.exit(0 if first == second else 1)
EOF
then
    repro="$root/determinism-canary-failure"
    mkdir -p "$repro"
    # Preserve everything needed to reproduce: both outputs, the exact
    # fixture tree, and the binary/build identity that produced them.
    cp "$work/report-1.json" "$repro/report-1.json"
    cp "$work/report-2.json" "$repro/report-2.json"
    rm -rf "${repro:?}/fixture"
    cp -r "$fixture" "$repro/fixture"
    {
        printf 'commit: '
        git -C "$root" rev-parse HEAD 2>/dev/null || echo unknown
        printf 'binary_sha256: '
        sha256sum "$bin" | awk '{print $1}'
    } >"$repro/tool-identity.txt"
    echo "DETERMINISM CANARY FAILED: repeated analysis diverged." >&2
    echo "Reproduction inputs preserved in $repro" >&2
    exit 1
fi

echo "Determinism canary passed: identical analysis across repeated runs."
