#!/usr/bin/env bash
# Verify the pinned OpenCode host bundle without touching the user's config.
set -euo pipefail

root=$(cd -- "$(dirname -- "$0")" && pwd)
version=$(opencode --version 2>/dev/null | tr -d '\r\n')
[[ "$version" == "1.18.30" ]] || {
  printf 'expected OpenCode 1.18.30, found %s\n' "$version" >&2
  exit 1
}

bash -n "$root/launch.sh"
[[ -x "$root/launch.sh" ]] || {
  printf 'launch.sh must be executable\n' >&2
  exit 1
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/omasafe-opencode-verify.XXXXXX")
trap 'rm -rf -- "$tmp"' EXIT
config="$tmp/config/opencode"
trusted="$tmp/trusted"
mkdir -p "$config" "$trusted/.opencode/agent" "$tmp/home" "$tmp/data" "$tmp/state" "$tmp/cache"
cp "$root/opencode.json" "$trusted/opencode.json"
cp "$root/.opencode/agent/omasafe-review.md" "$trusted/.opencode/agent/omasafe-review.md"

export HOME="$tmp/home"
export XDG_CONFIG_HOME="$config"
export XDG_DATA_HOME="$tmp/data"
export XDG_STATE_HOME="$tmp/state"
export XDG_CACHE_HOME="$tmp/cache"
export OPENCODE_DISABLE_AUTOUPDATE=true
export OPENCODE_DISABLE_MODELS_FETCH=true

cd "$trusted"
agent_dump=$(timeout 20 opencode debug agent omasafe-review 2>&1)
grep -q 'omasafe-review' <<<"$agent_dump"
grep -q '"bash": false' <<<"$agent_dump"
grep -q '"task": false' <<<"$agent_dump"
grep -q 'omasafe_review' "$root/.opencode/tools/omasafe_review.ts"
grep -q 'shell: false' "$root/.opencode/tools/omasafe_review.ts"
grep -q 'detached: true' "$root/.opencode/tools/omasafe_review.ts"
config_dump=$(timeout 20 opencode debug config 2>&1)
grep -q 'omasafe-review' <<<"$config_dump"

printf '%s\n' 'OpenCode 1.18.30 bundle/config verification passed.'
printf '%s\n' 'Interactive and headless deny probes still require a configured model; see README.'
