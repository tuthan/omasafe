#!/usr/bin/env bash
# Start the pinned OmaSafe review agent from this trusted bundle directory.
set -euo pipefail

bundle_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$bundle_dir/../.." && pwd)
skill_dir=$(cd -- "$repo_root/../omasafe-agent-skill/skill/omasafe-plugin-review" 2>/dev/null && pwd || true)

default_cli="$repo_root/target/debug/omasafe-cli"
default_runner="$skill_dir/scripts/run-omasafe.py"
default_python="/usr/bin/python3"
if [[ -L "$default_python" ]]; then
  default_python=$(readlink -f -- "$default_python")
fi

: "${OMASAFE_REVIEW_CLI:=$default_cli}"
: "${OMASAFE_REVIEW_RUNNER:=$default_runner}"
: "${OMASAFE_REVIEW_PYTHON:=$default_python}"
: "${OMASAFE_REVIEW_CWD:=$bundle_dir}"
export OMASAFE_REVIEW_CLI OMASAFE_REVIEW_RUNNER OMASAFE_REVIEW_PYTHON OMASAFE_REVIEW_CWD

for pair in \
  "OMASAFE_REVIEW_CLI:$OMASAFE_REVIEW_CLI" \
  "OMASAFE_REVIEW_RUNNER:$OMASAFE_REVIEW_RUNNER" \
  "OMASAFE_REVIEW_PYTHON:$OMASAFE_REVIEW_PYTHON"; do
  name=${pair%%:*}
  value=${pair#*:}
  [[ "$value" == /* && -f "$value" && ! -L "$value" ]] || {
    printf '%s must name an absolute regular file (got %s)\n' "$name" "$value" >&2
    exit 1
  }
done
[[ "$OMASAFE_REVIEW_CWD" == /* && -d "$OMASAFE_REVIEW_CWD" && ! -L "$OMASAFE_REVIEW_CWD" ]] || {
  printf 'OMASAFE_REVIEW_CWD must name an absolute trusted directory (got %s)\n' "$OMASAFE_REVIEW_CWD" >&2
  exit 1
}

cd -- "$OMASAFE_REVIEW_CWD"
exec opencode --agent omasafe-review "$@"
