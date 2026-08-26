#!/usr/bin/env bash
# Clean-VM lifecycle verification for an OmaSafe release.
#
# Codifies the manual clean-room checks that cannot run in CI because they
# need a real Omarchy session (systemd user units, the shell IPC, a live
# bar). Run against a FRESH VM snapshot per release; every step prints
# PASS/FAIL and the script exits nonzero on any failure.
#
# Usage:
#   scripts/vm-lifecycle.sh [USER@VMHOST]
# Without SSH arguments everything runs locally — only sensible inside the
# disposable VM itself.
set -uo pipefail

if [[ $# -gt 0 ]]; then
  ssh_target=$1
  run() { ssh -o BatchMode=yes "$ssh_target" "$@"; }
else
  run() { bash -lc "$*"; }
fi

failures=0
step() {
  local name=$1
  shift
  printf '\n--- %s ---\n' "$name"
  if out=$("$@" 2>&1); then
    printf 'PASS %s\n%s\n' "$name" "${out:0:500}"
  else
    printf 'FAIL %s (exit %d)\n%s\n' "$name" "$?" "$out"
    failures=$((failures + 1))
  fi
}

version=${OMASAFE_VERSION:?export OMASAFE_VERSION=<tag> before running}
base_url="https://github.com/tuthan/omasafe/releases/download/${version}"

# 1. Install from the pinned, reviewed installer URL.
step "install ${version}" run "
  set -euo pipefail
  curl -fsSL '${base_url}/install.sh' -o /tmp/omasafe-install-review.sh
  \$EDITOR /tmp/omasafe-install-review.sh   # review is part of the procedure
  bash /tmp/omasafe-install-review.sh --version '${version}'
"

# 2. Binary answers and reports provenance.
step "cli responds" run "'\$HOME/.local/bin/omasafe-cli' --version"
step "provenance json" run "'\$HOME/.local/bin/omasafe-cli' provenance --format json | head -c 400"

# 3. First scan works on a clean machine and writes state atomically.
step "first scan" run "'\$HOME/.local/bin/omasafe-cli' scan --format json | head -c 400"

# 4. Schedule coexistence: omasafe timer installed alongside omarchy timers.
step "schedule coexistence" run "
  systemctl --user list-timers | grep -i omasafe &&
  systemctl --user list-timers | grep -i omarchy
"

# 5. Upgrade = rerun installer for same/newer version; downgrade = explicit
# older pin. Both must succeed without orphaning state.
step "upgrade re-run" run "
  bash /tmp/omasafe-install-review.sh --version '${version}' &&
  '\$HOME/.local/bin/omasafe-cli' --version
"
if [[ -n ${OMASAFE_PREVIOUS_VERSION:-} ]]; then
  step "downgrade to ${OMASAFE_PREVIOUS_VERSION}" run "
    curl -fsSL 'https://github.com/tuthan/omasafe/releases/download/${OMASAFE_PREVIOUS_VERSION}/install.sh' |
      bash -s -- --version '${OMASAFE_PREVIOUS_VERSION}' &&
    '\$HOME/.local/bin/omasafe-cli' --version | grep -F '${OMASAFE_PREVIOUS_VERSION}'
  "
fi

# 6. Panel lifecycle: plugin installs, enables, rescans, disables cleanly.
# Requires the omasafe-plugin repo checked out in the VM.
step "panel validate" run "
  cd ~/Projects/omasafe-plugin && omarchy plugin validate .
"
step "panel enable/rescan" run "
  omarchy plugin enable io.github.tuthan.omasafe &&
  omarchy-shell shell rescanPlugins
"
step "panel disable" run "omarchy plugin disable io.github.tuthan.omasafe"

# 7. Third-party-bar notification independence: with a non-default bar in
# use, notify-send must still reach the session (OmaSafe never assumes its
# own panel is mounted).
step "notify independence" run "
  omarchy bar use omarchy.bar &&
  notify-send 'omasafe-lifecycle' 'independent of active bar' &&
  sleep 1
"

printf '\n=== lifecycle summary: %d failure(s) ===\n' "$failures"
if (( failures > 0 )); then
  printf 'Clean-VM lifecycle verification FAILED; do not cut the release.\n'
  exit 1
fi
printf 'Clean-VM lifecycle verification passed.\n'
