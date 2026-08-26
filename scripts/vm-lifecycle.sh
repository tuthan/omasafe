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
#
# VM prerequisites: an Omarchy session, the omasafe-plugin repo checked out
# at ~/Projects/omasafe-plugin (for the panel lifecycle steps), and no prior
# OmaSafe install.
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
  if out=$(run "$@" 2>&1); then
    printf 'PASS %s\n%s\n' "$name" "${out:0:500}"
  else
    printf 'FAIL %s\n%s\n' "$name" "$out"
    failures=$((failures + 1))
  fi
}

version=${OMASAFE_VERSION:?export OMASAFE_VERSION=<tag> before running}
# The reviewed installer is the tag's raw source script — the same URL the
# README tells users to review, so the VM exercises the documented path.
installer_url="https://raw.githubusercontent.com/tuthan/omasafe/${version}/scripts/install-cli.sh"

# 1. Install from the pinned, reviewed installer URL.
step "install ${version}" "
  set -euo pipefail
  curl --fail --proto '=https' --tlsv1.2 --location '${installer_url}' -o /tmp/omasafe-install-review.sh
  bash /tmp/omasafe-install-review.sh --version '${version}'
"
step "cli responds" "\$HOME/.local/bin/omasafe-cli --version"
step "provenance json" "\$HOME/.local/bin/omasafe-cli provenance --format json | head -c 400"

# 2. First scan works on a clean machine and writes state atomically.
step "first scan" "\$HOME/.local/bin/omasafe-cli scan --format json | head -c 400"

# 3. Schedule coexistence: omasafe timer installed alongside omarchy timers.
step "schedule coexistence" "
  systemctl --user list-timers | grep -i omasafe &&
  systemctl --user list-timers | grep -i omarchy
"

# 4. Upgrade = rerun installer for the same version; downgrade = explicit
# older pin. Both must succeed without orphaning state.
step "upgrade re-run" "
  bash /tmp/omasafe-install-review.sh --version '${version}' &&
  \$HOME/.local/bin/omasafe-cli --version
"
if [[ -n ${OMASAFE_PREVIOUS_VERSION:-} ]]; then
  step "downgrade to ${OMASAFE_PREVIOUS_VERSION}" "
    curl --fail --proto '=https' --tlsv1.2 --location \
      'https://raw.githubusercontent.com/tuthan/omasafe/${OMASAFE_PREVIOUS_VERSION}/scripts/install-cli.sh' \
      -o /tmp/omasafe-install-previous.sh &&
    bash /tmp/omasafe-install-previous.sh --version '${OMASAFE_PREVIOUS_VERSION}' &&
    \$HOME/.local/bin/omasafe-cli --version | grep -F '${OMASAFE_PREVIOUS_VERSION}'
  "
fi

# 5. Panel lifecycle: validate, enable + rescan, disable cleanly. Requires
# the omasafe-plugin checkout in the VM.
step "panel validate" "cd ~/Projects/omasafe-plugin && omarchy plugin validate ."
step "panel enable/rescan" "
  omarchy plugin enable io.github.tuthan.omasafe &&
  omarchy-shell shell rescanPlugins
"
step "panel visible in inventory" "\$HOME/.local/bin/omasafe-cli plugins inventory | grep io.github.tuthan.omasafe"
step "panel disable" "omarchy plugin disable io.github.tuthan.omasafe"

# 6. Third-party-bar notification independence: with the default bar forced
# back on, notify-send must still reach the session (OmaSafe never assumes
# its own panel is mounted).
step "notify independence" "
  omarchy bar use omarchy.bar &&
  notify-send 'omasafe-lifecycle' 'independent of active bar'
"

# 7. Uninstall: remove binary, schedule, and XDG trees; then verify nothing
# of OmaSafe persists. The panel plugin is native-managed and out of scope
# here beyond being disabled above.
step "uninstall" "
  set -euo pipefail
  systemctl --user disable --now omasafe-scan.timer || true
  rm -f ~/.config/systemd/user/omasafe-scan.service ~/.config/systemd/user/omasafe-scan.timer
  systemctl --user daemon-reload
  rm -f ~/.local/bin/omasafe-cli
  rm -rf ~/.cache/omasafe ~/.local/state/omasafe ~/.config/omasafe
"
step "post-uninstall persistence check" "! ls -d ~/.local/bin/omasafe-cli ~/.cache/omasafe ~/.local/state/omasafe ~/.config/omasafe ~/.config/systemd/user/omasafe-scan.* 2>/dev/null"

printf '\n=== lifecycle summary: %d failure(s) ===\n' "$failures"
if (( failures > 0 )); then
  printf 'Clean-VM lifecycle verification FAILED; do not cut the release.\n'
  exit 1
fi
printf 'Clean-VM lifecycle verification passed.\n'
