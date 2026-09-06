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

# 2. A clean VM starts without installed-scan snapshots. The first scan writes
# the advisory profile atomically and never treats cache persistence as a scan
# failure (exit 0 or the documented actionable exit 3 are both valid).
step "no snapshot on clean VM" "! test -e \"\$HOME/.cache/omasafe/scan-snapshots/installed-basic.json\" && ! test -e \"\$HOME/.cache/omasafe/scan-snapshots/installed-analysis.json\""
step "first scan" "
  set -e
  set +e
  \$HOME/.local/bin/omasafe-cli scan --format json >/tmp/omasafe-first-scan.json
  code=\$?
  set -e
  test \"\$code\" -eq 0 || test \"\$code\" -eq 3
"
step "basic snapshot is private and complete" "
  test -f \"\$HOME/.cache/omasafe/scan-snapshots/installed-basic.json\" &&
  test \"\$(stat -c '%a' \"\$HOME/.cache/omasafe/scan-snapshots/installed-basic.json\")\" = 600 &&
  grep -q '\"schema\": \"omasafe.scan-snapshot.v1\"' \"\$HOME/.cache/omasafe/scan-snapshots/installed-basic.json\" &&
  grep -q '\"scan_profile\": \"installed-basic\"' \"\$HOME/.cache/omasafe/scan-snapshots/installed-basic.json\"
"

# 3. Advisory timers write the basic profile; hardened timers write the shared
# analysis profile. Both retain the same private cache path in ReadWritePaths.
step "advisory timer writes basic profile" "
  \$HOME/.local/bin/omasafe-cli schedule install --policy advisory >/dev/null &&
  grep -q 'scan --notify --only-new$' \"\$HOME/.config/systemd/user/omasafe-scan.service\" &&
  ! grep -q -- '--include-analysis' \"\$HOME/.config/systemd/user/omasafe-scan.service\"
"
step "hardened timer writes analysis profile" "
  \$HOME/.local/bin/omasafe-cli schedule install --policy hardened >/dev/null &&
  grep -q 'scan --notify --only-new --include-analysis$' \"\$HOME/.config/systemd/user/omasafe-scan.service\" &&
  grep -q 'ReadWritePaths=.*\.cache/omasafe' \"\$HOME/.config/systemd/user/omasafe-scan.service\"
"

# 4. Schedule coexistence: omasafe timer installed alongside omarchy timers.
step "schedule coexistence" "
  systemctl --user list-timers | grep -i omasafe &&
  systemctl --user list-timers | grep -i omarchy
"

# 5. Generate the shared analysis profile, then exercise read-only hydration
# and validation. The widget uses this same profile through scan-cache show.
step "analysis scan profile" "
  set +e
  \$HOME/.local/bin/omasafe-cli scan --include-analysis --format json >/tmp/omasafe-analysis-scan.json
  code=\$?
  set -e
  test \"\$code\" -eq 0 || test \"\$code\" -eq 3
"
step "analysis snapshot hydrates" "
  test -f \"\$HOME/.cache/omasafe/scan-snapshots/installed-analysis.json\" &&
  \$HOME/.local/bin/omasafe-cli scan-cache show --profile installed-analysis --format json | grep -q 'cached-unvalidated'
"
step "basic snapshot validates" "
  \$HOME/.local/bin/omasafe-cli scan-cache show --profile installed-basic --validate --format json | grep -q 'cached-valid\|cached-stale\|cached-unvalidated'
"

# 6. Upgrade = rerun installer for the same version; downgrade = explicit
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

# 7. Panel lifecycle: validate, enable + rescan, disable cleanly. Requires
# the omasafe-plugin checkout in the VM.
step "panel validate" "cd ~/Projects/omasafe-plugin && omarchy plugin validate ."
step "panel enable/rescan" "
  omarchy plugin enable io.github.tuthan.omasafe &&
  omarchy-shell shell rescanPlugins
"
step "panel visible in inventory" "\$HOME/.local/bin/omasafe-cli plugins inventory | grep io.github.tuthan.omasafe"
step "panel cache hydration" "
  \$HOME/.local/bin/omasafe-cli scan-cache show --profile installed-analysis --format json | grep -q 'cached-'
"
step "panel disable" "omarchy plugin disable io.github.tuthan.omasafe"

# 8. Mutation, failed rescan retention, restored replacement, incompatible
# schema refusal, and safe cache deletion. All of these operate on the
# disposable VM cache only; trust/enforcement state stays outside this tree.
step "inventory mutation becomes stale" "
  probe=\"\$HOME/.config/omarchy/plugins/io.github.tuthan.omasafe/.omasafe-lifecycle-probe\"
  touch \"\$probe\"
  \$HOME/.local/bin/omasafe-cli scan-cache show --profile installed-basic --validate --format json | grep -q 'cached-stale\|inventory-changed'
  rm -f \"\$probe\"
"
step "failed rescan retains snapshot" "
  cache=\"\$HOME/.cache/omasafe/scan-snapshots/installed-basic.json\"
  cli=\"\$HOME/.local/bin/omasafe-cli\"
  backup=\"\$HOME/.local/bin/omasafe-cli.lifecycle-backup\"
  test -f \"\$cache\"
  mv \"\$cli\" \"\$backup\"
  set +e
  \"\$cli\" scan --format json >/dev/null 2>&1
  code=\$?
  set -e
  mv \"\$backup\" \"\$cli\"
  test \"\$code\" -ne 0 && test -s \"\$cache\"
"
step "successful rescan advances generation" "
  cache=\"\$HOME/.cache/omasafe/scan-snapshots/installed-basic.json\"
  before=\$(sed -n 's/.*\"generation\": \([0-9][0-9]*\),/\1/p' \"\$cache\")
  set +e
  \$HOME/.local/bin/omasafe-cli scan --format json >/dev/null 2>&1
  code=\$?
  set -e
  after=\$(sed -n 's/.*\"generation\": \([0-9][0-9]*\),/\1/p' \"\$cache\")
  test \"\$code\" -eq 0 || test \"\$code\" -eq 3
  test -n \"\$before\" && test -n \"\$after\" && test \"\$after\" -gt \"\$before\"
"
step "incompatible schema is refused" "
  cache=\"\$HOME/.cache/omasafe/scan-snapshots/installed-basic.json\"
  backup=\"\$cache.lifecycle-backup\"
  cp \"\$cache\" \"\$backup\"
  sed -i 's/omasafe.scan-snapshot.v1/omasafe.scan-snapshot.legacy/' \"\$cache\"
  \$HOME/.local/bin/omasafe-cli scan-cache show --profile installed-basic --format json | grep -q 'incompatible\|corrupt'
  mv \"\$backup\" \"\$cache\"
"
step "cache deletion preserves state" "
  test -d \"\$HOME/.local/state/omasafe\" &&
  rm -rf -- \"\$HOME/.cache/omasafe/scan-snapshots\" &&
  ! test -e \"\$HOME/.cache/omasafe/scan-snapshots/installed-basic.json\" &&
  test -d \"\$HOME/.local/state/omasafe\"
"

# 9. Third-party-bar notification independence: with the default bar forced
# back on, notify-send must still reach the session (OmaSafe never assumes
# its own panel is mounted).
step "notify independence" "
  omarchy bar use omarchy.bar &&
  notify-send 'omasafe-lifecycle' 'independent of active bar'
"

# 10. Uninstall: remove binary, schedule, and XDG trees; then verify nothing
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
