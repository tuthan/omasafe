#!/usr/bin/env bash
# H0 runtime reverification probes (plan slice H0):
#   Probe A: network Loader.source (remote QML component load)
#   Probe B: Qt.createComponent("http://...") — asynchronous completion
#   Probe C: network directory import with qmldir + `as` qualifier
#   Probe D: native plugin lifecycle against an ISOLATED shell profile
#
# Safety contract:
#   A/B/C each run an ISOLATED quickshell instance (separate process, throwaway
#   HOME/STATE/CACHE dirs); they never touch the running omarchy-shell or any
#   installed plugin tree. QML served from 127.0.0.1 is inert: properties only,
#   no IO, no imports beyond QtQuick.
#   Probe D requires OMASAFE_H0_ALLOW_LIFECYCLE=1. It runs the REAL native
#   install helper (`omarchy plugin add <local-marker-repo> --enable --yes`)
#   against a disposable profile: a disposable HOME (plugins dir + shell.json
#   live there) and a disposable copy of the installed shell config with a
#   UNIQUE instance path, so the live session shell is never addressed. It
#   then asserts discovery, enable, and IPC-only disable transitions. Prefer
#   running inside the clean VM; on a maintainer session it briefly renders a
#   second, empty bar.
#
# Exit status: 0 only when every probe asserted its expected markers;
# 2 for a lifecycle-guard refusal; 1 for any timeout, error, refused, or
# missing-marker outcome.
set -uo pipefail

work=$(mktemp -d /tmp/omasafe-h0.XXXXXX)
port=$((8300 + RANDOM % 300))
with_lifecycle=0
lifecycle_refused=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-lifecycle) with_lifecycle=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
cleanup() { [[ ${server_pid:-} ]] && kill "$server_pid" 2>/dev/null; [[ ${shell_pid:-} ]] && kill "$shell_pid" 2>/dev/null; rm -rf "$work"; }
trap cleanup EXIT

declare -i failures=0
note_fail() { echo "  FAIL: $*"; failures+=1; }
note_pass() { echo "  PASS: $*"; }
# expect/forbid take an extended regex and a log file.
expect() { if grep -Eq "$1" "$2"; then note_pass "$3"; else note_fail "$3 (missing marker: $1)"; fi; }
forbid() { if grep -Eq "$1" "$2"; then note_fail "$3 (forbidden marker present: $1)"; else note_pass "$3"; fi; }

mkdir -p "$work/served/deep-net-plugin" "$work/probes" "$work/home/.config" "$work/state" "$work/cache"
cat > "$work/served/marker.qml" <<'EOF'
import QtQuick
Item {
    property string markerText: "OMASAFE_REMOTE_MARKER_OK"
}
EOF
cat > "$work/served/deep-net-plugin/qmldir" <<'EOF'
singleton NetProbe 1.0 netprobe.qml
EOF
cat > "$work/served/deep-net-plugin/netprobe.qml" <<'EOF'
pragma Singleton
import QtQuick
QtObject {
    property string token: "OMASAFE_NETDIR_TOKEN_OK"
}
EOF

python3 - "$port" "$work/served" <<'PY' &
import http.server, socketserver, functools, sys
port, root = int(sys.argv[1]), sys.argv[2]
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=root)
socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(("127.0.0.1", port), handler).serve_forever()
PY
server_pid=$!
for _ in $(seq 50); do
  curl -fsS "http://127.0.0.1:$port/marker.qml" >/dev/null 2>&1 && break
  sleep 0.1
done

cat > "$work/probes/probeA.qml" <<QML
import QtQuick
import Quickshell
ShellRoot {
    Timer { id: guardTimer; interval: 8000; running: true; onTriggered: { console.log("PROBE_A_TIMEOUT"); Qt.exit(3) } }
    Loader {
        source: "http://127.0.0.1:$port/marker.qml"
        onLoaded: {
            console.log("PROBE_A_LOADED:", item ? item.markerText : "no-item")
            guardTimer.stop()
            Qt.exit(0)
        }
        onStatusChanged: console.log("PROBE_A_STATUS:", status)
    }
    Component.onCompleted: console.log("PROBE_A_UP")
}
QML

cat > "$work/probes/probeB.qml" <<QML
import QtQuick
import Quickshell
ShellRoot {
    Timer { interval: 15000; running: true; onTriggered: { console.log("PROBE_B_TIMEOUT"); Qt.exit(3) } }
    Item {
        id: host
        property var pending: null
        property int polls: 0
        Component.onCompleted: {
            pending = Qt.createComponent("http://127.0.0.1:$port/marker.qml")
            console.log("PROBE_B_INITIAL_STATUS:", pending ? pending.status : "null")
        }
        Timer {
            interval: 500
            running: host.pending !== null
            repeat: true
            onTriggered: {
                var comp = host.pending
                if (!comp) return
                host.polls++
                if (comp.status === Component.Ready) {
                    var obj = comp.createObject(null)
                    console.log("PROBE_B_READY:", obj && obj.markerText ? obj.markerText : "created-no-marker")
                    if (obj) obj.destroy()
                    Qt.exit(0)
                } else if (comp.status === Component.Error) {
                    console.log("PROBE_B_ERROR:", comp.errorString())
                    Qt.exit(2)
                } else {
                    console.log("PROBE_B_LOADING:", comp.status, "poll", host.polls)
                }
            }
        }
    }
    Component.onCompleted: console.log("PROBE_B_UP")
}
QML

cat > "$work/probes/probeC.qml" <<QML
import QtQuick
import Quickshell
import "http://127.0.0.1:$port/deep-net-plugin" as NetDir
ShellRoot {
    Timer { id: guardTimer; interval: 8000; running: true; onTriggered: { console.log("PROBE_C_TIMEOUT"); Qt.exit(3) } }
    Item {
        Component.onCompleted: {
            var present = typeof NetDir.NetProbe !== "undefined"
            console.log("PROBE_C_QUALIFIED:", present ? "type-present" : "type-missing")
            if (!present) {
                guardTimer.stop()
                Qt.exit(0)
                return
            }
            try {
                var t = NetDir.NetProbe.token
                console.log("PROBE_C_TOKEN:", typeof t !== "undefined" ? t : "no-token")
                guardTimer.stop()
                Qt.exit(0)
            } catch (e) {
                console.log("PROBE_C_TOKEN_FAILED:", e)
            }
        }
    }
    Component.onCompleted: console.log("PROBE_C_UP")
}
QML

run_probe() {
  local name="$1" file="$2"
  env HOME="$work/home" XDG_STATE_HOME="$work/state" XDG_CACHE_HOME="$work/cache" \
      timeout 25 quickshell -p "$file" >"$work/$name.log" 2>&1
  probe_rc=$?
  if [[ $probe_rc == 124 ]]; then
    note_fail "$name timed out (quickshell killed by the 25s ceiling)"
  fi
  echo "--- $name (quickshell exit: $probe_rc) ---"
  grep -E "PROBE_" "$work/$name.log" | sed 's/^/    /' || true
}

echo "--- PROBE A: network Loader.source ---"
run_probe probeA "$work/probes/probeA.qml"
expect 'PROBE_A_LOADED: OMASAFE_REMOTE_MARKER_OK' "$work/probeA.log" "remote Loader marker instantiated"
forbid 'PROBE_A_TIMEOUT' "$work/probeA.log" "probe A terminated with a verdict"
[[ $probe_rc == 0 ]] || note_fail "probe A returned unexpected exit $probe_rc"

echo "--- PROBE B: Qt.createComponent (async completion) ---"
run_probe probeB "$work/probes/probeB.qml"
expect 'PROBE_B_READY: OMASAFE_REMOTE_MARKER_OK' "$work/probeB.log" "remote createComponent reached Ready with a working instance"
forbid 'PROBE_B_ERROR' "$work/probeB.log" "no component error surfaced"
forbid 'PROBE_B_TIMEOUT' "$work/probeB.log" "probe B terminated with a verdict"
[[ $probe_rc == 0 ]] || note_fail "probe B returned unexpected exit $probe_rc"

echo "--- PROBE C: remote directory import ---"
run_probe probeC "$work/probes/probeC.qml"
# Interception evidence: the scanner refuses the import (relative-path
# normalization) OR the config loads but the type is missing. A fetched token
# would mean the runtime started resolving remote directory imports — that
# flips the H2 severity split and must fail this probe.
if grep -Eq 'Ignoring unresolvable import' "$work/probeC.log"; then
  # The verified runtime (Quickshell 0.3.1) exits 255 for this expected
  # rejection; enforce it so a later crash cannot reuse the interception
  # marker and pass.
  if [[ $probe_rc == 255 ]]; then
    note_pass "remote directory import was intercepted"
  else
    note_fail "interception branch returned unexpected exit $probe_rc (expected 255)"
  fi
elif grep -Eq 'PROBE_C_QUALIFIED: type-missing' "$work/probeC.log"; then
  note_pass "remote directory import resolved to a missing type"
  [[ $probe_rc == 0 ]] || note_fail "probe C type-missing verdict returned unexpected exit $probe_rc"
else
  note_fail "no interception evidence for the remote directory import"
fi
forbid 'PROBE_C_TIMEOUT' "$work/probeC.log" "probe C did not hit its timeout guard"
forbid 'OMASAFE_NETDIR_TOKEN_OK' "$work/probeC.log" "no remote token was fetched"

echo "--- PROBE D: native install lifecycle (isolated profile) ---"
if [[ $with_lifecycle != 1 ]]; then
  echo "  skipped: pass --with-lifecycle to run it"
elif [[ ${OMASAFE_H0_ALLOW_LIFECYCLE:-} != "1" ]]; then
  echo "  PROBE_D_REFUSED: set OMASAFE_H0_ALLOW_LIFECYCLE=1 (ideally inside the clean VM) to run the lifecycle probe"
  lifecycle_refused=1
  with_lifecycle=0
fi

if [[ $with_lifecycle == 1 ]]; then
  # Disposable shell copy: omarchy-shell requires $OMARCHY_PATH/shell/shell.qml,
  # and the copy's unique config path keeps qs instance selection pointed at
  # OUR instance, never the live session's.
  mkdir -p "$work/omarchy"
  cp -r /usr/share/omarchy/shell "$work/omarchy/shell"
  plugins_dir="$work/home/.config/omarchy/plugins"
  mkdir -p "$plugins_dir"

  # Marker plugin source repo (inert) the native helper can clone from a
  # local path; omarchy-git-url-check permits bare paths.
  marker_src="$work/marker-src"
  git init -q "$marker_src"
  cat > "$marker_src/manifest.json" <<'EOF'
{"schemaVersion":1,"id":"omasafe.h0.marker","name":"H0 marker","version":"1","kinds":["bar-widget"],"entryPoints":{"barWidget":"main.qml"}}
EOF
  printf 'import QtQuick\nItem { property bool inert: true }\n' > "$marker_src/main.qml"
  git -C "$marker_src" add -A
  git -C "$marker_src" -c user.name=probe -c user.email=probe@localhost commit -q -m marker

  ipc() {
    OMARCHY_PATH="$work/omarchy" timeout 10 qs ipc -n -p "$work/omarchy/shell/shell.qml" call shell "$@"
  }
  marker_enabled() {
    # The registry mutates shell.json and reloads asynchronously; poll past
    # the transient window where listPlugins can come back empty.
    local state
    for _ in $(seq 30); do
      state=$(ipc listPlugins 2>/dev/null \
        | jq -r '[.[] | select(.id == "omasafe.h0.marker")][0] | if . == null then "absent" else (.enabled | tostring) end' 2>/dev/null) || state=absent
      [[ $state != "absent" ]] && break
      sleep 0.1
    done
    echo "$state"
  }

  env HOME="$work/home" XDG_STATE_HOME="$work/state" XDG_CACHE_HOME="$work/cache" \
      quickshell -p "$work/omarchy/shell/shell.qml" >"$work/probeD-shell.log" 2>&1 &
  shell_pid=$!

  up=0
  for _ in $(seq 100); do
    if [[ $(OMARCHY_PATH="$work/omarchy" timeout 10 qs ipc -n -p "$work/omarchy/shell/shell.qml" call shell ping 2>/dev/null) == "ok" ]]; then
      up=1
      break
    fi
    sleep 0.1
  done
  if [[ $up != 1 ]]; then
    note_fail "isolated shell never answered ping (PROBE_D_FAILED)"
    sed 's/^/    /' "$work/probeD-shell.log" | head -30
  else
    # The REAL native helper, end to end: hidden .add.tmp staging, validate,
    # rename, rescanPlugins IPC, discovery wait, enable. Disposable HOME keeps
    # the plugins dir and shell.json writes out of the live profile.
    env HOME="$work/home" XDG_STATE_HOME="$work/state" XDG_CACHE_HOME="$work/cache" \
        OMARCHY_PATH="$work/omarchy" PATH="/usr/share/omarchy/bin:$PATH" \
        omarchy plugin add "$marker_src" --enable --yes >"$work/probeD-add.log" 2>&1
    add_rc=$?
    echo "  omarchy plugin add exit: $add_rc"
    sed 's/^/    /' "$work/probeD-add.log" | head -10
    if [[ $add_rc == 0 ]]; then
      note_pass "native helper installed and enabled the marker (PROBE_D_ADDED)"
    else
      note_fail "native helper failed (PROBE_D_FAILED)"
    fi
    state=$(marker_enabled)
    if [[ $state == "true" ]]; then
      note_pass "marker discovered and enabled via native helper"
    else
      note_fail "marker not enabled after native add (state: $state)"
    fi
    ipc setPluginEnabled 'omasafe.h0.marker' false >/dev/null 2>&1
    state=$(marker_enabled)
    if [[ $state == "false" ]]; then
      note_pass "IPC-only disable transition verified"
    else
      note_fail "disable transition not observed (state: $state)"
    fi
    if ls -d "$plugins_dir"/.add.tmp.* >/dev/null 2>&1; then
      note_fail "hidden staging directory leaked past the native add"
    else
      note_pass "no leftover hidden staging directory"
    fi
  fi
  kill "$shell_pid" 2>/dev/null
  wait "$shell_pid" 2>/dev/null
  shell_pid=""
fi

echo
echo "=== verdict summary ==="
if (( lifecycle_refused == 1 )); then
  echo "  lifecycle probe refused by guard — rerun with OMASAFE_H0_ALLOW_LIFECYCLE=1"
  exit 2
fi
if (( failures > 0 )); then
  echo "  $failures assertion(s) FAILED — treat H0 as unverified and investigate"
  exit 1
fi
echo "  all probe assertions passed"
