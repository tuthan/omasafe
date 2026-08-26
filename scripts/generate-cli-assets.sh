#!/usr/bin/env bash
set -euo pipefail

root_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
surface="$root_dir/docs/cli-surface.txt"
check_only=false
if [[ ${1:-} == "--check" ]]; then
  check_only=true
elif [[ $# -ne 0 ]]; then
  printf 'usage: %s [--check]\n' "$0" >&2
  exit 2
fi

[[ -f "$surface" ]] || { printf 'missing CLI surface: %s\n' "$surface" >&2; exit 1; }
top_level=$(awk -F '\t' '!/^#/ && NF {print $1}' "$surface" | awk '{print $1}' | sort -u | paste -sd' ' -)
[[ -n "$top_level" ]] || { printf 'CLI surface is empty\n' >&2; exit 1; }
package_version=$(awk -F '"' '/^version =/ {print $2; exit}' "$root_dir/Cargo.toml")
[[ -n "$package_version" ]] || { printf 'workspace version is missing\n' >&2; exit 1; }

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

write_asset() {
  local relative_path=$1
  local content=$2
  local target="$root_dir/$relative_path"
  local staged
  staged="$tmp_dir/$(basename "$relative_path")"
  mkdir -p "$(dirname "$target")"
  printf '%s\n' "$content" > "$staged"
  if $check_only; then
    cmp -s "$staged" "$target" || {
      printf 'generated asset is stale: %s\n' "$relative_path" >&2
      exit 1
    }
  else
    install -Dm644 "$staged" "$target"
  fi
}

write_asset docs/man/omasafe-cli.1 "$(cat <<EOF
.TH OMASAFE-CLI 1 "2026-08-21" "OmaSafe $package_version" "User Commands"
.SH NAME
omasafe-cli \- local trust and drift review for Omarchy plugins
.SH SYNOPSIS
.B omasafe-cli
.I COMMAND
.RI [ OPTIONS ]
.SH DESCRIPTION
OmaSafe inventories installed Omarchy plugins, compares them with trusted
baselines, and reports source drift. The CLI is the engine used by the optional
Omarchy bar-widget plugin.
.SH COMMANDS
.TP
.B paths
Print the XDG configuration, state, and cache paths used by OmaSafe.
.TP
.B provenance [--format text|json]
Print the deterministic build self-inventory, source revision, toolchain,
lockfile identity, supported runtime versions, and coverage limitations.
.TP
.B scan [--format text|json] [--notify] [--only-new] [--include-analysis]
Inventory plugins and report new or outstanding findings. Exit status 3 means
actionable findings remain. \fB--include-analysis\fR opts in to per-plugin
analysis events (new capabilities, finding regressions, analyzer-policy
updates, fingerprint instability); default scans stay quiet.
.TP
.B plugins inventory
Print the installed plugin inventory and marketplace correlation.
.TP
.B plugins trust PLUGIN_ID
Show a plugin identity and interactively accept it, or use explicit expected
identity values with --yes.
.TP
.B plugins status PLUGIN_ID
Report whether a plugin matches its trusted baseline.
.TP
.B plugins diff PLUGIN_ID
Show the file-level differences from the trusted baseline.
.TP
.B plugins review PLUGIN_ID
Acknowledge findings, change review decisions, rebaseline, restore, or untrust a
plugin. Untrust revokes the active baseline while preserving its history.
Suppress/reinstate manage scoped analysis suppressions
(\fB--rule RULE_ID\fR, optional \fB--path SCOPE\fR inside the plugin) recorded
with a reason in XDG config; they hide and de-enforce findings without ever
altering stored analysis results, and reinstating preserves the audit trail.
.TP
.B plugins review-update PLUGIN_ID [--expected-commit SHA] [--yes]
Review an exact candidate commit before updating: refuses on a dirty installed
worktree, fetches the pinned candidate into the bounded cache, validates it,
presents the delta versus the trusted baseline, then delegates the mutation to
the native updater. Unattended use requires --expected-commit with --yes;
postconditions (exact HEAD, rescan) must pass before the plugin is re-enabled
or trusted.
.TP
.B rules list [--format text|json]
Print the OmaSafe-owned capability rule catalog with severities, capabilities,
and review guidance. The catalog is static and versioned through the analyzer
policy identity.
.TP
.B rules explain RULE_ID [--format text|json]
Print one rule's full definition: severity, capability, verified surface
anchor, summary, review guidance, and any recorded marketplace-baseline
equivalence entries.
.TP
.B plugins analyze PLUGIN_ID [--format text|json] [--fail-on SEVERITY]
Inventory every shipped payload file of an installed plugin with type, mode,
size, digest, executable bit, and explicit analysis coverage state. Exit
status is 0 even when findings exist; CI policy uses --fail-on.
.TP
.B scan-plugin (--path DIR | --git URL --revision COMMIT) [--format text|json]
    [--fail-on SEVERITY]
Run the same bounded payload inventory against a local directory or a pinned
immutable Git revision read as raw objects (no checkout, filters, hooks, or
submodules). URLs carrying credentials are rejected.
.TP
.B marketplace refresh (--commit COMMIT | --latest)
Fetch and verify a pinned marketplace snapshot.
.TP
.B schedule install
Install the user-level scheduled scan unit.
.SH FILES
The configuration, state, and cache roots follow XDG_CONFIG_HOME,
XDG_STATE_HOME, and XDG_CACHE_HOME, defaulting to ~/.config/omasafe,
~/.local/state/omasafe, and ~/.cache/omasafe.
.SH EXIT STATUS
.TP
.B 0
The command completed successfully and no actionable scan findings remain.
.TP
.B 1
The command failed.
.TP
.B 2
Usage error: unrecognized top-level command.
.TP
.B 4
Only for \fBplugins analyze\fR and \fBscan-plugin\fR with \fB--fail-on SEVERITY\fR:
at least one finding met or exceeded the threshold. Findings are still a
successful report; the exit code is the CI opt-in signal, separate from
\fBscan\fR's actionable-result exit code 3.
.TP
.B 3
The scan completed and actionable findings remain.
.SH SEE ALSO
.BR omasafe-cli (1)
EOF
)"

write_asset docs/completions/omasafe-cli.bash "$(cat <<EOF
# bash completion for omasafe-cli; generated from docs/cli-surface.txt
_omasafe_cli() {
    local cur prev
    COMPREPLY=()
    cur="\${COMP_WORDS[COMP_CWORD]}"
    prev="\${COMP_WORDS[COMP_CWORD-1]:-}"
    local commands="$top_level"
    if [[ "\${COMP_CWORD}" -eq 1 ]]; then
        COMPREPLY=(\$(compgen -W "\${commands}" -- "\${cur}"))
        return
    fi
    case "\${COMP_WORDS[1]}" in
        scan|provenance|plugins|marketplace|rules|scan-plugin)
            COMPREPLY=(\$(compgen -W "--format --notify --only-new --include-analysis --yes --expected-head --expected-tree --expected-digest --action --reason --rule --path --commit --latest --git --revision --fail-on" -- "\${cur}"))
            ;;
        paths|schedule)
            COMPREPLY=()
            ;;
    esac
}
complete -F _omasafe_cli omasafe-cli
EOF
)"

write_asset docs/completions/_omasafe-cli "$(cat <<EOF
#compdef omasafe-cli
# zsh completion for omasafe-cli; generated from docs/cli-surface.txt
_arguments '1:command:($top_level)' '*:option:(--format --notify --only-new --include-analysis --yes --expected-head --expected-tree --expected-digest --action --reason --rule --path --commit --latest --git --revision --fail-on)'
EOF
)"

write_asset docs/completions/omasafe-cli.fish "$(cat <<EOF
# fish completion for omasafe-cli; generated from docs/cli-surface.txt
complete -c omasafe-cli -f -n "__fish_use_subcommand" -a "$top_level"
complete -c omasafe-cli -l format -r -a "text json"
complete -c omasafe-cli -l notify
complete -c omasafe-cli -l only-new
complete -c omasafe-cli -l include-analysis
complete -c omasafe-cli -l yes
complete -c omasafe-cli -l expected-head -r
complete -c omasafe-cli -l expected-tree -r
complete -c omasafe-cli -l expected-digest -r
complete -c omasafe-cli -l action -r -a "acknowledge exclude rebaseline restore untrust revoke suppress reinstate"
complete -c omasafe-cli -l reason -r
complete -c omasafe-cli -l rule -r
complete -c omasafe-cli -l commit -r
complete -c omasafe-cli -l path -r
complete -c omasafe-cli -l git -r
complete -c omasafe-cli -l revision -r
complete -c omasafe-cli -l fail-on -r -a "info low medium high critical"
EOF
)"

if ! $check_only; then
  chmod 755 "$root_dir/scripts/generate-cli-assets.sh"
fi
