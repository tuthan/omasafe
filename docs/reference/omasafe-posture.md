# OmaSafe posture report contract

The host posture family is independent from `omasafe.report.v1`, which is
plugin-scoped. `omasafe-cli posture scan --format json` emits
`omasafe.posture.v1`; the same report is kept at the private XDG state path as
`posture-report.json`. `posture export` reads that last completed report without
running host commands.

Each check has a stable ID, a state, bounded evidence, an observation time,
dependencies, coverage limitations, and a read-only next step. `incomplete` and
`error` are non-passing states and are preserved in text, JSON, Markdown, and
the state transition record. A missing optional dependency is visible in the
report; it does not become a pass.

`generated_at` and each check's `observed_at` are UTC RFC3339 seconds (`2026-09-08T00:00:00Z`).
JSON exports add `result_age_seconds`; consumers should surface a stale report
when that age exceeds their product freshness window.

The initial catalog is version 1:

| ID | Scope |
| --- | --- |
| `host.context` | Arch/Omarchy context |
| `updates.repository` | Repository package updates |
| `updates.omarchy` | Packaged Omarchy or development checkout updates |
| `vulnerabilities.arch_audit` | Official repository advisory coverage |
| `encryption.root_luks` | Root block-device ancestry |
| `firewall.configuration` | Readable nftables/ufw configuration |
| `firewall.service` | Firewall frontend service state |
| `firewall.effective` | Runtime firewall policy |
| `network.listeners` | Listening sockets and bounded attribution |
| `kernel.restart` | Running and installed kernel metadata |
| `packages.foreign` | Foreign package inventory |
| `packages.keyring` | Pacman keyring presence |
| `persistence.selected` | Selected system persistence locations |
| `execution.path` | World-writable PATH entries |
| `boot.secure_boot` | Informational firmware state |
| `ssh.configuration` | Applicable only when sshd is active |
| `packages.integrity` | Weekly integrity profile marker |
| `updates.post_update_hook` | Last observed Omarchy post-update hook |

Tools are resolved only from fixed, root-owned, non-group-writable absolute
directories (`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`). The inherited `PATH`
and `OMASAFE_POSTURE_TOOL_DIR` are never used for production posture tools;
fixture adapters are test-only. Child environments are cleared and stderr is
discarded from the report. A command that is missing, denied, timed out, truncated,
or malformed yields `incomplete` with a bounded explanation.

Repository updates run `checkupdates --nocolor` with `TMPDIR` pointing at a
private, mode-0700 OmaSafe temporary directory. Exit-0 output is retained as a
complete inventory. No-update exit 1/2 branches require a readable `sync/core.db`
and a clean `pacman -Qu --dbpath <private-db>` query; empty stdout with stderr,
missing sync metadata, or any other query failure is incomplete. Stale
`omasafe-checkupdates-*` directories older than one hour are swept before a new
database is created.

Secure Boot is read from `bootctl status --no-pager` when `/sys/firmware/efi`
exists. Legacy-BIOS hosts report `not_applicable`. Firewall configuration reads
`/etc/nftables.conf` or `/etc/ufw/*`; effective nftables policy is passing only
when a runtime base chain has both a hook and a default policy.

The collected host fields are limited to OS, architecture, Omarchy path and
version when available, running kernel, tool names/paths/versions, check
evidence, and coverage explanations. Raw process arguments, usernames, peer
addresses, file contents, secrets, and unrelated machine identifiers are not
stored in the default report.

The OmaSafe post-update hook is installed explicitly with `posture hook
install`. Its atomic private stamp records only that the Omarchy updater
reached the `post-update` stage. `posture hook self-test` executes the exact
installed script against an isolated test stamp and verifies that production
history did not move. A verified stamp is never described as completion of the
entire Omarchy update.

`posture hook uninstall` removes the hook only when its bytes still match the
OmaSafe-owned script. Installing the current hook also removes an exact copy
left at the pre-v0.3 `$XDG_CONFIG_HOME/omarchy/hooks/post-update.d` path.

`posture digest` renders the last completed report as a bounded support summary;
it has no time-window or episode aggregation yet, never runs host commands, and
does not change the monitored system.

The state file `posture-state.json` retains the last check state and one active
coverage episode per stable check ID. The first missing dependency is visible
without a recurring notification; a later transition from an observed state
to `incomplete` or `error` produces one notification, unchanged failures stay
quiet, and recovery closes the episode so a later loss can notify again.
New regression or attention states follow the same deduplicated transition
model; a stable machine does not generate a daily desktop notification.
