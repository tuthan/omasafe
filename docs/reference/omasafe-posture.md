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

Tools are resolved from fixed absolute directories (`/usr/bin`, `/usr/sbin`,
`/bin`, `/sbin`) or an explicit absolute fixture directory. The inherited
`PATH` is never used for posture tools. Child environments are cleared and
stderr is discarded. A command that is missing, denied, timed out, truncated,
or malformed yields `incomplete` with a bounded explanation.

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
OmaSafe-owned script.

`posture digest` renders the last completed report as a compact weekly support
digest; it never runs host commands or changes the monitored system.

The state file `posture-state.json` retains the last check state and one active
coverage episode per stable check ID. The first missing dependency is visible
without a recurring notification; a later transition from an observed state
to `incomplete` or `error` produces one notification, unchanged failures stay
quiet, and recovery closes the episode so a later loss can notify again.
New regression or attention states follow the same deduplicated transition
model; a stable machine does not generate a daily desktop notification.
