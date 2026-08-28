# Omarchy Plugin Security Surface

Verified: 2026-08-27 · Omarchy 4.0.1-1 · Quickshell 0.3.1-1 (package switched from
quickshell-git 0.3.0.r20 to the stable `quickshell` package between the 2026-08-25
reverification and this one)

Reverification 2026-08-27: version change detected and re-reviewed; shell.qml (38 KB) and
services/PluginRegistry.qml anchors present; Process/execDetached/FileView/network/Polkit/
PAM/WlSessionLock/Hyprland surfaces still reachable; plugin IPC unchanged; manifest
validation remains path containment with no third-party import allowlist; no rule meaning
changes. Remote-loading and lifecycle-staging answers below were obtained with
`scripts/h0-runtime-reverify.sh` against an ISOLATED quickshell instance plus static source
review of the installed `/usr/share/omarchy/shell` tree of this exact version. A clean-VM
re-run of the same script is required before the next release tag.

This is the versioned source-to-sink inventory for OmaSafe's plugin rules and threat model.
Reverify it for every supported Omarchy/Quickshell release. A newer unverified runtime
reduces coverage; it must never inherit a silent “supported” result.

## Reverified Answers OmaSafe Rules Depend On (H0, 2026-08-27)

1. **Remote / out-of-tree loading reachability.**
   - Network-loaded `Loader.source`: **REACHABLE.** Probe A served inert QML over loopback;
     the isolated instance instantiated it (`PROBE_A_LOADED: OMASAFE_REMOTE_MARKER_OK`,
     Loader status 1). No URL interceptor or network restriction exists in
     shell.qml/PluginRegistry.qml or the Quickshell 0.3.1 module set. The planned High rule
     for scheme literals in reference positions keeps its severity.
   - Remote directory imports (`import "https://…" [as X]`, qmldir-resolved): **NOT
     REACHABLE via that syntax.** Probe C: quickshell's scanner normalizes the URL string
     onto a relative filesystem path (`"…/probes/http://127.0.0.1/..."`) and drops it as an
     unresolvable import; nothing executes remotely through directory-import syntax. H2
     ships this form as an INDICATOR, never as the High remote-load finding.
   - `Qt.createComponent("http://…")`: **REACHABLE (asynchronous).** Probe B: the call
     enters `Component.Loading` and reaches `Component.Ready` with a working instance
     (`PROBE_B_READY: OMASAFE_REMOTE_MARKER_OK`). The probe polls for terminal status
     before deciding, because an immediate synchronous status check misreads Loading as
     failure. Scheme literals in `Qt.createComponent` positions share the High
     remote-component-load rule with `Loader.source`.
   - Out-of-tree absolute-path/traversal references resolve locally with no restriction
     (unchanged anchor: `entryPointUrl` only enforces manifest-level containment).
2. **Third-party lifecycle mutation reachability.** **REACHABLE.** Two independent routes:
   shell.qml injects live service objects into every plugin item — `pluginRegistry`,
   `shell`, `barWidgetRegistry`, `manifest` (shell.qml panel loader injection) — so plugin
   QML can call `pluginRegistry.setEnabled(...)` directly; and shell.qml's `IpcHandler`
   target "shell" exposes `rescanPlugins`, `setPluginEnabled`, `enablePlugin`,
   `putBarWidget`, `moveBarWidget`, `setBarWidget`, `listPlugins` to ANY local process via
   the public `omarchy-shell` CLI (omarchy-plugin-enable is itself just such a caller). A
   malicious plugin can therefore enable/disable lifecycle state without any native CLI
   involvement; `oma.shell.ipc-injected-objects` capability stays justified and first-party
   hooks must assume this route. Probe D (isolated shell copy, disposable HOME, explicit
   `OMASAFE_H0_ALLOW_LIFECYCLE=1` guard) confirmed the loop dynamically by running the REAL
   native helper (`omarchy plugin add <local marker repo> --enable --yes`): the helper
   cloned into a hidden `.add.tmp.*` staging dir, validated, renamed into place, rescanned
   via IPC, and enabled the marker (discovery + `enabled: true`); an IPC-only
   `setPluginEnabled … false` then flipped it to `enabled: false`, with no leftover staging
   directory.
3. **Inactive staging and install ordering.** `omarchy-plugin-add` clones into hidden
   `$PLUGINS_DIR/.add.tmp.$$` (hidden entries are ignored by both the registry scan glob
   and `localPluginIdForPath`), validates there, then `mv`s into `$PLUGINS_DIR/<id>` — a
   same-directory rename — before the optional enable step mutates shell.json via IPC. So:
   yes, an exact reviewed plugin tree CAN sit installed-and-inactive; the enabled state
   lives exclusively in shell.json mutated by IPC after placement. Residual window: during
   the final `mv`/rescan the registry's inotify watcher (`close_write,create,delete,move`)
   may observe the new tree before review completes, but no entry point loads until its id
   appears in shell.json (`bar.id`, `bar.layout.*`, or `plugins[]`). `omarchy-plugin-update`
   fast-forwards the LIVE worktree in place (rollback `git reset --hard ORIG_HEAD` on
   validation failure) — updates have NO inactive staging, which is why OmaSafe quiesces
   first. Consequence for H8a: hardened enable-gating CAN cover first install only up to
   the documented bypass (direct `omarchy plugin enable` / raw IPC), which stays a residual
   risk pending the upstream pre-activation hook proposal.

## Runtime Boundary

- Omarchy's bar, panels, overlays, menus, headless services, polkit agent, and lock screen
  run inside one long-lived `omarchy-shell` Quickshell process.
- First-party and enabled third-party plugins are discovered by the same plugin registry.
  Third-party entry points execute with the shell process's user permissions.
- Manifest validation enforces schema, safe relative entry-point paths, required files,
  reserved IDs, and no symlinks. These are path-containment/compatibility checks—not a
  runtime sandbox.
- The current source exposes the normal installed Quickshell and Qt Quick modules to plugin
  QML; there is no third-party import allowlist or per-plugin permission boundary.
- A plugin repository can ship arbitrary non-QML payloads and invoke them from QML. Only
  declared entry points are required to be QML.

## Verified Reachable Sinks and Sensitive Surfaces

| Surface | Security relevance | Initial OmaSafe treatment |
|---------|--------------------|---------------------------|
| `Quickshell.Io.Process` | Starts arbitrary argv; can invoke shells/interpreters and bundled payloads | Capability; finding depends on command/data provenance |
| `Quickshell.execDetached` | Starts detached processes; first-party helpers also use shell command strings | Capability; prioritize dynamic shell and bundled-payload edges |
| `FileView` | Reads/watches files and may participate in writes depending on use | Capability; raise priority for sensitive paths or persistence |
| QML/Qt networking | Can make outbound requests and retrieve runtime content | Capability; flag download/execute or sensitive exfiltration edges |
| `Timer` and `service` entry points | Enables periodic/headless behavior | Persistence/context signal, not malicious by itself |
| Clipboard access/helpers | May observe or replace clipboard contents | Capability; continuous headless monitoring is higher concern |
| Hyprland/Wayland APIs | Controls or observes compositor/session surfaces | Capability; severity follows concrete effect |
| `Quickshell.Services.Polkit` | Hosts authentication-agent UI in the shared process | High-priority third-party capability; architectural upstream concern |
| `WlSessionLock` / `WlSessionLockSurface` | Owns secure session-lock surfaces | High-priority third-party capability; near-zero ordinary plugin need |
| `PamContext` using Omarchy lock services | Handles password/fingerprint authentication flow | High-priority third-party capability; never infer password safety |
| Plugin/shell injected objects and IPC | May expose shell lifecycle/configuration operations | Inventory callable methods and bound arguments per release |

## H6 Capability Vocabulary (defined 2026-08-27; detectors land with their rules)

Capability observations assert presence of a sensitive surface, never intent. Escalation
predicates for evidence-backed findings (dataflow-connected egress, hidden/background
activation, dynamic attacker-controlled input) get their own stable finding IDs in the
v0.2.1 catalog; the vocabulary below is what those observations claim.

| Capability | Surface anchors / tools | Code variants that must be detected |
|---|---|---|
| `InputInjection` | `ydotool`, `wtype`, `wlrctl`, `hyprctl dispatch sendshortcut` | argv or shell-string use from plugin QML/scripts; legitimate automation is common, so escalation needs background/timer-driven invocation or dynamic keystroke content |
| `ScreenCapture` | `grim`, `slurp`, `wf-recorder`, `hyprshot`; Quickshell screenshot portals | argv use or Process invocation; escalate on timer/service-driven capture without user-visible trigger, or capture connected to an egress edge |
| `SensitiveDataAccess` | `~/.ssh`, `~/.gnupg`, keyring sockets (`ssh-agent`, `kwallet`, `gnome-keyring`), browser profile dirs, `~/.aws`, `~/.config/gh`, `~/.kube`, wallet directories | literal paths, `FileView.path`, `Process` args reading them. `/etc/shadow` stays OUT of the High set: normally unreadable to the user, so its reference is at most an intent indicator |

## Shared Polkit and Lock-Screen Threat

The first-party `omarchy.polkit` and `omarchy.lock` plugins share the process with community
plugins. Compromise of any loaded plugin therefore compromises the process that renders
authorization and lock UI, even though the system polkit/PAM services still enforce their
own protocols.

Consequences:

- OmaSafe cannot repair this architecture or treat the shell-rendered prompt as a trusted
  security boundary.
- Third-party imports/use of polkit, PAM, session-lock, or lock-surface APIs receive
  high-priority evidence-backed rules.
- The future root helper must remain safe even if arbitrary user-level QML requests a known
  action or interferes with UI. Fixed root-owned policy/action schemas bound the maximum
  privileged effect.
- Report the design exposure upstream independently of scanner implementation.

## Plugin-Kind Prioritization

All enabled plugin kinds share user-level permissions, so kind alone does not determine
severity.

- `service`: headless/long-running; prioritize for persistence and continuous monitoring.
- `bar`: replaces critical shell UI and cannot be disabled without selecting another bar;
  prioritize update/recovery testing. A third-party bar can omit OmaSafe's bar widget, so
  every such plugin receives a context capability (`replaces the bar`) and critical alerts
  must also use a shell-independent desktop-notification/CLI path.
- `overlay` / `panel` / `menu`: may capture focused input or imitate trusted surfaces;
  analyze activation and keyboard-focus behavior.
- `bar-widget`: usually long-running despite small UI; do not treat as low privilege.

Severity comes from the concrete sink, data flow, provenance, concealment, and user impact.

## Reverification Checklist

For each supported Omarchy release:

1. Record `omarchy version` and Quickshell version.
2. Inspect `shell.qml`, `PluginRegistry.qml`, plugin manifests, and plugin loader behavior.
3. Enumerate imports/usages of `Process`, `FileView`, `execDetached`, network APIs,
   Polkit, session lock, PAM, Wayland, and Hyprland surfaces.
4. Confirm whether third-party imports or injected objects are restricted.
5. Confirm plugin kinds, entry-point mapping, enable/disable/full-bar behavior, hot reload,
   and IPC methods such as `rescanPlugins` and `setPluginEnabled`. Re-run
   `scripts/h0-runtime-reverify.sh` (clean VM) to reproduce the remote-loading probes and
   record the three reverified answers above.
6. Run native/OmaSafe manifest-validator parity across the pinned corpus.
7. Version any changed rule meaning, capability mapping, or coverage limit.

## Primary References

- Omarchy plugin manual: https://omarchy.org/manual/shell-plugins/
- Omarchy source: https://github.com/basecamp/omarchy
- Marketplace security baseline:
  https://github.com/HANCORE-linux/omarchy-plugin-marketplace/blob/main/SECURITY.md
- Installed source anchors for the verified version:
  `/usr/share/omarchy/shell/shell.qml`,
  `/usr/share/omarchy/shell/services/PluginRegistry.qml`,
  `/usr/share/omarchy/shell/plugins/polkit/PolkitAgent.qml`, and
  `/usr/share/omarchy/shell/plugins/lock/Service.qml`.
