# Omarchy Plugin Security Surface

Verified: 2026-08-20 · Omarchy 4.0.0-1 · Quickshell 0.3.0

This is the versioned source-to-sink inventory for OmaSafe's plugin rules and threat model.
Reverify it for every supported Omarchy/Quickshell release. A newer unverified runtime
reduces coverage; it must never inherit a silent “supported” result.

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
   and IPC methods such as `rescanPlugins` and `setPluginEnabled`.
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
