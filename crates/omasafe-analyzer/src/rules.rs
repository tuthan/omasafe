//! OmaSafe-owned rule catalog and severity table.
//!
//! Rule IDs and meanings are stable after publication (rule contract). Every
//! definition below maps to a verified sink or payload edge recorded in
//! `docs/reference/omarchy-security-surface.md`. Capability detection is
//! separate from suspicious behavior: a capability result alone never asserts
//! malicious intent.

use serde::Serialize;

/// Monotonic version of this catalog. Bump when rules are added, retired, or
/// redefined; the policy identity changes with it.
pub const RULE_CATALOG_VERSION: u32 = 4;

/// Monotonic version of the severity table. Severity or rule-meaning changes
/// require a new version here.
pub const SEVERITY_TABLE_VERSION: u32 = 1;

/// Version of the verified security-surface reference this catalog derives from.
pub const SUPPORTED_SURFACE_VERSION: &str = "omarchy-security-surface.v1";

/// External marketplace rule-equivalence map version. The marketplace's
/// Automated Security Baseline is at V3 upstream (V4 is a separate future
/// policy there), so the shipped map records V3 with its verification commit;
/// staleness against newer external versions is part of the map API.
pub const EQUIVALENCE_MAP_VERSION: Option<&str> = Some("omarchy-marketplace-baseline-v3/1");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rendered = match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        };
        formatter.write_str(rendered)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Language {
    Qml,
    #[serde(rename = "javascript")]
    JavaScript,
    Shell,
    Python,
    #[serde(rename = "payload-binary")]
    PayloadBinary,
    Context,
}

impl std::fmt::Display for Language {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rendered = match self {
            Language::Qml => "qml",
            Language::JavaScript => "javascript",
            Language::Shell => "shell",
            Language::Python => "python",
            Language::PayloadBinary => "payload-binary",
            Language::Context => "context",
        };
        formatter.write_str(rendered)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    ProcessExecution,
    DetachedProcessExecution,
    DynamicCodeExecution,
    FilesystemAccess,
    NetworkAccess,
    PersistenceScheduling,
    ClipboardAccess,
    CompositorControl,
    PolkitAgentUi,
    SessionLockSurface,
    PamAuthentication,
    ShellIpcInventory,
    ReplacesBarContext,
}

impl std::fmt::Display for Capability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let rendered = match self {
            Capability::ProcessExecution => "process-execution",
            Capability::DetachedProcessExecution => "detached-process-execution",
            Capability::DynamicCodeExecution => "dynamic-code-execution",
            Capability::FilesystemAccess => "filesystem-access",
            Capability::NetworkAccess => "network-access",
            Capability::PersistenceScheduling => "persistence-scheduling",
            Capability::ClipboardAccess => "clipboard-access",
            Capability::CompositorControl => "compositor-control",
            Capability::PolkitAgentUi => "polkit-agent-ui",
            Capability::SessionLockSurface => "session-lock-surface",
            Capability::PamAuthentication => "pam-authentication",
            Capability::ShellIpcInventory => "shell-ipc-inventory",
            Capability::ReplacesBarContext => "replaces-bar-context",
        };
        formatter.write_str(rendered)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleDefinition {
    pub id: &'static str,
    pub title: &'static str,
    pub language: Language,
    pub capability: Capability,
    pub default_severity: Severity,
    /// Verified sink or payload edge from the security surface reference.
    pub surface_anchor: &'static str,
    pub summary: &'static str,
    pub review_guidance: &'static str,
}

const fn qml_rule(
    id: &'static str,
    title: &'static str,
    capability: Capability,
    default_severity: Severity,
    surface_anchor: &'static str,
    summary: &'static str,
    review_guidance: &'static str,
) -> RuleDefinition {
    RuleDefinition {
        id,
        title,
        language: Language::Qml,
        capability,
        default_severity,
        surface_anchor,
        summary,
        review_guidance,
    }
}

/// The seeded catalog, one entry per verified reachable sink plus the bar-replacement
/// context capability. Detectors for these rules land in S3/S4; catalog publication
/// precedes detector availability so IDs are stable from the first emitted report.
pub const CATALOG: &[RuleDefinition] = &[
    qml_rule(
        "oma.qml.process-execution",
        "QML process execution",
        Capability::ProcessExecution,
        Severity::Medium,
        "Quickshell.Io.Process",
        "QML starts an arbitrary argv child process.",
        "Review the command argv and data provenance; spawning alone is not malicious.",
    ),
    qml_rule(
        "oma.qml.detached-execution",
        "QML detached process execution",
        Capability::DetachedProcessExecution,
        Severity::Medium,
        "Quickshell.execDetached",
        "QML starts a detached process outside component lifetime.",
        "Prioritize dynamic shell command strings and bundled-payload edges.",
    ),
    qml_rule(
        "oma.qml.filesystem-access",
        "QML filesystem access",
        Capability::FilesystemAccess,
        Severity::Low,
        "FileView",
        "QML reads or watches files and may participate in writes.",
        "Raise priority for sensitive paths, persistence locations, or write participation.",
    ),
    qml_rule(
        "oma.qml.network-access",
        "QML network access",
        Capability::NetworkAccess,
        Severity::Medium,
        "QML/Qt networking",
        "QML can make outbound requests and retrieve runtime content.",
        "Flag download-and-execute chains and sensitive-data exfiltration edges.",
    ),
    qml_rule(
        "oma.qml.remote-component-load",
        "QML loads a component from a remote URL",
        Capability::NetworkAccess,
        Severity::High,
        "Reverified H0: network Loader.source / Qt.createComponent reachable",
        "A URL-scheme literal at Loader.source or Qt.createComponent loads QML code over the network; both sinks are verified reachable on the pinned runtime.",
        "Content loaded from a URL was never part of any reviewed commit; treat the plugin as unreviewed until the remote source is audited at the pinned revision.",
    ),
    qml_rule(
        "oma.qml.remote-directory-import",
        "Remote directory import indicator",
        Capability::NetworkAccess,
        Severity::Low,
        "Reverified H0: remote directory imports scanner-intercepted",
        "The plugin imports QML from a remote URL; the pinned runtime's scanner normalizes the URL onto a relative path and drops it, so nothing executes remotely through this syntax.",
        "Indicator only: no remote directory import executed on the pinned build, so this records intent, not a live load. Re-probe any newer runtime before escalating.",
    ),
    qml_rule(
        "oma.qml.out-of-tree-reference",
        "QML loads content from outside the plugin tree",
        Capability::FilesystemAccess,
        Severity::Medium,
        "Reverified H0: out-of-tree references resolve locally (no runtime sandbox)",
        "An absolute-path or traversal reference loads content from outside the reviewed plugin tree, bypassing commit-bound review.",
        "This is an unreviewed out-of-tree load, not a sandbox escape — there is no runtime sandbox. Audit the referenced location before trusting the review.",
    ),
    qml_rule(
        "oma.qml.dynamic-reference",
        "QML loads content through a computed reference",
        Capability::FilesystemAccess,
        Severity::Low,
        "safe relative entry-point paths",
        "A Loader source or FileView path is computed at runtime instead of a literal.",
        "Trace what flows into the reference; computed sinks evade static containment review.",
    ),
    qml_rule(
        "oma.qml.persistence-scheduling",
        "QML timer/service persistence",
        Capability::PersistenceScheduling,
        Severity::Info,
        "Timer and service entry points",
        "Enables periodic or headless long-running behavior.",
        "Context signal for continuous monitoring; not malicious by itself.",
    ),
    qml_rule(
        "oma.qml.clipboard-access",
        "QML clipboard access",
        Capability::ClipboardAccess,
        Severity::Medium,
        "Clipboard access/helpers",
        "May observe or replace clipboard contents.",
        "Continuous headless monitoring is higher concern than interactive use.",
    ),
    qml_rule(
        "oma.qml.compositor-control",
        "Hyprland/Wayland compositor control",
        Capability::CompositorControl,
        Severity::Medium,
        "Hyprland/Wayland APIs",
        "Controls or observes compositor and session surfaces.",
        "Severity follows the concrete effect on session integrity.",
    ),
    qml_rule(
        "oma.qml.polkit-agent-ui",
        "Third-party polkit agent UI",
        Capability::PolkitAgentUi,
        Severity::High,
        "Quickshell.Services.Polkit",
        "Hosts authentication-agent UI inside the shared shell process.",
        "Near-zero ordinary plugin need; treat as architectural exposure requiring manual triage.",
    ),
    qml_rule(
        "oma.qml.session-lock",
        "Third-party session-lock surface",
        Capability::SessionLockSurface,
        Severity::High,
        "WlSessionLock / WlSessionLockSurface",
        "Owns secure session-lock surfaces from third-party code.",
        "Near-zero ordinary plugin need; verify lock behavior manually before trusting.",
    ),
    qml_rule(
        "oma.qml.pam-authentication",
        "Third-party PAM authentication flow",
        Capability::PamAuthentication,
        Severity::High,
        "PamContext using Omarchy lock services",
        "Handles password/fingerprint authentication flow in third-party QML.",
        "Never infer password safety; audit credential handling paths directly.",
    ),
    qml_rule(
        "oma.qml.dynamic-code",
        "QML constructs code at runtime",
        Capability::DynamicCodeExecution,
        Severity::Medium,
        "no third-party import allowlist",
        "QML/JS builds or evaluates code from strings at runtime (Qt.createQmlObject, eval, new Function, atob decode chains).",
        "Trace the string provenance; runtime construction evades every static import review.",
    ),
    qml_rule(
        "oma.qml.obfuscated-payload-indicator",
        "Encoded payload indicator in QML/JS",
        Capability::DynamicCodeExecution,
        Severity::Low,
        "no third-party import allowlist",
        "Long base64-shaped literals suggest hidden payload material.",
        "Indicator only: decode the material manually and judge the decoded content.",
    ),
    RuleDefinition {
        id: "oma.script.download-execute",
        title: "Script downloads and executes remote content",
        language: Language::Shell,
        capability: Capability::ProcessExecution,
        default_severity: Severity::High,
        surface_anchor: "arbitrary non-QML payloads",
        summary: "A bundled script pipes downloaded content straight into a shell or interpreter.",
        review_guidance: "Match of the marketplace baseline's selectively blocking curl-pipe-shell family; treat as blocking until the install path is fixed.",
    },
    RuleDefinition {
        id: "oma.script.privilege-escalation",
        title: "Script escalates privileges or edits sudoers",
        language: Language::Shell,
        capability: Capability::ProcessExecution,
        default_severity: Severity::High,
        surface_anchor: "arbitrary non-QML payloads",
        summary: "A bundled script grants itself passwordless root or writes sudoers policy.",
        review_guidance: "Near-zero ordinary plugin need; verify the exact root command surface and input validation manually.",
    },
    RuleDefinition {
        id: "oma.python.download-execute",
        title: "Python script downloads and executes remote content",
        language: Language::Python,
        capability: Capability::ProcessExecution,
        default_severity: Severity::High,
        surface_anchor: "arbitrary non-QML payloads",
        summary: "Bundled Python fetches remote content and hands it straight to exec/system.",
        review_guidance: "Same family as script download-and-execute; treat as blocking until the install path is fixed.",
    },
    RuleDefinition {
        id: "oma.python.privilege-escalation",
        title: "Python script escalates privileges or edits sudoers",
        language: Language::Python,
        capability: Capability::ProcessExecution,
        default_severity: Severity::High,
        surface_anchor: "arbitrary non-QML payloads",
        summary: "Bundled Python invokes privilege wrappers or writes passwordless sudoers policy.",
        review_guidance: "Verify the exact root command surface; never infer safety from a benign-looking wrapper name.",
    },
    RuleDefinition {
        id: "oma.shell.ipc-injected-objects",
        title: "Shell IPC/injected object inventory",
        language: Language::JavaScript,
        capability: Capability::ShellIpcInventory,
        default_severity: Severity::Info,
        surface_anchor: "Plugin/shell injected objects and IPC",
        summary: "Inventory callable methods and bound arguments exposed to plugins.",
        review_guidance: "Assess lifecycle/configuration operations reachable from plugin code.",
    },
    RuleDefinition {
        id: "oma.context.replaces-bar",
        title: "Plugin replaces the bar",
        language: Language::Context,
        capability: Capability::ReplacesBarContext,
        default_severity: Severity::Info,
        surface_anchor: "Plugin-kind prioritization (bar)",
        summary: "A third-party whole-bar plugin suppresses ambient bar widgets including OmaSafe's.",
        review_guidance: "Critical alerts must remain reachable via desktop notification/CLI independent of the bar.",
    },
];

pub fn catalog() -> &'static [RuleDefinition] {
    CATALOG
}

pub fn rule(id: &str) -> Option<&'static RuleDefinition> {
    CATALOG.iter().find(|definition| definition.id == id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn rule_ids_are_unique_and_wellformed() {
        let mut seen = BTreeSet::new();
        for definition in CATALOG {
            assert!(definition.id.starts_with("oma."), "{}", definition.id);
            assert!(
                unique_insert(&mut seen, definition.id),
                "duplicate rule id {}",
                definition.id
            );
        }
        assert!(!seen.is_empty());
    }

    fn unique_insert(seen: &mut BTreeSet<&'static str>, id: &'static str) -> bool {
        seen.insert(id)
    }

    #[test]
    fn lookup_round_trips_every_catalog_entry() {
        for definition in CATALOG {
            assert_eq!(rule(definition.id), Some(definition));
        }
        assert!(rule("oma.does-not-exist").is_none());
    }

    #[test]
    fn high_priority_surfaces_are_high_severity() {
        assert_eq!(
            rule("oma.qml.polkit-agent-ui").unwrap().default_severity,
            Severity::High
        );
        assert_eq!(
            rule("oma.qml.session-lock").unwrap().default_severity,
            Severity::High
        );
        assert_eq!(
            rule("oma.qml.pam-authentication").unwrap().default_severity,
            Severity::High
        );
        assert_eq!(
            rule("oma.qml.remote-component-load")
                .unwrap()
                .default_severity,
            Severity::High
        );
    }

    #[test]
    fn remote_directory_import_stays_an_indicator() {
        // H0 verified remote directory imports are scanner-intercepted on the
        // pinned runtime: the rule must never claim the High remote-load
        // family, and its guidance must demand re-probing newer runtimes.
        let definition = rule("oma.qml.remote-directory-import").unwrap();
        assert_eq!(definition.default_severity, Severity::Low);
        assert!(definition.review_guidance.contains("Re-probe"));
        assert!(definition.summary.contains("scanner"));
    }

    #[test]
    fn severity_ordering_matches_documented_scale() {
        assert!(Severity::Info < Severity::Low);
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn every_rule_maps_to_its_verified_surface_anchor() {
        // Exact pairs from docs/reference/omarchy-security-surface.md so a
        // mis-mapped or duplicated anchor cannot pass on count alone.
        let expected: &[(&str, &str)] = &[
            ("oma.qml.process-execution", "Quickshell.Io.Process"),
            (
                "oma.qml.dynamic-reference",
                "safe relative entry-point paths",
            ),
            ("oma.qml.dynamic-code", "no third-party import allowlist"),
            (
                "oma.qml.obfuscated-payload-indicator",
                "no third-party import allowlist",
            ),
            ("oma.script.download-execute", "arbitrary non-QML payloads"),
            (
                "oma.script.privilege-escalation",
                "arbitrary non-QML payloads",
            ),
            ("oma.python.download-execute", "arbitrary non-QML payloads"),
            (
                "oma.python.privilege-escalation",
                "arbitrary non-QML payloads",
            ),
            ("oma.qml.detached-execution", "Quickshell.execDetached"),
            ("oma.qml.filesystem-access", "FileView"),
            ("oma.qml.network-access", "QML/Qt networking"),
            (
                "oma.qml.remote-component-load",
                "Reverified H0: network Loader.source / Qt.createComponent reachable",
            ),
            (
                "oma.qml.remote-directory-import",
                "Reverified H0: remote directory imports scanner-intercepted",
            ),
            (
                "oma.qml.out-of-tree-reference",
                "Reverified H0: out-of-tree references resolve locally (no runtime sandbox)",
            ),
            (
                "oma.qml.persistence-scheduling",
                "Timer and service entry points",
            ),
            ("oma.qml.clipboard-access", "Clipboard access/helpers"),
            ("oma.qml.compositor-control", "Hyprland/Wayland APIs"),
            ("oma.qml.polkit-agent-ui", "Quickshell.Services.Polkit"),
            (
                "oma.qml.session-lock",
                "WlSessionLock / WlSessionLockSurface",
            ),
            (
                "oma.qml.pam-authentication",
                "PamContext using Omarchy lock services",
            ),
            (
                "oma.shell.ipc-injected-objects",
                "Plugin/shell injected objects and IPC",
            ),
            (
                "oma.context.replaces-bar",
                "Plugin-kind prioritization (bar)",
            ),
        ];
        assert_eq!(CATALOG.len(), expected.len());
        for (id, anchor) in expected {
            let definition = rule(id).unwrap_or_else(|| panic!("missing rule {id}"));
            assert_eq!(definition.surface_anchor, *anchor, "anchor drift on {id}");
        }
    }
}
