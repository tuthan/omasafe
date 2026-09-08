//! OmaSafe-owned rule catalog and severity table.
//!
//! Rule IDs and meanings are stable after publication (rule contract). Every
//! definition below maps to a verified sink or payload edge recorded in
//! `docs/reference/omarchy-security-surface.md`. Capability detection is
//! separate from suspicious behavior: a capability result alone never asserts
//! malicious intent.

use std::collections::BTreeMap;

use omasafe_core::bounds::{
    DATAFLOW_TIME_BUDGET, MAX_DATAFLOW_ASSIGNMENT_DEPTH, MAX_DATAFLOW_STATEMENTS,
    MAX_PYTHON_FLOW_BINDINGS, MAX_PYTHON_FLOW_DEPTH, MAX_PYTHON_FLOW_NODES,
    MAX_PYTHON_FLOW_SOURCE_BYTES, MAX_PYTHON_FLOW_STATEMENTS, MAX_SHELL_PARSE_CHILD_PROGRAMS,
    MAX_SHELL_PARSE_DEPTH, MAX_SHELL_PARSE_NODES, MAX_SHELL_PARSE_SOURCE_BYTES,
    MAX_STAGED_CHAIN_LINES, PYTHON_FLOW_TIME_BUDGET, STAGED_CHAIN_TIME_BUDGET,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// Monotonic version of this catalog. Bump when rules are added, retired, or
/// redefined; the policy identity changes with it.
pub const RULE_CATALOG_VERSION: u32 = 9;

/// Monotonic version of the severity table. Severity or rule-meaning changes
/// require a new version here.
pub const SEVERITY_TABLE_VERSION: u32 = 1;

/// Version of the verified security-surface reference this catalog derives from.
pub const SUPPORTED_SURFACE_VERSION: &str = "omarchy-security-surface.v1";

/// External marketplace rule-equivalence map version. The marketplace's
/// Automated Security Baseline is at V3 upstream (V4 is a separate future
/// policy there), so the shipped map records V3 with its verification commit;
/// staleness against newer external versions is part of the map API.
pub const EQUIVALENCE_MAP_VERSION: Option<&str> = Some("omarchy-marketplace-baseline-v3/2");

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
    BundledBinary,
    SensitivePath,
    InputInjection,
    ScreenCapture,
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
            Capability::BundledBinary => "bundled-binary",
            Capability::SensitivePath => "sensitive-path",
            Capability::InputInjection => "input-injection",
            Capability::ScreenCapture => "screen-capture",
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleSemanticIdentity {
    pub schema: &'static str,
    pub rule_id: &'static str,
    pub review_revision: u32,
    pub severity: Severity,
    pub result_roles: &'static [&'static str],
    pub methods: &'static [&'static str],
    pub parser_features: BTreeMap<String, String>,
    pub semantic_limits: BTreeMap<String, u128>,
    pub normalization_revision: &'static str,
    pub runtime_surface_revision: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleSupport {
    pub status: &'static str,
    pub result_roles: Vec<&'static str>,
    pub predicates: Vec<&'static str>,
    pub languages: Vec<&'static str>,
    pub methods: Vec<&'static str>,
    pub limitations: Vec<&'static str>,
    pub benign_examples: Vec<&'static str>,
    pub fixture_ids: Vec<&'static str>,
}

pub fn rule_semantic_identity(id: &str) -> Option<RuleSemanticIdentity> {
    let definition = rule(id)?;
    let methods: &'static [&'static str] = match definition.language {
        Language::Qml | Language::JavaScript => &["qml-ast-or-lexical", "bounded-dataflow"],
        Language::Python => &["python-syntax-flow", "lexical-correlation"],
        Language::Shell => &["shell-ir", "lexical-correlation"],
        Language::Context | Language::PayloadBinary => &["inventory-or-context"],
    };
    let mut parser_features = BTreeMap::new();
    match definition.language {
        Language::Qml | Language::JavaScript => {
            parser_features.insert(
                "qml-parser".to_owned(),
                if cfg!(feature = "qml-parser") {
                    "tree-sitter-qmljs/0.3.1"
                } else {
                    "lexical-fallback-unassigned"
                }
                .to_owned(),
            );
        }
        Language::Python => {
            parser_features.insert(
                "python-parser".to_owned(),
                if cfg!(feature = "python-parser") {
                    "tree-sitter-python/0.25.0"
                } else {
                    "lexical-fallback-no-python-flow"
                }
                .to_owned(),
            );
        }
        _ => {}
    }
    let mut limits = BTreeMap::new();
    match definition.language {
        Language::Python => {
            limits.insert(
                "python-flow-source-bytes".to_owned(),
                MAX_PYTHON_FLOW_SOURCE_BYTES as u128,
            );
            limits.insert(
                "python-flow-nodes".to_owned(),
                MAX_PYTHON_FLOW_NODES as u128,
            );
            limits.insert(
                "python-flow-statements".to_owned(),
                MAX_PYTHON_FLOW_STATEMENTS as u128,
            );
            limits.insert(
                "python-flow-depth".to_owned(),
                MAX_PYTHON_FLOW_DEPTH as u128,
            );
            limits.insert(
                "python-flow-bindings".to_owned(),
                MAX_PYTHON_FLOW_BINDINGS as u128,
            );
            limits.insert(
                "python-flow-time-ms".to_owned(),
                PYTHON_FLOW_TIME_BUDGET.as_millis(),
            );
        }
        Language::Shell => {
            limits.insert(
                "shell-staged-lines".to_owned(),
                MAX_STAGED_CHAIN_LINES as u128,
            );
            limits.insert(
                "shell-staged-time-ms".to_owned(),
                STAGED_CHAIN_TIME_BUDGET.as_millis(),
            );
            limits.insert(
                "shell-parse-depth".to_owned(),
                MAX_SHELL_PARSE_DEPTH as u128,
            );
            limits.insert(
                "shell-parse-nodes".to_owned(),
                MAX_SHELL_PARSE_NODES as u128,
            );
            limits.insert(
                "shell-parse-child-programs".to_owned(),
                MAX_SHELL_PARSE_CHILD_PROGRAMS as u128,
            );
            limits.insert(
                "shell-parse-source-bytes".to_owned(),
                MAX_SHELL_PARSE_SOURCE_BYTES as u128,
            );
        }
        Language::Qml | Language::JavaScript => {
            limits.insert(
                "dataflow-statements".to_owned(),
                MAX_DATAFLOW_STATEMENTS as u128,
            );
            limits.insert(
                "dataflow-assignment-depth".to_owned(),
                MAX_DATAFLOW_ASSIGNMENT_DEPTH as u128,
            );
            limits.insert(
                "dataflow-time-ms".to_owned(),
                DATAFLOW_TIME_BUDGET.as_millis(),
            );
        }
        _ => {}
    }
    Some(RuleSemanticIdentity {
        schema: "omasafe.rule-semantics.v1",
        rule_id: definition.id,
        review_revision: match definition.id {
            // v0.2.4 changed the accepted staged-shell predicate and added
            // source/sink attribution to the H6 correlation findings; the
            // Python dataflow predicate was refined after the initial
            // v0.2.4 declaration; its review identity must be reconfirmed.
            "oma.script.download-execute"
            | "oma.qml.sensitive-data-egress"
            | "oma.script.sensitive-data-egress" => 2,
            "oma.python.download-execute" => 3,
            // v0.2.5 follow-up narrows resolvedUrl suppression to computed
            // arguments and preserves constant context edges outside the
            // modeled Loader/FileView sinks.
            "oma.qml.dynamic-reference" => 3,
            _ => 1,
        },
        severity: definition.default_severity,
        result_roles: &["capability", "finding"],
        methods,
        parser_features,
        semantic_limits: limits,
        normalization_revision: "normalized-result.v1",
        runtime_surface_revision: SUPPORTED_SURFACE_VERSION,
    })
}

pub fn rule_semantic_identity_digest(id: &str) -> Option<String> {
    let identity = rule_semantic_identity(id)?;
    let value = serde_json::to_value(&identity).expect("semantic identity serialization");
    let canonical = omasafe_core::scan_snapshot::canonical_json(&value);
    Some(hex(&Sha256::digest(canonical.as_bytes())))
}

pub fn rule_semantics_catalog_digest() -> String {
    let map: std::collections::BTreeMap<_, _> = CATALOG
        .iter()
        .filter_map(|definition| {
            rule_semantic_identity_digest(definition.id).map(|digest| (definition.id, digest))
        })
        .collect();
    let value = serde_json::to_value(&map).expect("semantic catalog serialization");
    let canonical = omasafe_core::scan_snapshot::canonical_json(&value);
    hex(&Sha256::digest(canonical.as_bytes()))
}

pub fn rule_support(id: &str) -> Option<RuleSupport> {
    let definition = rule(id)?;
    let partial: &'static [&'static str] = match definition.language {
        Language::Python => &["cross-file-flow", "multiline-reverse-shell"],
        Language::Shell => &["arbitrary-shell-evaluation"],
        Language::Qml | Language::JavaScript => &["dynamic-runtime-reachability"],
        _ => &["runtime-reachability"],
    };
    Some(RuleSupport {
        status: "implemented",
        result_roles: vec!["capability", "finding"],
        predicates: vec![definition.summary],
        languages: vec![match definition.language {
            Language::Qml => "qml",
            Language::JavaScript => "javascript",
            Language::Shell => "shell",
            Language::Python => "python",
            Language::PayloadBinary => "payload-binary",
            Language::Context => "context",
        }],
        methods: match definition.language {
            Language::Python => vec!["tree-sitter-python/0.25.0", "lexical-correlation"],
            Language::Shell => vec!["shell-ir", "lexical-correlation"],
            _ => vec!["ast-or-lexical"],
        },
        limitations: partial.to_vec(),
        benign_examples: vec!["capability-only use with no supported suspicious connection"],
        fixture_ids: Vec::new(),
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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

const fn script_rule(
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
        language: Language::Shell,
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
        "oma.qml.sensitive-path",
        "QML sensitive user-data path",
        Capability::SensitivePath,
        Severity::Low,
        "Sensitive user-data paths",
        "QML refers to credentials, keyrings, browser profiles, cloud credentials, wallets, or other sensitive user-data locations.",
        "Capability indicator only: confirm whether the path is actually read and whether any dataflow reaches an outbound sink.",
    ),
    qml_rule(
        "oma.qml.input-injection",
        "QML input injection capability",
        Capability::InputInjection,
        Severity::Info,
        "ydotool/wtype/wlrctl/hyprctl sendshortcut",
        "QML can synthesize keyboard or pointer input through desktop automation tools.",
        "Interactive accessibility workflows are legitimate; prioritize hidden, timer-driven, or dynamically controlled input.",
    ),
    qml_rule(
        "oma.qml.screen-capture",
        "QML screen capture capability",
        Capability::ScreenCapture,
        Severity::Info,
        "grim/slurp/wf-recorder/hyprshot",
        "QML can capture screen pixels or select a capture region.",
        "Review the user-visible trigger and whether captured material reaches an outbound sink.",
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
    qml_rule(
        "oma.qml.sensitive-data-egress",
        "QML sends sensitive user data outward",
        Capability::NetworkAccess,
        Severity::High,
        "Sensitive read connected to QML/Qt networking",
        "Bounded dataflow connects a sensitive local-user-data read to an outbound network sink.",
        "Treat as a concrete exfiltration path: identify the exact bytes read, destination, and user-visible consent boundary.",
    ),
    qml_rule(
        "oma.qml.input-injection-background",
        "QML performs background input injection",
        Capability::InputInjection,
        Severity::Medium,
        "Input injection from timer/service/background lifecycle",
        "Input automation is reachable from a background or lifecycle trigger rather than an explicit user action.",
        "Verify whether the automation is an expected accessibility workflow; dynamic keystrokes increase concern.",
    ),
    qml_rule(
        "oma.qml.screen-capture-background",
        "QML captures the screen in the background",
        Capability::ScreenCapture,
        Severity::Medium,
        "Screen capture from timer/service/background lifecycle",
        "Screen capture is reachable without a clear user-visible trigger.",
        "Review capture frequency, visibility, retention, and any outbound dataflow.",
    ),
    qml_rule(
        "oma.qml.persistence-background",
        "QML installs hidden persistence",
        Capability::PersistenceScheduling,
        Severity::Medium,
        "Persistence location plus background activation",
        "A persistence target is written or enabled from a background lifecycle path.",
        "Confirm the declared plugin need and inspect the exact startup command and payload provenance.",
    ),
    script_rule(
        "oma.script.sensitive-path",
        "Script sensitive user-data path",
        Capability::SensitivePath,
        Severity::Low,
        "Sensitive user-data paths in bundled scripts",
        "A bundled script refers to credentials, keyrings, browser profiles, cloud credentials, wallets, or other sensitive user-data locations.",
        "Capability indicator only: confirm whether the path is read and whether any dataflow reaches an outbound sink.",
    ),
    script_rule(
        "oma.script.input-injection",
        "Script input injection capability",
        Capability::InputInjection,
        Severity::Info,
        "ydotool/wtype/wlrctl/hyprctl sendshortcut",
        "A bundled script can synthesize keyboard or pointer input through desktop automation tools.",
        "Interactive accessibility workflows are legitimate; prioritize hidden, timer-driven, or dynamically controlled input.",
    ),
    script_rule(
        "oma.script.screen-capture",
        "Script screen capture capability",
        Capability::ScreenCapture,
        Severity::Info,
        "grim/slurp/wf-recorder/hyprshot",
        "A bundled script can capture screen pixels or select a capture region.",
        "Review the user-visible trigger and whether captured material reaches an outbound sink.",
    ),
    script_rule(
        "oma.script.clipboard-access",
        "Script clipboard capability",
        Capability::ClipboardAccess,
        Severity::Info,
        "wl-paste/cliphist/xclip clipboard helpers",
        "A bundled script reads, watches, or writes clipboard contents.",
        "Reading or watching clipboard data is more sensitive than wl-copy writes; inspect lifecycle and destinations.",
    ),
    script_rule(
        "oma.script.persistence-scheduling",
        "Script persistence capability",
        Capability::PersistenceScheduling,
        Severity::Info,
        "XDG autostart/systemd/user/cron/Hyprland persistence paths",
        "A bundled script can install or enable user-level persistence.",
        "Installing a declared user service can be legitimate; inspect hidden activation and dynamic payload provenance.",
    ),
    script_rule(
        "oma.script.sensitive-data-egress",
        "Script sends sensitive user data outward",
        Capability::NetworkAccess,
        Severity::High,
        "Sensitive read connected to script network egress",
        "Bounded lexical/dataflow evidence connects a sensitive local-user-data read to a network egress command.",
        "Treat as a concrete exfiltration path: identify the exact bytes read, destination, and user-visible consent boundary.",
    ),
    script_rule(
        "oma.script.input-injection-background",
        "Script performs background input injection",
        Capability::InputInjection,
        Severity::Medium,
        "Input injection from timer/service/background lifecycle",
        "Input automation is reachable from a background or lifecycle trigger rather than an explicit user action.",
        "Verify whether the automation is an expected accessibility workflow; dynamic keystrokes increase concern.",
    ),
    script_rule(
        "oma.script.screen-capture-background",
        "Script captures the screen in the background",
        Capability::ScreenCapture,
        Severity::Medium,
        "Screen capture from timer/service/background lifecycle",
        "Screen capture is reachable without a clear user-visible trigger.",
        "Review capture frequency, visibility, retention, and any outbound dataflow.",
    ),
    script_rule(
        "oma.script.persistence-background",
        "Script installs hidden persistence",
        Capability::PersistenceScheduling,
        Severity::Medium,
        "Persistence location plus background activation",
        "A persistence target is written or enabled from a background lifecycle path.",
        "Confirm the declared plugin need and inspect the exact startup command and payload provenance.",
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
        id: "oma.script.reverse-shell",
        title: "Script opens an interactive reverse shell",
        language: Language::Shell,
        capability: Capability::ProcessExecution,
        default_severity: Severity::High,
        surface_anchor: "arbitrary non-QML payloads",
        summary: "A bundled script opens an operator-controlled shell back to a remote host (/dev/tcp redirect, nc -e, socat exec:, bash -i >&).",
        review_guidance: "Highest-signal family in the catalog: an interactive remote shell is a full handover of the user account. Treat as blocking.",
    },
    RuleDefinition {
        id: "oma.python.reverse-shell",
        title: "Python script wires a socket to a process",
        language: Language::Python,
        capability: Capability::ProcessExecution,
        default_severity: Severity::High,
        surface_anchor: "arbitrary non-QML payloads",
        summary: "Bundled Python connects a network socket and hands it to a spawned process on the same statement line.",
        review_guidance: "The classic Python reverse shell is exactly this wiring. Review the connect target and spawned command manually; multi-line wiring is the H4 dataflow slice.",
    },
    RuleDefinition {
        id: "oma.script.decode-execute",
        title: "Script decodes content and executes it",
        language: Language::Shell,
        capability: Capability::ProcessExecution,
        default_severity: Severity::High,
        surface_anchor: "arbitrary non-QML payloads",
        summary: "A bundled script pipes decoded content (base64 -d, openssl enc -d, xxd -r) into a shell or interpreter on one line.",
        review_guidance: "Decoded-then-executed content was never reviewable text. Note the shell blind spot: an unquoted base64 blob is not a quoted literal, so the obfuscation indicator cannot fire on shell — this rule is the line-level net.",
    },
    RuleDefinition {
        id: "oma.script.privileged-shared-temp",
        title: "Privileged execution from shared temporary storage indicator",
        language: Language::Shell,
        capability: Capability::ProcessExecution,
        default_severity: Severity::Low,
        surface_anchor: "arbitrary non-QML payloads",
        summary: "A bundled script invokes a privilege wrapper on a /tmp or /dev/shm path.",
        review_guidance: "Indicator only: a pathname alone does not prove attacker control. Re-check whether anything outside the plugin can replace the referenced path before judging.",
    },
    RuleDefinition {
        id: "oma.script.privileged-shared-temp-controlled",
        title: "Script relaxes permissions on shared temporary storage",
        language: Language::Shell,
        capability: Capability::ProcessExecution,
        default_severity: Severity::High,
        surface_anchor: "arbitrary non-QML payloads",
        summary: "A bundled script makes a /tmp or /dev/shm path group- or world-writable on one line (chmod with a permissive mode).",
        review_guidance: "An explicit mode release on shared storage lets any local user swap the payload a privileged invocation later runs. Connected untrusted-write confirmation is the H4 dataflow slice.",
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
    RuleDefinition {
        id: "oma.payload.bundled-binary",
        title: "Bundled executable binary",
        language: Language::PayloadBinary,
        capability: Capability::BundledBinary,
        default_severity: Severity::Medium,
        surface_anchor: "Payload inventory native-format classification and invocation edges",
        summary: "A bundled executable binary is reachable from reviewed plugin code; unreferenced binaries remain inventory capability context.",
        review_guidance: "Review the binary's provenance and digest. Reachability is a Medium finding, not proof of malicious behavior; remote downloads or digest changes require separate provenance controls.",
    },
    RuleDefinition {
        id: "oma.context.omasafe-state-tamper",
        title: "OmaSafe state or plugin checkout tamper intent",
        language: Language::Context,
        capability: Capability::FilesystemAccess,
        default_severity: Severity::Medium,
        surface_anchor: "OmaSafe state directory, sibling plugin checkouts, and git control paths",
        summary: "Plugin code appears to write OmaSafe state, modify a sibling plugin checkout, or invoke git against another plugin directory.",
        review_guidance: "This detects intent, not protection: a quiet result does not mean the plugin is protected. Same-user authority is unbounded; real protection is deferred to v0.5.",
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
    fn shared_temp_pathname_is_never_a_finding_on_its_own() {
        // H3: the indicator records a privileged invocation touching shared
        // temporary storage; the High rule needs an explicit mode release.
        // The indicator ID is never repurposed as the finding.
        let indicator = rule("oma.script.privileged-shared-temp").unwrap();
        assert_eq!(indicator.default_severity, Severity::Low);
        assert!(
            indicator.summary.contains("indicator")
                || indicator.review_guidance.contains("Indicator only")
        );
        let controlled = rule("oma.script.privileged-shared-temp-controlled").unwrap();
        assert_eq!(controlled.default_severity, Severity::High);
        assert!(controlled.id != indicator.id);
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
            ("oma.script.reverse-shell", "arbitrary non-QML payloads"),
            ("oma.python.reverse-shell", "arbitrary non-QML payloads"),
            ("oma.script.decode-execute", "arbitrary non-QML payloads"),
            (
                "oma.script.privileged-shared-temp",
                "arbitrary non-QML payloads",
            ),
            (
                "oma.script.privileged-shared-temp-controlled",
                "arbitrary non-QML payloads",
            ),
            ("oma.qml.detached-execution", "Quickshell.execDetached"),
            ("oma.qml.filesystem-access", "FileView"),
            ("oma.qml.sensitive-path", "Sensitive user-data paths"),
            (
                "oma.qml.input-injection",
                "ydotool/wtype/wlrctl/hyprctl sendshortcut",
            ),
            ("oma.qml.screen-capture", "grim/slurp/wf-recorder/hyprshot"),
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
                "oma.qml.sensitive-data-egress",
                "Sensitive read connected to QML/Qt networking",
            ),
            (
                "oma.qml.input-injection-background",
                "Input injection from timer/service/background lifecycle",
            ),
            (
                "oma.qml.screen-capture-background",
                "Screen capture from timer/service/background lifecycle",
            ),
            (
                "oma.qml.persistence-background",
                "Persistence location plus background activation",
            ),
            (
                "oma.script.sensitive-path",
                "Sensitive user-data paths in bundled scripts",
            ),
            (
                "oma.script.input-injection",
                "ydotool/wtype/wlrctl/hyprctl sendshortcut",
            ),
            (
                "oma.script.screen-capture",
                "grim/slurp/wf-recorder/hyprshot",
            ),
            (
                "oma.script.clipboard-access",
                "wl-paste/cliphist/xclip clipboard helpers",
            ),
            (
                "oma.script.persistence-scheduling",
                "XDG autostart/systemd/user/cron/Hyprland persistence paths",
            ),
            (
                "oma.script.sensitive-data-egress",
                "Sensitive read connected to script network egress",
            ),
            (
                "oma.script.input-injection-background",
                "Input injection from timer/service/background lifecycle",
            ),
            (
                "oma.script.screen-capture-background",
                "Screen capture from timer/service/background lifecycle",
            ),
            (
                "oma.script.persistence-background",
                "Persistence location plus background activation",
            ),
            (
                "oma.shell.ipc-injected-objects",
                "Plugin/shell injected objects and IPC",
            ),
            (
                "oma.context.replaces-bar",
                "Plugin-kind prioritization (bar)",
            ),
            (
                "oma.payload.bundled-binary",
                "Payload inventory native-format classification and invocation edges",
            ),
            (
                "oma.context.omasafe-state-tamper",
                "OmaSafe state directory, sibling plugin checkouts, and git control paths",
            ),
        ];
        assert_eq!(CATALOG.len(), expected.len());
        for (id, anchor) in expected {
            let definition = rule(id).unwrap_or_else(|| panic!("missing rule {id}"));
            assert_eq!(definition.surface_anchor, *anchor, "anchor drift on {id}");
        }
    }

    #[test]
    fn semantic_identity_covers_every_rule_with_actual_feature_state() {
        let mut seen = BTreeSet::new();
        for definition in CATALOG {
            let identity = rule_semantic_identity(definition.id).expect("catalog rule identity");
            assert_eq!(identity.rule_id, definition.id);
            assert!(identity.review_revision > 0);
            assert!(seen.insert(identity.rule_id));
            let digest = rule_semantic_identity_digest(definition.id).expect("catalog digest");
            assert_eq!(digest.len(), 64);
            assert!(
                digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            );

            match definition.language {
                Language::Qml | Language::JavaScript => {
                    let parser = identity.parser_features.get("qml-parser");
                    #[cfg(feature = "qml-parser")]
                    assert_eq!(parser.map(String::as_str), Some("tree-sitter-qmljs/0.3.1"));
                    #[cfg(not(feature = "qml-parser"))]
                    assert_eq!(
                        parser.map(String::as_str),
                        Some("lexical-fallback-unassigned")
                    );
                    assert!(!identity.semantic_limits.is_empty());
                }
                Language::Python => {
                    let parser = identity.parser_features.get("python-parser");
                    #[cfg(feature = "python-parser")]
                    assert_eq!(
                        parser.map(String::as_str),
                        Some("tree-sitter-python/0.25.0")
                    );
                    #[cfg(not(feature = "python-parser"))]
                    assert_eq!(
                        parser.map(String::as_str),
                        Some("lexical-fallback-no-python-flow")
                    );
                    assert!(
                        identity
                            .semantic_limits
                            .contains_key("python-flow-source-bytes")
                    );
                    assert!(identity.semantic_limits.contains_key("python-flow-time-ms"));
                }
                Language::Shell => {
                    assert!(identity.semantic_limits.contains_key("shell-parse-depth"));
                    assert!(identity.semantic_limits.contains_key("shell-staged-lines"));
                }
                Language::Context | Language::PayloadBinary => {
                    assert!(identity.parser_features.is_empty());
                    assert!(identity.semantic_limits.is_empty());
                }
            }
        }
        assert_eq!(seen.len(), CATALOG.len());
        assert_eq!(rule_semantics_catalog_digest().len(), 64);
    }
}
