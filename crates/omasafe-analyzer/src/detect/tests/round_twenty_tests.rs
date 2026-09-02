//! H5 payload reachability, anti-OmaSafe intent, and IPC lifecycle coverage.

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

#[test]
fn referenced_elf_is_a_medium_bundled_binary_finding() {
    let source = "Item { Process { command: [\"./helper\"] } }\n";
    let mut inventory = PayloadInventory {
        entries: vec![
            entry("Main.qml", PayloadKind::Qml, source.len()),
            entry("helper", PayloadKind::ElfBinary, 64),
        ],
        ..Default::default()
    };
    let artifacts = analyze_inventory(
        &mut inventory,
        &|entry| match entry.relative_path.as_str() {
            "Main.qml" => Some(source.as_bytes().to_vec()),
            "helper" => Some(b"\x7fELF\x02\x01\x01\0".to_vec()),
            _ => None,
        },
        &TimeBudget::default(),
    );
    let finding = artifacts
        .rendered_findings()
        .into_iter()
        .find(|finding| finding.rule_id == "oma.payload.bundled-binary")
        .expect("referenced ELF finding");
    assert_eq!(finding.severity, "medium");
    assert!(finding.evidence.contains("helper"));
    assert!(inventory.entries[1].invocation_target);
}

#[test]
fn unreferenced_elf_is_inventory_capability_context() {
    let source = "Item { Text { text: \"hello\" } }\n";
    let mut inventory = PayloadInventory {
        entries: vec![
            entry("Main.qml", PayloadKind::Qml, source.len()),
            entry("helper", PayloadKind::ElfBinary, 64),
        ],
        ..Default::default()
    };
    let artifacts = analyze_inventory(
        &mut inventory,
        &|entry| (entry.relative_path == "Main.qml").then(|| source.as_bytes().to_vec()),
        &TimeBudget::default(),
    );
    assert!(
        !artifacts
            .rendered_findings()
            .iter()
            .any(|finding| finding.rule_id == "oma.payload.bundled-binary")
    );
    assert!(artifacts.capabilities.iter().any(|capability| {
        capability.capability == "bundled-binary"
            && capability.relative_path == "helper"
            && capability.line.is_none()
    }));
    assert_eq!(inventory.entries[1].coverage_state, CoverageState::Analyzed);
}

#[test]
fn shell_execution_of_elf_is_a_reachability_edge() {
    let source = "#!/bin/sh\n./helper --version\n";
    let mut inventory = PayloadInventory {
        entries: vec![
            entry("install.sh", PayloadKind::Shell, source.len()),
            entry("helper", PayloadKind::ElfBinary, 64),
        ],
        ..Default::default()
    };
    let artifacts = analyze_inventory(
        &mut inventory,
        &|entry| match entry.relative_path.as_str() {
            "install.sh" => Some(source.as_bytes().to_vec()),
            _ => None,
        },
        &TimeBudget::default(),
    );
    assert!(
        artifacts
            .edges
            .iter()
            .any(|edge| edge.from_path == "install.sh" && edge.target_path == "helper")
    );
    assert!(
        artifacts
            .rendered_findings()
            .iter()
            .any(|finding| finding.rule_id == "oma.payload.bundled-binary")
    );
}

#[test]
fn state_tamper_intent_and_ipc_lifecycle_are_disclosed() {
    let source = r#"Item {
    Component.onCompleted: {
        shell.setPluginEnabled("other", false)
        shell.rescanPlugins()
        FileView { path: "~/.local/state/omasafe/overrides.json"; write: true }
    }
    // setPluginEnabled and ~/.local/state/omasafe are documentation only
}
"#;
    let mut inventory = PayloadInventory {
        entries: vec![entry("Main.qml", PayloadKind::Qml, source.len())],
        ..Default::default()
    };
    let artifacts = analyze_inventory(
        &mut inventory,
        &|_| Some(source.as_bytes().to_vec()),
        &TimeBudget::default(),
    );
    let findings = artifacts.rendered_findings();
    let tamper = findings
        .iter()
        .find(|finding| finding.rule_id == "oma.context.omasafe-state-tamper")
        .expect("tamper intent finding");
    assert_eq!(tamper.severity, "medium");
    assert!(tamper.review_guidance.contains("intent, not protection"));
    assert_eq!(
        artifacts
            .capabilities
            .iter()
            .filter(|capability| capability.capability == "shell-ipc-inventory")
            .count(),
        2
    );
}

#[test]
fn multiline_state_path_and_write_are_correlated_within_one_qml_object() {
    let source = r#"Item {
    FileView {
        path: "~/.local/state/omasafe/overrides.json"
        write: true
    }
    OtherObject {
        write: true
    }
}
"#;
    let mut inventory = PayloadInventory {
        entries: vec![entry("Main.qml", PayloadKind::Qml, source.len())],
        ..Default::default()
    };
    let artifacts = analyze_inventory(
        &mut inventory,
        &|_| Some(source.as_bytes().to_vec()),
        &TimeBudget::default(),
    );
    let findings = artifacts.rendered_findings();
    let tamper = findings
        .iter()
        .find(|finding| finding.rule_id == "oma.context.omasafe-state-tamper")
        .expect("multiline state tamper finding");
    assert_eq!(tamper.line, Some(4));
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding.rule_id == "oma.context.omasafe-state-tamper")
            .count(),
        1,
        "unrelated objects must not be correlated"
    );
}

#[test]
fn quoted_tamper_prose_is_not_an_intent_indicator() {
    let source = r#"Item {
    Text { text: "Never run rm ~/.local/state/omasafe by hand" }
}
"#;
    let mut inventory = PayloadInventory {
        entries: vec![entry("Main.qml", PayloadKind::Qml, source.len())],
        ..Default::default()
    };
    let artifacts = analyze_inventory(
        &mut inventory,
        &|_| Some(source.as_bytes().to_vec()),
        &TimeBudget::default(),
    );
    assert!(
        !artifacts
            .rendered_findings()
            .iter()
            .any(|finding| finding.rule_id == "oma.context.omasafe-state-tamper")
    );
}
