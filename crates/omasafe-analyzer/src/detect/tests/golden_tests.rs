// ---------------------------------------------------------------------------
// Characterization golden (Stage A1 of docs/detect-rs-maintenance-plan.md):
// the script-fixture corpus's normalized artifacts are frozen so the Stage A
// extraction can prove itself behavior-preserving in both feature
// configurations.
// ---------------------------------------------------------------------------

use crate::detect::*;
use crate::fingerprint::fingerprint_results;
use std::fmt::Write;

const GOLDEN: &str = include_str!("../golden/fixture-corpus.txt");

/// One entry per committed script fixture, in fixture order. The sources
/// are embedded at compile time, so a fixture edit fails this gate loudly
/// instead of drifting the baseline silently.
const FIXTURE_SCRIPTS: &[(&str, &str)] = &[
    (
        "benign-scripts",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/plugins/benign-scripts/install.sh"
        )),
    ),
    (
        "decode-execute",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/plugins/decode-execute/install.sh"
        )),
    ),
    (
        "download-execute-nopipe",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/plugins/download-execute-nopipe/install.sh"
        )),
    ),
    (
        "privileged-shared-temp",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/plugins/privileged-shared-temp/install.sh"
        )),
    ),
    (
        "privileged-shared-temp-controlled",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/plugins/privileged-shared-temp-controlled/install.sh"
        )),
    ),
    (
        "script-fp-fn",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/plugins/script-fp-fn/install.sh"
        )),
    ),
    (
        "reverse-shell",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/plugins/reverse-shell/install.sh"
        )),
    ),
];

fn entry(path: &str, size: usize) -> PayloadEntry {
    PayloadEntry {
        relative_path: path.to_owned(),
        kind: PayloadKind::Shell,
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

/// Escape one evidence/detail string onto a single golden line.
fn one_line(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn golden_output() -> String {
    let stored: Vec<(String, Vec<u8>)> = FIXTURE_SCRIPTS
        .iter()
        .map(|(plugin, script)| (format!("{plugin}/install.sh"), script.as_bytes().to_vec()))
        .collect();
    let mut inventory = PayloadInventory::default();
    for (path, script) in &stored {
        inventory.entries.push(entry(path, script.len()));
    }
    let borrowed: Vec<(&str, &[u8])> = stored
        .iter()
        .map(|(path, script)| (path.as_str(), script.as_slice()))
        .collect();
    let (artifacts, _) = super::rule_contracts::analyze_with(inventory, &borrowed);

    let mut out = String::new();
    for finding in artifacts.rendered_findings() {
        let _ = writeln!(
            out,
            "finding {} {} {} {} {}",
            finding.rule_id,
            finding.severity,
            finding.relative_path,
            finding.line.unwrap_or(0),
            one_line(&finding.evidence)
        );
    }
    for capability in &artifacts.capabilities {
        let _ = writeln!(
            out,
            "capability {} {} {} {} {} {}",
            capability.capability,
            capability.language,
            capability.relative_path,
            capability.line.unwrap_or(0),
            capability.source_rule_id.as_deref().unwrap_or("-"),
            one_line(&capability.detail)
        );
    }
    for limitation in &artifacts.limitations {
        let _ = writeln!(out, "limitation {}", one_line(limitation));
    }
    let _ = writeln!(
        out,
        "fingerprint {}",
        fingerprint_results(&artifacts.results)
    );
    out
}

#[test]
fn fixture_corpus_matches_the_golden_record() {
    let output = golden_output();
    if std::env::var("OMASAFE_GOLDEN_PRINT").is_ok() {
        print!("{output}");
    }
    assert_eq!(
        output, GOLDEN,
        "normalized fixture artifacts changed — if intentional, update \
             detect/golden/fixture-corpus.txt (raw output: OMASAFE_GOLDEN_PRINT=1 \
             cargo test -p omasafe-analyzer fixture_corpus_matches -- --nocapture) \
             and review the diff as a behavior change"
    );
    assert_eq!(
        output,
        golden_output(),
        "repeated analyses must be byte-identical (determinism)"
    );
}
