//! Policy identity construction: a deterministic fingerprint over every
//! configured input that influences analysis output besides the source itself.
//!
//! Source drift and analyzer updates are different event types; the policy
//! identity is what makes that distinction decidable. Only limits that can
//! change analysis outcomes or coverage disclosures participate — presentation
//! budgets (e.g. diff rendering) are deliberately excluded so unrelated
//! changes never masquerade as analyzer updates.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Serialize;
use sha2::{Digest, Sha256};

use omasafe_core::bounds::{
    DATAFLOW_TIME_BUDGET, DEFAULT_TIME_BUDGET, GIT_PROCESS_BUDGET, MAX_CACHE_BYTES,
    MAX_DATAFLOW_ASSIGNMENT_DEPTH, MAX_DATAFLOW_STATEMENTS, MAX_EVIDENCE_BYTES_PER_RESULT,
    MAX_FILE_BYTES, MAX_FILES, MAX_METADATA_BYTES, MAX_PROCESS_OUTPUT_BYTES_PER_STREAM,
    MAX_SHELL_PARSE_CHILD_PROGRAMS, MAX_SHELL_PARSE_DEPTH, MAX_SHELL_PARSE_NODES,
    MAX_SHELL_PARSE_SOURCE_BYTES, MAX_SINK_REJECTIONS, MAX_STAGED_CHAIN_LINES, MAX_TOTAL_BYTES,
    MAX_TREE_DEPTH, SAMPLE_BYTES, STAGED_CHAIN_TIME_BUDGET,
};
use omasafe_report::analysis::PolicyIdentity;

use crate::rules::{
    CATALOG, EQUIVALENCE_MAP_VERSION, RULE_CATALOG_VERSION, SEVERITY_TABLE_VERSION,
    SUPPORTED_SURFACE_VERSION,
};

/// The configured ingestion limits hashed into the policy identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LimitsConfiguration {
    pub max_files: usize,
    pub max_file_bytes: u64,
    pub max_total_bytes: u64,
    pub max_metadata_bytes: usize,
    pub sample_bytes: u64,
    pub max_tree_depth: usize,
    pub default_time_budget_ms: u128,
    pub git_process_budget_ms: u128,
    pub max_cache_bytes: u64,
    /// Evidence caps shape coverage/truncation disclosure, hence policy.
    pub max_evidence_bytes_per_result: usize,
    /// Sink-rejection retention cap shapes limitation truncation disclosure,
    /// hence policy.
    pub max_sink_rejections: usize,
    /// Child-output capture cap feeds analysis input and truncation states.
    pub max_process_output_bytes_per_stream: usize,
    /// Maximum QML/JS statements visited by bounded intra-file dataflow.
    pub max_dataflow_statements: usize,
    /// Maximum recursive assignment/expression depth followed by dataflow.
    pub max_dataflow_assignment_depth: usize,
    /// Per-file dataflow wall-clock budget in milliseconds.
    pub dataflow_time_budget_ms: u128,
    /// Maximum physical shell lines considered by staged chain tracking.
    pub max_staged_chain_lines: usize,
    /// Per-file staged shell-chain wall-clock budget in milliseconds.
    pub staged_chain_time_budget_ms: u128,
    /// Maximum recursive depth used while constructing typed shell IR.
    pub max_shell_parse_depth: usize,
    /// Maximum typed shell IR nodes constructed in one source analysis.
    pub max_shell_parse_nodes: usize,
    /// Maximum shell command/process-substitution child programs constructed.
    pub max_shell_parse_child_programs: usize,
    /// Aggregate source bytes retained for recursively parsed shell children.
    pub max_shell_parse_source_bytes: usize,
}

pub fn limits_configuration() -> LimitsConfiguration {
    LimitsConfiguration {
        max_files: MAX_FILES,
        max_file_bytes: MAX_FILE_BYTES,
        max_total_bytes: MAX_TOTAL_BYTES,
        max_metadata_bytes: MAX_METADATA_BYTES,
        sample_bytes: SAMPLE_BYTES,
        max_tree_depth: MAX_TREE_DEPTH,
        default_time_budget_ms: DEFAULT_TIME_BUDGET.as_millis(),
        git_process_budget_ms: GIT_PROCESS_BUDGET.as_millis(),
        max_cache_bytes: MAX_CACHE_BYTES,
        max_evidence_bytes_per_result: MAX_EVIDENCE_BYTES_PER_RESULT,
        max_sink_rejections: MAX_SINK_REJECTIONS,
        max_process_output_bytes_per_stream: MAX_PROCESS_OUTPUT_BYTES_PER_STREAM,
        max_dataflow_statements: MAX_DATAFLOW_STATEMENTS,
        max_dataflow_assignment_depth: MAX_DATAFLOW_ASSIGNMENT_DEPTH,
        dataflow_time_budget_ms: DATAFLOW_TIME_BUDGET.as_millis(),
        max_staged_chain_lines: MAX_STAGED_CHAIN_LINES,
        staged_chain_time_budget_ms: STAGED_CHAIN_TIME_BUDGET.as_millis(),
        max_shell_parse_depth: MAX_SHELL_PARSE_DEPTH,
        max_shell_parse_nodes: MAX_SHELL_PARSE_NODES,
        max_shell_parse_child_programs: MAX_SHELL_PARSE_CHILD_PROGRAMS,
        max_shell_parse_source_bytes: MAX_SHELL_PARSE_SOURCE_BYTES,
    }
}

pub fn limits_fingerprint(limits: &LimitsConfiguration) -> String {
    let canonical = serde_json::to_vec(limits).expect("limits serialization cannot fail");
    hex(&Sha256::digest(canonical))
}

/// SHA-256 over the serialized rule catalog content. Version numbers alone
/// cannot guarantee meaning stability across builds; content hashing can.
/// Deterministic for a given catalog source; computed once per process.
pub fn rule_catalog_fingerprint() -> String {
    static FINGERPRINT: OnceLock<String> = OnceLock::new();
    FINGERPRINT
        .get_or_init(|| {
            let canonical = serde_json::to_vec(CATALOG).expect("catalog serialization cannot fail");
            hex(&Sha256::digest(canonical))
        })
        .clone()
}

/// The QML parsing strategy this build was compiled with. Builds with the
/// `qml-parser` feature parse real syntax; builds without it fall back to
/// lexical detection and say so, so report consumers can tell the difference
/// from the policy identity alone (ADR 0001).
#[cfg(feature = "qml-parser")]
pub const QML_PARSER_IDENTITY: &str = "tree-sitter-qmljs/0.3.1";
#[cfg(not(feature = "qml-parser"))]
pub const QML_PARSER_IDENTITY: &str = "lexical-fallback-unassigned";

/// Builds the current policy identity. No timestamp or environment value
/// participates; two calls in one build always agree.
pub fn policy_identity() -> PolicyIdentity {
    let mut parser_versions = BTreeMap::new();
    parser_versions.insert("qml".to_owned(), QML_PARSER_IDENTITY.to_owned());
    PolicyIdentity {
        analyzer_version: env!("CARGO_PKG_VERSION").to_owned(),
        rule_catalog_version: RULE_CATALOG_VERSION,
        rule_catalog_fingerprint: rule_catalog_fingerprint(),
        severity_table_version: SEVERITY_TABLE_VERSION,
        parser_versions,
        limits_fingerprint: limits_fingerprint(&limits_configuration()),
        equivalence_map_version: EQUIVALENCE_MAP_VERSION.map(str::to_owned),
        supported_surface_version: SUPPORTED_SURFACE_VERSION.to_owned(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_identity_is_deterministic_across_calls() {
        assert_eq!(
            serde_json::to_vec(&policy_identity()).unwrap(),
            serde_json::to_vec(&policy_identity()).unwrap()
        );
    }

    #[test]
    fn policy_identity_excludes_timestamps_and_paths() {
        let rendered = String::from_utf8(serde_json::to_vec(&policy_identity()).unwrap()).unwrap();
        assert!(!rendered.contains("generated_at"));
        assert!(!rendered.contains(std::env::temp_dir().to_str().unwrap()));
    }

    #[test]
    fn limits_fingerprint_tracks_limit_changes() {
        let mut changed = limits_configuration();
        let baseline = limits_fingerprint(&changed);
        changed.max_files += 1;
        assert_ne!(limits_fingerprint(&changed), baseline);
    }

    #[test]
    fn limits_policy_excludes_presentation_only_diff_budget() {
        // MAX_DIFF_BYTES is a rendering budget owned by plugin-trust; it must
        // not appear in analyzer limits so diff-display changes stay inert.
        let rendered =
            String::from_utf8(serde_json::to_vec(&limits_configuration()).unwrap()).unwrap();
        assert!(!rendered.contains("max_diff_bytes"));
    }

    #[test]
    fn catalog_fingerprint_covers_every_rule_and_is_stable() {
        let baseline = rule_catalog_fingerprint();
        assert_eq!(rule_catalog_fingerprint(), baseline);
        assert_eq!(baseline.len(), 64);
        // Every definition participates: serializing one rule alone cannot
        // produce the same digest prefix structure as the whole catalog.
        let single = serde_json::to_vec(&CATALOG[0]).unwrap();
        assert_ne!(hex(&Sha256::digest(single)), baseline);
    }

    #[test]
    fn qml_parser_state_is_explicit_and_feature_consistent() {
        let identity = policy_identity();
        let reported = identity.parser_versions.get("qml").map(String::as_str);
        #[cfg(feature = "qml-parser")]
        {
            assert_eq!(reported, Some(crate::qml::QML_PARSER_REPORT_VALUE));
            assert!(reported.unwrap().starts_with("tree-sitter-qmljs/"));
        }
        #[cfg(not(feature = "qml-parser"))]
        assert_eq!(reported, Some("lexical-fallback-unassigned"));
    }
}
