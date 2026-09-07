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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use omasafe_core::bounds::{
    DATAFLOW_TIME_BUDGET, DEFAULT_TIME_BUDGET, GIT_PROCESS_BUDGET, MAX_CACHE_BYTES,
    MAX_DATAFLOW_ASSIGNMENT_DEPTH, MAX_DATAFLOW_STATEMENTS, MAX_EVIDENCE_BYTES_PER_RESULT,
    MAX_FILE_BYTES, MAX_FILES, MAX_METADATA_BYTES, MAX_PROCESS_OUTPUT_BYTES_PER_STREAM,
    MAX_PYTHON_FLOW_BINDINGS, MAX_PYTHON_FLOW_DEPTH, MAX_PYTHON_FLOW_NODES,
    MAX_PYTHON_FLOW_SOURCE_BYTES, MAX_PYTHON_FLOW_STATEMENTS, MAX_SHELL_PARSE_CHILD_PROGRAMS,
    MAX_SHELL_PARSE_DEPTH, MAX_SHELL_PARSE_NODES, MAX_SHELL_PARSE_SOURCE_BYTES,
    MAX_SINK_REJECTIONS, MAX_STAGED_CHAIN_LINES, MAX_TOTAL_BYTES, MAX_TREE_DEPTH,
    PYTHON_FLOW_TIME_BUDGET, SAMPLE_BYTES, STAGED_CHAIN_TIME_BUDGET,
};
use omasafe_report::analysis::PolicyIdentity;

use crate::rules::{
    CATALOG, EQUIVALENCE_MAP_VERSION, RULE_CATALOG_VERSION, SEVERITY_TABLE_VERSION,
    SUPPORTED_SURFACE_VERSION, rule_semantic_identity_digest, rule_semantics_catalog_digest,
};

const COMPATIBILITY_SCHEMA: &str = "omasafe.review-compatibility.v1";
const COMPATIBILITY_PROJECTIONS: [&str; 4] =
    ["qml-python", "qml-only", "python-only", "lexical-only"];

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
    pub max_python_flow_source_bytes: usize,
    pub max_python_flow_nodes: usize,
    pub max_python_flow_statements: usize,
    pub max_python_flow_depth: usize,
    pub max_python_flow_bindings: usize,
    pub python_flow_time_budget_ms: u128,
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
        max_python_flow_source_bytes: MAX_PYTHON_FLOW_SOURCE_BYTES,
        max_python_flow_nodes: MAX_PYTHON_FLOW_NODES,
        max_python_flow_statements: MAX_PYTHON_FLOW_STATEMENTS,
        max_python_flow_depth: MAX_PYTHON_FLOW_DEPTH,
        max_python_flow_bindings: MAX_PYTHON_FLOW_BINDINGS,
        python_flow_time_budget_ms: PYTHON_FLOW_TIME_BUDGET.as_millis(),
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

/// Package the reviewed declaration alongside the analyzer. The declaration
/// is intentionally excluded from the source fingerprint because it records
/// review compatibility for a build rather than detector implementation.
pub const REVIEW_COMPATIBILITY_DECLARATION: &str = include_str!("../review-compatibility.json");

#[derive(Debug, Clone, Deserialize)]
struct CompatibilityDocument {
    schema: String,
    declarations: Vec<CompatibilityDeclaration>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompatibilityDeclaration {
    id: String,
    feature_projection: String,
    #[serde(default)]
    baseline_declaration_id: Option<String>,
    classification: String,
    detector_logic_fingerprint: Option<String>,
    semantic_catalog_digest: Option<String>,
    affected_rule_ids: Vec<String>,
    rule_semantic_digests: BTreeMap<String, String>,
    rule_review_revisions: BTreeMap<String, u32>,
    reviewer: String,
    date: String,
    rationale: String,
}

/// Builds the current policy identity. No timestamp or environment value
/// participates; two calls in one build always agree.
pub fn policy_identity() -> PolicyIdentity {
    let mut parser_versions = BTreeMap::new();
    parser_versions.insert("qml".to_owned(), QML_PARSER_IDENTITY.to_owned());
    parser_versions.insert(
        "python".to_owned(),
        if cfg!(feature = "python-parser") {
            "tree-sitter-python/0.25.0"
        } else {
            "lexical-fallback-no-python-flow"
        }
        .to_owned(),
    );
    let detector_logic_fingerprint = detector_logic_fingerprint();
    let semantic_catalog_digest = rule_semantics_catalog_digest();
    PolicyIdentity {
        analyzer_version: env!("CARGO_PKG_VERSION").to_owned(),
        rule_catalog_version: RULE_CATALOG_VERSION,
        rule_catalog_fingerprint: rule_catalog_fingerprint(),
        severity_table_version: SEVERITY_TABLE_VERSION,
        parser_versions,
        limits_fingerprint: limits_fingerprint(&limits_configuration()),
        equivalence_map_version: EQUIVALENCE_MAP_VERSION.map(str::to_owned),
        supported_surface_version: SUPPORTED_SURFACE_VERSION.to_owned(),
        detector_logic_fingerprint: Some(detector_logic_fingerprint.clone()),
        rule_semantics_catalog_digest: Some(semantic_catalog_digest.clone()),
        review_compatibility_declaration_id: current_compatibility_declaration_id(
            &detector_logic_fingerprint,
            &semantic_catalog_digest,
        ),
    }
}

fn detector_logic_fingerprint() -> String {
    let mut detector_hasher = Sha256::new();
    detector_hasher.update(b"omasafe.detector-logic.v1");
    detector_hasher.update((omasafe_core::CORE_LOGIC_FINGERPRINT.len() as u64).to_le_bytes());
    detector_hasher.update(omasafe_core::CORE_LOGIC_FINGERPRINT.as_bytes());
    let analyzer_fingerprint = env!("ANALYZER_LOGIC_FINGERPRINT");
    detector_hasher.update((analyzer_fingerprint.len() as u64).to_le_bytes());
    detector_hasher.update(analyzer_fingerprint.as_bytes());
    hex(&detector_hasher.finalize())
}

fn compatibility_document() -> Option<CompatibilityDocument> {
    let document: CompatibilityDocument =
        serde_json::from_str(REVIEW_COMPATIBILITY_DECLARATION).ok()?;
    validate_compatibility_document(&document).then_some(document)
}

fn current_rule_semantic_digests() -> BTreeMap<String, String> {
    CATALOG
        .iter()
        .filter_map(|definition| {
            rule_semantic_identity_digest(definition.id)
                .map(|digest| (definition.id.to_owned(), digest))
        })
        .collect()
}

fn current_rule_review_revisions() -> BTreeMap<String, u32> {
    CATALOG
        .iter()
        .filter_map(|definition| {
            crate::rules::rule_semantic_identity(definition.id)
                .map(|identity| (definition.id.to_owned(), identity.review_revision))
        })
        .collect()
}

fn semantic_map_digest(digests: &BTreeMap<String, String>) -> String {
    let value = serde_json::to_value(digests).expect("semantic map serialization cannot fail");
    let canonical = omasafe_core::scan_snapshot::canonical_json(&value);
    hex(&Sha256::digest(canonical.as_bytes()))
}

fn is_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn declaration_is_structurally_valid(declaration: &CompatibilityDeclaration) -> bool {
    declaration_digest(declaration).is_some_and(|digest| digest == declaration.id)
        && COMPATIBILITY_PROJECTIONS.contains(&declaration.feature_projection.as_str())
        && matches!(
            declaration.classification.as_str(),
            "semantic-change" | "review-compatible"
        )
        && declaration
            .detector_logic_fingerprint
            .as_deref()
            .is_some_and(is_hex_digest)
        && declaration
            .semantic_catalog_digest
            .as_deref()
            .is_some_and(is_hex_digest)
        && declaration.semantic_catalog_digest.as_deref()
            == Some(semantic_map_digest(&declaration.rule_semantic_digests).as_str())
        && !declaration.rule_semantic_digests.is_empty()
        && declaration.rule_semantic_digests.len() == declaration.rule_review_revisions.len()
        && declaration
            .rule_semantic_digests
            .iter()
            .all(|(rule_id, digest)| {
                rule_id.starts_with("oma.")
                    && is_hex_digest(digest)
                    && declaration
                        .rule_review_revisions
                        .get(rule_id)
                        .is_some_and(|revision| *revision > 0)
            })
        && declaration.affected_rule_ids.iter().all(|rule_id| {
            rule_id.starts_with("oma.") && declaration.rule_semantic_digests.contains_key(rule_id)
        })
        && declaration.affected_rule_ids.len()
            == declaration
                .affected_rule_ids
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
        && !declaration.reviewer.trim().is_empty()
        && !declaration.date.trim().is_empty()
        && !declaration.rationale.trim().is_empty()
}

fn validate_compatibility_document(document: &CompatibilityDocument) -> bool {
    if document.schema != COMPATIBILITY_SCHEMA || document.declarations.is_empty() {
        return false;
    }
    let mut ids = std::collections::BTreeSet::new();
    if document.declarations.iter().any(|declaration| {
        !ids.insert(declaration.id.as_str()) || !declaration_is_structurally_valid(declaration)
    }) {
        return false;
    }
    let known_rule_ids: std::collections::BTreeSet<_> =
        CATALOG.iter().map(|definition| definition.id).collect();
    if document.declarations.iter().any(|declaration| {
        declaration
            .rule_semantic_digests
            .keys()
            .any(|rule_id| !known_rule_ids.contains(rule_id.as_str()))
    }) {
        // A declaration retaining a retired or unknown row is history, but it
        // cannot be used as a current compatibility authority. Rejecting the
        // document here keeps an accidental lookup from authorizing it.
        return false;
    }

    for declaration in &document.declarations {
        let Some(baseline_id) = declaration.baseline_declaration_id.as_deref() else {
            if declaration.classification == "review-compatible" {
                return false;
            }
            if declaration.affected_rule_ids.is_empty() {
                return false;
            }
            continue;
        };
        if baseline_id == declaration.id {
            return false;
        }
        let Some(baseline) = declaration_by_id(document, baseline_id) else {
            return false;
        };
        if baseline.feature_projection != declaration.feature_projection {
            return false;
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut cursor = Some(declaration.id.as_str());
        while let Some(id) = cursor {
            if !seen.insert(id) {
                return false;
            }
            cursor = declaration_by_id(document, id)
                .and_then(|item| item.baseline_declaration_id.as_deref());
        }

        match declaration.classification.as_str() {
            "review-compatible" => {
                if !declaration.affected_rule_ids.is_empty()
                    || declaration.rule_semantic_digests != baseline.rule_semantic_digests
                    || declaration.rule_review_revisions != baseline.rule_review_revisions
                {
                    return false;
                }
            }
            "semantic-change" => {
                if declaration.affected_rule_ids.is_empty() {
                    return false;
                }
                let affected: std::collections::BTreeSet<_> = declaration
                    .affected_rule_ids
                    .iter()
                    .map(String::as_str)
                    .collect();
                for rule_id in &known_rule_ids {
                    let Some(current_digest) = declaration.rule_semantic_digests.get(*rule_id)
                    else {
                        return false;
                    };
                    let Some(baseline_digest) = baseline.rule_semantic_digests.get(*rule_id) else {
                        return false;
                    };
                    let Some(current_revision) = declaration.rule_review_revisions.get(*rule_id)
                    else {
                        return false;
                    };
                    let Some(baseline_revision) = baseline.rule_review_revisions.get(*rule_id)
                    else {
                        return false;
                    };
                    if affected.contains(rule_id) {
                        if current_digest == baseline_digest
                            || current_revision <= baseline_revision
                        {
                            return false;
                        }
                    } else if current_digest != baseline_digest
                        || current_revision != baseline_revision
                    {
                        return false;
                    }
                }
            }
            _ => unreachable!("structural validation checked classification"),
        }
    }
    true
}

fn declaration_digest(declaration: &CompatibilityDeclaration) -> Option<String> {
    let mut value = serde_json::to_value(declaration).ok()?;
    value.as_object_mut()?.remove("id");
    let digest =
        omasafe_core::scan_snapshot::canonical_digest("review-compatibility", "v1", &value);
    Some(digest)
}

fn current_compatibility_declaration_id(
    detector_logic: &str,
    semantic_catalog: &str,
) -> Option<String> {
    let document = compatibility_document()?;
    let current_rules = current_rule_semantic_digests();
    let current_revisions = current_rule_review_revisions();
    let projection = feature_projection();
    document.declarations.into_iter().find_map(|declaration| {
        let digest_matches = declaration_digest(&declaration);
        (declaration.feature_projection == projection
            && declaration.detector_logic_fingerprint.as_deref() == Some(detector_logic)
            && declaration.semantic_catalog_digest.as_deref() == Some(semantic_catalog)
            && declaration.rule_semantic_digests == current_rules
            && declaration.rule_review_revisions == current_revisions
            && digest_matches.as_deref() == Some(declaration.id.as_str()))
        .then_some(declaration.id)
    })
}

fn feature_projection() -> String {
    match (
        cfg!(feature = "qml-parser"),
        cfg!(feature = "python-parser"),
    ) {
        (true, true) => "qml-python".to_owned(),
        (true, false) => "qml-only".to_owned(),
        (false, true) => "python-only".to_owned(),
        (false, false) => "lexical-only".to_owned(),
    }
}

fn declaration_by_id<'a>(
    document: &'a CompatibilityDocument,
    id: &str,
) -> Option<&'a CompatibilityDeclaration> {
    document
        .declarations
        .iter()
        .find(|declaration| declaration.id == id)
}

fn declaration_lineage_contains(
    document: &CompatibilityDocument,
    current: &str,
    target: &str,
) -> bool {
    let mut cursor = Some(current);
    let mut seen = std::collections::BTreeSet::new();
    while let Some(id) = cursor {
        if !seen.insert(id) {
            return false;
        }
        if id == target {
            return true;
        }
        cursor = declaration_by_id(document, id)
            .and_then(|declaration| declaration.baseline_declaration_id.as_deref());
    }
    false
}

/// Validate whether a suppression created under a prior declared review can
/// survive a current declaration for this rule. A semantic-change declaration
/// only invalidates the rules it explicitly names; unchanged rules retain
/// their compatible review boundary.
pub fn suppression_semantic_compatible(
    rule_id: &str,
    stored_semantic_digest: Option<&str>,
    stored_declaration_id: Option<&str>,
    current_declaration_id: Option<&str>,
) -> bool {
    let (Some(stored_digest), Some(stored_id), Some(current_id)) = (
        stored_semantic_digest,
        stored_declaration_id,
        current_declaration_id,
    ) else {
        return false;
    };
    let Some(document) = compatibility_document() else {
        return false;
    };
    let Some(active_id) = current_compatibility_declaration_id(
        &detector_logic_fingerprint(),
        &rule_semantics_catalog_digest(),
    ) else {
        return false;
    };
    if active_id != current_id {
        return false;
    }
    suppression_semantic_compatible_in_document(
        &document,
        rule_id,
        stored_digest,
        stored_id,
        current_id,
    )
}

fn suppression_semantic_compatible_in_document(
    document: &CompatibilityDocument,
    rule_id: &str,
    stored_digest: &str,
    stored_id: &str,
    current_id: &str,
) -> bool {
    let Some(stored) = declaration_by_id(document, stored_id) else {
        return false;
    };
    let Some(current) = declaration_by_id(document, current_id) else {
        return false;
    };
    if !declaration_lineage_contains(document, current_id, stored_id)
        || current.affected_rule_ids.iter().any(|id| id == rule_id)
    {
        return false;
    }
    let Some(current_digest) = rule_semantic_identity_digest(rule_id) else {
        return false;
    };
    stored
        .rule_semantic_digests
        .get(rule_id)
        .is_some_and(|digest| digest == stored_digest && digest == &current_digest)
        && current
            .rule_semantic_digests
            .get(rule_id)
            .is_some_and(|digest| digest == &current_digest)
        && stored.rule_review_revisions.get(rule_id) == current.rule_review_revisions.get(rule_id)
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

    #[test]
    fn semantic_change_only_reconfirms_affected_rule() {
        let mut document = compatibility_document().expect("checked-in declarations are valid");
        let baseline = document
            .declarations
            .iter()
            .find(|declaration| declaration.feature_projection == feature_projection())
            .cloned()
            .expect("current projection declaration");
        let unaffected = "oma.qml.dynamic-reference";
        let affected = "oma.qml.process-execution";
        let unaffected_digest = rule_semantic_identity_digest(unaffected).unwrap();
        let affected_digest = rule_semantic_identity_digest(affected).unwrap();

        // Model a later semantic-change declaration linked to the prior
        // declaration. The changed row is deliberately synthetic; the
        // unaffected row remains byte-for-byte identical to the baseline.
        let mut changed = baseline.clone();
        changed.baseline_declaration_id = Some(baseline.id.clone());
        changed.classification = "semantic-change".to_owned();
        changed.affected_rule_ids = vec![affected.to_owned()];
        changed
            .rule_semantic_digests
            .insert(affected.to_owned(), "a".repeat(64));
        changed.rule_review_revisions.insert(
            affected.to_owned(),
            baseline.rule_review_revisions[affected] + 1,
        );
        changed.semantic_catalog_digest = Some(semantic_map_digest(&changed.rule_semantic_digests));
        changed.id = declaration_digest(&changed).unwrap();
        let current_id = changed.id.clone();
        document.declarations.push(changed);
        assert!(validate_compatibility_document(&document));

        // Reusing a suppression from the prior declaration remains valid for
        // an unchanged rule even though the current declaration is semantic-
        // change overall.
        assert!(suppression_semantic_compatible_in_document(
            &document,
            unaffected,
            &unaffected_digest,
            baseline.id.as_str(),
            &current_id,
        ));
        assert!(!suppression_semantic_compatible_in_document(
            &document,
            affected,
            &affected_digest,
            baseline.id.as_str(),
            &current_id,
        ));
    }

    #[test]
    fn invalid_canonical_maps_and_lineage_are_rejected() {
        let document = compatibility_document().expect("checked-in declarations are valid");

        let mut bad_map = document.clone();
        bad_map.declarations[0]
            .rule_semantic_digests
            .insert("oma.retired.rule".to_owned(), "0".repeat(64));
        bad_map.declarations[0].id = declaration_digest(&bad_map.declarations[0]).unwrap();
        assert!(!validate_compatibility_document(&bad_map));

        let mut bad_catalog_digest = document.clone();
        bad_catalog_digest.declarations[0].semantic_catalog_digest = Some("0".repeat(64));
        bad_catalog_digest.declarations[0].id =
            declaration_digest(&bad_catalog_digest.declarations[0]).unwrap();
        assert!(!validate_compatibility_document(&bad_catalog_digest));

        let mut bad_lineage = document.clone();
        bad_lineage.declarations[0].baseline_declaration_id = Some("missing".to_owned());
        bad_lineage.declarations[0].id = declaration_digest(&bad_lineage.declarations[0]).unwrap();
        assert!(!validate_compatibility_document(&bad_lineage));

        let mut bad_id = document;
        bad_id.declarations[0].id.replace_range(..1, "0");
        assert!(!validate_compatibility_document(&bad_id));
    }

    #[test]
    fn affected_rule_must_change_digest_and_revision_from_baseline() {
        let mut document = compatibility_document().expect("checked-in declarations are valid");
        let baseline = document.declarations[0].clone();
        let affected = "oma.qml.dynamic-reference";
        let mut changed = baseline.clone();
        changed.baseline_declaration_id = Some(baseline.id.clone());
        changed.classification = "semantic-change".to_owned();
        changed.affected_rule_ids = vec![affected.to_owned()];
        changed
            .rule_semantic_digests
            .insert(affected.to_owned(), "a".repeat(64));
        changed.semantic_catalog_digest = Some(semantic_map_digest(&changed.rule_semantic_digests));
        // The digest changed, but the review revision did not. This must not
        // pass as an affected semantic row.
        changed.id = declaration_digest(&changed).unwrap();
        document.declarations.push(changed);
        assert!(!validate_compatibility_document(&document));
    }

    #[test]
    fn undeclared_detector_or_catalog_identity_cannot_select_a_declaration() {
        assert!(current_compatibility_declaration_id(&"0".repeat(64), &"0".repeat(64)).is_none());
    }
}
