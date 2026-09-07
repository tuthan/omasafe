//! Additive analysis section for the `omasafe.report.v1` envelope.
//!
//! Analyzer-bearing commands (v0.2: `plugins analyze`, `scan-plugin`) embed an
//! optional [`AnalysisSection`] in their report result. Inventory, trust, diff,
//! and scan results remain byte-compatible: they simply omit this section.
//! Within the v0.x series the envelope is only extended additively; consumers
//! must ignore unknown fields.
//!
//! The analysis fingerprint is computed by `omasafe-analyzer` over normalized
//! semantic results only. It excludes timestamps, prose, excerpts, temporary
//! paths, and tool build versions by construction, so identical source identity
//! plus identical policy identity yields an identical fingerprint.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const ANALYSIS_SCHEMA_VERSION: &str = "omasafe.analysis.v1";

/// Versioned identity of everything that influences analysis output besides
/// the analyzed source itself. Any change here is labelled "analyzer update",
/// never plugin drift.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyIdentity {
    /// Version of the `omasafe-analyzer` crate that produced the results.
    pub analyzer_version: String,
    /// Monotonic version of the OmaSafe-owned rule catalog.
    pub rule_catalog_version: u32,
    /// SHA-256 over the serialized catalog content, so meaning changes are
    /// caught even if a version bump was forgotten.
    pub rule_catalog_fingerprint: String,
    /// Monotonic version of the severity table; meaning changes require a bump.
    pub severity_table_version: u32,
    /// Parser name to version (or explicit fallback label) actually in use.
    pub parser_versions: BTreeMap<String, String>,
    /// SHA-256 over the canonical configured ingestion limits.
    pub limits_fingerprint: String,
    /// Version of the external marketplace rule-equivalence map, when present.
    pub equivalence_map_version: Option<String>,
    /// Version of the verified Omarchy security-surface reference document.
    pub supported_surface_version: String,
    /// Build-derived detector implementation identity. Missing on legacy
    /// producers and therefore never treated as current full identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detector_logic_fingerprint: Option<String>,
    /// Digest of the declared per-rule semantic meanings, when reviewed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_semantics_catalog_digest: Option<String>,
    /// Immutable compatibility declaration covering the current build.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_compatibility_declaration_id: Option<String>,
}

/// The parser build actually used, per ADR 0001. Absent (`null`) in
/// lexical-fallback builds so consumers can weigh evidence quality directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParserMetadata {
    pub grammar: String,
    pub grammar_version: String,
    pub tree_sitter_version: String,
    pub language_abi_version: usize,
}

/// One fingerprintable finding rendered with its catalog facts. `evidence`
/// carries the normalized semantic value capped for presentation; the
/// fingerprint always covers the uncapped value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RenderedFinding {
    pub rule_id: String,
    pub title: String,
    /// Lowercase severity name from the catalog's severity table.
    pub severity: String,
    pub language: String,
    pub capability: String,
    pub relative_path: String,
    pub line: Option<u32>,
    /// Capped matched text or dynamic-sink description.
    pub evidence: String,
    /// Evidence quality; `null` where no parser participated at all.
    pub confidence: Option<String>,
    pub explanation: String,
    pub review_guidance: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_semantic_identity_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub analysis_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_summary: Option<EvidenceSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presentation: Option<PresentationMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_relative_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurrence_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_steps: Option<Vec<EvidenceStep>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior_context: Option<BehaviorContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceStep {
    pub id: String,
    pub role: String,
    pub relative_path: String,
    pub display_relative_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub column: Option<u32>,
    pub analysis_method: String,
    pub detail: String,
    pub origin: String,
    pub redacted: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvidenceSummary {
    pub total: usize,
    pub emitted: usize,
    pub omitted: usize,
    pub observation_collection_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PresentationMetadata {
    pub redacted: bool,
    pub truncated: bool,
    pub redaction_classes: Vec<String>,
    pub omitted_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BehaviorContext {
    pub connection: String,
    pub source_class: String,
    pub sink_kind: String,
    pub sink_argument_role: String,
    pub trigger: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<DestinationContext>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DestinationContext {
    pub scheme: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub path_display: Option<String>,
    pub dynamic: bool,
    pub redacted: bool,
}

/// An observed ability. Capability occurrences are context, never assertions
/// of malicious behavior, and do not participate in the analysis fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct CapabilityOccurrence {
    pub capability: String,
    pub language: String,
    /// Filled by the orchestrator after per-file analysis.
    pub relative_path: String,
    pub line: Option<u32>,
    /// Stable catalog rule covering this capability, when one exists yet.
    pub source_rule_id: Option<String>,
    /// Short factual detail (the sink spelling as written).
    pub detail: String,
    pub confidence: Option<String>,
    /// Catalog explanation for the covering rule.
    pub explanation: String,
    /// Catalog review guidance for the covering rule.
    pub review_guidance: String,
}

/// A literal file reference from analyzed code to an inventoried entry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct InvocationEdge {
    pub from_path: String,
    pub line: Option<u32>,
    pub target_path: String,
}

/// Which external baseline vocabulary this analysis's rule set was mapped
/// against, recorded so staleness is visible to consumers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EquivalenceSummary {
    pub map_version: String,
    pub external_system: String,
    pub external_ruleset_name: String,
    pub external_ruleset_version: String,
}

/// The additive per-report analysis object.
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisSection {
    pub schema: &'static str,
    pub policy_identity: PolicyIdentity,
    /// Hex-encoded SHA-256 over sorted normalized results (findings only).
    pub analysis_fingerprint: String,
    pub coverage_limitations: Vec<String>,
    /// Fingerprintable findings with catalog facts attached.
    pub findings: Vec<RenderedFinding>,
    /// Ability observations; excluded from the fingerprint by contract.
    pub capabilities: Vec<CapabilityOccurrence>,
    /// Resolved literal references between inventoried files.
    pub invocation_edges: Vec<InvocationEdge>,
    /// Parser build metadata; `None` in lexical-fallback builds (ADR 0001).
    pub parser: Option<ParserMetadata>,
    /// External baseline mapping summary; `None` when no map ships.
    pub equivalence: Option<EquivalenceSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parsers: Option<BTreeMap<String, ParserReportMetadata>>,
    #[serde(default)]
    pub coverage_gaps: Vec<CoverageGap>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ParserReportMetadata {
    pub method: String,
    pub grammar: String,
    pub grammar_version: String,
    pub runtime_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageGap {
    pub reason: String,
    pub language: String,
    pub rule_ids: Vec<String>,
    pub relative_path: Option<String>,
    pub line: Option<u32>,
    pub impact: String,
    pub detail: String,
}

impl AnalysisSection {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        policy_identity: PolicyIdentity,
        analysis_fingerprint: String,
        coverage_limitations: Vec<String>,
        findings: Vec<RenderedFinding>,
        capabilities: Vec<CapabilityOccurrence>,
        invocation_edges: Vec<InvocationEdge>,
        parser: Option<ParserMetadata>,
        equivalence: Option<EquivalenceSummary>,
    ) -> Self {
        Self {
            schema: ANALYSIS_SCHEMA_VERSION,
            policy_identity,
            analysis_fingerprint,
            coverage_limitations,
            findings,
            capabilities,
            invocation_edges,
            parser,
            equivalence,
            parsers: None,
            coverage_gaps: Vec::new(),
        }
    }
}
