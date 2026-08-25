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

use serde::Serialize;

pub const ANALYSIS_SCHEMA_VERSION: &str = "omasafe.analysis.v1";

/// Versioned identity of everything that influences analysis output besides
/// the analyzed source itself. Any change here is labelled "analyzer update",
/// never plugin drift.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
}

/// The additive per-report analysis object.
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisSection {
    pub schema: &'static str,
    pub policy_identity: PolicyIdentity,
    /// Hex-encoded SHA-256 over sorted normalized results.
    pub analysis_fingerprint: String,
    pub coverage_limitations: Vec<String>,
}

impl AnalysisSection {
    pub fn new(
        policy_identity: PolicyIdentity,
        analysis_fingerprint: String,
        coverage_limitations: Vec<String>,
    ) -> Self {
        Self {
            schema: ANALYSIS_SCHEMA_VERSION,
            policy_identity,
            analysis_fingerprint,
            coverage_limitations,
        }
    }
}
