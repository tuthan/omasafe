//! OmaSafe v0.2 deterministic payload/capability analysis engine.
//!
//! Foundations: the OmaSafe-owned rule catalog derived from the verified
//! Omarchy security surface, severity/policy identities, canonical result
//! normalization, bounded ingestion (filesystem trees and immutable Git
//! revisions), QML parsing with measured coverage (ADR 0001), and detectors
//! separating capability observation from suspicious-provenance findings.
//! Nothing here executes, sources, or renders scanned content.

pub mod detect;
pub mod fingerprint;
pub mod ingest;
pub mod payload;
pub mod policy;
pub mod rules;

#[cfg(feature = "qml-parser")]
pub mod qml;

pub use detect::{AnalysisArtifacts, analyze_inventory, parser_metadata};
pub use fingerprint::{Confidence, NormalizedResult, fingerprint_analysis, fingerprint_results};
pub use ingest::{
    IngestError, Limits, TargetSource, ensure_pinned_repository, ingest_filesystem,
    ingest_pinned_tree,
};
pub use omasafe_core::bounds::TimeBudget;
pub use payload::{CoverageState, PayloadEntry, PayloadInventory, PayloadKind};
pub use policy::policy_identity;
pub use rules::{
    Capability, EQUIVALENCE_MAP_VERSION, Language, RULE_CATALOG_VERSION, RuleDefinition,
    SEVERITY_TABLE_VERSION, SUPPORTED_SURFACE_VERSION, Severity, catalog, rule,
};
