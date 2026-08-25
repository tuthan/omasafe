//! OmaSafe v0.2 deterministic payload/capability analysis engine.
//!
//! S0 foundations: the OmaSafe-owned rule catalog derived from the verified
//! Omarchy security surface, the severity table, the policy identity, and the
//! analysis fingerprint canonicalization. S1 adds bounded payload ingestion:
//! filesystem trees and immutable Git revisions are inventoried with explicit
//! coverage states before any language analyzer exists. Nothing here executes,
//! sources, or renders scanned content.

pub mod fingerprint;
pub mod ingest;
pub mod payload;
pub mod policy;
pub mod rules;

pub use fingerprint::{Confidence, NormalizedResult, fingerprint_results};
pub use ingest::{
    IngestError, Limits, TargetSource, ensure_pinned_repository, ingest_filesystem,
    ingest_pinned_tree,
};
pub use payload::{CoverageState, PayloadEntry, PayloadInventory, PayloadKind};
pub use policy::policy_identity;
pub use rules::{
    Capability, EQUIVALENCE_MAP_VERSION, Language, RULE_CATALOG_VERSION, RuleDefinition,
    SEVERITY_TABLE_VERSION, SUPPORTED_SURFACE_VERSION, Severity, catalog, rule,
};
