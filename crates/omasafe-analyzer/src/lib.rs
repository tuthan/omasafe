//! OmaSafe v0.2 deterministic payload/capability analysis engine.
//!
//! S0 foundations: the OmaSafe-owned rule catalog derived from the verified
//! Omarchy security surface, the severity table, the policy identity, and the
//! analysis fingerprint canonicalization. Ingestion, parsers, and detectors
//! land in later slices; nothing here executes scanned content.

pub mod fingerprint;
pub mod policy;
pub mod rules;

pub use fingerprint::{NormalizedResult, fingerprint_results};
pub use policy::policy_identity;
pub use rules::{
    Capability, EQUIVALENCE_MAP_VERSION, Language, RULE_CATALOG_VERSION, RuleDefinition,
    SEVERITY_TABLE_VERSION, SUPPORTED_SURFACE_VERSION, Severity, catalog, rule,
};
