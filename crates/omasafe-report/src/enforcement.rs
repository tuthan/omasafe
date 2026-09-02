//! Typed enforcement decisions for the additive `omasafe.report.v1` surface.
//!
//! The analyzer's [`crate::analysis::PolicyIdentity`] describes what can
//! change analysis output. Enforcement has a separate identity: changing the
//! blocking threshold, the admitted rule families, coverage requirements, or
//! the override schema must never look like plugin drift. This module owns the
//! versioned values and the pure fail-closed evaluator; lifecycle mutation and
//! persistence remain CLI responsibilities.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::analysis::PolicyIdentity;

pub const ENFORCEMENT_SCHEMA_VERSION: &str = "omasafe.enforcement.v1";
pub const ENFORCEMENT_POLICY_SCHEMA_VERSION: &str = "omasafe.enforcement-policy.v1";
pub const ENFORCEMENT_POLICY_VERSION: u32 = 1;
pub const OVERRIDE_SCHEMA_VERSION: &str = "omasafe.override.v1";
pub const ENFORCEMENT_AUDIT_SCHEMA_VERSION: &str = "omasafe.enforcement-audit.v1";

/// H7's precision threshold for promoting a rule family into hardened
/// blocking. The threshold is intentionally strict: one false positive or an
/// unmeasured result keeps a family audit-only.
pub const H8B_PRECISION_THRESHOLD: f64 = 1.0;
/// H7's independently labelled fixture threshold for a blocking family.
pub const H8B_FIXTURE_DETECTION_THRESHOLD: f64 = 1.0;

/// The lifecycle policy selected by the caller. Advisory preserves the v0.2
/// reporting behavior; hardened adds the precision-independent gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementMode {
    Advisory,
    Hardened,
}

impl EnforcementMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
            Self::Hardened => "hardened",
        }
    }
}

impl std::str::FromStr for EnforcementMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "advisory" => Ok(Self::Advisory),
            "hardened" => Ok(Self::Hardened),
            _ => Err(format!(
                "policy must be advisory or hardened, got {value:?}"
            )),
        }
    }
}

/// The three orthogonal outcome fields consumed by the future panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvaluationState {
    Evaluated,
    NotEvaluated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementOutcome {
    Allow,
    Block,
}

impl EnforcementOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationBasis {
    Policy,
    Override,
}

/// A rule family admitted by H8b. Precision is optional because an empty or
/// untriaged H7 ledger must remain distinguishable from measured zero.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockingRuleFamily {
    pub rule_id: String,
    pub precision: Option<f64>,
    pub fixture_detection_rate: Option<f64>,
}

fn clears_h8b_threshold(value: Option<f64>, threshold: f64) -> bool {
    matches!(
        value,
        Some(value)
            if value.is_finite()
                && (0.0..=1.0).contains(&value)
                && value >= threshold
    )
}

/// Admit only families backed by both H7 measurements. This is deliberately
/// a pure filter over measured data: analyzer rule semantics never change, and
/// an absent/partial measurement cannot accidentally become a blocker.
pub fn admit_blocking_rule_families(
    candidates: impl IntoIterator<Item = BlockingRuleFamily>,
) -> Vec<BlockingRuleFamily> {
    let mut admitted: Vec<_> = candidates
        .into_iter()
        .filter(|family| {
            !family.rule_id.is_empty()
                && clears_h8b_threshold(family.precision, H8B_PRECISION_THRESHOLD)
                && clears_h8b_threshold(
                    family.fixture_detection_rate,
                    H8B_FIXTURE_DETECTION_THRESHOLD,
                )
        })
        .collect();
    admitted.sort_by(|left, right| {
        left.rule_id
            .cmp(&right.rule_id)
            .then_with(|| option_f64_cmp(left.precision, right.precision))
            .then_with(|| option_f64_cmp(left.fixture_detection_rate, right.fixture_detection_rate))
    });
    admitted.dedup_by(|left, right| left.rule_id == right.rule_id);
    admitted
}

/// Checked-in H8b admission result. The current real-plugin dispositions do
/// not cover a complete High-severity family, so no family is admitted in this
/// release. Maintainers should update this measured input (and the published
/// H8b report) after additional High-family triage; the policy identity will
/// then change automatically.
pub fn h8b_blocking_rule_families() -> Vec<BlockingRuleFamily> {
    admit_blocking_rule_families(std::iter::empty())
}

/// Inputs that are independent of rule precision and therefore safe to gate
/// as soon as H8a lands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageRequirements {
    pub require_complete_analysis: bool,
    pub require_fresh_analyzer_identity: bool,
    pub require_fresh_enforcement_policy_identity: bool,
    pub require_installed_tree_postconditions: bool,
}

impl Default for CoverageRequirements {
    fn default() -> Self {
        Self {
            require_complete_analysis: true,
            require_fresh_analyzer_identity: true,
            require_fresh_enforcement_policy_identity: true,
            require_installed_tree_postconditions: true,
        }
    }
}

/// Versioned enforcement configuration. Its canonical JSON digest is the
/// enforcement-policy identity bound into decisions and overrides.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnforcementPolicy {
    pub schema: String,
    pub version: u32,
    pub mode: EnforcementMode,
    pub blocking_threshold: String,
    pub blocking_rule_families: Vec<BlockingRuleFamily>,
    pub coverage_requirements: CoverageRequirements,
    pub installed_tree_postconditions: Vec<String>,
    pub override_schema: String,
}

impl EnforcementPolicy {
    /// H8b's evidence-gated admission is empty for the checked-in H7 result.
    /// H8a remains useful when no family clears the threshold, and the policy
    /// identity still records that measured outcome.
    pub fn new(mode: EnforcementMode) -> Self {
        Self {
            schema: ENFORCEMENT_POLICY_SCHEMA_VERSION.to_owned(),
            version: ENFORCEMENT_POLICY_VERSION,
            mode,
            blocking_threshold: "high".to_owned(),
            blocking_rule_families: h8b_blocking_rule_families(),
            coverage_requirements: CoverageRequirements::default(),
            installed_tree_postconditions: vec![
                "installed-tree-bytes-match-reviewed-candidate".to_owned(),
                "installed-tree-analysis-matches-reviewed-candidate".to_owned(),
                "installed-tree-coverage-matches-reviewed-candidate".to_owned(),
            ],
            override_schema: OVERRIDE_SCHEMA_VERSION.to_owned(),
        }
    }

    /// Returns a stable SHA-256 over the policy's canonical field order.
    pub fn identity(&self) -> String {
        // Rule-family and postcondition lists are sets in the policy
        // contract. Canonicalize their order so equivalent configuration
        // assembled by two callers cannot produce different identities.
        let mut canonical = self.clone();
        canonical.blocking_rule_families.sort_by(|left, right| {
            left.rule_id
                .cmp(&right.rule_id)
                .then_with(|| option_f64_cmp(left.precision, right.precision))
                .then_with(|| {
                    option_f64_cmp(left.fixture_detection_rate, right.fixture_detection_rate)
                })
        });
        canonical.installed_tree_postconditions.sort_unstable();
        let bytes =
            serde_json::to_vec(&canonical).expect("enforcement policy serialization cannot fail");
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn blocking_rule_ids(&self, observed: &[String]) -> Vec<String> {
        let mut ids: Vec<String> = self
            .blocking_rule_families
            .iter()
            .filter(|family| observed.iter().any(|id| id == &family.rule_id))
            .map(|family| family.rule_id.clone())
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// Evaluate one lifecycle operation without mutating anything. A missing
    /// or invalid override never weakens a block; a valid exact override may
    /// authorize an allow while retaining all blocker codes and rule IDs.
    pub fn evaluate(&self, input: EnforcementEvaluation) -> EnforcementDecision {
        let mut reason_codes = Vec::new();
        let blocking_rule_ids = self.blocking_rule_ids(&input.observed_rule_ids);

        if self.mode == EnforcementMode::Hardened {
            if self.coverage_requirements.require_complete_analysis
                && !input.coverage_limitations.is_empty()
            {
                reason_codes.push("coverage-incomplete".to_owned());
            }
            if self.coverage_requirements.require_fresh_analyzer_identity
                && !input.analyzer_identity_current
            {
                reason_codes.push("analyzer-identity-stale".to_owned());
            }
            if self
                .coverage_requirements
                .require_fresh_enforcement_policy_identity
                && !input.enforcement_policy_identity_current
            {
                reason_codes.push("enforcement-policy-identity-stale".to_owned());
            }
            if self
                .coverage_requirements
                .require_installed_tree_postconditions
                && !input.installed_tree_postconditions_passed
            {
                reason_codes.push("installed-tree-postcondition-failed".to_owned());
            }
            if !input.unsupported_executable_paths.is_empty() && !input.executable_digest_approved {
                reason_codes.push("unsupported-executable".to_owned());
            }
            if !blocking_rule_ids.is_empty() {
                reason_codes.push("blocking-rule-family".to_owned());
            }
        }

        reason_codes.sort();
        reason_codes.dedup();
        let has_blockers = !reason_codes.is_empty();
        let override_usable = input.override_present && input.override_valid && has_blockers;
        if input.override_present && !input.override_valid {
            reason_codes.push("override-expired-or-mismatched".to_owned());
            reason_codes.sort();
            reason_codes.dedup();
        }

        let outcome = if has_blockers && !override_usable {
            EnforcementOutcome::Block
        } else {
            EnforcementOutcome::Allow
        };
        let authorization_basis = if override_usable {
            Some(AuthorizationBasis::Override)
        } else {
            Some(AuthorizationBasis::Policy)
        };

        EnforcementDecision {
            schema: ENFORCEMENT_SCHEMA_VERSION.to_owned(),
            plugin_id: input.plugin_id,
            operation: input.operation,
            evaluation_state: EvaluationState::Evaluated,
            outcome,
            authorization_basis,
            installed_tree_postconditions_passed: input.installed_tree_postconditions_passed,
            reason_codes,
            blocking_rule_ids,
            coverage_counts: input.coverage_counts,
            coverage_limitations: input.coverage_limitations,
            commit: input.commit,
            tree: input.tree,
            content_digest: input.content_digest,
            analyzer_policy_identity: input.analyzer_policy_identity,
            enforcement_policy_identity: self.identity(),
            override_binding: input.override_binding,
            audit_event_id: input.audit_event_id,
            evaluated_at: input.evaluated_at,
            native_install_not_interposed: input.native_install_not_interposed,
        }
    }
}

fn option_f64_cmp(left: Option<f64>, right: Option<f64>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.partial_cmp(&right).unwrap_or(Ordering::Equal),
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
    }
}

/// Facts collected by the CLI before it calls the pure policy evaluator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnforcementEvaluation {
    pub plugin_id: String,
    pub operation: String,
    pub coverage_counts: BTreeMap<String, usize>,
    pub coverage_limitations: Vec<String>,
    pub unsupported_executable_paths: Vec<String>,
    pub executable_digest_approved: bool,
    pub analyzer_identity_current: bool,
    pub enforcement_policy_identity_current: bool,
    pub installed_tree_postconditions_passed: bool,
    pub observed_rule_ids: Vec<String>,
    pub commit: Option<String>,
    pub tree: Option<String>,
    pub content_digest: Option<String>,
    pub analyzer_policy_identity: Option<PolicyIdentity>,
    pub override_present: bool,
    pub override_valid: bool,
    pub override_binding: Option<OverrideBinding>,
    pub audit_event_id: String,
    pub evaluated_at: String,
    pub native_install_not_interposed: bool,
}

/// Exact-identity, expiring authorization. This is auditable state, not a
/// claim of tamper resistance against already-running same-user code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverrideBinding {
    pub schema: String,
    pub plugin_id: String,
    pub commit: String,
    pub tree: Option<String>,
    pub content_digest: String,
    pub analyzer_policy_identity: PolicyIdentity,
    pub enforcement_policy_identity: String,
    pub rule_ids: Vec<String>,
    pub coverage_limitations: Vec<String>,
    pub reason: String,
    pub created_at: String,
    pub expires_at: String,
}

/// Persisted decision shape. The CLI may add this object under
/// `result.enforcement` without changing the report envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnforcementDecision {
    pub schema: String,
    pub plugin_id: String,
    pub operation: String,
    pub evaluation_state: EvaluationState,
    pub outcome: EnforcementOutcome,
    pub authorization_basis: Option<AuthorizationBasis>,
    /// False is the fail-safe default when loading a v1 record written before
    /// this postcondition was persisted.
    #[serde(default)]
    pub installed_tree_postconditions_passed: bool,
    pub reason_codes: Vec<String>,
    pub blocking_rule_ids: Vec<String>,
    pub coverage_counts: BTreeMap<String, usize>,
    pub coverage_limitations: Vec<String>,
    pub commit: Option<String>,
    pub tree: Option<String>,
    pub content_digest: Option<String>,
    pub analyzer_policy_identity: Option<PolicyIdentity>,
    pub enforcement_policy_identity: String,
    pub override_binding: Option<OverrideBinding>,
    pub audit_event_id: String,
    pub evaluated_at: String,
    pub native_install_not_interposed: bool,
}

/// A durable record of an enforcement attempt. The CLI writes this at the
/// attempt boundary, including failed operations, so a notification failure
/// or a mid-mutation crash cannot erase the fact that an override or policy
/// decision was exercised.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementAuditEvent {
    pub schema: String,
    pub audit_event_id: String,
    pub plugin_id: String,
    pub operation: String,
    pub attempted_at: String,
    pub completed: bool,
    pub outcome: EnforcementOutcome,
    pub authorization_basis: Option<AuthorizationBasis>,
    pub reason_codes: Vec<String>,
    pub blocking_rule_ids: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evaluation() -> EnforcementEvaluation {
        EnforcementEvaluation {
            plugin_id: "io.example.test".into(),
            operation: "enable".into(),
            coverage_counts: BTreeMap::from([(String::from("analyzed"), 1)]),
            coverage_limitations: Vec::new(),
            unsupported_executable_paths: Vec::new(),
            executable_digest_approved: false,
            analyzer_identity_current: true,
            enforcement_policy_identity_current: true,
            installed_tree_postconditions_passed: true,
            observed_rule_ids: Vec::new(),
            commit: Some("a".repeat(40)),
            tree: Some("b".repeat(40)),
            content_digest: Some("c".repeat(64)),
            analyzer_policy_identity: None,
            override_present: false,
            override_valid: false,
            override_binding: None,
            audit_event_id: "audit-1".into(),
            evaluated_at: "2026-09-01T00:00:00Z".into(),
            native_install_not_interposed: true,
        }
    }

    #[test]
    fn identity_is_stable_and_changes_when_admission_changes() {
        let mut policy = EnforcementPolicy::new(EnforcementMode::Hardened);
        let first = policy.identity();
        assert_eq!(first.len(), 64);
        assert_eq!(first, policy.identity());
        policy.blocking_rule_families.push(BlockingRuleFamily {
            rule_id: "oma.script.reverse-shell".into(),
            precision: Some(1.0),
            fixture_detection_rate: Some(1.0),
        });
        assert_ne!(first, policy.identity());
    }

    #[test]
    fn h8b_checked_in_admission_is_empty_without_triaged_corpus_evidence() {
        assert_eq!(H8B_PRECISION_THRESHOLD, 1.0);
        assert_eq!(H8B_FIXTURE_DETECTION_THRESHOLD, 1.0);
        assert!(h8b_blocking_rule_families().is_empty());
        assert!(
            EnforcementPolicy::new(EnforcementMode::Hardened)
                .blocking_rule_families
                .is_empty()
        );
    }

    #[test]
    fn h8b_admission_requires_both_complete_measurements() {
        let admitted = admit_blocking_rule_families([
            BlockingRuleFamily {
                rule_id: "oma.script.reverse-shell".into(),
                precision: Some(1.0),
                fixture_detection_rate: Some(1.0),
            },
            BlockingRuleFamily {
                rule_id: "missing-precision".into(),
                precision: None,
                fixture_detection_rate: Some(1.0),
            },
            BlockingRuleFamily {
                rule_id: "missing-fixture-rate".into(),
                precision: Some(1.0),
                fixture_detection_rate: None,
            },
            BlockingRuleFamily {
                rule_id: "false-positive".into(),
                precision: Some(0.99),
                fixture_detection_rate: Some(1.0),
            },
        ]);
        assert_eq!(
            admitted,
            vec![BlockingRuleFamily {
                rule_id: "oma.script.reverse-shell".into(),
                precision: Some(1.0),
                fixture_detection_rate: Some(1.0),
            }]
        );
    }

    #[test]
    fn h8b_admission_is_deterministic_and_deduplicated() {
        let admitted = admit_blocking_rule_families([
            BlockingRuleFamily {
                rule_id: "z-rule".into(),
                precision: Some(1.0),
                fixture_detection_rate: Some(1.0),
            },
            BlockingRuleFamily {
                rule_id: "a-rule".into(),
                precision: Some(1.0),
                fixture_detection_rate: Some(1.0),
            },
            BlockingRuleFamily {
                rule_id: "a-rule".into(),
                precision: Some(1.0),
                fixture_detection_rate: Some(1.0),
            },
        ]);
        assert_eq!(
            admitted
                .iter()
                .map(|family| family.rule_id.as_str())
                .collect::<Vec<_>>(),
            vec!["a-rule", "z-rule"]
        );
    }

    #[test]
    fn admitted_family_blocks_hardened_but_not_advisory() {
        let family = BlockingRuleFamily {
            rule_id: "oma.script.reverse-shell".into(),
            precision: Some(1.0),
            fixture_detection_rate: Some(1.0),
        };
        let mut hardened = EnforcementPolicy::new(EnforcementMode::Hardened);
        hardened.blocking_rule_families = admit_blocking_rule_families([family.clone()]);
        let mut input = evaluation();
        input.observed_rule_ids = vec![family.rule_id.clone()];
        let decision = hardened.evaluate(input.clone());
        assert_eq!(decision.outcome, EnforcementOutcome::Block);
        assert_eq!(decision.blocking_rule_ids, vec![family.rule_id.clone()]);
        assert!(
            decision
                .reason_codes
                .contains(&"blocking-rule-family".into())
        );

        let mut advisory = EnforcementPolicy::new(EnforcementMode::Advisory);
        advisory.blocking_rule_families = vec![family.clone()];
        let decision = advisory.evaluate(input);
        assert_eq!(decision.outcome, EnforcementOutcome::Allow);
        assert_eq!(decision.blocking_rule_ids, vec![family.rule_id]);
        assert!(decision.reason_codes.is_empty());
    }

    #[test]
    fn identity_is_order_independent_for_set_like_policy_fields() {
        let mut left = EnforcementPolicy::new(EnforcementMode::Hardened);
        left.blocking_rule_families = vec![
            BlockingRuleFamily {
                rule_id: "z-rule".into(),
                precision: None,
                fixture_detection_rate: Some(1.0),
            },
            BlockingRuleFamily {
                rule_id: "a-rule".into(),
                precision: Some(1.0),
                fixture_detection_rate: None,
            },
        ];
        left.installed_tree_postconditions.reverse();
        let mut right = left.clone();
        right.blocking_rule_families.reverse();
        right.installed_tree_postconditions.reverse();
        assert_eq!(left.identity(), right.identity());
    }

    #[test]
    fn advisory_allows_but_still_returns_evaluated_contract() {
        let mut input = evaluation();
        input
            .coverage_limitations
            .push("time_budget_exhausted".into());
        let decision = EnforcementPolicy::new(EnforcementMode::Advisory).evaluate(input);
        assert_eq!(decision.evaluation_state, EvaluationState::Evaluated);
        assert_eq!(decision.outcome, EnforcementOutcome::Allow);
        assert_eq!(
            decision.authorization_basis,
            Some(AuthorizationBasis::Policy)
        );
        assert!(decision.reason_codes.is_empty());
    }

    #[test]
    fn hardened_blocks_incomplete_coverage_and_unapproved_executable() {
        let mut input = evaluation();
        input
            .coverage_limitations
            .push("time_budget_exhausted".into());
        input
            .unsupported_executable_paths
            .push("payload.bin".into());
        let decision = EnforcementPolicy::new(EnforcementMode::Hardened).evaluate(input);
        assert_eq!(decision.outcome, EnforcementOutcome::Block);
        assert!(
            decision
                .reason_codes
                .contains(&"coverage-incomplete".into())
        );
        assert!(
            decision
                .reason_codes
                .contains(&"unsupported-executable".into())
        );
    }

    #[test]
    fn valid_override_allows_but_retains_blockers() {
        let mut input = evaluation();
        input
            .coverage_limitations
            .push("time_budget_exhausted".into());
        input.override_present = true;
        input.override_valid = true;
        input.override_binding = Some(OverrideBinding {
            schema: OVERRIDE_SCHEMA_VERSION.into(),
            plugin_id: input.plugin_id.clone(),
            commit: input.commit.clone().unwrap(),
            tree: input.tree.clone(),
            content_digest: input.content_digest.clone().unwrap(),
            analyzer_policy_identity: serde_json::from_value(serde_json::json!({
                "analyzer_version":"0.2.1",
                "rule_catalog_version":7,
                "rule_catalog_fingerprint":"x",
                "severity_table_version":1,
                "parser_versions":{},
                "limits_fingerprint":"y",
                "equivalence_map_version":null,
                "supported_surface_version":"z"
            }))
            .unwrap(),
            enforcement_policy_identity: "policy".into(),
            rule_ids: Vec::new(),
            coverage_limitations: vec!["time_budget_exhausted".into()],
            reason: "operator review".into(),
            created_at: "2026-09-01T00:00:00Z".into(),
            expires_at: "2026-10-01T00:00:00Z".into(),
        });
        let decision = EnforcementPolicy::new(EnforcementMode::Hardened).evaluate(input);
        assert_eq!(decision.outcome, EnforcementOutcome::Allow);
        assert_eq!(
            decision.authorization_basis,
            Some(AuthorizationBasis::Override)
        );
        assert!(
            decision
                .reason_codes
                .contains(&"coverage-incomplete".into())
        );
    }

    #[test]
    fn invalid_override_fails_closed() {
        let mut input = evaluation();
        input
            .coverage_limitations
            .push("time_budget_exhausted".into());
        input.override_present = true;
        input.override_valid = false;
        let decision = EnforcementPolicy::new(EnforcementMode::Hardened).evaluate(input);
        assert_eq!(decision.outcome, EnforcementOutcome::Block);
        assert!(
            decision
                .reason_codes
                .contains(&"override-expired-or-mismatched".into())
        );
    }
}
