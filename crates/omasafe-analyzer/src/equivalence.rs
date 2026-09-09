//! Marketplace Baseline equivalence mapping (S4 / M5).
//!
//! OmaSafe rules are the owned vocabulary; this map records where the
//! marketplace's Automated Security Baseline covers the same ground, at what
//! strength, and against exactly which external version and commit. The map
//! never redefines OmaSafe severity or meaning: upstream vocabulary moving is
//! a staleness event requiring review, not a silent semantic change
//! (`docs/plans/v0.2.md` M5).

use serde::{Deserialize, Serialize};

/// The embedded map, generated from the marketplace's shipped policy catalogs.
pub const BASELINE_MAP_JSON: &str = include_str!("../equivalence/baseline-v3.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EquivalenceMap {
    pub map_version: String,
    pub external_system: String,
    pub external_ruleset_name: String,
    pub external_ruleset_version: String,
    pub verified_at_commit: String,
    pub verified_at_utc: String,
    pub notes: Vec<String>,
    pub entries: Vec<EquivalenceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EquivalenceEntry {
    /// Owning OmaSafe rule, when the entry is rule-level.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oma_rule_id: Option<String>,
    /// Capability-level coverage (inventory facts, not findings).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oma_capability: Option<String>,
    pub external_id: String,
    /// `structural-equivalent`, `partial-overlap`, or `not-covered`.
    pub relation: String,
    pub note: String,
}

impl EquivalenceMap {
    pub fn embedded() -> Self {
        serde_json::from_str(BASELINE_MAP_JSON).expect("embedded equivalence map is valid JSON")
    }

    /// True when an observed external baseline version no longer matches the
    /// version this map was verified against. Callers surface staleness as a
    /// report limitation; nothing is silently remapped.
    pub fn is_stale_against(&self, observed_external_version: &str) -> bool {
        self.external_ruleset_version != observed_external_version
    }

    /// External ids covered for one OmaSafe rule id.
    pub fn external_ids_for_rule(&self, oma_rule_id: &str) -> Vec<&str> {
        self.entries
            .iter()
            .filter(|entry| entry.oma_rule_id.as_deref() == Some(oma_rule_id))
            .map(|entry| entry.external_id.as_str())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_map_parses_and_records_v3() {
        let map = EquivalenceMap::embedded();
        assert_eq!(map.map_version, "2");
        assert_eq!(map.external_system, "omarchy-plugin-marketplace");
        assert_eq!(map.external_ruleset_version, "3");
        assert_eq!(map.verified_at_commit.len(), 40);
        assert!(!map.entries.is_empty());
    }

    #[test]
    fn staleness_is_exact_version_comparison() {
        let map = EquivalenceMap::embedded();
        assert!(!map.is_stale_against("3"));
        assert!(map.is_stale_against("4"));
    }

    #[test]
    fn curl_pipe_shell_maps_to_all_download_execute_rules() {
        let map = EquivalenceMap::embedded();
        let mut mapped = Vec::new();
        for rule_id in [
            "oma.qml.process-execution",
            "oma.script.download-execute",
            "oma.python.download-execute",
        ] {
            mapped.extend(map.external_ids_for_rule(rule_id));
        }
        assert!(mapped.contains(&"curl-pipe-shell"), "{mapped:?}");
    }

    #[test]
    fn map_covers_exactly_the_twelve_baseline_v3_external_ids() {
        let map = EquivalenceMap::embedded();
        let observed: std::collections::BTreeSet<&str> = map
            .entries
            .iter()
            .map(|entry| entry.external_id.as_str())
            .collect();
        let expected: std::collections::BTreeSet<&str> = [
            // Findings.
            "cargo-git-unpinned",
            "curl-pipe-shell",
            "privileged-process-control-from-shared-temp",
            "remote-git-execution-unpinned",
            "sudoers-dangerous-passwordless-command",
            // Capabilities.
            "bundled-executable-binary",
            "installer",
            "package-manager",
            "privilege",
            "remote-build",
            "service-management",
            "sudoers-modification",
        ]
        .into_iter()
        .collect();
        assert_eq!(observed, expected);
    }

    #[test]
    fn verification_commit_is_pinned_exactly() {
        let map = EquivalenceMap::embedded();
        assert_eq!(
            map.verified_at_commit,
            "964dc08df2a3450578727b665908272cd3a277e5"
        );
    }
}
