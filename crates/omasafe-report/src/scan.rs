//! Shared typed installed-scan result contracts.

use serde::{Deserialize, Serialize};

use crate::enforcement::EnforcementSummary;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanAlert {
    pub key: String,
    pub plugin_id: String,
    pub kind: String,
    pub severity: String,
    pub reason_code: String,
    pub message: String,
    pub post_change: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachePersistence {
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanResult {
    pub alerts: Vec<ScanAlert>,
    pub quiet: bool,
    pub outstanding: usize,
    pub new: usize,
    pub highest_severity: String,
    pub post_change_detection: bool,
    pub enforcement_summary: EnforcementSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_persistence: Option<CachePersistence>,
}
