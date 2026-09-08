//! Exact, expiring human review records for opaque executable payloads.
//!
//! A review record is evidence about one byte sequence at one plugin path. It
//! is deliberately not a malware verdict and it is never interchangeable with
//! a plugin-wide override. The CLI owns the interactive transaction; this
//! module owns the bounded, serializable contract and exact-match predicate.

use serde::{Deserialize, Serialize};

pub const EXECUTABLE_REVIEW_SCHEMA_VERSION: &str = "omasafe.executable-review.v1";
pub const EXECUTABLE_REVIEW_POLICY_VERSION: &str = "omasafe.executable-review-policy.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssessmentMethod {
    LocalMalwareScan,
    RemoteHashReputation,
    ManualBinaryReview,
    ReproducibleBuildReview,
    SignatureReview,
}

impl AssessmentMethod {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalMalwareScan => "local-malware-scan",
            Self::RemoteHashReputation => "remote-hash-reputation",
            Self::ManualBinaryReview => "manual-binary-review",
            Self::ReproducibleBuildReview => "reproducible-build-review",
            Self::SignatureReview => "signature-review",
        }
    }
}

impl std::str::FromStr for AssessmentMethod {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "local-malware-scan" => Ok(Self::LocalMalwareScan),
            "remote-hash-reputation" => Ok(Self::RemoteHashReputation),
            "manual-binary-review" => Ok(Self::ManualBinaryReview),
            "reproducible-build-review" => Ok(Self::ReproducibleBuildReview),
            "signature-review" => Ok(Self::SignatureReview),
            _ => Err(format!("unsupported executable review method: {value}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AssessmentOutcome {
    NoKnownIssue,
    IssueFound,
    Inconclusive,
}

impl AssessmentOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoKnownIssue => "no-known-issue",
            Self::IssueFound => "issue-found",
            Self::Inconclusive => "inconclusive",
        }
    }
}

impl std::str::FromStr for AssessmentOutcome {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "no-known-issue" => Ok(Self::NoKnownIssue),
            "issue-found" => Ok(Self::IssueFound),
            "inconclusive" => Ok(Self::Inconclusive),
            _ => Err(format!(
                "unsupported executable assessment outcome: {value}"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperatorDecision {
    Accepted,
    Rejected,
}

impl OperatorDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}

impl std::str::FromStr for OperatorDecision {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "accepted" => Ok(Self::Accepted),
            "rejected" => Ok(Self::Rejected),
            _ => Err(format!(
                "executable review decision must be accepted or rejected, got {value:?}"
            )),
        }
    }
}

/// The exact identity and bounded evidence for one external assessment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableReviewBinding {
    pub schema: String,
    pub plugin_id: String,
    pub relative_path: String,
    pub native_format: String,
    pub exact_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_commit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_tree: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_content_digest: Option<String>,
    pub review_policy_version: String,
    pub assessment_method: AssessmentMethod,
    pub provider: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_version: Option<String>,
    pub assessment_outcome: AssessmentOutcome,
    pub performed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_digest: Option<String>,
    #[serde(default)]
    pub limitations: Vec<String>,
    pub operator_decision: OperatorDecision,
    pub reason: String,
    pub decision_at: String,
    pub expires_at: String,
    pub audit_event_id: String,
}

impl ExecutableReviewBinding {
    /// Validate fields that are security-relevant at the state boundary.
    /// Source-derived strings are metadata only and receive strict byte caps.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != EXECUTABLE_REVIEW_SCHEMA_VERSION {
            return Err("unsupported executable review schema".to_owned());
        }
        if self.plugin_id.trim().is_empty() || self.plugin_id.len() > 256 {
            return Err("executable review plugin ID must be 1-256 bytes".to_owned());
        }
        if self.relative_path.is_empty()
            || self.relative_path.len() > 512
            || self.relative_path.starts_with('/')
            || self.relative_path.split('/').any(|part| part == "..")
        {
            return Err("executable review path must be a bounded relative path".to_owned());
        }
        if !is_sha256(&self.exact_sha256) {
            return Err("executable review requires an exact lowercase SHA-256".to_owned());
        }
        bounded_printable(&self.native_format, 64, "native format")?;
        validate_source_identity(self.source_commit.as_deref(), "source commit")?;
        validate_source_identity(self.source_tree.as_deref(), "source tree")?;
        if let Some(digest) = &self.source_content_digest
            && !is_sha256(digest)
        {
            return Err("executable review source content digest must be a SHA-256".to_owned());
        }
        if self.review_policy_version != EXECUTABLE_REVIEW_POLICY_VERSION {
            return Err("executable review policy version is not current".to_owned());
        }
        bounded_printable(&self.provider, 128, "provider")?;
        if let Some(version) = &self.provider_version {
            bounded_printable(version, 128, "provider version")?;
        }
        if let Some(reference) = &self.report_ref {
            bounded_printable(reference, 512, "report reference")?;
        }
        if let Some(digest) = &self.report_digest
            && !is_sha256(digest)
        {
            return Err("executable review report digest must be a SHA-256".to_owned());
        }
        if self.report_ref.is_none() && self.report_digest.is_none() {
            return Err("executable review requires a report reference or digest".to_owned());
        }
        if self.limitations.len() > 16
            || self.limitations.iter().any(|limitation| {
                limitation.len() > 256 || limitation.chars().any(char::is_control)
            })
        {
            return Err("executable review limitations exceed their bounds".to_owned());
        }
        bounded_printable(&self.reason, 1_024, "reason")?;
        bounded_printable(&self.audit_event_id, 256, "audit event ID")?;
        if !is_utc_timestamp(&self.performed_at)
            || !is_utc_timestamp(&self.decision_at)
            || !is_utc_timestamp(&self.expires_at)
        {
            return Err("executable review timestamps are required".to_owned());
        }
        Ok(())
    }

    /// An accepted no-known-issue assessment is still only valid for the
    /// exact path, plugin, digest, policy version, and unexpired record.
    pub fn authorizes(
        &self,
        plugin_id: &str,
        relative_path: &str,
        exact_sha256: &str,
        native_format: &str,
        now: &str,
    ) -> bool {
        self.validate().is_ok()
            && self.operator_decision == OperatorDecision::Accepted
            && self.assessment_outcome == AssessmentOutcome::NoKnownIssue
            && self.plugin_id == plugin_id
            && self.relative_path == relative_path
            && self.native_format == native_format
            && self.exact_sha256 == exact_sha256
            && self.expires_at.as_str() > now
    }

    /// Exact authorization including the current source identity when the
    /// caller has one. A record that omits an identity component cannot
    /// authorize a target whose current identity supplies that component.
    #[allow(
        clippy::too_many_arguments,
        reason = "the exact-match predicate keeps every identity component explicit"
    )]
    pub fn authorizes_with_identity(
        &self,
        plugin_id: &str,
        relative_path: &str,
        exact_sha256: &str,
        native_format: &str,
        source_commit: Option<&str>,
        source_tree: Option<&str>,
        source_content_digest: Option<&str>,
        now: &str,
    ) -> bool {
        self.authorizes(plugin_id, relative_path, exact_sha256, native_format, now)
            && self.source_commit.as_deref() == source_commit
            && self.source_tree.as_deref() == source_tree
            && self.source_content_digest.as_deref() == source_content_digest
            && self.expires_at.as_str() > now
    }
}

fn bounded_printable(value: &str, cap: usize, label: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > cap || value.chars().any(char::is_control) {
        return Err(format!(
            "executable review {label} must be bounded printable text"
        ));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_source_identity(value: Option<&str>, label: &str) -> Result<(), String> {
    if let Some(value) = value
        && (!(value.len() == 40 || value.len() == 64)
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
        return Err(format!(
            "executable review {label} must be a lowercase 40/64-character hex identity"
        ));
    }
    Ok(())
}

fn is_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> ExecutableReviewBinding {
        ExecutableReviewBinding {
            schema: EXECUTABLE_REVIEW_SCHEMA_VERSION.into(),
            plugin_id: "io.example.plugin".into(),
            relative_path: "bin/helper".into(),
            native_format: "elf".into(),
            exact_sha256: "a".repeat(64),
            source_commit: Some("b".repeat(40)),
            source_tree: None,
            source_content_digest: None,
            review_policy_version: EXECUTABLE_REVIEW_POLICY_VERSION.into(),
            assessment_method: AssessmentMethod::ManualBinaryReview,
            provider: "maintainer".into(),
            provider_version: None,
            assessment_outcome: AssessmentOutcome::NoKnownIssue,
            performed_at: "2026-09-08T00:00:00Z".into(),
            report_ref: None,
            report_digest: Some("c".repeat(64)),
            limitations: vec!["no behavior proof".into()],
            operator_decision: OperatorDecision::Accepted,
            reason: "reviewed exact bytes".into(),
            decision_at: "2026-09-08T00:00:00Z".into(),
            expires_at: "2099-01-01T00:00:00Z".into(),
            audit_event_id: "audit-1".into(),
        }
    }

    #[test]
    fn authorization_is_exact_and_expiring() {
        let record = binding();
        assert!(record.authorizes(
            "io.example.plugin",
            "bin/helper",
            &"a".repeat(64),
            "elf",
            "2026-09-08T00:00:00Z"
        ));
        assert!(!record.authorizes(
            "io.example.other",
            "bin/helper",
            &"a".repeat(64),
            "elf",
            "2026-09-08T00:00:00Z"
        ));
        assert!(!record.authorizes(
            "io.example.plugin",
            "bin/helper",
            &"c".repeat(64),
            "elf",
            "2026-09-08T00:00:00Z"
        ));
        assert!(!record.authorizes(
            "io.example.plugin",
            "bin/helper",
            &"a".repeat(64),
            "elf",
            "2100-01-01T00:00:00Z"
        ));
    }

    #[test]
    fn rejected_and_inconclusive_records_never_authorize() {
        let mut record = binding();
        record.assessment_outcome = AssessmentOutcome::Inconclusive;
        assert!(!record.authorizes(
            "io.example.plugin",
            "bin/helper",
            &"a".repeat(64),
            "elf",
            "2026-09-08T00:00:00Z"
        ));
        record.assessment_outcome = AssessmentOutcome::NoKnownIssue;
        record.operator_decision = OperatorDecision::Rejected;
        assert!(!record.authorizes(
            "io.example.plugin",
            "bin/helper",
            &"a".repeat(64),
            "elf",
            "2026-09-08T00:00:00Z"
        ));
    }

    #[test]
    fn malformed_evidence_metadata_is_rejected_before_authorization() {
        let mut record = binding();
        record.performed_at = "not-a-timestamp".into();
        assert!(record.validate().is_err());
        record = binding();
        record.report_digest = None;
        assert!(record.validate().is_err());
        record = binding();
        record.source_commit = Some("not-a-git-id".into());
        assert!(record.validate().is_err());
    }
}
