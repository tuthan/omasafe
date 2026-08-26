//! Analysis fingerprint canonicalization.
//!
//! The fingerprint is a SHA-256 over the sorted set of normalized results.
//! Normalization happens only in the fallible constructor [`NormalizedResult::new`];
//! fields are private and immutable afterwards, so every value entering the
//! hash has passed the same normalization. Timestamps, prose, excerpts,
//! temporary paths, and tool versions are excluded by construction: they have
//! no field. Confidence is included because a lexical-fallback conclusion and
//! an AST-backed conclusion are semantically different results.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Evidence quality behind one result; participates in the fingerprint because
/// parser fallback changes the meaning of a conclusion, not just its prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    AstBacked,
    LexicalFallback,
}

/// One normalized analysis result participating in the fingerprint.
///
/// `relative_path` is repository-relative with forward slashes; absolute paths
/// and `..` segments are rejected, never rewritten into something that looks
/// contained. `semantic_value` must already be rule-normalized by the detector;
/// it is hashed verbatim — no whitespace or separator collapsing, so distinct
/// argv strings stay distinct.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct NormalizedResult {
    rule_id: String,
    relative_path: String,
    line: Option<u32>,
    column: Option<u32>,
    semantic_value: String,
    confidence: Option<Confidence>,
}

/// Reasons a proposed result cannot be normalized into fingerprintable form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NormalizationError {
    AbsolutePath,
    TraversalSegment,
}

impl std::fmt::Display for NormalizationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NormalizationError::AbsolutePath => {
                write!(formatter, "result path must be relative to the target root")
            }
            NormalizationError::TraversalSegment => {
                write!(formatter, "result path contains a `..` traversal segment")
            }
        }
    }
}

impl std::error::Error for NormalizationError {}

impl NormalizedResult {
    pub fn new(
        rule_id: impl Into<String>,
        relative_path: &str,
        line: Option<u32>,
        column: Option<u32>,
        semantic_value: impl Into<String>,
        confidence: Option<Confidence>,
    ) -> Result<Self, NormalizationError> {
        Ok(Self {
            rule_id: rule_id.into(),
            relative_path: normalize_relative_path(relative_path)?,
            line,
            column,
            semantic_value: semantic_value.into(),
            confidence,
        })
    }

    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }

    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    pub fn line(&self) -> Option<u32> {
        self.line
    }

    pub fn column(&self) -> Option<u32> {
        self.column
    }

    pub fn semantic_value(&self) -> &str {
        &self.semantic_value
    }

    pub fn confidence(&self) -> Option<Confidence> {
        self.confidence
    }
}

/// Repository-relative, forward-slash form; rejects anything that would make
/// two different locations hash identically. Backslashes are preserved because
/// on Linux they are ordinary filename characters, not separators.
pub fn normalize_relative_path(path: &str) -> Result<String, NormalizationError> {
    if path.starts_with('/') {
        return Err(NormalizationError::AbsolutePath);
    }
    let mut parts: Vec<&str> = path.split('/').collect();
    parts.retain(|part| !part.is_empty() && *part != ".");
    if parts.contains(&"..") {
        return Err(NormalizationError::TraversalSegment);
    }
    Ok(parts.join("/"))
}

/// Hex-encoded SHA-256 over the sorted canonical JSON of findings plus
/// capability observations — every normalized semantic output participates,
/// so a capability-only source change moves the fingerprint just like a
/// finding does.
pub fn fingerprint_analysis(
    results: &[NormalizedResult],
    capabilities: &[omasafe_report::analysis::CapabilityOccurrence],
) -> String {
    let mut sorted_results: Vec<&NormalizedResult> = results.iter().collect();
    sorted_results.sort();
    sorted_results.dedup();
    let mut sorted_capabilities: Vec<&omasafe_report::analysis::CapabilityOccurrence> =
        capabilities.iter().collect();
    sorted_capabilities.sort();
    sorted_capabilities.dedup();
    let canonical = serde_json::to_vec(&serde_json::json!({
        "results": sorted_results,
        "capabilities": sorted_capabilities,
    }))
    .expect("normalized serialization cannot fail");
    hex(&Sha256::digest(canonical))
}

/// Hex-encoded SHA-256 over the sorted canonical JSON array of results.
///
/// Sorting plus set semantics (`dedup`) make the hash insensitive to emission
/// order and duplicate emission; identical inputs always agree.
pub fn fingerprint_results(results: &[NormalizedResult]) -> String {
    let mut sorted: Vec<&NormalizedResult> = results.iter().collect();
    sorted.sort();
    sorted.dedup();
    let canonical = serde_json::to_vec(&sorted).expect("normalized serialization cannot fail");
    hex(&Sha256::digest(canonical))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(path: &str, value: &str) -> NormalizedResult {
        NormalizedResult::new(
            "oma.qml.process-execution",
            path,
            Some(12),
            Some(5),
            value,
            Some(Confidence::AstBacked),
        )
        .unwrap()
    }

    #[test]
    fn empty_results_have_a_stable_fingerprint() {
        assert_eq!(fingerprint_results(&[]), fingerprint_results(&[]));
        assert_eq!(fingerprint_results(&[]).len(), 64);
    }

    #[test]
    fn order_and_duplication_do_not_matter_for_every_permutation() {
        let results = vec![
            result("ui/Main.qml", "/bin/sh -c ls"),
            NormalizedResult::new(
                "oma.qml.network-access",
                "ui/Feed.qml",
                None,
                None,
                "https://example.test/api",
                None,
            )
            .unwrap(),
            result("ui/Nested/Panel.qml", "python3 payload.py"),
        ];
        let baseline = fingerprint_results(&results);
        for order in [
            [0usize, 1, 2].as_slice(),
            [0, 2, 1].as_slice(),
            [1, 0, 2].as_slice(),
            [1, 2, 0].as_slice(),
            [2, 0, 1].as_slice(),
            [2, 1, 0].as_slice(),
        ] {
            let permuted: Vec<_> = order.iter().map(|index| results[*index].clone()).collect();
            assert_eq!(fingerprint_results(&permuted), baseline);
        }
        let duplicated = {
            let mut clone = results.clone();
            clone.push(results[0].clone());
            clone
        };
        assert_eq!(fingerprint_results(&duplicated), baseline);
    }

    #[test]
    fn any_field_change_changes_the_fingerprint() {
        let baseline = fingerprint_results(&[result("ui/Main.qml", "/bin/sh -c ls")]);
        let variants = vec![
            // Different rule.
            fingerprint_results(&[NormalizedResult::new(
                "oma.qml.detached-execution",
                "ui/Main.qml",
                Some(12),
                Some(5),
                "/bin/sh -c ls",
                Some(Confidence::AstBacked),
            )
            .unwrap()]),
            // Different location.
            fingerprint_results(&[result("ui/Main.qml", "/bin/sh -c ls").with_line(13)]),
            // Different semantic value.
            fingerprint_results(&[result("ui/Main.qml", "/bin/sh -c rm")]),
            // Different confidence.
            fingerprint_results(&[NormalizedResult::new(
                "oma.qml.process-execution",
                "ui/Main.qml",
                Some(12),
                Some(5),
                "/bin/sh -c ls",
                Some(Confidence::LexicalFallback),
            )
            .unwrap()]),
            // No confidence versus some confidence.
            fingerprint_results(&[NormalizedResult::new(
                "oma.qml.process-execution",
                "ui/Main.qml",
                Some(12),
                Some(5),
                "/bin/sh -c ls",
                None,
            )
            .unwrap()]),
        ];
        for variant in variants {
            assert_ne!(variant, baseline);
        }
    }

    #[test]
    fn distinct_argument_spacing_stays_distinct() {
        let single = fingerprint_results(&[result("run.sh", "tar -xzf archive")]);
        let doubled = fingerprint_results(&[result("run.sh", "tar  -xzf archive")]);
        assert_ne!(single, doubled);
    }

    #[test]
    fn backslash_filenames_are_not_separator_conflated() {
        let literal = normalize_relative_path(r"data\a\b").unwrap();
        let nested = normalize_relative_path("data/a/b").unwrap();
        assert_ne!(literal, nested);
    }

    #[test]
    fn dot_segments_are_dropped_but_traversal_is_rejected() {
        assert_eq!(
            normalize_relative_path("ui/./Main.qml").unwrap(),
            "ui/Main.qml"
        );
        assert!(matches!(
            normalize_relative_path("../../etc/passwd"),
            Err(NormalizationError::TraversalSegment)
        ));
        assert!(matches!(
            normalize_relative_path("ui/../../etc/passwd"),
            Err(NormalizationError::TraversalSegment)
        ));
        assert!(matches!(
            normalize_relative_path("/etc/passwd"),
            Err(NormalizationError::AbsolutePath)
        ));
    }

    #[test]
    fn fingerprint_excludes_prose_and_tool_version_by_type_shape() {
        let rendered = String::from_utf8(
            serde_json::to_vec(&[result("ui/Main.qml", "/bin/sh -c ls")]).unwrap(),
        )
        .unwrap();
        assert!(!rendered.contains("excerpt"));
        assert!(!rendered.contains("message"));
        assert!(!rendered.contains("tool_version"));
    }

    impl NormalizedResult {
        fn with_line(mut self, line: u32) -> Self {
            self.line = Some(line);
            self
        }
    }
}
