//! QML parsing via tree-sitter-qmljs, behind the `qml-parser` feature.
//!
//! The parser is a measurement target first: this module exposes coverage
//! metrics (how much of a file the grammar spans, and where it fails) so the
//! S2 decision in `docs/adr/0001-qml-parser.md` rests on numbers rather than
//! impressions. Parsing never executes content; a parse tree is inert data.
//!
//! Coverage is computed over leaf-node byte ranges: every leaf (named or
//! anonymous) contributes its span, spans are merged, and everything outside
//! the merged union — whitespace between tokens, skipped input after ERROR
//! recovery — counts as uncovered. A file with syntax errors still yields
//! partial coverage plus an explicit error count.

use tree_sitter::{Parser, Tree};

/// Version/identity facts surfaced into report metadata by callers.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct QmlParserIdentity {
    pub grammar: &'static str,
    pub grammar_version: &'static str,
    pub tree_sitter_version: &'static str,
    pub language_abi_version: usize,
}

pub const GRAMMAR_NAME: &str = "tree-sitter-qmljs";
pub const GRAMMAR_VERSION: &str = "0.3.1";
pub const TREE_SITTER_VERSION: &str = "0.26.13";

/// The `parserVersions.qml` value for builds with this feature on; policy.rs
/// mirrors the lexical fallback string when the feature is off.
pub const QML_PARSER_REPORT_VALUE: &str = concat!("tree-sitter-qmljs/", "0.3.1");

pub fn qml_parser_identity() -> QmlParserIdentity {
    let language: tree_sitter::Language = tree_sitter_qmljs::LANGUAGE.into();
    QmlParserIdentity {
        grammar: GRAMMAR_NAME,
        grammar_version: GRAMMAR_VERSION,
        tree_sitter_version: TREE_SITTER_VERSION,
        language_abi_version: language.abi_version(),
    }
}

/// Byte/line coverage and error counts for one parsed source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct QmlCoverageMetrics {
    /// True only when the parser could not produce a tree at all; partial
    /// results from error recovery keep this false but carry error counts.
    pub parse_failed: bool,
    pub total_bytes: u64,
    /// Bytes spanned by some token leaf.
    pub covered_bytes: u64,
    /// Uncovered bytes that are not pure ASCII whitespace. Formatting
    /// (indentation, newlines) is expected trivia; an uncovered identifier,
    /// punctuation, or literal means the grammar skipped something material.
    pub non_whitespace_gap_bytes: u64,
    pub total_lines: u64,
    /// Lines containing at least one uncovered byte.
    pub lines_with_gaps: u64,
    pub error_node_count: usize,
    pub missing_item_count: usize,
}

impl QmlCoverageMetrics {
    pub fn covered_ratio(&self) -> f64 {
        if self.total_bytes == 0 {
            return 1.0;
        }
        self.covered_bytes as f64 / self.total_bytes as f64
    }

    /// The kill criterion's "without material uncovered regions" test: zero
    /// grammar errors and every non-whitespace byte claimed by some token.
    pub fn parses_cleanly(&self) -> bool {
        !self.parse_failed
            && self.error_node_count == 0
            && self.missing_item_count == 0
            && self.non_whitespace_gap_bytes == 0
    }
}

fn new_parser() -> Parser {
    let mut parser = Parser::new();
    let language = tree_sitter_qmljs::LANGUAGE.into();
    parser
        .set_language(&language)
        .expect("tree-sitter-qmljs grammar is compatible with this tree-sitter");
    parser
}

/// Parse QML source into an inert syntax tree for downstream analysis.
pub fn parse_qml(source: &[u8]) -> Option<Tree> {
    new_parser().parse(source, None)
}

struct SpanUnion {
    spans: Vec<(usize, usize)>,
}

impl SpanUnion {
    fn new() -> Self {
        Self { spans: Vec::new() }
    }

    fn add(&mut self, start: usize, end: usize) {
        if start < end {
            self.spans.push((start, end));
        }
    }

    fn finish(mut self) -> Vec<(usize, usize)> {
        self.spans.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(self.spans.len());
        for (start, end) in self.spans {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        merged
    }
}

/// Count ERROR and missing nodes without recursion depth limits.
fn collect_error_counts(tree: &Tree) -> (usize, usize) {
    let (mut errors, mut missing) = (0usize, 0usize);
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.is_missing() {
            missing += 1;
            continue;
        }
        if node.is_error() {
            errors += 1;
        }
        if node.child_count() > 0 {
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
        }
    }
    (errors, missing)
}

/// Measure how much of `source` the grammar actually spans. Line metrics are
/// computed from the raw bytes: each maximal newline-free stretch touched by
/// a gap counts once.
pub fn measure_qml_coverage(source: &[u8]) -> QmlCoverageMetrics {
    fn count_newlines(bytes: &[u8]) -> u64 {
        bytes.iter().filter(|byte| **byte == b'\n').count() as u64
    }
    let total_lines = if source.is_empty() {
        0
    } else {
        count_newlines(source) + u64::from(*source.last().expect("non-empty") != b'\n')
    };

    let Some(tree) = parse_qml(source) else {
        // No tree means no byte is accounted for: everything non-whitespace
        // is a material gap and every line carries one.
        let non_ws = source
            .iter()
            .filter(|byte| !byte.is_ascii_whitespace())
            .count() as u64;
        return QmlCoverageMetrics {
            parse_failed: true,
            total_bytes: source.len() as u64,
            covered_bytes: 0,
            non_whitespace_gap_bytes: non_ws,
            total_lines,
            lines_with_gaps: total_lines,
            error_node_count: 0,
            missing_item_count: 0,
        };
    };

    let mut union = SpanUnion::new();
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        if node.child_count() == 0 {
            union.add(node.start_byte(), node.end_byte());
        } else {
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
        }
    }

    let covered_spans = union.finish();
    let covered_bytes: u64 = covered_spans
        .iter()
        .map(|(start, end)| (end - start) as u64)
        .sum();

    // Gaps are the complement of the merged leaf spans within the document.
    let mut gaps: Vec<(usize, usize)> = Vec::new();
    let mut cursor = 0usize;
    for (start, end) in &covered_spans {
        if cursor < *start {
            gaps.push((cursor, *start));
        }
        cursor = (*end).max(cursor);
    }
    if cursor < source.len() {
        gaps.push((cursor, source.len()));
    }

    let mut non_whitespace_gap_bytes = 0u64;
    for (start, end) in &gaps {
        non_whitespace_gap_bytes += source[*start..*end]
            .iter()
            .filter(|byte| !byte.is_ascii_whitespace())
            .count() as u64;
    }

    let mut line_starts = vec![0usize];
    for (index, byte) in source.iter().enumerate() {
        if *byte == b'\n' {
            line_starts.push(index + 1);
        }
    }
    let line_of =
        |byte: usize| line_starts.partition_point(|start| *start <= byte.min(source.len())) - 1;
    let mut touched_lines = std::collections::HashSet::new();
    let mut lines_with_gaps = 0u64;
    for (start, end) in &gaps {
        let first_line = line_of(*start);
        let last_line = line_of(end.saturating_sub(1));
        for line in first_line..=last_line {
            if touched_lines.insert(line) {
                lines_with_gaps += 1;
            }
        }
    }

    let (error_node_count, missing_item_count) = collect_error_counts(&tree);

    QmlCoverageMetrics {
        parse_failed: false,
        total_bytes: source.len() as u64,
        covered_bytes,
        non_whitespace_gap_bytes,
        total_lines,
        lines_with_gaps,
        error_node_count,
        missing_item_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_identity_reports_versions() {
        assert_eq!(
            QML_PARSER_REPORT_VALUE,
            format!("{GRAMMAR_NAME}/{GRAMMAR_VERSION}")
        );
        let identity = qml_parser_identity();
        assert_eq!(identity.grammar, GRAMMAR_NAME);
        assert_eq!(
            identity.language_abi_version, 14,
            "pin the qmljs 0.3.x grammar ABI; bump deliberately with the grammar"
        );
        assert!(identity.language_abi_version <= tree_sitter::LANGUAGE_VERSION);
    }

    #[test]
    fn clean_file_has_only_whitespace_gaps_and_parses_cleanly() {
        let source = b"import QtQuick\nText { text: \"hi\" }\n";
        let metrics = measure_qml_coverage(source);
        assert_eq!(metrics.error_node_count, 0);
        assert_eq!(metrics.missing_item_count, 0);
        assert!(
            metrics.covered_bytes < metrics.total_bytes,
            "indentation and newlines are expected trivia gaps"
        );
        assert_eq!(
            metrics.non_whitespace_gap_bytes, 0,
            "every meaningful byte must belong to a token"
        );
        assert!(metrics.parses_cleanly());
    }

    #[test]
    fn whitespace_only_regions_count_as_gaps_but_not_errors() {
        let source = b"Item {\n\n\n    width: 10\n}\n";
        let metrics = measure_qml_coverage(source);
        assert_eq!(metrics.error_node_count, 0);
        assert!(metrics.covered_ratio() < 1.0, "blank lines are uncovered");
        assert_eq!(metrics.non_whitespace_gap_bytes, 0);
        assert_eq!(
            metrics.lines_with_gaps, metrics.total_lines,
            "every line in this small file touches some trivia"
        );
        assert!(
            metrics.parses_cleanly(),
            "formatting trivia is not material"
        );
    }

    #[test]
    fn syntax_errors_are_counted_and_block_the_clean_check() {
        let bad_source = b"import QtQuick\nText { text: \"broken\"\nItem { ???\n";
        let metrics = measure_qml_coverage(bad_source);
        assert!(
            metrics.error_node_count + metrics.missing_item_count > 0,
            "malformed file must surface error nodes"
        );
        assert!(!metrics.parses_cleanly());
        assert_eq!(
            measure_qml_coverage(bad_source),
            metrics,
            "measurement is deterministic"
        );
    }

    #[test]
    fn dropped_meaningful_bytes_are_always_visible_somewhere() {
        // Whatever recovery strategy the grammar picks for garbage, the
        // metrics must expose it: error nodes, inserted missing items, or
        // material gap bytes.
        let cases: [&[u8]; 3] = [
            b"import QtQuick\nItem { @@@ }",
            b"Item { property int a  leftover }",
            b"}{",
        ];
        for source in cases {
            let metrics = measure_qml_coverage(source);
            assert!(
                metrics.error_node_count > 0
                    || metrics.missing_item_count > 0
                    || metrics.non_whitespace_gap_bytes > 0,
                "garbage input must surface somewhere"
            );
            assert!(!metrics.parses_cleanly());
        }
    }

    #[test]
    fn failed_parse_is_an_explicit_state_not_a_clean_file() {
        // The None path cannot arise from ordinary input with a configured
        // grammar, so exercise the semantics through the documented fields:
        // parse_failed blocks cleanliness regardless of gap accounting.
        let metrics = QmlCoverageMetrics {
            parse_failed: true,
            total_bytes: 4,
            covered_bytes: 0,
            non_whitespace_gap_bytes: 0,
            total_lines: 1,
            lines_with_gaps: 1,
            error_node_count: 0,
            missing_item_count: 0,
        };
        assert!(!metrics.parses_cleanly());
    }

    #[test]
    fn empty_and_tiny_inputs_are_stable() {
        assert_eq!(measure_qml_coverage(b"").total_bytes, 0);
        let one = measure_qml_coverage(b"x");
        assert_eq!(one.total_bytes, 1);
        assert_eq!(one.total_lines, 1);
    }

    #[test]
    fn metrics_are_deterministic_across_runs() {
        let source = b"import QtQuick.Layouts\nColumnLayout {\n  Text { text: qsTr(\"a\") }\n}\n";
        assert_eq!(measure_qml_coverage(source), measure_qml_coverage(source));
    }
}
