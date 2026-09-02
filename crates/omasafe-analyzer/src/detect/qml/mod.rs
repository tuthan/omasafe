//! QML/JavaScript frontend: per-language entry points over the
//! parser-backed and lexical-fallback builds.

#[cfg(feature = "qml-parser")]
pub(in crate::detect) mod ast;
#[cfg(feature = "qml-parser")]
pub(in crate::detect) mod dataflow;
pub(in crate::detect) mod lexical;
pub(in crate::detect) mod strings;

use self::lexical::lexical_scan;

use crate::detect::model::FileOutcome;
use crate::rules::Language;

#[cfg(feature = "qml-parser")]
pub(in crate::detect) fn analyze_qml_source(source: &str) -> FileOutcome {
    match crate::qml::parse_qml(source.as_bytes()) {
        Some(tree) => ast_scan_qml(source, &tree),
        None => lexical_scan(source, Language::Qml),
    }
}

#[cfg(not(feature = "qml-parser"))]
pub(in crate::detect) fn analyze_qml_source(source: &str) -> FileOutcome {
    lexical_scan(source, Language::Qml)
}

// ---------------------------------------------------------------------------
// AST-backed QML analysis (qml-parser feature).
// ---------------------------------------------------------------------------

#[cfg(feature = "qml-parser")]
fn ast_scan_qml(source: &str, tree: &tree_sitter::Tree) -> FileOutcome {
    ast::scan(source, tree)
}

pub(in crate::detect) fn analyze_javascript_source(source: &str) -> FileOutcome {
    lexical_scan(source, Language::JavaScript)
}
