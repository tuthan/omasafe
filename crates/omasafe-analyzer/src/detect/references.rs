//! Literal reference extraction, sink positions, and invocation-edge
//! resolution over the ingested inventory.

use std::collections::BTreeMap;

use crate::fingerprint::Confidence;
use crate::payload::{PayloadInventory, PayloadKind};

use crate::detect::model::{
    FileOutcome, OUT_OF_TREE_REFERENCE_RULE, REMOTE_COMPONENT_LOAD_RULE,
    REMOTE_DIRECTORY_IMPORT_RULE, ResultParts, parts,
};

/// Cheap path-likeness prefilter; the inventory existence check in
/// [`resolve_reference`] is the real gate.
pub(in crate::detect) fn is_path_shaped(value: &str) -> bool {
    if value.is_empty() || value.len() > 512 {
        return false;
    }
    value.contains('/') || (value.contains('.') && !value.contains(' '))
}

/// Resolve one literal reference against the inventory: plain relative paths
/// to inventoried files only — never traversal segments, schemes, absolute
/// paths, directories, or symlinks. Any bundled file can be an invocation
/// target (`Loader` sources, `FileView` paths, script payloads alike); the
/// existence check against the inventory is what keeps ordinary prose out.
pub(in crate::detect) fn resolve_reference(
    inventory: &PayloadInventory,
    by_path: &BTreeMap<String, usize>,
    from_path: &str,
    value: &str,
) -> Option<usize> {
    if value.is_empty()
        || value.len() > 512
        || value.starts_with('/')
        || value.contains(':')
        || value.contains(' ')
        || value.contains('\n')
    {
        return None;
    }
    // Leading "./" is ordinary relative spelling; only inner traversal
    // segments are hostile.
    let stripped = value.trim_start_matches("./");
    if stripped.is_empty()
        || stripped
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return None;
    }
    // QML/JS references resolve relative to the referencing file first;
    // repository-root-relative spellings are the fallback.
    let mut candidate_paths: Vec<String> = Vec::new();
    if let Some((directory, _file)) = from_path.rsplit_once('/') {
        candidate_paths.push(format!("{}/{}", directory, stripped));
    }
    candidate_paths.push(stripped.to_owned());
    for candidate in candidate_paths {
        if let Some(index) = by_path.get(candidate.as_str()) {
            if matches!(
                inventory.entries[*index].kind,
                PayloadKind::Symlink | PayloadKind::Directory | PayloadKind::Special
            ) {
                return None;
            }
            return Some(*index);
        }
    }
    None
}

/// Verified sink positions for reference candidates (H2). A path-shaped
/// string at one of these positions is a real load or execution input, so a
/// failed in-tree resolution is disclosed with a typed reason; path-shaped
/// strings anywhere else stay inventory context (R-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::detect) enum SinkPosition {
    LoaderSource,
    CreateComponent,
    Include,
    ProcessCommand,
    ExecDetached,
    FileViewPath,
}

impl SinkPosition {
    pub(in crate::detect) fn label(self) -> &'static str {
        match self {
            SinkPosition::LoaderSource => "Loader.source",
            SinkPosition::CreateComponent => "Qt.createComponent",
            SinkPosition::Include => "Qt.include",
            SinkPosition::ProcessCommand => "Process.command",
            SinkPosition::ExecDetached => "execDetached",
            SinkPosition::FileViewPath => "FileView.path",
        }
    }
}

/// One reference candidate collected during per-file analysis. `sink` marks
/// verified sink positions; unmarked candidates are inventory context only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::detect) struct ReferenceCandidate {
    pub(in crate::detect) line: u32,
    pub(in crate::detect) value: String,
    pub(in crate::detect) sink: Option<SinkPosition>,
}

/// Centralized scheme parsing for reference classification (H2 review):
/// URI schemes are case-insensitive (RFC 3986), so `HTTPS://…` must reach
/// the same verdict as its lowercase spelling, and one parser feeds rejection
/// reasons, the remote-load family, and the out-of-tree family so the three
/// can never disagree about the same literal. The remote set is the network
/// transports Qt's component loader accepts on the pinned runtime; `file`
/// denotes a local path, so it is an out-of-tree load, never remote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::detect) enum SchemeClass {
    Remote,
    LocalFile,
    Other,
}

pub(in crate::detect) fn scheme_class(value: &str) -> Option<SchemeClass> {
    let position = value.find(':')?;
    let scheme = &value[..position];
    let mut chars = scheme.chars();
    if !chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
    {
        return None;
    }
    if !chars.all(|char| char.is_ascii_alphanumeric() || matches!(char, '+' | '-' | '.')) {
        return None;
    }
    if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") {
        return Some(SchemeClass::Remote);
    }
    if scheme.eq_ignore_ascii_case("file") {
        return Some(SchemeClass::LocalFile);
    }
    Some(SchemeClass::Other)
}

/// Typed reason a reference cannot resolve in-tree, mirroring
/// [`resolve_reference`]'s rejection conditions so reports can triage it
/// (R-2): `remote`, `absolute`, `traversal`, `missing-local-target`,
/// `unsupported-scheme`. A `file://` URL names a local path outside the
/// tree, so its reason is `absolute`.
pub(in crate::detect) fn rejection_reason(value: &str) -> &'static str {
    match scheme_class(value) {
        Some(SchemeClass::Remote) => return "remote",
        Some(SchemeClass::LocalFile) => return "absolute",
        Some(SchemeClass::Other) => return "unsupported-scheme",
        None => {}
    }
    if value.starts_with('/') {
        return "absolute";
    }
    // Leading "./" is ordinary relative spelling; only inner traversal
    // segments are hostile (same rule as resolve_reference).
    let stripped = value.trim_start_matches("./");
    if stripped
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return "traversal";
    }
    "missing-local-target"
}

/// Absolute-path, traversal, or `file://` spelling: content from outside the
/// reviewed plugin tree. Leading "./" is ordinary relative spelling, not
/// traversal.
pub(in crate::detect) fn is_out_of_tree_spelling(value: &str) -> bool {
    if value.starts_with('/') {
        return true;
    }
    if matches!(scheme_class(value), Some(SchemeClass::LocalFile)) {
        return true;
    }
    value
        .trim_start_matches("./")
        .split('/')
        .any(|segment| segment == "..")
}

/// Findings for literals at load sinks (H2). Network schemes at the two
/// verified reachable load positions (H0 record) are the High
/// remote-component-load family; absolute/traversal spellings at load sinks
/// are unreviewed out-of-tree loads (Medium) — not sandbox escapes. Plain
/// relative spellings carry no finding: they resolve as inventory edges or
/// surface a typed rejection.
pub(in crate::detect) fn load_sink_finding(
    value: &str,
    sink: SinkPosition,
    line: u32,
    confidence: Confidence,
) -> Option<ResultParts> {
    let remote = matches!(scheme_class(value), Some(SchemeClass::Remote));
    if remote
        && matches!(
            sink,
            SinkPosition::LoaderSource | SinkPosition::CreateComponent
        )
    {
        return Some(parts(
            REMOTE_COMPONENT_LOAD_RULE,
            line,
            format!("remote-component-load:{}:{value}", sink.label()),
            confidence,
        ));
    }
    if matches!(
        sink,
        SinkPosition::LoaderSource | SinkPosition::CreateComponent | SinkPosition::Include
    ) && is_out_of_tree_spelling(value)
    {
        return Some(parts(
            OUT_OF_TREE_REFERENCE_RULE,
            line,
            format!("out-of-tree-reference:{}:{value}", sink.label()),
            confidence,
        ));
    }
    None
}

/// Record one sink-position literal: a load-sink finding when the spelling
/// carries one, otherwise a sink-marked reference candidate for in-tree
/// resolution (edge or typed rejection).
pub(in crate::detect) fn record_sink_reference(
    text: &str,
    sink: SinkPosition,
    line: u32,
    outcome: &mut FileOutcome,
) {
    if let Some(finding) = load_sink_finding(text, sink, line, outcome.confidence) {
        outcome.result_parts.push(finding);
        return;
    }
    if is_path_shaped(text) {
        outcome.references.push(ReferenceCandidate {
            line,
            value: text.to_owned(),
            sink: Some(sink),
        });
    }
}

/// Directory-import specifier handling, shared by the AST and lexical paths
/// (H2). Remote schemes record the verified-scanner-intercepted indicator —
/// never the High remote-load family; absolute/traversal spellings are
/// reachable local out-of-tree loads and carry the Medium finding. Plain
/// relative imports are ordinary QML and stay silent.
pub(in crate::detect) fn apply_directory_import(
    specifier: &str,
    line: u32,
    outcome: &mut FileOutcome,
) {
    let remote = matches!(scheme_class(specifier), Some(SchemeClass::Remote));
    if remote {
        outcome.result_parts.push(parts(
            REMOTE_DIRECTORY_IMPORT_RULE,
            line,
            format!("remote-directory-import:{specifier}"),
            outcome.confidence,
        ));
        return;
    }
    if is_out_of_tree_spelling(specifier) {
        outcome.result_parts.push(parts(
            OUT_OF_TREE_REFERENCE_RULE,
            line,
            format!("out-of-tree-reference:directory-import:{specifier}"),
            outcome.confidence,
        ));
    }
}
