//! S3 detectors: capability observation, suspicious-provenance findings, and
//! invocation-edge resolution over an ingested payload inventory.
//!
//! The rule contract separates ability from suspicion: seeing `Process`,
//! `execDetached`, `FileView`, or a network sink records a capability
//! occurrence; emitting a fingerprintable finding requires suspicious
//! provenance — shell-interpreter chains (`sh -c …`), dynamically composed
//! commands, or a network-response-to-execution chain in the same file.
//!
//! Evidence quality follows the build: with the `qml-parser` feature QML is
//! parsed and conclusions are [`Confidence::AstBacked`]; without it — and for
//! standalone `.js` resources, which the QML grammar cannot parse cleanly —
//! detection is line-lexical and labelled [`Confidence::LexicalFallback`] so
//! report consumers can weigh it accordingly (ADR 0001).
//!
//! Nothing here executes scanned content; parsing and scanning are inert.

use std::collections::{BTreeMap, BTreeSet};

use omasafe_core::bounds::{MAX_EVIDENCE_BYTES_PER_RESULT, MAX_FILE_BYTES, MAX_SINK_REJECTIONS};
use omasafe_report::analysis::{
    CapabilityOccurrence, InvocationEdge, ParserMetadata, RenderedFinding,
};

use crate::TimeBudget;
use crate::fingerprint::{Confidence, NormalizedResult};
use crate::payload::{CoverageState, PayloadEntry, PayloadInventory, PayloadKind};
use crate::rules::{Capability, Language, Severity, rule};

mod model;
mod qml;
mod script;
mod shell;

use model::balanced_bracket_span;
use qml::strings::decode_js_escapes;
use script::python::python_reverse_shell;
use shell::budget::ShellBudget;
use shell::command::{
    ScriptCommand, command_arguments, command_basename, env_split_string_command,
    is_redirect_operator, segment_commands, skip_command_prefixes, skip_wrapper_options,
};
use shell::consumption::shell_consumption_findings;
use shell::effects::{segment_stdin_reaches_interpreter, segment_stdout_preserved};
use shell::egress::{script_body_fetches, tokens_fetch_egress};
use shell::interpreter::{
    INTERPRETER_BASENAMES, InterpreterFamily, InterpreterMode, interpreter_family, interpreter_mode,
};
use shell::lexer::{ShellToken, tokenize};
use shell::source::shell_logical_units;
use shell::syntax::{conditional_statements, pipeline_segments};
use shell::xargs::xargs_body_fate;

/// Everything one analysis pass produced.
#[derive(Debug, Default)]
pub struct AnalysisArtifacts {
    /// Fingerprintable normalized results (suspicious provenance only).
    pub results: Vec<NormalizedResult>,
    /// Ability observations that never assert malicious intent.
    pub capabilities: Vec<CapabilityOccurrence>,
    /// Resolved literal references between analyzed files.
    pub edges: Vec<InvocationEdge>,
    /// Analysis-level disclosures (budget exhaustion, unavailable content).
    pub limitations: Vec<String>,
}

impl AnalysisArtifacts {
    /// Deterministic rendered findings joined with catalog facts. Duplicate
    /// normalized results collapse so repeated sinks render once.
    pub fn rendered_findings(&self) -> Vec<RenderedFinding> {
        let mut seen = std::collections::BTreeSet::new();
        let mut rendered = Vec::new();
        for result in &self.results {
            let key = (
                result.rule_id().to_owned(),
                result.relative_path().to_owned(),
                result.line(),
                result.semantic_value().to_owned(),
            );
            if !seen.insert(key) {
                continue;
            }
            let Some(definition) = rule(result.rule_id()) else {
                continue;
            };
            rendered.push((
                definition.default_severity,
                RenderedFinding {
                    rule_id: definition.id.to_owned(),
                    title: definition.title.to_owned(),
                    severity: definition.default_severity.to_string(),
                    language: definition.language.to_string(),
                    capability: definition.capability.to_string(),
                    relative_path: result.relative_path().to_owned(),
                    line: result.line(),
                    evidence: truncate_bytes(
                        result.semantic_value(),
                        MAX_EVIDENCE_BYTES_PER_RESULT,
                    ),
                    confidence: result.confidence().map(|confidence| match confidence {
                        Confidence::AstBacked => "ast-backed".to_owned(),
                        Confidence::LexicalFallback => "lexical-fallback".to_owned(),
                    }),
                    explanation: definition.summary.to_owned(),
                    review_guidance: definition.review_guidance.to_owned(),
                },
            ));
        }
        // Priority surfaces first: highest severity dominates the report view,
        // with stable path/rule/line ordering within a severity band.
        rendered.sort_by(|(severity_a, finding_a), (severity_b, finding_b)| {
            severity_b.cmp(severity_a).then_with(|| {
                (
                    &finding_a.relative_path,
                    &finding_a.rule_id,
                    finding_a.line,
                    &finding_a.evidence,
                )
                    .cmp(&(
                        &finding_b.relative_path,
                        &finding_b.rule_id,
                        finding_b.line,
                        &finding_b.evidence,
                    ))
            })
        });
        rendered.into_iter().map(|(_, finding)| finding).collect()
    }

    /// Highest finding severity, for `--fail-on` threshold decisions.
    pub fn max_severity(&self) -> Option<Severity> {
        self.results
            .iter()
            .filter_map(|result| rule(result.rule_id()))
            .map(|definition| definition.default_severity)
            .max()
    }
}

/// Parser identity for report embedding; `None` in lexical-fallback builds.
pub fn parser_metadata() -> Option<ParserMetadata> {
    #[cfg(feature = "qml-parser")]
    {
        let identity = crate::qml::qml_parser_identity();
        Some(ParserMetadata {
            grammar: identity.grammar.to_owned(),
            grammar_version: identity.grammar_version.to_owned(),
            tree_sitter_version: identity.tree_sitter_version.to_owned(),
            language_abi_version: identity.language_abi_version,
        })
    }
    #[cfg(not(feature = "qml-parser"))]
    None
}

fn truncate_bytes(value: &str, cap: usize) -> String {
    if value.len() <= cap {
        return value.to_owned();
    }
    let mut end = cap;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

/// Run every detector over a fully ingested inventory. `read_content` must
/// return bounded bytes for an entry; entries without a detector are skipped.
///
/// On return the inventory's analyzable entries carry final coverage states:
/// `analyzed` (findings reference them), `partial` (syntax errors degraded the
/// parse), or `unreferenced` (fully analyzed and reachable analysis found
/// nothing). Edge targets gain `referenced = true`.
pub fn analyze_inventory(
    inventory: &mut PayloadInventory,
    read_content: &dyn Fn(&PayloadEntry) -> Option<Vec<u8>>,
    budget: &TimeBudget,
) -> AnalysisArtifacts {
    let mut artifacts = AnalysisArtifacts::default();
    let mut by_path: BTreeMap<String, usize> = BTreeMap::new();
    for (index, entry) in inventory.entries.iter().enumerate() {
        by_path.insert(entry.relative_path.clone(), index);
    }

    struct PendingEdge {
        from_path: String,
        line: u32,
        value: String,
        sink: Option<SinkPosition>,
    }
    let mut pending_edges: Vec<PendingEdge> = Vec::new();

    for index in 0..inventory.entries.len() {
        if budget.expired() {
            artifacts
                .limitations
                .push("analysis_time_budget_exhausted".to_owned());
            break;
        }
        let entry = inventory.entries[index].clone();

        // Plugin manifests feed context results/capabilities (bar kind,
        // headless services). They are not language analysis.
        if entry.relative_path.ends_with("/manifest.json") || entry.relative_path == "manifest.json"
        {
            if entry.size <= MAX_FILE_BYTES {
                if let Some(content) = read_content(&entry) {
                    apply_manifest_context(&content, &entry.relative_path, &mut artifacts);
                } else {
                    artifacts
                        .limitations
                        .push(format!("content_unavailable:{}", entry.relative_path));
                }
            }
            continue;
        }

        let analyzable = matches!(
            entry.kind,
            PayloadKind::Qml | PayloadKind::JavaScript | PayloadKind::Shell | PayloadKind::Python
        );
        if !analyzable
            || !matches!(entry.coverage_state, CoverageState::Unsupported)
            || entry.size > MAX_FILE_BYTES
        {
            continue;
        }
        let Some(content) = read_content(&entry) else {
            artifacts
                .limitations
                .push(format!("content_unavailable:{}", entry.relative_path));
            continue;
        };
        let source = String::from_utf8_lossy(&content).into_owned();

        let entry_kind = entry.kind;
        let mut outcome = match &entry_kind {
            PayloadKind::Qml => analyze_qml_source(&source),
            PayloadKind::JavaScript => analyze_javascript_source(&source),
            kind @ (PayloadKind::Shell | PayloadKind::Python) => {
                let script_kind = kind.clone();
                analyze_script_source(&source, script_kind)
            }
            _ => unreachable!("kinds filtered above"),
        };

        // Anchor results onto the entry's canonical relative path.
        for candidate in &outcome.result_parts {
            if let Ok(normalized) = NormalizedResult::new(
                candidate.rule_id,
                &entry.relative_path,
                candidate.line,
                None,
                candidate.semantic_value.clone(),
                Some(candidate.confidence),
            ) {
                artifacts.results.push(normalized);
            }
        }
        for limitation in &outcome.limitations {
            artifacts
                .limitations
                .push(format!("{limitation}:{}", entry.relative_path));
        }
        for capability in &mut outcome.capabilities {
            capability.relative_path = entry.relative_path.clone();
            capability.confidence = Some(
                match outcome.confidence {
                    Confidence::AstBacked => "ast-backed",
                    Confidence::LexicalFallback => "lexical-fallback",
                }
                .to_owned(),
            );
        }
        // Decide the coverage state BEFORE draining observations.
        let produced_observations = outcome.has_findings() || !outcome.capabilities.is_empty();
        artifacts.capabilities.append(&mut outcome.capabilities);
        for candidate in outcome.references.drain(..) {
            pending_edges.push(PendingEdge {
                from_path: entry.relative_path.clone(),
                line: candidate.line,
                value: candidate.value,
                sink: candidate.sink,
            });
        }

        // `analyzed` means detectors produced observations (findings or
        // capabilities); `unreferenced` means they ran and saw nothing.
        // Shell/Python are always `partial`: minimal lexical coverage means
        // no match never implies clean behavior. Parse-degraded QML/JS is
        // likewise partial.
        inventory.entries[index].coverage_state =
            if matches!(entry_kind, PayloadKind::Shell | PayloadKind::Python)
                || outcome.parse_degraded
            {
                CoverageState::Partial
            } else if produced_observations {
                CoverageState::Analyzed
            } else {
                CoverageState::Unreferenced
            };
    }

    // Resolve literal references strictly inside the logical root. The loop
    // honors the analysis time budget (H2 review) and retains at most
    // MAX_SINK_REJECTIONS unique typed rejections, disclosing overflow
    // separately instead of expanding limitation strings without bound. The
    // cap is applied to the set of unique strings — deduplication happens as
    // rejections are collected, not after a fixed-size prefix is filled — so a
    // later unique rejection is never crowded out by earlier duplicates, and
    // duplicate-only input never reports truncation.
    let mut resolved: Vec<InvocationEdge> = Vec::new();
    let mut sink_rejections: BTreeSet<String> = BTreeSet::new();
    let mut sink_rejections_omitted = 0usize;
    for edge in pending_edges {
        if budget.expired() {
            let disclosed = artifacts
                .limitations
                .iter()
                .any(|limitation| limitation == "analysis_time_budget_exhausted");
            if !disclosed {
                artifacts
                    .limitations
                    .push("analysis_time_budget_exhausted".to_owned());
            }
            break;
        }
        let Some(target_index) =
            resolve_reference(inventory, &by_path, &edge.from_path, &edge.value)
        else {
            // Rejected references are disclosed only for verified sink
            // positions, with a typed reason (R-2). Non-sink path-shaped
            // strings stay inventory context, exactly as before.
            if edge.sink.is_some() {
                let rejection = format!(
                    "sink-reference-rejected:{}:{}:{}:{}",
                    rejection_reason(&edge.value),
                    edge.from_path,
                    edge.line,
                    edge.value
                );
                // A rejection already disclosed verbatim (retained in the
                // set) carries no new information. A rejection that cannot
                // be retained because the set is full is omitted: every such
                // occurrence is counted, because remembering WHICH values
                // were omitted would need unbounded fingerprints under
                // adversarial input — the truncation count is deliberately
                // an occurrence count, never a unique count (H2 review).
                if sink_rejections.contains(&rejection) {
                    // Already disclosed.
                } else if sink_rejections.len() < MAX_SINK_REJECTIONS {
                    sink_rejections.insert(rejection);
                } else {
                    sink_rejections_omitted += 1;
                }
            }
            continue;
        };
        inventory.entries[target_index].invocation_target = true;
        resolved.push(InvocationEdge {
            from_path: edge.from_path,
            line: Some(edge.line),
            target_path: inventory.entries[target_index].relative_path.clone(),
        });
    }
    // BTreeSet already yields sorted, unique strings.
    artifacts.limitations.extend(sink_rejections);
    if sink_rejections_omitted > 0 {
        artifacts.limitations.push(format!(
            "sink-reference-rejections-truncated:{sink_rejections_omitted}"
        ));
    }
    resolved.sort_by(|a, b| (&a.from_path, &a.target_path).cmp(&(&b.from_path, &b.target_path)));
    resolved.dedup_by(|a, b| a.from_path == b.from_path && a.target_path == b.target_path);
    artifacts.edges = resolved;

    artifacts.capabilities.sort_by(|a, b| {
        (&a.capability, &a.relative_path, a.line, &a.detail).cmp(&(
            &b.capability,
            &b.relative_path,
            b.line,
            &b.detail,
        ))
    });
    artifacts.capabilities.dedup_by(|a, b| {
        a.capability == b.capability
            && a.relative_path == b.relative_path
            && a.line == b.line
            && a.detail == b.detail
    });

    artifacts
}

/// Resolve one literal reference against the inventory: plain relative paths
/// to inventoried files only — never traversal segments, schemes, absolute
/// paths, directories, or symlinks. Any bundled file can be an invocation
/// target (`Loader` sources, `FileView` paths, script payloads alike); the
/// existence check against the inventory is what keeps ordinary prose out.
/// Cheap path-likeness prefilter; the inventory existence check in
/// [`resolve_reference`] is the real gate.
fn is_path_shaped(value: &str) -> bool {
    if value.is_empty() || value.len() > 512 {
        return false;
    }
    value.contains('/') || (value.contains('.') && !value.contains(' '))
}

fn resolve_reference(
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
enum SinkPosition {
    LoaderSource,
    CreateComponent,
    Include,
    ProcessCommand,
    ExecDetached,
    FileViewPath,
}

impl SinkPosition {
    fn label(self) -> &'static str {
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
struct ReferenceCandidate {
    line: u32,
    value: String,
    sink: Option<SinkPosition>,
}

/// Centralized scheme parsing for reference classification (H2 review):
/// URI schemes are case-insensitive (RFC 3986), so `HTTPS://…` must reach
/// the same verdict as its lowercase spelling, and one parser feeds rejection
/// reasons, the remote-load family, and the out-of-tree family so the three
/// can never disagree about the same literal. The remote set is the network
/// transports Qt's component loader accepts on the pinned runtime; `file`
/// denotes a local path, so it is an out-of-tree load, never remote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SchemeClass {
    Remote,
    LocalFile,
    Other,
}

fn scheme_class(value: &str) -> Option<SchemeClass> {
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
fn rejection_reason(value: &str) -> &'static str {
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
fn is_out_of_tree_spelling(value: &str) -> bool {
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
fn load_sink_finding(
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
fn record_sink_reference(text: &str, sink: SinkPosition, line: u32, outcome: &mut FileOutcome) {
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
fn apply_directory_import(specifier: &str, line: u32, outcome: &mut FileOutcome) {
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

/// Per-file detector output before cross-file anchoring.
struct FileOutcome {
    result_parts: Vec<ResultParts>,
    capabilities: Vec<CapabilityOccurrence>,
    references: Vec<ReferenceCandidate>,
    parse_degraded: bool,
    confidence: Confidence,
    /// Coverage limitations this file's analysis hit (budget exhaustion),
    /// anchored onto the entry path when artifacts are assembled.
    limitations: Vec<String>,
}

impl FileOutcome {
    fn has_findings(&self) -> bool {
        !self.result_parts.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SinkKind {
    Process,
    DetachedExecution,
}

const PROCESS_RULE: &str = "oma.qml.process-execution";
const DETACHED_RULE: &str = "oma.qml.detached-execution";
#[cfg_attr(not(test), allow(dead_code))]
const NETWORK_RULE: &str = "oma.qml.network-access";
#[cfg(feature = "qml-parser")]
const DYNAMIC_REFERENCE_RULE: &str = "oma.qml.dynamic-reference";
#[cfg_attr(not(test), allow(dead_code))]
const DYNAMIC_CODE_RULE: &str = "oma.qml.dynamic-code";
#[cfg_attr(not(test), allow(dead_code))]
const OBFUSCATION_RULE: &str = "oma.qml.obfuscated-payload-indicator";
const PERSISTENCE_RULE: &str = "oma.qml.persistence-scheduling";
const REMOTE_COMPONENT_LOAD_RULE: &str = "oma.qml.remote-component-load";
const REMOTE_DIRECTORY_IMPORT_RULE: &str = "oma.qml.remote-directory-import";
const OUT_OF_TREE_REFERENCE_RULE: &str = "oma.qml.out-of-tree-reference";
const SCRIPT_DOWNLOAD_EXECUTE_RULE: &str = "oma.script.download-execute";
const SCRIPT_PRIVILEGE_RULE: &str = "oma.script.privilege-escalation";
const PYTHON_DOWNLOAD_EXECUTE_RULE: &str = "oma.python.download-execute";
const PYTHON_PRIVILEGE_RULE: &str = "oma.python.privilege-escalation";
pub(in crate::detect) const SCRIPT_REVERSE_SHELL_RULE: &str = "oma.script.reverse-shell";
const PYTHON_REVERSE_SHELL_RULE: &str = "oma.python.reverse-shell";
pub(in crate::detect) const SCRIPT_DECODE_EXECUTE_RULE: &str = "oma.script.decode-execute";
pub(in crate::detect) const SHARED_TEMP_INDICATOR_RULE: &str = "oma.script.privileged-shared-temp";
pub(in crate::detect) const SHARED_TEMP_CONTROLLED_RULE: &str =
    "oma.script.privileged-shared-temp-controlled";
const REPLACES_BAR_RULE: &str = "oma.context.replaces-bar";

struct LexFlags {
    detached_any: Option<u32>,
    network: Option<u32>,
}

pub(in crate::detect) fn parts(
    rule_id: &'static str,
    line: u32,
    semantic_value: impl Into<String>,
    confidence: Confidence,
) -> ResultParts {
    ResultParts {
        rule_id,
        line: Some(line),
        semantic_value: truncate_bytes(&semantic_value.into(), MAX_EVIDENCE_BYTES_PER_RESULT),
        confidence,
    }
}

fn occurrence(
    capability: Capability,
    language: Language,
    line: u32,
    detail: &str,
) -> CapabilityOccurrence {
    // Script-language capability context has no dedicated catalog rule yet;
    // attributing it to QML rules would produce misleading guidance.
    let covering_rule = if matches!(language, Language::Shell | Language::Python) {
        None
    } else {
        capability_covering_rule(capability)
    }
    .and_then(crate::rules::rule);
    CapabilityOccurrence {
        capability: capability.to_string(),
        language: language.to_string(),
        relative_path: String::new(),
        line: Some(line),
        source_rule_id: covering_rule.map(|definition| definition.id.to_owned()),
        detail: truncate_bytes(detail, 200),
        confidence: None,
        explanation: covering_rule
            .map(|definition| definition.summary.to_owned())
            .unwrap_or_else(|| {
                "script capability observed; lexical coverage is minimal by design".to_owned()
            }),
        review_guidance: covering_rule
            .map(|definition| definition.review_guidance.to_owned())
            .unwrap_or_else(|| "Review the surrounding script manually".to_owned()),
    }
}

fn capability_covering_rule(capability: Capability) -> Option<&'static str> {
    match capability {
        Capability::ProcessExecution => Some("oma.qml.process-execution"),
        Capability::DetachedProcessExecution => Some("oma.qml.detached-execution"),
        Capability::FilesystemAccess => Some("oma.qml.filesystem-access"),
        Capability::NetworkAccess => Some("oma.qml.network-access"),
        Capability::PersistenceScheduling => Some(PERSISTENCE_RULE),
        Capability::ClipboardAccess => Some("oma.qml.clipboard-access"),
        Capability::CompositorControl => Some("oma.qml.compositor-control"),
        Capability::PolkitAgentUi => Some("oma.qml.polkit-agent-ui"),
        Capability::SessionLockSurface => Some("oma.qml.session-lock"),
        Capability::PamAuthentication => Some("oma.qml.pam-authentication"),
        Capability::DynamicCodeExecution => Some(DYNAMIC_CODE_RULE),
        _ => None,
    }
}

/// Shell-interpreter invocation inside a command string: an interpreter word
/// followed (after whitespace) by a `-c`-style flag. Returns the byte offset
/// of the interpreter word for evidence trimming.
fn find_shell_interpreter(text: &str) -> Option<usize> {
    const INTERPRETERS: [&str; 6] = ["sh", "bash", "zsh", "dash", "ksh", "ash"];
    let bytes = text.as_bytes();
    let mut position = 0usize;
    while position < bytes.len() {
        // Advance to the next word start; path separators stay inside words
        // so `/bin/sh -c` scans as basename `sh`.
        while position < bytes.len()
            && !bytes[position].is_ascii_alphanumeric()
            && bytes[position] != b'/'
        {
            position += 1;
        }
        if position >= bytes.len() {
            break;
        }
        let start = position;
        while position < bytes.len()
            && (bytes[position].is_ascii_alphanumeric() || bytes[position] == b'/')
        {
            position += 1;
        }
        let word = &text[start..position];
        let basename = word.rsplit('/').next().unwrap_or(word);
        if INTERPRETERS.contains(&basename) {
            // Skip whitespace, then require a `-c…` style flag.
            let mut cursor = position;
            while cursor < bytes.len() && (bytes[cursor] == b' ' || bytes[cursor] == b'\t') {
                cursor += 1;
            }
            if cursor + 1 < bytes.len()
                && bytes[cursor] == b'-'
                && bytes[cursor + 1] == b'c'
                && (cursor + 2 == bytes.len()
                    || bytes[cursor + 2] == b' '
                    || bytes[cursor + 2] == b'\t')
            {
                return Some(start);
            }
        }
        // Skip past this word even when it did not match.
        while position < bytes.len() && bytes[position] != b' ' {
            position += 1;
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Lexical analysis: standalone .js always, and all QML in fallback builds.
// ---------------------------------------------------------------------------

fn lexical_scan(source: &str, language: Language) -> FileOutcome {
    let mut outcome = FileOutcome {
        result_parts: Vec::new(),
        capabilities: Vec::new(),
        references: Vec::new(),
        parse_degraded: false,
        confidence: Confidence::LexicalFallback,
        limitations: Vec::new(),
    };
    let mut flags = LexFlags {
        detached_any: None,
        network: None,
    };

    for (index, raw_line) in source.lines().enumerate() {
        let number = index as u32 + 1;
        // One shared quote-aware trim: commented-out code is invisible to
        // every detector below, while quoted text survives intact.
        let line = strip_line_comment(raw_line, CommentStyle::DoubleSlash);
        if line.is_empty() {
            continue;
        }
        // Every occurrence gets its own argument judgment: a benign first
        // call must not mask a suspicious later one.
        let mut search_from = 0usize;
        while let Some(relative_offset) = find_word(&line[search_from..], "execDetached") {
            let offset = search_from + relative_offset;
            search_from = offset + "execDetached".len();
            flags.detached_any.get_or_insert(number);
            outcome.capabilities.push(occurrence(
                Capability::DetachedProcessExecution,
                language,
                number,
                &line[offset..],
            ));
            // The call's own paren: first '(' after the name, skipping only
            // whitespace.
            let mut cursor = search_from;
            while cursor < line.len() && matches!(line.as_bytes()[cursor], b' ' | b'\t') {
                cursor += 1;
            }
            if cursor < line.len()
                && line.as_bytes()[cursor] == b'('
                && let Some((start, end)) = balanced_bracket_span(line, cursor)
            {
                evaluate_execution_span(
                    &line[start..end],
                    SinkKind::DetachedExecution,
                    number,
                    &mut outcome,
                );
                // The executed path is also a reference sink (H2): literals
                // inside the argument span only, never the whole line.
                for literal in span_sink_literals(&line[start..end]) {
                    record_sink_reference(
                        &literal,
                        SinkPosition::ExecDetached,
                        number,
                        &mut outcome,
                    );
                }
            }
        }
        let is_network_line = line.contains("new XMLHttpRequest")
            || find_word(line, "fetch(").is_some()
            || line.contains("WebSocket");
        if is_network_line {
            flags.network.get_or_insert(number);
            outcome.capabilities.push(occurrence(
                Capability::NetworkAccess,
                language,
                number,
                line.trim(),
            ));
        }
        if find_word(line, "FileView").is_some() {
            outcome.capabilities.push(occurrence(
                Capability::FilesystemAccess,
                language,
                number,
                line.trim(),
            ));
        }
        if find_word(line, "Timer").is_some() {
            outcome.capabilities.push(occurrence(
                Capability::PersistenceScheduling,
                language,
                number,
                line.trim(),
            ));
        }
        if find_word(line, "Process").is_some() {
            // Every `command` binding gets its own judgment; the line is
            // already comment-trimmed by strip_line_comment.
            let mut search_from = 0usize;
            while let Some(relative_offset) = find_word(&line[search_from..], "command") {
                let word = search_from + relative_offset;
                search_from = word + "command".len();
                outcome.capabilities.push(occurrence(
                    Capability::ProcessExecution,
                    language,
                    number,
                    line.trim(),
                ));
                // Suspicious provenance only, judged on the binding value:
                // shell-interpreter chains or network response data. Command
                // argv is also a verified sink position (H2): literal
                // arguments inside the binding value span only — a bare
                // `command` identifier on a Process-free line never
                // participates.
                if let Some((start, end)) = binding_value_span(line, search_from) {
                    evaluate_execution_span(
                        &line[start..end],
                        SinkKind::Process,
                        number,
                        &mut outcome,
                    );
                    for literal in span_sink_literals(&line[start..end]) {
                        record_sink_reference(
                            &literal,
                            SinkPosition::ProcessCommand,
                            number,
                            &mut outcome,
                        );
                    }
                }
            }
        }
        // Priority surfaces (lexical parity with the AST path).
        if find_word(line, "Polkit").is_some() {
            outcome.result_parts.push(parts(
                "oma.qml.polkit-agent-ui",
                number,
                "polkit-surface",
                Confidence::LexicalFallback,
            ));
        }
        if find_word(line, "PamContext").is_some() || line.contains("Services.Pam") {
            outcome.result_parts.push(parts(
                "oma.qml.pam-authentication",
                number,
                "pam-surface",
                Confidence::LexicalFallback,
            ));
        }
        if find_word(line, "WlSessionLock").is_some() {
            outcome.result_parts.push(parts(
                "oma.qml.session-lock",
                number,
                "session-lock-surface",
                Confidence::LexicalFallback,
            ));
        }
        if lower_contains(line, "clipboard") {
            outcome.capabilities.push(occurrence(
                Capability::ClipboardAccess,
                language,
                number,
                "clipboard-token",
            ));
        }
        // Hyprland* type prefixes don't satisfy word-end boundaries, so a
        // plain containment check applies; this family is capability-level.
        if line.contains("Hyprland") || line.contains("Wlr") || find_word(line, "hyprctl").is_some()
        {
            outcome.capabilities.push(occurrence(
                Capability::CompositorControl,
                language,
                number,
                "compositor-token",
            ));
        }
        // Dynamic-code needles must appear as live code, not inside quoted
        // string values. `createComponent`/`include` are matched through the
        // same Qt-global receiver verification the sink detection uses (H2
        // review): `backend.Qt.createComponent(...)` is a member named Qt,
        // not the Qt API, while `Qt . createComponent(...)` with whitespace
        // around the dot IS the Qt API and must not lose its dynamic-code
        // finding.
        let code = unquoted_text(line);
        if find_word(&code, "eval(").is_some()
            || find_word(&code, "createQmlObject(").is_some()
            || find_word(&code, "atob(").is_some()
            || !find_qt_global_calls(&code, "createComponent").is_empty()
            || !find_qt_global_calls(&code, "include").is_empty()
            || code.contains("new Function")
        {
            outcome.result_parts.push(parts(
                DYNAMIC_CODE_RULE,
                number,
                "dynamic-code-construction",
                Confidence::LexicalFallback,
            ));
            outcome.capabilities.push(occurrence(
                Capability::DynamicCodeExecution,
                language,
                number,
                line.trim(),
            ));
        }
        for literal in line_literals(line) {
            if let Some(length) = encoded_literal_length(literal) {
                outcome.result_parts.push(parts(
                    OBFUSCATION_RULE,
                    number,
                    format!("encoded-literal:{length}"),
                    Confidence::LexicalFallback,
                ));
                break;
            }
        }
        let persistence_path = (line.contains("autostart")
            || line.contains("systemd/user")
            || line.contains(".config/systemd"))
            && find_word(line, "FileView").is_some();
        if persistence_path {
            outcome.result_parts.push(parts(
                PERSISTENCE_RULE,
                number,
                "persistence-location",
                Confidence::LexicalFallback,
            ));
        }
        collect_lexical_sink_references(line, &code, number, &mut outcome);
        collect_quoted_references(line, number, &mut outcome.references);
    }

    outcome
}

pub(in crate::detect) fn lower_contains(haystack: &str, needle: &str) -> bool {
    haystack.to_ascii_lowercase().contains(needle)
}

/// Suspicious-provenance judgment over an extracted execution-argument span.
fn evaluate_execution_span(span: &str, kind: SinkKind, number: u32, outcome: &mut FileOutcome) {
    let rule_id = match kind {
        SinkKind::Process => PROCESS_RULE,
        SinkKind::DetachedExecution => DETACHED_RULE,
    };
    let joined = join_line_literals(span);
    // Egress attribution (H3 review): only the executable position
    // attributes egress. See argv_head_fetches.
    let head = if kind == SinkKind::Process {
        argv_head_fetches(&line_literals(span))
    } else {
        HeadEgress {
            fetches: false,
            exhausted: false,
        }
    };
    if head.fetches {
        outcome.capabilities.push(occurrence(
            Capability::NetworkAccess,
            Language::Qml,
            number,
            "process-argv-fetch-tool",
        ));
    }
    if head.exhausted {
        disclose_budget_limitation(outcome);
    }
    if let Some(shell_offset) = find_shell_interpreter(&joined) {
        outcome.result_parts.push(parts(
            rule_id,
            number,
            format!("shell-interpreter-command:{}", &joined[shell_offset..]),
            Confidence::LexicalFallback,
        ));
    } else if span.contains("responseText") || span.contains(".response") || span.contains(".text(")
    {
        outcome.result_parts.push(parts(
            rule_id,
            number,
            "network-response-executed",
            Confidence::LexicalFallback,
        ));
    }
}

/// Egress attribution from Process argv (H3 review): only the executable
/// position attributes egress — an argv[0] spelling a fetch tool, or the
/// `-c` script body an interpreter head executes (see
/// script_body_fetches). Arbitrary argument positions never do, so
/// `["notify-send", "curl failed"]` records no network access. A single
/// element is a whole-command string whose first word is the executable;
/// a computed (missing) head stays unattributed until the H4 dataflow
/// slice can resolve it. A `-c` body whose analysis exceeded the budget
/// reports exhaustion so the caller can disclose the shortfall.
struct HeadEgress {
    fetches: bool,
    exhausted: bool,
}

fn argv_head_fetches(elements: &[&str]) -> HeadEgress {
    let silent = HeadEgress {
        fetches: false,
        exhausted: false,
    };
    let Some(first) = elements.first() else {
        return silent;
    };
    let head = if elements.len() == 1 {
        first.split_whitespace().next().unwrap_or(first)
    } else {
        first
    };
    let basename = head.rsplit('/').next().unwrap_or(head);
    if matches!(basename, "curl" | "wget") {
        return HeadEgress {
            fetches: true,
            exhausted: false,
        };
    }
    if INTERPRETER_BASENAMES.contains(&basename)
        && let Some(script) = elements
            .iter()
            .position(|element| *element == "-c")
            .and_then(|position| elements.get(position + 1))
    {
        let (fetches, exhausted) = script_body_fetches(script);
        return HeadEgress { fetches, exhausted };
    }
    silent
}

/// The value span after `property:` on one line, stopping at a closing
/// brace/comma at bracket depth zero.
fn binding_value_span(line: &str, property_word_end: usize) -> Option<(usize, usize)> {
    let colon = line[property_word_end..]
        .find(':')
        .map(|offset| property_word_end + offset)?;
    let mut start = colon + 1;
    while start < line.len() && line[start..].starts_with([' ', '\t']) {
        start += 1;
    }
    if start >= line.len() {
        return None;
    }
    let bytes = line.as_bytes();
    if matches!(bytes[start], b'[' | b'(' | b'{') {
        return balanced_bracket_span(line, start).map(|(_, end)| (start, end + 1));
    }
    // Scalar value runs to the first top-level terminator: brace, semicolon,
    // or a line comment. Commented text never participates in provenance.
    // The scan is quote-aware so a `//` INSIDE a quoted value (a URL scheme,
    // H2 review) never truncates the span.
    let mut end = start;
    let mut in_string: Option<u8> = None;
    while end < line.len() {
        let byte = bytes[end];
        match in_string {
            Some(quote) => {
                if byte == b'\\' {
                    end += 2;
                    continue;
                }
                if byte == quote {
                    in_string = None;
                }
            }
            None => {
                if byte == b'"' || byte == b'\'' {
                    in_string = Some(byte);
                } else if matches!(byte, b'}' | b';')
                    || (byte == b'/' && end + 1 < line.len() && bytes[end + 1] == b'/')
                {
                    break;
                }
            }
        }
        end += 1;
    }
    let trimmed = line[start..end.min(line.len())].trim_end();
    Some((start, start + trimmed.len()))
}

/// Comment syntax of the surrounding language. The two real line grammars
/// each get their own rule; shell comments are applied statefully by
/// `shell_logical_units` instead:
/// - QML/JS: `//` anywhere outside strings except in a scheme (`://`),
/// - Python: an unquoted `#` starts a comment at ANY position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommentStyle {
    /// `// …` — QML/JS.
    DoubleSlash,
    /// `# …` anywhere outside strings — Python.
    PythonHash,
}

/// The executable prefix of a source line under the language's comment rule,
/// honoring quoted strings throughout.
fn strip_line_comment(line: &str, style: CommentStyle) -> &str {
    let bytes = line.as_bytes();
    let mut in_string: Option<u8> = None;
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        match in_string {
            Some(quote) => {
                if byte == b'\\' {
                    index += 2;
                    continue;
                }
                if byte == quote {
                    in_string = None;
                }
            }
            None => {
                if byte == b'"' || byte == b'\'' {
                    in_string = Some(byte);
                    // Fall through so the cursor advances past the opening
                    // delimiter; otherwise the same byte immediately closes
                    // the string and markers inside it leak into detectors.
                }
                match style {
                    CommentStyle::DoubleSlash => {
                        if byte == b'/'
                            && index + 1 < bytes.len()
                            && bytes[index + 1] == b'/'
                            // Scheme guard: `https://host` is not a comment.
                            && (index == 0 || bytes[index - 1] != b':')
                        {
                            return &line[..index];
                        }
                    }
                    CommentStyle::PythonHash => {
                        if byte == b'#' {
                            return &line[..index];
                        }
                    }
                }
            }
        }
        index += 1;
    }
    line
}

/// Module name of an `import X.Y <version>` statement (keyword/version/as
/// excluded).
#[cfg(feature = "qml-parser")]
fn import_module_text(source: &str, node: tree_sitter::Node) -> String {
    let mut cursor = node.walk();
    let mut module = String::new();
    let mut children = Vec::new();
    for child in node.children(&mut cursor) {
        children.push(child);
    }
    // The grammar nests the module under nested_identifier when dotted;
    // otherwise a plain identifier. Version numbers are anonymous literals.
    for child in children {
        match child.kind() {
            "nested_identifier" | "identifier" => {
                module.push_str(&source[child.start_byte()..child.end_byte()]);
            }
            _ => {}
        }
    }
    module
}

/// Priority surfaces from imports. Near-zero-legitimacy third-party use of
/// polkit/PAM/session-lock APIs is itself the finding (surface doc); Hyprland/
/// Wayland imports record a compositor-control capability.
#[cfg(feature = "qml-parser")]
fn apply_import_surface(module: &str, line: u32, outcome: &mut FileOutcome) {
    if module.contains("Services.Polkit") {
        outcome.result_parts.push(parts(
            "oma.qml.polkit-agent-ui",
            line,
            "polkit-agent-import",
            Confidence::AstBacked,
        ));
    }
    if module.contains("PamContext") || module.contains("Services.Pam") {
        outcome.result_parts.push(parts(
            "oma.qml.pam-authentication",
            line,
            "pam-context-import",
            Confidence::AstBacked,
        ));
    }
    if module.contains("SessionLock") {
        outcome.result_parts.push(parts(
            "oma.qml.session-lock",
            line,
            "session-lock-import",
            Confidence::AstBacked,
        ));
    }
    if module.contains("Hyprland") || module.ends_with(".Wayland") || module.contains("Wlr") {
        outcome.capabilities.push(occurrence(
            Capability::CompositorControl,
            Language::Qml,
            line,
            &format!("import {module}"),
        ));
    }
}

/// Identifier/property tokens that mark priority or context surfaces.
#[cfg(feature = "qml-parser")]
fn apply_surface_token(
    source: &str,
    node: tree_sitter::Node,
    outcome: &mut FileOutcome,
    line: u32,
) {
    let _ = node;
    let text = &source[node.start_byte()..node.end_byte()];
    match text {
        "WlSessionLock" | "WlSessionLockSurface" => {
            outcome.result_parts.push(parts(
                "oma.qml.session-lock",
                line,
                format!("session-lock-type:{text}"),
                Confidence::AstBacked,
            ));
        }
        "PamContext" => {
            outcome.result_parts.push(parts(
                "oma.qml.pam-authentication",
                line,
                "pam-context-type",
                Confidence::AstBacked,
            ));
        }
        _ => {}
    }
    let lower = text.to_ascii_lowercase();
    if lower.contains("clipboard") {
        outcome.capabilities.push(occurrence(
            Capability::ClipboardAccess,
            Language::Qml,
            line,
            text,
        ));
    } else if text.starts_with("Hyprland") || text.starts_with("Wlr") || lower == "hyprctl" {
        outcome.capabilities.push(occurrence(
            Capability::CompositorControl,
            Language::Qml,
            line,
            text,
        ));
    }
}

/// Length of a base64-shaped literal worth surfacing as an indicator.
fn encoded_literal_length(content: &str) -> Option<usize> {
    let length = content.len();
    if length < 64 {
        return None;
    }
    let mut letters = false;
    let mut digits = false;
    for byte in content.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' => letters = true,
            b'0'..=b'9' => digits = true,
            b'+' | b'/' | b'=' | b'_' | b'-' => {}
            _ => return None,
        }
    }
    (letters && digits).then_some(length)
}
fn find_word(haystack: &str, needle: &str) -> Option<usize> {
    let bytes = haystack.as_bytes();
    let mut start = 0usize;
    while let Some(position) = haystack[start..].find(needle) {
        let absolute = start + position;
        let before_ok = absolute == 0 || !bytes[absolute - 1].is_ascii_alphanumeric();
        let after = absolute + needle.len();
        // Needles ending in punctuation (`eval(`) are followed by identifier
        // characters by design; only word-tailed needles require a word end.
        let requires_word_end = needle
            .chars()
            .last()
            .is_some_and(|character| character.is_ascii_alphanumeric());
        let after_ok =
            !requires_word_end || after >= bytes.len() || !bytes[after].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return Some(absolute);
        }
        start = absolute + needle.len().max(1);
    }
    None
}

/// All quoted literals on one line joined with single spaces, so argv-style
/// sources like `"sh", "-c", "cmd"` reconstruct into scannable text.
fn join_line_literals(line: &str) -> String {
    line_literals(line).join(" ")
}

/// Quoted string literals that look like paths become reference candidates.
fn collect_quoted_references(line: &str, number: u32, references: &mut Vec<ReferenceCandidate>) {
    for literal in line_literals(line) {
        // Decode escapes so context candidates match runtime spelling.
        let decoded = decode_js_escapes(literal);
        if is_path_shaped(&decoded) {
            references.push(ReferenceCandidate {
                line: number,
                value: decoded,
                sink: None,
            });
        }
    }
}

/// Runtime value of the quoted literals inside one span, escapes decoded
/// once at extraction (H2 review).
fn span_sink_literals(span: &str) -> Vec<String> {
    line_literals(span)
        .into_iter()
        .map(decode_js_escapes)
        .collect()
}

/// Sink positions on one lexical line (H2). The AST path marks reference
/// candidates precisely at binding/call nodes; the lexical fallback marks
/// the quoted literals of the binding value or call-argument span — never
/// every literal on the line, so an unrelated literal sharing the line
/// cannot inherit the sink (H2 review). Multi-line constructs degrade to
/// context, a documented lexical limitation — no match never implies clean
/// behavior.
fn collect_lexical_sink_references(line: &str, code: &str, number: u32, outcome: &mut FileOutcome) {
    // Import statements: the first quoted literal is the module specifier.
    if code.split_whitespace().next() == Some("import") {
        if let Some(specifier) = line_literals(line).into_iter().next() {
            let decoded = decode_js_escapes(specifier);
            apply_directory_import(&decoded, number, outcome);
        }
        return;
    }
    // Qt load-sink calls: only the FIRST argument (the URL) of a call whose
    // receiver is the Qt GLOBAL. `backend.Qt.createComponent(...)` (a member
    // named Qt) is not the Qt API and must not match; `Qt . createComponent(`
    // with whitespace around the dot IS the same call and must match.
    for (method, sink) in [
        ("createComponent", SinkPosition::CreateComponent),
        ("include", SinkPosition::Include),
    ] {
        for open_paren in find_qt_global_calls(code, method) {
            if let Some((start, end)) = first_argument_span(line, open_paren) {
                for literal in span_sink_literals(&line[start..end]) {
                    record_sink_reference(&literal, sink, number, outcome);
                }
            }
        }
    }
    // Binding sinks: only the value span after the binding word.
    mark_binding_literals(
        line,
        code,
        "Loader",
        "source",
        SinkPosition::LoaderSource,
        number,
        outcome,
    );
    mark_binding_literals(
        line,
        code,
        "FileView",
        "path",
        SinkPosition::FileViewPath,
        number,
        outcome,
    );
}

/// Mark the quoted literals of each `<binding_word>: <value>` binding value
/// span that lies INSIDE a `<object_word> { … }` object's brace span, at
/// brace depth zero of that object's initializer.
///
/// The binding must be scoped to the matching object's braces, not merely
/// share a line with the object word: `Loader {} Image { source: "…" }` must
/// not treat `Image.source` as `Loader.source`. Nested child objects must
/// not inherit the outer sink either — `Loader { Image { source: "…" } }`
/// carries the nested type's own semantics, so only depth-zero bindings
/// participate (H2 review). When the object's braces do not close on the
/// same line (a multi-line object), the span is unresolved and the construct
/// degrades to context — a documented lexical limitation.
fn mark_binding_literals(
    line: &str,
    code: &str,
    object_word: &str,
    binding_word: &str,
    sink: SinkPosition,
    number: u32,
    outcome: &mut FileOutcome,
) {
    let mut search_from = 0usize;
    while let Some(relative) = find_word(&code[search_from..], object_word) {
        let word_end = search_from + relative + object_word.len();
        search_from = word_end;
        // The object declaration is `<object_word> {`; only whitespace may sit
        // between the word and its opening brace.
        let Some(brace_open) = object_brace_open(code, word_end) else {
            continue;
        };
        let Some((body_start, body_end)) = balanced_bracket_span(line, brace_open) else {
            continue; // multi-line object: degrade to context
        };
        let body_end = body_end.min(code.len());
        if body_start > body_end {
            continue;
        }
        // Only the depth-zero segments of the object body participate:
        // segments inside a nested `{ … }` belong to a child object with its
        // own type. Slicing at brace bytes is UTF-8 safe (braces are ASCII
        // and cannot occur inside a multi-byte character).
        let body = &code[body_start..body_end];
        let mut segments: Vec<(usize, &str)> = Vec::new();
        let mut depth = 0usize;
        let mut segment_start = 0usize;
        for (offset, byte) in body.bytes().enumerate() {
            match byte {
                b'{' => {
                    depth += 1;
                    if depth == 1 {
                        segments.push((segment_start, &body[segment_start..offset]));
                    }
                }
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        segment_start = offset + 1;
                    }
                }
                _ => {}
            }
        }
        if depth == 0 {
            segments.push((segment_start, &body[segment_start..]));
        }
        for (segment_offset, segment) in segments {
            let mut inner_from = 0usize;
            while let Some(rel) = find_word(&segment[inner_from..], binding_word) {
                let match_start = inner_from + rel;
                inner_from = match_start + binding_word.len();
                // Map the segment offset back to the line; `body` starts at
                // `body_start` and `code` is a prefix of `line`, so offsets
                // align.
                let property_word_end = body_start + segment_offset + inner_from;
                if let Some((start, end)) = binding_value_span(line, property_word_end) {
                    for literal in span_sink_literals(&line[start..end]) {
                        record_sink_reference(&literal, sink, number, outcome);
                    }
                }
            }
        }
    }
}

/// Byte index of the `{` that opens a `<object_word> {` object declaration,
/// i.e. the first non-whitespace byte after the object word must be `{`.
fn object_brace_open(code: &str, after_word: usize) -> Option<usize> {
    let bytes = code.as_bytes();
    let index = skip_ascii_ws(bytes, after_word);
    (bytes.get(index) == Some(&b'{')).then_some(index)
}

/// Advance past ASCII spaces and tabs.
fn skip_ascii_ws(bytes: &[u8], mut index: usize) -> usize {
    while index < bytes.len() && matches!(bytes[index], b' ' | b'\t') {
        index += 1;
    }
    index
}

/// Byte indices of the `(` opening each `Qt.<method>(` call whose receiver is
/// the Qt GLOBAL. Tolerates whitespace around the `.` and before the `(`, and
/// rejects a `Qt` that is itself a member/identifier part (e.g.
/// `backend.Qt.<method>`, `myQt.<method>`).
fn find_qt_global_calls(code: &str, method: &str) -> Vec<usize> {
    let bytes = code.as_bytes();
    let mut result = Vec::new();
    let mut from = 0usize;
    while let Some(relative) = find_word(&code[from..], "Qt") {
        let qt_start = from + relative;
        let qt_end = qt_start + 2;
        from = qt_end;
        // Receiver must be the Qt global, not a member or a longer identifier.
        // `find_word` already excludes an alphanumeric predecessor; also reject
        // a member-access dot and identifier-continuation bytes.
        if qt_start > 0 && matches!(bytes[qt_start - 1], b'.' | b'_' | b'$') {
            continue;
        }
        let mut index = skip_ascii_ws(bytes, qt_end);
        if bytes.get(index) != Some(&b'.') {
            continue;
        }
        index = skip_ascii_ws(bytes, index + 1);
        if !code[index..].starts_with(method) {
            continue;
        }
        let method_end = index + method.len();
        if bytes
            .get(method_end)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'$'))
        {
            continue; // method name is a prefix of a longer identifier
        }
        let paren = skip_ascii_ws(bytes, method_end);
        if bytes.get(paren) != Some(&b'(') {
            continue;
        }
        result.push(paren);
        from = paren + 1;
    }
    result
}

/// The span of the FIRST argument inside a `(` at `open_paren` — from just
/// after the paren to the first top-level comma or the matching close paren.
/// Only the first argument of a load sink is the URL (H2 review).
fn first_argument_span(line: &str, open_paren: usize) -> Option<(usize, usize)> {
    let (inner_start, close) = balanced_bracket_span(line, open_paren)?;
    let bytes = line.as_bytes();
    let mut index = inner_start;
    let mut depth = 0usize;
    let mut in_string: Option<u8> = None;
    while index < close {
        let byte = bytes[index];
        match in_string {
            Some(quote) => {
                if byte == b'\\' {
                    index += 2;
                    continue;
                }
                if byte == quote {
                    in_string = None;
                }
            }
            None => match byte {
                b'"' | b'\'' => in_string = Some(byte),
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth = depth.saturating_sub(1),
                b',' if depth == 0 => return Some((inner_start, index)),
                _ => {}
            },
        }
        index += 1;
    }
    Some((inner_start, close))
}

fn line_literals(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    let mut literals = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        let quote = bytes[index];
        if quote != b'"' && quote != b'\'' {
            index += 1;
            continue;
        }
        match line[index + 1..].find(quote as char) {
            Some(length) => {
                literals.push(&line[index + 1..index + 1 + length]);
                index += length + 2;
            }
            None => break,
        }
    }
    literals
}

/// The line with quoted-literal contents blanked so detector needles inside
/// string values never satisfy them. Quote characters become spaces to keep
/// offsets and word boundaries stable.
fn unquoted_text(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut blanked = bytes.to_vec();
    let mut index = 0usize;
    while index < bytes.len() {
        let quote = bytes[index];
        if quote != b'"' && quote != b'\'' {
            index += 1;
            continue;
        }
        blanked[index] = b' ';
        match line[index + 1..].find(quote as char) {
            Some(length) => {
                for slot in &mut blanked[index + 1..index + 1 + length] {
                    *slot = b' ';
                }
                blanked[index + 1 + length] = b' ';
                index += length + 2;
            }
            None => break,
        }
    }
    String::from_utf8_lossy(&blanked).into_owned()
}

/// One detector observation before path anchoring.
pub(in crate::detect) struct ResultParts {
    pub(in crate::detect) rule_id: &'static str,
    line: Option<u32>,
    pub(in crate::detect) semantic_value: String,
    confidence: Confidence,
}

// ---------------------------------------------------------------------------
// Public per-language entry points.
// ---------------------------------------------------------------------------

fn analyze_javascript_source(source: &str) -> FileOutcome {
    lexical_scan(source, Language::JavaScript)
}

/// Minimal high-signal lexical rules for bundled shell/Python payloads.
/// Coverage is always labelled `partial`; no match never implies clean.
/// What a heredoc-owning command does with the redirected body: a shell
/// interpreter in stdin-script mode executes it, a pure stdin-forwarding
/// filter passes it to whatever consumes its stdout downstream, and
/// everything else treats it as data. The command containing the redirect
/// runs from the last top-level separator before it; wrapper chains count
/// when their wrapped command qualifies (`sudo sh <<X` executes the body).
fn classify_heredoc_owner(tokens: &[ShellToken], op_index: usize) -> shell::source::HeredocOwner {
    use shell::source::HeredocOwner;

    let mut boundary = 0usize;
    let mut depth = 0i32;
    for (index, token) in tokens[..op_index].iter().enumerate() {
        match token.operator() {
            Some("(" | "{" | "((") => depth += 1,
            Some(")" | "}" | "))") => depth = (depth - 1).max(0),
            Some("|" | "|&" | ";" | "&&" | "||" | "&") if depth == 0 => boundary = index + 1,
            _ => {}
        }
    }
    let commands = segment_commands(&tokens[boundary..op_index]);
    if commands.iter().any(|command| {
        interpreter_family(command) == Some(InterpreterFamily::Shell)
            && matches!(interpreter_mode(command), InterpreterMode::StdinScript)
    }) {
        return HeredocOwner::ExecutesStdin;
    }
    // `tee` always re-emits its stdin on stdout; `cat` only when no file
    // operand replaces the redirected stdin.
    if commands.iter().any(|command| match command.head {
        "tee" => true,
        "cat" => command.args.iter().all(|arg| arg.starts_with('-')),
        _ => false,
    }) {
        return HeredocOwner::ForwardsStdin;
    }
    HeredocOwner::Data
}

/// What becomes of a forwarded heredoc body downstream: the tail is parsed
/// whole and walked stage by stage with the same stdin models the inline
/// pipeline analysis uses — a stage the body reaches either executes it as
/// code, forwards it to the next stage's stdin (a plain transformer with
/// unredirected stdout), or spends it as data. A directly spelled
/// stdin-script shell interpreter yields the byte offset just past its head
/// word, where the body attaches as its `-c` body; an `xargs` sink applies
/// its input model to the body text (quoting, word splitting, replacement);
/// every other executing sink — a static `-c` body consuming stdin
/// (`sh -c sh`), a compound group's interpreter, `source /dev/stdin`,
/// `eval "$(cat)"` — has no direct insertion point and reports
/// `ExecutedIndirectly` so the body's lines stay in the source. Data sinks
/// and downstream modes that never read stdin as a script (`sh -n`,
/// `sh -c body`, `sh script.sh`, `--help`) report `NotExecuted`.
fn forwarded_body_fate(tail: &str, body: &str) -> shell::source::ForwardedBodyFate {
    use shell::source::ForwardedBodyFate;
    let tokens = tokenize(tail);
    // The tail opens with the pipeline operator that carried the body out
    // of the heredoc owner (`| sh`); the body enters its first stage.
    let downstream = match tokens.split_first() {
        Some((first, rest)) if matches!(first.operator(), Some("|" | "|&")) => rest,
        _ => &tokens[..],
    };
    // Later list members (`| sh; rm …`, `| sh && more`) run with their own
    // stdin; only the first statement carries the body.
    let Some(&(statement, _)) = conditional_statements(downstream).first() else {
        return ForwardedBodyFate::NotExecuted;
    };
    let segments = pipeline_segments(statement);
    let mut budget = ShellBudget::new();
    for (stage, segment) in segments.iter().enumerate() {
        // The stage executes its inherited stdin as code: the sink.
        if segment_stdin_reaches_interpreter(segment, &mut budget) {
            return match sink_head(segment) {
                // The body attaches as the interpreter's `-c` body.
                Some((head_end, command))
                    if interpreter_family(&command) == Some(InterpreterFamily::Shell)
                        && matches!(interpreter_mode(&command), InterpreterMode::StdinScript) =>
                {
                    ForwardedBodyFate::AttachAt(head_end)
                }
                // xargs feeds its input to the wrapped command's argv: its
                // own option, replacement, and input-field model decides
                // which part of the body actually executes.
                Some((_, command)) if command.head == "xargs" => xargs_body_fate(&command, body),
                // Every other executing sink consumes the body verbatim as
                // shell source.
                Some(_) => ForwardedBodyFate::ExecutedIndirectly,
                None => ForwardedBodyFate::ExecutedIndirectly,
            };
        }
        // Anything else keeps the body alive only by passing it through to
        // the next stage; walking off the end leaves it unexecuted.
        if stage + 1 == segments.len() || !segment_stdout_preserved(segment, &mut budget) {
            return ForwardedBodyFate::NotExecuted;
        }
    }
    ForwardedBodyFate::NotExecuted
}

/// The sink stage's command chain, unwrapped through execution and
/// privilege wrappers the way `segment_commands` does, with the final
/// head's byte span and its command (`sudo -u root sh` yields `sh` after
/// its span). `None` when the chain never lands on a word.
fn sink_head(segment: &[ShellToken]) -> Option<(usize, ScriptCommand<'_>)> {
    let mut index = 0usize;
    skip_command_prefixes(segment, &mut index);
    let (head, head_end) = loop {
        let word = segment.get(index).and_then(ShellToken::word)?;
        let basename = command_basename(word);
        let span_end = segment[index].span()?.1;
        if !matches!(
            basename,
            "sudo" | "pkexec" | "doas" | "command" | "env" | "exec" | "time"
        ) {
            break (basename, span_end);
        }
        index += 1;
        // `env -S 'sh …'` word-splits its command string: no position in
        // it can carry a mechanical rewrite.
        if basename == "env" && env_split_string_command(segment, index).is_some() {
            return None;
        }
        if !skip_wrapper_options(basename, segment, &mut index) {
            return None; // options ran off the end: nothing is executed
        }
    };
    // The command's own arguments end at the first non-redirection
    // operator — a statement separator or group closer inside a compound
    // (`(sh; cat)` leaves `cat` to the group, not to `sh`).
    let args_end = segment[index + 1..]
        .iter()
        .position(|token| matches!(token, ShellToken::Operator(op) if !is_redirect_operator(op)))
        .map_or(segment.len(), |offset| index + 1 + offset);
    let arguments = command_arguments(&segment[..args_end], index + 1);
    Some((
        head_end,
        ScriptCommand {
            head,
            args: arguments.iter().map(|(value, _)| *value).collect(),
            arg_dynamic: arguments.iter().map(|(_, dynamic)| *dynamic).collect(),
        },
    ))
}

fn analyze_script_source(source: &str, kind: PayloadKind) -> FileOutcome {
    let mut outcome = FileOutcome {
        result_parts: Vec::new(),
        capabilities: Vec::new(),
        references: Vec::new(),
        parse_degraded: false,
        confidence: Confidence::LexicalFallback,
        limitations: Vec::new(),
    };
    let language = match kind {
        PayloadKind::Python => Language::Python,
        _ => Language::Shell,
    };
    let (download_rule, privilege_rule) = match kind {
        PayloadKind::Python => (PYTHON_DOWNLOAD_EXECUTE_RULE, PYTHON_PRIVILEGE_RULE),
        _ => (SCRIPT_DOWNLOAD_EXECUTE_RULE, SCRIPT_PRIVILEGE_RULE),
    };
    // Set when the recursion budget for untrusted shell text runs out on any
    // line: the analysis degrades and discloses the shortfall.
    let mut budget_exhausted = false;

    // Shell commands assemble into LOGICAL units across escaped newlines,
    // open pipelines, quotes, and groups (H3 review): `curl URL \` followed
    // by `| sh`, and the grammar continuation `curl URL |` followed by
    // `sh`, are one pipeline, not two fragments. Python keeps its
    // per-line scan; the classic one-liner chains its statements with `;`.
    let units: Vec<(u32, String)> = match kind {
        PayloadKind::Python => source
            .lines()
            .enumerate()
            .map(|(index, raw_line)| {
                (
                    index as u32 + 1,
                    strip_line_comment(raw_line, CommentStyle::PythonHash).to_owned(),
                )
            })
            .filter(|(_, line)| !line.is_empty())
            .collect(),
        _ => shell_logical_units(source, &classify_heredoc_owner, &forwarded_body_fate),
    };

    for (number, line) in units {
        let line = line.as_str();

        // Download-and-execute (Python) and reverse-shell wiring are
        // line-level on purpose: the classic Python one-liner chains its
        // statements with `;`, so socket creation, connect, and descriptor
        // handoff legally live in separate statements of one line. The
        // shell consumption families below are statement-scoped instead.
        let code = unquoted_text(line);
        // Command-position families run on a real shell tokenisation so a
        // token's runtime value (`c"ur"l` → `curl`, escapes honoured) is kept
        // separate from its source syntax: a quoted executable heads its
        // command while quoted prose (`echo 'curl …'`) stays an operand, and
        // a quoted or escaped separator never splits a statement.
        let tokens = tokenize(line);
        let python_fetch_to_exec = matches!(kind, PayloadKind::Python)
            && (code.contains("urlopen")
                || code.contains("requests.get")
                || code.contains("urllib"))
            && (code.contains("os.system")
                || code.contains("subprocess")
                || code.contains("exec(")
                || code.contains("eval("));
        if python_fetch_to_exec {
            outcome.result_parts.push(parts(
                download_rule,
                number,
                "download-execute",
                Confidence::LexicalFallback,
            ));
        }

        // Egress attribution (H3): a fetch tool in command position is
        // network access from the plugin regardless of what happens to the
        // response — the same executable-position contract as QML argv
        // (`echo curl …` records nothing; see script_body_fetches).
        // Quoted literals stay invisible — a logged string mentioning curl
        // is not egress — while a fetch inside a live command substitution
        // (`payload="$(curl …)"`) is. The budget bounds the substitution and
        // group recursion over untrusted text; each traversal of the line
        // (egress here, consumption families below) owns its own, so nested
        // levels charge depth once per walk.
        let mut budget = ShellBudget::new();
        if tokens_fetch_egress(&tokens, &mut budget) {
            outcome.capabilities.push(occurrence(
                Capability::NetworkAccess,
                language,
                number,
                line.trim(),
            ));
        }
        if budget.exhausted() {
            budget_exhausted = true;
        }

        // Privilege escalation: an actual passwordless grant or a sudoers
        // WRITE. Read-only inspection (`grep NOPASSWD`, `cat`) and bare
        // sudo/pkexec invocation stay capability-level, matching the rule
        // summary's meaning. Both grant predicates require a real write
        // context — a sudoers mention alone is not a grant.
        let write_indicator = line.contains(">")
            || line.contains(">>")
            || line.contains("tee ")
            || line.contains("visudo")
            || line.contains("sed -i")
            || line.contains("chattr")
            || line.contains(".write(");
        // Read-only inspection of sudoers policy is not a grant.
        let first_word = line
            .split_whitespace()
            .next()
            .unwrap_or("")
            .rsplit('/')
            .next()
            .unwrap_or("");
        let readonly_inspection = matches!(
            first_word,
            "grep" | "cat" | "less" | "head" | "tail" | "stat" | "journalctl"
        );
        let grant_write_context = write_indicator && !readonly_inspection;
        let sudoers_write = line.contains("sudoers") && grant_write_context;
        let nopasswd_grant = line.contains("NOPASSWD") && grant_write_context;
        if nopasswd_grant || sudoers_write {
            outcome.result_parts.push(parts(
                privilege_rule,
                number,
                if nopasswd_grant {
                    "passwordless-root"
                } else {
                    "sudoers-write"
                },
                Confidence::LexicalFallback,
            ));
        }
        if ["sudo ", "pkexec ", "doas "]
            .iter()
            .any(|token| line.contains(token))
        {
            outcome.capabilities.push(occurrence(
                Capability::ProcessExecution,
                language,
                number,
                line.trim(),
            ));
        }
        if find_word(line, "systemctl").is_some()
            || find_word(line, "systemd-run").is_some()
            || find_word(line, "rc-service").is_some()
        {
            outcome.capabilities.push(occurrence(
                Capability::PersistenceScheduling,
                language,
                number,
                line.trim(),
            ));
        }
        if find_word(line, "pacman").is_some()
            || find_word(line, "paru").is_some()
            || find_word(line, "yay").is_some()
            || find_word(line, "apt-get").is_some()
            || find_word(line, "dnf ").is_some()
        {
            outcome.capabilities.push(occurrence(
                Capability::ProcessExecution,
                language,
                number,
                line.trim(),
            ));
        }

        // Reverse shell (H3, Python): a connected socket whose descriptor
        // reaches a process. Socket and dup2 words are independent — the
        // wiring must be explicit (see python_reverse_shell); multi-line
        // wiring is the H4 dataflow slice.
        if matches!(kind, PayloadKind::Python) {
            if python_reverse_shell(&code) {
                outcome.result_parts.push(parts(
                    PYTHON_REVERSE_SHELL_RULE,
                    number,
                    "reverse-shell",
                    Confidence::LexicalFallback,
                ));
            }
        } else {
            // Shell consumption families are statement- AND command-scoped
            // (H3 review): a fetcher, decoder, or chmod binds only to
            // consumption, targets, and paths inside its OWN statement and
            // in its OWN command position, so `eval "$(date)"; curl …`,
            // `echo chmod 777 /tmp/not-executed`, and `echo base64 -d | sh`
            // stay silent. Compound groups run their interiors as their own
            // statement list and as pipeline producers/consumers, so the
            // families recurse into them too.
            let mut found = Vec::new();
            let mut budget = ShellBudget::new();
            shell_consumption_findings(&tokens, number, download_rule, &mut found, &mut budget);
            if budget.exhausted() {
                budget_exhausted = true;
            }
            outcome.result_parts.extend(found);
        }
    }

    if budget_exhausted {
        disclose_budget_limitation(&mut outcome);
    }

    outcome
}

/// Record the analysis-budget coverage limitation once per file.
fn disclose_budget_limitation(outcome: &mut FileOutcome) {
    let limitation = "shell-analysis-budget-exhausted";
    if !outcome
        .limitations
        .iter()
        .any(|existing| existing == limitation)
    {
        outcome.limitations.push(limitation.to_owned());
    }
}

/// Plugin manifests feed context-level results and capability context that
/// influence review priority without ever asserting malicious behavior.
fn apply_manifest_context(content: &[u8], relative_path: &str, artifacts: &mut AnalysisArtifacts) {
    let value = match serde_json::from_slice::<serde_json::Value>(content) {
        Ok(value) => value,
        Err(_) => {
            artifacts
                .limitations
                .push(format!("manifest-context-unreadable:{relative_path}"));
            return;
        }
    };
    // Both the installed layout (`plugins: [...]`) and single-plugin trees
    // (`kinds` at top level or under one plugin object) are accepted.
    let mut kinds_lists: Vec<serde_json::Value> = Vec::new();
    if let Some(plugins) = value.get("plugins").and_then(serde_json::Value::as_array) {
        for plugin in plugins {
            if let Some(kinds) = plugin.get("kinds") {
                kinds_lists.push(kinds.clone());
            }
        }
    } else if let Some(kinds) = value.get("kinds") {
        kinds_lists.push(kinds.clone());
    }
    let mut seen_bar = false;
    let mut seen_service = false;
    for kinds_value in &kinds_lists {
        let Some(kinds) = kinds_value.as_array() else {
            continue;
        };
        for kind in kinds.iter().filter_map(serde_json::Value::as_str) {
            match kind {
                "bar" => seen_bar = true,
                "service" => seen_service = true,
                _ => {}
            }
        }
    }
    if !seen_bar && !seen_service {
        return;
    }
    if seen_bar
        && let Ok(result) = NormalizedResult::new(
            REPLACES_BAR_RULE,
            relative_path,
            None,
            None,
            "replaces-bar-context",
            None,
        )
    {
        artifacts.results.push(result);
    }
    if seen_service {
        let mut occurrence = occurrence(
            Capability::PersistenceScheduling,
            Language::Context,
            1,
            "headless-service-kind",
        );
        occurrence.relative_path = relative_path.to_owned();
        artifacts.capabilities.push(occurrence);
    }
}

#[cfg(feature = "qml-parser")]
fn analyze_qml_source(source: &str) -> FileOutcome {
    match crate::qml::parse_qml(source.as_bytes()) {
        Some(tree) => ast_scan_qml(source, &tree),
        None => lexical_scan(source, Language::Qml),
    }
}

#[cfg(not(feature = "qml-parser"))]
fn analyze_qml_source(source: &str) -> FileOutcome {
    lexical_scan(source, Language::Qml)
}

// ---------------------------------------------------------------------------
// AST-backed QML analysis (qml-parser feature).
// ---------------------------------------------------------------------------

#[cfg(feature = "qml-parser")]
mod ast {
    use super::*;

    /// Classified value of a binding or call argument.
    enum Value {
        Static(String),
        Dynamic(&'static str),
    }

    pub(super) fn scan(source: &str, tree: &tree_sitter::Tree) -> FileOutcome {
        let mut outcome = FileOutcome {
            result_parts: Vec::new(),
            capabilities: Vec::new(),
            references: Vec::new(),
            parse_degraded: tree.root_node().has_error(),
            confidence: Confidence::AstBacked,
            limitations: Vec::new(),
        };
        let mut flags = LexFlags {
            detached_any: None,
            network: None,
        };

        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            let kind = node.kind();
            match kind {
                "ui_import" => {
                    let module = import_module_text(source, node);
                    if !module.is_empty() {
                        apply_import_surface(&module, number_of(node), &mut outcome);
                    }
                    // Directory imports spell the module as a string:
                    // `import "./dialogs" as D`.
                    let mut import_cursor = node.walk();
                    let import_children: Vec<tree_sitter::Node> =
                        node.children(&mut import_cursor).collect();
                    for child in import_children {
                        if child.kind() == "string" {
                            let specifier = string_literal_content(source, child);
                            if !specifier.is_empty() {
                                apply_directory_import(&specifier, number_of(node), &mut outcome);
                            }
                        }
                    }
                }
                "ui_object_definition" => {
                    handle_object_definition(source, node, &mut outcome);
                    // Loader { source: <expr> }: computed sources are
                    // dynamic reference sinks. Qualified spellings
                    // (`QQ.Loader`) resolve through the terminal type
                    // segment (H2 review).
                    let is_loader = object_type_node(source, node).is_some_and(|type_node| {
                        terminal_segment(node_text(source, type_node)) == "Loader"
                    });
                    if is_loader && binding_value_named(source, node, "source").is_some() {
                        let binding = binding_value_named(source, node, "source").unwrap();
                        {
                            match classify_value(source, binding) {
                                Value::Static(text) => {
                                    record_sink_reference(
                                        &text,
                                        SinkPosition::LoaderSource,
                                        number_of(binding),
                                        &mut outcome,
                                    );
                                }
                                Value::Dynamic(_) => {
                                    outcome.result_parts.push(parts(
                                        DYNAMIC_REFERENCE_RULE,
                                        number_of(binding),
                                        format!(
                                            "dynamic-reference-sink:Loader.source:{}",
                                            node_text(source, unwrap_expression_statement(binding))
                                                .chars()
                                                .take(120)
                                                .collect::<String>()
                                        ),
                                        Confidence::AstBacked,
                                    ));
                                }
                            }
                        }
                    }
                }
                "call_expression" => {
                    handle_call_expression(source, node, &mut outcome, &mut flags);
                }
                "identifier" | "property_identifier" => {
                    let token_line = ast::number_of(node);
                    apply_surface_token(source, node, &mut outcome, token_line);
                }
                "string" => {
                    let content = string_literal_content(source, node);
                    if let Some(length) = encoded_literal_length(&content) {
                        outcome.result_parts.push(parts(
                            OBFUSCATION_RULE,
                            number_of(node),
                            format!("encoded-literal:{length}"),
                            Confidence::AstBacked,
                        ));
                    }
                }
                "new_expression" => {
                    if node.child_count() >= 2
                        && node_text(source, node.child(1).unwrap()) == "Function"
                    {
                        // Runtime code construction via the Function
                        // constructor is equivalent to eval for review
                        // purposes.
                        outcome.result_parts.push(parts(
                            DYNAMIC_CODE_RULE,
                            number_of(node),
                            "dynamic-code-construction:new Function",
                            Confidence::AstBacked,
                        ));
                        outcome.capabilities.push(occurrence(
                            Capability::DynamicCodeExecution,
                            Language::Qml,
                            number_of(node),
                            "new Function",
                        ));
                    }
                    if node.child_count() >= 2
                        && node_text(source, node.child(1).unwrap()) == "XMLHttpRequest"
                    {
                        flags.network.get_or_insert(number_of(node));
                        outcome.capabilities.push(occurrence(
                            Capability::NetworkAccess,
                            Language::Qml,
                            number_of(node),
                            "new XMLHttpRequest",
                        ));
                    } else if node.child_count() >= 2
                        && node_text(source, node.child(1).unwrap()) == "WebSocket"
                    {
                        flags.network.get_or_insert(number_of(node));
                        outcome.capabilities.push(occurrence(
                            Capability::NetworkAccess,
                            Language::Qml,
                            number_of(node),
                            "new WebSocket",
                        ));
                    }
                }
                _ => {}
            }
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
        }

        // Literal references: path-shaped strings in reference positions.
        collect_ast_references(source, tree, &mut outcome.references);

        outcome
    }

    pub(super) fn number_of(node: tree_sitter::Node) -> u32 {
        node.start_position().row as u32 + 1
    }

    fn node_text<'a>(source: &'a str, node: tree_sitter::Node) -> &'a str {
        &source[node.start_byte()..node.end_byte()]
    }

    /// The object-definition type node: an identifier or a
    /// nested_identifier for qualified spellings (`QtQuick as QQ` ->
    /// `QQ.Loader`), which the grammar permits (H2 review).
    fn object_type_node<'a>(
        source: &'a str,
        object: tree_sitter::Node<'a>,
    ) -> Option<tree_sitter::Node<'a>> {
        let _ = source;
        let mut cursor = object.walk();
        object
            .children(&mut cursor)
            .find(|child| matches!(child.kind(), "identifier" | "nested_identifier"))
    }

    /// Terminal segment of a (possibly dotted) type spelling: `QQ.Loader`
    /// and `Loader` both resolve to the `Loader` sink type.
    fn terminal_segment(type_text: &str) -> &str {
        type_text.rsplit('.').next().unwrap_or(type_text)
    }

    fn handle_object_definition(source: &str, node: tree_sitter::Node, outcome: &mut FileOutcome) {
        let Some(type_node) = object_type_node(source, node) else {
            return;
        };
        let type_name = terminal_segment(node_text(source, type_node));

        match type_name {
            "Process" => {
                outcome.capabilities.push(occurrence(
                    Capability::ProcessExecution,
                    Language::Qml,
                    number_of(type_node),
                    type_name,
                ));
                if let Some(binding_value) = binding_value(source, node, "command") {
                    evaluate_execution_value(source, binding_value, SinkKind::Process, outcome);
                    // Command argv is a verified sink position (H2): literal
                    // arguments outside the tree surface typed rejections;
                    // in-tree literals resolve as invocation edges.
                    handle_reference_sink_value(
                        source,
                        binding_value,
                        SinkPosition::ProcessCommand,
                        outcome,
                    );
                }
            }
            "FileView" => {
                outcome.capabilities.push(occurrence(
                    Capability::FilesystemAccess,
                    Language::Qml,
                    number_of(type_node),
                    type_name,
                ));
                if let Some(path_value) = binding_value(source, node, "path") {
                    let unwrapped = unwrap_expression_statement(path_value);
                    match classify_value(source, path_value) {
                        Value::Static(text) => {
                            // Persistence locations: writing toward autostart
                            // or user-systemd units is a context finding.
                            if text.contains("autostart")
                                || text.contains("systemd/user")
                                || text.contains(".config/systemd")
                            {
                                outcome.result_parts.push(parts(
                                    PERSISTENCE_RULE,
                                    number_of(unwrapped),
                                    format!("persistence-location:{text}"),
                                    Confidence::AstBacked,
                                ));
                            }
                            // FileView.path is a verified sink position (H2):
                            // the path participates in reference resolution
                            // with typed rejections, never load-sink findings.
                            handle_reference_sink_value(
                                source,
                                path_value,
                                SinkPosition::FileViewPath,
                                outcome,
                            );
                        }
                        Value::Dynamic(_) => {
                            // Computed reference sink: explicit low-confidence
                            // finding per the S3 exit criterion.
                            outcome.result_parts.push(parts(
                                DYNAMIC_REFERENCE_RULE,
                                number_of(unwrapped),
                                format!(
                                    "dynamic-reference-sink:FileView.path:{}",
                                    node_text(source, unwrapped)
                                        .chars()
                                        .take(120)
                                        .collect::<String>()
                                ),
                                Confidence::AstBacked,
                            ));
                        }
                    }
                }
            }
            "Timer" => {
                outcome.capabilities.push(occurrence(
                    Capability::PersistenceScheduling,
                    Language::Qml,
                    number_of(type_node),
                    type_name,
                ));
            }
            _ => {}
        }
    }

    /// The value expression of `property: value` inside one object
    /// definition. Bindings sit one level down, in the initializer.
    fn binding_value<'a>(
        source: &'a str,
        object: tree_sitter::Node<'a>,
        property: &str,
    ) -> Option<tree_sitter::Node<'a>> {
        binding_value_named(source, object, property)
    }

    fn binding_value_named<'a>(
        source: &'a str,
        object: tree_sitter::Node<'a>,
        property: &str,
    ) -> Option<tree_sitter::Node<'a>> {
        let mut outer = object.walk();
        let initializer = object
            .children(&mut outer)
            .find(|child| child.kind() == "ui_object_initializer")?;
        let mut cursor = initializer.walk();
        for child in initializer.children(&mut cursor) {
            if child.kind() != "ui_binding" {
                continue;
            }
            let mut binding_cursor = child.walk();
            let parts: Vec<tree_sitter::Node> = child.children(&mut binding_cursor).collect();
            let Some(name_node) = parts.first() else {
                continue;
            };
            if node_text(source, *name_node) != property {
                continue;
            }
            // Skip the ':' and take the expression after it.
            return parts.iter().rev().find(|part| part.kind() != ":").copied();
        }
        None
    }

    /// Process argv elements at runtime-value granularity (H3 review):
    /// static-shaped elements contribute their text; computed elements
    /// contribute nothing — an unknown position is never guessed at, which
    /// leaves dynamic-head egress to the H4 dataflow slice.
    fn argv_elements(source: &str, value: tree_sitter::Node) -> Vec<String> {
        let inner = unwrap_expression_statement(value);
        match inner.kind() {
            "array" => {
                let mut cursor = inner.walk();
                inner
                    .children(&mut cursor)
                    .filter(|child| child.is_named())
                    .map(|child| match classify_value(source, child) {
                        Value::Static(text) => text,
                        Value::Dynamic(_) => String::new(),
                    })
                    .collect()
            }
            _ => match classify_value(source, inner) {
                Value::Static(text) => text.split_whitespace().map(str::to_owned).collect(),
                Value::Dynamic(_) => Vec::new(),
            },
        }
    }

    fn classify_value(source: &str, node: tree_sitter::Node) -> Value {
        let inner = unwrap_expression_statement(node);
        match inner.kind() {
            "string" => Value::Static(string_literal_content(source, inner)),
            "template_string" => {
                let mut cursor = inner.walk();
                let has_substitution = inner
                    .children(&mut cursor)
                    .any(|child| child.kind() == "template_substitution");
                if has_substitution {
                    Value::Dynamic("dynamic-command")
                } else {
                    Value::Static(template_plain_content(source, inner))
                }
            }
            "array" => {
                let mut elements = Vec::new();
                let mut cursor = inner.walk();
                for child in inner.children(&mut cursor) {
                    if matches!(child.kind(), "[" | "]" | "," | ";" | "\"" | "'") {
                        continue;
                    }
                    match classify_value(source, child) {
                        Value::Static(text) => elements.push(text),
                        Value::Dynamic(reason) => return Value::Dynamic(reason),
                    }
                }
                Value::Static(elements.join(" "))
            }
            _ => {
                // Provenance marker: does this expression read network
                // response data? Checked over the raw slice so any nesting
                // depth counts.
                let text = node_text(source, inner);
                if text.contains("responseText")
                    || text.contains(".response")
                    || text.contains(".text(")
                {
                    Value::Dynamic("network-response-executed")
                } else {
                    Value::Dynamic("dynamic-command")
                }
            }
        }
    }

    fn unwrap_expression_statement<'a>(node: tree_sitter::Node<'a>) -> tree_sitter::Node<'a> {
        let mut current = node;
        loop {
            let mut cursor = current.walk();
            let named: Vec<tree_sitter::Node> = current
                .children(&mut cursor)
                .filter(|child| child.is_named())
                .collect();
            match (current.kind(), named.as_slice()) {
                ("expression_statement" | "parenthesized_expression", [single]) => {
                    current = *single
                }
                _ => return current,
            }
        }
    }

    /// Runtime content of a string literal: fragments verbatim plus each
    /// escape_sequence node decoded individually, so classification sees
    /// what the engine evaluates (`"\x68ttps://…"` is an `https://` load,
    /// H2 review) without re-decoding literal backslashes a `\\` escape
    /// produced.
    fn string_literal_content(source: &str, string_node: tree_sitter::Node) -> String {
        let mut content = String::new();
        let mut cursor = string_node.walk();
        for child in string_node.children(&mut cursor) {
            match child.kind() {
                "string_fragment" => content.push_str(node_text(source, child)),
                "escape_sequence" => content.push_str(&decode_js_escapes(node_text(source, child))),
                _ => {}
            }
        }
        content
    }

    fn template_plain_content(source: &str, template: tree_sitter::Node) -> String {
        let mut content = String::new();
        let mut cursor = template.walk();
        for child in template.children(&mut cursor) {
            match child.kind() {
                "string_fragment" => content.push_str(node_text(source, child)),
                "escape_sequence" => content.push_str(&decode_js_escapes(node_text(source, child))),
                _ => {}
            }
        }
        content
    }

    /// Unwraps transparent `(…)` wrappers so a parenthesized receiver such as
    /// `(Qt).createComponent(...)` verifies as the same Qt-global call as
    /// `Qt.createComponent(...)`.
    fn unwrap_transparent_parens(mut node: tree_sitter::Node) -> tree_sitter::Node {
        while node.kind() == "parenthesized_expression" {
            match node.named_child(0) {
                Some(inner) => node = inner,
                None => break,
            }
        }
        node
    }

    fn handle_call_expression(
        source: &str,
        node: tree_sitter::Node,
        outcome: &mut FileOutcome,
        flags: &mut LexFlags,
    ) {
        let mut cursor = node.walk();
        let children: Vec<tree_sitter::Node> = node.children(&mut cursor).collect();
        let Some(callee) = children.first().copied() else {
            return;
        };
        let callee_name = match callee.kind() {
            "member_expression" => {
                let mut member_cursor = callee.walk();
                callee
                    .children(&mut member_cursor)
                    .last()
                    .map(|last| node_text(source, last).to_owned())
                    .unwrap_or_default()
            }
            "identifier" => node_text(source, callee).to_owned(),
            _ => String::new(),
        };
        // Qt-receiver verification (H2 review): `createComponent` and
        // `include` are Qt global APIs; a user-defined
        // `backend.createComponent(...)` must not carry Qt-specific rules.
        // `Qt.some.createComponent(...)` also fails verification (its
        // receiver is a member expression, not the Qt global).
        let qt_receiver = callee.kind() == "member_expression" && {
            let mut receiver_cursor = callee.walk();
            callee
                .children(&mut receiver_cursor)
                .next()
                .map(unwrap_transparent_parens)
                .is_some_and(|receiver| {
                    receiver.kind() == "identifier" && node_text(source, receiver) == "Qt"
                })
        };
        let is_qt_sink =
            qt_receiver && matches!(callee_name.as_str(), "createComponent" | "include");
        if matches!(callee_name.as_str(), "eval" | "createQmlObject" | "atob") || is_qt_sink {
            outcome.result_parts.push(parts(
                DYNAMIC_CODE_RULE,
                number_of(node),
                format!("dynamic-code-construction:{callee_name}"),
                Confidence::AstBacked,
            ));
            outcome.capabilities.push(occurrence(
                Capability::DynamicCodeExecution,
                Language::Qml,
                number_of(node),
                &callee_name,
            ));
        }
        // Qt.createComponent / Qt.include are also reference sinks (H2):
        // their first argument decides whether remote or out-of-tree content
        // is loaded, or which in-tree file the invocation edge points at.
        if is_qt_sink {
            let sink = if callee_name == "createComponent" {
                SinkPosition::CreateComponent
            } else {
                SinkPosition::Include
            };
            if let Some(arguments) = children.iter().find(|child| child.kind() == "arguments") {
                let mut args_cursor = arguments.walk();
                let args: Vec<tree_sitter::Node> = arguments
                    .children(&mut args_cursor)
                    .filter(|child| child.is_named())
                    .collect();
                if let Some(first) = args.first().copied() {
                    handle_reference_sink_value(source, first, sink, outcome);
                }
            }
        }
        let is_detached = match callee.kind() {
            "member_expression" => {
                let mut member_cursor = callee.walk();
                callee
                    .children(&mut member_cursor)
                    .last()
                    .map(|last| node_text(source, last) == "execDetached")
                    .unwrap_or(false)
            }
            "identifier" => node_text(source, callee) == "execDetached",
            _ => false,
        };
        if !is_detached {
            // fetch(...) / X.fetch(...): network capability.
            let fetch_call = match callee.kind() {
                "identifier" => node_text(source, callee) == "fetch",
                "member_expression" => {
                    let mut member_cursor = callee.walk();
                    callee
                        .children(&mut member_cursor)
                        .last()
                        .map(|last| node_text(source, last) == "fetch")
                        .unwrap_or(false)
                }
                _ => false,
            };
            if fetch_call {
                flags.network.get_or_insert(number_of(node));
                outcome.capabilities.push(occurrence(
                    Capability::NetworkAccess,
                    Language::Qml,
                    number_of(node),
                    "fetch()",
                ));
            }
            return;
        }
        flags.detached_any.get_or_insert(number_of(node));
        outcome.capabilities.push(occurrence(
            Capability::DetachedProcessExecution,
            Language::Qml,
            number_of(node),
            node_text(source, node)
                .chars()
                .take(200)
                .collect::<String>()
                .as_str(),
        ));
        // First argument after the callee's arguments '(' — reuse classification.
        if let Some(arguments) = children.iter().find(|child| child.kind() == "arguments") {
            let mut args_cursor = arguments.walk();
            let args: Vec<tree_sitter::Node> = arguments
                .children(&mut args_cursor)
                .filter(|child| child.is_named())
                .collect();
            if let Some(first) = args.first().copied() {
                evaluate_execution_value(source, first, SinkKind::DetachedExecution, outcome);
                // The executed path is also a reference sink (H2): a literal
                // outside the tree is a typed rejection, a literal inside it
                // resolves as an invocation edge.
                handle_reference_sink_value(source, first, SinkPosition::ExecDetached, outcome);
            }
        }
    }

    fn evaluate_execution_value(
        source: &str,
        value_node: tree_sitter::Node,
        kind: SinkKind,
        outcome: &mut FileOutcome,
    ) {
        let number = number_of(value_node);
        let rule_id = match kind {
            SinkKind::Process => PROCESS_RULE,
            SinkKind::DetachedExecution => DETACHED_RULE,
        };
        // Egress attribution (H3 review): only the executable position
        // attributes egress. See argv_head_fetches.
        if kind == SinkKind::Process {
            let elements = argv_elements(source, value_node);
            let borrowed: Vec<&str> = elements.iter().map(String::as_str).collect();
            let head = argv_head_fetches(&borrowed);
            if head.fetches {
                outcome.capabilities.push(occurrence(
                    Capability::NetworkAccess,
                    Language::Qml,
                    number,
                    "process-argv-fetch-tool",
                ));
            }
            if head.exhausted {
                disclose_budget_limitation(outcome);
            }
        }
        match classify_value(source, value_node) {
            Value::Static(text) => {
                if let Some(shell_offset) = find_shell_interpreter(&text) {
                    outcome.result_parts.push(parts(
                        rule_id,
                        number,
                        format!(
                            "shell-interpreter-command:{}",
                            text.chars()
                                .skip(shell_offset)
                                .take(400)
                                .collect::<String>()
                        ),
                        Confidence::AstBacked,
                    ));
                }
            }
            Value::Dynamic(reason) => {
                let _ = kind;
                // A dynamic argument is only a finding when its visible
                // provenance is network response data; otherwise it stays a
                // capability observation (rule contract).
                if reason == "network-response-executed" {
                    outcome.result_parts.push(parts(
                        rule_id,
                        number,
                        reason,
                        Confidence::AstBacked,
                    ));
                }
            }
        }
    }

    /// Route a sink binding/call argument into reference handling (H2). Only
    /// static-shaped values participate: string literals, substitution-free
    /// template strings, and arrays of those. Fragments of computed
    /// expressions are not resolvable references and would misclassify, so
    /// they stay capability/finding material for the dataflow slice.
    fn handle_reference_sink_value(
        source: &str,
        value: tree_sitter::Node,
        sink: SinkPosition,
        outcome: &mut FileOutcome,
    ) {
        let inner = unwrap_expression_statement(value);
        match inner.kind() {
            "string" => record_sink_reference(
                &string_literal_content(source, inner),
                sink,
                number_of(inner),
                outcome,
            ),
            "template_string" => {
                let mut cursor = inner.walk();
                let substituted = inner
                    .children(&mut cursor)
                    .any(|child| child.kind() == "template_substitution");
                if !substituted {
                    record_sink_reference(
                        &template_plain_content(source, inner),
                        sink,
                        number_of(inner),
                        outcome,
                    );
                }
            }
            "array" => {
                let mut cursor = inner.walk();
                let children: Vec<tree_sitter::Node> = inner
                    .children(&mut cursor)
                    .filter(|child| child.is_named())
                    .collect();
                for child in children {
                    handle_reference_sink_value(source, child, sink, outcome);
                }
            }
            _ => {}
        }
    }

    fn collect_ast_references(
        source: &str,
        tree: &tree_sitter::Tree,
        references: &mut Vec<ReferenceCandidate>,
    ) {
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            let text = match node.kind() {
                "string" => string_literal_content(source, node),
                "template_string" => template_plain_content(source, node),
                _ => String::new(),
            };
            if is_path_shaped(&text) {
                references.push(ReferenceCandidate {
                    line: number_of(node),
                    value: text,
                    sink: None,
                });
            }
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
        }
    }
}

#[cfg(feature = "qml-parser")]
fn ast_scan_qml(source: &str, tree: &tree_sitter::Tree) -> FileOutcome {
    ast::scan(source, tree)
}

#[cfg(test)]
mod tests;
