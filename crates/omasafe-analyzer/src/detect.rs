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

mod model;
mod qml;
mod references;
mod script;
mod shell;

use std::collections::{BTreeMap, BTreeSet};

use omasafe_core::bounds::{MAX_EVIDENCE_BYTES_PER_RESULT, MAX_FILE_BYTES, MAX_SINK_REJECTIONS};
use omasafe_report::analysis::{
    CapabilityOccurrence, InvocationEdge, ParserMetadata, RenderedFinding,
};

use crate::TimeBudget;
use crate::fingerprint::{Confidence, NormalizedResult};
use crate::payload::{CoverageState, PayloadEntry, PayloadInventory, PayloadKind};
use crate::rules::{Capability, Language, Severity, rule};

// Re-exported: the shell detector modules and the test tree consume the
// model surface through the facade namespace.
pub(in crate::detect) use model::*;
// Names the behavior test tree reads through the facade glob; compiled
// only under test, where they are used.
#[cfg(test)]
pub(in crate::detect) use qml::strings::decode_js_escapes;
#[cfg(test)]
pub(in crate::detect) use script::{classify_heredoc_owner, forwarded_body_fate};
#[cfg(test)]
pub(in crate::detect) use shell::command::segment_commands;
#[cfg(test)]
pub(in crate::detect) use shell::lexer::tokenize;
#[cfg(test)]
pub(in crate::detect) use shell::source::shell_logical_units;

use crate::detect::references::{SinkPosition, rejection_reason, resolve_reference};

use qml::{analyze_javascript_source, analyze_qml_source};
use script::analyze_script_source;

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

        // H5 context surfaces are deliberately language-neutral.  They run
        // after the parser/lexical frontend so comments are removed once and
        // all source languages disclose the same intent vocabulary.
        apply_h5_context_observations(&source, &entry_kind, &mut outcome);
        // H6 user-data surfaces use a bounded, line-oriented correlation pass.
        // It records capabilities freely, but only emits findings when a
        // sensitive read is connected to an egress or a concrete background
        // trigger on the same bounded path.
        apply_h6_user_data_observations(&source, &entry_kind, &mut outcome);

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
                || !outcome.limitations.is_empty()
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

    // Native executable payloads have a three-tier reachability contract:
    // unreferenced files are inventory capability context, while a literal
    // invocation edge makes the binary a Medium finding.  Remote-download
    // and digest-approval provenance remains a separate control surface and
    // is called out in the catalog guidance rather than guessed here.
    for index in 0..inventory.entries.len() {
        let entry = inventory.entries[index].clone();
        if !is_native_executable(&entry.kind) {
            continue;
        }
        if entry.invocation_target {
            if let Ok(result) = NormalizedResult::new(
                BUNDLED_BINARY_RULE,
                &entry.relative_path,
                None,
                None,
                format!("bundled-binary:referenced:{}", entry.relative_path),
                None,
            ) {
                artifacts.results.push(result);
            }
        } else {
            let mut capability = occurrence(
                Capability::BundledBinary,
                Language::PayloadBinary,
                1,
                &format!("unreferenced-binary:{}", entry.relative_path),
            );
            capability.relative_path = entry.relative_path.clone();
            capability.line = None;
            capability.confidence = Some("inventory".to_owned());
            artifacts.capabilities.push(capability);
        }
        // The native-format inventory detector has now processed this entry;
        // Unsupported is reserved for payload kinds with no analyzer at all.
        inventory.entries[index].coverage_state = CoverageState::Analyzed;
    }

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

fn is_native_executable(kind: &PayloadKind) -> bool {
    matches!(
        kind,
        PayloadKind::ElfBinary | PayloadKind::MachOBinary | PayloadKind::PeBinary
    )
}

/// Detect H5's anti-OmaSafe intent indicators without pretending to provide
/// a sandbox.  Literal paths are required so ordinary filesystem capability
/// observations do not turn into tamper findings; comments and quoted IPC
/// documentation are excluded with the shared line helpers.
fn apply_h5_context_observations(source: &str, kind: &PayloadKind, outcome: &mut FileOutcome) {
    let language = match kind {
        PayloadKind::Qml => Language::Qml,
        PayloadKind::JavaScript => Language::JavaScript,
        PayloadKind::Shell => Language::Shell,
        PayloadKind::Python => Language::Python,
        _ => return,
    };
    const IPC_METHODS: [&str; 5] = [
        "setPluginEnabled",
        "setPluginDisabled",
        "rescanPlugins",
        "reloadPlugins",
        "restartPlugin",
    ];
    // H5 path/write evidence is correlated by this bounded lexical scope id.
    // A QML object gets a distinct id for every opening brace, so a path in
    // one object cannot pair with a write property in a sibling object.
    let mut next_scope_id = 1usize;
    let mut scope_stack = vec![0usize];
    let mut state_observations: BTreeMap<usize, (Option<u32>, Option<u32>, bool)> = BTreeMap::new();
    for (index, raw_line) in source.lines().enumerate() {
        let number = index as u32 + 1;
        let line = match kind {
            PayloadKind::Shell => script::strip_shell_comment(raw_line),
            PayloadKind::Python => strip_line_comment(raw_line, CommentStyle::PythonHash),
            _ => strip_line_comment(raw_line, CommentStyle::DoubleSlash),
        };
        if line.trim().is_empty() {
            continue;
        }
        let code = unquoted_text(line);
        let lower_code = code.to_ascii_lowercase();
        let open_braces = code.bytes().filter(|byte| *byte == b'{').count();
        let close_braces = code.bytes().filter(|byte| *byte == b'}').count();
        for _ in 0..open_braces {
            scope_stack.push(next_scope_id);
            next_scope_id += 1;
        }
        let scope_id = *scope_stack.last().unwrap_or(&0);
        for method in IPC_METHODS {
            if find_word(&code, method).is_some() {
                outcome.capabilities.push(occurrence(
                    Capability::ShellIpcInventory,
                    language,
                    number,
                    method,
                ));
            }
        }

        let lower = line.to_ascii_lowercase();
        let state_path = lower.contains(".local/state/omasafe");
        let plugin_path = lower.contains(".config/omarchy/plugins/");
        let write_intent = lower_code.contains("write")
            || lower_code.contains("writefile")
            || lower_code.contains("save")
            || lower_code.contains("remove")
            || lower_code.contains("rename")
            || lower_code.contains("rm ")
            || lower_code.contains("rmdir")
            || lower_code.contains("unlink")
            || lower_code.contains("mkdir")
            || lower_code.contains("touch ")
            || lower_code.contains("chmod ")
            || lower_code.contains("install ")
            || lower_code.contains("mv ")
            || lower_code.contains("cp ")
            || lower_code.contains(">>")
            || lower_code.contains('>');
        let qml_path_property = lower_code.contains("path")
            || lower_code.contains("readfile")
            || lower_code.contains("readtext");
        let state_path_evidence = state_path
            && (!matches!(kind, PayloadKind::Qml | PayloadKind::JavaScript)
                || qml_path_property
                || write_intent);
        if state_path_evidence {
            let observation = state_observations.entry(scope_id).or_default();
            observation.0 = Some(number);
            if write_intent {
                observation.1 = Some(number);
            }
        } else if write_intent
            && matches!(kind, PayloadKind::Qml | PayloadKind::JavaScript)
            && state_observations
                .get(&scope_id)
                .is_some_and(|observation| observation.0.is_some())
        {
            state_observations.entry(scope_id).or_default().1 = Some(number);
        }
        if let Some((path_line, write_line, emitted)) = state_observations.get_mut(&scope_id)
            && path_line.is_some()
            && write_line.is_some()
            && !*emitted
        {
            *emitted = true;
            outcome.result_parts.push(parts(
                OMASAFE_STATE_TAMPER_RULE,
                write_line.or(*path_line).unwrap_or(number),
                "omasafe-state-tamper:state-path-write",
                outcome.confidence,
            ));
        }
        let git_checkout = plugin_path && invokes_git(&code);
        if (plugin_path && write_intent) || git_checkout {
            let detail = if git_checkout {
                "omasafe-state-tamper:git-plugin-checkout"
            } else {
                "omasafe-state-tamper:plugin-checkout-write"
            };
            outcome.result_parts.push(parts(
                OMASAFE_STATE_TAMPER_RULE,
                number,
                detail,
                outcome.confidence,
            ));
        }

        for _ in 0..close_braces {
            if scope_stack.len() > 1 {
                scope_stack.pop();
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum H6Provenance {
    SensitivePath,
    SensitiveValue,
    Safe,
}

struct H6Assignment {
    name: String,
    scope_id: usize,
    provenance: H6Provenance,
}

/// H6 capability and escalation observations for user-data access, desktop
/// automation, screen capture, clipboard helpers, and persistence locations.
///
/// This is intentionally a small lexical/dataflow layer rather than a second
/// parser. Assignment state is scoped to the active brace path and retains
/// only the latest value for a name in a scope. A reassignment therefore
/// replaces old provenance instead of accumulating it for the rest of the
/// file. The assignment record cap is explicit and disclosed as partial
/// coverage if an adversarial source exhausts it.
fn apply_h6_user_data_observations(source: &str, kind: &PayloadKind, outcome: &mut FileOutcome) {
    let language = match kind {
        PayloadKind::Qml => Language::Qml,
        PayloadKind::JavaScript => Language::JavaScript,
        PayloadKind::Shell => Language::Shell,
        PayloadKind::Python => Language::Python,
        _ => return,
    };
    const SENSITIVE_PATHS: [&str; 15] = [
        ".ssh",
        ".gnupg",
        ".local/share/keyrings",
        "keyring",
        ".aws",
        ".config/gh",
        ".kube",
        "wallet",
        "metamask",
        ".config/google-chrome",
        ".config/chromium",
        ".mozilla",
        "login data",
        "cookies.sqlite",
        "/etc/shadow",
    ];
    const INPUT_TOOLS: [&str; 4] = ["ydotool", "wtype", "wlrctl", "hyprctl"];
    const CAPTURE_TOOLS: [&str; 4] = ["grim", "slurp", "wf-recorder", "hyprshot"];
    const CLIPBOARD_READ_TOOLS: [&str; 4] = ["wl-paste", "cliphist", "xclip", "xsel"];
    const PERSISTENCE_PATHS: [&str; 11] = [
        "autostart",
        ".config/systemd/user",
        ".config/environment.d",
        ".bashrc",
        ".zshrc",
        ".profile",
        ".config/hypr/",
        "exec-once",
        "crontab",
        "cron",
        "/etc/xdg/autostart",
    ];
    const EGRESS_TOOLS: [&str; 10] = [
        "curl",
        "wget",
        "nc",
        "socat",
        "requests",
        "urlopen",
        "urllib",
        "websocket",
        "fetch",
        "xmlhttprequest",
    ];
    const READ_MARKERS: [&str; 10] = [
        "readfile", "readtext", "fileview", "cat", "head", "tail", "grep", "open(", "fs.read",
        "readlink",
    ];

    const MAX_H6_ASSIGNMENTS: usize = 4096;
    let mut assignments = Vec::new();
    let mut next_scope_id = 1usize;
    let mut scope_stack = vec![0usize];
    let mut brace_depth = 0usize;
    let mut background_scopes: Vec<(usize, bool, bool)> = Vec::new();
    let mut visible_scopes = Vec::new();
    for (index, raw_line) in source.lines().enumerate() {
        let number = index as u32 + 1;
        let line = match kind {
            PayloadKind::Shell => script::strip_shell_comment(raw_line),
            PayloadKind::Python => strip_line_comment(raw_line, CommentStyle::PythonHash),
            _ => strip_line_comment(raw_line, CommentStyle::DoubleSlash),
        };
        if line.trim().is_empty() {
            continue;
        }
        let line_lower = line.to_ascii_lowercase();
        let code = unquoted_text(line);
        let lower_code = code.to_ascii_lowercase();
        let open_braces = code.bytes().filter(|byte| *byte == b'{').count();
        let close_braces = code.bytes().filter(|byte| *byte == b'}').count();
        for _ in 0..open_braces {
            scope_stack.push(next_scope_id);
            next_scope_id += 1;
        }
        let current_scope = *scope_stack.last().unwrap_or(&0);
        background_scopes.retain(|(scope_depth, _, _)| brace_depth >= *scope_depth);
        visible_scopes.retain(|scope_depth| brace_depth >= *scope_depth);
        let visible_trigger = [
            "onclick",
            "onpressed",
            "button",
            "useraction",
            "interactive",
        ]
        .iter()
        .any(|needle| lower_code.contains(needle));
        let background_here = [
            "timer",
            "setinterval",
            "oncompleted",
            "systemctl",
            "systemd-run",
            "service ",
            "cron",
            "at ",
        ]
        .iter()
        .any(|needle| lower_code.contains(needle));
        // Background provenance is scoped to the trigger's braced body (or to
        // the current line for command-style triggers). It must not leak from
        // an unrelated object or handler into the rest of the file. A
        // multiline disabled Timer cancels its own scope as soon as the
        // `running: false` declaration is observed.
        if (lower_code.contains("running: false") || lower_code.contains("running:false"))
            && let Some((_, _is_timer, disabled)) = background_scopes
                .iter_mut()
                .rev()
                .find(|(_, is_timer, _)| *is_timer)
        {
            *disabled = true;
        }
        let background = visible_scopes.is_empty()
            && !visible_trigger
            && (background_scopes.iter().any(|(_, _, disabled)| !disabled)
                || (background_here
                    && !lower_code.contains("running: false")
                    && !lower_code.contains("running:false")));

        let depth_after_open = brace_depth.saturating_add(open_braces);
        let depth_after = depth_after_open.saturating_sub(close_braces);
        if visible_trigger && open_braces > close_braces {
            visible_scopes.push(depth_after);
        }
        if background_here
            && !lower_code.contains("running: false")
            && !lower_code.contains("running:false")
            && open_braces > close_braces
        {
            let is_timer = lower_code.contains("timer");
            background_scopes.push((depth_after, is_timer, false));
        }
        brace_depth = depth_after;

        if let Some((variable, rhs)) = assignment_parts(line) {
            let rhs_lower = rhs.to_ascii_lowercase();
            let rhs_code_lower = unquoted_text(rhs).to_ascii_lowercase();
            let direct_sensitive_path = SENSITIVE_PATHS
                .iter()
                .any(|path| *path != "/etc/shadow" && rhs_lower.contains(path));
            let copied_provenance =
                visible_h6_assignment(&assignments, &scope_stack, &rhs_code_lower);
            let reads_sensitive_data = READ_MARKERS
                .iter()
                .any(|marker| find_word(&rhs_code_lower, marker).is_some())
                && (direct_sensitive_path
                    || copied_provenance
                        .is_some_and(|provenance| provenance != H6Provenance::Safe));
            let provenance = if reads_sensitive_data {
                H6Provenance::SensitiveValue
            } else if direct_sensitive_path {
                H6Provenance::SensitivePath
            } else if let Some(provenance) = copied_provenance {
                provenance
            } else {
                // Unknown and literal-safe assignments clear an earlier
                // sensitive value. Retaining the old value here would make a
                // later egress appear connected to a stale assignment.
                H6Provenance::Safe
            };
            if let Some(existing) = assignments.iter_mut().rev().find(|assignment| {
                assignment.scope_id == current_scope && assignment.name == variable
            }) {
                existing.provenance = provenance;
            } else if assignments.len() < MAX_H6_ASSIGNMENTS {
                assignments.push(H6Assignment {
                    name: variable,
                    scope_id: current_scope,
                    provenance,
                });
            } else if !outcome
                .limitations
                .iter()
                .any(|limitation| limitation == "h6-assignment-limit")
            {
                outcome.limitations.push("h6-assignment-limit".to_owned());
            }
        }

        let sensitive_path = SENSITIVE_PATHS
            .iter()
            .find(|needle| line_lower.contains(**needle));
        if let Some(path) = sensitive_path {
            outcome.capabilities.push(occurrence(
                Capability::SensitivePath,
                language,
                number,
                if *path == "/etc/shadow" {
                    "etc-shadow-intent"
                } else {
                    path
                },
            ));
        }

        let egress = EGRESS_TOOLS
            .iter()
            .any(|needle| find_word(&lower_code, needle).is_some());
        let sensitive_read_to_egress = egress
            && (egress_uses_sensitive_variable(
                &line_lower,
                &lower_code,
                &assignments,
                &scope_stack,
            ) || sensitive_read_connected_to_egress(
                &line_lower,
                &lower_code,
                kind,
                sensitive_path,
            ));
        if sensitive_read_to_egress {
            let rule_id = if matches!(language, Language::Shell | Language::Python) {
                SENSITIVE_DATA_EGRESS_RULE_SCRIPT
            } else {
                SENSITIVE_DATA_EGRESS_RULE_QML
            };
            outcome.result_parts.push(parts(
                rule_id,
                number,
                "sensitive-read-to-egress",
                outcome.confidence,
            ));
        }

        let input_tool = INPUT_TOOLS.iter().find(|tool| {
            let present =
                find_word(&lower_code, tool).is_some() || find_word(&line_lower, tool).is_some();
            present
                && (**tool != "hyprctl"
                    || lower_code.contains("sendshortcut")
                    || line_lower.contains("sendshortcut"))
        });
        if let Some(tool) = input_tool {
            outcome.capabilities.push(occurrence(
                Capability::InputInjection,
                language,
                number,
                tool,
            ));
            let dynamic_argument = lower_code.contains("input")
                || lower_code.contains("user_")
                || lower_code.contains("userinput")
                || lower_code.contains("argv")
                || line.contains('$');
            if (background && !visible_trigger) || dynamic_argument {
                let rule_id = if matches!(language, Language::Shell | Language::Python) {
                    INPUT_INJECTION_BACKGROUND_RULE_SCRIPT
                } else {
                    INPUT_INJECTION_BACKGROUND_RULE_QML
                };
                outcome.result_parts.push(parts(
                    rule_id,
                    number,
                    "background-input-injection",
                    outcome.confidence,
                ));
            }
        }

        let capture_tool = CAPTURE_TOOLS.iter().find(|tool| {
            find_word(&lower_code, tool).is_some() || find_word(&line_lower, tool).is_some()
        });
        if let Some(tool) = capture_tool {
            outcome.capabilities.push(occurrence(
                Capability::ScreenCapture,
                language,
                number,
                tool,
            ));
            if (background && !visible_trigger) || egress {
                let rule_id = if matches!(language, Language::Shell | Language::Python) {
                    SCREEN_CAPTURE_BACKGROUND_RULE_SCRIPT
                } else {
                    SCREEN_CAPTURE_BACKGROUND_RULE_QML
                };
                outcome.result_parts.push(parts(
                    rule_id,
                    number,
                    "background-screen-capture",
                    outcome.confidence,
                ));
            }
        }

        for tool in CLIPBOARD_READ_TOOLS {
            if find_word(&lower_code, tool).is_some() || find_word(&line_lower, tool).is_some() {
                let detail = if tool == "wl-paste" && lower_code.contains("--watch") {
                    "clipboard-watch"
                } else {
                    "clipboard-read"
                };
                outcome.capabilities.push(occurrence(
                    Capability::ClipboardAccess,
                    language,
                    number,
                    detail,
                ));
            }
        }
        if find_word(&lower_code, "wl-copy").is_some()
            || find_word(&line_lower, "wl-copy").is_some()
        {
            outcome.capabilities.push(occurrence(
                Capability::ClipboardAccess,
                language,
                number,
                "clipboard-write",
            ));
        }

        let persistence_target = PERSISTENCE_PATHS
            .iter()
            .find(|needle| line_lower.contains(**needle))
            .copied();
        let persistence_command = lower_code.contains("systemctl enable")
            || find_word(&lower_code, "crontab").is_some()
            || lower_code.contains(" at ")
            || lower_code.contains("exec-once");
        let write_intent = lower_code.contains("cp ")
            || lower_code.contains("tee ")
            || lower_code.contains("install ")
            || lower_code.contains("mkdir ")
            || lower_code.contains("touch ")
            || lower_code.contains("write")
            || lower_code.contains(">>")
            || lower_code.contains('>');
        if (persistence_target.is_some() || persistence_command)
            && (write_intent || persistence_command)
        {
            let detail = persistence_target.unwrap_or("persistence-command");
            outcome.capabilities.push(occurrence(
                Capability::PersistenceScheduling,
                language,
                number,
                detail,
            ));
            if background && !visible_trigger {
                let rule_id = if matches!(language, Language::Shell | Language::Python) {
                    PERSISTENCE_BACKGROUND_RULE_SCRIPT
                } else {
                    PERSISTENCE_BACKGROUND_RULE_QML
                };
                outcome.result_parts.push(parts(
                    rule_id,
                    number,
                    "background-persistence-write",
                    outcome.confidence,
                ));
            }
        }

        for _ in 0..close_braces {
            if scope_stack.len() > 1 {
                scope_stack.pop();
            }
        }
    }
}

fn assignment_parts(line: &str) -> Option<(String, &str)> {
    let bytes = line.as_bytes();
    let equals = bytes.iter().enumerate().find_map(|(index, byte)| {
        if *byte != b'=' {
            return None;
        }
        let previous = index
            .checked_sub(1)
            .and_then(|position| bytes.get(position));
        let next = bytes.get(index + 1);
        if matches!(previous, Some(b'=') | Some(b'!') | Some(b'<') | Some(b'>'))
            || matches!(next, Some(b'=') | Some(b'>'))
        {
            None
        } else {
            Some(index)
        }
    })?;
    let lhs = line[..equals]
        .trim()
        .trim_start_matches("property string ")
        .trim_start_matches("property var ")
        .trim_start_matches("let ")
        .trim_start_matches("var ")
        .trim_start_matches("const ")
        .trim_start_matches("export ")
        .trim();
    let name = lhs
        .rsplit(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .next()
        .unwrap_or_default();
    if name.is_empty()
        || name
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_digit())
    {
        None
    } else {
        Some((name.to_owned(), &line[equals + 1..]))
    }
}

fn visible_h6_assignment(
    assignments: &[H6Assignment],
    scope_stack: &[usize],
    text: &str,
) -> Option<H6Provenance> {
    assignments
        .iter()
        .rev()
        .find(|assignment| {
            scope_stack.contains(&assignment.scope_id)
                && find_word(text, &assignment.name).is_some()
        })
        .map(|assignment| assignment.provenance)
}

fn egress_uses_sensitive_variable(
    line_lower: &str,
    code_lower: &str,
    assignments: &[H6Assignment],
    scope_stack: &[usize],
) -> bool {
    const EGRESS_TOOLS: [&str; 10] = [
        "curl",
        "wget",
        "nc",
        "socat",
        "requests",
        "urlopen",
        "urllib",
        "websocket",
        "fetch",
        "xmlhttprequest",
    ];
    let Some(egress_offset) = EGRESS_TOOLS
        .iter()
        .filter_map(|tool| find_word(code_lower, tool))
        .min()
    else {
        return false;
    };
    line_lower.get(egress_offset..).is_some_and(|tail| {
        assignments.iter().rev().any(|assignment| {
            assignment.provenance == H6Provenance::SensitiveValue
                && scope_stack.contains(&assignment.scope_id)
                && find_word(tail, &assignment.name).is_some()
        })
    })
}

/// Require a concrete same-expression connection for direct sensitive reads.
/// A path and an egress on the same physical line are not enough: shell
/// commands separated by `;` must use a variable, command substitution, or a
/// pipe, while QML/Python expressions must put the read inside the egress
/// call. This keeps `cat secret >/dev/null; curl --version` capability-only.
fn sensitive_read_connected_to_egress(
    line_lower: &str,
    code_lower: &str,
    kind: &PayloadKind,
    sensitive_path: Option<&&str>,
) -> bool {
    const EGRESS_TOOLS: [&str; 10] = [
        "curl",
        "wget",
        "nc",
        "socat",
        "requests",
        "urlopen",
        "urllib",
        "websocket",
        "fetch",
        "xmlhttprequest",
    ];
    const READ_MARKERS: [&str; 10] = [
        "readfile", "readtext", "fileview", "cat", "head", "tail", "grep", "open(", "fs.read",
        "readlink",
    ];
    let Some(egress_offset) = EGRESS_TOOLS
        .iter()
        .filter_map(|tool| find_word(code_lower, tool))
        .min()
    else {
        return false;
    };
    let Some(path) = sensitive_path.copied() else {
        return false;
    };
    if path == "/etc/shadow" {
        return false;
    }
    let Some(path_offset) = line_lower.find(path) else {
        return false;
    };
    let has_read = |text: &str| {
        READ_MARKERS
            .iter()
            .any(|marker| find_word(text, marker).is_some())
    };

    if matches!(kind, PayloadKind::Shell) {
        // `cat secret | curl ...` and `curl --data "$(cat secret)"` are
        // explicit data paths; a semicolon-separated command is not.
        if let Some(pipe_offset) = line_lower.find('|') {
            return path_offset < pipe_offset
                && pipe_offset < egress_offset
                && has_read(&line_lower[..pipe_offset]);
        }
        if egress_offset < path_offset {
            let tail = &line_lower[egress_offset..];
            return tail.contains("$(") && has_read(tail) && tail.contains(path);
        }
        return false;
    }

    // In expression-oriented sources, a read nested in the egress call is a
    // direct connection. A statement separator breaks that connection.
    let tail = &line_lower[egress_offset..];
    let Some(read_offset) = READ_MARKERS
        .iter()
        .filter_map(|marker| find_word(tail, marker))
        .min()
    else {
        return false;
    };
    let read_absolute = egress_offset + read_offset;
    read_absolute < path_offset
        && !line_lower[egress_offset..read_absolute].contains(';')
        && has_read(&line_lower[read_absolute..])
}

fn invokes_git(code: &str) -> bool {
    let mut previous = None;
    for word in code.split_whitespace() {
        let command_word =
            word.trim_matches(|character: char| matches!(character, '(' | ')' | ';' | '|' | '&'));
        if (command_word == "git" || command_word.ends_with("/git"))
            && previous.is_none_or(|value| {
                matches!(
                    value,
                    "sudo" | "doas" | "pkexec" | "command" | "exec" | "env"
                )
            })
        {
            return true;
        }
        previous = Some(command_word);
    }
    false
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

#[cfg(test)]
mod tests;
