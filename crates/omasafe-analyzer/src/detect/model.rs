//! Shared detect-layer model: per-file outcomes, result pieces,
//! capability occurrence construction, the rule-id constants, and the
//! byte-span and text helpers more than one analysis layer needs.

use omasafe_core::bounds::MAX_EVIDENCE_BYTES_PER_RESULT;
use omasafe_report::analysis::CapabilityOccurrence;

use crate::fingerprint::Confidence;
use crate::rules::{Capability, Language};

use super::references::ReferenceCandidate;

/// The bracketed span starting at `open` ('(' or '['): to its matching
/// closer, honoring nesting and quoted strings.
pub(in crate::detect) fn balanced_bracket_span(text: &str, open: usize) -> Option<(usize, usize)> {
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

pub(in crate::detect) fn truncate_bytes(value: &str, cap: usize) -> String {
    if value.len() <= cap {
        return value.to_owned();
    }
    let mut end = cap;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &value[..end])
}

/// Per-file detector output before cross-file anchoring.
pub(in crate::detect) struct FileOutcome {
    pub(in crate::detect) result_parts: Vec<ResultParts>,
    pub(in crate::detect) capabilities: Vec<CapabilityOccurrence>,
    pub(in crate::detect) references: Vec<ReferenceCandidate>,
    pub(in crate::detect) parse_degraded: bool,
    pub(in crate::detect) confidence: Confidence,
    /// Coverage limitations this file's analysis hit (budget exhaustion),
    /// anchored onto the entry path when artifacts are assembled.
    pub(in crate::detect) limitations: Vec<String>,
}

impl FileOutcome {
    pub(in crate::detect) fn has_findings(&self) -> bool {
        !self.result_parts.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::detect) enum SinkKind {
    Process,
    DetachedExecution,
}

pub(in crate::detect) const PROCESS_RULE: &str = "oma.qml.process-execution";
pub(in crate::detect) const DETACHED_RULE: &str = "oma.qml.detached-execution";
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::detect) const NETWORK_RULE: &str = "oma.qml.network-access";
#[cfg(feature = "qml-parser")]
pub(in crate::detect) const DYNAMIC_REFERENCE_RULE: &str = "oma.qml.dynamic-reference";
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::detect) const DYNAMIC_CODE_RULE: &str = "oma.qml.dynamic-code";
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::detect) const OBFUSCATION_RULE: &str = "oma.qml.obfuscated-payload-indicator";
pub(in crate::detect) const PERSISTENCE_RULE: &str = "oma.qml.persistence-scheduling";
pub(in crate::detect) const REMOTE_COMPONENT_LOAD_RULE: &str = "oma.qml.remote-component-load";
pub(in crate::detect) const REMOTE_DIRECTORY_IMPORT_RULE: &str = "oma.qml.remote-directory-import";
pub(in crate::detect) const OUT_OF_TREE_REFERENCE_RULE: &str = "oma.qml.out-of-tree-reference";
pub(in crate::detect) const SCRIPT_DOWNLOAD_EXECUTE_RULE: &str = "oma.script.download-execute";
pub(in crate::detect) const SCRIPT_PRIVILEGE_RULE: &str = "oma.script.privilege-escalation";
pub(in crate::detect) const PYTHON_DOWNLOAD_EXECUTE_RULE: &str = "oma.python.download-execute";
pub(in crate::detect) const PYTHON_PRIVILEGE_RULE: &str = "oma.python.privilege-escalation";
pub(in crate::detect) const SCRIPT_REVERSE_SHELL_RULE: &str = "oma.script.reverse-shell";
pub(in crate::detect) const PYTHON_REVERSE_SHELL_RULE: &str = "oma.python.reverse-shell";
pub(in crate::detect) const SCRIPT_DECODE_EXECUTE_RULE: &str = "oma.script.decode-execute";
pub(in crate::detect) const SHARED_TEMP_INDICATOR_RULE: &str = "oma.script.privileged-shared-temp";
pub(in crate::detect) const SHARED_TEMP_CONTROLLED_RULE: &str =
    "oma.script.privileged-shared-temp-controlled";
pub(in crate::detect) const REPLACES_BAR_RULE: &str = "oma.context.replaces-bar";
pub(in crate::detect) const BUNDLED_BINARY_RULE: &str = "oma.payload.bundled-binary";
pub(in crate::detect) const OMASAFE_STATE_TAMPER_RULE: &str = "oma.context.omasafe-state-tamper";
pub(in crate::detect) const SENSITIVE_PATH_RULE_QML: &str = "oma.qml.sensitive-path";
pub(in crate::detect) const INPUT_INJECTION_RULE_QML: &str = "oma.qml.input-injection";
pub(in crate::detect) const SCREEN_CAPTURE_RULE_QML: &str = "oma.qml.screen-capture";
pub(in crate::detect) const SENSITIVE_DATA_EGRESS_RULE_QML: &str = "oma.qml.sensitive-data-egress";
pub(in crate::detect) const INPUT_INJECTION_BACKGROUND_RULE_QML: &str =
    "oma.qml.input-injection-background";
pub(in crate::detect) const SCREEN_CAPTURE_BACKGROUND_RULE_QML: &str =
    "oma.qml.screen-capture-background";
pub(in crate::detect) const PERSISTENCE_BACKGROUND_RULE_QML: &str =
    "oma.qml.persistence-background";
pub(in crate::detect) const SENSITIVE_PATH_RULE_SCRIPT: &str = "oma.script.sensitive-path";
pub(in crate::detect) const INPUT_INJECTION_RULE_SCRIPT: &str = "oma.script.input-injection";
pub(in crate::detect) const SCREEN_CAPTURE_RULE_SCRIPT: &str = "oma.script.screen-capture";
pub(in crate::detect) const CLIPBOARD_RULE_SCRIPT: &str = "oma.script.clipboard-access";
pub(in crate::detect) const PERSISTENCE_RULE_SCRIPT: &str = "oma.script.persistence-scheduling";
pub(in crate::detect) const SENSITIVE_DATA_EGRESS_RULE_SCRIPT: &str =
    "oma.script.sensitive-data-egress";
pub(in crate::detect) const INPUT_INJECTION_BACKGROUND_RULE_SCRIPT: &str =
    "oma.script.input-injection-background";
pub(in crate::detect) const SCREEN_CAPTURE_BACKGROUND_RULE_SCRIPT: &str =
    "oma.script.screen-capture-background";
pub(in crate::detect) const PERSISTENCE_BACKGROUND_RULE_SCRIPT: &str =
    "oma.script.persistence-background";

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

pub(in crate::detect) fn occurrence(
    capability: Capability,
    language: Language,
    line: u32,
    detail: &str,
) -> CapabilityOccurrence {
    let covering_rule = if matches!(language, Language::Shell | Language::Python) {
        script_capability_covering_rule(capability)
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

fn script_capability_covering_rule(capability: Capability) -> Option<&'static str> {
    match capability {
        Capability::SensitivePath => Some(SENSITIVE_PATH_RULE_SCRIPT),
        Capability::InputInjection => Some(INPUT_INJECTION_RULE_SCRIPT),
        Capability::ScreenCapture => Some(SCREEN_CAPTURE_RULE_SCRIPT),
        Capability::ClipboardAccess => Some(CLIPBOARD_RULE_SCRIPT),
        Capability::PersistenceScheduling => Some(PERSISTENCE_RULE_SCRIPT),
        _ => None,
    }
}

pub(in crate::detect) fn capability_covering_rule(capability: Capability) -> Option<&'static str> {
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
        Capability::ShellIpcInventory => Some("oma.shell.ipc-injected-objects"),
        Capability::BundledBinary => Some("oma.payload.bundled-binary"),
        Capability::SensitivePath => Some(SENSITIVE_PATH_RULE_QML),
        Capability::InputInjection => Some(INPUT_INJECTION_RULE_QML),
        Capability::ScreenCapture => Some(SCREEN_CAPTURE_RULE_QML),
        _ => None,
    }
}

pub(in crate::detect) fn lower_contains(haystack: &str, needle: &str) -> bool {
    haystack.to_ascii_lowercase().contains(needle)
}

/// Comment syntax of the surrounding language. The two real line grammars
/// each get their own rule; shell comments are applied statefully by
/// `shell_logical_units` instead:
/// - QML/JS: `//` anywhere outside strings except in a scheme (`://`),
/// - Python: an unquoted `#` starts a comment at ANY position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::detect) enum CommentStyle {
    /// `// …` — QML/JS.
    DoubleSlash,
    /// `# …` anywhere outside strings — Python.
    PythonHash,
}

/// The executable prefix of a source line under the language's comment rule,
/// honoring quoted strings throughout.
pub(in crate::detect) fn strip_line_comment(line: &str, style: CommentStyle) -> &str {
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

pub(in crate::detect) fn find_word(haystack: &str, needle: &str) -> Option<usize> {
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

/// The line with quoted-literal contents blanked so detector needles inside
/// string values never satisfy them. Quote characters become spaces to keep
/// offsets and word boundaries stable.
pub(in crate::detect) fn unquoted_text(line: &str) -> String {
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
    pub(in crate::detect) line: Option<u32>,
    pub(in crate::detect) semantic_value: String,
    pub(in crate::detect) confidence: Confidence,
}

/// Record the analysis-budget coverage limitation once per file.
pub(in crate::detect) fn disclose_budget_limitation(outcome: &mut FileOutcome) {
    let limitation = "shell-analysis-budget-exhausted";
    if !outcome
        .limitations
        .iter()
        .any(|existing| existing == limitation)
    {
        outcome.limitations.push(limitation.to_owned());
    }
}

/// Record a bounded QML/JS dataflow limitation once per file. Dataflow is
/// deliberately conservative: an exhausted bound is visible partial
/// coverage, never a clean result.
#[cfg(feature = "qml-parser")]
pub(in crate::detect) fn disclose_dataflow_limitation(outcome: &mut FileOutcome, kind: &str) {
    let limitation = format!("dataflow-{kind}");
    if !outcome
        .limitations
        .iter()
        .any(|existing| existing == &limitation)
    {
        outcome.limitations.push(limitation);
    }
}
