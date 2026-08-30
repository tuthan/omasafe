//! Lexical QML/JS fallback scanning (ADR 0001): line-scoped detection with
//! [`Confidence::LexicalFallback`] — standalone `.js` resources in every
//! build, and all QML when the `qml-parser` feature is off.

use crate::detect::model::{
    CommentStyle, DETACHED_RULE, DYNAMIC_CODE_RULE, FileOutcome, OBFUSCATION_RULE,
    PERSISTENCE_RULE, PROCESS_RULE, SinkKind, disclose_budget_limitation, find_word,
    lower_contains, occurrence, parts, strip_line_comment, unquoted_text,
};
use crate::detect::references::{
    ReferenceCandidate, SinkPosition, apply_directory_import, is_path_shaped, record_sink_reference,
};
use crate::fingerprint::Confidence;
use crate::rules::{Capability, Language};

use super::strings::decode_js_escapes;
use crate::detect::model::balanced_bracket_span;
use crate::detect::shell::egress::script_body_fetches;
use crate::detect::shell::interpreter::INTERPRETER_BASENAMES;

pub(in crate::detect) struct LexFlags {
    pub(in crate::detect) detached_any: Option<u32>,
    pub(in crate::detect) network: Option<u32>,
}

/// Shell-interpreter invocation inside a command string: an interpreter word
/// followed (after whitespace) by a `-c`-style flag. Returns the byte offset
/// of the interpreter word for evidence trimming.
pub(in crate::detect) fn find_shell_interpreter(text: &str) -> Option<usize> {
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

pub(in crate::detect) fn lexical_scan(source: &str, language: Language) -> FileOutcome {
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
pub(in crate::detect) struct HeadEgress {
    pub(in crate::detect) fetches: bool,
    pub(in crate::detect) exhausted: bool,
}

pub(in crate::detect) fn argv_head_fetches(elements: &[&str]) -> HeadEgress {
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

/// Length of a base64-shaped literal worth surfacing as an indicator.
pub(in crate::detect) fn encoded_literal_length(content: &str) -> Option<usize> {
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
