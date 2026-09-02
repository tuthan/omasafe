//! AST-backed QML scanning (`qml-parser` feature, ADR 0001): tree-sitter
//! walk producing [`Confidence::AstBacked`] conclusions, with the
//! import-surface and reference-sink handling shared by the walk.

use crate::detect::model::{
    DETACHED_RULE, DYNAMIC_CODE_RULE, DYNAMIC_REFERENCE_RULE, FileOutcome, OBFUSCATION_RULE,
    PERSISTENCE_RULE, PROCESS_RULE, SinkKind, disclose_budget_limitation,
    disclose_dataflow_limitation, occurrence, parts,
};
use crate::detect::qml::lexical::{
    argv_head_fetches, encoded_literal_length, find_shell_interpreter,
};
use crate::detect::references::{
    ReferenceCandidate, SinkPosition, apply_directory_import, is_path_shaped, record_sink_reference,
};
use crate::fingerprint::Confidence;
use crate::rules::{Capability, Language};

use super::dataflow::{DataflowFacts, FlowValue};
use super::strings::decode_js_escapes;

/// Module name of an `import X.Y <version>` statement (keyword/version/as
/// excluded).
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

/// Classified value of a binding or call argument after bounded dataflow.
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
    let mut dataflow = DataflowFacts::build(source, tree);

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
                handle_object_definition(source, node, &mut outcome, &mut dataflow);
                // Loader { source: <expr> }: computed sources are
                // dynamic reference sinks. Qualified spellings
                // (`QQ.Loader`) resolve through the terminal type
                // segment (H2 review).
                let is_loader = object_type_node(source, node).is_some_and(|type_node| {
                    terminal_segment(node_text(source, type_node)) == "Loader"
                });
                if is_loader && binding_value_named(source, node, "source").is_some() {
                    let binding = binding_value_named(source, node, "source").unwrap();
                    handle_reference_sink_value(
                        source,
                        binding,
                        SinkPosition::LoaderSource,
                        &mut outcome,
                        &mut dataflow,
                    );
                }
            }
            "call_expression" => {
                handle_call_expression(source, node, &mut outcome, &mut dataflow);
            }
            "identifier" | "property_identifier" => {
                let token_line = number_of(node);
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
                    outcome.capabilities.push(occurrence(
                        Capability::NetworkAccess,
                        Language::Qml,
                        number_of(node),
                        "new XMLHttpRequest",
                    ));
                } else if node.child_count() >= 2
                    && node_text(source, node.child(1).unwrap()) == "WebSocket"
                {
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

    for kind in dataflow.limitations() {
        disclose_dataflow_limitation(&mut outcome, kind);
    }

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

fn handle_object_definition(
    source: &str,
    node: tree_sitter::Node,
    outcome: &mut FileOutcome,
    dataflow: &mut DataflowFacts,
) {
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
                evaluate_execution_value(
                    source,
                    binding_value,
                    SinkKind::Process,
                    outcome,
                    dataflow,
                );
                // Command argv is a verified sink position (H2): literal
                // arguments outside the tree surface typed rejections;
                // in-tree literals resolve as invocation edges.
                handle_reference_sink_value(
                    source,
                    binding_value,
                    SinkPosition::ProcessCommand,
                    outcome,
                    dataflow,
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
                if let Value::Static(text) = classify_value(source, path_value, dataflow) {
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
                // FileView.path is a verified sink position (H2): the path
                // participates in reference resolution with typed
                // rejections; computed values stay explicit as dynamic,
                // tainted-reference findings.
                handle_reference_sink_value(
                    source,
                    path_value,
                    SinkPosition::FileViewPath,
                    outcome,
                    dataflow,
                );
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

/// Process argv elements at runtime-value granularity (H3/H4): static-shaped
/// elements contribute their text; dataflow-resolved identifiers do too, and
/// unknown positions stay empty so a dynamic head is never guessed at.
fn argv_elements(
    source: &str,
    value: tree_sitter::Node,
    dataflow: &mut DataflowFacts,
) -> Vec<String> {
    let inner = unwrap_expression_statement(value);
    match inner.kind() {
        "array" => {
            let mut cursor = inner.walk();
            inner
                .children(&mut cursor)
                .filter(|child| child.is_named())
                .map(|child| match classify_value(source, child, dataflow) {
                    Value::Static(text) => text,
                    Value::Dynamic(_) => String::new(),
                })
                .collect()
        }
        _ => match classify_value(source, inner, dataflow) {
            Value::Static(text) => text.split_whitespace().map(str::to_owned).collect(),
            Value::Dynamic(_) => Vec::new(),
        },
    }
}

fn classify_value(source: &str, node: tree_sitter::Node, dataflow: &mut DataflowFacts) -> Value {
    match dataflow.classify(source, node) {
        FlowValue::Static(text) => Value::Static(text),
        FlowValue::Network => Value::Dynamic("network-response-executed"),
        FlowValue::UserInput => Value::Dynamic("user-input-executed"),
        FlowValue::Dynamic | FlowValue::Unknown => Value::Dynamic("dynamic-command"),
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
            ("expression_statement" | "parenthesized_expression", [single]) => current = *single,
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
    dataflow: &mut DataflowFacts,
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
    let is_qt_sink = qt_receiver && matches!(callee_name.as_str(), "createComponent" | "include");
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
                handle_reference_sink_value(source, first, sink, outcome, dataflow);
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
            outcome.capabilities.push(occurrence(
                Capability::NetworkAccess,
                Language::Qml,
                number_of(node),
                "fetch()",
            ));
        }
        return;
    }
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
            evaluate_execution_value(
                source,
                first,
                SinkKind::DetachedExecution,
                outcome,
                dataflow,
            );
            // The executed path is also a reference sink (H2): a literal
            // outside the tree is a typed rejection, a literal inside it
            // resolves as an invocation edge.
            handle_reference_sink_value(
                source,
                first,
                SinkPosition::ExecDetached,
                outcome,
                dataflow,
            );
        }
    }
}

fn evaluate_execution_value(
    source: &str,
    value_node: tree_sitter::Node,
    kind: SinkKind,
    outcome: &mut FileOutcome,
    dataflow: &mut DataflowFacts,
) {
    let number = number_of(value_node);
    let rule_id = match kind {
        SinkKind::Process => PROCESS_RULE,
        SinkKind::DetachedExecution => DETACHED_RULE,
    };
    // Egress attribution (H3 review): only the executable position
    // attributes egress. See argv_head_fetches.
    if kind == SinkKind::Process {
        let elements = argv_elements(source, value_node, dataflow);
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
    match classify_value(source, value_node, dataflow) {
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
                outcome
                    .result_parts
                    .push(parts(rule_id, number, reason, Confidence::AstBacked));
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
    dataflow: &mut DataflowFacts,
) {
    let inner = unwrap_expression_statement(value);
    if inner.kind() == "array" {
        let mut cursor = inner.walk();
        let children: Vec<tree_sitter::Node> = inner
            .children(&mut cursor)
            .filter(|child| child.is_named())
            .collect();
        for child in children {
            handle_reference_sink_value(source, child, sink, outcome, dataflow);
        }
        return;
    }
    let flow = dataflow.classify(source, inner);
    match flow {
        FlowValue::Static(text) => record_sink_reference(&text, sink, number_of(inner), outcome),
        flow @ (FlowValue::Network
        | FlowValue::UserInput
        | FlowValue::Dynamic
        | FlowValue::Unknown)
            if matches!(
                sink,
                SinkPosition::LoaderSource | SinkPosition::FileViewPath
            ) =>
        {
            let reason = match flow {
                FlowValue::Network => "network-input",
                FlowValue::UserInput => "user-input",
                FlowValue::Unknown => "coverage-unknown",
                _ => "computed",
            };
            outcome.result_parts.push(parts(
                DYNAMIC_REFERENCE_RULE,
                number_of(inner),
                format!(
                    "dynamic-reference-sink:{}:{}:{}",
                    sink_name(sink),
                    reason,
                    node_text(source, inner)
                        .chars()
                        .take(120)
                        .collect::<String>()
                ),
                Confidence::AstBacked,
            ));
        }
        _ => {}
    }
}

fn sink_name(sink: SinkPosition) -> &'static str {
    match sink {
        SinkPosition::LoaderSource => "Loader.source",
        SinkPosition::FileViewPath => "FileView.path",
        SinkPosition::CreateComponent => "Qt.createComponent",
        SinkPosition::Include => "Qt.include",
        SinkPosition::ProcessCommand => "Process.command",
        SinkPosition::ExecDetached => "execDetached",
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
